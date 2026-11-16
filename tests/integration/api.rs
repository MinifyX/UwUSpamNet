use crate::{App, START};
use axum::http::{Method, StatusCode};
use serde_json::{json, Value};
use uwuspamnet::{db, Config, DAY};

const DIGEST: &str = "d1:0123456789abcdef0123456789abcdef";

/// A server in its own registration network: 2001:db8:<n>::/48.
fn net(n: u32) -> String {
    format!("2001:db8:{n:x}::1")
}

async fn servers(app: &App, n: u32) -> Vec<String> {
    let mut keys = Vec::new();
    for i in 1..=n {
        keys.push(app.register(&net(i)).await);
    }
    keys
}

fn spam(reason: &str) -> Value {
    json!([{ "verdict": "spam", "reason": reason, "digests": [DIGEST] }])
}

fn ham(reason: &str) -> Value {
    json!([{ "verdict": "ham", "reason": reason, "digests": [DIGEST] }])
}

async fn all_report(app: &App, keys: &[String], reports: Value) {
    for key in keys {
        let (status, body) = app.report(key, reports.clone()).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    }
}

fn digest_entry(list: &Value) -> Option<&Value> {
    list["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["value"] == DIGEST)
}

#[tokio::test]
async fn health_index_and_unknown_paths() {
    let app = App::new();
    let (status, body) = app
        .call(Method::GET, "/v1/health", "192.0.2.1", None, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["checks"]["database"], "ok");
    let (status, _) = app.call(Method::GET, "/", "192.0.2.1", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = app
        .call(Method::GET, "/nope", "192.0.2.1", None, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "not_found");
}

#[tokio::test]
async fn registration_validates_and_limits_per_ip() {
    let app = App::new();
    let (status, body) = app
        .call(
            Method::POST,
            "/v1/register",
            "192.0.2.7",
            None,
            Some(json!({ "name": "", "software": "x" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    let (status, body) = app
        .call(
            Method::POST,
            "/v1/register",
            "192.0.2.7",
            None,
            Some(json!({ "x": 1 })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_json");

    let (status, body) = app
        .call(
            Method::POST,
            "/v1/register",
            "192.0.2.7",
            None,
            Some(json!({
                "name": "mail.example.com",
                "software": "UwUMail 0.38.0",
                "contact": "postmaster@example.com"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(body["serverId"].as_str().unwrap().starts_with("s_"));
    assert!(body["key"].as_str().unwrap().starts_with("usn_"));
    for _ in 0..4 {
        app.register("192.0.2.7").await;
    }
    let (status, body) = app
        .call(
            Method::POST,
            "/v1/register",
            "192.0.2.7",
            None,
            Some(json!({ "name": "a.example.com", "software": "x" })),
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "rate_limited");
    // Another address, and the same one the next day, may.
    app.register("192.0.2.8").await;
    app.clock.advance(DAY);
    app.register("192.0.2.7").await;

    // The key is stored as a hash only, and the network instead of the address.
    let conn = app.state.db.lock().unwrap();
    let rows = db::servers(&conn).unwrap();
    assert!(rows.iter().all(|s| s.reg_net == "192.0.2.0/24"));
    let stored: String = conn
        .query_row("SELECT key_hash FROM servers LIMIT 1", [], |r| r.get(0))
        .unwrap();
    assert!(!stored.starts_with("usn_"));
}

#[tokio::test]
async fn auth_is_required() {
    let app = App::new();
    let (status, body) = app
        .call(Method::GET, "/v1/list", "192.0.2.1", None, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "unauthorized");
    let (status, _) = app.report("usn_wrong", spam("user")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn report_limits() {
    let app = App::new();
    let key = app.register("192.0.2.1").await;
    let many: Vec<Value> = (0..101).map(|_| spam("user")[0].clone()).collect();
    let (status, body) = app.report(&key, json!(many)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"], "too_large");
    let digests: Vec<String> = (0..9).map(|i| format!("d1:{i:032x}")).collect();
    let (status, _) = app
        .report(
            &key,
            json!([{ "verdict": "spam", "reason": "user", "digests": digests }]),
        )
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let (status, body) = app
        .report(&key, json!([{ "verdict": "maybe", "reason": "user" }]))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_json");

    // Invalid values are skipped; a report with nothing valid left is not counted.
    let (status, body) = app
        .report(
            &key,
            json!([
                { "verdict": "spam", "reason": "filter", "digests": ["nope"], "ip": "10.0.0.1" },
                { "verdict": "spam", "reason": "filter", "domains": ["bad.example.com", "-x"] }
            ]),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["accepted"], 1);
}

#[tokio::test]
async fn daily_report_budget() {
    let app = App::with(Config {
        reports_per_day: 3,
        ..Config::default()
    });
    let key = app.register("192.0.2.1").await;
    let two = json!([spam("user")[0], spam("filter")[0]]);
    assert_eq!(app.report(&key, two.clone()).await.0, StatusCode::ACCEPTED);
    assert_eq!(
        app.report(&key, two.clone()).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    app.clock.advance(DAY);
    assert_eq!(app.report(&key, two).await.0, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn three_networks_list_an_entry() {
    let app = App::new();
    let keys = servers(&app, 3).await;
    all_report(&app, &keys[..2], spam("filter")).await;
    assert!(digest_entry(&app.list(&keys[0], None).await).is_none());

    all_report(&app, &keys[2..], spam("filter")).await;
    let list = app.list(&keys[0], None).await;
    assert_eq!(list["full"], true);
    let entry = digest_entry(&list).expect("listed");
    assert_eq!(entry["kind"], "digest");
    assert_eq!(entry["score"], 1.0);
    assert_eq!(entry["expires"], uwuspamnet::rfc3339(START + 14 * DAY));
}

#[tokio::test]
async fn one_network_counts_once() {
    let app = App::new();
    let mut keys = Vec::new();
    for i in 1..=5 {
        keys.push(app.register(&format!("198.51.100.{i}")).await);
    }
    keys.push(app.register("203.0.113.1").await);
    all_report(&app, &keys, spam("user")).await;
    assert!(digest_entry(&app.list(&keys[0], None).await).is_none());
}

#[tokio::test]
async fn score_scales_and_user_counts_double() {
    let app = App::new();
    let keys = servers(&app, 10).await;
    all_report(&app, &keys[..3], spam("user")).await;
    let list = app.list(&keys[0], None).await;
    // Three networks, all people: weight 6 → 1 + 3·3/7.
    assert_eq!(digest_entry(&list).unwrap()["score"], 2.29);
    all_report(&app, &keys[3..], spam("filter")).await;
    let list = app.list(&keys[0], None).await;
    assert_eq!(digest_entry(&list).unwrap()["score"], 4.0);
}

#[tokio::test]
async fn ham_keeps_entries_out_and_shortens_them() {
    let app = App::new();
    let keys = servers(&app, 5).await;
    all_report(&app, &keys[..3], spam("filter")).await;
    // One person says ham: 3 spam votes < 3 × 2.
    all_report(&app, &keys[3..4], ham("user")).await;
    assert!(digest_entry(&app.list(&keys[0], None).await).is_none());

    // More spam: 2·2 + 3 = 7 ≥ 6 — listed, two days earlier gone.
    let users = [keys[0].clone(), keys[4].clone()];
    all_report(&app, &users, spam("user")).await;
    let list = app.list(&keys[0], None).await;
    let entry = digest_entry(&list).expect("listed");
    assert_eq!(entry["expires"], uwuspamnet::rfc3339(START + 12 * DAY));
}

#[tokio::test]
async fn entries_expire_and_show_up_as_removed() {
    let app = App::new();
    let keys = servers(&app, 3).await;
    all_report(&app, &keys, spam("filter")).await;
    let first = app.list(&keys[0], None).await;
    let cursor = first["cursor"].as_str().unwrap().to_string();
    assert!(digest_entry(&first).is_some());

    // Nothing new: an empty increment.
    let next = app.list(&keys[0], Some(&cursor)).await;
    assert_eq!(next["full"], false);
    assert!(next["entries"].as_array().unwrap().is_empty());
    assert_eq!(next["cursor"], cursor.as_str());

    app.clock.advance(14 * DAY);
    let next = app.list(&keys[0], Some(&cursor)).await;
    assert_eq!(
        next["removed"],
        json!([{ "kind": "digest", "value": DIGEST }])
    );
    assert!(digest_entry(&app.list(&keys[0], None).await).is_none());

    // Unknown cursors get the full list.
    let next = app.list(&keys[0], Some("999999")).await;
    assert_eq!(next["full"], true);
    let next = app.list(&keys[0], Some("garbage")).await;
    assert_eq!(next["full"], true);
}

#[tokio::test]
async fn later_reports_extend_an_entry() {
    let app = App::new();
    let keys = servers(&app, 3).await;
    all_report(&app, &keys, spam("filter")).await;
    let cursor = app.list(&keys[0], None).await["cursor"]
        .as_str()
        .unwrap()
        .to_string();
    app.clock.advance(5 * DAY);
    all_report(&app, &keys, spam("filter")).await;
    let next = app.list(&keys[0], Some(&cursor)).await;
    let entry = digest_entry(&next).expect("updated");
    assert_eq!(entry["expires"], uwuspamnet::rfc3339(START + 19 * DAY));
}

#[tokio::test]
async fn kinds_are_normalized() {
    let app = App::new();
    let keys = servers(&app, 3).await;
    let report = json!([{
        "verdict": "spam",
        "reason": "filter",
        "domains": ["Bad.Example.COM."],
        "ip": "2001:db8:aa:bb:1:2:3:4",
        "from": "sender.example.net"
    }]);
    all_report(&app, &keys, report).await;
    let list = app.list(&keys[0], None).await;
    let mut got: Vec<(String, String)> = list["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["kind"].as_str().unwrap().into(),
                e["value"].as_str().unwrap().into(),
            )
        })
        .collect();
    got.sort();
    assert_eq!(
        got,
        [
            ("domain".into(), "bad.example.com".into()),
            ("from".into(), "sender.example.net".into()),
            ("ip".into(), "2001:db8:aa:bb::/64".into()),
        ]
    );
}

#[tokio::test]
async fn allowlist_and_seed() {
    let app = App::new();
    let keys = servers(&app, 3).await;
    let report = json!([{
        "verdict": "spam",
        "reason": "user",
        "domains": ["mail.gmail.com", "bad.example.com"],
        "from": "gmail.com",
        "ip": "203.0.113.9"
    }]);
    all_report(&app, &keys, report).await;
    let values = |list: &Value| -> Vec<String> {
        let mut v: Vec<String> = list["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["value"].as_str().unwrap().to_string())
            .collect();
        v.sort();
        v
    };
    let list = app.list(&keys[0], None).await;
    assert_eq!(values(&list), ["203.0.113.9", "bad.example.com"]);

    let now = app.clock.now();
    {
        let mut conn = app.state.db.lock().unwrap();
        let v = db::allowlist_value("ip", "203.0.113.0/24").unwrap();
        db::allowlist_add(&mut conn, "ip", &v, "test", now).unwrap();
    }
    let list = app.list(&keys[0], None).await;
    assert_eq!(values(&list), ["bad.example.com"]);

    {
        let mut conn = app.state.db.lock().unwrap();
        assert!(db::allowlist_remove(&mut conn, "ip", "203.0.113.0/24", now).unwrap());
        assert!(db::allowlist_remove(&mut conn, "from", "gmail.com", now).unwrap());
    }
    let list = app.list(&keys[0], None).await;
    assert_eq!(
        values(&list),
        ["203.0.113.9", "bad.example.com", "gmail.com"]
    );
}

#[tokio::test]
async fn banning_drops_a_servers_reports() {
    let app = App::new();
    let keys = servers(&app, 3).await;
    all_report(&app, &keys, spam("filter")).await;
    let id = {
        let conn = app.state.db.lock().unwrap();
        db::servers(&conn).unwrap()[2].id.clone()
    };
    let now = app.clock.now();
    assert!(db::set_banned(&mut app.state.db.lock().unwrap(), &id, true, now).unwrap());
    assert!(digest_entry(&app.list(&keys[0], None).await).is_none());
    let (status, body) = app.report(&keys[2], spam("user")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "banned");

    assert!(db::set_banned(&mut app.state.db.lock().unwrap(), &id, false, now).unwrap());
    assert!(digest_entry(&app.list(&keys[0], None).await).is_some());
}

#[tokio::test]
async fn forwarded_for_only_when_trusted() {
    let app = App::with(Config {
        trust_forwarded: true,
        ..Config::default()
    });
    let mut req = axum::http::Request::post("/v1/register")
        .header("content-type", "application/json")
        .header("x-forwarded-for", "198.51.100.1, 203.0.113.50")
        .body(axum::body::Body::from(
            json!({ "name": "mail.example.com", "software": "x" }).to_string(),
        ))
        .unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo::<std::net::SocketAddr>(
            "127.0.0.1:1".parse().unwrap(),
        ));
    use tower::ServiceExt;
    let res = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let conn = app.state.db.lock().unwrap();
    assert_eq!(db::servers(&conn).unwrap()[0].reg_net, "203.0.113.0/24");
}
