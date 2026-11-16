//! The HTTP API, protocol v1 (`docs/protocol.md`).

use crate::db::{self, Accept, Report};
use crate::{digest, net, rfc3339, AppState, DAY};
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Query, State};
use axum::http::{header, Extensions, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};

pub const MAX_BODY: usize = 1024 * 1024;
pub const MAX_REPORTS: usize = 100;
pub const MAX_DIGESTS: usize = 8;
pub const MAX_DOMAINS: usize = 20;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/v1/health", get(health))
        .route("/v1/register", post(register))
        .route("/v1/reports", post(reports))
        .route("/v1/list", get(list))
        .fallback(|| async { ApiError::new(StatusCode::NOT_FOUND, "not_found") })
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

// --- errors --------------------------------------------------------------------------------

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    detail: Option<String>,
    retry_after: Option<i64>,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str) -> Self {
        Self {
            status,
            code,
            detail: None,
            retry_after: None,
        }
    }

    fn invalid(detail: impl Into<String>) -> Self {
        Self {
            detail: Some(detail.into()),
            ..Self::new(StatusCode::BAD_REQUEST, "invalid_request")
        }
    }

    fn too_large(detail: impl Into<String>) -> Self {
        Self {
            detail: Some(detail.into()),
            ..Self::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large")
        }
    }

    fn rate_limited(now: i64) -> Self {
        Self {
            retry_after: Some(DAY - now.rem_euclid(DAY)),
            ..Self::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited")
        }
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(err: rusqlite::Error) -> Self {
        tracing::error!(%err, "database");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({ "error": self.code });
        if let Some(detail) = self.detail {
            body["detail"] = detail.into();
        }
        let mut response = (self.status, Json(body)).into_response();
        if let Some(seconds) = self.retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, seconds.into());
        }
        response
    }
}

type ApiResult<T> = Result<T, ApiError>;

fn body<T>(parsed: Result<Json<T>, JsonRejection>) -> ApiResult<T> {
    match parsed {
        Ok(Json(value)) => Ok(value),
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            Err(ApiError::too_large(format!("body over {MAX_BODY} bytes")))
        }
        Err(rejection) => Err(ApiError {
            detail: Some(rejection.body_text()),
            ..ApiError::new(StatusCode::BAD_REQUEST, "invalid_json")
        }),
    }
}

// --- helpers -------------------------------------------------------------------------------

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// The client's address: the TCP peer, or behind a trusted proxy the last `X-Forwarded-For`
/// entry (the one the proxy itself added).
fn client_ip(state: &AppState, headers: &HeaderMap, ext: &Extensions) -> ApiResult<IpAddr> {
    if state.config.trust_forwarded {
        let forwarded = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .filter_map(|v| v.trim().parse::<IpAddr>().ok())
            .next_back();
        if let Some(ip) = forwarded {
            return Ok(ip);
        }
    }
    ext.get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .ok_or_else(|| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal"))
}

/// The server behind a bearer key.
fn authenticate(state: &AppState, headers: &HeaderMap) -> ApiResult<String> {
    let key = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|k| k.starts_with("usn_"))
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    let conn = state.db.lock().unwrap();
    match db::server_by_key(&conn, &sha256_hex(key))? {
        Some((_, true)) => Err(ApiError::new(StatusCode::FORBIDDEN, "banned")),
        Some((id, false)) => Ok(id),
        None => Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized")),
    }
}

/// A short single-line text field: trimmed, 1..=max characters, no control characters.
fn text_field(name: &str, value: &str, max: usize) -> ApiResult<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(ApiError::invalid(format!(
            "{name}: 1 to {max} characters, no control characters"
        )));
    }
    Ok(value.to_string())
}

// --- handlers ------------------------------------------------------------------------------

async fn index() -> impl IntoResponse {
    (
        [(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; style-src 'unsafe-inline'; img-src data:",
        )],
        Html(include_str!("page.html")),
    )
}

async fn health(State(state): State<AppState>) -> Response {
    let ok = state
        .db
        .lock()
        .unwrap()
        .query_row("SELECT 1", [], |r| r.get::<_, i64>(0))
        .is_ok();
    let status = if ok { "ok" } else { "error" };
    let body = json!({
        "status": status,
        "version": env!("CARGO_PKG_VERSION"),
        "checks": { "database": status },
    });
    let code = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body)).into_response()
}

#[derive(Deserialize)]
struct RegisterRequest {
    name: String,
    software: String,
    contact: Option<String>,
}

async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    ext: Extensions,
    request: Result<Json<RegisterRequest>, JsonRejection>,
) -> ApiResult<Response> {
    let now = state.clock.now();
    let ip = client_ip(&state, &headers, &ext)?;
    {
        let mut seen = state.registrations.lock().unwrap();
        let today = now.div_euclid(DAY);
        if seen.0 != today {
            *seen = (today, Default::default());
        }
        if seen.1.get(&ip).copied().unwrap_or(0) >= state.config.registrations_per_ip {
            return Err(ApiError::rate_limited(now));
        }
    }
    let request = body(request)?;
    let name = text_field("name", &request.name, 253)?;
    let software = text_field("software", &request.software, 100)?;
    let contact = match request.contact.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(c) => Some(text_field("contact", c, 254)?),
    };
    let id = format!("s_{}", random_hex(12));
    let key = format!("usn_{}", random_hex(32));
    let reg_net = net::registration_network(ip);
    db::insert_server(
        &state.db.lock().unwrap(),
        &db::NewServer {
            id: &id,
            name: &name,
            software: &software,
            contact: contact.as_deref(),
            key_hash: &sha256_hex(&key),
            reg_net: &reg_net,
        },
        now,
    )?;
    *state.registrations.lock().unwrap().1.entry(ip).or_insert(0) += 1;
    tracing::info!(%id, %name, %software, %reg_net, "registered");
    Ok((
        StatusCode::CREATED,
        Json(json!({ "serverId": id, "key": key })),
    )
        .into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Verdict {
    Spam,
    Ham,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Reason {
    User,
    Filter,
}

#[derive(Deserialize)]
struct ReportIn {
    verdict: Verdict,
    reason: Reason,
    #[serde(default)]
    digests: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
    ip: Option<String>,
    from: Option<String>,
}

#[derive(Deserialize)]
struct ReportsRequest {
    reports: Vec<ReportIn>,
}

async fn reports(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Result<Json<ReportsRequest>, JsonRejection>,
) -> ApiResult<Response> {
    let server = authenticate(&state, &headers)?;
    let request = body(request)?;
    if request.reports.len() > MAX_REPORTS {
        return Err(ApiError::too_large(format!(
            "at most {MAX_REPORTS} reports per request"
        )));
    }
    let mut stored = Vec::with_capacity(request.reports.len());
    for report in request.reports {
        if report.digests.len() > MAX_DIGESTS || report.domains.len() > MAX_DOMAINS {
            return Err(ApiError::too_large(format!(
                "at most {MAX_DIGESTS} digests and {MAX_DOMAINS} domains per report"
            )));
        }
        // Values that are not valid for their kind are skipped, not refused.
        let mut items: Vec<(&'static str, String)> = Vec::new();
        let digests = report.digests.into_iter().filter(|d| digest::is_valid(d));
        items.extend(digests.map(|d| ("digest", d)));
        let domains = report.domains.iter().filter_map(|d| net::domain(d));
        items.extend(domains.map(|d| ("domain", d)));
        items.extend(
            report
                .ip
                .as_deref()
                .and_then(net::reported_ip)
                .map(|v| ("ip", v)),
        );
        items.extend(
            report
                .from
                .as_deref()
                .and_then(net::domain)
                .map(|v| ("from", v)),
        );
        items.sort();
        items.dedup();
        if !items.is_empty() {
            stored.push(Report {
                spam: matches!(report.verdict, Verdict::Spam),
                user: matches!(report.reason, Reason::User),
                items,
            });
        }
    }
    let now = state.clock.now();
    let per_day = state.config.reports_per_day;
    let mut conn = state.db.lock().unwrap();
    match db::add_reports(&mut conn, &server, &stored, per_day, now)? {
        Accept::Accepted(n) => {
            Ok((StatusCode::ACCEPTED, Json(json!({ "accepted": n }))).into_response())
        }
        Accept::RateLimited => Err(ApiError::rate_limited(now)),
    }
}

#[derive(Deserialize)]
struct ListQuery {
    since: Option<String>,
}

async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    authenticate(&state, &headers)?;
    let now = state.clock.now();
    let since = query.since.and_then(|s| s.parse::<i64>().ok());
    let mut conn = state.db.lock().unwrap();
    db::sweep(&mut conn, now)?;
    let list = db::list(&conn, since)?;
    drop(conn);
    let entries: Vec<Value> = list
        .entries
        .iter()
        .map(|e| {
            json!({
                "kind": e.kind,
                "value": e.value,
                "score": e.score,
                "expires": rfc3339(e.expires),
            })
        })
        .collect();
    let removed: Vec<Value> = list
        .removed
        .iter()
        .map(|(kind, value)| json!({ "kind": kind, "value": value }))
        .collect();
    Ok(Json(json!({
        "cursor": list.cursor.to_string(),
        "full": list.full,
        "entries": entries,
        "removed": removed,
    })))
}
