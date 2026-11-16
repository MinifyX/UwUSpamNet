//! One integration test binary: every test runs the router in-process against its own
//! in-memory database and a fixed clock.

mod api;
mod digest;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use serde_json::{json, Value};
use std::net::SocketAddr;
use tower::ServiceExt;
use uwuspamnet::{AppState, Clock, Config};

/// 2026-11-16T12:00:00Z
pub const START: i64 = 1_794_830_400;

pub struct App {
    pub router: Router,
    pub clock: Clock,
    pub state: AppState,
}

#[allow(clippy::new_without_default)]
impl App {
    pub fn new() -> Self {
        Self::with(Config::default())
    }

    pub fn with(config: Config) -> Self {
        let clock = Clock::fixed(START);
        let state = AppState::new(
            uwuspamnet::db::open_in_memory().unwrap(),
            config,
            clock.clone(),
        );
        Self {
            router: uwuspamnet::api::router(state.clone()),
            clock,
            state,
        }
    }

    pub async fn call(
        &self,
        method: Method,
        path: &str,
        from: &str,
        key: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(key) = key {
            req = req.header("authorization", format!("Bearer {key}"));
        }
        let body = match body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let mut req = req.body(body).unwrap();
        let peer = SocketAddr::new(from.parse().unwrap(), 40000);
        req.extensions_mut().insert(ConnectInfo(peer));
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    /// Registers a server from `from` and returns its key.
    pub async fn register(&self, from: &str) -> String {
        let (status, body) = self
            .call(
                Method::POST,
                "/v1/register",
                from,
                None,
                Some(json!({ "name": "mail.example.com", "software": "Test 1.0" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["key"].as_str().unwrap().to_string()
    }

    pub async fn report(&self, key: &str, reports: Value) -> (StatusCode, Value) {
        self.call(
            Method::POST,
            "/v1/reports",
            "192.0.2.1",
            Some(key),
            Some(json!({ "reports": reports })),
        )
        .await
    }

    pub async fn list(&self, key: &str, since: Option<&str>) -> Value {
        let path = match since {
            Some(s) => format!("/v1/list?since={s}"),
            None => "/v1/list".into(),
        };
        let (status, body) = self
            .call(Method::GET, &path, "192.0.2.1", Some(key), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}
