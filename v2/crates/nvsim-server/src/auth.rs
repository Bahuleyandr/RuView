//! Bearer-token auth for the nvsim-server control plane.
//!
//! Mirrors the strict middleware from `wifi-densepose-sensing-server` —
//! gates every `/api/*` request and every `/ws/*` upgrade when
//! `NVSIM_API_TOKEN` is set. Browser WebSockets cannot set arbitrary
//! headers, so the token is also accepted via the
//! `Sec-WebSocket-Protocol: bearer.<token>` subprotocol (Kubernetes
//! kubectl-exec convention).
//!
//! Unlike the sensing-server, there is no "loopback default" exemption
//! here: nvsim-server's control plane (`PUT /api/scene`, `PUT /api/config`,
//! `POST /api/run`) lets any caller drive the deterministic pipeline,
//! and the CORS default is permissive enough that any web page open in
//! the user's browser could hit it. Gating both layers closes the gap.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

pub const API_TOKEN_ENV: &str = "NVSIM_API_TOKEN";

pub const PROTECTED_API_PREFIX: &str = "/api/";
pub const PROTECTED_WS_PREFIX: &str = "/ws/";
pub const WS_BEARER_SUBPROTOCOL_PREFIX: &str = "bearer.";

#[derive(Debug, Clone, Default)]
pub struct AuthState {
    token: Option<Arc<String>>,
}

impl AuthState {
    pub fn from_token(t: impl Into<String>) -> Self {
        let s = t.into();
        if s.is_empty() {
            AuthState { token: None }
        } else {
            AuthState { token: Some(Arc::new(s)) }
        }
    }

    pub fn from_env() -> Self {
        match std::env::var(API_TOKEN_ENV) {
            Ok(s) if !s.is_empty() => AuthState::from_token(s),
            _ => AuthState::default(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.token.is_some()
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    if let Some(s) = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        return Some(s.to_string());
    }
    let proto = headers.get("sec-websocket-protocol")?.to_str().ok()?;
    for entry in proto.split(',') {
        if let Some(tok) = entry.trim().strip_prefix(WS_BEARER_SUBPROTOCOL_PREFIX) {
            return Some(tok.to_string());
        }
    }
    None
}

pub async fn require_bearer(
    State(auth): State<AuthState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(expected) = auth.token.clone() else {
        return next.run(request).await;
    };
    let path = request.uri().path();
    let gated = path.starts_with(PROTECTED_API_PREFIX)
        || path.starts_with(PROTECTED_WS_PREFIX);
    if !gated {
        return next.run(request).await;
    }
    let supplied = extract_bearer(request.headers());
    let ok = supplied
        .as_deref()
        .map(|s| ct_eq(s.as_bytes(), expected.as_bytes()))
        .unwrap_or(false);
    if ok {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            "missing or invalid bearer token (Authorization: Bearer <NVSIM_API_TOKEN>, \
             or Sec-WebSocket-Protocol: bearer.<token> for browser WebSockets)\n",
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{HeaderName, HeaderValue, Request},
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    fn app(auth: AuthState) -> Router {
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .route("/api/health", get(|| async { "ok" }))
            .route("/api/scene", axum::routing::put(|| async { "ok" }))
            .route("/ws/stream", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(auth, require_bearer))
    }

    async fn status_of(
        r: Router,
        path: &str,
        hdr: Option<(&'static str, &str)>,
    ) -> StatusCode {
        let mut req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        if let Some((k, v)) = hdr {
            req.headers_mut().insert(
                HeaderName::from_static(k),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        r.oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn no_op_when_token_unset() {
        let r = app(AuthState::default());
        assert_eq!(status_of(r.clone(), "/api/health", None).await, StatusCode::OK);
        assert_eq!(status_of(r, "/ws/stream", None).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn gates_api_and_ws_when_token_set() {
        let r = app(AuthState::from_token("t1"));
        assert_eq!(status_of(r.clone(), "/api/health", None).await, StatusCode::UNAUTHORIZED);
        assert_eq!(status_of(r.clone(), "/ws/stream", None).await, StatusCode::UNAUTHORIZED);
        assert_eq!(
            status_of(r.clone(), "/api/health", Some(("authorization", "Bearer t1"))).await,
            StatusCode::OK
        );
        assert_eq!(
            status_of(r, "/ws/stream", Some(("sec-websocket-protocol", "bearer.t1"))).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn never_gates_health() {
        let r = app(AuthState::from_token("t1"));
        assert_eq!(status_of(r, "/health", None).await, StatusCode::OK);
    }
}
