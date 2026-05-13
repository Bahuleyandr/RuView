//! Bearer-token auth for the MAT REST + WebSocket API.
//!
//! The MAT crate ships as a library — operators are expected to mount
//! [`super::create_router`] into their own Axum app. Without auth in front,
//! the disaster-event control plane (`POST /api/v1/mat/events`,
//! `POST /api/v1/mat/scan/control`, etc.) is unauthenticated, and the
//! `/ws/mat/stream` socket streams live survivor and alert telemetry.
//!
//! Use [`apply_bearer_auth`] to wrap a built router with the strict gate
//! (`/api/v1/mat/*` + `/ws/mat/*`). Token comparison is constant-time.
//! Browser WebSockets can pass the token via
//! `Sec-WebSocket-Protocol: bearer.<token>`.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Router,
};

pub const API_TOKEN_ENV: &str = "MAT_API_TOKEN";

pub const PROTECTED_API_PREFIX: &str = "/api/v1/mat/";
pub const PROTECTED_WS_PREFIX: &str = "/ws/mat/";
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
    let gated = path.starts_with(PROTECTED_API_PREFIX) || path.starts_with(PROTECTED_WS_PREFIX);
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
            "missing or invalid bearer token (Authorization: Bearer <MAT_API_TOKEN>, \
             or Sec-WebSocket-Protocol: bearer.<token> for browser WebSockets)\n",
        )
            .into_response()
    }
}

/// Wrap a router with the MAT bearer-auth middleware.
///
/// Pass an [`AuthState`] from [`AuthState::from_env`] or [`AuthState::from_token`].
/// If the auth state is disabled (empty token), the middleware is a no-op —
/// **but the caller is then responsible for confirming the binary will only
/// be reachable on a trusted network.**
pub fn apply_bearer_auth(router: Router, auth: AuthState) -> Router {
    router.layer(axum::middleware::from_fn_with_state(auth, require_bearer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{HeaderName, HeaderValue, Request},
        routing::get,
    };
    use tower::ServiceExt;

    fn app(auth: AuthState) -> Router {
        let r = Router::new()
            .route("/api/v1/mat/events", get(|| async { "ok" }))
            .route("/ws/mat/stream", get(|| async { "ok" }))
            .route("/health", get(|| async { "ok" }));
        apply_bearer_auth(r, auth)
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
    async fn no_op_when_disabled() {
        let r = app(AuthState::default());
        assert_eq!(status_of(r.clone(), "/api/v1/mat/events", None).await, StatusCode::OK);
        assert_eq!(status_of(r, "/ws/mat/stream", None).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn gates_when_enabled() {
        let r = app(AuthState::from_token("k"));
        assert_eq!(
            status_of(r.clone(), "/api/v1/mat/events", None).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status_of(r.clone(), "/api/v1/mat/events", Some(("authorization", "Bearer k"))).await,
            StatusCode::OK
        );
        assert_eq!(
            status_of(r.clone(), "/ws/mat/stream", Some(("sec-websocket-protocol", "bearer.k"))).await,
            StatusCode::OK
        );
        // /health is never gated.
        assert_eq!(status_of(r, "/health", None).await, StatusCode::OK);
    }
}
