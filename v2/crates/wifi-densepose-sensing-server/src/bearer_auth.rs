//! Bearer-token auth for the sensing-server HTTP API.
//!
//! Two middlewares are exported:
//!
//! * [`require_bearer`] — the legacy `/api/v1/*`-only gate (#443). Kept for
//!   backward compatibility with callers that want to leave the WebSocket
//!   open. Operators should generally prefer the strict variant.
//! * [`require_bearer_strict`] — gates `/api/v1/*` AND every `/ws/*` upgrade,
//!   which is where the live biometric stream (presence, breathing rate,
//!   heart rate) actually flows. Browser WebSockets cannot set arbitrary
//!   headers, so the strict middleware accepts the token in either
//!   `Authorization: Bearer <t>` OR a `Sec-WebSocket-Protocol: bearer.<t>`
//!   subprotocol entry — the same pattern Kubernetes uses for kubectl exec.
//!
//! When the `RUVIEW_API_TOKEN` environment variable is unset (or empty), both
//! middlewares are no-ops. `/health*`, `/` and the static `/ui/*` mount are
//! NEVER gated, since orchestrator probes hit them anonymously and the UI
//! shell needs to load before it knows about the token.
//!
//! Token comparison uses a constant-time byte compare to avoid leaking the
//! value through timing.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Environment variable that gates the middleware. Unset / empty ⇒ auth off.
pub const API_TOKEN_ENV: &str = "RUVIEW_API_TOKEN";

/// Path prefix the middleware protects when auth is enabled.
pub const PROTECTED_PREFIX: &str = "/api/v1/";

/// Cheap, cloneable handle to the configured token (or `None`).
#[derive(Debug, Clone, Default)]
pub struct AuthState {
    /// The expected bearer token, if any. `None` ⇒ middleware is a no-op.
    token: Option<Arc<String>>,
}

impl AuthState {
    /// Build an [`AuthState`] from an explicit string. Empty ⇒ disabled.
    pub fn from_token(t: impl Into<String>) -> Self {
        let s = t.into();
        if s.is_empty() {
            AuthState { token: None }
        } else {
            AuthState { token: Some(Arc::new(s)) }
        }
    }

    /// Read [`API_TOKEN_ENV`] from the process environment. Returns
    /// `AuthState { token: None }` when the variable is unset or empty.
    pub fn from_env() -> Self {
        match std::env::var(API_TOKEN_ENV) {
            Ok(s) if !s.is_empty() => AuthState::from_token(s),
            _ => AuthState::default(),
        }
    }

    /// Whether the middleware will enforce auth on `/api/v1/*` requests.
    pub fn is_enabled(&self) -> bool {
        self.token.is_some()
    }
}

/// Constant-time byte slice equality. Returns `false` immediately on length
/// mismatch (lengths are not secret here — both sides are fixed tokens).
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

/// Path prefix for WebSocket upgrade routes the strict middleware protects.
pub const WS_PREFIX: &str = "/ws/";

/// Subprotocol scheme that carries a bearer token over `Sec-WebSocket-Protocol`,
/// used because browsers cannot set arbitrary headers on `new WebSocket(...)`.
/// Mirrors the Kubernetes kubectl-exec convention. Example header value:
/// `Sec-WebSocket-Protocol: bearer.<token>`.
pub const WS_BEARER_SUBPROTOCOL_PREFIX: &str = "bearer.";

/// Pull a bearer token out of an HTTP request: prefers `Authorization: Bearer
/// <t>`, falls back to `Sec-WebSocket-Protocol: bearer.<t>` for browser WS.
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    if let Some(s) = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        return Some(s.to_string());
    }
    // Sec-WebSocket-Protocol can list multiple comma-separated protocols.
    let proto = headers.get("sec-websocket-protocol")?.to_str().ok()?;
    for entry in proto.split(',') {
        let trimmed = entry.trim();
        if let Some(tok) = trimmed.strip_prefix(WS_BEARER_SUBPROTOCOL_PREFIX) {
            return Some(tok.to_string());
        }
    }
    None
}

/// Internal gate: returns `Ok` to pass through, `Err(Response)` to short-circuit.
fn check(auth: &AuthState, request: &Request, also_gate_ws: bool) -> Result<(), Response> {
    let Some(expected) = auth.token.clone() else {
        return Ok(());
    };
    let path = request.uri().path();
    let gated = path.starts_with(PROTECTED_PREFIX)
        || (also_gate_ws && path.starts_with(WS_PREFIX));
    if !gated {
        return Ok(());
    }
    let supplied = extract_bearer(request.headers());
    let ok = supplied
        .as_deref()
        .map(|s| ct_eq(s.as_bytes(), expected.as_bytes()))
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            "missing or invalid bearer token (set Authorization: Bearer <RUVIEW_API_TOKEN>, \
             or Sec-WebSocket-Protocol: bearer.<token> for browser WebSockets)\n",
        )
            .into_response())
    }
}

/// Axum middleware: enforces bearer auth on `/api/v1/*` only. WebSockets are
/// left open. Kept for backward compatibility — prefer
/// [`require_bearer_strict`] for new deployments.
pub async fn require_bearer(
    State(auth): State<AuthState>,
    request: Request,
    next: Next,
) -> Response {
    match check(&auth, &request, false) {
        Ok(()) => next.run(request).await,
        Err(resp) => resp,
    }
}

/// Axum middleware: enforces bearer auth on `/api/v1/*` AND `/ws/*` upgrades.
/// This is what an operator deploying outside a fully trusted LAN actually
/// wants — the WebSocket stream carries the live biometric telemetry and
/// should not be reachable anonymously.
pub async fn require_bearer_strict(
    State(auth): State<AuthState>,
    request: Request,
    next: Next,
) -> Response {
    match check(&auth, &request, true) {
        Ok(()) => next.run(request).await,
        Err(resp) => resp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    fn ok_handler() -> Router {
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .route("/api/v1/info", get(|| async { "ok" }))
            .route("/api/v1/sensitive", axum::routing::post(|| async { "ok" }))
            .route("/ws/sensing", get(|| async { "ok" }))
            .route("/ui/index.html", get(|| async { "<html/>" }))
    }

    fn wrap(auth: AuthState) -> Router {
        ok_handler()
            .layer(axum::middleware::from_fn_with_state(auth, require_bearer))
    }

    fn wrap_strict(auth: AuthState) -> Router {
        ok_handler()
            .layer(axum::middleware::from_fn_with_state(auth, require_bearer_strict))
    }

    async fn status(router: Router, method: &str, path: &str, auth: Option<&str>) -> StatusCode {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        if let Some(t) = auth {
            req.headers_mut()
                .insert(AUTHORIZATION, format!("Bearer {t}").parse().unwrap());
        }
        router.oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn middleware_is_no_op_when_token_unset() {
        let r = wrap(AuthState::default());
        assert_eq!(status(r.clone(), "GET", "/api/v1/info", None).await, StatusCode::OK);
        assert_eq!(status(r.clone(), "POST", "/api/v1/sensitive", None).await, StatusCode::OK);
        assert_eq!(status(r.clone(), "GET", "/health", None).await, StatusCode::OK);
        assert_eq!(status(r, "GET", "/ui/index.html", None).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn enabled_blocks_api_without_bearer() {
        let r = wrap(AuthState::from_token("s3cr3t"));
        assert_eq!(status(r.clone(), "GET", "/api/v1/info", None).await, StatusCode::UNAUTHORIZED);
        assert_eq!(
            status(r, "POST", "/api/v1/sensitive", None).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn enabled_blocks_api_with_wrong_bearer() {
        let r = wrap(AuthState::from_token("s3cr3t"));
        assert_eq!(
            status(r.clone(), "GET", "/api/v1/info", Some("nope")).await,
            StatusCode::UNAUTHORIZED
        );
        // Wrong scheme (Basic / token) — only "Bearer <token>" is accepted.
        let mut req = Request::builder()
            .method("GET")
            .uri("/api/v1/info")
            .body(Body::empty())
            .unwrap();
        req.headers_mut()
            .insert(AUTHORIZATION, "Basic s3cr3t".parse().unwrap());
        assert_eq!(r.oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn enabled_allows_api_with_correct_bearer() {
        let r = wrap(AuthState::from_token("s3cr3t"));
        assert_eq!(
            status(r.clone(), "GET", "/api/v1/info", Some("s3cr3t")).await,
            StatusCode::OK
        );
        assert_eq!(
            status(r, "POST", "/api/v1/sensitive", Some("s3cr3t")).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn enabled_never_gates_paths_outside_api_v1() {
        let r = wrap(AuthState::from_token("s3cr3t"));
        // Even with auth ON, `/health` and `/ui/*` are reachable without a token:
        // orchestrator probes and the local UI need to load unchallenged.
        assert_eq!(status(r.clone(), "GET", "/health", None).await, StatusCode::OK);
        assert_eq!(status(r, "GET", "/ui/index.html", None).await, StatusCode::OK);
    }

    #[test]
    fn ct_eq_basics() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));   // length mismatch
        assert!(!ct_eq(b"", b"x"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn from_env_treats_empty_as_disabled() {
        // Avoid touching the real env in a thread-shared test — exercise the
        // string ctor directly with the same trim logic.
        assert!(!AuthState::from_token("").is_enabled());
        assert!(AuthState::from_token("x").is_enabled());
    }

    #[test]
    fn protected_prefix_and_env_constants_are_stable() {
        // These are documented in the issue body and the README; keep them locked.
        assert_eq!(API_TOKEN_ENV, "RUVIEW_API_TOKEN");
        assert_eq!(PROTECTED_PREFIX, "/api/v1/");
        assert_eq!(WS_PREFIX, "/ws/");
        assert_eq!(WS_BEARER_SUBPROTOCOL_PREFIX, "bearer.");
    }

    #[tokio::test]
    async fn strict_gates_ws_when_token_set() {
        let r = wrap_strict(AuthState::from_token("s3cr3t"));
        // No token → 401 on the WS upgrade path
        assert_eq!(status(r.clone(), "GET", "/ws/sensing", None).await, StatusCode::UNAUTHORIZED);
        // Authorization header still works
        assert_eq!(status(r.clone(), "GET", "/ws/sensing", Some("s3cr3t")).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn strict_accepts_token_via_ws_subprotocol() {
        let r = wrap_strict(AuthState::from_token("s3cr3t"));
        let mut req = Request::builder()
            .method("GET")
            .uri("/ws/sensing")
            .body(Body::empty())
            .unwrap();
        req.headers_mut().insert(
            "sec-websocket-protocol",
            "v1.sensing, bearer.s3cr3t".parse().unwrap(),
        );
        assert_eq!(r.oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn strict_rejects_wrong_subprotocol_token() {
        let r = wrap_strict(AuthState::from_token("s3cr3t"));
        let mut req = Request::builder()
            .method("GET")
            .uri("/ws/sensing")
            .body(Body::empty())
            .unwrap();
        req.headers_mut()
            .insert("sec-websocket-protocol", "bearer.nope".parse().unwrap());
        assert_eq!(r.oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn strict_is_no_op_when_token_unset() {
        let r = wrap_strict(AuthState::default());
        assert_eq!(status(r.clone(), "GET", "/ws/sensing", None).await, StatusCode::OK);
        assert_eq!(status(r, "GET", "/api/v1/info", None).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn strict_never_gates_health_or_ui() {
        let r = wrap_strict(AuthState::from_token("s3cr3t"));
        assert_eq!(status(r.clone(), "GET", "/health", None).await, StatusCode::OK);
        assert_eq!(status(r, "GET", "/ui/index.html", None).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn lax_middleware_still_leaves_ws_open() {
        // Legacy behaviour preserved — `require_bearer` does NOT gate /ws/*.
        let r = wrap(AuthState::from_token("s3cr3t"));
        assert_eq!(status(r, "GET", "/ws/sensing", None).await, StatusCode::OK);
    }
}
