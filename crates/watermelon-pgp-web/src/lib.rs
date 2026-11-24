//! The web UI: server-rendered pages (maud) progressively enhanced with htmx.
//!
//! Every page works without JavaScript. All state lives in the vault; the only in-memory state
//! is login sessions and the login rate limiter, so a restart logs everyone out.

mod auth;
mod error;
mod routes;
mod views;

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    extract::Request,
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use tokio::net::TcpListener;
use watermelon_pgp_core::vault::Vault;

pub use auth::SESSION_COOKIE;
use auth::{LoginLimiter, Sessions};
use error::AppError;

/// Process-level web settings.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Mark the session cookie `Secure`; set when users reach the UI over HTTPS.
    pub secure_cookies: bool,
}

/// Shared by all requests.
#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    vault: Arc<Mutex<Vault>>,
    sessions: Sessions,
    limiter: LoginLimiter,
    config: Config,
}

impl AppState {
    pub fn new(vault: Arc<Mutex<Vault>>, config: Config) -> Self {
        Self(Arc::new(Inner {
            vault,
            sessions: Sessions::default(),
            limiter: LoginLimiter::default(),
            config,
        }))
    }

    /// Run `f` with the vault on a blocking thread. The vault lock is shared with the job
    /// engine, so `f` should only do database work.
    async fn vault<T, F>(&self, f: F) -> Result<T, AppError>
    where
        T: Send + 'static,
        F: FnOnce(&Vault) -> watermelon_pgp_core::Result<T> + Send + 'static,
    {
        let vault = Arc::clone(&self.0.vault);
        tokio::task::spawn_blocking(move || {
            let vault = vault
                .lock()
                .map_err(|_| AppError::internal("vault lock poisoned"))?;
            f(&vault).map_err(AppError::from)
        })
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
    }

    fn sessions(&self) -> &Sessions {
        &self.0.sessions
    }

    fn limiter(&self) -> &LoginLimiter {
        &self.0.limiter
    }

    fn config(&self) -> &Config {
        &self.0.config
    }
}

pub fn router(state: AppState) -> Router {
    routes::router()
        .layer(middleware::from_fn(reject_cross_origin))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// Serve until `shutdown` resolves.
pub async fn serve(
    state: AppState,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
    connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in [
        (header::CONTENT_SECURITY_POLICY, CSP),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "same-origin"),
        (
            header::HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    // Pages show key material and audit data: keep them out of caches. Static assets set
    // their own policy.
    headers
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    response
}

/// Defence in depth on top of SameSite cookies and CSRF tokens: browsers send `Origin` (and
/// `Sec-Fetch-Site`) on state-changing requests, so refuse those that come from another site.
async fn reject_cross_origin(request: Request, next: Next) -> Response {
    if request.method() == Method::GET || request.method() == Method::HEAD {
        return next.run(request).await;
    }
    let headers = request.headers();
    let cross_site = headers
        .get("sec-fetch-site")
        .is_some_and(|v| v.as_bytes() == b"cross-site");
    let origin_mismatch = match (headers.get(header::ORIGIN), headers.get(header::HOST)) {
        (Some(origin), Some(host)) => {
            let origin = origin.to_str().unwrap_or("");
            let authority = origin.split_once("://").map_or("", |(_, rest)| rest);
            authority.as_bytes() != host.as_bytes()
        }
        (Some(_), None) => true,
        (None, _) => false,
    };
    if cross_site || origin_mismatch {
        return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
    }
    next.run(request).await
}
