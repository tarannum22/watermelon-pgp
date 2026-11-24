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
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Router,
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use watermelon_pgp_core::vault::Vault;

pub use auth::SESSION_COOKIE;
use auth::{LoginLimiter, Sessions};
use error::AppError;

/// Process-level web settings.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Mark the session cookie `Secure`; set when users reach the UI over HTTPS.
    pub secure_cookies: bool,
    /// Send `Strict-Transport-Security`; set when serving HTTPS ourselves.
    pub hsts: bool,
}

/// A TLS certificate and key, reloadable while serving.
#[derive(Clone)]
pub struct Tls(RustlsConfig);

impl Tls {
    /// Load a PEM certificate chain and private key.
    pub async fn load(cert: &Path, key: &Path) -> std::io::Result<Self> {
        RustlsConfig::from_pem_file(cert, key).await.map(Self)
    }

    /// Swap in renewed files; new connections use them, open ones keep the old certificate.
    pub async fn reload(&self, cert: &Path, key: &Path) -> std::io::Result<()> {
        self.0.reload_from_pem_file(cert, key).await
    }
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
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .layer(middleware::from_fn(log_request))
        .with_state(state)
}

/// How long open requests get to finish once shutdown starts.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Serve on `listener` (HTTPS when `tls` is given) until `shutdown` resolves.
pub async fn serve(
    state: AppState,
    listener: std::net::TcpListener,
    tls: Option<Tls>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    let handle = Handle::new();
    {
        let handle = handle.clone();
        tokio::spawn(async move {
            shutdown.await;
            handle.graceful_shutdown(Some(SHUTDOWN_GRACE));
        });
    }
    let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
    match tls {
        Some(Tls(config)) => {
            axum_server::from_tcp_rustls(listener, config)?
                .handle(handle)
                .serve(app)
                .await
        }
        None => {
            axum_server::from_tcp(listener)?
                .handle(handle)
                .serve(app)
                .await
        }
    }
}

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
    connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

async fn security_headers(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    if state.config().hsts {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
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

/// One log line per request. Static assets and the health check stay quiet unless they fail.
async fn log_request(request: Request, next: Next) -> Response {
    let started = Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let client = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string());
    let response = next.run(request).await;
    let status = response.status().as_u16();
    let millis = started.elapsed().as_millis() as u64;
    let routine = path.starts_with("/static/") || path == "/healthz" || path.ends_with("/live");
    if status >= 500 {
        tracing::error!(%method, path, status, millis, client, "request");
    } else if !routine || status >= 400 {
        tracing::info!(%method, path, status, millis, client, "request");
    } else {
        tracing::debug!(%method, path, status, millis, client, "request");
    }
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
    // HTTP/1.1 names the target in `Host`; HTTP/2 (what browsers use over TLS) in the
    // `:authority` pseudo-header, which ends up in the request URI.
    let host = headers
        .get(header::HOST)
        .and_then(|host| host.to_str().ok())
        .or_else(|| request.uri().authority().map(|a| a.as_str()));
    let origin_mismatch = match (headers.get(header::ORIGIN), host) {
        (Some(origin), Some(host)) => {
            let origin = origin.to_str().unwrap_or("");
            let authority = origin.split_once("://").map_or("", |(_, rest)| rest);
            authority != host
        }
        (Some(_), None) => true,
        (None, _) => false,
    };
    if cross_site || origin_mismatch {
        return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
    }
    next.run(request).await
}
