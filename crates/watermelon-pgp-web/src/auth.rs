//! Login sessions, CSRF tokens and login rate limiting.
//!
//! Sessions are random 256-bit tokens in an `HttpOnly`, `SameSite=Strict` cookie; the server
//! keeps only their SHA-256, so a memory dump of the session table can't be replayed. Every
//! state-changing form carries the session's CSRF token in a `_csrf` field.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{
    body::Bytes,
    extract::{ConnectInfo, FromRequest, FromRequestParts, Request},
    http::{HeaderMap, HeaderValue, header, request::Parts},
    response::{IntoResponse, Redirect, Response},
};
use rand::{RngCore, rngs::OsRng};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use crate::{AppState, error::AppError};

pub const SESSION_COOKIE: &str = "watermelon_session";
pub const CSRF_FIELD: &str = "_csrf";
/// A session ends after this long without a request...
const IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// ...and in any case this long after login.
const MAX_SESSION_AGE: Duration = Duration::from_secs(12 * 60 * 60);
/// Failed logins allowed from one client before it has to wait.
const FREE_ATTEMPTS: u32 = 5;
const MAX_LOCKOUT: Duration = Duration::from_secs(15 * 60);
/// Bound the limiter's memory when many clients fail.
const MAX_TRACKED_CLIENTS: usize = 10_000;

/// A one-time message shown on the next page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flash {
    Success(String),
    Error(String),
}

/// The server-side identity of a session: the SHA-256 of its cookie token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKey([u8; 32]);

impl SessionKey {
    fn of(token: &str) -> Self {
        Self(Sha256::digest(token.as_bytes()).into())
    }
}

struct SessionData {
    csrf: String,
    created: Instant,
    last_seen: Instant,
    flash: Option<Flash>,
}

impl SessionData {
    fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.last_seen) > IDLE_TIMEOUT
            || now.duration_since(self.created) > MAX_SESSION_AGE
    }
}

#[derive(Default)]
pub struct Sessions {
    map: Mutex<HashMap<SessionKey, SessionData>>,
}

impl Sessions {
    /// Start a session and return its cookie token.
    pub fn create(&self) -> String {
        let token = random_token();
        let now = Instant::now();
        let mut map = self.map.lock().unwrap();
        map.retain(|_, data| !data.expired(now));
        map.insert(
            SessionKey::of(&token),
            SessionData {
                csrf: random_token(),
                created: now,
                last_seen: now,
                flash: None,
            },
        );
        token
    }

    /// The live session for `token`, refreshing its idle timer.
    #[cfg(test)]
    fn touch(&self, token: &str) -> Option<(SessionKey, String)> {
        self.touch_at(token, Instant::now())
    }

    #[cfg(test)]
    fn touch_at(&self, token: &str, now: Instant) -> Option<(SessionKey, String)> {
        self.lookup(token, now, true)
    }

    fn lookup(&self, token: &str, now: Instant, touch: bool) -> Option<(SessionKey, String)> {
        let key = SessionKey::of(token);
        let mut map = self.map.lock().unwrap();
        let data = map.get_mut(&key)?;
        if data.expired(now) {
            map.remove(&key);
            return None;
        }
        if touch {
            data.last_seen = now;
        }
        Some((key, data.csrf.clone()))
    }

    pub fn remove(&self, key: SessionKey) {
        self.map.lock().unwrap().remove(&key);
    }

    /// End every session except `keep`, e.g. after a password change.
    pub fn remove_others(&self, keep: SessionKey) {
        self.map.lock().unwrap().retain(|key, _| *key == keep);
    }

    pub fn flash(&self, key: SessionKey, flash: Flash) {
        if let Some(data) = self.map.lock().unwrap().get_mut(&key) {
            data.flash = Some(flash);
        }
    }

    pub fn take_flash(&self, key: SessionKey) -> Option<Flash> {
        self.map.lock().unwrap().get_mut(&key)?.flash.take()
    }
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn session_cookie(token: &str, secure: bool) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict{secure}"
    ))
    .expect("token is hex")
}

pub fn clear_cookie(secure: bool) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}"
    ))
    .expect("static cookie")
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

/// Where a request came from, for the audit log and rate limiting.
pub fn client(parts: &Parts) -> String {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map_or_else(|| "unknown".to_owned(), |info| info.0.ip().to_string())
}

/// A logged-in request. Extracting it redirects anonymous requests to the login page.
pub struct Authed {
    pub key: SessionKey,
    pub csrf: String,
    pub client: String,
}

impl Authed {
    pub fn check_csrf(&self, token: &str) -> Result<(), AppError> {
        if constant_time_eq(token.as_bytes(), self.csrf.as_bytes()) {
            Ok(())
        } else {
            Err(AppError::new(
                axum::http::StatusCode::FORBIDDEN,
                "the form has expired; reload the page and try again",
            ))
        }
    }
}

impl Authed {
    fn extract(parts: &Parts, state: &AppState, touch: bool) -> Option<Self> {
        let token = cookie(&parts.headers, SESSION_COOKIE)?;
        let (key, csrf) = state.sessions().lookup(token, Instant::now(), touch)?;
        Some(Self {
            key,
            csrf,
            client: client(parts),
        })
    }
}

/// Where an anonymous request is sent.
fn to_login(parts: &Parts) -> Response {
    if parts.headers.contains_key("hx-request") {
        // Make htmx do a full page load of the login page.
        ([("hx-redirect", "/login")], "").into_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

impl FromRequestParts<AppState> for Authed {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        Self::extract(parts, state, true).ok_or_else(|| to_login(parts))
    }
}

/// Like [`Authed`], but doesn't count as activity: for auto-refreshing panels, which would
/// otherwise keep an unattended session alive forever.
pub struct Watching(pub Authed);

impl FromRequestParts<AppState> for Watching {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        Authed::extract(parts, state, false)
            .map(Self)
            .ok_or_else(|| to_login(parts))
    }
}

/// The client's IP address, or `unknown`.
pub struct Client(pub String);

impl<S: Send + Sync> FromRequestParts<S> for Client {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(client(parts)))
    }
}

/// A logged-in, CSRF-checked form submission.
pub struct Posted<T> {
    pub auth: Authed,
    pub form: T,
}

impl<T: DeserializeOwned> FromRequest<AppState> for Posted<T> {
    type Rejection = Response;

    async fn from_request(request: Request, state: &AppState) -> Result<Self, Response> {
        let (mut parts, body) = request.into_parts();
        let auth = Authed::from_request_parts(&mut parts, state).await?;
        let bytes = Bytes::from_request(Request::from_parts(parts, body), state)
            .await
            .map_err(IntoResponse::into_response)?;
        let fields: Vec<(String, String)> = serde_html_form::from_bytes(&bytes)
            .map_err(|e| AppError::bad_request(format!("malformed form: {e}")).into_response())?;
        let token = fields
            .iter()
            .find(|(name, _)| name == CSRF_FIELD)
            .map_or("", |(_, value)| value.as_str());
        auth.check_csrf(token)
            .map_err(IntoResponse::into_response)?;
        let form = serde_html_form::from_bytes(&bytes)
            .map_err(|e| AppError::bad_request(format!("malformed form: {e}")).into_response())?;
        Ok(Self { auth, form })
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

struct Attempts {
    failures: u32,
    locked_until: Option<Instant>,
}

/// Slows down password guessing: after a few failures a client must wait, doubling each time.
#[derive(Default)]
pub struct LoginLimiter {
    map: Mutex<HashMap<String, Attempts>>,
}

impl LoginLimiter {
    /// `Err(wait)` while the client is locked out.
    pub fn check(&self, client: &str) -> Result<(), Duration> {
        let map = self.map.lock().unwrap();
        match map.get(client).and_then(|a| a.locked_until) {
            Some(until) if until > Instant::now() => Err(until - Instant::now()),
            _ => Ok(()),
        }
    }

    pub fn failed(&self, client: &str) {
        let now = Instant::now();
        let mut map = self.map.lock().unwrap();
        if map.len() >= MAX_TRACKED_CLIENTS && !map.contains_key(client) {
            map.retain(|_, a| a.locked_until.is_some_and(|until| until > now));
        }
        let attempts = map.entry(client.to_owned()).or_insert(Attempts {
            failures: 0,
            locked_until: None,
        });
        attempts.failures += 1;
        if attempts.failures >= FREE_ATTEMPTS {
            let doublings = (attempts.failures - FREE_ATTEMPTS).min(20);
            let wait = Duration::from_secs(1 << doublings).min(MAX_LOCKOUT);
            attempts.locked_until = Some(now + wait);
        }
    }

    pub fn succeeded(&self, client: &str) {
        self.map.lock().unwrap().remove(client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_locks_out_after_repeated_failures() {
        let limiter = LoginLimiter::default();
        for _ in 0..FREE_ATTEMPTS - 1 {
            limiter.failed("a");
            assert!(limiter.check("a").is_ok());
        }
        limiter.failed("a");
        assert!(limiter.check("a").is_err());
        assert!(limiter.check("b").is_ok(), "other clients unaffected");
        limiter.succeeded("a");
        assert!(limiter.check("a").is_ok());
    }

    #[test]
    fn sessions_expire_and_can_be_revoked() {
        let sessions = Sessions::default();
        let token = sessions.create();
        let (key, csrf) = sessions.touch(&token).unwrap();
        assert_eq!(csrf.len(), 64);
        assert!(sessions.touch("not-a-session").is_none());

        sessions.flash(key, Flash::Success("hi".into()));
        assert_eq!(sessions.take_flash(key), Some(Flash::Success("hi".into())));
        assert_eq!(sessions.take_flash(key), None);

        let later = Instant::now() + IDLE_TIMEOUT * 2;
        assert!(
            sessions.touch_at(&token, later).is_none(),
            "idle session expired"
        );
        assert!(sessions.touch(&token).is_none(), "and was removed");

        let a = sessions.create();
        let b = sessions.create();
        let (keep, _) = sessions.touch(&a).unwrap();
        sessions.remove_others(keep);
        assert!(sessions.touch(&a).is_some());
        assert!(sessions.touch(&b).is_none());
    }

    #[test]
    fn reads_cookie_among_others() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; watermelon_session=abc; b=2"),
        );
        assert_eq!(cookie(&headers, SESSION_COOKIE), Some("abc"));
        assert_eq!(cookie(&headers, "missing"), None);
    }
}
