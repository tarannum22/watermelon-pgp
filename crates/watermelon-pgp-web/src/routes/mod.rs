mod audit;
mod customers;
mod dashboard;
mod jobs;
mod keys;
mod session;
mod settings;

use std::collections::HashMap;

use axum::{
    Router,
    extract::Path,
    http::{StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use watermelon_pgp_core::{jobs::Job, store::Customer};

use crate::{
    AppState,
    auth::{Authed, Flash},
    error::AppError,
    views::{AuditNames, Nav, Page},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(dashboard::show))
        .route("/dashboard/live", get(dashboard::live))
        .route("/login", get(session::login_form).post(session::login))
        .route("/logout", post(session::logout))
        .route("/healthz", get(health))
        .route("/static/{file}", get(static_file))
        .route("/customers", get(customers::list).post(customers::create))
        .route("/customers/{id}", get(customers::show))
        .route("/customers/{id}/keys/generate", post(keys::generate))
        .route("/customers/{id}/keys/import", post(keys::import))
        .route("/keys", get(keys::list))
        .route("/keys/{fpr}", get(keys::show))
        .route("/keys/{fpr}/public", post(keys::export_public))
        .route("/keys/{fpr}/secret", post(keys::export_secret))
        .route("/keys/{fpr}/delete", post(keys::delete))
        .route("/jobs", get(jobs::list).post(jobs::create))
        .route("/jobs/new", get(jobs::new_form))
        .route("/jobs/{id}", get(jobs::show).post(jobs::update))
        .route("/jobs/{id}/edit", get(jobs::edit_form))
        .route("/jobs/{id}/live", get(jobs::live))
        .route("/jobs/{id}/enable", post(jobs::enable))
        .route("/jobs/{id}/disable", post(jobs::disable))
        .route("/jobs/{id}/delete", post(jobs::delete))
        .route("/jobs/{id}/retry", post(jobs::retry))
        .route("/audit", get(audit::list))
        .route("/settings", get(settings::show))
        .route("/settings/password", post(settings::change_password))
        .fallback(|| async { AppError::not_found("no such page") })
}

impl AppState {
    fn page<'a>(&self, auth: &'a Authed, title: &'a str, nav: Nav) -> Page<'a> {
        Page {
            title,
            nav,
            csrf: &auth.csrf,
            flash: self.sessions().take_flash(auth.key),
        }
    }

    /// Finish a form submission: show the outcome on the next page and go there.
    fn done(&self, auth: &Authed, to: &str, outcome: Result<String, AppError>) -> Redirect {
        let flash = match outcome {
            Ok(message) => Flash::Success(message),
            Err(e) => Flash::Error(e.message().to_owned()),
        };
        self.sessions().flash(auth.key, flash);
        Redirect::to(to)
    }
}

/// A form with nothing but the CSRF token.
#[derive(Deserialize)]
pub struct Empty {}

/// A form guarded by [`crate::views::confirm_box`].
#[derive(Deserialize)]
pub struct Confirmed {
    #[serde(default)]
    confirm: String,
}

impl Confirmed {
    fn check(&self) -> Result<(), AppError> {
        if self.confirm == "yes" {
            Ok(())
        } else {
            Err(AppError::bad_request("tick the confirmation box first"))
        }
    }
}

/// Customer and job names for rendering audit events.
struct Names {
    customers: HashMap<i64, String>,
    jobs: HashMap<i64, String>,
}

impl Names {
    fn new(customers: &[Customer], jobs: &[Job]) -> Self {
        Self {
            customers: customers.iter().map(|c| (c.id, c.name.clone())).collect(),
            jobs: jobs.iter().map(|j| (j.id, j.spec.name.clone())).collect(),
        }
    }
}

impl AuditNames for Names {
    fn customer(&self, id: i64) -> Option<&str> {
        self.customers.get(&id).map(String::as_str)
    }

    fn job(&self, id: i64) -> Option<&str> {
        self.jobs.get(&id).map(String::as_str)
    }
}

/// Liveness and database check for load balancers and monitoring. No login required.
async fn health(state: axum::extract::State<AppState>) -> Response {
    match state.vault(|vault| vault.customers().map(|_| ())).await {
        Ok(()) => (
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"status":"ok"}"#,
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"status":"error"}"#,
        )
            .into_response(),
    }
}

/// Assets are embedded in the binary. URLs carry the version, so they can be cached forever.
async fn static_file(Path(file): Path<String>) -> Response {
    let (content_type, body): (&str, &'static [u8]) = match file.as_str() {
        "htmx.min.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("../../assets/htmx.min.js"),
        ),
        "app.css" => (
            "text/css; charset=utf-8",
            include_bytes!("../../assets/app.css"),
        ),
        "logo.svg" => ("image/svg+xml", include_bytes!("../../assets/logo.svg")),
        _ => return AppError::not_found("no such file").into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        body,
    )
        .into_response()
}

/// `?customer=` style query values: blank means "not set".
fn parse_id(value: &str) -> Option<i64> {
    value.trim().parse().ok()
}
