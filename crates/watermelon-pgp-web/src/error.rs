use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use watermelon_pgp_core::Error;

use crate::views;

/// An error shown to the user. Internal details are logged, not displayed.
#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    message: String,
}

impl AppError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    pub fn internal(detail: impl std::fmt::Display) -> Self {
        tracing::error!(%detail, "internal error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error, see the server log",
        )
    }

    /// What the user sees.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl From<Error> for AppError {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound(what) => Self::not_found(format!("not found: {what}")),
            Error::Invalid(message) => Self::bad_request(message),
            Error::Conflict(message) => Self::new(StatusCode::CONFLICT, message),
            // Almost always caused by the uploaded or pasted data.
            Error::Pgp(e) => Self::bad_request(format!("OpenPGP: {e}")),
            e @ (Error::Db(_) | Error::Io(_) | Error::MasterKey(_) | Error::Unseal) => {
                Self::internal(e)
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status, views::error_page(self.status, &self.message)).into_response()
    }
}
