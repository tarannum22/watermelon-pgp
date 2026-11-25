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
    field: Option<&'static str>,
}

impl AppError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            field: None,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    /// Bad input in the form field named `field`, which a form can show the message next to.
    pub fn invalid_field(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field: Some(field),
            ..Self::bad_request(message)
        }
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

    /// The form field to blame, if one is.
    pub fn field(&self) -> Option<&'static str> {
        self.field
    }
}

impl From<Error> for AppError {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound(what) => Self::not_found(format!("not found: {what}")),
            Error::Invalid(message) => Self::bad_request(message),
            Error::InvalidField { field, message } => Self::invalid_field(field, message),
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
