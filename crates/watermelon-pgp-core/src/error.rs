#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("OpenPGP: {0}")]
    Pgp(#[from] pgp::errors::Error),
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("master key: {0}")]
    MasterKey(String),
    #[error("sealed data could not be opened (wrong master key or corrupted database)")]
    Unseal,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("{0}")]
    Invalid(String),
    /// Invalid input that one field of a form is to blame for, so a form can show the message
    /// next to it. `field` is the name of the form field (`input`, `recipients`, …).
    #[error("{message}")]
    InvalidField {
        field: &'static str,
        message: String,
    },
}

impl Error {
    pub fn invalid_field(field: &'static str, message: impl Into<String>) -> Self {
        Error::InvalidField {
            field,
            message: message.into(),
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
