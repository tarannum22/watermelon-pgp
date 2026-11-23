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
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
