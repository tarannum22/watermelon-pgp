//! Core of watermelon-pgp: OpenPGP operations, the master-key envelope, the SQLite store and
//! the audit log.

pub mod audit;
pub mod crypto;
pub mod envelope;
mod error;
pub mod jobs;
mod platform;
pub mod store;
pub mod vault;

pub use error::{Error, Result};
/// For the CLI's secret-key exports.
pub use platform::write_private_file;
