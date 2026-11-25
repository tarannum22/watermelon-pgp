//! Core of watermelon-pgp: OpenPGP operations, the master-key envelope, the SQLite store and
//! the audit log.

pub mod audit;
pub mod crypto;
pub mod envelope;
mod error;
pub mod jobs;
pub mod platform;
pub mod store;
pub mod vault;

pub use error::{Error, Result};
