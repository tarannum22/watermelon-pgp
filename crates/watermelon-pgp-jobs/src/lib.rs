//! Folder jobs: watch an input folder and encrypt or decrypt every file that lands in it.

pub mod engine;
pub mod failed;
mod platform;
pub mod process;
pub mod scan;

pub use engine::{Engine, PassReport, run_pass};
