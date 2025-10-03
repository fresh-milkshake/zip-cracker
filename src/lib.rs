//! ZIP Cracker Library
//!
//! A high-performance password recovery tool for ZIP archives.
//!
//! This library provides functionality for:
//! - Brute force password attacks
//! - Dictionary-based attacks
//! - Progress tracking and resumption
//!
pub mod cli;
pub mod config;
pub mod engine;
pub mod logging;

// Re-export main types for convenience
pub use cli::{Args, AttackMode};
pub use config::Config;
pub use engine::CrackerEngine;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Library description
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

/// Library authors
pub const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
