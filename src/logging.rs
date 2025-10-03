//! Logging utilities
//!
//! Provides a thin wrapper around `env_logger` so the rest of the
//! application can choose the verbosity level.

use env_logger::{Builder, Env};
use log::LevelFilter;
use std::io::Write;

/// Initialize the global logger based on CLI flags.
pub fn init(verbose: bool, quiet: bool) -> Result<(), String> {
    let mut builder = Builder::from_env(Env::default());

    let level = if quiet {
        LevelFilter::Warn
    } else if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    builder.filter_level(level);
    builder.format(|buf, record| {
        writeln!(
            buf,
            "{} [{}] {}",
            buf.timestamp_millis(),
            record.level(),
            record.args()
        )
    });

    builder.try_init().map_err(|e| e.to_string())
}
