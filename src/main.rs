//! ZIP Cracker - High-performance password recovery tool
//!
//! This is the main entry point for the CLI application.

use clap::Parser;
use std::fs;
use std::process;
use zip_cracker::{cli, config, engine, logging};

fn main() {
    // Parse command line arguments
    let args = cli::Args::parse();

    // Initialize logging based on CLI flags
    if let Err(e) = logging::init(args.verbose, args.quiet) {
        eprintln!("Failed to initialize logging: {e}");
        process::exit(1);
    }

    // Load configuration
    let config = match config::load(&args) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Configuration error: {e}");
            process::exit(1);
        }
    };

    match engine::run(&config) {
        Ok(Some(password)) => {
            println!("Password found: {password}");
            if let Some(output_file) = &config.output_file {
                if let Err(e) = fs::write(output_file, &password) {
                    eprintln!("Failed to write output file: {e}");
                }
            }
        }
        Ok(None) => {
            println!("Password not found");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("Error running cracker: {e}");
            process::exit(1);
        }
    }
}
