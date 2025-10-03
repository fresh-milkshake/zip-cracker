//! Configuration Management
//!
//! Handles loading and validation of configuration from CLI arguments.

use crate::cli::{Args, AttackMode};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub zip_file: PathBuf,
    pub attack_mode: AttackMode,
    pub charset: String,
    pub min_length: usize,
    pub max_length: usize,
    pub dictionary: Option<PathBuf>,
    pub threads: usize,
    pub gpu_enabled: bool,
    pub resume_file: Option<PathBuf>,
    pub output_file: Option<PathBuf>,
    pub verbose: bool,
    pub quiet: bool,
    pub show_progress: bool,
}

impl Config {
    /// Load configuration from CLI arguments
    pub fn load(args: &Args) -> Result<Self, String> {
        // Validate ZIP file exists
        if !args.zip_file.exists() {
            return Err(format!("ZIP file does not exist: {:?}", args.zip_file));
        }

        // Validate charset is not empty
        if args.charset.is_empty() {
            return Err("Character set cannot be empty".to_string());
        }

        // Validate length constraints
        if args.min_length == 0 {
            return Err("Minimum length must be at least 1".to_string());
        }

        if args.min_length > args.max_length {
            return Err("Minimum length cannot be greater than maximum length".to_string());
        }

        // Validate dictionary file if provided
        if let Some(ref dict_path) = args.dictionary {
            if !dict_path.as_path().exists() {
                return Err(format!("Dictionary file does not exist: {:?}", dict_path));
            }
        }

        // Validate attack mode requirements
        match args.mode {
            AttackMode::Dictionary | AttackMode::Hybrid => {
                if args.dictionary.is_none() {
                    return Err(
                        "Dictionary file is required for dictionary or hybrid attack".to_string(),
                    );
                }
            }
            _ => {}
        }

        // Determine number of threads (at least 1)
        let threads = if args.threads == 0 {
            num_cpus::get().max(1)
        } else {
            args.threads.max(1)
        };

        let config = Config {
            zip_file: args.zip_file.clone(),
            attack_mode: args.mode.clone(),
            charset: args.charset.clone(),
            min_length: args.min_length,
            max_length: args.max_length,
            dictionary: args.dictionary.clone(),
            threads,
            gpu_enabled: args.gpu,
            resume_file: args.resume.clone(),
            output_file: args.output.clone(),
            verbose: args.verbose,
            quiet: args.quiet,
            show_progress: args.progress,
        };

        config.validate()?;
        Ok(config)
    }

    /// Get unique characters from charset
    pub fn get_unique_chars(&self) -> Vec<char> {
        let mut chars: HashSet<char> = self.charset.chars().collect();
        let mut result: Vec<char> = chars.drain().collect();
        result.sort_unstable();
        result
    }

    /// Calculate total password space size for brute force
    pub fn calculate_password_space(&self) -> u64 {
        let charset_size = self.charset.len() as u64;
        let mut total = 0u64;

        for length in self.min_length..=self.max_length {
            total = total.saturating_add(charset_size.pow(length as u32));
        }

        total
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        // Warn if charset has duplicates
        let unique_chars = self.get_unique_chars();
        if unique_chars.len() != self.charset.len() {
            log::warn!(
                "Character set contains duplicates, using {} unique characters",
                unique_chars.len()
            );
        }

        // Warn if password space is very large
        let space_size = self.calculate_password_space();
        if space_size > 1_000_000_000_000 {
            log::warn!("Password space is very large: {} combinations", space_size);
        }

        Ok(())
    }
}

/// Convenience wrapper matching the original API used by `main`
pub fn load(args: &Args) -> Result<Config, String> {
    Config::load(args)
}
