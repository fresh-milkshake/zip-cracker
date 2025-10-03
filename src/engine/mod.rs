//! Cracker engine coordinating brute-force and dictionary attacks.

pub mod brute_force;
pub mod checker;
pub mod dictionary;
pub mod gpu;

use crate::cli::AttackMode;
use crate::config::Config;
use checker::PasswordChecker;
use std::collections::HashSet;

/// Main orchestrator for the cracking process.
pub struct CrackerEngine {
    config: Config,
    checker: PasswordChecker,
}

impl CrackerEngine {
    pub fn new(config: Config) -> Result<Self, String> {
        let checker = PasswordChecker::new(&config.zip_file)?;
        log::info!(
            "ZIP archive contains {} file(s), {} encrypted",
            checker.file_count(),
            checker.encrypted_count()
        );

        Ok(Self { config, checker })
    }

    pub fn run(&self) -> Result<Option<String>, String> {
        match self.config.attack_mode {
            AttackMode::BruteForce => self.run_brute_force(),
            AttackMode::Dictionary => self.run_dictionary(),
            AttackMode::Hybrid => self.run_hybrid(),
        }
    }

    fn run_brute_force(&self) -> Result<Option<String>, String> {
        log::info!("Starting brute force attack");
        log::info!(
            "Length range: {}-{}",
            self.config.min_length,
            self.config.max_length
        );

        let mut seen = HashSet::new();
        let charset: Vec<char> = self
            .config
            .charset
            .chars()
            .filter(|ch| seen.insert(*ch))
            .collect();

        log::info!("Effective character set size: {}", charset.len());

        if self.config.gpu_enabled {
            log::info!("GPU flag enabled; attempting accelerated search");
            match gpu::crack(
                &self.checker,
                charset.clone(),
                self.config.min_length,
                self.config.max_length,
                self.config.threads,
                self.config.show_progress,
            ) {
                Ok(result @ Some(_)) => return Ok(result),
                Ok(None) => return Ok(None),
                Err(err) => {
                    log::warn!("GPU path failed: {err}; falling back to CPU brute force");
                }
            }
        }

        brute_force::crack(
            &self.checker,
            charset,
            self.config.min_length,
            self.config.max_length,
            self.config.threads,
            self.config.show_progress,
        )
    }

    fn run_dictionary(&self) -> Result<Option<String>, String> {
        let dict_path = self
            .config
            .dictionary
            .as_ref()
            .ok_or_else(|| "Dictionary file not specified".to_string())?;

        dictionary::crack(
            &self.checker,
            dict_path,
            self.config.threads,
            self.config.show_progress,
        )
    }

    fn run_hybrid(&self) -> Result<Option<String>, String> {
        if let Some(password) = self.run_dictionary()? {
            return Ok(Some(password));
        }
        log::info!("Dictionary attack failed; switching to brute force");
        self.run_brute_force()
    }
}

/// Convenience wrapper mirroring the previous API.
pub fn run(config: &Config) -> Result<Option<String>, String> {
    let engine = CrackerEngine::new(config.clone())?;
    engine.run()
}
