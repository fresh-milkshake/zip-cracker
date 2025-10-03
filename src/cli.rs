//! Command Line Interface
//!
//! Handles parsing of command line arguments using clap.

use clap::{ArgAction, Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "zip-cracker",
    about = "High-performance ZIP password recovery tool",
    version,
    author
)]
pub struct Args {
    /// Path to the ZIP file to crack
    #[arg(short, long, required = true)]
    pub zip_file: PathBuf,

    /// Attack mode to use
    #[arg(short, long, default_value = "brute-force")]
    pub mode: AttackMode,

    /// Character set for brute force attack
    #[arg(
        short = 'c',
        long,
        default_value = "abcdefghijklmnopqrstuvwxyz0123456789"
    )]
    pub charset: String,

    /// Minimum password length
    #[arg(short = 'n', long, default_value = "1")]
    pub min_length: usize,

    /// Maximum password length
    #[arg(short = 'M', long, default_value = "8")]
    pub max_length: usize,

    /// Path to dictionary file for dictionary attack
    #[arg(short, long)]
    pub dictionary: Option<PathBuf>,

    /// Number of threads to use
    #[arg(short, long, default_value = "0")]
    pub threads: usize,

    /// Enable GPU acceleration
    #[arg(short, long)]
    pub gpu: bool,

    /// Resume from checkpoint file
    #[arg(short, long)]
    pub resume: Option<PathBuf>,

    /// Output file for found password
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Quiet mode (minimal output)
    #[arg(short, long)]
    pub quiet: bool,

    /// Show progress bar
    #[arg(long, action = ArgAction::SetTrue)]
    pub progress: bool,
}

#[derive(Clone, ValueEnum, Debug)]
pub enum AttackMode {
    /// Brute force attack
    BruteForce,
    /// Dictionary attack
    Dictionary,
    /// Hybrid attack (combination of both)
    Hybrid,
}

impl std::fmt::Display for AttackMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackMode::BruteForce => write!(f, "brute-force"),
            AttackMode::Dictionary => write!(f, "dictionary"),
            AttackMode::Hybrid => write!(f, "hybrid"),
        }
    }
}

impl std::str::FromStr for AttackMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "brute-force" | "brute" | "brute_force" => Ok(AttackMode::BruteForce),
            "dictionary" | "dict" => Ok(AttackMode::Dictionary),
            "hybrid" => Ok(AttackMode::Hybrid),
            _ => Err(format!("Unknown attack mode: {}", s)),
        }
    }
}
