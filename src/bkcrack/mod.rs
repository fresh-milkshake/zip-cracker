mod discovery;
mod process;
mod templates;
use templates::Confidence;

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zip::ZipArchive;

pub struct Options {
    pub executable: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub threads: usize,
    pub seconds: u64,
    pub attempt_seconds: u64,
    pub dry_run: bool,
    pub verbose: bool,
}

fn verified_archive(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut archive = ZipArchive::new(File::open(path)?)?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let expected = entry.size();
        let actual = io::copy(&mut entry, &mut io::sink())?;
        if actual != expected {
            return Err("Decrypted entry size does not match metadata".into());
        }
    }
    Ok(())
}

pub fn run(path: &Path, options: &Options) -> Result<(), Box<dyn std::error::Error>> {
    if options.threads == 0 || options.seconds == 0 || options.attempt_seconds == 0 {
        return Err("Threads and time budgets must be greater than zero".into());
    }
    let path = path.canonicalize()?;
    let attacks = discovery::discover(&path)?;
    if attacks.is_empty() {
        return Err(
            "No applicable automatic bkcrack guesses; no password search was performed".into(),
        );
    }
    println!("Automatic plaintext candidates: {}", attacks.len());
    for (number, attack) in attacks.iter().enumerate() {
        println!(
            "  {}. {:?}: {} ({} contiguous bytes, {} additional bytes; {})",
            number + 1,
            attack.name,
            attack.guess.description,
            attack.guess.bytes.len(),
            attack
                .guess
                .extra
                .iter()
                .map(|(_, bytes)| bytes.len())
                .sum::<usize>(),
            if attack.guess.confidence == Confidence::VerifiedCopy {
                "copy checked by size and CRC32"
            } else {
                "format assumption, not yet verified"
            }
        );
    }
    if options.dry_run {
        return Ok(());
    }
    let executable = process::locate(options.executable.as_deref())?;
    let output = options.output.clone().unwrap_or_else(|| {
        let mut name = path.file_stem().unwrap_or_default().to_os_string();
        name.push(".unlocked.zip");
        path.with_file_name(name)
    });
    if output.exists() {
        return Err(format!("Output already exists: {}", output.display()).into());
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    ctrlc::set_handler(move || {
        signal.store(true, Ordering::Relaxed);
    })?;
    let temporary = tempfile::tempdir()?;
    let started = Instant::now();
    for (number, attack) in attacks.iter().enumerate() {
        let remaining = Duration::from_secs(options.seconds).saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        if cancelled.load(Ordering::Relaxed) {
            return Err("Attack cancelled".into());
        }
        let budget = if attack.guess.confidence != Confidence::Variant {
            remaining
        } else {
            remaining.min(Duration::from_secs(options.attempt_seconds))
        };
        println!(
            "Trying {}/{}: {:?}, {} (up to {:.0}s)",
            number + 1,
            attacks.len(),
            attack.name,
            attack.guess.description,
            budget.as_secs_f64()
        );
        let plain = temporary.path().join("plaintext.bin");
        std::fs::write(&plain, &attack.guess.bytes)?;
        let log = temporary.path().join("attack.log");
        let mut command = Command::new(&executable);
        command
            .arg("-C")
            .arg(&path)
            .arg("--cipher-index")
            .arg(attack.index.to_string())
            .arg("-p")
            .arg(&plain)
            .arg("-j")
            .arg(options.threads.to_string());
        for (offset, bytes) in &attack.guess.extra {
            let hex = bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            command.arg("-x").arg(offset.to_string()).arg(hex);
        }
        let completion = process::run(&mut command, &log, budget, &cancelled)?;
        let log_text = std::fs::read_to_string(&log)?;
        if options.verbose {
            println!("{}", process::log_tail(&log)?);
        }
        if completion.timed_out {
            println!("  Time budget reached for this assumption");
            continue;
        }
        let Some(keys) = process::parse_keys(&log_text).filter(|_| completion.success) else {
            if !completion.success && !log_text.contains("Could not find the keys") {
                return Err(format!("bkcrack failed: {}", process::log_tail(&log)?).into());
            }
            println!("  Assumption did not recover keys");
            continue;
        };
        // Write to a temporary file on the destination filesystem, then publish without overwriting.
        let parent = output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let destination = tempfile::NamedTempFile::new_in(parent)?;
        let mut decrypt = Command::new(&executable);
        decrypt
            .arg("-C")
            .arg(&path)
            .arg("-k")
            .args(&keys)
            .arg("-D")
            .arg(destination.path());
        let remaining = Duration::from_secs(options.seconds).saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err("Keys recovered, but total time budget expired before decryption".into());
        }
        let completion = process::run(&mut decrypt, &log, remaining, &cancelled)?;
        if !completion.success {
            return Err(format!("Decryption failed: {}", process::log_tail(&log)?).into());
        }
        if let Err(error) = verified_archive(destination.path()) {
            println!("  Recovered keys failed full archive verification: {error}");
            continue;
        }
        destination.persist_noclobber(&output)?;
        println!("Recovered keys: {} {} {}", keys[0], keys[1], keys[2]);
        println!("Decrypted and verified: {}", output.display());
        println!(
            "Completed in {:.3}s without password candidates",
            started.elapsed().as_secs_f64()
        );
        return Ok(());
    }
    Err(format!("Automatic assumptions did not recover verified content within the selected attempts/time budget ({:.1}s)", started.elapsed().as_secs_f64()).into())
}
