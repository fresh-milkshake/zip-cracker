mod bkcrack;
mod cli;
mod functions;
mod generator;
mod mask;
mod presentation;

mod zipcrypto;

use cli::Args;
use crossbeam_channel::bounded;
use functions::{dictionary_attack, send_passwords};
use generator::{generate_attack, GenerationOptions};
use mask::{generate_mask_attack, Mask};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Instant;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use zip::{result::ZipError, ZipArchive};

type AppResult = Result<(), Box<dyn std::error::Error>>;

fn check_archive(path: &str) -> AppResult {
    let mut archive = ZipArchive::new(File::open(path)?)?;
    let result = match archive.by_index(0) {
        Err(ZipError::UnsupportedArchive("Password required to decrypt file")) => Ok(()),
        Ok(_) => Err("The zip file is not encrypted".into()),
        Err(error) => Err(error.into()),
    };
    result
}

fn run_dictionary_attack(zip_path: &str, dict_path: &str, verbose: bool) -> AppResult {
    check_archive(zip_path)?;
    let started = Instant::now();
    let lines = BufReader::new(File::open(dict_path)?)
        .lines()
        .collect::<Result<Vec<_>, _>>()?;
    let progress = presentation::progress(lines.len() as u64, "Dictionary");
    presentation::detail(format!(
        "Wordlist  {dict_path} · {} candidates",
        lines.len()
    ));
    let found = Arc::new(AtomicBool::new(false));
    let (send_password, receive_password) = bounded(100_000);
    let (send_found, receive_found) = bounded(1);
    let mut workers = Vec::new();
    for index in 0..num_cpus::get_physical().max(1) {
        if verbose {
            presentation::note(&format!("Starting worker {index}"));
        }
        workers.push(dictionary_attack(
            index,
            zip_path,
            found.clone(),
            receive_password.clone(),
            send_found.clone(),
            progress.clone(),
        ));
    }
    drop(receive_password);
    drop(send_found);
    let sender = send_passwords(found, send_password, lines);
    sender.join().map_err(|_| "Wordlist reader failed")?;
    for worker in workers {
        worker.join().map_err(|_| "Dictionary worker failed")?;
    }
    progress.finish_and_clear();
    if let Ok(password) = receive_found.try_recv() {
        presentation::success("Password found:", password);
    } else {
        presentation::note("No password found in the wordlist");
    }
    presentation::statistics(progress.position(), started.elapsed());
    Ok(())
}

fn run_generate_attack(
    zip_path: &str,
    options: &GenerationOptions,
    mask: Option<&Mask>,
) -> AppResult {
    check_archive(zip_path)?;
    let cancelled = AtomicBool::new(false);
    let result = if let Some(mask) = mask {
        generate_mask_attack(zip_path, mask, options.threads, options.limit, &cancelled)?
    } else {
        generate_attack(zip_path, options, &cancelled)?
    };
    let matched = result.password.is_some();
    if let Some(password) = result.password {
        presentation::success("Password found:", password);
    } else {
        presentation::note("No password found in the searched candidates");
    }
    presentation::statistics(result.checked, result.elapsed);
    if matched {
        presentation::detail("Full entry verification passed.");
    }
    println!();
    Ok(())
}

fn execute(args: Args) -> AppResult {
    let path = args.zip.as_str();
    if args.bkcrack {
        presentation::heading("Automatic recovery", path);
        let options = bkcrack::Options {
            executable: args.bkcrack_path,
            output: args.decrypt,
            threads: args.threads.unwrap_or_else(num_cpus::get),
            seconds: args.bkcrack_seconds,
            attempt_seconds: args.attempt_seconds,
            dry_run: args.dry_run,
            verbose: args.verbose,
        };
        bkcrack::run(std::path::Path::new(path), &options)
            .map_err(|error| format!("bkcrack mode: {error}").into())
    } else if args.generate {
        let options = GenerationOptions {
            min_length: args.min_length,
            max_length: args.max_length,
            charset: args.charset,
            threads: args.threads.unwrap_or_else(num_cpus::get),
            limit: args.limit,
        };
        let mask = args
            .mask
            .as_deref()
            .map(Mask::parse)
            .transpose()
            .unwrap_or_else(|error| {
                presentation::error(&format!("Invalid mask: {error}"));
                std::process::exit(2);
            });
        let validation = if mask.is_some() {
            if options.threads == 0 || options.limit == Some(0) {
                Err("Threads and limit must be greater than zero".into())
            } else {
                Ok(0)
            }
        } else {
            options.total()
        };
        if let Err(error) = validation {
            presentation::error(&format!("Invalid generation options: {error}"));
            std::process::exit(2);
        }
        presentation::heading(
            if mask.is_some() {
                "Password mask"
            } else {
                "Character search"
            },
            path,
        );
        if let Some(mask) = args.mask {
            presentation::note(&format!("Mask  {mask}"));
        }
        presentation::note(&format!("Workers  {}", options.threads));
        run_generate_attack(path, &options, mask.as_ref())
    } else {
        presentation::heading("Dictionary", path);
        run_dictionary_attack(
            path,
            args.dict.as_deref().ok_or("Choose a recovery method")?,
            args.verbose,
        )
    }
}

fn main() {
    let args = Args::parse_cli();
    presentation::configure(args.color);
    if let Err(error) = execute(args) {
        presentation::error(&error.to_string());
        std::process::exit(1);
    }
}
