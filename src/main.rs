mod archive;
mod bkcrack;
mod cli;
mod dictionary;
mod generator;
mod mask;
mod presentation;

mod zipcrypto;

use cli::Args;
use generator::{generate_attack, GenerationOptions};
use mask::{generate_mask_attack, Mask};
use std::sync::atomic::AtomicBool;

type AppResult = Result<(), Box<dyn std::error::Error>>;

fn run_generate_attack(
    zip_path: &str,
    options: &GenerationOptions,
    mask: Option<&Mask>,
) -> AppResult {
    archive::check_encrypted(zip_path)?;
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
        dictionary::run(
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
