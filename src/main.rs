// main.rs
mod bkcrack;
mod functions;
mod generator;
mod mask;
mod zipcrypto;

use functions::{dictionary_attack, send_passwords_from_file};
use generator::{generate_attack, GenerationOptions, DEFAULT_CHARSET};
use mask::{generate_mask_attack, Mask};

use clap::{ArgGroup, Parser};
use crossbeam_channel::{bounded, select};
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use zip::result::ZipError::UnsupportedArchive;
use zip::ZipArchive;

#[derive(Parser)]
#[command(name = "zip-cracker")]
#[command(about = "A tool for cracking password-protected ZIP files")]
#[command(group(ArgGroup::new("parallel_mode").args(["generate", "bkcrack"]).multiple(false)))]
struct Args {
    #[arg(help = "The zip file to bruteforce")]
    zip: String,

    #[arg(short, long, help = "Path to the dictionary to use for bruteforce")]
    dict: Option<String>,

    #[arg(short, long, help = "Use brute-force generation")]
    generate: bool,

    #[arg(
        long,
        help = "Automatically infer known plaintext and run bkcrack",
        conflicts_with = "dict"
    )]
    bkcrack: bool,

    #[arg(long, requires = "bkcrack", help = "Path to the bkcrack executable")]
    bkcrack_path: Option<std::path::PathBuf>,

    #[arg(
        long,
        requires = "bkcrack",
        help = "Destination ZIP (default: NAME.unlocked.zip; never overwrites)"
    )]
    decrypt: Option<std::path::PathBuf>,

    #[arg(
        long,
        requires = "bkcrack",
        help = "Show automatic plaintext assumptions without running an attack"
    )]
    dry_run: bool,

    #[arg(
        long,
        default_value_t = 180,
        requires = "bkcrack",
        help = "Total bkcrack attack/decryption budget in seconds"
    )]
    bkcrack_seconds: u64,

    #[arg(
        long,
        default_value_t = 60,
        requires = "bkcrack",
        help = "Seconds per format variant; structural headers and verified copies use the total budget"
    )]
    attempt_seconds: u64,

    #[arg(long, help = "Search a mask: ?l lowercase, ?u uppercase, ?d digits, ?s symbols, ?a ASCII, ?? literal ?", requires = "generate", conflicts_with_all = ["min_length", "max_length", "charset"])]
    mask: Option<String>,

    #[arg(long, default_value_t = 1, requires = "generate")]
    min_length: u32,

    #[arg(long, default_value_t = 8, requires = "generate")]
    max_length: u32,

    #[arg(long, default_value = DEFAULT_CHARSET, requires = "generate")]
    charset: String,

    #[arg(
        long,
        help = "Worker count (default: available logical CPUs)",
        requires = "parallel_mode"
    )]
    threads: Option<usize>,

    #[arg(
        long,
        help = "Stop after this many generated candidates",
        requires = "generate"
    )]
    limit: Option<u64>,

    #[arg(short, long, help = "Prints more information")]
    verbose: bool,
}

fn is_encrypted(zip_archive: &mut ZipArchive<File>) -> bool {
    let zip_result = zip_archive.by_index(0);
    match zip_result {
        Ok(_) => false,
        Err(UnsupportedArchive(msg)) => msg == "Password required to decrypt file",
        Err(e) => {
            eprintln!("Error reading zip file: {:?}", e);
            false
        }
    }
}

fn run_dictionary_attack(zip_path: &str, dict_path: &str, verbose: bool) {
    let password_found = Arc::new(AtomicBool::new(false));

    let file = match File::open(zip_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening zip file: {}", e);
            return;
        }
    };

    let mut zip_archive = match ZipArchive::new(file) {
        Ok(archive) => archive,
        Err(e) => {
            eprintln!("Error reading zip archive: {}", e);
            return;
        }
    };

    if !is_encrypted(&mut zip_archive) {
        eprintln!("The zip file is not encrypted");
        return;
    }

    let (send_password, receive_password) = bounded(100_000);
    let (send_found, receive_found) = bounded(1);
    let mut workers = Vec::new();

    for index in 0..num_cpus::get_physical() {
        if verbose {
            println!("Starting worker {}...", index);
        }
        let worker = dictionary_attack(
            index,
            zip_path,
            password_found.clone(),
            receive_password.clone(),
            send_found.clone(),
        );
        workers.push(worker);
    }

    if !dict_path.is_empty() {
        if verbose {
            println!("Starting password sender...");
        }
        let password_sender =
            send_passwords_from_file(password_found.clone(), send_password, dict_path.to_string());
        password_sender.join().unwrap();
    }

    select! {
        recv(receive_found) -> result => match result {
            Ok(password) => println!("Password found: {}", password),
            Err(e) => {
                eprintln!("Error while receiving password: {:?}", e);
                return;
            }
        },
        default(Duration::from_secs(10)) => {
            if verbose {
                println!("No password found");
            }
        }
    }

    password_found.store(true, Ordering::SeqCst);

    for worker in workers {
        worker.join().unwrap();
    }
}

fn run_generate_attack(
    zip_path: &str,
    verbose: bool,
    options: &GenerationOptions,
    mask: Option<&Mask>,
) {
    let password_found = Arc::new(AtomicBool::new(false));

    let file = match File::open(zip_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening zip file: {}", e);
            return;
        }
    };

    let mut zip_archive = match ZipArchive::new(file) {
        Ok(archive) => archive,
        Err(e) => {
            eprintln!("Error reading zip archive: {}", e);
            return;
        }
    };

    if !is_encrypted(&mut zip_archive) {
        eprintln!("The zip file is not encrypted");
        return;
    }

    if verbose {
        println!("Starting brute-force generator...");
    }

    let result = if let Some(mask) = mask {
        generate_mask_attack(
            zip_path,
            mask,
            options.threads,
            options.limit,
            &password_found,
        )
    } else {
        generate_attack(zip_path, options, &password_found)
    };
    match result {
        Ok(result) => {
            if let Some(password) = result.password {
                println!("Password found: {}", password);
            } else {
                println!("No password found in the searched candidates");
            }
            let seconds = result.elapsed.as_secs_f64();
            println!(
                "Checked {} passwords in {:.3}s ({:.0} passwords/s)",
                result.checked,
                seconds,
                result.checked as f64 / seconds.max(f64::EPSILON)
            );
        }
        Err(error) => {
            eprintln!("Generation failed: {}", error);
            std::process::exit(1);
        }
    }
}

fn main() {
    let args = Args::parse();

    if args.bkcrack {
        let options = bkcrack::Options {
            executable: args.bkcrack_path,
            output: args.decrypt,
            threads: args.threads.unwrap_or_else(num_cpus::get),
            seconds: args.bkcrack_seconds,
            attempt_seconds: args.attempt_seconds,
            dry_run: args.dry_run,
            verbose: args.verbose,
        };
        if let Err(error) = bkcrack::run(std::path::Path::new(&args.zip), &options) {
            eprintln!("bkcrack mode: {error}");
            std::process::exit(1);
        }
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
                eprintln!("Invalid mask: {}", error);
                std::process::exit(2);
            });
        let validation = if mask.is_some() {
            if options.threads == 0 || options.limit == Some(0) {
                Err("Threads and limit must be greater than zero".to_string())
            } else {
                Ok(0)
            }
        } else {
            options.total()
        };
        if let Err(error) = validation {
            eprintln!("Invalid generation options: {}", error);
            std::process::exit(2);
        }
        run_generate_attack(&args.zip, args.verbose, &options, mask.as_ref());
    } else {
        let dict_path = args.dict.as_deref().unwrap_or("");
        run_dictionary_attack(&args.zip, dict_path, args.verbose);
    }
}
