// main.rs
mod functions;

use functions::{dictionary_attack, send_passwords_from_file, generate_attack};

use clap::Parser;
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
struct Args {
    #[arg(help = "The zip file to bruteforce")]
    zip: String,

    #[arg(short, long, help = "Path to the dictionary to use for bruteforce")]
    dict: Option<String>,

    #[arg(short, long, help = "Use brute-force generation")]
    generate: bool,

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
        let password_sender = send_passwords_from_file(
            password_found.clone(),
            send_password,
            dict_path.to_string(),
        );
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

fn run_generate_attack(zip_path: &str, verbose: bool) {
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
    
    generate_attack(zip_path, password_found.clone());

    if verbose {
        println!("Brute-force attack completed");
    }
}

fn main() {
    let args = Args::parse();

    if args.generate {
        run_generate_attack(&args.zip, args.verbose);
    } else {
        let dict_path = args.dict.as_deref().unwrap_or("");
        run_dictionary_attack(&args.zip, dict_path, args.verbose);
    }
}
