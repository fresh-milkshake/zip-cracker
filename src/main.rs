// main.rs
mod functions;

use functions::{dictionary_attack, send_passwords_from_file, generate_attack};

use clap::{App, Arg};
use crossbeam_channel::{bounded, select};
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use zip::result::ZipError::UnsupportedArchive;
use zip::ZipArchive;

fn is_encrypted(zip_archive: &mut ZipArchive<File>) -> bool {
    let zip_result = zip_archive.by_index(0);
    match zip_result {
        Ok(_) => false,
        Err(UnsupportedArchive(msg)) => msg == "Password required to decrypt file",
        Err(e) => panic!("Unexpected error {:?}", e),
    }
}

fn run_dictionary_attack(zip_path: &str, dict_path: &str, verbose: bool) {
    let password_found = Arc::new(AtomicBool::new(false));

    let file = File::open(zip_path).unwrap();
    let mut zip_archive = ZipArchive::new(file).unwrap();

    if !is_encrypted(&mut zip_archive) {
        panic!("The zip file is not encrypted");
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
            Err(e) => panic!("Error while receiving password: {:?}", e),
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

    let file = File::open(zip_path).unwrap();
    let mut zip_archive = ZipArchive::new(file).unwrap();

    if !is_encrypted(&mut zip_archive) {
        panic!("The zip file is not encrypted");
    }

    let (send_password, receive_password) = bounded(100_000);
    let (send_found, receive_found) = bounded(1);

    if verbose {
        println!("Starting brute-force generator...");
    }
    generate_attack(zip_path, password_found.clone(), receive_password.clone(), send_found.clone());

    select! {
        recv(receive_found) -> result => match result {
            Ok(password) => println!("Password found: {}", password),
            Err(e) => panic!("Error while receiving password: {:?}", e),
        },
        default(Duration::from_secs(10)) => {
            if verbose {
                println!("No password found");
            }
        }
    }

    password_found.store(true, Ordering::SeqCst);
}

fn main() {
    let matches = App::new("Zip Bruteforce")
        .arg(Arg::with_name("zip")
            .required(true)
            .value_name("FILE")
            .help("The zip file to bruteforce"))
        .arg(Arg::with_name("dict")
            .short('d')
            .long("dict")
            .value_name("FILE")
            .help("Path to the dictionary to use for bruteforce"))
        .arg(Arg::with_name("generate")
            .short('g')
            .long("generate")
            .help("Use brute-force generation"))
        .arg(Arg::with_name("verbose")
            .short('v')
            .long("verbose")
            .help("Prints more information"))
        .get_matches();

    let zip_path = matches.value_of("zip").unwrap();
    let dict_path = matches.value_of("dict").unwrap_or_default();
    let generate = matches.is_present("generate");
    let verbose = matches.is_present("verbose");

    if generate {
        run_generate_attack(zip_path, verbose);
    } else {
        run_dictionary_attack(zip_path, dict_path, verbose);
    }
}
