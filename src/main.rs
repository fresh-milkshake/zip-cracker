mod functions;

use functions::dictionary_brute;
use functions::generate_brute;
use functions::password_sender;

use clap::{Arg, Command};
use crossbeam_channel::bounded;
use zip::result::ZipError::UnsupportedArchive;
use zip::ZipArchive;

use std::fs::File;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

fn is_valid(zip_archive: &mut ZipArchive<File>) -> bool {
    let zip_result = zip_archive.by_index(0);
    match zip_result {
        Ok(_) => false,
        Err(UnsupportedArchive(msg)) => msg == "Password required to decrypt file",
        Err(e) => panic!("Unexpected error {:?}", e),
    }
}

fn main() {
    let command = Command::new("Zip Bruteforcer").args(&[
        Arg::new("zip")
            .help("The zip file to bruteforce")
            .required(true)
            .index(1)
            .value_name("FILE"),
        Arg::new("dict")
            .help("Path to the dictionary to use for bruteforcing")
            .short('d')
            .long("dict")
            .value_name("FILE"),
        Arg::new("verbose")
            .help("Prints more information")
            .short('v')
            .long("verbose")
            .takes_value(false)
            .required(false),
    ]);

    let matches = command.get_matches();
    let zip_path = matches.value_of("zip").unwrap();
    let verbose = matches.is_present("verbose");
    let is_password_found = Arc::new(AtomicBool::new(false));

    let file = File::open(zip_path).unwrap();
    let mut zip_archive = ZipArchive::new(file).unwrap();
    let workers_count = num_cpus::get_physical();

    if !is_valid(&mut zip_archive) {
        panic!("The zip file is not encrypted");
    }

    let (send_password, receive_password) = bounded(workers_count * 10_000);
    let (send_found, receive_found) = bounded(1);

    if let Some(dict_path) = matches.value_of("dict") {
        let mut workers = Vec::with_capacity(workers_count);
        for index in 0..=workers_count {
            if verbose {
                println!("Starting worker {}...", index);
            }
            let worker = dictionary_brute(
                index,
                zip_path,
                is_password_found.clone(),
                receive_password.clone(),
                send_found.clone(),
            );
            workers.push(worker);
        }

        if verbose {
            println!("Starting password sender...");
        }
        let password_sender = password_sender(
            is_password_found.clone(),
            send_password,
            dict_path.to_string(),
        );
        password_sender.join().unwrap();

        if verbose {
            println!("Waiting for password...");
        }

        match receive_found.recv() {
            Ok(password) => println!("Password found: {}", password),
            Err(e) => panic!("Error while receiving password: {:?}", e),
        }

        for worker in workers {
            worker.join().unwrap();
        }
    }
}
