use crossbeam_channel::{Receiver, Sender};
use indicatif::{ProgressBar, ProgressStyle};
use zip::ZipArchive;

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::iter::repeat_with;

fn is_right_password(archive: &mut ZipArchive<File>, password: &str) -> bool {
    if let Ok(Ok(mut zip)) = archive.by_index_decrypt(0, password.as_bytes()) {
        let mut buffer = Vec::with_capacity(zip.size() as usize);
        zip.read_to_end(&mut buffer).is_ok()
    } else {
        false
    }
}

pub fn dictionary_attack(
    index: usize,
    zip_path: &str,
    is_password_found: Arc<AtomicBool>,
    receive_password: Receiver<String>,
    send_found: Sender<String>,
) -> JoinHandle<()> {
    let mut zip_archive = ZipArchive::new(File::open(zip_path).expect("Failed to open zip file")).expect("Failed to create ZipArchive");
    let builder = thread::Builder::new().name(format!("thread-{}", index));

    builder.spawn(move || {
        while !is_password_found.load(Ordering::Relaxed) {
            if let Ok(password) = receive_password.recv() {
                if is_right_password(&mut zip_archive, &password) {
                    is_password_found.store(true, Ordering::Relaxed);
                    println!("Password found: {}", password);
                    if send_found.send(password).is_err() {
                        break;
                    }
                }
            } else {
                break;
            }
        }
    }).expect("Failed to spawn thread")
}

pub fn send_passwords_from_file(
    is_password_found: Arc<AtomicBool>,
    send_password: Sender<String>,
    dict_path: String,
) -> JoinHandle<()> {
    let builder = thread::Builder::new().name("password-sender".to_string());

    builder.spawn(move || {
        let file = File::open(&dict_path).expect("Failed to open dictionary file");
        let reader = BufReader::new(file).lines();
        let lines_count = reader.count() as u64;

        let pb = ProgressBar::new(lines_count);
        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {eta} {msg}")
            .expect("Failed to set progress bar style")
            .progress_chars("=>-"));

        let file = File::open(&dict_path).expect("Failed to open dictionary file");
        let reader = BufReader::new(file).lines();
        for line in reader {
            if is_password_found.load(Ordering::Relaxed) {
                break;
            } else if let Ok(line_content) = line {
                if send_password.send(line_content).is_err() {
                    break;
                } else {
                    pb.inc(1);
                }
            }
        }
        pb.finish();
    }).expect("Failed to spawn thread")
}

fn multi_cartesian_product<T: Clone>(input: Vec<Vec<T>>) -> Vec<Vec<T>> {
    let mut result: Vec<Vec<T>> = vec![vec![]];

    for sub_list in input {
        let mut new_result: Vec<Vec<T>> = Vec::new();

        for item in &sub_list {
            for r in &result {
                let mut new_combination = r.clone();
                new_combination.push(item.clone());
                new_result.push(new_combination);
            }
        }

        result = new_result;
    }

    result
}


fn generate_passwords(length: usize) -> Vec<String> {
    let charset: Vec<char> = ('a'..='z').chain('A'..='Z').chain('0'..='9').collect();

    let input: Vec<Vec<char>> = vec![charset.clone(); length];
    let combinations = multi_cartesian_product(input);

    combinations.into_iter().map(|combination| combination.into_iter().collect()).collect()
}


use std::sync::Mutex;
use rayon::prelude::*;

pub fn generate_attack(
    zip_path: &str,
    is_password_found: Arc<AtomicBool>,
    receive_password: Receiver<String>,
    send_found: Sender<String>,
) {
    let zip_archive = Arc::new(Mutex::new(
        ZipArchive::new(File::open(zip_path).expect("Failed to open zip file"))
            .expect("Failed to create ZipArchive"),
    ));

    // Initialize the progress bar
    let total_combinations = (1..=8).map(|i| 62usize.pow(i as u32)).sum::<usize>() as u64;
    let pb = ProgressBar::new(total_combinations);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {eta} {msg}")
            .expect("Failed to set progress bar style")
            .progress_chars("=>-"),
    );

    for password_length in 1..=8 {
        let passwords = generate_passwords(password_length);

        let found_password = passwords.into_par_iter().find_any(|password| {
            pb.set_message(format!("Trying: {}", String::from(password)));
            pb.inc(1); // Increment progress

            if is_password_found.load(Ordering::Relaxed) {
                false
            } else {
                let mut zip_archive_guard = zip_archive.lock().unwrap();
                let result = is_right_password(&mut *zip_archive_guard, &password);
                drop(zip_archive_guard);

                if result {
                    is_password_found.store(true, Ordering::Relaxed);
                    println!("Password found: {}", password);
                    send_found.send(password.clone()).is_ok()
                } else {
                    false
                }
            }
        });

        if found_password.is_some() {
            break;
        }
    }

    pb.finish();
}
