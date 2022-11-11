use crossbeam_channel::{Receiver, Sender};
use indicatif::{ProgressBar, ProgressStyle};
use zip::ZipArchive;

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

fn is_right_password(archive: &mut ZipArchive<File>, password: &str) -> bool {
    let res = archive.by_index_decrypt(0, password.as_bytes());
    match res {
        Err(e) => panic!("Unexpected error {:?}", e),
        Ok(Err(_)) => false,
        Ok(Ok(mut zip)) => {
            let mut buffer = Vec::with_capacity(zip.size() as usize);
            match zip.read_to_end(&mut buffer) {
                Err(_) => false,
                Ok(_) => true,
            }
        }
    }
}

pub fn dictionary_brute(
    index: usize,
    zip_path: &str,
    is_password_found: Arc<AtomicBool>,
    receive_password: Receiver<String>,
    send_found: Sender<String>,
) -> JoinHandle<()> {
    let mut zip_archive = ZipArchive::new(File::open(zip_path).unwrap()).unwrap();
    return thread::Builder::new()
        .name(format!("thread-{}", index))
        .spawn(move || {
            while !is_password_found.load(Ordering::Relaxed) {
                let password = receive_password.recv();
                match password {
                    Err(_) => break,
                    Ok(password) => {
                        if is_right_password(&mut zip_archive, &password) {
                            is_password_found.store(true, Ordering::Relaxed);
                            println!("Password found: {}", password);
                            let response = send_found.send(password);
                            match response {
                                Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                    }
                }
            }
        })
        .unwrap();
}

pub fn password_sender(
    is_password_found: Arc<AtomicBool>,
    send_password: Sender<String>,
    dict_path: String,
) -> JoinHandle<()> {
    return thread::Builder::new()
        .name("password-sender".to_string())
        .spawn(move || {
            let file = File::open(&dict_path).unwrap();
            let reader = BufReader::new(file).lines();
            let lines_count = reader.count() as u64;

            let pb = ProgressBar::new(lines_count);
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .progress_chars("#>-"));

            let file = File::open(&dict_path).unwrap();
            let reader = BufReader::new(file).lines();
            for line in reader {
                if is_password_found.load(Ordering::Relaxed) {
                    break;
                } else {
                    let response = send_password.send(line.unwrap());
                    match response {
                        Err(_) => break,
                        Ok(_) => {
                            pb.inc(1);
                        }
                    }
                }
            }
            pb.finish();
        })
        .unwrap();
}

fn generate_passwords(length: usize) {}

pub fn generate_brute(zip_path: &str, is_password_found: Arc<AtomicBool>) {}
