use crossbeam_channel::{Receiver, Sender};
use indicatif::{ProgressBar, ProgressStyle};
use zip::ZipArchive;

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

pub(crate) fn is_right_password<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    password: &[u8],
) -> bool {
    if let Ok(Ok(mut zip)) = archive.by_index_decrypt(0, password) {
        io::copy(&mut zip, &mut io::sink()).is_ok()
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
    let mut zip_archive = ZipArchive::new(File::open(zip_path).expect("Failed to open zip file"))
        .expect("Failed to create ZipArchive");
    let builder = thread::Builder::new().name(format!("thread-{}", index));

    builder
        .spawn(move || {
            while !is_password_found.load(Ordering::Relaxed) {
                if let Ok(password) = receive_password.recv() {
                    if is_right_password(&mut zip_archive, password.as_bytes()) {
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
        })
        .expect("Failed to spawn thread")
}

pub fn send_passwords_from_file(
    is_password_found: Arc<AtomicBool>,
    send_password: Sender<String>,
    dict_path: String,
) -> JoinHandle<()> {
    let builder = thread::Builder::new().name("password-sender".to_string());

    builder
        .spawn(move || {
            let file = File::open(&dict_path).expect("Failed to open dictionary file");
            let lines: Vec<String> = BufReader::new(file)
                .lines()
                .collect::<Result<Vec<_>, _>>()
                .expect("Failed to read dictionary file");

            let pb = ProgressBar::new(lines.len() as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {eta} {msg}")
                    .expect("Failed to set progress bar style")
                    .progress_chars("=>-"),
            );

            for line in lines {
                if is_password_found.load(Ordering::Relaxed) {
                    break;
                }
                if send_password.send(line).is_err() {
                    break;
                }
                pb.inc(1);
            }
            pb.finish();
        })
        .expect("Failed to spawn thread")
}
