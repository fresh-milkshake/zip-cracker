use crossbeam_channel::{Receiver, Sender};
use indicatif::ProgressBar;
use zip::ZipArchive;

use std::fs::File;
use std::io::{self, Read, Seek};
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
    progress: ProgressBar,
) -> JoinHandle<()> {
    let mut zip_archive = ZipArchive::new(File::open(zip_path).expect("Failed to open zip file"))
        .expect("Failed to create ZipArchive");
    let builder = thread::Builder::new().name(format!("thread-{}", index));

    builder
        .spawn(move || {
            let mut pending = 0;
            while !is_password_found.load(Ordering::Relaxed) {
                if let Ok(password) = receive_password.recv() {
                    pending += 1;
                    if is_right_password(&mut zip_archive, password.as_bytes()) {
                        if is_password_found
                            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                            .is_ok()
                        {
                            let _ = send_found.send(password);
                        }
                        break;
                    }
                    if pending == 256 {
                        progress.inc(pending);
                        pending = 0;
                    }
                } else {
                    break;
                }
            }
            progress.inc(pending);
        })
        .expect("Failed to spawn thread")
}

pub fn send_passwords(
    is_password_found: Arc<AtomicBool>,
    send_password: Sender<String>,
    lines: Vec<String>,
) -> JoinHandle<()> {
    let builder = thread::Builder::new().name("password-sender".to_string());

    builder
        .spawn(move || {
            for line in lines {
                if is_password_found.load(Ordering::Relaxed) {
                    break;
                }
                if send_password.send(line).is_err() {
                    break;
                }
            }
        })
        .expect("Failed to spawn thread")
}
