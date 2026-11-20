use crate::archive::is_right_password;
use crate::presentation;
use crate::AppResult;
use crossbeam_channel::{bounded, Receiver, Sender};
use indicatif::ProgressBar;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Instant;
use zip::ZipArchive;

pub fn run(zip_path: &str, dict_path: &str, verbose: bool) -> AppResult {
    crate::archive::check_encrypted(zip_path)?;
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
        workers.push(spawn_worker(
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
    for password in lines {
        if found.load(Ordering::Relaxed) || send_password.send(password).is_err() {
            break;
        }
    }
    drop(send_password);
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

fn spawn_worker(
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
