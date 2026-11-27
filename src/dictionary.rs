mod producer;

use crate::archive::CachedArchive;
use crate::wordlists::Library;
use crate::{presentation, AppResult};
use crossbeam_channel::bounded;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

struct WorkerGuard<'a>(&'a AtomicBool);

impl Drop for WorkerGuard<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.store(true, Ordering::Relaxed);
        }
    }
}

pub struct Options {
    pub threads: usize,
    pub limit: Option<u64>,
    pub refresh: bool,
    pub rules: bool,
    pub keep_duplicates: bool,
    pub min_length: usize,
    pub max_length: usize,
}

pub fn run(zip_path: &str, sources: &[String], library: &Library, options: &Options) -> AppResult {
    if options.threads == 0 || options.limit == Some(0) || options.min_length > options.max_length {
        return Err(
            "Threads/limit must be positive and minimum word length must not exceed maximum".into(),
        );
    }
    let started = Instant::now();
    let archive = CachedArchive::open(zip_path)?;
    let filter = archive.filter;
    let batch_entries = if filter.is_some() { 1024 } else { 32 };
    let progress = presentation::streaming_progress("Dictionary");
    let producer_thread = std::thread::current();
    let found = AtomicBool::new(false);
    // Batches cap both candidate count and bytes; memory is independent of dictionary size.
    let (sender, receiver) = bounded::<producer::Batch>(8);
    let result = std::thread::scope(|scope| -> AppResult<(Option<Vec<u8>>, u64)> {
        let mut workers = Vec::new();
        for _ in 0..options.threads {
            let receiver = receiver.clone();
            let mut archive = archive.clone();
            let found = &found;
            let progress = &progress;
            let producer_thread = &producer_thread;
            workers.push(scope.spawn(move || {
                let _guard = WorkerGuard(found);
                while let Ok(batch) = receiver.recv() {
                    let mut checked = 0;
                    let mut result = None;
                    for password in batch.iter() {
                        if found.load(Ordering::Relaxed) || library.is_cancelled() {
                            break;
                        }
                        checked += 1;
                        if filter
                            .as_ref()
                            .is_none_or(|header| header.may_match(password))
                            && archive.verify_password(password)
                        {
                            if found
                                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                                .is_ok()
                            {
                                result = Some(password.to_vec());
                            }
                            break;
                        }
                    }
                    progress.inc(checked);
                    producer_thread.unpark();
                    if found.load(Ordering::Relaxed) || library.is_cancelled() {
                        return result;
                    }
                }
                None
            }));
        }
        drop(receiver);
        let produced = producer::send(
            sources,
            library,
            options,
            &found,
            &sender,
            &progress,
            batch_entries,
        );
        drop(sender);
        // Stop promptly on read/download errors, but join all workers before returning.
        if produced.is_err() {
            found.store(true, Ordering::Relaxed);
        }
        let mut password = None;
        for worker in workers {
            password = password.or(worker.join().map_err(|_| "Dictionary worker panicked")?);
        }
        Ok((password, produced?))
    });
    progress.finish_and_clear();
    presentation::statistics(progress.position(), started.elapsed());
    let (password, skipped) = result?;
    if let Some(password) = password {
        let display = match String::from_utf8(password) {
            Ok(password) => password,
            Err(error) => format!(
                "$HEX[{}]",
                error
                    .as_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ),
        };
        presentation::success("Password found:", display);
        presentation::detail("Full entry verification passed.");
    } else if library.is_cancelled() {
        return Err("Dictionary search cancelled".into());
    } else {
        presentation::note("No password found in the wordlist sources");
    }
    if skipped > 0 {
        presentation::detail(format!("Skipped {skipped} repeated/filtered candidates"));
    }
    Ok(())
}
