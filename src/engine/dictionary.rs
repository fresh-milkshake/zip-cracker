//! Dictionary-based password attack.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;

use super::checker::PasswordChecker;

const CHUNK_SIZE: usize = 4096;

fn process_chunk(
    chunk: &[String],
    checker: &PasswordChecker,
    progress: &Option<Arc<ProgressBar>>,
) -> Option<String> {
    chunk.par_iter().find_map_any(|candidate| {
        if let Some(pb) = progress.as_ref() {
            pb.inc(1);
        }

        match checker.check(candidate) {
            Ok(true) => Some(candidate.clone()),
            Ok(false) => None,
            Err(err) => {
                log::error!(
                    "Checker error for dictionary entry '{}': {}",
                    candidate,
                    err
                );
                None
            }
        }
    })
}

pub fn crack(
    checker: &PasswordChecker,
    dictionary_path: &Path,
    threads: usize,
    show_progress: bool,
) -> Result<Option<String>, String> {
    let file =
        File::open(dictionary_path).map_err(|e| format!("Failed to open dictionary file: {e}"))?;
    let reader = BufReader::new(file);

    let progress = if show_progress {
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::with_template("{spinner} {pos} candidates tested").unwrap());
        pb.enable_steady_tick(Duration::from_millis(100));
        Some(Arc::new(pb))
    } else {
        None
    };
    let progress_shared = progress.clone();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| format!("Failed to build thread pool: {e}"))?;

    let mut chunk = Vec::with_capacity(CHUNK_SIZE);

    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read dictionary line: {e}"))?;
        let candidate = line.trim();
        if candidate.is_empty() {
            continue;
        }
        chunk.push(candidate.to_string());

        if chunk.len() >= CHUNK_SIZE {
            if let Some(found) = pool.install(|| process_chunk(&chunk, checker, &progress_shared)) {
                if let Some(pb) = &progress {
                    pb.finish_and_clear();
                }
                return Ok(Some(found));
            }
            chunk.clear();
        }
    }

    if !chunk.is_empty() {
        if let Some(found) = pool.install(|| process_chunk(&chunk, checker, &progress_shared)) {
            if let Some(pb) = &progress {
                pb.finish_and_clear();
            }
            return Ok(Some(found));
        }
    }

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    Ok(None)
}
