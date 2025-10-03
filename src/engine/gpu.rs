//! GPU-assisted brute-force utilities.
//!
//! This module currently provides a high-throughput, chunked brute-force
//! implementation that can take advantage of wide parallelism. The design
//! keeps the API GPU-friendly so that real kernels can be plugged in later
//! without touching the engine.

use std::{cmp, sync::Arc, time::Duration};

use indicatif::{ProgressBar, ProgressStyle};
use rayon::{prelude::*, ThreadPoolBuilder};

use super::{brute_force::Keyspace, checker::PasswordChecker};

const GPU_MIN_CHUNK: usize = 16_384;

const GPU_MAX_CHUNK: usize = 1_048_576;

/// Execute a chunked brute-force search, optimized for very large keyspaces.
pub fn crack(
    checker: &PasswordChecker,
    charset: Vec<char>,
    min_length: usize,
    max_length: usize,
    threads: usize,
    show_progress: bool,
) -> Result<Option<String>, String> {
    let keyspace = Arc::new(Keyspace::new(charset, min_length, max_length)?);

    if keyspace.total() == 0 {
        return Ok(None);
    }

    log::info!(
        "GPU acceleration requested; running chunked brute-force over {} candidates",
        keyspace.total()
    );

    let total = keyspace.total();

    if total > usize::MAX as u64 {
        return Err("Keyspace too large for GPU chunk scheduling".to_string());
    }

    let total_indices = total as usize;

    if total_indices <= GPU_MIN_CHUNK {
        log::debug!("Keyspace below GPU threshold; using CPU brute force");
        let fallback_charset = keyspace.charset().to_vec();
        return super::brute_force::crack(
            checker,
            fallback_charset,
            min_length,
            max_length,
            threads,
            show_progress,
        );
    }

    let progress = if show_progress {
        let pb = ProgressBar::new(keyspace.total());
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({per_sec})",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        pb.enable_steady_tick(Duration::from_millis(100));
        Some(Arc::new(pb))
    } else {
        None
    };

    let progress_shared = progress.clone();

    let pool = ThreadPoolBuilder::new()
        .num_threads(threads.max(1))
        .build()
        .map_err(|e| format!("Failed to build thread pool: {e}"))?;

    let desired_chunks = threads.max(1) * 4;
    let adaptive_chunk = if desired_chunks > 0 {
        (total_indices / desired_chunks).max(1)
    } else {
        total_indices
    };
    let chunk_size = cmp::max(GPU_MIN_CHUNK, adaptive_chunk);
    let chunk_size = cmp::min(GPU_MAX_CHUNK, chunk_size);

    let total_chunks = (total_indices + chunk_size - 1) / chunk_size;

    let found = pool.install(|| {
        (0..total_chunks).into_par_iter().find_map_any(|chunk_id| {
            let start = chunk_id * chunk_size;
            if start >= total_indices {
                return None;
            }
            let remaining = total_indices - start;
            let len = remaining.min(chunk_size);
            if len == 0 {
                return None;
            }
            process_chunk(
                keyspace.as_ref(),
                checker,
                start as u64,
                len,
                progress_shared.as_ref().map(Arc::clone),
            )
        })
    });

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    Ok(found)
}

fn process_chunk(
    keyspace: &Keyspace,
    checker: &PasswordChecker,
    start_index: u64,
    count: usize,
    progress: Option<Arc<ProgressBar>>,
) -> Option<String> {
    if count == 0 {
        return None;
    }

    let charset = keyspace.charset();
    let base = charset.len();
    if base == 0 {
        return None;
    }

    let (mut segment_idx, local_index) = keyspace.segment_for_index(start_index)?;
    let segments = keyspace.segments();
    let mut digits = Vec::with_capacity(keyspace.max_length());
    let mut segment_len = match keyspace.segment_length(segment_idx) {
        Some(len) => len,
        None => return None,
    };

    initialize_digits(&mut digits, segment_len, local_index, base);
    let mut password = String::with_capacity(keyspace.max_length());
    let mut remaining = count;
    let mut current_index = start_index;
    let limit = keyspace.total();
    let mut processed = 0u64;

    while remaining > 0 && current_index < limit {
        password.clear();
        for &digit in &digits {
            password.push(charset[digit]);
        }

        let result = checker.check(&password);
        processed += 1;

        match result {
            Ok(true) => {
                if let Some(pb) = &progress {
                    pb.inc(processed);
                }
                return Some(password);
            }
            Ok(false) => {}
            Err(err) => {
                log::error!("Checker error for candidate '{}': {}", password, err);
            }
        }

        remaining -= 1;
        current_index += 1;

        if remaining == 0 || current_index >= limit {
            break;
        }

        if !increment_digits(&mut digits, base) {
            segment_idx += 1;
            if segment_idx >= segments.len() {
                break;
            }
            segment_len = match keyspace.segment_length(segment_idx) {
                Some(len) => len,
                None => break,
            };
            initialize_digits(&mut digits, segment_len, 0, base);
        }
    }

    if let Some(pb) = &progress {
        pb.inc(processed);
    }

    None
}

fn initialize_digits(digits: &mut Vec<usize>, length: usize, local_index: u64, base: usize) {
    digits.clear();
    digits.resize(length, 0);
    let mut value = local_index;
    let base_u64 = base as u64;

    for pos in (0..length).rev() {
        digits[pos] = (value % base_u64) as usize;
        value /= base_u64;
    }
}

fn increment_digits(digits: &mut [usize], base: usize) -> bool {
    for idx in (0..digits.len()).rev() {
        digits[idx] += 1;
        if digits[idx] < base {
            return true;
        }
        digits[idx] = 0;
    }
    false
}
