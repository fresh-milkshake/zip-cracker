//! Brute-force password generation and cracking.

use std::sync::Arc;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;

use super::checker::PasswordChecker;

/// Description of the keyspace for brute force search.
pub(crate) struct Keyspace {
    charset: Arc<Vec<char>>,
    segments: Vec<LengthSegment>,
    total: u64,
}

pub(crate) struct LengthSegment {
    length: usize,
    start: u64,
    count: u64,
}

impl Keyspace {
    pub fn new(charset: Vec<char>, min_length: usize, max_length: usize) -> Result<Self, String> {
        if charset.is_empty() {
            return Err("Character set cannot be empty".to_string());
        }
        if min_length == 0 {
            return Err("Minimum length must be at least 1".to_string());
        }
        if min_length > max_length {
            return Err("Minimum length cannot exceed maximum length".to_string());
        }

        let base = charset.len() as u64;
        let mut segments = Vec::new();
        let mut start = 0u64;

        for length in min_length..=max_length {
            let count = base
                .checked_pow(length as u32)
                .ok_or_else(|| "Password space is too large".to_string())?;
            segments.push(LengthSegment {
                length,
                start,
                count,
            });
            start = start.saturating_add(count);
        }

        Ok(Self {
            charset: Arc::new(charset),
            segments,
            total: start,
        })
    }

    #[inline]
    pub fn total(&self) -> u64 {
        self.total
    }

    #[inline]
    pub fn max_length(&self) -> usize {
        self.segments.last().map(|seg| seg.length).unwrap_or(0)
    }

    #[inline]
    pub fn charset(&self) -> &[char] {
        self.charset.as_ref()
    }

    #[inline]
    pub fn segments(&self) -> &[LengthSegment] {
        &self.segments
    }

    pub fn segment_for_index(&self, index: u64) -> Option<(usize, u64)> {
        if index >= self.total {
            return None;
        }

        self.segments
            .iter()
            .enumerate()
            .find(|(_, seg)| index < seg.start + seg.count)
            .map(|(idx, seg)| (idx, index - seg.start))
    }

    #[inline]
    pub fn segment_length(&self, segment_idx: usize) -> Option<usize> {
        self.segments.get(segment_idx).map(|seg| seg.length)
    }

    /// Convert a linear index into the corresponding password.
    #[inline]
    pub fn password_for(&self, index: u64) -> Option<String> {
        let segment = self
            .segments
            .iter()
            .find(|seg| index < seg.start + seg.count)?;

        let local_index = index - segment.start;
        let base = self.charset.len() as u64;

        let mut value = local_index;
        let mut buffer = vec![self.charset[0]; segment.length];

        for pos in (0..segment.length).rev() {
            let digit = (value % base) as usize;
            buffer[pos] = self.charset[digit];
            value /= base;
        }

        Some(buffer.into_iter().collect())
    }
}

/// Execute a brute-force attack.
pub fn crack(
    checker: &PasswordChecker,
    charset: Vec<char>,
    min_length: usize,
    max_length: usize,
    threads: usize,
    show_progress: bool,
) -> Result<Option<String>, String> {
    let keyspace = Keyspace::new(charset, min_length, max_length)?;
    if keyspace.total() == 0 {
        return Ok(None);
    }

    log::info!("Brute force keyspace: {} combinations", keyspace.total());

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

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| format!("Failed to build thread pool: {e}"))?;

    let found = pool.install(|| {
        (0..keyspace.total()).into_par_iter().find_map_any(|idx| {
            if let Some(pb) = progress_shared.as_ref() {
                pb.inc(1);
            }

            let candidate = keyspace.password_for(idx)?;
            match checker.check(&candidate) {
                Ok(true) => Some(candidate),
                Ok(false) => None,
                Err(err) => {
                    log::error!("Checker error for candidate '{}': {}", candidate, err);
                    None
                }
            }
        })
    });

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    Ok(found)
}
