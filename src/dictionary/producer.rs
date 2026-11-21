use super::Options;
use crate::wordlists::Library;
use crate::{presentation, AppResult};
use crossbeam_channel::Sender;
use indicatif::ProgressBar;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

const DEDUP_BYTES: usize = 8 * 1024 * 1024;
const DEDUP_ENTRIES: usize = 50_000;
const BATCH_BYTES: usize = 16 * 1024;
const BATCH_ENTRIES: usize = 256;

pub(super) fn send(
    sources: &[String],
    library: &Library,
    options: &Options,
    found: &AtomicBool,
    sender: &Sender<Vec<Vec<u8>>>,
    progress: &ProgressBar,
) -> AppResult<u64> {
    let mut seen = HashSet::new();
    let mut seen_bytes = 0;
    let mut files = HashSet::new();
    let mut batch = Vec::new();
    let mut batch_bytes = 0;
    let mut sent = 0u64;
    let mut skipped = 0;
    let stopped = || found.load(Ordering::Relaxed) || library.is_cancelled();
    'sources: for source in sources {
        if stopped() || options.limit.is_some_and(|limit| sent >= limit) {
            break;
        }
        let opened = library.open_search(source, options.refresh)?;
        if !options.keep_duplicates && !files.insert(opened.key) {
            continue;
        }
        progress.suspend(|| {
            presentation::detail(format!(
                "› {source}{}",
                if opened.remote { " · HTTP stream" } else { "" }
            ))
        });
        let mut input = opened.candidates;
        while !stopped() && options.limit.is_none_or(|limit| sent < limit) {
            // Finish available work before an I/O operation can block. This lets
            // even a match in the first line stop an unfinished HTTP response.
            if opened.remote && !input.has_buffered_line() {
                if !batch.is_empty() && sender.send(std::mem::take(&mut batch)).is_err() {
                    return Ok(skipped);
                }
                batch_bytes = 0;
                while progress.position() < sent && !stopped() {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                if stopped() {
                    break 'sources;
                }
            }
            let Some(word) = input.next().map_err(|error| format!("{source}: {error}"))? else {
                break;
            };
            for candidate in variants(word, options.rules) {
                if stopped() || options.limit.is_some_and(|limit| sent >= limit) {
                    break 'sources;
                }
                if candidate.len() < options.min_length || candidate.len() > options.max_length {
                    skipped += 1;
                    continue;
                }
                if !options.keep_duplicates {
                    // Exact byte comparisons, bounded to recent segments rather than a full-list set.
                    if seen.contains(&candidate) {
                        skipped += 1;
                        continue;
                    }
                    if seen.len() >= DEDUP_ENTRIES || seen_bytes + candidate.len() > DEDUP_BYTES {
                        seen.clear();
                        seen_bytes = 0;
                    }
                    seen_bytes += candidate.len();
                    seen.insert(candidate.clone());
                }
                sent += 1;
                batch_bytes += candidate.len();
                batch.push(candidate);
                if batch.len() >= BATCH_ENTRIES || batch_bytes >= BATCH_BYTES {
                    if sender.send(std::mem::take(&mut batch)).is_err() {
                        return Ok(skipped);
                    }
                    batch_bytes = 0;
                }
            }
        }
        // Give the workers this source before attempting the next (possibly remote) one.
        if !batch.is_empty() && sender.send(std::mem::take(&mut batch)).is_err() {
            return Ok(skipped);
        }
        batch_bytes = 0;
        // Finish this source before resolving/downloading another one. A match in
        // a small local list must not trigger an unnecessary large download.
        while progress.position() < sent && !stopped() {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    if !batch.is_empty() && !stopped() {
        let _ = sender.send(batch);
    }
    Ok(skipped)
}

fn variants(word: Vec<u8>, rules: bool) -> Vec<Vec<u8>> {
    if !rules {
        return vec![word];
    }
    let lowercase = word.to_ascii_lowercase();
    let mut capitalized = lowercase.clone();
    if let Some(first) = capitalized.first_mut() {
        first.make_ascii_uppercase();
    }
    let mut result = vec![word.clone(), lowercase, capitalized];
    for suffix in [b"1".as_slice(), b"123", b"!"] {
        let mut variant = word.clone();
        variant.extend_from_slice(suffix);
        result.push(variant);
    }
    result
}
