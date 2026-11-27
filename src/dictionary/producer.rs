use super::Options;
use crate::wordlists::Library;
use crate::{presentation, AppResult};
use crossbeam_channel::Sender;
use hashbrown::HashTable;
use indicatif::ProgressBar;
use std::collections::HashSet;
use std::hash::{BuildHasher, RandomState};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const DEDUP_BYTES: usize = 8 * 1024 * 1024;
const DEDUP_ENTRIES: usize = 50_000;
const BATCH_BYTES: usize = 32 * 1024;

#[derive(Default)]
pub(super) struct Batch {
    bytes: Vec<u8>,
    lengths: Vec<usize>,
}

impl Batch {
    pub(super) fn iter(&self) -> impl Iterator<Item = &[u8]> {
        let mut remaining = self.bytes.as_slice();
        self.lengths.iter().map(move |&length| {
            let (candidate, rest) = remaining.split_at(length);
            remaining = rest;
            candidate
        })
    }

    fn push(&mut self, candidate: &[u8], batch_entries: usize) {
        if self.lengths.capacity() == 0 {
            self.lengths.reserve(batch_entries);
            self.bytes.reserve((batch_entries * 16).min(BATCH_BYTES));
        }
        self.lengths.push(candidate.len());
        self.bytes.extend_from_slice(candidate);
    }

    fn flush(&mut self, sender: &Sender<Self>) -> bool {
        self.lengths.is_empty() || sender.send(std::mem::take(self)).is_ok()
    }
}

#[derive(Default)]
struct Seen {
    hash_builder: RandomState,
    entries: HashTable<(u64, Range<usize>)>,
    bytes: Vec<u8>,
}

impl Seen {
    fn insert(&mut self, candidate: &[u8]) -> bool {
        let hash = self.hash_builder.hash_one(candidate);
        if self
            .entries
            .find(hash, |(_, range)| &self.bytes[range.clone()] == candidate)
            .is_some()
        {
            return false;
        }
        if self.entries.len() >= DEDUP_ENTRIES || self.bytes.len() + candidate.len() > DEDUP_BYTES {
            self.entries.clear();
            self.bytes.clear();
        }
        // Store offsets instead of allocating a separate buffer for each unique word.
        let start = self.bytes.len();
        self.bytes.extend_from_slice(candidate);
        self.entries
            .insert_unique(hash, (hash, start..self.bytes.len()), |entry| entry.0);
        true
    }
}

pub(super) fn send(
    sources: &[String],
    library: &Library,
    options: &Options,
    found: &AtomicBool,
    sender: &Sender<Batch>,
    progress: &ProgressBar,
    batch_entries: usize,
) -> AppResult<u64> {
    let mut seen = Seen::default();
    let mut files = HashSet::new();
    let mut batch = Batch::default();
    let mut scratch = Vec::new();
    let mut sent = 0u64;
    let mut skipped = 0;
    let stopped = || found.load(Ordering::Relaxed) || library.is_cancelled();
    let wait_for_workers = |sent| {
        while progress.position() < sent && !stopped() {
            // Workers wake the producer after completing a batch. The timeout
            // also lets the producer observe cancellation when no batch completes.
            thread::park_timeout(Duration::from_millis(10));
        }
    };
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
                if !batch.flush(sender) {
                    return Ok(skipped);
                }
                wait_for_workers(sent);
                if stopped() {
                    break 'sources;
                }
            }
            let Some(word) = input.next().map_err(|error| format!("{source}: {error}"))? else {
                break;
            };
            let offered_all = offer_variants(word, options.rules, &mut scratch, |candidate| {
                if stopped() || options.limit.is_some_and(|limit| sent >= limit) {
                    return false;
                }
                if candidate.len() < options.min_length
                    || candidate.len() > options.max_length
                    || (!options.keep_duplicates && !seen.insert(candidate))
                {
                    skipped += 1;
                    return true;
                }
                batch.push(candidate, batch_entries);
                sent += 1;
                (batch.lengths.len() < batch_entries && batch.bytes.len() < BATCH_BYTES)
                    || batch.flush(sender)
            });
            if !offered_all {
                break 'sources;
            }
        }
        // Give the workers this source before attempting the next (possibly remote) one.
        if !batch.flush(sender) {
            return Ok(skipped);
        }
        // Finish this source before resolving/downloading another one. A match in
        // a small local list must not trigger an unnecessary large download.
        wait_for_workers(sent);
    }
    if !stopped() {
        batch.flush(sender);
    }
    Ok(skipped)
}

fn offer_variants(
    word: &[u8],
    rules: bool,
    scratch: &mut Vec<u8>,
    mut offer: impl FnMut(&[u8]) -> bool,
) -> bool {
    if !offer(word) {
        return false;
    }
    if !rules {
        return true;
    }
    scratch.clear();
    scratch.extend_from_slice(word);
    scratch.make_ascii_lowercase();
    if !offer(scratch) {
        return false;
    }
    if let Some(first) = scratch.first_mut() {
        first.make_ascii_uppercase();
    }
    if !offer(scratch) {
        return false;
    }
    scratch.copy_from_slice(word);
    for suffix in [b"1".as_slice(), b"123", b"!"] {
        scratch.truncate(word.len());
        scratch.extend_from_slice(suffix);
        if !offer(scratch) {
            return false;
        }
    }
    true
}
