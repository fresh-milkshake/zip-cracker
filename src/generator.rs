use crate::archive::is_right_password;
use crate::zipcrypto::HeaderFilter;
use indicatif::ProgressBar;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zip::ZipArchive;

const BLOCK_SIZE: u64 = 4096;
pub const MAX_PASSWORD_LENGTH: usize = 16;
pub const DEFAULT_CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
type CachedArchive = ZipArchive<Cursor<Arc<[u8]>>>;

pub struct GenerationOptions {
    pub min_length: u32,
    pub max_length: u32,
    pub charset: String,
    pub threads: usize,
    pub limit: Option<u64>,
}

impl GenerationOptions {
    pub fn total(&self) -> Result<u64, String> {
        if self.min_length == 0
            || self.min_length > self.max_length
            || self.max_length > MAX_PASSWORD_LENGTH as u32
        {
            return Err("Lengths must satisfy 1 <= min-length <= max-length <= 16".into());
        }
        let charset = self.charset.as_bytes();
        if charset.is_empty() || !self.charset.is_ascii() {
            return Err("Charset must contain nonempty ASCII characters".into());
        }
        let mut seen = [false; 128];
        for &byte in charset {
            if std::mem::replace(&mut seen[byte as usize], true) {
                return Err("Charset must not contain duplicate characters".into());
            }
        }
        if self.threads == 0 || self.limit == Some(0) {
            return Err("Threads and limit must be greater than zero".into());
        }
        let total = (self.min_length..=self.max_length)
            .try_fold(0u64, |total, length| {
                (charset.len() as u64)
                    .checked_pow(length)
                    .and_then(|count| total.checked_add(count))
            })
            .ok_or(
                "Search space exceeds the 64-bit candidate counter; narrow the charset or length",
            )?;
        Ok(self.limit.unwrap_or(total).min(total))
    }
}

pub struct GenerationResult {
    pub password: Option<String>,
    pub checked: u64,
    pub elapsed: Duration,
}

// Keep the original ordering: the first character is the least significant digit.
fn decode(mut index: u64, charset: &[u8], digits: &mut [usize], password: &mut [u8]) {
    for (digit, byte) in digits.iter_mut().zip(password) {
        *digit = (index % charset.len() as u64) as usize;
        *byte = charset[*digit];
        index /= charset.len() as u64;
    }
}

fn increment(charset: &[u8], digits: &mut [usize], password: &mut [u8]) {
    for (digit, byte) in digits.iter_mut().zip(password) {
        *digit += 1;
        if *digit < charset.len() {
            *byte = charset[*digit];
            break;
        }
        *digit = 0;
        *byte = charset[0];
    }
}

fn search_length(
    archive: &CachedArchive,
    options: &GenerationOptions,
    length: usize,
    count: u64,
    cancelled: &AtomicBool,
    progress: &ProgressBar,
) -> (Option<String>, u64) {
    let next = AtomicU64::new(0);
    let checked = AtomicU64::new(0);
    let found = AtomicBool::new(false);
    let mut metadata = archive.clone();
    let filter = metadata
        .by_index_raw(0)
        .ok()
        .and_then(|entry| HeaderFilter::from_entry(archive.clone().into_inner().get_ref(), &entry))
        .map(|header| header.prepare(options.charset.as_bytes(), length));
    let threads = (options.threads as u64).min(count.div_ceil(BLOCK_SIZE)) as usize;
    let password = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    // Only the cursor and metadata are cloned. Archive bytes are shared read-only.
                    let mut archive = archive.clone();
                    let charset = options.charset.as_bytes();
                    let mut password = [0u8; MAX_PASSWORD_LENGTH];
                    let mut digits = [0usize; MAX_PASSWORD_LENGTH];
                    loop {
                        if found.load(Ordering::Relaxed) || cancelled.load(Ordering::Relaxed) {
                            return None;
                        }
                        let start = next.fetch_add(BLOCK_SIZE, Ordering::Relaxed);
                        if start >= count {
                            return None;
                        }
                        let end = start.saturating_add(BLOCK_SIZE).min(count);
                        decode(
                            start,
                            charset,
                            &mut digits[..length],
                            &mut password[..length],
                        );
                        let mut attempts = 0;
                        let prefix_count =
                            filter.as_ref().map_or(1, |filter| filter.prefix_count());
                        let mut prefix_index = start % prefix_count;
                        let mut result = None;
                        while attempts < end - start {
                            if found.load(Ordering::Relaxed) || cancelled.load(Ordering::Relaxed) {
                                break;
                            }
                            let batch_size = if filter.is_some() {
                                (end - start - attempts).min(4) as usize
                            } else {
                                1
                            };
                            let mut candidates = [[0; MAX_PASSWORD_LENGTH]; 4];
                            for candidate in &mut candidates[..batch_size] {
                                *candidate = password;
                                increment(charset, &mut digits[..length], &mut password[..length]);
                            }
                            let matches = filter.as_ref().map_or([true; 4], |filter| {
                                filter.match_batch(prefix_index, &candidates, length)
                            });
                            attempts += batch_size as u64;
                            for lane in 0..batch_size {
                                if matches[lane]
                                    && is_right_password(&mut archive, &candidates[lane][..length])
                                {
                                    found.store(true, Ordering::Relaxed);
                                    result = Some(
                                        String::from_utf8(candidates[lane][..length].to_vec())
                                            .unwrap(),
                                    );
                                    break;
                                }
                            }
                            if result.is_some() {
                                break;
                            }
                            prefix_index += batch_size as u64;
                            if prefix_index >= prefix_count {
                                prefix_index %= prefix_count;
                            }
                        }
                        checked.fetch_add(attempts, Ordering::Relaxed);
                        progress.inc(attempts);
                        if result.is_some() {
                            return result;
                        }
                    }
                })
            })
            .collect();
        // Join every worker, including after a match, so counts include in-flight checks.
        let mut result = None;
        for handle in handles {
            result = result.or(handle.join().expect("Generator worker panicked"));
        }
        result
    });
    (password, checked.load(Ordering::Relaxed))
}

pub fn generate_attack(
    zip_path: &str,
    options: &GenerationOptions,
    cancelled: &AtomicBool,
) -> Result<GenerationResult, Box<dyn std::error::Error>> {
    let total = options.total()?;
    let started = Instant::now();
    // One archive-sized allocation avoids disk seeks for each password, regardless of search size.
    let bytes: Arc<[u8]> = std::fs::read(zip_path)?.into();
    let archive = ZipArchive::new(Cursor::new(bytes))?;
    let progress = crate::presentation::progress(total, "Character search");
    let mut checked = 0;
    let mut password = None;
    for length in options.min_length..=options.max_length {
        if checked == total || cancelled.load(Ordering::Relaxed) {
            break;
        }
        progress.set_message(format!("Length {length}"));
        let count = (options.charset.len() as u64)
            .pow(length)
            .min(total - checked);
        let (result, attempts) = search_length(
            &archive,
            options,
            length as usize,
            count,
            cancelled,
            &progress,
        );
        checked += attempts;
        if result.is_some() {
            password = result;
            break;
        }
    }
    progress.finish_and_clear();
    Ok(GenerationResult {
        password,
        checked,
        elapsed: started.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(charset: &str, length: u32) -> GenerationOptions {
        GenerationOptions {
            min_length: length,
            max_length: length,
            charset: charset.into(),
            threads: 4,
            limit: None,
        }
    }

    fn archive() -> CachedArchive {
        let bytes: Arc<[u8]> = include_bytes!("../tests/fixtures/abcde12.bin")
            .as_slice()
            .into();
        ZipArchive::new(Cursor::new(bytes)).unwrap()
    }

    #[test]
    fn odometer_matches_index_across_carries() {
        let mut digits = [0; 4];
        let mut actual = [b'a'; 4];
        for index in 0..81 {
            let mut expected = [0; 4];
            decode(index, b"abc", &mut [0; 4], &mut expected);
            assert_eq!(actual, expected);
            increment(b"abc", &mut digits, &mut actual);
        }
    }

    #[test]
    fn decodes_seven_character_index_beyond_u32() {
        let mut password = [0; 7];
        decode(
            3_115_827_589_710,
            DEFAULT_CHARSET.as_bytes(),
            &mut [0; 7],
            &mut password,
        );
        assert_eq!(&password, b"abcde12");
    }

    #[test]
    fn validates_search_space() {
        assert!(options("aab", 7).total().is_err());
        assert!(options("", 7).total().is_err());
        assert!(options("я", 7).total().is_err());
        assert!(options("ab", 17).total().is_err());
        assert_eq!(options("ab", 9).total().unwrap(), 512);
        assert!(options(DEFAULT_CHARSET, 16).total().is_err());
        assert_eq!(options(DEFAULT_CHARSET, 8).total().unwrap(), 62u64.pow(8));
    }

    #[test]
    fn exhausts_partial_block_without_missing_or_duplicating_candidates() {
        let (password, checked) = search_length(
            &archive(),
            &options("abc", 8),
            8,
            6500,
            &AtomicBool::new(false),
            &ProgressBar::hidden(),
        );
        assert!(password.is_none());
        assert_eq!(checked, 6500);
    }

    #[test]
    fn respects_cancellation() {
        let (password, checked) = search_length(
            &archive(),
            &options(DEFAULT_CHARSET, 7),
            7,
            62u64.pow(7),
            &AtomicBool::new(true),
            &ProgressBar::hidden(),
        );
        assert!(password.is_none());
        assert_eq!(checked, 0);
    }
}
