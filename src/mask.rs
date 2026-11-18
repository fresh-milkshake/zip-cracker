use crate::functions::is_right_password;
use crate::generator::{GenerationResult, MAX_PASSWORD_LENGTH};
use crate::zipcrypto::HeaderFilter;
use indicatif::{ProgressBar, ProgressStyle};
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use zip::ZipArchive;

const BLOCK_SIZE: u64 = 16_384;

pub struct Mask {
    positions: Vec<Vec<u8>>,
    count: u64,
}

impl Mask {
    pub fn parse(text: &str) -> Result<Self, String> {
        if !text.is_ascii() {
            return Err("Mask must contain ASCII characters".into());
        }
        let mut positions = Vec::new();
        let mut bytes = text.bytes();
        while let Some(byte) = bytes.next() {
            let charset = if byte != b'?' {
                vec![byte]
            } else {
                match bytes.next() {
                    Some(b'l') => (b'a'..=b'z').collect(),
                    Some(b'u') => (b'A'..=b'Z').collect(),
                    Some(b'd') => (b'0'..=b'9').collect(),
                    Some(b's') => (32..=126).filter(|byte: &u8| !byte.is_ascii_alphanumeric()).collect(),
                    Some(b'a') => (32..=126).collect(),
                    Some(b'?') => vec![b'?'],
                    _ => return Err("Mask tokens: ?l lowercase, ?u uppercase, ?d digits, ?s symbols, ?a printable ASCII, ?? literal question mark".into()),
                }
            };
            positions.push(charset);
        }
        if positions.is_empty() || positions.len() > MAX_PASSWORD_LENGTH {
            return Err("Mask length must be between 1 and 16 characters".into());
        }
        let count = positions
            .iter()
            .try_fold(1u64, |count, charset| {
                count.checked_mul(charset.len() as u64)
            })
            .ok_or("Mask search space exceeds the 64-bit candidate counter")?;
        Ok(Self { positions, count })
    }

    // Conventional lexicographic order: the rightmost position changes fastest.
    fn decode(&self, mut index: u64, digits: &mut [usize], password: &mut [u8]) {
        for position in (0..self.positions.len()).rev() {
            let charset = &self.positions[position];
            digits[position] = (index % charset.len() as u64) as usize;
            password[position] = charset[digits[position]];
            index /= charset.len() as u64;
        }
    }

    fn increment(&self, digits: &mut [usize], password: &mut [u8]) {
        for position in (0..self.positions.len()).rev() {
            let charset = &self.positions[position];
            digits[position] += 1;
            if digits[position] < charset.len() {
                password[position] = charset[digits[position]];
                break;
            }
            digits[position] = 0;
            password[position] = charset[0];
        }
    }
}

pub fn generate_mask_attack(
    path: &str,
    mask: &Mask,
    threads: usize,
    limit: Option<u64>,
    cancelled: &AtomicBool,
) -> Result<GenerationResult, Box<dyn std::error::Error>> {
    if threads == 0 || limit == Some(0) {
        return Err("Threads and limit must be greater than zero".into());
    }
    let started = Instant::now();
    let bytes: Arc<[u8]> = std::fs::read(path)?.into();
    let mut archive = ZipArchive::new(Cursor::new(bytes.clone()))?;
    let filter = archive
        .by_index_raw(0)
        .ok()
        .and_then(|entry| HeaderFilter::from_entry(&bytes, &entry));
    let total = limit.unwrap_or(mask.count).min(mask.count);
    let progress = ProgressBar::new(total);
    progress.set_style(ProgressStyle::with_template(
        "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {per_sec} {eta} Mask",
    )?);
    let next = AtomicU64::new(0);
    let checked = AtomicU64::new(0);
    let found = AtomicBool::new(false);
    let length = mask.positions.len();
    let worker_count = (threads as u64).min(total.div_ceil(BLOCK_SIZE)) as usize;
    let password = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..worker_count)
            .map(|_| {
                scope.spawn(|| {
                    let mut archive = archive.clone();
                    let mut password = [0; MAX_PASSWORD_LENGTH];
                    let mut digits = [0; MAX_PASSWORD_LENGTH];
                    loop {
                        if found.load(Ordering::Relaxed) || cancelled.load(Ordering::Relaxed) {
                            return None;
                        }
                        let start = next.fetch_add(BLOCK_SIZE, Ordering::Relaxed);
                        if start >= total {
                            return None;
                        }
                        let end = start.saturating_add(BLOCK_SIZE).min(total);
                        mask.decode(start, &mut digits, &mut password);
                        let mut attempts = 0;
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
                                mask.increment(&mut digits, &mut password);
                            }
                            let matches = filter.as_ref().map_or([true; 4], |filter| {
                                filter.match_passwords(&candidates, length)
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
        let mut result = None;
        for handle in handles {
            result = result.or(handle.join().expect("Mask worker panicked"));
        }
        result
    });
    progress.finish_and_clear();
    Ok(GenerationResult {
        password,
        checked: checked.load(Ordering::Relaxed),
        elapsed: started.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_radix_order_matches_odometer() {
        let mask = Mask::parse("?l?d!??").unwrap();
        assert_eq!(mask.count, 260);
        let mut digits = [0; MAX_PASSWORD_LENGTH];
        let mut actual = [0; MAX_PASSWORD_LENGTH];
        mask.decode(0, &mut digits, &mut actual);
        for index in 0..mask.count {
            let mut expected = [0; MAX_PASSWORD_LENGTH];
            mask.decode(index, &mut [0; MAX_PASSWORD_LENGTH], &mut expected);
            assert_eq!(actual, expected);
            mask.increment(&mut digits, &mut actual);
        }
        assert_eq!(&actual[..4], b"a0!?");
    }

    #[test]
    fn rejects_invalid_masks_and_overflow() {
        for text in [
            "",
            "?",
            "?x",
            "я",
            "12345678901234567",
            "?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a",
        ] {
            assert!(Mask::parse(text).is_err());
        }
        assert_eq!(
            Mask::parse("?l?l?l?l?l?d?d?d?l").unwrap().count,
            308_915_776_000
        );
    }
}
