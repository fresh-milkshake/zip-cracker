use crate::zipcrypto::HeaderFilter;
use crate::AppResult;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek};
use std::sync::Arc;
use zip::ZipArchive;

pub fn check_encrypted(path: &str) -> AppResult {
    let mut archive = ZipArchive::new(File::open(path)?)?;
    first_encrypted_file(&mut archive).map(|_| ())
}

fn first_encrypted_file<R: Read + Seek>(archive: &mut ZipArchive<R>) -> AppResult<usize> {
    for index in 0..archive.len() {
        let entry = archive.by_index_raw(index)?;
        if entry.encrypted() && !entry.is_dir() {
            return Ok(index);
        }
    }
    Err("The zip file is not encrypted".into())
}

#[derive(Clone)]
pub(crate) struct CachedArchive {
    archive: ZipArchive<Cursor<Arc<[u8]>>>,
    entry_index: usize,
    pub(crate) filter: Option<HeaderFilter>,
}

impl CachedArchive {
    pub(crate) fn open(path: &str) -> AppResult<Self> {
        check_encrypted(path)?;
        // Workers share the archive bytes and keep their own read cursors.
        let bytes: Arc<[u8]> = std::fs::read(path)?.into();
        let mut archive = ZipArchive::new(Cursor::new(bytes.clone()))?;
        let entry_index = first_encrypted_file(&mut archive)?;
        let entry = archive.by_index_raw(entry_index)?;
        let filter = HeaderFilter::from_entry(&bytes, &entry);
        drop(entry);
        Ok(Self {
            archive,
            entry_index,
            filter,
        })
    }

    #[inline]
    pub(crate) fn verify_password(&mut self, password: &[u8]) -> bool {
        is_right_password(&mut self.archive, self.entry_index, password)
    }
}

pub(crate) fn is_right_password<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    entry_index: usize,
    password: &[u8],
) -> bool {
    if let Ok(mut zip) = archive.by_index_decrypt(entry_index, password) {
        let expected = zip.size();
        // Read through EOF: this runs CRC/AES authentication as well as checking size.
        matches!(io::copy(&mut zip, &mut io::sink()), Ok(size) if size == expected)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn rejects_corrupt_payloads_even_with_the_correct_password() {
        for fixture in [
            include_bytes!("../tests/fixtures/abcde12.bin").as_slice(),
            include_bytes!("../tests/fixtures/deflated.bin").as_slice(),
            include_bytes!("../tests/fixtures/aes.bin").as_slice(),
        ] {
            let mut bytes = fixture.to_vec();
            let mut archive = ZipArchive::new(Cursor::new(&bytes)).unwrap();
            assert!(is_right_password(&mut archive, 0, b"abcde12"));
            let entry = archive.by_index_raw(0).unwrap();
            let last = (entry.data_start() + entry.compressed_size() - 1) as usize;
            drop(entry);
            drop(archive);
            bytes[last] ^= 0xff;
            let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
            assert!(!is_right_password(&mut archive, 0, b"abcde12"));
        }
    }

    #[test]
    fn rejects_incorrect_uncompressed_sizes() {
        for difference in [-1i64, 1] {
            let mut bytes = include_bytes!("../tests/fixtures/abcde12.bin").to_vec();
            let mut archive = ZipArchive::new(Cursor::new(&bytes)).unwrap();
            let entry = archive.by_index_raw(0).unwrap();
            let central = entry.central_header_start() as usize;
            let local = entry.header_start() as usize;
            let size = (entry.size() as i64 + difference) as u32;
            drop(entry);
            drop(archive);
            bytes[central + 24..central + 28].copy_from_slice(&size.to_le_bytes());
            bytes[local + 22..local + 26].copy_from_slice(&size.to_le_bytes());
            let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
            assert!(!is_right_password(&mut archive, 0, b"abcde12"));
        }
    }
}
