use crate::zipcrypto::HeaderFilter;
use crate::AppResult;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::sync::Arc;
use zip::{CompressionMethod, ZipArchive};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encryption {
    ZipCrypto,
    Aes,
    Other,
}

pub(crate) fn read_encryption(
    headers: &mut File,
    entry: &zip::read::ZipFile<'_, File>,
) -> AppResult<Option<Encryption>> {
    if !entry.encrypted() {
        return Ok(None);
    }
    headers.seek(SeekFrom::Start(entry.central_header_start()))?;
    let mut header = [0; 12];
    headers.read_exact(&mut header)?;
    if &header[..4] != b"PK\x01\x02" {
        return Err("Invalid ZIP central header".into());
    }
    let flags = u16::from_le_bytes([header[8], header[9]]);
    let method = u16::from_le_bytes([header[10], header[11]]);
    Ok(Some(match (method, flags & 0x40) {
        (99, _) => Encryption::Aes,
        (_, 0) => Encryption::ZipCrypto,
        _ => Encryption::Other,
    }))
}

pub(crate) const MIN_BKCRACK_ENTRY_SIZE: u64 = 12;

#[derive(Default)]
pub(crate) struct ArchiveInfo {
    pub files: usize,
    pub directories: usize,
    pub zipcrypto: usize,
    pub aes: usize,
    pub other: usize,
    pub password_search: bool,
    pub bkcrack: bool,
}

pub(crate) fn inspect(path: &str) -> AppResult<ArchiveInfo> {
    let mut archive = ZipArchive::new(File::open(path)?)?;
    let mut headers = File::open(path)?;
    let mut info = ArchiveInfo::default();
    for index in 0..archive.len() {
        let entry = archive.by_index_raw(index)?;
        if entry.is_dir() {
            info.directories += 1;
            continue;
        }
        info.files += 1;
        let Some(encryption) = read_encryption(&mut headers, &entry)? else {
            continue;
        };
        if info.zipcrypto + info.aes + info.other == 0 {
            info.password_search = encryption != Encryption::Other
                && matches!(
                    entry.compression(),
                    CompressionMethod::Stored
                        | CompressionMethod::Deflated
                        | CompressionMethod::Bzip2
                        | CompressionMethod::Zstd
                );
        }
        match encryption {
            Encryption::ZipCrypto => info.zipcrypto += 1,
            Encryption::Aes => info.aes += 1,
            Encryption::Other => info.other += 1,
        }
        info.bkcrack |= encryption == Encryption::ZipCrypto
            && entry.compression() == CompressionMethod::Stored
            && entry.size() >= MIN_BKCRACK_ENTRY_SIZE;
    }
    Ok(info)
}

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
