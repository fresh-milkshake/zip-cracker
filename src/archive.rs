use crate::AppResult;
use std::fs::File;
use std::io::{self, Read, Seek};
use zip::ZipArchive;

pub fn check_encrypted(path: &str) -> AppResult {
    let mut archive = ZipArchive::new(File::open(path)?)?;
    let encrypted = archive.by_index_raw(0)?.encrypted();
    if encrypted {
        Ok(())
    } else {
        Err("The zip file is not encrypted".into())
    }
}

pub(crate) fn is_right_password<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    password: &[u8],
) -> bool {
    if let Ok(mut zip) = archive.by_index_decrypt(0, password) {
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
            assert!(is_right_password(&mut archive, b"abcde12"));
            let entry = archive.by_index_raw(0).unwrap();
            let last = (entry.data_start() + entry.compressed_size() - 1) as usize;
            drop(entry);
            drop(archive);
            bytes[last] ^= 0xff;
            let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
            assert!(!is_right_password(&mut archive, b"abcde12"));
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
            assert!(!is_right_password(&mut archive, b"abcde12"));
        }
    }
}
