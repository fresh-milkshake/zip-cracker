use zip::read::ZipFile;

// A rejection filter only. Matches must still pass the ZIP reader's complete
// decryption/decompression/integrity check before being reported as passwords.
#[derive(Clone, Copy)]
pub struct HeaderFilter {
    encrypted: [u8; 12],
    expected: u8,
}

pub struct PreparedFilter {
    header: HeaderFilter,
    prefixes: Vec<Keys>,
    prefix_length: usize,
}

impl PreparedFilter {
    pub fn prefix_count(&self) -> u64 {
        self.prefixes.len() as u64
    }

    #[inline]
    pub fn match_batch<const N: usize>(
        &self,
        mut prefix_index: u64,
        passwords: &[[u8; N]; 4],
        length: usize,
    ) -> [bool; 4] {
        let mut keys = [Keys::new(); 4];
        for key in &mut keys {
            *key = self.prefixes[prefix_index as usize];
            prefix_index += 1;
            if prefix_index == self.prefix_count() {
                prefix_index = 0;
            }
        }
        for position in self.prefix_length..length {
            for lane in 0..4 {
                keys[lane].update(passwords[lane][position]);
            }
        }
        self.header.check_batch(keys)
    }

    #[inline]
    #[cfg(test)]
    pub fn may_match(&self, prefix_index: u64, password: &[u8]) -> bool {
        let mut keys = self.prefixes[prefix_index as usize];
        for &byte in &password[self.prefix_length..] {
            keys.update(byte);
        }
        self.header.check_keys(keys)
    }
}

impl HeaderFilter {
    #[inline]
    pub fn match_passwords<const N: usize>(
        &self,
        passwords: &[[u8; N]; 4],
        length: usize,
    ) -> [bool; 4] {
        let mut keys = [Keys::new(); 4];
        for position in 0..length {
            for lane in 0..4 {
                keys[lane].update(passwords[lane][position]);
            }
        }
        self.check_batch(keys)
    }

    #[inline]
    fn check_batch(&self, mut keys: [Keys; 4]) -> [bool; 4] {
        // Interleave independent candidates to hide the serial cipher dependency.
        for &byte in &self.encrypted[..11] {
            for key in &mut keys {
                let plain = byte ^ key.stream_byte();
                key.update(plain);
            }
        }
        keys.map(|key| self.encrypted[11] ^ key.stream_byte() == self.expected)
    }
    pub fn prepare(self, charset: &[u8], length: usize) -> PreparedFilter {
        // A bounded, shared cache, independent of the complete search space.
        let prefix_length = length.min(2);
        let count = charset.len().pow(prefix_length as u32);
        let mut prefixes = Vec::with_capacity(count);
        for mut index in 0..count {
            let mut keys = Keys::new();
            for _ in 0..prefix_length {
                keys.update(charset[index % charset.len()]);
                index /= charset.len();
            }
            prefixes.push(keys);
        }
        PreparedFilter {
            header: self,
            prefixes,
            prefix_length,
        }
    }
    pub fn from_entry(bytes: &[u8], entry: &ZipFile<'_>) -> Option<Self> {
        let central = usize::try_from(entry.central_header_start()).ok()?;
        let header = bytes.get(central..central.checked_add(46)?)?;
        if &header[..4] != b"PK\x01\x02" {
            return None;
        }
        let flags = u16::from_le_bytes([header[8], header[9]]);
        let method = u16::from_le_bytes([header[10], header[11]]);
        // AES and strong encryption use different header validation rules.
        if flags & 1 == 0 || flags & 0x40 != 0 || method == 99 || entry.compressed_size() < 12 {
            return None;
        }
        let start = usize::try_from(entry.data_start()).ok()?;
        let encrypted = bytes.get(start..start.checked_add(12)?)?.try_into().ok()?;
        let expected = if flags & 8 != 0 {
            header[13] // High byte of DOS time for entries using a data descriptor.
        } else {
            (entry.crc32() >> 24) as u8
        };
        Some(Self {
            encrypted,
            expected,
        })
    }

    #[inline]
    #[cfg(test)]
    pub fn may_match(&self, password: &[u8]) -> bool {
        let mut keys = Keys::new();
        for &byte in password {
            keys.update(byte);
        }
        self.check_keys(keys)
    }

    #[inline]
    #[cfg(test)]
    fn check_keys(&self, mut keys: Keys) -> bool {
        // Only the last header byte is checked; the first eleven evolve the keys.
        for &byte in &self.encrypted[..11] {
            let plain = byte ^ keys.stream_byte();
            keys.update(plain);
        }
        self.encrypted[11] ^ keys.stream_byte() == self.expected
    }
}

#[derive(Clone, Copy)]
struct Keys {
    first: u32,
    second: u32,
    third: u32,
}

impl Keys {
    #[inline]
    fn new() -> Self {
        Self {
            first: 0x12345678,
            second: 0x23456789,
            third: 0x34567890,
        }
    }

    #[inline]
    fn update(&mut self, byte: u8) {
        self.first = crc(self.first, byte);
        self.second = self
            .second
            .wrapping_add(self.first & 0xff)
            .wrapping_mul(0x08088405)
            .wrapping_add(1);
        self.third = crc(self.third, (self.second >> 24) as u8);
    }

    #[inline]
    fn stream_byte(&self) -> u8 {
        let value = (self.third as u16) | 3;
        (value.wrapping_mul(value ^ 1) >> 8) as u8
    }
}

#[inline]
fn crc(value: u32, byte: u8) -> u32 {
    (value >> 8) ^ CRC_TABLE[((value as u8) ^ byte) as usize]
}

const CRC_TABLE: [u32; 256] = {
    let mut table = [0; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = (value >> 1) ^ if value & 1 != 0 { 0xedb88320 } else { 0 };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functions::is_right_password;
    use std::io::{Cursor, Read};
    use zip::ZipArchive;

    #[test]
    fn filter_matches_library_header_validation() {
        for bytes in [
            include_bytes!("../tests/fixtures/abcde12.bin").as_slice(),
            include_bytes!("../tests/fixtures/deflated.bin").as_slice(),
        ] {
            let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
            let filter =
                HeaderFilter::from_entry(bytes, &archive.by_index_raw(0).unwrap()).unwrap();
            assert!(filter.may_match(b"abcde12"));
            let mut header_matches = 0;
            for index in 0..10_000 {
                let password = format!("wrong{index}");
                let expected =
                    matches!(archive.by_index_decrypt(0, password.as_bytes()), Ok(Ok(_)));
                assert_eq!(filter.may_match(password.as_bytes()), expected);
                if expected {
                    header_matches += 1;
                    assert!(!is_right_password(&mut archive, password.as_bytes()));
                }
            }
            assert!(header_matches > 0);
        }
    }

    #[test]
    fn aes_uses_library_fallback() {
        let bytes = include_bytes!("../tests/fixtures/aes.bin").as_slice();
        let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
        assert!(HeaderFilter::from_entry(bytes, &archive.by_index_raw(0).unwrap()).is_none());
    }

    #[test]
    fn batch_filter_matches_scalar_and_library_across_prefix_wraps() {
        let bytes = include_bytes!("../tests/fixtures/abcde12.bin").as_slice();
        let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
        let entry = archive.by_index_raw(0).unwrap();
        let header = HeaderFilter::from_entry(bytes, &entry).unwrap();
        assert!(HeaderFilter::from_entry(&[], &entry).is_none());
        drop(entry);
        for (charset, length) in [
            (b"a".as_slice(), 1),
            (b"ab", 1),
            (b"abc", 2),
            (b"abcde12", 7),
        ] {
            let prepared = header.prepare(charset, length);
            let count = (charset.len() as u64).pow(length as u32);
            for start in (0..count.min(10_000)).step_by(4) {
                let mut passwords = [[0; 8]; 4];
                for (lane, password) in passwords.iter_mut().enumerate() {
                    let mut index = start + lane as u64;
                    for byte in &mut password[..length] {
                        *byte = charset[index as usize % charset.len()];
                        index /= charset.len() as u64;
                    }
                }
                let batch =
                    prepared.match_batch(start % prepared.prefix_count(), &passwords, length);
                for lane in 0..4 {
                    let password = &passwords[lane][..length];
                    assert_eq!(
                        batch[lane],
                        prepared
                            .may_match((start + lane as u64) % prepared.prefix_count(), password)
                    );
                    assert_eq!(batch[lane], header.may_match(password));
                    assert_eq!(
                        batch[lane],
                        matches!(archive.by_index_decrypt(0, password), Ok(Ok(_)))
                    );
                }
            }
        }
    }

    #[test]
    fn data_descriptor_uses_dos_time_check_byte() {
        // Build a valid descriptor-style variant without relying on another ZIP writer.
        let mut bytes = include_bytes!("../tests/fixtures/abcde12.bin").to_vec();
        let mut archive = ZipArchive::new(Cursor::new(bytes.as_slice())).unwrap();
        let entry = archive.by_index_raw(0).unwrap();
        let start = entry.data_start() as usize;
        let local = entry.header_start() as usize;
        let central = entry.central_header_start() as usize;
        let crc = entry.crc32();
        let size = entry.size() as u32;
        let compressed = entry.compressed_size() as u32;
        drop(entry);
        let mut plaintext = Vec::new();
        archive
            .by_index_decrypt(0, b"abcde12")
            .unwrap()
            .unwrap()
            .read_to_end(&mut plaintext)
            .unwrap();
        drop(archive);
        let time = [bytes[local + 10], bytes[local + 11]];
        let mut keys = Keys::new();
        for &byte in b"abcde12" {
            keys.update(byte);
        }
        let header = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, time[1]];
        for (offset, plain) in header.into_iter().chain(plaintext).enumerate() {
            bytes[start + offset] = plain ^ keys.stream_byte();
            keys.update(plain);
        }
        bytes[local + 6] |= 8;
        bytes[central + 8] |= 8;
        bytes[local + 14..local + 26].fill(0);
        let descriptor: Vec<u8> = [0x08074b50, crc, compressed, size]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        bytes.splice(central..central, descriptor);
        let end = bytes.len() - 22;
        bytes[end + 16..end + 20].copy_from_slice(&((central + 16) as u32).to_le_bytes());
        let mut archive = ZipArchive::new(Cursor::new(bytes.as_slice())).unwrap();
        let filter = HeaderFilter::from_entry(&bytes, &archive.by_index_raw(0).unwrap()).unwrap();
        assert!(filter.may_match(b"abcde12"));
        assert!(is_right_password(&mut archive, b"abcde12"));
        for index in 0..1000 {
            let password = format!("wrong{index}");
            assert_eq!(
                filter.may_match(password.as_bytes()),
                matches!(archive.by_index_decrypt(0, password.as_bytes()), Ok(Ok(_)))
            );
        }
    }
}
