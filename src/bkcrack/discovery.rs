use super::templates::{self, Confidence, PlaintextGuess};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use zip::{CompressionMethod, ZipArchive};

const MAX_COPY: u64 = 16 * 1024 * 1024;
const MAX_KNOWN_BYTES: usize = 64 * 1024;

pub struct Attack {
    pub index: usize,
    pub name: String,
    pub guess: PlaintextGuess,
}

struct Entry {
    index: usize,
    name: String,
    relative: Option<PathBuf>,
    size: u64,
    crc: u32,
    encrypted: bool,
    zipcrypto: bool,
    stored: bool,
}

fn entry_metadata(
    path: &Path,
) -> Result<(ZipArchive<File>, Vec<Entry>), Box<dyn std::error::Error>> {
    let mut archive = ZipArchive::new(File::open(path)?)?;
    let mut headers = File::open(path)?;
    let mut entries = Vec::new();
    for index in 0..archive.len() {
        let entry = archive.by_index_raw(index)?;
        if entry.is_dir() {
            continue;
        }
        headers.seek(SeekFrom::Start(entry.central_header_start()))?;
        let mut header = [0; 46];
        headers.read_exact(&mut header)?;
        if &header[..4] != b"PK\x01\x02" {
            return Err("Invalid ZIP central header".into());
        }
        let flags = u16::from_le_bytes([header[8], header[9]]);
        let method = u16::from_le_bytes([header[10], header[11]]);
        entries.push(Entry {
            index,
            name: entry.name().into(),
            relative: entry.enclosed_name(),
            size: entry.size(),
            crc: entry.crc32(),
            encrypted: flags & 1 != 0,
            zipcrypto: flags & 1 != 0 && flags & 0x40 == 0 && method != 99,
            stored: entry.compression() == CompressionMethod::Stored,
        });
    }
    Ok((archive, entries))
}

fn verified_copy(
    mut reader: impl Read,
    entry: &Entry,
    description: String,
) -> io::Result<Option<PlaintextGuess>> {
    if !(12..=MAX_COPY).contains(&entry.size) {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    reader.by_ref().take(MAX_COPY + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != entry.size || crc32fast::hash(&bytes) != entry.crc {
        return Ok(None);
    }
    bytes.truncate(MAX_KNOWN_BYTES);
    Ok(Some(PlaintextGuess {
        description,
        bytes,
        extra: Vec::new(),
        confidence: Confidence::VerifiedCopy,
    }))
}

pub fn discover(path: &Path) -> Result<Vec<Attack>, Box<dyn std::error::Error>> {
    let path = path.canonicalize()?;
    let parent = path.parent().ok_or("Archive has no parent directory")?;
    let (mut archive, entries) = entry_metadata(&path)?;
    let mut attacks = Vec::new();
    for entry in &entries {
        if !entry.encrypted {
            continue;
        }
        if !entry.zipcrypto {
            println!("Skipping {:?}: encryption is not ZipCrypto", entry.name);
            continue;
        }
        if !entry.stored {
            println!("Skipping {:?}: compressed entry; original-file headers do not match the encrypted compressed stream", entry.name);
            continue;
        }
        if entry.size < 12 {
            println!(
                "Skipping {:?}: only {} plaintext bytes, fewer than this bkcrack mode requires",
                entry.name, entry.size
            );
            continue;
        }
        let mut guesses = Vec::new();
        // Inspect only the matching path beside the archive, never a recursive filesystem scan.
        if let Some(relative) = &entry.relative {
            let local = parent.join(relative);
            if let Ok(local) = local.canonicalize() {
                if local.starts_with(parent) && local != path {
                    if let Ok(file) = File::open(&local) {
                        if let Ok(Some(guess)) = verified_copy(
                            file,
                            entry,
                            format!(
                                "Matching local copy {:?}, size and CRC32 verified",
                                relative
                            ),
                        ) {
                            guesses.push(guess);
                        }
                    }
                }
            }
        }
        for other in &entries {
            if other.encrypted || other.size != entry.size || other.crc != entry.crc {
                continue;
            }
            if let Ok(file) = archive.by_index(other.index) {
                if let Ok(Some(guess)) = verified_copy(
                    file,
                    entry,
                    format!(
                        "Matching unencrypted entry {:?}, size and CRC32 verified",
                        other.name
                    ),
                ) {
                    guesses.push(guess);
                }
            }
        }
        if guesses.is_empty() {
            guesses = templates::for_entry(&entry.name, entry.size);
        }
        if guesses.is_empty() {
            println!(
                "No supported automatic plaintext assumption for {:?}",
                entry.name
            );
        }
        for guess in guesses {
            attacks.push(Attack {
                index: entry.index,
                name: entry.name.clone(),
                guess,
            });
        }
    }
    // Prefer independently checked local copies, then longer contiguous plaintext.
    attacks.sort_by_key(|attack| {
        (
            std::cmp::Reverse(attack.guess.confidence == Confidence::VerifiedCopy),
            std::cmp::Reverse(attack.guess.bytes.len()),
        )
    });
    Ok(attacks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixture(path: &Path) {
        std::fs::write(path, include_bytes!("../../tests/fixtures/abcde12.bin")).unwrap();
    }

    #[test]
    fn local_copy_is_accepted_only_after_size_and_crc_verification() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("encrypted.zip");
        fixture(&path);
        assert!(discover(&path).unwrap().is_empty());
        std::fs::write(directory.path().join("payload.txt"), b"wrong contents").unwrap();
        assert!(discover(&path).unwrap().is_empty());
        let mut archive = ZipArchive::new(File::open(&path).unwrap()).unwrap();
        let mut bytes = Vec::new();
        archive
            .by_index_decrypt(0, b"abcde12")
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        std::fs::write(directory.path().join("payload.txt"), bytes).unwrap();
        let guesses = discover(&path).unwrap();
        assert_eq!(guesses.len(), 1);
        assert_eq!(guesses[0].guess.confidence, Confidence::VerifiedCopy);
    }

    #[test]
    fn plaintext_inside_archive_is_discovered_without_external_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("encrypted.zip");
        fixture(&path);
        let mut source = ZipArchive::new(File::open(&path).unwrap()).unwrap();
        let mut bytes = Vec::new();
        source
            .by_index_decrypt(0, b"abcde12")
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        drop(source);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut writer = zip::ZipWriter::new_append(file).unwrap();
        writer
            .start_file("public-copy.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&bytes).unwrap();
        writer.finish().unwrap();
        // zip 0.6's writer drops the encryption flag when rewriting the central directory.
        // Restore it on the unchanged encrypted entry of this append-only test fixture.
        let mut archive = ZipArchive::new(File::open(&path).unwrap()).unwrap();
        let central = archive.by_index_raw(0).unwrap().central_header_start();
        drop(archive);
        let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(central + 8)).unwrap();
        file.write_all(&1u16.to_le_bytes()).unwrap();
        drop(file);
        let guesses = discover(&path).unwrap();
        assert_eq!(guesses.len(), 1);
        assert!(guesses[0].guess.description.contains("unencrypted entry"));
    }

    #[test]
    fn aes_and_deflate_do_not_get_plain_file_header_guesses() {
        let directory = tempfile::tempdir().unwrap();
        for (name, bytes) in [
            (
                "aes.zip",
                include_bytes!("../../tests/fixtures/aes.bin").as_slice(),
            ),
            (
                "deflate.zip",
                include_bytes!("../../tests/fixtures/deflated.bin").as_slice(),
            ),
        ] {
            let path = directory.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            assert!(discover(&path).unwrap().is_empty());
        }
    }
}
