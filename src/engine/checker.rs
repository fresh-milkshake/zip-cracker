//! Password checking utilities.
//!
//! Provides a lightweight wrapper around the `zip` crate that lets us
//! verify password candidates quickly without keeping the archive fully
//! in memory.

use std::fs::File;
use std::io::{self, Cursor};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use memmap2::Mmap;
use zip::read::ZipArchive;
use zip::result::ZipError;

/// Shared password checker that opens the archive on demand.
#[derive(Clone)]
pub struct PasswordChecker {
    zip_path: PathBuf,
    data: Arc<Mmap>,
    encrypted_indices: Arc<Vec<usize>>,
    total_files: usize,
}

impl PasswordChecker {
    /// Build a checker for the provided archive.
    pub fn new<P: AsRef<Path>>(zip_path: P) -> Result<Self, String> {
        let zip_path = zip_path.as_ref().to_path_buf();

        if !zip_path.exists() {
            return Err(format!("ZIP file does not exist: {:?}", zip_path));
        }

        let file = File::open(&zip_path).map_err(|e| format!("Failed to open ZIP file: {e}"))?;
        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| format!("Failed to memory-map ZIP file: {e}"))?;
        let data = Arc::new(mmap);

        let mut archive = ZipArchive::new(Cursor::new(&data[..]))
            .map_err(|e| format!("Failed to read ZIP file: {e}"))?;

        let total_files = archive.len();
        let mut encrypted_indices = Vec::new();

        for i in 0..total_files {
            match archive.by_index(i) {
                Ok(_) => {}
                Err(ZipError::UnsupportedArchive(detail))
                    if detail == ZipError::PASSWORD_REQUIRED =>
                {
                    encrypted_indices.push(i);
                }
                Err(e) => return Err(format!("Failed to inspect ZIP entry {i}: {e}")),
            }
        }

        if encrypted_indices.is_empty() {
            log::warn!("Archive does not contain encrypted entries");
        } else {
            log::info!(
                "Archive has {} encrypted file(s); checking the first encrypted entry",
                encrypted_indices.len()
            );
        }

        Ok(Self {
            zip_path,
            data,
            encrypted_indices: Arc::new(encrypted_indices),
            total_files,
        })
    }

    /// Total number of files in the archive.
    pub fn file_count(&self) -> usize {
        self.total_files
    }

    /// Number of encrypted files discovered during initial scan.
    pub fn encrypted_count(&self) -> usize {
        self.encrypted_indices.len()
    }

    /// Verify a candidate password.
    ///
    /// Only the first encrypted entry is used, which is sufficient for ZIP
    /// archives where a single password protects all entries.
    pub fn check(&self, password: &str) -> Result<bool, String> {
        let Some(&entry_index) = self.encrypted_indices.first() else {
            return Ok(false);
        };

        let mut archive = ZipArchive::new(Cursor::new(&self.data[..]))
            .map_err(|e| format!("Failed to read ZIP file: {e}"))?;
        let result = archive.by_index_decrypt(entry_index, password.as_bytes());

        match result {
            Ok(Ok(mut zip_file)) => {
                // Consume the entire stream to force CRC verification.
                match io::copy(&mut zip_file, &mut io::sink()) {
                    Ok(_) => Ok(true),
                    Err(err) if is_probable_wrong_password(&err) => Ok(false),
                    Err(err) => Err(format!("Failed to read decrypted data: {err}")),
                }
            }
            Ok(Err(_invalid_password)) => Ok(false),
            Err(ZipError::UnsupportedArchive(detail)) if detail == ZipError::PASSWORD_REQUIRED => {
                Ok(false)
            }
            Err(err) => Err(format!("Failed to decrypt ZIP entry: {err}")),
        }
    }

    /// Path for logging / debugging purposes.
    pub fn zip_path(&self) -> &Path {
        &self.zip_path
    }
}

fn is_probable_wrong_password(err: &io::Error) -> bool {
    const HINTS: &[&str] = &[
        "corrupt",
        "invalid",
        "checksum",
        "incorrect header check",
        "bad code lengths",
        "invalid distance code",
    ];

    if matches!(
        err.kind(),
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
    ) {
        return true;
    }

    let message = err.to_string().to_lowercase();
    if HINTS.iter().any(|hint| message.contains(hint)) {
        return true;
    }

    err.get_ref()
        .map(|inner| {
            let inner = inner.to_string().to_lowercase();
            HINTS.iter().any(|hint| inner.contains(hint))
        })
        .unwrap_or(false)
}
