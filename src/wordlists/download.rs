use super::{digest, Entry, Library};
use crate::presentation;
use crate::wordlists::reader::Candidates;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

// Network downloads are capped; local files are streamed without a file-size limit.
const MAX_DOWNLOAD: u64 = 2 * 1024 * 1024 * 1024;

impl Library {
    pub(super) fn download(
        &self,
        id: &str,
        url: &str,
        cached: Option<Entry>,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        if self.offline {
            return Err(format!("{id} is not available offline; fetch it online first").into());
        }
        presentation::note(&format!("Fetching {id}"));
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(60))
            .timeout(Duration::from_secs(600))
            .build();
        let mut request = agent.get(url).set(
            "User-Agent",
            concat!("zip-cracker/", env!("CARGO_PKG_VERSION")),
        );
        if let Some(entry) = cached.as_ref().filter(|entry| entry.source == url) {
            if let Some(etag) = &entry.etag {
                request = request.set("If-None-Match", etag);
            }
            if let Some(modified) = &entry.last_modified {
                request = request.set("If-Modified-Since", modified);
            }
        }
        let response = request
            .call()
            .map_err(|error| format!("Cannot fetch {id}: {error}"))?;
        if response.status() == 304 {
            let entry = cached.ok_or("Server returned 304 without a cached dictionary")?;
            presentation::detail("Cached copy is up to date");
            return Ok(self.object(&entry.sha256));
        }
        if response.status() != 200 {
            return Err(format!("Unexpected HTTP status {} for {id}", response.status()).into());
        }
        let content_type = response
            .header("Content-Type")
            .unwrap_or("")
            .to_ascii_lowercase();
        if content_type.contains("text/html") || content_type.contains("application/json") {
            return Err(format!(
                "{id}: server returned {content_type}, expected a text/gzip wordlist"
            )
            .into());
        }
        let length = response
            .header("Content-Length")
            .and_then(|value| value.parse::<u64>().ok());
        if length.is_some_and(|length| length > MAX_DOWNLOAD) {
            return Err(
                "Wordlist download exceeds the 2 GiB limit; use a local file instead".into(),
            );
        }
        let progress = ProgressBar::new(length.unwrap_or(0));
        progress.set_style(ProgressStyle::with_template(
            "  {spinner:.magenta} Downloading {bytes}/{total_bytes} · {bytes_per_sec}",
        )?);
        let etag = response.header("ETag").map(str::to_owned);
        let last_modified = response.header("Last-Modified").map(str::to_owned);
        let result = (|| {
            std::fs::create_dir_all(&self.root)?;
            let mut temporary = tempfile::NamedTempFile::new_in(&self.root)?;
            let mut hash = Sha256::new();
            let mut bytes = 0;
            let mut reader = response.into_reader();
            let mut buffer = [0u8; 64 * 1024];
            loop {
                self.check_cancelled()?;
                let count = match reader.read(&mut buffer) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                };
                if count == 0 {
                    break;
                }
                bytes += count as u64;
                if bytes > MAX_DOWNLOAD {
                    return Err("Wordlist download exceeds the 2 GiB limit".into());
                }
                temporary.write_all(&buffer[..count])?;
                hash.update(&buffer[..count]);
                progress.inc(count as u64);
            }
            // An incomplete body must never replace a usable cached version.
            if length.is_some_and(|expected| expected != bytes) {
                return Err("Incomplete wordlist download; cached copy was kept".into());
            }
            let mut candidates = Candidates::open(temporary.path())?;
            let mut lines = 0;
            while candidates.next()?.is_some() {
                self.check_cancelled()?;
                lines += 1;
            }
            drop(candidates);
            if lines == 0 {
                return Err("Downloaded wordlist is empty".into());
            }
            let entry = Entry {
                id: id.into(),
                source: url.into(),
                sha256: digest(hash.finalize()),
                bytes,
                lines,
                etag,
                last_modified,
            };
            self.publish(temporary, &entry, false)?;
            if let Some(old) = cached {
                if old.sha256 != entry.sha256 {
                    self.prune(&old.sha256);
                }
            }
            Ok(self.object(&entry.sha256))
        })();
        progress.finish_and_clear();
        result
    }
}
