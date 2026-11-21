use super::{catalog::CATALOG, digest, reader::Candidates, Entry, Library};
use crate::AppResult;
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Hash, PartialEq, Eq)]
pub(crate) enum SourceKey {
    File(PathBuf),
    Url(String),
}

pub(crate) struct SearchInput {
    pub candidates: Candidates,
    pub key: SourceKey,
    pub remote: bool,
}

impl SearchInput {
    fn file(path: &Path) -> AppResult<Self> {
        Ok(Self {
            candidates: Candidates::open(path)?,
            key: SourceKey::File(path.canonicalize()?),
            remote: false,
        })
    }
}

struct HttpBody {
    reader: Box<dyn Read>,
    expected: Option<u64>,
    received: u64,
}

impl Read for HttpBody {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let read = self.reader.read(buffer).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("Wordlist HTTP stream interrupted; search incomplete: {error}"),
            )
        })?;
        if read == 0 && self.expected.is_some_and(|size| size != self.received) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Wordlist HTTP stream ended early; search incomplete",
            ));
        }
        self.received += read as u64;
        Ok(read)
    }
}

impl Library {
    /// Use verified local copies when possible; otherwise search HTTP directly.
    pub fn open_search(&self, source: &str, refresh: bool) -> AppResult<SearchInput> {
        self.check_cancelled()?;
        if self.offline || (!source.starts_with('@') && Path::new(source).is_file()) {
            return SearchInput::file(&self.resolve(source, false)?);
        }
        let name = source.strip_prefix('@').unwrap_or(source);
        let direct = source.starts_with("https://") || source.starts_with("http://");
        let id = if direct {
            format!("url-{}", &digest(Sha256::digest(source.as_bytes()))[..16])
        } else {
            name.into()
        };
        let record = self.load(&id)?;
        if direct && record.as_ref().is_some_and(|entry| entry.source != source) {
            return Err("URL cache key collision".into());
        }
        let cached = record.as_ref().filter(|entry| self.verified(entry));
        if !refresh {
            if let Some(entry) = cached {
                return SearchInput::file(&self.object(&entry.sha256));
            }
        }
        let url = if direct {
            Some(source)
        } else {
            CATALOG
                .iter()
                .find(|entry| entry.id == name)
                .map(|entry| entry.url)
                .or_else(|| {
                    record
                        .as_ref()
                        .filter(|entry| {
                            entry.id.starts_with("url-")
                                && (entry.source.starts_with("https://")
                                    || entry.source.starts_with("http://"))
                        })
                        .map(|entry| entry.source.as_str())
                })
        };
        if let Some(url) = url {
            return self.open_http(url, cached);
        }
        SearchInput::file(&self.resolve(source, false)?)
    }

    fn open_http(&self, url: &str, cached: Option<&Entry>) -> AppResult<SearchInput> {
        // No whole-request deadline: large dictionaries can legitimately take hours.
        // The read timeout applies only while waiting for the next network bytes.
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(30))
            .build();
        let mut request = agent.get(url).set(
            "User-Agent",
            concat!("zip-cracker/", env!("CARGO_PKG_VERSION")),
        );
        if let Some(entry) = cached.filter(|entry| entry.source == url) {
            if let Some(etag) = &entry.etag {
                request = request.set("If-None-Match", etag);
            }
            if let Some(modified) = &entry.last_modified {
                request = request.set("If-Modified-Since", modified);
            }
        }
        let response = request
            .call()
            .map_err(|error| format!("Cannot open wordlist stream: {error}"))?;
        if response.status() == 304 {
            let entry = cached.ok_or("Server returned 304 without a cached wordlist")?;
            return SearchInput::file(&self.object(&entry.sha256));
        }
        if response.status() != 200 {
            return Err(format!("Unexpected wordlist HTTP status {}", response.status()).into());
        }
        let content_type = response
            .header("Content-Type")
            .unwrap_or("")
            .to_ascii_lowercase();
        if content_type.contains("text/html") || content_type.contains("application/json") {
            return Err(
                format!("Server returned {content_type}, expected a text/gzip wordlist").into(),
            );
        }
        let expected = response
            .header("Content-Length")
            .and_then(|size| size.parse().ok());
        let body = HttpBody {
            reader: response.into_reader(),
            expected,
            received: 0,
        };
        Ok(SearchInput {
            candidates: Candidates::from_reader(body)?,
            key: SourceKey::Url(url.into()),
            remote: true,
        })
    }
}
