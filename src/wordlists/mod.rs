mod catalog;
mod download;
mod picker;
pub(crate) mod reader;
mod stream;

use crate::cli::WordlistAction;
use crate::wordlists::reader::Candidates;
use crate::{presentation, AppResult};
use catalog::CATALOG;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Deserialize, Serialize)]
struct Entry {
    id: String,
    source: String,
    sha256: String,
    bytes: u64,
    lines: u64,
    etag: Option<String>,
    last_modified: Option<String>,
}

pub struct Library {
    root: PathBuf,
    offline: bool,
    cancelled: Arc<AtomicBool>,
}

fn digest(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn file_digest(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(digest(hash.finalize()))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 80
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

impl Library {
    pub fn new(directory: Option<&Path>, offline: bool) -> AppResult<Self> {
        let root = if let Some(directory) = directory {
            directory.to_owned()
        } else if let Some(directory) = std::env::var_os("ZIP_CRACKER_WORDLIST_DIR") {
            directory.into()
        } else {
            let base = if cfg!(windows) {
                std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
            } else if cfg!(target_os = "macos") {
                std::env::var_os("HOME").map(|home| PathBuf::from(home).join("Library/Caches"))
            } else {
                std::env::var_os("XDG_CACHE_HOME")
                    .map(PathBuf::from)
                    .or_else(|| {
                        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache"))
                    })
            }
            .ok_or("Cannot locate the wordlist cache; pass --wordlist-dir")?;
            base.join("zip-cracker/wordlists")
        };
        Ok(Self {
            root,
            offline,
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn handle_interrupts(&self) -> AppResult {
        let cancelled = self.cancelled.clone();
        ctrlc::set_handler(move || cancelled.store(true, Ordering::Relaxed))?;
        Ok(())
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    fn check_cancelled(&self) -> AppResult {
        if self.is_cancelled() {
            Err("Wordlist operation cancelled".into())
        } else {
            Ok(())
        }
    }

    fn manifest(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.json"))
    }
    fn object(&self, sha: &str) -> PathBuf {
        self.root.join("objects").join(sha)
    }

    fn load(&self, id: &str) -> AppResult<Option<Entry>> {
        if !valid_id(id) {
            return Err("Library IDs use 1–80 letters, digits, '-' or '_'".into());
        }
        let file = match File::open(self.manifest(id)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let entry: Entry = serde_json::from_reader(file.take(1024 * 1024))
            .map_err(|error| format!("Invalid cache record for {id}: {error}"))?;
        if entry.id != id
            || entry.sha256.len() != 64
            || !entry.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(format!("Invalid cache record for {id}; refresh or remove it").into());
        }
        Ok(Some(entry))
    }

    fn verified(&self, entry: &Entry) -> bool {
        let object = self.object(&entry.sha256);
        std::fs::metadata(&object).is_ok_and(|meta| meta.len() == entry.bytes)
            && file_digest(&object).is_ok_and(|hash| hash == entry.sha256)
    }

    pub fn resolve(&self, source: &str, refresh: bool) -> AppResult<PathBuf> {
        self.check_cancelled()?;
        if !source.starts_with('@') && Path::new(source).is_file() {
            return Ok(PathBuf::from(source));
        }
        let name = source.strip_prefix('@').unwrap_or(source);
        let builtin = CATALOG.iter().find(|entry| entry.id == name);
        let remote = source.starts_with("https://") || source.starts_with("http://");
        if !remote && !source.starts_with('@') && builtin.is_none() && !valid_id(source) {
            return Err(format!(
                "Wordlist file {source:?} was not found; use @ID for a library dictionary"
            )
            .into());
        }
        let id = if remote {
            format!("url-{}", &digest(Sha256::digest(source.as_bytes()))[..16])
        } else {
            name.into()
        };
        let mut cached = match self.load(&id) {
            Ok(entry) => entry,
            Err(_) if refresh && !self.offline && (remote || builtin.is_some()) => None,
            Err(error) => return Err(error),
        };
        let cached_url = cached
            .as_ref()
            .filter(|entry| {
                entry.id.starts_with("url-")
                    && (entry.source.starts_with("https://") || entry.source.starts_with("http://"))
            })
            .map(|entry| entry.source.clone());
        if let Some(entry) = &cached {
            if remote && entry.source != source {
                return Err("URL cache key collision".into());
            }
            if self.verified(entry) {
                if !refresh
                    || self.offline
                    || (!remote && builtin.is_none() && cached_url.is_none())
                {
                    return Ok(self.object(&entry.sha256));
                }
            } else {
                presentation::warning(format!("Cached {id} is missing or damaged"));
                cached = None;
            }
        }
        let url = builtin
            .map(|entry| entry.url)
            .or_else(|| remote.then_some(source))
            .or(cached_url.as_deref());
        if let Some(url) = url {
            self.download(&id, url, cached)
        } else {
            Err(format!("Wordlist {source:?} is missing or damaged; use 'wordlists list' or import a local file").into())
        }
    }

    fn lock(&self) -> io::Result<File> {
        std::fs::create_dir_all(&self.root)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.root.join(".lock"))?;
        lock.lock_exclusive()?;
        Ok(lock)
    }

    fn publish(
        &self,
        temporary: tempfile::NamedTempFile,
        entry: &Entry,
        create_only: bool,
    ) -> AppResult {
        let _lock = self.lock()?;
        if create_only && self.manifest(&entry.id).exists() {
            return Err(format!("@{} already exists; remove it first", entry.id).into());
        }
        std::fs::create_dir_all(self.root.join("objects"))?;
        // Content-addressed data is immutable; publish its record only after data is complete.
        temporary.as_file().sync_all()?;
        temporary.persist(self.object(&entry.sha256))?;
        let record = tempfile::NamedTempFile::new_in(&self.root)?;
        serde_json::to_writer_pretty(record.as_file(), entry)?;
        record.as_file().sync_all()?;
        record.persist(self.manifest(&entry.id))?;
        Ok(())
    }

    fn entries(&self) -> AppResult<Vec<Entry>> {
        let directory = match std::fs::read_dir(&self.root) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut entries = Vec::new();
        for file in directory {
            let path = file?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                if let Some(id) = path.file_stem().and_then(|id| id.to_str()) {
                    match self.load(id) {
                        Ok(Some(entry)) => entries.push(entry),
                        Err(error) => presentation::warning(error.to_string()),
                        _ => {}
                    }
                }
            }
        }
        entries.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(entries)
    }

    fn prune(&self, sha: &str) {
        if let Ok(_lock) = self.lock() {
            self.prune_locked(sha);
        }
    }

    fn prune_locked(&self, sha: &str) {
        if self
            .entries()
            .is_ok_and(|entries| entries.iter().all(|entry| entry.sha256 != sha))
        {
            let _ = std::fs::remove_file(self.object(sha));
        }
    }

    fn import(&self, path: &Path, id: &str) -> AppResult {
        if !valid_id(id) || id.starts_with("url-") || CATALOG.iter().any(|entry| entry.id == id) {
            return Err("Choose a custom ID using letters, digits, '-' or '_' (built-in IDs and url-* are reserved)".into());
        }
        if self.load(id)?.is_some() {
            return Err(format!("@{id} already exists; remove it first").into());
        }
        std::fs::create_dir_all(&self.root)?;
        let temporary = tempfile::NamedTempFile::new_in(&self.root)?;
        std::fs::copy(path, temporary.path())?;
        let mut candidates = Candidates::open(temporary.path())?;
        let mut lines = 0;
        while candidates.next()?.is_some() {
            self.check_cancelled()?;
            lines += 1;
        }
        drop(candidates);
        let entry = Entry {
            id: id.into(),
            source: path.canonicalize()?.display().to_string(),
            bytes: temporary.as_file().metadata()?.len(),
            lines,
            sha256: file_digest(temporary.path())?,
            etag: None,
            last_modified: None,
        };
        self.publish(temporary, &entry, true)?;
        presentation::success("Imported:", format!("@{id} · {lines} passwords"));
        Ok(())
    }

    pub fn execute(&self, action: WordlistAction) -> AppResult {
        match action {
            WordlistAction::List { query } => {
                presentation::heading("Wordlist library", &self.root.display().to_string());
                let query = query.unwrap_or_default().to_ascii_lowercase();
                let entries = self.entries()?;
                for dictionary in CATALOG {
                    if !format!("{} {}", dictionary.id, dictionary.description)
                        .to_ascii_lowercase()
                        .contains(&query)
                    {
                        continue;
                    }
                    let state = entries
                        .iter()
                        .find(|entry| entry.id == dictionary.id)
                        .map(|entry| {
                            format!("cached · {} lines · {} bytes", entry.lines, entry.bytes)
                        })
                        .unwrap_or_else(|| "stream on first use; fetch to save locally".into());
                    presentation::section(format!("@{} · {state}", dictionary.id));
                    presentation::detail(dictionary.description);
                    presentation::detail(dictionary.url);
                }
                for entry in entries
                    .iter()
                    .filter(|entry| !CATALOG.iter().any(|builtin| builtin.id == entry.id))
                {
                    if !format!("{} {}", entry.id, entry.source)
                        .to_ascii_lowercase()
                        .contains(&query)
                    {
                        continue;
                    }
                    presentation::section(format!(
                        "@{} · {} lines · {} bytes",
                        entry.id, entry.lines, entry.bytes
                    ));
                    presentation::detail(&entry.source);
                }
            }
            WordlistAction::Fetch { source, refresh } => {
                let path = self.resolve(&source, refresh)?;
                presentation::success("Ready:", path.display());
            }
            WordlistAction::Import { file, name } => {
                self.import(&file, name.trim_start_matches('@'))?
            }
            WordlistAction::Remove { name } => {
                let id = name.trim_start_matches('@');
                // Removing a corrupt record must still be possible, without trusting its hash.
                if !valid_id(id) {
                    return Err("Invalid library ID".into());
                }
                let _lock = self.lock()?;
                let entry = self.load(id).ok().flatten();
                std::fs::remove_file(self.manifest(id))?;
                if let Some(entry) = entry {
                    self.prune_locked(&entry.sha256);
                }
                presentation::success("Removed:", format!("@{id}"));
            }
        }
        Ok(())
    }
}
