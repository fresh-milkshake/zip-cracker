use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

struct RunningChild(Child);

impl Drop for RunningChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

pub struct Completion {
    pub success: bool,
    pub timed_out: bool,
}

pub fn run(
    command: &mut Command,
    log: &Path,
    budget: Duration,
    cancelled: &AtomicBool,
    label: &'static str,
) -> io::Result<Completion> {
    let output = File::create(log)?;
    command
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(output);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let mut child = RunningChild(command.spawn()?);
    let activity = crate::presentation::activity(label);
    let started = Instant::now();
    let mut last_update = Instant::now();
    loop {
        if let Some(status) = child.0.try_wait()? {
            return Ok(Completion {
                success: status.success(),
                timed_out: false,
            });
        }
        if cancelled.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Attack cancelled",
            ));
        }
        if started.elapsed() >= budget {
            return Ok(Completion {
                success: false,
                timed_out: true,
            });
        }
        let interval = if activity.0.is_hidden() {
            Duration::from_secs(5)
        } else {
            Duration::from_millis(250)
        };
        if last_update.elapsed() >= interval {
            let tail = log_tail(log).unwrap_or_default();
            if let Some((current, total)) = latest_progress(&tail) {
                if activity.0.length().is_none() {
                    activity.0.set_style(crate::presentation::progress_style());
                }
                activity.0.set_length(total);
                activity.0.set_position(current);
                if activity.0.is_hidden() {
                    crate::presentation::detail(format!(
                        "{label} · {current}/{total} · {:.0}s elapsed",
                        started.elapsed().as_secs_f64()
                    ));
                }
            } else {
                activity.0.tick();
            }
            last_update = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn latest_progress(log: &str) -> Option<(u64, u64)> {
    log.split(['\r', '\n']).rev().find_map(|line| {
        if !line.contains('%') {
            return None;
        }
        let (_, fraction) = line.rsplit_once('(')?;
        let (current, rest) = fraction.split_once('/')?;
        let total = rest.split_once(')')?.0;
        let current = current.trim().parse().ok()?;
        let total = total.trim().parse().ok()?;
        (total > 0 && current <= total).then_some((current, total))
    })
}

pub fn log_tail(path: &Path) -> io::Result<String> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    let size = file.metadata()?.len();
    file.seek(SeekFrom::Start(size.saturating_sub(4096)))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub fn parse_keys(log: &str) -> Option<[String; 3]> {
    log.split(['\r', '\n']).find_map(|line| {
        let words: Vec<_> = line.split_whitespace().collect();
        if words.len() == 3
            && words
                .iter()
                .all(|word| word.len() == 8 && word.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            Some([words[0].into(), words[1].into(), words[2].into()])
        } else {
            None
        }
    })
}

pub fn locate(explicit: Option<&Path>) -> io::Result<PathBuf> {
    if let Some(path) = explicit {
        return path.canonicalize();
    }
    if let Some(path) = std::env::var_os("BKCRACK_PATH") {
        return PathBuf::from(path).canonicalize();
    }
    let name = if cfg!(windows) {
        "bkcrack.exe"
    } else {
        "bkcrack"
    };
    let executable = std::env::current_exe()?;
    let mut candidates = vec![executable.with_file_name(name)];
    if let Some(paths) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&paths).map(|path| path.join(name)));
    }
    // Also recognize the local development installation downloaded for the test.
    if let Some(target) = executable.parent().and_then(Path::parent) {
        if let Ok(entries) = std::fs::read_dir(target) {
            let mut installations: Vec<_> = entries
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("bkcrack-"))
                .map(|entry| entry.path().join(name))
                .collect();
            installations.sort();
            installations.reverse();
            candidates.extend(installations);
        }
    }
    candidates.into_iter().find(|path| path.is_file()).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound,
        "bkcrack executable not found; place it beside this program, add it to PATH, or use --bkcrack-path"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_require_three_exact_hex_words() {
        assert!(parse_keys("Keys: aabbccdd 12345678 9abcdef0").is_none());
        assert!(parse_keys("aabbccdd 12345678 INVALID!").is_none());
        assert_eq!(
            parse_keys("progress\r\naabbccdd 12345678 9abcdef0\r\n").unwrap()[0],
            "aabbccdd"
        );
    }

    #[test]
    fn timeout_reaps_child_process() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("ping");
            command.args(["-n", "20", "127.0.0.1"]);
            command
        };
        #[cfg(not(windows))]
        let mut command = {
            let mut command = Command::new("sleep");
            command.arg("20");
            command
        };
        let started = Instant::now();
        let result = run(
            &mut command,
            &directory.path().join("log.txt"),
            Duration::from_millis(100),
            &AtomicBool::new(false),
            "Test process",
        )
        .unwrap();
        assert!(result.timed_out && !result.success);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn progress_uses_latest_valid_fraction_across_phase_resets() {
        assert_eq!(
            latest_progress("100 % (100 / 100)\r0.5 % (5 / 1000)\x1b[1K"),
            Some((5, 1000))
        );
        assert_eq!(latest_progress("broken % (900 / 10)\rtext"), None);
        assert_eq!(latest_progress("0 % (0 / 0)"), None);
    }
}
