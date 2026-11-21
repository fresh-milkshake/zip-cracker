use std::io::{BufRead, BufReader, Cursor, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

fn cli(cache: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zip-cracker"))
        .args(arguments)
        .arg("--wordlist-dir")
        .arg(cache)
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn archive() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/abcde12.bin")
        .display()
        .to_string()
}

struct Reply {
    header: &'static str,
    response: Vec<u8>,
}

fn server(replies: Vec<Reply>) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/words.txt", listener.local_addr().unwrap());
    let task = std::thread::spawn(move || {
        for reply in replies {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("Expected HTTP request: {error}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut request = String::new();
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                request.push_str(&line);
                if line == "\r\n" {
                    break;
                }
            }
            if !reply.header.is_empty() {
                assert!(
                    request.to_ascii_lowercase().contains(reply.header),
                    "{request}"
                );
            }
            socket.write_all(&reply.response).unwrap();
        }
    });
    (url, task)
}

fn response(body: &[u8], etag: &str) -> Vec<u8> {
    let mut result = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nETag: {etag}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    result.extend_from_slice(body);
    result
}

#[test]
fn http_search_starts_before_eof_and_stops_without_saving_the_body() {
    for (first, chunked, limit) in [
        ("abcde12\n", false, false),
        ("abcde12\n", true, false),
        ("wrong\n", false, true),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let cache = directory.path().join("unused-cache");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/huge.txt", listener.local_addr().unwrap());
        let (release, released) = std::sync::mpsc::channel();
        let task = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            if chunked {
                write!(socket, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n{:x}\r\n{first}\r\n", first.len()).unwrap();
            } else {
                // Advertise 1 TiB, but keep the body unfinished until the client exits.
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: 1099511627776\r\nContent-Type: text/plain\r\n\r\n{first}").unwrap();
            }
            socket.flush().unwrap();
            assert!(
                released.recv_timeout(Duration::from_secs(10)).is_ok(),
                "Client waited for the whole remote dictionary"
            );
        });
        let zip = archive();
        let mut arguments = vec![zip.as_str(), "-d", &url];
        if limit {
            arguments.extend(["--limit", "1"]);
        }
        let output = cli(&cache, &arguments);
        release.send(()).unwrap();
        let result = success(output);
        assert!(
            result.contains(if limit {
                "Checked 1 passwords"
            } else {
                "Password found: abcde12"
            }),
            "{result}"
        );
        assert!(!cache.exists(), "HTTP search must not create a disk cache");
        task.join().unwrap();
    }
}

#[test]
fn http_search_decodes_gzip_and_reports_truncated_transfers() {
    let directory = tempfile::tempdir().unwrap();
    let cache = directory.path().join("unused-cache");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder
        .write_all(b"\xef\xbb\xbfwrong\r\nwrong\r\nabcde12\r\n")
        .unwrap();
    let (url, task) = server(vec![Reply {
        header: "get /words.txt",
        response: response(&encoder.finish().unwrap(), "\"gzip\""),
    }]);
    let result = success(cli(&cache, &[&archive(), "-d", &url]));
    assert!(result.contains("Password found: abcde12"));
    assert!(!cache.exists());
    task.join().unwrap();
    let (url, task) = server(vec![Reply {
        header: "get /words.txt",
        response: b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\nConnection: close\r\n\r\nwrong\n"
            .to_vec(),
    }]);
    let output = cli(&cache, &[&archive(), "-d", &url]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("search incomplete"));
    assert!(!cache.exists());
    task.join().unwrap();
}

#[test]
fn download_cache_revalidation_failure_and_integrity_repair() {
    let directory = tempfile::tempdir().unwrap();
    let cache = directory.path();
    let body = b"wrong\nabcde12\n";
    let (url, task) = server(vec![
        Reply {
            header: "get /words.txt",
            response: response(body, "\"first\""),
        },
        Reply {
            header: "if-none-match: \"first\"",
            response: b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_vec(),
        },
        Reply {
            header: "if-none-match: \"first\"",
            response: b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\nConnection: close\r\n\r\nshort"
                .to_vec(),
        },
        Reply {
            header: "get /words.txt",
            response: response(body, "\"repaired\""),
        },
        Reply {
            header: "if-none-match: \"repaired\"",
            response: response(b"changed\nabcde12\n", "\"second\""),
        },
    ]);
    success(cli(cache, &["wordlists", "fetch", &url]));
    let records = std::fs::read_dir(cache)
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
        .unwrap();
    let metadata: serde_json::Value =
        serde_json::from_reader(std::fs::File::open(records.path()).unwrap()).unwrap();
    let id = metadata["id"].as_str().unwrap();
    let object = cache
        .join("objects")
        .join(metadata["sha256"].as_str().unwrap());
    assert_eq!(std::fs::read(&object).unwrap(), body);
    success(cli(cache, &["wordlists", "fetch", &url, "--offline"]));
    success(cli(cache, &["wordlists", "fetch", id, "--refresh"]));
    assert!(!cli(cache, &["wordlists", "fetch", &url, "--refresh"])
        .status
        .success());
    assert_eq!(std::fs::read(&object).unwrap(), body);
    success(cli(cache, &["wordlists", "fetch", &url, "--offline"]));
    std::fs::write(&object, b"WRONG\nabcde12\n").unwrap(); // same length: size alone cannot detect corruption
    assert!(!cli(cache, &["wordlists", "fetch", &url, "--offline"])
        .status
        .success());
    success(cli(cache, &["wordlists", "fetch", &url]));
    assert_eq!(std::fs::read(&object).unwrap(), body);
    success(cli(cache, &["wordlists", "fetch", &url, "--refresh"]));
    assert!(!object.exists());
    let result = success(cli(cache, &[&archive(), "-d", &url, "--offline"]));
    assert!(result.contains("Password found: abcde12"));
    task.join().unwrap();
}

#[test]
fn imported_gzip_is_reusable_and_removal_preserves_original_and_shared_objects() {
    let directory = tempfile::tempdir().unwrap();
    let cache = directory.path().join("library");
    for arguments in [
        vec!["wordlists", "--help"],
        vec!["wordlists", "fetch", "-h"],
        vec!["wordlists", "list", "--version"],
    ] {
        success(cli(&cache, &arguments));
    }
    let file = directory.path().join("words.gz");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder
        .write_all(b"\xef\xbb\xbfwrong\r\nabcde12\r\n")
        .unwrap();
    std::fs::write(&file, encoder.finish().unwrap()).unwrap();
    for id in ["personal", "shared"] {
        success(cli(
            &cache,
            &["wordlists", "import", file.to_str().unwrap(), "--name", id],
        ));
    }
    assert!(success(cli(&cache, &["wordlists", "list", "personal"])).contains("@personal"));
    success(cli(&cache, &["wordlists", "remove", "personal"]));
    assert!(file.exists());
    let result = success(cli(&cache, &[&archive(), "-d", "@shared", "--offline"]));
    assert!(result.contains("Password found: abcde12"));
    assert!(!cli(
        &cache,
        &[
            "wordlists",
            "import",
            file.to_str().unwrap(),
            "--name",
            "../escape"
        ]
    )
    .status
    .success());
    success(cli(&cache, &["wordlists", "remove", "shared"]));
    assert_eq!(std::fs::read_dir(cache.join("objects")).unwrap().count(), 0);
}

#[test]
fn multiple_sources_deduplication_rules_and_limits() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first.txt");
    let second = directory.path().join("second.txt");
    std::fs::write(&first, b"\xef\xbb\xbfwrong\r\nwrong\r\n").unwrap();
    std::fs::write(&second, b"wrong\nother\n").unwrap();
    let args = [
        archive(),
        first.display().to_string(),
        second.display().to_string(),
    ];
    let result = success(cli(
        directory.path(),
        &[&args[0], "-d", &args[1], "-d", &args[2]],
    ));
    assert!(result.contains("Checked 2 passwords"), "{result}");
    let result = success(cli(
        directory.path(),
        &[
            &args[0],
            "-d",
            &args[1],
            "-d",
            &args[2],
            "--keep-duplicates",
            "--limit",
            "3",
            "--threads",
            "2",
        ],
    ));
    assert!(result.contains("Checked 3 passwords"), "{result}");
    std::fs::write(&first, b"ABCDE12\n").unwrap();
    let result = success(cli(
        directory.path(),
        &[
            &args[0],
            "-d",
            &args[1],
            "--word-rules",
            "--word-min-length",
            "7",
            "--word-max-length",
            "7",
        ],
    ));
    assert!(result.contains("Password found: abcde12"));
    // Found/limit must stop before touching a missing or remote subsequent source.
    std::fs::write(&first, b"abcde12\n").unwrap();
    success(cli(
        directory.path(),
        &[
            &args[0],
            "-d",
            &args[1],
            "-d",
            "@does-not-exist",
            "--offline",
        ],
    ));
    std::fs::write(&first, b"wrong\n").unwrap();
    let result = success(cli(
        directory.path(),
        &[
            &args[0],
            "-d",
            &args[1],
            "-d",
            "@does-not-exist",
            "--limit",
            "1",
            "--offline",
        ],
    ));
    assert!(result.contains("Checked 1 passwords"));
}

#[test]
fn omitted_dictionary_source_requires_a_terminal_without_hanging() {
    let directory = tempfile::tempdir().unwrap();
    for sources in [
        vec!["-d"],
        vec!["-d", "--threads", "2"],
        vec!["-d", "@common-1k", "-d"],
    ] {
        let zip = archive();
        let mut arguments = vec![zip.as_str()];
        arguments.extend(sources);
        let output = cli(directory.path(), &arguments);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("requires an interactive terminal")
        );
    }
}

#[test]
fn raw_password_bytes_and_spaces_survive_dictionary_reading() {
    use zip::unstable::write::FileOptionsExt;
    let directory = tempfile::tempdir().unwrap();
    let zip_path = directory.path().join("raw.zip");
    let words = directory.path().join("words.txt");
    let password = b" raw\xff ";
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "payload",
            zip::write::SimpleFileOptions::default().with_deprecated_encryption(password),
        )
        .unwrap();
    writer.write_all(b"payload checked by CRC").unwrap();
    std::fs::write(&zip_path, writer.finish().unwrap().into_inner()).unwrap();
    let mut list = b"\xef\xbb\xbfwrong\r\n".to_vec();
    list.extend_from_slice(password);
    std::fs::write(&words, list).unwrap();
    let result = success(cli(
        directory.path(),
        &[zip_path.to_str().unwrap(), "-d", words.to_str().unwrap()],
    ));
    assert!(
        result.contains("Password found: $HEX[20726177ff20]"),
        "{result}"
    );
}

#[test]
fn dictionary_errors_propagate_and_invalid_options_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let words = directory.path().join("words.txt");
    for contents in [vec![b'a'; 65537], vec![0xff, 0xfe, b'a', 0]] {
        std::fs::write(&words, contents).unwrap();
        assert!(!cli(
            directory.path(),
            &[&archive(), "-d", words.to_str().unwrap()]
        )
        .status
        .success());
    }
    // A later invalid line must not be read after the exact limit is reached.
    let mut contents = b"wrong\n".to_vec();
    contents.extend(vec![b'a'; 65537]);
    std::fs::write(&words, contents).unwrap();
    success(cli(
        directory.path(),
        &[&archive(), "-d", words.to_str().unwrap(), "--limit", "1"],
    ));
    for flags in [
        vec!["--threads", "0"],
        vec!["--limit", "0"],
        vec!["--word-min-length", "9", "--word-max-length", "1"],
    ] {
        let mut args = vec![archive(), "-d".into(), words.display().to_string()];
        args.extend(flags.into_iter().map(str::to_owned));
        assert!(!cli(
            directory.path(),
            &args.iter().map(String::as_str).collect::<Vec<_>>()
        )
        .status
        .success());
    }
}
