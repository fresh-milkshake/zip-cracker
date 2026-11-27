use std::process::Command;

fn run(options: &[&str]) -> std::process::Output {
    run_archive("abcde12.bin", options)
}

fn run_archive(name: &str, options: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_zip-cracker"))
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .args(options)
        .output()
        .unwrap()
}

#[test]
fn bare_archive_reports_encryption_and_compatible_modes_without_a_terminal() {
    for (fixture, encryption, automatic_recovery) in [
        ("abcde12.bin", "ZipCrypto", true),
        ("deflated.bin", "ZipCrypto", false),
        ("aes.bin", "AES", false),
    ] {
        let output = run_archive(fixture, &[]);
        assert!(output.status.success(), "{fixture}: {:?}", output.stderr);
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("Files: 1 (1 encrypted)"), "{stdout}");
        assert!(stdout.contains(&format!("Encryption: {encryption}: 1")));
        assert!(stdout.contains("Wordlist (-d)"));
        assert!(stdout.contains("Password pattern (-g --mask)"));
        assert_eq!(stdout.contains("(--bkcrack)"), automatic_recovery);
        assert!(!stdout.contains("Checked"));
    }
}

#[test]
fn bare_archive_reports_unencrypted_files_without_offering_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("open.zip");
    let mut archive = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
    let options = zip::write::SimpleFileOptions::default();
    archive.add_directory("empty", options).unwrap();
    archive.start_file("document.txt", options).unwrap();
    archive.finish().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_zip-cracker"))
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Files: 1 (0 encrypted) · Directories: 1"));
    assert!(stdout.contains("No files require a password."));
    assert!(!stdout.contains("Available recovery modes"));
}

#[test]
fn password_search_skips_an_unencrypted_directory_at_the_start() {
    let directory = tempfile::tempdir().unwrap();
    let dictionary = directory.path().join("words.txt");
    std::fs::write(&dictionary, "aa\nab\n").unwrap();
    let archive = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/zips/unencrypted-directory-first.zip"
    );
    let inspection = Command::new(env!("CARGO_BIN_EXE_zip-cracker"))
        .arg(archive)
        .output()
        .unwrap();
    assert!(inspection.status.success());
    assert!(String::from_utf8(inspection.stdout)
        .unwrap()
        .contains("Files: 1 (1 encrypted) · Directories: 1"));

    for options in [
        vec!["-g", "--mask", "a?l"],
        vec![
            "-g",
            "--min-length",
            "2",
            "--max-length",
            "2",
            "--charset",
            "ab",
        ],
        vec!["-d", dictionary.to_str().unwrap(), "--offline"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_zip-cracker"))
            .arg(archive)
            .args(&options)
            .args(["--threads", "1", "--wordlist-dir"])
            .arg(directory.path().join("wordlists"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{options:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("Password found: ab"),
            "{options:?}: {stdout}"
        );
    }
}

#[test]
fn mask_recovers_passwords_with_zipcrypto_and_aes() {
    for (fixture, mask, expected) in [
        ("abcde12.bin", "abcde?d?d", "abcde12"),
        ("aes.bin", "abcde1?d", "abcde12"),
        ("nine.bin", "aaaaaaaa?l", "aaaaaaaaa"),
    ] {
        let output = run_archive(fixture, &["-g", "--mask", mask]);
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains(&format!("Password found: {expected}")));
    }
}

#[test]
fn normal_generator_supports_nine_character_passwords() {
    let output = run_archive(
        "nine.bin",
        &[
            "-g",
            "--min-length",
            "9",
            "--max-length",
            "9",
            "--charset",
            "ab",
        ],
    );
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("Password found: aaaaaaaaa"));
}

#[test]
fn mask_limits_cover_partial_batches_and_multiple_blocks() {
    for limit in ["1", "2", "3", "5", "16385"] {
        let output = run(&[
            "-g",
            "--mask",
            "?l?l?l?l",
            "--limit",
            limit,
            "--threads",
            "4",
        ]);
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("No password found"));
        assert!(text.contains(&format!("Checked {limit} passwords")));
    }
}

#[test]
fn mask_rejects_conflicting_or_invalid_arguments() {
    for arguments in [
        vec!["-g", "--mask", "?x"],
        vec!["-g", "--mask", "?l", "--charset", "abc"],
        vec!["-g", "--mask", "?l", "--max-length", "9"],
        vec!["-g", "--mask", "?l", "--threads", "0"],
        vec!["-g", "--mask", "?l", "--limit", "0"],
    ] {
        assert_eq!(run(&arguments).status.code(), Some(2));
    }
}

#[test]
fn limit_spans_lengths_and_stops_at_exact_checked_count() {
    let output = run(&["-g", "--limit", "10001", "--threads", "4"]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("No password found"));
    assert!(text.contains("Checked 10001 passwords"));
}

#[test]
fn finds_real_password_using_configured_search_space() {
    let output = run(&[
        "-g",
        "--min-length",
        "7",
        "--max-length",
        "7",
        "--charset",
        "abcde12",
        "--threads",
        "4",
    ]);
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("Password found: abcde12"));
}

#[test]
fn rejects_invalid_generation_options() {
    let no_arguments = Command::new(env!("CARGO_BIN_EXE_zip-cracker"))
        .output()
        .unwrap();
    assert_eq!(no_arguments.status.code(), Some(2));
    assert_eq!(run(&["--mask", "?d"]).status.code(), Some(2));
    for arguments in [
        vec!["-g", "--threads", "0"],
        vec!["-g", "--limit", "0"],
        vec!["-g", "--min-length", "8", "--max-length", "2"],
        vec!["-g", "--charset", "aa"],
    ] {
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("Invalid generation options"));
    }
}

#[test]
fn bkcrack_dry_run_builds_png_assumptions_without_open_text_or_backend() {
    let output = run_archive(
        "auto-png.bin",
        &["--bkcrack", "--dry-run", "--threads", "2"],
    );
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("PNG signature and IHDR"));
    assert!(text.contains("format assumption, not yet verified"));
    assert!(!text.contains("Matching local copy"));
}

#[test]
fn bkcrack_explains_unsupported_encryption_and_compression() {
    for (name, reason) in [
        ("aes.bin", "not ZipCrypto"),
        ("deflated.bin", "compressed entry"),
    ] {
        let output = run_archive(name, &["--bkcrack", "--dry-run"]);
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stdout).unwrap().contains(reason));
    }
}

#[test]
fn bkcrack_explains_missing_known_content_and_suggests_other_modes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("archive.zip");
    std::fs::write(
        &path,
        include_bytes!("zips/unencrypted-directory-first.zip"),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_zip-cracker"))
        .arg(path)
        .arg("--bkcrack")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("No matching unencrypted copy or recognized file header"));
    assert!(stdout.contains("protected/note.txt"));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("No passwords were tried"));
    assert!(stderr.contains("Try a wordlist (-d) or a password pattern (-g --mask)"));
}

#[test]
fn bkcrack_does_not_overwrite_existing_destination() {
    let directory = tempfile::tempdir().unwrap();
    let output_path = directory.path().join("already-exists.zip");
    std::fs::write(&output_path, b"existing output").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_zip-cracker"))
        .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/auto-png.bin"))
        .arg("--bkcrack")
        .arg("--bkcrack-path")
        .arg(env!("CARGO_BIN_EXE_zip-cracker"))
        .arg("--decrypt")
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("Output already exists"));
    assert_eq!(std::fs::read(output_path).unwrap(), b"existing output");
}

#[test]
fn bkcrack_rejects_incompatible_modes_and_zero_budgets() {
    let output = run(&["--bkcrack", "-g"]);
    assert_eq!(output.status.code(), Some(2));
    for option in ["--bkcrack-seconds", "--attempt-seconds", "--threads"] {
        let output = run_archive("auto-png.bin", &["--bkcrack", "--dry-run", option, "0"]);
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("greater than zero"));
    }
}

#[test]
fn colors_can_be_forced_or_disabled_for_redirected_output() {
    for (color, expected) in [("always", true), ("never", false)] {
        let output = run(&["-g", "--limit", "1", "--color", color]);
        assert!(output.status.success());
        assert_eq!(output.stdout.contains(&0x1b), expected);
        if !expected {
            assert!(!output.stderr.contains(&0x1b));
        }
    }
}

#[test]
fn auto_color_respects_no_color() {
    let output = Command::new(env!("CARGO_BIN_EXE_zip-cracker"))
        .args([
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/abcde12.bin"),
            "-g",
            "--limit",
            "1",
        ])
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!output.stdout.contains(&0x1b));
    assert!(!output.stderr.contains(&0x1b));
}

#[test]
fn dictionary_counts_checked_passwords_and_reports_a_match_only_once() {
    let directory = tempfile::tempdir().unwrap();
    let words = directory.path().join("words.txt");
    std::fs::write(&words, "wrong-one\nwrong-two\nwrong-three\n").unwrap();
    let output = run(&["-d", words.to_str().unwrap()]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Checked 3 passwords"));
    assert!(text.contains("No password found in the wordlist"));
    std::fs::write(&words, "abcde12\n".repeat(1000)).unwrap();
    let output = run(&["-d", words.to_str().unwrap()]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)
            .unwrap()
            .matches("Password found: abcde12")
            .count(),
        1
    );
}

#[test]
fn help_color_flags_work_before_and_after_help_even_with_no_color() {
    for arguments in [["-h", "--color", "always"], ["--color", "always", "--help"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_zip-cracker"))
            .args(arguments)
            .env("NO_COLOR", "1")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stdout.contains(&0x1b));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_zip-cracker"))
        .args(["--help", "--color=never"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!output.stdout.contains(&0x1b));
    let output = Command::new(env!("CARGO_BIN_EXE_zip-cracker"))
        .arg("-h")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(!output.stdout.contains(&0x1b));
}
