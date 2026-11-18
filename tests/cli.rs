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
    ]);
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("Password found: abcde12"));
}

#[test]
fn rejects_invalid_generation_options() {
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
