mod archive;
mod bkcrack;
mod cli;
mod dictionary;
mod generator;
mod mask;
mod presentation;
mod wordlists;

mod zipcrypto;

use cli::Args;
use console::{style, Style, Term};
use dialoguer::{theme::ColorfulTheme, Input, Select};
use generator::{generate_attack, GenerationOptions};
use mask::{generate_mask_attack, Mask};
use std::io::IsTerminal;
use std::sync::atomic::AtomicBool;

type AppResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn run_generate_attack(
    zip_path: &str,
    options: &GenerationOptions,
    mask: Option<&Mask>,
) -> AppResult {
    let cancelled = AtomicBool::new(false);
    let result = if let Some(mask) = mask {
        generate_mask_attack(zip_path, mask, options.threads, options.limit, &cancelled)?
    } else {
        generate_attack(zip_path, options, &cancelled)?
    };
    let matched = result.password.is_some();
    if let Some(password) = result.password {
        presentation::success("Password found:", password);
    } else {
        presentation::note("No password found in the searched candidates");
    }
    presentation::statistics(result.checked, result.elapsed);
    if matched {
        presentation::detail("Full entry verification passed.");
    }
    println!();
    Ok(())
}

enum RecoveryMode {
    Dictionary,
    Mask,
    Generate,
    Bkcrack,
}

fn select_recovery(args: &mut Args) -> AppResult<bool> {
    let path = args.zip.as_deref().ok_or("Choose a ZIP archive")?;
    let info = archive::inspect(path)?;
    let encrypted = info.zipcrypto + info.aes + info.other;
    presentation::heading("Archive details", path);
    presentation::detail(format!(
        "Files: {} ({} encrypted) · Directories: {}",
        info.files, encrypted, info.directories
    ));
    if encrypted == 0 {
        presentation::note("No files require a password.");
        return Ok(false);
    }

    let encryption: Vec<_> = [
        ("ZipCrypto", info.zipcrypto),
        ("AES", info.aes),
        ("Other", info.other),
    ]
    .into_iter()
    .filter(|&(_, count)| count > 0)
    .map(|(name, count)| format!("{name}: {count}"))
    .collect();
    presentation::detail(format!("Encryption: {}", encryption.join(", ")));

    let mut choices = Vec::new();
    if info.password_search {
        choices.extend([
            (
                RecoveryMode::Dictionary,
                "Wordlist (-d) · Try passwords from a list",
            ),
            (
                RecoveryMode::Mask,
                "Password pattern (-g --mask) · Use a pattern you remember",
            ),
            (
                RecoveryMode::Generate,
                "Character search (-g) · Try combinations; can take a long time",
            ),
        ]);
    }
    if info.bkcrack {
        choices.push((
            RecoveryMode::Bkcrack,
            "Automatic recovery (--bkcrack) · Try known file content; requires bkcrack",
        ));
    }
    if choices.is_empty() {
        presentation::note("No supported recovery modes for this archive.");
        return Ok(false);
    }

    let labels: Vec<_> = choices.iter().map(|&(_, label)| label).collect();
    let term = Term::stderr();
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() || !term.is_term() {
        presentation::section("Available recovery modes");
        for label in labels {
            presentation::detail(label);
        }
        return Ok(false);
    }

    let theme = ColorfulTheme {
        prompt_style: Style::new().for_stderr().bold(),
        prompt_prefix: style("  ?".to_owned()).for_stderr().color256(183),
        active_item_style: Style::new().for_stderr().cyan().bold(),
        active_item_prefix: style("  ›".to_owned()).for_stderr().color256(183),
        inactive_item_prefix: style("   ".to_owned()).for_stderr(),
        ..ColorfulTheme::default()
    };
    term.write_line(
        &style("\n    ↑ ↓ Move · Enter Select · Esc Exit")
            .for_stderr()
            .dim()
            .to_string(),
    )?;
    let Some(selected) = Select::with_theme(&theme)
        .with_prompt("Choose a recovery mode")
        .items(&labels)
        .default(0)
        .report(false)
        .interact_on_opt(&term)?
    else {
        return Ok(false);
    };
    match choices[selected].0 {
        RecoveryMode::Dictionary => args.dict.push(String::new()),
        RecoveryMode::Mask => {
            let mask: String = Input::new()
                .with_prompt("Pattern (e.g. backup-?d?d; leave blank to exit)")
                .allow_empty(true)
                .validate_with(|pattern: &String| {
                    if pattern.is_empty() {
                        Ok(())
                    } else {
                        Mask::parse(pattern).map(|_| ())
                    }
                })
                .interact_text_on(&term)?;
            if mask.is_empty() {
                return Ok(false);
            }
            args.mask = Some(mask);
            args.generate = true;
        }
        RecoveryMode::Generate => args.generate = true,
        RecoveryMode::Bkcrack => args.bkcrack = true,
    }
    Ok(true)
}

fn execute(mut args: Args) -> AppResult {
    if let Some(cli::Command::Wordlists { action }) = args.command {
        let library = wordlists::Library::new(args.wordlist_dir.as_deref(), args.offline)?;
        library.handle_interrupts()?;
        return library.execute(action);
    }
    if !args.bkcrack && !args.generate && args.dict.is_empty() && !select_recovery(&mut args)? {
        return Ok(());
    }
    let path = args.zip.as_deref().ok_or("Choose a ZIP archive")?;
    if args.bkcrack {
        presentation::heading("Automatic recovery", path);
        let options = bkcrack::Options {
            executable: args.bkcrack_path,
            output: args.decrypt,
            threads: args.threads.unwrap_or_else(num_cpus::get),
            seconds: args.bkcrack_seconds,
            attempt_seconds: args.attempt_seconds,
            dry_run: args.dry_run,
            verbose: args.verbose,
        };
        bkcrack::run(std::path::Path::new(path), &options)
    } else if args.generate {
        let options = GenerationOptions {
            min_length: args.min_length,
            max_length: args.max_length,
            charset: args.charset,
            threads: args.threads.unwrap_or_else(num_cpus::get),
            limit: args.limit,
        };
        let mask = args
            .mask
            .as_deref()
            .map(Mask::parse)
            .transpose()
            .unwrap_or_else(|error| {
                presentation::error(&format!("Invalid mask: {error}"));
                std::process::exit(2);
            });
        let validation = if mask.is_some() {
            if options.threads == 0 || options.limit == Some(0) {
                Err("Threads and limit must be greater than zero".into())
            } else {
                Ok(0)
            }
        } else {
            options.total()
        };
        if let Err(error) = validation {
            presentation::error(&format!("Invalid generation options: {error}"));
            std::process::exit(2);
        }
        presentation::heading(
            if mask.is_some() {
                "Password mask"
            } else {
                "Character search"
            },
            path,
        );
        if let Some(mask) = args.mask {
            presentation::note(&format!("Mask  {mask}"));
        }
        presentation::note(&format!("Workers  {}", options.threads));
        run_generate_attack(path, &options, mask.as_ref())
    } else {
        presentation::heading("Dictionary", path);
        let library = wordlists::Library::new(args.wordlist_dir.as_deref(), args.offline)?;
        let mut sources = args.dict;
        if sources.iter().any(String::is_empty) {
            archive::check_encrypted(path)?;
            for source in sources.iter_mut().filter(|source| source.is_empty()) {
                let Some(selected) = library.select()? else {
                    presentation::note("Wordlist selection cancelled");
                    return Ok(());
                };
                *source = selected;
            }
        }
        library.handle_interrupts()?;
        let options = dictionary::Options {
            threads: args.threads.unwrap_or_else(num_cpus::get),
            limit: args.limit,
            refresh: args.refresh_wordlists,
            rules: args.word_rules,
            keep_duplicates: args.keep_duplicates,
            min_length: args.word_min_length.unwrap_or(0),
            max_length: args.word_max_length.unwrap_or(usize::MAX),
        };
        dictionary::run(path, &sources, &library, &options)
    }
}

fn main() {
    let args = Args::parse_cli();
    presentation::configure(args.color);
    if let Err(error) = execute(args) {
        presentation::error(&error.to_string());
        std::process::exit(1);
    }
}
