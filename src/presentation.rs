use crate::cli::ColorMode;
use console::{style, Style};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::io::IsTerminal;

pub fn configure(mode: ColorMode) {
    let enabled = |terminal| match mode {
        ColorMode::Auto => terminal && std::env::var_os("NO_COLOR").is_none(),
        ColorMode::Always => true,
        ColorMode::Never => false,
    };
    console::set_colors_enabled(enabled(std::io::stdout().is_terminal()));
    console::set_colors_enabled_stderr(enabled(std::io::stderr().is_terminal()));
}

pub fn heading(title: &str, path: &str) {
    println!(
        "\n  {}  {}",
        Style::new().color256(183).bold().apply_to("ZIP CRACKER"),
        style(title).bold()
    );
    detail(path);
    println!();
}

pub fn section(message: impl std::fmt::Display) {
    println!("  {}", style(message).cyan().bold());
}
pub fn detail(message: impl std::fmt::Display) {
    println!("    {}", style(message).dim());
}
pub fn note(message: &str) {
    println!("  {} {}", style("·").dim(), style(message).dim());
}

pub fn statistics(checked: u64, elapsed: std::time::Duration) {
    let seconds = elapsed.as_secs_f64();
    println!(
        "  {} {} {} {:.3}s {} {}",
        style("Checked").dim(),
        style(checked).bold(),
        style("passwords in").dim(),
        seconds,
        style("·").dim(),
        style(format!(
            "{:.0} passwords/s",
            checked as f64 / seconds.max(f64::EPSILON)
        ))
        .cyan()
    );
}
pub fn warning(message: impl std::fmt::Display) {
    println!("  {} {message}", style("!").yellow().bold());
}
pub fn success(label: &str, value: impl std::fmt::Display) {
    println!(
        "\n  {} {} {}",
        style("✓").green(),
        style(label).bold(),
        Style::new().color256(158).bold().apply_to(value)
    );
}
pub fn error(message: &str) {
    eprintln!("\n  {} {message}\n", style("Error").red().bold());
}

pub fn progress(total: u64, label: &'static str) -> ProgressBar {
    let progress =
        ProgressBar::with_draw_target(Some(total), ProgressDrawTarget::stderr_with_hz(5));
    progress.set_style(progress_style());
    progress.set_message(label);
    progress
}

pub fn progress_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "  {spinner:.magenta} {msg:<14} [{bar:22.magenta/black}] {percent:>3}%\n    {counts} checked · {rate:.cyan} · ETA {eta}",
    ).expect("Static progress template")
        .with_key("counts", |state: &indicatif::ProgressState, writer: &mut dyn std::fmt::Write| {
            let _ = write!(writer, "{}/{}", compact(state.pos() as f64), compact(state.len().unwrap_or(0) as f64));
        })
        .with_key("rate", |state: &indicatif::ProgressState, writer: &mut dyn std::fmt::Write| {
            let _ = write!(writer, "{}/s", compact(state.per_sec()));
        })
        .progress_chars("━╸─")
}

fn compact(value: f64) -> String {
    for (scale, suffix) in [
        (1e18, "E"),
        (1e15, "P"),
        (1e12, "T"),
        (1e9, "B"),
        (1e6, "M"),
        (1e3, "K"),
    ] {
        if value >= scale {
            return format!("{:.1}{suffix}", value / scale);
        }
    }
    format!("{value:.0}")
}

pub struct Activity(pub ProgressBar);
impl Drop for Activity {
    fn drop(&mut self) {
        self.0.finish_and_clear();
    }
}

pub fn activity(label: &'static str) -> Activity {
    let progress = ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr_with_hz(5));
    progress.set_style(
        ProgressStyle::with_template("  {spinner:.magenta} {msg} · {elapsed_precise}")
            .expect("Static spinner template"),
    );
    progress.set_message(label);
    Activity(progress)
}
