use crate::generator::DEFAULT_CHARSET;
use clap::{
    builder::{
        styling::{AnsiColor, RgbColor, Styles},
        StyledStr,
    },
    Arg, ArgAction, ArgGroup, ColorChoice, CommandFactory, FromArgMatches, Parser, ValueEnum,
};

#[derive(Clone, Copy, Default, ValueEnum)]
pub enum ColorMode {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Parser)]
#[command(
    name = "zip-cracker",
    version,
    arg_required_else_help = true,
    override_usage = "zip-cracker <ZIP> (--bkcrack | -g | -d <WORDLIST>) [OPTIONS]",
    help_template = "{before-help}{about}\n\n{usage-heading} {usage}\n\n{all-args}{after-help}",
    term_width = 96
)]
#[command(about = "Recover ZIP files with automatic plaintext attacks, masks or wordlists.")]
#[command(group(ArgGroup::new("parallel_mode").args(["generate", "bkcrack"]).multiple(false)))]
#[command(group(ArgGroup::new("mode").args(["generate", "bkcrack", "dict"]).required(true).multiple(false)))]
pub struct Args {
    #[arg(help = "Encrypted ZIP archive")]
    pub zip: String,

    #[arg(
        short,
        long,
        value_name = "WORDLIST",
        help_heading = "Recovery modes — choose one",
        help = "Try a wordlist, one password per line"
    )]
    pub dict: Option<String>,

    #[arg(
        short,
        long,
        help_heading = "Recovery modes — choose one",
        help = "Search candidates with a mask or character range"
    )]
    pub generate: bool,

    #[arg(
        long,
        help_heading = "Recovery modes — choose one",
        help = "Recover ZipCrypto keys from inferred file content",
        long_help = "Recover ZipCrypto keys from inferred file content.\nChecks open copies and format templates for uncompressed ZIP entries.\nRequires bkcrack. Templates may not match every file.",
        conflicts_with = "dict"
    )]
    pub bkcrack: bool,

    #[arg(
        long,
        value_name = "FILE",
        help_heading = "Automatic recovery — --bkcrack",
        requires = "bkcrack",
        help = "Backend executable; default: app dir or PATH"
    )]
    pub bkcrack_path: Option<std::path::PathBuf>,

    #[arg(
        long,
        value_name = "ZIP",
        help_heading = "Automatic recovery — --bkcrack",
        requires = "bkcrack",
        help = "Verified ZIP; default NAME.unlocked.zip",
        long_help = "Write a verified ZIP (default NAME.unlocked.zip beside the input).\nExisting output files are never overwritten."
    )]
    pub decrypt: Option<std::path::PathBuf>,

    #[arg(
        long,
        help_heading = "Automatic recovery — --bkcrack",
        requires = "bkcrack",
        help = "Preview assumptions without running an attack"
    )]
    pub dry_run: bool,

    #[arg(
        long,
        value_name = "SECONDS",
        help_heading = "Automatic recovery — --bkcrack",
        default_value_t = 180,
        requires = "bkcrack",
        help = "Total recovery budget"
    )]
    pub bkcrack_seconds: u64,

    #[arg(
        long,
        value_name = "SECONDS",
        help_heading = "Automatic recovery — --bkcrack",
        default_value_t = 60,
        requires = "bkcrack",
        help = "Time budget per format variant",
        long_help = "Time budget per format variant. Structural headers and verified copies\nuse the total --bkcrack-seconds budget instead."
    )]
    pub attempt_seconds: u64,

    #[arg(long, value_name = "PATTERN", help_heading = "Candidate search — -g", help = "Search a password pattern; see mask tokens below", long_help = "Search a password pattern; see mask tokens below.\nUse a mask only when you know the password's structure.\nCannot be combined with --min-length, --max-length or --charset.", requires = "generate", conflicts_with_all = ["min_length", "max_length", "charset"])]
    pub mask: Option<String>,

    #[arg(
        long,
        value_name = "N",
        help_heading = "Candidate search — -g",
        help = "Shortest candidate length",
        default_value_t = 1,
        requires = "generate"
    )]
    pub min_length: u32,

    #[arg(
        long,
        value_name = "N",
        help_heading = "Candidate search — -g",
        help = "Longest candidate length, up to 16",
        default_value_t = 8,
        requires = "generate"
    )]
    pub max_length: u32,

    #[arg(long, value_name = "CHARS", help_heading = "Candidate search — -g", hide_default_value = true, help = "Unique ASCII characters; default: a-z, A-Z, 0-9", default_value = DEFAULT_CHARSET, requires = "generate")]
    pub charset: String,

    #[arg(
        long,
        value_name = "N",
        help_heading = "Workers",
        help = "Worker count (default: available logical CPUs)",
        requires = "parallel_mode"
    )]
    pub threads: Option<usize>,

    #[arg(
        long,
        value_name = "COUNT",
        help_heading = "Candidate search — -g",
        help = "Stop after this many generated candidates",
        requires = "generate"
    )]
    pub limit: Option<u64>,

    #[arg(long, value_enum, value_name = "WHEN", hide_possible_values = true, default_value_t = ColorMode::Auto, help_heading = "Display", help = "auto, always, never; auto honors NO_COLOR")]
    pub color: ColorMode,

    #[arg(
        short,
        long,
        help_heading = "Display",
        help = "Show extra execution details"
    )]
    pub verbose: bool,
}

impl Args {
    pub fn parse_cli() -> Self {
        let arguments: Vec<_> = std::env::args_os().collect();
        let mut color = ColorMode::Auto;
        let mut scan = arguments.iter().skip(1);
        while let Some(argument) = scan.next() {
            if argument == "--" {
                break;
            }
            let text = argument.to_string_lossy();
            let value = if text == "--color" {
                scan.next().and_then(|value| value.to_str())
            } else {
                text.strip_prefix("--color=")
            };
            if let Some(value) = value {
                if let Ok(mode) = ColorMode::from_str(value, false) {
                    color = mode;
                }
            }
        }
        let choice = match color {
            ColorMode::Always => ColorChoice::Always,
            ColorMode::Never => ColorChoice::Never,
            ColorMode::Auto if std::env::var_os("NO_COLOR").is_some() => ColorChoice::Never,
            ColorMode::Auto => ColorChoice::Auto,
        };
        let accent = RgbColor(191, 166, 255).on_default().bold();
        let cyan = AnsiColor::Cyan.on_default();
        let dim = AnsiColor::BrightBlack.on_default();
        let examples = StyledStr::from(format!(
            "{accent}Examples{accent:#}\n\
             {dim}  Preview automatic plaintext assumptions{dim:#}\n\
             {cyan}  zip-cracker archive.zip --bkcrack --dry-run{cyan:#}\n\n\
             {dim}  Search a known password pattern{dim:#}\n\
             {cyan}  zip-cracker archive.zip -g --mask '?l?l?l?d?d'{cyan:#}\n\n\
             {dim}  Try a wordlist{dim:#}\n\
             {cyan}  zip-cracker archive.zip -d words.txt{cyan:#}\n\n\
             {accent}Mask tokens{accent:#}\n\
             {cyan}  ?l{cyan:#} lowercase   {cyan}?u{cyan:#} uppercase   {cyan}?d{cyan:#} digits\n\
             {cyan}  ?s{cyan:#} symbols     {cyan}?a{cyan:#} printable ASCII   {cyan}??{cyan:#} literal ?\n\n\
             {dim}Quote masks in your shell. Large unknown-password searches can take years.{dim:#}\n"
        ));
        let mut command = Self::command()
            .color(choice)
            .before_help(StyledStr::from(format!(
                "{accent}ZIP CRACKER{accent:#}  {dim}{}{dim:#}",
                env!("CARGO_PKG_VERSION")
            )))
            .after_help(examples)
            .styles(
                Styles::styled()
                    .header(accent)
                    .usage(accent)
                    .literal(cyan.bold())
                    .placeholder(dim)
                    .context(dim)
                    .context_value(dim)
                    .error(AnsiColor::Red.on_default().bold())
                    .invalid(AnsiColor::Red.on_default())
                    .valid(AnsiColor::Green.on_default()),
            );
        command = command
            .disable_help_flag(true)
            .disable_version_flag(true)
            .arg(
                Arg::new("help")
                    .short('h')
                    .long("help")
                    .action(ArgAction::Help)
                    .help_heading("Display")
                    .help("Print help"),
            )
            .arg(
                Arg::new("version")
                    .short('V')
                    .long("version")
                    .action(ArgAction::Version)
                    .help_heading("Display")
                    .help("Print version"),
            );
        let matches = command
            .try_get_matches_from_mut(arguments)
            .unwrap_or_else(|error| error.exit());
        Self::from_arg_matches(&matches).unwrap_or_else(|error| error.format(&mut command).exit())
    }
}
