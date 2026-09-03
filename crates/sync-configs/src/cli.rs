use std::ffi::OsString;
use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum SyncMode {
    Symlink,
    Copy,
    #[value(name = "json_overlay")]
    JsonOverlay,
    #[value(name = "toml_overlay")]
    TomlOverlay,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum ManagedPathPolicy {
    #[default]
    Safe,
    Strict,
    Takeover,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum LogStyle {
    Off,
    #[default]
    Events,
    Transcript,
    Both,
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, ValueEnum)]
pub enum LogLevel {
    Debug,
    #[default]
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Elvish,
    Powershell,
}

impl From<CompletionShell> for clap_complete::Shell {
    fn from(value: CompletionShell) -> Self {
        match value {
            CompletionShell::Bash => Self::Bash,
            CompletionShell::Zsh => Self::Zsh,
            CompletionShell::Fish => Self::Fish,
            CompletionShell::Elvish => Self::Elvish,
            CompletionShell::Powershell => Self::PowerShell,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "sync-configs",
    version,
    about = "Manifest-driven, config-only filesystem and structured-overlay convergence"
)]
pub struct Cli {
    /// Path to the YAML manifest. Relative paths resolve from the caller's working directory.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Override the default mode for entries that do not explicitly set one.
    #[arg(long, value_enum)]
    pub mode: Option<SyncMode>,

    /// Do not prefer sibling source override files.
    #[arg(long)]
    pub no_source_overrides: bool,

    /// Activate a profile; repeat or separate values with commas.
    #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append)]
    pub profile: Vec<String>,

    /// Select profiles for a named host from --profile-map.
    #[arg(long, requires = "profile_map")]
    pub host_profile: Option<String>,

    /// External YAML profile map owned by the caller.
    #[arg(long)]
    pub profile_map: Option<PathBuf>,

    /// Nested list field inside the selected profile-map object.
    #[arg(long, requires = "profile_map")]
    pub profile_map_field: Option<String>,

    /// List profile names from the configured entries and exit.
    #[arg(long)]
    pub list_profiles: bool,

    /// Print example root and entry-file templates, then exit.
    #[arg(long)]
    pub print_example: bool,

    /// Initialize a root manifest, entries directory, and sample entry.
    #[arg(long, conflicts_with = "dry_run")]
    pub init: bool,

    /// Permit --init to overwrite existing scaffold files.
    #[arg(long, requires = "init")]
    pub force_init: bool,

    /// Plan and report without desired-state writes or hooks.
    #[arg(long)]
    pub dry_run: bool,

    /// Validate the selected manifest and profile map without writes or hooks.
    #[arg(long)]
    pub validate: bool,

    /// Output format; JSON never includes configuration values.
    #[arg(long, value_enum, default_value_t)]
    pub format: OutputFormat,

    /// Existing-target authority policy.
    #[arg(long, value_enum, default_value_t)]
    pub managed_path_policy: ManagedPathPolicy,

    /// Include up-to-date entries in the final report.
    #[arg(short, long)]
    pub verbose: bool,

    /// Disable colored human output.
    #[arg(long)]
    pub no_color: bool,

    /// Diagnostic artifact style.
    #[arg(long, value_enum, default_value_t)]
    pub log_style: LogStyle,

    /// Minimum structured event severity.
    #[arg(long, value_enum, default_value_t)]
    pub log_level: LogLevel,

    /// Absolute diagnostic run root.
    #[arg(long)]
    pub log_root: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Inspect and prune bounded diagnostic runs.
    Logs(LogsArgs),
    /// Emit this command's native completion to stdout.
    Completion {
        #[arg(value_enum)]
        shell: CompletionShell,
    },
}

#[derive(Debug, clap::Args)]
pub struct LogsArgs {
    /// Override the platform diagnostic root.
    #[arg(long, global = true)]
    pub log_root: Option<PathBuf>,
    #[command(subcommand)]
    pub command: LogCommand,
}

#[derive(Debug, Subcommand)]
pub enum LogCommand {
    /// List retained diagnostic runs.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show one run's metadata record.
    Show { run_id: String },
    /// Apply bounded retention.
    Prune {
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value_t = 30)]
        max_age_days: u64,
        #[arg(long, default_value_t = 100)]
        max_runs: usize,
        #[arg(long, default_value_t = 134_217_728)]
        max_bytes: u64,
    },
}

pub fn main_entry(argv0: OsString, args: Vec<OsString>) -> i32 {
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(argv0);
    argv.extend(args);
    match Cli::try_parse_from(argv) {
        Ok(Cli {
            command: Some(Commands::Completion { shell }),
            ..
        }) => {
            let mut command = command();
            clap_complete::generate(
                clap_complete::Shell::from(shell),
                &mut command,
                "sync-configs",
                &mut std::io::stdout(),
            );
            0
        }
        Ok(_) => 0,
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            code
        }
    }
}

pub fn command() -> clap::Command {
    Cli::command()
}
