use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};

pub use crate::run_logs::{LogLevel, LogStyle};

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
    #[arg(long, requires = "host_profile")]
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
    #[arg(long, value_enum, default_value_t = LogStyle::Events)]
    pub log_style: LogStyle,

    /// Minimum structured event severity.
    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    /// Absolute diagnostic run root.
    #[arg(long, global = true)]
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
        Ok(Cli {
            command: Some(Commands::Logs(arguments)),
            log_root,
            ..
        }) => run_logs_command(arguments, log_root),
        Ok(cli) => run_main(cli),
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            code
        }
    }
}

fn run_main(cli: Cli) -> i32 {
    let log_root = match crate::run_logs::resolve_log_root(cli.log_root.as_deref()) {
        Ok(root) => root,
        Err(error) => {
            eprintln!("sync-configs: {error}");
            return 2;
        }
    };
    let mut recorder =
        crate::run_logs::RunRecorder::start_safely(crate::run_logs::RecorderOptions::process(
            log_root,
            cli.log_style,
            cli.log_level,
            cli.dry_run,
        ));
    let result = crate::engine::execute(&cli);
    let mut exit_code = 1;
    match result {
        Ok(output) => {
            exit_code = output
                .report()
                .map(crate::report::Report::exit_code)
                .unwrap_or(0);
            if let Some(report) = output.report() {
                for record in &report.records {
                    recorder.record_entry_status(
                        &record.scope,
                        &record.name,
                        record.status.key(),
                        None,
                    );
                }
                recorder.record_summary(
                    report
                        .counts()
                        .into_iter()
                        .map(|(key, value)| (key.to_owned(), value))
                        .collect::<BTreeMap<_, _>>(),
                    report.records.len() as u64,
                );
            }
            let rendered = render_output(&cli, &output);
            if let Err(error) = write_main_output(&mut recorder, rendered.as_bytes(), false) {
                eprintln!("sync-configs: cannot write command output: {error}");
                exit_code = 1;
            }
        }
        Err(error) => {
            if cli.format == OutputFormat::Json {
                let failure = serde_json::json!({
                    "schema_version": crate::report::REPORT_SCHEMA_VERSION,
                    "outcome": "failed",
                    "exit_code": 1,
                    "dry_run": cli.dry_run,
                    "profiles": normalized_explicit_profiles(&cli.profile),
                    "error_kind": "convergence_failed",
                });
                let mut rendered = serde_json::to_vec(&failure).unwrap_or_else(|_| {
                    b"{\"schema_version\":1,\"outcome\":\"failed\",\"exit_code\":1}\n".to_vec()
                });
                if !rendered.ends_with(b"\n") {
                    rendered.push(b'\n');
                }
                let _ = write_main_output(&mut recorder, &rendered, false);
            } else {
                let rendered = format!("error: {error}\n");
                let _ = write_main_output(&mut recorder, rendered.as_bytes(), true);
            }
        }
    }
    recorder.finish(exit_code, false);
    exit_code
}

fn render_output(cli: &Cli, output: &crate::engine::RunOutput) -> String {
    if cli.format == OutputFormat::Json {
        let value = match output {
            crate::engine::RunOutput::Convergence(report)
            | crate::engine::RunOutput::Validation(report) => {
                serde_json::to_value(report.json()).expect("report serialization is infallible")
            }
            crate::engine::RunOutput::Profiles(profiles) => serde_json::json!({
                "schema_version": crate::report::REPORT_SCHEMA_VERSION,
                "outcome": "completed",
                "exit_code": 0,
                "dry_run": cli.dry_run,
                "profiles": normalized_explicit_profiles(&cli.profile),
                "available_profiles": profiles,
            }),
            crate::engine::RunOutput::Examples(_) => serde_json::json!({
                "schema_version": crate::report::REPORT_SCHEMA_VERSION,
                "outcome": "completed",
                "exit_code": 0,
                "dry_run": false,
                "profiles": [],
                "action": "print_example",
            }),
            crate::engine::RunOutput::Initialized(_) => serde_json::json!({
                "schema_version": crate::report::REPORT_SCHEMA_VERSION,
                "outcome": "completed",
                "exit_code": 0,
                "dry_run": false,
                "profiles": normalized_explicit_profiles(&cli.profile),
                "action": "initialized",
            }),
        };
        let mut rendered = serde_json::to_string(&value).expect("JSON value serialization");
        rendered.push('\n');
        return rendered;
    }

    match output {
        crate::engine::RunOutput::Convergence(report) => report.render_human(cli.verbose),
        crate::engine::RunOutput::Validation(_) => "valid\n".to_owned(),
        crate::engine::RunOutput::Profiles(profiles) => {
            let mut rendered = profiles.join("\n");
            if !rendered.is_empty() {
                rendered.push('\n');
            }
            rendered
        }
        crate::engine::RunOutput::Examples(examples) => examples.clone(),
        crate::engine::RunOutput::Initialized(paths) => format!(
            "[do] wrote {}\n[do] wrote {}\n[info] next: sync-configs --config {}\n",
            paths.manifest.display(),
            paths.example.display(),
            paths.manifest.display(),
        ),
    }
}

fn write_main_output(
    recorder: &mut crate::run_logs::RunRecorder,
    value: &[u8],
    stderr: bool,
) -> std::io::Result<()> {
    if stderr {
        let stream = std::io::stderr();
        let mut stream = stream.lock();
        recorder.write_console(&mut stream, value)
    } else {
        let stream = std::io::stdout();
        let mut stream = stream.lock();
        recorder.write_console(&mut stream, value)
    }
}

fn normalized_explicit_profiles(profiles: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    for profile in profiles {
        let profile = profile.trim();
        if !profile.is_empty() && !result.iter().any(|existing| existing == profile) {
            result.push(profile.to_owned());
        }
    }
    result
}

fn run_logs_command(arguments: LogsArgs, log_root: Option<PathBuf>) -> i32 {
    let root = match crate::run_logs::resolve_log_root(log_root.as_deref()) {
        Ok(root) => root,
        Err(error) => {
            eprintln!("sync-configs: {error}");
            return 1;
        }
    };
    let result = match arguments.command {
        LogCommand::List { json } => crate::run_logs::list_runs(&root).and_then(|runs| {
            if json {
                write_json(&runs)
            } else {
                let mut stdout = std::io::stdout().lock();
                for run in runs {
                    writeln!(
                        stdout,
                        "{}\t{}\t{}",
                        run.run_id,
                        run_status_name(run.status),
                        run.started_at
                    )
                    .map_err(output_error)?;
                }
                Ok(())
            }
        }),
        LogCommand::Show { run_id } => {
            crate::run_logs::show_run(&root, &run_id).and_then(|metadata| write_json(&metadata))
        }
        LogCommand::Prune {
            dry_run,
            max_age_days,
            max_runs,
            max_bytes,
        } => crate::run_logs::prune_runs(
            &root,
            crate::run_logs::RetentionPolicy {
                max_age_days,
                max_runs,
                max_bytes,
            },
            dry_run,
        )
        .and_then(|report| write_json(&report)),
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("sync-configs: {error}");
            1
        }
    }
}

fn write_json<T: serde::Serialize>(value: &T) -> Result<(), crate::run_logs::LogError> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, value)
        .map_err(|error| output_error(std::io::Error::other(error)))?;
    stdout.write_all(b"\n").map_err(output_error)
}

fn output_error(error: std::io::Error) -> crate::run_logs::LogError {
    crate::run_logs::LogError::from_io("cannot write command output", error)
}

fn run_status_name(status: crate::run_logs::RunStatus) -> &'static str {
    match status {
        crate::run_logs::RunStatus::Running => "running",
        crate::run_logs::RunStatus::Completed => "completed",
        crate::run_logs::RunStatus::Failed => "failed",
        crate::run_logs::RunStatus::Interrupted => "interrupted",
    }
}

pub fn command() -> clap::Command {
    Cli::command()
}
