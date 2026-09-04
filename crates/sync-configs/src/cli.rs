use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};

use crate::paths::{normalize_user_path, PathContext};
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum StandaloneOutputFormat {
    #[default]
    Human,
    Json,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum StandaloneManagedPathPolicy {
    #[default]
    Safe,
    Strict,
    Takeover,
}

impl From<StandaloneManagedPathPolicy> for crate::standalone::ManagedPathPolicy {
    fn from(value: StandaloneManagedPathPolicy) -> Self {
        match value {
            StandaloneManagedPathPolicy::Safe => Self::Safe,
            StandaloneManagedPathPolicy::Strict => Self::Strict,
            StandaloneManagedPathPolicy::Takeover => Self::Takeover,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum StandaloneTomlConflictPolicy {
    #[default]
    Source,
    Target,
}

impl From<StandaloneTomlConflictPolicy> for crate::overlay::toml::TomlConflictPolicy {
    fn from(value: StandaloneTomlConflictPolicy) -> Self {
        match value {
            StandaloneTomlConflictPolicy::Source => Self::Source,
            StandaloneTomlConflictPolicy::Target => Self::Target,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum StandaloneCommentedTargetPolicy {
    #[default]
    Respect,
    Activate,
    Error,
}

impl From<StandaloneCommentedTargetPolicy> for crate::overlay::toml::CommentedTargetPolicy {
    fn from(value: StandaloneCommentedTargetPolicy) -> Self {
        match value {
            StandaloneCommentedTargetPolicy::Respect => Self::Respect,
            StandaloneCommentedTargetPolicy::Activate => Self::Activate,
            StandaloneCommentedTargetPolicy::Error => Self::Error,
        }
    }
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
    /// Apply a source-wins JSON overlay without a manifest.
    JsonOverlay(JsonOverlayArgs),
    /// Apply or remove source-owned TOML keys without a manifest.
    TomlOverlay(TomlOverlayArgs),
    /// Classify an existing target against a managed source.
    ManagedPathPolicy(ManagedPathPolicyArgs),
}

#[derive(Debug, clap::Args)]
pub struct JsonOverlayArgs {
    /// Baseline JSON object to overlay from.
    pub source: PathBuf,
    /// Target JSON object to update.
    pub target: PathBuf,
    /// RFC 6901 pointer to replace exactly; repeat for multiple subtrees.
    #[arg(long = "replace-json-pointer", action = clap::ArgAction::Append)]
    pub replace_json_pointers: Vec<String>,
    /// Report without writing.
    #[arg(long)]
    pub dry_run: bool,
    /// Exit nonzero when the target differs, without writing.
    #[arg(long)]
    pub check: bool,
    /// Remove keys previously owned by this overlay but absent from the source.
    #[arg(long)]
    pub reconcile_removed_keys: bool,
    /// Stable receipt identity used by removed-key reconciliation when enabled.
    #[arg(long)]
    pub managed_overlay_id: Option<String>,
    /// Absolute ownership-receipt root used by removed-key reconciliation when enabled.
    #[arg(long)]
    pub state_root: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct TomlOverlayArgs {
    /// Baseline TOML file to overlay from or remove from the target.
    pub source: PathBuf,
    /// Target TOML file to update.
    pub target: PathBuf,
    /// Which file wins when both define a different value.
    #[arg(long, value_enum, default_value_t)]
    pub conflicts: StandaloneTomlConflictPolicy,
    /// Remove source-owned keys while retaining target-only keys.
    #[arg(long)]
    pub remove: bool,
    /// Report without writing.
    #[arg(long)]
    pub dry_run: bool,
    /// Exit nonzero when the target differs, without writing.
    #[arg(long)]
    pub check: bool,
    /// Remove keys previously owned by this overlay but absent from the source.
    #[arg(long)]
    pub reconcile_removed_keys: bool,
    /// Stable receipt identity used by removed-key reconciliation when enabled.
    #[arg(long)]
    pub managed_overlay_id: Option<String>,
    /// Absolute ownership-receipt root used by removed-key reconciliation when enabled.
    #[arg(long)]
    pub state_root: Option<PathBuf>,
    /// Policy for recognizable commented target assignments.
    #[arg(long, value_enum, default_value_t)]
    pub commented_target_policy: StandaloneCommentedTargetPolicy,
}

#[derive(Debug, clap::Args)]
pub struct ManagedPathPolicyArgs {
    pub source: PathBuf,
    pub target: PathBuf,
    #[arg(long, value_enum, default_value_t)]
    pub policy: StandaloneManagedPathPolicy,
    #[arg(long)]
    pub skeleton: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t)]
    pub format: StandaloneOutputFormat,
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
        Ok(Cli {
            command: Some(Commands::JsonOverlay(mut arguments)),
            dry_run,
            ..
        }) => {
            arguments.dry_run |= dry_run;
            run_json_overlay_command(arguments)
        }
        Ok(Cli {
            command: Some(Commands::TomlOverlay(mut arguments)),
            dry_run,
            ..
        }) => {
            arguments.dry_run |= dry_run;
            run_toml_overlay_command(arguments)
        }
        Ok(Cli {
            command: Some(Commands::ManagedPathPolicy(mut arguments)),
            format,
            ..
        }) => {
            if format == OutputFormat::Json {
                arguments.format = StandaloneOutputFormat::Json;
            }
            run_managed_path_policy_command(arguments)
        }
        Ok(cli) => run_main(cli),
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            code
        }
    }
}

fn run_json_overlay_command(arguments: JsonOverlayArgs) -> i32 {
    let paths = PathContext::from_current_environment().and_then(|context| {
        Ok((
            normalize_standalone_path_argument(&arguments.source, &context)?,
            normalize_standalone_path_argument(&arguments.target, &context)?,
        ))
    });
    let (source, target) = match paths {
        Ok(paths) => paths,
        Err(error) => {
            println!("error: {error}");
            return 1;
        }
    };
    let mut request = crate::standalone::JsonOverlayRequest::new(source, target);
    request.dry_run = arguments.dry_run;
    request.check = arguments.check;
    request.replace_json_pointers = arguments.replace_json_pointers;
    request.reconcile_removed_keys = arguments.reconcile_removed_keys;
    request.managed_overlay_id = arguments.managed_overlay_id;
    request.state_root = arguments.state_root;
    match crate::standalone::execute_json_overlay(&request) {
        Ok(outcome) => {
            print_overlay_outcome(
                &request.target,
                &outcome.overlay,
                outcome.check_failed,
                request.dry_run || request.check,
                false,
                true,
            );
            outcome.exit_code()
        }
        Err(error) => {
            println!("error: {error}");
            1
        }
    }
}

fn run_toml_overlay_command(arguments: TomlOverlayArgs) -> i32 {
    let paths = PathContext::from_current_environment().and_then(|context| {
        Ok((
            normalize_standalone_path_argument(&arguments.source, &context)?,
            normalize_standalone_path_argument(&arguments.target, &context)?,
        ))
    });
    let (source, target) = match paths {
        Ok(paths) => paths,
        Err(error) => {
            println!("error: {error}");
            return 1;
        }
    };
    let mut request = crate::standalone::TomlRequest::new(source, target);
    request.operation = if arguments.remove {
        crate::standalone::TomlOperation::Remove
    } else {
        crate::standalone::TomlOperation::Overlay
    };
    request.dry_run = arguments.dry_run;
    request.check = arguments.check;
    request.conflict_policy = arguments.conflicts.into();
    request.reconcile_removed_keys = arguments.reconcile_removed_keys;
    request.managed_overlay_id = arguments.managed_overlay_id;
    request.state_root = arguments.state_root;
    request.commented_target_policy = arguments.commented_target_policy.into();
    match crate::standalone::execute_toml(&request) {
        Ok(outcome) => {
            print_overlay_outcome(
                &request.target,
                &outcome.overlay,
                outcome.check_failed,
                request.dry_run || request.check,
                request.operation == crate::standalone::TomlOperation::Remove,
                false,
            );
            outcome.exit_code()
        }
        Err(error) => {
            println!("error: {error}");
            1
        }
    }
}

fn print_overlay_outcome(
    target: &std::path::Path,
    overlay: &crate::overlay::OverlayResult,
    check_failed: bool,
    report_only: bool,
    removal: bool,
    include_replaced: bool,
) {
    if !overlay.changed {
        if removal {
            println!("up-to-date {} removed=0", target.display());
        } else if include_replaced {
            println!(
                "up-to-date {} added=0 overwritten=0 replaced=0 removed=0 ownership_changed=0",
                target.display()
            );
        } else {
            println!(
                "up-to-date {} added=0 overwritten=0 removed=0 ownership_changed=0",
                target.display()
            );
        }
        return;
    }
    let verb = if removal {
        if report_only {
            "would-remove"
        } else {
            "removed"
        }
    } else if report_only || check_failed {
        "would-update"
    } else {
        "updated"
    };
    let materialized = if overlay.materialized_symlink {
        " materialized_symlink=1"
    } else {
        ""
    };
    if removal {
        println!(
            "{verb} {} removed={}{materialized}",
            target.display(),
            overlay.removed
        );
    } else if include_replaced {
        println!(
            "{verb} {} added={} overwritten={} replaced={} removed={} ownership_changed={}{materialized}",
            target.display(),
            overlay.added,
            overlay.overwritten,
            overlay.replaced,
            overlay.removed,
            usize::from(overlay.ownership_changed),
        );
    } else {
        println!(
            "{verb} {} added={} overwritten={} removed={} ownership_changed={}{materialized}",
            target.display(),
            overlay.added,
            overlay.overwritten,
            overlay.removed,
            usize::from(overlay.ownership_changed),
        );
    }
}

fn normalize_standalone_path_argument(
    path: &Path,
    context: &PathContext,
) -> Result<PathBuf, crate::paths::PathError> {
    let Some(raw) = path.to_str() else {
        return Ok(path.to_path_buf());
    };
    normalize_user_path(raw, context)
}

fn run_managed_path_policy_command(arguments: ManagedPathPolicyArgs) -> i32 {
    let paths = PathContext::from_current_environment().and_then(|context| {
        Ok((
            normalize_standalone_path_argument(&arguments.source, &context)?,
            normalize_standalone_path_argument(&arguments.target, &context)?,
            arguments
                .skeleton
                .as_deref()
                .map(|path| normalize_standalone_path_argument(path, &context))
                .transpose()?,
        ))
    });
    let (source, target, skeleton) = match paths {
        Ok(paths) => paths,
        Err(error) => {
            println!("error: {error}");
            return 1;
        }
    };
    let mut request = crate::standalone::ManagedPathRequest::new(source, target);
    request.policy = arguments.policy.into();
    request.skeleton = skeleton;
    let result = crate::standalone::classify_managed_path(&request);
    match arguments.format {
        StandaloneOutputFormat::Human => {
            println!(
                "{}: {} {}",
                result.state,
                result.action,
                result.target.display()
            );
            0
        }
        StandaloneOutputFormat::Json => {
            match serde_json::to_writer(std::io::stdout().lock(), &result) {
                Ok(()) => {
                    println!();
                    0
                }
                Err(error) => {
                    eprintln!("sync-configs: cannot write command output: {error}");
                    1
                }
            }
        }
    }
}

fn run_main(cli: Cli) -> i32 {
    let mut interrupt_guard = match crate::interrupt::RunGuard::begin() {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("sync-configs: {error}");
            return 2;
        }
    };
    let mut output_profiles = crate::engine::fallback_profiles_for_output(&cli);
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
    let result = crate::engine::execute_observed(&cli, &mut output_profiles);
    let interrupted_by_engine = result.as_ref().is_err_and(|error| error.is_interrupted());
    let interrupted = interrupt_guard.begin_finalization() || interrupted_by_engine;
    if interrupted {
        let rendered = if cli.format == OutputFormat::Json {
            let mut value = serde_json::to_vec(&serde_json::json!({
                "schema_version": crate::report::REPORT_SCHEMA_VERSION,
                "outcome": "interrupted",
                "exit_code": 130,
                "dry_run": cli.dry_run,
                "profiles": output_profiles,
                "error_kind": "interrupted",
            }))
            .unwrap_or_else(|_| {
                b"{\"schema_version\":1,\"outcome\":\"interrupted\",\"exit_code\":130}\n".to_vec()
            });
            if !value.ends_with(b"\n") {
                value.push(b'\n');
            }
            value
        } else {
            b"interrupted\n".to_vec()
        };
        let _ = write_main_output(&mut recorder, &rendered, cli.format != OutputFormat::Json);
        recorder.finish(130, true);
        return 130;
    }
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
            let rendered = render_output(&cli, &output, &output_profiles);
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
                    "profiles": output_profiles,
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

fn render_output(
    cli: &Cli,
    output: &crate::engine::RunOutput,
    output_profiles: &[String],
) -> String {
    if cli.format == OutputFormat::Json {
        let value = match output {
            crate::engine::RunOutput::Convergence(report)
            | crate::engine::RunOutput::Validation(report) => serde_json::to_value(report.json())
                .unwrap_or_else(|_| {
                    serde_json::json!({
                        "schema_version": crate::report::REPORT_SCHEMA_VERSION,
                        "outcome": "failed",
                        "exit_code": 1,
                        "error_kind": "report_serialization_failed",
                    })
                }),
            crate::engine::RunOutput::Profiles(profiles) => serde_json::json!({
                "schema_version": crate::report::REPORT_SCHEMA_VERSION,
                "outcome": "completed",
                "exit_code": 0,
                "dry_run": cli.dry_run,
                "profiles": output_profiles,
                "available_profiles": profiles,
            }),
            crate::engine::RunOutput::Examples(_) => serde_json::json!({
                "schema_version": crate::report::REPORT_SCHEMA_VERSION,
                "outcome": "completed",
                "exit_code": 0,
                "dry_run": false,
                "profiles": output_profiles,
                "action": "print_example",
            }),
            crate::engine::RunOutput::Initialized(_) => serde_json::json!({
                "schema_version": crate::report::REPORT_SCHEMA_VERSION,
                "outcome": "completed",
                "exit_code": 0,
                "dry_run": false,
                "profiles": output_profiles,
                "action": "initialized",
            }),
        };
        let mut rendered = value.to_string();
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
