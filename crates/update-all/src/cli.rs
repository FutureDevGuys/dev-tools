use crate::completions::CompletionSyncArgs;
use crate::config::{
    init_config_file, load_runtime_config, parse_engine_mode, parse_ui_mode, validate_config,
    DashboardQuitBehavior as ConfigDashboardQuitBehavior,
    MouseRowStrideMode as ConfigMouseRowStrideMode, RuntimeConfig, TaskPolicy,
};
use crate::logging::RunLogSink;
use crate::sections::Sections;
use crate::tasks::{run_async, run_sync, PrivilegeSession, TaskPolicies};
use crate::ui::{MouseRowStride, UiModeResolved};
use crate::updaters::{detected_builtin_tasks, HostOs};
use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use is_terminal::IsTerminal;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "update-all")]
#[command(disable_help_subcommand = true)]
#[command(
    about = "Run detected updater tasks and refresh managed shell completions.",
    long_about = "Run detected updater tasks and refresh managed shell completions.\n\nBuilt-in and custom updater tasks are catalog-driven. Catalog-linked tasks can declare relationships such as including `skills` with `npm`, and command candidates let `skills` run directly when available or through `npx --no-install skills` when only the local npm package is resolvable."
)]
pub struct RunCli {
    #[command(subcommand)]
    subcommand: Option<RunSubcommand>,

    #[arg(long = "engine-mode", value_enum)]
    engine_mode: Option<EngineMode>,

    #[arg(long = "jobs")]
    jobs: Option<String>,

    #[arg(long = "ui", value_enum)]
    ui: Option<UiMode>,

    #[arg(long = "dashboard", default_value_t = false)]
    dashboard: bool,

    #[arg(long = "plain", default_value_t = false)]
    plain: bool,

    #[arg(long = "debug-report", default_value_t = false)]
    debug_report: bool,

    #[arg(long = "config")]
    config: Option<PathBuf>,

    #[arg(long = "fail-fast", default_value_t = false)]
    fail_fast: bool,

    #[arg(
        long = "bootstrap",
        default_value_t = false,
        help = "Include the Windows user-scope foundations bootstrap task for this run"
    )]
    bootstrap: bool,

    #[arg(
        long = "only",
        help = "Run only the selected updater ids or sections; catalog-linked tasks may include related maintenance such as skills with npm"
    )]
    only: Option<String>,

    #[arg(
        long = "exclude",
        help = "Exclude comma-separated updater ids or functional categories"
    )]
    exclude: Option<String>,

    #[arg(
        long = "completions",
        help = "Control public completion refresh behavior: off or refresh"
    )]
    completions: Option<String>,

    #[arg(
        long = "completion-provider",
        help = "Comma-separated completion providers to refresh (for example: npm,path,pipx,uv,go)"
    )]
    completion_provider: Option<String>,

    #[arg(long = "version", default_value_t = false)]
    version: bool,

    #[arg(long = "build-info", hide = true, default_value_t = false)]
    build_info: bool,
}

#[derive(clap::Subcommand, Debug)]
enum RunSubcommand {
    /// Emit shell completion for update-all itself.
    Completion(CompletionCli),
    /// Manage binary-owned completion generation and installation.
    Completions(CompletionsCli),
    /// Install, inspect, update, or roll back authenticated update-all releases.
    #[command(name = "self")]
    SelfCommand(SelfCli),
    /// Install and update authenticated Dev Tools products.
    Product(ProductCli),
    /// Read, write, validate, and install update-all config files.
    Config(ConfigCli),
    /// Browse prior run artifacts.
    Restore(RestoreCli),
    /// Open a prior run by UUID, display name, or run directory name.
    Resume(ResumeCli),
    /// Rename a prior run by UUID, display name, or run directory name.
    Rename(RenameCli),
    /// Print detected built-in updater tasks for the current host.
    List(ListCli),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum EngineMode {
    Sync,
    Async,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum UiMode {
    Auto,
    Plain,
    Dashboard,
}

#[derive(clap::Args, Debug)]
#[command(about = "Emit shell completion for update-all itself.")]
struct CompletionCli {
    #[arg(value_name = "SHELL")]
    shell: Option<String>,

    #[arg(long = "shell")]
    shell_flag: Option<String>,
}

#[derive(clap::Args, Debug)]
#[command(about = "Browse prior update-all run artifacts.")]
struct RestoreCli {
    #[arg(value_name = "QUERY")]
    query: Option<String>,

    #[arg(long = "limit", default_value_t = 25)]
    limit: usize,

    #[arg(long = "json", default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
#[command(about = "Show a prior update-all run by UUID, display name, or run directory name.")]
struct ResumeCli {
    #[arg(value_name = "QUERY")]
    query: String,

    #[arg(long = "json", default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
#[command(about = "Rename a prior update-all run.")]
struct RenameCli {
    #[arg(value_name = "QUERY")]
    query: String,

    #[arg(value_name = "DISPLAY_NAME")]
    display_name: String,
}

impl RunCli {
    pub fn run(mut self) -> Result<()> {
        if self.version {
            let build = crate::build_info::current_build_info();
            crate::ua_outln!(
                "update-all {} profile={} git_commit={} git_dirty={} built_unix={}",
                env!("CARGO_PKG_VERSION"),
                build.profile,
                build.git_commit,
                build.git_dirty,
                build.built_unix
            );
            return Ok(());
        }

        if self.build_info {
            crate::ua_outln!(
                "{}",
                serde_json::to_string_pretty(&crate::build_info::current_build_info())?
            );
            return Ok(());
        }

        match self.subcommand.take() {
            Some(RunSubcommand::Completion(cli)) => return cli.run(),
            Some(RunSubcommand::Completions(cli)) => return cli.run(self.config),
            Some(RunSubcommand::SelfCommand(cli)) => return cli.run_with_default_path(self.config),
            Some(RunSubcommand::Product(cli)) => return cli.run(),
            Some(RunSubcommand::Config(cli)) => return cli.run_with_default_path(self.config),
            Some(RunSubcommand::Restore(cli)) => return cli.run(self.config),
            Some(RunSubcommand::Resume(cli)) => return cli.run(self.config),
            Some(RunSubcommand::Rename(cli)) => return cli.run(self.config),
            Some(RunSubcommand::List(cli)) => return cli.run(),
            None => {}
        }

        let startup_cfg = Some(
            load_runtime_config(self.config.clone())
                .map_err(|error| crate::InvalidPlan(format!("{error:#}")))?,
        );
        if startup_cfg
            .as_ref()
            .is_some_and(|config| config.install.auto_update)
        {
            if let Some(activation) = crate::release::maybe_auto_update()? {
                if activation.changed {
                    crate::ua_outln!(
                        "Authenticated update-all {} and activated it for the next invocation.",
                        activation.version.as_deref().unwrap_or("<unknown>")
                    );
                }
            }
        }

        if self.dashboard && self.plain {
            bail!("--dashboard and --plain are mutually exclusive");
        }

        let mut runtime_cfg = startup_cfg
            .ok_or_else(|| anyhow::anyhow!("runtime config unavailable after startup checks"))?;
        if self.bootstrap {
            runtime_cfg.updaters.bootstrap.enabled = true;
        }

        let engine_mode = self
            .engine_mode
            .or_else(|| parse_engine_mode_env("UPDATE_ALL_ENGINE_MODE"))
            .or(Some(runtime_cfg.engine.mode))
            .unwrap_or(EngineMode::Async);

        let jobs = self.jobs.clone().unwrap_or_else(|| {
            env::var("UPDATE_ALL_JOBS").unwrap_or_else(|_| runtime_cfg.engine.jobs.clone())
        });

        let explicit_ui = if self.dashboard {
            Some(UiMode::Dashboard)
        } else if self.plain {
            Some(UiMode::Plain)
        } else {
            self.ui
        };

        let ui_requested = explicit_ui
            .or_else(|| parse_ui_mode_env("UPDATE_ALL_UI"))
            .or(Some(runtime_cfg.ui.mode))
            .unwrap_or(UiMode::Dashboard);

        let ui = resolve_ui(ui_requested)?;
        if matches!(ui_requested, UiMode::Plain | UiMode::Dashboard) {
            persist_ui_choice(ui_requested);
        }

        let completions_mode = resolve_completion_mode(
            self.completions
                .clone()
                .or_else(|| env::var("UPDATE_ALL_COMPLETIONS_MODE").ok()),
        )?;

        let completion_providers = self
            .completion_provider
            .clone()
            .or_else(|| env::var("UPDATE_ALL_COMPLETION_PROVIDERS").ok())
            .unwrap_or_else(|| "npm,path,pipx,uv,go".to_string());

        let completion_discover = env::var("UPDATE_ALL_COMPLETION_DISCOVER")
            .ok()
            .unwrap_or_else(|| "0".to_string());

        let completion_strict = env::var("UPDATE_ALL_COMPLETION_STRICT")
            .ok()
            .unwrap_or_else(|| "warn".to_string());

        let completion_report = env::var("UPDATE_ALL_COMPLETION_REPORT")
            .ok()
            .unwrap_or_else(|| "compact".to_string());

        let completion_paths = resolve_completion_paths();
        let run_log = Arc::new(RunLogSink::new(
            &runtime_cfg.logging.run_dir,
            runtime_cfg.logging.timestamps,
        )?);
        let task_policies = resolve_task_policies(&runtime_cfg);
        let mouse_row_stride = resolve_mouse_row_stride(&runtime_cfg);

        let flags = Sections::from_cli_selectors(&self.only, &self.exclude)?;

        let fail_fast = self.fail_fast || runtime_cfg.engine.fail_fast;
        let host_os = HostOs::current();

        if let Some(src) = runtime_cfg.source_path.as_ref() {
            crate::ua_outln!("Using config: {}", src.display());
        }
        crate::ua_outln!("Run logs: {}", run_log.run_dir().display());
        crate::ua_outln!("Run ID: {}", run_log.run_id());

        match engine_mode {
            EngineMode::Sync => {
                if ui == UiModeResolved::Dashboard {
                    run_async(crate::tasks::AsyncContext {
                        flags,
                        host_os,
                        updater_config: runtime_cfg.updaters.clone(),
                        jobs: "1".to_string(),
                        ui,
                        fail_fast,
                        ui_persist_until_exit: runtime_cfg.ui.persist_until_exit,
                        completions_mode,
                        completion_providers,
                        completion_discover,
                        completion_strict,
                        completion_report,
                        filter_progress_noise: runtime_cfg.logging.filter_progress_noise,
                        rc_root: completion_paths.rc_root,
                        completion_managed_root: completion_paths.managed_root,
                        completion_config_path: runtime_cfg.source_path.clone(),
                        completion_catalog_path: completion_paths.catalog_path,
                        completion_registry_path: completion_paths.registry_path,
                        run_log: Some(run_log.clone()),
                        task_policies: task_policies.clone(),
                        interactive_runtime: runtime_cfg.interactive.clone(),
                        privilege_session: Arc::new(PrivilegeSession::default()),
                        dashboard_quit_behavior: map_dashboard_quit_behavior(
                            runtime_cfg.ui.dashboard_quit_behavior,
                        ),
                        mouse_row_stride,
                        quit_cancel_grace: std::time::Duration::from_millis(
                            runtime_cfg.ui.quit_cancel_grace_ms,
                        ),
                        show_global_log: runtime_cfg.ui.show_global_log,
                        max_in_memory_lines: runtime_cfg.logging.max_in_memory_lines,
                        max_events_per_frame: runtime_cfg.ui.max_events_per_frame,
                        task_colors: runtime_cfg.logging.task_colors,
                        note_verbosity: runtime_cfg.ui.note_verbosity,
                        debug_report: self.debug_report,
                    })?
                } else {
                    run_sync(crate::tasks::SyncContext {
                        flags,
                        host_os,
                        updater_config: runtime_cfg.updaters.clone(),
                        completions_mode,
                        completion_providers,
                        completion_discover,
                        completion_strict,
                        completion_report,
                        filter_progress_noise: runtime_cfg.logging.filter_progress_noise,
                        emit_plain: true,
                        event_tx: None,
                        run_log: Some(run_log.clone()),
                        rc_root: completion_paths.rc_root.clone(),
                        completion_managed_root: completion_paths.managed_root.clone(),
                        completion_config_path: runtime_cfg.source_path.clone(),
                        completion_catalog_path: completion_paths.catalog_path.clone(),
                        completion_registry_path: completion_paths.registry_path.clone(),
                        task_policies: task_policies.clone(),
                        interactive_runtime: runtime_cfg.interactive.clone(),
                        note_verbosity: runtime_cfg.ui.note_verbosity,
                        debug_report: self.debug_report,
                        privilege_session: Arc::new(PrivilegeSession::default()),
                        runtime_control: None,
                        prompt_runtime: Arc::new(crate::tasks::PromptRuntime::default()),
                    })?
                }
            }
            EngineMode::Async => run_async(crate::tasks::AsyncContext {
                flags,
                host_os,
                updater_config: runtime_cfg.updaters.clone(),
                jobs,
                ui,
                fail_fast,
                ui_persist_until_exit: runtime_cfg.ui.persist_until_exit,
                completions_mode,
                completion_providers,
                completion_discover,
                completion_strict,
                completion_report,
                filter_progress_noise: runtime_cfg.logging.filter_progress_noise,
                rc_root: completion_paths.rc_root,
                completion_managed_root: completion_paths.managed_root,
                completion_config_path: runtime_cfg.source_path.clone(),
                completion_catalog_path: completion_paths.catalog_path,
                completion_registry_path: completion_paths.registry_path,
                run_log: Some(run_log),
                task_policies,
                interactive_runtime: runtime_cfg.interactive.clone(),
                privilege_session: Arc::new(PrivilegeSession::default()),
                dashboard_quit_behavior: map_dashboard_quit_behavior(
                    runtime_cfg.ui.dashboard_quit_behavior,
                ),
                mouse_row_stride,
                quit_cancel_grace: std::time::Duration::from_millis(
                    runtime_cfg.ui.quit_cancel_grace_ms,
                ),
                show_global_log: runtime_cfg.ui.show_global_log,
                max_in_memory_lines: runtime_cfg.logging.max_in_memory_lines,
                max_events_per_frame: runtime_cfg.ui.max_events_per_frame,
                task_colors: runtime_cfg.logging.task_colors,
                note_verbosity: runtime_cfg.ui.note_verbosity,
                debug_report: self.debug_report,
            })?,
        }

        Ok(())
    }
}

impl CompletionCli {
    fn resolved_shell(&self) -> &str {
        self.shell_flag
            .as_deref()
            .or(self.shell.as_deref())
            .unwrap_or("zsh")
    }

    fn run(self) -> Result<()> {
        let shell = self.resolved_shell();
        let output = crate::completions::generate_update_all_completion(shell)?;
        crate::ua_out!("{output}");
        Ok(())
    }
}

impl RestoreCli {
    fn run(self, default_config_path: Option<PathBuf>) -> Result<()> {
        let root = run_history_root(default_config_path)?;
        let mut runs = if let Some(query) = self.query.as_deref() {
            crate::runs::resolve_run_query(&root, query)?
        } else {
            crate::runs::scan_runs(&root)?
        };
        runs.truncate(self.limit.max(1));
        if self.json {
            crate::ua_outln!("{}", serde_json::to_string_pretty(&runs_json(&runs))?);
            return Ok(());
        }
        print_run_table(&runs);
        if runs.is_empty() || !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Ok(());
        }
        crate::ua_out!("select run number to view, or Enter to exit: ");
        io::stdout().flush().ok();
        let mut input = String::new();
        io::stdin().read_line(&mut input).ok();
        let selected = input.trim().parse::<usize>().ok();
        if let Some(idx) = selected.and_then(|idx| idx.checked_sub(1)) {
            if let Some(run) = runs.get(idx) {
                print_run_detail(run);
            }
        }
        Ok(())
    }
}

impl ResumeCli {
    fn run(self, default_config_path: Option<PathBuf>) -> Result<()> {
        let root = run_history_root(default_config_path)?;
        let matches = crate::runs::resolve_run_query(&root, &self.query)?;
        let Some(run) = select_run_match(&matches)? else {
            bail!("no update-all run matched '{}'", self.query);
        };
        if self.json {
            crate::ua_outln!("{}", serde_json::to_string_pretty(&run_json(run))?);
        } else {
            print_run_detail(run);
        }
        Ok(())
    }
}

impl RenameCli {
    fn run(self, default_config_path: Option<PathBuf>) -> Result<()> {
        let trimmed = self.display_name.trim();
        if trimmed.is_empty() {
            bail!("display name cannot be empty");
        }
        let root = run_history_root(default_config_path)?;
        let matches = crate::runs::resolve_run_query(&root, &self.query)?;
        let Some(run) = select_run_match_for_rename(&matches, &self.query)? else {
            bail!("no update-all run matched '{}'", self.query);
        };
        let metadata = if run.path.join("run-meta.json").exists() {
            crate::runs::rename_metadata(&run.path, trimmed, now_unix_ms_u64())?
        } else {
            let mut metadata = run.metadata.clone();
            metadata.display_name = trimmed.to_string();
            metadata.updated_unix_ms = now_unix_ms_u64();
            crate::runs::write_metadata_atomic(&run.path, &metadata)?;
            metadata
        };
        crate::ua_outln!(
            "Renamed run {} to {}",
            metadata.run_id,
            metadata.display_name
        );
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct RunSummaryJson {
    run_id: String,
    display_name: String,
    status: String,
    created_unix_ms: u64,
    updated_unix_ms: u64,
    selected_tasks: Vec<String>,
    task_count: usize,
    issue_count: usize,
    exit_code: Option<i32>,
    elapsed_ms: Option<u64>,
    run_json_status: String,
    path: String,
}

fn run_history_root(default_config_path: Option<PathBuf>) -> Result<PathBuf> {
    Ok(load_runtime_config(default_config_path)
        .map_err(|error| crate::InvalidPlan(format!("{error:#}")))?
        .logging
        .run_dir)
}

fn select_run_match(
    matches: &[crate::runs::RunSummary],
) -> Result<Option<&crate::runs::RunSummary>> {
    if matches.len() <= 1 {
        return Ok(matches.first());
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        if let Some(run) = matches.first() {
            crate::ua_errln!(
                "warning: multiple runs matched; using most recently updated {} ({})",
                run.metadata.display_name,
                run.metadata.run_id
            );
        }
        return Ok(matches.first());
    }
    print_run_table(matches);
    crate::ua_out!("multiple runs matched; select run number [1]: ");
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    let selected = input.trim().parse::<usize>().ok().unwrap_or(1);
    Ok(selected
        .checked_sub(1)
        .and_then(|idx| matches.get(idx))
        .or_else(|| matches.first()))
}

fn select_run_match_for_rename<'a>(
    matches: &'a [crate::runs::RunSummary],
    query: &str,
) -> Result<Option<&'a crate::runs::RunSummary>> {
    select_run_match_for_rename_with_tty(
        matches,
        query,
        io::stdin().is_terminal(),
        io::stdout().is_terminal(),
    )
}

fn select_run_match_for_rename_with_tty<'a>(
    matches: &'a [crate::runs::RunSummary],
    query: &str,
    stdin_is_tty: bool,
    stdout_is_tty: bool,
) -> Result<Option<&'a crate::runs::RunSummary>> {
    if matches.len() <= 1 {
        return Ok(matches.first());
    }
    if stdin_is_tty && stdout_is_tty {
        return select_run_match(matches);
    }

    let mut exact_matches = matches
        .iter()
        .filter(|run| crate::runs::run_matches_exact_query(run, query));
    if let Some(first) = exact_matches.next() {
        if exact_matches.next().is_none() {
            return Ok(Some(first));
        }
    }

    bail!(
        "multiple update-all runs matched '{}'; non-interactive rename requires a unique exact run id, display name, or run directory name",
        query
    );
}

fn print_run_table(runs: &[crate::runs::RunSummary]) {
    let now = now_unix_ms_u64();
    crate::ua_outln!(
        "{:<4} {:<24} {:<15} {:<10} {:<9} {:<9} {:>6} {:<12} path",
        "#",
        "display",
        "id",
        "status",
        "created",
        "modified",
        "issues",
        "tasks"
    );
    for (idx, run) in runs.iter().enumerate() {
        crate::ua_outln!(
            "{:<4} {:<24} {:<15} {:<10} {:<9} {:<9} {:>6} {:<12} {}",
            idx + 1,
            truncate_cell(&run.metadata.display_name, 24),
            truncate_cell(&run.metadata.run_id, 15),
            truncate_cell(&run.metadata.status, 10),
            truncate_cell(&relative_time_label(run.metadata.created_unix_ms, now), 9),
            truncate_cell(&relative_time_label(run.metadata.updated_unix_ms, now), 9),
            run.issue_count,
            truncate_cell(&run.metadata.selected_tasks.join(","), 12),
            run.path.display()
        );
    }
}

fn print_run_detail(run: &crate::runs::RunSummary) {
    crate::ua_outln!("Run: {}", run.metadata.display_name);
    crate::ua_outln!("ID: {}", run.metadata.run_id);
    crate::ua_outln!("Status: {}", run.metadata.status);
    let now = now_unix_ms_u64();
    crate::ua_outln!(
        "Created: {} ({})",
        run.metadata.created_unix_ms,
        relative_time_label(run.metadata.created_unix_ms, now)
    );
    crate::ua_outln!(
        "Updated: {} ({})",
        run.metadata.updated_unix_ms,
        relative_time_label(run.metadata.updated_unix_ms, now)
    );
    crate::ua_outln!("Path: {}", run.path.display());
    crate::ua_outln!("Run artifact: {}", run.run_json_status.as_str());
    crate::ua_outln!(
        "Exit code: {}",
        run.exit_code
            .map_or_else(|| "-".to_string(), |v| v.to_string())
    );
    crate::ua_outln!(
        "Elapsed ms: {}",
        run.elapsed_ms
            .map_or_else(|| "-".to_string(), |v| v.to_string())
    );
    crate::ua_outln!("Tasks: {}", run.metadata.selected_tasks.join(","));
    crate::ua_outln!("Task count: {}", run.task_count);
    crate::ua_outln!("Issue count: {}", run.issue_count);
}

fn runs_json(runs: &[crate::runs::RunSummary]) -> Vec<RunSummaryJson> {
    runs.iter().map(run_json).collect()
}

fn run_json(run: &crate::runs::RunSummary) -> RunSummaryJson {
    RunSummaryJson {
        run_id: run.metadata.run_id.clone(),
        display_name: run.metadata.display_name.clone(),
        status: run.metadata.status.clone(),
        created_unix_ms: run.metadata.created_unix_ms,
        updated_unix_ms: run.metadata.updated_unix_ms,
        selected_tasks: run.metadata.selected_tasks.clone(),
        task_count: run.task_count,
        issue_count: run.issue_count,
        exit_code: run.exit_code,
        elapsed_ms: run.elapsed_ms,
        run_json_status: run.run_json_status.as_str().to_string(),
        path: run.path.display().to_string(),
    }
}

fn truncate_cell(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    if width <= 3 {
        return ".".repeat(width);
    }
    let kept = width.saturating_sub(3);
    let mut out = value.chars().take(kept).collect::<String>();
    out.push_str("...");
    out
}

fn relative_time_label(timestamp_unix_ms: u64, now_unix_ms: u64) -> String {
    if timestamp_unix_ms == 0 {
        return "-".to_string();
    }
    let (future, delta_ms) = if timestamp_unix_ms > now_unix_ms {
        (true, timestamp_unix_ms.saturating_sub(now_unix_ms))
    } else {
        (false, now_unix_ms.saturating_sub(timestamp_unix_ms))
    };
    let secs = delta_ms / 1000;
    let label = if secs < 5 {
        return "now".to_string();
    } else if secs < 60 {
        format!("{secs}s")
    } else if secs < 3_600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3_600)
    } else if secs < 31_536_000 {
        format!("{}d", secs / 86_400)
    } else {
        format!("{}y", secs / 31_536_000)
    };
    if future {
        format!("in {label}")
    } else {
        format!("{label} ago")
    }
}

fn now_unix_ms_u64() -> u64 {
    u64::try_from(now_unix_ms()).unwrap_or(u64::MAX)
}

fn resolve_completion_mode(requested: Option<String>) -> Result<String> {
    let mode = requested
        .unwrap_or_else(|| "refresh".to_string())
        .trim()
        .to_ascii_lowercase();
    match mode.as_str() {
        "off" | "refresh" => Ok(mode),
        "refresh+audit" => bail!(
            "completion mode 'refresh+audit' is retired; use public 'refresh', or invoke the one-release legacy bridge explicitly with `update-all completions sync --apply --rc-root <absolute-root> --shell <shell> --audit-command <absolute-executable>`"
        ),
        other => bail!("invalid completion mode '{other}'; expected off or refresh"),
    }
}

struct CompletionPaths {
    rc_root: PathBuf,
    managed_root: PathBuf,
    powershell_root: Option<PathBuf>,
    catalog_path: PathBuf,
    registry_path: PathBuf,
}

struct TempCompletionCatalog {
    path: PathBuf,
}

impl TempCompletionCatalog {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempCompletionCatalog {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn resolve_completion_paths() -> CompletionPaths {
    let rc_root = env::var("RC_ROOT")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let managed_root = env::var("UPDATE_ALL_COMPLETION_ROOT")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_completion_managed_root);

    let catalog_path = env::var("UPDATE_ALL_COMPLETION_CATALOG")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| managed_root.join("cache/managed-tools.json"));

    let registry_path = env::var("UPDATE_ALL_COMPLETION_REGISTRY")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| managed_root.join("cache/audit-registry.json"));

    let powershell_root = env::var("UPDATE_ALL_POWERSHELL_ROOT")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            env::var("UPDATE_ALL_POWERSHELL_ROOT")
                .ok()
                .filter(|p| !p.trim().is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| {
            rc_root
                .parent()
                .map(|home| home.join(".config/update-all/powershell"))
        })
        .or_else(|| {
            env::var("HOME")
                .ok()
                .filter(|p| !p.trim().is_empty())
                .map(|h| PathBuf::from(h).join(".config/update-all/powershell"))
        });

    CompletionPaths {
        rc_root,
        managed_root,
        powershell_root,
        catalog_path,
        registry_path,
    }
}

pub(crate) fn default_completion_managed_root() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local_app_data).join("update-all/completions");
        }
    }

    if let Some(xdg_data_home) = env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(xdg_data_home).join("update-all/completions");
    }

    if let Some(home) = env::var_os("HOME") {
        return PathBuf::from(home).join(".local/share/update-all/completions");
    }

    env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("/"))
        .join(".local/share/update-all/completions")
}

fn resolve_managed_completion_root(
    explicit: Option<PathBuf>,
    defaults: &CompletionPaths,
) -> Result<PathBuf> {
    let root = explicit.unwrap_or_else(|| defaults.managed_root.clone());
    if !root.is_absolute() {
        bail!(
            "managed completion root must be absolute: {}",
            root.display()
        );
    }
    Ok(root)
}

fn write_completion_apply_managed_catalog(
    catalog: &crate::completions::registry::Registry,
    providers_csv: &str,
) -> Result<TempCompletionCatalog> {
    let filtered =
        crate::completions::filter_completion_catalog_for_providers(catalog, providers_csv);
    let payload = serde_json::to_vec_pretty(&filtered).context("serialize effective catalog")?;
    let base_ms = now_unix_ms();
    for attempt in 0..32 {
        let mut path = env::temp_dir();
        path.push(format!(
            "update-all-managed-catalog-{}-{base_ms}-{attempt}.json",
            std::process::id()
        ));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                if let Err(err) = file.write_all(&payload) {
                    let _ = fs::remove_file(&path);
                    return Err(err).with_context(|| {
                        format!(
                            "write temporary completion managed catalog {}",
                            path.display()
                        )
                    });
                }
                return Ok(TempCompletionCatalog { path });
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "create temporary completion managed catalog {}",
                        path.display()
                    )
                });
            }
        }
    }
    bail!("could not allocate temporary completion managed catalog path after 32 attempts")
}

fn parse_engine_mode_env(key: &str) -> Option<EngineMode> {
    let v = env::var(key).ok()?;
    parse_engine_mode(&v)
}

fn parse_ui_mode_env(key: &str) -> Option<UiMode> {
    let v = env::var(key).ok()?;
    parse_ui_mode(&v)
}

fn resolve_ui(ui: UiMode) -> Result<UiModeResolved> {
    Ok(resolve_ui_with_tty(ui, io::stdout().is_terminal()))
}

fn resolve_ui_with_tty(ui: UiMode, stdout_is_tty: bool) -> UiModeResolved {
    match ui {
        UiMode::Plain => UiModeResolved::Plain,
        UiMode::Dashboard => UiModeResolved::Dashboard,
        UiMode::Auto => {
            if stdout_is_tty {
                UiModeResolved::Dashboard
            } else {
                UiModeResolved::Plain
            }
        }
    }
}

fn ui_state_file() -> Option<PathBuf> {
    if let Ok(p) = env::var("UPDATE_ALL_UI_STATE_FILE") {
        if !p.trim().is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    let cache_dir = env::var("XDG_CACHE_HOME")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            env::var("HOME")
                .ok()
                .filter(|p| !p.trim().is_empty())
                .map(|h| PathBuf::from(h).join(".cache"))
        })?;
    Some(cache_dir.join("update_all_ui_mode.txt"))
}

fn persist_ui_choice(ui: UiMode) {
    let Some(path) = ui_state_file() else { return };
    let val = match ui {
        UiMode::Plain => "plain",
        UiMode::Dashboard => "dashboard",
        UiMode::Auto => return,
    };
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let _ = fs::write(path, format!("{val}\n"));
}

fn resolve_task_policies(cfg: &crate::config::RuntimeConfig) -> TaskPolicies {
    let npm_install_default = env_u64("UPDATE_ALL_NPM_INSTALL_TIMEOUT_SECS", 180);
    let pipx_upgrade_default = env_u64("UPDATE_ALL_PIPX_UPGRADE_TIMEOUT_SECS", 180);
    TaskPolicies {
        npm_install: cfg
            .policy_or_default("npm_install", TaskPolicy::new(npm_install_default, 0, 0)),
        pipx_upgrade: cfg
            .policy_or_default("pipx_upgrade", TaskPolicy::new(pipx_upgrade_default, 0, 0)),
        system_update: cfg.policy_or_default("system_update", TaskPolicy::new(3600, 0, 0)),
        aur_update: cfg.policy_or_default("aur_update", TaskPolicy::new(10800, 0, 0)),
        tool_update: cfg.policy_or_default("tool_update", TaskPolicy::new(600, 0, 0)),
        extra: cfg.tasks.clone(),
    }
}

fn env_u64(name: &str, fallback: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(fallback)
}

fn now_unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn map_dashboard_quit_behavior(
    value: ConfigDashboardQuitBehavior,
) -> crate::ui::DashboardQuitBehavior {
    match value {
        ConfigDashboardQuitBehavior::CancelAll => crate::ui::DashboardQuitBehavior::CancelAll,
        ConfigDashboardQuitBehavior::Detach => crate::ui::DashboardQuitBehavior::Detach,
    }
}

fn resolve_mouse_row_stride(runtime_cfg: &crate::config::RuntimeConfig) -> MouseRowStride {
    let configured = env::var("UPDATE_ALL_UI_MOUSE_ROW_STRIDE")
        .ok()
        .and_then(|v| ConfigMouseRowStrideMode::parse(&v))
        .unwrap_or(runtime_cfg.ui.mouse_row_stride);
    match configured {
        ConfigMouseRowStrideMode::Auto => MouseRowStride::Auto,
        ConfigMouseRowStrideMode::One => MouseRowStride::One,
        ConfigMouseRowStrideMode::Two => MouseRowStride::Two,
    }
}

// ---- `update-all completions ...` --------------------------------------------

#[derive(clap::Args, Debug)]
#[command(
    about = "Generate, publish, and inspect managed shell completions.",
    long_about = "Generate, publish, and inspect managed shell completions.\n\nUse `sync` to probe enabled providers and publish an immutable snapshot, then `init <shell>` to print the read-only startup line for Bash, Zsh, Fish, Elvish, or PowerShell. The `install` command and sync's `--apply` flag are explicit legacy compatibility surfaces for Zsh and PowerShell only. Managed completion sync starts from the repo catalog, then additively merges user entries from your config under `[[completions.tools]]`. Matching `(provider, name)` entries can disable a repo-managed tool on your machine without editing the repository. Catalog entries can mark trusted optional tools as ambient and can declare generic command candidates for fallback launch forms such as local package runners.\n\nWhen your config is not in the default location, pass the global `--config <path>` flag before `completions` so sync uses the same file."
)]
pub struct CompletionsCli {
    #[command(subcommand)]
    cmd: CompletionsCmd,
}

#[derive(clap::Subcommand, Debug)]
enum CompletionsCmd {
    /// Probe providers and write managed completion payloads.
    Sync(CompletionsSyncCli),
    /// Install the legacy binary-owned bootstrap for Zsh or PowerShell.
    Install(CompletionsInstallCli),
    /// Emit read-only shell init code for the active managed completion snapshot.
    Init(CompletionsInitCli),
    /// Inspect the active managed completion snapshot.
    Status(CompletionsStatusCli),
}

#[derive(clap::Args, Debug)]
#[command(
    about = "Probe completion-capable tools and write managed completion files.",
    long_about = "Probe completion-capable tools and write managed completion files.",
    after_help = "Managed completion sync starts from the repo catalog, then additively merges user config from `[[completions.tools]]` in the active update-all config file.\n\nBeginner authoring loop:\n  1. `update-all config init`\n  2. Add one `[[completions.tools]]` entry\n  3. `update-all config validate --strict`\n  4. `update-all completions sync --providers <provider>`\n  5. Run `update-all completions init <shell>` and add its printed line to that shell's startup file. Supported values are `bash`, `zsh`, `fish`, `elvish`, and `powershell`.\n\nThe explicit `--apply --shell <shell>` bridge is legacy compatibility wiring for Zsh and PowerShell only. If you keep your config somewhere else, use `update-all --config /path/to/config.toml completions sync ...`."
)]
struct CompletionsSyncCli {
    #[arg(
        long = "providers",
        help = "Comma-separated providers to probe (for example: npm,path,pipx,uv,go)"
    )]
    providers: String,

    #[arg(
        long = "discover",
        default_value_t = false,
        help = "Discover provider tools from the local machine instead of only the registry"
    )]
    discover: bool,

    #[arg(
        long = "report",
        default_value = "compact",
        help = "Choose completion sync reporting style"
    )]
    report: String,

    #[arg(
        long = "catalog",
        help = "Path to the managed completion catalog JSON used as the baseline tool list"
    )]
    catalog: Option<PathBuf>,

    #[arg(long = "registry", help = "Path to the completion audit registry JSON")]
    registry: Option<PathBuf>,

    #[arg(
        long = "rc-root",
        help = "Legacy shell rc root where managed completions and bootstrap files are written"
    )]
    rc_root: Option<PathBuf>,

    #[arg(
        long = "managed-root",
        help = "Absolute public root where immutable managed completion snapshots are published"
    )]
    managed_root: Option<PathBuf>,

    #[arg(
        long = "powershell-root",
        help = "PowerShell runtime root containing the modules directory"
    )]
    powershell_root: Option<PathBuf>,

    #[arg(
        long = "apply",
        default_value_t = false,
        help = "Explicitly run legacy Zsh or PowerShell bootstrap wiring and apply/audit"
    )]
    apply: bool,

    #[arg(
        long = "shell",
        action = clap::ArgAction::Append,
        help = "Completion shell to publish; repeat, configure a default list, or use 'all' alone"
    )]
    shell: Vec<String>,

    #[arg(
        long = "audit",
        default_value = "off",
        help = "Audit mode to use after --apply"
    )]
    audit: String,

    #[arg(
        long = "audit-command",
        help = "Exact absolute executable used by the explicit legacy audit bridge"
    )]
    audit_command: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
#[command(about = "Install the legacy binary-owned bootstrap for Zsh or PowerShell.")]
struct CompletionsInstallCli {
    #[arg(
        long = "shell",
        default_value = "zsh",
        help = "Shell bootstrap target to install"
    )]
    shell: String,

    #[arg(
        long = "rc-root",
        help = "Shell rc root where the binary-owned completion bootstrap is written"
    )]
    rc_root: PathBuf,

    #[arg(
        long = "powershell-root",
        help = "PowerShell runtime root containing the modules directory"
    )]
    powershell_root: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
#[command(about = "Emit read-only shell init code for the active managed completion snapshot.")]
struct CompletionsInitCli {
    #[arg(value_name = "SHELL")]
    shell: String,

    #[arg(
        long = "managed-root",
        help = "Absolute public root where immutable managed completion snapshots are published"
    )]
    managed_root: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
#[command(about = "Inspect the active managed completion snapshot.")]
struct CompletionsStatusCli {
    #[arg(long = "json", default_value_t = false)]
    json: bool,

    #[arg(
        long = "managed-root",
        help = "Absolute public root where immutable managed completion snapshots are published"
    )]
    managed_root: Option<PathBuf>,
}

impl CompletionsCli {
    pub fn run(self, default_path: Option<PathBuf>) -> Result<()> {
        match self.cmd {
            CompletionsCmd::Sync(cli) => {
                let defaults = resolve_completion_paths();
                let audit_mode = cli.audit.trim().to_ascii_lowercase();
                if cli.rc_root.is_some() && cli.managed_root.is_some() {
                    bail!("--rc-root and --managed-root are mutually exclusive");
                }
                if cli.apply && cli.rc_root.is_none() {
                    bail!("--apply requires an explicit --rc-root compatibility target");
                }
                if !cli.apply
                    && (cli.powershell_root.is_some()
                        || cli.audit_command.is_some()
                        || cli.registry.is_some()
                        || audit_mode != "off")
                {
                    bail!(
                        "--powershell-root, --registry, --audit, and --audit-command require --apply"
                    );
                }
                if cli.apply && !matches!(audit_mode.as_str(), "off" | "fast" | "strict") {
                    bail!("invalid --audit '{}': expected off|fast|strict", cli.audit);
                }
                if cli.apply && audit_mode != "off" {
                    let audit_command = cli.audit_command.as_deref().context(
                        "--audit fast|strict requires an exact absolute --audit-command",
                    )?;
                    crate::completions::validate_exact_audit_command(audit_command)?;
                }
                let managed_root = if let Some(rc_root) = cli.rc_root.as_deref() {
                    if !rc_root.is_absolute() {
                        bail!("--rc-root must be absolute: {}", rc_root.display());
                    }
                    rc_root.join("shell/completions/.update-all-state")
                } else {
                    resolve_managed_completion_root(cli.managed_root, &defaults)?
                };
                let catalog_path = cli.catalog.unwrap_or_else(|| {
                    env::var("UPDATE_ALL_COMPLETION_CATALOG")
                        .ok()
                        .filter(|path| !path.trim().is_empty())
                        .map(PathBuf::from)
                        .unwrap_or_else(|| managed_root.join("cache/managed-tools.json"))
                });
                let registry_path = cli.registry.unwrap_or_else(|| {
                    env::var("UPDATE_ALL_COMPLETION_REGISTRY")
                        .ok()
                        .filter(|path| !path.trim().is_empty())
                        .map(PathBuf::from)
                        .unwrap_or_else(|| managed_root.join("cache/audit-registry.json"))
                });
                let runtime_config = load_runtime_config(default_path.clone())?;
                let shells = crate::completions::resolve_completion_shells(
                    &cli.shell,
                    &runtime_config.completions.shells,
                )?;
                if cli.apply && shells.len() != 1 {
                    bail!("--apply requires exactly one --shell target");
                }
                let rc_root = cli.rc_root.clone();
                let providers = cli.providers.clone();
                let res = crate::completions::completion_sync(CompletionSyncArgs {
                    providers_csv: providers.clone(),
                    discover: cli.discover,
                    report: cli.report,
                    catalog_path,
                    config_path: default_path,
                    rc_root: rc_root.clone(),
                    managed_root,
                    shells: shells.clone(),
                    progress_cb: None,
                })?;

                for line in res.events {
                    crate::ua_outln!("{line}");
                }
                crate::ua_outln!("completion_outcome={}", res.outcome.as_str());

                if cli.apply {
                    let rc_root = rc_root
                        .clone()
                        .context("--apply requires an explicit --rc-root")?;
                    let shell = shells[0].as_event_name().to_string();
                    let powershell_root = cli
                        .powershell_root
                        .clone()
                        .or(defaults.powershell_root.clone());
                    let install = crate::completions::completion_install(
                        crate::completions::CompletionInstallArgs {
                            shell: shell.clone(),
                            rc_root: rc_root.clone(),
                            powershell_root: powershell_root.clone(),
                        },
                    )?;
                    for line in install.events {
                        crate::ua_outln!("{line}");
                    }
                    let managed_catalog = if audit_mode == "off" {
                        None
                    } else {
                        Some(write_completion_apply_managed_catalog(
                            &res.effective_catalog,
                            &providers,
                        )?)
                    };
                    let applied = crate::completions::completion_apply(
                        crate::completions::CompletionApplyArgs {
                            shell,
                            rc_root,
                            powershell_root,
                            registry_path,
                            managed_catalog_path: managed_catalog
                                .as_ref()
                                .map(|catalog| catalog.path().to_path_buf()),
                            discover: cli.discover,
                            audit_mode,
                            audit_command: cli.audit_command,
                        },
                    )?;
                    for line in applied.events {
                        crate::ua_outln!("{line}");
                    }
                }
            }
            CompletionsCmd::Install(cli) => {
                let defaults = resolve_completion_paths();
                let install = crate::completions::completion_install(
                    crate::completions::CompletionInstallArgs {
                        shell: cli.shell,
                        rc_root: cli.rc_root,
                        powershell_root: cli.powershell_root.or(defaults.powershell_root),
                    },
                )?;
                for line in install.events {
                    crate::ua_outln!("{line}");
                }
            }
            CompletionsCmd::Init(cli) => {
                let defaults = resolve_completion_paths();
                let root = resolve_managed_completion_root(cli.managed_root, &defaults)?;
                let init = crate::completions::completion_init(&cli.shell, root)?;
                crate::ua_out!("{}", init.shell_code);
            }
            CompletionsCmd::Status(cli) => {
                let defaults = resolve_completion_paths();
                let root = resolve_managed_completion_root(cli.managed_root, &defaults)?;
                let status = crate::completions::completion_status(root)?;
                if cli.json {
                    crate::ua_outln!("{}", serde_json::to_string_pretty(&status.status)?);
                } else {
                    crate::ua_outln!("managed_root={}", status.status.root.display());
                    crate::ua_outln!(
                        "current_snapshot={}",
                        status
                            .status
                            .current_snapshot
                            .as_deref()
                            .unwrap_or("<none>")
                    );
                    crate::ua_outln!(
                        "available_shells={}",
                        if status.status.available_shells.is_empty() {
                            "<none>".to_string()
                        } else {
                            status.status.available_shells.join(",")
                        }
                    );
                    crate::ua_outln!("active_bindings={}", status.status.active_bindings.len());
                    for binding in &status.status.active_bindings {
                        crate::ua_outln!(
                            "binding={}:{} provider={} executable={} classification={}",
                            binding.shell,
                            binding.command,
                            binding.provider,
                            binding.executable.display(),
                            binding.classification.as_deref().unwrap_or("unknown")
                        );
                    }
                    crate::ua_outln!("issues={}", status.status.issues.len());
                    for issue in &status.status.issues {
                        crate::ua_outln!(
                            "issue={}:{} outcome={} reason={}",
                            issue.provider,
                            issue.command,
                            issue.outcome,
                            issue.reason.as_deref().unwrap_or("-")
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

// ---- `update-all self ...` ---------------------------------------------------

#[derive(clap::Args, Debug)]
#[command(about = "Install and update update-all from authenticated releases.")]
pub struct SelfCli {
    #[command(subcommand)]
    cmd: SelfCmd,
}

#[derive(clap::Subcommand, Debug)]
enum SelfCmd {
    /// Install the latest authenticated stable release.
    Install(SelfOutputCli),
    /// Show local activation and retained rollback state without network access.
    Status(SelfOutputCli),
    /// Authenticate the latest stable release metadata without installing it.
    Check(SelfOutputCli),
    /// Download, verify, and atomically activate the latest stable release.
    Update(SelfOutputCli),
    /// Atomically reactivate the retained previous version.
    Rollback(SelfOutputCli),
}

#[derive(clap::Args, Debug)]
struct SelfOutputCli {
    #[arg(long = "json", default_value_t = false)]
    json: bool,
}

impl SelfCli {
    fn run_with_default_path(self, _default_path: Option<PathBuf>) -> Result<()> {
        match self.cmd {
            SelfCmd::Install(cli) => emit_release_result(
                crate::release::install(crate::release::Product::UpdateAll)?,
                cli.json,
            ),
            SelfCmd::Status(cli) => {
                let status = crate::release::status(crate::release::Product::UpdateAll)?;
                if cli.json {
                    crate::ua_outln!("{}", serde_json::to_string_pretty(&status)?);
                } else {
                    crate::ua_outln!("Managed installation: {}", status.managed);
                    crate::ua_outln!(
                        "Installed version: {}",
                        status.installed_version.as_deref().unwrap_or("<unmanaged>")
                    );
                    crate::ua_outln!("Engine version: {}", status.engine_version);
                    crate::ua_outln!(
                        "Rollback version: {}",
                        status.previous_version.as_deref().unwrap_or("<none>")
                    );
                }
            }
            SelfCmd::Check(cli) => {
                let check = crate::release::check(crate::release::Product::UpdateAll)?;
                if cli.json {
                    crate::ua_outln!("{}", serde_json::to_string_pretty(&check)?);
                } else if check.update_available {
                    crate::ua_outln!(
                        "Update available: {} -> {} ({})",
                        check.installed_version.as_deref().unwrap_or("<unmanaged>"),
                        check.latest_version,
                        check.target
                    );
                } else {
                    crate::ua_outln!(
                        "Latest authenticated release is installed: {}",
                        check.latest_version
                    );
                }
            }
            SelfCmd::Update(cli) => emit_release_result(
                crate::release::update(crate::release::Product::UpdateAll)?,
                cli.json,
            ),
            SelfCmd::Rollback(cli) => emit_release_result(
                crate::release::rollback(crate::release::Product::UpdateAll)?,
                cli.json,
            ),
        }
        Ok(())
    }
}

fn emit_release_result(result: crate::release::Activation, json: bool) {
    if json {
        crate::ua_outln!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
        );
    } else if result.changed {
        crate::ua_outln!(
            "Activated {} {} at {}",
            product_name(result.product),
            result.version.as_deref().unwrap_or("<unknown>"),
            result
                .path
                .as_ref()
                .map_or_else(|| "<none>".to_string(), |path| path.display().to_string())
        );
    } else {
        crate::ua_outln!(
            "{}: {}{}",
            product_name(result.product),
            result.outcome,
            result
                .version
                .as_deref()
                .map_or_else(String::new, |version| format!(" ({version})"))
        );
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProductName {
    UpdateAll,
    DevCache,
    SyncConfigs,
    SkillsSync,
}

impl From<ProductName> for crate::release::Product {
    fn from(value: ProductName) -> Self {
        match value {
            ProductName::UpdateAll => Self::UpdateAll,
            ProductName::DevCache => Self::DevCache,
            ProductName::SyncConfigs => Self::SyncConfigs,
            ProductName::SkillsSync => Self::SkillsSync,
        }
    }
}

fn product_name(product: crate::release::Product) -> &'static str {
    product.id()
}

#[derive(clap::Args, Debug)]
#[command(about = "Install and update products through shared authenticated manifests.")]
struct ProductCli {
    #[command(subcommand)]
    cmd: ProductCmd,
}

#[derive(clap::Subcommand, Debug)]
enum ProductCmd {
    /// Install the latest authenticated stable release.
    Install(ProductOutputCli),
    /// Show local product activation state without network access.
    Status(ProductOutputCli),
    /// Authenticate the latest stable metadata without installing it.
    Check(ProductOutputCli),
    /// Update or install the latest authenticated stable release.
    Update(ProductOutputCli),
    /// Update only when the product command is already installed.
    UpdateIfInstalled(ProductOutputCli),
    /// Atomically reactivate the retained previous version.
    Rollback(ProductOutputCli),
}

#[derive(clap::Args, Debug)]
struct ProductOutputCli {
    #[arg(value_enum)]
    product: ProductName,
    #[arg(long = "json", default_value_t = false)]
    json: bool,
}

impl ProductCli {
    fn run(self) -> Result<()> {
        match self.cmd {
            ProductCmd::Install(cli) => {
                emit_release_result(crate::release::install(cli.product.into())?, cli.json)
            }
            ProductCmd::Status(cli) => {
                let status = crate::release::status(cli.product.into())?;
                if cli.json {
                    crate::ua_outln!("{}", serde_json::to_string_pretty(&status)?);
                } else {
                    crate::ua_outln!(
                        "{} managed={} active={}",
                        product_name(status.product),
                        status.managed,
                        status.installed_version.as_deref().unwrap_or("<none>")
                    );
                }
            }
            ProductCmd::Check(cli) => {
                let check = crate::release::check(cli.product.into())?;
                if cli.json {
                    crate::ua_outln!("{}", serde_json::to_string_pretty(&check)?);
                } else {
                    crate::ua_outln!(
                        "{} latest={} update_available={}",
                        product_name(check.product),
                        check.latest_version,
                        check.update_available
                    );
                }
            }
            ProductCmd::Update(cli) => {
                emit_release_result(crate::release::update(cli.product.into())?, cli.json)
            }
            ProductCmd::UpdateIfInstalled(cli) => emit_release_result(
                crate::release::update_if_installed(cli.product.into())?,
                cli.json,
            ),
            ProductCmd::Rollback(cli) => {
                emit_release_result(crate::release::rollback(cli.product.into())?, cli.json)
            }
        }
        Ok(())
    }
}

// ---- `update-all config ...` -------------------------------------------------

#[derive(clap::Args, Debug)]
#[command(about = "Create and validate update-all configuration.")]
pub struct ConfigCli {
    #[command(subcommand)]
    cmd: ConfigCmd,
}

#[derive(clap::Subcommand, Debug)]
enum ConfigCmd {
    /// Write a starter configuration.
    Init(ConfigInitCli),
    /// Validate the selected configuration and external catalogs.
    Validate(ConfigValidateCli),
}

#[derive(clap::Args, Debug)]
struct ConfigInitCli {
    #[arg(long = "path")]
    path: Option<PathBuf>,

    #[arg(long = "force", default_value_t = false)]
    force: bool,
}

#[derive(clap::Args, Debug)]
struct ConfigValidateCli {
    #[arg(long = "path")]
    path: Option<PathBuf>,

    #[arg(long = "strict", default_value_t = false)]
    strict: bool,
}

impl ConfigCli {
    pub fn run_with_default_path(self, default_path: Option<PathBuf>) -> Result<()> {
        match self.cmd {
            ConfigCmd::Init(cli) => {
                let path = init_config_file(cli.path.or(default_path), cli.force)?;
                crate::ua_outln!("Wrote config: {}", path.display());
            }
            ConfigCmd::Validate(cli) => {
                let report = validate_config(cli.path.or(default_path), cli.strict)
                    .map_err(|error| crate::InvalidPlan(format!("{error:#}")))?;
                match report.path {
                    Some(path) => crate::ua_outln!("Config OK: {}", path.display()),
                    None => {
                        crate::ua_outln!("Config OK: no config file found, defaults will be used")
                    }
                }
                for warning in report.warnings {
                    crate::ua_errln!("warning: {warning}");
                }
            }
        }
        Ok(())
    }
}

// ---- `update-all list ...` ---------------------------------------------------

#[derive(clap::Args, Debug)]
#[command(
    about = "Print detected built-in updater tasks for the current host.",
    long_about = "Print detected built-in updater tasks for the current host.\n\nDetection is host-aware and only includes locally available built-ins. This includes npm-adjacent tools such as `skills` when they are directly executable or locally resolvable via `npx --no-install skills`."
)]
pub struct ListCli {
    #[arg(
        long = "detected",
        default_value_t = true,
        help = "Show detected built-in updater tasks for this host"
    )]
    detected: bool,

    #[arg(
        long = "json",
        default_value_t = false,
        help = "Emit machine-readable JSON"
    )]
    json: bool,
}

impl ListCli {
    pub fn run(self) -> Result<()> {
        let host_os = HostOs::current();
        let mut rows: Vec<(String, String)> = Vec::new();

        if self.detected {
            for task in detected_builtin_tasks(host_os)? {
                rows.push((task.id, format!("{} ({})", task.label, task.category)));
            }
        }

        rows.sort_by(|a, b| a.0.cmp(&b.0));

        if self.json {
            let payload: Vec<serde_json::Value> = rows
                .iter()
                .map(|(id, label)| {
                    serde_json::json!({
                        "id": id,
                        "label": label,
                        "host_os": host_os.as_str()
                    })
                })
                .collect();
            crate::ua_outln!("{}", serde_json::to_string_pretty(&payload)?);
            return Ok(());
        }

        crate::ua_outln!("Host OS: {}", host_os.as_str());
        if rows.is_empty() {
            crate::ua_outln!("No updaters detected.");
        } else {
            for (id, label) in rows {
                crate::ua_outln!("{id}: {label}");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/cli_release.rs"]
mod tests;
