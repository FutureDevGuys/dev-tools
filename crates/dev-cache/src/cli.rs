use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use clap::{error::ErrorKind, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use serde::Serialize;

use crate::adapter::{Adapter, AdapterContext};
use crate::artifacts;
use crate::cargo_intercept;
use crate::config::{Config, EnvironmentOverrides};
use crate::dispatch::{classify_invocation, is_intercept_name, Dispatch};
use crate::gc::{self, GcOverrides};
use crate::install;
use crate::lease::RootLease;
use crate::migrate;
use crate::provenance;
use crate::repository::Repository;
use crate::root::RootHandle;
use crate::util::{directory_size, now_unix, write_json_atomic};

#[derive(Parser, Debug)]
#[command(
    name = "dev-cache",
    version,
    about = "Route disposable development caches safely"
)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[arg(long, global = true)]
    root: Option<PathBuf>,
    #[arg(long, value_enum, global = true)]
    mode: Option<Mode>,
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Option<CommandKind>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    On,
    Off,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CompletionShell {
    Bash,
    Elvish,
    Fish,
    PowerShell,
    Zsh,
}

#[derive(Subcommand, Debug)]
enum CommandKind {
    /// Generate a completion script from the live command definition.
    Completion {
        #[arg(value_enum)]
        shell: CompletionShell,
        /// Write atomically to a file instead of standard output.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Show effective routing state for the current worktree.
    Status,
    /// Check configuration, root ownership, PATH activation, and adapter tools.
    Doctor,
    /// Summarize space used by each owned cache class.
    Report,
    /// Print the routed path for an adapter.
    Path {
        #[arg(value_enum)]
        adapter: Adapter,
        #[arg(long)]
        repo: Option<PathBuf>,
    },
    /// Run a command with one adapter's native cache environment.
    Exec(ExecArgs),
    /// Inspect configuration or initialize an owned cache root.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Plan or apply lease-safe garbage collection.
    Gc(GcArgs),
    /// Manage verified disposable build artifacts.
    Artifacts {
        #[command(subcommand)]
        command: ArtifactCommand,
    },
    /// Copy this executable into a user bin directory.
    Install {
        #[arg(long)]
        bin_dir: Option<PathBuf>,
        #[arg(long)]
        activate: bool,
        #[arg(long)]
        intercept_dir: Option<PathBuf>,
    },
    /// Reconcile ownership-checked intercepts for supported installed tools.
    Activate {
        #[arg(long)]
        bin_dir: Option<PathBuf>,
        #[arg(long)]
        intercept_dir: Option<PathBuf>,
    },
    /// Remove only command intercepts owned by dev-cache.
    Deactivate {
        #[arg(long)]
        intercept_dir: Option<PathBuf>,
    },
    /// Remove dev-cache files created by its self-installer.
    Uninstall {
        #[arg(long)]
        bin_dir: Option<PathBuf>,
        #[arg(long)]
        intercept_dir: Option<PathBuf>,
    },
    /// Plan or copy a legacy cache into its routed destination.
    Migrate(MigrateArgs),
}

#[derive(Args, Debug)]
struct ExecArgs {
    #[arg(value_enum)]
    adapter: Adapter,
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    program: Vec<OsString>,
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
    /// Print effective configuration.
    Show,
    /// Validate effective configuration.
    Check,
    /// Claim an empty directory and write configuration.
    InitRoot {
        root: PathBuf,
        #[arg(long)]
        force_config: bool,
    },
    /// Atomically move the configured root on its current filesystem and update configuration.
    RelocateRoot {
        #[arg(value_name = "ROOT")]
        replacement: PathBuf,
    },
}

#[derive(Args, Debug)]
struct GcArgs {
    #[arg(long)]
    apply: bool,
    #[arg(long)]
    automatic: bool,
    #[arg(long)]
    max_bytes: Option<u64>,
    #[arg(long)]
    min_free_bytes: Option<u64>,
    #[arg(long)]
    target_free_bytes: Option<u64>,
    #[arg(long)]
    stale_after_days: Option<u64>,
}

#[derive(Subcommand, Debug)]
enum ArtifactCommand {
    /// Copy and verify a file into the BLAKE3 CAS.
    Put { source: PathBuf },
    /// Verify and restore one CAS object.
    Get {
        digest: String,
        destination: PathBuf,
    },
    /// List artifact metadata.
    List,
    /// Verify one artifact or the whole CAS.
    Verify { digest: Option<String> },
    /// Remove one disposable CAS object.
    Remove { digest: String },
}

#[derive(Args, Debug)]
struct MigrateArgs {
    #[arg(value_enum)]
    adapter: Adapter,
    source: PathBuf,
    #[arg(long)]
    repo: Option<PathBuf>,
    /// Select a cache resource when an adapter owns more than one (for example Go modules).
    #[arg(long)]
    resource: Option<String>,
    #[arg(long)]
    apply: bool,
    #[arg(long)]
    remove_source: bool,
}

#[derive(Serialize)]
struct StatusReport {
    enabled: bool,
    configured_root: Option<PathBuf>,
    root_valid: bool,
    platform: Option<String>,
    domain_id: Option<String>,
    physical_root_id: Option<String>,
    worktree: Option<PathBuf>,
    worktree_cache: Option<PathBuf>,
    routing_complete: bool,
    intercept_directory: PathBuf,
    path_entries: Vec<PathBuf>,
    routed_adapters: Vec<String>,
    real_executables: HashMap<String, Option<PathBuf>>,
    adapter_versions: HashMap<String, Option<String>>,
    effective_paths: HashMap<String, Vec<PathBuf>>,
    abstentions: Vec<String>,
    override_reasons: Vec<String>,
    provenance: Option<serde_json::Value>,
}

struct AdapterStatusDetails {
    real_executables: HashMap<String, Option<PathBuf>>,
    adapter_versions: HashMap<String, Option<String>>,
    effective_paths: HashMap<String, Vec<PathBuf>>,
    abstentions: Vec<String>,
    override_reasons: Vec<String>,
    applicable_adapters: HashSet<String>,
}

#[derive(Clone, Debug, Serialize)]
struct AdapterActivationClassification {
    adapter: String,
    state: String,
    enabled: bool,
    installed: bool,
    supported: bool,
    explicit_override: Option<PathBuf>,
    detail: Option<String>,
}

pub fn main_entry(argv0: OsString, args: Vec<OsString>) -> i32 {
    let result = if invoked_as_cargo(&argv0) {
        run_cargo(args)
    } else if invoked_as_rustup(&argv0) {
        run_rustup(args)
    } else if let Some((adapter, command)) = invoked_adapter(&argv0, &args) {
        run_adapter_intercept(adapter, &command, args)
    } else if is_intercept_name(&argv0.to_string_lossy()) {
        run_intercept_passthrough(&argv0, args)
    } else {
        run_cli(argv0, args)
    };
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("dev-cache: {error:#}");
            if error.to_string().contains("busy") {
                12
            } else {
                10
            }
        }
    }
}

fn run_intercept_passthrough(argv0: &OsStr, args: Vec<OsString>) -> Result<i32> {
    let command = Path::new(argv0)
        .file_stem()
        .and_then(|value| value.to_str())
        .context("resolve intercepted command name")?;
    let real = cargo_intercept::resolve_real_command(command, &env::current_exe()?)?;
    cargo_intercept::delegate(&real, &args, &[], None)
}

fn invoked_adapter(argv0: &OsStr, args: &[OsString]) -> Option<(Adapter, String)> {
    let stem = Path::new(argv0)
        .file_stem()?
        .to_string_lossy()
        .to_lowercase();
    let adapter = match classify_invocation(&stem, args) {
        Dispatch::Adapter(adapter) => adapter,
        Dispatch::Delegate => return None,
    };
    Some((adapter, stem))
}

fn invoked_as_rustup(argv0: &OsStr) -> bool {
    Path::new(argv0)
        .file_stem()
        .is_some_and(|stem| stem.to_string_lossy().eq_ignore_ascii_case("rustup"))
}

fn invoked_as_cargo(argv0: &OsStr) -> bool {
    Path::new(argv0)
        .file_stem()
        .is_some_and(|stem| stem.to_string_lossy().eq_ignore_ascii_case("cargo"))
}

fn run_cli(argv0: OsString, args: Vec<OsString>) -> Result<i32> {
    let mut cli = match Cli::try_parse_from(std::iter::once(argv0).chain(args)) {
        Ok(cli) => cli,
        Err(error) => {
            let exit_code = match error.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => 0,
                _ => 2,
            };
            error.print()?;
            return Ok(exit_code);
        }
    };
    let command = cli.command.take().unwrap_or(CommandKind::Status);
    match command {
        CommandKind::Completion { shell, output } => {
            if let Some(changed) = generate_completion(shell, output.as_deref())? {
                print_value(
                    cli.json,
                    &serde_json::json!({"completion":output,"changed":changed}),
                )?;
            }
            return Ok(0);
        }
        CommandKind::Config {
            command: ConfigCommand::InitRoot { root, force_config },
        } => return init_root(&cli, &root, force_config),
        CommandKind::Config {
            command: ConfigCommand::RelocateRoot { replacement },
        } => return relocate_root(&cli, &replacement),
        CommandKind::Install {
            bin_dir,
            activate,
            intercept_dir,
        } => {
            let bin_dir = bin_dir.unwrap_or_else(install::default_bin_dir);
            let target = install::install(&bin_dir)?;
            let activation = if activate {
                Some(install::activate(
                    &bin_dir,
                    &intercept_dir.unwrap_or_else(install::default_intercept_dir),
                )?)
            } else {
                None
            };
            print_value(
                cli.json,
                &serde_json::json!({"installed":target,"activation":activation}),
            )?;
            return Ok(0);
        }
        CommandKind::Activate {
            bin_dir,
            intercept_dir,
        } => {
            let result = install::activate(
                &bin_dir.unwrap_or_else(install::default_bin_dir),
                &intercept_dir.unwrap_or_else(install::default_intercept_dir),
            )?;
            print_value(
                cli.json,
                &serde_json::json!({"activated":result.changed,"target":result.target}),
            )?;
            return Ok(0);
        }
        CommandKind::Deactivate { intercept_dir } => {
            let changed =
                install::deactivate(&intercept_dir.unwrap_or_else(install::default_intercept_dir))?;
            print_value(cli.json, &serde_json::json!({"deactivated":changed}))?;
            return Ok(0);
        }
        CommandKind::Uninstall {
            bin_dir,
            intercept_dir,
        } => {
            let changed = install::uninstall(
                &bin_dir.unwrap_or_else(install::default_bin_dir),
                &intercept_dir.unwrap_or_else(install::default_intercept_dir),
            )?;
            print_value(cli.json, &serde_json::json!({"uninstalled":changed}))?;
            return Ok(0);
        }
        _ => {}
    }
    let (config, config_path) = effective_config(&cli)?;
    match command {
        CommandKind::Status => {
            print_value(cli.json, &status_report(&config)?)?;
            Ok(0)
        }
        CommandKind::Doctor => doctor(&config, config_path.as_deref(), cli.json),
        CommandKind::Report => report(&config, cli.json),
        CommandKind::Path { adapter, repo } => {
            path_command(&config, adapter, repo.as_deref(), cli.json)
        }
        CommandKind::Exec(exec) => exec_command(&config, exec),
        CommandKind::Config {
            command: ConfigCommand::Show,
        } => {
            print_config(&config, cli.json)?;
            Ok(0)
        }
        CommandKind::Config {
            command: ConfigCommand::Check,
        } => {
            config.validate()?;
            print_value(
                cli.json,
                &serde_json::json!({"valid":true,"config":config_path}),
            )?;
            Ok(0)
        }
        CommandKind::Gc(args) => gc_command(&config, args, cli.json),
        CommandKind::Artifacts { command } => artifact_command(&config, command, cli.json),
        CommandKind::Migrate(args) => migrate_command(&config, args, cli.json),
        CommandKind::Config {
            command: ConfigCommand::InitRoot { .. },
        }
        | CommandKind::Config {
            command: ConfigCommand::RelocateRoot { .. },
        }
        | CommandKind::Install { .. }
        | CommandKind::Activate { .. }
        | CommandKind::Deactivate { .. }
        | CommandKind::Uninstall { .. } => bail!("internal command dispatch error"),
        CommandKind::Completion { .. } => bail!("internal command dispatch error"),
    }
}

fn generate_completion(shell: CompletionShell, output: Option<&Path>) -> Result<Option<bool>> {
    let mut command = Cli::command();
    let mut payload = Vec::new();
    match shell {
        CompletionShell::Bash => clap_complete::generate(
            clap_complete::shells::Bash,
            &mut command,
            "dev-cache",
            &mut payload,
        ),
        CompletionShell::Elvish => clap_complete::generate(
            clap_complete::shells::Elvish,
            &mut command,
            "dev-cache",
            &mut payload,
        ),
        CompletionShell::Fish => clap_complete::generate(
            clap_complete::shells::Fish,
            &mut command,
            "dev-cache",
            &mut payload,
        ),
        CompletionShell::PowerShell => clap_complete::generate(
            clap_complete::shells::PowerShell,
            &mut command,
            "dev-cache",
            &mut payload,
        ),
        CompletionShell::Zsh => clap_complete::generate(
            clap_complete::shells::Zsh,
            &mut command,
            "dev-cache",
            &mut payload,
        ),
    }
    if let Some(path) = output {
        if fs::read(path).ok().as_deref() == Some(payload.as_slice()) {
            return Ok(Some(false));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension(format!("dev-cache-partial-{}", std::process::id()));
        fs::write(&temporary, payload)?;
        fs::rename(&temporary, path)?;
        Ok(Some(true))
    } else {
        use std::io::Write;
        std::io::stdout().write_all(&payload)?;
        Ok(None)
    }
}

fn effective_config(cli: &Cli) -> Result<(Config, Option<PathBuf>)> {
    let (config, path) = Config::load(cli.config.as_deref())?;
    let config = config.with_environment(EnvironmentOverrides {
        root: cli.root.clone(),
        mode: cli.mode.map(|mode| matches!(mode, Mode::On)),
        real_cargo: None,
    })?;
    Ok((config, path))
}

fn init_root(cli: &Cli, root_path: &Path, force_config: bool) -> Result<i32> {
    let root = RootHandle::initialize(root_path)?;
    let path = cli
        .config
        .clone()
        .unwrap_or_else(crate::config::default_config_path);
    if path.exists() {
        let existing = Config::parse(&fs::read_to_string(&path)?)?;
        let existing_root = existing
            .root
            .as_deref()
            .map(crate::util::path_from_home)
            .and_then(|configured| configured.canonicalize().ok());
        if existing_root.as_deref() == Some(root.root.as_path()) {
            print_value(
                cli.json,
                &serde_json::json!({"initialized":false,"root":root.root,"root_id":root.marker.root_id,"domain_id":root.domain_id,"config":path}),
            )?;
            return Ok(0);
        }
        if !force_config {
            bail!(
                "configuration already exists with a different root: {}; use --force-config to replace it",
                path.display()
            );
        }
    }
    let config = Config {
        root: Some(root.root.clone()),
        ..Config::default()
    };
    config.write_atomic(&path)?;
    print_value(
        cli.json,
        &serde_json::json!({"initialized":true,"root":root.root,"root_id":root.marker.root_id,"domain_id":root.domain_id,"config":path}),
    )?;
    Ok(0)
}

fn relocate_root(cli: &Cli, replacement: &Path) -> Result<i32> {
    let (mut config, _loaded_path) = effective_config(cli)?;
    let current = config
        .root
        .as_deref()
        .context("routing root is not configured")?;
    let root = RootHandle::open(current)?;
    let lease = RootLease::exclusive(&root)?;
    let relocated = root.relocate(replacement)?;
    config.version = 2;
    config.root = Some(relocated.root.clone());
    let config_path = cli
        .config
        .clone()
        .unwrap_or_else(crate::config::default_config_path);
    if let Err(error) = config.write_atomic(&config_path) {
        bail!(
            "cache root moved to {}, but configuration update failed: {error:#}; rerun with DEV_CACHE_ROOT set to the new path",
            relocated.root.display()
        );
    }
    drop(lease);
    print_value(
        cli.json,
        &serde_json::json!({"relocated":true,"root":relocated.root,"domain_id":relocated.domain_id,"config":config_path}),
    )?;
    Ok(0)
}

fn open_root(config: &Config) -> Result<RootHandle> {
    if !config.enabled {
        bail!("routing is disabled");
    }
    RootHandle::open(
        config
            .root
            .as_deref()
            .context("routing root is not configured")?,
    )
}

fn status_report(config: &Config) -> Result<StatusReport> {
    let intercept = install::default_intercept_dir();
    if !config.enabled {
        return Ok(StatusReport {
            enabled: false,
            configured_root: config.root.clone(),
            root_valid: false,
            platform: None,
            domain_id: None,
            physical_root_id: None,
            worktree: None,
            worktree_cache: None,
            routing_complete: false,
            intercept_directory: intercept,
            path_entries: env::var_os("PATH")
                .map(|path| env::split_paths(&path).collect())
                .unwrap_or_default(),
            routed_adapters: Vec::new(),
            real_executables: HashMap::new(),
            adapter_versions: HashMap::new(),
            effective_paths: HashMap::new(),
            abstentions: vec!["routing disabled".to_owned()],
            override_reasons: vec!["routing disabled".to_owned()],
            provenance: provenance::process_report(),
        });
    }
    let root = open_root(config)?;
    let repository = Repository::discover(&env::current_dir()?, &root)?;
    let details = status_adapter_details(config, &root, repository.as_ref())?;
    let mut activation = install::activation_audit(&intercept);
    let classifications = classify_activation(config, &mut activation);
    let routed_adapters = enabled_adapter_names(config)
        .into_iter()
        .filter(|name| {
            name == "temp"
                || (details.applicable_adapters.contains(name)
                    && activation.adapter_routed(name)
                    && classifications.iter().any(|classification| {
                        classification.adapter == *name && classification.state == "eligible"
                    })
                    && !activation.entrypoints.iter().any(|entry| {
                        entry.adapters.contains(name)
                            && entry
                                .classifications
                                .contains(&"explicit_override".to_owned())
                    })
                    && !details
                        .override_reasons
                        .iter()
                        .any(|reason| reason.starts_with(&format!("{name}:"))))
        })
        .collect();
    Ok(StatusReport {
        enabled: true,
        configured_root: config.root.clone(),
        root_valid: true,
        platform: Some(root.platform),
        domain_id: Some(root.domain_id),
        physical_root_id: Some(root.marker.root_id),
        worktree: repository.as_ref().map(|repo| repo.worktree.clone()),
        worktree_cache: repository.map(|repo| repo.cache_dir),
        routing_complete: activation.healthy(),
        intercept_directory: intercept,
        path_entries: env::var_os("PATH")
            .map(|path| env::split_paths(&path).collect())
            .unwrap_or_default(),
        routed_adapters,
        real_executables: details.real_executables,
        adapter_versions: details.adapter_versions,
        effective_paths: details.effective_paths,
        abstentions: details.abstentions,
        override_reasons: details.override_reasons,
        provenance: provenance::process_report(),
    })
}

fn status_adapter_details(
    config: &Config,
    root: &RootHandle,
    repository: Option<&Repository>,
) -> Result<AdapterStatusDetails> {
    let mut real_executables = HashMap::new();
    let mut adapter_versions = HashMap::new();
    let mut effective_paths = HashMap::new();
    let mut abstentions = Vec::new();
    let mut override_reasons = Vec::new();
    let mut applicable_adapters = HashSet::new();
    let current_dir = env::current_dir()?;
    let inherited: HashMap<String, String> = env::vars().collect();
    for adapter in [
        Adapter::Cargo,
        Adapter::Sccache,
        Adapter::Go,
        Adapter::Npm,
        Adapter::Pnpm,
        Adapter::Uv,
        Adapter::Pip,
        Adapter::Ccache,
        Adapter::Zig,
        Adapter::Meson,
        Adapter::Bun,
        Adapter::Yarn,
        Adapter::Temp,
    ] {
        let name = format!("{adapter:?}").to_lowercase();
        if !adapter_enabled(config, adapter) {
            abstentions.push(format!("{name}: disabled by configuration"));
            continue;
        }
        if let Some(program) = adapter.default_program() {
            let intercept = install::intercept_target(&install::default_intercept_dir(), program);
            let real = if adapter == Adapter::Cargo {
                config
                    .cargo
                    .real_path
                    .clone()
                    .filter(|path| path.is_file())
                    .or_else(|| cargo_intercept::resolve_real_command(program, &intercept).ok())
            } else {
                cargo_intercept::resolve_real_command(program, &intercept).ok()
            };
            if real.is_none() {
                abstentions.push(format!("{name}: executable not found"));
            }
            let version = real.as_ref().and_then(|program| {
                Command::new(program)
                    .args(adapter.version_args())
                    .output()
                    .ok()
                    .filter(|output| output.status.success())
                    .map(|output| {
                        String::from_utf8_lossy(&output.stdout)
                            .lines()
                            .next()
                            .unwrap_or_default()
                            .trim()
                            .to_owned()
                    })
                    .filter(|value| !value.is_empty())
            });
            adapter_versions.insert(name.clone(), version);
            let applicable = real.as_deref().is_some_and(|real| match adapter {
                Adapter::Meson => meson_version_at_least(real, program, &[], 1, 3),
                Adapter::Bun => program_version_at_least(real, 1, 0),
                Adapter::Yarn => yarn_is_classic(real, program, &[]),
                _ => true,
            });
            if applicable {
                applicable_adapters.insert(name.clone());
            } else if real.is_some() {
                abstentions.push(format!(
                    "{name}: installed version is unsupported or ambiguous"
                ));
            }
            real_executables.insert(name.clone(), real);
        }
        if adapter.default_program().is_some() && !applicable_adapters.contains(&name) {
            effective_paths.insert(name, Vec::new());
            continue;
        }
        if let Some(repository) = repository {
            let context = AdapterContext {
                worktree_cache: repository.cache_dir.clone(),
                shared_cache: root.shared(),
                domain_id: root.domain_id.clone(),
                inherited: inherited.clone(),
            };
            let defaults = adapter.environment(&AdapterContext {
                worktree_cache: repository.cache_dir.clone(),
                shared_cache: root.shared(),
                domain_id: root.domain_id.clone(),
                inherited: HashMap::new(),
            });
            let inherited_defaults = adapter.environment(&context);
            for variable in defaults.keys() {
                if !inherited_defaults.contains_key(variable) && inherited.contains_key(variable) {
                    override_reasons.push(format!(
                        "{name}:{variable}: inherited native environment override"
                    ));
                }
            }
            let filtered = if let Some(real) = real_executables
                .get(&name)
                .and_then(|program| program.as_deref())
            {
                filtered_adapter_values(
                    adapter,
                    &context,
                    real,
                    adapter.default_program().unwrap_or_default(),
                    &[],
                    &current_dir,
                )
            } else {
                inherited_defaults.clone()
            };
            for variable in inherited_defaults.keys() {
                if !filtered.contains_key(variable) {
                    override_reasons.push(format!(
                        "{name}:{variable}: persistent native configuration or adapter applicability"
                    ));
                }
            }
            let mut paths = filtered
                .values()
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .collect::<Vec<_>>();
            paths.sort();
            paths.dedup();
            effective_paths.insert(name, paths);
        }
    }
    if [
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET_DIR",
        "CARGO_BUILD_BUILD_DIR",
    ]
    .iter()
    .any(|name| env::var_os(name).is_some())
    {
        let reason = "cargo: inherited explicit build or target directory".to_owned();
        abstentions.push(reason.clone());
        override_reasons.push(reason);
    }
    override_reasons.sort();
    override_reasons.dedup();
    Ok(AdapterStatusDetails {
        real_executables,
        adapter_versions,
        effective_paths,
        abstentions,
        override_reasons,
        applicable_adapters,
    })
}

fn doctor(config: &Config, config_path: Option<&Path>, json: bool) -> Result<i32> {
    let mut checks = Vec::new();
    let config_ok = config.validate().is_ok();
    checks.push(serde_json::json!({"name":"config","ok":config_ok,"path":config_path}));
    let (root_check, root_ok) = if config.enabled {
        match open_root(config) {
            Ok(root) => (
                serde_json::json!({"name":"root","ok":true,"path":root.root}),
                true,
            ),
            Err(error) => (
                serde_json::json!({"name":"root","ok":false,"error":format!("{error:#}")}),
                false,
            ),
        }
    } else {
        (
            serde_json::json!({"name":"root","ok":true,"disabled":true}),
            true,
        )
    };
    checks.push(root_check);
    let mut activation = install::activation_audit(&install::default_intercept_dir());
    let classifications = classify_activation(config, &mut activation);
    let activation_ok = !config.enabled || activation.healthy();
    checks.push(serde_json::json!({
        "name":"intercept-path",
        "ok":!config.enabled || activation.path_state == "active",
        "state":activation.path_state,
        "occurrences":activation.path_occurrences,
    }));
    checks.push(serde_json::json!({
        "name":"entrypoint-activation",
        "ok":activation_ok,
        "mandatory_failures":activation.entrypoints.iter().filter(|entry| entry.mandatory && !entry.ok).count(),
    }));
    let (status, status_ok) = match status_report(config) {
        Ok(report) => (serde_json::to_value(report).unwrap_or_default(), true),
        Err(error) => (serde_json::json!({"error":format!("{error:#}")}), false),
    };
    checks.push(serde_json::json!({"name":"status-report","ok":status_ok}));
    print_value(
        json,
        &serde_json::json!({
            "checks":checks,
            "activation":activation,
            "adapter_classifications":classifications,
            "status":status,
        }),
    )?;
    Ok(if config_ok && root_ok && activation_ok && status_ok {
        0
    } else {
        1
    })
}

fn classify_activation(
    config: &Config,
    audit: &mut install::ActivationAudit,
) -> Vec<AdapterActivationClassification> {
    let adapters = [
        Adapter::Cargo,
        Adapter::Sccache,
        Adapter::Go,
        Adapter::Npm,
        Adapter::Pnpm,
        Adapter::Uv,
        Adapter::Pip,
        Adapter::Ccache,
        Adapter::Zig,
        Adapter::Meson,
        Adapter::Bun,
        Adapter::Yarn,
    ];
    let mut classifications = Vec::new();
    for adapter in adapters {
        let name = format!("{adapter:?}").to_lowercase();
        let enabled = config.enabled && adapter_enabled(config, adapter);
        let real = audit
            .entrypoints
            .iter()
            .find(|entry| entry.command == adapter.default_program().unwrap_or_default())
            .and_then(|entry| entry.real_executable.as_deref());
        let installed = real.is_some();
        let supported = real.is_some_and(|real| match adapter {
            Adapter::Meson => meson_version_at_least(real, "meson", &[], 1, 3),
            Adapter::Bun => program_version_at_least(real, 1, 0),
            Adapter::Yarn => yarn_is_classic(real, "yarn", &[]),
            _ => true,
        });
        let explicit_override = match adapter {
            Adapter::Cargo => config.cargo.real_path.clone(),
            _ => None,
        };
        let override_valid = explicit_override.as_ref().is_none_or(|path| path.is_file());
        let (state, detail) = if !enabled {
            (
                "intentional_abstention",
                Some("adapter is disabled by configuration".to_owned()),
            )
        } else if explicit_override.is_some() && !override_valid {
            (
                "invalid_override",
                Some("the explicit real executable does not exist".to_owned()),
            )
        } else if !installed {
            (
                "absent",
                Some("default executable is not installed".to_owned()),
            )
        } else if !supported {
            (
                "unsupported_version",
                Some("installed version is unsupported or ambiguous".to_owned()),
            )
        } else if explicit_override.is_some() {
            (
                "explicit_override",
                Some("routing uses an explicit real executable".to_owned()),
            )
        } else {
            ("eligible", None)
        };
        classifications.push(AdapterActivationClassification {
            adapter: name,
            state: state.to_owned(),
            enabled,
            installed,
            supported,
            explicit_override,
            detail,
        });
    }

    for entry in &mut audit.entrypoints {
        let relevant: Vec<&AdapterActivationClassification> = classifications
            .iter()
            .filter(|classification| entry.adapters.contains(&classification.adapter))
            .collect();
        entry.classifications = relevant
            .iter()
            .map(|classification| classification.state.clone())
            .collect();
        entry.classifications.sort();
        entry.classifications.dedup();
        if matches!(
            entry.state.as_str(),
            "stale_intercept"
                | "stale_intercept_precedence"
                | "duplicate_intercept_path"
                | "unowned_intercept"
                | "recursive"
        ) {
            entry.mandatory = true;
            entry.ok = false;
            continue;
        }
        if entry.command == "rustup" {
            if let Some(override_path) = env::var_os("DEV_CACHE_REAL_RUSTUP").map(PathBuf::from) {
                entry.classifications.push("explicit_override".to_owned());
                if !override_path.is_file() {
                    entry.state = "invalid_override".to_owned();
                    entry.detail = Some("DEV_CACHE_REAL_RUSTUP does not name a file".to_owned());
                    entry.mandatory = true;
                    entry.ok = false;
                    continue;
                }
            }
        }
        if relevant
            .iter()
            .any(|classification| classification.state == "invalid_override")
        {
            entry.state = "invalid_override".to_owned();
            entry.mandatory = entry.installed;
            entry.ok = !entry.mandatory;
            continue;
        }
        let eligible = relevant.iter().any(|classification| {
            matches!(
                classification.state.as_str(),
                "eligible" | "explicit_override"
            )
        });
        if entry.installed && !eligible {
            let classification = relevant
                .iter()
                .find(|classification| classification.state == "unsupported_version")
                .or_else(|| {
                    relevant
                        .iter()
                        .find(|classification| classification.state == "intentional_abstention")
                })
                .map(|classification| classification.state.as_str())
                .unwrap_or("intentional_abstention");
            entry.state = classification.to_owned();
            entry.mandatory = false;
            entry.ok = true;
        } else {
            entry.mandatory = entry.installed && eligible;
            if !entry.mandatory && entry.state == "absent" {
                entry.ok = true;
            }
        }
    }
    classifications
}

fn enabled_adapter_names(config: &Config) -> Vec<String> {
    [
        Adapter::Cargo,
        Adapter::Sccache,
        Adapter::Go,
        Adapter::Npm,
        Adapter::Pnpm,
        Adapter::Uv,
        Adapter::Pip,
        Adapter::Ccache,
        Adapter::Zig,
        Adapter::Meson,
        Adapter::Bun,
        Adapter::Yarn,
    ]
    .into_iter()
    .filter(|adapter| adapter_enabled(config, *adapter))
    .map(|adapter| format!("{adapter:?}").to_lowercase())
    .collect()
}

fn report(config: &Config, json: bool) -> Result<i32> {
    let root = open_root(config)?;
    let report = serde_json::json!({
        "root": root.root,
        "platform": root.platform,
        "bytes": directory_size(&root.platform_root),
        "free_bytes": fs2::available_space(&root.root)?,
        "repos_bytes": directory_size(&root.repos()),
        "shared_bytes": directory_size(&root.shared()),
        "artifacts_bytes": directory_size(&root.artifacts()),
    });
    print_value(json, &report)?;
    Ok(0)
}

fn path_command(
    config: &Config,
    adapter: Adapter,
    repo_path: Option<&Path>,
    json: bool,
) -> Result<i32> {
    let root = open_root(config)?;
    let path = adapter_path(&root, adapter, repo_path)?;
    if json {
        print_value(true, &serde_json::json!({"adapter":adapter,"path":path}))?;
    } else {
        println!("{}", path.display());
    }
    Ok(0)
}

fn adapter_path(root: &RootHandle, adapter: Adapter, repo_path: Option<&Path>) -> Result<PathBuf> {
    let repository = if matches!(adapter, Adapter::Temp) {
        Some(
            Repository::discover(repo_path.unwrap_or(&env::current_dir()?), root)?
                .context("resolve workspace scope")?,
        )
    } else {
        None
    };
    Ok(match adapter {
        Adapter::Cargo => root
            .shared()
            .join("cargo/intermediate/{workspace-path-hash}"),
        Adapter::Temp => repository
            .context("temp adapter requires repository context")?
            .cache_dir
            .join("temp/generic"),
        Adapter::Sccache => root.shared().join("sccache"),
        Adapter::Go => root.shared().join("go-build"),
        Adapter::Npm => root.shared().join("npm"),
        Adapter::Pnpm => root.shared().join("pnpm-store"),
        Adapter::Uv => root.shared().join("uv"),
        Adapter::Pip => root.shared().join("pip"),
        Adapter::Ccache => root.shared().join("ccache"),
        Adapter::Zig => root.shared().join("zig"),
        Adapter::Meson => root.shared().join("meson/packages"),
        Adapter::Bun => root.shared().join("bun/install"),
        Adapter::Yarn => root.shared().join("yarn/classic"),
    })
}

fn exec_command(config: &Config, args: ExecArgs) -> Result<i32> {
    ensure_adapter_enabled(config, args.adapter)?;
    let root = open_root(config)?;
    let repository = Repository::discover(&env::current_dir()?, &root)?
        .context("resolve current workspace scope")?;
    let lease = RootLease::shared(&root, &format!("exec:{:?}", args.adapter))?;
    let mut environment = adapter_environment(&root, &repository, args.adapter)?;
    if args.adapter == Adapter::Cargo && config.sccache.enabled {
        environment.extend(adapter_environment(&root, &repository, Adapter::Sccache)?);
        if let Some(size) = &config.sccache.cache_size {
            environment
                .entry("SCCACHE_CACHE_SIZE".to_owned())
                .or_insert_with(|| size.clone());
        }
    }
    let (program, program_args) = args.program.split_first().context("missing program")?;
    let resolved_program = if args.adapter == Adapter::Cargo
        && Path::new(program)
            .file_stem()
            .is_some_and(|stem| stem.to_string_lossy().eq_ignore_ascii_case("cargo"))
    {
        cargo_intercept::resolve_real_cargo(config, &env::current_exe()?)?.into_os_string()
    } else {
        program.clone()
    };
    let status = Command::new(&resolved_program)
        .args(program_args)
        .envs(environment)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("run {}", Path::new(&resolved_program).display()))?;
    let code = status.code().unwrap_or(1);
    drop(lease);
    maybe_automatic_gc(&root, config);
    Ok(code)
}

fn adapter_environment(
    root: &RootHandle,
    repository: &Repository,
    adapter: Adapter,
) -> Result<HashMap<String, String>> {
    let values = adapter_values(root, repository, adapter);
    prepare_adapter_environment(root, adapter, &values)?;
    Ok(values)
}

fn adapter_values(
    root: &RootHandle,
    repository: &Repository,
    adapter: Adapter,
) -> HashMap<String, String> {
    let inherited = env::vars().collect();
    let context = AdapterContext {
        worktree_cache: repository.cache_dir.clone(),
        shared_cache: root.shared(),
        domain_id: root.domain_id.clone(),
        inherited,
    };
    let mut values = adapter.environment(&context);
    provenance::attach(
        &context.inherited,
        &mut values,
        &format!("{adapter:?}").to_lowercase(),
    );
    values
}

fn prepare_adapter_environment(
    root: &RootHandle,
    adapter: Adapter,
    values: &HashMap<String, String>,
) -> Result<()> {
    let routed_paths: Vec<PathBuf> = values
        .iter()
        .filter(|(name, _)| name.as_str() != provenance::ENV_NAME)
        .map(|(_, value)| PathBuf::from(value))
        .filter(|path| path.is_absolute())
        .collect();
    for path in &routed_paths {
        if path.to_string_lossy().contains("{workspace-path-hash}") {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
        } else {
            fs::create_dir_all(path)?;
        }
    }
    if adapter.is_shared() {
        let shared = root.shared();
        let mut owned_roots = Vec::new();
        for path in routed_paths.iter().filter(|path| path.starts_with(&shared)) {
            if let Ok(relative) = path.strip_prefix(&shared) {
                if let Some(component) = relative.components().next() {
                    owned_roots.push(shared.join(component.as_os_str()));
                }
            }
        }
        owned_roots.sort();
        owned_roots.dedup();
        for path in owned_roots {
            fs::create_dir_all(&path)?;
            gc::mark_shared_cache(&path, &format!("{adapter:?}"))?;
        }
    }
    Ok(())
}

fn gc_command(config: &Config, args: GcArgs, json: bool) -> Result<i32> {
    if args.automatic && !config.enabled {
        return Ok(0);
    }
    let root = open_root(config)?;
    if args.automatic {
        if !config.maintenance.automatic {
            return Ok(0);
        }
        let marker = root.control().join("last-automatic-gc.json");
        if let Ok(value) = fs::read(&marker).and_then(|bytes| {
            serde_json::from_slice::<serde_json::Value>(&bytes).map_err(std::io::Error::other)
        }) {
            if value["unix"].as_u64().is_some_and(|last| {
                now_unix().saturating_sub(last) < config.maintenance.interval_hours * 3_600
            }) {
                return Ok(0);
            }
        }
        let report = gc::collect(
            &root,
            &config.gc,
            config.artifacts.stale_after_days,
            &GcOverrides::default(),
            true,
        )?;
        write_json_atomic(&marker, &serde_json::json!({"unix":now_unix()}))?;
        if json {
            print_value(true, &report)?;
        }
        return Ok(0);
    }
    let overrides = GcOverrides {
        max_bytes: args.max_bytes,
        min_free_bytes: args.min_free_bytes,
        target_free_bytes: args.target_free_bytes,
        stale_after_days: args.stale_after_days,
    };
    let report = gc::collect(
        &root,
        &config.gc,
        config.artifacts.stale_after_days,
        &overrides,
        args.apply,
    )?;
    print_value(json, &report)?;
    Ok(0)
}

fn artifact_command(config: &Config, command: ArtifactCommand, json: bool) -> Result<i32> {
    if !config.artifacts.enabled {
        bail!("artifact CAS is disabled");
    }
    let root = open_root(config)?;
    match command {
        ArtifactCommand::Put { source } => print_value(json, &artifacts::put(&root, &source)?)?,
        ArtifactCommand::Get {
            digest,
            destination,
        } => print_value(json, &artifacts::get(&root, &digest, &destination)?)?,
        ArtifactCommand::List => print_value(json, &artifacts::list(&root)?)?,
        ArtifactCommand::Verify { digest } => {
            print_value(json, &artifacts::verify(&root, digest.as_deref())?)?
        }
        ArtifactCommand::Remove { digest } => {
            artifacts::remove(&root, &digest)?;
            print_value(json, &serde_json::json!({"removed":digest}))?;
        }
    }
    Ok(0)
}

fn migrate_command(config: &Config, args: MigrateArgs, json: bool) -> Result<i32> {
    let root = open_root(config)?;
    let repository = if matches!(args.adapter, Adapter::Temp) {
        Repository::discover(args.repo.as_deref().unwrap_or(&env::current_dir()?), &root)?
    } else {
        None
    };
    let report = migrate::migrate_resource(
        &root,
        repository.as_ref(),
        args.adapter,
        args.resource.as_deref(),
        &args.source,
        args.apply,
        args.remove_source,
    )?;
    print_value(json, &report)?;
    Ok(0)
}

fn run_adapter_intercept(adapter: Adapter, command: &str, args: Vec<OsString>) -> Result<i32> {
    let (config, _) = Config::load(None)?;
    let current_exe = env::current_exe()?;
    let real = cargo_intercept::resolve_real_command(command, &current_exe)?;
    let help = cargo_intercept::is_help_request(args.iter().map(|arg| arg.to_string_lossy()));
    let informational = help || cargo_intercept::is_version_request(&args);
    if informational || !config.enabled {
        let help_status = if config.enabled {
            format!("{command} routing configured; no cache paths opened for help/version")
        } else {
            "routing disabled".to_owned()
        };
        let prefix = help.then(|| cargo_help_prefix(&help_status));
        return cargo_intercept::delegate(&real, &args, &[], prefix.as_deref());
    }
    let compiler_intercept = matches!(command, "cc" | "c++" | "gcc" | "g++" | "clang" | "clang++");
    if compiler_intercept && env::var_os("CCACHE_DISABLE").is_some() {
        return cargo_intercept::delegate(&real, &args, &[], None);
    }
    if adapter == Adapter::Meson && !meson_version_at_least(&real, command, &args, 1, 3) {
        return cargo_intercept::delegate(&real, &args, &[], None);
    }
    if adapter == Adapter::Bun && !program_version_at_least(&real, 1, 0) {
        return cargo_intercept::delegate(&real, &args, &[], None);
    }
    if !adapter_enabled(&config, adapter) {
        return cargo_intercept::delegate(&real, &args, &[], None);
    }
    let current_dir = env::current_dir()?;
    let preview_context = AdapterContext {
        worktree_cache: preview_root().join("workspace"),
        shared_cache: preview_root().join("cache"),
        domain_id: "preview".to_owned(),
        inherited: env::vars().collect(),
    };
    let preview = filtered_adapter_values(
        adapter,
        &preview_context,
        &real,
        command,
        &args,
        &current_dir,
    );
    if preview.is_empty() {
        if compiler_intercept {
            let ccache = cargo_intercept::resolve_real_command("ccache", &current_exe)?;
            let mut delegated = Vec::with_capacity(args.len() + 1);
            delegated.push(real.into_os_string());
            delegated.extend(args);
            return cargo_intercept::delegate(&ccache, &delegated, &[], None);
        }
        return cargo_intercept::delegate(&real, &args, &[], None);
    }
    let root = open_root(&config)?;
    let workspace =
        Repository::discover(&current_dir, &root)?.context("resolve current workspace scope")?;
    let lease = RootLease::shared(&root, &format!("intercept:{command}"))?;
    let context = AdapterContext {
        worktree_cache: workspace.cache_dir.clone(),
        shared_cache: root.shared(),
        domain_id: root.domain_id.clone(),
        inherited: env::vars().collect(),
    };
    let mut environment =
        filtered_adapter_values(adapter, &context, &real, command, &args, &current_dir);
    provenance::attach(
        &context.inherited,
        &mut environment,
        &format!("{adapter:?}").to_lowercase(),
    );
    prepare_adapter_environment(&root, adapter, &environment)?;
    let routed: Vec<(String, String)> = environment.into_iter().collect();
    let code = if compiler_intercept {
        let ccache = cargo_intercept::resolve_real_command("ccache", &current_exe)?;
        let mut delegated = Vec::with_capacity(args.len() + 1);
        delegated.push(real.into_os_string());
        delegated.extend(args);
        cargo_intercept::delegate(&ccache, &delegated, &routed, None)?
    } else {
        cargo_intercept::delegate(&real, &args, &routed, None)?
    };
    drop(lease);
    maybe_automatic_gc(&root, &config);
    Ok(code)
}

fn preview_root() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\dev-cache-preview")
    } else {
        PathBuf::from("/dev-cache-preview")
    }
}

fn filtered_adapter_values(
    adapter: Adapter,
    context: &AdapterContext,
    real: &Path,
    command: &str,
    args: &[OsString],
    current_dir: &Path,
) -> HashMap<String, String> {
    let mut environment = adapter.environment(context);
    if adapter == Adapter::Uv && !program_version_at_least(real, 0, 7) {
        environment.remove("UV_PYTHON_CACHE_DIR");
    }
    if adapter == Adapter::Yarn && !yarn_is_classic(real, command, args) {
        environment.remove("YARN_CACHE_FOLDER");
    }
    apply_native_cli_overrides(adapter, command, args, &mut environment);
    apply_persistent_overrides(adapter, real, current_dir, &mut environment);
    environment
}

fn apply_persistent_overrides(
    adapter: Adapter,
    real: &Path,
    current_dir: &Path,
    environment: &mut HashMap<String, String>,
) {
    match adapter {
        Adapter::Go => {
            let goenv = Command::new(real)
                .args(["env", "GOENV"])
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .map(|value| PathBuf::from(value.trim()));
            if let Some(contents) = goenv
                .filter(|path| path.is_file())
                .and_then(|path| fs::read_to_string(path).ok())
            {
                for (key, variable) in [
                    ("GOCACHE", "GOCACHE"),
                    ("GOMODCACHE", "GOMODCACHE"),
                    ("GOTMPDIR", "GOTMPDIR"),
                ] {
                    if config_line_present(&contents, key) {
                        environment.remove(variable);
                    }
                }
            }
        }
        Adapter::Npm | Adapter::Pnpm => {
            for path in ancestor_config_files(current_dir, ".npmrc")
                .into_iter()
                .chain(std::iter::once(crate::config::home_dir().join(".npmrc")))
            {
                let Ok(contents) = fs::read_to_string(path) else {
                    continue;
                };
                if config_line_present(&contents, "cache") {
                    environment.remove("npm_config_cache");
                    environment.remove("pnpm_config_cache_dir");
                }
                if config_line_present(&contents, "store-dir")
                    || config_line_present(&contents, "store_dir")
                    || config_line_present(&contents, "use-running-store-server")
                    || config_line_present(&contents, "use-store-server")
                {
                    environment.remove("pnpm_config_store_dir");
                }
            }
        }
        Adapter::Pip => {
            let candidates = [
                env::var_os("PIP_CONFIG_FILE").map(PathBuf::from),
                Some(crate::config::home_dir().join(".config/pip/pip.conf")),
                Some(crate::config::home_dir().join(".pip/pip.conf")),
            ];
            if candidates.into_iter().flatten().any(|path| {
                fs::read_to_string(path)
                    .ok()
                    .is_some_and(|contents| config_line_present(&contents, "cache-dir"))
            }) {
                environment.remove("PIP_CACHE_DIR");
            }
        }
        Adapter::Uv => {
            let mut candidates = Vec::new();
            for ancestor in current_dir.ancestors() {
                candidates.push((ancestor.join("uv.toml"), false));
                candidates.push((ancestor.join("pyproject.toml"), true));
            }
            candidates.push((crate::config::home_dir().join(".config/uv/uv.toml"), false));
            let configured = candidates.into_iter().any(|(path, pyproject)| {
                let Ok(contents) = fs::read_to_string(path) else {
                    return false;
                };
                let Ok(value) = toml::from_str::<toml::Value>(&contents) else {
                    return true;
                };
                let table = if pyproject {
                    value
                        .get("tool")
                        .and_then(|tool| tool.get("uv"))
                        .and_then(toml::Value::as_table)
                } else {
                    value.as_table()
                };
                table.is_some_and(|table| table.contains_key("cache-dir"))
            });
            if configured {
                environment.remove("UV_CACHE_DIR");
            }
        }
        Adapter::Ccache => {
            let path = env::var_os("CCACHE_CONFIGPATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| crate::config::home_dir().join(".config/ccache/ccache.conf"));
            if let Ok(contents) = fs::read_to_string(path) {
                if config_line_present(&contents, "cache_dir") {
                    environment.remove("CCACHE_DIR");
                }
                if config_line_present(&contents, "temporary_dir") {
                    environment.remove("CCACHE_TEMPDIR");
                }
            }
        }
        Adapter::Sccache if sccache_remote_or_disabled() => {
            environment.remove("SCCACHE_DIR");
        }
        Adapter::Bun => {
            let configured = ancestor_config_files(current_dir, "bunfig.toml")
                .into_iter()
                .chain(std::iter::once(
                    crate::config::home_dir().join(".bunfig.toml"),
                ))
                .any(|path| match fs::read_to_string(&path) {
                    Ok(contents) => toml::from_str::<toml::Value>(&contents)
                        .map(|value| toml_contains_normalized_key(&value, "globalstore"))
                        .unwrap_or(true),
                    Err(_) => path.exists(),
                });
            if configured {
                environment.remove("BUN_INSTALL_CACHE_DIR");
            }
        }
        Adapter::Yarn => {
            let configured = ancestor_config_files(current_dir, ".yarnrc")
                .into_iter()
                .chain(ancestor_config_files(current_dir, ".yarnrc.yml"))
                .chain(std::iter::once(crate::config::home_dir().join(".yarnrc")))
                .chain(std::iter::once(
                    crate::config::home_dir().join(".yarnrc.yml"),
                ))
                .filter_map(|path| fs::read_to_string(path).ok())
                .any(|contents| {
                    config_line_present(&contents, "cache-folder")
                        || config_line_present(&contents, "cacheFolder")
                        || config_line_present(&contents, "enableGlobalCache")
                });
            if configured {
                environment.remove("YARN_CACHE_FOLDER");
            }
        }
        _ => {}
    }
}

fn toml_contains_normalized_key(value: &toml::Value, desired: &str) -> bool {
    match value {
        toml::Value::Table(table) => table.iter().any(|(key, child)| {
            key.to_ascii_lowercase().replace(['-', '_', ' '], "") == desired
                || toml_contains_normalized_key(child, desired)
        }),
        toml::Value::Array(values) => values
            .iter()
            .any(|child| toml_contains_normalized_key(child, desired)),
        _ => false,
    }
}

fn sccache_remote_or_disabled() -> bool {
    [
        "SCCACHE_BUCKET",
        "SCCACHE_ENDPOINT",
        "SCCACHE_REDIS",
        "SCCACHE_MEMCACHED",
        "SCCACHE_GCS_BUCKET",
        "SCCACHE_AZURE_CONNECTION_STRING",
        "SCCACHE_DISABLE",
    ]
    .iter()
    .any(|name| env::var_os(name).is_some())
}

fn ancestor_config_files(start: &Path, name: &str) -> Vec<PathBuf> {
    start
        .ancestors()
        .map(|ancestor| ancestor.join(name))
        .collect()
}

fn config_line_present(contents: &str, key: &str) -> bool {
    contents.lines().any(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            return false;
        }
        line.split_once(['=', ':'])
            .is_some_and(|(candidate, _)| candidate.trim().eq_ignore_ascii_case(key))
    })
}

fn program_version_at_least(program: &Path, required_major: u64, required_minor: u64) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|output| parse_program_version(&output))
        .is_some_and(|(major, minor)| {
            major > required_major || (major == required_major && minor >= required_minor)
        })
}

fn meson_version_at_least(
    program: &Path,
    command: &str,
    args: &[OsString],
    required_major: u64,
    required_minor: u64,
) -> bool {
    let output = if command.starts_with("python") {
        Command::new(program)
            .args(["-m", "mesonbuild.mesonmain", "--version"])
            .output()
    } else {
        Command::new(program).arg("--version").output()
    };
    let _ = args;
    output
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|output| parse_program_version(&output))
        .is_some_and(|(major, minor)| {
            major > required_major || (major == required_major && minor >= required_minor)
        })
}

fn yarn_is_classic(program: &Path, command: &str, args: &[OsString]) -> bool {
    let output = if command == "corepack" {
        let Some(manager) = args.first() else {
            return false;
        };
        Command::new(program).arg(manager).arg("--version").output()
    } else {
        Command::new(program).arg("--version").output()
    };
    output
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|output| parse_program_version(&output))
        .is_some_and(|(major, _)| major < 2)
}

fn parse_program_version(output: &str) -> Option<(u64, u64)> {
    output.split_whitespace().find_map(|token| {
        let token = token.trim_start_matches(|character: char| !character.is_ascii_digit());
        let mut parts = token.split('.');
        Some((
            parts.next()?.parse::<u64>().ok()?,
            parts.next()?.parse::<u64>().ok()?,
        ))
    })
}

fn apply_native_cli_overrides(
    adapter: Adapter,
    command: &str,
    args: &[OsString],
    environment: &mut HashMap<String, String>,
) {
    let (command, args) = nested_command(command, args);
    let has = |names: &[&str]| {
        args.iter()
            .take_while(|arg| *arg != OsStr::new("--"))
            .any(|arg| {
                let arg = arg.to_string_lossy();
                names
                    .iter()
                    .any(|name| arg == *name || arg.starts_with(&format!("{name}=")))
            })
    };
    match adapter {
        Adapter::Npm if has(&["--cache"]) => {
            environment.remove("npm_config_cache");
        }
        Adapter::Pnpm => {
            if command == "pnpx"
                || args.first().is_some_and(|arg| arg == "dlx")
                || has(&["--use-running-store-server", "--use-store-server"])
            {
                environment.remove("pnpm_config_store_dir");
            }
            if has(&["--store-dir"]) {
                environment.remove("pnpm_config_store_dir");
            }
            if has(&["--cache-dir"]) {
                environment.remove("pnpm_config_cache_dir");
            }
        }
        Adapter::Uv => {
            if has(&["--no-cache"]) {
                environment.remove("UV_CACHE_DIR");
                environment.remove("UV_PYTHON_CACHE_DIR");
            } else if has(&["--cache-dir"]) {
                environment.remove("UV_CACHE_DIR");
            }
        }
        Adapter::Pip => {
            if has(&["--no-cache-dir", "--cache-dir"]) {
                environment.remove("PIP_CACHE_DIR");
            }
        }
        Adapter::Ccache if command == "ccache" && has(&["--set-config", "-o"]) => {
            environment.remove("CCACHE_DIR");
            environment.remove("CCACHE_TEMPDIR");
        }
        Adapter::Zig => {
            if has(&["--global-cache-dir"]) {
                environment.remove("ZIG_GLOBAL_CACHE_DIR");
            }
            if has(&["--cache-dir"]) {
                environment.remove("ZIG_LOCAL_CACHE_DIR");
            }
        }
        Adapter::Bun => {
            if has(&["--global", "-g"]) {
                environment.remove("BUN_INSTALL_CACHE_DIR");
            }
        }
        Adapter::Yarn if has(&["--cache-folder"]) => {
            environment.remove("YARN_CACHE_FOLDER");
        }
        _ => {}
    }
}

fn nested_command<'a>(command: &'a str, args: &'a [OsString]) -> (&'a str, &'a [OsString]) {
    if command != "corepack" {
        return (command, args);
    }
    let Some(manager) = args.first().and_then(|value| value.to_str()) else {
        return (command, args);
    };
    (manager, &args[1..])
}

fn run_cargo(args: Vec<OsString>) -> Result<i32> {
    let (config, _) = Config::load(None)?;
    let current_exe = env::current_exe()?;
    let real = cargo_intercept::resolve_real_cargo(&config, &current_exe)?;
    let help = cargo_intercept::is_help_request(args.iter().map(|arg| arg.to_string_lossy()));
    let informational = help || cargo_intercept::is_version_request(&args);
    let supports_build_dir =
        !informational && cargo_intercept::cargo_supports_build_dir(&real, &args);
    let routing = cargo_routing(&config, &args, informational, supports_build_dir)?;
    let prefix = help.then(|| cargo_help_prefix(&routing.status));
    let code = cargo_intercept::delegate(&real, &args, &routing.environment, prefix.as_deref())?;
    finish_cargo_routing(routing, &config);
    Ok(code)
}

fn run_rustup(args: Vec<OsString>) -> Result<i32> {
    let (config, _) = Config::load(None)?;
    let current_exe = env::current_exe()?;
    let real = cargo_intercept::resolve_real_rustup(&current_exe)?;
    let Some(cargo_args) = cargo_intercept::rustup_cargo_args(&args) else {
        return cargo_intercept::delegate(&real, &args, &[], None);
    };
    let help = cargo_intercept::is_help_request(cargo_args.iter().map(|arg| arg.to_string_lossy()));
    let informational = help || cargo_intercept::is_version_request(cargo_args);
    let supports_build_dir =
        !informational && cargo_intercept::rustup_cargo_supports_build_dir(&real, &args);
    let routing = cargo_routing(&config, cargo_args, informational, supports_build_dir)?;
    let prefix = help.then(|| cargo_help_prefix(&routing.status));
    let code = cargo_intercept::delegate(&real, &args, &routing.environment, prefix.as_deref())?;
    finish_cargo_routing(routing, &config);
    Ok(code)
}

struct CargoRouting {
    environment: Vec<(String, String)>,
    status: String,
    lease: Option<RootLease>,
    maintenance_root: Option<RootHandle>,
}

fn cargo_routing(
    config: &Config,
    args: &[OsString],
    help: bool,
    supports_build_dir: bool,
) -> Result<CargoRouting> {
    let mut routed = Vec::new();
    let mut status = "routing disabled".to_owned();
    let mut lease = None;
    let mut maintenance_root = None;
    let explicit_layout = env::var_os("CARGO_TARGET_DIR").is_some()
        || env::var_os("CARGO_BUILD_TARGET_DIR").is_some()
        || env::var_os("CARGO_BUILD_BUILD_DIR").is_some()
        || cargo_intercept::has_explicit_target_dir(args)
        || cargo_intercept::has_explicit_config(args);
    if config.enabled && config.cargo.enabled && !explicit_layout && !supports_build_dir && !help {
        let current_dir = env::current_dir()?;
        let repository_start = cargo_intercept::repository_start(args, &current_dir);
        match cargo_intercept::persistent_layout_override(&repository_start) {
            Ok(true) => {
                status = "routing bypassed by persistent Cargo layout configuration".to_owned();
            }
            Err(error) => {
                status = format!(
                    "routing abstained because Cargo configuration is unreadable: {error:#}"
                );
            }
            Ok(false) => {
                let wrapper_is_explicit = cargo_wrapper_is_explicit();
                let persistent_wrapper =
                    cargo_intercept::persistent_compiler_wrapper(&repository_start);
                if config.sccache.enabled
                    && !wrapper_is_explicit
                    && find_on_path("sccache").is_some()
                    && matches!(&persistent_wrapper, Ok(false))
                {
                    let root = open_root(config)?;
                    let repository = Repository::discover(&repository_start, &root)?
                        .context("resolve Cargo workspace scope")?;
                    lease = Some(RootLease::shared(&root, "cargo-sccache")?);
                    let mut environment =
                        adapter_environment(&root, &repository, Adapter::Sccache)?;
                    if let Some(size) = &config.sccache.cache_size {
                        environment
                            .entry("SCCACHE_CACHE_SIZE".to_owned())
                            .or_insert_with(|| size.clone());
                    }
                    environment.insert("RUSTC_WRAPPER".to_owned(), "sccache".to_owned());
                    routed.extend(environment);
                    maintenance_root = Some(root);
                    status = "Cargo is older than 1.91; native target layout preserved and sccache routing is active".to_owned();
                } else if persistent_wrapper.is_err() {
                    status = "routing abstained because Cargo wrapper configuration is unreadable"
                        .to_owned();
                } else {
                    status = "Cargo is older than 1.91; native target layout preserved and sccache injection abstained"
                        .to_owned();
                }
            }
        }
        return Ok(CargoRouting {
            environment: routed,
            status,
            lease,
            maintenance_root,
        });
    }
    if config.enabled && config.cargo.enabled && !explicit_layout && supports_build_dir {
        let current_dir = env::current_dir()?;
        let repository_start = cargo_intercept::repository_start(args, &current_dir);
        match cargo_intercept::persistent_layout_override(&repository_start) {
            Ok(true) => {
                status = "routing bypassed by persistent Cargo layout configuration".to_owned();
                return Ok(CargoRouting {
                    environment: routed,
                    status,
                    lease,
                    maintenance_root,
                });
            }
            Err(error) => {
                status = format!(
                    "routing abstained because Cargo configuration is unreadable: {error:#}"
                );
                return Ok(CargoRouting {
                    environment: routed,
                    status,
                    lease,
                    maintenance_root,
                });
            }
            Ok(false) => {}
        }
        let root = match open_root(config) {
            Ok(root) => root,
            Err(error) if help => {
                return Ok(CargoRouting {
                    environment: routed,
                    status: format!("routing unavailable: {error:#}"),
                    lease,
                    maintenance_root,
                });
            }
            Err(error) => return Err(error),
        };
        if let Some(repository) = Repository::discover(&repository_start, &root)? {
            lease = Some(RootLease::shared(&root, "cargo")?);
            let mut environment = adapter_environment(&root, &repository, Adapter::Cargo)?;
            if config.sccache.enabled {
                environment.extend(adapter_environment(&root, &repository, Adapter::Sccache)?);
                if let Some(size) = &config.sccache.cache_size {
                    environment
                        .entry("SCCACHE_CACHE_SIZE".to_owned())
                        .or_insert_with(|| size.clone());
                }
                let wrapper_is_explicit = cargo_wrapper_is_explicit();
                if !wrapper_is_explicit
                    && find_on_path("sccache").is_some()
                    && matches!(
                        cargo_intercept::persistent_compiler_wrapper(&repository_start),
                        Ok(false)
                    )
                {
                    environment.insert("RUSTC_WRAPPER".to_owned(), "sccache".to_owned());
                }
            }
            status = format!(
                "routing active; workspace={}; build-dir={}",
                repository.worktree.display(),
                root.shared()
                    .join("cargo/intermediate/{workspace-path-hash}")
                    .display()
            );
            routed.extend(environment);
            maintenance_root = Some(root);
        }
    } else if config.enabled && config.cargo.enabled && explicit_layout {
        status = "routing bypassed by explicit Cargo build or target directory".to_owned();
    } else if config.enabled && config.cargo.enabled && !help && !supports_build_dir {
        status = "routing abstained because Cargo is older than 1.91 or its version is unknown"
            .to_owned();
    }
    Ok(CargoRouting {
        environment: routed,
        status,
        lease,
        maintenance_root,
    })
}

fn cargo_wrapper_is_explicit() -> bool {
    [
        "RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "SCCACHE_DISABLE",
    ]
    .iter()
    .any(|name| env::var_os(name).is_some())
}

fn finish_cargo_routing(routing: CargoRouting, config: &Config) {
    drop(routing.lease);
    if let Some(root) = routing.maintenance_root.as_ref() {
        maybe_automatic_gc(root, config);
    }
}

fn cargo_help_prefix(status: &str) -> String {
    let help = Cli::command().render_help().to_string();
    format!("dev-cache: {status}\n\n{help}\n")
}

fn maybe_automatic_gc(root: &RootHandle, config: &Config) {
    if !config.maintenance.automatic {
        return;
    }
    let marker = root.control().join("last-automatic-gc.json");
    if let Ok(value) = fs::read(&marker).and_then(|bytes| {
        serde_json::from_slice::<serde_json::Value>(&bytes).map_err(std::io::Error::other)
    }) {
        if value["unix"].as_u64().is_some_and(|last| {
            now_unix().saturating_sub(last) < config.maintenance.interval_hours * 3_600
        }) {
            return;
        }
    }
    if gc::collect(
        root,
        &config.gc,
        config.artifacts.stale_after_days,
        &GcOverrides::default(),
        true,
    )
    .is_ok()
    {
        let _ = write_json_atomic(&marker, &serde_json::json!({"unix":now_unix()}));
    }
}

fn ensure_adapter_enabled(config: &Config, adapter: Adapter) -> Result<()> {
    if !adapter_enabled(config, adapter) {
        bail!("{adapter:?} adapter is disabled by configuration");
    }
    Ok(())
}

fn adapter_enabled(config: &Config, adapter: Adapter) -> bool {
    match adapter {
        Adapter::Cargo => config.cargo.enabled,
        Adapter::Sccache => config.sccache.enabled,
        Adapter::Go => config.adapters.go,
        Adapter::Npm => config.adapters.npm,
        Adapter::Pnpm => config.adapters.pnpm,
        Adapter::Uv => config.adapters.uv,
        Adapter::Pip => config.adapters.pip,
        Adapter::Ccache => config.adapters.ccache,
        Adapter::Zig => config.adapters.zig,
        Adapter::Meson => config.adapters.meson,
        Adapter::Bun => config.adapters.bun,
        Adapter::Yarn => config.adapters.yarn,
        Adapter::Temp => config.adapters.temp,
    }
}

fn find_on_path(program: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|dir| {
                dir.join(if cfg!(windows) {
                    format!("{program}.exe")
                } else {
                    program.to_owned()
                })
            })
            .find(|candidate| candidate.is_file())
    })
}

fn print_config(config: &Config, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(config)?);
    } else {
        print!("{}", toml::to_string_pretty(config)?);
    }
    Ok(())
}

fn print_value<T: Serialize>(json: bool, value: &T) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        let value = serde_json::to_value(value)?;
        if let Some(object) = value.as_object() {
            for (key, value) in object {
                println!("{key}: {}", display_json(value));
            }
        } else if let Some(array) = value.as_array() {
            for item in array {
                println!("{}", display_json(item));
            }
        } else {
            println!("{}", display_json(&value));
        }
    }
    Ok(())
}

fn display_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}
