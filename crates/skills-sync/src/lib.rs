//! Native implementation of the `skills-sync` command.

mod build_info {
    include!("../../build_info_runtime.rs");
}

use anyhow::{anyhow, Context, Result};
use dev_tools_product::{BuildInfo, ProductId};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const EXIT_USAGE: i32 = 1;
const EXIT_SCHEMA: i32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
enum CommandMode {
    Sync,
    Status,
    Doctor,
    Lock,
    Adopt,
    Help,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LockAction {
    Status,
    Repair,
}

impl LockAction {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Repair => "repair",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Scope {
    Global,
    Project,
    Both,
}

impl Scope {
    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "global" => Ok(Self::Global),
            "project" => Ok(Self::Project),
            "both" => Ok(Self::Both),
            other => Err(anyhow!("unsupported --scope value: {other}")),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Project => "project",
            Self::Both => "both",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ColorMode {
    Auto,
    Always,
    Never,
}

impl ColorMode {
    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "auto" => Ok(Self::Auto),
            "always" | "on" | "yes" | "true" | "1" => Ok(Self::Always),
            "never" | "off" | "no" | "false" | "0" => Ok(Self::Never),
            other => Err(anyhow!("unsupported color value: {other}")),
        }
    }

    fn enabled(self, json_output: bool) -> bool {
        if json_output {
            return false;
        }
        match self {
            Self::Auto => std::io::stdout().is_terminal(),
            Self::Always => true,
            Self::Never => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LinkPolicy {
    Default,
    Off,
}

impl LinkPolicy {
    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "default" => Ok(Self::Default),
            "off" => Ok(Self::Off),
            other => Err(anyhow!("unsupported --link-policy value: {other}")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AdoptPolicy {
    Inferred,
    Off,
    All,
}

impl AdoptPolicy {
    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "inferred" => Ok(Self::Inferred),
            "off" => Ok(Self::Off),
            "all" => Ok(Self::All),
            other => Err(anyhow!("unsupported --adopt-policy value: {other}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentLinkPolicy {
    Off,
    Warn,
    Safe,
    Reconcile,
}

impl AgentLinkPolicy {
    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "off" => Ok(Self::Off),
            "warn" => Ok(Self::Warn),
            "safe" => Ok(Self::Safe),
            "reconcile" => Ok(Self::Reconcile),
            other => Err(anyhow!("unsupported --agent-link-policy value: {other}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Warn => "warn",
            Self::Safe => "safe",
            Self::Reconcile => "reconcile",
        }
    }

    fn removes_broken_links(self) -> bool {
        matches!(self, Self::Safe | Self::Reconcile)
    }

    fn reconciles_duplicate_dirs(self) -> bool {
        self == Self::Reconcile
    }

    fn creates_missing_links(self) -> bool {
        self == Self::Reconcile
    }
}

#[derive(Clone, Debug)]
struct Options {
    mode: CommandMode,
    lock_action: Option<LockAction>,
    scope: Scope,
    global_lock_file: Option<PathBuf>,
    project_lock_file: PathBuf,
    ignore_project_lock: bool,
    skills_command: Vec<String>,
    json_output: bool,
    dry_run: bool,
    apply: bool,
    yes_flag: bool,
    quiet: bool,
    verbose: bool,
    color_mode: ColorMode,
    all_agents: bool,
    forced_agents: Vec<String>,
    link_policy: LinkPolicy,
    adopt_policy: Option<AdoptPolicy>,
    agent_link_policy: Option<AgentLinkPolicy>,
    agent_dirs: Vec<PathBuf>,
    adopt_source: String,
    adopt_skill: String,
}

#[derive(Clone, Debug)]
struct Endpoint {
    label: String,
    role: String,
    path: PathBuf,
    exists: bool,
    symlink: bool,
    readable: bool,
    broken: bool,
    realpath: Option<PathBuf>,
    lock: Option<Value>,
    error: Option<String>,
}

#[derive(Clone, Debug)]
struct GlobalLockSelection {
    selected: Option<Endpoint>,
    lock: Value,
    warnings: Vec<String>,
    errors: Vec<String>,
}

#[derive(Clone, Debug)]
struct ReadLock {
    path: PathBuf,
    present: bool,
    lock: Value,
}

#[derive(Clone, Debug, Serialize)]
struct EndpointSummary {
    label: String,
    role: String,
    path: String,
    exists: bool,
    symlink: bool,
    readable: bool,
    broken: bool,
    realpath: Option<String>,
    error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct DesiredSkill {
    name: String,
    slug: String,
    scope: String,
    source: String,
    lock_source: String,
    source_ref: String,
    source_url: String,
}

#[derive(Clone, Debug, Serialize)]
struct InstalledSkill {
    name: String,
    slug: String,
    path: String,
    scope: String,
    agents: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct AdoptionSkill {
    name: String,
    slug: String,
    path: String,
    scope: String,
    agents: Vec<String>,
    source: String,
    inference: String,
}

#[derive(Clone, Debug, Serialize)]
struct SkippedSkill {
    scope: String,
    name: String,
    reason: String,
}

#[derive(Clone, Debug)]
struct NormalizedLockSkills {
    desired: Vec<DesiredSkill>,
    skipped: Vec<SkippedSkill>,
}

#[derive(Clone, Debug)]
struct InvalidLockSkills {
    errors: Vec<String>,
    skipped: Vec<SkippedSkill>,
}

#[derive(Clone, Debug, Serialize)]
struct ImportedSkill {
    from: String,
    name: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "action")]
enum LockRepair {
    #[serde(rename = "write")]
    Write {
        path: String,
        imported: Vec<ImportedSkill>,
    },
}

#[derive(Clone, Debug, Serialize)]
struct AgentLinkIssue {
    kind: String,
    name: String,
    agent_dir: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    canonical_path: Option<String>,
    detail: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "action")]
enum AgentLinkRepair {
    #[serde(rename = "create_missing_symlink")]
    CreateMissingSymlink {
        name: String,
        agent: String,
        agent_dir: String,
        path: String,
        target: String,
    },
    #[serde(rename = "remove_broken_symlink")]
    RemoveBrokenSymlink {
        name: String,
        agent_dir: String,
        path: String,
        target: String,
    },
    #[serde(rename = "remove_invalid_symlink")]
    RemoveInvalidSymlink {
        name: String,
        agent_dir: String,
        path: String,
        target: String,
    },
    #[serde(rename = "remove_redundant_symlink")]
    RemoveRedundantSymlink {
        name: String,
        agent_dir: String,
        path: String,
        target: String,
        canonical_path: String,
    },
    #[serde(rename = "replace_noncanonical_symlink")]
    ReplaceNoncanonicalSymlink {
        name: String,
        agent_dir: String,
        path: String,
        old_target: String,
        target: String,
    },
    #[serde(rename = "backup_redundant_dir")]
    BackupRedundantDir {
        name: String,
        agent_dir: String,
        path: String,
        canonical_path: String,
        backup: String,
    },
    #[serde(rename = "backup_duplicate_dir")]
    BackupDuplicateDir {
        name: String,
        agent_dir: String,
        path: String,
        canonical_path: String,
        backup: String,
    },
    #[serde(rename = "replace_duplicate_dir")]
    ReplaceDuplicateDir {
        name: String,
        agent_dir: String,
        path: String,
        target: String,
        backup: String,
    },
}

#[derive(Clone, Debug, Serialize)]
struct AddPlan {
    scope: String,
    reason: String,
    source: String,
    skills: Vec<String>,
    agents: Vec<String>,
    argv: Vec<String>,
    command: String,
}

#[derive(Clone, Debug, Serialize)]
struct AppliedPlan {
    scope: String,
    reason: String,
    source: String,
    skills: Vec<String>,
    agents: Vec<String>,
    command: String,
}

#[derive(Clone, Debug, Serialize)]
struct Payload {
    command: String,
    lock_action: Option<String>,
    scope: String,
    global_lock_file: String,
    project_lock_file: Option<String>,
    skills_command: Vec<String>,
    lock_endpoints: Vec<EndpointSummary>,
    global_desired: Vec<DesiredSkill>,
    project_desired: Vec<DesiredSkill>,
    global_installed: Vec<InstalledSkill>,
    project_installed: Vec<InstalledSkill>,
    global_to_add: Vec<DesiredSkill>,
    project_to_add: Vec<DesiredSkill>,
    global_to_link: Vec<DesiredSkill>,
    project_to_link: Vec<DesiredSkill>,
    global_to_adopt: Vec<AdoptionSkill>,
    project_to_adopt: Vec<AdoptionSkill>,
    global_unlinked: Vec<InstalledSkill>,
    project_unlinked: Vec<InstalledSkill>,
    untracked_installed: Vec<InstalledSkill>,
    agent_link_policy: String,
    agent_dirs: Vec<String>,
    agent_link_issues: Vec<AgentLinkIssue>,
    planned_lock_repairs: Vec<LockRepair>,
    planned_agent_repairs: Vec<AgentLinkRepair>,
    planned_commands: Vec<AddPlan>,
    applied_agent_repairs: Vec<AgentLinkRepair>,
    applied: Vec<AppliedPlan>,
    skipped: Vec<SkippedSkill>,
    warnings: Vec<String>,
    errors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stderr: Option<String>,
}

#[derive(Clone, Debug)]
struct App {
    options: Options,
    include_global: bool,
    include_project: bool,
    default_yes: bool,
    global_lock_selection: GlobalLockSelection,
    project_lock: ReadLock,
    global_endpoints: Vec<Endpoint>,
    payload: Payload,
    skill_dir_compare_cache: BTreeMap<(String, String), std::result::Result<bool, String>>,
}

pub fn main_entry(args: Vec<String>) -> i32 {
    if args.first().is_some_and(|arg| arg == "--version") {
        println!("skills-sync {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    if args.first().is_some_and(|arg| arg == "--build-info") {
        build_info::print_build_info();
        return 0;
    }
    if args.first().is_some_and(|arg| arg == "build-info") {
        return print_standard_build_info(&args[1..]);
    }
    match Options::parse(args) {
        Ok(options) if options.mode == CommandMode::Help => {
            print_help();
            0
        }
        Ok(options) => match App::new(options).and_then(App::run) {
            Ok(code) => code,
            Err(err) => {
                eprintln!("skills-sync: {err:#}");
                EXIT_USAGE
            }
        },
        Err(err) => {
            eprintln!("skills-sync: {err:#}");
            EXIT_USAGE
        }
    }
}

fn print_standard_build_info(args: &[String]) -> i32 {
    if args != ["--json"] {
        eprintln!("skills-sync: build-info requires --json");
        return EXIT_SCHEMA;
    }
    let product = match ProductId::parse("skills-sync") {
        Ok(product) => product,
        Err(error) => {
            eprintln!("skills-sync: {error}");
            return EXIT_SCHEMA;
        }
    };
    let info = match BuildInfo::from_build_values(
        product,
        env!("CARGO_PKG_VERSION"),
        option_env!("DEV_TOOLS_GIT_COMMIT"),
        option_env!("DEV_TOOLS_GIT_DIRTY"),
        option_env!("DEV_TOOLS_BUILD_TARGET"),
        option_env!("DEV_TOOLS_BUILD_PROFILE"),
        option_env!("DEV_TOOLS_BUILD_UNIX"),
    ) {
        Ok(info) => info,
        Err(error) => {
            eprintln!("skills-sync: {error}");
            return EXIT_SCHEMA;
        }
    };
    match serde_json::to_writer_pretty(std::io::stdout().lock(), &info) {
        Ok(()) => {
            println!();
            0
        }
        Err(_) => {
            eprintln!("skills-sync: build information could not be written");
            1
        }
    }
}

impl Options {
    fn parse(args: Vec<String>) -> Result<Self> {
        let dry_run = env_bool("SKILLS_SYNC_DRY_RUN")?;
        let mut options = Self {
            mode: CommandMode::Sync,
            lock_action: None,
            scope: env_scope()?.unwrap_or(Scope::Global),
            global_lock_file: env_path("SKILLS_SYNC_GLOBAL_LOCK_FILE"),
            project_lock_file: env_path("SKILLS_SYNC_PROJECT_LOCK_FILE").unwrap_or_else(|| {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join("skills-lock.json")
            }),
            ignore_project_lock: env_bool("SKILLS_SYNC_NO_PROJECT_LOCK")?,
            skills_command: shell_words(
                &env_string("SKILLS_SYNC_SKILLS_CMD")
                    .unwrap_or_else(|| "npx skills@latest".to_string()),
            )?,
            json_output: env_bool("SKILLS_SYNC_JSON")?,
            dry_run,
            apply: !dry_run,
            yes_flag: env_bool("SKILLS_SYNC_YES")?,
            quiet: env_bool("SKILLS_SYNC_QUIET")?,
            verbose: env_bool("SKILLS_SYNC_VERBOSE")?,
            color_mode: env_color_mode()?,
            all_agents: env_bool("SKILLS_SYNC_ALL_AGENTS")?,
            forced_agents: env_agents(),
            link_policy: env_string("SKILLS_SYNC_LINK_POLICY")
                .map(|value| LinkPolicy::parse(&value))
                .transpose()?
                .unwrap_or(LinkPolicy::Default),
            adopt_policy: env_string("SKILLS_SYNC_ADOPT_POLICY")
                .map(|value| AdoptPolicy::parse(&value))
                .transpose()?,
            agent_link_policy: env_string("SKILLS_SYNC_AGENT_LINK_POLICY")
                .map(|value| AgentLinkPolicy::parse(&value))
                .transpose()?,
            agent_dirs: env_paths("SKILLS_SYNC_AGENT_DIRS"),
            adopt_source: String::new(),
            adopt_skill: String::new(),
        };

        let mut index = 0usize;
        while let Some(arg) = args.get(index) {
            match arg.as_str() {
                "sync" => {
                    options.mode = CommandMode::Sync;
                    index += 1;
                }
                "status" => {
                    options.mode = CommandMode::Status;
                    options.apply = false;
                    index += 1;
                }
                "doctor" => {
                    options.mode = CommandMode::Doctor;
                    options.apply = true;
                    index += 1;
                }
                "adopt" => {
                    options.mode = CommandMode::Adopt;
                    options.apply = true;
                    index += 1;
                }
                "lock" => {
                    options.mode = CommandMode::Lock;
                    options.lock_action = Some(LockAction::Status);
                    options.apply = false;
                    index += 1;
                    if let Some(action) = args.get(index) {
                        match action.as_str() {
                            "status" => {
                                options.lock_action = Some(LockAction::Status);
                                options.apply = false;
                                index += 1;
                            }
                            "repair" => {
                                options.lock_action = Some(LockAction::Repair);
                                options.apply = true;
                                index += 1;
                            }
                            _ => {}
                        }
                    }
                }
                "help" | "-h" | "--help" => {
                    options.mode = CommandMode::Help;
                    index += 1;
                }
                "-n" | "--dry-run" => {
                    options.dry_run = true;
                    options.apply = false;
                    index += 1;
                }
                "--apply" => {
                    options.apply = true;
                    index += 1;
                }
                "-j" | "--json" => {
                    options.json_output = true;
                    index += 1;
                }
                "-y" | "--yes" => {
                    options.yes_flag = true;
                    index += 1;
                }
                "-q" | "--quiet" => {
                    options.quiet = true;
                    index += 1;
                }
                "-v" | "--verbose" => {
                    options.verbose = true;
                    index += 1;
                }
                "-g" | "--global" => {
                    options.scope = Scope::Global;
                    index += 1;
                }
                "-p" | "--project" => {
                    options.scope = Scope::Project;
                    index += 1;
                }
                "-b" | "--both" => {
                    options.scope = Scope::Both;
                    index += 1;
                }
                "--scope" => {
                    let value = required_value(&args, index, "--scope")?;
                    options.scope = Scope::parse(value)?;
                    index += 2;
                }
                "-G" | "--global-lock-file" => {
                    let value = required_value(&args, index, "--global-lock-file")?;
                    options.global_lock_file = Some(expand_home_path(value));
                    index += 2;
                }
                "-P" | "--project-lock-file" => {
                    let value = required_value(&args, index, "--project-lock-file")?;
                    options.project_lock_file = expand_home_path(value);
                    index += 2;
                }
                "--no-project-lock" => {
                    options.ignore_project_lock = true;
                    index += 1;
                }
                "-c" | "--skills-cmd" => {
                    let value = required_value(&args, index, "--skills-cmd")?;
                    options.skills_command = shell_words(value)?;
                    index += 2;
                }
                "-a" | "--agent" => {
                    let value = required_value(&args, index, "--agent")?;
                    options.forced_agents.push(value.to_string());
                    index += 2;
                }
                "-A" | "--all-agents" => {
                    options.all_agents = true;
                    index += 1;
                }
                "--color" => {
                    let value = required_value(&args, index, "--color")?;
                    options.color_mode = ColorMode::parse(value)?;
                    index += 2;
                }
                "--no-color" => {
                    options.color_mode = ColorMode::Never;
                    index += 1;
                }
                "--link-policy" => {
                    let value = required_value(&args, index, "--link-policy")?;
                    options.link_policy = LinkPolicy::parse(value)?;
                    index += 2;
                }
                "--adopt-policy" => {
                    let value = required_value(&args, index, "--adopt-policy")?;
                    options.adopt_policy = Some(AdoptPolicy::parse(value)?);
                    index += 2;
                }
                "--agent-link-policy" => {
                    let value = required_value(&args, index, "--agent-link-policy")?;
                    options.agent_link_policy = Some(AgentLinkPolicy::parse(value)?);
                    index += 2;
                }
                "--agent-dir" => {
                    let value = required_value(&args, index, "--agent-dir")?;
                    options.agent_dirs.push(expand_home_path(value));
                    index += 2;
                }
                "--source" => {
                    options.adopt_source = required_value(&args, index, "--source")?.to_string();
                    index += 2;
                }
                "--skill" => {
                    options.adopt_skill = required_value(&args, index, "--skill")?.to_string();
                    index += 2;
                }
                "--" => break,
                other if other.starts_with('-') => return Err(anyhow!("unknown option: {other}")),
                other => return Err(anyhow!("unexpected argument: {other}")),
            }
        }

        if options.skills_command.is_empty() {
            return Err(anyhow!("empty skills command"));
        }
        options.forced_agents = normalize_agents(&options.forced_agents);
        Ok(options)
    }
}

impl App {
    fn new(options: Options) -> Result<Self> {
        let home = home_dir();
        let default_canonical_global_lock = home.join(".agents").join("skills-lock.json");
        let include_global = options.mode == CommandMode::Lock
            || matches!(options.scope, Scope::Global | Scope::Both);
        let include_project = options.mode != CommandMode::Lock
            && matches!(options.scope, Scope::Project | Scope::Both);
        let default_yes = options.yes_flag
            || matches!(
                options.mode,
                CommandMode::Sync | CommandMode::Doctor | CommandMode::Adopt
            );
        let agent_link_policy = effective_agent_link_policy(&options);

        let global_endpoints = build_global_endpoints(&options, &default_canonical_global_lock);
        let global_lock_selection = select_global_lock(
            &global_endpoints,
            &options,
            include_global
                && options.mode != CommandMode::Lock
                && options.mode != CommandMode::Doctor,
        );
        let project_lock = if include_project && !options.ignore_project_lock {
            read_lock_file(&options.project_lock_file, false)?
        } else {
            ReadLock {
                path: options.project_lock_file.clone(),
                present: false,
                lock: create_empty_project_lock(),
            }
        };
        let mut payload = Payload {
            command: command_name(&options.mode).to_string(),
            lock_action: options
                .lock_action
                .as_ref()
                .map(|action| action.as_str().to_string()),
            scope: options.scope.as_str().to_string(),
            global_lock_file: global_lock_selection
                .selected
                .as_ref()
                .map(|endpoint| path_string(&endpoint.path))
                .unwrap_or_else(|| path_string(&default_canonical_global_lock)),
            project_lock_file: if include_project && project_lock.present {
                Some(path_string(&project_lock.path))
            } else {
                None
            },
            skills_command: options.skills_command.clone(),
            lock_endpoints: global_endpoints.iter().map(endpoint_summary).collect(),
            global_desired: Vec::new(),
            project_desired: Vec::new(),
            global_installed: Vec::new(),
            project_installed: Vec::new(),
            global_to_add: Vec::new(),
            project_to_add: Vec::new(),
            global_to_link: Vec::new(),
            project_to_link: Vec::new(),
            global_to_adopt: Vec::new(),
            project_to_adopt: Vec::new(),
            global_unlinked: Vec::new(),
            project_unlinked: Vec::new(),
            untracked_installed: Vec::new(),
            agent_link_policy: agent_link_policy.as_str().to_string(),
            agent_dirs: Vec::new(),
            agent_link_issues: Vec::new(),
            planned_lock_repairs: Vec::new(),
            planned_agent_repairs: Vec::new(),
            planned_commands: Vec::new(),
            applied_agent_repairs: Vec::new(),
            applied: Vec::new(),
            skipped: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
            stderr: None,
        };
        if options.ignore_project_lock && include_project {
            payload
                .warnings
                .push("project lock ignored via --no-project-lock".to_string());
        }
        if include_project && !options.ignore_project_lock && !project_lock.present {
            payload.warnings.push(format!(
                "project lock not found: {}",
                options.project_lock_file.display()
            ));
        }
        payload
            .warnings
            .extend(global_lock_selection.warnings.clone());
        payload.errors.extend(global_lock_selection.errors.clone());

        Ok(Self {
            options,
            include_global,
            include_project,
            default_yes,
            global_lock_selection,
            project_lock,
            global_endpoints,
            payload,
            skill_dir_compare_cache: BTreeMap::new(),
        })
    }

    fn run(mut self) -> Result<i32> {
        match self.options.mode {
            CommandMode::Lock => {
                if self.options.lock_action == Some(LockAction::Repair) {
                    self.repair_global_lock_endpoints();
                }
                return Ok(self.finish_lock_only(if self.payload.errors.is_empty() {
                    0
                } else {
                    EXIT_USAGE
                }));
            }
            CommandMode::Adopt => {
                if self.options.adopt_source.is_empty() {
                    return Ok(self.fail(EXIT_USAGE, "adopt requires --source SOURCE"));
                }
                if self.options.adopt_skill.is_empty() {
                    return Ok(self.fail(EXIT_USAGE, "adopt requires --skill NAME"));
                }
                let scope = if self.options.scope == Scope::Project {
                    "project"
                } else {
                    "global"
                };
                let agents = self.resolve_target_agents(scope);
                let plan = self.build_add_plan(
                    scope,
                    &self.options.adopt_source,
                    &[self.options.adopt_skill.clone()],
                    &agents,
                    "adopt",
                    true,
                );
                self.payload.planned_commands.push(plan);
                return Ok(self.apply_or_report());
            }
            CommandMode::Doctor => {
                if self.include_global {
                    self.repair_global_lock_endpoints();
                }
            }
            CommandMode::Sync | CommandMode::Status => {}
            CommandMode::Help => {
                print_help();
                return Ok(0);
            }
        }

        if !self.payload.errors.is_empty() {
            return Ok(self.fail(EXIT_USAGE, "lock file conflict prevents sync"));
        }

        let global_lock = self.global_lock_selection.lock.clone();
        if self.include_global {
            match normalize_lock_skills(&global_lock, "global") {
                Ok(normalized) => {
                    self.payload.global_desired = normalized.desired;
                    self.payload.skipped.extend(normalized.skipped);
                }
                Err(invalid) => {
                    self.payload.errors.extend(invalid.errors);
                    self.payload.skipped.extend(invalid.skipped);
                }
            }
        }
        if self.include_project && self.project_lock.present {
            match normalize_lock_skills(&self.project_lock.lock, "project") {
                Ok(normalized) => {
                    self.payload.project_desired = normalized.desired;
                    self.payload.skipped.extend(normalized.skipped);
                }
                Err(invalid) => {
                    self.payload.errors.extend(invalid.errors);
                    self.payload.skipped.extend(invalid.skipped);
                }
            }
        }
        if !self.payload.errors.is_empty() {
            return Ok(self.fail(EXIT_USAGE, "lock file contains invalid skill entries"));
        }

        if self.include_global {
            self.payload.global_installed = match self.list_installed("global") {
                Ok(installed) => installed,
                Err(code) => return Ok(code),
            };
            self.build_scope_plans("global");
        }
        if self.include_project {
            self.payload.project_installed = match self.list_installed("project") {
                Ok(installed) => installed,
                Err(code) => return Ok(code),
            };
            self.build_scope_plans("project");
        }
        if self.include_global {
            self.audit_agent_links();
        }

        Ok(self.apply_or_report())
    }

    fn repair_global_lock_endpoints(&mut self) {
        if self.options.global_lock_file.is_some() {
            self.payload
                .warnings
                .push("lock repair skipped because --global-lock-file was provided".to_string());
            return;
        }

        let Some(canonical) = self
            .global_endpoints
            .iter()
            .find(|endpoint| endpoint.label == "canonical")
            .cloned()
        else {
            self.payload
                .errors
                .push("internal error: canonical global lock endpoint missing".to_string());
            return;
        };

        let mut merged = create_empty_global_lock();
        let mut imported = Vec::new();
        let mut merge_errors = Vec::new();
        for endpoint in &self.global_endpoints {
            if !endpoint.readable {
                continue;
            }
            let lock = normalize_global_lock(endpoint.lock.as_ref().unwrap_or(&Value::Null));
            merge_lock_into(
                &mut merged,
                &lock,
                endpoint,
                &mut imported,
                &mut merge_errors,
                endpoint.label != "canonical",
            );
        }
        if !merge_errors.is_empty() {
            self.payload.errors.extend(merge_errors);
            return;
        }

        let canonical_changed = !canonical.readable
            || canonical
                .lock
                .as_ref()
                .map(normalize_global_lock)
                .is_none_or(|lock| lock != merged);
        if canonical_changed {
            self.payload.planned_lock_repairs.push(LockRepair::Write {
                path: path_string(&canonical.path),
                imported: imported.clone(),
            });
            if !self.options.dry_run {
                if let Err(err) = write_json_following_useful_symlink(&canonical.path, &merged) {
                    self.payload.errors.push(err.to_string());
                    return;
                }
            }
        }

        self.global_lock_selection.lock = merged;
        self.global_lock_selection.selected =
            Some(inspect_endpoint("canonical", "source", &canonical.path));
        self.payload.global_lock_file = path_string(&canonical.path);
    }

    fn build_scope_plans(&mut self, scope: &str) {
        let (desired, installed) = if scope == "global" {
            (
                self.payload.global_desired.clone(),
                self.payload.global_installed.clone(),
            )
        } else {
            (
                self.payload.project_desired.clone(),
                self.payload.project_installed.clone(),
            )
        };
        let desired_slugs = desired
            .iter()
            .map(|entry| entry.slug.as_str())
            .collect::<BTreeSet<_>>();
        let mut installed_by_slug = BTreeMap::new();
        for entry in &installed {
            installed_by_slug
                .entry(entry.slug.as_str())
                .or_insert(entry);
        }
        let agents = self.resolve_target_agents(scope);
        let explicit_agents = !agents.is_empty() && !agents.iter().any(|agent| agent == "*");
        let mut to_add = Vec::new();
        let mut to_link = Vec::new();
        let mut to_adopt = Vec::new();
        let mut link_batches: BTreeMap<(String, Vec<String>), Vec<String>> = BTreeMap::new();

        for desired_entry in &desired {
            let Some(installed_entry) = installed_by_slug.get(desired_entry.slug.as_str()) else {
                to_add.push(desired_entry.clone());
                let plan = self.build_add_plan(
                    scope,
                    &desired_entry.source,
                    std::slice::from_ref(&desired_entry.name),
                    &agents,
                    "restore",
                    self.default_yes,
                );
                self.payload.planned_commands.push(plan);
                continue;
            };
            let missing_agents = if explicit_agents {
                let installed_agents = installed_entry.agents.iter().collect::<BTreeSet<_>>();
                agents
                    .iter()
                    .filter(|agent| {
                        !installed_agents.contains(agent)
                            && !(scope == "global"
                                && agent.as_str() == "codex"
                                && Self::global_canonical_skill_visible_to_codex(
                                    &home_dir(),
                                    &installed_entry.path,
                                ))
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            } else if installed_entry.agents.is_empty() {
                agents.clone()
            } else {
                Vec::new()
            };
            let needs_link = if explicit_agents {
                !missing_agents.is_empty()
            } else {
                installed_entry.agents.is_empty()
            };
            if needs_link {
                let installed_entry = (*installed_entry).clone();
                if scope == "global" {
                    self.payload.global_unlinked.push(installed_entry);
                } else {
                    self.payload.project_unlinked.push(installed_entry);
                }
                if self.options.link_policy != LinkPolicy::Off {
                    to_link.push(desired_entry.clone());
                    if explicit_agents || !self.repair_links_locally(scope) {
                        link_batches
                            .entry((desired_entry.repair_source(), missing_agents))
                            .or_default()
                            .push(desired_entry.name.clone());
                    }
                }
            }
        }

        for ((source, missing_agents), skills) in link_batches {
            let plan = self.build_add_plan(
                scope,
                &source,
                &skills,
                &missing_agents,
                "link",
                self.default_yes,
            );
            self.payload.planned_commands.push(plan);
        }

        let adopt_policy = self.effective_adopt_policy();
        if self.options.mode == CommandMode::Doctor && adopt_policy != AdoptPolicy::Off {
            for installed_entry in &installed {
                if desired_slugs.contains(installed_entry.slug.as_str()) {
                    continue;
                }
                let inferred = self.infer_install_source(installed_entry, scope, &adopt_policy);
                if inferred.source.is_empty() {
                    let mut untracked = installed_entry.clone();
                    untracked.reason = Some(inferred.reason);
                    self.payload.untracked_installed.push(untracked);
                    continue;
                }
                let skill = inferred
                    .skill
                    .clone()
                    .unwrap_or_else(|| installed_entry.name.clone());
                to_adopt.push(AdoptionSkill {
                    name: installed_entry.name.clone(),
                    slug: installed_entry.slug.clone(),
                    path: installed_entry.path.clone(),
                    scope: installed_entry.scope.clone(),
                    agents: installed_entry.agents.clone(),
                    source: inferred.source.clone(),
                    inference: inferred.reason.clone(),
                });
                let adopt_agents = if agents.is_empty() && inferred.prefer_all_agents {
                    vec!["*".to_string()]
                } else {
                    agents.clone()
                };
                let plan = self.build_add_plan(
                    scope,
                    &inferred.source,
                    &[skill],
                    &adopt_agents,
                    "adopt",
                    true,
                );
                self.payload.planned_commands.push(plan);
            }
        } else {
            for installed_entry in &installed {
                if !desired_slugs.contains(installed_entry.slug.as_str()) {
                    let mut untracked = installed_entry.clone();
                    untracked.reason = Some("not present in selected lock".to_string());
                    self.payload.untracked_installed.push(untracked);
                }
            }
        }

        if scope == "global" {
            self.payload.global_to_add = to_add;
            self.payload.global_to_link = to_link;
            self.payload.global_to_adopt = to_adopt;
        } else {
            self.payload.project_to_add = to_add;
            self.payload.project_to_link = to_link;
            self.payload.project_to_adopt = to_adopt;
        }
    }

    fn audit_agent_links(&mut self) {
        let policy = effective_agent_link_policy(&self.options);
        if policy == AgentLinkPolicy::Off {
            return;
        }

        let home = home_dir();
        let agent_dirs = discover_agent_dirs(&home, &self.options.agent_dirs);
        self.payload.agent_dirs = agent_dirs
            .iter()
            .map(|agent_dir| path_string(&agent_dir.path))
            .collect();

        let canonical = self.canonical_global_skill_paths();
        if canonical.is_empty() {
            return;
        }
        let backup_root = agent_repair_backup_root(&home);
        for agent_dir in agent_dirs {
            self.audit_agent_dir(&agent_dir, &canonical, policy, &backup_root);
        }
        self.audit_missing_agent_links(&home, &canonical, policy);
    }

    fn canonical_global_skill_paths(&self) -> BTreeMap<String, CanonicalSkill> {
        let mut canonical = BTreeMap::new();
        for installed in &self.payload.global_installed {
            if installed.path.is_empty() {
                continue;
            }
            let path = PathBuf::from(&installed.path);
            canonical.insert(
                installed.slug.clone(),
                CanonicalSkill {
                    name: installed.name.clone(),
                    path: path.clone(),
                    realpath: safe_realpath(&path),
                },
            );
        }
        canonical
    }

    fn audit_agent_dir(
        &mut self,
        agent_dir: &AgentDir,
        canonical: &BTreeMap<String, CanonicalSkill>,
        policy: AgentLinkPolicy,
        backup_root: &Path,
    ) {
        let entries = match fs::read_dir(&agent_dir.path) {
            Ok(entries) => entries,
            Err(err) => {
                self.payload.warnings.push(format!(
                    "failed to inspect agent skill dir {}: {err}",
                    agent_dir.path.display()
                ));
                return;
            }
        };

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            let path = entry.path();
            let slug = sanitize_name(&name);
            let canonical_skill = canonical.get(&slug);
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(err) => {
                    self.push_agent_issue(AgentLinkIssue {
                        kind: "unreadable".to_string(),
                        name,
                        agent_dir: path_string(&agent_dir.path),
                        path: path_string(&path),
                        target: None,
                        canonical_path: canonical_skill.map(|skill| path_string(&skill.path)),
                        detail: err.to_string(),
                    });
                    continue;
                }
            };

            if metadata.file_type().is_symlink() {
                self.audit_agent_symlink(&name, &path, agent_dir, canonical_skill, policy);
            } else if metadata.is_dir() {
                self.audit_agent_directory(
                    &name,
                    &path,
                    agent_dir,
                    canonical_skill,
                    policy,
                    backup_root,
                );
            } else {
                self.push_agent_issue(AgentLinkIssue {
                    kind: "unsupported_entry".to_string(),
                    name,
                    agent_dir: path_string(&agent_dir.path),
                    path: path_string(&path),
                    target: None,
                    canonical_path: canonical_skill.map(|skill| path_string(&skill.path)),
                    detail: "agent skill entry is neither a directory nor symlink".to_string(),
                });
            }
        }
    }

    fn audit_agent_symlink(
        &mut self,
        name: &str,
        path: &Path,
        agent_dir: &AgentDir,
        canonical_skill: Option<&CanonicalSkill>,
        policy: AgentLinkPolicy,
    ) {
        let raw_target = fs::read_link(path)
            .map(|target| target.display().to_string())
            .unwrap_or_default();
        let realpath = safe_realpath(path);
        if realpath.is_none() {
            let issue = AgentLinkIssue {
                kind: "broken_symlink".to_string(),
                name: name.to_string(),
                agent_dir: path_string(&agent_dir.path),
                path: path_string(path),
                target: Some(raw_target.clone()),
                canonical_path: canonical_skill.map(|skill| path_string(&skill.path)),
                detail: "agent skill symlink target does not exist".to_string(),
            };
            self.push_agent_issue(issue);
            if policy.removes_broken_links() {
                self.payload
                    .planned_agent_repairs
                    .push(AgentLinkRepair::RemoveBrokenSymlink {
                        name: name.to_string(),
                        agent_dir: path_string(&agent_dir.path),
                        path: path_string(path),
                        target: raw_target,
                    });
            }
            return;
        }

        let Some(canonical_skill) = canonical_skill else {
            if !path.join("SKILL.md").is_file() {
                let issue = AgentLinkIssue {
                    kind: "invalid_skill_symlink".to_string(),
                    name: name.to_string(),
                    agent_dir: path_string(&agent_dir.path),
                    path: path_string(path),
                    target: Some(raw_target.clone()),
                    canonical_path: None,
                    detail: "agent skill symlink target does not contain SKILL.md".to_string(),
                };
                self.push_agent_issue(issue);
                if policy.removes_broken_links() {
                    self.payload.planned_agent_repairs.push(
                        AgentLinkRepair::RemoveInvalidSymlink {
                            name: name.to_string(),
                            agent_dir: path_string(&agent_dir.path),
                            path: path_string(path),
                            target: raw_target,
                        },
                    );
                }
                return;
            }
            self.push_agent_issue(AgentLinkIssue {
                kind: "unmanaged_symlink".to_string(),
                name: name.to_string(),
                agent_dir: path_string(&agent_dir.path),
                path: path_string(path),
                target: Some(raw_target),
                canonical_path: None,
                detail: "agent skill link is not present in the global skills list".to_string(),
            });
            return;
        };

        if agent_dir.label == "codex" {
            let redundant = realpath == canonical_skill.realpath
                || self
                    .equivalent_skill_dirs_cached(path, &canonical_skill.path)
                    .unwrap_or(false);
            self.push_agent_issue(AgentLinkIssue {
                kind: if redundant {
                    "redundant_codex_symlink".to_string()
                } else {
                    "duplicate_codex_symlink".to_string()
                },
                name: name.to_string(),
                agent_dir: path_string(&agent_dir.path),
                path: path_string(path),
                target: Some(raw_target.clone()),
                canonical_path: Some(path_string(&canonical_skill.path)),
                detail: if redundant {
                    "Codex already reads the canonical global ~/.agents/skills entry".to_string()
                } else {
                    "same-slug Codex skill duplicates the canonical global ~/.agents/skills entry"
                        .to_string()
                },
            });
            if policy.reconciles_duplicate_dirs() {
                self.payload
                    .planned_agent_repairs
                    .push(AgentLinkRepair::RemoveRedundantSymlink {
                        name: name.to_string(),
                        agent_dir: path_string(&agent_dir.path),
                        path: path_string(path),
                        target: raw_target,
                        canonical_path: path_string(&canonical_skill.path),
                    });
            }
            return;
        }

        if realpath == canonical_skill.realpath {
            return;
        }
        self.push_agent_issue(AgentLinkIssue {
            kind: "noncanonical_symlink".to_string(),
            name: name.to_string(),
            agent_dir: path_string(&agent_dir.path),
            path: path_string(path),
            target: Some(raw_target.clone()),
            canonical_path: Some(path_string(&canonical_skill.path)),
            detail: format!(
                "agent skill link does not point at canonical global skill {}",
                canonical_skill.name
            ),
        });
        if policy.reconciles_duplicate_dirs() {
            self.payload
                .planned_agent_repairs
                .push(AgentLinkRepair::ReplaceNoncanonicalSymlink {
                    name: name.to_string(),
                    agent_dir: path_string(&agent_dir.path),
                    path: path_string(path),
                    old_target: raw_target,
                    target: path_string(&canonical_skill.path),
                });
        }
    }

    fn audit_agent_directory(
        &mut self,
        name: &str,
        path: &Path,
        agent_dir: &AgentDir,
        canonical_skill: Option<&CanonicalSkill>,
        policy: AgentLinkPolicy,
        backup_root: &Path,
    ) {
        let Some(canonical_skill) = canonical_skill else {
            self.push_agent_issue(AgentLinkIssue {
                kind: "unmanaged_dir".to_string(),
                name: name.to_string(),
                agent_dir: path_string(&agent_dir.path),
                path: path_string(path),
                target: None,
                canonical_path: None,
                detail: "agent skill directory is not present in the global skills list"
                    .to_string(),
            });
            return;
        };

        if safe_realpath(path) == canonical_skill.realpath {
            return;
        }

        if agent_dir.label == "codex" {
            match self.equivalent_skill_dirs_cached(path, &canonical_skill.path) {
                Ok(true) => {
                    self.push_agent_issue(AgentLinkIssue {
                        kind: "redundant_codex_dir".to_string(),
                        name: name.to_string(),
                        agent_dir: path_string(&agent_dir.path),
                        path: path_string(path),
                        target: None,
                        canonical_path: Some(path_string(&canonical_skill.path)),
                        detail: "Codex already reads the canonical global ~/.agents/skills entry"
                            .to_string(),
                    });
                    if policy.reconciles_duplicate_dirs() {
                        self.payload.planned_agent_repairs.push(
                            AgentLinkRepair::BackupRedundantDir {
                                name: name.to_string(),
                                agent_dir: path_string(&agent_dir.path),
                                path: path_string(path),
                                canonical_path: path_string(&canonical_skill.path),
                                backup: path_string(&backup_path_for(backup_root, agent_dir, name)),
                            },
                        );
                    }
                }
                Ok(false) => {
                    self.push_agent_issue(AgentLinkIssue {
                        kind: "duplicate_codex_dir".to_string(),
                        name: name.to_string(),
                        agent_dir: path_string(&agent_dir.path),
                        path: path_string(path),
                        target: None,
                        canonical_path: Some(path_string(&canonical_skill.path)),
                        detail:
                            "same-slug Codex skill differs from the canonical global ~/.agents/skills entry"
                                .to_string(),
                    });
                    if policy.reconciles_duplicate_dirs() {
                        self.payload.planned_agent_repairs.push(
                            AgentLinkRepair::BackupDuplicateDir {
                                name: name.to_string(),
                                agent_dir: path_string(&agent_dir.path),
                                path: path_string(path),
                                canonical_path: path_string(&canonical_skill.path),
                                backup: path_string(&backup_path_for(backup_root, agent_dir, name)),
                            },
                        );
                    }
                }
                Err(err) => self.push_agent_issue(AgentLinkIssue {
                    kind: "duplicate_compare_failed".to_string(),
                    name: name.to_string(),
                    agent_dir: path_string(&agent_dir.path),
                    path: path_string(path),
                    target: None,
                    canonical_path: Some(path_string(&canonical_skill.path)),
                    detail: err.to_string(),
                }),
            }
            return;
        }

        match self.equivalent_skill_dirs_cached(path, &canonical_skill.path) {
            Ok(true) => {
                self.push_agent_issue(AgentLinkIssue {
                    kind: "duplicate_equivalent_dir".to_string(),
                    name: name.to_string(),
                    agent_dir: path_string(&agent_dir.path),
                    path: path_string(path),
                    target: None,
                    canonical_path: Some(path_string(&canonical_skill.path)),
                    detail: "agent skill directory matches canonical global skill content"
                        .to_string(),
                });
                if policy.reconciles_duplicate_dirs() {
                    self.payload
                        .planned_agent_repairs
                        .push(AgentLinkRepair::ReplaceDuplicateDir {
                            name: name.to_string(),
                            agent_dir: path_string(&agent_dir.path),
                            path: path_string(path),
                            target: path_string(&canonical_skill.path),
                            backup: path_string(&backup_path_for(backup_root, agent_dir, name)),
                        });
                }
            }
            Ok(false) => self.push_agent_issue(AgentLinkIssue {
                kind: "duplicate_conflict_dir".to_string(),
                name: name.to_string(),
                agent_dir: path_string(&agent_dir.path),
                path: path_string(path),
                target: None,
                canonical_path: Some(path_string(&canonical_skill.path)),
                detail: "agent skill directory differs from canonical global skill content"
                    .to_string(),
            }),
            Err(err) => self.push_agent_issue(AgentLinkIssue {
                kind: "duplicate_compare_failed".to_string(),
                name: name.to_string(),
                agent_dir: path_string(&agent_dir.path),
                path: path_string(path),
                target: None,
                canonical_path: Some(path_string(&canonical_skill.path)),
                detail: err.to_string(),
            }),
        }
    }

    fn push_agent_issue(&mut self, issue: AgentLinkIssue) {
        self.payload.agent_link_issues.push(issue);
    }

    fn audit_missing_agent_links(
        &mut self,
        home: &Path,
        canonical: &BTreeMap<String, CanonicalSkill>,
        policy: AgentLinkPolicy,
    ) {
        if self.payload.global_to_link.is_empty() {
            return;
        }
        let target_agents = self.resolve_target_agents("global");
        if target_agents.is_empty() {
            return;
        }
        let mut seen = self
            .payload
            .planned_agent_repairs
            .iter()
            .filter_map(agent_repair_path)
            .collect::<BTreeSet<_>>();
        for desired in self.payload.global_to_link.clone() {
            let Some(canonical_skill) = canonical.get(&desired.slug) else {
                continue;
            };
            for agent in &target_agents {
                let Some(agent_dir) = agent_skill_dir(home, agent) else {
                    continue;
                };
                if same_path(&agent_dir.path, &canonical_skill.path)
                    || same_path(
                        &agent_dir.path,
                        canonical_skill.path.parent().unwrap_or(&agent_dir.path),
                    )
                {
                    continue;
                }
                let link_path = agent_dir.path.join(&desired.slug);
                if fs::symlink_metadata(&link_path).is_ok() {
                    continue;
                }
                let issue = AgentLinkIssue {
                    kind: "missing_symlink".to_string(),
                    name: desired.name.clone(),
                    agent_dir: path_string(&agent_dir.path),
                    path: path_string(&link_path),
                    target: Some(path_string(&canonical_skill.path)),
                    canonical_path: Some(path_string(&canonical_skill.path)),
                    detail: format!("agent skill link missing for {agent}"),
                };
                self.push_agent_issue(issue);
                if policy.creates_missing_links() && seen.insert(path_string(&link_path)) {
                    self.payload.planned_agent_repairs.push(
                        AgentLinkRepair::CreateMissingSymlink {
                            name: desired.name.clone(),
                            agent: agent.clone(),
                            agent_dir: path_string(&agent_dir.path),
                            path: path_string(&link_path),
                            target: path_string(&canonical_skill.path),
                        },
                    );
                }
            }
        }
    }

    fn repair_links_locally(&self, scope: &str) -> bool {
        if scope != "global" || !effective_agent_link_policy(&self.options).creates_missing_links()
        {
            return false;
        }
        let home = home_dir();
        let canonical_global_dir = home.join(".agents/skills");
        let agents = self.resolve_target_agents(scope);
        !agents.is_empty()
            && agents.iter().all(|agent| {
                agent_skill_dir(&home, agent)
                    .is_some_and(|agent_dir| !same_path(&agent_dir.path, &canonical_global_dir))
            })
    }

    fn effective_adopt_policy(&self) -> AdoptPolicy {
        self.options.adopt_policy.clone().unwrap_or_else(|| {
            if self.options.mode == CommandMode::Doctor {
                AdoptPolicy::Inferred
            } else {
                AdoptPolicy::Off
            }
        })
    }

    fn infer_install_source(
        &self,
        installed_entry: &InstalledSkill,
        scope: &str,
        adopt_policy: &AdoptPolicy,
    ) -> SourceInference {
        if installed_entry.path.is_empty() {
            return SourceInference::empty("installed path missing from skills list output");
        }
        let skill_dir = resolve_symlink_chain(Path::new(&installed_entry.path));
        let git_inference = infer_git_source(&skill_dir);
        if !git_inference.source.is_empty() {
            return git_inference;
        }
        let metadata_inference = infer_metadata_source(&skill_dir);
        if !metadata_inference.source.is_empty() {
            return metadata_inference;
        }
        let vendor_inference =
            infer_codex_desktop_vendor_source(&home_dir(), installed_entry, &skill_dir);
        if !vendor_inference.source.is_empty() {
            return vendor_inference;
        }
        if adopt_policy == &AdoptPolicy::All {
            return SourceInference {
                source: path_string(&skill_dir),
                skill: Some(installed_entry.name.clone()),
                reason: format!("local {scope} path fallback"),
                prefer_all_agents: false,
            };
        }
        SourceInference::empty("no source metadata or supported Git remote could be inferred")
    }

    fn list_installed(&mut self, scope: &str) -> Result<Vec<InstalledSkill>, i32> {
        let args = if scope == "global" {
            vec!["list".to_string(), "-g".to_string(), "--json".to_string()]
        } else {
            vec!["list".to_string(), "--json".to_string()]
        };
        let result = self.run_skills(&args);
        let result = match result {
            Ok(result) => result,
            Err(err) => return Err(self.fail(EXIT_USAGE, &err.to_string())),
        };
        if result.status != 0 {
            let message = format!(
                "skills list {}--json failed",
                if scope == "global" { "-g " } else { "" }
            );
            self.payload.stderr = Some(result.stderr.trim().to_string());
            return Err(self.fail(EXIT_USAGE, &message));
        }
        let parsed: Value = match serde_json::from_str(&result.stdout) {
            Ok(parsed) => parsed,
            Err(err) => {
                let message = format!("failed to parse {scope} skills JSON: {err}");
                return Err(self.fail(EXIT_SCHEMA, &message));
            }
        };
        let Some(entries) = parsed.as_array() else {
            let message = format!("{scope} skills JSON must be an array");
            return Err(self.fail(EXIT_SCHEMA, &message));
        };
        Ok(entries
            .iter()
            .filter_map(|entry| {
                let name = entry.get("name").and_then(Value::as_str)?.to_string();
                let agents = entry
                    .get("agents")
                    .and_then(Value::as_array)
                    .map(|items| {
                        normalize_agents(
                            &items
                                .iter()
                                .filter_map(Value::as_str)
                                .map(ToString::to_string)
                                .collect::<Vec<_>>(),
                        )
                    })
                    .unwrap_or_default();
                let path = entry
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                Some(InstalledSkill {
                    slug: sanitize_name(&name),
                    name,
                    path,
                    scope: scope.to_string(),
                    agents,
                    reason: None,
                })
            })
            .collect())
    }

    fn global_canonical_skill_visible_to_codex(home: &Path, raw_path: &str) -> bool {
        if raw_path.is_empty() {
            return false;
        }
        let skill_dir = resolve_symlink_chain(Path::new(raw_path));
        let canonical_root = resolve_symlink_chain(&home.join(".agents/skills"));
        skill_dir.starts_with(canonical_root) && skill_dir.join("SKILL.md").is_file()
    }

    fn resolve_target_agents(&self, _scope: &str) -> Vec<String> {
        if self.options.all_agents {
            return vec!["*".to_string()];
        }
        if !self.options.forced_agents.is_empty() {
            return self.options.forced_agents.clone();
        }
        Vec::new()
    }

    fn build_add_plan(
        &self,
        scope: &str,
        source: &str,
        skills: &[String],
        agents: &[String],
        reason: &str,
        yes: bool,
    ) -> AddPlan {
        let mut argv = self.options.skills_command.clone();
        argv.push("add".to_string());
        if scope == "global" {
            argv.push("-g".to_string());
        }
        argv.push(source.to_string());
        for skill in skills {
            argv.push("--skill".to_string());
            argv.push(skill.clone());
        }
        for agent in agents {
            argv.push("--agent".to_string());
            argv.push(agent.clone());
        }
        if yes {
            argv.push("-y".to_string());
        }
        AddPlan {
            scope: scope.to_string(),
            reason: reason.to_string(),
            source: source.to_string(),
            skills: skills.to_vec(),
            agents: agents.to_vec(),
            command: command_to_string(&argv),
            argv,
        }
    }

    fn run_skills(&self, args: &[String]) -> Result<ChildResult> {
        let Some(program) = self.options.skills_command.first() else {
            return Err(anyhow!("empty skills command"));
        };
        let command_program = resolve_command_program(program);
        let (capture, stdout_file) = TemporaryCapture::create("list")?;
        let output = Command::new(&command_program)
            .args(self.options.skills_command.iter().skip(1))
            .args(args)
            .env_remove("XDG_STATE_HOME")
            .stdout(Stdio::from(stdout_file))
            .output()
            .map_err(|err| {
                anyhow!(
                    "failed to run {}: {err}",
                    command_to_string(&self.options.skills_command)
                )
            })?;
        let stdout = capture.read_and_remove()?;
        Ok(ChildResult {
            status: output.status.code().unwrap_or(EXIT_USAGE),
            stdout,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn apply_or_report(&mut self) -> i32 {
        if self.options.mode == CommandMode::Status || self.options.dry_run || !self.options.apply {
            return self.finish(0);
        }
        self.dedupe_plans();
        let commands = self.payload.planned_commands.clone();
        for planned in commands {
            let Some(program) = planned.argv.first() else {
                return self.fail(EXIT_USAGE, "empty planned command");
            };
            let command_program = resolve_command_program(program);
            let child = Command::new(&command_program)
                .args(planned.argv.iter().skip(1))
                .env_remove("XDG_STATE_HOME")
                .output();
            let output = match child {
                Ok(output) => output,
                Err(err) => {
                    let message = format!("failed to run {}: {err}", planned.command);
                    return self.fail(EXIT_USAGE, &message);
                }
            };
            if !output.status.success() {
                let mut message = format!("command failed: {}", planned.command);
                if let Err(err) = self.apply_post_command_agent_cleanup() {
                    message.push_str(&format!("; post-command cleanup failed: {err}"));
                }
                self.drop_resolved_agent_link_issues();
                if self.options.json_output {
                    self.payload.stderr =
                        Some(String::from_utf8_lossy(&output.stderr).into_owned());
                }
                return self.fail(EXIT_USAGE, &message);
            }
            self.payload.applied.push(AppliedPlan {
                scope: planned.scope,
                reason: planned.reason,
                source: planned.source,
                skills: planned.skills,
                agents: planned.agents,
                command: planned.command,
            });
            if !self.options.quiet && self.options.verbose && !output.stdout.is_empty() {
                print!("{}", String::from_utf8_lossy(&output.stdout));
            }
        }
        let repairs = self.payload.planned_agent_repairs.clone();
        self.payload.planned_agent_repairs.clear();
        for repair in repairs {
            if !agent_link_repair_still_applies(&repair) {
                continue;
            }
            if let Err(err) = apply_agent_link_repair(&repair) {
                return self.fail(EXIT_USAGE, &err.to_string());
            }
            self.payload.planned_agent_repairs.push(repair.clone());
            self.payload.applied_agent_repairs.push(repair);
        }
        if let Err(err) = self.apply_post_command_agent_cleanup() {
            return self.fail(EXIT_USAGE, &err.to_string());
        }
        if let Err(code) = self.verify_post_apply_agent_visibility() {
            return code;
        }
        self.drop_resolved_agent_link_issues();
        self.finish(0)
    }

    fn verify_post_apply_agent_visibility(&mut self) -> std::result::Result<(), i32> {
        if self.payload.applied.is_empty()
            || self.options.all_agents
            || self.options.forced_agents.is_empty()
        {
            return Ok(());
        }
        let required_agents = self.options.forced_agents.clone();
        let mut failures = Vec::new();
        for scope in ["global", "project"] {
            if !self.payload.applied.iter().any(|plan| plan.scope == scope) {
                continue;
            }
            let installed = self.list_installed(scope)?;
            let installed_by_slug = installed
                .iter()
                .map(|entry| (entry.slug.as_str(), entry))
                .collect::<BTreeMap<_, _>>();
            let desired = if scope == "global" {
                &self.payload.global_desired
            } else {
                &self.payload.project_desired
            };
            for skill in desired {
                let installed_skill = installed_by_slug.get(skill.slug.as_str());
                for agent in &required_agents {
                    let visible = installed_skill.is_some_and(|entry| {
                        entry.agents.iter().any(|visible| visible == agent)
                            || (scope == "global"
                                && agent == "codex"
                                && Self::global_canonical_skill_visible_to_codex(
                                    &home_dir(),
                                    &entry.path,
                                ))
                    });
                    if !visible {
                        failures.push(format!("{scope} skill {} is missing {agent}", skill.name));
                    }
                }
            }
            if scope == "global" {
                self.payload.global_installed = installed;
            } else {
                self.payload.project_installed = installed;
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            let message = format!(
                "post-apply agent verification failed: {}",
                failures.join("; ")
            );
            Err(self.fail(EXIT_USAGE, &message))
        }
    }

    fn drop_resolved_agent_link_issues(&mut self) {
        let repaired_paths = self
            .payload
            .applied_agent_repairs
            .iter()
            .filter_map(agent_repair_path)
            .collect::<BTreeSet<_>>();
        if repaired_paths.is_empty() {
            return;
        }
        self.payload
            .agent_link_issues
            .retain(|issue| !repaired_paths.contains(&issue.path));
    }

    fn apply_post_command_agent_cleanup(&mut self) -> Result<()> {
        if !self.include_global
            || !effective_agent_link_policy(&self.options).reconciles_duplicate_dirs()
        {
            return Ok(());
        }
        let touched_slugs = self
            .payload
            .applied
            .iter()
            .filter(|plan| plan.scope == "global")
            .flat_map(|plan| plan.skills.iter().map(|skill| sanitize_name(skill)))
            .collect::<BTreeSet<_>>();
        if touched_slugs.is_empty() {
            return Ok(());
        }

        let home = home_dir();
        let mut canonical = self.canonical_global_skill_paths();
        for slug in &touched_slugs {
            let path = home.join(".agents/skills").join(slug);
            canonical.insert(
                slug.clone(),
                CanonicalSkill {
                    name: slug.clone(),
                    path: path.clone(),
                    realpath: safe_realpath(&path),
                },
            );
        }
        let mut seen_paths = self
            .payload
            .planned_agent_repairs
            .iter()
            .filter_map(agent_repair_path)
            .collect::<BTreeSet<_>>();
        seen_paths.extend(
            self.payload
                .applied_agent_repairs
                .iter()
                .filter_map(agent_repair_path),
        );
        let canonical_global_dir = home.join(".agents/skills");
        let backup_root = agent_repair_backup_root(&home);
        let agent_dirs = discover_agent_dirs(&home, &self.options.agent_dirs);

        for agent_dir in agent_dirs {
            if same_path(&agent_dir.path, &canonical_global_dir) {
                continue;
            }
            for slug in &touched_slugs {
                let Some(canonical_skill) = canonical.get(slug) else {
                    continue;
                };
                if !canonical_skill.path.exists() {
                    continue;
                }
                let path = agent_dir.path.join(slug);
                let Ok(metadata) = fs::symlink_metadata(&path) else {
                    continue;
                };
                let path_key = path_string(&path);
                if seen_paths.contains(&path_key) {
                    continue;
                }
                if metadata.file_type().is_symlink() {
                    self.apply_post_command_agent_symlink_cleanup(
                        slug,
                        &path,
                        &agent_dir,
                        canonical_skill,
                        &mut seen_paths,
                    )?;
                } else if metadata.is_dir() {
                    self.apply_post_command_agent_directory_cleanup(
                        slug,
                        &path,
                        &agent_dir,
                        canonical_skill,
                        &backup_root,
                        &mut seen_paths,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn apply_post_command_agent_symlink_cleanup(
        &mut self,
        slug: &str,
        path: &Path,
        agent_dir: &AgentDir,
        canonical_skill: &CanonicalSkill,
        seen_paths: &mut BTreeSet<String>,
    ) -> Result<()> {
        if agent_dir.label != "codex" {
            return Ok(());
        }
        let realpath = safe_realpath(path);
        if realpath.is_none() {
            return Ok(());
        }
        if realpath != canonical_skill.realpath
            && !self
                .equivalent_skill_dirs_cached(path, &canonical_skill.path)
                .unwrap_or(false)
        {
            return Ok(());
        }
        let raw_target = fs::read_link(path)
            .map(|target| target.display().to_string())
            .unwrap_or_default();
        self.push_agent_issue(AgentLinkIssue {
            kind: "redundant_codex_symlink".to_string(),
            name: slug.to_string(),
            agent_dir: path_string(&agent_dir.path),
            path: path_string(path),
            target: Some(raw_target.clone()),
            canonical_path: Some(path_string(&canonical_skill.path)),
            detail: "Codex already reads the canonical global ~/.agents/skills entry".to_string(),
        });
        self.apply_post_command_agent_repair(
            AgentLinkRepair::RemoveRedundantSymlink {
                name: slug.to_string(),
                agent_dir: path_string(&agent_dir.path),
                path: path_string(path),
                target: raw_target,
                canonical_path: path_string(&canonical_skill.path),
            },
            seen_paths,
        )
    }

    fn apply_post_command_agent_directory_cleanup(
        &mut self,
        slug: &str,
        path: &Path,
        agent_dir: &AgentDir,
        canonical_skill: &CanonicalSkill,
        backup_root: &Path,
        seen_paths: &mut BTreeSet<String>,
    ) -> Result<()> {
        if safe_realpath(path) == canonical_skill.realpath {
            return Ok(());
        }
        match self.equivalent_skill_dirs_cached(path, &canonical_skill.path) {
            Ok(true) if agent_dir.label == "codex" => {
                self.push_agent_issue(AgentLinkIssue {
                    kind: "redundant_codex_dir".to_string(),
                    name: slug.to_string(),
                    agent_dir: path_string(&agent_dir.path),
                    path: path_string(path),
                    target: None,
                    canonical_path: Some(path_string(&canonical_skill.path)),
                    detail: "Codex already reads the canonical global ~/.agents/skills entry"
                        .to_string(),
                });
                self.apply_post_command_agent_repair(
                    AgentLinkRepair::BackupRedundantDir {
                        name: slug.to_string(),
                        agent_dir: path_string(&agent_dir.path),
                        path: path_string(path),
                        canonical_path: path_string(&canonical_skill.path),
                        backup: path_string(&backup_path_for(backup_root, agent_dir, slug)),
                    },
                    seen_paths,
                )
            }
            Ok(false) if agent_dir.label == "codex" => {
                self.push_agent_issue(AgentLinkIssue {
                    kind: "duplicate_codex_dir".to_string(),
                    name: slug.to_string(),
                    agent_dir: path_string(&agent_dir.path),
                    path: path_string(path),
                    target: None,
                    canonical_path: Some(path_string(&canonical_skill.path)),
                    detail:
                        "same-slug Codex skill differs from the canonical global ~/.agents/skills entry"
                            .to_string(),
                });
                self.apply_post_command_agent_repair(
                    AgentLinkRepair::BackupDuplicateDir {
                        name: slug.to_string(),
                        agent_dir: path_string(&agent_dir.path),
                        path: path_string(path),
                        canonical_path: path_string(&canonical_skill.path),
                        backup: path_string(&backup_path_for(backup_root, agent_dir, slug)),
                    },
                    seen_paths,
                )
            }
            Ok(true) => {
                self.push_agent_issue(AgentLinkIssue {
                    kind: "duplicate_equivalent_dir".to_string(),
                    name: slug.to_string(),
                    agent_dir: path_string(&agent_dir.path),
                    path: path_string(path),
                    target: None,
                    canonical_path: Some(path_string(&canonical_skill.path)),
                    detail: "agent skill directory matches canonical global skill content"
                        .to_string(),
                });
                self.apply_post_command_agent_repair(
                    AgentLinkRepair::ReplaceDuplicateDir {
                        name: slug.to_string(),
                        agent_dir: path_string(&agent_dir.path),
                        path: path_string(path),
                        target: path_string(&canonical_skill.path),
                        backup: path_string(&backup_path_for(backup_root, agent_dir, slug)),
                    },
                    seen_paths,
                )
            }
            Ok(false) => {
                self.push_agent_issue(AgentLinkIssue {
                    kind: "duplicate_conflict_dir".to_string(),
                    name: slug.to_string(),
                    agent_dir: path_string(&agent_dir.path),
                    path: path_string(path),
                    target: None,
                    canonical_path: Some(path_string(&canonical_skill.path)),
                    detail: "agent skill directory differs from canonical global skill content"
                        .to_string(),
                });
                Ok(())
            }
            Err(err) => {
                self.push_agent_issue(AgentLinkIssue {
                    kind: "duplicate_compare_failed".to_string(),
                    name: slug.to_string(),
                    agent_dir: path_string(&agent_dir.path),
                    path: path_string(path),
                    target: None,
                    canonical_path: Some(path_string(&canonical_skill.path)),
                    detail: err.to_string(),
                });
                Ok(())
            }
        }
    }

    fn apply_post_command_agent_repair(
        &mut self,
        repair: AgentLinkRepair,
        seen_paths: &mut BTreeSet<String>,
    ) -> Result<()> {
        let path_key = agent_repair_path(&repair);
        if path_key
            .as_ref()
            .is_some_and(|path| seen_paths.contains(path))
        {
            return Ok(());
        }
        apply_agent_link_repair(&repair)?;
        if let Some(path) = path_key {
            seen_paths.insert(path);
        }
        self.payload.planned_agent_repairs.push(repair.clone());
        self.payload.applied_agent_repairs.push(repair);
        Ok(())
    }

    fn equivalent_skill_dirs_cached(&mut self, left: &Path, right: &Path) -> Result<bool> {
        let left_key = path_string(left);
        let right_key = path_string(right);
        let key = if left_key <= right_key {
            (left_key, right_key)
        } else {
            (right_key, left_key)
        };
        if let Some(cached) = self.skill_dir_compare_cache.get(&key) {
            return cached.clone().map_err(anyhow::Error::msg);
        }
        let result = equivalent_skill_dirs(left, right).map_err(|err| err.to_string());
        self.skill_dir_compare_cache.insert(key, result.clone());
        result.map_err(anyhow::Error::msg)
    }

    fn dedupe_plans(&mut self) {
        let mut seen = BTreeSet::new();
        self.payload.planned_commands.retain(|planned| {
            let key = planned.argv.join("\u{1f}");
            if seen.contains(&key) {
                false
            } else {
                seen.insert(key);
                true
            }
        });
    }

    fn fail(&mut self, code: i32, message: &str) -> i32 {
        push_unique(&mut self.payload.errors, message.to_string());
        if self.options.json_output {
            self.render_json_and_return(code)
        } else {
            let style = self.style();
            eprintln!("{} {}", style.prefix(), style.error(message));
            code
        }
    }

    fn finish_lock_only(&mut self, code: i32) -> i32 {
        if self.options.json_output {
            return self.render_json_and_return(code);
        }
        if !self.options.quiet {
            let style = self.style();
            println!(
                "{} {}",
                style.prefix(),
                style.heading("global lock endpoints")
            );
            for endpoint in &self.payload.lock_endpoints {
                let state = if endpoint.readable {
                    "readable"
                } else if endpoint.exists {
                    "unreadable"
                } else {
                    "missing"
                };
                let target = endpoint
                    .realpath
                    .as_ref()
                    .map(|realpath| format!(" -> {realpath}"))
                    .unwrap_or_default();
                println!(
                    "{} {} {}: {}{}",
                    style.prefix(),
                    style.label(&endpoint.label),
                    style.status(state),
                    style.path(&endpoint.path),
                    target
                );
            }
            for repair in &self.payload.planned_lock_repairs {
                match repair {
                    LockRepair::Write { path, .. } => println!(
                        "{} {} {}",
                        style.prefix(),
                        style.plan(if self.options.dry_run {
                            "would write"
                        } else {
                            "wrote"
                        }),
                        style.path(path)
                    ),
                }
            }
            for warning in &self.payload.warnings {
                println!(
                    "{} {} {}",
                    style.prefix(),
                    style.warning("warning"),
                    warning
                );
            }
            for error in &self.payload.errors {
                eprintln!("{} {}", style.prefix(), style.error(error));
            }
        }
        code
    }

    fn finish(&mut self, code: i32) -> i32 {
        self.dedupe_plans();
        if self.options.json_output {
            return self.render_json_and_return(code);
        }
        if !self.options.quiet {
            let style = self.style();
            println!(
                "{} {} {}",
                style.prefix(),
                style.label("global lock"),
                style.path(&self.payload.global_lock_file)
            );
            if self.include_project {
                if let Some(project_lock_file) = &self.payload.project_lock_file {
                    println!(
                        "{} {} {}",
                        style.prefix(),
                        style.label("project lock"),
                        style.path(project_lock_file)
                    );
                } else if self.options.ignore_project_lock {
                    println!("{} {} ignored", style.prefix(), style.label("project lock"));
                } else {
                    println!(
                        "{} {} not found at {}",
                        style.prefix(),
                        style.label("project lock"),
                        style.path(self.options.project_lock_file.display().to_string())
                    );
                }
            }
            println!(
                "{} {} {}",
                style.prefix(),
                style.label("using"),
                command_to_string(&self.options.skills_command)
            );
            for repair in &self.payload.planned_lock_repairs {
                match repair {
                    LockRepair::Write { path, .. } => println!(
                        "{} {} lock {}",
                        style.prefix(),
                        style.plan(if self.options.dry_run {
                            "would write"
                        } else {
                            "wrote"
                        }),
                        style.path(path)
                    ),
                }
            }
            let add_count = self.payload.global_to_add.len() + self.payload.project_to_add.len();
            let link_count = self.payload.global_to_link.len() + self.payload.project_to_link.len();
            let adopt_count =
                self.payload.global_to_adopt.len() + self.payload.project_to_adopt.len();
            let agent_repair_count = self.payload.planned_agent_repairs.len();
            println!(
                "{} {}",
                style.prefix(),
                style.summary(&format!(
                    "{add_count} restore(s), {link_count} link repair(s), {adopt_count} adoption(s), {agent_repair_count} agent repair(s), {} planned command(s)",
                self.payload.planned_commands.len()
                ))
            );
            if self.payload.planned_commands.is_empty()
                && self.payload.planned_lock_repairs.is_empty()
                && self.payload.planned_agent_repairs.is_empty()
            {
                println!(
                    "{} {}",
                    style.prefix(),
                    style.ok("selected scopes already match their lock files")
                );
            } else {
                for repair in &self.payload.planned_agent_repairs {
                    println!(
                        "{} {} [agent-link:{}] {}",
                        style.prefix(),
                        style.plan(
                            if self.options.dry_run || self.options.mode == CommandMode::Status {
                                "plan"
                            } else {
                                "repaired"
                            }
                        ),
                        agent_repair_action(repair),
                        agent_repair_summary(repair)
                    );
                }
                for planned in &self.payload.planned_commands {
                    println!(
                        "{} {} [{}:{}] {}",
                        style.prefix(),
                        style.plan("plan"),
                        planned.scope,
                        planned.reason,
                        planned.command
                    );
                }
            }
            if !self.payload.agent_link_issues.is_empty()
                && (self.options.mode == CommandMode::Doctor || self.options.verbose)
            {
                println!(
                    "{} {} {} agent skill link issue(s)",
                    style.prefix(),
                    style.advisory("info"),
                    self.payload.agent_link_issues.len()
                );
                for issue in &self.payload.agent_link_issues {
                    println!(
                        "{} {} [{}] {}: {}",
                        style.prefix(),
                        style.advisory(&issue.kind),
                        issue.agent_dir,
                        issue.name,
                        issue.detail
                    );
                }
            }
            if !self.payload.untracked_installed.is_empty()
                && (self.options.mode == CommandMode::Doctor || self.options.verbose)
            {
                println!(
                    "{} {} {} installed skill(s) could not be adopted automatically",
                    style.prefix(),
                    style.advisory("info"),
                    self.payload.untracked_installed.len()
                );
            }
            for skipped in &self.payload.skipped {
                println!(
                    "{} {} [{}] {}: {}",
                    style.prefix(),
                    style.advisory("skipped"),
                    skipped.scope,
                    skipped.name,
                    skipped.reason
                );
            }
            for warning in &self.payload.warnings {
                println!(
                    "{} {} {}",
                    style.prefix(),
                    style.warning("warning"),
                    warning
                );
            }
        }
        code
    }

    fn style(&self) -> Style {
        Style {
            enabled: self.options.color_mode.enabled(self.options.json_output),
        }
    }

    fn render_json_and_return(&self, code: i32) -> i32 {
        println!(
            "{}",
            serde_json::to_string_pretty(&self.payload).unwrap_or_else(|_| "{}".to_string())
        );
        code
    }
}

#[derive(Clone, Copy, Debug)]
struct Style {
    enabled: bool,
}

impl Style {
    fn paint(self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn prefix(self) -> String {
        self.paint("1;34", "skills-sync:")
    }

    fn heading(self, text: &str) -> String {
        self.paint("1", text)
    }

    fn label(self, text: &str) -> String {
        self.paint("36", text)
    }

    fn status(self, text: &str) -> String {
        match text {
            "readable" => self.ok(text),
            "unreadable" => self.warning(text),
            "missing" => self.paint("2", text),
            _ => text.to_string(),
        }
    }

    fn path(self, value: impl std::fmt::Display) -> String {
        self.paint("36", &value.to_string())
    }

    fn summary(self, text: &str) -> String {
        self.paint("1", text)
    }

    fn ok(self, text: &str) -> String {
        self.paint("32", text)
    }

    fn plan(self, text: &str) -> String {
        self.paint("35", text)
    }

    fn advisory(self, text: &str) -> String {
        self.paint("2", text)
    }

    fn warning(self, text: &str) -> String {
        self.paint("33", text)
    }

    fn error(self, text: &str) -> String {
        self.paint("31", text)
    }
}

#[derive(Clone, Debug)]
struct ChildResult {
    status: i32,
    stdout: String,
    stderr: String,
}

#[derive(Debug)]
struct TemporaryCapture {
    path: PathBuf,
}

impl TemporaryCapture {
    fn create(label: &str) -> Result<(Self, File)> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let process_id = std::process::id();
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "skills-sync-{label}-{process_id}-{timestamp}-{attempt}.json"
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            match options.open(&path) {
                Ok(file) => return Ok((Self { path }, file)),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(anyhow!("failed to create temporary {label} capture: {err}"));
                }
            }
        }
        Err(anyhow!(
            "failed to create temporary {label} capture: unique path unavailable"
        ))
    }

    fn read_and_remove(self) -> Result<String> {
        let contents = fs::read_to_string(&self.path).with_context(|| {
            format!(
                "failed to read temporary skills output from {}",
                self.path.display()
            )
        })?;
        fs::remove_file(&self.path).with_context(|| {
            format!(
                "failed to remove temporary skills output {}",
                self.path.display()
            )
        })?;
        Ok(contents)
    }
}

impl Drop for TemporaryCapture {
    fn drop(&mut self) {
        let _cleanup_result = fs::remove_file(&self.path);
    }
}

#[derive(Clone, Debug)]
struct SourceInference {
    source: String,
    skill: Option<String>,
    reason: String,
    prefer_all_agents: bool,
}

impl SourceInference {
    fn empty(reason: &str) -> Self {
        Self {
            source: String::new(),
            skill: None,
            reason: reason.to_string(),
            prefer_all_agents: false,
        }
    }
}

#[derive(Clone, Debug)]
struct AgentDir {
    label: String,
    path: PathBuf,
}

#[derive(Clone, Debug)]
struct CanonicalSkill {
    name: String,
    path: PathBuf,
    realpath: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SkillTreeEntry {
    File(Vec<u8>),
    Symlink(String),
}

fn command_name(mode: &CommandMode) -> &'static str {
    match mode {
        CommandMode::Sync => "sync",
        CommandMode::Status => "status",
        CommandMode::Doctor => "doctor",
        CommandMode::Lock => "lock",
        CommandMode::Adopt => "adopt",
        CommandMode::Help => "help",
    }
}

fn required_value<'a>(args: &'a [String], index: usize, option: &str) -> Result<&'a str> {
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("{option} requires a value"))
}

fn env_string(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn resolve_command_program(program: &str) -> PathBuf {
    let path = Path::new(program);
    if path.is_absolute()
        || path
            .parent()
            .is_some_and(|parent| !parent.as_os_str().is_empty())
    {
        return path.to_path_buf();
    }

    #[cfg(windows)]
    {
        if path.extension().is_some() {
            return path.to_path_buf();
        }

        let path_var = std::env::var_os("PATH").unwrap_or_default();
        let pathext =
            std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
        let extensions: Vec<String> = pathext
            .split(';')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                if value.starts_with('.') {
                    value.to_string()
                } else {
                    format!(".{value}")
                }
            })
            .collect();

        for dir in std::env::split_paths(&path_var) {
            for extension in &extensions {
                let candidate = dir.join(format!("{program}{extension}"));
                if candidate.is_file() {
                    return candidate;
                }
            }
        }
    }

    path.to_path_buf()
}

fn env_path(name: &str) -> Option<PathBuf> {
    env_string(name).map(|value| expand_home_path(&value))
}

fn env_paths(name: &str) -> Vec<PathBuf> {
    let Some(value) = env_string(name) else {
        return Vec::new();
    };
    std::env::split_paths(&value)
        .map(|path| expand_home_path(&path.to_string_lossy()))
        .collect()
}

fn env_bool(name: &str) -> Result<bool> {
    let Some(value) = env_string(name) else {
        return Ok(false);
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" => Ok(true),
        "0" | "false" | "no" | "n" | "off" => Ok(false),
        _ => Err(anyhow!(
            "{name} must be one of 1/0, true/false, yes/no, on/off"
        )),
    }
}

fn env_scope() -> Result<Option<Scope>> {
    env_string("SKILLS_SYNC_SCOPE")
        .map(|value| Scope::parse(&value))
        .transpose()
}

fn env_agents() -> Vec<String> {
    let mut agents = Vec::new();
    if let Some(value) = env_string("SKILLS_SYNC_AGENTS") {
        agents.extend(
            value
                .split(',')
                .map(str::trim)
                .filter(|agent| !agent.is_empty())
                .map(ToString::to_string),
        );
    }
    normalize_agents(&agents)
}

fn env_color_mode() -> Result<ColorMode> {
    if let Some(value) = env_string("SKILLS_SYNC_COLOR") {
        return ColorMode::parse(&value);
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return Ok(ColorMode::Never);
    }
    if let Some(value) = env_string("CLICOLOR_FORCE") {
        if value != "0" {
            return Ok(ColorMode::Always);
        }
    }
    Ok(ColorMode::Auto)
}

fn effective_agent_link_policy(options: &Options) -> AgentLinkPolicy {
    if let Some(policy) = options.agent_link_policy {
        return policy;
    }
    match options.mode {
        CommandMode::Doctor | CommandMode::Status => AgentLinkPolicy::Reconcile,
        CommandMode::Sync | CommandMode::Lock | CommandMode::Adopt | CommandMode::Help => {
            AgentLinkPolicy::Off
        }
    }
}

fn discover_agent_dirs(home: &Path, custom_dirs: &[PathBuf]) -> Vec<AgentDir> {
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    let claude_home = std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".claude"));

    let mut candidates = vec![
        AgentDir {
            label: "agents".to_string(),
            path: home.join(".agents/skills"),
        },
        AgentDir {
            label: "config-agents".to_string(),
            path: config_home.join("agents/skills"),
        },
        codex_private_skill_dir(home),
        AgentDir {
            label: "claude-code".to_string(),
            path: claude_home.join("skills"),
        },
        AgentDir {
            label: "gemini-cli".to_string(),
            path: home.join(".gemini/skills"),
        },
        AgentDir {
            label: "antigravity".to_string(),
            path: home.join(".gemini/antigravity/skills"),
        },
        AgentDir {
            label: "cursor".to_string(),
            path: home.join(".cursor/skills"),
        },
        AgentDir {
            label: "opencode".to_string(),
            path: config_home.join("opencode/skills"),
        },
        AgentDir {
            label: "continue".to_string(),
            path: home.join(".continue/skills"),
        },
        AgentDir {
            label: "factory".to_string(),
            path: home.join(".factory/skills"),
        },
    ];
    for (index, path) in custom_dirs.iter().enumerate() {
        candidates.push(AgentDir {
            label: format!("custom-{}", index + 1),
            path: path.clone(),
        });
    }

    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for candidate in candidates {
        if !candidate.path.is_dir() {
            continue;
        }
        let key = safe_realpath(&candidate.path).unwrap_or_else(|| candidate.path.clone());
        if seen.insert(path_string(&key)) {
            out.push(candidate);
        }
    }
    out
}

fn codex_private_skill_dir(home: &Path) -> AgentDir {
    let codex_home = codex_home_dir(home);
    AgentDir {
        label: "codex".to_string(),
        path: codex_home.join("skills"),
    }
}

fn codex_home_dir(home: &Path) -> PathBuf {
    std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".codex"))
}

fn agent_skill_dir(home: &Path, agent: &str) -> Option<AgentDir> {
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    let claude_home = std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".claude"));
    let path = match agent {
        "amp" => config_home.join("agents/skills"),
        "antigravity" => home.join(".gemini/antigravity/skills"),
        "claude-code" => claude_home.join("skills"),
        "cline" => home.join(".agents/skills"),
        "codex" => home.join(".agents/skills"),
        "cursor" => home.join(".cursor/skills"),
        "deepagents" => home.join(".deepagents/agent/skills"),
        "droid" => home.join(".factory/skills"),
        "gemini-cli" => home.join(".gemini/skills"),
        "github-copilot" => home.join(".copilot/skills"),
        "kimi-cli" => home.join(".config/agents/skills"),
        "opencode" => config_home.join("opencode/skills"),
        _ => return None,
    };
    Some(AgentDir {
        label: agent.to_string(),
        path,
    })
}

fn same_path(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    safe_realpath(left).is_some_and(|left_real| safe_realpath(right) == Some(left_real))
}

fn build_global_endpoints(options: &Options, canonical: &Path) -> Vec<Endpoint> {
    if let Some(override_path) = &options.global_lock_file {
        return vec![inspect_endpoint("override", "selected", override_path)];
    }
    vec![inspect_endpoint("canonical", "source", canonical)]
}

fn inspect_endpoint(label: &str, role: &str, path: &Path) -> Endpoint {
    let mut endpoint = Endpoint {
        label: label.to_string(),
        role: role.to_string(),
        path: path.to_path_buf(),
        exists: false,
        symlink: false,
        readable: false,
        broken: false,
        realpath: None,
        lock: None,
        error: None,
    };
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            endpoint.exists = true;
            endpoint.symlink = metadata.file_type().is_symlink();
            match fs::canonicalize(path) {
                Ok(realpath) => endpoint.realpath = Some(realpath),
                Err(_) => endpoint.broken = endpoint.symlink,
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => return endpoint,
        Err(err) => {
            endpoint.error = Some(err.to_string());
            return endpoint;
        }
    }
    match fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(lock) => {
                endpoint.lock = Some(lock);
                endpoint.readable = true;
            }
            Err(err) => endpoint.error = Some(err.to_string()),
        },
        Err(err) => endpoint.error = Some(err.to_string()),
    }
    endpoint
}

fn endpoint_summary(endpoint: &Endpoint) -> EndpointSummary {
    EndpointSummary {
        label: endpoint.label.clone(),
        role: endpoint.role.clone(),
        path: path_string(&endpoint.path),
        exists: endpoint.exists,
        symlink: endpoint.symlink,
        readable: endpoint.readable,
        broken: endpoint.broken,
        realpath: endpoint.realpath.as_ref().map(|path| path_string(path)),
        error: endpoint.error.clone(),
    }
}

fn select_global_lock(
    endpoints: &[Endpoint],
    options: &Options,
    required: bool,
) -> GlobalLockSelection {
    if options.global_lock_file.is_some() {
        let selected = endpoints.first().cloned();
        if selected.as_ref().is_none_or(|endpoint| !endpoint.readable) {
            if required {
                return GlobalLockSelection {
                    selected,
                    lock: create_empty_global_lock(),
                    warnings: Vec::new(),
                    errors: vec![format!(
                        "global lock file not found or unreadable: {}",
                        options
                            .global_lock_file
                            .as_ref()
                            .map(|path| path_string(path))
                            .unwrap_or_default()
                    )],
                };
            }
            return GlobalLockSelection {
                selected,
                lock: create_empty_global_lock(),
                warnings: Vec::new(),
                errors: Vec::new(),
            };
        }
        let lock = selected
            .as_ref()
            .and_then(|endpoint| endpoint.lock.as_ref())
            .map(normalize_global_lock)
            .unwrap_or_else(create_empty_global_lock);
        return GlobalLockSelection {
            selected,
            lock,
            warnings: Vec::new(),
            errors: Vec::new(),
        };
    }

    let selected = endpoints.first().cloned();
    let mut errors = Vec::new();
    if required && selected.as_ref().is_none_or(|endpoint| !endpoint.readable) {
        errors.push(format!(
            "global lock file not found or unreadable: {}",
            selected
                .as_ref()
                .map(|endpoint| path_string(&endpoint.path))
                .unwrap_or_default()
        ));
    }
    let lock = selected
        .as_ref()
        .filter(|endpoint| endpoint.readable)
        .and_then(|endpoint| endpoint.lock.as_ref())
        .map(normalize_global_lock)
        .unwrap_or_else(create_empty_global_lock);
    GlobalLockSelection {
        selected,
        lock,
        warnings: Vec::new(),
        errors,
    }
}

fn read_lock_file(path: &Path, required: bool) -> Result<ReadLock> {
    if !path.exists() {
        if required {
            return Err(anyhow!("lock file not found: {}", path.display()));
        }
        return Ok(ReadLock {
            path: path.to_path_buf(),
            present: false,
            lock: create_empty_project_lock(),
        });
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read JSON from {}", path.display()))?;
    let lock: Value = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse JSON from {}", path.display()))?;
    if !lock.is_object() {
        return Err(anyhow!(
            "lock file {} must be a JSON object",
            path.display()
        ));
    }
    if !lock.get("skills").is_some_and(Value::is_object) {
        return Err(anyhow!(
            "lock file {} must contain a top-level \"skills\" object",
            path.display()
        ));
    }
    Ok(ReadLock {
        path: path.to_path_buf(),
        present: true,
        lock,
    })
}

fn create_empty_global_lock() -> Value {
    json!({"version": 3, "skills": {}, "dismissed": {}})
}

fn create_empty_project_lock() -> Value {
    json!({"version": 1, "skills": {}})
}

fn normalize_global_lock(lock: &Value) -> Value {
    let Some(object) = lock.as_object() else {
        return create_empty_global_lock();
    };
    if !object.get("version").is_some_and(Value::is_number)
        || !object.get("skills").is_some_and(Value::is_object)
    {
        return create_empty_global_lock();
    }
    let mut normalized = object.clone();
    if !normalized.get("dismissed").is_some_and(Value::is_object) {
        normalized.insert("dismissed".to_string(), json!({}));
    }
    Value::Object(normalized)
}

fn merge_lock_into(
    target: &mut Value,
    source: &Value,
    endpoint: &Endpoint,
    imported: &mut Vec<ImportedSkill>,
    errors: &mut Vec<String>,
    report_imports: bool,
) {
    let Some(source_skills) = source.get("skills").and_then(Value::as_object) else {
        return;
    };
    let Some(target_object) = target.as_object_mut() else {
        errors.push("global lock merge target is not a JSON object".to_string());
        return;
    };
    {
        let Some(target_skills) = target_object
            .get_mut("skills")
            .and_then(Value::as_object_mut)
        else {
            errors.push("global lock merge target has no skills object".to_string());
            return;
        };
        for (name, entry) in source_skills {
            match target_skills.get(name) {
                None => {
                    target_skills.insert(name.clone(), entry.clone());
                    if report_imports {
                        imported.push(ImportedSkill {
                            from: path_string(&endpoint.path),
                            name: name.clone(),
                        });
                    }
                }
                Some(existing) if existing != entry => {
                    if lock_entries_share_source(existing, entry) {
                        if lock_entry_updated_at(entry) > lock_entry_updated_at(existing) {
                            target_skills.insert(name.clone(), entry.clone());
                            if report_imports {
                                imported.push(ImportedSkill {
                                    from: path_string(&endpoint.path),
                                    name: name.clone(),
                                });
                            }
                        }
                    } else {
                        errors.push(format!(
                            "global lock entry conflict for \"{name}\" between {} and another lock endpoint",
                            endpoint.path.display()
                        ));
                    }
                }
                Some(_) => {}
            }
        }
    }
    for key in ["lastSelectedAgents", "lastSelectedGlobalAgents"] {
        let should_copy = !target_object.contains_key(key);
        if should_copy {
            if let Some(value) = source.get(key).filter(|value| value.is_array()) {
                target_object.insert(key.to_string(), value.clone());
            }
        }
    }
    if let Some(source_dismissed) = source.get("dismissed").and_then(Value::as_object) {
        let target_dismissed = target_object
            .entry("dismissed".to_string())
            .or_insert_with(|| json!({}));
        if let Some(target_dismissed) = target_dismissed.as_object_mut() {
            for (key, value) in source_dismissed {
                target_dismissed.insert(key.clone(), value.clone());
            }
        }
    }
}

fn lock_entries_share_source(left: &Value, right: &Value) -> bool {
    ["source", "sourceType", "sourceUrl", "skillPath"]
        .iter()
        .all(|key| left.get(*key) == right.get(*key))
}

fn lock_entry_updated_at(entry: &Value) -> Option<&str> {
    entry.get("updatedAt").and_then(Value::as_str)
}

fn normalize_lock_skills(
    lock: &Value,
    scope: &str,
) -> std::result::Result<NormalizedLockSkills, InvalidLockSkills> {
    let mut normalized = Vec::new();
    let mut skipped = Vec::new();
    let mut errors = Vec::new();
    let Some(skills) = lock.get("skills").and_then(Value::as_object) else {
        return Ok(NormalizedLockSkills {
            desired: normalized,
            skipped,
        });
    };
    for (skill_name, meta) in skills {
        let source = build_install_source(meta);
        if source.is_empty() {
            let reason = format!("{scope} lock entry \"{skill_name}\" is missing source metadata");
            skipped.push(SkippedSkill {
                scope: scope.to_string(),
                name: skill_name.clone(),
                reason: reason.clone(),
            });
            errors.push(reason);
            continue;
        }
        normalized.push(DesiredSkill {
            name: skill_name.clone(),
            slug: sanitize_name(skill_name),
            scope: scope.to_string(),
            source,
            lock_source: meta
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            source_ref: meta
                .get("ref")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            source_url: meta
                .get("sourceUrl")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        });
    }
    if errors.is_empty() {
        Ok(NormalizedLockSkills {
            desired: normalized,
            skipped,
        })
    } else {
        Err(InvalidLockSkills { errors, skipped })
    }
}

impl DesiredSkill {
    fn repair_source(&self) -> String {
        if self.lock_source.is_empty() {
            self.source.clone()
        } else {
            append_ref(&self.lock_source, &self.source_ref)
        }
    }
}

fn build_install_source(entry: &Value) -> String {
    let Some(entry) = entry.as_object() else {
        return String::new();
    };
    let ref_value = json_string(entry, "ref");
    let source = json_string(entry, "source");
    let source_url = json_string(entry, "sourceUrl");
    let skill_path = json_string(entry, "skillPath");
    if !skill_path.is_empty() && !source.is_empty() {
        let source = format!(
            "{}/{}",
            source.trim_end_matches('/'),
            derive_skill_folder(&skill_path)
        );
        return append_ref(&source, &ref_value);
    }
    if !source_url.is_empty() {
        return append_ref(&source_url, &ref_value);
    }
    if !source.is_empty() {
        return append_ref(&source, &ref_value);
    }
    String::new()
}

fn json_string(entry: &Map<String, Value>, key: &str) -> String {
    entry
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string()
}

fn derive_skill_folder(skill_path: &str) -> String {
    skill_path
        .strip_suffix("/SKILL.md")
        .or_else(|| skill_path.strip_suffix("SKILL.md"))
        .unwrap_or(skill_path)
        .trim_end_matches('/')
        .to_string()
}

fn append_ref(source: &str, ref_value: &str) -> String {
    if ref_value.is_empty() {
        source.to_string()
    } else {
        format!("{source}#{ref_value}")
    }
}

fn infer_git_source(skill_dir: &Path) -> SourceInference {
    let skill_path = fs::canonicalize(skill_dir).unwrap_or_else(|_| skill_dir.to_path_buf());
    let root_output = Command::new("git")
        .arg("-C")
        .arg(&skill_path)
        .args(["rev-parse", "--show-toplevel"])
        .output();
    let Ok(root_output) = root_output else {
        return SourceInference::empty("installed skill is not inside a Git worktree");
    };
    if !root_output.status.success() {
        return SourceInference::empty("installed skill is not inside a Git worktree");
    }
    let root = String::from_utf8_lossy(&root_output.stdout)
        .trim()
        .to_string();
    let remote_output = Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["remote", "get-url", "origin"])
        .output();
    let Ok(remote_output) = remote_output else {
        return SourceInference::empty("Git worktree has no origin remote");
    };
    if !remote_output.status.success() {
        return SourceInference::empty("Git worktree has no origin remote");
    }
    let remote = String::from_utf8_lossy(&remote_output.stdout)
        .trim()
        .to_string();
    let owner_repo = github_owner_repo(&remote);
    if owner_repo.is_empty() {
        return SourceInference::empty("Git origin is not a supported GitHub remote");
    }
    let root_path = fs::canonicalize(&root).unwrap_or_else(|_| PathBuf::from(&root));
    let Ok(relative) = skill_path.strip_prefix(&root_path) else {
        return SourceInference::empty("skill path is outside the inferred Git root");
    };
    if relative.as_os_str().is_empty() {
        return SourceInference::empty("skill path is outside the inferred Git root");
    }
    let relative = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    SourceInference {
        source: format!("{owner_repo}/{relative}"),
        skill: None,
        reason: format!("GitHub origin {owner_repo}"),
        prefer_all_agents: false,
    }
}

fn github_owner_repo(remote: &str) -> String {
    if let Some(rest) = remote.strip_prefix("git@github.com:") {
        return trim_github_repo_suffix(rest);
    }
    if let Some(rest) = remote.strip_prefix("https://github.com/") {
        return trim_github_repo_suffix(rest);
    }
    String::new()
}

fn trim_github_repo_suffix(rest: &str) -> String {
    let rest = rest.trim_end_matches('/');
    let mut parts = rest.split('/');
    let Some(owner) = parts.next() else {
        return String::new();
    };
    let Some(repo) = parts.next() else {
        return String::new();
    };
    if parts.next().is_some() {
        return String::new();
    }
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    if owner.is_empty() || repo.is_empty() {
        String::new()
    } else {
        format!("{owner}/{repo}")
    }
}

fn infer_metadata_source(skill_dir: &Path) -> SourceInference {
    let skill_file = skill_dir.join("SKILL.md");
    let Ok(text) = fs::read_to_string(skill_file) else {
        return SourceInference::empty("SKILL.md unavailable for metadata inference");
    };
    let Some(frontmatter) = text.strip_prefix("---\n") else {
        return SourceInference::empty("SKILL.md has no frontmatter source metadata");
    };
    let Some((frontmatter, _rest)) = frontmatter.split_once("\n---") else {
        return SourceInference::empty("SKILL.md has no frontmatter source metadata");
    };
    for line in frontmatter.lines() {
        let trimmed = line.trim();
        for key in ["source:", "sourceUrl:", "source_url:"] {
            if let Some(value) = trimmed.strip_prefix(key) {
                let value = value
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string();
                if !value.is_empty() {
                    return SourceInference {
                        source: value,
                        skill: None,
                        reason: "SKILL.md source metadata".to_string(),
                        prefer_all_agents: false,
                    };
                }
            }
        }
    }
    SourceInference::empty("SKILL.md frontmatter has no source metadata")
}

fn infer_codex_desktop_vendor_source(
    home: &Path,
    installed_entry: &InstalledSkill,
    skill_dir: &Path,
) -> SourceInference {
    let codex_home = codex_home_dir(home);
    let cache_path = codex_home.join("vendor_imports/skills-curated-cache.json");
    let vendor_root = codex_home.join("vendor_imports/skills");
    if !cache_path.is_file() || !vendor_root.is_dir() {
        return SourceInference::empty("Codex Desktop vendor import cache unavailable");
    }
    let Ok(cache_text) = fs::read_to_string(&cache_path) else {
        return SourceInference::empty("Codex Desktop vendor import cache unreadable");
    };
    let Ok(cache) = serde_json::from_str::<Value>(&cache_text) else {
        return SourceInference::empty("Codex Desktop vendor import cache is invalid JSON");
    };
    let Some(entries) = cache
        .get("skills")
        .and_then(Value::as_array)
        .or_else(|| cache.as_array())
    else {
        return SourceInference::empty("Codex Desktop vendor import cache has no skills array");
    };

    let mut matched_entry = false;
    for entry in entries {
        if !codex_vendor_entry_matches(entry, &installed_entry.slug) {
            continue;
        }
        let Some(repo_path) = entry.get("repoPath").and_then(Value::as_str) else {
            continue;
        };
        let Some(relative_path) = safe_relative_repo_path(repo_path) else {
            continue;
        };
        let candidate_dir = vendor_root.join(relative_path);
        if !candidate_dir.is_dir() {
            continue;
        }
        matched_entry = true;
        match equivalent_skill_dirs(skill_dir, &candidate_dir) {
            Ok(true) => {
                let source = infer_git_source(&candidate_dir);
                if source.source.is_empty() {
                    return SourceInference::empty(
                        "Codex Desktop vendor import matched but GitHub source was unavailable",
                    );
                }
                return SourceInference {
                    source: source.source,
                    skill: Some(installed_entry.name.clone()),
                    reason: format!("Codex Desktop vendor import via {}", source.reason),
                    prefer_all_agents: true,
                };
            }
            Ok(false) => {}
            Err(_err) => {}
        }
    }

    if matched_entry {
        SourceInference::empty("Codex Desktop vendor import did not match installed content")
    } else {
        SourceInference::empty("no matching Codex Desktop vendor import could be inferred")
    }
}

fn codex_vendor_entry_matches(entry: &Value, slug: &str) -> bool {
    ["id", "name"].iter().any(|key| {
        entry
            .get(*key)
            .and_then(Value::as_str)
            .is_some_and(|value| sanitize_name(value) == slug)
    }) || entry
        .get("repoPath")
        .and_then(Value::as_str)
        .is_some_and(|value| {
            safe_relative_repo_path(value)
                .and_then(|path| {
                    path.file_name()
                        .map(|name| name.to_string_lossy().to_string())
                })
                .is_some_and(|name| sanitize_name(&name) == slug)
        })
}

fn safe_relative_repo_path(raw: &str) -> Option<PathBuf> {
    let path = Path::new(raw);
    if path.is_absolute() {
        return None;
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => out.push(part),
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

fn agent_repair_backup_root(home: &Path) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    home.join(".local/state/skills-sync/backups")
        .join(timestamp.to_string())
}

fn backup_path_for(backup_root: &Path, agent_dir: &AgentDir, name: &str) -> PathBuf {
    backup_root.join(sanitize_name(&agent_dir.label)).join(name)
}

fn equivalent_skill_dirs(left: &Path, right: &Path) -> Result<bool> {
    let left_entries = collect_skill_dir_entries(left)
        .with_context(|| format!("read skill tree {}", left.display()))?;
    let right_entries = collect_skill_dir_entries(right)
        .with_context(|| format!("read skill tree {}", right.display()))?;
    Ok(left_entries == right_entries)
}

fn collect_skill_dir_entries(root: &Path) -> Result<Vec<(String, SkillTreeEntry)>> {
    let mut entries = Vec::new();
    collect_skill_dir_entries_inner(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

fn collect_skill_dir_entries_inner(
    root: &Path,
    current: &Path,
    entries: &mut Vec<(String, SkillTreeEntry)>,
) -> Result<()> {
    for entry in fs::read_dir(current).with_context(|| format!("read {}", current.display()))? {
        let entry = entry?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            entries.push((
                relative,
                SkillTreeEntry::Symlink(
                    fs::read_link(&path)
                        .map(|target| target.display().to_string())
                        .unwrap_or_default(),
                ),
            ));
        } else if metadata.is_dir() {
            if should_skip_skill_tree_dir(&entry.file_name().to_string_lossy()) {
                continue;
            }
            collect_skill_dir_entries_inner(root, &path, entries)?;
        } else if metadata.is_file() {
            entries.push((relative, SkillTreeEntry::File(fs::read(&path)?)));
        }
    }
    Ok(())
}

fn should_skip_skill_tree_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".hg" | ".svn" | "node_modules" | "target" | ".cache" | "__pycache__"
    )
}

fn write_json_following_useful_symlink(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create lock directory {}", parent.display()))?;
    }
    if fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
        && fs::canonicalize(path).is_err()
    {
        fs::remove_file(path)
            .with_context(|| format!("remove broken symlink {}", path.display()))?;
    }
    fs::write(
        path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(value).context("serialize lock JSON")?
        ),
    )
    .with_context(|| format!("write lock {}", path.display()))
}

fn apply_agent_link_repair(repair: &AgentLinkRepair) -> Result<()> {
    match repair {
        AgentLinkRepair::CreateMissingSymlink { path, target, .. } => {
            let path = PathBuf::from(path);
            let target = PathBuf::from(target);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("create agent skill directory {}", parent.display())
                })?;
            }
            match fs::symlink_metadata(&path) {
                Ok(_) => Ok(()),
                Err(err) if err.kind() == ErrorKind::NotFound => symlink_path(&target, &path, true)
                    .with_context(|| format!("symlink {} -> {}", path.display(), target.display())),
                Err(err) => {
                    Err(err).with_context(|| format!("inspect agent skill link {}", path.display()))
                }
            }
        }
        AgentLinkRepair::RemoveBrokenSymlink { path, .. } => {
            let path = PathBuf::from(path);
            remove_path(&path)
                .with_context(|| format!("remove broken agent skill link {}", path.display()))
        }
        AgentLinkRepair::RemoveInvalidSymlink { path, .. } => {
            let path = PathBuf::from(path);
            remove_path(&path)
                .with_context(|| format!("remove invalid agent skill link {}", path.display()))
        }
        AgentLinkRepair::RemoveRedundantSymlink { path, .. } => {
            let path = PathBuf::from(path);
            remove_path(&path)
                .with_context(|| format!("remove redundant Codex skill link {}", path.display()))
        }
        AgentLinkRepair::ReplaceNoncanonicalSymlink {
            path,
            old_target,
            target,
            ..
        } => {
            let path = PathBuf::from(path);
            let old_target = PathBuf::from(old_target);
            let target = PathBuf::from(target);
            remove_path(&path).with_context(|| {
                format!("remove noncanonical agent skill link {}", path.display())
            })?;
            if let Err(err) = symlink_path(&target, &path, true) {
                let _ = symlink_path(&old_target, &path, true);
                return Err(anyhow!(
                    "symlink {} -> {} failed after removing old link: {err}",
                    path.display(),
                    target.display()
                ));
            }
            Ok(())
        }
        AgentLinkRepair::BackupRedundantDir { path, backup, .. } => {
            let path = PathBuf::from(path);
            let backup = PathBuf::from(backup);
            if let Some(parent) = backup.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create backup directory {}", parent.display()))?;
            }
            fs::rename(&path, &backup).with_context(|| {
                format!(
                    "move redundant Codex skill directory {} -> {}",
                    path.display(),
                    backup.display()
                )
            })
        }
        AgentLinkRepair::BackupDuplicateDir { path, backup, .. } => {
            let path = PathBuf::from(path);
            let backup = PathBuf::from(backup);
            if let Some(parent) = backup.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create backup directory {}", parent.display()))?;
            }
            fs::rename(&path, &backup).with_context(|| {
                format!(
                    "move duplicate Codex skill directory {} -> {}",
                    path.display(),
                    backup.display()
                )
            })
        }
        AgentLinkRepair::ReplaceDuplicateDir {
            path,
            target,
            backup,
            ..
        } => {
            let path = PathBuf::from(path);
            let target = PathBuf::from(target);
            let backup = PathBuf::from(backup);
            if let Some(parent) = backup.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create backup directory {}", parent.display()))?;
            }
            fs::rename(&path, &backup).with_context(|| {
                format!(
                    "move duplicate agent skill directory {} -> {}",
                    path.display(),
                    backup.display()
                )
            })?;
            if let Err(err) = symlink_path(&target, &path, true) {
                let _ = fs::rename(&backup, &path);
                return Err(anyhow!(
                    "symlink {} -> {} failed after backup move: {err}",
                    path.display(),
                    target.display()
                ));
            }
            Ok(())
        }
    }
}

fn agent_link_repair_still_applies(repair: &AgentLinkRepair) -> bool {
    match repair {
        AgentLinkRepair::CreateMissingSymlink { path, .. } => {
            matches!(
                fs::symlink_metadata(path),
                Err(err) if err.kind() == ErrorKind::NotFound
            )
        }
        AgentLinkRepair::RemoveBrokenSymlink { path, target, .. } => {
            link_target_matches(path, target) && safe_realpath(Path::new(path)).is_none()
        }
        AgentLinkRepair::RemoveInvalidSymlink { path, target, .. } => {
            link_target_matches(path, target) && !Path::new(path).join("SKILL.md").is_file()
        }
        AgentLinkRepair::RemoveRedundantSymlink { path, target, .. } => {
            link_target_matches(path, target)
        }
        AgentLinkRepair::ReplaceNoncanonicalSymlink {
            path, old_target, ..
        } => link_target_matches(path, old_target),
        AgentLinkRepair::BackupRedundantDir { path, backup, .. }
        | AgentLinkRepair::BackupDuplicateDir { path, backup, .. } => {
            path_is_real_dir(path) && !Path::new(backup).exists()
        }
        AgentLinkRepair::ReplaceDuplicateDir {
            path,
            target,
            backup,
            ..
        } => path_is_real_dir(path) && Path::new(target).exists() && !Path::new(backup).exists(),
    }
}

fn link_target_matches(path: &str, expected: &str) -> bool {
    let path = Path::new(path);
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
        && fs::read_link(path)
            .map(|target| target.display().to_string() == expected)
            .unwrap_or(false)
}

fn path_is_real_dir(path: &str) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn remove_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            if let Err(file_err) = fs::remove_file(path) {
                fs::remove_dir(path).with_context(|| {
                    format!(
                        "remove symlink {} as file ({file_err}) or directory",
                        path.display()
                    )
                })?;
            }
        }
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path)?;
        }
        Ok(_) => {
            fs::remove_file(path)?;
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    Ok(())
}

#[cfg(unix)]
fn symlink_path(target: &Path, link: &Path, _is_dir: bool) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn symlink_path(target: &Path, link: &Path, is_dir: bool) -> std::io::Result<()> {
    if is_dir {
        std::os::windows::fs::symlink_dir(target, link)
    } else {
        std::os::windows::fs::symlink_file(target, link)
    }
}

fn safe_realpath(path: &Path) -> Option<PathBuf> {
    fs::canonicalize(path).ok()
}

fn resolve_symlink_chain(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn expand_home_path(raw: &str) -> PathBuf {
    if raw == "~" {
        home_dir()
    } else if let Some(rest) = raw.strip_prefix("~/") {
        home_dir().join(rest)
    } else {
        PathBuf::from(raw)
    }
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn normalize_agents(values: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let normalized = if trimmed == "*" {
            "*".to_string()
        } else {
            sanitize_name(trimmed)
        };
        if seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    out
}

fn sanitize_name(name: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in name.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' {
            out.push(ch);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let trimmed = out.trim_matches(['.', '-']).to_string();
    if trimmed.is_empty() {
        "unnamed-skill".to_string()
    } else {
        trimmed.chars().take(255).collect()
    }
}

fn shell_words(input: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut had_token = false;
    for ch in input.chars() {
        if escaped {
            current.push(ch);
            had_token = true;
            escaped = false;
            continue;
        }
        match ch {
            '\\' if !in_single => {
                escaped = true;
                had_token = true;
            }
            '\'' if !in_double => {
                in_single = !in_single;
                had_token = true;
            }
            '"' if !in_single => {
                in_double = !in_double;
                had_token = true;
            }
            ch if ch.is_whitespace() && !in_single && !in_double => {
                if had_token {
                    words.push(current.clone());
                    current.clear();
                    had_token = false;
                }
            }
            _ => {
                current.push(ch);
                had_token = true;
            }
        }
    }
    if escaped {
        return Err(anyhow!("unterminated escape in --skills-cmd"));
    }
    if in_single || in_double {
        return Err(anyhow!("unterminated quote in --skills-cmd"));
    }
    if had_token {
        words.push(current);
    }
    Ok(words)
}

fn quote_arg(arg: &str) -> String {
    if arg
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "_./:@%+=,#-".contains(ch))
    {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\"'\"'"))
    }
}

fn command_to_string(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| quote_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn agent_repair_action(repair: &AgentLinkRepair) -> &'static str {
    match repair {
        AgentLinkRepair::CreateMissingSymlink { .. } => "create-missing-symlink",
        AgentLinkRepair::RemoveBrokenSymlink { .. } => "remove-broken-symlink",
        AgentLinkRepair::RemoveInvalidSymlink { .. } => "remove-invalid-symlink",
        AgentLinkRepair::RemoveRedundantSymlink { .. } => "remove-redundant-symlink",
        AgentLinkRepair::ReplaceNoncanonicalSymlink { .. } => "replace-noncanonical-symlink",
        AgentLinkRepair::BackupRedundantDir { .. } => "backup-redundant-dir",
        AgentLinkRepair::BackupDuplicateDir { .. } => "backup-duplicate-dir",
        AgentLinkRepair::ReplaceDuplicateDir { .. } => "replace-duplicate-dir",
    }
}

fn agent_repair_summary(repair: &AgentLinkRepair) -> String {
    match repair {
        AgentLinkRepair::CreateMissingSymlink {
            agent,
            path,
            target,
            ..
        } => format!("{agent} {path} -> {target}"),
        AgentLinkRepair::RemoveBrokenSymlink { path, target, .. } => {
            format!("remove {path} -> {target}")
        }
        AgentLinkRepair::RemoveInvalidSymlink { path, target, .. } => {
            format!("remove invalid skill link {path} -> {target}")
        }
        AgentLinkRepair::RemoveRedundantSymlink {
            path,
            target,
            canonical_path,
            ..
        } => format!("remove redundant Codex link {path} -> {target}; canonical {canonical_path}"),
        AgentLinkRepair::ReplaceNoncanonicalSymlink {
            path,
            old_target,
            target,
            ..
        } => format!("replace noncanonical link {path} -> {old_target}; canonical {target}"),
        AgentLinkRepair::BackupRedundantDir {
            path,
            canonical_path,
            backup,
            ..
        } => format!("backup redundant Codex dir {path} to {backup}; canonical {canonical_path}"),
        AgentLinkRepair::BackupDuplicateDir {
            path,
            canonical_path,
            backup,
            ..
        } => format!("backup duplicate Codex dir {path} to {backup}; canonical {canonical_path}"),
        AgentLinkRepair::ReplaceDuplicateDir {
            path,
            target,
            backup,
            ..
        } => format!("backup {path} to {backup}; link -> {target}"),
    }
}

fn agent_repair_path(repair: &AgentLinkRepair) -> Option<String> {
    match repair {
        AgentLinkRepair::CreateMissingSymlink { path, .. }
        | AgentLinkRepair::RemoveBrokenSymlink { path, .. }
        | AgentLinkRepair::RemoveInvalidSymlink { path, .. }
        | AgentLinkRepair::RemoveRedundantSymlink { path, .. }
        | AgentLinkRepair::ReplaceNoncanonicalSymlink { path, .. }
        | AgentLinkRepair::BackupRedundantDir { path, .. }
        | AgentLinkRepair::BackupDuplicateDir { path, .. }
        | AgentLinkRepair::ReplaceDuplicateDir { path, .. } => Some(path.clone()),
    }
}

fn print_help() {
    const HELP_TEXT: &str = r#"NAME
    skills-sync - make the `skills` CLI notice, track, and link your skills

WHAT IT DOES
    skills-sync compares three things:

      1. your skills lock file
      2. what `skills list` says is installed
      3. which agent links are missing

    It is for the common drift cases where `skills list -g` says skills are not
    linked, `skills update -g` misses skills, or another CLI installed a skill
    without adding it to the lock file.

START HERE
    1. Preview the global repair plan:
       skills-sync doctor -g -n -c skills

    2. If the plan looks right, apply it:
       skills-sync doctor -g -c skills

    3. Check that future updates can see the repaired state:
       skills-sync status -g -c skills
       skills update -g

WHAT CHANGES FILES?
    Read-only:
      skills-sync help
      skills-sync build-info --json
      skills-sync status
      skills-sync lock status
      any command with --dry-run

    Makes changes:
      skills-sync sync
      skills-sync doctor
      skills-sync lock repair
      skills-sync adopt

    Change-making commands can normalize the selected lock, create missing
    agent skill symlinks, remove broken or redundant
    Codex symlinks, replace noncanonical agent symlinks, back up duplicate
    Codex skill directories, back up and relink duplicate non-Codex agent skill
    directories, and run `skills add` to restore or adopt skills.

GLOBAL VS PROJECT
    --scope global    Use global skills under ~/.agents. This is the default and
                      is usually what you want for Codex, Claude, Gemini, and
                      other global CLIs.
    --scope project   Use the current directory's ./skills-lock.json.
    --scope both      Check both global and project locks.

    A bare `skills-sync status` no longer warns about a missing project lock.
    Use --scope project or --scope both when you intentionally want local
    project skills included.

LOCK FILES
    The default global lock is exactly ~/.agents/skills-lock.json. Use
    --global-lock-file when an explicit external profile supplies another lock;
    default discovery does not adopt any alternate path.

AGENT LINK RECONCILIATION
    skills-sync still delegates real install/link semantics to the upstream
    `skills add` command. By default it emits no --agent flags, so upstream can
    use its detected/default agent selection. Its local agent-link repair is
    only filesystem hygiene for existing agent skill directories that upstream
    does not report. The exception is Codex Desktop vendor-import adoption:
    when no agent was explicitly requested, skills-sync asks upstream for
    --agent '*' so the adopted skill is tracked and linked in one doctor pass.

    Codex global skills are canonical under ~/.agents/skills. If the same skill
    slug also exists under ~/.codex/skills, reconcile mode removes symlinks and
    backs up real directories instead of leaving Codex with a second global skill
    source. Codex-private slugs that are not present in ~/.agents/skills are left
    alone.

    --agent-link-policy off
        Do not scan or repair per-agent skill directories.

    --agent-link-policy warn
        Report broken links, invalid links, unmanaged entries, and duplicate
        directories only.

    --agent-link-policy safe
        Also remove broken or invalid skill symlinks inside known agent skill
        directories.

    --agent-link-policy reconcile
        Safe mode plus: create missing per-agent symlinks for installed global
        skills that `skills list -g` reports as unlinked and a local agent
        directory is still the right target. Non-Codex symlinks that point at a
        stale same-slug skill are replaced with symlinks to the canonical global
        skill. When a non-Codex duplicate real directory has the same normalized
        file tree as the canonical global skill, move it to
        ~/.local/state/skills-sync/backups/ and replace it with a symlink. Codex
        duplicates are backed up without a new symlink because Codex already
        reads ~/.agents/skills, including when the duplicate real directory
        differs from the canonical global skill.

COMMANDS
    build-info --json
        Emit checkout-independent common product build information.

    sync
        Restore skills from the selected lock files and repair installed skills
        that have no agent links. This is the default command.

    status
        Show what sync would do without making changes.

    doctor
        The broad repair command. It normalizes the selected lock, restores missing
        locked skills, relinks installed-but-unlinked skills, and safely adopts
        installed skills when their source can be inferred. If a skill was
        installed by Codex Desktop into a per-agent directory, doctor can adopt
        it when the copied skill matches Codex Desktop's local vendor import
        metadata and the vendor checkout has a supported GitHub origin.

    lock status
        Show the selected global lock and its readable state.

    lock repair
        Normalize the selected global lock without changing its path.

    adopt
        Add one explicitly sourced skill to the lock/tracking flow.

COMMON EXAMPLES
    Fix global skills when `skills update -g` misses them:
      skills-sync doctor -g -c skills
    This reads ~/.agents/skills-lock.json, checks `skills list -g --json`,
    restores missing locked skills, and asks upstream `skills add` to repair
    installed skills with no agent tracking using upstream's default agent
    selection.

    Preview everything first:
      skills-sync doctor -g -n -c skills
    This prints the same plan without writing lock files or running `skills add`.

    Inspect stale Codex/Claude/Gemini skill links without applying changes:
      skills-sync status -g --agent-link-policy reconcile -c skills

    Only inspect the lock-file problem:
      skills-sync lock status -c skills

    Normalize only the selected global lock:
      skills-sync lock repair -c skills

    Ask upstream to repair/register Codex only:
      skills-sync doctor -g -a codex -c skills

    Ask upstream to repair/register every upstream-supported agent:
      skills-sync doctor -g -A -c skills
    This passes --agent '*' to upstream. It does not pass upstream --all,
    because upstream --all means "all skills and all agents".

    Restore/link locked skills but do not adopt untracked installed skills:
      skills-sync doctor -g --adopt-policy off -c skills

    Adopt one skill from a known GitHub source:
      skills-sync adopt -g --source owner/repo/skills/name --skill name -a codex -c skills
    Use this when a skill is installed but no reliable source can be inferred.

    Adopt supported Codex Desktop-installed skills and transfer duplicates:
      skills-sync doctor -g -c skills
    When the source can be inferred, this runs upstream `skills add` for the
    canonical global install. If you did not pass -a or -A, Desktop-import
    adoption still passes --agent '*' so upstream records agent tracking in the
    same pass. It then reconciles duplicate per-agent copies: Codex duplicates
    are backed up because Codex reads ~/.agents/skills directly; equivalent
    non-Codex copies are backed up and replaced with symlinks.

    Work on a project-local lock in the current repo:
      skills-sync doctor -p -c skills
    This reads ./skills-lock.json in the current directory and runs project-local
    `skills add` commands without -g.

OPTIONS
    -h, --help
        Show this help.

    -n, --dry-run
        Preview the plan without writing files or running `skills add`.

    --apply
        Apply a plan. sync, doctor, lock repair, and adopt apply by default.

    -j, --json
        Print machine-readable output for scripts and tests.

    -y, --yes
        Pass -y to upstream `skills add` commands.

    -g, --global
        Shorthand for --scope global.

    -p, --project
        Shorthand for --scope project.

    -b, --both
        Shorthand for --scope both.

    --scope global|project|both
        Choose which lock scope to inspect or repair. Default: global.

    -G, --global-lock-file PATH
        Override the global lock path for advanced testing or recovery.

    -P, --project-lock-file PATH
        Override the project lock path. Default: ./skills-lock.json.

    --no-project-lock
        Ignore project-local locks and warnings.

    -c, --skills-cmd STRING
        Command used to call the upstream skills CLI. Use --skills-cmd skills
        when `skills` is already installed. Default: npx skills@latest.

    -a, --agent NAME
        Force one explicit upstream --agent target. Repeat this flag for
        multiple agents.

    -A, --all-agents
        Pass upstream --agent '*' to target all supported agents. This does
        not pass upstream --all, because upstream --all also broadens the skill
        selection.

    --color auto|always|never
        Control colored human output. Default: auto.

    --no-color
        Disable colored human output. Also honored through NO_COLOR.

    --link-policy default|off
        Choose whether installed-but-unlinked skills should be relinked.

    --adopt-policy inferred|off|all
        Choose whether doctor adopts untracked installed skills. Default for
        doctor: inferred. Use off for a conservative restore/link-only pass.

    --agent-link-policy off|warn|safe|reconcile
        Choose whether existing per-agent skill directories are audited and
        repaired. doctor and status default to reconcile; sync defaults to off.

    --agent-dir PATH
        Add one extra existing agent skill directory to the audit set. Repeat
        this flag for multiple directories.

    --source SOURCE
        Source used by adopt, for example owner/repo/skills/name.

    --skill NAME
        Skill name used by adopt.

    -q, --quiet
        Suppress human-readable summary output.

    -v, --verbose
        Keep extra diagnostic details when available.

ENVIRONMENT
    SKILLS_SYNC_SCOPE=global|project|both
        Default scope when no scope flag is provided.

    SKILLS_SYNC_SKILLS_CMD="skills"
        Default upstream command.

    SKILLS_SYNC_AGENTS="codex,claude"
        Default explicit upstream --agent targets.

    SKILLS_SYNC_COLOR=auto|always|never
        Default color mode. NO_COLOR disables color unless --color is provided.

    SKILLS_SYNC_JSON=1, SKILLS_SYNC_DRY_RUN=1, SKILLS_SYNC_YES=1,
    SKILLS_SYNC_QUIET=1, SKILLS_SYNC_VERBOSE=1, SKILLS_SYNC_ALL_AGENTS=1,
    SKILLS_SYNC_NO_PROJECT_LOCK=1
        Boolean defaults. Use 1/0, true/false, yes/no, or on/off.
        SKILLS_SYNC_ALL_AGENTS maps to upstream --agent '*', not upstream
        --all.

    SKILLS_SYNC_GLOBAL_LOCK_FILE=PATH, SKILLS_SYNC_PROJECT_LOCK_FILE=PATH,
    SKILLS_SYNC_LINK_POLICY=default|off, SKILLS_SYNC_ADOPT_POLICY=inferred|off|all
        Advanced defaults for recovery and scripted runs.

    SKILLS_SYNC_AGENT_LINK_POLICY=off|warn|safe|reconcile
        Default agent-link audit/repair policy.

    SKILLS_SYNC_AGENT_DIRS=PATHS
        Additional agent skill directories to scan, separated like PATH.
"#;
    print!("{HELP_TEXT}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_words_handles_quotes() {
        assert_eq!(
            shell_words("npx 'skills@latest' --flag=\"two words\"").unwrap(),
            vec!["npx", "skills@latest", "--flag=two words"]
        );
    }

    #[test]
    fn github_remote_parsing_supports_ssh_and_https() {
        assert_eq!(
            github_owner_repo("git@github.com:example-org/source-skills.git"),
            "example-org/source-skills"
        );
        assert_eq!(
            github_owner_repo("https://github.com/openai/skills.git"),
            "openai/skills"
        );
        assert_eq!(
            github_owner_repo("https://example.com/openai/skills.git"),
            ""
        );
    }

    #[test]
    fn install_source_uses_source_and_skill_path() {
        let entry = json!({
            "source": "openai/skills",
            "skillPath": "skills/.curated/playwright/SKILL.md",
            "ref": "main"
        });
        assert_eq!(
            build_install_source(&entry),
            "openai/skills/skills/.curated/playwright#main"
        );
    }

    #[test]
    fn sanitize_name_matches_cli_slugs() {
        assert_eq!(sanitize_name("Code Review"), "code-review");
        assert_eq!(sanitize_name("..."), "unnamed-skill");
    }
}
