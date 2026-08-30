use super::*;

const MINIMUM_GIT_VERSION: (u64, u64, u64) = (2, 40, 0);
#[cfg(windows)]
const GIT_CREDENTIAL_FRONTEND: &str = "git-credential-dev-auth.exe";
#[cfg(not(windows))]
const GIT_CREDENTIAL_FRONTEND: &str = "git-credential-dev-auth";
#[cfg(windows)]
const GIT_SIGNING_FRONTEND: &str = "ssh-keygen-dev-auth.exe";
#[cfg(not(windows))]
const GIT_SIGNING_FRONTEND: &str = "ssh-keygen-dev-auth";
#[cfg(windows)]
const GIT_REJECT_FRONTEND: &str = "false.exe";
#[cfg(not(windows))]
const GIT_REJECT_FRONTEND: &str = "false";
#[cfg(windows)]
const GIT_PAGER_FRONTEND: &str = "cat.exe";
#[cfg(not(windows))]
const GIT_PAGER_FRONTEND: &str = "cat";

#[derive(Debug, Clone)]
struct NativeUserDirs {
    home: PathBuf,
    config: PathBuf,
    runtime: PathBuf,
}

impl RuntimePaths {
    fn from_native(dirs: &NativeUserDirs) -> Self {
        Self {
            config: dirs.config.clone(),
            runtime: dirs.runtime.clone(),
        }
    }
    fn git_sandbox_dir(&self) -> PathBuf {
        self.runtime.join("git-sandbox")
    }

    #[cfg(all(test, unix))]
    fn git_child_bin_dir(&self) -> PathBuf {
        self.git_sandbox_dir().join("bin")
    }

    fn git_config_dir(&self) -> PathBuf {
        self.git_sandbox_dir().join("config")
    }

    fn git_home_dir(&self) -> PathBuf {
        self.git_sandbox_dir().join("home")
    }

    fn git_cache_dir(&self) -> PathBuf {
        self.git_sandbox_dir().join("cache")
    }

    fn git_data_dir(&self) -> PathBuf {
        self.git_sandbox_dir().join("data")
    }

    fn git_temp_dir(&self) -> PathBuf {
        self.git_sandbox_dir().join("tmp")
    }

    fn git_empty_config_file(&self) -> PathBuf {
        self.git_sandbox_dir().join("empty-config")
    }

    fn git_empty_attributes_file(&self) -> PathBuf {
        self.git_sandbox_dir().join("empty-attributes")
    }

    fn git_empty_hooks_dir(&self) -> PathBuf {
        self.git_sandbox_dir().join("empty-hooks")
    }
}

fn native_routing_directories() -> Result<NativeUserDirs> {
    let home = native_current_user_home()?;
    #[cfg(target_os = "macos")]
    let (config, runtime) = (
        home.join("Library/Application Support/dev-auth/config.toml"),
        home.join("Library/Caches/dev-auth/runtime"),
    );
    #[cfg(all(unix, not(target_os = "macos")))]
    let (config, runtime) = (
        home.join(".config/dev-auth/config.toml"),
        secure_login_runtime_dir()
            .map(|path| path.join("dev-auth"))
            .unwrap_or_else(|| home.join(".cache/dev-auth/runtime")),
    );
    #[cfg(windows)]
    let (config, runtime) = {
        let project = ProjectDirs::from("", "", "dev-auth")
            .context("the operating system has no user configuration directory")?;
        (
            project.config_dir().join("config.toml"),
            project.cache_dir().join("runtime"),
        )
    };
    #[cfg(not(any(unix, windows)))]
    let (config, runtime) = return Err(anyhow::anyhow!(
        "the current platform has no native configuration authority"
    ));
    Ok(NativeUserDirs {
        home,
        config,
        runtime,
    })
}

pub(super) fn native_runtime_paths() -> Result<RuntimePaths> {
    Ok(RuntimePaths::from_native(&native_routing_directories()?))
}

pub(super) fn frontend_runtime_and_config() -> Result<(RuntimePaths, Config)> {
    match env::var("DEV_AUTH_GIT_CHILD") {
        Ok(value) if value == "1" => {
            let directories = native_routing_directories()?;
            let expected = env::var("DEV_AUTH_GIT_CONFIG_SHA256")
                .context("managed Git child has no configuration binding")?;
            bound_frontend_runtime_and_config(&directories, &expected)
        }
        Ok(_) => bail!("managed Git child marker is malformed"),
        Err(env::VarError::NotPresent) => {
            let paths = RuntimePaths::discover()?;
            let config = load_config(&paths)?;
            Ok((paths, config))
        }
        Err(env::VarError::NotUnicode(_)) => bail!("managed Git child marker is not Unicode"),
    }
}

fn bound_frontend_runtime_and_config(
    directories: &NativeUserDirs,
    expected_digest: &str,
) -> Result<(RuntimePaths, Config)> {
    let paths = RuntimePaths::from_native(directories);
    let (config, actual_digest) = load_config_snapshot_at(&paths.config)?;
    if expected_digest.len() != 64
        || !expected_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        || actual_digest != expected_digest.to_ascii_lowercase()
    {
        bail!("managed Git child configuration binding does not match");
    }
    Ok((paths, config))
}

#[cfg(unix)]
fn native_current_user_home() -> Result<PathBuf> {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .context("query current operating-system user")?
        .context("current operating-system user has no account record")?;
    if !user.dir.is_absolute() {
        bail!("current operating-system user has no absolute home directory");
    }
    Ok(user.dir)
}

#[cfg(windows)]
fn native_current_user_home() -> Result<PathBuf> {
    let base = BaseDirs::new().context("the operating system has no user home directory")?;
    Ok(base.home_dir().to_path_buf())
}

#[cfg(not(any(unix, windows)))]
fn native_current_user_home() -> Result<PathBuf> {
    bail!("the current platform does not provide a supported user-home authority")
}

#[cfg(not(windows))]
fn lexical_absolute_path(path: &Path, base: &Path) -> Result<PathBuf> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        use std::path::Component;
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    bail!("Git workspace path escapes its filesystem root");
                }
            }
            Component::Normal(value) => normalized.push(value),
        }
    }
    if !normalized.is_absolute() {
        bail!("Git workspace path is not absolute");
    }
    Ok(normalized)
}

#[cfg(not(windows))]
fn reject_path_links(path: &Path, require_final: bool) -> Result<()> {
    let mut current = PathBuf::new();
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        let final_component = index + 1 == components.len();
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    bail!("Git workspace path must not traverse a symbolic link");
                }
                if !final_component && !metadata.file_type().is_dir() {
                    bail!("Git workspace path ancestor is not a directory");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && !require_final => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                bail!("declared Git workspace root does not exist")
            }
            Err(error) => return Err(error).context("inspect Git workspace path"),
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn canonical_existing_directory(path: &Path, description: &str) -> Result<PathBuf> {
    reject_path_links(path, true)?;
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {description}"))?;
    if !metadata.file_type().is_dir() {
        bail!("{description} is not a directory");
    }
    let canonical = fs::canonicalize(path).with_context(|| format!("resolve {description}"))?;
    if canonical != path {
        bail!("{description} has an ambiguous filesystem representation");
    }
    Ok(canonical)
}

#[cfg(not(windows))]
fn resolved_workspace_roots(config: &Config, home: &Path) -> Result<Vec<PathBuf>> {
    let policy = config
        .git
        .as_ref()
        .context("Git workspace policy is not declared")?;
    let mut roots = Vec::new();
    for declared in &policy.workspace_roots {
        let expanded = declared
            .strip_prefix("~/")
            .map_or_else(|| PathBuf::from(declared), |relative| home.join(relative));
        let absolute = lexical_absolute_path(&expanded, home)?;
        let root = canonical_existing_directory(&absolute, "declared Git workspace root")?;
        let metadata = fs::metadata(&root).context("inspect declared Git workspace root owner")?;
        if std::os::unix::fs::MetadataExt::uid(&metadata) != nix::unistd::Uid::effective().as_raw()
            || std::os::unix::fs::MetadataExt::mode(&metadata) & 0o022 != 0
        {
            bail!("declared Git workspace root must be owned by the effective user and not writable by group or others");
        }
        roots.push(root);
    }
    roots.sort();
    for pair in roots.windows(2) {
        if pair[1].starts_with(&pair[0]) {
            bail!("declared Git workspace roots overlap");
        }
    }
    Ok(roots)
}

#[cfg(not(windows))]
fn classify_existing_directory(path: &Path, roots: &[PathBuf]) -> Result<WorkspaceContext> {
    let absolute =
        lexical_absolute_path(path, &env::current_dir().context("read current directory")?)?;
    let canonical = canonical_existing_directory(&absolute, "Git workspace context")?;
    Ok(if roots.iter().any(|root| canonical.starts_with(root)) {
        WorkspaceContext::Managed
    } else {
        WorkspaceContext::Unmanaged
    })
}

#[cfg(windows)]
struct WindowsWorkspaceRoots {
    authority: windows_security::WorkspacePathAuthority,
    guards: Vec<windows_security::WorkspacePathGuard>,
}

#[cfg(windows)]
impl WindowsWorkspaceRoots {
    fn relation_to_roots(
        &self,
        guard: &windows_security::WorkspacePathGuard,
    ) -> WorkspacePathRelation {
        let mut contains_root = false;
        for (index, root) in self.guards.iter().enumerate() {
            match guard.relation_to_root(root) {
                windows_security::WorkspaceGuardRelation::Outside => {}
                windows_security::WorkspaceGuardRelation::Same
                | windows_security::WorkspaceGuardRelation::Inside => {
                    return WorkspacePathRelation::Inside(index);
                }
                windows_security::WorkspaceGuardRelation::Contains => contains_root = true,
            }
        }
        if contains_root {
            WorkspacePathRelation::ContainsRoot
        } else {
            WorkspacePathRelation::Outside
        }
    }

    fn lock_directory_relation(
        &self,
        path: &Path,
    ) -> Result<(WorkspacePathRelation, windows_security::WorkspacePathGuard)> {
        let guard = self
            .authority
            .lock_directory(path)
            .with_context(|| format!("lock Git directory path {}", path.display()))?;
        let relation = self.relation_to_roots(&guard);
        Ok((relation, guard))
    }

    fn lock_target_relation(
        &self,
        path: &Path,
    ) -> Result<(WorkspacePathRelation, windows_security::WorkspacePathGuard)> {
        let guard = self
            .authority
            .lock_target(path)
            .with_context(|| format!("lock Git target path {}", path.display()))?;
        let relation = self.relation_to_roots(&guard);
        Ok((relation, guard))
    }
}

#[cfg(windows)]
fn windows_absolute_path(path: &Path, base: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    if !absolute.is_absolute() {
        bail!("Git workspace path is not absolute");
    }
    Ok(absolute)
}

#[cfg(windows)]
fn resolved_workspace_roots(config: &Config, home: &Path) -> Result<WindowsWorkspaceRoots> {
    let policy = config
        .git
        .as_ref()
        .context("Git workspace policy is not declared")?;
    let authority = windows_security::WorkspacePathAuthority::current()
        .context("load current-user Windows workspace authority")?;
    let mut entries = Vec::new();
    for declared in &policy.workspace_roots {
        let expanded = declared
            .strip_prefix("~/")
            .map_or_else(|| PathBuf::from(declared), |relative| home.join(relative));
        let absolute = windows_absolute_path(&expanded, home)?;
        let guard = authority
            .lock_root(&absolute)
            .with_context(|| format!("lock declared Git workspace root {}", absolute.display()))?;
        entries.push((absolute, guard));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    for left in 0..entries.len() {
        for right in left + 1..entries.len() {
            if entries[left].1.relation_to_root(&entries[right].1)
                != windows_security::WorkspaceGuardRelation::Outside
            {
                bail!("declared Git workspace roots overlap");
            }
        }
    }
    Ok(WindowsWorkspaceRoots {
        authority,
        guards: entries.into_iter().map(|(_, guard)| guard).collect(),
    })
}

#[cfg(windows)]
fn classify_existing_directory(
    path: &Path,
    roots: &WindowsWorkspaceRoots,
) -> Result<WorkspaceContext> {
    let current = env::current_dir().context("read current directory")?;
    let absolute = windows_absolute_path(path, &current)?;
    let (relation, _guard) = roots.lock_directory_relation(&absolute)?;
    Ok(if matches!(relation, WorkspacePathRelation::Inside(_)) {
        WorkspaceContext::Managed
    } else {
        WorkspaceContext::Unmanaged
    })
}

#[cfg(not(windows))]
fn canonical_candidate_path(path: &Path, base: &Path) -> Result<PathBuf> {
    let absolute = lexical_absolute_path(path, base)?;
    let mut existing = absolute.clone();
    let mut missing = Vec::new();
    loop {
        match fs::symlink_metadata(&existing) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let leaf = existing
                    .file_name()
                    .context("Git target has no existing filesystem ancestor")?
                    .to_os_string();
                missing.push(leaf);
                if !existing.pop() {
                    bail!("Git target has no existing filesystem ancestor");
                }
            }
            Err(error) => return Err(error).context("inspect Git target path"),
        }
    }
    reject_path_links(&existing, true)?;
    let mut canonical = fs::canonicalize(&existing).context("resolve Git target ancestor")?;
    if canonical != existing {
        bail!("Git target has an ambiguous filesystem representation");
    }
    for leaf in missing.into_iter().rev() {
        canonical.push(leaf);
    }
    Ok(canonical)
}

#[cfg(windows)]
fn canonical_candidate_path(path: &Path, base: &Path) -> Result<PathBuf> {
    windows_absolute_path(path, base)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspacePathRelation {
    Outside,
    Inside(usize),
    ContainsRoot,
}

#[cfg(not(windows))]
fn workspace_path_relation(path: &Path, roots: &[PathBuf]) -> WorkspacePathRelation {
    if let Some(index) = roots.iter().position(|root| path.starts_with(root)) {
        WorkspacePathRelation::Inside(index)
    } else if roots.iter().any(|root| root.starts_with(path)) {
        WorkspacePathRelation::ContainsRoot
    } else {
        WorkspacePathRelation::Outside
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GitInvocationRoute {
    Managed(usize),
    Unmanaged,
}

#[cfg(windows)]
struct WindowsPathGuards {
    _guards: Vec<windows_security::WorkspacePathGuard>,
}

#[cfg(windows)]
impl WindowsPathGuards {
    fn new() -> Self {
        Self {
            _guards: Vec::new(),
        }
    }

    fn push(&mut self, guard: windows_security::WorkspacePathGuard) {
        self._guards.push(guard);
    }
}

#[cfg(windows)]
struct WindowsGitRoutingDecision {
    route: GitInvocationRoute,
    _path_guards: WindowsPathGuards,
}

#[cfg(windows)]
impl WindowsGitRoutingDecision {
    fn route(&self) -> GitInvocationRoute {
        self.route
    }
}

fn os_argument<'a>(argument: &'a OsStr, description: &str) -> Result<&'a str> {
    argument
        .to_str()
        .with_context(|| format!("{description} is not Unicode"))
}

fn option_path_value<'a>(
    arguments: &'a [OsString],
    index: &mut usize,
    option: &str,
) -> Result<&'a OsStr> {
    *index += 1;
    arguments
        .get(*index)
        .map(OsString::as_os_str)
        .with_context(|| format!("Git option {option} has no path value"))
}

fn parse_global_git_targets(
    arguments: &[OsString],
    cwd: &Path,
) -> Result<(usize, PathBuf, Vec<PathBuf>, bool)> {
    let mut index = 0_usize;
    let mut effective = cwd.to_path_buf();
    let mut targets = Vec::new();
    let mut deferred_overrides = Vec::new();
    let mut has_repository_override = false;
    while index < arguments.len() {
        let argument = os_argument(&arguments[index], "Git global option or command")?;
        match argument {
            "-C" => {
                has_repository_override = true;
                let path = option_path_value(arguments, &mut index, argument)?;
                let target = canonical_candidate_path(Path::new(path), &effective)?;
                effective = target.clone();
                targets.push(target);
            }
            _ if argument.starts_with("-C") && argument.len() > 2 => {
                has_repository_override = true;
                let target = canonical_candidate_path(Path::new(&argument[2..]), &effective)?;
                effective = target.clone();
                targets.push(target);
            }
            "--git-dir" | "--work-tree" => {
                has_repository_override = true;
                deferred_overrides
                    .push(option_path_value(arguments, &mut index, argument)?.to_os_string());
            }
            _ if argument.starts_with("--git-dir=") => {
                has_repository_override = true;
                deferred_overrides.push(OsString::from(&argument[10..]));
            }
            _ if argument.starts_with("--work-tree=") => {
                has_repository_override = true;
                deferred_overrides.push(OsString::from(&argument[12..]));
            }
            "-c" | "--config-env" => {
                bail!("Git routing does not admit caller configuration overrides")
            }
            "--namespace" | "--super-prefix" => {
                index += 1;
                if index >= arguments.len() {
                    bail!("Git global option {argument} has no value");
                }
            }
            _ if argument.starts_with("-c") && argument.len() > 2 => {
                bail!("Git routing does not admit caller configuration overrides")
            }
            _ if argument.starts_with("--config-env=") => {
                bail!("Git routing does not admit caller configuration overrides")
            }
            _ if argument.starts_with("--namespace=")
                || argument.starts_with("--super-prefix=") => {}
            _ if argument.starts_with("--exec-path=") => {
                targets.push(canonical_candidate_path(
                    Path::new(&argument[12..]),
                    &effective,
                )?);
            }
            "--bare"
            | "--no-pager"
            | "--paginate"
            | "-p"
            | "--no-replace-objects"
            | "--literal-pathspecs"
            | "--glob-pathspecs"
            | "--noglob-pathspecs"
            | "--icase-pathspecs"
            | "--no-optional-locks"
            | "--version"
            | "--help"
            | "--html-path"
            | "--man-path"
            | "--info-path"
            | "--exec-path" => {}
            _ if argument.starts_with('-') => {
                bail!("Git routing is ambiguous under an unknown global option")
            }
            _ => break,
        }
        index += 1;
    }
    for path in deferred_overrides {
        targets.push(canonical_candidate_path(Path::new(&path), &effective)?);
    }
    Ok((index, effective, targets, has_repository_override))
}

#[derive(Debug, Default)]
struct CommandRoutingTargets {
    paths: Vec<PathBuf>,
    destination: Option<PathBuf>,
}

fn command_routing_targets(
    command: &str,
    arguments: &[OsString],
    base: &Path,
) -> Result<CommandRoutingTargets> {
    if !matches!(command, "init" | "clone") {
        return Ok(CommandRoutingTargets::default());
    }
    let value_options: &[&str] = if command == "init" {
        &[
            "--template",
            "--separate-git-dir",
            "--object-format",
            "--ref-format",
            "--initial-branch",
            "-b",
        ]
    } else {
        &[
            "--branch",
            "-b",
            "--depth",
            "--filter",
            "--jobs",
            "-j",
            "--origin",
            "-o",
            "--reference",
            "--reference-if-able",
            "--separate-git-dir",
            "--shallow-since",
            "--shallow-exclude",
            "--server-option",
            "--template",
            "-u",
            "--upload-pack",
        ]
    };
    let flag_options: &[&str] = if command == "init" {
        &["--bare", "--quiet", "-q", "--shared"]
    } else {
        &[
            "--bare",
            "--dissociate",
            "--ipv4",
            "-4",
            "--ipv6",
            "-6",
            "--local",
            "-l",
            "--mirror",
            "--no-checkout",
            "-n",
            "--no-hardlinks",
            "--no-local",
            "--no-reject-shallow",
            "--no-single-branch",
            "--no-tags",
            "--progress",
            "--quiet",
            "-q",
            "--recurse-submodules",
            "--reject-shallow",
            "--remote-submodules",
            "--shared",
            "-s",
            "--single-branch",
            "--sparse",
            "--verbose",
            "-v",
        ]
    };
    let path_options: &[&str] = if command == "init" {
        &["--template", "--separate-git-dir"]
    } else {
        &[
            "--reference",
            "--reference-if-able",
            "--separate-git-dir",
            "--template",
        ]
    };
    let mut targets = Vec::new();
    let mut positionals = Vec::new();
    let mut index = 0_usize;
    while index < arguments.len() {
        let argument = os_argument(&arguments[index], "Git init or clone argument")?;
        if argument == "--" {
            for value in &arguments[index + 1..] {
                positionals.push(value.as_os_str());
            }
            break;
        }
        if value_options.contains(&argument) {
            index += 1;
            if index >= arguments.len() {
                bail!("Git {command} option has no value");
            }
            if path_options.contains(&argument) {
                targets.push(canonical_candidate_path(
                    Path::new(&arguments[index]),
                    base,
                )?);
            }
        } else if value_options
            .iter()
            .any(|option| argument.starts_with(&format!("{option}=")))
            || flag_options.contains(&argument)
        {
            for option in path_options {
                if let Some(value) = argument.strip_prefix(&format!("{option}=")) {
                    targets.push(canonical_candidate_path(Path::new(value), base)?);
                }
            }
            if command == "init" && argument.starts_with("--shared=") {
                // Optional-value flag; it never consumes the following positional target.
            }
        } else if argument.starts_with('-') {
            bail!("Git {command} target is ambiguous under an unknown option");
        } else {
            positionals.push(arguments[index].as_os_str());
        }
        index += 1;
    }
    let destination = if command == "init" {
        if positionals.len() > 1 {
            bail!("Git init target is ambiguous");
        }
        positionals
            .first()
            .copied()
            .unwrap_or_else(|| OsStr::new("."))
    } else {
        if !(1..=2).contains(&positionals.len()) {
            bail!("Git clone requires an explicit unambiguous source and destination");
        }
        positionals
            .get(1)
            .copied()
            .context("Git clone requires an explicit destination for safe routing")?
    };
    if command == "clone" {
        let source = positionals[0];
        let source_text = source.to_str();
        if source_text.is_some_and(|value| value.starts_with("file://")) {
            bail!("Git file-URL clone routing is ambiguous; use a local path or network URL");
        } else if !source_text
            .is_some_and(|value| value.contains("://") || value.starts_with("git@"))
        {
            targets.push(canonical_candidate_path(Path::new(source), base)?);
        }
    }
    let destination = canonical_candidate_path(Path::new(destination), base)?;
    targets.push(destination.clone());
    Ok(CommandRoutingTargets {
        paths: targets,
        destination: Some(destination),
    })
}

fn environment_value<'a>(
    environment: &'a BTreeMap<OsString, OsString>,
    key: &str,
) -> Option<&'a OsStr> {
    environment.iter().find_map(|(candidate, value)| {
        let candidate = candidate.to_str()?;
        let matches = if cfg!(windows) {
            candidate.eq_ignore_ascii_case(key)
        } else {
            candidate == key
        };
        matches.then_some(value.as_os_str())
    })
}

#[derive(Debug, Default)]
struct EnvironmentGitTargets {
    paths: Vec<PathBuf>,
    repository_override: bool,
}

fn push_environment_path(
    targets: &mut Vec<PathBuf>,
    environment: &BTreeMap<OsString, OsString>,
    variable: &str,
    cwd: &Path,
) -> Result<()> {
    if let Some(value) = environment_value(environment, variable) {
        if value.is_empty() {
            bail!("Git environment variable {variable} contains an empty path");
        }
        targets.push(canonical_candidate_path(Path::new(value), cwd)?);
    }
    Ok(())
}

fn push_program_environment_path(
    targets: &mut Vec<PathBuf>,
    environment: &BTreeMap<OsString, OsString>,
    variable: &str,
    cwd: &Path,
) -> Result<()> {
    let Some(value) = environment_value(environment, variable) else {
        return Ok(());
    };
    if value.is_empty() {
        return Ok(());
    }
    let text = os_argument(value, "Git program environment value")?;
    if text.bytes().any(|byte| byte.is_ascii_whitespace())
        || text.contains(['\'', '"', '`', '$', ';', '&', '|', '<', '>', '(', ')'])
    {
        bail!("Git environment variable {variable} contains an ambiguous command");
    }
    if Path::new(value).is_absolute() || text.contains(['/', '\\']) {
        targets.push(canonical_candidate_path(Path::new(value), cwd)?);
    }
    Ok(())
}

fn push_trace_environment_path(
    targets: &mut Vec<PathBuf>,
    environment: &BTreeMap<OsString, OsString>,
    variable: &str,
    cwd: &Path,
) -> Result<()> {
    let Some(value) = environment_value(environment, variable) else {
        return Ok(());
    };
    if value.is_empty() {
        return Ok(());
    }
    let text = os_argument(value, "Git trace environment value")?;
    if matches!(
        text.to_ascii_lowercase().as_str(),
        "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "true" | "false"
    ) {
        return Ok(());
    }
    let path = text
        .strip_prefix("af_unix:stream:")
        .or_else(|| text.strip_prefix("af_unix:dgram:"))
        .or_else(|| text.strip_prefix("af_unix:"))
        .unwrap_or(text);
    if path.is_empty() || !Path::new(path).is_absolute() {
        bail!("Git environment variable {variable} contains an ambiguous trace target");
    }
    targets.push(canonical_candidate_path(Path::new(path), cwd)?);
    Ok(())
}

fn environment_git_targets(
    environment: &BTreeMap<OsString, OsString>,
    cwd: &Path,
) -> Result<EnvironmentGitTargets> {
    let mut result = EnvironmentGitTargets::default();
    for variable in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_INDEX_FILE",
        "GIT_SHALLOW_FILE",
    ] {
        if let Some(value) = environment_value(environment, variable) {
            if value.is_empty() {
                bail!("Git target environment contains an empty path");
            }
            result
                .paths
                .push(canonical_candidate_path(Path::new(value), cwd)?);
            result.repository_override = true;
        }
    }
    if environment_value(environment, "GIT_ALTERNATE_OBJECT_DIRECTORIES").is_some() {
        bail!("Git alternate-object environment is not admitted by the routing boundary");
    }
    if ["GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"]
        .iter()
        .any(|variable| environment_value(environment, variable).is_some())
        || environment.keys().any(|key| {
            key.to_str().is_some_and(|key| {
                let key = if cfg!(windows) {
                    key.to_ascii_uppercase()
                } else {
                    key.to_owned()
                };
                key.starts_with("GIT_CONFIG_KEY_") || key.starts_with("GIT_CONFIG_VALUE_")
            })
        })
    {
        bail!("Git injected configuration environment is not admitted by the routing boundary");
    }

    for variable in [
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_EXEC_PATH",
        "GIT_TEMPLATE_DIR",
        "GIT_QUARANTINE_PATH",
        "GIT_REDIRECT_STDOUT",
        "GIT_REDIRECT_STDERR",
    ] {
        push_environment_path(&mut result.paths, environment, variable, cwd)?;
    }
    for variable in [
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "GIT_SSH",
        "GIT_EDITOR",
        "GIT_SEQUENCE_EDITOR",
        "GIT_PAGER",
        "PAGER",
    ] {
        push_program_environment_path(&mut result.paths, environment, variable, cwd)?;
    }
    if environment_value(environment, "GIT_SSH_COMMAND").is_some() {
        bail!("Git shell-command environment is not admitted by the routing boundary");
    }
    for variable in [
        "GIT_TRACE",
        "GIT_TRACE_FSMONITOR",
        "GIT_TRACE_PACK_ACCESS",
        "GIT_TRACE_PACKET",
        "GIT_TRACE_PACKFILE",
        "GIT_TRACE_PERFORMANCE",
        "GIT_TRACE_REFS",
        "GIT_TRACE_SETUP",
        "GIT_TRACE_SHALLOW",
        "GIT_TRACE_CURL",
        "GIT_TRACE2",
        "GIT_TRACE2_EVENT",
        "GIT_TRACE2_PERF",
    ] {
        push_trace_environment_path(&mut result.paths, environment, variable, cwd)?;
    }

    if let Some(path) = environment_value(environment, "PATH") {
        for entry in env::split_paths(path) {
            let entry = if entry.as_os_str().is_empty() {
                cwd.to_path_buf()
            } else {
                entry
            };
            result.paths.push(canonical_candidate_path(&entry, cwd)?);
        }
    }
    if let Some(home) = environment_value(environment, "HOME") {
        if home.is_empty() {
            bail!("Git HOME environment contains an empty path");
        }
        let home = canonical_candidate_path(Path::new(home), cwd)?;
        result.paths.extend([
            home.join(".gitconfig"),
            home.join(".config/git/config"),
            home.join(".config/git/attributes"),
            home.join(".config/git/ignore"),
        ]);
    }
    if let Some(config_home) = environment_value(environment, "XDG_CONFIG_HOME") {
        if config_home.is_empty() {
            bail!("Git XDG configuration environment contains an empty path");
        }
        let config_home = canonical_candidate_path(Path::new(config_home), cwd)?;
        result.paths.extend([
            config_home.join("git/config"),
            config_home.join("git/attributes"),
            config_home.join("git/ignore"),
        ]);
    }
    if let Some(profile) = environment_value(environment, "USERPROFILE") {
        if profile.is_empty() {
            bail!("Git user-profile environment contains an empty path");
        }
        result
            .paths
            .push(canonical_candidate_path(Path::new(profile), cwd)?.join(".gitconfig"));
    }
    for variable in ["APPDATA", "PROGRAMDATA"] {
        if let Some(directory) = environment_value(environment, variable) {
            if directory.is_empty() {
                bail!("Git environment variable {variable} contains an empty path");
            }
            result
                .paths
                .push(canonical_candidate_path(Path::new(directory), cwd)?.join("Git/config"));
        }
    }
    Ok(result)
}

#[cfg(not(windows))]
fn classify_git_invocation_at(
    arguments: &[OsString],
    cwd: &Path,
    roots: &[PathBuf],
    environment: &BTreeMap<OsString, OsString>,
) -> Result<GitInvocationRoute> {
    let current = canonical_existing_directory(
        &lexical_absolute_path(cwd, cwd)?,
        "Git invocation directory",
    )?;
    let current_relation = workspace_path_relation(&current, roots);
    let (command_index, effective, mut targets, has_repository_override) =
        parse_global_git_targets(arguments, &current)?;
    let environment_targets = environment_git_targets(environment, &effective)?;
    if current_relation == WorkspacePathRelation::Outside {
        targets.extend(environment_targets.paths.iter().cloned());
    }
    let command = arguments
        .get(command_index)
        .map(|value| os_argument(value, "Git command"))
        .transpose()?;
    let command_targets = command
        .map(|command| {
            command_routing_targets(command, &arguments[command_index + 1..], &effective)
        })
        .transpose()?
        .unwrap_or_default();
    if let Some(destination) = command_targets.destination.as_ref() {
        match fs::symlink_metadata(destination) {
            Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            }
            Ok(_) => bail!("Git init or clone destination must be a regular directory"),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let parent = destination
                    .parent()
                    .context("Git clone destination has no existing parent")?;
                canonical_existing_directory(parent, "Git clone destination parent")?;
            }
            Err(error) => return Err(error).context("inspect Git clone destination"),
        }
    }
    targets.extend(command_targets.paths);
    let target_relations: Vec<_> = targets
        .iter()
        .map(|target| workspace_path_relation(target, roots))
        .collect();
    match current_relation {
        WorkspacePathRelation::Outside => {
            if target_relations
                .iter()
                .any(|relation| *relation != WorkspacePathRelation::Outside)
            {
                bail!("unmanaged Git may not target a managed workspace; change directory first");
            }
            Ok(GitInvocationRoute::Unmanaged)
        }
        WorkspacePathRelation::Inside(root_index) => {
            if has_repository_override || environment_targets.repository_override {
                bail!("managed Git does not admit repository path overrides");
            }
            if command == Some("init") {
                bail!("managed Git does not admit repository initialization");
            }
            if command == Some("clone")
                && target_relations
                    .iter()
                    .any(|target| *target != WorkspacePathRelation::Inside(root_index))
            {
                bail!("managed Git clone destination must remain in the current workspace root");
            }
            Ok(GitInvocationRoute::Managed(root_index))
        }
        WorkspacePathRelation::ContainsRoot => {
            bail!("Git invocation directory ambiguously contains a managed workspace")
        }
    }
}

#[cfg(windows)]
fn classify_git_invocation_at(
    arguments: &[OsString],
    cwd: &Path,
    roots: &WindowsWorkspaceRoots,
    environment: &BTreeMap<OsString, OsString>,
) -> Result<WindowsGitRoutingDecision> {
    let current = windows_absolute_path(cwd, cwd)?;
    let (current_relation, current_guard) = roots.lock_directory_relation(&current)?;
    let mut path_guards = WindowsPathGuards::new();
    path_guards.push(current_guard);
    let (command_index, effective, mut targets, has_repository_override) =
        parse_global_git_targets(arguments, &current)?;
    let environment_targets = environment_git_targets(environment, &effective)?;
    if current_relation == WorkspacePathRelation::Outside {
        targets.extend(environment_targets.paths.iter().cloned());
    }
    let command = arguments
        .get(command_index)
        .map(|value| os_argument(value, "Git command"))
        .transpose()?;
    let command_targets = command
        .map(|command| {
            command_routing_targets(command, &arguments[command_index + 1..], &effective)
        })
        .transpose()?
        .unwrap_or_default();
    if let Some(destination) = command_targets.destination.as_ref() {
        let (_, destination_guard) =
            roots
                .lock_directory_relation(destination)
                .with_context(|| {
                    format!(
                        "Git {} destination must be pre-created for safe routing",
                        command.unwrap_or("operation")
                    )
                })?;
        path_guards.push(destination_guard);
    }
    targets.extend(command_targets.paths);
    let mut target_relations = Vec::with_capacity(targets.len());
    for target in &targets {
        let (relation, guard) = roots.lock_target_relation(target)?;
        target_relations.push(relation);
        path_guards.push(guard);
    }
    let route = match current_relation {
        WorkspacePathRelation::Outside => {
            if target_relations
                .iter()
                .any(|relation| *relation != WorkspacePathRelation::Outside)
            {
                bail!("unmanaged Git may not target a managed workspace; change directory first");
            }
            GitInvocationRoute::Unmanaged
        }
        WorkspacePathRelation::Inside(root_index) => {
            if has_repository_override || environment_targets.repository_override {
                bail!("managed Git does not admit repository path overrides");
            }
            if command == Some("init") {
                bail!("managed Git does not admit repository initialization");
            }
            if command == Some("clone")
                && target_relations
                    .iter()
                    .any(|target| *target != WorkspacePathRelation::Inside(root_index))
            {
                bail!("managed Git clone destination must remain in the current workspace root");
            }
            GitInvocationRoute::Managed(root_index)
        }
        WorkspacePathRelation::ContainsRoot => {
            bail!("Git invocation directory ambiguously contains a managed workspace")
        }
    };
    Ok(WindowsGitRoutingDecision {
        route,
        _path_guards: path_guards,
    })
}

#[cfg(not(windows))]
fn repository_marker_exists(start: &Path) -> Result<bool> {
    let mut directory = start.to_path_buf();
    loop {
        match fs::symlink_metadata(directory.join(".git")) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    bail!("Git repository marker must not be a symbolic link");
                }
                return Ok(true);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect Git repository marker"),
        }
        if !directory.pop() {
            return Ok(false);
        }
    }
}

fn git_probe_environment(
    environment: &BTreeMap<OsString, OsString>,
) -> BTreeMap<OsString, OsString> {
    let mut output = BTreeMap::new();
    for key in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_INDEX_FILE",
        "COMSPEC",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    ] {
        if let Some(value) = environment_value(environment, key) {
            output.insert(OsString::from(key), value.to_os_string());
        }
    }
    #[cfg(windows)]
    let null_config = "NUL";
    #[cfg(not(windows))]
    let null_config = "/dev/null";
    output.insert("GIT_CONFIG_GLOBAL".into(), null_config.into());
    output.insert("GIT_CONFIG_SYSTEM".into(), null_config.into());
    output.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
    output.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
    output.insert("GIT_OPTIONAL_LOCKS".into(), "0".into());
    output.insert("GIT_NO_LAZY_FETCH".into(), "1".into());
    output.insert("GIT_ASKPASS".into(), "false".into());
    output.insert("SSH_ASKPASS".into(), "false".into());
    output
}

fn human_git_probe_environment(
    environment: &BTreeMap<OsString, OsString>,
) -> BTreeMap<OsString, OsString> {
    let mut output = BTreeMap::new();
    for (key, value) in environment {
        let Some(name) = key.to_str() else {
            continue;
        };
        let normalized = if cfg!(windows) {
            name.to_ascii_uppercase()
        } else {
            name.to_owned()
        };
        let admitted = matches!(
            normalized.as_str(),
            "APPDATA"
                | "COMSPEC"
                | "GIT_ALTERNATE_OBJECT_DIRECTORIES"
                | "GIT_CEILING_DIRECTORIES"
                | "GIT_COMMON_DIR"
                | "GIT_CONFIG"
                | "GIT_CONFIG_COUNT"
                | "GIT_CONFIG_GLOBAL"
                | "GIT_CONFIG_NOSYSTEM"
                | "GIT_CONFIG_PARAMETERS"
                | "GIT_CONFIG_SYSTEM"
                | "GIT_DIR"
                | "GIT_DISCOVERY_ACROSS_FILESYSTEM"
                | "GIT_INDEX_FILE"
                | "GIT_NAMESPACE"
                | "GIT_OBJECT_DIRECTORY"
                | "GIT_SHALLOW_FILE"
                | "GIT_WORK_TREE"
                | "HOME"
                | "HOMEDRIVE"
                | "HOMEPATH"
                | "LANG"
                | "LC_ALL"
                | "LC_CTYPE"
                | "LOCALAPPDATA"
                | "PATHEXT"
                | "PROGRAMDATA"
                | "SYSTEMROOT"
                | "USERPROFILE"
                | "WINDIR"
                | "XDG_CONFIG_HOME"
        ) || normalized.starts_with("GIT_CONFIG_KEY_")
            || normalized.starts_with("GIT_CONFIG_VALUE_");
        if admitted {
            output.insert(key.clone(), value.clone());
        }
    }
    for (key, value) in [
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_NO_LAZY_FETCH", "1"),
        ("GIT_ASKPASS", "false"),
        ("SSH_ASKPASS", "false"),
        ("GCM_INTERACTIVE", "Never"),
    ] {
        output.insert(OsString::from(key), OsString::from(value));
    }
    output
}

fn run_git_path_probe_with_environment(
    program: &str,
    program_guard: &ProgramGuard,
    cwd: &Path,
    environment: BTreeMap<OsString, OsString>,
    selector: &str,
) -> Result<Option<PathBuf>> {
    let mut command = guarded_command(program, program_guard)?;
    let output = command
        .args(["rev-parse", "--path-format=absolute", selector])
        .current_dir(cwd)
        .env_clear()
        .envs(environment)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("inspect Git repository {selector}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    if !output.stderr.is_empty() || output.stdout.len() > RESPONSE_LIMIT as usize {
        bail!("Git repository probe returned an invalid response");
    }
    let text =
        std::str::from_utf8(&output.stdout).context("Git repository probe path is not UTF-8")?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .context("Git repository probe path has no terminator")?;
    if text.is_empty() || text.contains(['\n', '\r', '\0']) || !Path::new(text).is_absolute() {
        bail!("Git repository probe returned an ambiguous path");
    }
    Ok(Some(canonical_candidate_path(Path::new(text), cwd)?))
}

fn run_git_path_probe(
    program: &str,
    program_guard: &ProgramGuard,
    cwd: &Path,
    environment: &BTreeMap<OsString, OsString>,
    selector: &str,
) -> Result<Option<PathBuf>> {
    run_git_path_probe_with_environment(
        program,
        program_guard,
        cwd,
        git_probe_environment(environment),
        selector,
    )
}

fn run_human_git_path_probe(
    program: &str,
    program_guard: &ProgramGuard,
    cwd: &Path,
    environment: &BTreeMap<OsString, OsString>,
    selector: &str,
) -> Result<Option<PathBuf>> {
    run_git_path_probe_with_environment(
        program,
        program_guard,
        cwd,
        human_git_probe_environment(environment),
        selector,
    )
}

fn supported_git_version(stdout: &[u8], stderr: &[u8]) -> bool {
    if !stderr.is_empty() {
        return false;
    }
    let Ok(output) = std::str::from_utf8(stdout) else {
        return false;
    };
    let Some(version) = output
        .strip_suffix("\r\n")
        .or_else(|| output.strip_suffix('\n'))
        .and_then(|line| line.strip_prefix("git version "))
    else {
        return false;
    };
    if version.contains(['\n', '\r', '\0', ' ']) {
        return false;
    }
    let mut components = version.split('.');
    let parsed = (
        components
            .next()
            .and_then(|value| value.parse::<u64>().ok()),
        components
            .next()
            .and_then(|value| value.parse::<u64>().ok()),
        components.next().and_then(|value| {
            let digits: String = value
                .chars()
                .take_while(|character| character.is_ascii_digit())
                .collect();
            (!digits.is_empty())
                .then(|| digits.parse::<u64>().ok())
                .flatten()
        }),
    );
    matches!(parsed, (Some(2), Some(minor), Some(patch)) if (2, minor, patch) >= MINIMUM_GIT_VERSION)
}

pub(super) fn validate_git_version(program: &str, program_guard: &ProgramGuard) -> Result<()> {
    let mut command = guarded_command(program, program_guard)?;
    let output = command
        .arg("--version")
        .env_clear()
        .envs(sanitized_current_environment())
        .stdin(Stdio::null())
        .output()
        .context("inspect configured Git version")?;
    if !output.status.success() || !supported_git_version(&output.stdout, &output.stderr) {
        bail!("configured Git does not satisfy the reviewed 2.40-or-newer major-2 contract");
    }
    Ok(())
}

#[cfg(not(windows))]
fn validate_unmanaged_repository_context(
    program: &str,
    program_guard: &ProgramGuard,
    cwd: &Path,
    roots: &[PathBuf],
    environment: &BTreeMap<OsString, OsString>,
) -> Result<()> {
    let has_repository_hint = repository_marker_exists(cwd)?
        || ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"]
            .iter()
            .any(|key| environment_value(environment, key).is_some());
    let git_dir = run_human_git_path_probe(program, program_guard, cwd, environment, "--git-dir")?;
    if git_dir.is_none() {
        if has_repository_hint {
            bail!("Git repository location is present but cannot be resolved safely");
        }
        return Ok(());
    }
    let common_dir =
        run_human_git_path_probe(program, program_guard, cwd, environment, "--git-common-dir")?
            .context("Git common directory cannot be resolved safely")?;
    let top_level =
        run_human_git_path_probe(program, program_guard, cwd, environment, "--show-toplevel")?;
    for path in [git_dir.as_ref(), Some(&common_dir), top_level.as_ref()]
        .into_iter()
        .flatten()
    {
        if workspace_path_relation(path, roots) != WorkspacePathRelation::Outside {
            bail!("unmanaged Git repository metadata intersects a managed workspace");
        }
    }
    Ok(())
}

#[cfg(windows)]
fn lock_windows_repository_marker_chain(
    cwd: &Path,
    roots: &WindowsWorkspaceRoots,
    path_guards: &mut WindowsPathGuards,
) -> Result<bool> {
    let mut marker_exists = false;
    for directory in cwd.ancestors() {
        let (_, marker_guard) = roots.lock_target_relation(&directory.join(".git"))?;
        marker_exists |= marker_guard.target_exists();
        path_guards.push(marker_guard);
    }
    Ok(marker_exists)
}

#[cfg(windows)]
fn validate_unmanaged_repository_context(
    program: &str,
    program_guard: &ProgramGuard,
    cwd: &Path,
    roots: &WindowsWorkspaceRoots,
    environment: &BTreeMap<OsString, OsString>,
) -> Result<WindowsPathGuards> {
    let git_dir = run_human_git_path_probe(program, program_guard, cwd, environment, "--git-dir")?;
    let mut path_guards = WindowsPathGuards::new();
    if git_dir.is_none() {
        let marker_exists = lock_windows_repository_marker_chain(cwd, roots, &mut path_guards)?;
        if marker_exists
            || ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"]
                .iter()
                .any(|key| environment_value(environment, key).is_some())
        {
            bail!("Git repository location is present but cannot be resolved safely");
        }
        return Ok(path_guards);
    }
    let common_dir =
        run_human_git_path_probe(program, program_guard, cwd, environment, "--git-common-dir")?
            .context("Git common directory cannot be resolved safely")?;
    let top_level =
        run_human_git_path_probe(program, program_guard, cwd, environment, "--show-toplevel")?;
    for path in [git_dir.as_ref(), Some(&common_dir), top_level.as_ref()]
        .into_iter()
        .flatten()
    {
        let (relation, guard) = roots.lock_directory_relation(path)?;
        if relation != WorkspacePathRelation::Outside {
            bail!("unmanaged Git repository metadata intersects a managed workspace");
        }
        path_guards.push(guard);
    }
    Ok(path_guards)
}

fn validate_local_git_config_key(key: &str) -> Result<()> {
    let key = key.to_ascii_lowercase();
    let external_namespace = [
        "alias.",
        "author.",
        "browser.",
        "committer.",
        "credential.",
        "difftool.",
        "filter.",
        "gpg.",
        "guitool.",
        "hook.",
        "include.",
        "includeif.",
        "instaweb.",
        "man.",
        "mergetool.",
        "pager.",
        "protocol.",
        "sendemail.",
        "submodule.",
        "trailer.",
        "uploadpack.",
        "uploadpackfilter.",
        "url.",
        "user.",
        "http.",
        "https.",
    ]
    .iter()
    .any(|prefix| key.starts_with(prefix));
    let exact_external = matches!(
        key.as_str(),
        "blame.ignorerevsfile"
            | "commit.gpgsign"
            | "commit.template"
            | "core.alternaterefscommand"
            | "core.askpass"
            | "core.attributesfile"
            | "core.editor"
            | "core.excludesfile"
            | "core.fsmonitor"
            | "core.gitproxy"
            | "core.hookspath"
            | "core.pager"
            | "core.sshcommand"
            | "core.worktree"
            | "diff.external"
            | "diff.orderfile"
            | "fetch.fsck.skiplist"
            | "format.signaturefile"
            | "fsck.skiplist"
            | "gc.recentobjectshook"
            | "help.htmlpath"
            | "init.templatedir"
            | "interactive.difffilter"
            | "mailmap.blob"
            | "mailmap.file"
            | "merge.guitool"
            | "merge.tool"
            | "pull.octopus"
            | "pull.twohead"
            | "push.gpgsign"
            | "sequence.editor"
            | "tag.forcesignannotated"
            | "tag.gpgsign"
    );
    let structured_external = (key.starts_with("diff.")
        && (key.ends_with(".command") || key.ends_with(".textconv")))
        || (key.starts_with("merge.") && key.ends_with(".driver"))
        || (key.starts_with("remote.")
            && ![".url", ".fetch"]
                .iter()
                .any(|suffix| key.ends_with(suffix)))
        || (key.starts_with("branch.")
            && ![".remote", ".merge"]
                .iter()
                .any(|suffix| key.ends_with(suffix)));
    if external_namespace || exact_external || structured_external {
        bail!("local Git configuration declares an external or alternate authority");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_git_attributes(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("Git attributes file is not UTF-8")?;
    for line in text.lines() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for attribute in line.split_ascii_whitespace().skip(1) {
            let attribute = attribute
                .strip_prefix('-')
                .or_else(|| attribute.strip_prefix('!'))
                .unwrap_or(attribute);
            let name = attribute
                .split_once('=')
                .map_or(attribute, |(name, _)| name);
            if matches!(name, "filter" | "diff" | "merge") {
                bail!("Git attributes select an external content driver");
            }
        }
    }
    Ok(())
}

fn validate_local_git_configuration(
    program: &str,
    program_guard: &ProgramGuard,
    cwd: &Path,
    environment: &BTreeMap<OsString, OsString>,
) -> Result<()> {
    let mut command = guarded_command(program, program_guard)?;
    let output = command
        .args(["config", "--no-includes", "--null", "--name-only", "--list"])
        .current_dir(cwd)
        .env_clear()
        .envs(git_probe_environment(environment))
        .stdin(Stdio::null())
        .output()
        .context("inspect literal local Git configuration")?;
    if !output.status.success()
        || !output.stderr.is_empty()
        || output.stdout.len() > CONFIG_LIMIT as usize
        || output.stdout.last() != Some(&0)
    {
        bail!("literal local Git configuration cannot be validated safely");
    }
    for key in output.stdout[..output.stdout.len() - 1].split(|byte| *byte == 0) {
        if key.is_empty() {
            bail!("literal local Git configuration contains an empty key");
        }
        let key = std::str::from_utf8(key).context("literal local Git key is not UTF-8")?;
        validate_local_git_config_key(key).context("reject local Git configuration authority")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_bounded_public_file(path: &Path, description: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {description} at {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("{description} is not a regular non-link file");
    }
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("open {description}"))?
        .take(CONFIG_LIMIT + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {description}"))?;
    if bytes.len() as u64 > CONFIG_LIMIT {
        bail!("{description} exceeds the size limit");
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct RepositoryAttributesSnapshot {
    working: Vec<(PathBuf, Vec<u8>)>,
    indexed_entries: Vec<u8>,
    indexed_objects: Vec<(Vec<u8>, Vec<u8>)>,
}

#[cfg(target_os = "linux")]
fn repository_attributes_snapshot(
    program: &str,
    program_guard: &ProgramGuard,
    cwd: &Path,
    top_level: &Path,
    git_dir: &Path,
    common_dir: &Path,
) -> Result<RepositoryAttributesSnapshot> {
    const TOTAL_ATTRIBUTES_LIMIT: u64 = 16 * 1024 * 1024;
    use std::os::unix::ffi::OsStringExt;

    let indexed = indexed_git_attributes_snapshot(program, program_guard, cwd)?;
    let mut attribute_paths = vec![top_level.join(".gitattributes")];
    for path in &indexed.paths {
        let relative = PathBuf::from(OsString::from_vec(path.clone()));
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!("indexed Git attributes path is not a safe relative path");
        }
        attribute_paths.push(top_level.join(relative));
    }
    for (index, metadata_directory) in [git_dir, common_dir].into_iter().enumerate() {
        if index == 1 && common_dir == git_dir {
            continue;
        }
        let info_attributes = metadata_directory.join("info/attributes");
        attribute_paths.push(info_attributes);
    }
    attribute_paths.sort();
    attribute_paths.dedup();
    let mut snapshot = Vec::with_capacity(attribute_paths.len());
    let mut total = 0_u64;
    for path in attribute_paths {
        let bytes = match fs::symlink_metadata(&path) {
            Ok(_) => read_bounded_public_file(&path, "Git attributes file")?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("inspect Git attributes file"),
        };
        total = total
            .checked_add(bytes.len() as u64)
            .context("Git attributes size overflow")?;
        if total > TOTAL_ATTRIBUTES_LIMIT {
            bail!("managed repository exceeds the attributes size limit");
        }
        validate_git_attributes(&bytes)?;
        snapshot.push((path, bytes));
    }
    Ok(RepositoryAttributesSnapshot {
        working: snapshot,
        indexed_entries: indexed.entries,
        indexed_objects: indexed.objects,
    })
}

#[cfg(target_os = "linux")]
fn validate_repository_attributes(
    program: &str,
    program_guard: &ProgramGuard,
    cwd: &Path,
    top_level: &Path,
    git_dir: &Path,
    common_dir: &Path,
) -> Result<()> {
    repository_attributes_snapshot(program, program_guard, cwd, top_level, git_dir, common_dir)
        .map(|_| ())
}

#[cfg(not(target_os = "linux"))]
fn validate_repository_attributes(
    _program: &str,
    _program_guard: &ProgramGuard,
    _cwd: &Path,
    _top_level: &Path,
    _git_dir: &Path,
    _common_dir: &Path,
) -> Result<()> {
    bail!("managed Git repository attributes are not accepted on this platform")
}

fn reject_persistent_alternate_objects_path(common_dir: &Path) -> Result<()> {
    let alternates = common_dir.join("objects/info/alternates");
    match fs::symlink_metadata(&alternates) {
        Ok(_) => bail!("persistent Git alternate object databases are not admitted"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect persistent Git alternates authority"),
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct HeldRepositoryPath {
    path: PathBuf,
    file: File,
    directory: bool,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(target_os = "linux")]
impl HeldRepositoryPath {
    fn open(path: &Path, directory: bool) -> Result<Self> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        let file = options
            .open(path)
            .with_context(|| format!("hold Git repository authority at {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("inspect held Git authority at {}", path.display()))?;
        if metadata.file_type().is_symlink()
            || (directory && !metadata.file_type().is_dir())
            || (!directory && !metadata.file_type().is_file())
        {
            bail!("Git repository authority has an unsafe file type");
        }
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o022 != 0
        {
            bail!("Git repository authority must be current-user owned and not writable by group or others");
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
            directory,
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }

    fn verify_path_identity(&self) -> Result<()> {
        self.verify_path_identity_with_mutable_directory(false)
    }

    fn verify_path_identity_with_mutable_directory(
        &self,
        allow_directory_contents_to_change: bool,
    ) -> Result<()> {
        let metadata = fs::symlink_metadata(&self.path)
            .with_context(|| format!("reinspect Git authority at {}", self.path.display()))?;
        if metadata.file_type().is_symlink()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != self.uid
            || metadata.gid() != self.gid
            || metadata.mode() != self.mode
            || (!allow_directory_contents_to_change && metadata.nlink() != self.links)
            || (!self.directory
                && (metadata.len() != self.length
                    || metadata.mtime() != self.modified_seconds
                    || metadata.mtime_nsec() != self.modified_nanoseconds
                    || metadata.ctime() != self.changed_seconds
                    || metadata.ctime_nsec() != self.changed_nanoseconds))
        {
            bail!("Git repository authority changed during validation");
        }
        Ok(())
    }

    fn read_bounded(&self, limit: u64) -> Result<Vec<u8>> {
        let length = self
            .file
            .metadata()
            .context("inspect held Git authority file before reading")?
            .len();
        if length > limit {
            bail!("Git repository authority file exceeds its size limit");
        }
        let length = usize::try_from(length).context("Git authority file size is unsupported")?;
        let mut bytes = vec![0_u8; length];
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let read = std::os::unix::fs::FileExt::read_at(
                &self.file,
                &mut bytes[offset..],
                offset as u64,
            )
            .context("read held Git authority file")?;
            if read == 0 {
                bail!("Git repository authority changed while being read");
            }
            offset += read;
        }
        Ok(bytes)
    }

    fn update_digest(&self, digest: &mut Sha256, label: &[u8], bytes: Option<&[u8]>) {
        use std::os::unix::ffi::OsStrExt;

        update_length_prefixed_digest(digest, label);
        update_length_prefixed_digest(digest, self.path.as_os_str().as_bytes());
        digest.update(self.device.to_be_bytes());
        digest.update(self.inode.to_be_bytes());
        digest.update(self.uid.to_be_bytes());
        digest.update(self.gid.to_be_bytes());
        digest.update(self.mode.to_be_bytes());
        digest.update(self.links.to_be_bytes());
        digest.update(self.length.to_be_bytes());
        if !self.directory {
            digest.update(self.modified_seconds.to_be_bytes());
            digest.update(self.modified_nanoseconds.to_be_bytes());
            digest.update(self.changed_seconds.to_be_bytes());
            digest.update(self.changed_nanoseconds.to_be_bytes());
        }
        if let Some(bytes) = bytes {
            update_length_prefixed_digest(digest, bytes);
        }
    }

    fn update_mutable_directory_digest(&self, digest: &mut Sha256, label: &[u8]) {
        use std::os::unix::ffi::OsStrExt;

        update_length_prefixed_digest(digest, label);
        update_length_prefixed_digest(digest, self.path.as_os_str().as_bytes());
        digest.update(self.device.to_be_bytes());
        digest.update(self.inode.to_be_bytes());
        digest.update(self.uid.to_be_bytes());
        digest.update(self.gid.to_be_bytes());
        digest.update(self.mode.to_be_bytes());
    }
}

#[cfg(target_os = "linux")]
fn update_length_prefixed_digest(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

#[derive(Debug)]
struct GitChildAuthorityBinding {
    kind: &'static str,
    operation: String,
    digest: String,
    root: PathBuf,
    #[cfg(target_os = "linux")]
    ref_selectors: Vec<String>,
    #[cfg(target_os = "linux")]
    mutable_ref_selectors: BTreeSet<String>,
    #[cfg(target_os = "linux")]
    reference_values: BTreeMap<String, Option<String>>,
    #[cfg(target_os = "linux")]
    git_dir: PathBuf,
    #[cfg(target_os = "linux")]
    common_dir: PathBuf,
    #[cfg(target_os = "linux")]
    mutable_after_child: BTreeSet<PathBuf>,
    #[cfg(target_os = "linux")]
    _held_paths: Vec<HeldRepositoryPath>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct GitAuthorityRequest<'a> {
    config_digest: &'a str,
    capability: &'a str,
    operation: &'a str,
    owner: &'a str,
    repository: &'a str,
    ref_selectors: &'a [String],
    mutable_ref_selectors: &'a [String],
}

#[cfg(target_os = "linux")]
fn valid_bound_ref_selector(value: &str) -> bool {
    if matches!(value, "HEAD" | "FETCH_HEAD") {
        return true;
    }
    let relative = value
        .strip_prefix("refs/heads/")
        .or_else(|| value.strip_prefix("refs/tags/"))
        .or_else(|| value.strip_prefix("refs/remotes/origin/"));
    relative.is_some_and(|relative| {
        !relative.is_empty()
            && relative.len() <= 1024
            && relative.split('/').all(|component| {
                !component.is_empty()
                    && component != "."
                    && component != ".."
                    && !component.starts_with('.')
                    && !component.ends_with(['.', '/'])
                    && !component.ends_with(".lock")
                    && !component.contains("..")
                    && !component.contains("@{")
                    && !component.chars().any(|character| {
                        character.is_control()
                            || character.is_whitespace()
                            || matches!(character, '~' | '^' | ':' | '?' | '*' | '[' | '\\')
                    })
            })
    })
}

#[cfg(target_os = "linux")]
fn git_ref_authority_selectors(arguments: &[String]) -> Result<Vec<String>> {
    let (operation, tail) = arguments
        .split_first()
        .context("managed Git operation is missing")?;
    let mut selectors = Vec::new();
    match operation.as_str() {
        "commit" => selectors.push("HEAD".to_owned()),
        "tag" => {
            let mut index = 0_usize;
            let mut positionals = Vec::new();
            while index < tail.len() {
                match tail[index].as_str() {
                    "-m" | "--message" | "-F" | "--file" => index += 2,
                    "-a" | "--annotate" => index += 1,
                    value => {
                        positionals.push(value);
                        index += 1;
                    }
                }
            }
            let tag = positionals
                .first()
                .context("managed Git tag name is missing")?;
            selectors.push(format!("refs/tags/{tag}"));
            match positionals.get(1).copied().unwrap_or("HEAD") {
                value @ ("HEAD" | "FETCH_HEAD") => selectors.push(value.to_owned()),
                value if value.starts_with("refs/") => selectors.push(value.to_owned()),
                value
                    if matches!(value.len(), 40 | 64)
                        && value.bytes().all(|byte| byte.is_ascii_hexdigit()) => {}
                _ => bail!("managed Git tag target cannot be bound exactly"),
            }
        }
        "push" | "fetch" => {
            for refspec in tail.iter().filter(|value| value.contains(':')) {
                let (source, destination) = refspec
                    .split_once(':')
                    .context("managed Git refspec is malformed")?;
                let selector = if operation == "push" {
                    source
                } else {
                    destination
                };
                selectors.push(selector.to_owned());
            }
        }
        _ => {}
    }
    selectors.sort();
    selectors.dedup();
    if selectors.len() > 128 {
        bail!("managed Git reference authority has too many selectors");
    }
    if selectors
        .iter()
        .any(|value| !valid_bound_ref_selector(value))
    {
        bail!("managed Git reference authority is malformed");
    }
    Ok(selectors)
}

#[cfg(target_os = "linux")]
fn git_mutable_ref_selectors(arguments: &[String]) -> Result<Vec<String>> {
    let (operation, tail) = arguments
        .split_first()
        .context("managed Git operation is missing")?;
    let mut selectors = Vec::new();
    match operation.as_str() {
        "commit" => selectors.push("HEAD".to_owned()),
        "tag" => {
            let mut index = 0_usize;
            while index < tail.len() {
                match tail[index].as_str() {
                    "-m" | "--message" | "-F" | "--file" => index += 2,
                    "-a" | "--annotate" => index += 1,
                    value => {
                        selectors.push(format!("refs/tags/{value}"));
                        break;
                    }
                }
            }
        }
        "fetch" => {
            selectors.extend(
                tail.iter()
                    .filter_map(|value| value.split_once(':').map(|(_, destination)| destination))
                    .map(ToOwned::to_owned),
            );
        }
        _ => {}
    }
    selectors.sort();
    selectors.dedup();
    if selectors
        .iter()
        .any(|selector| !valid_bound_ref_selector(selector))
    {
        bail!("managed Git mutable reference authority is malformed");
    }
    Ok(selectors)
}

impl GitChildAuthorityBinding {
    #[cfg(target_os = "linux")]
    fn verify_held_paths(&self) -> Result<()> {
        for held in &self._held_paths {
            held.verify_path_identity_with_mutable_directory(self.kind == "clone")?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn verify_after_child(&self) -> Result<()> {
        for held in &self._held_paths {
            if self.mutable_after_child.contains(&held.path) {
                continue;
            }
            held.verify_path_identity_with_mutable_directory(held.directory)?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn operation_mutates_repository_authority(operation: &str) -> bool {
    matches!(
        operation,
        "add" | "restore" | "checkout" | "commit" | "tag" | "fetch"
    )
}

#[cfg(target_os = "linux")]
fn git_configuration_scope_snapshot(
    program: &str,
    program_guard: &ProgramGuard,
    cwd: &Path,
    scope: &str,
) -> Result<Vec<u8>> {
    let mut command = guarded_command(program, program_guard)?;
    let output = command
        .args([
            "config",
            scope,
            "--no-includes",
            "--null",
            "--show-origin",
            "--show-scope",
            "--list",
        ])
        .current_dir(cwd)
        .env_clear()
        .envs(git_probe_environment(&BTreeMap::new()))
        .stdin(Stdio::null())
        .output()
        .context("snapshot effective Git configuration scope")?;
    if !output.status.success()
        || !output.stderr.is_empty()
        || output.stdout.len() as u64 > CONFIG_LIMIT
        || output.stdout.last() != Some(&0)
    {
        bail!("effective Git configuration scope cannot be bound safely");
    }
    Ok(output.stdout)
}

#[cfg(target_os = "linux")]
struct IndexedGitAttributesSnapshot {
    entries: Vec<u8>,
    objects: Vec<(Vec<u8>, Vec<u8>)>,
    paths: Vec<Vec<u8>>,
}

#[cfg(target_os = "linux")]
fn indexed_git_attributes_snapshot(
    program: &str,
    program_guard: &ProgramGuard,
    cwd: &Path,
) -> Result<IndexedGitAttributesSnapshot> {
    let mut command = guarded_command(program, program_guard)?;
    let output = command
        .args([
            "ls-files",
            "--stage",
            "-z",
            "--",
            ".gitattributes",
            ":(glob)**/.gitattributes",
        ])
        .current_dir(cwd)
        .env_clear()
        .envs(git_probe_environment(&BTreeMap::new()))
        .stdin(Stdio::null())
        .output()
        .context("snapshot indexed Git attributes")?;
    if !output.status.success()
        || !output.stderr.is_empty()
        || output.stdout.len() as u64 > CONFIG_LIMIT
    {
        bail!("indexed Git attributes cannot be bound safely");
    }
    let mut object_ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for entry in output.stdout.split(|byte| *byte == 0) {
        if entry.is_empty() {
            continue;
        }
        let tab = entry
            .iter()
            .position(|byte| *byte == b'\t')
            .context("indexed Git attribute entry is malformed")?;
        let header = &entry[..tab];
        let mut fields = header.split(|byte| *byte == b' ');
        let mode = fields.next().unwrap_or_default();
        let object = fields.next().unwrap_or_default();
        let stage = fields.next().unwrap_or_default();
        if mode.is_empty()
            || object.len() < 40
            || !object.iter().all(u8::is_ascii_hexdigit)
            || stage != b"0"
            || fields.next().is_some()
        {
            bail!("indexed Git attribute entry is ambiguous");
        }
        object_ids.insert(object.to_vec());
        let path = &entry[tab + 1..];
        if path.is_empty() || path.contains(&0) {
            bail!("indexed Git attribute path is ambiguous");
        }
        paths.insert(path.to_vec());
    }
    let objects = read_indexed_attribute_objects_batch(program, program_guard, cwd, object_ids)?;
    Ok(IndexedGitAttributesSnapshot {
        entries: output.stdout,
        objects,
        paths: paths.into_iter().collect(),
    })
}

#[cfg(target_os = "linux")]
fn read_indexed_attribute_objects_batch(
    program: &str,
    program_guard: &ProgramGuard,
    cwd: &Path,
    object_ids: BTreeSet<Vec<u8>>,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    use std::io::{BufRead, BufReader, Write};

    const HEADER_LIMIT: u64 = 1024;
    const OBJECT_LIMIT: u64 = CONFIG_LIMIT;
    const AGGREGATE_LIMIT: u64 = 16 * 1024 * 1024;

    if object_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut requests = Vec::with_capacity(object_ids.len());
    for object in &object_ids {
        if object.len() < 40 || !object.iter().all(u8::is_ascii_hexdigit) {
            bail!("indexed Git attributes object ID is malformed");
        }
        requests.extend_from_slice(object);
        requests.push(b'\n');
    }
    let mut command = guarded_command(program, program_guard)?;
    let mut child = command
        .args(["cat-file", "--batch"])
        .current_dir(cwd)
        .env_clear()
        .envs(git_probe_environment(&BTreeMap::new()))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("start indexed Git attributes object batch")?;
    let mut input = child
        .stdin
        .take()
        .context("indexed Git attributes batch has no standard input")?;
    let writer = std::thread::spawn(move || -> io::Result<()> {
        input.write_all(&requests)?;
        input.flush()
    });
    let output = child
        .stdout
        .take()
        .context("indexed Git attributes batch has no standard output")?;
    let mut output = BufReader::new(output);
    let mut objects = Vec::with_capacity(object_ids.len());
    let mut aggregate = 0_u64;
    for expected in object_ids {
        let mut header = Vec::new();
        let count = output
            .by_ref()
            .take(HEADER_LIMIT + 1)
            .read_until(b'\n', &mut header)
            .context("read indexed Git attributes object header")?;
        if count == 0
            || count as u64 > HEADER_LIMIT
            || header.last() != Some(&b'\n')
            || header.contains(&0)
        {
            bail!("indexed Git attributes object header is malformed");
        }
        header.pop();
        let mut fields = header.split(|byte| *byte == b' ');
        let actual = fields.next().unwrap_or_default();
        let object_type = fields.next().unwrap_or_default();
        let size = std::str::from_utf8(fields.next().unwrap_or_default())
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .context("indexed Git attributes object size is malformed")?;
        if actual != expected
            || object_type != b"blob"
            || fields.next().is_some()
            || size > OBJECT_LIMIT
        {
            bail!("indexed Git attributes batch returned an unexpected object");
        }
        aggregate = aggregate
            .checked_add(size)
            .context("indexed Git attributes size overflow")?;
        if aggregate > AGGREGATE_LIMIT {
            bail!("indexed Git attributes exceed the aggregate size limit");
        }
        let mut bytes = vec![0_u8; size as usize];
        output
            .read_exact(&mut bytes)
            .context("read indexed Git attributes object")?;
        let mut terminator = [0_u8; 1];
        output
            .read_exact(&mut terminator)
            .context("read indexed Git attributes object terminator")?;
        if terminator != *b"\n" {
            bail!("indexed Git attributes object terminator is malformed");
        }
        validate_git_attributes(&bytes)?;
        objects.push((expected, bytes));
    }
    let mut trailing = [0_u8; 1];
    if output
        .read(&mut trailing)
        .context("check indexed Git attributes batch completion")?
        != 0
    {
        bail!("indexed Git attributes batch returned trailing output");
    }
    writer
        .join()
        .map_err(|_| anyhow::anyhow!("indexed Git attributes batch writer failed"))?
        .context("write indexed Git attributes object requests")?;
    if !child
        .wait()
        .context("wait for indexed Git attributes object batch")?
        .success()
    {
        bail!("indexed Git attributes object batch failed");
    }
    Ok(objects)
}

#[cfg(target_os = "linux")]
fn reject_persistent_alternate_objects(
    common_dir: &Path,
    held_paths: &mut Vec<HeldRepositoryPath>,
) -> Result<()> {
    let objects = common_dir.join("objects");
    held_paths.push(HeldRepositoryPath::open(&objects, true)?);
    let info = objects.join("info");
    match fs::symlink_metadata(&info) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            held_paths.push(HeldRepositoryPath::open(&info, true)?);
        }
        Ok(_) => bail!("Git object-info authority has an unsafe file type"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect Git object-info authority"),
    }
    reject_persistent_alternate_objects_path(common_dir)
}

#[cfg(target_os = "linux")]
fn push_unique_held_path(
    held_paths: &mut Vec<HeldRepositoryPath>,
    path: &Path,
    directory: bool,
) -> Result<()> {
    if held_paths.iter().any(|held| held.path == path) {
        return Ok(());
    }
    held_paths.push(HeldRepositoryPath::open(path, directory)?);
    Ok(())
}

#[cfg(target_os = "linux")]
fn hold_optional_regular_authority(
    held_paths: &mut Vec<HeldRepositoryPath>,
    path: &Path,
) -> Result<Option<usize>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            if let Some(index) = held_paths.iter().position(|held| held.path == path) {
                return Ok(Some(index));
            }
            held_paths.push(HeldRepositoryPath::open(path, false)?);
            Ok(Some(held_paths.len() - 1))
        }
        Ok(_) => bail!("Git reference authority has an unsafe file type"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("inspect Git reference authority"),
    }
}

#[cfg(target_os = "linux")]
fn hold_loose_ref_authority(
    common_dir: &Path,
    selector: &str,
    held_paths: &mut Vec<HeldRepositoryPath>,
) -> Result<()> {
    if !selector.starts_with("refs/") || !valid_bound_ref_selector(selector) {
        bail!("Git loose-reference authority is malformed");
    }
    let relative = Path::new(selector);
    let final_path = common_dir.join(relative);
    let parent = final_path
        .parent()
        .context("Git loose-reference authority has no parent")?;
    let mut current = common_dir.to_path_buf();
    for component in parent
        .strip_prefix(common_dir)
        .context("Git loose-reference authority leaves the common directory")?
        .components()
    {
        if !matches!(component, std::path::Component::Normal(_)) {
            bail!("Git loose-reference authority is not lexical");
        }
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
                push_unique_held_path(held_paths, &current, true)?;
            }
            Ok(_) => bail!("Git loose-reference directory has an unsafe file type"),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("inspect Git loose-reference directory"),
        }
    }
    hold_optional_regular_authority(held_paths, &final_path)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn hold_reference_authority(
    git_dir: &Path,
    common_dir: &Path,
    selectors: &[String],
    held_paths: &mut Vec<HeldRepositoryPath>,
) -> Result<Vec<String>> {
    let mut selectors = selectors.to_vec();
    selectors.sort();
    selectors.dedup();
    if selectors
        .iter()
        .any(|value| !valid_bound_ref_selector(value))
    {
        bail!("Git reference authority selector is malformed");
    }
    if selectors.is_empty() {
        return Ok(selectors);
    }
    hold_optional_regular_authority(held_paths, &common_dir.join("packed-refs"))?;
    if selectors.iter().any(|value| value == "HEAD") {
        let index = hold_optional_regular_authority(held_paths, &git_dir.join("HEAD"))?
            .context("Git HEAD authority is missing")?;
        let head = held_paths[index].read_bounded(4096)?;
        let head = std::str::from_utf8(&head).context("Git HEAD authority is not UTF-8")?;
        let head = head.trim_end_matches(['\r', '\n']);
        if let Some(symbolic) = head.strip_prefix("ref: ") {
            if !valid_bound_ref_selector(symbolic) || !symbolic.starts_with("refs/") {
                bail!("Git symbolic HEAD authority is malformed");
            }
            selectors.push(symbolic.to_owned());
        } else if !matches!(head.len(), 40 | 64)
            || !head.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("Git detached HEAD authority is malformed");
        }
    }
    if selectors.iter().any(|value| value == "FETCH_HEAD") {
        hold_optional_regular_authority(held_paths, &git_dir.join("FETCH_HEAD"))?;
    }
    selectors.sort();
    selectors.dedup();
    for selector in selectors.iter().filter(|value| value.starts_with("refs/")) {
        hold_loose_ref_authority(common_dir, selector, held_paths)?;
    }
    Ok(selectors)
}

#[cfg(target_os = "linux")]
fn exact_reference_hash(bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes).context("Git reference value is not UTF-8")?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if !matches!(text.len(), 40 | 64) || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("Git reference value is malformed");
    }
    Ok(text.to_ascii_lowercase())
}

#[cfg(target_os = "linux")]
fn packed_reference_values(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    let text = std::str::from_utf8(bytes).context("packed Git references are not UTF-8")?;
    let mut references = BTreeMap::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(peeled) = line.strip_prefix('^') {
            exact_reference_hash(peeled.as_bytes())?;
            continue;
        }
        let (hash, reference) = line
            .split_once(' ')
            .context("packed Git reference line is malformed")?;
        if reference.is_empty()
            || reference.contains(char::is_whitespace)
            || !reference.starts_with("refs/")
        {
            bail!("packed Git reference name is malformed");
        }
        let hash = exact_reference_hash(hash.as_bytes())?;
        if references.insert(reference.to_owned(), hash).is_some() {
            bail!("packed Git reference is duplicated");
        }
    }
    Ok(references)
}

#[cfg(target_os = "linux")]
fn held_file<'a>(
    held_paths: &'a [HeldRepositoryPath],
    path: &Path,
) -> Option<&'a HeldRepositoryPath> {
    held_paths
        .iter()
        .find(|held| held.path == path && !held.directory)
}

#[cfg(target_os = "linux")]
fn reference_authority_values(
    git_dir: &Path,
    common_dir: &Path,
    selectors: &[String],
    held_paths: &[HeldRepositoryPath],
) -> Result<BTreeMap<String, Option<String>>> {
    let packed_path = common_dir.join("packed-refs");
    let packed = match held_file(held_paths, &packed_path) {
        Some(held) => packed_reference_values(&held.read_bounded(16 * 1024 * 1024)?)?,
        None => BTreeMap::new(),
    };
    let mut values = BTreeMap::new();
    for selector in selectors {
        let value = match selector.as_str() {
            "HEAD" => {
                let held = held_file(held_paths, &git_dir.join("HEAD"))
                    .context("Git HEAD authority is missing")?;
                let bytes = held.read_bounded(4096)?;
                let text = std::str::from_utf8(&bytes).context("Git HEAD is not UTF-8")?;
                let text = text.trim_end_matches(['\r', '\n']);
                if let Some(symbolic) = text.strip_prefix("ref: ") {
                    if !valid_bound_ref_selector(symbolic) || !symbolic.starts_with("refs/") {
                        bail!("Git symbolic HEAD authority is malformed");
                    }
                    Some(format!("ref:{symbolic}"))
                } else {
                    Some(
                        exact_reference_hash(text.as_bytes())
                            .context("validate detached Git HEAD authority")?,
                    )
                }
            }
            "FETCH_HEAD" => match held_file(held_paths, &git_dir.join("FETCH_HEAD")) {
                Some(held) => {
                    let bytes = held.read_bounded(16 * 1024 * 1024)?;
                    if bytes.is_empty() {
                        bail!("Git FETCH_HEAD authority is empty");
                    }
                    for line in bytes
                        .split(|byte| *byte == b'\n')
                        .filter(|line| !line.is_empty())
                    {
                        let hash = line
                            .split(|byte| *byte == b'\t' || *byte == b' ')
                            .next()
                            .context("Git FETCH_HEAD line is malformed")?;
                        exact_reference_hash(hash).context("validate Git FETCH_HEAD authority")?;
                    }
                    Some(format!("sha256:{:x}", Sha256::digest(&bytes)))
                }
                None => None,
            },
            reference if reference.starts_with("refs/") => {
                match held_file(held_paths, &common_dir.join(reference)) {
                    Some(held) => Some(
                        exact_reference_hash(&held.read_bounded(4096)?)
                            .context("validate loose Git reference authority")?,
                    ),
                    None => packed.get(reference).cloned(),
                }
            }
            _ => bail!("Git reference authority selector is malformed"),
        };
        values.insert(selector.clone(), value);
    }
    Ok(values)
}

#[cfg(target_os = "linux")]
fn current_reference_authority_values(
    binding: &GitChildAuthorityBinding,
) -> Result<BTreeMap<String, Option<String>>> {
    let mut held_paths = Vec::new();
    let selectors = hold_reference_authority(
        &binding.git_dir,
        &binding.common_dir,
        &binding.ref_selectors,
        &mut held_paths,
    )?;
    if selectors != binding.ref_selectors {
        bail!("managed Git symbolic reference authority changed unexpectedly");
    }
    let values = reference_authority_values(
        &binding.git_dir,
        &binding.common_dir,
        &binding.ref_selectors,
        &held_paths,
    )?;
    for held in &held_paths {
        held.verify_path_identity()?;
    }
    Ok(values)
}

#[cfg(target_os = "linux")]
fn verify_reference_authority_transition(
    binding: &GitChildAuthorityBinding,
    child_succeeded: bool,
    dry_run: bool,
) -> Result<()> {
    if binding.ref_selectors.is_empty() {
        return Ok(());
    }
    let current = current_reference_authority_values(binding)?;
    if !child_succeeded || dry_run {
        if current != binding.reference_values {
            bail!("managed Git reference authority changed after a non-mutating result");
        }
        return Ok(());
    }
    for selector in &binding.ref_selectors {
        if !binding.mutable_ref_selectors.contains(selector)
            && current.get(selector) != binding.reference_values.get(selector)
        {
            bail!("managed Git changed a reference outside its declared operation");
        }
    }
    match binding.operation.as_str() {
        "commit" => {
            let before_head = binding
                .reference_values
                .get("HEAD")
                .and_then(Option::as_deref)
                .context("managed Git commit has no bound HEAD")?;
            let after_head = current
                .get("HEAD")
                .and_then(Option::as_deref)
                .context("managed Git commit removed HEAD")?;
            if let Some(symbolic) = before_head.strip_prefix("ref:") {
                if after_head != before_head
                    || current.get(symbolic).and_then(Option::as_deref).is_none()
                    || current.get(symbolic) == binding.reference_values.get(symbolic)
                {
                    bail!("managed Git commit did not produce its declared reference transition");
                }
            } else if after_head == before_head {
                bail!("managed Git commit did not advance detached HEAD");
            }
        }
        "tag" => {
            if binding.mutable_ref_selectors.len() != 1 {
                bail!("managed Git tag mutation authority is ambiguous");
            }
            let destination = binding
                .mutable_ref_selectors
                .iter()
                .next()
                .context("managed Git tag destination is missing")?;
            if current
                .get(destination)
                .and_then(Option::as_deref)
                .is_none()
                || current.get(destination) == binding.reference_values.get(destination)
            {
                bail!("managed Git tag did not create its declared reference");
            }
        }
        "fetch" => {
            for selector in &binding.mutable_ref_selectors {
                if current.get(selector).and_then(Option::as_deref).is_none() {
                    bail!("managed Git fetch did not materialize a declared reference");
                }
            }
        }
        "push" => {
            if current != binding.reference_values {
                bail!("managed Git push changed local reference authority");
            }
        }
        _ if binding.mutable_ref_selectors.is_empty() => {
            if current != binding.reference_values {
                bail!("managed Git changed reference authority unexpectedly");
            }
        }
        _ => bail!("managed Git reference mutation has no bounded postcondition"),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct ResolvedRepositoryPaths {
    top_level: PathBuf,
    git_dir: PathBuf,
    common_dir: PathBuf,
    held_selectors: Vec<HeldRepositoryPath>,
}

#[cfg(target_os = "linux")]
fn resolve_commondir_selector(git_dir: &Path, value: &str) -> Result<PathBuf> {
    let selector = Path::new(value);
    let normalized = if selector.is_absolute() {
        selector.to_path_buf()
    } else {
        let mut path = git_dir.to_path_buf();
        for component in selector.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    if !path.pop() {
                        bail!("linked-worktree common directory selector escapes the filesystem");
                    }
                }
                std::path::Component::Normal(component) => path.push(component),
                std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                    bail!("linked-worktree common directory selector is malformed")
                }
            }
        }
        path
    };
    canonical_candidate_path(&normalized, git_dir)
        .context("resolve linked-worktree common directory selector")
}

#[cfg(target_os = "linux")]
fn resolved_repository_paths(
    program: &str,
    program_guard: &ProgramGuard,
    cwd: &Path,
) -> Result<ResolvedRepositoryPaths> {
    let environment = BTreeMap::new();
    let git_dir = run_git_path_probe(program, program_guard, cwd, &environment, "--git-dir")?
        .context("managed Git directory cannot be resolved safely")?;
    let mut held_selectors = vec![HeldRepositoryPath::open(&git_dir, true)?];
    let commondir_path = git_dir.join("commondir");
    let expected_common_dir = match fs::symlink_metadata(&commondir_path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            let held = HeldRepositoryPath::open(&commondir_path, false)?;
            let bytes = held.read_bounded(RESPONSE_LIMIT)?;
            let text = std::str::from_utf8(&bytes)
                .context("linked-worktree common directory selector is not UTF-8")?;
            let value = text
                .strip_suffix('\n')
                .context("linked-worktree common directory selector has no terminator")?;
            if value.is_empty() || value.contains(['\n', '\r', '\0']) {
                bail!("linked-worktree common directory selector is malformed");
            }
            let selected = resolve_commondir_selector(&git_dir, value)?;
            held_selectors.push(held);
            selected
        }
        Ok(_) => bail!("linked-worktree common directory selector has an unsafe file type"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => git_dir.clone(),
        Err(error) => {
            return Err(error).context("inspect linked-worktree common directory selector")
        }
    };
    let common_dir = run_git_path_probe(
        program,
        program_guard,
        cwd,
        &environment,
        "--git-common-dir",
    )?
    .context("managed Git common directory cannot be resolved safely")?;
    if common_dir != expected_common_dir {
        bail!("linked-worktree common directory does not match its held selector");
    }
    let top_level =
        run_git_path_probe(program, program_guard, cwd, &environment, "--show-toplevel")?
            .context("managed Git worktree cannot be resolved safely")?;
    for held in &held_selectors {
        held.verify_path_identity()?;
    }
    Ok(ResolvedRepositoryPaths {
        top_level,
        git_dir,
        common_dir,
        held_selectors,
    })
}

#[cfg(target_os = "linux")]
fn repository_authority_binding(
    program: &str,
    program_guard: &ProgramGuard,
    cwd: &Path,
    request: GitAuthorityRequest<'_>,
) -> Result<GitChildAuthorityBinding> {
    let resolved = resolved_repository_paths(program, program_guard, cwd)?;
    let ResolvedRepositoryPaths {
        top_level,
        git_dir,
        common_dir,
        held_selectors,
    } = resolved;
    let actual_repository =
        literal_origin_repository_at_os(program, program_guard, cwd, &BTreeMap::new())?;
    if actual_repository != (request.owner.to_owned(), request.repository.to_owned()) {
        bail!("managed Git origin changed after repository selection");
    }
    validate_local_git_configuration(program, program_guard, cwd, &BTreeMap::new())?;
    let local_config = git_configuration_scope_snapshot(program, program_guard, cwd, "--local")?;
    let worktree_config =
        git_configuration_scope_snapshot(program, program_guard, cwd, "--worktree")?;

    let mut held_paths = held_selectors;
    for directory in [&top_level, &git_dir, &common_dir] {
        if held_paths
            .iter()
            .any(|held: &HeldRepositoryPath| held.path == *directory)
        {
            continue;
        }
        held_paths.push(HeldRepositoryPath::open(directory, true)?);
    }
    reject_persistent_alternate_objects(&common_dir, &mut held_paths)?;
    let ref_selectors = hold_reference_authority(
        &git_dir,
        &common_dir,
        request.ref_selectors,
        &mut held_paths,
    )?;
    let reference_values =
        reference_authority_values(&git_dir, &common_dir, &ref_selectors, &held_paths)?;
    let mut mutable_ref_selectors: BTreeSet<String> =
        request.mutable_ref_selectors.iter().cloned().collect();
    if request.operation == "commit" {
        if let Some(Some(symbolic)) = reference_values.get("HEAD") {
            if let Some(reference) = symbolic.strip_prefix("ref:") {
                mutable_ref_selectors.insert(reference.to_owned());
            }
        }
    }
    let attributes = repository_attributes_snapshot(
        program,
        program_guard,
        cwd,
        &top_level,
        &git_dir,
        &common_dir,
    )?;
    let mut public_files = vec![top_level.join(".git")];
    for metadata_directory in [&git_dir, &common_dir] {
        for relative in ["config", "config.worktree"] {
            public_files.push(metadata_directory.join(relative));
        }
    }
    public_files.push(git_dir.join("index"));
    public_files.extend(attributes.working.iter().map(|(path, _)| path.clone()));
    public_files.sort();
    public_files.dedup();
    for path in public_files {
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                held_paths.push(HeldRepositoryPath::open(&path, false)?);
            }
            Ok(metadata) if metadata.file_type().is_dir() && path == top_level.join(".git") => {
                held_paths.push(HeldRepositoryPath::open(&path, true)?);
            }
            Ok(_) => bail!("Git repository authority contains an unsafe path"),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect Git repository authority path"),
        }
    }

    let mut digest = Sha256::new();
    update_length_prefixed_digest(&mut digest, b"dev-auth-git-repository-authority-v1");
    update_length_prefixed_digest(&mut digest, request.config_digest.as_bytes());
    update_length_prefixed_digest(&mut digest, request.capability.as_bytes());
    update_length_prefixed_digest(&mut digest, request.operation.as_bytes());
    update_length_prefixed_digest(&mut digest, request.owner.as_bytes());
    update_length_prefixed_digest(&mut digest, request.repository.as_bytes());
    for selector in &ref_selectors {
        update_length_prefixed_digest(&mut digest, b"reference");
        update_length_prefixed_digest(&mut digest, selector.as_bytes());
        if let Some(Some(value)) = reference_values.get(selector) {
            update_length_prefixed_digest(&mut digest, value.as_bytes());
        }
    }
    for selector in &mutable_ref_selectors {
        update_length_prefixed_digest(&mut digest, b"mutable-reference");
        update_length_prefixed_digest(&mut digest, selector.as_bytes());
    }
    update_length_prefixed_digest(&mut digest, b"local-config");
    update_length_prefixed_digest(&mut digest, &local_config);
    update_length_prefixed_digest(&mut digest, b"worktree-config");
    update_length_prefixed_digest(&mut digest, &worktree_config);
    update_length_prefixed_digest(&mut digest, &attributes.indexed_entries);
    for (object, bytes) in &attributes.indexed_objects {
        update_length_prefixed_digest(&mut digest, object);
        update_length_prefixed_digest(&mut digest, bytes);
    }
    for held in &held_paths {
        let bytes = if held.file.metadata()?.file_type().is_file() {
            Some(held.read_bounded(16 * 1024 * 1024)?)
        } else {
            None
        };
        held.update_digest(&mut digest, b"path", bytes.as_deref());
    }
    for (path, bytes) in &attributes.working {
        use std::os::unix::ffi::OsStrExt;
        update_length_prefixed_digest(&mut digest, b"attributes");
        update_length_prefixed_digest(&mut digest, path.as_os_str().as_bytes());
        update_length_prefixed_digest(&mut digest, bytes);
    }
    for held in &held_paths {
        held.verify_path_identity()?;
    }
    let mut mutable_after_child = BTreeSet::new();
    if operation_mutates_repository_authority(request.operation) {
        mutable_after_child.extend(mutable_ref_selectors.iter().map(|selector| {
            match selector.as_str() {
                "HEAD" | "FETCH_HEAD" => git_dir.join(selector),
                reference => common_dir.join(reference),
            }
        }));
        if matches!(request.operation, "add" | "restore" | "checkout" | "commit") {
            mutable_after_child.insert(git_dir.join("index"));
        }
        if matches!(request.operation, "restore" | "checkout") {
            mutable_after_child.extend(attributes.working.iter().map(|(path, _)| path.clone()));
        }
    }
    Ok(GitChildAuthorityBinding {
        kind: "repository",
        operation: request.operation.to_owned(),
        digest: format!("{:x}", digest.finalize()),
        root: top_level,
        ref_selectors,
        mutable_ref_selectors,
        reference_values,
        git_dir,
        common_dir,
        mutable_after_child,
        _held_paths: held_paths,
    })
}

#[cfg(target_os = "linux")]
fn clone_authority_binding(
    destination: &Path,
    request: GitAuthorityRequest<'_>,
    prepare_destination: bool,
) -> Result<GitChildAuthorityBinding> {
    let parent = destination
        .parent()
        .context("managed clone destination has no parent")?;
    let parent = HeldRepositoryPath::open(parent, true)?;
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                bail!("managed clone destination is not a regular directory");
            }
            if prepare_destination
                && fs::read_dir(destination)
                    .context("inspect managed clone destination")?
                    .next()
                    .is_some()
            {
                bail!("managed clone destination must be empty before launch");
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && prepare_destination => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(destination)
                .context("create managed clone destination")?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            bail!("managed clone destination authority is missing")
        }
        Err(error) => return Err(error).context("inspect managed clone destination"),
    }
    parent.verify_path_identity_with_mutable_directory(true)?;
    let held = HeldRepositoryPath::open(destination, true)?;
    let mut digest = Sha256::new();
    update_length_prefixed_digest(&mut digest, b"dev-auth-git-clone-authority-v1");
    update_length_prefixed_digest(&mut digest, request.config_digest.as_bytes());
    update_length_prefixed_digest(&mut digest, request.capability.as_bytes());
    update_length_prefixed_digest(&mut digest, request.operation.as_bytes());
    update_length_prefixed_digest(&mut digest, request.owner.as_bytes());
    update_length_prefixed_digest(&mut digest, request.repository.as_bytes());
    held.update_mutable_directory_digest(&mut digest, b"destination");
    held.verify_path_identity()?;
    Ok(GitChildAuthorityBinding {
        kind: "clone",
        operation: request.operation.to_owned(),
        digest: format!("{:x}", digest.finalize()),
        root: destination.to_path_buf(),
        ref_selectors: Vec::new(),
        mutable_ref_selectors: BTreeSet::new(),
        reference_values: BTreeMap::new(),
        git_dir: PathBuf::new(),
        common_dir: PathBuf::new(),
        mutable_after_child: BTreeSet::new(),
        _held_paths: vec![parent, held],
    })
}

#[cfg(target_os = "linux")]
fn stable_repository_authority_binding(
    program: &str,
    program_guard: &ProgramGuard,
    cwd: &Path,
    request: GitAuthorityRequest<'_>,
) -> Result<GitChildAuthorityBinding> {
    let first = repository_authority_binding(program, program_guard, cwd, request)?;
    let second = repository_authority_binding(program, program_guard, cwd, request)?;
    if first.digest != second.digest || first.root != second.root {
        bail!("managed Git repository authority is not stable before launch");
    }
    Ok(second)
}

#[cfg(target_os = "linux")]
fn stable_clone_authority_binding(
    destination: &Path,
    request: GitAuthorityRequest<'_>,
) -> Result<GitChildAuthorityBinding> {
    let first = clone_authority_binding(destination, request, true)?;
    let second = clone_authority_binding(destination, request, false)?;
    if first.digest != second.digest || first.root != second.root {
        bail!("managed Git clone authority is not stable before launch");
    }
    Ok(second)
}

#[cfg(target_os = "linux")]
fn strict_git_child_environment(name: &str) -> Result<String> {
    match env::var(name) {
        Ok(value) if !value.is_empty() && !value.contains(['\n', '\r', '\0']) => Ok(value),
        Ok(_) => bail!("managed Git child binding is malformed"),
        Err(env::VarError::NotPresent) => bail!("private Git authority requires a managed child"),
        Err(env::VarError::NotUnicode(_)) => bail!("managed Git child binding is not Unicode"),
    }
}

#[cfg(target_os = "linux")]
fn strict_git_child_digest(name: &str) -> Result<String> {
    let digest = strict_git_child_environment(name)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("managed Git child digest is malformed");
    }
    Ok(digest)
}

#[cfg(target_os = "linux")]
struct GitAuthorityRevalidation<'a> {
    expected_capability: &'a str,
    actual_capability: &'a str,
    kind: &'a str,
    operation: &'a str,
    root: &'a Path,
    expected_digest: &'a str,
    config_digest: &'a str,
    ref_selectors: &'a [String],
    mutable_ref_selectors: &'a [String],
    requested_repository: Option<(&'a str, &'a str)>,
}

#[cfg(target_os = "linux")]
fn revalidate_git_child_authority_at(
    config: &Config,
    request: GitAuthorityRevalidation<'_>,
) -> Result<()> {
    if request.actual_capability != request.expected_capability {
        bail!("managed Git child capability does not match the private operation");
    }
    let operation_is_admitted = match request.expected_capability {
        "credential" => matches!(request.operation, "fetch" | "push" | "clone"),
        "signing" => matches!(request.operation, "commit" | "tag"),
        _ => false,
    };
    if !operation_is_admitted {
        bail!("managed Git child operation does not match the private capability");
    }
    if !request.root.is_absolute() {
        bail!("managed Git repository binding root is not absolute");
    }
    let program_guard = program_guard(&config.programs.git, "Git")?;
    let actual = match request.kind {
        "repository" => {
            let repository = match request.requested_repository {
                Some(repository) => (repository.0.to_owned(), repository.1.to_owned()),
                None => literal_origin_repository_at_os(
                    &config.programs.git,
                    &program_guard,
                    request.root,
                    &BTreeMap::new(),
                )?,
            };
            repository_authority_binding(
                &config.programs.git,
                &program_guard,
                request.root,
                GitAuthorityRequest {
                    config_digest: request.config_digest,
                    capability: request.expected_capability,
                    operation: request.operation,
                    owner: &repository.0,
                    repository: &repository.1,
                    ref_selectors: request.ref_selectors,
                    mutable_ref_selectors: request.mutable_ref_selectors,
                },
            )?
        }
        "clone" if request.expected_capability == "credential" => {
            let (owner, repository) = request
                .requested_repository
                .context("clone credential request has no repository")?;
            clone_authority_binding(
                request.root,
                GitAuthorityRequest {
                    config_digest: request.config_digest,
                    capability: request.expected_capability,
                    operation: request.operation,
                    owner,
                    repository,
                    ref_selectors: request.ref_selectors,
                    mutable_ref_selectors: request.mutable_ref_selectors,
                },
                false,
            )?
        }
        _ => bail!("managed Git child authority kind is not admitted"),
    };
    if actual.digest != request.expected_digest
        || actual.root != request.root
        || actual.operation != request.operation
    {
        bail!("managed Git repository authority binding does not match");
    }
    actual.verify_held_paths()
}

#[cfg(target_os = "linux")]
fn revalidate_git_child_authority(
    config: &Config,
    expected_capability: &str,
    requested_repository: Option<(&str, &str)>,
) -> Result<()> {
    if strict_git_child_environment("DEV_AUTH_GIT_CHILD")? != "1" {
        bail!("private Git authority requires a managed child");
    }
    let actual_capability = strict_git_child_environment("DEV_AUTH_GIT_CAPABILITY")?;
    let kind = strict_git_child_environment("DEV_AUTH_GIT_AUTHORITY_KIND")?;
    let operation = strict_git_child_environment("DEV_AUTH_GIT_OPERATION")?;
    let root = PathBuf::from(strict_git_child_environment(
        "DEV_AUTH_GIT_REPOSITORY_ROOT",
    )?);
    let expected_digest = strict_git_child_digest("DEV_AUTH_GIT_AUTHORITY_SHA256")?;
    let config_digest = strict_git_child_digest("DEV_AUTH_GIT_CONFIG_SHA256")?;
    let ref_selectors_text = strict_git_child_environment("DEV_AUTH_GIT_REF_SELECTORS")?;
    let ref_selectors: Vec<String> = serde_json::from_str(&ref_selectors_text)
        .context("managed Git reference authority is malformed")?;
    if ref_selectors.len() > 128
        || ref_selectors
            .iter()
            .any(|value| !valid_bound_ref_selector(value))
        || ref_selectors.windows(2).any(|pair| pair[0] >= pair[1])
    {
        bail!("managed Git reference authority is malformed");
    }
    let mutable_ref_selectors_text =
        strict_git_child_environment("DEV_AUTH_GIT_MUTABLE_REF_SELECTORS")?;
    let mutable_ref_selectors: Vec<String> = serde_json::from_str(&mutable_ref_selectors_text)
        .context("managed Git mutable reference authority is malformed")?;
    if mutable_ref_selectors.len() > 128
        || mutable_ref_selectors
            .iter()
            .any(|value| !valid_bound_ref_selector(value))
        || mutable_ref_selectors
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || mutable_ref_selectors
            .iter()
            .any(|value| !ref_selectors.contains(value))
    {
        bail!("managed Git mutable reference authority is malformed");
    }
    revalidate_git_child_authority_at(
        config,
        GitAuthorityRevalidation {
            expected_capability,
            actual_capability: &actual_capability,
            kind: &kind,
            operation: &operation,
            root: &root,
            expected_digest: &expected_digest,
            config_digest: &config_digest,
            ref_selectors: &ref_selectors,
            mutable_ref_selectors: &mutable_ref_selectors,
            requested_repository,
        },
    )
}

#[cfg(not(target_os = "linux"))]
fn revalidate_git_child_authority(
    _config: &Config,
    _expected_capability: &str,
    _requested_repository: Option<(&str, &str)>,
) -> Result<()> {
    bail!("private managed Git authority is not accepted on this platform")
}

pub(super) fn validate_bound_git_credential_authority(
    config: &Config,
    owner: &str,
    repository: &str,
) -> Result<()> {
    revalidate_git_child_authority(config, "credential", Some((owner, repository)))
}

pub(super) fn validate_bound_git_signing_authority(config: &Config) -> Result<()> {
    revalidate_git_child_authority(config, "signing", None)
}

#[cfg(not(windows))]
fn validate_managed_repository_context(
    program: &str,
    program_guard: &ProgramGuard,
    cwd: &Path,
    roots: &[PathBuf],
    root_index: usize,
    environment: &BTreeMap<OsString, OsString>,
    repository_required: bool,
) -> Result<Option<PathBuf>> {
    let has_repository_hint = repository_marker_exists(cwd)?
        || ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"]
            .iter()
            .any(|key| environment_value(environment, key).is_some());
    if has_repository_hint {
        validate_local_git_configuration(program, program_guard, cwd, environment)?;
    }
    let git_dir = run_git_path_probe(program, program_guard, cwd, environment, "--git-dir")?;
    if git_dir.is_none() {
        if repository_marker_exists(cwd)? || repository_required {
            bail!("managed Git repository location cannot be resolved safely");
        }
        return Ok(None);
    }
    let git_dir = git_dir.context("managed Git directory cannot be resolved safely")?;
    let common_dir =
        run_git_path_probe(program, program_guard, cwd, environment, "--git-common-dir")?
            .context("managed Git common directory cannot be resolved safely")?;
    let top_level =
        run_git_path_probe(program, program_guard, cwd, environment, "--show-toplevel")?
            .context("managed Git worktree cannot be resolved safely")?;
    for path in [&git_dir, &common_dir, &top_level] {
        if workspace_path_relation(path, roots) != WorkspacePathRelation::Inside(root_index) {
            bail!("managed Git repository metadata leaves its declared workspace root");
        }
    }
    if !has_repository_hint {
        validate_local_git_configuration(program, program_guard, cwd, environment)?;
    }
    reject_persistent_alternate_objects_path(&common_dir)?;
    validate_repository_attributes(
        program,
        program_guard,
        cwd,
        &top_level,
        &git_dir,
        &common_dir,
    )?;
    Ok(Some(top_level))
}

#[cfg(windows)]
fn validate_managed_repository_context(
    program: &str,
    program_guard: &ProgramGuard,
    cwd: &Path,
    roots: &WindowsWorkspaceRoots,
    root_index: usize,
    environment: &BTreeMap<OsString, OsString>,
    repository_required: bool,
) -> Result<WindowsPathGuards> {
    let git_dir = run_git_path_probe(program, program_guard, cwd, environment, "--git-dir")?;
    let mut path_guards = WindowsPathGuards::new();
    if git_dir.is_none() {
        let marker_exists = lock_windows_repository_marker_chain(cwd, roots, &mut path_guards)?;
        if marker_exists || repository_required {
            bail!("managed Git repository location cannot be resolved safely");
        }
        return Ok(path_guards);
    }
    let git_dir = git_dir.context("managed Git directory cannot be resolved safely")?;
    let common_dir =
        run_git_path_probe(program, program_guard, cwd, environment, "--git-common-dir")?
            .context("managed Git common directory cannot be resolved safely")?;
    let top_level =
        run_git_path_probe(program, program_guard, cwd, environment, "--show-toplevel")?
            .context("managed Git worktree cannot be resolved safely")?;
    for path in [&git_dir, &common_dir, &top_level] {
        let (relation, guard) = roots.lock_directory_relation(path)?;
        if relation != WorkspacePathRelation::Inside(root_index) {
            bail!("managed Git repository metadata leaves its declared workspace root");
        }
        path_guards.push(guard);
    }
    validate_local_git_configuration(program, program_guard, cwd, environment)?;
    reject_persistent_alternate_objects_path(&common_dir)?;
    validate_repository_attributes(
        program,
        program_guard,
        cwd,
        &top_level,
        &git_dir,
        &common_dir,
    )?;
    Ok(path_guards)
}

fn workspace_status_at(
    config_path: &Path,
    home: &Path,
    current: &Path,
) -> Result<WorkspaceContext> {
    let config = load_config_at(config_path)?;
    let roots = resolved_workspace_roots(&config, home)?;
    classify_existing_directory(current, &roots)
}

fn validate_workspace_policy_at(config: &Config, home: &Path) -> Result<()> {
    let _roots = resolved_workspace_roots(config, home)?;
    Ok(())
}

pub(super) fn validate_workspace_policy(config: &Config) -> Result<()> {
    let home = native_current_user_home()?;
    validate_workspace_policy_at(config, &home)
}

pub fn workspace_status() -> Result<WorkspaceContext> {
    let directories = native_routing_directories()?;
    let current = env::current_dir().context("read current directory")?;
    workspace_status_at(&directories.config, &directories.home, &current)
}
fn literal_origin_repository_at_os(
    program: &str,
    program_guard: &ProgramGuard,
    working_directory: &Path,
    environment: &BTreeMap<OsString, OsString>,
) -> Result<(String, String)> {
    let mut command = guarded_command(program, program_guard)?;
    let output = command
        .args([
            "config",
            "--no-includes",
            "--null",
            "--get-all",
            "remote.origin.url",
        ])
        .current_dir(working_directory)
        .env_clear()
        .envs(git_probe_environment(environment))
        .stdin(Stdio::null())
        .output()
        .context("read managed Git origin")?;
    if !output.status.success()
        || !output.stderr.is_empty()
        || output.stdout.len() as u64 > RESPONSE_LIMIT
    {
        bail!("managed repository has no safely readable literal origin");
    }
    let mut values = output.stdout.split(|byte| *byte == 0);
    let value = values.next().unwrap_or_default();
    if value.is_empty()
        || values
            .next()
            .is_none_or(|terminator| !terminator.is_empty())
        || values.next().is_some()
    {
        bail!("managed repository literal origin is missing or ambiguous");
    }
    let value = std::str::from_utf8(value).context("managed Git origin is not UTF-8")?;
    crate::parse_github_repository(value)
}

fn ensure_git_sandbox_roots(paths: &RuntimePaths) -> Result<()> {
    ensure_runtime(paths)?;
    ensure_private_directory(&paths.git_sandbox_dir())?;
    ensure_private_directory(&paths.git_config_dir())?;
    ensure_private_directory(&paths.git_home_dir())?;
    ensure_private_directory(&paths.git_cache_dir())?;
    ensure_private_directory(&paths.git_data_dir())?;
    ensure_private_directory(&paths.git_temp_dir())?;
    ensure_private_directory(&paths.git_empty_hooks_dir())?;
    ensure_empty_private_file(&paths.git_empty_config_file(), "empty Git configuration")?;
    ensure_empty_private_file(
        &paths.git_empty_attributes_file(),
        "empty Git attributes file",
    )
}

struct GitChildFrontends {
    directory: tempfile::TempDir,
    #[cfg(windows)]
    _guards: Vec<ProgramGuard>,
}

impl GitChildFrontends {
    fn path(&self) -> &Path {
        self.directory.path()
    }
}

fn git_child_frontend_names(capability: crate::GitCapability) -> Vec<&'static str> {
    let mut names = vec![GIT_REJECT_FRONTEND, GIT_PAGER_FRONTEND];
    match capability {
        crate::GitCapability::NoAuthority => {}
        crate::GitCapability::GitHubToken => names.push(GIT_CREDENTIAL_FRONTEND),
        crate::GitCapability::Signing => names.push(GIT_SIGNING_FRONTEND),
    }
    names.sort_unstable();
    names
}

fn git_capability_name(capability: crate::GitCapability) -> &'static str {
    match capability {
        crate::GitCapability::NoAuthority => "none",
        crate::GitCapability::GitHubToken => "credential",
        crate::GitCapability::Signing => "signing",
    }
}

fn require_supported_managed_git_platform() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        bail!("managed Git execution is accepted only on supported Linux")
    }
}

fn fresh_git_child_frontends(
    paths: &RuntimePaths,
    capability: crate::GitCapability,
) -> Result<GitChildFrontends> {
    ensure_git_sandbox_roots(paths)?;
    let directory = tempfile::Builder::new()
        .prefix("frontends-")
        .tempdir_in(paths.git_temp_dir())
        .context("create fresh private Git frontend directory")?;
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .context("restrict fresh private Git frontend directory")?;
    validate_private_directory(directory.path(), "fresh private Git frontend directory")?;
    let executable = env::current_exe().context("resolve running dev-auth executable")?;
    #[cfg(not(windows))]
    let digest = file_sha256(&executable, "running dev-auth executable")?;
    #[cfg(windows)]
    let mut executable_file = windows_security::lock_local_program_for_copy(&executable)
        .context("lock running dev-auth executable")?;
    #[cfg(windows)]
    let digest = file_sha256_file(&mut executable_file, "running dev-auth executable")?;
    #[cfg(windows)]
    let mut guards = Vec::new();
    for frontend in git_child_frontend_names(capability) {
        let destination = directory.path().join(frontend);
        #[cfg(not(windows))]
        install_gh_child_frontend(&executable, &destination, &digest)?;
        #[cfg(windows)]
        let temporary = destination.with_file_name(format!(".{frontend}.tmp"));
        #[cfg(windows)]
        windows_security::copy_open_file_to_private_replacement(&mut executable_file, &temporary)
            .context("copy Git child frontend into a private Windows file")?;
        #[cfg(windows)]
        let _ = private_read(&temporary, "temporary Git child frontend")?;
        #[cfg(windows)]
        if file_sha256(&temporary, "temporary Git child frontend")? != digest {
            bail!("copied Git child frontend does not match the running executable");
        }
        #[cfg(windows)]
        windows_security::atomically_replace_private_file(&temporary, &destination)
            .context("atomically activate private Git child frontend")?;
        #[cfg(windows)]
        {
            let destination_text = destination
                .to_str()
                .context("private Git child frontend path is not Unicode")?;
            guards.push(program_guard(
                destination_text,
                "private Git child frontend",
            )?);
        }
    }
    Ok(GitChildFrontends {
        directory,
        #[cfg(windows)]
        _guards: guards,
    })
}

fn private_git_frontend_name(name: &str) -> &'static str {
    match name {
        "credential" => "dev-auth",
        "ssh-keygen" => "ssh-keygen-dev-auth",
        "pager" => "cat",
        "reject" => "false",
        _ => "false",
    }
}

fn git_config_value(key: &str, value: &str) -> OsString {
    let mut output = OsString::from(key);
    output.push("=");
    output.push(value);
    output
}

fn git_config_path_value(key: &str, value: &Path) -> OsString {
    let mut output = OsString::from(key);
    output.push("=");
    output.push(value);
    output
}

fn managed_git_configuration_arguments(
    paths: &RuntimePaths,
    policy: &crate::GitPolicy,
    capability: crate::GitCapability,
    owner: &str,
    repository: &str,
    signing_public_key: Option<&str>,
    hooks: &Path,
) -> Result<Vec<OsString>> {
    let mut settings = vec![
        git_config_value("credential.helper", ""),
        git_config_value("credential.useHttpPath", "true"),
        git_config_value("credential.interactive", "false"),
        git_config_value("user.name", &policy.author_name),
        git_config_value("user.email", &policy.author_email),
        git_config_value("gpg.format", "ssh"),
        git_config_value("gpg.ssh.program", private_git_frontend_name("reject")),
        git_config_value("user.signingKey", ""),
        git_config_value("commit.gpgSign", "false"),
        git_config_value("tag.gpgSign", "false"),
        git_config_value("tag.forceSignAnnotated", "false"),
        git_config_path_value("core.hooksPath", hooks),
        git_config_path_value("core.attributesFile", &paths.git_empty_attributes_file()),
        git_config_value("core.editor", private_git_frontend_name("reject")),
        git_config_value("core.pager", private_git_frontend_name("pager")),
        git_config_value("core.fsmonitor", "false"),
        git_config_value("core.sshCommand", private_git_frontend_name("reject")),
        git_config_value("core.gitProxy", private_git_frontend_name("reject")),
        git_config_value("sequence.editor", private_git_frontend_name("reject")),
        git_config_value(
            "interactive.diffFilter",
            private_git_frontend_name("reject"),
        ),
        git_config_value("diff.external", private_git_frontend_name("reject")),
        git_config_value("protocol.allow", "never"),
        git_config_value("protocol.https.allow", "always"),
        git_config_value("protocol.http.allow", "never"),
        git_config_value("protocol.ssh.allow", "never"),
        git_config_value("protocol.git.allow", "never"),
        git_config_value("protocol.file.allow", "never"),
        git_config_value("protocol.ext.allow", "never"),
        git_config_value("maintenance.auto", "false"),
        git_config_value("gc.auto", "0"),
        git_config_value("fetch.recurseSubmodules", "false"),
        git_config_value("submodule.recurse", "false"),
        git_config_value("diff.ignoreSubmodules", "all"),
        git_config_value("status.submoduleSummary", "false"),
        git_config_value("checkout.recurseSubmodules", "false"),
        git_config_value("push.recurseSubmodules", "no"),
        git_config_value("http.followRedirects", "initial"),
        git_config_value("http.sslVerify", "true"),
        git_config_value("log.showSignature", "false"),
        git_config_value("url.https://github.com/.insteadOf", "git@github.com:"),
        git_config_value("url.https://github.com/.insteadOf", "ssh://git@github.com/"),
    ];
    match capability {
        crate::GitCapability::NoAuthority => {}
        crate::GitCapability::GitHubToken => {
            settings.push(git_config_value(
                "credential.helper",
                private_git_frontend_name("credential"),
            ));
            settings.push(git_config_value("credential.username", "x-access-token"));
        }
        crate::GitCapability::Signing => {
            let signing_public_key =
                signing_public_key.context("signing capability requires a public key")?;
            settings.push(git_config_value(
                "gpg.ssh.program",
                private_git_frontend_name("ssh-keygen"),
            ));
            settings.push(git_config_value("user.signingKey", signing_public_key));
            settings.push(git_config_value("commit.gpgSign", "true"));
            settings.push(git_config_value("tag.gpgSign", "true"));
            settings.push(git_config_value("tag.forceSignAnnotated", "true"));
        }
    }
    let repository_url = format!("https://github.com/{owner}/{repository}.git");
    settings.push(git_config_value("remote.origin.url", &repository_url));
    settings.push(git_config_value("remote.origin.pushurl", &repository_url));
    for context in [
        "https://github.com".to_owned(),
        format!("https://github.com/{owner}/{repository}"),
        repository_url.clone(),
    ] {
        settings.push(git_config_value(
            &format!("http.{context}.sslVerify"),
            "true",
        ));
        settings.push(git_config_value(&format!("http.{context}.proxy"), ""));
    }
    for context in [
        "https://github.com".to_owned(),
        format!("https://github.com/{owner}/{repository}"),
        repository_url,
    ] {
        let key = format!("credential.{context}.helper");
        settings.push(git_config_value(&key, ""));
        if capability == crate::GitCapability::GitHubToken {
            settings.push(git_config_value(
                &key,
                private_git_frontend_name("credential"),
            ));
        }
    }
    let mut arguments = Vec::with_capacity(settings.len() * 2);
    for setting in settings {
        arguments.push(OsString::from("-c"));
        arguments.push(setting);
    }
    Ok(arguments)
}

fn isolated_git_environment(
    input: &BTreeMap<OsString, OsString>,
    paths: &RuntimePaths,
    child_bin: &Path,
    policy: &crate::GitPolicy,
    capability: crate::GitCapability,
    config_digest: &str,
    authority: Option<&GitChildAuthorityBinding>,
) -> Result<BTreeMap<OsString, OsString>> {
    let mut environment = BTreeMap::new();
    for key in [
        "COLORTERM",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATHEXT",
        "SYSTEMROOT",
        "TERM",
        "WINDIR",
    ] {
        if let Some(value) = environment_value(input, key) {
            environment.insert(OsString::from(key), value.to_os_string());
        }
    }
    for (key, value) in [
        ("HOME", paths.git_home_dir()),
        ("USERPROFILE", paths.git_home_dir()),
        ("XDG_CONFIG_HOME", paths.git_config_dir()),
        ("XDG_CACHE_HOME", paths.git_cache_dir()),
        ("XDG_DATA_HOME", paths.git_data_dir()),
        ("APPDATA", paths.git_config_dir()),
        ("LOCALAPPDATA", paths.git_data_dir()),
        ("TMP", paths.git_temp_dir()),
        ("TEMP", paths.git_temp_dir()),
        ("TMPDIR", paths.git_temp_dir()),
        ("PATH", child_bin.to_path_buf()),
        ("GIT_CONFIG_GLOBAL", paths.git_empty_config_file()),
        ("GIT_CONFIG_SYSTEM", paths.git_empty_config_file()),
    ] {
        environment.insert(OsString::from(key), value.into_os_string());
    }
    for (key, value) in [
        ("DEV_AUTH_GIT_CHILD", "1"),
        ("DEV_AUTH_GIT_CONFIG_SHA256", config_digest),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_ATTR_NOSYSTEM", "1"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_ASKPASS", private_git_frontend_name("reject")),
        ("SSH_ASKPASS", private_git_frontend_name("reject")),
        ("GCM_INTERACTIVE", "Never"),
        ("GIT_EDITOR", private_git_frontend_name("reject")),
        ("GIT_SEQUENCE_EDITOR", private_git_frontend_name("reject")),
        ("GIT_PAGER", private_git_frontend_name("pager")),
        ("PAGER", private_git_frontend_name("pager")),
        ("GIT_EXTERNAL_DIFF", private_git_frontend_name("reject")),
        ("GIT_SSH", private_git_frontend_name("reject")),
        ("GIT_SSH_COMMAND", private_git_frontend_name("reject")),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_NO_LAZY_FETCH", "1"),
        ("GIT_NO_REPLACE_OBJECTS", "1"),
        ("GIT_LFS_SKIP_SMUDGE", "1"),
        ("GIT_AUTHOR_NAME", policy.author_name.as_str()),
        ("GIT_AUTHOR_EMAIL", policy.author_email.as_str()),
        ("GIT_COMMITTER_NAME", policy.author_name.as_str()),
        ("GIT_COMMITTER_EMAIL", policy.author_email.as_str()),
    ] {
        environment.insert(OsString::from(key), OsString::from(value));
    }
    environment.insert(
        OsString::from("DEV_AUTH_GIT_CAPABILITY"),
        OsString::from(git_capability_name(capability)),
    );
    if let Some(authority) = authority {
        environment.insert(
            OsString::from("DEV_AUTH_GIT_AUTHORITY_KIND"),
            OsString::from(authority.kind),
        );
        environment.insert(
            OsString::from("DEV_AUTH_GIT_AUTHORITY_SHA256"),
            OsString::from(&authority.digest),
        );
        environment.insert(
            OsString::from("DEV_AUTH_GIT_OPERATION"),
            OsString::from(&authority.operation),
        );
        environment.insert(
            OsString::from("DEV_AUTH_GIT_REPOSITORY_ROOT"),
            authority.root.as_os_str().to_os_string(),
        );
        #[cfg(target_os = "linux")]
        let ref_selectors = serde_json::to_string(&authority.ref_selectors)
            .context("serialize managed Git reference authority")?;
        #[cfg(target_os = "linux")]
        environment.insert(
            OsString::from("DEV_AUTH_GIT_REF_SELECTORS"),
            OsString::from(ref_selectors),
        );
        #[cfg(target_os = "linux")]
        let mutable_ref_selectors = serde_json::to_string(
            &authority
                .mutable_ref_selectors
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
        )
        .context("serialize managed Git mutable reference authority")?;
        #[cfg(target_os = "linux")]
        environment.insert(
            OsString::from("DEV_AUTH_GIT_MUTABLE_REF_SELECTORS"),
            OsString::from(mutable_ref_selectors),
        );
    }
    Ok(environment)
}

fn fresh_git_hooks_directory(paths: &RuntimePaths) -> Result<tempfile::TempDir> {
    let directory = tempfile::Builder::new()
        .prefix("hooks-")
        .tempdir_in(paths.git_temp_dir())
        .context("create fresh private Git hooks directory")?;
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .context("restrict fresh private Git hooks directory")?;
    validate_private_directory(directory.path(), "fresh private Git hooks directory")?;
    if fs::read_dir(directory.path())
        .context("inspect fresh private Git hooks directory")?
        .next()
        .is_some()
    {
        bail!("fresh private Git hooks directory is not empty");
    }
    Ok(directory)
}

fn declared_signing_public_key(
    paths: &RuntimePaths,
    config: &Config,
    profile_name: &str,
) -> Result<String> {
    let profile = config
        .ssh_profiles
        .get(profile_name)
        .context("Git SSH signing profile is not declared")?;
    let expected: BTreeSet<String> = profile
        .keys
        .iter()
        .map(|key| key.fingerprint.clone())
        .collect();
    let loaded = loaded_ssh_public_keys(paths, config)?;
    if loaded.keys().cloned().collect::<BTreeSet<_>>() != expected {
        bail!("dedicated SSH agent public keys do not match the Git signing profile");
    }
    let signing = profile
        .keys
        .iter()
        .find(|key| key.purpose == SshKeyPurpose::Signing)
        .context("Git SSH signing profile has no signing key")?;
    loaded
        .get(&signing.fingerprint)
        .cloned()
        .context("declared Git SSH signing key is not loaded")
}

fn managed_clone_destination(arguments: &[OsString], cwd: &Path) -> Result<PathBuf> {
    let targets = command_routing_targets("clone", &arguments[1..], cwd)?;
    targets
        .destination
        .context("managed Git clone destination is missing")
}

fn normalized_managed_git_arguments(
    arguments: &[String],
    owner: &str,
    repository: &str,
) -> Result<Vec<OsString>> {
    let repository_url = format!("https://github.com/{owner}/{repository}.git");
    let mut normalized = arguments.to_vec();
    match normalized.first().map(String::as_str) {
        Some("fetch" | "push") => {
            let remote = normalized
                .iter_mut()
                .skip(1)
                .find(|argument| !argument.starts_with('-'))
                .context("managed Git network command has no literal origin")?;
            if remote != "origin" {
                bail!("managed Git network command does not target literal origin");
            }
            *remote = repository_url;
            if normalized.first().is_some_and(|value| value == "fetch") {
                normalized.splice(
                    1..1,
                    ["--atomic", "--no-tags", "--no-write-fetch-head"]
                        .into_iter()
                        .map(str::to_owned),
                );
            }
        }
        Some("clone") => {
            let mut index = 1_usize;
            let mut source_replaced = false;
            while index < normalized.len() {
                match normalized[index].as_str() {
                    "-b" | "--branch" | "--depth" => index += 2,
                    value if value.starts_with('-') => index += 1,
                    _ if !source_replaced => {
                        normalized[index] = repository_url.clone();
                        source_replaced = true;
                        index += 1;
                    }
                    _ => index += 1,
                }
            }
            if !source_replaced {
                bail!("managed Git clone source is missing");
            }
        }
        _ => {}
    }
    Ok(normalized.into_iter().map(OsString::from).collect())
}

#[cfg(not(windows))]
fn validate_managed_clone_postcondition(
    program: &str,
    program_guard: &ProgramGuard,
    arguments: &[OsString],
    cwd: &Path,
    roots: &[PathBuf],
    root_index: usize,
    environment: &BTreeMap<OsString, OsString>,
) -> Result<()> {
    let destination = managed_clone_destination(arguments, cwd)?;
    validate_managed_repository_context(
        program,
        program_guard,
        &destination,
        roots,
        root_index,
        environment,
        true,
    )?;
    Ok(())
}

#[cfg(windows)]
fn validate_managed_clone_postcondition(
    program: &str,
    program_guard: &ProgramGuard,
    arguments: &[OsString],
    cwd: &Path,
    roots: &WindowsWorkspaceRoots,
    root_index: usize,
    environment: &BTreeMap<OsString, OsString>,
) -> Result<WindowsPathGuards> {
    let destination = managed_clone_destination(arguments, cwd)?;
    validate_managed_repository_context(
        program,
        program_guard,
        &destination,
        roots,
        root_index,
        environment,
        true,
    )
}

fn run_git_at_with_signing_key<F>(
    directories: &NativeUserDirs,
    cwd: &Path,
    environment: &BTreeMap<OsString, OsString>,
    arguments: &[OsString],
    signing_key_provider: F,
) -> Result<ExitStatus>
where
    F: FnOnce(&RuntimePaths, &Config, &str) -> Result<String>,
{
    let paths = RuntimePaths::from_native(directories);
    let (config, config_digest) = load_config_snapshot_at(&paths.config)?;
    let roots = resolved_workspace_roots(&config, &directories.home)?;
    let program_guard = program_guard(&config.programs.git, "Git")?;
    #[cfg(windows)]
    let routing_decision = classify_git_invocation_at(arguments, cwd, &roots, environment)?;
    #[cfg(windows)]
    let route = routing_decision.route();
    #[cfg(not(windows))]
    let route = classify_git_invocation_at(arguments, cwd, &roots, environment)?;
    let root_index = match route {
        GitInvocationRoute::Unmanaged => {
            #[cfg(windows)]
            let _repository_path_guards = validate_unmanaged_repository_context(
                &config.programs.git,
                &program_guard,
                cwd,
                &roots,
                environment,
            )?;
            #[cfg(not(windows))]
            validate_unmanaged_repository_context(
                &config.programs.git,
                &program_guard,
                cwd,
                &roots,
                environment,
            )?;
            let mut command = guarded_command(&config.programs.git, &program_guard)?;
            let status = command
                .args(arguments)
                .current_dir(cwd)
                .env_clear()
                .envs(environment)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .context("run configured Git in a proven unmanaged context")?;
            return Ok(status);
        }
        GitInvocationRoute::Managed(root_index) => root_index,
    };
    require_supported_managed_git_platform()?;
    validate_git_version(&config.programs.git, &program_guard)?;
    let unicode_arguments: Vec<String> = arguments
        .iter()
        .map(|argument| {
            argument
                .clone()
                .into_string()
                .map_err(|_| anyhow::anyhow!("managed Git arguments must be Unicode"))
        })
        .collect::<Result<_>>()?;
    let capability = crate::git_capability(&unicode_arguments)?;
    #[cfg(target_os = "linux")]
    let ref_selectors = git_ref_authority_selectors(&unicode_arguments)?;
    #[cfg(target_os = "linux")]
    let mutable_ref_selectors = git_mutable_ref_selectors(&unicode_arguments)?;
    let command_name = unicode_arguments
        .first()
        .context("managed Git command is missing")?;
    #[cfg(windows)]
    let _repository_path_guards = validate_managed_repository_context(
        &config.programs.git,
        &program_guard,
        cwd,
        &roots,
        root_index,
        environment,
        command_name != "clone",
    )?;
    let repository = match crate::managed_clone_repository(&unicode_arguments)? {
        Some(repository) => repository,
        None => {
            literal_origin_repository_at_os(&config.programs.git, &program_guard, cwd, environment)?
        }
    };
    #[cfg(not(windows))]
    validate_managed_repository_context(
        &config.programs.git,
        &program_guard,
        cwd,
        &roots,
        root_index,
        environment,
        command_name != "clone",
    )?;
    if !config.github.discover_installations {
        config
            .github
            .select_repository(&repository.0, &repository.1)?;
    }
    let policy = config
        .git
        .as_ref()
        .context("Git workspace policy is not declared")?;
    #[cfg(target_os = "linux")]
    let authority = match capability {
        crate::GitCapability::NoAuthority => Some(stable_repository_authority_binding(
            &config.programs.git,
            &program_guard,
            cwd,
            GitAuthorityRequest {
                config_digest: &config_digest,
                capability: git_capability_name(capability),
                operation: command_name,
                owner: &repository.0,
                repository: &repository.1,
                ref_selectors: &ref_selectors,
                mutable_ref_selectors: &mutable_ref_selectors,
            },
        )?),
        crate::GitCapability::GitHubToken if command_name == "clone" => {
            let destination = managed_clone_destination(arguments, cwd)?;
            Some(stable_clone_authority_binding(
                &destination,
                GitAuthorityRequest {
                    config_digest: &config_digest,
                    capability: git_capability_name(capability),
                    operation: command_name,
                    owner: &repository.0,
                    repository: &repository.1,
                    ref_selectors: &ref_selectors,
                    mutable_ref_selectors: &mutable_ref_selectors,
                },
            )?)
        }
        crate::GitCapability::GitHubToken | crate::GitCapability::Signing => {
            Some(stable_repository_authority_binding(
                &config.programs.git,
                &program_guard,
                cwd,
                GitAuthorityRequest {
                    config_digest: &config_digest,
                    capability: git_capability_name(capability),
                    operation: command_name,
                    owner: &repository.0,
                    repository: &repository.1,
                    ref_selectors: &ref_selectors,
                    mutable_ref_selectors: &mutable_ref_selectors,
                },
            )?)
        }
    };
    #[cfg(not(target_os = "linux"))]
    let authority: Option<GitChildAuthorityBinding> = match capability {
        crate::GitCapability::NoAuthority => None,
        crate::GitCapability::GitHubToken | crate::GitCapability::Signing => {
            bail!("private managed Git authority is not accepted on this platform")
        }
    };
    let frontends = fresh_git_child_frontends(&paths, capability)?;
    let signing_public_key = if capability == crate::GitCapability::Signing {
        Some(signing_key_provider(&paths, &config, &policy.ssh_profile)?)
    } else {
        None
    };
    let hooks = fresh_git_hooks_directory(&paths)?;
    let child_environment = isolated_git_environment(
        environment,
        &paths,
        frontends.path(),
        policy,
        capability,
        &config_digest,
        authority.as_ref(),
    )?;
    let mut child_arguments = managed_git_configuration_arguments(
        &paths,
        policy,
        capability,
        &repository.0,
        &repository.1,
        signing_public_key.as_deref(),
        hooks.path(),
    )?;
    child_arguments.extend(normalized_managed_git_arguments(
        &unicode_arguments,
        &repository.0,
        &repository.1,
    )?);
    let mut git_child = guarded_command(&config.programs.git, &program_guard)?;
    let status = git_child
        .args(&child_arguments)
        .current_dir(cwd)
        .env_clear()
        .envs(child_environment)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("run bounded managed-workspace Git command")?;
    #[cfg(target_os = "linux")]
    if let Some(expected) = &authority {
        expected.verify_after_child()?;
        verify_reference_authority_transition(
            expected,
            status.success(),
            unicode_arguments
                .iter()
                .any(|argument| argument == "--dry-run"),
        )?;
        if expected.kind == "repository" && !operation_mutates_repository_authority(command_name) {
            let actual = repository_authority_binding(
                &config.programs.git,
                &program_guard,
                &expected.root,
                GitAuthorityRequest {
                    config_digest: &config_digest,
                    capability: git_capability_name(capability),
                    operation: command_name,
                    owner: &repository.0,
                    repository: &repository.1,
                    ref_selectors: &ref_selectors,
                    mutable_ref_selectors: &mutable_ref_selectors,
                },
            )?;
            if actual.digest != expected.digest
                || actual.root != expected.root
                || actual.operation != expected.operation
            {
                bail!("managed Git repository authority changed during execution");
            }
        }
    }
    if status.success() && command_name == "clone" {
        #[cfg(windows)]
        let _post_clone_path_guards = validate_managed_clone_postcondition(
            &config.programs.git,
            &program_guard,
            arguments,
            cwd,
            &roots,
            root_index,
            environment,
        )?;
        #[cfg(not(windows))]
        validate_managed_clone_postcondition(
            &config.programs.git,
            &program_guard,
            arguments,
            cwd,
            &roots,
            root_index,
            environment,
        )?;
    }
    Ok(status)
}

fn run_git_at(
    directories: &NativeUserDirs,
    cwd: &Path,
    environment: &BTreeMap<OsString, OsString>,
    arguments: &[OsString],
) -> Result<ExitStatus> {
    run_git_at_with_signing_key(
        directories,
        cwd,
        environment,
        arguments,
        declared_signing_public_key,
    )
}

pub fn run_git(arguments: &[OsString]) -> Result<ExitStatus> {
    let directories = native_routing_directories()?;
    let cwd = env::current_dir().context("read Git invocation directory")?;
    let environment: BTreeMap<OsString, OsString> = env::vars_os().collect();
    run_git_at(&directories, &cwd, &environment, arguments)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use crate::GitHubProfile;
    #[cfg(unix)]
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(windows)]
    fn config_with_profiles(profiles: BTreeMap<String, SshProfile>) -> Config {
        Config {
            version: 1,
            credential_store: CredentialStore::default(),
            programs: crate::Programs {
                op: "/usr/bin/op".into(),
                gh: "/usr/bin/gh".into(),
                git: "/usr/bin/git".into(),
                ssh_add: "/usr/bin/ssh-add".into(),
                ssh_keygen: "/usr/bin/ssh-keygen".into(),
            },
            git: None,
            github: GitHubProfile {
                app_id: 1,
                private_key_ref: "op://Machine Vault/app/private-key".into(),
                repository_selection: crate::RepositorySelection::All,
                discover_installations: false,
                installations: Vec::new(),
                permissions: BTreeMap::new(),
            },
            profiles: BTreeMap::new(),
            ssh_profiles: profiles,
        }
    }

    #[cfg(unix)]
    fn write_workspace_config(config_path: &Path, workspace_root: &Path) {
        let parent = config_path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        let config = format!(
            r#"version = 1
[programs]
op = "/usr/bin/false"
gh = "/usr/bin/false"
git = "/usr/bin/git"
ssh_add = "/usr/bin/false"
ssh_keygen = "/usr/bin/false"
[git]
workspace_roots = ["{}"]
author_name = "Automation Worker"
author_email = "automation@example.invalid"
ssh_profile = "automation"
[github]
app_id = 42
private_key_ref = "op://Automation/app/private-key"
repository_selection = "all"
discover_installations = true
permissions = {{ actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }}
[[ssh_profiles.automation.keys]]
purpose = "authentication"
private_key_ref = "op://Automation/authentication/private-key"
fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[ssh_profiles.automation.keys]]
purpose = "signing"
private_key_ref = "op://Automation/signing/private-key"
fingerprint = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
"#,
            workspace_root.display()
        );
        fs::write(config_path, config).unwrap();
        fs::set_permissions(config_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(unix)]
    fn write_workspace_config_with_git(
        config_path: &Path,
        workspace_root: &Path,
        git_program: &Path,
    ) {
        write_workspace_config(config_path, workspace_root);
        let config = fs::read_to_string(config_path).unwrap().replace(
            "git = \"/usr/bin/git\"",
            &format!("git = \"{}\"", git_program.display()),
        );
        fs::write(config_path, config).unwrap();
        fs::set_permissions(config_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(unix)]
    fn test_git_guard() -> ProgramGuard {
        program_guard("/usr/bin/git", "test Git").unwrap()
    }

    #[cfg(windows)]
    fn alternate_windows_drive_case(path: &Path) -> PathBuf {
        let text = path.to_string_lossy();
        let mut characters = text.chars();
        let drive = characters
            .next()
            .expect("Windows test path must contain a drive letter");
        assert_eq!(characters.next(), Some(':'));
        let alternate = if drive.is_ascii_lowercase() {
            drive.to_ascii_uppercase()
        } else {
            drive.to_ascii_lowercase()
        };
        PathBuf::from(format!("{alternate}:{}", characters.as_str()))
    }

    #[cfg(windows)]
    fn create_windows_test_directory_symlink(target: &Path, link: &Path) -> bool {
        match std::os::windows::fs::symlink_dir(target, link) {
            Ok(()) => true,
            Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied
                    || error.raw_os_error()
                        == Some(
                            windows_sys::Win32::Foundation::ERROR_PRIVILEGE_NOT_HELD as i32,
                        ) =>
            {
                eprintln!("skipping Windows reparse test because link creation failed: {error}");
                false
            }
            Err(error) => panic!("create Windows test directory link: {error}"),
        }
    }

    #[cfg(windows)]
    fn windows_test_workspace_roots(managed: &Path, home: &Path) -> WindowsWorkspaceRoots {
        let mut config = config_with_profiles(BTreeMap::new());
        config.git = Some(crate::GitPolicy {
            workspace_roots: vec![managed.to_string_lossy().into_owned()],
            author_name: "Automation Worker".into(),
            author_email: "automation@example.invalid".into(),
            ssh_profile: "automation".into(),
        });
        resolved_workspace_roots(&config, home).unwrap()
    }

    #[cfg(windows)]
    #[test]
    fn windows_repository_marker_chain_retains_every_candidate_and_finds_ancestor_markers() {
        let temporary = tempfile::tempdir().unwrap();
        let managed = temporary.path().join("managed");
        let file_repository = managed.join("file-repository");
        let file_cwd = file_repository.join("nested/working");
        let directory_repository = managed.join("directory-repository");
        let directory_cwd = directory_repository.join("nested/working");
        let empty_cwd = managed.join("empty/nested/working");
        fs::create_dir_all(&file_cwd).unwrap();
        fs::create_dir_all(&directory_cwd).unwrap();
        fs::create_dir_all(&empty_cwd).unwrap();
        fs::write(file_repository.join(".git"), b"gitdir: metadata\n").unwrap();
        fs::create_dir(directory_repository.join(".git")).unwrap();
        let roots = windows_test_workspace_roots(&managed, temporary.path());

        for cwd in [&file_cwd, &directory_cwd] {
            let mut guards = WindowsPathGuards::new();
            assert!(lock_windows_repository_marker_chain(cwd, &roots, &mut guards).unwrap());
            assert_eq!(guards._guards.len(), cwd.ancestors().count());
        }

        let mut guards = WindowsPathGuards::new();
        assert!(!lock_windows_repository_marker_chain(&empty_cwd, &roots, &mut guards).unwrap());
        assert_eq!(guards._guards.len(), empty_cwd.ancestors().count());
    }

    #[cfg(windows)]
    #[test]
    fn windows_repository_marker_chain_rejects_a_reparse_ancestor() {
        let temporary = tempfile::tempdir().unwrap();
        let managed = temporary.path().join("managed");
        let target = managed.join("target");
        let linked = managed.join("linked");
        fs::create_dir_all(target.join("working")).unwrap();
        let roots = windows_test_workspace_roots(&managed, temporary.path());
        if !create_windows_test_directory_symlink(&target, &linked) {
            return;
        }

        let mut guards = WindowsPathGuards::new();
        assert!(
            lock_windows_repository_marker_chain(&linked.join("working"), &roots, &mut guards,)
                .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_workspace_routing_uses_held_identity_instead_of_path_spelling() {
        let temporary = tempfile::tempdir().unwrap();
        let managed = temporary.path().join("managed");
        let repository = managed.join("repository");
        let unmanaged = temporary.path().join("unmanaged");
        fs::create_dir_all(&repository).unwrap();
        fs::create_dir(&unmanaged).unwrap();

        let mut config = config_with_profiles(BTreeMap::new());
        config.git = Some(crate::GitPolicy {
            workspace_roots: vec![managed.to_string_lossy().into_owned()],
            author_name: "Automation Worker".into(),
            author_email: "automation@example.invalid".into(),
            ssh_profile: "automation".into(),
        });
        let roots = resolved_workspace_roots(&config, temporary.path()).unwrap();
        let aliased_repository = alternate_windows_drive_case(&repository);
        let environment = BTreeMap::new();

        assert_eq!(
            classify_existing_directory(&aliased_repository, &roots).unwrap(),
            WorkspaceContext::Managed
        );
        assert_eq!(
            classify_git_invocation_at(
                &["status".into()],
                &aliased_repository,
                &roots,
                &environment,
            )
            .unwrap()
            .route(),
            GitInvocationRoute::Managed(0)
        );
        assert!(classify_git_invocation_at(
            &[
                "-C".into(),
                aliased_repository.into_os_string(),
                "status".into(),
            ],
            &unmanaged,
            &roots,
            &environment,
        )
        .is_err());
        assert!(classify_git_invocation_at(
            &[
                format!("--exec-path={}", managed.display()).into(),
                "status".into(),
            ],
            &unmanaged,
            &roots,
            &environment,
        )
        .is_err());
        assert_eq!(
            classify_git_invocation_at(
                &[
                    format!("--exec-path={}", unmanaged.display()).into(),
                    "status".into(),
                ],
                &unmanaged,
                &roots,
                &environment,
            )
            .unwrap()
            .route(),
            GitInvocationRoute::Unmanaged,
        );
    }

    #[cfg(unix)]
    #[test]
    fn workspace_status_uses_only_injected_public_authorities_and_rejects_linked_roots() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let managed = home.join("managed");
        let unmanaged = home.join("unmanaged");
        let config_path = home.join(".config/dev-auth/config.toml");
        fs::create_dir_all(&managed).unwrap();
        fs::create_dir(&unmanaged).unwrap();
        write_workspace_config(&config_path, &managed);

        assert_eq!(
            workspace_status_at(&config_path, &home, &managed).unwrap(),
            WorkspaceContext::Managed
        );
        assert_eq!(
            workspace_status_at(&config_path, &home, &unmanaged).unwrap(),
            WorkspaceContext::Unmanaged
        );

        let linked = home.join("linked");
        std::os::unix::fs::symlink(&managed, &linked).unwrap();
        write_workspace_config(&config_path, &linked);
        assert!(workspace_status_at(&config_path, &home, &managed).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn git_route_classification_allows_only_proven_unmanaged_fallback() {
        let root = tempfile::tempdir().unwrap();
        let managed = root.path().join("managed");
        let managed_repository = managed.join("repository");
        let unmanaged = root.path().join("unmanaged");
        let unmanaged_repository = unmanaged.join("repository");
        fs::create_dir_all(&managed_repository).unwrap();
        fs::create_dir_all(&unmanaged_repository).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&managed_repository)
            .status()
            .unwrap()
            .success());
        let roots = vec![fs::canonicalize(&managed).unwrap()];
        let empty_environment = BTreeMap::new();

        assert_eq!(
            classify_git_invocation_at(
                &["status".into()],
                &managed_repository,
                &roots,
                &empty_environment,
            )
            .unwrap(),
            GitInvocationRoute::Managed(0)
        );
        assert_eq!(
            classify_git_invocation_at(
                &["status".into()],
                &unmanaged_repository,
                &roots,
                &empty_environment,
            )
            .unwrap(),
            GitInvocationRoute::Unmanaged
        );
        assert_eq!(
            classify_git_invocation_at(
                &[
                    "-C".into(),
                    unmanaged_repository.clone().into_os_string(),
                    "status".into()
                ],
                &unmanaged,
                &roots,
                &empty_environment,
            )
            .unwrap(),
            GitInvocationRoute::Unmanaged
        );
        assert!(classify_git_invocation_at(
            &[
                "-C".into(),
                managed_repository.clone().into_os_string(),
                "status".into()
            ],
            &unmanaged,
            &roots,
            &empty_environment,
        )
        .is_err());

        let outside_gitfile = root.path().join("outside-gitfile");
        fs::create_dir(&outside_gitfile).unwrap();
        fs::write(
            outside_gitfile.join(".git"),
            format!("gitdir: {}\n", managed_repository.join(".git").display()),
        )
        .unwrap();
        assert!(validate_unmanaged_repository_context(
            "/usr/bin/git",
            &test_git_guard(),
            &outside_gitfile,
            &roots,
            &empty_environment,
        )
        .is_err());
        assert!(classify_git_invocation_at(
            &[
                "-C".into(),
                unmanaged_repository.clone().into_os_string(),
                "status".into()
            ],
            &managed_repository,
            &roots,
            &empty_environment,
        )
        .is_err());

        assert_eq!(
            classify_git_invocation_at(
                &["init".into(), "new-repository".into()],
                &unmanaged,
                &roots,
                &empty_environment,
            )
            .unwrap(),
            GitInvocationRoute::Unmanaged
        );
        fs::create_dir(unmanaged.join("new-repository")).unwrap();
        assert_eq!(
            classify_git_invocation_at(
                &["init".into(), "new-repository".into()],
                &unmanaged,
                &roots,
                &empty_environment,
            )
            .unwrap(),
            GitInvocationRoute::Unmanaged
        );
        fs::create_dir(managed.join("new-repository")).unwrap();
        assert!(classify_git_invocation_at(
            &[
                "init".into(),
                managed.join("new-repository").into_os_string()
            ],
            &unmanaged,
            &roots,
            &empty_environment,
        )
        .is_err());
        assert!(classify_git_invocation_at(
            &["init".into(), "new-repository".into()],
            &managed,
            &roots,
            &empty_environment,
        )
        .is_err());
        assert!(classify_git_invocation_at(
            &[
                "init".into(),
                "--shared".into(),
                root.path().as_os_str().to_os_string(),
            ],
            &unmanaged,
            &roots,
            &empty_environment,
        )
        .is_err());

        fs::create_dir(managed.join("clone")).unwrap();
        fs::create_dir(unmanaged.join("clone")).unwrap();
        assert_eq!(
            classify_git_invocation_at(
                &[
                    "clone".into(),
                    "https://github.com/ExampleOrg/repository.git".into(),
                    "clone".into(),
                ],
                &managed,
                &roots,
                &empty_environment,
            )
            .unwrap(),
            GitInvocationRoute::Managed(0)
        );
        assert_eq!(
            classify_git_invocation_at(
                &[
                    "clone".into(),
                    "https://example.invalid/repository.git".into(),
                    "clone".into(),
                ],
                &unmanaged,
                &roots,
                &empty_environment,
            )
            .unwrap(),
            GitInvocationRoute::Unmanaged
        );
        assert!(classify_git_invocation_at(
            &[
                "clone".into(),
                "https://example.invalid/repository.git".into(),
                managed.join("clone").into_os_string(),
            ],
            &unmanaged,
            &roots,
            &empty_environment,
        )
        .is_err());
        assert!(classify_git_invocation_at(
            &[
                "clone".into(),
                "https://example.invalid/repository.git".into(),
                "--reference".into(),
                managed_repository.clone().into_os_string(),
                "clone".into(),
            ],
            &unmanaged,
            &roots,
            &empty_environment,
        )
        .is_err());
        assert!(classify_git_invocation_at(
            &[
                "clone".into(),
                "file:///tmp/repository.git".into(),
                "clone".into(),
            ],
            &unmanaged,
            &roots,
            &empty_environment,
        )
        .is_err());
        assert!(classify_git_invocation_at(
            &["-c".into(), "core.worktree=/tmp".into(), "status".into(),],
            &unmanaged,
            &roots,
            &empty_environment,
        )
        .is_err());

        for variable in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_INDEX_FILE",
            "GIT_SHALLOW_FILE",
        ] {
            let managed_environment = BTreeMap::from([(
                OsString::from(variable),
                managed_repository.clone().into_os_string(),
            )]);
            assert!(classify_git_invocation_at(
                &["status".into()],
                &unmanaged_repository,
                &roots,
                &managed_environment,
            )
            .is_err());
        }
        let relative_environment = BTreeMap::from([(
            OsString::from("GIT_DIR"),
            OsString::from("../../managed/repository/.git"),
        )]);
        assert!(classify_git_invocation_at(
            &[
                "-C".into(),
                unmanaged_repository.clone().into_os_string(),
                "status".into(),
            ],
            &unmanaged,
            &roots,
            &relative_environment,
        )
        .is_err());

        for (variable, value) in [
            ("GIT_CONFIG", managed.join("git-config")),
            ("GIT_CONFIG_GLOBAL", managed.join("global-config")),
            ("GIT_CONFIG_SYSTEM", managed.join("system-config")),
            ("GIT_EXEC_PATH", managed.join("git-exec")),
            ("GIT_TEMPLATE_DIR", managed.join("templates")),
            ("GIT_ASKPASS", managed.join("askpass")),
            ("SSH_ASKPASS", managed.join("ssh-askpass")),
            ("GIT_SSH", managed.join("ssh")),
            ("GIT_TRACE", managed.join("trace")),
        ] {
            let poisoned = BTreeMap::from([(OsString::from(variable), value.into_os_string())]);
            assert!(
                classify_git_invocation_at(
                    &["status".into()],
                    &unmanaged_repository,
                    &roots,
                    &poisoned,
                )
                .is_err(),
                "accepted managed {variable} target"
            );
        }

        for (variable, value) in [
            ("HOME", managed.clone()),
            ("XDG_CONFIG_HOME", managed.clone()),
            ("PATH", managed.clone()),
        ] {
            let poisoned = BTreeMap::from([(OsString::from(variable), value.into_os_string())]);
            assert!(
                classify_git_invocation_at(
                    &["status".into()],
                    &unmanaged_repository,
                    &roots,
                    &poisoned,
                )
                .is_err(),
                "accepted managed {variable} authority"
            );
        }

        for variable in [
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_PARAMETERS",
            "GIT_SSH_COMMAND",
        ] {
            let poisoned = BTreeMap::from([(
                OsString::from(variable),
                OsString::from("ambiguous injected authority"),
            )]);
            assert!(
                classify_git_invocation_at(
                    &["status".into()],
                    &unmanaged_repository,
                    &roots,
                    &poisoned,
                )
                .is_err(),
                "accepted ambiguous {variable}"
            );
        }

        let safe_human_environment = BTreeMap::from([
            (
                OsString::from("HOME"),
                root.path().join("human-home").into_os_string(),
            ),
            (
                OsString::from("XDG_CONFIG_HOME"),
                root.path().join("human-config").into_os_string(),
            ),
            (OsString::from("PATH"), OsString::from("/usr/bin")),
            (OsString::from("GIT_PAGER"), OsString::from("cat")),
            (OsString::from("PAGER"), OsString::from("cat")),
        ]);
        assert_eq!(
            classify_git_invocation_at(
                &["status".into()],
                &unmanaged_repository,
                &roots,
                &safe_human_environment,
            )
            .unwrap(),
            GitInvocationRoute::Unmanaged,
        );
    }

    #[test]
    fn managed_repository_policy_rejects_local_program_and_attribute_drivers() {
        for key in [
            "alias.escape",
            "author.name",
            "browser.firefox.path",
            "commit.gpgsign",
            "commit.template",
            "credential.helper",
            "credential.https://github.com.helper",
            "core.alternaterefscommand",
            "core.askpass",
            "filter.lfs.process",
            "filter.custom.clean",
            "filter.custom.smudge",
            "diff.custom.command",
            "diff.custom.textconv",
            "diff.orderfile",
            "difftool.custom.cmd",
            "fetch.fsck.skiplist",
            "format.signaturefile",
            "fsck.skiplist",
            "gc.recentobjectshook",
            "guitool.custom.cmd",
            "help.htmlpath",
            "hook.run.command",
            "init.templatedir",
            "instaweb.httpd",
            "mailmap.file",
            "man.viewer",
            "merge.custom.driver",
            "merge.guitool",
            "merge.tool",
            "pull.octopus",
            "pull.twohead",
            "push.gpgsign",
            "sendemail.smtpserver",
            "tag.forcesignannotated",
            "tag.gpgsign",
            "trailer.ifexists",
            "uploadpack.allowfilter",
            "uploadpackfilter.tree.maxdepth",
            "user.email",
            "user.name",
            "user.signingkey",
            "core.fsmonitor",
            "core.hookspath",
            "core.sshcommand",
            "core.gitproxy",
            "core.editor",
            "core.pager",
            "sequence.editor",
            "gpg.ssh.program",
            "include.path",
            "includeif.gitdir:~/repos/.path",
            "protocol.ext.allow",
            "remote.origin.uploadpack",
            "remote.origin.receivepack",
            "remote.origin.proxy",
            "submodule.child.update",
            "url.ssh://git@github.com/.insteadof",
            "http.https://github.com/.extraheader",
        ] {
            assert!(
                validate_local_git_config_key(key).is_err(),
                "accepted {key}"
            );
        }
        for key in [
            "core.repositoryformatversion",
            "core.filemode",
            "core.bare",
            "core.logallrefupdates",
            "remote.origin.url",
            "remote.origin.fetch",
            "branch.main.remote",
            "branch.main.merge",
        ] {
            validate_local_git_config_key(key).unwrap_or_else(|error| {
                panic!("rejected benign {key}: {error:#}");
            });
        }

        #[cfg(target_os = "linux")]
        {
            for line in [
                "* filter=lfs",
                "*.bin -filter",
                "*.rs diff=rust",
                "*.lock merge=ours",
                "[attr]binary -diff -merge -text",
            ] {
                assert!(
                    validate_git_attributes(line.as_bytes()).is_err(),
                    "accepted {line}"
                );
            }
            validate_git_attributes(b"* text=auto eol=lf\n*.zip binary export-ignore\n").unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn declared_workspace_root_rejects_group_or_world_writable_authority() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let config_path = root.path().join("config.toml");
        write_workspace_config(&config_path, &workspace);
        let config = parse_config(&fs::read(&config_path).unwrap()).unwrap();
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(resolved_workspace_roots(&config, root.path()).is_err());

        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).unwrap();
        resolved_workspace_roots(&config, root.path()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn offline_workspace_policy_validation_matches_runtime_root_contract() {
        let root = tempfile::tempdir().unwrap();
        let valid = root.path().join("valid");
        let missing = root.path().join("missing");
        let linked = root.path().join("linked");
        fs::create_dir(&valid).unwrap();
        fs::set_permissions(&valid, fs::Permissions::from_mode(0o700)).unwrap();
        let config_path = root.path().join("config.toml");
        write_workspace_config(&config_path, &valid);
        let mut config = parse_config(&fs::read(&config_path).unwrap()).unwrap();
        validate_workspace_policy_at(&config, root.path()).unwrap();

        config.git.as_mut().unwrap().workspace_roots = vec![missing.display().to_string()];
        assert!(validate_workspace_policy_at(&config, root.path()).is_err());

        std::os::unix::fs::symlink(&valid, &linked).unwrap();
        config.git.as_mut().unwrap().workspace_roots = vec![linked.display().to_string()];
        assert!(validate_workspace_policy_at(&config, root.path()).is_err());

        config.git.as_mut().unwrap().workspace_roots = vec![valid.display().to_string()];
        fs::set_permissions(&valid, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(validate_workspace_policy_at(&config, root.path()).is_err());
        fs::set_permissions(&valid, fs::Permissions::from_mode(0o700)).unwrap();

        let nested = valid.join("nested");
        fs::create_dir(&nested).unwrap();
        config.git.as_mut().unwrap().workspace_roots =
            vec![valid.display().to_string(), nested.display().to_string()];
        assert!(validate_workspace_policy_at(&config, root.path()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_repository_authority_rejects_foreign_writable_descendants() {
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repository");
        fs::create_dir(&repository).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "remote.origin.url",
                "https://github.com/ExampleOrg/repository.git",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        let guard = test_git_guard();
        let config_digest = "00".repeat(32);

        for (path, unsafe_mode, safe_mode) in [
            (repository.join(".git/config"), 0o664, 0o600),
            (repository.join(".git"), 0o775, 0o700),
            (repository.clone(), 0o775, 0o700),
        ] {
            fs::set_permissions(&path, fs::Permissions::from_mode(unsafe_mode)).unwrap();
            for (capability, operation) in [("credential", "fetch"), ("signing", "commit")] {
                assert!(repository_authority_binding(
                    "/usr/bin/git",
                    &guard,
                    &repository,
                    GitAuthorityRequest {
                        config_digest: &config_digest,
                        capability,
                        operation,
                        owner: "ExampleOrg",
                        repository: "repository",
                        ref_selectors: &[],
                        mutable_ref_selectors: &[],
                    },
                )
                .is_err());
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(safe_mode)).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn no_authority_commands_reject_unsafe_effective_repository_authority() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let managed = home.join("managed");
        let repository = managed.join("repository");
        let config_path = home.join(".config/dev-auth/config.toml");
        fs::create_dir_all(&repository).unwrap();
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).unwrap();
        write_workspace_config(&config_path, &managed);
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "remote.origin.url",
                "https://github.com/ExampleOrg/repository.git",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        fs::set_permissions(
            repository.join(".git/config"),
            fs::Permissions::from_mode(0o664),
        )
        .unwrap();
        let runtime = root.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let directories = NativeUserDirs {
            home,
            config: config_path,
            runtime: runtime.clone(),
        };

        let error = run_git_at(
            &directories,
            &repository,
            &BTreeMap::new(),
            &[OsString::from("status"), OsString::from("--short")],
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("current-user owned"),
            "unexpected failure: {error:#}"
        );
        assert!(fs::read_dir(&runtime).unwrap().next().is_none());

        fs::set_permissions(
            repository.join(".git/config"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(repository.join(".gitattributes"), b"* text eol=lf\n").unwrap();
        fs::set_permissions(
            repository.join(".gitattributes"),
            fs::Permissions::from_mode(0o664),
        )
        .unwrap();
        let error = run_git_at(
            &directories,
            &repository,
            &BTreeMap::new(),
            &[OsString::from("status"), OsString::from("--short")],
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("current-user owned"),
            "unexpected failure: {error:#}"
        );
        fs::remove_file(repository.join(".gitattributes")).unwrap();

        assert!(Command::new("/usr/bin/git")
            .args(["config", "extensions.worktreeConfig", "true"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "--worktree",
                "remote.origin.fetch",
                "+refs/heads/*:refs/remotes/origin/*",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        fs::set_permissions(
            repository.join(".git/config.worktree"),
            fs::Permissions::from_mode(0o664),
        )
        .unwrap();
        let error = run_git_at(
            &directories,
            &repository,
            &BTreeMap::new(),
            &[OsString::from("status"), OsString::from("--short")],
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("current-user owned"),
            "unexpected failure: {error:#}"
        );
        assert!(fs::read_dir(runtime).unwrap().next().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ref_bearing_no_authority_commands_fail_before_runtime_authority() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let managed = home.join("managed");
        let repository = managed.join("repository");
        let config_path = home.join(".config/dev-auth/config.toml");
        fs::create_dir_all(&repository).unwrap();
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).unwrap();
        write_workspace_config(&config_path, &managed);
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet", "--initial-branch=main"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--allow-empty",
                "--quiet",
                "--message=initial",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args(["branch", "feature"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "remote.origin.url",
                "https://github.com/ExampleOrg/repository.git",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        let runtime = root.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let directories = NativeUserDirs {
            home,
            config: config_path,
            runtime: runtime.clone(),
        };

        for arguments in [
            vec!["restore", "--source", "refs/heads/feature", "--", "file"],
            vec!["branch", "created", "refs/heads/feature"],
            vec!["switch", "feature"],
            vec!["checkout", "feature"],
            vec!["log", "feature"],
            vec!["show", "refs/heads/feature"],
        ] {
            let arguments: Vec<OsString> = arguments.into_iter().map(OsString::from).collect();
            let error =
                run_git_at(&directories, &repository, &BTreeMap::new(), &arguments).unwrap_err();
            assert!(
                format!("{error:#}").contains("bounded")
                    || format!("{error:#}").contains("managed automation surface")
                    || format!("{error:#}").contains("full object identifier"),
                "unexpected rejection: {error:#}"
            );
            assert!(fs::read_dir(&runtime).unwrap().next().is_none());
        }
        assert!(!repository.join(".git/refs/heads/created").exists());
        let head = Command::new("/usr/bin/git")
            .args(["symbolic-ref", "--quiet", "HEAD"])
            .current_dir(&repository)
            .output()
            .unwrap();
        assert!(head.status.success());
        assert_eq!(head.stdout, b"refs/heads/main\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn no_authority_commands_reject_symlinked_common_objects_authority() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let managed = home.join("managed");
        let repository = managed.join("repository");
        let external_objects = root.path().join("external-objects");
        let config_path = home.join(".config/dev-auth/config.toml");
        fs::create_dir_all(&repository).unwrap();
        fs::create_dir(&external_objects).unwrap();
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).unwrap();
        write_workspace_config(&config_path, &managed);
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "remote.origin.url",
                "https://github.com/ExampleOrg/repository.git",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        fs::remove_dir_all(repository.join(".git/objects")).unwrap();
        std::os::unix::fs::symlink(&external_objects, repository.join(".git/objects")).unwrap();
        let runtime = root.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let directories = NativeUserDirs {
            home,
            config: config_path,
            runtime: runtime.clone(),
        };

        let error = run_git_at(
            &directories,
            &repository,
            &BTreeMap::new(),
            &[OsString::from("status"), OsString::from("--short")],
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("object"),
            "unexpected failure: {error:#}"
        );
        assert!(fs::read_dir(runtime).unwrap().next().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_authority_binds_head_packed_and_loose_refs() {
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repository");
        fs::create_dir(&repository).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "remote.origin.url",
                "https://github.com/ExampleOrg/repository.git",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        let guard = test_git_guard();
        let config_digest = "00".repeat(32);
        let ref_selectors = vec!["HEAD".to_owned()];
        let capture = || {
            repository_authority_binding(
                "/usr/bin/git",
                &guard,
                &repository,
                GitAuthorityRequest {
                    config_digest: &config_digest,
                    capability: "signing",
                    operation: "commit",
                    owner: "ExampleOrg",
                    repository: "repository",
                    ref_selectors: &ref_selectors,
                    mutable_ref_selectors: &["HEAD".to_owned()],
                },
            )
        };
        for path in [
            repository.join(".git/HEAD"),
            repository.join(".git/packed-refs"),
            repository.join(".git/refs/heads/main"),
        ] {
            if !path.exists() {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(&path, b"0000000000000000000000000000000000000000\n").unwrap();
            }
            let original = fs::metadata(&path).unwrap().permissions();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
            assert!(
                capture().is_err(),
                "accepted writable ref authority at {}",
                path.display()
            );
            fs::set_permissions(&path, original).unwrap();
        }
        for path in [
            repository.join(".git/refs"),
            repository.join(".git/refs/heads"),
        ] {
            let original = fs::metadata(&path).unwrap().permissions();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o775)).unwrap();
            assert!(
                capture().is_err(),
                "accepted writable ref directory authority at {}",
                path.display()
            );
            fs::set_permissions(&path, original).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn indexed_attributes_use_one_bounded_batch_process() {
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repository");
        fs::create_dir(&repository).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        for index in 0..1000 {
            let directory = repository.join(format!("nested-{index}"));
            fs::create_dir(&directory).unwrap();
            fs::write(
                directory.join(".gitattributes"),
                format!("*.txt text eol=lf\n# unique {index}\n"),
            )
            .unwrap();
        }
        assert!(Command::new("/usr/bin/git")
            .args(["add", "."])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        let program_root = tempfile::Builder::new()
            .prefix("dev-auth-git-batch-")
            .tempdir_in(native_current_user_home().unwrap())
            .unwrap();
        fs::set_permissions(program_root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let counter = program_root.path().join("cat-file-count");
        let wrapper = program_root.path().join("git-wrapper");
        fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nif [ \"${{1:-}}\" = cat-file ]; then printf x >> '{}'; fi\nexec /usr/bin/git \"$@\"\n",
                counter.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
        let guard = program_guard(wrapper.to_str().unwrap(), "test Git").unwrap();

        let snapshot =
            indexed_git_attributes_snapshot(wrapper.to_str().unwrap(), &guard, &repository)
                .unwrap();
        assert_eq!(snapshot.objects.len(), 1000);
        assert_eq!(fs::read(&counter).unwrap(), b"x");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn indexed_attributes_batch_rejects_malformed_missing_and_trailing_responses() {
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repository");
        fs::create_dir(&repository).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        let program_root = tempfile::Builder::new()
            .prefix("dev-auth-git-batch-errors-")
            .tempdir_in(native_current_user_home().unwrap())
            .unwrap();
        fs::set_permissions(program_root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let requested = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        for (name, response) in [
            (
                "mismatch",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb blob 0\n\n",
            ),
            (
                "missing",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa missing\n",
            ),
            (
                "bad-size",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa blob nope\n",
            ),
            (
                "trailing",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa blob 0\n\ntrailing",
            ),
            (
                "oversized",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa blob 1048577\n",
            ),
        ] {
            let wrapper = program_root.path().join(format!("git-{name}"));
            fs::write(
                &wrapper,
                format!(
                    "#!/bin/sh\n/usr/bin/cat >/dev/null\nprintf '%s' '{}'\n",
                    response
                ),
            )
            .unwrap();
            fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
            let guard = program_guard(wrapper.to_str().unwrap(), "test Git").unwrap();
            assert!(
                read_indexed_attribute_objects_batch(
                    wrapper.to_str().unwrap(),
                    &guard,
                    &repository,
                    BTreeSet::from([requested.to_vec()]),
                )
                .is_err(),
                "accepted {name} batch response"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_ref_selector_grammar_is_operation_exact() {
        assert_eq!(
            git_ref_authority_selectors(&[
                "commit".into(),
                "--no-status".into(),
                "--message".into(),
                "change".into(),
            ])
            .unwrap(),
            vec!["HEAD"]
        );
        assert_eq!(
            git_ref_authority_selectors(&[
                "push".into(),
                "origin".into(),
                "refs/heads/main:refs/heads/main".into(),
            ])
            .unwrap(),
            vec!["refs/heads/main"]
        );
        assert_eq!(
            git_ref_authority_selectors(&[
                "fetch".into(),
                "origin".into(),
                "refs/heads/main:refs/remotes/origin/main".into(),
            ])
            .unwrap(),
            vec!["refs/remotes/origin/main"]
        );
        assert!(git_ref_authority_selectors(&[
            "tag".into(),
            "--message".into(),
            "release".into(),
            "v1".into(),
            "ambiguous-short-name".into(),
        ])
        .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_reference_transitions_are_operation_bounded() {
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repository");
        fs::create_dir(&repository).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet", "--initial-branch=main"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--quiet",
                "--allow-empty",
                "--message=initial",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "remote.origin.url",
                "https://github.com/ExampleOrg/repository.git",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        let guard = test_git_guard();
        let config_digest = "00".repeat(32);

        let commit_arguments = vec![
            "commit".to_owned(),
            "--no-status".to_owned(),
            "--allow-empty".to_owned(),
            "--message".to_owned(),
            "next".to_owned(),
        ];
        let commit_selectors = git_ref_authority_selectors(&commit_arguments).unwrap();
        let commit_mutations = git_mutable_ref_selectors(&commit_arguments).unwrap();
        let commit = repository_authority_binding(
            "/usr/bin/git",
            &guard,
            &repository,
            GitAuthorityRequest {
                config_digest: &config_digest,
                capability: "signing",
                operation: "commit",
                owner: "ExampleOrg",
                repository: "repository",
                ref_selectors: &commit_selectors,
                mutable_ref_selectors: &commit_mutations,
            },
        )
        .unwrap();
        assert!(Command::new("/usr/bin/git")
            .args([
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--quiet",
                "--allow-empty",
                "--message=next",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        commit.verify_after_child().unwrap();
        verify_reference_authority_transition(&commit, true, false).unwrap();

        let tag_arguments = vec![
            "tag".to_owned(),
            "--annotate".to_owned(),
            "--message".to_owned(),
            "release".to_owned(),
            "release".to_owned(),
            "HEAD".to_owned(),
        ];
        let tag_selectors = git_ref_authority_selectors(&tag_arguments).unwrap();
        let tag_mutations = git_mutable_ref_selectors(&tag_arguments).unwrap();
        let tag = repository_authority_binding(
            "/usr/bin/git",
            &guard,
            &repository,
            GitAuthorityRequest {
                config_digest: &config_digest,
                capability: "signing",
                operation: "tag",
                owner: "ExampleOrg",
                repository: "repository",
                ref_selectors: &tag_selectors,
                mutable_ref_selectors: &tag_mutations,
            },
        )
        .unwrap();
        assert!(Command::new("/usr/bin/git")
            .args([
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "tag",
                "--annotate",
                "--message=release",
                "release",
                "HEAD",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        tag.verify_after_child().unwrap();
        verify_reference_authority_transition(&tag, true, false).unwrap();

        let fetch_arguments = vec![
            "fetch".to_owned(),
            "origin".to_owned(),
            "refs/heads/main:refs/remotes/origin/main".to_owned(),
        ];
        let fetch_selectors = git_ref_authority_selectors(&fetch_arguments).unwrap();
        let fetch_mutations = git_mutable_ref_selectors(&fetch_arguments).unwrap();
        let fetch = repository_authority_binding(
            "/usr/bin/git",
            &guard,
            &repository,
            GitAuthorityRequest {
                config_digest: &config_digest,
                capability: "credential",
                operation: "fetch",
                owner: "ExampleOrg",
                repository: "repository",
                ref_selectors: &fetch_selectors,
                mutable_ref_selectors: &fetch_mutations,
            },
        )
        .unwrap();
        verify_reference_authority_transition(&fetch, true, true).unwrap();
        let head = Command::new("/usr/bin/git")
            .args(["rev-parse", "--verify", "HEAD"])
            .current_dir(&repository)
            .output()
            .unwrap();
        assert!(head.status.success());
        let head = String::from_utf8(head.stdout).unwrap();
        fs::create_dir_all(repository.join(".git/refs/remotes/origin")).unwrap();
        fs::write(repository.join(".git/refs/remotes/origin/main"), &head).unwrap();
        verify_reference_authority_transition(&fetch, true, false).unwrap();

        let push_arguments = vec![
            "push".to_owned(),
            "origin".to_owned(),
            "refs/heads/main:refs/heads/main".to_owned(),
        ];
        let push_selectors = git_ref_authority_selectors(&push_arguments).unwrap();
        let packed_refs = repository.join(".git/packed-refs");
        fs::write(&packed_refs, format!("{} refs/tags/stable\n", head.trim())).unwrap();
        let capture_push = || {
            repository_authority_binding(
                "/usr/bin/git",
                &guard,
                &repository,
                GitAuthorityRequest {
                    config_digest: &config_digest,
                    capability: "credential",
                    operation: "push",
                    owner: "ExampleOrg",
                    repository: "repository",
                    ref_selectors: &push_selectors,
                    mutable_ref_selectors: &[],
                },
            )
        };
        let packed_bound = capture_push().unwrap();
        fs::write(
            &packed_refs,
            format!(
                "{} refs/tags/stable\n{} refs/tags/undeclared\n",
                head.trim(),
                head.trim()
            ),
        )
        .unwrap();
        assert!(packed_bound.verify_after_child().is_err());
        fs::write(&packed_refs, format!("{} refs/tags/stable\n", head.trim())).unwrap();
        let push = capture_push().unwrap();
        fs::write(
            repository.join(".git/refs/heads/main"),
            "0".repeat(40) + "\n",
        )
        .unwrap();
        assert!(verify_reference_authority_transition(&push, true, false).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejected_local_config_key_is_value_blind() {
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repository");
        fs::create_dir(&repository).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        let sentinel = "CREDENTIAL-SENTINEL-DO-NOT-PRINT";
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "--local",
                &format!("http.https://{sentinel}@example.invalid.extraheader"),
                "value",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        let error = validate_local_git_configuration(
            "/usr/bin/git",
            &test_git_guard(),
            &repository,
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert!(!format!("{error:#}").contains(sentinel));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn persistent_alternate_object_databases_are_never_private_authority() {
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repository");
        let external = root.path().join("external-objects");
        fs::create_dir(&repository).unwrap();
        fs::create_dir(&external).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "remote.origin.url",
                "https://github.com/ExampleOrg/repository.git",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        let alternates = repository.join(".git/objects/info/alternates");
        let guard = test_git_guard();
        let config_digest = "00".repeat(32);
        let capture = || {
            repository_authority_binding(
                "/usr/bin/git",
                &guard,
                &repository,
                GitAuthorityRequest {
                    config_digest: &config_digest,
                    capability: "credential",
                    operation: "fetch",
                    owner: "ExampleOrg",
                    repository: "repository",
                    ref_selectors: &[],
                    mutable_ref_selectors: &[],
                },
            )
        };

        for value in [
            external.display().to_string(),
            "../../../../external-objects".to_owned(),
        ] {
            fs::write(&alternates, format!("{value}\n")).unwrap();
            assert!(capture().is_err());
            fs::remove_file(&alternates).unwrap();
        }
        std::os::unix::fs::symlink(&external, &alternates).unwrap();
        assert!(capture().is_err());
        fs::remove_file(&alternates).unwrap();

        let binding = capture().unwrap();
        fs::write(&alternates, format!("{}\n", external.display())).unwrap();
        assert!(binding.verify_held_paths().is_err() || capture().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn literal_origin_requires_exactly_one_effective_value() {
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repository");
        fs::create_dir(&repository).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        for value in [
            "https://github.com/ExampleOrg/one.git",
            "https://github.com/ExampleOrg/two.git",
        ] {
            assert!(Command::new("/usr/bin/git")
                .args(["config", "--local", "--add", "remote.origin.url", value])
                .current_dir(&repository)
                .status()
                .unwrap()
                .success());
        }
        assert!(literal_origin_repository_at_os(
            "/usr/bin/git",
            &test_git_guard(),
            &repository,
            &BTreeMap::new(),
        )
        .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn absent_managed_clone_destination_is_routable_and_reserved_privately() {
        let root = tempfile::tempdir().unwrap();
        let managed = root.path().join("managed");
        fs::create_dir(&managed).unwrap();
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).unwrap();
        let destination = managed.join("repository");
        let arguments = [
            OsString::from("clone"),
            OsString::from("--no-checkout"),
            OsString::from("https://github.com/ExampleOrg/repository.git"),
            OsString::from("repository"),
        ];
        assert_eq!(
            classify_git_invocation_at(
                &arguments,
                &managed,
                &[fs::canonicalize(&managed).unwrap()],
                &BTreeMap::new(),
            )
            .unwrap(),
            GitInvocationRoute::Managed(0)
        );

        let config_digest = "00".repeat(32);
        let binding = stable_clone_authority_binding(
            &destination,
            GitAuthorityRequest {
                config_digest: &config_digest,
                capability: "credential",
                operation: "clone",
                owner: "ExampleOrg",
                repository: "repository",
                ref_selectors: &[],
                mutable_ref_selectors: &[],
            },
        )
        .unwrap();
        assert!(destination.is_dir());
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o700
        );
        binding.verify_held_paths().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_authority_ignores_large_irrelevant_untracked_subtrees() {
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repository");
        fs::create_dir(&repository).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "remote.origin.url",
                "https://github.com/ExampleOrg/repository.git",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        let ignored = repository.join("ignored-generated-tree");
        fs::create_dir(&ignored).unwrap();
        for index in 0..4096 {
            fs::write(ignored.join(format!("artifact-{index}")), b"irrelevant").unwrap();
        }
        fs::set_permissions(&ignored, fs::Permissions::from_mode(0o000)).unwrap();

        let config_digest = "00".repeat(32);
        let result = repository_authority_binding(
            "/usr/bin/git",
            &test_git_guard(),
            &repository,
            GitAuthorityRequest {
                config_digest: &config_digest,
                capability: "credential",
                operation: "fetch",
                owner: "ExampleOrg",
                repository: "repository",
                ref_selectors: &[],
                mutable_ref_selectors: &[],
            },
        );
        fs::set_permissions(&ignored, fs::Permissions::from_mode(0o700)).unwrap();
        result.unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn proven_unmanaged_repository_keeps_human_local_configuration() {
        let root = tempfile::tempdir().unwrap();
        let managed = root.path().join("managed");
        let unmanaged = root.path().join("unmanaged");
        fs::create_dir(&managed).unwrap();
        fs::create_dir(&unmanaged).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&unmanaged)
            .status()
            .unwrap()
            .success());
        let marker = root.path().join("human-alias-ran");
        let authority_marker = root.path().join("automation-authority-ran");
        let authority = root.path().join("automation-authority");
        fs::write(
            &authority,
            format!(
                "#!/bin/sh\nprintf invoked > '{}'\nexit 99\n",
                authority_marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&authority, fs::Permissions::from_mode(0o700)).unwrap();
        let alias = format!("!printf invoked > '{}'", marker.display());
        for (key, value) in [
            ("alias.human", alias.as_str()),
            ("credential.helper", "!printf 'username=human\\n'"),
        ] {
            assert!(Command::new("/usr/bin/git")
                .args(["config", "--local", key, value])
                .current_dir(&unmanaged)
                .status()
                .unwrap()
                .success());
        }
        let roots = vec![fs::canonicalize(&managed).unwrap()];
        validate_unmanaged_repository_context(
            "/usr/bin/git",
            &test_git_guard(),
            &unmanaged,
            &roots,
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(!marker.exists());

        let home = root.path().join("home");
        let config_path = home.join(".config/dev-auth/config.toml");
        write_workspace_config(&config_path, &managed);
        let config = fs::read_to_string(&config_path).unwrap().replace(
            "op = \"/usr/bin/false\"",
            &format!("op = \"{}\"", authority.display()),
        );
        fs::write(&config_path, config).unwrap();
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
        let original_config = fs::read(&config_path).unwrap();
        let directories = NativeUserDirs {
            home,
            config: config_path.clone(),
            runtime: root.path().join("runtime"),
        };
        let status = run_git_at(
            &directories,
            &unmanaged,
            &BTreeMap::new(),
            &[OsString::from("human")],
        )
        .unwrap();
        assert!(status.success());
        assert!(marker.exists());
        assert!(!authority_marker.exists());
        assert!(!directories.runtime.exists());
        assert_eq!(fs::read(config_path).unwrap(), original_config);
    }

    #[cfg(unix)]
    #[test]
    fn rejected_managed_command_never_creates_private_runtime_state() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let managed = home.join("managed");
        let config_path = home.join(".config/dev-auth/config.toml");
        fs::create_dir_all(&managed).unwrap();
        write_workspace_config(&config_path, &managed);
        let directories = NativeUserDirs {
            home,
            config: config_path.clone(),
            runtime: root.path().join("runtime"),
        };
        let original_config = fs::read(&config_path).unwrap();

        assert!(run_git_at(
            &directories,
            &managed,
            &BTreeMap::new(),
            &[OsString::from("pull"), OsString::from("origin")],
        )
        .is_err());
        assert!(!directories.runtime.exists());
        assert_eq!(fs::read(config_path).unwrap(), original_config);
    }

    #[cfg(unix)]
    #[test]
    fn unmanaged_repository_probe_rejects_a_local_worktree_redirect_into_managed_space() {
        let root = tempfile::tempdir().unwrap();
        let managed = root.path().join("managed");
        let unmanaged = root.path().join("unmanaged");
        fs::create_dir(&managed).unwrap();
        fs::create_dir(&unmanaged).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&unmanaged)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args(["config", "--local", "core.worktree"])
            .arg(&managed)
            .current_dir(&unmanaged)
            .status()
            .unwrap()
            .success());
        let roots = vec![fs::canonicalize(&managed).unwrap()];
        assert!(validate_unmanaged_repository_context(
            "/usr/bin/git",
            &test_git_guard(),
            &unmanaged,
            &roots,
            &BTreeMap::new(),
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn managed_repository_preflight_rejects_local_filters_and_nested_attributes() {
        let root = tempfile::tempdir().unwrap();
        let managed = root.path().join("managed");
        let repository = managed.join("repository");
        fs::create_dir_all(repository.join("nested")).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        let roots = vec![fs::canonicalize(&managed).unwrap()];
        let environment = BTreeMap::new();
        let marker = root.path().join("external-driver-ran");
        let driver = root.path().join("external-driver");
        fs::write(
            &driver,
            format!("#!/bin/sh\nprintf invoked > '{}'\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(&driver, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "--local",
                "filter.evil.process",
                driver.to_str().unwrap(),
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(validate_managed_repository_context(
            "/usr/bin/git",
            &test_git_guard(),
            &repository,
            &roots,
            0,
            &environment,
            true,
        )
        .is_err());
        assert!(!marker.exists());

        assert!(Command::new("/usr/bin/git")
            .args(["config", "--local", "--unset-all", "filter.evil.process"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        fs::write(repository.join("nested/.gitattributes"), "* filter=evil\n").unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["add", "--", "nested/.gitattributes"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(validate_managed_repository_context(
            "/usr/bin/git",
            &test_git_guard(),
            &repository,
            &roots,
            0,
            &environment,
            true,
        )
        .is_err());
        assert!(!marker.exists());
        assert!(Command::new("/usr/bin/git")
            .args(["rm", "--cached", "--force", "--", "nested/.gitattributes"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        fs::remove_file(repository.join("nested/.gitattributes")).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "--local",
                "diff.external.command",
                driver.to_str().unwrap(),
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        fs::write(repository.join(".git/info/attributes"), "* diff=external\n").unwrap();
        assert!(validate_managed_repository_context(
            "/usr/bin/git",
            &test_git_guard(),
            &repository,
            &roots,
            0,
            &environment,
            true,
        )
        .is_err());
        assert!(!marker.exists());

        assert!(Command::new("/usr/bin/git")
            .args(["config", "--local", "--unset-all", "diff.external.command"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        fs::write(
            repository.join(".git/info/attributes"),
            "* merge=external\n",
        )
        .unwrap();
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "--local",
                "merge.external.driver",
                driver.to_str().unwrap(),
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        for operation in ["commit -a", "checkout", "pull"] {
            let result = validate_managed_repository_context(
                "/usr/bin/git",
                &test_git_guard(),
                &repository,
                &roots,
                0,
                &environment,
                true,
            );
            assert!(result.is_err(), "{operation} preflight unexpectedly passed");
            assert!(!marker.exists(), "{operation} executed an external driver");
        }
        let clone_arguments = [
            OsString::from("clone"),
            OsString::from("https://github.com/ExampleOrg/repository.git"),
            OsString::from("repository"),
        ];
        assert!(validate_managed_clone_postcondition(
            "/usr/bin/git",
            &test_git_guard(),
            &clone_arguments,
            &managed,
            &roots,
            0,
            &environment,
        )
        .is_err());
        assert!(
            !marker.exists(),
            "clone post-scan executed an external driver"
        );
    }

    #[cfg(unix)]
    #[test]
    fn managed_repository_preflight_rejects_info_attributes_without_a_driver_config() {
        let root = tempfile::tempdir().unwrap();
        let managed = root.path().join("managed");
        let repository = managed.join("repository");
        fs::create_dir_all(&repository).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        fs::write(repository.join(".git/info/attributes"), "* filter=evil\n").unwrap();

        assert!(validate_managed_repository_context(
            "/usr/bin/git",
            &test_git_guard(),
            &repository,
            &[fs::canonicalize(&managed).unwrap()],
            0,
            &BTreeMap::new(),
            true,
        )
        .is_err());
    }

    #[cfg(unix)]
    fn linked_worktree(root: &Path) -> (PathBuf, PathBuf) {
        let repository = root.join("repository");
        let worktree = root.join("worktree");
        fs::create_dir(&repository).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgSign=false",
                "commit",
                "--allow-empty",
                "--quiet",
                "-m",
                "initial",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args(["config", "extensions.worktreeConfig", "true"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args(["worktree", "add", "--detach", "--quiet"])
            .arg(&worktree)
            .arg("HEAD")
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        (repository, worktree)
    }

    #[cfg(unix)]
    #[test]
    fn linked_worktree_effective_config_rejects_hidden_external_authority() {
        let root = tempfile::tempdir().unwrap();
        let (repository, worktree) = linked_worktree(root.path());
        let marker = root.path().join("worktree-proxy-ran");
        let proxy = format!("!printf invoked > '{}'", marker.display());
        for (key, value) in [
            ("remote.origin.proxy", proxy.as_str()),
            ("credential.helper", "!exit 99"),
            ("core.hooksPath", "/tmp/hostile-hooks"),
        ] {
            assert!(Command::new("/usr/bin/git")
                .args(["config", "--worktree", key, value])
                .current_dir(&worktree)
                .status()
                .unwrap()
                .success());
            assert!(validate_local_git_configuration(
                "/usr/bin/git",
                &test_git_guard(),
                &worktree,
                &BTreeMap::new(),
            )
            .is_err());
            assert!(!marker.exists());
            assert!(Command::new("/usr/bin/git")
                .args(["config", "--worktree", "--unset-all", key])
                .current_dir(&worktree)
                .status()
                .unwrap()
                .success());
        }

        fs::write(repository.join(".git/info/attributes"), "* filter=evil\n").unwrap();
        assert!(validate_managed_repository_context(
            "/usr/bin/git",
            &test_git_guard(),
            &worktree,
            &[fs::canonicalize(root.path()).unwrap()],
            0,
            &BTreeMap::new(),
            true,
        )
        .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linked_worktree_commondir_is_held_private_authority() {
        let root = tempfile::tempdir().unwrap();
        let (repository, worktree) = linked_worktree(root.path());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "remote.origin.url",
                "https://github.com/ExampleOrg/repository.git",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "--worktree",
                "remote.origin.fetch",
                "+refs/heads/*:refs/remotes/origin/*",
            ])
            .current_dir(&worktree)
            .status()
            .unwrap()
            .success());
        let guard = test_git_guard();
        let git_dir = resolved_repository_paths("/usr/bin/git", &guard, &worktree)
            .unwrap()
            .git_dir;
        let commondir = git_dir.join("commondir");
        assert!(commondir.is_file());
        let original_commondir = fs::read(&commondir).unwrap();
        let alternate = root.path().join("alternate");
        fs::create_dir(&alternate).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&alternate)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "remote.origin.url",
                "https://github.com/OtherOrg/substituted.git",
            ])
            .current_dir(&alternate)
            .status()
            .unwrap()
            .success());
        fs::write(
            &commondir,
            format!("{}\n", alternate.join(".git").display()),
        )
        .unwrap();
        fs::set_permissions(&commondir, fs::Permissions::from_mode(0o664)).unwrap();
        let config_digest = "00".repeat(32);

        for (capability, operation, selectors, mutable) in [
            ("none", "status", Vec::new(), Vec::new()),
            (
                "credential",
                "fetch",
                vec!["refs/remotes/origin/main".to_owned()],
                vec!["refs/remotes/origin/main".to_owned()],
            ),
            (
                "signing",
                "commit",
                vec!["HEAD".to_owned()],
                vec!["HEAD".to_owned()],
            ),
        ] {
            let error = repository_authority_binding(
                "/usr/bin/git",
                &guard,
                &worktree,
                GitAuthorityRequest {
                    config_digest: &config_digest,
                    capability,
                    operation,
                    owner: "ExampleOrg",
                    repository: "repository",
                    ref_selectors: &selectors,
                    mutable_ref_selectors: &mutable,
                },
            )
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("current-user owned"),
                "unexpected linked-worktree rejection for {operation}: {error:#}"
            );
        }

        fs::write(&commondir, original_commondir).unwrap();
        fs::set_permissions(&commondir, fs::Permissions::from_mode(0o600)).unwrap();
        repository_authority_binding(
            "/usr/bin/git",
            &guard,
            &worktree,
            GitAuthorityRequest {
                config_digest: &config_digest,
                capability: "none",
                operation: "status",
                owner: "ExampleOrg",
                repository: "repository",
                ref_selectors: &[],
                mutable_ref_selectors: &[],
            },
        )
        .unwrap();
        fs::remove_file(&commondir).unwrap();
        std::os::unix::fs::symlink(alternate.join(".git"), &commondir).unwrap();
        assert!(resolved_repository_paths("/usr/bin/git", &guard, &worktree).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn linked_worktree_origin_uses_the_effective_no_include_authority() {
        let root = tempfile::tempdir().unwrap();
        let (repository, worktree) = linked_worktree(root.path());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "remote.origin.url",
                "https://github.com/BaseOwner/base.git",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "--worktree",
                "remote.origin.url",
                "https://github.com/WorktreeOwner/worktree.git",
            ])
            .current_dir(&worktree)
            .status()
            .unwrap()
            .success());
        validate_local_git_configuration(
            "/usr/bin/git",
            &test_git_guard(),
            &worktree,
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(literal_origin_repository_at_os(
            "/usr/bin/git",
            &test_git_guard(),
            &worktree,
            &BTreeMap::new(),
        )
        .is_err());
        assert!(Command::new("/usr/bin/git")
            .args(["config", "--local", "--unset-all", "remote.origin.url"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert_eq!(
            literal_origin_repository_at_os(
                "/usr/bin/git",
                &test_git_guard(),
                &worktree,
                &BTreeMap::new(),
            )
            .unwrap(),
            ("WorktreeOwner".to_owned(), "worktree".to_owned())
        );

        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "--worktree",
                "remote.origin.url",
                "file:///tmp/not-github",
            ])
            .current_dir(&worktree)
            .status()
            .unwrap()
            .success());
        assert!(literal_origin_repository_at_os(
            "/usr/bin/git",
            &test_git_guard(),
            &worktree,
            &BTreeMap::new(),
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn managed_git_child_environment_has_no_human_fallback_surface() {
        let root = tempfile::tempdir().unwrap();
        let paths = RuntimePaths {
            config: root.path().join("config.toml"),
            runtime: root.path().join("runtime"),
        };
        let policy = crate::GitPolicy {
            workspace_roots: vec!["~/repos".into()],
            author_name: "Automation Worker".into(),
            author_email: "automation@example.invalid".into(),
            ssh_profile: "automation".into(),
        };
        let input = BTreeMap::from([
            (OsString::from("HOME"), OsString::from("/human/home")),
            (OsString::from("PATH"), OsString::from("/human/bin")),
            (OsString::from("GH_TOKEN"), OsString::from("human-token")),
            (OsString::from("GIT_CONFIG_COUNT"), OsString::from("1")),
            (
                OsString::from("GIT_CONFIG_KEY_0"),
                OsString::from("credential.helper"),
            ),
            (
                OsString::from("GIT_CONFIG_VALUE_0"),
                OsString::from("human-helper"),
            ),
            (
                OsString::from("GIT_SSH_COMMAND"),
                OsString::from("human-ssh"),
            ),
            (
                OsString::from("XDG_CONFIG_HOME"),
                OsString::from("/human/config"),
            ),
            (
                OsString::from("GIT_CONFIG"),
                OsString::from("/human/gitconfig"),
            ),
            (
                OsString::from("GIT_CONFIG_GLOBAL"),
                OsString::from("/human/global-gitconfig"),
            ),
            (
                OsString::from("GIT_CONFIG_SYSTEM"),
                OsString::from("/human/system-gitconfig"),
            ),
            (
                OsString::from("GIT_CONFIG_PARAMETERS"),
                OsString::from("'credential.helper=human'"),
            ),
            (
                OsString::from("GIT_SHALLOW_FILE"),
                OsString::from("/human/shallow"),
            ),
            (
                OsString::from("GIT_EXEC_PATH"),
                OsString::from("/human/exec"),
            ),
            (
                OsString::from("GIT_TEMPLATE_DIR"),
                OsString::from("/human/template"),
            ),
            (OsString::from("GIT_TRACE"), OsString::from("/human/trace")),
            (
                OsString::from("GIT_EXTERNAL_DIFF"),
                OsString::from("/human/diff"),
            ),
            (
                OsString::from("GIT_ATTR_SOURCE"),
                OsString::from("human-attributes"),
            ),
            (OsString::from("GIT_SSL_NO_VERIFY"), OsString::from("true")),
            (
                OsString::from("GIT_ALLOW_PROTOCOL"),
                OsString::from("ext:ssh"),
            ),
            (
                OsString::from("GIT_AUTHOR_NAME"),
                OsString::from("Human Author"),
            ),
            (
                OsString::from("GIT_COMMITTER_EMAIL"),
                OsString::from("human@example.invalid"),
            ),
        ]);
        let environment = isolated_git_environment(
            &input,
            &paths,
            &paths.git_child_bin_dir(),
            &policy,
            crate::GitCapability::Signing,
            "00",
            None,
        )
        .unwrap();
        assert_eq!(
            environment.get(OsStr::new("PATH")),
            Some(&paths.git_child_bin_dir().into_os_string())
        );
        assert_eq!(
            environment.get(OsStr::new("HOME")),
            Some(&paths.git_home_dir().into_os_string())
        );
        for removed in [
            "GH_TOKEN",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
            "GIT_CONFIG",
            "GIT_CONFIG_PARAMETERS",
            "GIT_SHALLOW_FILE",
            "GIT_EXEC_PATH",
            "GIT_TEMPLATE_DIR",
            "GIT_TRACE",
            "GIT_ATTR_SOURCE",
            "GIT_SSL_NO_VERIFY",
            "GIT_ALLOW_PROTOCOL",
        ] {
            assert!(!environment.contains_key(OsStr::new(removed)));
        }
        assert_eq!(
            environment.get(OsStr::new("GIT_SSH_COMMAND")),
            Some(&OsString::from("false"))
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_EXTERNAL_DIFF")),
            Some(&OsString::from("false"))
        );
        assert_eq!(
            environment.get(OsStr::new("XDG_CONFIG_HOME")),
            Some(&paths.git_config_dir().into_os_string())
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_CONFIG_GLOBAL")),
            Some(&paths.git_empty_config_file().into_os_string())
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_CONFIG_SYSTEM")),
            Some(&paths.git_empty_config_file().into_os_string())
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_AUTHOR_NAME")),
            Some(&OsString::from("Automation Worker"))
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_COMMITTER_EMAIL")),
            Some(&OsString::from("automation@example.invalid"))
        );

        let hooks = root.path().join("hooks");
        let arguments = managed_git_configuration_arguments(
            &paths,
            &policy,
            crate::GitCapability::Signing,
            "ExampleOrg",
            "repository",
            Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest dev-auth:signing"),
            &hooks,
        )
        .unwrap();
        let settings: Vec<String> = arguments
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                assert_eq!(pair[0], OsStr::new("-c"));
                pair[1].to_string_lossy().into_owned()
            })
            .collect();
        for required in [
            "credential.helper=",
            "credential.useHttpPath=true",
            "credential.interactive=false",
            "user.name=Automation Worker",
            "user.email=automation@example.invalid",
            "gpg.format=ssh",
            "gpg.ssh.program=ssh-keygen-dev-auth",
            "commit.gpgSign=true",
            "tag.gpgSign=true",
            "protocol.allow=never",
            "protocol.https.allow=always",
            "protocol.ssh.allow=never",
            "diff.ignoreSubmodules=all",
            "status.submoduleSummary=false",
            "checkout.recurseSubmodules=false",
            "push.recurseSubmodules=no",
            "remote.origin.url=https://github.com/ExampleOrg/repository.git",
            "remote.origin.pushurl=https://github.com/ExampleOrg/repository.git",
            "http.https://github.com.sslVerify=true",
            "http.https://github.com.proxy=",
            "http.https://github.com/ExampleOrg/repository.git.sslVerify=true",
            "http.https://github.com/ExampleOrg/repository.git.proxy=",
        ] {
            assert!(
                settings.iter().any(|value| value == required),
                "missing {required}"
            );
        }
        assert_eq!(
            settings
                .iter()
                .filter(|value| *value == "credential.helper=dev-auth")
                .count(),
            0
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn repository_authority_binds_config_origin_attributes_index_and_file_identity() {
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repository");
        fs::create_dir(&repository).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "--local",
                "remote.origin.url",
                "https://github.com/ExampleOrg/repository.git",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        let guard = test_git_guard();
        let config_digest = "00".repeat(32);
        let request = GitAuthorityRequest {
            config_digest: &config_digest,
            capability: "credential",
            operation: "fetch",
            owner: "ExampleOrg",
            repository: "repository",
            ref_selectors: &[],
            mutable_ref_selectors: &[],
        };
        let capture =
            || repository_authority_binding("/usr/bin/git", &guard, &repository, request).unwrap();

        let initial = capture();
        assert_eq!(initial.digest, capture().digest);

        fs::write(repository.join(".gitattributes"), "* text eol=lf\n").unwrap();
        let working_tree_attributes = capture();
        assert_ne!(initial.digest, working_tree_attributes.digest);

        assert!(Command::new("/usr/bin/git")
            .args(["add", "--", ".gitattributes"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        let indexed_attributes = capture();
        assert_ne!(working_tree_attributes.digest, indexed_attributes.digest);

        assert!(Command::new("/usr/bin/git")
            .args(["config", "--local", "core.abbrev", "12"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        let config_value = capture();
        assert_ne!(indexed_attributes.digest, config_value.digest);

        let config_path = repository.join(".git/config");
        let prior_path = repository.join(".git/config.previous");
        let config_bytes = fs::read(&config_path).unwrap();
        fs::rename(&config_path, &prior_path).unwrap();
        fs::write(&config_path, config_bytes).unwrap();
        let replaced_identity = capture();
        assert_ne!(config_value.digest, replaced_identity.digest);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn changed_repository_authority_is_rejected_before_private_capability() {
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repository");
        let config_path = root.path().join("config/config.toml");
        fs::create_dir(&repository).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "--local",
                "remote.origin.url",
                "https://github.com/ExampleOrg/repository.git",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        write_workspace_config(&config_path, root.path());
        let config = load_config_at(&config_path).unwrap();
        let guard = test_git_guard();
        let config_digest = "00".repeat(32);
        let binding = repository_authority_binding(
            "/usr/bin/git",
            &guard,
            &repository,
            GitAuthorityRequest {
                config_digest: &config_digest,
                capability: "credential",
                operation: "fetch",
                owner: "ExampleOrg",
                repository: "repository",
                ref_selectors: &[],
                mutable_ref_selectors: &[],
            },
        )
        .unwrap();
        fs::write(repository.join("nested.gitattributes"), "* text eol=lf\n").unwrap();
        fs::write(repository.join(".gitattributes"), "* text eol=lf\n").unwrap();

        assert!(revalidate_git_child_authority_at(
            &config,
            GitAuthorityRevalidation {
                expected_capability: "credential",
                actual_capability: "credential",
                kind: "repository",
                operation: "fetch",
                root: &binding.root,
                expected_digest: &binding.digest,
                config_digest: &config_digest,
                ref_selectors: &binding.ref_selectors,
                mutable_ref_selectors: &[],
                requested_repository: Some(("ExampleOrg", "repository")),
            },
        )
        .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn clone_authority_allows_git_metadata_creation_but_rejects_destination_replacement() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("repository");
        let config_path = root.path().join("config/config.toml");
        write_workspace_config(&config_path, root.path());
        let config = load_config_at(&config_path).unwrap();
        let config_digest = "00".repeat(32);
        let binding = stable_clone_authority_binding(
            &destination,
            GitAuthorityRequest {
                config_digest: &config_digest,
                capability: "credential",
                operation: "clone",
                owner: "ExampleOrg",
                repository: "repository",
                ref_selectors: &[],
                mutable_ref_selectors: &[],
            },
        )
        .unwrap();

        fs::create_dir(destination.join(".git")).unwrap();
        revalidate_git_child_authority_at(
            &config,
            GitAuthorityRevalidation {
                expected_capability: "credential",
                actual_capability: "credential",
                kind: "clone",
                operation: "clone",
                root: &binding.root,
                expected_digest: &binding.digest,
                config_digest: &config_digest,
                ref_selectors: &binding.ref_selectors,
                mutable_ref_selectors: &[],
                requested_repository: Some(("ExampleOrg", "repository")),
            },
        )
        .unwrap();
        binding.verify_held_paths().unwrap();

        let replaced = root.path().join("replaced");
        fs::rename(&destination, &replaced).unwrap();
        fs::create_dir(&destination).unwrap();
        assert!(revalidate_git_child_authority_at(
            &config,
            GitAuthorityRevalidation {
                expected_capability: "credential",
                actual_capability: "credential",
                kind: "clone",
                operation: "clone",
                root: &binding.root,
                expected_digest: &binding.digest,
                config_digest: &config_digest,
                ref_selectors: &binding.ref_selectors,
                mutable_ref_selectors: &[],
                requested_repository: Some(("ExampleOrg", "repository")),
            },
        )
        .is_err());
        assert!(binding.verify_held_paths().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capability_specific_frontend_directories_contain_only_minimum_authority() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let paths = RuntimePaths {
            config: root.path().join("config.toml"),
            runtime: root.path().join("runtime"),
        };
        for (capability, expected) in [
            (
                crate::GitCapability::NoAuthority,
                vec![GIT_PAGER_FRONTEND, GIT_REJECT_FRONTEND],
            ),
            (
                crate::GitCapability::GitHubToken,
                vec![
                    GIT_PAGER_FRONTEND,
                    GIT_REJECT_FRONTEND,
                    GIT_CREDENTIAL_FRONTEND,
                ],
            ),
            (
                crate::GitCapability::Signing,
                vec![
                    GIT_PAGER_FRONTEND,
                    GIT_REJECT_FRONTEND,
                    GIT_SIGNING_FRONTEND,
                ],
            ),
        ] {
            let frontends = fresh_git_child_frontends(&paths, capability).unwrap();
            let mut names = fs::read_dir(frontends.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect::<Vec<_>>();
            names.sort();
            let mut expected = expected.into_iter().map(str::to_owned).collect::<Vec<_>>();
            expected.sort();
            assert_eq!(names, expected);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ignored_untracked_attributes_cannot_select_an_ambient_driver() {
        let root = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let repository = root.path().join("repository");
        fs::create_dir(&repository).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "--local",
                "remote.origin.url",
                "https://github.com/ExampleOrg/repository.git",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        fs::create_dir(repository.join("nested")).unwrap();
        fs::write(repository.join("nested/tracked.txt"), "initial\n").unwrap();
        fs::write(repository.join(".gitignore"), "nested/.gitattributes\n").unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["add", "--", ".gitignore", "nested/tracked.txt"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());

        let marker = root.path().join("ambient-filter-ran");
        let driver = root.path().join("ambient-filter");
        fs::write(
            &driver,
            format!("#!/bin/sh\nprintf invoked > '{}'\ncat\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(&driver, fs::Permissions::from_mode(0o700)).unwrap();
        let ambient_global = root.path().join("ambient-global-config");
        fs::write(
            &ambient_global,
            format!(
                "[filter \"evil\"]\n\tclean = {}\n\tsmudge = {}\n[diff \"evil\"]\n\tcommand = {}\n[merge \"evil\"]\n\tdriver = {}\n",
                driver.display(),
                driver.display(),
                driver.display(),
                driver.display(),
            ),
        )
        .unwrap();
        let guard = test_git_guard();
        let config_digest = "00".repeat(32);
        let request = GitAuthorityRequest {
            config_digest: &config_digest,
            capability: "credential",
            operation: "fetch",
            owner: "ExampleOrg",
            repository: "repository",
            ref_selectors: &[],
            mutable_ref_selectors: &[],
        };
        let before =
            repository_authority_binding("/usr/bin/git", &guard, &repository, request).unwrap();
        fs::write(
            repository.join("nested/.gitattributes"),
            "* filter=evil diff=evil merge=evil\n",
        )
        .unwrap();
        fs::write(repository.join("nested/tracked.txt"), "changed\n").unwrap();

        let ordinary = Command::new("/usr/bin/git")
            .args(["status", "--short"])
            .current_dir(&repository)
            .env("GIT_CONFIG_GLOBAL", &ambient_global)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .status()
            .unwrap();
        assert!(ordinary.success());
        assert!(
            marker.exists(),
            "positive control did not invoke the driver"
        );
        fs::remove_file(&marker).unwrap();

        let after =
            repository_authority_binding("/usr/bin/git", &guard, &repository, request).unwrap();
        assert_eq!(before.digest, after.digest);

        let paths = RuntimePaths {
            config: root.path().join("config.toml"),
            runtime: root.path().join("runtime"),
        };
        let policy = crate::GitPolicy {
            workspace_roots: vec![root.path().display().to_string()],
            author_name: "Automation Worker".into(),
            author_email: "automation@example.invalid".into(),
            ssh_profile: "automation".into(),
        };
        let frontends =
            fresh_git_child_frontends(&paths, crate::GitCapability::NoAuthority).unwrap();
        let hooks = fresh_git_hooks_directory(&paths).unwrap();
        let input = BTreeMap::from([(
            OsString::from("GIT_CONFIG_GLOBAL"),
            ambient_global.into_os_string(),
        )]);
        let environment = isolated_git_environment(
            &input,
            &paths,
            frontends.path(),
            &policy,
            crate::GitCapability::NoAuthority,
            &config_digest,
            None,
        )
        .unwrap();
        let mut arguments = managed_git_configuration_arguments(
            &paths,
            &policy,
            crate::GitCapability::NoAuthority,
            "ExampleOrg",
            "repository",
            None,
            hooks.path(),
        )
        .unwrap();
        arguments.extend([OsString::from("status"), OsString::from("--short")]);
        let mut child = guarded_command("/usr/bin/git", &guard).unwrap();
        let output = child
            .args(arguments)
            .current_dir(&repository)
            .env_clear()
            .envs(environment)
            .output()
            .unwrap();
        assert!(output.status.success(), "managed Git status failed");
        assert!(!marker.exists(), "managed Git executed the ambient driver");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn managed_public_git_path_succeeds_without_human_configuration() {
        let root = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let home = root.path().join("home");
        let managed = home.join("managed");
        let repository = managed.join("repository");
        fs::create_dir_all(&repository).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "--local",
                "remote.origin.url",
                "https://github.com/ExampleOrg/repository.git",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        let config_path = home.join(".config/dev-auth/config.toml");
        write_workspace_config(&config_path, &managed);
        let directories = NativeUserDirs {
            home,
            config: config_path,
            runtime: root.path().join("runtime"),
        };
        let hostile_global = root.path().join("hostile-global");
        fs::write(
            &hostile_global,
            "[alias]\n\tstatus = !exit 97\n[credential]\n\thelper = !exit 98\n",
        )
        .unwrap();
        let environment = BTreeMap::from([
            (
                OsString::from("GIT_CONFIG_GLOBAL"),
                hostile_global.into_os_string(),
            ),
            (
                OsString::from("GIT_ASKPASS"),
                OsString::from("/usr/bin/false"),
            ),
        ]);
        let status = run_git_at(
            &directories,
            &repository,
            &environment,
            &[OsString::from("status"), OsString::from("--short")],
        )
        .unwrap();
        assert!(status.success());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn managed_clone_credential_and_signing_paths_use_only_their_bound_frontend() {
        let native_home = native_current_user_home().unwrap();
        let root = tempfile::tempdir_in(native_home).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let home = root.path().join("home");
        let managed = home.join("managed");
        let repository = managed.join("repository");
        fs::create_dir_all(&repository).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "--local",
                "remote.origin.url",
                "https://github.com/ExampleOrg/repository.git",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--quiet",
                "--allow-empty",
                "--message=initial",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        let marker = root.path().join("managed-child-record");
        let wrapper = root.path().join("guarded-git");
        fs::write(
            &wrapper,
            format!(
                r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  printf 'git version 2.55.0\n'
  exit 0
fi
verb=
last=
for argument in "$@"; do
  case "$argument" in
    status|fetch|push|clone|commit|tag) verb=$argument ;;
  esac
  last=$argument
done
if [ -z "$verb" ]; then
  exec /usr/bin/git "$@"
fi
{{
  printf 'verb=%s capability=%s\n' "$verb" "$DEV_AUTH_GIT_CAPABILITY"
  printf 'askpass=%s global=%s\n' "$GIT_ASKPASS" "$GIT_CONFIG_GLOBAL"
  /usr/bin/find "$PATH" -mindepth 1 -maxdepth 1 -printf 'frontend=%f\n' | /usr/bin/sort
}} >> '{}'
if [ "$verb" = clone ]; then
  /usr/bin/git init --quiet "$last" || exit 80
  printf '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n[remote "origin"]\n\turl = https://github.com/ExampleOrg/repository.git\n' > "$last/.git/config" || exit 81
elif [ "$verb" = fetch ]; then
  head=$(/usr/bin/git rev-parse --verify HEAD) || exit 82
  /usr/bin/mkdir -p .git/refs/remotes/origin || exit 83
  printf '%s\n' "$head" > .git/refs/remotes/origin/main || exit 84
  printf '%s\t\tbranch main\n' "$head" > .git/FETCH_HEAD || exit 85
elif [ "$verb" = commit ]; then
  tree=$(/usr/bin/git rev-parse --verify 'HEAD^{{tree}}') || exit 86
  parent=$(/usr/bin/git rev-parse --verify HEAD) || exit 87
  next=$(printf 'bounded fixture\n' | /usr/bin/git -c user.name=Fixture -c user.email=fixture@example.invalid commit-tree "$tree" -p "$parent") || exit 88
  /usr/bin/git update-ref HEAD "$next" "$parent" || exit 89
fi
exit 0
"#,
                marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
        let config_path = home.join(".config/dev-auth/config.toml");
        write_workspace_config_with_git(&config_path, &managed, &wrapper);
        let directories = NativeUserDirs {
            home,
            config: config_path,
            runtime: root.path().join("runtime"),
        };
        let hostile_global = root.path().join("hostile-global");
        fs::write(&hostile_global, "[credential]\n\thelper = !exit 99\n").unwrap();
        let environment = BTreeMap::from([
            (
                OsString::from("GIT_CONFIG_GLOBAL"),
                hostile_global.as_os_str().to_os_string(),
            ),
            (
                OsString::from("GIT_ASKPASS"),
                OsString::from("/usr/bin/false"),
            ),
        ]);
        let signing_key = |_paths: &RuntimePaths, _config: &Config, profile: &str| {
            assert_eq!(profile, "automation");
            Ok("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest dev-auth:signing".to_owned())
        };

        let fetch = run_git_at_with_signing_key(
            &directories,
            &repository,
            &environment,
            &[
                OsString::from("fetch"),
                OsString::from("origin"),
                OsString::from("refs/heads/main:refs/remotes/origin/main"),
            ],
            signing_key,
        )
        .unwrap();
        assert!(fetch.success());
        let commit = run_git_at_with_signing_key(
            &directories,
            &repository,
            &environment,
            &[
                OsString::from("commit"),
                OsString::from("--no-status"),
                OsString::from("--message"),
                OsString::from("bounded message"),
            ],
            signing_key,
        )
        .unwrap();
        assert!(commit.success());
        let clone = run_git_at_with_signing_key(
            &directories,
            &managed,
            &environment,
            &[
                OsString::from("clone"),
                OsString::from("--no-checkout"),
                OsString::from("https://github.com/ExampleOrg/repository.git"),
                OsString::from("clone-target"),
            ],
            signing_key,
        )
        .unwrap();
        assert!(clone.success());

        let record = fs::read_to_string(&marker).unwrap();
        assert!(record.contains("verb=fetch capability=credential"));
        assert!(record.contains("verb=commit capability=signing"));
        assert!(record.contains("verb=clone capability=credential"));
        assert!(record.contains("frontend=git-credential-dev-auth"));
        assert!(record.contains("frontend=ssh-keygen-dev-auth"));
        assert!(!record.contains(&hostile_global.display().to_string()));
        assert!(!record.contains("askpass=/usr/bin/false"));
    }

    #[test]
    fn capability_specific_git_configuration_exposes_only_one_authority() {
        let root = tempfile::tempdir().unwrap();
        let paths = RuntimePaths {
            config: root.path().join("config.toml"),
            runtime: root.path().join("runtime"),
        };
        let policy = crate::GitPolicy {
            workspace_roots: vec!["~/repos".into()],
            author_name: "Automation Worker".into(),
            author_email: "automation@example.invalid".into(),
            ssh_profile: "automation".into(),
        };
        for capability in [
            crate::GitCapability::NoAuthority,
            crate::GitCapability::GitHubToken,
            crate::GitCapability::Signing,
        ] {
            let signing_key = (capability == crate::GitCapability::Signing)
                .then_some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest dev-auth:signing");
            let settings = managed_git_configuration_arguments(
                &paths,
                &policy,
                capability,
                "ExampleOrg",
                "repository",
                signing_key,
                root.path(),
            )
            .unwrap()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| pair[1].to_string_lossy().into_owned())
            .collect::<Vec<_>>();
            let credential_entries = settings
                .iter()
                .filter(|value| value.ends_with("helper=dev-auth"))
                .count();
            let signing_entries = settings
                .iter()
                .filter(|value| {
                    value.as_str() == "gpg.ssh.program=ssh-keygen-dev-auth"
                        || value.as_str() == "commit.gpgSign=true"
                        || value.as_str() == "tag.gpgSign=true"
                })
                .count();
            match capability {
                crate::GitCapability::NoAuthority => {
                    assert_eq!((credential_entries, signing_entries), (0, 0));
                }
                crate::GitCapability::GitHubToken => {
                    assert!(credential_entries >= 1);
                    assert_eq!(signing_entries, 0);
                }
                crate::GitCapability::Signing => {
                    assert_eq!(credential_entries, 0);
                    assert_eq!(signing_entries, 3);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capability_specific_git_environment_exposes_only_the_bound_authority() {
        let root = tempfile::tempdir().unwrap();
        let paths = RuntimePaths {
            config: root.path().join("config.toml"),
            runtime: root.path().join("runtime"),
        };
        let policy = crate::GitPolicy {
            workspace_roots: vec!["~/repos".into()],
            author_name: "Automation Worker".into(),
            author_email: "automation@example.invalid".into(),
            ssh_profile: "automation".into(),
        };
        let authority = GitChildAuthorityBinding {
            kind: "repository",
            operation: "fetch".into(),
            digest: "11".repeat(32),
            root: root.path().to_path_buf(),
            ref_selectors: Vec::new(),
            mutable_ref_selectors: BTreeSet::new(),
            reference_values: BTreeMap::new(),
            git_dir: PathBuf::new(),
            common_dir: PathBuf::new(),
            mutable_after_child: BTreeSet::new(),
            _held_paths: Vec::new(),
        };

        let none = isolated_git_environment(
            &BTreeMap::new(),
            &paths,
            root.path(),
            &policy,
            crate::GitCapability::NoAuthority,
            &"00".repeat(32),
            None,
        )
        .unwrap();
        assert_eq!(
            none.get(OsStr::new("DEV_AUTH_GIT_CAPABILITY")),
            Some(&OsString::from("none"))
        );
        for key in [
            "DEV_AUTH_GIT_AUTHORITY_KIND",
            "DEV_AUTH_GIT_AUTHORITY_SHA256",
            "DEV_AUTH_GIT_OPERATION",
            "DEV_AUTH_GIT_REPOSITORY_ROOT",
        ] {
            assert!(!none.contains_key(OsStr::new(key)), "unexpected {key}");
        }

        let credential = isolated_git_environment(
            &BTreeMap::new(),
            &paths,
            root.path(),
            &policy,
            crate::GitCapability::GitHubToken,
            &"00".repeat(32),
            Some(&authority),
        )
        .unwrap();
        assert_eq!(
            credential.get(OsStr::new("DEV_AUTH_GIT_CAPABILITY")),
            Some(&OsString::from("credential"))
        );
        assert_eq!(
            credential.get(OsStr::new("DEV_AUTH_GIT_OPERATION")),
            Some(&OsString::from("fetch"))
        );
        assert_eq!(
            credential.get(OsStr::new("DEV_AUTH_GIT_AUTHORITY_SHA256")),
            Some(&OsString::from("11".repeat(32)))
        );
    }

    #[test]
    fn managed_network_arguments_are_normalized_to_one_exact_https_repository() {
        let expected = OsString::from("https://github.com/ExampleOrg/repository.git");
        for input in [
            vec![
                "fetch",
                "origin",
                "refs/heads/main:refs/remotes/origin/main",
            ],
            vec!["push", "origin", "HEAD:refs/heads/change"],
            vec![
                "clone",
                "--no-checkout",
                "git@github.com:ExampleOrg/repository.git",
                "repository",
            ],
        ] {
            let command = input[0];
            let normalized = normalized_managed_git_arguments(
                &input.into_iter().map(str::to_owned).collect::<Vec<_>>(),
                "ExampleOrg",
                "repository",
            )
            .unwrap();
            assert!(normalized.contains(&expected));
            assert!(!normalized.iter().any(|argument| argument == "origin"));
            assert!(!normalized
                .iter()
                .any(|argument| argument.to_string_lossy().starts_with("git@")));
            if command == "fetch" {
                for required in ["--atomic", "--no-tags", "--no-write-fetch-head"] {
                    assert!(
                        normalized.contains(&OsString::from(required)),
                        "managed fetch omitted {required}"
                    );
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn managed_fetch_is_atomic_tagless_and_does_not_write_fetch_head() {
        let root = tempfile::tempdir().unwrap();
        let remote = root.path().join("remote.git");
        let seed = root.path().join("seed");
        let client = root.path().join("client");
        fs::create_dir(&seed).unwrap();
        fs::create_dir(&client).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--bare", "--quiet"])
            .arg(&remote)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet", "--initial-branch=main"])
            .current_dir(&seed)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--allow-empty",
                "--quiet",
                "--message=initial",
            ])
            .current_dir(&seed)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args(["tag", "auto-followed"])
            .current_dir(&seed)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args(["remote", "add", "origin"])
            .arg(&remote)
            .current_dir(&seed)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args(["push", "--quiet", "origin", "main", "--tags"])
            .current_dir(&seed)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&client)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args(["remote", "add", "origin"])
            .arg(&remote)
            .current_dir(&client)
            .status()
            .unwrap()
            .success());

        let fetch_head = client.join(".git/FETCH_HEAD");
        let sentinel = b"unchanged-fetch-head\n";
        fs::write(&fetch_head, sentinel).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args([
                "fetch",
                "--atomic",
                "--no-tags",
                "--no-write-fetch-head",
                "--quiet",
                "origin",
                "refs/heads/main:refs/remotes/origin/main",
            ])
            .current_dir(&client)
            .status()
            .unwrap()
            .success());
        assert!(!client.join(".git/refs/tags/auto-followed").exists());
        assert_eq!(fs::read(&fetch_head).unwrap(), sentinel);
        let before = Command::new("/usr/bin/git")
            .args(["rev-parse", "--verify", "refs/remotes/origin/main"])
            .current_dir(&client)
            .output()
            .unwrap();
        assert!(before.status.success());

        let failed = Command::new("/usr/bin/git")
            .args([
                "fetch",
                "--atomic",
                "--no-tags",
                "--no-write-fetch-head",
                "--quiet",
                "origin",
                "refs/heads/missing:refs/remotes/origin/main",
            ])
            .current_dir(&client)
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!failed.success());
        let after = Command::new("/usr/bin/git")
            .args(["rev-parse", "--verify", "refs/remotes/origin/main"])
            .current_dir(&client)
            .output()
            .unwrap();
        assert!(after.status.success());
        assert_eq!(after.stdout, before.stdout);
        assert_eq!(fs::read(fetch_head).unwrap(), sentinel);
    }

    #[cfg(unix)]
    #[test]
    fn managed_git_configuration_executes_only_the_private_credential_helper() {
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repository");
        fs::create_dir(&repository).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());

        let human_marker = root.path().join("human-helper-ran");
        let human_helper = root.path().join("human-helper");
        fs::write(
            &human_helper,
            format!(
                "#!/bin/sh\nprintf invoked > '{}'\nprintf 'username=human\\npassword=human-secret\\n'\n",
                human_marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&human_helper, fs::Permissions::from_mode(0o700)).unwrap();
        let human_command = format!("!{}", human_helper.display());
        for key in [
            "credential.helper",
            "credential.https://github.com.helper",
            "credential.https://github.com/ExampleOrg/repository.helper",
            "credential.https://github.com/ExampleOrg/repository.git.helper",
        ] {
            assert!(Command::new("/usr/bin/git")
                .args(["config", "--local", "--add", key, &human_command])
                .current_dir(&repository)
                .status()
                .unwrap()
                .success());
        }

        let paths = RuntimePaths {
            config: root.path().join("config.toml"),
            runtime: root.path().join("runtime"),
        };
        let policy = crate::GitPolicy {
            workspace_roots: vec![root.path().display().to_string()],
            author_name: "Automation Worker".into(),
            author_email: "automation@example.invalid".into(),
            ssh_profile: "automation".into(),
        };
        for directory in [
            paths.git_sandbox_dir(),
            paths.git_child_bin_dir(),
            paths.git_home_dir(),
            paths.git_config_dir(),
            paths.git_cache_dir(),
            paths.git_data_dir(),
            paths.git_temp_dir(),
        ] {
            fs::create_dir_all(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(paths.git_empty_config_file(), "").unwrap();
        fs::write(paths.git_empty_attributes_file(), "").unwrap();

        let private_marker = root.path().join("private-helper-ran");
        let private_helper = paths.git_child_bin_dir().join("git-credential-dev-auth");
        fs::write(
            &private_helper,
            format!(
                "#!/bin/sh\nprintf invoked > '{}'\nprintf 'quit=true\\n'\n",
                private_marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&private_helper, fs::Permissions::from_mode(0o700)).unwrap();
        let reject = paths.git_child_bin_dir().join("false");
        fs::write(&reject, "#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(&reject, fs::Permissions::from_mode(0o700)).unwrap();

        let ambient_global = root.path().join("ambient-global-config");
        let ambient_system = root.path().join("ambient-system-config");
        for config in [&ambient_global, &ambient_system] {
            fs::write(
                config,
                format!("[credential]\n\thelper = {human_command}\n"),
            )
            .unwrap();
        }
        let input = BTreeMap::from([
            (
                OsString::from("GIT_CONFIG_GLOBAL"),
                ambient_global.into_os_string(),
            ),
            (
                OsString::from("GIT_CONFIG_SYSTEM"),
                ambient_system.into_os_string(),
            ),
            (
                OsString::from("PATH"),
                root.path().as_os_str().to_os_string(),
            ),
        ]);
        let environment = isolated_git_environment(
            &input,
            &paths,
            &paths.git_child_bin_dir(),
            &policy,
            crate::GitCapability::GitHubToken,
            "00",
            None,
        )
        .unwrap();
        let hooks = tempfile::tempdir_in(paths.git_temp_dir()).unwrap();
        let mut arguments = managed_git_configuration_arguments(
            &paths,
            &policy,
            crate::GitCapability::GitHubToken,
            "ExampleOrg",
            "repository",
            None,
            hooks.path(),
        )
        .unwrap();
        arguments.extend([OsString::from("credential"), OsString::from("fill")]);
        let mut child = Command::new("/usr/bin/git")
            .args(arguments)
            .current_dir(&repository)
            .env_clear()
            .envs(environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"protocol=https\nhost=github.com\npath=ExampleOrg/repository.git\n\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();

        assert!(!output.status.success());
        assert!(private_marker.exists());
        assert!(!human_marker.exists());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("human-secret"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("human-secret"));
    }

    #[cfg(unix)]
    #[test]
    fn managed_git_child_rejects_a_changed_native_configuration_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let managed = home.join("managed");
        let config_path = home.join(".config/dev-auth/config.toml");
        fs::create_dir_all(&managed).unwrap();
        write_workspace_config(&config_path, &managed);
        let directories = NativeUserDirs {
            home,
            config: config_path.clone(),
            runtime: root.path().join("runtime"),
        };
        let (_, expected) = load_config_snapshot_at(&config_path).unwrap();
        bound_frontend_runtime_and_config(&directories, &expected).unwrap();

        let mut bytes = fs::read(&config_path).unwrap();
        bytes.extend_from_slice(b"\n# changed after parent classification\n");
        fs::write(&config_path, bytes).unwrap();
        assert!(bound_frontend_runtime_and_config(&directories, &expected).is_err());
    }

    #[test]
    fn git_version_parser_requires_reviewed_major_two_behavior() {
        for output in [
            b"git version 2.40.0\n".as_slice(),
            b"git version 2.55.0\n".as_slice(),
            b"git version 2.50.1.windows.1\r\n".as_slice(),
        ] {
            assert!(supported_git_version(output, b""), "{output:?}");
        }
        for output in [
            b"git version 2.39.5\n".as_slice(),
            b"git version 3.0.0\n".as_slice(),
            b"git version 2.55\n".as_slice(),
            b"git version 2.55.0\ntrailing\n".as_slice(),
            b"attacker git version 2.55.0\n".as_slice(),
            b"\xff\n".as_slice(),
        ] {
            assert!(!supported_git_version(output, b""), "{output:?}");
        }
        assert!(!supported_git_version(
            b"git version 2.55.0\n",
            b"warning\n"
        ));
    }
}
