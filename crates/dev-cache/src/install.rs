use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use dev_tools_command::{
    command_candidates as real_command_candidates, executable_candidates, first_executable,
    is_executable_file as executable_file, same_path_location,
};
use serde::{Deserialize, Serialize};

use crate::cargo_intercept;
use crate::config::home_dir;
use crate::entrypoint;
use crate::util::{hash_file, now_unix, write_json_atomic};

#[derive(Clone, Debug, Deserialize, Serialize)]
struct OwnershipRecord {
    schema_version: u32,
    kind: String,
    target: PathBuf,
    digest: String,
    created_unix: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct RustToolOwnershipRecord {
    schema_version: u32,
    package_name: String,
    binary_name: String,
    source_binary: PathBuf,
}

pub fn default_bin_dir() -> PathBuf {
    home_dir().join(".local/bin")
}

#[cfg(windows)]
pub fn default_intercept_dir() -> PathBuf {
    env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join("AppData/Local"))
        .join("dev-cache/intercepts")
}

pub fn intercept_target(intercept_dir: &Path, command: &str) -> PathBuf {
    intercept_dir.join(command_name(command))
}

#[cfg(not(windows))]
pub fn default_intercept_dir() -> PathBuf {
    env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".local/share"))
        .join("dev-cache/intercepts")
}

#[derive(Clone, Debug, Serialize)]
pub struct ActivationResult {
    pub target: PathBuf,
    pub rustup_target: PathBuf,
    pub targets: Vec<PathBuf>,
    pub changed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActivationAudit {
    pub intercept_directory: PathBuf,
    pub path_state: String,
    pub path_occurrences: usize,
    pub persistent_activation_files: Vec<PathBuf>,
    pub entrypoints: Vec<EntrypointAudit>,
    pub unmanaged_by_design: Vec<UnmanagedEntrypointAudit>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EntrypointAudit {
    pub command: String,
    pub adapters: Vec<String>,
    pub state: String,
    pub classifications: Vec<String>,
    pub mandatory: bool,
    pub ok: bool,
    pub installed: bool,
    pub intercept: PathBuf,
    pub owned: bool,
    pub intercept_digest: Option<String>,
    pub effective_executable: Option<PathBuf>,
    pub effective_is_intercept: bool,
    pub real_executable: Option<PathBuf>,
    pub resolved_real_executable: Option<PathBuf>,
    pub recursive: bool,
    pub stale_intercepts: Vec<PathBuf>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UnmanagedEntrypointAudit {
    pub command: String,
    pub state: String,
    pub effective_executable: PathBuf,
    pub reason: String,
}

impl ActivationAudit {
    pub fn healthy(&self) -> bool {
        self.path_state == "active"
            && self
                .entrypoints
                .iter()
                .all(|entry| !entry.mandatory || entry.ok)
    }

    pub fn adapter_routed(&self, adapter: &str) -> bool {
        let relevant: Vec<&EntrypointAudit> = self
            .entrypoints
            .iter()
            .filter(|entry| entry.adapters.iter().any(|candidate| candidate == adapter))
            .filter(|entry| entry.installed)
            .collect();
        !relevant.is_empty()
            && relevant
                .iter()
                .all(|entry| entry.state == "routed" && entry.ok)
    }
}

pub fn activation_audit(intercept_dir: &Path) -> ActivationAudit {
    let path_entries: Vec<PathBuf> = env::var_os("PATH")
        .map(|path| env::split_paths(&path).collect())
        .unwrap_or_default();
    let canonical_intercept = fs::canonicalize(intercept_dir).ok();
    let path_occurrences = path_entries
        .iter()
        .filter(|entry| {
            fs::canonicalize(entry).ok() == canonical_intercept
                || (canonical_intercept.is_none() && *entry == intercept_dir)
        })
        .count();
    let first_is_intercept = path_entries.first().is_some_and(|entry| {
        fs::canonicalize(entry).ok() == canonical_intercept
            || (canonical_intercept.is_none() && entry == intercept_dir)
    });
    let persistent_activation_files = persistent_activation_files(intercept_dir);
    let path_state = if path_occurrences > 1 {
        "duplicate_intercept_path"
    } else if first_is_intercept {
        "active"
    } else if path_occurrences == 1 {
        "intercept_not_first"
    } else if persistent_activation_files.is_empty() {
        "persistent_configuration_missing"
    } else {
        "stale_current_shell"
    }
    .to_owned();

    let mut commands: Vec<String> = entrypoint::STATIC_ENTRYPOINTS
        .iter()
        .map(|spec| spec.command.to_owned())
        .collect();
    commands.extend(discovered_versioned_commands(intercept_dir));
    commands.sort();
    commands.dedup();
    let entrypoints = commands
        .into_iter()
        .map(|command| audit_entrypoint(&command, intercept_dir, &path_entries, &path_state))
        .collect();
    let unmanaged_by_design = entrypoint::UNMANAGED_BY_DESIGN
        .iter()
        .filter_map(|command| {
            first_executable(&path_entries, command).map(|effective_executable| {
                UnmanagedEntrypointAudit {
                    command: (*command).to_owned(),
                    state: "unmanaged_by_design".to_owned(),
                    effective_executable,
                    reason:
                        "Dev Cache has no supported disposable-cache routing contract for this tool"
                            .to_owned(),
                }
            })
        })
        .collect();
    ActivationAudit {
        intercept_directory: intercept_dir.to_path_buf(),
        path_state,
        path_occurrences,
        persistent_activation_files,
        entrypoints,
        unmanaged_by_design,
    }
}

fn audit_entrypoint(
    command: &str,
    intercept_dir: &Path,
    path_entries: &[PathBuf],
    path_state: &str,
) -> EntrypointAudit {
    let intercept = intercept_dir.join(command_name(command));
    let owned = intercept.is_file() && owned_target(&intercept).unwrap_or(false);
    let effective_executable = first_executable(path_entries, command);
    let effective_is_intercept = effective_executable
        .as_ref()
        .is_some_and(|candidate| same_path_location(candidate, &intercept));
    let intercept_digest = intercept
        .is_file()
        .then(|| hash_file(&intercept).ok().map(|value| value.0))
        .flatten();
    let mut stale_intercepts = Vec::new();
    let mut real_executable = None;
    for candidate in executable_candidates(path_entries, command) {
        if same_path_location(&candidate, &intercept) {
            continue;
        }
        let looks_like_intercept = ownership_path(&candidate).is_file()
            || intercept_digest.as_ref().is_some_and(|digest| {
                hash_file(&candidate)
                    .ok()
                    .is_some_and(|value| &value.0 == digest)
            });
        if looks_like_intercept {
            stale_intercepts.push(candidate);
        } else if real_executable.is_none() {
            real_executable = Some(candidate);
        }
    }
    stale_intercepts.sort();
    stale_intercepts.dedup();
    let installed = real_executable.is_some();
    let resolved_real_executable = if intercept.is_file() {
        cargo_intercept::resolve_real_command(command, &intercept).ok()
    } else {
        None
    };
    let recursive = resolved_real_executable.as_ref().is_some_and(|resolved| {
        same_path_location(resolved, &intercept)
            || stale_intercepts
                .iter()
                .any(|candidate| same_path_location(candidate, resolved))
    }) || (intercept.is_file() && installed && resolved_real_executable.is_none());

    let (state, detail) = if !installed && intercept.is_file() {
        (
            "stale_intercept",
            Some("an intercept exists but no real executable is available".to_owned()),
        )
    } else if !installed {
        ("absent", None)
    } else if !intercept.is_file() {
        (
            "not_activated",
            Some("the installed command has no canonical Dev Cache intercept".to_owned()),
        )
    } else if !owned {
        (
            "unowned_intercept",
            Some("the canonical intercept has no valid ownership record".to_owned()),
        )
    } else if path_state == "duplicate_intercept_path" {
        (
            "duplicate_intercept_path",
            Some("the canonical intercept directory occurs more than once in PATH".to_owned()),
        )
    } else if !stale_intercepts.is_empty() {
        (
            "stale_intercept_precedence",
            Some("another Dev Cache intercept is present in PATH".to_owned()),
        )
    } else if !effective_is_intercept {
        (
            "shadowed",
            Some("another executable takes precedence over the canonical intercept".to_owned()),
        )
    } else if recursive {
        (
            "recursive",
            Some("intercept resolution reaches another Dev Cache intercept".to_owned()),
        )
    } else if resolved_real_executable.is_none() {
        (
            "unresolved",
            Some("the intercept cannot resolve a real executable without recursion".to_owned()),
        )
    } else {
        ("routed", None)
    };
    let ok = state == "routed" || state == "absent";
    EntrypointAudit {
        command: command.to_owned(),
        adapters: entrypoint::spec_for(command)
            .map(|spec| spec.adapters)
            .unwrap_or_default()
            .iter()
            .map(|adapter| format!("{adapter:?}").to_lowercase())
            .collect(),
        state: state.to_owned(),
        classifications: Vec::new(),
        mandatory: installed || intercept.is_file() || !stale_intercepts.is_empty(),
        ok,
        installed,
        intercept,
        owned,
        intercept_digest,
        effective_executable,
        effective_is_intercept,
        real_executable,
        resolved_real_executable,
        recursive,
        stale_intercepts,
        detail,
    }
}

fn discovered_versioned_commands(intercept_dir: &Path) -> Vec<String> {
    let mut commands = Vec::new();
    let Some(path) = env::var_os("PATH") else {
        return commands;
    };
    for directory in env::split_paths(&path) {
        if fs::canonicalize(&directory).ok() == fs::canonicalize(intercept_dir).ok() {
            continue;
        }
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            if !executable_file(&entry.path()) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_lowercase();
            let stem = name.strip_suffix(".exe").unwrap_or(&name);
            if entrypoint::is_versioned_command(stem, "pip")
                || entrypoint::is_versioned_command(stem, "python")
            {
                commands.push(stem.to_owned());
            }
        }
    }
    commands
}

fn persistent_activation_files(intercept_dir: &Path) -> Vec<PathBuf> {
    let home = home_dir();
    let mut candidates = vec![
        home.join(".profile"),
        home.join(".bash_profile"),
        home.join(".bash_login"),
        home.join(".bashrc"),
        home.join(".zprofile"),
        home.join(".zshenv"),
        home.join(".zshrc"),
        home.join(".config/fish/config.fish"),
        home.join("Documents/PowerShell/Microsoft.PowerShell_profile.ps1"),
        home.join("Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1"),
    ];
    candidates.sort();
    candidates.dedup();
    let exact = intercept_dir.to_string_lossy();
    candidates
        .into_iter()
        .filter(|path| {
            fs::metadata(path).is_ok_and(|metadata| metadata.len() <= 1024 * 1024)
                && fs::read_to_string(path).is_ok_and(|content| {
                    content.contains(exact.as_ref()) || content.contains("dev-cache/intercepts")
                })
        })
        .collect()
}

pub fn install(bin_dir: &Path) -> Result<PathBuf> {
    let source = env::current_exe()
        .context("resolve current dev-cache executable")?
        .canonicalize()?;
    fs::create_dir_all(bin_dir)?;
    let target = bin_dir.join(if cfg!(windows) {
        "dev-cache.exe"
    } else {
        "dev-cache"
    });
    if target.exists() {
        let (source_digest, _) = hash_file(&source)?;
        let (target_digest, _) = hash_file(&target)?;
        if source_digest == target_digest
            && (self_owned_install(&target)?
                || self_install_marker_claims_target(&target)?
                || rust_tool_owned_install(&target)?)
        {
            if !self_owned_install(&target)? {
                write_install_ownership(&target, target_digest)?;
            }
            let external_marker = rust_tool_ownership_path(&target);
            if external_marker.exists() {
                fs::remove_file(external_marker)?;
            }
            return Ok(target);
        }
        if !owned_install(&target)? {
            bail!(
                "refusing to overwrite unowned dev-cache binary: {}",
                target.display()
            );
        }
    }
    copy_atomically(&source, &target)?;
    let external_marker = rust_tool_ownership_path(&target);
    if external_marker.exists() {
        fs::remove_file(&external_marker)?;
    }
    let (digest, _) = hash_file(&target)?;
    write_install_ownership(&target, digest)?;
    Ok(target)
}

fn write_install_ownership(target: &Path, digest: String) -> Result<()> {
    write_json_atomic(
        &target.with_extension("dev-cache-owned.json"),
        &OwnershipRecord {
            schema_version: 1,
            kind: "install".to_owned(),
            target: target.to_path_buf(),
            digest,
            created_unix: now_unix(),
        },
    )
}

pub fn activate(bin_dir: &Path, intercept_dir: &Path) -> Result<ActivationResult> {
    let installed = bin_dir.join(if cfg!(windows) {
        "dev-cache.exe"
    } else {
        "dev-cache"
    });
    if !installed.is_file() {
        bail!(
            "dev-cache is not installed at {}; run dev-cache install",
            installed.display()
        );
    }
    fs::create_dir_all(intercept_dir)?;
    let target = intercept_dir.join(command_name("cargo"));
    let rustup_target = intercept_dir.join(command_name("rustup"));
    let commands = installed_intercept_commands(intercept_dir);
    let targets: Vec<PathBuf> = commands
        .iter()
        .map(|command| intercept_dir.join(command_name(command)))
        .collect();
    let previously_owned = owned_intercept_targets(intercept_dir)?;
    for candidate in targets.iter().chain(previously_owned.iter()) {
        if candidate.exists()
            && !owned_target(candidate)?
            && !repairable_owned_intercept(&installed, candidate)?
        {
            bail!(
                "refusing to overwrite unknown command intercept: {}",
                candidate.display()
            );
        }
    }
    let mut changed = false;
    for stale in previously_owned
        .iter()
        .filter(|candidate| !targets.contains(candidate))
    {
        if stale.exists() {
            fs::remove_file(stale)?;
        }
        for marker in ownership_paths(stale) {
            if marker.exists() {
                fs::remove_file(marker)?;
            }
        }
        changed = true;
    }
    for candidate in &targets {
        changed |= activate_alias(&installed, candidate)?;
    }
    Ok(ActivationResult {
        target,
        rustup_target,
        targets,
        changed,
    })
}

pub fn deactivate(intercept_dir: &Path) -> Result<bool> {
    for spec in entrypoint::STATIC_ENTRYPOINTS {
        let target = intercept_dir.join(command_name(spec.command));
        if target.exists() && !owned_target(&target)? {
            bail!(
                "refusing to remove unknown command intercept: {}",
                target.display()
            );
        }
    }
    let targets = owned_intercept_targets(intercept_dir)?;
    for target in &targets {
        if target.exists() && !owned_target(target)? {
            bail!(
                "refusing to remove unknown command intercept: {}",
                target.display()
            );
        }
    }
    let mut changed = false;
    for target in &targets {
        if !target.exists() {
            continue;
        }
        fs::remove_file(target)?;
        for marker in ownership_paths(target) {
            if marker.exists() {
                fs::remove_file(marker)?;
            }
        }
        changed = true;
    }
    Ok(changed)
}

pub fn uninstall(bin_dir: &Path, intercept_dir: &Path) -> Result<bool> {
    let _ = deactivate(intercept_dir)?;
    let mut changed = false;
    let target = bin_dir.join(command_name("dev-cache"));
    if target.exists() {
        if !owned_install(&target)? {
            bail!("refusing to remove unowned command: {}", target.display());
        }
        fs::remove_file(&target)?;
        for marker in [
            target.with_extension("dev-cache-owned.json"),
            rust_tool_ownership_path(&target),
        ] {
            if marker.exists() {
                fs::remove_file(marker)?;
            }
        }
        changed = true;
    }
    Ok(changed)
}

pub fn intercept_is_first_on_path(intercept_dir: &Path) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path)
        .next()
        .is_some_and(|first| fs::canonicalize(first).ok() == fs::canonicalize(intercept_dir).ok())
}

fn installed_intercept_commands(intercept_dir: &Path) -> Vec<String> {
    let mut commands: Vec<String> = entrypoint::STATIC_ENTRYPOINTS
        .iter()
        .filter(|spec| {
            real_command_exists(spec.command, intercept_dir)
                && spec
                    .requires_command
                    .is_none_or(|command| real_command_exists(command, intercept_dir))
        })
        .map(|spec| spec.command.to_owned())
        .collect();
    commands.extend(discovered_versioned_commands(intercept_dir));
    commands.sort();
    commands.dedup();
    commands
}

fn real_command_exists(command: &str, intercept_dir: &Path) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|directory| {
        fs::canonicalize(&directory).ok() != fs::canonicalize(intercept_dir).ok()
            && real_command_candidates(&directory, command)
                .into_iter()
                .any(|candidate| executable_file(&candidate))
    })
}

fn owned_intercept_targets(intercept_dir: &Path) -> Result<Vec<PathBuf>> {
    if !intercept_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut targets = Vec::new();
    for entry in fs::read_dir(intercept_dir)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !name.ends_with(".dev-cache-intercept.json") {
            continue;
        }
        let record: OwnershipRecord = serde_json::from_slice(&fs::read(&path)?)?;
        if record.target.parent() == Some(intercept_dir) {
            targets.push(record.target);
        }
    }
    targets.sort();
    targets.dedup();
    Ok(targets)
}

fn owned_target(target: &Path) -> Result<bool> {
    for marker in ownership_paths(target) {
        if !marker.is_file() {
            continue;
        }
        let record: OwnershipRecord = serde_json::from_slice(&fs::read(marker)?)?;
        let (digest, _) = hash_file(target)?;
        if record.kind == intercept_kind(target)
            && record.target == target
            && record.digest == digest
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn repairable_owned_intercept(installed: &Path, target: &Path) -> Result<bool> {
    let marker = ownership_path(target);
    if !marker.is_file() {
        return Ok(false);
    }
    let record: OwnershipRecord = serde_json::from_slice(&fs::read(marker)?)?;
    if record.schema_version != 1
        || record.kind != intercept_kind(target)
        || record.target != target
    {
        return Ok(false);
    }
    let (installed_digest, installed_size) = hash_file(installed)?;
    let (target_digest, target_size) = hash_file(target)?;
    Ok(installed_digest == target_digest && installed_size == target_size)
}

fn activate_alias(installed: &Path, target: &Path) -> Result<bool> {
    if target.exists() {
        let (installed_digest, _) = hash_file(installed)?;
        let (target_digest, _) = hash_file(target)?;
        if installed_digest == target_digest {
            let canonical = ownership_path(target);
            if canonical.is_file() && owned_target(target)? {
                return Ok(false);
            }
            write_intercept_ownership(target, target_digest)?;
            return Ok(true);
        }
        fs::remove_file(target)?;
        for marker in ownership_paths(target) {
            if marker.exists() {
                fs::remove_file(marker)?;
            }
        }
    }
    if fs::hard_link(installed, target).is_err() {
        copy_atomically(installed, target)?;
    }
    let (digest, _) = hash_file(target)?;
    write_intercept_ownership(target, digest)?;
    Ok(true)
}

fn write_intercept_ownership(target: &Path, digest: String) -> Result<()> {
    write_json_atomic(
        &ownership_path(target),
        &OwnershipRecord {
            schema_version: 1,
            kind: intercept_kind(target),
            target: target.to_path_buf(),
            digest,
            created_unix: now_unix(),
        },
    )
}

fn command_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_owned()
    }
}

fn intercept_kind(target: &Path) -> String {
    let stem = target
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("command");
    format!("{stem}-intercept")
}

fn owned_install(target: &Path) -> Result<bool> {
    Ok(self_owned_install(target)? || rust_tool_owned_install(target)?)
}

fn self_owned_install(target: &Path) -> Result<bool> {
    for marker in [target.with_extension("dev-cache-owned.json")] {
        if !marker.is_file() {
            continue;
        }
        let record: OwnershipRecord = serde_json::from_slice(&fs::read(marker)?)?;
        let (digest, _) = hash_file(target)?;
        if record.kind == "install" && record.target == target && record.digest == digest {
            return Ok(true);
        }
    }
    Ok(false)
}

fn self_install_marker_claims_target(target: &Path) -> Result<bool> {
    let marker = target.with_extension("dev-cache-owned.json");
    if !marker.is_file() {
        return Ok(false);
    }
    let record: OwnershipRecord = serde_json::from_slice(&fs::read(marker)?)?;
    Ok(record.schema_version == 1 && record.kind == "install" && record.target == target)
}

fn rust_tool_owned_install(target: &Path) -> Result<bool> {
    let marker = rust_tool_ownership_path(target);
    if !marker.is_file() {
        return Ok(false);
    }
    let record: RustToolOwnershipRecord = serde_json::from_slice(&fs::read(marker)?)?;
    let expected_binary_name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    if record.schema_version != 1
        || record.package_name != "dev-cache"
        || record.binary_name != expected_binary_name
        || !record.source_binary.is_file()
    {
        return Ok(false);
    }
    let (target_digest, _) = hash_file(target)?;
    let (source_digest, _) = hash_file(&record.source_binary)?;
    Ok(target_digest == source_digest)
}

fn rust_tool_ownership_path(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "dev-cache".to_owned());
    target.with_file_name(format!(".{name}.rust-tool.json"))
}

fn ownership_path(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "command".to_owned());
    target.with_file_name(format!("{name}.dev-cache-intercept.json"))
}

fn ownership_paths(target: &Path) -> [PathBuf; 1] {
    [ownership_path(target)]
}

fn copy_atomically(source: &Path, target: &Path) -> Result<()> {
    let temporary = target.with_extension(format!("dev-cache-partial-{}", std::process::id()));
    fs::copy(source, &temporary)
        .with_context(|| format!("copy {} to {}", source.display(), temporary.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&temporary)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&temporary, permissions)?;
    }
    if target.exists() {
        let backup = target.with_extension(format!("dev-cache-backup-{}", std::process::id()));
        fs::rename(target, &backup)?;
        if let Err(error) = fs::rename(&temporary, target) {
            let _ = fs::rename(&backup, target);
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        fs::remove_file(backup)?;
    } else {
        fs::rename(temporary, target)?;
    }
    Ok(())
}
