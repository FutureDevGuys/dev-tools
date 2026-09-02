use crate::SshKeyPurpose;
use crate::{
    parse_config, render_git_credential, sanitize_environment, CacheEntry, Config,
    CredentialRequest, CredentialStore, ExecProfile, SecretString, SelectedRepository, SshProfile,
};
use anyhow::{bail, Context, Result};
use directories::{BaseDirs, ProjectDirs};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use fs2::FileExt;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signature::Signer;
use ssh_agent_lib::agent::{listen, Session};
#[cfg(windows)]
use ssh_agent_lib::agent::{Agent, ListeningSocket};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, PublicCredential, SignRequest};
use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::{Algorithm as SshAlgorithm, HashAlg, PrivateKey, PublicKey, Signature};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, Read};
#[cfg(windows)]
use std::io::{Seek, SeekFrom};
use std::ops::{Deref, DerefMut};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeServer;
#[cfg(unix)]
use tokio::net::UnixListener;

#[cfg(windows)]
#[path = "windows_security.rs"]
mod windows_security;

#[path = "git_runtime.rs"]
mod git_runtime;

use git_runtime::{
    frontend_runtime_and_config, validate_bound_git_credential_authority,
    validate_bound_git_signing_authority, validate_git_version,
};
pub use git_runtime::{run_git, workspace_status};

const CONFIG_LIMIT: u64 = 1024 * 1024;
const RESPONSE_LIMIT: u64 = 64 * 1024;
// Reviewed against github/cli tag v2.98.0 at
// a255baf71d13fe5947a4eb7ad521ffd412d64cee.
const SUPPORTED_GH_VERSION: &str = "2.98.0";
const SUPPORTED_GH_VERSION_OUTPUT: &str =
    "gh version 2.98.0 (2026-08-21)\nhttps://github.com/cli/cli/releases/tag/v2.98.0\n";
#[cfg(windows)]
const GH_CHILD_FRONTENDS: [&str; 3] = ["git.exe", "cat.exe", "false.exe"];
#[cfg(not(windows))]
const GH_CHILD_FRONTENDS: [&str; 3] = ["git", "cat", "false"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStatus {
    pub config_ready: bool,
    pub service_token_enrolled: bool,
    pub runtime_ready: bool,
    pub ssh_agent_ready: bool,
    pub cached_installation_tokens: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub online: bool,
    pub declared_exec_profiles: usize,
    pub declared_ssh_profiles: usize,
    pub declared_secret_references: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceContext {
    Managed,
    Unmanaged,
}

#[derive(Debug)]
struct RuntimePaths {
    config: PathBuf,
    runtime: PathBuf,
}

impl RuntimePaths {
    fn discover() -> Result<Self> {
        let config = discover_config_path()?;
        let project = ProjectDirs::from("", "", "dev-auth")
            .context("the operating system has no user configuration directory")?;
        let base = BaseDirs::new().context("the operating system has no user home directory")?;
        let login_runtime = secure_login_runtime_dir();
        let runtime_root = select_runtime_root(
            base.runtime_dir(),
            login_runtime.as_deref(),
            project.cache_dir(),
        );
        Ok(Self {
            config,
            runtime: runtime_root,
        })
    }

    fn cache_dir(&self) -> PathBuf {
        self.runtime.join("github-installation-tokens")
    }

    fn gh_sandbox_dir(&self) -> PathBuf {
        self.runtime.join("gh-sandbox")
    }

    fn gh_child_bin_dir(&self) -> PathBuf {
        self.gh_sandbox_dir().join("bin")
    }

    fn gh_config_dir(&self) -> PathBuf {
        self.gh_sandbox_dir().join("config")
    }

    fn gh_home_dir(&self) -> PathBuf {
        self.gh_sandbox_dir().join("home")
    }

    fn gh_cache_dir(&self) -> PathBuf {
        self.gh_sandbox_dir().join("cache")
    }

    fn gh_data_dir(&self) -> PathBuf {
        self.gh_sandbox_dir().join("data")
    }

    fn gh_temp_dir(&self) -> PathBuf {
        self.gh_sandbox_dir().join("tmp")
    }

    fn gh_git_config_file(&self) -> PathBuf {
        self.gh_sandbox_dir().join("git-empty-config")
    }

    fn gh_git_attributes_file(&self) -> PathBuf {
        self.gh_sandbox_dir().join("git-empty-attributes")
    }

    fn gh_git_hooks_dir(&self) -> PathBuf {
        self.gh_sandbox_dir().join("git-empty-hooks")
    }

    fn exec_sandbox_dir(&self) -> PathBuf {
        self.runtime.join("exec-sandbox")
    }

    fn exec_profile_dir(&self, profile_name: &str) -> PathBuf {
        self.exec_sandbox_dir().join(profile_name)
    }

    fn exec_bin_dir(&self, profile_name: &str) -> PathBuf {
        self.exec_profile_dir(profile_name).join("bin")
    }

    fn exec_config_dir(&self, profile_name: &str) -> PathBuf {
        self.exec_profile_dir(profile_name).join("config")
    }

    fn exec_home_dir(&self, profile_name: &str) -> PathBuf {
        self.exec_profile_dir(profile_name).join("home")
    }

    fn exec_cache_dir(&self, profile_name: &str) -> PathBuf {
        self.exec_profile_dir(profile_name).join("cache")
    }

    fn exec_data_dir(&self, profile_name: &str) -> PathBuf {
        self.exec_profile_dir(profile_name).join("data")
    }

    fn exec_temp_dir(&self, profile_name: &str) -> PathBuf {
        self.exec_profile_dir(profile_name).join("tmp")
    }

    fn exec_runtime_dir(&self, profile_name: &str) -> PathBuf {
        self.exec_profile_dir(profile_name).join("runtime")
    }
}

fn discover_config_path() -> Result<PathBuf> {
    let project = ProjectDirs::from("", "", "dev-auth")
        .context("the operating system has no user configuration directory")?;
    Ok(project.config_dir().join("config.toml"))
}

fn select_runtime_root(
    environment_runtime: Option<&Path>,
    login_runtime: Option<&Path>,
    cache: &Path,
) -> PathBuf {
    environment_runtime
        .or(login_runtime)
        .map(|path| path.join("dev-auth"))
        .unwrap_or_else(|| cache.join("runtime"))
}

#[cfg(target_os = "linux")]
fn secure_login_runtime_dir() -> Option<PathBuf> {
    let path = PathBuf::from("/run/user").join(rustix::process::geteuid().as_raw().to_string());
    let metadata = fs::symlink_metadata(&path).ok()?;
    if metadata.file_type().is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.permissions().mode() & 0o077 == 0
    {
        Some(path)
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
fn secure_login_runtime_dir() -> Option<PathBuf> {
    None
}

fn load_config(paths: &RuntimePaths) -> Result<Config> {
    load_config_at(&paths.config)
}

fn load_config_at(path: &Path) -> Result<Config> {
    load_config_snapshot_at(path).map(|(config, _)| config)
}

fn load_config_snapshot_at(path: &Path) -> Result<(Config, String)> {
    let parent = path
        .parent()
        .context("dev-auth configuration has no parent directory")?;
    validate_private_directory(parent, "dev-auth configuration directory")?;
    let file = private_read(path, "dev-auth configuration")?;
    let mut bytes = Vec::new();
    file.take(CONFIG_LIMIT + 1)
        .read_to_end(&mut bytes)
        .context("read configuration")?;
    if bytes.len() as u64 > CONFIG_LIMIT {
        bail!("configuration exceeds the size limit");
    }
    let config = parse_config(&bytes)?;
    #[cfg(windows)]
    validate_configured_windows_programs(&config)?;
    let digest = Sha256::digest(&bytes);
    let digest = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok((config, digest))
}

#[cfg(windows)]
fn validate_configured_windows_programs(config: &Config) -> Result<()> {
    for (description, program) in [
        ("1Password CLI", &config.programs.op),
        ("GitHub CLI", &config.programs.gh),
        ("Git", &config.programs.git),
        ("ssh-add", &config.programs.ssh_add),
        ("ssh-keygen", &config.programs.ssh_keygen),
    ] {
        windows_security::validate_local_program(Path::new(program))
            .with_context(|| format!("validate configured {description} program at {program}"))?;
    }
    for (profile_name, profile) in &config.profiles {
        for executable in &profile.executables {
            windows_security::validate_local_program(Path::new(executable)).with_context(|| {
                format!("validate executable for profile {profile_name} at {executable}")
            })?;
        }
    }
    Ok(())
}

#[cfg(windows)]
type ProgramGuard = windows_security::ProgramGuard;
#[cfg(target_os = "linux")]
struct ProgramGuard {
    executable: OwnedFd,
    execution_path: PathBuf,
    _ancestor_directories: Vec<OwnedFd>,
    _proc_fd_directory: OwnedFd,
}

#[cfg(all(not(windows), not(target_os = "linux")))]
struct ProgramGuard;

struct GuardedCommand<'a> {
    command: Command,
    _guard: &'a ProgramGuard,
}

impl Deref for GuardedCommand<'_> {
    type Target = Command;

    fn deref(&self) -> &Self::Target {
        &self.command
    }
}

impl DerefMut for GuardedCommand<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.command
    }
}

#[cfg(windows)]
fn program_guard(program: &str, description: &str) -> Result<ProgramGuard> {
    windows_security::lock_local_program(Path::new(program))
        .with_context(|| format!("lock configured {description} program at {program}"))
}

#[cfg(target_os = "linux")]
fn program_guard(program: &str, description: &str) -> Result<ProgramGuard> {
    crate::validate_program(program, description)?;
    lock_linux_program(Path::new(program), description)
        .with_context(|| format!("lock configured {description} program at {program}"))
}

#[cfg(all(not(windows), not(target_os = "linux")))]
fn program_guard(program: &str, description: &str) -> Result<ProgramGuard> {
    crate::validate_program(program, description)?;
    bail!("configured program identity locking is not supported on this operating system")
}

#[cfg(windows)]
fn guarded_command<'a>(program: &str, guard: &'a ProgramGuard) -> Result<GuardedCommand<'a>> {
    Ok(GuardedCommand {
        command: Command::new(program),
        _guard: guard,
    })
}

#[cfg(target_os = "linux")]
fn guarded_command<'a>(program: &str, guard: &'a ProgramGuard) -> Result<GuardedCommand<'a>> {
    let descriptor = guard.executable.as_raw_fd();
    let mut command = Command::new(&guard.execution_path);
    command.arg0(program);
    // SAFETY: GuardedCommand borrows ProgramGuard, so the descriptor remains open
    // through spawn and child completion. After fork the child owns the same file
    // table entry. Clearing only FD_CLOEXEC with fcntl is async-signal-safe and lets
    // an interpreter reopen /proc/self/fd/N without a pathname lookup of the source.
    unsafe {
        command.pre_exec(move || {
            // SAFETY: the ProgramGuard borrow described above keeps this exact raw
            // descriptor valid until Command has completed its pre-exec callback.
            let descriptor = BorrowedFd::borrow_raw(descriptor);
            rustix::io::fcntl_setfd(descriptor, rustix::io::FdFlags::empty())
                .map_err(io::Error::from)
        });
    }
    Ok(GuardedCommand {
        command,
        _guard: guard,
    })
}

#[cfg(all(not(windows), not(target_os = "linux")))]
fn guarded_command<'a>(_program: &str, _guard: &'a ProgramGuard) -> Result<GuardedCommand<'a>> {
    bail!("configured program identity execution is not supported on this operating system")
}

#[cfg(target_os = "linux")]
struct LinuxProgramIdentity {
    effective_user: u32,
    effective_groups: BTreeSet<u32>,
}

#[cfg(target_os = "linux")]
impl LinuxProgramIdentity {
    fn current() -> Result<Self> {
        let mut effective_groups: BTreeSet<u32> = nix::unistd::getgroups()
            .context("read effective user's supplementary groups")?
            .into_iter()
            .map(|group| group.as_raw())
            .collect();
        effective_groups.insert(nix::unistd::getegid().as_raw());
        Ok(Self {
            effective_user: rustix::process::geteuid().as_raw(),
            effective_groups,
        })
    }

    fn can_execute(&self, owner: u32, group: u32, mode: u32) -> bool {
        if self.effective_user == 0 {
            return mode & 0o111 != 0;
        }
        if owner == self.effective_user {
            mode & 0o100 != 0
        } else if self.effective_groups.contains(&group) {
            mode & 0o010 != 0
        } else {
            mode & 0o001 != 0
        }
    }
}

#[cfg(target_os = "linux")]
fn validate_linux_program_component(
    metadata: &rustix::fs::Stat,
    expected_type: rustix::fs::FileType,
    identity: &LinuxProgramIdentity,
    description: &str,
) -> Result<()> {
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != expected_type {
        bail!("{description} has an unsafe filesystem object type");
    }
    if metadata.st_uid != 0 && metadata.st_uid != identity.effective_user {
        bail!("{description} is not owned by root or the effective user");
    }
    if metadata.st_mode & 0o022 != 0 {
        bail!("{description} is writable by group or other users");
    }
    if !identity.can_execute(metadata.st_uid, metadata.st_gid, metadata.st_mode) {
        bail!("{description} is not executable by the effective user");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_program_filesystem_is_local(filesystem_type: u64) -> bool {
    // Fail closed for known network, host-shared, and userspace-projected filesystems.
    // Native Linux/WSL filesystems and container overlay filesystems remain admissible.
    !matches!(
        filesystem_type,
        0x0000_6969 // NFS
            | 0xff53_4d42 // CIFS
            | 0x0000_517b // SMB
            | 0x0102_1997 // 9P / WSL host mounts
            | 0x7375_7245 // CODA
            | 0x5346_414f // AFS
            | 0x00c3_6400 // Ceph
            | 0x0000_564c // NCP
            | 0x6573_5546 // FUSE
            | 0x786f_4256 // VirtualBox shared folders
            | 0xbacb_acbc // VMware shared folders
    )
}

#[cfg(target_os = "linux")]
fn lock_linux_program(path: &Path, description: &str) -> Result<ProgramGuard> {
    let identity = LinuxProgramIdentity::current()?;
    let mut components = path.components();
    if components.next() != Some(std::path::Component::RootDir) {
        bail!("{description} must use an absolute native Linux path");
    }
    let names: Vec<OsString> = components
        .map(|component| match component {
            std::path::Component::Normal(name) => Ok(name.to_os_string()),
            _ => bail!("{description} path contains a non-canonical component"),
        })
        .collect::<Result<_>>()?;
    let (file_name, directory_names) = names
        .split_last()
        .context("configured program path has no executable name")?;

    let directory_flags = rustix::fs::OFlags::PATH
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    let root = rustix::fs::open("/", directory_flags, rustix::fs::Mode::empty())
        .context("open configured program filesystem root without following links")?;
    validate_linux_program_component(
        &rustix::fs::fstat(&root).context("inspect configured program filesystem root")?,
        rustix::fs::FileType::Directory,
        &identity,
        "configured program filesystem root",
    )?;
    let mut ancestor_directories = vec![root];
    for name in directory_names {
        let directory = rustix::fs::openat(
            ancestor_directories
                .last()
                .context("configured program ancestor chain is empty")?,
            name,
            directory_flags,
            rustix::fs::Mode::empty(),
        )
        .with_context(|| format!("open {description} ancestor without following links"))?;
        validate_linux_program_component(
            &rustix::fs::fstat(&directory)
                .with_context(|| format!("inspect {description} ancestor"))?,
            rustix::fs::FileType::Directory,
            &identity,
            "configured program ancestor",
        )?;
        ancestor_directories.push(directory);
    }

    let executable = rustix::fs::openat(
        ancestor_directories
            .last()
            .context("configured program ancestor chain is empty")?,
        file_name,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("open configured {description} executable without following links"))?;
    let executable_metadata = rustix::fs::fstat(&executable)
        .with_context(|| format!("inspect configured {description}"))?;
    validate_linux_program_component(
        &executable_metadata,
        rustix::fs::FileType::RegularFile,
        &identity,
        "configured program executable",
    )?;
    let filesystem = rustix::fs::fstatfs(&executable)
        .with_context(|| format!("inspect configured {description} filesystem"))?;
    if !linux_program_filesystem_is_local(filesystem.f_type as u64) {
        bail!("configured {description} executable is not on a trusted local filesystem");
    }

    let proc_fd_directory =
        rustix::fs::open("/proc/self/fd", directory_flags, rustix::fs::Mode::empty())
            .context("open Linux process file-descriptor directory")?;
    let proc_filesystem = rustix::fs::fstatfs(&proc_fd_directory)
        .context("inspect Linux process file-descriptor filesystem")?;
    if proc_filesystem.f_type as u64 != 0x0000_9fa0 {
        bail!("Linux process file-descriptor directory is not provided by procfs");
    }
    let execution_path = PathBuf::from(format!("/proc/self/fd/{}", executable.as_raw_fd()));
    let execution_metadata = fs::metadata(&execution_path)
        .context("inspect held configured-program execution identity")?;
    if execution_metadata.dev() != executable_metadata.st_dev
        || execution_metadata.ino() != executable_metadata.st_ino
    {
        bail!("held configured-program execution identity does not match its descriptor");
    }

    Ok(ProgramGuard {
        executable,
        execution_path,
        _ancestor_directories: ancestor_directories,
        _proc_fd_directory: proc_fd_directory,
    })
}

#[cfg(windows)]
fn validate_private_directory(path: &Path, description: &str) -> Result<()> {
    windows_security::validate_private_directory(path)
        .with_context(|| format!("inspect {description} at {}", path.display()))
}

#[cfg(not(windows))]
fn validate_private_directory(path: &Path, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {description} at {}", path.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!("{description} must be a directory");
    }
    #[cfg(unix)]
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        bail!("{description} is not owned by the current user");
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("{description} permissions must not grant group or other access");
    }
    Ok(())
}

#[cfg(windows)]
fn private_read(path: &Path, description: &str) -> Result<File> {
    windows_security::open_private_file(path)
        .with_context(|| format!("open and validate {description} at {}", path.display()))
}

#[cfg(not(windows))]
fn private_read(path: &Path, description: &str) -> Result<File> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {description} at {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("{description} must be a non-symlink regular file");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    let file = options
        .open(path)
        .with_context(|| format!("open {description} at {}", path.display()))?;
    validate_open_private_file(&file, description)?;
    Ok(file)
}

#[cfg(not(windows))]
fn validate_open_private_file(file: &File, description: &str) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {description}"))?;
    if !metadata.file_type().is_file() {
        bail!("{description} is not a regular file");
    }
    #[cfg(unix)]
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!("{description} has unsafe type, ownership, links, or permissions");
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_private_directory(path: &Path) -> Result<()> {
    windows_security::ensure_private_directory(path)
        .with_context(|| format!("create or validate private directory {}", path.display()))
}

#[cfg(not(windows))]
fn ensure_private_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(false);
        #[cfg(unix)]
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("create private runtime directory {}", path.display())
                })
            }
        }
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect private runtime directory {}", path.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!("private runtime path is not a directory");
    }
    #[cfg(unix)]
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        bail!("private runtime directory is not owned by the current user");
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("private runtime directory grants group or other access");
    }
    Ok(())
}

fn ensure_runtime(paths: &RuntimePaths) -> Result<()> {
    let parent = paths
        .runtime
        .parent()
        .context("private runtime path has no parent")?;
    #[cfg(windows)]
    windows_security::ensure_private_directory_all(parent)
        .with_context(|| format!("create or validate runtime root {}", parent.display()))?;
    #[cfg(not(windows))]
    {
        if !parent.exists() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            builder.mode(0o700);
            builder
                .create(parent)
                .with_context(|| format!("create runtime root {}", parent.display()))?;
        }
        let parent_metadata = fs::symlink_metadata(parent)
            .with_context(|| format!("inspect runtime root {}", parent.display()))?;
        if !parent_metadata.file_type().is_dir() || parent_metadata.file_type().is_symlink() {
            bail!("runtime root is not a directory");
        }
        #[cfg(unix)]
        if parent_metadata.uid() != rustix::process::geteuid().as_raw()
            || parent_metadata.permissions().mode() & 0o077 != 0
        {
            bail!("runtime root is not a private current-user directory");
        }
    }
    ensure_private_directory(&paths.runtime)?;
    ensure_private_directory(&paths.cache_dir())?;
    remove_legacy_token_files(paths)?;
    Ok(())
}

fn remove_legacy_token_files(paths: &RuntimePaths) -> Result<()> {
    for entry in fs::read_dir(paths.cache_dir()).context("enumerate runtime cache")? {
        let entry = entry.context("read runtime cache entry")?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let _ = private_read(&path, "legacy installation-token cache")?;
            fs::remove_file(&path).context("remove legacy file-backed installation-token cache")?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_secret_service_session_at(
    environment: &BTreeMap<String, String>,
    run_user_root: &Path,
    uid: u32,
) -> Result<()> {
    let runtime = run_user_root.join(uid.to_string());
    let runtime_metadata = fs::symlink_metadata(&runtime).with_context(|| {
        format!(
            "inspect current-user runtime directory {}",
            runtime.display()
        )
    })?;
    if !runtime_metadata.file_type().is_dir()
        || runtime_metadata.file_type().is_symlink()
        || runtime_metadata.uid() != uid
        || runtime_metadata.permissions().mode() & 0o077 != 0
    {
        bail!("Secret Service runtime must be a private current-user directory");
    }
    let bus = runtime.join("bus");
    let bus_metadata = fs::symlink_metadata(&bus)
        .with_context(|| format!("inspect current-user session bus {}", bus.display()))?;
    if !bus_metadata.file_type().is_socket()
        || bus_metadata.file_type().is_symlink()
        || bus_metadata.uid() != uid
    {
        bail!("Secret Service session bus must be a current-user Unix socket");
    }
    if environment
        .get("XDG_RUNTIME_DIR")
        .is_some_and(|value| Path::new(value) != runtime)
    {
        bail!("XDG_RUNTIME_DIR does not identify the current-user login runtime");
    }
    let expected_address = format!("unix:path={}", bus.display());
    if environment
        .get("DBUS_SESSION_BUS_ADDRESS")
        .is_some_and(|value| value != &expected_address)
    {
        bail!("DBUS_SESSION_BUS_ADDRESS does not identify the current-user session bus");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_secret_service_session() -> Result<()> {
    let environment: BTreeMap<String, String> = env::vars().collect();
    validate_secret_service_session_at(
        &environment,
        Path::new("/run/user"),
        rustix::process::geteuid().as_raw(),
    )
}

fn credential_entry(store: &CredentialStore) -> Result<Entry> {
    #[cfg(target_os = "linux")]
    validate_secret_service_session()?;
    Entry::new(&store.service, &store.account).context("open native OS credential-store entry")
}

fn sanitized_current_environment() -> BTreeMap<String, String> {
    let input: BTreeMap<String, String> = env::vars().collect();
    sanitize_environment(&input, &BTreeSet::new())
}

fn service_account_token(store: &CredentialStore) -> Result<SecretString> {
    let value = credential_entry(store)?
        .get_password()
        .context("the dev-auth service credential is not enrolled or the keyring is locked")?;
    if value.is_empty() || value.contains(['\n', '\r', '\0']) {
        bail!("credential-store value is malformed");
    }
    Ok(SecretString::new(value))
}

#[cfg(target_os = "linux")]
fn user_broker_credential_store(slot: &str) -> Result<CredentialStore> {
    validate_broker_credential_slot(slot)?;
    Ok(CredentialStore {
        service: "dev-auth-v3".into(),
        account: format!("user-broker-service-account-token-{slot}"),
    })
}

#[cfg(target_os = "linux")]
fn validate_broker_credential_slot(slot: &str) -> Result<()> {
    let mut bytes = slot.bytes();
    if slot.is_empty()
        || slot.len() > 64
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("broker credential slot is invalid");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn user_broker_service_tokens<'a>(
    slots: impl Iterator<Item = &'a str>,
) -> Result<BTreeMap<String, SecretString>> {
    slots
        .map(|slot| {
            Ok((
                slot.to_owned(),
                service_account_token(&user_broker_credential_store(slot)?)?,
            ))
        })
        .collect()
}

#[cfg(target_os = "linux")]
pub(crate) fn user_broker_service_token_for_slot(slot: &str) -> Result<SecretString> {
    service_account_token(&user_broker_credential_store(slot)?)
}

#[cfg(target_os = "linux")]
pub(crate) fn user_broker_service_token() -> Result<SecretString> {
    user_broker_service_token_for_slot("automation")
}

#[cfg(target_os = "linux")]
pub fn enroll_user_broker_service_token_for_slot(slot: &str, value: &[u8]) -> Result<()> {
    let store = user_broker_credential_store(slot)?;
    enroll_user_broker_service_token_at(&store, value)
}

#[cfg(target_os = "linux")]
fn enroll_user_broker_service_token_at(store: &CredentialStore, value: &[u8]) -> Result<()> {
    let value = std::str::from_utf8(value).context("service credential is not UTF-8")?;
    let value = value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value);
    if value.is_empty() || value.contains(['\n', '\r', '\0']) {
        bail!("service credential must be exactly one nonempty line");
    }
    let entry = credential_entry(store)?;
    match entry.get_password() {
        Ok(existing) => {
            let _existing = zeroize::Zeroizing::new(existing);
            bail!("user-broker credential is already enrolled; use explicit rotation")
        }
        Err(keyring::Error::NoEntry) => entry
            .set_password(value)
            .context("store user-broker credential in the native OS credential store"),
        Err(error) => Err(error).context("inspect existing user-broker credential"),
    }
}

#[cfg(target_os = "linux")]
pub fn enroll_user_broker_service_token(value: &[u8]) -> Result<()> {
    enroll_user_broker_service_token_for_slot("automation", value)
}

#[cfg(target_os = "linux")]
pub fn rotate_user_broker_service_token_for_slot(slot: &str, value: &[u8]) -> Result<()> {
    if !matches!(
        crate::broker_client::active_claim_and_probe()?.0,
        crate::broker_protocol::LocalSessionClaim::Absent
    ) {
        bail!("user-broker credential cannot rotate inside an admitted workload");
    }
    let value = std::str::from_utf8(value).context("service credential is not UTF-8")?;
    let value = value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value);
    if value.is_empty() || value.contains(['\n', '\r', '\0']) {
        bail!("service credential must be exactly one nonempty line");
    }
    let entry = credential_entry(&user_broker_credential_store(slot)?)?;
    let existing = entry
        .get_password()
        .context("user-broker credential is not enrolled")?;
    let _existing = zeroize::Zeroizing::new(existing);
    entry
        .set_password(value)
        .context("rotate user-broker credential in the native OS credential store")
}

#[cfg(target_os = "linux")]
pub fn rotate_user_broker_service_token(value: &[u8]) -> Result<()> {
    rotate_user_broker_service_token_for_slot("automation", value)
}

#[cfg(target_os = "linux")]
pub fn revoke_user_broker_service_token_for_slot(slot: &str) -> Result<()> {
    if !matches!(
        crate::broker_client::active_claim_and_probe()?.0,
        crate::broker_protocol::LocalSessionClaim::Absent
    ) {
        bail!("user-broker credential cannot be removed inside an admitted workload");
    }
    match credential_entry(&user_broker_credential_store(slot)?)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => {
            Err(error).context("remove user-broker credential from the native OS credential store")
        }
    }
}

#[cfg(target_os = "linux")]
pub fn revoke_user_broker_service_token() -> Result<()> {
    revoke_user_broker_service_token_for_slot("automation")
}

pub fn enroll_service_account_token(value: &[u8]) -> Result<()> {
    let paths = RuntimePaths::discover()?;
    let config = load_config(&paths)?;
    let value = std::str::from_utf8(value).context("service credential is not UTF-8")?;
    let value = value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value);
    if value.is_empty() || value.contains(['\n', '\r', '\0']) {
        bail!("service credential must be exactly one nonempty line");
    }
    credential_entry(&config.credential_store)?
        .set_password(value)
        .context("store service credential in the native OS credential store")
}

fn read_declared_secret(config: &Config, reference: &str) -> Result<SecretString> {
    let service_token = service_account_token(&config.credential_store)?;
    read_declared_secret_with_token(&config.programs.op, &service_token, reference)
}

pub(crate) fn read_declared_secret_with_token(
    op_program: &str,
    service_token: &SecretString,
    reference: &str,
) -> Result<SecretString> {
    crate::validate_op_reference(reference)?;
    let program_guard = program_guard(op_program, "1Password CLI")?;
    let output = guarded_command(op_program, &program_guard)?
        .args(["read", "--no-newline", reference])
        .env_clear()
        .envs(sanitized_current_environment())
        .env("OP_SERVICE_ACCOUNT_TOKEN", service_token.expose())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("run bounded 1Password item read")?;
    if !output.status.success() {
        bail!("1Password denied the declared item read");
    }
    let value = String::from_utf8(output.stdout).context("1Password item value is not UTF-8")?;
    if value.is_empty() || value.contains('\0') {
        bail!("1Password item value is empty or malformed");
    }
    Ok(SecretString::new(value))
}

#[derive(Debug, Serialize)]
struct AppJwtClaims {
    iat: i64,
    exp: i64,
    iss: String,
}

#[derive(Debug, Serialize)]
struct InstallationTokenRequest<'a> {
    repositories: &'a [String],
    permissions: &'a BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct InstallationTokenResponse {
    token: String,
    expires_at: String,
    permissions: BTreeMap<String, String>,
    repository_selection: String,
    repositories: Vec<RepositoryResponse>,
}

#[derive(Deserialize)]
struct RepositoryResponse {
    id: u64,
    full_name: String,
}

#[derive(Deserialize)]
struct InstallationAccountResponse {
    login: String,
}

#[derive(Deserialize)]
struct RepositoryInstallationResponse {
    id: u64,
    app_id: u64,
    account: InstallationAccountResponse,
    permissions: BTreeMap<String, String>,
    repository_selection: crate::RepositorySelection,
    suspended_at: Option<serde_json::Value>,
}

fn github_app_jwt(config: &Config, now: i64) -> Result<String> {
    let private_key = read_declared_secret(config, &config.github.private_key_ref)?;
    github_app_jwt_with_key(config.github.app_id, &private_key, now)
}

fn github_app_jwt_with_key(app_id: u64, private_key: &SecretString, now: i64) -> Result<String> {
    let key = EncodingKey::from_rsa_pem(private_key.expose().as_bytes())
        .context("GitHub App private key is not a valid RSA PEM key")?;
    encode(
        &Header::new(Algorithm::RS256),
        &AppJwtClaims {
            iat: now - 60,
            exp: now + 540,
            iss: app_id.to_string(),
        },
        &key,
    )
    .context("sign GitHub App JWT")
}

fn github_api_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(true)
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(format!("dev-auth/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

fn discover_repository_installation(
    config: &Config,
    owner: &str,
    repository: &str,
    now: i64,
) -> Result<SelectedRepository> {
    let jwt = github_app_jwt(config, now)?;
    discover_repository_installation_with_jwt(&config.github, owner, repository, &jwt)
}

fn discover_repository_installation_with_jwt(
    profile: &crate::GitHubProfile,
    owner: &str,
    repository: &str,
    jwt: &str,
) -> Result<SelectedRepository> {
    let url = format!("https://api.github.com/repos/{owner}/{repository}/installation");
    let mut response = github_api_agent()
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("X-GitHub-Api-Version", "2026-03-10")
        .call()
        .context("discover exact repository GitHub App installation")?;
    if !response.status().is_success() {
        bail!(
            "GitHub App repository installation lookup returned HTTP {}",
            response.status()
        );
    }
    let bytes = response
        .body_mut()
        .with_config()
        .limit(RESPONSE_LIMIT)
        .read_to_vec()
        .context("read bounded GitHub App installation response")?;
    validate_repository_installation_response(profile, owner, repository, &bytes)
}

fn validate_repository_installation_response(
    profile: &crate::GitHubProfile,
    owner: &str,
    repository: &str,
    bytes: &[u8],
) -> Result<SelectedRepository> {
    let installation: RepositoryInstallationResponse = serde_json::from_slice(bytes)
        .context("parse GitHub App repository installation response")?;
    if installation.id == 0
        || installation.app_id != profile.app_id
        || !installation.account.login.eq_ignore_ascii_case(owner)
        || installation.permissions != profile.permissions
        || installation.repository_selection != profile.repository_selection
        || installation.suspended_at.is_some()
    {
        bail!("GitHub App repository installation does not match the declared authority");
    }
    Ok(SelectedRepository {
        installation_id: installation.id,
        owner: owner.to_ascii_lowercase(),
        repository: repository.to_ascii_lowercase(),
    })
}

fn mint_installation_token(
    config: &Config,
    installation_id: u64,
    owner: &str,
    repository: &str,
    now: i64,
) -> Result<CacheEntry> {
    let jwt = github_app_jwt(config, now)?;
    mint_installation_token_with_jwt(
        &config.github,
        &jwt,
        installation_id,
        owner,
        repository,
        now,
    )
}

fn mint_installation_token_with_jwt(
    profile: &crate::GitHubProfile,
    jwt: &str,
    installation_id: u64,
    owner: &str,
    repository: &str,
    now: i64,
) -> Result<CacheEntry> {
    let repositories = [repository.to_owned()];
    let token = mint_scoped_installation_token_with_jwt(
        profile,
        jwt,
        installation_id,
        owner,
        &repositories,
        now,
    )?;
    Ok(CacheEntry::new(
        token.token,
        token.expires_at,
        profile.app_id,
        installation_id,
        owner.to_ascii_lowercase(),
        repository.to_owned(),
        profile.permissions.clone(),
    ))
}

fn mint_scoped_installation_token_with_jwt(
    profile: &crate::GitHubProfile,
    jwt: &str,
    installation_id: u64,
    owner: &str,
    repositories: &[String],
    now: i64,
) -> Result<BrokerGitHubToken> {
    if repositories.is_empty() || repositories.len() > 500 {
        bail!("GitHub token scope must contain between one and 500 repositories");
    }
    let expected_repositories = repositories
        .iter()
        .map(|repository| {
            if !crate::is_github_component(repository) {
                bail!("GitHub token scope contains an invalid repository name");
            }
            Ok(format!("{owner}/{repository}").to_ascii_lowercase())
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if expected_repositories.len() != repositories.len() {
        bail!("GitHub token scope contains a duplicate repository");
    }
    let agent = github_api_agent();
    let url = format!("https://api.github.com/app/installations/{installation_id}/access_tokens");
    let mut response = agent
        .post(&url)
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("X-GitHub-Api-Version", "2026-03-10")
        .send_json(&InstallationTokenRequest {
            repositories,
            permissions: &profile.permissions,
        })
        .context("request narrowed GitHub App installation token")?;
    if !response.status().is_success() {
        bail!(
            "GitHub App installation token request returned HTTP {}",
            response.status()
        );
    }
    let bytes = response
        .body_mut()
        .with_config()
        .limit(RESPONSE_LIMIT)
        .read_to_vec()
        .context("read bounded GitHub App response")?;
    let response: InstallationTokenResponse =
        serde_json::from_slice(&bytes).context("parse GitHub App token response")?;
    let expires_at = OffsetDateTime::parse(&response.expires_at, &Rfc3339)
        .context("parse GitHub App token expiry")?
        .unix_timestamp();
    if response.token.is_empty()
        || response.token.contains(['\n', '\r', '\0'])
        || expires_at <= now + 300
        || expires_at > now + 3700
        || response.permissions != profile.permissions
        || response.repository_selection != "selected"
    {
        bail!("GitHub returned an invalid installation token contract");
    }
    let returned_repositories = response
        .repositories
        .iter()
        .map(|repository| {
            if repository.id == 0 {
                bail!("GitHub token scope contains an invalid repository identity");
            }
            Ok(repository.full_name.to_ascii_lowercase())
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if returned_repositories.len() != response.repositories.len()
        || returned_repositories != expected_repositories
    {
        bail!("GitHub token scope does not exactly match the requested repositories");
    }
    Ok(BrokerGitHubToken {
        token: SecretString::new(response.token),
        expires_at,
    })
}

#[cfg(target_os = "linux")]
pub(crate) struct BrokerGitHubAuthority<'a> {
    pub op_program: &'a str,
    pub service_token: &'a SecretString,
    pub app_id: u64,
    pub private_key_ref: &'a str,
    pub permissions: BTreeMap<String, String>,
    pub installation_ids: &'a [u64],
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct BrokerGitHubToken {
    pub token: SecretString,
    pub expires_at: i64,
}

#[cfg(target_os = "linux")]
pub(crate) fn broker_revoke_github_token(token: &SecretString) -> Result<()> {
    let response = github_api_agent()
        .delete("https://api.github.com/installation/token")
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("token {}", token.expose()))
        .header("X-GitHub-Api-Version", "2026-03-10")
        .call()
        .context("revoke GitHub App installation token")?;
    if response.status().as_u16() != 204 {
        bail!("GitHub App token revocation was rejected");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn broker_github_token_for_repository(
    authority: BrokerGitHubAuthority<'_>,
    owner: &str,
    repository: &str,
) -> Result<BrokerGitHubToken> {
    broker_github_token_for_repositories(authority, owner, &[repository.to_owned()])
}

#[cfg(target_os = "linux")]
pub(crate) fn broker_github_token_for_repositories(
    authority: BrokerGitHubAuthority<'_>,
    owner: &str,
    repositories: &[String],
) -> Result<BrokerGitHubToken> {
    if repositories.is_empty() || repositories.len() > 500 {
        bail!("GitHub CLI authority requires a finite repository set");
    }
    let private_key = read_declared_secret_with_token(
        authority.op_program,
        authority.service_token,
        authority.private_key_ref,
    )?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let jwt = github_app_jwt_with_key(authority.app_id, &private_key, now)?;
    let profile = crate::GitHubProfile {
        app_id: authority.app_id,
        private_key_ref: authority.private_key_ref.to_owned(),
        repository_selection: crate::RepositorySelection::Selected,
        discover_installations: true,
        installations: Vec::new(),
        permissions: authority.permissions,
    };
    let mut installation_id = None;
    for repository in repositories {
        let selected =
            discover_repository_installation_with_jwt(&profile, owner, repository, &jwt)?;
        match installation_id {
            None => installation_id = Some(selected.installation_id),
            Some(expected) if expected == selected.installation_id => {}
            Some(_) => bail!("GitHub CLI repository scope crosses App installations"),
        }
    }
    let installation_id = installation_id.context("GitHub CLI authority has no repository")?;
    if !authority.installation_ids.is_empty()
        && authority
            .installation_ids
            .binary_search(&installation_id)
            .is_err()
    {
        bail!("GitHub App installation is outside the workload authority cap");
    }
    mint_scoped_installation_token_with_jwt(
        &profile,
        &jwt,
        installation_id,
        owner,
        repositories,
        now,
    )
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheFile {
    token: String,
    expires_at: i64,
    app_id: u64,
    installation_id: u64,
    owner: String,
    repository: String,
    permissions: BTreeMap<String, String>,
}

impl From<&CacheEntry> for CacheFile {
    fn from(entry: &CacheEntry) -> Self {
        Self {
            token: entry.token().expose().to_owned(),
            expires_at: entry.expires_at(),
            app_id: entry.app_id(),
            installation_id: entry.installation_id(),
            owner: entry.owner().to_owned(),
            repository: entry.repository().to_owned(),
            permissions: entry.permissions.clone(),
        }
    }
}

impl From<CacheFile> for CacheEntry {
    fn from(value: CacheFile) -> Self {
        CacheEntry::new(
            SecretString::new(value.token),
            value.expires_at,
            value.app_id,
            value.installation_id,
            value.owner,
            value.repository,
            value.permissions,
        )
    }
}

fn cache_key(
    app_id: u64,
    installation_id: u64,
    repository_selection: crate::RepositorySelection,
    repository: &str,
    permissions: &BTreeMap<String, String>,
) -> Result<String> {
    let public_scope = serde_json::to_vec(&(
        app_id,
        installation_id,
        repository_selection,
        repository,
        permissions,
    ))
    .context("serialize installation-token cache scope")?;
    Ok(format!("{:x}", Sha256::digest(public_scope)))
}

fn dynamic_cache_key(
    app_id: u64,
    repository_selection: crate::RepositorySelection,
    owner: &str,
    repository: &str,
    permissions: &BTreeMap<String, String>,
) -> Result<String> {
    let public_scope = serde_json::to_vec(&(
        "dynamic",
        app_id,
        repository_selection,
        owner.to_ascii_lowercase(),
        repository.to_ascii_lowercase(),
        permissions,
    ))
    .context("serialize dynamic installation-token cache scope")?;
    Ok(format!("{:x}", Sha256::digest(public_scope)))
}

fn cache_lifecycle_lock(paths: &RuntimePaths) -> Result<File> {
    private_open(&paths.runtime.join("cache-lifecycle.lock"))
}

fn with_cache_scope_lock<T, F>(paths: &RuntimePaths, key: &str, operation: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    ensure_runtime(paths)?;
    let lifecycle = cache_lifecycle_lock(paths)?;
    FileExt::lock_shared(&lifecycle).context("lock installation-token cache lifecycle")?;
    let scope = private_open(&paths.cache_dir().join(format!("{key}.lock")))?;
    scope
        .lock_exclusive()
        .context("lock installation-token cache scope")?;
    operation()
}

fn with_cache_purge_lock<T, F>(paths: &RuntimePaths, operation: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    ensure_runtime(paths)?;
    let lifecycle = cache_lifecycle_lock(paths)?;
    lifecycle
        .lock_exclusive()
        .context("lock installation-token cache lifecycle for purge")?;
    operation()
}

fn with_cache_scope_erase_lock<T, F>(paths: &RuntimePaths, key: &str, operation: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    ensure_runtime(paths)?;
    let lifecycle = cache_lifecycle_lock(paths)?;
    lifecycle
        .lock_exclusive()
        .context("lock installation-token cache lifecycle for erase")?;
    let scope_path = paths.cache_dir().join(format!("{key}.lock"));
    let scope = private_open(&scope_path)?;
    scope
        .lock_exclusive()
        .context("lock installation-token cache scope for erase")?;
    let value = operation()?;
    drop(scope);
    fs::remove_file(&scope_path).context("remove erased installation-token scope receipt")?;
    Ok(value)
}

fn locked_cache_entry<F>(
    paths: &RuntimePaths,
    config: &Config,
    selected: &SelectedRepository,
    create: F,
) -> Result<CacheEntry>
where
    F: FnOnce() -> Result<CacheEntry>,
{
    let key = cache_key(
        config.github.app_id,
        selected.installation_id,
        config.github.repository_selection,
        &selected.repository,
        &config.github.permissions,
    )?;
    with_cache_scope_lock(paths, &key, || {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if let Ok(entry) = read_cache(&config.credential_store, &key) {
            if entry.is_usable_at(
                now,
                config.github.app_id,
                selected.installation_id,
                &selected.owner,
                &selected.repository,
                &config.github.permissions,
            ) {
                return Ok(entry);
            }
        }
        let entry = create()?;
        if !entry.is_usable_at(
            now,
            config.github.app_id,
            selected.installation_id,
            &selected.owner,
            &selected.repository,
            &config.github.permissions,
        ) {
            bail!("new installation token is not usable for the requested scope");
        }
        write_cache(&config.credential_store, &key, &entry)?;
        Ok(entry)
    })
}

fn locked_dynamic_cache_entry(
    paths: &RuntimePaths,
    config: &Config,
    owner: &str,
    repository: &str,
) -> Result<CacheEntry> {
    let owner = owner.to_ascii_lowercase();
    let repository = repository.to_ascii_lowercase();
    let key = dynamic_cache_key(
        config.github.app_id,
        config.github.repository_selection,
        &owner,
        &repository,
        &config.github.permissions,
    )?;
    with_cache_scope_lock(paths, &key, || {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        resolve_dynamic_cache_entry(
            DynamicRepositoryScope {
                now,
                app_id: config.github.app_id,
                owner: &owner,
                repository: &repository,
                permissions: &config.github.permissions,
            },
            || discover_repository_installation(config, &owner, &repository, now),
            || read_cache(&config.credential_store, &key),
            |installation_id| {
                mint_installation_token(
                    config,
                    installation_id,
                    &owner,
                    &repository,
                    OffsetDateTime::now_utc().unix_timestamp(),
                )
            },
            |entry| write_cache(&config.credential_store, &key, entry),
        )
    })
}

struct DynamicRepositoryScope<'a> {
    now: i64,
    app_id: u64,
    owner: &'a str,
    repository: &'a str,
    permissions: &'a BTreeMap<String, String>,
}

fn resolve_dynamic_cache_entry<Discover, Read, Mint, Write>(
    scope: DynamicRepositoryScope<'_>,
    discover: Discover,
    read: Read,
    mint: Mint,
    write: Write,
) -> Result<CacheEntry>
where
    Discover: FnOnce() -> Result<SelectedRepository>,
    Read: FnOnce() -> Result<CacheEntry>,
    Mint: FnOnce(u64) -> Result<CacheEntry>,
    Write: FnOnce(&CacheEntry) -> Result<()>,
{
    let selected = discover()?;
    if selected.owner != scope.owner || selected.repository != scope.repository {
        bail!("live GitHub installation does not match the requested repository");
    }
    if let Ok(entry) = read() {
        if entry.is_usable_for_repository_at(
            scope.now,
            scope.app_id,
            selected.installation_id,
            scope.owner,
            scope.repository,
            scope.permissions,
        ) {
            return Ok(entry);
        }
    }

    let entry = mint(selected.installation_id)?;
    if !entry.is_usable_for_repository_at(
        scope.now,
        scope.app_id,
        selected.installation_id,
        scope.owner,
        scope.repository,
        scope.permissions,
    ) {
        bail!("new installation token is not usable for the requested repository");
    }
    write(&entry)?;
    Ok(entry)
}

#[cfg(windows)]
fn private_open(path: &Path) -> Result<File> {
    windows_security::open_or_create_private_file(path)
        .with_context(|| format!("open private runtime file {}", path.display()))
}

#[cfg(not(windows))]
fn private_open(path: &Path) -> Result<File> {
    if path.is_symlink() {
        bail!("private runtime path must not be a symlink");
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    options
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .mode(0o600);
    let file = options
        .open(path)
        .with_context(|| format!("open private runtime file {}", path.display()))?;
    validate_open_private_file(&file, "private runtime file")?;
    Ok(file)
}

fn cache_entry(store: &CredentialStore, key: &str) -> Result<Entry> {
    #[cfg(target_os = "linux")]
    validate_secret_service_session()?;
    Entry::new(&format!("{}:github-installation-token", store.service), key)
        .context("open native installation-token cache entry")
}

fn read_cache(store: &CredentialStore, key: &str) -> Result<CacheEntry> {
    let secret = cache_entry(store, key)?
        .get_password()
        .context("read native installation-token cache")?;
    let value: CacheFile =
        serde_json::from_str(&secret).context("parse installation-token cache")?;
    if value.token.is_empty() || value.token.contains(['\n', '\r', '\0']) {
        bail!("installation-token cache is malformed");
    }
    Ok(value.into())
}

fn write_cache(store: &CredentialStore, key: &str, entry: &CacheEntry) -> Result<()> {
    let secret = serde_json::to_string(&CacheFile::from(entry))
        .context("serialize installation-token cache")?;
    cache_entry(store, key)?
        .set_password(&secret)
        .context("write native installation-token cache")
}

fn token_entry_for_repository(
    paths: &RuntimePaths,
    config: &Config,
    owner: &str,
    repository: &str,
) -> Result<CacheEntry> {
    if config.github.discover_installations {
        return locked_dynamic_cache_entry(paths, config, owner, repository);
    }
    let selected = config.github.select_repository(owner, repository)?;
    locked_cache_entry(paths, config, &selected, || {
        mint_installation_token(
            config,
            selected.installation_id,
            &selected.owner,
            &selected.repository,
            OffsetDateTime::now_utc().unix_timestamp(),
        )
    })
}

pub fn credential_get(input: &[u8]) -> Result<String> {
    let (paths, config) = frontend_runtime_and_config()?;
    credential_get_with_sources(
        input,
        |owner, repository| validate_bound_git_credential_authority(&config, owner, repository),
        |owner, repository| token_entry_for_repository(&paths, &config, owner, repository),
    )
}

#[cfg(target_os = "linux")]
pub fn broker_credential_get(input: &[u8]) -> Result<String> {
    let request = CredentialRequest::parse(input)?;
    let (owner, repository) = request.repository()?;
    match crate::broker_client::request_active(
        crate::broker_protocol::BrokerRequest::GitCredential {
            protocol: "https".into(),
            host: "github.com".into(),
            owner: owner.into(),
            repository: repository.into(),
        },
    )? {
        crate::broker_protocol::BrokerResponse::GitCredential {
            username,
            password,
            expires_at,
        } => {
            if username != "x-access-token" {
                bail!("broker returned an unsupported Git credential username");
            }
            let expires_at = OffsetDateTime::parse(&expires_at, &Rfc3339)
                .context("parse broker Git credential expiry")?
                .unix_timestamp();
            render_git_credential(password.expose(), expires_at)
        }
        crate::broker_protocol::BrokerResponse::Denied { code, message } => {
            bail!("broker denied Git credentials ({code}): {message}")
        }
        crate::broker_protocol::BrokerResponse::NoSession
        | crate::broker_protocol::BrokerResponse::Accepted
        | crate::broker_protocol::BrokerResponse::Ready { .. }
        | crate::broker_protocol::BrokerResponse::GhExecutionToken { .. }
        | crate::broker_protocol::BrokerResponse::Signature { .. } => {
            bail!("broker returned an invalid Git credential response")
        }
    }
}

#[cfg(target_os = "linux")]
pub fn broker_credential_erase(input: &[u8]) -> Result<()> {
    let request = CredentialRequest::parse(input)?;
    let (owner, repository) = request.repository()?;
    match crate::broker_client::request_active(
        crate::broker_protocol::BrokerRequest::InvalidateGitCredential {
            protocol: "https".into(),
            host: "github.com".into(),
            owner: owner.into(),
            repository: repository.into(),
        },
    )? {
        crate::broker_protocol::BrokerResponse::Accepted => Ok(()),
        crate::broker_protocol::BrokerResponse::Denied { code, message } => {
            bail!("broker denied Git credential invalidation ({code}): {message}")
        }
        crate::broker_protocol::BrokerResponse::NoSession
        | crate::broker_protocol::BrokerResponse::Ready { .. }
        | crate::broker_protocol::BrokerResponse::GitCredential { .. }
        | crate::broker_protocol::BrokerResponse::GhExecutionToken { .. }
        | crate::broker_protocol::BrokerResponse::Signature { .. } => {
            bail!("broker returned an invalid credential-invalidation response")
        }
    }
}

fn credential_get_with_sources<A, T>(input: &[u8], authorize: A, token_source: T) -> Result<String>
where
    A: FnOnce(&str, &str) -> Result<()>,
    T: FnOnce(&str, &str) -> Result<CacheEntry>,
{
    let request = CredentialRequest::parse(input)?;
    let (owner, repository) = request.repository()?;
    authorize(owner, repository)?;
    let entry = token_source(owner, repository)?;
    render_git_credential(entry.token().expose(), entry.expires_at())
}

pub fn github_token_for_repository(owner: &str, repository: &str) -> Result<SecretString> {
    let paths = RuntimePaths::discover()?;
    let config = load_config(&paths)?;
    let entry = token_entry_for_repository(&paths, &config, owner, repository)?;
    Ok(entry.token().clone())
}

fn forwarded_gh_arguments(
    mut plan: crate::GhInvocationPlan,
    owner: &str,
    repository: &str,
) -> Vec<String> {
    if plan.inject_repository_argument {
        plan.forwarded_arguments
            .insert(2, format!("{owner}/{repository}"));
    }
    plan.forwarded_arguments
}

fn origin_repository_at(
    program: &str,
    working_directory: Option<&Path>,
    environment: &BTreeMap<String, String>,
) -> Result<String> {
    let program_guard = program_guard(program, "Git")?;
    let mut command = guarded_command(program, &program_guard)?;
    command
        .args([
            "config",
            "--no-includes",
            "--null",
            "--get-all",
            "remote.origin.url",
        ])
        .env_clear()
        .envs(environment)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    if let Some(working_directory) = working_directory {
        command.current_dir(working_directory);
    }
    let output = command.output().context("read current Git origin")?;
    if !output.status.success() {
        bail!("no explicit repository and no literal local Git origin");
    }
    if output.stdout.len() as u64 > RESPONSE_LIMIT {
        bail!("literal local Git origin exceeds the size limit");
    }
    let mut values = output.stdout.split(|byte| *byte == 0);
    let value = values.next().unwrap_or_default();
    if value.is_empty()
        || values
            .next()
            .is_none_or(|terminator| !terminator.is_empty())
        || values.next().is_some()
    {
        bail!("literal local Git origin is missing or ambiguous");
    }
    String::from_utf8(value.to_vec()).context("literal local Git origin is not UTF-8")
}

fn origin_repository(program: &str) -> Result<String> {
    origin_repository_at(program, None, &sanitized_current_environment())
}

fn preconfigured_gh_repository(
    selected: Option<(String, String)>,
) -> Result<Option<(String, String)>> {
    if selected.is_some() {
        return Ok(selected);
    }
    match env::var("GH_REPO") {
        Ok(value) => crate::exact_github_repository(&value).map(Some),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => bail!("GH_REPO is not valid Unicode"),
    }
}

fn resolve_gh_repository(
    selected: Option<(String, String)>,
    git_program: &str,
) -> Result<(String, String)> {
    match selected {
        Some(repository) => Ok(repository),
        None => crate::parse_github_repository(&origin_repository(git_program)?),
    }
}

fn file_sha256(path: &Path, description: &str) -> Result<[u8; 32]> {
    let mut file = File::open(path).with_context(|| format!("open {description}"))?;
    file_sha256_file(&mut file, description)
}

fn file_sha256_file(file: &mut File, description: &str) -> Result<[u8; 32]> {
    #[cfg(windows)]
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("rewind {description}"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("read {description}"))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    #[cfg(windows)]
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("rewind {description}"))?;
    Ok(digest.finalize().into())
}

#[cfg(not(windows))]
fn install_gh_child_frontend(source: &Path, destination: &Path, digest: &[u8; 32]) -> Result<()> {
    #[cfg(windows)]
    if destination.exists()
        && private_read(destination, "gh child frontend").is_ok()
        && file_sha256(destination, "gh child frontend")? == *digest
    {
        return Ok(());
    }
    #[cfg(not(windows))]
    if destination.exists() {
        let _ = private_read(destination, "gh child frontend")?;
        if file_sha256(destination, "gh child frontend")? == *digest {
            return Ok(());
        }
    }
    let name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .context("gh child frontend name is invalid")?;
    let temporary = destination.with_file_name(format!(".{name}.tmp"));
    #[cfg(not(windows))]
    if temporary.exists() {
        let _ = private_read(&temporary, "temporary gh child frontend")?;
        fs::remove_file(&temporary).context("remove stale temporary gh child frontend")?;
    }
    #[cfg(windows)]
    windows_security::copy_to_private_replacement(source, &temporary)
        .context("copy gh child frontend into a private Windows file")?;
    #[cfg(not(windows))]
    fs::copy(source, &temporary).context("copy gh child frontend")?;
    #[cfg(unix)]
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700))
        .context("make gh child frontend executable")?;
    let _ = private_read(&temporary, "temporary gh child frontend")?;
    if file_sha256(&temporary, "temporary gh child frontend")? != *digest {
        bail!("copied gh child frontend does not match the running executable");
    }
    #[cfg(windows)]
    windows_security::atomically_replace_private_file(&temporary, destination)
        .context("atomically activate private gh child frontend")?;
    #[cfg(not(windows))]
    {
        if destination.exists() {
            fs::remove_file(destination).context("remove superseded gh child frontend")?;
        }
        fs::rename(&temporary, destination).context("activate gh child frontend")?;
    }
    Ok(())
}

fn ensure_empty_private_file(path: &Path, description: &str) -> Result<()> {
    let file = private_open(path).with_context(|| format!("open {description}"))?;
    file.set_len(0)
        .with_context(|| format!("truncate {description}"))?;
    file.sync_all()
        .with_context(|| format!("synchronize {description}"))
}

fn ensure_gh_sandbox_roots(paths: &RuntimePaths) -> Result<()> {
    ensure_runtime(paths)?;
    ensure_private_directory(&paths.gh_sandbox_dir())?;
    ensure_private_directory(&paths.gh_child_bin_dir())?;
    ensure_private_directory(&paths.gh_config_dir())?;
    ensure_private_directory(&paths.gh_home_dir())?;
    ensure_private_directory(&paths.gh_cache_dir())?;
    ensure_private_directory(&paths.gh_data_dir())?;
    ensure_private_directory(&paths.gh_temp_dir())?;
    ensure_private_directory(&paths.gh_git_hooks_dir())?;
    ensure_empty_private_file(&paths.gh_git_config_file(), "empty Git configuration")?;
    ensure_empty_private_file(&paths.gh_git_attributes_file(), "empty Git attributes file")
}

#[cfg(windows)]
fn gh_child_frontend_guards(paths: &RuntimePaths) -> Result<Vec<ProgramGuard>> {
    GH_CHILD_FRONTENDS
        .iter()
        .map(|frontend| {
            let path = paths.gh_child_bin_dir().join(frontend);
            windows_security::lock_local_program(&path)
                .with_context(|| format!("lock private gh child frontend at {}", path.display()))
        })
        .collect()
}

#[cfg(not(windows))]
fn ensure_gh_sandbox(paths: &RuntimePaths) -> Result<()> {
    ensure_gh_sandbox_roots(paths)?;
    let lock = private_open(&paths.runtime.join("gh-sandbox.lock"))?;
    lock.lock_exclusive().context("lock gh sandbox update")?;
    let executable = env::current_exe().context("resolve running dev-auth executable")?;
    let digest = file_sha256(&executable, "running dev-auth executable")?;
    for frontend in GH_CHILD_FRONTENDS {
        install_gh_child_frontend(
            &executable,
            &paths.gh_child_bin_dir().join(frontend),
            &digest,
        )?;
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_gh_sandbox(paths: &RuntimePaths) -> Result<()> {
    ensure_gh_sandbox_roots(paths)?;
    let lock = private_open(&paths.runtime.join("gh-sandbox.lock"))?;
    lock.lock_exclusive().context("lock gh sandbox update")?;
    let executable = env::current_exe().context("resolve running dev-auth executable")?;
    let mut executable_file = windows_security::lock_local_program_for_copy(&executable)
        .context("lock running dev-auth executable")?;
    let digest = file_sha256_file(&mut executable_file, "running dev-auth executable")?;
    for frontend in GH_CHILD_FRONTENDS {
        let destination = paths.gh_child_bin_dir().join(frontend);
        if destination.exists()
            && private_read(&destination, "gh child frontend").is_ok()
            && file_sha256(&destination, "gh child frontend")? == digest
        {
            continue;
        }
        let name = destination
            .file_name()
            .and_then(|value| value.to_str())
            .context("gh child frontend name is invalid")?;
        let temporary = destination.with_file_name(format!(".{name}.tmp"));
        if temporary.exists() {
            let _ = private_read(&temporary, "temporary gh child frontend")?;
            fs::remove_file(&temporary).context("remove stale temporary gh child frontend")?;
        }
        windows_security::copy_open_file_to_private_replacement(&mut executable_file, &temporary)
            .context("copy gh child frontend into a private Windows file")?;
        let _ = private_read(&temporary, "temporary gh child frontend")?;
        if file_sha256(&temporary, "temporary gh child frontend")? != digest {
            bail!("copied gh child frontend does not match the running executable");
        }
        windows_security::atomically_replace_private_file(&temporary, &destination)
            .context("atomically activate private gh child frontend")?;
    }
    Ok(())
}

fn isolated_gh_environment(
    input: &BTreeMap<String, String>,
    paths: &RuntimePaths,
    token: &SecretString,
    owner: &str,
    repository: &str,
    git_program: &str,
) -> BTreeMap<String, String> {
    const PLATFORM_ALLOWED: &[&str] = &[
        "COLORTERM",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATHEXT",
        "SYSTEMROOT",
        "TERM",
    ];
    let mut environment: BTreeMap<String, String> = input
        .iter()
        .filter(|(key, _)| {
            PLATFORM_ALLOWED
                .iter()
                .any(|allowed| key.eq_ignore_ascii_case(allowed))
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    environment.insert(
        "PATH".into(),
        paths.gh_child_bin_dir().display().to_string(),
    );
    environment.insert(
        "GH_CONFIG_DIR".into(),
        paths.gh_config_dir().display().to_string(),
    );
    environment.insert("HOME".into(), paths.gh_home_dir().display().to_string());
    environment.insert(
        "USERPROFILE".into(),
        paths.gh_home_dir().display().to_string(),
    );
    environment.insert(
        "XDG_CONFIG_HOME".into(),
        paths.gh_config_dir().display().to_string(),
    );
    environment.insert(
        "XDG_CACHE_HOME".into(),
        paths.gh_cache_dir().display().to_string(),
    );
    environment.insert(
        "XDG_DATA_HOME".into(),
        paths.gh_data_dir().display().to_string(),
    );
    environment.insert(
        "APPDATA".into(),
        paths.gh_config_dir().display().to_string(),
    );
    environment.insert(
        "LOCALAPPDATA".into(),
        paths.gh_data_dir().display().to_string(),
    );
    for variable in ["TMP", "TEMP", "TMPDIR"] {
        environment.insert(variable.into(), paths.gh_temp_dir().display().to_string());
    }
    environment.insert("GH_TOKEN".into(), token.expose().into());
    environment.insert("GH_HOST".into(), "github.com".into());
    environment.insert("GH_REPO".into(), format!("{owner}/{repository}"));
    environment.insert("GH_PROMPT_DISABLED".into(), "1".into());
    environment.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
    environment.insert("GH_EDITOR".into(), "false".into());
    environment.insert("GIT_EDITOR".into(), "false".into());
    environment.insert("VISUAL".into(), "false".into());
    environment.insert("EDITOR".into(), "false".into());
    environment.insert("GH_BROWSER".into(), "false".into());
    environment.insert("BROWSER".into(), "false".into());
    environment.insert("GH_PAGER".into(), "cat".into());
    environment.insert("PAGER".into(), "cat".into());
    environment.insert("GH_NO_UPDATE_NOTIFIER".into(), "1".into());
    environment.insert("GH_NO_EXTENSION_UPDATE_NOTIFIER".into(), "1".into());
    environment.insert("GH_TELEMETRY".into(), "false".into());
    environment.insert("DEV_AUTH_GH_CHILD".into(), "1".into());
    environment.insert("DEV_AUTH_GH_GIT".into(), git_program.into());
    environment
}

pub fn run_gh(arguments: &[String]) -> Result<ExitStatus> {
    let plan = crate::parse_gh_invocation(arguments)?;
    let selected_repository = preconfigured_gh_repository(plan.repository.clone())?;
    let paths = RuntimePaths::discover()?;
    let config = load_config(&paths)?;
    let (owner, repository) = resolve_gh_repository(selected_repository, &config.programs.git)?;
    ensure_gh_sandbox(&paths)?;
    #[cfg(windows)]
    let _frontend_guards = gh_child_frontend_guards(&paths)?;
    let program_guard = program_guard(&config.programs.gh, "GitHub CLI")?;
    validate_gh_version(&config.programs.gh, &paths, &program_guard)?;
    let forwarded = forwarded_gh_arguments(plan, &owner, &repository);
    let entry = token_entry_for_repository(&paths, &config, &owner, &repository)?;
    let token = entry.token().clone();
    let input: BTreeMap<String, String> = env::vars().collect();
    let environment = isolated_gh_environment(
        &input,
        &paths,
        &token,
        &owner,
        &repository,
        &config.programs.git,
    );
    guarded_command(&config.programs.gh, &program_guard)?
        .args(forwarded)
        .env_clear()
        .envs(environment)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("run repository-scoped gh command")
}

fn run_native_program(
    program: &str,
    description: &str,
    arguments: &[OsString],
) -> Result<ExitStatus> {
    let guard = program_guard(program, description)?;
    guarded_command(program, &guard)?
        .args(arguments)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("run configured native {description}"))
}

#[cfg(unix)]
fn exec_native_program(program: &str, description: &str, arguments: &[OsString]) -> Result<()> {
    let guard = program_guard(program, description)?;
    let error = guarded_command(program, &guard)?
        .args(arguments)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .exec();
    Err(error).with_context(|| format!("exec configured native {description}"))
}

pub fn run_native_git(arguments: &[OsString]) -> Result<ExitStatus> {
    #[cfg(unix)]
    {
        let (_, receipt) = crate::setup::current_frontend_installation()?;
        run_native_program(&receipt.native_git, "Git", arguments)
    }
    #[cfg(not(unix))]
    {
        let paths = RuntimePaths::discover()?;
        let config = load_config(&paths)?;
        run_native_program(&config.programs.git, "Git", arguments)
    }
}

pub fn run_native_gh(arguments: &[OsString]) -> Result<ExitStatus> {
    #[cfg(unix)]
    {
        let (_, receipt) = crate::setup::current_frontend_installation()?;
        run_native_program(&receipt.native_gh, "GitHub CLI", arguments)
    }
    #[cfg(not(unix))]
    {
        let paths = RuntimePaths::discover()?;
        let config = load_config(&paths)?;
        run_native_program(&config.programs.gh, "GitHub CLI", arguments)
    }
}

#[cfg(unix)]
pub fn exec_native_git(arguments: &[OsString]) -> Result<()> {
    let (_, receipt) = crate::setup::current_frontend_installation()?;
    exec_native_program(&receipt.native_git, "Git", arguments)
}

#[cfg(unix)]
pub fn exec_native_gh(arguments: &[OsString]) -> Result<()> {
    let (_, receipt) = crate::setup::current_frontend_installation()?;
    exec_native_program(&receipt.native_gh, "GitHub CLI", arguments)
}

#[cfg(target_os = "linux")]
pub fn exec_broker_git(arguments: &[OsString]) -> Result<()> {
    let (paths, receipt) = crate::setup::current_installation()?;
    let active = active_broker_profile(&receipt)?;
    let profile = &active.profile;
    let policy = &active.policy;
    let helper = paths.bin_dir.join("git-credential-dev-auth");
    let helper = helper
        .to_str()
        .context("broker Git credential-helper path is not UTF-8")?;
    if helper.chars().any(char::is_whitespace) {
        bail!("broker Git credential-helper path contains whitespace");
    }
    let ssh_keygen = paths.bin_dir.join("ssh-keygen-dev-auth");
    let ssh_keygen = ssh_keygen
        .to_str()
        .context("broker ssh-keygen adapter path is not UTF-8")?;
    if ssh_keygen.chars().any(char::is_whitespace) {
        bail!("broker ssh-keygen adapter path contains whitespace");
    }
    let ssh_command = if profile.ssh_keys.is_empty() {
        "/usr/bin/false"
    } else {
        &policy.programs.ssh
    };
    let configuration = broker_git_configuration(profile, helper, ssh_keygen, ssh_command);
    let signing_socket = validated_agent_socket(
        crate::broker_agent::SIGNING_AGENT_ENV,
        crate::broker_protocol::SshOperationPurpose::GitSigning,
        &active,
        profile.signing_key.is_some(),
    )?;
    let authentication_socket = validated_agent_socket(
        "SSH_AUTH_SOCK",
        crate::broker_protocol::SshOperationPurpose::Authentication,
        &active,
        !profile.ssh_keys.is_empty(),
    )?;
    let guard = program_guard(&receipt.native_git, "Git")?;
    let mut command = guarded_command(&receipt.native_git, &guard)?;
    remove_automation_credential_environment(&mut command);
    command
        .args(arguments)
        .env("GIT_CONFIG_COUNT", configuration.len().to_string())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/usr/bin/false")
        .env("SSH_ASKPASS", "/usr/bin/false")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for (index, (key, value)) in configuration.iter().enumerate() {
        command.env(format!("GIT_CONFIG_KEY_{index}"), key);
        command.env(format!("GIT_CONFIG_VALUE_{index}"), value);
    }
    if let Some(socket) = authentication_socket {
        command
            .env("SSH_AUTH_SOCK", socket)
            .env("GIT_SSH", &policy.programs.ssh)
            .env("GIT_SSH_VARIANT", "ssh");
    } else {
        command.env("GIT_SSH", "/usr/bin/false");
    }
    if let Some(socket) = signing_socket {
        command.env(crate::broker_agent::SIGNING_AGENT_ENV, socket);
    }
    let error = command.exec();
    Err(error).context("exec broker-authorized native Git")
}

#[cfg(target_os = "linux")]
fn broker_git_configuration(
    profile: &crate::policy_v2::ResolvedAuthorityProfile,
    credential_helper: &str,
    ssh_keygen: &str,
    ssh_command: &str,
) -> Vec<(String, String)> {
    let mut configuration = vec![
        ("credential.helper".to_owned(), String::new()),
        ("credential.helper".to_owned(), credential_helper.to_owned()),
        ("credential.useHttpPath".to_owned(), "true".to_owned()),
        ("credential.interactive".to_owned(), "never".to_owned()),
        ("core.askPass".to_owned(), "/usr/bin/false".to_owned()),
        ("core.sshCommand".to_owned(), ssh_command.to_owned()),
        ("http.extraHeader".to_owned(), String::new()),
        ("gpg.program".to_owned(), "/usr/bin/false".to_owned()),
    ];
    if let Some(identity) = &profile.git_identity {
        configuration.extend([
            ("user.name".to_owned(), identity.name.clone()),
            ("user.email".to_owned(), identity.email.clone()),
        ]);
    }
    if let Some(signing_key) = &profile.signing_key {
        configuration.extend([
            ("gpg.format".to_owned(), "ssh".to_owned()),
            ("gpg.ssh.program".to_owned(), ssh_keygen.to_owned()),
            (
                "user.signingKey".to_owned(),
                format!("key::{}", signing_key.public_key),
            ),
            ("commit.gpgSign".to_owned(), "true".to_owned()),
            ("tag.gpgSign".to_owned(), "true".to_owned()),
        ]);
    } else {
        configuration.extend([
            ("gpg.ssh.program".to_owned(), "/usr/bin/false".to_owned()),
            ("commit.gpgSign".to_owned(), "false".to_owned()),
            ("tag.gpgSign".to_owned(), "false".to_owned()),
        ]);
    }
    configuration
}

#[cfg(target_os = "linux")]
pub fn exec_broker_ssh_keygen(arguments: &[OsString]) -> Result<()> {
    let (_, receipt) = crate::setup::current_installation()?;
    let active = active_broker_profile(&receipt)?;
    let profile = &active.profile;
    let policy = &active.policy;
    if profile.signing_key.is_none() {
        bail!("workload profile has no broker signing authority");
    }
    let socket = validated_agent_socket(
        crate::broker_agent::SIGNING_AGENT_ENV,
        crate::broker_protocol::SshOperationPurpose::GitSigning,
        &active,
        true,
    )?
    .context("signing agent socket is unavailable")?;
    let guard = program_guard(&policy.programs.ssh_keygen, "ssh-keygen")?;
    let mut command = guarded_command(&policy.programs.ssh_keygen, &guard)?;
    remove_automation_credential_environment(&mut command);
    command
        .args(arguments)
        .env("SSH_AUTH_SOCK", socket)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let error = command.exec();
    Err(error).context("exec broker-backed native ssh-keygen")
}

#[cfg(target_os = "linux")]
struct ActiveBrokerProfile {
    session_id: String,
    owner_uid: u32,
    mode: crate::setup::InstallMode,
    profile: crate::policy_v2::ResolvedAuthorityProfile,
    policy: crate::policy_v2::ResolvedPolicy,
}

#[cfg(target_os = "linux")]
fn active_broker_profile(receipt: &crate::setup::InstallReceipt) -> Result<ActiveBrokerProfile> {
    let (_, probe) = crate::broker_client::active_claim_and_probe()?;
    let (session_id, owner_uid, execution_uid, profile_name) = match probe {
        crate::broker_protocol::BrokerSessionProbe::Verified {
            session_id,
            owner_uid,
            execution_uid,
            profile,
            ..
        } => (session_id, owner_uid, execution_uid, profile),
        _ => bail!("caller is outside a verified workload session"),
    };
    let expected_execution_uid = match receipt.mode {
        crate::setup::InstallMode::Strong => {
            crate::linux_platform::IdentityUserNamespace::from_current_process()
                .context("verified workload lacks its identity user namespace")?;
            nix::unistd::Uid::effective().as_raw()
        }
        crate::setup::InstallMode::UserOnly => nix::unistd::Uid::effective().as_raw(),
    };
    if execution_uid != expected_execution_uid {
        bail!("broker session execution identity does not match the caller");
    }
    let policy = match receipt.mode {
        crate::setup::InstallMode::Strong => {
            crate::policy_store::load_resolved_policy_for_uid(owner_uid)?
        }
        crate::setup::InstallMode::UserOnly => {
            crate::policy_store::load_user_only_resolved_policy_for_uid(owner_uid)?
        }
    };
    let profile = policy
        .authority_profiles
        .get(&profile_name)
        .context("active broker profile is no longer configured")?
        .clone();
    Ok(ActiveBrokerProfile {
        session_id,
        owner_uid,
        mode: receipt.mode,
        profile,
        policy,
    })
}

#[cfg(target_os = "linux")]
fn validated_agent_socket(
    variable: &str,
    purpose: crate::broker_protocol::SshOperationPurpose,
    active: &ActiveBrokerProfile,
    required: bool,
) -> Result<Option<PathBuf>> {
    let value = std::env::var_os(variable).map(PathBuf::from);
    let Some(socket) = value else {
        if required {
            bail!("configured workload capability has no broker SSH agent socket");
        }
        return Ok(None);
    };
    if !required {
        bail!("workload environment exposes an undeclared broker SSH agent");
    }
    let execution_uid = nix::unistd::Uid::effective().as_raw();
    if socket
        != crate::broker_agent::agent_socket_path(
            active.mode,
            active.owner_uid,
            &active.session_id,
            purpose,
        )
    {
        bail!("broker SSH agent socket does not match the admitted session");
    }
    let metadata = fs::symlink_metadata(&socket).context("inspect broker SSH agent socket")?;
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.uid() != execution_uid
        || metadata.mode() & 0o077 != 0
    {
        bail!("broker SSH agent socket has unsafe authority");
    }
    Ok(Some(socket))
}

#[cfg(target_os = "linux")]
pub fn exec_broker_gh(arguments: &[OsString], session_id: &str) -> Result<()> {
    if session_id.len() != 32 || !session_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("broker session identifier is invalid");
    }
    let token = match crate::broker_client::request_active(
        crate::broker_protocol::BrokerRequest::GhExecutionToken,
    )? {
        crate::broker_protocol::BrokerResponse::GhExecutionToken { token, .. } => token,
        crate::broker_protocol::BrokerResponse::Denied { code, message } => {
            bail!("broker denied GitHub CLI authority ({code}): {message}")
        }
        crate::broker_protocol::BrokerResponse::NoSession
        | crate::broker_protocol::BrokerResponse::Accepted
        | crate::broker_protocol::BrokerResponse::Ready { .. }
        | crate::broker_protocol::BrokerResponse::GitCredential { .. }
        | crate::broker_protocol::BrokerResponse::Signature { .. } => {
            bail!("broker returned an invalid GitHub CLI response")
        }
    };
    let (_, receipt) = crate::setup::current_installation()?;
    let active = active_broker_profile(&receipt)?;
    if active.session_id != session_id {
        bail!("GitHub CLI broker session changed during authorization");
    }
    let session_runtime = match receipt.mode {
        crate::setup::InstallMode::Strong => {
            let runtime = PathBuf::from(format!("/run/dev-auth-workload-{session_id}"));
            validate_private_directory(&runtime, "managed workload runtime")?;
            runtime
        }
        crate::setup::InstallMode::UserOnly => {
            let runtime = PathBuf::from(format!("/run/user/{}/dev-auth-v3", active.owner_uid));
            validate_private_directory(
                runtime.parent().context("broker runtime has no parent")?,
                "native-user login runtime",
            )?;
            ensure_private_directory(&runtime)?;
            let session_runtime = runtime.join(session_id);
            ensure_private_directory(&session_runtime)?;
            session_runtime
        }
    };
    let gh_config = session_runtime.join("gh");
    ensure_private_directory(&gh_config)?;

    let guard = program_guard(&receipt.native_gh, "GitHub CLI")?;
    let mut command = guarded_command(&receipt.native_gh, &guard)?;
    remove_automation_credential_environment(&mut command);
    command
        .args(arguments)
        .env("GH_TOKEN", token.expose())
        .env("GH_CONFIG_DIR", &gh_config)
        .env("GH_PROMPT_DISABLED", "1")
        .env("GH_NO_UPDATE_NOTIFIER", "1")
        .env("GH_NO_EXTENSION_UPDATE_NOTIFIER", "1")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let error = command.exec();
    Err(error).context("exec broker-authorized native GitHub CLI")
}

#[cfg(target_os = "linux")]
fn remove_automation_credential_environment(command: &mut Command) {
    for variable in [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "SSH_AUTH_SOCK",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
    ] {
        command.env_remove(variable);
    }
    for key in env::vars_os().map(|(key, _)| key) {
        let text = key.to_string_lossy();
        if text.starts_with("GIT_CONFIG_KEY_") || text.starts_with("GIT_CONFIG_VALUE_") {
            command.env_remove(key);
        }
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/usr/bin/false")
        .env("SSH_ASKPASS", "/usr/bin/false");
}

fn gh_version_is_supported(stdout: &[u8], stderr: &[u8]) -> bool {
    if !stderr.is_empty() {
        return false;
    }
    stdout == SUPPORTED_GH_VERSION_OUTPUT.as_bytes()
        || stdout == SUPPORTED_GH_VERSION_OUTPUT.replace('\n', "\r\n").as_bytes()
}

fn isolated_gh_probe_environment(paths: &RuntimePaths) -> BTreeMap<String, String> {
    let mut environment = BTreeMap::from([
        ("HOME".into(), paths.gh_home_dir().display().to_string()),
        (
            "GH_CONFIG_DIR".into(),
            paths.gh_config_dir().display().to_string(),
        ),
        (
            "XDG_CONFIG_HOME".into(),
            paths.gh_config_dir().display().to_string(),
        ),
        (
            "XDG_CACHE_HOME".into(),
            paths.gh_cache_dir().display().to_string(),
        ),
        (
            "XDG_DATA_HOME".into(),
            paths.gh_data_dir().display().to_string(),
        ),
        (
            "APPDATA".into(),
            paths.gh_config_dir().display().to_string(),
        ),
        (
            "LOCALAPPDATA".into(),
            paths.gh_data_dir().display().to_string(),
        ),
        ("TMP".into(), paths.gh_temp_dir().display().to_string()),
        ("TEMP".into(), paths.gh_temp_dir().display().to_string()),
        ("TMPDIR".into(), paths.gh_temp_dir().display().to_string()),
        ("GH_PROMPT_DISABLED".into(), "1".into()),
        ("GH_NO_UPDATE_NOTIFIER".into(), "1".into()),
        ("GH_NO_EXTENSION_UPDATE_NOTIFIER".into(), "1".into()),
        ("GH_TELEMETRY".into(), "false".into()),
    ]);
    for variable in ["COMSPEC", "PATHEXT", "SYSTEMROOT", "WINDIR"] {
        if let Ok(value) = env::var(variable) {
            environment.insert(variable.into(), value);
        }
    }
    environment
}

fn validate_gh_version(
    program: &str,
    paths: &RuntimePaths,
    program_guard: &ProgramGuard,
) -> Result<()> {
    let output = guarded_command(program, program_guard)?
        .arg("--version")
        .env_clear()
        .envs(isolated_gh_probe_environment(paths))
        .stdin(Stdio::null())
        .output()
        .context("inspect configured GitHub CLI version")?;
    if !output.status.success() || !gh_version_is_supported(&output.stdout, &output.stderr) {
        bail!(
            "configured GitHub CLI does not match the supported {} protocol",
            SUPPORTED_GH_VERSION
        );
    }
    Ok(())
}

fn valid_git_ref_fragment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value != "@"
        && !value.starts_with(['-', '.', '/'])
        && !value.ends_with(['.', '/'])
        && !value.contains("..")
        && !value.contains("@{")
        && !value.contains("//")
        && !value.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(character, '~' | '^' | ':' | '?' | '*' | '[' | '\\')
        })
        && value
            .split('/')
            .all(|component| !component.is_empty() && !component.ends_with(".lock"))
}

fn valid_full_ref(value: &str) -> bool {
    ["refs/heads/", "refs/remotes/"].iter().any(|prefix| {
        value
            .strip_prefix(prefix)
            .is_some_and(valid_git_ref_fragment)
    })
}

fn valid_remote_name(value: &str) -> bool {
    valid_git_ref_fragment(value) && !value.contains('/')
}

fn valid_log_range(value: &str) -> bool {
    let Some((base, head)) = value.split_once("...") else {
        return false;
    };
    !head.contains("...") && valid_git_ref_fragment(base) && valid_git_ref_fragment(head)
}

fn valid_commit_object(value: &str) -> bool {
    value == "HEAD"
        || matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || valid_full_ref(value)
}

fn unquote_go_regexp_literal(value: &str) -> Option<String> {
    const META: &str = r"\.+*?()|[]{}^$";
    let mut result = String::new();
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            let escaped = characters.next()?;
            if !META.contains(escaped) {
                return None;
            }
            result.push(escaped);
        } else if META.contains(character) {
            return None;
        } else {
            result.push(character);
        }
    }
    Some(result)
}

fn valid_branch_config_pattern(value: &str) -> bool {
    const PREFIX: &str = r"^branch\.";
    const SUFFIX: &str = r"\.(remote|merge|pushremote|gh-merge-base)$";
    value
        .strip_prefix(PREFIX)
        .and_then(|value| value.strip_suffix(SUFFIX))
        .and_then(unquote_go_regexp_literal)
        .is_some_and(|branch| valid_git_ref_fragment(&branch))
}

fn bounded_gh_git_arguments(arguments: &[String]) -> Result<Vec<String>> {
    let (signature_disabled, command_arguments) = match arguments {
        [flag, value, remaining @ ..] if flag == "-c" && value == "log.ShowSignature=false" => {
            (true, remaining)
        }
        _ => (false, arguments),
    };
    let arguments: Vec<&str> = command_arguments.iter().map(String::as_str).collect();
    let admitted = match arguments.as_slice() {
        ["remote", "-v"] => true,
        ["remote", "get-url", "--", remote] => valid_remote_name(remote),
        ["symbolic-ref", "--quiet", "HEAD"] => true,
        ["show-ref", "--verify", "--", references @ ..] => {
            !references.is_empty()
                && references
                    .iter()
                    .all(|reference| *reference == "HEAD" || valid_full_ref(reference))
        }
        ["config", "--get-regexp", r"^remote\..*\.gh-resolved$"] => true,
        ["config", "--get-regexp", pattern] => valid_branch_config_pattern(pattern),
        ["config", "push.default" | "remote.pushDefault"] => true,
        ["rev-parse", "--symbolic-full-name", revision] => revision
            .strip_suffix("@{push}")
            .is_some_and(valid_git_ref_fragment),
        ["rev-parse", "--verify", reference] => reference
            .strip_prefix("refs/heads/")
            .is_some_and(valid_git_ref_fragment),
        ["rev-parse", "--show-toplevel" | "--git-dir" | "--show-prefix"] => true,
        ["log", "--pretty=format:%H%x00%s%x00%b%x00", "--cherry", range] => {
            signature_disabled && valid_log_range(range)
        }
        ["show", "-s", "--pretty=format:%H,%s", "HEAD"] => signature_disabled,
        ["show", "-s", "--pretty=format:%b", object] => {
            signature_disabled && valid_commit_object(object)
        }
        _ => false,
    };
    if !admitted {
        bail!("internal gh Git operation is outside the bounded read-only surface");
    }
    Ok(command_arguments.to_vec())
}

pub fn run_gh_git_child(arguments: &[String]) -> Result<ExitStatus> {
    let arguments = bounded_gh_git_arguments(arguments)?;
    let program = env::var("DEV_AUTH_GH_GIT")
        .context("internal gh Git frontend has no configured executable")?;
    crate::validate_program(&program, "internal gh Git executable")?;
    let program_guard = program_guard(&program, "internal gh Git")?;
    let input: BTreeMap<String, String> = env::vars().collect();
    let mut environment = sanitize_environment(&input, &BTreeSet::new());
    let paths = RuntimePaths::discover()?;
    let parent = Path::new(&program)
        .parent()
        .context("configured Git executable has no parent directory")?;
    let path = env::join_paths([paths.gh_child_bin_dir(), parent.to_path_buf()])
        .context("construct bounded internal Git executable path")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("bounded internal Git executable path is not Unicode"))?;
    environment.insert("PATH".into(), path);
    environment.insert("HOME".into(), paths.gh_home_dir().display().to_string());
    environment.insert(
        "USERPROFILE".into(),
        paths.gh_home_dir().display().to_string(),
    );
    environment.insert(
        "XDG_CONFIG_HOME".into(),
        paths.gh_config_dir().display().to_string(),
    );
    environment.insert(
        "XDG_CACHE_HOME".into(),
        paths.gh_cache_dir().display().to_string(),
    );
    environment.insert(
        "XDG_DATA_HOME".into(),
        paths.gh_data_dir().display().to_string(),
    );
    environment.insert(
        "APPDATA".into(),
        paths.gh_config_dir().display().to_string(),
    );
    environment.insert(
        "LOCALAPPDATA".into(),
        paths.gh_data_dir().display().to_string(),
    );
    for variable in ["TMP", "TEMP", "TMPDIR"] {
        environment.insert(variable.into(), paths.gh_temp_dir().display().to_string());
    }
    environment.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
    environment.insert("GIT_ASKPASS".into(), "false".into());
    environment.insert("SSH_ASKPASS".into(), "false".into());
    environment.insert("GCM_INTERACTIVE".into(), "Never".into());
    environment.insert("GIT_EDITOR".into(), "false".into());
    environment.insert("GIT_SEQUENCE_EDITOR".into(), "false".into());
    environment.insert("GIT_PAGER".into(), "cat".into());
    environment.insert("GIT_SSH_COMMAND".into(), "false".into());
    environment.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
    environment.insert(
        "GIT_CONFIG_SYSTEM".into(),
        paths.gh_git_config_file().display().to_string(),
    );
    environment.insert(
        "GIT_CONFIG_GLOBAL".into(),
        paths.gh_git_config_file().display().to_string(),
    );
    environment.insert("GIT_ATTR_NOSYSTEM".into(), "1".into());
    environment.insert("GIT_NO_LAZY_FETCH".into(), "1".into());
    environment.insert("GIT_OPTIONAL_LOCKS".into(), "0".into());
    let attributes_file = paths.gh_git_attributes_file();
    let attributes_file = attributes_file
        .to_str()
        .context("private Git attributes path is not Unicode")?;
    let hooks_dir = paths.gh_git_hooks_dir();
    let hooks_dir = hooks_dir
        .to_str()
        .context("private Git hooks path is not Unicode")?;
    let config_overrides = [
        ("credential.helper", ""),
        ("credential.interactive", "false"),
        ("core.askPass", "false"),
        ("core.attributesFile", attributes_file),
        ("core.editor", "false"),
        ("core.excludesFile", attributes_file),
        ("core.hooksPath", hooks_dir),
        ("core.pager", "cat"),
        ("core.sshCommand", "false"),
        ("http.cookieFile", ""),
        ("http.extraHeader", ""),
        ("http.saveCookies", "false"),
        ("log.showSignature", "false"),
        ("sequence.editor", "false"),
    ];
    environment.insert(
        "GIT_CONFIG_COUNT".into(),
        config_overrides.len().to_string(),
    );
    for (index, (key, value)) in config_overrides.iter().enumerate() {
        environment.insert(format!("GIT_CONFIG_KEY_{index}"), (*key).into());
        environment.insert(format!("GIT_CONFIG_VALUE_{index}"), (*value).into());
    }
    environment.remove("GH_TOKEN");
    environment.remove("GITHUB_TOKEN");
    environment.remove("DEV_AUTH_GH_CHILD");
    environment.remove("DEV_AUTH_GH_GIT");
    guarded_command(&program, &program_guard)?
        .args(&arguments)
        .env_clear()
        .envs(environment)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("run configured Git without the GitHub installation token")
}

pub fn credential_erase(input: &[u8]) -> Result<()> {
    let (paths, config) = frontend_runtime_and_config()?;
    let request = CredentialRequest::parse(input)?;
    let (owner, repository) = request.repository()?;
    validate_bound_git_credential_authority(&config, owner, repository)?;
    ensure_runtime(&paths)?;
    let key = if config.github.discover_installations {
        dynamic_cache_key(
            config.github.app_id,
            config.github.repository_selection,
            owner,
            repository,
            &config.github.permissions,
        )?
    } else {
        let selected = config.github.select_repository(owner, repository)?;
        cache_key(
            config.github.app_id,
            selected.installation_id,
            config.github.repository_selection,
            &selected.repository,
            &config.github.permissions,
        )?
    };
    with_cache_scope_erase_lock(&paths, &key, || {
        match cache_entry(&config.credential_store, &key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error).context("remove native installation-token cache"),
        }
    })
}

fn declared_profile<'a>(config: &'a Config, name: &str) -> Result<&'a ExecProfile> {
    config
        .profiles
        .get(name)
        .context("requested execution profile is not declared")
}

fn ensure_exec_sandbox(paths: &RuntimePaths, profile_name: &str) -> Result<()> {
    ensure_runtime(paths)?;
    ensure_private_directory(&paths.exec_sandbox_dir())?;
    ensure_private_directory(&paths.exec_profile_dir(profile_name))?;
    for directory in [
        paths.exec_bin_dir(profile_name),
        paths.exec_config_dir(profile_name),
        paths.exec_home_dir(profile_name),
        paths.exec_cache_dir(profile_name),
        paths.exec_data_dir(profile_name),
        paths.exec_temp_dir(profile_name),
        paths.exec_runtime_dir(profile_name),
    ] {
        ensure_private_directory(&directory)?;
    }
    Ok(())
}

fn create_empty_exec_path(paths: &RuntimePaths, profile_name: &str) -> Result<tempfile::TempDir> {
    let directory = tempfile::Builder::new()
        .prefix("run-")
        .tempdir_in(paths.exec_bin_dir(profile_name))
        .context("create fresh private profile executable path")?;
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .context("restrict fresh profile executable path")?;
    validate_private_directory(directory.path(), "fresh profile executable path")?;
    if fs::read_dir(directory.path())
        .context("inspect fresh profile executable path")?
        .next()
        .is_some()
    {
        bail!("fresh profile executable path is not empty");
    }
    Ok(directory)
}

fn isolated_exec_environment(
    input: &BTreeMap<String, String>,
    paths: &RuntimePaths,
    profile_name: &str,
    executable_path: &Path,
) -> BTreeMap<String, String> {
    const PASS_THROUGH: &[&str] = &["COLORTERM", "LANG", "LC_ALL", "LC_CTYPE", "TERM"];
    let mut environment: BTreeMap<String, String> = input
        .iter()
        .filter(|(key, _)| {
            PASS_THROUGH
                .iter()
                .any(|allowed| key.eq_ignore_ascii_case(allowed))
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let home = paths.exec_home_dir(profile_name).display().to_string();
    let config = paths.exec_config_dir(profile_name).display().to_string();
    let cache = paths.exec_cache_dir(profile_name).display().to_string();
    let data = paths.exec_data_dir(profile_name).display().to_string();
    let temporary = paths.exec_temp_dir(profile_name).display().to_string();
    environment.insert("HOME".into(), home.clone());
    environment.insert("USERPROFILE".into(), home);
    environment.insert("PATH".into(), executable_path.display().to_string());
    environment.insert("XDG_CONFIG_HOME".into(), config.clone());
    environment.insert("XDG_CACHE_HOME".into(), cache);
    environment.insert("XDG_DATA_HOME".into(), data.clone());
    environment.insert(
        "XDG_RUNTIME_DIR".into(),
        paths.exec_runtime_dir(profile_name).display().to_string(),
    );
    environment.insert("APPDATA".into(), config);
    environment.insert("LOCALAPPDATA".into(), data);
    for variable in ["TMP", "TEMP", "TMPDIR"] {
        environment.insert(variable.into(), temporary.clone());
    }
    environment
}

pub fn exec_profile(profile_name: &str, command: &[String]) -> Result<ExitStatus> {
    let paths = RuntimePaths::discover()?;
    let config = load_config(&paths)?;
    let profile = declared_profile(&config, profile_name)?;
    let executable = command.first().context("profile command is missing")?;
    if !profile.executables.contains(executable) {
        bail!("command executable is not admitted by the selected profile");
    }
    let program_guard = program_guard(executable, "declared profile executable")?;
    ensure_exec_sandbox(&paths, profile_name)?;
    let executable_path = create_empty_exec_path(&paths, profile_name)?;
    let input: BTreeMap<String, String> = env::vars().collect();
    let mut child_environment =
        isolated_exec_environment(&input, &paths, profile_name, executable_path.path());
    for (variable, reference) in &profile.environment {
        child_environment.insert(
            variable.clone(),
            read_declared_secret(&config, reference)?.expose().into(),
        );
    }
    let mut child = guarded_command(executable, &program_guard)?;
    child
        .args(&command[1..])
        .env_clear()
        .envs(child_environment)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    child.status().context("run declared credential profile")
}

#[cfg(unix)]
fn ssh_agent_socket(paths: &RuntimePaths) -> PathBuf {
    paths.runtime.join("ssh-agent.sock")
}

#[cfg(windows)]
fn ssh_agent_pipe(paths: &RuntimePaths) -> String {
    let identity = Sha256::digest(paths.config.to_string_lossy().as_bytes());
    format!(r"\\.\pipe\dev-auth-ssh-agent-{identity:x}")
}

#[cfg(windows)]
#[derive(Debug)]
struct PrivateNamedPipeListener {
    server: NamedPipeServer,
    name: std::ffi::OsString,
}

#[cfg(windows)]
impl PrivateNamedPipeListener {
    fn bind(name: impl Into<std::ffi::OsString>) -> io::Result<Self> {
        let name = name.into();
        let server = windows_security::create_private_named_pipe(name.as_os_str(), true)?;
        Ok(Self { server, name })
    }

    fn next_server(&self) -> io::Result<NamedPipeServer> {
        windows_security::create_private_named_pipe(self.name.as_os_str(), false)
    }
}

#[cfg(windows)]
#[ssh_agent_lib::async_trait]
impl ListeningSocket for PrivateNamedPipeListener {
    type Stream = NamedPipeServer;

    async fn accept(&mut self) -> io::Result<Self::Stream> {
        self.server.connect().await?;
        let next = self.next_server()?;
        Ok(std::mem::replace(&mut self.server, next))
    }
}

#[cfg(unix)]
fn ssh_agent_endpoint(paths: &RuntimePaths) -> Result<String> {
    ssh_agent_socket(paths)
        .into_os_string()
        .into_string()
        .map_err(|_| anyhow::anyhow!("SSH agent socket path is not UTF-8"))
}

#[cfg(windows)]
fn ssh_agent_endpoint(paths: &RuntimePaths) -> Result<String> {
    Ok(ssh_agent_pipe(paths))
}

pub fn agent_endpoint() -> Result<String> {
    ssh_agent_endpoint(&RuntimePaths::discover()?)
}

#[cfg(unix)]
fn validate_ssh_agent_socket(paths: &RuntimePaths) -> Result<PathBuf> {
    let socket = ssh_agent_socket(paths);
    let metadata = fs::symlink_metadata(&socket).context("inspect dedicated SSH agent socket")?;
    if !metadata.file_type().is_socket() || metadata.uid() != rustix::process::geteuid().as_raw() {
        bail!("dedicated SSH agent socket is unavailable or not current-user owned");
    }
    Ok(socket)
}

fn ssh_add_command<'a>(
    paths: &RuntimePaths,
    config: &Config,
    program_guard: &'a ProgramGuard,
) -> Result<GuardedCommand<'a>> {
    #[cfg(unix)]
    validate_ssh_agent_socket(paths)?;
    let mut command = guarded_command(&config.programs.ssh_add, program_guard)?;
    command
        .env_clear()
        .envs(sanitized_current_environment())
        .env("SSH_AUTH_SOCK", ssh_agent_endpoint(paths)?)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(command)
}

pub fn run_ssh_keygen(arguments: &[String]) -> Result<ExitStatus> {
    let (paths, config) = frontend_runtime_and_config()?;
    let program_guard = program_guard(&config.programs.ssh_keygen, "ssh-keygen")?;
    if is_git_verification_operation(arguments)? {
        return guarded_command(&config.programs.ssh_keygen, &program_guard)?
            .args(arguments)
            .env_clear()
            .envs(sanitized_current_environment())
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .context("run public OpenSSH Git verification");
    }
    with_validated_git_signing_authority(
        || validate_bound_git_signing_authority(&config),
        || {
            ensure_runtime(&paths)?;
            #[cfg(unix)]
            validate_ssh_agent_socket(&paths)?;
            let loaded = loaded_ssh_fingerprints(&paths, &config)?;
            let profile_name = &config
                .git
                .as_ref()
                .context("Git workspace policy is not declared")?
                .ssh_profile;
            let profile = config
                .ssh_profiles
                .get(profile_name)
                .context("Git SSH signing profile is not declared")?;
            let expected: BTreeSet<String> = profile
                .keys
                .iter()
                .map(|key| key.fingerprint.clone())
                .collect();
            if loaded != expected {
                bail!("dedicated SSH agent keys do not match the Git signing profile");
            }
            validate_signing_key_argument(
                arguments,
                profile,
                &config.programs.ssh_keygen,
                &program_guard,
            )?;
            let input: BTreeMap<String, String> = env::vars().collect();
            let mut environment = sanitize_environment(&input, &BTreeSet::new());
            environment.insert("SSH_AUTH_SOCK".into(), ssh_agent_endpoint(&paths)?);
            guarded_command(&config.programs.ssh_keygen, &program_guard)?
                .args(arguments)
                .env_clear()
                .envs(environment)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .context("run OpenSSH key operation with the dedicated agent")
        },
    )
}

fn with_validated_git_signing_authority<A, S, T>(authorize: A, use_signing_agent: S) -> Result<T>
where
    A: FnOnce() -> Result<()>,
    S: FnOnce() -> Result<T>,
{
    authorize()?;
    use_signing_agent()
}

fn is_git_verification_operation(arguments: &[String]) -> Result<bool> {
    let operation = exact_option_value(arguments, "-Y")?;
    match operation {
        "sign" => Ok(false),
        "find-principals" => Ok(true),
        "verify" => {
            if exact_option_value(arguments, "-n")? != "git" {
                bail!("automation verification is restricted to the git namespace");
            }
            Ok(true)
        }
        _ => bail!("unsupported OpenSSH operation for Git signing or verification"),
    }
}

fn unique_declared_ssh_profile<'a>(
    config: &'a Config,
    loaded: &BTreeSet<String>,
) -> Result<&'a SshProfile> {
    let mut matches = config.ssh_profiles.values().filter(|profile| {
        profile
            .keys
            .iter()
            .map(|key| key.fingerprint.clone())
            .collect::<BTreeSet<_>>()
            == *loaded
    });
    let profile = matches
        .next()
        .context("dedicated SSH agent keys do not match a declared profile")?;
    if matches.next().is_some() {
        bail!("dedicated SSH agent keys match more than one declared profile");
    }
    Ok(profile)
}

fn validate_signing_key_argument(
    arguments: &[String],
    profile: &SshProfile,
    ssh_keygen_program: &str,
    program_guard: &ProgramGuard,
) -> Result<()> {
    if exact_option_value(arguments, "-Y")? != "sign" {
        return Ok(());
    }
    let public_key = exact_option_value(arguments, "-f")?;
    let namespace = exact_option_value(arguments, "-n")?;
    if namespace != "git" {
        bail!("automation signing is restricted to the git namespace");
    }
    let expected = profile
        .keys
        .iter()
        .find(|key| key.purpose == SshKeyPurpose::Signing)
        .context("declared SSH profile has no signing key")?;
    let output = guarded_command(ssh_keygen_program, program_guard)?
        .args(["-lf", public_key, "-E", "sha256"])
        .env_clear()
        .envs(sanitized_current_environment())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("inspect requested SSH signing key")?;
    if !output.status.success() {
        bail!("requested SSH signing public key is unreadable or invalid");
    }
    let text = String::from_utf8(output.stdout).context("SSH signing fingerprint is not UTF-8")?;
    let fingerprint = text
        .split_whitespace()
        .nth(1)
        .context("SSH signing fingerprint output is invalid")?;
    if fingerprint != expected.fingerprint {
        bail!("requested SSH signing key does not match the declared signing fingerprint");
    }
    Ok(())
}

fn exact_option_value<'a>(arguments: &'a [String], option: &str) -> Result<&'a str> {
    let mut values = arguments
        .windows(2)
        .filter(|pair| pair[0] == option)
        .map(|pair| pair[1].as_str());
    let value = values
        .next()
        .with_context(|| format!("OpenSSH operation requires exactly one {option} value"))?;
    if values.next().is_some() || value.starts_with('-') {
        bail!("OpenSSH operation requires exactly one {option} value");
    }
    Ok(value)
}

fn clear_ssh_agent(paths: &RuntimePaths, config: &Config) -> Result<()> {
    let program_guard = program_guard(&config.programs.ssh_add, "ssh-add")?;
    let mut command = ssh_add_command(paths, config, &program_guard)?;
    let status = command
        .arg("-D")
        .stdin(Stdio::null())
        .status()
        .context("clear dedicated SSH agent")?;
    if !status.success() {
        bail!("dedicated SSH agent rejected key removal");
    }
    Ok(())
}

fn loaded_ssh_fingerprints(paths: &RuntimePaths, config: &Config) -> Result<BTreeSet<String>> {
    let program_guard = program_guard(&config.programs.ssh_add, "ssh-add")?;
    let mut command = ssh_add_command(paths, config, &program_guard)?;
    let output = command
        .args(["-l", "-E", "sha256"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .output()
        .context("list dedicated SSH agent keys")?;
    if !output.status.success() {
        bail!("dedicated SSH agent rejected key listing");
    }
    let text = String::from_utf8(output.stdout).context("SSH agent key list is not UTF-8")?;
    let mut fingerprints = BTreeSet::new();
    for line in text.lines() {
        let fingerprint = line
            .split_whitespace()
            .nth(1)
            .context("SSH agent returned an invalid key-list row")?;
        if !crate::is_sha256_fingerprint(fingerprint)
            || !fingerprints.insert(fingerprint.to_owned())
        {
            bail!("SSH agent returned an invalid or duplicate fingerprint");
        }
    }
    Ok(fingerprints)
}

fn parse_agent_public_keys(text: &str) -> Result<BTreeMap<String, String>> {
    let mut keys = BTreeMap::new();
    for line in text.lines() {
        let public_key = PublicKey::from_openssh(line)
            .context("SSH agent returned an invalid public-key row")?;
        if public_key.algorithm() != SshAlgorithm::Ed25519 {
            bail!("SSH agent returned a non-Ed25519 public key");
        }
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        if keys.contains_key(&fingerprint) {
            bail!("SSH agent returned a duplicate public key");
        }
        let canonical = PublicKey::new(
            public_key.key_data().clone(),
            format!("dev-auth:{fingerprint}"),
        )
        .to_openssh()
        .context("encode declared SSH public key")?;
        keys.insert(fingerprint, canonical);
    }
    Ok(keys)
}

fn loaded_ssh_public_keys(
    paths: &RuntimePaths,
    config: &Config,
) -> Result<BTreeMap<String, String>> {
    let program_guard = program_guard(&config.programs.ssh_add, "ssh-add")?;
    let mut command = ssh_add_command(paths, config, &program_guard)?;
    let output = command
        .arg("-L")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .output()
        .context("list dedicated SSH agent public keys")?;
    if !output.status.success() {
        bail!("dedicated SSH agent rejected public-key listing");
    }
    let text =
        String::from_utf8(output.stdout).context("SSH agent public-key list is not UTF-8")?;
    parse_agent_public_keys(&text)
}

pub fn ssh_load(profile_name: &str) -> Result<()> {
    let paths = RuntimePaths::discover()?;
    ensure_runtime(&paths)?;
    let config = load_config(&paths)?;
    let profile = config
        .ssh_profiles
        .get(profile_name)
        .context("requested SSH profile is not declared")?;
    let expected: BTreeSet<String> = profile
        .keys
        .iter()
        .map(|key| key.fingerprint.clone())
        .collect();
    let loaded = loaded_ssh_fingerprints(&paths, &config)?;
    if loaded != expected {
        bail!("dedicated SSH agent fingerprints do not match the declared profile");
    }
    Ok(())
}

pub fn ssh_public(profile_name: &str, purpose: SshKeyPurpose) -> Result<String> {
    let paths = RuntimePaths::discover()?;
    ensure_runtime(&paths)?;
    let config = load_config(&paths)?;
    let profile = config
        .ssh_profiles
        .get(profile_name)
        .context("requested SSH profile is not declared")?;
    let expected: BTreeSet<String> = profile
        .keys
        .iter()
        .map(|key| key.fingerprint.clone())
        .collect();
    let loaded = loaded_ssh_public_keys(&paths, &config)?;
    if loaded.keys().cloned().collect::<BTreeSet<_>>() != expected {
        bail!("dedicated SSH agent public keys do not match the declared profile");
    }
    let declared = profile
        .keys
        .iter()
        .find(|key| key.purpose == purpose)
        .context("declared SSH profile does not contain the requested key purpose")?;
    loaded
        .get(&declared.fingerprint)
        .cloned()
        .context("requested declared SSH public key is not loaded")
}

struct AgentIdentity {
    private_key: PrivateKey,
    public_key: PublicKey,
    fingerprint: String,
}

#[derive(Clone)]
struct DeclaredAgent {
    identities: Arc<RwLock<Vec<AgentIdentity>>>,
}

impl DeclaredAgent {
    fn new(identities: Vec<AgentIdentity>) -> Self {
        Self {
            identities: Arc::new(RwLock::new(identities)),
        }
    }
}

fn agent_failure(message: &'static str) -> AgentError {
    AgentError::other(io::Error::other(message))
}

#[ssh_agent_lib::async_trait]
impl Session for DeclaredAgent {
    async fn request_identities(&mut self) -> std::result::Result<Vec<Identity>, AgentError> {
        let identities = self
            .identities
            .read()
            .map_err(|_| agent_failure("SSH identity lock is poisoned"))?;
        Ok(identities
            .iter()
            .map(|identity| Identity {
                credential: PublicCredential::Key(identity.public_key.key_data().clone()),
                comment: format!("dev-auth:{}", identity.fingerprint),
            })
            .collect())
    }

    async fn sign(&mut self, request: SignRequest) -> std::result::Result<Signature, AgentError> {
        if request.flags != 0 {
            return Err(agent_failure("unsupported SSH signature flags"));
        }
        let PublicCredential::Key(requested) = request.credential else {
            return Err(agent_failure(
                "SSH certificates are not declared identities",
            ));
        };
        let identities = self
            .identities
            .read()
            .map_err(|_| agent_failure("SSH identity lock is poisoned"))?;
        let identity = identities
            .iter()
            .find(|identity| identity.public_key.key_data() == &requested)
            .ok_or_else(|| agent_failure("SSH signing identity is not declared"))?;
        identity
            .private_key
            .try_sign(&request.data)
            .map_err(AgentError::other)
    }

    async fn remove_all_identities(&mut self) -> std::result::Result<(), AgentError> {
        self.identities
            .write()
            .map_err(|_| agent_failure("SSH identity lock is poisoned"))?
            .clear();
        Ok(())
    }
}

#[cfg(windows)]
impl Agent<PrivateNamedPipeListener> for DeclaredAgent {
    fn new_session(&mut self, _socket: &NamedPipeServer) -> impl Session {
        self.clone()
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn broker_sign_ssh(
    op_program: &str,
    service_token: &SecretString,
    private_key_ref: &str,
    declared_public_key: &str,
    declared_fingerprint: &str,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.is_empty() || payload.len() > 1024 * 1024 {
        bail!("SSH signing payload size is invalid");
    }
    let source = read_declared_secret_with_token(op_program, service_token, private_key_ref)?;
    let private_key = parse_declared_ssh_private_key(&source)?;
    let public_key = PublicKey::from_openssh(declared_public_key)
        .context("declared operation public key is invalid")?;
    if private_key.public_key().key_data() != public_key.key_data()
        || public_key.fingerprint(HashAlg::Sha256).to_string() != declared_fingerprint
    {
        bail!("declared operation key identity does not match private material");
    }
    let signature = private_key
        .try_sign(payload)
        .context("perform broker-backed SSH signature")?;
    Vec::<u8>::try_from(signature).context("encode broker-backed SSH signature")
}

fn parse_declared_ssh_private_key(source: &SecretString) -> Result<PrivateKey> {
    if let Ok(private_key) = PrivateKey::from_openssh(source.expose().as_bytes()) {
        return Ok(private_key);
    }
    let signing_key = ed25519_dalek::SigningKey::from_pkcs8_pem(source.expose())
        .map_err(|_| anyhow::anyhow!("declared SSH key is not supported private-key material"))?;
    PrivateKey::new(
        KeypairData::Ed25519(Ed25519Keypair::from(signing_key)),
        "dev-auth automation key",
    )
    .context("construct declared Ed25519 SSH key")
}

pub fn validate_configuration(online: bool) -> Result<ValidationReport> {
    let paths = git_runtime::native_runtime_paths()?;
    let config = load_config(&paths)?;
    let gh_program_guard = program_guard(&config.programs.gh, "GitHub CLI")?;
    validate_gh_version(&config.programs.gh, &paths, &gh_program_guard)?;
    if config.git.is_some() {
        let git_program_guard = program_guard(&config.programs.git, "Git")?;
        validate_git_version(&config.programs.git, &git_program_guard)?;
        git_runtime::validate_workspace_policy(&config)?;
    }
    let references = config.declared_secret_references();
    if online {
        let mut secrets = BTreeMap::new();
        for reference in &references {
            secrets.insert(reference, read_declared_secret(&config, reference)?);
        }
        let app_key = secrets
            .get(&config.github.private_key_ref)
            .context("declared GitHub App private key was not checked")?;
        EncodingKey::from_rsa_pem(app_key.expose().as_bytes())
            .context("GitHub App private key is not a valid RSA PEM key")?;
        for profile in config.ssh_profiles.values() {
            for key in &profile.keys {
                let source = secrets
                    .get(&key.private_key_ref)
                    .context("declared SSH private key was not checked")?;
                let private_key = parse_declared_ssh_private_key(source)?;
                if private_key.is_encrypted() || private_key.algorithm() != SshAlgorithm::Ed25519 {
                    bail!("declared SSH key must be an unencrypted Ed25519 OpenSSH key");
                }
                if private_key
                    .public_key()
                    .fingerprint(HashAlg::Sha256)
                    .to_string()
                    != key.fingerprint
                {
                    bail!("declared SSH key fingerprint does not match its private key");
                }
            }
        }
    }
    Ok(ValidationReport {
        online,
        declared_exec_profiles: config.profiles.len(),
        declared_ssh_profiles: config.ssh_profiles.len(),
        declared_secret_references: references.len(),
    })
}

fn declared_agent(config: &Config, profile: &SshProfile) -> Result<DeclaredAgent> {
    let mut identities = Vec::with_capacity(profile.keys.len());
    for declared in &profile.keys {
        let source = read_declared_secret(config, &declared.private_key_ref)?;
        let private_key = parse_declared_ssh_private_key(&source)?;
        if private_key.is_encrypted() || private_key.algorithm() != SshAlgorithm::Ed25519 {
            bail!("declared SSH key must be an unencrypted Ed25519 OpenSSH key");
        }
        let public_key = private_key.public_key().clone();
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        if fingerprint != declared.fingerprint {
            bail!("declared SSH key fingerprint does not match its private key");
        }
        identities.push(AgentIdentity {
            private_key,
            public_key,
            fingerprint,
        });
    }
    Ok(DeclaredAgent::new(identities))
}

#[cfg(unix)]
fn prepare_unix_agent_socket(paths: &RuntimePaths) -> Result<UnixListener> {
    let socket = ssh_agent_socket(paths);
    if socket.exists() {
        let metadata = fs::symlink_metadata(&socket).context("inspect stale SSH agent socket")?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            bail!("existing SSH agent endpoint is not a current-user socket");
        }
        fs::remove_file(&socket).context("remove stale SSH agent socket")?;
    }
    UnixListener::bind(&socket).context("bind dedicated SSH agent socket")
}

pub fn run_agent(profile_name: &str) -> Result<()> {
    let paths = RuntimePaths::discover()?;
    ensure_runtime(&paths)?;
    let config = load_config(&paths)?;
    let profile = config
        .ssh_profiles
        .get(profile_name)
        .context("requested SSH profile is not declared")?;
    let lock = private_open(&paths.runtime.join("ssh-agent.lock"))?;
    lock.try_lock_exclusive()
        .context("another dedicated SSH agent is already active")?;
    let agent = declared_agent(&config, profile)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .context("create dedicated SSH agent runtime")?;

    #[cfg(unix)]
    {
        let listener = {
            let _runtime_guard = runtime.enter();
            prepare_unix_agent_socket(&paths)?
        };
        let result = runtime.block_on(listen(listener, agent));
        let _ = fs::remove_file(ssh_agent_socket(&paths));
        result.context("run dedicated SSH agent")?;
    }
    #[cfg(windows)]
    {
        let listener = {
            let _runtime_guard = runtime.enter();
            PrivateNamedPipeListener::bind(ssh_agent_pipe(&paths))
                .context("bind dedicated SSH agent named pipe")?
        };
        runtime
            .block_on(listen(listener, agent))
            .context("run dedicated SSH agent")?;
    }
    Ok(())
}

pub fn runtime_status() -> Result<RuntimeStatus> {
    let paths = RuntimePaths::discover()?;
    let config = load_config(&paths);
    let config_ready = config.is_ok();
    let service_token_enrolled = config
        .as_ref()
        .is_ok_and(|config| service_account_token(&config.credential_store).is_ok());
    let runtime_ready = ensure_runtime(&paths).is_ok();
    let ssh_agent_ready = config.as_ref().is_ok_and(|config| {
        config.ssh_profiles.is_empty()
            || loaded_ssh_fingerprints(&paths, config)
                .and_then(|loaded| unique_declared_ssh_profile(config, &loaded).map(|_| ()))
                .is_ok()
    });
    let cached_installation_tokens = config
        .as_ref()
        .ok()
        .and_then(|config| {
            fs::read_dir(paths.cache_dir()).ok().map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter_map(|entry| {
                        let path = entry.path();
                        if !path.extension().is_some_and(|value| value == "lock") {
                            return None;
                        }
                        path.file_stem()?.to_str().map(str::to_owned)
                    })
                    .filter(|key| read_cache(&config.credential_store, key).is_ok())
                    .count()
            })
        })
        .unwrap_or(0);
    Ok(RuntimeStatus {
        config_ready,
        service_token_enrolled,
        runtime_ready,
        ssh_agent_ready,
        cached_installation_tokens,
    })
}

pub fn purge_runtime() -> Result<()> {
    let paths = RuntimePaths::discover()?;
    let config = load_config(&paths)?;
    with_cache_purge_lock(&paths, || {
        let mut scopes = Vec::<(String, PathBuf)>::new();
        for entry in fs::read_dir(paths.cache_dir()).context("enumerate dev-auth runtime cache")? {
            let entry = entry.context("read dev-auth runtime cache entry")?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("lock") {
                bail!("unknown file in dev-auth runtime cache");
            }
            let key = path
                .file_stem()
                .and_then(|value| value.to_str())
                .context("runtime lock has an invalid cache key")?
                .to_owned();
            let _ = private_read(&path, "installation-token scope receipt")?;
            scopes.push((key, path));
        }
        scopes.sort_by(|left, right| left.0.cmp(&right.0));

        if loaded_ssh_fingerprints(&paths, &config).is_ok() {
            clear_ssh_agent(&paths, &config)?;
        }
        for (key, path) in scopes {
            match cache_entry(&config.credential_store, &key)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(error) => return Err(error).context("purge native installation-token cache"),
            }
            fs::remove_file(&path).context("remove purged installation-token scope receipt")?;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GitHubProfile, SshKey};
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ssh_key::private::{Ed25519Keypair, KeypairData};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(target_os = "linux")]
    use std::os::unix::net::UnixListener as StdUnixListener;
    use std::sync::mpsc;
    #[cfg(unix)]
    use std::sync::{Arc, Barrier};
    use std::thread;

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

    #[cfg(target_os = "linux")]
    fn linux_program_test_directory() -> tempfile::TempDir {
        let home = BaseDirs::new().unwrap();
        tempfile::Builder::new()
            .prefix("dev-auth-program-guard-")
            .tempdir_in(home.home_dir())
            .unwrap()
    }

    #[cfg(target_os = "linux")]
    fn write_linux_test_program(path: &Path, output: &str, mode: u32) {
        fs::write(path, format!("#!/bin/sh\nprintf {output}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn credential_authority_failure_precedes_every_token_source() {
        let token_source_called = std::cell::Cell::new(false);
        let result = credential_get_with_sources(
            b"protocol=https\nhost=github.com\npath=ExampleOrg/repository.git\n\n",
            |_owner, _repository| bail!("bound repository authority mismatch"),
            |_owner, _repository| -> Result<CacheEntry> {
                token_source_called.set(true);
                bail!("token source must not run")
            },
        );
        assert!(result.is_err());
        assert!(!token_source_called.get());
    }

    #[test]
    fn signing_authority_failure_precedes_every_agent_access() {
        let agent_accessed = std::cell::Cell::new(false);
        let result = with_validated_git_signing_authority(
            || bail!("bound repository authority mismatch"),
            || -> Result<()> {
                agent_accessed.set(true);
                bail!("signing agent must not be accessed")
            },
        );
        assert!(result.is_err());
        assert!(!agent_accessed.get());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_program_guard_executes_the_held_identity_after_path_replacement() {
        let temporary = linux_program_test_directory();
        let program = temporary.path().join("tool");
        write_linux_test_program(&program, "original", 0o755);

        let guard = program_guard(program.to_str().unwrap(), "test program").unwrap();
        let mut command = guarded_command(program.to_str().unwrap(), &guard).unwrap();
        let held_path = temporary.path().join("held-tool");
        fs::rename(&program, &held_path).unwrap();
        write_linux_test_program(&program, "replacement", 0o755);

        let output = command.output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"original");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_program_guard_rejects_final_and_ancestor_symlinks() {
        let temporary = linux_program_test_directory();
        let real_directory = temporary.path().join("real");
        fs::create_dir(&real_directory).unwrap();
        fs::set_permissions(&real_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let program = real_directory.join("tool");
        write_linux_test_program(&program, "trusted", 0o755);
        assert!(program_guard(real_directory.to_str().unwrap(), "test program",).is_err());

        let final_link = temporary.path().join("tool-link");
        std::os::unix::fs::symlink(&program, &final_link).unwrap();
        assert!(program_guard(final_link.to_str().unwrap(), "test program").is_err());

        let ancestor_link = temporary.path().join("directory-link");
        std::os::unix::fs::symlink(&real_directory, &ancestor_link).unwrap();
        assert!(
            program_guard(ancestor_link.join("tool").to_str().unwrap(), "test program",).is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_program_guard_rejects_writable_or_non_executable_components() {
        let temporary = linux_program_test_directory();
        let directory = temporary.path().join("bin");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let program = directory.join("tool");

        write_linux_test_program(&program, "unsafe", 0o775);
        assert!(program_guard(program.to_str().unwrap(), "test program").is_err());

        write_linux_test_program(&program, "not-executable", 0o600);
        assert!(program_guard(program.to_str().unwrap(), "test program").is_err());

        write_linux_test_program(&program, "unsafe-ancestor", 0o700);
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(program_guard(program.to_str().unwrap(), "test program").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_program_identity_applies_effective_owner_and_group_execute_bits() {
        let user = LinuxProgramIdentity {
            effective_user: 1000,
            effective_groups: BTreeSet::from([2000]),
        };
        assert!(user.can_execute(1000, 3000, 0o100));
        assert!(user.can_execute(0, 2000, 0o010));
        assert!(user.can_execute(0, 3000, 0o001));
        assert!(!user.can_execute(0, 3000, 0o010));

        let root = LinuxProgramIdentity {
            effective_user: 0,
            effective_groups: BTreeSet::new(),
        };
        assert!(root.can_execute(0, 0, 0o001));
        assert!(!root.can_execute(0, 0, 0o600));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_program_filesystem_policy_rejects_remote_and_host_shared_types() {
        for filesystem_type in [
            0x0000_6969,
            0xff53_4d42,
            0x0102_1997,
            0x6573_5546,
            0x786f_4256,
        ] {
            assert!(!linux_program_filesystem_is_local(filesystem_type));
        }
        for filesystem_type in [0x0000_ef53, 0x9123_683e, 0x794c_7630, 0x0102_1994] {
            assert!(linux_program_filesystem_is_local(filesystem_type));
        }
    }

    #[test]
    fn gh_version_parser_accepts_only_the_reviewed_protocol_release() {
        assert!(gh_version_is_supported(
            SUPPORTED_GH_VERSION_OUTPUT.as_bytes(),
            b""
        ));
        assert!(gh_version_is_supported(
            SUPPORTED_GH_VERSION_OUTPUT.replace('\n', "\r\n").as_bytes(),
            b""
        ));
        for output in [
            b"gh version 2.98.0 (2026-08-20)\nhttps://github.com/cli/cli/releases/tag/v2.98.0\n"
                .as_slice(),
            b"gh version 2.97.0 (2026-08-13)\n".as_slice(),
            b"gh version 2.99.0 (2026-08-27)\n".as_slice(),
            b"attacker gh version 2.98.0\n".as_slice(),
            b"gh version\n".as_slice(),
            b"\xff\n".as_slice(),
        ] {
            assert!(!gh_version_is_supported(output, b""));
        }
        assert!(!gh_version_is_supported(
            SUPPORTED_GH_VERSION_OUTPUT.as_bytes(),
            b"warning\n"
        ));
    }

    #[test]
    fn installation_token_request_is_narrowed_by_repository_name() {
        let permissions = BTreeMap::from([("contents".into(), "write".into())]);
        let repositories = vec!["brand-new-repository".to_owned()];
        let request = InstallationTokenRequest {
            repositories: &repositories,
            permissions: &permissions,
        };
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({
                "repositories": ["brand-new-repository"],
                "permissions": {"contents": "write"}
            })
        );
    }

    #[test]
    fn dynamic_cache_scope_is_case_insensitive_and_owner_specific() {
        let permissions = BTreeMap::from([("contents".into(), "write".into())]);
        let expected = dynamic_cache_key(
            42,
            crate::RepositorySelection::All,
            "ExampleOrg",
            "Sample-Repo",
            &permissions,
        )
        .unwrap();
        assert_eq!(
            expected,
            dynamic_cache_key(
                42,
                crate::RepositorySelection::All,
                "exampleorg",
                "sample-repo",
                &permissions,
            )
            .unwrap()
        );
        assert_ne!(
            expected,
            dynamic_cache_key(
                42,
                crate::RepositorySelection::All,
                "AnotherOrg",
                "sample-repo",
                &permissions,
            )
            .unwrap()
        );
        assert_ne!(
            expected,
            dynamic_cache_key(
                99,
                crate::RepositorySelection::All,
                "ExampleOrg",
                "Sample-Repo",
                &permissions,
            )
            .unwrap()
        );
        assert_ne!(
            expected,
            dynamic_cache_key(
                42,
                crate::RepositorySelection::Selected,
                "ExampleOrg",
                "Sample-Repo",
                &permissions,
            )
            .unwrap()
        );
    }

    fn test_cache_entry(installation_id: u64) -> CacheEntry {
        CacheEntry::new_for_test(
            SecretString::new("test-token".into()),
            10_000,
            42,
            installation_id,
            "exampleorg".into(),
            "sample-repo".into(),
            BTreeMap::from([("contents".into(), "write".into())]),
        )
    }

    #[test]
    fn dynamic_cache_hit_fails_closed_when_live_discovery_fails() {
        use std::cell::Cell;

        let cache_was_read = Cell::new(false);
        let result = resolve_dynamic_cache_entry(
            DynamicRepositoryScope {
                now: 1,
                app_id: 42,
                owner: "exampleorg",
                repository: "sample-repo",
                permissions: &BTreeMap::from([("contents".into(), "write".into())]),
            },
            || bail!("live installation authority is unavailable"),
            || {
                cache_was_read.set(true);
                Ok(test_cache_entry(101))
            },
            |_| panic!("mint must not run after failed discovery"),
            |_| panic!("write must not run after failed discovery"),
        );

        assert!(result.is_err());
        assert!(!cache_was_read.get());
    }

    #[test]
    fn dynamic_cache_hit_with_stale_installation_id_is_refreshed() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let written = RefCell::new(None);
        let permissions = BTreeMap::from([("contents".into(), "write".into())]);
        let result = resolve_dynamic_cache_entry(
            DynamicRepositoryScope {
                now: 1,
                app_id: 42,
                owner: "exampleorg",
                repository: "sample-repo",
                permissions: &permissions,
            },
            || {
                events.borrow_mut().push("discover");
                Ok(SelectedRepository {
                    installation_id: 202,
                    owner: "exampleorg".into(),
                    repository: "sample-repo".into(),
                })
            },
            || {
                events.borrow_mut().push("read");
                Ok(test_cache_entry(101))
            },
            |installation_id| {
                events.borrow_mut().push("mint");
                Ok(test_cache_entry(installation_id))
            },
            |entry| {
                events.borrow_mut().push("write");
                *written.borrow_mut() = Some(entry.clone());
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(result.installation_id(), 202);
        assert_eq!(written.borrow().as_ref().unwrap().installation_id(), 202);
        assert_eq!(*events.borrow(), ["discover", "read", "mint", "write"]);
    }

    #[test]
    fn dynamic_cache_hit_with_current_installation_is_reused_after_discovery() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let permissions = BTreeMap::from([("contents".into(), "write".into())]);
        let result = resolve_dynamic_cache_entry(
            DynamicRepositoryScope {
                now: 1,
                app_id: 42,
                owner: "exampleorg",
                repository: "sample-repo",
                permissions: &permissions,
            },
            || {
                events.borrow_mut().push("discover");
                Ok(SelectedRepository {
                    installation_id: 202,
                    owner: "exampleorg".into(),
                    repository: "sample-repo".into(),
                })
            },
            || {
                events.borrow_mut().push("read");
                Ok(test_cache_entry(202))
            },
            |_| panic!("mint must not run for a current cache entry"),
            |_| panic!("write must not run for a current cache entry"),
        )
        .unwrap();

        assert_eq!(result.installation_id(), 202);
        assert_eq!(*events.borrow(), ["discover", "read"]);
    }

    #[test]
    fn gh_child_environment_replaces_ambient_execution_and_ui_surfaces() {
        let paths = RuntimePaths {
            config: PathBuf::from("/private/config.toml"),
            runtime: PathBuf::from("/private/runtime"),
        };
        let input = BTreeMap::from([
            ("HOME".into(), "/home/example".into()),
            ("PATH".into(), "/attacker/bin".into()),
            ("GH_TOKEN".into(), "human-token".into()),
            ("GITHUB_TOKEN".into(), "human-token".into()),
            ("GH_EDITOR".into(), "/attacker/editor".into()),
            ("BROWSER".into(), "/attacker/browser".into()),
            ("PAGER".into(), "/attacker/pager".into()),
            ("COMSPEC".into(), "/attacker/shell".into()),
        ]);
        let environment = isolated_gh_environment(
            &input,
            &paths,
            &SecretString::new("installation-token".into()),
            "example",
            "repository",
            "/trusted/bin/git",
        );
        assert_eq!(
            environment["HOME"],
            paths.gh_home_dir().display().to_string()
        );
        assert_eq!(
            environment["XDG_CONFIG_HOME"],
            paths.gh_config_dir().display().to_string()
        );
        assert_eq!(
            environment["XDG_CACHE_HOME"],
            paths.gh_cache_dir().display().to_string()
        );
        assert_eq!(
            environment["XDG_DATA_HOME"],
            paths.gh_data_dir().display().to_string()
        );
        assert_eq!(
            environment["PATH"],
            paths.gh_child_bin_dir().display().to_string()
        );
        assert_eq!(environment["GH_TOKEN"], "installation-token");
        assert!(!environment.contains_key("GITHUB_TOKEN"));
        assert_eq!(environment["GH_EDITOR"], "false");
        assert_eq!(environment["BROWSER"], "false");
        assert_eq!(environment["PAGER"], "cat");
        assert_eq!(environment["DEV_AUTH_GH_CHILD"], "1");
        assert_eq!(environment["DEV_AUTH_GH_GIT"], "/trusted/bin/git");
        assert!(!environment.contains_key("COMSPEC"));
        assert!(!environment.values().any(|value| value.contains("attacker")));
        assert!(!environment.values().any(|value| value == "/home/example"));
    }

    #[test]
    fn profile_child_environment_replaces_ambient_helpers_and_human_config() {
        let paths = RuntimePaths {
            config: PathBuf::from("/private/config.toml"),
            runtime: PathBuf::from("/private/runtime"),
        };
        let input = BTreeMap::from([
            ("HOME".into(), "/home/example".into()),
            ("USERPROFILE".into(), "C:\\Users\\example".into()),
            ("PATH".into(), "/attacker/bin".into()),
            ("APPDATA".into(), "C:\\Users\\example\\AppData".into()),
            ("LOCALAPPDATA".into(), "C:\\Users\\example\\Local".into()),
            ("XDG_CONFIG_HOME".into(), "/home/example/.config".into()),
            ("XDG_CACHE_HOME".into(), "/home/example/.cache".into()),
            ("XDG_DATA_HOME".into(), "/home/example/.local/share".into()),
            ("COMSPEC".into(), "C:\\attacker\\cmd.exe".into()),
            (
                "DBUS_SESSION_BUS_ADDRESS".into(),
                "unix:path=/attacker/bus".into(),
            ),
            ("DISPLAY".into(), ":99".into()),
            ("GH_TOKEN".into(), "human-token".into()),
        ]);

        let executable_path = paths
            .exec_bin_dir("profile-a")
            .join("fresh-execution-directory");
        let environment = isolated_exec_environment(&input, &paths, "profile-a", &executable_path);

        assert_eq!(
            environment["HOME"],
            paths
                .runtime
                .join("exec-sandbox/profile-a/home")
                .display()
                .to_string()
        );
        assert_eq!(
            environment["USERPROFILE"],
            paths
                .runtime
                .join("exec-sandbox/profile-a/home")
                .display()
                .to_string()
        );
        assert_eq!(environment["PATH"], executable_path.display().to_string());
        assert_eq!(
            environment["XDG_CONFIG_HOME"],
            paths
                .runtime
                .join("exec-sandbox/profile-a/config")
                .display()
                .to_string()
        );
        assert_eq!(
            environment["XDG_CACHE_HOME"],
            paths
                .runtime
                .join("exec-sandbox/profile-a/cache")
                .display()
                .to_string()
        );
        assert_eq!(
            environment["XDG_DATA_HOME"],
            paths
                .runtime
                .join("exec-sandbox/profile-a/data")
                .display()
                .to_string()
        );
        for variable in ["COMSPEC", "DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "GH_TOKEN"] {
            assert!(!environment.contains_key(variable));
        }
        assert!(!environment.values().any(|value| value.contains("attacker")));
        assert!(!environment.values().any(|value| value == "/home/example"));
        assert!(!environment
            .values()
            .any(|value| value == "C:\\Users\\example"));
    }

    #[test]
    fn profile_sandbox_is_private_empty_and_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("runtime/dev-auth");
        let paths = RuntimePaths {
            config: root.path().join("config.toml"),
            runtime,
        };

        ensure_exec_sandbox(&paths, "profile-a").unwrap();
        ensure_exec_sandbox(&paths, "profile-a").unwrap();

        for directory in [
            paths.exec_sandbox_dir(),
            paths.exec_profile_dir("profile-a"),
            paths.exec_bin_dir("profile-a"),
            paths.exec_config_dir("profile-a"),
            paths.exec_home_dir("profile-a"),
            paths.exec_cache_dir("profile-a"),
            paths.exec_data_dir("profile-a"),
            paths.exec_temp_dir("profile-a"),
            paths.exec_runtime_dir("profile-a"),
        ] {
            let metadata = fs::symlink_metadata(&directory).unwrap();
            assert!(metadata.file_type().is_dir());
            assert!(!metadata.file_type().is_symlink());
            #[cfg(unix)]
            assert_eq!(metadata.permissions().mode() & 0o077, 0);
        }
        assert_eq!(
            fs::read_dir(paths.exec_bin_dir("profile-a"))
                .unwrap()
                .count(),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_private_directory_creation_is_idempotent_but_unsafe_objects_fail() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let target = root.path().join("runtime");
        let barrier = Arc::new(Barrier::new(8));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let target = target.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                ensure_private_directory(&target)
            }));
        }
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        let metadata = fs::symlink_metadata(&target).unwrap();
        assert!(metadata.file_type().is_dir());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);

        fs::remove_dir(&target).unwrap();
        std::os::unix::fs::symlink(root.path(), &target).unwrap();
        assert!(ensure_private_directory(&target).is_err());
    }

    #[test]
    fn profile_exec_path_is_fresh_and_ignores_stale_helpers() {
        let root = tempfile::tempdir().unwrap();
        let paths = RuntimePaths {
            config: root.path().join("config.toml"),
            runtime: root.path().join("runtime/dev-auth"),
        };

        ensure_exec_sandbox(&paths, "profile-a").unwrap();
        fs::write(
            paths.exec_bin_dir("profile-a").join("stale-helper"),
            b"must never be executable through the profile PATH",
        )
        .unwrap();

        let first = create_empty_exec_path(&paths, "profile-a").unwrap();
        assert_ne!(first.path(), paths.exec_bin_dir("profile-a"));
        assert_eq!(fs::read_dir(first.path()).unwrap().count(), 0);
        assert!(!first.path().join("stale-helper").exists());

        let first_path = first.path().to_path_buf();
        drop(first);
        assert!(!first_path.exists());

        let second = create_empty_exec_path(&paths, "profile-a").unwrap();
        assert_ne!(second.path(), first_path);
        assert_eq!(fs::read_dir(second.path()).unwrap().count(), 0);
        assert!(!second.path().join("stale-helper").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn origin_authority_ignores_local_and_global_url_rewrites() {
        let repository = tempfile::tempdir().unwrap();
        let environment = BTreeMap::from([("HOME".into(), "/nonexistent".into())]);
        for arguments in [
            vec!["init", "--quiet"],
            vec![
                "remote",
                "add",
                "origin",
                "https://github.com/ExampleOrg/sample-repo.git",
            ],
            vec![
                "config",
                "--local",
                "--add",
                "url.https://github.com/OtherOrg/.insteadOf",
                "https://github.com/ExampleOrg/",
            ],
        ] {
            let status = Command::new("/usr/bin/git")
                .args(arguments)
                .current_dir(repository.path())
                .status()
                .unwrap();
            assert!(status.success());
        }

        let rewritten = Command::new("/usr/bin/git")
            .args(["remote", "get-url", "origin"])
            .current_dir(repository.path())
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8(rewritten.stdout).unwrap().trim(),
            "https://github.com/OtherOrg/sample-repo.git"
        );
        assert_eq!(
            origin_repository_at("/usr/bin/git", Some(repository.path()), &environment).unwrap(),
            "https://github.com/ExampleOrg/sample-repo.git"
        );

        let global_repository = tempfile::tempdir().unwrap();
        for arguments in [
            vec!["init", "--quiet"],
            vec![
                "remote",
                "add",
                "origin",
                "https://github.com/ExampleOrg/sample-repo.git",
            ],
        ] {
            let status = Command::new("/usr/bin/git")
                .args(arguments)
                .current_dir(global_repository.path())
                .status()
                .unwrap();
            assert!(status.success());
        }
        let global_home = tempfile::tempdir().unwrap();
        fs::write(
            global_home.path().join(".gitconfig"),
            "[url \"https://github.com/OtherOrg/\"]\n\tinsteadOf = https://github.com/ExampleOrg/\n",
        )
        .unwrap();
        let global_environment =
            BTreeMap::from([("HOME".into(), global_home.path().display().to_string())]);
        let globally_rewritten = Command::new("/usr/bin/git")
            .args(["remote", "get-url", "origin"])
            .current_dir(global_repository.path())
            .env_clear()
            .envs(&global_environment)
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8(globally_rewritten.stdout).unwrap().trim(),
            "https://github.com/OtherOrg/sample-repo.git"
        );
        assert_eq!(
            origin_repository_at(
                "/usr/bin/git",
                Some(global_repository.path()),
                &global_environment,
            )
            .unwrap(),
            "https://github.com/ExampleOrg/sample-repo.git"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gh_origin_authority_accepts_one_effective_worktree_origin_and_rejects_duplicates() {
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repository");
        let worktree = root.path().join("worktree");
        fs::create_dir(&repository).unwrap();
        for arguments in [
            vec!["init", "--quiet"],
            vec!["config", "user.name", "Test User"],
            vec!["config", "user.email", "test@example.invalid"],
        ] {
            assert!(Command::new("/usr/bin/git")
                .args(arguments)
                .current_dir(&repository)
                .status()
                .unwrap()
                .success());
        }
        fs::write(repository.join("tracked"), b"tracked\n").unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["add", "tracked"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args(["commit", "--quiet", "-m", "initial"])
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
            .args(["worktree", "add", "--quiet", "--detach"])
            .arg(&worktree)
            .current_dir(&repository)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "--worktree",
                "remote.origin.url",
                "https://github.com/ExampleOrg/worktree-only.git",
            ])
            .current_dir(&worktree)
            .status()
            .unwrap()
            .success());
        let environment = BTreeMap::from([("HOME".into(), "/nonexistent".into())]);
        assert_eq!(
            origin_repository_at("/usr/bin/git", Some(&worktree), &environment).unwrap(),
            "https://github.com/ExampleOrg/worktree-only.git"
        );

        assert!(Command::new("/usr/bin/git")
            .args([
                "config",
                "--local",
                "remote.origin.url",
                "https://github.com/ExampleOrg/common.git",
            ])
            .current_dir(&worktree)
            .status()
            .unwrap()
            .success());
        assert!(origin_repository_at("/usr/bin/git", Some(&worktree), &environment).is_err());
    }

    #[test]
    fn gh_git_child_accepts_only_source_derived_read_operations() {
        let accepted = [
            vec!["remote", "-v"],
            vec!["remote", "get-url", "--", "origin"],
            vec!["symbolic-ref", "--quiet", "HEAD"],
            vec![
                "show-ref",
                "--verify",
                "--",
                "HEAD",
                "refs/heads/feature.v1",
                "refs/remotes/origin/feature.v1",
            ],
            vec!["config", "--get-regexp", r"^remote\..*\.gh-resolved$"],
            vec![
                "config",
                "--get-regexp",
                r"^branch\.feature\.v1\.(remote|merge|pushremote|gh-merge-base)$",
            ],
            vec!["config", "push.default"],
            vec!["config", "remote.pushDefault"],
            vec!["rev-parse", "--symbolic-full-name", "feature.v1@{push}"],
            vec!["rev-parse", "--verify", "refs/heads/feature.v1"],
            vec!["rev-parse", "--show-toplevel"],
            vec!["rev-parse", "--git-dir"],
            vec!["rev-parse", "--show-prefix"],
            vec!["-c", "log.ShowSignature=false", "log", "%PLACEHOLDER%"],
            vec![
                "-c",
                "log.ShowSignature=false",
                "show",
                "-s",
                "--pretty=format:%H,%s",
                "HEAD",
            ],
            vec![
                "-c",
                "log.ShowSignature=false",
                "show",
                "-s",
                "--pretty=format:%b",
                "0123456789abcdef0123456789abcdef01234567",
            ],
        ];

        for arguments in accepted {
            let mut arguments: Vec<String> = arguments.into_iter().map(str::to_owned).collect();
            if arguments.get(2).map(String::as_str) == Some("log") {
                arguments.splice(
                    3..4,
                    [
                        "--pretty=format:%H%x00%s%x00%b%x00".into(),
                        "--cherry".into(),
                        "origin/main...feature.v1".into(),
                    ],
                );
            }
            let bounded = bounded_gh_git_arguments(&arguments)
                .unwrap_or_else(|error| panic!("{arguments:?}: {error:#}"));
            assert!(!bounded.iter().any(|argument| argument == "-c"));
        }
    }

    #[test]
    fn gh_git_child_rejects_network_mutation_and_local_execution_surfaces() {
        let rejected = [
            vec!["status", "--porcelain"],
            vec!["credential", "fill"],
            vec!["fetch", "origin"],
            vec!["pull"],
            vec!["push", "origin", "HEAD"],
            vec!["checkout", "main"],
            vec!["branch", "-D", "main"],
            vec!["config", "credential.helper"],
            vec!["config", "--get-regexp", ".*"],
            vec!["remote", "get-url", "origin"],
            vec!["remote", "set-url", "origin", "ext::attacker"],
            vec!["-C", "/tmp", "remote", "-v"],
            vec!["-ccredential.helper=!attacker", "remote", "-v"],
            vec!["-c", "credential.helper=!attacker", "remote", "-v"],
            vec!["-c", "log.ShowSignature=false", "fetch", "origin"],
            vec![
                "-c",
                "log.ShowSignature=true",
                "show",
                "-s",
                "--pretty=format:%H,%s",
                "HEAD",
            ],
            vec!["show-ref", "--verify", "--", "--head"],
            vec!["show-ref", "--verify", "--", "refs/tags/release"],
            vec![
                "rev-parse",
                "--symbolic-full-name",
                "feature@{push}:attacker",
            ],
            vec!["rev-parse", "--verify", "refs/heads/main^{object}"],
            vec![
                "-c",
                "log.ShowSignature=false",
                "show",
                "--textconv",
                "HEAD:file",
            ],
        ];

        for arguments in rejected {
            let arguments: Vec<String> = arguments.into_iter().map(str::to_owned).collect();
            assert!(
                bounded_gh_git_arguments(&arguments).is_err(),
                "{arguments:?}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credential_store_accepts_only_the_current_user_session_bus() {
        let run_user_root = tempfile::tempdir().unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let runtime = run_user_root.path().join(uid.to_string());
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let bus = runtime.join("bus");
        let _listener = StdUnixListener::bind(&bus).unwrap();
        let expected_address = format!("unix:path={}", bus.display());

        validate_secret_service_session_at(
            &BTreeMap::from([
                ("XDG_RUNTIME_DIR".into(), runtime.display().to_string()),
                ("DBUS_SESSION_BUS_ADDRESS".into(), expected_address.clone()),
            ]),
            run_user_root.path(),
            uid,
        )
        .unwrap();
        validate_secret_service_session_at(&BTreeMap::new(), run_user_root.path(), uid).unwrap();

        for environment in [
            BTreeMap::from([(
                "XDG_RUNTIME_DIR".into(),
                run_user_root.path().display().to_string(),
            )]),
            BTreeMap::from([(
                "DBUS_SESSION_BUS_ADDRESS".into(),
                "unix:path=/tmp/attacker-bus".into(),
            )]),
        ] {
            assert!(
                validate_secret_service_session_at(&environment, run_user_root.path(), uid,)
                    .is_err()
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credential_store_rejects_a_non_socket_session_bus() {
        let run_user_root = tempfile::tempdir().unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let runtime = run_user_root.path().join(uid.to_string());
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(runtime.join("bus"), b"not a socket").unwrap();

        let error = validate_secret_service_session_at(&BTreeMap::new(), run_user_root.path(), uid)
            .unwrap_err()
            .to_string();
        assert!(error.contains("current-user Unix socket"));
    }

    #[test]
    fn cache_erase_waits_for_refresh_and_cannot_be_undone_by_it() {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let paths = RuntimePaths {
            config: root.path().join("config.toml"),
            runtime: root.path().join("runtime"),
        };
        ensure_runtime(&paths).unwrap();
        let marker = root.path().join("cache-value");
        let refresh_paths = RuntimePaths {
            config: paths.config.clone(),
            runtime: paths.runtime.clone(),
        };
        let refresh_marker = marker.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let refresh = thread::spawn(move || {
            with_cache_scope_lock(&refresh_paths, "scope", || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                fs::write(refresh_marker, b"refreshed").unwrap();
                Ok(())
            })
            .unwrap();
        });
        entered_rx.recv().unwrap();

        let erase_paths = RuntimePaths {
            config: paths.config.clone(),
            runtime: paths.runtime.clone(),
        };
        let erase_marker = marker.clone();
        let (erased_tx, erased_rx) = mpsc::channel();
        let erase = thread::spawn(move || {
            with_cache_scope_erase_lock(&erase_paths, "scope", || {
                fs::remove_file(&erase_marker).unwrap();
                erased_tx.send(()).unwrap();
                Ok(())
            })
            .unwrap();
        });
        assert!(matches!(
            erased_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        release_tx.send(()).unwrap();
        refresh.join().unwrap();
        erased_rx.recv().unwrap();
        erase.join().unwrap();
        assert!(!marker.exists());
        assert!(!paths.cache_dir().join("scope.lock").exists());
    }

    #[test]
    fn purge_excludes_in_flight_refreshes_until_their_writes_finish() {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let paths = RuntimePaths {
            config: root.path().join("config.toml"),
            runtime: root.path().join("runtime"),
        };
        ensure_runtime(&paths).unwrap();
        let lifecycle = cache_lifecycle_lock(&paths).unwrap();
        lifecycle.lock_shared().unwrap();

        let competing = cache_lifecycle_lock(&paths).unwrap();
        assert!(competing.try_lock_exclusive().is_err());
        FileExt::unlock(&lifecycle).unwrap();

        with_cache_purge_lock(&paths, || Ok(())).unwrap();
    }

    #[test]
    fn repository_view_flag_is_translated_to_its_native_positional_selector() {
        let arguments: Vec<String> = vec![
            "repo".into(),
            "view".into(),
            "-R".into(),
            "ExampleOrg/sample-repo".into(),
            "--json".into(),
            "nameWithOwner".into(),
        ];
        let plan = crate::parse_gh_invocation(&arguments).unwrap();
        assert_eq!(
            plan.repository,
            Some(("ExampleOrg".into(), "sample-repo".into()))
        );
        assert_eq!(
            forwarded_gh_arguments(plan, "ExampleOrg", "sample-repo"),
            vec![
                "repo",
                "view",
                "ExampleOrg/sample-repo",
                "--json",
                "nameWithOwner"
            ]
        );
    }

    #[test]
    fn repository_view_injects_the_resolved_repository_when_no_selector_is_positional() {
        let arguments: Vec<String> = vec![
            "repo".into(),
            "view".into(),
            "--json".into(),
            "nameWithOwner".into(),
        ];
        let plan = crate::parse_gh_invocation(&arguments).unwrap();
        assert_eq!(plan.repository, None);
        assert_eq!(
            forwarded_gh_arguments(plan, "ExampleOrg", "sample-repo"),
            vec![
                "repo",
                "view",
                "ExampleOrg/sample-repo",
                "--json",
                "nameWithOwner"
            ]
        );
    }

    #[test]
    fn repository_flags_are_bound_once_and_removed_from_child_arguments() {
        let arguments: Vec<String> = vec![
            "pr".into(),
            "list".into(),
            "-R".into(),
            "ExampleOrg/sample-repo".into(),
        ];
        let plan = crate::parse_gh_invocation(&arguments).unwrap();
        assert_eq!(
            plan.repository,
            Some(("ExampleOrg".into(), "sample-repo".into()))
        );
        assert_eq!(
            forwarded_gh_arguments(plan, "ExampleOrg", "sample-repo"),
            vec!["pr", "list"]
        );
    }

    #[test]
    fn repository_view_positional_selects_the_token_scope_and_is_forwarded() {
        let arguments: Vec<String> = vec![
            "repo".into(),
            "view".into(),
            "ExampleOrg/sample-repo".into(),
            "--json".into(),
            "nameWithOwner".into(),
        ];
        let plan = crate::parse_gh_invocation(&arguments).unwrap();
        assert_eq!(
            plan.repository,
            Some(("ExampleOrg".into(), "sample-repo".into()))
        );
        assert_eq!(
            forwarded_gh_arguments(plan, "ExampleOrg", "sample-repo"),
            vec![
                "repo",
                "view",
                "ExampleOrg/sample-repo",
                "--json",
                "nameWithOwner"
            ]
        );
    }

    #[test]
    fn repository_view_positional_after_value_flag_selects_the_token_scope() {
        let arguments: Vec<String> = vec![
            "repo".into(),
            "view".into(),
            "--json".into(),
            "nameWithOwner".into(),
            "ExampleOrg/sample-repo".into(),
        ];
        let plan = crate::parse_gh_invocation(&arguments).unwrap();
        assert_eq!(
            plan.repository,
            Some(("ExampleOrg".into(), "sample-repo".into()))
        );
        assert_eq!(
            forwarded_gh_arguments(plan, "ExampleOrg", "sample-repo"),
            vec![
                "repo",
                "view",
                "ExampleOrg/sample-repo",
                "--json",
                "nameWithOwner"
            ]
        );
    }

    #[test]
    fn repository_view_rejects_conflicting_flag_and_late_positional_selectors() {
        let arguments: Vec<String> = vec![
            "repo".into(),
            "view".into(),
            "--repo".into(),
            "ExampleOrg/first".into(),
            "--json".into(),
            "nameWithOwner".into(),
            "ExampleOrg/second".into(),
        ];
        assert!(crate::parse_gh_invocation(&arguments)
            .unwrap_err()
            .to_string()
            .contains("more than one repository selector"));
    }

    #[test]
    fn option_values_that_look_like_repository_flags_do_not_select_a_token_scope() {
        let arguments: Vec<String> = vec![
            "pr".into(),
            "create".into(),
            "--head".into(),
            "automation/change".into(),
            "--base".into(),
            "main".into(),
            "--title".into(),
            "Bounded change".into(),
            "--body".into(),
            "--repo=OtherOrg/other-repo".into(),
        ];
        let plan = crate::parse_gh_invocation(&arguments).unwrap();
        assert_eq!(plan.repository, None);
        assert_eq!(plan.forwarded_arguments, arguments);
    }

    #[test]
    fn dynamic_installation_response_must_match_exact_repository_authority() {
        let mut config = config_with_profiles(BTreeMap::new());
        config.github.app_id = 42;
        config.github.discover_installations = true;
        config.github.permissions = crate::approved_github_permissions();
        let response = serde_json::json!({
            "id": 101,
            "app_id": 42,
            "account": {"login": "ExampleOrg"},
            "permissions": config.github.permissions,
            "repository_selection": "all",
            "suspended_at": null
        });
        let selected = validate_repository_installation_response(
            &config.github,
            "exampleorg",
            "New-Repository",
            &serde_json::to_vec(&response).unwrap(),
        )
        .unwrap();
        assert_eq!(selected.installation_id, 101);
        assert_eq!(selected.owner, "exampleorg");
        assert_eq!(selected.repository, "new-repository");

        let mut wrong_selection = response.clone();
        wrong_selection["repository_selection"] = serde_json::json!("selected");
        assert!(validate_repository_installation_response(
            &config.github,
            "exampleorg",
            "New-Repository",
            &serde_json::to_vec(&wrong_selection).unwrap(),
        )
        .is_err());

        let mut wrong_app = response;
        wrong_app["app_id"] = serde_json::json!(99);
        assert!(validate_repository_installation_response(
            &config.github,
            "exampleorg",
            "New-Repository",
            &serde_json::to_vec(&wrong_app).unwrap(),
        )
        .is_err());
    }

    fn profile(authentication: &str, signing: &str) -> SshProfile {
        SshProfile {
            keys: vec![
                SshKey {
                    purpose: SshKeyPurpose::Authentication,
                    private_key_ref: "op://Machine Vault/ssh-auth/private-key".into(),
                    fingerprint: authentication.into(),
                },
                SshKey {
                    purpose: SshKeyPurpose::Signing,
                    private_key_ref: "op://Machine Vault/ssh-sign/private-key".into(),
                    fingerprint: signing.into(),
                },
            ],
        }
    }

    #[test]
    fn signing_agent_must_match_exactly_one_declared_profile() {
        let authentication = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let signing = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let loaded = BTreeSet::from([authentication.into(), signing.into()]);
        let config = config_with_profiles(BTreeMap::from([(
            "automation".into(),
            profile(authentication, signing),
        )]));
        assert!(unique_declared_ssh_profile(&config, &loaded).is_ok());

        let wrong = BTreeSet::from([authentication.into()]);
        assert!(unique_declared_ssh_profile(&config, &wrong).is_err());

        let duplicated = config_with_profiles(BTreeMap::from([
            ("automation".into(), profile(authentication, signing)),
            ("duplicate".into(), profile(authentication, signing)),
        ]));
        assert!(unique_declared_ssh_profile(&duplicated, &loaded).is_err());
    }

    #[test]
    fn dedicated_agent_exposes_only_declared_keys_and_supports_purge() {
        let private_key = PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[42; 32])),
            "test automation key",
        )
        .unwrap();
        let public_key = private_key.public_key().clone();
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        let mut agent = DeclaredAgent::new(vec![AgentIdentity {
            private_key,
            public_key: public_key.clone(),
            fingerprint: fingerprint.clone(),
        }]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        let identities = runtime.block_on(agent.request_identities()).unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].comment, format!("dev-auth:{fingerprint}"));
        let message = b"bounded automation signature";
        let signature = runtime
            .block_on(agent.sign(SignRequest {
                credential: PublicCredential::Key(public_key.key_data().clone()),
                data: message.to_vec(),
                flags: 0,
            }))
            .unwrap();
        signature::Verifier::verify(&public_key, message, &signature).unwrap();

        runtime.block_on(agent.remove_all_identities()).unwrap();
        assert!(runtime
            .block_on(agent.request_identities())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn agent_public_key_rows_are_revalidated_and_canonicalized() {
        let private_key = PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[43; 32])),
            "untrusted agent comment",
        )
        .unwrap();
        let public_key = private_key.public_key();
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        let rows =
            parse_agent_public_keys(&format!("{}\n", public_key.to_openssh().unwrap())).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[&fingerprint],
            PublicKey::new(
                public_key.key_data().clone(),
                format!("dev-auth:{fingerprint}")
            )
            .to_openssh()
            .unwrap()
        );
        let duplicate = format!(
            "{}\n{}\n",
            public_key.to_openssh().unwrap(),
            public_key.to_openssh().unwrap()
        );
        assert!(parse_agent_public_keys(&duplicate).is_err());
        assert!(parse_agent_public_keys("not-a-public-key\n").is_err());
    }

    #[test]
    fn declared_ssh_key_accepts_native_ssh_and_pkcs8_ed25519_encodings() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[21; 32]);
        let pkcs8 = signing_key.to_pkcs8_pem(Default::default()).unwrap();
        let parsed = parse_declared_ssh_private_key(&SecretString::new(pkcs8.to_string())).unwrap();
        assert_eq!(parsed.algorithm(), SshAlgorithm::Ed25519);

        let native = PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[22; 32])),
            "native test key",
        )
        .unwrap()
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap();
        let parsed =
            parse_declared_ssh_private_key(&SecretString::new(native.to_string())).unwrap();
        assert_eq!(parsed.algorithm(), SshAlgorithm::Ed25519);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn broker_signing_returns_only_a_verifiable_signature_for_the_declared_key() {
        let directory = linux_program_test_directory();
        let private_key = PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[29; 32])),
            "broker signing test key",
        )
        .unwrap();
        let public_key = private_key.public_key().clone();
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        let key_path = directory.path().join("private-key");
        fs::write(
            &key_path,
            private_key.to_openssh(ssh_key::LineEnding::LF).unwrap(),
        )
        .unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        let op = directory.path().join("op");
        fs::write(
            &op,
            format!(
                "#!/usr/bin/bash\n/usr/bin/cat -- '{}'\n",
                key_path.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&op, fs::Permissions::from_mode(0o700)).unwrap();

        let payload = b"broker-backed commit signature";
        let encoded = broker_sign_ssh(
            op.to_str().unwrap(),
            &SecretString::new("test-service-token".into()),
            "op://Automation/signing/private-key",
            &public_key.to_openssh().unwrap(),
            &fingerprint,
            payload,
        )
        .unwrap();
        let signature = Signature::try_from(encoded.as_slice()).unwrap();
        signature::Verifier::verify(&public_key, payload, &signature).unwrap();

        assert!(broker_sign_ssh(
            op.to_str().unwrap(),
            &SecretString::new("test-service-token".into()),
            "op://Automation/signing/private-key",
            &public_key.to_openssh().unwrap(),
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            payload,
        )
        .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn transparent_broker_git_configuration_is_profile_derived_and_operation_only() {
        let key = crate::policy_v2::OperationKeyConfig {
            private_key_ref: "op://Automation/signing/private-key".into(),
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPuruylR5Dw9TRBXnt/aS8+Sj1dH3mUEcqFz8iItXZaZ dev-auth-policy-test".into(),
            fingerprint: "SHA256:5QH+7oUNO/MqyIzx8cLnowDLL1ZieiobwK9fp361KnI".into(),
        };
        let profile = crate::policy_v2::ResolvedAuthorityProfile {
            system_cap: "release".into(),
            credential_slot: "automation".into(),
            github: None,
            signing: true,
            signing_key: Some(key.clone()),
            ssh: true,
            ssh_keys: vec![key],
            git_identity: Some(crate::policy_v2::GitIdentityConfig {
                name: "Automation Agent".into(),
                email: "automation@example.invalid".into(),
            }),
            secret_references: BTreeSet::new(),
        };
        let configuration = broker_git_configuration(
            &profile,
            "/opt/dev-auth/bin/git-credential-dev-auth",
            "/opt/dev-auth/bin/ssh-keygen-dev-auth",
            "/usr/bin/ssh",
        );
        assert!(configuration.contains(&(
            "credential.helper".into(),
            "/opt/dev-auth/bin/git-credential-dev-auth".into()
        )));
        assert!(configuration.contains(&(
            "gpg.ssh.program".into(),
            "/opt/dev-auth/bin/ssh-keygen-dev-auth".into()
        )));
        assert!(configuration.contains(&("commit.gpgSign".into(), "true".into())));
        assert!(configuration.contains(&("core.sshCommand".into(), "/usr/bin/ssh".into())));
        assert!(configuration.contains(&("http.extraHeader".into(), String::new())));
        assert!(configuration.contains(&("user.name".into(), "Automation Agent".into())));
        assert!(configuration.contains(&("user.email".into(), "automation@example.invalid".into())));
        assert!(!configuration
            .iter()
            .any(|(_, value)| value.contains("private-key")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn transparent_broker_children_isolate_human_git_config_without_parsing_editor_values() {
        let mut command = Command::new("/usr/bin/true");
        command
            .env("GIT_CONFIG_GLOBAL", "/home/user/.gitconfig")
            .env("GIT_CONFIG_NOSYSTEM", "0")
            .env("GIT_TERMINAL_PROMPT", "1")
            .env("GIT_ASKPASS", "/home/user/bin/askpass")
            .env("SSH_ASKPASS", "/home/user/bin/ssh-askpass")
            .env("GH_TOKEN", "human-token-sentinel")
            .env("GIT_EDITOR", "code-insiders --wait");

        remove_automation_credential_environment(&mut command);

        let environment = command
            .get_envs()
            .map(|(name, value)| (name.to_owned(), value.map(OsStr::to_owned)))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            environment.get(OsStr::new("GIT_CONFIG_GLOBAL")),
            Some(&Some(OsString::from("/dev/null")))
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_CONFIG_NOSYSTEM")),
            Some(&Some(OsString::from("1")))
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_TERMINAL_PROMPT")),
            Some(&Some(OsString::from("0")))
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_ASKPASS")),
            Some(&Some(OsString::from("/usr/bin/false")))
        );
        assert_eq!(
            environment.get(OsStr::new("SSH_ASKPASS")),
            Some(&Some(OsString::from("/usr/bin/false")))
        );
        assert_eq!(environment.get(OsStr::new("GH_TOKEN")), Some(&None));
        assert_eq!(
            environment.get(OsStr::new("GIT_EDITOR")),
            Some(&Some(OsString::from("code-insiders --wait")))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn git_signing_requires_the_declared_signing_public_key() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let signing_key = directory.path().join("signing");
        let authentication_key = directory.path().join("authentication");
        for key in [&signing_key, &authentication_key] {
            assert!(Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(key)
                .status()
                .unwrap()
                .success());
        }
        let fingerprint = |key: &Path| {
            let output = Command::new("ssh-keygen")
                .args(["-lf"])
                .arg(key.with_extension("pub"))
                .args(["-E", "sha256"])
                .output()
                .unwrap();
            String::from_utf8(output.stdout)
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
                .to_owned()
        };
        let profile = profile(
            &fingerprint(&authentication_key),
            &fingerprint(&signing_key),
        );
        let arguments = |key: &Path| {
            vec![
                "-Y".into(),
                "sign".into(),
                "-n".into(),
                "git".into(),
                "-f".into(),
                key.with_extension("pub").display().to_string(),
            ]
        };
        let ssh_keygen_program = "/usr/bin/ssh-keygen";
        let program_guard = program_guard(ssh_keygen_program, "ssh-keygen").unwrap();
        assert!(validate_signing_key_argument(
            &arguments(&signing_key),
            &profile,
            ssh_keygen_program,
            &program_guard,
        )
        .is_ok());
        assert!(validate_signing_key_argument(
            &arguments(&authentication_key),
            &profile,
            ssh_keygen_program,
            &program_guard,
        )
        .is_err());
        let mut wrong_namespace = arguments(&signing_key);
        wrong_namespace[3] = "file".into();
        assert!(validate_signing_key_argument(
            &wrong_namespace,
            &profile,
            ssh_keygen_program,
            &program_guard,
        )
        .is_err());
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn unsupported_unix_program_identity_execution_fails_closed() {
        assert!(program_guard("/usr/bin/true", "test program").is_err());
    }

    #[test]
    fn git_verification_operations_are_public_and_bounded() {
        assert!(is_git_verification_operation(&[
            "-Y".into(),
            "find-principals".into(),
            "-f".into(),
            "/tmp/allowed-signers".into(),
        ])
        .unwrap());
        assert!(is_git_verification_operation(&[
            "-Y".into(),
            "verify".into(),
            "-n".into(),
            "git".into(),
        ])
        .unwrap());
        assert!(!is_git_verification_operation(&[
            "-Y".into(),
            "sign".into(),
            "-n".into(),
            "git".into(),
        ])
        .unwrap());
        assert!(is_git_verification_operation(&[
            "-Y".into(),
            "verify".into(),
            "-n".into(),
            "file".into(),
        ])
        .is_err());
        assert!(is_git_verification_operation(&["-t".into(), "ed25519".into()]).is_err());
    }

    #[test]
    fn login_runtime_precedes_cache_when_the_environment_is_missing() {
        assert_eq!(
            select_runtime_root(None, Some(Path::new("/run/user/1000")), Path::new("/cache")),
            PathBuf::from("/run/user/1000/dev-auth")
        );
        assert_eq!(
            select_runtime_root(None, None, Path::new("/cache")),
            PathBuf::from("/cache/runtime")
        );
    }
}
