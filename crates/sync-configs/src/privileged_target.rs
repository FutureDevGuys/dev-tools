#[cfg(unix)]
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

#[cfg(unix)]
use crate::manifest::{DirectoryStrategy, Mode};
use crate::manifest::{Entry, Privilege};
use crate::privilege::{validate_trusted_executable, PrivilegeError, PrivilegeSession};

#[derive(Debug, Error)]
pub enum PrivilegedTargetError {
    #[error("privileged regular-file targets are unavailable on this platform")]
    Unsupported,
    #[error("entry '{entry}' has an invalid privileged target contract: {detail}")]
    InvalidEntry { entry: String, detail: &'static str },
    #[error("unknown target_owner for entry '{entry}': {name}")]
    UnknownOwner { entry: String, name: String },
    #[error("unknown target_group for entry '{entry}': {name}")]
    UnknownGroup { entry: String, name: String },
    #[error("cannot resolve {kind} identity '{name}'")]
    IdentityLookup { kind: &'static str, name: String },
    #[error("entry '{entry}' would make its privileged target unreadable to the invoking user")]
    UnreadableTarget { entry: String },
    #[error(
        "entry '{entry}' would make its privileged target parent inaccessible to the invoking user"
    )]
    InaccessibleParent { entry: String },
    #[error("{label} is missing: {path}")]
    Missing { label: &'static str, path: PathBuf },
    #[error("cannot inspect {label}: {path}: {source}")]
    Inspect {
        label: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{label} must not be a symbolic link: {path}")]
    Symlink { label: &'static str, path: PathBuf },
    #[error("{label} must be a regular file: {path}")]
    NotRegularFile { label: &'static str, path: PathBuf },
    #[error("{label} changed while it was being inspected: {path}")]
    ChangedDuringInspection { label: &'static str, path: PathBuf },
    #[error("privileged target parent must be absolute: {0}")]
    RelativeParent(PathBuf),
    #[error("privileged target parent must not traverse a symbolic link: {0}")]
    SymlinkParent(PathBuf),
    #[error("privileged target parent component is not a directory: {0}")]
    NonDirectoryParent(PathBuf),
    #[error("cannot inspect privileged target parent {path}: {source}")]
    InspectParent {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("required system command '{name}' is unavailable or unsafe")]
    UnsafeCommand { name: &'static str },
    #[error("privileged copy state drifted {phase}: {target}")]
    Drift {
        phase: &'static str,
        target: PathBuf,
    },
    #[error("privileged copy mutation requires one shared sudo session")]
    MissingSession,
    #[error("privileged copy mutation requires prevalidated system commands")]
    MissingCommands,
    #[error("privileged {operation} failed for {target}: {source}")]
    PrivilegedCommand {
        operation: &'static str,
        target: PathBuf,
        #[source]
        source: PrivilegeError,
    },
    #[error("privileged copy temporary target already exists: {0}")]
    TemporaryExists(PathBuf),
    #[error("privileged copy temporary target failed verification: {0}")]
    TemporaryVerification(PathBuf),
    #[error("privileged copy failed exact postcondition verification: {0}")]
    Postcondition(PathBuf),
    #[error("privileged temporary cleanup failed for {path} after: {primary}")]
    Cleanup { path: PathBuf, primary: String },
}

/// Name-to-ID resolution is kept outside the mutation boundary so every selected
/// target can be validated before a sudo timestamp is acquired.
pub trait IdentityResolver {
    fn user_id(&self, name: &str) -> Result<Option<u32>, String>;
    fn group_id(&self, name: &str) -> Result<Option<u32>, String>;
}

/// Native NSS-backed identity resolution for supported Unix hosts.
#[derive(Clone, Debug, Default)]
pub struct SystemIdentityResolver;

impl SystemIdentityResolver {
    pub fn resolve() -> Result<Self, PrivilegedTargetError> {
        #[cfg(not(unix))]
        {
            Err(PrivilegedTargetError::Unsupported)
        }
        #[cfg(unix)]
        {
            Ok(Self)
        }
    }
}

impl IdentityResolver for SystemIdentityResolver {
    fn user_id(&self, name: &str) -> Result<Option<u32>, String> {
        #[cfg(unix)]
        {
            nix::unistd::User::from_name(name)
                .map(|user| user.map(|user| user.uid.as_raw()))
                .map_err(|error| error.to_string())
        }
        #[cfg(not(unix))]
        {
            let _ = name;
            Err("native user lookup is unavailable".to_owned())
        }
    }

    fn group_id(&self, name: &str) -> Result<Option<u32>, String> {
        #[cfg(unix)]
        {
            nix::unistd::Group::from_name(name)
                .map(|group| group.map(|group| group.gid.as_raw()))
                .map_err(|error| error.to_string())
        }
        #[cfg(not(unix))]
        {
            let _ = name;
            Err("native group lookup is unavailable".to_owned())
        }
    }
}

#[derive(Clone, Debug)]
pub struct PrivilegedCommands {
    chmod: PathBuf,
    install: PathBuf,
    move_file: PathBuf,
    remove: PathBuf,
}

impl PrivilegedCommands {
    pub fn resolve() -> Result<Self, PrivilegedTargetError> {
        Self::new(
            required_system_command("chmod")?,
            required_system_command("install")?,
            required_system_command("mv")?,
            required_system_command("rm")?,
        )
    }

    pub fn new(
        chmod: PathBuf,
        install: PathBuf,
        move_file: PathBuf,
        remove: PathBuf,
    ) -> Result<Self, PrivilegedTargetError> {
        let chmod = validate_command("chmod", &chmod)?;
        let install = validate_command("install", &install)?;
        let move_file = validate_command("mv", &move_file)?;
        let remove = validate_command("rm", &remove)?;
        Ok(Self {
            chmod,
            install,
            move_file,
            remove,
        })
    }
}

fn required_system_command(name: &'static str) -> Result<PathBuf, PrivilegedTargetError> {
    resolve_system_command(name).ok_or(PrivilegedTargetError::UnsafeCommand { name })
}

fn resolve_system_command(name: &str) -> Option<PathBuf> {
    ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        .into_iter()
        .map(|directory| Path::new(directory).join(name))
        .find(|candidate| validate_trusted_executable(candidate).is_ok())
}

fn validate_command(name: &'static str, path: &Path) -> Result<PathBuf, PrivilegedTargetError> {
    validate_trusted_executable(path)
        .map(|()| path.to_path_buf())
        .map_err(|_| PrivilegedTargetError::UnsafeCommand { name })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileSnapshot {
    exists: bool,
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    digest: Option<[u8; 32]>,
}

impl FileSnapshot {
    #[cfg(unix)]
    const fn missing() -> Self {
        Self {
            exists: false,
            device: 0,
            inode: 0,
            size: 0,
            modified_seconds: 0,
            modified_nanoseconds: 0,
            uid: 0,
            gid: 0,
            mode: 0,
            links: 0,
            digest: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectorySnapshot {
    path: PathBuf,
    exists: bool,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

impl DirectorySnapshot {
    #[cfg(unix)]
    fn missing(path: PathBuf) -> Self {
        Self {
            path,
            exists: false,
            device: 0,
            inode: 0,
            uid: 0,
            gid: 0,
            mode: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivilegedCopyPlan {
    pub entry: Entry,
    pub owner_uid: u32,
    pub group_gid: u32,
    pub file_mode: u32,
    pub parent_mode: u32,
    source_snapshot: FileSnapshot,
    target_snapshot: FileSnapshot,
    parent_snapshots: Vec<DirectorySnapshot>,
    pub parent_needs_update: bool,
    pub target_needs_update: bool,
    pub blocked_existing: bool,
    force: bool,
}

impl PrivilegedCopyPlan {
    pub const fn needs_mutation(&self) -> bool {
        !self.blocked_existing && (self.parent_needs_update || self.target_needs_update)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivilegedTargetOutcome {
    UpToDate,
    WouldChange,
    Changed,
    SkippedExisting,
}

/// Plan every privileged entry from an already profile-selected set. No
/// authentication or privileged command is performed here.
pub fn plan_selected_privileged_entries(
    selected_entries: &[Entry],
    force: bool,
    identities: &dyn IdentityResolver,
) -> Result<Vec<PrivilegedCopyPlan>, PrivilegedTargetError> {
    selected_entries
        .iter()
        .filter(|entry| entry.target_privilege == Privilege::Sudo)
        .map(|entry| plan_privileged_copy(entry, force, identities))
        .collect()
}

pub fn plan_privileged_copy(
    entry: &Entry,
    force: bool,
    identities: &dyn IdentityResolver,
) -> Result<PrivilegedCopyPlan, PrivilegedTargetError> {
    #[cfg(not(unix))]
    {
        let _ = (entry, force, identities);
        Err(PrivilegedTargetError::Unsupported)
    }
    #[cfg(unix)]
    {
        validate_entry_shape(entry)?;
        let owner = entry
            .target_owner
            .as_deref()
            .ok_or_else(|| invalid_entry(entry, "target_owner is required"))?;
        let group = entry
            .target_group
            .as_deref()
            .ok_or_else(|| invalid_entry(entry, "target_group is required"))?;
        let owner_uid = identities
            .user_id(owner)
            .map_err(|_| PrivilegedTargetError::IdentityLookup {
                kind: "user",
                name: owner.to_owned(),
            })?
            .ok_or_else(|| PrivilegedTargetError::UnknownOwner {
                entry: entry.name.clone(),
                name: owner.to_owned(),
            })?;
        let group_gid = identities
            .group_id(group)
            .map_err(|_| PrivilegedTargetError::IdentityLookup {
                kind: "group",
                name: group.to_owned(),
            })?
            .ok_or_else(|| PrivilegedTargetError::UnknownGroup {
                entry: entry.name.clone(),
                name: group.to_owned(),
            })?;
        let file_mode = entry
            .permissions
            .as_ref()
            .and_then(|policy| policy.file)
            .ok_or_else(|| invalid_entry(entry, "permissions.file is required"))?
            .get();
        let parent_mode = entry
            .target_parent_mode
            .ok_or_else(|| invalid_entry(entry, "target_parent_mode is required"))?
            .get();
        validate_invoker_access(entry, owner_uid, group_gid, file_mode, parent_mode)?;

        let source_snapshot =
            snapshot_regular_file(&entry.source, "privileged copy source", false)?;
        let parent = entry
            .target
            .parent()
            .ok_or_else(|| invalid_entry(entry, "target must name a regular file"))?;
        let parent_snapshots = snapshot_directory_path(parent)?;
        let target_snapshot = snapshot_regular_file(&entry.target, "privileged copy target", true)?;
        let parent_snapshot = parent_snapshots
            .last()
            .ok_or_else(|| invalid_entry(entry, "target parent is unavailable"))?;
        let parent_needs_update = !parent_snapshot.exists || parent_snapshot.mode != parent_mode;
        let content_differs =
            !target_snapshot.exists || target_snapshot.digest != source_snapshot.digest;
        let metadata_differs = target_snapshot.exists
            && (target_snapshot.uid != owner_uid
                || target_snapshot.gid != group_gid
                || target_snapshot.mode != file_mode);
        let blocked_existing =
            target_snapshot.exists && content_differs && !(entry.reconcile_existing || force);
        Ok(PrivilegedCopyPlan {
            entry: entry.clone(),
            owner_uid,
            group_gid,
            file_mode,
            parent_mode,
            source_snapshot,
            target_snapshot,
            parent_snapshots,
            parent_needs_update,
            target_needs_update: content_differs || metadata_differs,
            blocked_existing,
            force,
        })
    }
}

/// Apply a fully preflighted batch. All plans are revalidated before the one
/// shared authentication step. Dry runs, blocked targets, and no-op batches do
/// not require or touch a privilege session.
pub fn apply_privileged_plans(
    plans: &[PrivilegedCopyPlan],
    dry_run: bool,
    identities: &dyn IdentityResolver,
    session: Option<&mut PrivilegeSession>,
    commands: Option<&PrivilegedCommands>,
) -> Result<Vec<PrivilegedTargetOutcome>, PrivilegedTargetError> {
    let current = revalidate_privileged_plans(plans, identities)?;

    if dry_run {
        return Ok(current.iter().map(dry_run_outcome).collect());
    }
    if !current.iter().any(PrivilegedCopyPlan::needs_mutation) {
        return Ok(current.iter().map(noop_outcome).collect());
    }
    let commands = commands.ok_or(PrivilegedTargetError::MissingCommands)?;
    let session = session.ok_or(PrivilegedTargetError::MissingSession)?;
    session
        .ensure_authenticated()
        .map_err(|source| PrivilegedTargetError::PrivilegedCommand {
            operation: "authentication",
            target: PathBuf::from("sudo-session"),
            source,
        })?;

    let mut outcomes = Vec::with_capacity(plans.len());
    for plan in plans {
        if plan.blocked_existing {
            outcomes.push(PrivilegedTargetOutcome::SkippedExisting);
        } else if !plan.needs_mutation() {
            outcomes.push(PrivilegedTargetOutcome::UpToDate);
        } else {
            apply_one(plan, identities, session, commands)?;
            outcomes.push(PrivilegedTargetOutcome::Changed);
        }
    }
    Ok(outcomes)
}

/// Revalidate a complete planned batch without authenticating or mutating.
/// The engine uses this boundary after trusted pre-hooks and expansion so a
/// late drift in any active privileged target stops every target before sudo.
#[doc(hidden)]
pub fn revalidate_privileged_plans(
    plans: &[PrivilegedCopyPlan],
    identities: &dyn IdentityResolver,
) -> Result<Vec<PrivilegedCopyPlan>, PrivilegedTargetError> {
    let mut current = Vec::with_capacity(plans.len());
    for plan in plans {
        let replanned = plan_privileged_copy(&plan.entry, plan.force, identities)?;
        if !snapshots_match_exactly(plan, &replanned) {
            return Err(drift(plan, "between plan and apply"));
        }
        current.push(replanned);
    }
    Ok(current)
}

fn dry_run_outcome(plan: &PrivilegedCopyPlan) -> PrivilegedTargetOutcome {
    if plan.blocked_existing {
        PrivilegedTargetOutcome::SkippedExisting
    } else if plan.needs_mutation() {
        PrivilegedTargetOutcome::WouldChange
    } else {
        PrivilegedTargetOutcome::UpToDate
    }
}

fn noop_outcome(plan: &PrivilegedCopyPlan) -> PrivilegedTargetOutcome {
    if plan.blocked_existing {
        PrivilegedTargetOutcome::SkippedExisting
    } else {
        PrivilegedTargetOutcome::UpToDate
    }
}

fn apply_one(
    original: &PrivilegedCopyPlan,
    identities: &dyn IdentityResolver,
    session: &PrivilegeSession,
    commands: &PrivilegedCommands,
) -> Result<(), PrivilegedTargetError> {
    let mut current = plan_privileged_copy(&original.entry, original.force, identities)?;
    if !snapshots_match_for_revalidation(original, &current) {
        return Err(drift(original, "between plan and apply"));
    }
    if current.blocked_existing {
        return Err(drift(original, "and became blocked before apply"));
    }

    if current.parent_needs_update {
        let immediately_before = plan_privileged_copy(&original.entry, original.force, identities)?;
        if !snapshots_match_exactly(&current, &immediately_before) {
            return Err(drift(original, "immediately before parent mutation"));
        }
        let parent = original
            .entry
            .target
            .parent()
            .ok_or_else(|| invalid_entry(&original.entry, "target must name a regular file"))?;
        let parent_snapshot = current
            .parent_snapshots
            .last()
            .ok_or_else(|| invalid_entry(&original.entry, "target parent is unavailable"))?;
        if parent_snapshot.exists {
            run_privileged(
                session,
                vec![
                    commands.chmod.as_os_str().to_owned(),
                    OsString::from(format!("{:04o}", original.parent_mode)),
                    OsString::from("--"),
                    parent.as_os_str().to_owned(),
                ],
                "parent chmod",
                &original.entry.target,
            )?;
        } else {
            run_privileged(
                session,
                vec![
                    commands.install.as_os_str().to_owned(),
                    OsString::from("-d"),
                    OsString::from("-o"),
                    OsString::from(original.owner_uid.to_string()),
                    OsString::from("-g"),
                    OsString::from(original.group_gid.to_string()),
                    OsString::from("-m"),
                    OsString::from(format!("{:04o}", original.parent_mode)),
                    OsString::from("--"),
                    parent.as_os_str().to_owned(),
                ],
                "parent install",
                &original.entry.target,
            )?;
        }
        let after_parent = plan_privileged_copy(&original.entry, original.force, identities)?;
        if current.source_snapshot != after_parent.source_snapshot
            || current.target_snapshot != after_parent.target_snapshot
            || !parent_transition_is_safe(&current, &after_parent)
            || after_parent.parent_needs_update
        {
            return Err(drift(original, "immediately before file install"));
        }
        current = after_parent;
    }

    if current.target_needs_update {
        let immediately_before = plan_privileged_copy(&original.entry, original.force, identities)?;
        if !snapshots_match_exactly(&current, &immediately_before) {
            return Err(drift(original, "immediately before file install"));
        }
        stage_and_replace(&current, identities, session, commands)?;
    }

    let verified = plan_privileged_copy(&original.entry, original.force, identities)?;
    if verified.blocked_existing || verified.needs_mutation() {
        return Err(PrivilegedTargetError::Postcondition(
            original.entry.target.clone(),
        ));
    }
    Ok(())
}

fn stage_and_replace(
    plan: &PrivilegedCopyPlan,
    identities: &dyn IdentityResolver,
    session: &PrivilegeSession,
    commands: &PrivilegedCommands,
) -> Result<(), PrivilegedTargetError> {
    let temporary = temporary_target(&plan.entry.target)?;
    if path_exists_nofollow(&temporary)? {
        return Err(PrivilegedTargetError::TemporaryExists(temporary));
    }
    let result = (|| {
        run_privileged(
            session,
            vec![
                commands.install.as_os_str().to_owned(),
                OsString::from("-o"),
                OsString::from(plan.owner_uid.to_string()),
                OsString::from("-g"),
                OsString::from(plan.group_gid.to_string()),
                OsString::from("-m"),
                OsString::from(format!("{:04o}", plan.file_mode)),
                OsString::from("--"),
                plan.entry.source.as_os_str().to_owned(),
                temporary.as_os_str().to_owned(),
            ],
            "file install",
            &plan.entry.target,
        )?;
        let staged = snapshot_regular_file(&temporary, "privileged copy temporary target", false)?;
        if staged.digest != plan.source_snapshot.digest
            || staged.uid != plan.owner_uid
            || staged.gid != plan.group_gid
            || staged.mode != plan.file_mode
            || staged.links != 1
        {
            return Err(PrivilegedTargetError::TemporaryVerification(
                temporary.clone(),
            ));
        }
        let before_replace = plan_privileged_copy(&plan.entry, plan.force, identities)?;
        if !snapshots_match_exactly(plan, &before_replace) {
            return Err(drift(plan, "immediately before atomic replace"));
        }
        run_privileged(
            session,
            vec![
                commands.move_file.as_os_str().to_owned(),
                OsString::from("-f"),
                OsString::from("--"),
                temporary.as_os_str().to_owned(),
                plan.entry.target.as_os_str().to_owned(),
            ],
            "atomic replace",
            &plan.entry.target,
        )?;
        Ok(())
    })();

    if let Err(primary_error) = &result {
        let cleanup_needed = path_exists_nofollow(&temporary).unwrap_or(true);
        if cleanup_needed
            && run_privileged_cleanup(
                session,
                vec![
                    commands.remove.as_os_str().to_owned(),
                    OsString::from("-f"),
                    OsString::from("--"),
                    temporary.as_os_str().to_owned(),
                ],
                "temporary cleanup",
                &temporary,
            )
            .is_err()
        {
            return Err(PrivilegedTargetError::Cleanup {
                path: temporary,
                primary: primary_error.to_string(),
            });
        }
    }
    result
}

fn run_privileged(
    session: &PrivilegeSession,
    argv: Vec<OsString>,
    operation: &'static str,
    target: &Path,
) -> Result<(), PrivilegedTargetError> {
    session
        .run(&argv)
        .map(|_| ())
        .map_err(|source| PrivilegedTargetError::PrivilegedCommand {
            operation,
            target: target.to_path_buf(),
            source,
        })
}

fn run_privileged_cleanup(
    session: &PrivilegeSession,
    argv: Vec<OsString>,
    operation: &'static str,
    target: &Path,
) -> Result<(), PrivilegedTargetError> {
    session.run_cleanup(&argv).map(|_| ()).map_err(|source| {
        PrivilegedTargetError::PrivilegedCommand {
            operation,
            target: target.to_path_buf(),
            source,
        }
    })
}

fn temporary_target(target: &Path) -> Result<PathBuf, PrivilegedTargetError> {
    let name = target
        .file_name()
        .ok_or_else(|| PrivilegedTargetError::InvalidEntry {
            entry: target.display().to_string(),
            detail: "target must name a regular file",
        })?
        .to_string_lossy();
    Ok(target.with_file_name(format!(".{name}.sync-configs-{}.tmp", Uuid::new_v4())))
}

fn path_exists_nofollow(path: &Path) -> Result<bool, PrivilegedTargetError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(PrivilegedTargetError::Inspect {
            label: "privileged copy temporary target",
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(unix)]
fn validate_entry_shape(entry: &Entry) -> Result<(), PrivilegedTargetError> {
    if entry.target_privilege != Privilege::Sudo {
        return Err(invalid_entry(entry, "target_privilege must be sudo"));
    }
    if entry.mode != Mode::Copy {
        return Err(invalid_entry(entry, "only copy mode is supported"));
    }
    if !entry.source.is_absolute()
        || contains_parent(&entry.source)
        || !entry.target.is_absolute()
        || contains_parent(&entry.target)
    {
        return Err(invalid_entry(
            entry,
            "source and target must be explicit absolute paths",
        ));
    }
    if entry.directory_strategy != DirectoryStrategy::AsDirectory
        || !entry.include.is_empty()
        || !entry.exclude.is_empty()
        || !entry.ignore_files.is_empty()
        || !entry.discover_ignore_files
        || !entry.use_default_filters
    {
        return Err(invalid_entry(
            entry,
            "directory expansion and filters are unsupported",
        ));
    }
    let Some(permissions) = entry.permissions.as_ref() else {
        return Err(invalid_entry(entry, "permissions.file is required"));
    };
    if permissions.file.is_none() || permissions.dir.is_some() || permissions.recursive {
        return Err(invalid_entry(entry, "only permissions.file is supported"));
    }
    if entry.source_permissions.is_some() {
        return Err(invalid_entry(entry, "source_permissions is unsupported"));
    }
    if entry.target_owner.is_none()
        || entry.target_group.is_none()
        || entry.target_parent_mode.is_none()
    {
        return Err(invalid_entry(
            entry,
            "target_owner, target_group, and target_parent_mode are required",
        ));
    }
    if entry.pre_script.is_some() || entry.post_script.is_some() {
        return Err(invalid_entry(entry, "per-entry scripts are unsupported"));
    }
    if entry.target.file_name().is_none() {
        return Err(invalid_entry(entry, "target must name a regular file"));
    }
    Ok(())
}

fn invalid_entry(entry: &Entry, detail: &'static str) -> PrivilegedTargetError {
    PrivilegedTargetError::InvalidEntry {
        entry: entry.name.clone(),
        detail,
    }
}

#[cfg(unix)]
fn contains_parent(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

#[cfg(unix)]
fn validate_invoker_access(
    entry: &Entry,
    owner_uid: u32,
    group_gid: u32,
    file_mode: u32,
    parent_mode: u32,
) -> Result<(), PrivilegedTargetError> {
    let current_uid = rustix::process::geteuid().as_raw();
    let current_gid = rustix::process::getegid().as_raw();
    let groups = rustix::process::getgroups()
        .map_err(|_| PrivilegedTargetError::IdentityLookup {
            kind: "invoking user groups",
            name: current_uid.to_string(),
        })?
        .into_iter()
        .map(|group| group.as_raw())
        .collect::<BTreeSet<_>>();
    let has = |mode: u32, permission: u32| {
        let shift = if current_uid == owner_uid {
            6
        } else if current_gid == group_gid || groups.contains(&group_gid) {
            3
        } else {
            0
        };
        mode & (permission << shift) != 0
    };
    if !has(file_mode, 0o4) {
        return Err(PrivilegedTargetError::UnreadableTarget {
            entry: entry.name.clone(),
        });
    }
    if !has(parent_mode, 0o1) {
        return Err(PrivilegedTargetError::InaccessibleParent {
            entry: entry.name.clone(),
        });
    }
    Ok(())
}

fn snapshot_regular_file(
    path: &Path,
    label: &'static str,
    missing_ok: bool,
) -> Result<FileSnapshot, PrivilegedTargetError> {
    #[cfg(not(unix))]
    {
        let _ = (path, label, missing_ok);
        Err(PrivilegedTargetError::Unsupported)
    }
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let before = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound && missing_ok => {
                return Ok(FileSnapshot::missing());
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Err(PrivilegedTargetError::Missing {
                    label,
                    path: path.to_path_buf(),
                });
            }
            Err(source) => {
                return Err(PrivilegedTargetError::Inspect {
                    label,
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        if before.file_type().is_symlink() {
            return Err(PrivilegedTargetError::Symlink {
                label,
                path: path.to_path_buf(),
            });
        }
        if !before.is_file() {
            return Err(PrivilegedTargetError::NotRegularFile {
                label,
                path: path.to_path_buf(),
            });
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|source| PrivilegedTargetError::Inspect {
                label,
                path: path.to_path_buf(),
                source,
            })?;
        let opened = file
            .metadata()
            .map_err(|source| PrivilegedTargetError::Inspect {
                label,
                path: path.to_path_buf(),
                source,
            })?;
        if !opened.is_file() || metadata_identity(&before) != metadata_identity(&opened) {
            return Err(PrivilegedTargetError::ChangedDuringInspection {
                label,
                path: path.to_path_buf(),
            });
        }
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count =
                file.read(&mut buffer)
                    .map_err(|source| PrivilegedTargetError::Inspect {
                        label,
                        path: path.to_path_buf(),
                        source,
                    })?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        let after =
            fs::symlink_metadata(path).map_err(|source| PrivilegedTargetError::Inspect {
                label,
                path: path.to_path_buf(),
                source,
            })?;
        if after.file_type().is_symlink()
            || metadata_identity(&before) != metadata_identity(&after)
            || metadata_identity(&opened) != metadata_identity(&after)
        {
            return Err(PrivilegedTargetError::ChangedDuringInspection {
                label,
                path: path.to_path_buf(),
            });
        }
        let digest: [u8; 32] = digest.finalize().into();
        Ok(FileSnapshot {
            exists: true,
            device: after.dev(),
            inode: after.ino(),
            size: after.size(),
            modified_seconds: after.mtime(),
            modified_nanoseconds: after.mtime_nsec(),
            uid: after.uid(),
            gid: after.gid(),
            mode: after.mode() & 0o7777,
            links: after.nlink(),
            digest: Some(digest),
        })
    }
}

#[cfg(unix)]
fn metadata_identity(metadata: &fs::Metadata) -> (u64, u64, u64, i64, i64, u32, u32, u32, u64) {
    use std::os::unix::fs::MetadataExt;
    (
        metadata.dev(),
        metadata.ino(),
        metadata.size(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode() & 0o7777,
        metadata.nlink(),
    )
}

#[cfg(unix)]
fn snapshot_directory_path(path: &Path) -> Result<Vec<DirectorySnapshot>, PrivilegedTargetError> {
    #[cfg(not(unix))]
    {
        let _ = path;
        return Err(PrivilegedTargetError::Unsupported);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if !path.is_absolute() || contains_parent(path) {
            return Err(PrivilegedTargetError::RelativeParent(path.to_path_buf()));
        }
        let mut paths = vec![PathBuf::from("/")];
        let mut current = PathBuf::from("/");
        for component in path.components() {
            match component {
                Component::RootDir => continue,
                Component::Normal(part) => {
                    current.push(part);
                    paths.push(current.clone());
                }
                _ => return Err(PrivilegedTargetError::RelativeParent(path.to_path_buf())),
            }
        }
        let mut missing = false;
        let mut snapshots = Vec::with_capacity(paths.len());
        for current in paths {
            if missing {
                snapshots.push(DirectorySnapshot::missing(current));
                continue;
            }
            let metadata = match fs::symlink_metadata(&current) {
                Ok(metadata) => metadata,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    missing = true;
                    snapshots.push(DirectorySnapshot::missing(current));
                    continue;
                }
                Err(source) => {
                    return Err(PrivilegedTargetError::InspectParent {
                        path: current,
                        source,
                    });
                }
            };
            if metadata.file_type().is_symlink() {
                return Err(PrivilegedTargetError::SymlinkParent(current));
            }
            if !metadata.is_dir() {
                return Err(PrivilegedTargetError::NonDirectoryParent(current));
            }
            snapshots.push(DirectorySnapshot {
                path: current,
                exists: true,
                device: metadata.dev(),
                inode: metadata.ino(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: metadata.mode() & 0o7777,
            });
        }
        Ok(snapshots)
    }
}

fn snapshots_match_exactly(left: &PrivilegedCopyPlan, right: &PrivilegedCopyPlan) -> bool {
    left.owner_uid == right.owner_uid
        && left.group_gid == right.group_gid
        && left.file_mode == right.file_mode
        && left.parent_mode == right.parent_mode
        && left.source_snapshot == right.source_snapshot
        && left.target_snapshot == right.target_snapshot
        && left.parent_snapshots == right.parent_snapshots
        && left.parent_needs_update == right.parent_needs_update
        && left.target_needs_update == right.target_needs_update
        && left.blocked_existing == right.blocked_existing
}

fn snapshots_match_for_revalidation(
    original: &PrivilegedCopyPlan,
    current: &PrivilegedCopyPlan,
) -> bool {
    original.owner_uid == current.owner_uid
        && original.group_gid == current.group_gid
        && original.file_mode == current.file_mode
        && original.parent_mode == current.parent_mode
        && original.source_snapshot == current.source_snapshot
        && original.target_snapshot == current.target_snapshot
        && original.target_needs_update == current.target_needs_update
        && original.blocked_existing == current.blocked_existing
        && (original.parent_snapshots == current.parent_snapshots
            || parent_transition_is_safe(original, current))
}

fn parent_transition_is_safe(original: &PrivilegedCopyPlan, current: &PrivilegedCopyPlan) -> bool {
    if original.parent_snapshots.len() != current.parent_snapshots.len()
        || current.parent_needs_update
    {
        return false;
    }
    let final_index = original.parent_snapshots.len().saturating_sub(1);
    original
        .parent_snapshots
        .iter()
        .zip(&current.parent_snapshots)
        .enumerate()
        .all(|(index, (before, after))| {
            if before.path != after.path || !after.exists {
                return false;
            }
            if !before.exists {
                return index != final_index || after.mode == original.parent_mode;
            }
            before.device == after.device
                && before.inode == after.inode
                && before.uid == after.uid
                && before.gid == after.gid
                && (before.mode == after.mode
                    || (index == final_index && after.mode == original.parent_mode))
        })
}

fn drift(plan: &PrivilegedCopyPlan, phase: &'static str) -> PrivilegedTargetError {
    PrivilegedTargetError::Drift {
        phase,
        target: plan.entry.target.clone(),
    }
}
