//! Dev Auth update adapter. Installation mutation remains owned by the full
//! setup transaction, including its retained generation and native exclusion.

use crate::stable_release::{
    self, ReleaseObservationFailure, ReleaseObservationFailureKind,
    StableReleaseObservationStorage, StableReleaseStorage,
};
use anyhow::Context;
use dev_tools_product::ProductId;
use dev_tools_update::{
    AuthenticatedCandidate, InstallationSnapshot, OperationRequest, UpdateAdapter, UpdateError,
    UpdateErrorKind, UpdatePolicy,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

const WORKER_SCHEMA: &str = "dev-auth-update-apply-worker-v1";
const WORKER_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum WorkerOutcome {
    Completed,
    RequiresSetup,
    Blocked,
    Operational,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerReport {
    schema: String,
    plan_sha256: String,
    release_version: String,
    outcome: WorkerOutcome,
    changed: Option<bool>,
    verified: bool,
}

#[derive(Clone, Copy)]
pub enum UpdateOperation {
    Status,
    Check,
    Install { offline: bool },
    Apply { offline: bool },
    Rollback,
}

pub fn execute(operation: UpdateOperation) -> dev_tools_product::OperationResultV2 {
    let policy = UpdatePolicy::standard(ProductId::parse("dev-auth").expect("fixed product id"));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs());
    let mut adapter = DevAuthUpdateAdapter::new(operation);
    dev_tools_update::execute(
        &policy,
        match operation {
            UpdateOperation::Status => OperationRequest::status(),
            UpdateOperation::Check => OperationRequest::check(),
            UpdateOperation::Install { offline } => OperationRequest::install(offline),
            UpdateOperation::Apply { offline } => OperationRequest::apply(offline),
            UpdateOperation::Rollback => OperationRequest::rollback(),
        },
        now,
        &mut adapter,
    )
}

fn map_observation_failure(error: ReleaseObservationFailure) -> UpdateError {
    UpdateError::new(match error.kind() {
        ReleaseObservationFailureKind::Network => UpdateErrorKind::Network,
        ReleaseObservationFailureKind::Authenticity => UpdateErrorKind::Authenticity,
        ReleaseObservationFailureKind::Authority => UpdateErrorKind::Authority,
        ReleaseObservationFailureKind::Operational => UpdateErrorKind::Operational,
    })
}

fn staged_matches_candidate(
    staged: &stable_release::StagedStableRelease,
    candidate: &AuthenticatedCandidate,
) -> bool {
    let actual = &staged.verified;
    let expected = candidate.verified();
    actual.root_generation == expected.root_generation
        && actual.root_sha256 == expected.root_sha256
        && actual.manifest_generation == expected.manifest_generation
        && actual.manifest_sha256 == expected.manifest_sha256
        && actual.version == expected.version.to_string()
        && Some(actual.source_commit.as_str()) == expected.source_commit.as_deref()
        && actual.target == expected.target
        && actual.artifact_url == expected.artifact_url
        && actual.artifact_length == expected.artifact_length
        && actual.artifact_sha256 == expected.artifact_sha256
}

fn read_worker_report(
    path: &Path,
    digest: &str,
    version: &str,
) -> Result<WorkerReport, UpdateError> {
    let document = dev_tools_installation::read_atomic_document(
        path,
        &dev_tools_installation::DocumentAuthority {
            owner_uid: nix::unistd::Uid::effective().as_raw(),
            mode: 0o600,
            limit: 4096,
        },
    )
    .map_err(|_| UpdateError::new(UpdateErrorKind::Authority))?
    .ok_or(UpdateError::new(UpdateErrorKind::Operational))?;
    let report: WorkerReport = serde_json::from_slice(&document.bytes)
        .map_err(|_| UpdateError::new(UpdateErrorKind::Authority))?;
    if report.schema != WORKER_SCHEMA
        || report.plan_sha256 != digest
        || report.release_version != version
    {
        return Err(UpdateError::new(UpdateErrorKind::Authority));
    }
    Ok(report)
}

fn run_worker_child(
    executable: &Path,
    plan: &Path,
    digest: &str,
    result: &Path,
    staging_lock: &fs::File,
) -> Result<std::process::ExitStatus, UpdateError> {
    let mut command = Command::new(executable);
    let parent_pid = std::process::id();
    let lock_fd = staging_lock.as_raw_fd();
    command
        .arg0("dev-auth")
        .args(["update-worker", "--plan"])
        .arg(plan)
        .args(["--sha256", digest, "--result"])
        .arg(result)
        .arg("--staging-lock-fd")
        .arg(lock_fd.to_string())
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    // SAFETY: prctl is async-signal-safe in this child-only callback; no Rust
    // allocation or lock is touched. Parent death must not orphan setup work.
    unsafe {
        command.pre_exec(move || {
            if nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGTERM) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if nix::libc::getppid() != parent_pid as nix::libc::pid_t {
                return Err(std::io::Error::from_raw_os_error(nix::libc::EPIPE));
            }
            if nix::libc::fcntl(lock_fd, nix::libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|_| UpdateError::new(UpdateErrorKind::Operational))?;
    let deadline = Instant::now() + WORKER_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(100)),
            Ok(None) => {
                let group = nix::unistd::Pid::from_raw(
                    i32::try_from(child.id())
                        .map_err(|_| UpdateError::new(UpdateErrorKind::Operational))?,
                );
                let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGTERM);
                thread::sleep(Duration::from_secs(1));
                if child.try_wait().ok().flatten().is_none() {
                    let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
                }
                let _ = child.wait();
                return Err(UpdateError::new(UpdateErrorKind::Interrupted));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(UpdateError::new(UpdateErrorKind::Operational));
            }
        }
    }
}

fn validate_inherited_staging_lock(plan_path: &Path, fd: RawFd) -> anyhow::Result<fs::File> {
    anyhow::ensure!(fd >= 3, "update staging descriptor is invalid");
    // SAFETY: fcntl inspects a numeric descriptor without retaining a pointer.
    anyhow::ensure!(
        unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) } >= 0,
        "update staging descriptor is unavailable"
    );
    // SAFETY: the private worker takes ownership of the one descriptor passed
    // by its parent; the parent retains its own copy in the separate process.
    let file = unsafe { fs::File::from_raw_fd(fd) };
    let observed = file.metadata()?;
    let path = plan_path
        .parent()
        .context("update plan has no staging directory")?
        .join("update.lock");
    let expected = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        expected.file_type().is_file()
            && !expected.file_type().is_symlink()
            && expected.uid() == nix::unistd::Uid::effective().as_raw()
            && expected.mode() & 0o777 == 0o600
            && expected.nlink() == 1
            && observed.dev() == expected.dev()
            && observed.ino() == expected.ino(),
        "update staging descriptor does not match its owner-only lock"
    );
    fs2::FileExt::try_lock_exclusive(&file)
        .context("update worker cannot retain its staging lock")?;
    Ok(file)
}

/// The verified candidate executes this exact setup plan after the old binary
/// has prepared and retained all source documents. No credential input enters
/// this worker, and it emits only a value-free private result document.
pub fn run_apply_worker(plan_path: &Path, digest: &str, result_path: &Path, lock_fd: RawFd) -> i32 {
    let _staging_lock = match validate_inherited_staging_lock(plan_path, lock_fd) {
        Ok(lock) => lock,
        Err(_) => {
            eprintln!("dev-auth: update worker staging_lock failed");
            return 4;
        }
    };
    let mut stage = "plan_read";
    let mut run = || -> anyhow::Result<WorkerReport> {
        let plan = if nix::unistd::Uid::effective().is_root() {
            crate::setup_v3::read_root_setup_plan_v3_at(plan_path)?
        } else {
            crate::setup_v3::read_setup_plan_v3_at(plan_path)?
        };
        stage = "staging_custody";
        let staging = plan_path
            .parent()
            .context("update plan has no staging directory")?;
        let staging_metadata = fs::symlink_metadata(staging)?;
        stage = "staging_plan_name";
        if plan_path.file_name() != Some(std::ffi::OsStr::new("update-plan.json")) {
            anyhow::bail!("update staging authority is invalid");
        }
        stage = "staging_result_name";
        if result_path != staging.join("update-result.json") {
            anyhow::bail!("update staging authority is invalid");
        }
        stage = "staging_parent";
        if staging.parent() != Some(plan.installation.paths.data_root.as_path()) {
            anyhow::bail!("update staging authority is invalid");
        }
        stage = "staging_prefix";
        if !staging
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("dev-auth-update-sources-"))
        {
            anyhow::bail!("update staging authority is invalid");
        }
        stage = "staging_type";
        if !staging_metadata.is_dir() || staging_metadata.file_type().is_symlink() {
            anyhow::bail!("update staging authority is invalid");
        }
        stage = "staging_owner";
        if staging_metadata.uid() != nix::unistd::Uid::effective().as_raw() {
            anyhow::bail!("update staging authority is invalid");
        }
        stage = "staging_mode";
        if staging_metadata.mode() & 0o777 != 0o700 {
            anyhow::bail!("update staging authority is invalid");
        }
        stage = "candidate_identity";
        if crate::setup_v3::setup_apply_candidate_path(&plan, digest)?.is_some() {
            anyhow::bail!("update worker is not the authenticated setup candidate");
        }
        stage = "apply";
        let applied = crate::setup_v3::apply_setup_plan_v3(&plan, digest, &BTreeMap::new());
        let (outcome, changed, verified) = match applied {
            Ok(report) if report.verified => (WorkerOutcome::Completed, Some(report.changed), true),
            Ok(report) if !report.input_required.is_empty() => {
                (WorkerOutcome::RequiresSetup, Some(report.changed), false)
            }
            Ok(report) => (WorkerOutcome::Blocked, Some(report.changed), false),
            Err(_) => (WorkerOutcome::Operational, None, false),
        };
        Ok(WorkerReport {
            schema: WORKER_SCHEMA.into(),
            plan_sha256: digest.into(),
            release_version: plan.installation.request.version,
            outcome,
            changed,
            verified,
        })
    };
    let report = match run() {
        Ok(report) => report,
        Err(_) => {
            eprintln!("dev-auth: update worker {stage} failed");
            return 4;
        }
    };
    let encoded = match serde_jcs::to_vec(&report) {
        Ok(encoded) => encoded,
        Err(_) => return 1,
    };
    if dev_tools_installation::write_atomic_document(
        result_path,
        &encoded,
        &dev_tools_installation::DocumentAuthority {
            owner_uid: nix::unistd::Uid::effective().as_raw(),
            mode: 0o600,
            limit: 4096,
        },
        None,
    )
    .is_err()
    {
        return 1;
    }
    match report.outcome {
        WorkerOutcome::Completed => 0,
        WorkerOutcome::RequiresSetup | WorkerOutcome::Blocked => 3,
        WorkerOutcome::Operational => 1,
    }
}

struct DevAuthUpdateAdapter {
    operation: UpdateOperation,
    paths: Option<crate::setup::SetupPaths>,
    mode: Option<crate::setup::InstallMode>,
    after_mutation: bool,
    restored_absence: bool,
    installation_storage: Option<StableReleaseStorage>,
    observation_storage: Option<StableReleaseObservationStorage>,
}

impl DevAuthUpdateAdapter {
    fn new(operation: UpdateOperation) -> Self {
        Self {
            operation,
            paths: None,
            mode: None,
            after_mutation: false,
            restored_absence: false,
            installation_storage: None,
            observation_storage: None,
        }
    }

    fn needs_payload(&self) -> bool {
        matches!(
            self.operation,
            UpdateOperation::Apply { .. } | UpdateOperation::Install { .. }
        )
    }

    fn installation_storage(&self) -> Result<&StableReleaseStorage, UpdateError> {
        self.installation_storage
            .as_ref()
            .ok_or(UpdateError::new(UpdateErrorKind::RequiresSetup))
    }

    fn observation_storage(&self) -> Result<&StableReleaseObservationStorage, UpdateError> {
        self.observation_storage
            .as_ref()
            .ok_or(UpdateError::new(UpdateErrorKind::RequiresSetup))
    }

    fn artifact_available(
        &self,
        observation: &stable_release::StableReleaseObservation,
    ) -> Result<bool, UpdateError> {
        if !self.needs_payload() {
            return Ok(false);
        }
        let storage = self.installation_storage()?;
        let Some(cached) = stable_release::observe_prepared_release(storage, observation)
            .map_err(|_| UpdateError::new(UpdateErrorKind::Authority))?
        else {
            return Ok(false);
        };
        stable_release::require_accepted_release(storage, &cached.verified)
            .map_err(|_| UpdateError::new(UpdateErrorKind::Authority))?;
        Ok(true)
    }
}

impl UpdateAdapter for DevAuthUpdateAdapter {
    fn inspect(&mut self) -> Result<InstallationSnapshot, UpdateError> {
        if self.after_mutation {
            if self.restored_absence {
                return Ok(InstallationSnapshot::absent());
            }
            let paths = self
                .paths
                .as_ref()
                .ok_or(UpdateError::new(UpdateErrorKind::Operational))?;
            let report = crate::setup::verify_at_read_only(paths)
                .map_err(|_| UpdateError::new(UpdateErrorKind::Authority))?;
            let version = Version::parse(&report.version)
                .map_err(|_| UpdateError::new(UpdateErrorKind::Authority))?;
            return Ok(InstallationSnapshot::managed(Some(version)));
        }
        let installed = crate::setup::running_executable_has_version_layout()
            .map_err(|_| UpdateError::new(UpdateErrorKind::Operational))?;
        if !installed {
            if matches!(self.operation, UpdateOperation::Install { .. }) {
                return Ok(InstallationSnapshot::requires_setup(None));
            }
            return Ok(InstallationSnapshot::external(
                Version::parse(env!("CARGO_PKG_VERSION")).ok(),
            ));
        }
        let (paths, receipt) = crate::setup::current_installation()
            .map_err(|_| UpdateError::new(UpdateErrorKind::Authority))?;
        let version = Version::parse(&receipt.version)
            .map_err(|_| UpdateError::new(UpdateErrorKind::Authority))?;
        if matches!(
            self.operation,
            UpdateOperation::Apply { .. } | UpdateOperation::Rollback
        ) && receipt.mode == crate::setup::InstallMode::Strong
            && !nix::unistd::Uid::effective().is_root()
        {
            return Ok(InstallationSnapshot::requires_setup(Some(version)));
        }
        if matches!(
            self.operation,
            UpdateOperation::Apply { .. } | UpdateOperation::Rollback
        ) {
            let owner_uid = if receipt.mode == crate::setup::InstallMode::Strong {
                0
            } else {
                nix::unistd::Uid::effective().as_raw()
            };
            let transition = crate::setup_transition::retained_transition(&paths, owner_uid)
                .map_err(|_| UpdateError::new(UpdateErrorKind::Authority))?;
            match (self.operation, transition.as_ref().map(|state| state.phase)) {
                (UpdateOperation::Apply { .. }, Some(crate::setup_transition::Phase::Accepted)) => {
                }
                (UpdateOperation::Apply { .. }, None)
                | (
                    UpdateOperation::Apply { .. },
                    Some(crate::setup_transition::Phase::RestoredInactive),
                )
                | (UpdateOperation::Rollback, None) => {
                    return Ok(InstallationSnapshot::requires_setup(Some(version)));
                }
                (UpdateOperation::Apply { .. }, _) => {
                    return Err(UpdateError::new(UpdateErrorKind::Blocked));
                }
                _ => {}
            }
        }
        self.paths = Some(paths);
        self.mode = Some(receipt.mode);
        self.installation_storage = Some(
            stable_release::native_release_storage(receipt.mode)
                .map_err(|_| UpdateError::new(UpdateErrorKind::Operational))?,
        );
        self.observation_storage = Some(
            stable_release::native_user_observation_storage()
                .map_err(|_| UpdateError::new(UpdateErrorKind::Operational))?,
        );
        Ok(InstallationSnapshot::managed(Some(version)))
    }

    fn load_authenticated_candidate(
        &mut self,
    ) -> Result<Option<AuthenticatedCandidate>, UpdateError> {
        let observation =
            stable_release::load_user_release_observation_classified(self.observation_storage()?)
                .map_err(map_observation_failure)?;
        observation
            .map(|observation| {
                let verified = observation
                    .verified()
                    .map_err(|_| UpdateError::new(UpdateErrorKind::Authenticity))?;
                let available = self.artifact_available(&observation)?;
                AuthenticatedCandidate::new(verified, observation.checked_at_unix(), available)
            })
            .transpose()
    }

    fn refresh_authenticated_candidate(&mut self) -> Result<AuthenticatedCandidate, UpdateError> {
        let observation =
            stable_release::check_user_stable_release_classified(self.observation_storage()?)
                .map_err(map_observation_failure)?;
        let verified = observation
            .verified()
            .map_err(|_| UpdateError::new(UpdateErrorKind::Authenticity))?;
        let available = self.artifact_available(&observation)?;
        AuthenticatedCandidate::new(verified, observation.checked_at_unix(), available)
    }

    fn prepare_artifact(
        &mut self,
        candidate: &AuthenticatedCandidate,
    ) -> Result<AuthenticatedCandidate, UpdateError> {
        let storage = self.installation_storage()?;
        let observation =
            stable_release::load_user_release_observation_classified(self.observation_storage()?)
                .map_err(map_observation_failure)?
                .ok_or(UpdateError::new(UpdateErrorKind::Authority))?;
        if observation.checked_at_unix() != candidate.checked_at_unix()
            || observation
                .verified()
                .map_err(|_| UpdateError::new(UpdateErrorKind::Authenticity))?
                != *candidate.verified()
        {
            return Err(UpdateError::new(UpdateErrorKind::Authority));
        }
        stable_release::prepare_observed_release(storage, &observation)
            .map_err(|_| UpdateError::new(UpdateErrorKind::Operational))?;
        AuthenticatedCandidate::new(
            candidate.verified().clone(),
            candidate.checked_at_unix(),
            true,
        )
    }

    fn install(&mut self, _: &AuthenticatedCandidate) -> Result<bool, UpdateError> {
        Err(UpdateError::new(UpdateErrorKind::RequiresSetup))
    }

    fn apply(&mut self, candidate: &AuthenticatedCandidate) -> Result<bool, UpdateError> {
        let storage = self.installation_storage()?;
        let staged = stable_release::stage_latest_stable_release(storage, true)
            .map_err(|_| UpdateError::new(UpdateErrorKind::Authority))?;
        if !staged_matches_candidate(&staged, candidate) {
            return Err(UpdateError::new(UpdateErrorKind::Authority));
        }
        let plan = crate::setup_v3::build_update_plan_for_verified_release(
            &staged,
            matches!(self.operation, UpdateOperation::Apply { offline: true }),
        )
        .map_err(|_| UpdateError::new(UpdateErrorKind::Authority))?;
        let path = plan
            .write_private_plan()
            .map_err(|_| UpdateError::new(UpdateErrorKind::Operational))?;
        let result = plan.private_result_path();
        let candidate_executable =
            crate::setup_v3::setup_apply_candidate_path(&plan.plan, &plan.sha256)
                .map_err(|_| UpdateError::new(UpdateErrorKind::Authority))?;
        let executable = candidate_executable
            .or_else(|| std::env::current_exe().ok())
            .ok_or(UpdateError::new(UpdateErrorKind::Operational))?;
        self.after_mutation = true;
        let status = run_worker_child(
            &executable,
            &path,
            &plan.sha256,
            &result,
            plan.staging_lock(),
        )?;
        if status.code() == Some(4) && !result.exists() {
            return Err(UpdateError::new(UpdateErrorKind::Authority).with_changed(false));
        }
        let report = read_worker_report(&result, &plan.sha256, &staged.verified.version)?;
        match (
            status.code(),
            report.outcome,
            report.verified,
            report.changed,
        ) {
            (Some(0), WorkerOutcome::Completed, true, Some(changed)) => Ok(changed),
            (Some(3), WorkerOutcome::RequiresSetup, false, Some(changed)) => {
                Err(UpdateError::new(UpdateErrorKind::RequiresSetup).with_changed(changed))
            }
            (Some(3), WorkerOutcome::Blocked, false, Some(changed)) => {
                Err(UpdateError::new(UpdateErrorKind::Blocked).with_changed(changed))
            }
            (Some(1), WorkerOutcome::Operational, false, _) => {
                Err(UpdateError::new(UpdateErrorKind::Operational))
            }
            _ => Err(UpdateError::new(UpdateErrorKind::Authority)),
        }
    }

    fn rollback(&mut self) -> Result<bool, UpdateError> {
        let mode = self
            .mode
            .ok_or(UpdateError::new(UpdateErrorKind::RequiresSetup))?;
        let paths = self
            .paths
            .as_ref()
            .ok_or(UpdateError::new(UpdateErrorKind::RequiresSetup))?;
        let owner_uid = if mode == crate::setup::InstallMode::Strong {
            0
        } else {
            nix::unistd::Uid::effective().as_raw()
        };
        crate::setup_v3::reclaim_abandoned_update_staging_at(&paths.data_root, owner_uid)
            .map_err(|_| UpdateError::new(UpdateErrorKind::Authority).with_changed(false))?;
        self.after_mutation = true;
        let report = crate::setup_v3::restore_setup_v3(mode);
        if report.exit_code == 0 && report.verified {
            if let Some(paths) = &self.paths {
                self.restored_absence = matches!(
                    fs::symlink_metadata(paths.data_root.join("install-v2.json")),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound
                );
            }
            return Ok(report.changed.unwrap_or(false));
        }
        let kind = match report.exit_code {
            3 => UpdateErrorKind::Blocked,
            4 => UpdateErrorKind::Authority,
            130 => UpdateErrorKind::Interrupted,
            _ => UpdateErrorKind::Operational,
        };
        let error = UpdateError::new(kind);
        Err(match report.changed {
            Some(changed) => error.with_changed(changed),
            None => error,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    #[test]
    fn inherited_worker_lock_remains_exclusive_after_parent_closes_its_copy() {
        let root = tempfile::tempdir().unwrap();
        let lock_path = root.path().join("update.lock");
        let parent = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        fs2::FileExt::lock_exclusive(&parent).unwrap();
        let child_fd = rustix::io::fcntl_dupfd_cloexec(&parent, 3)
            .unwrap()
            .into_raw_fd();
        let worker =
            validate_inherited_staging_lock(&root.path().join("update-plan.json"), child_fd)
                .unwrap();
        drop(parent);
        let another = fs::OpenOptions::new().read(true).open(&lock_path).unwrap();
        assert!(fs2::FileExt::try_lock_exclusive(&another).is_err());
        drop(worker);
        fs2::FileExt::try_lock_exclusive(&another).unwrap();
    }
}
