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
use sha2::Digest;
use std::collections::BTreeMap;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

const REQUEST_SCHEMA: &str = "dev-auth-update-apply-request-v1";
const REQUEST_LIMIT: u64 = 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerRequest {
    schema: String,
    accepted_plan_sha256: String,
    installation_receipt_sha256: String,
    intent: crate::deployment::DeploymentIntent,
    release: crate::release_manifest::VerifiedDevAuthRelease,
}

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
    request_sha256: String,
    setup_plan_sha256: String,
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
    let policy = UpdatePolicy::standard(ProductId::parse("dev-auth").expect("fixed product id")); // INVARIANT: this literal satisfies the product ID grammar.
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
        || report.request_sha256 != digest
        || report.setup_plan_sha256.len() != 64
        || !report
            .setup_plan_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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
    staging_directory: &fs::File,
    expected: &crate::release_manifest::VerifiedDevAuthRelease,
) -> Result<std::process::ExitStatus, UpdateError> {
    let held = dev_tools_command::HeldExecutable::open(executable)
        .map_err(|_| UpdateError::new(UpdateErrorKind::Authority).with_changed(false))?;
    let mut retained_executable = held
        .open_read_handle()
        .map_err(|_| UpdateError::new(UpdateErrorKind::Authority).with_changed(false))?;
    let identity = dev_tools_installation::ArtifactIdentity::from_open_unix_file(
        &mut retained_executable,
        expected.artifact_length,
        |metadata| {
            anyhow::ensure!(
                metadata.uid() == nix::unistd::Uid::effective().as_raw()
                    && metadata.mode() & 0o111 != 0
                    && metadata.mode() & 0o022 == 0
                    && metadata.nlink() == 1,
                "update candidate custody is invalid"
            );
            Ok(())
        },
    )
    .map_err(|_| UpdateError::new(UpdateErrorKind::Authority))?;
    if identity.length != expected.artifact_length || identity.sha256 != expected.artifact_sha256 {
        return Err(UpdateError::new(UpdateErrorKind::Authority));
    }
    let directory_fd = staging_directory.as_raw_fd();
    // Execute the retained opened inode, never reopen the candidate pathname.
    let mut command = held
        .command(std::ffi::OsStr::new("dev-auth"))
        .map_err(|_| UpdateError::new(UpdateErrorKind::Authority).with_changed(false))?;
    let parent_pid = std::process::id();
    let lock_fd = staging_lock.as_raw_fd();
    command
        .arg0("dev-auth")
        .args(["update-worker", "--request"])
        .arg(plan)
        .args(["--sha256", digest, "--result"])
        .arg(result)
        .arg("--staging-lock-fd")
        .arg(lock_fd.to_string())
        .arg("--staging-dir-fd")
        .arg(directory_fd.to_string())
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
            for fd in [lock_fd, directory_fd] {
                if nix::libc::fcntl(fd, nix::libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let output =
        dev_tools_command::run_prepared_bounded_command(&mut command, WORKER_TIMEOUT, 64 * 1024)
            .map_err(|error| {
                UpdateError::new(match error.kind() {
                    dev_tools_command::BoundedCommandErrorKind::Cancelled
                    | dev_tools_command::BoundedCommandErrorKind::TimedOut => {
                        UpdateErrorKind::Interrupted
                    }
                    _ => UpdateErrorKind::Operational,
                })
            })?;
    Ok(output.status)
}

// A raw inherited number conveys no Rust ownership. Duplicate it with one
// kernel operation, then own only the fresh close-on-exec descriptor. Safe
// callers can retain/drop their original handle without double-close hazards.
fn duplicate_worker_descriptor(fd: RawFd) -> anyhow::Result<fs::File> {
    anyhow::ensure!(fd >= 3, "update staging descriptor is invalid");
    // SAFETY: F_DUPFD_CLOEXEC takes only integer arguments. The kernel checks
    // the supplied number and returns a fresh descriptor owned by this call.
    let duplicated = unsafe { nix::libc::fcntl(fd, nix::libc::F_DUPFD_CLOEXEC, 3) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error()).context("duplicate update staging descriptor");
    }
    // SAFETY: the successful duplication above creates this live, otherwise
    // unowned descriptor. File is its sole Rust owner on every return path.
    let retained = unsafe { fs::File::from_raw_fd(duplicated) };
    // These private protocol descriptors remain usable by their original
    // owner, but must not leak into subsequent native helper executions.
    // SAFETY: both operations use only integer descriptor/flag arguments;
    // the kernel handles an unavailable concurrently closed number as an error.
    let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) };
    if flags < 0
        || unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFD, flags | nix::libc::FD_CLOEXEC) } < 0
    {
        return Err(std::io::Error::last_os_error())
            .context("restrict update descriptor inheritance");
    }
    Ok(retained)
}

fn validate_inherited_staging_lock(plan_path: &Path, fd: RawFd) -> anyhow::Result<fs::File> {
    let file = duplicate_worker_descriptor(fd)?;
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

/// Only the authenticated candidate derives and executes the replacement plan.
/// It has no network callback and no credential input; its embedded native
/// payloads supply the next generation rather than those of the old binary.
/// Descriptor numbers are borrowed, duplicated into private close-on-exec
/// owners and marked close-on-exec on their original handles. This safe API
/// never consumes a caller's Rust descriptor ownership.
pub fn run_apply_worker(
    request_path: &Path,
    digest: &str,
    result_path: &Path,
    lock_fd: RawFd,
    directory_fd: RawFd,
) -> i32 {
    let _staging_lock = match validate_inherited_staging_lock(request_path, lock_fd) {
        Ok(lock) => lock,
        Err(_) => return 4,
    };
    if directory_fd == lock_fd {
        return 4;
    }
    let staging_directory = match duplicate_worker_descriptor(directory_fd) {
        Ok(directory) => directory,
        Err(_) => return 4,
    };
    let mut stage = "request_read";
    let mut run = || -> anyhow::Result<WorkerReport> {
        let authority = dev_tools_installation::DocumentAuthority {
            owner_uid: nix::unistd::Uid::effective().as_raw(),
            mode: 0o600,
            limit: REQUEST_LIMIT,
        };
        let document = dev_tools_installation::read_atomic_document(request_path, &authority)?
            .context("update request is absent")?;
        anyhow::ensure!(
            format!("{:x}", sha2::Sha256::digest(&document.bytes)) == digest,
            "update request digest differs"
        );
        let request: WorkerRequest = serde_json::from_slice(&document.bytes)?;
        anyhow::ensure!(
            request.schema == REQUEST_SCHEMA,
            "update request schema differs"
        );
        stage = "staging_custody";
        let staging = request_path
            .parent()
            .context("update request has no parent")?;
        let named = fs::symlink_metadata(staging)?;
        let held = staging_directory.metadata()?;
        anyhow::ensure!(
            request_path.file_name() == Some(std::ffi::OsStr::new("update-request.json"))
                && result_path == staging.join("update-result.json")
                && staging
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("dev-auth-update-sources-"))
                && named.is_dir()
                && !named.file_type().is_symlink()
                && named.uid() == authority.owner_uid
                && named.mode() & 0o7777 == 0o700
                && held.dev() == named.dev()
                && held.ino() == named.ino(),
            "update staging authority differs"
        );
        stage = "candidate_identity";
        let native = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
            .context("update native account is absent")?;
        let paths = match request.intent.mode {
            crate::deployment::DeploymentMode::Strong if native.uid.is_root() => {
                crate::setup::SetupPaths::strong()
            }
            crate::deployment::DeploymentMode::UserOnly if !native.uid.is_root() => {
                crate::setup::SetupPaths::user_only(&native.dir)
            }
            _ => anyhow::bail!("update requires the installation owner"),
        };
        let receipt =
            crate::setup::read_install_receipt_at(&paths)?.context("update receipt is absent")?;
        anyhow::ensure!(
            staging.parent() == Some(paths.data_root.as_path()),
            "update staging root differs"
        );
        let storage = stable_release::native_release_storage(receipt.mode)?;
        let staged = stable_release::load_exact_accepted_release(&storage, &request.release)?;
        anyhow::ensure!(
            staged.verified == request.release,
            "update release authority differs"
        );
        anyhow::ensure!(
            crate::setup::setup_executable_identity(&std::env::current_exe()?)?
                == (
                    request.release.artifact_length,
                    request.release.artifact_sha256.clone()
                ),
            "worker is not the authenticated candidate"
        );
        stage = "accepted_authority";
        let preservation = crate::setup_v3::validate_update_intent_from_accepted_at(
            &paths,
            &receipt,
            &request.intent,
            &request.accepted_plan_sha256,
            &request.installation_receipt_sha256,
            staging,
        )?;
        stage = "plan_build";
        let plan = crate::setup_v3::build_preserving_update_plan(
            request.intent,
            request.release,
            preservation,
        )?;
        let (_, plan_sha256) = crate::setup_v3::render_setup_plan_v3(&plan)?;
        stage = "apply";
        let applied = crate::setup_v3::apply_setup_plan_v3(&plan, &plan_sha256, &BTreeMap::new());
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
            request_sha256: digest.into(),
            setup_plan_sha256: plan_sha256,
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
            let report = crate::setup::observe_update_installation_identity_at(paths)
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
        let mut sources = crate::setup_v3::prepare_update_intent_from_accepted()
            .map_err(|_| UpdateError::new(UpdateErrorKind::Authority))?;
        sources.intent.offline = matches!(self.operation, UpdateOperation::Apply { offline: true });
        let request = WorkerRequest {
            schema: REQUEST_SCHEMA.into(),
            accepted_plan_sha256: sources.accepted_plan_sha256.clone(),
            installation_receipt_sha256: sources.installation_receipt_sha256.clone(),
            intent: sources.intent.clone(),
            release: staged.verified.clone(),
        };
        let bytes = serde_jcs::to_vec(&request)
            .map_err(|_| UpdateError::new(UpdateErrorKind::Operational))?;
        let digest = format!("{:x}", sha2::Sha256::digest(&bytes));
        let path = sources.source_directory().join("update-request.json");
        let result = sources.source_directory().join("update-result.json");
        dev_tools_installation::write_atomic_document(
            &path,
            &bytes,
            &dev_tools_installation::DocumentAuthority {
                owner_uid: nix::unistd::Uid::effective().as_raw(),
                mode: 0o600,
                limit: REQUEST_LIMIT,
            },
            None,
        )
        .map_err(|_| UpdateError::new(UpdateErrorKind::Operational))?;
        self.after_mutation = true;
        let status = run_worker_child(
            &staged.verified.artifact_path,
            &path,
            &digest,
            &result,
            sources.staging_lock(),
            sources.staging_directory(),
            &staged.verified,
        )?;
        if status.code() == Some(4) && !result.exists() {
            return Err(UpdateError::new(UpdateErrorKind::Authority).with_changed(false));
        }
        let report = read_worker_report(&result, &digest, &staged.verified.version)?;
        match (
            status.code(),
            report.outcome,
            report.verified,
            report.changed,
        ) {
            (Some(0), WorkerOutcome::Completed, true, Some(changed)) => {
                let paths = self
                    .paths
                    .as_ref()
                    .ok_or(UpdateError::new(UpdateErrorKind::Authority).with_changed(changed))?;
                let owner = if self.mode == Some(crate::setup::InstallMode::Strong) {
                    0
                } else {
                    nix::unistd::Uid::effective().as_raw()
                };
                let accepted =
                    crate::setup_transition::retained_transition(paths, owner).map_err(|_| {
                        UpdateError::new(UpdateErrorKind::Authority).with_changed(changed)
                    })?;
                if !accepted.is_some_and(|transition| {
                    transition.phase == crate::setup_transition::Phase::Accepted
                        && transition.plan_sha256 == report.setup_plan_sha256
                }) {
                    return Err(UpdateError::new(UpdateErrorKind::Authority).with_changed(changed));
                }
                Ok(changed)
            }
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
    use std::os::unix::fs::OpenOptionsExt;

    #[test]
    fn safe_worker_descriptor_validation_does_not_consume_caller_ownership() {
        let root = tempfile::tempdir().unwrap();
        let original = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.path().join("update.lock"))
            .unwrap();
        fs2::FileExt::lock_exclusive(&original).unwrap();
        let worker = validate_inherited_staging_lock(
            &root.path().join("update-request.json"),
            original.as_raw_fd(),
        )
        .unwrap();
        drop(worker);
        assert!(original.metadata().is_ok());
        assert!(duplicate_worker_descriptor(-1).is_err());
    }

    #[test]
    fn worker_report_rejects_unbound_identity_and_unknown_authority() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("update-result.json");
        let report = WorkerReport {
            schema: WORKER_SCHEMA.into(),
            request_sha256: "1".repeat(64),
            setup_plan_sha256: "3".repeat(64),
            release_version: "0.5.1".into(),
            outcome: WorkerOutcome::Completed,
            changed: Some(true),
            verified: true,
        };
        let authority = dev_tools_installation::DocumentAuthority {
            owner_uid: nix::unistd::geteuid().as_raw(),
            mode: 0o600,
            limit: 4096,
        };
        let encoded = serde_jcs::to_vec(&report).unwrap();
        dev_tools_installation::write_atomic_document(&path, &encoded, &authority, None).unwrap();
        assert!(read_worker_report(&path, &"1".repeat(64), "0.5.1").is_ok());
        assert!(read_worker_report(&path, &"2".repeat(64), "0.5.1").is_err());
        assert!(read_worker_report(&path, &"1".repeat(64), "0.5.2").is_err());
        let mut value = serde_json::to_value(&report).unwrap();
        value["execute"] = serde_json::Value::String("caller-controlled command".into());
        assert!(serde_json::from_value::<WorkerReport>(value).is_err());
    }

    #[test]
    fn inherited_worker_lock_remains_exclusive_after_parent_closes_its_copy() {
        if crate::test_isolation::run_isolated(concat!(
            module_path!(),
            "::inherited_worker_lock_remains_exclusive_after_parent_closes_its_copy"
        )) {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let lock_path = root.path().join("update.lock");
        let parent = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        fs2::FileExt::lock_exclusive(&parent).unwrap();
        let child_descriptor = rustix::io::fcntl_dupfd_cloexec(&parent, 3).unwrap();
        let worker = validate_inherited_staging_lock(
            &root.path().join("update-request.json"),
            child_descriptor.as_raw_fd(),
        )
        .unwrap();
        drop(child_descriptor);
        drop(parent);
        let another = fs::OpenOptions::new().read(true).open(&lock_path).unwrap();
        assert!(fs2::FileExt::try_lock_exclusive(&another).is_err());
        drop(worker);
        fs2::FileExt::try_lock_exclusive(&another).unwrap();
    }
}
