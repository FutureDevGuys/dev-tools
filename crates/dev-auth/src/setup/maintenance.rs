//! Separate ordinary maintenance helper ownership. No workload launcher authority
//! or policy permission is inferred from installation of this fixed helper.
use super::*;
use dev_tools_installation::{
    ArtifactIdentity, DocumentAuthority, DocumentDirectoryPreparation, ExistingDocumentDirectory,
};

pub const HELPER_PATH: &str = "/usr/local/lib/dev-auth/dev-auth-maintenance-helper";
pub const RECEIPT_PATH: &str = "/usr/local/lib/dev-auth/maintenance-helper-v1.json";
pub const POLICY_PATH: &str = "/etc/dev-auth/privilege-policy-v1.json";
pub const POLKIT_PATH: &str =
    "/usr/share/polkit-1/actions/com.futuredevguys.dev-auth.maintenance.policy";
pub const POLKIT: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<policyconfig><vendor>Future Dev Guys</vendor><action id=\"com.futuredevguys.dev-auth.maintenance\"><description>Authorize bounded Dev Auth maintenance</description><message>Administrator authentication is required for the displayed Dev Auth operation audience and expiry</message><defaults><allow_any>no</allow_any><allow_inactive>no</allow_inactive><allow_active>auth_admin</allow_active></defaults><annotate key=\"org.freedesktop.policykit.exec.path\">/usr/local/lib/dev-auth/dev-auth-maintenance-helper</annotate></action></policyconfig>\n";
const NAME: &str = "dev-auth-maintenance-helper";
const SIDECAR: &str = "maintenance-helper-v1.json";
const SCHEMA: &str = "dev-auth-maintenance-helper-v1";

pub(crate) fn supports_version(version: &str) -> bool {
    semver::Version::parse(version).is_ok_and(|version| version >= semver::Version::new(0, 5, 0))
}
fn supports(receipt: &InstallReceipt) -> bool {
    receipt.mode == InstallMode::Strong && supports_version(&receipt.version)
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    protocol: String,
    helper: SetupHelperReceipt,
    polkit_path: String,
    polkit_sha256: String,
}
fn expected(receipt: &InstallReceipt) -> Result<Receipt> {
    let mut helper = expected_setup_helper_receipt(
        Path::new(HELPER_PATH),
        receipt,
        &crate::release_manifest::target_id()?,
    );
    helper.schema = SCHEMA.into();
    helper.protocol = SCHEMA.into();
    Ok(Receipt {
        schema: SCHEMA.into(),
        protocol: SCHEMA.into(),
        helper,
        polkit_path: POLKIT_PATH.into(),
        polkit_sha256: bytes_identity(POLKIT.as_bytes()).sha256,
    })
}
fn helper_authority(owner: u32) -> DocumentAuthority {
    DocumentAuthority {
        owner_uid: owner,
        mode: 0o755,
        limit: BINARY_LIMIT,
    }
}
fn document_authority(owner: u32) -> DocumentAuthority {
    DocumentAuthority {
        owner_uid: owner,
        mode: 0o644,
        limit: RECEIPT_LIMIT,
    }
}
fn release_identity(receipt: &InstallReceipt) -> ArtifactIdentity {
    ArtifactIdentity {
        length: receipt.executable_length,
        sha256: receipt.executable_sha256.clone(),
    }
}
fn bytes_identity(bytes: &[u8]) -> ArtifactIdentity {
    ArtifactIdentity {
        length: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
    }
}

/// Fixed-leaf proof shared by initial publication and retained forward recovery.
/// The caller owns release approval, setup exclusion and product receipt CAS.
pub(super) struct Completion {
    directory: ExistingDocumentDirectory,
    source_directory: ExistingDocumentDirectory,
    source_name: std::ffi::OsString,
    polkit_directory: DocumentDirectoryPreparation,
    polkit_name: std::ffi::OsString,
    owner: u32,
    candidate: ArtifactIdentity,
    helper_observed: Option<ArtifactIdentity>,
    sidecar_observed: Option<ArtifactIdentity>,
    polkit_observed: Option<ArtifactIdentity>,
    sidecar_bytes: Vec<u8>,
}
impl Completion {
    pub(super) fn observe(
        paths: &SetupPaths,
        candidate: &InstallReceipt,
        prior: Option<&InstallReceipt>,
        source: &Path,
    ) -> Result<Option<Self>> {
        if !supports(candidate) {
            return Ok(None);
        }
        if !nix::unistd::Uid::effective().is_root()
            || paths != &SetupPaths::strong()
            || Path::new(&candidate.executable) != paths.versioned_binary(&candidate.version)
        {
            bail!("maintenance publication requires native strong installation authority");
        }
        validate_native_ancestors(Path::new(HELPER_PATH))?;
        validate_native_ancestors(Path::new(POLKIT_PATH))?;
        Self::observe_at(
            &paths.data_root,
            Path::new(POLKIT_PATH),
            candidate,
            prior,
            source,
            0,
        )
        .map(Some)
    }
    fn observe_at(
        directory: &Path,
        polkit: &Path,
        candidate: &InstallReceipt,
        prior: Option<&InstallReceipt>,
        source: &Path,
        owner: u32,
    ) -> Result<Self> {
        if !supports(candidate) {
            bail!("selected release predates maintenance helper ownership");
        }
        let directory = ExistingDocumentDirectory::open(directory, owner)?;
        let source_directory = ExistingDocumentDirectory::open(
            source
                .parent()
                .context("maintenance source has no parent")?,
            owner,
        )?;
        let source_name = source
            .file_name()
            .context("maintenance source has no name")?
            .to_owned();
        let source = source_directory
            .read(&source_name, &helper_authority(owner))?
            .context("maintenance source is absent")?;
        let candidate_identity = release_identity(candidate);
        if source.identity != candidate_identity {
            bail!("maintenance source differs from approved release");
        }
        let prior = prior.filter(|receipt| supports(receipt));
        let helper = directory.read(OsStr::new(NAME), &helper_authority(owner))?;
        if helper.as_ref().is_some_and(|value| {
            value.identity != candidate_identity
                && !prior.is_some_and(|prior| value.identity == release_identity(prior))
        }) {
            bail!("maintenance helper is outside retained executable authority");
        }
        let sidecar = directory.read(OsStr::new(SIDECAR), &document_authority(owner))?;
        let expected = expected(candidate)?;
        let prior_expected = prior.map(expected_receipt).transpose()?;
        let mut sidecar_bytes = serde_json::to_vec_pretty(&expected)?;
        if let Some(sidecar) = &sidecar {
            let parsed: Receipt = serde_json::from_slice(&sidecar.bytes)?;
            if parsed == expected {
                sidecar_bytes = sidecar.bytes.clone();
            } else if prior_expected.as_ref() != Some(&parsed) {
                bail!("maintenance receipt is outside retained release authority");
            }
        }
        let polkit_directory = DocumentDirectoryPreparation::observe(
            polkit
                .parent()
                .context("maintenance action has no parent")?,
            owner,
            0o755,
        )?;
        let polkit_name = polkit
            .file_name()
            .context("maintenance action has no name")?
            .to_owned();
        let polkit = polkit_directory.read(&polkit_name, &document_authority(owner))?;
        if polkit
            .as_ref()
            .is_some_and(|value| value.identity != bytes_identity(POLKIT.as_bytes()))
        {
            bail!("maintenance action is outside fixed product authority");
        }
        Ok(Self {
            directory,
            source_directory,
            source_name,
            polkit_directory,
            polkit_name,
            owner,
            candidate: candidate_identity,
            helper_observed: helper.map(|v| v.identity),
            sidecar_observed: sidecar.map(|v| v.identity),
            polkit_observed: polkit.map(|v| v.identity),
            sidecar_bytes,
        })
    }
    pub(super) fn needs_publication(&self) -> bool {
        self.helper_observed.as_ref() != Some(&self.candidate)
            || self.sidecar_observed.as_ref() != Some(&bytes_identity(&self.sidecar_bytes))
            || self.polkit_observed.as_ref() != Some(&bytes_identity(POLKIT.as_bytes()))
    }
    pub(super) fn verify_observed(&self) -> Result<()> {
        self.verify_progress(0, None)
    }
    fn verify_progress(
        &self,
        completed: usize,
        polkit: Option<&ExistingDocumentDirectory>,
    ) -> Result<()> {
        let source = self
            .source_directory
            .read(&self.source_name, &helper_authority(self.owner))?
            .context("maintenance source disappeared")?;
        if source.identity != self.candidate {
            bail!("maintenance source changed after admission");
        }
        for (name, authority, prior, candidate, phase) in [
            (
                NAME,
                helper_authority(self.owner),
                self.helper_observed.as_ref(),
                self.candidate.clone(),
                1,
            ),
            (
                SIDECAR,
                document_authority(self.owner),
                self.sidecar_observed.as_ref(),
                bytes_identity(&self.sidecar_bytes),
                3,
            ),
        ] {
            let current = self.directory.read(OsStr::new(name), &authority)?;
            let expected = if completed >= phase {
                Some(&candidate)
            } else {
                prior
            };
            if current.as_ref().map(|v| &v.identity) != expected {
                bail!("maintenance leaf changed after admission");
            }
        }
        let observed = match polkit {
            Some(directory) => {
                directory.read(&self.polkit_name, &document_authority(self.owner))?
            }
            None => self
                .polkit_directory
                .read(&self.polkit_name, &document_authority(self.owner))?,
        };
        let identity = bytes_identity(POLKIT.as_bytes());
        if observed.as_ref().map(|v| &v.identity)
            != if completed >= 2 {
                Some(&identity)
            } else {
                self.polkit_observed.as_ref()
            }
        {
            bail!("maintenance action changed after admission");
        }
        Ok(())
    }
    pub(super) fn complete(
        &self,
        mut verify: impl FnMut() -> Result<()>,
        mut record: impl FnMut(bool),
    ) -> Result<bool> {
        verify()?;
        self.verify_observed()?;
        let (polkit, mut changed) = self.polkit_directory.prepare()?;
        record(changed);
        verify()?;
        self.verify_progress(0, Some(&polkit))?;
        let source = self
            .source_directory
            .read(&self.source_name, &helper_authority(self.owner))?
            .context("maintenance source disappeared")?;
        let published = self.directory.write(
            OsStr::new(NAME),
            &source.bytes,
            &helper_authority(self.owner),
            self.helper_observed.as_ref(),
        )?;
        record(published);
        changed |= published;
        verify()?;
        self.verify_progress(1, Some(&polkit))?;
        let published = polkit.write(
            &self.polkit_name,
            POLKIT.as_bytes(),
            &document_authority(self.owner),
            self.polkit_observed.as_ref(),
        )?;
        record(published);
        changed |= published;
        verify()?;
        self.verify_progress(2, Some(&polkit))?;
        let published = self.directory.write(
            OsStr::new(SIDECAR),
            &self.sidecar_bytes,
            &document_authority(self.owner),
            self.sidecar_observed.as_ref(),
        )?;
        record(published);
        changed |= published;
        verify()?;
        self.verify_progress(3, Some(&polkit))?;
        Ok(changed)
    }
}
fn expected_receipt(receipt: &InstallReceipt) -> Result<Receipt> {
    expected(receipt)
}

/// Fresh installation never adopts a same-content unreceipted fixed leaf.
/// An already committed exact shared candidate is the only incomplete-install
/// exception; full setup also validates original absence in retained approval.
pub(super) fn prepare_install(
    paths: &SetupPaths,
    candidate: &InstallReceipt,
    prior: Option<&InstallReceipt>,
) -> Result<()> {
    if !supports(candidate) || prior.is_some_and(supports) {
        return Ok(());
    }
    let present = [HELPER_PATH, RECEIPT_PATH, POLKIT_PATH]
        .into_iter()
        .try_fold(false, |present, path| -> Result<bool> {
            match fs::symlink_metadata(path) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(present),
                Err(error) => Err(error.into()),
            }
        })?;
    if !present {
        return Ok(());
    }
    let shared = dev_tools_installation::read_versioned_installation_receipt(
        &shared_installation_layout(paths, InstallMode::Strong),
    )?
    .context("unreceipted maintenance artifacts lack a committed candidate")?;
    if shared.active_version != candidate.version
        || shared.active_identity != release_identity(candidate)
        || shared.previous_version.as_deref() != prior.map(|receipt| receipt.version.as_str())
        || shared.previous_identity != prior.map(release_identity)
    {
        bail!("unreceipted maintenance artifacts are outside exact interrupted installation authority");
    }
    Ok(())
}

pub(super) fn reconcile(
    paths: &SetupPaths,
    receipt: &InstallReceipt,
    prior: Option<&InstallReceipt>,
) -> Result<()> {
    if let Some(completion) =
        Completion::observe(paths, receipt, prior, Path::new(&receipt.executable))?
    {
        completion.complete(|| Ok(()), |_| {})?;
    } else if receipt.mode == InstallMode::Strong {
        require_absent()?;
    }
    Ok(())
}

pub(super) fn require_absent() -> Result<()> {
    for path in [HELPER_PATH, RECEIPT_PATH, POLKIT_PATH] {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(error.into()),
            Ok(_) => bail!("pre-maintenance release retains unexpected maintenance artifacts; use exact retained recovery"),
        }
    }
    Ok(())
}

pub(super) fn verify(paths: &SetupPaths, receipt: &InstallReceipt) -> Result<()> {
    if !supports(receipt) {
        return Ok(());
    }
    if paths != &SetupPaths::strong() {
        bail!("maintenance helper requires canonical strong layout");
    }
    validate_native_ancestors(Path::new(HELPER_PATH))?;
    validate_native_ancestors(Path::new(POLKIT_PATH))?;
    verify_at(&paths.data_root, Path::new(POLKIT_PATH), receipt, 0)
}
fn verify_at(directory: &Path, polkit: &Path, receipt: &InstallReceipt, owner: u32) -> Result<()> {
    let directory = ExistingDocumentDirectory::open(directory, owner)?;
    let helper = directory
        .read(OsStr::new(NAME), &helper_authority(owner))?
        .context("maintenance helper is absent")?;
    let sidecar = directory
        .read(OsStr::new(SIDECAR), &document_authority(owner))?
        .context("maintenance receipt is absent")?;
    let action_directory = ExistingDocumentDirectory::open(
        polkit
            .parent()
            .context("maintenance action has no parent")?,
        owner,
    )?;
    let action = action_directory
        .read(
            polkit
                .file_name()
                .context("maintenance action has no name")?,
            &document_authority(owner),
        )?
        .context("maintenance action is absent")?;
    if helper.identity != release_identity(receipt)
        || serde_json::from_slice::<Receipt>(&sidecar.bytes)? != expected(receipt)?
        || action.identity != bytes_identity(POLKIT.as_bytes())
    {
        bail!("maintenance installation differs from its receipt authority");
    }
    Ok(())
}

fn validated_installation() -> Result<InstallReceipt> {
    let paths = SetupPaths::strong();
    let receipt = read_receipt(&paths.receipt_path())?;
    if !supports(&receipt)
        || receipt.source_commit.is_none()
        || receipt.root_generation.is_none()
        || receipt.manifest_generation.is_none()
    {
        bail!("maintenance requires an authenticated helper-owning release");
    }
    validate_root_owned_executable(Path::new(HELPER_PATH), "receipt-owned maintenance helper")?;
    verify_runtime_installation_at(&paths, &receipt)?;
    verify(&paths, &receipt)?;
    Ok(receipt)
}
pub fn validate_installed_maintenance_helper() -> Result<PathBuf> {
    Ok(PathBuf::from(validated_installation()?.executable))
}

pub fn maintenance_installation_identity() -> Result<String> {
    let receipt = validated_installation()?;
    let current = std::env::current_exe()?;
    if current != Path::new(&receipt.executable) && current != Path::new(HELPER_PATH) {
        bail!("maintenance caller is outside active executable authority");
    }
    let running = fs::metadata("/proc/self/exe")?;
    let named = fs::symlink_metadata(&current)?;
    if running.dev() != named.dev() || running.ino() != named.ino() {
        bail!("running maintenance executable was replaced");
    }
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_jcs::to_vec(&receipt)?)
    ))
}
pub fn validate_running_maintenance_helper() -> Result<PathBuf> {
    let current = std::env::current_exe()?;
    if current != Path::new(HELPER_PATH) {
        bail!("maintenance requires its dedicated installed helper");
    }
    let running = fs::metadata("/proc/self/exe")?;
    let named = fs::symlink_metadata(HELPER_PATH)?;
    if running.dev() != named.dev() || running.ino() != named.ino() {
        bail!("running maintenance helper was replaced");
    }
    validate_installed_maintenance_helper()
}

fn validate_native_ancestors(path: &Path) -> Result<()> {
    use std::path::Component;
    if !path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        bail!("maintenance destination is not canonical");
    }
    let mut current = PathBuf::new();
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        current.push(component.as_os_str());
        if components.peek().is_none() {
            break;
        }
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            bail!("maintenance destination has unsafe ancestor custody");
        }
    }
    Ok(())
}

/// Explicit root-only policy publication. Absence remains the default-deny state.
/// An accepted setup generation is not rewritten; restoration rejects later drift.
pub fn install_privilege_policy(
    source: &Path,
    sha256: &str,
    expected_current_sha256: Option<&str>,
) -> Result<bool> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("administrative policy installation requires native root");
    }
    crate::privilege::policy::hex_digest(sha256)?;
    if let Some(expected) = expected_current_sha256 {
        crate::privilege::policy::hex_digest(expected)?;
    }
    let (paths, _lease) =
        native_setup_exclusion(InstallMode::Strong, "administrative policy publication")?;
    crate::setup_transition::require_accepted(&paths, 0)?;
    validate_installed_maintenance_helper()?;
    let bytes = crate::privilege::custody::read_document(source, 0, 0o644)?;
    let path = Path::new(POLICY_PATH);
    validate_native_ancestors(path)?;
    publish_policy_at(path, &bytes, sha256, expected_current_sha256, 0)
}

fn publish_policy_at(
    path: &Path,
    bytes: &[u8],
    sha256: &str,
    expected_current_sha256: Option<&str>,
    owner: u32,
) -> Result<bool> {
    crate::privilege::policy::hex_digest(sha256)?;
    if let Some(expected) = expected_current_sha256 {
        crate::privilege::policy::hex_digest(expected)?;
    }
    if bytes_identity(bytes).sha256 != sha256 {
        bail!("administrative policy differs from approved source digest");
    }
    crate::privilege::policy::parse_policy(bytes)?;
    let directory = ExistingDocumentDirectory::open(
        path.parent()
            .context("administrative policy has no parent")?,
        owner,
    )?;
    let authority = DocumentAuthority {
        owner_uid: owner,
        mode: 0o644,
        limit: POLICY_LIMIT,
    };
    let name = path
        .file_name()
        .context("administrative policy has no name")?;
    let current = directory.read(name, &authority)?;
    if current
        .as_ref()
        .map(|document| document.identity.sha256.as_str())
        != expected_current_sha256
    {
        bail!("administrative policy changed before publication");
    }
    directory.write(
        name,
        bytes,
        &authority,
        current.as_ref().map(|document| &document.identity),
    )
}

pub(crate) fn candidate_sidecar(
    plan: &SetupPlan,
    prior: Option<&InstallReceipt>,
) -> Result<Vec<u8>> {
    let receipt = selected_installation_receipt(
        &plan.paths,
        &plan.request,
        plan.verified_release.as_ref(),
        prior,
        &ArtifactIdentity {
            length: plan.source_length,
            sha256: plan.source_sha256.clone(),
        },
    );
    serde_json::to_vec_pretty(&expected(&receipt)?)
        .context("serialize retained maintenance receipt")
}
pub(crate) fn validate_retained_sidecar(
    bytes: Option<&[u8]>,
    prior: Option<&InstallReceipt>,
) -> Result<()> {
    match (bytes, prior.filter(|receipt| supports(receipt))) {
        (Some(bytes), Some(receipt))
            if serde_json::from_slice::<Receipt>(bytes)? == expected(receipt)? =>
        {
            Ok(())
        }
        (None, None) => Ok(()),
        _ => bail!("retained maintenance receipt differs from original release authority"),
    }
}

/// Retire only exact receipt-owned artifacts, tolerating interrupted removal.
/// No policy is removed: administrator authority remains independently owned.
pub(super) fn remove(paths: &SetupPaths, receipt: &InstallReceipt) -> Result<bool> {
    if !supports(receipt) {
        return Ok(false);
    }
    if !nix::unistd::Uid::effective().is_root() || paths != &SetupPaths::strong() {
        bail!("maintenance removal requires native strong authority");
    }
    remove_at(&paths.data_root, Path::new(POLKIT_PATH), receipt, 0)
}
fn remove_at(
    directory: &Path,
    polkit: &Path,
    receipt: &InstallReceipt,
    owner: u32,
) -> Result<bool> {
    let directory = ExistingDocumentDirectory::open(directory, owner)?;
    let action_directory = ExistingDocumentDirectory::open(
        polkit
            .parent()
            .context("maintenance action has no parent")?,
        owner,
    )?;
    let name = polkit
        .file_name()
        .context("maintenance action has no name")?;
    let helper = directory.read(OsStr::new(NAME), &helper_authority(owner))?;
    let sidecar = directory.read(OsStr::new(SIDECAR), &document_authority(owner))?;
    let action = action_directory.read(name, &document_authority(owner))?;
    if helper
        .as_ref()
        .is_some_and(|v| v.identity != release_identity(receipt))
        || action
            .as_ref()
            .is_some_and(|v| v.identity != bytes_identity(POLKIT.as_bytes()))
    {
        bail!("maintenance removal found independently changed bytes");
    }
    if let Some(sidecar) = &sidecar {
        if serde_json::from_slice::<Receipt>(&sidecar.bytes)? != expected(receipt)? {
            bail!("maintenance removal found an unrelated receipt");
        }
    }
    // The enclosing install receipt remains authority if process death already
    // removed one leaf. Observe all leaves before any retirement.
    let mut changed = directory.remove(
        OsStr::new(NAME),
        &helper_authority(owner),
        &release_identity(receipt),
    )?;
    changed |= action_directory.remove(
        name,
        &document_authority(owner),
        &bytes_identity(POLKIT.as_bytes()),
    )?;
    let sidecar_identity =
        sidecar
            .map(|v| v.identity)
            .unwrap_or(bytes_identity(&serde_json::to_vec_pretty(&expected(
                receipt,
            )?)?));
    changed |= directory.remove(
        OsStr::new(SIDECAR),
        &document_authority(owner),
        &sidecar_identity,
    )?;
    Ok(changed)
}

pub(super) fn restore_executable(
    directory: &ExistingDocumentDirectory,
    prior: Option<&InstallReceipt>,
    candidate: &InstallReceipt,
) -> Result<bool> {
    if !supports(candidate) {
        return Ok(false);
    }
    restore_executable_at(directory, prior, candidate, 0)
}
fn restore_executable_at(
    directory: &ExistingDocumentDirectory,
    prior: Option<&InstallReceipt>,
    candidate: &InstallReceipt,
    owner: u32,
) -> Result<bool> {
    let authority = helper_authority(owner);
    let current = directory.read(OsStr::new(NAME), &authority)?;
    let prior = prior.filter(|receipt| supports(receipt));
    if current.as_ref().is_some_and(|v| {
        v.identity != release_identity(candidate)
            && !prior.is_some_and(|p| v.identity == release_identity(p))
    }) {
        bail!("maintenance helper is outside retained restoration authority");
    }
    match prior {
        None => directory.remove(OsStr::new(NAME), &authority, &release_identity(candidate)),
        Some(prior) => {
            let source = Path::new(&prior.executable);
            let parent = ExistingDocumentDirectory::open(
                source
                    .parent()
                    .context("retained maintenance source has no parent")?,
                owner,
            )?;
            let source = parent
                .read(
                    source
                        .file_name()
                        .context("retained maintenance source has no name")?,
                    &authority,
                )?
                .context("retained maintenance source is absent")?;
            if source.identity != release_identity(prior) {
                bail!("retained maintenance source changed");
            }
            directory.write(
                OsStr::new(NAME),
                &source.bytes,
                &authority,
                current.as_ref().map(|v| &v.identity),
            )
        }
    }
}

pub(super) fn resume_rollback(
    paths: &SetupPaths,
    installed: &InstallReceipt,
) -> Result<Option<SetupReport>> {
    let Some(previous) = installed.previous_release.as_ref() else {
        return Ok(None);
    };
    if installed.mode != InstallMode::Strong
        || !(supports(installed) || supports_version(&previous.version))
    {
        return Ok(None);
    }
    let active = paths.data_root.join("active");
    match fs::symlink_metadata(&active) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(metadata)
            if metadata.file_type().is_symlink()
                && fs::read_link(&active)? == Path::new(&installed.executable) =>
        {
            return Ok(None)
        }
        Ok(_) => {}
    }
    let shared = dev_tools_installation::verify_versioned_installation(
        &shared_installation_layout(paths, installed.mode),
    )?;
    let Some(target) = rollback_target(paths, installed, &shared)? else {
        return Ok(None);
    };
    if !nix::unistd::Uid::effective().is_root() || paths != &SetupPaths::strong() {
        bail!("maintenance rollback requires native strong custody");
    }
    require_broker_sockets_absent()?;
    verify_receipted_installation_components(paths, &target, false, StrongAssetVerification::None)?;
    verify_linux_system_assets_against(&target.system_assets)?;
    // Every maintenance leaf is selected before changing another component.
    let completion = Completion::observe(
        paths,
        &target,
        Some(installed),
        Path::new(&target.executable),
    )?;
    if completion.is_none() {
        remove(paths, installed)?;
    }
    install_privileged_launcher(
        Path::new(&target.executable),
        Path::new(PRIVILEGED_LAUNCHER_PATH),
        paths,
    )?;
    if release_supports_setup_helper(&target) {
        reconcile_setup_helper(
            paths,
            &target,
            &crate::release_manifest::target_id()?,
            SetupHelperReconcileOptions {
                prior_receipt: Some(installed),
                allow_current_without_sidecar: true,
            },
        )?;
    } else if release_supports_setup_helper(installed) {
        remove_setup_helper(paths, installed)?;
    }
    if let Some(completion) = completion {
        completion.complete(|| Ok(()), |_| {})?;
    }
    write_receipt(&paths.receipt_path(), &target)?;
    super::verify_at(paths).map(Some)
}
fn rollback_target(
    paths: &SetupPaths,
    installed: &InstallReceipt,
    shared: &dev_tools_installation::VersionedReceipt,
) -> Result<Option<InstallReceipt>> {
    if shared.active_version == installed.version {
        return Ok(None);
    }
    let previous = installed
        .previous_release
        .as_ref()
        .context("maintenance rollback has no retained release")?;
    if shared.product != "dev-auth"
        || shared.data_root != paths.data_root
        || shared.bin_dir != paths.bin_dir
        || shared.artifact_name != "dev-auth"
        || shared.aliases != shared_product_aliases()
        || shared.active_version != previous.version
        || shared.active_identity
            != (ArtifactIdentity {
                length: previous.executable_length,
                sha256: previous.executable_sha256.clone(),
            })
        || shared.previous_version.as_deref() != Some(installed.version.as_str())
        || shared.previous_identity.as_ref() != Some(&release_identity(installed))
        || !installed.transparent_aliases.is_empty()
        || previous.system_assets != system_asset_digests()
    {
        bail!("maintenance rollback differs from exact retained binary transition");
    }
    let mut target = installed.clone();
    target.version = previous.version.clone();
    target.executable = paths
        .versioned_binary(&target.version)
        .display()
        .to_string();
    target.executable_length = previous.executable_length;
    target.executable_sha256 = previous.executable_sha256.clone();
    target.source_commit = previous.source_commit.clone();
    target.root_generation = previous.root_generation;
    target.manifest_generation = previous.manifest_generation;
    target.system_assets = previous.system_assets.clone();
    target.previous_release = Some(retained_release(installed));
    Ok(Some(target))
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture {
        _root: tempfile::TempDir,
        data: PathBuf,
        action: PathBuf,
        source: PathBuf,
        receipt: InstallReceipt,
        owner: u32,
    }
    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let data = root.path().join("data");
            let action = root.path().join("actions").join("maintenance.policy");
            let source = root.path().join("versions").join("0.5.0").join("dev-auth");
            fs::create_dir(&data).unwrap();
            fs::create_dir(action.parent().unwrap()).unwrap();
            fs::create_dir_all(source.parent().unwrap()).unwrap();
            fs::write(&source, b"synthetic maintenance candidate; never executed").unwrap();
            fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
            let identity = bytes_identity(&fs::read(&source).unwrap());
            let owner = fs::metadata(&data).unwrap().uid();
            let receipt = InstallReceipt {
                schema: RECEIPT_SCHEMA.into(),
                mode: InstallMode::Strong,
                version: "0.5.0".into(),
                executable: source.display().to_string(),
                bin_dir: root.path().join("bin").display().to_string(),
                executable_length: identity.length,
                executable_sha256: identity.sha256,
                source_commit: Some("a".repeat(40)),
                root_generation: Some(1),
                manifest_generation: Some(2),
                native_git: "/usr/bin/git".into(),
                native_gh: "/usr/bin/gh".into(),
                product_aliases: PRODUCT_ALIASES.map(str::to_owned).to_vec(),
                transparent_aliases: vec![],
                privileged_launcher: Some(PRIVILEGED_LAUNCHER_PATH.into()),
                system_assets: system_asset_digests(),
                previous_release: None,
            };
            Self {
                _root: root,
                data,
                action,
                source,
                receipt,
                owner,
            }
        }
        fn proof(&self, prior: Option<&InstallReceipt>) -> Result<Completion> {
            Completion::observe_at(
                &self.data,
                &self.action,
                &self.receipt,
                prior,
                &self.source,
                self.owner,
            )
        }
        fn verify(&self) {
            verify_at(&self.data, &self.action, &self.receipt, self.owner).unwrap();
        }
    }
    #[test]
    fn maintenance_inventory_is_versioned_and_admin_auth_is_not_cached() {
        assert!(!supports_version("0.4.99"));
        assert!(!supports_version("0.5.0-rc.1"));
        assert!(supports_version("0.5.0"));
        assert!(maintenance_current_state_paths("0.4.1").is_empty());
        assert_eq!(maintenance_current_state_paths("0.5.0").len(), 4);
        assert_eq!(linux_system_assets().len(), 5);
        assert!(POLKIT.contains("<allow_active>auth_admin</allow_active>"));
        assert!(!POLKIT.contains("auth_admin_keep"));
        assert!(!POLKIT.contains("auth_self"));
        assert!(linux_system_assets()
            .iter()
            .any(|(_, body, _)| body.contains("<allow_active>auth_self</allow_active>")));
    }
    #[test]
    fn maintenance_publication_is_distinct_ordinary_copy_and_unchanged_retry() {
        let fixture = Fixture::new();
        let proof = fixture.proof(None).unwrap();
        assert!(proof.needs_publication());
        assert!(proof.complete(|| Ok(()), |_| {}).unwrap());
        fixture.verify();
        let helper = fs::metadata(fixture.data.join(NAME)).unwrap();
        assert_eq!(helper.mode() & 0o7777, 0o755);
        assert_eq!(helper.nlink(), 1);
        assert_ne!(helper.ino(), fs::metadata(&fixture.source).unwrap().ino());
        assert!(!fixture.data.join("privilege-policy-v1.json").exists());
        let proof = fixture.proof(None).unwrap();
        assert!(!proof.needs_publication());
        assert!(!proof.complete(|| Ok(()), |_| {}).unwrap());
        assert_eq!(
            helper.ino(),
            fs::metadata(fixture.data.join(NAME)).unwrap().ino()
        );
    }
    #[test]
    fn maintenance_interrupted_publication_resumes_exact_candidate() {
        for fail_on in 1..=5 {
            let fixture = Fixture::new();
            let proof = fixture.proof(None).unwrap();
            let mut calls = 0;
            let mut changed = false;
            assert!(proof
                .complete(
                    || {
                        calls += 1;
                        if calls == fail_on {
                            bail!("synthetic interruption");
                        }
                        Ok(())
                    },
                    |value| changed |= value
                )
                .is_err());
            assert_eq!(changed, fail_on >= 3);
            fixture
                .proof(None)
                .unwrap()
                .complete(|| Ok(()), |_| {})
                .unwrap();
            fixture.verify();
        }
    }
    #[test]
    fn maintenance_unknown_collision_is_preserved_after_partial_change() {
        let fixture = Fixture::new();
        let proof = fixture.proof(None).unwrap();
        let mut calls = 0;
        let mut changed = false;
        assert!(proof
            .complete(
                || {
                    calls += 1;
                    if calls == 3 {
                        fs::write(&fixture.action, b"independent action")?;
                        fs::set_permissions(&fixture.action, fs::Permissions::from_mode(0o644))?;
                    }
                    Ok(())
                },
                |value| changed |= value
            )
            .is_err());
        assert!(changed);
        assert_eq!(fs::read(&fixture.action).unwrap(), b"independent action");
        assert!(!fixture.data.join(SIDECAR).exists());
        assert!(fixture.proof(None).is_err());
    }
    #[test]
    fn maintenance_custody_rejects_setid_links_drift_and_unknown_receipt_fields() {
        for name in [NAME, SIDECAR] {
            let fixture = Fixture::new();
            fixture
                .proof(None)
                .unwrap()
                .complete(|| Ok(()), |_| {})
                .unwrap();
            let path = fixture.data.join(name);
            let original = fs::read(&path).unwrap();
            for mode in [0o4755, 0o2755, 0o777] {
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
                assert!(fixture.proof(None).is_err());
            }
            fs::set_permissions(
                &path,
                fs::Permissions::from_mode(if name == NAME { 0o755 } else { 0o644 }),
            )
            .unwrap();
            let link = fixture.data.join("other");
            fs::hard_link(&path, &link).unwrap();
            assert!(fixture.proof(None).is_err());
            fs::remove_file(&link).unwrap();
            fs::remove_file(&path).unwrap();
            symlink(&fixture.source, &path).unwrap();
            assert!(fixture.proof(None).is_err());
            fs::remove_file(&path).unwrap();
            fs::write(&path, &original).unwrap();
            fs::set_permissions(
                &path,
                fs::Permissions::from_mode(if name == NAME { 0o755 } else { 0o644 }),
            )
            .unwrap();
            if name == SIDECAR {
                let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
                value["unapproved"] = serde_json::json!(true);
                fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
                assert!(fixture.proof(None).is_err());
            }
        }
        let fixture = Fixture::new();
        fs::set_permissions(&fixture.source, fs::Permissions::from_mode(0o4755)).unwrap();
        assert!(fixture.proof(None).is_err());
    }
    #[test]
    fn maintenance_replacement_requires_exact_prior_receipt_and_recovers_mixed_pairs() {
        let mut fixture = Fixture::new();
        fixture
            .proof(None)
            .unwrap()
            .complete(|| Ok(()), |_| {})
            .unwrap();
        let prior = fixture.receipt.clone();
        fixture.source = fixture
            .source
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("0.5.1/dev-auth");
        fs::create_dir(fixture.source.parent().unwrap()).unwrap();
        fs::write(&fixture.source, b"synthetic successor; never executed").unwrap();
        fs::set_permissions(&fixture.source, fs::Permissions::from_mode(0o755)).unwrap();
        fixture.receipt.version = "0.5.1".into();
        fixture.receipt.executable = fixture.source.display().to_string();
        let identity = bytes_identity(&fs::read(&fixture.source).unwrap());
        fixture.receipt.executable_length = identity.length;
        fixture.receipt.executable_sha256 = identity.sha256;
        assert!(fixture.proof(None).is_err());
        let proof = fixture.proof(Some(&prior)).unwrap();
        let mut calls = 0;
        assert!(proof
            .complete(
                || {
                    calls += 1;
                    if calls == 3 {
                        bail!("interrupted after copy");
                    }
                    Ok(())
                },
                |_| {}
            )
            .is_err());
        fixture
            .proof(Some(&prior))
            .unwrap()
            .complete(|| Ok(()), |_| {})
            .unwrap();
        fixture.verify();
        assert!(validate_retained_sidecar(
            Some(&serde_json::to_vec(&expected(&prior).unwrap()).unwrap()),
            Some(&prior)
        )
        .is_ok());
        assert!(validate_retained_sidecar(None, Some(&prior)).is_err());
    }
    #[test]
    fn maintenance_owned_removal_is_idempotent_and_preserves_unrelated_bytes() {
        let fixture = Fixture::new();
        fixture
            .proof(None)
            .unwrap()
            .complete(|| Ok(()), |_| {})
            .unwrap();
        fs::write(&fixture.action, b"independent action").unwrap();
        assert!(remove_at(
            &fixture.data,
            &fixture.action,
            &fixture.receipt,
            fixture.owner
        )
        .is_err());
        assert!(fixture.data.join(NAME).exists());
        fs::write(&fixture.action, POLKIT).unwrap();
        assert!(remove_at(
            &fixture.data,
            &fixture.action,
            &fixture.receipt,
            fixture.owner
        )
        .unwrap());
        assert!(!remove_at(
            &fixture.data,
            &fixture.action,
            &fixture.receipt,
            fixture.owner
        )
        .unwrap());
    }
    #[test]
    fn maintenance_stale_proof_and_source_change_do_not_publish() {
        let fixture = Fixture::new();
        let proof = fixture.proof(None).unwrap();
        fs::write(fixture.data.join(NAME), b"independent helper").unwrap();
        fs::set_permissions(fixture.data.join(NAME), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(proof
            .complete(|| Ok(()), |_| panic!("stale proof mutated"))
            .is_err());
        fs::remove_file(fixture.data.join(NAME)).unwrap();
        let proof = fixture.proof(None).unwrap();
        fs::write(&fixture.source, b"changed source").unwrap();
        assert!(proof
            .complete(|| Ok(()), |_| panic!("source drift mutated"))
            .is_err());
    }
    #[test]
    fn maintenance_policy_requires_explicit_digest_cas_and_preserves_denial() {
        let fixture = Fixture::new();
        let path = fixture.data.join("policy.json");
        let bytes = br#"{"schema":"dev-auth-privilege-policy-v1","capabilities":{}}"#;
        let digest = bytes_identity(bytes).sha256;
        assert!(publish_policy_at(&path, bytes, &"0".repeat(64), None, fixture.owner).is_err());
        assert!(!path.exists());
        assert!(publish_policy_at(&path, bytes, &digest, None, fixture.owner).unwrap());
        assert!(publish_policy_at(&path, bytes, &digest, None, fixture.owner).is_err());
        assert!(!publish_policy_at(&path, bytes, &digest, Some(&digest), fixture.owner).unwrap());
        let replacement = [bytes.as_slice(), b"\n"].concat();
        assert!(publish_policy_at(
            &path,
            &replacement,
            &bytes_identity(&replacement).sha256,
            Some(&"1".repeat(64)),
            fixture.owner
        )
        .is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(publish_policy_at(
            &path,
            &replacement,
            &bytes_identity(&replacement).sha256,
            Some(&digest),
            fixture.owner
        )
        .unwrap());
        let invalid = br#"{"schema":"dev-auth-privilege-policy-v1","capabilities":{},"allow_root_shell":true}"#;
        assert!(publish_policy_at(
            &path,
            invalid,
            &bytes_identity(invalid).sha256,
            Some(&bytes_identity(&replacement).sha256),
            fixture.owner
        )
        .is_err());
        assert_eq!(fs::read(&path).unwrap(), replacement);
    }
    #[test]
    fn maintenance_helper_restores_exact_prior_or_initial_absence() {
        let fixture = Fixture::new();
        fixture
            .proof(None)
            .unwrap()
            .complete(|| Ok(()), |_| {})
            .unwrap();
        let mut prior = fixture.receipt.clone();
        prior.version = "0.5.0".into();
        let prior_source = fixture._root.path().join("prior");
        fs::write(&prior_source, b"retained prior executable").unwrap();
        fs::set_permissions(&prior_source, fs::Permissions::from_mode(0o755)).unwrap();
        let identity = bytes_identity(b"retained prior executable");
        prior.executable = prior_source.display().to_string();
        prior.executable_length = identity.length;
        prior.executable_sha256 = identity.sha256;
        let directory = ExistingDocumentDirectory::open(&fixture.data, fixture.owner).unwrap();
        assert!(
            restore_executable_at(&directory, Some(&prior), &fixture.receipt, fixture.owner)
                .unwrap()
        );
        assert_eq!(
            fs::read(fixture.data.join(NAME)).unwrap(),
            b"retained prior executable"
        );
        assert!(
            !restore_executable_at(&directory, Some(&prior), &fixture.receipt, fixture.owner)
                .unwrap()
        );
        fs::write(fixture.data.join(NAME), b"independent helper").unwrap();
        assert!(
            restore_executable_at(&directory, Some(&prior), &fixture.receipt, fixture.owner)
                .is_err()
        );
        fs::write(fixture.data.join(NAME), fs::read(&fixture.source).unwrap()).unwrap();
        assert!(restore_executable_at(&directory, None, &fixture.receipt, fixture.owner).unwrap());
        assert!(!restore_executable_at(&directory, None, &fixture.receipt, fixture.owner).unwrap());
    }

    #[test]
    fn maintenance_rollback_selection_requires_exact_retained_binary_history() {
        let fixture = Fixture::new();
        let paths = SetupPaths {
            data_root: fixture.data.clone(),
            bin_dir: fixture._root.path().join("bin"),
        };
        let mut installed = fixture.receipt.clone();
        let mut prior = retained_release(&installed);
        prior.version = "0.4.1".into();
        prior.executable_sha256 = "b".repeat(64);
        installed.previous_release = Some(prior.clone());
        let mut shared = dev_tools_installation::VersionedReceipt {
            schema: "dev-tools-versioned-installation-v1".into(),
            product: "dev-auth".into(),
            data_root: paths.data_root.clone(),
            bin_dir: paths.bin_dir.clone(),
            artifact_name: "dev-auth".into(),
            active_version: prior.version.clone(),
            active_identity: ArtifactIdentity {
                length: prior.executable_length,
                sha256: prior.executable_sha256.clone(),
            },
            previous_version: Some(installed.version.clone()),
            previous_identity: Some(release_identity(&installed)),
            aliases: shared_product_aliases(),
        };
        let target = rollback_target(&paths, &installed, &shared)
            .unwrap()
            .unwrap();
        assert_eq!(target.version, "0.4.1");
        assert_eq!(target.previous_release.unwrap().version, "0.5.0");
        shared.active_identity.sha256 = "c".repeat(64);
        assert!(rollback_target(&paths, &installed, &shared).is_err());
        shared.active_identity.sha256 = prior.executable_sha256;
        shared.previous_identity = None;
        assert!(rollback_target(&paths, &installed, &shared).is_err());
    }
}
