use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const RECEIPT_SCHEMA: &str = "dev-auth-install-v2";

pub fn setup_template(name: &str) -> Result<&'static str> {
    match name {
        "deployment" => Ok(include_str!("../deployment-v1.example.toml")),
        "administrator-policy" => Ok(include_str!("../policy-v2.example.toml")),
        "user-only-policy" => Ok(include_str!("../policy-v2-user-only.example.toml")),
        "user-config" => Ok(include_str!("../config-v2.example.toml")),
        _ => bail!(
            "setup template must be deployment, administrator-policy, user-only-policy, or user-config"
        ),
    }
}
const RECEIPT_LIMIT: u64 = 64 * 1024;
const POLICY_LIMIT: u64 = 1024 * 1024;
const BINARY_LIMIT: u64 = 256 * 1024 * 1024;
const WORKLOAD_ALIAS_RECEIPT_SCHEMA: &str = "dev-auth-workload-aliases-v1";
const DESKTOP_ENTRY_RECEIPT_SCHEMA: &str = "dev-auth-desktop-entries-v1";
const PRODUCT_ALIASES: [&str; 5] = [
    "dev-auth",
    "git-credential-dev-auth",
    "git-dev-auth",
    "gh-dev-auth",
    "ssh-keygen-dev-auth",
];
const TRANSPARENT_ALIASES: [&str; 2] = ["git", "gh"];
const SYSTEM_CREDENTIAL_PATH: &str = "/etc/credstore.encrypted/dev-auth.op-service-account-token";
const SYSTEM_CREDENTIAL_DIRECTORY: &str = "/etc/credstore.encrypted/dev-auth-slots";
const PRIVILEGED_LAUNCHER_PATH: &str = "/usr/local/lib/dev-auth/dev-auth-workload-launcher";
const SYSTEM_ASSETS: [(&str, &str, u32); 5] = [
    (
        "/etc/sysusers.d/dev-auth.conf",
        "u dev-auth - \"dev-auth workload identity broker\" /nonexistent /usr/bin/nologin\n",
        0o644,
    ),
    (
        "/etc/systemd/system/dev-auth-broker.socket",
        "[Unit]\nDescription=Dev Auth public broker socket\n\n[Socket]\nListenStream=/run/dev-auth/broker.sock\nFileDescriptorName=public\nDirectoryMode=0755\nSocketMode=0666\nSocketUser=root\nSocketGroup=root\nRemoveOnStop=yes\nService=dev-auth-broker.service\n\n[Install]\nWantedBy=sockets.target\n",
        0o644,
    ),
    (
        "/etc/systemd/system/dev-auth-broker-control.socket",
        "[Unit]\nDescription=Dev Auth supervisor control socket\n\n[Socket]\nListenStream=/run/dev-auth/control.sock\nFileDescriptorName=control\nDirectoryMode=0755\nSocketMode=0600\nSocketUser=root\nSocketGroup=root\nRemoveOnStop=yes\nService=dev-auth-broker.service\n\n[Install]\nWantedBy=sockets.target\n",
        0o644,
    ),
    (
        "/etc/systemd/system/dev-auth-broker.service",
        "[Unit]\nDescription=Dev Auth protected workload identity broker\nRequires=dev-auth-broker.socket dev-auth-broker-control.socket\nAfter=network-online.target\n\n[Service]\nType=simple\nUser=dev-auth\nGroup=dev-auth\nSockets=dev-auth-broker.socket dev-auth-broker-control.socket\nExecStart=/usr/local/bin/dev-auth broker serve\nLoadCredentialEncrypted=op-service-account-token:/etc/credstore.encrypted/dev-auth-slots\nRestart=on-failure\nRestartSec=2s\nUMask=0077\nNoNewPrivileges=yes\nPrivateDevices=yes\nPrivateTmp=yes\nProtectClock=yes\nProtectControlGroups=yes\nProtectHome=yes\nProtectHostname=yes\nProtectKernelLogs=yes\nProtectKernelModules=yes\nProtectKernelTunables=yes\nProtectSystem=strict\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nRestrictNamespaces=yes\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\n\n[Install]\nWantedBy=multi-user.target\n",
        0o644,
    ),
    (
        "/usr/share/polkit-1/actions/com.futuredevguys.dev-auth.policy",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE policyconfig PUBLIC \"-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN\" \"http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd\">\n<policyconfig>\n  <vendor>Future Dev Guys</vendor>\n  <vendor_url>https://github.com/FutureDevGuys/dev-tools</vendor_url>\n  <action id=\"com.futuredevguys.dev-auth.launch-workload\">\n    <description>Launch an administrator-approved dev-auth workload</description>\n    <message>Authentication is required to launch this dev-auth workload</message>\n    <defaults>\n      <allow_any>no</allow_any>\n      <allow_inactive>no</allow_inactive>\n      <allow_active>yes</allow_active>\n    </defaults>\n    <annotate key=\"org.freedesktop.policykit.exec.path\">/usr/local/lib/dev-auth/dev-auth-workload-launcher</annotate>\n  </action>\n</policyconfig>\n",
        0o644,
    ),
];

pub(crate) fn installation_current_state_paths(
    paths: &SetupPaths,
    mode: InstallMode,
) -> Vec<(String, String, PathBuf)> {
    let mut current = vec![
        (
            "installation_receipt".into(),
            "system".into(),
            paths.data_root.join("install-v2.json"),
        ),
        (
            "shared_installation_receipt".into(),
            "system".into(),
            paths.data_root.join("installation-receipt-v1.json"),
        ),
        (
            "active_release_pointer".into(),
            "system".into(),
            paths.data_root.join("active"),
        ),
        (
            "previous_release_pointer".into(),
            "system".into(),
            paths.data_root.join("previous"),
        ),
    ];
    current.extend(PRODUCT_ALIASES.into_iter().map(|alias| {
        (
            "product_launcher".into(),
            alias.into(),
            paths.bin_dir.join(alias),
        )
    }));
    current.extend(TRANSPARENT_ALIASES.into_iter().map(|alias| {
        (
            "transparent_launcher".into(),
            alias.into(),
            paths.bin_dir.join(alias),
        )
    }));
    if mode == InstallMode::Strong {
        current.push((
            "privileged_workload_launcher".into(),
            "system".into(),
            PathBuf::from(PRIVILEGED_LAUNCHER_PATH),
        ));
        current.extend(linux_system_assets().into_iter().map(|(path, _, _)| {
            (
                "system_integration".into(),
                path.display().to_string(),
                path.to_path_buf(),
            )
        }));
    }
    current
}

pub(crate) fn user_integration_receipt_paths(
    home: &Path,
    user: &str,
) -> Vec<(String, String, PathBuf)> {
    vec![
        (
            "workload_launcher_receipt".into(),
            user.into(),
            workload_alias_receipt_path(home),
        ),
        (
            "desktop_entry_receipt".into(),
            user.into(),
            desktop_entry_receipt_path(home),
        ),
    ]
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstallMode {
    Strong,
    UserOnly,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SetupPaths {
    pub data_root: PathBuf,
    pub bin_dir: PathBuf,
}

impl SetupPaths {
    pub fn user_only(home: &Path) -> Self {
        Self {
            data_root: home.join(".local/share/dev-auth"),
            bin_dir: home.join(".local/bin"),
        }
    }

    pub fn strong() -> Self {
        Self {
            data_root: PathBuf::from("/usr/local/lib/dev-auth"),
            bin_dir: PathBuf::from("/usr/local/bin"),
        }
    }

    fn receipt_path(&self) -> PathBuf {
        self.data_root.join("install-v2.json")
    }

    fn versioned_binary(&self, version: &str) -> PathBuf {
        self.data_root
            .join("versions")
            .join(version)
            .join("dev-auth")
    }
}

fn shared_installation_layout(
    paths: &SetupPaths,
    mode: InstallMode,
) -> dev_tools_installation::VersionedLayout {
    dev_tools_installation::VersionedLayout {
        product: "dev-auth".into(),
        data_root: paths.data_root.clone(),
        bin_dir: paths.bin_dir.clone(),
        artifact_name: "dev-auth".into(),
        owner_uid: match mode {
            InstallMode::Strong => 0,
            InstallMode::UserOnly => nix::unistd::Uid::effective().as_raw(),
        },
        directory_mode: 0o755,
    }
}

fn shared_product_aliases() -> Vec<String> {
    let mut aliases = PRODUCT_ALIASES
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    aliases.sort();
    aliases
}

fn verify_shared_installation(
    paths: &SetupPaths,
    receipt: &InstallReceipt,
) -> Result<dev_tools_installation::VersionedReceipt> {
    let shared = dev_tools_installation::verify_versioned_installation(
        &shared_installation_layout(paths, receipt.mode),
    )?;
    if shared.active_version != receipt.version
        || shared.active_identity.length != receipt.executable_length
        || shared.active_identity.sha256 != receipt.executable_sha256
        || shared.aliases != shared_product_aliases()
    {
        bail!("shared installation receipt disagrees with dev-auth product metadata");
    }
    Ok(shared)
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallRequest {
    pub mode: InstallMode,
    pub version: String,
    pub source_executable: PathBuf,
    pub native_git: PathBuf,
    pub native_gh: PathBuf,
    pub activate_transparent_launchers: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SetupPlan {
    pub schema: String,
    pub paths: SetupPaths,
    pub request: InstallRequest,
    pub source_length: u64,
    pub source_sha256: String,
    #[serde(default)]
    pub verified_release: Option<crate::release_manifest::VerifiedDevAuthRelease>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallReceipt {
    pub schema: String,
    pub mode: InstallMode,
    pub version: String,
    pub executable: String,
    pub bin_dir: String,
    pub executable_length: u64,
    pub executable_sha256: String,
    #[serde(default)]
    pub source_commit: Option<String>,
    #[serde(default)]
    pub root_generation: Option<u64>,
    #[serde(default)]
    pub manifest_generation: Option<u64>,
    pub native_git: String,
    pub native_gh: String,
    pub product_aliases: Vec<String>,
    pub transparent_aliases: Vec<String>,
    #[serde(default)]
    pub privileged_launcher: Option<String>,
    #[serde(default)]
    pub system_assets: BTreeMap<String, String>,
    #[serde(default)]
    pub previous_release: Option<RetainedRelease>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetainedRelease {
    pub version: String,
    pub executable_length: u64,
    pub executable_sha256: String,
    #[serde(default)]
    pub source_commit: Option<String>,
    #[serde(default)]
    pub root_generation: Option<u64>,
    #[serde(default)]
    pub manifest_generation: Option<u64>,
    #[serde(default)]
    pub system_assets: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SetupReport {
    pub schema: String,
    pub mode: InstallMode,
    pub version: String,
    pub executable: String,
    pub product_aliases_ready: bool,
    pub transparent_launchers_active: bool,
    pub native_git: String,
    pub native_gh: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UninstallReport {
    pub schema: String,
    pub mode: InstallMode,
    pub version: String,
    pub preserved_policy: bool,
    pub preserved_credential: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StateCleanupReport {
    pub schema: String,
    pub mode: InstallMode,
    pub policy_removed: bool,
    pub user_config_removed: bool,
    pub credential_revoked: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UserIntegrationReport {
    pub schema: String,
    pub workload_launchers_ready: bool,
    pub desktop_entries_ready: bool,
}

pub(crate) fn v3_launcher_readiness(
    setup: &SetupReport,
    integrations: Option<&UserIntegrationReport>,
) -> (bool, bool) {
    let workload_tool_plane_ready = setup.product_aliases_ready
        && integrations
            .is_some_and(|report| report.workload_launchers_ready && report.desktop_entries_ready);
    let launcher_resolution_ready = setup.transparent_launchers_active;
    (workload_tool_plane_ready, launcher_resolution_ready)
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SetupReadinessReport {
    pub schema: String,
    pub mode: InstallMode,
    pub installed: bool,
    pub authenticated_release: bool,
    pub policy_ready: bool,
    pub user_config_ready: bool,
    pub policy_resolution_ready: bool,
    pub credential_ready: bool,
    pub broker_ready: bool,
    pub workload_launchers_ready: bool,
    pub desktop_entries_ready: bool,
    pub workload_tool_plane_ready: bool,
    /// Receipt-owned global same-name Git and GitHub CLI launchers are active.
    pub transparent_launchers_active: bool,
    /// Normal command resolution is fully active for the requested deployment.
    pub launcher_resolution_ready: bool,
    pub next_action: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryStatus {
    Usable,
    Absent,
    Unsafe,
    Unsupported,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiscoveredPath {
    pub path: String,
    pub status: DiscoveryStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SetupDiscoveryReport {
    pub schema: String,
    pub mode: InstallMode,
    pub platform: String,
    pub strong_backend_available: bool,
    pub running_executable: String,
    pub programs: BTreeMap<String, Vec<DiscoveredPath>>,
    pub workload_launchers: BTreeMap<String, Vec<DiscoveredPath>>,
    pub desktop_entries: BTreeMap<String, Vec<DiscoveredPath>>,
    pub blockers: Vec<SetupPrerequisiteBlocker>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SetupPrerequisiteBlocker {
    pub component: String,
    pub status: DiscoveryStatus,
    pub required_for: String,
    pub package_hints: BTreeMap<String, String>,
}

struct ConfiguredWorkloadDiscovery {
    launchers: BTreeMap<String, Vec<DiscoveredPath>>,
    desktop_entries: BTreeMap<String, Vec<DiscoveredPath>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WorkloadAliasReceipt {
    schema: String,
    executable: String,
    aliases: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DesktopEntryReceipt {
    schema: String,
    entries: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V1MigrationPreview {
    pub schema: String,
    pub source_path: String,
    pub source_sha256: String,
    pub workspace_roots: Vec<String>,
    pub github_owners: Vec<String>,
    pub github_repositories: Vec<String>,
    pub execution_profiles: Vec<String>,
    pub ssh_profiles: Vec<String>,
    pub unresolved: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V1MigrationReport {
    pub schema: String,
    pub source_path: String,
    pub source_sha256: String,
    pub backup_path: String,
    pub user_config_path: String,
    pub user_config_sha256: String,
}

pub fn build_plan(paths: &SetupPaths, request: &InstallRequest) -> Result<SetupPlan> {
    validate_install_request(paths, request)?;
    let (source_length, source_sha256) = file_identity(&request.source_executable)?;
    Ok(SetupPlan {
        schema: "dev-auth-setup-plan-v2".into(),
        paths: paths.clone(),
        request: request.clone(),
        source_length,
        source_sha256,
        verified_release: None,
    })
}

pub fn build_verified_release_plan(
    mode: InstallMode,
    activate_transparent_launchers: bool,
    verified: crate::release_manifest::VerifiedDevAuthRelease,
) -> Result<SetupPlan> {
    build_verified_release_plan_with_native_programs(
        mode,
        activate_transparent_launchers,
        verified,
        PathBuf::from("/usr/bin/git"),
        PathBuf::from("/usr/bin/gh"),
    )
}

pub fn build_verified_release_plan_with_native_programs(
    mode: InstallMode,
    activate_transparent_launchers: bool,
    verified: crate::release_manifest::VerifiedDevAuthRelease,
    native_git: PathBuf,
    native_gh: PathBuf,
) -> Result<SetupPlan> {
    let artifact = fs::canonicalize(&verified.artifact_path)
        .context("resolve the verified release artifact")?;
    let paths = match mode {
        InstallMode::Strong => SetupPaths::strong(),
        InstallMode::UserOnly => {
            let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
                .context("effective user account does not exist")?;
            SetupPaths::user_only(&user.dir)
        }
    };
    let request = InstallRequest {
        mode,
        version: verified.version.clone(),
        source_executable: artifact,
        native_git,
        native_gh,
        activate_transparent_launchers,
    };
    let mut plan = build_plan(&paths, &request)?;
    if plan.source_length != verified.artifact_length
        || plan.source_sha256 != verified.artifact_sha256
    {
        bail!("verified release artifact changed before setup planning");
    }
    plan.verified_release = Some(verified);
    validate_plan(&plan)?;
    Ok(plan)
}

pub fn discover_plan(mode: InstallMode, activate_transparent_launchers: bool) -> Result<SetupPlan> {
    let paths = match mode {
        InstallMode::Strong => SetupPaths::strong(),
        InstallMode::UserOnly => {
            let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
                .context("effective user account does not exist")?;
            SetupPaths::user_only(&user.dir)
        }
    };
    let source_executable = fs::canonicalize(std::env::current_exe()?)
        .context("resolve the running dev-auth executable")?;
    let native_git = discover_native_program(
        &[Path::new("/usr/bin/git"), Path::new("/bin/git")],
        "native Git",
        &paths.bin_dir,
    )?;
    let native_gh = discover_native_program(
        &[Path::new("/usr/bin/gh"), Path::new("/bin/gh")],
        "native GitHub CLI",
        &paths.bin_dir,
    )?;
    build_plan(
        &paths,
        &InstallRequest {
            mode,
            version: env!("CARGO_PKG_VERSION").into(),
            source_executable,
            native_git,
            native_gh,
            activate_transparent_launchers,
        },
    )
}

pub fn discover_setup(mode: InstallMode) -> Result<SetupDiscoveryReport> {
    discover_setup_with_configuration(mode, None, &[])
}

pub fn discover_setup_with_configuration(
    mode: InstallMode,
    administrator_policy: Option<&Path>,
    user_configurations: &[(String, PathBuf)],
) -> Result<SetupDiscoveryReport> {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
        .context("effective user account does not exist")?;
    let running_executable = fs::canonicalize(std::env::current_exe()?)
        .context("resolve the running dev-auth executable")?;
    let policy = administrator_policy
        .map(|path| {
            crate::policy_v2::parse_system_policy_v2(&read_discovery_document(
                path,
                "administrator policy",
            )?)
        })
        .transpose()?;
    if policy.is_none() && !user_configurations.is_empty() {
        bail!("configured workload discovery requires --administrator-policy");
    }
    if let Some(policy) = &policy {
        let expected_mode = match mode {
            InstallMode::Strong => crate::policy_v2::SystemMode::Strong,
            InstallMode::UserOnly => crate::policy_v2::SystemMode::UserOnly,
        };
        if policy.mode != expected_mode {
            bail!("administrator policy mode disagrees with discovery mode");
        }
    }
    let programs = discover_programs(mode, user.uid.as_raw(), policy.as_ref());
    let configured = discover_configured_workloads(mode, policy.as_ref(), user_configurations)?;
    let strong_blockers = setup_prerequisite_blockers(InstallMode::Strong, &programs);
    let strong_backend_available = strong_backend_available_from_blockers(&strong_blockers);
    let mut blockers = if mode == InstallMode::Strong {
        strong_blockers
    } else {
        setup_prerequisite_blockers(mode, &programs)
    };
    blockers.extend(
        configured
            .launchers
            .iter()
            .filter_map(|(subject, candidates)| {
                if candidates
                    .iter()
                    .any(|candidate| candidate.status == DiscoveryStatus::Usable)
                {
                    return None;
                }
                let status = if candidates
                    .iter()
                    .any(|candidate| candidate.status == DiscoveryStatus::Unsafe)
                {
                    DiscoveryStatus::Unsafe
                } else {
                    DiscoveryStatus::Absent
                };
                Some(SetupPrerequisiteBlocker {
                    component: format!("workload_launcher:{subject}"),
                    status,
                    required_for: "workload_admission".into(),
                    package_hints: BTreeMap::new(),
                })
            }),
    );
    blockers.sort_by(|left, right| left.component.cmp(&right.component));
    Ok(SetupDiscoveryReport {
        schema: "dev-auth-setup-discovery-v1".into(),
        mode,
        platform: std::env::consts::OS.into(),
        strong_backend_available,
        running_executable: running_executable.display().to_string(),
        programs,
        workload_launchers: configured.launchers,
        desktop_entries: configured.desktop_entries,
        blockers,
    })
}

fn discover_programs(
    mode: InstallMode,
    owner_uid: u32,
    policy: Option<&crate::policy_v2::SystemPolicyV2>,
) -> BTreeMap<String, Vec<DiscoveredPath>> {
    let mut candidates = BTreeMap::<String, Vec<PathBuf>>::from([
        ("git".into(), vec!["/usr/bin/git".into(), "/bin/git".into()]),
        ("gh".into(), vec!["/usr/bin/gh".into(), "/bin/gh".into()]),
        (
            "op".into(),
            vec!["/usr/bin/op".into(), "/usr/local/bin/op".into()],
        ),
        ("ssh".into(), vec!["/usr/bin/ssh".into(), "/bin/ssh".into()]),
        (
            "ssh_keygen".into(),
            vec!["/usr/bin/ssh-keygen".into(), "/bin/ssh-keygen".into()],
        ),
        ("pkexec".into(), vec!["/usr/bin/pkexec".into()]),
        ("systemd_run".into(), vec!["/usr/bin/systemd-run".into()]),
        (
            "systemd_creds".into(),
            vec!["/usr/bin/systemd-creds".into()],
        ),
        (
            "systemd_sysusers".into(),
            vec!["/usr/bin/systemd-sysusers".into()],
        ),
        ("systemctl".into(), vec!["/usr/bin/systemctl".into()]),
        ("bubblewrap".into(), vec!["/usr/bin/bwrap".into()]),
        ("firejail".into(), vec!["/usr/bin/firejail".into()]),
        ("podman".into(), vec!["/usr/bin/podman".into()]),
    ]);
    if let Some(policy) = policy {
        candidates.insert("git".into(), vec![PathBuf::from(&policy.programs.git)]);
        candidates.insert("gh".into(), vec![PathBuf::from(&policy.programs.gh)]);
        candidates.insert("op".into(), vec![PathBuf::from(&policy.programs.op)]);
        candidates.insert("ssh".into(), vec![PathBuf::from(&policy.programs.ssh)]);
        candidates.insert(
            "ssh_keygen".into(),
            vec![PathBuf::from(&policy.programs.ssh_keygen)],
        );
        for (name, adapter) in &policy.sandbox_adapters {
            candidates.insert(
                format!("sandbox:{name}"),
                vec![PathBuf::from(&adapter.executable)],
            );
        }
    }
    candidates
        .into_iter()
        .map(|(name, candidates)| {
            let discovered = discover_owned_paths(&candidates, mode, owner_uid, true);
            (name, discovered)
        })
        .collect()
}

fn discover_configured_workloads(
    mode: InstallMode,
    policy: Option<&crate::policy_v2::SystemPolicyV2>,
    user_configurations: &[(String, PathBuf)],
) -> Result<ConfiguredWorkloadDiscovery> {
    if policy.is_none() && user_configurations.is_empty() {
        return Ok(ConfiguredWorkloadDiscovery {
            launchers: BTreeMap::new(),
            desktop_entries: BTreeMap::new(),
        });
    }
    let policy = policy.context("configured workload discovery requires --administrator-policy")?;

    let mut launchers = BTreeMap::new();
    let mut desktop_entries = BTreeMap::new();
    let mut users = BTreeSet::new();
    for (user_name, source) in user_configurations {
        if !users.insert(user_name.clone()) {
            bail!("configured workload discovery contains a duplicate user");
        }
        let account = nix::unistd::User::from_name(user_name)?
            .with_context(|| format!("configured discovery user {user_name} does not exist"))?;
        let config = crate::policy_v2::parse_user_config_v2(&read_discovery_document(
            source,
            "user configuration",
        )?)?;
        for workload in config.workloads {
            let launcher = policy
                .trusted_launchers
                .get(&workload.launcher)
                .with_context(|| {
                    format!(
                        "configured workload {} references an unknown launcher",
                        workload.name
                    )
                })?;
            let subject = format!("{user_name}:{}", workload.name);
            launchers.insert(
                subject.clone(),
                discover_owned_paths(&[PathBuf::from(launcher)], mode, account.uid.as_raw(), true),
            );
            if workload.desktop.is_some() {
                let path = account
                    .dir
                    .join(".local/share/applications")
                    .join(format!("dev-auth-{}.desktop", workload.name));
                desktop_entries.insert(
                    subject,
                    discover_owned_paths(&[path], mode, account.uid.as_raw(), false),
                );
            }
        }
    }
    Ok(ConfiguredWorkloadDiscovery {
        launchers,
        desktop_entries,
    })
}

fn read_discovery_document(path: &Path, description: &str) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        bail!("{description} path must be absolute");
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open {description} {}", path.display()))?;
    let before = file
        .metadata()
        .with_context(|| format!("inspect {description} {}", path.display()))?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.len() > POLICY_LIMIT
    {
        bail!("{description} has unsafe discovery authority");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(POLICY_LIMIT + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {description}"))?;
    let after = file
        .metadata()
        .with_context(|| format!("reinspect {description}"))?;
    if bytes.len() as u64 > POLICY_LIMIT
        || bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        bail!("{description} changed while being read");
    }
    Ok(bytes)
}

fn strong_backend_available_from_blockers(blockers: &[SetupPrerequisiteBlocker]) -> bool {
    cfg!(target_os = "linux")
        && !blockers.iter().any(|blocker| {
            matches!(
                blocker.component.as_str(),
                "linux_strong_backend"
                    | "pkexec"
                    | "systemd_run"
                    | "systemd_creds"
                    | "systemd_sysusers"
                    | "systemctl"
                    | "cgroup_v2"
                    | "pidfd"
                    | "systemd_runtime"
                    | "systemd_full_identity_users"
            )
        })
}

fn setup_prerequisite_blockers(
    mode: InstallMode,
    programs: &BTreeMap<String, Vec<DiscoveredPath>>,
) -> Vec<SetupPrerequisiteBlocker> {
    let mut required = vec!["git", "gh", "op", "ssh", "ssh_keygen"];
    if mode == InstallMode::Strong {
        required.extend([
            "pkexec",
            "systemd_run",
            "systemd_creds",
            "systemd_sysusers",
            "systemctl",
        ]);
    }
    let mut blockers = required
        .into_iter()
        .filter_map(|component| {
            let candidates = programs.get(component)?;
            if candidates
                .iter()
                .any(|candidate| candidate.status == DiscoveryStatus::Usable)
            {
                return None;
            }
            let status = if candidates
                .iter()
                .any(|candidate| candidate.status == DiscoveryStatus::Unsafe)
            {
                DiscoveryStatus::Unsafe
            } else {
                DiscoveryStatus::Absent
            };
            Some(prerequisite_blocker(
                component,
                status,
                if mode == InstallMode::Strong {
                    "strong_setup"
                } else {
                    "user_only_setup"
                },
            ))
        })
        .collect::<Vec<_>>();
    if mode == InstallMode::Strong {
        if !cfg!(target_os = "linux") {
            blockers.push(prerequisite_blocker(
                "linux_strong_backend",
                DiscoveryStatus::Unsupported,
                "strong_setup",
            ));
        } else {
            if !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
                blockers.push(prerequisite_blocker(
                    "cgroup_v2",
                    DiscoveryStatus::Absent,
                    "strong_admission",
                ));
            }
            if rustix::process::pidfd_open(
                rustix::process::getpid(),
                rustix::process::PidfdFlags::empty(),
            )
            .is_err()
            {
                blockers.push(prerequisite_blocker(
                    "pidfd",
                    DiscoveryStatus::Unsupported,
                    "strong_admission",
                ));
            }
            if !Path::new("/run/systemd/system").is_dir() {
                blockers.push(prerequisite_blocker(
                    "systemd_runtime",
                    DiscoveryStatus::Absent,
                    "strong_admission",
                ));
            }
            if !systemd_supports_full_identity_users(Path::new("/usr/bin/systemd-run")) {
                blockers.push(prerequisite_blocker(
                    "systemd_full_identity_users",
                    DiscoveryStatus::Unsupported,
                    "strong_admission",
                ));
            }
        }
    }
    blockers.sort_by(|left, right| left.component.cmp(&right.component));
    blockers
}

pub(crate) fn require_setup_prerequisites(
    mode: InstallMode,
    owner_uid: u32,
    policy: &crate::policy_v2::SystemPolicyV2,
) -> Result<()> {
    let programs = discover_programs(mode, owner_uid, Some(policy));
    let blockers = setup_prerequisite_blockers(mode, &programs);
    if !blockers.is_empty() {
        let components = blockers
            .iter()
            .map(|blocker| blocker.component.as_str())
            .collect::<Vec<_>>()
            .join(",");
        bail!("dev-auth setup prerequisites are not ready: {components}");
    }
    Ok(())
}

fn prerequisite_blocker(
    component: &str,
    status: DiscoveryStatus,
    required_for: &str,
) -> SetupPrerequisiteBlocker {
    let packages = match component {
        "git" => [("arch", "git"), ("debian", "git"), ("fedora", "git")],
        "gh" => [("arch", "github-cli"), ("debian", "gh"), ("fedora", "gh")],
        "op" => [
            ("arch", "1password-cli"),
            ("debian", "1password-cli"),
            ("fedora", "1password-cli"),
        ],
        "ssh" | "ssh_keygen" => [
            ("arch", "openssh"),
            ("debian", "openssh-client"),
            ("fedora", "openssh-clients"),
        ],
        "pkexec" => [
            ("arch", "polkit"),
            ("debian", "polkitd-pkla"),
            ("fedora", "polkit"),
        ],
        "systemd_run"
        | "systemd_creds"
        | "systemd_sysusers"
        | "systemctl"
        | "systemd_runtime"
        | "systemd_full_identity_users" => [
            ("arch", "systemd"),
            ("debian", "systemd"),
            ("fedora", "systemd"),
        ],
        _ => [("arch", ""), ("debian", ""), ("fedora", "")],
    };
    SetupPrerequisiteBlocker {
        component: component.into(),
        status,
        required_for: required_for.into(),
        package_hints: packages
            .into_iter()
            .filter(|(_, package)| !package.is_empty())
            .map(|(distribution, package)| (distribution.into(), package.into()))
            .collect(),
    }
}

fn systemd_supports_full_identity_users(executable: &Path) -> bool {
    let arguments = [std::ffi::OsString::from("--version")];
    let environment = BTreeMap::new();
    let Ok(output) = dev_tools_command::run_bounded_command(&dev_tools_command::BoundedCommand {
        executable,
        arguments: &arguments,
        environment: &environment,
        cwd: None,
        timeout: Duration::from_secs(2),
        output_limit: 64 * 1024,
    }) else {
        return false;
    };
    output.status.success() && parse_systemd_major_version(&output.stdout).is_some_and(|v| v >= 257)
}

fn parse_systemd_major_version(output: &[u8]) -> Option<u32> {
    let first = output.split(|byte| *byte == b'\n').next()?;
    let first = std::str::from_utf8(first).ok()?;
    let mut fields = first.split_ascii_whitespace();
    if fields.next()? != "systemd" {
        return None;
    }
    fields.next()?.parse().ok()
}

pub fn setup_readiness(mode: InstallMode) -> Result<SetupReadinessReport> {
    let paths = match mode {
        InstallMode::Strong => SetupPaths::strong(),
        InstallMode::UserOnly => {
            let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
                .context("effective user account does not exist")?;
            SetupPaths::user_only(&user.dir)
        }
    };
    setup_readiness_at(&paths, mode)
}

pub fn setup_readiness_at(paths: &SetupPaths, mode: InstallMode) -> Result<SetupReadinessReport> {
    let mut report = SetupReadinessReport {
        schema: "dev-auth-setup-readiness-v2".into(),
        mode,
        installed: false,
        authenticated_release: false,
        policy_ready: false,
        user_config_ready: false,
        policy_resolution_ready: false,
        credential_ready: false,
        broker_ready: false,
        workload_launchers_ready: false,
        desktop_entries_ready: false,
        workload_tool_plane_ready: false,
        transparent_launchers_active: false,
        launcher_resolution_ready: false,
        next_action: "verify_release_and_apply_plan".into(),
    };
    match fs::symlink_metadata(paths.receipt_path()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(report),
        Err(error) => return Err(error).context("inspect setup readiness receipt"),
        Ok(_) => {}
    }
    let receipt = read_receipt(&paths.receipt_path())?;
    if receipt.mode != mode {
        bail!("installed dev-auth mode does not match the requested readiness mode");
    }
    let privileged = nix::unistd::Uid::effective().is_root();
    let setup = if readiness_requires_private_installation_verification(mode, privileged) {
        verify_at(paths)?
    } else {
        verify_receipted_installation_at(paths, &receipt, false)?
    };
    report.installed = true;
    report.transparent_launchers_active = setup.transparent_launchers_active;
    report.authenticated_release = receipt.source_commit.is_some()
        && receipt.root_generation.is_some()
        && receipt.manifest_generation.is_some();
    if !report.authenticated_release {
        report.next_action = "install_authenticated_release".into();
        return Ok(report);
    }

    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
        .context("effective user account does not exist")?;
    let policy_path = match mode {
        InstallMode::Strong => PathBuf::from(crate::policy_store::SYSTEM_POLICY_PATH),
        InstallMode::UserOnly => crate::policy_store::user_policy_path(&user),
    };
    let policy = match fs::symlink_metadata(&policy_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            report.next_action = match mode {
                InstallMode::Strong => "install_system_policy",
                InstallMode::UserOnly => "install_user_policy",
            }
            .into();
            return Ok(report);
        }
        Err(error) => return Err(error).context("inspect setup policy readiness"),
        Ok(_) => match mode {
            InstallMode::Strong => crate::policy_store::load_system_policy()?,
            InstallMode::UserOnly => {
                crate::policy_store::load_user_policy_at(&policy_path, user.uid.as_raw())?
            }
        },
    };
    report.policy_ready = true;

    let user_config_path = crate::policy_store::user_config_path(&user);
    let user_config = match fs::symlink_metadata(&user_config_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            report.next_action = "install_user_config".into();
            return Ok(report);
        }
        Err(error) => return Err(error).context("inspect user configuration readiness"),
        Ok(_) => crate::policy_store::load_user_config_at(&user_config_path, user.uid.as_raw())?,
    };
    report.user_config_ready = true;
    if !policy
        .allowed_users
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&user.name))
    {
        bail!("effective user is outside the administrator policy");
    }
    let resolved = crate::policy_v2::resolve_policy_for_user(&policy, &user.name, &user_config)?;
    report.policy_resolution_ready = true;

    let required_slots = resolved
        .authority_profiles
        .values()
        .map(|profile| profile.credential_slot.as_str())
        .collect::<BTreeSet<_>>();
    match mode {
        InstallMode::Strong => {
            let broker_ready = matches!(
                crate::broker_client::probe_system_broker(),
                crate::broker_protocol::BrokerSessionProbe::NoSession
                    | crate::broker_protocol::BrokerSessionProbe::Verified { .. }
            );
            let privileged_credential_ready = privileged
                && required_slots
                    .iter()
                    .all(|slot| system_service_credential_slot_ready(slot));
            let (credential_ready, broker_ready, next_action) =
                strong_runtime_readiness(broker_ready, privileged, privileged_credential_ready);
            report.credential_ready = credential_ready;
            report.broker_ready = broker_ready;
            if let Some(next_action) = next_action {
                report.next_action = next_action.into();
                return Ok(report);
            }
        }
        InstallMode::UserOnly => {
            report.credential_ready = required_slots
                .iter()
                .all(|slot| crate::runtime::user_broker_service_token_for_slot(slot).is_ok());
            if !report.credential_ready {
                report.next_action = "enroll_user_credential".into();
                return Ok(report);
            }
            report.broker_ready = true;
        }
    }

    let integrations = match verify_user_integrations_at(
        &user.dir,
        Path::new(&receipt.executable),
        &resolved.workloads,
        user.uid.as_raw(),
    ) {
        Ok(integrations) => integrations,
        Err(_) => {
            report.next_action = "update_user_config".into();
            return Ok(report);
        }
    };
    report.workload_launchers_ready = integrations.workload_launchers_ready;
    report.desktop_entries_ready = integrations.desktop_entries_ready;
    let launcher_readiness = v3_launcher_readiness(&setup, Some(&integrations));
    report.workload_tool_plane_ready = launcher_readiness.0;
    report.launcher_resolution_ready = launcher_readiness.1;
    if !report.launcher_resolution_ready {
        report.next_action = "apply_transparent_activation_plan".into();
        return Ok(report);
    }
    report.next_action = "ready".into();
    Ok(report)
}

fn strong_runtime_readiness(
    broker_ready: bool,
    privileged: bool,
    privileged_credential_ready: bool,
) -> (bool, bool, Option<&'static str>) {
    if broker_ready {
        return (true, true, None);
    }
    if !privileged {
        return (false, false, Some("run_privileged_setup_plan"));
    }
    if !privileged_credential_ready {
        return (false, false, Some("enroll_system_credential"));
    }
    (true, false, Some("start_system_broker"))
}

fn readiness_requires_private_installation_verification(
    mode: InstallMode,
    privileged: bool,
) -> bool {
    mode == InstallMode::UserOnly || privileged
}

pub fn transparent_launchers_resolve_first_at(
    paths: &SetupPaths,
    executable: &Path,
    path_environment: &OsStr,
) -> Result<bool> {
    let expected = fs::canonicalize(executable).context("resolve installed dev-auth executable")?;
    for command in TRANSPARENT_ALIASES {
        let mut resolved = None;
        for directory in std::env::split_paths(path_environment) {
            if !directory.is_absolute() {
                bail!("PATH contains a relative launcher directory");
            }
            let candidate = directory.join(command);
            match fs::symlink_metadata(&candidate) {
                Ok(_) => {
                    resolved = Some(
                        fs::canonicalize(&candidate)
                            .with_context(|| format!("resolve {command} from PATH"))?,
                    );
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("inspect {command} from PATH"))
                }
            }
        }
        if resolved.as_ref() != Some(&expected) {
            return Ok(false);
        }
        if fs::canonicalize(paths.bin_dir.join(command)).ok().as_ref() != Some(&expected) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn discover_owned_paths(
    candidates: &[PathBuf],
    mode: InstallMode,
    owner_uid: u32,
    executable: bool,
) -> Vec<DiscoveredPath> {
    candidates
        .iter()
        .map(|path| {
            let status = match fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    DiscoveryStatus::Absent
                }
                Err(_) => DiscoveryStatus::Unsafe,
                Ok(metadata) => {
                    let base_safe = metadata.file_type().is_file()
                        && !metadata.file_type().is_symlink()
                        && metadata.mode() & 0o022 == 0
                        && (!executable || metadata.mode() & 0o111 != 0);
                    let authority_safe = base_safe
                        && discovery_path_authority_is_safe(path, mode, owner_uid).unwrap_or(false);
                    if authority_safe {
                        DiscoveryStatus::Usable
                    } else {
                        DiscoveryStatus::Unsafe
                    }
                }
            };
            DiscoveredPath {
                path: path.display().to_string(),
                status,
            }
        })
        .collect()
}

fn discovery_path_authority_is_safe(
    path: &Path,
    mode: InstallMode,
    owner_uid: u32,
) -> Result<bool> {
    if !path.is_absolute() {
        return Ok(false);
    }
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)?;
        let owner_allowed = match mode {
            InstallMode::Strong => metadata.uid() == 0,
            InstallMode::UserOnly => metadata.uid() == 0 || metadata.uid() == owner_uid,
        };
        if metadata.file_type().is_symlink() || !owner_allowed || metadata.mode() & 0o022 != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn render_plan(plan: &SetupPlan) -> Result<(Vec<u8>, String)> {
    validate_plan(plan)?;
    let bytes = serde_json::to_vec_pretty(plan).context("serialize setup plan")?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    Ok((bytes, digest))
}

pub fn apply_plan(plan: &SetupPlan, approved_sha256: &str) -> Result<SetupReport> {
    let (_, digest) = render_plan(plan)?;
    if digest != approved_sha256 {
        bail!("setup plan does not match the approved digest");
    }
    let (source_length, source_sha256) = file_identity(&plan.request.source_executable)?;
    if source_length != plan.source_length || source_sha256 != plan.source_sha256 {
        bail!("setup executable changed after plan approval");
    }
    install_at_with_release(&plan.paths, &plan.request, plan.verified_release.as_ref())
}

pub fn write_plan_at(path: &Path, plan: &SetupPlan) -> Result<String> {
    let (content, digest) = render_plan(plan)?;
    write_private_public_document(path, &content, "setup plan")?;
    Ok(digest)
}

fn write_private_public_document(path: &Path, content: &[u8], description: &str) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{description} path has no parent"))?;
    if !parent.is_dir() {
        bail!("{description} parent is not a directory");
    }
    let temporary = path.with_extension(format!("new-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("create temporary {description}"))?;
    file.write_all(content)
        .with_context(|| format!("write {description}"))?;
    file.sync_all()
        .with_context(|| format!("sync {description}"))?;
    match fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(error).with_context(|| format!("publish {description}"))
        }
    }
}

pub fn read_plan_at(path: &Path) -> Result<SetupPlan> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect setup plan {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > RECEIPT_LIMIT
    {
        bail!("dev-auth setup plan is unsafe");
    }
    let mut input = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .context("open setup plan")?
        .take(RECEIPT_LIMIT + 1)
        .read_to_end(&mut input)
        .context("read setup plan")?;
    let plan: SetupPlan = serde_json::from_slice(&input).context("parse setup plan")?;
    validate_plan(&plan)?;
    Ok(plan)
}

pub fn preview_v1_migration() -> Result<V1MigrationPreview> {
    let owner_uid = nix::unistd::Uid::effective().as_raw();
    if owner_uid == 0 {
        bail!("v1 migration preview must run as the native user");
    }
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
        .context("effective user account does not exist")?;
    let source = user.dir.join(".config/dev-auth/config.toml");
    preview_v1_migration_at(&source, owner_uid)
}

pub fn preview_v1_migration_at(source: &Path, owner_uid: u32) -> Result<V1MigrationPreview> {
    let (_, config, source_sha256) = read_v1_configuration_at(source, owner_uid)?;

    let mut owners = config
        .github
        .installations
        .iter()
        .map(|installation| installation.owner.to_ascii_lowercase())
        .collect::<Vec<_>>();
    owners.sort();
    owners.dedup();
    let mut repositories = config
        .github
        .installations
        .iter()
        .flat_map(|installation| installation.repositories.iter())
        .map(|repository| repository.to_ascii_lowercase())
        .collect::<Vec<_>>();
    repositories.sort();
    repositories.dedup();
    let mut execution_profiles = config.profiles.keys().cloned().collect::<Vec<_>>();
    execution_profiles.sort();
    let mut ssh_profiles = config.ssh_profiles.keys().cloned().collect::<Vec<_>>();
    ssh_profiles.sort();

    Ok(V1MigrationPreview {
        schema: "dev-auth-v1-migration-preview-v1".into(),
        source_path: source.display().to_string(),
        source_sha256,
        workspace_roots: config
            .git
            .map(|git| git.workspace_roots)
            .unwrap_or_default(),
        github_owners: owners,
        github_repositories: repositories,
        execution_profiles,
        ssh_profiles,
        unresolved: vec![
            "administrator policy approval and installation".into(),
            "trusted workload launcher identities".into(),
            "workload-to-authority-profile mappings".into(),
            "sandbox adapter selection and acceptance".into(),
        ],
    })
}

pub fn write_v1_migration_preview_at(path: &Path, preview: &V1MigrationPreview) -> Result<String> {
    let content = serde_json::to_vec_pretty(preview).context("serialize v1 migration preview")?;
    if content.len() as u64 > RECEIPT_LIMIT {
        bail!("v1 migration preview exceeds the size limit");
    }
    write_private_public_document(path, &content, "v1 migration preview")?;
    Ok(format!("{:x}", Sha256::digest(&content)))
}

pub fn migrate_v1_configuration(
    user_config_source: &Path,
    approved_user_config_sha256: &str,
    approved_v1_sha256: &str,
) -> Result<V1MigrationReport> {
    let owner_uid = nix::unistd::Uid::effective().as_raw();
    if owner_uid == 0 {
        bail!("v1 migration must run as the native non-root user");
    }
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
        .context("effective user account does not exist")?;
    let source = user.dir.join(".config/dev-auth/config.toml");
    let (legacy_bytes, legacy, source_sha256) = read_v1_configuration_at(&source, owner_uid)?;
    validate_current_digest(&legacy_bytes, approved_v1_sha256)?;

    let user_config_bytes =
        read_approved_public_document(user_config_source, approved_user_config_sha256)?;
    let user_config = crate::policy_v2::parse_user_config_v2(&user_config_bytes)?;
    let (_, receipt) = current_installation()?;
    let system_policy = match receipt.mode {
        InstallMode::Strong => crate::policy_store::load_system_policy()?,
        InstallMode::UserOnly => crate::policy_store::load_user_policy_at(
            &crate::policy_store::user_policy_path(&user),
            owner_uid,
        )?,
    };
    let resolved =
        crate::policy_v2::resolve_policy_for_user(&system_policy, &user.name, &user_config)?;
    validate_v1_migration_resolution(&legacy, &resolved, &user.dir)?;

    let backup = user
        .dir
        .join(".config/dev-auth/migrations/v1")
        .join(&source_sha256)
        .join("config.toml");
    let backup_parent = backup.parent().context("v1 backup path has no parent")?;
    ensure_directory_chain_for_owner(backup_parent, owner_uid, 0o700)?;
    install_policy_document(&backup, &legacy_bytes, owner_uid, 0o600)?;
    let destination = install_user_config(user_config_source, approved_user_config_sha256)?;

    Ok(V1MigrationReport {
        schema: "dev-auth-v1-migration-v1".into(),
        source_path: source.display().to_string(),
        source_sha256,
        backup_path: backup.display().to_string(),
        user_config_path: destination.display().to_string(),
        user_config_sha256: approved_user_config_sha256.to_ascii_lowercase(),
    })
}

fn read_v1_configuration_at(
    source: &Path,
    owner_uid: u32,
) -> Result<(Vec<u8>, crate::Config, String)> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("inspect v1 configuration {}", source.display()))?;
    if !source.is_absolute()
        || !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o077 != 0
        || metadata.len() > POLICY_LIMIT
    {
        bail!("v1 configuration has unsafe filesystem authority");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(source)
        .context("open v1 configuration")?
        .take(POLICY_LIMIT + 1)
        .read_to_end(&mut bytes)
        .context("read v1 configuration")?;
    if bytes.len() as u64 > POLICY_LIMIT {
        bail!("v1 configuration exceeds the size limit");
    }
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let config = crate::parse_config(&bytes)?;
    Ok((bytes, config, digest))
}

fn validate_v1_migration_resolution(
    legacy: &crate::Config,
    resolved: &crate::policy_v2::ResolvedPolicy,
    native_home: &Path,
) -> Result<()> {
    if legacy.programs.op != resolved.programs.op
        || legacy.programs.git != resolved.programs.git
        || legacy.programs.gh != resolved.programs.gh
        || legacy.programs.ssh_keygen != resolved.programs.ssh_keygen
    {
        bail!("v2 policy changes a legacy credential-bearing program");
    }

    let legacy_references = legacy.declared_secret_references();
    for profile in resolved.authority_profiles.values() {
        if !profile
            .secret_references
            .iter()
            .all(|reference| legacy_references.contains(reference))
        {
            bail!("v2 policy introduces a secret reference outside the v1 configuration");
        }
    }
    for workload in resolved.workloads.values() {
        if !workload
            .secret_references
            .iter()
            .all(|reference| legacy_references.contains(reference))
        {
            bail!("v2 workload introduces a secret reference outside the v1 configuration");
        }
    }

    let required_permissions = legacy
        .github
        .permissions
        .iter()
        .map(|(name, value)| {
            let permission = match value.as_str() {
                "read" => crate::policy_v2::Permission::Read,
                "write" => crate::policy_v2::Permission::Write,
                _ => bail!("v1 GitHub permission has an unsupported value"),
            };
            Ok((name.as_str(), permission))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let github_profiles = resolved
        .authority_profiles
        .values()
        .filter_map(|profile| profile.github.as_ref())
        .filter(|github| {
            github.app_id == legacy.github.app_id
                && github.private_key_ref == legacy.github.private_key_ref
                && required_permissions
                    .iter()
                    .all(|(name, permission)| github.permissions.get(*name) == Some(permission))
        })
        .collect::<Vec<_>>();
    if github_profiles.is_empty() {
        bail!("v2 policy does not resolve the v1 GitHub App authority");
    }
    for installation in &legacy.github.installations {
        let owner = installation.owner.to_ascii_lowercase();
        let repositories = installation
            .repositories
            .iter()
            .map(|repository| repository.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if !github_profiles.iter().any(|github| {
            github.owners.contains(&owner)
                && github
                    .installation_ids
                    .contains(&installation.installation_id)
                && (installation.all_repositories || repositories.is_subset(&github.repositories))
        }) {
            bail!("v2 policy does not resolve a declared v1 GitHub installation");
        }
    }

    if let Some(git) = &legacy.git {
        let legacy_roots = git
            .workspace_roots
            .iter()
            .map(|root| expand_v1_workspace_root(root, native_home))
            .collect::<Result<Vec<_>>>()?;
        let mut matched_root = false;
        for workload in resolved.workloads.values() {
            let profile = resolved
                .authority_profiles
                .get(&workload.authority_profile)
                .context("resolved workload references a missing authority profile")?;
            for root in &workload.workspace_roots {
                let root = Path::new(&root.path);
                if !legacy_roots
                    .iter()
                    .any(|legacy_root| root == legacy_root || root.starts_with(legacy_root))
                {
                    bail!("v2 workload widens the v1 workspace-root boundary");
                }
                matched_root = true;
                if profile.git_identity.as_ref()
                    != Some(&crate::policy_v2::GitIdentityConfig {
                        name: git.author_name.clone(),
                        email: git.author_email.clone(),
                    })
                {
                    bail!("v2 workload changes the v1 Git author identity");
                }
            }
        }
        if !matched_root {
            bail!("v2 policy does not map any v1 workspace root");
        }

        let ssh_profile = legacy
            .ssh_profiles
            .get(&git.ssh_profile)
            .context("v1 Git SSH profile is missing")?;
        for key in &ssh_profile.keys {
            let matched = resolved
                .authority_profiles
                .values()
                .any(|profile| match key.purpose {
                    crate::SshKeyPurpose::Signing => {
                        profile.signing_key.as_ref().is_some_and(|candidate| {
                            candidate.private_key_ref == key.private_key_ref
                                && candidate.fingerprint == key.fingerprint
                        })
                    }
                    crate::SshKeyPurpose::Authentication => {
                        profile.ssh_keys.iter().any(|candidate| {
                            candidate.private_key_ref == key.private_key_ref
                                && candidate.fingerprint == key.fingerprint
                        })
                    }
                });
            if !matched {
                bail!("v2 policy does not resolve a v1 SSH operation key");
            }
        }
    }
    Ok(())
}

fn expand_v1_workspace_root(root: &str, native_home: &Path) -> Result<PathBuf> {
    let expanded = if root == "~" {
        native_home.to_path_buf()
    } else if let Some(relative) = root.strip_prefix("~/") {
        native_home.join(relative)
    } else {
        PathBuf::from(root)
    };
    if !expanded.is_absolute() {
        bail!("v1 workspace root cannot be resolved to an absolute native path");
    }
    Ok(expanded)
}

pub fn install_at(paths: &SetupPaths, request: &InstallRequest) -> Result<SetupReport> {
    install_at_with_release(paths, request, None)
}

fn install_at_with_release(
    paths: &SetupPaths,
    request: &InstallRequest,
    verified_release: Option<&crate::release_manifest::VerifiedDevAuthRelease>,
) -> Result<SetupReport> {
    validate_install_request(paths, request)?;
    let prior_receipt = match fs::symlink_metadata(paths.receipt_path()) {
        Ok(_) => Some(read_receipt(&paths.receipt_path())?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("inspect prior installation receipt"),
    };
    if prior_receipt
        .as_ref()
        .is_some_and(|prior| prior.mode != request.mode)
    {
        bail!("installation mode cannot change in place");
    }
    if prior_receipt.as_ref().is_some_and(|prior| {
        prior.version != request.version && !prior.transparent_aliases.is_empty()
    }) {
        bail!("same-name launchers must be deactivated before a version update");
    }
    if prior_receipt
        .as_ref()
        .is_some_and(|prior| prior.version != request.version)
    {
        match request.mode {
            InstallMode::Strong => require_broker_sockets_absent()?,
            InstallMode::UserOnly => require_user_sessions_absent()?,
        }
    }
    let (_, requested_source_sha256) = file_identity(&request.source_executable)?;
    if let Some(prior) = prior_receipt.as_ref() {
        validate_release_transition(prior, request, &requested_source_sha256, verified_release)?;
    }
    ensure_directory_chain(&paths.data_root, request.mode)?;
    ensure_directory_chain(&paths.bin_dir, request.mode)?;
    let shared_layout = shared_installation_layout(paths, request.mode);
    let shared_aliases = shared_product_aliases();
    if !dev_tools_installation::versioned_installation_receipt_exists(&shared_layout)? {
        if let Some(prior) = prior_receipt.as_ref() {
            let prior_executable = PathBuf::from(&prior.executable);
            if prior.mode == InstallMode::Strong {
                detach_legacy_privileged_launcher(&prior_executable, prior)?;
            }
            dev_tools_installation::adopt_versioned_installation(
                &dev_tools_installation::VersionedAdoption {
                    layout: shared_layout.clone(),
                    version: prior.version.clone(),
                    identity: dev_tools_installation::ArtifactIdentity {
                        length: prior.executable_length,
                        sha256: prior.executable_sha256.clone(),
                    },
                    aliases: shared_aliases.clone(),
                },
                |_| Ok(()),
            )?;
        }
    }
    let shared_report = dev_tools_installation::apply_versioned_installation(
        &dev_tools_installation::VersionedInstallRequest {
            layout: shared_layout,
            version: request.version.clone(),
            source: request.source_executable.clone(),
            identity: dev_tools_installation::ArtifactIdentity {
                length: fs::symlink_metadata(&request.source_executable)?.len(),
                sha256: requested_source_sha256.clone(),
            },
            aliases: shared_aliases,
        },
        |_| Ok(()),
    )?;
    let executable = paths.versioned_binary(&shared_report.receipt.active_version);
    let (executable_length, executable_sha256) = file_identity(&executable)?;
    if request.mode == InstallMode::Strong {
        install_privileged_launcher(&executable, Path::new(PRIVILEGED_LAUNCHER_PATH), paths)?;
        install_linux_system_assets(prior_receipt.as_ref())?;
    }
    if request.activate_transparent_launchers {
        install_aliases(
            &paths.bin_dir,
            &executable,
            &TRANSPARENT_ALIASES,
            prior_receipt.as_ref(),
        )?;
    }

    let preserved_provenance = prior_receipt.as_ref().filter(|prior| {
        prior.version == request.version && prior.executable_sha256 == executable_sha256
    });
    let source_commit = verified_release
        .map(|release| release.source_commit.clone())
        .or_else(|| preserved_provenance.and_then(|prior| prior.source_commit.clone()));
    let root_generation = verified_release
        .map(|release| release.root_generation)
        .or_else(|| preserved_provenance.and_then(|prior| prior.root_generation));
    let manifest_generation = verified_release
        .map(|release| release.manifest_generation)
        .or_else(|| preserved_provenance.and_then(|prior| prior.manifest_generation));

    let previous_release = match prior_receipt.as_ref() {
        Some(prior) if prior.version == request.version => prior.previous_release.clone(),
        Some(prior) => Some(retained_release(prior)),
        None => None,
    };
    let receipt = InstallReceipt {
        schema: RECEIPT_SCHEMA.into(),
        mode: request.mode,
        version: request.version.clone(),
        executable: executable.display().to_string(),
        bin_dir: paths.bin_dir.display().to_string(),
        executable_length,
        executable_sha256,
        source_commit,
        root_generation,
        manifest_generation,
        native_git: request.native_git.display().to_string(),
        native_gh: request.native_gh.display().to_string(),
        product_aliases: PRODUCT_ALIASES.iter().map(ToString::to_string).collect(),
        transparent_aliases: if request.activate_transparent_launchers {
            TRANSPARENT_ALIASES
                .iter()
                .map(ToString::to_string)
                .collect()
        } else {
            Vec::new()
        },
        privileged_launcher: (request.mode == InstallMode::Strong)
            .then(|| PRIVILEGED_LAUNCHER_PATH.to_owned()),
        system_assets: if request.mode == InstallMode::Strong {
            system_asset_digests()
        } else {
            BTreeMap::new()
        },
        previous_release,
    };
    write_receipt(&paths.receipt_path(), &receipt)?;
    verify_at(paths)
}

fn validate_release_transition(
    prior: &InstallReceipt,
    request: &InstallRequest,
    requested_source_sha256: &str,
    verified_release: Option<&crate::release_manifest::VerifiedDevAuthRelease>,
) -> Result<()> {
    let prior_authenticated = prior.source_commit.is_some()
        || prior.root_generation.is_some()
        || prior.manifest_generation.is_some();
    if prior_authenticated
        && !(prior.source_commit.is_some()
            && prior.root_generation.is_some()
            && prior.manifest_generation.is_some())
    {
        bail!("installed authenticated-release receipt is incomplete");
    }
    let Some(release) = verified_release else {
        if prior_authenticated
            && (prior.version != request.version
                || prior.executable_sha256 != requested_source_sha256)
        {
            bail!("an authenticated installation cannot be replaced by an unsigned artifact");
        }
        return Ok(());
    };
    if let Some(prior_root) = prior.root_generation {
        if release.root_generation < prior_root {
            bail!("release root generation cannot roll back");
        }
    }
    if let Some(prior_manifest) = prior.manifest_generation {
        if release.manifest_generation < prior_manifest {
            bail!("release manifest generation cannot roll back");
        }
        if prior.version != release.version && release.manifest_generation == prior_manifest {
            bail!("version updates require a newer release manifest generation");
        }
        if release.manifest_generation == prior_manifest
            && (prior.version != release.version
                || prior.source_commit.as_deref() != Some(release.source_commit.as_str())
                || prior.executable_sha256 != release.artifact_sha256)
        {
            bail!("release manifest generation cannot identify different source");
        }
    }
    Ok(())
}

pub fn current_installation() -> Result<(SetupPaths, InstallReceipt)> {
    let (paths, receipt, _) = current_installation_identity()?;
    verify_shared_installation(&paths, &receipt)?;
    verify_exact_alias_set(
        &paths.bin_dir,
        &paths.data_root.join("active"),
        &receipt.product_aliases,
        &PRODUCT_ALIASES,
        false,
    )?;
    verify_exact_alias_set(
        &paths.bin_dir,
        Path::new(&receipt.executable),
        &receipt.transparent_aliases,
        &TRANSPARENT_ALIASES,
        true,
    )?;
    Ok((paths, receipt))
}

pub(crate) fn current_frontend_installation() -> Result<(SetupPaths, InstallReceipt)> {
    let (paths, receipt, metadata) = current_installation_identity()?;
    let expected_owner = match receipt.mode {
        InstallMode::Strong => 0,
        InstallMode::UserOnly => nix::unistd::Uid::effective().as_raw(),
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o777 != 0o755
        || metadata.len() != receipt.executable_length
    {
        bail!("running transparent frontend has unsafe filesystem authority");
    }
    Ok((paths, receipt))
}

fn current_installation_identity() -> Result<(SetupPaths, InstallReceipt, fs::Metadata)> {
    let executable = fs::canonicalize(std::env::current_exe()?)
        .context("resolve the running dev-auth executable")?;
    let version_dir = executable
        .parent()
        .context("installed dev-auth executable has no version directory")?;
    let versions_dir = version_dir
        .parent()
        .context("installed dev-auth executable has no versions directory")?;
    if versions_dir.file_name().and_then(|name| name.to_str()) != Some("versions") {
        bail!("running dev-auth executable is outside the standalone version layout");
    }
    let data_root = versions_dir
        .parent()
        .context("installed dev-auth executable has no data root")?
        .to_path_buf();
    let receipt = read_receipt(&data_root.join("install-v2.json"))?;
    let paths = SetupPaths {
        data_root,
        bin_dir: PathBuf::from(&receipt.bin_dir),
    };
    if receipt.schema != RECEIPT_SCHEMA {
        bail!("dev-auth installation receipt schema is unsupported");
    }
    validate_version(&receipt.version)?;
    validate_directory(&paths.data_root, receipt.mode)?;
    validate_directory(&paths.bin_dir, receipt.mode)?;
    let receipted_executable = paths.versioned_binary(&receipt.version);
    if receipted_executable != executable || Path::new(&receipt.executable) != executable {
        bail!("running dev-auth executable is not the receipt-owned active version");
    }
    let metadata = fs::symlink_metadata(&executable)
        .context("inspect running receipt-owned dev-auth executable")?;
    Ok((paths, receipt, metadata))
}

pub fn verify_at(paths: &SetupPaths) -> Result<SetupReport> {
    let receipt = read_receipt(&paths.receipt_path())?;
    verify_receipted_installation_at(paths, &receipt, true)
}

fn verify_receipted_installation_at(
    paths: &SetupPaths,
    receipt: &InstallReceipt,
    verify_private_shared_receipt: bool,
) -> Result<SetupReport> {
    if receipt.schema != RECEIPT_SCHEMA {
        bail!("dev-auth installation receipt schema is unsupported");
    }
    validate_version(&receipt.version)?;
    validate_directory(&paths.data_root, receipt.mode)?;
    validate_directory(&paths.bin_dir, receipt.mode)?;
    let executable = PathBuf::from(&receipt.executable);
    let expected_executable = paths.versioned_binary(&receipt.version);
    if executable != expected_executable {
        bail!("dev-auth installation receipt names an unexpected executable");
    }
    let (length, digest) = file_identity(&executable)?;
    if length != receipt.executable_length || digest != receipt.executable_sha256 {
        bail!("installed dev-auth executable does not match its receipt");
    }
    if verify_private_shared_receipt {
        verify_shared_installation(paths, receipt)?;
    }
    verify_exact_alias_set(
        &paths.bin_dir,
        &paths.data_root.join("active"),
        &receipt.product_aliases,
        &PRODUCT_ALIASES,
        false,
    )?;
    verify_exact_alias_set(
        &paths.bin_dir,
        &executable,
        &receipt.transparent_aliases,
        &TRANSPARENT_ALIASES,
        true,
    )?;
    validate_native_program(Path::new(&receipt.native_git), "native Git")?;
    validate_native_program(Path::new(&receipt.native_gh), "native GitHub CLI")?;
    if receipt.mode == InstallMode::Strong {
        if receipt.system_assets != system_asset_digests() {
            bail!("dev-auth system asset receipt does not match this product version");
        }
        verify_privileged_launcher(&executable, receipt)?;
        verify_linux_system_assets()?;
    }

    Ok(SetupReport {
        schema: "dev-auth-setup-report-v1".into(),
        mode: receipt.mode,
        version: receipt.version.clone(),
        executable: executable.display().to_string(),
        product_aliases_ready: true,
        transparent_launchers_active: !receipt.transparent_aliases.is_empty(),
        native_git: receipt.native_git.clone(),
        native_gh: receipt.native_gh.clone(),
    })
}

pub fn repair_at(paths: &SetupPaths) -> Result<SetupReport> {
    let receipt = read_receipt(&paths.receipt_path())?;
    let request = InstallRequest {
        mode: receipt.mode,
        version: receipt.version,
        source_executable: PathBuf::from(receipt.executable),
        native_git: PathBuf::from(receipt.native_git),
        native_gh: PathBuf::from(receipt.native_gh),
        activate_transparent_launchers: !receipt.transparent_aliases.is_empty(),
    };
    install_at(paths, &request)
}

pub fn rollback_at(paths: &SetupPaths) -> Result<SetupReport> {
    let mut receipt = read_receipt(&paths.receipt_path())?;
    verify_at(paths)?;
    if !receipt.transparent_aliases.is_empty() {
        deactivate_transparent_launchers_at(paths)?;
        receipt = read_receipt(&paths.receipt_path())?;
    }
    if receipt.mode == InstallMode::Strong {
        stop_system_broker_at(paths)?;
    }
    let Some(previous) = receipt.previous_release.clone() else {
        return verify_at(paths);
    };
    validate_version(&previous.version)?;
    let layout = shared_installation_layout(paths, receipt.mode);
    let shared = dev_tools_installation::verify_versioned_installation(&layout)?;
    if shared.active_version == receipt.version {
        let expected = dev_tools_installation::ArtifactIdentity {
            length: previous.executable_length,
            sha256: previous.executable_sha256.clone(),
        };
        let rolled_back =
            dev_tools_installation::rollback_versioned_installation(&layout, |candidate| {
                let (length, sha256) = file_identity(candidate)?;
                if length != expected.length || sha256 != expected.sha256 {
                    bail!("retained dev-auth release does not match product metadata");
                }
                Ok(())
            })?;
        if rolled_back.receipt.active_version != previous.version
            || rolled_back.receipt.active_identity != expected
        {
            bail!("shared installation rollback selected an unexpected release");
        }
    } else if shared.active_version != previous.version
        || shared.previous_version.as_deref() != Some(receipt.version.as_str())
        || shared.active_identity.length != previous.executable_length
        || shared.active_identity.sha256 != previous.executable_sha256
    {
        bail!("shared installation state cannot resume the product rollback");
    }

    let current = retained_release(&receipt);
    receipt.version = previous.version;
    receipt.executable = paths
        .versioned_binary(&receipt.version)
        .display()
        .to_string();
    receipt.executable_length = previous.executable_length;
    receipt.executable_sha256 = previous.executable_sha256;
    receipt.source_commit = previous.source_commit;
    receipt.root_generation = previous.root_generation;
    receipt.manifest_generation = previous.manifest_generation;
    receipt.system_assets = previous.system_assets;
    receipt.previous_release = Some(current);
    receipt.transparent_aliases.clear();
    if receipt.mode == InstallMode::Strong {
        if receipt.system_assets != system_asset_digests() {
            bail!("retained release requires incompatible system service assets");
        }
        install_privileged_launcher(
            Path::new(&receipt.executable),
            Path::new(PRIVILEGED_LAUNCHER_PATH),
            paths,
        )?;
    }
    write_receipt(&paths.receipt_path(), &receipt)?;
    verify_at(paths)
}

fn retained_release(receipt: &InstallReceipt) -> RetainedRelease {
    RetainedRelease {
        version: receipt.version.clone(),
        executable_length: receipt.executable_length,
        executable_sha256: receipt.executable_sha256.clone(),
        source_commit: receipt.source_commit.clone(),
        root_generation: receipt.root_generation,
        manifest_generation: receipt.manifest_generation,
        system_assets: receipt.system_assets.clone(),
    }
}

pub fn uninstall_at(paths: &SetupPaths) -> Result<UninstallReport> {
    let mut receipt = read_receipt(&paths.receipt_path())?;
    verify_at(paths)?;
    if !receipt.transparent_aliases.is_empty() {
        deactivate_transparent_launchers_at(paths)?;
        receipt = read_receipt(&paths.receipt_path())?;
    }
    if receipt.mode == InstallMode::Strong {
        if !nix::unistd::Uid::effective().is_root() {
            bail!("strong installation removal requires root");
        }
        stop_system_broker()?;
    } else {
        let owner_uid = nix::unistd::Uid::effective().as_raw();
        let home = paths
            .data_root
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .context("user-only installation has no native home")?;
        if paths != &SetupPaths::user_only(home) {
            bail!("user-only installation is outside the native user product layout");
        }
        reconcile_workload_launchers_at(home, Path::new(&receipt.executable), &[], owner_uid)?;
        reconcile_desktop_entries_at(home, &BTreeMap::new(), owner_uid)?;
        remove_empty_workload_alias_receipt(home, &receipt.executable, owner_uid)?;
    }

    let executable = PathBuf::from(&receipt.executable);
    if receipt.mode == InstallMode::Strong {
        remove_privileged_launcher(&executable, &receipt)?;
        remove_linux_system_assets(&receipt)?;
    }
    dev_tools_installation::uninstall_versioned_installation(&shared_installation_layout(
        paths,
        receipt.mode,
    ))?;
    fs::remove_file(paths.receipt_path()).context("remove installation receipt")?;
    remove_directory_if_empty(Some(&paths.data_root))?;
    if receipt.mode == InstallMode::Strong {
        run_system_command(
            Path::new("/usr/bin/systemctl"),
            &[OsStr::new("daemon-reload")],
            "reload removed system service definitions",
        )?;
    }
    Ok(UninstallReport {
        schema: "dev-auth-uninstall-report-v1".into(),
        mode: receipt.mode,
        version: receipt.version,
        preserved_policy: true,
        preserved_credential: true,
    })
}

pub fn purge_system_state() -> Result<StateCleanupReport> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("system-state cleanup requires root");
    }
    require_uninstalled_layout(&SetupPaths::strong())?;
    require_broker_sockets_absent()?;
    let policy_path = Path::new(crate::policy_store::SYSTEM_POLICY_PATH);
    let policy = match fs::symlink_metadata(policy_path) {
        Ok(_) => Some(crate::policy_store::load_system_policy()?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("inspect administrator policy before cleanup"),
    };
    let mut credential_revoked = remove_system_credential_slots(policy.as_ref())?;
    credential_revoked |= remove_optional_state_file(
        Path::new(SYSTEM_CREDENTIAL_PATH),
        0,
        0o077,
        BINARY_LIMIT,
        "legacy encrypted system credential",
    )?;
    let policy_removed =
        remove_optional_state_file(policy_path, 0, 0o022, POLICY_LIMIT, "administrator policy")?;
    Ok(StateCleanupReport {
        schema: "dev-auth-state-cleanup-v1".into(),
        mode: InstallMode::Strong,
        policy_removed,
        user_config_removed: false,
        credential_revoked,
    })
}

pub fn purge_user_state() -> Result<StateCleanupReport> {
    let owner_uid = nix::unistd::Uid::effective().as_raw();
    if owner_uid == 0 {
        bail!("user-state cleanup requires a native non-root user");
    }
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
        .context("effective user account does not exist")?;
    require_uninstalled_layout(&SetupPaths::user_only(&user.dir))?;
    if !matches!(
        crate::broker_client::active_claim_and_probe()?.0,
        crate::broker_protocol::LocalSessionClaim::Absent
    ) {
        bail!("user state cannot be removed inside an admitted workload");
    }
    let policy_path = crate::policy_store::user_policy_path(&user);
    let policy = match fs::symlink_metadata(&policy_path) {
        Ok(_) => Some(crate::policy_store::load_user_policy_at(
            &policy_path,
            owner_uid,
        )?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("inspect user policy before cleanup"),
    };
    if let Some(policy) = &policy {
        for slot in policy.credential_slots.keys() {
            crate::runtime::revoke_user_broker_service_token_for_slot(slot)?;
        }
    } else {
        crate::revoke_user_broker_service_token()?;
    }
    let policy_removed = remove_optional_state_file(
        &policy_path,
        owner_uid,
        0o077,
        POLICY_LIMIT,
        "user-only administrator policy",
    )?;
    let user_config_removed = remove_optional_state_file(
        &crate::policy_store::user_config_path(&user),
        owner_uid,
        0o077,
        POLICY_LIMIT,
        "user configuration",
    )?;
    Ok(StateCleanupReport {
        schema: "dev-auth-state-cleanup-v1".into(),
        mode: InstallMode::UserOnly,
        policy_removed,
        user_config_removed,
        credential_revoked: true,
    })
}

fn remove_system_credential_slots(
    policy: Option<&crate::policy_v2::SystemPolicyV2>,
) -> Result<bool> {
    let directory = Path::new(SYSTEM_CREDENTIAL_DIRECTORY);
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("inspect system credential slot directory"),
    };
    let policy = policy
        .context("system credential slots remain without administrator policy cleanup authority")?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
    {
        bail!("system credential slot directory has unsafe cleanup authority");
    }
    let declared = policy.credential_slots.keys().collect::<BTreeSet<_>>();
    let mut entries = fs::read_dir(directory)
        .context("enumerate system credential slots")?
        .map(|entry| entry.context("read system credential slot entry"))
        .collect::<Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let mut removed = false;
    for entry in entries {
        let slot = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("system credential slot name is not UTF-8"))?;
        validate_credential_slot(&slot)?;
        if !declared.contains(&slot) {
            bail!("system credential slot is not owned by administrator policy");
        }
        removed |= remove_optional_state_file(
            &entry.path(),
            0,
            0o077,
            BINARY_LIMIT,
            "encrypted system credential slot",
        )?;
    }
    fs::remove_dir(directory).context("remove empty system credential slot directory")?;
    Ok(removed)
}

fn require_uninstalled_layout(paths: &SetupPaths) -> Result<()> {
    match fs::symlink_metadata(paths.receipt_path()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => bail!("dev-auth must be uninstalled before state cleanup"),
        Err(error) => return Err(error).context("inspect installation receipt before cleanup"),
    }
    for alias in PRODUCT_ALIASES.into_iter().chain(TRANSPARENT_ALIASES) {
        match fs::symlink_metadata(paths.bin_dir.join(alias)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => bail!("dev-auth launcher artifacts remain before state cleanup"),
            Err(error) => return Err(error).context("inspect launcher before state cleanup"),
        }
    }
    Ok(())
}

fn require_broker_sockets_absent() -> Result<()> {
    for socket in [
        crate::broker_client::SYSTEM_BROKER_SOCKET,
        crate::broker_client::SYSTEM_CONTROL_SOCKET,
    ] {
        match fs::symlink_metadata(socket) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => bail!("system broker socket remains before state cleanup"),
            Err(error) => return Err(error).context("inspect broker socket before cleanup"),
        }
    }
    Ok(())
}

fn require_user_sessions_absent() -> Result<()> {
    let owner_uid = nix::unistd::Uid::effective().as_raw();
    if owner_uid == 0 {
        bail!("user-only installation requires a native non-root user");
    }
    require_user_sessions_absent_at(
        &PathBuf::from(format!("/run/user/{owner_uid}/dev-auth-v3/user-sessions")),
        owner_uid,
    )
}

fn require_user_sessions_absent_at(sessions: &Path, owner_uid: u32) -> Result<()> {
    let metadata = match fs::symlink_metadata(sessions) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect user workload sessions"),
    };
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o077 != 0
    {
        bail!("user workload session directory has unsafe authority");
    }
    let mut entries = fs::read_dir(sessions).context("enumerate user workload sessions")?;
    if entries.next().transpose()?.is_some() {
        bail!("user workload sessions must stop before a version update");
    }
    Ok(())
}

fn remove_optional_state_file(
    path: &Path,
    owner_uid: u32,
    forbidden_mode: u32,
    limit: u64,
    description: &str,
) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).with_context(|| format!("inspect {description}")),
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & forbidden_mode != 0
        || metadata.len() > limit
    {
        bail!("{description} has unsafe cleanup authority");
    }
    fs::remove_file(path).with_context(|| format!("remove {description}"))?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("sync {description} directory"))?;
    }
    Ok(true)
}

fn remove_privileged_launcher(executable: &Path, receipt: &InstallReceipt) -> Result<()> {
    verify_privileged_launcher(executable, receipt)?;
    let launcher = receipt
        .privileged_launcher
        .as_deref()
        .context("strong installation receipt has no privileged launcher")?;
    fs::remove_file(launcher).context("remove privileged workload launcher")
}

fn remove_linux_system_assets(receipt: &InstallReceipt) -> Result<()> {
    if receipt.system_assets != system_asset_digests() {
        bail!("system assets are not owned by this product version");
    }
    verify_linux_system_assets()?;
    for (path, _, _) in linux_system_assets() {
        fs::remove_file(path)
            .with_context(|| format!("remove dev-auth system asset {}", path.display()))?;
    }
    Ok(())
}

fn remove_directory_if_empty(path: Option<&Path>) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(error) => {
            Err(error).with_context(|| format!("remove empty directory {}", path.display()))
        }
    }
}

fn remove_empty_workload_alias_receipt(
    home: &Path,
    executable: &str,
    owner_uid: u32,
) -> Result<()> {
    let receipt = read_workload_alias_receipt(home, owner_uid)?
        .context("workload alias receipt disappeared during uninstall")?;
    if !receipt.aliases.is_empty() || receipt.executable != executable {
        bail!("workload alias receipt changed during uninstall");
    }
    fs::remove_file(workload_alias_receipt_path(home))
        .context("remove empty workload alias receipt")
}

pub fn privileged_launcher_path() -> &'static Path {
    Path::new(PRIVILEGED_LAUNCHER_PATH)
}

pub fn validate_running_privileged_launcher() -> Result<PathBuf> {
    let current = std::env::current_exe().context("resolve privileged workload launcher")?;
    if current != Path::new(PRIVILEGED_LAUNCHER_PATH) {
        bail!("privileged workload dispatch requires the dedicated launcher identity");
    }
    let (paths, receipt) = current_installation_from_privileged_launcher(&current)?;
    let executable = paths.versioned_binary(&receipt.version);
    verify_privileged_launcher(&executable, &receipt)?;
    Ok(executable)
}

fn current_installation_from_privileged_launcher(
    launcher: &Path,
) -> Result<(SetupPaths, InstallReceipt)> {
    let data_root = launcher
        .parent()
        .context("privileged launcher has no product root")?
        .to_path_buf();
    let receipt = read_receipt(&data_root.join("install-v2.json"))?;
    if receipt.schema != RECEIPT_SCHEMA || receipt.mode != InstallMode::Strong {
        bail!("privileged launcher receipt is invalid");
    }
    validate_version(&receipt.version)?;
    let paths = SetupPaths {
        data_root,
        bin_dir: PathBuf::from(&receipt.bin_dir),
    };
    validate_directory(&paths.data_root, InstallMode::Strong)?;
    validate_directory(&paths.bin_dir, InstallMode::Strong)?;
    let executable = paths.versioned_binary(&receipt.version);
    if Path::new(&receipt.executable) != executable {
        bail!("privileged launcher receipt names an unexpected executable");
    }
    let metadata = fs::symlink_metadata(&executable)
        .context("inspect privileged launcher receipt executable")?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() != receipt.executable_length
    {
        bail!("privileged launcher executable does not match its receipt");
    }
    Ok((paths, receipt))
}

pub fn deactivate_transparent_launchers_at(paths: &SetupPaths) -> Result<SetupReport> {
    let mut receipt = read_receipt(&paths.receipt_path())?;
    if receipt.schema != RECEIPT_SCHEMA {
        bail!("dev-auth installation receipt schema is unsupported");
    }
    let executable = PathBuf::from(&receipt.executable);
    for alias in &receipt.transparent_aliases {
        remove_owned_alias(&paths.bin_dir.join(alias), &executable)?;
    }
    receipt.transparent_aliases.clear();
    write_receipt(&paths.receipt_path(), &receipt)?;
    verify_at(paths)
}

pub fn activate_transparent_launchers_at(paths: &SetupPaths) -> Result<SetupReport> {
    let mut receipt = read_receipt(&paths.receipt_path())?;
    if receipt.schema != RECEIPT_SCHEMA {
        bail!("dev-auth installation receipt schema is unsupported");
    }
    if !receipt.transparent_aliases.is_empty() {
        return verify_at(paths);
    }
    verify_at(paths)?;
    if receipt.mode == InstallMode::Strong {
        match crate::broker_client::probe_system_broker() {
            crate::broker_protocol::BrokerSessionProbe::NoSession => {}
            crate::broker_protocol::BrokerSessionProbe::Verified { .. } => {
                bail!("refusing launcher activation from inside a workload session")
            }
            crate::broker_protocol::BrokerSessionProbe::Invalid { reason }
            | crate::broker_protocol::BrokerSessionProbe::Unavailable { reason } => {
                bail!("system broker is not ready for launcher activation: {reason}")
            }
        }
    }

    let executable = PathBuf::from(&receipt.executable);
    install_aliases(
        &paths.bin_dir,
        &executable,
        &TRANSPARENT_ALIASES,
        Some(&receipt),
    )?;
    receipt.transparent_aliases = TRANSPARENT_ALIASES
        .iter()
        .map(ToString::to_string)
        .collect();
    if let Err(error) = write_receipt(&paths.receipt_path(), &receipt) {
        for alias in TRANSPARENT_ALIASES {
            let _ = remove_owned_alias(&paths.bin_dir.join(alias), &executable);
        }
        return Err(error).context("record transparent launcher activation");
    }
    verify_at(paths)
}

pub fn start_system_broker() -> Result<SetupReport> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("system broker activation requires root");
    }
    let (paths, _) = current_installation()?;
    start_system_broker_at(&paths)
}

pub fn start_system_broker_at(paths: &SetupPaths) -> Result<SetupReport> {
    if !nix::unistd::Uid::effective().is_root() || *paths != SetupPaths::strong() {
        bail!("system broker activation requires root and the system layout");
    }
    let receipt = read_receipt(&paths.receipt_path())?;
    if receipt.mode != InstallMode::Strong {
        bail!("system broker activation requires a strong installation");
    }
    verify_at(paths)?;
    let policy = crate::policy_store::load_system_policy()?;
    if Path::new(&policy.programs.git) != Path::new(&receipt.native_git)
        || Path::new(&policy.programs.gh) != Path::new(&receipt.native_gh)
    {
        bail!("administrator policy and installation receipt disagree on native tools");
    }
    for slot in policy.credential_slots.keys() {
        if !system_service_credential_slot_ready(slot) {
            bail!("encrypted system broker credential slot is not ready");
        }
    }
    run_system_command(
        Path::new("/usr/bin/systemd-sysusers"),
        &[OsStr::new("/etc/sysusers.d/dev-auth.conf")],
        "create the protected broker account",
    )?;
    run_system_command(
        Path::new("/usr/bin/systemctl"),
        &[OsStr::new("daemon-reload")],
        "reload system service definitions",
    )?;
    run_system_command(
        Path::new("/usr/bin/systemctl"),
        &[
            OsStr::new("enable"),
            OsStr::new("--now"),
            OsStr::new("dev-auth-broker.socket"),
            OsStr::new("dev-auth-broker-control.socket"),
        ],
        "activate broker sockets",
    )?;
    match crate::broker_client::probe_system_broker() {
        crate::broker_protocol::BrokerSessionProbe::NoSession => verify_at(paths),
        crate::broker_protocol::BrokerSessionProbe::Verified { .. } => {
            bail!("system broker activation ran inside an admitted workload")
        }
        crate::broker_protocol::BrokerSessionProbe::Invalid { reason }
        | crate::broker_protocol::BrokerSessionProbe::Unavailable { reason } => {
            bail!("system broker did not become ready: {reason}")
        }
    }
}

pub fn stop_system_broker() -> Result<SetupReport> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("system broker deactivation requires root");
    }
    let (paths, _) = current_installation()?;
    stop_system_broker_at(&paths)
}

pub fn stop_system_broker_at(paths: &SetupPaths) -> Result<SetupReport> {
    if !nix::unistd::Uid::effective().is_root() || *paths != SetupPaths::strong() {
        bail!("system broker deactivation requires root and the system layout");
    }
    let receipt = read_receipt(&paths.receipt_path())?;
    if receipt.mode != InstallMode::Strong {
        bail!("system broker deactivation requires a strong installation");
    }
    if !receipt.transparent_aliases.is_empty() {
        bail!("transparent launchers must be deactivated before stopping the broker");
    }
    run_system_command(
        Path::new("/usr/bin/systemctl"),
        &[
            OsStr::new("disable"),
            OsStr::new("--now"),
            OsStr::new("dev-auth-broker.socket"),
            OsStr::new("dev-auth-broker-control.socket"),
            OsStr::new("dev-auth-broker.service"),
        ],
        "stop broker services",
    )?;
    verify_at(paths)
}

fn run_system_command(program: &Path, arguments: &[&OsStr], description: &str) -> Result<()> {
    validate_native_program(program, description)?;
    let status = Command::new(program)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| description.to_string())?;
    if !status.success() {
        bail!("{description} failed");
    }
    Ok(())
}

fn validate_install_request(paths: &SetupPaths, request: &InstallRequest) -> Result<()> {
    if request.mode == InstallMode::Strong && !cfg!(target_os = "linux") {
        bail!("strong setup is supported only on Linux");
    }
    validate_version(&request.version)?;
    if !paths.data_root.is_absolute() || !paths.bin_dir.is_absolute() {
        bail!("dev-auth setup paths must be absolute");
    }
    if paths.data_root.starts_with(&paths.bin_dir) || paths.bin_dir.starts_with(&paths.data_root) {
        bail!("dev-auth data and launcher directories must not contain one another");
    }
    validate_native_program(&request.source_executable, "setup executable")?;
    validate_native_program(&request.native_git, "native Git")?;
    validate_native_program(&request.native_gh, "native GitHub CLI")?;
    if request.native_git == request.native_gh
        || request.native_git.starts_with(&paths.bin_dir)
        || request.native_gh.starts_with(&paths.bin_dir)
    {
        bail!("native programs must be distinct and outside the managed launcher directory");
    }
    if request.mode == InstallMode::Strong && request.activate_transparent_launchers {
        bail!("strong setup activates same-name launchers only after broker readiness");
    }
    if request.mode == InstallMode::Strong {
        validate_root_owned_executable(&request.native_git, "native Git")?;
        validate_root_owned_executable(&request.native_gh, "native GitHub CLI")?;
        for (path, description) in [
            (Path::new("/usr/bin/pkexec"), "polkit workload launcher"),
            (
                Path::new("/usr/bin/systemd-run"),
                "transient workload service manager",
            ),
            (
                Path::new("/usr/bin/systemd-creds"),
                "system credential tool",
            ),
            (
                Path::new("/usr/bin/systemd-sysusers"),
                "system account manager",
            ),
            (Path::new("/usr/bin/systemctl"), "system service manager"),
        ] {
            validate_root_owned_executable(path, description)?;
        }
    }
    Ok(())
}

pub fn linux_system_assets() -> Vec<(&'static Path, &'static str, u32)> {
    SYSTEM_ASSETS
        .iter()
        .map(|(path, content, mode)| (Path::new(path), *content, *mode))
        .collect()
}

pub fn enroll_system_service_credential(value: &[u8]) -> Result<()> {
    enroll_system_service_credential_slot("automation", value)
}

pub fn enroll_system_service_credential_slot(slot: &str, value: &[u8]) -> Result<()> {
    if nix::unistd::Uid::effective().as_raw() != 0 {
        bail!("system service credential enrollment requires root");
    }
    let destination = system_credential_slot_path(slot)?;
    store_system_service_credential_at(
        Path::new("/usr/bin/systemd-creds"),
        &destination,
        slot,
        value,
        0,
        false,
    )
}

pub fn rotate_system_service_credential(value: &[u8]) -> Result<()> {
    if nix::unistd::Uid::effective().as_raw() != 0 {
        bail!("system service credential rotation requires root");
    }
    let (paths, _) = current_installation()?;
    rotate_system_service_credential_at(&paths, value)
}

pub fn rotate_system_service_credential_at(paths: &SetupPaths, value: &[u8]) -> Result<()> {
    rotate_system_service_credential_slot_at(paths, "automation", value)
}

pub fn rotate_system_service_credential_slot_at(
    paths: &SetupPaths,
    slot: &str,
    value: &[u8],
) -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() || *paths != SetupPaths::strong() {
        bail!("system service credential rotation requires root and the system layout");
    }
    require_stopped_strong_installation_at(paths)?;
    let destination = system_credential_slot_path(slot)?;
    store_system_service_credential_at(
        Path::new("/usr/bin/systemd-creds"),
        &destination,
        slot,
        value,
        0,
        true,
    )
}

pub fn revoke_system_service_credential() -> Result<()> {
    if nix::unistd::Uid::effective().as_raw() != 0 {
        bail!("system service credential revocation requires root");
    }
    let (paths, _) = current_installation()?;
    revoke_system_service_credential_at(&paths)
}

pub fn revoke_system_service_credential_at(paths: &SetupPaths) -> Result<()> {
    revoke_system_service_credential_slot_at(paths, "automation")
}

pub fn revoke_system_service_credential_slot_at(paths: &SetupPaths, slot: &str) -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() || *paths != SetupPaths::strong() {
        bail!("system service credential revocation requires root and the system layout");
    }
    require_stopped_strong_installation_at(paths)?;
    let path = system_credential_slot_path(slot)?;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect system service credential"),
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
    {
        bail!("system service credential has unsafe revocation authority");
    }
    fs::remove_file(path).context("remove encrypted system service credential")
}

fn require_stopped_strong_installation() -> Result<()> {
    let (paths, _) = current_installation()?;
    require_stopped_strong_installation_at(&paths)
}

fn require_stopped_strong_installation_at(paths: &SetupPaths) -> Result<()> {
    let receipt = read_receipt(&paths.receipt_path())?;
    if receipt.mode != InstallMode::Strong || !receipt.transparent_aliases.is_empty() {
        bail!("operation requires a stopped, deactivated strong installation");
    }
    for socket in [
        crate::broker_client::SYSTEM_BROKER_SOCKET,
        crate::broker_client::SYSTEM_CONTROL_SOCKET,
    ] {
        if fs::symlink_metadata(socket).is_ok() {
            bail!("operation requires stopped broker sockets");
        }
    }
    Ok(())
}

pub fn system_service_credential_ready() -> bool {
    system_service_credential_slot_ready("automation")
}

pub fn system_service_credential_slot_ready(slot: &str) -> bool {
    let Ok(path) = system_credential_slot_path(slot) else {
        return false;
    };
    let parent_ready = path.parent().is_some_and(|parent| {
        fs::symlink_metadata(parent).is_ok_and(|metadata| {
            metadata.file_type().is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.mode() & 0o077 == 0
        })
    });
    parent_ready
        && fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.mode() & 0o077 == 0
                && metadata.nlink() == 1
                && metadata.len() > 0
                && metadata.len() <= BINARY_LIMIT
        })
}

fn system_credential_slot_path(slot: &str) -> Result<PathBuf> {
    validate_credential_slot(slot)?;
    Ok(Path::new(SYSTEM_CREDENTIAL_DIRECTORY).join(slot))
}

fn validate_credential_slot(slot: &str) -> Result<()> {
    let mut bytes = slot.bytes();
    if slot.is_empty()
        || slot.len() > 64
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("credential slot is invalid");
    }
    Ok(())
}

pub fn user_service_credential_ready() -> bool {
    crate::runtime::user_broker_service_token().is_ok()
}

pub fn install_system_policy(source: &Path, approved_sha256: &str) -> Result<PathBuf> {
    reconcile_system_policy(source, approved_sha256, None)
}

pub fn reconcile_system_policy(
    source: &Path,
    approved_sha256: &str,
    current_sha256: Option<&str>,
) -> Result<PathBuf> {
    reconcile_system_policy_at(
        &SetupPaths::strong(),
        source,
        approved_sha256,
        current_sha256,
    )
}

pub fn reconcile_system_policy_at(
    paths: &SetupPaths,
    source: &Path,
    approved_sha256: &str,
    current_sha256: Option<&str>,
) -> Result<PathBuf> {
    if !nix::unistd::Uid::effective().is_root() || *paths != SetupPaths::strong() {
        bail!("administrator policy installation requires root and the system layout");
    }
    let bytes = read_approved_public_document(source, approved_sha256)?;
    let policy = crate::policy_v2::parse_system_policy_v2(&bytes)?;
    validate_system_policy_programs(&policy)?;
    let destination = PathBuf::from(crate::policy_store::SYSTEM_POLICY_PATH);
    match (fs::symlink_metadata(&destination), current_sha256) {
        (Err(error), _) if error.kind() == std::io::ErrorKind::NotFound => {
            install_policy_document(&destination, &bytes, 0, 0o644)?;
        }
        (Err(error), _) => return Err(error).context("inspect administrator policy"),
        (Ok(_), _) if fs::read(&destination)? == bytes => {
            install_policy_document(&destination, &bytes, 0, 0o644)?;
        }
        (Ok(_), Some(current)) => {
            require_stopped_strong_installation_at(paths)?;
            replace_policy_document(&destination, &bytes, 0, 0o644, current)?;
        }
        (Ok(_), None) => install_policy_document(&destination, &bytes, 0, 0o644)?,
    }
    Ok(destination)
}

pub fn update_system_policy(
    source: &Path,
    approved_sha256: &str,
    current_sha256: &str,
) -> Result<PathBuf> {
    if nix::unistd::Uid::effective().as_raw() != 0 {
        bail!("administrator policy update requires root");
    }
    require_stopped_strong_installation()?;
    let bytes = read_approved_public_document(source, approved_sha256)?;
    let policy = crate::policy_v2::parse_system_policy_v2(&bytes)?;
    validate_system_policy_programs(&policy)?;
    let destination = PathBuf::from(crate::policy_store::SYSTEM_POLICY_PATH);
    replace_policy_document(&destination, &bytes, 0, 0o644, current_sha256)?;
    Ok(destination)
}

pub fn install_user_policy(source: &Path, approved_sha256: &str) -> Result<PathBuf> {
    let owner_uid = nix::unistd::Uid::effective().as_raw();
    if owner_uid == 0 {
        bail!("user-only policy must be installed by its native user");
    }
    let (_, receipt) = current_installation()?;
    if receipt.mode != InstallMode::UserOnly {
        bail!("user-only policy cannot configure a strong installation");
    }
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
        .context("effective user account does not exist")?;
    let bytes = read_approved_public_document(source, approved_sha256)?;
    let policy = crate::policy_v2::parse_system_policy_v2(&bytes)?;
    validate_user_policy_programs(&policy, &user, owner_uid)?;
    let destination = crate::policy_store::user_policy_path(&user);
    install_policy_document(&destination, &bytes, owner_uid, 0o600)?;
    Ok(destination)
}

pub fn install_user_policy_for_account_at(
    paths: &SetupPaths,
    source: &Path,
    approved_sha256: &str,
    user_name: &str,
) -> Result<PathBuf> {
    reconcile_user_policy_for_account_at(paths, source, approved_sha256, user_name, None)
}

pub fn reconcile_user_policy_for_account_at(
    paths: &SetupPaths,
    source: &Path,
    approved_sha256: &str,
    user_name: &str,
    current_sha256: Option<&str>,
) -> Result<PathBuf> {
    let user = nix::unistd::User::from_name(user_name)?
        .context("user-only policy names an unknown native account")?;
    let owner_uid = user.uid.as_raw();
    if nix::unistd::Uid::effective() != user.uid || *paths != SetupPaths::user_only(&user.dir) {
        bail!("user-only policy requires its native account layout");
    }
    let receipt = read_receipt(&paths.receipt_path())?;
    if receipt.mode != InstallMode::UserOnly {
        bail!("user-only policy cannot configure a strong installation");
    }
    let bytes = read_approved_public_document(source, approved_sha256)?;
    let policy = crate::policy_v2::parse_system_policy_v2(&bytes)?;
    validate_user_policy_programs(&policy, &user, owner_uid)?;
    let destination = crate::policy_store::user_policy_path(&user);
    match (fs::symlink_metadata(&destination), current_sha256) {
        (Err(error), _) if error.kind() == std::io::ErrorKind::NotFound => {
            install_policy_document(&destination, &bytes, owner_uid, 0o600)?;
        }
        (Err(error), _) => return Err(error).context("inspect user-only policy"),
        (Ok(_), _) if fs::read(&destination)? == bytes => {
            install_policy_document(&destination, &bytes, owner_uid, 0o600)?;
        }
        (Ok(_), Some(current)) => {
            if !matches!(
                crate::broker_client::active_claim_and_probe()?.0,
                crate::broker_protocol::LocalSessionClaim::Absent
            ) {
                bail!("user-only policy cannot change inside an admitted workload");
            }
            let config = crate::policy_store::load_user_config_at(
                &crate::policy_store::user_config_path(&user),
                owner_uid,
            )?;
            crate::policy_v2::resolve_policy_for_user(&policy, &user.name, &config)
                .context("updated user-only policy would invalidate the user configuration")?;
            replace_policy_document(&destination, &bytes, owner_uid, 0o600, current)?;
        }
        (Ok(_), None) => install_policy_document(&destination, &bytes, owner_uid, 0o600)?,
    }
    Ok(destination)
}

pub fn update_user_policy(
    source: &Path,
    approved_sha256: &str,
    current_sha256: &str,
) -> Result<PathBuf> {
    let owner_uid = nix::unistd::Uid::effective().as_raw();
    if owner_uid == 0 {
        bail!("user-only policy update requires a native non-root user");
    }
    let (_, receipt) = current_installation()?;
    if receipt.mode != InstallMode::UserOnly {
        bail!("user-only policy cannot update a strong installation");
    }
    if !matches!(
        crate::broker_client::active_claim_and_probe()?.0,
        crate::broker_protocol::LocalSessionClaim::Absent
    ) {
        bail!("user-only policy cannot change inside an admitted workload");
    }
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
        .context("effective user account does not exist")?;
    let bytes = read_approved_public_document(source, approved_sha256)?;
    let policy = crate::policy_v2::parse_system_policy_v2(&bytes)?;
    validate_user_policy_programs(&policy, &user, owner_uid)?;
    let config = crate::policy_store::load_user_config_at(
        &crate::policy_store::user_config_path(&user),
        owner_uid,
    )?;
    crate::policy_v2::resolve_policy_for_user(&policy, &user.name, &config)
        .context("updated user-only policy would invalidate the active user configuration")?;
    let destination = crate::policy_store::user_policy_path(&user);
    replace_policy_document(&destination, &bytes, owner_uid, 0o600, current_sha256)?;
    Ok(destination)
}

pub fn install_user_config(source: &Path, approved_sha256: &str) -> Result<PathBuf> {
    install_or_update_user_config(source, approved_sha256, None)
}

pub fn install_strong_user_config(
    source: &Path,
    approved_sha256: &str,
    user_name: &str,
) -> Result<PathBuf> {
    install_user_config_for_account_at(&SetupPaths::strong(), source, approved_sha256, user_name)
}

pub fn install_user_config_for_account_at(
    paths: &SetupPaths,
    source: &Path,
    approved_sha256: &str,
    user_name: &str,
) -> Result<PathBuf> {
    reconcile_user_config_for_account_at(paths, source, approved_sha256, user_name, None)
}

pub fn reconcile_user_config_for_account_at(
    paths: &SetupPaths,
    source: &Path,
    approved_sha256: &str,
    user_name: &str,
    current_sha256: Option<&str>,
) -> Result<PathBuf> {
    reconcile_user_config_for_account_with_integrations_at(
        paths,
        source,
        approved_sha256,
        user_name,
        current_sha256,
        true,
    )
}

/// Install a validated user configuration without publishing workload entrypoints.
///
/// Full setup uses this while the candidate is inactive. Workload launchers and
/// desktop entries are reconciled only after credential and broker readiness.
pub fn reconcile_inactive_user_config_for_account_at(
    paths: &SetupPaths,
    source: &Path,
    approved_sha256: &str,
    user_name: &str,
    current_sha256: Option<&str>,
) -> Result<PathBuf> {
    reconcile_user_config_for_account_with_integrations_at(
        paths,
        source,
        approved_sha256,
        user_name,
        current_sha256,
        false,
    )
}

fn reconcile_user_config_for_account_with_integrations_at(
    paths: &SetupPaths,
    source: &Path,
    approved_sha256: &str,
    user_name: &str,
    current_sha256: Option<&str>,
    reconcile_integrations: bool,
) -> Result<PathBuf> {
    let user = nix::unistd::User::from_name(user_name)?
        .context("user configuration names an unknown native account")?;
    let bytes = read_approved_public_document(source, approved_sha256)?;
    let user_config = crate::policy_v2::parse_user_config_v2(&bytes)?;
    let installation = read_receipt(&paths.receipt_path())?;
    match installation.mode {
        InstallMode::Strong => {
            if !nix::unistd::Uid::effective().is_root() || *paths != SetupPaths::strong() {
                bail!("strong user configuration requires root and the system layout");
            }
        }
        InstallMode::UserOnly => {
            if nix::unistd::Uid::effective() != user.uid
                || *paths != SetupPaths::user_only(&user.dir)
            {
                bail!("user-only configuration requires its native account layout");
            }
        }
    }
    let policy = match installation.mode {
        InstallMode::Strong => crate::policy_store::load_system_policy()?,
        InstallMode::UserOnly => crate::policy_store::load_user_policy_at(
            &crate::policy_store::user_policy_path(&user),
            user.uid.as_raw(),
        )?,
    };
    if !policy
        .allowed_users
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&user.name))
    {
        bail!("native user is outside administrator policy");
    }
    let resolved = crate::policy_v2::resolve_policy_for_user(&policy, &user.name, &user_config)?;
    let executable = PathBuf::from(&installation.executable);
    let aliases = resolved.workloads.keys().cloned().collect::<Vec<_>>();
    let owner_uid = user.uid.as_raw();
    if reconcile_integrations {
        preflight_workload_launchers_at(&user.dir, &executable, &aliases, owner_uid)?;
        preflight_desktop_entries_at(&user.dir, &resolved.workloads, owner_uid)?;
    }
    let destination = crate::policy_store::user_config_path(&user);
    let old_workloads = preflight_user_config_destination(
        &destination,
        &bytes,
        current_sha256,
        owner_uid,
        &policy,
        &user.name,
        reconcile_integrations,
    )?;
    let old_aliases = old_workloads.keys().cloned().collect::<Vec<_>>();
    let result = (|| {
        if reconcile_integrations {
            reconcile_workload_launchers_at(&user.dir, &executable, &aliases, owner_uid)?;
            reconcile_desktop_entries_at(&user.dir, &resolved.workloads, owner_uid)?;
        }
        match current_sha256 {
            Some(current) => {
                replace_policy_document(&destination, &bytes, owner_uid, 0o600, current)
            }
            None => install_policy_document(&destination, &bytes, owner_uid, 0o600),
        }
    })();
    if let Err(error) = result {
        if reconcile_integrations {
            let alias_rollback =
                reconcile_workload_launchers_at(&user.dir, &executable, &old_aliases, owner_uid);
            let desktop_rollback =
                reconcile_desktop_entries_at(&user.dir, &old_workloads, owner_uid);
            if alias_rollback.is_err() || desktop_rollback.is_err() {
                bail!("user configuration apply failed and integration rollback was incomplete: {error:#}");
            }
        }
        return Err(error).context("apply user configuration transaction");
    }
    Ok(destination)
}

pub fn update_user_config(
    source: &Path,
    approved_sha256: &str,
    current_sha256: &str,
) -> Result<PathBuf> {
    install_or_update_user_config(source, approved_sha256, Some(current_sha256))
}

fn install_or_update_user_config(
    source: &Path,
    approved_sha256: &str,
    current_sha256: Option<&str>,
) -> Result<PathBuf> {
    let owner_uid = nix::unistd::Uid::effective().as_raw();
    if owner_uid == 0 {
        bail!("user configuration must be installed by its native user");
    }
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
        .context("effective user account does not exist")?;
    let bytes = read_approved_public_document(source, approved_sha256)?;
    let user_config = crate::policy_v2::parse_user_config_v2(&bytes)?;
    let (_, receipt) = current_installation()?;
    let system_policy = match receipt.mode {
        InstallMode::Strong => crate::policy_store::load_system_policy()?,
        InstallMode::UserOnly => crate::policy_store::load_user_policy_at(
            &crate::policy_store::user_policy_path(&user),
            owner_uid,
        )?,
    };
    if !system_policy
        .allowed_users
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&user.name))
    {
        bail!("native user is outside administrator policy");
    }
    let resolved =
        crate::policy_v2::resolve_policy_for_user(&system_policy, &user.name, &user_config)?;
    let (installation_paths, installation) = current_installation()?;
    let executable = PathBuf::from(&installation.executable);
    let aliases = resolved.workloads.keys().cloned().collect::<Vec<_>>();
    preflight_workload_launchers_at(&user.dir, &executable, &aliases, owner_uid)?;
    preflight_desktop_entries_at(&user.dir, &resolved.workloads, owner_uid)?;
    let destination = crate::policy_store::user_config_path(&user);
    let old_workloads = preflight_user_config_destination(
        &destination,
        &bytes,
        current_sha256,
        owner_uid,
        &system_policy,
        &user.name,
        true,
    )?;
    let old_aliases = old_workloads.keys().cloned().collect::<Vec<_>>();
    let result = (|| {
        reconcile_workload_launchers_at(&user.dir, &executable, &aliases, owner_uid)?;
        reconcile_desktop_entries_at(&user.dir, &resolved.workloads, owner_uid)?;
        match current_sha256 {
            Some(current) => {
                replace_policy_document(&destination, &bytes, owner_uid, 0o600, current)
            }
            None => install_policy_document(&destination, &bytes, owner_uid, 0o600),
        }
    })();
    if let Err(error) = result {
        let alias_rollback =
            reconcile_workload_launchers_at(&user.dir, &executable, &old_aliases, owner_uid);
        let desktop_rollback = reconcile_desktop_entries_at(&user.dir, &old_workloads, owner_uid);
        if alias_rollback.is_err() || desktop_rollback.is_err() {
            bail!(
                "user configuration update failed and launcher rollback was incomplete: {error:#}"
            );
        }
        return Err(error).context("apply user configuration transaction");
    }
    if installation.mode == InstallMode::UserOnly
        && installation_paths != SetupPaths::user_only(&user.dir)
    {
        bail!("user-only installation is outside the native user product layout");
    }
    Ok(destination)
}

fn workload_alias_receipt_path(home: &Path) -> PathBuf {
    home.join(".local/share/dev-auth/workload-aliases-v1.json")
}

fn desktop_entry_receipt_path(home: &Path) -> PathBuf {
    home.join(".local/share/dev-auth/desktop-entries-v1.json")
}

fn desktop_entry_directory(home: &Path) -> PathBuf {
    home.join(".local/share/applications")
}

pub fn verify_user_integrations_at(
    home: &Path,
    executable: &Path,
    workloads: &BTreeMap<String, crate::policy_v2::ResolvedWorkload>,
    owner_uid: u32,
) -> Result<UserIntegrationReport> {
    let aliases = workloads.keys().cloned().collect::<Vec<_>>();
    validate_workload_alias_names(&aliases)?;
    validate_native_program(executable, "workload broker executable")?;
    let workload_receipt = read_workload_alias_receipt(home, owner_uid)?;
    if aliases.is_empty() {
        if workload_receipt
            .as_ref()
            .is_some_and(|receipt| !receipt.aliases.is_empty())
        {
            bail!("workload launcher receipt contains undeclared aliases");
        }
    } else {
        let receipt = workload_receipt
            .as_ref()
            .context("workload launcher receipt is not installed")?;
        if receipt.executable != executable.display().to_string() || receipt.aliases != aliases {
            bail!("workload launcher receipt does not match the resolved policy");
        }
        for alias in &aliases {
            let path = home.join(".local/bin").join(alias);
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("inspect workload launcher {}", path.display()))?;
            if !metadata.file_type().is_symlink() || fs::read_link(&path)? != executable {
                bail!("workload launcher does not match its receipt");
            }
        }
    }

    let desired = desired_desktop_entries(home, workloads)?;
    let expected_digests = desired
        .iter()
        .map(|(name, content)| (name.clone(), format!("{:x}", Sha256::digest(content))))
        .collect::<BTreeMap<_, _>>();
    let desktop_receipt = read_desktop_entry_receipt(home, owner_uid)?;
    if expected_digests.is_empty() {
        if desktop_receipt
            .as_ref()
            .is_some_and(|receipt| !receipt.entries.is_empty())
        {
            bail!("desktop entry receipt contains undeclared entries");
        }
    } else {
        let receipt = desktop_receipt
            .as_ref()
            .context("desktop entry receipt is not installed")?;
        if receipt.entries != expected_digests {
            bail!("desktop entry receipt does not match the resolved policy");
        }
        let directory = desktop_entry_directory(home);
        let directory_metadata =
            fs::symlink_metadata(&directory).context("inspect desktop entry directory")?;
        if !directory_metadata.file_type().is_dir()
            || directory_metadata.file_type().is_symlink()
            || directory_metadata.uid() != owner_uid
            || directory_metadata.mode() & 0o022 != 0
        {
            bail!("desktop entry directory has unsafe authority");
        }
        for (name, content) in &desired {
            let path = directory.join(name);
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("inspect desktop workload entry {}", path.display()))?;
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != owner_uid
                || metadata.mode() & 0o022 != 0
                || fs::read(&path)? != *content
            {
                bail!("desktop workload entry does not match its receipt");
            }
        }
    }

    Ok(UserIntegrationReport {
        schema: "dev-auth-user-integration-report-v1".into(),
        workload_launchers_ready: true,
        desktop_entries_ready: true,
    })
}

fn desired_desktop_entries(
    home: &Path,
    workloads: &BTreeMap<String, crate::policy_v2::ResolvedWorkload>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let bin = home.join(".local/bin");
    workloads
        .iter()
        .filter_map(|(name, workload)| {
            workload.desktop.as_ref().map(|desktop| {
                let launcher = bin.join(name);
                let launcher = launcher
                    .to_str()
                    .context("desktop workload launcher path is not UTF-8")?;
                let mut content = format!(
                    "[Desktop Entry]\nType=Application\nVersion=1.0\nName={}\nExec={}\nTerminal={}\nCategories=Development;\nX-Dev-Auth-Workload={}\n",
                    desktop.display_name.replace('\\', "\\\\"),
                    quote_desktop_exec_token(launcher)?,
                    if desktop.terminal { "true" } else { "false" },
                    name,
                );
                if let Some(icon) = &desktop.icon {
                    content.push_str(&format!("Icon={icon}\n"));
                }
                Ok((format!("dev-auth-{name}.desktop"), content.into_bytes()))
            })
        })
        .collect()
}

fn quote_desktop_exec_token(value: &str) -> Result<String> {
    if value.is_empty() || value.chars().any(char::is_control) {
        bail!("desktop workload launcher path is invalid");
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        if matches!(character, '\\' | '"' | '`' | '$') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    Ok(quoted)
}

fn preflight_desktop_entries_at(
    home: &Path,
    workloads: &BTreeMap<String, crate::policy_v2::ResolvedWorkload>,
    owner_uid: u32,
) -> Result<()> {
    let desired = desired_desktop_entries(home, workloads)?;
    let directory = desktop_entry_directory(home);
    if directory.exists() {
        let metadata =
            fs::symlink_metadata(&directory).context("inspect desktop entry directory")?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != owner_uid
            || metadata.mode() & 0o022 != 0
        {
            bail!("desktop entry directory has unsafe authority");
        }
    }
    let previous = read_desktop_entry_receipt(home, owner_uid)?;
    for (name, content) in &desired {
        let path = directory.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                let current = fs::read(&path)?;
                let current_digest = format!("{:x}", Sha256::digest(&current));
                let owned = metadata.file_type().is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == owner_uid
                    && metadata.mode() & 0o022 == 0
                    && (current == *content
                        || previous
                            .as_ref()
                            .and_then(|receipt| receipt.entries.get(name))
                            == Some(&current_digest));
                if !owned {
                    bail!("refusing to replace an unowned desktop workload entry");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect desktop workload entry"),
        }
    }
    Ok(())
}

pub fn reconcile_desktop_entries_at(
    home: &Path,
    workloads: &BTreeMap<String, crate::policy_v2::ResolvedWorkload>,
    owner_uid: u32,
) -> Result<()> {
    preflight_desktop_entries_at(home, workloads, owner_uid)?;
    let desired = desired_desktop_entries(home, workloads)?;
    let directory = desktop_entry_directory(home);
    let previous = read_desktop_entry_receipt(home, owner_uid)?;
    if desired.is_empty() && previous.is_none() {
        return Ok(());
    }
    ensure_directory_chain_for_owner(&directory, owner_uid, 0o755)?;
    if let Some(previous) = &previous {
        for (name, digest) in previous
            .entries
            .iter()
            .filter(|(name, _)| !desired.contains_key(*name))
        {
            let path = directory.join(name);
            match fs::symlink_metadata(&path) {
                Ok(metadata)
                    if metadata.file_type().is_file()
                        && !metadata.file_type().is_symlink()
                        && metadata.uid() == owner_uid
                        && format!("{:x}", Sha256::digest(fs::read(&path)?)) == *digest =>
                {
                    fs::remove_file(path).context("remove retired desktop workload entry")?
                }
                Ok(_) => bail!("refusing to remove a drifted desktop workload entry"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("inspect retired desktop workload entry"),
            }
        }
    }
    let mut entry_digests = BTreeMap::new();
    for (name, content) in desired {
        let path = directory.join(&name);
        if fs::read(&path).ok().as_deref() != Some(content.as_slice()) {
            write_public_user_file(&path, &content, owner_uid, 0o644, "desktop workload entry")?;
        }
        entry_digests.insert(name, format!("{:x}", Sha256::digest(&content)));
    }
    let receipt_path = desktop_entry_receipt_path(home);
    if entry_digests.is_empty() {
        match fs::remove_file(&receipt_path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("remove empty desktop entry receipt"),
        }
    }
    let receipt = DesktopEntryReceipt {
        schema: DESKTOP_ENTRY_RECEIPT_SCHEMA.into(),
        entries: entry_digests,
    };
    let bytes = serde_json::to_vec_pretty(&receipt).context("serialize desktop entry receipt")?;
    ensure_directory_chain_for_owner(
        receipt_path
            .parent()
            .context("desktop entry receipt has no parent")?,
        owner_uid,
        0o755,
    )?;
    write_owned_public_document(
        &receipt_path,
        &bytes,
        owner_uid,
        0o600,
        "desktop entry receipt",
    )
}

fn write_public_user_file(
    path: &Path,
    content: &[u8],
    owner_uid: u32,
    mode: u32,
    description: &str,
) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{description} has no parent"))?;
    ensure_directory_chain_for_owner(parent, owner_uid, 0o755)?;
    let temporary = path.with_extension(format!("new-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("create temporary {description}"))?;
    file.write_all(content)
        .with_context(|| format!("write {description}"))?;
    file.sync_all()
        .with_context(|| format!("sync {description}"))?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))
        .with_context(|| format!("set {description} permissions"))?;
    set_owner_if_root(&temporary, owner_uid)?;
    match fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(error).with_context(|| format!("publish {description}"))
        }
    }
}

fn read_desktop_entry_receipt(home: &Path, owner_uid: u32) -> Result<Option<DesktopEntryReceipt>> {
    let path = desktop_entry_receipt_path(home);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect desktop entry receipt"),
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o077 != 0
        || metadata.len() > RECEIPT_LIMIT
    {
        bail!("desktop entry receipt has unsafe authority");
    }
    let receipt: DesktopEntryReceipt =
        serde_json::from_slice(&fs::read(path)?).context("parse desktop entry receipt")?;
    if receipt.schema != DESKTOP_ENTRY_RECEIPT_SCHEMA
        || receipt.entries.keys().any(|name| {
            !name.starts_with("dev-auth-")
                || !name.ends_with(".desktop")
                || name.contains(['/', '\\'])
        })
        || receipt.entries.values().any(|digest| {
            digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        bail!("desktop entry receipt is invalid");
    }
    Ok(Some(receipt))
}

fn preflight_workload_launchers_at(
    home: &Path,
    executable: &Path,
    aliases: &[String],
    owner_uid: u32,
) -> Result<()> {
    validate_workload_alias_names(aliases)?;
    validate_native_program(executable, "workload broker executable")?;
    let bin_dir = home.join(".local/bin");
    if bin_dir.exists() {
        let metadata =
            fs::symlink_metadata(&bin_dir).context("inspect workload launcher directory")?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != owner_uid
            || metadata.mode() & 0o022 != 0
        {
            bail!("workload launcher directory has unsafe authority");
        }
    }
    let previous = read_workload_alias_receipt(home, owner_uid)?;
    for alias in aliases {
        let path = bin_dir.join(alias);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                let owned = metadata.file_type().is_symlink()
                    && (fs::read_link(&path).ok().as_deref() == Some(executable)
                        || previous.as_ref().is_some_and(|receipt| {
                            receipt.aliases.contains(alias)
                                && fs::read_link(&path).ok().as_deref()
                                    == Some(Path::new(&receipt.executable))
                        }));
                if !owned {
                    bail!(
                        "refusing to replace an unowned workload launcher: {}",
                        path.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect workload launcher"),
        }
    }
    Ok(())
}

pub fn reconcile_workload_launchers_at(
    home: &Path,
    executable: &Path,
    aliases: &[String],
    owner_uid: u32,
) -> Result<()> {
    preflight_workload_launchers_at(home, executable, aliases, owner_uid)?;
    let bin_dir = home.join(".local/bin");
    ensure_directory_chain_for_owner(&bin_dir, owner_uid, 0o755)?;
    let previous = read_workload_alias_receipt(home, owner_uid)?;
    if let Some(previous) = &previous {
        for alias in previous
            .aliases
            .iter()
            .filter(|alias| !aliases.contains(alias))
        {
            let path = bin_dir.join(alias);
            match fs::symlink_metadata(&path) {
                Ok(_) => remove_owned_alias(&path, Path::new(&previous.executable))?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("inspect retired workload launcher"),
            }
        }
    }
    for alias in aliases {
        let path = bin_dir.join(alias);
        if fs::read_link(&path).ok().as_deref() == Some(executable) {
            continue;
        }
        let temporary = path.with_extension(format!("new-{}", std::process::id()));
        symlink(executable, &temporary).context("stage workload launcher")?;
        if let Err(error) = fs::rename(&temporary, &path) {
            let _ = fs::remove_file(&temporary);
            return Err(error).context("publish workload launcher");
        }
    }
    let receipt = WorkloadAliasReceipt {
        schema: WORKLOAD_ALIAS_RECEIPT_SCHEMA.into(),
        executable: executable.display().to_string(),
        aliases: aliases.to_vec(),
    };
    let bytes = serde_json::to_vec_pretty(&receipt).context("serialize workload alias receipt")?;
    let path = workload_alias_receipt_path(home);
    let parent = path
        .parent()
        .context("workload alias receipt has no parent")?;
    ensure_directory_chain_for_owner(parent, owner_uid, 0o755)?;
    write_owned_public_document(&path, &bytes, owner_uid, 0o600, "workload alias receipt")
}

fn write_owned_public_document(
    path: &Path,
    content: &[u8],
    owner_uid: u32,
    mode: u32,
    description: &str,
) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{description} path has no parent"))?;
    ensure_directory_chain_for_owner(parent, owner_uid, 0o755)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != owner_uid
                || metadata.mode() & 0o777 != mode
            {
                bail!("{description} has unsafe replacement authority");
            }
            if fs::read(path)? == content {
                return Ok(());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("inspect {description}")),
    }
    let temporary = path.with_extension(format!("new-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("create temporary {description}"))?;
    if let Err(error) = (|| -> Result<()> {
        file.write_all(content)?;
        file.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
        set_owner_if_root(&temporary, owner_uid)?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })() {
        let _ = fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("publish {description}"));
    }
    Ok(())
}

fn read_workload_alias_receipt(
    home: &Path,
    owner_uid: u32,
) -> Result<Option<WorkloadAliasReceipt>> {
    let path = workload_alias_receipt_path(home);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect workload alias receipt"),
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o077 != 0
        || metadata.len() > RECEIPT_LIMIT
    {
        bail!("workload alias receipt has unsafe authority");
    }
    let bytes = fs::read(&path).context("read workload alias receipt")?;
    let receipt: WorkloadAliasReceipt =
        serde_json::from_slice(&bytes).context("parse workload alias receipt")?;
    if receipt.schema != WORKLOAD_ALIAS_RECEIPT_SCHEMA {
        bail!("workload alias receipt schema is unsupported");
    }
    validate_workload_alias_names(&receipt.aliases)?;
    Ok(Some(receipt))
}

fn validate_workload_alias_names(aliases: &[String]) -> Result<()> {
    if aliases.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("workload launcher aliases must be sorted and unique");
    }
    for alias in aliases {
        if alias.is_empty()
            || alias.len() > 64
            || !alias.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
            || PRODUCT_ALIASES.contains(&alias.as_str())
            || TRANSPARENT_ALIASES.contains(&alias.as_str())
            || alias == "dev-auth-workload-launcher"
        {
            bail!("workload launcher alias is invalid or reserved");
        }
    }
    Ok(())
}

pub fn resolve_current_workload_alias(alias: &str) -> Result<crate::policy_v2::ResolvedWorkload> {
    let owner_uid = nix::unistd::Uid::effective().as_raw();
    if owner_uid == 0 {
        bail!("workload launcher alias must run as its native user");
    }
    validate_workload_alias_names(&[alias.to_owned()])?;
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
        .context("native user account does not exist")?;
    let (_, installation) = current_installation()?;
    let executable = PathBuf::from(&installation.executable);
    let receipt = read_workload_alias_receipt(&user.dir, owner_uid)?
        .context("workload launcher receipt is not installed")?;
    if !receipt.aliases.iter().any(|value| value == alias)
        || Path::new(&receipt.executable) != executable
    {
        bail!("workload launcher is outside the installed alias set");
    }
    let path = user.dir.join(".local/bin").join(alias);
    let metadata = fs::symlink_metadata(&path).context("inspect current workload launcher")?;
    if !metadata.file_type().is_symlink() || fs::read_link(&path)? != executable {
        bail!("current workload launcher does not match its receipt");
    }
    let policy = match installation.mode {
        InstallMode::Strong => crate::policy_store::load_resolved_policy_for_uid(owner_uid)?,
        InstallMode::UserOnly => {
            crate::policy_store::load_user_only_resolved_policy_for_uid(owner_uid)?
        }
    };
    policy
        .workloads
        .get(alias)
        .cloned()
        .context("workload launcher is absent from the resolved user policy")
}

fn read_approved_public_document(source: &Path, approved_sha256: &str) -> Result<Vec<u8>> {
    if !source.is_absolute()
        || approved_sha256.len() != 64
        || !approved_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("public configuration source or digest is invalid");
    }
    let metadata = fs::symlink_metadata(source).context("inspect public configuration source")?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > POLICY_LIMIT
    {
        bail!("public configuration source is unsafe");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(source)
        .context("open public configuration source")?
        .take(POLICY_LIMIT + 1)
        .read_to_end(&mut bytes)
        .context("read public configuration source")?;
    if bytes.len() as u64 > POLICY_LIMIT
        || format!("{:x}", Sha256::digest(&bytes)) != approved_sha256.to_ascii_lowercase()
    {
        bail!("public configuration does not match the approved digest");
    }
    Ok(bytes)
}

fn validate_system_policy_programs(policy: &crate::policy_v2::SystemPolicyV2) -> Result<()> {
    if policy.mode != crate::policy_v2::SystemMode::Strong {
        bail!("administrator policy document has the wrong mode");
    }
    for (path, description) in [
        (&policy.programs.op, "1Password CLI"),
        (&policy.programs.git, "Git"),
        (&policy.programs.gh, "GitHub CLI"),
        (&policy.programs.ssh, "SSH"),
        (&policy.programs.ssh_keygen, "ssh-keygen"),
    ] {
        validate_root_owned_executable(Path::new(path), description)?;
    }
    for path in policy.trusted_launchers.values() {
        validate_root_owned_executable(Path::new(path), "trusted workload launcher")?;
    }
    for adapter in policy.sandbox_adapters.values() {
        validate_root_owned_executable(
            Path::new(&adapter.executable),
            "sandbox adapter executable",
        )?;
    }
    Ok(())
}

fn validate_user_policy_programs(
    policy: &crate::policy_v2::SystemPolicyV2,
    user: &nix::unistd::User,
    owner_uid: u32,
) -> Result<()> {
    if policy.mode != crate::policy_v2::SystemMode::UserOnly {
        bail!("user-only policy document has the wrong mode");
    }
    if !policy
        .allowed_users
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&user.name))
    {
        bail!("user-only policy does not admit the native user");
    }
    for (path, description) in [
        (&policy.programs.op, "1Password CLI"),
        (&policy.programs.git, "Git"),
        (&policy.programs.gh, "GitHub CLI"),
        (&policy.programs.ssh, "SSH"),
        (&policy.programs.ssh_keygen, "ssh-keygen"),
    ] {
        validate_user_or_root_executable(Path::new(path), owner_uid, description)?;
    }
    for path in policy.trusted_launchers.values() {
        validate_user_or_root_executable(Path::new(path), owner_uid, "trusted workload launcher")?;
    }
    for adapter in policy.sandbox_adapters.values() {
        validate_user_or_root_executable(
            Path::new(&adapter.executable),
            owner_uid,
            "sandbox adapter executable",
        )?;
    }
    Ok(())
}

fn preflight_user_config_destination(
    destination: &Path,
    new_bytes: &[u8],
    current_sha256: Option<&str>,
    owner_uid: u32,
    system_policy: &crate::policy_v2::SystemPolicyV2,
    native_user: &str,
    resolve_current_workloads: bool,
) -> Result<BTreeMap<String, crate::policy_v2::ResolvedWorkload>> {
    match fs::symlink_metadata(destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if current_sha256.is_some() {
                bail!("user configuration update has no current document");
            }
            Ok(BTreeMap::new())
        }
        Err(error) => Err(error).context("inspect current user configuration"),
        Ok(_) => {
            let current = crate::policy_store::load_user_config_at(destination, owner_uid)?;
            let current_bytes = fs::read(destination).context("read current user configuration")?;
            match current_sha256 {
                Some(_) if current_bytes == new_bytes => {}
                Some(expected) => validate_current_digest(&current_bytes, expected)?,
                None if current_bytes == new_bytes => {}
                None => bail!("user configuration already exists; use a digest-bound update"),
            }
            if resolve_current_workloads {
                Ok(
                    crate::policy_v2::resolve_policy_for_user(
                        system_policy,
                        native_user,
                        &current,
                    )?
                    .workloads,
                )
            } else {
                Ok(BTreeMap::new())
            }
        }
    }
}

fn validate_current_digest(bytes: &[u8], expected: &str) -> Result<()> {
    if expected.len() != 64
        || !expected.bytes().all(|byte| byte.is_ascii_hexdigit())
        || format!("{:x}", Sha256::digest(bytes)) != expected.to_ascii_lowercase()
    {
        bail!("current configuration does not match the approved replacement digest");
    }
    Ok(())
}

fn replace_policy_document(
    destination: &Path,
    bytes: &[u8],
    owner_uid: u32,
    mode: u32,
    current_sha256: &str,
) -> Result<()> {
    let metadata = fs::symlink_metadata(destination)
        .with_context(|| format!("inspect configuration document {}", destination.display()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != mode
        || metadata.len() > POLICY_LIMIT
    {
        bail!("configuration document has unsafe replacement authority");
    }
    let current = fs::read(destination).context("read current configuration document")?;
    validate_current_digest(&current, current_sha256)?;
    if current == bytes {
        return Ok(());
    }
    let parent = destination
        .parent()
        .context("configuration destination has no parent")?;
    let temporary = destination.with_extension(format!("new-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .context("create replacement configuration document")?;
    if let Err(error) = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
        fs::rename(&temporary, destination)?;
        File::open(parent)?.sync_all()
    })() {
        let _ = fs::remove_file(&temporary);
        return Err(error).context("publish replacement configuration document");
    }
    Ok(())
}

fn install_policy_document(
    destination: &Path,
    bytes: &[u8],
    owner_uid: u32,
    mode: u32,
) -> Result<()> {
    let parent = destination
        .parent()
        .context("configuration destination has no parent")?;
    ensure_directory_chain_for_owner(parent, owner_uid, 0o755)?;
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != owner_uid
                || metadata.mode() & 0o777 != mode
                || fs::read(destination)? != bytes
            {
                bail!("refusing to overwrite a drifted configuration document");
            }
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect configuration destination"),
    }
    let temporary = destination.with_extension(format!("new-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .context("create configuration document")?;
    file.write_all(bytes)
        .context("write configuration document")?;
    file.sync_all().context("sync configuration document")?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))
        .context("set configuration document permissions")?;
    set_owner_if_root(&temporary, owner_uid)?;
    fs::rename(&temporary, destination).context("publish configuration document")
}

#[cfg(test)]
fn enroll_system_service_credential_at(
    systemd_creds: &Path,
    destination: &Path,
    value: &[u8],
    owner_uid: u32,
) -> Result<()> {
    store_system_service_credential_at(
        systemd_creds,
        destination,
        "automation",
        value,
        owner_uid,
        false,
    )
}

fn store_system_service_credential_at(
    systemd_creds: &Path,
    destination: &Path,
    slot: &str,
    value: &[u8],
    owner_uid: u32,
    replace: bool,
) -> Result<()> {
    validate_native_program(systemd_creds, "systemd-creds")?;
    validate_credential_slot(slot)?;
    if value.is_empty()
        || value.len() as u64 > RECEIPT_LIMIT
        || value.contains(&b'\0')
        || value
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .count()
            != 1
    {
        bail!("service credential must be exactly one bounded nonempty line");
    }
    let parent = destination
        .parent()
        .context("system credential path has no parent")?;
    ensure_directory_chain_for_owner(parent, owner_uid, 0o700)?;
    let parent_metadata =
        fs::symlink_metadata(parent).context("inspect private system credential directory")?;
    if parent_metadata.mode() & 0o077 != 0 {
        bail!("system credential directory is not private");
    }
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if !replace {
                bail!("system service credential already exists; use the rotation workflow");
            }
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != owner_uid
                || metadata.mode() & 0o077 != 0
                || metadata.len() == 0
                || metadata.len() > BINARY_LIMIT
            {
                bail!("system service credential has unsafe rotation authority");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && replace => {
            bail!("system service credential is not enrolled")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect system service credential"),
    }
    let temporary = destination.with_extension(format!("new-{}", std::process::id()));
    let credential_name = format!("--name=op-service-account-token_{slot}");
    let mut child = Command::new(systemd_creds)
        .args([
            "encrypt",
            &credential_name,
            "-",
            temporary
                .to_str()
                .context("system credential path is not UTF-8")?,
        ])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("start systemd credential encryption")?;
    let write_result = child
        .stdin
        .take()
        .context("systemd credential encryption has no stdin")?
        .write_all(value);
    let status = child
        .wait()
        .context("wait for systemd credential encryption")?;
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(error).context("write service credential to encryption pipe");
    }
    if !status.success() {
        let _ = fs::remove_file(&temporary);
        bail!("systemd credential encryption failed");
    }
    let initial_metadata =
        fs::symlink_metadata(&temporary).context("inspect encrypted system service credential")?;
    if !initial_metadata.file_type().is_file()
        || initial_metadata.file_type().is_symlink()
        || initial_metadata.uid() != owner_uid
        || initial_metadata.len() == 0
        || initial_metadata.len() > BINARY_LIMIT
    {
        let _ = fs::remove_file(&temporary);
        bail!("encrypted system service credential is unsafe");
    }
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
        .context("protect encrypted system service credential")?;
    fs::rename(&temporary, destination).context("publish encrypted system service credential")?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("sync encrypted system service credential directory")
}

fn ensure_directory_chain_for_owner(path: &Path, owner_uid: u32, mode: u32) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect credential directory {}", path.display()))?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != owner_uid
            || metadata.mode() & 0o022 != 0
        {
            bail!("system credential directory has unsafe authority");
        }
        return Ok(());
    }
    let parent = path
        .parent()
        .context("credential directory has no parent")?;
    ensure_directory_chain_for_owner(parent, owner_uid, mode)?;
    fs::create_dir(path).with_context(|| format!("create {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("set permissions on {}", path.display()))?;
    set_owner_if_root(path, owner_uid)?;
    Ok(())
}

fn set_owner_if_root(path: &Path, owner_uid: u32) -> Result<()> {
    let current = fs::symlink_metadata(path)
        .with_context(|| format!("inspect owned path {}", path.display()))?
        .uid();
    if current == owner_uid {
        return Ok(());
    }
    if !nix::unistd::Uid::effective().is_root() {
        bail!("created path does not belong to the native user");
    }
    nix::unistd::chown(path, Some(nix::unistd::Uid::from_raw(owner_uid)), None)
        .with_context(|| format!("assign native ownership to {}", path.display()))
}

fn system_asset_digests() -> BTreeMap<String, String> {
    linux_system_assets()
        .into_iter()
        .map(|(path, content, _)| {
            (
                path.display().to_string(),
                format!("{:x}", Sha256::digest(content.as_bytes())),
            )
        })
        .collect()
}

fn install_linux_system_assets(prior_receipt: Option<&InstallReceipt>) -> Result<()> {
    for (path, content, mode) in linux_system_assets() {
        let parent = path.parent().context("system asset path has no parent")?;
        ensure_directory_chain(parent, InstallMode::Strong)?;
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != 0
                    || metadata.mode() & 0o777 != mode
                {
                    bail!(
                        "refusing to replace a drifted system asset: {}",
                        path.display()
                    );
                }
                let existing = fs::read(path)?;
                if existing == content.as_bytes() {
                    continue;
                }
                let existing_digest = format!("{:x}", Sha256::digest(&existing));
                let prior_owned = prior_receipt.is_some_and(|receipt| {
                    receipt.system_assets.get(&path.display().to_string()) == Some(&existing_digest)
                });
                if !prior_owned {
                    bail!(
                        "refusing to replace a drifted system asset: {}",
                        path.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect dev-auth system asset"),
        }
        let temporary = path.with_extension(format!("new-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .context("create dev-auth system asset")?;
        file.write_all(content.as_bytes())
            .context("write dev-auth system asset")?;
        file.sync_all().context("sync dev-auth system asset")?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))
            .context("set dev-auth system asset permissions")?;
        fs::rename(&temporary, path).context("publish dev-auth system asset")?;
    }
    Ok(())
}

fn verify_linux_system_assets() -> Result<()> {
    for (path, content, mode) in linux_system_assets() {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect dev-auth system asset {}", path.display()))?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != mode
            || fs::read(path)? != content.as_bytes()
        {
            bail!("dev-auth system asset does not match product policy");
        }
    }
    Ok(())
}

fn discover_native_program(
    candidates: &[&Path],
    description: &str,
    managed_bin_dir: &Path,
) -> Result<PathBuf> {
    for candidate in candidates {
        if candidate.starts_with(managed_bin_dir) {
            continue;
        }
        if validate_native_program(candidate, description).is_ok() {
            return Ok((*candidate).to_path_buf());
        }
    }
    bail!("{description} was not found at an approved system path")
}

fn validate_plan(plan: &SetupPlan) -> Result<()> {
    if plan.schema != "dev-auth-setup-plan-v2" {
        bail!("dev-auth setup plan schema is unsupported");
    }
    if plan.source_length == 0
        || plan.source_length > BINARY_LIMIT
        || plan.source_sha256.len() != 64
        || !plan
            .source_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("dev-auth setup plan contains an invalid source identity");
    }
    if let Some(release) = &plan.verified_release {
        let reverified = crate::release_manifest::verify_dev_auth_release(
            &release.root_path,
            &release.manifest_path,
            &release.artifact_path,
        )?;
        if &reverified != release
            || release.schema != "dev-auth-verified-release-v1"
            || release.version != plan.request.version
            || release.artifact_path != plan.request.source_executable
            || release.artifact_length != plan.source_length
            || release.artifact_sha256 != plan.source_sha256
            || release.manifest_generation == 0
            || release.root_generation == 0
        {
            bail!("verified release identity does not match the setup plan");
        }
    }
    validate_install_request(&plan.paths, &plan.request)
}

fn validate_version(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || value.starts_with(['.', '-'])
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        bail!("dev-auth version is invalid");
    }
    Ok(())
}

fn ensure_directory_chain(path: &Path, mode: InstallMode) -> Result<()> {
    if path.exists() {
        validate_directory(path, mode)?;
        return Ok(());
    }
    let parent = path.parent().context("setup directory has no parent")?;
    if !parent.exists() {
        ensure_directory_chain(parent, mode)?;
    } else {
        validate_directory(parent, mode)?;
    }
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).with_context(|| format!("create {}", path.display())),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("set permissions on {}", path.display()))?;
    validate_directory(path, mode)
}

fn validate_directory(path: &Path, mode: InstallMode) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect setup directory {}", path.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!(
            "setup directory is not a real directory: {}",
            path.display()
        );
    }
    let expected_uid = match mode {
        InstallMode::Strong => 0,
        InstallMode::UserOnly => nix::unistd::Uid::effective().as_raw(),
    };
    if metadata.uid() != expected_uid {
        bail!("setup directory has the wrong owner: {}", path.display());
    }
    if metadata.mode() & 0o022 != 0 {
        bail!(
            "setup directory is group- or world-writable: {}",
            path.display()
        );
    }
    Ok(())
}

fn validate_native_program(path: &Path, description: &str) -> Result<()> {
    if !path.is_absolute() {
        bail!("{description} path must be absolute");
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {description} at {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("{description} must be a regular non-symlink file");
    }
    if metadata.mode() & 0o111 == 0 {
        bail!("{description} is not executable");
    }
    if metadata.mode() & 0o022 != 0 {
        bail!("{description} is group- or world-writable");
    }
    Ok(())
}

pub(crate) fn validate_root_owned_executable(path: &Path, description: &str) -> Result<()> {
    validate_native_program(path, description)?;
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("inspect {description} path {}", current.display()))?;
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            bail!("{description} path is not root-owned immutable authority");
        }
    }
    Ok(())
}

pub(crate) fn validate_user_or_root_executable(
    path: &Path,
    owner_uid: u32,
    description: &str,
) -> Result<()> {
    validate_native_program(path, description)?;
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("inspect {description} path {}", current.display()))?;
        if metadata.file_type().is_symlink()
            || (metadata.uid() != 0 && metadata.uid() != owner_uid)
            || metadata.mode() & 0o022 != 0
        {
            bail!("{description} path is outside the user-only trust boundary");
        }
    }
    Ok(())
}

fn install_privileged_launcher(
    executable: &Path,
    launcher: &Path,
    paths: &SetupPaths,
) -> Result<()> {
    if launcher != Path::new(PRIVILEGED_LAUNCHER_PATH)
        || launcher.parent() != Some(paths.data_root.as_path())
    {
        bail!("privileged launcher path is outside the strong product root");
    }
    let executable_metadata = fs::symlink_metadata(executable)
        .context("inspect versioned executable for privileged launcher")?;
    if executable_metadata.uid() != 0 || executable_metadata.nlink() != 1 {
        bail!("privileged launcher source is not root-owned");
    }
    let executable_identity = file_identity(executable)?;
    match fs::symlink_metadata(launcher) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.mode() & 0o777 != 0o755
                || metadata.nlink() != 1
            {
                bail!("privileged workload launcher has unsafe authority");
            }
            if file_identity(launcher)? == executable_identity {
                return Ok(());
            }
            let prior = read_receipt(&paths.receipt_path())?;
            let prior_executable = PathBuf::from(&prior.executable);
            if prior.mode != InstallMode::Strong
                || prior.privileged_launcher.as_deref() != launcher.to_str()
                || file_identity(launcher)?
                    != (prior.executable_length, prior.executable_sha256.clone())
                || file_identity(&prior_executable)?
                    != (prior.executable_length, prior.executable_sha256.clone())
            {
                bail!("refusing to replace an unowned privileged workload launcher");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect privileged workload launcher"),
    }
    let temporary = launcher.with_extension(format!("new-{}", std::process::id()));
    stage_executable_copy(executable, &temporary, &executable_identity)?;
    if let Err(error) = fs::rename(&temporary, launcher) {
        let _ = fs::remove_file(&temporary);
        return Err(error).context("publish privileged workload launcher");
    }
    verify_privileged_launcher_copy(executable, launcher)
}

fn detach_legacy_privileged_launcher(executable: &Path, receipt: &InstallReceipt) -> Result<()> {
    if receipt.mode != InstallMode::Strong
        || receipt.privileged_launcher.as_deref() != Some(PRIVILEGED_LAUNCHER_PATH)
        || Path::new(&receipt.executable) != executable
    {
        bail!("legacy privileged launcher receipt is invalid");
    }
    let launcher = Path::new(PRIVILEGED_LAUNCHER_PATH);
    let executable_metadata =
        fs::symlink_metadata(executable).context("inspect legacy versioned executable")?;
    let launcher_metadata =
        fs::symlink_metadata(launcher).context("inspect legacy privileged launcher")?;
    if !launcher_metadata.file_type().is_file()
        || launcher_metadata.file_type().is_symlink()
        || launcher_metadata.uid() != 0
        || launcher_metadata.mode() & 0o777 != 0o755
        || file_identity(executable)?
            != (receipt.executable_length, receipt.executable_sha256.clone())
        || file_identity(launcher)?
            != (receipt.executable_length, receipt.executable_sha256.clone())
    {
        bail!("legacy privileged launcher does not match its receipt");
    }
    if !same_file_identity(&launcher_metadata, &executable_metadata) {
        if executable_metadata.nlink() != 1 || launcher_metadata.nlink() != 1 {
            bail!("legacy privileged launcher has unexpected link authority");
        }
        return Ok(());
    }
    if executable_metadata.nlink() != 2 {
        bail!("legacy privileged launcher has unexpected hardlink authority");
    }
    let temporary = launcher.with_extension(format!("detach-{}", std::process::id()));
    stage_executable_copy(
        executable,
        &temporary,
        &(receipt.executable_length, receipt.executable_sha256.clone()),
    )?;
    if let Err(error) = fs::rename(&temporary, launcher) {
        let _ = fs::remove_file(&temporary);
        return Err(error).context("detach legacy privileged launcher hardlink");
    }
    verify_privileged_launcher_copy(executable, launcher)
}

fn stage_executable_copy(source: &Path, temporary: &Path, expected: &(u64, String)) -> Result<()> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(source)
        .context("open executable copy source")?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(temporary)
        .context("create executable copy temporary")?;
    std::io::copy(&mut input, &mut output).context("copy executable")?;
    output.sync_all().context("sync executable copy")?;
    fs::set_permissions(temporary, fs::Permissions::from_mode(0o755))
        .context("protect executable copy")?;
    if &file_identity(temporary)? != expected {
        let _ = fs::remove_file(temporary);
        bail!("executable copy changed before publication");
    }
    Ok(())
}

fn verify_privileged_launcher(executable: &Path, receipt: &InstallReceipt) -> Result<()> {
    if receipt.mode != InstallMode::Strong
        || receipt.privileged_launcher.as_deref() != Some(PRIVILEGED_LAUNCHER_PATH)
    {
        bail!("strong installation receipt does not own the privileged launcher");
    }
    verify_privileged_launcher_copy(executable, Path::new(PRIVILEGED_LAUNCHER_PATH))
}

fn verify_privileged_launcher_copy(source: &Path, target: &Path) -> Result<()> {
    let source_metadata =
        fs::symlink_metadata(source).context("inspect privileged launcher source")?;
    let target_metadata =
        fs::symlink_metadata(target).context("inspect privileged workload launcher")?;
    if !target_metadata.file_type().is_file()
        || target_metadata.file_type().is_symlink()
        || target_metadata.uid() != 0
        || target_metadata.mode() & 0o777 != 0o755
        || target_metadata.nlink() != 1
        || source_metadata.nlink() != 1
        || file_identity(source)? != file_identity(target)?
    {
        bail!("privileged workload launcher does not match the receipt-owned executable");
    }
    Ok(())
}

fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn install_aliases(
    bin_dir: &Path,
    executable: &Path,
    aliases: &[&str],
    prior_receipt: Option<&InstallReceipt>,
) -> Result<()> {
    for name in aliases {
        let alias = bin_dir.join(name);
        match fs::symlink_metadata(&alias) {
            Ok(metadata) => {
                let target = fs::read_link(&alias).ok();
                let prior_owned = prior_receipt.is_some_and(|receipt| {
                    target.as_deref() == Some(Path::new(&receipt.executable))
                        && (receipt.product_aliases.iter().any(|value| value == name)
                            || receipt
                                .transparent_aliases
                                .iter()
                                .any(|value| value == name))
                });
                if !metadata.file_type().is_symlink()
                    || (target.as_deref() != Some(executable) && !prior_owned)
                {
                    bail!(
                        "refusing to replace an unowned launcher: {}",
                        alias.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("inspect launcher {}", alias.display()))
            }
        }
    }
    for name in aliases {
        let alias = bin_dir.join(name);
        if fs::read_link(&alias).ok().as_deref() == Some(executable) {
            continue;
        }
        let temporary = alias.with_extension(format!("new-{}", std::process::id()));
        symlink(executable, &temporary)
            .with_context(|| format!("stage launcher {}", alias.display()))?;
        if let Err(error) = fs::rename(&temporary, &alias) {
            let _ = fs::remove_file(&temporary);
            return Err(error).with_context(|| format!("install launcher {}", alias.display()));
        }
    }
    Ok(())
}

fn verify_exact_alias_set(
    bin_dir: &Path,
    executable: &Path,
    receipt_aliases: &[String],
    allowed_aliases: &[&str],
    allow_empty: bool,
) -> Result<()> {
    let expected: Vec<String> = allowed_aliases.iter().map(ToString::to_string).collect();
    if receipt_aliases != expected && !(allow_empty && receipt_aliases.is_empty()) {
        bail!("dev-auth installation receipt contains an unexpected alias");
    }
    for alias in receipt_aliases {
        let path = bin_dir.join(alias);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect launcher {}", path.display()))?;
        if !metadata.file_type().is_symlink() || fs::read_link(&path)? != executable {
            bail!(
                "dev-auth launcher does not match its receipt: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn remove_owned_alias(alias: &Path, executable: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(alias)
        .with_context(|| format!("inspect launcher {}", alias.display()))?;
    if !metadata.file_type().is_symlink() || fs::read_link(alias)? != executable {
        bail!("refusing to remove a launcher that is not receipt-owned");
    }
    fs::remove_file(alias).with_context(|| format!("remove launcher {}", alias.display()))
}

fn file_identity(path: &Path) -> Result<(u64, String)> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect executable {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("installed dev-auth executable is not a regular non-symlink file");
    }
    if metadata.mode() & 0o111 == 0 || metadata.mode() & 0o022 != 0 {
        bail!("installed dev-auth executable has unsafe permissions");
    }
    if metadata.len() > BINARY_LIMIT {
        bail!("installed dev-auth executable exceeds the size limit");
    }
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).context("hash dev-auth executable")?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok((metadata.len(), format!("{:x}", hasher.finalize())))
}

pub(crate) fn setup_executable_identity(path: &Path) -> Result<(u64, String)> {
    file_identity(path)
}

fn write_receipt(path: &Path, receipt: &InstallReceipt) -> Result<()> {
    let content = serde_json::to_vec_pretty(receipt).context("serialize install receipt")?;
    if content.len() as u64 > RECEIPT_LIMIT {
        bail!("dev-auth installation receipt exceeds the size limit");
    }
    let temporary = path.with_extension(format!("new-{}", std::process::id()));
    let mode = receipt_permissions(receipt.mode);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)
        .with_context(|| format!("create {}", temporary.display()))?;
    file.write_all(&content).context("write install receipt")?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .context("set install receipt permissions")?;
    file.sync_all().context("sync install receipt")?;
    match fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(error).context("publish install receipt")
        }
    }
}

fn read_receipt(path: &Path) -> Result<InstallReceipt> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect install receipt {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > RECEIPT_LIMIT
        || metadata.nlink() != 1
        || !receipt_mode_is_safe(metadata.mode())
    {
        bail!("dev-auth installation receipt is unsafe");
    }
    let mut input = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .context("open install receipt")?
        .take(RECEIPT_LIMIT + 1)
        .read_to_end(&mut input)
        .context("read install receipt")?;
    let receipt: InstallReceipt =
        serde_json::from_slice(&input).context("parse install receipt")?;
    let expected_owner = match receipt.mode {
        InstallMode::Strong => 0,
        InstallMode::UserOnly => nix::unistd::Uid::effective().as_raw(),
    };
    if metadata.uid() != expected_owner
        || !receipt_mode_matches_installation(metadata.mode(), receipt.mode)
    {
        bail!("dev-auth installation receipt has unsafe ownership or permissions");
    }
    Ok(receipt)
}

fn receipt_permissions(mode: InstallMode) -> u32 {
    match mode {
        InstallMode::Strong => 0o644,
        InstallMode::UserOnly => 0o600,
    }
}

fn receipt_mode_is_safe(mode: u32) -> bool {
    matches!(mode & 0o777, 0o600 | 0o644)
}

fn receipt_mode_matches_installation(mode: u32, installation_mode: InstallMode) -> bool {
    match installation_mode {
        InstallMode::Strong => matches!(mode & 0o777, 0o600 | 0o644),
        InstallMode::UserOnly => mode & 0o777 == 0o600,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_receipts_are_public_read_only_and_user_receipts_remain_private() {
        assert_eq!(receipt_permissions(InstallMode::Strong), 0o644);
        assert_eq!(receipt_permissions(InstallMode::UserOnly), 0o600);
        assert!(receipt_mode_is_safe(0o644));
        assert!(receipt_mode_is_safe(0o600));
        assert!(!receipt_mode_is_safe(0o664));
        assert!(!receipt_mode_is_safe(0o755));
        assert!(receipt_mode_matches_installation(
            0o600,
            InstallMode::Strong
        ));
        assert!(receipt_mode_matches_installation(
            0o644,
            InstallMode::Strong
        ));
        assert!(receipt_mode_matches_installation(
            0o600,
            InstallMode::UserOnly
        ));
        assert!(!receipt_mode_matches_installation(
            0o644,
            InstallMode::UserOnly
        ));
    }

    #[test]
    fn unprivileged_strong_readiness_uses_the_live_broker_as_credential_proof() {
        assert!(!readiness_requires_private_installation_verification(
            InstallMode::Strong,
            false
        ));
        assert!(readiness_requires_private_installation_verification(
            InstallMode::Strong,
            true
        ));
        assert!(readiness_requires_private_installation_verification(
            InstallMode::UserOnly,
            false
        ));
        assert_eq!(
            strong_runtime_readiness(false, false, false),
            (false, false, Some("run_privileged_setup_plan"))
        );
        assert_eq!(
            strong_runtime_readiness(true, false, false),
            (true, true, None)
        );
        assert_eq!(
            strong_runtime_readiness(false, true, false),
            (false, false, Some("enroll_system_credential"))
        );
        assert_eq!(
            strong_runtime_readiness(false, true, true),
            (true, false, Some("start_system_broker"))
        );
    }

    #[test]
    fn strong_backend_availability_includes_runtime_admission_blockers() {
        let runtime_blocker =
            prerequisite_blocker("cgroup_v2", DiscoveryStatus::Absent, "strong_admission");
        assert!(!strong_backend_available_from_blockers(&[runtime_blocker]));

        let account_manager =
            prerequisite_blocker("systemd_sysusers", DiscoveryStatus::Absent, "strong_setup");
        assert!(!strong_backend_available_from_blockers(&[account_manager]));

        let unrelated_blocker =
            prerequisite_blocker("git", DiscoveryStatus::Absent, "strong_setup");
        assert!(strong_backend_available_from_blockers(&[unrelated_blocker]));
    }

    #[test]
    fn workload_discovery_is_configuration_driven_and_has_no_product_names() {
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
            .unwrap()
            .unwrap();
        let root = tempfile::tempdir_in(&user.dir).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let launcher = root.path().join("future-agent");
        fs::write(&launcher, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
        let git = root.path().join("native-git");
        let gh = root.path().join("native-gh");
        let op = root.path().join("native-op");
        let ssh = root.path().join("native-ssh");
        let ssh_keygen = root.path().join("native-ssh-keygen");
        for program in [&git, &gh, &op, &ssh, &ssh_keygen] {
            fs::write(program, b"#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(program, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let policy = root.path().join("policy.toml");
        fs::write(
            &policy,
            format!(
                r#"version = 2
mode = "user_only"
allowed_users = ["{}"]

[programs]
op = "{}"
git = "{}"
gh = "{}"
ssh = "{}"
ssh_keygen = "{}"

[trusted_launchers]
future = "{}"

[github_apps]
[credential_slots]
[authority_caps]
[workspace_caps]
"#,
                user.name,
                op.display(),
                git.display(),
                gh.display(),
                ssh.display(),
                ssh_keygen.display(),
                launcher.display()
            ),
        )
        .unwrap();
        let config = root.path().join("config.toml");
        fs::write(
            &config,
            r#"version = 2

[[workloads]]
name = "future-agent"
launcher = "future"
profile = "unused"
secret_references = []
workspace_roots = []
desktop = { display_name = "Future Agent", terminal = false }

[workloads.sandbox]
mode = "none"
adapters = []
"#,
        )
        .unwrap();

        let empty = discover_setup(InstallMode::UserOnly).unwrap();
        assert!(empty.workload_launchers.is_empty());
        assert!(empty.desktop_entries.is_empty());

        let configured = discover_setup_with_configuration(
            InstallMode::UserOnly,
            Some(&policy),
            &[(user.name.clone(), config)],
        )
        .unwrap();
        assert_eq!(
            configured.workload_launchers[&format!("{}:future-agent", user.name)][0].status,
            DiscoveryStatus::Usable
        );
        assert_eq!(
            configured.programs["git"][0].path,
            git.display().to_string()
        );
        assert_eq!(configured.programs["op"][0].path, op.display().to_string());
        assert_eq!(
            configured.programs["ssh"][0].path,
            ssh.display().to_string()
        );
        assert_eq!(
            configured.desktop_entries[&format!("{}:future-agent", user.name)][0].status,
            DiscoveryStatus::Absent
        );
        assert!(!configured
            .blockers
            .iter()
            .any(|blocker| blocker.component.starts_with("workload_launcher:")));
        assert!(!configured.workload_launchers.contains_key("codex"));
        assert!(!configured.workload_launchers.contains_key("claude"));
    }

    #[test]
    fn v3_readiness_requires_both_private_tool_plane_and_global_transparent_launchers() {
        let mut setup = SetupReport {
            schema: "dev-auth-setup-report-v2".into(),
            mode: InstallMode::UserOnly,
            version: "0.3.0-test".into(),
            executable: "/opt/dev-auth/dev-auth".into(),
            native_git: "/usr/bin/git".into(),
            native_gh: "/usr/bin/gh".into(),
            product_aliases_ready: true,
            transparent_launchers_active: false,
        };
        let integrations = UserIntegrationReport {
            schema: "dev-auth-user-integration-v1".into(),
            workload_launchers_ready: true,
            desktop_entries_ready: true,
        };
        assert_eq!(
            v3_launcher_readiness(&setup, Some(&integrations)),
            (true, false)
        );
        setup.transparent_launchers_active = true;
        assert_eq!(
            v3_launcher_readiness(&setup, Some(&integrations)),
            (true, true)
        );
        assert_eq!(v3_launcher_readiness(&setup, None), (false, true));
    }

    #[test]
    fn full_identity_user_namespace_requires_systemd_257_or_newer() {
        assert_eq!(
            parse_systemd_major_version(b"systemd 257 (257.9)\n"),
            Some(257)
        );
        assert_eq!(parse_systemd_major_version(b"systemd 261\n"), Some(261));
        assert_eq!(parse_systemd_major_version(b"systemd 256\n"), Some(256));
        assert_eq!(parse_systemd_major_version(b"not-systemd 261\n"), None);
        assert_eq!(parse_systemd_major_version(b"systemd future\n"), None);
    }

    #[test]
    fn authenticated_installations_reject_unsigned_and_generation_rollback_updates() {
        let prior = InstallReceipt {
            schema: RECEIPT_SCHEMA.into(),
            mode: InstallMode::UserOnly,
            version: "0.3.0".into(),
            executable: "/opt/dev-auth/0.3.0/dev-auth".into(),
            bin_dir: "/opt/dev-auth/bin".into(),
            executable_length: 10,
            executable_sha256: "a".repeat(64),
            source_commit: Some("b".repeat(40)),
            root_generation: Some(4),
            manifest_generation: Some(10),
            native_git: "/usr/bin/git".into(),
            native_gh: "/usr/bin/gh".into(),
            product_aliases: Vec::new(),
            transparent_aliases: Vec::new(),
            privileged_launcher: None,
            system_assets: BTreeMap::new(),
            previous_release: None,
        };
        let mut request = InstallRequest {
            mode: InstallMode::UserOnly,
            version: "0.3.1".into(),
            source_executable: PathBuf::from("/opt/candidate/dev-auth"),
            native_git: PathBuf::from("/usr/bin/git"),
            native_gh: PathBuf::from("/usr/bin/gh"),
            activate_transparent_launchers: false,
        };
        let mut release = crate::release_manifest::VerifiedDevAuthRelease {
            schema: "dev-auth-verified-release-v1".into(),
            root_path: PathBuf::from("/tmp/root.json"),
            manifest_path: PathBuf::from("/tmp/manifest.json"),
            root_generation: 4,
            manifest_generation: 11,
            version: request.version.clone(),
            source_commit: "c".repeat(40),
            target: "linux-x86_64".into(),
            artifact_path: request.source_executable.clone(),
            artifact_url: "https://example.invalid/dev-auth".into(),
            artifact_length: 10,
            artifact_sha256: "d".repeat(64),
            root_sha256: "e".repeat(64),
            manifest_sha256: "f".repeat(64),
        };

        assert!(
            validate_release_transition(&prior, &request, &release.artifact_sha256, None).is_err()
        );
        release.root_generation = 3;
        assert!(validate_release_transition(
            &prior,
            &request,
            &release.artifact_sha256,
            Some(&release),
        )
        .is_err());
        release.root_generation = 4;
        release.manifest_generation = 9;
        assert!(validate_release_transition(
            &prior,
            &request,
            &release.artifact_sha256,
            Some(&release),
        )
        .is_err());
        release.manifest_generation = 10;
        assert!(validate_release_transition(
            &prior,
            &request,
            &release.artifact_sha256,
            Some(&release),
        )
        .is_err());
        release.manifest_generation = 11;
        assert!(validate_release_transition(
            &prior,
            &request,
            &release.artifact_sha256,
            Some(&release),
        )
        .is_ok());

        request.version = prior.version.clone();
        assert!(
            validate_release_transition(&prior, &request, &prior.executable_sha256, None,).is_ok()
        );
    }

    #[test]
    fn system_credential_enrollment_and_rotation_are_explicit() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let tool = root.path().join("systemd-creds");
        fs::write(
            &tool,
            "#!/bin/sh\nset -eu\ntest \"$1\" = encrypt\ntest \"$2\" = --name=op-service-account-token_automation\ntest \"$3\" = -\numask 077\ncat > \"$4\"\n",
        )
        .unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
        let destination = root.path().join("credstore/service-token");
        let owner = nix::unistd::Uid::effective().as_raw();
        enroll_system_service_credential_at(&tool, &destination, b"test-service-token\n", owner)
            .unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"test-service-token\n");
        assert_eq!(
            fs::symlink_metadata(&destination).unwrap().mode() & 0o777,
            0o600
        );
        assert!(
            enroll_system_service_credential_at(&tool, &destination, b"replacement\n", owner,)
                .is_err()
        );
        store_system_service_credential_at(
            &tool,
            &destination,
            "automation",
            b"replacement\n",
            owner,
            true,
        )
        .unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"replacement\n");
        assert_eq!(
            fs::symlink_metadata(&destination).unwrap().mode() & 0o777,
            0o600
        );

        fs::remove_file(&destination).unwrap();
        assert!(store_system_service_credential_at(
            &tool,
            &destination,
            "automation",
            b"missing-current\n",
            owner,
            true,
        )
        .is_err());
    }

    #[test]
    fn policy_replacement_is_compare_and_swap_and_never_follows_drift() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let destination = root.path().join("policy.toml");
        fs::write(&destination, b"version = 1\n").unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o600)).unwrap();
        let owner = nix::unistd::Uid::effective().as_raw();
        let current = format!("{:x}", Sha256::digest(b"version = 1\n"));
        replace_policy_document(&destination, b"version = 2\n", owner, 0o600, &current).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"version = 2\n");

        assert!(
            replace_policy_document(&destination, b"version = 3\n", owner, 0o600, &current,)
                .is_err()
        );
        assert_eq!(fs::read(&destination).unwrap(), b"version = 2\n");

        let outside = root.path().join("outside");
        fs::write(&outside, b"outside\n").unwrap();
        fs::remove_file(&destination).unwrap();
        std::os::unix::fs::symlink(&outside, &destination).unwrap();
        let outside_digest = format!("{:x}", Sha256::digest(b"outside\n"));
        assert!(replace_policy_document(
            &destination,
            b"replacement\n",
            owner,
            0o600,
            &outside_digest,
        )
        .is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"outside\n");
    }

    #[test]
    fn state_cleanup_is_idempotent_and_never_follows_a_symlink() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let owner = nix::unistd::Uid::effective().as_raw();
        let state = root.path().join("state.toml");
        fs::write(&state, b"version = 2\n").unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            remove_optional_state_file(&state, owner, 0o077, POLICY_LIMIT, "test state").unwrap()
        );
        assert!(
            !remove_optional_state_file(&state, owner, 0o077, POLICY_LIMIT, "test state").unwrap()
        );

        let outside = root.path().join("outside");
        fs::write(&outside, b"preserve").unwrap();
        symlink(&outside, &state).unwrap();
        assert!(
            remove_optional_state_file(&state, owner, 0o077, POLICY_LIMIT, "test state").is_err()
        );
        assert_eq!(fs::read(&outside).unwrap(), b"preserve");
    }

    #[test]
    fn v1_migration_requires_an_explicit_non_widening_v2_resolution() {
        let legacy = crate::parse_config(
            br#"
version = 1

[programs]
op = "/usr/bin/op"
gh = "/usr/bin/gh"
git = "/usr/bin/git"
ssh_add = "/usr/bin/ssh-add"
ssh_keygen = "/usr/bin/ssh-keygen"

[git]
workspace_roots = ["/srv/source"]
author_name = "Automation Agent"
author_email = "automation@example.invalid"
ssh_profile = "automation"

[github]
app_id = 42
private_key_ref = "op://Machine Vault/github-app/private-key"
repository_selection = "selected"
discover_installations = false
permissions = { actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }

[[github.installations]]
owner = "ExampleOrg"
installation_id = 101
repositories = ["api"]

[[ssh_profiles.automation.keys]]
purpose = "authentication"
private_key_ref = "op://Machine Vault/release/ssh-private-key"
fingerprint = "SHA256:5QH+7oUNO/MqyIzx8cLnowDLL1ZieiobwK9fp361KnI"

[[ssh_profiles.automation.keys]]
purpose = "signing"
private_key_ref = "op://Machine Vault/release/signing-private-key"
fingerprint = "SHA256:MAZx0fmOBVsH2stM9hAveivu4wCDmzwJoBJNZlN3g8w"
"#,
        )
        .unwrap();
        let system = crate::policy_v2::parse_system_policy_v2(
            br#"
version = 2
mode = "strong"
allowed_users = ["automation"]

[programs]
op = "/usr/bin/op"
git = "/usr/bin/git"
gh = "/usr/bin/gh"
ssh = "/usr/bin/ssh"
ssh_keygen = "/usr/bin/ssh-keygen"

[trusted_launchers]
agent = "/opt/dev-auth/agent"

[github_apps.automation]
app_id = 42
private_key_references = ["op://Machine Vault/github-app/private-key"]

[credential_slots.automation]
users = ["automation"]
authority_caps = ["release"]
secret_references = ["op://Machine Vault/github-app/private-key", "op://Machine Vault/release/ssh-private-key", "op://Machine Vault/release/signing-private-key"]

[authority_caps.release]
github_apps = ["automation"]
owners = ["ExampleOrg"]
repositories = ["api"]
permissions = { actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }
installation_ids = [101]
signing = true
ssh = true
git_identities = [{ name = "Automation Agent", email = "automation@example.invalid" }]
secret_references = ["op://Machine Vault/github-app/private-key", "op://Machine Vault/release/ssh-private-key", "op://Machine Vault/release/signing-private-key"]

[workspace_caps.source]
path = "/srv/source"
access = "read_write"
"#,
        )
        .unwrap();
        let user = crate::policy_v2::parse_user_config_v2(
            br#"
version = 2

[authority_profiles.publish]
cap = "release"
signing = true
signing_key = { private_key_ref = "op://Machine Vault/release/signing-private-key", public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPWR87z4BHtBodJUStB0X7zUDrgyLhM3kQ3Sxo8X4lrY", fingerprint = "SHA256:MAZx0fmOBVsH2stM9hAveivu4wCDmzwJoBJNZlN3g8w" }
ssh = true
ssh_keys = [{ private_key_ref = "op://Machine Vault/release/ssh-private-key", public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPuruylR5Dw9TRBXnt/aS8+Sj1dH3mUEcqFz8iItXZaZ dev-auth-policy-test", fingerprint = "SHA256:5QH+7oUNO/MqyIzx8cLnowDLL1ZieiobwK9fp361KnI" }]
git_identity = { name = "Automation Agent", email = "automation@example.invalid" }
secret_references = ["op://Machine Vault/github-app/private-key", "op://Machine Vault/release/ssh-private-key", "op://Machine Vault/release/signing-private-key"]

[authority_profiles.publish.github]
app_cap = "automation"
private_key_ref = "op://Machine Vault/github-app/private-key"
owners = ["ExampleOrg"]
repositories = ["api"]
permissions = { actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }

[[workloads]]
name = "release-agent"
launcher = "agent"
profile = "publish"
secret_references = []
workspace_roots = [{ cap = "source", path = "/srv/source", access = "read_write" }]

[workloads.sandbox]
mode = "none"
adapters = []
"#,
        )
        .unwrap();
        let resolved = crate::policy_v2::resolve_policy(&system, &user).unwrap();

        validate_v1_migration_resolution(&legacy, &resolved, Path::new("/home/automation"))
            .unwrap();

        let mut widened = resolved.clone();
        widened
            .workloads
            .get_mut("release-agent")
            .unwrap()
            .workspace_roots[0]
            .path = "/srv/unapproved".into();
        assert!(
            validate_v1_migration_resolution(&legacy, &widened, Path::new("/home/automation"))
                .is_err()
        );
    }
}
