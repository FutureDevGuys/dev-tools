use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, PublicKey};
use std::collections::{BTreeMap, BTreeSet};

const MAX_WORKSPACE_ROOTS_PER_WORKLOAD: usize = 64;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SystemMode {
    Strong,
    UserOnly,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SystemPrograms {
    pub op: String,
    pub git: String,
    pub gh: String,
    pub ssh: String,
    pub ssh_keygen: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Read,
    Write,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCap {
    #[serde(default)]
    pub github_apps: Vec<String>,
    #[serde(default)]
    pub owners: Vec<String>,
    #[serde(default)]
    pub repositories: Vec<String>,
    #[serde(default)]
    pub permissions: BTreeMap<String, Permission>,
    #[serde(default)]
    pub installation_ids: Vec<u64>,
    #[serde(default)]
    pub signing: bool,
    #[serde(default)]
    pub release_signing_products: Vec<String>,
    #[serde(default)]
    pub release_signing_keys: Vec<ReleaseSigningKeyConfig>,
    #[serde(default)]
    pub ssh: bool,
    #[serde(default)]
    pub git_identities: Vec<GitIdentityConfig>,
    pub secret_references: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct GitIdentityConfig {
    pub name: String,
    pub email: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GitHubAppCap {
    pub app_id: u64,
    pub private_key_references: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialSlotCap {
    pub users: Vec<String>,
    pub authority_caps: Vec<String>,
    pub secret_references: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceCap {
    pub path: String,
    pub access: WorkspaceAccess,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxVisibility {
    Required,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxPeerIdentity {
    Preserve,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxCgroupIdentity {
    Retain,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxDescendantContainment {
    Retain,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxNetworkNamespace {
    Inherit,
    Isolated,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxWorkspaceMounts {
    Requested,
}

impl SandboxNetworkNamespace {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inherit => "inherit",
            Self::Isolated => "isolated",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "inherit" => Ok(Self::Inherit),
            "isolated" => Ok(Self::Isolated),
            _ => bail!("sandbox network-namespace contract is invalid"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SandboxAdapterCap {
    pub executable: String,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default)]
    pub argument_separator: bool,
    pub launcher_visibility: SandboxVisibility,
    pub broker_socket_visibility: SandboxVisibility,
    pub peer_identity: SandboxPeerIdentity,
    pub cgroup_identity: SandboxCgroupIdentity,
    pub descendant_containment: SandboxDescendantContainment,
    pub network_namespace: SandboxNetworkNamespace,
    pub workspace_mounts: SandboxWorkspaceMounts,
    pub read_only_mount_arguments: Vec<String>,
    pub read_write_mount_arguments: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SystemPolicyV2 {
    pub version: u32,
    pub mode: SystemMode,
    pub allowed_users: Vec<String>,
    pub programs: SystemPrograms,
    pub trusted_launchers: BTreeMap<String, String>,
    pub github_apps: BTreeMap<String, GitHubAppCap>,
    pub credential_slots: BTreeMap<String, CredentialSlotCap>,
    pub authority_caps: BTreeMap<String, AuthorityCap>,
    pub workspace_caps: BTreeMap<String, WorkspaceCap>,
    #[serde(default)]
    pub sandbox_adapters: BTreeMap<String, SandboxAdapterCap>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NoSessionRouting {
    #[default]
    NativePassthrough,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidSessionRouting {
    Deny,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    #[serde(default)]
    pub no_session: NoSessionRouting,
    #[serde(default)]
    pub help_footer: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GitHubConfigV2 {
    pub app_cap: String,
    pub private_key_ref: String,
    pub owners: Vec<String>,
    #[serde(default)]
    pub repositories: Vec<String>,
    #[serde(default)]
    pub permissions: BTreeMap<String, Permission>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityProfile {
    pub cap: String,
    #[serde(default)]
    pub github: Option<GitHubConfigV2>,
    #[serde(default)]
    pub signing: bool,
    #[serde(default)]
    pub signing_key: Option<OperationKeyConfig>,
    #[serde(default)]
    pub release_signing_products: Vec<String>,
    #[serde(default)]
    pub release_signing_key: Option<ReleaseSigningKeyConfig>,
    #[serde(default)]
    pub ssh: bool,
    #[serde(default)]
    pub ssh_keys: Vec<OperationKeyConfig>,
    #[serde(default)]
    pub git_identity: Option<GitIdentityConfig>,
    pub secret_references: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct OperationKeyConfig {
    pub private_key_ref: String,
    pub public_key: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSigningKeyConfig {
    pub private_key_ref: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMode {
    None,
    Auto,
    Required,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    pub mode: SandboxMode,
    #[serde(default)]
    pub adapters: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRootRequest {
    pub cap: String,
    pub path: String,
    pub access: WorkspaceAccess,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DesktopWorkloadConfig {
    pub display_name: String,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub terminal: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkloadConfig {
    pub name: String,
    pub launcher: String,
    pub profile: String,
    pub secret_references: Vec<String>,
    pub workspace_roots: Vec<WorkspaceRootRequest>,
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub desktop: Option<DesktopWorkloadConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UserConfigV2 {
    pub version: u32,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub authority_profiles: BTreeMap<String, AuthorityProfile>,
    #[serde(default)]
    pub workloads: Vec<WorkloadConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRouting {
    pub no_session: NoSessionRouting,
    pub invalid_session: InvalidSessionRouting,
    pub help_footer: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGitHubAuthority {
    pub app_cap: String,
    pub app_id: u64,
    pub private_key_ref: String,
    pub owners: BTreeSet<String>,
    pub repositories: BTreeSet<String>,
    pub permissions: BTreeMap<String, Permission>,
    pub installation_ids: BTreeSet<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAuthorityProfile {
    pub system_cap: String,
    pub credential_slot: String,
    pub github: Option<ResolvedGitHubAuthority>,
    pub signing: bool,
    pub signing_key: Option<OperationKeyConfig>,
    pub release_signing_products: BTreeSet<String>,
    pub release_signing_key: Option<ReleaseSigningKeyConfig>,
    pub ssh: bool,
    pub ssh_keys: Vec<OperationKeyConfig>,
    pub git_identity: Option<GitIdentityConfig>,
    pub secret_references: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSandbox {
    pub mode: SandboxMode,
    pub adapters: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedWorkspaceRoot {
    pub system_cap: String,
    pub path: String,
    pub access: WorkspaceAccess,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedWorkload {
    pub launcher: String,
    pub launcher_path: String,
    pub authority_profile: String,
    pub secret_references: Vec<String>,
    pub workspace_roots: Vec<ResolvedWorkspaceRoot>,
    pub sandbox: ResolvedSandbox,
    pub desktop: Option<DesktopWorkloadConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPolicy {
    pub mode: SystemMode,
    pub allowed_users: BTreeSet<String>,
    pub programs: SystemPrograms,
    pub trusted_launchers: BTreeMap<String, String>,
    pub sandbox_adapters: BTreeMap<String, SandboxAdapterCap>,
    pub routing: ResolvedRouting,
    pub authority_profiles: BTreeMap<String, ResolvedAuthorityProfile>,
    pub workloads: BTreeMap<String, ResolvedWorkload>,
}

pub fn parse_system_policy_v2(input: &[u8]) -> Result<SystemPolicyV2> {
    let text = std::str::from_utf8(input).context("system policy is not UTF-8")?;
    let policy: SystemPolicyV2 = toml::from_str(text).context("system policy is not valid TOML")?;
    validate_system_policy(&policy)?;
    Ok(policy)
}

pub fn require_system_policy_narrows(
    administrator: &SystemPolicyV2,
    candidate: &SystemPolicyV2,
) -> Result<()> {
    validate_system_policy(administrator).context("validate administrator policy")?;
    validate_system_policy(candidate).context("validate narrowing policy")?;
    if candidate.mode != administrator.mode {
        bail!("narrowing policy changes the administrator policy mode");
    }
    if candidate.programs != administrator.programs {
        bail!("narrowing policy changes an administrator-pinned program");
    }

    let administrator_users = administrator
        .allowed_users
        .iter()
        .map(|user| user.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if candidate
        .allowed_users
        .iter()
        .map(|user| user.to_ascii_lowercase())
        .any(|user| !administrator_users.contains(&user))
    {
        bail!("narrowing policy widens the administrator user cap");
    }

    require_exact_map_subset(
        &administrator.trusted_launchers,
        &candidate.trusted_launchers,
        "trusted launcher",
    )?;
    require_exact_map_subset(
        &administrator.sandbox_adapters,
        &candidate.sandbox_adapters,
        "sandbox adapter",
    )?;

    for (name, app) in &candidate.github_apps {
        let administrator_app = administrator
            .github_apps
            .get(name)
            .with_context(|| format!("narrowing policy introduces GitHub App cap {name}"))?;
        if app.app_id != administrator_app.app_id
            || !is_subset(
                &app.private_key_references,
                &administrator_app.private_key_references,
            )
        {
            bail!("narrowing policy widens GitHub App cap {name}");
        }
    }

    for (name, slot) in &candidate.credential_slots {
        let administrator_slot = administrator
            .credential_slots
            .get(name)
            .with_context(|| format!("narrowing policy introduces credential slot {name}"))?;
        if !is_case_insensitive_subset(&slot.users, &administrator_slot.users)
            || !is_subset(&slot.authority_caps, &administrator_slot.authority_caps)
            || !is_subset(
                &slot.secret_references,
                &administrator_slot.secret_references,
            )
        {
            bail!("narrowing policy widens credential slot {name}");
        }
    }

    for (name, cap) in &candidate.authority_caps {
        let administrator_cap = administrator
            .authority_caps
            .get(name)
            .with_context(|| format!("narrowing policy introduces authority cap {name}"))?;
        if !is_subset(&cap.github_apps, &administrator_cap.github_apps)
            || !is_case_insensitive_subset(&cap.owners, &administrator_cap.owners)
            || !bounded_optional_scope(&cap.repositories, &administrator_cap.repositories, true)
            || !bounded_optional_scope(
                &cap.installation_ids,
                &administrator_cap.installation_ids,
                false,
            )
            || (cap.signing && !administrator_cap.signing)
            || !is_subset(
                &cap.release_signing_products,
                &administrator_cap.release_signing_products,
            )
            || !is_subset(
                &cap.release_signing_keys,
                &administrator_cap.release_signing_keys,
            )
            || (cap.ssh && !administrator_cap.ssh)
            || !is_subset(&cap.git_identities, &administrator_cap.git_identities)
            || !is_subset(&cap.secret_references, &administrator_cap.secret_references)
        {
            bail!("narrowing policy widens authority cap {name}");
        }
        for (permission, requested) in &cap.permissions {
            let Some(allowed) = administrator_cap.permissions.get(permission) else {
                bail!("narrowing policy adds permission {permission} to authority cap {name}");
            };
            if requested > allowed {
                bail!("narrowing policy widens permission {permission} in authority cap {name}");
            }
        }
    }

    for (name, cap) in &candidate.workspace_caps {
        let administrator_cap = administrator
            .workspace_caps
            .get(name)
            .with_context(|| format!("narrowing policy introduces workspace cap {name}"))?;
        if cap.access > administrator_cap.access
            || !path_is_within(&cap.path, &administrator_cap.path)
        {
            bail!("narrowing policy widens workspace cap {name}");
        }
    }
    Ok(())
}

fn require_exact_map_subset<T: PartialEq>(
    administrator: &BTreeMap<String, T>,
    candidate: &BTreeMap<String, T>,
    description: &str,
) -> Result<()> {
    for (name, value) in candidate {
        if administrator.get(name) != Some(value) {
            bail!("narrowing policy changes or introduces {description} {name}");
        }
    }
    Ok(())
}

fn is_subset<T: Ord + Clone>(candidate: &[T], administrator: &[T]) -> bool {
    let administrator = administrator.iter().cloned().collect::<BTreeSet<_>>();
    candidate.iter().all(|value| administrator.contains(value))
}

fn is_case_insensitive_subset(candidate: &[String], administrator: &[String]) -> bool {
    let administrator = administrator
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    candidate
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .all(|value| administrator.contains(&value))
}

fn bounded_optional_scope<T>(candidate: &[T], administrator: &[T], case_insensitive: bool) -> bool
where
    T: Clone + Ord + ToString,
{
    if administrator.is_empty() {
        return true;
    }
    if candidate.is_empty() {
        return false;
    }
    if case_insensitive {
        let administrator = administrator
            .iter()
            .map(|value| value.to_string().to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        candidate
            .iter()
            .map(|value| value.to_string().to_ascii_lowercase())
            .all(|value| administrator.contains(&value))
    } else {
        is_subset(candidate, administrator)
    }
}

fn validate_system_policy(policy: &SystemPolicyV2) -> Result<()> {
    if policy.version != 2 {
        bail!("unsupported system policy version");
    }

    validate_unique(
        &policy.allowed_users,
        "system policy contains a duplicate allowed user",
        |user| validate_public_name(user, "allowed user"),
        |user| user.to_ascii_lowercase(),
    )?;
    if policy.allowed_users.is_empty() {
        bail!("system policy must declare at least one allowed user");
    }

    let programs = [
        ("1Password CLI", &policy.programs.op),
        ("Git", &policy.programs.git),
        ("GitHub CLI", &policy.programs.gh),
        ("SSH", &policy.programs.ssh),
        ("ssh-keygen", &policy.programs.ssh_keygen),
    ];
    let mut program_paths = BTreeSet::new();
    for (description, path) in programs {
        validate_absolute_executable(path, description)?;
        if !program_paths.insert(normalize_path_for_comparison(path)) {
            bail!("system policy contains a duplicate program path");
        }
    }

    for (name, adapter) in &policy.sandbox_adapters {
        validate_policy_identifier(name, "sandbox adapter")?;
        if name == "native" {
            bail!("native execution is not a sandbox adapter");
        }
        validate_absolute_executable(&adapter.executable, "sandbox adapter executable")?;
        if adapter.arguments.len() > 128
            || adapter.arguments.iter().any(|argument| {
                argument.is_empty() || argument.len() > 4096 || argument.contains('\0')
            })
        {
            bail!("sandbox adapter contains an invalid fixed argument");
        }
        validate_sandbox_mount_arguments(
            &adapter.read_only_mount_arguments,
            "read-only workspace mount",
        )?;
        validate_sandbox_mount_arguments(
            &adapter.read_write_mount_arguments,
            "read-write workspace mount",
        )?;
    }

    for (name, path) in &policy.trusted_launchers {
        validate_policy_identifier(name, "trusted launcher")?;
        validate_absolute_executable(path, "trusted launcher")?;
    }
    ensure_unique_map_paths(&policy.trusted_launchers, "trusted launcher")?;

    let mut github_app_ids = BTreeSet::new();
    for (name, app) in &policy.github_apps {
        validate_policy_identifier(name, "GitHub App cap")?;
        if app.app_id == 0 {
            bail!("GitHub App cap ID must be positive");
        }
        if !github_app_ids.insert(app.app_id) {
            bail!("system policy contains a duplicate GitHub App ID");
        }
        validate_unique(
            &app.private_key_references,
            "GitHub App cap contains a duplicate private-key reference",
            |reference| super::validate_op_reference(reference),
            Clone::clone,
        )?;
        if app.private_key_references.is_empty() {
            bail!("GitHub App cap must declare at least one private-key reference");
        }
    }

    for (name, slot) in &policy.credential_slots {
        validate_policy_identifier(name, "credential slot")?;
        validate_unique(
            &slot.users,
            "credential slot contains a duplicate native user",
            |user| {
                validate_public_name(user, "credential slot native user")?;
                if !policy
                    .allowed_users
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(user))
                {
                    bail!("credential slot names a user outside system policy");
                }
                Ok(())
            },
            |user| user.to_ascii_lowercase(),
        )?;
        if slot.users.is_empty() {
            bail!("credential slot must name at least one native user");
        }
        validate_unique(
            &slot.authority_caps,
            "credential slot contains a duplicate authority cap",
            |cap| {
                validate_policy_identifier(cap, "credential slot authority cap")?;
                if !policy.authority_caps.contains_key(cap) {
                    bail!("credential slot references an unknown authority cap");
                }
                Ok(())
            },
            Clone::clone,
        )?;
        if slot.authority_caps.is_empty() {
            bail!("credential slot must name at least one authority cap");
        }
        validate_secret_references(&slot.secret_references, "credential slot")?;
        if slot.secret_references.is_empty() {
            bail!("credential slot must declare at least one secret reference");
        }
    }

    for (name, cap) in &policy.authority_caps {
        validate_policy_identifier(name, "authority cap")?;
        validate_unique(
            &cap.github_apps,
            "authority cap contains a duplicate GitHub App cap",
            |app| {
                validate_policy_identifier(app, "GitHub App cap reference")?;
                if !policy.github_apps.contains_key(app) {
                    bail!("authority cap references an unknown GitHub App cap");
                }
                Ok(())
            },
            Clone::clone,
        )?;
        if cap.github_apps.is_empty() {
            if !cap.owners.is_empty()
                || !cap.repositories.is_empty()
                || !cap.permissions.is_empty()
                || !cap.installation_ids.is_empty()
            {
                bail!("authority cap declares GitHub scope without a GitHub App cap");
            }
        } else {
            validate_github_scope(
                &cap.owners,
                &cap.repositories,
                &cap.permissions,
                "authority cap",
            )?;
        }
        validate_secret_references(&cap.secret_references, "authority cap")?;
        validate_unique(
            &cap.release_signing_products,
            "authority cap contains a duplicate release-signing product",
            |product| validate_policy_identifier(product, "release-signing product"),
            Clone::clone,
        )?;
        validate_unique(
            &cap.release_signing_keys,
            "authority cap contains a duplicate release-signing key",
            |key| validate_release_signing_key(key, &cap.secret_references),
            |key| key.public_key.clone(),
        )?;
        if cap.release_signing_products.is_empty() != cap.release_signing_keys.is_empty() {
            bail!("authority cap release-signing products and operation keys disagree");
        }
        let matching_slots = policy
            .credential_slots
            .iter()
            .filter(|(_, slot)| slot.authority_caps.contains(name))
            .collect::<Vec<_>>();
        if matching_slots.len() != 1 {
            bail!("authority cap must belong to exactly one credential slot");
        }
        let slot_references = matching_slots[0]
            .1
            .secret_references
            .iter()
            .collect::<BTreeSet<_>>();
        if cap
            .secret_references
            .iter()
            .any(|reference| !slot_references.contains(reference))
        {
            bail!("authority cap widens its credential slot secret references");
        }
        if cap.installation_ids.contains(&0)
            || cap
                .installation_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            bail!("authority cap contains an invalid installation ID");
        }
        validate_unique(
            &cap.git_identities,
            "authority cap contains a duplicate Git identity",
            |identity| super::validate_git_author(&identity.name, &identity.email),
            |identity| identity.clone(),
        )?;
    }
    for (name, cap) in &policy.workspace_caps {
        validate_policy_identifier(name, "workspace cap")?;
        validate_canonical_absolute_path(&cap.path, "workspace cap")?;
    }
    ensure_unique_workspace_cap_paths(&policy.workspace_caps)?;

    Ok(())
}

fn validate_sandbox_mount_arguments(arguments: &[String], description: &str) -> Result<()> {
    if arguments.is_empty()
        || arguments.len() > 32
        || arguments.iter().any(|argument| {
            argument.is_empty() || argument.len() > 4096 || argument.contains('\0') || {
                let without_path = argument.replace("{path}", "");
                without_path.contains('{') || without_path.contains('}')
            }
        })
        || !arguments.iter().any(|argument| argument.contains("{path}"))
    {
        bail!("sandbox adapter contains invalid {description} arguments");
    }
    Ok(())
}

pub fn parse_user_config_v2(input: &[u8]) -> Result<UserConfigV2> {
    let text = std::str::from_utf8(input).context("user configuration is not UTF-8")?;
    let config: UserConfigV2 =
        toml::from_str(text).context("user configuration is not valid TOML")?;
    validate_user_config(&config)?;
    Ok(config)
}

fn validate_user_config(config: &UserConfigV2) -> Result<()> {
    if config.version != 2 {
        bail!("unsupported user configuration version");
    }

    for (name, profile) in &config.authority_profiles {
        validate_policy_identifier(name, "authority profile")?;
        validate_policy_identifier(&profile.cap, "authority cap reference")?;
        if let Some(github) = &profile.github {
            validate_policy_identifier(&github.app_cap, "GitHub App cap reference")?;
            super::validate_op_reference(&github.private_key_ref)?;
            validate_github_scope(
                &github.owners,
                &github.repositories,
                &github.permissions,
                "authority profile",
            )?;
        }
        validate_secret_references(&profile.secret_references, "authority profile")?;
        if let Some(identity) = &profile.git_identity {
            super::validate_git_author(&identity.name, &identity.email)?;
        }
        match (&profile.signing_key, profile.signing) {
            (Some(key), true) => validate_operation_key(key, &profile.secret_references)?,
            (None, false) => {}
            (Some(_), false) => bail!("authority profile declares a signing key without signing"),
            (None, true) => bail!("authority profile enables signing without an operation key"),
        }
        match (
            &profile.release_signing_key,
            profile.release_signing_products.is_empty(),
        ) {
            (Some(key), false) => validate_release_signing_key(key, &profile.secret_references)?,
            (None, true) => {}
            (Some(_), true) => {
                bail!("authority profile declares a release-signing key without products")
            }
            (None, false) => {
                bail!("authority profile enables release signing without an operation key")
            }
        }
        validate_unique(
            &profile.release_signing_products,
            "authority profile contains a duplicate release-signing product",
            |product| validate_policy_identifier(product, "release-signing product"),
            Clone::clone,
        )?;
        if profile.ssh != !profile.ssh_keys.is_empty() {
            bail!("authority profile SSH capability and operation keys disagree");
        }
        validate_unique(
            &profile.ssh_keys,
            "authority profile contains a duplicate SSH operation key",
            |key| validate_operation_key(key, &profile.secret_references),
            |key| key.fingerprint.clone(),
        )?;
    }

    let mut workload_names = BTreeSet::new();
    for workload in &config.workloads {
        validate_policy_identifier(&workload.name, "workload")?;
        if [
            "dev-auth",
            "dev-auth-workload-launcher",
            "git",
            "gh",
            "git-dev-auth",
            "gh-dev-auth",
            "git-credential-dev-auth",
            "ssh-keygen-dev-auth",
        ]
        .contains(&workload.name.as_str())
        {
            bail!("workload name collides with a reserved product launcher");
        }
        if !workload_names.insert(workload.name.clone()) {
            bail!("user configuration contains a duplicate workload name");
        }
        validate_policy_identifier(&workload.launcher, "workload launcher reference")?;
        validate_policy_identifier(&workload.profile, "workload authority profile reference")?;
        if workload.workspace_roots.len() > MAX_WORKSPACE_ROOTS_PER_WORKLOAD {
            bail!("workload may declare at most 64 workspace roots");
        }
        validate_unique(
            &workload.workspace_roots,
            "workload contains a duplicate workspace root",
            |root| {
                validate_policy_identifier(&root.cap, "workspace cap reference")?;
                validate_canonical_absolute_path(&root.path, "workload workspace root")
            },
            |root| normalize_path_for_comparison(&root.path),
        )?;
        validate_secret_references(&workload.secret_references, "workload")?;
        validate_unique(
            &workload.sandbox.adapters,
            "workload contains a duplicate sandbox adapter",
            |adapter| validate_policy_identifier(adapter, "sandbox adapter"),
            Clone::clone,
        )?;
        match workload.sandbox.mode {
            SandboxMode::None if !workload.sandbox.adapters.is_empty() => {
                bail!("sandbox mode none cannot declare adapters")
            }
            SandboxMode::Required if workload.sandbox.adapters.is_empty() => {
                bail!("sandbox mode required must declare at least one adapter")
            }
            SandboxMode::None | SandboxMode::Auto | SandboxMode::Required => {}
        }
        if let Some(desktop) = &workload.desktop {
            if desktop.display_name.is_empty()
                || desktop.display_name.len() > 128
                || desktop
                    .display_name
                    .chars()
                    .any(|character| character.is_control())
            {
                bail!("workload desktop display name is invalid");
            }
            if desktop.icon.as_ref().is_some_and(|icon| {
                icon.is_empty()
                    || icon.len() > 256
                    || !icon.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
                    })
            }) {
                bail!("workload desktop icon is invalid");
            }
        }
    }

    Ok(())
}

pub fn resolve_policy(system: &SystemPolicyV2, user: &UserConfigV2) -> Result<ResolvedPolicy> {
    resolve_policy_inner(system, None, user)
}

pub fn resolve_policy_for_user(
    system: &SystemPolicyV2,
    native_user: &str,
    user: &UserConfigV2,
) -> Result<ResolvedPolicy> {
    validate_public_name(native_user, "native user")?;
    if !system
        .allowed_users
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(native_user))
    {
        bail!("native user is outside system policy");
    }
    resolve_policy_inner(system, Some(native_user), user)
}

fn resolve_policy_inner(
    system: &SystemPolicyV2,
    native_user: Option<&str>,
    user: &UserConfigV2,
) -> Result<ResolvedPolicy> {
    validate_system_policy(system)?;
    validate_user_config(user)?;

    let mut authority_profiles = BTreeMap::new();
    for (name, requested) in &user.authority_profiles {
        let cap = system.authority_caps.get(&requested.cap).with_context(|| {
            format!("authority profile {name} references an unknown system cap")
        })?;
        let (credential_slot, slot) = system
            .credential_slots
            .iter()
            .find(|(_, slot)| slot.authority_caps.contains(&requested.cap))
            .context("authority profile has no credential slot")?;
        if native_user.is_some_and(|native_user| {
            !slot
                .users
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(native_user))
        }) {
            bail!("authority profile {name} credential slot denies the native user");
        }
        let github = requested
            .github
            .as_ref()
            .map(|github| resolve_github_authority(system, cap, name, github))
            .transpose()?;
        if requested.signing && !cap.signing {
            bail!("authority profile {name} widens the system signing cap");
        }
        if !is_subset(
            &requested.release_signing_products,
            &cap.release_signing_products,
        ) {
            bail!("authority profile {name} widens the system release-signing cap");
        }
        if requested
            .release_signing_key
            .as_ref()
            .is_some_and(|key| !cap.release_signing_keys.contains(key))
        {
            bail!("authority profile {name} selects an unapproved release-signing key");
        }
        if requested.ssh && !cap.ssh {
            bail!("authority profile {name} widens the system SSH cap");
        }
        if requested
            .git_identity
            .as_ref()
            .is_some_and(|identity| !cap.git_identities.contains(identity))
        {
            bail!("authority profile {name} widens the system Git identity cap");
        }
        let cap_secret_references: BTreeSet<_> = cap.secret_references.iter().cloned().collect();
        let secret_references: BTreeSet<_> = requested.secret_references.iter().cloned().collect();
        if !secret_references.is_subset(&cap_secret_references) {
            bail!("authority profile {name} widens the system secret-reference cap");
        }

        authority_profiles.insert(
            name.clone(),
            ResolvedAuthorityProfile {
                system_cap: requested.cap.clone(),
                credential_slot: credential_slot.clone(),
                github,
                signing: requested.signing,
                signing_key: requested.signing_key.clone(),
                release_signing_products: requested
                    .release_signing_products
                    .iter()
                    .cloned()
                    .collect(),
                release_signing_key: requested.release_signing_key.clone(),
                ssh: requested.ssh,
                ssh_keys: requested.ssh_keys.clone(),
                git_identity: requested.git_identity.clone(),
                secret_references,
            },
        );
    }

    let trusted_launchers = system.trusted_launchers.clone();
    let sandbox_adapters = system.sandbox_adapters.clone();
    let mut workloads = BTreeMap::new();
    for workload in &user.workloads {
        let launcher_path = trusted_launchers.get(&workload.launcher).with_context(|| {
            format!(
                "workload {} references an untrusted launcher",
                workload.name
            )
        })?;
        let profile = authority_profiles.get(&workload.profile).with_context(|| {
            format!(
                "workload {} references an unknown authority profile",
                workload.name
            )
        })?;
        let workload_secret_references: BTreeSet<_> =
            workload.secret_references.iter().cloned().collect();
        if !workload_secret_references.is_subset(&profile.secret_references) {
            bail!(
                "workload {} widens its authority profile secret references",
                workload.name
            );
        }
        if workload
            .sandbox
            .adapters
            .iter()
            .any(|adapter| !sandbox_adapters.contains_key(adapter))
        {
            bail!(
                "workload {} requests a sandbox adapter outside system policy",
                workload.name
            );
        }
        let mut workspace_roots = Vec::with_capacity(workload.workspace_roots.len());
        for requested_root in &workload.workspace_roots {
            let cap = system
                .workspace_caps
                .get(&requested_root.cap)
                .with_context(|| {
                    format!(
                        "workload {} references an unknown workspace cap",
                        workload.name
                    )
                })?;
            if requested_root.access > cap.access {
                bail!("workload {} widens its workspace access cap", workload.name);
            }
            if !path_is_within(&requested_root.path, &cap.path) {
                bail!(
                    "workload {} workspace root leaves its system cap",
                    workload.name
                );
            }
            workspace_roots.push(ResolvedWorkspaceRoot {
                system_cap: requested_root.cap.clone(),
                path: requested_root.path.clone(),
                access: requested_root.access,
            });
        }

        workloads.insert(
            workload.name.clone(),
            ResolvedWorkload {
                launcher: workload.launcher.clone(),
                launcher_path: launcher_path.clone(),
                authority_profile: workload.profile.clone(),
                secret_references: workload.secret_references.clone(),
                workspace_roots,
                sandbox: ResolvedSandbox {
                    mode: workload.sandbox.mode,
                    adapters: workload.sandbox.adapters.clone(),
                },
                desktop: workload.desktop.clone(),
            },
        );
    }

    Ok(ResolvedPolicy {
        mode: system.mode,
        allowed_users: system.allowed_users.iter().cloned().collect(),
        programs: system.programs.clone(),
        trusted_launchers,
        sandbox_adapters,
        routing: ResolvedRouting {
            no_session: user.routing.no_session,
            invalid_session: InvalidSessionRouting::Deny,
            help_footer: user.routing.help_footer,
        },
        authority_profiles,
        workloads,
    })
}

fn validate_operation_key(key: &OperationKeyConfig, selected_references: &[String]) -> Result<()> {
    super::validate_op_reference(&key.private_key_ref)?;
    if !selected_references.contains(&key.private_key_ref) {
        bail!("operation key reference is outside the authority profile secret references");
    }
    let public_key = PublicKey::from_openssh(&key.public_key)
        .context("operation public key is not valid OpenSSH data")?;
    if public_key.fingerprint(HashAlg::Sha256).to_string() != key.fingerprint {
        bail!("operation public key does not match its declared fingerprint");
    }
    Ok(())
}

fn validate_release_signing_key(
    key: &ReleaseSigningKeyConfig,
    selected_references: &[String],
) -> Result<()> {
    super::validate_op_reference(&key.private_key_ref)?;
    if !selected_references.contains(&key.private_key_ref) {
        bail!("release-signing key reference is outside the authority secret references");
    }
    dev_tools_release::parse_release_public_key(&key.public_key)
        .context("release-signing public key is invalid")?;
    Ok(())
}

fn resolve_github_authority(
    system: &SystemPolicyV2,
    cap: &AuthorityCap,
    profile_name: &str,
    requested: &GitHubConfigV2,
) -> Result<ResolvedGitHubAuthority> {
    if !cap.github_apps.contains(&requested.app_cap) {
        bail!("authority profile {profile_name} widens its GitHub App cap");
    }
    let app = system
        .github_apps
        .get(&requested.app_cap)
        .context("authority profile references an unknown GitHub App cap")?;
    if !app
        .private_key_references
        .contains(&requested.private_key_ref)
    {
        bail!("authority profile {profile_name} widens the GitHub private-key cap");
    }
    let cap_owners = canonical_github_set(&cap.owners);
    let owners = canonical_github_set(&requested.owners);
    if !owners.is_subset(&cap_owners) {
        bail!("authority profile {profile_name} widens the system owner cap");
    }
    let cap_repositories = canonical_github_set(&cap.repositories);
    let repositories = canonical_github_set(&requested.repositories);
    if !cap_repositories.is_empty()
        && (repositories.is_empty() || !repositories.is_subset(&cap_repositories))
    {
        bail!("authority profile {profile_name} widens the system repository cap");
    }
    for (permission, requested_level) in &requested.permissions {
        let Some(cap_level) = cap.permissions.get(permission) else {
            bail!("authority profile {profile_name} requests an uncapped permission");
        };
        if requested_level > cap_level {
            bail!("authority profile {profile_name} widens a system permission cap");
        }
    }
    Ok(ResolvedGitHubAuthority {
        app_cap: requested.app_cap.clone(),
        app_id: app.app_id,
        private_key_ref: requested.private_key_ref.clone(),
        owners,
        repositories,
        permissions: requested.permissions.clone(),
        installation_ids: cap.installation_ids.iter().copied().collect(),
    })
}

fn validate_github_scope(
    owners: &[String],
    repositories: &[String],
    permissions: &BTreeMap<String, Permission>,
    description: &str,
) -> Result<()> {
    if owners.is_empty() {
        bail!("{description} must declare at least one owner");
    }
    validate_unique(
        owners,
        &format!("{description} contains a duplicate owner"),
        |owner| validate_github_component(owner, "owner"),
        |owner| owner.to_ascii_lowercase(),
    )?;
    validate_unique(
        repositories,
        &format!("{description} contains a duplicate repository"),
        |repository| validate_github_component(repository, "repository"),
        |repository| repository.to_ascii_lowercase(),
    )?;
    if permissions.is_empty() {
        bail!("{description} must declare at least one GitHub permission");
    }
    for permission in permissions.keys() {
        validate_permission_name(permission)?;
    }
    Ok(())
}

fn validate_secret_references(secret_references: &[String], description: &str) -> Result<()> {
    validate_unique(
        secret_references,
        &format!("{description} contains a duplicate secret reference"),
        |reference| super::validate_op_reference(reference),
        Clone::clone,
    )?;
    Ok(())
}

fn validate_unique<T, K, V, N>(
    values: &[T],
    duplicate_message: &str,
    mut validate: V,
    mut normalize: N,
) -> Result<()>
where
    K: Ord,
    V: FnMut(&T) -> Result<()>,
    N: FnMut(&T) -> K,
{
    let mut seen = BTreeSet::new();
    for value in values {
        validate(value)?;
        if !seen.insert(normalize(value)) {
            bail!(duplicate_message.to_owned());
        }
    }
    Ok(())
}

fn validate_policy_identifier(value: &str, description: &str) -> Result<()> {
    let mut bytes = value.bytes();
    if value.len() > 64
        || !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("{description} contains unsupported characters");
    }
    Ok(())
}

fn validate_public_name(value: &str, description: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("{description} contains unsupported characters");
    }
    Ok(())
}

fn validate_github_component(value: &str, description: &str) -> Result<()> {
    if !super::is_github_component(value) {
        bail!("{description} is not a valid GitHub component");
    }
    Ok(())
}

fn validate_permission_name(value: &str) -> Result<()> {
    let mut bytes = value.bytes();
    if value.len() > 64
        || !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        bail!("permission name contains unsupported characters");
    }
    Ok(())
}

fn validate_absolute_executable(value: &str, description: &str) -> Result<()> {
    super::validate_program(value, description)?;
    if value.starts_with("//")
        || value.starts_with("\\\\")
        || value.contains(['$', '%'])
        || has_unsafe_path_component(value)
    {
        bail!("{description} has an unsafe executable path");
    }
    Ok(())
}

fn validate_canonical_absolute_path(value: &str, description: &str) -> Result<()> {
    super::validate_program(value, description)?;
    if value.starts_with("//")
        || value.starts_with("\\\\")
        || value.contains(['$', '%', '~'])
        || has_unsafe_path_component(value)
    {
        bail!("{description} must be a canonical absolute path");
    }
    Ok(())
}

fn has_unsafe_path_component(value: &str) -> bool {
    let normalized = value.replace('\\', "/");
    let path = normalized
        .strip_prefix("~/")
        .or_else(|| normalized.strip_prefix('/'))
        .or_else(|| {
            normalized
                .as_bytes()
                .get(1)
                .filter(|byte| **byte == b':')
                .and_then(|_| normalized.get(3..))
        })
        .unwrap_or(&normalized);
    path.split('/')
        .any(|component| matches!(component, "" | "." | ".."))
}

fn normalize_path_for_comparison(value: &str) -> String {
    let normalized = value.replace('\\', "/");
    if cfg!(windows) {
        normalized.to_ascii_lowercase()
    } else {
        normalized
    }
}

fn ensure_unique_map_paths(paths: &BTreeMap<String, String>, description: &str) -> Result<()> {
    let mut seen = BTreeSet::new();
    for path in paths.values() {
        if !seen.insert(normalize_path_for_comparison(path)) {
            bail!("system policy contains a duplicate {description} path");
        }
    }
    Ok(())
}

fn ensure_unique_workspace_cap_paths(paths: &BTreeMap<String, WorkspaceCap>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for cap in paths.values() {
        if !seen.insert(normalize_path_for_comparison(&cap.path)) {
            bail!("system policy contains a duplicate workspace cap path");
        }
    }
    Ok(())
}

fn path_is_within(path: &str, root: &str) -> bool {
    let path = normalize_path_for_comparison(path);
    let root = normalize_path_for_comparison(root);
    path == root
        || path
            .strip_prefix(&root)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

fn canonical_github_set(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect()
}
