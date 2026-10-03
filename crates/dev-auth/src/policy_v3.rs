//! Versioned logical-resource and workload authority. Parsing never admits work.
use crate::logical_authority::{
    require_narrowing, validate_users, CredentialAuthority, ResolvedResource, ResourceSelection,
};
use crate::policy_v2::{validate_absolute_executable, SystemMode};
use crate::policy_v2::{
    DesktopWorkloadConfig, ResolvedSandbox, ResolvedWorkspaceRoot, SandboxAdapterCap,
    SandboxConfig, SandboxMode, WorkspaceCap, WorkspaceRootRequest,
};
use anyhow::{bail, Context, Result};
use dev_tools_secret::LogicalSecretName;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const DOCUMENT_LIMIT: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativePrograms {
    pub git: String,
    pub gh: String,
    pub ssh: String,
    pub ssh_keygen: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Admission {
    EnrolledNoninteractive,
    ApprovalRequired,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LogicalSelection {
    pub cap: String,
    pub resources: BTreeMap<String, ResourceSelection>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadCap {
    pub users: Vec<String>,
    pub resource_cap: String,
    pub launchers: Vec<String>,
    pub admission: Vec<Admission>,
    pub max_duration_seconds: u64,
    #[serde(default)]
    pub operations: crate::policy_v3_operations::OperationAuthority,
    #[serde(default)]
    pub workspace_caps: Vec<String>,
    #[serde(default)]
    pub sandbox_adapters: Vec<String>,
    #[serde(default)]
    pub require_sandbox: bool,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemPolicyV3 {
    pub schema: String,
    pub mode: SystemMode,
    pub allowed_users: Vec<String>,
    pub programs: NativePrograms,
    pub trusted_launchers: BTreeMap<String, String>,
    pub credentials: CredentialAuthority,
    pub workload_caps: BTreeMap<String, WorkloadCap>,
    #[serde(default)]
    pub workspace_caps: BTreeMap<String, WorkspaceCap>,
    #[serde(default)]
    pub sandbox_adapters: BTreeMap<String, SandboxAdapterCap>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityProfileV3 {
    pub cap: String,
    pub resources: BTreeMap<String, ResourceSelection>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadConfigV3 {
    pub name: String,
    pub profile: String,
    pub launcher: String,
    pub admission: Admission,
    pub duration_seconds: u64,
    pub resources: BTreeMap<String, ResourceSelection>,
    #[serde(default)]
    pub operations: crate::policy_v3_operations::OperationSelection,
    #[serde(default)]
    pub workspace_roots: Vec<WorkspaceRootRequest>,
    #[serde(default = "default_sandbox")]
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub desktop: Option<DesktopWorkloadConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfigV3 {
    pub schema: String,
    #[serde(default)]
    pub routing: crate::policy_v2::RoutingConfig,
    pub authority_profiles: BTreeMap<String, AuthorityProfileV3>,
    pub workloads: Vec<WorkloadConfigV3>,
}

/// Product policy output, not proof of native admission or credential enrollment.
pub struct ResolvedWorkloadV3 {
    pub native_user: String,
    pub system_cap: String,
    pub launcher_path: String,
    pub admission: Admission,
    pub duration_seconds: u64,
    pub resources: BTreeMap<LogicalSecretName, ResolvedResource>,
    pub operations: crate::policy_v3_operations::ResolvedOperations,
    pub workspace_roots: Vec<ResolvedWorkspaceRoot>,
    pub sandbox: ResolvedSandbox,
    pub desktop: Option<DesktopWorkloadConfig>,
}

pub fn parse_user_config_v3(input: &[u8]) -> Result<UserConfigV3> {
    let user: UserConfigV3 = decode(input)?;
    user.validate()?;
    Ok(user)
}

pub fn resolve_policy_for_user(
    system: &SystemPolicyV3,
    native_user: &str,
    user: &UserConfigV3,
) -> Result<BTreeMap<String, ResolvedWorkloadV3>> {
    system.validate()?;
    user.validate()?;
    if !system
        .allowed_users
        .iter()
        .any(|allowed| allowed == native_user)
    {
        bail!("native account is outside administrator authority");
    }
    // Validate unused profiles too. A valid selected workload cannot conceal
    // widened or dangling declarations elsewhere in the same config document.
    for profile in user.authority_profiles.values() {
        let cap = system
            .workload_caps
            .get(&profile.cap)
            .context("authority profile has no workload cap")?;
        if !cap.users.iter().any(|allowed| allowed == native_user) {
            bail!("native account is outside workload authority");
        }
        system
            .credentials
            .resolve_validated(native_user, &cap.resource_cap, &profile.resources)?;
    }
    let mut resolved = BTreeMap::new();
    for workload in &user.workloads {
        let profile = user
            .authority_profiles
            .get(&workload.profile)
            .context("workload has no authority profile")?;
        let cap = &system.workload_caps[&profile.cap];
        if !cap.launchers.contains(&workload.launcher) {
            bail!("workload launcher is outside authority");
        }
        if !cap.admission.contains(&workload.admission) {
            bail!("workload admission is outside authority");
        }
        if workload.duration_seconds == 0 || workload.duration_seconds > cap.max_duration_seconds {
            bail!("workload duration is outside authority");
        }
        for (name, requested) in &workload.resources {
            let allowed = profile
                .resources
                .get(name)
                .context("workload resource is outside profile authority")?;
            require_narrowing(requested, allowed)?;
        }
        let resources = system.credentials.resolve_validated(
            native_user,
            &cap.resource_cap,
            &workload.resources,
        )?;
        let operations = cap.operations.resolve(&workload.operations, &resources)?;
        let mut workspace_roots = Vec::new();
        for requested in &workload.workspace_roots {
            if !cap.workspace_caps.contains(&requested.cap) {
                bail!("workspace selection is outside workload authority");
            }
            let allowed = &system.workspace_caps[&requested.cap];
            if requested.access > allowed.access
                || !crate::policy_v2::path_is_within(&requested.path, &allowed.path)
            {
                bail!("workspace selection widens access or path authority");
            }
            workspace_roots.push(ResolvedWorkspaceRoot {
                system_cap: requested.cap.clone(),
                path: requested.path.clone(),
                access: requested.access,
            });
        }
        if workload
            .sandbox
            .adapters
            .iter()
            .any(|adapter| !cap.sandbox_adapters.contains(adapter))
            || (cap.require_sandbox && workload.sandbox.mode != SandboxMode::Required)
        {
            bail!("sandbox selection is outside workload authority");
        }
        resolved.insert(
            workload.name.clone(),
            ResolvedWorkloadV3 {
                native_user: native_user.to_owned(),
                system_cap: profile.cap.clone(),
                launcher_path: system.trusted_launchers[&workload.launcher].clone(),
                admission: workload.admission,
                duration_seconds: workload.duration_seconds,
                resources,
                operations,
                workspace_roots,
                sandbox: ResolvedSandbox {
                    mode: workload.sandbox.mode,
                    adapters: workload.sandbox.adapters.clone(),
                },
                desktop: workload.desktop.clone(),
            },
        );
    }
    Ok(resolved)
}

/// Adapts resolved v3 workload authority to the retained native execution engine.
/// This is not a serialization or v2 policy migration.
pub fn resolve_runtime_policy_for_user(
    system: &SystemPolicyV3,
    native_user: &str,
    user: &UserConfigV3,
) -> Result<crate::policy_v2::ResolvedPolicy> {
    use crate::policy_v2 as execution;
    let resolved = resolve_policy_for_user(system, native_user, user)?;
    let mut authority_profiles = BTreeMap::new();
    let mut workloads = BTreeMap::new();
    for requested in &user.workloads {
        let authority = &resolved[&requested.name];
        let resource = |name: &LogicalSecretName| -> Result<&ResolvedResource> {
            authority
                .resources
                .get(name)
                .context("native operation resource is unresolved")
        };
        let operation_key = |key: &crate::policy_v3_operations::ResolvedSshKey| -> Result<execution::ResolvedOperationKey> {
            let resource = resource(&key.resource)?;
            Ok(execution::ResolvedOperationKey {
                credential_slot: resource.credential_slot().to_owned(),
                key: execution::OperationKeyConfig {
                    private_key_ref: resource.reference.expose_to_provider().to_owned(),
                    public_key: key.public_key.clone(),
                    fingerprint: key.fingerprint.clone(),
                },
            })
        };
        let github = authority
            .operations
            .github
            .as_ref()
            .map(|github| -> Result<_> {
                let resource = resource(&github.resource)?;
                Ok(execution::ResolvedGitHubAuthority {
                    credential_slot: resource.credential_slot().to_owned(),
                    app_cap: github.resource.as_str().to_owned(),
                    app_id: github.app_id,
                    repository_selection: github.repository_selection,
                    private_key_ref: resource.reference.expose_to_provider().to_owned(),
                    owners: github.owners.clone(),
                    repositories: github.repositories.clone(),
                    permissions: github.permissions.clone(),
                    installation_ids: github.installation_ids.clone(),
                })
            })
            .transpose()?;
        let signing_key = authority
            .operations
            .signing
            .as_ref()
            .map(operation_key)
            .transpose()?;
        let ssh_keys = authority
            .operations
            .ssh
            .iter()
            .map(operation_key)
            .collect::<Result<Vec<_>>>()?;
        let release_signing_key = authority
            .operations
            .release_signing
            .as_ref()
            .map(|key| -> Result<_> {
                let resource = resource(&key.resource)?;
                Ok(execution::ResolvedReleaseSigningKey {
                    credential_slot: resource.credential_slot().to_owned(),
                    key: execution::ReleaseSigningKeyConfig {
                        private_key_ref: resource.reference.expose_to_provider().to_owned(),
                        public_key: key.public_key.clone(),
                    },
                })
            })
            .transpose()?;
        // Execution profiles are workload-specific: two workloads selecting the
        // same user profile must not share its unnarrowed superset of grants.
        authority_profiles.insert(
            requested.name.clone(),
            execution::ResolvedAuthorityProfile {
                system_cap: authority.system_cap.clone(),
                credential_slots: authority
                    .resources
                    .values()
                    .map(|resource| resource.credential_slot().to_owned())
                    .collect(),
                github,
                signing: signing_key.is_some(),
                signing_key,
                release_signing_products: authority
                    .operations
                    .release_signing
                    .as_ref()
                    .map(|key| key.products.clone())
                    .unwrap_or_default(),
                release_signing_key,
                ssh: !ssh_keys.is_empty(),
                ssh_keys,
                git_identity: authority.operations.git_identity.clone(),
                // Exportable references are not passed through the legacy engine.
                secret_references: BTreeSet::new(),
                logical_authority: Some(LogicalSelection {
                    cap: authority.system_cap.clone(),
                    resources: requested.resources.clone(),
                }),
            },
        );
        workloads.insert(
            requested.name.clone(),
            execution::ResolvedWorkload {
                launcher: requested.launcher.clone(),
                launcher_path: authority.launcher_path.clone(),
                authority_profile: requested.name.clone(),
                secret_references: Vec::new(),
                workspace_roots: authority.workspace_roots.clone(),
                sandbox: authority.sandbox.clone(),
                desktop: authority.desktop.clone(),
                admission: Some(authority.admission),
                duration_seconds: Some(authority.duration_seconds),
            },
        );
    }
    Ok(execution::ResolvedPolicy {
        mode: system.mode,
        allowed_users: system.allowed_users.iter().cloned().collect(),
        programs: execution::SystemPrograms {
            // A missed legacy provider call fails closed instead of choosing a
            // global provider that could belong to a different credential slot.
            op: String::new(),
            git: system.programs.git.clone(),
            gh: system.programs.gh.clone(),
            ssh: system.programs.ssh.clone(),
            ssh_keygen: system.programs.ssh_keygen.clone(),
        },
        trusted_launchers: system.trusted_launchers.clone(),
        sandbox_adapters: system.sandbox_adapters.clone(),
        routing: execution::ResolvedRouting {
            no_session: user.routing.no_session,
            invalid_session: execution::InvalidSessionRouting::Deny,
            help_footer: user.routing.help_footer,
        },
        authority_profiles,
        workloads,
    })
}

impl UserConfigV3 {
    fn validate(&self) -> Result<()> {
        if self.schema != "dev-auth-user-config-v3" {
            bail!("unsupported user configuration schema");
        }
        if self.authority_profiles.len() > 256 || self.workloads.len() > 256 {
            bail!("user configuration exceeds the declaration limit");
        }
        for (name, profile) in &self.authority_profiles {
            LogicalSecretName::parse(name)?;
            LogicalSecretName::parse(&profile.cap)?;
            validate_selections(&profile.resources)?;
        }
        let mut names = BTreeSet::new();
        for workload in &self.workloads {
            LogicalSecretName::parse(&workload.name)?;
            if workload.name.is_empty()
                || workload.name.len() > 64
                || !workload.name.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_')
                })
            {
                bail!("workload name is invalid");
            }
            LogicalSecretName::parse(&workload.profile)?;
            LogicalSecretName::parse(&workload.launcher)?;
            if !names.insert(&workload.name) {
                bail!("user configuration has duplicate workloads");
            }
            validate_selections(&workload.resources)?;
            if workload.workspace_roots.len() > 64 || workload.sandbox.adapters.len() > 32 {
                bail!("workload execution selection exceeds the declaration limit");
            }
            let mut roots = BTreeSet::new();
            for root in &workload.workspace_roots {
                crate::policy_v2::validate_canonical_absolute_path(
                    &root.path,
                    "workload workspace",
                )?;
                if !roots.insert(&root.path) {
                    bail!("workload workspace selection is duplicated");
                }
            }
            if workload
                .sandbox
                .adapters
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != workload.sandbox.adapters.len()
                || (workload.sandbox.mode == SandboxMode::None
                    && !workload.sandbox.adapters.is_empty())
                || (workload.sandbox.mode == SandboxMode::Required
                    && workload.sandbox.adapters.is_empty())
            {
                bail!("workload sandbox selection is invalid");
            }
            if let Some(desktop) = &workload.desktop {
                if desktop.display_name.is_empty()
                    || desktop.display_name.len() > 128
                    || desktop.display_name.chars().any(char::is_control)
                    || desktop.icon.as_ref().is_some_and(|icon| {
                        icon.is_empty()
                            || icon.len() > 256
                            || !icon.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric()
                                    || matches!(byte, b'/' | b'.' | b'_' | b'-')
                            })
                    })
                {
                    bail!("workload desktop selection is invalid");
                }
            }
        }
        Ok(())
    }
}

fn default_sandbox() -> SandboxConfig {
    SandboxConfig {
        mode: SandboxMode::None,
        adapters: Vec::new(),
    }
}

fn validate_selections(resources: &BTreeMap<String, ResourceSelection>) -> Result<()> {
    if resources.len() > 1024 {
        bail!("resource selection exceeds the declaration limit");
    }
    for (name, selected) in resources {
        LogicalSecretName::parse(name)?;
        require_narrowing(selected, selected)?;
    }
    Ok(())
}

pub fn parse_system_policy_v3(input: &[u8]) -> Result<SystemPolicyV3> {
    let policy: SystemPolicyV3 = decode(input)?;
    policy.validate()?;
    Ok(policy)
}

pub fn require_system_policy_narrows(upper: &SystemPolicyV3, lower: &SystemPolicyV3) -> Result<()> {
    upper.validate()?;
    lower.validate()?;
    if upper.mode != lower.mode
        || upper.programs != lower.programs
        || !subset(&lower.allowed_users, &upper.allowed_users)
    {
        bail!("narrowing policy changes native authority");
    }
    exact_subset(&upper.trusted_launchers, &lower.trusted_launchers)?;
    exact_subset(&upper.sandbox_adapters, &lower.sandbox_adapters)?;
    for (name, provider) in &lower.credentials.providers {
        let allowed = upper
            .credentials
            .providers
            .get(name)
            .context("narrowing introduces provider")?;
        let crate::logical_authority::ProviderInstance::OnePassword { executable } = provider;
        let crate::logical_authority::ProviderInstance::OnePassword {
            executable: allowed_executable,
        } = allowed;
        if executable != allowed_executable {
            bail!("narrowing changes provider authority");
        }
    }
    for (name, slot) in &lower.credentials.credential_slots {
        let allowed = upper
            .credentials
            .credential_slots
            .get(name)
            .context("narrowing introduces credential slot")?;
        if slot.provider != allowed.provider || !subset(&slot.users, &allowed.users) {
            bail!("narrowing changes credential slot authority");
        }
    }
    for (name, resource) in &lower.credentials.resources {
        let allowed = upper
            .credentials
            .resources
            .get(name)
            .context("narrowing introduces resource")?;
        if resource.credential_slot != allowed.credential_slot
            || resource.reference != allowed.reference
            || resource.kind != allowed.kind
            || !subset(&resource.purposes, &allowed.purposes)
            || !subset(&resource.projections, &allowed.projections)
        {
            bail!("narrowing changes logical resource authority");
        }
    }
    for (name, cap) in &lower.credentials.resource_caps {
        let allowed = upper
            .credentials
            .resource_caps
            .get(name)
            .context("narrowing introduces resource cap")?;
        if !subset(&cap.users, &allowed.users) {
            bail!("narrowing widens resource accounts");
        }
        for (name, selection) in &cap.resources {
            require_narrowing(
                selection,
                allowed
                    .resources
                    .get(name)
                    .context("narrowing introduces resource selection")?,
            )?;
        }
    }
    for (name, cap) in &lower.workspace_caps {
        let allowed = upper
            .workspace_caps
            .get(name)
            .context("narrowing introduces workspace")?;
        if cap.access > allowed.access
            || !crate::policy_v2::path_is_within(&cap.path, &allowed.path)
        {
            bail!("narrowing widens workspace authority");
        }
    }
    for (name, cap) in &lower.workload_caps {
        let allowed = upper
            .workload_caps
            .get(name)
            .context("narrowing introduces workload cap")?;
        if cap.resource_cap != allowed.resource_cap
            || !subset(&cap.users, &allowed.users)
            || !subset(&cap.launchers, &allowed.launchers)
            || !subset(&cap.admission, &allowed.admission)
            || cap.max_duration_seconds > allowed.max_duration_seconds
            || !subset(&cap.workspace_caps, &allowed.workspace_caps)
            || !subset(&cap.sandbox_adapters, &allowed.sandbox_adapters)
            || (allowed.require_sandbox && !cap.require_sandbox)
        {
            bail!("narrowing widens workload authority");
        }
        allowed.operations.require_narrows(&cap.operations)?;
    }
    Ok(())
}

fn subset<T: PartialEq>(lower: &[T], upper: &[T]) -> bool {
    lower.iter().all(|value| upper.contains(value))
}

fn exact_subset<T: PartialEq>(
    upper: &BTreeMap<String, T>,
    lower: &BTreeMap<String, T>,
) -> Result<()> {
    if lower
        .iter()
        .any(|(name, value)| upper.get(name) != Some(value))
    {
        bail!("narrowing changes a pinned authority");
    }
    Ok(())
}

fn decode<T: DeserializeOwned>(input: &[u8]) -> Result<T> {
    if input.len() > DOCUMENT_LIMIT {
        bail!("authority document exceeds the size limit");
    }
    let text = std::str::from_utf8(input)
        .map_err(|_| anyhow::anyhow!("authority document is not UTF-8"))?;
    toml::from_str(text).map_err(|_| anyhow::anyhow!("authority document is not valid TOML"))
}

impl SystemPolicyV3 {
    pub fn validate(&self) -> Result<()> {
        if self.schema != "dev-auth-administrator-policy-v3" {
            bail!("unsupported administrator policy schema");
        }
        validate_users(&self.allowed_users)?;
        self.credentials.validate()?;
        if self.trusted_launchers.len() > 256
            || self.workload_caps.len() > 256
            || self.workspace_caps.len() > 256
            || self.sandbox_adapters.len() > 32
        {
            bail!("workload authority exceeds the declaration limit");
        }
        for program in [
            &self.programs.git,
            &self.programs.gh,
            &self.programs.ssh,
            &self.programs.ssh_keygen,
        ] {
            validate_absolute_executable(program, "native program")?;
        }
        for (name, path) in &self.trusted_launchers {
            LogicalSecretName::parse(name)?;
            validate_absolute_executable(path, "trusted launcher")?;
        }
        for (name, cap) in &self.workspace_caps {
            LogicalSecretName::parse(name)?;
            crate::policy_v2::validate_canonical_absolute_path(&cap.path, "workspace cap")?;
        }
        crate::policy_v2::ensure_unique_workspace_cap_paths(&self.workspace_caps)?;
        for (name, adapter) in &self.sandbox_adapters {
            LogicalSecretName::parse(name)?;
            validate_absolute_executable(&adapter.executable, "sandbox adapter")?;
            if name == "native"
                || adapter.arguments.len() > 128
                || adapter.arguments.iter().any(|argument| {
                    argument.is_empty() || argument.len() > 4096 || argument.contains('\0')
                })
            {
                bail!("sandbox adapter definition is invalid");
            }
            crate::policy_v2::validate_sandbox_mount_arguments(
                &adapter.read_only_mount_arguments,
                "read-only mount",
            )?;
            crate::policy_v2::validate_sandbox_mount_arguments(
                &adapter.read_write_mount_arguments,
                "read-write mount",
            )?;
        }
        for (name, slot) in &self.credentials.credential_slots {
            if name.len() > 64 {
                bail!("credential slot exceeds the native identifier limit");
            }
            if slot
                .users
                .iter()
                .any(|user| !self.allowed_users.contains(user))
            {
                bail!("credential slot widens administrator account authority");
            }
        }
        for cap in self.credentials.resource_caps.values() {
            if cap
                .users
                .iter()
                .any(|user| !self.allowed_users.contains(user))
            {
                bail!("resource cap widens administrator account authority");
            }
        }
        for (name, cap) in &self.workload_caps {
            LogicalSecretName::parse(name)?;
            validate_users(&cap.users)?;
            cap.operations
                .validate(&self.credentials, &cap.resource_cap)?;
            let resources = self
                .credentials
                .resource_caps
                .get(&cap.resource_cap)
                .context("workload cap has no resource cap")?;
            if cap
                .users
                .iter()
                .any(|user| !self.allowed_users.contains(user) || !resources.users.contains(user))
            {
                bail!("workload cap widens account authority");
            }
            if cap.launchers.is_empty()
                || cap.launchers.len() > 256
                || cap.launchers.iter().collect::<BTreeSet<_>>().len() != cap.launchers.len()
                || cap
                    .launchers
                    .iter()
                    .any(|launcher| !self.trusted_launchers.contains_key(launcher))
            {
                bail!("workload cap has invalid launcher authority");
            }
            if cap.admission.is_empty()
                || cap.admission.iter().collect::<BTreeSet<_>>().len() != cap.admission.len()
            {
                bail!("workload cap has empty or duplicated admission authority");
            }
            for (selected, declared) in [
                (
                    &cap.workspace_caps,
                    self.workspace_caps.keys().collect::<BTreeSet<_>>(),
                ),
                (
                    &cap.sandbox_adapters,
                    self.sandbox_adapters.keys().collect::<BTreeSet<_>>(),
                ),
            ] {
                if selected.len() > 256
                    || selected.iter().collect::<BTreeSet<_>>().len() != selected.len()
                    || selected.iter().any(|name| !declared.contains(name))
                {
                    bail!("workload cap selects invalid execution authority");
                }
            }
            if cap.require_sandbox && cap.sandbox_adapters.is_empty() {
                bail!("required sandbox authority has no adapter");
            }
            // There is no product-wide hours cap. Arithmetic and native clock
            // representability are checked again when fixing the actual deadline.
            if cap.max_duration_seconds == 0 {
                bail!("workload duration authority must be positive");
            }
        }
        Ok(())
    }
}
