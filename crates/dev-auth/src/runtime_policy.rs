//! Explicit installed-policy dispatch; authority versions are never inferred.
use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Clone)]
pub enum RuntimeAdministrator {
    Legacy(crate::policy_v2::SystemPolicyV2),
    Logical(crate::policy_v3::SystemPolicyV3),
}

pub fn parse_runtime_administrator(input: &[u8]) -> Result<RuntimeAdministrator> {
    #[derive(Deserialize)]
    struct Header {
        version: Option<u32>,
        schema: Option<String>,
    }
    if input.len() > 1024 * 1024 {
        bail!("administrator policy exceeds the size limit");
    }
    let text = std::str::from_utf8(input)
        .map_err(|_| anyhow::anyhow!("administrator policy is not UTF-8"))?;
    // This partial decode chooses a parser, not authority. The selected parser
    // still rejects every unknown field in the complete document.
    let header: Header = toml::from_str(text)
        .map_err(|_| anyhow::anyhow!("administrator policy is not valid TOML"))?;
    match (header.version, header.schema.as_deref()) {
        (Some(2), None) => Ok(RuntimeAdministrator::Legacy(
            crate::policy_v2::parse_system_policy_v2(input)?,
        )),
        (None, Some("dev-auth-administrator-policy-v3")) => Ok(RuntimeAdministrator::Logical(
            crate::policy_v3::parse_system_policy_v3(input)?,
        )),
        _ => bail!("administrator policy version is unsupported or ambiguous"),
    }
}

impl RuntimeAdministrator {
    pub fn allowed_users(&self) -> &[String] {
        match self {
            Self::Legacy(policy) => &policy.allowed_users,
            Self::Logical(policy) => &policy.allowed_users,
        }
    }

    pub fn authority_schema(&self) -> Option<&'static str> {
        match self {
            Self::Legacy(_) => None,
            Self::Logical(_) => Some("dev-auth-administrator-policy-v3"),
        }
    }

    pub fn require_narrows(&self, candidate: &Self) -> Result<()> {
        match (self, candidate) {
            (Self::Legacy(upper), Self::Legacy(lower)) => {
                crate::policy_v2::require_system_policy_narrows(upper, lower)
            }
            (Self::Logical(upper), Self::Logical(lower)) => {
                crate::policy_v3::require_system_policy_narrows(upper, lower)
            }
            _ => bail!("narrowing across this authority version is not available"),
        }
    }

    /// Pinned native programs. V3 provider programs have a separate namespace.
    pub fn programs(&self) -> std::collections::BTreeMap<&str, &str> {
        match self {
            Self::Legacy(policy) => std::collections::BTreeMap::from([
                ("git", policy.programs.git.as_str()),
                ("gh", policy.programs.gh.as_str()),
                ("ssh", policy.programs.ssh.as_str()),
                ("ssh_keygen", policy.programs.ssh_keygen.as_str()),
                ("op", policy.programs.op.as_str()),
            ]),
            Self::Logical(policy) => std::collections::BTreeMap::from([
                ("git", policy.programs.git.as_str()),
                ("gh", policy.programs.gh.as_str()),
                ("ssh", policy.programs.ssh.as_str()),
                ("ssh_keygen", policy.programs.ssh_keygen.as_str()),
            ]),
        }
    }

    pub fn provider_programs(&self) -> std::collections::BTreeMap<&str, &str> {
        match self {
            Self::Legacy(_) => std::collections::BTreeMap::new(),
            Self::Logical(policy) => policy
                .credentials
                .providers
                .iter()
                .map(|(name, provider)| {
                    let crate::logical_authority::ProviderInstance::OnePassword { executable } =
                        provider;
                    (name.as_str(), executable.as_str())
                })
                .collect(),
        }
    }

    pub fn trusted_launchers(&self) -> &std::collections::BTreeMap<String, String> {
        match self {
            Self::Legacy(policy) => &policy.trusted_launchers,
            Self::Logical(policy) => &policy.trusted_launchers,
        }
    }

    pub fn sandbox_adapters(
        &self,
    ) -> &std::collections::BTreeMap<String, crate::policy_v2::SandboxAdapterCap> {
        match self {
            Self::Legacy(policy) => &policy.sandbox_adapters,
            Self::Logical(policy) => &policy.sandbox_adapters,
        }
    }

    pub fn resolve_user(
        &self,
        native_user: &str,
        input: &[u8],
    ) -> Result<crate::policy_v2::ResolvedPolicy> {
        if input.len() > 1024 * 1024 {
            bail!("user configuration exceeds the size limit");
        }
        match self {
            Self::Legacy(policy) => crate::policy_v2::resolve_policy_for_user(
                policy,
                native_user,
                &crate::policy_v2::parse_user_config_v2(input)?,
            ),
            Self::Logical(policy) => crate::policy_v3::resolve_runtime_policy_for_user(
                policy,
                native_user,
                &crate::policy_v3::parse_user_config_v3(input)?,
            ),
        }
    }

    pub fn mode(&self) -> crate::policy_v2::SystemMode {
        match self {
            Self::Legacy(policy) => policy.mode,
            Self::Logical(policy) => policy.mode,
        }
    }

    pub fn credential_slot_names(&self) -> Vec<&str> {
        match self {
            Self::Legacy(policy) => policy.credential_slots.keys().map(String::as_str).collect(),
            Self::Logical(policy) => policy
                .credentials
                .credential_slots
                .keys()
                .map(String::as_str)
                .collect(),
        }
    }

    pub fn provider_program(&self, credential_slot: &str) -> Result<&str> {
        match self {
            Self::Legacy(policy) => {
                if !policy.credential_slots.contains_key(credential_slot) {
                    bail!("credential slot is outside administrator policy");
                }
                Ok(&policy.programs.op)
            }
            Self::Logical(policy) => {
                let slot = policy
                    .credentials
                    .credential_slots
                    .get(credential_slot)
                    .context("credential slot is outside administrator policy")?;
                match policy
                    .credentials
                    .providers
                    .get(&slot.provider)
                    .context("credential provider is outside administrator policy")?
                {
                    crate::logical_authority::ProviderInstance::OnePassword { executable } => {
                        Ok(executable)
                    }
                }
            }
        }
    }
}
