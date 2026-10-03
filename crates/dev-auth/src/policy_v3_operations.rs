//! Operation capabilities select logical resources, never provider references.
use crate::logical_authority::{
    CredentialAuthority, ResolvedResource, ResourceKind, ResourcePurpose,
};
use crate::policy_v2::{validate_github_scope, GitIdentityConfig, Permission};
use anyhow::{bail, Context, Result};
use dev_tools_secret::LogicalSecretName;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubCap {
    pub app_id: u64,
    pub repository_selection: crate::RepositorySelection,
    pub owners: Vec<String>,
    #[serde(default)]
    pub repositories: Vec<String>,
    pub permissions: BTreeMap<String, Permission>,
    #[serde(default)]
    pub installation_ids: Vec<u64>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshKeyCap {
    pub public_key: String,
    pub fingerprint: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseKeyCap {
    pub public_key: String,
    pub products: Vec<String>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationAuthority {
    #[serde(default)]
    pub github: BTreeMap<String, GitHubCap>,
    #[serde(default)]
    pub signing: BTreeMap<String, SshKeyCap>,
    #[serde(default)]
    pub ssh: BTreeMap<String, SshKeyCap>,
    #[serde(default)]
    pub release_signing: BTreeMap<String, ReleaseKeyCap>,
    #[serde(default)]
    pub git_identities: Vec<GitIdentityConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubSelection {
    pub resource: String,
    pub owners: Vec<String>,
    #[serde(default)]
    pub repositories: Vec<String>,
    pub permissions: BTreeMap<String, Permission>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSelection {
    pub resource: String,
    pub products: Vec<String>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationSelection {
    #[serde(default)]
    pub github: Option<GitHubSelection>,
    #[serde(default)]
    pub signing: Option<String>,
    #[serde(default)]
    pub ssh: Vec<String>,
    #[serde(default)]
    pub release_signing: Option<ReleaseSelection>,
    #[serde(default)]
    pub git_identity: Option<GitIdentityConfig>,
}

pub struct ResolvedGitHub {
    pub resource: LogicalSecretName,
    pub app_id: u64,
    pub repository_selection: crate::RepositorySelection,
    pub owners: BTreeSet<String>,
    pub repositories: BTreeSet<String>,
    pub permissions: BTreeMap<String, Permission>,
    pub installation_ids: BTreeSet<u64>,
}

pub struct ResolvedSshKey {
    pub resource: LogicalSecretName,
    pub public_key: String,
    pub fingerprint: String,
}

pub struct ResolvedReleaseKey {
    pub resource: LogicalSecretName,
    pub public_key: String,
    pub products: BTreeSet<String>,
}

#[derive(Default)]
pub struct ResolvedOperations {
    pub github: Option<ResolvedGitHub>,
    pub signing: Option<ResolvedSshKey>,
    pub ssh: Vec<ResolvedSshKey>,
    pub release_signing: Option<ResolvedReleaseKey>,
    pub git_identity: Option<GitIdentityConfig>,
}

impl OperationAuthority {
    pub(crate) fn require_narrows(&self, lower: &Self) -> Result<()> {
        for (name, cap) in &lower.github {
            let allowed = self
                .github
                .get(name)
                .context("narrowing introduces GitHub authority")?;
            if cap.app_id != allowed.app_id
                || cap.repository_selection != allowed.repository_selection
                || !canonical(&cap.owners).is_subset(&canonical(&allowed.owners))
                || (!allowed.repositories.is_empty()
                    && (cap.repositories.is_empty()
                        || !canonical(&cap.repositories)
                            .is_subset(&canonical(&allowed.repositories))))
                || (!allowed.installation_ids.is_empty()
                    && (cap.installation_ids.is_empty()
                        || cap
                            .installation_ids
                            .iter()
                            .any(|id| !allowed.installation_ids.contains(id))))
                || cap.permissions.iter().any(|(name, right)| {
                    !allowed
                        .permissions
                        .get(name)
                        .is_some_and(|maximum| right <= maximum)
                })
            {
                bail!("narrowing widens GitHub authority");
            }
        }
        for (lower, upper) in [(&lower.signing, &self.signing), (&lower.ssh, &self.ssh)] {
            for (name, cap) in lower {
                let allowed = upper
                    .get(name)
                    .context("narrowing introduces signing authority")?;
                if cap.public_key != allowed.public_key || cap.fingerprint != allowed.fingerprint {
                    bail!("narrowing changes signing identity");
                }
            }
        }
        for (name, cap) in &lower.release_signing {
            let allowed = self
                .release_signing
                .get(name)
                .context("narrowing introduces release authority")?;
            if cap.public_key != allowed.public_key
                || !product_set(&cap.products)?.is_subset(&product_set(&allowed.products)?)
            {
                bail!("narrowing widens release authority");
            }
        }
        if lower
            .git_identities
            .iter()
            .any(|identity| !self.git_identities.contains(identity))
        {
            bail!("narrowing changes Git identity");
        }
        Ok(())
    }

    pub(crate) fn validate(&self, credentials: &CredentialAuthority, cap: &str) -> Result<()> {
        if self.github.len() > 1024
            || self.signing.len() > 1024
            || self.ssh.len() > 1024
            || self.release_signing.len() > 1024
            || self.git_identities.len() > 256
        {
            bail!("operation authority exceeds the declaration limit");
        }
        for (name, github) in &self.github {
            require_operation_resource(credentials, cap, name, ResourcePurpose::GitHubToken)?;
            validate_github_scope(
                &github.owners,
                &github.repositories,
                &github.permissions,
                "GitHub cap",
            )?;
            if github.app_id == 0
                || github.installation_ids.len() > 1024
                || github.installation_ids.contains(&0)
                || github
                    .installation_ids
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    != github.installation_ids.len()
            {
                bail!("GitHub operation cap has invalid application or installation authority");
            }
        }
        for (keys, purpose) in [
            (&self.signing, ResourcePurpose::GitSigning),
            (&self.ssh, ResourcePurpose::SshAuthentication),
        ] {
            for (name, key) in keys {
                require_operation_resource(credentials, cap, name, purpose)?;
                let public = ssh_key::PublicKey::from_openssh(&key.public_key)
                    .map_err(|_| anyhow::anyhow!("SSH operation public key is invalid"))?;
                if public.fingerprint(ssh_key::HashAlg::Sha256).to_string() != key.fingerprint {
                    bail!("SSH operation key fingerprint does not match");
                }
            }
        }
        for (name, key) in &self.release_signing {
            require_operation_resource(credentials, cap, name, ResourcePurpose::ReleaseSigning)?;
            dev_tools_release::parse_release_public_key(&key.public_key)
                .map_err(|_| anyhow::anyhow!("release operation public key is invalid"))?;
            product_set(&key.products)?;
        }
        let mut identities = BTreeSet::new();
        for identity in &self.git_identities {
            crate::validate_git_author(&identity.name, &identity.email)
                .map_err(|_| anyhow::anyhow!("Git identity is invalid"))?;
            if !identities.insert(identity) {
                bail!("operation authority contains duplicate Git identities");
            }
        }
        Ok(())
    }

    pub(crate) fn resolve(
        &self,
        selected: &OperationSelection,
        resources: &BTreeMap<LogicalSecretName, ResolvedResource>,
    ) -> Result<ResolvedOperations> {
        let github = selected
            .github
            .as_ref()
            .map(|requested| {
                let resource = require_selected_resource(
                    resources,
                    &requested.resource,
                    ResourcePurpose::GitHubToken,
                )?;
                let allowed = self
                    .github
                    .get(&requested.resource)
                    .context("GitHub operation is outside authority")?;
                validate_github_scope(
                    &requested.owners,
                    &requested.repositories,
                    &requested.permissions,
                    "GitHub selection",
                )?;
                let owners = canonical(&requested.owners);
                let repositories = canonical(&requested.repositories);
                if !owners.is_subset(&canonical(&allowed.owners))
                    || (!allowed.repositories.is_empty()
                        && (repositories.is_empty()
                            || !repositories.is_subset(&canonical(&allowed.repositories))))
                    || requested.permissions.iter().any(|(name, right)| {
                        !allowed
                            .permissions
                            .get(name)
                            .is_some_and(|allowed| right <= allowed)
                    })
                {
                    bail!("GitHub operation widens scope authority");
                }
                Ok(ResolvedGitHub {
                    resource,
                    app_id: allowed.app_id,
                    repository_selection: allowed.repository_selection,
                    owners,
                    repositories,
                    permissions: requested.permissions.clone(),
                    installation_ids: allowed.installation_ids.iter().copied().collect(),
                })
            })
            .transpose()?;
        let signing = selected
            .signing
            .as_ref()
            .map(|name| {
                resolve_ssh_key(&self.signing, resources, name, ResourcePurpose::GitSigning)
            })
            .transpose()?;
        if selected.ssh.len() > 64
            || selected.ssh.iter().collect::<BTreeSet<_>>().len() != selected.ssh.len()
        {
            bail!("SSH key selection is oversized or duplicated");
        }
        let ssh = selected
            .ssh
            .iter()
            .map(|name| {
                resolve_ssh_key(
                    &self.ssh,
                    resources,
                    name,
                    ResourcePurpose::SshAuthentication,
                )
            })
            .collect::<Result<_>>()?;
        let release_signing = selected
            .release_signing
            .as_ref()
            .map(|requested| {
                let resource = require_selected_resource(
                    resources,
                    &requested.resource,
                    ResourcePurpose::ReleaseSigning,
                )?;
                let allowed = self
                    .release_signing
                    .get(&requested.resource)
                    .context("release operation is outside authority")?;
                let products = product_set(&requested.products)?;
                if !products.is_subset(&product_set(&allowed.products)?) {
                    bail!("release operation widens product authority");
                }
                Ok(ResolvedReleaseKey {
                    resource,
                    public_key: allowed.public_key.clone(),
                    products,
                })
            })
            .transpose()?;
        if selected
            .git_identity
            .as_ref()
            .is_some_and(|identity| !self.git_identities.contains(identity))
        {
            bail!("Git identity is outside authority");
        }
        Ok(ResolvedOperations {
            github,
            signing,
            ssh,
            release_signing,
            git_identity: selected.git_identity.clone(),
        })
    }
}

fn require_operation_resource(
    credentials: &CredentialAuthority,
    cap: &str,
    name: &str,
    purpose: ResourcePurpose,
) -> Result<()> {
    LogicalSecretName::parse(name)?;
    let resource = credentials
        .resources
        .get(name)
        .context("operation resource is undeclared")?;
    let selected = credentials
        .resource_caps
        .get(cap)
        .and_then(|cap| cap.resources.get(name))
        .context("operation resource is outside the resource cap")?;
    if resource.kind != ResourceKind::OperationOnly || !selected.purposes.contains(&purpose) {
        bail!("operation resource has invalid purpose or export authority");
    }
    Ok(())
}

fn require_selected_resource(
    resources: &BTreeMap<LogicalSecretName, ResolvedResource>,
    name: &str,
    purpose: ResourcePurpose,
) -> Result<LogicalSecretName> {
    let name = LogicalSecretName::parse(name)?;
    if !resources
        .get(&name)
        .is_some_and(|resource| resource.allows(purpose))
    {
        bail!("operation requires selected logical resource purpose");
    }
    Ok(name)
}

fn resolve_ssh_key(
    keys: &BTreeMap<String, SshKeyCap>,
    resources: &BTreeMap<LogicalSecretName, ResolvedResource>,
    name: &str,
    purpose: ResourcePurpose,
) -> Result<ResolvedSshKey> {
    let resource = require_selected_resource(resources, name, purpose)?;
    let key = keys
        .get(name)
        .context("SSH operation is outside authority")?;
    Ok(ResolvedSshKey {
        resource,
        public_key: key.public_key.clone(),
        fingerprint: key.fingerprint.clone(),
    })
}

fn canonical(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn product_set(values: &[String]) -> Result<BTreeSet<String>> {
    if values.is_empty() || values.len() > 256 {
        bail!("release product selection is empty or oversized");
    }
    let mut products = BTreeSet::new();
    for value in values {
        LogicalSecretName::parse(value)?;
        if !products.insert(value.clone()) {
            bail!("release product selection is duplicated");
        }
    }
    Ok(products)
}
