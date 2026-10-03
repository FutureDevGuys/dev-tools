//! Credential portion of administrator policy v3. Resolution is not admission.
//!
//! The broker must supply the authenticated native user, selected administrator
//! cap and narrowed workload request. These in-memory grants are not receipts.
use anyhow::{bail, Context, Result};
use dev_tools_secret::{LogicalSecretName, ProviderId, SecretReference};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ResourcePurpose {
    Read,
    Public,
    #[serde(rename = "github_token")]
    GitHubToken,
    SshAuthentication,
    GitSigning,
    ReleaseSigning,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Projection {
    Stdin,
    Descriptor,
    File,
    Environment,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Exportable,
    OperationOnly,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderInstance {
    OnePassword { executable: String },
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSlot {
    pub provider: String,
    pub users: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBinding {
    pub credential_slot: String,
    pub reference: String,
    pub kind: ResourceKind,
    pub purposes: Vec<ResourcePurpose>,
    #[serde(default)]
    pub projections: Vec<Projection>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceSelection {
    pub purposes: Vec<ResourcePurpose>,
    #[serde(default)]
    pub projections: Vec<Projection>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceCap {
    pub users: Vec<String>,
    pub resources: BTreeMap<String, ResourceSelection>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialAuthority {
    pub providers: BTreeMap<String, ProviderInstance>,
    pub credential_slots: BTreeMap<String, CredentialSlot>,
    pub resources: BTreeMap<String, ResourceBinding>,
    pub resource_caps: BTreeMap<String, ResourceCap>,
}

/// Contains an opaque provider reference and deliberately has no Debug or serde.
pub struct ResolvedResource {
    pub(crate) provider: ProviderId,
    pub(crate) credential_slot: String,
    pub(crate) reference: SecretReference,
    pub(crate) purposes: BTreeSet<ResourcePurpose>,
    pub(crate) projections: BTreeSet<Projection>,
}

impl ResolvedResource {
    pub fn provider(&self) -> &ProviderId {
        &self.provider
    }
    pub fn credential_slot(&self) -> &str {
        &self.credential_slot
    }
    pub fn allows(&self, purpose: ResourcePurpose) -> bool {
        self.purposes.contains(&purpose)
    }
    pub fn allows_projection(&self, projection: Projection) -> bool {
        self.projections.contains(&projection)
    }

    pub fn read_exportable(
        &self,
        provider: &dyn dev_tools_secret::SecretProvider,
        credential_slot: &str,
        context: dev_tools_secret::OperationContext<'_>,
    ) -> std::result::Result<dev_tools_secret::SecretMaterial, dev_tools_secret::SecretError> {
        use dev_tools_secret::{SecretError, SecretErrorKind, SecretPurpose};
        context.checkpoint()?;
        if provider.id() != &self.provider
            || credential_slot != self.credential_slot
            || !self.allows(ResourcePurpose::Read)
        {
            return Err(SecretError::new(SecretErrorKind::PermissionDenied));
        }
        let capabilities = provider.capabilities();
        if !capabilities.exportable_read || !capabilities.metadata {
            return Err(SecretError::new(SecretErrorKind::Unsupported));
        }
        let metadata = provider.metadata(&self.reference, SecretPurpose::Export, context)?;
        context.checkpoint()?;
        if !metadata.exportable {
            return Err(SecretError::new(SecretErrorKind::PermissionDenied));
        }
        let material = provider.read_exportable(&self.reference, context)?;
        context.checkpoint()?;
        Ok(material)
    }

    pub fn public_material(
        &self,
        provider: &dyn dev_tools_secret::SecretProvider,
        credential_slot: &str,
        context: dev_tools_secret::OperationContext<'_>,
    ) -> std::result::Result<dev_tools_secret::PublicMaterial, dev_tools_secret::SecretError> {
        use dev_tools_secret::{SecretError, SecretErrorKind, SecretPurpose};
        context.checkpoint()?;
        if provider.id() != &self.provider
            || credential_slot != self.credential_slot
            || !self.allows(ResourcePurpose::Public)
        {
            return Err(SecretError::new(SecretErrorKind::PermissionDenied));
        }
        let capabilities = provider.capabilities();
        if !capabilities.public_material || !capabilities.metadata {
            return Err(SecretError::new(SecretErrorKind::Unsupported));
        }
        let metadata =
            provider.metadata(&self.reference, SecretPurpose::PublicMaterial, context)?;
        context.checkpoint()?;
        if !metadata.public_material {
            return Err(SecretError::new(SecretErrorKind::PermissionDenied));
        }
        let material = provider.public_material(&self.reference, context)?;
        context.checkpoint()?;
        Ok(material)
    }
}

impl CredentialAuthority {
    /// Validates even unused declarations before any grants can be resolved.
    pub fn validate(&self) -> Result<()> {
        if self.providers.len() > 32
            || self.credential_slots.len() > 64
            || self.resources.len() > 1024
            || self.resource_caps.len() > 256
        {
            bail!("credential authority exceeds the declaration limit");
        }
        for (name, provider) in &self.providers {
            ProviderId::parse(name)?;
            match provider {
                ProviderInstance::OnePassword { executable } => {
                    use std::path::{Component, Path};
                    if !Path::new(executable).is_absolute()
                        || executable.contains('\0')
                        || !Path::new(executable).components().all(|component| {
                            matches!(
                                component,
                                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
                            )
                        })
                    {
                        bail!("provider executable is not a normal absolute path");
                    }
                }
            }
        }
        for (name, slot) in &self.credential_slots {
            ProviderId::parse(name)?;
            if !self.providers.contains_key(&slot.provider) {
                bail!("credential slot has no declared provider");
            }
            validate_users(&slot.users)?;
        }
        let mut identities = BTreeMap::new();
        for (name, binding) in &self.resources {
            LogicalSecretName::parse(name)?;
            let slot = self
                .credential_slots
                .get(&binding.credential_slot)
                .context("resource has no declared credential slot")?;
            SecretReference::new(&binding.reference)?;
            match self
                .providers
                .get(&slot.provider)
                .context("resource provider is unavailable")?
            {
                ProviderInstance::OnePassword { .. } => {
                    crate::validate_op_reference(&binding.reference).map_err(|_| {
                        anyhow::anyhow!("resource has an invalid provider reference")
                    })?
                }
            }
            let rights = selection_sets(&ResourceSelection {
                purposes: binding.purposes.clone(),
                projections: binding.projections.clone(),
            })?;
            if binding.kind == ResourceKind::OperationOnly
                && (rights.0.contains(&ResourcePurpose::Read) || !rights.1.is_empty())
            {
                bail!("operation-only resource cannot be exported or projected");
            }
            // A second logical name or credential slot cannot bypass the
            // nonexportability of the same provider-native resource.
            if identities
                .insert((&slot.provider, &binding.reference), binding.kind)
                .is_some_and(|kind| kind != binding.kind)
            {
                bail!("resource aliases have conflicting export authority");
            }
        }
        for (name, cap) in &self.resource_caps {
            LogicalSecretName::parse(name)?;
            validate_users(&cap.users)?;
            if cap.resources.len() > 1024 {
                bail!("resource cap exceeds the declaration limit");
            }
            for (name, selected) in &cap.resources {
                let binding = self
                    .resources
                    .get(name)
                    .context("resource cap names an undeclared resource")?;
                let slot = &self.credential_slots[&binding.credential_slot];
                if cap.users.iter().any(|user| !slot.users.contains(user)) {
                    bail!("resource cap widens credential-slot account authority");
                }
                require_narrowing(
                    selected,
                    &ResourceSelection {
                        purposes: binding.purposes.clone(),
                        projections: binding.projections.clone(),
                    },
                )?;
            }
        }
        Ok(())
    }

    pub fn resolve(
        &self,
        native_user: &str,
        cap: &str,
        requested: &BTreeMap<String, ResourceSelection>,
    ) -> Result<BTreeMap<LogicalSecretName, ResolvedResource>> {
        self.validate()?;
        self.resolve_validated(native_user, cap, requested)
    }

    pub(crate) fn resolve_validated(
        &self,
        native_user: &str,
        cap: &str,
        requested: &BTreeMap<String, ResourceSelection>,
    ) -> Result<BTreeMap<LogicalSecretName, ResolvedResource>> {
        validate_users(&[native_user.to_owned()])?;
        let cap = self
            .resource_caps
            .get(cap)
            .context("resource cap is unavailable")?;
        if !cap.users.iter().any(|user| user == native_user) {
            bail!("native account is outside resource authority");
        }
        if requested.len() > 1024 {
            bail!("requested resources exceed the declaration limit");
        }
        let mut resolved = BTreeMap::new();
        for (name, selected) in requested {
            let allowed = cap
                .resources
                .get(name)
                .context("requested resource is outside the cap")?;
            require_narrowing(selected, allowed)?;
            let binding = &self.resources[name];
            let slot = &self.credential_slots[&binding.credential_slot];
            let (purposes, projections) = selection_sets(selected)?;
            resolved.insert(
                LogicalSecretName::parse(name)?,
                ResolvedResource {
                    provider: ProviderId::parse(&slot.provider)?,
                    credential_slot: binding.credential_slot.clone(),
                    reference: SecretReference::new(&binding.reference)?,
                    purposes,
                    projections,
                },
            );
        }
        Ok(resolved)
    }
}

pub(crate) fn validate_users(users: &[String]) -> Result<()> {
    if users.is_empty() || users.len() > 256 {
        bail!("credential account set is empty or oversized");
    }
    let mut seen = BTreeSet::new();
    for user in users {
        if user.is_empty()
            || user.len() > 128
            || !user
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            || !seen.insert(user)
        {
            bail!("credential account set is invalid");
        }
    }
    Ok(())
}

fn selection_sets(
    selected: &ResourceSelection,
) -> Result<(BTreeSet<ResourcePurpose>, BTreeSet<Projection>)> {
    let purposes = selected.purposes.iter().copied().collect::<BTreeSet<_>>();
    let projections = selected
        .projections
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if purposes.is_empty()
        || purposes.len() != selected.purposes.len()
        || projections.len() != selected.projections.len()
    {
        bail!("resource rights are empty or duplicated");
    }
    if !projections.is_empty() && !purposes.contains(&ResourcePurpose::Read) {
        bail!("resource projection requires export authority");
    }
    Ok((purposes, projections))
}

pub(crate) fn require_narrowing(
    selected: &ResourceSelection,
    allowed: &ResourceSelection,
) -> Result<()> {
    let selected = selection_sets(selected)?;
    let allowed = selection_sets(allowed)?;
    if !selected.0.is_subset(&allowed.0) || !selected.1.is_subset(&allowed.1) {
        bail!("requested resource rights widen authority");
    }
    Ok(())
}
