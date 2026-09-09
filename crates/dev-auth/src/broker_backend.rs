use crate::broker_protocol::SshOperationPurpose;
use crate::linux_admission::{
    SessionGitHubGrant, SessionOperationKeyGrant, SessionReleaseSigningGrant,
};
use crate::policy_v2::SystemMode;
use crate::provider_operation::ProviderOperation;
use crate::runtime::{
    broker_github_token_for_repositories, broker_github_token_for_repository,
    broker_revoke_github_token_with_timeout, broker_sign_release_manifest_bytes, broker_sign_ssh,
    BrokerGitHubAuthority, BrokerGitHubToken, GITHUB_API_TIMEOUT,
};
use crate::runtime_policy::RuntimeAdministrator;
use crate::SecretString;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use time::OffsetDateTime;

const CREDENTIAL_LIMIT: u64 = 64 * 1024;
const TOKEN_REFRESH_MARGIN_SECONDS: i64 = 300;
const SERVICE_CREDENTIAL_PREFIX: &str = "op-service-account-token_";
pub(crate) const SESSION_CLEANUP_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(120);

fn logical_binding_matches(
    policy: &crate::policy_v3::SystemPolicyV3,
    name: &str,
    slot: &str,
    reference: &str,
) -> bool {
    policy
        .credentials
        .resources
        .get(name)
        .is_some_and(|resource| {
            resource.credential_slot == slot
                && resource.reference == reference
                && resource.kind == crate::logical_authority::ResourceKind::OperationOnly
        })
}

fn validate_logical_github_grant(
    policy: &crate::policy_v3::SystemPolicyV3,
    grant: &SessionGitHubGrant,
) -> Result<()> {
    let canonical = |values: &[String]| {
        values
            .iter()
            .map(|value| value.to_ascii_lowercase())
            .collect::<BTreeSet<_>>()
    };
    let owners = canonical(&grant.owners);
    let repositories = canonical(&grant.repositories);
    let permitted = policy.workload_caps.values().any(|cap| {
        cap.operations.github.iter().any(|(name, allowed)| {
            logical_binding_matches(policy, name, &grant.credential_slot, &grant.private_key_ref)
                && allowed.app_id == grant.app_id
                && allowed.repository_selection == grant.repository_selection
                && !owners.is_empty()
                && owners.is_subset(&canonical(&allowed.owners))
                && (allowed.repositories.is_empty()
                    || (!repositories.is_empty()
                        && repositories.is_subset(&canonical(&allowed.repositories))))
                && !grant.permissions.is_empty()
                && grant.permissions.iter().all(|(name, requested)| {
                    allowed
                        .permissions
                        .get(name)
                        .is_some_and(|allowed| requested <= allowed)
                })
                && (allowed.installation_ids.is_empty()
                    || (!grant.installation_ids.is_empty()
                        && grant
                            .installation_ids
                            .iter()
                            .all(|id| allowed.installation_ids.contains(id))))
        })
    });
    if !permitted {
        bail!("session GitHub authority is outside logical administrator policy");
    }
    Ok(())
}

fn validate_logical_ssh_grant(
    policy: &crate::policy_v3::SystemPolicyV3,
    purpose: SshOperationPurpose,
    grant: &SessionOperationKeyGrant,
) -> Result<()> {
    let permitted = policy.workload_caps.values().any(|cap| {
        let keys = match purpose {
            SshOperationPurpose::GitSigning => &cap.operations.signing,
            SshOperationPurpose::Authentication => &cap.operations.ssh,
        };
        keys.iter().any(|(name, key)| {
            logical_binding_matches(policy, name, &grant.credential_slot, &grant.private_key_ref)
                && key.public_key == grant.public_key
                && key.fingerprint == grant.fingerprint
        })
    });
    if !permitted {
        bail!("session SSH authority is outside logical administrator policy");
    }
    Ok(())
}

fn validate_logical_release_grant(
    policy: &crate::policy_v3::SystemPolicyV3,
    grant: &SessionReleaseSigningGrant,
    product: &str,
) -> Result<()> {
    let permitted = policy.workload_caps.values().any(|cap| {
        cap.operations.release_signing.iter().any(|(name, key)| {
            logical_binding_matches(policy, name, &grant.credential_slot, &grant.private_key_ref)
                && key.public_key == grant.public_key
                && !grant.products.is_empty()
                && grant
                    .products
                    .iter()
                    .all(|product| key.products.contains(product))
                && grant.products.iter().any(|allowed| allowed == product)
        })
    });
    if !permitted {
        bail!("session release authority is outside logical administrator policy");
    }
    Ok(())
}

fn repository_cache_key(
    session_id: &str,
    grant: &SessionGitHubGrant,
    owner: &str,
    repository: &str,
) -> Result<String> {
    let public_scope = serde_json::to_vec(&(
        session_id,
        &grant.credential_slot,
        grant.app_id,
        grant.repository_selection,
        owner.to_ascii_lowercase(),
        repository.to_ascii_lowercase(),
        &grant.permissions,
        &grant.installation_ids,
    ))?;
    Ok(format!("{:x}", Sha256::digest(public_scope)))
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ProviderValidationCounts {
    pub authentication_checked: u32,
    pub authentication_total: u32,
    pub resources_checked: u32,
    pub resources_total: u32,
    pub keys_checked: u32,
    pub keys_failed: u32,
    pub keys_total: u32,
}

enum ExpectedOperationKey<'a> {
    GitHub,
    Ssh(&'a crate::policy_v3_operations::SshKeyCap),
    Release(&'a crate::policy_v3_operations::ReleaseKeyCap),
}

fn expected_operation_keys<'a>(
    authority: &'a crate::policy_v3_operations::OperationAuthority,
    name: &str,
    grant: &crate::logical_authority::ResolvedResource,
) -> Vec<ExpectedOperationKey<'a>> {
    use crate::logical_authority::ResourcePurpose;
    let mut keys = Vec::new();
    if grant.allows(ResourcePurpose::GitHubToken) && authority.github.contains_key(name) {
        keys.push(ExpectedOperationKey::GitHub);
    }
    for (purpose, declarations) in [
        (ResourcePurpose::GitSigning, &authority.signing),
        (ResourcePurpose::SshAuthentication, &authority.ssh),
    ] {
        if grant.allows(purpose) {
            if let Some(key) = declarations.get(name) {
                keys.push(ExpectedOperationKey::Ssh(key));
            }
        }
    }
    if grant.allows(ResourcePurpose::ReleaseSigning) {
        if let Some(key) = authority.release_signing.get(name) {
            keys.push(ExpectedOperationKey::Release(key));
        }
    }
    keys
}

impl ExpectedOperationKey<'_> {
    fn validate(&self, material: &dev_tools_secret::SecretMaterial) -> Result<()> {
        match self {
            Self::GitHub => crate::runtime::validate_rsa_key_material(material),
            Self::Ssh(key) => crate::runtime::validate_ssh_key_material(
                material,
                &key.public_key,
                &key.fingerprint,
            ),
            Self::Release(key) => {
                crate::runtime::validate_release_key_material(material, &key.public_key)
            }
        }
    }
}

pub(crate) trait CapabilityBackend: Send + Sync {
    fn validate_providers(
        &self,
        _operation: &ProviderOperation<'_>,
        _session: &crate::linux_admission::VerifiedLinuxSession,
    ) -> Result<ProviderValidationCounts> {
        bail!("provider validation is unavailable")
    }

    fn secret_material(
        &self,
        _operation: &ProviderOperation<'_>,
        _session: &crate::linux_admission::VerifiedLinuxSession,
        _resource: &str,
        _purpose: crate::logical_authority::ResourcePurpose,
        _projection: Option<crate::logical_authority::Projection>,
    ) -> Result<crate::broker_protocol::SensitiveBytes> {
        bail!("logical resource delivery is unavailable")
    }

    fn github_token(
        &self,
        operation: &ProviderOperation<'_>,
        session_id: &str,
        grant: &SessionGitHubGrant,
        owner: &str,
        repository: &str,
    ) -> Result<BrokerGitHubToken>;

    fn gh_token(
        &self,
        operation: &ProviderOperation<'_>,
        session_id: &str,
        grant: &SessionGitHubGrant,
    ) -> Result<BrokerGitHubToken>;

    fn invalidate_github_token(
        &self,
        operation: &ProviderOperation<'_>,
        session_id: &str,
        grant: &SessionGitHubGrant,
        owner: &str,
        repository: &str,
    ) -> Result<()>;

    fn sign_ssh(
        &self,
        operation: &ProviderOperation<'_>,
        session_id: &str,
        purpose: SshOperationPurpose,
        grant: &SessionOperationKeyGrant,
        payload: &[u8],
    ) -> Result<Vec<u8>>;

    fn sign_release_manifest(
        &self,
        operation: &ProviderOperation<'_>,
        session_id: &str,
        grant: &SessionReleaseSigningGrant,
        payload: &[u8],
    ) -> Result<Vec<u8>>;

    fn revoke_session(&self, session_id: &str) -> Result<()>;

    fn revoke_session_before(&self, session_id: &str, deadline: Instant) -> Result<()> {
        if deadline <= Instant::now() {
            bail!("session cleanup deadline elapsed");
        }
        self.revoke_session(session_id)
    }
}

#[derive(Clone)]
struct CachedToken {
    generation: u64,
    scope_key: String,
    session_id: String,
    token: SecretString,
    expires_at: i64,
}

#[derive(Default)]
struct TokenCache {
    active: BTreeMap<String, CachedToken>,
    pending_revocation: BTreeMap<u64, CachedToken>,
    next_generation: u64,
}

#[derive(Clone)]
enum CachedTokenLocation {
    Active { key: String, generation: u64 },
    Pending { generation: u64 },
}

#[derive(Clone)]
struct CachedTokenRevocation {
    location: CachedTokenLocation,
    token: SecretString,
}

impl TokenCache {
    fn next_generation(&mut self) -> Result<u64> {
        let generation = self.next_generation;
        self.next_generation = generation
            .checked_add(1)
            .context("broker token cache generation overflowed")?;
        Ok(generation)
    }

    fn session_revocations(&self, session_id: &str) -> Vec<CachedTokenRevocation> {
        let active = self
            .active
            .iter()
            .filter(|(_, entry)| entry.session_id == session_id)
            .map(|(key, entry)| CachedTokenRevocation {
                location: CachedTokenLocation::Active {
                    key: key.clone(),
                    generation: entry.generation,
                },
                token: entry.token.clone(),
            });
        let pending = self
            .pending_revocation
            .iter()
            .filter(|(_, entry)| entry.session_id == session_id)
            .map(|(generation, entry)| CachedTokenRevocation {
                location: CachedTokenLocation::Pending {
                    generation: *generation,
                },
                token: entry.token.clone(),
            });
        active.chain(pending).collect()
    }

    fn scope_revocations(&self, session_id: &str, key: &str) -> Vec<CachedTokenRevocation> {
        let active = self
            .active
            .get(key)
            .filter(|entry| entry.session_id == session_id)
            .map(|entry| CachedTokenRevocation {
                location: CachedTokenLocation::Active {
                    key: key.to_owned(),
                    generation: entry.generation,
                },
                token: entry.token.clone(),
            });
        let pending = self
            .pending_revocation
            .iter()
            .filter(|(_, entry)| entry.session_id == session_id && entry.scope_key == key)
            .map(|(generation, entry)| CachedTokenRevocation {
                location: CachedTokenLocation::Pending {
                    generation: *generation,
                },
                token: entry.token.clone(),
            });
        active.into_iter().chain(pending).collect()
    }

    fn remove_revoked(&mut self, location: &CachedTokenLocation) {
        match location {
            CachedTokenLocation::Active { key, generation } => {
                if self
                    .active
                    .get(key)
                    .is_some_and(|entry| entry.generation == *generation)
                {
                    self.active.remove(key);
                }
                self.pending_revocation.remove(generation);
            }
            CachedTokenLocation::Pending { generation } => {
                self.pending_revocation.remove(generation);
            }
        }
    }
}

pub(crate) struct SystemCapabilityBackend {
    policy: RuntimeAdministrator,
    service_tokens: BTreeMap<String, SecretString>,
    cache: Mutex<TokenCache>,
}

impl SystemCapabilityBackend {
    pub(crate) fn load() -> Result<Self> {
        Self::load_at(
            Path::new(crate::policy_store::SYSTEM_POLICY_PATH),
            systemd_credential_directory()?.as_path(),
        )
    }

    pub(crate) fn load_user(
        policy_path: &Path,
        owner_uid: u32,
        interaction: crate::runtime::CredentialInteraction,
    ) -> Result<Self> {
        let policy = crate::policy_store::load_runtime_user_policy_at(policy_path, owner_uid)?;
        if policy.mode() != SystemMode::UserOnly {
            bail!("user broker requires a user-only administrator policy");
        }
        Ok(Self {
            service_tokens: crate::runtime::user_broker_service_tokens(
                policy.credential_slot_names().into_iter(),
                interaction,
            )?,
            policy,
            cache: Mutex::new(TokenCache::default()),
        })
    }

    fn load_at(policy_path: &Path, credential_directory: &Path) -> Result<Self> {
        let policy = crate::policy_store::load_runtime_system_policy_at(policy_path)?;
        if policy.mode() != SystemMode::Strong {
            bail!("system broker requires a strong-mode administrator policy");
        }
        let service_tokens = read_service_credentials(credential_directory, &policy)?;
        Ok(Self {
            policy,
            service_tokens,
            cache: Mutex::new(TokenCache::default()),
        })
    }

    fn service_token(&self, slot: &str) -> Result<&SecretString> {
        self.service_tokens
            .get(slot)
            .context("session credential slot is not loaded by the broker")
    }

    fn validate_grant(&self, grant: &SessionGitHubGrant) -> Result<&SecretString> {
        let policy = match &self.policy {
            RuntimeAdministrator::Legacy(policy) => policy,
            RuntimeAdministrator::Logical(policy) => {
                validate_logical_github_grant(policy, grant)?;
                return self.service_token(&grant.credential_slot);
            }
        };
        let slot = policy
            .credential_slots
            .get(&grant.credential_slot)
            .context("session credential slot is outside administrator policy")?;
        let (app_name, app) = policy
            .github_apps
            .iter()
            .find(|(_, app)| app.app_id == grant.app_id)
            .context("session GitHub App is outside administrator policy")?;
        if !app.private_key_references.contains(&grant.private_key_ref) {
            bail!("session GitHub private-key reference is outside administrator policy");
        }
        if app.repository_selection != grant.repository_selection {
            bail!("session GitHub repository selection is outside administrator policy");
        }
        let owners = grant
            .owners
            .iter()
            .map(|owner| owner.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        let repositories = grant
            .repositories
            .iter()
            .map(|repository| repository.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        let allowed = policy.authority_caps.iter().any(|(cap_name, cap)| {
            if !slot.authority_caps.contains(cap_name) {
                return false;
            }
            if !cap.github_apps.contains(app_name) {
                return false;
            }
            let cap_owners = cap
                .owners
                .iter()
                .map(|owner| owner.to_ascii_lowercase())
                .collect::<BTreeSet<_>>();
            let cap_repositories = cap
                .repositories
                .iter()
                .map(|repository| repository.to_ascii_lowercase())
                .collect::<BTreeSet<_>>();
            owners.is_subset(&cap_owners)
                && (cap_repositories.is_empty()
                    || (!repositories.is_empty() && repositories.is_subset(&cap_repositories)))
                && grant.permissions.iter().all(|(permission, requested)| {
                    cap.permissions
                        .get(permission)
                        .is_some_and(|allowed| requested <= allowed)
                })
                && (cap.installation_ids.is_empty()
                    || (!grant.installation_ids.is_empty()
                        && grant
                            .installation_ids
                            .iter()
                            .all(|id| cap.installation_ids.binary_search(id).is_ok())))
        });
        if !allowed {
            bail!("session GitHub authority is outside administrator policy");
        }
        self.service_token(&grant.credential_slot)
    }

    fn permissions(grant: &SessionGitHubGrant) -> BTreeMap<String, String> {
        grant
            .permissions
            .iter()
            .map(|(name, level)| {
                (
                    name.clone(),
                    match level {
                        crate::policy_v2::Permission::Read => "read".to_owned(),
                        crate::policy_v2::Permission::Write => "write".to_owned(),
                    },
                )
            })
            .collect()
    }

    fn validate_operation_grant(
        &self,
        purpose: SshOperationPurpose,
        grant: &SessionOperationKeyGrant,
    ) -> Result<&SecretString> {
        let policy = match &self.policy {
            RuntimeAdministrator::Legacy(policy) => policy,
            RuntimeAdministrator::Logical(policy) => {
                validate_logical_ssh_grant(policy, purpose, grant)?;
                return self.service_token(&grant.credential_slot);
            }
        };
        let slot = policy
            .credential_slots
            .get(&grant.credential_slot)
            .context("session credential slot is outside administrator policy")?;
        let allowed = policy.authority_caps.iter().any(|(cap_name, cap)| {
            if !slot.authority_caps.contains(cap_name) {
                return false;
            }
            (match purpose {
                SshOperationPurpose::GitSigning => cap.signing,
                SshOperationPurpose::Authentication => cap.ssh,
            }) && cap
                .secret_references
                .iter()
                .any(|reference| reference == &grant.private_key_ref)
        });
        if !allowed {
            bail!("session SSH operation authority is outside administrator policy");
        }
        self.service_token(&grant.credential_slot)
    }

    fn validate_release_signing_grant(
        &self,
        grant: &SessionReleaseSigningGrant,
        product: &str,
    ) -> Result<&SecretString> {
        let policy = match &self.policy {
            RuntimeAdministrator::Legacy(policy) => policy,
            RuntimeAdministrator::Logical(policy) => {
                validate_logical_release_grant(policy, grant, product)?;
                return self.service_token(&grant.credential_slot);
            }
        };
        let slot = policy
            .credential_slots
            .get(&grant.credential_slot)
            .context("session credential slot is outside administrator policy")?;
        let allowed = policy.authority_caps.iter().any(|(cap_name, cap)| {
            slot.authority_caps.contains(cap_name)
                && cap
                    .release_signing_products
                    .iter()
                    .any(|item| item == product)
                && cap
                    .release_signing_keys
                    .contains(&crate::policy_v2::ReleaseSigningKeyConfig {
                        private_key_ref: grant.private_key_ref.clone(),
                        public_key: grant.public_key.clone(),
                    })
                && cap
                    .secret_references
                    .iter()
                    .any(|reference| reference == &grant.private_key_ref)
        });
        if !allowed {
            bail!("session release-signing authority is outside administrator policy");
        }
        self.service_token(&grant.credential_slot)
    }

    fn cached(
        &self,
        operation: &ProviderOperation<'_>,
        key: &str,
        now: i64,
    ) -> Result<Option<BrokerGitHubToken>> {
        operation.checkpoint()?;
        let cache = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("broker token cache lock is poisoned"))?;
        let token = cache.active.get(key).and_then(|entry| {
            (entry.expires_at > now + TOKEN_REFRESH_MARGIN_SECONDS).then(|| BrokerGitHubToken {
                token: entry.token.clone(),
                expires_at: entry.expires_at,
            })
        });
        drop(cache);
        if token.is_some() {
            operation.checkpoint()?;
        }
        Ok(token)
    }

    fn cache(
        &self,
        operation: &ProviderOperation<'_>,
        session_id: &str,
        key: String,
        token: &BrokerGitHubToken,
    ) -> Result<()> {
        self.cache_with(
            session_id,
            key,
            token,
            || operation.checkpoint(),
            |replaced| {
                operation.checkpoint()?;
                broker_revoke_github_token_with_timeout(replaced, operation.http_timeout()?)
            },
        )
    }

    fn cache_with(
        &self,
        session_id: &str,
        key: String,
        token: &BrokerGitHubToken,
        mut checkpoint: impl FnMut() -> Result<()>,
        mut revoke: impl FnMut(&SecretString) -> Result<()>,
    ) -> Result<()> {
        let replaced = {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| anyhow::anyhow!("broker token cache lock is poisoned"))?;
            let generation = cache.next_generation()?;
            let scope_key = key.clone();
            let entry = CachedToken {
                generation,
                scope_key,
                session_id: session_id.to_owned(),
                token: token.token.clone(),
                expires_at: token.expires_at,
            };
            if let Err(error) = checkpoint() {
                // The provider may already have created this token. It must
                // remain session-owned even though cancellation prevents
                // publication, so close cleanup can revoke it before ack.
                cache.pending_revocation.insert(generation, entry);
                return Err(error);
            }
            let replaced = cache.active.insert(key, entry);
            replaced.map(|entry| {
                let generation = entry.generation;
                let token = entry.token.clone();
                cache.pending_revocation.insert(generation, entry);
                (generation, token)
            })
        };
        if let Some((generation, replaced)) = replaced {
            revoke(&replaced)?;
            self.cache
                .lock()
                .map_err(|_| anyhow::anyhow!("broker token cache lock is poisoned"))?
                .pending_revocation
                .remove(&generation);
        }
        Ok(())
    }

    #[cfg(test)]
    fn take_cached(&self, key: &str) -> Result<Option<CachedToken>> {
        self.cache
            .lock()
            .map_err(|_| anyhow::anyhow!("broker token cache lock is poisoned"))
            .map(|mut cache| cache.active.remove(key))
    }

    #[cfg(test)]
    fn active_revocation(&self, key: &str) -> Result<Option<CachedTokenRevocation>> {
        let cache = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("broker token cache lock is poisoned"))?;
        Ok(cache.active.get(key).map(|entry| CachedTokenRevocation {
            location: CachedTokenLocation::Active {
                key: key.to_owned(),
                generation: entry.generation,
            },
            token: entry.token.clone(),
        }))
    }

    fn remove_revoked(&self, location: &CachedTokenLocation) -> Result<()> {
        self.cache
            .lock()
            .map_err(|_| anyhow::anyhow!("broker token cache lock is poisoned"))?
            .remove_revoked(location);
        Ok(())
    }

    fn invalidate_scope_with(
        &self,
        session_id: &str,
        key: &str,
        mut revoke: impl FnMut(&SecretString) -> Result<()>,
    ) -> Result<()> {
        let tokens = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("broker token cache lock is poisoned"))?
            .scope_revocations(session_id, key);
        let mut failed = false;
        for entry in tokens {
            match revoke(&entry.token) {
                Ok(()) => self.remove_revoked(&entry.location)?,
                Err(_) => failed = true,
            }
        }
        let retained = !self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("broker token cache lock is poisoned"))?
            .scope_revocations(session_id, key)
            .is_empty();
        if failed || retained {
            bail!("one or more scoped GitHub tokens could not be revoked");
        }
        Ok(())
    }

    fn revoke_session_before_with(
        &self,
        session_id: &str,
        deadline: Instant,
        mut now: impl FnMut() -> Instant,
        mut revoke: impl FnMut(&SecretString, Duration) -> Result<()>,
    ) -> Result<()> {
        let tokens = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("broker token cache lock is poisoned"))?
            .session_revocations(session_id);
        let mut failed = false;
        for entry in tokens {
            let Some(remaining) = deadline
                .checked_duration_since(now())
                .filter(|remaining| !remaining.is_zero())
            else {
                failed = true;
                break;
            };
            match revoke(&entry.token, remaining.min(GITHUB_API_TIMEOUT)) {
                Ok(()) => self.remove_revoked(&entry.location)?,
                Err(_) => failed = true,
            }
        }
        let retained = !self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("broker token cache lock is poisoned"))?
            .session_revocations(session_id)
            .is_empty();
        if failed || retained {
            bail!("one or more session tokens could not be revoked");
        }
        Ok(())
    }
}

impl SystemCapabilityBackend {
    fn validate_providers_with<H, F>(
        &self,
        operation: &ProviderOperation<'_>,
        session: &crate::linux_admission::VerifiedLinuxSession,
        mut authenticate: H,
        mut retrieve: F,
    ) -> Result<ProviderValidationCounts>
    where
        H: FnMut(&crate::logical_authority::ResolvedResource) -> Result<()>,
        F: FnMut(
            &crate::logical_authority::ResolvedResource,
        ) -> Result<dev_tools_secret::SecretMaterial>,
    {
        operation.checkpoint()?;
        if session.authority.hard_deadline_expired()? {
            bail!("workload authority expired");
        }
        let RuntimeAdministrator::Logical(policy) = &self.policy else {
            bail!("logical resource authority is unavailable");
        };
        let selection = session
            .authority
            .logical
            .as_ref()
            .context("logical session authority is absent")?;
        let cap = policy
            .workload_caps
            .get(&selection.cap)
            .context("workload cap is absent")?;
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(session.owner_uid))?
            .context("native workload account is absent")?;
        if !cap.users.contains(&user.name) {
            bail!("workload account is outside authority");
        }
        let grants =
            policy
                .credentials
                .resolve(&user.name, &cap.resource_cap, &selection.resources)?;
        let mut counts = ProviderValidationCounts {
            resources_total: u32::try_from(grants.len()).context("resource count exceeds limit")?,
            authentication_total: u32::try_from(
                grants
                    .values()
                    .map(|grant| grant.credential_slot())
                    .collect::<BTreeSet<_>>()
                    .len(),
            )
            .context("credential slot count exceeds limit")?,
            ..ProviderValidationCounts::default()
        };
        let mut authenticated_slots = BTreeSet::new();
        for (name, grant) in &grants {
            operation.checkpoint()?;
            if session.authority.hard_deadline_expired()? {
                bail!("workload authority expired");
            }
            if authenticated_slots.insert(grant.credential_slot()) {
                let result = authenticate(grant);
                if validation_observation_succeeded(result)? {
                    counts.authentication_checked += 1;
                }
                operation.checkpoint()?;
                if session.authority.hard_deadline_expired()? {
                    bail!("workload authority expired");
                }
            }
            let keys = expected_operation_keys(&cap.operations, name.as_str(), grant);
            counts.keys_total = counts
                .keys_total
                .checked_add(u32::try_from(keys.len())?)
                .context("key observation count exceeds limit")?;
            match retrieve(grant) {
                Ok(material) => {
                    operation.checkpoint()?;
                    if session.authority.hard_deadline_expired()? {
                        bail!("workload authority expired");
                    }
                    counts.resources_checked += 1;
                    for key in keys {
                        if key.validate(&material).is_ok() {
                            counts.keys_checked += 1;
                        } else {
                            counts.keys_failed += 1;
                        }
                    }
                }
                Err(error) => {
                    validation_observation_succeeded(Err(error))?;
                }
            }
        }
        operation.checkpoint()?;
        if session.authority.hard_deadline_expired()? {
            bail!("workload authority expired");
        }
        Ok(counts)
    }
}

fn validation_observation_succeeded(result: Result<()>) -> Result<bool> {
    if result
        .as_ref()
        .err()
        .and_then(|error| error.downcast_ref::<dev_tools_secret::SecretError>())
        .is_some_and(crate::provider_operation::validation_must_stop)
    {
        result.map(|()| true)
    } else {
        Ok(result.is_ok())
    }
}

impl CapabilityBackend for SystemCapabilityBackend {
    fn validate_providers(
        &self,
        operation: &ProviderOperation<'_>,
        session: &crate::linux_admission::VerifiedLinuxSession,
    ) -> Result<ProviderValidationCounts> {
        self.validate_providers_with(
            operation,
            session,
            |grant| {
                let slot = grant.credential_slot();
                let provider = crate::runtime::OnePasswordProvider::named(
                    grant.provider().clone(),
                    self.policy.provider_program(slot)?,
                    self.service_token(slot)?,
                )?;
                match dev_tools_secret::SecretProvider::health(
                    &provider,
                    operation.secret_context(),
                )? {
                    dev_tools_secret::ProviderHealth::Healthy => Ok(()),
                    dev_tools_secret::ProviderHealth::Unavailable => {
                        bail!("provider authentication unavailable")
                    }
                }
            },
            |grant| {
                let slot = grant.credential_slot();
                let provider = crate::runtime::OnePasswordProvider::named(
                    grant.provider().clone(),
                    self.policy.provider_program(slot)?,
                    self.service_token(slot)?,
                )?;
                // Validation consumes only the admitted reference internally.
                // Operation-only bytes never cross the broker response boundary.
                let material = dev_tools_secret::SecretProvider::read_exportable(
                    &provider,
                    &grant.reference,
                    operation.secret_context(),
                )?;
                Ok(material)
            },
        )
    }

    fn secret_material(
        &self,
        operation: &ProviderOperation<'_>,
        session: &crate::linux_admission::VerifiedLinuxSession,
        resource: &str,
        purpose: crate::logical_authority::ResourcePurpose,
        projection: Option<crate::logical_authority::Projection>,
    ) -> Result<crate::broker_protocol::SensitiveBytes> {
        use crate::logical_authority::ResourcePurpose;
        operation.checkpoint()?;
        if session.authority.hard_deadline_expired()? {
            bail!("workload authority expired");
        }
        let RuntimeAdministrator::Logical(policy) = &self.policy else {
            bail!("logical resource authority is unavailable");
        };
        let selection = session
            .authority
            .logical
            .as_ref()
            .context("logical session authority is absent")?;
        let cap = policy
            .workload_caps
            .get(&selection.cap)
            .context("workload cap is absent")?;
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(session.owner_uid))?
            .context("native workload account is absent")?;
        if !cap.users.contains(&user.name) {
            bail!("workload account is outside authority");
        }
        let grants =
            policy
                .credentials
                .resolve(&user.name, &cap.resource_cap, &selection.resources)?;
        let name = dev_tools_secret::LogicalSecretName::parse(resource)?;
        let grant = grants
            .get(&name)
            .context("logical resource is outside workload authority")?;
        if !grant.allows(purpose)
            || projection.is_some_and(|projection| !grant.allows_projection(projection))
            || (purpose != ResourcePurpose::Read && projection.is_some())
        {
            bail!("logical resource purpose or projection is outside authority");
        }
        let slot = grant.credential_slot();
        let provider = crate::runtime::OnePasswordProvider::named(
            grant.provider().clone(),
            self.policy.provider_program(slot)?,
            self.service_token(slot)?,
        )?;
        let material = match purpose {
            ResourcePurpose::Read => {
                let material =
                    grant.read_exportable(&provider, slot, operation.secret_context())?;
                crate::broker_protocol::SensitiveBytes::new(material.expose_secret().to_vec())?
            }
            ResourcePurpose::Public => {
                let material =
                    grant.public_material(&provider, slot, operation.secret_context())?;
                crate::broker_protocol::SensitiveBytes::new(material.as_bytes().to_vec())?
            }
            _ => bail!("unsupported logical material purpose"),
        };
        operation.checkpoint()?;
        if session.authority.hard_deadline_expired()? {
            bail!("workload authority expired");
        }
        Ok(material)
    }

    fn github_token(
        &self,
        operation: &ProviderOperation<'_>,
        session_id: &str,
        grant: &SessionGitHubGrant,
        owner: &str,
        repository: &str,
    ) -> Result<BrokerGitHubToken> {
        operation.checkpoint()?;
        let service_token = self.validate_grant(grant)?;
        let key = repository_cache_key(session_id, grant, owner, repository)?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if let Some(token) = self.cached(operation, &key, now)? {
            return Ok(token);
        }
        let token = broker_github_token_for_repository(
            operation,
            BrokerGitHubAuthority {
                op_program: self.policy.provider_program(&grant.credential_slot)?,
                service_token,
                app_id: grant.app_id,
                repository_selection: grant.repository_selection,
                private_key_ref: &grant.private_key_ref,
                permissions: Self::permissions(grant),
                installation_ids: &grant.installation_ids,
            },
            owner,
            repository,
        )?;
        self.cache(operation, session_id, key, &token)?;
        Ok(token)
    }

    fn gh_token(
        &self,
        operation: &ProviderOperation<'_>,
        session_id: &str,
        grant: &SessionGitHubGrant,
    ) -> Result<BrokerGitHubToken> {
        operation.checkpoint()?;
        let service_token = self.validate_grant(grant)?;
        let [owner] = grant.owners.as_slice() else {
            bail!("GitHub CLI authority requires exactly one owner");
        };
        let public_scope = serde_json::to_vec(&(
            "gh",
            session_id,
            &grant.credential_slot,
            grant.app_id,
            grant.repository_selection,
            owner.to_ascii_lowercase(),
            &grant.repositories,
            &grant.permissions,
            &grant.installation_ids,
        ))?;
        let key = format!("{:x}", Sha256::digest(public_scope));
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if let Some(token) = self.cached(operation, &key, now)? {
            return Ok(token);
        }
        let token = broker_github_token_for_repositories(
            operation,
            BrokerGitHubAuthority {
                op_program: self.policy.provider_program(&grant.credential_slot)?,
                service_token,
                app_id: grant.app_id,
                repository_selection: grant.repository_selection,
                private_key_ref: &grant.private_key_ref,
                permissions: Self::permissions(grant),
                installation_ids: &grant.installation_ids,
            },
            owner,
            &grant.repositories,
        )?;
        self.cache(operation, session_id, key, &token)?;
        Ok(token)
    }

    fn invalidate_github_token(
        &self,
        operation: &ProviderOperation<'_>,
        session_id: &str,
        grant: &SessionGitHubGrant,
        owner: &str,
        repository: &str,
    ) -> Result<()> {
        operation.checkpoint()?;
        self.validate_grant(grant)?;
        let key = repository_cache_key(session_id, grant, owner, repository)?;
        self.invalidate_scope_with(session_id, &key, |token| {
            operation.checkpoint()?;
            broker_revoke_github_token_with_timeout(token, operation.http_timeout()?)
        })
    }

    fn sign_ssh(
        &self,
        operation: &ProviderOperation<'_>,
        _session_id: &str,
        purpose: SshOperationPurpose,
        grant: &SessionOperationKeyGrant,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        operation.checkpoint()?;
        let service_token = self.validate_operation_grant(purpose, grant)?;
        broker_sign_ssh(
            operation,
            self.policy.provider_program(&grant.credential_slot)?,
            service_token,
            &grant.private_key_ref,
            &grant.public_key,
            &grant.fingerprint,
            payload,
        )
    }

    fn sign_release_manifest(
        &self,
        operation: &ProviderOperation<'_>,
        _session_id: &str,
        grant: &SessionReleaseSigningGrant,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        operation.checkpoint()?;
        let document = dev_tools_release::validate_unsigned_release_document(payload)?;
        if !grant.products.contains(&document.authority) {
            bail!("release manifest product is outside the session grant");
        }
        let service_token = self.validate_release_signing_grant(grant, &document.authority)?;
        broker_sign_release_manifest_bytes(
            operation,
            self.policy.provider_program(&grant.credential_slot)?,
            service_token,
            &grant.private_key_ref,
            &grant.public_key,
            payload,
        )
    }

    fn revoke_session(&self, session_id: &str) -> Result<()> {
        let deadline = Instant::now()
            .checked_add(SESSION_CLEANUP_ATTEMPT_TIMEOUT)
            .context("session cleanup deadline overflowed")?;
        self.revoke_session_before(session_id, deadline)
    }

    fn revoke_session_before(&self, session_id: &str, deadline: Instant) -> Result<()> {
        self.revoke_session_before_with(session_id, deadline, Instant::now, |token, timeout| {
            broker_revoke_github_token_with_timeout(token, timeout)
        })
    }
}

fn systemd_credential_directory() -> Result<PathBuf> {
    let directory = PathBuf::from(
        std::env::var_os("CREDENTIALS_DIRECTORY")
            .context("systemd did not provide the broker credential directory")?,
    );
    if !directory.is_absolute() {
        bail!("systemd credential directory is not absolute");
    }
    Ok(directory)
}

fn read_service_credentials(
    directory: &Path,
    policy: &RuntimeAdministrator,
) -> Result<BTreeMap<String, SecretString>> {
    let metadata =
        fs::symlink_metadata(directory).context("inspect broker credential directory")?;
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || !credential_metadata_mode_is_safe(metadata.uid(), effective_uid, metadata.mode())
    {
        bail!("broker credential directory has unsafe filesystem authority");
    }
    let mut tokens = BTreeMap::new();
    let declared_slots = policy.credential_slot_names();
    for slot in &declared_slots {
        let path = directory.join(format!("{SERVICE_CREDENTIAL_PREFIX}{slot}"));
        tokens.insert((*slot).to_owned(), read_service_credential(&path)?);
    }
    for entry in fs::read_dir(directory).context("enumerate broker credentials")? {
        let entry = entry.context("read broker credential entry")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(slot) = name.strip_prefix(SERVICE_CREDENTIAL_PREFIX) {
            if !declared_slots.contains(&slot) {
                bail!("broker received an undeclared credential slot");
            }
        }
    }
    Ok(tokens)
}

fn read_service_credential(path: &Path) -> Result<SecretString> {
    let metadata = fs::symlink_metadata(path).context("inspect broker service credential")?;
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || !credential_metadata_mode_is_safe(metadata.uid(), effective_uid, metadata.mode())
        || metadata.nlink() != 1
        || metadata.len() > CREDENTIAL_LIMIT
    {
        bail!("broker service credential has unsafe filesystem authority");
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    let file = options
        .open(path)
        .context("open broker service credential")?;
    let held = file
        .metadata()
        .context("inspect held broker service credential")?;
    if held.dev() != metadata.dev()
        || held.ino() != metadata.ino()
        || held.nlink() != 1
        || held.len() != metadata.len()
    {
        bail!("broker service credential changed while it was being held");
    }
    let bytes = read_bounded_reader(file, CREDENTIAL_LIMIT, "broker service credential")?;
    let value = String::from_utf8(bytes).context("broker service credential is not UTF-8")?;
    let value = value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(&value)
        .to_owned();
    if value.is_empty() || value.contains(['\n', '\r', '\0']) {
        bail!("broker service credential is malformed");
    }
    Ok(SecretString::new(value))
}

fn credential_metadata_mode_is_safe(owner_uid: u32, effective_uid: u32, mode: u32) -> bool {
    let permissions = mode & 0o777;
    if owner_uid == 0 {
        permissions & 0o027 == 0
    } else {
        owner_uid == effective_uid && permissions & 0o077 == 0
    }
}

fn read_bounded_reader(reader: impl Read, limit: u64, description: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {description}"))?;
    if bytes.len() as u64 > limit {
        bail!("{description} exceeds the size limit");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_v2::{
        AuthorityCap, CredentialSlotCap, GitHubAppCap, Permission, SystemPrograms,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicBool;

    fn operation() -> ProviderOperation<'static> {
        ProviderOperation::uncancelled().unwrap()
    }

    fn logical_validation_fixture() -> (
        SystemCapabilityBackend,
        crate::linux_admission::VerifiedLinuxSession,
    ) {
        let uid = nix::unistd::Uid::effective();
        let user = nix::unistd::User::from_uid(uid).unwrap().unwrap();
        let text = include_str!("../policy-v3-user-only.example.toml")
            .replace("\"automation\"", &format!("{:?}", user.name));
        let mut policy: crate::policy_v3::SystemPolicyV3 = toml::from_str(&text).unwrap();
        policy
            .credentials
            .resources
            .get_mut("service-token")
            .unwrap()
            .credential_slot = "automation".into();
        policy.credentials.providers.insert(
            "secondary".into(),
            crate::logical_authority::ProviderInstance::OnePassword {
                executable: "/opt/fixture/op-secondary".into(),
            },
        );
        policy.credentials.credential_slots.insert(
            "secondary".into(),
            crate::logical_authority::CredentialSlot {
                provider: "secondary".into(),
                users: vec![user.name],
            },
        );
        let mut second = policy.credentials.resources["service-token"].clone();
        second.credential_slot = "secondary".into();
        second.reference = "op://Fixture/Second/token".into();
        policy
            .credentials
            .resources
            .insert("zz-token".into(), second);
        let rights = policy.credentials.resource_caps["worker"].resources["service-token"].clone();
        policy
            .credentials
            .resource_caps
            .get_mut("worker")
            .unwrap()
            .resources
            .insert("zz-token".into(), rights.clone());
        let session = crate::linux_admission::VerifiedLinuxSession {
            session_id: "0123456789abcdef0123456789abcdef".into(),
            owner_uid: uid.as_raw(),
            execution_uid: uid.as_raw(),
            workload: "worker".into(),
            profile: "worker".into(),
            authority: crate::linux_admission::SessionAuthorityGrant {
                logical: Some(crate::policy_v3::LogicalSelection {
                    cap: "worker".into(),
                    resources: BTreeMap::from([
                        ("service-token".into(), rights.clone()),
                        ("zz-token".into(), rights),
                    ]),
                }),
                hard_deadline_boot_ms: None,
                github: None,
                signing: None,
                release_signing: None,
                ssh: Vec::new(),
            },
            cgroup: PathBuf::new(),
            expires_at_unix: i64::MAX,
        };
        (
            SystemCapabilityBackend {
                policy: RuntimeAdministrator::Logical(policy),
                service_tokens: BTreeMap::from([
                    (
                        "automation".into(),
                        SecretString::new("first-fixture-token".into()),
                    ),
                    (
                        "secondary".into(),
                        SecretString::new("second-fixture-token".into()),
                    ),
                ]),
                cache: Mutex::new(TokenCache::default()),
            },
            session,
        )
    }

    #[test]
    fn provider_validation_resolves_each_slot_and_continues_after_independent_denial() {
        let (backend, mut session) = logical_validation_fixture();
        let mut reads = Vec::new();
        let counts = backend
            .validate_providers_with(
                &operation(),
                &session,
                |_| Ok(()),
                |grant| {
                    let slot = grant.credential_slot();
                    reads.push((
                        grant.provider().as_str().to_owned(),
                        slot.to_owned(),
                        backend.policy.provider_program(slot)?.to_owned(),
                        backend.service_token(slot)?.expose().to_owned(),
                    ));
                    if slot == "automation" {
                        bail!("fixture denial");
                    }
                    assert_eq!(
                        grant.reference.expose_to_provider(),
                        "op://Fixture/Second/token"
                    );
                    Ok(dev_tools_secret::SecretMaterial::new(b"fixture".to_vec())?)
                },
            )
            .unwrap();
        assert_eq!(
            counts,
            ProviderValidationCounts {
                authentication_checked: 2,
                authentication_total: 2,
                resources_checked: 1,
                resources_total: 2,
                ..ProviderValidationCounts::default()
            }
        );
        assert_eq!(
            reads,
            vec![
                (
                    "primary".into(),
                    "automation".into(),
                    "/usr/bin/op".into(),
                    "first-fixture-token".into()
                ),
                (
                    "secondary".into(),
                    "secondary".into(),
                    "/opt/fixture/op-secondary".into(),
                    "second-fixture-token".into()
                ),
            ]
        );
        let logical = session.authority.logical.as_mut().unwrap();
        logical
            .resources
            .insert("outside".into(), logical.resources["service-token"].clone());
        assert!(backend
            .validate_providers_with(
                &operation(),
                &session,
                |_| panic!("unresolved authority reached authentication"),
                |_| panic!("unresolved authority reached provider")
            )
            .is_err());
    }

    #[test]
    fn provider_authentication_is_once_per_selected_slot_and_independent_of_retrieval() {
        let (mut backend, mut session) = logical_validation_fixture();
        let RuntimeAdministrator::Logical(policy) = &mut backend.policy else {
            unreachable!();
        };
        let alias = policy.credentials.resources["service-token"].clone();
        policy.credentials.resources.insert("alias".into(), alias);
        let rights = policy.credentials.resource_caps["worker"].resources["service-token"].clone();
        policy
            .credentials
            .resource_caps
            .get_mut("worker")
            .unwrap()
            .resources
            .insert("alias".into(), rights.clone());
        session
            .authority
            .logical
            .as_mut()
            .unwrap()
            .resources
            .insert("alias".into(), rights);
        let mut slots = Vec::new();
        let mut reads = 0;
        let counts = backend
            .validate_providers_with(
                &operation(),
                &session,
                |grant| {
                    slots.push(grant.credential_slot().to_owned());
                    if grant.credential_slot() == "automation" {
                        bail!("fixture authentication denial");
                    }
                    Ok(())
                },
                |_| {
                    reads += 1;
                    Ok(dev_tools_secret::SecretMaterial::new(b"fixture".to_vec())?)
                },
            )
            .unwrap();
        assert_eq!(slots, ["automation", "secondary"]);
        assert_eq!(reads, 3);
        assert_eq!(
            counts,
            ProviderValidationCounts {
                authentication_checked: 1,
                authentication_total: 2,
                resources_checked: 3,
                resources_total: 3,
                ..ProviderValidationCounts::default()
            }
        );
    }

    #[test]
    fn provider_validation_separates_unread_invalid_and_valid_operation_keys() {
        use crate::logical_authority::{ResourceKind, ResourcePurpose, ResourceSelection};
        let (mut backend, mut session) = logical_validation_fixture();
        let RuntimeAdministrator::Logical(policy) = &mut backend.policy else {
            unreachable!()
        };
        let resource = policy
            .credentials
            .resources
            .get_mut("service-token")
            .unwrap();
        resource.kind = ResourceKind::OperationOnly;
        resource.purposes = vec![ResourcePurpose::ReleaseSigning];
        resource.projections.clear();
        let rights = ResourceSelection {
            purposes: vec![ResourcePurpose::ReleaseSigning],
            projections: Vec::new(),
        };
        policy
            .credentials
            .resource_caps
            .get_mut("worker")
            .unwrap()
            .resources
            .insert("service-token".into(), rights.clone());
        session
            .authority
            .logical
            .as_mut()
            .unwrap()
            .resources
            .insert("service-token".into(), rights);
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let public = key
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        policy
            .workload_caps
            .get_mut("worker")
            .unwrap()
            .operations
            .release_signing
            .insert(
                "service-token".into(),
                crate::policy_v3_operations::ReleaseKeyCap {
                    public_key: public,
                    products: vec!["fixture".into()],
                },
            );
        for (value, resources, passed, failed) in [
            (None, 1, 0, 0),
            (Some("08".repeat(32)), 2, 0, 1),
            (Some("09".repeat(32)), 2, 1, 0),
        ] {
            let counts = backend
                .validate_providers_with(
                    &operation(),
                    &session,
                    |_| Ok(()),
                    |grant| {
                        if grant.credential_slot() == "automation" {
                            let value = value.as_ref().context("fixture resource unavailable")?;
                            Ok(dev_tools_secret::SecretMaterial::new(
                                value.as_bytes().to_vec(),
                            )?)
                        } else {
                            Ok(dev_tools_secret::SecretMaterial::new(vec![0xff])?)
                        }
                    },
                )
                .unwrap();
            assert_eq!(
                counts,
                ProviderValidationCounts {
                    authentication_checked: 2,
                    authentication_total: 2,
                    resources_checked: resources,
                    resources_total: 2,
                    keys_checked: passed,
                    keys_failed: failed,
                    keys_total: 1,
                }
            );
        }
    }

    #[test]
    fn authentication_cancellation_or_failed_cleanup_prevents_resource_reads() {
        let (backend, session) = logical_validation_fixture();
        for cleanup_failure in [false, true] {
            let cancelled = AtomicBool::new(false);
            let operation = ProviderOperation::new(&cancelled).unwrap();
            let mut attempts = 0;
            let result = backend.validate_providers_with(
                &operation,
                &session,
                |_| {
                    attempts += 1;
                    if cleanup_failure {
                        return Err(dev_tools_secret::SecretError::new(
                            dev_tools_secret::SecretErrorKind::CleanupFailed,
                        )
                        .into());
                    }
                    cancelled.store(true, std::sync::atomic::Ordering::Release);
                    Ok(())
                },
                |_| panic!("terminal authentication reached resource retrieval"),
            );
            assert!(result.is_err());
            assert_eq!(attempts, 1);
        }
    }

    #[test]
    fn provider_validation_cancellation_and_failed_cleanup_prevent_further_reads() {
        let (backend, session) = logical_validation_fixture();
        for cleanup_failure in [false, true] {
            let cancelled = AtomicBool::new(false);
            let operation = ProviderOperation::new(&cancelled).unwrap();
            let mut attempts = 0;
            let result = backend.validate_providers_with(
                &operation,
                &session,
                |_| Ok(()),
                |_| {
                    attempts += 1;
                    if cleanup_failure {
                        return Err(dev_tools_secret::SecretError::new(
                            dev_tools_secret::SecretErrorKind::CleanupFailed,
                        )
                        .into());
                    }
                    cancelled.store(true, std::sync::atomic::Ordering::Release);
                    Ok(dev_tools_secret::SecretMaterial::new(b"fixture".to_vec())?)
                },
            );
            assert!(result.is_err());
            assert_eq!(attempts, 1);
        }
    }

    fn policy_with_two_slots() -> RuntimeAdministrator {
        let authority_cap = |app: &str, reference: &str| AuthorityCap {
            github_apps: vec![app.into()],
            owners: vec!["ExampleOrg".into()],
            repositories: vec!["repository".into()],
            permissions: BTreeMap::from([("contents".into(), Permission::Read)]),
            installation_ids: Vec::new(),
            signing: false,
            release_signing_products: Vec::new(),
            release_signing_keys: Vec::new(),
            ssh: false,
            git_identities: Vec::new(),
            secret_references: vec![reference.into()],
        };
        RuntimeAdministrator::Legacy(crate::policy_v2::SystemPolicyV2 {
            version: 2,
            mode: SystemMode::Strong,
            allowed_users: vec!["automation".into()],
            programs: SystemPrograms {
                op: "/usr/bin/op".into(),
                git: "/usr/bin/git".into(),
                gh: "/usr/bin/gh".into(),
                ssh: "/usr/bin/ssh".into(),
                ssh_keygen: "/usr/bin/ssh-keygen".into(),
            },
            trusted_launchers: BTreeMap::new(),
            github_apps: BTreeMap::from([
                (
                    "alpha".into(),
                    GitHubAppCap {
                        app_id: 1,
                        repository_selection: crate::RepositorySelection::Selected,
                        private_key_references: vec!["op://Vault/alpha/private-key".into()],
                    },
                ),
                (
                    "beta".into(),
                    GitHubAppCap {
                        app_id: 2,
                        repository_selection: crate::RepositorySelection::Selected,
                        private_key_references: vec!["op://Vault/beta/private-key".into()],
                    },
                ),
            ]),
            credential_slots: BTreeMap::from([
                (
                    "alpha".into(),
                    CredentialSlotCap {
                        users: vec!["automation".into()],
                        authority_caps: vec!["alpha".into()],
                        secret_references: vec!["op://Vault/alpha/private-key".into()],
                    },
                ),
                (
                    "beta".into(),
                    CredentialSlotCap {
                        users: vec!["automation".into()],
                        authority_caps: vec!["beta".into()],
                        secret_references: vec!["op://Vault/beta/private-key".into()],
                    },
                ),
            ]),
            authority_caps: BTreeMap::from([
                (
                    "alpha".into(),
                    authority_cap("alpha", "op://Vault/alpha/private-key"),
                ),
                (
                    "beta".into(),
                    authority_cap("beta", "op://Vault/beta/private-key"),
                ),
            ]),
            workspace_caps: BTreeMap::new(),
            sandbox_adapters: BTreeMap::new(),
        })
    }

    #[test]
    fn exact_credential_slot_selects_its_own_service_account_token() {
        let backend = SystemCapabilityBackend {
            policy: policy_with_two_slots(),
            service_tokens: BTreeMap::from([
                ("alpha".into(), SecretString::new("token-alpha".into())),
                ("beta".into(), SecretString::new("token-beta".into())),
            ]),
            cache: Mutex::new(TokenCache::default()),
        };
        let mut grant = SessionGitHubGrant {
            credential_slot: "beta".into(),
            app_id: 2,
            repository_selection: crate::RepositorySelection::Selected,
            private_key_ref: "op://Vault/beta/private-key".into(),
            owners: vec!["exampleorg".into()],
            repositories: vec!["repository".into()],
            permissions: BTreeMap::from([("contents".into(), Permission::Read)]),
            installation_ids: Vec::new(),
        };
        assert_eq!(
            backend.validate_grant(&grant).unwrap().expose(),
            "token-beta"
        );

        grant.credential_slot = "alpha".into();
        assert!(backend.validate_grant(&grant).is_err());
    }

    #[test]
    fn repository_cache_invalidation_uses_the_selection_bound_insertion_key() {
        let backend = SystemCapabilityBackend {
            policy: policy_with_two_slots(),
            service_tokens: BTreeMap::new(),
            cache: Mutex::new(TokenCache::default()),
        };
        let mut grant = SessionGitHubGrant {
            credential_slot: "beta".into(),
            app_id: 2,
            repository_selection: crate::RepositorySelection::Selected,
            private_key_ref: "op://Vault/beta/private-key".into(),
            owners: vec!["exampleorg".into()],
            repositories: vec!["repository".into()],
            permissions: BTreeMap::from([("contents".into(), Permission::Read)]),
            installation_ids: Vec::new(),
        };

        let selected_key =
            repository_cache_key("session", &grant, "ExampleOrg", "Repository").unwrap();
        grant.repository_selection = crate::RepositorySelection::All;
        let all_key = repository_cache_key("session", &grant, "ExampleOrg", "Repository").unwrap();
        assert_ne!(selected_key, all_key);

        for key in [selected_key, all_key] {
            backend
                .cache(
                    &operation(),
                    "session",
                    key.clone(),
                    &BrokerGitHubToken {
                        token: SecretString::new("installation-token".into()),
                        expires_at: i64::MAX,
                    },
                )
                .unwrap();
            assert!(backend.take_cached(&key).unwrap().is_some());
            assert!(backend.take_cached(&key).unwrap().is_none());
        }
    }

    #[test]
    fn cancelled_cache_reads_and_publication_never_issue_a_token() {
        let backend = SystemCapabilityBackend {
            policy: policy_with_two_slots(),
            service_tokens: BTreeMap::new(),
            cache: Mutex::new(TokenCache::default()),
        };
        let live = AtomicBool::new(false);
        let operation =
            ProviderOperation::with_test_timeout(&live, Duration::from_secs(60)).unwrap();
        backend
            .cache(
                &operation,
                "session",
                "active-scope".into(),
                &BrokerGitHubToken {
                    token: SecretString::new("active-token".into()),
                    expires_at: i64::MAX,
                },
            )
            .unwrap();

        live.store(true, std::sync::atomic::Ordering::Release);
        assert!(backend.cached(&operation, "active-scope", 0).is_err());
        assert!(backend
            .cache(
                &operation,
                "session",
                "cancelled-scope".into(),
                &BrokerGitHubToken {
                    token: SecretString::new("cancelled-token".into()),
                    expires_at: i64::MAX,
                },
            )
            .is_err());

        let retained = backend.cache.lock().unwrap().session_revocations("session");
        assert_eq!(retained.len(), 2);
        let cleanup_start = Instant::now();
        backend
            .revoke_session_before_with(
                "session",
                cleanup_start + Duration::from_secs(1),
                || cleanup_start,
                |_token, _timeout| Ok(()),
            )
            .unwrap();
        assert!(backend
            .cache
            .lock()
            .unwrap()
            .session_revocations("session")
            .is_empty());
    }

    #[test]
    fn explicit_invalidation_revokes_active_and_pending_tokens_for_only_the_exact_scope() {
        let backend = SystemCapabilityBackend {
            policy: policy_with_two_slots(),
            service_tokens: BTreeMap::new(),
            cache: Mutex::new(TokenCache::default()),
        };
        let grant = SessionGitHubGrant {
            credential_slot: "beta".into(),
            app_id: 2,
            repository_selection: crate::RepositorySelection::Selected,
            private_key_ref: "op://Vault/beta/private-key".into(),
            owners: vec!["exampleorg".into()],
            repositories: vec!["repository".into()],
            permissions: BTreeMap::from([("contents".into(), Permission::Read)]),
            installation_ids: Vec::new(),
        };
        let session_id = "target-session";
        let target_key =
            repository_cache_key(session_id, &grant, "ExampleOrg", "Repository").unwrap();
        let other_scope_key =
            repository_cache_key(session_id, &grant, "ExampleOrg", "OtherRepository").unwrap();
        let other_session_key =
            repository_cache_key("other-session", &grant, "ExampleOrg", "Repository").unwrap();

        let seed_failed_refresh = |key: &str, session: &str, prefix: &str| {
            backend
                .cache_with(
                    session,
                    key.to_owned(),
                    &BrokerGitHubToken {
                        token: SecretString::new(format!("{prefix}-old")),
                        expires_at: i64::MAX,
                    },
                    || Ok(()),
                    |_token| Ok(()),
                )
                .unwrap();
            assert!(backend
                .cache_with(
                    session,
                    key.to_owned(),
                    &BrokerGitHubToken {
                        token: SecretString::new(format!("{prefix}-active")),
                        expires_at: i64::MAX,
                    },
                    || Ok(()),
                    |token| {
                        assert_eq!(token.expose(), format!("{prefix}-old"));
                        bail!("injected refresh revocation failure")
                    },
                )
                .is_err());
        };
        seed_failed_refresh(&target_key, session_id, "target");
        seed_failed_refresh(&other_scope_key, session_id, "other-scope");
        seed_failed_refresh(&other_session_key, "other-session", "other-session");

        let mut revoked = BTreeSet::new();
        backend
            .invalidate_scope_with(session_id, &target_key, |token| {
                revoked.insert(token.expose().to_owned());
                Ok(())
            })
            .unwrap();

        assert_eq!(
            revoked,
            BTreeSet::from(["target-active".to_owned(), "target-old".to_owned()])
        );
        let cache = backend.cache.lock().unwrap();
        assert!(cache.scope_revocations(session_id, &target_key).is_empty());
        assert_eq!(
            cache.scope_revocations(session_id, &other_scope_key).len(),
            2
        );
        assert_eq!(
            cache
                .scope_revocations("other-session", &other_session_key)
                .len(),
            2
        );
    }

    #[test]
    fn explicit_invalidation_retains_only_failed_tokens_for_retry() {
        let backend = SystemCapabilityBackend {
            policy: policy_with_two_slots(),
            service_tokens: BTreeMap::new(),
            cache: Mutex::new(TokenCache::default()),
        };
        let session_id = "retry-invalidation-session";
        let key = "retry-invalidation-scope";
        backend
            .cache_with(
                session_id,
                key.into(),
                &BrokerGitHubToken {
                    token: SecretString::new("old-token".into()),
                    expires_at: i64::MAX,
                },
                || Ok(()),
                |_token| Ok(()),
            )
            .unwrap();
        assert!(backend
            .cache_with(
                session_id,
                key.into(),
                &BrokerGitHubToken {
                    token: SecretString::new("active-token".into()),
                    expires_at: i64::MAX,
                },
                || Ok(()),
                |_token| bail!("injected refresh revocation failure"),
            )
            .is_err());

        assert!(backend
            .invalidate_scope_with(session_id, key, |token| {
                if token.expose() == "old-token" {
                    bail!("injected invalidation revocation failure");
                }
                Ok(())
            })
            .is_err());
        let retained = backend
            .cache
            .lock()
            .unwrap()
            .scope_revocations(session_id, key);
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].token.expose(), "old-token");

        backend
            .invalidate_scope_with(session_id, key, |_token| Ok(()))
            .unwrap();
        assert!(backend
            .cache
            .lock()
            .unwrap()
            .scope_revocations(session_id, key)
            .is_empty());
    }

    #[test]
    fn failed_session_cleanup_retains_token_for_a_later_successful_retry() {
        let backend = SystemCapabilityBackend {
            policy: policy_with_two_slots(),
            service_tokens: BTreeMap::new(),
            cache: Mutex::new(TokenCache::default()),
        };
        let session_id = "retry-session";
        let key = "scope".to_owned();
        backend
            .cache(
                &operation(),
                session_id,
                key.clone(),
                &BrokerGitHubToken {
                    token: SecretString::new("installation-token".into()),
                    expires_at: i64::MAX,
                },
            )
            .unwrap();
        let start = Instant::now();
        let deadline = start + SESSION_CLEANUP_ATTEMPT_TIMEOUT;

        assert!(backend
            .revoke_session_before_with(
                session_id,
                deadline,
                || start,
                |_token, timeout| {
                    assert_eq!(timeout, GITHUB_API_TIMEOUT);
                    bail!("injected provider failure")
                },
            )
            .is_err());
        assert!(backend.active_revocation(&key).unwrap().is_some());

        backend
            .revoke_session_before_with(
                session_id,
                deadline,
                || start,
                |_token, timeout| {
                    assert_eq!(timeout, GITHUB_API_TIMEOUT);
                    Ok(())
                },
            )
            .unwrap();
        assert!(backend.active_revocation(&key).unwrap().is_none());
    }

    #[test]
    fn session_cleanup_shares_one_deadline_and_leaves_unattempted_tokens_for_retry() {
        let backend = SystemCapabilityBackend {
            policy: policy_with_two_slots(),
            service_tokens: BTreeMap::new(),
            cache: Mutex::new(TokenCache::default()),
        };
        let session_id = "bounded-session";
        for key in ["scope-a", "scope-b"] {
            backend
                .cache(
                    &operation(),
                    session_id,
                    key.into(),
                    &BrokerGitHubToken {
                        token: SecretString::new(format!("installation-token-{key}")),
                        expires_at: i64::MAX,
                    },
                )
                .unwrap();
        }
        let start = Instant::now();
        let deadline = start + SESSION_CLEANUP_ATTEMPT_TIMEOUT;
        let mut times = [start, deadline].into_iter();
        let mut observed_timeouts = Vec::new();

        assert!(backend
            .revoke_session_before_with(
                session_id,
                deadline,
                || times.next().unwrap(),
                |_token, timeout| {
                    observed_timeouts.push(timeout);
                    Ok(())
                },
            )
            .is_err());
        assert_eq!(observed_timeouts, vec![GITHUB_API_TIMEOUT]);
        assert_eq!(
            backend
                .cache
                .lock()
                .unwrap()
                .session_revocations(session_id)
                .len(),
            1
        );

        backend
            .revoke_session_before_with(session_id, deadline, || start, |_token, _timeout| Ok(()))
            .unwrap();
    }

    #[test]
    fn broker_loads_every_declared_slot_and_rejects_extra_or_linked_credentials() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for (slot, value) in [("alpha", "token-alpha"), ("beta", "token-beta")] {
            let path = root
                .path()
                .join(format!("{SERVICE_CREDENTIAL_PREFIX}{slot}"));
            fs::write(&path, value).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let policy = policy_with_two_slots();
        let tokens = read_service_credentials(root.path(), &policy).unwrap();
        assert_eq!(tokens["alpha"].expose(), "token-alpha");
        assert_eq!(tokens["beta"].expose(), "token-beta");

        let extra = root
            .path()
            .join(format!("{SERVICE_CREDENTIAL_PREFIX}undeclared"));
        fs::write(&extra, "unused").unwrap();
        fs::set_permissions(&extra, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_service_credentials(root.path(), &policy).is_err());
        fs::remove_file(extra).unwrap();

        let alpha = root
            .path()
            .join(format!("{SERVICE_CREDENTIAL_PREFIX}alpha"));
        std::fs::hard_link(&alpha, root.path().join("linked-copy")).unwrap();
        assert!(read_service_credentials(root.path(), &policy).is_err());
    }

    #[test]
    fn systemd_root_credential_modes_are_not_general_group_read_authority() {
        let effective_uid = nix::unistd::Uid::effective().as_raw();
        assert!(credential_metadata_mode_is_safe(0, effective_uid, 0o550));
        assert!(credential_metadata_mode_is_safe(0, effective_uid, 0o440));
        assert!(!credential_metadata_mode_is_safe(0, effective_uid, 0o570));
        assert!(!credential_metadata_mode_is_safe(0, effective_uid, 0o444));
        assert!(!credential_metadata_mode_is_safe(
            effective_uid,
            effective_uid,
            0o550
        ));
        assert!(credential_metadata_mode_is_safe(
            effective_uid,
            effective_uid,
            0o500
        ));
    }
}
