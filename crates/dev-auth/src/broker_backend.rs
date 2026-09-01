use crate::broker_protocol::SshOperationPurpose;
use crate::linux_admission::{SessionGitHubGrant, SessionOperationKeyGrant};
use crate::policy_v2::{SystemMode, SystemPolicyV2};
use crate::runtime::{
    broker_github_token_for_repositories, broker_github_token_for_repository,
    broker_revoke_github_token, broker_sign_ssh, BrokerGitHubAuthority, BrokerGitHubToken,
};
use crate::SecretString;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use time::OffsetDateTime;

const CREDENTIAL_LIMIT: u64 = 64 * 1024;
const TOKEN_REFRESH_MARGIN_SECONDS: i64 = 300;
const SERVICE_CREDENTIAL_NAME: &str = "op-service-account-token";

pub(crate) trait CapabilityBackend: Send + Sync {
    fn github_token(
        &self,
        session_id: &str,
        grant: &SessionGitHubGrant,
        owner: &str,
        repository: &str,
    ) -> Result<BrokerGitHubToken>;

    fn gh_token(&self, session_id: &str, grant: &SessionGitHubGrant) -> Result<BrokerGitHubToken>;

    fn invalidate_github_token(
        &self,
        session_id: &str,
        grant: &SessionGitHubGrant,
        owner: &str,
        repository: &str,
    ) -> Result<()>;

    fn sign_ssh(
        &self,
        session_id: &str,
        purpose: SshOperationPurpose,
        grant: &SessionOperationKeyGrant,
        payload: &[u8],
    ) -> Result<Vec<u8>>;

    fn revoke_session(&self, session_id: &str) -> Result<()>;
}

struct CachedToken {
    session_id: String,
    token: SecretString,
    expires_at: i64,
}

pub(crate) struct SystemCapabilityBackend {
    policy: SystemPolicyV2,
    service_token: SecretString,
    cache: Mutex<BTreeMap<String, CachedToken>>,
}

impl SystemCapabilityBackend {
    pub(crate) fn load() -> Result<Self> {
        Self::load_at(
            Path::new(crate::policy_store::SYSTEM_POLICY_PATH),
            systemd_credential_path()?.as_path(),
        )
    }

    pub(crate) fn load_user(policy_path: &Path, owner_uid: u32) -> Result<Self> {
        let policy = crate::policy_store::load_user_policy_at(policy_path, owner_uid)?;
        if policy.mode != SystemMode::UserOnly {
            bail!("user broker requires a user-only administrator policy");
        }
        Ok(Self {
            policy,
            service_token: crate::runtime::user_broker_service_token()?,
            cache: Mutex::new(BTreeMap::new()),
        })
    }

    fn load_at(policy_path: &Path, credential_path: &Path) -> Result<Self> {
        let policy = crate::policy_store::load_system_policy_at(policy_path)?;
        if policy.mode != SystemMode::Strong {
            bail!("system broker requires a strong-mode administrator policy");
        }
        let service_token = read_service_credential(credential_path)?;
        Ok(Self {
            policy,
            service_token,
            cache: Mutex::new(BTreeMap::new()),
        })
    }

    fn validate_grant(&self, grant: &SessionGitHubGrant) -> Result<()> {
        let (app_name, app) = self
            .policy
            .github_apps
            .iter()
            .find(|(_, app)| app.app_id == grant.app_id)
            .context("session GitHub App is outside administrator policy")?;
        if !app.private_key_references.contains(&grant.private_key_ref) {
            bail!("session GitHub private-key reference is outside administrator policy");
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
        let allowed = self.policy.authority_caps.values().any(|cap| {
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
        Ok(())
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
    ) -> Result<()> {
        let allowed = self.policy.authority_caps.values().any(|cap| {
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
        Ok(())
    }

    fn cached(&self, key: &str, now: i64) -> Result<Option<BrokerGitHubToken>> {
        let cache = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("broker token cache lock is poisoned"))?;
        Ok(cache.get(key).and_then(|entry| {
            (entry.expires_at > now + TOKEN_REFRESH_MARGIN_SECONDS).then(|| BrokerGitHubToken {
                token: entry.token.clone(),
                expires_at: entry.expires_at,
            })
        }))
    }

    fn cache(&self, session_id: &str, key: String, token: &BrokerGitHubToken) -> Result<()> {
        let replaced = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("broker token cache lock is poisoned"))?
            .insert(
                key,
                CachedToken {
                    session_id: session_id.to_owned(),
                    token: token.token.clone(),
                    expires_at: token.expires_at,
                },
            );
        if let Some(replaced) = replaced {
            broker_revoke_github_token(&replaced.token)?;
        }
        Ok(())
    }
}

impl CapabilityBackend for SystemCapabilityBackend {
    fn github_token(
        &self,
        session_id: &str,
        grant: &SessionGitHubGrant,
        owner: &str,
        repository: &str,
    ) -> Result<BrokerGitHubToken> {
        self.validate_grant(grant)?;
        let public_scope = serde_json::to_vec(&(
            session_id,
            grant.app_id,
            owner.to_ascii_lowercase(),
            repository.to_ascii_lowercase(),
            &grant.permissions,
            &grant.installation_ids,
        ))?;
        let key = format!("{:x}", Sha256::digest(public_scope));
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if let Some(token) = self.cached(&key, now)? {
            return Ok(token);
        }
        let token = broker_github_token_for_repository(
            BrokerGitHubAuthority {
                op_program: &self.policy.programs.op,
                service_token: &self.service_token,
                app_id: grant.app_id,
                private_key_ref: &grant.private_key_ref,
                permissions: Self::permissions(grant),
                installation_ids: &grant.installation_ids,
            },
            owner,
            repository,
        )?;
        self.cache(session_id, key, &token)?;
        Ok(token)
    }

    fn gh_token(&self, session_id: &str, grant: &SessionGitHubGrant) -> Result<BrokerGitHubToken> {
        self.validate_grant(grant)?;
        let [owner] = grant.owners.as_slice() else {
            bail!("GitHub CLI authority requires exactly one owner");
        };
        if grant.repositories.is_empty() {
            bail!("GitHub CLI authority requires an exact finite repository set");
        }
        let public_scope = serde_json::to_vec(&(
            "gh",
            session_id,
            grant.app_id,
            owner.to_ascii_lowercase(),
            &grant.repositories,
            &grant.permissions,
            &grant.installation_ids,
        ))?;
        let key = format!("{:x}", Sha256::digest(public_scope));
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if let Some(token) = self.cached(&key, now)? {
            return Ok(token);
        }
        let token = broker_github_token_for_repositories(
            BrokerGitHubAuthority {
                op_program: &self.policy.programs.op,
                service_token: &self.service_token,
                app_id: grant.app_id,
                private_key_ref: &grant.private_key_ref,
                permissions: Self::permissions(grant),
                installation_ids: &grant.installation_ids,
            },
            owner,
            &grant.repositories,
        )?;
        self.cache(session_id, key, &token)?;
        Ok(token)
    }

    fn invalidate_github_token(
        &self,
        session_id: &str,
        grant: &SessionGitHubGrant,
        owner: &str,
        repository: &str,
    ) -> Result<()> {
        self.validate_grant(grant)?;
        let public_scope = serde_json::to_vec(&(
            session_id,
            grant.app_id,
            owner.to_ascii_lowercase(),
            repository.to_ascii_lowercase(),
            &grant.permissions,
            &grant.installation_ids,
        ))?;
        let key = format!("{:x}", Sha256::digest(public_scope));
        let removed = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("broker token cache lock is poisoned"))?
            .remove(&key);
        if let Some(removed) = removed {
            broker_revoke_github_token(&removed.token)?;
        }
        Ok(())
    }

    fn sign_ssh(
        &self,
        _session_id: &str,
        purpose: SshOperationPurpose,
        grant: &SessionOperationKeyGrant,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        self.validate_operation_grant(purpose, grant)?;
        broker_sign_ssh(
            &self.policy.programs.op,
            &self.service_token,
            &grant.private_key_ref,
            &grant.public_key,
            &grant.fingerprint,
            payload,
        )
    }

    fn revoke_session(&self, session_id: &str) -> Result<()> {
        let tokens = {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| anyhow::anyhow!("broker token cache lock is poisoned"))?;
            let keys = cache
                .iter()
                .filter_map(|(key, token)| (token.session_id == session_id).then_some(key.clone()))
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|key| cache.remove(&key))
                .collect::<Vec<_>>()
        };
        let mut revocation_failed = false;
        for token in tokens {
            if broker_revoke_github_token(&token.token).is_err() {
                revocation_failed = true;
            }
        }
        if revocation_failed {
            bail!("one or more session tokens could not be revoked");
        }
        Ok(())
    }
}

fn systemd_credential_path() -> Result<PathBuf> {
    let directory = PathBuf::from(
        std::env::var_os("CREDENTIALS_DIRECTORY")
            .context("systemd did not provide the broker credential directory")?,
    );
    if !directory.is_absolute() {
        bail!("systemd credential directory is not absolute");
    }
    Ok(directory.join(SERVICE_CREDENTIAL_NAME))
}

fn read_service_credential(path: &Path) -> Result<SecretString> {
    let metadata = fs::symlink_metadata(path).context("inspect broker service credential")?;
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || (metadata.uid() != 0 && metadata.uid() != effective_uid)
        || metadata.mode() & 0o077 != 0
        || metadata.len() > CREDENTIAL_LIMIT
    {
        bail!("broker service credential has unsafe filesystem authority");
    }
    let bytes = read_bounded_file(path, CREDENTIAL_LIMIT, "broker service credential")?;
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

fn read_bounded_file(path: &Path, limit: u64, description: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("open {description}"))?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {description}"))?;
    if bytes.len() as u64 > limit {
        bail!("{description} exceeds the size limit");
    }
    Ok(bytes)
}
