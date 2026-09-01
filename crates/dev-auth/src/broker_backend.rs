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
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use time::OffsetDateTime;

const CREDENTIAL_LIMIT: u64 = 64 * 1024;
const TOKEN_REFRESH_MARGIN_SECONDS: i64 = 300;
const SERVICE_CREDENTIAL_PREFIX: &str = "op-service-account-token_";

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
    service_tokens: BTreeMap<String, SecretString>,
    cache: Mutex<BTreeMap<String, CachedToken>>,
}

impl SystemCapabilityBackend {
    pub(crate) fn load() -> Result<Self> {
        Self::load_at(
            Path::new(crate::policy_store::SYSTEM_POLICY_PATH),
            systemd_credential_directory()?.as_path(),
        )
    }

    pub(crate) fn load_user(policy_path: &Path, owner_uid: u32) -> Result<Self> {
        let policy = crate::policy_store::load_user_policy_at(policy_path, owner_uid)?;
        if policy.mode != SystemMode::UserOnly {
            bail!("user broker requires a user-only administrator policy");
        }
        Ok(Self {
            service_tokens: crate::runtime::user_broker_service_tokens(
                policy.credential_slots.keys().map(String::as_str),
            )?,
            policy,
            cache: Mutex::new(BTreeMap::new()),
        })
    }

    fn load_at(policy_path: &Path, credential_directory: &Path) -> Result<Self> {
        let policy = crate::policy_store::load_system_policy_at(policy_path)?;
        if policy.mode != SystemMode::Strong {
            bail!("system broker requires a strong-mode administrator policy");
        }
        let service_tokens = read_service_credentials(credential_directory, &policy)?;
        Ok(Self {
            policy,
            service_tokens,
            cache: Mutex::new(BTreeMap::new()),
        })
    }

    fn service_token(&self, slot: &str) -> Result<&SecretString> {
        self.service_tokens
            .get(slot)
            .context("session credential slot is not loaded by the broker")
    }

    fn validate_grant(&self, grant: &SessionGitHubGrant) -> Result<&SecretString> {
        let slot = self
            .policy
            .credential_slots
            .get(&grant.credential_slot)
            .context("session credential slot is outside administrator policy")?;
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
        let allowed = self.policy.authority_caps.iter().any(|(cap_name, cap)| {
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
        let slot = self
            .policy
            .credential_slots
            .get(&grant.credential_slot)
            .context("session credential slot is outside administrator policy")?;
        let allowed = self.policy.authority_caps.iter().any(|(cap_name, cap)| {
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
        let service_token = self.validate_grant(grant)?;
        let public_scope = serde_json::to_vec(&(
            session_id,
            &grant.credential_slot,
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
                service_token,
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
        let service_token = self.validate_grant(grant)?;
        let [owner] = grant.owners.as_slice() else {
            bail!("GitHub CLI authority requires exactly one owner");
        };
        if grant.repositories.is_empty() {
            bail!("GitHub CLI authority requires an exact finite repository set");
        }
        let public_scope = serde_json::to_vec(&(
            "gh",
            session_id,
            &grant.credential_slot,
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
                service_token,
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
            &grant.credential_slot,
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
        let service_token = self.validate_operation_grant(purpose, grant)?;
        broker_sign_ssh(
            &self.policy.programs.op,
            service_token,
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
    policy: &SystemPolicyV2,
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
    for slot in policy.credential_slots.keys() {
        let path = directory.join(format!("{SERVICE_CREDENTIAL_PREFIX}{slot}"));
        tokens.insert(slot.clone(), read_service_credential(&path)?);
    }
    for entry in fs::read_dir(directory).context("enumerate broker credentials")? {
        let entry = entry.context("read broker credential entry")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(slot) = name.strip_prefix(SERVICE_CREDENTIAL_PREFIX) {
            if !policy.credential_slots.contains_key(slot) {
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

    fn policy_with_two_slots() -> SystemPolicyV2 {
        let authority_cap = |app: &str, reference: &str| AuthorityCap {
            github_apps: vec![app.into()],
            owners: vec!["ExampleOrg".into()],
            repositories: vec!["repository".into()],
            permissions: BTreeMap::from([("contents".into(), Permission::Read)]),
            installation_ids: Vec::new(),
            signing: false,
            ssh: false,
            git_identities: Vec::new(),
            secret_references: vec![reference.into()],
        };
        SystemPolicyV2 {
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
                        private_key_references: vec!["op://Vault/alpha/private-key".into()],
                    },
                ),
                (
                    "beta".into(),
                    GitHubAppCap {
                        app_id: 2,
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
        }
    }

    #[test]
    fn exact_credential_slot_selects_its_own_service_account_token() {
        let backend = SystemCapabilityBackend {
            policy: policy_with_two_slots(),
            service_tokens: BTreeMap::from([
                ("alpha".into(), SecretString::new("token-alpha".into())),
                ("beta".into(), SecretString::new("token-beta".into())),
            ]),
            cache: Mutex::new(BTreeMap::new()),
        };
        let mut grant = SessionGitHubGrant {
            credential_slot: "beta".into(),
            app_id: 2,
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
