use crate::broker_protocol::{BrokerRequest, BrokerResponse, SshOperationPurpose};
use crate::linux_admission::SessionOperationKeyGrant;
use anyhow::{bail, Context, Result};
use ssh_agent_lib::agent::{listen, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, PublicCredential, SignRequest};
use ssh_key::{PublicKey, Signature};
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const SIGNING_AGENT_ENV: &str = "DEV_AUTH_SIGNING_AGENT_SOCK";

pub fn agent_socket_path(
    owner_uid: u32,
    session_id: &str,
    purpose: SshOperationPurpose,
) -> PathBuf {
    let leaf = match purpose {
        SshOperationPurpose::GitSigning => "signing.sock",
        SshOperationPurpose::Authentication => "authentication.sock",
    };
    PathBuf::from(format!(
        "/run/user/{owner_uid}/dev-auth-v3/agent-sessions/{session_id}/{leaf}"
    ))
}

#[derive(Clone)]
struct BrokerAgentIdentity {
    grant: SessionOperationKeyGrant,
    public_key: PublicKey,
}

#[derive(Clone)]
struct BrokerAgent {
    broker_socket: PathBuf,
    profile: String,
    purpose: SshOperationPurpose,
    identities: Arc<Vec<BrokerAgentIdentity>>,
}

fn agent_failure(message: &'static str) -> AgentError {
    AgentError::other(io::Error::other(message))
}

#[ssh_agent_lib::async_trait]
impl Session for BrokerAgent {
    async fn request_identities(&mut self) -> std::result::Result<Vec<Identity>, AgentError> {
        Ok(self
            .identities
            .iter()
            .map(|identity| Identity {
                credential: PublicCredential::Key(identity.public_key.key_data().clone()),
                comment: format!("dev-auth:{}", identity.grant.fingerprint),
            })
            .collect())
    }

    async fn sign(&mut self, request: SignRequest) -> std::result::Result<Signature, AgentError> {
        if request.flags != 0 {
            return Err(agent_failure("unsupported SSH signature flags"));
        }
        let PublicCredential::Key(requested) = request.credential else {
            return Err(agent_failure("SSH certificates are not broker identities"));
        };
        let identity = self
            .identities
            .iter()
            .find(|identity| identity.public_key.key_data() == &requested)
            .ok_or_else(|| agent_failure("SSH signing identity is outside the workload profile"))?;
        let response = crate::broker_client::request_at(
            &self.broker_socket,
            BrokerRequest::SignSsh {
                profile: self.profile.clone(),
                purpose: self.purpose,
                public_key_fingerprint: identity.grant.fingerprint.clone(),
                payload: request.data.clone(),
            },
        )
        .map_err(|_| agent_failure("workload broker could not perform SSH signing"))?;
        let signature = match response {
            BrokerResponse::Signature { signature } => Signature::try_from(signature.as_slice())
                .map_err(|_| agent_failure("workload broker returned an invalid SSH signature"))?,
            BrokerResponse::Denied { .. }
            | BrokerResponse::NoSession
            | BrokerResponse::Accepted
            | BrokerResponse::Ready { .. }
            | BrokerResponse::GitCredential { .. }
            | BrokerResponse::GhExecutionToken { .. } => {
                return Err(agent_failure("workload broker denied SSH signing"))
            }
        };
        signature::Verifier::verify(&identity.public_key, &request.data, &signature)
            .map_err(|_| agent_failure("workload broker signature did not verify"))?;
        Ok(signature)
    }
}

pub fn run_agent_proxy(
    session_id: &str,
    profile_name: &str,
    purpose: SshOperationPurpose,
    socket: &Path,
    broker_socket: &Path,
) -> Result<()> {
    validate_identifier(session_id, "session identifier")?;
    validate_identifier(profile_name, "authority profile")?;
    let owner_uid = nix::unistd::Uid::effective().as_raw();
    if owner_uid == 0 {
        bail!("broker SSH agent must run as the admitted native user");
    }
    let (_, receipt) = crate::setup::current_installation()?;
    let policy = match receipt.mode {
        crate::setup::InstallMode::Strong => {
            crate::policy_store::load_resolved_policy_for_uid(owner_uid)?
        }
        crate::setup::InstallMode::UserOnly => {
            crate::policy_store::load_user_only_resolved_policy_for_uid(owner_uid)?
        }
    };
    let profile = policy
        .authority_profiles
        .get(profile_name)
        .context("broker SSH agent profile is not configured")?;
    let grants = match purpose {
        SshOperationPurpose::GitSigning => profile.signing_key.iter().collect::<Vec<_>>(),
        SshOperationPurpose::Authentication => profile.ssh_keys.iter().collect::<Vec<_>>(),
    };
    if grants.is_empty() {
        bail!("broker SSH agent purpose has no configured operation key");
    }
    let identities = grants
        .into_iter()
        .map(|grant| {
            Ok(BrokerAgentIdentity {
                public_key: PublicKey::from_openssh(&grant.public_key)
                    .context("parse broker SSH agent public key")?,
                grant: SessionOperationKeyGrant {
                    credential_slot: profile.credential_slot.clone(),
                    private_key_ref: grant.private_key_ref.clone(),
                    public_key: grant.public_key.clone(),
                    fingerprint: grant.fingerprint.clone(),
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let listener = bind_agent_socket(socket, session_id, purpose, owner_uid)?;
    validate_broker_socket(broker_socket, session_id, receipt.mode, owner_uid)?;
    let agent = BrokerAgent {
        broker_socket: broker_socket.to_owned(),
        profile: profile_name.to_owned(),
        purpose,
        identities: Arc::new(identities),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("create broker SSH agent runtime")?;
    runtime
        .block_on(listen(listener, agent))
        .map_err(anyhow::Error::from)
        .context("serve broker SSH agent")
}

fn bind_agent_socket(
    socket: &Path,
    session_id: &str,
    purpose: SshOperationPurpose,
    owner_uid: u32,
) -> Result<tokio::net::UnixListener> {
    let runtime = PathBuf::from(format!("/run/user/{owner_uid}"));
    let product = runtime.join("dev-auth-v3");
    let agents = product.join("agent-sessions");
    let session = agents.join(session_id);
    if socket != agent_socket_path(owner_uid, session_id, purpose) {
        bail!("broker SSH agent socket is outside the private session runtime");
    }
    validate_private_directory(&runtime, owner_uid)?;
    for directory in [&product, &agents, &session] {
        match fs::create_dir(directory) {
            Ok(()) => fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("create broker agent directory {}", directory.display())
                })
            }
        }
        validate_private_directory(directory, owner_uid)?;
    }
    let listener =
        tokio::net::UnixListener::bind(socket).context("bind broker SSH agent socket")?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    let metadata = fs::symlink_metadata(socket).context("inspect broker SSH agent socket")?;
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o077 != 0
    {
        bail!("broker SSH agent socket has unsafe authority");
    }
    Ok(listener)
}

fn validate_broker_socket(
    socket: &Path,
    session_id: &str,
    mode: crate::setup::InstallMode,
    owner_uid: u32,
) -> Result<()> {
    match mode {
        crate::setup::InstallMode::Strong => {
            if socket != Path::new(crate::broker_client::SYSTEM_BROKER_SOCKET) {
                bail!("strong SSH agent broker selector is invalid");
            }
        }
        crate::setup::InstallMode::UserOnly => {
            let expected = PathBuf::from(format!(
                "/run/user/{owner_uid}/dev-auth-v3/user-sessions/{session_id}/broker.sock"
            ));
            if socket != expected {
                bail!("user-only SSH agent broker selector is invalid");
            }
        }
    }
    let metadata = fs::symlink_metadata(socket).context("inspect SSH agent broker socket")?;
    let expected_uid = match mode {
        crate::setup::InstallMode::Strong => 0,
        crate::setup::InstallMode::UserOnly => owner_uid,
    };
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_uid
        || (mode == crate::setup::InstallMode::UserOnly && metadata.mode() & 0o077 != 0)
    {
        bail!("SSH agent broker selector is not a native socket");
    }
    Ok(())
}

fn validate_private_directory(path: &Path, owner_uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect private runtime directory {}", path.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o077 != 0
    {
        bail!("private runtime directory has unsafe authority");
    }
    Ok(())
}

fn validate_identifier(value: &str, description: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        bail!("{description} is invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker_protocol::{
        decode_request_frame, encode_response_frame, BrokerResponseEnvelope,
        BROKER_PROTOCOL_VERSION,
    };
    use signature::Signer;
    use ssh_key::private::{Ed25519Keypair, KeypairData};
    use ssh_key::{HashAlg, PrivateKey};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;

    #[test]
    fn agent_forwards_only_the_bound_identity_and_verifies_the_broker_signature() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let private_key = PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[31; 32])),
            "broker agent test",
        )
        .unwrap();
        let public_key = private_key.public_key().clone();
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        let expected_fingerprint = fingerprint.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0_u8; 4];
            stream.read_exact(&mut length).unwrap();
            let mut request = vec![0_u8; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut request).unwrap();
            let request = decode_request_frame(&request).unwrap();
            let BrokerRequest::SignSsh {
                profile,
                purpose,
                public_key_fingerprint,
                payload,
            } = request.request
            else {
                panic!("unexpected broker request")
            };
            assert_eq!(profile, "automation");
            assert_eq!(purpose, SshOperationPurpose::Authentication);
            assert_eq!(public_key_fingerprint, expected_fingerprint);
            let signature = private_key.try_sign(&payload).unwrap();
            let response = encode_response_frame(&BrokerResponseEnvelope {
                version: BROKER_PROTOCOL_VERSION,
                request_id: request.request_id,
                response: BrokerResponse::Signature {
                    signature: Vec::<u8>::try_from(signature).unwrap(),
                },
            })
            .unwrap();
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        });
        let grant = SessionOperationKeyGrant {
            credential_slot: "automation".into(),
            private_key_ref: "op://Automation/ssh/private-key".into(),
            public_key: public_key.to_openssh().unwrap(),
            fingerprint,
        };
        let mut agent = BrokerAgent {
            broker_socket: socket,
            profile: "automation".into(),
            purpose: SshOperationPurpose::Authentication,
            identities: Arc::new(vec![BrokerAgentIdentity {
                grant,
                public_key: public_key.clone(),
            }]),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let payload = b"SSH authentication challenge".to_vec();
        let signature = runtime
            .block_on(agent.sign(SignRequest {
                credential: PublicCredential::Key(public_key.key_data().clone()),
                data: payload.clone(),
                flags: 0,
            }))
            .unwrap();
        signature::Verifier::verify(&public_key, &payload, &signature).unwrap();
        server.join().unwrap();
    }
}
