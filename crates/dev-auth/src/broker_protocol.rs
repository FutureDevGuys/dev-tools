use anyhow::{bail, Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use zeroize::Zeroizing;

pub const BROKER_PROTOCOL_VERSION: u32 = 3;
pub const MAX_BROKER_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_BROKER_RESPONSE_FRAME_BYTES: usize = 256 * 1024;
pub const MAX_SECRET_MATERIAL_BYTES: usize = 64 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct SensitiveBytes(Zeroizing<Vec<u8>>);

impl SensitiveBytes {
    pub fn new(value: Vec<u8>) -> Result<Self> {
        let value = Zeroizing::new(value);
        if value.len() > MAX_SECRET_MATERIAL_BYTES {
            bail!("secret material exceeds the size limit");
        }
        Ok(Self(value))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl Serialize for SensitiveBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        use base64::Engine;
        let encoded =
            Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(self.expose()));
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for SensitiveBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        use base64::Engine;
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        if encoded.len() > MAX_SECRET_MATERIAL_BYTES.div_ceil(3) * 4 {
            return Err(serde::de::Error::custom(
                "secret material exceeds the size limit",
            ));
        }
        let mut value = Zeroizing::new(vec![0u8; encoded.len() / 4 * 3]);
        let length = base64::engine::general_purpose::STANDARD
            .decode_slice(encoded.as_bytes(), &mut value)
            .map_err(|_| serde::de::Error::custom("secret material encoding is invalid"))?;
        if length > MAX_SECRET_MATERIAL_BYTES {
            return Err(serde::de::Error::custom(
                "secret material exceeds the size limit",
            ));
        }
        value.truncate(length);
        Ok(Self(value))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SensitiveString(Zeroizing<String>);

impl SensitiveString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SensitiveString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl fmt::Display for SensitiveString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl Serialize for SensitiveString {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.expose())
    }
}

impl<'de> Deserialize<'de> for SensitiveString {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrokerRequestEnvelope {
    pub version: u32,
    pub request_id: String,
    pub request: BrokerRequest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrokerRequest {
    #[serde(deserialize_with = "crate::strict_serde::empty_variant")]
    ValidateProviders,
    SecretRead {
        resource: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        projection: Option<crate::logical_authority::Projection>,
    },
    SecretPublic {
        resource: String,
    },
    #[serde(deserialize_with = "crate::strict_serde::empty_variant")]
    Probe,
    ActivateSession {
        session_id: String,
    },
    RenewSession {
        session_id: String,
    },
    EndSession {
        session_id: String,
    },
    GitCredential {
        protocol: String,
        host: String,
        owner: String,
        repository: String,
    },
    InvalidateGitCredential {
        protocol: String,
        host: String,
        owner: String,
        repository: String,
    },
    #[serde(deserialize_with = "crate::strict_serde::empty_variant")]
    GhExecutionToken,
    SignSsh {
        profile: String,
        purpose: SshOperationPurpose,
        public_key_fingerprint: String,
        #[serde(with = "hex_bytes")]
        payload: Vec<u8>,
    },
    SignReleaseManifest {
        profile: String,
        release_public_key: String,
        #[serde(with = "hex_bytes")]
        payload: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SshOperationPurpose {
    GitSigning,
    Authentication,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrokerResponseEnvelope {
    pub version: u32,
    pub request_id: String,
    pub response: BrokerResponse,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BrokerResponse {
    ProviderValidation {
        authentication_checked: u32,
        authentication_total: u32,
        resources_checked: u32,
        resources_total: u32,
        keys_checked: u32,
        keys_failed: u32,
        keys_total: u32,
    },
    SecretMaterial {
        material: SensitiveBytes,
    },
    NoSession,
    Accepted,
    Ready {
        session_id: String,
        owner_uid: u32,
        execution_uid: u32,
        workload: String,
        profile: String,
        expires_at: String,
        hard_deadline_boot_ms: Option<u64>,
    },
    GitCredential {
        username: String,
        password: SensitiveString,
        expires_at: String,
    },
    GhExecutionToken {
        token: SensitiveString,
        expires_at: String,
    },
    Signature {
        #[serde(with = "hex_bytes")]
        signature: Vec<u8>,
    },
    Denied {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalSessionClaim {
    Absent,
    Present { marker: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerSessionProbe {
    Verified {
        session_id: String,
        owner_uid: u32,
        execution_uid: u32,
        workload: String,
        profile: String,
    },
    NoSession,
    Invalid {
        reason: String,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingDecision {
    NativePassthrough,
    BrokerSession {
        session_id: String,
        workload: String,
        profile: String,
    },
    Deny {
        reason: String,
    },
}

pub fn decide_routing(claim: &LocalSessionClaim, probe: BrokerSessionProbe) -> RoutingDecision {
    match (claim, probe) {
        (LocalSessionClaim::Absent, BrokerSessionProbe::NoSession) => {
            RoutingDecision::NativePassthrough
        }
        (
            LocalSessionClaim::Present { .. },
            BrokerSessionProbe::Verified {
                session_id,
                workload,
                profile,
                ..
            },
        ) => RoutingDecision::BrokerSession {
            session_id,
            workload,
            profile,
        },
        (LocalSessionClaim::Absent, BrokerSessionProbe::Verified { .. }) => RoutingDecision::Deny {
            reason: "broker reported a session without a trusted local admission marker".into(),
        },
        (LocalSessionClaim::Present { .. }, BrokerSessionProbe::NoSession) => {
            RoutingDecision::Deny {
                reason: "trusted local admission marker has no active broker session".into(),
            }
        }
        (_, BrokerSessionProbe::Invalid { reason })
        | (_, BrokerSessionProbe::Unavailable { reason }) => RoutingDecision::Deny { reason },
    }
}

pub fn decode_request_frame(input: &[u8]) -> Result<BrokerRequestEnvelope> {
    if input.len() > MAX_BROKER_FRAME_BYTES {
        bail!("broker request exceeds the frame limit");
    }
    let request: BrokerRequestEnvelope =
        serde_json::from_slice(input).context("parse broker request")?;
    validate_request_envelope(&request)?;
    Ok(request)
}

pub fn encode_request_frame(request: &BrokerRequestEnvelope) -> Result<Vec<u8>> {
    validate_request_envelope(request)?;
    let output = serde_json::to_vec(request).context("serialize broker request")?;
    if output.len() > MAX_BROKER_FRAME_BYTES {
        bail!("broker request exceeds the frame limit");
    }
    Ok(output)
}

pub fn decode_response_frame(input: &[u8]) -> Result<BrokerResponseEnvelope> {
    if input.len() > MAX_BROKER_RESPONSE_FRAME_BYTES {
        bail!("broker response exceeds the frame limit");
    }
    let response: BrokerResponseEnvelope =
        serde_json::from_slice(input).context("parse broker response")?;
    if response.version != BROKER_PROTOCOL_VERSION {
        bail!("broker response protocol version is unsupported");
    }
    validate_request_id(&response.request_id)?;
    validate_response(&response.response)?;
    Ok(response)
}

pub fn encode_response_frame(response: &BrokerResponseEnvelope) -> Result<Vec<u8>> {
    if response.version != BROKER_PROTOCOL_VERSION {
        bail!("broker response protocol version is unsupported");
    }
    validate_request_id(&response.request_id)?;
    validate_response(&response.response)?;
    let output = serde_json::to_vec(response).context("serialize broker response")?;
    if output.len() > MAX_BROKER_RESPONSE_FRAME_BYTES {
        bail!("broker response exceeds the frame limit");
    }
    Ok(output)
}

fn validate_response(response: &BrokerResponse) -> Result<()> {
    match response {
        BrokerResponse::ProviderValidation {
            authentication_checked,
            authentication_total,
            resources_checked,
            resources_total,
            keys_checked,
            keys_failed,
            keys_total,
        } => {
            if resources_checked > resources_total
                || authentication_checked > authentication_total
                || keys_checked
                    .checked_add(*keys_failed)
                    .is_none_or(|observed| observed > *keys_total)
            {
                bail!("provider validation counts are invalid");
            }
            Ok(())
        }
        BrokerResponse::SecretMaterial { .. } => Ok(()),
        BrokerResponse::Ready {
            session_id,
            workload,
            profile,
            expires_at,
            ..
        } => {
            validate_request_id(session_id)?;
            validate_public_identifier(workload, "workload")?;
            validate_public_identifier(profile, "authority profile")?;
            validate_timestamp(expires_at)
        }
        BrokerResponse::GitCredential {
            username,
            password,
            expires_at,
        } => {
            if username != "x-access-token" || !valid_secret(password.expose()) {
                bail!("broker Git credential response is invalid");
            }
            validate_timestamp(expires_at)
        }
        BrokerResponse::GhExecutionToken { token, expires_at } => {
            if !valid_secret(token.expose()) {
                bail!("broker GitHub CLI token response is invalid");
            }
            validate_timestamp(expires_at)
        }
        BrokerResponse::Signature { signature } => {
            if signature.is_empty() || signature.len() > 16 * 1024 {
                bail!("broker signature response is invalid");
            }
            Ok(())
        }
        BrokerResponse::Denied { code, message } => {
            validate_public_identifier(code, "denial code")?;
            if message.is_empty()
                || message.len() > 512
                || message
                    .chars()
                    .any(|character| character.is_control() && character != '\t')
            {
                bail!("broker denial message is invalid");
            }
            Ok(())
        }
        BrokerResponse::NoSession | BrokerResponse::Accepted => Ok(()),
    }
}

fn validate_timestamp(value: &str) -> Result<()> {
    OffsetDateTime::parse(value, &Rfc3339)
        .context("broker response timestamp is invalid")
        .map(|_| ())
}

fn valid_secret(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 * 1024 && !value.contains(['\n', '\r', '\0'])
}

fn validate_public_identifier(value: &str, description: &str) -> Result<()> {
    let mut bytes = value.bytes();
    if value.len() > 64
        || !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        bail!("broker {description} is invalid");
    }
    Ok(())
}

fn validate_request_envelope(request: &BrokerRequestEnvelope) -> Result<()> {
    if request.version != BROKER_PROTOCOL_VERSION {
        bail!("broker request protocol version is unsupported");
    }
    validate_request_id(&request.request_id)?;
    match &request.request {
        BrokerRequest::SecretRead { resource, .. } | BrokerRequest::SecretPublic { resource } => {
            dev_tools_secret::LogicalSecretName::parse(resource.clone())
                .map(|_| ())
                .map_err(|_| anyhow::anyhow!("logical resource name is invalid"))
        }
        BrokerRequest::Probe | BrokerRequest::ValidateProviders => Ok(()),
        BrokerRequest::ActivateSession { session_id }
        | BrokerRequest::RenewSession { session_id }
        | BrokerRequest::EndSession { session_id } => validate_request_id(session_id),
        BrokerRequest::GitCredential {
            protocol,
            host,
            owner,
            repository,
        }
        | BrokerRequest::InvalidateGitCredential {
            protocol,
            host,
            owner,
            repository,
        } => {
            if protocol != "https" {
                bail!("Git credential protocol is not admitted");
            }
            if host != "github.com" {
                bail!("Git credential host is not admitted");
            }
            validate_resource_component(owner, "GitHub owner")?;
            validate_resource_component(repository, "GitHub repository")
        }
        BrokerRequest::GhExecutionToken => Ok(()),
        BrokerRequest::SignSsh {
            profile,
            purpose: _,
            public_key_fingerprint,
            payload,
        } => {
            validate_resource_component(profile, "SSH profile")?;
            if !crate::is_sha256_fingerprint(public_key_fingerprint) {
                bail!("SSH key fingerprint is invalid");
            }
            if payload.is_empty() || payload.len() > 1024 * 1024 {
                bail!("SSH signing payload size is invalid");
            }
            Ok(())
        }
        BrokerRequest::SignReleaseManifest {
            profile,
            release_public_key,
            payload,
        } => {
            validate_resource_component(profile, "release-signing profile")?;
            dev_tools_release::parse_release_public_key(release_public_key)?;
            dev_tools_release::validate_unsigned_release_document(payload)?;
            Ok(())
        }
    }
}

fn validate_request_id(value: &str) -> Result<()> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("broker request identifier must contain exactly 32 hexadecimal characters");
    }
    Ok(())
}

fn validate_resource_component(value: &str, description: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 255
        || value.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(character, '/' | '\\' | '@' | ':' | '?' | '#')
        })
    {
        bail!("{description} is invalid");
    }
    Ok(())
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = String::with_capacity(value.len() * 2);
        for byte in value {
            use std::fmt::Write;
            write!(&mut output, "{byte:02x}").map_err(serde::ser::Error::custom)?;
        }
        serializer.serialize_str(&output)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = String::deserialize(deserializer)?;
        if input.len() % 2 != 0 || !input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(serde::de::Error::custom("hex byte string is invalid"));
        }
        input
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = std::str::from_utf8(pair).map_err(serde::de::Error::custom)?;
                u8::from_str_radix(text, 16).map_err(serde::de::Error::custom)
            })
            .collect()
    }
}
