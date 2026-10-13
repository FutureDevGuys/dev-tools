//! Public value-free result for explicit metadata of an admitted resource.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    Text,
    Concealed,
    OneTimePassword,
    Other,
}

impl From<dev_tools_secret::SecretValueType> for ValueType {
    fn from(value: dev_tools_secret::SecretValueType) -> Self {
        match value {
            dev_tools_secret::SecretValueType::Text => Self::Text,
            dev_tools_secret::SecretValueType::Concealed => Self::Concealed,
            dev_tools_secret::SecretValueType::OneTimePassword => Self::OneTimePassword,
            dev_tools_secret::SecretValueType::Other => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MetadataReport {
    pub schema: &'static str,
    pub operation: &'static str,
    pub outcome: &'static str,
    pub exit_code: i32,
    pub error_kind: Option<&'static str>,
    /// None on any unsuccessful observation, never an inferred absence.
    pub resource_exists: Option<bool>,
    pub value_type: Option<ValueType>,
}

impl MetadataReport {
    pub fn failure(kind: &'static str, exit_code: i32) -> Self {
        Self {
            schema: "dev-auth-resource-metadata-v1",
            operation: "secret_metadata",
            outcome: "not_observed",
            exit_code,
            error_kind: Some(kind),
            resource_exists: None,
            value_type: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn observed(value_type: ValueType) -> Self {
        Self {
            outcome: "observed",
            error_kind: None,
            resource_exists: Some(true),
            value_type: Some(value_type),
            ..Self::failure("", 0)
        }
    }
}

/// No admission dialog, credential fallback, local discovery or value read.
pub fn discover(resource: &str) -> MetadataReport {
    if dev_tools_secret::LogicalSecretName::parse(resource).is_err() {
        return MetadataReport::failure("invalid_invocation", 2);
    }
    discover_admitted(resource)
}

#[cfg(target_os = "linux")]
fn discover_admitted(resource: &str) -> MetadataReport {
    use crate::broker_protocol::{
        BrokerRequest, BrokerResponse, BrokerSessionProbe, LocalSessionClaim,
    };
    match crate::broker_client::active_claim_and_probe() {
        Ok((LocalSessionClaim::Absent, BrokerSessionProbe::NoSession)) => {
            return MetadataReport::failure("admission_required", 3);
        }
        Ok((LocalSessionClaim::Present { .. }, BrokerSessionProbe::Verified { .. })) => {}
        Ok((_, BrokerSessionProbe::Unavailable { .. })) => {
            return MetadataReport::failure("broker_unavailable", 1);
        }
        _ => return MetadataReport::failure("admission_invalid", 4),
    }
    match crate::broker_client::request_active(BrokerRequest::SecretMetadata {
        resource: resource.into(),
    }) {
        Ok(BrokerResponse::ResourceMetadata { value_type }) => MetadataReport::observed(value_type),
        Ok(BrokerResponse::Denied { code, .. }) => match code.as_str() {
            "metadata_unsupported" => MetadataReport::failure("unsupported", 3),
            "metadata_cancelled" => MetadataReport::failure("cancelled", 130),
            "metadata_deadline" => MetadataReport::failure("deadline_exceeded", 3),
            "metadata_invalid_response" => MetadataReport::failure("invalid_response", 4),
            "metadata_cleanup_failed" => MetadataReport::failure("cleanup_failed", 1),
            "provider_unavailable" => MetadataReport::failure("provider_unavailable", 1),
            _ => MetadataReport::failure("resource_denied", 4),
        },
        Ok(_) => MetadataReport::failure("invalid_response", 4),
        Err(_) => MetadataReport::failure("broker_failed", 1),
    }
}

#[cfg(not(target_os = "linux"))]
fn discover_admitted(_resource: &str) -> MetadataReport {
    MetadataReport::failure("unsupported", 3)
}
