//! Provider-neutral contracts for bounded secret operations.
//!
//! This crate owns representation, cancellation, deadlines, capabilities, and
//! value-free failures. It deliberately owns no product authorization policy,
//! provider authentication mechanism, ambient credential lookup, or logging.

use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_REFERENCE_BYTES: usize = 4 * 1024;
const MAX_SECRET_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderId(String);

impl ProviderId {
    pub fn parse(value: impl Into<String>) -> Result<Self, SecretError> {
        Ok(Self(parse_identifier(value.into())?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LogicalSecretName(String);

impl LogicalSecretName {
    pub fn parse(value: impl Into<String>) -> Result<Self, SecretError> {
        Ok(Self(parse_identifier(value.into())?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque provider-native reference. It intentionally implements neither
/// `Debug` nor `Display`, preventing accidental diagnostic interpolation.
///
/// ```compile_fail
/// let reference = dev_tools_secret::SecretReference::new("provider://secret").unwrap();
/// println!("{reference:?}");
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretReference(String);

impl SecretReference {
    pub fn new(value: impl Into<String>) -> Result<Self, SecretError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_REFERENCE_BYTES
            || value
                .bytes()
                .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
        {
            return Err(SecretError::new(SecretErrorKind::InvalidReference));
        }
        Ok(Self(value))
    }

    /// Exposes the opaque value only at the trusted provider adapter boundary.
    pub fn expose_to_provider(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretPurpose {
    Export,
    PublicMaterial,
    Sign,
    Metadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderCapabilities {
    pub exportable_read: bool,
    pub public_material: bool,
    pub signing: bool,
    pub metadata: bool,
}

impl ProviderCapabilities {
    pub fn allows(self, purpose: SecretPurpose) -> bool {
        match purpose {
            SecretPurpose::Export => self.exportable_read,
            SecretPurpose::PublicMaterial => self.public_material,
            SecretPurpose::Sign => self.signing,
            SecretPurpose::Metadata => self.metadata,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderHealth {
    Healthy,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretMetadata {
    pub exportable: bool,
    pub public_material: bool,
    pub signing: bool,
}

/// Secret bytes zeroized on explicit request and on drop. This type implements
/// neither `Clone`, `Debug`, `Display`, nor serialization traits.
///
/// ```compile_fail
/// let material = dev_tools_secret::SecretMaterial::new(vec![1]).unwrap();
/// println!("{material:?}");
/// ```
///
/// ```compile_fail
/// let material = dev_tools_secret::SecretMaterial::new(vec![1]).unwrap();
/// let _copy = material.clone();
/// ```
pub struct SecretMaterial(Vec<u8>);

impl SecretMaterial {
    pub fn new(value: Vec<u8>) -> Result<Self, SecretError> {
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            return Err(SecretError::new(SecretErrorKind::InvalidResponse));
        }
        Ok(Self(value))
    }

    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl Zeroize for SecretMaterial {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PublicMaterial(Vec<u8>);

impl PublicMaterial {
    pub fn new(value: Vec<u8>) -> Result<Self, SecretError> {
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            return Err(SecretError::new(SecretErrorKind::InvalidResponse));
        }
        Ok(Self(value))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProviderSignature(Vec<u8>);

impl ProviderSignature {
    pub fn new(value: Vec<u8>) -> Result<Self, SecretError> {
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            return Err(SecretError::new(SecretErrorKind::InvalidResponse));
        }
        Ok(Self(value))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy)]
pub struct OperationContext<'a> {
    deadline: Instant,
    cancelled: &'a AtomicBool,
}

impl<'a> OperationContext<'a> {
    pub fn new(deadline: Instant, cancelled: &'a AtomicBool) -> Self {
        Self {
            deadline,
            cancelled,
        }
    }

    pub fn deadline(self) -> Instant {
        self.deadline
    }

    pub fn is_cancelled(self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn remaining(self) -> Result<Duration, SecretError> {
        self.checkpoint()?;
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| SecretError::new(SecretErrorKind::DeadlineExceeded))
    }

    pub fn checkpoint(self) -> Result<(), SecretError> {
        if self.is_cancelled() {
            return Err(SecretError::new(SecretErrorKind::Cancelled));
        }
        if Instant::now() >= self.deadline {
            return Err(SecretError::new(SecretErrorKind::DeadlineExceeded));
        }
        Ok(())
    }
}

pub trait SecretProvider: Send + Sync {
    fn id(&self) -> &ProviderId;
    fn capabilities(&self) -> ProviderCapabilities;
    fn health(&self, context: OperationContext<'_>) -> Result<ProviderHealth, SecretError>;
    fn metadata(
        &self,
        reference: &SecretReference,
        purpose: SecretPurpose,
        context: OperationContext<'_>,
    ) -> Result<SecretMetadata, SecretError>;
    fn read_exportable(
        &self,
        reference: &SecretReference,
        context: OperationContext<'_>,
    ) -> Result<SecretMaterial, SecretError>;
    fn public_material(
        &self,
        reference: &SecretReference,
        context: OperationContext<'_>,
    ) -> Result<PublicMaterial, SecretError>;
    fn sign(
        &self,
        reference: &SecretReference,
        payload: &[u8],
        context: OperationContext<'_>,
    ) -> Result<ProviderSignature, SecretError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretErrorKind {
    InvalidIdentifier,
    InvalidReference,
    Unsupported,
    PermissionDenied,
    ProviderUnavailable,
    ProviderFailure,
    InvalidResponse,
    Cancelled,
    DeadlineExceeded,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretError {
    kind: SecretErrorKind,
}

impl SecretError {
    pub fn new(kind: SecretErrorKind) -> Self {
        Self { kind }
    }

    pub fn kind(self) -> SecretErrorKind {
        self.kind
    }
}

impl fmt::Debug for SecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SecretError({:?})", self.kind)
    }
}

impl fmt::Display for SecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            SecretErrorKind::InvalidIdentifier => "secret identifier is invalid",
            SecretErrorKind::InvalidReference => "secret reference is invalid",
            SecretErrorKind::Unsupported => "secret operation is unsupported",
            SecretErrorKind::PermissionDenied => "secret operation is not permitted",
            SecretErrorKind::ProviderUnavailable => "secret provider is unavailable",
            SecretErrorKind::ProviderFailure => "secret provider operation failed",
            SecretErrorKind::InvalidResponse => "secret provider response is invalid",
            SecretErrorKind::Cancelled => "secret operation was cancelled",
            SecretErrorKind::DeadlineExceeded => "secret operation deadline was exceeded",
        })
    }
}

impl Error for SecretError {}

fn parse_identifier(value: String) -> Result<String, SecretError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || index > 0 && matches!(byte, b'-' | b'_')
        })
        || !value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
    {
        return Err(SecretError::new(SecretErrorKind::InvalidIdentifier));
    }
    Ok(value)
}
