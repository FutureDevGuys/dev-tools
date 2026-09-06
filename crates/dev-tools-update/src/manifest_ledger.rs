//! Authority-bound anti-rollback state. The product owns durable custody, locking,
//! atomic publication and an identity independent of evictable metadata caches.

use crate::artifact::ArtifactRecord;
use crate::discovery::{verify_static_manifest_metadata, DiscoveryError};
use dev_tools_release::{
    accept_verified_release, ReleaseAuthority, ReleaseMetadata, ReleaseState, VerifiedRelease,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SCHEMA: &str = "dev-tools-manifest-ledger-v1";
pub const MANIFEST_LEDGER_LIMIT: usize = 4096;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityBinding {
    product: String,
    target: String,
    trusted_root_key: [u8; 32],
}

impl AuthorityBinding {
    fn from_record(record: &ArtifactRecord) -> Result<Self, DiscoveryError> {
        let authority = record
            .release_authority()
            .ok_or(DiscoveryError::Authentication)?;
        Self::from_authority(&authority)
    }

    fn from_authority(authority: &ReleaseAuthority) -> Result<Self, DiscoveryError> {
        if authority.product.is_empty()
            || authority.target.is_empty()
            || authority.product.chars().any(char::is_control)
            || authority.target.chars().any(char::is_control)
        {
            return Err(DiscoveryError::Authentication);
        }
        let key = dev_tools_release::parse_release_public_key(&authority.trusted_root_key)
            .map_err(|_| DiscoveryError::Authentication)?;
        Ok(Self {
            product: authority.product.clone(),
            target: authority.target.clone(),
            trusted_root_key: key.to_bytes(),
        })
    }
}

/// Local acceptance state, not a signed document or proof of artifact custody.
/// Loading assumes a product-owned file read with validated ownership and type.
/// Absence must not silently reset a previously established installation ledger.
#[derive(Clone)]
pub struct ManifestLedger {
    document: LedgerDocument,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerDocument {
    schema: String,
    authority: AuthorityBinding,
    state: ReleaseState,
}

impl ManifestLedger {
    /// Import an explicitly admitted legacy acceptance history without resetting it.
    ///
    /// This validates representation and binds product, target and pinned root;
    /// it does not authenticate history, prove first use, or permit replacing an
    /// existing ledger. The product must establish source custody, exclude its
    /// old writers and durably publish the result without losing concurrent
    /// history. A default state is only for explicitly authorized first use.
    /// Original signed metadata remains necessary for subsequent verification.
    /// Schema/URL policy is reapplied by each verification call, not frozen in
    /// the durable authority-stream identifier.
    pub fn import_release_state(
        authority: &ReleaseAuthority,
        state: ReleaseState,
    ) -> Result<Self, DiscoveryError> {
        if !valid_state(&state) {
            return Err(DiscoveryError::InvalidMetadata);
        }
        let ledger = Self {
            document: LedgerDocument {
                schema: SCHEMA.into(),
                authority: AuthorityBinding::from_authority(authority)?,
                state,
            },
        };
        ledger.to_bytes()?;
        Ok(ledger)
    }

    /// Load the unchanged ledger codec using product-owned release authority.
    /// File custody and absence/reinitialization policy remain product-owned.
    pub fn from_bytes_with_authority(
        bytes: &[u8],
        authority: &ReleaseAuthority,
    ) -> Result<Self, DiscoveryError> {
        let ledger = Self::decode(bytes)?;
        ledger.require_release_authority(authority)?;
        Ok(ledger)
    }

    /// Stable authority-stream identity, not authentication or file custody.
    ///
    /// SHA-256 covers the ASCII domain `dev-tools-manifest-authority-v1`, the
    /// product and target UTF-8 bytes, each followed by NUL, then the normalized
    /// 32-byte pinned root key. Product/target grammar excludes NUL. This encoding
    /// is independent of ledger schema, accepted generations, URLs and catalog
    /// names; changing it requires an explicit durable-state migration.
    pub fn authority_id(&self) -> [u8; 32] {
        let authority = &self.document.authority;
        let mut hash = Sha256::new();
        for component in [
            b"dev-tools-manifest-authority-v1".as_slice(),
            authority.product.as_bytes(),
            authority.target.as_bytes(),
        ] {
            hash.update(component);
            hash.update([0]);
        }
        hash.update(authority.trusted_root_key);
        hash.finalize().into()
    }

    /// Explicit first-use initialization. This cannot prove historical latestness.
    pub fn new(record: &ArtifactRecord) -> Result<Self, DiscoveryError> {
        Ok(Self {
            document: LedgerDocument {
                schema: SCHEMA.into(),
                authority: AuthorityBinding::from_record(record)?,
                state: ReleaseState::default(),
            },
        })
    }

    pub fn from_bytes(bytes: &[u8], record: &ArtifactRecord) -> Result<Self, DiscoveryError> {
        let ledger = Self::decode(bytes)?;
        ledger.require_authority(record)?;
        Ok(ledger)
    }

    fn decode(bytes: &[u8]) -> Result<Self, DiscoveryError> {
        if bytes.is_empty() || bytes.len() > MANIFEST_LEDGER_LIMIT {
            return Err(DiscoveryError::InventoryLimit);
        }
        let document: LedgerDocument =
            serde_json::from_slice(bytes).map_err(|_| DiscoveryError::InvalidMetadata)?;
        if document.schema != SCHEMA || !valid_state(&document.state) {
            return Err(DiscoveryError::InvalidMetadata);
        }
        Ok(Self { document })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DiscoveryError> {
        let bytes =
            serde_json::to_vec(&self.document).map_err(|_| DiscoveryError::InvalidMetadata)?;
        if bytes.len() > MANIFEST_LEDGER_LIMIT {
            return Err(DiscoveryError::InventoryLimit);
        }
        Ok(bytes)
    }

    /// Authenticate and apply monotonic acceptance in memory. The caller must
    /// publish this state atomically before reporting durable acceptance. Neither
    /// returned metadata nor this ledger authenticates downloaded artifact bytes.
    pub fn accept(
        &mut self,
        record: &ArtifactRecord,
        metadata: &ReleaseMetadata,
    ) -> Result<(VerifiedRelease, bool), DiscoveryError> {
        self.require_authority(record)?;
        let verified = verify_static_manifest_metadata(record, metadata)?;
        self.accept_verified(verified)
    }

    /// Authenticate under current product policy and apply monotonic acceptance
    /// in memory. The caller must commit durably before reporting acceptance.
    pub fn accept_release_metadata(
        &mut self,
        authority: &ReleaseAuthority,
        metadata: &ReleaseMetadata,
    ) -> Result<(VerifiedRelease, bool), DiscoveryError> {
        self.require_release_authority(authority)?;
        let verified = verify_product_metadata(authority, metadata)?;
        self.accept_verified(verified)
    }

    fn accept_verified(
        &mut self,
        verified: VerifiedRelease,
    ) -> Result<(VerifiedRelease, bool), DiscoveryError> {
        let mut next = self.clone();
        let changed = accept_verified_release(&mut next.document.state, &verified)
            .map_err(|_| DiscoveryError::Acceptance)?;
        if !valid_state(&next.document.state) {
            return Err(DiscoveryError::Acceptance);
        }
        next.to_bytes()?;
        *self = next;
        Ok((verified, changed))
    }

    /// Authenticate retained metadata without advancing online acceptance.
    ///
    /// The supplied root must exactly match this ledger's accepted root; an old
    /// manifest may be paired with that current signed root to enforce current
    /// key revocations. Missing or superseded root evidence fails closed. Future
    /// manifests/versions and conflicting current-generation metadata fail too.
    /// This does not establish historical acceptance, receipt ownership, artifact
    /// custody, freshness, or rollback permission. Callers must independently bind
    /// the returned version, length and digest to receipt-owned verified content.
    pub fn verify_retained_metadata(
        &self,
        record: &ArtifactRecord,
        metadata: &ReleaseMetadata,
    ) -> Result<VerifiedRelease, DiscoveryError> {
        self.require_authority(record)?;
        let verified = verify_static_manifest_metadata(record, metadata)?;
        self.verify_retained(verified)
    }

    /// Reauthenticate a retained manifest against the exact accepted root and
    /// current product policy without changing history. This establishes neither
    /// historical acceptance nor receipt ownership, custody or rollback permission.
    pub fn verify_retained_with_authority(
        &self,
        authority: &ReleaseAuthority,
        metadata: &ReleaseMetadata,
    ) -> Result<VerifiedRelease, DiscoveryError> {
        self.require_release_authority(authority)?;
        let verified = verify_product_metadata(authority, metadata)?;
        self.verify_retained(verified)
    }

    fn verify_retained(
        &self,
        verified: VerifiedRelease,
    ) -> Result<VerifiedRelease, DiscoveryError> {
        let state = &self.document.state;
        let accepted_version = state
            .accepted_version
            .as_deref()
            .ok_or(DiscoveryError::Acceptance)?
            .parse::<semver::Version>()
            .map_err(|_| DiscoveryError::Acceptance)?;
        if verified.root_generation != state.accepted_root_generation
            || Some(&verified.root_sha256) != state.accepted_root_sha256.as_ref()
            || verified.manifest_generation > state.accepted_generation
            || verified.version > accepted_version
            || (verified.manifest_generation == state.accepted_generation
                && Some(&verified.manifest_sha256) != state.accepted_manifest_sha256.as_ref())
            || (verified.version == accepted_version
                && Some(&verified.artifact_sha256) != state.accepted_binary_sha256.as_ref())
        {
            return Err(DiscoveryError::Acceptance);
        }
        Ok(verified)
    }

    fn require_authority(&self, record: &ArtifactRecord) -> Result<(), DiscoveryError> {
        if self.document.authority != AuthorityBinding::from_record(record)? {
            return Err(DiscoveryError::Authentication);
        }
        Ok(())
    }

    fn require_release_authority(
        &self,
        authority: &ReleaseAuthority,
    ) -> Result<(), DiscoveryError> {
        if self.document.authority != AuthorityBinding::from_authority(authority)? {
            return Err(DiscoveryError::Authentication);
        }
        Ok(())
    }
}

fn verify_product_metadata(
    authority: &ReleaseAuthority,
    metadata: &ReleaseMetadata,
) -> Result<VerifiedRelease, DiscoveryError> {
    let verified = dev_tools_release::verify_release_metadata(metadata, authority)
        .map_err(|_| DiscoveryError::Authentication)?;
    if !verified.version.pre.is_empty() {
        return Err(DiscoveryError::InvalidMetadata);
    }
    Ok(verified)
}

fn valid_state(state: &ReleaseState) -> bool {
    if state == &ReleaseState::default() {
        return true;
    }
    let valid_hash = |value: &Option<String>| {
        value.as_ref().is_some_and(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
    };
    state.accepted_root_generation > 0
        && state.accepted_generation > 0
        && valid_hash(&state.accepted_root_sha256)
        && valid_hash(&state.accepted_manifest_sha256)
        && valid_hash(&state.accepted_binary_sha256)
        && state
            .accepted_version
            .as_ref()
            .and_then(|value| value.parse::<semver::Version>().ok())
            .is_some_and(|version| version.pre.is_empty())
}
