use dev_tools_secret::{
    LogicalSecretName, OperationContext, ProviderCapabilities, ProviderHealth, ProviderId,
    ProviderSignature, PublicMaterial, SecretError, SecretErrorKind, SecretMaterial,
    SecretMetadata, SecretProvider, SecretPurpose, SecretReference,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

#[test]
fn identifiers_are_normalized_and_reject_log_or_path_injection() {
    assert_eq!(
        ProviderId::parse("one-password").unwrap().as_str(),
        "one-password"
    );
    assert_eq!(
        LogicalSecretName::parse("release-signing")
            .unwrap()
            .as_str(),
        "release-signing"
    );
    for invalid in ["", "OnePassword", "../secret", "secret/ref", "secret\nref"] {
        assert!(ProviderId::parse(invalid).is_err(), "accepted {invalid:?}");
        assert!(
            LogicalSecretName::parse(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }
}

#[test]
fn opaque_references_and_material_are_not_rendered_by_errors() {
    let reference = SecretReference::new("op://Automation/private/key").unwrap();
    assert_eq!(
        reference.expose_to_provider(),
        "op://Automation/private/key"
    );
    let error = SecretError::new(SecretErrorKind::ProviderUnavailable);
    assert_eq!(format!("{error}"), "secret provider is unavailable");
    assert_eq!(format!("{error:?}"), "SecretError(ProviderUnavailable)");
    assert!(!format!("{error:?}").contains(reference.expose_to_provider()));
}

#[test]
fn secret_material_zeroizes_without_becoming_serializable_or_debuggable() {
    let mut material = SecretMaterial::new(b"durable-secret".to_vec()).unwrap();
    assert_eq!(material.expose_secret(), b"durable-secret");
    material.zeroize();
    assert!(material.expose_secret().iter().all(|byte| *byte == 0));
}

#[test]
fn secret_material_constructor_preserves_its_exact_size_boundary() {
    for length in [0, 16 * 1024 * 1024 + 1] {
        let error = SecretMaterial::new(vec![b'x'; length]).err().unwrap();
        assert_eq!(error.kind(), SecretErrorKind::InvalidResponse);
        assert_eq!(error.to_string(), "secret provider response is invalid");
    }
    let material = SecretMaterial::new(vec![b'x'; 16 * 1024 * 1024]).unwrap();
    assert_eq!(material.expose_secret().len(), 16 * 1024 * 1024);
}

#[test]
fn one_absolute_operation_context_shares_deadline_and_cancellation() {
    let cancelled = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(5);
    let context = OperationContext::new(deadline, &cancelled);
    assert!(context.remaining().unwrap() <= Duration::from_secs(5));
    context.checkpoint().unwrap();
    cancelled.store(true, Ordering::Release);
    assert_eq!(
        context.checkpoint().unwrap_err().kind(),
        SecretErrorKind::Cancelled
    );

    let not_cancelled = AtomicBool::new(false);
    let expired = OperationContext::new(Instant::now(), &not_cancelled);
    assert_eq!(
        expired.checkpoint().unwrap_err().kind(),
        SecretErrorKind::DeadlineExceeded
    );
}

#[test]
fn provider_capabilities_distinguish_export_from_operation_only_authority() {
    let capabilities = ProviderCapabilities {
        exportable_read: false,
        public_material: true,
        signing: true,
        metadata: true,
    };
    assert!(!capabilities.allows(SecretPurpose::Export));
    assert!(capabilities.allows(SecretPurpose::PublicMaterial));
    assert!(capabilities.allows(SecretPurpose::Sign));
}

struct DefaultMetadataProvider {
    id: ProviderId,
}

impl SecretProvider for DefaultMetadataProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            exportable_read: true,
            public_material: true,
            signing: true,
            metadata: true,
        }
    }

    fn health(&self, _: OperationContext<'_>) -> Result<ProviderHealth, SecretError> {
        panic!("default metadata discovery must not probe provider health")
    }

    fn metadata(
        &self,
        _: &SecretReference,
        _: SecretPurpose,
        _: OperationContext<'_>,
    ) -> Result<SecretMetadata, SecretError> {
        panic!("capability metadata must not substitute for explicit observation")
    }

    fn read_exportable(
        &self,
        _: &SecretReference,
        _: OperationContext<'_>,
    ) -> Result<SecretMaterial, SecretError> {
        panic!("default metadata discovery must not export secret material")
    }

    fn public_material(
        &self,
        _: &SecretReference,
        _: OperationContext<'_>,
    ) -> Result<PublicMaterial, SecretError> {
        panic!("default metadata discovery must not retrieve public material")
    }

    fn sign(
        &self,
        _: &SecretReference,
        _: &[u8],
        _: OperationContext<'_>,
    ) -> Result<ProviderSignature, SecretError> {
        panic!("default metadata discovery must not perform a signing operation")
    }
}

#[test]
fn metadata_discovery_default_is_unsupported_without_export() {
    let provider = DefaultMetadataProvider {
        id: ProviderId::parse("independent").unwrap(),
    };
    let provider: &dyn SecretProvider = &provider;
    let reference = SecretReference::new("independent://fixture/private-key").unwrap();
    let cancelled = AtomicBool::new(false);
    let context = OperationContext::new(Instant::now() + Duration::from_secs(5), &cancelled);
    assert!(provider.capabilities().metadata);
    let error = provider.discover_metadata(&reference, context).unwrap_err();
    assert_eq!(error.kind(), SecretErrorKind::Unsupported);
}

#[test]
fn metadata_discovery_default_checks_cancelled_and_expired_context() {
    let provider = DefaultMetadataProvider {
        id: ProviderId::parse("independent").unwrap(),
    };
    let reference = SecretReference::new("independent://fixture/private-key").unwrap();
    for (cancelled, deadline, expected) in [
        (
            true,
            Instant::now() + Duration::from_secs(5),
            SecretErrorKind::Cancelled,
        ),
        (false, Instant::now(), SecretErrorKind::DeadlineExceeded),
    ] {
        let cancelled = AtomicBool::new(cancelled);
        let context = OperationContext::new(deadline, &cancelled);
        let error = provider.discover_metadata(&reference, context).unwrap_err();
        assert_eq!(error.kind(), expected);
    }
}
