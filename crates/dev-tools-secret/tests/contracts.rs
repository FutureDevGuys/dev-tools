use dev_tools_secret::{
    LogicalSecretName, OperationContext, ProviderCapabilities, ProviderId, SecretError,
    SecretErrorKind, SecretMaterial, SecretPurpose, SecretReference,
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
