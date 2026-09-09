use dev_auth::logical_authority::{
    CredentialAuthority, Projection, ResourcePurpose, ResourceSelection,
};
use dev_tools_secret::LogicalSecretName;
use std::collections::BTreeMap;

const AUTHORITY: &str = r#"
[providers.vault]
kind = "one_password"
executable = "/usr/bin/op"
[credential_slots.service]
provider = "vault"
users = ["worker"]
[resources.database]
credential_slot = "service"
reference = "op://Fixture/database/password"
kind = "exportable"
purposes = ["read"]
projections = ["stdin", "descriptor"]
[resources.signer]
credential_slot = "service"
reference = "op://Fixture/ssh/private-key"
kind = "operation_only"
purposes = ["public", "git_signing"]
[resource_caps.build]
users = ["worker"]
[resource_caps.build.resources.database]
purposes = ["read"]
projections = ["stdin"]
[resource_caps.build.resources.signer]
purposes = ["public", "git_signing"]
"#;

fn authority() -> CredentialAuthority {
    let text = if cfg!(windows) {
        AUTHORITY.replace(
            "executable = \"/usr/bin/op\"",
            "executable = 'C:\\Program Files\\1Password\\op.exe'",
        )
    } else {
        AUTHORITY.to_owned()
    };
    toml::from_str(&text).unwrap()
}
fn request(
    purpose: ResourcePurpose,
    projections: Vec<Projection>,
) -> BTreeMap<String, ResourceSelection> {
    BTreeMap::from([(
        "database".into(),
        ResourceSelection {
            purposes: vec![purpose],
            projections,
        },
    )])
}

#[test]
fn resolves_logical_resource_to_exact_provider_slot_and_narrowed_rights() {
    let grants = authority()
        .resolve(
            "worker",
            "build",
            &request(ResourcePurpose::Read, vec![Projection::Stdin]),
        )
        .unwrap();
    let grant = &grants[&LogicalSecretName::parse("database").unwrap()];
    assert_eq!(grant.provider().as_str(), "vault");
    assert_eq!(grant.credential_slot(), "service");
    assert!(grant.allows(ResourcePurpose::Read));
    assert!(!grant.allows(ResourcePurpose::GitSigning));
    assert!(grant.allows_projection(Projection::Stdin));
    assert!(!grant.allows_projection(Projection::Descriptor));
}

#[test]
fn both_account_caps_and_every_resource_right_must_narrow() {
    for (user, cap, requested) in [
        ("other", "build", request(ResourcePurpose::Read, vec![])),
        ("worker", "missing", request(ResourcePurpose::Read, vec![])),
        (
            "worker",
            "build",
            request(ResourcePurpose::GitSigning, vec![]),
        ),
        (
            "worker",
            "build",
            request(ResourcePurpose::Read, vec![Projection::Descriptor]),
        ),
        (
            "worker",
            "build",
            request(ResourcePurpose::Read, vec![Projection::Environment]),
        ),
    ] {
        assert!(authority().resolve(user, cap, &requested).is_err());
    }
    let mut authority = authority();
    authority.credential_slots.get_mut("service").unwrap().users = vec!["other".into()];
    assert!(authority
        .resolve("worker", "build", &request(ResourcePurpose::Read, vec![]))
        .is_err());
}

#[test]
fn operation_only_keys_cannot_be_relabeled_as_exportable_by_a_cap_or_caller() {
    let mut authority = authority();
    authority
        .resources
        .get_mut("signer")
        .unwrap()
        .purposes
        .push(ResourcePurpose::Read);
    assert!(authority
        .resolve("worker", "build", &request(ResourcePurpose::Read, vec![]))
        .is_err());
}

#[test]
fn invalid_unused_bindings_are_rejected_and_errors_never_echo_provider_references() {
    let mut authority = authority();
    authority.resources.get_mut("signer").unwrap().reference =
        "private-value\nnot-a-reference".into();
    let error = authority
        .resolve("worker", "build", &request(ResourcePurpose::Read, vec![]))
        .err()
        .unwrap();
    assert!(!format!("{error:#?}").contains("private-value"));
}

struct IndependentProvider {
    id: dev_tools_secret::ProviderId,
    calls: std::sync::atomic::AtomicUsize,
    exportable: bool,
    public_material: bool,
    cancel_after: Option<usize>,
}

impl IndependentProvider {
    fn new(id: &str) -> Self {
        Self {
            id: dev_tools_secret::ProviderId::parse(id).unwrap(),
            calls: 0.into(),
            exportable: true,
            public_material: false,
            cancel_after: None,
        }
    }

    fn called(&self, context: dev_tools_secret::OperationContext<'_>) {
        let count = self
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if self.cancel_after == Some(count) {
            context
                .cancellation_signal()
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

impl dev_tools_secret::SecretProvider for IndependentProvider {
    fn id(&self) -> &dev_tools_secret::ProviderId {
        &self.id
    }
    fn capabilities(&self) -> dev_tools_secret::ProviderCapabilities {
        dev_tools_secret::ProviderCapabilities {
            exportable_read: true,
            public_material: self.public_material,
            signing: false,
            metadata: true,
        }
    }
    fn health(
        &self,
        _: dev_tools_secret::OperationContext<'_>,
    ) -> Result<dev_tools_secret::ProviderHealth, dev_tools_secret::SecretError> {
        panic!("reads must not add a health probe")
    }
    fn metadata(
        &self,
        _: &dev_tools_secret::SecretReference,
        purpose: dev_tools_secret::SecretPurpose,
        context: dev_tools_secret::OperationContext<'_>,
    ) -> Result<dev_tools_secret::SecretMetadata, dev_tools_secret::SecretError> {
        assert_eq!(
            purpose,
            if self.public_material {
                dev_tools_secret::SecretPurpose::PublicMaterial
            } else {
                dev_tools_secret::SecretPurpose::Export
            }
        );
        self.called(context);
        Ok(dev_tools_secret::SecretMetadata {
            exportable: self.exportable,
            public_material: self.public_material,
            signing: false,
        })
    }
    fn read_exportable(
        &self,
        reference: &dev_tools_secret::SecretReference,
        context: dev_tools_secret::OperationContext<'_>,
    ) -> Result<dev_tools_secret::SecretMaterial, dev_tools_secret::SecretError> {
        assert_eq!(
            reference.expose_to_provider(),
            "op://Fixture/database/password"
        );
        self.called(context);
        dev_tools_secret::SecretMaterial::new(vec![0, 255, 1, 10])
    }
    fn public_material(
        &self,
        _: &dev_tools_secret::SecretReference,
        context: dev_tools_secret::OperationContext<'_>,
    ) -> Result<dev_tools_secret::PublicMaterial, dev_tools_secret::SecretError> {
        self.called(context);
        dev_tools_secret::PublicMaterial::new(b"fixture-public".to_vec())
    }
    fn sign(
        &self,
        _: &dev_tools_secret::SecretReference,
        _: &[u8],
        _: dev_tools_secret::OperationContext<'_>,
    ) -> Result<dev_tools_secret::ProviderSignature, dev_tools_secret::SecretError> {
        panic!("unexpected signing operation")
    }
}

#[test]
fn independent_provider_exposes_public_material_without_exporting_operation_only_keys() {
    let requested = BTreeMap::from([(
        "signer".into(),
        ResourceSelection {
            purposes: vec![ResourcePurpose::Public],
            projections: vec![],
        },
    )]);
    let grants = authority().resolve("worker", "build", &requested).unwrap();
    let grant = &grants[&LogicalSecretName::parse("signer").unwrap()];
    let mut provider = IndependentProvider::new("vault");
    provider.public_material = true;
    provider.exportable = false;
    let cancelled = false.into();
    let context = dev_tools_secret::OperationContext::new(
        std::time::Instant::now() + std::time::Duration::from_secs(2),
        &cancelled,
    );
    assert_eq!(
        grant
            .public_material(&provider, "service", context)
            .unwrap()
            .as_bytes(),
        b"fixture-public"
    );
    assert!(grant
        .read_exportable(&provider, "service", context)
        .is_err());
    assert_eq!(provider.calls.load(std::sync::atomic::Ordering::Relaxed), 2);
}

#[test]
fn independent_provider_serves_the_same_resolved_consumer_without_reference_input() {
    let grants = authority()
        .resolve("worker", "build", &request(ResourcePurpose::Read, vec![]))
        .unwrap();
    let grant = &grants[&LogicalSecretName::parse("database").unwrap()];
    let provider = IndependentProvider::new("vault");
    let cancelled = false.into();
    let context = dev_tools_secret::OperationContext::new(
        std::time::Instant::now() + std::time::Duration::from_secs(2),
        &cancelled,
    );
    let bytes = grant
        .read_exportable(&provider, "service", context)
        .unwrap();
    assert_eq!(bytes.expose_secret(), &[0, 255, 1, 10]);
    assert_eq!(provider.calls.load(std::sync::atomic::Ordering::Relaxed), 2);
}

#[test]
fn cancellation_between_provider_stages_never_releases_material() {
    let grants = authority()
        .resolve("worker", "build", &request(ResourcePurpose::Read, vec![]))
        .unwrap();
    let grant = &grants[&LogicalSecretName::parse("database").unwrap()];
    for stage in [1, 2] {
        let mut provider = IndependentProvider::new("vault");
        provider.cancel_after = Some(stage);
        let cancelled = false.into();
        let context = dev_tools_secret::OperationContext::new(
            std::time::Instant::now() + std::time::Duration::from_secs(2),
            &cancelled,
        );
        let error = grant
            .read_exportable(&provider, "service", context)
            .err()
            .unwrap();
        assert_eq!(error.kind(), dev_tools_secret::SecretErrorKind::Cancelled);
        assert_eq!(
            provider.calls.load(std::sync::atomic::Ordering::Relaxed),
            stage
        );
    }
}

#[test]
fn expired_context_and_operation_only_resource_never_issue_an_export() {
    let requested = BTreeMap::from([(
        "signer".into(),
        ResourceSelection {
            purposes: vec![ResourcePurpose::Public, ResourcePurpose::GitSigning],
            projections: vec![],
        },
    )]);
    let grants = authority().resolve("worker", "build", &requested).unwrap();
    let grant = &grants[&LogicalSecretName::parse("signer").unwrap()];
    for deadline in [
        std::time::Instant::now(),
        std::time::Instant::now() + std::time::Duration::from_secs(2),
    ] {
        let provider = IndependentProvider::new("vault");
        let cancelled = false.into();
        let context = dev_tools_secret::OperationContext::new(deadline, &cancelled);
        assert!(grant
            .read_exportable(&provider, "service", context)
            .is_err());
        assert_eq!(provider.calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}

#[test]
fn a_second_logical_name_or_slot_cannot_export_an_operation_only_reference() {
    let mut authority = authority();
    let mut alias = authority.resources["signer"].clone();
    alias.kind = dev_auth::logical_authority::ResourceKind::Exportable;
    alias.purposes = vec![ResourcePurpose::Read];
    alias.credential_slot = "second".into();
    authority.credential_slots.insert(
        "second".into(),
        authority.credential_slots["service"].clone(),
    );
    authority.resources.insert("alias".into(), alias);
    assert!(authority.validate().is_err());
}

#[test]
fn duplicate_and_empty_rights_fail_instead_of_being_silently_normalized() {
    for selected in [
        ResourceSelection {
            purposes: vec![],
            projections: vec![],
        },
        ResourceSelection {
            purposes: vec![ResourcePurpose::Read, ResourcePurpose::Read],
            projections: vec![],
        },
        ResourceSelection {
            purposes: vec![ResourcePurpose::Read],
            projections: vec![Projection::Stdin, Projection::Stdin],
        },
    ] {
        let requested = BTreeMap::from([("database".into(), selected)]);
        assert!(authority().resolve("worker", "build", &requested).is_err());
    }
}

#[test]
fn wrong_provider_slot_and_cancelled_requests_never_reach_the_provider() {
    let grants = authority()
        .resolve("worker", "build", &request(ResourcePurpose::Read, vec![]))
        .unwrap();
    let grant = &grants[&LogicalSecretName::parse("database").unwrap()];
    for (id, slot, cancelled) in [
        ("other", "service", false),
        ("vault", "other", false),
        ("vault", "service", true),
    ] {
        let provider = IndependentProvider::new(id);
        let cancelled = cancelled.into();
        let context = dev_tools_secret::OperationContext::new(
            std::time::Instant::now() + std::time::Duration::from_secs(2),
            &cancelled,
        );
        assert!(grant.read_exportable(&provider, slot, context).is_err());
        assert_eq!(provider.calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}

#[test]
fn provider_nonexportability_is_independent_of_product_export_permission() {
    let grants = authority()
        .resolve("worker", "build", &request(ResourcePurpose::Read, vec![]))
        .unwrap();
    let grant = &grants[&LogicalSecretName::parse("database").unwrap()];
    let mut provider = IndependentProvider::new("vault");
    provider.exportable = false;
    let cancelled = false.into();
    let context = dev_tools_secret::OperationContext::new(
        std::time::Instant::now() + std::time::Duration::from_secs(2),
        &cancelled,
    );
    assert!(grant
        .read_exportable(&provider, "service", context)
        .is_err());
    assert_eq!(provider.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
}
