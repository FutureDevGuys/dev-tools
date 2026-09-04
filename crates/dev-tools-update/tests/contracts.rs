use dev_tools_product::{
    CacheFreshness, CommonOperation, ErrorKind, InstallationState, OperationOutcome, ProductId,
};
use dev_tools_release::VerifiedRelease;
use dev_tools_update::{
    execute, AuthenticatedCandidate, InstallationSnapshot, OperationRequest, UpdateAdapter,
    UpdateError, UpdateErrorKind, UpdatePolicy,
};
use semver::Version;

#[derive(Default)]
struct FakeAdapter {
    installation: Option<InstallationSnapshot>,
    cached: Option<AuthenticatedCandidate>,
    refreshed: Option<AuthenticatedCandidate>,
    inspect_calls: usize,
    cache_calls: usize,
    refresh_calls: usize,
    install_calls: usize,
    apply_calls: usize,
    rollback_calls: usize,
}

impl UpdateAdapter for FakeAdapter {
    fn inspect(&mut self) -> Result<InstallationSnapshot, UpdateError> {
        self.inspect_calls += 1;
        self.installation
            .clone()
            .ok_or(UpdateError::new(UpdateErrorKind::Operational))
    }

    fn load_authenticated_candidate(
        &mut self,
    ) -> Result<Option<AuthenticatedCandidate>, UpdateError> {
        self.cache_calls += 1;
        Ok(self.cached.clone())
    }

    fn refresh_authenticated_candidate(&mut self) -> Result<AuthenticatedCandidate, UpdateError> {
        self.refresh_calls += 1;
        self.refreshed
            .clone()
            .ok_or(UpdateError::new(UpdateErrorKind::Network))
    }

    fn install(&mut self, _: &AuthenticatedCandidate) -> Result<bool, UpdateError> {
        self.install_calls += 1;
        Ok(true)
    }

    fn apply(&mut self, _: &AuthenticatedCandidate) -> Result<bool, UpdateError> {
        self.apply_calls += 1;
        Ok(true)
    }

    fn rollback(&mut self) -> Result<bool, UpdateError> {
        self.rollback_calls += 1;
        Ok(true)
    }
}

fn policy() -> UpdatePolicy {
    UpdatePolicy::new(ProductId::parse("demo-tool").expect("product"), 86_400)
        .expect("valid policy")
}

fn managed(version: &str) -> InstallationSnapshot {
    InstallationSnapshot::managed(Some(Version::parse(version).expect("version")))
}

fn candidate(
    version: &str,
    checked_at_unix: u64,
    artifact_available: bool,
) -> AuthenticatedCandidate {
    AuthenticatedCandidate::new(
        VerifiedRelease {
            root_generation: 1,
            root_sha256: "a".repeat(64),
            manifest_generation: 1,
            manifest_sha256: "b".repeat(64),
            manifest_schema: "dev-tools-product-v1".into(),
            product: "demo-tool".into(),
            version: Version::parse(version).expect("version"),
            source_commit: None,
            target: "linux-x86_64".into(),
            artifact_url: "https://example.invalid/artifact".into(),
            artifact_length: 1,
            artifact_sha256: "c".repeat(64),
        },
        checked_at_unix,
        artifact_available,
    )
    .expect("candidate")
}

#[test]
fn status_is_cache_only_and_expired_evidence_is_unknown() {
    let mut adapter = FakeAdapter {
        installation: Some(managed("1.0.0")),
        cached: Some(candidate("1.1.0", 10, true)),
        ..FakeAdapter::default()
    };

    let result = execute(&policy(), OperationRequest::status(), 86_411, &mut adapter);

    assert_eq!(result.outcome, OperationOutcome::Unknown);
    assert_eq!(result.cache_freshness, Some(CacheFreshness::Expired));
    assert_eq!(result.installation_state, Some(InstallationState::Managed));
    assert_eq!(result.installed_version.as_deref(), Some("1.0.0"));
    assert_eq!(result.available_version.as_deref(), Some("1.1.0"));
    assert_eq!(adapter.inspect_calls, 1);
    assert_eq!(adapter.cache_calls, 1);
    assert_eq!(adapter.refresh_calls, 0);
}

#[test]
fn status_reports_current_or_stale_from_fresh_authenticated_cache() {
    let mut current = FakeAdapter {
        installation: Some(managed("1.1.0")),
        cached: Some(candidate("1.1.0", 10, false)),
        ..FakeAdapter::default()
    };
    let current_result = execute(&policy(), OperationRequest::status(), 20, &mut current);
    assert_eq!(current_result.outcome, OperationOutcome::Current);
    assert_eq!(current_result.cache_freshness, Some(CacheFreshness::Fresh));

    let mut stale = FakeAdapter {
        installation: Some(managed("1.0.0")),
        cached: Some(candidate("1.1.0", 10, false)),
        ..FakeAdapter::default()
    };
    let stale_result = execute(&policy(), OperationRequest::status(), 20, &mut stale);
    assert_eq!(stale_result.outcome, OperationOutcome::Stale);
}

#[test]
fn check_is_the_only_metadata_only_network_operation() {
    let mut adapter = FakeAdapter {
        installation: Some(managed("1.0.0")),
        refreshed: Some(candidate("1.1.0", 20, false)),
        ..FakeAdapter::default()
    };

    let result = execute(&policy(), OperationRequest::check(), 20, &mut adapter);

    assert_eq!(result.operation, CommonOperation::UpdateCheck);
    assert_eq!(result.outcome, OperationOutcome::Stale);
    assert_eq!(adapter.cache_calls, 0);
    assert_eq!(adapter.refresh_calls, 1);
    assert_eq!(adapter.install_calls + adapter.apply_calls, 0);
}

#[test]
fn offline_apply_uses_only_a_cached_authenticated_artifact() {
    let mut adapter = FakeAdapter {
        installation: Some(managed("1.0.0")),
        cached: Some(candidate("1.1.0", 10, true)),
        ..FakeAdapter::default()
    };

    let result = execute(
        &policy(),
        OperationRequest::apply(true),
        100_000,
        &mut adapter,
    );

    assert_eq!(result.outcome, OperationOutcome::Updated);
    assert!(result.changed);
    assert_eq!(adapter.cache_calls, 1);
    assert_eq!(adapter.refresh_calls, 0);
    assert_eq!(adapter.apply_calls, 1);
}

#[test]
fn offline_apply_without_cached_artifact_is_blocked_without_network() {
    let mut adapter = FakeAdapter {
        installation: Some(managed("1.0.0")),
        cached: Some(candidate("1.1.0", 10, false)),
        ..FakeAdapter::default()
    };

    let result = execute(&policy(), OperationRequest::apply(true), 20, &mut adapter);

    assert_eq!(result.outcome, OperationOutcome::Blocked);
    assert_eq!(result.error_kind, Some(ErrorKind::Blocked));
    assert_eq!(result.exit_code, 3);
    assert_eq!(adapter.refresh_calls, 0);
    assert_eq!(adapter.apply_calls, 0);
}

#[test]
fn external_and_requires_setup_installations_are_never_mutated() {
    for (installation, expected, error) in [
        (
            InstallationSnapshot::external(Some(Version::new(1, 0, 0))),
            OperationOutcome::External,
            None,
        ),
        (
            InstallationSnapshot::requires_setup(Some(Version::new(1, 0, 0))),
            OperationOutcome::RequiresSetup,
            Some(ErrorKind::RequiresSetup),
        ),
    ] {
        let mut adapter = FakeAdapter {
            installation: Some(installation),
            refreshed: Some(candidate("1.1.0", 20, true)),
            ..FakeAdapter::default()
        };
        let result = execute(&policy(), OperationRequest::apply(false), 20, &mut adapter);
        assert_eq!(result.outcome, expected);
        assert_eq!(result.error_kind, error);
        assert_eq!(adapter.cache_calls + adapter.refresh_calls, 0);
        assert_eq!(adapter.apply_calls, 0);
    }
}

#[test]
fn an_unknown_observation_is_not_implicitly_treated_as_requires_setup() {
    let mut adapter = FakeAdapter {
        installation: Some(InstallationSnapshot::unknown(Some(Version::new(1, 0, 0)))),
        cached: Some(candidate("1.1.0", 10, false)),
        ..FakeAdapter::default()
    };

    let result = execute(&policy(), OperationRequest::status(), 20, &mut adapter);

    assert_eq!(result.outcome, OperationOutcome::Unknown);
    assert_eq!(result.installation_state, Some(InstallationState::Unknown));
    assert_eq!(result.installed_version.as_deref(), Some("1.0.0"));
    assert_eq!(result.available_version.as_deref(), Some("1.1.0"));
    assert_eq!(result.error_kind, None);
}

#[test]
fn rollback_is_network_free_and_only_available_for_managed_installs() {
    let mut adapter = FakeAdapter {
        installation: Some(managed("1.1.0")),
        ..FakeAdapter::default()
    };

    let result = execute(&policy(), OperationRequest::rollback(), 20, &mut adapter);

    assert_eq!(result.outcome, OperationOutcome::RolledBack);
    assert_eq!(adapter.rollback_calls, 1);
    assert_eq!(adapter.cache_calls + adapter.refresh_calls, 0);
}

#[test]
fn candidate_product_mismatch_is_an_authority_violation() {
    let mut wrong = candidate("1.1.0", 20, true);
    wrong = AuthenticatedCandidate::new(
        VerifiedRelease {
            product: "other-tool".into(),
            ..wrong.verified().clone()
        },
        20,
        true,
    )
    .expect("candidate shape");
    let mut adapter = FakeAdapter {
        installation: Some(managed("1.0.0")),
        refreshed: Some(wrong),
        ..FakeAdapter::default()
    };

    let result = execute(&policy(), OperationRequest::apply(false), 20, &mut adapter);

    assert_eq!(result.outcome, OperationOutcome::AuthorityViolation);
    assert_eq!(result.error_kind, Some(ErrorKind::Authority));
    assert_eq!(result.exit_code, 4);
    assert_eq!(adapter.apply_calls, 0);
}

#[test]
fn adapter_errors_map_to_stable_value_free_categories() {
    struct Failing;
    impl UpdateAdapter for Failing {
        fn inspect(&mut self) -> Result<InstallationSnapshot, UpdateError> {
            Err(UpdateError::new(UpdateErrorKind::Interrupted))
        }
        fn load_authenticated_candidate(
            &mut self,
        ) -> Result<Option<AuthenticatedCandidate>, UpdateError> {
            unreachable!()
        }
        fn refresh_authenticated_candidate(
            &mut self,
        ) -> Result<AuthenticatedCandidate, UpdateError> {
            unreachable!()
        }
        fn install(&mut self, _: &AuthenticatedCandidate) -> Result<bool, UpdateError> {
            unreachable!()
        }
        fn apply(&mut self, _: &AuthenticatedCandidate) -> Result<bool, UpdateError> {
            unreachable!()
        }
        fn rollback(&mut self) -> Result<bool, UpdateError> {
            unreachable!()
        }
    }
    let mut adapter = Failing;
    let result = execute(&policy(), OperationRequest::status(), 20, &mut adapter);
    assert_eq!(result.outcome, OperationOutcome::Interrupted);
    assert_eq!(result.exit_code, 130);
    assert!(!serde_json::to_string(&result)
        .expect("json")
        .contains("secret"));
}

#[test]
fn post_inspection_failures_preserve_known_installation_context() {
    let mut adapter = FakeAdapter {
        installation: Some(managed("1.0.0")),
        ..FakeAdapter::default()
    };

    let result = execute(&policy(), OperationRequest::check(), 20, &mut adapter);

    assert_eq!(result.outcome, OperationOutcome::Failed);
    assert_eq!(result.error_kind, Some(ErrorKind::Network));
    assert_eq!(result.installation_state, Some(InstallationState::Managed));
    assert_eq!(result.installed_version.as_deref(), Some("1.0.0"));
}
