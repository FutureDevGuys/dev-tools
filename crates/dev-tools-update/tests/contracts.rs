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
    mutation_error: Option<UpdateError>,
    post_inspection_error: Option<UpdateError>,
    suppress_mutation: bool,
    prepare_calls: usize,
    prepared: Option<AuthenticatedCandidate>,
    prepare_error: Option<UpdateError>,
}

impl UpdateAdapter for FakeAdapter {
    fn inspect(&mut self) -> Result<InstallationSnapshot, UpdateError> {
        self.inspect_calls += 1;
        if self.inspect_calls > 1 {
            if let Some(error) = self.post_inspection_error {
                return Err(error);
            }
        }
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

    fn prepare_artifact(
        &mut self,
        candidate: &AuthenticatedCandidate,
    ) -> Result<AuthenticatedCandidate, UpdateError> {
        self.prepare_calls += 1;
        if let Some(error) = self.prepare_error {
            return Err(error);
        }
        Ok(self.prepared.clone().unwrap_or_else(|| {
            AuthenticatedCandidate::new(
                candidate.verified().clone(),
                candidate.checked_at_unix(),
                true,
            )
            .unwrap()
        }))
    }

    fn install(&mut self, candidate: &AuthenticatedCandidate) -> Result<bool, UpdateError> {
        self.install_calls += 1;
        if !self.suppress_mutation {
            self.installation = Some(InstallationSnapshot::managed(Some(
                candidate.verified().version.clone(),
            )));
        }
        self.mutation_error.map_or(Ok(true), Err)
    }

    fn apply(&mut self, candidate: &AuthenticatedCandidate) -> Result<bool, UpdateError> {
        self.apply_calls += 1;
        if !self.suppress_mutation {
            self.installation = Some(InstallationSnapshot::managed(Some(
                candidate.verified().version.clone(),
            )));
        }
        self.mutation_error.map_or(Ok(true), Err)
    }

    fn rollback(&mut self) -> Result<bool, UpdateError> {
        self.rollback_calls += 1;
        if !self.suppress_mutation {
            self.installation = Some(managed("0.9.0"));
        }
        self.mutation_error.map_or(Ok(true), Err)
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
    assert_eq!(result.changed, Some(true));
    assert_eq!(adapter.cache_calls, 1);
    assert_eq!(adapter.refresh_calls, 0);
    assert_eq!(adapter.apply_calls, 1);
}

#[test]
fn check_cannot_claim_currentness_from_expired_or_future_evidence() {
    for (checked_at, now) in [(10, 86_411), (21, 20)] {
        for installed in ["1.0.0", "1.1.0"] {
            let mut adapter = FakeAdapter {
                installation: Some(managed(installed)),
                refreshed: Some(candidate("1.1.0", checked_at, false)),
                ..FakeAdapter::default()
            };
            let result = execute(&policy(), OperationRequest::check(), now, &mut adapter);
            assert_eq!(result.outcome, OperationOutcome::Unknown);
            assert_eq!(result.cache_freshness, Some(CacheFreshness::Expired));
            assert_eq!(result.available_version.as_deref(), Some("1.1.0"));
            assert_eq!(result.exit_code, 0);
            assert_eq!(result.changed, Some(false));
            assert_eq!(adapter.refresh_calls, 1);
            assert_eq!(
                adapter.cache_calls + adapter.install_calls + adapter.apply_calls,
                0
            );
        }
    }
}

#[test]
fn check_accepts_evidence_at_the_exact_freshness_limit() {
    let mut adapter = FakeAdapter {
        installation: Some(managed("1.1.0")),
        refreshed: Some(candidate("1.1.0", 10, false)),
        ..FakeAdapter::default()
    };
    let result = execute(&policy(), OperationRequest::check(), 86_410, &mut adapter);
    assert_eq!(result.outcome, OperationOutcome::Current);
    assert_eq!(result.cache_freshness, Some(CacheFreshness::Fresh));
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

#[test]
fn late_mutation_failure_does_not_claim_unchanged() {
    let mut adapter = FakeAdapter {
        installation: Some(managed("1.0.0")),
        cached: Some(candidate("1.1.0", 10, true)),
        mutation_error: Some(UpdateError::new(UpdateErrorKind::Operational)),
        ..FakeAdapter::default()
    };
    let result = execute(&policy(), OperationRequest::apply(true), 20, &mut adapter);
    assert_eq!(
        adapter.installation.as_ref().unwrap().version(),
        Some(&Version::new(1, 1, 0))
    );
    assert_eq!(
        serde_json::to_value(&result).unwrap()["changed"],
        serde_json::Value::Null
    );
    assert_eq!(result.installed_version.as_deref(), Some("1.1.0"));
}

#[test]
fn successful_mutation_reports_post_operation_version() {
    let mut adapter = FakeAdapter {
        installation: Some(managed("1.0.0")),
        cached: Some(candidate("1.1.0", 10, true)),
        ..FakeAdapter::default()
    };
    let result = execute(&policy(), OperationRequest::apply(true), 20, &mut adapter);
    assert_eq!(result.installed_version.as_deref(), Some("1.1.0"));
}

#[test]
fn every_mutation_preserves_change_evidence_and_post_observation_failure() {
    for request in [
        OperationRequest::install(true),
        OperationRequest::apply(true),
        OperationRequest::rollback(),
    ] {
        for changed in [None, Some(false), Some(true)] {
            for observation_fails in [false, true] {
                let mut error = UpdateError::new(UpdateErrorKind::Interrupted);
                if let Some(changed) = changed {
                    error = error.with_changed(changed);
                }
                let mut adapter = FakeAdapter {
                    installation: Some(if request.operation() == CommonOperation::UpdateInstall {
                        InstallationSnapshot::absent()
                    } else {
                        managed("1.0.0")
                    }),
                    cached: Some(candidate("1.1.0", 10, true)),
                    mutation_error: Some(error),
                    suppress_mutation: changed == Some(false),
                    post_inspection_error: observation_fails
                        .then(|| UpdateError::new(UpdateErrorKind::Operational)),
                    ..FakeAdapter::default()
                };
                let result = execute(&policy(), request, 20, &mut adapter);
                assert_eq!(result.schema, "dev-tools-operation-result-v2");
                assert_eq!(result.changed, changed);
                assert_eq!(result.exit_code, 130);
                assert_eq!(result.error_kind, Some(ErrorKind::Interrupted));
                assert_eq!(adapter.inspect_calls, 2);
                if observation_fails {
                    assert_eq!(result.installed_version, None);
                    assert_eq!(result.installation_state, Some(InstallationState::Unknown));
                } else if changed == Some(false) {
                    assert_eq!(
                        result.installed_version.as_deref(),
                        if request.operation() == CommonOperation::UpdateInstall {
                            None
                        } else {
                            Some("1.0.0")
                        }
                    );
                } else {
                    assert_eq!(
                        result.installed_version.as_deref(),
                        Some(if request.operation() == CommonOperation::UpdateRollback {
                            "0.9.0"
                        } else {
                            "1.1.0"
                        })
                    );
                }
            }
        }
    }
}

#[test]
fn successful_mutation_followed_by_failed_observation_retains_known_progress() {
    let mut adapter = FakeAdapter {
        installation: Some(managed("1.0.0")),
        cached: Some(candidate("1.1.0", 10, true)),
        post_inspection_error: Some(UpdateError::new(UpdateErrorKind::Integrity)),
        ..FakeAdapter::default()
    };
    let result = execute(&policy(), OperationRequest::apply(true), 20, &mut adapter);
    assert_eq!(result.changed, Some(true));
    assert_eq!(result.exit_code, 4);
    assert_eq!(result.error_kind, Some(ErrorKind::Integrity));
    assert_eq!(result.installed_version, None);
    assert_eq!(result.installation_state, Some(InstallationState::Unknown));
    assert_eq!(result.available_version.as_deref(), Some("1.1.0"));
}

#[test]
fn preflight_failure_establishes_no_installation_change() {
    let mut adapter = FakeAdapter::default();
    let result = execute(&policy(), OperationRequest::apply(false), 20, &mut adapter);
    assert_eq!(result.changed, Some(false));
    assert_eq!(adapter.inspect_calls, 1);
    assert_eq!(adapter.apply_calls, 0);
}

#[test]
fn current_offline_apply_needs_no_artifact_payload() {
    let mut adapter = FakeAdapter {
        installation: Some(managed("1.1.0")),
        cached: Some(candidate("1.1.0", 10, false)),
        ..FakeAdapter::default()
    };
    let result = execute(
        &policy(),
        OperationRequest::apply(true),
        100_000,
        &mut adapter,
    );
    assert_eq!(result.outcome, OperationOutcome::NoOp);
    assert_eq!(result.changed, Some(false));
    assert_eq!(adapter.refresh_calls + adapter.apply_calls, 0);
}

#[test]
fn online_mutation_has_a_separate_artifact_preparation_boundary() {
    let mut adapter = FakeAdapter {
        installation: Some(managed("1.0.0")),
        refreshed: Some(candidate("1.1.0", 20, false)),
        ..FakeAdapter::default()
    };
    let result = execute(&policy(), OperationRequest::apply(false), 20, &mut adapter);
    assert_eq!(result.outcome, OperationOutcome::Updated);
    assert_eq!(result.installed_version.as_deref(), Some("1.1.0"));
    assert_eq!(adapter.prepare_calls, 1);
}

#[test]
fn local_and_metadata_only_operations_never_prepare_artifacts() {
    for request in [
        OperationRequest::status(),
        OperationRequest::check(),
        OperationRequest::apply(true),
        OperationRequest::rollback(),
    ] {
        let mut adapter = FakeAdapter {
            installation: Some(managed("1.0.0")),
            cached: Some(candidate("1.1.0", 10, false)),
            refreshed: Some(candidate("1.1.0", 20, false)),
            ..FakeAdapter::default()
        };
        execute(&policy(), request, 20, &mut adapter);
        assert_eq!(adapter.prepare_calls, 0);
    }
    for (installed, available) in [("1.1.0", false), ("1.0.0", true)] {
        let mut adapter = FakeAdapter {
            installation: Some(managed(installed)),
            refreshed: Some(candidate("1.1.0", 20, available)),
            ..FakeAdapter::default()
        };
        execute(&policy(), OperationRequest::apply(false), 20, &mut adapter);
        assert_eq!(adapter.prepare_calls, 0);
    }
}

#[test]
fn preparation_cannot_replace_authenticated_release_or_freshness() {
    let original = candidate("1.1.0", 20, false);
    let mut changed_target = original.verified().clone();
    changed_target.target = "different-target".into();
    let mut changed_digest = original.verified().clone();
    changed_digest.artifact_sha256 = "d".repeat(64);
    for prepared in [
        candidate("1.2.0", 20, true),
        candidate("1.1.0", 21, true),
        AuthenticatedCandidate::new(changed_target, 20, true).unwrap(),
        AuthenticatedCandidate::new(changed_digest, 20, true).unwrap(),
    ] {
        let mut adapter = FakeAdapter {
            installation: Some(managed("1.0.0")),
            refreshed: Some(original.clone()),
            prepared: Some(prepared),
            ..FakeAdapter::default()
        };
        let result = execute(&policy(), OperationRequest::apply(false), 20, &mut adapter);
        assert_eq!(result.error_kind, Some(ErrorKind::Authority));
        assert_eq!(result.changed, Some(false));
        assert_eq!(adapter.apply_calls, 0);
    }
}

#[test]
fn failed_or_incomplete_preparation_never_enters_installation_mutation() {
    for error in [
        None,
        Some(UpdateError::new(UpdateErrorKind::Network).with_changed(true)),
    ] {
        let mut adapter = FakeAdapter {
            installation: Some(InstallationSnapshot::absent()),
            refreshed: Some(candidate("1.1.0", 20, false)),
            prepared: Some(candidate("1.1.0", 20, false)),
            prepare_error: error,
            ..FakeAdapter::default()
        };
        let result = execute(
            &policy(),
            OperationRequest::install(false),
            20,
            &mut adapter,
        );
        assert_ne!(result.exit_code, 0);
        assert_eq!(result.changed, Some(false));
        assert_eq!(adapter.install_calls, 0);
        assert_eq!(adapter.prepare_calls, 1);
    }
}
