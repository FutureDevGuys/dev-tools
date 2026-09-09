//! Independent, value-free observations; none grants workload authority.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationComponent {
    All,
    Configuration,
    Tools,
    Providers,
}

impl ValidationComponent {
    fn tools(self) -> bool {
        matches!(self, Self::All | Self::Tools)
    }

    fn providers(self) -> bool {
        matches!(self, Self::All | Self::Providers)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ValidationRequest {
    pub component: ValidationComponent,
    pub online: bool,
    pub noninteractive: bool,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    Passed,
    Failed,
    Blocked,
    NotChecked,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidationCheck {
    pub component: &'static str,
    pub status: ValidationStatus,
    pub error_kind: Option<&'static str>,
    /// Number of successfully checked objects, not attempted operations.
    pub checked: usize,
    pub total: Option<usize>,
    pub exit_code: i32,
}

#[derive(Clone, Debug, Serialize)]
pub struct ComponentValidationReport {
    pub schema: &'static str,
    pub product: &'static str,
    pub authority: Option<&'static str>,
    pub online: bool,
    pub error_kind: Option<&'static str>,
    pub exit_code: i32,
    pub declared_exec_profiles: Option<usize>,
    pub declared_ssh_profiles: Option<usize>,
    pub declared_secret_references: Option<usize>,
    pub checks: Vec<ValidationCheck>,
}

impl ComponentValidationReport {
    fn new(online: bool) -> Self {
        Self {
            schema: "dev-auth-validation-v1",
            product: "dev-auth",
            authority: None,
            online,
            error_kind: None,
            exit_code: 0,
            declared_exec_profiles: None,
            declared_ssh_profiles: None,
            declared_secret_references: None,
            checks: [
                "configuration",
                "github_cli",
                "git",
                "provider_executable",
                "enrollment",
                "provider_authentication",
                "provider_resources",
                "key_material",
            ]
            .into_iter()
            .map(|component| ValidationCheck {
                component,
                status: ValidationStatus::NotChecked,
                error_kind: None,
                checked: 0,
                total: None,
                exit_code: 0,
            })
            .collect(),
        }
    }

    pub fn invalid_invocation() -> Self {
        let mut report = Self::new(false);
        report.error_kind = Some("invalid_invocation");
        report.exit_code = 2;
        report
    }

    fn set(
        &mut self,
        component: &'static str,
        status: ValidationStatus,
        error: Option<(&'static str, i32)>,
        checked: usize,
        total: Option<usize>,
    ) {
        let Some(check) = self
            .checks
            .iter_mut()
            .find(|check| check.component == component)
        else {
            // Internal callers use only the fixed inventory above. Preserve a
            // failure instead of turning an omitted observation into success.
            self.error_kind = Some("validation_internal");
            self.exit_code = 1;
            return;
        };
        *check = ValidationCheck {
            component,
            status,
            error_kind: error.map(|(kind, _)| kind),
            checked,
            total,
            exit_code: error.map_or(0, |(_, code)| code),
        };
    }

    fn observed(
        &mut self,
        component: &'static str,
        result: Result<()>,
        error: &'static str,
        code: i32,
    ) {
        match result {
            Ok(()) => self.set(component, ValidationStatus::Passed, None, 1, Some(1)),
            Err(_) => self.set(
                component,
                if code == 3 {
                    ValidationStatus::Blocked
                } else {
                    ValidationStatus::Failed
                },
                Some((error, code)),
                0,
                Some(1),
            ),
        }
    }

    fn finish(mut self) -> Self {
        if self.error_kind.is_none() {
            // Authority, invalid configuration, operational failure and blocked
            // are deliberately not ordered by their numeric process status.
            for category in [4, 2, 1, 3] {
                if let Some(check) = self.checks.iter().find(|check| check.exit_code == category) {
                    self.exit_code = category;
                    self.error_kind = check.error_kind;
                    break;
                }
            }
        }
        self
    }
}

/// Validate independent components through the current public product authority.
/// Provider operations occur only when explicitly selected and online. Reports
/// contain counts and fixed categories, never provider values or references.
pub fn validate_components(request: ValidationRequest) -> ComponentValidationReport {
    let mut report = ComponentValidationReport::new(request.online);
    #[cfg(target_os = "linux")]
    match crate::setup::running_executable_has_version_layout() {
        Ok(true) => return validate_installed(request, report),
        Ok(false) => {}
        Err(_) => {
            report.observed(
                "configuration",
                Err(anyhow::anyhow!("unavailable")),
                "installation_unavailable",
                1,
            );
            return report.finish();
        }
    }
    let loaded = git_runtime::native_runtime_paths().and_then(|paths| {
        read_config_snapshot_at(&paths.config).map(|(config, _)| (paths, config))
    });
    let (paths, config) = match loaded {
        Ok(loaded) => loaded,
        Err(_) => {
            report.observed(
                "configuration",
                Err(anyhow::anyhow!("unavailable")),
                "configuration_unavailable_or_invalid",
                2,
            );
            return report.finish();
        }
    };
    validate_legacy(&paths, &config, request, report).finish()
}

pub(super) fn validate_legacy_compatibility(online: bool) -> Result<ValidationReport> {
    let paths = git_runtime::native_runtime_paths()?;
    let config = load_config(&paths)?;
    let report = validate_legacy(
        &paths,
        &config,
        ValidationRequest {
            component: ValidationComponent::All,
            online,
            noninteractive: false,
        },
        ComponentValidationReport::new(online),
    )
    .finish();
    if let Some(kind) = report.error_kind {
        bail!("configuration validation failed: {kind}");
    }
    Ok(ValidationReport {
        online,
        declared_exec_profiles: config.profiles.len(),
        declared_ssh_profiles: config.ssh_profiles.len(),
        declared_secret_references: config.declared_secret_references().len(),
    })
}

fn validate_legacy(
    paths: &RuntimePaths,
    config: &Config,
    request: ValidationRequest,
    mut report: ComponentValidationReport,
) -> ComponentValidationReport {
    report.authority = Some("legacy_v1");
    report.declared_exec_profiles = Some(config.profiles.len());
    report.declared_ssh_profiles = Some(config.ssh_profiles.len());
    report.declared_secret_references = Some(config.declared_secret_references().len());
    report.observed("configuration", Ok(()), "configuration_invalid", 2);
    if request.component.tools() {
        let gh = program_guard(&config.programs.gh, "GitHub CLI")
            .and_then(|guard| validate_gh_version(&config.programs.gh, paths, &guard));
        report.observed("github_cli", gh, "legacy_gh_protocol_unsupported", 3);
        if config.git.is_some() {
            let git = program_guard(&config.programs.git, "Git")
                .and_then(|guard| validate_git_version(&config.programs.git, &guard))
                .and_then(|()| git_runtime::validate_workspace_policy(config));
            report.observed("git", git, "git_protocol_or_workspace_unavailable", 3);
        }
    }
    if request.component.providers() {
        report.observed(
            "provider_executable",
            program_guard(&config.programs.op, "1Password CLI").map(|_| ()),
            "provider_executable_unavailable",
            3,
        );
        if request.online {
            match validation_credential(&config.credential_store, request.noninteractive) {
                Ok(token) => {
                    report.observed("enrollment", Ok(()), "enrollment_unavailable", 3);
                    match OnePasswordProvider::new(&config.programs.op, &token) {
                        Ok(provider) => validate_legacy_resources(config, &provider, &mut report),
                        Err(_) => report.observed(
                            "provider_resources",
                            Err(anyhow::anyhow!("unavailable")),
                            "provider_unavailable",
                            3,
                        ),
                    }
                }
                Err(_) => report.observed(
                    "enrollment",
                    Err(anyhow::anyhow!("unavailable")),
                    "enrollment_unavailable",
                    3,
                ),
            }
        }
    }
    report
}

fn validation_credential(store: &CredentialStore, noninteractive: bool) -> Result<SecretString> {
    if !noninteractive {
        return service_account_token(store);
    }
    #[cfg(target_os = "linux")]
    {
        let mut credentials =
            prompt_free_store::read(&BTreeMap::from([("validation".into(), store.clone())]))?;
        credentials
            .remove("validation")
            .context("enrollment is unavailable")
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = store;
        bail!("prompt-free enrollment validation is unavailable on this platform")
    }
}

fn validate_legacy_resources(
    config: &Config,
    provider: &dyn SecretProvider,
    report: &mut ComponentValidationReport,
) {
    let Ok(operation) = crate::provider_operation::ProviderOperation::uncancelled() else {
        report.observed(
            "provider_resources",
            Err(anyhow::anyhow!("unavailable")),
            "provider_operation_unavailable",
            1,
        );
        return;
    };
    let references = config.declared_secret_references();
    let health = provider.health(operation.secret_context());
    let must_stop = health
        .as_ref()
        .err()
        .is_some_and(crate::provider_operation::validation_must_stop);
    report.observed(
        "provider_authentication",
        match health {
            Ok(ProviderHealth::Healthy) => Ok(()),
            Ok(ProviderHealth::Unavailable) | Err(_) => {
                Err(anyhow::anyhow!("provider authentication unavailable"))
            }
        },
        "provider_authentication_unavailable",
        1,
    );
    if must_stop {
        return;
    }
    let mut checked = 0;
    let mut keys_checked = 0;
    let mut keys_failed = false;
    let total_keys = 1 + config
        .ssh_profiles
        .values()
        .map(|profile| profile.keys.len())
        .sum::<usize>();
    for reference in &references {
        if operation.secret_context().checkpoint().is_err() {
            break;
        }
        let material = match SecretReference::new(reference.clone())
            .and_then(|reference| provider.read_exportable(&reference, operation.secret_context()))
        {
            Ok(material) => material,
            Err(error) if crate::provider_operation::validation_must_stop(&error) => break,
            Err(_) => continue,
        };
        checked += 1;
        if reference == &config.github.private_key_ref {
            if validate_rsa_key_material(&material).is_ok() {
                keys_checked += 1;
            } else {
                keys_failed = true;
            }
        }
        for key in config
            .ssh_profiles
            .values()
            .flat_map(|profile| &profile.keys)
            .filter(|key| &key.private_key_ref == reference)
        {
            let valid = provider_material_as_secret_string(&material)
                .and_then(|source| parse_declared_ssh_private_key(&source))
                .is_ok_and(|private_key| {
                    !private_key.is_encrypted()
                        && private_key.algorithm() == SshAlgorithm::Ed25519
                        && private_key
                            .public_key()
                            .fingerprint(HashAlg::Sha256)
                            .to_string()
                            == key.fingerprint
                });
            if valid {
                keys_checked += 1;
            } else {
                keys_failed = true;
            }
        }
    }
    report.set(
        "provider_resources",
        if checked == references.len() {
            ValidationStatus::Passed
        } else {
            ValidationStatus::Failed
        },
        (checked != references.len()).then_some(("provider_resource_unavailable", 1)),
        checked,
        Some(references.len()),
    );
    report.set(
        "key_material",
        if keys_failed {
            ValidationStatus::Failed
        } else if keys_checked == total_keys {
            ValidationStatus::Passed
        } else {
            ValidationStatus::NotChecked
        },
        keys_failed.then_some(("provider_key_material_invalid", 4)),
        keys_checked,
        Some(total_keys),
    );
}

#[cfg(target_os = "linux")]
fn validate_installed(
    request: ValidationRequest,
    mut report: ComponentValidationReport,
) -> ComponentValidationReport {
    // Never fall back to legacy home configuration from a versioned installation.
    report.authority = Some("installed_broker");
    if request.component.providers() && request.online {
        validate_admitted_resources(&mut report);
        // Execution identities need not be allowed to read their owner's
        // configuration. The authenticated broker owns provider resolution.
        if request.component == ValidationComponent::Providers {
            return report.finish();
        }
    }
    let context = (|| -> Result<_> {
        let (_, receipt) = crate::setup::current_runtime_installation()?;
        let uid = nix::unistd::geteuid().as_raw();
        let policy = match receipt.mode {
            crate::setup::InstallMode::Strong => {
                crate::policy_store::load_resolved_policy_for_uid(uid)?
            }
            crate::setup::InstallMode::UserOnly => {
                crate::policy_store::load_user_only_resolved_policy_for_uid(uid)?
            }
        };
        Ok((receipt, policy))
    })();
    let (receipt, policy) = match context {
        Ok(context) => context,
        Err(_) => {
            report.observed(
                "configuration",
                Err(anyhow::anyhow!("unavailable")),
                "installed_authority_unavailable",
                3,
            );
            return report.finish();
        }
    };
    report.authority = Some("installed_broker");
    report.observed("configuration", Ok(()), "configuration_invalid", 2);
    report.declared_exec_profiles = Some(policy.workloads.len());
    if request.component.tools() {
        for (component, executable) in [
            ("github_cli", &receipt.native_gh),
            ("git", &receipt.native_git),
        ] {
            report.observed(
                component,
                program_guard(executable, "native executable").map(|_| ()),
                "native_executable_unavailable",
                3,
            );
        }
    }
    report.finish()
}

#[cfg(target_os = "linux")]
fn validate_admitted_resources(report: &mut ComponentValidationReport) {
    apply_admitted_observation(
        report,
        crate::broker_client::request_active(
            crate::broker_protocol::BrokerRequest::ValidateProviders,
        ),
    );
}

#[cfg(target_os = "linux")]
fn apply_admitted_observation(
    report: &mut ComponentValidationReport,
    response: Result<crate::broker_protocol::BrokerResponse>,
) {
    use crate::broker_protocol::BrokerResponse;
    match response {
        Ok(BrokerResponse::ProviderValidation {
            authentication_checked,
            authentication_total,
            resources_checked,
            resources_total,
            keys_checked,
            keys_failed,
            keys_total,
        }) => {
            for (component, checked, total, error) in [
                (
                    "provider_authentication",
                    authentication_checked,
                    authentication_total,
                    "provider_authentication_unavailable",
                ),
                (
                    "provider_resources",
                    resources_checked,
                    resources_total,
                    "provider_resource_unavailable",
                ),
            ] {
                let complete = checked == total;
                report.set(
                    component,
                    if complete {
                        ValidationStatus::Passed
                    } else {
                        ValidationStatus::Failed
                    },
                    (!complete).then_some((error, 1)),
                    checked as usize,
                    Some(total as usize),
                );
            }
            report.set(
                "key_material",
                if keys_failed > 0 {
                    ValidationStatus::Failed
                } else if keys_checked == keys_total {
                    ValidationStatus::Passed
                } else {
                    ValidationStatus::NotChecked
                },
                (keys_failed > 0).then_some(("provider_key_material_invalid", 4)),
                keys_checked as usize,
                Some(keys_total as usize),
            );
        }
        Ok(BrokerResponse::Denied { code, .. }) if code == "provider_unavailable" => report
            .observed(
                "provider_resources",
                Err(anyhow::anyhow!("unavailable")),
                "provider_unavailable",
                1,
            ),
        Ok(BrokerResponse::Denied { .. }) => report.observed(
            "provider_resources",
            Err(anyhow::anyhow!("denied")),
            "provider_validation_denied",
            4,
        ),
        Ok(_) | Err(_) => report.observed(
            "provider_resources",
            Err(anyhow::anyhow!("unavailable")),
            "admitted_provider_validation_required",
            3,
        ),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::broker_protocol::BrokerResponse;

    struct FixtureProvider {
        id: ProviderId,
        values: BTreeMap<String, Vec<u8>>,
        reads: std::sync::Mutex<Vec<String>>,
    }

    impl SecretProvider for FixtureProvider {
        fn id(&self) -> &ProviderId {
            &self.id
        }
        fn capabilities(&self) -> ProviderCapabilities {
            panic!("unexpected capability probe")
        }
        fn health(
            &self,
            context: SecretOperationContext<'_>,
        ) -> std::result::Result<ProviderHealth, SecretError> {
            context.checkpoint()?;
            Ok(ProviderHealth::Healthy)
        }
        fn metadata(
            &self,
            _: &SecretReference,
            _: SecretPurpose,
            _: SecretOperationContext<'_>,
        ) -> std::result::Result<SecretMetadata, SecretError> {
            panic!("unexpected metadata probe")
        }
        fn read_exportable(
            &self,
            reference: &SecretReference,
            context: SecretOperationContext<'_>,
        ) -> std::result::Result<SecretMaterial, SecretError> {
            context.checkpoint()?;
            self.reads
                .lock()
                .unwrap()
                .push(reference.expose_to_provider().into());
            let bytes = self
                .values
                .get(reference.expose_to_provider())
                .ok_or_else(|| SecretError::new(SecretErrorKind::PermissionDenied))?;
            SecretMaterial::new(bytes.clone())
        }
        fn public_material(
            &self,
            _: &SecretReference,
            _: SecretOperationContext<'_>,
        ) -> std::result::Result<SecretPublicMaterial, SecretError> {
            panic!("unexpected public-material probe")
        }
        fn sign(
            &self,
            _: &SecretReference,
            _: &[u8],
            _: SecretOperationContext<'_>,
        ) -> std::result::Result<ProviderSignature, SecretError> {
            panic!("unexpected signing probe")
        }
    }

    #[test]
    fn resource_validation_continues_after_denial_and_separates_invalid_key_material() {
        let mut config: Config = toml::from_str(include_str!("../../config.example.toml")).unwrap();
        let key = PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[39; 32])),
            "fixture",
        )
        .unwrap();
        let profile = config.ssh_profiles.get_mut("automation").unwrap();
        profile.keys[0].fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let auth_reference = profile.keys[0].private_key_ref.clone();
        let bad_reference = profile.keys[1].private_key_ref.clone();
        let provider = FixtureProvider {
            id: ProviderId::parse("independent-fixture").unwrap(),
            values: BTreeMap::from([
                (
                    auth_reference,
                    key.to_openssh(ssh_key::LineEnding::LF)
                        .unwrap()
                        .as_bytes()
                        .to_vec(),
                ),
                (bad_reference, b"not-a-private-key-must-not-escape".to_vec()),
                (
                    config.profiles["terraform-plan"].environment["TF_TOKEN_app_terraform_io"]
                        .clone(),
                    vec![0, 255, 10],
                ),
            ]),
            reads: std::sync::Mutex::new(Vec::new()),
        };
        let mut report = ComponentValidationReport::new(true);
        validate_legacy_resources(&config, &provider, &mut report);
        let report = report.finish();
        assert_eq!(report.exit_code, 4);
        let resources = report
            .checks
            .iter()
            .find(|check| check.component == "provider_resources")
            .unwrap();
        assert_eq!((resources.checked, resources.total), (3, Some(4)));
        assert_eq!(resources.status, ValidationStatus::Failed);
        let keys = report
            .checks
            .iter()
            .find(|check| check.component == "key_material")
            .unwrap();
        assert_eq!((keys.checked, keys.total), (1, Some(3)));
        assert_eq!(keys.status, ValidationStatus::Failed);
        assert_eq!(
            *provider.reads.lock().unwrap(),
            config
                .declared_secret_references()
                .into_iter()
                .collect::<Vec<_>>()
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("must-not-escape"));
        assert!(!json.contains("op://"));
    }

    #[test]
    fn admitted_provider_observation_preserves_counts_without_inventing_other_checks() {
        for (checked, total, code) in [(2, 2, 0), (1, 2, 1), (0, 0, 0)] {
            let mut report = ComponentValidationReport::new(true);
            apply_admitted_observation(
                &mut report,
                Ok(BrokerResponse::ProviderValidation {
                    authentication_checked: checked,
                    authentication_total: total,
                    resources_checked: checked,
                    resources_total: total,
                    keys_checked: 0,
                    keys_failed: 0,
                    keys_total: 1,
                }),
            );
            let report = report.finish();
            assert_eq!(report.exit_code, code);
            for check in &report.checks {
                if matches!(
                    check.component,
                    "provider_resources" | "provider_authentication"
                ) {
                    assert_eq!(check.checked, checked as usize);
                    assert_eq!(check.total, Some(total as usize));
                } else {
                    assert_eq!(check.status, ValidationStatus::NotChecked);
                }
            }
        }
    }

    #[test]
    fn admitted_key_observation_preserves_unread_invalid_and_valid_distinctions() {
        for (checked, failed, total, status, code) in [
            (0, 0, 1, ValidationStatus::NotChecked, 0),
            (0, 1, 1, ValidationStatus::Failed, 4),
            (1, 0, 1, ValidationStatus::Passed, 0),
            (0, 0, 0, ValidationStatus::Passed, 0),
        ] {
            let mut report = ComponentValidationReport::new(true);
            apply_admitted_observation(
                &mut report,
                Ok(BrokerResponse::ProviderValidation {
                    authentication_checked: 1,
                    authentication_total: 1,
                    resources_checked: 1,
                    resources_total: 1,
                    keys_checked: checked,
                    keys_failed: failed,
                    keys_total: total,
                }),
            );
            let report = report.finish();
            assert_eq!(report.exit_code, code);
            let keys = report
                .checks
                .iter()
                .find(|check| check.component == "key_material")
                .unwrap();
            assert_eq!(keys.status, status);
            assert_eq!(
                (keys.checked, keys.total),
                (checked as usize, Some(total as usize))
            );
        }
    }

    #[test]
    fn admitted_authentication_failure_is_not_hidden_by_successful_resource_reads() {
        let mut report = ComponentValidationReport::new(true);
        apply_admitted_observation(
            &mut report,
            Ok(BrokerResponse::ProviderValidation {
                authentication_checked: 1,
                authentication_total: 2,
                resources_checked: 3,
                resources_total: 3,
                keys_checked: 0,
                keys_failed: 0,
                keys_total: 0,
            }),
        );
        let report = report.finish();
        assert_eq!(report.exit_code, 1);
        let authentication = report
            .checks
            .iter()
            .find(|check| check.component == "provider_authentication")
            .unwrap();
        assert_eq!(authentication.status, ValidationStatus::Failed);
        assert_eq!(
            authentication.error_kind,
            Some("provider_authentication_unavailable")
        );
        let resources = report
            .checks
            .iter()
            .find(|check| check.component == "provider_resources")
            .unwrap();
        assert_eq!(resources.status, ValidationStatus::Passed);
    }

    #[test]
    fn admitted_provider_observation_separates_unavailable_and_authority_failures() {
        for (response, code, kind) in [
            (
                Ok(BrokerResponse::Denied {
                    code: "provider_unavailable".into(),
                    message: "must-not-escape".into(),
                }),
                1,
                "provider_unavailable",
            ),
            (
                Ok(BrokerResponse::Denied {
                    code: "resource_denied".into(),
                    message: "must-not-escape".into(),
                }),
                4,
                "provider_validation_denied",
            ),
            (
                Ok(BrokerResponse::NoSession),
                3,
                "admitted_provider_validation_required",
            ),
            (
                Err(anyhow::anyhow!("must-not-escape")),
                3,
                "admitted_provider_validation_required",
            ),
        ] {
            let mut report = ComponentValidationReport::new(true);
            apply_admitted_observation(&mut report, response);
            let report = report.finish();
            assert_eq!(report.exit_code, code);
            assert_eq!(report.error_kind, Some(kind));
            assert!(!serde_json::to_string(&report)
                .unwrap()
                .contains("must-not-escape"));
        }
    }
}
