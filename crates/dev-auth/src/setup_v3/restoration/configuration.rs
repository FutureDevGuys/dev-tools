use super::*;

pub(super) struct ConfigurationSpec<'a> {
    pub prior: &'a RetainedSetupObject,
    pub candidate: Option<&'a [u8]>,
    pub authority: DocumentAuthority,
}

pub(super) fn strong_configuration_specs(
    generation: &RetainedSetupGeneration,
) -> Result<Vec<ConfigurationSpec<'_>>> {
    let plan = &generation.plan;
    if plan.intent.mode != DeploymentMode::Strong
        || plan.installation.request.mode != crate::setup::InstallMode::Strong
    {
        bail!("strong configuration selection requires matching deployment authority");
    }
    let (current_relative, alternate_relative) = match plan.authority_schema.as_deref() {
        None => (
            crate::policy_store::USER_CONFIG_RELATIVE_PATH,
            crate::policy_store::USER_CONFIG_V3_RELATIVE_PATH,
        ),
        Some("dev-auth-administrator-policy-v3") => (
            crate::policy_store::USER_CONFIG_V3_RELATIVE_PATH,
            crate::policy_store::USER_CONFIG_RELATIVE_PATH,
        ),
        _ => bail!("strong restoration has unsupported candidate configuration authority"),
    };
    let mut specs = vec![configuration_spec(
        generation,
        "administrator_policy",
        "system",
        Path::new(crate::policy_store::SYSTEM_POLICY_PATH),
        0,
        0o644,
        Some(document_identity(plan, "administrator_policy", "system")?),
    )?];
    for account in &plan.accounts {
        for (kind, relative, candidate) in [
            (
                "user_configuration",
                current_relative,
                Some(document_identity(
                    plan,
                    "user_configuration",
                    &account.name,
                )?),
            ),
            ("retained_user_configuration", alternate_relative, None),
        ] {
            specs.push(configuration_spec(
                generation,
                kind,
                &account.name,
                &account.home.join(relative),
                account.uid,
                0o600,
                candidate,
            )?);
        }
    }
    for account in &plan.retiring_accounts {
        for (kind, relative) in [
            (
                "retiring_user_configuration_v2",
                crate::policy_store::USER_CONFIG_RELATIVE_PATH,
            ),
            (
                "retiring_user_configuration_v3",
                crate::policy_store::USER_CONFIG_V3_RELATIVE_PATH,
            ),
        ] {
            specs.push(configuration_spec(
                generation,
                kind,
                &account.name,
                &account.home.join(relative),
                account.uid,
                0o600,
                None,
            )?);
        }
    }
    Ok(specs)
}

fn configuration_spec<'a>(
    generation: &'a RetainedSetupGeneration,
    kind: &str,
    subject: &str,
    path: &Path,
    owner_uid: u32,
    mode: u32,
    candidate: Option<&DocumentIdentity>,
) -> Result<ConfigurationSpec<'a>> {
    let prior = retained_object(generation, kind, subject)?;
    if prior.current.path != path
        || prior.current.identity.as_ref().is_some_and(|identity| {
            identity.owner_uid != owner_uid
                || if kind == "administrator_policy" {
                    !matches!(identity.mode, 0o600 | 0o644)
                } else {
                    identity.mode != 0o600
                }
        })
    {
        bail!("retained configuration has incompatible destination or custody");
    }
    Ok(ConfigurationSpec {
        prior,
        candidate: candidate
            .map(|identity| candidate_bytes(&generation.candidate_documents, identity))
            .transpose()?,
        authority: DocumentAuthority {
            owner_uid,
            mode,
            limit: DOCUMENT_LIMIT,
        },
    })
}

pub(super) fn validate_prior_strong_configuration(
    generation: &RetainedSetupGeneration,
) -> Result<()> {
    let specs = strong_configuration_specs(generation)?;
    let administrator = specs
        .first()
        .context("retained administrator policy selection is absent")?;
    let Some(bytes) = administrator.prior.bytes.as_deref() else {
        if !generation.plan.retiring_accounts.is_empty() {
            bail!("retiring accounts have no retained administrator authority");
        }
        // No old policy grants these user documents authority. Preserve them
        // without interpreting them as active configuration or starting work.
        return Ok(());
    };
    let policy = parse_runtime_administrator(bytes)?;
    if policy.mode() != SystemMode::Strong {
        bail!("retained administrator policy has incompatible mode");
    }
    let desired = generation
        .plan
        .accounts
        .iter()
        .map(|account| account.name.as_str())
        .collect::<BTreeSet<_>>();
    let retiring = generation
        .plan
        .retiring_accounts
        .iter()
        .map(|account| account.name.as_str())
        .collect::<BTreeSet<_>>();
    let expected_retiring = policy
        .allowed_users()
        .iter()
        .map(String::as_str)
        .filter(|name| !desired.contains(name))
        .collect::<BTreeSet<_>>();
    if retiring != expected_retiring {
        bail!("retained administrator users differ from the approved retiring-account set");
    }
    let relative = if policy.authority_schema().is_some() {
        crate::policy_store::USER_CONFIG_V3_RELATIVE_PATH
    } else {
        crate::policy_store::USER_CONFIG_RELATIVE_PATH
    };
    for account in generation
        .plan
        .accounts
        .iter()
        .chain(&generation.plan.retiring_accounts)
    {
        if !policy.allowed_users().contains(&account.name) {
            continue;
        }
        let path = account.home.join(relative);
        let selected = specs
            .iter()
            .find(|spec| {
                spec.prior.current.path == path && spec.prior.current.subject == account.name
            })
            .context("prior policy's user configuration is not retained")?;
        if let Some(bytes) = selected.prior.bytes.as_deref() {
            let resolved = policy.resolve_user(&account.name, bytes)?;
            validate_resolved_workspace_authority(&resolved, account.uid)?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    #[test]
    fn strong_configuration_selection_rejects_wrong_custody_and_destinations() {
        for kind in [
            "administrator_policy",
            "user_configuration",
            "retained_user_configuration",
            "retiring_user_configuration_v2",
            "retiring_user_configuration_v3",
        ] {
            for change in ["owner", "mode", "path", "bytes"] {
                let mut generation = generation(true);
                let object = generation
                    .documents
                    .iter_mut()
                    .find(|object| object.current.kind == kind)
                    .unwrap();
                let original = object.current.clone();
                match change {
                    "owner" => object.current.identity.as_mut().unwrap().owner_uid = 42,
                    "mode" => object.current.identity.as_mut().unwrap().mode = 0o4755,
                    "path" => object.current.path = PathBuf::from("/unowned/config"),
                    "bytes" => object.bytes.as_mut().unwrap().push(b'!'),
                    _ => unreachable!(),
                }
                *generation
                    .plan
                    .current_paths
                    .iter_mut()
                    .find(|current| **current == original)
                    .unwrap() = object.current.clone();
                assert!(
                    strong_configuration_specs(&generation).is_err(),
                    "{kind}: {change}"
                );
            }
        }
    }

    #[test]
    fn prior_strong_policy_selects_its_own_version_for_desired_and_retiring_users() {
        for candidate_logical in [false, true] {
            for prior_logical in [false, true] {
                let mut generation = generation(candidate_logical);
                let (policy, original_user, config) = if prior_logical {
                    (include_str!("../../../policy-v3.example.toml"), "automation",
                        "schema = \"dev-auth-user-config-v3\"\nworkloads = []\n[authority_profiles]\n")
                } else {
                    (
                        include_str!("../../../policy-v2.example.toml"),
                        "example-user",
                        "version = 2\n",
                    )
                };
                let policy = policy.replace(original_user, "alpha").replace(
                    "allowed_users = [\"alpha\"]",
                    "allowed_users = [\"alpha\", \"gamma\"]",
                );
                let parsed = parse_runtime_administrator(policy.as_bytes()).unwrap();
                parsed.resolve_user("alpha", config.as_bytes()).unwrap();
                replace_prior(
                    &mut generation,
                    "administrator_policy",
                    "system",
                    policy.as_bytes(),
                );
                let desired_kind = if candidate_logical == prior_logical {
                    "user_configuration"
                } else {
                    "retained_user_configuration"
                };
                let retiring_kind = if prior_logical {
                    "retiring_user_configuration_v3"
                } else {
                    "retiring_user_configuration_v2"
                };
                replace_prior(&mut generation, desired_kind, "alpha", config.as_bytes());
                replace_prior(&mut generation, retiring_kind, "gamma", config.as_bytes());
                validate_prior_strong_configuration(&generation).unwrap();
                replace_prior(
                    &mut generation,
                    retiring_kind,
                    "gamma",
                    b"invalid restored config",
                );
                assert!(validate_prior_strong_configuration(&generation).is_err());
                replace_prior(&mut generation, retiring_kind, "gamma", config.as_bytes());
                generation.plan.retiring_accounts.clear();
                assert!(validate_prior_strong_configuration(&generation).is_err());
            }
        }
    }

    fn replace_prior(
        generation: &mut RetainedSetupGeneration,
        kind: &str,
        subject: &str,
        bytes: &[u8],
    ) {
        let object = generation
            .documents
            .iter_mut()
            .find(|object| object.current.kind == kind && object.current.subject == subject)
            .unwrap();
        let identity = object.current.identity.as_mut().unwrap();
        identity.length = bytes.len() as u64;
        identity.sha256 = sha256_hex(bytes);
        object.bytes = Some(bytes.to_vec());
        *generation
            .plan
            .current_paths
            .iter_mut()
            .find(|current| current.kind == kind && current.subject == subject)
            .unwrap() = object.current.clone();
    }

    #[test]
    fn strong_restoration_selects_admin_desired_and_retiring_configuration_versions() {
        for logical in [false, true] {
            let generation = generation(logical);
            let specs = strong_configuration_specs(&generation).unwrap();
            assert_eq!(specs.len(), 7);
            for spec in specs {
                let current = &spec.prior.current;
                let expected_uid = match current.subject.as_str() {
                    "system" => 0,
                    "alpha" => 1000,
                    "beta" => 1001,
                    "gamma" => 1002,
                    _ => panic!("unexpected selected account"),
                };
                assert_eq!(spec.authority.owner_uid, expected_uid);
                assert_eq!(
                    spec.authority.mode,
                    if expected_uid == 0 { 0o644 } else { 0o600 }
                );
                assert_eq!(spec.prior.current.identity.as_ref().unwrap().mode, 0o600);
                assert_eq!(
                    spec.candidate.is_some(),
                    matches!(
                        current.kind.as_str(),
                        "administrator_policy" | "user_configuration"
                    )
                );
                assert_eq!(spec.authority.limit, DOCUMENT_LIMIT);
            }
        }
    }

    // This fixture describes document selection, not a signed setup plan or
    // native account authority. No fixture destination is opened or written.
    pub(in crate::setup_v3::restoration) fn generation(logical: bool) -> RetainedSetupGeneration {
        let account = |name: &str, uid| NativeAccountIdentity {
            name: name.into(),
            uid,
            gid: uid,
            home: PathBuf::from(format!("/fixture/{name}")),
        };
        let accounts = vec![account("alpha", 1000), account("beta", 1001)];
        let retiring_accounts = vec![account("gamma", 1002)];
        let installation = SetupPlan {
            schema: "dev-auth-setup-plan-v2".into(),
            paths: crate::setup::SetupPaths::strong(),
            request: crate::setup::InstallRequest {
                mode: crate::setup::InstallMode::Strong,
                version: "0.4.0".into(),
                source_executable: "/fixture/candidate".into(),
                native_git: "/usr/bin/git".into(),
                native_gh: "/usr/bin/gh".into(),
                activate_transparent_launchers: false,
            },
            source_length: 0,
            source_sha256: String::new(),
            verified_release: None,
        };
        let intent = DeploymentIntent {
            schema: "dev-auth-deployment-v1".into(),
            mode: DeploymentMode::Strong,
            channel: crate::deployment::Channel::Stable,
            offline: true,
            activation: Activation::Inactive,
            administrator_policy: "/fixture/policy".into(),
            users: Vec::new(),
            credentials: Vec::new(),
        };
        let authority_schema = logical.then_some("dev-auth-administrator-policy-v3");
        let mut documents = Vec::new();
        let mut candidate_documents = Vec::new();
        for (kind, subject, path) in expected_current_path_keys(
            &installation,
            &intent,
            &accounts,
            &retiring_accounts,
            authority_schema,
        )
        .into_iter()
        .filter(|(kind, _, _)| {
            matches!(
                kind.as_str(),
                "administrator_policy"
                    | "user_configuration"
                    | "retained_user_configuration"
                    | "retiring_user_configuration_v2"
                    | "retiring_user_configuration_v3"
            )
        }) {
            let uid = accounts
                .iter()
                .chain(&retiring_accounts)
                .find(|account| account.name == subject)
                .map_or(0, |account| account.uid);
            let bytes = format!("prior {kind} {subject}").into_bytes();
            let current = CurrentPathIdentity {
                kind: kind.clone(),
                subject: subject.clone(),
                path,
                identity: Some(CurrentFileIdentity {
                    object_type: "file".into(),
                    owner_uid: uid,
                    mode: 0o600,
                    link_count: 1,
                    length: bytes.len() as u64,
                    sha256: sha256_hex(&bytes),
                    link_target: None,
                }),
            };
            documents.push(RetainedSetupObject {
                current,
                bytes: Some(bytes),
            });
            if matches!(kind.as_str(), "administrator_policy" | "user_configuration") {
                let bytes = format!("candidate {kind} {subject}").into_bytes();
                candidate_documents.push(RetainedCandidateDocument {
                    identity: DocumentIdentity {
                        kind,
                        subject,
                        path: "/fixture/source".into(),
                        length: bytes.len() as u64,
                        sha256: sha256_hex(&bytes),
                    },
                    bytes,
                });
            }
        }
        RetainedSetupGeneration {
            schema: "dev-auth-retained-setup-generation-v1".into(),
            plan_sha256: String::new(),
            plan: SetupPlanV3 {
                schema: "dev-auth-setup-plan-v3".into(),
                authority_schema: authority_schema.map(str::to_owned),
                intent,
                intent_sha256: String::new(),
                installation,
                current_paths: documents
                    .iter()
                    .map(|object| object.current.clone())
                    .collect(),
                source_documents: candidate_documents
                    .iter()
                    .map(|document| document.identity.clone())
                    .collect(),
                accounts,
                retiring_accounts,
                current_credential_ready: BTreeSet::new(),
                current_broker_state: "stopped".into(),
                current_state_sha256: String::new(),
                actions: Vec::new(),
            },
            documents,
            candidate_documents,
        }
    }
}
