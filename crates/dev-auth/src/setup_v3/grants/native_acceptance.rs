#![cfg(test)]

//! Fixed, no-password native acceptance. The fixture establishes synthetic
//! prior approval; public recovery/restoration perform all installed mutations.
//! This does not claim signed release intake or a real administrator grant.
use super::*;
use std::os::unix::fs::PermissionsExt;

fn invoke(executable: &Path, arguments: &[&str]) -> serde_json::Value {
    eprintln!(
        "privilege setup fixture: {} {arguments:?}",
        executable.display()
    );
    let output = dev_tools_command::run_bounded_command(&dev_tools_command::BoundedCommand {
        executable,
        arguments: &arguments
            .iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>(),
        environment: &BTreeMap::new(),
        cwd: Some(Path::new("/")),
        timeout: std::time::Duration::from_secs(90),
        output_limit: 64 * 1024,
    })
    .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "fixed public operation did not return JSON: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(
        output.status.code(),
        result["exit_code"].as_i64().map(|code| code as i32)
    );
    result
}

#[test]
#[ignore = "only the installed-fixture preparer requires an embedded native sudo payload"]
fn native_fixture_embedded_sudo_payload_available() {
    assert!(
        !assets::SUDO_LIBRARY.is_empty(),
        "rebuild the library test with DEV_AUTH_SUDO_ARTIFACT set to the source-matched native sudo helper"
    );
}

#[test]
#[ignore = "requires an explicitly owned rootful disposable systemd container and /candidate/dev-auth; never run on the host"]
fn native_disposable_privilege_only_recovery_and_restore() {
    privilege_only_recovery_and_restore(Case::Initial);
}

#[test]
#[ignore = "requires an explicitly owned rootful disposable systemd container and /candidate/dev-auth; never run on the host"]
fn native_disposable_privilege_only_resumes_partial_withdrawal() {
    privilege_only_recovery_and_restore(Case::Interrupted);
}

#[test]
#[ignore = "requires an explicitly owned rootful disposable systemd container and /candidate/dev-auth; never run on the host"]
fn native_disposable_privilege_only_reconfiguration_restores_prior_inactive() {
    privilege_only_recovery_and_restore(Case::Reconfigured);
}

#[test]
#[ignore = "requires an explicitly owned rootful disposable systemd container and /candidate/dev-auth; never run on the host"]
fn native_disposable_privilege_only_rejects_foreign_integrations_before_publication() {
    privilege_only_recovery_and_restore(Case::ForeignIntegrations);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Initial,
    Interrupted,
    Reconfigured,
    ForeignIntegrations,
}

fn privilege_only_recovery_and_restore(case: Case) {
    assert_eq!(
        std::env::var("DEV_AUTH_NATIVE_SYSTEMD_FIXTURE").as_deref(),
        Ok("disposable")
    );
    assert!(nix::unistd::geteuid().is_root());
    assert!(Path::new("/run/.containerenv").is_file());
    assert_eq!(
        fs::read_to_string("/proc/1/comm").unwrap().trim(),
        "systemd"
    );
    let paths = crate::setup::SetupPaths::strong();
    assert!(!paths.data_root.exists());
    assert!(!Path::new(crate::policy_store::SYSTEM_POLICY_PATH).exists());
    for (_, _, path) in super::paths()
        .into_iter()
        .filter(|(_, _, path)| path != Path::new(SUDO_CONF))
    {
        assert!(
            !path.exists(),
            "fixture requires absent privilege destinations"
        );
    }
    // Preserve the image's tools, but prove they are not consulted by setup.
    for (tool, retained) in [
        ("/usr/bin/git", "/fixture/native-git"),
        ("/usr/bin/gh", "/fixture/native-gh"),
    ] {
        assert!(Path::new(tool).is_file());
        fs::rename(tool, retained).unwrap();
    }
    let original_conf = fs::read(SUDO_CONF).ok();
    let policy_source = Path::new("/fixture/privilege-policy.json");
    fs::write(
        policy_source,
        serde_json::to_vec(&crate::privilege::grants::policy::Policy::template()).unwrap(),
    )
    .unwrap();
    fs::set_permissions(policy_source, fs::Permissions::from_mode(0o600)).unwrap();
    let source = Path::new("/candidate/dev-auth");
    let executable_identity = ArtifactIdentity::from_file(source, CURRENT_OBJECT_LIMIT).unwrap();
    let extracted = "/fixture/matched-sudo.so";
    let status = std::process::Command::new(source)
        .args(["grant-payload", extracted])
        .env_clear()
        .status()
        .unwrap();
    assert!(status.success());
    let library = fs::read(extracted).unwrap();
    let version = env!("CARGO_PKG_VERSION");
    let installation = SetupPlan {
        schema: "dev-auth-setup-binary-plan-v3".into(),
        paths: paths.clone(),
        request: crate::setup::InstallRequest {
            purpose: SetupPurpose::PrivilegeOnly,
            mode: crate::setup::InstallMode::Strong,
            version: version.into(),
            source_executable: source.into(),
            native_git: PathBuf::new(),
            native_gh: PathBuf::new(),
            activate_transparent_launchers: false,
        },
        source_length: executable_identity.length,
        source_sha256: executable_identity.sha256.clone(),
        verified_release: Some(crate::release_manifest::VerifiedDevAuthRelease {
            schema: "dev-auth-verified-release-v1".into(),
            root_path: "/unavailable-root".into(),
            manifest_path: "/unavailable-manifest".into(),
            root_generation: 1,
            manifest_generation: 1,
            version: version.into(),
            source_commit: "a".repeat(40),
            target: crate::release_manifest::target_id().unwrap(),
            artifact_path: source.into(),
            artifact_url: "https://example.invalid/fixture".into(),
            artifact_length: executable_identity.length,
            artifact_sha256: executable_identity.sha256.clone(),
            root_sha256: "b".repeat(64),
            manifest_sha256: "c".repeat(64),
        }),
    };
    let intent = DeploymentIntent {
        bindings: Vec::new(),
        purpose: SetupPurpose::PrivilegeOnly,
        schema: "dev-auth-deployment-intent-v2".into(),
        mode: DeploymentMode::Strong,
        channel: crate::deployment::Channel::Stable,
        offline: true,
        activation: if case == Case::Reconfigured {
            Activation::Inactive
        } else {
            Activation::Transparent
        },
        administrator_policy: policy_source.into(),
        grant_policy: None,
        users: vec![],
        credentials: vec![],
    };
    if case == Case::ForeignIntegrations {
        reject_foreign_integrations_before_publication(&installation, &intent);
        return;
    }
    let (current_paths, current_credential_ready, current_broker_state) = current_state_snapshot(
        &installation,
        &intent,
        &[],
        &[],
        Some("dev-auth-administrator-grant-policy-v1"),
    )
    .unwrap();
    let current_state_sha256 = stored_current_state_digest(
        &current_paths,
        &current_credential_ready,
        &current_broker_state,
    )
    .unwrap();
    let plan = SetupPlanV3 {
        credential_preservation: None,
        grant_previous_block: None,
        grant_current_state: None,
        grant_payload: payload_with_library(&installation, &library).unwrap(),
        authority_schema: Some("dev-auth-administrator-grant-policy-v1".into()),
        schema: "dev-auth-setup-plan-v4".into(),
        intent_sha256: sha256_hex(&canonical_deployment_intent(&intent).unwrap()),
        actions: planned_action_contract(&intent),
        intent,
        installation,
        source_documents: vec![
            read_document(policy_source, "grant_policy", "system")
                .unwrap()
                .identity,
        ],
        accounts: vec![],
        retiring_accounts: vec![],
        current_paths,
        current_credential_ready,
        current_broker_state,
        current_state_sha256,
    };
    let digest = sha256_hex(&serde_jcs::to_vec(&plan).unwrap());
    let lock = crate::setup_transition::lock_path(DeploymentMode::Strong, None).unwrap();
    {
        let _lease = InstallationLock::try_acquire(&lock).unwrap().unwrap();
        crate::setup_transition::begin(&paths, 0, &digest, || {
            capture_retained_generation(&plan, &digest)
        })
        .unwrap();
    }
    fs::remove_file(policy_source).unwrap();
    let result = invoke(
        source,
        &["setup", "recover", "--mode", "strong", "--format", "json"],
    );
    assert_eq!(result["verified"], true, "{result}");
    assert_eq!(result["changed"], true);
    let installed = paths
        .data_root
        .join("versions")
        .join(version)
        .join("dev-auth");
    assert_eq!(fs::read(LIBRARY).unwrap(), library);
    assert!(!Path::new("/etc/credstore.encrypted/dev-auth-slots").exists());
    assert!(!Path::new(crate::policy_store::SYSTEM_POLICY_PATH).exists());
    assert!(!Path::new("/usr/bin/git").exists() && !Path::new("/usr/bin/gh").exists());
    let record: crate::setup::InstallReceipt =
        serde_json::from_slice(&fs::read(paths.data_root.join("install-v2.json")).unwrap())
            .unwrap();
    assert_eq!(record.purpose, SetupPurpose::PrivilegeOnly);
    assert!(record.native_git.is_empty() && record.native_gh.is_empty());
    assert!(native::run(
        Path::new("/usr/bin/sudo"),
        &["-n".into(), "--".into(), "/usr/bin/true".into()]
    )
    .is_ok());
    fs::remove_file(source).unwrap();
    let repeat = invoke(
        &installed,
        &["setup", "recover", "--mode", "strong", "--format", "json"],
    );
    assert_eq!(repeat["verified"], true, "{repeat}");
    assert_eq!(repeat["changed"], false);
    if case == Case::Reconfigured {
        reconfigure_and_restore_prior(&plan, &installed);
        write_result(case);
        return;
    }
    if case == Case::Interrupted {
        let _lease = InstallationLock::try_acquire(&lock).unwrap().unwrap();
        crate::setup_transition::advance(
            &paths,
            0,
            &digest,
            crate::setup_transition::Phase::Restoring,
        )
        .unwrap();
        let generation = retained(&plan).unwrap();
        let files = desired_files(&plan, &generation.candidate_documents).unwrap();
        stop(&plan).unwrap();
        // Reproduce the durable prefix of restore() through removal of the
        // stopped service definition, before its daemon-reload. The next
        // operation is the public command, not an in-process continuation.
        for kind in ["grant_sudoers", "grant_sudo_conf", "grant_service"] {
            let file = files.iter().find(|file| file.kind == kind).unwrap();
            FileChange::new(file, prior(&generation, kind).unwrap())
                .unwrap()
                .restore()
                .unwrap();
        }
        assert!(!Path::new(SERVICE).exists());
    }
    let restored = invoke(
        &installed,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    if restored["verified"] != true {
        let retained = retained(&plan).unwrap();
        eprintln!(
            "privilege restoration observation: {:?}",
            verify_restored(&retained).err()
        );
        let core =
            crate::setup::restoration::InitialInstallationRestoration::new(&plan.installation);
        eprintln!(
            "core restoration observation: {:?}",
            core.and_then(|core| core.verify_restored()).err()
        );
        let properties = native::run(Path::new("/usr/bin/systemctl"), &[
            "show".into(), "--all".into(), "--property=Id,LoadState,ActiveState,SubState,FragmentPath,DropInPaths,UnitFileState,ControlGroup,MainPID,ControlPID,Job".into(), UNIT.into()
        ]).unwrap();
        eprintln!(
            "fixed native service observation: {}",
            String::from_utf8_lossy(&properties)
        );
        for (_, _, path) in super::paths() {
            eprintln!("fixed file {} present={}", path.display(), path.exists());
        }
    }
    assert_eq!(restored["verified"], true, "{restored}");
    assert_eq!(fs::read(SUDO_CONF).ok(), original_conf);
    for (path, _, _) in crate::setup::linux_system_assets() {
        assert!(
            !path.exists(),
            "privilege-only restore must retire shared system definitions"
        );
    }
    for (_, _, path) in super::paths()
        .into_iter()
        .filter(|(_, _, path)| path != Path::new(SUDO_CONF))
    {
        assert!(!path.exists());
    }
    assert!(!Path::new("/usr/local/bin/dev-auth").exists());
    let repeat = invoke(
        &installed,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    assert_eq!(repeat["verified"], true, "{repeat}");
    assert_eq!(repeat["changed"], false);
    write_result(case);
}

fn reject_foreign_integrations_before_publication(
    installation: &SetupPlan,
    intent: &DeploymentIntent,
) {
    let snapshot = || {
        current_state_snapshot(
            installation,
            intent,
            &[],
            &[],
            Some("dev-auth-administrator-grant-policy-v1"),
        )
        .unwrap()
    };
    let (absent, _, _) = snapshot();
    validate_existing_component(installation, &absent).unwrap();
    // The service goes last: its ordinary read-only observation may leave a
    // loaded, stopped manager record until the disposable fixture is discarded.
    for kind in [
        "grant_library",
        "grant_action",
        "grant_sudoers",
        "grant_service",
    ] {
        let (_, _, path) = super::paths()
            .into_iter()
            .find(|(role, _, _)| role == kind)
            .unwrap();
        let preparation = dev_tools_installation::DocumentDirectoryPreparation::observe(
            path.parent().unwrap(),
            0,
            0o755,
        )
        .unwrap();
        let (_directory, _) = preparation.prepare().unwrap();
        let bytes = if kind == "grant_service" {
            [
                assets::SERVICE.as_bytes(),
                b"\n# independently owned fixture definition\n",
            ]
            .concat()
        } else {
            format!("# independently owned {kind} fixture\n").into_bytes()
        };
        let mode = if kind == "grant_sudoers" {
            0o440
        } else {
            0o644
        };
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let native = fs::symlink_metadata(&path).unwrap();
        let custody = (
            native.dev(),
            native.ino(),
            native.uid(),
            native.gid(),
            native.nlink(),
            native.mode(),
        );
        assert!(native.is_file());
        assert_eq!((native.uid(), native.gid(), native.nlink()), (0, 0, 1));
        assert_eq!(native.mode() & 0o7777, mode);
        let before = snapshot();
        assert!(before.0.iter().any(|entry| {
            entry.kind == kind
                && entry.path == path
                && entry.identity.as_ref().is_some_and(|identity| {
                    identity.owner_uid == 0
                        && identity.mode == mode
                        && identity.length == bytes.len() as u64
                        && identity.sha256 == sha256_hex(&bytes)
                })
        }));
        let error = validate_existing_component(installation, &before.0)
            .expect_err("foreign grant integration must reject before setup publication");
        assert_eq!(
            error.to_string(),
            "privilege setup cannot overwrite unowned native integration files"
        );
        assert_eq!(snapshot(), before);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let after = fs::symlink_metadata(&path).unwrap();
        assert_eq!(
            (
                after.dev(),
                after.ino(),
                after.uid(),
                after.gid(),
                after.nlink(),
                after.mode(),
            ),
            custody
        );
        for name in [
            "install-v2.json",
            "installation-receipt-v1.json",
            "setup-transition-v1.json",
            "active",
            "previous",
            "versions",
        ] {
            assert!(matches!(
                fs::symlink_metadata(installation.paths.data_root.join(name)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ));
        }
        fs::remove_file(path).unwrap();
    }
    fs::write(
        "/fixture/privilege-foreign-integration-result.json",
        b"{\"schema\":\"dev-auth-native-privilege-foreign-integration-v1\",\"passed\":true,\"signed_release\":false,\"administrator_grant\":false}\n",
    )
    .unwrap();
}

fn write_result(case: Case) {
    fs::write(
        "/fixture/privilege-setup-result.json",
        serde_json::to_vec(&serde_json::json!({
            "schema": "dev-auth-native-privilege-setup-v1",
            "passed": true,
            "signed_release": false,
            "credentials_required": false,
            "partial_withdrawal": case == Case::Interrupted,
            "reconfiguration": case == Case::Reconfigured,
        }))
        .unwrap(),
    )
    .unwrap();
}

fn reconfigure_and_restore_prior(original: &SetupPlanV3, installed: &Path) {
    let paths = &original.installation.paths;
    let before_files = super::paths()
        .into_iter()
        .map(|(_, _, path)| {
            let bytes = fs::read(&path).ok();
            let mode = fs::metadata(&path).ok().map(|meta| meta.mode() & 0o7777);
            (path, bytes, mode)
        })
        .collect::<Vec<_>>();
    let before_receipt = fs::read(paths.data_root.join("install-v2.json")).unwrap();
    let next_policy_path = Path::new("/fixture/next-privilege-policy.json");
    let mut policy = crate::privilege::grants::policy::Policy::template();
    policy.operations.insert(
        "fixture-check".into(),
        crate::privilege::grants::policy::ExecutionPlan {
            output_limit_bytes: None,
            nodes: vec![crate::privilege::grants::policy::PlanCommand {
                run_as: None,
                stdin: None,
                stdout: None,
                stderr: None,
                after: Vec::new(),
                program: "/usr/bin/true".into(),
                arguments: Vec::new(),
                working_directory: "/".into(),
                environment: Vec::new(),
            }],
            pipes: Vec::new(),
            exit_policy: crate::privilege::grants::policy::ExitPolicy::Last,
        },
    );
    let next_policy = serde_json::to_vec(&policy).unwrap();
    fs::write(next_policy_path, &next_policy).unwrap();
    fs::set_permissions(next_policy_path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut next = original.clone();
    next.intent.activation = Activation::Transparent;
    next.intent.administrator_policy = next_policy_path.into();
    next.intent_sha256 = sha256_hex(&canonical_deployment_intent(&next.intent).unwrap());
    next.actions = planned_action_contract(&next.intent);
    next.source_documents = vec![
        read_document(next_policy_path, "grant_policy", "system")
            .unwrap()
            .identity,
    ];
    next.grant_previous_block = previously_owned_block(&next.installation, &next.intent).unwrap();
    let (current, ready, state) = current_state_snapshot(
        &next.installation,
        &next.intent,
        &[],
        &[],
        Some("dev-auth-administrator-grant-policy-v1"),
    )
    .unwrap();
    validate_existing_component(&next.installation, &current).unwrap();
    next.current_state_sha256 = stored_current_state_digest(&current, &ready, &state).unwrap();
    next.current_paths = current;
    next.current_credential_ready = ready;
    next.current_broker_state = state;
    let digest = sha256_hex(&serde_jcs::to_vec(&next).unwrap());
    let lock = crate::setup_transition::lock_path(DeploymentMode::Strong, None).unwrap();
    {
        let _lease = InstallationLock::try_acquire(&lock).unwrap().unwrap();
        crate::setup_transition::begin(paths, 0, &digest, || {
            capture_retained_generation(&next, &digest)
        })
        .unwrap();
    }
    fs::remove_file(next_policy_path).unwrap();
    let recovered = invoke(
        installed,
        &["setup", "recover", "--mode", "strong", "--format", "json"],
    );
    assert_eq!(recovered["verified"], true, "{recovered}");
    assert_eq!(recovered["changed"], true);
    assert_eq!(
        fs::read(crate::privilege::grants::SYSTEM_POLICY).unwrap(),
        next_policy
    );
    assert!(!native::observe().unwrap().stopped);
    let repeat = invoke(
        installed,
        &["setup", "recover", "--mode", "strong", "--format", "json"],
    );
    assert_eq!(repeat["verified"], true, "{repeat}");
    assert_eq!(repeat["changed"], false);
    let restored = invoke(
        installed,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    assert_eq!(restored["verified"], true, "{restored}");
    assert_eq!(restored["changed"], true);
    for (path, bytes, mode) in before_files {
        assert_eq!(fs::read(&path).ok(), bytes, "{path:?}");
        assert_eq!(
            fs::metadata(&path).ok().map(|meta| meta.mode() & 0o7777),
            mode,
            "{path:?}"
        );
    }
    assert_eq!(
        fs::read(paths.data_root.join("install-v2.json")).unwrap(),
        before_receipt
    );
    let state = native::observe().unwrap();
    assert!(state.loaded && state.stopped && !state.enabled);
    assert!(!Path::new("/etc/credstore.encrypted/dev-auth-slots").exists());
    assert!(!Path::new(crate::policy_store::SYSTEM_POLICY_PATH).exists());
    assert!(!Path::new("/usr/bin/git").exists() && !Path::new("/usr/bin/gh").exists());
    let repeat = invoke(
        installed,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    assert_eq!(repeat["verified"], true, "{repeat}");
    assert_eq!(repeat["changed"], false);
}
