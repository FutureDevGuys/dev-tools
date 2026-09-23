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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Initial,
    Interrupted,
    Reconfigured,
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
        serde_json::to_vec(&crate::privilege::policy::Policy::template()).unwrap(),
    )
    .unwrap();
    fs::set_permissions(policy_source, fs::Permissions::from_mode(0o600)).unwrap();
    let source = Path::new("/candidate/dev-auth");
    let executable_identity = ArtifactIdentity::from_file(source, CURRENT_OBJECT_LIMIT).unwrap();
    let extracted = "/fixture/matched-sudo.so";
    let status = std::process::Command::new(source)
        .args(["privilege-payload", extracted])
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
        privilege_policy: None,
        users: vec![],
        credentials: vec![],
        bindings: vec![],
    };
    let (current_paths, current_credential_ready, current_broker_state) = current_state_snapshot(
        &installation,
        &intent,
        &[],
        &[],
        Some("dev-auth-privilege-policy-v1"),
    )
    .unwrap();
    let current_state_sha256 = stored_current_state_digest(
        &current_paths,
        &current_credential_ready,
        &current_broker_state,
    )
    .unwrap();
    let plan = SetupPlanV3 {
        privilege_previous_block: None,
        privilege_current_state: None,
        privilege_payload: payload_with_library(&installation, &library).unwrap(),
        authority_schema: Some("dev-auth-privilege-policy-v1".into()),
        schema: "dev-auth-setup-plan-v4".into(),
        intent_sha256: sha256_hex(&canonical_deployment_intent(&intent).unwrap()),
        actions: planned_action_contract(&intent),
        intent,
        installation,
        source_documents: vec![
            read_document(policy_source, "privilege_policy", "system")
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
        for kind in [
            "privilege_sudoers",
            "privilege_sudo_conf",
            "privilege_service",
        ] {
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
    let mut policy = crate::privilege::policy::Policy::template();
    policy.operations.insert(
        "fixture-check".into(),
        crate::privilege::policy::ExecutionPlan {
            nodes: vec![crate::privilege::policy::PlanCommand {
                program: "/usr/bin/true".into(),
                arguments: Vec::new(),
                working_directory: "/".into(),
                environment: Vec::new(),
            }],
            pipes: Vec::new(),
            exit_policy: crate::privilege::policy::ExitPolicy::Last,
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
        read_document(next_policy_path, "privilege_policy", "system")
            .unwrap()
            .identity,
    ];
    next.privilege_previous_block =
        previously_owned_block(&next.installation, &next.intent).unwrap();
    let (current, ready, state) = current_state_snapshot(
        &next.installation,
        &next.intent,
        &[],
        &[],
        Some("dev-auth-privilege-policy-v1"),
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
        fs::read(crate::privilege::SYSTEM_POLICY).unwrap(),
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
