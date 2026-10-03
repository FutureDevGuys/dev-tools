//! Candidate-only strong restoration, with no fabricated prior installation.
use super::*;

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_initial_strong_generation_restores_absence() {
    initial_strong_generation_case(false);
}

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_initial_strong_generation_resumes_partial_withdrawal() {
    initial_strong_generation_case(true);
}

fn initial_strong_generation_case(partial: bool) {
    assert_eq!(
        std::env::var("DEV_AUTH_NATIVE_SYSTEMD_FIXTURE").as_deref(),
        Ok("disposable")
    );
    assert!(nix::unistd::Uid::effective().is_root());
    assert!(Path::new("/run/.containerenv").is_file());
    assert_eq!(
        fs::read_to_string("/proc/1/comm").unwrap().trim(),
        "systemd"
    );
    let paths = SetupPaths::strong();
    let assets = crate::setup::linux_system_assets();
    for path in std::iter::once(paths.data_root.clone())
        .chain(std::iter::once(PathBuf::from(
            crate::policy_store::SYSTEM_POLICY_PATH,
        )))
        .chain(assets.iter().map(|(path, _, _)| path.to_path_buf()))
        .chain(
            ALIASES
                .into_iter()
                .chain(["git", "gh"])
                .map(|name| paths.bin_dir.join(name)),
        )
    {
        assert_eq!(
            fs::symlink_metadata(path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }
    let name = "dev-auth-initial-alpha";
    assert!(nix::unistd::User::from_name(name).unwrap().is_none());
    run(
        "/usr/sbin/useradd",
        &["--create-home", "--no-log-init", name],
    );
    let user = nix::unistd::User::from_name(name).unwrap().unwrap();
    let account = NativeAccountIdentity {
        name: user.name,
        uid: user.uid.as_raw(),
        gid: user.gid.as_raw(),
        home: user.dir,
    };
    for relative in [
        "",
        ".config",
        ".config/dev-auth",
        ".local",
        ".local/bin",
        ".local/share",
        ".local/share/dev-auth",
    ] {
        let path = account.home.join(relative);
        fs::create_dir_all(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        rustix::fs::chownat(
            rustix::fs::CWD,
            &path,
            Some(rustix::fs::Uid::from_raw(account.uid)),
            None,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .unwrap();
    }
    publish(
        &account.home.join("unrelated"),
        b"unrelated account bytes",
        0o600,
        account.uid,
    );
    let root = tempfile::tempdir().unwrap();
    let source_policy = root.path().join("candidate-policy");
    let source_config = root.path().join("candidate-config");
    let policy_bytes = policy(&[&account.name]);
    let configuration =
        b"schema = \"dev-auth-user-config-v3\"\nworkloads = []\n[authority_profiles]\n";
    publish(&source_policy, &policy_bytes, 0o600, 0);
    publish(&source_config, configuration, 0o600, 0);
    let source = std::env::current_exe().unwrap();
    let identity = ArtifactIdentity::from_file(&source, 256 * 1024 * 1024).unwrap();
    let installation = SetupPlan {
        schema: "dev-auth-setup-plan-v2".into(),
        paths: paths.clone(),
        request: crate::setup::InstallRequest {
            mode: InstallMode::Strong,
            version: "0.4.0".into(),
            source_executable: source.clone(),
            native_git: "/usr/bin/true".into(),
            native_gh: "/usr/bin/true".into(),
            activate_transparent_launchers: false,
        },
        source_length: identity.length,
        source_sha256: identity.sha256.clone(),
        // Source-bound fixture claims exercise composition, not signature verification.
        verified_release: Some(crate::release_manifest::VerifiedDevAuthRelease {
            schema: "dev-auth-verified-release-v1".into(),
            root_path: root.path().join("unavailable-root"),
            manifest_path: root.path().join("unavailable-manifest"),
            root_generation: 1,
            manifest_generation: 1,
            version: "0.4.0".into(),
            source_commit: "a".repeat(40),
            target: crate::release_manifest::target_id().unwrap(),
            artifact_path: source.clone(),
            artifact_url: "https://example.invalid/fixture".into(),
            artifact_length: identity.length,
            artifact_sha256: identity.sha256.clone(),
            root_sha256: "b".repeat(64),
            manifest_sha256: "c".repeat(64),
        }),
    };
    let intent = DeploymentIntent {
        schema: "dev-auth-deployment-intent-v1".into(),
        mode: DeploymentMode::Strong,
        channel: crate::deployment::Channel::Stable,
        offline: true,
        activation: Activation::Inactive,
        administrator_policy: source_policy.clone(),
        users: vec![crate::deployment::DeploymentUser {
            name: account.name.clone(),
            config: source_config.clone(),
            policy: None,
        }],
        credentials: Vec::new(),
    };
    let (current_paths, ready, broker) = current_state_snapshot(
        &installation,
        &intent,
        std::slice::from_ref(&account),
        &[],
        Some("dev-auth-administrator-policy-v3"),
    )
    .unwrap();
    assert!(current_paths
        .iter()
        .all(|current| current.identity.is_none()));
    let plan = SetupPlanV3 {
        schema: "dev-auth-setup-plan-v3".into(),
        authority_schema: Some("dev-auth-administrator-policy-v3".into()),
        intent_sha256: sha256_hex(&canonical_deployment_intent(&intent).unwrap()),
        actions: planned_action_contract(&intent),
        intent,
        installation,
        source_documents: vec![
            read_document(&source_policy, "administrator_policy", "system")
                .unwrap()
                .identity,
            read_document(&source_config, "user_configuration", &account.name)
                .unwrap()
                .identity,
        ],
        accounts: vec![account.clone()],
        retiring_accounts: Vec::new(),
        current_state_sha256: stored_current_state_digest(&current_paths, &ready, &broker).unwrap(),
        current_paths,
        current_credential_ready: ready,
        current_broker_state: broker,
    };
    validate_setup_plan_v3_with_installation_check(&plan, &|_| Ok(())).unwrap();
    let digest = sha256_hex(&serde_jcs::to_vec(&plan).unwrap());
    crate::setup_transition::begin(&paths, 0, &digest, || {
        capture_retained_generation(&plan, &digest)
    })
    .unwrap();
    let retained = crate::setup_transition::retained_transition(&paths, 0)
        .unwrap()
        .unwrap()
        .bytes;
    let mut aliases = ALIASES.map(str::to_owned).to_vec();
    aliases.sort();
    dev_tools_installation::apply_versioned_installation(
        &VersionedInstallRequest {
            layout: VersionedLayout {
                product: "dev-auth".into(),
                data_root: paths.data_root.clone(),
                bin_dir: paths.bin_dir.clone(),
                artifact_name: "dev-auth".into(),
                owner_uid: 0,
                directory_mode: 0o755,
                bin_directory_mode: None,
            },
            version: "0.4.0".into(),
            source,
            identity: identity.clone(),
            aliases,
        },
        |_| Ok(()),
    )
    .unwrap();
    let candidate = InstallReceipt {
        schema: "dev-auth-install-v2".into(),
        mode: InstallMode::Strong,
        version: "0.4.0".into(),
        executable: paths
            .data_root
            .join("versions/0.4.0/dev-auth")
            .display()
            .to_string(),
        bin_dir: paths.bin_dir.display().to_string(),
        executable_length: identity.length,
        executable_sha256: identity.sha256.clone(),
        source_commit: Some("a".repeat(40)),
        root_generation: Some(1),
        manifest_generation: Some(1),
        native_git: "/usr/bin/true".into(),
        native_gh: "/usr/bin/true".into(),
        product_aliases: ALIASES.map(str::to_owned).to_vec(),
        transparent_aliases: vec!["git".into(), "gh".into()],
        privileged_launcher: Some(
            paths
                .data_root
                .join("dev-auth-workload-launcher")
                .display()
                .to_string(),
        ),
        system_assets: assets
            .iter()
            .map(|(path, bytes, _)| (path.display().to_string(), sha256_hex(bytes.as_bytes())))
            .collect(),
        previous_release: None,
    };
    let binary = fs::read(&candidate.executable).unwrap();
    publish(
        &paths.data_root.join("dev-auth-workload-launcher"),
        &binary,
        0o4755,
        0,
    );
    publish(
        &paths.data_root.join("dev-auth-setup-helper"),
        &binary,
        0o755,
        0,
    );
    publish(
        &paths.data_root.join("setup-helper-v1.json"),
        &sidecar(&candidate, &paths),
        0o644,
        0,
    );
    for name in ["git", "gh"] {
        std::os::unix::fs::symlink(&candidate.executable, paths.bin_dir.join(name)).unwrap();
    }
    publish(
        &paths.data_root.join("install-v2.json"),
        &serde_json::to_vec_pretty(&candidate).unwrap(),
        0o644,
        0,
    );
    for (path, bytes, mode) in &assets {
        publish(path, bytes.as_bytes(), *mode, 0);
    }
    publish(
        Path::new(crate::policy_store::SYSTEM_POLICY_PATH),
        &policy_bytes,
        0o644,
        0,
    );
    publish(
        &account
            .home
            .join(crate::policy_store::USER_CONFIG_V3_RELATIVE_PATH),
        configuration,
        0o600,
        account.uid,
    );
    fs::remove_file(source_policy).unwrap();
    fs::remove_file(source_config).unwrap();
    run(
        "/usr/bin/systemctl",
        &["--no-ask-password", "daemon-reload"],
    );
    run(
        "/usr/bin/systemctl",
        &[
            "--no-ask-password",
            "enable",
            "--now",
            "dev-auth-broker.socket",
            "dev-auth-broker-control.socket",
        ],
    );
    assert!(Path::new("/run/dev-auth/broker.sock").exists());
    assert!(Path::new("/run/dev-auth/control.sock").exists());
    let generation: RetainedSetupGeneration = serde_json::from_slice(&retained).unwrap();
    let launcher = fs::File::open(paths.data_root.join("dev-auth-workload-launcher")).unwrap();
    if partial {
        // Stop under the actual retained component and admission lease, then
        // interrupt the real document sequence after its first unit removal.
        let lock = crate::setup_transition::lock_path(DeploymentMode::Strong, None).unwrap();
        let _lease = InstallationLock::try_acquire(&lock).unwrap().unwrap();
        crate::setup_transition::advance(&paths, 0, &digest, Phase::Restoring).unwrap();
        let installation = installation_restoration(&generation).unwrap();
        assert!(installation.deactivate().unwrap());
        let mut removed_unit = false;
        for document in restoration_documents(&generation).unwrap() {
            document.restore().unwrap();
            if document.prior.current.path
                == Path::new("/etc/systemd/system/dev-auth-broker.socket")
            {
                removed_unit = true;
                break;
            }
        }
        assert!(removed_unit);
        assert!(!Path::new("/etc/systemd/system/dev-auth-broker.socket").exists());
        assert!(Path::new("/etc/systemd/system/dev-auth-broker-control.socket").exists());
    } else {
        for kind in ["privileged_workload_launcher", "privileged_setup_helper"] {
            let mut changed: RetainedSetupGeneration = serde_json::from_slice(&retained).unwrap();
            changed
                .plan
                .current_paths
                .iter_mut()
                .find(|current| current.kind == kind)
                .unwrap()
                .identity = Some(CurrentFileIdentity {
                object_type: "file".into(),
                owner_uid: 0,
                mode: 0o755,
                link_count: 1,
                length: identity.length,
                sha256: identity.sha256.clone(),
                link_target: None,
            });
            assert!(
                installation_restoration(&changed).is_err(),
                "existing original {kind} is not initial absence"
            );
        }
        for (name, valid, mode) in [
            ("dev-auth-setup-helper", binary.clone(), 0o755),
            ("setup-helper-v1.json", sidecar(&candidate, &paths), 0o644),
        ] {
            let path = paths.data_root.join(name);
            publish(&path, b"unrelated fixture bytes", mode, 0);
            let mut progress = RecoveryProgress::new();
            assert!(restore_owned_inner(InstallMode::Strong, &mut progress, &mut None).is_err());
            assert_eq!(
                crate::setup_transition::retained_transition(&paths, 0)
                    .unwrap()
                    .unwrap()
                    .phase,
                Phase::Pending
            );
            assert_eq!(fs::read(&path).unwrap(), b"unrelated fixture bytes");
            assert!(paths.bin_dir.join("git").exists());
            assert!(Path::new("/run/dev-auth/broker.sock").exists());
            publish(&path, &valid, mode, 0);
        }
    }
    for changed in [true, false] {
        let mut progress = RecoveryProgress::new();
        let mut retry = None;
        let result = restore_owned_inner(InstallMode::Strong, &mut progress, &mut retry)
            .expect("initial strong generation restores its approved absence");
        assert_eq!(result.changed, changed);
        assert!(result.verified);
        assert_eq!(retry, Some(PathBuf::from(&candidate.executable)));
    }
    assert_eq!(launcher.metadata().unwrap().mode() & 0o7777, 0o755);
    assert_eq!(launcher.metadata().unwrap().nlink(), 0);
    let transition = crate::setup_transition::retained_transition(&paths, 0)
        .unwrap()
        .unwrap();
    assert_eq!(transition.phase, Phase::RestoredInactive);
    assert_eq!(transition.bytes, retained);
    for (_, _, path) in crate::setup::installation_current_state_paths(&paths, InstallMode::Strong)
    {
        assert_eq!(
            fs::symlink_metadata(path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }
    for path in [
        PathBuf::from(crate::policy_store::SYSTEM_POLICY_PATH),
        account
            .home
            .join(crate::policy_store::USER_CONFIG_V3_RELATIVE_PATH),
        PathBuf::from("/run/dev-auth/broker.sock"),
        PathBuf::from("/run/dev-auth/control.sock"),
    ] {
        assert_eq!(
            fs::symlink_metadata(path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }
    assert_eq!(
        ArtifactIdentity::from_file(Path::new(&candidate.executable), 256 * 1024 * 1024).unwrap(),
        identity
    );
    assert_eq!(
        fs::read(account.home.join("unrelated")).unwrap(),
        b"unrelated account bytes"
    );
    assert_eq!(
        fs::metadata(account.home.join("unrelated")).unwrap().uid(),
        account.uid
    );
    assert_eq!(restore_setup_v3(InstallMode::Strong).exit_code, 3);
}
