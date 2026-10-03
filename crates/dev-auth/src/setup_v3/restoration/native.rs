//! Full fixed-path composition in an explicitly disposable systemd container.
//! Synthetic release claims exercise retention, not release authentication.
use super::*;
use crate::setup::{InstallMode, InstallReceipt, SetupHelperReceipt, SetupPaths};
use dev_tools_installation::{ArtifactIdentity, VersionedInstallRequest, VersionedLayout};
use std::os::unix::fs::PermissionsExt;

mod initial;

const ALIASES: [&str; 5] = [
    "dev-auth",
    "git-credential-dev-auth",
    "git-dev-auth",
    "gh-dev-auth",
    "ssh-keygen-dev-auth",
];

fn run(executable: &str, arguments: &[&str]) {
    let arguments = arguments
        .iter()
        .map(std::ffi::OsString::from)
        .collect::<Vec<_>>();
    let output = dev_tools_command::run_bounded_command(&dev_tools_command::BoundedCommand {
        executable: Path::new(executable),
        arguments: &arguments,
        environment: &BTreeMap::from([("LC_ALL".into(), "C".into())]),
        cwd: Some(Path::new("/")),
        timeout: std::time::Duration::from_secs(30),
        output_limit: 64 * 1024,
    })
    .unwrap();
    assert!(
        output.status.success(),
        "fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn publish(path: &Path, bytes: &[u8], mode: u32, uid: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    rustix::fs::chownat(
        rustix::fs::CWD,
        path,
        Some(rustix::fs::Uid::from_raw(uid)),
        None,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .unwrap();
    fs::File::open(path).unwrap().sync_all().unwrap();
}

fn sidecar(receipt: &InstallReceipt, paths: &SetupPaths) -> Vec<u8> {
    serde_json::to_vec_pretty(&SetupHelperReceipt {
        schema: "dev-auth-setup-helper-v1".into(),
        protocol: "dev-auth-setup-helper-v1".into(),
        helper_path: paths
            .data_root
            .join("dev-auth-setup-helper")
            .display()
            .to_string(),
        helper_length: receipt.executable_length,
        helper_sha256: receipt.executable_sha256.clone(),
        source_version: receipt.version.clone(),
        source_target: crate::release_manifest::target_id().unwrap(),
        source_commit: receipt.source_commit.clone(),
        root_generation: receipt.root_generation,
        manifest_generation: receipt.manifest_generation,
        active_executable: receipt.executable.clone(),
        active_executable_length: receipt.executable_length,
        active_executable_sha256: receipt.executable_sha256.clone(),
        install_receipt_path: paths
            .data_root
            .join("install-v2.json")
            .display()
            .to_string(),
        install_receipt_schema: receipt.schema.clone(),
    })
    .unwrap()
}

fn policy(users: &[&str]) -> Vec<u8> {
    format!(
        r#"schema = "dev-auth-administrator-policy-v3"
mode = "strong"
allowed_users = {users:?}
[programs]
git = "/usr/bin/true"
gh = "/usr/bin/true"
ssh = "/usr/bin/true"
ssh_keygen = "/usr/bin/true"
[trusted_launchers]
[credentials.providers]
[credentials.credential_slots]
[credentials.resources]
[credentials.resource_caps]
[workload_caps]
"#
    )
    .into_bytes()
}

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_strong_generation_restores_inactive_and_retries() {
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
    // The outer container owner must remove the whole fixture after success,
    // failure or process death. Never adopt a pre-existing product installation.
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
            fs::symlink_metadata(&path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }
    for name in ["dev-auth-retained-alpha", "dev-auth-retained-beta"] {
        assert!(nix::unistd::User::from_name(name).unwrap().is_none());
    }
    run(
        "/usr/sbin/useradd",
        &["--create-home", "--no-log-init", "dev-auth-retained-alpha"],
    );
    run(
        "/usr/sbin/useradd",
        &["--create-home", "--no-log-init", "dev-auth-retained-beta"],
    );
    let accounts = ["dev-auth-retained-alpha", "dev-auth-retained-beta"].map(|name| {
        let user = nix::unistd::User::from_name(name).unwrap().unwrap();
        NativeAccountIdentity {
            name: user.name,
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            home: user.dir,
        }
    });
    for account in &accounts {
        for relative in [
            "",
            ".config",
            ".config/dev-auth",
            ".local",
            ".local/bin",
            ".local/share",
            ".local/share/dev-auth",
            ".local/share/applications",
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
    }
    let root = tempfile::tempdir().unwrap();
    let original_source = root.path().join("prior-source");
    let original_bytes = b"non-executed retained product fixture\n";
    publish(&original_source, original_bytes, 0o755, 0);
    let mut aliases = ALIASES.map(str::to_owned).to_vec();
    aliases.sort();
    let layout = VersionedLayout {
        product: "dev-auth".into(),
        data_root: paths.data_root.clone(),
        bin_dir: paths.bin_dir.clone(),
        artifact_name: "dev-auth".into(),
        owner_uid: 0,
        directory_mode: 0o755,
        bin_directory_mode: None,
    };
    let mut request = VersionedInstallRequest {
        layout,
        version: "0.4.0".into(),
        source: original_source.clone(),
        identity: ArtifactIdentity::from_file(&original_source, 256 * 1024 * 1024).unwrap(),
        aliases,
    };
    dev_tools_installation::apply_versioned_installation(&request, |_| Ok(())).unwrap();
    let mut old_assets = BTreeMap::new();
    for (path, content, mode) in &assets {
        let bytes = if path.extension().is_some_and(|ext| ext == "policy") {
            format!("{content}\n<!-- retained fixture generation -->\n").into_bytes()
        } else {
            format!("{content}\n# retained fixture generation\n").into_bytes()
        };
        publish(path, &bytes, *mode, 0);
        old_assets.insert(path.display().to_string(), sha256_hex(&bytes));
    }
    let prior = InstallReceipt {
        schema: "dev-auth-install-v2".into(),
        mode: InstallMode::Strong,
        version: request.version.clone(),
        executable: paths
            .data_root
            .join("versions/0.4.0/dev-auth")
            .display()
            .to_string(),
        bin_dir: paths.bin_dir.display().to_string(),
        executable_length: request.identity.length,
        executable_sha256: request.identity.sha256.clone(),
        source_commit: Some("a".repeat(40)),
        root_generation: Some(1),
        manifest_generation: Some(1),
        native_git: "/usr/bin/true".into(),
        native_gh: "/usr/bin/true".into(),
        product_aliases: ALIASES.map(str::to_owned).to_vec(),
        transparent_aliases: Vec::new(),
        privileged_launcher: Some(
            paths
                .data_root
                .join("dev-auth-workload-launcher")
                .display()
                .to_string(),
        ),
        system_assets: old_assets,
        previous_release: None,
    };
    let prior_receipt = serde_json::to_vec_pretty(&prior).unwrap();
    let prior_sidecar = sidecar(&prior, &paths);
    publish(
        &paths.data_root.join("install-v2.json"),
        &prior_receipt,
        0o644,
        0,
    );
    publish(
        &paths.data_root.join("dev-auth-workload-launcher"),
        original_bytes,
        0o4755,
        0,
    );
    publish(
        &paths.data_root.join("dev-auth-setup-helper"),
        original_bytes,
        0o755,
        0,
    );
    publish(
        &paths.data_root.join("setup-helper-v1.json"),
        &prior_sidecar,
        0o644,
        0,
    );
    let old_policy = policy(&[&accounts[0].name, &accounts[1].name]);
    let new_policy = policy(&[&accounts[0].name]);
    let old_config = b"schema = \"dev-auth-user-config-v3\"\nworkloads = []\n[authority_profiles]\n# retained configuration\n";
    let new_config = b"schema = \"dev-auth-user-config-v3\"\nworkloads = []\n[authority_profiles]\n# candidate configuration\n";
    publish(
        Path::new(crate::policy_store::SYSTEM_POLICY_PATH),
        &old_policy,
        0o600,
        0,
    );
    for account in &accounts {
        publish(
            &account
                .home
                .join(crate::policy_store::USER_CONFIG_V3_RELATIVE_PATH),
            old_config,
            0o600,
            account.uid,
        );
        crate::setup::reconcile_workload_launchers_at(
            &account.home,
            Path::new(&prior.executable),
            &["owned".into()],
            account.uid,
        )
        .unwrap();
        // Retiring account reproduces the historical root publisher. The
        // desired account retains the corrected native-owner publication.
        if account == &accounts[1] {
            rustix::fs::chownat(
                rustix::fs::CWD,
                account.home.join(".local/bin/owned"),
                Some(rustix::fs::Uid::ROOT),
                None,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .unwrap();
        }
        let desktop_name = "dev-auth-owned.desktop";
        let desktop = b"retained desktop bytes\n";
        publish(
            &account
                .home
                .join(".local/share/applications")
                .join(desktop_name),
            desktop,
            0o644,
            account.uid,
        );
        let receipt = serde_json::to_vec(&crate::setup::DesktopEntryReceipt {
            schema: crate::setup::DESKTOP_ENTRY_RECEIPT_SCHEMA.into(),
            entries: BTreeMap::from([(desktop_name.into(), sha256_hex(desktop))]),
        })
        .unwrap();
        publish(
            &account
                .home
                .join(".local/share/dev-auth/desktop-entries-v1.json"),
            &receipt,
            0o600,
            account.uid,
        );
        publish(
            &account.home.join("unrelated"),
            b"unrelated account file",
            0o600,
            account.uid,
        );
    }
    let source_policy = root.path().join("candidate-policy");
    let source_config = root.path().join("candidate-config");
    publish(&source_policy, &new_policy, 0o600, 0);
    publish(&source_config, new_config, 0o600, 0);
    let candidate_source = std::env::current_exe().unwrap();
    request.version = "0.4.1".into();
    request.source = candidate_source.clone();
    request.identity = ArtifactIdentity::from_file(&candidate_source, 256 * 1024 * 1024).unwrap();
    let installation = SetupPlan {
        schema: "dev-auth-setup-plan-v2".into(),
        paths: paths.clone(),
        request: crate::setup::InstallRequest {
            mode: InstallMode::Strong,
            version: request.version.clone(),
            source_executable: candidate_source.clone(),
            native_git: "/usr/bin/true".into(),
            native_gh: "/usr/bin/true".into(),
            activate_transparent_launchers: false,
        },
        source_length: request.identity.length,
        source_sha256: request.identity.sha256.clone(),
        verified_release: Some(crate::release_manifest::VerifiedDevAuthRelease {
            schema: "dev-auth-verified-release-v1".into(),
            root_path: root.path().join("unavailable-root"),
            manifest_path: root.path().join("unavailable-manifest"),
            root_generation: 1,
            manifest_generation: 2,
            version: request.version.clone(),
            source_commit: "b".repeat(40),
            target: crate::release_manifest::target_id().unwrap(),
            artifact_path: candidate_source,
            artifact_url: "https://example.invalid/fixture".into(),
            artifact_length: request.identity.length,
            artifact_sha256: request.identity.sha256.clone(),
            root_sha256: "c".repeat(64),
            manifest_sha256: "d".repeat(64),
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
            name: accounts[0].name.clone(),
            config: source_config.clone(),
            policy: None,
        }],
        credentials: Vec::new(),
    };
    let (current_paths, ready, broker) = current_state_snapshot(
        &installation,
        &intent,
        &accounts[..1],
        &accounts[1..],
        Some("dev-auth-administrator-policy-v3"),
    )
    .unwrap();
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
            read_document(&source_config, "user_configuration", &accounts[0].name)
                .unwrap()
                .identity,
        ],
        accounts: accounts[..1].to_vec(),
        retiring_accounts: accounts[1..].to_vec(),
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
    dev_tools_installation::apply_versioned_installation(&request, |_| Ok(())).unwrap();
    let generation: RetainedSetupGeneration = serde_json::from_slice(&retained).unwrap();
    let legacy = generation
        .documents
        .iter()
        .find(|object| {
            object.current.kind == "workload_launcher" && object.current.subject == accounts[1].name
        })
        .unwrap();
    assert_eq!(legacy.current.identity.as_ref().unwrap().owner_uid, 0);
    let mut candidate = prior.clone();
    candidate.version = request.version.clone();
    candidate.executable = paths
        .data_root
        .join("versions/0.4.1/dev-auth")
        .display()
        .to_string();
    candidate.executable_length = request.identity.length;
    candidate
        .executable_sha256
        .clone_from(&request.identity.sha256);
    candidate.source_commit = Some("b".repeat(40));
    candidate.manifest_generation = Some(2);
    candidate.system_assets = assets
        .iter()
        .map(|(path, bytes, _)| (path.display().to_string(), sha256_hex(bytes.as_bytes())))
        .collect();
    candidate.previous_release = Some(crate::setup::RetainedRelease {
        version: prior.version.clone(),
        executable_length: prior.executable_length,
        executable_sha256: prior.executable_sha256.clone(),
        source_commit: prior.source_commit.clone(),
        root_generation: prior.root_generation,
        manifest_generation: prior.manifest_generation,
        system_assets: prior.system_assets.clone(),
    });
    let candidate_bytes = fs::read(&candidate.executable).unwrap();
    publish(
        &paths.data_root.join("dev-auth-workload-launcher"),
        &candidate_bytes,
        0o4755,
        0,
    );
    publish(
        &paths.data_root.join("dev-auth-setup-helper"),
        &candidate_bytes,
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
    candidate.transparent_aliases = vec!["git".into(), "gh".into()];
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
        &new_policy,
        0o644,
        0,
    );
    publish(
        &accounts[0]
            .home
            .join(crate::policy_store::USER_CONFIG_V3_RELATIVE_PATH),
        new_config,
        0o600,
        accounts[0].uid,
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
    // This invokes the actual native-owner/lease/direction/composition body,
    // not the public gate, which must remain closed during qualification.
    for changed in [true, false] {
        let mut progress = RecoveryProgress::new();
        let mut retry = None;
        let report = restore_owned_inner(InstallMode::Strong, &mut progress, &mut retry).unwrap();
        assert_eq!(report.changed, changed);
        assert!(report.verified);
        assert_eq!(retry, Some(PathBuf::from(&candidate.executable)));
    }
    let transition = crate::setup_transition::retained_transition(&paths, 0)
        .unwrap()
        .unwrap();
    assert_eq!(transition.phase, Phase::RestoredInactive);
    assert_eq!(transition.bytes, retained);
    let restored: InstallReceipt =
        serde_json::from_slice(&fs::read(paths.data_root.join("install-v2.json")).unwrap())
            .unwrap();
    assert_eq!(restored.version, prior.version);
    assert_eq!(restored.source_commit, prior.source_commit);
    assert_eq!(restored.system_assets, prior.system_assets);
    assert!(restored.transparent_aliases.is_empty());
    assert_eq!(
        restored.previous_release.as_ref().unwrap().version,
        candidate.version
    );
    assert_eq!(
        fs::read(paths.data_root.join("dev-auth-workload-launcher")).unwrap(),
        original_bytes
    );
    assert_eq!(
        fs::metadata(paths.data_root.join("dev-auth-workload-launcher"))
            .unwrap()
            .mode()
            & 0o7777,
        0o4755
    );
    assert_eq!(
        fs::read(paths.data_root.join("dev-auth-setup-helper")).unwrap(),
        original_bytes
    );
    assert_eq!(
        fs::read(paths.data_root.join("setup-helper-v1.json")).unwrap(),
        prior_sidecar
    );
    for document in restoration_documents(&generation).unwrap() {
        document.verify_restored().unwrap();
    }
    for account in &accounts {
        for relative in [
            ".local/bin/owned",
            ".local/share/applications/dev-auth-owned.desktop",
            ".local/share/dev-auth/workload-aliases-v1.json",
            ".local/share/dev-auth/desktop-entries-v1.json",
        ] {
            assert!(fs::symlink_metadata(account.home.join(relative)).is_err());
        }
        assert_eq!(
            fs::read(account.home.join("unrelated")).unwrap(),
            b"unrelated account file"
        );
        assert_eq!(
            fs::metadata(account.home.join("unrelated")).unwrap().uid(),
            account.uid
        );
    }
    for path in ["/run/dev-auth/broker.sock", "/run/dev-auth/control.sock"] {
        assert!(fs::symlink_metadata(path).is_err());
    }
    let retry = restore_setup_v3(InstallMode::Strong);
    assert_eq!(retry.exit_code, 0);
    assert_eq!(retry.changed, Some(false));
    assert!(retry.verified);
    assert_eq!(retry.next_action, "create_setup_plan");
}
