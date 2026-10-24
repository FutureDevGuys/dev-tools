#![cfg(unix)]

use dev_auth::setup::{
    activate_transparent_launchers_at, apply_plan, build_plan, deactivate_transparent_launchers_at,
    install_at, read_plan_at, reconcile_desktop_entries_at, reconcile_workload_launchers_at,
    render_plan, repair_at, rollback_at, setup_readiness_at,
    transparent_launchers_resolve_first_at, uninstall_at, verify_at, verify_user_integrations_at,
    write_plan_at, write_v1_migration_preview_at, InstallMode, InstallRequest, SetupPaths,
};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::process::Command;

fn executable(path: &std::path::Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn fixture() -> (tempfile::TempDir, SetupPaths, InstallRequest) {
    let root = tempfile::Builder::new()
        .prefix("dev-auth-setup-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let native = root.path().join("native");
    let home = root.path().join("home");
    fs::create_dir(&native).unwrap();
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&native, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let source = native.join("dev-auth-candidate");
    let git = native.join("git");
    let gh = native.join("gh");
    executable(&source, "candidate-v0.3");
    executable(&git, "native-git");
    executable(&gh, "native-gh");
    let paths = SetupPaths::user_only(&home);
    let request = InstallRequest {
        purpose: Default::default(),
        mode: InstallMode::UserOnly,
        version: "0.3.0-test".into(),
        source_executable: source,
        native_git: git,
        native_gh: gh,
        activate_transparent_launchers: false,
    };
    (root, paths, request)
}

#[test]
fn build_info_is_machine_readable_and_names_exact_source_when_embedded() {
    let output = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .arg("build-info")
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["product"], "dev-auth");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert!(
        value["source_commit"].is_null() || value["source_commit"].as_str().unwrap().len() == 40
    );
}

#[test]
fn privilege_only_binary_plan_has_no_native_git_or_gh_authority() {
    let (_root, _paths, mut request) = fixture();
    request.purpose = dev_auth::deployment::SetupPurpose::PrivilegeOnly;
    request.mode = InstallMode::Strong;
    request.version = "0.5.0".into();
    request.native_git = Default::default();
    request.native_gh = Default::default();
    let plan = build_plan(&SetupPaths::strong(), &request).unwrap();
    assert_eq!(plan.schema, "dev-auth-setup-binary-plan-v3");
    assert!(plan.request.native_git.as_os_str().is_empty());
    assert!(plan.request.native_gh.as_os_str().is_empty());
    request.native_git = "/unconfigured-native-program-must-not-be-consulted".into();
    assert!(build_plan(&SetupPaths::strong(), &request).is_err());
    request.native_git = Default::default();
    request.mode = InstallMode::UserOnly;
    assert!(build_plan(&SetupPaths::strong(), &request).is_err());
}

#[test]
fn standalone_setup_installs_every_product_alias_before_same_name_activation() {
    let (_root, paths, request) = fixture();
    let report = install_at(&paths, &request).unwrap();
    assert!(report.product_aliases_ready);
    assert!(!report.transparent_launchers_active);
    for alias in [
        "dev-auth",
        "git-credential-dev-auth",
        "git-dev-auth",
        "gh-dev-auth",
        "ssh-keygen-dev-auth",
    ] {
        assert!(fs::symlink_metadata(paths.bin_dir.join(alias))
            .unwrap()
            .file_type()
            .is_symlink());
    }
    assert!(!paths.bin_dir.join("git").exists());
    assert!(!paths.bin_dir.join("gh").exists());
    assert_eq!(verify_at(&paths).unwrap(), report);
}

#[test]
fn setup_discovery_is_value_free_and_never_trusts_caller_path() {
    let output = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .args(["setup", "discover", "--mode", "user-only"])
        .env("PATH", "/tmp/attacker-bin")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "dev-auth-setup-discovery-v1");
    assert_eq!(report["mode"], "user_only");
    assert_eq!(report["programs"]["git"][0]["path"], "/usr/bin/git");
    assert_eq!(report["programs"]["op"][0]["path"], "/usr/bin/op");
    assert!(report["blockers"].is_array());
    for blocker in report["blockers"].as_array().unwrap() {
        assert!(blocker["component"].as_str().is_some());
        assert!(blocker["required_for"].as_str().is_some());
        assert!(blocker["package_hints"].is_object());
    }
    assert!(!String::from_utf8(output.stdout)
        .unwrap()
        .contains("attacker-bin"));
}

#[test]
fn setup_owns_transparent_git_and_gh_and_deactivation_removes_them_first() {
    let (_root, paths, request) = fixture();
    let installed = install_at(&paths, &request).unwrap();
    assert!(!installed.transparent_launchers_active);
    let report = activate_transparent_launchers_at(&paths).unwrap();
    assert!(report.transparent_launchers_active);
    for alias in ["git", "gh"] {
        assert!(fs::symlink_metadata(paths.bin_dir.join(alias))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    let deactivated = deactivate_transparent_launchers_at(&paths).unwrap();
    assert!(!deactivated.transparent_launchers_active);
    assert!(!paths.bin_dir.join("git").exists());
    assert!(!paths.bin_dir.join("gh").exists());
    assert!(paths.bin_dir.join("dev-auth").exists());
}

#[test]
fn rollback_removes_same_name_routing_but_preserves_the_reversible_installation() {
    let (_root, paths, mut request) = fixture();
    request.activate_transparent_launchers = true;
    install_at(&paths, &request).unwrap();

    let report = rollback_at(&paths).unwrap();
    assert!(!report.transparent_launchers_active);
    assert!(!paths.bin_dir.join("git").exists());
    assert!(!paths.bin_dir.join("gh").exists());
    assert!(paths.bin_dir.join("dev-auth").exists());
    assert!(paths.data_root.join("install-v2.json").exists());
    assert!(std::path::Path::new(&report.executable).exists());
}

#[test]
fn binary_only_rollback_cannot_bypass_a_full_setup_generation() {
    for phase in ["pending", "accepted"] {
        let (_root, paths, mut request) = fixture();
        request.activate_transparent_launchers = true;
        install_at(&paths, &request).unwrap();
        let transition = paths.data_root.join("setup-transition-v1.json");
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": "dev-auth-setup-transition-v1",
            "plan_sha256": "a".repeat(64),
            "phase": phase,
            "retained_generation": {"length": 1, "sha256": "b".repeat(64)}
        }))
        .unwrap();
        fs::write(&transition, &bytes).unwrap();
        fs::set_permissions(&transition, fs::Permissions::from_mode(0o600)).unwrap();
        let receipt_path = paths.data_root.join("install-v2.json");
        let receipt_before = fs::read(&receipt_path).unwrap();
        let alias_before = fs::read_link(paths.bin_dir.join("git")).unwrap();

        let result = rollback_at(&paths);
        assert!(
            result.is_err(),
            "binary rollback bypassed {phase} full setup"
        );
        assert_eq!(fs::read(&receipt_path).unwrap(), receipt_before);
        assert_eq!(
            fs::read_link(paths.bin_dir.join("git")).unwrap(),
            alias_before
        );
        assert_eq!(fs::read(&transition).unwrap(), bytes);
    }
}

#[test]
fn rollback_switches_to_the_retained_release_and_is_resume_safe() {
    let (root, paths, mut request) = fixture();
    request.version = "0.3.0-old".into();
    request.activate_transparent_launchers = true;
    let old_source = request.source_executable.clone();
    executable(&old_source, "candidate-v0.3-old");
    let old = install_at(&paths, &request).unwrap();
    deactivate_transparent_launchers_at(&paths).unwrap();

    let new_source = root.path().join("native/dev-auth-new");
    executable(&new_source, "candidate-v0.3-new");
    request.version = "0.3.1-new".into();
    request.source_executable = new_source;
    request.activate_transparent_launchers = false;
    let new = install_at(&paths, &request).unwrap();
    assert_eq!(new.version, "0.3.1-new");

    let rolled_back = rollback_at(&paths).unwrap();
    assert_eq!(rolled_back.version, old.version);
    assert_eq!(rolled_back.executable, old.executable);
    assert!(!rolled_back.transparent_launchers_active);
    assert_eq!(
        fs::read_link(paths.bin_dir.join("dev-auth")).unwrap(),
        paths.data_root.join("active")
    );
    assert_eq!(
        fs::canonicalize(paths.bin_dir.join("dev-auth")).unwrap(),
        fs::canonicalize(old.executable).unwrap()
    );

    let restored = rollback_at(&paths).unwrap();
    assert_eq!(restored.version, new.version);
    assert_eq!(restored.executable, new.executable);
    assert!(!restored.transparent_launchers_active);
}

#[test]
fn uninstall_removes_only_receipted_product_files_and_preserves_native_tools() {
    let (_root, paths, mut request) = fixture();
    request.activate_transparent_launchers = true;
    let native_git = request.native_git.clone();
    let native_gh = request.native_gh.clone();
    install_at(&paths, &request).unwrap();

    let report = uninstall_at(&paths).unwrap();
    assert_eq!(report.schema, "dev-auth-uninstall-report-v1");
    assert!(report.preserved_policy);
    assert!(report.preserved_credential);
    assert!(!paths.data_root.exists());
    for alias in [
        "git",
        "gh",
        "dev-auth",
        "git-credential-dev-auth",
        "git-dev-auth",
        "gh-dev-auth",
        "ssh-keygen-dev-auth",
    ] {
        assert!(!paths.bin_dir.join(alias).exists());
    }
    assert!(native_git.exists());
    assert!(native_gh.exists());
}

#[test]
fn setup_never_replaces_unowned_same_name_tools() {
    let (_root, paths, mut request) = fixture();
    fs::create_dir_all(&paths.bin_dir).unwrap();
    fs::set_permissions(&paths.bin_dir, fs::Permissions::from_mode(0o700)).unwrap();
    executable(&paths.bin_dir.join("git"), "unowned-git");
    request.activate_transparent_launchers = true;
    assert!(install_at(&paths, &request).is_err());
    assert_eq!(fs::read(paths.bin_dir.join("git")).unwrap(), b"unowned-git");
}

#[test]
fn verification_and_deactivation_refuse_alias_drift() {
    let (root, paths, mut request) = fixture();
    request.activate_transparent_launchers = true;
    install_at(&paths, &request).unwrap();
    let alias = paths.bin_dir.join("git");
    fs::remove_file(&alias).unwrap();
    symlink(root.path().join("native/git"), &alias).unwrap();
    assert!(verify_at(&paths).is_err());
    assert!(deactivate_transparent_launchers_at(&paths).is_err());
    assert_eq!(
        fs::read_link(alias).unwrap(),
        root.path().join("native/git")
    );
}

#[test]
fn setup_is_idempotent_for_the_exact_versioned_artifact() {
    let (_root, paths, request) = fixture();
    let first = install_at(&paths, &request).unwrap();
    let second = install_at(&paths, &request).unwrap();
    assert_eq!(first, second);
}

#[test]
fn setup_adopts_the_validated_legacy_layout_and_retains_it_for_rollback() {
    use sha2::{Digest, Sha256};

    let (_root, paths, request) = fixture();
    let legacy_version = "0.2.8";
    let legacy = paths
        .data_root
        .join("versions")
        .join(legacy_version)
        .join("dev-auth");
    fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    fs::create_dir_all(&paths.bin_dir).unwrap();
    for directory in [
        &paths.data_root,
        &paths.data_root.join("versions"),
        legacy.parent().unwrap(),
        &paths.bin_dir,
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let bytes = fs::read(&request.source_executable).unwrap();
    fs::write(&legacy, &bytes).unwrap();
    fs::set_permissions(&legacy, fs::Permissions::from_mode(0o755)).unwrap();
    let product_aliases = [
        "dev-auth",
        "git-credential-dev-auth",
        "git-dev-auth",
        "gh-dev-auth",
        "ssh-keygen-dev-auth",
    ];
    for alias in product_aliases {
        symlink(&legacy, paths.bin_dir.join(alias)).unwrap();
    }
    let receipt = serde_json::json!({
        "schema": "dev-auth-install-v2",
        "mode": "user_only",
        "version": legacy_version,
        "executable": legacy,
        "bin_dir": paths.bin_dir,
        "executable_length": bytes.len(),
        "executable_sha256": format!("{:x}", Sha256::digest(&bytes)),
        "source_commit": null,
        "root_generation": null,
        "manifest_generation": null,
        "native_git": request.native_git,
        "native_gh": request.native_gh,
        "product_aliases": product_aliases,
        "transparent_aliases": [],
        "privileged_launcher": null,
        "system_assets": {}
    });
    let receipt_path = paths.data_root.join("install-v2.json");
    fs::write(&receipt_path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
    fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600)).unwrap();

    let report = install_at(&paths, &request).unwrap();
    assert_eq!(report.version, request.version);
    let shared = dev_tools_installation::verify_versioned_installation(
        &dev_tools_installation::VersionedLayout {
            product: "dev-auth".into(),
            data_root: paths.data_root.clone(),
            bin_dir: paths.bin_dir.clone(),
            artifact_name: "dev-auth".into(),
            owner_uid: fs::metadata(paths.data_root.parent().unwrap())
                .unwrap()
                .uid(),
            directory_mode: 0o755,
            bin_directory_mode: None,
        },
    )
    .unwrap();
    assert_eq!(shared.active_version, request.version);
    assert_eq!(shared.previous_version.as_deref(), Some(legacy_version));
    assert_eq!(
        fs::read_link(paths.bin_dir.join("dev-auth")).unwrap(),
        paths.data_root.join("active")
    );
}

#[test]
fn repair_reconstructs_only_receipt_owned_aliases() {
    let (_root, paths, request) = fixture();
    let installed = install_at(&paths, &request).unwrap();
    let alias = paths.bin_dir.join("gh-dev-auth");
    fs::remove_file(&alias).unwrap();

    assert_eq!(repair_at(&paths).unwrap(), installed);
    assert_eq!(
        fs::read_link(&alias).unwrap(),
        paths.data_root.join("active")
    );

    fs::remove_file(&alias).unwrap();
    executable(&alias, "unowned");
    assert!(repair_at(&paths).is_err());
    assert_eq!(fs::read(&alias).unwrap(), b"unowned");
}

#[test]
fn repair_keeps_receipted_artifact_authority_when_bytes_have_changed() {
    let (_root, paths, request) = fixture();
    let installed = install_at(&paths, &request).unwrap();
    let receipt_path = paths.data_root.join("install-v2.json");
    let receipt = fs::read(&receipt_path).unwrap();
    let alias = paths.bin_dir.join("dev-auth");
    fs::remove_file(&alias).unwrap();
    fs::write(&installed.executable, b"changed candidate").unwrap();
    assert!(repair_at(&paths).is_err());
    assert!(fs::symlink_metadata(&alias).is_err());
    assert_eq!(fs::read(&receipt_path).unwrap(), receipt);
    assert_eq!(
        fs::read(&installed.executable).unwrap(),
        b"changed candidate"
    );
}

#[test]
fn failed_artifact_identity_never_leaves_a_published_version() {
    let (_root, paths, request) = fixture();
    let source = request.source_executable.clone();
    let original = fs::read(&source).unwrap();
    let plan = build_plan(&paths, &request).unwrap();
    let (_, digest) = render_plan(&plan).unwrap();
    fs::write(&source, b"different-candidate").unwrap();
    assert!(apply_plan(&plan, &digest).is_err());
    assert!(!paths
        .data_root
        .join("versions/0.3.0-test/dev-auth")
        .exists());
    fs::write(source, original).unwrap();
}

#[test]
fn unattended_setup_requires_the_exact_public_plan_and_source_artifact() {
    let (_root, paths, request) = fixture();
    let plan = build_plan(&paths, &request).unwrap();
    let (_, digest) = render_plan(&plan).unwrap();
    assert!(apply_plan(&plan, &"0".repeat(64)).is_err());

    let mut altered = plan.clone();
    altered.request.activate_transparent_launchers = true;
    assert!(apply_plan(&altered, &digest).is_err());

    fs::write(&request.source_executable, "different-candidate").unwrap();
    assert!(apply_plan(&plan, &digest).is_err());
}

#[test]
fn public_plan_file_is_strict_private_and_round_trips() {
    let (root, paths, request) = fixture();
    let plan = build_plan(&paths, &request).unwrap();
    let path = root.path().join("setup-plan.json");
    let digest = write_plan_at(&path, &plan).unwrap();
    assert_eq!(read_plan_at(&path).unwrap(), plan);
    assert_eq!(render_plan(&plan).unwrap().1, digest);
    assert_eq!(
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn setup_plan_rejects_a_forged_authenticated_release_claim() {
    let (_root, paths, request) = fixture();
    let mut plan = build_plan(&paths, &request).unwrap();
    plan.verified_release = Some(dev_auth::release_manifest::VerifiedDevAuthRelease {
        schema: "dev-auth-verified-release-v1".into(),
        root_path: std::path::PathBuf::from("/tmp/dev-auth-root-fixture"),
        manifest_path: std::path::PathBuf::from("/tmp/dev-auth-manifest-fixture"),
        root_generation: 1,
        manifest_generation: 2,
        version: request.version.clone(),
        source_commit: "a".repeat(40),
        target: "linux-x86_64".into(),
        artifact_path: request.source_executable.clone(),
        artifact_url: "https://github.com/FutureDevGuys/dev-tools/releases/download/dev-auth%2Fv0.3.0-test/dev-auth-0.3.0-test-linux-x86_64".into(),
        artifact_length: plan.source_length,
        artifact_sha256: plan.source_sha256.clone(),
        root_sha256: "b".repeat(64),
        manifest_sha256: "c".repeat(64),
    });
    assert!(render_plan(&plan).is_err());
}

#[test]
fn v1_migration_preview_is_read_only_private_and_never_exports_secret_references() {
    let (root, _paths, _request) = fixture();
    let source = root.path().join("config-v1.toml");
    fs::write(&source, include_bytes!("../config.example.toml")).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
    let owner_uid = std::os::unix::fs::MetadataExt::uid(&fs::symlink_metadata(&source).unwrap());
    let before = fs::read(&source).unwrap();

    let preview = dev_auth::setup::preview_v1_migration_at(&source, owner_uid).unwrap();
    assert_eq!(preview.schema, "dev-auth-v1-migration-preview-v1");
    assert_eq!(preview.source_path, source.display().to_string());
    assert!(preview
        .unresolved
        .iter()
        .any(|value| value.contains("workload")));
    assert_eq!(fs::read(&source).unwrap(), before);

    let output = root.path().join("migration-preview.json");
    let digest = write_v1_migration_preview_at(&output, &preview).unwrap();
    assert_eq!(digest.len(), 64);
    let rendered = fs::read_to_string(&output).unwrap();
    assert!(!rendered.contains("op://"));
    assert!(!rendered.contains("private-key"));
    assert_eq!(
        fs::symlink_metadata(output).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn setup_cli_never_treats_a_binary_install_plan_as_full_desired_state() {
    let (_root, paths, request) = fixture();
    let plan = build_plan(&paths, &request).unwrap();
    let plan_path = paths.data_root.parent().unwrap().join("approved-plan.json");
    fs::create_dir_all(plan_path.parent().unwrap()).unwrap();
    let digest = write_plan_at(&plan_path, &plan).unwrap();

    let rejected = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .args([
            "setup",
            "apply",
            "--plan",
            plan_path.to_str().unwrap(),
            "--sha256",
            &"0".repeat(64),
        ])
        .status()
        .unwrap();
    assert!(!rejected.success());

    let rejected_even_with_the_matching_digest = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .args([
            "setup",
            "apply",
            "--plan",
            plan_path.to_str().unwrap(),
            "--sha256",
            &digest,
        ])
        .output()
        .unwrap();
    assert!(
        !rejected_even_with_the_matching_digest.status.success(),
        "{}",
        String::from_utf8_lossy(&rejected_even_with_the_matching_digest.stderr)
    );
    assert!(
        String::from_utf8_lossy(&rejected_even_with_the_matching_digest.stderr)
            .contains("setup apply accepts only a full setup plan")
    );
}

#[cfg(target_os = "linux")]
const FIXTURE_OPERATOR: &str = "fixture-operator";

/// A user-only plan for the effective native account that a newer release
/// rendered for `candidate`: it carries a component and an action that this
/// release does not know.
#[cfg(target_os = "linux")]
fn newer_candidate_plan(root: &std::path::Path, candidate: &std::path::Path) -> Vec<u8> {
    use dev_auth::deployment::{
        canonical_deployment_intent, Activation, Channel, DeploymentIntent, DeploymentMode,
        DeploymentUser,
    };
    use dev_auth::setup::SetupPlan;
    use dev_auth::setup_v3::{
        planned_action_contract, DocumentIdentity, NativeAccountIdentity, SetupPlanV3,
    };
    use sha2::{Digest, Sha256};

    let sha256 = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    let home = root.join("home");
    let intent = DeploymentIntent {
        purpose: Default::default(),
        schema: "dev-auth-deployment-intent-v1".into(),
        mode: DeploymentMode::UserOnly,
        channel: Channel::Stable,
        offline: true,
        activation: Activation::Inactive,
        administrator_policy: root.join("policy.toml"),
        grant_policy: None,
        users: vec![DeploymentUser {
            name: user.name.clone(),
            config: root.join("config.toml"),
            policy: None,
        }],
        credentials: Vec::new(),
        bindings: Vec::new(),
    };
    let candidate_bytes = fs::read(candidate).unwrap();
    let mut actions = planned_action_contract(&intent);
    let verify = actions.pop().unwrap();
    actions.push(dev_auth::setup_v3::SetupActionV3 {
        order: actions.len() as u32,
        kind: "install_future_component".into(),
        subject: None,
    });
    actions.push(dev_auth::setup_v3::SetupActionV3 {
        order: actions.len() as u32,
        ..verify
    });
    let plan = SetupPlanV3 {
        credential_preservation: None,
        grant_previous_block: None,
        grant_current_state: None,
        grant_payload: Default::default(),
        authority_schema: None,
        schema: "dev-auth-setup-plan-v3".into(),
        intent_sha256: sha256(&canonical_deployment_intent(&intent).unwrap()),
        installation: SetupPlan {
            schema: "dev-auth-setup-plan-v2".into(),
            paths: SetupPaths::user_only(&home),
            request: InstallRequest {
                purpose: Default::default(),
                mode: InstallMode::UserOnly,
                version: "99.0.0".into(),
                source_executable: candidate.into(),
                native_git: root.join("git"),
                native_gh: root.join("gh"),
                activate_transparent_launchers: false,
            },
            source_length: candidate_bytes.len() as u64,
            source_sha256: sha256(&candidate_bytes),
            verified_release: None,
        },
        source_documents: vec![DocumentIdentity {
            kind: "administrator_policy".into(),
            subject: "system".into(),
            path: intent.administrator_policy.clone(),
            length: 1,
            sha256: "b".repeat(64),
        }],
        accounts: vec![NativeAccountIdentity {
            name: user.name,
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            home,
        }],
        retiring_accounts: Vec::new(),
        intent,
        current_paths: Vec::new(),
        current_credential_ready: Default::default(),
        current_broker_state: "inactive".into(),
        current_state_sha256: "c".repeat(64),
        actions,
    };
    let mut plan = serde_json::to_value(plan).unwrap();
    plan["future_component"] = serde_json::json!({"schema": "dev-auth-future-component-v1"});
    serde_jcs::to_vec(&plan).unwrap()
}

#[cfg(target_os = "linux")]
#[test]
fn installed_release_hands_a_newer_candidates_plan_to_it_without_judging_its_contract() {
    use sha2::{Digest, Sha256};

    let root = tempfile::tempdir().unwrap();
    let record = root.path().join("handoff.log");
    let candidate = root.path().join("candidate");
    executable(
        &candidate,
        &format!(
            "#!/bin/sh\n{{ printf 'arg=%s\\n' \"$@\"; printf 'cwd=%s\\n' \"$(pwd)\"; printf 'sentinel=%s\\n' \"${{DEV_AUTH_HANDOFF_SENTINEL-unset}}\"; }} > '{}'\n",
            record.display()
        ),
    );
    let plan = root.path().join("setup-plan.json");
    let bytes = newer_candidate_plan(root.path(), &candidate);
    fs::write(&plan, &bytes).unwrap();
    fs::set_permissions(&plan, fs::Permissions::from_mode(0o600)).unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));

    for operation in ["apply", "verify"] {
        let _ = fs::remove_file(&record);
        let output = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args(["setup", operation, "--plan"])
            .arg(&plan)
            .args(["--sha256", &digest, "--format", "json"])
            .env("DEV_AUTH_HANDOFF_SENTINEL", "inherited")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "setup {operation} did not reach its candidate: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(&record).unwrap(),
            format!(
                "arg=setup\narg={operation}\narg=--plan\narg={}\narg=--sha256\narg={digest}\narg=--format\narg=json\ncwd=/\nsentinel=unset\n",
                plan.display()
            ),
            "setup {operation} handed off with different arguments or environment"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn a_plan_is_never_handed_to_a_candidate_it_does_not_authenticate() {
    use sha2::{Digest, Sha256};

    let root = tempfile::tempdir().unwrap();
    let record = root.path().join("handoff.log");
    let candidate = root.path().join("candidate");
    executable(
        &candidate,
        &format!("#!/bin/sh\ntouch '{}'\n", record.display()),
    );
    let newer: serde_json::Value =
        serde_json::from_slice(&newer_candidate_plan(root.path(), &candidate)).unwrap();
    let mut changed_candidate = newer.clone();
    changed_candidate["installation"]["source_sha256"] = "0".repeat(64).into();
    let mut strong_without_release = newer.clone();
    strong_without_release["intent"]["mode"] = "strong".into();
    strong_without_release["installation"]["request"]["mode"] = "strong".into();
    let mut mismatched_modes = newer.clone();
    mismatched_modes["installation"]["request"]["mode"] = "strong".into();
    let plan = root.path().join("setup-plan.json");
    for (case, document, approve_other_bytes) in [
        ("another digest", &newer, true),
        ("changed candidate", &changed_candidate, false),
        (
            "strong plan without a release",
            &strong_without_release,
            false,
        ),
        ("mismatched modes", &mismatched_modes, false),
    ] {
        let bytes = serde_jcs::to_vec(document).unwrap();
        fs::write(&plan, &bytes).unwrap();
        fs::set_permissions(&plan, fs::Permissions::from_mode(0o600)).unwrap();
        let approved = if approve_other_bytes {
            [bytes.as_slice(), b" "].concat()
        } else {
            bytes
        };
        let digest = format!("{:x}", Sha256::digest(&approved));
        for operation in ["apply", "verify"] {
            let output = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
                .args(["setup", operation, "--plan"])
                .arg(&plan)
                .args(["--sha256", &digest, "--format", "json"])
                .env_clear()
                .output()
                .unwrap();
            assert!(
                !output.status.success(),
                "setup {operation} accepted the {case} plan"
            );
            assert!(
                !record.exists(),
                "setup {operation} handed the {case} plan to its candidate"
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn this_release_names_itself_as_the_release_to_plan_with_for_an_older_planners_plan() {
    use dev_auth::setup_v3::planned_action_contract;
    use sha2::{Digest, Sha256};

    let root = tempfile::tempdir().unwrap();
    let this_release = std::path::Path::new(env!("CARGO_BIN_EXE_dev-auth"));
    let mut plan: serde_json::Value =
        serde_json::from_slice(&newer_candidate_plan(root.path(), this_release)).unwrap();
    plan.as_object_mut().unwrap().remove("future_component");
    let version = env!("CARGO_PKG_VERSION");
    plan["installation"]["request"]["version"] = version.into();
    let intent = serde_json::from_value(plan["intent"].clone()).unwrap();
    let mut older_actions = planned_action_contract(&intent);
    older_actions.remove(0);
    for (order, action) in older_actions.iter_mut().enumerate() {
        action.order = order as u32;
    }
    plan["actions"] = serde_json::to_value(older_actions).unwrap();
    plan["current_state_sha256"] = format!(
        "{:x}",
        Sha256::digest(
            serde_jcs::to_vec(&serde_json::json!({
                "files": plan["current_paths"],
                "credential_ready": plan["current_credential_ready"],
                "broker": plan["current_broker_state"],
            }))
            .unwrap()
        )
    )
    .into();
    let bytes = serde_jcs::to_vec(&plan).unwrap();
    let path = root.path().join("setup-plan.json");
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));

    for operation in ["apply", "verify"] {
        let output = Command::new(this_release)
            .args(["setup", operation, "--plan"])
            .arg(&path)
            .args(["--sha256", &digest, "--format", "json"])
            .env_clear()
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "setup {operation} accepted the plan"
        );
        assert!(output.stdout.is_empty());
        let diagnostic = String::from_utf8(output.stderr).unwrap();
        for expected in [
            format!("setup {operation} accepts only a full setup plan: setup plan was not rendered by Dev Auth {version}, the release it installs: its action contract differs"),
            format!("regenerate it with the Dev Auth {version} candidate's `dev-auth setup plan`"),
        ] {
            assert!(diagnostic.contains(&expected), "{expected:?} is absent from {diagnostic:?}");
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn a_release_never_renders_a_setup_plan_for_another_release() {
    use dev_auth::deployment::{
        Activation, Channel, DeploymentIntent, DeploymentMode, DeploymentUser,
    };

    let root = tempfile::tempdir().unwrap();
    let intent = DeploymentIntent {
        purpose: Default::default(),
        schema: "dev-auth-deployment-intent-v1".into(),
        mode: DeploymentMode::UserOnly,
        channel: Channel::Stable,
        offline: true,
        activation: Activation::Inactive,
        administrator_policy: root.path().join("policy.toml"),
        grant_policy: None,
        users: vec![DeploymentUser {
            name: FIXTURE_OPERATOR.into(),
            config: root.path().join("config.toml"),
            policy: None,
        }],
        credentials: Vec::new(),
        bindings: Vec::new(),
    };
    let release = dev_auth::release_manifest::VerifiedDevAuthRelease {
        schema: "dev-auth-verified-release-v1".into(),
        root_path: root.path().join("root.json"),
        manifest_path: root.path().join("manifest.json"),
        root_generation: 1,
        manifest_generation: 1,
        version: "0.5.7".into(),
        source_commit: "d".repeat(40),
        target: "linux-x86_64".into(),
        artifact_path: root.path().join("artifact"),
        artifact_url: "https://github.com/FutureDevGuys/dev-tools/releases/download/dev-auth%2Fv0.5.7/dev-auth-0.5.7-linux-x86_64".into(),
        artifact_length: 1,
        artifact_sha256: "e".repeat(64),
        root_sha256: "f".repeat(64),
        manifest_sha256: "0".repeat(64),
    };
    let error =
        dev_auth::setup_v3::build_setup_plan_v3_for_verified_release(intent, release).unwrap_err();
    let error = format!("{error:#}");
    for expected in [
        format!(
            "Dev Auth {} cannot render the setup plan for Dev Auth 0.5.7",
            env!("CARGO_PKG_VERSION")
        ),
        "run `dev-auth setup plan` from the Dev Auth 0.5.7 candidate".to_owned(),
    ] {
        assert!(
            error.contains(&expected),
            "{expected:?} is absent from {error:?}"
        );
    }
}

#[test]
fn strong_setup_owns_hardened_socket_activated_service_assets() {
    let assets = dev_auth::setup::linux_system_assets();
    assert_eq!(assets.len(), 5);
    let combined = assets
        .iter()
        .map(|(path, content, _)| format!("{}\n{content}", path.display()))
        .collect::<String>();
    assert!(combined.contains("/run/dev-auth/broker.sock"));
    assert!(combined.contains("/run/dev-auth/control.sock"));
    assert!(combined.contains("SocketMode=0666"));
    assert!(combined.contains("SocketMode=0600"));
    assert!(combined.contains("User=dev-auth"));
    assert!(!combined.contains("dev-auth-workload -"));
    assert!(combined.contains("LoadCredentialEncrypted=op-service-account-token:"));
    assert!(combined.contains("RuntimeDirectory=dev-auth-provider"));
    assert!(combined.contains("RuntimeDirectoryMode=0700"));
    assert!(combined.contains("Environment=HOME=/run/dev-auth-provider"));
    assert!(combined.contains("ProtectSystem=strict"));
    assert!(combined.contains("ExecStart=/usr/local/bin/dev-auth broker serve"));
    assert!(combined.contains("com.futuredevguys.dev-auth.launch-workload"));
    assert!(combined.contains(
        "org.freedesktop.policykit.exec.path\">/usr/local/lib/dev-auth/dev-auth-workload-launcher"
    ));
    assert!(combined.contains("<allow_active>auth_self</allow_active>"));
    assert!(!combined.contains("<allow_active>yes</allow_active>"));
    assert!(combined.contains("<allow_inactive>no</allow_inactive>"));
    assert!(combined.contains("<allow_any>no</allow_any>"));
}

#[test]
fn dedicated_privileged_launcher_never_exposes_the_administrative_cli() {
    let root = tempfile::tempdir().unwrap();
    let launcher = root.path().join("dev-auth-workload-launcher");
    fs::copy(env!("CARGO_BIN_EXE_dev-auth"), &launcher).unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(launcher)
        .args(["setup", "verify"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("supervisor"));
    assert!(!stderr.contains("setup directory"));
}

#[test]
fn setup_reconciles_generic_same_name_workload_launchers_without_overwriting_user_tools() {
    let (root, paths, request) = fixture();
    let report = install_at(&paths, &request).unwrap();
    let installed_executable = std::path::PathBuf::from(report.executable);
    let owner_uid =
        std::os::unix::fs::MetadataExt::uid(&fs::symlink_metadata(root.path()).unwrap());
    let home = root.path().join("workload-home");
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();

    reconcile_workload_launchers_at(
        &home,
        &installed_executable,
        &["claude".into(), "codex".into()],
        owner_uid,
    )
    .unwrap();
    for alias in ["claude", "codex"] {
        assert_eq!(
            fs::read_link(home.join(".local/bin").join(alias)).unwrap(),
            installed_executable
        );
    }

    reconcile_workload_launchers_at(&home, &installed_executable, &["codex".into()], owner_uid)
        .unwrap();
    assert!(!home.join(".local/bin/claude").exists());
    executable(&home.join(".local/bin/claude"), "unowned");
    assert!(reconcile_workload_launchers_at(
        &home,
        &installed_executable,
        &["claude".into(), "codex".into()],
        owner_uid,
    )
    .is_err());
    assert_eq!(
        fs::read(home.join(".local/bin/claude")).unwrap(),
        b"unowned"
    );
}

#[test]
fn setup_generates_generic_receipted_desktop_workload_entries() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let owner_uid =
        std::os::unix::fs::MetadataExt::uid(&fs::symlink_metadata(root.path()).unwrap());
    let policy = dev_auth::policy_v2::parse_system_policy_v2(include_bytes!(
        "../policy-v2-user-only.example.toml"
    ))
    .unwrap();
    let config =
        dev_auth::policy_v2::parse_user_config_v2(include_bytes!("../config-v2.example.toml"))
            .unwrap();
    let resolved = dev_auth::policy_v2::resolve_policy(&policy, &config).unwrap();

    reconcile_desktop_entries_at(root.path(), &resolved.workloads, owner_uid).unwrap();
    let entry = root
        .path()
        .join(".local/share/applications/dev-auth-automation-agent.desktop");
    let content = fs::read_to_string(&entry).unwrap();
    assert!(content.contains("Name=Automation Agent"));
    assert!(content.contains("X-Dev-Auth-Workload=automation-agent"));
    assert!(content.contains(&format!(
        "Exec=\"{}/.local/bin/automation-agent\"",
        root.path().display()
    )));
    assert_eq!(
        fs::symlink_metadata(&entry).unwrap().permissions().mode() & 0o777,
        0o644
    );

    fs::write(&entry, "user modified").unwrap();
    assert!(reconcile_desktop_entries_at(
        root.path(),
        &std::collections::BTreeMap::new(),
        owner_uid
    )
    .is_err());
    assert_eq!(fs::read_to_string(entry).unwrap(), "user modified");
}

#[test]
fn setup_verifies_exact_workload_and_desktop_integrations_without_reconciling_them() {
    let (root, paths, request) = fixture();
    let report = install_at(&paths, &request).unwrap();
    let installed_executable = std::path::PathBuf::from(report.executable);
    let owner_uid =
        std::os::unix::fs::MetadataExt::uid(&fs::symlink_metadata(root.path()).unwrap());
    let home = root.path().join("integration-home");
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let policy = dev_auth::policy_v2::parse_system_policy_v2(include_bytes!(
        "../policy-v2-user-only.example.toml"
    ))
    .unwrap();
    let config =
        dev_auth::policy_v2::parse_user_config_v2(include_bytes!("../config-v2.example.toml"))
            .unwrap();
    let resolved = dev_auth::policy_v2::resolve_policy(&policy, &config).unwrap();
    let aliases = resolved.workloads.keys().cloned().collect::<Vec<_>>();

    reconcile_workload_launchers_at(&home, &installed_executable, &aliases, owner_uid).unwrap();
    reconcile_desktop_entries_at(&home, &resolved.workloads, owner_uid).unwrap();
    let ready =
        verify_user_integrations_at(&home, &installed_executable, &resolved.workloads, owner_uid)
            .unwrap();
    assert!(ready.workload_launchers_ready);
    assert!(ready.desktop_entries_ready);

    fs::remove_file(home.join(".local/bin/automation-agent")).unwrap();
    std::os::unix::fs::symlink("/usr/bin/false", home.join(".local/bin/automation-agent")).unwrap();
    assert!(verify_user_integrations_at(
        &home,
        &installed_executable,
        &resolved.workloads,
        owner_uid,
    )
    .is_err());
}

#[test]
fn setup_readiness_names_the_next_safe_standalone_operation() {
    let (_root, paths, request) = fixture();
    let absent = setup_readiness_at(&paths, InstallMode::UserOnly).unwrap();
    assert!(!absent.installed);
    assert_eq!(absent.next_action, "verify_release_and_apply_plan");

    install_at(&paths, &request).unwrap();
    let installed = setup_readiness_at(&paths, InstallMode::UserOnly).unwrap();
    assert!(installed.installed);
    assert!(!installed.authenticated_release);
    assert_eq!(installed.next_action, "install_authenticated_release");
}

#[test]
fn setup_proves_same_name_launchers_win_path_resolution_without_mutating_shells() {
    let (root, paths, mut request) = fixture();
    request.activate_transparent_launchers = true;
    let report = install_at(&paths, &request).unwrap();
    let executable = std::path::Path::new(&report.executable);
    let native_first =
        std::env::join_paths([root.path().join("native"), paths.bin_dir.clone()]).unwrap();
    assert!(!transparent_launchers_resolve_first_at(&paths, executable, &native_first,).unwrap());

    let managed_first =
        std::env::join_paths([paths.bin_dir.clone(), root.path().join("native")]).unwrap();
    assert!(transparent_launchers_resolve_first_at(&paths, executable, &managed_first,).unwrap());
    assert!(transparent_launchers_resolve_first_at(
        &paths,
        executable,
        std::ffi::OsStr::new("relative:/usr/bin"),
    )
    .is_err());
}

#[test]
fn version_updates_require_deactivated_launchers_and_preserve_mode() {
    let (_root, paths, mut request) = fixture();
    request.activate_transparent_launchers = true;
    install_at(&paths, &request).unwrap();
    request.version = "0.3.1-test".into();
    assert!(install_at(&paths, &request).is_err());

    deactivate_transparent_launchers_at(&paths).unwrap();
    install_at(&paths, &request).unwrap();
    request.mode = InstallMode::Strong;
    assert!(install_at(&paths, &request).is_err());
}

#[test]
fn strong_install_never_activates_same_name_launchers_before_readiness() {
    let (_root, paths, mut request) = fixture();
    request.mode = dev_auth::setup::InstallMode::Strong;
    request.activate_transparent_launchers = true;
    assert!(dev_auth::setup::build_plan(&paths, &request).is_err());
}
#[test]
fn removing_an_absent_workload_integration_is_a_true_no_op() {
    let home = tempfile::tempdir().unwrap();
    dev_auth::setup::reconcile_workload_launchers_at(
        home.path(),
        &std::env::current_exe().unwrap(),
        &[],
        nix::unistd::Uid::effective().as_raw(),
    )
    .unwrap();
    assert!(!home.path().join(".local").exists());
}
