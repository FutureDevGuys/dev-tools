#![cfg(unix)]

use dev_auth::deployment::{
    canonical_deployment_intent, normalize_deployment, parse_deployment_document, Activation,
    Channel, CredentialIntent, DeploymentCliInput, DeploymentMode,
};
use dev_auth::setup::{build_plan, InstallMode, InstallRequest, SetupPaths};
use dev_auth::setup_v3::{
    build_setup_plan_v3_at, credential_requirements, render_setup_plan_v3,
    setup_apply_candidate_path, verify_setup_plan_v3,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

const DEPLOYMENT: &str = r#"
schema = "dev-auth-deployment-v1"
mode = "strong"
channel = "stable"
offline = true
activation = "transparent"
administrator_policy = "/srv/dev-auth/policy.toml"

[[users]]
name = "alice"
config = "/srv/dev-auth/alice.toml"

[[users]]
name = "bob"
config = "/srv/dev-auth/bob.toml"

[[credentials]]
slot = "automation"
intent = "enroll-if-absent"
"#;

fn cli_equivalent() -> DeploymentCliInput {
    DeploymentCliInput {
        mode: Some(DeploymentMode::Strong),
        channel: Some(Channel::Stable),
        offline: Some(true),
        activation: Some(Activation::Transparent),
        administrator_policy: Some(PathBuf::from("/srv/dev-auth/policy.toml")),
        user_configs: vec![
            ("bob".into(), PathBuf::from("/srv/dev-auth/bob.toml")),
            ("alice".into(), PathBuf::from("/srv/dev-auth/alice.toml")),
        ],
        user_policies: Vec::new(),
        credential_intents: vec![("automation".into(), CredentialIntent::EnrollIfAbsent)],
    }
}

#[test]
fn toml_and_cli_normalize_to_identical_canonical_intent() {
    let document = parse_deployment_document(DEPLOYMENT.as_bytes()).unwrap();
    let from_document =
        normalize_deployment(Some(document.clone()), DeploymentCliInput::default()).unwrap();
    let from_cli = normalize_deployment(None, cli_equivalent()).unwrap();
    let mixed = normalize_deployment(Some(document), cli_equivalent()).unwrap();

    assert_eq!(from_document, from_cli);
    assert_eq!(mixed, from_cli);
    assert_eq!(
        canonical_deployment_intent(&from_document).unwrap(),
        canonical_deployment_intent(&from_cli).unwrap()
    );
    assert_eq!(from_document.users[0].name, "alice");
    assert_eq!(from_document.users[1].name, "bob");
}

#[test]
fn published_deployment_example_is_nonsecret_and_parses_as_full_desired_state() {
    let source = include_bytes!("../deployment-v1.example.toml");
    let document = parse_deployment_document(source).unwrap();
    assert_eq!(document.schema, "dev-auth-deployment-v1");
    assert_eq!(document.mode, DeploymentMode::Strong);
    assert_eq!(document.activation, Activation::Transparent);
    assert_eq!(document.users.len(), 1);
    assert_eq!(document.credentials.len(), 1);
    let text = std::str::from_utf8(source).unwrap();
    assert!(!text.contains("op://"));
    assert!(!text.to_ascii_lowercase().contains("token ="));
    assert!(!text.to_ascii_lowercase().contains("password ="));
}

#[test]
fn conflicting_or_duplicate_definitions_fail_before_planning() {
    let document = parse_deployment_document(DEPLOYMENT.as_bytes()).unwrap();
    let mut conflict = cli_equivalent();
    conflict.activation = Some(Activation::Inactive);
    assert!(normalize_deployment(Some(document), conflict).is_err());

    let mut duplicate_user = cli_equivalent();
    duplicate_user
        .user_configs
        .push(("alice".into(), PathBuf::from("/srv/dev-auth/alice.toml")));
    assert!(normalize_deployment(None, duplicate_user).is_err());

    let mut duplicate_slot = cli_equivalent();
    duplicate_slot
        .credential_intents
        .push(("automation".into(), CredentialIntent::EnrollIfAbsent));
    assert!(normalize_deployment(None, duplicate_slot).is_err());
}

#[test]
fn deployment_rejects_unsafe_or_inapplicable_authority() {
    let relative = DEPLOYMENT.replace("/srv/dev-auth/policy.toml", "relative/dev-auth/policy.toml");
    assert!(parse_deployment_document(relative.as_bytes()).is_err());

    let strong_user_policy = DEPLOYMENT.replace(
        "config = \"/srv/dev-auth/alice.toml\"",
        "config = \"/srv/dev-auth/alice.toml\"\npolicy = \"/srv/dev-auth/alice-policy.toml\"",
    );
    assert!(parse_deployment_document(strong_user_policy.as_bytes()).is_err());

    let duplicate =
        format!("{DEPLOYMENT}\n[[credentials]]\nslot = \"automation\"\nintent = \"preserve\"\n");
    assert!(parse_deployment_document(duplicate.as_bytes()).is_err());
}

#[test]
fn user_only_policy_is_explicit_and_trust_boundary_remains_degraded() {
    let document = parse_deployment_document(
        br#"
schema = "dev-auth-deployment-v1"
mode = "user-only"
channel = "stable"
activation = "inactive"
administrator_policy = "/srv/dev-auth/user-cap.toml"

[[users]]
name = "alice"
config = "/srv/dev-auth/alice.toml"
policy = "/srv/dev-auth/alice-policy.toml"

[[credentials]]
slot = "automation"
intent = "preserve"
"#,
    )
    .unwrap();
    let intent = normalize_deployment(Some(document), DeploymentCliInput::default()).unwrap();
    assert_eq!(intent.mode, DeploymentMode::UserOnly);
    assert_eq!(
        intent.users[0].policy.as_deref(),
        Some(std::path::Path::new("/srv/dev-auth/alice-policy.toml"))
    );
}

#[test]
fn equivalent_intents_produce_identical_setup_v3_actions_and_digest() {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    let root = tempfile::Builder::new()
        .prefix(".dev-auth-deployment-test-")
        .tempdir_in(&user.dir)
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let policy = root.path().join("policy.toml");
    let config = root.path().join("config.toml");
    let candidate = root.path().join("dev-auth");
    let op = root.path().join("op");
    let git = root.path().join("git");
    let gh = root.path().join("gh");
    let ssh = root.path().join("ssh");
    let ssh_keygen = root.path().join("ssh-keygen");
    fs::write(
        &policy,
        format!(
            r#"version = 2
mode = "user_only"
allowed_users = ["{}"]
[programs]
op = "{}"
git = "{}"
gh = "{}"
ssh = "{}"
ssh_keygen = "{}"
[trusted_launchers]
[github_apps]
[credential_slots]
[authority_caps]
[workspace_caps]
"#,
            user.name,
            op.display(),
            git.display(),
            gh.display(),
            ssh.display(),
            ssh_keygen.display()
        ),
    )
    .unwrap();
    fs::write(&config, "version = 2\n").unwrap();
    for path in [&policy, &config] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    for path in [&candidate, &op, &git, &gh, &ssh, &ssh_keygen] {
        fs::write(path, b"fixture").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let paths = SetupPaths::user_only(&user.dir);
    let installation = build_plan(
        &paths,
        &InstallRequest {
            mode: InstallMode::UserOnly,
            version: "0.3.0-test".into(),
            source_executable: candidate,
            native_git: git,
            native_gh: gh,
            activate_transparent_launchers: false,
        },
    )
    .unwrap();
    let document = parse_deployment_document(
        format!(
            r#"schema = "dev-auth-deployment-v1"
mode = "user-only"
channel = "stable"
activation = "transparent"
administrator_policy = "{}"
[[users]]
name = "{}"
config = "{}"
"#,
            policy.display(),
            user.name,
            config.display()
        )
        .as_bytes(),
    )
    .unwrap();
    let intent_from_document =
        normalize_deployment(Some(document), DeploymentCliInput::default()).unwrap();
    let intent_from_cli = normalize_deployment(
        None,
        DeploymentCliInput {
            mode: Some(DeploymentMode::UserOnly),
            channel: Some(Channel::Stable),
            offline: Some(false),
            activation: Some(Activation::Transparent),
            administrator_policy: Some(policy),
            user_configs: vec![(user.name.clone(), config)],
            user_policies: Vec::new(),
            credential_intents: Vec::new(),
        },
    )
    .unwrap();

    let document_plan =
        build_setup_plan_v3_at(intent_from_document, installation.clone(), false).unwrap();
    let cli_plan = build_setup_plan_v3_at(intent_from_cli, installation, false).unwrap();
    assert_eq!(document_plan, cli_plan);
    assert_eq!(
        render_setup_plan_v3(&document_plan).unwrap(),
        render_setup_plan_v3(&cli_plan).unwrap()
    );
    assert_eq!(document_plan.schema, "dev-auth-setup-plan-v3");
    assert!(
        !document_plan
            .installation
            .request
            .activate_transparent_launchers
    );
    assert!(document_plan
        .actions
        .iter()
        .any(|action| action.kind == "activate_transparent_launchers"));
    assert_eq!(
        document_plan.actions[document_plan.actions.len() - 2].kind,
        "activate_transparent_launchers"
    );
    assert_eq!(document_plan.actions.last().unwrap().kind, "verify");
    for (kind, subject, path) in [
        (
            "shared_installation_receipt",
            "system",
            document_plan
                .installation
                .paths
                .data_root
                .join("installation-receipt-v1.json"),
        ),
        (
            "active_release_pointer",
            "system",
            document_plan.installation.paths.data_root.join("active"),
        ),
        (
            "product_launcher",
            "git-dev-auth",
            document_plan
                .installation
                .paths
                .bin_dir
                .join("git-dev-auth"),
        ),
        (
            "transparent_launcher",
            "git",
            document_plan.installation.paths.bin_dir.join("git"),
        ),
        (
            "workload_launcher_receipt",
            user.name.as_str(),
            user.dir
                .join(".local/share/dev-auth/workload-aliases-v1.json"),
        ),
        (
            "desktop_entry_receipt",
            user.name.as_str(),
            user.dir
                .join(".local/share/dev-auth/desktop-entries-v1.json"),
        ),
    ] {
        assert!(document_plan.current_paths.iter().any(|current| {
            current.kind == kind && current.subject == subject && current.path == path
        }));
    }
    let (_, digest) = render_setup_plan_v3(&document_plan).unwrap();
    let verification = verify_setup_plan_v3(&document_plan, &digest).unwrap();
    assert!(!verification.changed);
    assert!(!verification.verified);
    assert_eq!(verification.next_action, "apply");
    assert_eq!(
        setup_apply_candidate_path(&document_plan, &digest).unwrap(),
        Some(document_plan.installation.request.source_executable.clone())
    );
}

#[test]
fn setup_plan_binds_transparent_upstreams_to_administrator_policy() {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    let root = tempfile::Builder::new()
        .prefix(".dev-auth-deployment-test-")
        .tempdir_in(&user.dir)
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let policy = root.path().join("policy.toml");
    let config = root.path().join("config.toml");
    let candidate = root.path().join("dev-auth");
    let op = root.path().join("op");
    let installed_git = root.path().join("installed-git");
    let policy_git = root.path().join("policy-git");
    let native_gh = root.path().join("gh");
    let ssh = root.path().join("ssh");
    let ssh_keygen = root.path().join("ssh-keygen");
    fs::write(
        &policy,
        format!(
            r#"version = 2
mode = "user_only"
allowed_users = ["{}"]
[programs]
op = "{}"
git = "{}"
gh = "{}"
ssh = "{}"
ssh_keygen = "{}"
[trusted_launchers]
[github_apps]
[credential_slots]
[authority_caps]
[workspace_caps]
"#,
            user.name,
            op.display(),
            policy_git.display(),
            native_gh.display(),
            ssh.display(),
            ssh_keygen.display()
        ),
    )
    .unwrap();
    fs::write(&config, "version = 2\n").unwrap();
    for path in [
        &policy,
        &config,
        &candidate,
        &op,
        &installed_git,
        &policy_git,
        &native_gh,
        &ssh,
        &ssh_keygen,
    ] {
        if !path.exists() {
            fs::write(path, b"fixture").unwrap();
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut installation = build_plan(
        &SetupPaths::user_only(&user.dir),
        &InstallRequest {
            mode: InstallMode::UserOnly,
            version: "0.3.0-test".into(),
            source_executable: candidate,
            native_git: installed_git,
            native_gh,
            activate_transparent_launchers: false,
        },
    )
    .unwrap();
    let intent = normalize_deployment(
        Some(
            parse_deployment_document(
                format!(
                    r#"schema = "dev-auth-deployment-v1"
mode = "user-only"
channel = "stable"
activation = "inactive"
administrator_policy = "{}"
[[users]]
name = "{}"
config = "{}"
"#,
                    policy.display(),
                    user.name,
                    config.display()
                )
                .as_bytes(),
            )
            .unwrap(),
        ),
        DeploymentCliInput::default(),
    )
    .unwrap();

    let mut displaced = installation.clone();
    displaced.paths = SetupPaths {
        data_root: root.path().join("displaced-data"),
        bin_dir: root.path().join("displaced-bin"),
    };
    let error = build_setup_plan_v3_at(intent.clone(), displaced, false).unwrap_err();
    assert!(error
        .to_string()
        .contains("deployment installation layout is not canonical"));

    let error = build_setup_plan_v3_at(intent.clone(), installation.clone(), false).unwrap_err();
    assert!(error
        .to_string()
        .contains("administrator-pinned native Git"));

    installation.request.native_git = policy_git;
    fs::set_permissions(&op, fs::Permissions::from_mode(0o777)).unwrap();
    let error = build_setup_plan_v3_at(intent, installation, false).unwrap_err();
    assert!(error
        .to_string()
        .contains("1Password CLI is group- or world-writable"));
}

#[test]
fn inactive_setup_plans_stage_product_state_without_activating_workloads_or_broker() {
    let document = parse_deployment_document(
        br#"
schema = "dev-auth-deployment-v1"
mode = "user-only"
channel = "stable"
activation = "inactive"
administrator_policy = "/srv/dev-auth/user-cap.toml"

[[users]]
name = "alice"
config = "/srv/dev-auth/alice.toml"

[[credentials]]
slot = "automation"
intent = "enroll-if-absent"
"#,
    )
    .unwrap();
    let intent = normalize_deployment(Some(document), DeploymentCliInput::default()).unwrap();
    let actions = dev_auth::setup_v3::planned_action_contract(&intent);
    assert!(actions
        .iter()
        .any(|action| action.kind == "install_release"));
    assert!(actions
        .iter()
        .any(|action| action.kind == "install_user_configuration"));
    assert!(!actions
        .iter()
        .any(|action| action.kind == "install_user_integrations"));
    assert!(!actions.iter().any(|action| action.kind == "start_broker"));
    assert!(!actions
        .iter()
        .any(|action| action.kind == "activate_transparent_launchers"));
}

#[test]
fn credential_requirements_are_intent_exact_and_resume_safe() {
    let credentials = vec![
        dev_auth::deployment::DeploymentCredential {
            slot: "enroll".into(),
            intent: CredentialIntent::EnrollIfAbsent,
        },
        dev_auth::deployment::DeploymentCredential {
            slot: "rotate".into(),
            intent: CredentialIntent::Rotate,
        },
        dev_auth::deployment::DeploymentCredential {
            slot: "preserve".into(),
            intent: CredentialIntent::Preserve,
        },
        dev_auth::deployment::DeploymentCredential {
            slot: "revoke".into(),
            intent: CredentialIntent::Revoke,
        },
    ];
    let absent = credential_requirements(&credentials, &std::collections::BTreeSet::new());
    assert_eq!(
        absent.required,
        std::collections::BTreeSet::from(["enroll".into(), "rotate".into()])
    );
    assert_eq!(absent.blocked, vec!["preserve".to_owned()]);

    let enrolled = credential_requirements(
        &credentials,
        &std::collections::BTreeSet::from(["enroll".into(), "preserve".into()]),
    );
    assert_eq!(
        enrolled.required,
        std::collections::BTreeSet::from(["rotate".into()])
    );
    assert!(enrolled.blocked.is_empty());
}
