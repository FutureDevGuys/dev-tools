#![cfg(unix)]

use dev_auth::deployment::{
    canonical_deployment_intent, normalize_deployment, parse_deployment_document, Activation,
    Channel, CredentialIntent, DeploymentCliInput, DeploymentMode,
};
use dev_auth::setup::{build_plan, InstallMode, InstallRequest, SetupPaths};
use dev_auth::setup_v3::{build_setup_plan_v3_at, render_setup_plan_v3};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

const DEPLOYMENT: &str = r#"
schema = "dev-auth-deployment-v1"
mode = "strong"
channel = "stable"
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
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    let policy = root.path().join("policy.toml");
    let config = root.path().join("config.toml");
    let candidate = root.path().join("dev-auth");
    let git = root.path().join("git");
    let gh = root.path().join("gh");
    fs::write(
        &policy,
        format!(
            r#"version = 2
mode = "user_only"
allowed_users = ["{}"]
[programs]
op = "/usr/bin/op"
git = "/usr/bin/git"
gh = "/usr/bin/gh"
ssh = "/usr/bin/ssh"
ssh_keygen = "/usr/bin/ssh-keygen"
[trusted_launchers]
[github_apps]
[authority_caps]
[workspace_caps]
"#,
            user.name
        ),
    )
    .unwrap();
    fs::write(&config, "version = 2\n").unwrap();
    for path in [&policy, &config] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    for path in [&candidate, &git, &gh] {
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
    .unwrap();
    let intent_from_document =
        normalize_deployment(Some(document), DeploymentCliInput::default()).unwrap();
    let intent_from_cli = normalize_deployment(
        None,
        DeploymentCliInput {
            mode: Some(DeploymentMode::UserOnly),
            channel: Some(Channel::Stable),
            activation: Some(Activation::Inactive),
            administrator_policy: Some(policy),
            user_configs: vec![(user.name, config)],
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
    assert_eq!(document_plan.actions.last().unwrap().kind, "verify");
}
