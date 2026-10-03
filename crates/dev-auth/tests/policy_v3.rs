use dev_auth::policy_v3::{
    parse_system_policy_v3, parse_user_config_v3, resolve_policy_for_user, Admission,
};

const POLICY: &str = r#"
schema = "dev-auth-administrator-policy-v3"
mode = "strong"
allowed_users = ["worker"]
[programs]
git = "/usr/bin/git"
gh = "/usr/bin/gh"
ssh = "/usr/bin/ssh"
ssh_keygen = "/usr/bin/ssh-keygen"
[trusted_launchers]
worker = "/opt/fixture/worker"
[credentials.providers.primary]
kind = "one_password"
executable = "/usr/bin/op"
[credentials.credential_slots.database]
provider = "primary"
users = ["worker"]
[credentials.resources.database]
credential_slot = "database"
reference = "op://Fixture/database/password"
kind = "exportable"
purposes = ["read"]
projections = ["stdin"]
[credentials.resource_caps.build]
users = ["worker"]
[credentials.resource_caps.build.resources.database]
purposes = ["read"]
projections = ["stdin"]
[workload_caps.build]
users = ["worker"]
resource_cap = "build"
launchers = ["worker"]
admission = ["enrolled_noninteractive", "approval_required"]
max_duration_seconds = 172800
"#;

fn policy_text() -> String {
    if cfg!(windows) {
        POLICY
            .replace("/usr/bin/", "C:/Tools/")
            .replace("/opt/fixture/", "C:/Fixture/")
    } else {
        POLICY.to_owned()
    }
}

#[test]
fn explicit_v3_document_accepts_named_provider_and_bounded_overnight_authority() {
    assert!(parse_system_policy_v3(policy_text().as_bytes()).is_ok());
}

#[cfg(unix)]
#[test]
fn shipped_v3_templates_resolve_without_enabling_automatic_admission() {
    let user = dev_auth::setup::setup_template("user-config-v3").unwrap();
    for name in ["administrator-policy-v3", "user-only-policy-v3"] {
        let policy = dev_auth::runtime_policy::parse_runtime_administrator(
            dev_auth::setup::setup_template(name).unwrap().as_bytes(),
        )
        .unwrap();
        let resolved = policy.resolve_user("automation", user.as_bytes()).unwrap();
        assert_eq!(
            resolved.workloads["worker"].admission,
            Some(Admission::ApprovalRequired)
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn setup_discovery_uses_every_v3_provider_and_never_an_ambient_default() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.toml");
    let policy = format!(
        "{}\n[credentials.providers.secondary]\nkind = 'one_password'\nexecutable = '/opt/fixture/second-op'\n",
        policy_text()
    );
    std::fs::write(&path, policy).unwrap();
    let report = dev_auth::setup::discover_setup_with_configuration(
        dev_auth::setup::InstallMode::Strong,
        Some(&path),
        &[],
    )
    .expect("explicit v3 policy must be usable by setup discovery");
    let json = serde_json::to_value(report).unwrap();
    let programs = json["programs"].as_object().unwrap();
    assert!(programs.contains_key("provider:primary"));
    assert!(programs.contains_key("provider:secondary"));
    assert!(!programs.contains_key("op"));
}

#[test]
fn version_unknown_fields_and_sensitive_parse_errors_fail_closed() {
    for text in [
        policy_text().replace("policy-v3", "policy-v2"),
        format!("private_marker = 'never-echo-this'\n{}", policy_text()),
        policy_text().replace("max_duration_seconds = 172800", "max_duration_seconds = 0"),
        policy_text().replace("\nusers = [\"worker\"]", "\nusers = [\"other\"]"),
    ] {
        let error = parse_system_policy_v3(text.as_bytes())
            .err()
            .expect("must reject invalid authority");
        assert!(!format!("{error:#?}").contains("never-echo-this"));
    }
}

const USER: &str = r#"
schema = "dev-auth-user-config-v3"
[authority_profiles.build]
cap = "build"
[authority_profiles.build.resources.database]
purposes = ["read"]
projections = ["stdin"]
[[workloads]]
name = "batch"
profile = "build"
launcher = "worker"
admission = "enrolled_noninteractive"
duration_seconds = 86400
[workloads.resources.database]
purposes = ["read"]
"#;

#[test]
fn workload_resolves_logical_resources_and_explicit_admission_without_eight_hour_cap() {
    let system = parse_system_policy_v3(policy_text().as_bytes()).unwrap();
    let user = parse_user_config_v3(USER.as_bytes()).unwrap();
    let resolved = resolve_policy_for_user(&system, "worker", &user).unwrap();
    let workload = &resolved["batch"];
    assert_eq!(workload.duration_seconds, 86400);
    assert_eq!(workload.admission, Admission::EnrolledNoninteractive);
    let name = dev_tools_secret::LogicalSecretName::parse("database").unwrap();
    assert_eq!(workload.resources[&name].credential_slot(), "database");
    assert!(!workload.resources[&name]
        .allows_projection(dev_auth::logical_authority::Projection::Stdin));
}

#[test]
fn workload_cannot_expand_account_resources_projection_launcher_or_admission() {
    let policy = policy_text().replace(
        "[\"enrolled_noninteractive\", \"approval_required\"]",
        "[\"approval_required\"]",
    );
    let system = parse_system_policy_v3(policy.as_bytes()).unwrap();
    let approved = USER.replace("enrolled_noninteractive", "approval_required");
    for (native_user, text) in [
        ("other", approved.clone()),
        ("Worker", approved.clone()),
        (
            "worker",
            approved.replace("duration_seconds = 86400", "duration_seconds = 172801"),
        ),
        (
            "worker",
            approved.replace("duration_seconds = 86400", "duration_seconds = 0"),
        ),
        (
            "worker",
            approved.replace("launcher = \"worker\"", "launcher = \"unknown\""),
        ),
        ("worker", USER.into()),
        (
            "worker",
            approved.replace(
                "[workloads.resources.database]",
                "[workloads.resources.unknown]",
            ),
        ),
        (
            "worker",
            format!("{approved}\nprojections = [\"environment\"]\n"),
        ),
    ] {
        let user = parse_user_config_v3(text.as_bytes()).unwrap();
        assert!(resolve_policy_for_user(&system, native_user, &user).is_err());
    }
    let user = parse_user_config_v3(approved.as_bytes()).unwrap();
    assert!(resolve_policy_for_user(&system, "worker", &user).is_ok());
}

fn github_policy() -> String {
    format!(
        r#"{}
[credentials.resources.github]
credential_slot = "database"
reference = "op://Fixture/github/private-key"
kind = "operation_only"
purposes = ["github_token"]
[credentials.resource_caps.build.resources.github]
purposes = ["github_token"]
[workload_caps.build.operations.github.github]
app_id = 123
repository_selection = "selected"
owners = ["FixtureOrg"]
repositories = ["fixture"]
permissions = {{contents = "read"}}
installation_ids = [1234]
"#,
        policy_text()
    )
}

fn github_user() -> String {
    format!(
        r#"{}
[authority_profiles.build.resources.github]
purposes = ["github_token"]
[workloads.resources.github]
purposes = ["github_token"]
[workloads.operations.github]
resource = "github"
owners = ["fixtureorg"]
repositories = ["fixture"]
permissions = {{contents = "read"}}
"#,
        USER
    )
}

#[test]
fn github_operation_uses_same_logical_resource_resolution_and_narrowed_scope() {
    let system = parse_system_policy_v3(github_policy().as_bytes()).unwrap();
    let user = parse_user_config_v3(github_user().as_bytes()).unwrap();
    let resolved = resolve_policy_for_user(&system, "worker", &user).unwrap();
    let operation = resolved["batch"].operations.github.as_ref().unwrap();
    assert_eq!(operation.resource.as_str(), "github");
    assert_eq!(operation.app_id, 123);
    assert_eq!(
        operation
            .installation_ids
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        [1234]
    );
    assert!(operation.owners.contains("fixtureorg"));
    assert!(!resolved["batch"].resources[&operation.resource]
        .allows(dev_auth::logical_authority::ResourcePurpose::Read));
}

#[test]
fn github_operation_denies_resource_purpose_or_repository_permission_expansion() {
    let system = parse_system_policy_v3(github_policy().as_bytes()).unwrap();
    for user in [
        github_user().replace("resource = \"github\"", "resource = \"database\""),
        github_user().replace("owners = [\"fixtureorg\"]", "owners = [\"unrelated\"]"),
        github_user().replace("repositories = [\"fixture\"]", "repositories = []"),
        github_user().replace(
            "repositories = [\"fixture\"]",
            "repositories = [\"unrelated\"]",
        ),
        github_user().replace("contents = \"read\"", "contents = \"write\""),
        github_user().replace("contents = \"read\"", "issues = \"read\""),
        github_user().replace(
            "[workloads.resources.github]\npurposes = [\"github_token\"]",
            "",
        ),
    ] {
        let user = parse_user_config_v3(user.as_bytes()).unwrap();
        assert!(resolve_policy_for_user(&system, "worker", &user).is_err());
    }
}

#[test]
fn malformed_unused_operation_caps_fail_before_resolution() {
    for policy in [
        github_policy().replace("app_id = 123", "app_id = 0"),
        github_policy().replace(
            "installation_ids = [1234]",
            "installation_ids = [1234, 1234]",
        ),
        github_policy().replace("operations.github.github", "operations.github.database"),
        github_policy().replace("kind = \"operation_only\"", "kind = \"exportable\""),
        github_policy().replace(
            "owners = [\"FixtureOrg\"]",
            "owners = [\"FixtureOrg\", \"fixtureorg\"]",
        ),
    ] {
        assert!(parse_system_policy_v3(policy.as_bytes()).is_err());
    }
}

fn signing_policy() -> String {
    format!(
        r#"{}
[credentials.providers.signing]
kind = "one_password"
executable = "{}"
[credentials.credential_slots.signing]
provider = "signing"
users = ["worker"]
[credentials.resources.ssh]
credential_slot = "signing"
reference = "op://Fixture/ssh/private-key"
kind = "operation_only"
purposes = ["git_signing", "ssh_authentication", "public"]
[credentials.resources.release]
credential_slot = "signing"
reference = "op://Fixture/release/private-key"
kind = "operation_only"
purposes = ["release_signing", "public"]
[credentials.resource_caps.build.resources.ssh]
purposes = ["git_signing", "ssh_authentication", "public"]
[credentials.resource_caps.build.resources.release]
purposes = ["release_signing", "public"]
[workload_caps.build.operations.signing.ssh]
public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPuruylR5Dw9TRBXnt/aS8+Sj1dH3mUEcqFz8iItXZaZ fixture"
fingerprint = "SHA256:5QH+7oUNO/MqyIzx8cLnowDLL1ZieiobwK9fp361KnI"
[workload_caps.build.operations.ssh.ssh]
public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPuruylR5Dw9TRBXnt/aS8+Sj1dH3mUEcqFz8iItXZaZ fixture"
fingerprint = "SHA256:5QH+7oUNO/MqyIzx8cLnowDLL1ZieiobwK9fp361KnI"
[workload_caps.build.operations.release_signing.release]
public_key = "11686a3552e97ca8d717b24007da01716c308dd526340e50a15461f400850072"
products = ["fixture-product"]
"#,
        github_policy(),
        if cfg!(windows) {
            "C:/Tools/op-signing.exe"
        } else {
            "/opt/fixture/op-signing"
        }
    )
}

fn signing_user() -> String {
    format!(r#"{}
[authority_profiles.build.resources.ssh]
purposes = ["git_signing", "ssh_authentication", "public"]
[authority_profiles.build.resources.release]
purposes = ["release_signing", "public"]
[workloads.resources.ssh]
purposes = ["git_signing", "ssh_authentication", "public"]
[workloads.resources.release]
purposes = ["release_signing", "public"]
"#, github_user().replace("[workloads.operations.github]", "[workloads.operations]\nsigning = \"ssh\"\nssh = [\"ssh\"]\nrelease_signing = { resource = \"release\", products = [\"fixture-product\"] }\n[workloads.operations.github]"))
}

#[test]
fn all_operation_families_share_resolution_across_multiple_provider_slots() {
    let system = parse_system_policy_v3(signing_policy().as_bytes()).unwrap();
    let user = parse_user_config_v3(signing_user().as_bytes()).unwrap();
    let resolved = resolve_policy_for_user(&system, "worker", &user).unwrap();
    let workload = &resolved["batch"];
    let github = workload.operations.github.as_ref().unwrap();
    let signing = workload.operations.signing.as_ref().unwrap();
    let ssh = &workload.operations.ssh[0];
    let release = workload.operations.release_signing.as_ref().unwrap();
    for (resource, provider, slot) in [
        (&github.resource, "primary", "database"),
        (&signing.resource, "signing", "signing"),
        (&ssh.resource, "signing", "signing"),
        (&release.resource, "signing", "signing"),
    ] {
        let grant = &workload.resources[resource];
        assert_eq!(grant.provider().as_str(), provider);
        assert_eq!(grant.credential_slot(), slot);
        assert!(!grant.allows(dev_auth::logical_authority::ResourcePurpose::Read));
    }
    assert_eq!(
        release
            .products
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["fixture-product"]
    );
}

#[test]
fn signing_keys_products_and_purposes_cannot_be_substituted() {
    let system = parse_system_policy_v3(signing_policy().as_bytes()).unwrap();
    for user in [
        signing_user().replace("signing = \"ssh\"", "signing = \"release\""),
        signing_user().replace("ssh = [\"ssh\"]", "ssh = [\"ssh\", \"ssh\"]"),
        signing_user().replace("products = [\"fixture-product\"]", "products = [\"unrelated\"]"),
        signing_user().replace("products = [\"fixture-product\"]", "products = []"),
        signing_user().replace("[workloads.resources.ssh]\npurposes = [\"git_signing\", \"ssh_authentication\", \"public\"]", "[workloads.resources.ssh]\npurposes = [\"public\"]"),
    ] {
        let user = parse_user_config_v3(user.as_bytes()).unwrap();
        assert!(resolve_policy_for_user(&system, "worker", &user).is_err());
    }
    for policy in [
        signing_policy().replace(
            "5QH+7oUNO/MqyIzx8cLnowDLL1ZieiobwK9fp361KnI",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        signing_policy().replace(
            "11686a3552e97ca8d717b24007da01716c308dd526340e50a15461f400850072",
            "invalid",
        ),
    ] {
        assert!(parse_system_policy_v3(policy.as_bytes()).is_err());
    }
}

#[test]
fn v3_workloads_preserve_narrowed_workspace_and_desktop_intent() {
    let root = if cfg!(windows) {
        "C:/Workspaces"
    } else {
        "/srv/workspaces"
    };
    let policy = format!(
        "{}\n[workspace_caps.source]\npath = '{root}'\naccess = 'read_write'\n",
        policy_text().replace(
            "max_duration_seconds = 172800",
            "max_duration_seconds = 172800\nworkspace_caps = ['source']"
        )
    );
    let user = USER.replace("duration_seconds = 86400", &format!("duration_seconds = 86400\nworkspace_roots = [{{ cap = 'source', path = '{root}/fixture', access = 'read_only' }}]\ndesktop = {{ display_name = 'Fixture', terminal = true }}"));
    let system = parse_system_policy_v3(policy.as_bytes()).unwrap();
    let user = parse_user_config_v3(user.as_bytes()).unwrap();
    assert!(resolve_policy_for_user(&system, "worker", &user).is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn native_session_grants_keep_each_logical_operation_in_its_real_credential_slot() {
    let system = parse_system_policy_v3(signing_policy().as_bytes()).unwrap();
    let user = parse_user_config_v3(signing_user().as_bytes()).unwrap();
    let resolved =
        dev_auth::policy_v3::resolve_runtime_policy_for_user(&system, "worker", &user).unwrap();
    let workload = &resolved.workloads["batch"];
    let profile = &resolved.authority_profiles[&workload.authority_profile];
    let native = dev_auth::linux_admission::session_authority_from_resolved(profile);
    assert_eq!(native.github.unwrap().credential_slot, "database");
    assert_eq!(native.signing.unwrap().credential_slot, "signing");
    assert_eq!(native.ssh[0].credential_slot, "signing");
    assert_eq!(native.release_signing.unwrap().credential_slot, "signing");
}

#[test]
fn installed_policy_dispatch_selects_explicit_v3_and_never_accepts_a_mixed_user_version() {
    let policy =
        dev_auth::runtime_policy::parse_runtime_administrator(signing_policy().as_bytes()).unwrap();
    let resolved = policy
        .resolve_user("worker", signing_user().as_bytes())
        .unwrap();
    let workload = &resolved.workloads["batch"];
    let profile = &resolved.authority_profiles[&workload.authority_profile];
    assert_eq!(
        profile
            .credential_slots
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["database", "signing"]
    );
    assert!(policy.resolve_user("worker", b"version = 2").is_err());
    assert!(dev_auth::runtime_policy::parse_runtime_administrator(
        format!("version = 2\n{}", signing_policy()).as_bytes()
    )
    .is_err());
}

#[test]
fn v3_administrator_narrowing_preserves_bindings_and_removes_authority_only() {
    use dev_auth::runtime_policy::parse_runtime_administrator;
    let original = policy_text();
    let administrator = parse_runtime_administrator(original.as_bytes()).unwrap();
    let narrowed = original
        .replace(
            "max_duration_seconds = 172800",
            "max_duration_seconds = 86400",
        )
        .replace(
            "[\"enrolled_noninteractive\", \"approval_required\"]",
            "[\"approval_required\"]",
        );
    let candidate = parse_runtime_administrator(narrowed.as_bytes()).unwrap();
    administrator
        .require_narrows(&candidate)
        .expect("bounded v3 narrowing must be accepted");
    assert!(candidate.require_narrows(&administrator).is_err());
    let fewer_projections = parse_runtime_administrator(
        original
            .replace("projections = [\"stdin\"]", "projections = []")
            .as_bytes(),
    )
    .unwrap();
    administrator
        .require_narrows(&fewer_projections)
        .expect("removing projection rights narrows authority");
    assert!(fewer_projections.require_narrows(&administrator).is_err());
    for changed in [
        original.replace(
            "op://Fixture/database/password",
            "op://Fixture/other/password",
        ),
        original
            .replace("/usr/bin/op", "/opt/other/op")
            .replace("C:/Tools/op", "C:/Other/op"),
        original.replace(
            "max_duration_seconds = 172800",
            "max_duration_seconds = 172801",
        ),
    ] {
        let changed = parse_runtime_administrator(changed.as_bytes()).unwrap();
        assert!(administrator.require_narrows(&changed).is_err());
    }
}

#[test]
fn v3_policy_narrowing_checks_operation_scope_even_when_unused_by_a_workload() {
    use dev_auth::runtime_policy::parse_runtime_administrator;
    let original = signing_policy();
    let administrator = parse_runtime_administrator(original.as_bytes()).unwrap();
    for changed in [
        original.replace("app_id = 123", "app_id = 124"),
        original.replace("installation_ids = [1234]", "installation_ids = []"),
        original.replace("installation_ids = [1234]", "installation_ids = [1235]"),
        original.replace("repositories = [\"fixture\"]", "repositories = []"),
        original.replace("contents = \"read\"", "contents = \"write\""),
        original.replace(
            "products = [\"fixture-product\"]",
            "products = [\"other-product\"]",
        ),
    ] {
        let changed = parse_runtime_administrator(changed.as_bytes()).unwrap();
        assert!(administrator.require_narrows(&changed).is_err());
    }
    let broad = original
        .replace("contents = \"read\"", "contents = \"write\"")
        .replace("repositories = [\"fixture\"]", "repositories = []")
        .replace("installation_ids = [1234]", "installation_ids = []")
        .replace(
            "products = [\"fixture-product\"]",
            "products = [\"fixture-product\", \"other-product\"]",
        );
    let broad = parse_runtime_administrator(broad.as_bytes()).unwrap();
    broad.require_narrows(&administrator).unwrap();
}
