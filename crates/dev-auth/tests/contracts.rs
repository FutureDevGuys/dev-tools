use dev_auth::{
    admit_gh_arguments, parse_config, parse_github_repository, render_git_credential,
    sanitize_environment, CacheEntry, CredentialRequest, GitHubInstallation, GitHubProfile,
    SecretString,
};
use std::collections::{BTreeMap, BTreeSet};

fn exact_permissions() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("actions".into(), "read".into()),
        ("checks".into(), "read".into()),
        ("contents".into(), "write".into()),
        ("metadata".into(), "read".into()),
        ("pull_requests".into(), "write".into()),
        ("statuses".into(), "read".into()),
    ])
}

fn profile() -> GitHubProfile {
    GitHubProfile {
        app_id: 42,
        private_key_ref: "op://Automation/contributor-app/private-key".into(),
        installations: vec![GitHubInstallation {
            owner: "FutureDevGuys".into(),
            installation_id: 101,
            repositories: BTreeMap::from([("dev-tools".into(), 202)]),
        }],
        permissions: exact_permissions(),
    }
}

#[test]
fn credential_request_requires_exact_https_github_repository_path() {
    let request = CredentialRequest::parse(
        b"protocol=https\nhost=github.com\npath=FutureDevGuys/dev-tools.git\n\n",
    )
    .unwrap();
    assert_eq!(
        request.repository().unwrap(),
        ("FutureDevGuys", "dev-tools")
    );

    for invalid in [
        b"protocol=ssh\nhost=github.com\npath=FutureDevGuys/dev-tools.git\n\n".as_slice(),
        b"protocol=https\nhost=example.com\npath=FutureDevGuys/dev-tools.git\n\n".as_slice(),
        b"protocol=https\nhost=github.com\npath=FutureDevGuys/dev-tools/extra\n\n".as_slice(),
        b"protocol=https\nhost=github.com\n\n".as_slice(),
    ] {
        assert!(CredentialRequest::parse(invalid).is_err());
    }
}

#[test]
fn profile_selects_one_exact_installation_and_numeric_repository() {
    let selected = profile()
        .select_repository("FutureDevGuys", "dev-tools")
        .unwrap();
    assert_eq!(selected.installation_id, 101);
    assert_eq!(selected.repository_id, 202);
    assert!(profile()
        .select_repository("FutureDevGuys", "unknown")
        .is_err());
    assert!(profile()
        .select_repository("DevGuyRash", "dev-tools")
        .is_err());
    assert_eq!(
        profile()
            .select_repository("futuredevguys", "DEV-TOOLS")
            .unwrap()
            .repository_id,
        202
    );
    let mut duplicate = profile();
    duplicate.installations.push(GitHubInstallation {
        owner: "futuredevguys".into(),
        installation_id: 303,
        repositories: BTreeMap::from([("dev-tools".into(), 404)]),
    });
    assert!(duplicate
        .select_repository("FutureDevGuys", "dev-tools")
        .is_err());
}

#[test]
fn secret_debug_and_display_never_reveal_the_value() {
    let secret = SecretString::new("github_pat_should_never_appear".into());
    assert_eq!(format!("{secret:?}"), "[REDACTED]");
    assert_eq!(format!("{secret}"), "[REDACTED]");
}

#[test]
fn cache_refreshes_before_expiry_and_never_accepts_wrong_scope() {
    let entry = CacheEntry::new_for_test(
        SecretString::new("token".into()),
        10_000,
        101,
        202,
        BTreeMap::from([("contents".into(), "write".into())]),
    );
    assert!(entry.is_usable_at(9_699, 101, 202, &entry.permissions));
    assert!(!entry.is_usable_at(9_700, 101, 202, &entry.permissions));
    assert!(!entry.is_usable_at(1, 999, 202, &entry.permissions));
    assert!(!entry.is_usable_at(1, 101, 999, &entry.permissions));
}

#[test]
fn child_environment_keeps_runtime_basics_and_removes_credentials() {
    let input = BTreeMap::from([
        ("HOME".into(), "/home/example".into()),
        ("PATH".into(), "/usr/bin".into()),
        ("TERM".into(), "xterm".into()),
        ("GH_TOKEN".into(), "human".into()),
        ("GITHUB_TOKEN".into(), "human".into()),
        ("OP_SERVICE_ACCOUNT_TOKEN".into(), "service".into()),
        ("AWS_SECRET_ACCESS_KEY".into(), "cloud".into()),
        ("UNRELATED_RANDOM".into(), "ambient".into()),
    ]);
    let output = sanitize_environment(&input, &BTreeSet::new());
    assert_eq!(output.get("HOME").unwrap(), "/home/example");
    assert_eq!(output.get("PATH").unwrap(), "/usr/bin");
    assert_eq!(output.get("TERM").unwrap(), "xterm");
    assert!(!output.contains_key("GH_TOKEN"));
    assert!(!output.contains_key("GITHUB_TOKEN"));
    assert!(!output.contains_key("OP_SERVICE_ACCOUNT_TOKEN"));
    assert!(!output.contains_key("AWS_SECRET_ACCESS_KEY"));
    assert!(!output.contains_key("UNRELATED_RANDOM"));
}

#[test]
fn configuration_is_closed_and_requires_automation_vault_references() {
    let config = parse_config(
        br#"
version = 1

[github]
app_id = 42
private_key_ref = "op://Automation/contributor-app/private-key"
permissions = { actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }

[[github.installations]]
owner = "FutureDevGuys"
installation_id = 101
repositories = { dev-tools = 202 }

[profiles.terraform-plan]
executables = ["/usr/bin/terraform"]
environment = { TF_TOKEN_app_terraform_io = "op://Automation/hcp-plan/token" }

[[ssh_profiles.automation.keys]]
purpose = "authentication"
private_key_ref = "op://Automation/workstation-ssh/private-key"
fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

[[ssh_profiles.automation.keys]]
purpose = "signing"
private_key_ref = "op://Automation/workstation-signing/private-key"
fingerprint = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
"#,
    )
    .unwrap();
    assert_eq!(config.version, 1);
    assert_eq!(config.github.app_id, 42);
    assert_eq!(
        config.profiles["terraform-plan"].executables,
        ["/usr/bin/terraform"]
    );
    assert_eq!(config.ssh_profiles["automation"].keys.len(), 2);

    for invalid in [
        br#"version = 1
[github]
app_id = 42
private_key_ref = "op://Personal/key/private-key"
permissions = { contents = "write" }
installations = []
"#
        .as_slice(),
        br#"version = 2
[github]
app_id = 42
private_key_ref = "op://Automation/key/private-key"
permissions = { contents = "write" }
installations = []
"#
        .as_slice(),
        br#"version = 1
unknown = true
[github]
app_id = 42
private_key_ref = "op://Automation/key/private-key"
permissions = { contents = "write" }
installations = []
"#
        .as_slice(),
        br#"version = 1
[github]
app_id = 42
private_key_ref = "op://Automation/key/private-key"
permissions = { actions = "read", administration = "write", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }
[[github.installations]]
owner = "FutureDevGuys"
installation_id = 101
repositories = { dev-tools = 202 }
"#
        .as_slice(),
    ] {
        assert!(parse_config(invalid).is_err());
    }
}

#[test]
fn git_credential_output_is_exact_and_contains_an_expiry() {
    let response = render_git_credential("installation-token", 10_000).unwrap();
    assert_eq!(
        response,
        "username=x-access-token\npassword=installation-token\npassword_expiry_utc=10000\n\n"
    );
    assert!(render_git_credential("line\nbreak", 10_000).is_err());
    assert!(render_git_credential("token", 0).is_err());
}

#[test]
fn github_repository_parser_accepts_only_exact_github_repository_identifiers() {
    for (source, expected) in [
        ("FutureDevGuys/dev-tools", ("FutureDevGuys", "dev-tools")),
        (
            "https://github.com/FutureDevGuys/dev-tools.git",
            ("FutureDevGuys", "dev-tools"),
        ),
        (
            "git@github.com:FutureDevGuys/dev-tools.git",
            ("FutureDevGuys", "dev-tools"),
        ),
        (
            "ssh://git@github.com/FutureDevGuys/dev-tools.git",
            ("FutureDevGuys", "dev-tools"),
        ),
    ] {
        assert_eq!(
            parse_github_repository(source).unwrap(),
            (expected.0.to_owned(), expected.1.to_owned())
        );
    }
    for invalid in [
        "https://example.com/FutureDevGuys/dev-tools.git",
        "FutureDevGuys/dev-tools/extra",
        "github.com/FutureDevGuys/dev-tools",
        "https://github.com/FutureDevGuys/dev-tools?token=secret",
    ] {
        assert!(parse_github_repository(invalid).is_err());
    }
}

#[test]
fn gh_surface_is_repository_scoped_and_excludes_administration() {
    for accepted in [
        vec!["pr", "list"],
        vec!["pr", "create", "-R", "FutureDevGuys/dev-tools"],
        vec!["run", "view"],
        vec!["workflow", "list"],
        vec!["release", "download"],
        vec!["repo", "view"],
        vec!["status"],
    ] {
        assert!(admit_gh_arguments(&accepted).is_ok(), "{accepted:?}");
    }
    for rejected in [
        vec!["auth", "login"],
        vec!["api", "user"],
        vec!["repo", "create"],
        vec!["repo", "delete"],
        vec!["workflow", "run"],
        vec!["secret", "set"],
        vec!["variable", "set"],
        vec!["issue", "create"],
    ] {
        assert!(admit_gh_arguments(&rejected).is_err(), "{rejected:?}");
    }
}
