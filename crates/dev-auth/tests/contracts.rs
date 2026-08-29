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
        private_key_ref: "op://Machine Vault/contributor-app/private-key".into(),
        discover_installations: false,
        installations: vec![GitHubInstallation {
            owner: "ExampleOrg".into(),
            installation_id: 101,
            all_repositories: false,
            repositories: BTreeSet::from(["sample-repo".into()]),
        }],
        permissions: exact_permissions(),
    }
}

#[test]
fn credential_request_requires_exact_https_github_repository_path() {
    let request = CredentialRequest::parse(
        b"protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\n\n",
    )
    .unwrap();
    assert_eq!(request.repository().unwrap(), ("ExampleOrg", "sample-repo"));

    for invalid in [
        b"protocol=ssh\nhost=github.com\npath=ExampleOrg/sample-repo.git\n\n".as_slice(),
        b"protocol=https\nhost=example.com\npath=ExampleOrg/sample-repo.git\n\n".as_slice(),
        b"protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo/extra\n\n".as_slice(),
        b"protocol=https\nhost=github.com\n\n".as_slice(),
    ] {
        assert!(CredentialRequest::parse(invalid).is_err());
    }
}

#[test]
fn credential_request_accepts_git_eof_termination_and_capabilities() {
    let request = CredentialRequest::parse(
        b"capability[]=authtype\ncapability[]=state\nprotocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\nwwwauth[]=Basic realm=\"GitHub\"\n",
    )
    .unwrap();
    assert_eq!(request.repository().unwrap(), ("ExampleOrg", "sample-repo"));

    assert!(CredentialRequest::parse(
        b"protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git"
    )
    .is_err());
    assert!(CredentialRequest::parse(
        b"protocol=https\nhost=github.com\n\npath=ExampleOrg/sample-repo.git\n"
    )
    .is_err());
    assert!(CredentialRequest::parse(
        b"protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\npath=ExampleOrg/other.git\n"
    )
    .is_err());
}

#[test]
fn profile_selects_one_exact_installation_and_repository_name() {
    let selected = profile()
        .select_repository("ExampleOrg", "sample-repo")
        .unwrap();
    assert_eq!(selected.installation_id, 101);
    assert_eq!(selected.owner, "exampleorg");
    assert_eq!(selected.repository, "sample-repo");
    assert!(profile()
        .select_repository("ExampleOrg", "unknown")
        .is_err());
    assert!(profile()
        .select_repository("OtherOwner", "sample-repo")
        .is_err());
    assert_eq!(
        profile()
            .select_repository("exampleorg", "SAMPLE-REPO")
            .unwrap()
            .repository,
        "sample-repo"
    );
    let mut duplicate = profile();
    duplicate.installations.push(GitHubInstallation {
        owner: "exampleorg".into(),
        installation_id: 303,
        all_repositories: false,
        repositories: BTreeSet::from(["sample-repo".into()]),
    });
    assert!(duplicate
        .select_repository("ExampleOrg", "sample-repo")
        .is_err());
}

#[test]
fn all_repository_installation_selects_new_repository_without_static_ids() {
    let profile = GitHubProfile {
        app_id: 42,
        private_key_ref: "op://Machine Vault/contributor-app/private-key".into(),
        discover_installations: false,
        installations: vec![GitHubInstallation {
            owner: "ExampleOrg".into(),
            installation_id: 101,
            all_repositories: true,
            repositories: BTreeSet::new(),
        }],
        permissions: exact_permissions(),
    };
    let selected = profile
        .select_repository("exampleorg", "brand-new-repository")
        .unwrap();
    assert_eq!(selected.installation_id, 101);
    assert_eq!(selected.owner, "exampleorg");
    assert_eq!(selected.repository, "brand-new-repository");
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
        42,
        101,
        "exampleorg".into(),
        "sample-repo".into(),
        BTreeMap::from([("contents".into(), "write".into())]),
    );
    assert!(entry.is_usable_at(
        9_699,
        42,
        101,
        "exampleorg",
        "sample-repo",
        &entry.permissions
    ));
    assert!(!entry.is_usable_at(
        9_700,
        42,
        101,
        "exampleorg",
        "sample-repo",
        &entry.permissions
    ));
    assert!(!entry.is_usable_at(1, 99, 101, "exampleorg", "sample-repo", &entry.permissions));
    assert!(!entry.is_usable_at(1, 42, 999, "exampleorg", "sample-repo", &entry.permissions));
    assert!(!entry.is_usable_at(
        1,
        42,
        101,
        "another-owner",
        "sample-repo",
        &entry.permissions
    ));
    assert!(!entry.is_usable_at(1, 42, 101, "exampleorg", "syscfg", &entry.permissions));
}

#[test]
fn child_environment_keeps_runtime_basics_and_removes_credentials() {
    let input = BTreeMap::from([
        ("HOME".into(), "/home/example".into()),
        ("PATH".into(), "/usr/bin".into()),
        ("SystemRoot".into(), "C:\\Windows".into()),
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
    assert_eq!(output.get("SystemRoot").unwrap(), "C:\\Windows");
    assert_eq!(output.get("TERM").unwrap(), "xterm");
    assert!(!output.contains_key("GH_TOKEN"));
    assert!(!output.contains_key("GITHUB_TOKEN"));
    assert!(!output.contains_key("OP_SERVICE_ACCOUNT_TOKEN"));
    assert!(!output.contains_key("AWS_SECRET_ACCESS_KEY"));
    assert!(!output.contains_key("UNRELATED_RANDOM"));
}

#[test]
fn configuration_is_closed_and_accepts_account_neutral_vault_references() {
    let config = parse_config(
        br#"
version = 1

[credential_store]
service = "example-credential-broker"
account = "service-token"

[programs]
op = "/opt/1Password/op"
gh = "/usr/bin/gh"
git = "/usr/bin/git"
ssh_add = "/usr/bin/ssh-add"
ssh_keygen = "/usr/bin/ssh-keygen"

[github]
app_id = 42
	private_key_ref = "op://Any Vault/contributor-app/private-key"
permissions = { actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }

[[github.installations]]
owner = "ExampleOrg"
installation_id = 101
repositories = ["sample-repo"]

[profiles.terraform-plan]
	executables = ["/usr/bin/terraform"]
	environment = { TF_TOKEN_app_terraform_io = "op://Team Vault/hcp-plan/token" }

[[ssh_profiles.automation.keys]]
purpose = "authentication"
	private_key_ref = "op://Machine Credentials/workstation-ssh/private-key"
fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

[[ssh_profiles.automation.keys]]
purpose = "signing"
	private_key_ref = "op://Machine Credentials/workstation-signing/private-key"
fingerprint = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
"#,
    )
    .unwrap();
    assert_eq!(config.version, 1);
    assert_eq!(config.credential_store.service, "example-credential-broker");
    assert_eq!(config.credential_store.account, "service-token");
    assert_eq!(config.programs.gh, "/usr/bin/gh");
    assert_eq!(config.github.app_id, 42);
    assert_eq!(
        config.profiles["terraform-plan"].executables,
        ["/usr/bin/terraform"]
    );
    assert_eq!(config.ssh_profiles["automation"].keys.len(), 2);
    assert_eq!(
        config.declared_secret_references(),
        BTreeSet::from([
            "op://Any Vault/contributor-app/private-key".to_owned(),
            "op://Machine Credentials/workstation-signing/private-key".to_owned(),
            "op://Machine Credentials/workstation-ssh/private-key".to_owned(),
            "op://Team Vault/hcp-plan/token".to_owned(),
        ])
    );

    for invalid in [
        br#"version = 1
[github]
app_id = 42
        private_key_ref = "not-op://Personal/key/private-key"
permissions = { contents = "write" }
installations = []
"#
        .as_slice(),
        br#"version = 2
[github]
app_id = 42
private_key_ref = "op://Machine Vault/key/private-key"
permissions = { contents = "write" }
installations = []
"#
        .as_slice(),
        br#"version = 1
unknown = true
[github]
app_id = 42
private_key_ref = "op://Machine Vault/key/private-key"
permissions = { contents = "write" }
installations = []
"#
        .as_slice(),
        br#"version = 1
[github]
app_id = 42
private_key_ref = "op://Machine Vault/key/private-key"
permissions = { actions = "read", administration = "write", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }
[[github.installations]]
owner = "ExampleOrg"
installation_id = 101
repositories = ["sample-repo"]
"#
        .as_slice(),
    ] {
        assert!(parse_config(invalid).is_err());
    }
}

#[test]
fn published_example_is_complete_and_valid() {
    let config = parse_config(include_bytes!("../config.example.toml")).unwrap();
    assert!(config.github.discover_installations);
    assert!(config.github.installations.is_empty());
    assert_eq!(config.profiles.len(), 1);
    assert_eq!(config.ssh_profiles.len(), 1);
    assert_eq!(config.declared_secret_references().len(), 4);
}

#[test]
fn installation_scope_is_exactly_all_or_a_static_allowlist() {
    let base = |installation: &str| {
        format!(
            r#"version = 1
[programs]
op = "/opt/1Password/op"
gh = "/usr/bin/gh"
git = "/usr/bin/git"
ssh_add = "/usr/bin/ssh-add"
ssh_keygen = "/usr/bin/ssh-keygen"
[github]
app_id = 42
private_key_ref = "op://Machine Vault/contributor-app/private-key"
permissions = {{ actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }}
[[github.installations]]
owner = "ExampleOrg"
installation_id = 101
{installation}
"#
        )
    };
    assert!(parse_config(base("all_repositories = true").as_bytes()).is_ok());
    assert!(parse_config(base("repositories = [\"sample-repo\"]").as_bytes()).is_ok());
    assert!(parse_config(
        base("all_repositories = true\nrepositories = [\"sample-repo\"]").as_bytes()
    )
    .is_err());
    assert!(parse_config(base("all_repositories = false").as_bytes()).is_err());

    let dynamic = r#"version = 1
[programs]
op = "/opt/1Password/op"
gh = "/usr/bin/gh"
git = "/usr/bin/git"
ssh_add = "/usr/bin/ssh-add"
ssh_keygen = "/usr/bin/ssh-keygen"
[github]
app_id = 42
private_key_ref = "op://Machine Vault/contributor-app/private-key"
discover_installations = true
permissions = { actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }
"#;
    assert!(parse_config(dynamic.as_bytes()).is_ok());
    assert!(parse_config(
        format!(
            "{dynamic}[[github.installations]]\nowner = \"ExampleOrg\"\ninstallation_id = 101\nall_repositories = true\n"
        )
        .as_bytes()
    )
    .is_err());
}

#[test]
fn credential_bearing_commands_require_exact_absolute_paths() {
    let config = |programs: &str, profile: &str| {
        format!(
            r#"version = 1
[programs]
{programs}
[github]
app_id = 42
private_key_ref = "op://Machine Vault/contributor-app/private-key"
discover_installations = true
permissions = {{ actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }}
{profile}
"#
        )
    };
    let unix_programs = r#"op = "/opt/1Password/op"
gh = "/usr/bin/gh"
git = "/usr/bin/git"
ssh_add = "/usr/bin/ssh-add"
ssh_keygen = "/usr/bin/ssh-keygen""#;
    let windows_programs = r#"op = 'C:\Program Files\1Password CLI\op.exe'
gh = 'C:\Program Files\GitHub CLI\gh.exe'
git = 'C:\Program Files\Git\cmd\git.exe'
ssh_add = 'C:\Windows\System32\OpenSSH\ssh-add.exe'
ssh_keygen = 'C:\Windows\System32\OpenSSH\ssh-keygen.exe'"#;

    assert!(parse_config(config(unix_programs, "").as_bytes()).is_ok());
    assert!(parse_config(config(windows_programs, "").as_bytes()).is_ok());
    assert!(parse_config(
        config(
            unix_programs,
            "[profiles.plan]\nexecutables = [\"/usr/bin/terraform\"]"
        )
        .as_bytes()
    )
    .is_ok());

    for shadowable in ["op", "./op", "bin/op", "..\\op.exe"] {
        let programs = unix_programs.replace(
            "op = \"/opt/1Password/op\"",
            &format!("op = '{}'", shadowable),
        );
        assert!(parse_config(config(&programs, "").as_bytes()).is_err());
    }
    assert!(parse_config(
        config(
            unix_programs,
            "[profiles.plan]\nexecutables = [\"terraform\"]"
        )
        .as_bytes()
    )
    .is_err());
    assert!(parse_config(
        config(
            unix_programs,
            "[profiles.plan]\nexecutables = [\".\\\\terraform.exe\"]"
        )
        .as_bytes()
    )
    .is_err());
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
        ("ExampleOrg/sample-repo", ("ExampleOrg", "sample-repo")),
        (
            "https://github.com/ExampleOrg/sample-repo.git",
            ("ExampleOrg", "sample-repo"),
        ),
        (
            "git@github.com:ExampleOrg/sample-repo.git",
            ("ExampleOrg", "sample-repo"),
        ),
        (
            "ssh://git@github.com/ExampleOrg/sample-repo.git",
            ("ExampleOrg", "sample-repo"),
        ),
    ] {
        assert_eq!(
            parse_github_repository(source).unwrap(),
            (expected.0.to_owned(), expected.1.to_owned())
        );
    }
    for invalid in [
        "https://example.com/ExampleOrg/sample-repo.git",
        "ExampleOrg/sample-repo/extra",
        "ExampleOrg/..",
        "./sample-repo",
        "github.com/ExampleOrg/sample-repo",
        "https://github.com/ExampleOrg/sample-repo?token=secret",
    ] {
        assert!(parse_github_repository(invalid).is_err());
    }
}

#[test]
fn gh_surface_is_repository_scoped_and_excludes_administration() {
    for accepted in [
        vec!["pr", "list"],
        vec!["pr", "create", "-R", "ExampleOrg/sample-repo"],
        vec!["run", "view"],
        vec!["workflow", "list"],
        vec!["release", "download"],
        vec!["repo", "view"],
    ] {
        assert!(admit_gh_arguments(&accepted).is_ok(), "{accepted:?}");
    }
    for rejected in [
        vec!["auth", "login"],
        vec!["api", "user"],
        vec!["repo", "create"],
        vec!["repo", "clone"],
        vec!["repo", "delete"],
        vec!["workflow", "run"],
        vec!["secret", "set"],
        vec!["variable", "set"],
        vec!["issue", "create"],
        vec!["status"],
        vec!["repo", "view", "--web"],
        vec!["pr", "view", "-w"],
        vec!["pr", "create", "--editor"],
        vec!["pr", "close", "42", "--delete-branch"],
        vec!["pr", "close", "42", "-d"],
        vec!["pr", "merge", "42", "--delete-branch=false"],
        vec!["pr", "merge", "42", "-d=false"],
    ] {
        assert!(admit_gh_arguments(&rejected).is_err(), "{rejected:?}");
    }
}
