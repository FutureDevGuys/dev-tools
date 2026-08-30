use dev_auth::{
    admit_gh_arguments, admit_git_arguments, parse_config, parse_github_repository,
    render_git_credential, sanitize_environment, CacheEntry, CredentialRequest, GitHubInstallation,
    GitHubProfile, RepositorySelection, SecretString,
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
        repository_selection: RepositorySelection::Selected,
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
        repository_selection: RepositorySelection::All,
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
    assert!(entry.is_usable_for_repository_at(
        1,
        42,
        101,
        "exampleorg",
        "sample-repo",
        &entry.permissions
    ));
    assert!(!entry.is_usable_for_repository_at(
        1,
        42,
        999,
        "exampleorg",
        "sample-repo",
        &entry.permissions
    ));
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

[git]
workspace_roots = ["~/repos", "/srv/automation"]
author_name = "Example Automation"
author_email = "automation@example.invalid"
ssh_profile = "automation"

[github]
app_id = 42
	private_key_ref = "op://Any Vault/contributor-app/private-key"
repository_selection = "selected"
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
        config.github.repository_selection,
        RepositorySelection::Selected
    );
    assert_eq!(
        config.profiles["terraform-plan"].executables,
        ["/usr/bin/terraform"]
    );
    assert_eq!(config.ssh_profiles["automation"].keys.len(), 2);
    let git = config.git.as_ref().unwrap();
    assert_eq!(git.workspace_roots, ["~/repos", "/srv/automation"]);
    assert_eq!(git.author_name, "Example Automation");
    assert_eq!(git.author_email, "automation@example.invalid");
    assert_eq!(git.ssh_profile, "automation");
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
    assert_eq!(config.github.repository_selection, RepositorySelection::All);
    assert!(config.github.installations.is_empty());
    assert_eq!(config.profiles.len(), 1);
    assert_eq!(config.ssh_profiles.len(), 1);
    assert!(config.git.is_some());
    assert_eq!(config.declared_secret_references().len(), 4);
}

#[test]
fn home_relative_workspace_roots_cannot_become_windows_or_alternate_paths() {
    let example = include_str!("../config.example.toml");
    for invalid_root in [
        "~/C:/Windows",
        "~/C:\\Windows",
        "~/../repos",
        "~/repos/./nested",
        "~/repos//nested",
    ] {
        let invalid = example.replace("~/repos", invalid_root);
        assert!(
            parse_config(invalid.as_bytes()).is_err(),
            "accepted {invalid_root}"
        );
    }
}

#[test]
fn execution_profiles_cannot_override_private_sandbox_variables() {
    let example = include_str!("../config.example.toml");
    for variable in ["PATH", "home", "XDG_CONFIG_HOME", "Temp"] {
        let invalid = example.replace("TF_TOKEN_app_terraform_io", variable);
        let error = parse_config(invalid.as_bytes()).unwrap_err().to_string();
        assert!(error.contains("conflicts with the private sandbox"));
    }
}

#[test]
fn installation_scope_is_exactly_all_or_a_static_allowlist() {
    let base = |selection: &str, installation: &str| {
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
repository_selection = "{selection}"
permissions = {{ actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }}
[[github.installations]]
owner = "ExampleOrg"
installation_id = 101
{installation}
"#
        )
    };
    assert!(parse_config(base("all", "all_repositories = true").as_bytes()).is_ok());
    assert!(parse_config(base("selected", "repositories = [\"sample-repo\"]").as_bytes()).is_ok());
    assert!(parse_config(
        base(
            "all",
            "all_repositories = true\nrepositories = [\"sample-repo\"]"
        )
        .as_bytes()
    )
    .is_err());
    assert!(parse_config(base("selected", "all_repositories = false").as_bytes()).is_err());
    assert!(parse_config(base("all", "repositories = [\"sample-repo\"]").as_bytes()).is_err());
    assert!(parse_config(base("selected", "all_repositories = true").as_bytes()).is_err());

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
repository_selection = "all"
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
repository_selection = "all"
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
        vec![
            "pr",
            "create",
            "-R",
            "ExampleOrg/sample-repo",
            "--head",
            "automation/change",
            "--base",
            "main",
            "--title",
            "Bounded change",
            "--body",
            "Reviewed body",
        ],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--base=main",
            "--title=Bounded change",
            "--body-file=-",
        ],
        vec![
            "pr",
            "create",
            "-H",
            "automation/change",
            "-B",
            "main",
            "-t",
            "Bounded change",
            "-F",
            "-",
        ],
        vec!["run", "view", "42"],
        vec!["workflow", "list"],
        vec!["release", "view", "v1.0.0"],
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
        vec!["run", "download"],
        vec!["release", "download"],
        vec!["secret", "set"],
        vec!["variable", "set"],
        vec!["issue", "create"],
        vec!["status"],
        vec!["repo", "view", "--web"],
        vec!["pr", "view", "-w"],
        vec!["pr", "create", "--editor"],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--title=Bounded change",
            "--body=Reviewed body",
            "-dF/proc/self/environ",
        ],
        vec!["pr", "view", "42", "-wc"],
        vec!["run", "view", "42", "-wv"],
        vec!["workflow", "view", "build", "-wy"],
        vec!["repo", "view", "-wbmain"],
        vec!["repo", "view", "-RExampleOrg/sample-repo"],
        vec!["repo", "view", "-R=ExampleOrg/sample-repo"],
        vec!["repo", "view", "-w=true"],
        vec!["repo", "view", "--"],
        vec!["pr", "create"],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--title=Bounded change",
            "--body=Reviewed body",
        ],
        vec![
            "pr",
            "create",
            "--title",
            "Bounded change",
            "--body",
            "Reviewed body",
        ],
        vec![
            "pr",
            "create",
            "--head",
            "automation/change",
            "--body",
            "Reviewed body",
        ],
        vec![
            "pr",
            "create",
            "--head",
            "automation/change",
            "--title",
            "Bounded change",
        ],
        vec![
            "pr",
            "create",
            "--head",
            "automation/change",
            "--title",
            "Bounded change",
            "--body",
            "Reviewed body",
            "--body-file",
            "reviewed.md",
        ],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--title=Bounded change",
            "--body-file=reviewed.md",
        ],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--title=Bounded change",
            "--body-file=/proc/self/environ",
        ],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--title=Bounded change",
            "--body-file=symlink-to-private-file",
        ],
        vec![
            "pr",
            "create",
            "--head",
            "automation/change",
            "--head=automation/other",
            "--title",
            "Bounded change",
            "--body",
            "Reviewed body",
        ],
        vec![
            "pr",
            "create",
            "--head",
            "automation/change",
            "--title=Bounded change",
            "-t",
            "Other title",
            "--body",
            "Reviewed body",
        ],
        vec![
            "pr",
            "create",
            "--head=",
            "--title=Bounded change",
            "--body=Reviewed body",
        ],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--title=",
            "--body=Reviewed body",
        ],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--base=main",
            "--title=Bounded change",
            "--body=Reviewed body",
            "--dry-run",
        ],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--base=main",
            "--title=Bounded change",
            "--body=Reviewed body",
            "--fill",
        ],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--base=main",
            "--title=Bounded change",
            "--body=Reviewed body",
            "--fill-first",
        ],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--base=main",
            "--title=Bounded change",
            "--body=Reviewed body",
            "--fill-verbose",
        ],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--base=main",
            "--title=Bounded change",
            "--body=Reviewed body",
            "-f",
        ],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--base=main",
            "--title=Bounded change",
            "--body=Reviewed body",
            "--recover",
            "recovery-token",
        ],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--base=main",
            "--title=Bounded change",
            "--body=Reviewed body",
            "--template",
            "pull_request.md",
        ],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--base=main",
            "--title=Bounded change",
            "--body=Reviewed body",
            "-e",
        ],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--base=main",
            "--title=Bounded change",
            "--body=Reviewed body",
            "-dw",
        ],
        vec!["pr", "close", "42", "--delete-branch"],
        vec!["pr", "close", "42", "-d"],
        vec!["pr", "merge", "42", "--delete-branch=false"],
        vec!["pr", "merge", "42", "-d=false"],
    ] {
        assert!(admit_gh_arguments(&rejected).is_err(), "{rejected:?}");
    }
}

#[test]
fn gh_pull_request_mutations_require_explicit_noninteractive_inputs() {
    for accepted in [
        vec!["pr", "comment", "42", "--body", "Reviewed comment"],
        vec!["pr", "comment", "42", "--body-file=-"],
        vec!["pr", "edit", "42", "--title", "Revised title"],
        vec!["pr", "edit", "42", "--body-file", "-"],
        vec!["pr", "ready", "42"],
        vec!["pr", "review", "42", "--approve"],
        vec![
            "pr",
            "review",
            "42",
            "--comment",
            "--body",
            "Reviewed comment",
        ],
        vec!["pr", "review", "42", "--request-changes", "--body-file=-"],
        vec!["pr", "merge", "42", "--squash"],
        vec!["pr", "merge", "42", "--merge", "--body-file", "-"],
        vec!["pr", "close", "42"],
        vec!["pr", "reopen", "42"],
    ] {
        assert!(admit_gh_arguments(&accepted).is_ok(), "{accepted:?}");
    }

    for rejected in [
        vec!["pr", "comment", "--body", "inferred target"],
        vec!["pr", "comment", "42"],
        vec!["pr", "comment", "42", "--body-file", "reviewed.md"],
        vec!["pr", "comment", "42", "--body-file=/proc/self/environ"],
        vec!["pr", "comment", "42", "--body-file=symlink-to-private-file"],
        vec!["pr", "comment", "42", "--edit-last", "--body", "edited"],
        vec!["pr", "comment", "42", "--delete-last"],
        vec!["pr", "edit", "--title", "inferred target"],
        vec!["pr", "edit", "42"],
        vec!["pr", "edit", "42", "--body-file=reviewed.md"],
        vec!["pr", "review", "--approve"],
        vec!["pr", "review", "42"],
        vec!["pr", "review", "42", "--comment"],
        vec![
            "pr",
            "review",
            "42",
            "--approve",
            "--request-changes",
            "--body",
            "conflicting",
        ],
        vec!["pr", "review", "42", "--approve", "--body-file=reviewed.md"],
        vec!["pr", "review", "42", "-aF/proc/self/environ"],
        vec!["pr", "ready", "--undo"],
        vec!["pr", "merge", "--squash"],
        vec!["pr", "merge", "42"],
        vec!["pr", "merge", "42", "--admin", "--squash"],
        vec!["pr", "merge", "42", "--merge", "--squash"],
        vec!["pr", "merge", "42", "--squash", "--body-file=reviewed.md"],
        vec!["pr", "merge", "42", "-mF/proc/self/environ"],
        vec!["pr", "merge", "42", "--merge", "-dF/reviewed.md"],
        vec!["pr", "close", "42", "-dcTEXT"],
        vec!["pr", "close"],
        vec!["pr", "reopen"],
    ] {
        assert!(admit_gh_arguments(&rejected).is_err(), "{rejected:?}");
    }
}

#[test]
fn gh_pull_request_targets_and_flags_are_fail_closed() {
    for accepted in [
        vec!["pr", "view", "42"],
        vec!["pr", "checks", "42", "--required"],
        vec!["pr", "diff", "42", "--name-only"],
    ] {
        assert!(admit_gh_arguments(&accepted).is_ok(), "{accepted:?}");
    }

    for subcommand in ["view", "checks", "diff"] {
        for selector in [
            "https://github.com/OtherOrg/other-repo/pull/42",
            "feature/branch",
            "0",
            "-1",
        ] {
            let rejected = vec!["pr", subcommand, selector];
            assert!(admit_gh_arguments(&rejected).is_err(), "{rejected:?}");
        }
        let inferred = vec!["pr", subcommand];
        assert!(admit_gh_arguments(&inferred).is_err(), "{inferred:?}");
    }

    for subcommand in [
        "comment", "edit", "ready", "review", "merge", "close", "reopen",
    ] {
        let rejected = vec![
            "pr",
            subcommand,
            "https://github.com/OtherOrg/other-repo/pull/42",
        ];
        assert!(admit_gh_arguments(&rejected).is_err(), "{rejected:?}");
    }

    for rejected in [
        vec!["pr", "list", "--unknown"],
        vec!["pr", "view", "42", "--unknown"],
        vec!["pr", "checks", "42", "--unknown"],
        vec!["pr", "diff", "42", "--allow-escape-sequences"],
        vec!["run", "list", "--unknown"],
        vec!["run", "view", "1", "--unknown"],
        vec!["run", "watch", "1", "--unknown"],
        vec!["workflow", "list", "--unknown"],
        vec!["workflow", "view", "build.yml", "--unknown"],
        vec!["release", "list", "--unknown"],
        vec!["release", "view", "v1.0.0", "--unknown"],
        vec!["repo", "view", "--unknown"],
        vec![
            "pr",
            "create",
            "--head",
            "h",
            "--base",
            "b",
            "--title",
            "t",
            "--body",
            "safe",
            "-dF/proc/self/environ",
        ],
        vec!["pr", "review", "42", "-aF/proc/self/environ"],
        vec!["pr", "merge", "42", "-mF/proc/self/environ"],
        vec!["pr", "close", "42", "-dccomment"],
        vec!["pr", "merge", "42", "--merge", "-dF/proc/self/environ"],
        vec![
            "pr", "create", "--head", "h", "--base", "b", "--title", "t", "--body", "b", "-e",
        ],
        vec![
            "pr", "create", "--head", "h", "--base", "b", "--title", "t", "--body", "b", "-dw",
        ],
        vec!["pr", "view", "42", "-wc"],
        vec!["run", "view", "1", "-wv"],
        vec!["workflow", "view", "1", "-wy"],
        vec!["repo", "view", "-wbmain"],
        vec!["repo", "view", "-w=true"],
        vec!["repo", "view", "-ROtherOrg/other-repo"],
        vec!["repo", "view", "-R=OtherOrg/other-repo"],
    ] {
        assert!(admit_gh_arguments(&rejected).is_err(), "{rejected:?}");
    }
}

#[test]
fn managed_git_surface_is_exact_and_rejects_process_and_authority_escapes() {
    for admitted in [
        vec!["status", "--short"],
        vec!["add", "--", "src/lib.rs"],
        vec!["restore", "--", "src/lib.rs"],
        vec!["branch", "--list"],
        vec!["switch", "feature"],
        vec!["checkout", "feature"],
        vec!["log", "--oneline", "HEAD"],
        vec!["show", "--stat", "HEAD"],
        vec!["commit", "--no-status", "--message", "bounded change"],
        vec!["commit", "--no-status", "--file", "-"],
        vec!["tag", "--message", "release", "v1.2.3"],
        vec![
            "fetch",
            "origin",
            "refs/heads/main:refs/remotes/origin/main",
        ],
        vec!["push", "origin", "HEAD:refs/heads/feature"],
        vec![
            "clone",
            "--no-checkout",
            "https://github.com/ExampleOrg/repository.git",
            "repository",
        ],
        vec![
            "clone",
            "--no-checkout",
            "git@github.com:ExampleOrg/repository.git",
            "nested/repository",
        ],
    ] {
        admit_git_arguments(&admitted).unwrap_or_else(|error| {
            panic!("expected admitted Git arguments {admitted:?}: {error:#}")
        });
    }

    for rejected in [
        vec!["-c", "credential.helper=!human", "status"],
        vec!["-ccore.hooksPath=/tmp/hooks", "status"],
        vec!["--config-env=credential.helper=HELPER", "status"],
        vec!["-C", "/tmp/repository", "status"],
        vec!["--git-dir=/tmp/repository/.git", "status"],
        vec!["--work-tree", "/tmp/repository", "status"],
        vec!["--exec-path=/tmp/bin", "status"],
        vec!["init", "repository"],
        vec!["human-alias"],
        vec!["config", "credential.helper", "!human"],
        vec!["credential", "fill"],
        vec!["submodule", "foreach", "git", "push"],
        vec!["worktree", "add", "../other"],
        vec!["filter-branch", "--tree-filter", "human-command"],
        vec!["difftool", "--extcmd", "human-command"],
        vec!["commit", "--no-gpg-sign", "--message", "unsigned"],
        vec!["commit", "--author", "Human <human@example.com>", "-m", "x"],
        vec!["commit", "--file", "/proc/self/environ"],
        vec!["commit", "--message", "missing no-status"],
        vec![
            "commit",
            "--no-status",
            "--message",
            "one",
            "--message",
            "two",
        ],
        vec!["commit", "--no-status", "--message", "one", "--file", "-"],
        vec!["commit", "--no-status", "--file=-"],
        vec!["commit", "--no-status", "--message", "one", "--status"],
        vec!["commit", "--no-status", "--no-status", "--message", "one"],
        vec!["commit", "--no-status", "--message", "one", "--all"],
        vec!["commit", "--no-status", "--message", "one", "--amend"],
        vec![
            "commit",
            "--no-status",
            "--message",
            "one",
            "--reuse-message",
            "HEAD",
        ],
        vec![
            "commit",
            "--no-status",
            "--message",
            "one",
            "--reedit-message",
            "HEAD",
        ],
        vec![
            "commit",
            "--no-status",
            "--message",
            "one",
            "--fixup",
            "HEAD",
        ],
        vec![
            "commit",
            "--no-status",
            "--message",
            "one",
            "--squash",
            "HEAD",
        ],
        vec!["commit", "--no-status", "--message", "one", "--edit"],
        vec![
            "commit",
            "--no-status",
            "--message",
            "one",
            "--cleanup",
            "strip",
        ],
        vec!["commit", "--no-status", "--message", "one", "--scissors"],
        vec!["commit", "--no-status", "--message", "one", "--no-verify"],
        vec![
            "commit",
            "--no-status",
            "--message",
            "one",
            "--",
            "src/lib.rs",
        ],
        vec!["commit", "--no-status", "--message", "one", "src/lib.rs"],
        vec!["tag", "--no-sign", "v1.2.3"],
        vec!["tag", "--no-sign", "--message", "one", "v1.2.3"],
        vec!["tag", "--local-user", "human", "v1.2.3"],
        vec!["tag", "--message", "one", "--message", "two", "v1.2.3"],
        vec!["tag", "--message", "one", "--file", "-", "v1.2.3"],
        vec!["tag", "--file=-", "v1.2.3"],
        vec!["log", "--ext-diff", "HEAD"],
        vec!["log", "--output=/tmp/leak", "HEAD"],
        vec!["log", "--unknown", "HEAD"],
        vec!["show", "--textconv", "HEAD"],
        vec!["show", "--output", "/tmp/leak", "HEAD"],
        vec!["show", "--unknown", "HEAD"],
        vec!["status", "--pathspec-from-file=/proc/self/environ"],
        vec!["status", "--unknown"],
        vec!["add", "--pathspec-from-file=/proc/self/environ"],
        vec!["add", "src/lib.rs"],
        vec!["restore", "--pathspec-from-file", "/proc/self/environ"],
        vec!["restore", "src/lib.rs"],
        vec!["branch", "--edit-description", "main"],
        vec!["branch", "--unknown"],
        vec!["switch", "--guess", "feature"],
        vec!["switch", "--unknown", "feature"],
        vec!["checkout", "--conflict=merge", "feature"],
        vec!["checkout", "--unknown", "feature"],
        vec!["fetch", "--upload-pack", "human-command", "origin"],
        vec!["push", "--receive-pack=human-command", "origin"],
        vec!["fetch"],
        vec!["fetch", "origin"],
        vec!["fetch", "origin", "main"],
        vec![
            "fetch",
            "origin",
            "+refs/heads/main:refs/remotes/origin/main",
        ],
        vec!["fetch", "origin", ":refs/remotes/origin/main"],
        vec!["fetch", "origin", "refs/heads/main:refs/heads/main"],
        vec!["fetch", "origin", "refs/tags/v1:refs/remotes/origin/v1"],
        vec!["pull", "--ff-only", "origin", "main"],
        vec!["pull", "--ff-only"],
        vec!["push"],
        vec!["push", "origin"],
        vec!["push", "origin", "main"],
        vec!["push", "origin", "+HEAD:refs/heads/feature"],
        vec!["push", "origin", ":refs/heads/main"],
        vec!["push", "origin", "refs/tags/v1:refs/heads/v1"],
        vec!["push", "origin", "refs/heads/main:refs/tags/main"],
        vec!["push", "origin", "HEAD:refs/tags/v1"],
        vec![
            "push",
            "--set-upstream",
            "origin",
            "HEAD:refs/heads/feature",
        ],
        vec!["push", "-u", "origin", "HEAD:refs/heads/feature"],
        vec!["push", "origin", "HEAD:refs/heads/../feature"],
        vec![
            "clone",
            "--config",
            "credential.helper=!human",
            "https://github.com/a/b",
        ],
        vec!["clone", "--template=/tmp/hooks", "https://github.com/a/b"],
        vec!["clone", "--recurse-submodules", "https://github.com/a/b"],
        vec![
            "clone",
            "https://github.com/ExampleOrg/repository",
            "repository",
        ],
        vec![
            "clone",
            "--no-checkout",
            "https://github.com/ExampleOrg/repository",
            "../repository",
        ],
        vec![
            "clone",
            "--no-checkout",
            "https://github.com/ExampleOrg/repository",
            "/tmp/repository",
        ],
        vec![
            "clone",
            "--no-checkout",
            "https://github.com/ExampleOrg/repository",
            ".",
        ],
        vec!["clone", "file:///tmp/repository"],
        vec!["clone", "ssh://example.com/repository"],
        vec!["clone", "http://github.com/ExampleOrg/repository"],
        vec!["clone", "ext::human-command"],
        vec!["clone", "ExampleOrg/repository", "repository"],
        vec!["clone", "https://github.com/ExampleOrg/repository"],
        vec!["push", "https://github.com/OtherOrg/other", "HEAD"],
    ] {
        assert!(
            admit_git_arguments(&rejected).is_err(),
            "unsafe Git arguments were admitted: {rejected:?}"
        );
    }
}
