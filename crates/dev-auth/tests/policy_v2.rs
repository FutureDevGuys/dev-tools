use dev_auth::policy_v2::{
    parse_system_policy_v2, parse_user_config_v2, require_system_policy_narrows, resolve_policy,
    InvalidSessionRouting, NoSessionRouting, Permission, SandboxMode, SystemMode, WorkspaceAccess,
};
use dev_auth::RepositorySelection;
use std::collections::{BTreeMap, BTreeSet};

const SYSTEM_POLICY: &str = r#"
version = 2
mode = "strong"
allowed_users = ["automation"]

[programs]
op = "/usr/bin/op"
git = "/usr/bin/git"
gh = "/usr/bin/gh"
ssh = "/usr/bin/ssh"
ssh_keygen = "/usr/bin/ssh-keygen"

[trusted_launchers]
agent = "/opt/dev-auth/bin/agent"

[sandbox_adapters.bubblewrap]
executable = "/usr/bin/bwrap"
arguments = ["--ro-bind", "/", "/", "--dev-bind", "/dev", "/dev", "--proc", "/proc", "--share-net"]
argument_separator = true
launcher_visibility = "required"
broker_socket_visibility = "required"
peer_identity = "preserve"
cgroup_identity = "retain"
descendant_containment = "retain"
network_namespace = "inherit"
workspace_mounts = "requested"
read_only_mount_arguments = ["--ro-bind", "{path}", "{path}"]
read_write_mount_arguments = ["--bind", "{path}", "{path}"]

[github_apps.automation]
app_id = 42
repository_selection = "selected"
private_key_references = ["op://Machine Vault/github-app/private-key"]

[credential_slots.automation]
users = ["automation"]
authority_caps = ["release"]
secret_references = ["op://Machine Vault/github-app/private-key", "op://Machine Vault/release/token", "op://Machine Vault/release/ssh-private-key", "op://Machine Vault/release/manifest-private-key"]

[authority_caps.release]
github_apps = ["automation"]
owners = ["ExampleOrg", "SecondOrg"]
repositories = ["api", "website"]
permissions = { contents = "write", metadata = "read", pull_requests = "write" }
installation_ids = [101, 102]
signing = true
release_signing_products = ["dev-auth", "update-all"]
release_signing_keys = [{ private_key_ref = "op://Machine Vault/release/manifest-private-key", public_key = "11686a3552e97ca8d717b24007da01716c308dd526340e50a15461f400850072" }]
ssh = true
git_identities = [{ name = "Automation Agent", email = "automation@example.invalid" }]
secret_references = ["op://Machine Vault/github-app/private-key", "op://Machine Vault/release/token", "op://Machine Vault/release/ssh-private-key", "op://Machine Vault/release/manifest-private-key"]

[workspace_caps.source]
path = "/srv/source"
access = "read_only"
"#;

const USER_CONFIG: &str = r#"
version = 2

[routing]
help_footer = true

[authority_profiles.publish]
cap = "release"
signing = false
release_signing_products = ["dev-auth"]
release_signing_key = { private_key_ref = "op://Machine Vault/release/manifest-private-key", public_key = "11686a3552e97ca8d717b24007da01716c308dd526340e50a15461f400850072" }
ssh = true
git_identity = { name = "Automation Agent", email = "automation@example.invalid" }
secret_references = ["op://Machine Vault/release/token", "op://Machine Vault/release/ssh-private-key", "op://Machine Vault/release/manifest-private-key"]
ssh_keys = [{ private_key_ref = "op://Machine Vault/release/ssh-private-key", public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPuruylR5Dw9TRBXnt/aS8+Sj1dH3mUEcqFz8iItXZaZ dev-auth-policy-test", fingerprint = "SHA256:5QH+7oUNO/MqyIzx8cLnowDLL1ZieiobwK9fp361KnI" }]

[authority_profiles.publish.github]
app_cap = "automation"
private_key_ref = "op://Machine Vault/github-app/private-key"
owners = ["exampleorg"]
repositories = ["api"]
permissions = { contents = "write", metadata = "read" }

[[workloads]]
name = "release-agent"
launcher = "agent"
profile = "publish"
secret_references = []
workspace_roots = [{ cap = "source", path = "/srv/source/api", access = "read_only" }]

[workloads.sandbox]
mode = "required"
adapters = ["bubblewrap"]
"#;

#[test]
fn published_v2_examples_parse_and_resolve_together() {
    let system = parse_system_policy_v2(include_bytes!("../policy-v2.example.toml")).unwrap();
    let user = parse_user_config_v2(include_bytes!("../config-v2.example.toml")).unwrap();
    let resolved = resolve_policy(&system, &user).unwrap();
    assert_eq!(resolved.mode, SystemMode::Strong);
    assert!(resolved.workloads.contains_key("automation-agent"));
}

#[test]
fn published_user_only_policy_example_is_explicitly_degraded_and_resolves() {
    let policy = parse_system_policy_v2(include_bytes!("../policy-v2-user-only.example.toml"))
        .expect("published user-only policy example must parse");
    let user = parse_user_config_v2(include_bytes!("../config-v2.example.toml"))
        .expect("published user config example must parse");
    assert_eq!(policy.mode, SystemMode::UserOnly);
    let resolved =
        resolve_policy(&policy, &user).expect("published user-only examples must resolve");
    assert_eq!(resolved.mode, SystemMode::UserOnly);
    assert!(resolved.workloads.contains_key("automation-agent"));
}

#[test]
fn per_user_policy_must_narrow_the_administrator_policy() {
    let administrator = parse_system_policy_v2(
        SYSTEM_POLICY
            .replace("mode = \"strong\"", "mode = \"user_only\"")
            .as_bytes(),
    )
    .unwrap();
    let narrowed = parse_system_policy_v2(
        SYSTEM_POLICY
            .replace("mode = \"strong\"", "mode = \"user_only\"")
            .replace(
                "owners = [\"ExampleOrg\", \"SecondOrg\"]",
                "owners = [\"ExampleOrg\"]",
            )
            .replace(
                "repositories = [\"api\", \"website\"]",
                "repositories = [\"api\"]",
            )
            .replace("installation_ids = [101, 102]", "installation_ids = [101]")
            .replace("signing = true", "signing = false")
            .as_bytes(),
    )
    .unwrap();
    require_system_policy_narrows(&administrator, &narrowed).unwrap();

    for wider in [
        SYSTEM_POLICY
            .replace("mode = \"strong\"", "mode = \"user_only\"")
            .replace("git = \"/usr/bin/git\"", "git = \"/usr/local/bin/git\""),
        SYSTEM_POLICY
            .replace("mode = \"strong\"", "mode = \"user_only\"")
            .replace(
                "owners = [\"ExampleOrg\", \"SecondOrg\"]",
                "owners = [\"ExampleOrg\", \"SecondOrg\", \"OtherOrg\"]",
            ),
        SYSTEM_POLICY
            .replace("mode = \"strong\"", "mode = \"user_only\"")
            .replace("metadata = \"read\"", "metadata = \"write\""),
        SYSTEM_POLICY
            .replace("mode = \"strong\"", "mode = \"user_only\"")
            .replace("path = \"/srv/source\"", "path = \"/etc\""),
        SYSTEM_POLICY
            .replace("mode = \"strong\"", "mode = \"user_only\"")
            .replace("\"--share-net\"", "\"--unshare-net\""),
    ] {
        let wider = parse_system_policy_v2(wider.as_bytes()).unwrap();
        assert!(require_system_policy_narrows(&administrator, &wider).is_err());
    }
}

#[test]
fn resolves_strict_policy_with_compatibility_defaults_and_narrowed_authority() {
    let system = parse_system_policy_v2(SYSTEM_POLICY.as_bytes()).unwrap();
    let user = parse_user_config_v2(USER_CONFIG.as_bytes()).unwrap();
    let resolved = resolve_policy(&system, &user).unwrap();

    assert_eq!(resolved.mode, SystemMode::Strong);
    let publish = resolved.authority_profiles.get("publish").unwrap();
    assert_eq!(
        publish.release_signing_products,
        BTreeSet::from(["dev-auth".to_owned()])
    );
    assert!(publish.release_signing_key.is_some());
    assert_eq!(
        resolved.routing.no_session,
        NoSessionRouting::NativePassthrough
    );
    assert_eq!(
        resolved.routing.invalid_session,
        InvalidSessionRouting::Deny
    );
    assert_eq!(resolved.routing.help_footer, Some(true));
    let github = resolved.authority_profiles["publish"]
        .github
        .as_ref()
        .unwrap();
    assert_eq!(github.app_id, 42);
    assert_eq!(github.app_cap, "automation");
    assert_eq!(github.repository_selection, RepositorySelection::Selected);
    assert_eq!(
        github.private_key_ref,
        "op://Machine Vault/github-app/private-key"
    );
    assert_eq!(
        resolved.trusted_launchers["agent"],
        "/opt/dev-auth/bin/agent"
    );

    let profile = &resolved.authority_profiles["publish"];
    assert_eq!(profile.system_cap, "release");
    assert_eq!(profile.credential_slot, "automation");
    let github = profile.github.as_ref().unwrap();
    assert_eq!(github.owners, BTreeSet::from(["exampleorg".to_owned()]));
    assert_eq!(github.repositories, BTreeSet::from(["api".to_owned()]));
    assert_eq!(
        github.permissions,
        BTreeMap::from([
            ("contents".to_owned(), Permission::Write),
            ("metadata".to_owned(), Permission::Read),
        ])
    );
    assert!(!profile.signing);
    assert!(profile.ssh);
    assert_eq!(
        profile.git_identity.as_ref().unwrap().email,
        "automation@example.invalid"
    );
    assert_eq!(github.installation_ids, BTreeSet::from([101, 102]));

    let workload = &resolved.workloads["release-agent"];
    assert_eq!(workload.launcher, "agent");
    assert_eq!(workload.launcher_path, "/opt/dev-auth/bin/agent");
    assert_eq!(workload.authority_profile, "publish");
    assert_eq!(workload.sandbox.mode, SandboxMode::Required);
    assert_eq!(workload.secret_references, Vec::<String>::new());
    assert_eq!(workload.workspace_roots[0].system_cap, "source");
    assert_eq!(workload.workspace_roots[0].path, "/srv/source/api");
    assert_eq!(
        workload.workspace_roots[0].access,
        WorkspaceAccess::ReadOnly
    );
    assert_eq!(workload.sandbox.adapters, ["bubblewrap"]);
    let adapter = &resolved.sandbox_adapters["bubblewrap"];
    assert_eq!(
        adapter.launcher_visibility,
        dev_auth::policy_v2::SandboxVisibility::Required
    );
    assert_eq!(
        adapter.broker_socket_visibility,
        dev_auth::policy_v2::SandboxVisibility::Required
    );
    assert_eq!(
        adapter.peer_identity,
        dev_auth::policy_v2::SandboxPeerIdentity::Preserve
    );
    assert_eq!(
        adapter.cgroup_identity,
        dev_auth::policy_v2::SandboxCgroupIdentity::Retain
    );
    assert_eq!(
        adapter.descendant_containment,
        dev_auth::policy_v2::SandboxDescendantContainment::Retain
    );
    assert_eq!(
        adapter.network_namespace,
        dev_auth::policy_v2::SandboxNetworkNamespace::Inherit
    );
    assert_eq!(
        adapter.workspace_mounts,
        dev_auth::policy_v2::SandboxWorkspaceMounts::Requested
    );
    assert_eq!(
        adapter.read_only_mount_arguments,
        ["--ro-bind", "{path}", "{path}"]
    );
    assert_eq!(
        adapter.read_write_mount_arguments,
        ["--bind", "{path}", "{path}"]
    );
}

#[test]
fn release_manifest_signing_is_distinct_from_git_signing_authority() {
    let system = parse_system_policy_v2(SYSTEM_POLICY.as_bytes()).unwrap();
    let git_key_for_release = USER_CONFIG.replace(
        "release_signing_key = { private_key_ref = \"op://Machine Vault/release/manifest-private-key\"",
        "release_signing_key = { private_key_ref = \"op://Machine Vault/release/ssh-private-key\"",
    );
    let git_key_for_release = parse_user_config_v2(git_key_for_release.as_bytes()).unwrap();
    assert!(resolve_policy(&system, &git_key_for_release).is_err());

    let without_release_key = USER_CONFIG
        .lines()
        .filter(|line| !line.starts_with("release_signing_key = "))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(parse_user_config_v2(without_release_key.as_bytes()).is_err());

    let git_only = USER_CONFIG
        .lines()
        .filter(|line| {
            !line.starts_with("release_signing_products = ")
                && !line.starts_with("release_signing_key = ")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let git_only = parse_user_config_v2(git_only.as_bytes()).unwrap();
    let resolved = resolve_policy(&system, &git_only).unwrap();
    let publish = resolved.authority_profiles.get("publish").unwrap();
    assert!(publish.release_signing_key.is_none());
    assert!(publish.release_signing_products.is_empty());
}

#[test]
fn routing_is_native_without_a_session_and_never_allows_invalid_passthrough() {
    let default_footer = parse_user_config_v2(
        USER_CONFIG
            .replace("[routing]\nhelp_footer = true\n\n", "")
            .as_bytes(),
    )
    .unwrap();
    assert_eq!(default_footer.routing.help_footer, None);

    let unsafe_input = USER_CONFIG.replace(
        "help_footer = true",
        "help_footer = true\ninvalid_session = \"native_passthrough\"",
    );
    assert!(parse_user_config_v2(unsafe_input.as_bytes()).is_err());

    let legacy_workspace_routing = USER_CONFIG.replace(
        "help_footer = true",
        "help_footer = true\nno_session = \"workspace_compatibility\"",
    );
    assert!(parse_user_config_v2(legacy_workspace_routing.as_bytes()).is_err());
}

#[test]
fn strict_parsers_reject_unknown_duplicate_and_unsafe_inputs() {
    let cases = [
        SYSTEM_POLICY.replace("mode = \"strong\"", "mode = \"strong\"\nunknown = true"),
        SYSTEM_POLICY.replace(
            "allowed_users = [\"automation\"]",
            "allowed_users = [\"automation\", \"AUTOMATION\"]",
        ),
        SYSTEM_POLICY.replace(
            "agent = \"/opt/dev-auth/bin/agent\"",
            "agent = \"relative/agent\"",
        ),
        SYSTEM_POLICY.replace(
            "secret_references = [\"op://Machine Vault/github-app/private-key\", \"op://Machine Vault/release/token\", \"op://Machine Vault/release/ssh-private-key\", \"op://Machine Vault/release/manifest-private-key\"]",
            "secret_references = [\"plaintext-secret\"]",
        ),
    ];
    for invalid in cases {
        assert!(
            parse_system_policy_v2(invalid.as_bytes()).is_err(),
            "unexpectedly accepted:\n{invalid}"
        );
    }

    let missing_repository_selection = SYSTEM_POLICY
        .lines()
        .filter(|line| !line.starts_with("repository_selection = "))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(parse_system_policy_v2(missing_repository_selection.as_bytes()).is_err());

    let user_cases = [
        USER_CONFIG.replace(
            "app_cap = \"automation\"",
            "app_cap = \"automation\"\nunknown = true",
        ),
        USER_CONFIG.replace(
            "workspace_roots = [{ cap = \"source\", path = \"/srv/source/api\", access = \"read_only\" }]",
            "workspace_roots = [{ cap = \"source\", path = \"/srv/source/api\", access = \"read_only\" }, { cap = \"source\", path = \"/srv/source/api\", access = \"read_only\" }]",
        ),
        USER_CONFIG.replace("name = \"release-agent\"", "name = \"release-agent\nspoof\""),
        USER_CONFIG.replace("name = \"release-agent\"", "name = \"git\""),
    ];
    for invalid in user_cases {
        assert!(
            parse_user_config_v2(invalid.as_bytes()).is_err(),
            "unexpectedly accepted:\n{invalid}"
        );
    }
}

#[test]
fn workload_workspace_root_count_is_bounded() {
    let roots = (0..65)
        .map(|index| {
            format!(
                "{{ cap = \"source\", path = \"/srv/source/root-{index}\", access = \"read_only\" }}"
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let input = USER_CONFIG.replace(
        "workspace_roots = [{ cap = \"source\", path = \"/srv/source/api\", access = \"read_only\" }]",
        &format!("workspace_roots = [{roots}]"),
    );

    let error = parse_user_config_v2(input.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("at most 64 workspace roots"));
}

#[test]
fn user_configuration_cannot_select_an_uncapped_github_app_or_key() {
    let system = parse_system_policy_v2(SYSTEM_POLICY.as_bytes()).unwrap();
    for invalid in [
        USER_CONFIG.replace("app_cap = \"automation\"", "app_cap = \"other\""),
        USER_CONFIG.replace(
            "private_key_ref = \"op://Machine Vault/github-app/private-key\"",
            "private_key_ref = \"op://Machine Vault/other/private-key\"",
        ),
    ] {
        let user = parse_user_config_v2(invalid.as_bytes()).unwrap();
        assert!(resolve_policy(&system, &user).is_err());
    }
}

#[test]
fn credential_slots_bind_users_caps_and_secret_references() {
    let system = parse_system_policy_v2(SYSTEM_POLICY.as_bytes()).unwrap();
    let user = parse_user_config_v2(USER_CONFIG.as_bytes()).unwrap();
    assert!(dev_auth::policy_v2::resolve_policy_for_user(&system, "automation", &user).is_ok());
    assert!(dev_auth::policy_v2::resolve_policy_for_user(&system, "other-user", &user).is_err());

    for invalid in [
        SYSTEM_POLICY.replace(
            "[credential_slots.automation]\nusers = [\"automation\"]",
            "[credential_slots.automation]\nusers = [\"other-user\"]",
        ),
        SYSTEM_POLICY.replace("authority_caps = [\"release\"]", "authority_caps = [\"other\"]"),
        SYSTEM_POLICY.replace(
            "secret_references = [\"op://Machine Vault/github-app/private-key\", \"op://Machine Vault/release/token\", \"op://Machine Vault/release/ssh-private-key\", \"op://Machine Vault/release/manifest-private-key\"]\n\n[authority_caps.release]",
            "secret_references = [\"op://Machine Vault/github-app/private-key\"]\n\n[authority_caps.release]",
        ),
    ] {
        assert!(parse_system_policy_v2(invalid.as_bytes()).is_err());
    }
}

#[test]
fn resolution_rejects_every_user_authority_expansion() {
    let system = parse_system_policy_v2(SYSTEM_POLICY.as_bytes()).unwrap();
    for invalid in [
        USER_CONFIG.replace("owners = [\"exampleorg\"]", "owners = [\"OtherOrg\"]"),
        USER_CONFIG.replace("repositories = [\"api\"]", "repositories = [\"unknown\"]"),
        USER_CONFIG.replace(
            "email = \"automation@example.invalid\"",
            "email = \"human@example.invalid\"",
        ),
        USER_CONFIG.replace("repositories = [\"api\"]", "repositories = []"),
        USER_CONFIG.replace(
            "permissions = { contents = \"write\", metadata = \"read\" }",
            "permissions = { contents = \"write\", metadata = \"write\" }",
        ),
    ] {
        let user = parse_user_config_v2(invalid.as_bytes()).unwrap();
        assert!(
            resolve_policy(&system, &user).is_err(),
            "unexpectedly resolved:\n{invalid}"
        );
    }

    let system_without_signing = parse_system_policy_v2(
        SYSTEM_POLICY
            .replace("signing = true", "signing = false")
            .as_bytes(),
    )
    .unwrap();
    let user_with_signing = parse_user_config_v2(
        USER_CONFIG
            .replace(
                "signing = false",
                "signing = true\nsigning_key = { private_key_ref = \"op://Machine Vault/release/ssh-private-key\", public_key = \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPuruylR5Dw9TRBXnt/aS8+Sj1dH3mUEcqFz8iItXZaZ dev-auth-policy-test\", fingerprint = \"SHA256:5QH+7oUNO/MqyIzx8cLnowDLL1ZieiobwK9fp361KnI\" }",
            )
            .as_bytes(),
    )
    .unwrap();
    assert!(resolve_policy(&system_without_signing, &user_with_signing).is_err());
}

#[test]
fn resolution_rejects_untrusted_references_and_sandbox_expansion() {
    let system = parse_system_policy_v2(SYSTEM_POLICY.as_bytes()).unwrap();
    for invalid in [
        USER_CONFIG.replace("launcher = \"agent\"", "launcher = \"other\""),
        USER_CONFIG.replace("profile = \"publish\"", "profile = \"other\""),
        USER_CONFIG.replace("adapters = [\"bubblewrap\"]", "adapters = [\"containerd\"]"),
        USER_CONFIG.replace(
            "secret_references = []",
            "secret_references = [\"op://Machine Vault/other/private-key\"]",
        ),
    ] {
        let user = parse_user_config_v2(invalid.as_bytes()).unwrap();
        assert!(
            resolve_policy(&system, &user).is_err(),
            "unexpectedly resolved:\n{invalid}"
        );
    }
}

#[test]
fn workspace_and_secret_scope_must_narrow_named_admin_caps() {
    let system = parse_system_policy_v2(SYSTEM_POLICY.as_bytes()).unwrap();
    for invalid in [
        USER_CONFIG.replace("cap = \"source\"", "cap = \"other\""),
        USER_CONFIG.replace("path = \"/srv/source/api\"", "path = \"/etc\""),
        USER_CONFIG.replace("access = \"read_only\"", "access = \"read_write\""),
        USER_CONFIG.replace(
            "secret_references = []",
            "secret_references = [\"op://Machine Vault/unapproved/token\"]",
        ),
    ] {
        let user = parse_user_config_v2(invalid.as_bytes()).unwrap();
        assert!(resolve_policy(&system, &user).is_err());
    }
}

#[test]
fn non_github_workloads_do_not_need_an_app_or_private_key() {
    let system_input = SYSTEM_POLICY
        .replace("github_apps = [\"automation\"]\n", "")
        .replace("owners = [\"ExampleOrg\", \"SecondOrg\"]\n", "")
        .replace("repositories = [\"api\", \"website\"]\n", "")
        .replace(
            "permissions = { contents = \"write\", metadata = \"read\", pull_requests = \"write\" }\n",
            "",
        )
        .replace("installation_ids = [101, 102]\n", "");
    let user_input = USER_CONFIG
        .replace(
            "\n[authority_profiles.publish.github]\napp_cap = \"automation\"\nprivate_key_ref = \"op://Machine Vault/github-app/private-key\"\nowners = [\"exampleorg\"]\nrepositories = [\"api\"]\npermissions = { contents = \"write\", metadata = \"read\" }\n",
            "\n",
        );
    let system = parse_system_policy_v2(system_input.as_bytes()).unwrap();
    let user = parse_user_config_v2(user_input.as_bytes()).unwrap();
    let resolved = resolve_policy(&system, &user).unwrap();
    assert!(resolved.authority_profiles["publish"].github.is_none());
    assert!(resolved.authority_profiles["publish"].ssh);
}

#[test]
fn workload_may_request_no_filesystem_authority() {
    let system = parse_system_policy_v2(SYSTEM_POLICY.as_bytes()).unwrap();
    let user = parse_user_config_v2(
        USER_CONFIG
            .replace(
                "workspace_roots = [{ cap = \"source\", path = \"/srv/source/api\", access = \"read_only\" }]",
                "workspace_roots = []",
            )
            .as_bytes(),
    )
    .unwrap();
    let resolved = resolve_policy(&system, &user).unwrap();
    assert!(resolved.workloads["release-agent"]
        .workspace_roots
        .is_empty());
}

#[test]
fn sandbox_modes_have_fail_closed_adapter_contracts() {
    let system = parse_system_policy_v2(SYSTEM_POLICY.as_bytes()).unwrap();
    let none_with_adapter = USER_CONFIG.replace("mode = \"required\"", "mode = \"none\"");
    assert!(parse_user_config_v2(none_with_adapter.as_bytes()).is_err());

    let required_without_adapter =
        USER_CONFIG.replace("adapters = [\"bubblewrap\"]", "adapters = []");
    assert!(parse_user_config_v2(required_without_adapter.as_bytes()).is_err());

    let auto_without_adapter =
        required_without_adapter.replace("mode = \"required\"", "mode = \"auto\"");
    let user = parse_user_config_v2(auto_without_adapter.as_bytes()).unwrap();
    assert!(resolve_policy(&system, &user).is_ok());

    let user_only = parse_system_policy_v2(
        SYSTEM_POLICY
            .replace("mode = \"strong\"", "mode = \"user_only\"")
            .as_bytes(),
    )
    .unwrap();
    assert!(resolve_policy(&user_only, &user).is_ok());

    let none_without_adapter =
        required_without_adapter.replace("mode = \"required\"", "mode = \"none\"");
    let none = parse_user_config_v2(none_without_adapter.as_bytes()).unwrap();
    assert!(resolve_policy(&system, &none).is_ok());
    assert!(resolve_policy(&user_only, &none).is_ok());

    assert!(parse_system_policy_v2(
        SYSTEM_POLICY
            .replace("[sandbox_adapters.bubblewrap]", "[sandbox_adapters.native]")
            .as_bytes()
    )
    .is_err());

    for invalid in [
        SYSTEM_POLICY.replace("launcher_visibility = \"required\"\n", ""),
        SYSTEM_POLICY.replace("broker_socket_visibility = \"required\"\n", ""),
        SYSTEM_POLICY.replace(
            "peer_identity = \"preserve\"",
            "peer_identity = \"translate\"",
        ),
        SYSTEM_POLICY.replace(
            "cgroup_identity = \"retain\"",
            "cgroup_identity = \"escape\"",
        ),
        SYSTEM_POLICY.replace(
            "descendant_containment = \"retain\"",
            "descendant_containment = \"detach\"",
        ),
        SYSTEM_POLICY.replace("workspace_mounts = \"requested\"\n", ""),
        SYSTEM_POLICY.replace(
            "read_only_mount_arguments = [\"--ro-bind\", \"{path}\", \"{path}\"]",
            "read_only_mount_arguments = [\"--ro-bind\", \"/tmp\", \"/tmp\"]",
        ),
        SYSTEM_POLICY.replace(
            "read_write_mount_arguments = [\"--bind\", \"{path}\", \"{path}\"]",
            "read_write_mount_arguments = [\"--bind\", \"{other}\", \"{other}\"]",
        ),
    ] {
        assert!(parse_system_policy_v2(invalid.as_bytes()).is_err());
    }
}

#[test]
fn resolution_revalidates_public_input_models() {
    let system = parse_system_policy_v2(SYSTEM_POLICY.as_bytes()).unwrap();
    let user = parse_user_config_v2(USER_CONFIG.as_bytes()).unwrap();

    let mut mutated_system = system.clone();
    mutated_system
        .trusted_launchers
        .insert("agent".into(), "relative/agent".into());
    assert!(resolve_policy(&mutated_system, &user).is_err());

    let mut mutated_user = user.clone();
    mutated_user.workloads[0].name = "release-agent\nspoof".into();
    assert!(resolve_policy(&system, &mutated_user).is_err());
}

#[test]
fn version_and_mode_are_exact_contracts() {
    assert!(parse_system_policy_v2(
        SYSTEM_POLICY
            .replace("version = 2", "version = 1")
            .as_bytes()
    )
    .is_err());
    assert!(
        parse_user_config_v2(USER_CONFIG.replace("version = 2", "version = 1").as_bytes()).is_err()
    );
    assert!(parse_system_policy_v2(
        SYSTEM_POLICY
            .replace("mode = \"strong\"", "mode = \"root\"")
            .as_bytes()
    )
    .is_err());
}
