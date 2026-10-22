//! Public installed-workload composition. No real credentials or host policy.
use super::*;

const CASE: &str = "generic_projection::installed_public_composition_projects_into_native_child";
const CONSUMER: &str = "generic_projection::plain_rust_consumer";

#[test]
fn installed_public_composition_projects_into_native_child() {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    if user.name == "dev-auth-test" {
        run_installed_user_only_validation_child(true);
        return;
    }
    let sandbox = NativeUserSandbox::new();
    let candidate = std::env::var_os("DEV_AUTH_TEST_PRODUCT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_dev-auth")));
    sandbox.install_binary_from(&candidate, &sandbox.root.join("product"));
    let store = enrolled_store::EnrolledStore::start(
        &sandbox.runtime,
        std::collections::BTreeMap::from([
            ("automation".into(), "fixture-enrollment-one".into()),
            ("secondary".into(), "fixture-enrollment-two".into()),
        ]),
    );
    let current = std::env::current_exe().unwrap();
    let output = bounded_output_with_timeout(
        sandbox.command(&current, &sandbox.home).args([
            "--exact",
            CASE,
            "--test-threads=1",
            "--nocapture",
        ]),
        Duration::from_secs(180),
        "installed generic projection composition",
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let observations = store.observations.lock().unwrap();
    assert!(observations.reads.len() > 2);
    assert_eq!(observations.reads.len(), observations.searches.len());
    assert!(
        observations
            .reads
            .chunks_exact(2)
            .all(|pair| pair == ["automation", "secondary"])
    );
    assert_eq!(observations.reads.len() % 2, 0);
}

/// This child is an ordinary native program: it imports no Dev Auth API.
#[test]
fn plain_rust_consumer() {
    let Some(marker) = std::env::var_os("GENERIC_CONSUMER_MARKER") else {
        return;
    };
    let expected = b"fixture-export";
    let mut stdin = Vec::new();
    std::io::stdin().read_to_end(&mut stdin).unwrap();
    assert!(stdin == expected);
    assert!(fs::read("/proc/self/fd/7").unwrap() == expected);
    let path = std::env::var_os("GENERIC_FILE").unwrap();
    assert!(Path::new(&path).starts_with("/proc/self/fd"));
    assert!(fs::read(&path).unwrap() == expected);
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o400);
    assert!(
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|mut file| file.write_all(b"replacement"))
            .is_err()
    );
    assert!(std::env::var_os("GENERIC_TOKEN").unwrap() == "fixture-export");
    assert!(std::env::var_os("OP_SERVICE_ACCOUNT_TOKEN").is_none());
    assert_eq!(nix::unistd::getuid(), nix::unistd::geteuid());
    assert!(!nix::unistd::getuid().is_root());
    assert_eq!(
        std::env::current_dir().unwrap(),
        PathBuf::from(std::env::var_os("GENERIC_EXPECTED_CWD").unwrap())
    );
    assert!(!std::env::args_os().any(|arg| arg == "fixture-export"));
    fs::write(marker, b"consumer started").unwrap();
    println!("generic child stdout");
    eprintln!("generic child stderr");
    std::process::exit(29);
}

fn resource_selection(projections: &[&str]) -> toml::Value {
    toml::Value::Table(toml::map::Map::from_iter([
        ("purposes".into(), toml::Value::Array(vec!["read".into()])),
        (
            "projections".into(),
            toml::Value::Array(projections.iter().map(|value| (*value).into()).collect()),
        ),
    ]))
}

pub(super) fn exercise(paths: &dev_auth::setup::SetupPaths, root: &Path) {
    let installed = paths.bin_dir.join("dev-auth");
    let canonical = fs::canonicalize(&installed).unwrap();
    let config_root = root.parent().unwrap().join(".config/dev-auth");
    let policy_path = config_root.join("policy-v3.toml");
    let config_path = config_root.join("config-v3.toml");
    let mut policy: toml::Value =
        toml::from_str(&fs::read_to_string(&policy_path).unwrap()).unwrap();
    let mut config: toml::Value =
        toml::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    policy["trusted_launchers"]
        .as_table_mut()
        .unwrap()
        .insert("secret-executor".into(), canonical.to_str().unwrap().into());
    policy["workload_caps"]["worker"]["launchers"]
        .as_array_mut()
        .unwrap()
        .push("secret-executor".into());
    let projections = ["stdin", "descriptor", "file", "environment"];
    policy["credentials"]["resource_caps"]["worker"]["resources"]
        .as_table_mut()
        .unwrap()
        .insert("token".into(), resource_selection(&projections));
    config["authority_profiles"]["worker"]["resources"]
        .as_table_mut()
        .unwrap()
        .insert("token".into(), resource_selection(&projections));
    let missing: toml::Value = toml::from_str(
        r#"credential_slot = "automation"
reference = "op://Fixture/Missing/value"
kind = "exportable"
purposes = ["read"]
"#,
    )
    .unwrap();
    policy["credentials"]["resources"]
        .as_table_mut()
        .unwrap()
        .insert("missing-token".into(), missing);
    for table in [
        &mut policy["credentials"]["resource_caps"]["worker"]["resources"],
        &mut config["authority_profiles"]["worker"]["resources"],
    ] {
        table
            .as_table_mut()
            .unwrap()
            .insert("missing-token".into(), resource_selection(&["environment"]));
    }
    for (name, allowed) in [
        ("secret-executor", projections.as_slice()),
        ("narrow-executor", ["stdin"].as_slice()),
    ] {
        let mut workload: toml::Value = toml::from_str(
            r#"name = "placeholder"
launcher = "secret-executor"
profile = "worker"
admission = "enrolled_noninteractive"
duration_seconds = 120
resources = {}
"#,
        )
        .unwrap();
        workload["name"] = name.into();
        let resources = workload["resources"].as_table_mut().unwrap();
        resources.insert("token".into(), resource_selection(allowed));
        resources.insert("missing-token".into(), resource_selection(&["environment"]));
        resources.insert(
            "release".into(),
            config["authority_profiles"]["worker"]["resources"]["release"].clone(),
        );
        config["workloads"].as_array_mut().unwrap().push(workload);
    }
    for (path, value) in [(&policy_path, &policy), (&config_path, &config)] {
        fs::write(path, toml::to_string_pretty(value).unwrap()).unwrap();
    }
    let primary_calls = root.join("op-primary.calls");
    let calls = || fs::read(&primary_calls).unwrap();
    let secondary_calls = root.join("op-secondary.calls");
    let unchanged_secondary = fs::read(&secondary_calls).unwrap();

    let marker = root.join("generic-consumer-marker");
    let inner_result = root.join("generic-inner-result.json");
    let outer_result = root.join("generic-outer-result.json");
    let mut success = launch(&installed, root, "secret-executor", &outer_result);
    success
        .env("GENERIC_TOKEN", "ambient-value-must-not-win")
        .env("GENERIC_CONSUMER_MARKER", &marker)
        .env("GENERIC_EXPECTED_CWD", root)
        .args([
            "secret",
            "exec",
            "--stdin",
            "token",
            "--fd",
            "7=token",
            "--file",
            "GENERIC_FILE=token",
            "--env",
            "GENERIC_TOKEN=token",
            "--result-file",
        ])
        .arg(&inner_result)
        .arg("--")
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", CONSUMER, "--nocapture"]);
    let output = bounded_output(&mut success);
    assert_eq!(output.status.code(), Some(29), "{output:?}");
    assert_eq!(fs::read(&marker).unwrap(), b"consumer started");
    assert!(String::from_utf8_lossy(&output.stdout).contains("generic child stdout"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("generic child stderr"));
    assert_value_free(&output, &[&inner_result, &outer_result]);
    assert_report(&inner_result, "exited", Some(true), 29);
    assert_report(&outer_result, "exited", None, 29);
    assert!(std::env::var_os("GENERIC_TOKEN").is_none());
    assert!(std::env::var_os("GENERIC_FILE").is_none());

    // An unmodified system binary has no Dev Auth library or adapter.
    let cat_outer = root.join("cat-outer.json");
    let cat_inner = root.join("cat-inner.json");
    let mut cat = launch(&installed, root, "secret-executor", &cat_outer);
    cat.args(["secret", "exec", "--stdin", "token", "--result-file"])
        .arg(&cat_inner)
        .args(["--", "/usr/bin/cat"]);
    let cat = bounded_output(&mut cat);
    assert!(cat.status.success());
    assert!(cat.stdout == b"fixture-export");
    assert!(cat.stderr.is_empty());
    assert_report(&cat_inner, "exited", Some(true), 0);
    // Child stdout belongs to the consumer, not to value-free control output.
    assert_value_free(
        &Output {
            status: cat.status,
            stdout: Vec::new(),
            stderr: cat.stderr,
        },
        &[&cat_inner, &cat_outer],
    );

    for (index, workload, projection, resource, command, expected, outcome) in [
        (
            0,
            "secret-executor",
            "GENERIC_TOKEN",
            "unknown-resource",
            "/usr/bin/touch",
            4,
            "resource_denied",
        ),
        (
            1,
            "secret-executor",
            "GENERIC_TOKEN",
            "release",
            "/usr/bin/touch",
            4,
            "resource_denied",
        ),
        (
            2,
            "narrow-executor",
            "GENERIC_TOKEN",
            "token",
            "/usr/bin/touch",
            4,
            "resource_denied",
        ),
        (
            3,
            "secret-executor",
            "PATH",
            "token",
            "/usr/bin/touch",
            2,
            "",
        ),
        (
            4,
            "secret-executor",
            "GENERIC_TOKEN",
            "token",
            "/absent-native-consumer",
            2,
            "executable_unavailable",
        ),
        (
            5,
            "secret-executor",
            "GENERIC_TOKEN",
            "missing-token",
            "/usr/bin/touch",
            4,
            "resource_denied",
        ),
    ] {
        let before = calls();
        let marker = root.join(format!("denied-consumer-{index}"));
        let outer = root.join(format!("denied-outer-{index}.json"));
        let inner = root.join(format!("denied-inner-{index}.json"));
        let mut command_line = launch(&installed, root, workload, &outer);
        command_line
            .env("GENERIC_TOKEN", "ambient-value-must-not-authorize")
            .args(["secret", "exec", "--env"])
            .arg(format!("{projection}={resource}"))
            .arg("--result-file")
            .arg(&inner)
            .args(["--", command])
            .arg(&marker);
        let output = bounded_output(&mut command_line);
        assert_eq!(output.status.code(), Some(expected), "{index}: {output:?}");
        assert!(!marker.exists(), "denied consumer started: {index}");
        if outcome.is_empty() {
            assert!(!inner.exists());
        } else {
            assert_report(&inner, outcome, Some(false), expected);
        }
        assert_value_free(&output, &[&outer]);
        if inner.exists() {
            assert_value_free(&output, &[&inner]);
        }
        let mut expected_calls = before;
        if index == 5 {
            expected_calls.extend_from_slice(b"read\n");
        }
        assert_eq!(calls(), expected_calls, "wrong provider path: {index}");
        assert_eq!(fs::read(&secondary_calls).unwrap(), unchanged_secondary);
        assert_sessions_settled();
    }

    // Retrieval is all-or-nothing even when a later provider operation fails.
    let mut expected_calls = calls();
    expected_calls.extend_from_slice(b"read\nread\n");
    let marker = root.join("partially-retrieved-consumer");
    let inner = root.join("partial-inner.json");
    let outer = root.join("partial-outer.json");
    let mut partial = launch(&installed, root, "secret-executor", &outer);
    partial
        .args([
            "secret",
            "exec",
            "--stdin",
            "token",
            "--env",
            "GENERIC_TOKEN=missing-token",
            "--result-file",
        ])
        .arg(&inner)
        .args(["--", "/usr/bin/touch"])
        .arg(&marker);
    let output = bounded_output(&mut partial);
    assert_eq!(output.status.code(), Some(4));
    assert_report(&inner, "resource_denied", Some(false), 4);
    assert!(!marker.exists());
    assert_eq!(calls(), expected_calls);
    assert_eq!(fs::read(&secondary_calls).unwrap(), unchanged_secondary);
    assert_value_free(&output, &[&inner, &outer]);
    assert_sessions_settled();

    // Fresh administrator approval is never inferred from noninteractive input.
    // This proves only the public no-start gate, not native Sudo authorization.
    let before = calls();
    let marker = root.join("unapproved-privileged-consumer");
    let result = root.join("unapproved-privilege-result.json");
    let output = bounded_output(
        Command::new(&installed)
            .env_clear()
            .current_dir(root)
            .args([
                "workload",
                "launch",
                "secret-executor",
                "--non-interactive",
                "--privilege-scope",
                "workload",
                "--privilege-duration",
                "30m",
                "--result-file",
            ])
            .arg(&result)
            .args([
                "--",
                "secret",
                "exec",
                "--env",
                "GENERIC_TOKEN=token",
                "--",
                "/usr/bin/touch",
            ])
            .arg(&marker),
    );
    assert_eq!(output.status.code(), Some(3));
    assert_report(&result, "approval_required", Some(false), 3);
    assert_value_free(&output, &[&result]);
    assert!(!marker.exists());
    assert_eq!(calls(), before);
}

fn launch(installed: &Path, root: &Path, workload: &str, result: &Path) -> Command {
    let mut command = Command::new(installed);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir(root)
        .args([
            "workload",
            "launch",
            workload,
            "--non-interactive",
            "--result-file",
        ])
        .arg(result)
        .arg("--");
    command
}

fn assert_report(path: &Path, outcome: &str, started: Option<bool>, code: i32) {
    let report: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(report["outcome"], outcome);
    assert_eq!(report["started"], serde_json::json!(started));
    assert_eq!(report["exit_code"], code);
}

fn assert_value_free(output: &Output, reports: &[&Path]) {
    let mut observations = output.stdout.clone();
    observations.extend_from_slice(&output.stderr);
    for path in reports {
        observations.extend(fs::read(path).unwrap());
    }
    let observations = String::from_utf8_lossy(&observations);
    for forbidden in [
        "fixture-export",
        "fixture-enrollment",
        "op://",
        "ambient-value",
    ] {
        assert!(!observations.contains(forbidden));
    }
}

fn assert_sessions_settled() {
    let uid = nix::unistd::Uid::effective().as_raw();
    let sessions = PathBuf::from(format!("/run/user/{uid}/dev-auth-v3/user-sessions"));
    assert_eq!(fs::read_dir(sessions).unwrap().count(), 0);
}
