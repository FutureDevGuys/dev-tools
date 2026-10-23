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
        run_installed_user_only_validation_child(Some(exercise));
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
    assert!(observations
        .reads
        .as_chunks::<2>()
        .0
        .iter()
        .all(|pair| *pair == ["automation", "secondary"]));
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
    assert!(fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .and_then(|mut file| file.write_all(b"replacement"))
        .is_err());
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

fn configure_public_authority(
    policy: &mut toml::Value,
    config: &mut toml::Value,
    canonical: &Path,
) {
    policy["trusted_launchers"]
        .as_table_mut()
        .unwrap()
        .insert("secret-executor".into(), canonical.to_str().unwrap().into());
    policy["workload_caps"]["worker"]["launchers"]
        .as_array_mut()
        .unwrap()
        .push("secret-executor".into());
    let projections = ["stdin", "descriptor", "file", "environment"];
    policy["credentials"]["resources"]["token"]
        .as_table_mut()
        .unwrap()
        .insert(
            "projections".into(),
            toml::Value::Array(projections.iter().map(|value| (*value).into()).collect()),
        );
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
projections = ["environment"]
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
    configure_public_authority(&mut policy, &mut config, &canonical);
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    resolve_fixture_authority(&policy, &config, &user.name);
    for (path, value) in [(&policy_path, &policy), (&config_path, &config)] {
        fs::write(path, toml::to_string_pretty(value).unwrap()).unwrap();
    }
    reconcile_fixture_aliases(&canonical, &config);
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
    require_success_audit_only(&cat.stderr, "secret-executor", "secret-executor", 1).unwrap();
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

    // Consumer startup is all-or-nothing even when a later provider operation fails.
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

// Broker audit is an intentional stderr channel, separate from child errors.
// Reject arbitrary text, malformed/extra fields, denials, wrong identity and
// unexpected capabilities rather than treating all stderr as harmless logging.
fn require_success_audit_only(
    stderr: &[u8],
    workload: &str,
    profile: &str,
    expected_reads: usize,
) -> Result<(), &'static str> {
    let text = std::str::from_utf8(stderr).map_err(|_| "non-UTF8 stderr")?;
    let records = text
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "non-audit stderr")?;
    if records.len() < 3 {
        return Err("incomplete audit lifecycle");
    }
    let session = records[0]["session_id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .ok_or("missing audit session")?;
    let mut reads = 0;
    let mut probes = 0;
    for (index, record) in records.iter().enumerate() {
        let object = record.as_object().ok_or("audit is not an object")?;
        if record["schema"] != "dev-auth-broker-audit-v1"
            || record["timestamp_unix"].as_i64().is_none()
            || record["session_id"].as_str() != Some(session)
        {
            return Err("wrong audit schema or session");
        }
        if index == 0 || index == records.len() - 1 {
            let expected = if index == 0 {
                ("user_session_start", "accepted")
            } else {
                ("user_session_stop", "revoked")
            };
            if object.len() != 5 || record["event"] != expected.0 || record["outcome"] != expected.1
            {
                return Err("unexpected audit lifecycle");
            }
        } else {
            if object.len() != 9
                || record["event"] != "capability_request"
                || record["workload"] != workload
                || record["profile"] != profile
            {
                return Err("unexpected audit consumer");
            }
            match (record["capability"].as_str(), record["outcome"].as_str()) {
                (Some("probe"), Some("ready"))
                    if record.get("resource_sha256") == Some(&serde_json::Value::Null) =>
                {
                    probes += 1
                }
                (Some("secret_read"), Some("material_issued"))
                    if record["resource_sha256"].as_str().is_some_and(|hash| {
                        hash.len() == 64
                            && hash
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    }) =>
                {
                    reads += 1
                }
                _ => return Err("unexpected audit capability or outcome"),
            }
        }
    }
    if probes < 2 || reads != expected_reads {
        return Err("unexpected audit operation counts");
    }
    Ok(())
}

#[test]
fn successful_audit_filter_rejects_non_audit_errors_and_wrong_authority() {
    let common = serde_json::json!({"schema":"dev-auth-broker-audit-v1", "timestamp_unix":1, "session_id":"fixture"});
    let record = |event: &str, outcome: &str, capability: Option<&str>| {
        let mut value = common.clone();
        let fields = value.as_object_mut().unwrap();
        fields.insert("event".into(), event.into());
        fields.insert("outcome".into(), outcome.into());
        if let Some(capability) = capability {
            fields.insert("capability".into(), capability.into());
            fields.insert("workload".into(), "worker".into());
            fields.insert("profile".into(), "profile".into());
            fields.insert(
                "resource_sha256".into(),
                if capability == "secret_read" {
                    "a".repeat(64).into()
                } else {
                    serde_json::Value::Null
                },
            );
        }
        value
    };
    let records = vec![
        record("user_session_start", "accepted", None),
        record("capability_request", "ready", Some("probe")),
        record("capability_request", "material_issued", Some("secret_read")),
        record("capability_request", "ready", Some("probe")),
        record("user_session_stop", "revoked", None),
    ];
    let encode = |records: &[serde_json::Value]| {
        records
            .iter()
            .map(|r| serde_json::to_string(r).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    };
    let valid = encode(&records);
    assert!(require_success_audit_only(valid.as_bytes(), "worker", "profile", 1).is_ok());
    for altered in [
        format!("{valid}\nconsumer error"),
        valid.replace("material_issued", "denied"),
        valid.replace("\"worker\"", "\"other\""),
        valid.replace("\"revoked\"", "\"failed\""),
    ] {
        assert!(require_success_audit_only(altered.as_bytes(), "worker", "profile", 1).is_err());
    }
    let mut changed = records.clone();
    changed[2]["session_id"] = "other".into();
    assert!(
        require_success_audit_only(encode(&changed).as_bytes(), "worker", "profile", 1).is_err()
    );
    assert!(require_success_audit_only(valid.as_bytes(), "worker", "profile", 2).is_err());
    let mut changed = records.clone();
    let fields = changed[1].as_object_mut().unwrap();
    fields.remove("resource_sha256");
    fields.insert("unexpected".into(), "fixture-export".into());
    assert!(
        require_success_audit_only(encode(&changed).as_bytes(), "worker", "profile", 1).is_err()
    );
}

fn assert_sessions_settled() {
    let uid = nix::unistd::Uid::effective().as_raw();
    let sessions = PathBuf::from(format!("/run/user/{uid}/dev-auth-v3/user-sessions"));
    assert_eq!(fs::read_dir(sessions).unwrap().count(), 0);
}

/// Observe the same disposable namespace before testing any credential path.
/// A rejected system executable is never executed by this diagnostic.
#[test]
fn installed_projection_namespace_custody_diagnostic() {
    const CASE: &str = "generic_projection::installed_projection_namespace_custody_diagnostic";
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    if user.name != "dev-auth-test" {
        let sandbox = NativeUserSandbox::new();
        let output = bounded_output_with_timeout(
            sandbox
                .command(&std::env::current_exe().unwrap(), &sandbox.home)
                .args(["--exact", CASE, "--test-threads=1", "--nocapture"]),
            Duration::from_secs(30),
            "projection fixture namespace custody diagnostic",
        );
        assert!(output.status.success(), "{output:?}");
        print!("{}", String::from_utf8_lossy(&output.stdout));
        assert!(output.stderr.is_empty(), "{output:?}");
        return;
    }
    println!("effective uid={}", user.uid.as_raw());
    let mapping = fs::read("/proc/self/uid_map").unwrap();
    assert!(mapping.len() <= 4096);
    println!("namespace uid_map={}", String::from_utf8_lossy(&mapping));
    for path in ["/", "/usr", "/usr/bin", "/usr/bin/printenv"] {
        let metadata = fs::symlink_metadata(path).unwrap();
        println!(
            "custody path={path} uid={} gid={} mode={:o} regular={} directory={} symlink={}",
            metadata.uid(),
            metadata.gid(),
            metadata.mode() & 0o7777,
            metadata.is_file(),
            metadata.is_dir(),
            metadata.file_type().is_symlink(),
        );
    }
    match dev_tools_command::HeldExecutable::open(Path::new("/usr/bin/printenv")) {
        Ok(_) => println!("system printenv retained custody=accepted (not executed)"),
        Err(error) => println!("system printenv retained custody=denied (not executed): {error:#}"),
    }
    // Byte-identical native material in independently legitimate fixture-user
    // custody, inspected only. No denied command is retried via this copy.
    let copied = user.dir.join("custody-inspection-printenv");
    fs::copy("/usr/bin/printenv", &copied).unwrap();
    fs::set_permissions(&copied, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        fs::read(&copied).unwrap(),
        fs::read("/usr/bin/printenv").unwrap()
    );
    dev_tools_command::HeldExecutable::open(&copied)
        .expect("fixture-owned byte-identical native copy must retain custody");
    println!("fixture-owned byte-identical printenv retained custody=accepted (not executed)");
    fs::remove_file(copied).unwrap();
}

const CONFIGURED_CASE: &str =
    "generic_projection::installed_configured_projection_keeps_native_consumer_authority";
const CONFIGURED_CONSUMER: &str = "generic_projection::configured_native_consumer";
const CONFIGURED_DRIVER: &str = "generic_projection::configured_admitted_driver";

#[test]
fn installed_configured_projection_keeps_native_consumer_authority() {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    if user.name == "dev-auth-test" {
        run_installed_user_only_validation_child(Some(exercise_configured));
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
            CONFIGURED_CASE,
            "--test-threads=1",
            "--nocapture",
        ]),
        Duration::from_secs(180),
        "installed configured projection acceptance",
    );
    assert!(output.status.success(), "{output:?}");
    let observations = store.observations.lock().unwrap();
    assert!(observations.reads.len() > 2);
    assert_eq!(observations.reads.len(), observations.searches.len());
    assert!(observations
        .reads
        .iter()
        .all(|slot| slot == "automation" || slot == "secondary"));
}

/// An ordinary native consumer. Its first effect witnesses any attempted start,
/// even if a projection check would subsequently fail.
#[test]
fn configured_native_consumer() {
    let Some(marker) = std::env::var_os("GENERIC_CONFIGURED_MARKER") else {
        return;
    };
    fs::write(marker, b"configured consumer started").unwrap();
    assert!(std::env::var_os("GENERIC_TOKEN").unwrap() == "fixture-export");
    assert!(std::env::var_os("OP_SERVICE_ACCOUNT_TOKEN").is_none());
    assert_eq!(nix::unistd::getuid(), nix::unistd::geteuid());
    assert!(!nix::unistd::getuid().is_root());
    assert_eq!(
        std::env::current_dir().unwrap(),
        PathBuf::from(std::env::var_os("GENERIC_EXPECTED_CWD").unwrap())
    );
    assert!(!std::env::args_os().any(|arg| arg == "fixture-export"));
    println!("configured child stdout");
    eprintln!("configured child stderr");
    std::process::exit(29);
}

fn environment_projection(resource: &str, target: &str) -> toml::Value {
    toml::Value::Table(toml::map::Map::from_iter([
        ("resource".into(), resource.into()),
        ("kind".into(), "environment".into()),
        ("target".into(), target.into()),
    ]))
}

fn reconcile_fixture_aliases(canonical: &Path, config: &toml::Value) {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    let mut names = config["workloads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|workload| workload["name"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    names.sort();
    dev_auth::setup::reconcile_workload_launchers_at(
        &user.dir,
        canonical,
        &names,
        user.uid.as_raw(),
    )
    .unwrap();
}

fn configured_consumer_arguments(command: &mut Command, root: &Path, marker: &Path) {
    command
        .env("GENERIC_CONFIGURED_MARKER", marker)
        .env("GENERIC_EXPECTED_CWD", root)
        .args(["--exact", CONFIGURED_CONSUMER, "--nocapture"]);
}

fn write_authority(path: &Path, document: &toml::Value) {
    fs::write(path, toml::to_string_pretty(document).unwrap()).unwrap();
}

fn configured_workload_mut<'a>(config: &'a mut toml::Value, name: &str) -> &'a mut toml::Value {
    config["workloads"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|workload| workload["name"].as_str() == Some(name))
        .unwrap()
}

// Pure fixture construction is tested before requiring a native namespace or bus.
fn configure_consumer_authority(
    policy: &mut toml::Value,
    config: &mut toml::Value,
    consumer: &Path,
    printenv: &Path,
) {
    for (name, path) in [
        ("configured-consumer", consumer),
        ("configured-printenv", printenv),
    ] {
        policy["trusted_launchers"]
            .as_table_mut()
            .unwrap()
            .insert(name.into(), path.to_str().unwrap().into());
    }
    let missing: toml::Value = toml::from_str(
        r#"credential_slot = "automation"
reference = "op://Fixture/Missing/value"
kind = "exportable"
purposes = ["read"]
projections = ["environment"]
"#,
    )
    .unwrap();
    policy["credentials"]["resources"]
        .as_table_mut()
        .unwrap()
        .insert("missing-token".into(), missing);
    policy["credentials"]["resources"]["token"]
        .as_table_mut()
        .unwrap()
        .insert(
            "projections".into(),
            toml::Value::Array(vec!["environment".into()]),
        );
    let resources = toml::Value::Table(toml::map::Map::from_iter([
        ("token".into(), resource_selection(&["environment"])),
        ("missing-token".into(), resource_selection(&["environment"])),
    ]));
    for (name, selection) in resources.as_table().unwrap() {
        policy["credentials"]["resource_caps"]["worker"]["resources"]
            .as_table_mut()
            .unwrap()
            .insert(name.clone(), selection.clone());
    }
    let token = environment_projection("token", "GENERIC_TOKEN");
    let missing = environment_projection("missing-token", "GENERIC_TOKEN");
    let later = environment_projection("missing-token", "GENERIC_SECOND");
    for (name, launcher, projections) in [
        (
            "configured-consumer",
            "configured-consumer",
            vec![token.clone()],
        ),
        (
            "configured-printenv",
            "configured-printenv",
            vec![token.clone()],
        ),
        ("configured-missing", "configured-consumer", vec![missing]),
        (
            "configured-partial",
            "configured-consumer",
            vec![token.clone(), later],
        ),
        ("configured-empty", "configured-consumer", vec![]),
    ] {
        let mut cap = policy["workload_caps"]["worker"].clone();
        cap["launchers"] = toml::Value::Array(vec![launcher.into()]);
        let mut destinations = projections.clone();
        if name == "configured-consumer" {
            destinations.push(environment_projection("token", "OTHER_TOKEN"));
        } else if name == "configured-empty" {
            destinations.push(token.clone());
        }
        cap.as_table_mut().unwrap().insert(
            "secret_projections".into(),
            toml::Value::Array(destinations),
        );
        policy["workload_caps"]
            .as_table_mut()
            .unwrap()
            .insert(name.into(), cap);
        config["authority_profiles"].as_table_mut().unwrap().insert(
            name.into(),
            toml::Value::Table(toml::map::Map::from_iter([
                ("cap".into(), name.into()),
                ("resources".into(), resources.clone()),
            ])),
        );
        let mut workload: toml::Value = toml::from_str(
            r#"name = "placeholder"
launcher = "placeholder"
profile = "placeholder"
admission = "enrolled_noninteractive"
duration_seconds = 120
"#,
        )
        .unwrap();
        workload["name"] = name.into();
        workload["launcher"] = launcher.into();
        workload["profile"] = name.into();
        let table = workload.as_table_mut().unwrap();
        table.insert("resources".into(), resources.clone());
        table.insert("secret_projections".into(), toml::Value::Array(projections));
        config["workloads"].as_array_mut().unwrap().push(workload);
    }
}

fn projection_authority_seed() -> (toml::Value, toml::Value) {
    // Match the installed seed's intentionally absent optional projection keys.
    let policy: toml::Value = toml::from_str(
        r#"schema = "dev-auth-administrator-policy-v3"
mode = "user_only"
allowed_users = ["fixture"]
[programs]
git = "/usr/bin/true"
gh = "/usr/bin/true"
ssh = "/usr/bin/true"
ssh_keygen = "/usr/bin/true"
[trusted_launchers]
generic-worker = "/opt/fixture/original"
[credentials.providers.primary]
kind = "one_password"
executable = "/opt/fixture/provider"
[credentials.credential_slots.automation]
provider = "primary"
users = ["fixture"]
[credentials.resources.token]
credential_slot = "automation"
reference = "op://Fixture/Token/value"
kind = "exportable"
purposes = ["read"]
[credentials.resources.release]
credential_slot = "automation"
reference = "op://Fixture/Release/value"
kind = "operation_only"
purposes = ["release_signing"]
[credentials.resource_caps.worker]
users = ["fixture"]
[credentials.resource_caps.worker.resources.token]
purposes = ["read"]
[credentials.resource_caps.worker.resources.release]
purposes = ["release_signing"]
[workload_caps.worker]
users = ["fixture"]
resource_cap = "worker"
launchers = ["generic-worker"]
admission = ["enrolled_noninteractive"]
max_duration_seconds = 120
"#,
    )
    .unwrap();
    let config: toml::Value = toml::from_str(
        r#"schema = "dev-auth-user-config-v3"
workloads = []
[authority_profiles.worker]
cap = "worker"
[authority_profiles.worker.resources.token]
purposes = ["read"]
[authority_profiles.worker.resources.release]
purposes = ["release_signing"]
"#,
    )
    .unwrap();
    (policy, config)
}

#[test]
fn configured_authority_fixture_constructs_and_resolves_all_consumers() {
    let (mut policy, mut config) = projection_authority_seed();
    assert!(policy["workload_caps"]["worker"]
        .get("secret_projections")
        .is_none());
    configure_consumer_authority(
        &mut policy,
        &mut config,
        Path::new("/opt/fixture/native"),
        Path::new("/opt/fixture/printenv"),
    );
    let policy =
        dev_auth::policy_v3::parse_system_policy_v3(toml::to_string(&policy).unwrap().as_bytes())
            .expect("configured fixture administrator policy must parse");
    let config =
        dev_auth::policy_v3::parse_user_config_v3(toml::to_string(&config).unwrap().as_bytes())
            .expect("configured fixture user config must parse");
    let resolved = dev_auth::policy_v3::resolve_policy_for_user(&policy, "fixture", &config)
        .expect("all configured fixture consumers must retain admitted projection authority");
    assert_eq!(resolved.len(), 5);
    for (name, count) in [
        ("configured-consumer", 1),
        ("configured-printenv", 1),
        ("configured-missing", 1),
        ("configured-partial", 2),
        ("configured-empty", 0),
    ] {
        let workload = &resolved[name];
        assert_eq!(workload.secret_projections.len(), count, "{name}");
        let expected = if name == "configured-printenv" {
            "/opt/fixture/printenv"
        } else {
            "/opt/fixture/native"
        };
        assert_eq!(workload.launcher_path, expected, "{name}");
    }
}

fn resolve_fixture_authority(
    policy: &toml::Value,
    config: &toml::Value,
    user: &str,
) -> std::collections::BTreeMap<String, dev_auth::policy_v3::ResolvedWorkloadV3> {
    let policy =
        dev_auth::policy_v3::parse_system_policy_v3(toml::to_string(policy).unwrap().as_bytes())
            .expect("fixture administrator policy must parse before launching");
    let config =
        dev_auth::policy_v3::parse_user_config_v3(toml::to_string(config).unwrap().as_bytes())
            .expect("fixture user config must parse before launching");
    dev_auth::policy_v3::resolve_policy_for_user(&policy, user, &config)
        .expect("fixture authority must resolve before launching")
}

#[test]
fn public_authority_fixture_constructs_and_resolves_all_consumers() {
    let (mut policy, mut config) = projection_authority_seed();
    configure_public_authority(&mut policy, &mut config, Path::new("/opt/fixture/dev-auth"));
    let resolved = resolve_fixture_authority(&policy, &config, "fixture");
    let parsed_policy =
        dev_auth::policy_v3::parse_system_policy_v3(toml::to_string(&policy).unwrap().as_bytes())
            .unwrap();
    let parsed_config =
        dev_auth::policy_v3::parse_user_config_v3(toml::to_string(&config).unwrap().as_bytes())
            .unwrap();
    let runtime = dev_auth::policy_v3::resolve_runtime_policy_for_user(
        &parsed_policy,
        "fixture",
        &parsed_config,
    )
    .unwrap();
    // The user profile is a shared narrowing template; runtime broker identities
    // are per-workload so no sibling inherits its unnarrowed grants.
    for workload in &parsed_config.workloads {
        assert_eq!(workload.profile, "worker");
        assert_eq!(
            runtime.workloads[&workload.name].authority_profile,
            workload.name
        );
        assert!(runtime.authority_profiles.contains_key(&workload.name));
    }
    assert_eq!(resolved.len(), 2);
    for name in ["secret-executor", "narrow-executor"] {
        assert_eq!(resolved[name].launcher_path, "/opt/fixture/dev-auth");
        assert!(resolved[name].secret_projections.is_empty());
    }
}

pub(super) fn exercise_configured(paths: &dev_auth::setup::SetupPaths, root: &Path) {
    let installed = paths.bin_dir.join("dev-auth");
    let canonical = fs::canonicalize(&installed).unwrap();
    let config_root = root.parent().unwrap().join(".config/dev-auth");
    let policy_path = config_root.join("policy-v3.toml");
    let config_path = config_root.join("config-v3.toml");
    let mut policy: toml::Value =
        toml::from_str(&fs::read_to_string(&policy_path).unwrap()).unwrap();
    let mut config: toml::Value =
        toml::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    let consumer = root.join("configured-native-consumer");
    fs::copy(std::env::current_exe().unwrap(), &consumer).unwrap();
    fs::set_permissions(&consumer, fs::Permissions::from_mode(0o700)).unwrap();
    // The namespace maps only the fixture UID; bound host-root /usr files
    // have overflow UID65534 and correctly fail native consumer custody.
    // Prepare a separately declared, byte-identical system-tool fixture before
    // admission. This tests ordinary tool behavior under legitimate user-only
    // custody, not execution through that rejected host-root path.
    let printenv = root.join("printenv");
    fs::copy("/usr/bin/printenv", &printenv).unwrap();
    fs::set_permissions(&printenv, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        fs::read(&printenv).unwrap(),
        fs::read("/usr/bin/printenv").unwrap()
    );
    configure_consumer_authority(&mut policy, &mut config, &consumer, &printenv);
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    resolve_fixture_authority(&policy, &config, &user.name);
    write_authority(&policy_path, &policy);
    write_authority(&config_path, &config);
    reconcile_fixture_aliases(&canonical, &config);
    let primary_calls = root.join("op-primary.calls");
    let secondary_calls = root.join("op-secondary.calls");
    let secondary_before = fs::read(&secondary_calls).unwrap();

    let marker = root.join("configured-success-marker");
    let result = root.join("configured-success.json");
    let mut command = launch(&installed, root, "configured-consumer", &result);
    command.env("GENERIC_TOKEN", "ambient-value-must-not-win");
    configured_consumer_arguments(&mut command, root, &marker);
    let output = bounded_output(&mut command);
    assert_eq!(output.status.code(), Some(29), "{output:?}");
    assert_eq!(fs::read(&marker).unwrap(), b"configured consumer started");
    assert!(String::from_utf8_lossy(&output.stdout).contains("configured child stdout"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("configured child stderr"));
    assert_report(&result, "exited", None, 29);
    assert_value_free(&output, &[&result]);
    assert!(std::env::var_os("GENERIC_TOKEN").is_none());
    assert_sessions_settled();

    // These are printenv's raw arguments, never an alternate executable request.
    let marker = root.join("raw-argv-must-not-create");
    let result = root.join("configured-printenv.json");
    let mut command = launch(&installed, root, "configured-printenv", &result);
    command
        .arg("/usr/bin/touch")
        .arg(&marker)
        .arg("GENERIC_TOKEN");
    let output = bounded_output(&mut command);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        output.stdout,
        b"fixture-export\n",
        "configured printenv: status={:?}; stderr={}; result={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(8192)]),
        fs::read(&result)
            .map(|bytes| String::from_utf8_lossy(&bytes[..bytes.len().min(8192)]).into_owned())
            .unwrap_or_else(|error| format!("unavailable: {error}")),
    );
    require_success_audit_only(
        &output.stderr,
        "configured-printenv",
        "configured-printenv",
        1,
    )
    .expect("printenv stderr must contain only the expected value-free successful broker audit");
    assert!(!marker.exists());
    assert_report(&result, "exited", None, 1);
    assert_value_free(
        &Output {
            status: output.status,
            stdout: Vec::new(),
            stderr: output.stderr,
        },
        &[&result],
    );
    assert_sessions_settled();

    // A later failed acquisition must not start even a partially populated child.
    for (name, reads) in [("configured-missing", 1), ("configured-partial", 2)] {
        let mut expected = fs::read(&primary_calls).unwrap();
        for _ in 0..reads {
            expected.extend_from_slice(b"read\n");
        }
        let marker = root.join(format!("{name}-marker"));
        let result = root.join(format!("{name}.json"));
        let mut command = launch(&installed, root, name, &result);
        command.env("GENERIC_TOKEN", "ambient-value-must-not-authorize");
        configured_consumer_arguments(&mut command, root, &marker);
        let output = bounded_output(&mut command);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert_report(&result, "failed", None, 1);
        assert!(!marker.exists());
        assert_eq!(fs::read(&primary_calls).unwrap(), expected);
        assert_value_free(&output, &[&result]);
        assert_sessions_settled();
    }

    // Invalid projection authority is rejected before contacting a provider.
    for (name, reserved) in [("denied-projection", false), ("reserved-destination", true)] {
        let mut denied = config.clone();
        let workload = configured_workload_mut(&mut denied, "configured-consumer");
        if reserved {
            workload["secret_projections"] =
                toml::Value::Array(vec![environment_projection("token", "PATH")]);
        } else {
            workload["resources"]["token"] = resource_selection(&[]);
        }
        write_authority(&config_path, &denied);
        let before = fs::read(&primary_calls).unwrap();
        let marker = root.join(format!("{name}-marker"));
        let result = root.join(format!("{name}.json"));
        let mut command = launch(&installed, root, "configured-consumer", &result);
        configured_consumer_arguments(&mut command, root, &marker);
        let output = bounded_output(&mut command);
        write_authority(&config_path, &config);
        assert!(!output.status.success(), "{output:?}");
        assert!(!marker.exists());
        assert_eq!(fs::read(&primary_calls).unwrap(), before);
        assert_value_free(&output, &[&result]);
        assert_sessions_settled();
    }

    // The same real admitted session cannot adopt changed projection authority.
    for name in ["configured-consumer", "configured-empty"] {
        let result = root.join(format!("{name}-driver.json"));
        let mut command = launch(&installed, root, name, &result);
        command
            .env("GENERIC_DRIVER_WORKLOAD", name)
            .env("GENERIC_INSTALLED", &installed)
            .env("GENERIC_CONFIG_PATH", &config_path)
            .env("GENERIC_EXPECTED_CWD", root)
            .args(["--exact", CONFIGURED_DRIVER, "--nocapture"]);
        let output = bounded_output(&mut command);
        assert!(output.status.success(), "{output:?}");
        assert_report(&result, "exited", None, 0);
        assert_value_free(&output, &[&result]);
        assert_sessions_settled();
    }
    assert_eq!(fs::read(&secondary_calls).unwrap(), secondary_before);
    exercise_held_consumer(&installed, root, &consumer, &policy_path, &policy);
}

/// Runs inside the real admitted workload, retaining its broker socket/session
/// while changing only this disposable user's configuration.
#[test]
fn configured_admitted_driver() {
    let Ok(name) = std::env::var("GENERIC_DRIVER_WORKLOAD") else {
        return;
    };
    let installed = PathBuf::from(std::env::var_os("GENERIC_INSTALLED").unwrap());
    let config_path = PathBuf::from(std::env::var_os("GENERIC_CONFIG_PATH").unwrap());
    let root = PathBuf::from(std::env::var_os("GENERIC_EXPECTED_CWD").unwrap());
    let original = fs::read(&config_path).unwrap();
    let config: toml::Value = toml::from_str(std::str::from_utf8(&original).unwrap()).unwrap();
    let mut cases = if name == "configured-empty" {
        vec![(
            "none-to-some",
            vec![environment_projection("token", "GENERIC_TOKEN")],
        )]
    } else {
        vec![
            (
                "unchanged",
                vec![environment_projection("token", "GENERIC_TOKEN")],
            ),
            (
                "some-to-other",
                vec![environment_projection("token", "OTHER_TOKEN")],
            ),
            ("some-to-none", vec![]),
        ]
    };
    for (case, projections) in cases.drain(..) {
        let before = fs::read(root.join("op-primary.calls")).unwrap();
        let mut changed = config.clone();
        configured_workload_mut(&mut changed, &name)["secret_projections"] =
            toml::Value::Array(projections);
        write_authority(&config_path, &changed);
        let marker = root.join(format!("nested-{case}-marker"));
        let mut command = Command::new(&installed);
        // Do not clear or synthesize admission hints: reuse the real session.
        command.args(["workload", "launch", &name, "--non-interactive", "--"]);
        configured_consumer_arguments(&mut command, &root, &marker);
        let output = bounded_output(&mut command);
        fs::write(&config_path, &original).unwrap();
        if case == "unchanged" {
            assert_eq!(output.status.code(), Some(29), "{output:?}");
            assert_eq!(fs::read(marker).unwrap(), b"configured consumer started");
            let mut expected = before;
            expected.extend_from_slice(b"read\n");
            assert_eq!(fs::read(root.join("op-primary.calls")).unwrap(), expected);
        } else {
            assert!(!output.status.success(), "{output:?}");
            assert!(
                !marker.exists(),
                "changed admission started its consumer: {case}"
            );
            assert_eq!(fs::read(root.join("op-primary.calls")).unwrap(), before);
        }
        assert_value_free(&output, &[]);
    }
}

fn exercise_held_consumer(
    installed: &Path,
    root: &Path,
    consumer: &Path,
    policy_path: &Path,
    policy: &toml::Value,
) {
    use nix::poll::{poll, PollFd, PollFlags};
    use std::os::fd::AsFd;
    let ready = root.join("provider-ready.fifo");
    let resume = root.join("provider-resume.fifo");
    for path in [&ready, &resume] {
        nix::unistd::mkfifo(
            path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
    }
    // O_RDWR prevents FIFO-open deadlock; poll bounds waiting for the provider's
    // explicit first-read handshake. No delay is used as evidence of ordering.
    let mut ready_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&ready)
        .unwrap();
    let mut resume_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&resume)
        .unwrap();
    let provider = root.join("gated-provider");
    fs::write(&provider, format!(
        "#!/bin/sh\n[ \"$OP_SERVICE_ACCOUNT_TOKEN\" = 'fixture-enrollment-one' ] || exit 90\ncase \"$*\" in\n'user get --me --format json') printf '%s' '{{\"id\":\"fixture\",\"state\":\"ACTIVE\",\"type\":\"SERVICE_ACCOUNT\"}}' ;;\n'read --no-newline op://Fixture/Token/value') printf R > '{}'; read -r release < '{}'; [ \"$release\" = resume ] || exit 93; printf '%s' 'fixture-export' ;;\n*) exit 92 ;;\nesac\n",
        ready.display(), resume.display()
    )).unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();
    let mut gated = policy.clone();
    gated["credentials"]["providers"]["primary"]["executable"] = provider.to_str().unwrap().into();
    write_authority(policy_path, &gated);
    let replacement = root.join("replacement-native-consumer");
    fs::copy("/usr/bin/false", &replacement).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
    let original_inode = fs::metadata(consumer).unwrap().ino();
    assert_ne!(original_inode, fs::metadata(&replacement).unwrap().ino());
    let marker = root.join("retained-consumer-marker");
    let result = root.join("retained-consumer.json");
    let mut command = launch(installed, root, "configured-consumer", &result);
    configured_consumer_arguments(&mut command, root, &marker);
    let output = std::thread::scope(|scope| {
        let replace = scope.spawn(|| {
            let mut descriptors = [PollFd::new(ready_file.as_fd(), PollFlags::POLLIN)];
            assert_eq!(poll(&mut descriptors, 20_000u16).unwrap(), 1);
            assert!(descriptors[0]
                .revents()
                .unwrap()
                .contains(PollFlags::POLLIN));
            let mut handshake = [0u8; 1];
            ready_file.read_exact(&mut handshake).unwrap();
            assert_eq!(handshake, *b"R");
            fs::rename(&replacement, consumer).unwrap();
            assert_ne!(fs::metadata(consumer).unwrap().ino(), original_inode);
            resume_file.write_all(b"resume\n").unwrap();
        });
        let output = bounded_output(&mut command);
        replace.join().unwrap();
        output
    });
    write_authority(policy_path, policy);
    assert_eq!(output.status.code(), Some(29), "{output:?}");
    assert_eq!(fs::read(marker).unwrap(), b"configured consumer started");
    assert_report(&result, "exited", None, 29);
    assert_value_free(&output, &[&result]);
    assert_sessions_settled();
}
