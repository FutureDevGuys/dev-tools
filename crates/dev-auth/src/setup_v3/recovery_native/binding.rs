#![cfg(test)]

//! Native strong-mode mutable binding qualification in the disposable image.
use super::*;
use crate::deployment::DeploymentBinding;
use crate::smart_binding::{
    advance_binding, build_binding_plan, canonical_binding_plan, resolve_structured_target,
    BindingCodeTrust, BindingIntent, BindingPlan, BindingPlanChange, BindingReceipt,
};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

const WORKER: &str = "/usr/local/libexec/dev-auth-fixture-worker";
const PINNED_WORKER: &str = "/usr/local/libexec/dev-auth-pinned-fixture-worker";
const PINNED_RESOURCE: &str = "/usr/local/libexec/dev-auth-pinned-resource";

fn user_worker(account: &nix::unistd::User) -> PathBuf {
    account.dir.join("mutable-worker")
}

pub(super) fn prepare_targets_and_policy(
    account: &nix::unistd::User,
    policy: Vec<u8>,
    config: Vec<u8>,
) -> (Vec<u8>, Vec<u8>) {
    let target = user_worker(account);
    fs::write(&target, fs::read(WORKER).unwrap()).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    nix::unistd::chown(&target, Some(account.uid), Some(account.gid)).unwrap();
    assert_eq!(fs::metadata(&target).unwrap().uid(), account.uid.as_raw());
    publish(
        Path::new(PINNED_WORKER),
        b"#!/bin/sh\nset -eu\nIFS= read -r resource < \"$(/usr/bin/dirname \"$0\")/dev-auth-pinned-resource\"\nprintf 'pinned-path=%s\\npinned-resource=%s\\n' \"$0\" \"$resource\"\nif [ \"${1-}\" = nested ]; then\n  command -v bound-pinned-worker | /usr/bin/grep -q '/tool-bin/bound-pinned-worker$'\n  bound-pinned-worker child\n  printf 'pinned-nested=passed\\n'\nfi\n",
        0o755,
    );
    publish(
        Path::new(PINNED_RESOURCE),
        b"adjacent-root-resource\n",
        0o644,
    );
    let policy = String::from_utf8(policy).unwrap();
    assert!(policy.contains(WORKER));
    let policy = policy
        .replace(WORKER, target.to_str().unwrap())
        .replace(
            "[credentials.providers.primary]",
            &format!("pinned-worker = \"{PINNED_WORKER}\"\n[credentials.providers.primary]"),
        )
        .replace(
            "launchers = [\"worker\"]",
            "launchers = [\"worker\", \"pinned-worker\"]",
        );
    let mut config = String::from_utf8(config).unwrap();
    // This scenario rebinds the shared `worker` launcher to user-owned code.
    // The generic workload fixture also names `short-worker` at that launcher;
    // strong policy requires a separate exact binding for every such workload.
    // The binding scenario does not exercise that second workload.
    let short_worker = "\n[[workloads]]\nname = \"short-worker\"\nprofile = \"worker\"\nlauncher = \"worker\"\nadmission = \"enrolled_noninteractive\"\nduration_seconds = 8\n[workloads.resources.token]\npurposes = [\"read\"]\nprojections = [\"stdin\"]\n";
    assert!(config.contains(short_worker));
    config = config.replace(short_worker, "");
    assert!(config.contains("duration_seconds = 60\n[workloads.resources.token]"));
    config = config.replace(
        "duration_seconds = 60\n[workloads.resources.token]",
        "duration_seconds = 60\ndesktop = { display_name = \"Fixture Worker\", terminal = false }\n[workloads.resources.token]",
    );
    config.push_str(
        "\n[[workloads]]\nname = \"pinned-worker\"\nprofile = \"worker\"\nlauncher = \"pinned-worker\"\nadmission = \"enrolled_noninteractive\"\nduration_seconds = 60\n[workloads.resources.token]\npurposes = [\"read\"]\nprojections = [\"stdin\"]\n",
    );
    (policy.into_bytes(), config.into_bytes())
}

pub(super) fn prepare(account: &nix::unistd::User) -> Vec<DeploymentBinding> {
    let target = user_worker(account);
    let intent = BindingIntent::structured("bound-worker", "worker", &target, Vec::<String>::new())
        .unwrap()
        .with_code_trust(BindingCodeTrust::Mutable)
        .with_desktop_entry(true);
    let plan = build_binding_plan(
        "fixture-binding",
        intent,
        resolve_structured_target(&target).unwrap(),
        None,
    )
    .unwrap();
    let bytes = canonical_binding_plan(&plan).unwrap();
    let path = PathBuf::from("/fixture-input/binding-plan.json");
    publish(&path, &bytes, 0o600);
    let mutable = DeploymentBinding {
        user: account.name.clone(),
        name: plan.name,
        plan: path,
        sha256: sha256_hex(&bytes),
    };
    let pinned_target = Path::new(PINNED_WORKER);
    let pinned_plan = build_binding_plan(
        "fixture-pinned-binding",
        BindingIntent::structured(
            "bound-pinned-worker",
            "pinned-worker",
            pinned_target,
            Vec::<String>::new(),
        )
        .unwrap(),
        resolve_structured_target(pinned_target).unwrap(),
        None,
    )
    .unwrap();
    let pinned_bytes = canonical_binding_plan(&pinned_plan).unwrap();
    let pinned_path = PathBuf::from("/fixture-input/pinned-binding-plan.json");
    publish(&pinned_path, &pinned_bytes, 0o600);
    vec![
        mutable,
        DeploymentBinding {
            user: account.name.clone(),
            name: pinned_plan.name,
            plan: pinned_path,
            sha256: sha256_hex(&pinned_bytes),
        },
    ]
}

fn run_bound(account: &nix::unistd::User, alias: &Path, edited: bool, nested: bool) {
    let mut command = Command::new(alias);
    command
        .uid(account.uid.as_raw())
        .gid(account.gid.as_raw())
        .env_clear()
        .env("HOME", &account.dir)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(&account.dir);
    if nested {
        command.arg("nested");
    }
    let output = dev_tools_command::run_prepared_bounded_command(
        &mut command,
        Duration::from_secs(40),
        64 * 1024,
    )
    .unwrap();
    assert!(
        output.status.success(),
        "bound workload failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("workload-credential-check=passed"));
    assert_eq!(stdout.contains("strong-binding-nested=passed"), nested);
    assert_eq!(stdout.contains("strong-binding-edit=passed"), edited);
    assert!(!stdout.contains("fixture-delivered-secret"));
    assert!(!stdout.contains("fixture-service-account"));
}

fn run_pinned(account: &nix::unistd::User, alias: &Path, nested: bool) {
    let mut command = Command::new(alias);
    command
        .uid(account.uid.as_raw())
        .gid(account.gid.as_raw())
        .env_clear()
        .env("HOME", &account.dir)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(&account.dir);
    if nested {
        command.arg("nested");
    }
    let output = dev_tools_command::run_prepared_bounded_command(
        &mut command,
        Duration::from_secs(40),
        64 * 1024,
    )
    .unwrap();
    assert!(
        output.status.success(),
        "pinned workload failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!("pinned-path={PINNED_WORKER}")));
    assert!(stdout.contains("pinned-resource=adjacent-root-resource"));
    assert_eq!(stdout.contains("pinned-nested=passed"), nested);
    assert!(!stdout.contains("pinned-drift=observed"));
}

fn run_desktop(account: &nix::unistd::User, desktop: &Path) {
    let marker = account.dir.join("desktop-launch-passed");
    assert!(!marker.exists());
    let mut command = Command::new("/usr/bin/gio");
    command
        .arg("launch")
        .arg(desktop)
        .uid(account.uid.as_raw())
        .gid(account.gid.as_raw())
        .env_clear()
        .env("HOME", &account.dir)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(&account.dir);
    let output = dev_tools_command::run_prepared_bounded_command(
        &mut command,
        Duration::from_secs(40),
        64 * 1024,
    )
    .unwrap();
    assert!(
        output.status.success(),
        "native desktop launch failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let deadline = Instant::now() + Duration::from_secs(40);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(fs::read(&marker).unwrap(), b"desktop-launch=passed\n");
    assert_eq!(fs::metadata(&marker).unwrap().uid(), account.uid.as_raw());
}

fn run_service(account: &nix::unistd::User, alias: &Path) {
    let mut command = Command::new("/usr/bin/systemd-run");
    command
        .args([
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--unit=dev-auth-binding-service-probe",
        ])
        .arg(format!("--uid={}", account.uid))
        .arg(format!("--gid={}", account.gid))
        .arg(format!("--working-directory={}", account.dir.display()))
        .arg(format!("--setenv=HOME={}", account.dir.display()))
        .arg("--setenv=PATH=/usr/bin:/bin")
        .arg(alias)
        .env_clear();
    let output = dev_tools_command::run_prepared_bounded_command(
        &mut command,
        Duration::from_secs(60),
        64 * 1024,
    )
    .unwrap();
    assert!(
        output.status.success(),
        "native service launch failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("workload-credential-check=passed"));
    assert!(!stdout.contains("fixture-delivered-secret"));
    assert!(!stdout.contains("fixture-service-account"));
}

fn run_editor(account: &nix::unistd::User) {
    let marker = account.dir.join("editor-launch-passed");
    assert!(!marker.exists());
    let repository = account.dir.join("editor-probe");
    let path = format!("{}:/usr/bin:/bin", account.dir.join(".local/bin").display());
    let mut initialize = Command::new("/usr/bin/git");
    initialize
        .args(["init", "-q"])
        .arg(&repository)
        .uid(account.uid.as_raw())
        .gid(account.gid.as_raw())
        .env_clear()
        .env("HOME", &account.dir)
        .env("PATH", &path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .current_dir(&account.dir);
    let initialized = dev_tools_command::run_prepared_bounded_command(
        &mut initialize,
        Duration::from_secs(20),
        64 * 1024,
    )
    .unwrap();
    assert!(initialized.status.success());

    let mut commit = Command::new("/usr/bin/git");
    commit
        .arg("-C")
        .arg(&repository)
        .args([
            "-c",
            "user.name=Fixture User",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--allow-empty",
        ])
        .uid(account.uid.as_raw())
        .gid(account.gid.as_raw())
        .env_clear()
        .env("HOME", &account.dir)
        .env("PATH", &path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_EDITOR", "bound-worker")
        .env("GIT_TERMINAL_PROMPT", "0")
        .current_dir(&account.dir);
    let output = dev_tools_command::run_prepared_bounded_command(
        &mut commit,
        Duration::from_secs(60),
        64 * 1024,
    )
    .unwrap();
    // The fixture editor intentionally leaves COMMIT_EDITMSG empty, so Git
    // aborts the commit after exercising its real editor-child path.
    assert!(!output.status.success());
    assert_eq!(fs::read(&marker).unwrap(), b"editor-launch=passed\n");
    assert_eq!(fs::metadata(&marker).unwrap().uid(), account.uid.as_raw());
    for stream in [&output.stdout, &output.stderr] {
        assert!(!stream
            .windows(b"fixture-delivered-secret".len())
            .any(|window| window == b"fixture-delivered-secret"));
        assert!(!stream
            .windows(b"fixture-service-account".len())
            .any(|window| window == b"fixture-service-account"));
    }
}

fn run_native_config_locator(account: &nix::unistd::User, executable: &Path) {
    let own = |path: &Path, mode| {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        nix::unistd::chown(path, Some(account.uid), Some(account.gid)).unwrap();
    };
    let workspace = account.dir.join("repos");
    fs::create_dir(&workspace).unwrap();
    own(&workspace, 0o700);
    let native = account.dir.join(".config/dev-auth/config.toml");
    assert!(!native.exists());
    fs::write(&native, include_bytes!("../../../config.example.toml")).unwrap();
    own(&native, 0o600);
    let alternate_home = account.dir.join("alternate-home");
    let alternate_home_config = alternate_home.join(".config/dev-auth/config.toml");
    let alternate_xdg = account.dir.join("alternate-xdg");
    let alternate_xdg_config = alternate_xdg.join("dev-auth/config.toml");
    for path in [
        &alternate_home,
        &alternate_home.join(".config"),
        alternate_home_config.parent().unwrap(),
        &alternate_xdg,
        alternate_xdg_config.parent().unwrap(),
    ] {
        fs::create_dir_all(path).unwrap();
        own(path, 0o700);
    }
    for path in [&alternate_home_config, &alternate_xdg_config] {
        fs::write(path, b"invalid = [").unwrap();
        own(path, 0o600);
    }
    let observe = || {
        let mut command = Command::new(executable);
        command
            .arg("workspace-status")
            .uid(account.uid.as_raw())
            .gid(account.gid.as_raw())
            .env_clear()
            .env("HOME", &alternate_home)
            .env("XDG_CONFIG_HOME", &alternate_xdg)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&workspace);
        dev_tools_command::run_prepared_bounded_command(
            &mut command,
            Duration::from_secs(20),
            64 * 1024,
        )
        .unwrap()
    };
    let selected = observe();
    assert!(
        selected.status.success(),
        "native config locator failed: {}",
        String::from_utf8_lossy(&selected.stderr)
    );
    assert_eq!(selected.stdout, b"managed\n");
    assert!(selected.stderr.is_empty());
    for path in [&alternate_home_config, &alternate_xdg_config] {
        fs::write(path, include_bytes!("../../../config.example.toml")).unwrap();
        own(path, 0o600);
    }
    fs::remove_file(&native).unwrap();
    let absent = observe();
    assert!(!absent.status.success());
    assert!(absent.stdout.is_empty());
    let diagnostic = String::from_utf8(absent.stderr).unwrap();
    assert!(diagnostic.contains(&native.display().to_string()));
    assert!(!diagnostic.contains(&alternate_home_config.display().to_string()));
    assert!(!diagnostic.contains(&alternate_xdg_config.display().to_string()));
}

pub(super) fn exercise(account: &nix::unistd::User, executable: &Path) {
    let alias = account.dir.join(".local/bin/bound-worker");
    let desktop = account
        .dir
        .join(".local/share/applications/dev-auth-bound-worker.desktop");
    let pinned_alias = account.dir.join(".local/bin/bound-pinned-worker");
    assert!(fs::symlink_metadata(&alias)
        .unwrap()
        .file_type()
        .is_symlink());
    let desktop_metadata = fs::symlink_metadata(&desktop).unwrap();
    assert!(desktop_metadata.file_type().is_file());
    assert_eq!(desktop_metadata.uid(), account.uid.as_raw());
    assert!(fs::read_to_string(&desktop)
        .unwrap()
        .contains("bound-worker"));
    let receipt = crate::binding_activation::native_receipt_path(
        InstallMode::Strong,
        &account.dir,
        account.uid.as_raw(),
    )
    .unwrap();
    assert!(receipt.is_file());
    assert!(fs::symlink_metadata(&pinned_alias)
        .unwrap()
        .file_type()
        .is_symlink());
    let installation = crate::setup::read_install_receipt_at(&crate::setup::SetupPaths::strong())
        .unwrap()
        .unwrap();
    let pinned_set = crate::binding_activation::read_at(
        &receipt,
        InstallMode::Strong,
        account.uid.as_raw(),
        &installation,
    )
    .unwrap()
    .unwrap()
    .0;
    assert_eq!(pinned_set.bindings.len(), 2);
    for link in [&alias, &pinned_alias] {
        crate::setup::verify_current_workload_alias_link(
            link.file_name().unwrap().to_str().unwrap(),
            &account.dir,
            account.uid.as_raw(),
            Path::new(&installation.executable),
        )
        .unwrap();
    }
    let pinned_artifact = crate::binding_activation::pinned_artifact_path(
        account.uid.as_raw(),
        "bound-pinned-worker",
        &pinned_set.bindings["bound-pinned-worker"],
    )
    .unwrap();
    assert!(pinned_artifact.is_file());
    assert_eq!(
        crate::binding_activation::verify_pinned_artifact(
            account.uid.as_raw(),
            "bound-pinned-worker",
            &pinned_set.bindings["bound-pinned-worker"],
        )
        .unwrap(),
        pinned_artifact,
    );
    let mut mount_probe = Command::new("/usr/bin/systemd-run");
    mount_probe
        .args([
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--unit=dev-auth-pin-probe",
        ])
        .arg(format!("--uid={}", account.uid))
        .arg(format!("--gid={}", account.gid))
        .arg("--property=PrivateUsers=full")
        .arg("--property=PrivateMounts=yes")
        .arg(format!(
            "--property=BindReadOnlyPaths={}:{}",
            pinned_artifact.display(),
            PINNED_WORKER
        ))
        .args(["/usr/bin/test", PINNED_WORKER, "-ef"])
        .arg(&pinned_artifact)
        .env_clear();
    let mount_probe = dev_tools_command::run_prepared_bounded_command(
        &mut mount_probe,
        Duration::from_secs(40),
        64 * 1024,
    )
    .unwrap();
    assert!(
        mount_probe.status.success(),
        "pinned mount probe failed: {}",
        String::from_utf8_lossy(&mount_probe.stderr)
    );
    run_pinned(account, &pinned_alias, false);
    run_pinned(account, &pinned_alias, true);

    fs::write(
        PINNED_WORKER,
        b"#!/bin/sh\nprintf 'pinned-drift=observed\\n'\nexit 19\n",
    )
    .unwrap();
    fs::set_permissions(PINNED_WORKER, fs::Permissions::from_mode(0o755)).unwrap();
    run_pinned(account, &pinned_alias, false);
    let update_snapshot = crate::setup_v3::prepare_update_intent_from_accepted_at(
        &crate::setup::SetupPaths::strong(),
        &installation,
    )
    .unwrap();
    let preserved = update_snapshot
        .intent
        .bindings
        .iter()
        .find(|binding| binding.name == "fixture-pinned-binding")
        .unwrap();
    let preserved_bytes = fs::read(&preserved.plan).unwrap();
    assert_eq!(sha256_hex(&preserved_bytes), preserved.sha256);
    let preserved_plan: BindingPlan = serde_json::from_slice(&preserved_bytes).unwrap();
    assert_eq!(preserved_plan.change, BindingPlanChange::Unchanged);
    assert_eq!(
        preserved_plan.current_receipt,
        Some(pinned_set.bindings["bound-pinned-worker"].clone())
    );
    assert_eq!(
        crate::smart_binding::canonical_retained_binding_plan(&preserved_plan).unwrap(),
        preserved_bytes
    );
    drop(update_snapshot);
    run_bound(account, &alias, false, false);
    run_bound(account, &alias, false, true);
    run_desktop(account, &desktop);
    run_service(account, &alias);
    run_editor(account);
    run_native_config_locator(account, executable);

    let target = user_worker(account);
    let mut updated = fs::read(&target).unwrap();
    updated.extend_from_slice(b"printf 'strong-binding-edit=passed\\n'\n");
    fs::write(&target, &updated).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(fs::metadata(&target).unwrap().uid(), account.uid.as_raw());
    run_bound(account, &alias, true, false);

    let accepted = recover(executable);
    assert!(accepted.verified, "{accepted:?}");
    assert_eq!(accepted.changed, Some(false));
    let restoration = command(
        executable,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    assert!(restoration.status.success());
    let report: serde_json::Value = serde_json::from_slice(&restoration.stdout).unwrap();
    assert_eq!(report["verified"], true);
    assert_eq!(report["changed"], true);
    assert_eq!(
        fs::symlink_metadata(&alias).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        fs::symlink_metadata(&desktop).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        fs::symlink_metadata(&pinned_alias).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        fs::symlink_metadata(&receipt).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert!(target.is_file());
    assert_eq!(
        fs::symlink_metadata(&pinned_artifact).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert!(
        !crate::setup::verify_at_read_only(&SetupPaths::strong())
            .unwrap()
            .transparent_launchers_active
    );
    let restored_again = command(
        executable,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    assert!(restored_again.status.success());
    let report: serde_json::Value = serde_json::from_slice(&restored_again.stdout).unwrap();
    assert_eq!(report["changed"], false);
    exercise_pinned_retirement(account, &installation);
    publish(
        Path::new("/fixture/binding-strong-result.json"),
        b"{\"schema\":\"dev-auth-native-strong-binding-v1\",\"passed\":true,\"mutable_edit\":true,\"desktop_entry\":true,\"desktop_launch\":true,\"service_launch\":true,\"editor_launch\":true,\"native_config_locator\":true,\"pinned_bytes\":true,\"pinned_update_snapshot\":true,\"pinned_retirement\":true,\"pinned_retirement_interrupted\":true,\"restored\":true}\n",
        0o644,
    );
}

fn exercise_pinned_retirement(
    account: &nix::unistd::User,
    installation: &crate::setup::InstallReceipt,
) {
    let alias = "bound-retirement-probe";
    let first_target = Path::new("/usr/bin/true");
    let first = BindingReceipt::new(
        BindingIntent::structured(
            alias,
            "retirement-probe",
            first_target,
            Vec::<String>::new(),
        )
        .unwrap(),
        resolve_structured_target(first_target).unwrap(),
    )
    .unwrap();
    let second_target = Path::new("/usr/bin/false");
    let second = advance_binding(
        &first,
        BindingIntent::structured(
            alias,
            "retirement-probe",
            second_target,
            Vec::<String>::new(),
        )
        .unwrap(),
        resolve_structured_target(second_target).unwrap(),
    )
    .unwrap();
    let third_target = Path::new("/usr/bin/id");
    let third = advance_binding(
        &second,
        BindingIntent::structured(
            alias,
            "retirement-probe",
            third_target,
            Vec::<String>::new(),
        )
        .unwrap(),
        resolve_structured_target(third_target).unwrap(),
    )
    .unwrap();
    let generations = [&first, &second, &third];
    let stores = generations.map(|binding| {
        assert!(crate::binding_activation::publish_pinned_artifact(
            account.uid.as_raw(),
            alias,
            binding,
        )
        .unwrap());
        crate::binding_activation::pinned_artifact_path(account.uid.as_raw(), alias, binding)
            .unwrap()
    });
    let retained = crate::binding_activation::BindingSetReceipt {
        schema: "dev-auth-binding-set-v1".into(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        account_uid: account.uid.as_raw(),
        product_executable: installation.executable.clone().into(),
        product_sha256: installation.executable_sha256.clone(),
        bindings: BTreeMap::from([(alias.into(), third.clone())]),
        pinned_artifacts: BTreeMap::from([(
            alias.into(),
            dev_tools_installation::ArtifactIdentity {
                length: third.active.resolved.identity().length,
                sha256: third.active.resolved.identity().sha256.clone(),
            },
        )]),
    };
    let keep_path = Path::new("/fixture-input/pinned-retirement-keep.json");
    publish(keep_path, &serde_jcs::to_vec(&retained).unwrap(), 0o600);
    let mut interrupted = Command::new("/fixture/library-test");
    interrupted
        .args([
            "--ignored",
            "--exact",
            "setup_v3::recovery_native::binding::native_disposable_retirement_abort_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("DEV_AUTH_NATIVE_SYSTEMD_FIXTURE", "disposable")
        .env("DEV_AUTH_TEST_PIN_RETIRE_ABORT", "after_receipt")
        .current_dir("/");
    let interrupted = dev_tools_command::run_prepared_bounded_command(
        &mut interrupted,
        Duration::from_secs(40),
        64 * 1024,
    )
    .unwrap();
    assert_eq!(
        interrupted.status.code(),
        Some(77),
        "retirement death fixture did not stop at the receipt boundary: {}",
        String::from_utf8_lossy(&interrupted.stderr)
    );
    assert!(PathBuf::from(format!(
        "/var/lib/dev-auth/pinned-bindings/{}/retirement-v1.json",
        account.uid
    ))
    .is_file());
    assert!(stores[0].is_file());
    assert_eq!(
        crate::binding_activation::garbage_collect_superseded_pins(
            account.uid.as_raw(),
            &[retained],
        )
        .unwrap(),
        1
    );
    assert!(!stores[0].exists());
    assert_eq!(
        fs::read(&stores[1]).unwrap(),
        fs::read(second_target).unwrap()
    );
    assert_eq!(
        fs::read(&stores[2]).unwrap(),
        fs::read(third_target).unwrap()
    );
    assert_eq!(
        crate::binding_activation::garbage_collect_superseded_pins(account.uid.as_raw(), &[])
            .unwrap(),
        2
    );
    assert!(!stores[1].exists());
    assert!(!stores[2].exists());
}

#[test]
#[ignore = "child-only abrupt retirement fixture in an owned disposable systemd container"]
fn native_disposable_retirement_abort_child() {
    assert_eq!(
        std::env::var("DEV_AUTH_NATIVE_SYSTEMD_FIXTURE").as_deref(),
        Ok("disposable")
    );
    assert!(nix::unistd::Uid::effective().is_root());
    assert!(Path::new("/run/.containerenv").is_file());
    let account = nix::unistd::User::from_name("dev-auth-recover-alpha")
        .unwrap()
        .unwrap();
    let retained: crate::binding_activation::BindingSetReceipt =
        serde_json::from_slice(&fs::read("/fixture-input/pinned-retirement-keep.json").unwrap())
            .unwrap();
    assert_eq!(retained.account_uid, account.uid.as_raw());
    let _ = crate::binding_activation::garbage_collect_superseded_pins(
        account.uid.as_raw(),
        &[retained],
    )
    .unwrap();
    panic!("retirement death fixture did not reach its abrupt exit");
}
