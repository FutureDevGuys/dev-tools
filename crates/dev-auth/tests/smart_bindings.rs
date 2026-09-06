#![cfg(unix)]

use dev_auth::smart_binding::{
    advance_binding, build_binding_plan, canonical_binding_plan, classify_binding_change,
    default_proxy_directories, require_automatic_refresh, resolve_continuation,
    resolve_structured_target, validate_binding_receipt_structure, write_binding_plan,
    BindingAuthority, BindingChange, BindingIntent, BindingMode, BindingPlanChange, BindingReceipt,
    BindingResolution, BindingTargetIntent,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn executable(path: &Path, body: &[u8]) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn continuation_targets_reject_ignored_execution_constraints() {
    let target = serde_json::json!({"kind": "continuation"});
    let parsed: BindingTargetIntent = serde_json::from_value(target.clone()).unwrap();
    assert_eq!(parsed, BindingTargetIntent::Continuation);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), target);
    let mut invalid = target;
    invalid["executable"] = serde_json::json!("/unexpected");
    assert!(serde_json::from_value::<BindingTargetIntent>(invalid).is_err());
}

#[test]
fn structured_arguments_preserve_native_values_at_every_insertion_position() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let fixed = vec![OsString::from("before"), OsString::from("after")];
    let caller = vec![
        OsString::from(""),
        OsString::from("two words"),
        OsString::from("$(not-a-command); *"),
        OsString::from_vec(vec![0xff, b'x']),
    ];
    for index in 0..=fixed.len() {
        let target = BindingTargetIntent::Structured {
            executable: "/unused/target".into(),
            argv_prefix: fixed.clone(),
            caller_argument_index: index,
        };
        let expected = fixed[..index]
            .iter()
            .chain(&caller)
            .chain(&fixed[index..])
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(target.forward_arguments(&caller).unwrap(), expected);
        assert_eq!(target.forward_arguments(&[]).unwrap(), fixed);
    }
    assert_eq!(
        BindingTargetIntent::Continuation
            .forward_arguments(&caller)
            .unwrap(),
        caller
    );
}

#[test]
fn argument_assembly_rejects_invalid_positions_and_unimplemented_shell_targets() {
    let invalid = BindingTargetIntent::Structured {
        executable: "/unused/target".into(),
        argv_prefix: vec![],
        caller_argument_index: usize::MAX,
    };
    assert!(invalid.forward_arguments(&[]).is_err());
    let shell = BindingTargetIntent::PinnedShell {
        shell: "/unused/shell".into(),
        source_sha256: "a".repeat(64),
    };
    assert!(shell.forward_arguments(&[]).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn binding_snapshot_is_digest_verified_sealed_and_independent_of_in_place_writes() {
    use dev_auth::smart_binding::snapshot_binding_executable;
    use std::io::{Read, Write};

    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("agent");
    let bytes = b"approved executable bytes";
    executable(&target, bytes);
    let BindingResolution::Structured { identity } = resolve_structured_target(&target).unwrap()
    else {
        unreachable!()
    };
    let mut wrong = identity.clone();
    wrong.sha256 = "0".repeat(64);
    assert!(snapshot_binding_executable(&wrong).is_err());
    let mut snapshot = snapshot_binding_executable(&identity).unwrap();
    assert!(rustix::fs::fcntl_get_seals(&snapshot).unwrap().contains(
        rustix::fs::SealFlags::SEAL
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::WRITE
    ));
    assert!(rustix::io::fcntl_getfd(&snapshot)
        .unwrap()
        .contains(rustix::io::FdFlags::CLOEXEC));
    assert_eq!(
        snapshot.metadata().unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(snapshot.write_all(b"changed").is_err());
    assert!(snapshot.set_len(0).is_err());
    assert!(snapshot.set_len(1024).is_err());
    executable(&target, &vec![b'x'; bytes.len()]);
    let mut captured = Vec::new();
    snapshot.read_to_end(&mut captured).unwrap();
    assert_eq!(captured, bytes);
    assert!(snapshot_binding_executable(&identity).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn retained_binding_checks_approved_bytes_and_executes_the_same_identity() {
    use dev_auth::smart_binding::retain_binding_executable;
    use dev_tools_command::run_prepared_bounded_command;
    use std::time::Duration;

    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("agent");
    executable(&target, b"#!/bin/sh\nprintf '%s' \"$1\"\n");
    let resolved = resolve_structured_target(&target).unwrap();
    let BindingResolution::Structured { identity } = resolved else {
        unreachable!()
    };
    let mut wrong_digest = identity.clone();
    wrong_digest.sha256 = "0".repeat(64);
    assert!(retain_binding_executable(&wrong_digest).is_err());

    let retained = retain_binding_executable(&identity).unwrap();
    fs::remove_file(&target).unwrap();
    executable(&target, b"#!/bin/sh\nprintf replacement\n");
    assert!(retain_binding_executable(&identity).is_err());
    let mut command = retained.command(target.as_os_str()).unwrap();
    command.arg("literal $(not-expanded)").env_clear();
    let result = run_prepared_bounded_command(&mut command, Duration::from_secs(3), 4096).unwrap();
    assert!(result.status.success());
    assert_eq!(result.stdout, b"literal $(not-expanded)");
    assert!(result.stderr.is_empty());
}

#[test]
fn continuation_skips_nonexecutable_files_and_broken_links_before_a_wrapper() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let first = root.path().join("first");
    let wrappers = root.path().join("wrappers");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&wrappers).unwrap();
    executable(&wrappers.join("agent"), b"wrapper");
    let search_path = std::env::join_paths([&first, &wrappers]).unwrap();
    for kind in ["nonexecutable", "broken-link"] {
        let candidate = first.join("agent");
        if kind == "nonexecutable" {
            fs::write(&candidate, b"data, not a command").unwrap();
            fs::set_permissions(&candidate, fs::Permissions::from_mode(0o600)).unwrap();
        } else {
            symlink(first.join("absent-target"), &candidate).unwrap();
        }
        #[cfg(target_os = "linux")]
        {
            let native = Command::new("/usr/bin/bash")
                .env_clear()
                .env("PATH", &search_path)
                .args(["--noprofile", "--norc", "-c", "command -v agent"])
                .output()
                .unwrap();
            assert!(native.status.success(), "{kind}");
            assert_eq!(
                String::from_utf8(native.stdout).unwrap().trim_end(),
                wrappers.join("agent").to_str().unwrap(),
                "{kind}"
            );
        }
        let resolved = resolve_continuation("agent", &search_path, &[]).unwrap();
        assert_eq!(resolved.visible_path, wrappers.join("agent"), "{kind}");
        assert_eq!(resolved.search_index, 1, "{kind}");
        assert_eq!(resolved.continuation_path, search_path, "{kind}");
        assert!(fs::symlink_metadata(&candidate).is_ok(), "{kind}");
        fs::remove_file(candidate).unwrap();
    }
}

#[test]
fn continuation_preserves_missing_search_entries_without_aborting_discovery() {
    let root = tempfile::tempdir().unwrap();
    let before = root.path().join("not-installed-before");
    let wrappers = root.path().join("wrappers");
    let after = root.path().join("not-installed-after");
    fs::create_dir(&wrappers).unwrap();
    executable(&wrappers.join("agent"), b"wrapper");
    let search_path = std::env::join_paths([&before, &wrappers, &after]).unwrap();

    let resolved = resolve_continuation("agent", &search_path, &[]).unwrap();

    assert_eq!(resolved.visible_path, wrappers.join("agent"));
    assert_eq!(resolved.search_index, 1);
    assert_eq!(resolved.continuation_path, search_path);
    assert!(!before.exists());
    assert!(!after.exists());
    let intent = BindingIntent::continuation("agent", "automation").unwrap();
    assert!(build_binding_plan("binding", intent, resolved, None).is_ok());
}

#[test]
fn continuation_skips_owned_proxy_layers_and_preserves_the_resolution_cursor() {
    let root = tempfile::tempdir().unwrap();
    let proxy = root.path().join("proxy");
    let wrappers = root.path().join("wrappers");
    let vendor = root.path().join("vendor");
    fs::create_dir(&proxy).unwrap();
    fs::create_dir(&wrappers).unwrap();
    fs::create_dir(&vendor).unwrap();
    executable(&proxy.join("codex"), b"proxy");
    executable(&wrappers.join("codex"), b"wrapper");
    executable(&vendor.join("codex"), b"vendor");

    let search_path = std::env::join_paths([&proxy, &wrappers, &vendor]).unwrap();
    let resolved = resolve_continuation("codex", &search_path, std::slice::from_ref(&proxy))
        .expect("resolve the pre-proxy command");

    assert_eq!(resolved.visible_path, wrappers.join("codex"));
    assert_eq!(resolved.search_index, 0);
    assert_eq!(
        std::env::split_paths(&resolved.continuation_path).collect::<Vec<_>>(),
        vec![wrappers, vendor]
    );
    assert_eq!(resolved.identity.length, 7);
}

#[test]
fn continuation_preserves_a_symlinked_wrapper_directory_as_the_visible_layer() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let real_wrappers = root.path().join("real-wrappers");
    let visible_wrappers = root.path().join("visible-wrappers");
    fs::create_dir(&real_wrappers).unwrap();
    executable(&real_wrappers.join("agent"), b"wrapper");
    symlink(&real_wrappers, &visible_wrappers).unwrap();

    let search_path = std::env::join_paths([&visible_wrappers]).unwrap();
    let resolved = resolve_continuation("agent", &search_path, &[]).unwrap();

    assert_eq!(resolved.visible_path, visible_wrappers.join("agent"));
    assert_eq!(
        std::env::split_paths(&resolved.continuation_path).collect::<Vec<_>>(),
        vec![visible_wrappers]
    );
    assert_eq!(resolved.canonical_path, real_wrappers.join("agent"));
}

#[test]
fn an_underlying_identity_change_is_a_refresh_but_a_new_target_is_a_rebind() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    executable(&bin.join("agent"), b"version-one");
    let path = std::env::join_paths([&bin]).unwrap();
    let first = resolve_continuation("agent", &path, &[]).unwrap();
    let intent = BindingIntent::continuation("agent", "automation").unwrap();
    let active = BindingReceipt::new(intent.clone(), first.clone()).unwrap();

    assert_eq!(
        classify_binding_change(&active, &intent, &first),
        BindingChange::Unchanged
    );

    executable(&bin.join("agent"), b"version-two");
    let refreshed = resolve_continuation("agent", &path, &[]).unwrap();
    assert_eq!(
        classify_binding_change(&active, &intent, &refreshed),
        BindingChange::Refresh
    );

    let rebound_intent =
        BindingIntent::structured("agent", "automation", "/opt/agents/agent", ["--managed"])
            .unwrap();
    assert_eq!(
        classify_binding_change(&active, &rebound_intent, &refreshed),
        BindingChange::Rebind
    );
}

#[test]
fn generations_advance_once_and_retain_one_exact_rollback_generation() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    executable(&bin.join("agent"), b"one");
    let path = std::env::join_paths([&bin]).unwrap();
    let intent = BindingIntent::continuation("agent", "automation").unwrap();
    let first = resolve_continuation("agent", &path, &[]).unwrap();
    let receipt = BindingReceipt::new(intent.clone(), first).unwrap();

    executable(&bin.join("agent"), b"two");
    let second = resolve_continuation("agent", &path, &[]).unwrap();
    let advanced = advance_binding(&receipt, intent.clone(), second.clone()).unwrap();
    assert_eq!(advanced.active.generation, 2);
    assert_eq!(advanced.previous.as_ref().unwrap().generation, 1);

    let unchanged = advance_binding(&advanced, intent, second).unwrap();
    assert_eq!(unchanged, advanced);
    assert_eq!(unchanged.active.generation, 2);
}

#[test]
fn strong_automatic_refresh_requires_independent_authority() {
    let system = resolve_continuation("true", std::ffi::OsStr::new("/usr/bin"), &[]).unwrap();
    assert_eq!(system.identity.authority, BindingAuthority::RootOwned);
    require_automatic_refresh(BindingMode::Strong, &system, false).unwrap();

    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    executable(&bin.join("agent"), b"user-owned");
    let path = std::env::join_paths([&bin]).unwrap();
    let user_owned = resolve_continuation("agent", &path, &[]).unwrap();
    assert_eq!(user_owned.identity.authority, BindingAuthority::UserOwned);
    assert!(require_automatic_refresh(BindingMode::Strong, &user_owned, true).is_err());
    assert!(require_automatic_refresh(BindingMode::UserOnly, &user_owned, false).is_err());
    require_automatic_refresh(BindingMode::UserOnly, &user_owned, true).unwrap();
}

#[test]
fn a_tampered_receipt_lineage_cannot_be_advanced() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    executable(&bin.join("agent"), b"one");
    let path = std::env::join_paths([&bin]).unwrap();
    let intent = BindingIntent::continuation("agent", "automation").unwrap();
    let resolution = resolve_continuation("agent", &path, &[]).unwrap();
    let mut receipt = BindingReceipt::new(intent.clone(), resolution.clone()).unwrap();
    receipt.active.generation = 4;

    assert!(validate_binding_receipt_structure(&receipt).is_err());
    assert!(advance_binding(&receipt, intent, resolution).is_err());
}

#[test]
fn receipt_structure_rejects_malformed_historical_identity_without_reopening_it() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("agent");
    executable(&target, b"old");
    let intent = BindingIntent::structured("agent", "automation", &target, ["fixed"]).unwrap();
    let first =
        BindingReceipt::new(intent.clone(), resolve_structured_target(&target).unwrap()).unwrap();
    executable(&target, b"replacement");
    let receipt =
        advance_binding(&first, intent, resolve_structured_target(&target).unwrap()).unwrap();
    fs::remove_file(&target).unwrap();
    validate_binding_receipt_structure(&receipt)
        .expect("structural validation must not reopen active or historical targets");

    for digest in ["", "not-a-digest", &"a".repeat(63), &"A".repeat(64)] {
        let mut invalid = receipt.clone();
        let BindingResolution::Structured { identity } =
            &mut invalid.previous.as_mut().unwrap().resolved
        else {
            unreachable!()
        };
        identity.sha256 = digest.to_owned();
        assert!(
            validate_binding_receipt_structure(&invalid).is_err(),
            "malformed historical digest must not enter a receipt"
        );
    }
    let mut invalid = receipt;
    let BindingResolution::Structured { identity } = &mut invalid.active.resolved else {
        unreachable!()
    };
    identity.length = u64::MAX;
    assert!(validate_binding_receipt_structure(&invalid).is_err());
}

#[test]
fn a_tampered_resolution_cursor_or_identity_cannot_be_accepted() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    executable(&bin.join("agent"), b"one");
    let path = std::env::join_paths([&bin]).unwrap();
    let intent = BindingIntent::continuation("agent", "automation").unwrap();
    let resolution = resolve_continuation("agent", &path, &[]).unwrap();
    let receipt = BindingReceipt::new(intent.clone(), resolution.clone()).unwrap();

    let mut bad_cursor = resolution.clone();
    bad_cursor.search_index = 1;
    assert!(advance_binding(&receipt, intent.clone(), bad_cursor).is_err());

    let mut bad_identity = resolution;
    bad_identity.identity.authority = BindingAuthority::RootOwned;
    assert!(advance_binding(&receipt, intent, bad_identity).is_err());
}

#[test]
fn continuation_rejects_relative_search_entries_and_proxy_only_cycles() {
    let root = tempfile::tempdir().unwrap();
    let proxy = root.path().join("proxy");
    fs::create_dir(&proxy).unwrap();
    executable(&proxy.join("agent"), b"proxy");

    assert!(resolve_continuation("agent", std::ffi::OsStr::new("relative"), &[]).is_err());
    let path = std::env::join_paths([&proxy]).unwrap();
    assert!(resolve_continuation("agent", &path, &[proxy]).is_err());
}

#[test]
fn canonical_binding_plans_are_value_stable_and_create_new() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    executable(&bin.join("agent"), b"one");
    let search_path = std::env::join_paths([&bin]).unwrap();
    let intent = BindingIntent::continuation("agent", "automation").unwrap();
    let resolution = resolve_continuation("agent", &search_path, &[]).unwrap();
    let first =
        build_binding_plan("agent-binding", intent.clone(), resolution.clone(), None).unwrap();
    let second = build_binding_plan("agent-binding", intent, resolution, None).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.change, BindingPlanChange::Install);
    assert_eq!(
        first
            .actions
            .iter()
            .map(|step| step.action)
            .collect::<Vec<_>>(),
        vec![
            dev_auth::smart_binding::BindingPlanActionKind::ValidateTarget,
            dev_auth::smart_binding::BindingPlanActionKind::PublishBinding,
            dev_auth::smart_binding::BindingPlanActionKind::VerifyBinding,
            dev_auth::smart_binding::BindingPlanActionKind::ActivateProxy,
        ]
    );

    let output = root.path().join("binding-plan.json");
    let digest = write_binding_plan(&output, &first).unwrap();
    assert_eq!(digest.len(), 64);
    assert!(write_binding_plan(&output, &first).is_err());
    let persisted: serde_json::Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_eq!(persisted["schema"], "dev-auth-workload-binding-plan-v2");
    assert_eq!(persisted["resolved"]["kind"], "continuation");
    assert_eq!(persisted["change"], "install");
}

#[test]
fn replacement_plans_require_verification_before_final_activation() {
    use dev_auth::smart_binding::BindingPlanActionKind::*;
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("agent");
    executable(&target, b"old");
    let intent = BindingIntent::structured("agent", "automation", &target, ["old"]).unwrap();
    let receipt =
        BindingReceipt::new(intent.clone(), resolve_structured_target(&target).unwrap()).unwrap();
    executable(&target, b"new");
    let resolved = resolve_structured_target(&target).unwrap();
    let rebound = BindingIntent::structured("agent", "automation", &target, ["new"]).unwrap();
    for (desired, change) in [
        (intent, BindingPlanChange::Refresh),
        (rebound, BindingPlanChange::Rebind),
    ] {
        let mut plan =
            build_binding_plan("binding", desired, resolved.clone(), Some(&receipt)).unwrap();
        assert_eq!(plan.change, change);
        assert_eq!(
            plan.actions
                .iter()
                .map(|step| step.action)
                .collect::<Vec<_>>(),
            vec![
                DeactivateProxy,
                ValidateTarget,
                PublishBinding,
                VerifyBinding,
                ActivateProxy
            ]
        );
        canonical_binding_plan(&plan).unwrap();
        plan.actions.retain(|step| step.action != VerifyBinding);
        for (index, step) in plan.actions.iter_mut().enumerate() {
            step.order = u16::try_from(index + 1).unwrap();
        }
        assert!(
            canonical_binding_plan(&plan).is_err(),
            "omitting verification must invalidate approval bytes"
        );
    }
}

#[test]
fn non_install_plans_are_recomputed_from_the_embedded_current_receipt() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    executable(&bin.join("agent"), b"one");
    let search_path = std::env::join_paths([&bin]).unwrap();
    let intent = BindingIntent::continuation("agent", "automation").unwrap();
    let resolution = resolve_continuation("agent", &search_path, &[]).unwrap();
    let receipt = BindingReceipt::new(intent.clone(), resolution.clone()).unwrap();
    let mut plan = build_binding_plan("agent-binding", intent, resolution, Some(&receipt)).unwrap();
    assert_eq!(plan.change, BindingPlanChange::Unchanged);
    canonical_binding_plan(&plan).unwrap();

    plan.change = BindingPlanChange::Refresh;
    assert!(canonical_binding_plan(&plan).is_err());
}

#[test]
fn standard_proxy_roots_include_strong_and_user_only_installations() {
    let roots = default_proxy_directories().unwrap();
    assert!(roots.contains(&Path::new("/usr/local/lib/dev-auth/workload-bindings/bin").into()));
    assert!(roots
        .iter()
        .any(|root| { root.ends_with(Path::new(".local/share/dev-auth/workload-bindings/bin",)) }));
}

#[test]
fn cli_discovers_and_plans_the_current_continuation_without_mutation() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    let absent = root.path().join("optional-bin");
    fs::create_dir(&bin).unwrap();
    executable(&bin.join("agent"), b"wrapper");
    let search_path = std::env::join_paths([&absent, &bin]).unwrap();

    let discovery = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .args(["workload", "bind", "discover", "agent", "--json"])
        .env("PATH", &search_path)
        .output()
        .unwrap();
    assert!(
        discovery.status.success(),
        "{}",
        String::from_utf8_lossy(&discovery.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&discovery.stdout).unwrap();
    assert_eq!(report["schema"], "dev-auth-workload-binding-discovery-v1");
    assert_eq!(report["command_name"], "agent");
    assert_eq!(report["resolved"]["search_index"], 1);
    assert!(!absent.exists());
    assert_eq!(
        report["resolved"]["visible_path"],
        bin.join("agent").to_str().unwrap()
    );

    let plan = root.path().join("plan.json");
    let planned = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .args([
            "workload",
            "bind",
            "plan",
            "agent-binding",
            "--workload",
            "automation",
            "--command-name",
            "agent",
            "--target",
            "current-resolution",
            "--output",
            plan.to_str().unwrap(),
            "--json",
        ])
        .env("PATH", &search_path)
        .output()
        .unwrap();
    assert!(
        planned.status.success(),
        "{}",
        String::from_utf8_lossy(&planned.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&planned.stdout).unwrap();
    assert_eq!(result["schema"], "dev-auth-workload-binding-plan-result-v1");
    assert_eq!(result["change"], "install");
    assert_eq!(result["sha256"].as_str().unwrap().len(), 64);
    assert!(plan.is_file());
    assert_eq!(fs::read_dir(&bin).unwrap().count(), 1);
}

#[test]
#[cfg(target_os = "linux")]
fn cli_structured_plan_rejects_owned_proxy_targets_before_output() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    let proxies = data.join("dev-auth/workload-bindings/bin");
    fs::create_dir_all(&proxies).unwrap();
    let target = proxies.join("agent");
    executable(&target, b"inspection only");
    let output = root.path().join("plan.json");
    let result = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .env_clear()
        .env("HOME", root.path())
        .env("XDG_DATA_HOME", &data)
        .args([
            "workload",
            "bind",
            "plan",
            "binding",
            "--command-name",
            "agent",
            "--workload",
            "automation",
            "--target",
            "structured",
            "--executable",
        ])
        .arg(&target)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        !result.status.success(),
        "owned proxy accepted as explicit target"
    );
    assert!(!output.exists());
    assert_eq!(fs::read(&target).unwrap(), b"inspection only");
}

#[test]
fn structured_exclusions_resolve_directory_aliases_and_preserve_siblings() {
    use dev_auth::smart_binding::resolve_structured_target_excluding;
    let root = tempfile::tempdir().unwrap();
    let proxy = root.path().join("proxy");
    let sibling = root.path().join("proxy-other");
    fs::create_dir(&proxy).unwrap();
    fs::create_dir(&sibling).unwrap();
    let rejected = proxy.join("agent");
    let accepted = sibling.join("agent");
    executable(&rejected, b"proxy");
    executable(&accepted, b"downstream");
    let alias = root.path().join("proxy-alias");
    std::os::unix::fs::symlink(&proxy, &alias).unwrap();
    let exclusions = vec![alias, root.path().join("absent-proxy")];
    assert!(resolve_structured_target_excluding(&rejected, &exclusions).is_err());
    assert_eq!(
        resolve_structured_target_excluding(&accepted, &exclusions).unwrap(),
        resolve_structured_target(&accepted).unwrap()
    );
    assert!(!root.path().join("absent-proxy").exists());
    assert!(resolve_structured_target_excluding(&accepted, &["relative".into()]).is_err());
}

#[test]
fn structured_plans_bind_the_declared_executable_and_argument_position() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let target = bin.join("vendor-runtime");
    executable(&target, b"wrapper");
    let resolved = resolve_structured_target(&target).unwrap();
    let intent =
        BindingIntent::structured("agent", "automation", &target, ["--mode", "batch"]).unwrap();
    assert!(build_binding_plan("binding", intent.clone(), resolved.clone(), None).is_ok());
    let mut substituted = intent.clone();
    if let BindingTargetIntent::Structured { executable, .. } = &mut substituted.target {
        *executable = root.path().join("different-executable");
    }
    assert!(
        build_binding_plan("binding", substituted, resolved.clone(), None).is_err(),
        "structured target cannot differ from the pinned executable"
    );
    let mut invalid_position = intent;
    if let BindingTargetIntent::Structured {
        caller_argument_index,
        ..
    } = &mut invalid_position.target
    {
        *caller_argument_index = 3;
    }
    assert!(build_binding_plan("binding", invalid_position, resolved, None).is_err());
}

#[test]
fn cli_plans_a_structured_alias_without_path_discovery_or_execution() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("vendor-runtime");
    executable(&target, b"not an executable program; inspection only");
    let output = root.path().join("plan.json");
    let result = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .env_clear()
        .args([
            "workload",
            "bind",
            "plan",
            "agent-binding",
            "--command-name",
            "agent",
            "--workload",
            "automation",
            "--target",
            "structured",
            "--executable",
        ])
        .arg(&target)
        .args([
            "--arg",
            "--mode",
            "--arg",
            "batch",
            "--caller-argument-index",
            "1",
            "--output",
        ])
        .arg(&output)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let plan: dev_auth::smart_binding::BindingPlan =
        serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(plan.schema, "dev-auth-workload-binding-plan-v2");
    assert_eq!(plan.intent.command_name, "agent");
    assert!(matches!(
        plan.resolved,
        BindingResolution::Structured { .. }
    ));
    match plan.intent.target {
        BindingTargetIntent::Structured {
            argv_prefix,
            caller_argument_index,
            ..
        } => {
            assert_eq!(
                argv_prefix,
                vec![std::ffi::OsString::from("--mode"), "batch".into()]
            );
            assert_eq!(caller_argument_index, 1);
        }
        _ => panic!("expected structured intent"),
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
}

#[test]
fn structured_resolution_does_not_invent_a_path_slot_and_rejects_kind_confusion() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("vendor-runtime");
    executable(&target, b"runtime");
    let resolved = resolve_structured_target(&target).unwrap();
    let intent = BindingIntent::structured("agent", "automation", &target, ["--batch"]).unwrap();
    let plan = build_binding_plan("agent", intent.clone(), resolved.clone(), None).unwrap();
    let document: serde_json::Value =
        serde_json::from_slice(&canonical_binding_plan(&plan).unwrap()).unwrap();
    assert_eq!(document["schema"], "dev-auth-workload-binding-plan-v2");
    assert_eq!(document["resolved"]["kind"], "structured");
    assert!(document["resolved"].get("search_index").is_none());
    assert!(document["resolved"].get("continuation_path").is_none());
    let continuation = BindingIntent::continuation("agent", "automation").unwrap();
    assert!(build_binding_plan("agent", continuation, resolved.clone(), None).is_err());
    let via_path = resolve_continuation("vendor-runtime", root.path().as_os_str(), &[]).unwrap();
    assert!(build_binding_plan("agent", intent.clone(), via_path, None).is_err());
    let receipt = BindingReceipt::new(intent.clone(), resolved.clone()).unwrap();
    assert_eq!(
        advance_binding(&receipt, intent.clone(), resolved.clone()).unwrap(),
        receipt
    );
    executable(&target, b"replacement");
    assert!(build_binding_plan("agent", intent.clone(), resolved, None).is_err());
    let refreshed = resolve_structured_target(&target).unwrap();
    let plan =
        build_binding_plan("agent", intent.clone(), refreshed.clone(), Some(&receipt)).unwrap();
    assert_eq!(plan.change, BindingPlanChange::Refresh);
    let next = advance_binding(&receipt, intent, refreshed).unwrap();
    assert_eq!(next.previous.as_ref(), Some(&receipt.active));
}

#[test]
fn structured_cli_rejects_invalid_shapes_before_writing_a_plan() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("vendor-runtime");
    executable(&target, b"runtime");
    let output = root.path().join("plan.json");
    for extra in [
        vec!["--target", "structured"],
        vec!["--target", "structured", "--executable", "relative"],
        vec![
            "--target",
            "structured",
            "--executable",
            target.to_str().unwrap(),
            "--caller-argument-index",
            "1",
        ],
        vec![
            "--target",
            "structured",
            "--executable",
            target.to_str().unwrap(),
            "--executable",
            target.to_str().unwrap(),
        ],
        vec!["--target", "current-resolution", "--arg", "--batch"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .env_clear()
            .args([
                "workload",
                "bind",
                "plan",
                "agent",
                "--command-name",
                "agent",
                "--workload",
                "automation",
                "--output",
            ])
            .arg(&output)
            .args(extra)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!output.exists());
    }
}

#[test]
fn v2_resolution_rejects_extra_fields_and_legacy_schema_relabeling() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("agent");
    executable(&target, b"runtime");
    let resolved = resolve_structured_target(&target).unwrap();
    let mut encoded = serde_json::to_value(&resolved).unwrap();
    encoded["search_index"] = serde_json::json!(0);
    assert!(serde_json::from_value::<BindingResolution>(encoded).is_err());
    let intent = BindingIntent::structured("agent", "automation", &target, ["--batch"]).unwrap();
    let mut plan = build_binding_plan("agent", intent.clone(), resolved.clone(), None).unwrap();
    plan.schema = "dev-auth-workload-binding-plan-v1".into();
    assert!(canonical_binding_plan(&plan).is_err());
    let mut receipt = BindingReceipt::new(intent, resolved).unwrap();
    receipt.schema = "dev-auth-workload-binding-receipt-v1".into();
    assert!(validate_binding_receipt_structure(&receipt).is_err());
}

#[test]
fn pinned_shell_cannot_be_planned_without_its_source_and_policy_custody() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    executable(&bin.join("agent"), b"wrapper");
    let path = std::env::join_paths([&bin]).unwrap();
    let resolved = resolve_continuation("agent", &path, &[]).unwrap();
    let mut intent = BindingIntent::continuation("agent", "automation").unwrap();
    intent.target = BindingTargetIntent::PinnedShell {
        shell: resolved.canonical_path.clone(),
        source_sha256: "a".repeat(64),
    };
    assert!(build_binding_plan("binding", intent, resolved, None).is_err());
}

#[test]
fn discovery_rejects_a_symlink_to_fifo_without_blocking() {
    use dev_tools_command::run_prepared_bounded_command;
    use std::os::unix::fs::symlink;
    use std::time::Duration;
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let fifo = root.path().join("fifo");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    symlink(&fifo, bin.join("agent")).unwrap();
    let result = run_prepared_bounded_command(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args(["workload", "bind", "discover", "agent", "--json"])
            .env("PATH", &bin),
        Duration::from_secs(5),
        4096,
    )
    .expect("discovery must reject special files without waiting for a writer");
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
}
