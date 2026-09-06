#![cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]

use dev_tools_command::run_prepared_bounded_command_with_cancellation;
use dev_tools_installation::{
    apply_versioned_installation, versioned_v2, ArtifactIdentity, DocumentAuthority,
    InstallationLock, VersionedInstallRequest, VersionedLayout,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// Published update-all/v0.1.8, source 18834a3b5ee550a14a12d207ca76033275fbe358.
// Its signed manifest binds this exact Linux artifact. Never accept a rebuilt
// substitute or select an installed command through ambient PATH.
const LEGACY_LENGTH: u64 = 15_379_624;
const LEGACY_SHA256: &str = "2c8f44e5bb9b3bb3964c3f544e04a85b73b27ec2d167b8f341e310ad291d0ed4";
const RELEASE_URL: &str =
    "https://github.com/FutureDevGuys/dev-tools/releases/download/update-all%2Fv0.1.8";

#[test]
#[ignore = "requires explicitly selected signed 0.1.8 artifact, strace and public GitHub HTTPS"]
fn legacy_checker_overwrites_a_successor_document_despite_the_installation_lock() {
    exercise_legacy_writer(false);
}

#[test]
#[ignore = "requires explicitly selected signed 0.1.8 artifact, strace and public GitHub HTTPS"]
fn legacy_checker_cannot_replace_a_retired_state_directory() {
    exercise_legacy_writer(true);
}

#[test]
#[ignore = "requires explicitly selected signed 0.1.8 artifact; local-only"]
fn legacy_installer_is_excluded_by_pending_and_committed_protocol_upgrade() {
    let root = tempfile::tempdir().unwrap();
    let staged = staged_legacy_binary(root.path());
    let product = root.path().join("state/dev-tools/products/update-all");
    let layout = VersionedLayout {
        product: "update-all".into(),
        data_root: product.clone(),
        bin_dir: root.path().join(".local/bin"),
        artifact_name: "update-all".into(),
        owner_uid: fs::metadata(root.path()).unwrap().uid(),
        directory_mode: 0o700,
        bin_directory_mode: Some(0o755),
    };
    let old = VersionedInstallRequest {
        layout: layout.clone(),
        version: "0.1.8".into(),
        source: staged.clone(),
        identity: ArtifactIdentity {
            length: LEGACY_LENGTH,
            sha256: LEGACY_SHA256.into(),
        },
        aliases: vec!["update-all".into()],
    };
    apply_versioned_installation(&old, |_| Ok(())).unwrap();
    // The synthetic current candidate gives the frozen engine a valid local
    // rollback control. Only its health text is needed; it is not release evidence.
    let source = root.path().join("synthetic-current");
    fs::write(&source, b"#!/bin/sh\nprintf '%s\\n' 'update-all 0.1.9'\n").unwrap();
    let current = VersionedInstallRequest {
        layout: layout.clone(),
        version: "0.1.9".into(),
        identity: ArtifactIdentity::from_file(&source, 1024).unwrap(),
        source,
        aliases: vec!["update-all".into()],
    };
    apply_versioned_installation(&current, |_| Ok(())).unwrap();
    let invoke = || {
        let mut command = Command::new(&staged);
        command
            .env_clear()
            .env("HOME", root.path())
            .env("XDG_STATE_HOME", root.path().join("state"))
            .env("PATH", "/nonexistent")
            .current_dir(root.path())
            .args(["self", "rollback", "--json"]);
        run_prepared_bounded_command_with_cancellation(
            &mut command,
            Duration::from_secs(15),
            64 * 1024,
            &AtomicBool::new(false),
        )
        .unwrap()
    };
    let control = invoke();
    assert!(
        control.status.success(),
        "rollback control failed: {control:?}"
    );
    assert_eq!(
        fs::canonicalize(layout.bin_dir.join("update-all")).unwrap(),
        product.join("versions/0.1.8/update-all")
    );
    let active = apply_versioned_installation(&current, |_| Ok(()))
        .unwrap()
        .receipt;
    let state_before = fs::read(product.join("state.json")).unwrap();
    assert!(versioned_v2::initialize(&layout, LEGACY_LENGTH, |_| {
        anyhow::bail!("fixture product cutover interrupted")
    })
    .is_err());
    for pending in [true, false] {
        if !pending {
            versioned_v2::initialize(&layout, LEGACY_LENGTH, |_| Ok(())).unwrap();
        }
        let receipt_before = fs::read(product.join("installation-receipt-v1.json")).unwrap();
        let rejected = invoke();
        assert!(
            !rejected.status.success(),
            "legacy rollback bypassed protocol fence"
        );
        let error_text = String::from_utf8_lossy(&rejected.stderr);
        assert!(
            error_text.contains("unknown field") || error_text.contains("unsupported"),
            "failure was not protocol rejection: {rejected:?}"
        );
        assert_eq!(fs::read(product.join("state.json")).unwrap(), state_before);
        assert_eq!(
            fs::read(product.join("installation-receipt-v1.json")).unwrap(),
            receipt_before
        );
        assert_eq!(
            fs::canonicalize(layout.bin_dir.join("update-all")).unwrap(),
            product.join("versions/0.1.9/update-all")
        );
    }
    assert_eq!(
        versioned_v2::observe(&layout, LEGACY_LENGTH).unwrap(),
        Some(active)
    );
}

#[test]
#[ignore = "requires explicitly selected signed 0.1.8 artifact and strace; local-only"]
fn retained_legacy_ordinary_run_survives_pending_and_committed_cutover() {
    let root = tempfile::tempdir().unwrap();
    let staged = staged_legacy_binary(root.path());
    let product = root.path().join("state/dev-tools/products/update-all");
    let layout = VersionedLayout {
        product: "update-all".into(),
        data_root: product.clone(),
        bin_dir: root.path().join(".local/bin"),
        artifact_name: "update-all".into(),
        owner_uid: fs::metadata(root.path()).unwrap().uid(),
        directory_mode: 0o700,
        bin_directory_mode: Some(0o755),
    };
    apply_versioned_installation(
        &VersionedInstallRequest {
            layout: layout.clone(),
            version: "0.1.8".into(),
            source: staged,
            identity: ArtifactIdentity {
                length: LEGACY_LENGTH,
                sha256: LEGACY_SHA256.into(),
            },
            aliases: vec!["update-all".into()],
        },
        |_| Ok(()),
    )
    .unwrap();
    let config = root.path().join("config/update-all");
    fs::create_dir_all(config.join("catalog.d/local")).unwrap();
    // Omission deliberately retains the frozen product's default auto_update=true.
    fs::write(config.join("config.toml"), "[ui]\nmode = \"plain\"\n").unwrap();
    fs::write(
        config.join("catalog.d/local/probe.toml"),
        r#"
[tasks."local/probe"]
label = "Retained ordinary operation"
os = ["linux"]
detect_mode = "command_available"
category = "maintenance"
command = "/usr/bin/true"
policy_key = "tool_update"
"#,
    )
    .unwrap();
    let authority = DocumentAuthority {
        owner_uid: layout.owner_uid,
        mode: 0o600,
        limit: 64 * 1024,
    };
    let state = product.join("state.json");
    dev_tools_installation::write_atomic_document(&state, b"{}", &authority, None).unwrap();
    assert!(versioned_v2::initialize(&layout, LEGACY_LENGTH, |_| {
        dev_tools_installation::retire_atomic_document(&state, &authority, false)?;
        anyhow::bail!("fixture interruption after product-state retirement")
    })
    .is_err());
    for pending in [true, false] {
        if !pending {
            versioned_v2::initialize(&layout, LEGACY_LENGTH, |_| Ok(())).unwrap();
        }
        let receipt = product.join("installation-receipt-v1.json");
        let journal = product.join("installation-transition-v1.json");
        let before = (fs::read(&receipt).unwrap(), fs::read(&journal).ok());
        let trace = root.path().join("ordinary.trace");
        let mut command = Command::new("/usr/bin/strace");
        command
            .env_clear()
            .env("HOME", root.path())
            .env("XDG_CONFIG_HOME", root.path().join("config"))
            .env("XDG_STATE_HOME", root.path().join("state"))
            .env("PATH", "/nonexistent")
            .current_dir(root.path())
            .args(["--kill-on-exit", "-f", "--trace=network,execve", "-o"])
            .arg(&trace)
            .arg(layout.bin_dir.join("update-all"))
            .args(["--plain", "--only", "local/probe", "--completions", "off"]);
        let output = run_prepared_bounded_command_with_cancellation(
            &mut command,
            Duration::from_secs(30),
            64 * 1024,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(
            output.status.success(),
            "ordinary operation failed: {output:?}"
        );
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains("warning: automatic update check unavailable:"));
        assert!(fs::metadata(&trace).unwrap().len() <= 1024 * 1024);
        let trace = fs::read_to_string(trace).unwrap();
        assert!(
            trace.contains("execve(\"/usr/bin/true\""),
            "task was not executed: {trace}"
        );
        assert!(
            !trace.contains("AF_INET"),
            "ordinary operation attempted IP networking: {trace}"
        );
        assert_eq!(
            (fs::read(&receipt).unwrap(), fs::read(&journal).ok()),
            before
        );
        assert_eq!(
            fs::canonicalize(layout.bin_dir.join("update-all")).unwrap(),
            product.join("versions/0.1.8/update-all")
        );
        let retired = dev_tools_installation::observe_retired_atomic_document(&state, &authority)
            .unwrap()
            .unwrap();
        assert_eq!(retired.captured.unwrap().bytes, b"{}");
    }
}

fn staged_legacy_binary(root: &Path) -> PathBuf {
    let selected = PathBuf::from(
        std::env::var_os("DEV_TOOLS_LEGACY_UPDATE_ALL")
            .expect("select the authenticated update-all 0.1.8 artifact explicitly"),
    );
    assert!(selected.is_absolute());
    let mut bytes = Vec::new();
    fs::File::open(selected)
        .unwrap()
        .take(LEGACY_LENGTH + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes.len() as u64, LEGACY_LENGTH);
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), LEGACY_SHA256);
    let staged = root.join("legacy-update-all");
    fs::write(&staged, bytes).unwrap();
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o755)).unwrap();
    staged
}

fn exercise_legacy_writer(directory_fence: bool) {
    let root = tempfile::tempdir().unwrap();
    let staged = staged_legacy_binary(root.path());
    let product = root.path().join("state/dev-tools/products/update-all");
    fs::create_dir_all(&product).unwrap();
    fs::set_permissions(&product, fs::Permissions::from_mode(0o700)).unwrap();
    let _installation_lock = InstallationLock::acquire(&product.join("installation.lock")).unwrap();
    let state = product.join("state.json");
    let trace = root.path().join("rename.trace");
    let mut command = Command::new("/usr/bin/strace");
    command
        .env_clear()
        .env("HOME", root.path())
        .env("XDG_STATE_HOME", root.path().join("state"))
        .env("PATH", "/nonexistent")
        .env(
            "DEV_TOOLS_ROOT_URL",
            format!("{RELEASE_URL}/dev-tools-root.json"),
        )
        .env(
            "DEV_TOOLS_MANIFEST_URL",
            format!("{RELEASE_URL}/update-all-stable.json"),
        )
        .current_dir(root.path())
        .args([
            "--kill-on-exit",
            "-f",
            "--trace=rename",
            "--inject=rename:delay_enter=2s",
            "-o",
        ])
        .arg(&trace)
        .arg(staged)
        .args(["self", "check", "--json"]);
    let cancelled = Arc::new(AtomicBool::new(false));
    let runner_cancelled = Arc::clone(&cancelled);
    std::thread::scope(|scope| {
        let runner = scope.spawn(move || {
            run_prepared_bounded_command_with_cancellation(
                &mut command,
                Duration::from_secs(90),
                64 * 1024,
                &runner_cancelled,
            )
        });

        // The incumbent creates this temporary only after loading prior state and
        // authenticating metadata. Syscall-entry delay opens the competing-write
        // window; the final assertions reject a missed window instead of claiming
        // success from elapsed time. This filename is only a fixture handshake,
        // never production deletion authority.
        let deadline = Instant::now() + Duration::from_secs(80);
        let mut prepared = false;
        while Instant::now() < deadline && !runner.is_finished() {
            prepared = fs::read_dir(&product)
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    name.starts_with(".state.json.") && name.ends_with(".tmp")
                });
            if prepared {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let successor = b"{\"schema\":\"successor-fixture\"}";
        let mutation = if !prepared {
            Err(std::io::Error::other(
                "legacy checker did not prepare its state write",
            ))
        } else if directory_fence {
            let authority = DocumentAuthority {
                owner_uid: product.metadata().unwrap().uid(),
                mode: 0o600,
                limit: 1024,
            };
            dev_tools_installation::write_atomic_document(&state, successor, &authority, None)
                .and_then(|_| {
                    dev_tools_installation::retire_atomic_document(&state, &authority, false)
                })
                .map(|(changed, captured)| {
                    assert!(changed);
                    assert_eq!(captured.unwrap().bytes, successor);
                })
                .map_err(std::io::Error::other)
        } else {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&state)
                .and_then(|mut file| std::io::Write::write_all(&mut file, successor))
        };
        if mutation.is_err() {
            cancelled.store(true, Ordering::Release);
        }
        let output = runner.join().unwrap();
        assert!(
            mutation.is_ok(),
            "state-write handshake failed: {mutation:?}; runner: {output:?}"
        );
        let output = output.unwrap();
        assert!(fs::metadata(&trace).unwrap().len() <= 64 * 1024);
        let trace = fs::read_to_string(trace).unwrap();
        assert!(
            trace.contains(".state.json."),
            "state publication was not traced"
        );
        if directory_fence {
            assert!(!output.status.success());
            assert!(state.is_dir());
            assert!(
                trace.contains("EISDIR"),
                "failure was not the state-path fence: {trace}"
            );
            let authority = DocumentAuthority {
                owner_uid: product.metadata().unwrap().uid(),
                mode: 0o600,
                limit: 1024,
            };
            let (changed, captured) =
                dev_tools_installation::retire_atomic_document(&state, &authority, false).unwrap();
            assert!(!changed);
            assert_eq!(captured.unwrap().bytes, successor);
        } else {
            assert!(output.status.success(), "legacy check failed: {output:?}");
            let bytes = fs::read(&state).unwrap();
            assert_ne!(bytes, successor);
            let legacy: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(legacy["accepted_generation"], 9);
            assert_eq!(legacy["accepted_version"], "0.1.8");
        }
    });
}
