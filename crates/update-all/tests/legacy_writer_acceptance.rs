#![cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]

use dev_tools_command::run_prepared_bounded_command_with_cancellation;
use dev_tools_installation::InstallationLock;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
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
            fs::create_dir(&state)
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
