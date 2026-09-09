//! Opt-in feasibility evidence, not a binding activation or broker-admission test.
#![cfg(target_os = "linux")]

use dev_auth::smart_binding::{
    resolve_structured_target, snapshot_binding_executable, BindingResolution,
};
use dev_tools_command::{run_prepared_bounded_command_with_public_input, HeldExecutable};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::Duration;

#[test]
#[ignore = "requires explicitly selected native Bubblewrap and user namespace support"]
fn plain_snapshot_mounts_do_not_protect_late_parent_replacement() {
    let bubblewrap = std::env::var_os("DEV_TOOLS_TEST_BWRAP")
        .expect("select native Bubblewrap with DEV_TOOLS_TEST_BWRAP");
    let mut observations = Vec::new();
    for anchor_parent in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("bin");
        fs::create_dir(&directory).unwrap();
        let target = directory.join("wrapper");
        fs::write(&target, b"#!/bin/sh\nprintf 'captured\\n'\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let BindingResolution::Structured { identity } =
            resolve_structured_target(&target).unwrap()
        else {
            unreachable!()
        };
        let mut snapshot = snapshot_binding_executable(&identity).unwrap();
        let mut bytes = Vec::new();
        snapshot.read_to_end(&mut bytes).unwrap();
        let held = HeldExecutable::open(bubblewrap.as_ref()).unwrap();
        let mut command = held.command(OsStr::new("bwrap")).unwrap();
        command
            .env_clear()
            .current_dir(root.path())
            .args([
                "--unshare-user",
                "--die-with-parent",
                "--ro-bind",
                "/",
                "/",
                "--bind",
            ])
            .arg(root.path())
            .arg(root.path());
        if anchor_parent {
            command.arg("--bind").arg(&directory).arg(&directory);
        }
        command
            .args(["--perms", "0700", "--ro-bind-data", "0"])
            .arg(&target);
        command.args(["--", "/bin/sh", "-c", "printf ready > \"$1/ready\"; while [ ! -e \"$1/continue\" ]; do /usr/bin/sleep 0.01; done; exec \"$1/bin/wrapper\"", "probe"]).arg(root.path());
        let (output, replaced) = std::thread::scope(|scope| {
            let runner = scope.spawn(|| {
                run_prepared_bounded_command_with_public_input(
                    &mut command,
                    &bytes,
                    Duration::from_secs(10),
                    4096,
                )
            });
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !root.path().join("ready").exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(
                root.path().join("ready").exists(),
                "namespace did not reach its gate"
            );
            let replaced = fs::rename(&directory, root.path().join("moved")).is_ok();
            if replaced {
                fs::create_dir(&directory).unwrap();
                fs::write(&target, b"#!/bin/sh\nprintf 'replacement\\n'\n").unwrap();
                fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
            }
            fs::write(root.path().join("continue"), b"continue").unwrap();
            (runner.join().unwrap().unwrap(), replaced)
        });
        assert!(
            output.status.success(),
            "anchor_parent={anchor_parent} replaced={replaced} stderr={:?}",
            output.stderr
        );
        observations.push((anchor_parent, replaced, output.stdout));
    }
    // This is a retained counterexample, not production execution behavior.
    // A bind mount remains attached to the renamed host dentry; its old path
    // can resolve to unapproved bytes in both variants. Activation must not
    // treat either mechanism as complete captured-byte path custody.
    assert_eq!(
        observations,
        vec![
            (false, true, b"replacement\n".to_vec()),
            (true, true, b"replacement\n".to_vec())
        ]
    );
}

#[test]
#[ignore = "requires explicitly selected native Bubblewrap and user namespace support"]
fn private_snapshot_mount_preserves_script_path_resources_arguments_and_exit() {
    let bubblewrap = std::env::var_os("DEV_TOOLS_TEST_BWRAP")
        .expect("select an absolute native Bubblewrap executable with DEV_TOOLS_TEST_BWRAP");
    let held = HeldExecutable::open(bubblewrap.as_ref()).expect("retain Bubblewrap executable");
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("wrapper");
    let source = b"#!/bin/sh\nIFS= read -r resource < \"$(/usr/bin/dirname \"$0\")/resource\"\nprintf '%s\\n%s\\n%s\\n' \"$0\" \"$resource\" \"$1\"\nprintf 'fixture stderr\\n' >&2\nexit 7\n";
    fs::write(root.path().join("resource"), b"adjacent public resource\n").unwrap();
    fs::write(&target, source).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    let argument = OsString::from_vec(b"literal $(not-expanded) \xff".to_vec());
    let baseline = Command::new(&target)
        .arg(&argument)
        .env_clear()
        .current_dir(root.path())
        .output()
        .unwrap();
    assert_eq!(baseline.status.code(), Some(7));
    assert!(baseline.stdout.ends_with(b"literal $(not-expanded) \xff\n"));

    let BindingResolution::Structured { identity } = resolve_structured_target(&target).unwrap()
    else {
        unreachable!()
    };
    let mut snapshot = snapshot_binding_executable(&identity).unwrap();
    fs::write(&target, b"in-place replacement after verified capture").unwrap();
    let mut snapshot_bytes = Vec::new();
    snapshot.read_to_end(&mut snapshot_bytes).unwrap();
    assert_eq!(snapshot_bytes, source);

    let replacement = b"#!/bin/sh\nprintf 'replacement\\n'\n";
    fs::remove_file(&target).unwrap();
    fs::write(&target, replacement).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();

    for project_snapshot in [false, true] {
        let mut command = held.command(OsStr::new("bwrap")).unwrap();
        command.env_clear().current_dir(root.path()).args([
            "--unshare-user",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
        ]);
        if project_snapshot {
            command
                .args(["--perms", "0700", "--ro-bind-data", "0"])
                .arg(&target);
        }
        command.arg("--").arg(&target).arg(&argument);
        let result = run_prepared_bounded_command_with_public_input(
            &mut command,
            &snapshot_bytes,
            Duration::from_secs(5),
            4096,
        )
        .expect("bounded synthetic namespace probe");
        if project_snapshot {
            assert_eq!(result.status.code(), baseline.status.code());
            assert_eq!(result.stdout, baseline.stdout);
            assert_eq!(result.stderr, baseline.stderr);
        } else {
            assert!(result.status.success());
            assert_eq!(result.stdout, b"replacement\n");
            assert_ne!(result.stdout, baseline.stdout);
        }
        assert_eq!(fs::read(&target).unwrap(), replacement);
    }
}
