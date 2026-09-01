#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Stdio};

fn install_frontends(root: &Path, git: &Path, gh: &Path) -> dev_auth::setup::SetupPaths {
    let paths = dev_auth::setup::SetupPaths {
        data_root: root.join("data/dev-auth"),
        bin_dir: root.join("bin"),
    };
    dev_auth::setup::install_at(
        &paths,
        &dev_auth::setup::InstallRequest {
            mode: dev_auth::setup::InstallMode::UserOnly,
            version: "0.3.0-test".into(),
            source_executable: Path::new(env!("CARGO_BIN_EXE_dev-auth")).to_path_buf(),
            native_git: git.to_path_buf(),
            native_gh: gh.to_path_buf(),
            activate_transparent_launchers: true,
        },
    )
    .unwrap();
    paths
}

#[test]
fn same_name_git_without_session_forwards_native_command_unchanged() {
    let root = tempfile::Builder::new()
        .prefix("dev-auth-transparent-git-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = root.path().join("runtime");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();

    let record = root.path().join("git-record");
    let native_git = root.path().join("native-git");
    fs::write(
        &native_git,
        format!(
            "#!/bin/sh\n{{ printf 'editor=%s\\n' \"$GIT_EDITOR\"; printf 'arg=%s\\n' \"$@\"; cat; }} > '{}'\nexit 23\n",
            record.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&native_git, fs::Permissions::from_mode(0o700)).unwrap();
    let native_gh = root.path().join("native-gh");
    fs::write(&native_gh, "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&native_gh, fs::Permissions::from_mode(0o700)).unwrap();
    let paths = install_frontends(root.path(), &native_git, &native_gh);
    let frontend = paths.bin_dir.join("git");
    let mut child = Command::new(&frontend)
        .args([
            "future-command",
            "--future-flag=value",
            "operand with spaces",
        ])
        .env_clear()
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("PATH", "/usr/bin")
        .env("GIT_EDITOR", "code-insiders --wait")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"stdin-payload\n")
        .unwrap();
    let status = child.wait().unwrap();

    assert_eq!(status.code(), Some(23));
    let record = fs::read_to_string(record).unwrap();
    assert!(record.contains("editor=code-insiders --wait\n"));
    assert!(record.contains("arg=future-command\n"));
    assert!(record.contains("arg=--future-flag=value\n"));
    assert!(record.contains("arg=operand with spaces\n"));
    assert!(record.ends_with("stdin-payload\n"));
}

#[test]
fn same_name_gh_without_session_forwards_native_command_unchanged() {
    let root = tempfile::Builder::new()
        .prefix("dev-auth-transparent-gh-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = root.path().join("runtime");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();

    let record = root.path().join("gh-record");
    let native_gh = root.path().join("native-gh");
    fs::write(
        &native_gh,
        format!(
            "#!/bin/sh\n{{ printf 'editor=%s\\n' \"$GH_EDITOR\"; printf 'arg=%s\\n' \"$@\"; }} > '{}'\nexit 29\n",
            record.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&native_gh, fs::Permissions::from_mode(0o700)).unwrap();
    let native_git = root.path().join("native-git");
    fs::write(&native_git, "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&native_git, fs::Permissions::from_mode(0o700)).unwrap();
    let paths = install_frontends(root.path(), &native_git, &native_gh);
    let frontend = paths.bin_dir.join("gh");
    let status = Command::new(&frontend)
        .args(["future-extension", "--new-option", "value with spaces"])
        .env_clear()
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("PATH", "/usr/bin")
        .env("GH_EDITOR", "code-insiders --wait")
        .status()
        .unwrap();

    assert_eq!(status.code(), Some(29));
    let record = fs::read_to_string(record).unwrap();
    assert!(record.contains("editor=code-insiders --wait\n"));
    assert!(record.contains("arg=future-extension\n"));
    assert!(record.contains("arg=--new-option\n"));
    assert!(record.contains("arg=value with spaces\n"));
}

#[test]
fn same_name_frontend_is_replaced_by_native_process_for_signal_transparency() {
    let root = tempfile::Builder::new()
        .prefix("dev-auth-transparent-signal-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = root.path().join("runtime");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();

    let native_git = root.path().join("native-git");
    fs::write(&native_git, "#!/bin/sh\nkill -TERM $$\n").unwrap();
    fs::set_permissions(&native_git, fs::Permissions::from_mode(0o700)).unwrap();
    let native_gh = root.path().join("native-gh");
    fs::write(&native_gh, "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&native_gh, fs::Permissions::from_mode(0o700)).unwrap();
    let paths = install_frontends(root.path(), &native_git, &native_gh);
    let frontend = paths.bin_dir.join("git");

    let status = Command::new(&frontend)
        .env_clear()
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("PATH", "/usr/bin")
        .status()
        .unwrap();

    assert_eq!(status.signal(), Some(15));
}
