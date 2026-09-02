use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use dev_tools_command::{
    executable_candidates, first_executable, prepend_path, run_bounded_command, same_path_location,
    BoundedCommand,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
fn executable(path: &Path) {
    fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn bounded_command_capture_is_environment_explicit_size_bounded_and_timed() {
    let output = run_bounded_command(&BoundedCommand {
        executable: Path::new("/usr/bin/printf"),
        arguments: &["%s".into(), "hello".into()],
        environment: &Default::default(),
        cwd: None,
        timeout: Duration::from_secs(1),
        output_limit: 32,
    })
    .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"hello");
    assert!(output.stderr.is_empty());

    let oversized = run_bounded_command(&BoundedCommand {
        executable: Path::new("/usr/bin/printf"),
        arguments: &["%033d".into(), "1".into()],
        environment: &Default::default(),
        cwd: None,
        timeout: Duration::from_secs(1),
        output_limit: 32,
    });
    assert!(oversized.is_err());

    let timed_out = run_bounded_command(&BoundedCommand {
        executable: Path::new("/usr/bin/sleep"),
        arguments: &["2".into()],
        environment: &Default::default(),
        cwd: None,
        timeout: Duration::from_millis(10),
        output_limit: 32,
    });
    assert!(timed_out.is_err());
}

#[cfg(unix)]
#[test]
fn executable_search_preserves_path_order_and_requires_execute_permission() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    fs::write(first.path().join("tool"), b"not executable").unwrap();
    executable(&second.path().join("tool"));
    let path = vec![first.path().to_path_buf(), second.path().to_path_buf()];

    assert_eq!(
        executable_candidates(&path, "tool"),
        vec![second.path().join("tool")]
    );
    assert_eq!(
        first_executable(&path, "tool"),
        Some(second.path().join("tool"))
    );
}

#[test]
fn same_location_accepts_equivalent_parent_paths_but_not_other_names() {
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("nested");
    fs::create_dir(&nested).unwrap();
    assert!(same_path_location(
        &nested.join("../nested/tool"),
        &nested.join("tool")
    ));
    assert!(!same_path_location(
        &nested.join("tool"),
        &nested.join("other")
    ));
}

#[test]
fn path_prepend_is_platform_encoded_and_rejects_non_absolute_directory() {
    let inherited = std::env::join_paths([Path::new("/usr/bin"), Path::new("/bin")]).unwrap();
    let value = prepend_path(
        Path::new("/opt/dev-auth/session-bin"),
        Some(OsStr::new(&inherited)),
    )
    .unwrap();
    assert_eq!(
        std::env::split_paths(&value).collect::<Vec<PathBuf>>(),
        vec![
            PathBuf::from("/opt/dev-auth/session-bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin")
        ]
    );
    assert!(prepend_path(Path::new("relative/bin"), None).is_err());
}
