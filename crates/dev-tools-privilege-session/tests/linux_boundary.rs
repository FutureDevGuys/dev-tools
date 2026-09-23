#![cfg(target_os = "linux")]

use dev_tools_privilege_session::linux::{boot_time, ExecutionBoundary};
use std::fs::File;
use std::time::Duration;

#[test]
fn an_ordinary_directory_cannot_be_presented_as_a_native_cgroup_boundary() {
    let directory = File::open(".").unwrap();
    let deadline = boot_time().unwrap() + Duration::from_secs(30);
    assert!(ExecutionBoundary::create(&directory, "not-a-real-boundary", deadline).is_err());
    assert!(!std::path::Path::new("not-a-real-boundary").exists());
}

#[test]
fn boundary_names_cannot_escape_the_retained_parent() {
    let directory = File::open(".").unwrap();
    let deadline = boot_time().unwrap() + Duration::from_secs(30);
    for name in [
        "",
        ".",
        "..",
        "../escape",
        "/absolute",
        "with/slash",
        "with space",
    ] {
        assert!(ExecutionBoundary::create(&directory, name, deadline).is_err());
    }
}
