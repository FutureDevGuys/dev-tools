//! Single-test process isolation for unit tests that observe descriptor release.
//!
//! A concurrent test's child holds copies of every descriptor in the shared
//! libtest process, close-on-exec ones included, until it executes. A lock,
//! pipe writer or executable writer closed here can therefore stay open for an
//! unbounded time. The isolated process has no concurrent test threads.

#![cfg(test)]

const MARKER: &str = "DEV_AUTH_ISOLATED_UNIT_TEST";

/// Returns `false` inside the isolated process, where the caller runs its body.
/// Otherwise runs `full_name` (from `concat!(module_path!(), "::name")`) alone,
/// requires exactly that test to pass, and returns `true`.
pub(crate) fn run_isolated(full_name: &str) -> bool {
    let (_, name) = full_name
        .split_once("::")
        .expect("isolated test name includes its crate");
    if std::env::var_os(MARKER).is_some_and(|value| value == name) {
        return false;
    }
    let mut environment: std::collections::BTreeMap<_, _> = std::env::vars_os().collect();
    environment.insert(MARKER.into(), name.into());
    let output = dev_tools_command::run_bounded_command(&dev_tools_command::BoundedCommand {
        executable: &std::env::current_exe().unwrap(),
        arguments: &[
            "--exact".into(),
            name.into(),
            "--test-threads=1".into(),
            "--nocapture".into(),
        ],
        environment: &environment,
        cwd: None,
        timeout: std::time::Duration::from_secs(120),
        output_limit: 1024 * 1024,
    })
    .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed"),
        "isolated {name}: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    true
}
