use super::*;
use wait_timeout::ChildExt;

const FIXTURE_ROOT: &str = "DEV_AUTH_INTEGRATION_DURABILITY_ROOT";
const EXPECT_FAILURE: &str = "DEV_AUTH_INTEGRATION_DURABILITY_EXPECT_FAILURE";

#[test]
#[ignore = "requires native Linux strace acceptance"]
fn integration_deactivation_durability_fixture() {
    let root = PathBuf::from(std::env::var_os(FIXTURE_ROOT).expect("durability fixture root"));
    let owner = nix::unistd::Uid::effective().as_raw();
    let outcome = reconcile_workload_launchers_at(&root, &root.join("executable"), &[], owner)
        .and_then(|()| reconcile_desktop_entries_at(&root, &BTreeMap::new(), owner));
    if std::env::var_os(EXPECT_FAILURE).is_some() {
        assert!(outcome.is_err());
    } else {
        outcome.unwrap();
    }
}

#[test]
#[ignore = "requires native Linux strace acceptance"]
fn integration_deactivation_orders_directory_sync_before_discarding_ownership() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let executable = root.path().join("executable");
    fs::write(&executable, b"fixture executable").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let owner = nix::unistd::Uid::effective().as_raw();
    let policy = crate::policy_v2::parse_system_policy_v2(include_bytes!(
        "../../policy-v2-user-only.example.toml"
    ))
    .unwrap();
    let config =
        crate::policy_v2::parse_user_config_v2(include_bytes!("../../config-v2.example.toml"))
            .unwrap();
    let resolved = crate::policy_v2::resolve_policy(&policy, &config).unwrap();
    let aliases = resolved.workloads.keys().cloned().collect::<Vec<_>>();
    reconcile_workload_launchers_at(root.path(), &executable, &aliases, owner).unwrap();
    reconcile_desktop_entries_at(root.path(), &resolved.workloads, owner).unwrap();

    let trace = trace_deactivation(root.path(), "remove", None);
    let lines = trace.lines().collect::<Vec<_>>();
    let find = |needle: &str| {
        lines
            .iter()
            .position(|line| line.contains(needle) && line.ends_with("= 0"))
            .unwrap_or_else(|| panic!("missing syscall {needle}"))
    };
    let bin = root.path().join(".local/bin");
    let desktop = root.path().join(".local/share/applications");
    let receipts = root.path().join(".local/share/dev-auth");
    let workload_unlink = find(&format!("unlink(\"{}/automation-agent\"", bin.display()));
    let bin_sync = find(&format!("<{}>)", bin.display()));
    let workload_receipt = lines
        .iter()
        .position(|line| {
            line.contains("rename(")
                && line.contains("workload-aliases-v1.json")
                && line.ends_with("= 0")
        })
        .unwrap();
    assert!(workload_unlink < bin_sync && bin_sync < workload_receipt);
    let desktop_unlink = find(&format!(
        "unlink(\"{}/dev-auth-automation-agent.desktop\"",
        desktop.display()
    ));
    let desktop_sync = find(&format!("<{}>)", desktop.display()));
    let receipt_unlink = find(&format!(
        "unlink(\"{}/desktop-entries-v1.json\"",
        receipts.display()
    ));
    let receipt_sync = lines
        .iter()
        .enumerate()
        .find(|(index, line)| {
            *index > receipt_unlink
                && line.contains("fsync(")
                && line.contains(&format!("<{}>)", receipts.display()))
                && line.ends_with("= 0")
        })
        .map(|(index, _)| index)
        .expect("receipt absence must be synchronized");
    assert!(
        desktop_unlink < desktop_sync
            && desktop_sync < receipt_unlink
            && receipt_unlink < receipt_sync
    );

    let retry = trace_deactivation(root.path(), "retry", None);
    assert!(
        retry.lines().any(|line| line.contains("fsync(")
            && line.contains(&format!("<{}>)", receipts.display()))
            && line.ends_with("= 0")),
        "retry must synchronize receipt absence"
    );
    assert!(!retry.contains("unlink("));

    for (line, receipt_retained) in [(desktop_sync, true), (receipt_sync, false)] {
        reconcile_workload_launchers_at(root.path(), &executable, &aliases, owner).unwrap();
        reconcile_desktop_entries_at(root.path(), &resolved.workloads, owner).unwrap();
        let ordinal = lines[..=line]
            .iter()
            .filter(|line| line.contains("fsync("))
            .count();
        let failed = trace_deactivation(root.path(), "failed", Some(ordinal));
        assert!(failed.contains("EIO") && failed.contains("INJECTED"));
        assert_eq!(
            desktop_entry_receipt_path(root.path()).exists(),
            receipt_retained
        );
        assert!(!desktop.join("dev-auth-automation-agent.desktop").exists());
        trace_deactivation(root.path(), "recovered", None);
        assert!(!desktop_entry_receipt_path(root.path()).exists());
        assert!(!bin.join("automation-agent").exists());
    }
}

#[test]
fn integration_directory_sync_rejects_unsafe_leaf_and_never_creates_absence() {
    let root = tempfile::tempdir().unwrap();
    let owner = nix::unistd::Uid::effective().as_raw();
    sync_existing_integration_directory(&root.path().join("absent/child"), owner).unwrap();
    assert!(!root.path().join("absent").exists());
    assert!(sync_existing_integration_directory(root.path(), owner + 1).is_err());
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(sync_existing_integration_directory(root.path(), owner).is_err());
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let link = root.path().join("link");
    symlink(root.path(), &link).unwrap();
    assert!(sync_existing_integration_directory(&link, owner).is_err());
    sync_existing_integration_directory(root.path(), owner).unwrap();
}

fn trace_deactivation(root: &Path, phase: &str, failed_sync: Option<usize>) -> String {
    let trace = root.join(format!("{phase}.trace"));
    let mut command = Command::new("/usr/bin/strace");
    command
        .args([
            "--kill-on-exit",
            "-f",
            "-qq",
            "-yy",
            "-s",
            "4096",
            "-e",
            "trace=fsync,rename,unlink,unlinkat",
            "-o",
        ])
        .arg(&trace);
    if let Some(ordinal) = failed_sync {
        command.args(["-e", &format!("inject=fsync:error=EIO:when={ordinal}")]);
    }
    command
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "setup::restoration_durability::integration_deactivation_durability_fixture",
            "--ignored",
            "--test-threads=1",
        ])
        .env_clear()
        .env(FIXTURE_ROOT, root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if failed_sync.is_some() {
        command.env(EXPECT_FAILURE, "1");
    }
    let mut child = command.spawn().unwrap();
    let Some(status) = child.wait_timeout(Duration::from_secs(30)).unwrap() else {
        let _ = child.kill();
        let _ = child.wait();
        panic!("integration durability trace exceeded its deadline");
    };
    assert!(status.success());
    let mut bytes = Vec::new();
    File::open(trace)
        .unwrap()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 1024 * 1024);
    String::from_utf8(bytes).unwrap()
}
