use dev_tools_installation::InstallationLock;

#[test]
fn nonblocking_acquisition_reports_a_held_lock_as_unavailable() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("held.lock");
    let held = InstallationLock::try_acquire(&path).unwrap().unwrap();
    assert!(InstallationLock::try_acquire(&path).unwrap().is_none());
    drop(held);
    assert!(InstallationLock::try_acquire(&path).unwrap().is_some());
}
