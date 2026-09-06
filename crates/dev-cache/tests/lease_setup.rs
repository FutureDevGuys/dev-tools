use std::collections::BTreeSet;
use std::fs;

use dev_cache::lease::{active_resource_ids, RootLease};
use dev_cache::root::RootHandle;

#[test]
fn setup_lease_excludes_collection_without_publishing_unscoped_activity() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("root")).expect("cache root");
    let directory = root.control().join("leases");
    let lease = RootLease::shared(&root, "compiler-setup").expect("setup lease");

    assert!(RootLease::try_exclusive(&root).unwrap().is_none());
    assert_eq!(
        fs::read_dir(&directory).unwrap().count(),
        0,
        "the held setup lock already excludes collection; no unscoped record is needed"
    );

    let active = lease
        .into_active(&["second".into(), "first".into(), "first".into()])
        .expect("publish scoped activity before releasing setup lock");
    let collector = RootLease::try_exclusive(&root)
        .unwrap()
        .expect("resource activity does not block unrelated collection");
    assert_eq!(
        active_resource_ids(&root).unwrap(),
        BTreeSet::from(["first".into(), "second".into()])
    );
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
    drop(collector);
    drop(active);
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
}

#[test]
fn abandoned_setup_leaves_no_activity_and_releases_collection_lock() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("root")).expect("cache root");
    let lease = RootLease::shared(&root, "abandoned-setup").unwrap();
    drop(lease);
    assert!(RootLease::try_exclusive(&root).unwrap().is_some());
    assert_eq!(
        fs::read_dir(root.control().join("leases")).unwrap().count(),
        0
    );
}

#[test]
fn failed_activity_publication_does_not_leave_a_live_lease_or_locked_root() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("root")).expect("cache root");
    let directory = root.control().join("leases");
    let backup = root.control().join("leases-before-failure");
    let lease = RootLease::shared(&root, "failed-publication").unwrap();
    fs::rename(&directory, &backup).unwrap();
    fs::write(&directory, b"unrelated file blocks publication").unwrap();
    assert!(lease.into_active(&["resource".into()]).is_err());
    assert_eq!(
        fs::read(&directory).unwrap(),
        b"unrelated file blocks publication"
    );
    fs::remove_file(&directory).unwrap();
    fs::rename(&backup, &directory).unwrap();
    assert!(RootLease::try_exclusive(&root).unwrap().is_some());
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
}

#[test]
fn independent_activity_in_one_process_has_independent_cleanup() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("root")).expect("cache root");
    let first = RootLease::shared(&root, "first-operation")
        .unwrap()
        .into_active(&["first-resource".into()])
        .unwrap();
    let second = RootLease::shared(&root, "second-operation")
        .unwrap()
        .into_active(&["second-resource".into()])
        .unwrap();
    assert_eq!(
        fs::read_dir(root.control().join("leases")).unwrap().count(),
        2
    );
    assert_eq!(
        active_resource_ids(&root).unwrap(),
        BTreeSet::from(["first-resource".into(), "second-resource".into()])
    );
    drop(second);
    assert_eq!(
        active_resource_ids(&root).unwrap(),
        BTreeSet::from(["first-resource".into()])
    );
    drop(first);
    assert!(active_resource_ids(&root).unwrap().is_empty());
}
