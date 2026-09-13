#![cfg(any(target_os = "linux", target_os = "macos", windows))]

use std::fs;

use dev_cache::root::RootHandle;

fn marker(root: &RootHandle) -> serde_json::Value {
    serde_json::from_slice(&fs::read(root.marker_path()).unwrap()).unwrap()
}

fn replace_marker(root: &RootHandle, value: &serde_json::Value) {
    fs::write(
        root.marker_path(),
        serde_json::to_vec_pretty(value).unwrap(),
    )
    .unwrap();
}

#[test]
fn native_volume_identity_is_retained_independently_of_device_number() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(temp.path()).unwrap();
    assert!(marker(&root)["stable_volume_identity"].is_string());
}

#[cfg(target_os = "macos")]
#[test]
fn macos_runtime_is_not_labeled_as_linux() {
    assert_eq!(dev_cache::root::platform_namespace(), "macos");
}

#[test]
fn matching_filesystem_repairs_device_number_without_resetting_cache_identity() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(temp.path()).unwrap();
    fs::write(root.shared().join("sentinel"), b"preserved cache").unwrap();
    let mut before = marker(&root);
    let actual_device = before["volume_identity"].clone();
    before["volume_identity"] = "unix-dev:1".into();
    replace_marker(&root, &before);
    let reopened = RootHandle::open(temp.path()).expect("same filesystem may be renumbered");
    let after = marker(&reopened);
    before["volume_identity"] = actual_device;
    assert_eq!(
        after, before,
        "only the transient device observation changes"
    );
    assert_eq!(reopened.domain_id, root.domain_id);
    assert_eq!(
        fs::read(reopened.shared().join("sentinel")).unwrap(),
        b"preserved cache"
    );
}

#[test]
fn observing_renumbered_filesystem_is_read_only() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(temp.path()).unwrap();
    let mut value = marker(&root);
    value["volume_identity"] = "unix-dev:1".into();
    replace_marker(&root, &value);
    let before = fs::read(root.marker_path()).unwrap();
    let observed = RootHandle::observe(temp.path()).expect("stable identity is sufficient");
    assert_eq!(observed.domain_id, root.domain_id);
    assert_eq!(fs::read(root.marker_path()).unwrap(), before);
}

#[test]
fn different_filesystem_is_rejected_even_if_device_number_is_reused() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(temp.path()).unwrap();
    let mut value = marker(&root);
    value["stable_volume_identity"] = "different-filesystem".into();
    replace_marker(&root, &value);
    let before = fs::read(root.marker_path()).unwrap();
    assert!(RootHandle::observe(temp.path()).is_err());
    assert!(RootHandle::open(temp.path()).is_err());
    assert_eq!(fs::read(root.marker_path()).unwrap(), before);
}

#[test]
fn legacy_marker_enrollment_requires_the_original_volume_check() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(temp.path()).unwrap();
    let mut legacy = marker(&root);
    legacy
        .as_object_mut()
        .unwrap()
        .remove("stable_volume_identity");
    replace_marker(&root, &legacy);
    let before = fs::read(root.marker_path()).unwrap();
    RootHandle::observe(temp.path()).unwrap();
    assert_eq!(fs::read(root.marker_path()).unwrap(), before);
    RootHandle::open(temp.path()).unwrap();
    assert!(marker(&root)["stable_volume_identity"].is_string());
    legacy["volume_identity"] = "unix-dev:1".into();
    replace_marker(&root, &legacy);
    assert!(RootHandle::open(temp.path()).is_err());
    assert_eq!(marker(&root), legacy);
}

#[test]
fn concurrent_repairs_keep_the_same_runtime_domain() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(temp.path()).unwrap();
    let mut value = marker(&root);
    value["volume_identity"] = "unix-dev:1".into();
    replace_marker(&root, &value);
    let workers = (0..8)
        .map(|_| {
            let path = root.root.clone();
            std::thread::spawn(move || RootHandle::open(&path).unwrap().domain_id)
        })
        .collect::<Vec<_>>();
    for worker in workers {
        assert_eq!(worker.join().unwrap(), root.domain_id);
    }
    assert_eq!(marker(&root)["root_id"], value["root_id"]);
    assert_eq!(marker(&root)["runtime_domains"], value["runtime_domains"]);
}

#[cfg(unix)]
#[test]
fn marker_repair_does_not_follow_an_old_predictable_temporary_symlink() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("root")).unwrap();
    let unrelated = temp.path().join("unrelated");
    fs::write(&unrelated, b"unrelated bytes").unwrap();
    let collision = root
        .marker_path()
        .with_extension(format!("tmp-{}", std::process::id()));
    std::os::unix::fs::symlink(&unrelated, &collision).unwrap();
    let mut legacy = marker(&root);
    legacy
        .as_object_mut()
        .unwrap()
        .remove("stable_volume_identity");
    replace_marker(&root, &legacy);
    RootHandle::open(&root.root).unwrap();
    assert_eq!(fs::read(&unrelated).unwrap(), b"unrelated bytes");
    assert!(fs::symlink_metadata(collision)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(!fs::symlink_metadata(root.marker_path())
        .unwrap()
        .file_type()
        .is_symlink());
}
