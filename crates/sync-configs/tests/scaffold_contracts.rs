use std::fs;

use sync_configs::scaffold::{derive_paths, initialize, render_examples};
use tempfile::TempDir;

#[test]
fn canonical_manifest_name_uses_canonical_entries_directory() {
    let root = TempDir::new().expect("tempdir");
    let paths = derive_paths(&root.path().join("sync_targets.yaml"));
    assert_eq!(paths.entries_dir, root.path().join("sync_targets.d"));
    assert_eq!(
        paths.example,
        root.path().join("sync_targets.d/00-example.yaml")
    );
}

#[test]
fn initialize_is_idempotently_guarded_and_force_replaces_both_files() {
    let root = TempDir::new().expect("tempdir");
    let manifest = root.path().join("custom.yaml");
    let paths = initialize(&manifest, false).expect("first init");
    assert!(paths.manifest.is_file());
    assert!(paths.example.is_file());
    assert!(fs::read_to_string(&manifest)
        .unwrap()
        .contains("entries_dir: ./custom.d"));

    fs::write(&manifest, "local = true\n").unwrap();
    fs::write(&paths.example, "local example\n").unwrap();
    assert!(initialize(&manifest, false).is_err());
    assert_eq!(fs::read_to_string(&manifest).unwrap(), "local = true\n");
    assert_eq!(
        fs::read_to_string(&paths.example).unwrap(),
        "local example\n"
    );

    initialize(&manifest, true).expect("force init");
    assert!(!fs::read_to_string(&manifest).unwrap().contains("local"));
    assert!(!fs::read_to_string(&paths.example)
        .unwrap()
        .contains("local example"));
}

#[test]
fn a_symlinked_entries_directory_is_rejected_without_following_it() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let root = TempDir::new().expect("tempdir");
        let outside = root.path().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, root.path().join("sync_targets.d")).unwrap();
        let error = initialize(&root.path().join("sync_targets.yaml"), false).unwrap_err();
        assert!(error.to_string().contains("not a real directory"));
        assert!(fs::read_dir(outside).unwrap().next().is_none());
    }
}

#[test]
fn printed_examples_contain_both_supported_manifest_shapes() {
    let rendered = render_examples();
    assert!(rendered.starts_with("# --- sync_targets.yaml ---"));
    assert!(rendered.contains("# --- sync_targets.d/00-example.yaml ---"));
    assert!(rendered.contains("mode: toml_overlay"));
    assert!(rendered.ends_with('\n'));
}
