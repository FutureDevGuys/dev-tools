#![cfg(target_os = "linux")]

use dev_tools_installation::{
    ArtifactIdentity, VersionedAdoption, VersionedLayout, VersionedTwoLevelAdoption,
};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;

fn fixture(root: &Path) -> VersionedTwoLevelAdoption {
    let layout = VersionedLayout {
        product: "fixture".into(),
        data_root: root.join("data"),
        bin_dir: root.join("bin"),
        artifact_name: "fixture".into(),
        owner_uid: fs::metadata(root).unwrap().uid(),
        directory_mode: 0o700,
        bin_directory_mode: None,
    };
    let version = "1.0.0";
    let artifact = layout
        .data_root
        .join("versions")
        .join(version)
        .join("fixture");
    fs::create_dir_all(artifact.parent().unwrap()).unwrap();
    fs::create_dir_all(&layout.bin_dir).unwrap();
    for path in [
        &layout.data_root,
        &layout.bin_dir,
        &layout.data_root.join("versions"),
        artifact.parent().unwrap(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::write(&artifact, b"authenticated fixture bytes").unwrap();
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o755)).unwrap();
    let version_pointer = layout.data_root.join("current");
    symlink(artifact.parent().unwrap(), &version_pointer).unwrap();
    symlink(
        version_pointer.join("fixture"),
        layout.bin_dir.join("fixture"),
    )
    .unwrap();
    VersionedTwoLevelAdoption {
        adoption: VersionedAdoption {
            layout,
            version: version.into(),
            identity: ArtifactIdentity::from_file(&artifact, 1024).unwrap(),
            aliases: vec!["fixture".into()],
        },
        version_pointer,
    }
}

fn snapshot(root: &Path) -> Vec<(std::path::PathBuf, u32, u64, Vec<u8>)> {
    fn visit(path: &Path, out: &mut Vec<(std::path::PathBuf, u32, u64, Vec<u8>)>) {
        let metadata = fs::symlink_metadata(path).unwrap();
        let bytes = if metadata.file_type().is_symlink() {
            fs::read_link(path)
                .unwrap()
                .as_os_str()
                .as_encoded_bytes()
                .to_vec()
        } else if metadata.is_file() {
            fs::read(path).unwrap()
        } else {
            Vec::new()
        };
        out.push((path.into(), metadata.mode(), metadata.ino(), bytes));
        if metadata.is_dir() {
            let mut entries = fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            entries.sort();
            for entry in entries {
                visit(&entry, out);
            }
        }
    }
    let mut result = Vec::new();
    visit(root, &mut result);
    result
}

#[test]
fn legacy_preflight_preserves_unhardened_layout_and_namespace() {
    let root = tempfile::tempdir().unwrap();
    let request = fixture(root.path());
    let before = snapshot(root.path());
    dev_tools_installation::verify_two_level_versioned_adoption(&request, 1024).unwrap();
    assert_eq!(
        snapshot(root.path()),
        before,
        "preflight must not adopt or harden the installation"
    );
}

#[test]
fn legacy_preflight_rejects_hostile_custody_without_repair() {
    for change in [
        "receipt",
        "journal",
        "active",
        "previous",
        "directory-mode",
        "directory-symlink",
        "missing-directory",
        "artifact-mode",
        "artifact-symlink",
        "artifact-hardlink",
        "artifact-bytes",
        "owner",
        "alias",
        "current",
        "missing-artifact",
        "bound",
        "zero-bound",
        "version",
        "alias-name",
        "pointer-path",
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut request = fixture(root.path());
        let layout = &request.adoption.layout;
        let artifact = layout.data_root.join("versions/1.0.0/fixture");
        let mut bound = 1024;
        match change {
            "receipt" | "journal" => fs::write(
                layout.data_root.join(if change == "receipt" {
                    "installation-receipt-v1.json"
                } else {
                    "installation-transition-v1.json"
                }),
                b"unknown authority",
            )
            .unwrap(),
            "active" | "previous" => symlink(&artifact, layout.data_root.join(change)).unwrap(),
            "directory-mode" => {
                fs::set_permissions(&layout.bin_dir, fs::Permissions::from_mode(0o777)).unwrap()
            }
            "directory-symlink" => {
                let versions = layout.data_root.join("versions");
                let moved = root.path().join("moved-versions");
                fs::rename(&versions, &moved).unwrap();
                symlink(moved, versions).unwrap();
            }
            "missing-directory" => {
                fs::rename(&layout.data_root, root.path().join("retained-data")).unwrap();
            }
            "artifact-mode" => {
                fs::set_permissions(&artifact, fs::Permissions::from_mode(0o777)).unwrap()
            }
            "artifact-symlink" => {
                let moved = root.path().join("moved-artifact");
                fs::rename(&artifact, &moved).unwrap();
                symlink(moved, &artifact).unwrap();
            }
            "artifact-hardlink" => {
                fs::hard_link(&artifact, root.path().join("extra-link")).unwrap()
            }
            "artifact-bytes" => fs::write(&artifact, b"unapproved content").unwrap(),
            "owner" => request.adoption.layout.owner_uid ^= 1,
            "alias" | "current" => {
                let path = if change == "alias" {
                    layout.bin_dir.join("fixture")
                } else {
                    request.version_pointer.clone()
                };
                fs::remove_file(&path).unwrap();
                symlink(root.path().join("unowned"), path).unwrap();
            }
            "missing-artifact" => fs::remove_file(&artifact).unwrap(),
            "bound" => bound = request.adoption.identity.length - 1,
            "zero-bound" => bound = 0,
            "version" => request.adoption.version = "../escape".into(),
            "alias-name" => request.adoption.aliases = vec!["../escape".into()],
            "pointer-path" => request.version_pointer = root.path().join("other"),
            _ => unreachable!(),
        }
        let before = snapshot(root.path());
        assert!(
            dev_tools_installation::verify_two_level_versioned_adoption(&request, bound).is_err(),
            "{change}"
        );
        assert_eq!(snapshot(root.path()), before, "{change}");
    }
}

#[test]
fn legacy_preflight_preserves_absent_pointers_without_claiming_receipt_ownership() {
    let root = tempfile::tempdir().unwrap();
    let request = fixture(root.path());
    fs::remove_file(&request.version_pointer).unwrap();
    fs::remove_file(request.adoption.layout.bin_dir.join("fixture")).unwrap();
    let before = snapshot(root.path());
    dev_tools_installation::verify_two_level_versioned_adoption(&request, 1024).unwrap();
    assert_eq!(snapshot(root.path()), before);
}
