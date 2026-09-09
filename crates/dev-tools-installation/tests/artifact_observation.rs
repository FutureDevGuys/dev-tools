#![cfg(unix)]

use dev_tools_installation::ArtifactIdentity;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[test]
fn opened_observation_rewinds_and_leaves_link_policy_to_the_caller() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("artifact");
    fs::write(&path, b"abc").unwrap();
    fs::hard_link(&path, root.path().join("retained")).unwrap();
    assert!(ArtifactIdentity::from_file(&path, 3).is_err());
    let mut file = File::open(&path).unwrap();
    file.seek(SeekFrom::Start(2)).unwrap();
    let identity = ArtifactIdentity::from_open_unix_file(&mut file, 3, |metadata| {
        assert_eq!(metadata.nlink(), 2);
        Ok(())
    })
    .unwrap();
    assert_eq!(identity.length, 3);
    assert_eq!(
        identity.sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(ArtifactIdentity::from_open_unix_file(&mut file, 3, |_| {
        anyhow::bail!("product rejected artifact")
    })
    .is_err());
}

#[test]
fn opened_observation_rejects_oversize_before_product_validation() {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"abcd").unwrap();
    assert!(ArtifactIdentity::from_open_unix_file(&mut file, 3, |_| {
        panic!("oversize artifact reached product validation")
    })
    .is_err());
}

#[test]
fn opened_observation_rejects_growth_truncation_and_metadata_mutation() {
    for operation in ["growth", "truncation", "mode", "link", "same_length_write"] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("artifact");
        fs::write(&path, b"abc").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut file = File::open(&path).unwrap();
        let result = ArtifactIdentity::from_open_unix_file(&mut file, 1024, |_| {
            match operation {
                "growth" => OpenOptions::new()
                    .append(true)
                    .open(&path)?
                    .write_all(b"d")?,
                "truncation" => OpenOptions::new().write(true).open(&path)?.set_len(2)?,
                "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?,
                "link" => fs::hard_link(&path, root.path().join("second"))?,
                "same_length_write" => {
                    fs::write(&path, b"xyz")?;
                    // Make timestamp change deterministic even on coarse filesystems.
                    File::open(&path)?.set_modified(std::time::UNIX_EPOCH)?;
                }
                _ => unreachable!(),
            }
            Ok(())
        });
        assert!(result.is_err(), "accepted {operation}");
    }
}

#[test]
fn opened_observation_preserves_explicit_empty_file_policy() {
    let mut file = tempfile::tempfile().unwrap();
    assert_eq!(
        ArtifactIdentity::from_open_unix_file(&mut file, 0, |_| Ok(()))
            .unwrap()
            .length,
        0
    );
}
