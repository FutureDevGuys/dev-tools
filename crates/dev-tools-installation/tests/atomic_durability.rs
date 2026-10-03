#![cfg(target_os = "linux")]

use anyhow::{bail, Context, Result};
use dev_tools_installation::{
    observe_retired_atomic_document, read_atomic_document, remove_atomic_document_if_unchanged,
    retire_atomic_document, versioned_v2, write_atomic_document, ArtifactIdentity,
    DocumentAuthority, VersionedLayout,
};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const FIXTURE_ROOT: &str = "DEV_TOOLS_ATOMIC_DURABILITY_FIXTURE";
const FIXTURE_PHASE: &str = "DEV_TOOLS_ATOMIC_DURABILITY_PHASE";

#[test]
#[ignore = "requires Linux strace acceptance"]
fn cutover_observation_has_no_write_sync_or_lock_syscalls() -> Result<()> {
    let root = tempfile::tempdir()?;
    let authority = DocumentAuthority {
        owner_uid: root.path().metadata()?.uid(),
        mode: 0o700,
        limit: 64,
    };
    let path = root.path().join("first/second/document.json");
    write_atomic_document(&path, b"document", &authority, None)?;
    retire_atomic_document(&path, &authority, false)?;
    versioned_v2::initialize(&observation_layout(root.path())?, 1024, |_| Ok(()))?;
    let trace = trace_fixture(root.path(), "retired-read")?;
    assert_read_only_trace(&trace);
    Ok(())
}

fn assert_read_only_trace(trace: &str) {
    for forbidden in [
        "fsync(",
        "fdatasync(",
        "flock(",
        "fchmod(",
        "chmod(",
        "fchown(",
        "mkdir(",
        "mkdirat(",
        "rename(",
        "renameat(",
        "renameat2(",
        "link(",
        "linkat(",
        "unlink(",
        "unlinkat(",
        "symlink(",
        "symlinkat(",
        "truncate(",
        "ftruncate(",
        "O_CREAT",
        "O_TRUNC",
        "O_WRONLY",
        "O_RDWR",
    ] {
        assert!(
            !trace.contains(forbidden),
            "read-only cutover observation used {forbidden}"
        );
    }
}

#[test]
#[ignore = "requires Linux strace acceptance"]
fn legacy_adoption_observation_has_no_write_sync_or_lock_syscalls() -> Result<()> {
    use dev_tools_installation::{ArtifactIdentity, VersionedAdoption, VersionedTwoLevelAdoption};
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = tempfile::tempdir()?;
    let layout = observation_layout(root.path())?;
    let version_dir = layout.data_root.join("versions/1.0.0");
    fs::create_dir_all(&version_dir)?;
    fs::create_dir_all(&layout.bin_dir)?;
    for directory in [
        &layout.data_root,
        &layout.bin_dir,
        &layout.data_root.join("versions"),
        &version_dir,
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
    }
    let artifact = version_dir.join(&layout.artifact_name);
    fs::write(&artifact, b"legacy bytes")?;
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o755))?;
    let version_pointer = layout.data_root.join("current");
    symlink(&version_dir, &version_pointer)?;
    symlink(
        version_pointer.join("fixture"),
        layout.bin_dir.join("fixture"),
    )?;
    let request = VersionedTwoLevelAdoption {
        adoption: VersionedAdoption {
            layout,
            version: "1.0.0".into(),
            identity: ArtifactIdentity::from_file(&artifact, 1024)?,
            aliases: vec!["fixture".into()],
        },
        version_pointer,
    };
    fs::write(
        root.path().join("legacy-request.json"),
        serde_json::to_vec(&request)?,
    )?;
    assert_read_only_trace(&trace_fixture(root.path(), "legacy-read")?);
    Ok(())
}

fn observation_layout(root: &Path) -> Result<VersionedLayout> {
    Ok(VersionedLayout {
        product: "fixture".into(),
        data_root: root.join("installation"),
        bin_dir: root.join("bin"),
        artifact_name: "fixture".into(),
        owner_uid: root.metadata()?.uid(),
        directory_mode: 0o700,
        bin_directory_mode: None,
    })
}

// Explicit Linux acceptance: the trace observes the public implementation,
// rather than a test hook that could omit the production durability boundary.
// Run with /usr/bin/strace available and ptrace permitted:
// cargo test -p dev-tools-installation --test atomic_durability atomic_document_publication_ -- --ignored
#[test]
#[ignore = "requires Linux strace acceptance"]
fn atomic_document_publication_syncs_ancestors_and_retry() -> Result<()> {
    let root = tempfile::tempdir()?;
    let trace = trace_fixture(root.path(), "create")?;
    let publication = publication_line(&trace)?;
    for parent in [root.path().to_path_buf(), root.path().join("first")] {
        let synced = directory_sync_line(&trace, &parent)?;
        assert!(
            synced < publication,
            "ancestor must be durable before document publication"
        );
    }
    assert!(directory_sync_line(&trace, &root.path().join("first/second"))? > publication);

    let retry = trace_fixture(root.path(), "noop")?;
    assert!(
        publication_line(&retry).is_err(),
        "idempotent retry must not publish again"
    );
    for parent in [
        root.path().to_path_buf(),
        root.path().join("first"),
        root.path().join("first/second"),
    ] {
        directory_sync_line(&retry, &parent)?;
    }
    assert!(
        retry.lines().any(|line| line.contains("fsync(")
            && line.contains("/document.json>")
            && line.ends_with("= 0")),
        "idempotent acknowledgement must sync the admitted document too"
    );
    let observation = trace_fixture(root.path(), "read")?;
    assert!(
        !observation.contains("fsync("),
        "read-only observation must not synchronize storage"
    );
    Ok(())
}

#[test]
#[ignore = "requires Linux strace acceptance"]
fn atomic_document_publication_syncs_final_file_mode() -> Result<()> {
    let root = tempfile::tempdir()?;
    let trace = trace_fixture(root.path(), "create")?;
    let publication = publication_line(&trace)?;
    let protected = trace
        .lines()
        .position(|line| {
            line.contains("fchmod(")
                && line.contains("/.dev-tools-document-")
                && line.ends_with("= 0")
        })
        .context("document permissions were not applied")?;
    let synced = trace
        .lines()
        .enumerate()
        .find_map(|(index, line)| {
            (index > protected
                && line.contains("fsync(")
                && line.contains("/.dev-tools-document-")
                && line.ends_with("= 0"))
            .then_some(index)
        })
        .context("final document mode was not synchronized before publication")?;
    assert!(synced < publication);
    Ok(())
}

#[test]
#[ignore = "requires Linux strace acceptance"]
fn atomic_document_publication_retry_finishes_failed_parent_sync() -> Result<()> {
    let baseline = tempfile::tempdir()?;
    let trace = trace_fixture(baseline.path(), "create")?;
    let last_sync = trace.lines().filter(|line| line.contains("fsync(")).count();
    assert!(last_sync > 0);
    let root = tempfile::tempdir()?;
    let failed = trace_fixture_with_fault(root.path(), "failed-publication-sync", Some(last_sync))?;
    let published = publication_line(&failed)?;
    let failure = failed
        .lines()
        .position(|line| line.contains("fsync(") && line.contains("EIO"))
        .context("native sync failure was not injected")?;
    assert!(
        failure > published,
        "fixture must fail after publication, not before it"
    );
    let retry = trace_fixture(root.path(), "noop")?;
    assert!(publication_line(&retry).is_err());
    directory_sync_line(&retry, &root.path().join("first/second"))?;
    assert!(retry.lines().any(|line| line.contains("fsync(")
        && line.contains("/document.json>")
        && line.ends_with("= 0")));
    Ok(())
}

#[test]
#[ignore = "requires Linux strace acceptance"]
fn atomic_document_removal_syncs_absence_and_recovers_failed_sync() -> Result<()> {
    let root = tempfile::tempdir()?;
    let authority = DocumentAuthority {
        owner_uid: root.path().metadata()?.uid(),
        mode: 0o700,
        limit: 64,
    };
    let path = root.path().join("first/second/document.json");
    write_atomic_document(&path, b"document", &authority, None)?;
    let trace = trace_fixture(root.path(), "remove")?;
    let removal = trace
        .lines()
        .position(|line| {
            line.contains("unlinkat(") && line.contains("document.json") && line.ends_with("= 0")
        })
        .context("document removal was not traced")?;
    assert!(directory_sync_line(&trace, path.parent().unwrap())? > removal);
    let retry = trace_fixture(root.path(), "remove-noop")?;
    directory_sync_line(&retry, path.parent().unwrap())?;
    assert!(!retry.contains("unlinkat("));
    write_atomic_document(&path, b"document", &authority, None)?;
    let failed = trace_fixture_with_fault(root.path(), "remove-failed-sync", Some(1))?;
    assert!(failed
        .lines()
        .any(|line| line.contains("fsync(") && line.contains("EIO")));
    assert!(!path.exists());
    let retry = trace_fixture(root.path(), "remove-noop")?;
    directory_sync_line(&retry, path.parent().unwrap())?;
    assert!(!retry.contains("unlinkat("));
    Ok(())
}

#[test]
#[ignore = "requires Linux strace acceptance"]
fn activation_withdrawal_syncs_absence_and_recovers_sync_failures() -> Result<()> {
    for fault in [None, Some(1), Some(3)] {
        let root = tempfile::tempdir()?;
        let layout = observation_layout(root.path())?;
        let source = root.path().join("source");
        fs::write(&source, b"retained executable")?;
        let installed = dev_tools_installation::apply_versioned_installation(
            &dev_tools_installation::VersionedInstallRequest {
                layout: layout.clone(),
                version: "1.0.0".into(),
                identity: ArtifactIdentity::from_file(&source, 1024)?,
                source,
                aliases: vec!["fixture".into()],
            },
            |_| Ok(()),
        )?;
        fs::write(
            root.path().join("withdrawal-authority.json"),
            serde_json::to_vec(&installed.receipt)?,
        )?;
        let phase = if fault.is_some() {
            "withdraw-failed-sync"
        } else {
            "withdraw"
        };
        let trace = trace_fixture_with_fault(root.path(), phase, fault)?;
        if let Some(ordinal) = fault {
            assert!(trace.contains("EIO") && trace.contains("INJECTED"));
            assert_eq!(
                layout
                    .data_root
                    .join("installation-receipt-v1.json")
                    .exists(),
                ordinal == 1
            );
        } else {
            let lines = trace.lines().collect::<Vec<_>>();
            let receipt_unlink = lines
                .iter()
                .position(|line| {
                    line.contains("unlinkat(")
                        && line.contains("installation-receipt-v1.json")
                        && line.ends_with("= 0")
                })
                .context("receipt withdrawal was not traced")?;
            assert!(directory_sync_line(&trace, &layout.bin_dir)? < receipt_unlink);
            assert!(directory_sync_line(&trace, &layout.data_root)? < receipt_unlink);
            assert!(lines
                .iter()
                .skip(receipt_unlink + 1)
                .any(|line| line.contains("fsync(")
                    && line.contains(&format!("<{}>)", layout.data_root.display()))
                    && line.ends_with("= 0")));
        }
        let retry = trace_fixture(root.path(), "withdraw-retry")?;
        directory_sync_line(&retry, &layout.bin_dir)?;
        directory_sync_line(&retry, &layout.data_root)?;
        if fault != Some(1) {
            assert!(!retry.contains("unlinkat("));
        }
        assert!(!layout
            .data_root
            .join("installation-receipt-v1.json")
            .exists());
        assert!(fs::symlink_metadata(layout.data_root.join("active")).is_err());
        assert!(fs::symlink_metadata(layout.bin_dir.join("fixture")).is_err());
        assert_eq!(
            fs::read(layout.data_root.join("versions/1.0.0/fixture"))?,
            b"retained executable"
        );
        assert!(layout.data_root.join("installation.lock").is_file());
    }
    Ok(())
}

#[test]
#[ignore = "child fixture for Linux syscall acceptance"]
fn atomic_document_durability_fixture() -> Result<()> {
    let Some(root) = std::env::var_os(FIXTURE_ROOT) else {
        return Ok(());
    };
    let root = std::path::PathBuf::from(root);
    let path = root.join("first/second/document.json");
    let authority = DocumentAuthority {
        owner_uid: fs::metadata(&root)?.uid(),
        mode: 0o700,
        limit: 64,
    };
    match std::env::var(FIXTURE_PHASE)?.as_str() {
        phase @ ("directory-create"
        | "directory-noop"
        | "directory-read"
        | "directory-failed-sync") => {
            let proof = dev_tools_installation::DocumentDirectoryPreparation::observe(
                &root.join("prepared"),
                authority.owner_uid,
                0o755,
            )?;
            if phase == "directory-read" {
                proof.verify_observed()?;
                proof.read(std::ffi::OsStr::new("asset"), &authority)?;
            } else {
                let result = proof.prepare();
                if phase == "directory-failed-sync" {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result?.1, phase == "directory-create");
                    assert_eq!(root.join("prepared").metadata()?.mode() & 0o7777, 0o755);
                }
            }
            return Ok(());
        }
        phase @ ("held-create"
        | "held-noop"
        | "held-failed-sync"
        | "held-read"
        | "held-remove"
        | "held-remove-noop"
        | "held-remove-failed-sync") => {
            use sha2::{Digest, Sha256};
            use std::ffi::OsStr;
            let directory = dev_tools_installation::ExistingDocumentDirectory::open(
                &root.join("held"),
                authority.owner_uid,
            )?;
            let name = OsStr::new("document.json");
            let result = if phase.starts_with("held-remove") {
                directory.remove(
                    name,
                    &authority,
                    &ArtifactIdentity {
                        length: 8,
                        sha256: format!("{:x}", Sha256::digest(b"document")),
                    },
                )
            } else if phase == "held-read" {
                assert_eq!(
                    directory
                        .read(name, &authority)?
                        .context("held document is absent")?
                        .bytes,
                    b"document"
                );
                return Ok(());
            } else {
                directory.write(name, b"document", &authority, None)
            };
            if phase.ends_with("failed-sync") {
                assert!(result.is_err());
            } else if phase.ends_with("noop") {
                assert!(!result?);
            } else {
                assert!(result?);
            }
            return Ok(());
        }
        phase @ ("withdraw" | "withdraw-failed-sync" | "withdraw-retry") => {
            let expected =
                serde_json::from_slice(&fs::read(root.join("withdrawal-authority.json"))?)?;
            let result = dev_tools_installation::withdraw_versioned_installation_activation(
                &observation_layout(&root)?,
                &expected,
                1024,
            );
            if phase == "withdraw-failed-sync" {
                assert!(result.is_err());
            } else {
                result?;
            }
            return Ok(());
        }
        phase @ ("remove" | "remove-noop" | "remove-failed-sync") => {
            use sha2::{Digest, Sha256};
            let expected = ArtifactIdentity {
                length: 8,
                sha256: format!("{:x}", Sha256::digest(b"document")),
            };
            let result = remove_atomic_document_if_unchanged(&path, &authority, &expected);
            match phase {
                "remove" => assert!(result?),
                "remove-noop" => assert!(!result?),
                _ => assert!(result.is_err()),
            }
            assert!(!path.exists());
            return Ok(());
        }
        "create" => assert!(write_atomic_document(&path, b"document", &authority, None)?),
        "noop" => assert!(!write_atomic_document(
            &path,
            b"document",
            &authority,
            None
        )?),
        "failed-publication-sync" => {
            assert!(write_atomic_document(&path, b"document", &authority, None).is_err());
        }
        "read" => {}
        "legacy-read" => {
            let request = serde_json::from_slice(&fs::read(root.join("legacy-request.json"))?)?;
            dev_tools_installation::verify_two_level_versioned_adoption(&request, 1024)?;
            return Ok(());
        }
        "retired-read" => {
            let captured = observe_retired_atomic_document(&path, &authority)?
                .context("retirement is absent")?
                .captured
                .context("captured document is absent")?;
            assert_eq!(captured.bytes, b"document");
            assert!(versioned_v2::read_receipt_metadata(&observation_layout(&root)?)?.is_none());
            assert!(versioned_v2::pending_recovery(&observation_layout(&root)?)?.is_none());
            return Ok(());
        }
        _ => bail!("unsupported public durability fixture phase"),
    }
    let document = read_atomic_document(&path, &authority)?.context("document is absent")?;
    assert_eq!(document.bytes, b"document");
    assert_eq!(fs::metadata(&path)?.mode() & 0o777, 0o700);
    Ok(())
}

#[test]
#[ignore = "requires Linux strace acceptance"]
fn held_document_publication_is_descriptor_relative_and_durably_resumable() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for fault in [None, Some(1), Some(2)] {
        let root = tempfile::tempdir()?;
        let parent = root.path().join("held");
        fs::create_dir(&parent)?;
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
        let trace = trace_fixture_with_fault(
            root.path(),
            if fault.is_some() {
                "held-failed-sync"
            } else {
                "held-create"
            },
            fault,
        )?;
        if fault.is_some() {
            assert!(trace.contains("EIO") && trace.contains("INJECTED"));
            assert_eq!(parent.join("document.json").exists(), fault == Some(2));
        } else {
            let lines = trace.lines().collect::<Vec<_>>();
            let staged = lines
                .iter()
                .position(|line| {
                    line.contains("openat(")
                        && line.contains("O_CREAT")
                        && line.contains(".dev-tools-document-")
                })
                .context("descriptor-relative staging was not traced")?;
            assert!(lines[staged].contains(&format!("<{}>", parent.display())));
            assert!(!lines[staged].contains("AT_FDCWD"));
            let mode = lines
                .iter()
                .position(|line| line.contains("fchmod(") && line.contains(".dev-tools-document-"))
                .context("held file mode was not traced")?;
            let file_sync = lines
                .iter()
                .position(|line| line.contains("fsync(") && line.contains(".dev-tools-document-"))
                .context("held file sync was not traced")?;
            let publish = lines
                .iter()
                .position(|line| {
                    line.contains("renameat2(")
                        && line.contains("\"document.json\"")
                        && line.contains("RENAME_NOREPLACE")
                })
                .context("descriptor-relative publication was not traced")?;
            assert_eq!(
                lines[publish]
                    .matches(&format!("<{}>", parent.display()))
                    .count(),
                2
            );
            let parent_sync = directory_sync_line(&trace, &parent)?;
            assert!(
                staged < mode && mode < file_sync && file_sync < publish && publish < parent_sync
            );
            assert!(!trace.contains("mkdir") && !trace.contains(" chmod("));
        }
        let retry = trace_fixture(
            root.path(),
            if fault == Some(1) {
                "held-create"
            } else {
                "held-noop"
            },
        )?;
        directory_sync_line(&retry, &parent)?;
        if fault != Some(1) {
            assert!(!retry.contains("renameat"));
        }
        assert_eq!(fs::read(parent.join("document.json"))?, b"document");
        assert_read_only_trace(&trace_fixture(root.path(), "held-read")?);
        let removed = trace_fixture_with_fault(root.path(), "held-remove-failed-sync", Some(1))?;
        assert!(removed.contains("unlinkat(") && removed.contains("EIO"));
        assert!(!parent.join("document.json").exists());
        let absent = trace_fixture(root.path(), "held-remove-noop")?;
        assert!(!absent.contains("unlinkat("));
        directory_sync_line(&absent, &parent)?;
        assert!(fs::read_dir(&parent)?.next().is_none());
    }
    Ok(())
}

#[test]
#[ignore = "requires Linux strace acceptance"]
fn conditional_directory_publication_syncs_final_metadata_and_resumes_failed_sync() -> Result<()> {
    let root = tempfile::tempdir()?;
    assert_read_only_trace(&trace_fixture(root.path(), "directory-read")?);
    let trace = trace_fixture(root.path(), "directory-create")?;
    let lines = trace.lines().collect::<Vec<_>>();
    let stage = lines
        .iter()
        .position(|line| line.contains("mkdirat(") && line.contains(".dev-tools-directory-"))
        .context("missing directory staging")?;
    let mode = lines
        .iter()
        .position(|line| {
            line.contains("fchmod(")
                && line.contains(".dev-tools-directory-")
                && line.contains("0755")
        })
        .context("missing final directory mode")?;
    let sync = lines
        .iter()
        .position(|line| line.contains("fsync(") && line.contains(".dev-tools-directory-"))
        .context("missing staged directory sync")?;
    let publish = lines
        .iter()
        .position(|line| {
            line.contains("renameat2(")
                && line.contains("\"prepared\"")
                && line.contains("RENAME_NOREPLACE")
        })
        .context("missing conditional directory publication")?;
    let parent_sync = lines
        .iter()
        .enumerate()
        .find(|(index, line)| {
            *index > publish
                && line.contains("fsync(")
                && line.contains(&format!("<{}>", root.path().display()))
        })
        .map(|(index, _)| index)
        .context("missing parent sync after publication")?;
    assert!(stage < mode && mode < sync && sync < publish && publish < parent_sync);
    assert!(!lines[stage].contains("AT_FDCWD"));
    assert_eq!(
        lines[publish]
            .matches(&format!("<{}>", root.path().display()))
            .count(),
        2
    );
    let retry = trace_fixture(root.path(), "directory-noop")?;
    assert!(!retry.contains("mkdirat(") && !retry.contains("renameat"));
    directory_sync_line(&retry, root.path())?;
    directory_sync_line(&retry, &root.path().join("prepared"))?;
    assert_read_only_trace(&trace_fixture(root.path(), "directory-read")?);
    for (line, exists) in [(sync, false), (parent_sync, true)] {
        let fresh = tempfile::tempdir()?;
        let ordinal = lines[..=line]
            .iter()
            .filter(|line| line.contains("fsync("))
            .count();
        let failed =
            trace_fixture_with_fault(fresh.path(), "directory-failed-sync", Some(ordinal))?;
        assert!(failed.contains("EIO") && failed.contains("INJECTED"));
        assert_eq!(fresh.path().join("prepared").exists(), exists);
        let retry = trace_fixture(
            fresh.path(),
            if exists {
                "directory-noop"
            } else {
                "directory-create"
            },
        )?;
        directory_sync_line(&retry, fresh.path())?;
        assert!(!exists || !retry.contains("renameat"));
        assert!(fs::read_dir(fresh.path())?.all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".dev-tools-directory-")));
    }
    Ok(())
}

fn trace_fixture(root: &Path, phase: &str) -> Result<String> {
    trace_fixture_with_fault(root, phase, None)
}

fn trace_fixture_with_fault(
    root: &Path,
    phase: &str,
    failed_sync: Option<usize>,
) -> Result<String> {
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
            "trace=fsync,fdatasync,flock,fchmod,chmod,fchown,mkdir,mkdirat,rename,renameat,renameat2,link,linkat,unlink,unlinkat,symlink,symlinkat,truncate,ftruncate,open,openat",
            "-o",
        ])
        .arg(&trace);
    if let Some(ordinal) = failed_sync {
        command.args(["-e", &format!("inject=fsync:error=EIO:when={ordinal}")]);
    }
    let mut child = command
        .arg(std::env::current_exe()?)
        .args([
            "--exact",
            "atomic_document_durability_fixture",
            "--ignored",
            "--test-threads=1",
        ])
        .env_clear()
        .env("LC_ALL", "C")
        .env(FIXTURE_ROOT, root)
        .env(FIXTURE_PHASE, phase)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("launch native strace acceptance")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            // --kill-on-exit binds the exact tracee to this tracing process.
            let _ = child.kill();
            child.wait().context("reap timed out tracing process")?;
            bail!("native durability acceptance exceeded its deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if !status.success() {
        bail!("native durability tracing failed with {status}");
    }
    let mut bytes = Vec::new();
    File::open(trace)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        bail!("native durability trace exceeded its bound");
    }
    String::from_utf8(bytes).context("decode native durability trace")
}

fn publication_line(trace: &str) -> Result<usize> {
    trace
        .lines()
        .position(|line| {
            (line.contains("rename") || line.contains("link(") || line.contains("linkat("))
                && line.contains("/document.json")
                && line.ends_with("= 0")
        })
        .context("document publication was not traced")
}

fn directory_sync_line(trace: &str, path: &Path) -> Result<usize> {
    let descriptor = format!("<{}>)", path.display());
    trace
        .lines()
        .position(|line| {
            line.contains("fsync(") && line.contains(&descriptor) && line.ends_with("= 0")
        })
        .with_context(|| format!("directory was not synchronized: {}", path.display()))
}
