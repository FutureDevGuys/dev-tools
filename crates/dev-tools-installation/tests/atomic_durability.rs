#![cfg(target_os = "linux")]

use anyhow::{bail, Context, Result};
use dev_tools_installation::{read_atomic_document, write_atomic_document, DocumentAuthority};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const FIXTURE_ROOT: &str = "DEV_TOOLS_ATOMIC_DURABILITY_FIXTURE";
const FIXTURE_PHASE: &str = "DEV_TOOLS_ATOMIC_DURABILITY_PHASE";

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
        _ => bail!("unsupported public durability fixture phase"),
    }
    let document = read_atomic_document(&path, &authority)?.context("document is absent")?;
    assert_eq!(document.bytes, b"document");
    assert_eq!(fs::metadata(&path)?.mode() & 0o777, 0o700);
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
            "trace=fsync,fchmod,fchown,mkdirat,rename,renameat,renameat2,link,linkat,unlink",
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
