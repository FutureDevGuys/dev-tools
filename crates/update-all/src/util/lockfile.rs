//! PID-based scoped lock files for update-all runtime coordination.

use anyhow::{Context, Result};
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug)]
pub(crate) struct PidLockOptions<'a> {
    pub file_name: &'a str,
    pub label: &'a str,
    pub active_detail: &'a str,
    pub retry_detail: &'a str,
    pub stale_after: Duration,
}

#[derive(Debug)]
pub(crate) struct ScopedFileLock {
    path: PathBuf,
    payload: String,
}

impl Drop for ScopedFileLock {
    fn drop(&mut self) {
        match fs::read_to_string(&self.path) {
            Ok(content) if content == self.payload => {
                let _ = fs::remove_file(&self.path);
            }
            _ => {}
        }
    }
}

pub(crate) fn try_acquire_pid_lock(
    root: &Path,
    options: PidLockOptions<'_>,
) -> Result<ScopedFileLock> {
    fs::create_dir_all(root)
        .map_err(|e| anyhow::anyhow!("create lock directory {}: {e}", root.display()))?;
    let lock_path = root.join(options.file_name);
    for _ in 0..2 {
        match fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&lock_path)
        {
            Ok(mut file) => {
                let payload = match write_pid_lock_payload(&mut file) {
                    Ok(payload) => payload,
                    Err(err) => {
                        let _ = fs::remove_file(&lock_path);
                        return Err(err);
                    }
                };
                return Ok(ScopedFileLock {
                    path: lock_path,
                    payload,
                });
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if remove_stale_pid_lock(&lock_path, options.stale_after) {
                    continue;
                }
                return Err(anyhow::anyhow!(
                    "{} is held at {}; {}",
                    options.label,
                    lock_path.display(),
                    options.active_detail
                ));
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "create lock file {}: {e}",
                    lock_path.display()
                ));
            }
        }
    }

    Err(anyhow::anyhow!(
        "{} is held at {}; {}",
        options.label,
        lock_path.display(),
        options.retry_detail
    ))
}

pub(crate) fn remove_stale_pid_lock(lock_path: &Path, stale_after: Duration) -> bool {
    remove_stale_pid_lock_with_probe(
        lock_path,
        stale_after,
        process_liveness_is_authoritative(),
        process_appears_running,
    )
}

pub(crate) fn remove_stale_pid_lock_with_probe(
    lock_path: &Path,
    stale_after: Duration,
    process_liveness_authoritative: bool,
    process_appears_running: impl Fn(u32) -> bool,
) -> bool {
    let content = fs::read_to_string(lock_path).unwrap_or_default();
    let pid = parse_lock_value(&content, "pid").and_then(|value| value.parse::<u32>().ok());
    if let Some(pid) = pid {
        if process_appears_running(pid) {
            if process_liveness_authoritative {
                return false;
            }
        } else {
            return fs::remove_file(lock_path).is_ok();
        }
    }

    let created_unix_ms =
        parse_lock_value(&content, "created_unix_ms").and_then(|value| value.parse::<u128>().ok());
    if created_unix_ms
        .is_some_and(|created_unix_ms| lock_timestamp_is_stale(created_unix_ms, stale_after))
    {
        return fs::remove_file(lock_path).is_ok();
    }

    if created_unix_ms.is_none() && lock_file_mtime_is_stale(lock_path, stale_after) {
        return fs::remove_file(lock_path).is_ok();
    }

    false
}

fn write_pid_lock_payload(file: &mut fs::File) -> Result<String> {
    let payload = format!(
        "pid={}\ncreated_unix_ms={}\n",
        std::process::id(),
        now_unix_ms()
    );
    file.write_all(payload.as_bytes())
        .context("write lock payload")?;
    file.flush().context("flush lock")?;
    Ok(payload)
}

fn parse_lock_value<'a>(content: &'a str, key: &str) -> Option<&'a str> {
    content
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
}

#[cfg(target_os = "linux")]
fn process_appears_running(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

#[cfg(not(target_os = "linux"))]
fn process_appears_running(_pid: u32) -> bool {
    true
}

#[cfg(target_os = "linux")]
fn process_liveness_is_authoritative() -> bool {
    true
}

#[cfg(not(target_os = "linux"))]
fn process_liveness_is_authoritative() -> bool {
    false
}

fn lock_timestamp_is_stale(created_unix_ms: u128, stale_after: Duration) -> bool {
    let stale_after_ms = stale_after.as_millis();
    now_unix_ms().saturating_sub(created_unix_ms) >= stale_after_ms
}

fn lock_file_mtime_is_stale(lock_path: &Path, stale_after: Duration) -> bool {
    let Ok(meta) = fs::metadata(lock_path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    let Ok(age) = SystemTime::now().duration_since(modified) else {
        return false;
    };
    age >= stale_after
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn scoped_pid_lock_removes_file_on_drop() {
        let temp = TempDir::new().unwrap();
        let options = test_options();
        let lock = try_acquire_pid_lock(temp.path(), options).unwrap();
        let lock_path = temp.path().join(options.file_name);
        assert!(lock_path.is_file());

        drop(lock);

        assert!(!lock_path.exists());
    }

    #[test]
    fn active_pid_lock_blocks_second_acquire() {
        let temp = TempDir::new().unwrap();
        let options = test_options();
        let _lock = try_acquire_pid_lock(temp.path(), options).unwrap();

        let err = try_acquire_pid_lock(temp.path(), options).unwrap_err();

        assert!(err.to_string().contains("test lock is held"), "{err:#}");
    }

    #[test]
    fn scoped_pid_lock_does_not_remove_replaced_lock_on_drop() {
        let temp = TempDir::new().unwrap();
        let options = test_options();
        let lock = try_acquire_pid_lock(temp.path(), options).unwrap();
        let lock_path = temp.path().join(options.file_name);
        let replacement = "pid=123\ncreated_unix_ms=456\n";
        fs::write(&lock_path, replacement).unwrap();

        drop(lock);

        assert_eq!(fs::read_to_string(&lock_path).unwrap(), replacement);
    }

    #[test]
    fn stale_pid_lock_is_reclaimed() {
        let temp = TempDir::new().unwrap();
        let options = test_options();
        let lock_path = temp.path().join(options.file_name);
        fs::write(&lock_path, "pid=999999999\ncreated_unix_ms=1\n").unwrap();

        let lock = try_acquire_pid_lock(temp.path(), options).unwrap();
        let payload = fs::read_to_string(&lock_path).unwrap();

        assert!(payload.contains(&format!("pid={}", std::process::id())));
        drop(lock);
        assert!(!lock_path.exists());
    }

    fn test_options() -> PidLockOptions<'static> {
        PidLockOptions {
            file_name: ".test.lock",
            label: "test lock",
            active_detail: "active owner",
            retry_detail: "retry later",
            stale_after: Duration::from_secs(6 * 60 * 60),
        }
    }
}
