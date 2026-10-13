//! Bounded catalog diagnostics. These observations never authorize GC actions.
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::adapter::Adapter;
use crate::config::GcConfig;
use crate::lease::RootLease;
use crate::resources::{self, CleanupStrategy, ResourceKind, ResourceRecord};
use crate::root::RootHandle;

const MAX_RECORD_BYTES: u64 = 64 * 1024;

#[derive(Args, Debug, Serialize)]
pub(crate) struct InventoryArgs {
    /// Maximum directory entries inspected, including non-JSON entries.
    #[arg(long, default_value_t = 1_000, value_parser = clap::value_parser!(u64).range(1..=100_000))]
    max_entries: u64,
    /// Maximum catalog content bytes read; an individual record is at most 64 KiB.
    #[arg(long, default_value_t = 4_194_304, value_parser = clap::value_parser!(u64).range(1..=67_108_864))]
    max_metadata_bytes: u64,
    /// Cooperative scan deadline checked between entries, not a kernel-I/O timeout.
    #[arg(long, default_value_t = 1_000, value_parser = clap::value_parser!(u64).range(1..=60_000))]
    max_millis: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct Inventory {
    schema: &'static str,
    scope: &'static str,
    complete: bool,
    enumeration_complete: bool,
    stopped_reason: Option<&'static str>,
    budgets: InventoryArgs,
    max_record_bytes: u64,
    observed_at_unix: u64,
    elapsed_millis: u128,
    entries_observed: u64,
    metadata_bytes_read: u64,
    records_observed: usize,
    // Null means unobserved, including when the catalog happens to be empty.
    payload_bytes: Option<u64>,
    reclaimable_bytes: Option<u64>,
    activity_scope: &'static str,
    resources: Vec<ResourceSummary>,
    issues: Vec<InventoryIssue>,
}

impl Inventory {
    pub(crate) fn exit_code(&self) -> i32 {
        if !self.issues.is_empty() {
            1
        } else if !self.complete {
            3
        } else {
            0
        }
    }
}

#[derive(Debug, Serialize)]
struct ResourceSummary {
    resource_id: String,
    adapter: Adapter,
    kind: ResourceKind,
    relative_path: PathBuf,
    cleanup: CleanupStrategy,
    last_used_unix: u64,
    age_seconds: u64,
    stale_after_seconds: u64,
    age_class: &'static str,
    retention: &'static str,
    hazards: std::collections::BTreeSet<String>,
}

#[derive(Debug, Serialize)]
struct InventoryIssue {
    path: String,
    error_kind: &'static str,
}

pub(crate) fn observe(
    root: &RootHandle,
    policy: &GcConfig,
    budgets: InventoryArgs,
) -> Result<Inventory> {
    // Match preview coordination without publishing or cleaning activity.
    let _lease = RootLease::shared_read_only(root)?;
    Ok(scan(root, policy, budgets, Instant::now))
}

fn scan(
    root: &RootHandle,
    policy: &GcConfig,
    budgets: InventoryArgs,
    mut clock: impl FnMut() -> Instant,
) -> Inventory {
    let started = clock();
    let mut result = Inventory {
        schema: "dev-cache-inventory-v1",
        scope: "resource-catalog-metadata",
        complete: false,
        enumeration_complete: false,
        stopped_reason: None,
        budgets,
        max_record_bytes: MAX_RECORD_BYTES,
        observed_at_unix: crate::util::now_unix(),
        elapsed_millis: 0,
        entries_observed: 0,
        metadata_bytes_read: 0,
        records_observed: 0,
        payload_bytes: None,
        reclaimable_bytes: None,
        activity_scope: "not_observed",
        resources: Vec::new(),
        issues: Vec::new(),
    };
    let directory = root.control().join("resources");
    if let Err(kind) = validate_directory(&directory) {
        result.issue(directory, kind);
        result.elapsed_millis = clock().duration_since(started).as_millis();
        return result;
    }
    let mut entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(_) => {
            result.issue(directory, "catalog-open-failed");
            result.elapsed_millis = clock().duration_since(started).as_millis();
            return result;
        }
    };
    let now = result.observed_at_unix;
    loop {
        if clock().duration_since(started) >= Duration::from_millis(result.budgets.max_millis) {
            result.stopped_reason = Some("time-budget");
            break;
        }
        if result.entries_observed >= result.budgets.max_entries {
            // Do not consume an extra entry to prove EOF. Reaching the budget
            // is conservatively partial even if this was the last entry.
            result.stopped_reason = Some("entry-budget");
            break;
        }
        let entry = match entries.next() {
            None => {
                result.enumeration_complete = true;
                break;
            }
            Some(Err(_)) => {
                result.issue(directory.clone(), "catalog-entry-failed");
                break;
            }
            Some(Ok(entry)) => entry,
        };
        result.entries_observed += 1;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let remaining = result.budgets.max_metadata_bytes - result.metadata_bytes_read;
        let bytes = match read_record(&path, remaining, &mut result.metadata_bytes_read) {
            Ok(bytes) => bytes,
            Err("metadata-byte-budget") => {
                result.stopped_reason = Some("metadata-byte-budget");
                break;
            }
            Err(kind) => {
                result.issue(path, kind);
                continue;
            }
        };
        let record = match serde_json::from_slice::<ResourceRecord>(&bytes) {
            Ok(record) => record,
            Err(_) => {
                result.issue(path, "invalid-record-json");
                continue;
            }
        };
        if resources::validate_record(root, &record).is_err()
            || resources::catalog_path(root, &record.resource_id) != path
        {
            result.issue(path, "invalid-resource-record");
            continue;
        }
        result.resources.push(summarize(record, policy, now));
    }
    result
        .resources
        .sort_by(|a, b| a.resource_id.cmp(&b.resource_id));
    result.records_observed = result.resources.len();
    result.complete = result.enumeration_complete && result.issues.is_empty();
    result.elapsed_millis = clock().duration_since(started).as_millis();
    result
}

impl Inventory {
    fn issue(&mut self, path: PathBuf, error_kind: &'static str) {
        // Arbitrary catalog filenames are diagnostics, not authority. Preserve
        // the complete JSON observation even for non-UTF-8 Unix filenames.
        self.issues.push(InventoryIssue {
            path: path.to_string_lossy().into_owned(),
            error_kind,
        });
    }
}

fn summarize(record: ResourceRecord, policy: &GcConfig, now: u64) -> ResourceSummary {
    let last_used_unix = record
        .last_completed_unix
        .unwrap_or(record.last_started_unix)
        .max(record.last_maintained_unix.unwrap_or(0));
    let age_seconds = now.saturating_sub(last_used_unix);
    let stale_after_seconds = if matches!(
        record.kind,
        ResourceKind::GoTemp | ResourceKind::CcacheTemp | ResourceKind::GenericTemp
    ) {
        policy.temp_grace_hours.saturating_mul(3_600)
    } else {
        policy.stale_after_days.saturating_mul(86_400)
    };
    ResourceSummary {
        resource_id: record.resource_id,
        adapter: record.adapter,
        kind: record.kind,
        relative_path: record.relative_path,
        cleanup: record.cleanup,
        last_used_unix,
        age_seconds,
        stale_after_seconds,
        age_class: if age_seconds >= stale_after_seconds {
            "stale-by-age"
        } else if age_seconds >= policy.pressure_min_age_hours.saturating_mul(3_600) {
            "pressure-age-only"
        } else {
            "recent"
        },
        retention: if record.cleanup == CleanupStrategy::Retain {
            "retained-final-output"
        } else {
            "requires-current-gc-validation"
        },
        hazards: record.hazards,
    }
}

fn validate_directory(directory: &Path) -> Result<(), &'static str> {
    // Read-only pathname preflights, not descriptor-relative mutation custody.
    // Do not follow a redirected catalog or any of its ancestors.
    for path in directory.ancestors() {
        let metadata = fs::symlink_metadata(path).map_err(|_| "catalog-metadata-failed")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
            return Err("unsafe-catalog-directory");
        }
    }
    Ok(())
}

fn read_record(path: &Path, remaining: u64, bytes_read: &mut u64) -> Result<Vec<u8>, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "record-metadata-failed")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
        return Err("unsafe-record-type");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(|_| "record-open-failed")?;
    let metadata = file.metadata().map_err(|_| "record-metadata-failed")?;
    if !metadata.is_file() || is_reparse(&metadata) {
        return Err("unsafe-record-type");
    }
    if metadata.len() > MAX_RECORD_BYTES {
        return Err("record-too-large");
    }
    // Reserve one byte to detect growth, without exceeding the total budget.
    let limit = metadata.len() + 1;
    if limit > remaining {
        return Err("metadata-byte-budget");
    }
    let mut bytes = Vec::new();
    let read = file.take(limit).read_to_end(&mut bytes);
    *bytes_read += bytes.len() as u64;
    read.map_err(|_| "record-read-failed")?;
    if bytes.len() as u64 > metadata.len() {
        return Err("record-changed-during-read");
    }
    Ok(bytes)
}

#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budgets() -> InventoryArgs {
        InventoryArgs {
            max_entries: 1_000,
            max_metadata_bytes: 4_194_304,
            max_millis: 1_000,
        }
    }

    #[test]
    fn elapsed_budget_stops_before_an_entry_is_consumed() {
        let temp = tempfile::tempdir().unwrap();
        let root = RootHandle::initialize(&temp.path().join("root")).unwrap();
        fs::write(root.control().join("resources/unread.json"), b"not JSON").unwrap();
        let start = Instant::now();
        let mut calls = 0;
        let result = scan(&root, &GcConfig::default(), budgets(), || {
            calls += 1;
            start + Duration::from_secs(u64::from(calls > 1))
        });
        assert_eq!(result.stopped_reason, Some("time-budget"));
        assert!(!result.complete);
        assert_eq!(result.entries_observed, 0);
        assert_eq!(result.metadata_bytes_read, 0);
        assert_eq!(result.exit_code(), 3);
    }

    #[test]
    fn exact_entry_budget_is_conservatively_partial_without_an_extra_read() {
        let temp = tempfile::tempdir().unwrap();
        let root = RootHandle::initialize(&temp.path().join("root")).unwrap();
        fs::write(root.control().join("resources/one.tmp"), b"ignored").unwrap();
        let result = scan(
            &root,
            &GcConfig::default(),
            InventoryArgs {
                max_entries: 1,
                ..budgets()
            },
            Instant::now,
        );
        assert_eq!(result.entries_observed, 1);
        assert_eq!(result.stopped_reason, Some("entry-budget"));
        assert!(!result.enumeration_complete);
    }

    #[test]
    fn metadata_read_budget_includes_a_growth_probe_and_never_exceeds_the_limit() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("record.json");
        fs::write(&path, b"{} ").unwrap();
        let mut read = 0;
        assert_eq!(
            read_record(&path, 3, &mut read),
            Err("metadata-byte-budget")
        );
        assert_eq!(read, 0);
        assert_eq!(read_record(&path, 4, &mut read).unwrap(), b"{} ");
        assert_eq!(read, 3);
    }
}
