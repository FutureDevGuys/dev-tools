//! Read-only, single-pass apparent-size observation. This is not GC authority.
use std::fs;
use std::io::Write;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::root::RootHandle;

const MAX_DEPTH: usize = 256;

#[derive(Debug, Default)]
pub(crate) struct Observation {
    pub complete: bool,
    pub cancelled: bool,
    pub bytes: Option<u64>,
    pub repos_bytes: Option<u64>,
    pub shared_bytes: Option<u64>,
    pub artifacts_bytes: Option<u64>,
    pub other_bytes: Option<u64>,
    pub entries_observed: u64,
    pub files_observed: u64,
    pub links_skipped: u64,
    pub error_kind: Option<&'static str>,
}

impl Observation {
    pub fn fail(&mut self, kind: &'static str) {
        self.complete = false;
        self.error_kind = Some(kind);
        self.bytes = None;
        self.repos_bytes = None;
        self.shared_bytes = None;
        self.artifacts_bytes = None;
        self.other_bytes = None;
    }

    fn check_cancelled(&mut self, cancelled: &AtomicBool) -> bool {
        if cancelled.load(Ordering::Acquire) {
            self.cancelled = true;
            self.fail("cancelled");
        }
        self.cancelled
    }
}

#[derive(Default)]
pub(crate) struct Progress {
    last: Option<Duration>,
}

impl Progress {
    pub fn due(&mut self, elapsed: Duration) -> bool {
        if self
            .last
            .is_none_or(|last| elapsed.saturating_sub(last) >= Duration::from_secs(1))
        {
            self.last = Some(elapsed);
            true
        } else {
            false
        }
    }
}

pub(crate) fn write_progress(writer: &mut impl Write, entries: u64) {
    // Progress is optional. A closed/broken stderr must not replace the scan's
    // result with a formatting panic or operational failure.
    let _ = writeln!(
        writer,
        "dev-cache report: scanning cache sizes ({entries} entries); Ctrl-C stops the scan"
    );
}

pub(crate) fn observe(
    root: &RootHandle,
    cancelled: &AtomicBool,
    mut progress: impl FnMut(u64),
) -> Observation {
    progress(0);
    scan(root, cancelled, |_, entries| progress(entries))
}

fn validate_root(root: &RootHandle) -> Result<(), &'static str> {
    // Do not turn a malformed domain selector or a redirected ancestor into a
    // new traversal root. These are pathname preflights, not retained custody.
    let relative = root
        .platform_root
        .strip_prefix(&root.root)
        .map_err(|_| "unsafe-root")?;
    if !root.root.is_absolute()
        || relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("unsafe-root");
    }
    let ancestors = root.platform_root.ancestors().collect::<Vec<_>>();
    if ancestors.len() > MAX_DEPTH {
        return Err("depth-limit");
    }
    for path in ancestors.into_iter().rev() {
        let metadata = fs::symlink_metadata(path).map_err(|_| "root-observation-failed")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err("unsafe-root");
        }
    }
    Ok(())
}

fn scan(
    root: &RootHandle,
    cancelled: &AtomicBool,
    mut visited: impl FnMut(&Path, u64),
) -> Observation {
    let mut result = Observation::default();
    if result.check_cancelled(cancelled) {
        return result;
    }
    if let Err(kind) = validate_root(root) {
        result.fail(kind);
        return result;
    }
    let mut sizes = [0_u64; 4];
    let mut entries = walkdir::WalkDir::new(&root.platform_root)
        .follow_links(false)
        .follow_root_links(false)
        .max_open(32)
        .into_iter();
    loop {
        if result.check_cancelled(cancelled) {
            return result;
        }
        let Some(entry) = entries.next() else { break };
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                result.fail("tree-observation-failed");
                return result;
            }
        };
        if entry.depth() > MAX_DEPTH {
            result.fail("depth-limit");
            return result;
        }
        result.entries_observed += 1;
        visited(entry.path(), result.entries_observed);
        if result.check_cancelled(cancelled) {
            return result;
        }
        // DirEntry metadata obeys the no-follow setting. Obtain it once per
        // entry and use that same observation for both total and class sizes.
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                result.fail("metadata-observation-failed");
                return result;
            }
        };
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            if metadata.is_dir() {
                entries.skip_current_dir();
            }
            result.links_skipped += 1;
            if entry.depth() == 0 {
                result.fail("unsafe-root");
                return result;
            }
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(&root.platform_root)
            .expect("walk is rooted");
        let class = if relative.starts_with("workspaces") {
            0
        } else if relative.starts_with("cache") {
            1
        } else if relative.starts_with("artifacts/blake3") {
            2
        } else {
            3
        };
        let Some(size) = sizes[class].checked_add(metadata.len()) else {
            result.fail("size-overflow");
            return result;
        };
        sizes[class] = size;
        result.files_observed += 1;
    }
    if result.check_cancelled(cancelled) {
        return result;
    }
    let Some(total) = checked_total(&sizes) else {
        result.fail("size-overflow");
        return result;
    };
    result.bytes = Some(total);
    result.repos_bytes = Some(sizes[0]);
    result.shared_bytes = Some(sizes[1]);
    result.artifacts_bytes = Some(sizes[2]);
    result.other_bytes = Some(sizes[3]);
    result.complete = true;
    result
}

fn checked_total(sizes: &[u64; 4]) -> Option<u64> {
    sizes
        .iter()
        .try_fold(0_u64, |total, size| total.checked_add(*size))
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn fixture() -> (tempfile::TempDir, RootHandle) {
        let temp = tempfile::tempdir().unwrap();
        let root = RootHandle::initialize(&temp.path().join("cache-root")).unwrap();
        (temp, root)
    }

    #[test]
    fn single_pass_counts_each_file_once_and_keeps_existing_classes() {
        let (_temp, root) = fixture();
        for (relative, size) in [
            ("workspaces/test/payload", 2),
            ("cache/test/payload", 3),
            ("artifacts/blake3/test", 5),
            ("artifacts/metadata/test", 7),
            ("trash/test", 11),
        ] {
            let path = root.platform_root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, vec![0; size]).unwrap();
        }
        let mut visited = BTreeSet::new();
        let observation = scan(&root, &AtomicBool::new(false), |path, _| {
            assert!(visited.insert(path.to_owned()), "entry traversed twice");
        });
        assert!(observation.complete);
        assert_eq!(observation.entries_observed as usize, visited.len());
        assert_eq!(observation.repos_bytes, Some(2));
        assert_eq!(observation.shared_bytes, Some(3));
        assert_eq!(observation.artifacts_bytes, Some(5));
        // The stable coordination file is empty; metadata and trash are other.
        assert_eq!(observation.other_bytes, Some(18));
        assert_eq!(observation.bytes, Some(28));
    }

    #[test]
    fn cancellation_before_or_during_scan_never_returns_complete_sizes() {
        let (_temp, root) = fixture();
        let cancelled = AtomicBool::new(true);
        let observation = scan(&root, &cancelled, |_, _| {
            panic!("pre-cancelled scan visited a path")
        });
        assert!(observation.cancelled);
        assert!(!observation.complete);
        assert_eq!(observation.bytes, None);
        cancelled.store(false, Ordering::Release);
        let observation = scan(&root, &cancelled, |_, entries| {
            if entries == 2 {
                cancelled.store(true, Ordering::Release);
            }
        });
        assert!(observation.cancelled);
        assert_eq!(observation.entries_observed, 2);
        assert_eq!(observation.shared_bytes, None);
    }

    #[test]
    fn missing_root_returns_unknown_sizes() {
        let (_temp, mut root) = fixture();
        root.platform_root.push("missing");
        let observation = observe(&root, &AtomicBool::new(false), |_| {});
        assert!(!observation.complete);
        assert_eq!(observation.bytes, None);
        assert!(observation.error_kind.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn links_are_not_traversed_and_redirected_ancestors_are_rejected() {
        let (temp, root) = fixture();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("unrelated"), vec![0; 4096]).unwrap();
        std::os::unix::fs::symlink(&outside, root.shared().join("linked")).unwrap();
        let observation = observe(&root, &AtomicBool::new(false), |_| {});
        assert!(observation.complete);
        assert_eq!(observation.bytes, Some(0));
        assert_eq!(observation.links_skipped, 1);
        let original = root.platform_root.with_extension("original");
        fs::rename(&root.platform_root, &original).unwrap();
        std::os::unix::fs::symlink(&original, &root.platform_root).unwrap();
        let observation = observe(&root, &AtomicBool::new(false), |_| {});
        assert!(!observation.complete);
        assert_eq!(observation.error_kind, Some("unsafe-root"));
        assert_eq!(observation.bytes, None);
    }

    #[cfg(unix)]
    #[test]
    fn a_disappearing_entry_fails_without_publishing_partial_sizes() {
        let (_temp, root) = fixture();
        let disappearing = root.shared().join("disappearing");
        fs::write(&disappearing, b"payload").unwrap();
        let observation = scan(&root, &AtomicBool::new(false), |path, _| {
            if path == disappearing {
                fs::remove_file(path).unwrap();
            }
        });
        assert!(!observation.complete);
        assert_eq!(observation.bytes, None);
        assert_eq!(observation.shared_bytes, None);
        assert_eq!(observation.error_kind, Some("metadata-observation-failed"));
    }

    #[test]
    fn changing_already_observed_files_does_not_diverge_total_and_classes() {
        let (_temp, root) = fixture();
        fs::write(root.shared().join("first"), b"123").unwrap();
        fs::write(root.shared().join("second"), b"12345").unwrap();
        let mut previous = None;
        let observation = scan(&root, &AtomicBool::new(false), |path, _| {
            if path.parent() == Some(root.shared().as_path()) {
                if let Some(previous) = previous.take() {
                    fs::write(previous, vec![0; 100]).unwrap();
                }
                previous = Some(path.to_owned());
            }
        });
        assert!(observation.complete);
        assert_eq!(observation.shared_bytes, Some(8));
        assert_eq!(observation.bytes, Some(8));
    }

    #[test]
    fn excessive_tree_depth_fails_without_publishing_partial_sizes() {
        let (_temp, root) = fixture();
        let mut path = root.shared();
        for _ in 0..257 {
            path.push("d");
            fs::create_dir(&path).unwrap();
        }
        let observation = observe(&root, &AtomicBool::new(false), |_| {});
        assert!(!observation.complete);
        assert!(!observation.cancelled);
        assert_eq!(observation.error_kind, Some("depth-limit"));
        assert_eq!(observation.bytes, None);
        assert_eq!(observation.shared_bytes, None);
    }

    #[test]
    fn checked_byte_total_rejects_overflow_at_the_exact_boundary() {
        assert_eq!(checked_total(&[u64::MAX - 3, 1, 1, 1]), Some(u64::MAX));
        assert_eq!(checked_total(&[u64::MAX - 3, 1, 1, 2]), None);
        assert_eq!(checked_total(&[0, 0, 0, 0]), Some(0));
    }

    #[test]
    fn a_failed_progress_writer_does_not_change_the_scan_result() {
        struct FailedWriter {
            attempts: usize,
        }
        impl Write for FailedWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                self.attempts += 1;
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (_temp, root) = fixture();
        let mut writer = FailedWriter { attempts: 0 };
        let observation = observe(&root, &AtomicBool::new(false), |entries| {
            write_progress(&mut writer, entries);
        });
        assert!(writer.attempts > 0);
        assert!(observation.complete);
        assert_eq!(observation.bytes, Some(0));
        assert_eq!(observation.error_kind, None);
    }

    #[test]
    fn progress_is_rate_limited_without_sleeping() {
        let mut progress = Progress::default();
        assert!(progress.due(Duration::ZERO));
        assert!(!progress.due(Duration::from_millis(999)));
        assert!(progress.due(Duration::from_secs(1)));
        assert!(!progress.due(Duration::from_millis(1001)));
        assert!(progress.due(Duration::from_secs(3)));
    }
}
