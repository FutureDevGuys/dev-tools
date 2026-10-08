//! Read-only, single-pass apparent-size observation. This is not GC authority.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
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

pub(crate) fn write_gc_progress(writer: &mut impl Write, entries: u64) {
    let _ = writeln!(
        writer,
        "dev-cache gc: planning and observing cache sizes ({entries} size-scan entries)"
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

/// Complete apparent-size observations only; none of these paths grants
/// mutation authority. Index memory is proportional to selected paths.
#[derive(Debug)]
pub(crate) struct PathMeasurements {
    pub total: u64,
    pub paths: BTreeMap<PathBuf, u64>,
}

#[cfg(test)]
fn measure_paths(root: &RootHandle, paths: &[PathBuf]) -> Result<PathMeasurements, &'static str> {
    measure_paths_with_progress(root, paths, |_| {})
}

pub(crate) fn measure_paths_with_progress(
    root: &RootHandle,
    paths: &[PathBuf],
    mut progress: impl FnMut(u64),
) -> Result<PathMeasurements, &'static str> {
    progress(0);
    measure_paths_observed(root, paths, |_, entries| progress(entries))
}

fn measure_paths_observed(
    root: &RootHandle,
    paths: &[PathBuf],
    mut visited: impl FnMut(&Path, u64),
) -> Result<PathMeasurements, &'static str> {
    let mut measured = BTreeMap::new();
    for path in paths {
        let relative = path
            .strip_prefix(&root.platform_root)
            .map_err(|_| "unsafe-candidate")?;
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err("unsafe-candidate");
        }
        measured.insert(path.clone(), 0_u64);
    }
    let mut unobserved = measured.keys().cloned().collect::<BTreeSet<_>>();
    let observation = scan_with_files(
        root,
        &AtomicBool::new(false),
        |path, entries| {
            unobserved.remove(path);
            visited(path, entries);
        },
        |path, bytes| add_file_sizes(&mut measured, path, bytes),
    );
    if !observation.complete {
        return Err(observation.error_kind.unwrap_or("incomplete-observation"));
    }
    validate_unobserved_candidates(&unobserved)?;
    Ok(PathMeasurements {
        total: observation.bytes.ok_or("incomplete-observation")?,
        paths: measured,
    })
}

fn validate_unobserved_candidates(paths: &BTreeSet<PathBuf>) -> Result<(), &'static str> {
    for path in paths {
        // A lexical index is not a filesystem identity oracle: an alternate
        // spelling can resolve to an existing object on casefold filesystems.
        // Only actual absence may produce zero without a visited candidate root.
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("candidate-metadata-failed"),
            Ok(_) => return Err("unmatched-candidate"),
        }
    }
    Ok(())
}

fn add_file_sizes(
    measured: &mut BTreeMap<PathBuf, u64>,
    path: &Path,
    bytes: u64,
) -> Result<(), &'static str> {
    // Component-wise ancestor lookup handles overlapping roots and exact-file
    // candidates without comparing each file against the entire candidate set.
    for ancestor in path.ancestors() {
        if let Some(total) = measured.get_mut(ancestor) {
            *total = total.checked_add(bytes).ok_or("candidate-size-overflow")?;
        }
    }
    Ok(())
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

fn scan(root: &RootHandle, cancelled: &AtomicBool, visited: impl FnMut(&Path, u64)) -> Observation {
    scan_with_files(root, cancelled, visited, |_, _| Ok(()))
}

fn scan_with_files(
    root: &RootHandle,
    cancelled: &AtomicBool,
    mut visited: impl FnMut(&Path, u64),
    mut observed_file: impl FnMut(&Path, u64) -> Result<(), &'static str>,
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
        if let Err(kind) = observed_file(entry.path(), metadata.len()) {
            result.fail(kind);
            return result;
        }
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
            write_gc_progress(&mut writer, entries);
        });
        assert!(writer.attempts > 0);
        assert!(observation.complete);
        assert_eq!(observation.bytes, Some(0));
        assert_eq!(observation.error_kind, None);
    }

    #[test]
    fn indexed_candidates_match_subtree_sizes_with_one_entry_visit() {
        let (_temp, root) = fixture();
        for (relative, size) in [
            ("cache/a/direct", 3),
            ("cache/a/nested/file", 5),
            ("cache/ab/sibling", 7),
            ("workspaces/other", 11),
        ] {
            let path = root.platform_root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, vec![0; size]).unwrap();
        }
        let paths = vec![
            root.shared().join("a"),
            root.shared().join("a/nested"),
            root.shared().join("a/nested/file"),
            root.shared().join("ab"),
            root.shared().join("absent"),
            root.shared().join("a"),
        ];
        let mut visits = BTreeSet::new();
        let measurement = measure_paths_observed(&root, &paths, |path, _| {
            assert!(visits.insert(path.to_owned()), "entry measured twice");
        })
        .unwrap();
        assert_eq!(
            measurement.total,
            crate::util::directory_size(&root.platform_root)
        );
        assert_eq!(measurement.total, 26);
        assert_eq!(
            measurement.paths.len(),
            5,
            "duplicate candidate is indexed once"
        );
        for path in paths {
            assert_eq!(measurement.paths[&path], crate::util::directory_size(&path));
        }
        assert_eq!(measurement.paths[&root.shared().join("a")], 8);
        assert_eq!(measurement.paths[&root.shared().join("a/nested")], 5);
        assert_eq!(measurement.paths[&root.shared().join("ab")], 7);
    }

    #[test]
    fn unobserved_existing_candidate_can_never_be_reported_as_zero() {
        let (_temp, root) = fixture();
        let empty = root.shared().join("empty");
        fs::create_dir(&empty).unwrap();
        let file = root.shared().join("file");
        fs::write(&file, b"payload").unwrap();
        // Force the invariant's unmatched condition without depending on the
        // host filesystem's casefold configuration. Native alternate-spelling
        // acceptance is separate; existing aliases must take this rejection.
        for path in [&empty, &file] {
            assert_eq!(
                validate_unobserved_candidates(&BTreeSet::from([path.clone()])),
                Err("unmatched-candidate")
            );
        }
        let absent = root.shared().join("absent");
        assert_eq!(
            validate_unobserved_candidates(&BTreeSet::from([absent.clone()])),
            Ok(())
        );
        let measurement = measure_paths(&root, &[empty.clone(), absent.clone()]).unwrap();
        assert_eq!(
            measurement.paths[&empty], 0,
            "observed empty directory remains valid"
        );
        assert_eq!(
            measurement.paths[&absent], 0,
            "proven absent candidate remains valid"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unobserved_candidate_metadata_errors_are_not_absence() {
        let (_temp, root) = fixture();
        let file = root.shared().join("ordinary-file");
        fs::write(&file, b"payload").unwrap();
        assert_eq!(
            validate_unobserved_candidates(&BTreeSet::from([file.join("child")])),
            Err("candidate-metadata-failed")
        );
    }

    #[test]
    fn candidate_index_rejects_overflow_without_large_files() {
        let path = PathBuf::from("cache/a/file");
        let mut sizes =
            BTreeMap::from([(PathBuf::from("cache/a"), u64::MAX - 1), (path.clone(), 0)]);
        assert_eq!(add_file_sizes(&mut sizes, &path, 1), Ok(()));
        assert_eq!(sizes[Path::new("cache/a")], u64::MAX);
        assert_eq!(
            add_file_sizes(&mut sizes, &path, 1),
            Err("candidate-size-overflow")
        );
    }

    #[test]
    fn invalid_candidate_is_rejected_before_traversal() {
        let (_temp, root) = fixture();
        for path in [
            root.root.join("outside-domain"),
            root.platform_root.join("../outside"),
        ] {
            let result = measure_paths_observed(&root, &[path], |_, _| {
                panic!("invalid candidate reached traversal");
            });
            assert!(matches!(result, Err("unsafe-candidate")));
        }
    }

    #[cfg(unix)]
    #[test]
    fn candidate_measurement_error_never_returns_partial_totals() {
        let (_temp, root) = fixture();
        let removed = root.shared().join("removed");
        fs::write(&removed, b"data").unwrap();
        let result = measure_paths_observed(&root, &[root.shared()], |path, _| {
            if path == removed {
                fs::remove_file(path).unwrap();
            }
        });
        assert!(matches!(result, Err("metadata-observation-failed")));
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
