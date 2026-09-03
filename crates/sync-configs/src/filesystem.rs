//! Ordinary, unprivileged filesystem expansion and convergence.
//!
//! This module deliberately operates on already validated manifest entries. Privileged
//! regular-file targets, structured overlays, and hooks have separate execution boundaries.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use globset::{GlobBuilder, GlobMatcher};
use thiserror::Error;
use walkdir::WalkDir;

use crate::manifest::{DirectoryStrategy, Entry, Mode, PermissionPolicy, Privilege};
use crate::paths::{
    candidate_source_override, lexical_normalize, normalize_user_path, PathContext, PathPlatform,
};

const DEFAULT_IGNORE_FILE_NAMES: [&str; 4] = [".gitignore", ".ignore", ".rgignore", ".fdignore"];
const DEFAULT_FILTERS: &str = r#"
.DS_Store
Thumbs.db
Desktop.ini
$RECYCLE.BIN/
.Spotlight-V100/
.Trashes/
._*
.idea/
.vscode/
*.swp
*.swo
*~
__pycache__/
*.py[cod]
*.pyo
.pytest_cache/
.mypy_cache/
.ruff_cache/
.hypothesis/
.tox/
.nox/
.pyre/
.pytype/
.coverage
.coverage.*
htmlcov/
pip-wheel-metadata/
node_modules/
.npm/
.pnpm-store/
.yarn/
.turbo/
.eslintcache
.stylelintcache
.svelte-kit/
.parcel-cache/
.next/
.nuxt/
vite.svg
*.tsbuildinfo
target/
.coverprofile
cover.out
.gradle/
*.class
*.jar
*.war
*.nar
hs_err_pid*
replay_pid*
cmake-build-*/
CMakeFiles/
CMakeCache.txt
compile_commands.json
makedep*
libtool
aclocal.m4
m4/
autom4te.cache/
*.o
*.obj
*.a
*.lib
*.so
*.dylib
*.dll
*.exe
obj/
*.rsuser
.bundle/
_build/
erl_crash.dump
.terraform/
.terragrunt-cache/
.serverless/
.aws-sam/
dist/
build/
out/
coverage/
.cache/
tmp/
tmp-*/
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedPathPolicy {
    Safe,
    Strict,
    Takeover,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExistingState {
    Absent,
    ManagedLink,
    RelocatedManagedLink,
    IdenticalSource,
    SkeletonDefault,
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryAction {
    None,
    Create,
    Adopt,
    Replace,
    UpdatePermissions,
    Block,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryStatus {
    UpToDate,
    Changed,
    WouldChange,
    MissingSource,
    SkippedExisting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryOutcome {
    pub name: String,
    pub source: PathBuf,
    pub target: PathBuf,
    pub status: EntryStatus,
    pub action: EntryAction,
    pub existing_state: ExistingState,
    pub backup: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct ExpansionOptions {
    pub prefer_source_overrides: bool,
    pub environment: BTreeMap<OsString, OsString>,
    pub home: Option<PathBuf>,
}

impl Default for ExpansionOptions {
    fn default() -> Self {
        let environment: BTreeMap<OsString, OsString> = env::vars_os().collect();
        let home = if cfg!(windows) {
            environment
                .get(OsStr::new("USERPROFILE"))
                .map(PathBuf::from)
                .or_else(|| {
                    let drive = environment.get(OsStr::new("HOMEDRIVE"))?;
                    let path = environment.get(OsStr::new("HOMEPATH"))?;
                    let mut joined = drive.clone();
                    joined.push(path);
                    Some(PathBuf::from(joined))
                })
        } else {
            environment.get(OsStr::new("HOME")).map(PathBuf::from)
        };
        Self {
            prefer_source_overrides: true,
            environment,
            home,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConvergeOptions<'a> {
    pub dry_run: bool,
    pub managed_path_policy: ManagedPathPolicy,
    pub backup_root: &'a Path,
    pub previous_sources: &'a [PathBuf],
    pub skeleton: Option<&'a Path>,
    pub max_backup_candidates: usize,
}

#[derive(Debug, Error)]
pub enum FilesystemError {
    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("entry '{entry}' uses unsupported ordinary filesystem mode {mode}")]
    UnsupportedMode { entry: String, mode: Mode },
    #[error("entry '{entry}' is privileged and must use the privileged target executor")]
    PrivilegedEntry { entry: String },
    #[error("entry '{entry}' uses filters with directory_strategy: as_directory")]
    FiltersOnWholeDirectory { entry: String },
    #[error("entry '{entry}' uses filters but its source cannot be expanded: {path}")]
    FiltersOnLiteralSource { entry: String, path: PathBuf },
    #[error("invalid glob or ignore pattern {pattern:?}: {message}")]
    InvalidPattern { pattern: String, message: String },
    #[error("source pattern is not representable as UTF-8: {0}")]
    NonUtf8Pattern(PathBuf),
    #[error("source link or reparse point is not allowed: {0}")]
    SourceLink(PathBuf),
    #[error("source is neither a regular file nor a directory: {0}")]
    UnsupportedSource(PathBuf),
    #[error("target ancestor is a link or reparse point: {0}")]
    TargetAncestorLink(PathBuf),
    #[error("target ancestor is not a directory: {0}")]
    TargetAncestorNotDirectory(PathBuf),
    #[error("target is a special filesystem object and will not be replaced: {0}")]
    UnsupportedTarget(PathBuf),
    #[error("backup root must be an absolute path: {0}")]
    RelativeBackupRoot(PathBuf),
    #[error("no free bounded backup name remains for {target} under {root}")]
    BackupNamesExhausted { target: PathBuf, root: PathBuf },
    #[error("backup root is not an owner-only directory controlled by this user: {0}")]
    UnsafeBackupRoot(PathBuf),
    #[error("cannot activate {target}; rollback also failed ({rollback}) after: {primary}")]
    RollbackFailed {
        target: PathBuf,
        primary: String,
        rollback: String,
    },
    #[error("filesystem convergence did not produce the exact requested postcondition: {0}")]
    Postcondition(PathBuf),
    #[error("cannot resolve an explicit ignore path: {0}")]
    IgnorePath(String),
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> FilesystemError {
    FilesystemError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(unix)]
fn has_glob(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str()
        .as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'*' | b'?' | b'['))
}

#[cfg(not(unix))]
fn has_glob(path: &Path) -> bool {
    path.as_os_str()
        .to_string_lossy()
        .bytes()
        .any(|byte| matches!(byte, b'*' | b'?' | b'['))
}

fn is_link_or_reparse(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        return metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }
    #[cfg(not(windows))]
    false
}

fn symlink_metadata(
    path: &Path,
    operation: &'static str,
) -> Result<Option<Metadata>, FilesystemError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(operation, path, error)),
    }
}

fn expansion_context(options: &ExpansionOptions) -> Result<PathContext, FilesystemError> {
    let cwd = env::current_dir()
        .map_err(|error| io_error("read current directory", Path::new("."), error))?;
    Ok(PathContext::new(
        PathPlatform::current(),
        cwd,
        options.home.clone(),
        env::temp_dir(),
        options.environment.clone(),
    ))
}

#[derive(Debug)]
struct FilterRule {
    matcher: GlobMatcher,
    negated: bool,
    directory_only: bool,
    anchored: bool,
    basename_only: bool,
}

fn parse_rule(raw: &str) -> Result<Option<FilterRule>, FilesystemError> {
    let mut line = raw.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let negated = line.starts_with('!');
    if negated {
        line = line[1..].trim();
    }
    if line.is_empty() {
        return Ok(None);
    }
    let directory_only = line.ends_with('/');
    if directory_only {
        line = line.trim_end_matches('/');
    }
    let anchored = line.starts_with('/');
    if anchored {
        line = line.trim_start_matches('/');
    }
    if line.is_empty() {
        return Ok(None);
    }
    let basename_only = !line.contains('/');
    let matcher = GlobBuilder::new(line)
        .literal_separator(true)
        .backslash_escape(true)
        .build()
        .map_err(|error| FilesystemError::InvalidPattern {
            pattern: raw.to_owned(),
            message: error.to_string(),
        })?
        .compile_matcher();
    Ok(Some(FilterRule {
        matcher,
        negated,
        directory_only,
        anchored,
        basename_only,
    }))
}

fn parse_rules(contents: &str) -> Result<Vec<FilterRule>, FilesystemError> {
    contents
        .lines()
        .map(parse_rule)
        .filter_map(Result::transpose)
        .collect()
}

fn suffixes(path: &Path) -> Vec<PathBuf> {
    let components: Vec<OsString> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_os_string()),
            _ => None,
        })
        .collect();
    (0..components.len())
        .map(|start| components[start..].iter().collect())
        .collect()
}

fn rule_matches(rule: &FilterRule, relative: &Path, is_directory: bool) -> bool {
    let mut candidates = vec![(relative.to_path_buf(), is_directory)];
    if !is_directory {
        let mut parent = relative.parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            candidates.push((path.to_path_buf(), true));
            parent = path.parent();
        }
    }
    for (candidate, candidate_is_directory) in candidates {
        if rule.directory_only && !candidate_is_directory {
            continue;
        }
        if rule.basename_only {
            if candidate
                .components()
                .filter_map(|component| match component {
                    Component::Normal(part) => Some(part),
                    _ => None,
                })
                .any(|part| rule.matcher.is_match(Path::new(part)))
            {
                return true;
            }
        } else if rule.anchored {
            if rule.matcher.is_match(&candidate) {
                return true;
            }
        } else if suffixes(&candidate)
            .iter()
            .any(|suffix| rule.matcher.is_match(suffix))
        {
            return true;
        }
    }
    false
}

struct Filters {
    ignored: Vec<FilterRule>,
    included: Vec<FilterRule>,
    ignore_files: BTreeSet<PathBuf>,
}

fn resolve_ignore_path(
    raw: &str,
    root: &Path,
    context: &PathContext,
) -> Result<PathBuf, FilesystemError> {
    let normalized = normalize_user_path(raw, context)
        .map_err(|error| FilesystemError::IgnorePath(error.to_string()))?;
    let absolute = if normalized.is_absolute() {
        normalized
    } else {
        root.join(normalized)
    };
    Ok(lexical_normalize(&absolute, PathPlatform::current()))
}

fn load_filters(
    entry: &Entry,
    root: &Path,
    options: &ExpansionOptions,
) -> Result<Filters, FilesystemError> {
    let context = expansion_context(options)?;
    let mut ignored = if entry.use_default_filters {
        parse_rules(DEFAULT_FILTERS)?
    } else {
        Vec::new()
    };
    let mut ignore_files = BTreeSet::new();
    if entry.discover_ignore_files {
        for name in DEFAULT_IGNORE_FILE_NAMES {
            let candidate = root.join(name);
            if symlink_metadata(&candidate, "inspect ignore file")?.is_some() {
                ignore_files.insert(candidate);
            }
        }
    }
    for raw in &entry.ignore_files {
        let candidate = resolve_ignore_path(raw, root, &context)?;
        if symlink_metadata(&candidate, "inspect ignore file")?.is_some() {
            ignore_files.insert(candidate);
        }
    }
    for path in &ignore_files {
        let metadata = symlink_metadata(path, "inspect ignore file")?.ok_or_else(|| {
            io_error(
                "inspect ignore file",
                path,
                io::Error::from(io::ErrorKind::NotFound),
            )
        })?;
        if is_link_or_reparse(&metadata) {
            return Err(FilesystemError::SourceLink(path.clone()));
        }
        if !metadata.is_file() {
            return Err(FilesystemError::UnsupportedSource(path.clone()));
        }
        let contents =
            fs::read_to_string(path).map_err(|error| io_error("read ignore file", path, error))?;
        ignored.extend(parse_rules(&contents)?);
    }
    for raw in &entry.exclude {
        if let Some(rule) = parse_rule(raw)? {
            ignored.push(rule);
        }
    }
    let included = entry
        .include
        .iter()
        .map(|raw| parse_rule(raw))
        .filter_map(Result::transpose)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Filters {
        ignored,
        included,
        ignore_files,
    })
}

impl Filters {
    fn keeps(&self, root: &Path, candidate: &Path, is_directory: bool) -> bool {
        let candidate = lexical_normalize(candidate, PathPlatform::current());
        if self.ignore_files.contains(&candidate) {
            return false;
        }
        let Ok(relative) = candidate.strip_prefix(root) else {
            return false;
        };
        let mut excluded = false;
        for rule in &self.ignored {
            if rule_matches(rule, relative, is_directory) {
                excluded = !rule.negated;
            }
        }
        if !self.included.is_empty()
            && !self
                .included
                .iter()
                .any(|rule| rule_matches(rule, relative, is_directory))
        {
            return false;
        }
        if !self.included.is_empty() {
            excluded = false;
        }
        !excluded
    }
}

fn entry_uses_filters(entry: &Entry) -> bool {
    !entry.include.is_empty()
        || !entry.exclude.is_empty()
        || !entry.ignore_files.is_empty()
        || !entry.discover_ignore_files
        || !entry.use_default_filters
}

fn expanded_entry(entry: &Entry, source: PathBuf, target: PathBuf, relative: &Path) -> Entry {
    let mut expanded = entry.clone();
    expanded.name = if !entry.name.is_empty() && entry.name != entry.target.to_string_lossy() {
        if relative.as_os_str().is_empty() {
            entry.name.clone()
        } else {
            format!("{}/{}", entry.name, relative.to_string_lossy())
        }
    } else {
        target.to_string_lossy().into_owned()
    };
    expanded.source = source;
    expanded.target = target;
    expanded.directory_strategy = DirectoryStrategy::AsDirectory;
    expanded.include.clear();
    expanded.exclude.clear();
    expanded.ignore_files.clear();
    expanded.discover_ignore_files = true;
    expanded.use_default_filters = true;
    expanded
}

fn walk_entries(root: &Path) -> Result<Vec<walkdir::DirEntry>, FilesystemError> {
    let mut entries = Vec::new();
    for result in WalkDir::new(root)
        .follow_links(false)
        .min_depth(1)
        .sort_by_file_name()
    {
        let item = result.map_err(|error| {
            let path = error.path().unwrap_or(root);
            let source = error
                .io_error()
                .map(|source| io::Error::new(source.kind(), source.to_string()))
                .unwrap_or_else(|| io::Error::other(error.to_string()));
            io_error("walk source directory", path, source)
        })?;
        if is_link_or_reparse(&item.metadata().map_err(|error| {
            io_error(
                "inspect source directory entry",
                item.path(),
                io::Error::other(error.to_string()),
            )
        })?) {
            return Err(FilesystemError::SourceLink(item.path().to_path_buf()));
        }
        entries.push(item);
    }
    Ok(entries)
}

fn expand_directory(
    entry: &Entry,
    options: &ExpansionOptions,
) -> Result<Vec<Entry>, FilesystemError> {
    match entry.directory_strategy {
        DirectoryStrategy::AsDirectory => {
            if entry_uses_filters(entry) {
                return Err(FilesystemError::FiltersOnWholeDirectory {
                    entry: entry.name.clone(),
                });
            }
            validate_source_tree(&entry.source)?;
            Ok(vec![entry.clone()])
        }
        DirectoryStrategy::Children => {
            let filters = load_filters(entry, &entry.source, options)?;
            let mut children = fs::read_dir(&entry.source)
                .map_err(|error| io_error("read source directory", &entry.source, error))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| io_error("read source directory", &entry.source, error))?;
            children.sort_by_key(|child| child.file_name());
            let mut expanded = Vec::new();
            for child in children {
                let path = child.path();
                let link_metadata = fs::symlink_metadata(&path)
                    .map_err(|error| io_error("inspect source child", &path, error))?;
                if is_link_or_reparse(&link_metadata) {
                    return Err(FilesystemError::SourceLink(path));
                }
                let metadata = link_metadata;
                if !metadata.is_file() && !metadata.is_dir() {
                    return Err(FilesystemError::UnsupportedSource(path));
                }
                if !filters.keeps(&entry.source, &path, metadata.is_dir()) {
                    continue;
                }
                if metadata.is_dir() {
                    validate_source_tree(&path)?;
                }
                let relative = PathBuf::from(child.file_name());
                expanded.push(expanded_entry(
                    entry,
                    path,
                    entry.target.join(&relative),
                    &relative,
                ));
            }
            Ok(expanded)
        }
        DirectoryStrategy::Recursive => {
            let filters = load_filters(entry, &entry.source, options)?;
            let mut expanded = Vec::new();
            for child in walk_entries(&entry.source)? {
                if !child.file_type().is_file() {
                    continue;
                }
                let path = child.path();
                if !filters.keeps(&entry.source, path, false) {
                    continue;
                }
                let relative = path.strip_prefix(&entry.source).map_err(|_| {
                    FilesystemError::FiltersOnLiteralSource {
                        entry: entry.name.clone(),
                        path: path.to_path_buf(),
                    }
                })?;
                expanded.push(expanded_entry(
                    entry,
                    path.to_path_buf(),
                    entry.target.join(relative),
                    relative,
                ));
            }
            Ok(expanded)
        }
    }
}

fn glob_literal_root(pattern: &Path) -> PathBuf {
    let mut root = PathBuf::new();
    for component in pattern.components() {
        if has_glob(Path::new(component.as_os_str())) {
            break;
        }
        root.push(component.as_os_str());
    }
    if root.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        root
    }
}

fn expand_glob(entry: &Entry, options: &ExpansionOptions) -> Result<Vec<Entry>, FilesystemError> {
    let pattern = entry
        .source
        .to_str()
        .ok_or_else(|| FilesystemError::NonUtf8Pattern(entry.source.clone()))?;
    let matcher = GlobBuilder::new(pattern)
        .literal_separator(true)
        .backslash_escape(true)
        .build()
        .map_err(|error| FilesystemError::InvalidPattern {
            pattern: pattern.to_owned(),
            message: error.to_string(),
        })?
        .compile_matcher();
    let root = glob_literal_root(&entry.source);
    let Some(metadata) = symlink_metadata(&root, "inspect glob root")? else {
        return Ok(Vec::new());
    };
    if is_link_or_reparse(&metadata) {
        return Err(FilesystemError::SourceLink(root));
    }
    if !metadata.is_dir() {
        return Ok(Vec::new());
    }
    let filters = load_filters(entry, &root, options)?;
    let mut expanded = Vec::new();
    for child in WalkDir::new(&root).follow_links(false).sort_by_file_name() {
        let child = child.map_err(|error| {
            let path = error.path().unwrap_or(&root);
            io_error("walk glob root", path, io::Error::other(error.to_string()))
        })?;
        let path = child.path();
        let metadata = child.metadata().map_err(|error| {
            io_error(
                "inspect glob candidate",
                path,
                io::Error::other(error.to_string()),
            )
        })?;
        if is_link_or_reparse(&metadata) {
            return Err(FilesystemError::SourceLink(path.to_path_buf()));
        }
        if !matcher.is_match(path) || !filters.keeps(&root, path, metadata.is_dir()) {
            continue;
        }
        if !metadata.is_file() && !metadata.is_dir() {
            return Err(FilesystemError::UnsupportedSource(path.to_path_buf()));
        }
        if metadata.is_dir() {
            validate_source_tree(path)?;
        }
        let relative =
            path.strip_prefix(&root)
                .map_err(|_| FilesystemError::FiltersOnLiteralSource {
                    entry: entry.name.clone(),
                    path: path.to_path_buf(),
                })?;
        expanded.push(expanded_entry(
            entry,
            path.to_path_buf(),
            entry.target.join(relative),
            relative,
        ));
    }
    Ok(expanded)
}

fn apply_source_overrides(entries: &mut [Entry]) {
    let selected: BTreeSet<PathBuf> = entries.iter().map(|entry| entry.source.clone()).collect();
    for entry in entries {
        let candidate = candidate_source_override(&entry.source);
        if candidate != entry.source && candidate.exists() && !selected.contains(&candidate) {
            entry.source = candidate;
        }
    }
}

pub fn expand_entries(
    entries: &[Entry],
    options: &ExpansionOptions,
) -> Result<Vec<Entry>, FilesystemError> {
    let mut expanded = Vec::new();
    for entry in entries {
        if has_glob(&entry.source) {
            expanded.extend(expand_glob(entry, options)?);
            continue;
        }
        match symlink_metadata(&entry.source, "inspect source")? {
            Some(metadata) if is_link_or_reparse(&metadata) => {
                return Err(FilesystemError::SourceLink(entry.source.clone()));
            }
            Some(metadata) if metadata.is_dir() => {
                expanded.extend(expand_directory(entry, options)?);
            }
            Some(metadata) if metadata.is_file() => {
                if entry_uses_filters(entry) {
                    return Err(FilesystemError::FiltersOnLiteralSource {
                        entry: entry.name.clone(),
                        path: entry.source.clone(),
                    });
                }
                expanded.push(entry.clone());
            }
            Some(_) => return Err(FilesystemError::UnsupportedSource(entry.source.clone())),
            None => {
                if entry_uses_filters(entry) {
                    return Err(FilesystemError::FiltersOnLiteralSource {
                        entry: entry.name.clone(),
                        path: entry.source.clone(),
                    });
                }
                expanded.push(entry.clone());
            }
        }
    }
    if options.prefer_source_overrides {
        apply_source_overrides(&mut expanded);
    }
    Ok(expanded)
}

fn absolute_lexical(path: &Path) -> Result<PathBuf, FilesystemError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| io_error("read current directory", Path::new("."), error))?
            .join(path)
    };
    Ok(lexical_normalize(&absolute, PathPlatform::current()))
}

fn lexical_link_target(target: &Path) -> Result<PathBuf, FilesystemError> {
    let raw = fs::read_link(target).map_err(|error| io_error("read target link", target, error))?;
    let joined = if raw.is_absolute() {
        raw
    } else {
        target.parent().unwrap_or_else(|| Path::new(".")).join(raw)
    };
    absolute_lexical(&joined)
}

fn validate_source_tree(root: &Path) -> Result<(), FilesystemError> {
    let metadata =
        fs::symlink_metadata(root).map_err(|error| io_error("inspect source", root, error))?;
    if is_link_or_reparse(&metadata) {
        return Err(FilesystemError::SourceLink(root.to_path_buf()));
    }
    if metadata.is_file() {
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(FilesystemError::UnsupportedSource(root.to_path_buf()));
    }
    walk_entries(root).map(|_| ())
}

fn validate_existing_target_ancestors(target: &Path) -> Result<(), FilesystemError> {
    let target = absolute_lexical(target)?;
    let Some(parent) = target.parent() else {
        return Ok(());
    };
    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component.as_os_str());
        let Some(metadata) = symlink_metadata(&current, "inspect target ancestor")? else {
            continue;
        };
        if is_link_or_reparse(&metadata) {
            return Err(FilesystemError::TargetAncestorLink(current));
        }
        if !metadata.is_dir() {
            return Err(FilesystemError::TargetAncestorNotDirectory(current));
        }
    }
    Ok(())
}

fn target_resolves_exactly_to_source(
    source: &Path,
    target: &Path,
) -> Result<bool, FilesystemError> {
    let Some(_) = symlink_metadata(target, "inspect resolved target alias")? else {
        return Ok(false);
    };
    let canonical_source = fs::canonicalize(source)
        .map_err(|error| io_error("resolve source identity", source, error))?;
    let canonical_target = match fs::canonicalize(target) {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(io_error("resolve target identity", target, error)),
    };
    Ok(canonical_target == canonical_source)
}

fn create_parent_directories(target: &Path) -> Result<(), FilesystemError> {
    validate_existing_target_ancestors(target)?;
    let absolute = absolute_lexical(target)?;
    let parent = absolute.parent().unwrap_or_else(|| Path::new("."));
    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component.as_os_str());
        match symlink_metadata(&current, "inspect target ancestor")? {
            Some(metadata) if is_link_or_reparse(&metadata) => {
                return Err(FilesystemError::TargetAncestorLink(current));
            }
            Some(metadata) if !metadata.is_dir() => {
                return Err(FilesystemError::TargetAncestorNotDirectory(current));
            }
            Some(_) => {}
            None => match fs::create_dir(&current) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let metadata = fs::symlink_metadata(&current).map_err(|error| {
                        io_error("inspect raced target ancestor", &current, error)
                    })?;
                    if is_link_or_reparse(&metadata) {
                        return Err(FilesystemError::TargetAncestorLink(current));
                    }
                    if !metadata.is_dir() {
                        return Err(FilesystemError::TargetAncestorNotDirectory(current));
                    }
                }
                Err(error) => return Err(io_error("create target ancestor", &current, error)),
            },
        }
    }
    validate_existing_target_ancestors(target)
}

#[cfg(unix)]
fn open_regular_nofollow(path: &Path) -> Result<File, FilesystemError> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| io_error("open regular file without following links", path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect opened file", path, error))?;
    if !metadata.is_file() {
        return Err(FilesystemError::UnsupportedSource(path.to_path_buf()));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_regular_nofollow(path: &Path) -> Result<File, FilesystemError> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect regular file", path, error))?;
    if is_link_or_reparse(&before) || !before.is_file() {
        return Err(FilesystemError::SourceLink(path.to_path_buf()));
    }
    let file = File::open(path).map_err(|error| io_error("open regular file", path, error))?;
    let after = fs::symlink_metadata(path)
        .map_err(|error| io_error("reinspect regular file", path, error))?;
    if is_link_or_reparse(&after) || !after.is_file() {
        return Err(FilesystemError::SourceLink(path.to_path_buf()));
    }
    Ok(file)
}

fn files_equal(left: &Path, right: &Path) -> Result<bool, FilesystemError> {
    let left_metadata =
        fs::symlink_metadata(left).map_err(|error| io_error("inspect source file", left, error))?;
    let right_metadata = fs::symlink_metadata(right)
        .map_err(|error| io_error("inspect target file", right, error))?;
    if is_link_or_reparse(&left_metadata)
        || is_link_or_reparse(&right_metadata)
        || !left_metadata.is_file()
        || !right_metadata.is_file()
        || left_metadata.len() != right_metadata.len()
    {
        return Ok(false);
    }
    let mut left_file = open_regular_nofollow(left)?;
    let mut right_file = open_regular_nofollow(right)?;
    let mut left_buffer = [0_u8; 64 * 1024];
    let mut right_buffer = [0_u8; 64 * 1024];
    loop {
        let left_count = left_file
            .read(&mut left_buffer)
            .map_err(|error| io_error("read source file", left, error))?;
        let right_count = right_file
            .read(&mut right_buffer)
            .map_err(|error| io_error("read target file", right, error))?;
        if left_count != right_count || left_buffer[..left_count] != right_buffer[..right_count] {
            return Ok(false);
        }
        if left_count == 0 {
            return Ok(true);
        }
    }
}

fn sorted_directory(path: &Path) -> Result<Vec<(OsString, Metadata)>, FilesystemError> {
    let mut children = Vec::new();
    for child in fs::read_dir(path).map_err(|error| io_error("read directory", path, error))? {
        let child = child.map_err(|error| io_error("read directory entry", path, error))?;
        let child_path = child.path();
        let metadata = fs::symlink_metadata(&child_path)
            .map_err(|error| io_error("inspect directory entry", &child_path, error))?;
        children.push((child.file_name(), metadata));
    }
    children.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(children)
}

fn trees_equal(left: &Path, right: &Path) -> Result<bool, FilesystemError> {
    let left_metadata =
        fs::symlink_metadata(left).map_err(|error| io_error("inspect source", left, error))?;
    let right_metadata =
        fs::symlink_metadata(right).map_err(|error| io_error("inspect target", right, error))?;
    if is_link_or_reparse(&left_metadata) || is_link_or_reparse(&right_metadata) {
        return Ok(false);
    }
    if left_metadata.is_file() || right_metadata.is_file() {
        return if left_metadata.is_file() && right_metadata.is_file() {
            files_equal(left, right)
        } else {
            Ok(false)
        };
    }
    if !left_metadata.is_dir() || !right_metadata.is_dir() {
        return Ok(false);
    }
    let left_children = sorted_directory(left)?;
    let right_children = sorted_directory(right)?;
    if left_children.len() != right_children.len() {
        return Ok(false);
    }
    for ((left_name, left_meta), (right_name, right_meta)) in
        left_children.into_iter().zip(right_children)
    {
        if left_name != right_name {
            return Ok(false);
        }
        if is_link_or_reparse(&left_meta) || is_link_or_reparse(&right_meta) {
            return Ok(false);
        }
        let left_child = left.join(&left_name);
        let right_child = right.join(&right_name);
        if !trees_equal(&left_child, &right_child)? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(unix)]
fn mode_matches(metadata: &Metadata, expected: u32) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777 == expected
}

#[cfg(windows)]
fn mode_matches(metadata: &Metadata, expected: u32) -> bool {
    metadata.permissions().readonly() == (expected & 0o222 == 0)
}

#[cfg(not(any(unix, windows)))]
fn mode_matches(_metadata: &Metadata, _expected: u32) -> bool {
    true
}

fn permissions_match(
    path: &Path,
    policy: Option<&PermissionPolicy>,
) -> Result<bool, FilesystemError> {
    let Some(policy) = policy else {
        return Ok(true);
    };
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error("inspect permissions", path, error))?;
    if is_link_or_reparse(&metadata) {
        return Ok(false);
    }
    let expected = if metadata.is_dir() {
        policy.dir
    } else {
        policy.file
    };
    if expected.is_some_and(|mode| !mode_matches(&metadata, mode.get())) {
        return Ok(false);
    }
    if metadata.is_dir() && policy.recursive {
        for child in walk_entries(path)? {
            let metadata = child.metadata().map_err(|error| {
                io_error(
                    "inspect recursive permissions",
                    child.path(),
                    io::Error::other(error.to_string()),
                )
            })?;
            let expected = if metadata.is_dir() {
                policy.dir
            } else {
                policy.file
            };
            if expected.is_some_and(|mode| !mode_matches(&metadata, mode.get())) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), FilesystemError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| io_error("set permissions", path, error))
}

#[cfg(windows)]
fn set_mode(path: &Path, mode: u32) -> Result<(), FilesystemError> {
    let mut permissions = fs::metadata(path)
        .map_err(|error| io_error("inspect permissions", path, error))?
        .permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    fs::set_permissions(path, permissions).map_err(|error| io_error("set permissions", path, error))
}

#[cfg(not(any(unix, windows)))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), FilesystemError> {
    Ok(())
}

fn apply_permissions(
    path: &Path,
    policy: Option<&PermissionPolicy>,
) -> Result<(), FilesystemError> {
    let Some(policy) = policy else {
        return Ok(());
    };
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error("inspect permissions", path, error))?;
    if is_link_or_reparse(&metadata) {
        return Err(FilesystemError::SourceLink(path.to_path_buf()));
    }
    if metadata.is_dir() && policy.recursive {
        let children = walk_entries(path)?;
        for child in children.iter().filter(|child| child.file_type().is_file()) {
            if let Some(mode) = policy.file {
                set_mode(child.path(), mode.get())?;
            }
        }
        for child in children
            .iter()
            .rev()
            .filter(|child| child.file_type().is_dir())
        {
            if let Some(mode) = policy.dir {
                set_mode(child.path(), mode.get())?;
            }
        }
    }
    let mode = if metadata.is_dir() {
        policy.dir
    } else {
        policy.file
    };
    if let Some(mode) = mode {
        set_mode(path, mode.get())?;
    }
    Ok(())
}

/// Validate and, unless `dry_run` is set, apply one entry's source-side permission policy.
///
/// The return value is `true` exactly when the source did not already satisfy the policy. This
/// seam is shared by ordinary filesystem entries and structured-overlay execution; it never
/// follows a source symlink or reparse point.
pub fn apply_source_permissions(entry: &Entry, dry_run: bool) -> Result<bool, FilesystemError> {
    if entry.source_permissions.is_none() {
        return Ok(false);
    }
    validate_source_tree(&entry.source)?;
    let needs_change = !permissions_match(&entry.source, entry.source_permissions.as_ref())?;
    if needs_change && !dry_run {
        apply_permissions(&entry.source, entry.source_permissions.as_ref())?;
        if !permissions_match(&entry.source, entry.source_permissions.as_ref())? {
            return Err(FilesystemError::Postcondition(entry.source.clone()));
        }
    }
    Ok(needs_change)
}

fn classify_symlink_target(
    entry: &Entry,
    options: &ConvergeOptions<'_>,
    target_metadata: Option<&Metadata>,
) -> Result<ExistingState, FilesystemError> {
    let Some(metadata) = target_metadata else {
        return Ok(ExistingState::Absent);
    };
    if is_link_or_reparse(metadata) {
        let link_target = lexical_link_target(&entry.target)?;
        if link_target == absolute_lexical(&entry.source)? {
            return Ok(ExistingState::ManagedLink);
        }
        for previous in options.previous_sources {
            if link_target == absolute_lexical(previous)? {
                return Ok(ExistingState::RelocatedManagedLink);
            }
        }
        return Ok(ExistingState::Conflict);
    }
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(FilesystemError::UnsupportedTarget(entry.target.clone()));
    }
    if trees_equal(&entry.source, &entry.target)? {
        return Ok(ExistingState::IdenticalSource);
    }
    if let Some(skeleton) = options.skeleton {
        if symlink_metadata(skeleton, "inspect skeleton")?.is_some()
            && trees_equal(skeleton, &entry.target)?
        {
            return Ok(ExistingState::SkeletonDefault);
        }
    }
    Ok(ExistingState::Conflict)
}

fn classify_copy_target(
    entry: &Entry,
    target_metadata: Option<&Metadata>,
) -> Result<ExistingState, FilesystemError> {
    let Some(metadata) = target_metadata else {
        return Ok(ExistingState::Absent);
    };
    if is_link_or_reparse(metadata) {
        return Ok(ExistingState::Conflict);
    }
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(FilesystemError::UnsupportedTarget(entry.target.clone()));
    }
    if trees_equal(&entry.source, &entry.target)? {
        Ok(ExistingState::IdenticalSource)
    } else {
        Ok(ExistingState::Conflict)
    }
}

fn choose_action(
    entry: &Entry,
    policy: ManagedPathPolicy,
    state: ExistingState,
    target_permissions_match: bool,
) -> (EntryAction, bool) {
    match entry.mode {
        Mode::Copy => match state {
            ExistingState::Absent => (EntryAction::Create, false),
            ExistingState::IdenticalSource if target_permissions_match => {
                (EntryAction::None, false)
            }
            ExistingState::IdenticalSource => (EntryAction::UpdatePermissions, false),
            ExistingState::Conflict if entry.reconcile_existing => (EntryAction::Replace, false),
            ExistingState::Conflict if policy == ManagedPathPolicy::Takeover => {
                (EntryAction::Replace, true)
            }
            _ => (EntryAction::Block, false),
        },
        Mode::Symlink => match state {
            ExistingState::Absent => (EntryAction::Create, false),
            ExistingState::ManagedLink => (EntryAction::None, false),
            ExistingState::RelocatedManagedLink => (EntryAction::Adopt, false),
            ExistingState::IdenticalSource if policy == ManagedPathPolicy::Safe => {
                (EntryAction::Adopt, false)
            }
            ExistingState::SkeletonDefault if policy == ManagedPathPolicy::Safe => {
                (EntryAction::Replace, true)
            }
            _ if policy == ManagedPathPolicy::Takeover => (EntryAction::Replace, true),
            _ => (EntryAction::Block, false),
        },
        _ => (EntryAction::Block, false),
    }
}

fn backup_relative_path(target: &Path) -> Result<PathBuf, FilesystemError> {
    let target = absolute_lexical(target)?;
    let mut relative = PathBuf::from("_absolute");
    for component in target.components() {
        match component {
            Component::Normal(part) => relative.push(part),
            Component::Prefix(prefix) => {
                let text = prefix.as_os_str().to_string_lossy();
                let sanitized: String = text
                    .chars()
                    .map(|character| {
                        if character.is_ascii_alphanumeric() {
                            character
                        } else {
                            '_'
                        }
                    })
                    .collect();
                relative.push(format!("_volume_{sanitized}"));
            }
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                return Err(FilesystemError::TargetAncestorNotDirectory(target));
            }
        }
    }
    Ok(relative)
}

fn append_backup_suffix(path: &Path, suffix: usize) -> PathBuf {
    if suffix == 0 {
        return path.to_path_buf();
    }
    let mut name = path
        .file_name()
        .unwrap_or_else(|| OsStr::new("target"))
        .to_os_string();
    name.push(format!(".backup-{suffix}"));
    path.with_file_name(name)
}

fn select_backup_path(
    target: &Path,
    options: &ConvergeOptions<'_>,
) -> Result<PathBuf, FilesystemError> {
    if !options.backup_root.is_absolute() {
        return Err(FilesystemError::RelativeBackupRoot(
            options.backup_root.to_path_buf(),
        ));
    }
    validate_backup_root(options.backup_root)?;
    let base = options.backup_root.join(backup_relative_path(target)?);
    for suffix in 0..options.max_backup_candidates {
        let candidate = append_backup_suffix(&base, suffix);
        if symlink_metadata(&candidate, "inspect backup candidate")?.is_none() {
            return Ok(candidate);
        }
    }
    Err(FilesystemError::BackupNamesExhausted {
        target: target.to_path_buf(),
        root: options.backup_root.to_path_buf(),
    })
}

fn validate_backup_root(path: &Path) -> Result<(), FilesystemError> {
    validate_existing_target_ancestors(&path.join("backup-candidate"))?;
    let Some(metadata) = symlink_metadata(path, "inspect backup root")? else {
        return Ok(());
    };
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(FilesystemError::UnsafeBackupRoot(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(FilesystemError::UnsafeBackupRoot(path.to_path_buf()));
        }
    }
    Ok(())
}

fn set_owner_only_directory(path: &Path) -> Result<(), FilesystemError> {
    #[cfg(unix)]
    set_mode(path, 0o700)?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn create_private_directories(path: &Path) -> Result<(), FilesystemError> {
    let absolute = absolute_lexical(path)?;
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        match symlink_metadata(&current, "inspect backup ancestor")? {
            Some(metadata) if is_link_or_reparse(&metadata) => {
                return Err(FilesystemError::TargetAncestorLink(current));
            }
            Some(metadata) if !metadata.is_dir() => {
                return Err(FilesystemError::TargetAncestorNotDirectory(current));
            }
            Some(_) => {}
            None => {
                fs::create_dir(&current)
                    .map_err(|error| io_error("create backup directory", &current, error))?;
                set_owner_only_directory(&current)?;
            }
        }
    }
    Ok(())
}

fn remove_any(path: &Path) -> Result<(), FilesystemError> {
    let Some(metadata) = symlink_metadata(path, "inspect removable path")? else {
        return Ok(());
    };
    if metadata.is_dir() && !is_link_or_reparse(&metadata) {
        fs::remove_dir_all(path).map_err(|error| io_error("remove directory", path, error))
    } else {
        fs::remove_file(path).map_err(|error| io_error("remove file", path, error))
    }
}

fn unique_sibling(target: &Path, label: &str) -> Result<PathBuf, FilesystemError> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let base_name = target.file_name().unwrap_or_else(|| OsStr::new("target"));
    for index in 0..64_u32 {
        let mut name = OsString::from(".");
        name.push(base_name);
        name.push(format!(".{label}-{}-{index}", std::process::id()));
        let candidate = parent.join(name);
        if symlink_metadata(&candidate, "inspect staging candidate")?.is_none() {
            return Ok(candidate);
        }
    }
    Err(FilesystemError::BackupNamesExhausted {
        target: target.to_path_buf(),
        root: parent.to_path_buf(),
    })
}

fn source_mode(metadata: &Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(metadata.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

fn copy_regular(source: &Path, target: &Path) -> Result<(), FilesystemError> {
    let mut input = open_regular_nofollow(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|error| io_error("create staged file", target, error))?;
    io::copy(&mut input, &mut output)
        .map_err(|error| io_error("copy regular file", target, error))?;
    output
        .flush()
        .map_err(|error| io_error("flush staged file", target, error))?;
    let metadata = input
        .metadata()
        .map_err(|error| io_error("inspect copied source", source, error))?;
    if let Some(mode) = source_mode(&metadata) {
        set_mode(target, mode)?;
    }
    Ok(())
}

fn copy_tree(source: &Path, target: &Path) -> Result<(), FilesystemError> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| io_error("inspect copy source", source, error))?;
    if is_link_or_reparse(&metadata) {
        return Err(FilesystemError::SourceLink(source.to_path_buf()));
    }
    if metadata.is_file() {
        return copy_regular(source, target);
    }
    if !metadata.is_dir() {
        return Err(FilesystemError::UnsupportedSource(source.to_path_buf()));
    }
    fs::create_dir(target).map_err(|error| io_error("create staged directory", target, error))?;
    let mut children = fs::read_dir(source)
        .map_err(|error| io_error("read copy source", source, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error("read copy source", source, error))?;
    children.sort_by_key(|child| child.file_name());
    for child in children {
        let child_source = child.path();
        let child_target = target.join(child.file_name());
        copy_tree(&child_source, &child_target)?;
    }
    if let Some(mode) = source_mode(&metadata) {
        set_mode(target, mode)?;
    }
    Ok(())
}

fn create_staged_target(entry: &Entry, staged: &Path) -> Result<(), FilesystemError> {
    match entry.mode {
        Mode::Copy => {
            copy_tree(&entry.source, staged)?;
            apply_permissions(staged, entry.permissions.as_ref())
        }
        Mode::Symlink => create_symlink(&entry.source, staged),
        mode => Err(FilesystemError::UnsupportedMode {
            entry: entry.name.clone(),
            mode,
        }),
    }
}

#[cfg(unix)]
fn create_symlink(source: &Path, target: &Path) -> Result<(), FilesystemError> {
    std::os::unix::fs::symlink(source, target)
        .map_err(|error| io_error("create staged symlink", target, error))
}

#[cfg(windows)]
fn create_symlink(source: &Path, target: &Path) -> Result<(), FilesystemError> {
    let metadata =
        fs::metadata(source).map_err(|error| io_error("inspect symlink source", source, error))?;
    if metadata.is_dir() {
        std::os::windows::fs::symlink_dir(source, target)
    } else {
        std::os::windows::fs::symlink_file(source, target)
    }
    .map_err(|error| io_error("create staged symlink", target, error))
}

#[cfg(not(any(unix, windows)))]
fn create_symlink(_source: &Path, target: &Path) -> Result<(), FilesystemError> {
    Err(io_error(
        "create staged symlink",
        target,
        io::Error::new(
            io::ErrorKind::Unsupported,
            "symbolic links are unsupported on this target",
        ),
    ))
}

fn activate_staged(
    entry: &Entry,
    staged: &Path,
    persistent_backup: Option<&Path>,
) -> Result<(), FilesystemError> {
    let target_exists =
        symlink_metadata(&entry.target, "inspect target before activation")?.is_some();
    if !target_exists {
        return fs::rename(staged, &entry.target)
            .map_err(|error| io_error("activate staged target", &entry.target, error));
    }
    let displaced = if let Some(backup) = persistent_backup {
        let parent = backup.parent().unwrap_or_else(|| Path::new("."));
        create_private_directories(parent)?;
        backup.to_path_buf()
    } else {
        unique_sibling(&entry.target, "rollback")?
    };
    fs::rename(&entry.target, &displaced)
        .map_err(|error| io_error("move displaced target", &entry.target, error))?;
    if let Err(primary) = fs::rename(staged, &entry.target) {
        match fs::rename(&displaced, &entry.target) {
            Ok(()) => return Err(io_error("activate staged target", &entry.target, primary)),
            Err(rollback) => {
                return Err(FilesystemError::RollbackFailed {
                    target: entry.target.clone(),
                    primary: primary.to_string(),
                    rollback: rollback.to_string(),
                });
            }
        }
    }
    if persistent_backup.is_none() {
        remove_any(&displaced)?;
    }
    Ok(())
}

fn postcondition_matches(entry: &Entry) -> Result<bool, FilesystemError> {
    if !permissions_match(&entry.source, entry.source_permissions.as_ref())? {
        return Ok(false);
    }
    match entry.mode {
        Mode::Symlink => {
            let Some(metadata) = symlink_metadata(&entry.target, "verify target link")? else {
                return Ok(false);
            };
            Ok(is_link_or_reparse(&metadata)
                && lexical_link_target(&entry.target)? == absolute_lexical(&entry.source)?)
        }
        Mode::Copy => {
            let Some(metadata) = symlink_metadata(&entry.target, "verify copied target")? else {
                return Ok(false);
            };
            if is_link_or_reparse(&metadata) {
                return Ok(false);
            }
            Ok(trees_equal(&entry.source, &entry.target)?
                && permissions_match(&entry.target, entry.permissions.as_ref())?)
        }
        _ => Ok(false),
    }
}

pub fn converge_entry(
    entry: &Entry,
    options: &ConvergeOptions<'_>,
) -> Result<EntryOutcome, FilesystemError> {
    if entry.target_privilege != Privilege::User {
        return Err(FilesystemError::PrivilegedEntry {
            entry: entry.name.clone(),
        });
    }
    if !matches!(entry.mode, Mode::Symlink | Mode::Copy) {
        return Err(FilesystemError::UnsupportedMode {
            entry: entry.name.clone(),
            mode: entry.mode,
        });
    }
    let Some(source_metadata) = symlink_metadata(&entry.source, "inspect source")? else {
        validate_existing_target_ancestors(&entry.target)?;
        return Ok(EntryOutcome {
            name: entry.name.clone(),
            source: entry.source.clone(),
            target: entry.target.clone(),
            status: EntryStatus::MissingSource,
            action: EntryAction::None,
            existing_state: ExistingState::Absent,
            backup: None,
        });
    };
    if is_link_or_reparse(&source_metadata) {
        return Err(FilesystemError::SourceLink(entry.source.clone()));
    }
    if !source_metadata.is_file() && !source_metadata.is_dir() {
        return Err(FilesystemError::UnsupportedSource(entry.source.clone()));
    }
    validate_source_tree(&entry.source)?;
    if entry.mode == Mode::Symlink
        && target_resolves_exactly_to_source(&entry.source, &entry.target)?
    {
        let source_permissions_match =
            permissions_match(&entry.source, entry.source_permissions.as_ref())?;
        if source_permissions_match {
            return Ok(EntryOutcome {
                name: entry.name.clone(),
                source: entry.source.clone(),
                target: entry.target.clone(),
                status: EntryStatus::UpToDate,
                action: EntryAction::None,
                existing_state: ExistingState::ManagedLink,
                backup: None,
            });
        }
        if options.dry_run {
            return Ok(EntryOutcome {
                name: entry.name.clone(),
                source: entry.source.clone(),
                target: entry.target.clone(),
                status: EntryStatus::WouldChange,
                action: EntryAction::UpdatePermissions,
                existing_state: ExistingState::ManagedLink,
                backup: None,
            });
        }
        apply_permissions(&entry.source, entry.source_permissions.as_ref())?;
        if !permissions_match(&entry.source, entry.source_permissions.as_ref())?
            || !target_resolves_exactly_to_source(&entry.source, &entry.target)?
        {
            return Err(FilesystemError::Postcondition(entry.target.clone()));
        }
        return Ok(EntryOutcome {
            name: entry.name.clone(),
            source: entry.source.clone(),
            target: entry.target.clone(),
            status: EntryStatus::Changed,
            action: EntryAction::UpdatePermissions,
            existing_state: ExistingState::ManagedLink,
            backup: None,
        });
    }
    validate_existing_target_ancestors(&entry.target)?;
    let target_metadata = symlink_metadata(&entry.target, "inspect target")?;
    let state = match entry.mode {
        Mode::Symlink => classify_symlink_target(entry, options, target_metadata.as_ref())?,
        Mode::Copy => classify_copy_target(entry, target_metadata.as_ref())?,
        mode => {
            return Err(FilesystemError::UnsupportedMode {
                entry: entry.name.clone(),
                mode,
            });
        }
    };
    let target_permissions_match = if target_metadata.is_some() && entry.mode == Mode::Copy {
        permissions_match(&entry.target, entry.permissions.as_ref())?
    } else {
        true
    };
    let source_permissions_match =
        permissions_match(&entry.source, entry.source_permissions.as_ref())?;
    let (mut action, persistent_backup) = choose_action(
        entry,
        options.managed_path_policy,
        state,
        target_permissions_match,
    );
    if action == EntryAction::None && !source_permissions_match {
        action = EntryAction::UpdatePermissions;
    }
    if action == EntryAction::Block {
        return Ok(EntryOutcome {
            name: entry.name.clone(),
            source: entry.source.clone(),
            target: entry.target.clone(),
            status: EntryStatus::SkippedExisting,
            action,
            existing_state: state,
            backup: None,
        });
    }
    if action == EntryAction::None {
        return Ok(EntryOutcome {
            name: entry.name.clone(),
            source: entry.source.clone(),
            target: entry.target.clone(),
            status: EntryStatus::UpToDate,
            action,
            existing_state: state,
            backup: None,
        });
    }
    let backup = persistent_backup
        .then(|| select_backup_path(&entry.target, options))
        .transpose()?;
    if options.dry_run {
        return Ok(EntryOutcome {
            name: entry.name.clone(),
            source: entry.source.clone(),
            target: entry.target.clone(),
            status: EntryStatus::WouldChange,
            action,
            existing_state: state,
            backup,
        });
    }
    if !source_permissions_match {
        apply_permissions(&entry.source, entry.source_permissions.as_ref())?;
    }
    if action == EntryAction::UpdatePermissions {
        if entry.mode == Mode::Copy && !target_permissions_match {
            apply_permissions(&entry.target, entry.permissions.as_ref())?;
        }
    } else {
        create_parent_directories(&entry.target)?;
        let staged = unique_sibling(&entry.target, "stage")?;
        if let Err(error) = create_staged_target(entry, &staged) {
            let _ = remove_any(&staged);
            return Err(error);
        }
        if let Err(error) = activate_staged(entry, &staged, backup.as_deref()) {
            let _ = remove_any(&staged);
            return Err(error);
        }
    }
    validate_existing_target_ancestors(&entry.target)?;
    if !postcondition_matches(entry)? {
        return Err(FilesystemError::Postcondition(entry.target.clone()));
    }
    Ok(EntryOutcome {
        name: entry.name.clone(),
        source: entry.source.clone(),
        target: entry.target.clone(),
        status: EntryStatus::Changed,
        action,
        existing_state: state,
        backup,
    })
}
