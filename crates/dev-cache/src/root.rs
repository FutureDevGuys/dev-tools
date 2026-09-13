use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::util::now_unix;

mod volume;

const MARKER_NAME: &str = ".dev-cache-root.json";

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpenMode {
    Observe,
    Prepare,
}

#[derive(Clone, Debug)]
pub struct RootHandle {
    pub root: PathBuf,
    pub platform: String,
    pub platform_root: PathBuf,
    pub marker: RootMarker,
    pub domain_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RootMarker {
    pub schema_version: u32,
    pub root_id: String,
    pub canonical_path: PathBuf,
    pub volume_identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stable_volume_identity: Option<String>,
    pub created_unix: u64,
    #[serde(default)]
    pub runtime_domains: HashMap<String, String>,
}

impl RootHandle {
    pub fn initialize(path: &Path) -> Result<Self> {
        let path = crate::util::path_from_home(path);
        fs::create_dir_all(&path)
            .with_context(|| format!("create cache root {}", path.display()))?;
        let canonical = path
            .canonicalize()
            .with_context(|| format!("resolve cache root {}", path.display()))?;
        let marker_path = canonical.join(MARKER_NAME);
        if marker_path.exists() {
            return Self::initialize_coordination(&canonical);
        }
        let mut entries =
            fs::read_dir(&canonical).with_context(|| format!("inspect {}", canonical.display()))?;
        if entries.next().transpose()?.is_some() {
            bail!(
                "refusing to claim nonempty unmarked cache root: {}",
                canonical.display()
            );
        }
        ensure_writable(&canonical)?;
        let observed_volume = volume::observe(&canonical)?;
        let root_id = random_id();
        let mut runtime_domains = HashMap::new();
        runtime_domains.insert(runtime_key(), random_id());
        let marker = RootMarker {
            schema_version: 2,
            root_id,
            canonical_path: canonical.clone(),
            volume_identity: observed_volume.device,
            stable_volume_identity: observed_volume.stable,
            created_unix: now_unix(),
            runtime_domains,
        };
        write_marker_atomic(&marker_path, &marker)?;
        Self::initialize_coordination(&canonical)
    }

    fn initialize_coordination(path: &Path) -> Result<Self> {
        let root = Self::open(path)?;
        crate::lease::prepare_root_lock(&root)?;
        Ok(root)
    }

    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_mode(path, OpenMode::Prepare)
    }

    /// Inspect an already initialized runtime layout without creating entries,
    /// probing writability or enrolling a runtime domain. Missing state is an
    /// error, not permission to repair it. This does not prove write access.
    pub fn observe(path: &Path) -> Result<Self> {
        Self::open_with_mode(path, OpenMode::Observe)
    }

    fn open_with_mode(path: &Path, mode: OpenMode) -> Result<Self> {
        let requested = crate::util::path_from_home(path);
        if !requested.is_dir() {
            bail!("configured cache root is missing: {}", requested.display());
        }
        let canonical = requested
            .canonicalize()
            .with_context(|| format!("resolve cache root {}", requested.display()))?;
        let marker_path = canonical.join(MARKER_NAME);
        let mut marker = read_marker(&marker_path, &canonical)?;
        let current_volume = volume::observe(&canonical)?;
        volume::validate(&marker, &current_volume)?;
        if mode == OpenMode::Prepare {
            ensure_writable(&canonical)?;
        }
        let platform = platform_namespace();
        let key = runtime_key();
        if mode == OpenMode::Prepare
            && (marker.volume_identity != current_volume.device
                || (marker.stable_volume_identity.is_none() && current_volume.stable.is_some())
                || !marker.runtime_domains.contains_key(&key))
        {
            // Only a needed marker update acquires write coordination. Normal
            // observation and already-enrolled opens do not create a lock.
            let _lock = marker_lock(&canonical)?;
            marker = read_marker(&marker_path, &canonical)?;
            let fresh_volume = volume::observe(&canonical)?;
            volume::validate(&marker, &fresh_volume)?;
            let before = marker.clone();
            marker.volume_identity = fresh_volume.device;
            marker.stable_volume_identity = fresh_volume.stable;
            marker
                .runtime_domains
                .entry(key.clone())
                .or_insert_with(random_id);
            if marker != before {
                write_marker_atomic(&marker_path, &marker)?;
            }
        }
        if !marker.runtime_domains.contains_key(&key) {
            bail!("cache root has no initialized domain for this runtime");
        }
        let domain_id = marker.runtime_domains[&key].clone();
        let platform_root = canonical.join("v2").join("domains").join(&domain_id);
        for relative in [
            "control/leases",
            "control/resources",
            "control/gc-journal",
            "workspaces",
            "cache",
            "artifacts/blake3",
            "migration",
            "trash",
        ] {
            let directory = platform_root.join(relative);
            if mode == OpenMode::Prepare {
                fs::create_dir_all(&directory)
                    .with_context(|| format!("create cache layout {relative}"))?;
            } else if !directory.is_dir() {
                bail!("cache layout is missing directory {relative}");
            }
        }
        Ok(Self {
            root: canonical,
            platform,
            platform_root,
            marker,
            domain_id,
        })
    }

    pub fn marker_path(&self) -> PathBuf {
        self.root.join(MARKER_NAME)
    }

    pub fn relocate(mut self, requested: &Path) -> Result<Self> {
        let requested = crate::util::path_from_home(requested);
        if !requested.is_absolute() {
            bail!(
                "replacement cache root must be absolute: {}",
                requested.display()
            );
        }
        if requested.exists() {
            bail!(
                "replacement cache root already exists: {}",
                requested.display()
            );
        }
        let parent = requested
            .parent()
            .context("replacement cache root has no parent")?
            .canonicalize()
            .with_context(|| format!("resolve replacement parent for {}", requested.display()))?;
        let leaf = requested
            .file_name()
            .context("replacement cache root has no final component")?;
        let replacement = parent.join(leaf);
        let current_volume = volume::observe(&self.root)?;
        volume::validate(&self.marker, &current_volume)?;
        if volume_identity(&parent)? != current_volume.device {
            bail!("replacement cache root must remain on the same filesystem or volume");
        }
        self.marker.volume_identity = current_volume.device;
        self.marker.stable_volume_identity = current_volume.stable;
        let original = self.root.clone();
        self.marker.canonical_path = replacement.clone();
        write_marker_atomic(&self.marker_path(), &self.marker)?;
        if let Err(error) = fs::rename(&original, &replacement) {
            self.marker.canonical_path = original.clone();
            let _ = write_marker_atomic(&original.join(MARKER_NAME), &self.marker);
            return Err(error).with_context(|| {
                format!(
                    "atomically rename cache root {} to {}",
                    original.display(),
                    replacement.display()
                )
            });
        }
        Self::open(&replacement)
    }

    pub fn control(&self) -> PathBuf {
        self.platform_root.join("control")
    }
    pub fn shared(&self) -> PathBuf {
        self.platform_root.join("cache")
    }
    pub fn repos(&self) -> PathBuf {
        self.platform_root.join("workspaces")
    }
    pub fn trash(&self) -> PathBuf {
        self.platform_root.join("trash")
    }
    pub fn artifacts(&self) -> PathBuf {
        self.platform_root.join("artifacts/blake3")
    }
}

fn read_marker(path: &Path, canonical: &Path) -> Result<RootMarker> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect cache-root marker {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 * 1024 {
        bail!("cache-root marker is not a bounded ordinary file");
    }
    let marker: RootMarker = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("read cache-root marker {}", path.display()))?,
    )
    .context("parse cache-root marker")?;
    if marker.schema_version != 2 {
        bail!(
            "unsupported cache-root marker version {}; expected 2",
            marker.schema_version
        );
    }
    if marker.canonical_path != canonical {
        bail!(
            "cache-root path changed: marker={}, current={}",
            marker.canonical_path.display(),
            canonical.display()
        );
    }
    Ok(marker)
}

fn write_marker_atomic(path: &Path, marker: &RootMarker) -> Result<()> {
    let parent = path.parent().context("cache-root marker has no parent")?;
    let temporary = parent.join(format!(".dev-cache-marker-{}.tmp", random_id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .context("create new cache-root marker stage")?;
    let written = (|| -> Result<()> {
        serde_json::to_writer_pretty(&mut file, marker)?;
        file.write_all(b"\n")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = match fs::symlink_metadata(path) {
                Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {
                    meta.permissions().mode() & 0o777
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0o644,
                _ => bail!("cache-root marker publication lost ordinary-file ownership"),
            };
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        file.sync_all()?;
        Ok(())
    })();
    drop(file);
    if let Err(error) = written {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error).context("publish cache-root marker");
    }
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn marker_lock(root: &Path) -> Result<fs::File> {
    use fs2::FileExt;
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(root.join(".dev-cache-root.lock"))
        .context("open cache-root marker coordination")?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("cache-root marker coordination is not a regular file");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            bail!("cache-root marker coordination is a reparse point");
        }
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    bail!("cache-root marker is busy; retry the operation");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => return Err(error).context("lock cache-root marker"),
        }
    }
}

fn ensure_writable(path: &Path) -> Result<()> {
    let probe = path.join(format!(".dev-cache-write-probe-{}", random_id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&probe)
        .with_context(|| format!("create private cache-root write probe: {}", path.display()))?;
    let written = file.write_all(b"probe");
    drop(file);
    // Attempt cleanup even on a failed write, preserving the primary failure.
    let removed = fs::remove_file(&probe);
    written.with_context(|| format!("cache root is not writable: {}", path.display()))?;
    removed.with_context(|| format!("remove write probe {}", probe.display()))
}

fn random_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn runtime_key() -> String {
    let mut identity = platform_namespace();
    if let Ok(machine_id) = fs::read_to_string("/etc/machine-id") {
        identity.push('\0');
        identity.push_str(machine_id.trim());
    }
    for name in ["WSL_DISTRO_NAME", "COMPUTERNAME"] {
        if let Some(value) = std::env::var_os(name) {
            identity.push('\0');
            identity.push_str(&value.to_string_lossy());
        }
    }
    blake3::hash(identity.as_bytes()).to_hex().to_string()
}

pub fn platform_namespace() -> String {
    if cfg!(windows) {
        "windows".to_owned()
    } else if cfg!(target_os = "linux")
        && (std::env::var_os("WSL_DISTRO_NAME").is_some()
            || std::env::var_os("WSL_INTEROP").is_some())
    {
        "wsl".to_owned()
    } else {
        std::env::consts::OS.to_owned()
    }
}

#[cfg(unix)]
fn volume_identity(path: &Path) -> Result<String> {
    use std::os::unix::fs::MetadataExt;
    Ok(format!("unix-dev:{}", fs::metadata(path)?.dev()))
}

#[cfg(windows)]
fn volume_identity(path: &Path) -> Result<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{GetVolumeInformationW, GetVolumePathNameW};

    let mut input: Vec<u16> = path.as_os_str().encode_wide().collect();
    input.push(0);
    let mut volume_path = vec![0_u16; 32768];
    // SAFETY: both buffers are valid writable/readable UTF-16 allocations for the
    // supplied lengths and remain alive for the duration of the Win32 calls.
    let ok = unsafe {
        GetVolumePathNameW(
            input.as_ptr(),
            volume_path.as_mut_ptr(),
            volume_path.len() as u32,
        )
    };
    if ok == 0 {
        bail!("GetVolumePathNameW failed for {}", path.display());
    }
    let mut serial = 0_u32;
    // SAFETY: volume_path is NUL-terminated by the successful call above; all
    // optional output buffers are null and serial points to initialized storage.
    let ok = unsafe {
        GetVolumeInformationW(
            volume_path.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut serial,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        )
    };
    if ok == 0 {
        bail!("GetVolumeInformationW failed for {}", path.display());
    }
    Ok(format!("windows-volume:{serial:08x}"))
}

#[cfg(not(any(unix, windows)))]
fn volume_identity(path: &Path) -> Result<String> {
    Ok(format!("path:{}", path.display()))
}
