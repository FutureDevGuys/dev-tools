use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::util::{now_unix, write_json_atomic};

const MARKER_NAME: &str = ".dev-cache-root.json";

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
            return Self::open(&canonical);
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
        let volume_identity = volume_identity(&canonical)?;
        let root_id = random_id();
        let mut runtime_domains = HashMap::new();
        runtime_domains.insert(runtime_key(), random_id());
        let marker = RootMarker {
            schema_version: 2,
            root_id,
            canonical_path: canonical.clone(),
            volume_identity,
            created_unix: now_unix(),
            runtime_domains,
        };
        write_json_atomic(&marker_path, &marker)?;
        Self::open(&canonical)
    }

    pub fn open(path: &Path) -> Result<Self> {
        let requested = crate::util::path_from_home(path);
        if !requested.is_dir() {
            bail!("configured cache root is missing: {}", requested.display());
        }
        let canonical = requested
            .canonicalize()
            .with_context(|| format!("resolve cache root {}", requested.display()))?;
        let marker_path = canonical.join(MARKER_NAME);
        let mut marker: RootMarker = serde_json::from_slice(
            &fs::read(&marker_path)
                .with_context(|| format!("read cache-root marker {}", marker_path.display()))?,
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
        let current_volume = volume_identity(&canonical)?;
        if marker.volume_identity != current_volume {
            bail!(
                "cache-root volume changed; expected {}, found {}",
                marker.volume_identity,
                current_volume
            );
        }
        ensure_writable(&canonical)?;
        let platform = platform_namespace();
        let key = runtime_key();
        if !marker.runtime_domains.contains_key(&key) {
            marker.runtime_domains.insert(key.clone(), random_id());
            write_json_atomic(&marker_path, &marker)?;
        }
        let domain_id = marker.runtime_domains[&key].clone();
        let platform_root = canonical.join("v2").join("domains").join(&domain_id);
        for relative in [
            "control/leases",
            "workspaces",
            "cache",
            "artifacts/blake3",
            "migration",
            "trash",
        ] {
            fs::create_dir_all(platform_root.join(relative))
                .with_context(|| format!("create cache layout {relative}"))?;
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
        if volume_identity(&parent)? != self.marker.volume_identity {
            bail!("replacement cache root must remain on the same filesystem or volume");
        }
        let original = self.root.clone();
        self.marker.canonical_path = replacement.clone();
        write_json_atomic(&self.marker_path(), &self.marker)?;
        if let Err(error) = fs::rename(&original, &replacement) {
            self.marker.canonical_path = original.clone();
            let _ = write_json_atomic(&original.join(MARKER_NAME), &self.marker);
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

fn ensure_writable(path: &Path) -> Result<()> {
    let probe = path.join(format!(".dev-cache-write-probe-{}", std::process::id()));
    fs::write(&probe, b"probe")
        .with_context(|| format!("cache root is not writable: {}", path.display()))?;
    fs::remove_file(&probe).with_context(|| format!("remove write probe {}", probe.display()))
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
    } else if std::env::var_os("WSL_DISTRO_NAME").is_some()
        || std::env::var_os("WSL_INTEROP").is_some()
    {
        "wsl".to_owned()
    } else {
        "linux".to_owned()
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
