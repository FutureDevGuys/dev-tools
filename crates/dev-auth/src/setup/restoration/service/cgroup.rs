use super::*;
use std::os::fd::OwnedFd;

const CGROUP2_MAGIC: u64 = 0x6367_7270;
const LIMIT: u64 = 4096;
const MAX_ENTRIES: usize = 16_384;

pub(super) fn require_absence(include_broker: bool) -> Result<()> {
    let root = KernelDirectory::open(Path::new(crate::linux_admission::WORKLOAD_CGROUP_ROOT))?;
    let mut entries = rustix::fs::Dir::read_from(&root.directory)?;
    for (index, entry) in (&mut entries).enumerate() {
        if index >= MAX_ENTRIES {
            bail!("native workload domain inventory exceeds its bound");
        }
        let entry = entry?;
        let name = entry.file_name();
        if !name.to_bytes().starts_with(b"dev-auth-workload-") {
            continue;
        }
        let name = name
            .to_str()
            .context("native workload domain has an invalid name")?;
        let path = root.path.join(name);
        if crate::linux_admission::workload_session_id(&path).is_none() {
            bail!("native workload domain has unsupported product ownership");
        }
        root.require_empty(OsStr::new(name))?;
    }
    if include_broker {
        for unit in UNITS {
            root.require_empty(OsStr::new(unit.name()))?;
        }
    }
    root.validate()
}

struct KernelDirectory {
    directory: OwnedFd,
    path: PathBuf,
}

impl KernelDirectory {
    fn open(path: &Path) -> Result<Self> {
        let directory = rustix::fs::open(path, directory_flags(), rustix::fs::Mode::empty())?;
        require_kernel_directory(&directory)?;
        if fs::canonicalize(path)? != path {
            bail!("native cgroup root is not canonical");
        }
        let result = Self {
            directory,
            path: path.to_owned(),
        };
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> Result<()> {
        require_kernel_directory(&self.directory)?;
        let held = rustix::fs::fstat(&self.directory)?;
        let named = fs::symlink_metadata(&self.path)?;
        if !named.is_dir()
            || named.file_type().is_symlink()
            || held.st_dev != named.dev()
            || held.st_ino != named.ino()
            || held.st_uid != named.uid()
            || held.st_mode != named.mode()
        {
            bail!("native cgroup root no longer names the held directory");
        }
        Ok(())
    }

    fn require_empty(&self, name: &OsStr) -> Result<()> {
        if !matches!(
            Path::new(name).components().collect::<Vec<_>>().as_slice(),
            [std::path::Component::Normal(_)]
        ) {
            bail!("native cgroup observation requires a single unit leaf");
        }
        self.validate()?;
        let directory = match rustix::fs::openat(
            &self.directory,
            name,
            directory_flags(),
            rustix::fs::Mode::empty(),
        ) {
            Ok(directory) => directory,
            Err(rustix::io::Errno::NOENT) => {
                self.validate()?;
                return Ok(());
            }
            Err(error) => return Err(error).context("open native unit cgroup"),
        };
        require_kernel_directory(&directory)?;
        if read_population(&directory)? {
            bail!("native product execution domain remains populated");
        }
        let held = rustix::fs::fstat(&directory)?;
        let named =
            rustix::fs::statat(&self.directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        if held.st_dev != named.st_dev
            || held.st_ino != named.st_ino
            || held.st_uid != named.st_uid
            || held.st_mode != named.st_mode
        {
            bail!("native unit cgroup changed during observation");
        }
        self.validate()
    }
}

fn directory_flags() -> rustix::fs::OFlags {
    rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC
}

fn require_kernel_directory(directory: &OwnedFd) -> Result<()> {
    if rustix::fs::fstatfs(directory)?.f_type as u64 != CGROUP2_MAGIC {
        bail!("native cgroup observation requires the kernel cgroup-v2 filesystem");
    }
    let metadata = rustix::fs::fstat(directory)?;
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::Directory
        || metadata.st_uid != 0
        || metadata.st_mode & 0o022 != 0
    {
        bail!("native cgroup directory has unsafe custody");
    }
    Ok(())
}

fn read_population(directory: &OwnedFd) -> Result<bool> {
    require_kernel_directory(directory)?;
    let file = File::from(rustix::fs::openat(
        directory,
        "cgroup.events",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    let held = file.metadata()?;
    if !held.is_file()
        || held.uid() != 0
        || held.mode() & 0o022 != 0
        || rustix::fs::fstatfs(&file)?.f_type as u64 != CGROUP2_MAGIC
    {
        bail!("native cgroup events have unsafe kernel custody");
    }
    let mut bytes = Vec::new();
    (&file).take(LIMIT + 1).read_to_end(&mut bytes)?;
    let result = populated(&bytes)?;
    let named = rustix::fs::statat(
        directory,
        "cgroup.events",
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )?;
    if held.dev() != named.st_dev
        || held.ino() != named.st_ino
        || held.uid() != named.st_uid
        || held.mode() != named.st_mode
    {
        bail!("native cgroup events changed during observation");
    }
    Ok(result)
}

fn populated(bytes: &[u8]) -> Result<bool> {
    if bytes.is_empty() || bytes.len() as u64 > LIMIT {
        bail!("native cgroup events exceed content bounds");
    }
    let text = std::str::from_utf8(bytes).context("native cgroup events are not UTF-8")?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let mut words = line.split_ascii_whitespace();
        let key = words.next().context("native cgroup event key is absent")?;
        let value = words
            .next()
            .context("native cgroup event value is absent")?;
        if words.next().is_some()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || value.parse::<u64>().is_err()
            || fields.insert(key, value).is_some()
        {
            bail!("native cgroup event fields are invalid or ambiguous");
        }
    }
    match fields.get("populated").copied() {
        Some("0") => Ok(false),
        Some("1") => Ok(true),
        _ => bail!("native cgroup population is not an explicit boolean"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_filesystem_cannot_forge_native_population_evidence() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("cgroup.events"), b"populated 0\n").unwrap();
        let error = match KernelDirectory::open(root.path()) {
            Ok(_) => panic!("ordinary files cannot supply kernel population evidence"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("cgroup-v2 filesystem"));
    }

    #[test]
    #[ignore = "read-only native acceptance requires a running systemd host with cgroup v2"]
    fn native_system_slice_population_includes_its_running_descendants() {
        let root =
            KernelDirectory::open(Path::new(crate::linux_admission::WORKLOAD_CGROUP_ROOT)).unwrap();
        assert!(read_population(&root.directory).unwrap());
        root.validate().unwrap();
    }

    #[test]
    fn kernel_population_requires_one_explicit_bounded_boolean() {
        assert!(!populated(b"populated 0\nfrozen 0\n").unwrap());
        assert!(populated(b"populated 1\nfrozen 0\n").unwrap());
        assert!(!populated(b"future_counter 1\npopulated 0\n").unwrap());
        for bytes in [
            b"".as_slice(),
            b"frozen 0\n",
            b"populated 2\n",
            b"populated 0\npopulated 1\n",
            b"populated 0 trailing\n",
            b"populated -1\n",
            b"populated 0\nfrozen bad\n",
        ] {
            assert!(populated(bytes).is_err());
        }
        assert!(populated(&vec![b' '; 4097]).is_err());
    }
}
