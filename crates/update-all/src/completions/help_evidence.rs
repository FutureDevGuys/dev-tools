//! Owner-only, content-addressed raw help evidence.
//!
//! Evidence is keyed by exact resolved command identity plus exact argv. The raw
//! object is immutable and bounded; a small owner-only key reference lets parser
//! upgrades reprocess the captured bytes without invoking the command again.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

pub(crate) const EVIDENCE_FORMAT_VERSION: u16 = 1;
pub(crate) const DEFAULT_STDOUT_LIMIT: usize = 2 * 1024 * 1024;
pub(crate) const DEFAULT_STDERR_LIMIT: usize = 256 * 1024;
const EVIDENCE_MAGIC: &[u8; 8] = b"UACHE\0\x01\0";
const REF_MAGIC: &[u8; 8] = b"UACHR\0\x01\0";
const MAX_OBJECT_BYTES: usize = DEFAULT_STDOUT_LIMIT + DEFAULT_STDERR_LIMIT + 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceKey {
    pub(crate) candidate_identity: String,
    pub(crate) executable: PathBuf,
    pub(crate) argv: Vec<String>,
}

impl EvidenceKey {
    pub(crate) fn digest(&self) -> String {
        let mut bytes = Vec::new();
        push_field(&mut bytes, b"update-all-help-evidence-key-v1");
        push_field(&mut bytes, self.candidate_identity.as_bytes());
        push_field(&mut bytes, path_bytes(&self.executable).as_slice());
        for arg in &self.argv {
            push_field(&mut bytes, arg.as_bytes());
        }
        sha256_hex(&bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapturedHelp {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout_truncated: bool,
    pub(crate) stderr_truncated: bool,
}

impl CapturedHelp {
    pub(crate) fn bounded(mut self, stdout_limit: usize, stderr_limit: usize) -> Self {
        if self.stdout.len() > stdout_limit {
            self.stdout.truncate(stdout_limit);
            self.stdout_truncated = true;
        }
        if self.stderr.len() > stderr_limit {
            self.stderr.truncate(stderr_limit);
            self.stderr_truncated = true;
        }
        self
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        let total = EVIDENCE_MAGIC
            .len()
            .saturating_add(2)
            .saturating_add(1 + 4)
            .saturating_add(2)
            .saturating_add(8 + self.stdout.len())
            .saturating_add(8 + self.stderr.len());
        if total > MAX_OBJECT_BYTES {
            return Err(invalid("raw help evidence exceeds the hard object bound"));
        }
        let mut output = Vec::with_capacity(total);
        output.extend_from_slice(EVIDENCE_MAGIC);
        output.extend_from_slice(&EVIDENCE_FORMAT_VERSION.to_be_bytes());
        match self.exit_code {
            None => output.push(0),
            Some(code) => {
                output.push(1);
                output.extend_from_slice(&code.to_be_bytes());
            }
        }
        output.push(u8::from(self.stdout_truncated));
        output.push(u8::from(self.stderr_truncated));
        push_u64_bytes(&mut output, &self.stdout)?;
        push_u64_bytes(&mut output, &self.stderr)?;
        Ok(output)
    }

    fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_OBJECT_BYTES {
            return Err(invalid("raw help evidence object exceeds its hard bound"));
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(EVIDENCE_MAGIC.len())? != EVIDENCE_MAGIC {
            return Err(invalid("raw help evidence magic mismatch"));
        }
        let version = cursor.u16()?;
        if version != EVIDENCE_FORMAT_VERSION {
            return Err(invalid("unsupported raw help evidence version"));
        }
        let exit_code = match cursor.u8()? {
            0 => None,
            1 => Some(cursor.i32()?),
            _ => return Err(invalid("invalid raw help exit-code tag")),
        };
        let stdout_truncated = cursor.bool()?;
        let stderr_truncated = cursor.bool()?;
        let stdout = cursor.bytes(DEFAULT_STDOUT_LIMIT)?;
        let stderr = cursor.bytes(DEFAULT_STDERR_LIMIT)?;
        cursor.finish()?;
        Ok(Self {
            stdout,
            stderr,
            exit_code,
            stdout_truncated,
            stderr_truncated,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredEvidence {
    pub(crate) digest: String,
    pub(crate) capture: CapturedHelp,
    pub(crate) reused: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct HelpEvidenceStore {
    root: PathBuf,
    stdout_limit: usize,
    stderr_limit: usize,
}

impl HelpEvidenceStore {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self {
            root,
            stdout_limit: DEFAULT_STDOUT_LIMIT,
            stderr_limit: DEFAULT_STDERR_LIMIT,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_limits(root: PathBuf, stdout_limit: usize, stderr_limit: usize) -> Self {
        Self {
            root,
            stdout_limit,
            stderr_limit,
        }
    }

    pub(crate) fn capture_once<F>(
        &self,
        key: &EvidenceKey,
        capture: F,
    ) -> io::Result<StoredEvidence>
    where
        F: FnOnce() -> io::Result<CapturedHelp>,
    {
        self.ensure_layout()?;
        if let Some(existing) = self.load_for_key(key)? {
            return Ok(StoredEvidence {
                digest: existing.0,
                capture: existing.1,
                reused: true,
            });
        }
        let capture = capture()?.bounded(self.stdout_limit, self.stderr_limit);
        let encoded = capture.encode()?;
        let digest = sha256_hex(&encoded);
        self.write_object(&digest, &encoded)?;
        self.write_reference(&key.digest(), &digest)?;
        Ok(StoredEvidence {
            digest,
            capture,
            reused: false,
        })
    }

    pub(crate) fn load_for_key(
        &self,
        key: &EvidenceKey,
    ) -> io::Result<Option<(String, CapturedHelp)>> {
        let reference = self.reference_path(&key.digest())?;
        let digest = match fs::read_to_string(&reference) {
            Ok(value) => value.trim().to_owned(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !is_sha256_hex(&digest) {
            return Err(invalid(
                "raw help evidence reference contains an invalid digest",
            ));
        }
        let object = self.object_path(&digest)?;
        let bytes = read_bounded(&object, MAX_OBJECT_BYTES)?;
        if sha256_hex(&bytes) != digest {
            return Err(invalid("raw help evidence content digest mismatch"));
        }
        Ok(Some((digest, CapturedHelp::decode(&bytes)?)))
    }

    pub(crate) fn load_digest(&self, digest: &str) -> io::Result<CapturedHelp> {
        if !is_sha256_hex(digest) {
            return Err(invalid("invalid raw help evidence digest"));
        }
        let bytes = read_bounded(&self.object_path(digest)?, MAX_OBJECT_BYTES)?;
        if sha256_hex(&bytes) != digest {
            return Err(invalid("raw help evidence content digest mismatch"));
        }
        CapturedHelp::decode(&bytes)
    }

    fn ensure_layout(&self) -> io::Result<()> {
        create_private_dir(&self.root)?;
        create_private_dir(&self.root.join("objects"))?;
        create_private_dir(&self.root.join("refs"))?;
        Ok(())
    }

    fn object_path(&self, digest: &str) -> io::Result<PathBuf> {
        if !is_sha256_hex(digest) {
            return Err(invalid("invalid evidence object digest"));
        }
        contained_join(
            &self.root,
            Path::new("objects")
                .join(&digest[..2])
                .join(format!("{digest}.raw")),
        )
    }

    fn reference_path(&self, key_digest: &str) -> io::Result<PathBuf> {
        if !is_sha256_hex(key_digest) {
            return Err(invalid("invalid evidence reference digest"));
        }
        contained_join(
            &self.root,
            Path::new("refs")
                .join(&key_digest[..2])
                .join(format!("{key_digest}.ref")),
        )
    }

    fn write_object(&self, digest: &str, bytes: &[u8]) -> io::Result<()> {
        let target = self.object_path(digest)?;
        if target.exists() {
            let existing = read_bounded(&target, MAX_OBJECT_BYTES)?;
            if existing != bytes || sha256_hex(&existing) != digest {
                return Err(invalid("existing help evidence object is corrupt"));
            }
            return Ok(());
        }
        let parent = target
            .parent()
            .ok_or_else(|| invalid("evidence object has no parent"))?;
        create_private_dir(parent)?;
        atomic_private_write(&target, bytes)
    }

    fn write_reference(&self, key_digest: &str, object_digest: &str) -> io::Result<()> {
        let target = self.reference_path(key_digest)?;
        let parent = target
            .parent()
            .ok_or_else(|| invalid("evidence reference has no parent"))?;
        create_private_dir(parent)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(REF_MAGIC);
        bytes.extend_from_slice(object_digest.as_bytes());
        bytes.push(b'\n');
        // The readable reference payload intentionally omits the magic on disk so
        // existing diagnostic tooling can inspect it. The magic participates in
        // atomic-write uniqueness and is retained here as a format-domain marker.
        let _ = bytes.split_off(REF_MAGIC.len());
        atomic_private_write(&target, format!("{object_digest}\n").as_bytes())
    }
}

pub(crate) fn publish_private_content_object(
    root: &Path,
    extension: &str,
    digest: &str,
    bytes: &[u8],
    limit: usize,
) -> io::Result<PathBuf> {
    if !root.is_absolute() {
        return Err(invalid_input("private content root must be absolute"));
    }
    if !safe_file_component(extension) {
        return Err(invalid_input("private content extension is invalid"));
    }
    if bytes.len() > limit {
        return Err(invalid("private content object exceeds its hard bound"));
    }
    if !is_sha256_hex(digest) || sha256_hex(bytes) != digest {
        return Err(invalid("private content object digest mismatch"));
    }

    create_private_dir(root)?;
    let relative = Path::new("objects")
        .join(&digest[..2])
        .join(format!("{digest}.{extension}"));
    let target = contained_join(root, relative)?;
    let parent = target
        .parent()
        .ok_or_else(|| invalid_input("private content object has no parent"))?;
    create_private_dir(parent)?;
    atomic_private_write(&target, bytes)?;
    sync_dir(parent)?;
    Ok(target)
}

pub(crate) fn private_content_object_is_healthy(
    root: &Path,
    extension: &str,
    path: &Path,
    digest: &str,
    limit: usize,
) -> bool {
    if !root.is_absolute() || !safe_file_component(extension) || !is_sha256_hex(digest) {
        return false;
    }
    let Ok(expected) = contained_join(
        root,
        Path::new("objects")
            .join(&digest[..2])
            .join(format!("{digest}.{extension}")),
    ) else {
        return false;
    };
    if path != expected {
        return false;
    }
    read_bounded(path, limit).is_ok_and(|bytes| sha256_hex(&bytes) == digest)
}

fn safe_file_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn contained_join(root: &Path, relative: PathBuf) -> io::Result<PathBuf> {
    if relative.is_absolute() {
        return Err(invalid(
            "absolute paths are not allowed below the evidence root",
        ));
    }
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(invalid("non-normal path component below the evidence root"));
        }
    }
    Ok(root.join(relative))
}

fn read_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(invalid("help evidence path is not a regular file"));
    }
    let file = File::open(path)?;
    let max = u64::try_from(limit).map_err(|_| invalid("evidence byte bound overflow"))?;
    if metadata.len() > max {
        return Err(invalid("help evidence file exceeds its hard bound"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid("help evidence file exceeds its hard bound"));
    }
    Ok(bytes)
}
fn verify_existing_object(path: &Path, expected: &[u8]) -> io::Result<()> {
    use std::io::Read;

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "content-addressed evidence path is not a regular file",
        ));
    }
    let file = fs::File::open(path)?;
    let limit = u64::try_from(expected.len())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut actual = Vec::with_capacity(expected.len().saturating_add(1));
    file.take(limit).read_to_end(&mut actual)?;
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "content-addressed evidence object does not match its digest",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

fn atomic_private_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if path.exists() {
        return verify_existing_object(path, bytes);
    }

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "evidence object has no parent")
    })?;
    create_private_dir(parent)?;

    let mut nonce = 0_u32;
    let (temp_path, mut file) = loop {
        let candidate = parent.join(format!(
            ".{}.{}.{}.tmp",
            path.file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("object"),
            std::process::id(),
            nonce,
        ));
        nonce = nonce.saturating_add(1);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(file) => break (candidate, file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    };

    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);

        // Hard-link publication is no-clobber: a concurrent writer can win, but an
        // immutable digest path is never replaced.
        match fs::hard_link(&temp_path, path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                verify_existing_object(path, bytes)
            }
            Err(error) => Err(error),
        }
    })();
    let _ = fs::remove_file(&temp_path);
    result?;
    sync_dir(parent)
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_dir() {
            return Err(invalid("help evidence directory is not a directory"));
        }
        if metadata.permissions().mode() & 0o777 != 0o700 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn push_u64_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> io::Result<()> {
    let len = u64::try_from(bytes.len()).map_err(|_| invalid("help evidence length overflow"))?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn push_field(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    output.extend_from_slice(bytes);
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().to_string_lossy().as_bytes().to_vec()
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, count: usize) -> io::Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| invalid("evidence cursor overflow"))?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invalid("truncated help evidence"))?;
        self.offset = end;
        Ok(result)
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn bool(&mut self) -> io::Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid("invalid evidence boolean")),
        }
    }
    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| invalid("truncated evidence u16"))?,
        ))
    }
    fn i32(&mut self) -> io::Result<i32> {
        Ok(i32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| invalid("truncated evidence i32"))?,
        ))
    }
    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| invalid("truncated evidence u64"))?,
        ))
    }
    fn bytes(&mut self, limit: usize) -> io::Result<Vec<u8>> {
        let len = usize::try_from(self.u64()?).map_err(|_| invalid("evidence length overflow"))?;
        if len > limit {
            return Err(invalid("evidence stream exceeds its hard bound"));
        }
        Ok(self.take(len)?.to_vec())
    }
    fn finish(&self) -> io::Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(invalid("trailing raw help evidence bytes"))
        }
    }
}

struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    bit_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffer_len: 0,
            bit_len: 0,
        }
    }

    fn digest(bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(bytes);
        hasher.finalize()
    }

    fn update(&mut self, mut bytes: &[u8]) {
        self.bit_len = self
            .bit_len
            .wrapping_add((bytes.len() as u64).wrapping_mul(8));
        if self.buffer_len != 0 {
            let available = 64 - self.buffer_len;
            let take = available.min(bytes.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&bytes[..take]);
            self.buffer_len += take;
            bytes = &bytes[take..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }
        while bytes.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&bytes[..64]);
            self.compress(&block);
            bytes = &bytes[64..];
        }
        if !bytes.is_empty() {
            self.buffer[..bytes.len()].copy_from_slice(bytes);
            self.buffer_len = bytes.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0; 64];
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..64].copy_from_slice(&self.bit_len.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut output = [0u8; 32];
        for (chunk, value) in output.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        output
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut words = [0u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            let mut word = [0u8; 4];
            word.copy_from_slice(chunk);
            words[index] = u32::from_be_bytes(word);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "update-all-help-evidence-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        path
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn evidence_is_captured_once_per_exact_identity() {
        let root = temp_root("once");
        let store = HelpEvidenceStore::with_limits(root.clone(), 1024, 1024);
        let key = EvidenceKey {
            candidate_identity: "candidate-a".into(),
            executable: PathBuf::from("/bin/tool"),
            argv: vec!["--help".into()],
        };
        let first = store
            .capture_once(&key, || {
                Ok(CapturedHelp {
                    stdout: b"help".to_vec(),
                    stderr: Vec::new(),
                    exit_code: Some(0),
                    stdout_truncated: false,
                    stderr_truncated: false,
                })
            })
            .unwrap();
        let second = store
            .capture_once(&key, || panic!("same identity must not rerun help"))
            .unwrap();
        assert!(!first.reused);
        assert!(second.reused);
        assert_eq!(first.digest, second.digest);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn evidence_streams_are_bounded() {
        let root = temp_root("bounded");
        let store = HelpEvidenceStore::with_limits(root.clone(), 4, 3);
        let key = EvidenceKey {
            candidate_identity: "candidate".into(),
            executable: PathBuf::from("/bin/tool"),
            argv: vec!["--help".into()],
        };
        let stored = store
            .capture_once(&key, || {
                Ok(CapturedHelp {
                    stdout: b"123456".to_vec(),
                    stderr: b"abcde".to_vec(),
                    exit_code: Some(2),
                    stdout_truncated: false,
                    stderr_truncated: false,
                })
            })
            .unwrap();
        assert_eq!(stored.capture.stdout, b"1234");
        assert_eq!(stored.capture.stderr, b"abc");
        assert!(stored.capture.stdout_truncated);
        assert!(stored.capture.stderr_truncated);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn evidence_files_and_directories_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp_root("permissions");
        let store = HelpEvidenceStore::new(root.clone());
        let key = EvidenceKey {
            candidate_identity: "candidate".into(),
            executable: PathBuf::from("/bin/tool"),
            argv: vec!["--help".into()],
        };
        let stored = store
            .capture_once(&key, || {
                Ok(CapturedHelp {
                    stdout: b"help".to_vec(),
                    stderr: Vec::new(),
                    exit_code: Some(0),
                    stdout_truncated: false,
                    stderr_truncated: false,
                })
            })
            .unwrap();
        let object = store.object_path(&stored.digest).unwrap();
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(object).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod immutable_object_publication_tests {
    use super::atomic_private_write;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_directory(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock must be after epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("update-all-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).expect("create temporary evidence directory");
        path
    }

    #[test]
    fn content_addressed_object_publication_never_clobbers_existing_bytes() {
        let root = temporary_directory("help-evidence-no-clobber");
        let object = root.join("object");
        atomic_private_write(&object, b"first").expect("publish first object");
        let error = atomic_private_write(&object, b"second")
            .expect_err("a digest path must never accept different bytes");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(fs::read(&object).expect("read object"), b"first");
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn content_addressed_object_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let root = temporary_directory("help-evidence-mode");
        let object = root.join("object");
        atomic_private_write(&object, b"private").expect("publish object");
        let mode = fs::metadata(&object)
            .expect("object metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(root);
    }
}
