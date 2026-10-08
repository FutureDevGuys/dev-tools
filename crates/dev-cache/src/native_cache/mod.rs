//! Explicit native build-cache scope. Engine storage is never a filesystem GC resource.
mod http;

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};

const API: &str = "/v1.51";
#[cfg(target_os = "linux")]
const OUTPUT_LIMIT: usize = 8 * 1024 * 1024;
const MAX_RECORDS: usize = 32;
const MAX_OBSERVED_RECORDS: usize = 20_000;
#[cfg(target_os = "linux")]
const OPERATION_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, ValueEnum, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    Docker,
    Podman,
}

#[derive(Clone, Copy, Debug, ValueEnum, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PrivilegeDomain {
    Rootless,
    Rootful,
}

#[derive(Debug, Args)]
pub struct NativeCacheArgs {
    #[arg(value_enum)]
    pub provider: Provider,
    /// Explicit local Unix socket path, never a context name or network URL.
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Apply only the explicitly selected cache IDs after fresh admission.
    #[arg(long)]
    pub apply: bool,
    /// Engine ID observed in a preview; mandatory for apply.
    #[arg(long)]
    pub engine_id: Option<String>,
    /// Exact native DockerRootDir observed in a preview; mandatory for apply.
    #[arg(long)]
    pub storage_root: Option<PathBuf>,
    /// Expected engine privilege domain; mandatory for apply.
    #[arg(long, value_enum)]
    pub privilege_domain: Option<PrivilegeDomain>,
    /// Exact build-cache ID; repeat for at most 32 records. Mandatory for apply.
    #[arg(long)]
    pub cache_id: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NativeCacheReport {
    pub schema: &'static str,
    pub provider: Provider,
    pub operation: &'static str,
    pub outcome: &'static str,
    pub error_kind: Option<&'static str>,
    pub changed: Option<bool>,
    pub mutation_uncertain: bool,
    pub scope: Option<Scope>,
    pub before: Option<Accounting>,
    pub after: Option<Accounting>,
    pub selected_cache_ids: Vec<String>,
    pub deleted_cache_ids: Vec<String>,
    pub reclaimed_bytes: Option<u64>,
    pub exit_code: i32,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Scope {
    pub builder: &'static str,
    pub socket: PathBuf,
    pub engine_id: String,
    pub storage_root: PathBuf,
    pub privilege_domain: PrivilegeDomain,
    pub server_version: String,
    pub backend_locality: &'static str,
    pub daemon_executable: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
pub struct Accounting {
    /// Sum of eligible native record sizes, not guaranteed physical disk recovery.
    pub reclaimable_record_bytes_estimate: u64,
    pub shared_record_bytes: u64,
    pub records: Vec<CacheRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheRecord {
    #[serde(rename(deserialize = "ID"))]
    pub id: String,
    #[serde(rename(deserialize = "Type"))]
    pub kind: String,
    #[serde(rename(deserialize = "InUse"))]
    pub in_use: bool,
    #[serde(rename(deserialize = "Shared"))]
    pub shared: bool,
    #[serde(rename(deserialize = "Size"))]
    pub bytes: u64,
    #[serde(skip_deserializing)]
    pub eligible: bool,
    #[serde(skip_deserializing)]
    pub abstention: Option<&'static str>,
}

#[derive(Deserialize)]
struct Version {
    #[serde(rename = "ApiVersion")]
    api_version: String,
    #[serde(rename = "MinAPIVersion")]
    min_api_version: String,
    #[serde(rename = "Platform")]
    platform: Platform,
}
#[derive(Deserialize)]
struct Platform {
    #[serde(rename = "Name")]
    name: String,
}
#[derive(Deserialize)]
struct EngineInfo {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "DockerRootDir")]
    root: PathBuf,
    #[serde(rename = "SecurityOptions")]
    security: Vec<String>,
    #[serde(rename = "OSType")]
    os: String,
    #[serde(rename = "OperatingSystem")]
    operating_system: String,
    #[serde(rename = "ServerVersion")]
    version: String,
}
#[derive(Deserialize)]
struct DiskUsage {
    #[serde(rename = "BuildCache", deserialize_with = "required_nullable")]
    cache: Option<Vec<CacheRecord>>,
}
#[derive(Deserialize)]
struct Pruned {
    #[serde(rename = "CachesDeleted", deserialize_with = "required_nullable")]
    deleted: Option<Vec<String>>,
    #[serde(rename = "SpaceReclaimed")]
    bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Invalid,
    Unsupported,
    Permission,
    Provider,
    Protocol,
    Scope,
    Ineligible,
    Cancelled,
    Timeout,
    Socket,
    Limit,
    Deferred,
    Locality,
}
impl Failure {
    fn kind(self) -> &'static str {
        match self {
            Self::Invalid => "invalid-native-scope",
            Self::Unsupported => "unsupported-native-provider",
            Self::Permission => "native-permission-denied",
            Self::Provider => "native-provider-failed",
            Self::Protocol => "unsupported-native-response",
            Self::Scope => "native-scope-changed",
            Self::Ineligible => "cache-record-not-eligible",
            Self::Cancelled => "cancelled",
            Self::Timeout => "native-operation-timeout",
            Self::Socket => "invalid-local-socket",
            Self::Limit => "native-accounting-limit",
            Self::Deferred => "native-prune-deferred",
            Self::Locality => "native-daemon-locality-unverified",
        }
    }
    fn code(self) -> i32 {
        match self {
            Self::Invalid => 2,
            Self::Unsupported
            | Self::Permission
            | Self::Ineligible
            | Self::Deferred
            | Self::Locality => 3,
            Self::Scope | Self::Socket => 4,
            Self::Cancelled => 130,
            _ => 1,
        }
    }
}

impl NativeCacheReport {
    fn new(args: &NativeCacheArgs) -> Self {
        Self {
            schema: "dev-cache-native-cache-v1",
            provider: args.provider,
            operation: if args.apply { "apply" } else { "preview" },
            outcome: "preview",
            error_kind: None,
            changed: Some(false),
            mutation_uncertain: false,
            scope: None,
            before: None,
            after: None,
            selected_cache_ids: args.cache_id.clone(),
            deleted_cache_ids: Vec::new(),
            reclaimed_bytes: Some(0),
            exit_code: 0,
        }
    }
    fn fail(&mut self, error: Failure) {
        self.outcome = if error == Failure::Unsupported {
            "unsupported"
        } else if error == Failure::Locality {
            "blocked"
        } else if error == Failure::Deferred {
            "incomplete"
        } else {
            "failed"
        };
        self.error_kind = Some(error.kind());
        self.exit_code = error.code();
    }
}

pub fn execute(args: &NativeCacheArgs, cancelled: &AtomicBool) -> NativeCacheReport {
    let mut report = NativeCacheReport::new(args);
    let result = (|| {
        if args.provider != Provider::Docker || !cfg!(target_os = "linux") {
            return Err(Failure::Unsupported);
        }
        validate_args(args)?;
        check_cancelled(cancelled)?;
        let mut relay = NativeSocket::new(args, cancelled)?;
        execute_with(&mut relay, args, &mut report)
    })();
    if let Err(error) = result {
        report.fail(error);
    }
    report
}

fn normal_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}
fn validate_args(args: &NativeCacheArgs) -> Result<(), Failure> {
    if !args.socket.as_deref().is_some_and(normal_absolute)
        || args.cache_id.len() > MAX_RECORDS
        || args.cache_id.iter().any(|id| !valid_id(id))
        || args.cache_id.iter().collect::<BTreeSet<_>>().len() != args.cache_id.len()
        || args
            .engine_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 256 || id.chars().any(char::is_control))
        || args
            .storage_root
            .as_deref()
            .is_some_and(|path| !normal_absolute(path))
        || (args.apply
            && (args.engine_id.is_none()
                || args.storage_root.is_none()
                || args.privilege_domain.is_none()
                || args.cache_id.is_empty()))
    {
        return Err(Failure::Invalid);
    }
    Ok(())
}
fn check_cancelled(cancelled: &AtomicBool) -> Result<(), Failure> {
    if cancelled.load(Ordering::Acquire) {
        Err(Failure::Cancelled)
    } else {
        Ok(())
    }
}

trait Transport {
    fn socket(&self) -> &Path;
    fn daemon_executable(&self) -> Option<&Path>;
    fn get(&mut self, path: &str) -> Result<Vec<u8>, Failure>;
    fn prune(&mut self, path: &str) -> Result<Vec<u8>, (Failure, bool)>;
}
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
fn json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Failure> {
    serde_json::from_slice(bytes).map_err(|_| Failure::Protocol)
}
fn api_version(value: &str) -> Option<(u32, u32)> {
    let (major, minor) = value.split_once('.')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}
fn observe_scope(transport: &mut impl Transport) -> Result<Scope, Failure> {
    let version: Version = json(&transport.get("/version")?)?;
    if !version.platform.name.starts_with("Docker Engine")
        || api_version(&version.api_version).is_none_or(|v| v < (1, 51))
        || api_version(&version.min_api_version).is_none_or(|v| v > (1, 51))
    {
        return Err(Failure::Unsupported);
    }
    let info: EngineInfo = json(&transport.get(&format!("{API}/info"))?)?;
    if info.os != "linux"
        || info
            .operating_system
            .to_lowercase()
            .contains("docker desktop")
        || !normal_absolute(&info.root)
        || info.id.is_empty()
        || info.id.len() > 256
        || info.id.chars().any(char::is_control)
        || info.version.is_empty()
    {
        return Err(Failure::Unsupported);
    }
    Ok(Scope {
        builder: "docker-engine-integrated-buildkit",
        socket: transport.socket().to_owned(),
        engine_id: info.id,
        storage_root: info.root,
        privilege_domain: if info.security.iter().any(|item| item == "name=rootless") {
            PrivilegeDomain::Rootless
        } else {
            PrivilegeDomain::Rootful
        },
        server_version: info.version,
        backend_locality: if transport.daemon_executable().is_some() {
            "verified-local-dockerd"
        } else {
            "unverified"
        },
        daemon_executable: transport.daemon_executable().map(Path::to_owned),
    })
}
fn check_expected(args: &NativeCacheArgs, scope: &Scope) -> Result<(), Failure> {
    if args
        .engine_id
        .as_ref()
        .is_some_and(|value| value != &scope.engine_id)
        || args
            .storage_root
            .as_ref()
            .is_some_and(|value| value != &scope.storage_root)
        || args
            .privilege_domain
            .is_some_and(|value| value != scope.privilege_domain)
    {
        return Err(Failure::Scope);
    }
    Ok(())
}
fn accounting(transport: &mut impl Transport) -> Result<Accounting, Failure> {
    let usage: DiskUsage = json(&transport.get(&format!("{API}/system/df?type=build-cache"))?)?;
    let mut records = usage.cache.unwrap_or_default();
    if records.len() > MAX_OBSERVED_RECORDS {
        return Err(Failure::Limit);
    }
    let mut ids = BTreeSet::new();
    let mut eligible_bytes = 0u64;
    let mut shared_bytes = 0u64;
    for record in &mut records {
        if !valid_id(&record.id) || !ids.insert(record.id.clone()) {
            return Err(Failure::Protocol);
        }
        record.abstention = if record.in_use {
            Some("active-build-cache")
        } else if record.shared {
            Some("shared-with-retained-resource")
        } else if !matches!(
            record.kind.as_str(),
            "regular" | "source.local" | "source.git.checkout" | "exec.cachemount"
        ) {
            Some("unsupported-cache-kind")
        } else {
            None
        };
        record.eligible = record.abstention.is_none();
        if record.eligible {
            eligible_bytes = eligible_bytes
                .checked_add(record.bytes)
                .ok_or(Failure::Limit)?;
        }
        if record.shared {
            shared_bytes = shared_bytes
                .checked_add(record.bytes)
                .ok_or(Failure::Limit)?;
        }
    }
    records.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(Accounting {
        reclaimable_record_bytes_estimate: eligible_bytes,
        shared_record_bytes: shared_bytes,
        records,
    })
}
fn prune_path(record: &CacheRecord) -> String {
    // Moby converts id values to regex, so anchoring is mandatory. IDs were
    // restricted to ASCII alphanumerics. BuildKit boolean fields are presence
    // fields: private:{} produces bare `private`, NOT `private==true`.
    let filters = serde_json::json!({"id":{format!("^{}$", record.id):true}, "type":{record.kind.clone():true}, "private":{}});
    format!(
        "{API}/build/prune?all=false&filters={}",
        http::query_encode(&filters.to_string())
    )
}
fn execute_with(
    transport: &mut impl Transport,
    args: &NativeCacheArgs,
    report: &mut NativeCacheReport,
) -> Result<(), Failure> {
    let scope = observe_scope(transport)?;
    check_expected(args, &scope)?;
    report.scope = Some(scope.clone());
    report.before = Some(accounting(transport)?);
    if !args.apply {
        return Ok(());
    }
    if scope.daemon_executable.is_none() {
        return Err(Failure::Locality);
    }
    // Reject the complete selection before any mutation, then revalidate each
    // record immediately before its own provider-side prune operation.
    for id in &args.cache_id {
        if report
            .before
            .as_ref()
            .unwrap()
            .records
            .iter()
            .any(|record| &record.id == id && !record.eligible)
        {
            return Err(Failure::Ineligible);
        }
    }
    for id in &args.cache_id {
        if observe_scope(transport)? != scope {
            return Err(Failure::Scope);
        }
        let current = accounting(transport)?;
        let Some(record) = current.records.iter().find(|record| &record.id == id) else {
            continue;
        };
        if !record.eligible {
            return Err(Failure::Ineligible);
        }
        // Once entered, a failed request may have changed the daemon. Neither
        // CLI termination nor missing response proves rollback or cancellation.
        let previous_changed = report.changed;
        report.mutation_uncertain = true;
        if report.changed != Some(true) {
            report.changed = None;
        }
        let bytes = match transport.prune(&prune_path(record)) {
            Ok(bytes) => bytes,
            Err((error, sent)) => {
                if !sent {
                    report.changed = previous_changed;
                    report.mutation_uncertain = false;
                }
                return Err(error);
            }
        };
        let result: Pruned = json(&bytes)?;
        let deleted = result.deleted.unwrap_or_default();
        if deleted.len() > 1
            || deleted.iter().any(|deleted| deleted != id)
            || (deleted.is_empty() && result.bytes != 0)
        {
            return Err(Failure::Scope);
        }
        report.mutation_uncertain = false;
        if !deleted.is_empty() {
            report.changed = Some(true);
        } else if report.changed.is_none() {
            report.changed = Some(false);
        }
        report.deleted_cache_ids.extend(deleted);
        report.reclaimed_bytes = report
            .reclaimed_bytes
            .and_then(|bytes| bytes.checked_add(result.bytes));
        if report.reclaimed_bytes.is_none() {
            return Err(Failure::Limit);
        }
    }
    if observe_scope(transport)? != scope {
        return Err(Failure::Scope);
    }
    report.after = Some(accounting(transport)?);
    let after = report.after.as_ref().unwrap();
    if after
        .records
        .iter()
        .any(|record| report.deleted_cache_ids.contains(&record.id))
    {
        return Err(Failure::Scope);
    }
    if after
        .records
        .iter()
        .any(|record| record.eligible && args.cache_id.contains(&record.id))
    {
        return Err(Failure::Deferred);
    }
    report.outcome = "completed";
    Ok(())
}

#[cfg(target_os = "linux")]
struct NativeSocket<'a> {
    socket: PathBuf,
    socket_identity: (u64, u64, u32),
    peer: Option<(i32, u32, u32)>,
    daemon: Option<LocalDaemon>,
    attestation_initialized: bool,
    deadline: Instant,
    cancelled: &'a AtomicBool,
}
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct LocalDaemon {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
fn attest_local_daemon(pid: i32) -> Option<LocalDaemon> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    // A local forwarding socket is not locality proof. Only a directly
    // connected, independently root-custodied native dockerd executable can
    // authorize mutation. Lack of /proc permission remains read-only.
    let proc_path = PathBuf::from(format!("/proc/{pid}/exe"));
    let executable_path = std::fs::read_link(&proc_path).ok()?;
    if executable_path.file_name()? != "dockerd" || !normal_absolute(&executable_path) {
        return None;
    }
    let held =
        dev_tools_command::HeldExecutable::open_with_validation(&executable_path, |fd, _| {
            let file = std::fs::File::from(fd.try_clone_to_owned()?);
            let metadata = file.metadata()?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                anyhow::bail!("native daemon executable custody is not exclusively root-owned");
            }
            Ok(())
        })
        .ok()?;
    let mut file = held.open_read_handle().ok()?;
    let metadata = file.metadata().ok()?;
    let peer_metadata = std::fs::metadata(&proc_path).ok()?;
    if metadata.dev() != peer_metadata.dev() || metadata.ino() != peer_metadata.ino() {
        return None;
    }
    let mut magic = [0; 4];
    file.read_exact(&mut magic).ok()?;
    if &magic != b"\x7fELF" {
        return None;
    }
    Some(LocalDaemon {
        path: executable_path,
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(target_os = "linux")]
fn socket_identity(path: &Path) -> Result<(u64, u64, u32), Failure> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::symlink_metadata(path).map_err(socket_path_failure)?;
    // SAFETY: geteuid has no preconditions and does not mutate process state.
    let uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_socket() || (metadata.uid() != 0 && metadata.uid() != uid) {
        return Err(Failure::Socket);
    }
    Ok((metadata.dev(), metadata.ino(), metadata.uid()))
}
#[cfg(target_os = "linux")]
fn socket_path_failure(error: std::io::Error) -> Failure {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        Failure::Permission
    } else {
        Failure::Socket
    }
}
#[cfg(target_os = "linux")]
fn peer_identity(stream: &std::os::unix::net::UnixStream) -> Result<(i32, u32, u32), Failure> {
    use std::os::fd::AsRawFd;
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
    // SAFETY: the live stream owns fd, and both mutable buffers have the exact
    // initialized types/sizes required by Linux SO_PEERCRED.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of_val(&credentials) || credentials.pid <= 0
    {
        return Err(Failure::Socket);
    }
    Ok((credentials.pid, credentials.uid, credentials.gid))
}
#[cfg(target_os = "linux")]
impl<'a> NativeSocket<'a> {
    fn new(args: &NativeCacheArgs, cancelled: &'a AtomicBool) -> Result<Self, Failure> {
        let socket =
            std::fs::canonicalize(args.socket.as_ref().unwrap()).map_err(socket_path_failure)?;
        let socket_identity = socket_identity(&socket)?;
        Ok(Self {
            socket,
            socket_identity,
            peer: None,
            daemon: None,
            attestation_initialized: false,
            deadline: Instant::now() + OPERATION_TIMEOUT,
            cancelled,
        })
    }
    fn request(&mut self, method: &str, path: &str) -> Result<Vec<u8>, (Failure, bool)> {
        use std::io::{Read, Write};
        let mut sent = false;
        let result = (|| {
            check_cancelled(self.cancelled)?;
            if socket_identity(&self.socket)? != self.socket_identity {
                return Err(Failure::Scope);
            }
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Failure::Timeout);
            }
            let deadline = Instant::now()
                + if method == "GET" {
                    remaining.min(Duration::from_secs(20))
                } else {
                    remaining
                };
            let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
                .map_err(io_failure)?;
            let address = socket2::SockAddr::unix(&self.socket).map_err(|_| Failure::Socket)?;
            socket
                .connect_timeout(&address, remaining.min(Duration::from_millis(100)))
                .map_err(io_failure)?;
            let descriptor: std::os::fd::OwnedFd = socket.into();
            let mut stream = std::os::unix::net::UnixStream::from(descriptor);
            stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .map_err(io_failure)?;
            stream
                .set_write_timeout(Some(Duration::from_millis(100)))
                .map_err(io_failure)?;
            let peer = peer_identity(&stream)?;
            if self.peer.is_some_and(|expected| peer != expected)
                || peer.1 != self.socket_identity.2
            {
                return Err(Failure::Scope);
            }
            self.peer = Some(peer);
            let daemon = attest_local_daemon(peer.0);
            if self.attestation_initialized && self.daemon != daemon {
                return Err(Failure::Scope);
            }
            self.daemon = daemon;
            self.attestation_initialized = true;
            if socket_identity(&self.socket)? != self.socket_identity {
                return Err(Failure::Scope);
            }
            let input = http::request(method, path);
            let mut pending = input.as_slice();
            while !pending.is_empty() {
                check_deadline(self.cancelled, deadline)?;
                match stream.write(pending) {
                    Ok(0) => return Err(Failure::Provider),
                    Ok(count) => {
                        sent = true;
                        pending = &pending[count..];
                    }
                    Err(error) if retry_io(&error) => continue,
                    Err(error) => return Err(io_failure(error)),
                }
            }
            // Keep the write half open. Half-closing here cancels Go HTTP
            // request contexts and can interrupt a provider prune mid-change.
            let mut output = Vec::new();
            let mut buffer = [0; 8192];
            loop {
                check_deadline(self.cancelled, deadline)?;
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        if output.len() + count > OUTPUT_LIMIT {
                            return Err(Failure::Limit);
                        }
                        output.extend_from_slice(&buffer[..count]);
                    }
                    Err(error) if retry_io(&error) => continue,
                    Err(error) => return Err(io_failure(error)),
                }
            }
            if socket_identity(&self.socket)? != self.socket_identity {
                return Err(Failure::Scope);
            }
            Ok(http::decode(&output)?.to_vec())
        })();
        result.map_err(|error| (error, sent))
    }
}
#[cfg(target_os = "linux")]
fn check_deadline(cancelled: &AtomicBool, deadline: Instant) -> Result<(), Failure> {
    check_cancelled(cancelled)?;
    if Instant::now() >= deadline {
        Err(Failure::Timeout)
    } else {
        Ok(())
    }
}
#[cfg(target_os = "linux")]
fn retry_io(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
    )
}
#[cfg(target_os = "linux")]
fn io_failure(error: std::io::Error) -> Failure {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => Failure::Permission,
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Failure::Timeout,
        _ => Failure::Provider,
    }
}
#[cfg(target_os = "linux")]
impl Transport for NativeSocket<'_> {
    fn daemon_executable(&self) -> Option<&Path> {
        self.daemon.as_ref().map(|daemon| daemon.path.as_path())
    }
    fn socket(&self) -> &Path {
        &self.socket
    }
    fn get(&mut self, path: &str) -> Result<Vec<u8>, Failure> {
        self.request("GET", path).map_err(|(error, _)| error)
    }
    fn prune(&mut self, path: &str) -> Result<Vec<u8>, (Failure, bool)> {
        self.request("POST", path)
    }
}
#[cfg(not(target_os = "linux"))]
struct NativeSocket;
#[cfg(not(target_os = "linux"))]
impl NativeSocket {
    fn new(_: &NativeCacheArgs, _: &AtomicBool) -> Result<Self, Failure> {
        Err(Failure::Unsupported)
    }
}
#[cfg(not(target_os = "linux"))]
impl Transport for NativeSocket {
    fn daemon_executable(&self) -> Option<&Path> {
        None
    }
    fn socket(&self) -> &Path {
        Path::new("")
    }
    fn get(&mut self, _: &str) -> Result<Vec<u8>, Failure> {
        Err(Failure::Unsupported)
    }
    fn prune(&mut self, _: &str) -> Result<Vec<u8>, (Failure, bool)> {
        Err((Failure::Unsupported, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct AccountingFixture(serde_json::Value);
    impl Transport for AccountingFixture {
        fn daemon_executable(&self) -> Option<&Path> {
            None
        }
        fn socket(&self) -> &Path {
            Path::new("/fixture/engine.sock")
        }
        fn get(&mut self, path: &str) -> Result<Vec<u8>, Failure> {
            assert_eq!(path, "/v1.51/system/df?type=build-cache");
            Ok(serde_json::to_vec(&self.0).unwrap())
        }
        fn prune(&mut self, _: &str) -> Result<Vec<u8>, (Failure, bool)> {
            panic!("accounting cannot prune")
        }
    }
    fn record(id: &str, bytes: u64) -> serde_json::Value {
        json!({"ID":id,"Type":"regular","InUse":false,"Shared":false,"Size":bytes})
    }
    #[test]
    fn native_accounting_does_not_turn_missing_unknown_or_invalid_data_into_zero() {
        for value in [
            json!({}),
            json!({"BuildCache":{}}),
            json!({"BuildCache":[{"ID":"a"}]}),
            json!({"BuildCache":[{"ID":"a","Type":"regular","InUse":false,"Shared":false,"Size":-1}]}),
            json!({"BuildCache":[record("a",1),record("a",2)]}),
            json!({"BuildCache":[record("a.*",1)]}),
        ] {
            assert_eq!(
                accounting(&mut AccountingFixture(value)).unwrap_err(),
                Failure::Protocol
            );
        }
        for value in [json!({"BuildCache":null}), json!({"BuildCache":[]})] {
            let actual = accounting(&mut AccountingFixture(value)).unwrap();
            assert!(actual.records.is_empty());
            assert_eq!(actual.reclaimable_record_bytes_estimate, 0);
        }
        assert!(json::<Pruned>(br#"{"SpaceReclaimed":0}"#).is_err());
        assert!(json::<Pruned>(br#"{"CachesDeleted":null,"SpaceReclaimed":0}"#).is_ok());
    }
    #[test]
    fn native_record_budgets_fail_closed() {
        assert_eq!(
            accounting(&mut AccountingFixture(
                json!({"BuildCache":[record("a",u64::MAX),record("b",1)]})
            ))
            .unwrap_err(),
            Failure::Limit
        );
        let records = (0..=MAX_OBSERVED_RECORDS)
            .map(|id| record(&format!("record{id}"), 1))
            .collect::<Vec<_>>();
        assert_eq!(
            accounting(&mut AccountingFixture(json!({"BuildCache":records}))).unwrap_err(),
            Failure::Limit
        );
    }
    #[test]
    fn provider_input_cannot_inject_eligibility() {
        let mut active = record("a", 12);
        active["InUse"] = json!(true);
        active["eligible"] = json!(true);
        let mut shared = record("b", 23);
        shared["Shared"] = json!(true);
        let mut unknown = record("c", 34);
        unknown["Type"] = json!("volume");
        let result = accounting(&mut AccountingFixture(
            json!({"BuildCache":[active,shared,unknown,record("d",45)]}),
        ))
        .unwrap();
        assert_eq!(result.reclaimable_record_bytes_estimate, 45);
        assert_eq!(result.shared_record_bytes, 23);
        assert_eq!(
            result
                .records
                .iter()
                .filter(|record| record.eligible)
                .count(),
            1
        );
        assert_eq!(result.records[0].abstention, Some("active-build-cache"));
        assert_eq!(
            result.records[1].abstention,
            Some("shared-with-retained-resource")
        );
        assert_eq!(result.records[2].abstention, Some("unsupported-cache-kind"));
    }
    #[test]
    fn exact_native_filter_uses_presence_not_boolean_string_equality() {
        let record: CacheRecord = serde_json::from_value(record("a123", 1)).unwrap();
        let filters = r#"{"id":{"^a123$":true},"private":{},"type":{"regular":true}}"#;
        assert_eq!(
            prune_path(&record),
            format!(
                "/v1.51/build/prune?all=false&filters={}",
                http::query_encode(filters)
            )
        );
    }
}

#[cfg(test)]
mod state_tests;
