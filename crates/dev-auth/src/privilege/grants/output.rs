//! Policy-owned external output custody. A pinned root helper owns blocking
//! caller sinks inside the same job cgroup as the graph worker. The coordinator
//! never changes a caller's shared open-file-description flags or blocks on its
//! writes. A separate reader keeps enforcing the cap while sink writers block.
//! Internal graph pipe edges and terminal input do not cross this output meter.

use super::{Failure, OutputCounts, OutputObservation};
use dev_tools_privilege_session::linux::{terminal, NativeContext, SpawnPermit};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, VecDeque};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

const BUFFER: usize = 16 * 1024;
const CONFIG_LIMIT: usize = 16 * 1024;
const SCHEMA: &str = "dev-auth-grant-output-relay-v1";

/// Native private frame, never a serialized public ABI. Supported Linux
/// x86_64/aarch64 have lock-free, eight-byte-aligned AtomicU64. mmap is page
/// aligned; the only Rust access is atomic. The coordinator initializes before
/// spawn and seals the exact 80-byte length against shrink/grow. The reader main
/// owns observed[0..3], one dedicated sink writer owns each forwarded slot,
/// reader main owns complete/exceeded, and writers may CAS sticky failure.
/// No payload or submitted descriptor/path is stored in this frame. Incomplete
/// forwarded counts are confirmed lower bounds, never claimed exact writes.
#[repr(C, align(8))]
struct CounterFrame {
    observed: [AtomicU64; 3],
    forwarded: [AtomicU64; 3],
    complete: AtomicU64,
    exceeded: AtomicU64,
    failure: AtomicU64,
    reserved: AtomicU64,
}

const FRAME_SIZE: usize = 80;
const _: () = assert!(std::mem::size_of::<CounterFrame>() == FRAME_SIZE);
const _: () = assert!(std::mem::align_of::<CounterFrame>() == 8);

struct Mapping {
    address: NonNull<CounterFrame>,
    descriptor: OwnedFd,
}

// SAFETY: the fixed mapping is never moved, resized or unmapped while any Arc
// owner exists. Every shared field is an AtomicU64; no borrowed payload pointer
// or non-atomic mutation is exposed. Supported targets are gated in map().
unsafe impl Send for Mapping {} // SAFETY: Arc retains the fixed mapping; all exposed shared fields are atomic.

unsafe impl Sync for Mapping {} // SAFETY: shared access exposes only atomics within the Arc-owned mapping.

impl Mapping {
    fn map(descriptor: OwnedFd, initialize: bool) -> io::Result<Self> {
        if !cfg!(all(
            target_has_atomic = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )) {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let stat = rustix::fs::fstat(&descriptor)?;
        if stat.st_size != FRAME_SIZE as i64
            || !rustix::fs::fcntl_get_seals(&descriptor)?.contains(length_seals())
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // SAFETY: a held sealed exact-length descriptor backs a page-aligned
        // shared mapping. MAP_FAILED is checked before constructing NonNull;
        // writable access remains necessary for only atomic frame counters.
        let raw = unsafe {
            nix::libc::mmap(
                std::ptr::null_mut(),
                FRAME_SIZE,
                nix::libc::PROT_READ | nix::libc::PROT_WRITE,
                nix::libc::MAP_SHARED,
                descriptor.as_raw_fd(),
                0,
            )
        };
        if raw == nix::libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let address = NonNull::new(raw.cast::<CounterFrame>()).ok_or(io::ErrorKind::InvalidData)?;
        let mapping = Self {
            address,
            descriptor,
        };
        if initialize {
            // SAFETY: this fresh zero-length-then-sized memfd has no other
            // mapping or writer yet. Initialize actual AtomicU64 objects once.
            unsafe {
                mapping.address.as_ptr().write(CounterFrame {
                    observed: std::array::from_fn(|_| AtomicU64::new(0)),
                    forwarded: std::array::from_fn(|_| AtomicU64::new(0)),
                    complete: AtomicU64::new(0),
                    exceeded: AtomicU64::new(0),
                    failure: AtomicU64::new(0),
                    reserved: AtomicU64::new(0),
                });
            }
        }
        Ok(mapping)
    }

    fn frame(&self) -> &CounterFrame {
        // SAFETY: mmap alignment/layout/length are checked at construction;
        // this mapping remains live and the returned reference exposes atomics.
        unsafe { self.address.as_ref() }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this is the final Arc owner of exactly this mmap. The held
        // descriptor is dropped after the mapping; no pointer escapes ownership.
        unsafe { nix::libc::munmap(self.address.as_ptr().cast(), FRAME_SIZE) };
    }
}

#[derive(Clone)]
pub(super) struct Counters {
    mapping: Arc<Mapping>,
    limit: u64,
}

impl Counters {
    fn new(limit: u64) -> io::Result<Self> {
        let descriptor = rustix::fs::memfd_create(
            "dev-auth-output-counts",
            rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
        )?;
        rustix::fs::ftruncate(&descriptor, FRAME_SIZE as u64)?;
        rustix::fs::fcntl_add_seals(&descriptor, length_seals())?;
        Ok(Self {
            mapping: Arc::new(Mapping::map(descriptor, true)?),
            limit,
        })
    }

    pub(super) fn exceeded(&self) -> bool {
        self.mapping.frame().exceeded.load(Ordering::Acquire) != 0
    }

    pub(super) fn failed(&self) -> bool {
        self.mapping.frame().failure.load(Ordering::Acquire) != 0
    }

    pub(super) fn cleanup_failed(&self) -> bool {
        self.mapping.frame().failure.load(Ordering::Acquire) == 2
    }

    /// A final native helper wait witness makes counters stable. An incomplete
    /// bounded-cleanup snapshot reports only monotone pointwise lower bounds.
    pub(super) fn observation(&self, terminalized: bool) -> Result<OutputObservation, Failure> {
        let frame = self.mapping.frame();
        let forwarded = frame
            .forwarded
            .each_ref()
            .map(|v| v.load(Ordering::Acquire));
        // Read forwarded first: its writer can only advance after the reader
        // published observed bytes. Monotone loads also bound incomplete views.
        let observed = frame.observed.each_ref().map(|v| v.load(Ordering::Acquire));
        let complete = frame.complete.load(Ordering::Acquire);
        let exceeded = frame.exceeded.load(Ordering::Acquire);
        if observed.iter().any(|value| *value > self.limit + 1)
            || forwarded.iter().any(|value| *value > self.limit)
            || observed.iter().sum::<u64>() > self.limit + 1
            || forwarded.iter().sum::<u64>() > self.limit
            || observed
                .iter()
                .zip(forwarded)
                .any(|(seen, sent)| sent > *seen)
            || complete > 1
            || exceeded > 1
            || frame.reserved.load(Ordering::Acquire) != 0
            || frame.failure.load(Ordering::Acquire) > 2
            || (complete == 1 && (exceeded != 0 || self.failed()))
        {
            return Err(Failure::RuntimeFailure);
        }
        let counts = |values: [u64; 3]| OutputCounts {
            stdout: values[0],
            stderr: values[1],
            merged_pty: values[2],
        };
        Ok(OutputObservation {
            limit_bytes: self.limit,
            observed: counts(observed),
            forwarded: counts(forwarded),
            complete: terminalized && complete == 1,
            limit_exceeded: exceeded == 1,
        })
    }
}

fn length_seals() -> rustix::fs::SealFlags {
    rustix::fs::SealFlags::SEAL | rustix::fs::SealFlags::SHRINK | rustix::fs::SealFlags::GROW
}

fn config_seals() -> rustix::fs::SealFlags {
    length_seals() | rustix::fs::SealFlags::WRITE
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: String,
    limit: u64,
    channels: Vec<Channel>,
    input: Option<Input>,
    gate: i32,
    kill: i32,
    counters: i32,
    #[serde(default)]
    worker: Option<i32>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Channel {
    kind: usize,
    source: i32,
    sink: i32,
    pty: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    source: i32,
    sink: i32,
}

pub(super) struct Prepared {
    pub streams: [OwnedFd; 3],
    pub master: Option<OwnedFd>,
    pub relay: Relay,
    pub counters: Counters,
}

pub(super) struct Relay {
    arguments: Vec<std::ffi::OsString>,
    inherited: Vec<OwnedFd>,
}

impl Relay {
    pub(super) fn spawn(
        mut self,
        permit: SpawnPermit,
        executable: File,
        worker: &std::process::Child,
    ) -> io::Result<std::process::Child> {
        // Retain the actual still-owned graph worker, never a submitted PID.
        // The helper observes native exit even while the coordinator is stopped.
        let pid = rustix::process::Pid::from_raw(worker.id() as i32)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let witness = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())?;
        let old = self.inherited.pop().ok_or(io::ErrorKind::InvalidData)?;
        let mut old = File::from(old);
        let mut bytes = Vec::new();
        Read::by_ref(&mut old)
            .take((CONFIG_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > CONFIG_LIMIT {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut config: Configuration = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        config.worker = Some(witness.as_raw_fd());
        let mut snapshot = File::from(rustix::fs::memfd_create(
            "dev-auth-output-relay",
            rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
        )?);
        let bytes = serde_json::to_vec(&config).map_err(io::Error::other)?;
        if bytes.len() > CONFIG_LIMIT {
            return Err(io::ErrorKind::InvalidData.into());
        }
        snapshot.write_all(&bytes)?;
        snapshot.seek(SeekFrom::Start(0))?;
        rustix::fs::fcntl_add_seals(&snapshot, config_seals())?;
        self.arguments[1] = snapshot.as_raw_fd().to_string().into();
        self.inherited.extend([witness, snapshot.into()]);
        let null: OwnedFd = File::options()
            .read(true)
            .write(true)
            .open("/dev/null")?
            .into();
        let context = NativeContext {
            working_directory: File::open("/")?,
            mount_namespace: None,
            uid: 0,
            effective_uid: 0,
            gid: 0,
            supplementary_groups: vec![],
            user_session: None,
            controlling_terminal: false,
            inherited_files: self.inherited,
        };
        permit.spawn_held(
            executable,
            std::ffi::OsStr::new("dev-auth"),
            &self.arguments,
            &[],
            context,
            [
                null.as_fd().try_clone_to_owned()?,
                null.as_fd().try_clone_to_owned()?,
                null,
            ],
        )
    }
}

pub(super) fn prepare(
    limit: u64,
    streams: [OwnedFd; 3],
    master: Option<OwnedFd>,
    stop: (OwnedFd, OwnedFd),
) -> Result<Prepared, Failure> {
    if limit == 0 || limit > super::policy::MAX_PLAN_OUTPUT_BYTES {
        return Err(Failure::InvalidRequest);
    }
    prepare_native(limit, streams, master, stop).map_err(|_| Failure::NativeUnavailable)
}

fn prepare_native(
    limit: u64,
    mut streams: [OwnedFd; 3],
    master: Option<OwnedFd>,
    (gate, kill): (OwnedFd, OwnedFd),
) -> io::Result<Prepared> {
    let counters = Counters::new(limit)?;
    let frame = counters.mapping.descriptor.as_fd().try_clone_to_owned()?;
    let mut config = Configuration {
        schema: SCHEMA.into(),
        limit,
        channels: Vec::new(),
        input: None,
        gate: gate.as_raw_fd(),
        kill: kill.as_raw_fd(),
        counters: frame.as_raw_fd(),
        worker: None,
    };
    let mut inherited = vec![gate, kill, frame];
    let terminal_identity = master
        .as_ref()
        .map(|_| rustix::fs::fstat(&streams[0]))
        .transpose()?;
    for (index, stream) in streams.iter_mut().enumerate().skip(1) {
        let stat = rustix::fs::fstat(&*stream)?;
        if terminal_identity
            .as_ref()
            .is_some_and(|tty| tty.st_dev == stat.st_dev && tty.st_ino == stat.st_ino)
        {
            continue;
        }
        let (source, writer) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(io::Error::from)?;
        nonblocking(&source)?; // Fresh owned OFD; no caller flags are changed.
        let sink = std::mem::replace(stream, writer);
        config.channels.push(Channel {
            kind: index - 1,
            source: source.as_raw_fd(),
            sink: sink.as_raw_fd(),
            pty: false,
        });
        inherited.extend([source, sink]);
    }
    let client_master = if let Some(inner) = master {
        let outer = terminal::Pty::from_terminal(&streams[0])?;
        let mut raw = nix::sys::termios::tcgetattr(&outer.slave)?;
        nix::sys::termios::cfmakeraw(&mut raw);
        nix::sys::termios::tcsetattr(&outer.slave, nix::sys::termios::SetArg::TCSANOW, &raw)?;
        nonblocking(&inner)?;
        nonblocking(&outer.slave)?;
        let input_source = outer.slave.as_fd().try_clone_to_owned()?;
        let input_sink = inner.as_fd().try_clone_to_owned()?;
        config.input = Some(Input {
            source: input_source.as_raw_fd(),
            sink: input_sink.as_raw_fd(),
        });
        config.channels.push(Channel {
            kind: 2,
            source: inner.as_raw_fd(),
            sink: outer.slave.as_raw_fd(),
            pty: true,
        });
        inherited.extend([inner, outer.slave, input_source, input_sink]);
        Some(outer.master)
    } else {
        None
    };
    let bytes = serde_json::to_vec(&config).map_err(io::Error::other)?;
    if bytes.len() > CONFIG_LIMIT {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut snapshot = File::from(rustix::fs::memfd_create(
        "dev-auth-output-relay",
        rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
    )?);
    snapshot.write_all(&bytes)?;
    snapshot.seek(SeekFrom::Start(0))?;
    rustix::fs::fcntl_add_seals(&snapshot, config_seals())?;
    let arguments = vec![
        "grant-output-relay".into(),
        snapshot.as_raw_fd().to_string().into(),
    ];
    inherited.push(snapshot.into());
    Ok(Prepared {
        streams,
        master: client_master,
        relay: Relay {
            arguments,
            inherited,
        },
        counters,
    })
}

fn nonblocking(fd: &OwnedFd) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(fd)?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK)?;
    Ok(())
}

#[doc(hidden)]
pub fn run_worker() -> i32 {
    if !nix::unistd::getuid().is_root()
        || !nix::unistd::geteuid().is_root()
        || nix::unistd::getgid().as_raw() != 0
        || nix::unistd::getegid().as_raw() != 0
    {
        return 4;
    }
    let mut arguments = std::env::args_os().skip(2);
    let Some(fd) = arguments
        .next()
        .and_then(|v| v.to_str().and_then(|s| s.parse::<i32>().ok()))
        .filter(|fd| *fd >= 3)
    else {
        return 2;
    };
    if arguments.next().is_some() {
        return 2;
    }
    match worker(fd) {
        Ok(()) => 0,
        Err(_) => 125,
    }
}

fn take_fd(fd: i32) -> io::Result<OwnedFd> {
    // SAFETY: validate existence before forming the sole child-side Rust owner.
    // All descriptors were retained by the trusted same-product parent across
    // exec. The sealed configuration rejects repeated integer ownership.
    if fd < 3 || unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) } < 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn worker(fd: i32) -> io::Result<()> {
    let mut snapshot = File::from(take_fd(fd)?);
    if !rustix::fs::fcntl_get_seals(&snapshot)?.contains(config_seals()) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut snapshot)
        .take((CONFIG_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > CONFIG_LIMIT {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let config: Configuration = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let mut used = BTreeSet::from([fd]);
    let mut kinds = BTreeSet::new();
    let mut all = vec![config.gate, config.kill, config.counters];
    all.extend(config.worker);
    for channel in &config.channels {
        if channel.kind > 2 || !kinds.insert(channel.kind) || channel.pty != (channel.kind == 2) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        all.extend([channel.source, channel.sink]);
    }
    if let Some(input) = &config.input {
        all.extend([input.source, input.sink]);
    }
    if config.schema != SCHEMA
        || config.limit == 0
        || config.limit > super::policy::MAX_PLAN_OUTPUT_BYTES
        || config.channels.is_empty()
        || config.channels.len() > 3
        || config.input.is_some() != kinds.contains(&2)
        || all.iter().any(|fd| *fd < 3 || !used.insert(*fd))
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let counters = Counters {
        mapping: Arc::new(Mapping::map(take_fd(config.counters)?, false)?),
        limit: config.limit,
    };
    // Before threads exist, ignore only this private helper's SIGPIPE so a
    // caller disconnect is published as transport failure and job-only stop.
    // SAFETY: changes this process's disposition, with no concurrent handlers.
    unsafe {
        nix::sys::signal::signal(
            nix::sys::signal::Signal::SIGPIPE,
            nix::sys::signal::SigHandler::SigIgn,
        )
    }
    .map_err(io::Error::from)?;
    let stop = Stop {
        gate: take_fd(config.gate)?,
        kill: File::from(take_fd(config.kill)?),
    };
    // Block workload-directed catchable signals only in this private transport
    // process. Its sink threads inherit the mask; forced cgroup SIGKILL remains
    // authoritative, while handled payload signals cannot destroy transport.
    // SAFETY: initialize and install this process thread's native mask before
    // any helper thread exists; no application-wide signal handler is changed.
    unsafe {
        let mut set: nix::libc::sigset_t = std::mem::zeroed();
        if nix::libc::sigfillset(&mut set) != 0
            || nix::libc::pthread_sigmask(nix::libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0
        {
            return Err(io::ErrorKind::Other.into());
        }
    }
    let worker = config.worker.map(take_fd).transpose()?;
    let result = relay(config.channels, config.input, &counters, worker);
    if result.is_err() {
        counters
            .mapping
            .frame()
            .failure
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .ok();
        // cgroup.kill normally terminates this helper as well. A failed stop is
        // sticky in the fixed frame and the coordinator must retry/join cleanup.
        if stop.stop().is_err() {
            counters.mapping.frame().failure.store(2, Ordering::Release);
        }
    }
    result
}

struct Stop {
    gate: OwnedFd,
    kill: File,
}
impl Stop {
    fn stop(&self) -> io::Result<()> {
        let gate = nix::unistd::write(&self.gate, &1_u64.to_ne_bytes())
            .map_err(io::Error::from)
            .and_then(|n| {
                if n == 8 {
                    Ok(())
                } else {
                    Err(io::ErrorKind::WriteZero.into())
                }
            });
        let kill = self.kill.write_at(b"1", 0).and_then(|n| {
            if n == 1 {
                Ok(())
            } else {
                Err(io::ErrorKind::WriteZero.into())
            }
        });
        gate.and(kill)
    }
}

struct QueueState {
    bytes: VecDeque<u8>,
    closed: bool,
}
struct Queue {
    state: Mutex<QueueState>,
    ready: Condvar,
}
impl Queue {
    fn new(limit: usize) -> Self {
        // At most three preallocated queues; actual queued payload across them
        // and writer buffers never exceeds limit. Capacity is <=3*limit.
        Self {
            state: Mutex::new(QueueState {
                bytes: VecDeque::with_capacity(limit),
                closed: false,
            }),
            ready: Condvar::new(),
        }
    }
    fn push(&self, bytes: &[u8]) -> io::Result<()> {
        let mut state = self.state.lock().map_err(|_| io::ErrorKind::Other)?;
        if state.closed || state.bytes.len() + bytes.len() > state.bytes.capacity() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        state.bytes.extend(bytes);
        self.ready.notify_one();
        Ok(())
    }
    fn close(&self) -> io::Result<()> {
        self.state.lock().map_err(|_| io::ErrorKind::Other)?.closed = true;
        self.ready.notify_one();
        Ok(())
    }
    fn pop(&self, target: &mut [u8]) -> io::Result<usize> {
        let mut state = self.state.lock().map_err(|_| io::ErrorKind::Other)?;
        while state.bytes.is_empty() && !state.closed {
            state = self.ready.wait(state).map_err(|_| io::ErrorKind::Other)?;
        }
        let count = target.len().min(state.bytes.len());
        for target in target.iter_mut().take(count) {
            *target = state.bytes.pop_front().ok_or(io::ErrorKind::InvalidData)?;
        }
        Ok(count)
    }
}

struct Reader {
    source: OwnedFd,
    kind: usize,
    pty: bool,
    eof: bool,
    queue: Arc<Queue>,
}

fn relay(
    channels: Vec<Channel>,
    input: Option<Input>,
    counters: &Counters,
    worker: Option<OwnedFd>,
) -> io::Result<()> {
    let mut readers = Vec::new();
    let mut writers = Vec::new();
    for channel in channels {
        let queue = Arc::new(Queue::new(counters.limit as usize));
        let sink = take_fd(channel.sink)?;
        let writer_queue = queue.clone();
        let counts = counters.clone();
        let kind = channel.kind;
        let writer = std::thread::Builder::new()
            .name("grant-output-sink".into())
            .spawn(move || {
                let result =
                    write_queue(sink, &writer_queue, &counts.mapping.frame().forwarded[kind]);
                if result.is_err() {
                    counts
                        .mapping
                        .frame()
                        .failure
                        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                        .ok();
                }
                result
            })?;
        writers.push(writer);
        readers.push(Reader {
            source: take_fd(channel.source)?,
            kind,
            pty: channel.pty,
            eof: false,
            queue,
        });
    }
    let mut input = input
        .map(|i| Ok::<_, io::Error>((take_fd(i.source)?, take_fd(i.sink)?)))
        .transpose()?;
    let mut input_buffer = VecDeque::with_capacity(BUFFER);
    let mut buffer = [0_u8; BUFFER];
    let mut meter = Meter {
        limit: counters.limit,
        observed: 0,
    };
    let mut last_window = None;
    let mut drain = DrainSettlement::default();
    while readers.iter().any(|reader| !reader.eof) {
        let ended = worker.as_ref().is_some_and(|fd| {
            let mut ready = [nix::poll::PollFd::new(
                fd.as_fd(),
                nix::poll::PollFlags::POLLIN,
            )];
            !matches!(
                nix::poll::poll(&mut ready, nix::poll::PollTimeout::ZERO),
                Ok(0)
            )
        });
        if drain.observe(ended, std::time::Instant::now()) {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if counters.failed() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let mut input_closed = false;
        if let Some((source, sink)) = &input {
            let window = terminal::window_size(source)?;
            if last_window != Some(window) {
                terminal::set_window_size(sink, window)?;
                last_window = Some(window);
            }
        }
        let mut descriptors = readers
            .iter()
            .filter(|reader| !reader.eof)
            .map(|reader| {
                nix::poll::PollFd::new(reader.source.as_fd(), nix::poll::PollFlags::POLLIN)
            })
            .collect::<Vec<_>>();
        if let Some((source, _)) = &input {
            if input_buffer.len() < BUFFER {
                descriptors.push(nix::poll::PollFd::new(
                    source.as_fd(),
                    nix::poll::PollFlags::POLLIN,
                ));
            }
        }
        nix::poll::poll(&mut descriptors, 20_u16).map_err(io::Error::from)?;
        drop(descriptors);
        for reader in readers.iter_mut().filter(|reader| !reader.eof) {
            let request = meter.read_capacity(BUFFER);
            match nix::unistd::read(&reader.source, &mut buffer[..request]) {
                Ok(0) => {
                    reader.eof = true;
                    reader.queue.close()?;
                }
                Ok(count) => {
                    let accepted = meter.record(count)?;
                    counters.mapping.frame().observed[reader.kind]
                        .fetch_add(count as u64, Ordering::Release);
                    if accepted > 0 {
                        reader.queue.push(&buffer[..accepted])?;
                    }
                    if accepted < count {
                        counters
                            .mapping
                            .frame()
                            .exceeded
                            .store(1, Ordering::Release);
                        return Err(io::ErrorKind::FileTooLarge.into());
                    }
                }
                Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => {}
                Err(nix::errno::Errno::EIO) if reader.pty => {
                    reader.eof = true;
                    reader.queue.close()?;
                }
                Err(error) => return Err(io::Error::from(error)),
            }
        }
        // Transparent PTY input has one fixed-size queue and is not output.
        // Inner master and outer slave are fresh owned nonblocking OFDs.
        if let Some((source, sink)) = &input {
            let available = BUFFER - input_buffer.len();
            if available > 0 {
                match nix::unistd::read(source, &mut buffer[..available]) {
                    Ok(0) | Err(nix::errno::Errno::EIO) => {
                        input_closed = true;
                    }
                    Ok(count) => input_buffer.extend(&buffer[..count]),
                    Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => {}
                    Err(error) => return Err(io::Error::from(error)),
                }
            }
            if !input_closed && !input_buffer.is_empty() {
                let bytes = input_buffer.make_contiguous();
                match nix::unistd::write(sink, bytes) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(count) => {
                        input_buffer.drain(..count);
                    }
                    Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => {}
                    Err(nix::errno::Errno::EIO) => {
                        input_closed = true;
                    }
                    Err(error) => return Err(io::Error::from(error)),
                }
            }
        }
        if input_closed {
            input = None;
            input_buffer.clear();
        }
    }
    drop(input); // Do not await caller input EOF after every output terminalizes.
                 // EOF also starts the bounded drain if the worker is still settling. Do not
                 // block in JoinHandle::join until all bounded sink writers have finished.
    while writers.iter().any(|writer| !writer.is_finished()) {
        if counters.failed() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if drain.observe(true, std::time::Instant::now()) {
            return Err(io::ErrorKind::TimedOut.into());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    for writer in writers {
        writer.join().map_err(|_| io::ErrorKind::Other)??;
    }
    counters
        .mapping
        .frame()
        .complete
        .store(1, Ordering::Release);
    Ok(())
}

#[derive(Default)]
pub(super) struct DrainSettlement {
    deadline: Option<std::time::Instant>,
}
impl DrainSettlement {
    pub(super) fn observe(&mut self, worker_ended: bool, now: std::time::Instant) -> bool {
        if worker_ended {
            self.deadline
                .get_or_insert(now + std::time::Duration::from_secs(5));
        }
        self.deadline.is_some_and(|deadline| now >= deadline)
    }
}

fn write_queue(sink: OwnedFd, queue: &Queue, forwarded: &AtomicU64) -> io::Result<()> {
    let mut buffer = [0_u8; BUFFER];
    loop {
        let count = queue.pop(&mut buffer)?;
        if count == 0 {
            return Ok(());
        }
        let mut offset = 0;
        while offset < count {
            match nix::unistd::write(&sink, &buffer[offset..count]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(written) => {
                    forwarded.fetch_add(written as u64, Ordering::Release);
                    offset += written;
                }
                Err(nix::errno::Errno::EINTR) => {}
                Err(nix::errno::Errno::EAGAIN) => {
                    let mut descriptors = [nix::poll::PollFd::new(
                        sink.as_fd(),
                        nix::poll::PollFlags::POLLOUT,
                    )];
                    nix::poll::poll(&mut descriptors, 20_u16).map_err(io::Error::from)?;
                }
                Err(error) => return Err(io::Error::from(error)),
            }
        }
    }
}

struct Meter {
    limit: u64,
    observed: u64,
}
impl Meter {
    fn read_capacity(&self, buffer: usize) -> usize {
        ((self.limit - self.observed) + 1).min(buffer as u64) as usize
    }
    fn record(&mut self, read: usize) -> io::Result<usize> {
        if read == 0 || read > self.read_capacity(BUFFER) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let accepted = (self.limit - self.observed).min(read as u64) as usize;
        self.observed += read as u64;
        Ok(accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_worker_exit_starts_one_bounded_drain_without_refresh() {
        let now = std::time::Instant::now();
        let mut drain = DrainSettlement::default();
        assert!(!drain.observe(false, now + std::time::Duration::from_secs(30)));
        assert!(!drain.observe(true, now + std::time::Duration::from_secs(30)));
        assert!(!drain.observe(true, now + std::time::Duration::from_secs(34)));
        assert!(drain.observe(true, now + std::time::Duration::from_secs(35)));
        assert!(drain.observe(false, now + std::time::Duration::from_secs(36)));
    }
    use std::os::fd::IntoRawFd;
    #[test]
    fn aggregate_budget_reads_only_remaining_and_one_detector_byte() {
        let mut meter = Meter {
            limit: 9,
            observed: 0,
        };
        assert_eq!(meter.read_capacity(BUFFER), 10);
        assert_eq!(meter.record(4).unwrap(), 4);
        assert_eq!(meter.read_capacity(BUFFER), 6);
        assert_eq!(meter.record(6).unwrap(), 5);
        assert_eq!(meter.observed, 10);
    }
    #[test]
    fn malicious_unbounded_read_count_is_rejected_before_accounting() {
        let mut meter = Meter {
            limit: 9,
            observed: 0,
        };
        assert!(meter.record(usize::MAX).is_err());
        assert_eq!(meter.observed, 0);
    }
    #[test]
    fn exact_limit_requires_eof_or_the_one_byte_probe() {
        let mut meter = Meter {
            limit: 9,
            observed: 0,
        };
        assert_eq!(meter.record(9).unwrap(), 9);
        assert_eq!(meter.read_capacity(BUFFER), 1);
        assert_eq!(meter.record(1).unwrap(), 0);
    }

    #[test]
    fn separate_streams_drain_exactly_before_complete_and_share_one_cap() {
        let counters = Counters::new(9).unwrap();
        let mut channels = Vec::new();
        let mut sinks = Vec::new();
        for (kind, bytes) in [(0, b"stdout".as_slice()), (1, b"err".as_slice())] {
            let (source, writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
            nonblocking(&source).unwrap();
            nix::unistd::write(&writer, bytes).unwrap();
            drop(writer);
            let sink =
                rustix::fs::memfd_create("output-test", rustix::fs::MemfdFlags::CLOEXEC).unwrap();
            sinks.push(File::from(sink.as_fd().try_clone_to_owned().unwrap()));
            channels.push(Channel {
                kind,
                source: source.into_raw_fd(),
                sink: sink.into_raw_fd(),
                pty: false,
            });
        }
        relay(channels, None, &counters, None).unwrap();
        let output = counters.observation(true).unwrap();
        assert!(output.complete);
        assert!(!output.limit_exceeded);
        assert_eq!(output.observed.stdout, 6);
        assert_eq!(output.observed.stderr, 3);
        assert_eq!(output.forwarded.stdout, 6);
        assert_eq!(output.forwarded.stderr, 3);
        let mut bytes = [0; 6];
        assert_eq!(sinks[0].read_at(&mut bytes, 0).unwrap(), 6);
        assert_eq!(&bytes, b"stdout");
        assert_eq!(sinks[1].read_at(&mut bytes, 0).unwrap(), 3);
        assert_eq!(&bytes[..3], b"err");
    }

    #[test]
    fn blocked_sink_does_not_block_budget_detector_or_grow_the_payload_queue() {
        let (source, sink) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
        nonblocking(&source).unwrap();
        nonblocking(&sink).unwrap();
        let mut filled = 0;
        loop {
            match nix::unistd::write(&sink, &[0; BUFFER]) {
                Ok(count) => filled += count,
                Err(nix::errno::Errno::EAGAIN) => break,
                result => panic!("unexpected fill result: {result:?}"),
            }
        }
        let flags = rustix::fs::fcntl_getfl(&sink).unwrap();
        rustix::fs::fcntl_setfl(&sink, flags & !rustix::fs::OFlags::NONBLOCK).unwrap();
        let queue = Arc::new(Queue::new(32));
        let forwarded = Arc::new(AtomicU64::new(0));
        let writer_queue = queue.clone();
        let writer_counts = forwarded.clone();
        let (finished, join) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let result = write_queue(sink, &writer_queue, &writer_counts);
            finished.send(result).unwrap();
        });
        let mut meter = Meter {
            limit: 32,
            observed: 0,
        };
        assert_eq!(meter.record(32).unwrap(), 32);
        queue.push(&[1; 32]).unwrap();
        assert_eq!(meter.read_capacity(BUFFER), 1);
        assert_eq!(meter.record(1).unwrap(), 0);
        assert_eq!(forwarded.load(Ordering::Acquire), 0);
        assert!(queue.state.lock().unwrap().bytes.len() <= 32);
        queue.close().unwrap();
        // Release the isolated test sink, then require the sole writer join.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut drained = 0;
        let mut bytes = [0; BUFFER];
        while drained < filled + 32 {
            match nix::unistd::read(&source, &mut bytes) {
                Ok(count) if count > 0 => drained += count,
                Err(nix::errno::Errno::EAGAIN) => {
                    assert!(std::time::Instant::now() < deadline);
                    std::thread::yield_now();
                }
                result => panic!("unexpected drain result: {result:?}"),
            }
        }
        join.recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
            .unwrap();
        writer.join().unwrap();
        assert_eq!(forwarded.load(Ordering::Acquire), 32);
    }

    #[test]
    fn sink_disconnect_is_a_transport_failure_without_a_numeric_success() {
        let (source, sink) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
        drop(source);
        let queue = Queue::new(4);
        queue.push(b"data").unwrap();
        queue.close().unwrap();
        let writer = std::thread::spawn(move || {
            // This test thread exclusively owns its signal mask. Blocking PIPE
            // tests EPIPE without altering parallel tests' process disposition.
            let mut signals = nix::sys::signal::SigSet::empty();
            signals.add(nix::sys::signal::Signal::SIGPIPE);
            nix::sys::signal::pthread_sigmask(
                nix::sys::signal::SigmaskHow::SIG_BLOCK,
                Some(&signals),
                None,
            )
            .unwrap();
            write_queue(sink, &queue, &AtomicU64::new(0))
        });
        assert_eq!(
            writer.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn preparation_keeps_original_caller_sink_flags_and_uses_fixed_sealed_counters() {
        let (read, sink) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
        let original = sink.as_fd().try_clone_to_owned().unwrap();
        let before = rustix::fs::fcntl_getfl(&original).unwrap();
        let null: OwnedFd = File::options()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap()
            .into();
        let gate = nix::sys::eventfd::EventFd::from_value_and_flags(
            0,
            nix::sys::eventfd::EfdFlags::EFD_CLOEXEC,
        )
        .unwrap();
        let kill =
            rustix::fs::memfd_create("output-stop-test", rustix::fs::MemfdFlags::CLOEXEC).unwrap();
        let prepared = prepare(
            32,
            [null.as_fd().try_clone_to_owned().unwrap(), sink, null],
            None,
            (gate.as_fd().try_clone_to_owned().unwrap(), kill),
        )
        .unwrap();
        assert_eq!(rustix::fs::fcntl_getfl(&original).unwrap(), before);
        assert_eq!(
            rustix::fs::fstat(&prepared.counters.mapping.descriptor)
                .unwrap()
                .st_size,
            FRAME_SIZE as i64
        );
        assert!(
            rustix::fs::fcntl_get_seals(&prepared.counters.mapping.descriptor)
                .unwrap()
                .contains(length_seals())
        );
        assert!(rustix::fs::ftruncate(
            &prepared.counters.mapping.descriptor,
            (FRAME_SIZE + 1) as u64
        )
        .is_err());
        drop((prepared, read));
    }

    #[test]
    #[ignore = "explicit root-only child mode of the isolated output acceptance fixture"]
    fn native_output_relay_child() {
        assert!(nix::unistd::getuid().is_root());
        assert!(nix::unistd::geteuid().is_root());
        let descriptor = std::env::var("DEV_AUTH_GRANT_OUTPUT_FIXTURE_FD")
            .unwrap()
            .parse::<i32>()
            .unwrap();
        worker(descriptor).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly owned root transient cgroup-v2 acceptance service; never auto-run"]
    fn native_cap_with_blocked_sink_kills_only_its_job_and_preserves_a_sibling() {
        use dev_tools_privilege_session::linux::{boot_time, ExecutionBoundary};
        use std::os::unix::fs::MetadataExt;
        use std::time::{Duration, Instant};
        assert!(nix::unistd::getuid().is_root());
        assert!(nix::unistd::geteuid().is_root());
        let own = File::open("/proc/self/ns/user")
            .unwrap()
            .metadata()
            .unwrap();
        let init = File::open("/proc/1/ns/user").unwrap().metadata().unwrap();
        assert_eq!((own.dev(), own.ino()), (init.dev(), init.ino()));
        let membership = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let path = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .unwrap();
        let suffix = path
            .strip_prefix("/system.slice/dev-tools-privilege-accept-")
            .and_then(|value| value.strip_suffix(".service"))
            .expect("explicit isolated acceptance service required");
        assert_eq!(suffix.len(), 32);
        assert!(suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        let parent = File::open(format!("/sys/fs/cgroup{path}")).unwrap();
        let deadline = boot_time().unwrap() + Duration::from_secs(30);
        let name = format!("output-{}", std::process::id());
        let mut grant = ExecutionBoundary::create(&parent, &name, deadline).unwrap();
        let mut job = ExecutionBoundary::create(grant.directory(), "capped-job", deadline).unwrap();
        let mut sibling =
            ExecutionBoundary::create(grant.directory(), "sibling-job", deadline).unwrap();
        let null = || -> OwnedFd {
            File::options()
                .read(true)
                .write(true)
                .open("/dev/null")
                .unwrap()
                .into()
        };
        let context = |inherited_files| NativeContext {
            working_directory: File::open("/").unwrap(),
            mount_namespace: None,
            uid: 0,
            effective_uid: 0,
            gid: 0,
            supplementary_groups: vec![],
            user_session: None,
            controlling_terminal: false,
            inherited_files,
        };
        let mut sentinel = sibling
            .permit(vec![grant.gate().unwrap()])
            .unwrap()
            .spawn_held(
                File::open("/usr/bin/sleep").unwrap(),
                std::ffi::OsStr::new("sleep"),
                &["30".into()],
                &[],
                context(vec![]),
                [null(), null(), null()],
            )
            .unwrap();
        let (sink_read, sink_write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
        nonblocking(&sink_write).unwrap();
        while let Ok(count) = nix::unistd::write(&sink_write, &[0; BUFFER]) {
            assert!(count > 0);
        }
        let flags = rustix::fs::fcntl_getfl(&sink_write).unwrap();
        rustix::fs::fcntl_setfl(&sink_write, flags & !rustix::fs::OFlags::NONBLOCK).unwrap();
        let prepared = prepare(
            32,
            [null(), sink_write, null()],
            None,
            job.stop_handles().unwrap(),
        )
        .unwrap();
        let counts = prepared.counters.clone();
        let image = File::open(std::env::current_exe().unwrap()).unwrap();
        let fd = prepared.relay.arguments[1].clone();
        let mut relay = job
            .permit(vec![grant.gate().unwrap()])
            .unwrap()
            .spawn_held(
                image,
                std::ffi::OsStr::new("output-test"),
                &[
                    "--ignored".into(),
                    "--exact".into(),
                    "privilege::grants::output::tests::native_output_relay_child".into(),
                    "--nocapture".into(),
                ],
                &[("DEV_AUTH_GRANT_OUTPUT_FIXTURE_FD".into(), fd)],
                context(prepared.relay.inherited),
                [null(), null(), null()],
            )
            .unwrap();
        let mut producer = job
            .permit(vec![grant.gate().unwrap()])
            .unwrap()
            .spawn_held(
                File::open("/usr/bin/printf").unwrap(),
                std::ffi::OsStr::new("printf"),
                &["x".repeat(64).into()],
                &[],
                context(vec![]),
                prepared.streams,
            )
            .unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        let mut relay_done = false;
        let mut producer_done = false;
        while !relay_done || !producer_done {
            relay_done |= relay.try_wait().unwrap().is_some();
            producer_done |= producer.try_wait().unwrap().is_some();
            assert!(
                Instant::now() < until,
                "both owned children must terminalize despite the blocked sink"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // Both terminal try_wait observations above have already reaped these
        // children; wait confirms their cached statuses without another wait.
        relay.wait().unwrap();
        producer.wait().unwrap();
        let output = counts.observation(true).unwrap();
        assert!(output.limit_exceeded);
        assert_eq!(output.observed.stdout, 33);
        assert!(output.forwarded.stdout <= 32);
        assert!(!output.complete);
        assert!(sentinel.try_wait().unwrap().is_none());
        assert!(!grant.is_empty().unwrap());
        assert!(job.is_empty().unwrap());
        job.stop().unwrap();
        job.remove().unwrap();
        sibling.stop().unwrap();
        sentinel.wait().unwrap();
        sibling.remove().unwrap();
        grant.stop().unwrap();
        grant.remove().unwrap();
        drop(sink_read);
    }
}
