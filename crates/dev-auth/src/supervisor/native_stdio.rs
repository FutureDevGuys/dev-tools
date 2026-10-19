//! Nonterminal standard streams cross the authenticated service-peer socket,
//! never PID1. This frame does not grant admission or open a caller-selected path.
use anyhow::{bail, Context, Result};
use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
};
use std::fs::File;
use std::io::{IoSlice, IoSliceMut, IsTerminal};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const FRAME_MAGIC: &[u8; 5] = b"DAIO1";
const CAPTURED: u8 = 8;
const HANDOFF_BUDGET: Duration = Duration::from_secs(10);

pub(crate) enum NativeStdio {
    Terminal,
    Captured([Option<File>; 3]),
}

impl NativeStdio {
    /// Hold only the inherited standard descriptors, outside reserved slots.
    /// Closed channels stay closed; no path, environment hint or numeric caller
    /// argument can select another descriptor or acquire new open authority.
    pub(crate) fn capture() -> Result<Self> {
        let mut streams = [None, None, None];
        for (slot, stream) in streams.iter_mut().enumerate() {
            // SAFETY: fcntl accepts any integer, including a closed standard
            // slot. Success atomically allocates a distinct owned CLOEXEC FD.
            let fd = unsafe { nix::libc::fcntl(slot as i32, nix::libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(nix::libc::EBADF) {
                    return Err(error).context("retain native workload standard stream");
                }
            } else {
                // SAFETY: that successful duplication allocated this FD, and
                // File becomes its only owner, closing it on every error path.
                *stream = Some(unsafe { File::from_raw_fd(fd) });
            }
        }
        if streams
            .iter()
            .all(|stream| stream.as_ref().is_some_and(File::is_terminal))
        {
            Ok(Self::Terminal)
        } else {
            Ok(Self::Captured(streams))
        }
    }

    pub(crate) fn systemd_arguments(&self) -> &'static [&'static str] {
        match self {
            Self::Terminal => &["--pipe", "--pty"],
            Self::Captured(_) => &[
                "--property=StandardInput=null",
                "--property=StandardOutput=null",
                "--property=StandardError=null",
            ],
        }
    }

    /// The dispatcher must authenticate the receiving UID/GID, retained peer
    /// identity and exact workload cgroup before calling this function.
    pub(crate) fn send(&self, stream: &UnixStream) -> Result<()> {
        let mut frame = [0; 6];
        frame[..5].copy_from_slice(FRAME_MAGIC);
        let mut descriptors = Vec::with_capacity(3);
        if let Self::Captured(streams) = self {
            frame[5] = CAPTURED;
            for (slot, source) in streams.iter().enumerate() {
                if let Some(source) = source {
                    frame[5] |= 1 << slot;
                    descriptors.push(source.as_fd());
                }
            }
        }
        let mut storage = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
        let mut ancillary = SendAncillaryBuffer::new(&mut storage);
        if !descriptors.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors))
        {
            bail!("native standard stream handoff exceeds its descriptor bound");
        }
        stream.set_write_timeout(Some(HANDOFF_BUDGET))?;
        let count = sendmsg(
            stream,
            &[IoSlice::new(&frame)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .context("send authenticated native standard streams")?;
        // Never resend rights after a partial send. The failed launch owns the
        // peer and service cleanup; the receiver cannot activate a partial frame.
        if count != frame.len() {
            bail!("native standard stream handoff was incomplete");
        }
        Ok(())
    }

    /// The service must authenticate the root dispatcher before receiving.
    /// Kernel-delivered rights have CLOEXEC and RAII ownership even on malformed
    /// frames, excess rights, EOF, timeout and ancillary truncation.
    pub(crate) fn receive(stream: &mut UnixStream) -> Result<Self> {
        Self::receive_before(stream, Instant::now() + HANDOFF_BUDGET)
    }

    fn receive_before(stream: &mut UnixStream, deadline: Instant) -> Result<Self> {
        let mut frame = [0; 6];
        let mut offset = 0;
        let mut descriptors = Vec::with_capacity(3);
        while offset < frame.len() {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .context("native standard stream handoff deadline expired")?;
            stream.set_read_timeout(Some(remaining))?;
            let mut storage = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
            let mut ancillary = RecvAncillaryBuffer::new(&mut storage);
            let received = match recvmsg(
                &*stream,
                &mut [IoSliceMut::new(&mut frame[offset..])],
                &mut ancillary,
                RecvFlags::CMSG_CLOEXEC,
            ) {
                Err(rustix::io::Errno::INTR) => continue,
                result => result.context("receive authenticated native standard streams")?,
            };
            if received.bytes == 0
                || received
                    .flags
                    .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
            {
                bail!("native standard stream handoff is truncated");
            }
            for message in ancillary.drain() {
                let RecvAncillaryMessage::ScmRights(rights) = message else {
                    bail!("native standard stream handoff has unexpected ancillary data");
                };
                for descriptor in rights {
                    if descriptors.len() == 3 {
                        bail!("native standard stream handoff has excess descriptors");
                    }
                    // Normalize outside 0..2 before mapping, including when a
                    // service inherited a closed channel. Preserve the same OFD.
                    let held = rustix::io::fcntl_dupfd_cloexec(&descriptor, 3)
                        .context("retain received native standard stream")?;
                    descriptors.push(File::from(held));
                }
            }
            offset += received.bytes;
        }
        let selection = frame[5];
        if &frame[..5] != FRAME_MAGIC
            || selection & !15 != 0
            || (selection != 0 && selection & CAPTURED == 0)
            || descriptors.len() != (selection & 7).count_ones() as usize
        {
            bail!("native standard stream frame and descriptor roles differ");
        }
        if selection == 0 {
            return Ok(Self::Terminal);
        }
        let mut descriptors = descriptors.into_iter();
        Ok(Self::Captured(std::array::from_fn(|slot| {
            if selection & (1 << slot) != 0 {
                descriptors.next()
            } else {
                None
            }
        })))
    }

    /// Replace only 0..2, before creating workload/credential workers.
    ///
    /// # Safety
    /// The caller must exclusively own process-wide standard stream replacement:
    /// no other thread or retained Rust owner may concurrently use or close 0..2.
    /// A failed partial replacement must terminate this fresh service without
    /// executing a payload or activating credentials. All sources are owned,
    /// CLOEXEC descriptors above 2; no source can alias a later destination slot.
    pub(crate) unsafe fn install(self) -> Result<()> {
        let Self::Captured(streams) = self else {
            return Ok(());
        };
        for (slot, source) in streams.iter().enumerate() {
            let result = if let Some(source) = source {
                // SAFETY: the caller provides exclusive stdio replacement, the
                // owned source is live and above 2, and dup2 clears CLOEXEC on
                // the distinct destination without changing the shared OFD.
                unsafe { nix::libc::dup2(source.as_raw_fd(), slot as i32) }
            } else {
                // SAFETY: only the exclusively owned standard slot is closed.
                unsafe { nix::libc::close(slot as i32) }
            };
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if source.is_some() || error.raw_os_error() != Some(nix::libc::EBADF) {
                    return Err(error).context("install authenticated native standard streams");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};

    fn source() -> File {
        let (source, _) = UnixStream::pair().unwrap();
        File::from(std::os::fd::OwnedFd::from(source))
    }

    fn open_copies(source: &File) -> usize {
        let selected = source.metadata().unwrap();
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| std::fs::metadata(entry.path()).ok())
            .filter(|metadata| metadata.dev() == selected.dev() && metadata.ino() == selected.ino())
            .count()
    }

    fn raw_frame(stream: &UnixStream, bytes: &[u8], source: &File, count: usize) {
        let rights = vec![source.as_fd(); count];
        let mut storage = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(128))];
        let mut ancillary = SendAncillaryBuffer::new(&mut storage);
        if count != 0 {
            assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights)));
        }
        assert_eq!(
            sendmsg(
                stream,
                &[IoSlice::new(bytes)],
                &mut ancillary,
                SendFlags::NOSIGNAL
            )
            .unwrap(),
            bytes.len()
        );
    }

    #[test]
    fn captured_streams_never_delegate_caller_fds_through_pid1() {
        let streams = NativeStdio::Captured(std::array::from_fn(|_| {
            Some(File::open("/dev/null").unwrap())
        }));
        let args = streams.systemd_arguments();
        assert!(!args.contains(&"--pipe"));
        assert!(!args.contains(&"--pty"));
        for property in [
            "--property=StandardInput=null",
            "--property=StandardOutput=null",
            "--property=StandardError=null",
        ] {
            assert!(args.contains(&property));
        }
    }

    #[test]
    fn terminal_streams_keep_the_existing_native_pty_route() {
        assert_eq!(
            NativeStdio::Terminal.systemd_arguments(),
            ["--pipe", "--pty"]
        );
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        NativeStdio::Terminal.send(&sender).unwrap();
        assert!(matches!(
            NativeStdio::receive(&mut receiver).unwrap(),
            NativeStdio::Terminal
        ));
    }

    #[test]
    fn received_streams_retain_exact_identity_cloexec_and_owned_lifetime() {
        let source = source();
        let metadata = source.metadata().unwrap();
        let baseline = open_copies(&source);
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        raw_frame(&sender, b"DAIO1\x0f", &source, 3);
        let received = NativeStdio::receive(&mut receiver).unwrap();
        let NativeStdio::Captured(streams) = &received else {
            panic!("captured frame expected");
        };
        for stream in streams.iter().flatten() {
            let actual = stream.metadata().unwrap();
            assert_eq!(
                (actual.dev(), actual.ino()),
                (metadata.dev(), metadata.ino())
            );
            assert!(stream.as_raw_fd() >= 3);
            assert!(rustix::io::fcntl_getfd(stream)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC));
        }
        assert_eq!(open_copies(&source), baseline + 3);
        drop(received);
        assert_eq!(open_copies(&source), baseline);
    }

    #[test]
    fn handed_off_regular_streams_keep_the_original_open_file_offset() {
        use std::io::{Seek, SeekFrom};
        let mut source = File::from(
            rustix::fs::memfd_create("dev-auth-stdio-offset", rustix::fs::MemfdFlags::CLOEXEC)
                .unwrap(),
        );
        source.write_all(b"abcdef").unwrap();
        source.seek(SeekFrom::Start(0)).unwrap();
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        raw_frame(&sender, b"DAIO1\x09", &source, 1);
        let NativeStdio::Captured([Some(mut received), None, None]) =
            NativeStdio::receive(&mut receiver).unwrap()
        else {
            panic!("stdin-only frame expected");
        };
        let mut bytes = [0; 3];
        source.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"abc");
        received.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"def");
        assert_eq!(source.stream_position().unwrap(), 6);
    }

    #[test]
    fn fragmented_stream_frame_preserves_roles_and_owns_every_right() {
        let source = source();
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_all(b"D").unwrap();
        raw_frame(&sender, b"AIO1\x0a", &source, 1);
        let NativeStdio::Captured(streams) = NativeStdio::receive(&mut receiver).unwrap() else {
            panic!("captured frame expected");
        };
        assert!(streams[0].is_none());
        assert!(streams[1].is_some());
        assert!(streams[2].is_none());
    }

    #[test]
    fn malformed_missing_extra_and_truncated_rights_fail_without_descriptor_leaks() {
        for (frame, count) in [
            (&b"DASF1\x0f"[..], 3), // Old private protocol is never reinterpreted.
            (&b"DAIO1\xff"[..], 3),
            (&b"DAIO1\x07"[..], 3),
            (&b"DAIO1\x00"[..], 1),
            (&b"DAIO1\x0f"[..], 2),
            (&b"DAIO1\x0f"[..], 4),
            (&b"DAIO1\x0f"[..], 128),
            (&b"DAIO1"[..], 3),
        ] {
            let source = source();
            let baseline = open_copies(&source);
            let (sender, mut receiver) = UnixStream::pair().unwrap();
            raw_frame(&sender, frame, &source, count);
            sender.shutdown(Shutdown::Write).unwrap();
            assert!(NativeStdio::receive(&mut receiver).is_err());
            assert_eq!(
                open_copies(&source),
                baseline,
                "rights leaked after rejected frame"
            );
        }
    }

    #[test]
    fn an_expired_handoff_cannot_wait_or_change_process_streams() {
        let (_sender, mut receiver) = UnixStream::pair().unwrap();
        assert!(NativeStdio::receive_before(&mut receiver, Instant::now()).is_err());
    }

    #[test]
    fn a_closed_receiver_returns_error_without_sigpipe() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        drop(receiver);
        assert!(NativeStdio::Terminal.send(&sender).is_err());
    }

    struct OwnedTestChild(Child);

    impl OwnedTestChild {
        fn finish(&mut self) {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = self.0.try_wait().unwrap() {
                    assert!(status.success(), "stdio child failed: {status}");
                    return;
                }
                if Instant::now() >= deadline {
                    self.0.kill().unwrap();
                    self.0.wait().unwrap();
                    panic!("stdio child exceeded its fixed deadline");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    impl Drop for OwnedTestChild {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    #[test]
    fn real_terminal_and_mixed_streams_select_the_correct_transport() {
        const CHILD_MODE: &str = "DEV_AUTH_TEST_NATIVE_STDIO_TTY";
        if let Some(mode) = std::env::var_os(CHILD_MODE) {
            let streams = NativeStdio::capture().unwrap();
            if mode == "terminal" {
                assert!(matches!(streams, NativeStdio::Terminal));
            } else {
                let NativeStdio::Captured([Some(input), Some(output), Some(errors)]) = streams
                else {
                    panic!("mixed capture expected");
                };
                assert!(input.is_terminal());
                assert!(!output.is_terminal());
                assert!(!errors.is_terminal());
            }
            std::process::exit(0);
        }
        for mode in ["terminal", "mixed"] {
            let (mut master, mut slave) = (-1, -1);
            // SAFETY: openpty receives writable integer outputs and null optional
            // buffers/settings. Success returns two distinct owned descriptors.
            let result = unsafe {
                nix::libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            };
            assert_eq!(result, 0);
            // SAFETY: successful openpty allocated both FDs; each File owns one.
            let (_master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
            let mut command = Command::new(std::env::current_exe().unwrap());
            let full_name = concat!(
                module_path!(),
                "::real_terminal_and_mixed_streams_select_the_correct_transport"
            );
            command
                .args([
                    "--exact",
                    full_name.split_once("::").unwrap().1,
                    "--nocapture",
                ])
                .env(CHILD_MODE, mode)
                .stdin(Stdio::from(slave.try_clone().unwrap()));
            if mode == "terminal" {
                command
                    .stdout(Stdio::from(slave.try_clone().unwrap()))
                    .stderr(Stdio::from(slave));
            } else {
                command.stdout(Stdio::null()).stderr(Stdio::null());
            }
            OwnedTestChild(command.spawn().unwrap()).finish();
        }
    }

    #[test]
    fn binary_and_closed_streams_survive_actual_child_installation() {
        const CHILD_MODE: &str = "DEV_AUTH_TEST_NATIVE_STDIO_MODE";
        const SOCKET_SLOT: i32 = 198;
        const DATA: &[u8] = b"stdin\0\xff\nseparate channels";
        if let Some(mode) = std::env::var_os(CHILD_MODE) {
            // SAFETY: the parent created this single inherited descriptor in
            // the fresh test process; it has no other Rust owner after exec.
            let mut socket = unsafe { UnixStream::from_raw_fd(SOCKET_SLOT) };
            let streams = NativeStdio::receive(&mut socket).unwrap();
            // SAFETY: this isolated test process exclusively owns its initially
            // null standard streams, and exits instead of returning to libtest.
            unsafe {
                streams.install().unwrap();
            }
            if mode == "closed" {
                // SAFETY: fcntl accepts the possibly closed integer slot.
                assert_eq!(unsafe { nix::libc::fcntl(0, nix::libc::F_GETFD) }, -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(nix::libc::EBADF)
                );
                assert!(matches!(
                    NativeStdio::capture().unwrap(),
                    NativeStdio::Captured([None, Some(_), Some(_)])
                ));
            } else {
                let mut input = Vec::new();
                std::io::stdin().read_to_end(&mut input).unwrap();
                assert_eq!(input, DATA);
            }
            std::io::stdout().write_all(DATA).unwrap();
            std::io::stderr()
                .write_all(&DATA.iter().rev().copied().collect::<Vec<_>>())
                .unwrap();
            std::process::exit(0);
        }

        for mode in ["binary", "closed"] {
            let (mut input, stdin) = UnixStream::pair().unwrap();
            input.write_all(DATA).unwrap();
            input.shutdown(Shutdown::Write).unwrap();
            let (mut stdout, output) = UnixStream::pair().unwrap();
            let (mut stderr, errors) = UnixStream::pair().unwrap();
            stdout
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stderr
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let streams = NativeStdio::Captured([
                (mode != "closed").then(|| File::from(std::os::fd::OwnedFd::from(stdin))),
                Some(File::from(std::os::fd::OwnedFd::from(output))),
                Some(File::from(std::os::fd::OwnedFd::from(errors))),
            ]);
            let (sender, receiver) = UnixStream::pair().unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            let full_name = concat!(
                module_path!(),
                "::binary_and_closed_streams_survive_actual_child_installation"
            );
            command
                .args([
                    "--exact",
                    full_name.split_once("::").unwrap().1,
                    "--nocapture",
                ])
                .env(CHILD_MODE, mode)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            // SAFETY: this child-only callback owns receiver, and maps one live
            // socket onto a reserved test slot before exec using only fcntl/dup2.
            unsafe {
                command.pre_exec(move || {
                    if nix::libc::dup2(receiver.as_raw_fd(), SOCKET_SLOT) < 0
                        || nix::libc::fcntl(SOCKET_SLOT, nix::libc::F_SETFD, 0) < 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut child = OwnedTestChild(command.spawn().unwrap());
            streams.send(&sender).unwrap();
            drop(streams);
            let mut output = vec![0; DATA.len()];
            stdout.read_exact(&mut output).unwrap();
            assert_eq!(output, DATA);
            stderr.read_exact(&mut output).unwrap();
            assert_eq!(output, DATA.iter().rev().copied().collect::<Vec<_>>());
            child.finish();
        }
    }
}
