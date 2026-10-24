use super::Failure;
use dev_tools_privilege_session::linux::terminal::{self, Pty, RawTerminal};
use nix::poll::{poll, PollFd, PollFlags};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::socket::{self, MsgFlags, SockFlag, SockType};
use std::collections::VecDeque;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::time::Duration;

pub(super) const START_SCHEMA: &str = "dev-auth-administrator-grant-execution-start-v1";

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Started {
    pub schema: String,
    pub hard_deadline_milliseconds: u64,
    pub terminal: bool,
}

pub(super) fn event_pair() -> Result<(OwnedFd, OwnedFd), Failure> {
    socket::socketpair(
        socket::AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .map_err(|_| Failure::NativeUnavailable)
}

pub(super) fn prepare_streams(
    mut streams: Vec<OwnedFd>,
    terminal: bool,
) -> Result<([OwnedFd; 3], OwnedFd, Option<OwnedFd>), Failure> {
    if streams.len() != 4 {
        return Err(Failure::InvalidRequest);
    }
    let events = streams.pop().ok_or(Failure::InvalidRequest)?;
    if socket::getsockopt(&events, socket::sockopt::SockType)
        .map_err(|_| Failure::InvalidRequest)?
        != SockType::SeqPacket
        || socket::getpeername::<socket::UnixAddr>(events.as_raw_fd()).is_err()
    {
        return Err(Failure::InvalidRequest);
    }
    let mut master = None;
    if terminal {
        let pty = Pty::from_terminal(&streams[0]).map_err(|_| Failure::NativeUnavailable)?;
        let source = rustix::fs::fstat(&streams[0]).map_err(|_| Failure::NativeUnavailable)?;
        for stream in &mut streams {
            let current = rustix::fs::fstat(&*stream).map_err(|_| Failure::NativeUnavailable)?;
            if current.st_dev == source.st_dev
                && current.st_ino == source.st_ino
                && current.st_rdev == source.st_rdev
            {
                *stream = pty
                    .slave
                    .try_clone()
                    .map_err(|_| Failure::NativeUnavailable)?;
            }
        }
        master = Some(pty.master);
    }
    Ok((
        streams.try_into().map_err(|_| Failure::InvalidRequest)?,
        events,
        master,
    ))
}

pub(super) fn receive_signal(events: &OwnedFd) -> Result<Option<Signal>, Failure> {
    let mut bytes = [0_u8; 3];
    match socket::recv(
        events.as_raw_fd(),
        &mut bytes,
        MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
    ) {
        // A receive that could not run now is retried on the next poll.
        Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR | nix::errno::Errno::ENOMEM) => {
            Ok(None)
        }
        Ok(2) if bytes[0] == 0 => {
            let signal =
                Signal::try_from(i32::from(bytes[1])).map_err(|_| Failure::ProtocolViolation)?;
            if forwardable(signal) {
                Ok(Some(signal))
            } else {
                Err(Failure::ProtocolViolation)
            }
        }
        _ => Err(Failure::ProtocolViolation),
    }
}

pub(super) fn report_stopped(events: &OwnedFd, signal: Signal) -> Result<(), Failure> {
    socket::send(
        events.as_raw_fd(),
        &[1, signal as u8],
        MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
    )
    .map_err(|_| Failure::RuntimeFailure)
    .and_then(|length| {
        if length == 2 {
            Ok(())
        } else {
            Err(Failure::ProtocolViolation)
        }
    })
}

fn forwardable(signal: Signal) -> bool {
    matches!(
        signal,
        Signal::SIGHUP
            | Signal::SIGINT
            | Signal::SIGQUIT
            | Signal::SIGTERM
            | Signal::SIGUSR1
            | Signal::SIGUSR2
            | Signal::SIGTSTP
            | Signal::SIGCONT
            | Signal::SIGWINCH
            | Signal::SIGALRM
    )
}

pub(super) struct Signals {
    previous: SigSet,
    descriptor: SignalFd,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Signals {
    pub(super) fn new() -> Result<Self, Failure> {
        let previous = SigSet::thread_get_mask().map_err(|_| Failure::NativeUnavailable)?;
        let mut selected = SigSet::empty();
        for signal in [
            Signal::SIGHUP,
            Signal::SIGINT,
            Signal::SIGQUIT,
            Signal::SIGTERM,
            Signal::SIGUSR1,
            Signal::SIGUSR2,
            Signal::SIGTSTP,
            Signal::SIGCONT,
            Signal::SIGWINCH,
            Signal::SIGALRM,
        ] {
            selected.add(signal);
        }
        selected
            .thread_block()
            .map_err(|_| Failure::NativeUnavailable)?;
        let descriptor =
            match SignalFd::with_flags(&selected, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK) {
                Ok(descriptor) => descriptor,
                Err(_) => {
                    let _ = previous.thread_set_mask();
                    return Err(Failure::NativeUnavailable);
                }
            };
        Ok(Self {
            previous,
            descriptor,
            _thread: std::marker::PhantomData,
        })
    }
}

impl Signals {
    /// Wait for the coordinator's first answer to an execution that needs
    /// approval. A signal that would end the caller cancels the request, so
    /// it never reaches a program that starts after the caller gave up.
    pub(super) fn wait_for_answer(
        &self,
        connection: &impl AsFd,
        seconds: u32,
    ) -> Result<(), Failure> {
        let deadline = std::time::Instant::now() + Duration::from_secs(seconds.into());
        while std::time::Instant::now() < deadline {
            let mut descriptors = [
                PollFd::new(connection.as_fd(), PollFlags::POLLIN),
                PollFd::new(self.descriptor.as_fd(), PollFlags::POLLIN),
            ];
            match poll(&mut descriptors, 100_u16) {
                Ok(_) | Err(nix::errno::Errno::EINTR) => {}
                Err(_) => return Err(Failure::NativeUnavailable),
            }
            let [answer, signal] = descriptors.map(|descriptor| descriptor.revents());
            if answer.is_some_and(|flags| {
                flags.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
            }) {
                return Ok(());
            }
            if signal.is_some_and(|flags| flags.contains(PollFlags::POLLIN)) {
                while let Some(info) = self
                    .descriptor
                    .read_signal()
                    .map_err(|_| Failure::NativeUnavailable)?
                {
                    if !matches!(
                        Signal::try_from(info.ssi_signo as i32),
                        Ok(Signal::SIGWINCH | Signal::SIGCONT | Signal::SIGTSTP)
                    ) {
                        return Err(Failure::Interrupted);
                    }
                }
            }
        }
        Err(Failure::NativeUnavailable)
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        let _ = self.previous.thread_set_mask();
    }
}

fn nonblocking(fd: &OwnedFd) -> Result<(), Failure> {
    let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL)
        .map_err(|_| Failure::NativeUnavailable)?;
    nix::fcntl::fcntl(
        fd,
        nix::fcntl::FcntlArg::F_SETFL(
            nix::fcntl::OFlag::from_bits_retain(flags) | nix::fcntl::OFlag::O_NONBLOCK,
        ),
    )
    .map_err(|_| Failure::NativeUnavailable)?;
    Ok(())
}

/// Pump a descriptor-owned PTY without mixing protocol/result bytes into child
/// output. Non-TTY execution uses the same signal channel and hard wait bound.
pub(super) fn wait_execution(
    connection: &OwnedFd,
    events: OwnedFd,
    started: Started,
    master: Option<OwnedFd>,
    signals: Signals,
) -> Result<Vec<u8>, Failure> {
    if started.schema != START_SCHEMA
        || started.terminal != master.is_some()
        || started.hard_deadline_milliseconds == 0
    {
        return Err(Failure::ProtocolViolation);
    }
    let hard_deadline = Duration::from_millis(started.hard_deadline_milliseconds);
    let terminal = if let Some(master) = &master {
        nonblocking(master)?;
        let terminal = File::options()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOCTTY | nix::libc::O_NONBLOCK)
            .open("/dev/tty")
            .map_err(|_| Failure::NativeUnavailable)?;
        if nix::unistd::tcgetpgrp(&terminal).map_err(|_| Failure::NativeUnavailable)?
            != nix::unistd::getpgrp()
        {
            return Err(Failure::NativeUnavailable);
        }
        terminal::set_window_size(
            master,
            terminal::window_size(&terminal).map_err(|_| Failure::NativeUnavailable)?,
        )
        .map_err(|_| Failure::NativeUnavailable)?;
        Some(terminal)
    } else {
        None
    };
    let mut raw = terminal
        .as_ref()
        .map(RawTerminal::enter)
        .transpose()
        .map_err(|_| Failure::NativeUnavailable)?;
    let mut input = VecDeque::<u8>::new();
    let mut output = VecDeque::<u8>::new();
    let mut terminal_open = true;
    let mut result = None;
    let mut drained_by = None;
    let mut events_open = true;
    let mut completion_by = None;
    loop {
        let now = dev_tools_privilege_session::linux::boot_time()
            .map_err(|_| Failure::NativeUnavailable)?;
        if now > hard_deadline.saturating_add(Duration::from_secs(5)) {
            return Err(Failure::GrantExpired);
        }
        if result.is_none() && completion_by.is_some_and(|deadline| now >= deadline) {
            return Err(Failure::RuntimeFailure);
        }
        if result.is_some()
            && (output.is_empty() && !terminal_open
                || drained_by.is_some_and(|deadline| now >= deadline))
        {
            if !output.is_empty() {
                return Err(Failure::RuntimeFailure);
            }
            return result.ok_or(Failure::ProtocolViolation);
        }
        let mut descriptors = vec![
            PollFd::new(
                connection.as_fd(),
                if result.is_none() {
                    PollFlags::POLLIN
                } else {
                    PollFlags::empty()
                },
            ),
            PollFd::new(
                events.as_fd(),
                if events_open {
                    PollFlags::POLLIN
                } else {
                    PollFlags::empty()
                },
            ),
            PollFd::new(signals.descriptor.as_fd(), PollFlags::POLLIN),
        ];
        if let (Some(master), Some(terminal)) = (&master, &terminal) {
            descriptors.push(PollFd::new(
                master.as_fd(),
                if terminal_open && output.len() < 65_536 {
                    PollFlags::POLLIN
                } else {
                    PollFlags::empty()
                } | if !input.is_empty() {
                    PollFlags::POLLOUT
                } else {
                    PollFlags::empty()
                },
            ));
            descriptors.push(PollFd::new(
                terminal.as_fd(),
                if result.is_none() && input.len() < 65_536 {
                    PollFlags::POLLIN
                } else {
                    PollFlags::empty()
                } | if !output.is_empty() {
                    PollFlags::POLLOUT
                } else {
                    PollFlags::empty()
                },
            ));
        }
        match poll(&mut descriptors, 50_u16) {
            Ok(_) | Err(nix::errno::Errno::EINTR) => {}
            Err(_) => return Err(Failure::NativeUnavailable),
        }
        let ready: Vec<_> = descriptors
            .iter()
            .map(|descriptor| descriptor.revents().unwrap_or(PollFlags::POLLERR))
            .collect();
        drop(descriptors);
        if result.is_none()
            && ready[0].intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
        {
            let packet = super::transport::receive_owned(connection)
                .map_err(|_| Failure::ProtocolViolation)?;
            if !packet.descriptors.is_empty() {
                return Err(Failure::ProtocolViolation);
            }
            if master.is_none() {
                return Ok(packet.bytes);
            }
            result = Some(packet.bytes);
            drained_by = Some(now.saturating_add(Duration::from_secs(2)));
        }
        if events_open && ready[1].intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
            let mut message = [0; 3];
            let length = socket::recv(
                events.as_raw_fd(),
                &mut message,
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
            )
            .map_err(|_| Failure::ProtocolViolation)?;
            if length == 0 {
                // The executor drops its signal endpoint before the enclosing
                // control handler publishes the final result. Drain that result
                // under a short bound; EOF is not a malformed signal packet.
                events_open = false;
                completion_by = Some(now.saturating_add(Duration::from_secs(5)));
            } else {
                if length != 2
                    || message[0] != 1
                    || !matches!(
                        Signal::try_from(i32::from(message[1])),
                        Ok(Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU)
                    )
                {
                    return Err(Failure::ProtocolViolation);
                }
                drop(raw.take());
                nix::sys::signal::raise(Signal::SIGSTOP).map_err(|_| Failure::RuntimeFailure)?;
                raw = terminal
                    .as_ref()
                    .map(RawTerminal::enter)
                    .transpose()
                    .map_err(|_| Failure::NativeUnavailable)?;
                send_signal(&events, Signal::SIGCONT)?;
            }
        }
        if ready[2].contains(PollFlags::POLLIN) {
            while let Some(info) = signals
                .descriptor
                .read_signal()
                .map_err(|_| Failure::NativeUnavailable)?
            {
                let signal = Signal::try_from(info.ssi_signo as i32)
                    .map_err(|_| Failure::ProtocolViolation)?;
                if signal == Signal::SIGWINCH {
                    if let (Some(master), Some(terminal)) = (&master, &terminal) {
                        terminal::set_window_size(
                            master,
                            terminal::window_size(terminal)
                                .map_err(|_| Failure::NativeUnavailable)?,
                        )
                        .map_err(|_| Failure::NativeUnavailable)?;
                    }
                } else if events_open {
                    send_signal(&events, signal)?;
                }
            }
        }
        if let (Some(master), Some(terminal)) = (&master, &terminal) {
            if ready[3].intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
                && terminal_open
                && output.len() < 65_536
            {
                terminal_open = read_buffer(master, &mut output, true)?;
            }
            if ready[3].contains(PollFlags::POLLOUT) && !input.is_empty() {
                write_buffer(master, &mut input)?;
            }
            if ready[4].contains(PollFlags::POLLIN)
                && input.len() < 65_536
                && result.is_none()
                && !read_buffer(terminal, &mut input, false)?
            {
                return Err(Failure::Interrupted);
            }
            if ready[4].contains(PollFlags::POLLOUT) && !output.is_empty() {
                write_buffer(terminal, &mut output)?;
            }
        }
    }
}

fn send_signal(events: &OwnedFd, signal: Signal) -> Result<(), Failure> {
    if !forwardable(signal) {
        return Err(Failure::ProtocolViolation);
    }
    socket::send(
        events.as_raw_fd(),
        &[0, signal as u8],
        MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
    )
    .map_err(|_| Failure::RuntimeFailure)
    .and_then(|length| {
        if length == 2 {
            Ok(())
        } else {
            Err(Failure::ProtocolViolation)
        }
    })
}

fn read_buffer(fd: &impl AsFd, buffer: &mut VecDeque<u8>, pty: bool) -> Result<bool, Failure> {
    let mut bytes = [0; 8192];
    let available = bytes.len().min(65_536 - buffer.len());
    match nix::unistd::read(fd, &mut bytes[..available]) {
        Ok(0) => Ok(false),
        Ok(length) => {
            buffer.extend(&bytes[..length]);
            Ok(true)
        }
        Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => Ok(true),
        Err(nix::errno::Errno::EIO) if pty => Ok(false),
        Err(_) => Err(Failure::RuntimeFailure),
    }
}

fn write_buffer(fd: &impl AsFd, buffer: &mut VecDeque<u8>) -> Result<(), Failure> {
    match nix::unistd::write(fd, buffer.as_slices().0) {
        Ok(0) => Err(Failure::RuntimeFailure),
        Ok(length) => {
            buffer.drain(..length);
            Ok(())
        }
        Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => Ok(()),
        Err(_) => Err(Failure::RuntimeFailure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn nonterminal_execution_forwards_native_signals_and_preserves_result_bytes() {
        let before = SigSet::thread_get_mask().unwrap();
        let signals = Signals::new().unwrap();
        let (client, server) = event_pair().unwrap();
        let (events, received) = event_pair().unwrap();
        let responder = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if let Some(signal) = receive_signal(&received).unwrap() {
                    assert_eq!(signal, Signal::SIGUSR1);
                    break;
                }
                assert!(Instant::now() < deadline, "signal was not forwarded");
                std::thread::sleep(Duration::from_millis(5));
            }
            socket::send(
                server.as_raw_fd(),
                b"unaltered-result-bytes",
                MsgFlags::MSG_NOSIGNAL,
            )
            .unwrap();
        });
        // raise is thread-directed; this test's mask owns the pending signal
        // without disturbing concurrently running test threads.
        nix::sys::signal::raise(Signal::SIGUSR1).unwrap();
        let result = wait_execution(
            &client,
            events,
            Started {
                schema: START_SCHEMA.to_owned(),
                hard_deadline_milliseconds: u64::try_from(
                    (dev_tools_privilege_session::linux::boot_time().unwrap()
                        + Duration::from_secs(4))
                    .as_millis(),
                )
                .unwrap(),
                terminal: false,
            },
            None,
            signals,
        )
        .unwrap();
        responder.join().unwrap();
        assert_eq!(result, b"unaltered-result-bytes");
        let after = SigSet::thread_get_mask().unwrap();
        for signal in [
            Signal::SIGINT,
            Signal::SIGTERM,
            Signal::SIGUSR1,
            Signal::SIGTSTP,
        ] {
            assert_eq!(before.contains(signal), after.contains(signal));
        }
    }

    #[test]
    fn redirected_streams_remain_distinct_from_the_owned_terminal() {
        let original = Pty::new().unwrap();
        let (pipe_read, pipe_write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
        let pipe_identity = rustix::fs::fstat(&pipe_write).unwrap();
        let (client_events, server_events) = event_pair().unwrap();
        let streams = vec![
            original.slave.try_clone().unwrap(),
            pipe_write,
            original.slave.try_clone().unwrap(),
            server_events,
        ];
        let (streams, _, master) = prepare_streams(streams, true).unwrap();
        assert!(master.is_some());
        assert!(nix::unistd::isatty(&streams[0]).unwrap());
        assert!(nix::unistd::isatty(&streams[2]).unwrap());
        let after = rustix::fs::fstat(&streams[1]).unwrap();
        assert_eq!(
            (after.st_dev, after.st_ino),
            (pipe_identity.st_dev, pipe_identity.st_ino)
        );
        drop((pipe_read, client_events));
    }

    #[test]
    fn malformed_signal_frames_fail_closed() {
        let (sender, receiver) = event_pair().unwrap();
        for bytes in [
            vec![0],
            vec![0, Signal::SIGTERM as u8, 1],
            vec![1, Signal::SIGTERM as u8],
            vec![0, 255],
        ] {
            socket::send(sender.as_raw_fd(), &bytes, MsgFlags::MSG_NOSIGNAL).unwrap();
            assert_eq!(receive_signal(&receiver), Err(Failure::ProtocolViolation));
        }
    }

    #[test]
    fn terminal_transport_preserves_input_resize_interrupt_and_restoration() {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        let outer = Pty::new().unwrap();
        terminal::set_window_size(
            &outer.slave,
            terminal::WindowSize {
                rows: 25,
                columns: 80,
                pixel_width: 0,
                pixel_height: 0,
            },
        )
        .unwrap();
        let saved = nix::sys::termios::tcgetattr(&outer.slave).unwrap();
        let fixture = concat!(module_path!(), "::terminal_client_fixture");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                fixture.split_once("::").unwrap().1,
                "--nocapture",
            ])
            .env("DEV_AUTH_GRANT_PTY_FIXTURE", "client")
            .stdin(Stdio::from(outer.slave.try_clone().unwrap()))
            .stdout(Stdio::from(outer.slave.try_clone().unwrap()))
            .stderr(Stdio::from(outer.slave.try_clone().unwrap()));
        // SAFETY: the post-fork closure uses only initialized stack objects and
        // async-signal-safe syscalls. Blocking these signals before exec makes
        // every libtest thread inherit the single-thread CLI's signal context.
        unsafe {
            command.pre_exec(|| {
                let mut mask = std::mem::zeroed::<nix::libc::sigset_t>();
                nix::libc::sigemptyset(&mut mask);
                for signal in [
                    nix::libc::SIGWINCH,
                    nix::libc::SIGINT,
                    nix::libc::SIGTERM,
                    nix::libc::SIGHUP,
                    nix::libc::SIGCONT,
                    nix::libc::SIGTSTP,
                ] {
                    nix::libc::sigaddset(&mut mask, signal);
                }
                if nix::libc::sigprocmask(nix::libc::SIG_BLOCK, &mask, std::ptr::null_mut()) != 0
                    || nix::libc::setsid() < 0
                    || nix::libc::ioctl(0, nix::libc::TIOCSCTTY, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        nonblocking(&outer.master).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut output = Vec::new();
        let mut entered = false;
        let mut resized = false;
        let mut interrupted = false;
        let status = loop {
            let mut bytes = [0; 4096];
            match nix::unistd::read(&outer.master, &mut bytes) {
                Ok(length) => output.extend_from_slice(&bytes[..length]),
                Err(
                    nix::errno::Errno::EAGAIN | nix::errno::Errno::EIO | nix::errno::Errno::EINTR,
                ) => {}
                Err(error) => panic!("outer terminal read: {error}"),
            }
            assert!(output.len() < 65_536);
            let text = String::from_utf8_lossy(&output);
            if !entered
                && !nix::sys::termios::tcgetattr(&outer.slave)
                    .unwrap()
                    .local_flags
                    .contains(nix::sys::termios::LocalFlags::ICANON)
            {
                nix::unistd::write(&outer.master, b"literal;$bytes\n").unwrap();
                entered = true;
            }
            if entered && !resized && text.contains("literal;$bytes") {
                terminal::set_window_size(
                    &outer.slave,
                    terminal::WindowSize {
                        rows: 41,
                        columns: 113,
                        pixel_width: 0,
                        pixel_height: 0,
                    },
                )
                .unwrap();
                resized = true;
            }
            if resized && !interrupted && text.contains("RESIZE_OBSERVED") {
                nix::unistd::write(&outer.master, &[3]).unwrap();
                interrupted = true;
            }
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("terminal transport timed out: {text}");
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert!(
            status.success(),
            "{status}: {}",
            String::from_utf8_lossy(&output)
        );
        assert!(entered && resized && interrupted);
        assert_eq!(nix::sys::termios::tcgetattr(&outer.slave).unwrap(), saved);
        assert!(!String::from_utf8_lossy(&output).contains("transport-private-result"));
    }

    #[test]
    #[ignore = "owned terminal child fixture invoked only by terminal_transport_preserves_input_resize_interrupt_and_restoration"]
    fn terminal_client_fixture() {
        use std::os::unix::process::{CommandExt, ExitStatusExt};
        use std::process::{Command, Stdio};
        assert_eq!(
            std::env::var("DEV_AUTH_GRANT_PTY_FIXTURE").as_deref(),
            Ok("client")
        );
        let (events, server_events) = event_pair().unwrap();
        let streams = vec![
            std::io::stdin().as_fd().try_clone_to_owned().unwrap(),
            std::io::stdout().as_fd().try_clone_to_owned().unwrap(),
            std::io::stderr().as_fd().try_clone_to_owned().unwrap(),
            server_events,
        ];
        let (streams, server_events, master) = prepare_streams(streams, true).unwrap();
        let observer = streams[0].try_clone().unwrap();
        let [stdin, stdout, stderr] = streams;
        let mut command = Command::new("/usr/bin/cat");
        command
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        // SAFETY: only async-signal-safe native setup on initialized stack data
        // runs after fork; no allocation, locks or Rust destructors participate.
        unsafe {
            command.pre_exec(|| {
                let mut empty = std::mem::zeroed::<nix::libc::sigset_t>();
                nix::libc::sigemptyset(&mut empty);
                if nix::libc::sigprocmask(nix::libc::SIG_SETMASK, &empty, std::ptr::null_mut()) != 0
                    || nix::libc::setsid() < 0
                    || nix::libc::ioctl(0, nix::libc::TIOCSCTTY, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut command = command.spawn().unwrap();
        let (client, server) = event_pair().unwrap();
        let signals = Signals::new().unwrap();
        let responder = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut resized = false;
            loop {
                if !resized && terminal::window_size(&observer).unwrap().columns == 113 {
                    nix::unistd::write(&observer, b"RESIZE_OBSERVED\n").unwrap();
                    resized = true;
                }
                if let Some(signal) = receive_signal(&server_events).unwrap() {
                    nix::sys::signal::kill(nix::unistd::Pid::from_raw(command.id() as i32), signal)
                        .unwrap();
                }
                if let Some(status) = command.try_wait().unwrap() {
                    assert_eq!(status.signal(), Some(nix::libc::SIGINT));
                    assert!(resized);
                    break;
                }
                if Instant::now() >= deadline {
                    let _ = command.kill();
                    let _ = command.wait();
                    panic!("terminal child did not complete");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            drop(observer);
            socket::send(
                server.as_raw_fd(),
                b"transport-private-result",
                MsgFlags::MSG_NOSIGNAL,
            )
            .unwrap();
        });
        let result = wait_execution(
            &client,
            events,
            Started {
                schema: START_SCHEMA.to_owned(),
                hard_deadline_milliseconds: u64::try_from(
                    (dev_tools_privilege_session::linux::boot_time().unwrap()
                        + Duration::from_secs(8))
                    .as_millis(),
                )
                .unwrap(),
                terminal: true,
            },
            master,
            signals,
        )
        .unwrap();
        responder.join().unwrap();
        assert_eq!(result, b"transport-private-result");
    }
}
