//! Linux message-oriented IPC. Native credentials are checked before request
//! bytes are accepted; descriptors are close-on-exec and bounded per message.

use super::model::Failure;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::socket::{
    connect, getsockopt, sendmsg, socket, sockopt, AddressFamily, ControlMessage, MsgFlags,
    SockFlag, SockType, UnixAddr,
};
use std::io::IoSlice;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub(super) const HELLO: &[u8; 8] = b"DVPRIV1\0";

pub(super) use super::packet::receive_owned;
pub(super) fn exchange(
    path: &Path,
    request: &[u8],
    execution: Option<bool>,
    deadline_seconds: u32,
    approval: bool,
) -> Result<Vec<u8>, (Failure, Option<bool>)> {
    exchange_with_launch_descriptors(path, request, execution, deadline_seconds, approval, None)
}

pub(super) fn exchange_with_launch_descriptors(
    path: &Path,
    request: &[u8],
    execution: Option<bool>,
    deadline_seconds: u32,
    approval: bool,
    launch: Option<&[std::os::fd::RawFd; 3]>,
) -> Result<Vec<u8>, (Failure, Option<bool>)> {
    if launch.is_some() && (execution.is_some() || approval) {
        return Err((Failure::InvalidRequest, Some(false)));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        (
            if error.kind() == std::io::ErrorKind::NotFound {
                Failure::RequiresSetup
            } else {
                Failure::AuthorityDenied
            },
            Some(false),
        )
    })?;
    use std::os::unix::fs::FileTypeExt;
    if !metadata.file_type().is_socket() || metadata.uid() != 0 {
        return Err((Failure::AuthorityDenied, Some(false)));
    }
    let socket = socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .map_err(|_| (Failure::NativeUnavailable, Some(false)))?;
    let address = UnixAddr::new(path).map_err(|_| (Failure::InvalidRequest, Some(false)))?;
    // AF_UNIX returns EAGAIN for a full nonblocking accept queue. No request
    // was sent; never turn connection pressure into an unbounded connect.
    connect(socket.as_raw_fd(), &address).map_err(|error| {
        (
            if error == nix::errno::Errno::EAGAIN {
                Failure::Busy
            } else {
                Failure::NativeUnavailable
            },
            Some(false),
        )
    })?;
    let peer = getsockopt(&socket, sockopt::PeerCredentials)
        .map_err(|_| (Failure::AuthorityDenied, Some(false)))?;
    let peer_pidfd = getsockopt(&socket, sockopt::PeerPidfd)
        .map_err(|_| (Failure::NativeUnavailable, Some(false)))?;
    if peer.uid() != 0 || !alive(&peer_pidfd) {
        return Err((Failure::AuthorityDenied, Some(false)));
    }
    wait_readable(&socket, 10).map_err(|failure| (failure, Some(false)))?;
    let hello = receive_owned(&socket).map_err(|_| (Failure::ProtocolViolation, Some(false)))?;
    if hello.bytes != HELLO || !hello.descriptors.is_empty() || !alive(&peer_pidfd) {
        return Err((Failure::ProtocolViolation, Some(false)));
    }
    let _agent = if approval {
        super::tty_agent::TtyAgent::for_request().map_err(|failure| (failure, Some(false)))?
    } else {
        None
    };
    let events = execution
        .map(|_| super::execution_io::event_pair())
        .transpose()
        .map_err(|failure| (failure, Some(false)))?;
    let signals = execution
        .map(|_| super::execution_io::Signals::new())
        .transpose()
        .map_err(|failure| (failure, Some(false)))?;
    let streams = events
        .as_ref()
        .map(|(_, server)| [0, 1, 2, server.as_raw_fd()]);
    let controls = if let Some(streams) = &streams {
        vec![ControlMessage::ScmRights(streams)]
    } else if let Some(launch) = launch {
        vec![ControlMessage::ScmRights(launch)]
    } else {
        Vec::new()
    };
    let sent = sendmsg::<UnixAddr>(
        socket.as_raw_fd(),
        &[IoSlice::new(request)],
        &controls,
        MsgFlags::MSG_NOSIGNAL,
        None,
    )
    .map_err(|_| (Failure::RuntimeFailure, Some(false)))?;
    if sent != request.len() {
        return Err((
            Failure::ProtocolViolation,
            if sent == 0 { Some(false) } else { None },
        ));
    }
    wait_readable(
        &socket,
        if execution.is_some() {
            10
        } else {
            deadline_seconds
        },
    )
    .map_err(|failure| (failure, None))?;
    let mut packet = receive_owned(&socket).map_err(|_| (Failure::ProtocolViolation, None))?;
    if !alive(&peer_pidfd) {
        return Err((Failure::ProtocolViolation, None));
    }
    if let Some(terminal) = execution {
        if let Ok(started) = serde_json::from_slice::<super::execution_io::Started>(&packet.bytes) {
            if started.terminal != terminal || packet.descriptors.len() != usize::from(terminal) {
                return Err((Failure::ProtocolViolation, None));
            }
            let master = packet.descriptors.pop();
            let (events, server) = events.ok_or((Failure::ProtocolViolation, None))?;
            drop(server);
            return super::execution_io::wait_execution(
                &socket,
                events,
                started,
                master,
                signals.ok_or((Failure::ProtocolViolation, None))?,
            )
            .map_err(|failure| (failure, Some(true)));
        }
    }
    if !packet.descriptors.is_empty() {
        return Err((Failure::ProtocolViolation, None));
    }
    Ok(packet.bytes)
}

fn alive(fd: &impl AsFd) -> bool {
    let mut descriptors = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
    matches!(poll(&mut descriptors, PollTimeout::ZERO), Ok(0))
}

fn wait_readable(fd: &impl AsFd, seconds: u32) -> Result<(), Failure> {
    let timeout = if seconds == 0 {
        PollTimeout::NONE
    } else {
        PollTimeout::try_from(std::time::Duration::from_secs(seconds.into()))
            .map_err(|_| Failure::InvalidRequest)?
    };
    let mut descriptors = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
    match poll(&mut descriptors, timeout) {
        Ok(ready)
            if ready > 0
                && descriptors[0]
                    .revents()
                    .is_some_and(|flags| flags.contains(PollFlags::POLLIN)) =>
        {
            Ok(())
        }
        Err(nix::errno::Errno::EINTR) => Err(Failure::Interrupted),
        _ => Err(Failure::NativeUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_descriptor_messages_close_every_installed_pipe_writer() {
        if crate::test_isolation::run_isolated(concat!(
            module_path!(),
            "::truncated_descriptor_messages_close_every_installed_pipe_writer"
        )) {
            return;
        }
        let (sender, receiver) = nix::sys::socket::socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        let (read, write) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC | nix::fcntl::OFlag::O_NONBLOCK)
                .unwrap();
        let copies = vec![write.as_raw_fd(); 64];
        sendmsg::<UnixAddr>(
            sender.as_raw_fd(),
            &[IoSlice::new(b"x")],
            &[ControlMessage::ScmRights(&copies)],
            MsgFlags::MSG_NOSIGNAL,
            None,
        )
        .unwrap();
        drop(write);
        assert!(receive_owned(&receiver).is_err());
        let mut byte = [0_u8];
        assert_eq!(
            nix::unistd::read(&read, &mut byte).unwrap(),
            0,
            "a rejected truncated frame must not leak received writers"
        );
    }
}
