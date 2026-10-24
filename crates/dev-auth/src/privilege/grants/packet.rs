//! Product-private native packet ownership shared by the Dev Auth executable
//! and its receipt-owned sudo plugin. This is not a public broker protocol.

use std::os::fd::AsRawFd;

pub(crate) const FRAME_LIMIT: usize = 60 * 1024;

pub(crate) struct Packet {
    pub bytes: Vec<u8>,
    pub descriptors: Vec<std::os::fd::OwnedFd>,
    pub credentials: Option<nix::sys::socket::UnixCredentials>,
}

pub(crate) fn receive_owned(fd: &impl AsRawFd) -> std::io::Result<Packet> {
    use std::os::fd::FromRawFd;
    let mut bytes = vec![0; FRAME_LIMIT + 1];
    // Linux cmsghdr consists of size_t and two C ints. Word storage establishes
    // its alignment; bounds are checked before every header or data read.
    const _: () =
        assert!(std::mem::align_of::<usize>() >= std::mem::align_of::<nix::libc::cmsghdr>());
    let mut ancillary = [0_usize; 32];
    let mut vector = nix::libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message = nix::libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut vector,
        msg_iovlen: 1,
        msg_control: ancillary.as_mut_ptr().cast(),
        msg_controllen: std::mem::size_of_val(&ancillary),
        msg_flags: 0,
    };
    // SAFETY: all pointed-to buffers are initialized, uniquely writable and
    // live for recvmsg. The kernel writes at most the supplied lengths. Native
    // descriptor ownership is recovered below even on ancillary truncation;
    // nix's high-level cmsgs iterator refuses that case before exposing FDs.
    let length = unsafe {
        nix::libc::recvmsg(
            fd.as_raw_fd(),
            &mut message,
            nix::libc::MSG_CMSG_CLOEXEC | nix::libc::MSG_TRUNC | nix::libc::MSG_DONTWAIT,
        )
    };
    if length < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let length = length as usize;
    let mut descriptors = Vec::new();
    let mut credentials = None;
    let mut invalid = false;
    let control_length = message
        .msg_controllen
        .min(std::mem::size_of_val(&ancillary));
    let base = ancillary.as_ptr().cast::<u8>();
    let mut offset = 0;
    let header_size = std::mem::size_of::<nix::libc::cmsghdr>();
    while offset <= control_length && header_size <= control_length - offset {
        // SAFETY: the complete native header lies within initialized storage;
        // read_unaligned avoids creating a Rust reference to foreign layout.
        let header =
            unsafe { std::ptr::read_unaligned(base.add(offset).cast::<nix::libc::cmsghdr>()) };
        if header.cmsg_len < header_size || header.cmsg_len > control_length - offset {
            invalid = true;
            break;
        }
        let payload = header.cmsg_len - header_size;
        // SAFETY: header and payload lengths were checked within the buffer.
        let data = unsafe { base.add(offset + header_size) };
        if header.cmsg_level == nix::libc::SOL_SOCKET && header.cmsg_type == nix::libc::SCM_RIGHTS {
            if !payload.is_multiple_of(std::mem::size_of::<i32>()) {
                invalid = true;
            }
            for index in 0..payload / std::mem::size_of::<i32>() {
                // SAFETY: each complete C int fits in the validated payload.
                // recvmsg installs a distinct valid descriptor for every
                // complete SCM_RIGHTS entry, including repeated sender FDs.
                let descriptor = unsafe {
                    std::ptr::read_unaligned(
                        data.add(index * std::mem::size_of::<i32>()).cast::<i32>(),
                    )
                };
                if descriptor < 0 {
                    invalid = true;
                    continue;
                }
                descriptors.push(unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor) });
            }
        } else if header.cmsg_level == nix::libc::SOL_SOCKET
            && header.cmsg_type == nix::libc::SCM_CREDENTIALS
            && payload == std::mem::size_of::<nix::libc::ucred>()
        {
            if credentials.is_some() {
                invalid = true;
            }
            // SAFETY: the exact-sized kernel credential payload was checked;
            // ucred contains only initialized C integer fields, all bit-valid.
            credentials = Some(nix::sys::socket::UnixCredentials::from(unsafe {
                std::ptr::read_unaligned(data.cast::<nix::libc::ucred>())
            }));
        } else {
            invalid = true;
        }
        let word = std::mem::size_of::<usize>();
        let Some(aligned) = header
            .cmsg_len
            .checked_add(word - 1)
            .map(|size| size & !(word - 1))
        else {
            invalid = true;
            break;
        };
        let Some(next) = offset.checked_add(aligned) else {
            invalid = true;
            break;
        };
        offset = next;
    }
    if invalid
        || length == 0
        || length > FRAME_LIMIT
        || message.msg_flags & (nix::libc::MSG_TRUNC | nix::libc::MSG_CTRUNC) != 0
    {
        // All complete rights have already entered RAII owners. In particular,
        // returning this error closes the kernel's partially delivered set.
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    bytes.truncate(length);
    Ok(Packet {
        bytes,
        descriptors,
        credentials,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{self, MsgFlags, SockFlag, SockType, UnixAddr};

    fn pair() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
        let (receiver, sender) = socket::socketpair(
            socket::AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        )
        .unwrap();
        socket::setsockopt(&receiver, socket::sockopt::PassCred, &true).unwrap();
        (receiver, sender)
    }

    #[test]
    fn closed_peer_is_end_of_stream_not_a_malformed_frame() {
        let (receiver, sender) = pair();
        drop(sender);
        assert_eq!(
            receive_owned(&receiver).err().map(|error| error.kind()),
            Some(std::io::ErrorKind::UnexpectedEof)
        );
    }

    #[test]
    fn peer_closed_with_unread_frames_is_a_reset() {
        let (receiver, sender) = pair();
        socket::send(receiver.as_raw_fd(), b"unread", MsgFlags::MSG_NOSIGNAL).unwrap();
        drop(sender);
        assert_eq!(
            receive_owned(&receiver).err().map(|error| error.kind()),
            Some(std::io::ErrorKind::ConnectionReset)
        );
    }

    #[test]
    fn empty_frame_from_a_live_peer_is_malformed() {
        let (receiver, sender) = pair();
        socket::sendmsg::<UnixAddr>(
            sender.as_raw_fd(),
            &[std::io::IoSlice::new(&[])],
            &[],
            MsgFlags::MSG_NOSIGNAL,
            None,
        )
        .unwrap();
        assert_eq!(
            receive_owned(&receiver).err().map(|error| error.kind()),
            Some(std::io::ErrorKind::InvalidData)
        );
        drop(sender);
    }
}
