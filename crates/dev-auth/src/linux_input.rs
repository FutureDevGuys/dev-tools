//! Bounded public stdin after native admission. This is not credential input.

use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::io::{self, ErrorKind};
use std::os::fd::AsFd;
use std::time::{Duration, Instant};

pub(crate) fn read_bounded(
    input: &impl AsFd,
    limit: usize,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    if limit == 0 || limit > 1024 * 1024 || timeout.is_zero() {
        return Err(io::Error::from(ErrorKind::InvalidInput));
    }
    let deadline = Instant::now() + timeout;
    let mut payload = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::from(ErrorKind::TimedOut));
        }
        let mut descriptors = [PollFd::new(input.as_fd(), PollFlags::POLLIN)];
        let wait = PollTimeout::try_from(remaining)
            .map_err(|_| io::Error::from(ErrorKind::InvalidInput))?;
        match poll(&mut descriptors, wait) {
            Ok(0) => return Err(io::Error::from(ErrorKind::TimedOut)),
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(io::Error::from_raw_os_error(error as i32)),
        }
        let mut chunk = [0_u8; 4096];
        let available = (limit + 1 - payload.len()).min(chunk.len());
        let count = match nix::unistd::read(input, &mut chunk[..available]) {
            Ok(count) => count,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(io::Error::from_raw_os_error(error as i32)),
        };
        if count == 0 {
            break;
        }
        payload.extend_from_slice(&chunk[..count]);
        if payload.len() > limit {
            return Err(io::Error::from(ErrorKind::InvalidData));
        }
    }
    if payload.is_empty() {
        return Err(io::Error::from(ErrorKind::InvalidData));
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, Write};
    use std::os::unix::net::UnixStream;

    #[test]
    fn public_input_is_bounded_and_a_stalled_pipe_times_out() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&vec![0x5a; 24 * 1024]).unwrap();
        file.rewind().unwrap();
        assert_eq!(
            read_bounded(&file, 24 * 1024, Duration::from_secs(1)).unwrap(),
            vec![0x5a; 24 * 1024]
        );

        file.set_len(24 * 1024 + 1).unwrap();
        file.rewind().unwrap();
        assert_eq!(
            read_bounded(&file, 24 * 1024, Duration::from_secs(1))
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );

        let (reader, _writer) = UnixStream::pair().unwrap();
        assert_eq!(
            read_bounded(&reader, 16 * 1024, Duration::from_millis(20))
                .unwrap_err()
                .kind(),
            ErrorKind::TimedOut
        );
    }
}
