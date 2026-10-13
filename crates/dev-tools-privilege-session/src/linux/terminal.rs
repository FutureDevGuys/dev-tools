//! Descriptor-owned Linux PTYs. Allocation is close-on-exec from the first
//! syscall, including the slave, so concurrent privileged spawns cannot inherit
//! another caller's terminal through an openpty/fcntl race.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;

pub struct Pty {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

impl Pty {
    pub fn new() -> io::Result<Self> {
        let master: OwnedFd = File::options()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOCTTY)
            .open("/dev/ptmx")?
            .into();
        let unlock = 0_i32;
        // SAFETY: master is an owned freshly opened PTY descriptor; unlock is a
        // live initialized C int for this synchronous ioctl. It is not retained.
        if unsafe { nix::libc::ioctl(master.as_raw_fd(), nix::libc::TIOCSPTLCK, &unlock) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: TIOCGPTPEER takes integer open flags and returns a newly owned
        // descriptor, without pathname resolution or an inheritance window.
        let slave = unsafe {
            nix::libc::ioctl(
                master.as_raw_fd(),
                nix::libc::TIOCGPTPEER,
                nix::libc::O_RDWR | nix::libc::O_NOCTTY | nix::libc::O_CLOEXEC,
            )
        };
        if slave < 0 {
            return Err(io::Error::last_os_error());
        }
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };
        Ok(Self { master, slave })
    }

    pub fn from_terminal(source: &impl AsFd) -> io::Result<Self> {
        let termios = nix::sys::termios::tcgetattr(source)?;
        let window = window_size(source)?;
        let pty = Self::new()?;
        nix::sys::termios::tcsetattr(&pty.slave, nix::sys::termios::SetArg::TCSANOW, &termios)?;
        set_window_size(&pty.slave, window)?;
        Ok(pty)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowSize {
    pub rows: u16,
    pub columns: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

pub fn window_size(fd: &impl AsFd) -> io::Result<WindowSize> {
    let mut size = nix::libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: the borrowed descriptor and correctly laid-out writable winsize
    // remain live for the synchronous call; no pointer escapes.
    if unsafe { nix::libc::ioctl(fd.as_fd().as_raw_fd(), nix::libc::TIOCGWINSZ, &mut size) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(WindowSize {
        rows: size.ws_row,
        columns: size.ws_col,
        pixel_width: size.ws_xpixel,
        pixel_height: size.ws_ypixel,
    })
}

pub fn set_window_size(fd: &impl AsFd, size: WindowSize) -> io::Result<()> {
    let size = nix::libc::winsize {
        ws_row: size.rows,
        ws_col: size.columns,
        ws_xpixel: size.pixel_width,
        ws_ypixel: size.pixel_height,
    };
    // SAFETY: size is an initialized native winsize, borrowed only during the
    // ioctl. The kernel applies foreground process-group SIGWINCH semantics.
    if unsafe { nix::libc::ioctl(fd.as_fd().as_raw_fd(), nix::libc::TIOCSWINSZ, &size) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Restore the caller terminal even when transport or execution fails. The
/// saved descriptor and mode belong to this invocation, not an ambient path.
pub struct RawTerminal {
    fd: OwnedFd,
    saved: nix::sys::termios::Termios,
}

impl RawTerminal {
    pub fn enter(fd: &impl AsFd) -> io::Result<Self> {
        let fd = fd.as_fd().try_clone_to_owned()?;
        let saved = nix::sys::termios::tcgetattr(&fd)?;
        let mut raw = saved.clone();
        nix::sys::termios::cfmakeraw(&mut raw);
        nix::sys::termios::tcsetattr(&fd, nix::sys::termios::SetArg::TCSANOW, &raw)?;
        Ok(Self { fd, saved })
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        let _ =
            nix::sys::termios::tcsetattr(&self.fd, nix::sys::termios::SetArg::TCSANOW, &self.saved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminals_are_cloexec_and_preserve_modes_and_resize() {
        let pty = Pty::new().unwrap();
        for fd in [&pty.master, &pty.slave] {
            let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD).unwrap();
            assert_ne!(flags & nix::libc::FD_CLOEXEC, 0);
        }
        let size = WindowSize {
            rows: 42,
            columns: 113,
            pixel_width: 0,
            pixel_height: 0,
        };
        set_window_size(&pty.slave, size).unwrap();
        let copy = Pty::from_terminal(&pty.slave).unwrap();
        assert_eq!(window_size(&copy.master).unwrap(), size);
        let original = nix::sys::termios::tcgetattr(&pty.slave).unwrap();
        {
            let _guard = RawTerminal::enter(&pty.slave).unwrap();
            assert!(!nix::sys::termios::tcgetattr(&pty.slave)
                .unwrap()
                .local_flags
                .contains(nix::sys::termios::LocalFlags::ICANON));
        }
        assert_eq!(nix::sys::termios::tcgetattr(&pty.slave).unwrap(), original);
    }

    #[test]
    fn native_terminal_refuses_non_terminal_inputs() {
        let file = File::open("/dev/null").unwrap();
        assert!(Pty::from_terminal(&file).is_err());
        assert!(RawTerminal::enter(&file).is_err());
    }
}
