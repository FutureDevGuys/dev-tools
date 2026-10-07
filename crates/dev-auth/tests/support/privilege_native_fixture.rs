//! Opt-in, non-installed acceptance subject. Never a public product helper.
#[cfg(target_os = "linux")]
mod privilege_native_contract;
#[cfg(target_os = "linux")]
mod privilege_native_controller;
#[cfg(target_os = "linux")]
mod privilege_native_core;
#[cfg(target_os = "linux")]
mod privilege_native_faults;
#[cfg(target_os = "linux")]
mod privilege_native_prepare;
#[cfg(target_os = "linux")]
mod privilege_receipt_native_prepare;
#[cfg(target_os = "linux")]
mod privilege_receipt_native_support;
#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{bail, Context, Result};
    use std::{
        ffi::CString, fs, io::Write, os::unix::fs::OpenOptionsExt, path::Path, time::Duration,
    };
    pub fn run() -> Result<()> {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        if args.as_slice() == ["timer-stop"] {
            let deadline = dev_auth::linux_platform::boot_time_millis()?
                .checked_add(150)
                .context("clock overflow")?;
            let _timer = dev_auth::privilege::deadline::HardDeadline::arm(deadline)?;
            println!("timer-armed");
            std::io::stdout().flush()?;
            unsafe {
                nix::libc::raise(nix::libc::SIGSTOP);
            }
            bail!("stopped coordinator survived its kernel deadline");
        }
        match args.as_slice() {
            [mode] if mode == "core-filter-selftest" => super::privilege_native_core::selftest(),
            [mode] if mode == "core-filter-child" => super::privilege_native_core::assert_filter(),
            [mode] if mode == "core-positive" => super::privilege_native_core::positive(),
            [mode, pid] if mode == "core-collector" => super::privilege_native_core::collect(pid),
            [mode, path] if mode == "core-descendant" => {
                super::privilege_native_core::descendant(Path::new(path))
            }
            [mode, path] if mode == "receipt-prepare" => {
                super::privilege_receipt_native_prepare::prepare(Path::new(path))
            }
            [mode, path] if mode == "receipt-input" => {
                super::privilege_receipt_native_prepare::finish(Path::new(path))
            }
            [mode, path] if mode == "receipt-controller" => {
                super::privilege_receipt_native_support::controller(Path::new(path))
            }
            [mode, path] if mode == "receipt-driver" => {
                super::privilege_receipt_native_support::driver(Path::new(path))
            }
            [mode, action, path] if mode == "helper" => helper(action, Path::new(path)),
            [mode, case, dev_auth, fixture, approval] if mode == "controller" => {
                super::privilege_native_controller::run(
                    case,
                    Path::new(dev_auth),
                    Path::new(fixture),
                    Path::new(approval),
                )
            }
            [mode, case, dev_auth, fixture, root] if mode == "prepare" => {
                super::privilege_native_prepare::run(
                    case,
                    Path::new(dev_auth),
                    Path::new(fixture),
                    Path::new(root),
                )
            }
            [mode, case, dev_auth, fixture, root, plan] if mode == "write-input" => {
                super::privilege_native_prepare::input(
                    case,
                    Path::new(dev_auth),
                    Path::new(fixture),
                    Path::new(root),
                    Path::new(plan),
                )
            }
            [mode, input] if mode == "fault-driver" => {
                super::privilege_native_faults::run(Path::new(input))
            }
            _ => bail!("invalid acceptance subject invocation"),
        }
    }
    pub(super) fn fixture(path: &Path) -> Result<()> {
        if !path.is_absolute()
            || !path.starts_with("/var/tmp")
            || !path.components().any(|c| {
                c.as_os_str()
                    .to_string_lossy()
                    .starts_with("dev-auth-privilege-native-")
            })
        {
            bail!("acceptance requires its explicit disposable fixture root");
        }
        Ok(())
    }
    fn helper(action: &str, path: &Path) -> Result<()> {
        fixture(path)?;
        if unsafe { nix::libc::geteuid() } != 0
            || unsafe { nix::libc::getpid() } <= 1
            || unsafe { nix::libc::prctl(nix::libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1
        {
            bail!("acceptance helper is outside its admitted root namespace");
        }
        match action {
            "core-probe" => super::privilege_native_core::payload(path),
            "write" => {
                let mut file = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
                    .open(path)?;
                file.write_all(b"approved-root-effect\n")?;
                file.sync_all()?;
                println!("native_uid=0");
                Ok(())
            }
            "probe" => {
                const CAPS: u64 = (1 << 0) | (1 << 1) | (1 << 3) | (1 << 4);
                let status = fs::read_to_string("/proc/self/status")?;
                for name in ["CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"] {
                    let value = status
                        .lines()
                        .find_map(|line| line.strip_prefix(&format!("{name}:")))
                        .context("capability observation absent")?;
                    if u64::from_str_radix(value.trim(), 16)? != CAPS {
                        bail!("post-exec filesystem capabilities differ from the fixed mask");
                    }
                }
                if Path::new("/run/systemd/private").exists()
                    || Path::new("/sys/fs/cgroup/cgroup.procs").exists()
                {
                    bail!("host control authority is visible");
                }
                if fs::OpenOptions::new()
                    .write(true)
                    .open("/proc/sysrq-trigger")
                    .is_ok()
                {
                    bail!("global proc control is writable");
                }
                let socket =
                    unsafe { nix::libc::socket(nix::libc::AF_UNIX, nix::libc::SOCK_STREAM, 0) };
                if socket >= 0 {
                    unsafe {
                        nix::libc::close(socket);
                    }
                    bail!("external socket capability is available");
                }
                if unsafe { nix::libc::unshare(nix::libc::CLONE_NEWUSER) } == 0 {
                    bail!("new namespace authority is available");
                }
                let mut file = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .custom_flags(nix::libc::O_NOFOLLOW)
                    .open(path)?;
                file.write_all(b"namespace-and-syscall-probes-passed\n")?;
                Ok(())
            }
            "nested-probe" => {
                let sentinel = path.join("sentinel");
                if !path.is_dir()
                    || fs::read_dir(path)?.next().is_some()
                    || fs::read(&sentinel).is_ok()
                    || fs::OpenOptions::new().write(true).open(&sentinel).is_ok()
                {
                    bail!("writable resource imported an unapproved nested mount");
                }
                Ok(())
            }
            "hold" => {
                fs::write(path, b"operation-started\n")?;
                std::thread::sleep(Duration::from_millis(750));
                Ok(())
            }
            "streams" => {
                use std::io::Read;
                let mut input = Vec::new();
                std::io::stdin().read_to_end(&mut input)?;
                if input != [0, 255, 10, 13, 128] {
                    bail!("binary fixture input changed");
                }
                std::io::stdout().write_all(&input)?;
                std::io::stderr().write_all(&[255, 0, 127, 10])?;
                Ok(())
            }
            "blocked-output" => {
                fs::write(path, b"output-started\n")?;
                std::io::stdout().write_all(&vec![0xa5; 32 * 1024])?;
                Ok(())
            }
            "signal-term" | "signal-segv" => {
                // This deliberately exercises the actual native helper. If a
                // namespace-init arrangement swallows the default self signal,
                // the acceptance must fail rather than fake a signal receipt.
                let signal = if action == "signal-term" {
                    nix::libc::SIGTERM
                } else {
                    nix::libc::SIGSEGV
                };
                unsafe {
                    nix::libc::signal(signal, nix::libc::SIG_DFL);
                    nix::libc::raise(signal);
                }
                bail!("native helper survived its self signal");
            }
            "detached" | "leader-exit" => {
                let mut synchronization = [0; 2];
                if unsafe { nix::libc::pipe2(synchronization.as_mut_ptr(), nix::libc::O_CLOEXEC) }
                    != 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                let target = CString::new(path.as_os_str().as_encoded_bytes())?;
                // This dedicated fixture is single-threaded. Post-fork child
                // uses only native async-signal-safe syscalls and fixed buffers.
                let child = unsafe { nix::libc::fork() };
                if child < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                if child == 0 {
                    unsafe {
                        nix::libc::close(synchronization[0]);
                        nix::libc::setsid();
                        let second = nix::libc::fork();
                        if second != 0 {
                            nix::libc::_exit(if second < 0 { 1 } else { 0 });
                        }
                        nix::libc::signal(nix::libc::SIGTERM, nix::libc::SIG_IGN);
                        let fd = nix::libc::open(
                            target.as_ptr(),
                            nix::libc::O_WRONLY
                                | nix::libc::O_CREAT
                                | nix::libc::O_APPEND
                                | nix::libc::O_NOFOLLOW,
                            0o600,
                        );
                        if fd < 0 {
                            nix::libc::_exit(2);
                        }
                        let tick = b"tick\n";
                        let delay = nix::libc::timespec {
                            tv_sec: 0,
                            tv_nsec: 20_000_000,
                        };
                        let mut reported = false;
                        loop {
                            if nix::libc::write(fd, tick.as_ptr().cast(), tick.len())
                                != tick.len() as isize
                            {
                                nix::libc::_exit(3);
                            }
                            if !reported {
                                if nix::libc::write(synchronization[1], tick.as_ptr().cast(), 1)
                                    != 1
                                {
                                    nix::libc::_exit(4);
                                }
                                nix::libc::close(synchronization[1]);
                                reported = true;
                            }
                            nix::libc::nanosleep(&delay, std::ptr::null_mut());
                        }
                    }
                }
                unsafe {
                    nix::libc::close(synchronization[1]);
                }
                let mut byte = 0u8;
                loop {
                    let read = unsafe {
                        nix::libc::read(synchronization[0], (&mut byte as *mut u8).cast(), 1)
                    };
                    if read == 1 {
                        break;
                    }
                    if read < 0
                        && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                    {
                        continue;
                    }
                    bail!("detached descendant did not establish its first protected write");
                }
                unsafe {
                    nix::libc::close(synchronization[0]);
                }
                if action == "leader-exit" {
                    unsafe {
                        nix::libc::_exit(23);
                    }
                }
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            _ => bail!("unknown acceptance helper operation"),
        }
    }
}
#[cfg(target_os = "linux")]
fn main() {
    if linux::run().is_err() {
        eprintln!("native privilege fixture failed");
        std::process::exit(1);
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(3);
}
