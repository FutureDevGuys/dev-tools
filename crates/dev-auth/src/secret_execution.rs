use anyhow::{bail, Result};
#[cfg(target_os = "linux")]
use dev_auth::logical_authority::Projection;
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Target {
    Stdin,
    Descriptor(i32),
    File(String),
    Environment(String),
}

pub(super) struct Request {
    pub target: Target,
    pub resource: String,
}

impl Request {
    #[cfg(target_os = "linux")]
    pub fn projection(&self) -> Projection {
        match self.target {
            Target::Stdin => Projection::Stdin,
            Target::Descriptor(_) => Projection::Descriptor,
            Target::File(_) => Projection::File,
            Target::Environment(_) => Projection::Environment,
        }
    }
}

pub(super) fn validate(requests: &[Request]) -> Result<()> {
    if requests.is_empty() || requests.len() > 32 {
        bail!("projection count is invalid");
    }
    let mut targets = BTreeSet::new();
    let mut environment = BTreeSet::new();
    for request in requests {
        dev_tools_secret::LogicalSecretName::parse(&request.resource)?;
        if !targets.insert(request.target.clone()) {
            bail!("projection target is duplicated");
        }
        match &request.target {
            Target::Descriptor(fd) if !(3..=1024).contains(fd) => {
                bail!("projection descriptor is invalid")
            }
            Target::File(name) | Target::Environment(name)
                if !environment.insert(name) || !environment_name(name) =>
            {
                bail!("projection environment name is invalid or duplicated");
            }
            _ => {}
        }
    }
    Ok(())
}

fn environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 128
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !name.starts_with("DEV_AUTH_")
        && !name.starts_with("LD_")
        && !name.starts_with("DYLD_")
        && !matches!(
            name,
            "PATH" | "HOME" | "USER" | "LOGNAME" | "SHELL" | "OP_SERVICE_ACCOUNT_TOKEN"
        )
}

#[cfg(target_os = "linux")]
pub(super) struct Prepared {
    command: std::process::Command,
    _files: Vec<std::fs::File>,
}

#[cfg(target_os = "linux")]
impl Prepared {
    pub fn new(
        mut command: std::process::Command,
        requests: &[Request],
        values: Vec<dev_auth::broker_protocol::SensitiveBytes>,
    ) -> Result<Self> {
        use anyhow::Context;
        use std::fs::File;
        use std::io::{Seek, SeekFrom, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::process::CommandExt;
        validate(requests)?;
        if requests.len() != values.len()
            || values
                .iter()
                .map(|value| value.expose().len())
                .sum::<usize>()
                > 1024 * 1024
        {
            bail!("projection material count or size is invalid");
        }
        let mut files = Vec::new();
        let mut descriptors = Vec::new();
        let mut selected = requests
            .iter()
            .filter_map(|request| match request.target {
                Target::Descriptor(fd) => Some(fd),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        for (request, value) in requests.iter().zip(values) {
            if let Target::Environment(name) = &request.target {
                if value.expose().contains(&0) {
                    bail!("environment projection cannot represent this material");
                }
                command.env(name, std::ffi::OsStr::from_bytes(value.expose()));
                continue;
            }
            let mut file = File::from(rustix::fs::memfd_create(
                "dev-auth-projection",
                rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
            )?);
            rustix::fs::fchmod(&file, rustix::fs::Mode::from_bits_truncate(0o400))?;
            file.write_all(value.expose())
                .context("prepare anonymous projection")?;
            file.seek(SeekFrom::Start(0))?;
            rustix::fs::fcntl_add_seals(
                &file,
                rustix::fs::SealFlags::SEAL
                    | rustix::fs::SealFlags::SHRINK
                    | rustix::fs::SealFlags::GROW
                    | rustix::fs::SealFlags::WRITE,
            )?;
            if request.target == Target::Stdin {
                command.stdin(std::process::Stdio::from(file));
                continue;
            }
            let target = match &request.target {
                Target::Descriptor(fd) => *fd,
                Target::File(name) => {
                    let target = (64..=1024)
                        .find(|fd| !selected.contains(fd))
                        .context("projection descriptors are exhausted")?;
                    selected.insert(target);
                    command.env(name, format!("/proc/self/fd/{target}"));
                    target
                }
                _ => unreachable!("stdin and environment handled before descriptor projection"),
            };
            // Retain sources above every allowed target so dup2 cannot destroy a
            // later source. These descriptors remain CLOEXEC in the parent.
            let source = File::from(rustix::io::fcntl_dupfd_cloexec(&file, 1025)?);
            descriptors.push((source.as_raw_fd(), target));
            files.push(source);
        }
        // SAFETY: Prepared exclusively owns both the command and retained source
        // files through spawn. The callback uses only async-signal-safe dup2;
        // target numbers were checked, are distinct and cannot alias any source.
        unsafe {
            command.pre_exec(move || {
                for (source, target) in &descriptors {
                    if nix::libc::dup2(*source, *target) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        Ok(Self {
            command,
            _files: files,
        })
    }

    pub fn run(
        mut self,
        continue_running: impl FnMut() -> bool,
    ) -> Result<dev_tools_command::InheritedCommandOutput> {
        dev_tools_command::run_prepared_inherited_command(&mut self.command, continue_running)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use dev_auth::broker_protocol::SensitiveBytes;
    use std::fs::File;
    use std::process::{Command, Stdio};

    #[test]
    fn native_projection_delivers_binary_stdin_descriptor_file_and_explicit_environment() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("output");
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "cat; cat <&7; cat \"$SECRET_FILE\"; printf '%s' \"$SECRET_VALUE\"; exit 29",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdout(Stdio::from(File::create(&output).unwrap()));
        let requests = vec![
            Request {
                target: Target::Stdin,
                resource: "input".into(),
            },
            Request {
                target: Target::Descriptor(7),
                resource: "descriptor".into(),
            },
            Request {
                target: Target::File("SECRET_FILE".into()),
                resource: "file".into(),
            },
            Request {
                target: Target::Environment("SECRET_VALUE".into()),
                resource: "environment".into(),
            },
        ];
        let values = [
            vec![0, 255, 10],
            vec![1, 254],
            vec![2, 253],
            b"environment-sentinel".to_vec(),
        ]
        .into_iter()
        .map(|value| SensitiveBytes::new(value).unwrap())
        .collect();
        let prepared = Prepared::new(command, &requests, values).unwrap();
        let result = prepared.run(|| true).unwrap();
        assert_eq!(result.status.code(), Some(29));
        assert_eq!(
            std::fs::read(output).unwrap(),
            [
                vec![0, 255, 10, 1, 254, 2, 253],
                b"environment-sentinel".to_vec()
            ]
            .concat()
        );
    }

    #[test]
    fn projection_targets_reject_collisions_and_reserved_authority_environment() {
        for name in [
            "DEV_AUTH_SESSION",
            "LD_PRELOAD",
            "PATH",
            "OP_SERVICE_ACCOUNT_TOKEN",
            "bad=name",
        ] {
            assert!(validate(&[Request {
                target: Target::Environment(name.into()),
                resource: "token".into()
            }])
            .is_err());
        }
        assert!(validate(&[
            Request {
                target: Target::File("TOKEN".into()),
                resource: "one".into()
            },
            Request {
                target: Target::Environment("TOKEN".into()),
                resource: "two".into()
            },
        ])
        .is_err());
    }

    #[test]
    fn projection_memfds_are_sealed_private_and_closed_after_execution() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let requests = vec![Request {
            target: Target::Descriptor(7),
            resource: "token".into(),
        }];
        let mut command = Command::new("/bin/true");
        command.env_clear();
        let mut prepared = Prepared::new(
            command,
            &requests,
            vec![SensitiveBytes::new(vec![0, 255]).unwrap()],
        )
        .unwrap();
        let file = &mut prepared._files[0];
        assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o400);
        assert!(file.write_all(b"replacement").is_err());
        assert!(file.set_len(0).is_err());
        assert!(rustix::io::fcntl_getfd(&*file)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));
        let identity = file.metadata().unwrap().ino();
        let descriptor_path = format!("/proc/self/fd/{}", file.as_raw_fd());
        assert!(prepared.run(|| true).unwrap().status.success());
        assert!(
            !std::fs::metadata(descriptor_path).is_ok_and(|metadata| metadata.ino() == identity)
        );
    }

    #[test]
    fn environment_nul_and_projection_count_mismatch_fail_before_child_start() {
        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("must-not-exist");
        let requests = vec![Request {
            target: Target::Environment("TOKEN".into()),
            resource: "token".into(),
        }];
        let mut command = Command::new("/usr/bin/touch");
        command.arg(&marker);
        assert!(Prepared::new(
            command,
            &requests,
            vec![SensitiveBytes::new(vec![1, 0, 2]).unwrap()]
        )
        .is_err());
        assert!(!marker.exists());
        assert!(Prepared::new(Command::new("/bin/true"), &requests, vec![]).is_err());
    }
}
