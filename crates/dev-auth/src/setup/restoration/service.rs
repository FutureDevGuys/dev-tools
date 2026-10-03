use super::*;

mod cgroup;
mod initial;

pub(super) use initial::{require_completion_stopped, synchronize_completion};

const COMMON_PROPERTIES: [&str; 11] = [
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "FragmentPath",
    "DropInPaths",
    "UnitFileState",
    "Job",
    "ControlGroup",
    "ControlPID",
    "NeedDaemonReload",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unit {
    PublicSocket,
    ControlSocket,
    Broker,
}

const UNITS: [Unit; 3] = [Unit::PublicSocket, Unit::ControlSocket, Unit::Broker];

impl Unit {
    fn name(self) -> &'static str {
        match self {
            Self::PublicSocket => "dev-auth-broker.socket",
            Self::ControlSocket => "dev-auth-broker-control.socket",
            Self::Broker => "dev-auth-broker.service",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    Show(Unit),
    DisablePersistent,
    DisableRuntime,
    Stop,
    Reload,
    DisablePersistentUnit(Unit),
    DisableRuntimeUnit(Unit),
    StopUnit(Unit),
}

impl Operation {
    fn arguments(self) -> Vec<std::ffi::OsString> {
        let mut arguments = vec!["--system", "--no-pager", "--no-ask-password"]
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>();
        match self {
            Self::Show(unit) => {
                arguments.extend(["show".into(), "--all".into()]);
                let mut properties = COMMON_PROPERTIES.to_vec();
                if unit == Unit::Broker {
                    properties.push("MainPID");
                }
                arguments.push(format!("--property={}", properties.join(",")).into());
                arguments.push(unit.name().into());
            }
            Self::DisablePersistent => arguments.extend(["--no-reload".into(), "disable".into()]),
            // One reload follows removal of both persistent and runtime
            // activation links. It never starts a product unit.
            Self::DisableRuntime => arguments.extend(["--runtime".into(), "disable".into()]),
            Self::Stop => arguments.push("stop".into()),
            Self::Reload => arguments.push("daemon-reload".into()),
            Self::DisablePersistentUnit(unit) => {
                arguments.extend(["--no-reload".into(), "disable".into(), unit.name().into()])
            }
            Self::DisableRuntimeUnit(unit) => {
                arguments.extend(["--runtime".into(), "disable".into(), unit.name().into()])
            }
            Self::StopUnit(unit) => arguments.extend(["stop".into(), unit.name().into()]),
        }
        if matches!(
            self,
            Self::DisablePersistent | Self::DisableRuntime | Self::Stop
        ) {
            arguments.extend(UNITS.map(|unit| unit.name().into()));
        }
        arguments
    }
}

struct Observation {
    stopped: bool,
    enabled: bool,
    needs_reload: bool,
}

fn parse_observation(unit: Unit, bytes: &[u8]) -> Result<Observation> {
    parse_loaded_observation(unit, &observation_fields(unit, bytes)?, false)
}

fn observation_fields(unit: Unit, bytes: &[u8]) -> Result<BTreeMap<&str, &str>> {
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        bail!("unit observation exceeds content bounds");
    }
    let text = std::str::from_utf8(bytes).context("unit observation is not UTF-8")?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .context("unit observation has malformed fields")?;
        if fields.insert(key, value).is_some() {
            bail!("unit observation has duplicate fields");
        }
    }
    let mut expected = COMMON_PROPERTIES.into_iter().collect::<BTreeSet<_>>();
    if unit == Unit::Broker {
        expected.insert("MainPID");
    }
    if fields.keys().copied().collect::<BTreeSet<_>>() != expected || fields["Id"] != unit.name() {
        bail!("unit observation has unexpected fields or identity");
    }
    Ok(fields)
}

fn parse_loaded_observation(
    unit: Unit,
    fields: &BTreeMap<&str, &str>,
    missing_definition: bool,
) -> Result<Observation> {
    if fields["LoadState"] != "loaded"
        || fields["FragmentPath"] != format!("/etc/systemd/system/{}", unit.name())
        || !fields["DropInPaths"].is_empty()
        || (!fields["ControlGroup"].is_empty()
            && fields["ControlGroup"] != format!("/system.slice/{}", unit.name()))
    {
        bail!("unit observation differs from fixed product ownership");
    }
    let enabled = match fields["UnitFileState"] {
        "enabled" | "enabled-runtime" => true,
        "disabled" | "static" => false,
        "" if missing_definition => false,
        _ => bail!("unit activation state is outside retained service authority"),
    };
    let needs_reload = match fields["NeedDaemonReload"] {
        "yes" => true,
        "no" => false,
        _ => bail!("unit reload state is invalid"),
    };
    let pid = |key| -> Result<u32> {
        let value: &str = fields[key];
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            bail!("unit process identity is invalid");
        }
        value
            .parse()
            .context("unit process identity exceeds its bound")
    };
    let control_pid = pid("ControlPID")?;
    let main_pid = if unit == Unit::Broker {
        pid("MainPID")?
    } else {
        0
    };
    let stopped = matches!(
        (fields["ActiveState"], fields["SubState"]),
        ("inactive", "dead") | ("failed", "failed")
    ) && control_pid == 0
        && main_pid == 0
        && fields["Job"].is_empty();
    Ok(Observation {
        stopped,
        enabled,
        needs_reload,
    })
}

trait ServiceBackend {
    fn execute(&mut self, operation: Operation) -> Result<Vec<u8>>;
    fn require_absence(&mut self, include_broker: bool) -> Result<()>;
}

fn observations(backend: &mut impl ServiceBackend) -> Result<Vec<Observation>> {
    UNITS
        .into_iter()
        .map(|unit| parse_observation(unit, &backend.execute(Operation::Show(unit))?))
        .collect()
}

fn verify_with(backend: &mut impl ServiceBackend, allow_reload: bool) -> Result<()> {
    if observations(backend)?
        .iter()
        .any(|state| !state.stopped || state.enabled || (!allow_reload && state.needs_reload))
    {
        bail!("retained broker units are not inactive");
    }
    backend.require_absence(true)
}

/// Read-only stopped-state evidence for an already-verified fixed candidate.
/// The enclosing setup owner supplies complete asset and admission authority.
pub(super) fn require_candidate_services_stopped() -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("strong candidate completion requires native root");
    }
    verify_with(&mut NativeBackend::new()?, false)
}

fn stop_with(backend: &mut impl ServiceBackend) -> Result<bool> {
    let states = observations(backend)?;
    // Legacy workloads need absence evidence even after participating successor
    // workloads have released the enclosing exclusive setup lease.
    backend.require_absence(false)?;
    let mut changed = false;
    if states.iter().any(|state| state.enabled) {
        backend.execute(Operation::DisablePersistent)?;
        backend.execute(Operation::DisableRuntime)?;
        changed = true;
    }
    if states.iter().any(|state| !state.stopped) {
        backend.execute(Operation::Stop)?;
        changed = true;
    }
    // Command exit is only a request outcome. Unit state, kernel population
    // and socket absence independently establish the stopped postcondition.
    verify_with(backend, true)?;
    Ok(changed)
}

fn synchronize_with(backend: &mut impl ServiceBackend) -> Result<bool> {
    verify_with(backend, true)?;
    let changed = observations(backend)?
        .iter()
        .any(|state| state.needs_reload);
    if changed {
        backend.execute(Operation::Reload)?;
    }
    verify_with(backend, false)?;
    Ok(changed)
}

struct NativeBackend {
    deadline: std::time::Instant,
}

impl NativeBackend {
    fn new() -> Result<Self> {
        validate_root_owned_executable(Path::new("/usr/bin/systemctl"), "system service manager")?;
        Ok(Self {
            deadline: std::time::Instant::now() + Duration::from_secs(60),
        })
    }
}

impl ServiceBackend for NativeBackend {
    fn execute(&mut self, operation: Operation) -> Result<Vec<u8>> {
        let remaining = self
            .deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|value| !value.is_zero())
            .context("retained service operation deadline elapsed")?;
        let arguments = operation.arguments();
        let environment = BTreeMap::from([
            ("LC_ALL".into(), "C".into()),
            ("SYSTEMD_COLORS".into(), "0".into()),
        ]);
        let output = dev_tools_command::run_bounded_command(&dev_tools_command::BoundedCommand {
            executable: Path::new("/usr/bin/systemctl"),
            arguments: &arguments,
            environment: &environment,
            cwd: Some(Path::new("/")),
            timeout: remaining,
            output_limit: 64 * 1024,
        })
        .map_err(|_| anyhow::anyhow!("retained system service request did not complete"))?;
        if !output.status.success() {
            bail!("retained system service request failed");
        }
        Ok(output.stdout)
    }

    fn require_absence(&mut self, include_broker: bool) -> Result<()> {
        cgroup::require_absence(include_broker)?;
        if include_broker {
            require_broker_sockets_absent()?;
        }
        Ok(())
    }
}

impl RetainedInstallationRestoration {
    pub(crate) fn stop_retained_services(&self) -> Result<bool> {
        if self.original.mode == InstallMode::UserOnly {
            return Ok(false);
        }
        self.require_service_authority()?;
        stop_with(&mut NativeBackend::new()?)
    }

    pub(super) fn require_retained_services_stopped(&self) -> Result<()> {
        if self.original.mode == InstallMode::UserOnly {
            return Ok(());
        }
        self.require_service_authority()?;
        verify_with(&mut NativeBackend::new()?, true)
    }

    pub(super) fn synchronize_retained_services(&self) -> Result<bool> {
        if self.original.mode == InstallMode::UserOnly {
            return Ok(false);
        }
        self.require_service_authority()?;
        synchronize_with(&mut NativeBackend::new()?)
    }

    pub(super) fn verify_retained_services_inactive(&self) -> Result<()> {
        if self.original.mode == InstallMode::UserOnly {
            return Ok(());
        }
        self.require_service_authority()?;
        verify_with(&mut NativeBackend::new()?, false)
    }

    fn require_service_authority(&self) -> Result<()> {
        if !nix::unistd::Uid::effective().is_root()
            || self.paths != SetupPaths::strong()
            || self.original.mode != InstallMode::Strong
            || !self.admitted_receipt()?.transparent_aliases.is_empty()
        {
            bail!("retained service control requires inactive native system authority");
        }
        self.verify_inactive_transparent()?;
        // Exact current unit bytes must belong to either retained release.
        // A cached service state never grants ownership of a new unit file.
        let directory = dev_tools_installation::ExistingDocumentDirectory::open(
            Path::new("/etc/systemd/system"),
            0,
        )?;
        for unit in UNITS {
            let path = Path::new("/etc/systemd/system").join(unit.name());
            let document = directory
                .read(
                    OsStr::new(unit.name()),
                    &DocumentAuthority {
                        owner_uid: 0,
                        mode: 0o644,
                        limit: RECEIPT_LIMIT,
                    },
                )?
                .context("retained service unit file is absent")?;
            let key = path.display().to_string();
            if self.original.system_assets.get(&key) != Some(&document.identity.sha256)
                && self.candidate.system_assets.get(&key) != Some(&document.identity.sha256)
            {
                bail!("service unit file is outside retained release authority");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "mutates fixed units; requires an explicitly opted-in disposable systemd container"]
    fn native_disposable_systemd_shutdown_removes_sockets_and_is_idempotent() {
        assert_eq!(
            std::env::var("DEV_AUTH_NATIVE_SYSTEMD_FIXTURE").as_deref(),
            Ok("disposable")
        );
        assert!(nix::unistd::Uid::effective().is_root());
        assert!(Path::new("/run/.containerenv").is_file());
        assert_eq!(
            fs::read_to_string("/proc/1/comm").unwrap().trim(),
            "systemd"
        );
        // No installed product is admitted by this fixture. The outer runner
        // owns the disposable container, including cleanup after test failure.
        for unit in UNITS {
            assert!(!Path::new("/etc/systemd/system").join(unit.name()).exists());
        }
        require_broker_sockets_absent().unwrap();
        cgroup::require_absence(true).unwrap();
        for (path, content, mode) in SYSTEM_ASSETS {
            if Path::new(path).parent() != Some(Path::new("/etc/systemd/system")) {
                continue;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(path)
                .unwrap();
            file.write_all(content.as_bytes()).unwrap();
            file.sync_all().unwrap();
        }
        let run = |arguments: &[&str]| {
            let arguments = ["--system", "--no-pager", "--no-ask-password"]
                .into_iter()
                .chain(arguments.iter().copied())
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>();
            let output =
                dev_tools_command::run_bounded_command(&dev_tools_command::BoundedCommand {
                    executable: Path::new("/usr/bin/systemctl"),
                    arguments: &arguments,
                    environment: &BTreeMap::from([("LC_ALL".into(), "C".into())]),
                    cwd: Some(Path::new("/")),
                    timeout: Duration::from_secs(30),
                    output_limit: 64 * 1024,
                })
                .unwrap();
            assert!(output.status.success(), "fixture systemctl request failed");
        };
        run(&["daemon-reload"]);
        run(&[
            "enable",
            "--now",
            "dev-auth-broker.socket",
            "dev-auth-broker-control.socket",
        ]);
        let states = observations(&mut NativeBackend::new().unwrap()).unwrap();
        assert!(states[..2]
            .iter()
            .all(|state| !state.stopped && state.enabled));
        assert!(require_broker_sockets_absent().is_err());
        assert!(stop_with(&mut NativeBackend::new().unwrap()).unwrap());
        verify_with(&mut NativeBackend::new().unwrap(), false).unwrap();
        assert!(!stop_with(&mut NativeBackend::new().unwrap()).unwrap());
        assert!(!synchronize_with(&mut NativeBackend::new().unwrap()).unwrap());
    }

    #[test]
    #[ignore = "read-only native acceptance requires installed fixed Dev Auth system units"]
    fn native_fixed_service_observations_use_bounded_read_only_queries() {
        let mut backend = NativeBackend::new().unwrap();
        for unit in UNITS {
            let bytes = backend.execute(Operation::Show(unit)).unwrap();
            parse_observation(unit, &bytes).unwrap();
        }
    }

    #[test]
    fn service_observations_reject_unowned_or_ambiguous_units_and_nonterminal_processes() {
        let mut backend = Backend {
            operations: Vec::new(),
            active: false,
            enabled: false,
            populated: false,
            late_population: false,
            needs_reload: false,
        };
        for unit in UNITS {
            let bytes = backend.execute(Operation::Show(unit)).unwrap();
            let text = String::from_utf8(bytes).unwrap();
            assert!(parse_observation(unit, text.as_bytes()).unwrap().stopped);
            for (from, to) in [
                ("LoadState=loaded", "LoadState=not-found"),
                ("DropInPaths=\n", "DropInPaths=/unowned/override.conf\n"),
                (
                    "FragmentPath=/etc/systemd/system/",
                    "FragmentPath=/unowned/",
                ),
                ("UnitFileState=disabled", "UnitFileState=generated"),
                (
                    "ControlGroup=\n",
                    "ControlGroup=/system.slice/unowned.service\n",
                ),
                ("ControlPID=0", "ControlPID=-1"),
                ("NeedDaemonReload=no", "NeedDaemonReload=unknown"),
            ] {
                assert!(
                    parse_observation(unit, text.replace(from, to).as_bytes()).is_err(),
                    "{from}"
                );
            }
            assert!(
                parse_observation(unit, format!("{text}Id={}\n", unit.name()).as_bytes()).is_err()
            );
            assert!(parse_observation(unit, text.replace("Job=\n", "").as_bytes()).is_err());
            for (from, to) in [("ControlPID=0", "ControlPID=7"), ("Job=\n", "Job=11\n")] {
                assert!(
                    !parse_observation(unit, text.replace(from, to).as_bytes())
                        .unwrap()
                        .stopped
                );
            }
            if unit == Unit::Broker {
                assert!(
                    !parse_observation(unit, text.replace("MainPID=0", "MainPID=7").as_bytes())
                        .unwrap()
                        .stopped
                );
            }
        }
        backend.needs_reload = true;
        assert!(verify_with(&mut backend, false).is_err());
        assert!(synchronize_with(&mut backend).unwrap());
        assert!(!synchronize_with(&mut backend).unwrap());
        backend.active = true;
        assert!(synchronize_with(&mut backend).is_err());
    }

    #[test]
    fn retained_service_operations_have_fixed_units_and_no_interactive_or_async_mode() {
        for operation in [
            Operation::DisablePersistent,
            Operation::DisableRuntime,
            Operation::Stop,
        ] {
            let args = operation.arguments();
            assert_eq!(
                &args[args.len() - 3..],
                &UNITS.map(|unit| std::ffi::OsString::from(unit.name()))
            );
            assert!(args.contains(&"--system".into()));
            assert!(args.contains(&"--no-ask-password".into()));
            assert!(!args.contains(&"--no-block".into()));
            assert!(!args.contains(&"--force".into()));
        }
        assert_eq!(
            Operation::Reload.arguments(),
            [
                "--system",
                "--no-pager",
                "--no-ask-password",
                "daemon-reload"
            ]
            .map(std::ffi::OsString::from)
        );
    }

    struct Backend {
        operations: Vec<Operation>,
        active: bool,
        enabled: bool,
        populated: bool,
        late_population: bool,
        needs_reload: bool,
    }

    impl ServiceBackend for Backend {
        fn execute(&mut self, operation: Operation) -> Result<Vec<u8>> {
            self.operations.push(operation);
            match operation {
                Operation::Show(unit) => Ok(format!(
                    "Id={}\nLoadState=loaded\nActiveState={}\nSubState={}\nFragmentPath=/etc/systemd/system/{}\nDropInPaths=\nUnitFileState={}\nJob=\nControlGroup={}\nControlPID=0\nNeedDaemonReload={}\n{}",
                    unit.name(), if self.active { "active" } else { "inactive" },
                    if self.active { if unit == Unit::Broker { "running" } else { "listening" } } else { "dead" },
                    unit.name(), if self.enabled { "enabled" } else { "disabled" },
                    if self.active { format!("/system.slice/{}", unit.name()) } else { String::new() },
                    if self.needs_reload { "yes" } else { "no" },
                    if unit == Unit::Broker { format!("MainPID={}\n", if self.active { 123 } else { 0 }) } else { String::new() },
                ).into_bytes()),
                Operation::DisablePersistent | Operation::DisableRuntime
                    | Operation::DisablePersistentUnit(_) | Operation::DisableRuntimeUnit(_) => {
                    self.enabled = false; Ok(Vec::new())
                }
                Operation::Stop | Operation::StopUnit(_) => { self.active = false; Ok(Vec::new()) },
                Operation::Reload => { self.needs_reload = false; Ok(Vec::new()) },
            }
        }

        fn require_absence(&mut self, include_broker: bool) -> Result<()> {
            if self.populated || (include_broker && self.late_population) {
                bail!("fixture domain remains populated");
            }
            Ok(())
        }
    }

    #[test]
    fn retained_service_stop_requires_terminal_domain_evidence_and_is_repeatable() {
        let mut backend = Backend {
            operations: Vec::new(),
            active: true,
            enabled: true,
            populated: false,
            late_population: false,
            needs_reload: false,
        };
        assert!(stop_with(&mut backend).unwrap());
        assert!(!backend.active);
        assert!(!backend.enabled);
        let changes = backend
            .operations
            .iter()
            .filter(|operation| !matches!(operation, Operation::Show(_)))
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(
            changes,
            [
                Operation::DisablePersistent,
                Operation::DisableRuntime,
                Operation::Stop
            ]
        );
        backend.operations.clear();
        assert!(!stop_with(&mut backend).unwrap());
        assert!(backend
            .operations
            .iter()
            .all(|operation| matches!(operation, Operation::Show(_))));
        backend.populated = true;
        backend.active = true;
        backend.operations.clear();
        assert!(stop_with(&mut backend).is_err());
        assert!(backend
            .operations
            .iter()
            .all(|operation| matches!(operation, Operation::Show(_))));
        backend.populated = false;
        backend.late_population = true;
        assert!(stop_with(&mut backend).is_err());
        assert!(
            !backend.active,
            "a successful stop request is not terminal domain evidence"
        );
    }
}
