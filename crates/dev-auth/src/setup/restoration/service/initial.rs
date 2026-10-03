//! Initial generations can withdraw fixed definitions instead of restoring
//! earlier ones. Missing definitions never grant permission to stop a process.
use super::*;

struct InitialObservation {
    loaded: bool,
    state: Observation,
}

fn parse_initial_observation(
    unit: Unit,
    bytes: &[u8],
    file_present: bool,
) -> Result<InitialObservation> {
    let fields = observation_fields(unit, bytes)?;
    if fields["LoadState"] == "loaded" {
        let state = parse_loaded_observation(unit, &fields, !file_present)?;
        if !file_present && (!state.stopped || state.enabled) {
            bail!("missing unit definition cannot authorize service shutdown");
        }
        return Ok(InitialObservation {
            loaded: true,
            state,
        });
    }
    if fields["LoadState"] != "not-found"
        || !matches!(
            (fields["ActiveState"], fields["SubState"]),
            ("inactive", "dead") | ("failed", "failed")
        )
        || !fields["FragmentPath"].is_empty()
        || !fields["DropInPaths"].is_empty()
        || !fields["UnitFileState"].is_empty()
        || !fields["Job"].is_empty()
        || !fields["ControlGroup"].is_empty()
        || fields["ControlPID"] != "0"
        || fields["NeedDaemonReload"] != "no"
        || (unit == Unit::Broker && fields["MainPID"] != "0")
    {
        bail!("unit absence is not an exact terminal system observation");
    }
    Ok(InitialObservation {
        loaded: false,
        state: Observation {
            stopped: true,
            enabled: false,
            needs_reload: false,
        },
    })
}

fn initial_observations(
    backend: &mut impl ServiceBackend,
    files: &[bool; 3],
) -> Result<Vec<InitialObservation>> {
    UNITS
        .into_iter()
        .zip(files)
        .map(|(unit, present)| {
            parse_initial_observation(unit, &backend.execute(Operation::Show(unit))?, *present)
        })
        .collect()
}

fn verify_initial_stopped_with(
    backend: &mut impl ServiceBackend,
    files: &[bool; 3],
    require_missing: bool,
) -> Result<()> {
    if initial_observations(backend, files)?
        .iter()
        .any(|observation| {
            !observation.state.stopped
                || observation.state.enabled
                || (require_missing && (observation.loaded || observation.state.needs_reload))
        })
    {
        bail!("initial broker unit retirement is incomplete");
    }
    backend.require_absence(true)
}

fn stop_initial_with(backend: &mut impl ServiceBackend, files: &[bool; 3]) -> Result<bool> {
    let observations = initial_observations(backend, files)?;
    backend.require_absence(false)?;
    let mut changed = false;
    for (unit, observation) in UNITS.into_iter().zip(&observations) {
        if observation.state.enabled {
            backend.execute(Operation::DisablePersistentUnit(unit))?;
            backend.execute(Operation::DisableRuntimeUnit(unit))?;
            changed = true;
        }
    }
    for (unit, observation) in UNITS.into_iter().zip(&observations) {
        if !observation.state.stopped {
            backend.execute(Operation::StopUnit(unit))?;
            changed = true;
        }
    }
    verify_initial_stopped_with(backend, files, false)?;
    Ok(changed)
}

fn synchronize_initial_with(backend: &mut impl ServiceBackend) -> Result<bool> {
    let files = [false; 3];
    verify_initial_stopped_with(backend, &files, false)?;
    let changed = initial_observations(backend, &files)?
        .iter()
        .any(|observation| observation.loaded || observation.state.needs_reload);
    if changed {
        backend.execute(Operation::Reload)?;
    }
    verify_initial_stopped_with(backend, &files, true)?;
    Ok(changed)
}

pub(in crate::setup::restoration) fn require_completion_stopped(files: &[bool; 3]) -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("strong definition completion requires native root");
    }
    verify_initial_stopped_with(&mut NativeBackend::new()?, files, false)
}

fn synchronize_completion_with(
    backend: &mut impl ServiceBackend,
    mut record_change: impl FnMut(bool),
) -> Result<bool> {
    verify_initial_stopped_with(backend, &[true; 3], false)?;
    let changed = initial_observations(backend, &[true; 3])?
        .iter()
        .any(|observation| !observation.loaded || observation.state.needs_reload);
    if changed {
        backend.execute(Operation::Reload)?;
        record_change(true);
    }
    verify_with(backend, false)?;
    Ok(changed)
}

pub(in crate::setup::restoration) fn synchronize_completion(
    record_change: impl FnMut(bool),
) -> Result<bool> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("strong definition completion requires native root");
    }
    synchronize_completion_with(&mut NativeBackend::new()?, record_change)
}

impl InitialInstallationRestoration {
    fn initial_service_authority(&self) -> Result<[bool; 3]> {
        self.require_initial_native_authority()?;
        if self
            .admitted_receipt()?
            .is_some_and(|receipt| !receipt.transparent_aliases.is_empty())
        {
            bail!("initial service control requires inactive integrations");
        }
        self.verify_inactive_transparent()?;
        let directory = dev_tools_installation::ExistingDocumentDirectory::open(
            Path::new("/etc/systemd/system"),
            0,
        )?;
        let mut present = [false; 3];
        for (index, unit) in UNITS.into_iter().enumerate() {
            if let Some(document) = directory.read(
                OsStr::new(unit.name()),
                &DocumentAuthority {
                    owner_uid: 0,
                    mode: 0o644,
                    limit: RECEIPT_LIMIT,
                },
            )? {
                let key = format!("/etc/systemd/system/{}", unit.name());
                if self.candidate.system_assets.get(&key) != Some(&document.identity.sha256) {
                    bail!("initial service file differs from retained candidate authority");
                }
                present[index] = true;
            }
        }
        Ok(present)
    }

    pub(in crate::setup::restoration) fn stop_initial_services(&self) -> Result<bool> {
        if self.candidate.mode == InstallMode::UserOnly {
            return Ok(false);
        }
        let files = self.initial_service_authority()?;
        stop_initial_with(&mut NativeBackend::new()?, &files)
    }

    pub(in crate::setup::restoration) fn require_initial_services_stopped(&self) -> Result<()> {
        if self.candidate.mode == InstallMode::UserOnly {
            return Ok(());
        }
        let files = self.initial_service_authority()?;
        verify_initial_stopped_with(&mut NativeBackend::new()?, &files, false)
    }

    pub(in crate::setup::restoration) fn synchronize_initial_services(&self) -> Result<bool> {
        if self.candidate.mode == InstallMode::UserOnly {
            return Ok(false);
        }
        if self
            .initial_service_authority()?
            .iter()
            .any(|present| *present)
        {
            bail!("initial unit definitions remain installed");
        }
        synchronize_initial_with(&mut NativeBackend::new()?)
    }

    pub(in crate::setup::restoration) fn verify_initial_services_absent(&self) -> Result<()> {
        if self.candidate.mode == InstallMode::UserOnly {
            return Ok(());
        }
        if self
            .initial_service_authority()?
            .iter()
            .any(|present| *present)
        {
            bail!("initial unit definitions remain installed");
        }
        verify_initial_stopped_with(&mut NativeBackend::new()?, &[false; 3], true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn absent(unit: Unit) -> String {
        format!("Id={}\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nFragmentPath=\nDropInPaths=\nUnitFileState=\nJob=\nControlGroup=\nControlPID=0\nNeedDaemonReload=no\n{}", unit.name(),
            if unit == Unit::Broker { "MainPID=0\n" } else { "" })
    }

    struct InitialBackend {
        files: [bool; 3],
        loaded: [bool; 3],
        active: [bool; 3],
        enabled: [bool; 3],
        late_population: bool,
        stuck_reload: bool,
        operations: Vec<Operation>,
    }

    impl ServiceBackend for InitialBackend {
        fn execute(&mut self, operation: Operation) -> Result<Vec<u8>> {
            self.operations.push(operation);
            let index = |unit| UNITS.iter().position(|expected| *expected == unit).unwrap();
            match operation {
                Operation::Show(unit) => {
                    let i = index(unit);
                    if !self.loaded[i] {
                        return Ok(absent(unit).into_bytes());
                    }
                    Ok(format!("Id={}\nLoadState=loaded\nActiveState={}\nSubState={}\nFragmentPath=/etc/systemd/system/{}\nDropInPaths=\nUnitFileState={}\nJob=\nControlGroup=\nControlPID=0\nNeedDaemonReload={}\n{}",
                        unit.name(), if self.active[i] { "active" } else { "inactive" },
                        if self.active[i] { "running" } else { "dead" }, unit.name(),
                        if !self.files[i] { "" } else if self.enabled[i] { "enabled" } else { "disabled" },
                        if self.files[i] { "no" } else { "yes" },
                        if unit == Unit::Broker { "MainPID=0\n" } else { "" }).into_bytes())
                }
                Operation::DisablePersistentUnit(unit) | Operation::DisableRuntimeUnit(unit) => {
                    self.enabled[index(unit)] = false;
                    Ok(Vec::new())
                }
                Operation::StopUnit(unit) => {
                    self.active[index(unit)] = false;
                    Ok(Vec::new())
                }
                Operation::Reload => {
                    if !self.stuck_reload {
                        self.loaded = self.files;
                    }
                    Ok(Vec::new())
                }
                _ => panic!("initial fixture received a non-selected service mutation"),
            }
        }

        fn require_absence(&mut self, include_broker: bool) -> Result<()> {
            if include_broker && self.late_population {
                bail!("fixture broker domain remains populated");
            }
            Ok(())
        }
    }

    #[test]
    fn completion_reload_requires_loaded_stopped_definitions_and_preserves_known_change() {
        let mut backend = InitialBackend {
            files: [true; 3],
            loaded: [false; 3],
            active: [false; 3],
            enabled: [false; 3],
            late_population: false,
            stuck_reload: true,
            operations: Vec::new(),
        };
        let mut changed = false;
        assert!(synchronize_completion_with(&mut backend, |value| changed |= value).is_err());
        assert!(
            changed,
            "a successful reload request is retained after failed observation"
        );
        backend.stuck_reload = false;
        assert!(synchronize_completion_with(&mut backend, |_| {}).unwrap());
        backend.operations.clear();
        assert!(!synchronize_completion_with(&mut backend, |_| {}).unwrap());
        assert!(backend
            .operations
            .iter()
            .all(|operation| matches!(operation, Operation::Show(_))));
        backend.active[0] = true;
        backend.operations.clear();
        assert!(synchronize_completion_with(&mut backend, |_| {}).is_err());
        assert!(backend
            .operations
            .iter()
            .all(|operation| matches!(operation, Operation::Show(_))));
        backend.active[0] = false;
        backend.late_population = true;
        assert!(synchronize_completion_with(&mut backend, |_| {}).is_err());
    }

    #[test]
    fn initial_shutdown_preserves_missing_units_and_requires_terminal_domain_evidence() {
        let files = [false, true, true];
        let mut backend = InitialBackend {
            files,
            loaded: [false, true, true],
            active: [false, true, false],
            enabled: [false, true, false],
            late_population: false,
            stuck_reload: false,
            operations: Vec::new(),
        };
        assert!(stop_initial_with(&mut backend, &files).unwrap());
        assert_eq!(
            backend
                .operations
                .iter()
                .filter(|operation| !matches!(operation, Operation::Show(_)))
                .copied()
                .collect::<Vec<_>>(),
            [
                Operation::DisablePersistentUnit(Unit::ControlSocket),
                Operation::DisableRuntimeUnit(Unit::ControlSocket),
                Operation::StopUnit(Unit::ControlSocket)
            ]
        );
        backend.operations.clear();
        assert!(!stop_initial_with(&mut backend, &files).unwrap());
        assert!(backend
            .operations
            .iter()
            .all(|operation| matches!(operation, Operation::Show(_))));
        backend.loaded[0] = true;
        backend.active[0] = true;
        backend.operations.clear();
        assert!(stop_initial_with(&mut backend, &files).is_err());
        assert!(backend
            .operations
            .iter()
            .all(|operation| matches!(operation, Operation::Show(_))));
        backend.loaded[0] = false;
        backend.active[0] = false;
        backend.active[1] = true;
        backend.late_population = true;
        assert!(stop_initial_with(&mut backend, &files).is_err());
        assert!(
            !backend.active[1],
            "a completed stop request does not establish domain absence"
        );
    }

    #[test]
    fn initial_reload_requires_observed_definition_absence_and_has_an_unchanged_retry() {
        let mut backend = InitialBackend {
            files: [false; 3],
            loaded: [true; 3],
            active: [false; 3],
            enabled: [false; 3],
            late_population: false,
            stuck_reload: true,
            operations: Vec::new(),
        };
        assert!(
            synchronize_initial_with(&mut backend).is_err(),
            "successful reload with still-loaded definitions is not absence"
        );
        backend.stuck_reload = false;
        assert!(synchronize_initial_with(&mut backend).unwrap());
        backend.operations.clear();
        assert!(!synchronize_initial_with(&mut backend).unwrap());
        assert!(backend
            .operations
            .iter()
            .all(|operation| matches!(operation, Operation::Show(_))));
        backend.late_population = true;
        assert!(synchronize_initial_with(&mut backend).is_err());
    }

    #[test]
    fn initial_unit_absence_is_explicit_and_never_relaxes_retained_service_ownership() {
        for unit in UNITS {
            let bytes = absent(unit);
            let observed = parse_initial_observation(unit, bytes.as_bytes(), false).unwrap();
            assert!(!observed.loaded && observed.state.stopped && !observed.state.enabled);
            assert!(parse_observation(unit, bytes.as_bytes()).is_err());
            for (from, to) in [
                ("LoadState=not-found", "LoadState=error"),
                ("ActiveState=inactive", "ActiveState=active"),
                ("SubState=dead", "SubState=running"),
                ("FragmentPath=\n", "FragmentPath=/foreign/unit\n"),
                ("DropInPaths=\n", "DropInPaths=/foreign/dropin\n"),
                ("UnitFileState=\n", "UnitFileState=enabled\n"),
                ("Job=\n", "Job=7\n"),
                (
                    "ControlGroup=\n",
                    "ControlGroup=/system.slice/foreign.service\n",
                ),
                ("ControlPID=0", "ControlPID=1"),
                ("NeedDaemonReload=no", "NeedDaemonReload=yes"),
            ] {
                assert!(
                    parse_initial_observation(unit, bytes.replace(from, to).as_bytes(), false)
                        .is_err(),
                    "{from}"
                );
            }
            if unit == Unit::Broker {
                assert!(parse_initial_observation(
                    unit,
                    bytes.replace("MainPID=0", "MainPID=1").as_bytes(),
                    false
                )
                .is_err());
            }
            assert!(
                parse_initial_observation(unit, format!("{bytes}Job=\n").as_bytes(), false)
                    .is_err()
            );
            assert!(
                parse_initial_observation(unit, bytes.replace("Job=\n", "").as_bytes(), false)
                    .is_err()
            );
            let loaded = bytes
                .replace("LoadState=not-found", "LoadState=loaded")
                .replace(
                    "FragmentPath=\n",
                    &format!("FragmentPath=/etc/systemd/system/{}\n", unit.name()),
                );
            assert!(
                parse_initial_observation(unit, loaded.as_bytes(), false)
                    .unwrap()
                    .loaded
            );
            assert!(parse_initial_observation(unit, loaded.as_bytes(), true).is_err());
            assert!(parse_initial_observation(
                unit,
                loaded.replace("ControlPID=0", "ControlPID=1").as_bytes(),
                false
            )
            .is_err());
            assert!(parse_initial_observation(
                unit,
                loaded
                    .replace("UnitFileState=\n", "UnitFileState=enabled\n")
                    .as_bytes(),
                false
            )
            .is_err());
        }
    }
}
