//! Fixed native observations and service transitions for the privilege component.
use super::*;
use std::time::{Duration, Instant};

const PROPERTIES: &str = "Id,LoadState,ActiveState,SubState,FragmentPath,DropInPaths,ControlGroup,MainPID,ControlPID,Job,UnitFileState,KillMode,SendSIGKILL,Delegate,ExitType,RemainAfterExit,TimeoutStopUSec";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub loaded: bool,
    pub stopped: bool,
    pub enabled: bool,
}

pub(super) fn run(program: &Path, arguments: &[std::ffi::OsString]) -> Result<Vec<u8>> {
    crate::setup::validate_root_owned_executable(program, "native privilege setup tool")?;
    let output = dev_tools_command::run_bounded_command(&dev_tools_command::BoundedCommand {
        executable: program,
        arguments,
        environment: &BTreeMap::from([("LC_ALL".into(), "C".into())]),
        cwd: Some(Path::new("/")),
        timeout: Duration::from_secs(10),
        output_limit: DOCUMENT_LIMIT as usize,
    })?;
    if !output.status.success() {
        bail!("native privilege setup operation failed");
    }
    Ok(output.stdout)
}

fn systemctl(arguments: &[&str]) -> Result<Vec<u8>> {
    let arguments = ["--system", "--no-pager", "--no-ask-password"]
        .into_iter()
        .chain(arguments.iter().copied())
        .map(std::ffi::OsString::from)
        .collect::<Vec<_>>();
    run(Path::new("/usr/bin/systemctl"), &arguments)
}

pub(super) fn observe() -> Result<State> {
    parse(&systemctl(&[
        "show",
        "--all",
        &format!("--property={PROPERTIES}"),
        UNIT,
    ])?)
}

fn parse(bytes: &[u8]) -> Result<State> {
    let text = std::str::from_utf8(bytes).context("native service observation is not UTF-8")?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .context("malformed native service observation")?;
        if fields.insert(key, value).is_some() {
            bail!("duplicate native service observation");
        }
    }
    if fields.keys().copied().collect::<BTreeSet<_>>() != PROPERTIES.split(',').collect()
        || fields["Id"] != UNIT
        || !fields["DropInPaths"].is_empty()
        || (!fields["ControlGroup"].is_empty()
            && fields["ControlGroup"] != format!("/system.slice/{UNIT}"))
    {
        bail!("privilege service observation has unowned authority");
    }
    let stopped = matches!(
        (fields["ActiveState"], fields["SubState"]),
        ("inactive", "dead") | ("failed", "failed")
    ) && fields["MainPID"] == "0"
        && fields["ControlPID"] == "0"
        && fields["Job"].is_empty();
    if fields["LoadState"] == "not-found" {
        if !stopped || !fields["FragmentPath"].is_empty() || !fields["UnitFileState"].is_empty() {
            bail!("absent privilege service has live or foreign authority");
        }
        return Ok(State {
            loaded: false,
            stopped: true,
            enabled: false,
        });
    }
    if fields["LoadState"] != "loaded"
        || fields["FragmentPath"] != SERVICE
        || fields["KillMode"] != "control-group"
        || fields["SendSIGKILL"] != "yes"
        || fields["Delegate"] != "no"
        || fields["ExitType"] != "main"
        || fields["RemainAfterExit"] != "no"
        || fields["TimeoutStopUSec"] != "5s"
        || !fields["Job"].is_empty()
    {
        bail!("privilege service lacks its owned teardown contract");
    }
    let enabled = match fields["UnitFileState"] {
        "enabled" | "enabled-runtime" => true,
        "disabled" | "static" => false,
        _ => bail!("privilege activation links have unsupported ownership"),
    };
    if !stopped
        && (fields["ActiveState"] != "active"
            || fields["SubState"] != "running"
            || fields["MainPID"]
                .parse::<u32>()
                .ok()
                .filter(|pid| *pid > 0)
                .is_none())
    {
        bail!("privilege service has a nonterminal transition");
    }
    Ok(State {
        loaded: true,
        stopped,
        enabled,
    })
}

pub(super) fn stop() -> Result<bool> {
    let before = observe()?;
    if before.enabled {
        systemctl(&["disable", "--no-reload", UNIT])?;
        systemctl(&["disable", "--runtime", UNIT])?;
    }
    if !before.stopped {
        systemctl(&["stop", UNIT])?;
    }
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let state = observe()?;
        if state.stopped
            && !state.enabled
            && crate::setup::restoration::require_privilege_domain_empty().is_ok()
        {
            return Ok(before.enabled || !before.stopped);
        }
        if Instant::now() >= until {
            bail!("privilege service cleanup is incomplete");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub(super) fn reload() -> Result<()> {
    systemctl(&["daemon-reload"])?;
    Ok(())
}

pub(super) fn activate() -> Result<()> {
    systemctl(&["enable", UNIT])?;
    systemctl(&["start", UNIT])?;
    let state = observe()?;
    if !state.loaded || state.stopped || !state.enabled {
        bail!("privilege service did not activate");
    }
    Ok(())
}

pub(super) fn sudo_compatibility(owned_group: bool) -> Result<()> {
    let bytes = run(
        Path::new("/usr/bin/cvtsudoers"),
        &["-f".into(), "json".into(), "/etc/sudoers".into()],
    )?;
    check_sudoers_export(&bytes, owned_group)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation() -> String {
        format!("Id={UNIT}\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nFragmentPath={SERVICE}\nDropInPaths=\nControlGroup=\nMainPID=0\nControlPID=0\nJob=\nUnitFileState=disabled\nKillMode=control-group\nSendSIGKILL=yes\nDelegate=no\nExitType=main\nRemainAfterExit=no\nTimeoutStopUSec=5s\n")
    }

    #[test]
    fn service_identity_and_teardown_are_not_inferred_from_an_inactive_label() {
        let before = observation();
        assert!(parse(before.as_bytes()).unwrap().stopped);
        for (from, to) in [
            ("MainPID=0", "MainPID=42"),
            ("Delegate=no", "Delegate=yes"),
            ("KillMode=control-group", "KillMode=process"),
            ("TimeoutStopUSec=5s", "TimeoutStopUSec=90s"),
            ("DropInPaths=", "DropInPaths=/independent.conf"),
            ("Job=", "Job=45"),
        ] {
            assert!(
                parse(before.replace(from, to).as_bytes()).is_err(),
                "{from}"
            );
        }
        assert!(parse(format!("{before}MainPID=0\n").as_bytes()).is_err());
    }
}
