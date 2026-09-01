use anyhow::{bail, Context, Result};
use std::io::{self, Read};
use zeroize::Zeroize;

const REQUEST_LIMIT: u64 = 64 * 1024;

#[cfg(unix)]
fn exit_status_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(255)
}

#[cfg(not(unix))]
fn exit_status_code(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(255)
}

fn usage() -> &'static str {
    "Usage:\n  dev-auth build-info\n  dev-auth setup discover [--mode strong|user-only]\n  dev-auth setup readiness [--mode strong|user-only]\n  dev-auth setup verify-release --root PATH --manifest PATH --artifact PATH\n  dev-auth setup plan-release --root PATH --manifest PATH --artifact PATH [--mode strong|user-only] [--activate] --output PATH\n  dev-auth setup plan [--deployment PATH] [--mode strong|user-only] [--channel stable] [--offline] [--activation transparent|inactive] [--administrator-policy PATH] [--user-config USER=PATH]... [--user-policy USER=PATH]... [--credential-intent SLOT=preserve|enroll-if-absent|rotate|revoke]... --output PATH [--format human|json]\n  dev-auth setup apply --plan PATH --sha256 HEX [--credential-stdin SLOT] [--credential-fd SLOT=FD]... [--credential-file SLOT=PATH]... [--format human|json]\n  dev-auth setup migrate-v1-preview --output PATH\n  dev-auth setup migrate-v1 --config PATH --sha256 HEX --v1-sha256 HEX\n  dev-auth setup install-policy --source PATH --sha256 HEX\n  dev-auth setup update-policy --source PATH --sha256 HEX --current-sha256 HEX\n  dev-auth setup install-user-policy --source PATH --sha256 HEX\n  dev-auth setup update-user-policy --source PATH --sha256 HEX --current-sha256 HEX\n  dev-auth setup install-user-config --source PATH --sha256 HEX\n  dev-auth setup update-user-config --source PATH --sha256 HEX --current-sha256 HEX\n  dev-auth setup enroll-system|enroll-user\n  dev-auth setup rotate-system|rotate-user\n  dev-auth setup revoke-system|revoke-user\n  dev-auth setup start-system\n  dev-auth setup stop-system\n  dev-auth setup verify [--mode strong|user-only]\n  dev-auth setup repair [--mode strong|user-only]\n  dev-auth setup rollback [--mode strong|user-only]\n  dev-auth setup activate [--mode strong|user-only]\n  dev-auth setup deactivate [--mode strong|user-only]\n  dev-auth setup uninstall [--mode strong|user-only]\n  dev-auth setup purge-system-state|purge-user-state\n  dev-auth reconcile plan --source PATH --output PLAN --format json\n  dev-auth reconcile apply --plan PLAN --sha256 HEX --format json\n  dev-auth reconcile verify --source PATH --format json\n  dev-auth workload launch NAME -- [args...]\n  dev-auth broker serve\n  dev-auth enroll\n  dev-auth validate [--online]\n  dev-auth workspace-status\n  dev-auth exec --profile NAME -- COMMAND [args...]\n  dev-auth agent --profile NAME\n  dev-auth agent-endpoint\n  dev-auth ssh-load --profile NAME\n  dev-auth ssh-public --profile NAME --purpose authentication|signing\n  dev-auth status [--broker]\n  dev-auth explain git|gh\n  dev-auth purge"
}

#[cfg(target_os = "linux")]
fn run_workload_os() -> Result<i32> {
    let mut arguments = std::env::args_os().skip(2);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("launch")) {
        bail!("workload requires the operation launch");
    }
    let workload = arguments
        .next()
        .context("workload launch requires a configured workload name")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("workload name is not UTF-8"))?;
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--")) {
        bail!("workload launch requires -- before workload arguments");
    }
    let arguments = arguments.collect::<Vec<_>>();
    let status = dev_auth::supervisor::run_workload_alias(&workload, &arguments)?;
    Ok(exit_status_code(status))
}

#[cfg(target_os = "linux")]
fn run_workload_alias_os(workload: &str) -> Result<i32> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let status = dev_auth::supervisor::run_workload_alias(workload, &arguments)?;
    Ok(exit_status_code(status))
}

#[cfg(target_os = "linux")]
fn run_supervisor_os() -> Result<i32> {
    let mut arguments = std::env::args_os().skip(2);
    let operation = arguments
        .next()
        .context("supervisor operation is missing")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("supervisor operation is not UTF-8"))?;
    run_supervisor_arguments(&operation, &mut arguments)
}

#[cfg(target_os = "linux")]
fn run_privileged_launcher_os() -> Result<i32> {
    let mut arguments = std::env::args_os().skip(1);
    run_supervisor_arguments("dispatch", &mut arguments)
}

#[cfg(target_os = "linux")]
fn run_supervisor_arguments(
    operation: &str,
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<i32> {
    if !matches!(operation, "dispatch" | "launch")
        || arguments.next().as_deref() != Some(std::ffi::OsStr::new("--uid"))
    {
        bail!("supervisor requires dispatch or launch with exact public selectors");
    }
    let owner_uid = arguments
        .next()
        .context("supervisor owner UID is missing")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("supervisor owner UID is not UTF-8"))?
        .parse::<u32>()
        .context("supervisor owner UID is invalid")?;
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--workload")) {
        bail!("supervisor workload selector is missing");
    }
    let workload = arguments
        .next()
        .context("supervisor workload name is missing")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("supervisor workload name is not UTF-8"))?;
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--cwd")) {
        bail!("supervisor current-directory selector is missing");
    }
    let cwd = std::path::PathBuf::from(
        arguments
            .next()
            .context("supervisor current directory is missing")?,
    );
    let session_id = if operation == "launch" {
        if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--session")) {
            bail!("supervisor session selector is missing");
        }
        Some(
            arguments
                .next()
                .context("supervisor session identifier is missing")?
                .into_string()
                .map_err(|_| anyhow::anyhow!("supervisor session identifier is not UTF-8"))?,
        )
    } else {
        None
    };
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--launcher-pid")) {
        bail!("supervisor launcher PID selector is missing");
    }
    let launcher_pid = arguments
        .next()
        .context("supervisor launcher PID is missing")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("supervisor launcher PID is not UTF-8"))?
        .parse::<u32>()
        .context("supervisor launcher PID is invalid")?;
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--environment-socket")) {
        bail!("supervisor environment socket selector is missing");
    }
    let environment_socket = std::path::PathBuf::from(
        arguments
            .next()
            .context("supervisor environment socket is missing")?,
    );
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--")) {
        bail!("supervisor requires -- before workload arguments");
    }
    let arguments = arguments.collect::<Vec<_>>();
    if let Some(session_id) = session_id {
        let status = dev_auth::supervisor::run_root_supervisor(
            owner_uid,
            &workload,
            &cwd,
            &session_id,
            launcher_pid,
            &environment_socket,
            &arguments,
        )?;
        Ok(exit_status_code(status))
    } else {
        dev_auth::supervisor::run_root_dispatcher(
            owner_uid,
            &workload,
            &cwd,
            launcher_pid,
            &environment_socket,
            &arguments,
        )?;
        bail!("privileged workload dispatcher returned unexpectedly")
    }
}

#[cfg(target_os = "linux")]
fn run_supervisor_child_os() -> Result<i32> {
    let mut arguments = std::env::args_os().skip(2);
    let session_id = arguments
        .next()
        .context("supervisor child session is missing")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("supervisor child session is not UTF-8"))?;
    let workload = arguments
        .next()
        .context("supervisor child workload is missing")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("supervisor child workload is not UTF-8"))?;
    let cgroup = std::path::PathBuf::from(
        arguments
            .next()
            .context("supervisor child cgroup is missing")?,
    );
    let launcher = std::path::PathBuf::from(
        arguments
            .next()
            .context("supervisor child launcher is missing")?,
    );
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--sandbox")) {
        bail!("supervisor child sandbox selector is missing");
    }
    let sandbox = match arguments.next().as_deref() {
        Some(value) if value == std::ffi::OsStr::new("none") => None,
        Some(value) if value == std::ffi::OsStr::new("configured") => {
            let executable = std::path::PathBuf::from(
                arguments
                    .next()
                    .context("supervisor child sandbox executable is missing")?,
            );
            let argument_separator = match arguments.next().as_deref() {
                Some(value) if value == std::ffi::OsStr::new("separator") => true,
                Some(value) if value == std::ffi::OsStr::new("direct") => false,
                _ => bail!("supervisor child sandbox separator mode is invalid"),
            };
            let count = arguments
                .next()
                .context("supervisor child sandbox argument count is missing")?
                .into_string()
                .map_err(|_| anyhow::anyhow!("sandbox argument count is not UTF-8"))?
                .parse::<usize>()
                .context("supervisor child sandbox argument count is invalid")?;
            if count > 128 {
                bail!("supervisor child sandbox argument count is oversized");
            }
            let mut adapter_arguments = Vec::with_capacity(count);
            for _ in 0..count {
                adapter_arguments.push(
                    arguments
                        .next()
                        .context("supervisor child sandbox argument is missing")?,
                );
            }
            Some(dev_auth::supervisor::SandboxLaunch {
                executable,
                arguments: adapter_arguments,
                argument_separator,
            })
        }
        _ => bail!("supervisor child sandbox selector is invalid"),
    };
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--gate-fd")) {
        bail!("supervisor child admission gate selector is missing");
    }
    let gate_fd = arguments
        .next()
        .context("supervisor child admission gate is missing")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("supervisor child admission gate is not UTF-8"))?
        .parse::<std::os::fd::RawFd>()
        .context("supervisor child admission gate is invalid")?;
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--")) {
        bail!("supervisor child requires -- before workload arguments");
    }
    let arguments = arguments.collect::<Vec<_>>();
    dev_auth::supervisor::run_supervisor_child(
        &session_id,
        &workload,
        &cgroup,
        &launcher,
        sandbox.as_ref(),
        gate_fd,
        &arguments,
    )?;
    bail!("supervisor child returned unexpectedly")
}

#[cfg(target_os = "linux")]
fn run_sandbox_child_os() -> Result<i32> {
    let mut arguments = std::env::args_os().skip(2);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--session")) {
        bail!("sandbox child session selector is missing");
    }
    let session_id = arguments
        .next()
        .context("sandbox child session is missing")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("sandbox child session is not UTF-8"))?;
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--workload")) {
        bail!("sandbox child workload selector is missing");
    }
    let workload = arguments
        .next()
        .context("sandbox child workload is missing")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("sandbox child workload is not UTF-8"))?;
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--launcher")) {
        bail!("sandbox child launcher selector is missing");
    }
    let launcher = std::path::PathBuf::from(
        arguments
            .next()
            .context("sandbox child launcher is missing")?,
    );
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--")) {
        bail!("sandbox child requires -- before workload arguments");
    }
    let arguments = arguments.collect::<Vec<_>>();
    dev_auth::supervisor::run_sandbox_child(&session_id, &workload, &launcher, &arguments)?;
    bail!("sandbox child returned unexpectedly")
}

#[cfg(target_os = "linux")]
fn run_agent_proxy_os() -> Result<i32> {
    let mut arguments = std::env::args_os().skip(2);
    let selector = |arguments: &mut std::iter::Skip<std::env::ArgsOs>, expected: &str| {
        if arguments.next().as_deref() != Some(std::ffi::OsStr::new(expected)) {
            bail!("broker SSH agent selector is invalid");
        }
        arguments
            .next()
            .context("broker SSH agent selector value is missing")
    };
    let session = selector(&mut arguments, "--session")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("broker SSH agent session is not UTF-8"))?;
    let profile = selector(&mut arguments, "--profile")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("broker SSH agent profile is not UTF-8"))?;
    let purpose = selector(&mut arguments, "--purpose")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("broker SSH agent purpose is not UTF-8"))?;
    let purpose = match purpose.as_str() {
        "git-signing" => dev_auth::broker_protocol::SshOperationPurpose::GitSigning,
        "authentication" => dev_auth::broker_protocol::SshOperationPurpose::Authentication,
        _ => bail!("broker SSH agent purpose is invalid"),
    };
    let socket = std::path::PathBuf::from(selector(&mut arguments, "--socket")?);
    let broker = std::path::PathBuf::from(selector(&mut arguments, "--broker")?);
    if arguments.next().is_some() {
        bail!("broker SSH agent received trailing arguments");
    }
    dev_auth::broker_agent::run_agent_proxy(&session, &profile, purpose, &socket, &broker)?;
    bail!("broker SSH agent stopped unexpectedly")
}

#[cfg(unix)]
fn setup_mode(value: Option<&str>) -> Result<dev_auth::setup::InstallMode> {
    match value.unwrap_or("strong") {
        "strong" => Ok(dev_auth::setup::InstallMode::Strong),
        "user-only" => Ok(dev_auth::setup::InstallMode::UserOnly),
        _ => bail!("setup mode must be strong or user-only"),
    }
}

#[cfg(unix)]
fn setup_paths(mode: dev_auth::setup::InstallMode) -> Result<dev_auth::setup::SetupPaths> {
    match mode {
        dev_auth::setup::InstallMode::Strong => Ok(dev_auth::setup::SetupPaths::strong()),
        dev_auth::setup::InstallMode::UserOnly => {
            let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
                .context("effective user account does not exist")?;
            Ok(dev_auth::setup::SetupPaths::user_only(&user.dir))
        }
    }
}

#[cfg(unix)]
fn run_setup(mut arguments: impl Iterator<Item = String>) -> Result<i32> {
    let operation = arguments.next().context(usage())?;
    match operation.as_str() {
        "discover" => {
            let mut mode = None;
            while let Some(argument) = arguments.next() {
                match argument.as_str() {
                    "--mode" if mode.is_none() => {
                        mode = Some(arguments.next().context("--mode requires a value")?)
                    }
                    _ => bail!("setup discover received an unsupported or duplicate argument"),
                }
            }
            let report = dev_auth::setup::discover_setup(setup_mode(mode.as_deref())?)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(0)
        }
        "readiness" => {
            let mut mode = None;
            while let Some(argument) = arguments.next() {
                match argument.as_str() {
                    "--mode" if mode.is_none() => {
                        mode = Some(arguments.next().context("--mode requires a value")?)
                    }
                    _ => bail!("setup readiness received an unsupported or duplicate argument"),
                }
            }
            let report = dev_auth::setup::setup_readiness(setup_mode(mode.as_deref())?)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(if report.next_action == "ready" { 0 } else { 1 })
        }
        "verify-release" => {
            let mut root = None;
            let mut manifest = None;
            let mut artifact = None;
            while let Some(argument) = arguments.next() {
                let destination = match argument.as_str() {
                    "--root" if root.is_none() => &mut root,
                    "--manifest" if manifest.is_none() => &mut manifest,
                    "--artifact" if artifact.is_none() => &mut artifact,
                    _ => bail!("release verification received an unsupported argument"),
                };
                *destination = Some(arguments.next().context("release path is missing")?);
            }
            let path = |value: Option<String>, flag: &str| -> Result<std::path::PathBuf> {
                let path = std::path::PathBuf::from(
                    value.with_context(|| format!("release verification requires {flag} PATH"))?,
                );
                if !path.is_absolute() {
                    bail!("release verification paths must be absolute");
                }
                Ok(path)
            };
            let report = dev_auth::release_manifest::verify_dev_auth_release(
                &path(root, "--root")?,
                &path(manifest, "--manifest")?,
                &path(artifact, "--artifact")?,
            )?;
            println!("{}", serde_json::to_string(&report)?);
            Ok(0)
        }
        "plan-release" => {
            let mut root = None;
            let mut manifest = None;
            let mut artifact = None;
            let mut output = None;
            let mut mode = None;
            let mut activate = false;
            while let Some(argument) = arguments.next() {
                match argument.as_str() {
                    "--root" if root.is_none() => {
                        root = Some(arguments.next().context("--root requires a path")?)
                    }
                    "--manifest" if manifest.is_none() => {
                        manifest = Some(arguments.next().context("--manifest requires a path")?)
                    }
                    "--artifact" if artifact.is_none() => {
                        artifact = Some(arguments.next().context("--artifact requires a path")?)
                    }
                    "--output" if output.is_none() => {
                        output = Some(arguments.next().context("--output requires a path")?)
                    }
                    "--mode" if mode.is_none() => {
                        mode = Some(arguments.next().context("--mode requires a value")?)
                    }
                    "--activate" if !activate => activate = true,
                    _ => bail!("release setup planning received an unsupported argument"),
                }
            }
            let absolute = |value: Option<String>, flag: &str| -> Result<std::path::PathBuf> {
                let path = std::path::PathBuf::from(
                    value
                        .with_context(|| format!("release setup planning requires {flag} PATH"))?,
                );
                if !path.is_absolute() {
                    bail!("release setup planning paths must be absolute");
                }
                Ok(path)
            };
            let root = absolute(root, "--root")?;
            let manifest = absolute(manifest, "--manifest")?;
            let artifact = absolute(artifact, "--artifact")?;
            let output = absolute(output, "--output")?;
            let verified =
                dev_auth::release_manifest::verify_dev_auth_release(&root, &manifest, &artifact)?;
            let plan = dev_auth::setup::build_verified_release_plan(
                setup_mode(mode.as_deref())?,
                activate,
                verified,
            )?;
            let digest = dev_auth::setup::write_plan_at(&output, &plan)?;
            println!("setup_plan_path={}", output.display());
            println!("setup_plan_sha256={digest}");
            Ok(0)
        }
        "plan" => {
            let mut deployment = None;
            let mut output = None;
            let mut format = None;
            let mut cli = dev_auth::deployment::DeploymentCliInput::default();
            while let Some(argument) = arguments.next() {
                match argument.as_str() {
                    "--deployment" if deployment.is_none() => {
                        deployment = Some(arguments.next().context("--deployment requires a path")?)
                    }
                    "--mode" if cli.mode.is_none() => {
                        cli.mode = Some(
                            arguments
                                .next()
                                .context("--mode requires a value")?
                                .parse()?,
                        )
                    }
                    "--channel" if cli.channel.is_none() => {
                        cli.channel = Some(
                            arguments
                                .next()
                                .context("--channel requires a value")?
                                .parse()?,
                        )
                    }
                    "--offline" if cli.offline.is_none() => cli.offline = Some(true),
                    "--activation" if cli.activation.is_none() => {
                        cli.activation = Some(
                            arguments
                                .next()
                                .context("--activation requires a value")?
                                .parse()?,
                        )
                    }
                    "--administrator-policy" if cli.administrator_policy.is_none() => {
                        cli.administrator_policy = Some(std::path::PathBuf::from(
                            arguments
                                .next()
                                .context("--administrator-policy requires a path")?,
                        ))
                    }
                    "--user-config" => {
                        let value = arguments
                            .next()
                            .context("--user-config requires USER=PATH")?;
                        let (user, path) = value
                            .split_once('=')
                            .context("--user-config requires USER=PATH")?;
                        cli.user_configs
                            .push((user.into(), std::path::PathBuf::from(path)));
                    }
                    "--user-policy" => {
                        let value = arguments
                            .next()
                            .context("--user-policy requires USER=PATH")?;
                        let (user, path) = value
                            .split_once('=')
                            .context("--user-policy requires USER=PATH")?;
                        cli.user_policies
                            .push((user.into(), std::path::PathBuf::from(path)));
                    }
                    "--credential-intent" => {
                        let value = arguments
                            .next()
                            .context("--credential-intent requires SLOT=INTENT")?;
                        let (slot, intent) = value
                            .split_once('=')
                            .context("--credential-intent requires SLOT=INTENT")?;
                        cli.credential_intents.push((slot.into(), intent.parse()?));
                    }
                    "--output" if output.is_none() => {
                        output = Some(arguments.next().context("--output requires a path")?)
                    }
                    "--format" if format.is_none() => {
                        format = Some(arguments.next().context("--format requires a value")?)
                    }
                    _ => bail!("setup plan received an unsupported or duplicate argument"),
                }
            }
            let output =
                std::path::PathBuf::from(output.context("setup plan requires --output PATH")?);
            if !output.is_absolute() {
                bail!("setup plan output path must be absolute");
            }
            let format = format.as_deref().unwrap_or("human");
            if !matches!(format, "human" | "json") {
                bail!("setup plan format must be human or json");
            }
            let document = deployment
                .map(|value| {
                    dev_auth::deployment::read_deployment_document(&std::path::PathBuf::from(value))
                })
                .transpose()?;
            let intent = dev_auth::deployment::normalize_deployment(document, cli)?;
            let install_mode = match intent.mode {
                dev_auth::deployment::DeploymentMode::Strong => {
                    dev_auth::setup::InstallMode::Strong
                }
                dev_auth::deployment::DeploymentMode::UserOnly => {
                    dev_auth::setup::InstallMode::UserOnly
                }
            };
            let release_storage = dev_auth::stable_release::native_release_storage(install_mode)?;
            let staged = dev_auth::stable_release::stage_latest_stable_release(
                &release_storage,
                intent.offline,
            )?;
            let installation =
                dev_auth::setup::build_verified_release_plan(install_mode, false, staged.verified);
            let plan = installation.and_then(|installation| {
                dev_auth::setup_v3::build_setup_plan_v3(intent, installation)
            });
            let result = plan.and_then(|plan| {
                dev_auth::setup_v3::write_setup_plan_v3_at(&output, &plan)
                    .map(|digest| (plan, digest))
            });
            let (plan, digest) = result?;
            match format {
                "human" => {
                    println!("setup_plan_path={}", output.display());
                    println!("setup_plan_sha256={digest}");
                    println!("release_version={}", plan.installation.request.version);
                }
                "json" => println!(
                    "{}",
                    serde_json::json!({
                        "schema": "dev-auth-setup-plan-result-v1",
                        "plan": output,
                        "sha256": digest,
                        "release_version": plan.installation.request.version,
                    })
                ),
                _ => bail!("setup plan format changed after validation"),
            }
            Ok(0)
        }
        "apply" => {
            let mut plan_path = None;
            let mut digest = None;
            let mut format = None;
            let mut credential_sources = std::collections::BTreeMap::new();
            while let Some(argument) = arguments.next() {
                match argument.as_str() {
                    "--plan" if plan_path.is_none() => {
                        plan_path = Some(arguments.next().context("--plan requires a path")?)
                    }
                    "--sha256" if digest.is_none() => {
                        digest = Some(arguments.next().context("--sha256 requires a digest")?)
                    }
                    "--credential-stdin" => {
                        let slot = arguments
                            .next()
                            .context("--credential-stdin requires SLOT")?;
                        if credential_sources
                            .insert(
                                slot,
                                dev_auth::credential_input::CredentialInputSource::Stdin,
                            )
                            .is_some()
                        {
                            bail!("credential input slot was defined more than once");
                        }
                    }
                    "--credential-fd" => {
                        let value = arguments
                            .next()
                            .context("--credential-fd requires SLOT=FD")?;
                        let (slot, fd) = value
                            .split_once('=')
                            .context("--credential-fd requires SLOT=FD")?;
                        let source = dev_auth::credential_input::CredentialInputSource::Fd(
                            fd.parse()
                                .context("credential file descriptor is invalid")?,
                        );
                        if credential_sources.insert(slot.into(), source).is_some() {
                            bail!("credential input slot was defined more than once");
                        }
                    }
                    "--credential-file" => {
                        let value = arguments
                            .next()
                            .context("--credential-file requires SLOT=PATH")?;
                        let (slot, path) = value
                            .split_once('=')
                            .context("--credential-file requires SLOT=PATH")?;
                        let path = std::path::PathBuf::from(path);
                        if !path.is_absolute() {
                            bail!("credential file path must be absolute");
                        }
                        let source = dev_auth::credential_input::CredentialInputSource::File(path);
                        if credential_sources.insert(slot.into(), source).is_some() {
                            bail!("credential input slot was defined more than once");
                        }
                    }
                    "--format" if format.is_none() => {
                        format = Some(arguments.next().context("--format requires a value")?)
                    }
                    _ => bail!("setup apply received an unsupported or duplicate argument"),
                }
            }
            let plan_path =
                std::path::PathBuf::from(plan_path.context("setup apply requires --plan PATH")?);
            if !plan_path.is_absolute() {
                bail!("setup plan path must be absolute");
            }
            let digest = digest.context("setup apply requires --sha256 HEX")?;
            let format = format.as_deref().unwrap_or("json");
            if !matches!(format, "human" | "json") {
                bail!("setup apply format must be human or json");
            }
            let plan = dev_auth::setup_v3::read_setup_plan_v3_at(&plan_path)
                .context("setup apply accepts only a full setup plan v3")?;
            if let Some(candidate) = dev_auth::setup_v3::setup_apply_candidate_path(&plan, &digest)?
            {
                #[cfg(unix)]
                {
                    use std::os::unix::process::CommandExt;
                    let error = std::process::Command::new(&candidate)
                        .args(std::env::args_os().skip(1))
                        .exec();
                    return Err(error).with_context(|| {
                        format!("execute verified setup candidate {}", candidate.display())
                    });
                }
                #[cfg(not(unix))]
                bail!("setup candidate handoff is unavailable on this platform");
            }
            let declared = plan
                .intent
                .credentials
                .iter()
                .map(|credential| credential.slot.clone())
                .collect::<std::collections::BTreeSet<_>>();
            let required = dev_auth::setup_v3::required_credential_slots_for_plan(&plan)?.required;
            let mut allowed_owner_uids = plan
                .accounts
                .iter()
                .map(|account| account.uid)
                .collect::<std::collections::BTreeSet<_>>();
            if plan.intent.mode == dev_auth::deployment::DeploymentMode::Strong {
                allowed_owner_uids.insert(0);
            }
            let mut stdin = std::io::stdin().lock();
            let credentials = dev_auth::credential_input::load_credential_inputs(
                &declared,
                &required,
                &credential_sources,
                &dev_auth::credential_input::CredentialInputContext {
                    mode: plan.intent.mode,
                    allowed_owner_uids,
                },
                &mut stdin,
            )?;
            let report = dev_auth::setup_v3::apply_setup_plan_v3(&plan, &digest, &credentials)?;
            if format == "json" {
                println!("{}", serde_json::to_string(&report)?);
            } else {
                println!("changed={}", report.changed);
                println!("verified={}", report.verified);
                println!("next_action={}", report.next_action);
                for slot in &report.input_required {
                    println!("input_required={slot}");
                }
                for slot in &report.blocked {
                    println!("blocked={slot}");
                }
            }
            Ok(if !report.input_required.is_empty() {
                3
            } else if !report.blocked.is_empty() {
                2
            } else {
                0
            })
        }
        "migrate-v1-preview" => {
            if arguments.next().as_deref() != Some("--output") {
                bail!("setup migrate-v1-preview requires --output PATH");
            }
            let output = std::path::PathBuf::from(
                arguments
                    .next()
                    .context("setup migrate-v1-preview output path is missing")?,
            );
            if !output.is_absolute() || arguments.next().is_some() {
                bail!("setup migrate-v1-preview requires one absolute output path");
            }
            let preview = dev_auth::setup::preview_v1_migration()?;
            let digest = dev_auth::setup::write_v1_migration_preview_at(&output, &preview)?;
            println!("migration_preview_path={}", output.display());
            println!("migration_preview_sha256={digest}");
            Ok(0)
        }
        "migrate-v1" => {
            let mut config = None;
            let mut digest = None;
            let mut v1_digest = None;
            while let Some(argument) = arguments.next() {
                match argument.as_str() {
                    "--config" if config.is_none() => {
                        config = Some(arguments.next().context("--config requires a path")?)
                    }
                    "--sha256" if digest.is_none() => {
                        digest = Some(arguments.next().context("--sha256 requires a digest")?)
                    }
                    "--v1-sha256" if v1_digest.is_none() => {
                        v1_digest = Some(arguments.next().context("--v1-sha256 requires a digest")?)
                    }
                    _ => bail!("v1 migration received an unsupported argument"),
                }
            }
            let config =
                std::path::PathBuf::from(config.context("v1 migration requires --config PATH")?);
            if !config.is_absolute() {
                bail!("v1 migration configuration path must be absolute");
            }
            let report = dev_auth::setup::migrate_v1_configuration(
                &config,
                &digest.context("v1 migration requires --sha256 HEX")?,
                &v1_digest.context("v1 migration requires --v1-sha256 HEX")?,
            )?;
            println!("{}", serde_json::to_string(&report)?);
            Ok(0)
        }
        "enroll-system" | "enroll-user" | "rotate-system" | "rotate-user" => {
            if arguments.next().is_some() {
                bail!("setup credential enrollment accepts no arguments");
            }
            let mut value = Vec::new();
            io::stdin()
                .take(REQUEST_LIMIT + 1)
                .read_to_end(&mut value)
                .context("read system service credential from standard input")?;
            if value.len() as u64 > REQUEST_LIMIT {
                value.zeroize();
                bail!("service credential exceeds the size limit");
            }
            let result = match operation.as_str() {
                "enroll-system" => dev_auth::setup::enroll_system_service_credential(&value),
                "enroll-user" => dev_auth::enroll_user_broker_service_token(&value),
                "rotate-system" => dev_auth::setup::rotate_system_service_credential(&value),
                "rotate-user" => dev_auth::rotate_user_broker_service_token(&value),
                _ => bail!("unknown credential enrollment operation"),
            };
            value.zeroize();
            result?;
            if operation.starts_with("rotate-") {
                println!("service_credential_rotated=true");
            } else {
                println!("service_credential_enrolled=true");
            }
            Ok(0)
        }
        "revoke-system" | "revoke-user" => {
            if arguments.next().is_some() {
                bail!("credential revocation accepts no arguments");
            }
            if operation == "revoke-system" {
                dev_auth::setup::revoke_system_service_credential()?;
            } else {
                dev_auth::revoke_user_broker_service_token()?;
            }
            println!("service_credential_revoked=true");
            Ok(0)
        }
        "start-system" | "stop-system" => {
            if arguments.next().is_some() {
                bail!("system broker lifecycle operation accepts no arguments");
            }
            let report = if operation == "start-system" {
                dev_auth::setup::start_system_broker()?
            } else {
                dev_auth::setup::stop_system_broker()?
            };
            println!("{}", serde_json::to_string(&report)?);
            Ok(0)
        }
        "install-policy"
        | "update-policy"
        | "install-user-policy"
        | "update-user-policy"
        | "install-user-config"
        | "update-user-config" => {
            let mut source = None;
            let mut digest = None;
            let mut current_digest = None;
            while let Some(argument) = arguments.next() {
                match argument.as_str() {
                    "--source" if source.is_none() => {
                        source = Some(arguments.next().context("--source requires a path")?)
                    }
                    "--sha256" if digest.is_none() => {
                        digest = Some(arguments.next().context("--sha256 requires a digest")?)
                    }
                    "--current-sha256" if current_digest.is_none() => {
                        current_digest = Some(
                            arguments
                                .next()
                                .context("--current-sha256 requires a digest")?,
                        )
                    }
                    _ => bail!("configuration install received an unsupported argument"),
                }
            }
            let source = std::path::PathBuf::from(
                source.context("configuration install requires --source PATH")?,
            );
            if !source.is_absolute() {
                bail!("configuration source path must be absolute");
            }
            let digest = digest.context("configuration install requires --sha256 HEX")?;
            let is_update = operation.starts_with("update-");
            if is_update != current_digest.is_some() {
                bail!("only configuration updates accept and require --current-sha256 HEX");
            }
            let destination = match operation.as_str() {
                "install-policy" => dev_auth::setup::install_system_policy(&source, &digest)?,
                "update-policy" => dev_auth::setup::update_system_policy(
                    &source,
                    &digest,
                    &current_digest
                        .context("configuration update requires --current-sha256 HEX")?,
                )?,
                "install-user-policy" => dev_auth::setup::install_user_policy(&source, &digest)?,
                "update-user-policy" => dev_auth::setup::update_user_policy(
                    &source,
                    &digest,
                    &current_digest
                        .context("configuration update requires --current-sha256 HEX")?,
                )?,
                "install-user-config" => dev_auth::setup::install_user_config(&source, &digest)?,
                "update-user-config" => dev_auth::setup::update_user_config(
                    &source,
                    &digest,
                    &current_digest
                        .context("configuration update requires --current-sha256 HEX")?,
                )?,
                _ => bail!("unknown configuration install operation"),
            };
            println!("configuration_installed={}", destination.display());
            Ok(0)
        }
        "purge-system-state" | "purge-user-state" => {
            if arguments.next().is_some() {
                bail!("state cleanup accepts no arguments");
            }
            let report = if operation == "purge-system-state" {
                dev_auth::setup::purge_system_state()?
            } else {
                dev_auth::setup::purge_user_state()?
            };
            println!("{}", serde_json::to_string(&report)?);
            Ok(0)
        }
        "verify" | "repair" | "rollback" | "activate" | "deactivate" | "uninstall" => {
            let mut mode = None;
            while let Some(argument) = arguments.next() {
                match argument.as_str() {
                    "--mode" if mode.is_none() => {
                        mode = Some(arguments.next().context("--mode requires a value")?)
                    }
                    _ => bail!("setup operation received an unsupported or duplicate argument"),
                }
            }
            let paths = setup_paths(setup_mode(mode.as_deref())?)?;
            if operation == "uninstall" {
                let report = dev_auth::setup::uninstall_at(&paths)?;
                println!("{}", serde_json::to_string(&report)?);
                return Ok(0);
            }
            let report = match operation.as_str() {
                "verify" => dev_auth::setup::verify_at(&paths)?,
                "repair" => dev_auth::setup::repair_at(&paths)?,
                "rollback" => dev_auth::setup::rollback_at(&paths)?,
                "activate" => dev_auth::setup::activate_transparent_launchers_at(&paths)?,
                "deactivate" => dev_auth::setup::deactivate_transparent_launchers_at(&paths)?,
                _ => bail!("unknown setup operation"),
            };
            println!("{}", serde_json::to_string(&report)?);
            Ok(0)
        }
        _ => bail!("unknown setup operation\n{}", usage()),
    }
}

#[cfg(not(unix))]
fn run_setup(_arguments: impl Iterator<Item = String>) -> Result<i32> {
    bail!("dev-auth setup is not supported on this platform yet")
}

#[cfg(unix)]
fn run_reconcile(mut arguments: impl Iterator<Item = String>) -> Result<i32> {
    let operation = arguments
        .next()
        .context("reconcile requires plan, apply, or verify")?;
    let mut source = None;
    let mut plan = None;
    let mut output = None;
    let mut digest = None;
    let mut format = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--source" if source.is_none() => {
                source = Some(arguments.next().context("--source requires PATH")?)
            }
            "--plan" if plan.is_none() => {
                plan = Some(arguments.next().context("--plan requires PATH")?)
            }
            "--output" if output.is_none() => {
                output = Some(arguments.next().context("--output requires PATH")?)
            }
            "--sha256" if digest.is_none() => {
                digest = Some(arguments.next().context("--sha256 requires HEX")?)
            }
            "--format" if format.is_none() => {
                format = Some(arguments.next().context("--format requires json")?)
            }
            _ => bail!("reconcile received an unsupported or duplicate argument"),
        }
    }
    if format.as_deref() != Some("json") {
        bail!("reconcile requires --format json");
    }
    let report = match operation.as_str() {
        "plan" => {
            if plan.is_some() || digest.is_some() {
                bail!("reconcile plan accepts only source and output paths");
            }
            let source =
                std::path::PathBuf::from(source.context("reconcile plan requires --source PATH")?);
            let output =
                std::path::PathBuf::from(output.context("reconcile plan requires --output PLAN")?);
            if !source.is_absolute() || !output.is_absolute() {
                bail!("reconcile source and output paths must be absolute");
            }
            match dev_auth::reconcile::plan_user_config_for_protocol(&source)? {
                dev_auth::reconcile::UserConfigPlanOutcome::Ready { plan, result } => {
                    dev_auth::reconcile::write_plan(&output, &plan)?;
                    result
                }
                dev_auth::reconcile::UserConfigPlanOutcome::Deferred(result) => result,
            }
        }
        "apply" => {
            if source.is_some() || output.is_some() {
                bail!("reconcile apply accepts only a plan and digest");
            }
            let plan_path =
                std::path::PathBuf::from(plan.context("reconcile apply requires --plan PLAN")?);
            if !plan_path.is_absolute() {
                bail!("reconcile plan path must be absolute");
            }
            let digest = digest.context("reconcile apply requires --sha256 HEX")?;
            let plan = dev_auth::reconcile::read_plan(&plan_path)?;
            dev_auth::reconcile::apply_user_config(&plan, &digest)?
        }
        "verify" => {
            if plan.is_some() || output.is_some() || digest.is_some() {
                bail!("reconcile verify accepts only a source path");
            }
            let source = std::path::PathBuf::from(
                source.context("reconcile verify requires --source PATH")?,
            );
            if !source.is_absolute() {
                bail!("reconcile source path must be absolute");
            }
            dev_auth::reconcile::verify_user_config(&source)?
        }
        _ => bail!("reconcile requires plan, apply, or verify"),
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(0)
}

#[cfg(not(unix))]
fn run_reconcile(_arguments: impl Iterator<Item = String>) -> Result<i32> {
    bail!("dev-auth reconciliation is not supported on this platform yet")
}

fn run() -> Result<i32> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().context(usage())?;
    match command.as_str() {
        "build-info" => {
            if arguments.next().is_some() {
                bail!("build-info accepts no arguments");
            }
            println!("{}", serde_json::to_string(&dev_auth::build_info())?);
            Ok(0)
        }
        "setup" => run_setup(arguments),
        "reconcile" => run_reconcile(arguments),
        "broker" => {
            if arguments.next().as_deref() != Some("serve") || arguments.next().is_some() {
                bail!("broker requires the exact operation: serve");
            }
            #[cfg(target_os = "linux")]
            {
                dev_auth::broker_server::serve_systemd_broker()?;
                bail!("system broker stopped unexpectedly")
            }
            #[cfg(not(target_os = "linux"))]
            {
                bail!("the strong workload broker is supported only on Linux")
            }
        }
        "enroll" => {
            if arguments.next().is_some() {
                bail!("enroll accepts no arguments");
            }
            let mut value = Vec::new();
            io::stdin()
                .take(REQUEST_LIMIT + 1)
                .read_to_end(&mut value)
                .context("read service credential from standard input")?;
            if value.len() as u64 > REQUEST_LIMIT {
                value.zeroize();
                bail!("service credential exceeds the size limit");
            }
            let result = dev_auth::enroll_service_account_token(&value);
            value.zeroize();
            result?;
            Ok(0)
        }
        "status" => {
            let broker = match arguments.next().as_deref() {
                None => false,
                Some("--broker") if arguments.next().is_none() => true,
                _ => bail!("status accepts only the optional --broker flag"),
            };
            if broker {
                #[cfg(unix)]
                {
                    println!(
                        "{}",
                        serde_json::to_string(&dev_auth::diagnostics::broker_status()?)?
                    );
                    return Ok(0);
                }
                #[cfg(not(unix))]
                bail!("broker status is not supported on this platform yet");
            }
            let status = dev_auth::runtime_status()?;
            println!(
                "config_ready={} service_token_enrolled={} runtime_ready={} ssh_agent_ready={} cached_installation_tokens={}",
                status.config_ready,
                status.service_token_enrolled,
                status.runtime_ready,
                status.ssh_agent_ready,
                status.cached_installation_tokens
            );
            Ok(
                if status.config_ready
                    && status.service_token_enrolled
                    && status.runtime_ready
                    && status.ssh_agent_ready
                {
                    0
                } else {
                    1
                },
            )
        }
        "explain" => {
            let command = arguments.next().context("explain requires git or gh")?;
            if arguments.next().is_some() {
                bail!("explain accepts exactly one command name");
            }
            #[cfg(unix)]
            {
                println!(
                    "{}",
                    serde_json::to_string(&dev_auth::diagnostics::explain(&command)?)?
                );
                Ok(0)
            }
            #[cfg(not(unix))]
            {
                let _ = command;
                bail!("explain is not supported on this platform yet")
            }
        }
        "validate" => {
            let online = match arguments.next().as_deref() {
                None => false,
                Some("--online") if arguments.next().is_none() => true,
                _ => bail!("validate accepts only the optional --online flag"),
            };
            let report = dev_auth::validate_configuration(online)?;
            println!(
                "config_valid=true online={} declared_exec_profiles={} declared_ssh_profiles={} declared_secret_references={}",
                report.online,
                report.declared_exec_profiles,
                report.declared_ssh_profiles,
                report.declared_secret_references
            );
            Ok(0)
        }
        "workspace-status" => {
            if arguments.next().is_some() {
                bail!("workspace-status accepts no arguments");
            }
            match dev_auth::workspace_status()? {
                dev_auth::WorkspaceContext::Managed => {
                    println!("managed");
                    Ok(0)
                }
                dev_auth::WorkspaceContext::Unmanaged => {
                    println!("unmanaged");
                    Ok(3)
                }
            }
        }
        "purge" => {
            if arguments.next().is_some() {
                bail!("purge accepts no arguments");
            }
            dev_auth::purge_runtime()?;
            Ok(0)
        }
        "exec" => {
            if arguments.next().as_deref() != Some("--profile") {
                bail!("exec requires --profile NAME");
            }
            let profile = arguments.next().context("exec profile name is missing")?;
            if arguments.next().as_deref() != Some("--") {
                bail!("exec requires -- before the command");
            }
            let child: Vec<String> = arguments.collect();
            let status = dev_auth::exec_profile(&profile, &child)?;
            Ok(exit_status_code(status))
        }
        "agent" => {
            if arguments.next().as_deref() != Some("--profile") {
                bail!("agent requires --profile NAME");
            }
            let profile = arguments.next().context("agent profile name is missing")?;
            if arguments.next().is_some() {
                bail!("agent accepts no additional arguments");
            }
            dev_auth::run_agent(&profile)?;
            Ok(0)
        }
        "agent-endpoint" => {
            if arguments.next().is_some() {
                bail!("agent-endpoint accepts no arguments");
            }
            println!("{}", dev_auth::agent_endpoint()?);
            Ok(0)
        }
        "ssh-load" => {
            if arguments.next().as_deref() != Some("--profile") {
                bail!("ssh-load requires --profile NAME");
            }
            let profile = arguments
                .next()
                .context("ssh-load profile name is missing")?;
            if arguments.next().is_some() {
                bail!("ssh-load accepts no additional arguments");
            }
            dev_auth::ssh_load(&profile)?;
            Ok(0)
        }
        "ssh-public" => {
            if arguments.next().as_deref() != Some("--profile") {
                bail!("ssh-public requires --profile NAME --purpose authentication|signing");
            }
            let profile = arguments
                .next()
                .context("ssh-public profile name is missing")?;
            if arguments.next().as_deref() != Some("--purpose") {
                bail!("ssh-public requires --purpose authentication|signing");
            }
            let purpose = match arguments.next().as_deref() {
                Some("authentication") => dev_auth::SshKeyPurpose::Authentication,
                Some("signing") => dev_auth::SshKeyPurpose::Signing,
                _ => bail!("ssh-public purpose must be authentication or signing"),
            };
            if arguments.next().is_some() {
                bail!("ssh-public accepts no additional arguments");
            }
            println!("{}", dev_auth::ssh_public(&profile, purpose)?);
            Ok(0)
        }
        "--help" | "-h" | "help" => {
            println!("{}", usage());
            Ok(0)
        }
        _ => bail!("unknown command\n{}", usage()),
    }
}

fn run_credential_frontend() -> Result<i32> {
    let operation = std::env::args()
        .nth(1)
        .context("credential-helper operation is required")?;
    let mut input = Vec::new();
    io::stdin()
        .take(REQUEST_LIMIT + 1)
        .read_to_end(&mut input)
        .context("read Git credential request")?;
    if input.len() as u64 > REQUEST_LIMIT {
        bail!("Git credential request exceeds the size limit");
    }
    match operation.as_str() {
        "get" => {
            #[cfg(target_os = "linux")]
            let output = match dev_auth::broker_client::active_claim_and_probe()?.0 {
                dev_auth::broker_protocol::LocalSessionClaim::Present { .. } => {
                    dev_auth::broker_credential_get(&input)?
                }
                dev_auth::broker_protocol::LocalSessionClaim::Absent => {
                    dev_auth::credential_get(&input)?
                }
            };
            #[cfg(not(target_os = "linux"))]
            let output = dev_auth::credential_get(&input)?;
            print!("{output}");
        }
        "store" => {}
        "erase" => {
            #[cfg(target_os = "linux")]
            match dev_auth::broker_client::active_claim_and_probe()?.0 {
                dev_auth::broker_protocol::LocalSessionClaim::Present { .. } => {
                    dev_auth::broker_credential_erase(&input)?
                }
                dev_auth::broker_protocol::LocalSessionClaim::Absent => {
                    dev_auth::credential_erase(&input)?
                }
            }
            #[cfg(not(target_os = "linux"))]
            dev_auth::credential_erase(&input)?;
        }
        _ => bail!("unsupported credential-helper operation"),
    }
    Ok(0)
}

fn run_gh_frontend() -> Result<i32> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let status = dev_auth::run_gh(&arguments)?;
    Ok(exit_status_code(status))
}

fn run_git_frontend() -> Result<i32> {
    let arguments: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let status = dev_auth::run_git(&arguments)?;
    Ok(exit_status_code(status))
}

fn run_native_git_frontend() -> Result<i32> {
    let arguments: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    #[cfg(unix)]
    {
        #[cfg(target_os = "linux")]
        {
            let (claim, probe) = dev_auth::broker_client::active_claim_and_probe()?;
            match claim {
                dev_auth::broker_protocol::LocalSessionClaim::Absent => {}
                claim @ dev_auth::broker_protocol::LocalSessionClaim::Present { .. } => {
                    match dev_auth::broker_protocol::decide_routing(&claim, probe) {
                        dev_auth::broker_protocol::RoutingDecision::BrokerSession { .. } => {
                            dev_auth::exec_broker_git(&arguments)?;
                            bail!("broker-authorized Git exec returned unexpectedly")
                        }
                        dev_auth::broker_protocol::RoutingDecision::Deny { reason } => {
                            bail!(reason)
                        }
                        dev_auth::broker_protocol::RoutingDecision::NativePassthrough => {
                            bail!("admitted workload cannot fall back to native human Git")
                        }
                    }
                }
            }
        }
        dev_auth::exec_native_git(&arguments)?;
        bail!("native Git exec returned unexpectedly")
    }
    #[cfg(not(unix))]
    {
        let status = dev_auth::run_native_git(&arguments)?;
        Ok(exit_status_code(status))
    }
}

fn run_native_gh_frontend() -> Result<i32> {
    let arguments: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    #[cfg(unix)]
    {
        #[cfg(target_os = "linux")]
        {
            let (claim, probe) = dev_auth::broker_client::active_claim_and_probe()?;
            match claim {
                dev_auth::broker_protocol::LocalSessionClaim::Absent => {}
                claim @ dev_auth::broker_protocol::LocalSessionClaim::Present { .. } => {
                    match dev_auth::broker_protocol::decide_routing(&claim, probe) {
                        dev_auth::broker_protocol::RoutingDecision::BrokerSession {
                            session_id,
                            ..
                        } => {
                            dev_auth::exec_broker_gh(&arguments, &session_id)?;
                            bail!("broker-authorized GitHub CLI exec returned unexpectedly")
                        }
                        dev_auth::broker_protocol::RoutingDecision::Deny { reason } => {
                            bail!(reason)
                        }
                        dev_auth::broker_protocol::RoutingDecision::NativePassthrough => {
                            bail!("admitted workload cannot fall back to native human GitHub CLI")
                        }
                    }
                }
            }
        }
        dev_auth::exec_native_gh(&arguments)?;
        bail!("native GitHub CLI exec returned unexpectedly")
    }
    #[cfg(not(unix))]
    {
        let status = dev_auth::run_native_gh(&arguments)?;
        Ok(exit_status_code(status))
    }
}

fn run_ssh_keygen_frontend() -> Result<i32> {
    #[cfg(target_os = "linux")]
    {
        let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
        let (claim, probe) = dev_auth::broker_client::active_claim_and_probe()?;
        if matches!(
            claim,
            dev_auth::broker_protocol::LocalSessionClaim::Present { .. }
        ) {
            if !matches!(
                probe,
                dev_auth::broker_protocol::BrokerSessionProbe::Verified { .. }
            ) {
                bail!("workload broker session is invalid or unavailable");
            }
            dev_auth::exec_broker_ssh_keygen(&arguments)?;
            bail!("broker ssh-keygen adapter returned unexpectedly");
        }
    }
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let status = dev_auth::run_ssh_keygen(&arguments)?;
    Ok(exit_status_code(status))
}

fn run_gh_git_child_frontend() -> Result<i32> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let status = dev_auth::run_gh_git_child(&arguments)?;
    Ok(exit_status_code(status))
}

fn run_gh_pager_frontend() -> Result<i32> {
    if std::env::args().nth(1).is_some() {
        bail!("the internal gh pager accepts no file arguments");
    }
    io::copy(&mut io::stdin().lock(), &mut io::stdout().lock())
        .context("forward bounded gh output")?;
    Ok(0)
}

fn main() {
    let program = std::env::args_os()
        .next()
        .and_then(|value| {
            std::path::PathBuf::from(value)
                .file_name()
                .map(|name| name.to_owned())
        })
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| "dev-auth".into());
    let normalized_program = program.to_ascii_lowercase();
    let frontend = normalized_program
        .strip_suffix(".exe")
        .unwrap_or(&normalized_program);
    let gh_child = std::env::var("DEV_AUTH_GH_CHILD").as_deref() == Ok("1");
    let git_child = std::env::var("DEV_AUTH_GIT_CHILD").as_deref() == Ok("1");
    #[cfg(target_os = "linux")]
    let core_operation = std::env::args_os().nth(1);
    let result = match (frontend, gh_child, git_child) {
        ("git", true, _) => run_gh_git_child_frontend(),
        ("cat", true, _) => run_gh_pager_frontend(),
        ("false", true, _) => Ok(1),
        ("cat", _, true) => run_gh_pager_frontend(),
        ("false", _, true) => Ok(1),
        (_, true, _) | (_, _, true) => Err(anyhow::anyhow!(
            "unrecognized private child launcher identity"
        )),
        ("git", _, _) => run_native_git_frontend(),
        ("gh", _, _) => run_native_gh_frontend(),
        ("git-dev-auth", _, _) => run_git_frontend(),
        ("git-credential-dev-auth", _, _) => run_credential_frontend(),
        ("gh-dev-auth", _, _) => run_gh_frontend(),
        ("ssh-keygen-dev-auth", _, _) => run_ssh_keygen_frontend(),
        #[cfg(target_os = "linux")]
        ("dev-auth-workload-launcher", false, false) => run_privileged_launcher_os(),
        #[cfg(target_os = "linux")]
        ("dev-auth", false, false)
            if core_operation.as_deref() == Some(std::ffi::OsStr::new("workload")) =>
        {
            run_workload_os()
        }
        #[cfg(target_os = "linux")]
        ("dev-auth", false, false)
            if core_operation.as_deref() == Some(std::ffi::OsStr::new("supervisor")) =>
        {
            run_supervisor_os()
        }
        #[cfg(target_os = "linux")]
        ("dev-auth", false, false)
            if core_operation.as_deref() == Some(std::ffi::OsStr::new("supervisor-child")) =>
        {
            run_supervisor_child_os()
        }
        #[cfg(target_os = "linux")]
        ("dev-auth", false, false)
            if core_operation.as_deref() == Some(std::ffi::OsStr::new("sandbox-child")) =>
        {
            run_sandbox_child_os()
        }
        #[cfg(target_os = "linux")]
        ("dev-auth", false, false)
            if core_operation.as_deref() == Some(std::ffi::OsStr::new("agent-proxy")) =>
        {
            run_agent_proxy_os()
        }
        ("dev-auth", _, _) => run(),
        #[cfg(target_os = "linux")]
        (workload, false, false) => run_workload_alias_os(workload),
        #[cfg(not(target_os = "linux"))]
        _ => run(),
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            if frontend == "git-credential-dev-auth"
                && std::env::args().nth(1).as_deref() == Some("get")
            {
                println!("quit=true");
            }
            eprintln!("{program}: {error:#}");
            std::process::exit(2);
        }
    }
}
