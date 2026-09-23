//! Policy-owned plans run in one already-admitted native execution boundary.
//! A sealed descriptor supplies the plan to a private same-product worker; it
//! is never exposed through argv, environment, or a mutable temporary file.

use super::policy::{ExecutionPlan, ExitPolicy, Policy};
use super::{Authority, Failure};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus};
use std::time::Duration;

const LIMIT: usize = 1024 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: String,
    plan: ExecutionPlan,
    deadline_milliseconds: u64,
}

pub(super) fn select(
    policy: &Policy,
    granted: &Authority,
    selected: &Authority,
) -> Result<ExecutionPlan, Failure> {
    if !granted.permits(selected) {
        return Err(Failure::AuthorityDenied);
    }
    let plan = match selected {
        Authority::ExactPlan { sha256 } => policy.plans.get(sha256),
        Authority::Typed { operations } if operations.len() == 1 => {
            policy.operations.get(&operations[0])
        }
        _ => None,
    }
    .ok_or(Failure::AuthorityDenied)?;
    plan.validate()?;
    Ok(plan.clone())
}

pub(super) fn prepare(plan: ExecutionPlan, deadline: Duration) -> Result<OwnedFd, Failure> {
    let bytes = serde_json::to_vec(&Snapshot {
        schema: "dev-auth-plan-worker-v1".into(),
        plan,
        deadline_milliseconds: u64::try_from(deadline.as_millis())
            .map_err(|_| Failure::InvalidRequest)?,
    })
    .map_err(|_| Failure::InvalidRequest)?;
    if bytes.len() > LIMIT {
        return Err(Failure::InvalidRequest);
    }
    let mut file = File::from(
        rustix::fs::memfd_create(
            "dev-auth-plan",
            rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
        )
        .map_err(|_| Failure::NativeUnavailable)?,
    );
    file.write_all(&bytes)
        .and_then(|_| file.seek(SeekFrom::Start(0)).map(|_| ()))
        .map_err(|_| Failure::RuntimeFailure)?;
    rustix::fs::fcntl_add_seals(&file, required_seals()).map_err(|_| Failure::NativeUnavailable)?;
    Ok(file.into())
}

fn required_seals() -> rustix::fs::SealFlags {
    rustix::fs::SealFlags::SEAL
        | rustix::fs::SealFlags::SHRINK
        | rustix::fs::SealFlags::GROW
        | rustix::fs::SealFlags::WRITE
}

#[doc(hidden)]
pub fn run_worker() -> i32 {
    if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
        return 4;
    }
    let mut arguments = std::env::args_os().skip(2);
    let Some(descriptor) = arguments
        .next()
        .and_then(|value| value.to_str().and_then(|value| value.parse::<i32>().ok()))
        .filter(|fd| *fd >= 3)
    else {
        return 2;
    };
    if arguments.next().is_some() {
        return 2;
    }
    // SAFETY: F_GETFD checks the integer before making a Rust descriptor owner.
    // The private worker exclusively owns descriptors inherited from its parent.
    if unsafe { nix::libc::fcntl(descriptor, nix::libc::F_GETFD) } < 0 {
        return 4;
    }
    let file = File::from(unsafe { OwnedFd::from_raw_fd(descriptor) });
    if !rustix::fs::fcntl_get_seals(&file).is_ok_and(|flags| flags.contains(required_seals())) {
        return 4;
    }
    match read_and_run(file) {
        Ok(status) => status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)),
        Err(_) => {
            eprintln!("dev-auth: approved command graph failed");
            125
        }
    }
}

fn read_and_run(mut file: File) -> Result<ExitStatus, Failure> {
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::InvalidRequest)?;
    drop(file);
    if bytes.len() > LIMIT {
        return Err(Failure::InvalidRequest);
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|_| Failure::InvalidRequest)?;
    if snapshot.schema != "dev-auth-plan-worker-v1" {
        return Err(Failure::InvalidRequest);
    }
    snapshot.plan.validate()?;
    let deadline = Duration::from_millis(snapshot.deadline_milliseconds);
    let commands = snapshot
        .plan
        .nodes
        .iter()
        .map(|node| {
            let mut command = Command::new(&node.program);
            command
                .args(&node.arguments)
                .current_dir(&node.working_directory)
                .env_clear()
                .envs(node.environment.iter().map(|(key, value)| (key, value)));
            command
        })
        .collect();
    let pipes = snapshot
        .plan
        .pipes
        .iter()
        .map(|pipe| (pipe.from, pipe.to))
        .collect::<Vec<_>>();
    let output = dev_tools_command::run_command_graph(commands, &pipes, || {
        dev_tools_privilege_session::linux::boot_time().is_ok_and(|now| now < deadline)
    });
    if output.failure.is_some() {
        return Err(Failure::RuntimeFailure);
    }
    let statuses = output
        .statuses
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(Failure::RuntimeFailure)?;
    aggregate(&statuses, snapshot.plan.exit_policy)
}

fn aggregate(statuses: &[ExitStatus], policy: ExitPolicy) -> Result<ExitStatus, Failure> {
    let last = statuses.last().copied().ok_or(Failure::InvalidRequest)?;
    Ok(match policy {
        ExitPolicy::Last => last,
        ExitPolicy::All => statuses
            .iter()
            .find(|status| !status.success())
            .copied()
            .unwrap_or(last),
        ExitPolicy::Pipefail => statuses
            .iter()
            .rfind(|status| !status.success())
            .copied()
            .unwrap_or(last),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    #[test]
    fn graph_exit_selection_preserves_declared_order() {
        let statuses = [
            ExitStatus::from_raw(2 << 8),
            ExitStatus::from_raw(3 << 8),
            ExitStatus::from_raw(0),
        ];
        assert_eq!(
            aggregate(&statuses, ExitPolicy::Last).unwrap().code(),
            Some(0)
        );
        assert_eq!(
            aggregate(&statuses, ExitPolicy::All).unwrap().code(),
            Some(2)
        );
        assert_eq!(
            aggregate(&statuses, ExitPolicy::Pipefail).unwrap().code(),
            Some(3)
        );
    }
    #[test]
    fn worker_plan_is_sealed_and_read_once_without_a_named_file() {
        let plan = ExecutionPlan {
            nodes: vec![super::super::policy::PlanCommand {
                program: "/usr/bin/true".into(),
                arguments: vec![],
                working_directory: "/".into(),
                environment: vec![],
            }],
            pipes: vec![],
            exit_policy: ExitPolicy::All,
        };
        let fd = prepare(
            plan,
            dev_tools_privilege_session::linux::boot_time().unwrap() + Duration::from_secs(3),
        )
        .unwrap();
        assert!(rustix::fs::fcntl_get_seals(fd.as_fd())
            .unwrap()
            .contains(required_seals()));
        assert!(read_and_run(fd.into()).unwrap().success());
    }

    #[test]
    fn named_graph_selection_cannot_expand_the_grant() {
        let plan = ExecutionPlan {
            nodes: vec![super::super::policy::PlanCommand {
                program: "/usr/bin/true".into(),
                arguments: vec![],
                working_directory: "/".into(),
                environment: vec![],
            }],
            pipes: vec![],
            exit_policy: ExitPolicy::All,
        };
        let mut policy = Policy::template();
        policy.operations.insert("allowed".into(), plan.clone());
        policy.operations.insert("other".into(), plan);
        let grant = Authority::Typed {
            operations: vec!["allowed".into()],
        };
        assert!(select(&policy, &grant, &grant).is_ok());
        assert!(select(
            &policy,
            &grant,
            &Authority::Typed {
                operations: vec!["other".into()]
            }
        )
        .is_err());
        assert!(select(
            &policy,
            &Authority::Administrator,
            &Authority::Typed {
                operations: vec!["missing".into()]
            }
        )
        .is_err());
    }
}
