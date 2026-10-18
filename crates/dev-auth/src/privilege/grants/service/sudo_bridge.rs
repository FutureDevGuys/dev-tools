use super::*;
use crate::privilege::grants::sudo_wire::{
    Decision, Message, Request, Response, SUDO_HELLO, SUDO_SCHEMA,
};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

pub(super) async fn connection(service: Arc<Service>, descriptor: OwnedFd) -> Result<(), Failure> {
    socket::setsockopt(&descriptor, socket::sockopt::PassCred, &true)
        .map_err(|_| Failure::NativeUnavailable)?;
    let peer = crate::linux_admission::peer_evidence_fd(&descriptor)
        .map_err(|_| Failure::AuthorityDenied)?;
    let executable =
        File::open(format!("/proc/{}/exe", peer.pid)).map_err(|_| Failure::AuthorityDenied)?;
    if peer.uid != 0
        || !native::alive(peer.peer_pidfd())
        || !native::same_file(&executable, &service.sudo_file)?
        || !policy_unchanged(&service)
    {
        return Err(Failure::AuthorityDenied);
    }
    let descriptor = AsyncFd::new(descriptor).map_err(|_| Failure::NativeUnavailable)?;
    send_packet(&descriptor, SUDO_HELLO).await?;
    let request = receive(&descriptor, &peer, Duration::from_secs(3)).await?;
    let Request::Preflight { uid } = request else {
        return Err(Failure::InvalidRequest);
    };
    let mut caller = Caller::capture_sudo(descriptor.get_ref(), uid)?;
    normalize_execution_scope(&service, &mut caller).await?;
    let caller_group =
        File::open(&caller.peer.unified_cgroup).map_err(|_| Failure::AuthorityDenied)?;
    let host = File::open("/proc/self/ns/user").map_err(|_| Failure::NativeUnavailable)?;
    let native_namespace = native::same_file(&host, &caller.user_namespace)?;
    // A native sudo image may reach its plugin before spawn() returns to the
    // coordinator. Wait for the directly owned Child identity, never infer a
    // free relay admission from cgroup membership alone.
    let ready_by = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let state = service.state.lock().await;
        let mut preparing = false;
        for job in state.jobs.values() {
            if job.relay == RelayAdmission::Preparing
                && job.preparing
                && native::same_file(&caller_group, job.boundary.directory())?
            {
                preparing = true;
                break;
            }
        }
        drop(state);
        if !preparing {
            break;
        }
        if std::time::Instant::now() >= ready_by || !caller.still_present() {
            return Err(Failure::Busy);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let (id, deadline, relay_job) = {
        let mut state = service.state.lock().await;
        state.registry.poll(now()?);
        let mut source_job = None;
        for (id, job) in &state.jobs {
            if native::same_file(&caller_group, job.boundary.directory())? {
                source_job = Some((*id, job.grant, job.relay.may_claim(peer.pid)));
                break;
            }
        }
        let selection = if let Some((_, grant, _)) = source_job {
            Ok(grant)
        } else {
            select(&state, &caller.scope, None)
        };
        let id = match selection {
            Ok(id) => id,
            Err(Failure::NoGrant) => {
                drop(state);
                reply(&descriptor, Decision::Native, Duration::ZERO, &[], None).await?;
                return Ok(());
            }
            Err(failure) => return Err(failure),
        };
        let grant = state.registry.get(id).ok_or(Failure::NoGrant)?;
        if state.stopping
            || grant.lifetime.state() != LeaseState::Active
            || !grant.scope.contains(&caller.scope)
        {
            return Err(Failure::GrantRevoked);
        }
        (
            id,
            grant.lifetime.hard_deadline(),
            source_job.and_then(|(job, _, relay)| relay.then_some(job)),
        )
    };
    let setup_lease = setup_admission(&service)?;
    if !native_namespace {
        {
            let mut state = service.state.lock().await;
            if state.pending_relays.len() >= MAX_EXECUTIONS
                || state.pending_relays.contains_key(&caller.peer.pid)
            {
                return Err(Failure::Busy);
            }
            let expires = now()?
                .checked_add(Duration::from_secs(3))
                .ok_or(Failure::NativeUnavailable)?
                .min(deadline);
            state.pending_relays.insert(
                caller.peer.pid,
                PendingRelay {
                    caller,
                    grant: id,
                    expires,
                },
            );
        }
        reply(&descriptor, Decision::Relay, deadline, &[], Some(id)).await?;
        return Ok(());
    }
    reply(&descriptor, Decision::Managed, deadline, &[], Some(id)).await?;
    let request = receive(&descriptor, &peer, Duration::from_secs(30)).await?;
    if matches!(request, Request::Complete) {
        reply(&descriptor, Decision::Native, Duration::ZERO, &[], None).await?;
        return Ok(());
    }
    let Request::Admit {
        command_info,
        arguments,
        environment,
    } = request
    else {
        return Err(Failure::InvalidRequest);
    };
    if !caller.still_present()
        || !policy_unchanged(&service)
        || !native::same_file(
            &File::open(format!("/proc/{}/exe", peer.pid)).map_err(|_| Failure::AuthorityDenied)?,
            &executable,
        )?
    {
        return Err(Failure::AuthorityDenied);
    }
    let job_id = if let Some(id) = relay_job {
        id
    } else {
        new_id()?
    };
    let descriptors = {
        let mut state = service.state.lock().await;
        if state.stopping || (relay_job.is_none() && state.jobs.len() >= MAX_EXECUTIONS) {
            return Err(Failure::Busy);
        }
        let grant = state.registry.get(id).ok_or(Failure::NoGrant)?;
        let authority = admit_authority(
            &service.policy,
            grant.authority,
            &command_info,
            arguments,
            environment,
        )?;
        if relay_job.is_none() {
            state
                .registry
                .admit(id, &caller.scope, &authority, now()?)
                .map_err(session_failure)?;
        } else {
            state.registry.poll(now()?);
            let grant = state.registry.get(id).ok_or(Failure::NoGrant)?;
            if grant.lifetime.state() != LeaseState::Active
                || !grant.scope.contains(&caller.scope)
                || !grant.authority.contains(&authority)
            {
                return Err(Failure::AuthorityDenied);
            }
            let relay = state.jobs.get_mut(&job_id).ok_or(Failure::NoGrant)?;
            relay.relay.claim(peer.pid)?;
        }
        let metadata = state.metadata.get(&id).ok_or(Failure::NoGrant)?;
        let new_boundary = if relay_job.is_some() {
            None
        } else {
            Some(
                ExecutionBoundary::create(
                    metadata.boundary.directory(),
                    &format!("exec-{job_id:032x}"),
                    deadline,
                )
                .map_err(|_| Failure::NativeUnavailable)?,
            )
        };
        let boundary = new_boundary
            .as_ref()
            .or_else(|| state.jobs.get(&job_id).map(|job| &job.boundary))
            .ok_or(Failure::NoGrant)?;
        let (procs, gate, _) = boundary
            .attachment()
            .map_err(|_| Failure::NativeUnavailable)?;
        let mut descriptors = vec![procs, gate, native::clone_fd(&service.coordinator)?];
        let mut ancestor = Some(id);
        while let Some(id) = ancestor {
            descriptors.push(
                state
                    .metadata
                    .get(&id)
                    .ok_or(Failure::NoGrant)?
                    .boundary
                    .gate()
                    .map_err(|_| Failure::RuntimeFailure)?,
            );
            ancestor = state.registry.get(id).ok_or(Failure::NoGrant)?.parent;
        }
        if descriptors.len() > 32 {
            return Err(Failure::Busy);
        }
        if let Some(boundary) = new_boundary {
            state.jobs.insert(
                job_id,
                Job {
                    grant: id,
                    boundary,
                    preparing: true,
                    leader_done: false,
                    external_leader: Some(native::clone_fd(peer.peer_pidfd())?),
                    external_complete: false,
                    origin: caller.scope.clone(),
                    relay: RelayAdmission::Ordinary,
                    captured: None,
                },
            );
        }
        descriptors
    };
    let result = admitted(
        &service,
        &descriptor,
        &peer,
        Admission {
            grant_id: id,
            job_id,
            deadline,
            descriptors,
            setup_lease,
        },
    )
    .await;
    if result.is_err() {
        let mut state = service.state.lock().await;
        if let Some(job) = state.jobs.get_mut(&job_id) {
            let _ = job.boundary.stop();
        }
    }
    result
}

struct Admission {
    grant_id: GrantId,
    job_id: GrantId,
    deadline: Duration,
    descriptors: Vec<OwnedFd>,
    setup_lease: Option<dev_tools_installation::InstallationLock>,
}

async fn admitted(
    service: &Service,
    descriptor: &AsyncFd<OwnedFd>,
    peer: &crate::linux_admission::LinuxPeerEvidence,
    admission: Admission,
) -> Result<(), Failure> {
    let Admission {
        grant_id,
        job_id,
        deadline,
        descriptors,
        setup_lease,
    } = admission;
    reply(
        descriptor,
        Decision::Managed,
        deadline,
        &descriptors,
        Some(grant_id),
    )
    .await?;
    drop(descriptors);
    if !matches!(
        receive(descriptor, peer, Duration::from_secs(3)).await?,
        Request::Attached
    ) {
        return Err(Failure::ProtocolViolation);
    }
    {
        let mut state = service.state.lock().await;
        state.registry.poll(now()?);
        if state
            .registry
            .get(grant_id)
            .is_none_or(|grant| grant.lifetime.state() != LeaseState::Active)
            || !policy_unchanged(service)
        {
            return Err(Failure::GrantRevoked);
        }
        let path = crate::linux_admission::read_unified_cgroup(peer.pid)
            .map_err(|_| Failure::AuthorityDenied)?;
        let observed = root_file(&path, true)?;
        let job = state.jobs.get_mut(&job_id).ok_or(Failure::NoGrant)?;
        if !native::same_file(&observed, job.boundary.directory())?
            || !native::alive(peer.peer_pidfd())
        {
            return Err(Failure::AuthorityDenied);
        }
        job.preparing = false;
    }
    reply(
        descriptor,
        Decision::Attached,
        deadline,
        &[],
        Some(grant_id),
    )
    .await?;
    drop(setup_lease);
    let remaining = deadline.saturating_sub(now()?);
    if !matches!(
        receive_with_completion(descriptor, peer, remaining, true)
            .await
            .inspect_err(|failure| {
                eprintln!("dev-auth native sudo completion failed: {failure:?}");
            })?,
        Request::Complete
    ) {
        return Err(Failure::ProtocolViolation);
    }
    {
        let mut state = service.state.lock().await;
        let job = state.jobs.get_mut(&job_id).ok_or(Failure::NoGrant)?;
        let executable =
            File::open(format!("/proc/{}/exe", peer.pid)).map_err(|_| Failure::AuthorityDenied)?;
        let group = crate::linux_admission::read_unified_cgroup(peer.pid)
            .map_err(|_| Failure::AuthorityDenied)?;
        if !native::same_file(&executable, &service.sudo_file)?
            || !native::same_file(&root_file(&group, true)?, job.boundary.directory())?
            || !native::alive(peer.peer_pidfd())
        {
            return Err(Failure::AuthorityDenied);
        }
        job.external_complete = true;
    }
    reply(
        descriptor,
        Decision::Attached,
        deadline,
        &[],
        Some(grant_id),
    )
    .await
}

fn admit_authority(
    policy: &Policy,
    granted: &Authority,
    info: &[OsString],
    arguments: Vec<OsString>,
    environment: Vec<OsString>,
) -> Result<Authority, Failure> {
    if arguments.is_empty()
        || arguments.len() > 1024
        || info.len() > 128
        || environment.len() > 1024
    {
        return Err(Failure::InvalidRequest);
    }
    let number = |name: &[u8]| {
        field(info, name)?
            .to_str()
            .ok_or(Failure::InvalidRequest)?
            .parse::<u32>()
            .map_err(|_| Failure::InvalidRequest)
    };
    let uid = number(b"runas_uid")?;
    let gid = number(b"runas_gid")?;
    let program = field(info, b"command")?.to_os_string();
    if !Path::new(&program).is_absolute() {
        return Err(Failure::InvalidRequest);
    }
    if matches!(granted, Authority::Administrator) {
        return Ok(Authority::Administrator);
    }
    if uid != 0
        || gid != 0
        || info
            .iter()
            .any(|value| value.as_bytes().starts_with(b"chroot="))
    {
        return Err(Failure::AuthorityDenied);
    }
    let directory = field(info, b"cwd")?.to_os_string();
    let environment = environment
        .into_iter()
        .map(|value| {
            let bytes = value.as_bytes();
            let offset = bytes
                .iter()
                .position(|byte| *byte == b'=')
                .ok_or(Failure::InvalidRequest)?;
            Ok((
                OsStr::from_bytes(&bytes[..offset]).to_owned(),
                OsStr::from_bytes(&bytes[offset + 1..]).to_owned(),
            ))
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    let observed_environment = environment.clone();
    let (authority, command) = execution_authority(
        policy,
        granted,
        crate::privilege::grants::Execution {
            program,
            arguments: arguments.into_iter().skip(1).collect(),
            working_directory: directory,
            environment,
            terminal: false,
        },
    )?;
    if command.environment != observed_environment {
        return Err(Failure::AuthorityDenied);
    }
    Ok(authority)
}

fn field<'a>(values: &'a [OsString], name: &[u8]) -> Result<&'a OsStr, Failure> {
    let mut result = None;
    for value in values {
        let bytes = value.as_bytes();
        let separator = bytes
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(Failure::InvalidRequest)?;
        if &bytes[..separator] == name {
            if result.is_some() {
                return Err(Failure::InvalidRequest);
            }
            result = Some(OsStr::from_bytes(&bytes[separator + 1..]));
        }
    }
    result.ok_or(Failure::InvalidRequest)
}

async fn receive(
    descriptor: &AsyncFd<OwnedFd>,
    peer: &crate::linux_admission::LinuxPeerEvidence,
    timeout: Duration,
) -> Result<Request, Failure> {
    receive_with_completion(descriptor, peer, timeout, false).await
}

async fn receive_with_completion(
    descriptor: &AsyncFd<OwnedFd>,
    peer: &crate::linux_admission::LinuxPeerEvidence,
    timeout: Duration,
    completion_only: bool,
) -> Result<Request, Failure> {
    tokio::time::timeout(timeout, async {
        loop {
            let mut ready = descriptor
                .readable()
                .await
                .map_err(|_| Failure::NativeUnavailable)?;
            let packet =
                match ready.try_io(|fd| crate::privilege::grants::packet::receive_owned(fd.get_ref())) {
                    Ok(Ok(packet)) => packet,
                    Err(_) => continue,
                    _ => return Err(Failure::ProtocolViolation),
                };
            if !packet.descriptors.is_empty()
                || !packet.credentials.is_some_and(|credentials| {
                    sender_identity_matches(peer.pid, peer.uid, peer.gid, credentials, completion_only)
                })
                || !native::alive(peer.peer_pidfd())
            {
                let credentials = packet.credentials;
                eprintln!(
                    "dev-auth native sudo message identity rejected: pid_match={} uid_match={} gid_match={} alive={} unexpected_fds={}",
                    credentials.is_some_and(|value| value.pid() as u32 == peer.pid),
                    credentials.is_some_and(|value| value.uid() == peer.uid),
                    credentials.is_some_and(|value| value.gid() == peer.gid),
                    native::alive(peer.peer_pidfd()),
                    !packet.descriptors.is_empty(),
                );
                return Err(Failure::AuthorityDenied);
            }
            let message: Message =
                serde_json::from_slice(&packet.bytes).map_err(|_| Failure::InvalidRequest)?;
            if message.schema != SUDO_SCHEMA
                || (completion_only && !matches!(message.request, Request::Complete))
            {
                return Err(Failure::InvalidRequest);
            }
            return Ok(message.request);
        }
    })
    .await
    .map_err(|_| Failure::RuntimeFailure)?
}

fn sender_identity_matches(
    pid: u32,
    uid: u32,
    gid: u32,
    sender: socket::UnixCredentials,
    completion_only: bool,
) -> bool {
    // Native sudo retains root but adopts run-as groups during its execution
    // lifecycle. Only its terminal Complete message may carry a changed GID;
    // it creates no authority/admission and still needs the retained PID, root
    // identity, native executable and owned cgroup before completion is accepted.
    sender.pid() as u32 == pid
        && sender.uid() == uid
        && (sender.gid() == gid || (completion_only && uid == 0))
}

async fn reply(
    descriptor: &AsyncFd<OwnedFd>,
    decision: Decision,
    deadline: Duration,
    descriptors: &[OwnedFd],
    grant: Option<GrantId>,
) -> Result<(), Failure> {
    let bytes = serde_json::to_vec(&Response {
        schema: SUDO_SCHEMA.into(),
        decision,
        hard_deadline_milliseconds: u64::try_from(deadline.as_millis())
            .map_err(|_| Failure::InvalidRequest)?,
        grant: grant.map(|id| format!("{id:032x}")),
    })
    .map_err(|_| Failure::RuntimeFailure)?;
    let descriptors: Vec<_> = descriptors.iter().map(AsRawFd::as_raw_fd).collect();
    let controls = if descriptors.is_empty() {
        Vec::new()
    } else {
        vec![socket::ControlMessage::ScmRights(&descriptors)]
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let mut ready = descriptor
                .writable()
                .await
                .map_err(|_| Failure::NativeUnavailable)?;
            match ready.try_io(|fd| {
                socket::sendmsg::<UnixAddr>(
                    fd.get_ref().as_raw_fd(),
                    &[std::io::IoSlice::new(&bytes)],
                    &controls,
                    MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
                    None,
                )
                .map_err(io::Error::from)
            }) {
                Ok(Ok(count)) if count == bytes.len() => return Ok(()),
                Err(_) => continue,
                _ => return Err(Failure::RuntimeFailure),
            }
        }
    })
    .await
    .map_err(|_| Failure::RuntimeFailure)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_plan_node_effects_cannot_enter_through_native_sudo_metadata() {
        use crate::privilege::grants::policy::ExecutionPlan;

        let base = serde_json::json!({
            "nodes":[{"program":"/usr/bin/true","arguments":[],"working_directory":"/","environment":[]}],
            "pipes":[],"exit_policy":"last"
        });
        let info = [
            "runas_uid=0".into(),
            "runas_gid=0".into(),
            "command=/usr/bin/true".into(),
            "cwd=/".into(),
        ];
        let arguments = vec!["/usr/bin/true".into()];
        let typed = Authority::Typed {
            operations: vec!["selected".into()],
        };
        let mut policy = Policy::template();
        policy.operations.insert(
            "selected".into(),
            serde_json::from_value::<ExecutionPlan>(base.clone()).unwrap(),
        );
        assert_eq!(
            admit_authority(&policy, &typed, &info, arguments.clone(), vec![]),
            Ok(typed.clone())
        );
        for (field, effect) in [
            (
                "run_as",
                serde_json::json!({"uid":0,"gid":0,"supplementary_groups":[]}),
            ),
            ("stdin", serde_json::json!("inherit")),
            ("stdout", serde_json::json!("null")),
            ("stderr", serde_json::json!("null")),
        ] {
            let mut selected = base.clone();
            selected["nodes"][0][field] = effect;
            let plan: ExecutionPlan = serde_json::from_value(selected).unwrap();
            let digest = plan.digest().unwrap();
            policy.operations.insert("selected".into(), plan.clone());
            policy.plans.insert(digest.clone(), plan);
            for authority in [typed.clone(), Authority::ExactPlan { sha256: digest }] {
                assert_eq!(
                    admit_authority(&policy, &authority, &info, arguments.clone(), vec![]),
                    Err(Failure::AuthorityDenied)
                );
            }
            assert_eq!(
                admit_authority(
                    &policy,
                    &Authority::Administrator,
                    &info,
                    arguments.clone(),
                    vec![]
                ),
                Ok(Authority::Administrator)
            );
        }
    }

    #[test]
    fn completion_allows_native_group_transition_without_new_admission() {
        let original = socket::UnixCredentials::from(nix::libc::ucred {
            pid: 123,
            uid: 0,
            gid: 984,
        });
        let completed = socket::UnixCredentials::from(nix::libc::ucred {
            pid: 123,
            uid: 0,
            gid: 0,
        });
        for completion in [false, true] {
            assert!(sender_identity_matches(123, 0, 984, original, completion));
            assert!(!sender_identity_matches(124, 0, 984, completed, completion));
            assert!(!sender_identity_matches(
                123, 1000, 984, completed, completion
            ));
        }
        assert!(!sender_identity_matches(123, 0, 984, completed, false));
        assert!(sender_identity_matches(123, 0, 984, completed, true));
    }
}
