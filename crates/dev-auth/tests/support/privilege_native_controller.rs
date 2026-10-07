use super::{linux::fixture, privilege_native_contract::Case};
use anyhow::{bail, Context, Result};
use dev_auth::privilege::{custody, policy, protocol, runtime};
use std::{
    fs,
    io::Write,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            net::UnixStream,
            process::ExitStatusExt,
        },
    },
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn publish(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let temporary = root.join(format!(".{name}.pending"));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temporary, root.join(name))?;
    Ok(())
}
fn request(session: &str, id: &str, plan: &str) -> protocol::Envelope {
    protocol::Envelope {
        version: 1,
        session: session.into(),
        request_id: id.into(),
        action: protocol::Action::Execute {
            name: "fixture".into(),
            plan: plan.into(),
        },
    }
}
fn send(session: &str, id: &str, plan: &str) -> Result<UnixStream> {
    let mut stream = UnixStream::connect(runtime::socket_path(session)?)?;
    protocol::write(
        &mut stream,
        &request(session, id, plan),
        protocol::CONTROL_BUDGET,
    )?;
    Ok(stream)
}
fn reply(stream: &mut UnixStream) -> Result<protocol::ExecutionReply> {
    policy::parse(&protocol::read(stream, Duration::from_secs(65))?)
}
fn status(session: &str) -> Result<protocol::Observation> {
    let mut stream = UnixStream::connect(runtime::socket_path(session)?)?;
    protocol::write(
        &mut stream,
        &protocol::Envelope {
            version: 1,
            session: session.into(),
            request_id: custody::random_id()?,
            action: protocol::Action::Status {},
        },
        protocol::CONTROL_BUDGET,
    )?;
    policy::parse(&protocol::read(&mut stream, protocol::CONTROL_BUDGET)?)
}
fn accepted(reply: &protocol::ExecutionReply) -> Result<()> {
    if reply.observation.started != Some(true)
        || reply.observation.exit_code != Some(0)
        || reply.observation.signal.is_some()
        || !reply.observation.cleanup_complete
    {
        bail!("approved transaction did not complete cleanly");
    }
    Ok(())
}
fn denied(reply: &protocol::ExecutionReply, reason: &str) -> Result<()> {
    if reply.observation.started != Some(false)
        || reply.observation.error_kind.as_deref() != Some(reason)
        || !reply.stdout.is_empty()
        || !reply.stderr.is_empty()
    {
        bail!("denied transaction did not preserve fixed no-effect result");
    }
    Ok(())
}
fn wait_file(path: &Path) -> Result<()> {
    let until = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        if Instant::now() >= until {
            bail!("fixture synchronization timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

pub fn run(case: &str, dev_auth: &Path, root: &Path, approval: &Path) -> Result<()> {
    fixture(root)?;
    if unsafe { nix::libc::geteuid() } == 0 {
        bail!("controller was elevated");
    }
    let case: Case = serde_json::from_value(serde_json::Value::String(case.into()))?;
    let approval: policy::ApprovalPlan = policy::parse(&fs::read(approval)?)?;
    let session = std::env::var("DEV_AUTH_PRIVILEGE_SESSION")?;
    protocol::token(&session)?;
    publish(root, "session", session.as_bytes())?;
    wait_file(&root.join("observer-held"))?;
    let command = |plan: &str| {
        let mut command = Command::new(dev_auth);
        command.args([
            "privilege",
            "execute-plan",
            "--session",
            &session,
            "--operation",
            "fixture",
            "--plan-id",
            plan,
        ]);
        command
    };
    let before = status(&session)?;
    match case {
        Case::CoreCollector => {
            let result = root.join("core-result.json");
            let output = command("core-probe")
                .arg("--result-file")
                .arg(&result)
                .output()?;
            let observed: protocol::Observation = policy::parse(&fs::read(result)?)?;
            if output.status.signal() != Some(nix::libc::SIGSEGV)
                || observed.signal != Some(nix::libc::SIGSEGV)
                || observed.exit_code.is_some()
                || !observed.cleanup_complete
            {
                bail!("native core helper/wrapper signal or cleanup differs");
            }
        }
        Case::Reuse => {
            for plan in ["write-a", "write-b", "write-a", "probe"] {
                if !command(plan).status()?.success() {
                    bail!("approved repeated operation failed");
                }
            }
            if command("not-granted").status()?.code() != Some(4) {
                bail!("unapproved plan was not denied");
            }
            for name in ["a", "b", "probe"] {
                if fs::symlink_metadata(root.join("scope").join(name))?.uid() != 0 {
                    bail!("effect did not use native root");
                }
            }
            if fs::metadata(root.join("scope/a"))?.len()
                != 2 * b"approved-root-effect\n".len() as u64
                || fs::metadata(root.join("scope/b"))?.len()
                    != b"approved-root-effect\n".len() as u64
            {
                bail!("reuse effect count differs");
            }
        }
        Case::Busy => {
            let mut first = send(&session, &custody::random_id()?, "hold")?;
            wait_file(&root.join("scope/hold"))?;
            let mut competing = send(&session, &custody::random_id()?, "write-a")?;
            denied(&reply(&mut competing)?, "busy")?;
            accepted(&reply(&mut first)?)?;
            if root.join("scope/a").exists()
                || status(&session)?.remaining_uses + 1 != before.remaining_uses
            {
                bail!("busy request consumed use or changed protected resource");
            }
        }
        Case::Replay => {
            let id = custody::random_id()?;
            accepted(&reply(&mut send(&session, &id, "write-a")?)?)?;
            let remaining = status(&session)?.remaining_uses;
            denied(
                &reply(&mut send(&session, &id, "write-b")?)?,
                "admission_denied",
            )?;
            if root.join("scope/b").exists() || status(&session)?.remaining_uses != remaining {
                bail!("replayed request consumed use or produced an effect");
            }
        }
        Case::Exhaustion => {
            let uses = approval
                .operations
                .get("fixture")
                .context("fixture operation absent")?
                .max_uses;
            if uses > 8 || approval.request.total_uses > 8 {
                bail!("exhaustion fixture budget must be at most eight");
            }
            let expected = uses.min(approval.request.total_uses);
            for _ in 0..expected {
                accepted(&reply(&mut send(
                    &session,
                    &custody::random_id()?,
                    "write-a",
                )?)?)?;
            }
            // Exhaustion can terminalize the controller immediately. Publish
            // progress before waiting for the observer's stale-request check.
            publish(root, "exhausted", &expected.to_be_bytes())?;
            let result =
                send(&session, &custody::random_id()?, "write-b").and_then(|mut s| reply(&mut s));
            if result.is_ok_and(|r| r.observation.started == Some(true)) {
                bail!("exhausted authority admitted work");
            }
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        Case::MalformedIpc => {
            let valid = serde_json::to_value(request(&session, &custody::random_id()?, "write-a"))?;
            let mut cases = Vec::new();
            for (key, value) in [
                ("version", serde_json::json!(2)),
                ("session", serde_json::json!("spoof")),
                ("request_id", serde_json::json!("bad")),
                ("caller_pid", serde_json::json!(std::process::id())),
            ] {
                let mut malformed = valid.clone();
                malformed[key] = value;
                cases.push(serde_json::to_vec(&malformed)?);
            }
            cases.push(b"{not-json".to_vec());
            for bytes in cases {
                let mut stream = UnixStream::connect(runtime::socket_path(&session)?)?;
                stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
                stream.write_all(&bytes)?;
                if protocol::read(&mut stream, Duration::from_secs(3)).is_ok() {
                    bail!("malformed control frame was accepted");
                }
            }
            for header in [0u32, protocol::FRAME_LIMIT as u32 + 1] {
                let mut stream = UnixStream::connect(runtime::socket_path(&session)?)?;
                stream.write_all(&header.to_be_bytes())?;
                if protocol::read(&mut stream, Duration::from_secs(3)).is_ok() {
                    bail!("invalid frame length was accepted");
                }
            }
            let mut slow = UnixStream::connect(runtime::socket_path(&session)?)?;
            slow.write_all(&[0])?;
            if protocol::read(&mut slow, Duration::from_secs(3)).is_ok() {
                bail!("partial frame was accepted");
            }
            unsolicited_descriptor(&session)?;
            let after = status(&session)?;
            if before.remaining_uses != after.remaining_uses
                || before.hard_deadline_boot_ms != after.hard_deadline_boot_ms
                || root.join("scope/a").exists()
            {
                bail!("malformed IPC changed authority or resources");
            }
        }
        Case::IdentityDenial => {
            publish(root, "identity-ready", b"ready")?;
            wait_file(&root.join("identity-tested"))?;
            if status(&session)?.remaining_uses != before.remaining_uses
                || root.join("scope/a").exists()
            {
                bail!("outside-controller identity consumed authority");
            }
        }
        Case::ResourceReplaced => {
            fs::rename(root.join("scope"), root.join("scope-held"))?;
            fs::create_dir(root.join("scope"))?;
            publish(root, "resource-replaced", b"ready")?;
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        Case::NestedResourceMount => {
            if !command("nested-probe").status()?.success()
                || !command("write-a").status()?.success()
            {
                bail!("nested resource mount isolation or later reuse failed");
            }
        }
        Case::LeaderExit => {
            let result_path = root.join("leader-exit.json");
            let output = command("leader-exit")
                .arg("--result-file")
                .arg(&result_path)
                .output()?;
            let observation: protocol::Observation = policy::parse(&fs::read(result_path)?)?;
            if output.status.code() != Some(23)
                || output.status.signal().is_some()
                || observation.exit_code != Some(23)
                || observation.signal.is_some()
                || observation.started != Some(true)
                || !observation.cleanup_complete
                || !output.stdout.is_empty()
                || !output.stderr.is_empty()
            {
                bail!("leader-exit status or whole-operation cleanup differs");
            }
            let heartbeat = root.join("scope/leader-heartbeat");
            let before_write = fs::metadata(&heartbeat)?;
            if before_write.uid() != 0 || before_write.len() < 5 {
                bail!("detached root descendant never wrote");
            }
            std::thread::sleep(Duration::from_millis(400));
            if fs::metadata(&heartbeat)?.len() != before_write.len() {
                bail!("descendant wrote after leader transaction returned");
            }
            if !command("write-a").status()?.success()
                || status(&session)?.remaining_uses + 2 != before.remaining_uses
            {
                bail!("successful descendant cleanup did not leave the session reusable");
            }
        }
        Case::SignalFidelity => {
            let streams = command("streams").output()?;
            if !streams.status.success()
                || streams.stdout != [0, 255, 10, 13, 128]
                || streams.stderr != [255, 0, 127, 10]
            {
                bail!("binary native stream fidelity differs");
            }
            for (plan, signal) in [
                ("signal-term", nix::libc::SIGTERM),
                ("signal-segv", nix::libc::SIGSEGV),
            ] {
                let result_path = root.join(format!("{plan}.json"));
                let result = command(plan)
                    .arg("--result-file")
                    .arg(&result_path)
                    .output()?;
                let observation: protocol::Observation = policy::parse(&fs::read(result_path)?)?;
                if observation.signal != Some(signal)
                    || observation.exit_code.is_some()
                    || observation.started != Some(true)
                    || !observation.cleanup_complete
                    || result.status.signal() != Some(signal)
                    || !result.stdout.is_empty()
                    || !result.stderr.is_empty()
                {
                    bail!("native signal identity was flattened into an ordinary exit");
                }
            }
        }
        Case::BlockedIo => {
            // Hold the reader open without draining it. The execute frontend
            // must block after the bounded reply fills this pipe, while the
            // independent authority deadline remains effective.
            let (_reader, writer) = nix::unistd::pipe()?;
            if unsafe { nix::libc::fcntl(_reader.as_raw_fd(), nix::libc::F_SETPIPE_SZ, 4096) } < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut child = command("blocked-output")
                .stdout(Stdio::from(writer))
                .stderr(Stdio::null())
                .spawn()?;
            wait_file(&root.join("scope/output"))?;
            std::thread::sleep(Duration::from_millis(250));
            if child.try_wait()?.is_some() {
                bail!("fixture output did not block its frontend");
            }
            publish(root, "io-blocked", b"ready")?;
            // A second admitted transaction proves that blocked child output
            // cannot stall the control owner. Keep its root descendant alive
            // while the first frontend still holds the undrained pipe.
            let _ = command("detached").status()?;
            bail!("blocked-output controller survived terminal authority loss");
        }
        Case::NearIdleAdmission => {
            let old_idle = before
                .hard_deadline_boot_ms
                .checked_sub(approval.request.hard_seconds * 1000)
                .context("approval clock underflow")?
                + approval.request.idle_seconds * 1000;
            let admit_at = old_idle
                .checked_sub(600)
                .context("fixture idle interval too short")?;
            while dev_auth::linux_platform::boot_time_millis()? < admit_at {
                let polled = status(&session)?;
                if polled.remaining_uses != before.remaining_uses
                    || polled.hard_deadline_boot_ms != before.hard_deadline_boot_ms
                {
                    bail!("status polling changed authority accounting");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            accepted(&reply(&mut send(
                &session,
                &custody::random_id()?,
                "hold",
            )?)?)?;
            let finished = dev_auth::linux_platform::boot_time_millis()?;
            if finished <= old_idle {
                bail!("near-idle subject did not cross the original deadline");
            }
            publish(root, "near-idle-passed", &finished.to_be_bytes())?;
            // Continued polling must not postpone the renewed idle expiry.
            loop {
                let _ = status(&session)?;
                std::thread::sleep(Duration::from_millis(40));
            }
        }
        Case::IdleExpiry => loop {
            std::thread::sleep(Duration::from_secs(1));
        },
        _ if case.needs_heartbeat() => {
            let _ = command("detached").status()?;
            bail!("controller survived terminal authority loss");
        }
        _ => bail!("acceptance case has no controller action"),
    }
    if !case.completes_normally() {
        bail!("terminal fixture case unexpectedly returned");
    }
    let after = status(&session)?;
    if after.hard_deadline_boot_ms != before.hard_deadline_boot_ms {
        bail!("session hard deadline changed");
    }
    publish(root, "controller-passed", case.name().as_bytes())?;
    Ok(())
}

fn unsolicited_descriptor(session: &str) -> Result<()> {
    let mut stream = UnixStream::connect(runtime::socket_path(session)?)?;
    let source = fs::File::open("/dev/null")?;
    let mut byte = [0u8];
    let mut vector = nix::libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // Aligned storage for exactly one SCM_RIGHTS record. The receiver must close
    // the unsolicited descriptor and reject the entire frame.
    let mut storage = [0usize; 8];
    let mut message: nix::libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = storage.as_mut_ptr().cast();
    message.msg_controllen =
        unsafe { nix::libc::CMSG_SPACE(std::mem::size_of::<i32>() as _) } as usize;
    unsafe {
        let header = nix::libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = nix::libc::SOL_SOCKET;
        (*header).cmsg_type = nix::libc::SCM_RIGHTS;
        (*header).cmsg_len = nix::libc::CMSG_LEN(std::mem::size_of::<i32>() as _) as usize;
        std::ptr::write(
            nix::libc::CMSG_DATA(header).cast::<i32>(),
            source.as_raw_fd(),
        );
        if nix::libc::sendmsg(stream.as_raw_fd(), &message, nix::libc::MSG_NOSIGNAL) != 1 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    if protocol::read(&mut stream, Duration::from_secs(3)).is_ok() {
        bail!("unsolicited descriptor was accepted");
    }
    Ok(())
}
