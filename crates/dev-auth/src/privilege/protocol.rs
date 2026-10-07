//! Bounded value-free authority control, separate from admitted child streams.
use super::policy::{identifier, DOCUMENT_LIMIT};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{IoSliceMut, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

pub const VERSION: u32 = 1;
pub const FRAME_LIMIT: usize = DOCUMENT_LIMIT;
pub const CONTROL_BUDGET: Duration = Duration::from_secs(2);

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u32,
    pub session: String,
    pub request_id: String,
    pub action: Action,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Execute { name: String, plan: String },
    Status {},
    Revoke {},
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub version: u32,
    pub outcome: String,
    pub started: Option<bool>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub remaining_uses: u64,
    pub hard_deadline_boot_ms: u64,
    pub cleanup_complete: bool,
    pub error_kind: Option<String>,
}

impl Observation {
    /// Positive terminal cleanup does not erase an earlier failed or unknown
    /// effect. Public terminal commands must preserve both facts.
    /// Child exit metadata is observational. Protocol/cancellation/cleanup
    /// failure cannot turn a native exit zero into CLI success.
    pub fn execution_exit_code(&self) -> i32 {
        if let Some(code) = self.exit_code.filter(|code| *code != 0) {
            return code;
        }
        if self.outcome == "exited"
            && self.exit_code == Some(0)
            && self.signal.is_none()
            && self.error_kind.is_none()
            && self.cleanup_complete
            && self.started == Some(true)
        {
            0
        } else {
            1
        }
    }
    pub fn terminal_success(&self) -> bool {
        self.cleanup_complete
            && self.error_kind.is_none()
            && matches!(self.outcome.as_str(), "completed" | "stopped")
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReply {
    pub observation: Observation,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub fn parse_request(bytes: &[u8]) -> Result<Envelope> {
    let request: Envelope = super::policy::parse(bytes)?;
    if request.version != VERSION {
        bail!("administrative control version is unsupported");
    }
    token(&request.session)?;
    token(&request.request_id)?;
    if let Action::Execute { name, plan } = &request.action {
        identifier(name)?;
        identifier(plan)?;
    }
    Ok(request)
}

pub fn token(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("administrative control identity is invalid");
    }
    Ok(())
}

pub fn read(stream: &mut UnixStream, budget: Duration) -> Result<Vec<u8>> {
    let deadline = Instant::now()
        .checked_add(budget)
        .context("administrative frame deadline overflow")?;
    let mut header = [0; 4];
    receive_before(stream, &mut header, deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > FRAME_LIMIT {
        bail!("administrative control frame exceeds bounds");
    }
    let mut bytes = vec![0; length];
    receive_before(stream, &mut bytes, deadline)?;
    Ok(bytes)
}

fn receive_before(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
    use rustix::net::{recvmsg, RecvAncillaryBuffer, RecvFlags, ReturnFlags};
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let mut storage = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut storage);
        let received = match recvmsg(
            &*stream,
            &mut [IoSliceMut::new(bytes)],
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC,
        ) {
            Err(rustix::io::Errno::INTR) => continue,
            result => result?,
        };
        let unexpected = ancillary.drain().count() != 0;
        if unexpected || received.flags.contains(ReturnFlags::CTRUNC) || received.bytes == 0 {
            bail!("administrative control transport is invalid");
        }
        let (_, rest) = bytes.split_at_mut(received.bytes);
        bytes = rest;
    }
    Ok(())
}

pub fn write<T: Serialize>(stream: &mut UnixStream, value: &T, budget: Duration) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > FRAME_LIMIT {
        bail!("administrative control response exceeds bounds");
    }
    let deadline = Instant::now()
        .checked_add(budget)
        .context("administrative frame deadline overflow")?;
    send_before(stream, &(bytes.len() as u32).to_be_bytes(), deadline)?;
    send_before(stream, &bytes, deadline)
}

fn send_before(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => bail!("administrative control peer closed"),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .context("administrative control deadline expired")
}
