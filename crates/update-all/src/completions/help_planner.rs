//! Conservative help-evidence planner.
//!
//! The planner is callable only after native planning has reported unavailable or
//! invalid. A valid native result is an authority barrier and returns without any
//! help lookup or process execution.

use super::help_evidence::{sha256_hex, CapturedHelp, EvidenceKey, HelpEvidenceStore};
use super::help_ir::{parse_help, CommandNode, Completeness, CompletionIr, EvidenceRef};
use crate::util::process::{command_for_executable, terminate_process_group};
use std::collections::{BTreeSet, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Child, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) const HELP_PLANNER_VERSION: u16 = 1;
pub(crate) const DEFAULT_MAX_DEPTH: usize = 2;
pub(crate) const HARD_MAX_DEPTH: usize = 3;
pub(crate) const DEFAULT_CHILD_PROBES: usize = 16;
pub(crate) const DEFAULT_TOTAL_BUDGET: Duration = Duration::from_secs(12);
pub(crate) const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub(crate) const DEFAULT_ATTEMPT_BUDGET: usize = 20;
pub(crate) const DEFAULT_STDOUT_LIMIT: usize = 2 * 1024 * 1024;
pub(crate) const DEFAULT_STDERR_LIMIT: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeAuthority {
    Valid,
    Unavailable,
    Invalid,
}

#[derive(Clone, Debug)]
pub(crate) struct HelpPlanRequest {
    pub(crate) native_authority: NativeAuthority,
    pub(crate) command_name: String,
    pub(crate) candidate_identity: String,
    pub(crate) executable: PathBuf,
    pub(crate) launch_argv: Vec<OsString>,
    pub(crate) evidence_root: PathBuf,
    pub(crate) controlled_path: Option<OsString>,
    pub(crate) preloaded_root: Option<CapturedHelp>,
}

#[derive(Clone, Debug)]
pub(crate) struct HelpPlanLimits {
    pub(crate) max_depth: usize,
    pub(crate) max_child_probes: usize,
    pub(crate) total_budget: Duration,
    pub(crate) per_probe_timeout: Duration,
    pub(crate) attempt_budget: usize,
    pub(crate) stdout_limit: usize,
    pub(crate) stderr_limit: usize,
}

impl Default for HelpPlanLimits {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            max_child_probes: DEFAULT_CHILD_PROBES,
            total_budget: DEFAULT_TOTAL_BUDGET,
            per_probe_timeout: DEFAULT_PROBE_TIMEOUT,
            attempt_budget: DEFAULT_ATTEMPT_BUDGET,
            stdout_limit: DEFAULT_STDOUT_LIMIT,
            stderr_limit: DEFAULT_STDERR_LIMIT,
        }
    }
}

impl HelpPlanLimits {
    fn validate(&self) -> io::Result<()> {
        if self.max_depth > HARD_MAX_DEPTH {
            return Err(invalid("help recursion exceeds the hard depth limit"));
        }
        if self.max_child_probes > DEFAULT_CHILD_PROBES {
            return Err(invalid("help recursion exceeds the hard child-probe limit"));
        }
        if self.attempt_budget > DEFAULT_ATTEMPT_BUDGET {
            return Err(invalid("help planning exceeds the hard attempt limit"));
        }
        if self.total_budget > Duration::from_secs(15) || self.total_budget.is_zero() {
            return Err(invalid(
                "help planning total budget is outside the supported bound",
            ));
        }
        if self.per_probe_timeout.is_zero() || self.per_probe_timeout > self.total_budget {
            return Err(invalid(
                "help per-probe timeout is outside the total budget",
            ));
        }
        if self.stdout_limit > DEFAULT_STDOUT_LIMIT || self.stderr_limit > DEFAULT_STDERR_LIMIT {
            return Err(invalid("help output limit exceeds its hard bound"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HelpPlanOutcome {
    NativeAuthoritative,
    Generated(HelpPlan),
    Unavailable(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HelpPlan {
    pub(crate) ir: CompletionIr,
    pub(crate) canonical_ir: Vec<u8>,
    pub(crate) canonical_digest: String,
    pub(crate) process_attempts: usize,
    pub(crate) evidence_reuses: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct ProbeSpec {
    pub(crate) executable: PathBuf,
    pub(crate) argv: Vec<OsString>,
    pub(crate) path: Option<OsString>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProbeResult {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) status: Option<i32>,
    pub(crate) timed_out: bool,
    pub(crate) stdout_truncated: bool,
    pub(crate) stderr_truncated: bool,
}

pub(crate) trait HelpProbeRunner {
    fn run(
        &mut self,
        spec: &ProbeSpec,
        timeout: Duration,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> io::Result<ProbeResult>;
}

#[derive(Default)]
pub(crate) struct BoundedHelpRunner;

impl HelpProbeRunner for BoundedHelpRunner {
    fn run(
        &mut self,
        spec: &ProbeSpec,
        timeout: Duration,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> io::Result<ProbeResult> {
        if !spec.executable.is_absolute() {
            return Err(invalid("help runner requires an exact absolute executable"));
        }
        let metadata = fs::metadata(&spec.executable)?;
        if !metadata.is_file() {
            return Err(invalid("help runner executable is not a regular file"));
        }
        let mut command = command_for_executable(&spec.executable);
        command.args(&spec.argv);
        command
            .current_dir(std::env::temp_dir())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.env_clear();
        if let Some(path) = &spec.path {
            command.env("PATH", path);
        }
        command
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .env("PAGER", "cat")
            .env("GIT_PAGER", "cat");
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| invalid("help child stdout was not piped"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| invalid("help child stderr was not piped"))?;
        let stdout_reader = spawn_bounded_reader(stdout, stdout_limit);
        let stderr_reader = spawn_bounded_reader(stderr, stderr_limit);
        let started = Instant::now();
        let (status, timed_out) = loop {
            if let Some(status) = child.try_wait()? {
                break (Some(status), false);
            }
            if started.elapsed() >= timeout {
                terminate_process_tree(&mut child);
                break (child.wait().ok(), true);
            }
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = join_reader(stdout_reader)?;
        let stderr = join_reader(stderr_reader)?;
        Ok(ProbeResult {
            stdout: stdout.bytes,
            stderr: stderr.bytes,
            status: status.as_ref().and_then(ExitStatus::code),
            timed_out,
            stdout_truncated: stdout.truncated,
            stderr_truncated: stderr.truncated,
        })
    }
}

struct BoundedRead {
    bytes: Vec<u8>,
    truncated: bool,
}

fn spawn_bounded_reader<R>(
    mut reader: R,
    limit: usize,
) -> thread::JoinHandle<io::Result<BoundedRead>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
        let mut buffer = [0u8; 8192];
        let mut truncated = false;
        loop {
            let count = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            let remaining = limit.saturating_sub(bytes.len());
            let keep = remaining.min(count);
            bytes.extend_from_slice(&buffer[..keep]);
            if keep < count {
                truncated = true;
            }
        }
        Ok(BoundedRead { bytes, truncated })
    })
}

fn join_reader(handle: thread::JoinHandle<io::Result<BoundedRead>>) -> io::Result<BoundedRead> {
    handle
        .join()
        .map_err(|_| invalid("help output reader panicked"))?
}

fn terminate_process_tree(child: &mut Child) {
    terminate_process_group(child.id());
    let _ = child.kill();
}

pub(crate) fn plan_help<R: HelpProbeRunner>(
    request: &HelpPlanRequest,
    limits: &HelpPlanLimits,
    runner: &mut R,
) -> io::Result<HelpPlanOutcome> {
    limits.validate()?;
    if request.native_authority == NativeAuthority::Valid {
        return Ok(HelpPlanOutcome::NativeAuthoritative);
    }
    if !request.executable.is_absolute() {
        return Err(invalid(
            "help planner requires an exact resolved executable",
        ));
    }
    let store = HelpEvidenceStore::new(request.evidence_root.clone());
    let started = Instant::now();
    let mut attempts = 0usize;
    let mut reuses = 0usize;
    let root_path = vec![request.command_name.clone()];
    let root_capture = capture_node(
        request,
        limits,
        runner,
        &store,
        &root_path,
        started,
        &mut attempts,
        &mut reuses,
    )?;
    let Some((root_node, root_evidence)) = root_capture else {
        return Ok(HelpPlanOutcome::Unavailable(
            "bounded root help evidence was unavailable or unparseable".into(),
        ));
    };
    let mut ir = CompletionIr::new(request.command_name.clone(), root_evidence);
    ir.root = root_node;
    let mut queue = VecDeque::new();
    for child in &ir.root.subcommands {
        queue.push_back(child.canonical_path.clone());
    }
    let mut visited = BTreeSet::new();
    visited.insert(root_path.join("\0"));
    let mut child_probes = 0usize;
    while let Some(path) = queue.pop_front() {
        let depth = path.len().saturating_sub(1);
        if depth > limits.max_depth {
            mark_partial(&mut ir.root, &path, Completeness::PartialDepth);
            continue;
        }
        if child_probes >= limits.max_child_probes
            || attempts >= limits.attempt_budget
            || started.elapsed() >= limits.total_budget
        {
            mark_partial(&mut ir.root, &path, Completeness::PartialBudget);
            continue;
        }
        let cycle_key = path.join("\0");
        if !visited.insert(cycle_key) {
            mark_partial(&mut ir.root, &path, Completeness::PartialCycle);
            continue;
        }
        child_probes += 1;
        match capture_node(
            request,
            limits,
            runner,
            &store,
            &path,
            started,
            &mut attempts,
            &mut reuses,
        )? {
            Some((node, evidence)) => {
                let evidence_index = ir.evidence.len();
                ir.evidence.push(evidence);
                let mut reparsed = node;
                rebind_evidence(&mut reparsed, evidence_index);
                for child in &reparsed.subcommands {
                    queue.push_back(child.canonical_path.clone());
                }
                ir.merge_node(reparsed);
            }
            None => mark_partial(&mut ir.root, &path, Completeness::PartialParse),
        }
    }
    ir.normalize();
    let canonical_ir = ir.encode_canonical()?;
    let canonical_digest = sha256_hex(&canonical_ir);
    Ok(HelpPlanOutcome::Generated(HelpPlan {
        ir,
        canonical_ir,
        canonical_digest,
        process_attempts: attempts,
        evidence_reuses: reuses,
    }))
}

fn capture_node<R: HelpProbeRunner>(
    request: &HelpPlanRequest,
    limits: &HelpPlanLimits,
    runner: &mut R,
    store: &HelpEvidenceStore,
    command_path: &[String],
    started: Instant,
    attempts: &mut usize,
    reuses: &mut usize,
) -> io::Result<Option<(CommandNode, EvidenceRef)>> {
    if *attempts >= limits.attempt_budget || started.elapsed() >= limits.total_budget {
        return Ok(None);
    }
    let mut argv = request.launch_argv.clone();
    argv.extend(command_path.iter().skip(1).map(OsString::from));
    argv.push(OsString::from("--help"));
    let key = EvidenceKey {
        candidate_identity: request.candidate_identity.clone(),
        executable: request.executable.clone(),
        argv: argv
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect(),
    };
    let remaining = limits.total_budget.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Ok(None);
    }
    let timeout = limits.per_probe_timeout.min(remaining);
    let is_root = command_path.len() == 1;
    let mut preloaded = is_root.then(|| request.preloaded_root.clone()).flatten();
    let mut invoked = false;
    let stored = store.capture_once(&key, || {
        if let Some(capture) = preloaded.take() {
            return Ok(capture);
        }
        invoked = true;
        *attempts += 1;
        let result = runner.run(
            &ProbeSpec {
                executable: request.executable.clone(),
                argv: argv.clone(),
                path: request.controlled_path.clone(),
            },
            timeout,
            limits.stdout_limit,
            limits.stderr_limit,
        )?;
        if result.timed_out {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "help probe timed out",
            ));
        }
        Ok(CapturedHelp {
            stdout: result.stdout,
            stderr: result.stderr,
            exit_code: result.status,
            stdout_truncated: result.stdout_truncated,
            stderr_truncated: result.stderr_truncated,
        })
    });
    let stored = match stored {
        Ok(value) => value,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    if stored.reused {
        *reuses += 1;
    }
    debug_assert!(stored.reused || invoked || (is_root && request.preloaded_root.is_some()));
    let parse_bytes = if !stored.capture.stdout.is_empty() {
        &stored.capture.stdout
    } else {
        &stored.capture.stderr
    };
    if parse_bytes.is_empty() {
        return Ok(None);
    }
    let evidence = EvidenceRef {
        digest: stored.digest,
        argv: key.argv,
        exit_code: stored.capture.exit_code,
        truncated_stdout: stored.capture.stdout_truncated,
        truncated_stderr: stored.capture.stderr_truncated,
    };
    let node = parse_help(parse_bytes, command_path, 0);
    if node.options.is_empty() && node.positionals.is_empty() && node.subcommands.is_empty() {
        return Ok(None);
    }
    Ok(Some((node, evidence)))
}

fn rebind_evidence(node: &mut CommandNode, evidence_index: usize) {
    node.evidence.clear();
    node.evidence.push(evidence_index);
    if let Some(description) = &mut node.description {
        description.evidence.clear();
        description.evidence.push(evidence_index);
    }
    for option in &mut node.options {
        if let Some(description) = &mut option.description {
            description.evidence.clear();
            description.evidence.push(evidence_index);
        }
    }
    for positional in &mut node.positionals {
        if let Some(description) = &mut positional.description {
            description.evidence.clear();
            description.evidence.push(evidence_index);
        }
    }
    for child in &mut node.subcommands {
        rebind_evidence(child, evidence_index);
    }
}

fn mark_partial(root: &mut CommandNode, path: &[String], reason: Completeness) {
    let mut node = root;
    for part in path.iter().skip(1) {
        let Some(next) = node.find_child_mut(part) else {
            return;
        };
        node = next;
    }
    node.completeness.remove(&Completeness::Unknown);
    node.completeness.remove(&Completeness::Complete);
    node.completeness.insert(reason);
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Default)]
    struct FakeRunner {
        calls: Arc<Mutex<Vec<Vec<OsString>>>>,
        outputs: VecDeque<ProbeResult>,
    }
    impl HelpProbeRunner for FakeRunner {
        fn run(
            &mut self,
            spec: &ProbeSpec,
            _: Duration,
            _: usize,
            _: usize,
        ) -> io::Result<ProbeResult> {
            self.calls.lock().unwrap().push(spec.argv.clone());
            self.outputs
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no fake output"))
        }
    }
    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "update-all-help-plan-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }
    fn request(root: PathBuf, native: NativeAuthority) -> HelpPlanRequest {
        HelpPlanRequest {
            native_authority: native,
            command_name: "tool".into(),
            candidate_identity: "identity".into(),
            executable: if cfg!(windows) {
                PathBuf::from(r"C:\tool.exe")
            } else {
                PathBuf::from("/bin/tool")
            },
            launch_argv: Vec::new(),
            evidence_root: root,
            controlled_path: None,
            preloaded_root: None,
        }
    }
    fn result(stdout: &[u8]) -> ProbeResult {
        ProbeResult {
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
            status: Some(0),
            timed_out: false,
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    #[test]
    fn valid_native_is_authoritative_and_runs_zero_help_probes() {
        let root = temp_root("native");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut runner = FakeRunner {
            calls: calls.clone(),
            outputs: VecDeque::new(),
        };
        assert_eq!(
            plan_help(
                &request(root, NativeAuthority::Valid),
                &HelpPlanLimits::default(),
                &mut runner
            )
            .unwrap(),
            HelpPlanOutcome::NativeAuthoritative
        );
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn exact_identity_reuses_raw_evidence_without_process_probe() {
        let root = temp_root("reuse");
        let mut first = FakeRunner {
            calls: Arc::default(),
            outputs: VecDeque::from([result(
                b"Usage: tool [OPTIONS]\n\nOptions:\n  --flag  flag\n",
            )]),
        };
        let first_plan = plan_help(
            &request(root.clone(), NativeAuthority::Unavailable),
            &HelpPlanLimits {
                max_depth: 0,
                max_child_probes: 0,
                ..HelpPlanLimits::default()
            },
            &mut first,
        )
        .unwrap();
        assert!(matches!(first_plan, HelpPlanOutcome::Generated(_)));
        let mut second = FakeRunner::default();
        let second_plan = plan_help(
            &request(root.clone(), NativeAuthority::Unavailable),
            &HelpPlanLimits {
                max_depth: 0,
                max_child_probes: 0,
                ..HelpPlanLimits::default()
            },
            &mut second,
        )
        .unwrap();
        let HelpPlanOutcome::Generated(second_plan) = second_plan else {
            panic!("expected generated")
        };
        assert_eq!(second_plan.process_attempts, 0);
        assert_eq!(second_plan.evidence_reuses, 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn native_root_help_is_persisted_without_a_second_process_probe() {
        let root = temp_root("preloaded-root");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut first_request = request(root.clone(), NativeAuthority::Unavailable);
        first_request.preloaded_root = Some(CapturedHelp {
            stdout: b"Usage: tool [OPTIONS]\n\nOptions:\n  --flag  flag\n".to_vec(),
            stderr: Vec::new(),
            exit_code: None,
            stdout_truncated: false,
            stderr_truncated: false,
        });
        let limits = HelpPlanLimits {
            max_depth: 0,
            max_child_probes: 0,
            ..HelpPlanLimits::default()
        };
        let mut first = FakeRunner {
            calls: calls.clone(),
            outputs: VecDeque::new(),
        };
        let first_plan = plan_help(&first_request, &limits, &mut first).unwrap();
        let HelpPlanOutcome::Generated(first_plan) = first_plan else {
            panic!("expected generated help plan");
        };
        assert_eq!(first_plan.process_attempts, 0);
        assert!(calls.lock().unwrap().is_empty());

        let mut second = FakeRunner::default();
        let second_plan = plan_help(
            &request(root.clone(), NativeAuthority::Unavailable),
            &limits,
            &mut second,
        )
        .unwrap();
        let HelpPlanOutcome::Generated(second_plan) = second_plan else {
            panic!("expected cached help plan");
        };
        assert_eq!(second_plan.process_attempts, 0);
        assert_eq!(second_plan.evidence_reuses, 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn recursion_is_bounded_and_marks_partial_nodes() {
        let root = temp_root("budget");
        let root_help = b"Usage: tool <COMMAND>\n\nCommands:\n  a  first\n  b  second\n";
        let child_help = b"Usage: tool a [OPTIONS]\n\nOptions:\n  --flag  flag\n";
        let mut runner = FakeRunner {
            calls: Arc::default(),
            outputs: VecDeque::from([result(root_help), result(child_help)]),
        };
        let outcome = plan_help(
            &request(root.clone(), NativeAuthority::Invalid),
            &HelpPlanLimits {
                max_child_probes: 1,
                attempt_budget: 2,
                ..HelpPlanLimits::default()
            },
            &mut runner,
        )
        .unwrap();
        let HelpPlanOutcome::Generated(plan) = outcome else {
            panic!("expected generated")
        };
        assert_eq!(plan.process_attempts, 2);
        assert!(plan
            .ir
            .root
            .subcommands
            .iter()
            .any(|node| node.completeness.contains(&Completeness::PartialBudget)));
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_runner_times_out_and_terminates_descendants() {
        let shell = PathBuf::from("/bin/sh");
        if !shell.exists() {
            return;
        }
        let marker = temp_root("descendant-marker");
        let script = format!(
            "(sleep 1; printf bad > {}) & sleep 30",
            shell_quote(&marker)
        );
        let mut runner = BoundedHelpRunner;
        let result = runner
            .run(
                &ProbeSpec {
                    executable: shell,
                    argv: vec![OsString::from("-c"), OsString::from(script)],
                    path: Some(OsString::from("/usr/bin:/bin")),
                },
                Duration::from_millis(100),
                1024,
                1024,
            )
            .unwrap();
        assert!(result.timed_out);
        thread::sleep(Duration::from_millis(1200));
        assert!(
            !marker.exists(),
            "descendant survived the process-group termination"
        );
    }

    #[cfg(unix)]
    fn shell_quote(path: &std::path::Path) -> String {
        format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
    }
}
