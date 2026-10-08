//! Public-command protocol contracts against disposable local HTTP fixtures.
//! These mocks do not qualify a real Docker engine or any native platform.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tempfile::TempDir;

const VERSION: &str = "/version";
const INFO: &str = "/v1.51/info";
const USAGE: &str = "/v1.51/system/df?type=build-cache";
const CHILD_TIMEOUT: Duration = Duration::from_secs(10);

struct Step {
    request: String,
    response: Vec<u8>,
    probe_write_half: bool,
    hold_response: bool,
    replace_socket: bool,
}

impl Step {
    fn json(method: &str, path: &str, value: Value) -> Self {
        Self::status(method, path, 200, value)
    }

    fn status(method: &str, path: &str, status: u16, value: Value) -> Self {
        let body = value.to_string();
        Self {
            request: format!("{method} {path} HTTP/1.0"),
            response: format!(
                "HTTP/1.0 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
            probe_write_half: false,
            hold_response: false,
            replace_socket: false,
        }
    }
}

#[derive(Default)]
struct Traffic {
    requests: Vec<String>,
    errors: Vec<String>,
    write_half_probes: usize,
}

struct Fixture {
    _directory: TempDir,
    socket: PathBuf,
    expected: Vec<String>,
    traffic: Arc<Mutex<Traffic>>,
    stop: Arc<AtomicBool>,
    arrivals: mpsc::Receiver<usize>,
    worker: Option<JoinHandle<()>>,
}

impl Fixture {
    fn new(steps: Vec<Step>) -> Self {
        // A short absolute pathname also fits Linux sockaddr_un's bounded path.
        let directory = tempfile::Builder::new()
            .prefix("dev-cache-native-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = directory.path().join("engine.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        // All responses originate from this test process. No engine, forked
        // helper, privilege change, or ambient Docker context is involved.
        // SAFETY: geteuid has no preconditions and does not mutate state.
        assert_eq!(fs::metadata(&socket).unwrap().uid(), unsafe {
            libc::geteuid()
        });
        let expected = steps.iter().map(|step| step.request.clone()).collect();
        let traffic = Arc::new(Mutex::new(Traffic::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let (sender, arrivals) = mpsc::channel();
        let shared = traffic.clone();
        let stopping = stop.clone();
        let socket_path = socket.clone();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut steps = steps.into_iter();
            let mut replacements = Vec::new();
            while !stopping.load(Ordering::Acquire) && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => {
                        shared.lock().unwrap().errors.push(error.to_string());
                        break;
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                let request = match read_request(&mut stream, &stopping) {
                    Ok(request) => request,
                    Err(error) => {
                        shared.lock().unwrap().errors.push(error);
                        continue;
                    }
                };
                let index = {
                    let mut traffic = shared.lock().unwrap();
                    traffic.requests.push(request);
                    traffic.requests.len()
                };
                let _ = sender.send(index);
                let Some(step) = steps.next() else {
                    let response = Step::status("GET", "/unexpected", 500, json!({}));
                    let _ = stream.write_all(&response.response);
                    continue;
                };
                if step.probe_write_half {
                    let mut byte = [0];
                    match stream.read(&mut byte) {
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) =>
                        {
                            shared.lock().unwrap().write_half_probes += 1
                        }
                        Ok(0) => shared
                            .lock()
                            .unwrap()
                            .errors
                            .push("client half-closed before delayed response".into()),
                        other => shared
                            .lock()
                            .unwrap()
                            .errors
                            .push(format!("unexpected request bytes while waiting: {other:?}")),
                    }
                }
                if step.hold_response {
                    while !stopping.load(Ordering::Acquire) && Instant::now() < deadline {
                        thread::sleep(Duration::from_millis(2));
                    }
                    continue;
                }
                if step.replace_socket {
                    fs::remove_file(&socket_path).unwrap();
                    replacements.push(UnixListener::bind(&socket_path).unwrap());
                }
                if let Err(error) = stream.write_all(&step.response) {
                    shared.lock().unwrap().errors.push(error.to_string());
                }
            }
        });
        Self {
            _directory: directory,
            socket,
            expected,
            traffic,
            stop,
            arrivals,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> Traffic {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap();
        let traffic = std::mem::take(&mut *self.traffic.lock().unwrap());
        assert!(traffic.errors.is_empty(), "{:?}", traffic.errors);
        assert_eq!(traffic.requests, self.expected, "exact native HTTP traffic");
        traffic
    }

    fn await_request(&self, number: usize) {
        let deadline = Instant::now() + CHILD_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "request {number} did not arrive");
            if self.arrivals.recv_timeout(left).expect("fixture request") == number {
                break;
            }
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn read_request(stream: &mut UnixStream, stop: &AtomicBool) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut bytes = Vec::new();
    let mut chunk = [0; 2048];
    loop {
        if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err("incomplete or unbounded fixture request".into());
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err("EOF before HTTP request headers".into()),
            Ok(count) => bytes.extend_from_slice(&chunk[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(error) => return Err(error.to_string()),
        }
        if bytes.len() > 16 * 1024 {
            return Err("oversized fixture request".into());
        }
        if bytes.ends_with(b"\r\n\r\n") {
            let text = String::from_utf8(bytes).map_err(|error| error.to_string())?;
            let (request, headers) = text.split_once("\r\n").unwrap();
            if headers != "Host: docker\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: 0\r\n\r\n" {
                return Err(format!("unexpected request headers/body: {headers:?}"));
            }
            return Ok(request.to_owned());
        }
    }
}

fn version() -> Value {
    json!({
        "Platform": {"Name": "Docker Engine - Community"},
        "ApiVersion": "1.51", "MinAPIVersion": "1.24"
    })
}

fn info() -> Value {
    json!({
        "ID": "fixture-engine", "DockerRootDir": "/fixture/storage",
        "SecurityOptions": ["name=rootless"], "OSType": "linux",
        "OperatingSystem": "fixture", "ServerVersion": "28.3.3"
    })
}

fn record(id: &str, kind: &str, bytes: u64) -> Value {
    json!({"ID": id, "Type": kind, "InUse": false, "Shared": false, "Size": bytes})
}

fn observe(records: Value) -> Vec<Step> {
    vec![
        Step::json("GET", VERSION, version()),
        Step::json("GET", INFO, info()),
        Step::json("GET", USAGE, json!({"BuildCache": records})),
    ]
}

fn apply_args(ids: &[&str]) -> Vec<String> {
    let mut args = vec![
        "--apply".into(),
        "--engine-id=fixture-engine".into(),
        "--storage-root=/fixture/storage".into(),
        "--privilege-domain=rootless".into(),
    ];
    args.extend(ids.iter().map(|id| format!("--cache-id={id}")));
    args
}

fn command(home: &Path, provider: &str, socket: Option<&Path>, args: &[String]) -> Command {
    // A transferred test executable can exercise the exact sibling product
    // artifact on a native test host without retaining a build-host pathname.
    let executable = std::env::var_os("DEV_CACHE_NATIVE_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_dev-cache")));
    assert!(
        executable.is_absolute(),
        "DEV_CACHE_NATIVE_TEST_BINARY must be an absolute path"
    );
    let mut command = Command::new(executable);
    command
        .env_clear()
        .env("HOME", home)
        .env("PATH", "")
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_RUNTIME_DIR", home.join("runtime"))
        .current_dir(home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(["container-cache", provider, "--json"]);
    if let Some(socket) = socket {
        command.arg("--socket").arg(socket);
    }
    command.args(args);
    command
}

struct OwnedChild(Option<Child>);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn bounded_output(child: Child) -> Output {
    let mut child = OwnedChild(Some(child));
    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        if child.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            return child.0.take().unwrap().wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            let _ = child.0.as_mut().unwrap().kill();
            let output = child.0.take().unwrap().wait_with_output().unwrap();
            panic!(
                "native-cache child exceeded {CHILD_TIMEOUT:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn report(output: Output, exit_code: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(exit_code),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    // from_slice also rejects a second JSON document or trailing diagnostics.
    let value: Value = serde_json::from_slice(&output.stdout).expect("one JSON report");
    assert_eq!(value["schema"], "dev-cache-native-cache-v1");
    assert_eq!(value["exit_code"], exit_code);
    value
}

fn run(fixture: &Fixture, args: &[String], exit_code: i32) -> Value {
    let home = tempfile::tempdir().unwrap();
    report(
        bounded_output(
            command(home.path(), "docker", Some(&fixture.socket), args)
                .spawn()
                .unwrap(),
        ),
        exit_code,
    )
}

fn assert_unmutated(value: &Value, error: &str) {
    assert_eq!(value["error_kind"], error);
    assert_eq!(value["changed"], false);
    assert_eq!(value["mutation_uncertain"], false);
    assert_eq!(value["deleted_cache_ids"], json!([]));
    assert_eq!(value["reclaimed_bytes"], 0);
    assert!(value["after"].is_null());
}

#[test]
fn preview_is_observe_only_and_reports_exact_local_scope_and_abstentions() {
    let mut active = record("active1", "regular", 11);
    active["InUse"] = json!(true);
    let mut shared = record("shared1", "regular", 17);
    shared["Shared"] = json!(true);
    let fixture = Fixture::new(observe(json!([
        record("z9", "source.local", 29),
        active,
        shared,
        record("unknown1", "future.kind", 23),
        record("a1", "regular", 7)
    ])));
    let result = run(&fixture, &["--cache-id=a1".into()], 0);
    assert_eq!(result["operation"], "preview");
    assert_eq!(result["outcome"], "preview");
    assert_eq!(result["provider"], "docker");
    assert!(result["error_kind"].is_null());
    assert_eq!(result["changed"], false);
    assert_eq!(result["mutation_uncertain"], false);
    assert_eq!(result["selected_cache_ids"], json!(["a1"]));
    assert_eq!(result["deleted_cache_ids"], json!([]));
    assert_eq!(
        result["scope"],
        json!({
            "builder": "docker-engine-integrated-buildkit", "socket": fixture.socket,
            "engine_id": "fixture-engine", "storage_root": "/fixture/storage",
            "privilege_domain": "rootless", "server_version": "28.3.3",
            "backend_locality": "unverified", "daemon_executable": null
        })
    );
    assert_eq!(result["before"]["reclaimable_record_bytes_estimate"], 36);
    assert_eq!(result["before"]["shared_record_bytes"], 17);
    let records = result["before"]["records"].as_array().unwrap();
    assert_eq!(
        records
            .iter()
            .map(|row| row["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["a1", "active1", "shared1", "unknown1", "z9"]
    );
    for (index, reason) in [
        (1, "active-build-cache"),
        (2, "shared-with-retained-resource"),
        (3, "unsupported-cache-kind"),
    ] {
        assert_eq!(records[index]["eligible"], false);
        assert_eq!(records[index]["abstention"], reason);
    }
    assert_eq!(records[0]["eligible"], true);
    assert!(result["after"].is_null());
    fixture.finish();
}

#[test]
fn ambient_docker_and_buildx_settings_cannot_redirect_explicit_socket() {
    let fixture = Fixture::new(observe(json!([])));
    let home = tempfile::tempdir().unwrap();
    let mut cmd = command(home.path(), "docker", Some(&fixture.socket), &[]);
    cmd.env("DOCKER_HOST", "tcp://127.0.0.1:1")
        .env("DOCKER_CONTEXT", "hostile-context")
        .env("DOCKER_CONFIG", home.path().join("hostile-config"))
        .env("BUILDX_BUILDER", "hostile-builder")
        .env("BUILDKIT_HOST", "tcp://127.0.0.1:2");
    let result = report(bounded_output(cmd.spawn().unwrap()), 0);
    assert_eq!(result["scope"]["socket"], json!(fixture.socket));
    fixture.finish();
}

#[test]
fn provider_and_local_socket_admission_fail_before_any_http_request() {
    let fixture = Fixture::new(vec![]);
    let home = tempfile::tempdir().unwrap();
    let result = report(
        bounded_output(
            command(home.path(), "podman", Some(&fixture.socket), &[])
                .spawn()
                .unwrap(),
        ),
        3,
    );
    assert_eq!(result["outcome"], "unsupported");
    assert_unmutated(&result, "unsupported-native-provider");
    let result = report(
        bounded_output(
            command(home.path(), "docker", None, &[])
                .env(
                    "DOCKER_HOST",
                    format!("unix://{}", fixture.socket.display()),
                )
                .spawn()
                .unwrap(),
        ),
        2,
    );
    assert_unmutated(&result, "invalid-native-scope");
    for path in [
        "relative.sock",
        "tcp://127.0.0.1:2375",
        "https://remote.invalid/socket",
        "unix:///tmp/engine.sock",
        "/tmp/../engine.sock",
    ] {
        let result = report(
            bounded_output(
                command(home.path(), "docker", Some(Path::new(path)), &[])
                    .spawn()
                    .unwrap(),
            ),
            2,
        );
        assert_unmutated(&result, "invalid-native-scope");
    }
    let regular = home.path().join("not-a-socket");
    fs::write(&regular, b"untouched").unwrap();
    for path in [
        home.path(),
        regular.as_path(),
        &home.path().join("absent.sock"),
    ] {
        let result = report(
            bounded_output(
                command(home.path(), "docker", Some(path), &[])
                    .spawn()
                    .unwrap(),
            ),
            4,
        );
        assert_unmutated(&result, "invalid-local-socket");
    }
    assert_eq!(fs::read(regular).unwrap(), b"untouched");
    fixture.finish();
}

#[test]
fn apply_requires_all_scope_fields_and_a_bounded_unique_alphanumeric_selection() {
    let fixture = Fixture::new(vec![]);
    let complete = apply_args(&["cache1"]);
    for omitted in 1..complete.len() {
        let mut args = complete.clone();
        args.remove(omitted);
        assert_unmutated(&run(&fixture, &args, 2), "invalid-native-scope");
    }
    let long = "a".repeat(129);
    for ids in [
        vec!["cache1", "cache1"],
        vec![""],
        vec!["bad-id"],
        vec!["a.*"],
        vec!["a/b"],
        vec!["é"],
        vec![long.as_str()],
    ] {
        assert_unmutated(&run(&fixture, &apply_args(&ids), 2), "invalid-native-scope");
    }
    let ids: Vec<String> = (0..33).map(|index| format!("cache{index}")).collect();
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    assert_unmutated(
        &run(&fixture, &apply_args(&refs), 2),
        "invalid-native-scope",
    );
    fixture.finish();
}

#[test]
fn cache_accounting_accepts_explicit_null_or_empty_but_never_missing_fields() {
    for cache in [Value::Null, json!([])] {
        let fixture = Fixture::new(observe(cache));
        let result = run(&fixture, &[], 0);
        assert_eq!(result["before"]["records"], json!([]));
        assert_eq!(result["before"]["reclaimable_record_bytes_estimate"], 0);
        fixture.finish();
    }
    let mut bad_bodies = vec![json!({}), json!({"BuildCache": {}})];
    for field in ["ID", "Type", "InUse", "Shared", "Size"] {
        let mut incomplete = record("a1", "regular", 1);
        incomplete.as_object_mut().unwrap().remove(field);
        bad_bodies.push(json!({"BuildCache": [incomplete]}));
    }
    bad_bodies.extend([
        json!({"BuildCache": [record("a1", "regular", 1), record("a1", "regular", 2)]}),
        json!({"BuildCache": [record("bad-id", "regular", 1)]}),
        json!({"BuildCache": [{"ID":"a1","Type":"regular","InUse":null,"Shared":false,"Size":1}]}),
        json!({"BuildCache": [{"ID":"a1","Type":"regular","InUse":false,"Shared":false,"Size":-1}]}),
    ]);
    for body in bad_bodies {
        let mut steps = observe(json!([]));
        steps[2] = Step::json("GET", USAGE, body);
        let fixture = Fixture::new(steps);
        assert_unmutated(&run(&fixture, &[], 1), "unsupported-native-response");
        fixture.finish();
    }
}

#[test]
fn socket_identity_replacement_is_detected_before_further_requests() {
    let mut step = Step::json("GET", VERSION, version());
    step.replace_socket = true;
    let fixture = Fixture::new(vec![step]);
    assert_unmutated(&run(&fixture, &[], 4), "native-scope-changed");
    fixture.finish();
}

#[test]
fn unsupported_engine_capabilities_are_not_interpreted_as_empty_cache() {
    for (field, value) in [
        ("ApiVersion", json!("1.50")),
        ("MinAPIVersion", json!("1.52")),
        ("ApiVersion", json!("bad")),
        ("Platform", json!({"Name":"Podman Engine"})),
    ] {
        let mut incompatible = version();
        incompatible[field] = value;
        let fixture = Fixture::new(vec![Step::json("GET", VERSION, incompatible)]);
        assert_unmutated(&run(&fixture, &[], 3), "unsupported-native-provider");
        fixture.finish();
    }
    for (field, value) in [
        ("OSType", json!("windows")),
        ("OperatingSystem", json!("Docker Desktop")),
        ("DockerRootDir", json!("relative")),
    ] {
        let mut incompatible = info();
        incompatible[field] = value;
        let fixture = Fixture::new(vec![
            Step::json("GET", VERSION, version()),
            Step::json("GET", INFO, incompatible),
        ]);
        assert_unmutated(&run(&fixture, &[], 3), "unsupported-native-provider");
        fixture.finish();
    }
}

#[test]
fn permission_denied_before_mutation_is_value_free_and_unchanged() {
    let fixture = Fixture::new(vec![Step::status(
        "GET",
        VERSION,
        403,
        json!({"message":"sensitive-provider-detail"}),
    )]);
    let result = run(&fixture, &[], 3);
    assert_unmutated(&result, "native-permission-denied");
    assert!(!result.to_string().contains("sensitive-provider-detail"));
    fixture.finish();
}

#[test]
fn docker_shaped_local_proxy_is_readable_but_cannot_authorize_apply() {
    let fixture = Fixture::new(observe(json!([record("a1", "regular", 10)])));
    let result = run(&fixture, &apply_args(&["a1"]), 3);
    assert_unmutated(&result, "native-daemon-locality-unverified");
    assert_eq!(result["scope"]["backend_locality"], "unverified");
    assert!(result["scope"]["daemon_executable"].is_null());
    assert_eq!(result["before"]["records"][0]["eligible"], true);
    // Matching engine identity, scope, and accounting from a local peer do not
    // establish that the peer is a local native Docker daemon. No POST follows.
    fixture.finish();
}

#[test]
fn request_write_half_stays_open_while_provider_delays_get_response() {
    let mut steps = observe(json!([]));
    steps[0].probe_write_half = true;
    let fixture = Fixture::new(steps);
    let result = run(&fixture, &[], 0);
    assert_eq!(result["changed"], false);
    assert_eq!(fixture.finish().write_half_probes, 1);
}

#[test]
fn sigint_during_get_returns_bounded_cancellation_without_mutation() {
    let mut first = Step::json("GET", VERSION, version());
    first.hold_response = true;
    let fixture = Fixture::new(vec![first]);
    let home = tempfile::tempdir().unwrap();
    let mut child = OwnedChild(Some(
        command(home.path(), "docker", Some(&fixture.socket), &[])
            .spawn()
            .unwrap(),
    ));
    fixture.await_request(1);
    // The first GET proves the CLI installed its cancellation handler. Signal
    // only the exact child this test owns; panic cleanup also reaps that child.
    // SAFETY: this is a live owned child PID and SIGINT is a valid signal.
    assert_eq!(
        unsafe { libc::kill(child.0.as_ref().unwrap().id() as libc::pid_t, libc::SIGINT) },
        0
    );
    let result = report(bounded_output(child.0.take().unwrap()), 130);
    assert_unmutated(&result, "cancelled");
    fixture.finish();
}
