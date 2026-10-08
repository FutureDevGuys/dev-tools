//! Pure state-machine contracts. These fakes do not attest daemon locality.
//! Public socket admission and process behavior are covered by CLI tests.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::{
    execute_with, validate_args, Failure, NativeCacheArgs, NativeCacheReport, PrivilegeDomain,
    Provider, Transport,
};

const VERSION: &str = "/version";
const INFO: &str = "/v1.51/info";
const USAGE: &str = "/v1.51/system/df?type=build-cache";

struct Step {
    method: &'static str,
    path: String,
    result: Result<Vec<u8>, (Failure, bool)>,
}

impl Step {
    fn json(method: &'static str, path: &str, value: Value) -> Self {
        Self {
            method,
            path: path.into(),
            result: Ok(serde_json::to_vec(&value).unwrap()),
        }
    }
    fn status(method: &'static str, path: &str, status: u16, value: Value) -> Self {
        if status == 200 {
            return Self::json(method, path, value);
        }
        Self::failure(
            method,
            path,
            if matches!(status, 401 | 403) {
                Failure::Permission
            } else {
                Failure::Provider
            },
            method == "POST",
        )
    }
    fn failure(method: &'static str, path: &str, error: Failure, sent: bool) -> Self {
        Self {
            method,
            path: path.into(),
            result: Err((error, sent)),
        }
    }
}

struct ScriptedTransport {
    pending: VecDeque<Step>,
    daemon: Option<PathBuf>,
}

impl ScriptedTransport {
    fn request(&mut self, method: &str, path: &str) -> Result<Vec<u8>, (Failure, bool)> {
        let expected = self.pending.pop_front().expect("unexpected native request");
        assert_eq!(method, expected.method);
        assert_eq!(
            path, expected.path,
            "exact provider filter and API boundary"
        );
        expected.result
    }
}

impl Transport for ScriptedTransport {
    fn socket(&self) -> &Path {
        Path::new("/fixture/mock.sock")
    }
    fn daemon_executable(&self) -> Option<&Path> {
        self.daemon.as_deref()
    }
    fn get(&mut self, path: &str) -> Result<Vec<u8>, Failure> {
        self.request("GET", path).map_err(|(error, _)| error)
    }
    fn prune(&mut self, path: &str) -> Result<Vec<u8>, (Failure, bool)> {
        self.request("POST", path)
    }
}

struct Fixture(RefCell<ScriptedTransport>);

impl Fixture {
    fn new(steps: Vec<Step>) -> Self {
        // This pathname is only a typed input to a cfg(test) state-machine
        // fake. It does not exist or grant any executable or socket authority.
        Self(RefCell::new(ScriptedTransport {
            pending: steps.into(),
            daemon: Some(PathBuf::from("/usr/bin/dockerd")),
        }))
    }
    fn finish(self) {
        assert!(
            self.0.into_inner().pending.is_empty(),
            "unconsumed expected requests"
        );
    }
}

fn apply_args(ids: &[&str]) -> NativeCacheArgs {
    NativeCacheArgs {
        provider: Provider::Docker,
        socket: Some(PathBuf::from("/fixture/mock.sock")),
        apply: true,
        engine_id: Some("fixture-engine".into()),
        storage_root: Some(PathBuf::from("/fixture/storage")),
        privilege_domain: Some(PrivilegeDomain::Rootless),
        cache_id: ids.iter().map(|id| (*id).to_owned()).collect(),
    }
}

fn run(fixture: &Fixture, args: &NativeCacheArgs, exit_code: i32) -> Value {
    let mut report = NativeCacheReport::new(args);
    if let Err(error) = validate_args(args)
        .and_then(|()| execute_with(&mut *fixture.0.borrow_mut(), args, &mut report))
    {
        report.fail(error);
    }
    let value = serde_json::to_value(report).unwrap();
    assert_eq!(value["schema"], "dev-cache-native-cache-v1");
    assert_eq!(value["exit_code"], exit_code, "{value}");
    value
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

fn encoded_query(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

fn prune_path(id: &str, kind: &str) -> String {
    // Intentionally spell out the provider contract independently of the
    // implementation: bare private presence, anchored ID, and exact type.
    let filters =
        format!("{{\"id\":{{\"^{id}$\":true}},\"private\":{{}},\"type\":{{\"{kind}\":true}}}}");
    format!(
        "/v1.51/build/prune?all=false&filters={}",
        encoded_query(&filters)
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
fn maximum_selection_and_id_length_are_accepted_without_widening_scope() {
    let mut ids: Vec<String> = (0..31).map(|index| format!("cache{index}")).collect();
    ids.push("a".repeat(128));
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let mut steps = observe(json!([]));
    for _ in &ids {
        steps.extend(observe(json!([])));
    }
    steps.extend(observe(json!([])));
    let fixture = Fixture::new(steps);
    let result = run(&fixture, &apply_args(&refs), 0);
    assert_eq!(result["outcome"], "completed");
    assert_eq!(result["changed"], false);
    assert_eq!(result["selected_cache_ids"], json!(ids));
    fixture.finish();
}

#[test]
fn entire_selection_is_admitted_before_the_first_prune() {
    for rejected in ["active", "shared", "unknown"] {
        let mut candidate = record("second2", "regular", 20);
        match rejected {
            "active" => candidate["InUse"] = json!(true),
            "shared" => candidate["Shared"] = json!(true),
            "unknown" => candidate["Type"] = json!("future.kind"),
            _ => unreachable!(),
        }
        let fixture = Fixture::new(observe(json!([record("first1", "regular", 10), candidate])));
        let result = run(&fixture, &apply_args(&["first1", "second2"]), 3);
        assert_unmutated(&result, "cache-record-not-eligible");
        fixture.finish();
    }
}

#[test]
fn apply_sends_only_exact_private_record_prunes_and_fresh_after_accounting() {
    let before = json!([
        record("a1", "regular", 10),
        record("b2", "source.git.checkout", 20)
    ]);
    let remaining = json!([record("b2", "source.git.checkout", 20)]);
    let mut steps = observe(before.clone());
    steps.extend(observe(before));
    steps.push(Step::json(
        "POST",
        &prune_path("a1", "regular"),
        json!({"CachesDeleted":["a1"], "SpaceReclaimed":8}),
    ));
    steps.extend(observe(remaining));
    steps.push(Step::json(
        "POST",
        &prune_path("b2", "source.git.checkout"),
        json!({"CachesDeleted":["b2"], "SpaceReclaimed":15}),
    ));
    steps.extend(observe(Value::Null));
    let fixture = Fixture::new(steps);
    let result = run(&fixture, &apply_args(&["a1", "b2"]), 0);
    assert_eq!(result["operation"], "apply");
    assert_eq!(result["outcome"], "completed");
    assert!(result["error_kind"].is_null());
    assert_eq!(result["changed"], true);
    assert_eq!(result["mutation_uncertain"], false);
    assert_eq!(result["selected_cache_ids"], json!(["a1", "b2"]));
    assert_eq!(result["deleted_cache_ids"], json!(["a1", "b2"]));
    assert_eq!(result["reclaimed_bytes"], 23);
    assert_eq!(result["before"]["reclaimable_record_bytes_estimate"], 30);
    assert_eq!(result["after"]["reclaimable_record_bytes_estimate"], 0);
    assert_eq!(result["after"]["records"], json!([]));
    fixture.finish();
}

#[test]
fn native_no_deletion_accepts_null_and_empty_but_reports_eligible_records_as_deferred() {
    for deleted in [Value::Null, json!([])] {
        let cache = json!([record("a1", "exec.cachemount", 10)]);
        let mut steps = observe(cache.clone());
        steps.extend(observe(cache.clone()));
        steps.push(Step::json(
            "POST",
            &prune_path("a1", "exec.cachemount"),
            json!({"CachesDeleted": deleted, "SpaceReclaimed": 0}),
        ));
        steps.extend(observe(cache));
        let fixture = Fixture::new(steps);
        let result = run(&fixture, &apply_args(&["a1"]), 3);
        assert_eq!(result["outcome"], "incomplete");
        assert_eq!(result["error_kind"], "native-prune-deferred");
        assert_eq!(result["changed"], false);
        assert_eq!(result["mutation_uncertain"], false);
        assert_eq!(result["deleted_cache_ids"], json!([]));
        assert_eq!(result["reclaimed_bytes"], 0);
        assert_eq!(result["before"], result["after"]);
        fixture.finish();
    }
}

#[test]
fn repeated_apply_of_an_absent_selection_is_a_clean_no_op_without_prune() {
    let mut steps = observe(Value::Null);
    steps.extend(observe(json!([])));
    steps.extend(observe(json!([])));
    let fixture = Fixture::new(steps);
    let result = run(&fixture, &apply_args(&["previouslyDeleted1"]), 0);
    assert_eq!(result["outcome"], "completed");
    assert!(result["error_kind"].is_null());
    assert_eq!(result["changed"], false);
    assert_eq!(result["mutation_uncertain"], false);
    assert_eq!(result["selected_cache_ids"], json!(["previouslyDeleted1"]));
    assert_eq!(result["deleted_cache_ids"], json!([]));
    assert_eq!(result["before"], result["after"]);
    fixture.finish();
}

#[test]
fn provider_no_deletion_can_complete_when_after_observation_proves_ineligibility() {
    for reason in ["InUse", "Shared"] {
        let cache = json!([record("a1", "regular", 10)]);
        let mut retained = record("a1", "regular", 10);
        retained[reason] = json!(true);
        let mut steps = observe(cache.clone());
        steps.extend(observe(cache));
        steps.push(Step::json(
            "POST",
            &prune_path("a1", "regular"),
            json!({"CachesDeleted": null, "SpaceReclaimed": 0}),
        ));
        steps.extend(observe(json!([retained])));
        let fixture = Fixture::new(steps);
        let result = run(&fixture, &apply_args(&["a1"]), 0);
        assert_eq!(result["outcome"], "completed");
        assert_eq!(result["changed"], false);
        assert_eq!(result["mutation_uncertain"], false);
        assert_eq!(result["after"]["records"][0]["eligible"], false);
        assert_eq!(result["deleted_cache_ids"], json!([]));
        fixture.finish();
    }
}

#[test]
fn deleted_id_still_present_afterward_fails_without_erasing_confirmed_mutation() {
    let cache = json!([record("a1", "regular", 10)]);
    let mut steps = observe(cache.clone());
    steps.extend(observe(cache.clone()));
    steps.push(Step::json(
        "POST",
        &prune_path("a1", "regular"),
        json!({"CachesDeleted": ["a1"], "SpaceReclaimed": 7}),
    ));
    steps.extend(observe(cache));
    let fixture = Fixture::new(steps);
    let result = run(&fixture, &apply_args(&["a1"]), 4);
    assert_eq!(result["outcome"], "failed");
    assert_eq!(result["error_kind"], "native-scope-changed");
    assert_eq!(result["changed"], true);
    assert_eq!(result["mutation_uncertain"], false);
    assert_eq!(result["deleted_cache_ids"], json!(["a1"]));
    assert_eq!(result["reclaimed_bytes"], 7);
    assert_eq!(result["after"]["records"][0]["id"], "a1");
    fixture.finish();
}

#[test]
fn a_record_that_disappeared_before_its_prune_is_a_clean_no_op() {
    let mut steps = observe(json!([record("a1", "regular", 10)]));
    steps.extend(observe(json!([])));
    steps.extend(observe(Value::Null));
    let fixture = Fixture::new(steps);
    let result = run(&fixture, &apply_args(&["a1"]), 0);
    assert_eq!(result["outcome"], "completed");
    assert_eq!(result["changed"], false);
    assert_eq!(result["mutation_uncertain"], false);
    assert_eq!(result["deleted_cache_ids"], json!([]));
    fixture.finish();
}

#[test]
fn incomplete_or_out_of_scope_prune_responses_leave_mutation_uncertain() {
    for (body, error, code) in [
        (
            json!({"SpaceReclaimed": 0}),
            "unsupported-native-response",
            1,
        ),
        (
            json!({"CachesDeleted": []}),
            "unsupported-native-response",
            1,
        ),
        (
            json!({"CachesDeleted": ["other2"], "SpaceReclaimed": 1}),
            "native-scope-changed",
            4,
        ),
        (
            json!({"CachesDeleted": ["a1", "other2"], "SpaceReclaimed": 1}),
            "native-scope-changed",
            4,
        ),
        (
            json!({"CachesDeleted": [], "SpaceReclaimed": 1}),
            "native-scope-changed",
            4,
        ),
    ] {
        let cache = json!([record("a1", "regular", 10)]);
        let mut steps = observe(cache.clone());
        steps.extend(observe(cache));
        steps.push(Step::json("POST", &prune_path("a1", "regular"), body));
        let fixture = Fixture::new(steps);
        let result = run(&fixture, &apply_args(&["a1"]), code);
        assert_eq!(result["outcome"], "failed");
        assert_eq!(result["error_kind"], error);
        assert!(result["changed"].is_null());
        assert_eq!(result["mutation_uncertain"], true);
        assert_eq!(result["deleted_cache_ids"], json!([]));
        assert!(result["after"].is_null());
        fixture.finish();
    }
}

#[test]
fn native_failure_retains_confirmed_partial_progress_and_value_free_errors() {
    let cache = json!([record("a1", "regular", 10), record("b2", "regular", 20)]);
    let mut steps = observe(cache.clone());
    steps.extend(observe(cache));
    steps.push(Step::json(
        "POST",
        &prune_path("a1", "regular"),
        json!({"CachesDeleted":["a1"],"SpaceReclaimed":7}),
    ));
    steps.extend(observe(json!([record("b2", "regular", 20)])));
    steps.push(Step::status(
        "POST",
        &prune_path("b2", "regular"),
        500,
        json!({"message":"provider-secret-must-not-escape"}),
    ));
    let fixture = Fixture::new(steps);
    let result = run(&fixture, &apply_args(&["a1", "b2"]), 1);
    assert_eq!(result["error_kind"], "native-provider-failed");
    assert_eq!(result["changed"], true);
    assert_eq!(result["mutation_uncertain"], true);
    assert_eq!(result["deleted_cache_ids"], json!(["a1"]));
    assert_eq!(result["reclaimed_bytes"], 7);
    assert!(result["after"].is_null());
    assert!(!result.to_string().contains("provider-secret"));
    fixture.finish();
}

#[test]
fn expected_scope_mismatches_and_fresh_identity_changes_block_mutation() {
    for (field, value) in [
        ("ID", json!("other-engine")),
        ("DockerRootDir", json!("/other/storage")),
        ("SecurityOptions", json!([])),
    ] {
        let mut changed = info();
        changed[field] = value;
        let fixture = Fixture::new(vec![
            Step::json("GET", VERSION, version()),
            Step::json("GET", INFO, changed.clone()),
        ]);
        assert_unmutated(
            &run(&fixture, &apply_args(&["a1"]), 4),
            "native-scope-changed",
        );
        fixture.finish();
        let mut steps = observe(json!([record("a1", "regular", 10)]));
        steps.extend([
            Step::json("GET", VERSION, version()),
            Step::json("GET", INFO, changed),
        ]);
        let fixture = Fixture::new(steps);
        assert_unmutated(
            &run(&fixture, &apply_args(&["a1"]), 4),
            "native-scope-changed",
        );
        fixture.finish();
    }
}

#[test]
fn changed_eligibility_is_rechecked_immediately_before_prune() {
    let mut active = record("a1", "regular", 10);
    active["InUse"] = json!(true);
    let mut steps = observe(json!([record("a1", "regular", 10)]));
    steps.extend(observe(json!([active])));
    let fixture = Fixture::new(steps);
    assert_unmutated(
        &run(&fixture, &apply_args(&["a1"]), 3),
        "cache-record-not-eligible",
    );
    fixture.finish();
}

#[test]
fn post_mutation_scope_change_preserves_confirmed_change() {
    let cache = json!([record("a1", "regular", 10)]);
    let mut steps = observe(cache.clone());
    steps.extend(observe(cache));
    steps.push(Step::json(
        "POST",
        &prune_path("a1", "regular"),
        json!({"CachesDeleted":["a1"], "SpaceReclaimed":7}),
    ));
    let mut changed = info();
    changed["ServerVersion"] = json!("29.0.0");
    steps.extend([
        Step::json("GET", VERSION, version()),
        Step::json("GET", INFO, changed),
    ]);
    let fixture = Fixture::new(steps);
    let result = run(&fixture, &apply_args(&["a1"]), 4);
    assert_eq!(result["error_kind"], "native-scope-changed");
    assert_eq!(result["changed"], true);
    assert_eq!(result["mutation_uncertain"], false);
    assert_eq!(result["deleted_cache_ids"], json!(["a1"]));
    assert_eq!(result["reclaimed_bytes"], 7);
    assert!(result["after"].is_null());
    fixture.finish();
}

#[test]
fn cancellation_distinguishes_unsent_prune_from_entered_mutation() {
    for sent in [false, true] {
        let cache = json!([record("a1", "regular", 10)]);
        let mut steps = observe(cache.clone());
        steps.extend(observe(cache));
        steps.push(Step::failure(
            "POST",
            &prune_path("a1", "regular"),
            Failure::Cancelled,
            sent,
        ));
        let fixture = Fixture::new(steps);
        let result = run(&fixture, &apply_args(&["a1"]), 130);
        assert_eq!(result["error_kind"], "cancelled");
        assert_eq!(
            result["changed"],
            if sent { Value::Null } else { json!(false) }
        );
        assert_eq!(result["mutation_uncertain"], sent);
        assert_eq!(result["deleted_cache_ids"], json!([]));
        assert!(result["after"].is_null());
        fixture.finish();
    }
}

#[test]
fn later_unsent_failure_preserves_confirmed_partial_progress_without_uncertainty() {
    let cache = json!([record("a1", "regular", 10), record("b2", "regular", 20)]);
    let mut steps = observe(cache.clone());
    steps.extend(observe(cache));
    steps.push(Step::json(
        "POST",
        &prune_path("a1", "regular"),
        json!({"CachesDeleted":["a1"], "SpaceReclaimed":7}),
    ));
    steps.extend(observe(json!([record("b2", "regular", 20)])));
    steps.push(Step::failure(
        "POST",
        &prune_path("b2", "regular"),
        Failure::Cancelled,
        false,
    ));
    let fixture = Fixture::new(steps);
    let result = run(&fixture, &apply_args(&["a1", "b2"]), 130);
    assert_eq!(result["error_kind"], "cancelled");
    assert_eq!(result["changed"], true);
    assert_eq!(result["mutation_uncertain"], false);
    assert_eq!(result["deleted_cache_ids"], json!(["a1"]));
    assert_eq!(result["reclaimed_bytes"], 7);
    fixture.finish();
}

#[test]
fn reclaimed_total_overflow_preserves_all_confirmed_deleted_ids() {
    let cache = json!([record("a1", "regular", 1), record("b2", "regular", 1)]);
    let mut steps = observe(cache.clone());
    steps.extend(observe(cache));
    steps.push(Step::json(
        "POST",
        &prune_path("a1", "regular"),
        json!({"CachesDeleted":["a1"], "SpaceReclaimed":u64::MAX}),
    ));
    steps.extend(observe(json!([record("b2", "regular", 1)])));
    steps.push(Step::json(
        "POST",
        &prune_path("b2", "regular"),
        json!({"CachesDeleted":["b2"], "SpaceReclaimed":1}),
    ));
    let fixture = Fixture::new(steps);
    let result = run(&fixture, &apply_args(&["a1", "b2"]), 1);
    assert_eq!(result["error_kind"], "native-accounting-limit");
    assert_eq!(result["changed"], true);
    assert_eq!(result["mutation_uncertain"], false);
    assert_eq!(result["deleted_cache_ids"], json!(["a1", "b2"]));
    assert!(result["reclaimed_bytes"].is_null());
    assert!(result["after"].is_null());
    fixture.finish();
}

#[test]
fn unverified_transport_can_observe_but_cannot_apply() {
    for apply in [false, true] {
        let fixture = Fixture::new(observe(json!([record("a1", "regular", 10)])));
        fixture.0.borrow_mut().daemon = None;
        let mut args = apply_args(&["a1"]);
        args.apply = apply;
        let result = run(&fixture, &args, if apply { 3 } else { 0 });
        assert_eq!(result["scope"]["backend_locality"], "unverified");
        assert!(result["scope"]["daemon_executable"].is_null());
        assert_eq!(result["before"]["records"][0]["eligible"], true);
        if apply {
            assert_unmutated(&result, "native-daemon-locality-unverified");
        } else {
            assert_eq!(result["outcome"], "preview");
        }
        fixture.finish();
    }
}
