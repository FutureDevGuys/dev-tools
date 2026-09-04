use sync_configs::report::{ReconcilerSummary, Record, Report, Status};

#[test]
fn json_is_one_value_free_summary_document() {
    let report = Report {
        dry_run: true,
        profiles: vec!["linux".to_owned(), "desktop".to_owned()],
        records: vec![Record {
            status: Status::Performed,
            scope: "DO_NOT_SERIALIZE_SCOPE".to_owned(),
            name: "DO_NOT_SERIALIZE_NAME".to_owned(),
            message: "DO_NOT_SERIALIZE_VALUE".to_owned(),
            output: None,
        }],
        reconcilers: vec![ReconcilerSummary {
            schema: "dev-tools-reconcile-result-v1",
            name: "owner-tool".to_owned(),
            group: Some("Identity".to_owned()),
            subgroup: Some("Dev Auth".to_owned()),
            scope: "user".to_owned(),
            changed: true,
            verified: true,
            deferred: false,
            input_required: Vec::new(),
            next_action: "none".to_owned(),
            diagnostics: Vec::new(),
        }],
    };
    let encoded = serde_json::to_string(&report.json()).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&encoded).expect("one JSON document");
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["outcome"], "completed");
    assert_eq!(parsed["exit_code"], 0);
    assert_eq!(parsed["dry_run"], true);
    assert_eq!(parsed["profiles"], serde_json::json!(["linux", "desktop"]));
    assert_eq!(
        parsed["reconcilers"][0]["schema"],
        serde_json::json!("dev-tools-reconcile-result-v1")
    );
    assert!(!encoded.contains("DO_NOT_SERIALIZE"));
}

#[test]
fn human_output_is_grouped_deterministically_and_collapses_unchanged_entries() {
    let report = Report {
        records: vec![
            Record {
                status: Status::UpToDate,
                scope: "Second".into(),
                name: "unchanged".into(),
                message: "already up to date".into(),
                output: None,
            },
            Record {
                status: Status::Performed,
                scope: "First".into(),
                name: "updated".into(),
                message: "copied".into(),
                output: None,
            },
        ],
        ..Report::default()
    };
    let rendered = report.render_human(false);
    assert!(rendered.find("Performed").unwrap() < rendered.find("Up-to-date").unwrap());
    assert!(rendered.contains("Up-to-date (1 entries, use --verbose to list)"));
    assert!(!rendered.contains("already up to date"));
    assert!(rendered.contains("Summary: 1 updated, 1 up-to-date"));

    let verbose = report.render_human(true);
    assert!(verbose.contains("already up to date"));
}

#[test]
fn any_entry_error_makes_the_report_failed() {
    let report = Report {
        records: vec![Record {
            status: Status::ScriptError,
            scope: "scope".into(),
            name: "name".into(),
            message: "hook failed".into(),
            output: None,
        }],
        ..Report::default()
    };
    assert_eq!(report.exit_code(), 1);
    assert_eq!(report.json().outcome, "failed");
}
