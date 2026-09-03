//! Deterministic, value-conscious convergence reporting.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;

pub const REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Performed,
    Info,
    ScriptError,
    ScriptSkipped,
    SkippedExisting,
    MissingSource,
    Errors,
    InputRequired,
    Deferred,
    SuppressedComment,
    UpToDate,
}

impl Status {
    pub const ORDER: [Self; 11] = [
        Self::Performed,
        Self::Info,
        Self::ScriptError,
        Self::ScriptSkipped,
        Self::SkippedExisting,
        Self::MissingSource,
        Self::Errors,
        Self::InputRequired,
        Self::Deferred,
        Self::SuppressedComment,
        Self::UpToDate,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::Performed => "performed",
            Self::Info => "info",
            Self::ScriptError => "script_error",
            Self::ScriptSkipped => "script_skipped",
            Self::SkippedExisting => "skipped_existing",
            Self::MissingSource => "missing_source",
            Self::Errors => "errors",
            Self::InputRequired => "input_required",
            Self::Deferred => "deferred",
            Self::SuppressedComment => "suppressed_comment",
            Self::UpToDate => "up_to_date",
        }
    }

    const fn heading(self) -> &'static str {
        match self {
            Self::Performed => "Performed",
            Self::Info => "Information",
            Self::ScriptError => "Script Errors",
            Self::ScriptSkipped => "Script Skipped",
            Self::SkippedExisting => "Skipped (existing target)",
            Self::MissingSource => "Skipped (missing source)",
            Self::Errors => "Errors",
            Self::InputRequired => "Input Required",
            Self::Deferred => "Deferred",
            Self::SuppressedComment => "Suppressed by comments",
            Self::UpToDate => "Up-to-date",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Performed => "[do]",
            Self::Info => "[info]",
            Self::ScriptError | Self::Errors => "[error]",
            Self::InputRequired => "[input]",
            Self::Deferred => "[defer]",
            Self::SuppressedComment => "[note]",
            _ => "[skip]",
        }
    }

    pub const fn is_error(self) -> bool {
        matches!(self, Self::Errors | Self::ScriptError)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub status: Status,
    pub scope: String,
    pub name: String,
    pub message: String,
    pub output: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ReconcilerSummary {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subgroup: Option<String>,
    pub scope: String,
    pub changed: bool,
    pub verified: bool,
    pub deferred: bool,
    pub input_required: Vec<String>,
    pub next_action: String,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct JsonReport {
    pub schema_version: u32,
    pub outcome: &'static str,
    pub exit_code: i32,
    pub dry_run: bool,
    pub profiles: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reconcilers: Vec<ReconcilerSummary>,
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub dry_run: bool,
    pub profiles: Vec<String>,
    pub records: Vec<Record>,
    pub reconcilers: Vec<ReconcilerSummary>,
}

impl Report {
    pub fn exit_code(&self) -> i32 {
        i32::from(self.records.iter().any(|record| record.status.is_error()))
    }

    pub fn json(&self) -> JsonReport {
        let exit_code = self.exit_code();
        JsonReport {
            schema_version: REPORT_SCHEMA_VERSION,
            outcome: if exit_code == 0 {
                "completed"
            } else {
                "failed"
            },
            exit_code,
            dry_run: self.dry_run,
            profiles: self.profiles.clone(),
            reconcilers: self.reconcilers.clone(),
        }
    }

    pub fn counts(&self) -> BTreeMap<&'static str, u64> {
        let mut counts = BTreeMap::new();
        for record in &self.records {
            *counts.entry(record.status.key()).or_insert(0) += 1;
        }
        counts
    }

    pub fn render_human(&self, verbose: bool) -> String {
        if self.records.is_empty() {
            return "No entries defined in config; nothing to do.\n".to_owned();
        }
        let scope_width = self
            .records
            .iter()
            .map(|record| record.scope.chars().count())
            .max()
            .unwrap_or(0);
        let name_width = self
            .records
            .iter()
            .map(|record| record.name.chars().count())
            .max()
            .unwrap_or(0);
        let mut output = String::new();
        for status in Status::ORDER {
            let records: Vec<_> = self
                .records
                .iter()
                .filter(|record| record.status == status)
                .collect();
            if records.is_empty() {
                continue;
            }
            if status == Status::UpToDate && !verbose {
                let _ = writeln!(
                    output,
                    "\n{} ({} entries, use --verbose to list)",
                    status.heading(),
                    records.len()
                );
                continue;
            }
            let _ = writeln!(output, "\n{} ({}):", status.heading(), records.len());
            for record in records {
                let _ = writeln!(
                    output,
                    "  {} {:scope_width$} {:name_width$} {}",
                    status.label(),
                    record.scope,
                    record.name,
                    record.message,
                    scope_width = scope_width,
                    name_width = name_width
                );
                if let Some(script_output) = &record.output {
                    for line in script_output.trim().lines() {
                        let _ = writeln!(
                            output,
                            "    [info] {:scope_width$} {:name_width$} {}",
                            record.scope,
                            record.name,
                            line,
                            scope_width = scope_width,
                            name_width = name_width
                        );
                    }
                }
            }
        }
        let counts = self.counts();
        let performed = counts.get("performed").copied().unwrap_or(0);
        let up_to_date = counts.get("up_to_date").copied().unwrap_or(0);
        let existing = counts.get("skipped_existing").copied().unwrap_or(0);
        let missing = counts.get("missing_source").copied().unwrap_or(0);
        let script_skipped = counts.get("script_skipped").copied().unwrap_or(0);
        let deferred = counts.get("deferred").copied().unwrap_or(0);
        let input = counts.get("input_required").copied().unwrap_or(0);
        let errors = counts.get("errors").copied().unwrap_or(0)
            + counts.get("script_error").copied().unwrap_or(0);
        let skipped = existing + missing + script_skipped + deferred + input;
        let _ = writeln!(
            output,
            "\nSummary: {performed} updated, {up_to_date} up-to-date, {skipped} skipped (existing: {existing}, missing: {missing}), {errors} errors across {} entries.",
            self.records
                .iter()
                .filter(|record| record.status != Status::Info && record.status != Status::SuppressedComment)
                .count()
        );
        output
    }
}
