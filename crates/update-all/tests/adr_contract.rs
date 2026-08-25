use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const REQUIRED_SECTIONS: [&str; 8] = [
    "## Context",
    "## Decision",
    "## Invariants",
    "## Rejected alternatives",
    "## Consequences and known limitations",
    "## Verification",
    "## Runtime acceptance",
    "## Supersession conditions",
];

fn markdown_records(dir: &Path) -> Vec<PathBuf> {
    let mut records = fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().and_then(|ext| ext.to_str()) == Some("md")
                && path.file_name().and_then(|name| name.to_str()) != Some("README.md")
        })
        .collect::<Vec<_>>();
    records.sort();
    records
}

fn collect_rust_sources(dir: &Path, output: &mut String) {
    for entry in fs::read_dir(dir).unwrap().filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, output);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            output.push_str(&fs::read_to_string(path).unwrap());
        }
    }
}

#[test]
fn update_all_adrs_have_valid_lifecycle_sections_and_regression_contracts() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let adr_dir = manifest_dir.join("docs/adr");
    let records = markdown_records(&adr_dir);
    assert!(
        !records.is_empty(),
        "ADR directory must contain numbered records"
    );

    let mut rust_sources = String::new();
    collect_rust_sources(&manifest_dir.join("src"), &mut rust_sources);
    collect_rust_sources(&manifest_dir.join("tests"), &mut rust_sources);

    let mut numbers = BTreeSet::new();
    for (index, path) in records.iter().enumerate() {
        let filename = path.file_name().unwrap().to_string_lossy();
        let number = filename
            .split('-')
            .next()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or_else(|| panic!("ADR filename is not numbered: {filename}"));
        assert!(numbers.insert(number), "duplicate ADR number {number:04}");
        assert_eq!(number, index + 1, "ADR numbering must be contiguous");

        let body = fs::read_to_string(path).unwrap();
        for section in REQUIRED_SECTIONS {
            assert!(body.contains(section), "{filename} missing {section}");
        }

        let status = body
            .lines()
            .find_map(|line| line.strip_prefix("status: "))
            .unwrap_or_else(|| panic!("{filename} missing status"));
        let verification = body
            .lines()
            .find_map(|line| line.strip_prefix("verification: "))
            .unwrap_or_else(|| panic!("{filename} missing verification"));
        assert!(
            matches!(
                (status, verification),
                ("proposed", "pending")
                    | ("accepted", "verified")
                    | ("superseded", "verified")
                    | ("superseded", "pending")
            ),
            "{filename} has invalid lifecycle combination {status}/{verification}"
        );

        let verification_section = body
            .split("## Verification")
            .nth(1)
            .and_then(|tail| tail.split("## Runtime acceptance").next())
            .unwrap();
        let test_names = verification_section
            .split('`')
            .enumerate()
            .filter_map(|(index, value)| (index % 2 == 1).then_some(value))
            .collect::<Vec<_>>();
        assert!(
            !test_names.is_empty(),
            "{filename} names no regression tests"
        );
        for test_name in test_names {
            assert!(
                rust_sources.contains(&format!("fn {test_name}")),
                "{filename} names missing regression test {test_name}"
            );
        }

        if status == "superseded" {
            let replacement = body
                .split("replacement: ")
                .nth(1)
                .and_then(|tail| tail.lines().next())
                .unwrap_or_else(|| panic!("{filename} missing replacement link"));
            assert!(
                adr_dir.join(replacement).is_file(),
                "{filename} replacement does not exist: {replacement}"
            );
        }
    }
}
