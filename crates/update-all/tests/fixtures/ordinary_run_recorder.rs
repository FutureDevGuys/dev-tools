//! Harmless native stand-in for the four visible product-update commands.
use std::{env, fs::OpenOptions, io::Write, path::PathBuf};

fn main() {
    let arguments: Vec<_> = env::args().skip(1).collect();
    assert_eq!(arguments.len(), 4, "unexpected fixture invocation");
    assert_eq!(arguments[0], "product");
    assert_eq!(arguments[1], "update-if-installed");
    assert!(matches!(
        arguments[2].as_str(),
        "update-all" | "dev-cache" | "sync-configs" | "skills-sync"
    ));
    assert_eq!(arguments[3], "--json");
    let root = PathBuf::from(env::var_os("ORDINARY_RUN_FIXTURE_ROOT").unwrap());
    let mut calls = OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("calls.tsv"))
        .unwrap();
    writeln!(calls, "{}", arguments.join("\t")).unwrap();
    println!(
        "{{\"schema\":\"dev-tools-operation-result-v2\",\"product\":\"{}\",\"operation\":\"update_apply\",\"outcome\":\"completed\",\"changed\":false,\"exit_code\":0}}",
        arguments[2]
    );
}
