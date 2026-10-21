//! Native harmless provider for configuration-selection executable tests.
use std::{env, fs, path::PathBuf};

fn main() {
    let root = PathBuf::from(env::var_os("CONFIG_SELECTION_FIXTURE_ROOT").unwrap());
    let args: Vec<_> = env::args().skip(1).collect();
    assert_eq!(args.len(), 1, "exactly one fixture marker is required");
    assert!(matches!(args[0].as_str(), "fallback" | "selected" | "cli"));
    fs::write(root.join(format!("{}.marker", args[0])), "executed\n").unwrap();
    println!("{} configuration marker completed", args[0]);
}
