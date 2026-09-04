use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()));

    println!("cargo:rerun-if-changed=../build_info_build.rs");
    println!("cargo:rerun-if-changed=../build_info_runtime.rs");
    if let Some(workspace_root) = workspace_root(&manifest_dir) {
        println!(
            "cargo:rerun-if-changed={}",
            workspace_root.join("Cargo.lock").display()
        );
    }
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");
    if manifest_dir.join("config.example.toml").exists() {
        println!("cargo:rerun-if-changed=config.example.toml");
    }

    println!(
        "cargo:rustc-env=DEV_TOOLS_BUILD_PROFILE={}",
        env::var("PROFILE").unwrap_or_else(|_| "unknown".into())
    );
    println!(
        "cargo:rustc-env=DEV_TOOLS_BUILD_TARGET={}",
        env::var("TARGET").unwrap_or_else(|_| "unknown".into())
    );
    println!("cargo:rustc-env=DEV_TOOLS_BUILD_UNIX={}", build_unix());
    println!(
        "cargo:rustc-env=DEV_TOOLS_GIT_COMMIT={}",
        env::var("DEV_TOOLS_GIT_COMMIT").unwrap_or_else(|_| "unknown".into())
    );
    println!(
        "cargo:rustc-env=DEV_TOOLS_GIT_DIRTY={}",
        env::var("DEV_TOOLS_GIT_DIRTY").unwrap_or_else(|_| "unknown".into())
    );
    println!("cargo:rerun-if-env-changed=DEV_TOOLS_GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=DEV_TOOLS_GIT_DIRTY");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}

fn build_unix() -> u64 {
    if let Ok(value) = env::var("SOURCE_DATE_EPOCH") {
        return value.parse().unwrap_or(0);
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn workspace_root(manifest_dir: &std::path::Path) -> Option<PathBuf> {
    for candidate in manifest_dir.ancestors() {
        let manifest = candidate.join("Cargo.toml");
        if manifest.is_file()
            && fs::read_to_string(&manifest)
                .map(|content| content.contains("[workspace]"))
                .unwrap_or(false)
        {
            return Some(candidate.to_path_buf());
        }
    }
    None
}
