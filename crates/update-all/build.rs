#![allow(clippy::print_stdout)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()));
    let workspace_root = workspace_root(&manifest_dir).unwrap_or_else(|| manifest_dir.clone());

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("Cargo.lock").display()
    );
    println!("cargo:rerun-if-changed=config.example.toml");
    println!("cargo:rerun-if-changed=trust/root-public-key.txt");
    emit_release_source_rerun_paths(&manifest_dir);
    emit_git_rerun_paths(&manifest_dir);

    set_env(
        "UPDATE_ALL_BUILD_PROFILE",
        &env::var("PROFILE").unwrap_or_else(|_| "unknown".into()),
    );
    set_env(
        "UPDATE_ALL_GIT_COMMIT",
        &env::var("DEV_TOOLS_GIT_COMMIT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| git_output(&manifest_dir, &["rev-parse", "HEAD"]))
            .unwrap_or_else(|| "unknown".into()),
    );
    set_env(
        "UPDATE_ALL_GIT_DIRTY",
        &env::var("DEV_TOOLS_GIT_DIRTY")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| if git_dirty(&manifest_dir) { "1" } else { "0" }.into()),
    );
    set_env("UPDATE_ALL_BUILD_UNIX", &build_unix().to_string());
    set_env(
        "UPDATE_ALL_TRUST_ROOT_PUBLIC_KEY",
        &env::var("DEV_TOOLS_TRUST_ROOT_PUBLIC_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                fs::read_to_string(manifest_dir.join("trust/root-public-key.txt"))
                    .ok()
                    .map(|value| value.trim().to_string())
            })
            .unwrap_or_else(|| "invalid".into()),
    );
    println!("cargo:rerun-if-env-changed=DEV_TOOLS_GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=DEV_TOOLS_GIT_DIRTY");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo:rerun-if-env-changed=DEV_TOOLS_TRUST_ROOT_PUBLIC_KEY");
}

fn set_env(name: &str, value: &str) {
    println!("cargo:rustc-env={name}={value}");
}

fn emit_release_source_rerun_paths(manifest_dir: &Path) {
    let mut paths = Vec::new();
    collect_release_source_files(&manifest_dir.join("src"), &mut paths);
    paths.sort();
    paths.dedup();
    for path in paths {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn collect_release_source_files(path: &Path, paths: &mut Vec<PathBuf>) {
    if path.is_file() {
        paths.push(path.to_path_buf());
        return;
    }
    if !path.is_dir() || is_test_only_source_dir(path) {
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        collect_release_source_files(&entry.path(), paths);
    }
}

fn is_test_only_source_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "tests")
}

fn git_output(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn git_dirty(root: &Path) -> bool {
    let output = Command::new("git")
        .args([
            "status",
            "--porcelain",
            "--untracked-files=normal",
            "--ignore-submodules",
        ])
        .current_dir(root)
        .output();
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    String::from_utf8(output.stdout)
        .map(|stdout| !stdout.trim().is_empty())
        .unwrap_or(false)
}

fn emit_git_rerun_paths(root: &Path) {
    for git_path in git_rerun_paths(root) {
        println!("cargo:rerun-if-changed={}", git_path.display());
    }
}

fn git_rerun_paths(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    // Do not watch .git/index here. git status can refresh it while this build
    // script computes UPDATE_ALL_GIT_DIRTY, making release builds self-stale.
    for pathspec in ["HEAD", "packed-refs"] {
        if let Some(path) = git_path(root, pathspec) {
            paths.push(path);
        }
    }

    if let Some(branch) = git_output(root, &["branch", "--show-current"]) {
        if let Some(path) = git_path(root, &format!("refs/heads/{branch}")) {
            paths.push(path);
        }
    }

    paths
}

fn git_path(root: &Path, pathspec: &str) -> Option<PathBuf> {
    let output = git_output(root, &["rev-parse", "--git-path", pathspec])?;
    Some(expand_git_path(root, &output))
}

fn expand_git_path(root: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn workspace_root(manifest_dir: &Path) -> Option<PathBuf> {
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

fn build_unix() -> u64 {
    if let Ok(value) = env::var("SOURCE_DATE_EPOCH") {
        return value.parse().unwrap_or(0);
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn target_dir() -> Option<String> {
    let out_dir = PathBuf::from(env::var("OUT_DIR").ok()?);
    let build_dir = out_dir
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "build"))?;
    build_dir
        .parent()
        .and_then(Path::parent)
        .map(|path| path.to_string_lossy().into_owned())
}
