use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

use crate::config::Config;

pub fn is_help_request<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect();
    if args.is_empty() {
        return true;
    }
    if args.len() == 1 && args[0].starts_with('+') {
        return true;
    }
    for (index, arg) in args.iter().enumerate() {
        if arg == "--" {
            break;
        }
        if arg == "-h" || arg == "--help" || arg == "help" {
            return true;
        }
        if index == 0 && arg.starts_with('+') {
            continue;
        }
    }
    false
}

pub fn is_version_request(args: &[OsString]) -> bool {
    matches!(args, [arg] if arg == OsStr::new("--version") || arg == OsStr::new("-V") || arg == OsStr::new("version"))
        || matches!(args, [selector, arg] if selector.to_string_lossy().starts_with('+') && (arg == OsStr::new("--version") || arg == OsStr::new("-V")))
}

pub fn has_explicit_target_dir(args: &[OsString]) -> bool {
    args.iter()
        .take_while(|arg| *arg != OsStr::new("--"))
        .any(|arg| {
            arg == OsStr::new("--target-dir") || arg.to_string_lossy().starts_with("--target-dir=")
        })
}

pub fn has_explicit_config(args: &[OsString]) -> bool {
    args.iter()
        .take_while(|arg| *arg != OsStr::new("--"))
        .any(|arg| arg == OsStr::new("--config") || arg.to_string_lossy().starts_with("--config="))
}

pub fn persistent_layout_override(start: &Path) -> Result<bool> {
    for candidate in cargo_config_files(start) {
        if !candidate.is_file() {
            continue;
        }
        let value = read_cargo_config(&candidate)?;
        if value
            .get("build")
            .and_then(toml::Value::as_table)
            .is_some_and(|build| {
                build.contains_key("build-dir") || build.contains_key("target-dir")
            })
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn persistent_compiler_wrapper(start: &Path) -> Result<bool> {
    for candidate in cargo_config_files(start) {
        if !candidate.is_file() {
            continue;
        }
        let value = read_cargo_config(&candidate)?;
        if value
            .get("build")
            .and_then(toml::Value::as_table)
            .is_some_and(|build| {
                build.contains_key("rustc-wrapper") || build.contains_key("rustc-workspace-wrapper")
            })
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn cargo_config_files(start: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let start = start.canonicalize().unwrap_or_else(|_| start.to_path_buf());
    for ancestor in start.ancestors() {
        candidates.push(ancestor.join(".cargo/config.toml"));
        candidates.push(ancestor.join(".cargo/config"));
    }
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::config::home_dir().join(".cargo"));
    candidates.push(cargo_home.join("config.toml"));
    candidates.push(cargo_home.join("config"));
    candidates
}

fn read_cargo_config(candidate: &Path) -> Result<toml::Value> {
    let raw = fs::read_to_string(candidate)
        .with_context(|| format!("read Cargo configuration {}", candidate.display()))?;
    toml::from_str(&raw)
        .with_context(|| format!("parse Cargo configuration {}", candidate.display()))
}

pub fn cargo_supports_build_dir(real: &Path, args: &[OsString]) -> bool {
    let mut command = Command::new(real);
    if let Some(selector) = args
        .first()
        .filter(|arg| arg.to_string_lossy().starts_with('+'))
    {
        command.arg(selector);
    }
    command.arg("--version");
    command
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|output| cargo_version(&output))
        .is_some_and(|(major, minor)| major > 1 || (major == 1 && minor >= 91))
}

pub fn rustup_cargo_supports_build_dir(real: &Path, args: &[OsString]) -> bool {
    let Some(cargo_index) = args.iter().position(|arg| {
        Path::new(arg)
            .file_stem()
            .is_some_and(|stem| stem.to_string_lossy().eq_ignore_ascii_case("cargo"))
    }) else {
        return false;
    };
    Command::new(real)
        .args(&args[..=cargo_index])
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|output| cargo_version(&output))
        .is_some_and(|(major, minor)| major > 1 || (major == 1 && minor >= 91))
}

fn cargo_version(output: &str) -> Option<(u64, u64)> {
    let version = output.split_whitespace().nth(1)?;
    let mut parts = version.split('.');
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

pub fn repository_start(args: &[OsString], current_dir: &Path) -> PathBuf {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if arg == OsStr::new("--") {
            break;
        }
        if arg == OsStr::new("--manifest-path") {
            if let Some(path) = args.get(index + 1) {
                return manifest_parent(path, current_dir);
            }
            break;
        }
        if let Some(path) = arg.to_string_lossy().strip_prefix("--manifest-path=") {
            return manifest_parent(OsStr::new(path), current_dir);
        }
        index += 1;
    }
    current_dir.to_path_buf()
}

fn manifest_parent(manifest: &OsStr, current_dir: &Path) -> PathBuf {
    let manifest = Path::new(manifest);
    let manifest = if manifest.is_absolute() {
        manifest.to_path_buf()
    } else {
        current_dir.join(manifest)
    };
    manifest.parent().unwrap_or(current_dir).to_path_buf()
}

pub fn resolve_real_cargo(config: &Config, current_exe: &Path) -> Result<PathBuf> {
    if let Some(path) = config.cargo.real_path.clone() {
        return validate_candidate(path, current_exe);
    }
    resolve_on_path("cargo", current_exe)
}

pub fn resolve_real_rustup(current_exe: &Path) -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("DEV_CACHE_REAL_RUSTUP").map(PathBuf::from) {
        return validate_candidate(path, current_exe);
    }
    resolve_on_path("rustup", current_exe)
}

pub fn resolve_real_command(command: &str, current_exe: &Path) -> Result<PathBuf> {
    resolve_on_path(command, current_exe)
}

fn resolve_on_path(command: &str, current_exe: &Path) -> Result<PathBuf> {
    let path = env::var_os("PATH").context("PATH is not set")?;
    let directories: Vec<PathBuf> = env::split_paths(&path).collect();
    let current_parent = current_exe
        .parent()
        .and_then(|path| fs::canonicalize(path).ok());
    let start = current_parent
        .as_ref()
        .and_then(|parent| {
            directories
                .iter()
                .position(|directory| fs::canonicalize(directory).ok().as_ref() == Some(parent))
        })
        .map_or(0, |index| index + 1);
    for dir in directories.into_iter().skip(start) {
        for candidate in command_candidates(&dir, command) {
            if candidate.is_file() && !same_file(&candidate, current_exe) {
                return validate_candidate(candidate, current_exe);
            }
        }
    }
    bail!("could not resolve real {command} without recursion")
}

#[cfg(not(windows))]
fn command_candidates(directory: &Path, command: &str) -> Vec<PathBuf> {
    vec![directory.join(command)]
}

#[cfg(windows)]
fn command_candidates(directory: &Path, command: &str) -> Vec<PathBuf> {
    windows_command_candidates(
        directory,
        command,
        &env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_owned()),
    )
}

#[cfg(any(windows, test))]
fn windows_command_candidates(directory: &Path, command: &str, path_ext: &str) -> Vec<PathBuf> {
    if Path::new(command).extension().is_some() {
        return vec![directory.join(command)];
    }
    path_ext
        .split(';')
        .filter(|extension| !extension.is_empty())
        .map(|extension| directory.join(format!("{command}{extension}")))
        .collect()
}

pub fn rustup_cargo_args(args: &[OsString]) -> Option<&[OsString]> {
    if args.first()? != OsStr::new("run") {
        return None;
    }
    let mut index = 1;
    if args
        .get(index)
        .is_some_and(|arg| arg == OsStr::new("--install"))
    {
        index += 1;
    }
    let _toolchain = args.get(index)?;
    index += 1;
    let command = Path::new(args.get(index)?).file_stem()?;
    if !command.to_string_lossy().eq_ignore_ascii_case("cargo") {
        return None;
    }
    Some(&args[index + 1..])
}

fn validate_candidate(path: PathBuf, current_exe: &Path) -> Result<PathBuf> {
    let executable = if path.is_absolute() {
        path
    } else {
        env::current_dir()?.join(path)
    };
    if !executable.is_file() {
        bail!(
            "configured real Cargo does not exist: {}",
            executable.display()
        );
    }
    if same_file(&executable, current_exe) {
        bail!("configured real command resolves to dev-cache intercept");
    }
    executable
        .canonicalize()
        .with_context(|| format!("resolve {}", executable.display()))?;
    Ok(executable)
}

fn same_file(left: &Path, right: &Path) -> bool {
    same_file::is_same_file(left, right).unwrap_or_else(|_| {
        match (fs::canonicalize(left), fs::canonicalize(right)) {
            (Ok(left), Ok(right)) => left == right,
            _ => false,
        }
    })
}

pub fn delegate(
    real: &Path,
    args: &[OsString],
    environment: &[(String, String)],
    help_prefix: Option<&str>,
) -> Result<i32> {
    if let Some(prefix) = help_prefix {
        let mut stdout = io::stdout().lock();
        stdout.write_all(prefix.as_bytes())?;
        stdout.flush()?;
    }
    let status = Command::new(real)
        .args(args)
        .envs(environment.iter().cloned())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("run {}", real.display()))?;
    Ok(status
        .code()
        .unwrap_or_else(|| if status.success() { 0 } else { 1 }))
}

#[cfg(test)]
mod windows_lexical_tests {
    use super::windows_command_candidates;
    use std::path::Path;

    #[test]
    fn pathext_expansion_is_ordered_and_does_not_double_extensions() {
        assert_eq!(
            windows_command_candidates(Path::new(r"C:\Tools"), "go", ".EXE;.CMD;.BAT"),
            [
                Path::new(r"C:\Tools").join("go.EXE"),
                Path::new(r"C:\Tools").join("go.CMD"),
                Path::new(r"C:\Tools").join("go.BAT"),
            ]
        );
        assert_eq!(
            windows_command_candidates(Path::new(r"C:\Tools"), "go.exe", ".EXE;.CMD"),
            [Path::new(r"C:\Tools").join("go.exe")]
        );
    }
}
