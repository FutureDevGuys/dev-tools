use crate::adapter::Adapter;
use crate::entrypoint::{self, EntrypointMode};
use std::ffi::OsString;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dispatch {
    Adapter(Adapter),
    Delegate,
}

pub fn classify_invocation(command: &str, args: &[OsString]) -> Dispatch {
    let spec = entrypoint::spec_for(command);
    // Static completion generation needs no cache routing or maintenance. Match
    // only the native root command, never a tool/script argument with that name.
    let completion = match spec.map(|spec| spec.command) {
        Some("uv") => uv_completion(args),
        Some("uvx") => args
            .first()
            .is_some_and(|arg| arg == "--generate-shell-completion"),
        _ => false,
    };
    if completion {
        return Dispatch::Delegate;
    }
    let adapter = match spec.map(|spec| spec.mode) {
        Some(EntrypointMode::Direct(adapter)) => Some(adapter),
        Some(EntrypointMode::Python) => classify_python(args),
        Some(EntrypointMode::PyLauncher) => classify_py(args),
        Some(EntrypointMode::Corepack) => classify_corepack(args),
        Some(EntrypointMode::Cargo | EntrypointMode::Rustup) | None => None,
    };
    adapter.map_or(Dispatch::Delegate, Dispatch::Adapter)
}

fn uv_completion(args: &[OsString]) -> bool {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let arg = arg.as_encoded_bytes();
        if arg == b"generate-shell-completion" {
            return true;
        }
        // Only skip known root options. Never search a workload's arguments or
        // mistake a value (including a non-Unicode path) for the root command.
        let (option, attached_value) = arg
            .iter()
            .position(|byte| *byte == b'=')
            .map_or((arg, false), |index| (&arg[..index], true));
        match option {
            b"--cache-dir"
            | b"--color"
            | b"--allow-insecure-host"
            | b"--directory"
            | b"--project"
            | b"--config-file" => {
                if !attached_value && args.next().is_none() {
                    return false;
                }
            }
            b"--no-cache"
            | b"--managed-python"
            | b"--no-managed-python"
            | b"--no-python-downloads"
            | b"--quiet"
            | b"--verbose"
            | b"--system-certs"
            | b"--native-tls"
            | b"--offline"
            | b"--no-progress"
            | b"--no-config"
            | b"--help"
            | b"--version"
                if !attached_value => {}
            _ if arg.starts_with(b"-")
                && arg.len() > 1
                && arg[1..]
                    .iter()
                    .all(|byte| matches!(byte, b'n' | b'q' | b'v' | b'h' | b'V')) => {}
            _ => return false,
        }
    }
    false
}

pub fn is_intercept_name(command: &str) -> bool {
    entrypoint::spec_for(command).is_some()
}

fn classify_python(args: &[OsString]) -> Option<Adapter> {
    match exact_module(args)? {
        "pip" => Some(Adapter::Pip),
        "mesonbuild.mesonmain" => Some(Adapter::Meson),
        _ => None,
    }
}

fn classify_py(args: &[OsString]) -> Option<Adapter> {
    let args = args
        .first()
        .and_then(|value| value.to_str())
        .filter(|value| is_py_selector(value))
        .map_or(args, |_| &args[1..]);
    (exact_module(args) == Some("pip")).then_some(Adapter::Pip)
}

fn classify_corepack(args: &[OsString]) -> Option<Adapter> {
    match args.first()?.to_str()? {
        "pnpm" | "pnpx" => Some(Adapter::Pnpm),
        "yarn" | "yarnpkg" => Some(Adapter::Yarn),
        _ => None,
    }
}

fn exact_module(args: &[OsString]) -> Option<&str> {
    if args.first()?.to_str()? != "-m" {
        return None;
    }
    args.get(1)?.to_str()
}

fn is_py_selector(value: &str) -> bool {
    if let Some(tag) = value.strip_prefix("-V:") {
        return !tag.is_empty() && !tag.chars().any(char::is_whitespace);
    }
    let Some(version) = value.strip_prefix('-') else {
        return false;
    };
    let version = version
        .strip_suffix("-32")
        .or_else(|| version.strip_suffix("-64"))
        .unwrap_or(version);
    !version.is_empty()
        && version
            .chars()
            .all(|character| character.is_ascii_digit() || character == '.')
        && version.chars().any(|character| character.is_ascii_digit())
        && !version.starts_with('.')
        && !version.ends_with('.')
        && !version.contains("..")
}
