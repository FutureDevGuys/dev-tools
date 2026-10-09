//! Opt-in retained Cargo outputs. Discovery does not build, fetch dependencies,
//! edit Cargo configuration, or infer workspace ownership from Git grouping.
use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::cargo_intercept;
use crate::root::RootHandle;

pub(crate) struct Invocation<'a> {
    pub real: &'a Path,
    /// For Rustup, `run TOOLCHAIN cargo`; otherwise empty.
    pub prefix: Vec<OsString>,
    pub args: &'a [OsString],
}

impl Invocation<'_> {
    fn cargo_probe(&self, args: &[OsString], cwd: &Path) -> Result<Vec<u8>> {
        let mut command = Command::new(self.real);
        // A probe must never install a missing toolchain.
        command.args(self.prefix.iter().filter(|arg| *arg != "--install"));
        if let Some(selector) = self
            .args
            .first()
            .filter(|arg| arg.to_string_lossy().starts_with('+'))
        {
            command.arg(selector);
        }
        command.args(args);
        probe(command, cwd)
    }

    fn compiler_probe(&self, args: &[&str], cwd: &Path) -> Result<Vec<u8>> {
        let mut command = if !self.prefix.is_empty() {
            let mut prefix = self.prefix.clone();
            prefix.pop(); // Replace the Cargo command with rustc in the same Rustup context.
            let mut command = Command::new(self.real);
            command.args(prefix.iter().filter(|arg| *arg != "--install"));
            command.arg("rustc");
            command
        } else {
            let sibling = self.real.with_file_name(if cfg!(windows) {
                "rustup.exe"
            } else {
                "rustup"
            });
            let proxy = same_file::is_same_file(self.real, &sibling).unwrap_or(false);
            let selector = self
                .args
                .first()
                .and_then(|arg| arg.to_str())
                .and_then(|arg| arg.strip_prefix('+'));
            if proxy {
                // Rustup may borrow Cargo for a custom toolchain. Resolve the
                // active toolchain, not Cargo's physical sibling compiler.
                let toolchain = if let Some(selector) = selector {
                    selector.to_owned()
                } else {
                    let mut command = Command::new(&sibling);
                    command.args(["show", "active-toolchain"]);
                    let output = probe(command, cwd)?;
                    std::str::from_utf8(&output)?
                        .split_whitespace()
                        .next()
                        .context("missing active Rustup toolchain")?
                        .to_owned()
                };
                let mut command = Command::new(sibling);
                command.args(["run", &toolchain, "rustc"]);
                command
            } else {
                if selector.is_some() {
                    bail!("unresolved explicit Rustup toolchain");
                }
                let paths =
                    env::split_paths(&env::var_os("PATH").context("missing compiler PATH")?)
                        .map(|path| {
                            if path.is_absolute() {
                                path
                            } else {
                                cwd.join(path)
                            }
                        })
                        .collect::<Vec<_>>();
                let rustc = dev_tools_command::first_executable(&paths, "rustc")
                    .context("unresolved native Rust compiler")?;
                Command::new(rustc)
            }
        };
        command.args(args);
        probe(command, cwd)
    }
}

#[derive(Deserialize)]
struct LocatedProject {
    root: PathBuf,
}

/// The result is a concrete target-dir. Cargo continues to own its normal
/// target-triple/profile layout below it. Templates are not supported here.
pub(crate) fn target_dir(
    root: &RootHandle,
    invocation: &Invocation<'_>,
    cwd: &Path,
) -> Result<PathBuf> {
    eligible(invocation, cwd)?;
    let mut locate = vec![
        "locate-project".into(),
        "--workspace".into(),
        "--message-format=json".into(),
    ];
    let mut args = invocation.args.iter().take_while(|arg| *arg != "--");
    while let Some(arg) = args.next() {
        if arg == "--manifest-path" {
            locate.push(arg.clone());
            locate.push(args.next().context("missing Cargo manifest path")?.clone());
        } else if arg.to_string_lossy().starts_with("--manifest-path=") {
            locate.push(arg.clone());
        }
    }
    let located: LocatedProject = serde_json::from_slice(&invocation.cargo_probe(&locate, cwd)?)
        .context("unresolved Cargo workspace")?;
    if !located.root.is_absolute() || located.root.file_name() != Some(OsStr::new("Cargo.toml")) {
        bail!("invalid Cargo workspace manifest");
    }
    let manifest = located
        .root
        .canonicalize()
        .context("resolve Cargo workspace manifest")?;
    if !manifest.is_file() {
        bail!("Cargo workspace manifest is not a file");
    }
    let compiler = invocation.compiler_probe(&["--version", "--verbose"], cwd)?;
    let compiler_text = std::str::from_utf8(&compiler)?;
    if !compiler_text.starts_with("rustc ")
        || !compiler_text.lines().any(|line| line.starts_with("host: "))
        || !compiler_text
            .lines()
            .any(|line| line.starts_with("commit-hash: "))
    {
        bail!("unrecognized native compiler identity");
    }
    let sysroot = invocation.compiler_probe(&["--print", "sysroot"], cwd)?;
    let sysroot = PathBuf::from(std::str::from_utf8(&sysroot)?.trim_end_matches(['\r', '\n']));
    if !sysroot.is_absolute() || !sysroot.is_dir() {
        bail!("unresolved native compiler sysroot");
    }
    let sysroot = sysroot.canonicalize()?;
    let cargo = invocation.cargo_probe(&["--version".into(), "--verbose".into()], cwd)?;
    if !cargo.starts_with(b"cargo ") {
        bail!("unrecognized native Cargo identity");
    }
    let filesystem = crate::repository::filesystem_identity(
        manifest.parent().context("workspace manifest parent")?,
    )?;
    let workspace = fingerprint(&[
        manifest.as_os_str().as_encoded_bytes(),
        filesystem.as_bytes(),
    ]);
    let toolchain = fingerprint(&[sysroot.as_os_str().as_encoded_bytes(), &compiler, &cargo]);
    Ok(root
        .platform_root
        .join("outputs/cargo")
        .join(workspace)
        .join(toolchain))
}

fn fingerprint(parts: &[&[u8]]) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"dev-cache-cargo-output-v1");
    for part in parts {
        hash.update(&(part.len() as u64).to_le_bytes());
        hash.update(part);
    }
    hash.finalize().to_hex().to_string()
}

fn probe(mut command: Command, cwd: &Path) -> Result<Vec<u8>> {
    command
        .current_dir(cwd)
        .env("RUSTUP_AUTO_INSTALL", "0")
        .env("DEV_CACHE_MODE", "off");
    let output = dev_tools_command::run_prepared_bounded_command(
        &mut command,
        Duration::from_secs(10),
        64 * 1024,
    )
    .context("observe native Cargo output identity")?;
    if !output.status.success() {
        // Captured diagnostics are not authority and may contain private values.
        bail!("native Cargo output identity probe failed");
    }
    Ok(output.stdout)
}

pub(crate) fn eligible(invocation: &Invocation<'_>, cwd: &Path) -> Result<()> {
    let inherited = env::vars().collect();
    if [
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET_DIR",
        "CARGO_BUILD_BUILD_DIR",
    ]
    .iter()
    .any(|name| {
        env::var_os(name).is_some() && !crate::provenance::inherited_is_managed(&inherited, name)
    }) {
        bail!("explicit native Cargo layout environment");
    }
    if !invocation.prefix.is_empty()
        && invocation
            .args
            .first()
            .is_some_and(|arg| arg.to_string_lossy().starts_with('+'))
    {
        bail!("nested Rustup toolchain selector is unsupported");
    }
    validate_invocation(invocation.args)?;
    validate_configuration(cwd)
}

fn validate_invocation(args: &[OsString]) -> Result<()> {
    let mut command = None;
    let mut manifest_seen = false;
    let mut args = args.iter().take_while(|arg| *arg != "--");
    while let Some(arg) = args.next() {
        let value = arg.to_str().context("non-Unicode Cargo argument")?;
        if value == "--color" {
            args.next().context("missing Cargo color")?;
            continue;
        }
        if value == "-C"
            || value.starts_with("-C")
            || value == "-Z"
            || value.starts_with("-Z")
            || [
                "--target-dir",
                "--build-dir",
                "--artifact-dir",
                "--out-dir",
                "--config",
            ]
            .iter()
            .any(|flag| value == *flag || value.starts_with(&format!("{flag}=")))
        {
            bail!("explicit or unsupported Cargo output selector");
        }
        if value == "--manifest-path" || value.starts_with("--manifest-path=") {
            if manifest_seen {
                bail!("duplicate Cargo manifest selector");
            }
            manifest_seen = true;
            if value == "--manifest-path" {
                let path = args.next().context("missing Cargo manifest path")?;
                if path.is_empty() {
                    bail!("empty Cargo manifest path");
                }
            } else if value == "--manifest-path=" {
                bail!("empty Cargo manifest path");
            }
            continue;
        }
        if command.is_none() {
            if value.starts_with('+')
                || matches!(
                    value,
                    "--offline"
                        | "--locked"
                        | "--frozen"
                        | "--quiet"
                        | "-q"
                        | "--verbose"
                        | "-v"
                        | "-vv"
                )
                || value.starts_with("--color=")
            {
                continue;
            }
            if value.starts_with('-') {
                bail!("unsupported Cargo global option");
            }
            command = Some(value);
        }
    }
    if !matches!(
        command,
        Some(
            "build"
                | "check"
                | "test"
                | "bench"
                | "run"
                | "doc"
                | "rustc"
                | "rustdoc"
                | "clean"
                | "metadata"
                | "locate-project"
        )
    ) {
        bail!("Cargo command does not have a supported final-output contract");
    }
    Ok(())
}

fn validate_configuration(cwd: &Path) -> Result<()> {
    // These can change which compiler Cargo runs, including through wrappers.
    // Do not silently key outputs using a different compiler's identity.
    for name in [
        "RUSTC",
        "CARGO_BUILD_RUSTC",
        "RUSTDOC",
        "CARGO_BUILD_RUSTDOC",
        "RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    ] {
        if env::var_os(name).is_some() {
            // Dev Cache's own sccache injection is a compiler-preserving wrapper.
            if name == "RUSTC_WRAPPER" && env::var(name).ok().as_deref() == Some("sccache") {
                let inherited = env::vars().collect();
                if crate::provenance::inherited_is_managed(&inherited, name) {
                    continue;
                }
            }
            bail!("explicit native compiler configuration");
        }
    }
    // Cargo reads configuration from invocation cwd, not --manifest-path.
    for path in cargo_intercept::cargo_config_files(cwd) {
        let Some(raw) = cargo_intercept::read_configuration(&path)? else {
            continue;
        };
        let value: toml::Value = toml::from_str(&raw).context("unparseable Cargo configuration")?;
        if value.get("include").is_some() || value.get("env").is_some() {
            bail!("indirect Cargo configuration requires native output layout");
        }
        if value
            .get("build")
            .and_then(toml::Value::as_table)
            .is_some_and(|build| {
                [
                    "target-dir",
                    "build-dir",
                    "rustc",
                    "rustdoc",
                    "rustc-wrapper",
                    "rustc-workspace-wrapper",
                ]
                .iter()
                .any(|name| build.contains_key(*name))
            })
        {
            bail!("persistent Cargo output or compiler configuration");
        }
    }
    Ok(())
}
