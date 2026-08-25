use std::path::Path;

use crate::adapter::Adapter;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntrypointMode {
    Cargo,
    Rustup,
    Direct(Adapter),
    Python,
    PyLauncher,
    Corepack,
}

#[derive(Clone, Copy, Debug)]
pub struct EntrypointSpec {
    pub command: &'static str,
    pub adapters: &'static [Adapter],
    pub mode: EntrypointMode,
    pub requires_command: Option<&'static str>,
}

pub const STATIC_ENTRYPOINTS: &[EntrypointSpec] = &[
    EntrypointSpec {
        command: "cargo",
        adapters: &[Adapter::Cargo],
        mode: EntrypointMode::Cargo,
        requires_command: None,
    },
    EntrypointSpec {
        command: "rustup",
        adapters: &[Adapter::Cargo],
        mode: EntrypointMode::Rustup,
        requires_command: None,
    },
    EntrypointSpec {
        command: "sccache",
        adapters: &[Adapter::Sccache],
        mode: EntrypointMode::Direct(Adapter::Sccache),
        requires_command: None,
    },
    EntrypointSpec {
        command: "go",
        adapters: &[Adapter::Go],
        mode: EntrypointMode::Direct(Adapter::Go),
        requires_command: None,
    },
    EntrypointSpec {
        command: "npm",
        adapters: &[Adapter::Npm],
        mode: EntrypointMode::Direct(Adapter::Npm),
        requires_command: None,
    },
    EntrypointSpec {
        command: "npx",
        adapters: &[Adapter::Npm],
        mode: EntrypointMode::Direct(Adapter::Npm),
        requires_command: None,
    },
    EntrypointSpec {
        command: "pnpm",
        adapters: &[Adapter::Pnpm],
        mode: EntrypointMode::Direct(Adapter::Pnpm),
        requires_command: None,
    },
    EntrypointSpec {
        command: "pnpx",
        adapters: &[Adapter::Pnpm],
        mode: EntrypointMode::Direct(Adapter::Pnpm),
        requires_command: None,
    },
    EntrypointSpec {
        command: "uv",
        adapters: &[Adapter::Uv],
        mode: EntrypointMode::Direct(Adapter::Uv),
        requires_command: None,
    },
    EntrypointSpec {
        command: "uvx",
        adapters: &[Adapter::Uv],
        mode: EntrypointMode::Direct(Adapter::Uv),
        requires_command: None,
    },
    EntrypointSpec {
        command: "pip",
        adapters: &[Adapter::Pip],
        mode: EntrypointMode::Direct(Adapter::Pip),
        requires_command: None,
    },
    EntrypointSpec {
        command: "pip3",
        adapters: &[Adapter::Pip],
        mode: EntrypointMode::Direct(Adapter::Pip),
        requires_command: None,
    },
    EntrypointSpec {
        command: "ccache",
        adapters: &[Adapter::Ccache],
        mode: EntrypointMode::Direct(Adapter::Ccache),
        requires_command: None,
    },
    EntrypointSpec {
        command: "cc",
        adapters: &[Adapter::Ccache],
        mode: EntrypointMode::Direct(Adapter::Ccache),
        requires_command: Some("ccache"),
    },
    EntrypointSpec {
        command: "c++",
        adapters: &[Adapter::Ccache],
        mode: EntrypointMode::Direct(Adapter::Ccache),
        requires_command: Some("ccache"),
    },
    EntrypointSpec {
        command: "gcc",
        adapters: &[Adapter::Ccache],
        mode: EntrypointMode::Direct(Adapter::Ccache),
        requires_command: Some("ccache"),
    },
    EntrypointSpec {
        command: "g++",
        adapters: &[Adapter::Ccache],
        mode: EntrypointMode::Direct(Adapter::Ccache),
        requires_command: Some("ccache"),
    },
    EntrypointSpec {
        command: "clang",
        adapters: &[Adapter::Ccache],
        mode: EntrypointMode::Direct(Adapter::Ccache),
        requires_command: Some("ccache"),
    },
    EntrypointSpec {
        command: "clang++",
        adapters: &[Adapter::Ccache],
        mode: EntrypointMode::Direct(Adapter::Ccache),
        requires_command: Some("ccache"),
    },
    EntrypointSpec {
        command: "zig",
        adapters: &[Adapter::Zig],
        mode: EntrypointMode::Direct(Adapter::Zig),
        requires_command: None,
    },
    EntrypointSpec {
        command: "meson",
        adapters: &[Adapter::Meson],
        mode: EntrypointMode::Direct(Adapter::Meson),
        requires_command: None,
    },
    EntrypointSpec {
        command: "bun",
        adapters: &[Adapter::Bun],
        mode: EntrypointMode::Direct(Adapter::Bun),
        requires_command: None,
    },
    EntrypointSpec {
        command: "bunx",
        adapters: &[Adapter::Bun],
        mode: EntrypointMode::Direct(Adapter::Bun),
        requires_command: None,
    },
    EntrypointSpec {
        command: "yarn",
        adapters: &[Adapter::Yarn],
        mode: EntrypointMode::Direct(Adapter::Yarn),
        requires_command: None,
    },
    EntrypointSpec {
        command: "yarnpkg",
        adapters: &[Adapter::Yarn],
        mode: EntrypointMode::Direct(Adapter::Yarn),
        requires_command: None,
    },
    EntrypointSpec {
        command: "corepack",
        adapters: &[Adapter::Pnpm, Adapter::Yarn],
        mode: EntrypointMode::Corepack,
        requires_command: None,
    },
    EntrypointSpec {
        command: "python",
        adapters: &[Adapter::Pip, Adapter::Meson],
        mode: EntrypointMode::Python,
        requires_command: None,
    },
    EntrypointSpec {
        command: "python3",
        adapters: &[Adapter::Pip, Adapter::Meson],
        mode: EntrypointMode::Python,
        requires_command: None,
    },
    EntrypointSpec {
        command: "py",
        adapters: &[Adapter::Pip, Adapter::Meson],
        mode: EntrypointMode::PyLauncher,
        requires_command: None,
    },
];

pub const UNMANAGED_BY_DESIGN: &[&str] = &["gradle", "mvn", "cmake", "ninja", "poetry", "pdm"];

pub fn normalized_command(command: &str) -> String {
    let command = Path::new(command)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(command);
    let lower = command.to_ascii_lowercase();
    [".exe", ".com", ".cmd", ".bat"]
        .iter()
        .find_map(|extension| lower.strip_suffix(extension))
        .unwrap_or(&lower)
        .to_owned()
}

pub fn spec_for(command: &str) -> Option<EntrypointSpec> {
    let command = normalized_command(command);
    if let Some(spec) = STATIC_ENTRYPOINTS
        .iter()
        .find(|spec| spec.command == command)
    {
        return Some(*spec);
    }
    if is_versioned_command(&command, "pip") {
        return Some(EntrypointSpec {
            command: "pip*",
            adapters: &[Adapter::Pip],
            mode: EntrypointMode::Direct(Adapter::Pip),
            requires_command: None,
        });
    }
    if is_versioned_command(&command, "python") {
        return Some(EntrypointSpec {
            command: "python*",
            adapters: &[Adapter::Pip, Adapter::Meson],
            mode: EntrypointMode::Python,
            requires_command: None,
        });
    }
    None
}

pub fn is_versioned_command(command: &str, prefix: &str) -> bool {
    command.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .chars()
                .all(|character| character.is_ascii_digit() || character == '.')
            && suffix.chars().any(|character| character.is_ascii_digit())
            && !suffix.starts_with('.')
            && !suffix.ends_with('.')
            && !suffix.contains("..")
    })
}
