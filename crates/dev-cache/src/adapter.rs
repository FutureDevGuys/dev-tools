use std::collections::HashMap;
use std::path::PathBuf;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::provenance;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Adapter {
    Cargo,
    Sccache,
    Go,
    Npm,
    Pnpm,
    Uv,
    Pip,
    Ccache,
    Zig,
    Meson,
    Bun,
    Yarn,
    Temp,
}

#[derive(Clone, Debug)]
pub struct AdapterContext {
    pub worktree_cache: PathBuf,
    pub shared_cache: PathBuf,
    pub domain_id: String,
    pub inherited: HashMap<String, String>,
}

impl Adapter {
    pub fn environment(self, context: &AdapterContext) -> HashMap<String, String> {
        let mut values = Vec::new();
        let repo = &context.worktree_cache;
        let shared = &context.shared_cache;
        match self {
            Self::Cargo => {
                values.push((
                    "CARGO_BUILD_BUILD_DIR",
                    shared.join("cargo/intermediate/{workspace-path-hash}"),
                ));
            }
            Self::Sccache => {
                if !sccache_remote_or_disabled(&context.inherited) {
                    values.push(("SCCACHE_DIR", shared.join("sccache")));
                }
                if !sccache_remote_or_disabled(&context.inherited)
                    && !context.inherited.contains_key("SCCACHE_SERVER_UDS")
                    && !context.inherited.contains_key("SCCACHE_SERVER_PORT")
                {
                    values.push((
                        "SCCACHE_SERVER_PORT",
                        PathBuf::from(domain_server_port(&context.domain_id).to_string()),
                    ));
                }
            }
            Self::Go => {
                values.push(("GOCACHE", shared.join("go-build")));
                values.push(("GOMODCACHE", shared.join("go-mod")));
                values.push(("GOTMPDIR", repo.join("temp/go")));
            }
            Self::Npm => values.push(("npm_config_cache", shared.join("npm"))),
            Self::Pnpm => {
                values.push(("pnpm_config_store_dir", shared.join("pnpm-store")));
                values.push(("pnpm_config_cache_dir", shared.join("pnpm-cache")));
            }
            Self::Uv => {
                values.push(("UV_CACHE_DIR", shared.join("uv")));
                values.push(("UV_PYTHON_CACHE_DIR", shared.join("uv-python")));
            }
            Self::Pip => values.push(("PIP_CACHE_DIR", shared.join("pip"))),
            Self::Ccache => {
                values.push(("CCACHE_DIR", shared.join("ccache")));
                values.push(("CCACHE_TEMPDIR", repo.join("temp/ccache")));
            }
            Self::Zig => {
                values.push(("ZIG_GLOBAL_CACHE_DIR", shared.join("zig/global")));
                values.push(("ZIG_LOCAL_CACHE_DIR", repo.join("zig/local")));
            }
            Self::Meson => {
                values.push(("MESON_PACKAGE_CACHE_DIR", shared.join("meson/packages")));
            }
            Self::Bun => {
                values.push(("BUN_INSTALL_CACHE_DIR", shared.join("bun/install")));
                values.push((
                    "BUN_RUNTIME_TRANSPILER_CACHE_PATH",
                    shared.join("bun/transpiler"),
                ));
            }
            Self::Yarn => values.push(("YARN_CACHE_FOLDER", shared.join("yarn/classic"))),
            Self::Temp => values.extend(temp_values(repo.join("temp/generic"))),
        }
        values
            .into_iter()
            .filter_map(|(key, value)| {
                (!context.inherited.contains_key(key)
                    || provenance::inherited_is_managed(&context.inherited, key))
                .then(|| (key.to_owned(), value.to_string_lossy().into_owned()))
            })
            .collect()
    }

    pub fn default_program(self) -> Option<&'static str> {
        match self {
            Self::Cargo => Some("cargo"),
            Self::Sccache => Some("sccache"),
            Self::Go => Some("go"),
            Self::Npm => Some("npm"),
            Self::Pnpm => Some("pnpm"),
            Self::Uv => Some("uv"),
            Self::Pip => Some("pip"),
            Self::Ccache => Some("ccache"),
            Self::Zig => Some("zig"),
            Self::Meson => Some("meson"),
            Self::Bun => Some("bun"),
            Self::Yarn => Some("yarn"),
            Self::Temp => None,
        }
    }

    pub fn version_args(self) -> &'static [&'static str] {
        match self {
            Self::Go | Self::Zig => &["version"],
            Self::Temp => &[],
            _ => &["--version"],
        }
    }

    pub fn is_shared(self) -> bool {
        !matches!(self, Self::Temp)
    }
}

fn sccache_remote_or_disabled(inherited: &HashMap<String, String>) -> bool {
    [
        "SCCACHE_BUCKET",
        "SCCACHE_ENDPOINT",
        "SCCACHE_REDIS",
        "SCCACHE_MEMCACHED",
        "SCCACHE_GCS_BUCKET",
        "SCCACHE_AZURE_CONNECTION_STRING",
        "SCCACHE_DISABLE",
    ]
    .iter()
    .any(|name| inherited.contains_key(*name))
}

fn domain_server_port(domain_id: &str) -> u16 {
    let digest = blake3::hash(domain_id.as_bytes());
    let offset = u16::from_be_bytes([digest.as_bytes()[0], digest.as_bytes()[1]]) as u32;
    (10_000 + (offset % 50_000)) as u16
}

fn temp_values(path: PathBuf) -> Vec<(&'static str, PathBuf)> {
    vec![
        ("TMPDIR", path.clone()),
        ("TEMP", path.clone()),
        ("TMP", path),
    ]
}
