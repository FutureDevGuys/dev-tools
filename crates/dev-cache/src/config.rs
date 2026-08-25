use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub enabled: bool,
    pub root: Option<PathBuf>,
    pub cargo: CargoConfig,
    pub sccache: SccacheConfig,
    pub adapters: AdapterConfig,
    pub gc: GcConfig,
    pub artifacts: ArtifactConfig,
    pub maintenance: MaintenanceConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct CargoConfig {
    pub enabled: bool,
    pub real_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SccacheConfig {
    pub enabled: bool,
    pub cache_size: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct AdapterConfig {
    pub go: bool,
    pub npm: bool,
    pub pnpm: bool,
    pub uv: bool,
    pub pip: bool,
    pub ccache: bool,
    pub zig: bool,
    pub meson: bool,
    pub bun: bool,
    pub yarn: bool,
    pub temp: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct GcConfig {
    pub min_free_bytes: u64,
    pub target_free_bytes: u64,
    pub max_bytes: Option<u64>,
    pub stale_after_days: u64,
    pub pressure_min_age_hours: u64,
    pub orphan_grace_days: u64,
    pub temp_grace_hours: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ArtifactConfig {
    pub enabled: bool,
    pub stale_after_days: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct MaintenanceConfig {
    pub automatic: bool,
    pub interval_hours: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvironmentOverrides {
    pub root: Option<PathBuf>,
    pub mode: Option<bool>,
    pub real_cargo: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 2,
            enabled: true,
            root: None,
            cargo: CargoConfig::default(),
            sccache: SccacheConfig::default(),
            adapters: AdapterConfig::default(),
            gc: GcConfig::default(),
            artifacts: ArtifactConfig::default(),
            maintenance: MaintenanceConfig::default(),
        }
    }
}

impl Default for CargoConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            real_path: None,
        }
    }
}

impl Default for SccacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_size: None,
        }
    }
}

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            go: true,
            npm: true,
            pnpm: true,
            uv: true,
            pip: true,
            ccache: true,
            zig: true,
            meson: true,
            bun: true,
            yarn: true,
            temp: true,
        }
    }
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            min_free_bytes: 50 * 1024 * 1024 * 1024,
            target_free_bytes: 100 * 1024 * 1024 * 1024,
            max_bytes: None,
            stale_after_days: 120,
            pressure_min_age_hours: 24,
            orphan_grace_days: 7,
            temp_grace_hours: 24,
        }
    }
}

impl Default for ArtifactConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            stale_after_days: 120,
        }
    }
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            automatic: true,
            interval_hours: 24,
        }
    }
}

impl Config {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let config: Self = toml::from_str(raw).context("parse dev-cache TOML")?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(explicit: Option<&Path>) -> Result<(Self, Option<PathBuf>)> {
        if let Some(path) = explicit {
            if !path.is_file() {
                bail!("explicit configuration does not exist: {}", path.display());
            }
        }
        let path = explicit
            .map(Path::to_path_buf)
            .or_else(config_path_from_environment);
        let mut config = if let Some(path) = path.as_ref().filter(|path| path.is_file()) {
            Self::parse(
                &fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?,
            )?
        } else {
            Self::disabled()
        };
        config = config.with_environment(EnvironmentOverrides::from_process())?;
        Ok((config, path))
    }

    pub fn with_environment(mut self, overrides: EnvironmentOverrides) -> Result<Self> {
        if let Some(root) = overrides.root {
            self.root = Some(root);
        }
        if let Some(mode) = overrides.mode {
            self.enabled = mode;
        }
        if let Some(path) = overrides.real_cargo {
            self.cargo.real_path = Some(path);
        }
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 2 {
            bail!("unsupported config version {}; expected 2", self.version);
        }
        if self.enabled && self.root.is_none() {
            bail!("enabled routing requires root");
        }
        if self.gc.target_free_bytes < self.gc.min_free_bytes {
            bail!("gc.target_free_bytes must be at least gc.min_free_bytes");
        }
        if self.maintenance.interval_hours == 0 {
            bail!("maintenance.interval_hours must be positive");
        }
        Ok(())
    }

    pub fn write_atomic(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension(format!("dev-cache-partial-{}", std::process::id()));
        fs::write(&temporary, toml::to_string_pretty(self)?)?;
        fs::rename(&temporary, path)
            .with_context(|| format!("publish dev-cache configuration {}", path.display()))
    }
}

impl EnvironmentOverrides {
    pub fn from_process() -> Self {
        Self {
            root: env::var_os("DEV_CACHE_ROOT").map(PathBuf::from),
            mode: env::var_os("DEV_CACHE_MODE")
                .and_then(|value| value.into_string().ok())
                .and_then(|value| match value.as_str() {
                    "on" | "1" | "true" => Some(true),
                    "off" | "0" | "false" => Some(false),
                    _ => None,
                }),
            real_cargo: env::var_os("DEV_CACHE_REAL_CARGO").map(PathBuf::from),
        }
    }
}

pub fn default_config_path() -> PathBuf {
    if cfg!(windows) {
        env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join("AppData/Local"))
            .join("dev-cache/config.toml")
    } else {
        env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join(".config"))
            .join("dev-cache/config.toml")
    }
}

fn config_path_from_environment() -> Option<PathBuf> {
    if let Some(path) = env::var_os("DEV_CACHE_CONFIG") {
        return Some(PathBuf::from(path));
    }
    Some(default_config_path())
}

pub fn home_dir() -> PathBuf {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}
