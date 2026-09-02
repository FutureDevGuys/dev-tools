use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// The exact single-range UID map produced by systemd's full identity user namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityUserNamespace;

impl IdentityUserNamespace {
    pub const RANGE_LENGTH: u32 = u32::MAX;

    pub fn parse(input: &[u8]) -> Result<Self> {
        let input = std::str::from_utf8(input).context("UID map is not UTF-8")?;
        let mut lines = input.lines();
        let line = lines.next().context("UID map is empty")?;
        if lines.any(|remaining| !remaining.trim().is_empty()) {
            bail!("identity UID map must contain exactly one range");
        }

        let mut fields = line.split_ascii_whitespace();
        let inside_start = parse_field(fields.next(), "inside UID start")?;
        let host_start = parse_field(fields.next(), "host UID start")?;
        let length = parse_field(fields.next(), "UID range length")?;
        if fields.next().is_some() {
            bail!("identity UID map contains unexpected fields");
        }
        if inside_start != 0 {
            bail!("identity UID map must begin at namespace UID zero");
        }
        if host_start != 0 {
            bail!("identity UID map must preserve host UID zero");
        }
        if length != Self::RANGE_LENGTH {
            bail!("full identity UID map must preserve the complete UID range");
        }
        Ok(Self)
    }

    pub fn parse_maps(uid_map: &[u8], gid_map: &[u8]) -> Result<Self> {
        Self::parse(uid_map).context("validate full identity UID map")?;
        Self::parse(gid_map).context("validate full identity GID map")?;
        Ok(Self)
    }

    pub fn from_current_process() -> Result<Self> {
        let uid_map = read_identity_map_at(Path::new("/proc/self/uid_map"), "UID")?;
        let gid_map = read_identity_map_at(Path::new("/proc/self/gid_map"), "GID")?;
        Self::parse_maps(&uid_map, &gid_map)
    }
}

fn read_identity_map_at(path: &Path, description: &str) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect current process {description} map"))?;
    if !metadata.file_type().is_file() || metadata.len() > 4096 {
        bail!("current process {description} map has unsafe filesystem authority");
    }
    let mut input = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .with_context(|| format!("open current process {description} map"))?
        .take(4097)
        .read_to_end(&mut input)
        .with_context(|| format!("read current process {description} map"))?;
    if input.len() > 4096 {
        bail!("current process {description} map exceeds the size limit");
    }
    Ok(input)
}

fn parse_field(value: Option<&str>, description: &str) -> Result<u32> {
    value
        .with_context(|| format!("UID map is missing {description}"))?
        .parse::<u32>()
        .with_context(|| format!("UID map {description} is invalid"))
}
