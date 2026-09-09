use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Host boot-relative monotonic time, including time spent suspended. Strong
/// workloads retain the host time namespace; these ticks never cross hosts.
pub fn boot_time_millis() -> Result<u64> {
    let mut value = nix::libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` is a live, aligned writable timespec with the libc ABI.
    // clock_gettime writes only that object and retains no pointer after return.
    if unsafe { nix::libc::clock_gettime(nix::libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        bail!("native boot clock is unavailable");
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        bail!("native boot clock returned an invalid observation");
    }
    u64::try_from(value.tv_sec)?
        .checked_mul(1000)
        .and_then(|seconds| seconds.checked_add(value.tv_nsec as u64 / 1_000_000))
        .context("native boot clock observation overflowed")
}

pub(crate) fn deadline_after_seconds(now_ms: u64, seconds: u64) -> Result<u64> {
    if seconds == 0 {
        bail!("approved duration must be positive");
    }
    seconds
        .checked_mul(1000)
        .and_then(|duration| now_ms.checked_add(duration))
        .context("approved duration exceeds the native clock range")
}

/// A complete identity mapping, including systemd's root/non-root partitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityUserNamespace;

impl IdentityUserNamespace {
    pub const RANGE_LENGTH: u32 = u32::MAX;

    pub fn parse(input: &[u8]) -> Result<Self> {
        if input.len() > 4096 {
            bail!("identity map exceeds its observation bound");
        }
        let input = std::str::from_utf8(input).context("UID map is not UTF-8")?;
        let mut ranges = Vec::new();
        for line in input.lines().filter(|line| !line.trim().is_empty()) {
            let mut fields = line.split_ascii_whitespace();
            let inside_start = parse_field(fields.next(), "inside UID start")?;
            let host_start = parse_field(fields.next(), "host UID start")?;
            let length = parse_field(fields.next(), "UID range length")?;
            if fields.next().is_some() || inside_start != host_start || length == 0 {
                bail!("identity map contains invalid or remapped ranges");
            }
            let end = u64::from(inside_start) + u64::from(length);
            if end > u64::from(Self::RANGE_LENGTH) {
                bail!("identity range exceeds native ID bounds");
            }
            ranges.push((u64::from(inside_start), end));
        }
        ranges.sort_unstable();
        let mut next = 0;
        for (start, end) in ranges {
            if start != next {
                bail!("identity map has a gap or overlapping ranges");
            }
            next = end;
        }
        if next != u64::from(Self::RANGE_LENGTH) {
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
