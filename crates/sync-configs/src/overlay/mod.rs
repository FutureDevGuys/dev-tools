//! Structured JSON and TOML overlays with receipt-backed key ownership.

pub mod json;
pub mod ownership;
pub mod toml;

/// A structured configuration path. Each component is an exact object/table key.
pub type PathKey = Vec<String>;

/// Observable, value-free accounting for one structured overlay.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OverlayResult {
    pub changed: bool,
    pub added: usize,
    pub overwritten: usize,
    pub replaced: usize,
    pub removed: usize,
    pub text: String,
    pub materialized_symlink: bool,
    pub ownership_changed: bool,
    pub suppressed: Vec<PathKey>,
}
