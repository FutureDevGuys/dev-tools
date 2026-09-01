use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct Registry {
    #[allow(dead_code)] // Reason: accepted for forward-compatible schema parsing.
    pub schema_version: Option<u64>,
    #[serde(default)]
    pub providers: Vec<RegistryProvider>,
    #[serde(default)]
    pub tools: Vec<RegistryTool>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct RegistryProvider {
    pub name: String,
    pub enabled: Option<bool>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct RegistryTool {
    pub name: String,
    pub provider: Option<String>,
    pub enabled: Option<bool>,
    pub managed_required: Option<bool>,
    /// Explicit binding preference. A higher configured value overrides PATH
    /// resolution when multiple providers publish the same command binding.
    pub priority: Option<i64>,
    #[serde(default)]
    pub ambient: bool,
    #[allow(dead_code)] // Reason: accepted for forward-compatible schema parsing.
    pub command: Option<String>,
    #[serde(default)]
    pub command_candidates: Vec<RegistryCommandCandidate>,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct RegistryCommandCandidate {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub probe_args: Vec<String>,
}
