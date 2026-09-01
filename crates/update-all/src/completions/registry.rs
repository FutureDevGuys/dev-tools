use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    /// Dynamic native completion output from an ambient executable is denied
    /// unless this explicit catalog policy grants trust.
    #[serde(default)]
    pub trust_dynamic: bool,
    #[allow(dead_code)] // Reason: accepted for forward-compatible schema parsing.
    pub command: Option<String>,
    #[serde(default)]
    pub command_candidates: Vec<RegistryCommandCandidate>,
    /// Provider-owned static completion files. Paths resolve relative to
    /// the provider bin directory (or the exact executable directory when the
    /// provider directory is unavailable); template expansion must still
    /// produce a relative path inside that root.
    #[serde(default)]
    pub bundled_completions: Vec<RegistryBundledCompletion>,
    /// Non-standard, non-mutating completion generator invocations. Recipes
    /// always execute the already-resolved candidate executable.
    #[serde(default)]
    pub completion_recipes: Vec<RegistryCompletionRecipe>,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, Eq)]
pub struct RegistryCommandCandidate {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub probe_args: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, Eq)]
pub struct RegistryBundledCompletion {
    pub shell: String,
    pub path: String,
    pub id: Option<String>,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, Eq)]
pub struct RegistryCompletionRecipe {
    pub id: Option<String>,
    /// Empty means every supported shell. `powershell`, `pwsh`, and `ps1`
    /// select the same PowerShell target.
    #[serde(default)]
    pub shells: Vec<String>,
    /// Direct argv appended after the candidate's configured launch argv.
    /// `{shell}` and `{command}` are expanded without shell interpolation.
    #[serde(default, alias = "argv")]
    pub args: Vec<String>,
    /// Explicit environment additions for this recipe. The process runner
    /// starts from its controlled allow-list rather than inheriting all state.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}
