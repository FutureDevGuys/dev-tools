//! Shared wire contract for Dev Tools reconcilers.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RESULT_SCHEMA: &str = "dev-tools-reconcile-result-v1";
pub const RESULT_JSON_SCHEMA: &str =
    include_str!("../schemas/dev-tools-reconcile-result-v1.schema.json");
const TOKEN_LIMIT: usize = 128;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReconcileResult {
    pub schema: String,
    pub changed: bool,
    pub verified: bool,
    pub deferred: bool,
    pub input_required: Vec<String>,
    pub next_action: String,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalResult {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

impl ReconcileResult {
    pub fn pending(next_action: impl Into<String>) -> Result<Self> {
        Self::build(
            false,
            false,
            false,
            Vec::new(),
            next_action.into(),
            Vec::new(),
        )
    }

    pub fn change_required(next_action: impl Into<String>) -> Result<Self> {
        Self::build(
            false,
            true,
            false,
            Vec::new(),
            next_action.into(),
            Vec::new(),
        )
    }

    pub fn changed() -> Self {
        Self {
            schema: RESULT_SCHEMA.into(),
            changed: true,
            verified: true,
            deferred: false,
            input_required: Vec::new(),
            next_action: "none".into(),
            diagnostics: Vec::new(),
        }
    }

    pub fn verified() -> Self {
        Self {
            schema: RESULT_SCHEMA.into(),
            changed: false,
            verified: true,
            deferred: false,
            input_required: Vec::new(),
            next_action: "none".into(),
            diagnostics: Vec::new(),
        }
    }

    pub fn deferred<I, S>(next_action: impl Into<String>, diagnostics: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::build(
            true,
            false,
            false,
            Vec::new(),
            next_action.into(),
            diagnostics.into_iter().map(Into::into).collect(),
        )
    }

    pub fn input_required<I, S>(next_action: impl Into<String>, slots: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::build(
            false,
            false,
            false,
            slots.into_iter().map(Into::into).collect(),
            next_action.into(),
            Vec::new(),
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != RESULT_SCHEMA {
            bail!("reconcile result schema is unsupported");
        }
        validate_token(&self.next_action, "next action")?;
        validate_tokens(&self.input_required, "input slot")?;
        validate_tokens(&self.diagnostics, "diagnostic")?;
        if self.changed && (self.deferred || !self.input_required.is_empty()) {
            bail!("changed reconcile result has inconsistent terminal state");
        }
        if self.verified && (self.deferred || !self.input_required.is_empty()) {
            bail!("verified reconcile result has inconsistent terminal state");
        }
        if self.deferred && !self.input_required.is_empty() {
            bail!("deferred reconcile result cannot also require credential input");
        }
        if self.verified && self.next_action != "none" {
            bail!("verified reconcile result must not require another action");
        }
        if !self.changed
            && !self.verified
            && !self.deferred
            && self.input_required.is_empty()
            && self.next_action == "none"
        {
            bail!("nonterminal reconcile result must name its next action");
        }
        Ok(())
    }

    pub fn canonical(&self) -> Result<CanonicalResult> {
        self.validate()?;
        let bytes = serde_jcs::to_vec(self)?;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        Ok(CanonicalResult { bytes, sha256 })
    }

    fn build(
        deferred: bool,
        changed: bool,
        verified: bool,
        input_required: Vec<String>,
        next_action: String,
        diagnostics: Vec<String>,
    ) -> Result<Self> {
        let result = Self {
            schema: RESULT_SCHEMA.into(),
            changed,
            verified,
            deferred,
            input_required,
            next_action,
            diagnostics,
        };
        result.validate()?;
        Ok(result)
    }
}

fn validate_tokens(tokens: &[String], description: &str) -> Result<()> {
    for token in tokens {
        validate_token(token, description)?;
    }
    if tokens.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("reconcile {description}s must be sorted and unique");
    }
    Ok(())
}

fn validate_token(token: &str, description: &str) -> Result<()> {
    if token.is_empty()
        || token.len() > TOKEN_LIMIT
        || !token.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        bail!("reconcile {description} is invalid");
    }
    Ok(())
}
