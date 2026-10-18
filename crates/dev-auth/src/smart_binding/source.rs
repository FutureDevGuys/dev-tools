//! Digest-selected complete deployment proposals. No function edits the source
//! in place, activates an alias or treats declarative bytes as native authority.
use super::*;
use crate::binding_deployment::{BindingDeploymentDocument, DeploymentBinding};

const SOURCE_LIMIT: u64 = 1024 * 1024;

pub struct SelectedBinding {
    pub selection: DeploymentBinding,
    pub plan: BindingPlan,
    pub receipt: BindingReceipt,
}

pub enum SourceChange<'a> {
    Plan {
        plan_path: &'a Path,
        plan_sha256: &'a str,
    },
    Remove {
        name: &'a str,
    },
}

pub(crate) fn is_canonical_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Check the selected raw bytes and canonical JSON before deserializing the
/// authority-bearing type. A digest of differently formatted or rounded bytes
/// cannot stand in for the canonical approved plan.
pub(crate) fn decode_plan(
    bytes: &[u8],
    expected_sha256: &str,
    inspect_target: bool,
) -> Result<BindingPlan> {
    require_digest(bytes, expected_sha256)?;
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("binding plan is not a JSON document"))?;
    if serde_jcs::to_vec(&value).context("canonicalize binding source bytes")? != bytes {
        bail!("binding plan source bytes are not canonical JSON");
    }
    let plan: BindingPlan = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("parse workload binding plan"))?;
    let canonical = if inspect_target {
        canonical_binding_plan(&plan)?
    } else {
        validate_binding_plan(&plan, false)?;
        serde_jcs::to_vec(&plan).context("canonicalize selected binding plan")?
    };
    if canonical != bytes {
        bail!("binding plan source differs from its exact canonical authority");
    }
    Ok(plan)
}

pub fn read_plan(path: &Path, expected_sha256: &str) -> Result<BindingPlan> {
    decode_plan(&read_source(path)?, expected_sha256, true)
}

/// Source selection is a draft predecessor, never an installed receipt. Setup
/// independently compares this plan with its retained native before-state.
pub fn read_binding(
    source_path: &Path,
    source_sha256: &str,
    user: &str,
    name: &str,
) -> Result<SelectedBinding> {
    let bytes = read_source(source_path)?;
    require_digest(&bytes, source_sha256)?;
    let source = crate::binding_deployment::parse(&bytes)?;
    validate_source_plans(&source)?;
    let selection = source
        .bindings
        .iter()
        .find(|binding| binding.user == user && binding.name == name)
        .context("named binding is absent from the selected deployment source")?
        .clone();
    let plan = decode_plan(&read_source(&selection.plan)?, &selection.sha256, false)?;
    if plan.name != name {
        bail!("deployment binding name differs from the selected exact plan");
    }
    let receipt = receipt_from_plan(&plan)?;
    Ok(SelectedBinding {
        selection,
        plan,
        receipt,
    })
}

pub fn receipt_from_plan(plan: &BindingPlan) -> Result<BindingReceipt> {
    validate_binding_plan(plan, false)?;
    let receipt = match (&plan.current_receipt, plan.change) {
        (Some(prior), BindingPlanChange::Unchanged) => prior.clone(),
        (current, change) => BindingReceipt {
            schema: BINDING_RECEIPT_SCHEMA.into(),
            platform: plan.platform.clone(),
            active: BindingGeneration {
                generation: match current {
                    Some(prior) => prior
                        .active
                        .generation
                        .checked_add(1)
                        .context("binding generation overflow")?,
                    None if change == BindingPlanChange::Install => 1,
                    None => bail!("binding source plan lacks its predecessor"),
                },
                intent: plan.intent.clone(),
                resolved: plan.resolved.clone(),
            },
            previous: current.as_ref().map(|receipt| receipt.active.clone()),
        },
    };
    validate_binding_receipt_structure(&receipt)?;
    Ok(receipt)
}

pub fn propose(
    source_path: &Path,
    source_sha256: &str,
    user: &str,
    change: SourceChange<'_>,
    output: &Path,
) -> Result<String> {
    let bytes = read_source(source_path)?;
    require_digest(&bytes, source_sha256)?;
    let source = crate::binding_deployment::parse(&bytes)?;
    validate_source_plans(&source)?;
    let (name, candidate) = match change {
        SourceChange::Plan {
            plan_path,
            plan_sha256,
        } => {
            let plan = read_plan(plan_path, plan_sha256)?;
            let previous = source
                .bindings
                .iter()
                .find(|binding| binding.user == user && binding.name == plan.name);
            let prior = previous
                .map(|binding| {
                    let selected =
                        decode_plan(&read_source(&binding.plan)?, &binding.sha256, false)?;
                    if selected.name != binding.name {
                        bail!("deployment predecessor has a different binding name");
                    }
                    receipt_from_plan(&selected)
                })
                .transpose()?;
            if plan.current_receipt != prior {
                bail!("binding plan does not name the exact selected source predecessor");
            }
            if prior.as_ref() == Some(&receipt_from_plan(&plan)?) {
                return write_proposal(output, &bytes);
            }
            let candidate = DeploymentBinding {
                user: user.into(),
                name: plan.name.clone(),
                plan: plan_path.to_path_buf(),
                sha256: plan_sha256.into(),
            };
            (plan.name, Some(candidate))
        }
        SourceChange::Remove { name } => {
            if !source
                .bindings
                .iter()
                .any(|binding| binding.user == user && binding.name == name)
            {
                bail!("cannot remove a binding absent from the selected deployment source");
            }
            (name.to_owned(), None)
        }
    };
    if !source.users.iter().any(|native| native.name == user) {
        bail!("binding proposal selects an undeclared native account");
    }
    let previous = source
        .bindings
        .iter()
        .find(|binding| binding.user == user && binding.name == name);
    if candidate.as_ref() == previous {
        return write_proposal(output, &bytes);
    }
    // Preserve all other source declarations, including the separately owned
    // grant component, instead of serializing only a binding-specific subset.
    let mut document: toml::Value = toml::from_str(std::str::from_utf8(&bytes)?)?;
    let table = document
        .as_table_mut()
        .context("binding deployment source is not a table")?;
    let bindings = table
        .entry("bindings")
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .context("binding source selection is not an array")?;
    bindings.retain(|entry| {
        !(entry.get("user").and_then(toml::Value::as_str) == Some(user)
            && entry.get("name").and_then(toml::Value::as_str) == Some(&name))
    });
    if let Some(candidate) = candidate {
        bindings
            .push(toml::Value::try_from(candidate).context("encode binding selection proposal")?);
    }
    let proposed =
        toml::to_string_pretty(&document).context("encode complete deployment proposal")?;
    let proposed_document = crate::binding_deployment::parse(proposed.as_bytes())?;
    validate_source_plans(&proposed_document)?;
    write_proposal(output, proposed.as_bytes())
}

fn require_digest(bytes: &[u8], expected: &str) -> Result<()> {
    if !is_canonical_digest(expected) || format!("{:x}", Sha256::digest(bytes)) != expected {
        bail!("selected source bytes do not match the exact digest");
    }
    Ok(())
}

fn validate_source_plans(source: &BindingDeploymentDocument) -> Result<()> {
    let mut aliases = std::collections::BTreeSet::new();
    for binding in &source.bindings {
        let plan = decode_plan(&read_source(&binding.plan)?, &binding.sha256, false)?;
        if plan.name != binding.name || !aliases.insert((&binding.user, plan.intent.command_name)) {
            bail!("deployment source repeats an alias or mismatches a selected plan name");
        }
    }
    Ok(())
}

pub(crate) fn read_source(path: &Path) -> Result<Vec<u8>> {
    require_absolute_normal_path(path, "binding source")?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK);
    let mut file = options.open(path).context("open binding source")?;
    let before = file.metadata().context("inspect opened binding source")?;
    if !before.is_file() || before.len() == 0 || before.len() > SOURCE_LIMIT {
        bail!("binding source is not a bounded regular file");
    }
    #[cfg(unix)]
    if before.nlink() != 1 || before.mode() & 0o022 != 0 {
        bail!("binding source has unsafe custody");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(SOURCE_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len()
        || !same_open_file(&before, &file.metadata()?)
        || !same_open_file(&before, &fs::symlink_metadata(path)?)
    {
        bail!("binding source changed while being read");
    }
    Ok(bytes)
}

fn write_proposal(output: &Path, bytes: &[u8]) -> Result<String> {
    require_absolute_normal_path(output, "binding proposal output")?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let mut file = options
        .open(output)
        .context("create private binding deployment proposal")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
