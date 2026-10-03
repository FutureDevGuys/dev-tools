use super::*;
use crate::setup::{WorkloadAliasReceipt, WORKLOAD_ALIAS_RECEIPT_SCHEMA};

mod desktop;
pub(super) use desktop::desktop_retirements;

enum EntryObservation<T> {
    Absent,
    Owned(T),
    Unowned,
}

impl<T> EntryObservation<T> {
    fn is_owned(&self) -> bool {
        matches!(self, Self::Owned(_))
    }
}

pub(super) struct WorkloadRetirement {
    home: PathBuf,
    owner: u32,
    original: Option<WorkloadAliasReceipt>,
    original_owners: BTreeMap<String, u32>,
    candidate: WorkloadAliasReceipt,
    original_installation: PathBuf,
}

impl WorkloadRetirement {
    fn targets(&self) -> Result<BTreeMap<String, Vec<(PathBuf, u32)>>> {
        let mut targets: BTreeMap<String, Vec<(PathBuf, u32)>> = BTreeMap::new();
        for (receipt, original) in self
            .original
            .iter()
            .map(|receipt| (receipt, true))
            .chain(std::iter::once((&self.candidate, false)))
        {
            if receipt.schema != WORKLOAD_ALIAS_RECEIPT_SCHEMA
                || receipt.executable.is_empty()
                || receipt.executable.len() > 4096
                || receipt.executable.contains('\0')
            {
                bail!("retained workload receipt has invalid authority");
            }
            crate::setup::validate_workload_alias_names(&receipt.aliases)?;
            for alias in &receipt.aliases {
                targets.entry(alias.clone()).or_default().push((
                    PathBuf::from(&receipt.executable),
                    if original {
                        self.original_owners
                            .get(alias)
                            .copied()
                            .unwrap_or(self.owner)
                    } else {
                        self.owner
                    },
                ));
            }
        }
        Ok(targets)
    }

    fn authority(&self) -> DocumentAuthority {
        DocumentAuthority {
            owner_uid: self.owner,
            mode: 0o600,
            limit: DOCUMENT_LIMIT,
        }
    }

    fn receipt_path(&self) -> PathBuf {
        self.home
            .join(".local/share/dev-auth/workload-aliases-v1.json")
    }

    fn observe_receipt(
        &self,
        directory: Option<&dev_tools_installation::ExistingDocumentDirectory>,
    ) -> Result<Option<dev_tools_installation::AtomicDocument>> {
        let Some(directory) = directory else {
            return Ok(None);
        };
        let document = directory.read(
            std::ffi::OsStr::new("workload-aliases-v1.json"),
            &self.authority(),
        )?;
        if let Some(document) = &document {
            let receipt: WorkloadAliasReceipt = serde_json::from_slice(&document.bytes)?;
            let empty_allowed = receipt.schema == WORKLOAD_ALIAS_RECEIPT_SCHEMA
                && receipt.aliases.is_empty()
                && (receipt.executable == self.candidate.executable
                    || receipt.executable == self.original_installation.to_string_lossy()
                    || self
                        .original
                        .as_ref()
                        .is_some_and(|prior| receipt.executable == prior.executable));
            if !empty_allowed
                && receipt != self.candidate
                && self.original.as_ref() != Some(&receipt)
            {
                bail!("current workload receipt is outside the retained generation");
            }
        }
        Ok(document)
    }

    fn observe_links(
        &self,
        directory: Option<&dev_tools_installation::ExistingDocumentDirectory>,
        receipt: Option<&dev_tools_installation::AtomicDocument>,
    ) -> Result<BTreeMap<String, EntryObservation<(PathBuf, u32)>>> {
        let mut claimed: BTreeSet<String> = self
            .original
            .iter()
            .flat_map(|receipt| receipt.aliases.iter().cloned())
            .collect();
        if let Some(receipt) = receipt {
            claimed.extend(serde_json::from_slice::<WorkloadAliasReceipt>(&receipt.bytes)?.aliases);
        }
        let mut observed = BTreeMap::new();
        for (name, targets) in self.targets()? {
            let metadata = match directory {
                Some(directory) => directory.metadata(std::ffi::OsStr::new(&name))?,
                None => None,
            };
            let observation = match (directory, metadata) {
                (Some(directory), Some(metadata))
                    if metadata.file_type().is_symlink()
                        && targets.iter().any(|(_, owner)| *owner == metadata.uid())
                        && metadata.nlink() == 1
                        && metadata.len() > 0
                        && metadata.len() <= 4096 =>
                {
                    match directory.read_symbolic_link_with_owner(
                        std::ffi::OsStr::new(&name),
                        metadata.uid(),
                    )? {
                        Some(target)
                            if targets.iter().any(|(expected, owner)| {
                                *owner == metadata.uid()
                                    && expected.as_os_str() == target.as_os_str()
                            }) =>
                        {
                            EntryObservation::Owned((target, metadata.uid()))
                        }
                        Some(_) => EntryObservation::Unowned,
                        None => EntryObservation::Absent,
                    }
                }
                (_, None) => EntryObservation::Absent,
                _ => EntryObservation::Unowned,
            };
            if claimed.contains(&name) && matches!(observation, EntryObservation::Unowned) {
                bail!("receipted workload launcher differs from the retained generation");
            }
            observed.insert(name, observation);
        }
        Ok(observed)
    }

    pub(super) fn observe(&self) -> Result<()> {
        let receipt_directory = open_restoration_parent(&self.receipt_path(), self.owner)?;
        let bin = open_restoration_parent(&self.home.join(".local/bin/unused"), self.owner)?;
        let receipt = self.observe_receipt(receipt_directory.as_ref())?;
        self.observe_links(bin.as_ref(), receipt.as_ref())?;
        Ok(())
    }

    pub(super) fn verify_retired(&self) -> Result<()> {
        let receipt_directory = open_restoration_parent(&self.receipt_path(), self.owner)?;
        let bin = open_restoration_parent(&self.home.join(".local/bin/unused"), self.owner)?;
        if self.observe_receipt(receipt_directory.as_ref())?.is_some()
            || self
                .observe_links(bin.as_ref(), None)?
                .values()
                .any(EntryObservation::is_owned)
        {
            bail!("retained workload integrations remain installed");
        }
        Ok(())
    }

    pub(super) fn retire(&self) -> Result<bool> {
        let receipt_directory = open_restoration_parent(&self.receipt_path(), self.owner)?;
        let bin = open_restoration_parent(&self.home.join(".local/bin/unused"), self.owner)?;
        // Admit all current evidence before removing anything. The retained
        // generation, not an independently changed receipt, bounds the names.
        let receipt = self.observe_receipt(receipt_directory.as_ref())?;
        let links = self.observe_links(bin.as_ref(), receipt.as_ref())?;
        let mut changed = false;
        if let Some(bin) = &bin {
            for (name, targets) in self.targets()? {
                let expected = match links.get(&name).context("workload observation is absent")? {
                    EntryObservation::Owned(target) => target,
                    EntryObservation::Absent => &targets[0],
                    EntryObservation::Unowned => continue,
                };
                changed |= bin.remove_symbolic_link_with_owner(
                    std::ffi::OsStr::new(&name),
                    &expected.0,
                    expected.1,
                )?;
            }
        }
        // Each entry's parent has been synced before discarding the live
        // receipt. The retained generation survives both absent-receipt retries
        // and candidate entries published before their receipt.
        if let Some(directory) = &receipt_directory {
            let expected = match receipt {
                Some(receipt) => receipt.identity,
                None => {
                    let bytes = serde_json::to_vec(&self.candidate)?;
                    dev_tools_installation::ArtifactIdentity {
                        length: bytes.len() as u64,
                        sha256: sha256_hex(&bytes),
                    }
                }
            };
            changed |= directory.remove(
                std::ffi::OsStr::new("workload-aliases-v1.json"),
                &self.authority(),
                &expected,
            )?;
        }
        self.verify_retired()?;
        Ok(changed)
    }
}

pub(super) fn workload_retirements(
    generation: &RetainedSetupGeneration,
    original_installation: &Path,
) -> Result<Vec<WorkloadRetirement>> {
    let plan = &generation.plan;
    let mut retirements = Vec::new();
    for account in plan.accounts.iter().chain(&plan.retiring_accounts) {
        let original = retained_object(generation, "workload_launcher_receipt", &account.name)?;
        let expected_path = account
            .home
            .join(".local/share/dev-auth/workload-aliases-v1.json");
        if original.current.path != expected_path
            || original
                .current
                .identity
                .as_ref()
                .is_some_and(|identity| identity.owner_uid != account.uid || identity.mode != 0o600)
        {
            bail!("retained workload receipt has incompatible custody or destination");
        }
        let original: Option<WorkloadAliasReceipt> = original
            .bytes
            .as_deref()
            .map(serde_json::from_slice)
            .transpose()?;
        let aliases = candidate_workloads(generation, account)?
            .keys()
            .cloned()
            .collect();
        let mut retirement = WorkloadRetirement {
            home: account.home.clone(),
            owner: account.uid,
            original,
            original_owners: BTreeMap::new(),
            candidate: WorkloadAliasReceipt {
                schema: WORKLOAD_ALIAS_RECEIPT_SCHEMA.into(),
                executable: plan
                    .installation
                    .paths
                    .data_root
                    .join("versions")
                    .join(&plan.installation.request.version)
                    .join("dev-auth")
                    .display()
                    .to_string(),
                aliases,
            },
            original_installation: original_installation.to_path_buf(),
        };
        retirement.targets()?;
        let extras = generation
            .documents
            .iter()
            .filter(|object| {
                object.current.kind == "workload_launcher" && object.current.subject == account.name
            })
            .collect::<Vec<_>>();
        let prior_aliases = retirement
            .original
            .as_ref()
            .map(|receipt| receipt.aliases.as_slice())
            .unwrap_or(&[]);
        if extras.len() != prior_aliases.len() {
            bail!("retained workload object inventory is incomplete or ambiguous");
        }
        for alias in prior_aliases {
            let path = account.home.join(".local/bin").join(alias);
            let matching = extras
                .iter()
                .filter(|object| object.current.path == path)
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                bail!("retained workload object selection is ambiguous");
            }
            let object = matching[0];
            let identity = object
                .current
                .identity
                .as_ref()
                .context("retained workload object identity is absent")?;
            let target = retirement
                .original
                .as_ref()
                .context("retained workload receipt is absent")?
                .executable
                .as_str();
            if object.bytes.is_some()
                || identity.object_type != "symlink"
                || (identity.owner_uid != account.uid
                    && !(identity.owner_uid == 0
                        && plan.intent.mode == DeploymentMode::Strong
                        && nix::unistd::Uid::effective().is_root()))
                || identity.mode != 0o777
                || identity.link_count != 1
                || identity.length != target.len() as u64
                || identity.sha256 != sha256_hex(target.as_bytes())
                || identity.link_target.as_ref().map(|path| path.as_os_str())
                    != Some(std::ffi::OsStr::new(target))
            {
                bail!("retained workload object differs from its approved receipt");
            }
            retirement
                .original_owners
                .insert(alias.clone(), identity.owner_uid);
        }
        retirements.push(retirement);
    }
    Ok(retirements)
}

fn candidate_workloads(
    generation: &RetainedSetupGeneration,
    account: &NativeAccountIdentity,
) -> Result<BTreeMap<String, crate::policy_v2::ResolvedWorkload>> {
    let plan = &generation.plan;
    if plan.intent.activation != Activation::Transparent || !plan.accounts.contains(account) {
        return Ok(BTreeMap::new());
    }
    let administrator = document_identity(plan, "administrator_policy", "system")?;
    let authority = if plan.intent.mode == DeploymentMode::UserOnly {
        plan.source_documents
            .iter()
            .find(|document| document.kind == "user_policy" && document.subject == account.name)
            .unwrap_or(administrator)
    } else {
        administrator
    };
    let policy =
        parse_runtime_administrator(candidate_bytes(&generation.candidate_documents, authority)?)?;
    let configuration = document_identity(plan, "user_configuration", &account.name)?;
    Ok(policy
        .resolve_user(
            &account.name,
            candidate_bytes(&generation.candidate_documents, configuration)?,
        )?
        .workloads)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn integration_generation(root: Option<&Path>) -> RetainedSetupGeneration {
        let mut generation = crate::setup_v3::restoration::configuration::tests::generation(true);
        let accounts = generation
            .plan
            .accounts
            .iter_mut()
            .chain(&mut generation.plan.retiring_accounts);
        for account in accounts {
            if let Some(root) = root {
                account.home = root.join(&account.name);
            }
        }
        for account in generation
            .plan
            .accounts
            .iter()
            .chain(&generation.plan.retiring_accounts)
        {
            let target = "/fixture/prior/dev-auth";
            let desktop = b"retained desktop fixture\n";
            let workload = WorkloadAliasReceipt {
                schema: WORKLOAD_ALIAS_RECEIPT_SCHEMA.into(),
                executable: target.into(),
                aliases: vec!["owned".into()],
            };
            let entries = crate::setup::DesktopEntryReceipt {
                schema: crate::setup::DESKTOP_ENTRY_RECEIPT_SCHEMA.into(),
                entries: BTreeMap::from([("dev-auth-owned.desktop".into(), sha256_hex(desktop))]),
            };
            for (kind, relative, bytes) in [
                (
                    "workload_launcher_receipt",
                    ".local/share/dev-auth/workload-aliases-v1.json",
                    serde_json::to_vec(&workload).unwrap(),
                ),
                (
                    "desktop_entry_receipt",
                    ".local/share/dev-auth/desktop-entries-v1.json",
                    serde_json::to_vec(&entries).unwrap(),
                ),
                (
                    "workload_launcher",
                    ".local/bin/owned",
                    target.as_bytes().to_vec(),
                ),
                (
                    "desktop_entry",
                    ".local/share/applications/dev-auth-owned.desktop",
                    desktop.to_vec(),
                ),
            ] {
                let link = kind == "workload_launcher";
                let current = CurrentPathIdentity {
                    kind: kind.into(),
                    subject: account.name.clone(),
                    path: account.home.join(relative),
                    identity: Some(CurrentFileIdentity {
                        object_type: if link { "symlink" } else { "file" }.into(),
                        owner_uid: account.uid,
                        mode: if link {
                            0o777
                        } else if kind.ends_with("receipt") {
                            0o600
                        } else {
                            0o644
                        },
                        link_count: 1,
                        length: bytes.len() as u64,
                        sha256: sha256_hex(&bytes),
                        link_target: link.then(|| PathBuf::from(target)),
                    }),
                };
                if kind.ends_with("receipt") {
                    generation.plan.current_paths.push(current.clone());
                }
                generation.documents.push(RetainedSetupObject {
                    current,
                    bytes: (!link).then_some(bytes),
                });
            }
        }
        generation
    }

    #[test]
    fn integration_selection_binds_desired_and_retiring_accounts_to_retained_receipts() {
        let generation = integration_generation(None);
        let workloads =
            workload_retirements(&generation, Path::new("/fixture/prior/dev-auth")).unwrap();
        assert_eq!(workloads.len(), 3);
        assert!(workloads
            .iter()
            .all(|retirement| retirement.candidate.aliases.is_empty()));
        assert_eq!(desktop_retirements(&generation).unwrap().len(), 3);
        for kind in [
            "workload_launcher_receipt",
            "desktop_entry_receipt",
            "workload_launcher",
            "desktop_entry",
        ] {
            for corruption in ["owner", "mode", "path", "identity", "duplicate", "missing"] {
                let mut generation = integration_generation(None);
                let index = generation
                    .documents
                    .iter()
                    .position(|object| {
                        object.current.kind == kind && object.current.subject == "gamma"
                    })
                    .unwrap();
                let original = generation.documents[index].current.clone();
                let object = &mut generation.documents[index];
                match corruption {
                    "owner" => object.current.identity.as_mut().unwrap().owner_uid = 0,
                    "mode" => object.current.identity.as_mut().unwrap().mode = 0o4777,
                    "path" => object.current.path = "/fixture/unowned".into(),
                    "identity" => object.current.identity.as_mut().unwrap().sha256 = "0".repeat(64),
                    "duplicate" | "missing" => {}
                    _ => unreachable!(),
                }
                if let Some(approved) = generation
                    .plan
                    .current_paths
                    .iter_mut()
                    .find(|current| **current == original)
                {
                    *approved = object.current.clone();
                }
                if corruption == "duplicate" {
                    let object = &generation.documents[index];
                    generation.documents.push(RetainedSetupObject {
                        current: object.current.clone(),
                        bytes: object.bytes.clone(),
                    });
                } else if corruption == "missing" {
                    generation.documents.remove(index);
                }
                let rejected = if kind.starts_with("workload") {
                    workload_retirements(&generation, Path::new("/fixture/prior/dev-auth")).is_err()
                } else {
                    desktop_retirements(&generation).is_err()
                };
                assert!(rejected, "{kind}: {corruption}");
            }
        }
    }

    #[test]
    #[ignore = "requires Linux subordinate UID/GID mappings and unshare"]
    fn native_root_integration_retirement_preserves_account_and_directory_boundaries() {
        if !nix::unistd::Uid::effective().is_root() {
            let arguments = [
                std::ffi::OsString::from("--user"), "--map-auto".into(), "--map-root-user".into(),
                std::env::current_exe().unwrap().into_os_string(), "--exact".into(),
                "setup_v3::restoration::integration::tests::native_root_integration_retirement_preserves_account_and_directory_boundaries".into(), "--ignored".into(), "--nocapture".into(),
            ];
            let output =
                dev_tools_command::run_bounded_command(&dev_tools_command::BoundedCommand {
                    executable: Path::new("/usr/bin/unshare"),
                    arguments: &arguments,
                    environment: &BTreeMap::new(),
                    cwd: None,
                    timeout: std::time::Duration::from_secs(30),
                    output_limit: 16 * 1024,
                })
                .unwrap();
            assert!(
                output.status.success(),
                "stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let mut generation = integration_generation(Some(root.path()));
        generation.plan_sha256 = sha256_hex(&serde_jcs::to_vec(&generation.plan).unwrap());
        let set_owner = |path: &Path, owner| {
            rustix::fs::chownat(
                rustix::fs::CWD,
                path,
                Some(rustix::fs::Uid::from_raw(owner)),
                None,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .unwrap();
        };
        for account in generation
            .plan
            .accounts
            .iter()
            .chain(&generation.plan.retiring_accounts)
        {
            for relative in [
                "",
                ".local",
                ".local/bin",
                ".local/share",
                ".local/share/dev-auth",
                ".local/share/applications",
            ] {
                let path = account.home.join(relative);
                fs::create_dir(&path).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                set_owner(&path, account.uid);
            }
            fs::write(account.home.join("unrelated"), b"unrelated account bytes").unwrap();
            set_owner(&account.home.join("unrelated"), account.uid);
        }
        for object in generation.documents.iter().filter(|object| {
            matches!(
                object.current.kind.as_str(),
                "workload_launcher_receipt"
                    | "desktop_entry_receipt"
                    | "workload_launcher"
                    | "desktop_entry"
            )
        }) {
            let identity = object.current.identity.as_ref().unwrap();
            if let Some(target) = &identity.link_target {
                std::os::unix::fs::symlink(target, &object.current.path).unwrap();
            } else {
                fs::write(&object.current.path, object.bytes.as_ref().unwrap()).unwrap();
                fs::set_permissions(
                    &object.current.path,
                    fs::Permissions::from_mode(identity.mode),
                )
                .unwrap();
            }
            set_owner(&object.current.path, identity.owner_uid);
        }
        let workloads =
            workload_retirements(&generation, Path::new("/fixture/prior/dev-auth")).unwrap();
        let desktops = desktop_retirements(&generation).unwrap();
        let first = &generation.plan.accounts[0];
        let bin = first.home.join(".local/bin");
        let retained_bin = first.home.join(".local/retained-bin");
        let foreign = root.path().join("foreign");
        fs::create_dir(&foreign).unwrap();
        std::os::unix::fs::symlink("/unrelated/program", foreign.join("owned")).unwrap();
        fs::rename(&bin, &retained_bin).unwrap();
        std::os::unix::fs::symlink(&foreign, &bin).unwrap();
        assert!(workloads[0].retire().is_err());
        assert!(fs::symlink_metadata(retained_bin.join("owned")).is_ok());
        assert_eq!(
            fs::read_link(foreign.join("owned")).unwrap(),
            Path::new("/unrelated/program")
        );
        fs::remove_file(&bin).unwrap();
        fs::rename(&retained_bin, &bin).unwrap();
        set_owner(&bin.join("owned"), 0);
        assert!(workloads[0].retire().is_err());
        assert!(first
            .home
            .join(".local/share/dev-auth/workload-aliases-v1.json")
            .exists());
        set_owner(&bin.join("owned"), first.uid);
        // A legacy root-owned original is admitted only when that ownership
        // was retained, not merely because a current link is root-owned.
        let legacy = generation.plan.retiring_accounts[0]
            .home
            .join(".local/bin/owned");
        set_owner(&legacy, 0);
        generation
            .documents
            .iter_mut()
            .find(|object| object.current.path == legacy)
            .unwrap()
            .current
            .identity
            .as_mut()
            .unwrap()
            .owner_uid = 0;
        let workloads = workload_retirements(&generation, Path::new("/fixture/prior/dev-auth"))
            .expect("strong generation admits the retained legacy root owner");
        let mut pair_check =
            workload_retirements(&generation, Path::new("/fixture/prior/dev-auth"))
                .unwrap()
                .pop()
                .unwrap();
        pair_check.candidate.aliases = vec!["owned".into()];
        let prior_target = fs::read_link(&legacy).unwrap();
        fs::remove_file(&legacy).unwrap();
        std::os::unix::fs::symlink(&pair_check.candidate.executable, &legacy).unwrap();
        assert!(
            pair_check.retire().is_err(),
            "root candidate is not the retained root original"
        );
        assert_eq!(fs::symlink_metadata(&legacy).unwrap().uid(), 0);
        fs::remove_file(&legacy).unwrap();
        std::os::unix::fs::symlink(&prior_target, &legacy).unwrap();
        set_owner(&legacy, pair_check.owner);
        assert!(
            pair_check.retire().is_err(),
            "native-owner prior target is not either admitted pair"
        );
        set_owner(&legacy, 0);
        pair_check.observe().unwrap();
        generation.plan.intent.mode = DeploymentMode::UserOnly;
        assert!(workload_retirements(&generation, Path::new("/fixture/prior/dev-auth")).is_err());
        generation.plan.intent.mode = DeploymentMode::Strong;
        let first = &generation.plan.accounts[0];
        // A later account's desktop drift must block the composite operation
        // before it removes an earlier account's valid launcher or receipt.
        let last_desktop = generation.plan.retiring_accounts[0]
            .home
            .join(".local/share/applications/dev-auth-owned.desktop");
        let original_desktop = fs::read(&last_desktop).unwrap();
        fs::write(&last_desktop, b"unrelated account edit\n").unwrap();
        let retire = || retire_user_integrations(&generation, Path::new("/fixture/prior/dev-auth"));
        assert!(retire().is_err());
        assert!(fs::symlink_metadata(bin.join("owned")).is_ok());
        assert!(first
            .home
            .join(".local/share/dev-auth/workload-aliases-v1.json")
            .exists());
        assert_eq!(
            fs::read(&last_desktop).unwrap(),
            b"unrelated account edit\n"
        );
        fs::write(&last_desktop, original_desktop).unwrap();
        assert!(retire().unwrap());
        assert!(!retire().unwrap());
        for retirement in &workloads {
            retirement.verify_retired().unwrap();
        }
        for retirement in &desktops {
            retirement.verify_retired().unwrap();
        }
        for account in generation
            .plan
            .accounts
            .iter()
            .chain(&generation.plan.retiring_accounts)
        {
            assert_eq!(
                fs::read(account.home.join("unrelated")).unwrap(),
                b"unrelated account bytes"
            );
            assert_eq!(
                fs::metadata(account.home.join("unrelated")).unwrap().uid(),
                account.uid
            );
            for relative in [
                ".local/bin",
                ".local/share/dev-auth",
                ".local/share/applications",
            ] {
                let metadata = fs::metadata(account.home.join(relative)).unwrap();
                assert_eq!(metadata.uid(), account.uid);
                assert_eq!(metadata.mode() & 0o7777, 0o700);
            }
        }
    }

    #[test]
    fn workload_retirement_preserves_unclaimed_candidate_name_collisions() {
        let temporary = tempfile::tempdir().unwrap();
        let home = temporary.path();
        fs::create_dir_all(home.join(".local/bin")).unwrap();
        let external_file = home.join(".local/bin/external-file");
        let external_link = home.join(".local/bin/external-link");
        fs::write(&external_file, b"user executable").unwrap();
        std::os::unix::fs::symlink("/unrelated/program", &external_link).unwrap();
        let retirement = WorkloadRetirement {
            home: home.to_path_buf(),
            owner: nix::unistd::Uid::effective().as_raw(),
            original: None,
            original_owners: BTreeMap::new(),
            candidate: WorkloadAliasReceipt {
                schema: WORKLOAD_ALIAS_RECEIPT_SCHEMA.into(),
                executable: "/candidate/dev-auth".into(),
                aliases: vec!["external-file".into(), "external-link".into()],
            },
            original_installation: "/candidate/dev-auth".into(),
        };
        assert!(!retirement.retire().unwrap());
        retirement.verify_retired().unwrap();
        assert_eq!(fs::read(&external_file).unwrap(), b"user executable");
        assert_eq!(
            fs::read_link(&external_link).unwrap(),
            Path::new("/unrelated/program")
        );
        assert!(!home.join(".local/share").exists());
    }

    #[test]
    fn workload_retirement_removes_partial_candidate_without_expanding_receipt_authority() {
        let temporary = tempfile::tempdir().unwrap();
        let home = temporary.path();
        fs::create_dir_all(home.join(".local/bin")).unwrap();
        fs::create_dir_all(home.join(".local/share/dev-auth")).unwrap();
        let old_target = home.join("old");
        let candidate_target = home.join("candidate");
        fs::write(&old_target, b"old executable fixture").unwrap();
        fs::write(&candidate_target, b"candidate executable fixture").unwrap();
        let original = WorkloadAliasReceipt {
            schema: WORKLOAD_ALIAS_RECEIPT_SCHEMA.into(),
            executable: old_target.display().to_string(),
            aliases: vec!["old-work".into()],
        };
        let candidate = WorkloadAliasReceipt {
            schema: WORKLOAD_ALIAS_RECEIPT_SCHEMA.into(),
            executable: candidate_target.display().to_string(),
            aliases: vec!["new-work".into()],
        };
        let receipt_path = home.join(".local/share/dev-auth/workload-aliases-v1.json");
        fs::write(&receipt_path, serde_json::to_vec(&original).unwrap()).unwrap();
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&old_target, home.join(".local/bin/old-work")).unwrap();
        std::os::unix::fs::symlink(&candidate_target, home.join(".local/bin/new-work")).unwrap();
        std::os::unix::fs::symlink(&candidate_target, home.join(".local/bin/unrelated")).unwrap();
        let retirement = WorkloadRetirement {
            home: home.to_path_buf(),
            owner: nix::unistd::Uid::effective().as_raw(),
            original: Some(original),
            original_owners: BTreeMap::new(),
            candidate,
            original_installation: old_target.clone(),
        };
        let mut foreign_receipt = retirement.original.clone().unwrap();
        foreign_receipt.aliases.push("unrelated".into());
        fs::write(&receipt_path, serde_json::to_vec(&foreign_receipt).unwrap()).unwrap();
        assert!(retirement.retire().is_err());
        for name in ["old-work", "new-work", "unrelated"] {
            assert!(fs::symlink_metadata(home.join(".local/bin").join(name)).is_ok());
        }
        fs::write(
            &receipt_path,
            serde_json::to_vec(retirement.original.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
        let new_link = home.join(".local/bin/new-work");
        fs::write(
            &receipt_path,
            serde_json::to_vec(&retirement.candidate).unwrap(),
        )
        .unwrap();
        fs::remove_file(&new_link).unwrap();
        std::os::unix::fs::symlink(&old_target, &new_link).unwrap();
        assert!(retirement.retire().is_err());
        assert!(receipt_path.exists());
        assert!(fs::symlink_metadata(home.join(".local/bin/old-work")).is_ok());
        fs::remove_file(&new_link).unwrap();
        std::os::unix::fs::symlink(&candidate_target, &new_link).unwrap();
        assert!(retirement.retire().unwrap());
        assert!(fs::symlink_metadata(home.join(".local/bin/old-work")).is_err());
        assert!(fs::symlink_metadata(home.join(".local/bin/new-work")).is_err());
        assert!(fs::symlink_metadata(home.join(".local/bin/unrelated")).is_ok());
        assert!(!receipt_path.exists());
        assert_eq!(fs::read(&old_target).unwrap(), b"old executable fixture");
        assert_eq!(
            fs::read(&candidate_target).unwrap(),
            b"candidate executable fixture"
        );
        assert!(!retirement.retire().unwrap());
        // Receipt removal alone is not the terminal condition: interrupted
        // candidate publication remains selected by the retained approval.
        std::os::unix::fs::symlink(&candidate_target, &new_link).unwrap();
        assert!(retirement.verify_retired().is_err());
        assert!(retirement.retire().unwrap());
        retirement.verify_retired().unwrap();
    }
}
