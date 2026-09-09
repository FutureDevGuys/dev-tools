use super::*;
use crate::setup::{DesktopEntryReceipt, DESKTOP_ENTRY_RECEIPT_SCHEMA};

struct EntryVersion {
    bytes: Vec<u8>,
    mode: u32,
}

pub(in crate::setup_v3::restoration) struct DesktopRetirement {
    home: PathBuf,
    owner: u32,
    original: Option<DesktopEntryReceipt>,
    candidate: DesktopEntryReceipt,
    entries: BTreeMap<String, Vec<EntryVersion>>,
}

impl DesktopRetirement {
    fn authority(&self, mode: u32) -> DocumentAuthority {
        DocumentAuthority {
            owner_uid: self.owner,
            mode,
            limit: DOCUMENT_LIMIT,
        }
    }

    fn receipt_path(&self) -> PathBuf {
        self.home
            .join(".local/share/dev-auth/desktop-entries-v1.json")
    }

    fn observe_receipt(
        &self,
        directory: Option<&dev_tools_installation::ExistingDocumentDirectory>,
    ) -> Result<Option<dev_tools_installation::AtomicDocument>> {
        let Some(directory) = directory else {
            return Ok(None);
        };
        let document = directory.read(
            std::ffi::OsStr::new("desktop-entries-v1.json"),
            &self.authority(0o600),
        )?;
        if let Some(document) = &document {
            let receipt: DesktopEntryReceipt = serde_json::from_slice(&document.bytes)?;
            let empty =
                receipt.schema == DESKTOP_ENTRY_RECEIPT_SCHEMA && receipt.entries.is_empty();
            if !empty && receipt != self.candidate && self.original.as_ref() != Some(&receipt) {
                bail!("current desktop receipt is outside the retained generation");
            }
        }
        Ok(document)
    }

    fn observe_entry(
        &self,
        directory: &dev_tools_installation::ExistingDocumentDirectory,
        name: &str,
        versions: &[EntryVersion],
    ) -> Result<EntryObservation<(dev_tools_installation::AtomicDocument, u32)>> {
        let Some(metadata) = directory.metadata(std::ffi::OsStr::new(name))? else {
            return Ok(EntryObservation::Absent);
        };
        let mode = metadata.mode() & 0o7777;
        if !metadata.is_file()
            || metadata.uid() != self.owner
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > DOCUMENT_LIMIT
            || !versions.iter().any(|version| version.mode == mode)
        {
            return Ok(EntryObservation::Unowned);
        }
        // Only a compatible bounded regular file is opened for content. Read
        // failures remain failures, never evidence of an unrelated user file.
        let Some(document) = directory.read(std::ffi::OsStr::new(name), &self.authority(mode))?
        else {
            return Ok(EntryObservation::Absent);
        };
        if versions
            .iter()
            .any(|version| version.mode == mode && version.bytes == document.bytes)
        {
            Ok(EntryObservation::Owned((document, mode)))
        } else {
            Ok(EntryObservation::Unowned)
        }
    }

    fn observe_entries(
        &self,
        directory: Option<&dev_tools_installation::ExistingDocumentDirectory>,
        receipt: Option<&dev_tools_installation::AtomicDocument>,
    ) -> Result<BTreeMap<String, EntryObservation<(dev_tools_installation::AtomicDocument, u32)>>>
    {
        let mut claimed: BTreeSet<String> = self
            .original
            .iter()
            .flat_map(|receipt| receipt.entries.keys().cloned())
            .collect();
        if let Some(receipt) = receipt {
            claimed.extend(
                serde_json::from_slice::<DesktopEntryReceipt>(&receipt.bytes)?
                    .entries
                    .into_keys(),
            );
        }
        let mut result = BTreeMap::new();
        for (name, versions) in &self.entries {
            if versions.is_empty() {
                bail!("desktop entry has no retained authority");
            }
            let observation = match directory {
                Some(directory) => self.observe_entry(directory, name, versions)?,
                None => EntryObservation::Absent,
            };
            if claimed.contains(name) && matches!(observation, EntryObservation::Unowned) {
                bail!("receipted desktop entry differs from retained content or custody");
            }
            result.insert(name.clone(), observation);
        }
        Ok(result)
    }

    pub(in crate::setup_v3::restoration) fn observe(&self) -> Result<()> {
        let receipts = open_restoration_parent(&self.receipt_path(), self.owner)?;
        let entries = open_restoration_parent(
            &self.home.join(".local/share/applications/unused"),
            self.owner,
        )?;
        let receipt = self.observe_receipt(receipts.as_ref())?;
        self.observe_entries(entries.as_ref(), receipt.as_ref())?;
        Ok(())
    }

    pub(in crate::setup_v3::restoration) fn verify_retired(&self) -> Result<()> {
        let receipts = open_restoration_parent(&self.receipt_path(), self.owner)?;
        let entries = open_restoration_parent(
            &self.home.join(".local/share/applications/unused"),
            self.owner,
        )?;
        if self.observe_receipt(receipts.as_ref())?.is_some()
            || self
                .observe_entries(entries.as_ref(), None)?
                .values()
                .any(EntryObservation::is_owned)
        {
            bail!("retained desktop integrations remain installed");
        }
        Ok(())
    }

    pub(in crate::setup_v3::restoration) fn retire(&self) -> Result<bool> {
        let receipts = open_restoration_parent(&self.receipt_path(), self.owner)?;
        let entries = open_restoration_parent(
            &self.home.join(".local/share/applications/unused"),
            self.owner,
        )?;
        let receipt = self.observe_receipt(receipts.as_ref())?;
        let observations = self.observe_entries(entries.as_ref(), receipt.as_ref())?;
        let mut changed = false;
        if let Some(directory) = &entries {
            for (name, versions) in &self.entries {
                let (expected, mode) = match observations
                    .get(name)
                    .context("desktop observation is absent")?
                {
                    EntryObservation::Owned((document, mode)) => (document.identity.clone(), *mode),
                    EntryObservation::Absent => (identity(&versions[0].bytes), versions[0].mode),
                    EntryObservation::Unowned => continue,
                };
                changed |= directory.remove(
                    std::ffi::OsStr::new(name),
                    &self.authority(mode),
                    &expected,
                )?;
            }
        }
        if let Some(directory) = &receipts {
            let expected = match receipt {
                Some(document) => document.identity,
                None => identity(&serde_json::to_vec(&self.candidate)?),
            };
            changed |= directory.remove(
                std::ffi::OsStr::new("desktop-entries-v1.json"),
                &self.authority(0o600),
                &expected,
            )?;
        }
        self.verify_retired()?;
        Ok(changed)
    }
}

fn identity(bytes: &[u8]) -> dev_tools_installation::ArtifactIdentity {
    dev_tools_installation::ArtifactIdentity {
        length: bytes.len() as u64,
        sha256: sha256_hex(bytes),
    }
}

pub(in crate::setup_v3::restoration) fn desktop_retirements(
    generation: &RetainedSetupGeneration,
) -> Result<Vec<DesktopRetirement>> {
    let mut result = Vec::new();
    for account in generation
        .plan
        .accounts
        .iter()
        .chain(&generation.plan.retiring_accounts)
    {
        let retained = retained_object(generation, "desktop_entry_receipt", &account.name)?;
        if retained.current.path
            != account
                .home
                .join(".local/share/dev-auth/desktop-entries-v1.json")
            || retained
                .current
                .identity
                .as_ref()
                .is_some_and(|identity| identity.owner_uid != account.uid || identity.mode != 0o600)
        {
            bail!("retained desktop receipt has incompatible custody or destination");
        }
        let original: Option<DesktopEntryReceipt> = retained
            .bytes
            .as_deref()
            .map(serde_json::from_slice)
            .transpose()?;
        let desired = crate::setup::desired_desktop_entries(
            &account.home,
            &candidate_workloads(generation, account)?,
        )?;
        let candidate = DesktopEntryReceipt {
            schema: DESKTOP_ENTRY_RECEIPT_SCHEMA.into(),
            entries: desired
                .iter()
                .map(|(name, bytes)| (name.clone(), sha256_hex(bytes)))
                .collect(),
        };
        let mut entries: BTreeMap<String, Vec<EntryVersion>> = desired
            .into_iter()
            .map(|(name, bytes)| (name, vec![EntryVersion { bytes, mode: 0o644 }]))
            .collect();
        let retained_entries = generation
            .documents
            .iter()
            .filter(|object| {
                object.current.kind == "desktop_entry" && object.current.subject == account.name
            })
            .collect::<Vec<_>>();
        if retained_entries.len() != original.as_ref().map_or(0, |receipt| receipt.entries.len()) {
            bail!("retained desktop object inventory is incomplete or ambiguous");
        }
        if let Some(original) = &original {
            if original.schema != DESKTOP_ENTRY_RECEIPT_SCHEMA {
                bail!("retained desktop receipt schema is incompatible");
            }
            for (name, digest) in &original.entries {
                // Keep legacy valid product filenames, but never let a receipt
                // select another directory or a non-product entry.
                if !name.starts_with("dev-auth-")
                    || !name.ends_with(".desktop")
                    || name.contains(['/', '\\', '\0'])
                {
                    bail!("retained desktop entry name is incompatible");
                }
                let path = account.home.join(".local/share/applications").join(name);
                let selected = retained_entries
                    .iter()
                    .filter(|object| object.current.path == path)
                    .collect::<Vec<_>>();
                if selected.len() != 1 {
                    bail!("retained desktop entry selection is ambiguous");
                }
                let object = selected[0];
                let approved = object
                    .current
                    .identity
                    .as_ref()
                    .context("retained desktop identity is absent")?;
                let bytes = object
                    .bytes
                    .as_deref()
                    .context("retained desktop bytes are absent")?;
                if approved.object_type != "file"
                    || approved.link_count != 1
                    || approved.link_target.is_some()
                    || approved.owner_uid != account.uid
                    || approved.mode & !0o777 != 0
                    || approved.mode & 0o022 != 0
                    || bytes.is_empty()
                    || bytes.len() as u64 > DOCUMENT_LIMIT
                    || bytes.len() as u64 != approved.length
                    || sha256_hex(bytes) != approved.sha256
                    || approved.sha256 != *digest
                {
                    bail!("retained desktop content differs from approved custody or receipt");
                }
                entries.entry(name.clone()).or_default().push(EntryVersion {
                    bytes: bytes.to_vec(),
                    mode: approved.mode,
                });
            }
        }
        result.push(DesktopRetirement {
            home: account.home.clone(),
            owner: account.uid,
            original,
            candidate,
            entries,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn desktop_retirement_preserves_unclaimed_candidate_name_collisions() {
        for kind in ["bytes", "permissions", "symlink", "directory", "fifo"] {
            let temporary = tempfile::tempdir().unwrap();
            let home = temporary.path();
            let directory = home.join(".local/share/applications");
            fs::create_dir_all(&directory).unwrap();
            let name = "dev-auth-external.desktop";
            let path = directory.join(name);
            match kind {
                "bytes" | "permissions" => {
                    fs::write(
                        &path,
                        if kind == "bytes" {
                            b"unrelated".as_slice()
                        } else {
                            b"candidate".as_slice()
                        },
                    )
                    .unwrap();
                    fs::set_permissions(
                        &path,
                        fs::Permissions::from_mode(if kind == "permissions" {
                            0o600
                        } else {
                            0o644
                        }),
                    )
                    .unwrap();
                }
                "symlink" => std::os::unix::fs::symlink("/unrelated/file", &path).unwrap(),
                "directory" => fs::create_dir(&path).unwrap(),
                "fifo" => rustix::fs::mkfifoat(
                    rustix::fs::CWD,
                    &path,
                    rustix::fs::Mode::from_raw_mode(0o600),
                )
                .unwrap(),
                _ => unreachable!(),
            }
            let before = fs::symlink_metadata(&path).unwrap();
            let retirement = DesktopRetirement {
                home: home.to_path_buf(),
                owner: nix::unistd::Uid::effective().as_raw(),
                original: None,
                candidate: DesktopEntryReceipt {
                    schema: DESKTOP_ENTRY_RECEIPT_SCHEMA.into(),
                    entries: BTreeMap::from([(name.into(), sha256_hex(b"candidate"))]),
                },
                entries: BTreeMap::from([(
                    name.into(),
                    vec![EntryVersion {
                        bytes: b"candidate".to_vec(),
                        mode: 0o644,
                    }],
                )]),
            };
            assert!(!retirement.retire().unwrap(), "{kind}");
            retirement.verify_retired().unwrap();
            let after = fs::symlink_metadata(&path).unwrap();
            assert_eq!(
                (before.ino(), before.mode(), before.len()),
                (after.ino(), after.mode(), after.len())
            );
            assert!(!home.join(".local/share/dev-auth").exists());
        }
    }

    #[test]
    fn desktop_retirement_preserves_drift_and_finds_unreceipted_candidate() {
        let temporary = tempfile::tempdir().unwrap();
        let home = temporary.path();
        let directory = home.join(".local/share/applications");
        fs::create_dir_all(&directory).unwrap();
        fs::create_dir_all(home.join(".local/share/dev-auth")).unwrap();
        let original_bytes = b"original desktop fixture";
        let candidate_bytes = b"candidate desktop fixture";
        let original = DesktopEntryReceipt {
            schema: DESKTOP_ENTRY_RECEIPT_SCHEMA.into(),
            entries: BTreeMap::from([("dev-auth-old.desktop".into(), sha256_hex(original_bytes))]),
        };
        let candidate = DesktopEntryReceipt {
            schema: DESKTOP_ENTRY_RECEIPT_SCHEMA.into(),
            entries: BTreeMap::from([("dev-auth-new.desktop".into(), sha256_hex(candidate_bytes))]),
        };
        let receipt_path = home.join(".local/share/dev-auth/desktop-entries-v1.json");
        fs::write(&receipt_path, serde_json::to_vec(&original).unwrap()).unwrap();
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(directory.join("dev-auth-old.desktop"), original_bytes).unwrap();
        fs::write(directory.join("dev-auth-new.desktop"), candidate_bytes).unwrap();
        fs::write(directory.join("unrelated.desktop"), candidate_bytes).unwrap();
        for name in [
            "dev-auth-old.desktop",
            "dev-auth-new.desktop",
            "unrelated.desktop",
        ] {
            fs::set_permissions(directory.join(name), fs::Permissions::from_mode(0o644)).unwrap();
        }
        let retirement = DesktopRetirement {
            home: home.to_path_buf(),
            owner: nix::unistd::Uid::effective().as_raw(),
            original: Some(original),
            candidate,
            entries: BTreeMap::from([
                (
                    "dev-auth-old.desktop".into(),
                    vec![EntryVersion {
                        bytes: original_bytes.to_vec(),
                        mode: 0o644,
                    }],
                ),
                (
                    "dev-auth-new.desktop".into(),
                    vec![EntryVersion {
                        bytes: candidate_bytes.to_vec(),
                        mode: 0o644,
                    }],
                ),
            ]),
        };
        let mut foreign = retirement.original.clone().unwrap();
        foreign
            .entries
            .insert("unrelated.desktop".into(), sha256_hex(candidate_bytes));
        fs::write(&receipt_path, serde_json::to_vec(&foreign).unwrap()).unwrap();
        assert!(retirement.retire().is_err());
        fs::write(
            &receipt_path,
            serde_json::to_vec(retirement.original.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
        let old_path = directory.join("dev-auth-old.desktop");
        fs::write(&old_path, b"unrelated owner edit").unwrap();
        assert!(retirement.retire().is_err());
        assert!(directory.join("dev-auth-new.desktop").exists());
        assert!(receipt_path.exists());
        fs::write(&old_path, original_bytes).unwrap();
        fs::set_permissions(&old_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(retirement.retire().is_err());
        assert!(directory.join("dev-auth-new.desktop").exists());
        fs::set_permissions(&old_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(retirement.retire().unwrap());
        assert!(!directory.join("dev-auth-old.desktop").exists());
        assert!(!directory.join("dev-auth-new.desktop").exists());
        assert!(!receipt_path.exists());
        assert_eq!(
            fs::read(directory.join("unrelated.desktop")).unwrap(),
            candidate_bytes
        );
        assert!(!retirement.retire().unwrap());
        fs::write(directory.join("dev-auth-new.desktop"), candidate_bytes).unwrap();
        fs::set_permissions(
            directory.join("dev-auth-new.desktop"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(retirement.verify_retired().is_err());
        assert!(retirement.retire().unwrap());
        retirement.verify_retired().unwrap();
    }
}
