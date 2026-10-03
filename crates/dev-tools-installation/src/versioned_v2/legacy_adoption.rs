//! Forward-only receipt-less two-level adoption. Products authenticate the
//! proposed receipt and retire independent legacy writers in the local callback.
use super::*;

const SCHEMA: &str = "dev-tools-versioned-protocol-adoption-v2";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: String,
    layout: VersionedLayout,
    next: VersionedReceipt,
    legacy: VersionedLegacyTransition,
}

/// A read-only preflight, not a receipt or authorization token. Commit repeats
/// custody checks and compares the captured topology under the installation lock.
pub struct PreparedAdoption {
    request: VersionedTwoLevelAdoption,
    journal: Journal,
    artifact_limit: u64,
}

/// Prepare an authenticated product-selected active and optional retained identity
/// without filesystem mutation or execution. The caller owns release proof and
/// ancestor trust; no identity is inferred from a legacy filename or state field.
pub fn prepare(
    request: &VersionedTwoLevelAdoption,
    expected: &VersionedReceipt,
    artifact_limit: u64,
) -> Result<PreparedAdoption> {
    let layout = &request.adoption.layout;
    validate_versioned_receipt(layout, expected)?;
    if request.adoption.version != expected.active_version
        || request.adoption.identity != expected.active_identity
        || request.adoption.aliases != expected.aliases
    {
        bail!("legacy adoption does not match the proposed installation");
    }
    verify_two_level_versioned_adoption(request, artifact_limit)?;
    if let Some((version, identity)) = expected
        .previous_version
        .as_ref()
        .zip(expected.previous_identity.as_ref())
    {
        if identity.length > artifact_limit {
            bail!("retained legacy artifact exceeds its bound");
        }
        inspect_legacy_adoption_directory_read_only(
            &layout.versions_dir().join(version),
            layout.owner_uid,
        )?;
        verify_versioned_artifact_authority(
            &layout.version_artifact(version),
            layout.owner_uid,
            identity,
        )?;
    }
    let legacy = inspect_legacy_transition(
        &request.adoption,
        Some(&request.version_pointer),
        &layout.version_artifact(&expected.active_version),
    )?;
    Ok(PreparedAdoption {
        request: request.clone(),
        artifact_limit,
        journal: Journal {
            schema: SCHEMA.into(),
            layout: layout.clone(),
            next: expected.clone(),
            legacy,
        },
    })
}

impl PreparedAdoption {
    /// Start forward-only adoption under the existing installation lock. Errors
    /// may include directory hardening or a durable journal. The journal fences
    /// v1 writers before the callback, and is retained on callback failure.
    ///
    /// The callback authenticates both identities and durably retires independent
    /// product writers. It must be bounded, local, idempotent, and must not mutate
    /// installation state, reacquire this lock, or wait for its holder. An outer
    /// product lease must precede the installation lock. Callback success is
    /// required before any pointer or receipt publication. Resume may repeat it.
    pub fn commit(
        self,
        commit_product_state: impl FnOnce(&VersionedReceipt) -> Result<()>,
    ) -> Result<VersionedReceipt> {
        let layout = &self.journal.layout;
        inspect_legacy_adoption_directory_read_only(&layout.data_root, layout.owner_uid)?;
        let lock = InstallationLock::acquire(&layout.lock_path())?;
        let current = prepare(&self.request, &self.journal.next, self.artifact_limit)?;
        if current.journal != self.journal {
            bail!("legacy topology changed before adoption");
        }
        harden_legacy_adoption_layout(layout, &self.journal.next.active_version)?;
        if let Some(version) = &self.journal.next.previous_version {
            harden_legacy_adoption_directory(
                &layout.versions_dir().join(version),
                layout.owner_uid,
                layout.directory_mode,
            )?;
        }
        for path in [
            &layout.data_root,
            &layout.bin_dir,
            &layout.versions_dir(),
            &layout
                .versions_dir()
                .join(&self.journal.next.active_version),
        ] {
            sync_directory(path)?;
        }
        if let Some(version) = &self.journal.next.previous_version {
            sync_directory(&layout.versions_dir().join(version))?;
        }
        verify_observation_lock(layout, &lock)?;
        write_new_journal(layout, &self.journal)?;
        finish(
            &self.journal,
            self.artifact_limit,
            &lock,
            commit_product_state,
            |_| Ok(()),
        )
    }
}

/// Read only the strict pending adoption metadata. This authenticates no release,
/// checks no artifact custody, and neither creates a journal nor resumes one.
pub fn read_pending_receipt(layout: &VersionedLayout) -> Result<VersionedReceipt> {
    Ok(read_journal(layout)?.0.next)
}

/// Resume only an existing adoption journal. This is forward-only: it never
/// restores a v1 writer or cancels product retirement. The callback has commit's
/// authentication, bounded-local-work and lock-order contract. No pending journal
/// is an error, including completed repeats; use ordinary v2 observation then.
pub fn resume(
    layout: &VersionedLayout,
    artifact_limit: u64,
    commit_product_state: impl FnOnce(&VersionedReceipt) -> Result<()>,
) -> Result<VersionedReceipt> {
    validate_layout(layout)?;
    require_bound(artifact_limit)?;
    inspect_owned_directory_read_only(&layout.data_root, layout)?;
    let lock = InstallationLock::acquire(&layout.lock_path())?;
    let (journal, _) = read_journal(layout)?;
    finish(
        &journal,
        artifact_limit,
        &lock,
        commit_product_state,
        |_| Ok(()),
    )
}

fn read_journal(layout: &VersionedLayout) -> Result<(Journal, ArtifactIdentity)> {
    validate_layout(layout)?;
    let document = read_atomic_document(&layout.journal_path(), &receipt_authority(layout))?
        .context("installation has no legacy adoption to resume")?;
    let journal: Journal = serde_json::from_slice(&document.bytes)?;
    validate_journal(layout, &journal)?;
    Ok((journal, document.identity))
}

pub(super) fn recognizes(layout: &VersionedLayout, bytes: &[u8]) -> Result<bool> {
    let Ok(journal) = serde_json::from_slice::<Journal>(bytes) else {
        return Ok(false);
    };
    validate_journal(layout, &journal)?;
    Ok(true)
}

fn validate_journal(layout: &VersionedLayout, journal: &Journal) -> Result<()> {
    if journal.schema != SCHEMA || journal.layout != *layout {
        bail!("legacy adoption journal does not match its layout");
    }
    validate_versioned_receipt(layout, &journal.next)?;
    let pointer = journal
        .legacy
        .version_pointer
        .as_deref()
        .context("legacy adoption requires a two-level pointer")?;
    validate_legacy_version_pointer(layout, pointer)?;
    // Keep the v1 legacy-adoption rule (no previous identity) unchanged. Only
    // this distinct v2 journal can retain an independently authenticated version.
    let active_only = VersionedReceipt {
        previous_version: None,
        previous_identity: None,
        ..journal.next.clone()
    };
    validate_legacy_transition(layout, &active_only, &journal.legacy)
}

fn inspect_links(journal: &Journal) -> Result<()> {
    let layout = &journal.layout;
    let next = &journal.next;
    admissible_link(
        &layout.active_pointer(),
        Some(&layout.version_artifact(&next.active_version)),
        None,
        true,
    )?;
    admissible_link(
        &layout.previous_pointer(),
        next.previous_version
            .as_deref()
            .map(|v| layout.version_artifact(v))
            .as_deref(),
        None,
        true,
    )?;
    let pointer = journal
        .legacy
        .version_pointer
        .as_deref()
        .context("legacy version pointer missing")?;
    admissible_link(
        pointer,
        journal
            .legacy
            .version_pointer_present
            .then(|| layout.versions_dir().join(&next.active_version))
            .as_deref(),
        None,
        true,
    )?;
    for alias in &next.aliases {
        let present = journal.legacy.present_aliases.contains(alias);
        admissible_link(
            &layout.bin_dir.join(alias),
            Some(&layout.active_pointer()),
            present
                .then(|| pointer.join(&layout.artifact_name))
                .as_deref(),
            !present,
        )?;
    }
    Ok(())
}

fn admissible_link(
    path: &Path,
    target: Option<&Path>,
    alternate: Option<&Path>,
    absent: bool,
) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let actual = fs::read_link(path)?;
            if target == Some(actual.as_path()) || alternate == Some(actual.as_path()) {
                Ok(())
            } else {
                bail!("legacy adoption has unowned pointer drift")
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && absent => Ok(()),
        _ => bail!("legacy adoption has unowned pointer drift"),
    }
}

fn installed(
    layout: &VersionedLayout,
    next: &VersionedReceipt,
) -> Result<Option<VersionedReceipt>> {
    if read_versioned_receipt_document(layout)?.is_none() {
        return Ok(None);
    }
    let receipt =
        read_receipt(layout)?.context("legacy adoption cannot replace an empty v2 receipt")?;
    if receipt != *next {
        bail!("installation changed during legacy adoption");
    }
    Ok(Some(receipt))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Active,
    Previous,
    Alias(usize),
    PointerRetired,
    Receipt,
}

fn finish(
    journal: &Journal,
    artifact_limit: u64,
    lock: &InstallationLock,
    commit_product_state: impl FnOnce(&VersionedReceipt) -> Result<()>,
    mut observe: impl FnMut(Phase) -> Result<()>,
) -> Result<VersionedReceipt> {
    let layout = &journal.layout;
    validate_journal(layout, journal)?;
    require_bound(artifact_limit)?;
    inspect_owned_directory_read_only(&layout.data_root, layout)?;
    inspect_owned_directory_read_only(&layout.bin_dir, layout)?;
    verify_recovery_artifacts(layout, &journal.next, artifact_limit)?;
    let prior = installed(layout, &journal.next)?;
    inspect_links(journal)?;
    let (current, identity) = read_journal(layout)?;
    if current != *journal {
        bail!("legacy adoption changed before product cutover");
    }
    commit_product_state(&journal.next)?;
    verify_observation_lock(layout, lock)?;
    if read_journal(layout)?.1 != identity || installed(layout, &journal.next)? != prior {
        bail!("legacy adoption authority changed during product cutover");
    }
    verify_recovery_artifacts(layout, &journal.next, artifact_limit)?;
    inspect_links(journal)?;
    if prior.is_none() {
        restore_owned_symlink(
            &layout.active_pointer(),
            &layout.version_artifact(&journal.next.active_version),
            None,
        )?;
        observe(Phase::Active)?;
        if let Some(version) = &journal.next.previous_version {
            restore_owned_symlink(
                &layout.previous_pointer(),
                &layout.version_artifact(version),
                None,
            )?;
        }
        observe(Phase::Previous)?;
        let pointer = journal
            .legacy
            .version_pointer
            .as_deref()
            .context("legacy version pointer missing")?;
        for (index, alias) in journal.next.aliases.iter().enumerate() {
            let old = journal
                .legacy
                .present_aliases
                .contains(alias)
                .then(|| pointer.join(&layout.artifact_name));
            restore_owned_symlink(
                &layout.bin_dir.join(alias),
                &layout.active_pointer(),
                old.as_deref(),
            )?;
            observe(Phase::Alias(index))?;
        }
        if journal.legacy.version_pointer_present {
            remove_symlink_if_target(
                pointer,
                &layout.versions_dir().join(&journal.next.active_version),
            )?;
        }
        observe(Phase::PointerRetired)?;
        write_receipt(layout, Some(&journal.next))?;
        observe(Phase::Receipt)?;
    }
    require_path_absent(
        journal
            .legacy
            .version_pointer
            .as_deref()
            .context("legacy version pointer missing")?,
    )?;
    verify_versioned_receipt(layout, &journal.next)?;
    verify_observation_lock(layout, lock)?;
    remove_transition_journal(layout)?;
    Ok(journal.next.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adoption_resumes_forward_at_each_publication_boundary() -> Result<()> {
        for boundary in [
            Phase::Active,
            Phase::Previous,
            Phase::Alias(0),
            Phase::Alias(1),
            Phase::PointerRetired,
            Phase::Receipt,
        ] {
            let root = tempfile::tempdir()?;
            let request = crate::versioned_tests::two_level_adoption(root.path());
            let layout = &request.adoption.layout;
            let retained = layout.version_artifact("0.9.0");
            fs::create_dir(retained.parent().context("retained parent")?)?;
            fs::set_permissions(
                retained.parent().context("retained parent")?,
                fs::Permissions::from_mode(0o700),
            )?;
            fs::write(&retained, b"retained")?;
            fs::set_permissions(&retained, fs::Permissions::from_mode(0o755))?;
            let expected = VersionedReceipt {
                schema: VERSIONED_RECEIPT_SCHEMA.into(),
                product: layout.product.clone(),
                data_root: layout.data_root.clone(),
                bin_dir: layout.bin_dir.clone(),
                artifact_name: layout.artifact_name.clone(),
                active_version: request.adoption.version.clone(),
                active_identity: request.adoption.identity.clone(),
                previous_version: Some("0.9.0".into()),
                previous_identity: Some(ArtifactIdentity::from_file(&retained, 1024)?),
                aliases: request.adoption.aliases.clone(),
            };
            assert!(prepare(&request, &expected, 1024)?
                .commit(|_| bail!("park after fence"))
                .is_err());
            let unmarked = layout.data_root.join(".dev-tools-unmarked");
            fs::write(&unmarked, b"not adoption-owned")?;
            {
                let lock = InstallationLock::acquire(&layout.lock_path())?;
                let (journal, _) = read_journal(layout)?;
                let mut reached = false;
                assert!(finish(
                    &journal,
                    1024,
                    &lock,
                    |_| Ok(()),
                    |phase| {
                        if phase == boundary {
                            reached = true;
                            bail!("interrupted publication");
                        }
                        Ok(())
                    }
                )
                .is_err());
                assert!(reached, "{boundary:?}");
            }
            assert_eq!(
                super::super::pending_recovery(layout)?,
                Some(super::super::PendingRecovery::LegacyAdoption)
            );
            for alias in &expected.aliases {
                assert_eq!(
                    fs::canonicalize(layout.bin_dir.join(alias))?,
                    layout.version_artifact(&expected.active_version),
                    "{boundary:?}"
                );
            }
            assert_eq!(
                resume(layout, 1024, |receipt| {
                    assert_eq!(*receipt, expected);
                    Ok(())
                })?,
                expected
            );
            assert_eq!(super::super::observe(layout, 1024)?, Some(expected));
            assert_eq!(fs::read(&unmarked)?, b"not adoption-owned");
            assert!(!request.version_pointer.exists());
            assert!(!layout.journal_path().exists());
        }
        Ok(())
    }
}
