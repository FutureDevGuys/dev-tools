use super::*;

pub(super) struct BindingRestoration<'a> {
    prior: &'a RetainedSetupObject,
    candidate: Option<Vec<u8>>,
    authority: DocumentAuthority,
}

impl BindingRestoration<'_> {
    fn document(&self) -> Result<RestorationDocument<'_>> {
        RestorationDocument::new(
            self.prior,
            self.candidate.as_deref(),
            self.authority.clone(),
        )
    }

    pub(super) fn observe(&self) -> Result<()> {
        if self.candidate.is_none() && self.prior.bytes.is_some() {
            return self.observe_retired_prior().map(|_| ());
        }
        self.document()?.observe().map(|_| ())
    }

    pub(super) fn restore(&self) -> Result<bool> {
        if self.candidate.is_none() && self.prior.bytes.is_some() {
            let current = self.observe_retired_prior()?;
            if current.is_some() {
                return Ok(false);
            }
            let (directory, authority) = self.prior_directory()?;
            return directory.write(
                self.prior
                    .current
                    .path
                    .file_name()
                    .context("retained binding receipt has no name")?,
                self.prior
                    .bytes
                    .as_deref()
                    .context("retained binding bytes are absent")?,
                &authority,
                None,
            );
        }
        self.document()?.restore()
    }

    pub(super) fn verify_restored(&self) -> Result<()> {
        if self.candidate.is_none() && self.prior.bytes.is_some() {
            if self.observe_retired_prior()?.is_none() {
                bail!("retained binding receipt restoration is incomplete");
            }
            return Ok(());
        }
        self.document()?.verify_restored()
    }

    fn prior_directory(
        &self,
    ) -> Result<(
        dev_tools_installation::ExistingDocumentDirectory,
        DocumentAuthority,
    )> {
        let identity = self
            .prior
            .current
            .identity
            .as_ref()
            .context("retained binding receipt identity is absent")?;
        if identity.owner_uid != self.authority.owner_uid || !matches!(identity.mode, 0o600 | 0o644)
        {
            bail!("retained binding receipt has incompatible custody");
        }
        let mut authority = self.authority.clone();
        authority.mode = identity.mode;
        let directory =
            open_restoration_parent(&self.prior.current.path, self.authority.owner_uid)?
                .context("retained binding receipt parent is absent")?;
        Ok((directory, authority))
    }

    fn observe_retired_prior(&self) -> Result<Option<dev_tools_installation::AtomicDocument>> {
        let (directory, authority) = self.prior_directory()?;
        let current = directory.read(
            self.prior
                .current
                .path
                .file_name()
                .context("retained binding receipt has no name")?,
            &authority,
        )?;
        if current
            .as_ref()
            .is_some_and(|document| Some(document.bytes.as_slice()) != self.prior.bytes.as_deref())
        {
            bail!("binding receipt changed outside the retained restoration pair");
        }
        Ok(current)
    }
}

pub(super) fn binding_restorations(
    generation: &RetainedSetupGeneration,
) -> Result<Vec<BindingRestoration<'_>>> {
    let plan = &generation.plan;
    if plan.intent.schema != "dev-auth-deployment-intent-v3" {
        return Ok(Vec::new());
    }
    let prior_installation =
        retained_installation_receipts(generation)?.map(|(receipt, _)| receipt);
    let candidate_executable = plan
        .installation
        .paths
        .data_root
        .join("versions")
        .join(&plan.installation.request.version)
        .join("dev-auth");
    let mut restorations = Vec::new();
    for account in plan.accounts.iter().chain(&plan.retiring_accounts) {
        let prior = retained_object(generation, "binding_set_receipt", &account.name)?;
        let path = crate::binding_activation::native_receipt_path(
            plan.installation.request.mode,
            &account.home,
            account.uid,
        )?;
        if prior.current.path != path {
            bail!("retained binding receipt has an unexpected native destination");
        }
        let prior_set = prior
            .bytes
            .as_ref()
            .map(|bytes| {
                serde_json::from_slice::<crate::binding_activation::BindingSetReceipt>(bytes)
            })
            .transpose()
            .context("decode prior binding set receipt")?;
        if prior_set.is_some() != prior.current.identity.is_some()
            || (prior_set.is_some() && prior_installation.is_none())
        {
            bail!("retained binding receipt does not match prior installation authority");
        }
        let candidate = if plan
            .accounts
            .iter()
            .any(|active| active.name == account.name)
        {
            let plans =
                plan.intent
                    .bindings
                    .iter()
                    .filter(|binding| binding.user == account.name)
                    .map(|binding| {
                        let subject = format!("{}/{}", binding.user, binding.name);
                        let identity = document_identity(plan, "binding_plan", &subject)?;
                        serde_json::from_slice::<crate::smart_binding::BindingPlan>(
                            candidate_bytes(&generation.candidate_documents, identity)?,
                        )
                        .context("decode approved binding plan for restoration")
                    })
                    .collect::<Result<Vec<_>>>()?;
            let expected = crate::binding_activation::expected_desired_with_identity(
                account.uid,
                &candidate_executable,
                &plan.installation.source_sha256,
                prior_set.as_ref().zip(prior_installation.as_ref()),
                &plans,
            )?;
            if expected.bindings.is_empty() {
                None
            } else {
                Some(serde_jcs::to_vec(&expected)?)
            }
        } else {
            None
        };
        restorations.push(BindingRestoration {
            prior,
            candidate,
            authority: crate::binding_activation::authority(
                plan.installation.request.mode,
                account.uid,
            ),
        });
    }
    Ok(restorations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn removed_candidate_binding_receipt_restores_only_retained_prior_bytes() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("binding-set-v1.json");
        let bytes = b"retained prior binding receipt".to_vec();
        let owner_uid = fs::metadata(root.path()).unwrap().uid();
        let prior = RetainedSetupObject {
            current: CurrentPathIdentity {
                kind: "binding_set_receipt".into(),
                subject: "test-user".into(),
                path: path.clone(),
                identity: Some(CurrentFileIdentity {
                    object_type: "file".into(),
                    owner_uid,
                    mode: 0o600,
                    link_count: 1,
                    length: bytes.len() as u64,
                    sha256: sha256_hex(&bytes),
                    link_target: None,
                }),
            },
            bytes: Some(bytes.clone()),
        };
        let restoration = BindingRestoration {
            prior: &prior,
            candidate: None,
            authority: DocumentAuthority {
                owner_uid,
                mode: 0o600,
                limit: 1024 * 1024,
            },
        };
        restoration.observe().unwrap();
        assert!(restoration.restore().unwrap());
        restoration.verify_restored().unwrap();
        assert!(!restoration.restore().unwrap());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        fs::write(&path, b"foreign binding receipt").unwrap();
        assert!(restoration.observe().is_err());
    }
}
