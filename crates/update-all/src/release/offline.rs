//! Explicit local signed bytes for the existing product installation authority.
//! No URL is fetched and local admission never advances online-check freshness.
use super::*;

#[derive(Debug)]
pub(crate) struct OfflineBundlePaths {
    pub root_document: PathBuf,
    pub manifest: PathBuf,
    pub artifact: PathBuf,
}

pub(crate) fn install(product: Product, bundle: &OfflineBundlePaths) -> Result<Activation> {
    validate_paths(bundle)?;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let paths = Paths::resolve(product)?;
        let mut authority = release_authority(product);
        // New local intake never widens the bounded online legacy exception.
        authority.accepted_manifest_schemas = vec!["dev-tools-product-v2".into()];
        authority.require_source_commit = true;
        install_with_authority(product, &paths, bundle, &authority)
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        bail!("offline signed-bundle installation is unsupported on this runtime")
    }
}

fn validate_paths(bundle: &OfflineBundlePaths) -> Result<()> {
    for path in [&bundle.root_document, &bundle.manifest, &bundle.artifact] {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            bail!("offline release bundle paths must be absolute without parent traversal");
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn current_uid() -> u32 {
    // SAFETY: geteuid has no arguments, borrowed memory or failure state.
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid()
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read_input(path: &Path, limit: u64, uid: u32) -> Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    // The shared reader traverses every component by nofollow descriptors.
    // These policy checks additionally reject foreign/writable authority.
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent).context("inspect offline input parent")?;
        let root_sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || (metadata.mode() & 0o022 != 0 && !root_sticky)
        {
            bail!("offline release input parent has unsafe filesystem authority");
        }
    }
    let metadata = fs::symlink_metadata(path).context("inspect offline release input")?;
    if !metadata.is_file()
        || (metadata.uid() != uid && metadata.uid() != 0)
        || metadata.nlink() != 1
        || metadata.mode() & 0o7022 != 0
    {
        bail!("offline release input has unsafe filesystem authority");
    }
    Ok(dev_tools_installation::read_atomic_document(
        path,
        &dev_tools_installation::DocumentAuthority {
            owner_uid: metadata.uid(),
            mode: metadata.mode() & 0o777,
            limit,
        },
    )?
    .context("offline release input disappeared")?
    .bytes)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn install_with_authority(
    product: Product,
    paths: &Paths,
    bundle: &OfflineBundlePaths,
    authority: &ReleaseAuthority,
) -> Result<Activation> {
    validate_paths(bundle)?;
    if classify_install(product, paths)? == InstallClassification::External {
        return Ok(externally_managed(product, paths));
    }
    require_current_runtime(product)?;
    prepare(product, paths, bundle, authority)?.activate()
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct Prepared<'a> {
    product: Product,
    paths: &'a Paths,
    writer: ReleaseStateWriter<'a>,
    state: ReleaseState,
    verified: VerifiedManifest,
    cached_artifact: PathBuf,
    recovered: bool,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn prepare<'a>(
    product: Product,
    paths: &'a Paths,
    bundle: &OfflineBundlePaths,
    authority: &ReleaseAuthority,
) -> Result<Prepared<'a>> {
    load_state(paths)?;
    let uid = current_uid();
    if state_document_authority(paths)?.owner_uid != uid {
        bail!("offline installation root must belong to the invoking user");
    }
    // The legacy lock primitive can create its parent with public directory
    // mode. Establish the product's private root first without adopting or
    // chmodding an existing collision.
    let layout = shared_installation_layout(product, paths)?;
    dev_tools_installation::ensure_owned_directory(&layout.data_root, uid, layout.directory_mode)?;
    let (writer, mut state) = ReleaseStateWriter::begin(paths)?;
    let classification = classify_install(product, paths)?;
    if classification == InstallClassification::External {
        bail!("offline installation became externally managed before admission");
    }
    let mut prior_installation = classification == InstallClassification::Managed;
    for path in [
        &paths.versions,
        &paths.current,
        &paths.product_root.join("active"),
        &paths.product_root.join("previous"),
    ] {
        prior_installation |=
            path_entry_present(path, "inspect prior offline installation authority")?;
    }
    if prior_installation
        && (writer.expected.is_none()
            || state.accepted_root_generation == 0
            || state.accepted_generation == 0
            || state.accepted_version.is_none()
            || !state.accepted_root_sha256.as_deref().is_some_and(is_sha256)
            || !state
                .accepted_manifest_sha256
                .as_deref()
                .is_some_and(is_sha256)
            || !state
                .accepted_binary_sha256
                .as_deref()
                .is_some_and(is_sha256))
    {
        return managed_legacy_missing_authority();
    }
    let metadata = ReleaseMetadata {
        root: read_input(&bundle.root_document, METADATA_LIMIT, uid)?,
        manifest: read_input(&bundle.manifest, METADATA_LIMIT, uid)?,
    };
    let artifact = read_input(&bundle.artifact, ARTIFACT_LIMIT, uid)?;
    let shared = dev_tools_release::verify_release_metadata(&metadata, authority)
        .and_then(|verified| {
            dev_tools_release::verify_artifact_bytes(&verified, &artifact)?;
            Ok(verified)
        })
        .map_err(|error| {
            IntegrityFailure(format!("offline release authentication failed: {error:#}"))
        })?;
    if !shared.version.pre.is_empty() {
        return integrity("offline release bundle must identify a stable version");
    }
    let verified = project_verified_manifest(shared);
    // Reject rollback/equivocation before installation recovery or execution.
    let mut accepted = state.clone();
    accept_manifest_metadata(&mut accepted, &verified)?;
    shared_installation_layout(product, paths)?;
    // Cache entries are immutable. Different signed metadata for the same
    // version has its own root so legitimate metadata-only advancement works.
    let cache_root = paths
        .product_root
        .join("cache/offline-bundles")
        .join(format!(
            "{}-{}",
            verified.root_sha256, verified.manifest_sha256
        ));
    dev_tools_installation::ensure_owned_directory(&cache_root, uid, 0o700)?;
    let cached = dev_tools_release::cache_verified_release(
        &cache_root,
        authority,
        &metadata,
        &artifact,
        uid,
    )?;
    let prior_active = (state.active_version.clone(), state.previous_version.clone());
    let recovered = adopt_legacy_installation(product, paths, &mut state)?;
    let recovered =
        recovered || prior_active != (state.active_version.clone(), state.previous_version.clone());
    accept_manifest_metadata(&mut state, &verified)?;
    // Installation and accepted history are distinct authorities. Commit
    // monotonic history first under the same lease, so interruption cannot
    // leave an activated candidate with forgotten anti-rollback acceptance.
    let writer = writer.save_and_continue(&state)?;
    Ok(Prepared {
        product,
        paths,
        writer,
        state,
        verified,
        cached_artifact: cached.artifact_path,
        recovered,
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Prepared<'_> {
    fn activate(mut self) -> Result<Activation> {
        let mut activation = activate_verified_source(
            self.product,
            self.paths,
            &mut self.state,
            &self.verified,
            &self.cached_artifact,
        )?;
        if self.recovered {
            activation.changed = true;
            activation.outcome = "updated".into();
        }
        self.writer.save(&self.state)?;
        Ok(activation)
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;
