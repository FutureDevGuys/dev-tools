//! Product-owned, one-release signer bootstrap. Not a shared trust primitive.
use anyhow::{bail, Result};
use dev_tools_release::ProductManifestSpec;

pub(super) fn construct(spec: &ProductManifestSpec) -> Result<Vec<u8>> {
    let bytes = dev_tools_release::build_unsigned_product_manifest(spec)?;
    if spec.product != "dev-auth" || spec.version != "0.3.11" {
        return Ok(bytes);
    }
    if spec.artifacts.len() != 1 {
        bail!("Dev Auth signer bootstrap requires exactly one target");
    }
    let mut document: serde_json::Value = serde_json::from_slice(&bytes)?;
    document["schema"] = "dev-auth-product-v2".into();
    let bytes = serde_jcs::to_vec(&document)?;
    dev_tools_release::validate_unsigned_product_manifest(&bytes)?;
    Ok(bytes)
}

pub(super) fn accepted_schemas(product: &str) -> Vec<String> {
    let mut schemas = vec!["dev-tools-product-v2".into()];
    if product == "dev-auth" {
        schemas.push("dev-auth-product-v2".into());
    }
    schemas
}

pub(super) fn require_publishable(product: &str, version: &str, schema: &str) -> Result<()> {
    if schema == "dev-tools-product-v2"
        || (product == "dev-auth" && version == "0.3.11" && schema == "dev-auth-product-v2")
    {
        Ok(())
    } else {
        bail!("product manifest has an unsupported publication contract outside the one-release signer bootstrap policy")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dev_tools_release::ManifestArtifact;

    #[test]
    fn legacy_publication_is_limited_to_exact_bootstrap_identity() {
        assert!(require_publishable("dev-auth", "0.3.11", "dev-auth-product-v2").is_ok());
        for (product, version, schema) in [
            ("dev-auth", "0.3.10", "dev-auth-product-v2"),
            ("dev-auth", "0.3.12", "dev-auth-product-v2"),
            ("dev-auth", "0.3.11+other", "dev-auth-product-v2"),
            ("update-all", "0.3.11", "dev-auth-product-v2"),
            ("dev-auth", "0.3.11", "dev-tools-product-v1"),
        ] {
            assert!(require_publishable(product, version, schema).is_err());
        }
    }

    #[test]
    fn only_dev_auth_0311_uses_the_source_bound_bootstrap_format() {
        for (product, version, schema) in [
            ("dev-auth", "0.3.11", "dev-auth-product-v2"),
            ("dev-auth", "0.3.12", "dev-tools-product-v2"),
            ("dev-auth", "0.3.10", "dev-tools-product-v2"),
            ("update-all", "0.3.11", "dev-tools-product-v2"),
        ] {
            let spec = ProductManifestSpec {
                product: product.into(), version: version.into(), generation: 31,
                source_commit: "a".repeat(40),
                artifacts: vec![ManifestArtifact {
                    target: "linux-x86_64".into(),
                    url: format!("https://github.com/FutureDevGuys/dev-tools/releases/download/{product}%2Fv{version}/{product}-{version}-linux-x86_64"),
                    length: 10, sha256: "b".repeat(64),
                }],
            };
            let bytes = construct(&spec).unwrap();
            let identity = dev_tools_release::validate_unsigned_product_manifest(&bytes).unwrap();
            assert_eq!(identity.schema, schema);
            let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                document["source_commit"].as_str(),
                Some(spec.source_commit.as_str())
            );
        }
    }
}
