use dev_tools_conformance::{
    audit_workspace_metadata, inspect_declared_stage, inspect_product, ProductDefinition,
    ProductLifecycle, ProductStandardStage, ProductUnderTest, WorkspaceDependencyFailure,
    PUBLIC_PRODUCTS,
};
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn public_product_inventory_is_explicit_and_release_admin_is_planned() {
    let products = PUBLIC_PRODUCTS
        .iter()
        .map(|product| (product.name, product.lifecycle, product.standard_stage))
        .collect::<Vec<_>>();
    assert_eq!(
        products,
        vec![
            (
                "update-all",
                ProductLifecycle::Current,
                ProductStandardStage::BuildInfo,
            ),
            (
                "dev-auth",
                ProductLifecycle::Current,
                ProductStandardStage::Inventory,
            ),
            (
                "dev-cache",
                ProductLifecycle::Current,
                ProductStandardStage::BuildInfo,
            ),
            (
                "sync-configs",
                ProductLifecycle::Current,
                ProductStandardStage::BuildInfo,
            ),
            (
                "skills-sync",
                ProductLifecycle::Current,
                ProductStandardStage::BuildInfo,
            ),
            (
                "release-admin",
                ProductLifecycle::Planned,
                ProductStandardStage::Inventory,
            ),
        ]
    );
}

#[test]
fn standalone_fixture_satisfies_the_common_local_contract() {
    let sandbox = tempfile::tempdir().expect("sandbox");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_conformance-fixture"));
    let definition = ProductDefinition {
        name: "demo-tool",
        lifecycle: ProductLifecycle::Current,
        standard_stage: ProductStandardStage::Full,
    };
    let subject = ProductUnderTest::new(definition, executable, sandbox.path())
        .expect("valid conformance subject");

    let report = inspect_product(&subject).expect("run local conformance checks");

    assert!(report.is_conformant(), "{report:#?}");
    assert_eq!(report.product, "demo-tool");
    assert_eq!(report.version.as_deref(), Some("1.2.3"));
    assert_eq!(report.checks.len(), 10);
    assert!(report.checks.iter().all(|check| check.passed));
}

#[test]
fn build_info_stage_checks_only_local_identity_contracts() {
    let sandbox = tempfile::tempdir().expect("sandbox");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_conformance-fixture"));
    let definition = ProductDefinition {
        name: "demo-tool",
        lifecycle: ProductLifecycle::Current,
        standard_stage: ProductStandardStage::BuildInfo,
    };
    let subject = ProductUnderTest::new(definition, executable, sandbox.path())
        .expect("valid conformance subject");

    let report = inspect_declared_stage(&subject).expect("run declared checks");

    assert!(report.passed_declared_stage(), "{report:#?}");
    assert!(!report.is_conformant());
    assert_eq!(report.checks.len(), 2);
    assert_eq!(report.checks[0].name, "version");
    assert_eq!(report.checks[1].name, "build_info");
}

#[test]
fn workspace_dependency_direction_is_enforced_from_cargo_metadata() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .canonicalize()
        .expect("canonical workspace root");
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps", "--locked"])
        .current_dir(&workspace)
        .output()
        .expect("run cargo metadata");
    assert!(output.status.success(), "cargo metadata failed");

    let report = audit_workspace_metadata(&workspace, &output.stdout).expect("audit metadata");

    assert!(report.is_conformant(), "{report:#?}");
    assert_eq!(report.workspace_package_count, 12);
    assert!(report.failures.is_empty());
}

#[test]
fn dependency_audit_rejects_external_paths_and_product_runtime_coupling() {
    let workspace = Path::new("/workspace");
    let metadata = br#"{
      "packages": [
        {
          "name": "update-all",
          "manifest_path": "/workspace/crates/update-all/Cargo.toml",
          "dependencies": [
            {"name": "dev-cache", "path": "/workspace/crates/dev-cache"},
            {"name": "private-policy", "path": "/private/policy"}
          ]
        },
        {
          "name": "dev-cache",
          "manifest_path": "/workspace/crates/dev-cache/Cargo.toml",
          "dependencies": []
        }
      ],
      "workspace_members": ["update-all 0.1.0 (path+file:///workspace/crates/update-all)", "dev-cache 0.1.0 (path+file:///workspace/crates/dev-cache)"]
    }"#;

    let report = audit_workspace_metadata(workspace, metadata).expect("audit metadata");

    assert_eq!(
        report.failures,
        vec![
            WorkspaceDependencyFailure::ExternalPathDependency,
            WorkspaceDependencyFailure::ProductRuntimeCoupling,
        ]
    );
}
