use assert_cmd::Command;
#[cfg(unix)]
use base64::engine::general_purpose::STANDARD as BASE64;
#[cfg(unix)]
use base64::Engine as _;
#[cfg(unix)]
use dev_tools_release::{
    build_signed_envelope, build_unsigned_crate_set, build_unsigned_product_manifest,
    build_unsigned_root_document, release_key_id, root_key_id, verify_crate_package_bytes,
    verify_crate_set_metadata, verify_release_bytes, verify_root_bytes, ArtifactUrlPolicy,
    CratePackageSpec, CrateSetAuthority, CrateSetMetadata, CrateSetSpec, EnvelopeSignature,
    ManifestArtifact, ProductManifestSpec, ReleaseAuthority, ReleaseBundle, RootDocumentSpec,
    RootReleaseKey,
};
#[cfg(unix)]
use ed25519_dalek::{Signer, SigningKey};
use predicates::prelude::*;
#[cfg(unix)]
use serde_json::json;
#[cfg(unix)]
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "linux")]
use std::process::Command as ProcessCommand;

#[test]
fn exposes_common_identity_without_loading_release_inputs() {
    Command::cargo_bin("release-admin")
        .expect("release-admin binary")
        .arg("--version")
        .assert()
        .success()
        .stdout("release-admin 0.1.0\n")
        .stderr("");

    let output = Command::cargo_bin("release-admin")
        .expect("release-admin binary")
        .args(["build-info", "--json"])
        .output()
        .expect("run build-info");
    assert!(output.status.success(), "build-info failed");
    assert!(output.stderr.is_empty(), "build-info wrote diagnostics");
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("build-info JSON");
    assert_eq!(payload["schema"], "dev-tools-build-info-v1");
    assert_eq!(payload["product"], "release-admin");
    assert_eq!(payload["version"], "0.1.0");
}

#[test]
fn help_exposes_only_native_typed_release_operations() {
    Command::cargo_bin("release-admin")
        .expect("release-admin binary")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("root"))
        .stdout(predicate::str::contains("manifest"))
        .stdout(predicate::str::contains("crate-set"))
        .stdout(predicate::str::contains("set"))
        .stdout(predicate::str::contains("publish").not())
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("build-info"));

    Command::cargo_bin("release-admin")
        .expect("release-admin binary")
        .args(["crate-set", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("verify-registry"))
        .stdout(predicate::str::contains("bootstrap-publish"));

    Command::cargo_bin("release-admin")
        .expect("release-admin binary")
        .args(["set", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("build"))
        .stdout(predicate::str::contains("compare"))
        .stdout(predicate::str::contains("publish"));
}

#[cfg(unix)]
#[test]
fn set_compare_requires_two_exact_owner_private_byte_identical_trees() {
    let root = tempfile::tempdir().expect("root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let first = root.path().join("first");
    let second = root.path().join("second");
    for candidate in [&first, &second] {
        fs::create_dir(candidate).unwrap();
        fs::set_permissions(candidate, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(candidate.join("releases")).unwrap();
        fs::set_permissions(
            candidate.join("releases"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::write(candidate.join("releases/manifest.json"), b"signed\n").unwrap();
        fs::set_permissions(
            candidate.join("releases/manifest.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }

    let output = Command::cargo_bin("release-admin")
        .unwrap()
        .args(["set", "compare"])
        .args(["--first", first.to_str().unwrap()])
        .args(["--second", second.to_str().unwrap()])
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "comparison failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["schema"], "release-admin-set-compare-v1");
    assert_eq!(result["identical"], true);
    assert_eq!(result["files"], 1);
    assert_eq!(result["bytes"], 7);

    fs::write(second.join("releases/manifest.json"), b"changed\n").unwrap();
    Command::cargo_bin("release-admin")
        .unwrap()
        .args(["set", "compare"])
        .args(["--first", first.to_str().unwrap()])
        .args(["--second", second.to_str().unwrap()])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains(
            "release-set candidates are not byte-identical",
        ));

    fs::write(second.join("releases/manifest.json"), b"signed\n").unwrap();
    fs::set_permissions(
        second.join("releases/manifest.json"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    Command::cargo_bin("release-admin")
        .unwrap()
        .args(["set", "compare"])
        .args(["--first", first.to_str().unwrap()])
        .args(["--second", second.to_str().unwrap()])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains(
            "release-set candidates are not byte-identical",
        ));

    fs::set_permissions(
        second.join("releases/manifest.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::create_dir(second.join("releases/empty")).unwrap();
    fs::set_permissions(
        second.join("releases/empty"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    Command::cargo_bin("release-admin")
        .unwrap()
        .args(["set", "compare"])
        .args(["--first", first.to_str().unwrap()])
        .args(["--second", second.to_str().unwrap()])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains(
            "release-set candidates are not byte-identical",
        ));

    fs::remove_dir(second.join("releases/empty")).unwrap();
    fs::set_permissions(
        second.join("releases/manifest.json"),
        fs::Permissions::from_mode(0o4600),
    )
    .unwrap();
    Command::cargo_bin("release-admin")
        .unwrap()
        .args(["set", "compare"])
        .args(["--first", first.to_str().unwrap()])
        .args(["--second", second.to_str().unwrap()])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains(
            "release-set entry has unsafe filesystem authority",
        ));
}

#[cfg(target_os = "linux")]
#[test]
fn set_build_constructs_one_exact_source_bound_release_without_python() {
    let root = tempfile::tempdir().expect("root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let source = root.path().join("source");
    fs::create_dir_all(source.join("crates/update-all")).unwrap();
    fs::write(
        source.join("crates/update-all/Cargo.toml"),
        "[package]\nname = \"update-all\"\nversion = \"1.2.3\"\nedition = \"2021\"\n",
    )
    .unwrap();
    git(&source, &["init", "--quiet"]);
    git(&source, &["config", "user.name", "release test"]);
    git(
        &source,
        &["config", "user.email", "release@example.invalid"],
    );
    git(&source, &["add", "crates/update-all/Cargo.toml"]);
    git(&source, &["commit", "--quiet", "-m", "fixture"]);
    let source_commit = git_output(&source, &["rev-parse", "HEAD"]);

    let cargo_home = root.path().join("cargo-home");
    fs::create_dir(&cargo_home).unwrap();
    fs::set_permissions(&cargo_home, fs::Permissions::from_mode(0o700)).unwrap();
    let fake_cargo = root.path().join("cargo");
    fs::write(
        &fake_cargo,
        "#!/bin/sh\nset -eu\nmkdir -p \"$CARGO_TARGET_DIR/release\"\nprintf 'native release\\n' >\"$CARGO_TARGET_DIR/release/update-all\"\n",
    )
    .unwrap();
    fs::set_permissions(&fake_cargo, fs::Permissions::from_mode(0o755)).unwrap();

    let root_key = SigningKey::from_bytes(&[7; 32]);
    let release_key = SigningKey::from_bytes(&[9; 32]);
    let release_id = release_key_id(&hex(&release_key.verifying_key().to_bytes())).unwrap();
    let unsigned_root = build_unsigned_root_document(&RootDocumentSpec {
        generation: 1,
        release_keys: vec![RootReleaseKey {
            public_key: hex(&release_key.verifying_key().to_bytes()),
            revoked: false,
        }],
    })
    .unwrap();
    let root_document = build_signed_envelope(
        &unsigned_root,
        &[EnvelopeSignature {
            key_id: root_key_id(&hex(&root_key.verifying_key().to_bytes())).unwrap(),
            signature: root_key.sign(&unsigned_root).to_bytes().to_vec(),
        }],
    )
    .unwrap();
    let root_path = root.path().join("root.json");
    fs::write(&root_path, &root_document).unwrap();
    let trusted_root = root.path().join("root-public-key.txt");
    fs::write(
        &trusted_root,
        format!("{}\n", hex(&root_key.verifying_key().to_bytes())),
    )
    .unwrap();

    let artifact_fixture = root.path().join("artifact-fixture");
    fs::write(&artifact_fixture, b"native release\n").unwrap();
    let unsigned_manifest = build_unsigned_product_manifest(&ProductManifestSpec {
        product: "update-all".into(),
        generation: 7,
        version: "1.2.3".into(),
        source_commit: source_commit.clone(),
        artifacts: vec![manifest_artifact(
            "update-all",
            "1.2.3",
            "linux-x86_64",
            &artifact_fixture,
        )],
    })
    .unwrap();
    let signer_marker = root.path().join("signer-count");
    let signer = root.path().join("signer");
    fs::write(
        &signer,
        format!(
            "#!/bin/sh\nset -eu\n[ \"$1\" = sign-release-manifest ]\n[ \"$2\" = --profile ]\n[ \"$3\" = source-maintenance ]\ncat >/dev/null\nprintf x >>'{}'\nprintf '%s\\n' '{}'\n",
            signer_marker.display(),
            BASE64.encode(release_key.sign(&unsigned_manifest).to_bytes())
        ),
    )
    .unwrap();
    fs::set_permissions(&signer, fs::Permissions::from_mode(0o755)).unwrap();
    let output = root.path().join("release-set");

    let result = Command::cargo_bin("release-admin")
        .unwrap()
        .args(["set", "build"])
        .args(["--source-root", source.to_str().unwrap()])
        .args(["--source-commit", &source_commit])
        .args(["--git", "/usr/bin/git"])
        .args(["--cargo", fake_cargo.to_str().unwrap()])
        .args(["--cargo-home", cargo_home.to_str().unwrap()])
        .args(["--target", "linux-x86_64"])
        .args(["--product", "update-all"])
        .args(["--manifest-generation", "update-all=7"])
        .args(["--root-document", root_path.to_str().unwrap()])
        .args(["--trusted-root-public-key", trusted_root.to_str().unwrap()])
        .args(["--release-key-id", &release_id])
        .args(["--signer", signer.to_str().unwrap()])
        .args(["--signer-profile", "source-maintenance"])
        .args(["--output", output.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "set build failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stderr.is_empty());
    let summary: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(summary["schema"], "release-admin-set-build-v1");
    assert_eq!(summary["source_commit"], source_commit);
    assert_eq!(summary["controlled_build"], true);
    assert!(summary.get("reproducible_input").is_none());
    assert_eq!(summary["products"].as_array().unwrap().len(), 1);
    assert_eq!(fs::read(&signer_marker).unwrap(), b"x");

    let product = output.join("releases/update-all");
    let artifact = product.join("update-all-1.2.3-linux-x86_64");
    let verified = verify_release_bytes(
        &ReleaseBundle {
            root: fs::read(product.join("dev-tools-root.json")).unwrap(),
            manifest: fs::read(product.join("update-all-stable.json")).unwrap(),
            artifact: fs::read(&artifact).unwrap(),
        },
        &ReleaseAuthority {
            trusted_root_key: hex(&root_key.verifying_key().to_bytes()),
            product: "update-all".into(),
            accepted_manifest_schemas: vec!["dev-tools-product-v2".into()],
            target: "linux-x86_64".into(),
            artifact_url: ArtifactUrlPolicy::GitHubRelease {
                owner: "FutureDevGuys".into(),
                repository: "dev-tools".into(),
            },
            require_source_commit: true,
            engine_protocol: 1,
        },
    )
    .unwrap();
    assert_eq!(
        verified.source_commit.as_deref(),
        Some(source_commit.as_str())
    );
    assert_eq!(fs::read(&artifact).unwrap(), b"native release\n");
    assert!(!output.join("build").exists());
    assert!(git_output(&source, &["status", "--porcelain"]).is_empty());

    let second_output = root.path().join("release-set-second");
    Command::cargo_bin("release-admin")
        .unwrap()
        .args(["set", "build"])
        .args(["--source-root", source.to_str().unwrap()])
        .args(["--source-commit", &source_commit])
        .args(["--git", "/usr/bin/git"])
        .args(["--cargo", fake_cargo.to_str().unwrap()])
        .args(["--cargo-home", cargo_home.to_str().unwrap()])
        .args(["--target", "linux-x86_64"])
        .args(["--product", "update-all"])
        .args(["--manifest-generation", "update-all=7"])
        .args(["--root-document", root_path.to_str().unwrap()])
        .args(["--trusted-root-public-key", trusted_root.to_str().unwrap()])
        .args(["--release-key-id", &release_id])
        .args(["--signer", signer.to_str().unwrap()])
        .args(["--signer-profile", "source-maintenance"])
        .args(["--output", second_output.to_str().unwrap()])
        .assert()
        .success()
        .stderr("");
    assert_eq!(fs::read(&signer_marker).unwrap(), b"xx");
    for name in [
        "dev-tools-root.json",
        "update-all-stable.json",
        "update-all-1.2.3-linux-x86_64",
    ] {
        assert_eq!(
            fs::read(output.join("releases/update-all").join(name)).unwrap(),
            fs::read(second_output.join("releases/update-all").join(name)).unwrap(),
            "independent release bytes differ for {name}"
        );
    }
}

#[test]
fn cargo_credential_plugin_fails_closed_without_echoing_input() {
    Command::cargo_bin("release-admin")
        .expect("release-admin binary")
        .arg("--cargo-plugin")
        .write_stdin("do-not-echo-this\n")
        .assert()
        .failure()
        .stdout(predicate::str::starts_with("{\"v\":[1]}\n"))
        .stdout(predicate::str::contains(
            "registry publication authority denied",
        ))
        .stdout(predicate::str::contains("do-not-echo-this").not())
        .stderr("");
}

#[cfg(target_os = "linux")]
#[test]
fn crate_set_build_and_verify_use_one_operation_only_signer_and_exact_package_bytes() {
    let root = tempfile::tempdir().expect("root");
    let root_key = SigningKey::from_bytes(&[7; 32]);
    let release_key = SigningKey::from_bytes(&[9; 32]);
    let release_id = release_key_id(&hex(&release_key.verifying_key().to_bytes())).unwrap();
    let unsigned_root = build_unsigned_root_document(&RootDocumentSpec {
        generation: 1,
        release_keys: vec![RootReleaseKey {
            public_key: hex(&release_key.verifying_key().to_bytes()),
            revoked: false,
        }],
    })
    .unwrap();
    let root_document = build_signed_envelope(
        &unsigned_root,
        &[EnvelopeSignature {
            key_id: root_key_id(&hex(&root_key.verifying_key().to_bytes())).unwrap(),
            signature: root_key.sign(&unsigned_root).to_bytes().to_vec(),
        }],
    )
    .unwrap();
    let root_path = root.path().join("root.json");
    fs::write(&root_path, &root_document).unwrap();
    let trusted_root = root.path().join("root-public-key.txt");
    fs::write(
        &trusted_root,
        format!("{}\n", hex(&root_key.verifying_key().to_bytes())),
    )
    .unwrap();
    let source_commit = "d".repeat(40);
    let package = root.path().join("dev-tools-command-0.1.0.crate");
    write_crate_archive(
        &package,
        "dev-tools-command",
        "0.1.0",
        &source_commit,
        b"pub fn command() {}\n",
    );
    let package_bytes = fs::read(&package).unwrap();
    let unsigned = build_unsigned_crate_set(&CrateSetSpec {
        generation: 1,
        source_commit: source_commit.clone(),
        registry: "crates-io".into(),
        packages: vec![CratePackageSpec {
            name: "dev-tools-command".into(),
            version: "0.1.0".into(),
            length: package_bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(&package_bytes)),
        }],
    })
    .unwrap();
    let signature = BASE64.encode(release_key.sign(&unsigned).to_bytes());
    let signer_marker = root.path().join("signer-count");
    let signer = root.path().join("signer");
    fs::write(
        &signer,
        format!(
            "#!/bin/sh\n[ \"$1\" = sign-release-manifest ] || exit 2\n[ \"$2\" = --profile ] || exit 2\n[ \"$3\" = source-maintenance ] || exit 2\ncat >/dev/null\nprintf x >> '{}'\nprintf '%s\\n' '{}'\n",
            signer_marker.display(), signature
        ),
    )
    .unwrap();
    fs::set_permissions(&signer, fs::Permissions::from_mode(0o755)).unwrap();
    let output = root.path().join("shared-crates.json");
    let package_argument = format!("dev-tools-command@0.1.0={}", package.display());

    Command::cargo_bin("release-admin")
        .unwrap()
        .args(["crate-set", "build"])
        .args(["--source-commit", &source_commit, "--generation", "1"])
        .args(["--package", &package_argument])
        .args(["--root-document", root_path.to_str().unwrap()])
        .args(["--trusted-root-public-key", trusted_root.to_str().unwrap()])
        .args(["--release-key-id", &release_id])
        .args(["--signer", signer.to_str().unwrap()])
        .args(["--signer-profile", "source-maintenance"])
        .args(["--output", output.to_str().unwrap()])
        .assert()
        .success()
        .stderr("");
    assert_eq!(fs::read(&signer_marker).unwrap(), b"x");

    let verified = verify_crate_set_metadata(
        &CrateSetMetadata {
            root: root_document,
            manifest: fs::read(&output).unwrap(),
        },
        &CrateSetAuthority {
            trusted_root_key: hex(&root_key.verifying_key().to_bytes()),
            registry: "crates-io".into(),
            source_commit: source_commit.clone(),
        },
    )
    .unwrap();
    verify_crate_package_bytes(
        &verified,
        "dev-tools-command",
        "0.1.0",
        &fs::read(&package).unwrap(),
    )
    .unwrap();

    Command::cargo_bin("release-admin")
        .unwrap()
        .args(["crate-set", "verify"])
        .args(["--source-commit", &source_commit])
        .args(["--package", &package_argument])
        .args(["--root-document", root_path.to_str().unwrap()])
        .args(["--manifest", output.to_str().unwrap()])
        .args(["--trusted-root-public-key", trusted_root.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"packages\":1"))
        .stderr("");
}

#[cfg(target_os = "linux")]
#[test]
fn crate_set_build_rejects_mislabeled_archive_before_invoking_the_signer() {
    let root = tempfile::tempdir().unwrap();
    let package = root.path().join("dev-tools-command-0.1.0.crate");
    let source_commit = "d".repeat(40);
    write_crate_archive(
        &package,
        "different-package",
        "0.1.0",
        &source_commit,
        b"pub fn wrong() {}\n",
    );
    let signer = root.path().join("signer");
    let marker = root.path().join("signer-ran");
    fs::write(
        &signer,
        format!("#!/bin/sh\ntouch '{}'\nexit 2\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&signer, fs::Permissions::from_mode(0o755)).unwrap();
    let root_key = SigningKey::from_bytes(&[7; 32]);
    let release_key = SigningKey::from_bytes(&[9; 32]);
    let release_id = release_key_id(&hex(&release_key.verifying_key().to_bytes())).unwrap();
    let unsigned_root = build_unsigned_root_document(&RootDocumentSpec {
        generation: 1,
        release_keys: vec![RootReleaseKey {
            public_key: hex(&release_key.verifying_key().to_bytes()),
            revoked: false,
        }],
    })
    .unwrap();
    let root_document = build_signed_envelope(
        &unsigned_root,
        &[EnvelopeSignature {
            key_id: root_key_id(&hex(&root_key.verifying_key().to_bytes())).unwrap(),
            signature: root_key.sign(&unsigned_root).to_bytes().to_vec(),
        }],
    )
    .unwrap();
    let root_path = root.path().join("root.json");
    fs::write(&root_path, root_document).unwrap();
    let trusted_root = root.path().join("root-public-key.txt");
    fs::write(
        &trusted_root,
        format!("{}\n", hex(&root_key.verifying_key().to_bytes())),
    )
    .unwrap();

    Command::cargo_bin("release-admin")
        .unwrap()
        .args(["crate-set", "build"])
        .args(["--source-commit", &source_commit, "--generation", "1"])
        .args([
            "--package",
            &format!("dev-tools-command@0.1.0={}", package.display()),
        ])
        .args(["--root-document", root_path.to_str().unwrap()])
        .args(["--trusted-root-public-key", trusted_root.to_str().unwrap()])
        .args(["--release-key-id", &release_id])
        .args(["--signer", signer.to_str().unwrap()])
        .args(["--signer-profile", "source-maintenance"])
        .args(["--output", root.path().join("set.json").to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("crate archive package identity"));
    assert!(!marker.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn crate_set_package_reproduces_exact_clean_commit_bytes_twice() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let (source, source_commit) = write_git_crate_fixture(root.path());

    let fixture = root.path().join("fixture.crate");
    write_crate_archive(
        &fixture,
        "dev-tools-command",
        "0.1.0",
        &source_commit,
        b"pub fn command() {}\n",
    );
    let marker = root.path().join("cargo-count");
    let cargo = root.path().join("cargo");
    fs::write(
        &cargo,
        format!(
            "#!/bin/sh\nset -eu\ntarget=\npackage=\nwhile [ \"$#\" -gt 0 ]; do\n  case \"$1\" in\n    --target-dir) target=$2; shift 2 ;;\n    --package) package=$2; shift 2 ;;\n    *) shift ;;\n  esac\ndone\n[ \"$package\" = dev-tools-command ]\nmkdir -p \"$target/package\"\ncp '{}' \"$target/package/dev-tools-command-0.1.0.crate\"\nprintf x >> '{}'\n",
            fixture.display(),
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
    let cargo_home = root.path().join("cargo-home");
    fs::create_dir(&cargo_home).unwrap();
    let output = root.path().join("packages");

    Command::cargo_bin("release-admin")
        .unwrap()
        .args(["crate-set", "package"])
        .args(["--source-root", source.to_str().unwrap()])
        .args(["--source-commit", &source_commit])
        .args(["--git", "/usr/bin/git"])
        .args(["--cargo", cargo.to_str().unwrap()])
        .args(["--cargo-home", cargo_home.to_str().unwrap()])
        .args(["--package", "dev-tools-command@0.1.0"])
        .args(["--output", output.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "\"schema\":\"release-admin-crate-package-v1\"",
        ))
        .stderr("");

    assert_eq!(fs::read(&marker).unwrap(), b"xx");
    assert_eq!(
        fs::read(output.join("dev-tools-command-0.1.0.crate")).unwrap(),
        fs::read(&fixture).unwrap()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn crate_set_package_rejects_a_dirty_source_before_running_cargo() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let (source, source_commit) = write_git_crate_fixture(root.path());
    fs::write(source.join("untracked"), "dirty\n").unwrap();
    let marker = root.path().join("cargo-ran");
    let cargo = root.path().join("cargo");
    fs::write(
        &cargo,
        format!("#!/bin/sh\ntouch '{}'\nexit 92\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
    let cargo_home = root.path().join("cargo-home");
    fs::create_dir(&cargo_home).unwrap();

    Command::cargo_bin("release-admin")
        .unwrap()
        .args(["crate-set", "package"])
        .args(["--source-root", source.to_str().unwrap()])
        .args(["--source-commit", &source_commit])
        .args(["--git", "/usr/bin/git"])
        .args(["--cargo", cargo.to_str().unwrap()])
        .args(["--cargo-home", cargo_home.to_str().unwrap()])
        .args(["--package", "dev-tools-command@0.1.0"])
        .args(["--output", root.path().join("packages").to_str().unwrap()])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("source checkout is not clean"));
    assert!(!marker.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn crate_set_package_rejects_a_committed_symlink_before_running_cargo() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let (source, _) = write_git_crate_fixture(root.path());
    let outside = root.path().join("outside.rs");
    fs::write(&outside, "pub fn injected() {}\n").unwrap();
    std::os::unix::fs::symlink(&outside, source.join("src/injected.rs")).unwrap();
    git(&source, &["add", "src/injected.rs"]);
    git(&source, &["commit", "--quiet", "-m", "linked fixture"]);
    let source_commit = git_output(&source, &["rev-parse", "HEAD"]);
    let marker = root.path().join("cargo-ran");
    let cargo = root.path().join("cargo");
    fs::write(
        &cargo,
        format!("#!/bin/sh\ntouch '{}'\nexit 92\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
    let cargo_home = root.path().join("cargo-home");
    fs::create_dir(&cargo_home).unwrap();

    Command::cargo_bin("release-admin")
        .unwrap()
        .args(["crate-set", "package"])
        .args(["--source-root", source.to_str().unwrap()])
        .args(["--source-commit", &source_commit])
        .args(["--git", "/usr/bin/git"])
        .args(["--cargo", cargo.to_str().unwrap()])
        .args(["--cargo-home", cargo_home.to_str().unwrap()])
        .args(["--package", "dev-tools-command@0.1.0"])
        .args(["--output", root.path().join("packages").to_str().unwrap()])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains(
            "source checkout contains a non-regular tracked entry",
        ));
    assert!(!marker.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn crate_set_package_rejects_nonreproducible_bytes_without_publishing_output() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let (source, source_commit) = write_git_crate_fixture(root.path());
    let first = root.path().join("first.crate");
    let second = root.path().join("second.crate");
    write_crate_archive(
        &first,
        "dev-tools-command",
        "0.1.0",
        &source_commit,
        b"pub fn command() { println!(\"first\"); }\n",
    );
    write_crate_archive(
        &second,
        "dev-tools-command",
        "0.1.0",
        &source_commit,
        b"pub fn command() { println!(\"second\"); }\n",
    );
    let marker = root.path().join("cargo-count");
    let cargo = root.path().join("cargo");
    fs::write(
        &cargo,
        format!(
            "#!/bin/sh\nset -eu\ntarget=\npackage=\nwhile [ \"$#\" -gt 0 ]; do\n  case \"$1\" in\n    --target-dir) target=$2; shift 2 ;;\n    --package) package=$2; shift 2 ;;\n    *) shift ;;\n  esac\ndone\n[ \"$package\" = dev-tools-command ]\nmkdir -p \"$target/package\"\nif [ -e '{}' ]; then source='{}'; else source='{}'; fi\ncp \"$source\" \"$target/package/dev-tools-command-0.1.0.crate\"\nprintf x >> '{}'\n",
            marker.display(),
            second.display(),
            first.display(),
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
    let cargo_home = root.path().join("cargo-home");
    fs::create_dir(&cargo_home).unwrap();
    let output = root.path().join("packages");

    Command::cargo_bin("release-admin")
        .unwrap()
        .args(["crate-set", "package"])
        .args(["--source-root", source.to_str().unwrap()])
        .args(["--source-commit", &source_commit])
        .args(["--git", "/usr/bin/git"])
        .args(["--cargo", cargo.to_str().unwrap()])
        .args(["--cargo-home", cargo_home.to_str().unwrap()])
        .args(["--package", "dev-tools-command@0.1.0"])
        .args(["--output", output.to_str().unwrap()])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains(
            "independent crate package builds are not byte-identical",
        ));
    assert_eq!(fs::read(&marker).unwrap(), b"xx");
    assert!(!output.exists());
}

#[cfg(unix)]
#[test]
fn root_build_uses_offline_root_authority_and_shared_canonical_contract() {
    let root = tempfile::tempdir().expect("root");
    let root_key = SigningKey::from_bytes(&[7; 32]);
    let release_key = SigningKey::from_bytes(&[9; 32]);
    let root_private = root.path().join("root-private-key.txt");
    let trusted_root = root.path().join("root-public-key.txt");
    let release_public = root.path().join("release-public-key.txt");
    fs::write(&root_private, format!("{}\n", hex(&root_key.to_bytes()))).expect("root key");
    fs::set_permissions(&root_private, fs::Permissions::from_mode(0o600)).expect("private mode");
    fs::write(
        &trusted_root,
        format!("{}\n", hex(&root_key.verifying_key().to_bytes())),
    )
    .expect("root public key");
    fs::write(
        &release_public,
        format!("{}\n", hex(&release_key.verifying_key().to_bytes())),
    )
    .expect("release public key");
    let output = root.path().join("dev-tools-root.json");

    Command::cargo_bin("release-admin")
        .expect("release-admin binary")
        .args(["root", "build", "--root-private-key"])
        .arg(&root_private)
        .arg("--release-public-key")
        .arg(&release_public)
        .arg("--trusted-root-public-key")
        .arg(&trusted_root)
        .args(["--generation", "2", "--output"])
        .arg(&output)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"generation\":2"))
        .stderr("");

    let verified = verify_root_bytes(
        &fs::read(&output).expect("signed root"),
        &hex(&root_key.verifying_key().to_bytes()),
    )
    .expect("verify signed root");
    assert_eq!(verified.generation, 2);
    assert_eq!(verified.active_release_keys, 1);

    Command::cargo_bin("release-admin")
        .expect("release-admin binary")
        .args(["root", "build", "--root-private-key"])
        .arg(&root_private)
        .arg("--release-public-key")
        .arg(&release_public)
        .arg("--trusted-root-public-key")
        .arg(&trusted_root)
        .args(["--generation", "2", "--output"])
        .arg(&output)
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("root output already exists"));
}

#[cfg(unix)]
#[test]
fn root_build_rejects_a_group_readable_private_key() {
    let root = tempfile::tempdir().expect("root");
    let root_key = SigningKey::from_bytes(&[7; 32]);
    let release_key = SigningKey::from_bytes(&[9; 32]);
    let root_private = root.path().join("root-private-key.txt");
    let trusted_root = root.path().join("root-public-key.txt");
    let release_public = root.path().join("release-public-key.txt");
    fs::write(&root_private, format!("{}\n", hex(&root_key.to_bytes()))).expect("root key");
    fs::set_permissions(&root_private, fs::Permissions::from_mode(0o640)).expect("unsafe mode");
    fs::write(
        &trusted_root,
        format!("{}\n", hex(&root_key.verifying_key().to_bytes())),
    )
    .expect("root public key");
    fs::write(
        &release_public,
        format!("{}\n", hex(&release_key.verifying_key().to_bytes())),
    )
    .expect("release public key");

    Command::cargo_bin("release-admin")
        .expect("release-admin binary")
        .args(["root", "build", "--root-private-key"])
        .arg(&root_private)
        .arg("--release-public-key")
        .arg(&release_public)
        .arg("--trusted-root-public-key")
        .arg(&trusted_root)
        .args(["--generation", "2", "--output"])
        .arg(root.path().join("dev-tools-root.json"))
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains(
            "root private key must be an owner-owned, owner-only regular file",
        ));
}

#[cfg(unix)]
#[test]
fn manifest_build_rejects_an_unaccepted_target_before_invoking_the_signer() {
    let root = tempfile::tempdir().expect("root");
    let signer_marker = root.path().join("signer-was-called");
    let signer = root.path().join("signer");
    fs::write(
        &signer,
        format!("#!/bin/sh\n: >'{}'\nexit 92\n", signer_marker.display()),
    )
    .expect("signer");
    fs::set_permissions(&signer, fs::Permissions::from_mode(0o755)).expect("signer mode");
    let artifact = root.path().join("sync-configs.exe");
    fs::write(&artifact, b"artifact").expect("artifact");

    Command::cargo_bin("release-admin")
        .expect("release-admin binary")
        .args(["manifest", "build", "--product", "sync-configs"])
        .args(["--version", "0.2.0", "--source-commit", &"d".repeat(40)])
        .args(["--generation", "14"])
        .args([
            "--artifact",
            &format!("windows-x86_64={}", artifact.display()),
        ])
        .arg("--root-document")
        .arg(root.path().join("unused-root.json"))
        .arg("--trusted-root-public-key")
        .arg(root.path().join("unused-root.pub"))
        .args(["--release-key-id", "release-0123456789abcdef"])
        .arg("--signer")
        .arg(&signer)
        .args(["--signer-profile", "source-maintenance", "--output"])
        .arg(root.path().join("sync-configs-stable.json"))
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains(
            "sync-configs release target is not accepted: windows-x86_64",
        ));

    assert!(
        !signer_marker.exists(),
        "signer must not run for a rejected target"
    );
}

#[cfg(unix)]
#[test]
fn manifest_build_rejects_a_revoked_release_key_before_invoking_the_signer() {
    let root = tempfile::tempdir().expect("root");
    let root_key = SigningKey::from_bytes(&[7; 32]);
    let revoked_release = SigningKey::from_bytes(&[9; 32]);
    let active_release = SigningKey::from_bytes(&[11; 32]);
    let root_payload = build_unsigned_root_document(&RootDocumentSpec {
        generation: 2,
        release_keys: vec![
            RootReleaseKey {
                public_key: hex(&revoked_release.verifying_key().to_bytes()),
                revoked: true,
            },
            RootReleaseKey {
                public_key: hex(&active_release.verifying_key().to_bytes()),
                revoked: false,
            },
        ],
    })
    .expect("root payload");
    let root_document = build_signed_envelope(
        &root_payload,
        &[EnvelopeSignature {
            key_id: root_key_id(&hex(&root_key.verifying_key().to_bytes())).unwrap(),
            signature: root_key.sign(&root_payload).to_bytes().to_vec(),
        }],
    )
    .expect("root document");
    let root_path = root.path().join("root.json");
    fs::write(&root_path, root_document).expect("root document file");
    let trusted_root = root.path().join("root.pub");
    fs::write(
        &trusted_root,
        format!("{}\n", hex(&root_key.verifying_key().to_bytes())),
    )
    .expect("trusted root");
    let artifact = root.path().join("dev-auth");
    fs::write(&artifact, b"artifact").expect("artifact");
    let signer_marker = root.path().join("signer-was-called");
    let signer = root.path().join("signer");
    fs::write(
        &signer,
        format!("#!/bin/sh\n: >'{}'\nexit 92\n", signer_marker.display()),
    )
    .expect("signer");
    fs::set_permissions(&signer, fs::Permissions::from_mode(0o755)).expect("signer mode");

    Command::cargo_bin("release-admin")
        .expect("release-admin binary")
        .args(["manifest", "build", "--product", "dev-auth"])
        .args(["--version", "0.3.10", "--source-commit", &"d".repeat(40)])
        .args(["--generation", "1"])
        .args([
            "--artifact",
            &format!("linux-x86_64={}", artifact.display()),
        ])
        .arg("--root-document")
        .arg(&root_path)
        .arg("--trusted-root-public-key")
        .arg(&trusted_root)
        .args([
            "--release-key-id",
            &release_key_id(&hex(&revoked_release.verifying_key().to_bytes())).unwrap(),
        ])
        .arg("--signer")
        .arg(&signer)
        .args(["--signer-profile", "source-maintenance", "--output"])
        .arg(root.path().join("dev-auth-stable.json"))
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains(
            "release key is not active in the authenticated root",
        ));

    assert!(
        !signer_marker.exists(),
        "signer must not run for a revoked key"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn manifest_build_uses_the_shared_contract_and_one_operation_only_signer() {
    let root = tempfile::tempdir().expect("root");
    let root_key = SigningKey::from_bytes(&[7; 32]);
    let release_key = SigningKey::from_bytes(&[9; 32]);
    let release_id = release_key_id(&hex(&release_key.verifying_key().to_bytes())).unwrap();
    let root_payload = json!({
        "schema": "dev-tools-root-v1",
        "generation": 1,
        "release_keys": [{
            "key_id": release_id.clone(),
            "public_key": hex(&release_key.verifying_key().to_bytes()),
            "revoked": false,
        }],
    });
    let root_document = signed(root_payload, "root-test", &root_key);
    let root_path = root.path().join("root.json");
    fs::write(&root_path, &root_document).expect("root document");
    let trusted_root = root.path().join("root-public-key.txt");
    fs::write(
        &trusted_root,
        format!("{}\n", hex(&root_key.verifying_key().to_bytes())),
    )
    .expect("trusted root");

    let linux = root.path().join("dev-auth-linux");
    fs::write(&linux, b"linux artifact").expect("linux artifact");
    let source_commit = "d".repeat(40);
    let unsigned = build_unsigned_product_manifest(&ProductManifestSpec {
        product: "dev-auth".into(),
        generation: 1,
        version: "0.3.10".into(),
        source_commit: source_commit.clone(),
        artifacts: vec![manifest_artifact(
            "dev-auth",
            "0.3.10",
            "linux-x86_64",
            &linux,
        )],
    })
    .expect("unsigned manifest");
    let signature = BASE64.encode(release_key.sign(&unsigned).to_bytes());
    let signer = root.path().join("signer");
    fs::write(
        &signer,
        format!(
            "#!/bin/sh\n[ \"$1\" = sign-release-manifest ] || exit 2\n[ \"$2\" = --profile ] || exit 2\n[ \"$3\" = source-maintenance ] || exit 2\ncat >/dev/null\nprintf '%s\\n' '{}'\n",
            signature
        ),
    )
    .expect("signer");
    fs::set_permissions(&signer, fs::Permissions::from_mode(0o755)).expect("executable signer");
    let output = root.path().join("dev-auth-stable.json");

    Command::cargo_bin("release-admin")
        .expect("release-admin binary")
        .args(["manifest", "build", "--product", "dev-auth"])
        .args(["--version", "0.3.10", "--source-commit", &source_commit])
        .args(["--generation", "1"])
        .args(["--artifact", &format!("linux-x86_64={}", linux.display())])
        .args(["--root-document", root_path.to_str().unwrap()])
        .args(["--trusted-root-public-key", trusted_root.to_str().unwrap()])
        .args(["--release-key-id", &release_id])
        .args(["--signer", signer.to_str().unwrap()])
        .args(["--signer-profile", "source-maintenance"])
        .args(["--output", output.to_str().unwrap()])
        .assert()
        .success()
        .stderr("");

    let manifest = fs::read(&output).expect("signed manifest");
    let verified = verify_release_bytes(
        &ReleaseBundle {
            root: root_document.clone(),
            manifest: manifest.clone(),
            artifact: fs::read(&linux).expect("artifact bytes"),
        },
        &ReleaseAuthority {
            trusted_root_key: hex(&root_key.verifying_key().to_bytes()),
            product: "dev-auth".into(),
            accepted_manifest_schemas: vec!["dev-tools-product-v2".into()],
            target: "linux-x86_64".into(),
            artifact_url: ArtifactUrlPolicy::GitHubRelease {
                owner: "FutureDevGuys".into(),
                repository: "dev-tools".into(),
            },
            require_source_commit: true,
            engine_protocol: 1,
        },
    )
    .expect("verify target projection");
    assert_eq!(
        verified.source_commit.as_deref(),
        Some(source_commit.as_str())
    );

    let linux_argument = format!(
        "linux-x86_64={}",
        root.path().join("dev-auth-linux").display()
    );
    Command::cargo_bin("release-admin")
        .expect("release-admin binary")
        .args(["set", "verify", "--product", "dev-auth"])
        .args(["--source-commit", &source_commit])
        .args(["--artifact", &linux_argument])
        .args(["--root-document", root_path.to_str().unwrap()])
        .args(["--manifest", output.to_str().unwrap()])
        .args(["--trusted-root-public-key", trusted_root.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"targets\":1"))
        .stderr("");

    fs::write(root.path().join("dev-auth-linux"), b"tampered").expect("tamper artifact");
    Command::cargo_bin("release-admin")
        .expect("release-admin binary")
        .args(["set", "verify", "--product", "dev-auth"])
        .args(["--source-commit", &source_commit])
        .args(["--artifact", &linux_argument])
        .args(["--root-document", root_path.to_str().unwrap()])
        .args(["--manifest", output.to_str().unwrap()])
        .args(["--trusted-root-public-key", trusted_root.to_str().unwrap()])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains(
            "release artifact does not match the signed manifest",
        ));
}

#[cfg(unix)]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(unix)]
fn signed(value: serde_json::Value, key_id: &str, key: &SigningKey) -> Vec<u8> {
    let canonical = serde_jcs::to_vec(&value).expect("canonical payload");
    serde_jcs::to_vec(&json!({
        "signed": value,
        "signatures": [{
            "key_id": key_id,
            "signature": BASE64.encode(key.sign(&canonical).to_bytes()),
        }],
    }))
    .expect("signed envelope")
}

#[cfg(unix)]
fn manifest_artifact(
    product: &str,
    version: &str,
    target: &str,
    path: &std::path::Path,
) -> ManifestArtifact {
    let bytes = fs::read(path).expect("artifact bytes");
    let suffix = if target.starts_with("windows-") {
        ".exe"
    } else {
        ""
    };
    ManifestArtifact {
        target: target.into(),
        url: format!(
            "https://github.com/FutureDevGuys/dev-tools/releases/download/{product}%2Fv{version}/{product}-{version}-{target}{suffix}"
        ),
        length: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
    }
}

#[cfg(unix)]
fn write_crate_archive(
    path: &std::path::Path,
    name: &str,
    version: &str,
    source_commit: &str,
    source: &[u8],
) {
    let file = fs::File::create(path).unwrap();
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let root = format!("{name}-{version}");
    let manifest =
        format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n");
    let vcs = format!("{{\"git\":{{\"sha1\":\"{source_commit}\"}}}}");
    for (entry_path, bytes) in [
        (format!("{root}/Cargo.toml"), manifest.as_bytes()),
        (format!("{root}/.cargo_vcs_info.json"), vcs.as_bytes()),
        (format!("{root}/src/lib.rs"), source),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        archive.append_data(&mut header, entry_path, bytes).unwrap();
    }
    archive.into_inner().unwrap().finish().unwrap();
}

#[cfg(target_os = "linux")]
fn git(root: &std::path::Path, arguments: &[&str]) {
    let status = ProcessCommand::new("/usr/bin/git")
        .current_dir(root)
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success(), "git fixture command failed");
}

#[cfg(target_os = "linux")]
fn git_output(root: &std::path::Path, arguments: &[&str]) -> String {
    let output = ProcessCommand::new("/usr/bin/git")
        .current_dir(root)
        .args(arguments)
        .output()
        .unwrap();
    assert!(output.status.success(), "git fixture command failed");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[cfg(target_os = "linux")]
fn write_git_crate_fixture(root: &std::path::Path) -> (std::path::PathBuf, String) {
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    fs::create_dir(source.join("src")).unwrap();
    fs::write(
        source.join("Cargo.toml"),
        "[package]\nname = \"dev-tools-command\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::write(source.join("src/lib.rs"), "pub fn command() {}\n").unwrap();
    git(&source, &["init", "--quiet"]);
    git(&source, &["config", "user.name", "release test"]);
    git(
        &source,
        &["config", "user.email", "release@example.invalid"],
    );
    git(&source, &["add", "Cargo.toml", "src/lib.rs"]);
    git(&source, &["commit", "--quiet", "-m", "fixture"]);
    let source_commit = git_output(&source, &["rev-parse", "HEAD"]);
    (source, source_commit)
}
