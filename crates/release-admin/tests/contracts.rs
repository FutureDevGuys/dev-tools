use assert_cmd::Command;
#[cfg(unix)]
use base64::engine::general_purpose::STANDARD as BASE64;
#[cfg(unix)]
use base64::Engine as _;
#[cfg(unix)]
use dev_tools_release::{
    build_signed_envelope, build_unsigned_product_manifest, build_unsigned_root_document,
    release_key_id, root_key_id, verify_release_bytes, verify_root_bytes, ArtifactUrlPolicy,
    EnvelopeSignature, ManifestArtifact, ProductManifestSpec, ReleaseAuthority, ReleaseBundle,
    RootDocumentSpec, RootReleaseKey,
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
        .stdout(predicate::str::contains("set"))
        .stdout(predicate::str::contains("publish"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("build-info"));
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
