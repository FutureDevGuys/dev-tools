#![cfg(target_os = "linux")]

use assert_cmd::Command;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dev_tools_release::verify_root_bytes;
use ed25519_dalek::{Signer, SigningKey};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

// These deterministic synthetic keys have no operational authority.
fn public_key(seed: u8) -> String {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn private_key(path: &Path, seed: u8) {
    fs::write(path, format!("{seed:02x}").repeat(32)).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn document_bytes(value: &serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_jcs::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn manifest_command(root: &Path, signer: &Path, output: &Path) -> Command {
    let mut command = Command::cargo_bin("release-admin").unwrap();
    command
        .args(["manifest", "build", "--product", "dev-auth"])
        .args(["--version", "1.2.3", "--generation", "2"])
        .args(["--source-commit", &"a".repeat(40)])
        .args([
            "--artifact",
            &format!("linux-x86_64={}", root.join("artifact").display()),
        ])
        .arg("--root-document")
        .arg(root.join("root.json"))
        .arg("--trusted-root-public-key")
        .arg(root.join("root.pub"))
        .args(["--release-key-id", "release-fe812c12f3ab4ce6"])
        .arg("--signer")
        .arg(signer)
        .args(["--signer-profile", "fixture"])
        .arg("--output")
        .arg(output);
    command
}

#[test]
fn tracked_root_document_matches_the_product_trust_anchor() {
    let root = include_bytes!("../../../release-trust/dev-tools-root.json");
    let trusted_root = include_str!("../../update-all/trust/root-public-key.txt").trim();
    let verified = verify_root_bytes(root, trusted_root).unwrap();
    assert_eq!(verified.active_release_keys, 1);
}

#[test]
fn frozen_root_rotation_and_manifest_corpus_preserve_native_construction() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let vectors: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/releases/native-construction.json"
    ))
    .unwrap();
    for seed in [3, 13] {
        private_key(&root.join(format!("root-{seed}.key")), seed);
    }
    fs::write(root.join("root.pub"), public_key(3)).unwrap();
    fs::write(root.join("release.pub"), public_key(7)).unwrap();
    fs::write(root.join("artifact"), b"fixture artifact").unwrap();

    for (iteration, seeds) in [[3, 13], [13, 3]].iter().enumerate() {
        let output = root.join(format!("rotation-{iteration}.json"));
        let mut command = Command::cargo_bin("release-admin").unwrap();
        command.args(["root", "build"]);
        for seed in seeds {
            command
                .arg("--root-private-key")
                .arg(root.join(format!("root-{seed}.key")));
        }
        command
            .arg("--release-public-key")
            .arg(root.join("release.pub"))
            .arg("--trusted-root-public-key")
            .arg(root.join("root.pub"))
            .args(["--generation", "2", "--output"])
            .arg(&output)
            .assert()
            .success()
            .stderr("");
        let bytes = fs::read(&output).unwrap();
        assert_eq!(bytes, document_bytes(&vectors["root"]));
        for seed in seeds {
            let verified = verify_root_bytes(&bytes, &public_key(*seed)).unwrap();
            assert_eq!(verified.generation, 2);
            assert_eq!(verified.active_release_keys, 1);
        }
    }
    fs::write(
        root.join("root.json"),
        serde_jcs::to_vec(&vectors["root"]).unwrap(),
    )
    .unwrap();
    let expected_payload = serde_jcs::to_vec(&vectors["manifest"]["signed"]).unwrap();
    let signature = vectors["manifest"]["signatures"][0]["signature"]
        .as_str()
        .unwrap();
    let signer = root.join("signer");
    fs::write(
        &signer,
        format!(
            "#!/bin/sh\n[ \"$#\" = 3 ] && [ \"$1\" = sign-release-manifest ] && [ \"$2\" = --profile ] && [ \"$3\" = fixture ] || exit 8\n/bin/cat >'{}'\nprintf '%s\\n' '{}'\n",
            root.join("payload").display(), signature
        ),
    )
    .unwrap();
    fs::set_permissions(&signer, fs::Permissions::from_mode(0o700)).unwrap();
    for iteration in 0..2 {
        let output = root.join(format!("manifest-{iteration}.json"));
        manifest_command(root, &signer, &output)
            .assert()
            .success()
            .stderr("");
        assert_eq!(fs::read(root.join("payload")).unwrap(), expected_payload);
        assert_eq!(
            fs::read(output).unwrap(),
            document_bytes(&vectors["manifest"])
        );
    }

    let wrong_signature = BASE64.encode(
        SigningKey::from_bytes(&[11; 32])
            .sign(&expected_payload)
            .to_bytes(),
    );
    for (iteration, body) in [
        format!("printf '%s\\n' '{wrong_signature}'"),
        "printf 'not-base64!\\n'".into(),
        "printf 'YQ==\\n'".into(),
        format!("printf '%s\\nextra\\n' '{signature}'"),
        format!("printf '%s' '{signature}'"),
        "printf '%0300d\\n' 0".into(),
        format!("printf '%s\\n' '{signature}'; printf 'provider detail' >&2"),
        "exit 9".into(),
    ]
    .iter()
    .enumerate()
    {
        let rejected_signer = root.join(format!("rejected-signer-{iteration}"));
        fs::write(
            &rejected_signer,
            format!("#!/bin/sh\n/bin/cat >/dev/null\n{body}\n"),
        )
        .unwrap();
        fs::set_permissions(&rejected_signer, fs::Permissions::from_mode(0o700)).unwrap();
        let output = root.join(format!("rejected-{iteration}.json"));
        let result = manifest_command(root, &rejected_signer, &output)
            .output()
            .unwrap();
        assert!(
            !result.status.success(),
            "invalid signer case {iteration} was accepted"
        );
        assert!(result.stdout.is_empty());
        assert!(
            !output.exists(),
            "invalid signature must not publish output"
        );
        assert!(!String::from_utf8_lossy(&result.stderr).contains("provider detail"));
    }
}
