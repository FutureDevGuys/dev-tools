from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
BUILD_ROOT = ROOT / "scripts/build-root-document.py"
BUILD_RELEASE = ROOT / "scripts/build-signed-release.py"
PUBLISH = ROOT / "scripts/publish-release-set.py"
sys.path.insert(0, str(ROOT / "scripts"))
PUBLISH_SPEC = importlib.util.spec_from_file_location("publish_release_set", PUBLISH)
assert PUBLISH_SPEC is not None and PUBLISH_SPEC.loader is not None
PUBLISH_MODULE = importlib.util.module_from_spec(PUBLISH_SPEC)
sys.modules[PUBLISH_SPEC.name] = PUBLISH_MODULE
PUBLISH_SPEC.loader.exec_module(PUBLISH_MODULE)
from release_signing import envelope as sign_envelope


def write_private_key(path: Path, key: Ed25519PrivateKey) -> None:
    path.write_text(key.private_bytes_raw().hex(), encoding="ascii")
    path.chmod(0o600)


def write_public_key(path: Path, key: Ed25519PrivateKey) -> None:
    path.write_text(key.public_key().public_bytes_raw().hex() + "\n", encoding="ascii")


def build_release_set(
    tmp_path: Path, *, sync_configs_target: str = "linux-x86_64"
) -> tuple[Path, Path, str]:
    root_key = Ed25519PrivateKey.from_private_bytes(bytes([3]) * 32)
    release_key = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
    root_private = tmp_path / "root.key"
    release_private = tmp_path / "release.key"
    release_public = tmp_path / "release.pub"
    trusted_root = tmp_path / "root.pub"
    root_document = tmp_path / "dev-tools-root.json"
    write_private_key(root_private, root_key)
    write_private_key(release_private, release_key)
    write_public_key(release_public, release_key)
    write_public_key(trusted_root, root_key)
    subprocess.run(
        [
            sys.executable,
            str(BUILD_ROOT),
            "--root-private-key",
            str(root_private),
            "--release-public-key",
            str(release_public),
            "--trusted-root-public-key",
            str(trusted_root),
            "--generation",
            "1",
            "--output",
            str(root_document),
        ],
        cwd=ROOT,
        check=True,
    )
    release_root = tmp_path / "releases"
    for product, version, target, artifact_name in (
        ("update-all", "1.2.3", "linux-x86_64", "update-all"),
        ("sync-configs", "2.3.4", "linux-x86_64", "sync-configs.pyz"),
    ):
        artifact = tmp_path / artifact_name
        artifact.write_bytes(f"{product} fixture\n".encode())
        subprocess.run(
            [
                sys.executable,
                str(BUILD_RELEASE),
                "--product",
                product,
                "--version",
                version,
                "--target",
                target,
                "--artifact",
                str(artifact),
                "--root-document",
                str(root_document),
                "--release-private-key",
                str(release_private),
                "--trusted-root-public-key",
                str(trusted_root),
                "--manifest-generation",
                "1",
                "--output",
                str(release_root / product),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    if sync_configs_target != "linux-x86_64":
        # The shared builder now rejects an unaccepted target before signing.
        # Construct an authentically signed, policy-invalid fixture directly so
        # the publisher's independent fail-closed boundary is still exercised.
        manifest_path = release_root / "sync-configs/sync-configs-stable.json"
        manifest_envelope = json.loads(manifest_path.read_text(encoding="utf-8"))
        signed = manifest_envelope["signed"]
        artifact = signed["artifacts"].pop("linux-x86_64")
        signed["artifacts"] = {sync_configs_target: artifact}
        key_id = manifest_envelope["signatures"][0]["key_id"]
        manifest_path.write_text(
            json.dumps(
                sign_envelope(signed, key_id, release_key),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
    return release_root, trusted_root, "a" * 40


def write_fake_commands(tmp_path: Path) -> tuple[Path, Path, Path]:
    state = tmp_path / "provider-state"
    state.mkdir()
    command = tmp_path / "provider.py"
    command.write_text(
        r"""#!/usr/bin/python3
import json
import os
import shutil
import sys
from pathlib import Path

state = Path(os.environ["PUBLICATION_TEST_STATE"])
log = state / "calls.jsonl"
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({"argv0": Path(sys.argv[0]).name, "args": sys.argv[1:]}) + "\n")
args = sys.argv[1:]
source = "a" * 40
if Path(sys.argv[0]).name == "git":
    if args[:3] == ["status", "--porcelain", "--untracked-files=normal"]:
        raise SystemExit(0)
    if args[:2] == ["cat-file", "-e"]:
        raise SystemExit(0)
    if args[:2] == ["tag", "--list"]:
        tag = args[2]
        if (state / ("tag-" + tag.replace("/", "_"))).exists():
            print(tag)
        raise SystemExit(0)
    if args[:2] == ["tag", "-s"]:
        tag = args[2]
        (state / ("tag-" + tag.replace("/", "_"))).write_text(source)
        raise SystemExit(0)
    if args[:3] == ["config", "--get", "user.signingKey"]:
        print("key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGFx1w/enBxQRy/DEl59qE3az25LG9DbYUue2Bj5IghY fixture")
        raise SystemExit(0)
    if len(args) == 4 and args[0] == "-c" and args[2] == "verify-tag":
        key, separator, allowed_signers = args[1].partition("=")
        if key != "gpg.ssh.allowedSignersFile" or not separator:
            raise SystemExit(93)
        (state / "allowed-signers.txt").write_text(
            Path(allowed_signers).read_text(encoding="ascii"), encoding="ascii"
        )
        raise SystemExit(0)
    if args and args[0] == "verify-tag":
        raise SystemExit(93)
    if args[:3] == ["rev-list", "-n", "1"]:
        print(source)
        raise SystemExit(0)
    if args and args[0] == "ls-remote":
        tag = args[-2].removeprefix("refs/tags/")
        if (state / ("remote-" + tag.replace("/", "_"))).exists():
            print("b" * 40 + "\trefs/tags/" + tag)
            print(source + "\trefs/tags/" + tag + "^{}")
        raise SystemExit(0)
    if args and args[0] == "fetch":
        tag = args[-1].split(":", 1)[1].removeprefix("refs/tags/")
        (state / ("tag-" + tag.replace("/", "_"))).write_text(source)
        raise SystemExit(0)
    if args and args[0] == "push":
        tag = args[-1].split(":", 1)[0].removeprefix("refs/tags/")
        (state / ("remote-" + tag.replace("/", "_"))).write_text(source)
        raise SystemExit(0)
    raise SystemExit(91)

if args[:2] == ["release", "view"]:
    if os.environ.get("PUBLICATION_TEST_GH_VIEW_ERROR") == "1":
        print("provider unavailable", file=sys.stderr)
        raise SystemExit(2)
    tag = args[2]
    record = state / ("release-" + tag.replace("/", "_") + ".json")
    if not record.exists():
        print("release not found", file=sys.stderr)
        raise SystemExit(1)
    paths = json.loads(record.read_text())
    print(json.dumps({
        "tagName": tag,
        "isDraft": False,
        "isPrerelease": False,
        "assets": [
            {"name": name, "size": Path(path).stat().st_size}
            for name, path in paths.items()
        ],
    }))
    raise SystemExit(0)
if args[:2] == ["release", "create"]:
    tag = args[2]
    assets = [Path(value) for value in args[args.index("--notes") + 2 :]]
    record = state / ("release-" + tag.replace("/", "_") + ".json")
    record.write_text(json.dumps({path.name: str(path) for path in assets}))
    raise SystemExit(0)
if args[:2] == ["release", "download"]:
    tag = args[2]
    destination = Path(args[args.index("--dir") + 1])
    pattern = args[args.index("--pattern") + 1]
    record = state / ("release-" + tag.replace("/", "_") + ".json")
    source_path = Path(json.loads(record.read_text())[pattern])
    shutil.copy2(source_path, destination / pattern)
    raise SystemExit(0)
raise SystemExit(92)
""",
        encoding="utf-8",
    )
    command.chmod(0o755)
    git = tmp_path / "git"
    gh = tmp_path / "gh"
    git.symlink_to(command)
    gh.symlink_to(command)
    return git, gh, state


def invoke_publisher(
    monkeypatch: pytest.MonkeyPatch,
    release_root: Path,
    trusted_root: Path,
    source_commit: str,
    git: Path,
    gh: Path,
) -> int:
    monkeypatch.setattr(
        PUBLISH_MODULE,
        "exact_command",
        lambda path, _name: PUBLISH_MODULE.ExactCommand(
            launcher=path,
            executable=path,
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(PUBLISH),
            "--release-root",
            str(release_root),
            "--trusted-root-public-key",
            str(trusted_root),
            "--source-commit",
            source_commit,
            "--repository",
            "FutureDevGuys/dev-tools",
            "--git-command",
            str(git),
            "--gh-command",
            str(gh),
            "--format",
            "json",
        ],
    )
    return PUBLISH_MODULE.main()


def test_publisher_verifies_signatures_tags_and_assets_then_resumes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    release_root, trusted_root, source_commit = build_release_set(tmp_path)
    git, gh, state = write_fake_commands(tmp_path)
    monkeypatch.setenv("PUBLICATION_TEST_STATE", str(state))
    assert (
        invoke_publisher(
            monkeypatch, release_root, trusted_root, source_commit, git, gh
        )
        == 0
    )
    first_report = json.loads(capsys.readouterr().out)
    assert first_report["changed"] is True
    assert first_report["verified"] is True
    assert first_report["tag_source_commit"] == source_commit
    assert all(item["source_bound"] is False for item in first_report["releases"])
    assert [item["tag"] for item in first_report["releases"]] == [
        "sync-configs/v2.3.4",
        "update-all/v1.2.3",
    ]

    assert (
        invoke_publisher(
            monkeypatch, release_root, trusted_root, source_commit, git, gh
        )
        == 0
    )
    second_report = json.loads(capsys.readouterr().out)
    assert second_report["changed"] is False
    assert second_report["verified"] is True

    calls = [
        json.loads(line) for line in (state / "calls.jsonl").read_text().splitlines()
    ]
    assert any(
        call["argv0"] == "git" and call["args"][:2] == ["tag", "-s"] for call in calls
    )
    assert (state / "allowed-signers.txt").read_text(encoding="ascii") == (
        '* namespaces="git" ssh-ed25519 '
        "AAAAC3NzaC1lZDI1NTE5AAAAIGFx1w/enBxQRy/DEl59qE3az25LG9DbYUue2Bj5IghY\n"
    )
    assert any(
        call["argv0"] == "gh" and call["args"][:2] == ["release", "create"]
        for call in calls
    )
    for call in calls:
        if call["argv0"] == "gh" and call["args"][:2] == ["release", "create"]:
            notes = call["args"][call["args"].index("--notes") + 1]
            assert "from source" not in notes
            assert "does not bind artifact provenance" in notes


def test_publisher_rejects_a_tampered_artifact_before_provider_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_root, trusted_root, source_commit = build_release_set(tmp_path)
    git, gh, state = write_fake_commands(tmp_path)
    artifact = next((release_root / "update-all").glob("update-all-*-linux-x86_64"))
    artifact.write_bytes(b"tampered")
    monkeypatch.setenv("PUBLICATION_TEST_STATE", str(state))
    with pytest.raises(SystemExit, match="artifact"):
        invoke_publisher(
            monkeypatch, release_root, trusted_root, source_commit, git, gh
        )
    assert not (state / "calls.jsonl").exists()


@pytest.mark.parametrize(
    "target",
    ("windows-x86_64", "macos-aarch64", "linux-aarch64"),
)
def test_publisher_rejects_an_unaccepted_sync_configs_target_before_provider_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    release_root, trusted_root, source_commit = build_release_set(
        tmp_path, sync_configs_target=target
    )
    git, gh, state = write_fake_commands(tmp_path)
    monkeypatch.setenv("PUBLICATION_TEST_STATE", str(state))

    with pytest.raises(
        SystemExit,
        match=f"sync-configs release target is not accepted: {target}",
    ):
        invoke_publisher(
            monkeypatch, release_root, trusted_root, source_commit, git, gh
        )

    assert not (state / "calls.jsonl").exists()


def test_publisher_does_not_treat_a_provider_error_as_an_absent_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_root, trusted_root, source_commit = build_release_set(tmp_path)
    git, gh, state = write_fake_commands(tmp_path)
    monkeypatch.setenv("PUBLICATION_TEST_STATE", str(state))
    monkeypatch.setenv("PUBLICATION_TEST_GH_VIEW_ERROR", "1")
    with pytest.raises(SystemExit, match="could not determine release state"):
        invoke_publisher(
            monkeypatch, release_root, trusted_root, source_commit, git, gh
        )
    calls = [
        json.loads(line) for line in (state / "calls.jsonl").read_text().splitlines()
    ]
    assert not any(
        call["argv0"] == "gh" and call["args"][:2] == ["release", "create"]
        for call in calls
    )


def test_publisher_pins_root_owned_same_name_launchers_and_rejects_user_paths(
    tmp_path: Path,
) -> None:
    command = PUBLISH_MODULE.exact_command(Path("/usr/bin/git"), "git")
    assert command.launcher == Path("/usr/bin/git")
    assert command.executable == Path("/usr/bin/git")

    fake = tmp_path / "git"
    fake.symlink_to("/usr/bin/git")
    with pytest.raises(SystemExit, match="not root-owned"):
        PUBLISH_MODULE.exact_command(fake, "git")
