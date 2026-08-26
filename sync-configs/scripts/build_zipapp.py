from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import zipapp
import zipfile
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
ROOT = PROJECT.parent
PACKAGE = PROJECT / "syncconfigs"
REQUIREMENTS = PROJECT / "requirements-release.txt"
DIST = PROJECT / "dist"
NATIVE_SUFFIXES = {".dll", ".dylib", ".pyd", ".so"}
ZIP_PORTABLE_MINIMUM_EPOCH = 315619200
RETIRED_TOP_LEVEL_MODULES = {
    "json_overlay.py",
    "managed_path_policy.py",
    "overlay_ownership.py",
    "syncconfig_cli.py",
    "toml_overlay.py",
}


def project_version() -> str:
    metadata = tomllib.loads((PROJECT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(metadata["project"]["version"])


def install_dependencies(payload: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--require-hashes",
            "--no-deps",
            "--no-binary",
            "PyYAML",
            "--target",
            str(payload),
            "--requirement",
            str(REQUIREMENTS),
        ],
        cwd=ROOT,
        check=True,
    )


def retain_dependency_license(payload: Path) -> None:
    licenses = sorted(payload.glob("*yaml-*.dist-info/licenses/LICENSE"))
    if len(licenses) != 1:
        raise RuntimeError("the bundled PyYAML license was not found exactly once")
    destination = payload / "THIRD_PARTY_LICENSES" / "PyYAML.txt"
    destination.parent.mkdir()
    shutil.copy2(licenses[0], destination)


def remove_build_metadata_and_native_code(payload: Path) -> None:
    for path in sorted(payload.rglob("*"), reverse=True):
        if path.is_file() and (
            path.suffix.lower() in NATIVE_SUFFIXES or path.suffix == ".pyc"
        ):
            path.unlink()
        elif path.is_dir() and (
            path.name == "__pycache__"
            or path.name.endswith(".dist-info")
            or path.name.endswith(".egg-info")
        ):
            shutil.rmtree(path)


def normalize_payload(payload: Path) -> None:
    try:
        timestamp = int(
            os.environ.get("SOURCE_DATE_EPOCH", ZIP_PORTABLE_MINIMUM_EPOCH)
        )
    except ValueError as exc:
        raise RuntimeError("SOURCE_DATE_EPOCH must be an integer") from exc
    if time.localtime(timestamp)[:3] < (1980, 1, 1):
        raise RuntimeError("SOURCE_DATE_EPOCH must be representable by the ZIP format")

    paths = [payload, *sorted(payload.rglob("*"))]
    for path in paths:
        if path.is_symlink():
            raise RuntimeError(f"release payload contains a symbolic link: {path}")
        path.chmod(0o755 if path.is_dir() else 0o644)
        os.utime(path, (timestamp, timestamp), follow_symlinks=False)


def validate_archive(path: Path, expected_version: str) -> None:
    with zipfile.ZipFile(path) as archive:
        members = set(archive.namelist())
    if members.intersection(RETIRED_TOP_LEVEL_MODULES):
        raise RuntimeError("the zipapp contains a retired top-level module")
    required = {
        "THIRD_PARTY_LICENSES/PyYAML.txt",
        "syncconfigs/cli.py",
        "syncconfigs/default_filters.gitignore",
        "yaml/__init__.py",
    }
    missing = required.difference(members)
    if missing:
        raise RuntimeError(f"the zipapp is missing required files: {sorted(missing)}")
    native = sorted(
        member for member in members if Path(member).suffix.lower() in NATIVE_SUFFIXES
    )
    if native:
        raise RuntimeError(f"the platform-neutral zipapp contains native files: {native}")

    for arguments, expected in (
        (("--help",), "usage: sync-configs"),
        (("--version",), f"sync-configs {expected_version}"),
    ):
        result = subprocess.run(
            [sys.executable, "-S", str(path), *arguments],
            cwd=path.parent,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0 or expected not in result.stdout:
            raise RuntimeError(
                "the zipapp did not satisfy its isolated CLI contract: "
                f"arguments={arguments!r}, exit={result.returncode}, "
                f"stdout={result.stdout[:200]!r}, stderr={result.stderr.strip()!r}"
            )


def main() -> int:
    version = project_version()
    DIST.mkdir(exist_ok=True)
    destination = DIST / f"sync-configs-{version}.pyz"

    with tempfile.TemporaryDirectory(prefix="sync-configs-release-") as raw_temp:
        temporary = Path(raw_temp)
        payload = temporary / "payload"
        shutil.copytree(PACKAGE, payload / "syncconfigs")
        (payload / "syncconfigs/_release_version.py").write_text(
            f"__version__ = {version!r}\n",
            encoding="utf-8",
        )
        install_dependencies(payload)
        retain_dependency_license(payload)
        remove_build_metadata_and_native_code(payload)
        (payload / "__main__.py").write_text(
            "from syncconfigs.cli import main\nraise SystemExit(main())\n",
            encoding="utf-8",
        )
        normalize_payload(payload)
        candidate = temporary / destination.name
        zipapp.create_archive(
            payload,
            target=candidate,
            interpreter="/usr/bin/env python3",
            compressed=True,
        )
        validate_archive(candidate, version)
        descriptor, raw_staged = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=DIST
        )
        os.close(descriptor)
        staged = Path(raw_staged)
        try:
            shutil.copy2(candidate, staged)
            os.replace(staged, destination)
        finally:
            staged.unlink(missing_ok=True)

    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    print(f"{destination.name} sha256:{digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
