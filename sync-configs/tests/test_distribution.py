from __future__ import annotations

from pathlib import Path
import tomllib


def test_distribution_selects_only_the_canonical_import_package() -> None:
    project = Path(__file__).resolve().parents[1]
    metadata = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8"))

    assert metadata["tool"]["setuptools"]["packages"] == ["syncconfigs"]
    assert "py-modules" not in metadata["tool"]["setuptools"]
