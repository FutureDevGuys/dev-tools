"""Public package for the sync-configs command."""

import tomllib
from pathlib import Path

try:
    from ._release_version import __version__
except ModuleNotFoundError:
    metadata = tomllib.loads(
        (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(
            encoding="utf-8"
        )
    )
    __version__ = str(metadata["project"]["version"])
