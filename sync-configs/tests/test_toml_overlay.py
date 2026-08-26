from __future__ import annotations

import tomllib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from syncconfigs import toml_overlay


def test_respect_policy_preserves_commented_assignment_and_reports_path() -> None:
    source = '[model_providers.bridge]\nenv_key = "SECRET_NAME"\nmodel = "gpt"\n'
    target = '[model_providers.bridge]\n   # env_key = "OLD_NAME"\nmodel = "old"\n'

    result = toml_overlay.overlay_toml_text(
        source,
        target,
        commented_target_policy="respect",
    )

    assert result.suppressed == (("model_providers", "bridge", "env_key"),)
    assert '   # env_key = "OLD_NAME"' in result.text
    assert tomllib.loads(result.text)["model_providers"]["bridge"]["model"] == "gpt"
    assert "env_key" not in tomllib.loads(result.text)["model_providers"]["bridge"]


def test_respect_policy_suppresses_descendants_of_commented_table() -> None:
    source = '[model_providers.bridge]\nenv_key = "SECRET_NAME"\nmodel = "gpt"\n'
    target = '  # [model_providers.bridge]\n# env_key = "OLD_NAME"\n'

    result = toml_overlay.overlay_toml_text(
        source,
        target,
        commented_target_policy="respect",
    )

    assert set(result.suppressed) == {
        ("model_providers", "bridge", "env_key"),
        ("model_providers", "bridge", "model"),
    }
    assert tomllib.loads(result.text) == {}
    assert "# [model_providers.bridge]" in result.text


def test_activate_policy_retains_existing_overlay_behavior() -> None:
    result = toml_overlay.overlay_toml_text(
        "feature = true\n",
        "  # feature = false\n",
        commented_target_policy="activate",
    )
    assert result.suppressed == ()
    assert tomllib.loads(result.text)["feature"] is True


def test_error_policy_blocks_without_exposing_values() -> None:
    with pytest.raises(ValueError, match=r"commented target paths suppress source keys: secret") as exc:
        toml_overlay.overlay_toml_text(
            'secret = "do-not-report"\n',
            ' # secret = "also-private"\n',
            commented_target_policy="error",
        )
    assert "do-not-report" not in str(exc.value)
    assert "also-private" not in str(exc.value)


def test_mutually_exclusive_siblings_prune_target_only_opposite_key() -> None:
    result = toml_overlay.overlay_toml_text(
        '[model_providers.bridge]\nenv_key = "SECRET_NAME"\n',
        '[model_providers.bridge]\nauth = "stale-private-value"\nother = true\n',
        exclusive_sibling_groups=((('model_providers', '*'), ('auth', 'env_key')),),
    )
    parsed = tomllib.loads(result.text)["model_providers"]["bridge"]
    assert parsed == {"env_key": "SECRET_NAME", "other": True}
    assert result.removed == 1


def test_mutually_exclusive_siblings_reject_invalid_source_without_values() -> None:
    with pytest.raises(ValueError, match=r"mutually exclusive source keys.*auth, env_key") as exc:
        toml_overlay.overlay_toml_text(
            '[model_providers.bridge]\nauth = "private-a"\nenv_key = "private-b"\n',
            "",
            exclusive_sibling_groups=((('model_providers', '*'), ('auth', 'env_key')),),
        )
    assert "private-a" not in str(exc.value)
    assert "private-b" not in str(exc.value)
