"""Accepted product release targets.

Compilation is portability evidence, not production acceptance. Keep the
release boundary fail-closed until each product/target pair has completed its
native runtime and installation acceptance.
"""

from __future__ import annotations


ACCEPTED_PRODUCT_TARGETS: dict[str, frozenset[str]] = {
    "sync-configs": frozenset({"linux-x86_64"}),
}


def require_accepted_release_target(product: str, target: str) -> None:
    accepted = ACCEPTED_PRODUCT_TARGETS.get(product)
    if accepted is not None and target not in accepted:
        raise SystemExit(f"{product} release target is not accepted: {target}")
