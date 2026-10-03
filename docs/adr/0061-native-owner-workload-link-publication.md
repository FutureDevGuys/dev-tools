---
authority: canonical
owner: dev-auth
---

# ADR 0061: Native ownership of root-published workload links

status: proposed
verification: pending

## Decision

Linux workload reconciliation publishes a newly staged workload symlink with the target native account's ownership before renaming it to its final name. Previously, root setup created the symlink as root while publishing its receipt as the native user; retained-generation capture correctly rejected that mismatch. The workload executable remains root-owned and unchanged.

The publication boundary opens the staged link with `O_PATH | O_NOFOLLOW`, verifies its creating effective UID, single-link symlink identity and exact target, then assigns the selected native account's UID and primary GID through an empty-path operation on that held descriptor. It does not follow the executable target or use a replaceable pathname as the privileged ownership-change destination. Named and held inode identity must still agree before publication. Existing directory synchronization precedes receipt publication. The enclosing setup owner remains responsible for account validation and writer exclusion; this correction does not make the legacy pathname rename transaction atomic against an independent directory writer.

This applies to newly staged Linux links. It neither silently changes ownership on an already-installed matching link nor independently admits historically root-owned links into retained removal authority. [ADR 0063](0063-retained-legacy-workload-link-ownership.md) defines that separate retained-owner compatibility. Non-Linux publication retains its existing implementation and remains separately unqualified. No receipt or CLI schema changes.

## Evidence

The disposable systemd full-generation fixture exposed the mismatch while capturing a generation: the product-created link had UID 0 while its receipt had the native user's UID. A focused native user-namespace regression then failed at the wrong-owner assertion before the correction. It now requires native link ownership, unchanged target UID/mode/inode, successful generation capture and an unchanged link inode on repeat.

Run the focused gate explicitly with `cargo test -p dev-auth --locked --lib setup::tests::root_workload_publication_assigns_link_not_target_to_native_account -- --ignored --exact`. It requires subordinate UID/GID mappings, `unshare` and an existing native `nobody` account; it uses disposable files and does not execute the synthetic target. The broader systemd fixture and its independent acceptance limits are recorded in ADR 0057.
