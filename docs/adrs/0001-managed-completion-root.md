---
authority: canonical
owner: dev-tools
topic: managed-completion-root
kind: adr
status: accepted
date: 2026-09-01
---

# 0001 — Publish managed completions through an immutable public root

## Context

`update-all` currently mixes two separate concerns in one checkout-backed runtime tree: generating completion artifacts for managed tools and editing shell-owned bootstrap paths under a caller-supplied rc root. That coupling makes idempotency harder to prove, encourages product-specific path assumptions, and makes it difficult for a consumer such as `syscfg` to load completions without granting `update-all` write access to its own startup files. It also leaves no durable public contract for non-Zsh shells.

The desired boundary is generic. `update-all` should stay responsible for discovering commands, preferring authoritative native completions, generating validated fallback only when necessary, and publishing the resulting managed artifacts. Shell configuration authorities should decide whether and how to source those artifacts.

## Decision

`update-all` publishes managed completion state under one absolute public managed root selected by `--managed-root`, then `UPDATE_ALL_COMPLETION_ROOT`, then the platform default. The initial platform defaults are `$XDG_DATA_HOME/update-all/completions` with the standard XDG fallback on Unix and `%LOCALAPPDATA%\update-all\completions` on Windows. The managed root is product-owned data, not checkout state.

Publication is immutable and activation is atomic:

- content is stored under `objects/` by digest;
- validated activation snapshots live under `snapshots/<digest>/`;
- `current` selects the active snapshot;
- sync-wide identity and attempt caches may live under the same managed root;
- a second unchanged publication does not rewrite `current`, create a new snapshot, or mutate existing objects.

`update-all completion <shell>` remains the trusted self-completion emitter for Bash, Zsh, Fish, Elvish, and PowerShell. `update-all completions init <shell>` is read-only and emits shell code on stdout that sources the currently active immutable snapshot for that shell. `update-all completions status` is read-only inspection. Legacy `completions install` and checkout `--rc-root` paths remain explicit compatibility surfaces only; they do not define the public contract.

The managed root is generic. It does not encode `syscfg`, repository paths, browser behavior, or shellrc-specific assumptions. Shell loaders remain the consumer's responsibility.

## Consequences

Consumers can source managed completions from a stable data contract without letting `update-all` edit their startup files. Publication becomes easier to test for exact no-op behavior because activation changes are reduced to immutable snapshot creation and one `current` replacement. Five-shell self-completion is available immediately through one surface even while richer external managed-tool completion support continues to evolve behind the same contract.

This decision does not make native payload augmentation or shell startup editing automatic. Valid native output remains authoritative, and fallback remains conservative. Additional identity memoization, authoritative provider inventories, and richer five-shell managed-tool rendering will extend this root rather than replace it.
