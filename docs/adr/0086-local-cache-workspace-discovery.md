---
authority: canonical
owner: dev-tools
---

# ADR 0086: Local cache workspace discovery

status: proposed
verification: pending

Dev Cache discovers workspace grouping through Rust filesystem metadata rather than invoking Git. The nearest ancestor with a recognized `.git` file or directory is the grouping boundary, including linked worktrees and submodules; otherwise the nearest supported language manifest is used, falling back to the requested directory. A marker is a grouping hint, not proof of a valid repository or authentication authority. Git environment overrides and Git configuration do not select cache ownership.

This removes an unbounded external command and possible credential-broker invocation from cache discovery, especially repeated compiler interception. It also preserves standalone operation without Git. Discovery does not read Git configuration or initialize repository state. Gitfiles are read with an 8 KiB bound; their target is checked for HEAD and objects/commondir metadata without reading those files. Existing domain/path/filesystem identity checks remain unchanged. Cache scope follows the canonical requested directory and marker ancestry; the cache product does not emulate Git's environment-dependent repository resolution.

Regression tests cover ordinary and linked worktree markers, nested language manifests, submodule boundaries and non-Git workspaces. Native platform and release qualification remain required; test results alone do not establish installed acceptance.
