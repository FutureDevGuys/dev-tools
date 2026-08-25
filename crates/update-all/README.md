# update-all

`update-all` runs detected system and developer-tool updates through a catalog-driven engine with compact dashboard and plain-output frontends.

Public built-ins cover broadly applicable package and language managers. Additional organizations and users can add namespaced TOML catalogs under the platform configuration directory without rebuilding the binary.

The command updates itself only from authenticated stable-release manifests. Runtime release checks use native HTTPS and do not require Git, GitHub CLI, curl, wget, Python, authentication, or a source checkout.

See the repository [README](../../README.md) and [update-all documentation](../../docs/update-all.md) for installation, catalog authoring, result semantics, and the release trust model.
