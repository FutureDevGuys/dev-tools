# Artifact Update source coverage

The declared source catalog has 14 variants. The table connects each implemented discovery boundary to its executable regression corpus; it is not a live-provider availability or native-platform acceptance claim. Run `cargo test --locked -p dev-tools-update` for the shared corpus and `cargo test --locked -p artifact-update` for product dispatch, persistence and command behavior.

| Source | Local behavior and boundary | Regression corpus under `crates/dev-tools-update` |
| --- | --- | --- |
| GitHub | Bounded complete release pages; stable local ranking; exact-resource conditional reuse | `src/discovery.rs`: pagination, ambiguity, validator identity, failed-refresh preservation and cache codec tests |
| GitLab | Explicit API/project; named asset links; excludes upcoming releases | `src/discovery/gitlab.rs`: complete pagination, invalid/ambiguous metadata and distinct cache identity |
| Forgejo | Explicit instance/repository; terminal empty page required despite short instance-capped pages | `src/discovery/forgejo.rs`: short-page continuation, inventory bounds, hostile candidates and conditional reuse |
| Gitea | Separate provider/cache identity with the same bounded page parser | `src/discovery/gitea.rs`: short-page continuation, stable selection, malformed candidates and failed refresh |
| Generic JSON | Only explicit local JSON pointers select versions and assets | `src/discovery/generic_json.rs`: pointer escapes, duplicate/mistyped data, ambiguity, bounds and current-mapping reselection |
| Generic XML | Literal local namespace-qualified mappings; bounded inert XML, no external resolution | `src/discovery/generic_xml.rs`: RSS/Atom and attribute mappings, hostile XML, scalar ambiguity, storage bounds and cache reselection |
| npm | One explicit distribution tag; exact package identity; tarball URL remains inert | `src/discovery/npm.rs`: tag request, identity, stable version rules, duplicate fields, bounds and cache round trip |
| crates.io | Fixed sparse-index identity; stable unyanked versions; derived download URL | `src/discovery/crates_io.rs`: path construction, complete bounded records, malformed identity/version data and failed refresh |
| Maven | Explicit local coordinates, classifier and extension; no POM resolution or execution | `src/discovery/maven.rs`: namespaces, hostile/ambiguous XML, coordinate mismatch, parser bounds and conditional reuse |
| Sparkle | Explicit bundle/display version; stable full-file enclosures, no delta installation | `src/discovery/sparkle.rs`: modern/legacy fields, channels, duplicate versions, hostile XML and failure-preserving cache |
| zsync | Bounded control metadata and full-file candidates; no reconstruction or checksum authentication | `src/discovery/zsync.rs`: binary record length, header bounds, relative references, mirror ambiguity and final-location cache identity |
| HTML | Static link inventory and local filename captures; no script execution or DOM interpretation | `src/discovery/html.rs`: raw-text exclusions, unsupported contexts, entity decoding, ambiguity, bounds and final-location cache identity |
| URL | Header-only probe; locally admitted redirects and filename-derived observation | `src/discovery/url_source.rs`: redirect admission, current captures, final location and failed-probe preservation |
| Static manifest | Exact local root/product/target/artifact URL; source-bound signed metadata, separate ledger acceptance | `tests/static_manifest.rs` and `src/discovery.rs`: real synthetic signatures, explicit authority rejection, retained-root checks, rollback ledger and bounded host-specific retrieval |

The thirteen ordinary sources produce unverified observations, never installation authority. Their cache codecs reparse original metadata under current local rules; failed refreshes do not become successful stale observations. HTML and zsync additionally bind relative references to the final admitted metadata location. URL probes retain no response body. Linux product dispatch and persistence select each source's own codec in `crates/artifact-update/src/cache.rs`; static manifests bypass that observation cache and use the separate signed ledger path in `crates/artifact-update/src/lib.rs`.

Static manifest verification delegates to `dev-tools-release`, whose exact-URL authority rejects multi-target manifests. Signature verification alone neither authenticates artifact bytes nor advances accepted generations. Installation, retained rollback, interrupted-publication recovery and real release-binary/platform qualification remain separate from source coverage. See the [product guide](artifact-update.md) for precise limits and the [product standard](product-standard.md) for acceptance requirements.
