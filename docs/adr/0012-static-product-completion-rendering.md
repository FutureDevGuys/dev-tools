---
authority: canonical
owner: dev-tools
---

# ADR 0012: Static product completion rendering

status: proposed
verification: pending

## Decision

All seven public products compile the focused `dev-tools-completion` renderer into their standalone binaries. Products own their command definitions and invocation grammar. The renderer consumes trusted Clap 4 metadata and deliberately exposes the Clap Complete 4 shell selector; it emits bytes for Bash, Zsh, Fish, Elvish and PowerShell without configuration, environment, filesystem, discovery, process or publication authority. Registration names use a plain ASCII command-identifier grammar. That validation does not sanitize the rest of the metadata: all names, descriptions and values remain trusted source-owned inputs because generated output is executable shell code.

The dependency edges use the already locked MIT-or-Apache-2.0 `clap` and `clap_complete` packages from `clap-rs/clap`, with default and dynamic-completion features disabled on the shared edges. No package version or runtime stack is added. The adapter is separate from product identity and result contracts. Registry publication, standalone feature audits and release size qualification remain required before downstream adoption.

The selected Bash generator encodes hyphenated roots inconsistently between transitions and child-detail labels. The shared renderer adjusts only internal Bash child paths while preserving the real registration name. Native regression tests reproduce empty `build-info --j` results in both Sync Configs and Update All before integration and require `--json` afterward. The adjustment is removed when native root, nested and hyphenated-command tests pass without it on the selected upstream version. Consuming the command tree prevents internal path changes leaking into later renderings.

The selected Fish generator explicitly stops generating below two subcommands, omitting implemented options such as Dev Auth's `workload bind plan --command-name`. The private Fish module retains the MIT-or-Apache-2.0 upstream 4.6.9 renderer with its attribution and MIT notice, extending the deep-path condition and traversal. It builds command metadata before rendering directly into a string, replacing the upstream panic-based I/O adapter without adding output authority. Native tests cover three/four-level options, visible aliases, option values, child commands and sibling isolation. Shallow Fish rendering and other non-Bash generators retain upstream bytes. This correction preserves upstream token-presence conditions; it is not a complete Clap argument parser, and positional completion or disambiguation of option values that equal subcommand names is not claimed. Remove the private module when the selected upstream renderer passes the deep-tree native regression without it.

Update All's managed completion inventory, trust, query, activation and startup-ownership contracts remain governed by its product ADRs 0009–0013. Only its trusted self-completion emitter changes. Dev Cache's optional atomic, idempotent file-output path remains product-owned and unchanged. Sync Configs now reports completion-output write failure as operational exit 1 rather than allowing the generator to panic on stdout failure. Existing operational grammar and persisted state remain unchanged.

The selected Elvish generator omits allowed option values entirely. The private Elvish renderer adapts the attributed upstream 4.6.9 command-tree renderer under the included MIT notice and emits visible choices after explicit long/short option tokens and visible aliases. It suppresses that value path after `--`, quotes metadata as Elvish strings, bounds display padding at zero and returns no candidates for unknown command paths. Native editor probes cover choices, repeated options, aliases and sibling isolation. Command-path resolution retains the upstream leading-subcommand-before-options model; positional choices, attached `--option=value` completion, variable-arity value consumption and options before subcommands remain unqualified. This is not a full Clap parser. Remove this module when upstream passes the native value regressions. Zsh and PowerShell retain upstream bytes; the earlier non-Bash preservation statement does not apply to this Elvish correction.

Dev Auth adds completion only inside the core public-command dispatcher after frontend identity and private-child routing. It does not bypass Git/GitHub, workload or helper entrypoints, load policy, enumerate profiles, read credential input or contact the broker. Static metadata excludes internal helpers and covers only implemented public commands, including the additive common identity interface governed by ADR 0002. Its retained no-argument build-info form and remaining common lifecycle migration are unchanged.

## Verification and acceptance

Dev Cache accepts the common `powershell` selector and retains its previous `power-shell` spelling as an input alias. Native qualification covers the canonical spelling; product regression tests preserve both accepted inputs.

The explicit [native completion qualification](../native-completion-qualification.md) lane sources generated scripts for every public product under real Linux Bash, Zsh, Fish, PowerShell and Elvish runtimes and checks root/nested candidates with registration-removal controls. It requires explicit runtime paths and never silently skips a requested test. This does not establish native Windows/macOS or complete command-tree acceptance.

Skills Sync adds early static completion dispatch without replacing its manual operational parser. Its product metadata covers current commands, nested lock actions and policy values without discovering local agents. Tests require generation despite invalid operational environment defaults and native Bash suggestions for build identity, nested lock options and policy values. Its mutating doctor behavior remains an explicitly incomplete common-interface migration, not a read-only claim.

`dev-tools-completion/tests/render.rs` covers invalid registration syntax, unchanged shallow non-Bash rendering and native Bash candidates for plain, underscored and hyphenated roots, plus an explicit native Fish deep-tree regression. Each consumer retains public-binary completion tests; the Sync Configs, Update All and Dev Cache `self_completion_bash_resolves_hyphenated_subcommand` tests reproduce the defect before integration and protect the corrected behavior. Artifact Update covers command-specific options, no configuration reads and no state mutation. Dev Cache retains `completion_file_generation_is_atomic_and_idempotent`. Workspace conformance covers the shared registry metadata. Native shell tests run only where the corresponding shell is installed; output generation and cross-compilation do not establish native five-shell or platform acceptance.
