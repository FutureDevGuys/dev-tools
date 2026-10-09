---
authority: canonical
owner: dev-cache
---

# ADR 0105: Opt-in retained Cargo final outputs

status: proposed
verification: pending

## Decision

`cargo.final_outputs = true` opts a configured machine into concrete, workspace-specific `CARGO_TARGET_DIR` routing for supported Cargo commands on Cargo 1.91 or newer. It defaults to false. The existing native-template intermediate route remains separate. Storage is beneath the selected runtime domain's reserved `outputs/cargo/<workspace>/<toolchain>` subtree; no machine-specific mount or private consumer path is product policy. Source trees, existing target directories and running builds are never moved or rewritten.

The workspace key hashes the canonical manifest reported by a bounded native `cargo locate-project --workspace --message-format=json` probe and the workspace directory's filesystem identity. It is independent of Dev Cache's broader Git/worktree grouping, so separate Cargo workspaces in one repository do not collide; members of one Cargo workspace share a target root. Manifest selectors are forwarded as native argv. The toolchain key hashes the selected compiler's verbose identity and canonical sysroot plus Cargo's verbose identity. A recognized Rustup proxy uses its selected/active toolchain, including borrowed Cargo for custom toolchains; explicit `rustup run` retains its selector. Direct Cargo observes the default PATH compiler. Explicit native compiler/wrapper configuration abstains rather than guessing. This is an observed toolchain identity, not immutable attestation of every linker, sysroot file or plugin across concurrent changes.

Cargo owns target-triple and profile subdirectories below the target root. Dev Cache does not invent separate dev/test or release/bench layouts, flatten profiles, parse custom target JSON, or share one global target directory. Final-output paths are concrete: Cargo's `{workspace-path-hash}` template is supported only for intermediate `build-dir` routing.

Initially admitted commands are `build`, `check`, `test`, `bench`, `run`, `doc`, `rustc`, `rustdoc`, `clean`, `metadata` and `locate-project`. Shorthand aliases and external subcommands are excluded because their expansion may select another workspace. Help/version, install/new/init, package/publish, unknown global options, nightly scope modifiers, duplicate manifest selectors and explicit output selectors retain native delegation. Custom build scripts and arguments after `--` can select their own outputs; they are not intercepted or sandboxed.

Explicit environment values (including empty values), CLI output/configuration overrides and persistent Cargo layout settings remain authoritative. Configuration is resolved from the invocation working directory, not the selected manifest's directory. Included configuration, `[env]`, custom compiler/wrapper settings, links, nonregular files and oversized/unreadable configuration cause conservative abstention. Configuration reads are capped at 1 MiB; new native identity probes close stdin, cap each output stream at 64 KiB and use the shared ten-second execution bound. Version capability probes use the same bound. Probes disable automatic Rustup installation and never forward `--install`; the actual user command retains its original arguments. Identity-probe failure on an otherwise admitted opt-in command is an error, not silent repository-local output creation. Native explicit/unsupported-layout abstention still delegates the original command, with a diagnostic for the new eligibility checks.

Exact inherited Dev Cache provenance permits nested workspace/toolchain rebinding, but never grants filesystem custody. When a nested command abstains, is disabled, or uses a native override, exact managed target/build directory and wrapper variables that are not reapplied are removed before delegation. User-edited values remain authoritative. Composed provenance never records itself. The existing read-only-root one-delegation fallback also removes exact inherited managed Cargo output settings; it remains a documented native-layout fallback, not a promise that failed storage can still accept outputs.

`dev-cache exec cargo cargo ...` uses the same opt-in routing path. In opt-in mode the program must be Cargo, not an arbitrary shell/build wrapper whose workspace cannot be established. `dev-cache path cargo --final-outputs [--repo DIR]` observes the selected root and resolves the effective current-toolchain path without creating output directories or catalog records. Set `RUSTUP_TOOLCHAIN` when querying another toolchain. Status includes the retained target path or an abstention reason. Normal `path cargo` retains its intermediate-path contract.

## Ownership, retention and accounting

`CargoFinalOutput` catalog records use `CleanupStrategy::Retain`. They retain the normal root/domain/path/generation identity, resource-specific activity lease and completion accounting. The reserved output subtree is outside disposable workspace/cache paths. Catalog validation rejects any disposable kind or strategy claiming it, and applied GC independently rejects actions overlapping the subtree. Existing nonempty, uncataloged final-output paths are never adopted. Preparation validates path components against links/reparse points before creating the new path.

GC observes but never selects retained output resources for stale, orphan or pressure deletion. They produce an explicit intentional abstention, not an incomplete-GC failure. `report.retained_outputs_bytes` is a subset of `other_bytes`; preserving the existing total equation avoids double counting for old report consumers. Retained bytes still contribute to total storage pressure and can create a truthful, irreducible size/free-space shortfall. They are not a durable backup: native `cargo clean`, user actions or external storage failure can remove them. Retaining Cargo's target tree does not establish that every example/test/dynamic executable remains runnable after disposable intermediate-cache cleanup.

No new mandatory root directories are introduced. Existing roots remain observable without materializing outputs. No implicit migration or repair of existing source-local target trees occurs.

## Compatibility and qualification

False configuration is omitted when serialized, so a default configuration remains readable by older binaries. Before rollback to a binary that rejects unknown config fields, remove the enabled `final_outputs` key. Older readers report new resource-kind records as catalog issues and do not understand this route; outputs remain outside their disposable trees. Keeping those records/outputs intact is preferable to an implicit downgrade migration.

This is a Cargo-specific final-output feature, not universal relocation of arbitrary build systems. Go output flags, compiler `-o`, Zig installation prefixes, Meson build trees, package-manager scripts and Python package output directories remain separate native contracts. Their currently supported caches keep their existing routing.

Source acceptance requires default-compatibility and opt-in public-binary tests covering workspace/member/manifest identity, toolchain differences, unchanged profile/triple arguments, native override precedence, nested provenance rebinding/abstention, bounded discovery, read-only path/report behavior, retained-resource lease/accounting, catalog tampering and stale/orphan/pressure GC. Native acceptance must additionally exercise real Cargo/Rustup workspaces and builds, output consumers and dynamic dependencies, interrupted/repeated commands, actual read-only storage and the selected supported operating systems. Compilation and synthetic tests do not establish signed distribution, installed activation, native platform acceptance or rollback qualification.

References: [Cargo build layout](https://doc.rust-lang.org/cargo/reference/build-cache.html), [Cargo configuration](https://doc.rust-lang.org/cargo/reference/config.html), [workspace discovery](https://doc.rust-lang.org/cargo/commands/cargo-locate-project.html), [Rustup custom toolchains](https://rust-lang.github.io/rustup/concepts/toolchains.html).
