# skills-sync

`skills-sync` reconciles agent skill discovery, locking, linking, adoption, dry-run, and JSON output from explicit public provider definitions. Personal source manifests, agent selection, and managed-lock policy belong to the caller.

Use `skills-sync repair` for the broad repair workflow; preview with `skills-sync repair --dry-run` and retain your existing scope and provider arguments. `doctor` currently remains an equivalent mutating compatibility spelling, and both emit the legacy JSON `command: "doctor"` value. This expansion does not change existing workflows or implement the common read-only doctor. [ADR 0014](adr/0014-skills-sync-explicit-repair-transition.md) defines the release and consumer-migration gates before that later change. Repair can run the selected upstream provider; it is not a network-free diagnostic command.

`skills-sync completion bash|zsh|fish|elvish|powershell` prints static shell code from product-owned command metadata without reading operational environment settings, inspecting skills or locks, invoking an upstream command, or editing startup files. It preserves the existing operational parser and describes implemented commands, including the currently mutating `doctor` workflow; it does not imply completion of the common read-only doctor/update migration.

`skills-sync build-info --json` emits the common checkout-independent `dev-tools-build-info-v1` document without reading lock files or invoking the upstream skills command. The hidden `--build-info` form remains for rollback to the pre-standard 0.1 line and is removed in the next minor release after one accepted release has shipped the standard subcommand.
