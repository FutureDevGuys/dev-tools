# skills-sync

`skills-sync` reconciles agent skill discovery, locking, linking, adoption, dry-run, and JSON output from explicit public provider definitions. Personal source manifests, agent selection, and managed-lock policy belong to the caller.

`skills-sync build-info --json` emits the common checkout-independent `dev-tools-build-info-v1` document without reading lock files or invoking the upstream skills command. The hidden `--build-info` form remains for rollback to the pre-standard 0.1 line and is removed in the next minor release after one accepted release has shipped the standard subcommand.
