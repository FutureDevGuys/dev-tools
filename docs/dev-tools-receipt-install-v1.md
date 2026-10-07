# Standalone receipt-install protocol v1

This optional, finite maintenance adapter is implemented in the unreleased Dev Auth 0.5 candidate. It does not require a sibling product, source checkout, interpreter, Git, registry, network or user-home installation. An independently approved native artifact implements the interface. The current supplied implementation reuses Syscfg's existing receipt/journal installer; Dev Auth neither contains another installer nor executes the installed payload.

## Authority and bootstrap

The administrator separately approves and deploys an exact root-owned ordinary mode-0755 ELF at `/usr/local/lib/dev-tools-maintenance/executors/<executor>/executor` and a root-owned mode-0644 canonical JCS record beside it at `executor-v1.json`. All ancestors have native-root custody and no other-writer permission. No special bits or file capabilities are permitted. This is explicit deployment evidence, not a new signature, signing authority, installer self-report or automatic trust-on-first-use.

The closed record fields are `schema` (`dev-tools-maintenance-executor-v1`), `protocol` (`dev-tools-receipt-install-v1`), `executable`, `executable_sha256` (64 lowercase hex), `executable_length` (1..268435456), `source_fingerprint` and `build_receipt_sha256` (both `sha256:` plus 64 lowercase hex). The source and build receipt identities must come from independently reviewed build evidence. Copying a user-owned program and reading its own receipt does not establish this authority.

The Dev Auth operation's `adapter` object independently pins `receipt_path`, the exact raw record `receipt_sha256` (unprefixed hex), `source_fingerprint` and `build_receipt_sha256`. Every exact plan separately pins the executable path/hash. Adapter metadata is part of the immutable operation definition digest. Root admission verifies the entire binding, ELF length/hash/custody, resources and physical identities; these checks repeat before native operation release. Public planning needs only the nonsecret supplied metadata, not read access to private root generations.

Installing this record/policy is a separate privileged deployment decision. This source patch does not deploy it. Root policy defaults to absent/deny and is installed only through the existing digest/CAS setup interface. A helper installation or policy document does not itself create a grant.

## Closed request

The only argv is `maintenance-v1`. Cwd is `/`; the environment is empty. Stdin is an anonymous regular memory file sealed against writes, growth, shrinkage and seal changes, positioned at zero, with 1..65536 bytes. The producer accepts neither a pipe nor an ordinary file as a substitute.

The request is compact canonical JSON with these lexicographically ordered keys and no newline:

- `action`: exactly `status`, `install` or `resume`
- `binary`: exact installed command identifier
- `candidate`: required artifact object
- `destination`: `/opt/dev-tools-maintenance/<audience>/bin`
- `journal`: `/var/lib/dev-tools-maintenance/journals/<audience>/<binary>`
- `previous`: required artifact object or explicit null
- `schema`: `dev-tools-receipt-install-v1`
- `tool`: exact receipt tool identifier

An artifact has `generation`, `receipt_sha256` and `source_fingerprint`, in that order. Digests use `sha256:` plus 64 lowercase hex. The generation is one opaque lowercase identifier (up to128 bytes) below `/var/lib/dev-tools-maintenance/generations/`. The owning implementation verifies its filename/receipt relationship; Dev Auth does not add a producer-specific naming rule. The supplied Syscfg implementation requires its existing `syscfg-<canonical-receipt-digest>` name. Tool/binary/audience/executor identifiers contain lowercase ASCII letters, digits, hyphen or underscore, up to64 bytes.

Unknown or duplicate fields, omitted fields, noncanonical JSON, path normalization tricks, extra argv/environment, mismatched tool/source/binary/receipt and a candidate equal to its predecessor reject. Status requires `previous:null`.

## Effects and resources

The candidate and optional predecessor generations are read-only. Destination and journal are read-write only for install/resume; status mounts both read-only and never creates/opens a journal lock for writing. Generations and journals are root0700; the dedicated destination is root0700 or0755. Every ancestor has no-follow root custody. The resource map must match the derived names, paths and access exactly. Distinct names sharing one directory inode reject. Writable bind aliases of retained adapter/receipt/Dev Auth enforcement or protected runtime/hook parents reject.

Install uses the existing guarded artifact publication, journal and unknown-occupant rules. It changes only the selected executable/receipt pair and its bounded staging/lock/journal material. Special-bit and file-capability publication is rejected. It does not execute the payload, publish global aliases, refresh PATH, change services/accounts/kernel policy, install dependencies or perform network actions. A reverse replacement requires a separate exact plan naming the retained candidate and approved current predecessor; it is not implicit rollback authority.

Resume acquires the existing journal lock and matches the retained full candidate receipt, exact generation/destination/tool and Pending predecessor before any recovery write. A settled Current record may already have dropped its predecessor, but must still match the approved candidate/path. Unbound path-only recovery and legacy script intents reject. The existing installer, rather than the wrapper, proves an interrupted known pending hardlink before recovery; final installed files return to strict single-link custody.

Dev Auth's shared setup exclusion stays held throughout the grant. The dedicated installer uses its own journal lock, so there is no upgrade to Dev Auth's setup lock. Dev Auth self-upgrade, policy mutation, adapter replacement and shared enforcement-containing destinations remain outside the live grant. Use the normal signed setup route after complete session cleanup.

The approval display exposes action/tool/binary, candidate/predecessor receipt identities, exact resources and executor evidence. Each typed installer status/install/resume consumes one use; plain session status neither consumes a use nor renews idle time.

## Result and interruption

Stdout is one compact canonical JSON document, without trailing newline, with fields `attempted`, `cleanup_errors`, `error`, `outcome`, `retained_staging`, `schema`. Schema is `dev-tools-receipt-install-result-v1`. Successful outcomes are `current`, `changed`, `unchanged` and exit0. `rejected` exits2; operational `failed` exits1, or128+signal for cooperative HUP/INT/TERM. Error/staging are nullable. `attempted` describes entry into the guarded installer, never an assertion that mutation happened or rollback completed.

The canonical status success vector is:

```json
{"attempted":false,"cleanup_errors":[],"error":null,"outcome":"current","retained_staging":null,"schema":"dev-tools-receipt-install-result-v1"}
```

A missing/malformed/inconsistent report cannot become CLI success even if the helper exits0. Native signal/exit metadata remains separate. Abrupt interruption preserves unknown effects; positive process cleanup cannot undo a completed filesystem effect. A later already-approved resume can reconcile a retained matching journal. A malformed normal-exit report stops the grant. Cleanup failure is sticky.

## Qualification

Source/ABI tests are distinct from native approval and execution. The real-artifact matrix is [RECEIPT-NATIVE.md](../crates/dev-auth/tests/support/RECEIPT-NATIVE.md). The27-case synthetic containment matrix and signed setup fixtures remain separate required gates. All new native runs remain NOT RUN until explicit disposable native deployment and administrator approval. The host must already meet the documented systemd/cgroup-v2/pidfd/mount/seccomp and supported file/absolute-pipe core profile prerequisites; this adapter changes none of them.
