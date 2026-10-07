# Real receipt-installer native acceptance

Status: runnable source harness; actual native runs NOT RUN. This row uses the authentic standalone receipt installer and ordinary Dev Auth candidate. It does not use the synthetic privileged helper protocol to stand in for maintenance compatibility. The feature-built fixture executable supplies only the non-root controller, root fault observer and non-root document preparer.

## Prerequisites and independently approved inputs

Use one fresh, explicitly authorized disposable, network-free systemd guest with private cgroups/PID/mount/IPC/UTS namespaces, no host mounts and `/run/.containerenv`. The host must already satisfy Dev Auth's native platform and supported file/absolute-pipe `core_pattern` requirements. Do not change kernel settings to make a row pass. Supply a real non-root login with administrator approval and the signed/setup-qualified ordinary candidate, including the separate receipt-owned maintenance helper. Retain its independently built artifact hash and evidence that it was built without `native-privilege-fixture`.

Separately approve/deploy the standalone installer artifact and canonical root deployment record described in `docs/dev-tools-receipt-install-v1.md`. Its source/build identities must be independent reviewed evidence. A hash read from a newly copied user-home installation is not bootstrap approval. Record the supplied implementation's native loader/libc prerequisites; the own-computer debug artifact currently needs Linux x86_64 and GLIBC2.39. There is no source checkout at execution.

Provide two actual independently verified native generations of one selected tool, A and B, with distinct canonical receipt/artifact identities, identical tool/binary binding, and their original canonical receipt bytes. Deploy both in root0700 generation directories named according to the producer's existing rules (`syscfg-<canonical receipt SHA256>`), each containing the executable and root0600 `receipt.json`. Their source fingerprints and receipt digests are independently admitted inputs. No payload is executed during this acceptance. The implementation validates special modes/capabilities and final custody itself.

For each case, separately provision a fresh dedicated root0700 or0755 `/opt/dev-tools-maintenance/native-receipt-<case-id>/bin`, a matching root0700 `/var/lib/dev-tools-maintenance/journals/native-receipt-<case-id>/<binary>` and root-owned non-writable ancestors. The target binary, sidecar and journal state must initially be absent. Place a root0644 `unrelated-sentinel` with known bytes in the target. Do not reuse a target after interrupted writes. For `alias-denied`, explicitly provision the target as a bind alias of the admitted executor's parent instead; this destructive-test preparation is a separate administrator action in this disposable guest. The driver checks the actual same directory inode before trying admission. A passing transaction row with the same candidate/adapter is required as its positive control.

Deploy the separately built `dev-auth-privilege-native-fixture` observer/controller as an independently pinned root-owned ordinary executable. It is never selected as the privileged effect. No command below installs policy, deploys root assets or bypasses a native approval.

## Document preparation (non-root)

Create a private caller-owned0700 `/var/tmp/dev-auth-receipt-native-<case-id>` directory. Supply a caller-owned0600 preparation JSON document with exactly these fields:

- `schema`: `dev-auth-receipt-native-preparation-v1`
- `case`: `transaction`, `revoke`, `hard-expiry` or `alias-denied`
- `dev_auth`, `dev_auth_sha256`: ordinary installed candidate path and independently expected artifact hash
- `controller`, `controller_sha256`: root-deployed fixture executable path and independently expected hash
- `fixture_root`: the fresh private directory
- `audience`: `native-receipt-<case-id>` matching the explicitly provisioned system target
- `executor_receipt`: the complete independently approved deployment record object
- `executor_receipt_sha256`: exact canonical record hash, without prefix
- `receipt_a`, `receipt_b`: byte arrays containing the original independently supplied canonical producer receipts

Run `dev-auth-privilege-native-fixture receipt-prepare /absolute/preparation.json`. It writes new0600 `policy.json`, `request.json` and `executor-v1.json` documents in the fixture directory. These files are only review material; they are not root policy or deployment authority. The generated policy admits six exact plans,16 total/per-operation uses and180-second hard/idle/operation caps. The hard-expiry case uses30 seconds for all three, so an earlier idle or operation timeout cannot satisfy its gate.

After separate explicit root policy installation through the public digest/CAS setup interface, run the ordinary candidate:

```text
dev-auth privilege plan --request /var/tmp/dev-auth-receipt-native-CASE/request.json --output /var/tmp/dev-auth-receipt-native-CASE/approval.json --json
dev-auth-privilege-native-fixture receipt-input /absolute/preparation.json
```

The second command verifies the canonical public approval exactly resolves the supplied policy/request, then writes `real-input.json`. Supply an independently reviewed root-owned0600 copy of this final input to the root driver. The root copy still pins the exact public approval bytes/hash and independent A/B receipts. Keep the caller copy and its absolute name unchanged. Neither selector nor document creates a session.

## Run the native row

Start the explicitly authorized root observer in the same disposable guest:

```text
DEV_AUTH_NATIVE_RECEIPT_FIXTURE=disposable dev-auth-privilege-native-fixture receipt-driver /absolute/root-owned/input.json
```

It verifies actual root generations, controller image, deployment-record digest, clean setup exclusion and case prerequisites before publishing its exact root0644 ready marker. Then, as the native non-root observer, run the compiled integration test with the exact input:

```text
DEV_AUTH_NATIVE_RECEIPT_FIXTURE=disposable DEV_AUTH_NATIVE_RECEIPT_INPUT=/var/tmp/dev-auth-receipt-native-CASE/real-input.json cargo test -p dev-auth --features native-privilege-fixture --test privilege_receipt_native real_receipt_installer_reuses_one_approved_grant -- --ignored --exact --nocapture
```

The installed candidate named by the input remains the ordinary build. Cargo here is only one way to launch the precompiled test driver; the same test executable can be transferred and run with its usual `--ignored --exact` flags without a checkout, Cargo or network on the guest. Give the actual native administrator approval when requested. A declined prompt cannot count as alias denial because that row requires an authenticated root terminal observation.

## Exact finite cases

- `transaction`: within one grant, observe missing A, install A, status A, repeat install A unchanged, interrupt actual install B after its matching Pending journal is durable, resume B under the same grant, status B, explicitly reverse-replace A and status A again, then revoke. The observer requires actual helper SIGKILL metadata for the interrupted call. The root observer verifies exact final A executable/receipt/ownership/modes and unchanged unrelated sentinel
- `revoke`: stop the actual installer after its approved Pending journal is observed, then public revoke must kill it and every retained descendant. Completed or partial effects are not called rolled back
- `hard-expiry`: stop the actual installer at the same durable milestone; require real boot time to reach the retained hard deadline, equal idle/operation duration preventing earlier cancellation, positive domain cleanup and the defined successful terminal or independent killed-coordinator fallback. An unrelated early failure cannot count
- `alias-denied`: verify the target is physically the protected executor-parent inode, then require authenticated root admission rejection before the controller marker appears, no live maintenance unit and setup writer admission. This negative row requires the corresponding positive real transaction gate

The fault observer retains exact coordinator/helper pidfds and whole-service directory identity. It checks the actual controller inode/argv/owner and the real helper inode/argv/domain before any finite signal. It stops the selected helper, confirms stopped state and rechecks the matching Pending journal before killing it. A missed Pending window is a failed run, never relabeled as interruption. Use genuine approved artifact sizes/inputs and retain evidence; do not add a production sleep hook or synthetic replacement helper.

All successful terminal rows require positive whole-service cgroup emptiness/removal, coordinator death, removed handoff/control sockets, stale execute denial, released setup exclusion and root-driver completion. The independent setup writer must reject while the grant is active. The root observer never removes evidence or mutates installer journals. Stopped children are resumed on injector failure where possible; product hard expiry remains the outer safety bound. Retain failed-run evidence and clean the disposable guest only through its separately authorized lifecycle.

## Required companion gates

Run the27-case containment matrix in `PRIVILEGE-NATIVE.md` against its explicit feature candidate and signed installation/upgrade/restoration cases in `setup_v3/recovery_native/signed.rs`. Neither replaces the ordinary-build real-adapter row. Suspend/resume and genuine native platform approval remain required recorded qualification. Source compilation or all ignored tests listing successfully is not a native pass.
