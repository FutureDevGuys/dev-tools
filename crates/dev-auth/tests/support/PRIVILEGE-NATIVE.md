# Runnable finite maintenance-session matrix

This harness is opt-in test code, not a product helper, installer, policy bypass,
credential source, or unattended approval agent. The generic fixture protocol is rejected by ordinary product builds. Its test
feature never qualifies the released signed adapter by itself. No root/native acceptance has
been run in the source-only cloud container. Every privileged row is NOT RUN
until its actual isolated guest run succeeds. Compile/source tests are separate.

## Build and source-only checks

Serially, using the repository's normal toolchain and target directory:

```
cargo test -p dev-auth --features native-privilege-fixture --test privilege_native --bin dev-auth-privilege-native-fixture
cargo clippy -p dev-auth --features native-privilege-fixture --test privilege_native --bin dev-auth-privilege-native-fixture -- -D warnings
```

The default test run executes the real unprivileged stopped-process kernel timer
and closed-input/fixture-safety contract tests. The public-session test stays ignored. Compile
success cannot establish administrator approval, containment, cleanup or support.

## Explicit native prerequisites

Use a freshly owned, disposable rootful Linux guest/container with PID 1 systemd,
a private cgroup-v2 hierarchy supporting cgroup.kill and pidfds, mount/PID/IPC/UTS/
network namespace support, native open_tree/mount_setattr/move_mount, and
`/run/.containerenv`. The controller-gate row also requires the root fixture
observer to read the target process syscall state through `/proc/PID/syscall`;
an unavailable observation fails the row rather than weakening its precondition. Do not run this on a host or
with host secrets, host resource mounts or the user's real configuration. A
marker alone is not isolation: the operator must provision the actual guest.
The harness requires a readable supported native core profile. File patterns and
absolute pipe handlers are admitted with the process-local immutable CORE1 guard;
@/@@ socket collectors reject. A privileged SIGSEGV must not invoke an out-of-domain
collector. The three cases in CORE-NATIVE.md require an already configured isolated
collector and acknowledged positive controls; source checks alone do not qualify it.

The synthetic containment guest must already contain a separately authenticated
installed test candidate built with `native-privilege-fixture`,
its complete maintenance receipt/helper/action assets, a real non-root logind
session with `/run/user/UID`, an administrator account, and a native polkit agent
that can perform non-kept administrator authentication. Native approval is manual
once per fresh grant. This harness never creates accounts, installs artifacts,
changes approval policy or enters credentials. Pin the compiled fixture binary
in a root-owned mode-0755 ordinary file under the guest's public `/usr` runtime,
for example `/usr/local/lib/dev-auth-privilege-native-fixture`. Never install it as a
product helper, set-ID binary or polkit-authorized executable.

Prepare each case in a new caller-owned mode-0700 direct child directory named
`/var/tmp/dev-auth-privilege-native-CASE-UNIQUE`. As that non-root user run:

```
/usr/local/lib/dev-auth-privilege-native-fixture prepare CASE /usr/local/bin/dev-auth /usr/local/lib/dev-auth-privilege-native-fixture FIXTURE_ROOT
```

This only creates a mode-0700 `scope` directory and canonical nonsecret
`policy.json` and `request.json`. Review the exact finite native fixture audience.
An explicitly authorized administrator must copy the policy to a root-custodied
source and use the candidate's digest-bound `setup install-privilege-policy` (or
CAS `update-privilege-policy` for a reused disposable guest). Installing policy is
an independent authorization step; this document does not authorize it.

After the policy is installed, the non-root user runs the public plan command:

```
dev-auth privilege plan --request FIXTURE_ROOT/request.json --output FIXTURE_ROOT/approval.json --json
/usr/local/lib/dev-auth-privilege-native-fixture write-input CASE /usr/local/bin/dev-auth /usr/local/lib/dev-auth-privilege-native-fixture FIXTURE_ROOT FIXTURE_ROOT/approval.json
```

`input.json` is closed-schema, caller-owned mode 0600 and pins the canonical
approval digest. There are no shell-command, PID, arbitrary path-effect or fault
command fields. All exact plans use the single disposable `scope` resource and
fixed compiled helper subjects. The test rejects other resources/arguments,
stale effects, changed fixture digests, long leases and unsafe input ownership.

For the ten root-fault cases below, an authorized administrator must first copy
that exact input to a root-owned mode-0600 document beneath root-owned parents,
then explicitly start this non-installed test binary as root inside the guest:

```
DEV_AUTH_NATIVE_PRIVILEGE_FAULTS=disposable /usr/local/lib/dev-auth-privilege-native-fixture fault-driver /fixture-input/CASE.json
```

Leave that process running in a separate guest terminal. It publishes a checked
ready marker, waits for the pinned session/controller and an established root
heartbeat, applies only the selected finite fault, checks native setup exclusion,
and exits after terminal whole-service cleanup. It never obtains a grant. The
observer remains non-root throughout:

```
DEV_AUTH_NATIVE_PRIVILEGE_FIXTURE=disposable DEV_AUTH_NATIVE_PRIVILEGE_INPUT=FIXTURE_ROOT/input.json cargo test -p dev-auth --features native-privilege-fixture --test privilege_native public_reusable_session_approval_execution_and_terminal_cleanup -- --ignored --exact --nocapture
```

Alternatively run the already compiled test executable with the same filter and
environment; Cargo/source/toolchain are not installed-product dependencies.
Complete the real native administrator prompt. Record the exact candidate,
policy/plan/fixture digests, case, command, test exit, root-driver exit, and logs.
A timeout or absent result is a failure, never a skipped/passed row. Reset the
entire disposable guest after an interrupted root fault; do not improvise host
cleanup or rerun over uncertain retained state.

## Finite executable cases

- reuse: two distinct root writes, later repeated write, native root ownership,
  denied unknown plan, namespace/syscall and post-ELF capability-mask probes
- revoke: explicit owner revoke while a double-forked, setsid, TERM-ignoring root
  descendant writes; wait for authenticated cleanup and prove no later writes
- hard-expiry: detached root operation with equal idle/hard caps; independent
  lifetime terminates both payload domains
- idle-expiry: idle controller with a shorter idle cap; finish before hard cap
- near-idle-admission: status-poll until 600ms before the old two-second idle
  deadline, admit a 750ms operation across that deadline, then prove continued
  polling cannot postpone the renewed idle expiry
- coordinator-death (root driver): SIGKILL retained coordinator pidfd while both
  payload domains are populated; preserve failed/unknown execution result
- bootstrap-death (root driver): kill exact root bootstrap identified by its
  retained handoff listener and pinned approval; no terminal receipt is assumed
- handoff-bootstrap-death (root driver): bind the exact request frontend, its
  root bootstrap and existing native handoff listener/service; pause retained
  bootstrap/coordinator pidfds, require no controller domain or controller marker,
  kill bootstrap and resume coordinator. The observer retains the original unit
  before the fault; the driver waits original guardian/systemd-run pidfds, requires
  no protected effect and no stale handoff/control endpoint. A missed early
  window fails the case and resumes stopped processes; it is never relabeled
  as active-session death. No production sleep or gate bypass is used
- controller-gate-bootstrap-death (root driver): require an existing controller
  domain, freeze its coordinator, and retain the sole root pre-exec child. The
  child must still have the coordinator executable/argv and be sleeping in the
  one-byte native socket receive gate. Kill exact bootstrap and resume coordinator;
  require that no controller marker/effect appears and all retained pidfds/domains
  terminalize. This is distinct from the earlier no-controller-domain row
- guardian-death (root driver): kill the exact transient service's cgroup domain.
  The current guardian is systemd's service boundary, not a second product daemon
- malformed-ipc: invalid JSON/version/ID/unknown caller-PID field, zero/oversize
  frame, slow partial frame and unsolicited SCM_RIGHTS all reject without effect,
  deadline refresh or budget consumption
- identity-denial: an outside-controller process copies session/UID environment
  hints and requests a valid plan; kernel identity rejects without root effects
- policy-replaced (root driver): replace the policy inode with identical bytes;
  stop existing authority and restore the exact retained original afterward
- helper-replaced (root driver): same-byte inode replacement of maintenance helper
- resource-replaced: rename the retained scope and create a same-name replacement;
  neither old nor replacement scope acquires an unapproved effect
- nested-resource-mount (root driver): before the grant, attach a private
  read-only bind of a synthetic root-only sentinel directory beneath scope/nested.
  Both source and target are held by fd; the source is outside the approved scope.
  Before the grant, require the driver and PID1 to share their mount namespace and
  prove the same sentinel inode/bytes are visible through PID1’s rooted view.
  The admitted helper must see the empty underlying mountpoint, cannot read or
  write the sentinel, and can subsequently reuse the grant. After terminal
  observer proof, verify the sentinel unchanged, unmount the retained fixture
  and remove only its exact empty mountpoint. No mount is created on the host
- busy: hold one transaction, reject a concurrent valid transaction with `busy`,
  then prove only the accepted use was consumed
- replay: reuse the exact accepted request ID with a different allowed plan;
  reject without a second effect or budget consumption
- exhaustion: consume the selected three-use shared/operation budget, deny further
  work, verify exact root effect count and reject the stale session
- blocked-io: fixed binary output fills an intentionally undrained 4096-byte pipe
  in the first execute frontend; a second admitted detached root operation runs
  concurrently with that blockage, and independent expiry kills both domains
- setup-exclusion (root driver): exact native writer-admission probe (shared lock plus
  orphan cgroup fence) denies while payloads are populated and permits after
  verified cleanup
- cleanup-failure (root driver): corrupt the exact held operation cgroup's custody
  mode so retained cleanup cannot certify success; preserve a failed/nonzero
  result even if systemd later independently proves emptiness; restore only the
  retained fixture inode and check exclusion throughout
- leader-exit: a double-forked TERM-ignoring root writer proves its first
  heartbeat, then the actual helper leader exits23. Require CLI/result23,
  positive operation cleanup and stable heartbeat before a later successful
  operation reuses the same grant
- signal-fidelity: exact binary stdin/stdout/stderr, self-SIGTERM and self-SIGSEGV;
  result documents must retain signal identity rather than only numeric 128+N

All cases check no stale execute revival and independently retain/observe the
original kernel service domain, require empty/removed state, removed control
endpoint, and stopped heartbeat when applicable. The feature-only writer probe is read-only and invokes the actual Strong
writer exclusion without mutating installation state. This is sampled
observation, not a formal proof of absence of every sub-sampling race.

The established-session, pre-controller-domain and retained-controller-gate
death rows are separate executable cases with different required observations. The early row
requires an already-created native service and no controller domain; it does not
pretend to cover every instruction boundary before native guardian creation.
Actual suspend/resume, session logout, broader handoff-race qualification and
real consumer compatibility remain separate native gates. Do not rename these
narrower tests as proof of those gates.

## Signed upgrade and exact rollback

Reuse the existing native signed-release fixture rather than a synthetic receipt
or downloaded executable presented as signed evidence:

```
DEV_AUTH_NATIVE_SYSTEMD_FIXTURE=disposable cargo test -p dev-auth --lib setup_v3::recovery_native::signed::native_disposable_signed_v3_patch_upgrade_and_restore -- --ignored --exact --nocapture
```

That root-only fixture requires a separate fresh disposable systemd guest, exact
authentic release sets under `/signed/prior` (0.4.0) and `/signed/candidate` (the
candidate package version), and explicit authorization for its account creation
and public signed setup/apply/restore actions. It uses real verify-release,
plan/apply/verify, repeat/no-op checks and exact retained restoration. Missing
signed candidate bytes are a blocking prerequisite, not permission to generate
fake release provenance. Run maintenance session approval cases separately after
candidate installation; signed release authenticity never grants execution.

The separate retained-maintenance-policy fixture is also runnable:

```
DEV_AUTH_NATIVE_SYSTEMD_FIXTURE=disposable cargo test -p dev-auth --lib setup_v3::recovery_native::signed::native_disposable_signed_maintenance_prior_policy_preservation -- --ignored --exact --nocapture
```

It uses the same exact `/signed/prior` and `/signed/candidate` layout, with
`DEV_AUTH_SIGNED_MAINTENANCE_PRIOR_VERSION` defaulting to `0.5.0`. The prior must
be at least 0.5.0 and no newer than the candidate. Equal versions require identical
artifact bytes; in that case a benign configuration comment creates a real
retention/restoration transaction, explicitly not a version-upgrade claim. The
0.4-to-candidate fixture separately checks helper/sidecar/polkit custody,
absent-policy denial and complete maintenance-group absence after 0.4 restoration.
Both signed rows still require actual authentic artifact sets and a native run.

## Pipe collector qualification

The matrix now includes `core-collector`, `core-coordinator-death` and `core-bootstrap-death` (27 cases total). Their preconfigured isolated-kernel collector, positive controls and exact native-negative proof are specified in [CORE-NATIVE.md](CORE-NATIVE.md). The root driver never writes core_pattern. Pipe support uses inherited immutable CORE1; @/@@ socket collectors still reject. `core_limit_filter_survives_native_child_exec_and_rejects_writes` is a separate unprivileged no-crash source check, not collector qualification.
