# Explicit native container build cache

**Qualification status: native Docker acceptance and installed-release qualification are NOT RUN.** The command has a deliberately narrow source contract; source tests and fake socket responses do not establish supported native operation. Rootful and rootless qualification are separate gates.

`dev-cache container-cache` inspects a selected engine's native build cache and can request removal of explicitly selected eligible records. The engine owns the storage throughout. This command does not use the Dev Cache root, filesystem GC, automatic maintenance, intercepts, Docker CLI, Buildx, Docker contexts or Docker configuration. It creates no temporary directories. [ADR 0099](adr/0099-explicit-native-container-build-cache.md) owns the protocol and authority boundary.

## Command

Preview an explicitly selected Linux Unix-socket endpoint for Docker Engine:

```text
dev-cache container-cache docker --socket /absolute/path/docker.sock --json
```

Apply only after the preview establishes local-daemon attestation, choosing IDs and retaining the engine identity:

```text
dev-cache container-cache docker --socket /absolute/path/docker.sock \
  --apply --engine-id ENGINE_ID --storage-root /native/docker/root \
  --privilege-domain rootless --cache-id CACHE_ID --json
```

Use `--privilege-domain rootful` for a rootful engine. Repeat `--cache-id` for at most 32 distinct IDs. Apply requires all identity options and at least one ID. Paths must be absolute; the socket is a filesystem Unix socket, never a context name, URL, SSH destination or TCP endpoint. `--storage-root` is the expected native `DockerRootDir` identity; it is not a directory that Dev Cache may inspect or delete.

The fixed API is 1.51. The provider must identify as Linux Docker Engine and advertise an API range containing that version. Other provider implementations are not admitted merely because they accept Docker-shaped API requests. `dev-cache container-cache podman --json` reports unsupported without provider contact. Non-Linux operation is also unsupported.

Preview requests native observations only and leaves Dev Cache routing/configuration/root state untouched. It does not initialize or repair either product's storage. An unavailable or permission-denied socket is an error; the command does not discover another socket, elevate privileges, start an engine or alter its permissions.

## Local-daemon admission

A Unix socket can lead to an SSH/socat forwarding process instead of a local engine. Preview therefore reports `backend_locality` as `verified-local-dockerd` or `unverified`, separately from native engine identity, with a nullable `daemon_executable` path. Read-only accounting through an unverified endpoint does not authorize apply.

Apply requires positive native peer-executable evidence. The product uses the socket peer's PID/UID/GID, reads `/proc/PID/exe`, and verifies a root-owned ELF executable named `dockerd` through the existing held-executable custody checks. Executable and path ancestors must be root-owned and not group/world-writable. Links are rejected; product validation also rejects root-owned sticky writable directories, including `/tmp`, which the shared foundation can otherwise admit. The retained device/inode must match the peer executable target. Each connection rechecks the evidence; changed proof or scope stops further work.

If the executable cannot be read or proven, or the peer is a forwarding process, locality remains unverified and apply reports `blocked`, exiting 3 with `native-daemon-locality-unverified` before any POST. It first completes the three initial version, scope and accounting GETs, retaining useful read-only observations in the rejection result. The locality gate applies even if selected IDs are already absent. There is no trust flag, helper or automatic elevation. Docker-group access to a rootful socket does not guarantee permission to inspect the rootful peer's executable; such access may support preview only. Rootless use can qualify with a readable vendor-installed root-owned `dockerd`, but a user-owned installation cannot qualify for apply under this contract. Do not change ownership or weaken procfs/security settings merely to make a test pass. [Linux peer credentials](https://man7.org/linux/man-pages/man7/unix.7.html), [procfs executable access](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html).

Inherited or systemd socket-activated listeners can expose their original listening process's credentials rather than `dockerd`'s. When that prevents positive daemon attestation, apply remains blocked. Initial native acceptance uses a listener created directly by the qualified daemon; socket activation needs separate qualification and cannot bypass the same predicate.

The attestation trusts the root-administered executable and local process boundary. It does not establish signed-vendor provenance, defeat a compromised trusted daemon/root administrator or prove that native storage is on a local filesystem. Engine ID, root, privilege domain and record eligibility remain independent required checks.

## Selection and accounting

Native accounting exposes record identity, type, use/shared state and size. Known `regular`, `source.local`, `source.git.checkout` and `exec.cachemount` records may be eligible when inactive and unshared. Unknown types, active/shared records and unsafe or ambiguous responses cannot authorize deletion. Required identity and accounting fields must be present and correctly typed. An explicit native `BuildCache: null` is an empty cache list; missing `BuildCache` is invalid. Unknown or unavailable byte counts are never presented as a successful zero-byte observation.

Apply freshly observes the expected engine and selected records. A present-but-ineligible selection rejects the complete selection before mutation. An ID already absent from valid current accounting is a clean no-op and receives no POST. Repeating a successful apply whose IDs are all absent therefore completes with `changed=false`. Each selected eligible record receives one constrained native prune. Each fixes `all=false`, anchors the ID as an exact regex, matches the current allowed type and requires the native `private` presence predicate. For example, the unencoded filter object for one observed `source.local` record is:

```json
{"id":{"^g41agepgdczekxg2mtw0dujsv$":true},"type":{"source.local":true},"private":{}}
```

The adapter encodes this object into the query string. It never accepts arbitrary filter text. The empty `private` map is intentional: Moby maps it to a presence test. Boolean-looking equality strings such as `shared=false`, `inuse=false` or `private=true` do not implement these native presence predicates. Native reference locking supplies the final active-record check and `all=false` excludes shared/internal/frontend records. Engine-internal paired records and unreferenced metadata remain subject to native cleanup semantics. [Moby translation](https://github.com/moby/moby/blob/v28.3.3/builder/builder-next/builder.go), [BuildKit pruning](https://github.com/moby/buildkit/blob/v0.23.2/cache/manager.go).

The JSON result uses `dev-cache-native-cache-v1`. It separates before/after observations, selected and provider-reported deleted IDs, reclaimed bytes, and confirmed versus uncertain mutation. Summed eligible record sizes are an estimate, not a guarantee of physical disk recovery. Shared-byte accounting is separate. Successful provider deletion evidence survives a later observation failure. A partial batch is not rolled back; an interrupted or failed POST may already have changed native state. Such a result stops further mutation and must not be interpreted as a clean no-op. Review a fresh preview before deciding what to do next.

If the provider reports an ID deleted but it remains in the post-observation, the result fails scope verification while retaining `changed=true`. If a selected record remains eligible after a successful native no-deletion response, the result is `incomplete`, with `native-prune-deferred` and exit category 3. A record that became active or shared is preserved and can complete with its newly observed abstention. This distinguishes a satisfied selection, protected state and unfinished eligible work.

Images, containers, volumes, native engine directories and unrelated Buildx builders are outside this command. It neither relocates their data nor issues general prune operations. Independent builds and native automatic GC can change accounting concurrently; snapshots are not global engine locks.

## Transport limits

The product opens the explicit Linux Unix socket directly. Socket inode/owner and native peer PID/UID/GID observations bind successive connections; changed custody fails closed. It sends fixed HTTP/1.0 requests and accepts bounded close-delimited JSON responses. It does not resolve IP/DNS destinations, negotiate TLS, follow redirects, accept compressed responses or provide a general HTTP client. Unsupported framing and malformed/truncated responses fail closed. The write side remains open through response completion, avoiding premature native request cancellation.

Socket-protocol work has a 120-second deadline, initialized after the initial socket canonicalization and custody checks; each GET has a deadline of at most 20 seconds within the remaining budget, and response capture is limited to 8 MiB. Connection, write and read waits are bounded to 100 milliseconds so cancellation and remaining deadlines can be checked. These deadlines and cancellation checks do not interrupt synchronous filesystem/procfs or executable-custody calls, so they do not guarantee a hard wall-clock limit for the whole command. Ctrl-C requests orderly interruption; after mutation starts it cannot establish that the daemon stopped or rolled back. The only product-generated requests are:

- `GET /version`
- `GET /v1.51/info`
- `GET /v1.51/system/df?type=build-cache`
- `POST /v1.51/build/prune?all=false&filters=...` with the fixed predicate above

Ambient `DOCKER_HOST`, `DOCKER_CONTEXT`, Docker/Buildx configuration, proxy variables and CLI hooks do not participate. Stable local socket custody and matching native API fields alone do not prove backend locality; mutating requests additionally require the local-daemon admission above.

## Disposable native acceptance

This is a proposed qualification procedure, not a record of a completed run or permission to touch a workstation's engine. Use an explicitly disposable Linux VM with no host engine socket, host data-directory mounts, credentials, unrelated workloads or external network access. Pre-provision trusted runtime prerequisites separately. Do not install software, change services, grant permissions or change host security settings as an implicit part of testing.

Record the candidate source commit, binary digest and build information, OS/kernel/architecture, Docker Engine version/build, BuildKit dependency, storage driver, rootful/rootless mode, peer executable identity and locality result. The source-reviewed reference is Docker Engine 28.3.3, API 1.51, with BuildKit 0.23.2. Other engine versions and storage backends need their own recorded qualification; a successful HTTP response alone does not establish compatible filter semantics or local-daemon admission.

### Rootful setup

Use a fresh private directory such as `/run/dev-cache-native-acceptance`, mode 0700, inside the disposable VM. The fixture owns its `data`, `exec`, `run` and `fixture-contexts` children. Its `daemon.json` contains:

```json
{"features":{"containerd-snapshotter":false},"builder":{"gc":{"enabled":false}}}
```

Start the pre-provisioned daemon by its verified absolute executable path with these explicit arguments, expanding `R` to the fixture's absolute private directory:

```text
--config-file R/daemon.json
--data-root R/data
--exec-root R/exec
--pidfile R/run/dockerd.pid
--host unix://R/run/docker.sock
--storage-driver overlay2
--bridge none
--iptables=false
--ip6tables=false
--ip-forward=false
--ip-masq=false
--userland-proxy=false
```

There must be no other daemon or external containerd endpoint in the VM. Do not supply a host containerd socket or TCP listener. Disabling automatic builder GC makes record-survival assertions attributable to the test. The network options avoid implicit bridge/firewall changes within this isolated fixture. They are not a substitute for the VM boundary. Docker documents independent data/exec/config/pid/socket paths for multiple-daemon isolation. [Daemon options](https://docs.docker.com/reference/cli/dockerd/).

Observe the native engine ID and require `DockerRootDir` to equal the fixture data root. Require a valid `SecurityOptions` observation without `name=rootless`. The daemon must run the pre-provisioned root-owned ELF `dockerd` through root-owned admitted ancestors, and the test caller must already have permission to read its procfs executable evidence. Require verified backend locality before deletion cases. Run a separate nonprivileged socket-access case to confirm preview-only behavior when procfs evidence is unavailable. Stop immediately if any scope differs or prerequisite is missing; never fall back to an existing daemon or grant new access implicitly.

### Rootless setup

Use a separate fresh VM or reset disposable VM and a dedicated pre-provisioned unprivileged user. The official rootless launcher and its required user-namespace/runtime prerequisites must already exist. Give the run separate private absolute HOME, XDG_RUNTIME_DIR, daemon config, data, exec, pid and socket paths. Start only its test daemon through the official rootless launcher with the equivalent explicit isolation arguments and a qualified storage driver. Do not run the installation/setup tool, enable a user service or modify sysctls during this test. [Rootless runtime guidance](https://docs.docker.com/engine/security/rootless/tips/).

Require `name=rootless` in the decoded native security options and the expected engine ID/root. The peer must execute a pre-provisioned vendor root-owned ELF `dockerd` with readable procfs evidence and admitted root-owned ancestors. Require verified backend locality for deletion cases; a user-owned daemon installation is a negative read-only case, not a reason to weaken admission. Repeat the entire acceptance matrix. A rootful result does not qualify rootless behavior; an overlay2 result does not silently qualify another storage driver or the containerd image store.

### Offline fixtures

Prepare fixture data through a separate test-only direct Engine API client. This setup client may use fixture-creation endpoints; those endpoints must never enter the product adapter's allowlist. The product itself requires neither that client nor a Docker CLI.

1. Submit at least two distinct tar contexts containing `FROM scratch`, `COPY payload /fixture`, and independent payload bytes. Use BuildKit `version=2`, `networkmode=none` and `outputs=[{"type":"cacheonly"}]` on the native build endpoint. This requires no pull, registry, external Dockerfile frontend or Buildx plugin. Positively observe at least one eligible selected record and one independent unselected sentinel.
2. Submit a separate scratch build with native image export to create an image and shared-cache sentinel. Record its image identity. Create explicitly named fixture-only container and volume sentinels through the setup client, then record their identities and payload checksums where applicable.
3. For active-reference testing, copy a trusted static fixture executable into a scratch context and keep a native build running in an explicit bounded wait with `networkmode=none`. Positively observe active cache records before attempting the negative case. Stop that fixture through its own bounded setup controller after the assertion.
4. Capture complete exposed cache/image/container/volume inventories. Missing expected eligible, shared or active states invalidate setup; never compensate by relaxing filters or using a broad prune.

### Acceptance matrix

| Case | Required evidence |
| --- | --- |
| Preview | Only allowed GETs; unchanged exposed cache and sentinel inventories, fixture bytes, and Dev Cache root/configuration state. |
| Local daemon | Readable, root-owned held ELF `dockerd` identity matches the native peer; locality remains stable on every connection before apply. |
| Unverified locality | Forwarding proxy, unreadable procfs executable, user-owned/non-ELF/wrong-name executable, group/world-writable ancestry (including sticky directories), or an unprovable inherited listener permits only otherwise-valid preview accounting; apply reports blocked, exits 3 with `native-daemon-locality-unverified` and issues no POST. |
| Changed attestation | Changed peer, executable identity, socket custody or locality proof stops further work; already confirmed mutations remain accurately reported. |
| Exact deletion | At least one positively eligible selected ID actually disappears; response deleted IDs contain only that request's ID; fresh post-accounting succeeds. A zero-deletion HTTP 200 does not pass. |
| Unselected isolation | Independent unselected IDs, shared-cache sentinel, exported image, containers, volumes and fixture bytes remain. |
| Wrong scope | Wrong engine ID, root or privilege domain causes no POST. Repeat with scope changing between observations. |
| Invalid selection | Omitted apply IDs, duplicate/unsafe IDs, more than 32 IDs, unknown types, active/shared records and missing/malformed required fields cause no POST. A present-but-ineligible record rejects the entire selection. |
| Already satisfied | Selected IDs absent from valid current accounting receive no POST. Repeating a successful apply completes with `changed=false` when all selected IDs are absent. |
| Post-observation truth | A reported deleted ID that remains is a scope failure retaining established change. A selected eligible record that remains produces incomplete/deferred exit 3; a newly protected record remains with its observed abstention. |
| Empty accounting | Explicit `BuildCache: null` and `[]` represent empty lists; omitted or malformed accounting fails. |
| Native race | A selected record becoming active or shared before prune is protected by native checks. Record actual protected state; a fake response is insufficient. |
| Partial results | Interrupt/fail a later request after earlier confirmed deletion; preserve confirmed progress, stop remaining requests and accurately report uncertain effects. |
| Response failure | Delayed/truncated/oversized/malformed responses and provider disconnects terminate within bounds; post-POST failures never claim known no change. |
| Cancellation | Connect/read/write stalls and Ctrl-C settle promptly within the operation deadline; delayed native responses are not prematurely cancelled by a write-half close. |
| Ambient inputs | Conflicting Docker host/context/Buildx/proxy/hook inputs do not change the explicit Unix destination or invoke another process. |
| Unsupported scope | Podman and non-Linux entrypoints report unsupported without contact; remote URLs and invalid socket custody fail closed. |

Adversarial fake-socket fixtures can establish client-side rejection, exact request encoding, framing limits and deterministic race sequencing. They cannot replace native deletion, active/shared protection, local-daemon admission or rootful/rootless acceptance. An ordinary fake socket server must fail apply's locality check; source-level mutation fixtures need an internal test seam, never a production trust override. Capture allowed-request traces, before/after inventories, product JSON and process exit results. Mark every unexecuted case NOT RUN rather than skipped-success. Retain evidence outside the disposable VM, then destroy the whole VM; do not use general engine prune as cleanup. Signed installed-artifact and clean-device product acceptance remain separate release gates.

Reclaimed-byte accumulation is checked. If it overflows, `reclaimed_bytes` is null and the operation fails while retaining every provider-confirmed deleted ID and established change.
