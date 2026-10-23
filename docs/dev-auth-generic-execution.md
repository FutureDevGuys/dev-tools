# Configured consumer projection and generic execution

The new source candidate in [ADR0135](adr/0135-admission-bound-workload-environment-projections.md) attaches administrator-capped environment projections directly to the existing trusted consumer. This is the narrow route when policy pins a specific executable. Synthetic Linux user-only configured-consumer and standalone secret-exec acceptance passed. Strong, actual Sudo and signed delivery remain separate pending gates.

The composition below is the separate broad arbitrary-command route. It is not a substitute for configured-consumer security and is not an active deployment instruction.

## Narrow configured-consumer interface

The existing public command remains:

```text
dev-auth workload launch generic-worker --non-interactive -- argument
```

The trusted launcher is the consumer's canonical executable, not Dev Auth or an
extra shell wrapper. Its administrator workload cap permits exact destinations;
the user workload narrows that list. Both use the same data-only declaration:

```toml
secret_projections = [
  { resource = "service-token", kind = "environment", target = "SERVICE_TOKEN" }
]
```

This is a fragment, not a complete policy or permission to activate it. Existing
logical resource, credential-slot/provider, native-user, read and environment-
projection selection must also resolve through the cap/profile/workload chain.
The resource must be exportable. No credential value belongs in these files.

The configured consumer, raw arguments, cwd, streams and existing native lifetime
remain authoritative. There is no application-specific adapter. The broker's
admission digest fixes the consumer path and exact destinations; final execution
retains the executable before reads and rechecks admitted identity/deadline after
all values are ready. Missing/denied material does not use an ambient fallback or
start a partially populated target. Same-owner executable replacement before the
hold and authorized in-place writes retain their existing trust limits.

The first declaration supports environment projection only. Runtime/admission,
loader, managed Git/GitHub/SSH and shell controls are reserved. Other unrelated
inherited environment is not claimed to be sanitized. Standalone `secret exec`
continues to support the four forms under its different arbitrary-command policy.

Run the installed configured-consumer acceptance fixture with:

```text
cargo test -p dev-auth --locked --test cli generic_projection::installed_configured_projection_keeps_native_consumer_authority -- --exact --test-threads=1 --nocapture
```

It uses only disposable synthetic material and tests native/stock consumers,
raw-argv non-substitution, missing and late provider failure, admitted mapping
changes, deterministic path replacement during retrieval and session cleanup.
A transferred runner uses fixture-only `DEV_AUTH_TEST_PRODUCT` as described below.
Neither this fixture nor source tests prove native Sudo or signed deployment.
For Strong launch grants, final activation follows projection success; delayed
retrieval must still satisfy the existing bootstrap deadline and cleanup gates.

## Separate broad generic composition



Dev Auth already has two separate public operations: `workload launch` admits a
configured workload; `secret exec` projects that workload's authorized logical
resources into an ordinary executable. Neither operation requires a consumer
SDK, an application adapter, a sibling product or a new secret broker.

## Explicit composition

Select a workload whose trusted launcher is the **canonical regular-file path
of the ordinary installed Dev Auth executable**. Resolve that path from the
accepted installation, not from caller PATH. Do not select the symlink alias,
the dedicated set-user-ID launcher, or an unverified candidate. The existing
setup/policy review and activation rules remain mandatory.

The administrator resource cap, user authority profile and workload selection
must all permit the logical resource's `read` purpose and the selected projection.
The resource must be exportable. For example, the matching selection fragment is:

```toml
purposes = ["read"]
projections = ["environment"]
```

This fragment is not a complete policy or permission to activate a workload.
Provider references belong only in the existing administrator/provider
configuration. The caller uses a logical name:

```text
dev-auth workload launch generic-worker --non-interactive -- secret exec --env SERVICE_TOKEN=service-token -- /absolute/program argument
```

The first separator belongs to workload launch; the second belongs to secret
exec. Arguments are native argv, not shell source. The application path and its
ordinary arguments are caller-selected within the admitted workload. Trusting
Dev Auth as this launcher authorizes this generic execution surface, not just
one particular downstream application. A deployment that requires an exact
application entry point must not silently replace that entry-point policy with
the generic launcher.

Other existing projections are `--stdin RESOURCE`, `--fd FD=RESOURCE` and
`--file VARIABLE=RESOURCE`. File projection exposes an anonymous sealed
descriptor path, not a persistent secret file. Environment projection is explicit
and has the ordinary child-environment exposure boundary; it is not a stronger
secret channel. The parent environment is not modified.

A noninteractive request does not grant admission. Approval-required workloads,
missing enrollment, denied resource/projection rights and unavailable providers
fail closed. There is no ambient-file or direct-provider fallback. All requested
values must be acquired and the same admission/deadline revalidated before the
consumer starts, including when a later resource fails after an earlier read.

`--result-file` can be selected independently on each operation. Child stdout
and stderr remain the child's streams and may contain whatever the child writes.
Only Dev Auth's separate control results/diagnostics are value-free. The outer
launch may report `started: null`; do not reinterpret it as proof the final
consumer started. The inner secret-exec result reports its own child observation.

### Normal aliases are a separate contract

A structured workload binding deliberately rejects the installed Dev Auth
executable as its own target. This explicit composition does not bypass that
cycle guard or establish transparent same-name alias support. Consumer-owned
configuration may invoke the public command, but must preserve its intended
entry-point restrictions and direct-authentication alternatives.

## Privilege and actual Sudo

Credential admission runs the ordinary workload as its native user. The finite
maintenance `privilege request/execute` family and the administrator-grant/Sudo
family have separate authorities. A successful generic credential operation
proves neither privileged execution nor stock Sudo authentication.

The existing launch-with-grant controls are explicit and separately approved:

```text
dev-auth workload launch generic-worker --privilege-scope workload --privilege-duration 30m -- secret exec --env SERVICE_TOKEN=service-token -- /absolute/program argument
```

Fresh approval requires the existing native strong setup and PolicyKit path;
`--non-interactive` returns `approval_required` without starting the workload.
No password input, PAM replacement, global Sudo timestamp refresh or new
credential is part of this composition.

The existing upstream Sudo bridge uses the receipt-owned native helper and
per-invocation authority checks described in [ADR 0115](adr/0115-native-administrator-grants-with-maintenance-compatibility.md).
Its setup and scoped authentication rules are not installed or changed by these
examples. Do not add a general NOPASSWD rule to make a test pass.

When Dev Auth is the configured launcher, launch-grant activation proves that
executable's startup, **not** the eventual consumer's successful startup.
Workload-scoped grants must settle when this workload terminates after a failed
projection or failed consumer exec. A separately approved user-scoped grant
intentionally may survive that failure until its independent deadline, logout or
revocation.

## Observable acceptance and remaining gates

Run the compiled public-binary composition fixture with:

```text
cargo test -p dev-auth --locked --test cli generic_projection::installed_public_composition_projects_into_native_child -- --exact --test-threads=1 --nocapture
```

For a transferred test runner, set the fixture-only `DEV_AUTH_TEST_PRODUCT` to
its matching ordinary product binary. This input is compiled into the test
runner only; production Dev Auth does not recognize it. Verify both artifact
hashes and source identity before running. No source checkout is needed at run
time because the remaining fixture material is embedded.

The fixture needs native Bubblewrap and a private disposable D-Bus daemon, uses
only synthetic provider/enrollment material, and installs only inside its
disposable native-user namespace. It exercises:

- an ordinary Rust child and unchanged system executable through the same public
  interface, all four projection kinds, native cwd/streams/nonzero status,
  environment precedence, no secret argv, sealed file custody and separate results;
- unknown resources, a selected operation-only resource, a denied projection,
  reserved environment names, missing executables and a positively observed
  missing-provider-resource failure;
- a later provider failure after successful earlier acquisition, with no child
  marker, value-free results and settled user-session directories;
- noninteractive fresh privilege approval returning promptly without child or
  provider effects.

A build or the user-only fixture is not a strong, signed, real-provider or Sudo
qualification. The actual Sudo acceptance must additionally use a non-root
consumer in an explicitly approved workload scope, receive its synthetic secret,
then execute both PATH-resolved and absolute upstream Sudo for a fixed harmless
payload. Prove native identity preservation, approved scope/deadline, denied
managed requests with warm native authorization, copied-hint/wrong-peer denial,
failure/expiry/revocation cleanup and unaffected ordinary non-root work.
A bare `sudo -n id -u` success or root fixture invocation is insufficient
attribution.

Keep source tests, native strong acceptance, signed installation and the actual
installed product identity as distinct evidence. The captured-stream qualification
requirements in [ADR 0131](adr/0131-authenticated-native-workload-stdio-handoff.md)
and the broader [executable acceptance inventory](dev-auth-acceptance.md) remain
open until their exact native gates pass. Do not weaken policy, identity mapping,
SELinux, signing or setup custody to substitute for an unavailable fixture.

### Disposable namespace custody

The synthetic user-only fixture maps only its native fixture UID. Host-root
files under the bound `/usr` consequently appear as overflow UID 65534 and are
correctly rejected by the executable-custody validator. Its configured stock
`printenv` consumer is therefore a byte-identical copy prepared in legitimate
fixture-user custody before policy declaration and admission. The exact copied
path is the admitted launcher. The v4 metadata-only native diagnostic observed rejection of the unmapped
system path and did not execute it. The diagnostic reports custody rather than
requiring a particular host UID map. The repaired configured-consumer fixture passed on native Linux with synthetic
material. It qualifies ordinary system-tool behavior and raw argv through the
same interface, not host-root custody inside the disposable namespace. The
separate copied-shell component also passed. Native Strong qualification remains
a separate pending gate.
