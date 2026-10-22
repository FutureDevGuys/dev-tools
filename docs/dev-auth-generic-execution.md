# Generic workload and secret execution

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
