---
authority: canonical
owner: dev-auth
---

# ADR 0114: Admitted value-free resource metadata

status: proposed
verification: pending

## Decision

`dev-auth secret metadata RESOURCE [--non-interactive] [--json]` explicitly observes one logical resource already selected by the current admitted v3 workload. It never prompts, enrolls credentials, discovers another credential source, or falls back to the retained legacy configuration. Any selected purpose permits this value-free observation, including an operation-only purpose; read, public-material and projection rights remain separate. Metadata does not grant, renew or extend workload or administrator authority.

The product-neutral secret foundation adds a coarse `SecretValueType`, a successful `SecretMetadataObservation`, and `SecretProvider::discover_metadata`. Its default implementation checks the existing absolute deadline/cancellation context and returns `Unsupported`. The existing `metadata` method retains its adapter-capability declaration semantics and does not establish resource existence. Shared code owns no provider queries, resource policy or presentation.

The broker adds logical-name-only `secret_metadata` and coarse `resource_metadata` variants to its existing unreleased internal protocol identity 3. Requests reject provider references, credential slots, user identities and undeclared fields. The broker re-resolves the verified native owner's selected resource against current administrator policy and the exact provider/credential slot. Existing operation admission, hard deadlines, cancellation and response-publication guards remain mandatory. Audit records hash logical names and contain no provider reference, native type string or resource value.

The 1Password adapter invokes only the held provider's fixed `read --no-newline REFERENCE?attribute=type` query. The vendor's [secret-reference documentation](https://www.1password.dev/cli/secret-references) defines `attribute=type` for fields and file attachments, and its [read-command documentation](https://www.1password.dev/cli/reference/commands/read) defines `--no-newline`. These documented interfaces supply the adapter's query and output-format basis. Existing approved value-format selectors are removed before adding the fixed type selector; unknown or combined queries and unsupported reference characters fail before provider invocation. Neither whole-item JSON nor a field-value read supplies metadata. The Linux sealed-credential child independently validates the metadata selector and retains the existing exact helper/provider descriptor authority before execution.

Each provider operation keeps its existing absolute budget and owned cancellation/cleanup. Capture is limited to 1 KiB per stdout/stderr stream; successful type output must be a nonempty ASCII alphanumeric/underscore scalar of at most 64 bytes with no newline. Known types map to `text`, `concealed` or `one_time_password`; other valid scalar names map only to `other`. Raw captures stay zeroizing and never become diagnostic output.

JSON emits exactly one `dev-auth-resource-metadata-v1` document, including invalid invocations. Only a successful exact-resource observation returns `resource_exists: true` and a coarse `value_type`. Every failure leaves both observations null; missing permission, provider failure, unsupported discovery or an unavailable broker never establish absence. Fixed error kinds use the common exit categories. Human failure diagnostics use stderr. Non-Linux observation returns unsupported until a native admitted path is qualified; doctor remains local and does not invoke this operation.

## Compatibility and verification

Existing authority schemas, enrollment, secret exports, operation-only keys, bindings, administrator sessions and installation mechanisms are unchanged. Existing provider implementations continue compiling through the default-unsupported method. An older broker rejects the new operation; a mixed version does not infer another operation or credential source. Compatible installed activation follows the existing stopped-broker/source-bound setup boundary. No installed policy or accepted release is reissued by this source increment.

Focused verification covers default unsupported discovery, exact provider/slot selection, operation-only observation without export, empty/unselected rights, deadline/cancellation before and during provider work, late-result suppression during session closure, logical-only protocol decoding, coarse responses and hashed audit output. Public CLI fixtures require prompt-free admission failure and value-free invalid JSON, generated completion, and the actual sealed-provider-child fixed selector. Runtime fakes distinguish exact type queries from value reads and reject malformed/oversized output without echoing it.

These source fixtures do not establish real-provider metadata, signed installed admission, strong-mode native custody or another platform's runtime support. Those acceptance gates remain pending and must be recorded separately before claiming supported delivery.
