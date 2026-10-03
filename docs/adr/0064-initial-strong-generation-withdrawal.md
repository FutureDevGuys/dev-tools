---
authority: canonical
owner: dev-auth
---

# ADR 0064: Initial strong-generation withdrawal

status: proposed
verification: pending

## Decision

The internal Linux strong restoration composition can restore an initial installation's approved absence. Both original product/shared receipts, every public and transparent activation path, the privileged workload launcher, setup helper/sidecar and all fixed system assets must have been absent in the retained approval. Receipt absence alone is insufficient. Executable payloads are not copied into generation documents; their approved original absence is checked directly in the canonical current-path inventory. No synthetic previous release is used to select rollback.

The initial installation component derives the exact candidate product/shared receipts, helper sidecar and immutable continuation identity from retained approval. Strong construction requires effective root, canonical system paths, a helper-owning candidate and matching retained release provenance. Current ownership is either the exact candidate, its supported transparent-deactivated form, or absence from interrupted publication/withdrawal. Product receipts remain root-owned 0644, shared ownership remains root-owned 0600, and the immutable continuation remains root-owned ordinary 0755 with exact single-link content custody. The data directory is held for product receipt and helper operations. No receipt, CLI or retained-generation schema changes.

Every fixed helper leaf is observed before helper removal. The ordinary setup helper and sidecar may contain only their exact derived candidate bytes or be absent. The privileged workload launcher may contain only exact candidate bytes at the candidate release's mode or ordinary 0755, or be absent. Retirement clears set-ID permission on the held launcher, synchronizes it, rechecks named identity and removes the exact ordinary file descriptor-relative. Helper and sidecar removal uses the same exact-content existing-directory boundary. Absent retries synchronize the selected parent; unrelated contents, ownership, modes, hard links, symlinks and replaced directory authority are not adopted. No immutable executable or credential material is deleted.

The service component admits each fixed unit definition only when its current root-owned 0644 document matches the compiled candidate digest, or when the file is absent. Before a stop request, a missing definition must already have stopped, disabled, job-free state and no process identity. It never authorizes stopping an active process. Present candidate-owned units may be disabled and stopped through direct fixed-unit, noninteractive commands. All units are observed before the first service mutation, and the native kernel workload/broker-domain and socket-absence checks remain mandatory. A successful command does not substitute for terminal evidence.

After candidate unit documents are removed, an inactive cached loaded unit may require a manager reload. Terminal verification requires explicit `not-found` definition state, empty fragment/drop-in/activation/job/process authority and independent kernel/socket absence. Query errors are not absence. Existing prior-generation restoration keeps its loaded-definition requirement. The machine-readable interface uses explicit `show --all --property` fields, including for nonexistent units, as specified by [systemd's interface](https://github.com/systemd/systemd/blob/main/man/systemctl.xml). Each native service component operation retains its shared 60-second command budget and fixed executable authority.

The enclosing owner keeps the native account checks, exclusive setup lease, exact running candidate, durable restoration direction and configuration-pair admission. It stops services before removing configuration and system documents, retires native helpers and shared activation, removes the exact product receipt, synchronizes the manager and verifies complete inactive absence before marking the generation restored. Partial unit, helper, alias and receipt removal cannot discard the outer recovery authority. Immutable candidate bytes, credentials, credential-action receipts and unrelated files remain available. A new plan is required before reactivation.

The public strong restoration command remains gated pending full acceptance. Initial interruption before the immutable candidate exists, original helper absence during a prior-installation upgrade, active-broker/process-death and signed-provider acceptance, hostile independent root writers and non-Linux custody are not established by this increment.

## Evidence

The disposable systemd first-installation fixture initially failed at the user-only constructor gate. It now exercises actual strong restoration from absent prior authority with active sockets, candidate-only configuration/assets/helpers and no source configuration files. It checks activation and receipt absence, an unchanged retained generation and retry executable, unchanged terminal repeat, and unrelated native-account file preservation. Additional checks reject helper/sidecar drift before changing the transition and inspect an open launcher descriptor to require ordinary permissions and zero links after removal. A separate fixture resumes after the real stopped-component/document sequence has removed the first unit definition while later definitions remain.

Focused tests cover exact initial asset selection, explicit absent-unit field validation, missing-definition no-stop behavior, selected fixed-unit commands, late kernel population, unsuccessful observed reload completion and unchanged retry. Existing user-only initial restoration and prior-generation service checks remain regression gates. Native fixtures run individually in explicitly owned, network-free, mount-free disposable systemd containers, with outer time bounds and cleanup. They use synthetic source-bound release claims and no credentials or broker process; they are not signed release, real process-death/power-loss, enrolled provider or platform-support evidence.
