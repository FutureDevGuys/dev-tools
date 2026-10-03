---
authority: canonical
owner: dev-auth
---

# ADR 0069: Committed binary-journal settlement during setup recovery

status: proposed
verification: pending

## Decision

[ADR 0074](0074-committed-upgrade-product-receipt-recovery.md) extends committed settlement to the exact retained prior user-only product receipt awaiting successor publication.

[ADR 0073](0073-initial-staged-binary-forward-recovery.md) separately admits initial user-only staged-binary forward completion before shared commit; other settlement cases retain the committed-candidate requirement.

[ADR 0072](0072-initial-product-receipt-recovery.md) extends this decision only for an absent initial user-only product receipt after the exact shared candidate is committed.

Linux `dev-auth setup recover` may settle a committed binary journal belonging to its exact retained pending setup generation. This narrowly supersedes ADR 0044's rejection of every pending binary journal. Recovery still requires a complete verifiable product installation, exact running candidate bytes, native ownership, the exclusive setup lease and intact private retention. It cannot install an executable, replace a source, restore a prior binary or discover another release.

The retained product and shared installation receipts establish the prior endpoint, including explicit paired absence. Their approved paths, native owner, receipt permissions, bounded retained bytes and history must agree. The installed candidate's version, executable identity, native programs, previous-release history and any authenticated provenance must agree with the approved plan and retained prior. Same-version recovery cannot substitute different bytes or invent provenance. Unpaired legacy receipts remain outside this recovery case.

Before entering mutation, the shared exact-transition observer verifies both journal endpoints in their original roles, bounded artifact custody and the committed candidate's activation. The product revalidates the retained plan, candidate configuration and native identities and rejects undeclared credential inputs. Wrong candidate bytes, an unapproved prior, a reverse transition, incomplete installation or malformed retention reject without settling the journal. Accepted generations cannot use this path to replay a newly introduced journal, and restoration direction cannot resume forward.

After admission, settlement rechecks the product receipt and committed shared candidate under the installation lock and invokes the exact-transition recovery primitive. The product callback denies an uncommitted shared state before the generic primitive can restore prior links. Ordinary full-setup retries retain their read-only pre-deactivation check and cannot perform this settlement implicitly. No binary mutation is selected when observation found no journal; subsequent read-only deactivation still rejects an intervening journal.

Successful settlement contributes `changed: true` and the `settle_binary_transition` action to the existing setup-recovery result. Later configuration or credential failure does not erase an already-established change; errors with unknown entered progress remain `changed: null`, and pre-mutation rejection remains unchanged. Missing enrollment returns promptly, preserves pending admission exclusion and does not activate workloads. Source executable downloads and original policy/configuration inputs are not needed for this continuation.

## Evidence and remaining gates

The disposable native-user CLI fixture reproduces implicit journal repair through ordinary retry and requires its rejection. It rejects a differently hashed recovery executable and an unapproved prior endpoint while preserving exact journal, transition and retained-generation bytes. It then removes the original executable source, settles the approved committed journal through the installed public command, reports the missing credential with a real change, and repeats without change. Result tests retain value-free errors and distinguish known change from unknown entered progress. Shared tests cover read-only journal preservation, absent-lock rejection, exact direction and both generic recovery outcomes.

This is source-built Linux native evidence, not a signed production upgrade or process-death simulation. Recovery interrupted before a complete product receipt, generic prior-generation transition selection, stopped-broker migration, mixed-version writer coordination and complete active-broker teardown remain delivery requirements. Strong signed recovery and other native backends retain their own acceptance gates. No frozen publication input or installed production policy is changed by this implementation.
