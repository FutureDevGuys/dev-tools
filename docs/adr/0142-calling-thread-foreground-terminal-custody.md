---
authority: canonical
owner: dev-tools
---

# ADR 0142: Calling-thread foreground terminal custody

status: accepted
verification: verified

## Context

A multithreaded product can need a native foreground command without adopting the single-threaded terminal command-graph supervisor. Reimplementing terminal transfer in each product would duplicate foreground ownership and restoration rules.

## Decision

The Linux dev-tools-command crate exposes ForegroundTerminal as a narrow calling-thread lease over the existing terminal-custody implementation. Opening requires current foreground ownership and returns absence when no controlling terminal exists. The lease retains original terminal attributes and the opening thread's signal mask, blocks only SIGTTOU on that thread, prepares a child-owned process group without leaking that added block to the child, and transfers the terminal only to a retained unreaped direct child leading a group in the same session.

Explicit restoration and Drop restore the original foreground group, terminal attributes, and opening-thread mask. The lease is neither Send nor Sync. It introduces no global signal handler, child reaper, product policy, privilege authority, command broker, or authentication implementation. Existing inherited-command and command-graph behavior remains unchanged. The caller owns serialization, UI suspension, argv, captured streams, deadlines, cancellation, stopped-child handling, and child cleanup.

## Verification

The shared native inherited fixture tests explicit restoration, Drop, panic, spawn failure, background refusal, absent controlling terminals, foreground /dev/tty input, child signal masks, and terminal-attribute restoration through disposable PTYs. The shared crate's library, integration, documentation, formatting, and strict lint checks pass. Update All's consuming executable separately checks terminal handoff and captured custom-task results. These checks establish Linux terminal mechanics; they do not establish real sudo policy support, signed publication, installed acceptance, or non-Linux qualification.

## Linux consumer qualification

Update All 0.1.17 compiled this mechanism from source `74ce7f9a157b88297952073f4ff0e38ab2e8eada`. Its signed Linux x86-64 artifact passed direct and nested native sudo launches, an intentional protected failure without replay, and cancellation with matching saved outcomes. Managed installation activated those same verified bytes and retained the prior version for rollback. This accepts the Linux mechanism and exercised consumer path; it adds no non-Linux support or arbitrary-descendant containment claim.
