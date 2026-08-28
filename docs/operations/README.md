# Operations documentation

This directory contains stable operator guidance for currently implemented or
actively maintained core operational boundaries. It is not a status-report or
handoff archive.

Current document:

- [`SURREALDB_CREDENTIAL_AUTHORITY.md`](SURREALDB_CREDENTIAL_AUTHORITY.md) —
  credential-owner, validation, and recovery boundary for the canonical-store
  bridge.

Dated branch-cleanup handoffs, milestone runbooks, live-runtime campaign notes,
and one-off production-cutover reports are intentionally absent. Current live
Windows installation, process, store, restart, fencing, and Product-Pulse work
is tracked in GitHub issue #11 and its current PR/CI artifacts. A historical
runbook may be recovered from Git history, but it is not restored to this
checkout as an authority source.

An operational document remains here only while:

- its command or contract has a current source owner;
- it names its actual authority, credential, state, and failure boundary;
- it does not claim live support from prose;
- its links and commands are checked with the applicable current source path;
- retirement or replacement is explicit.
