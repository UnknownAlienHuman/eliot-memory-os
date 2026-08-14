# ELIOT implementation blockers — 2026-08-14

Status: bounded follow-up backlog. These items reached two failed implementation/gate cycles and are paused while independent work continues. This report is supporting telemetry; it does not modify the governing Runtime oracle and does not issue `CELL_ACCEPTED`, product, or release authority.

Integration snapshot: branch `swarm/A-04-cell`, source frontier `763f7e2` when this report was created.

## Paused work

### A-01 / A-03 / A-05 — admitted agent launch path

Closed portions: raw launch requests no longer directly enter the Codex/ACP adapter path; identifiers and admitted invocations revalidate after deserialization; C0-12 freshness, integrity, taint, privacy, verifier, epistemic-use, fence and effect checks are present; provider results remain candidate-only.

Remaining authority blockers:

- P-03 `ProcessRequest` and start receipt have no Kernel-issued `DispatchPermit`, action-lease/revision-head validation, executable/environment/tree/effect binding, or actual process/image/Job identity. A-03/A-05 therefore cannot safely execute the request.
- Canonical C0-06 `HandoffCausalLink` lacks required source-event/outbox cursors and in-flight operation/effect dispositions. Non-fresh admission cannot honestly treat its completeness flag as sufficient.
- `NARROW` does not seal the selected work unit, narrowed scope/effect ceiling, and admitted route class into the readiness decision.
- C0-07 task-revision validation has a non-material mode bypass.

Resume condition: P-03 and C0-06 owners publish the missing canonical fields, or the adapters are changed to an explicit typed-unavailable launch boundary. Then rerun the unchanged trio gate.

### G-03 — task aggregate and Task Controller

Remaining blockers:

- `TaskAggregate::intake` creates a canonical `TaskContract` directly from an untrusted proposal without owner admission, `TaskSelectionEvidence`, WorkScope/project identity, source binding, or ambiguity disposition.
- Lifecycle omits `OPEN`, suspend/resume, closing/closed, reopen, cancel and evidence supersession; failed acceptance evidence cannot be replaced safely.
- Verification is not bound to required property, task revision/fence, artifact overlap, freshness, proof ceiling, or unresolved effects.
- Retry identity uses `Debug` formatting instead of a canonical encoding.
- The aggregate has no durable event/rehydration, atomic prepared transition, persisted receipt, or crash/unknown reconciliation boundary.
- Controller lease and sealed Cargo dependency contracts remain incomplete.

Resume condition: define or integrate the exact TaskSelectionEvidence plus canonical event/persistence boundary, then perform a Sol-owned rewrite and independent gate.

### G-10 — module and capability registry

Remaining blockers:

- Required blueprint API is asynchronous and RequestMeta-bound; the candidate remains synchronous.
- Blueprint instance authority, fork/update lineage, verification saga, package/signature/provenance/license/SBOM checks, compatibility, bindings, conformance and runtime receipts are incomplete.
- Readiness still trusts caller-supplied booleans/opaque evidence rather than verifier-bound fresh evidence.
- Route fingerprint omits host, protocol/transport, runtime/provider/model/auth/billing, role/tool semantics, continuation/compaction and feature/tool/context hashes.
- Component cycles and resolved binding requirements are not fully validated.
- Root workspace and exact Cargo graph are not integrated.

Resume condition: integrate canonical verifier/readiness evidence and full route fingerprint contracts, then rewrite the blueprint saga from the exact Implementation contract.

### P-11 — bounded task runtime

Closed portions: bounded two-lane fairness, sticky shutdown intent, admission closure, protected control capacity, poison-safe registry, panic containment and owned supervised attempts exist in the second candidate.

Remaining blockers:

- Registry `active` is incremented before spawn, but its cleanup guard is created only on first poll. Immediate pre-poll abort leaks the active entry; shutdown deterministically returns `Incomplete` with `no_orphans == false`.
- Every P-01 platform error is mapped to `Saturated`, incorrectly classifying validation, identity, permission, unavailable, timeout and provider failures as capacity pressure.

Resume condition: construct the cleanup token before spawn and capture it into the future so never-polled abort drops it; add ordinary and supervised regressions; preserve a typed platform failure instead of collapsing it to saturation. Then rerun the independent stress gate.

## Work continuing independently

- Native Sol repairs: P-05 HostStateJournal, S-04 blob store, A-12 WASM facade.
- Candidate reviews pending: G-02, G-08, G-09, Q-01, A-10, A-13, P-02 platform/IPC, S-03.
- Accepted and integrated source in this pass: G-17 budget/quota state machine (`a774a01`, workspace integration `763f7e2`) and the supervisor deadline fixture (`7a18ece`).

No paused item may be promoted from package-local green tests alone. Each requires its stated prerequisite, an independent semantic gate, root workspace integration, and the normal workspace verifier.
