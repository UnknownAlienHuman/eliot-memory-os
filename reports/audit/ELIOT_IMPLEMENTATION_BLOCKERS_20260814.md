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

### A-12 — WASM component runtime facade

Closed portions: the second candidate provides the sealed provider edge set, fail-closed basic IDs/digests, canonical generation/work/lease/fence projections, an injected component-engine port, bounded execution dispositions and honest typed unavailability when no engine/process binding exists. Its package gates pass with 13 tests.

Remaining authority blockers:

- The engine invocation omits exact WIT world/version, state-contract digest, imports/exports and verifier identity, so the engine boundary is not sealed to the claimed component contract.
- Differential evidence compares adapter-reported digests instead of independently deriving result/effect/state digests from observed execution.
- Shadow/canary/rollback/cutover evidence is accepted as non-empty caller strings rather than exact generation/epoch/receipt-bound proof.
- Owner and lifecycle revisions are not coupled to a canonical owner/lease receipt; terminal cancellation may overwrite a completed result, and an unresolved post-commit cancel is incorrectly classified as `CANCELLED`.
- The accepted P-03 start receipt/image identity is not retained in the A-12 receipt, and exact-array serde silently deduplicates duplicates.

Resume condition: publish the complete component/engine identity and receipt bindings, derive differential proof from observed artifacts, bind promotion to exact receipts, make terminal replay immutable, preserve post-commit unknown, and add duplicate-array/adversarial adapter regressions. Then rerun an independent gate without changing the Runtime oracle.

### P-05 — HostStateJournal

Closed portions: the second candidate provides explicit lineage-aware epochs, typed activation/kernel/dependency/wake/drain records, legal local lifecycle matrices, a prepared transaction backend, stable unknown transaction identities and 17 passing package tests with the exact direct provider set.

Remaining authority blockers:

- The required torn-frame, checksum/corruption, unknown-version, flush-unknown and sync-unknown recovery fixtures are absent.
- `KernelRecord` omits the approved artifact hash and active/candidate pipe identity, and permits `ACTIVE` without mandatory process identity/readiness proof.
- Kernel activation is not bound to the current Eliot activation; drain/wake/dependency records share a fence but lack the required cross-record identity, and draining/clean stop can omit `drain_generation`.
- Observation/epoch-retirement appends do not invalidate the clean marker, leaving a stale clean-shutdown claim after later journal activity.
- Reconciliation accepts an arbitrary transaction identity without binding it to the current Host epoch.

Resume condition: complete the Kernel and cross-record identities, make clean-marker invalidation exhaustive, bind reconciliation identities to Host epoch, and add the exact corruption/torn/flush/sync recovery corpus. Then rerun the independent P-05 gate.

### S-04 — blob API and store

Closed portions: the second candidate separates provider-neutral API and filesystem implementation, injects platform/codec/key/AEAD/live-set ports, validates basic identities, models staged publication/recovery and key rotation, and passes 5 API plus 9 implementation tests.

Remaining authority blockers:

- A missing key provider is translated to typed `PLAN_GAP` during stage but leaks raw `ProviderUnavailable` during read and verification.
- Tombstone payload/metadata paths are containment-checked but are not proven to be the canonical paths derived from the tombstone locator, so a corrupted tombstone can delete unrelated in-root files.
- Recovery journal temp/final paths are not canonically derived from operation identity and metadata locator before publication.
- Exact operation replay compares locator/policy/plaintext identity but omits the stored request and authority bindings.

Resume condition: make provider-unavailable translation uniform, bind tombstone and journal paths to canonical locator/operation derivation, and require exact request/authority identity on replay with adversarial recovery fixtures. Then rerun the independent S-04 gate.

## Work continuing independently

- Independent candidate gates continue for bounded governor/security/store/surface repairs.
- Candidate reviews pending: G-02, G-08, G-09, Q-01, A-10, A-13, P-02 platform/IPC, S-03.
- Accepted and integrated source in this pass: G-17 budget/quota state machine (`a774a01`, workspace integration `763f7e2`) and the supervisor deadline fixture (`7a18ece`).

No paused item may be promoted from package-local green tests alone. Each requires its stated prerequisite, an independent semantic gate, root workspace integration, and the normal workspace verifier.
