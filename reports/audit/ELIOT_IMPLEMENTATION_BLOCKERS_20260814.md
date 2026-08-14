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

### G-02 — WorkScope identity and admission

Closed portions: the repair adds typed scope/root/workspace projections, discovery/onboarding structures and ten passing package tests while retaining the exact direct provider edge to C0-12.

Remaining authority blockers:

- Deserialized candidate sets and candidates reach onboarding without rerunning the constructor invariants.
- Onboarding checks lease shape/root labels but does not authorize the required discovery read classes.
- Observed root labels are not bound to the candidate's filesystem/root identity.
- State-fence resource generation, scope revision and provider-owned revision heads are not coupled; scope ceilings can widen beyond the admitted ceiling.
- `admit` and `ScopeBindingGuard` compare caller-provided projections without a provider-owned admission/receipt binding.
- Discovery and workspace identities omit the host/session/filesystem/worktree/freshness/privacy evidence needed to distinguish clones and worktrees safely.

Resume condition: add provider-owned identity/revision evidence, exact root and read-class binding, fail-closed revalidation after serde, subset-only ceiling admission and adversarial clone/worktree fixtures. Until then the API must remain observation-only rather than authority-bearing.

### Q-01 — source assurance admission

Closed portions: the repair adds canonical source-set hashing, typed frontier/revision/scope dispositions and eight passing package tests without breaking current consumers.

Remaining authority blockers:

- `ThreatStatus::Unknown` is not denied, so an unknown threat with otherwise verified caller statuses can be admitted.
- Verifier/quarantine/receipt evidence remains caller-supplied status text rather than independently bound proof.
- Privacy class, requested epistemic use and effect ceiling are carried but never enforced during admission.
- The expected exact StateFence is absent from the admission expectation and nested public serde types do not deny unknown fields.
- Observation-domain coverage required by the Q-01 execution plan is absent.

Resume condition: make every unknown security axis fail closed, bind independent verifier/quarantine receipts and exact fence, enforce privacy/use/effect and observation domains, and add nested-serde/adversarial admission tests.

### S-01 — provider-neutral store transaction API

Closed portions: the repair makes opaque IDs fail closed after serde, validates the prepared manifest digest, covers ordering scopes and binds outbox operation/fence fields; six package tests pass.

Remaining authority blockers:

- `CanonicalStoreClient::apply_prepared` carries only the prepared transition, so projections and outbox intents in `StoreTransaction` cannot cross the provider boundary atomically.
- The operation manifest authorizes only transition class/effect and is not bound to each exact named mutation operation.
- Receipt and health manifest digests are not validated as canonical SHA-256 values.
- Transaction validation permits duplicate projection IDs, outbox IDs and outbox sequences.

Resume condition: make the complete transaction the applied client contract, bind every named operation to its manifest, validate all manifest-digest surfaces and reject duplicate exact-array identities.

### G-08 — problem/conflict/attention state machines

Closed portions: the repair retains the G-08 object family and typed ID/enum hardening with six passing package tests.

Remaining authority blockers:

- Multiple transitions mutate state/evidence before checked revision increment, so overflow returns an error after a partial mutation.
- Reopen, resolve, satisfy and evidence paths mutate before duplicate/validation checks or permit repeated terminal transitions.
- Problem acknowledgement changes state without advancing revision; several terminal transitions lack exact owner/terminal guards.
- Record-level deserialization bypasses ordinary-field validation even though typed IDs reject malformed values.
- The manifest retains a direct C0-01 dependency beyond the exact C0-03/C0-11 provider set.

Resume condition: compute and validate every transition fully before one infallible mutation sink, make terminal/reopen/idempotency rules exhaustive, advance revisions on every observable change, revalidate record-level serde and seal the direct dependency set.

### G-09 — immutable configuration and policy snapshots

Closed portions: the repair adds generation/source-assurance fields, semantic snapshot deserialization, a pure CAS projection and nine passing package tests.

Remaining authority blockers:

- Intent validation ignores a successful `ApplicabilityResult` whose outcome is `UNSUPPORTED`, allowing a wrong-scope candidate to continue.
- Active snapshot, applicability context and candidate are not proven to share one machine/scope/fence lineage; only caller-supplied pairs are compared.
- Snapshot IDs are free strings without canonical content identity and may be reused for changed payload/revision.
- The CAS result is synthesized from caller projections without publishing/receipt authority or an exact expected active fence/revision.
- Approval and trigger records are caller-provided labels without authenticated principal, expiry, conditions, pre-authorization or the required Dreamer/problem/maintenance origin binding.
- Rollback lineage omits exact owner and active applicability coupling.

Resume condition: bind active/context/candidate to one provider-observed identity and exact CAS head, make snapshot identity content-stable, reject every non-applicable outcome, and use authenticated approval/pre-authorization/origin receipts with adversarial cross-machine and replay tests.

### C0-06 — non-fresh agent handoff contract

Closed portions: the second contract adds source event/outbox cursor envelopes, in-flight operation/effect dispositions, source fence/epoch, omission/replay/rehydration fields, target routing and complete-versus-partial validation; 15 contract tests and current consumers compile.

Remaining authority blockers:

- Event/outbox/replay cursors remain opaque strings with no ordering/monotonicity or replay-within-source bound.
- The target attempt is not cryptographically bound to the exact route fingerprint and post-resume revalidation receipt.
- Nested `PublicReference` digests accept arbitrary nonblank text instead of canonical lowercase SHA-256.
- Derived serde accepts duplicate/cross-fence/target-invalid semantic payloads unless every caller remembers to invoke `.validate()`.

Resume condition: introduce typed ordered cursor coordinates and bounds, seal target route/receipt identity, make all referenced digests canonical and provide a fail-closed semantic decode path that consumers cannot bypass. Then rerun the unchanged A-01 continuity gate.

### P-03 — provider-neutral process dispatch contract

Closed portions: the second candidate declares the exact C0-04/C0-05/P-01 Cargo edges and models executable/artifact/argv/environment/resource/effect identities, dispatch permits, pre-resume checks, physical process identity and replay conflict with 17 passing local tests.

Remaining authority blockers:

- It defines a second locally constructible AuthorityEpoch/StateFence/revision/lease model instead of consuming provider-owned canonical authority.
- `DispatchPermit::issue` is public and caller-fabricable; it is not a Kernel-issued capability.
- The original raw `ProcessExecutor::start(ProcessRequest, sink)` route remains public and is still used by Codex/ACP, bypassing the permit entirely.
- Physical image/Job/creation identity remains optional on raw process state/receipt paths, so PID/image reuse is not universally fail closed.
- Several public serde surfaces accept malformed/duplicate arrays unless callers voluntarily invoke constructors/validators.
- The candidate lock projection was not updated and strict clippy still reports a documentation lint, though these are secondary to the authority bypass.

Resume condition: make a provider-issued canonical permit the only executable start capability, remove or seal the raw route, consume one provider-owned fence/revision/lease model, require physical identity before resume/receipt and expose only fail-closed decode paths. Then rerun A-03/A-05 against the unchanged P-03 boundary.

## Active first-gate blockers

### S-03 — SurrealDB canonical-store adapter

Mechanical proof is green: format, check, six unit tests and strict clippy pass. The generated standalone `Cargo.lock` was removed after verification.

The first independent gate rejects terminal acceptance:

- The package explicitly contains no SurrealDB SDK/client, credentials, schema, named parameterized operation implementation or live readiness path. Its own `PLAN_GAP.md` therefore contradicts the cell's required `ADAPTER + real SurrealDB compatibility/crash tests` proof rather than satisfying it.
- `MigrationGate::Ready` trusts a caller-supplied free-form schema revision. It is not bound to the exact MIG-02 migration receipt, immutable migration checksum, schema snapshot, compatibility decision, migration capability or active provider generation.
- The transport transaction carries only the incomplete prepared-transition projection and does not prove the complete atomic event/projection/relation/revision/receipt/outbox transaction required by S-01/I5.19.
- Receipt, revision-head and ordering-head responses are not bound back to the exact requested identity/set and several are returned without validation, uniqueness or completeness checks.
- The provider-neutral trait collapses unknown and partial write outcomes to `StoreError::Unavailable`, losing the required reconcile-before-replay distinction for normal `CanonicalStoreClient` callers.
- Health manufactures an operation-manifest digest from the free-form schema revision and marks the store ready from reachability plus that string; it does not prove protocol, contract catalogue, schema generation or named-operation compatibility.
- The crate is an isolated nested workspace and has no root-workspace integration proof. Its six tests do not exercise real RPC, named reads, migrations, transaction/idempotency, crash/restart, unknown-commit reconciliation, backup/restore or compatibility fixtures.

Repair condition for the one remaining bounded cycle: implement the real sealed S-03 provider boundary behind versioned named parameterized operations, bind MIG-02 and active provider generation exactly, preserve typed unknown/partial recovery, validate every response against the request, and add real isolated compatibility/crash/restart fixtures without exposing vendor types or raw query strings.

## Work continuing independently

- Independent candidate gates continue for bounded governor/security/store/surface repairs.
- Candidate reviews pending: A-10, A-13, P-02 IPC and one bounded S-03 repair cycle.
- Accepted and integrated source in this pass: G-17 budget/quota state machine (`a774a01`, workspace integration `763f7e2`) and the supervisor deadline fixture (`7a18ece`).

No paused item may be promoted from package-local green tests alone. Each requires its stated prerequisite, an independent semantic gate, root workspace integration, and the normal workspace verifier.
