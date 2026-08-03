# Cognitive runtime invariants

Status: normative for `ELIOT_COGNITIVE_COMPLETION_ULTRA_MASTER_FINAL_v4_1.md`

Baseline: `88a5f049d71a9c535f51811eb7da273416c27118`

Current gate: Phases 0 and 1, including C7-03A through C7-03C, accepted;
Phase 2 / Block B1 active; provider cognition is forbidden

This document fixes ownership and acceptance constraints. It does not claim
that every invariant is already enforced. Current enforcement and evidence are
recorded separately in `COGNITIVE_CAPABILITY_MATRIX.json`; source, canonical
receipts, focused tests, measurements, and field artifacts remain the truth.

## 1. Truth, authority, and runtime owners

1. **CRI-001 — one canonical truth.** SurrealDB is canonical memory truth.
   Search, cue, dependency, dirty, utility, pyramid, and activation state are
   derived projections. A derived record may be rebuilt from canonical truth
   but may not become a competing source of truth.
2. **CRI-002 — one normal writer.** The Governor-owned `WriterActor` is the
   only normal application mutation authority. Provider output, model prose,
   retrieval results, local caches, tests, and controllers do not acquire write
   authority by producing a plausible value.
3. **CRI-003 — one provider route policy and process runner.** All provider
   execution uses the existing `ProviderRoutePolicy` and
   `ProviderProcessRunner`. Cognitive work may not add a provider-specific
   runner, restart owner, timeout owner, or shadow execution route.
4. **CRI-004 — supervised process facts precede interpretation.** A provider
   process is created and contained by the existing Windows Job Object path.
   Spawn, exit, cleanup, timeout, and reap facts are persisted before output
   admission, parsing, or cognitive interpretation.
5. **CRI-005 — existing control owners remain unique.** Provider campaigns are
   controller-owned; MCP profiles are catalog-owned; authority is
   operation-bound with epoch/generation fencing and reconciliation; the
   provider-plan seal remains the sole transactional dispatch seal.
6. **CRI-006 — no parallel platform.** Cognitive completion may not add a
   database, search service, actor/orchestration framework, authority owner,
   MCP family, provider runner, or parallel cognitive schema.

## 2. Completion and reporting

1. **CRI-010 — one task completion decision.** Only the existing
   `CompletionGate`, evaluating a grounded `CompletionProof`, may emit or
   authorize task-level `DONE_VERIFIED`. Receipt checks may ground the proof;
   they may not mutate a task to done through an independent decision path. No
   new `FinishGate` is allowed.
2. **CRI-011 — required verifier evidence is exact.** A required `WorkItem`
   cannot complete until every required verifier has current, scoped, passed
   evidence. A verifier name, planned check, unscoped run, stale receipt, or
   prose assertion is not completion evidence.
3. **CRI-012 — candidate code requires accepted review.** A task involving the
   current candidate diff cannot finish unless the applicable
   `CandidateReview` is accepted for the patch runner and is bound to the exact
   project, task, work item, diff, and canonical receipt.
4. **CRI-013 — stop coordination is part of proof.** `StopCoordinationGate`
   blocks completion while an applicable controller message requiring action,
   blocker, decision request, conflict notice, or unresolved work conflict is
   pending. Historical resolved or out-of-scope coordination does not block.
5. **CRI-014 — operation state is not task completion.** Suboperations report
   only `OPERATION_COMPLETED`, `ACTIVE`, `BLOCKED`, or `FAILED`. They never
   report task-level `DONE_VERIFIED`, and report status is typed rather than an
   unconstrained literal.
6. **CRI-015 — completion is fail-closed.** Missing, ambiguous, stale,
   rejected, failed, or unknown evidence cannot be converted to done. A fully
   scoped proof with all required evidence may complete; incomplete proof
   returns the most specific non-done status.

## 3. Storage, retrieval, and projections

1. **CRI-020 — one daemon database lease.** The current `DbClientSet` owns one
   database-server lease and generation, a fixed read pool, one ordered write
   transport, and one admin/health transport shared by `CanonicalStore` clones.
   Acquisition and reconnect are bounded; shutdown is explicit and idempotent;
   an external production server is never stopped by client shutdown.
2. **CRI-021 — every query has one access class.** `NamedSurqlOp::access_class`
   exhaustively classifies every operation as `Read`, `Write`, or `Admin`.
   Writes are never silently replayed after a possible send.
3. **CRI-022 — one tokenizer and deterministic admission.** Tokenization is
   uncapped before ordered selection. Query terms are selected in the order
   query, task cues, concepts; document terms in the order identity/reference,
   cues, concepts, preview, remaining text. Deduplication preserves first
   occurrence; sorting cannot precede the cap.
4. **CRI-023 — FTS proposes, Rust decides.** SurrealDB 3.1.4 FULLTEXT may use
   BM25 relevance only to order bounded candidate admission; authority is a
   deterministic tie-breaker and remains a feature of the final Rust ranker.
   Project isolation, Unicode, opaque identifiers, bound query parameters, and
   an index-backed `EXPLAIN` are required before cutover. The database score is
   never exposed in the recall response or copied into `L0FeatureScore`.
5. **CRI-024 — bounded reads never repair an entire project inline.** Normal L0
   performs an exact-handle lookup or one FTS query, admits at most 257 handles,
   loads at most 256 compact rows, returns at most 12 previews, and returns
   `no_useful_memory` when no useful candidate exists. A read may not rebuild a
   whole project synchronously.
6. **CRI-025 — one recoverable projection coordinator.** The existing search
   outbox evolves into one `CognitiveProjectionCoordinator` for search, cue,
   dependency/dirty, and utility projections. Canonical commit happens first;
   derived application is idempotent and revision-fenced; affected shards are
   published atomically.

## 4. Hot understanding and context compilation

1. **CRI-030 — one understanding runtime.** There is exactly one engine-owned,
   daemon-owned `UnderstandingRuntime`. The current app-owned `UlRuntime` is
   migrated into it; both may not remain constructible production owners.
2. **CRI-031 — immutable revision-bound snapshots.** The runtime owns immutable
   cue, summary, concept/pyramid, activation, dependency/dirty, utility, and
   pending-injection snapshots. Projection updates replace only affected
   shards and publish an internally consistent revision.
3. **CRI-032 — bounded post-tool activation.** `PostToolUse` normalizes cues,
   performs direct firing, performs at most depth-two bounded activation,
   stages pending injection, and queues trace persistence asynchronously.
   Direct firing works with zero graph edges; spread uses whatever valid edges
   exist. A 500-edge enable threshold is forbidden.
4. **CRI-033 — PreToolUse is memory-resident.** `PreToolUse` drains prepared
   injection and applies the negative-memory gate. It performs no database,
   network, process, or model call and no synchronous projection write.
5. **CRI-034 — one compiler result.** One engine call returns the context
   packet, `ProjectUnderstandingModel`, cognitive gate, and prediction intents.
   MCP validates and serializes that result; it does not rebuild or overwrite a
   second understanding model.
6. **CRI-035 — causal paths are evidence-backed.** Material action paths are
   graph-derived and may cross subsystems: intent to concepts, owners,
   symbols/entrypoints, control/data/state flows, observables, and verifiers.
   Every edge has exact evidence or is `Unknown` with a required probe. R1+
   action requires a decision-sufficient path or a probe gate.
7. **CRI-036 — one revision fence.** Task compilation fences canonical truth,
   search, pyramid, cue/activation, and task revision. Staleness produces a
   bounded degraded packet, never an inline project rebuild.

## 5. Learning, utility, distillation, and forgetting

1. **CRI-040 — verified outcomes start learning.** Only verified task outcome
   evidence can enqueue a `VerifiedEpisodeProjection`. An episode becomes an
   `ExperienceCase` candidate only when it has a mechanism, counterexample, or
   reuse cue; otherwise the result is `NothingToLearn`.
2. **CRI-041 — procedure promotion stays governed.** Contrasting cases may
   form a pattern. An experience or `SkillCard` enters normal context only when
   mature, scoped, anti-scope-safe, verifier-bound, and admitted by existing
   lifecycle gates. Candidate generation never promotes current truth.
3. **CRI-042 — delivery is not benefit.** Utility records benefit only when
   memory changes a probe or action, selects a correct verifier, prevents a
   failure, or is cited by verified completion. Delivery, visibility, and
   unused expansion are neutral. Stale/wrong-scope use, false activation,
   negative transfer, and attributable verifier failure are harm.
4. **CRI-043 — automatic forgetting is reversible.** Automatic lifecycle
   actions are exact, reversible, and high-confidence, with restore conditions
   and regret. Protected structure cannot be removed by a compression
   candidate.
5. **CRI-044 — compression proves reconstruction.** Compression follows
   eligible sources, bounded reasoning candidate, protected-structure
   validation, candidate-only persistence, fixed replay, and promote/reject.
   It records measured expected reconstruction delta.
6. **CRI-045 — sleep proposes; it does not believe.** Sleep/dream consumes
   complete grounded traces and may propose procedures, failures,
   counterexamples, forgetting, or tests with exact references and
   where-not-apply. No substantive pattern yields a no-op report, not generic
   boilerplate or direct belief mutation.

## 6. Prediction, calibration, and evaluation mode

1. **CRI-050 — predictions are machine-checkable.** A prediction has an exact
   intervention, expected observable value or range, verifier, packet binding,
   action-lease binding, and resolution. A generic cheap probe is not evidence
   that a diagnostic outcome “appears.”
2. **CRI-051 — calibration is scoped and non-authoritative.** Hit, miss,
   partial, and unresolvable outcomes, Brier score, blast precision/recall,
   trend, and sample sufficiency are persisted per subsystem. Calibration may
   change warnings or probes; it cannot change truth.
3. **CRI-052 — production never hides memory silently.** Evaluation mode is
   explicit: `Production`, `ShadowEvaluation`, or `Certification`. Production
   does not assign ordinary tasks to control by ID parity. Counterfactual
   replay occurs only in shadow evaluation; treatment/control tasks are
   isolated in certification.
4. **CRI-053 — token policy measures outcomes, not delivery.** Comparable
   cohorts or shadow replay measure tokens, elapsed time, tool calls to first
   correct action, verifier quality, final outcome, and attributable
   memory-caused harm.

## 7. Evidence and phase gates

Phase gates are cumulative. A phase cannot pass on declarations, stale reports,
zero-test filters, or a later phase's evidence. Each phase commit must compile,
pass its focused behavior gate, and be pushed before the next phase begins.

| Phase | Current state | Required gate before advancement |
| --- | --- | --- |
| 0 — truthful capability/completion | `ACCEPTED` | Archive ref exists; matrix and invariants exist; only `CompletionGate` plus `CompletionProof` can complete a task; verifier/review/coordination negatives and complete-proof positive pass. |
| 1 — storage/retrieval | `ACCEPTED_C7_03A_THROUGH_C7_03C` | Phase 0 accepted; persistent clients, lossless bounded retrieval, projection ownership and single-pass packet persistence passed focused provider-free gates. PF1/PF2/PF3, one exact R01 and final bounded isolation remain later certification evidence, not Phase 1 advancement gates. |
| 2 — hot understanding runtime | `IN_PROGRESS_B1` | Phase 1 accepted; one engine-owned runtime, projection recovery, zero-edge direct fire, no PreToolUse I/O, restart behavior and p95 budgets must pass without providers. |
| 3 — context compiler | `LOCKED` | Phase 2 accepted; one engine compiler, graph-derived causal paths, real scoped cues/cases, one revision fence, and bounded degraded staleness pass without providers. |
| 4 — learning/distillation | `LOCKED` | Phase 3 accepted; grounded episode/case/skill learning, real utility attribution, reversible forgetting/compression, and grounded/no-op sleep pass without providers. |
| 5 — prediction/policy | `LOCKED` | Phase 4 accepted; verifier-bound predictions, subsystem calibration, explicit modes, and comparable token/action evaluation pass without providers. |
| 6 — provider-free connected gate | `LOCKED` | Phases 0–5 accepted; at most 18 normal-route cases pass with restart, negative memory, truthful completion, and bounded isolated concurrency. |
| 7 — field certification | `LOCKED` | Phase 6 accepted; three pilots and reciprocal isolated blind transfer pass through consolidated routes with zero unknown outcomes and zero controller substitution. |
| 8 — release | `LOCKED` | Phase 7 accepted; deletion gate, final single-run workspace checks, PR, independent review, CI, merge, and independent main-SHA CI pass. |

Provider cognition in product/runtime paths and provider-generated acceptance
evidence are forbidden through Phase 6. A read-only architecture consultation
is advisory only: it may identify questions, but cannot execute a product route,
receive authority or count as acceptance evidence. Phase 7 may use providers
only after the local provider-free gate passes and only through the existing
sealed, supervised, authority-bound routes. Internal related-context agents are
pilot evidence, not blind-transfer certification.

## 8. Acceptance and deletion discipline

- Passing correctness does not waive latency, isolation, restart, or cleanup
  gates; an SLO miss is a repair target, not proof of completion.
- A provider/model result is evidence to verify locally, never a replacement
  for source, runtime, verifier, or canonical receipts.
- Scale fixtures are reused; unchanged scale runs and unchanged provider
  retries are forbidden.
- After cutover, manual search postings, request-path project rebuild, database
  work in PreToolUse/firing, the 500-edge gate, app-layer duplicate compilation,
  full experience scans, unused compiler stubs, build-ID parity routing,
  unchanged-fallback promotion, default production control assignment,
  fabricated diagnostic predictions, generic sleep boilerplate, hard-coded
  task completion in subreports, and silent 128/512 maintenance caps must be
  removed or proven isolated, non-constructible compatibility code.
- Final completion requires the ordered v4.1 commit chain and final-head
  evidence. Earlier Understanding Layer “certified” reports remain historical
  evidence and cannot certify the superseding connected runtime by themselves.
