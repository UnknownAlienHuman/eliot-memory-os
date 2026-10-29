# Eliot Memory OS V3 — Cognition

**Revision 1.0-draft.25 · 2026-10-28 · design algorithms, not runtime evidence.**

[Architecture](ARCHITECTURE.md) owns product invariants;
[Implementation](IMPLEMENTATION.md) owns runtime, Store and physical maintenance;
the [Inference contract](INFERENCE-CONTRACT.md) owns the proposed external-call boundary.
This document owns reconstruction, retrieval, interpretation, revision and later use.
Initial learning changes external memory, methods, context and bounded configuration,
not model weights.

## 0. Availability boundary

Base reconstructs work, retrieves exact/lexical evidence, handles explicit notes,
corrections/commitments, opens source/history, evaluates applicability/grounds and packs
bounded context without a model. Controller foundation already exists; its scoped Memory
inference extension does not. See [the source comparison](INFERENCE-CONTRACT.md#0-authority-and-prerequisites).

Only model-assisted jobs wait for that extension. Do not recreate controller L0/L1,
require an unrelated Agent-binding issue, or disable Base because inference is unavailable.
Implementation §11 owns build order; cognitive algorithms are not another roadmap.

## 1. Observations, claims and revisions

An observation preserves occurrence identity, exact accepted source bytes/blob,
occurrence/receipt times, work/resource binding, locator, capture limitations,
source-supplied relations and disclosure. It records what a source supplied, not universal
truth. Equal content from separate occurrences remains separate. Capture policy applies
before durable custody; see [Implementation §7.1](IMPLEMENTATION.md#71-capture-policy-before-durable-custody).
Preserve supplied temporal resolution/offset separately from certainty; a normalized
millisecond projection cannot invent unavailable precision or replace the original value.

A semantic item is a revisable claim, method, explanation, commitment, prediction or
project view. Retain exact current/history revisions, origin/reuse/disclosure,
conditions/exceptions, validity, grounds and independent support/exposure/influence.
Original bytes, converted representation, excerpt, summary and claim have distinct
identities and explicit links.

## 2. Current-work reconstruction

Prefer `project + workspace + actual host task identity`; fall back to
`project + workspace + actor/session`. Path, branch, commit and resource version are
environment, not task identity.

Resolve captured binding → open current addressed goal/plan/progress/commitments → add
later observations of that work → apply explicit correction/withdrawal/supersession →
mark association/environment gaps → only then retrieve related experience.

A similar cancelled direction is not current work. Late results retain issue-time
binding. Fork/transfer creates explicit relations, not silent renaming. A model summary
or suggested method cannot silently replace the user's goal/acceptance criteria. Retain
the source goal and an explicitly attributable amendment; an inference is not an amendment.

## 3. Grounds and applicability

For one conclusion revision, links in a non-null grounds group are conjunctive;
different groups are alternatives; ungrouped support is advisory. Navigation is not
evidence; cycles add no independent support. Unknown composition stays unknown.

Applicability is `applicable | inapplicable | conditional_or_unknown`. Evaluate material
selectors, validity, work/resource version and exceptions. Token/vector similarity is
not sufficient. Methods and contraindications travel together.

Correction/refutation/erasure triggers bounded reverse traversal over affected revisions.
Load complete required groups before deciding impact; a truncated traversal cannot
pretend that no additional affected conclusion exists.

## 4. Episode membership and coverage

An episode is a finite grouping over actual session/task/call/result relations. Freeze
job inputs and distinguish selected, supplied, processed, unavailable and remaining.
There is no global processed bit. Partial output does not complete omitted material;
replay of an occurrence is not new experience.

## 5. Direct updates

Notes/commitments are ordinary scoped Memory items with source observations. Display,
acknowledgement, due time and notification do not resolve a commitment.

Structured correction verifies expected current revision, preserves history, publishes
the revision/source/grounds/replacement and coalesces affected work in one transaction.
Exact replay returns the original result; stale revision conflicts. Store transaction
shape belongs to Implementation, not a separate cognitive persistence owner.

## 6. Retrieval and context

### 6.1 Decision frame

Use work address, observed resource versions, focused question, exact cues, constraints
and budget. Missing address or source coverage remains explicit, not guessed from a
similar result.

### 6.2 Candidate arms

Generate independently bounded candidates from direct handles/addresses, exact cues/
aliases, lexical search, compatible vectors when enabled, grounds/contradictions/
replacements, typed relations and eligible methods. Apply project/work scope before arm
limits; union before final selection.

Return examined scope/cut, arm availability and truncation/gaps with the result. An empty
top-K means no match in that examined retrieval, not that no relevant source exists.
Timeout, unavailable arm and truncated traversal are not successful empty searches.
Independent useful arms may still contribute a qualified partial answer.

### 6.3 Lexical snapshot

Lexical ranking is one bounded top-K Store snapshot. Its BM25 corpus/order can change
between calls; there is no durable cross-call cursor. A later expansion is a new snapshot
with new observed Store/schema/query facts. Equal scores use canonical-ID tie-break.
A zero score remains a match; score proves neither support, truth nor applicability.
Exact SQL belongs to [Implementation §5.1](IMPLEMENTATION.md#51-exact-full-text-shape).

### 6.4 Packing

Prioritize current goal/criteria/progress; exact corrections/constraints; open commitments;
applicable or conditional methods with exceptions; relevant episodes; dissent/unknowns/
missing checks; exact source handles.

When a complete qualified unit does not fit, emit a faithful reduction plus handle or
omit it with an explicit gap. Never drop negation, version or contraindication to fit.

Retrieved text, documents, tool output and recalled model answers are evidence, not
new host/system instructions. Render them as attributed data with source/revision and
scope, separately from the selected processing recipe and current user request. Neither
quoted commands nor a model's claim of authorization can change permissions, disclosure,
provider route, execution budget or the user goal. Text delimiters alone do not enforce
this boundary; the application accepts only the owning operation's closed DTO/effects.

### 6.5 Handoff

Keep prepared, emitted through host contract, action-associated when observable,
used/influential (often unknown) and outcome-observed distinct. Packet creation proves
neither use nor success. Context failure does not roll back capture.

Retain the emitted packet's exact bytes/digest, source revisions and observable host
handoff identity in existing observation/job records. When that packet is later captured
from a transcript, preserve the occurrence and mark known injected/derived lineage.
It is not independent evidence for the same claim or a new outcome of the method.
Do not deduplicate real occurrences by text similarity; unknown echo attribution stays
unknown. Mere recapture of Eliot's own context cannot drive an interpretation feedback loop.

## 7. Exact open

Require one exact handle/locator and optional bounded range. Do not rerun search,
conversion, Research or inference to satisfy a historical handle. Empty selector is not
broad retrieval; history never falls forward.

Return requested/resolved identity, revision/representation, range/digest, current/history
disposition, capture limitations, qualifications, relation descriptors, expansion handles,
continuation and explicit missing/forbidden/erased/damaged/unsupported state.

## 8. Processing methods and jobs

A processing method is an ordinary versioned Memory item: purpose, instruction body,
input/result contract, conditions/limitations and disclosure consequences. First enable
stores a real default; upgrade never overwrites an edited revision. Job claim freezes
exact method and source coverage. A stored method without a consumer is not improvement.

Automatic mode is `off | idle | background`; a profile may forbid automatic calls.
New committed input, correction or explicit question can trigger interpretation. Reads,
packet creation, cleanup and accounting cannot. For `(project,purpose,target)`, permit
one active job and one coalesced successor. Waiting is not failure or retry authorization.
Keep reserved limits, measured usage and unknown usage distinct. A configured token/cost
ceiling is not observed consumption; absent provider accounting is not zero usage.

## 9. Controller-backed job lifecycle

### 9.1 Stable identity and live admission

Use the inference contract's admitted scoped caller and exact pre-send mutation identity.
Persist the canonical ID outside rollback state and in its owning job before send.
Live recovery uses the same method/ID/bytes; payload conflict or provider uncertainty
never authorizes a replacement call ID. Read-only mutation lookup handles uncertain
auxiliary effects; restore must not probe existence by resubmitting an old mutation.

Admission distinguishes `prepared | admitted | retired_not_admitted | admission_unknown`.
A method string or accepted controller Agent command is not inference admission.

### 9.2 Result and cognitive states

Read bounded exact call status → range-read its result → verify digest/length → durably
publish the Memory result blob → decode the purpose-specific schema → publish accepted
revisions atomically → expose them to the later consumer. Retain malformed/partial
transport facts without claiming cognitive completion.

```text
changes
no_change
partial
conflict_or_unknown
decode_failed
operational_failed
```

No-change requires completed cognitive work over supplied input. A refused profile,
missing result, unknown call, truncated input/output or failed decoder is not no-change.
The call's technical success does not prove the interpretation is supported.

Before publication, resolve cited source IDs/ranges against admitted supplied input or
an explicit authorized exact read; an ID in model JSON cannot create evidence. Recheck
expected revisions, current scope/disclosure and suppression/deletion notices. Unsupported
claims remain qualified proposals; fabricated sources or unauthorized effects reject.
An old job result cannot reinstate a withdrawn method or erased source.

### 9.3 Cleanup authority

After verified copy or terminal no-result, request caller-authorized release only after
the backup-set owner confirms no retained generation needs that call. Queued cancellation
and explicit abandon-for-erasure follow the inference contract; cleanup has its own state.
A useful revision may be consumed while cleanup debt remains visible.

Controller-owner break-glass is external authority. Missing caller leaves owner-action
debt until non-content readback, not an owner-token fallback.

## 10. Backup admission and authority

Physical backup algorithms belong only to
[Implementation §8](IMPLEMENTATION.md#8-backup-set-owner-and-lifecycle); the external cut
belongs only to [Inference §8–10](INFERENCE-CONTRACT.md#8-memory-backup-interaction).
Cognition consumes the following facts rather than maintaining another backup protocol:

- source/revision/coverage/result facts come from one admitted backup cut;
- a closed job is self-contained only if all needed bodies/facts are retained and no
  later settlement, publication or controller readback/cleanup remains;
- a dependent job still needs its exact external call/copy and remains release-pinned;
- retired IDs never run; unknown external effects remain unknown;
- terminal backup records do not prove physical erasure.

Base backups have no external inference dependency. Do not fabricate a controller cut
or require controller availability for an installation that has never admitted calls.

## 11. Exact rollback and external work

Restore exact backup cognition, not a merge of later Store rows. Current suppression/
deletion notices dominate backup content; see
[Implementation §10](IMPLEMENTATION.md#10-erasure-rotation-and-observability).
Post-cut spool is reconciled by exact identity and bytes through Implementation's owner; its existence is not permission to adopt unrelated
future results.

Closed jobs restore from exact backup facts. Dependent jobs need the exact call/copy.
Retired IDs stay retired; unknown admission disables inference until reconciled.
The inference contract owns the fixed post-cut inventory and auxiliary-effect readback.
Never turn post-cut results into restored cognition merely because they are available.

History gap, missing dependent copy, identity loss or unresolved external mutation keeps
external work unavailable while otherwise valid Base remains useful. Local corruption/
lease/cutover failures separately block their affected operation. Reconciled installation
records outrank restored maintenance mirrors; mirrors cannot clear pins or replay effects.

## 12. Consolidation, disagreement and improvement

Distinguish source replay, packet grouping, same-item revision, synthesis, generalization
and correction/split. Broader patterns are separate provisional items linked to exact
sources; never merge source IDs or rewrite history.

Disagreement belongs to a question, scope and time. Preserve alternatives and grounds;
select the cheapest discriminating observation. Voting is not evidence. Predictions
retain expected observations before action.

Attribution distinguishes method offered, handoff evidence, action observed, adherence
known/inferred/unknown, criterion outcome and comparative benefit. An attributable
attempt/criterion contributes once, not once per repeated report.

Improvement identifies the failed edge/revision, retains a counterexample, changes
conditions/body or scoped negative memory, preserves history and checks that later
context/request actually consumes the revision. No intelligence score or separate
self-improvement registry substitutes for that path.

Automatic changes may revise methods or non-security parameters only within owner-
configured bounds, through the existing revision writer and a named consumer. They
cannot raise permission/disclosure/cost ceilings or retire a withdrawal. Code changes
remain developer work, not a runtime self-modifying execution path.

## 13. Forgetting and erasure

Withdrawal changes guidance, not bytes. Exposure reduction, supersession/refutation,
source deletion and physical erasure are different decisions. Withdrawal is also an
outside-rollback suppression fact: an older active revision remains withheld after
restore, even when its bytes may still be opened for permitted historical inspection.

[Implementation §10](IMPLEMENTATION.md#10-erasure-rotation-and-observability) owns physical
erasure across controlled current/history/blob/spool/packet/job/backup/previous/candidate
copies. Cognition fences affected jobs, propagates loss/refutation through complete
grounds groups and does not resurrect erased material from a historical handle.

Controller membership tombstones may remain after content erasure until the safe cut
advances. They are text-free continuity facts, not retained result content or deletion
proof. Missing external cleanup authority remains explicit debt.

## 14. Failure diagnosis and evidence

Locate the failed edge: capture; IPC; Store/spool/schema; binding/selection; retrieval/
packing; caller identity/admission; provider/disclosure; result copy/decode/publication;
host delivery/use/attribution; backup/restore; release/retention; cleanup/erasure.
Correct its owning implementation/contract, not a new registry or report family.

Base evidence:

```text
real event → Store commit or durable stage → replay → restart → context/retrieval → exact open
```

Learning evidence:

```text
scoped caller + persisted ID
→ one call / at most one provider attempt
→ exact result or typed unknown
→ supported revision or valid no-change
→ later context actually consumes it
→ dependency-aware cleanup and restart/rollback readback
```

Maintenance evidence follows the physical and inference owner contracts. An upstream
unit test, compiling DTO, prepared packet or model response alone proves none of these
complete paths.

## 15. Additive capabilities and their consumers

These retained requirements are later increments, not reasons to scaffold new engines
before Base. Each uses existing observations, revisions, finite jobs and exact open.

| Capability | Input → result → actual consumer | Failure boundary |
|---|---|---|
| Project views | Explicit question/scope/cut → versioned answer with source coverage → context or exact view open | Failed/partial refresh retains the prior qualified view and exposes its age/gaps, not an empty successful refresh. |
| Cross-project methods | Attributable episode/outcome → provisional generalization with conditions and origin → authorized project retrieval | Shared label is not broad efficacy or permission. Selected membership must be persisted/enforced before that mode is enabled. |
| Documents/media | Permitted original → versioned external conversion with hierarchy and page/span/time locators → retrieval and exact representation open | Conversion failure preserves allowed raw access and states unsupported/partial; no invented text or flattened loss of provenance. |
| Embeddings | Exact source revision plus query/document role and compatible model/space → individually mapped vectors → optional retrieval arm | Missing, mismatched or failed input has no fabricated zero/aggregate vector; exact/lexical Base remains available. |
| Research | Explicit finite acquisition request through the configured external owner → retained result, sources and terminal/partial status → ordinary interpretation | Unavailable source or failed request is not no-findings; Memory does not add another research executor. |

Self-inspection uses the same source/open/status paths for Eliot's own documents and
operations; it does not create a separate self-model registry.

Adapters are chosen when their first writer and consumer are implemented. Historical
donor choices are research inputs, not authorization to add unused dependencies.
