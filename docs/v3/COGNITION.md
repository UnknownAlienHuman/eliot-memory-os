# Eliot Memory OS V3 — Cognition

**Revision 1.0-draft.16 · 2026-10-26 · normative algorithms used by V3.**

[Architecture](ARCHITECTURE.md) owns product/authority invariants. [Implementation](IMPLEMENTATION.md) owns runtime and persistence. [Inference Contract 0.11](INFERENCE-CONTRACT.md) owns the sole Memory↔controller call boundary. This document defines reconstruction, retrieval, learning, revision and self-improvement algorithms.

Nothing here implies model-weight training. Initial learning changes external memory, processing methods, context selection and bounded configuration.

## 0. Availability boundary

Base cognition works without controller inference:

- direct work-address reconstruction;
- exact/lexical retrieval;
- explicit notes, corrections and commitments;
- source/history opening;
- deterministic applicability/grounds handling;
- bounded context packing.

Model-assisted learning waits for controller V2 issue #200, V2 L0/L1 and Contract 0.11 P1a. Missing inference never disables Base.

## 1. Observations, claims and revisions

### 1.1 Observation

An observation preserves what a source actually supplied:

```text
source/stream occurrence identity
exact accepted bytes or blob
occurrence time + precision
receipt time
work/resource binding
locator
capture limitations/redactions
source-supplied relations
disclosure
```

Observation is not a truth claim. Equal payloads from different occurrences remain different observations. Digest verifies bytes; it is not occurrence identity.

### 1.2 Semantic item

A semantic item is a revisable claim, method, explanation, commitment, prediction, project view or other useful derived statement. It retains:

```text
current revision
origin and reuse scope
disclosure
conditions/exceptions/selectors
validity
source/grounds links
support, exposure and influence state
```

Historical revisions remain exact-openable. Current and history never substitute for each other.

### 1.3 Source, representation and claim stay separate

Original bytes, converted representation, excerpt, summary and semantic claim have distinct identities and explicit links. Conversion/summary never becomes replacement source truth. Dirty/untracked source is cited by retained bytes/range, not repository HEAD alone.

## 2. Current-work reconstruction

Address work before similarity search.

### 2.1 Direct address

Preferred key:

```text
project + workspace + actual host task identity
```

Fallback:

```text
project + workspace + actor/session
```

Path, branch, commit and resource version are observed environment, not task identity.

### 2.2 Reconstruction algorithm

1. Resolve captured project/workspace/task binding.
2. Open current addressed goal/plan/progress/commitments directly.
3. Add later observations bound to the same continuing work.
4. Apply explicit correction/withdrawal/supersession revisions.
5. Mark unresolved association or changed environment as gaps.
6. Only then retrieve related experience.

A similar cancelled direction does not become current. Late results keep issue-time binding. Fork/transfer creates relations, not silent renaming.

## 3. Grounds and applicability

### 3.1 Grounds groups

For one conclusion revision:

- links in one non-null group are required together;
- different groups are alternatives;
- ungrouped support is advisory;
- navigation links carry no evidential Boolean meaning.

Unknown composition remains unknown. Citation count is not proof. Cycles provide no independent support.

### 3.2 Applicability

```text
applicable
inapplicable
conditional_or_unknown
```

Evaluate material selectors, validity, resource/work version and explicit exceptions. Token overlap or vector similarity is never sufficient proof. A method and its contraindication travel together.

### 3.3 Source change

A correction, refutation, live-condition change or erasure triggers bounded reverse traversal over affected conclusion revisions. Load complete grounds groups before impact decision. Traversal pages/coalesces; it does not verify the whole graph before ordinary reads.

## 4. Episode membership and coverage

An episode is a finite grouping over actual relations:

```text
session/task
call/result
ordered source events
observed outcome/feedback
```

Freeze job input explicitly. Distinguish:

```text
selected       candidate source members/ranges
supplied       exact bytes/revisions placed in request
processed      portions the result actually covers
unavailable    omitted/missing/damaged material
remaining      eligible material not covered
```

There is no global processed bit. Useful partial output cannot mark omitted material complete. Replay of one source occurrence does not create new experience.

## 5. Direct user updates

### 5.1 Notes and commitments

Explicit notes/commitments use ordinary Memory items with source observation and scope. Acknowledgement, display, due time or notification does not resolve a commitment. Resolution follows a matching observed event or explicit owner change.

### 5.2 Corrections

Structured correction is authoritative user intent about Memory content, not automatic truth about the external world.

One transaction:

1. opens current revision;
2. verifies expected revision;
3. preserves prior revision in history;
4. publishes new current revision;
5. records correction source, grounds/replacement links and exact result handle;
6. coalesces affected reconsideration work.

Replay of same correction returns prior result. Stale expected revision conflicts instead of overwriting intervening work.

## 6. Retrieval and context assembly

### 6.1 Decision frame

```text
work address
observed resource versions
focused question
typed/exact cues
constraints
budget
```

### 6.2 Independent candidate arms

Generate bounded candidates independently from:

- direct handles and current-work addresses;
- exact cues/aliases;
- lexical search;
- compatible vector space when enabled;
- grounds/contradictions/replacements;
- typed relations;
- local and eligible reusable methods.

Apply project/work selectors before arm limits. Union before final selection. One arm's top-k cannot erase a material exception found by another.

### 6.3 Ranking

Rank relevance separately from support/applicability. A retrieved item remains qualified by source, revision, limitations and conditions. Retrieval frequency does not strengthen truth.

### 6.4 Packing

Pack, in priority order:

1. current goal/criteria/progress;
2. exact corrections and constraints;
3. open commitments;
4. applicable/conditional methods plus exceptions;
5. relevant prior episodes;
6. dissent, uncertainty and missing checks;
7. exact source handles.

If a complete qualified unit cannot fit, emit faithful bounded reduction plus handle or omit it with explicit gap. Never drop negation/version/contraindication to fit.

### 6.5 Handoff states

```text
prepared
emitted through host contract
action-associated when observable
used/influential: usually unknown
outcome observed
```

Do not infer use/success from packet creation. Context failure does not roll back capture.

## 7. Exact source opening

`open` requires one exact handle/locator and optional bounded range. It never reruns search, conversion, Research or inference to satisfy a historical handle.

Return:

```text
requested and resolved identity
revision/representation
returned range + digest
current/history disposition
capture limitations and material qualifications
revision-aware relation descriptors
expansion handles
next cursor or explicit non-pageable gap
missing | forbidden | erased | damaged | unsupported
```

Historical handle never falls forward. Current handle does not resurrect history. Empty selector is validation/empty exact result, not broad retrieval.

## 8. Processing methods and first enable

A processing method is an ordinary versioned Memory item:

```text
purpose
instruction/body
input contract
result contract
conditions/limitations
disclosure consequences
```

First enable stores one real default method. Upgrade never overwrites user-edited/learned revision. Job claim freezes exact method revision; request builder opens that body. A stored method with no consumer is knowledge, not improvement.

## 9. Controller-backed job lifecycle

### 9.1 Stable caller and external ID

One Memory installation uses stable controller `client_id` and current token version. Before every caller mutation:

1. authenticate exact controller/client identity;
2. allocate/persist monotonic global ULID from installation state outside rollback roots;
3. persist WriteId in owning job/maintenance record;
4. only then send.

This applies to call, cancel, release and retention advance.

### 9.2 Live call admission

```text
frozen sources + exact recipe + disclosure
→ exact request bytes/digest persisted
→ inference WriteId persisted
→ inference.text with same ID/bytes
→ controller first-admits or returns existing call
```

Same identity is idempotent. Mismatch is `id_conflict`. Provider uncertainty belongs to retained call; never allocate another call ID to recover.

Memory retains admission state:

```text
prepared
admitted
retired_not_admitted
admission_unknown
```

During normal live recovery, a prepared ID may still first-admit. During backup/restore, §14 applies the stricter cut semantics.

### 9.3 Result read and decode

1. Read bounded non-content call status.
2. When result exists, range-read exact bytes.
3. Verify length/digest.
4. Durably publish Memory result blob.
5. Decode through purpose-specific closed schema.
6. Retain malformed/partial transport facts without cognitive success.
7. Publish accepted revisions atomically under expected revisions.
8. Create release WriteId and release only after verified Memory copy or terminal no-result.

Store conflict replays retained decoded proposal/result, not inference.

### 9.4 Cognitive result states

```text
changes                  typed create/revise proposals
no_change                completed valid work over supplied input
partial                  usable output with exact incomplete coverage
conflict_or_unknown      unresolved semantic result
decode_failed            exact body retained, no publication
operational_failed       admission/provider/readback failure, no cognitive body
```

Profile unavailable/disallowed, disclosure mismatch, provider failure, no result, malformed output, truncation or omitted input is not successful no-change.

### 9.5 Cleanup authority and states

Cleanup is separate from cognitive outcome:

- verified Memory result copy → `memory_copy_verified`;
- terminal call with no future result → `terminal_without_result`;
- unresolved work selected for erasure → `abandon_for_erasure`.

With a valid caller, queued work may first receive caller `inference.cancel`, then caller `inference.release(abandon_for_erasure)`. Input/result copies retain independent state.

Controller-owner `inference.erase` is local break-glass. Memory cannot call it. When caller cleanup is unavailable, Memory records `owner_action_required` plus exact non-content call identity and waits for observed owner readback. Request alone is not effect.

A useful revision may be consumed while cleanup remains incomplete; status/erasure exposes debt.

## 10. Automatic work and coalescing

Automatic mode:

```text
off
idle
background
```

Profile may independently deny automatic calls. Interpretation triggers only on new committed relevant input, correction or explicit question. Reads, packet creation, release, cleanup, embedding completion and accounting do not self-trigger another learning job.

For `(project, purpose, target)` allow one active job and one coalesced successor. Preserve first queued time. Waiting for idle/profile/disclosure/resume is not failed attempt. Foreground arrival stops new idle dispatch but does not duplicate admitted call.

## 11. Consolidation and revision

Distinguish:

```text
source replay
packet grouping
same-item revision
new synthesis
generalization
correction/split
```

A broader pattern creates separate provisional item linked to exact sources. It does not merge source IDs or rewrite historical handles. Split publishes new current items/relations while old handles remain exact.

A curation result is complete only when ordinary context/open/method consumers change. An unread report is not product behavior.

## 12. Outcome attribution and method improvement

Where external action can be correlated, retain:

```text
method revision offered
handoff evidence
action observed
adherence known/inferred/unknown
criterion outcome observed
comparative benefit supported/unknown
```

One attributable attempt/criterion contributes once. Replayed hooks, summaries and duplicate reports are not independent outcomes.

Method improvement:

1. locate exact failed edge or method revision;
2. retain concrete counterexample/outcome;
3. revise method conditions/body or create scoped negative memory;
4. preserve old revision/history;
5. prove later request/context consumes new revision.

No global intelligence score or mandatory model judge.

## 13. Disagreement, prediction and research

Disagreement belongs to question, scope and time. Preserve alternatives/grounds, then select cheapest useful discriminating observation. Voting is not evidence. Provisional choice records rationale and reconsideration trigger.

A prediction records expected observation before action, conditions and available check. Static dependency, co-change and causal explanation are distinct.

Research starts from retained Memory/exact local sources. External acquisition answers a concrete remaining gap. Store compact findings, alternatives, coverage and exact report/source handles. Failed request, completed-uninformative and useful-partial are different outcomes. Do not loop merely because uncertainty remains.

## 14. Backup admission closure, retention and rollback cognition

### 14.1 Admission cut

Before controlled backup:

1. stop new controller-backed admission requests;
2. pause/drain the single controller-dispatch owner so no send races the cut;
3. persist every already-created call/cancel/release WriteId;
4. authenticate exact controller/client identity;
5. classify every call ID:
   - exact call/readback → `admitted` + `admission_seq`;
   - exact healthy absence and no in-flight sender → `retired_not_admitted`, never send again;
   - unavailable/ambiguous → `admission_unknown` and controller-continuity gap;
6. reconcile created cancel/release from actual call state or retire proven-unsent mutation;
7. only then record controller `high_water` and guaranteed `retain_after_seq`;
8. freeze Store/spool backup facts through Implementation's brief cut.

The installation-scoped WriteId generator is not part of rollback backup.

A controller-continuous backup contains only admitted external calls. Local source/recipe intent may remain after a retired attempt, but the retired ID is not a call and does not pin retention.

### 14.2 Retention cut

```text
required_retain_after_seq =
  minimum high_water among every locally retained restorable backup
```

After local backup set changes durably, create maintenance record with expected/new cut and precommitted retention WriteId, then call `inference.retention.advance`. Lost reply reuses same ID. Advance before backup-set readback is invalid; failure to advance is conservative.

Calls above cut retain bounded membership metadata. If content is erased above cut, controller leaves text-free tombstone until cut advancement. Deleting even tombstone requires retirement of every backup pinning interval first.

### 14.3 In-cut jobs after restore

```text
admitted + matching call -> read/cancel/release original
admitted call missing/below guarantee -> history_gap/damaged; never first-admit
retired_not_admitted -> old ID remains retired; fresh successor only after inventory
admission_unknown -> hold with inference disabled
mismatch -> conflict
caller unavailable -> hold
```

An old backup never first-admits an absent call ID.

### 14.4 Post-cut calls

Capture one inventory high-water and page fixed interval:

```text
inference.list(after = backup_high_water,
               through = inventory_high_water)
```

Cursor binds controller/client, bounds, API version and page shape. If backup high-water is below `retain_after_seq`, return `history_gap`; physical presence of some rows does not make interval complete.

Because absent cut attempts were retired, returned calls are outside the backup's admitted set. Do not adopt results as restored cognition. With valid caller, use cancel/release-abandon. Without caller, retain owner-action-required debt until controller-local owner readback.

All new inference remains disabled until inventory completes and every row is dispositioned. Base remains usable. Controller/caller unavailability, admission unknown or history gap produces `external_work_inventory_unavailable`, never false empty or complete rollback.

## 15. Forgetting and erasure

Withdrawal changes guidance, not physical bytes.

Physical erasure:

1. publish monotonic deletion notice;
2. close affected mutation/replay admission;
3. reconcile active Store/replay/controller effects;
4. cancel/fence pending jobs;
5. use caller cancel/release-abandon when caller is valid;
6. otherwise record owner-action-required and wait for observed break-glass result;
7. delete current rows/blobs/spool/packet/job copies;
8. delete affected previous roots/candidates/backups wholly when selective offline rewrite is absent;
9. retain explicit provider/off-machine/tombstone gaps.

A controller call above `retain_after_seq` may retain only bounded non-content membership tombstone after content deletion. Complete deletion of tombstone requires prior backup retirement and cut advancement.

Deletion fence/tombstone prevents false reintroduction/inventory but is not proof every controlled copy was deleted. Complete erasure requires exact absence or explicit incomplete debt.

## 16. Failure diagnosis

Classify the failed connected edge:

```text
host capture
relay/daemon IPC
Store/spool durability
work binding/source selection
controller identity/WriteId admission
backup admission closure
profile/disclosure/capacity
provider execution/readback
retention/history inventory
authority/owner-action boundary
result copy/decoding
Memory publication
retrieval/packing
host delivery
use/outcome attribution
cleanup/erasure
```

Correct that edge. Do not manufacture another registry, report family or duplicated lesson to hide it.

## 17. Required evidence

Base evidence:

```text
real host event
→ Store commit or durable stage
→ replay when staged
→ restart
→ direct continuation/context or retrieval
→ exact source open
```

Learning evidence:

```text
stable caller + precommitted global WriteId
→ one admitted call / at most one provider attempt
→ exact result or typed no-result/unknown
→ decoded revision or valid no-change
→ later context reads resulting revision
→ exact caller-authorized cleanup
→ backup admission closure + restart/rollback reconciliation
```

Retention/erasure evidence:

```text
backup contains admitted calls only
→ proven absent attempts retired
→ backup-set change durably read back
→ monotonic retain-after advance
→ fixed-window list complete above cut
→ erased content leaves membership tombstone while pinned
→ explicit history_gap/owner debt when guarantees unavailable
```

Source review, DTOs, schema execution and Clippy are not runtime qualification, but are required minimum checks during implementation.