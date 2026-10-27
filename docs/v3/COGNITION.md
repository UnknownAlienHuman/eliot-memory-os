# Eliot Memory OS V3 — Cognition

**Revision 1.0-draft.20 · 2026-10-27 · normative algorithms used by V3.**

[Architecture](ARCHITECTURE.md) owns product/authority invariants. [Implementation](IMPLEMENTATION.md) owns runtime and persistence. [Inference Contract 0.15](INFERENCE-CONTRACT.md) owns the sole Memory↔controller call boundary. This document defines reconstruction, retrieval, learning, revision and self-improvement algorithms.

Nothing here implies model-weight training. Initial learning changes external memory, processing methods, context selection and bounded configuration.

## 0. Availability boundary

Base cognition works without controller inference:

- direct work-address reconstruction;
- exact/lexical retrieval;
- explicit notes, corrections and commitments;
- source/history opening;
- deterministic applicability/grounds handling;
- bounded context packing.

Model-assisted learning waits for controller V2 issue #200, V2 L0/L1 and Contract 0.15 P1a. Missing inference never disables Base.

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
3. Add later observations bound to same continuing work.
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

Evaluate material selectors, validity, resource/work version and explicit exceptions. Token overlap or vector similarity is never sufficient proof. Method and contraindication travel together.

### 3.3 Source change

Correction, refutation, live-condition change or erasure triggers bounded reverse traversal over affected conclusion revisions. Load complete grounds groups before impact decision. Traversal pages/coalesces; it does not verify whole graph before ordinary reads.

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
processed      portions result actually covers
unavailable    omitted/missing/damaged material
remaining      eligible material not covered
```

There is no global processed bit. Useful partial output cannot mark omitted material complete. Replay of one source occurrence does not create new experience.

## 5. Direct user updates

### 5.1 Notes and commitments

Explicit notes/commitments use ordinary Memory items with source observation and scope. Acknowledgement, display, due time or notification does not resolve a commitment. Resolution follows matching observed event or explicit owner change.

### 5.2 Corrections

Structured correction is authoritative user intent about Memory content, not automatic truth about external world.

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

Apply project/work selectors before arm limits. Union before final selection. One arm's top-k cannot erase material exception found by another.

### 6.3 Ranking

Rank relevance separately from support/applicability. Retrieved item remains qualified by source, revision, limitations and conditions. Retrieval frequency does not strengthen truth.

### 6.4 Packing

Pack, in priority order:

1. current goal/criteria/progress;
2. exact corrections and constraints;
3. open commitments;
4. applicable/conditional methods plus exceptions;
5. relevant prior episodes;
6. dissent, uncertainty and missing checks;
7. exact source handles.

If complete qualified unit cannot fit, emit faithful bounded reduction plus handle or omit it with explicit gap. Never drop negation/version/contraindication to fit.

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

`open` requires one exact handle/locator and optional bounded range. It never reruns search, conversion, Research or inference to satisfy historical handle.

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

A processing method is ordinary versioned Memory item:

```text
purpose
instruction/body
input contract
result contract
conditions/limitations
disclosure consequences
```

First enable stores one real default method. Upgrade never overwrites user-edited/learned revision. Job claim freezes exact method revision; request builder opens that body. Stored method with no consumer is knowledge, not improvement.

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

During normal live recovery, prepared ID may still first-admit. During backup/restore, §14 applies stricter cut semantics.

### 9.3 Result read and decode

1. Read bounded non-content call status.
2. When result exists, range-read exact bytes.
3. Verify length/digest.
4. Durably publish Memory result blob.
5. Decode through purpose-specific closed schema.
6. Retain malformed/partial transport facts without cognitive success.
7. Publish accepted revisions atomically under expected revisions.
8. Create release WriteId only after verified Memory copy or terminal no-result.
9. Before sending release, scan the authoritative installation-scoped controlled backup set.

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

### 9.5 Cleanup authority and controlled backup set

Cleanup is separate from cognitive outcome:

- verified Memory result copy → `memory_copy_verified`;
- terminal call with no future result → `terminal_without_result`;
- unresolved work selected for erasure → `abandon_for_erasure`.

With valid caller, queued work may first receive `inference.cancel`, then caller `inference.release(...)`.

One controller-mutation owner serializes call admission, cancel, release and retention advance. Backup/retirement closes or coordinates this owner so cleanup cannot pass stale controlled-set readback.

For each admitted in-cut call, backup stores:

```text
controller_closed
controller_dependent
```

`controller_closed` means backup contains exact terminal Memory-owned result/no-result and no future controller settlement, copy, cleanup or readback is required.

`controller_dependent` means backup still needs controller status, current/future result bytes or cleanup/readback.

The authoritative set is reconstructed from installation files:

```text
fence + matching manifest + no retire  -> retained/restorable
fence + matching manifest + retire     -> retired/non-restorable
fence + no manifest + abort             -> aborted-before-publish
other ambiguity                         -> unresolved/fail closed
```

Release remains pending while any retained restorable backup or unresolved provisional fence marks the call dependent.

A published backup is retired only by exact durable `retire.json`. File deletion is not retirement. `retire.json` is mutually exclusive with pre-publication abort, binds backup/plan/manifest identity and is retained as monotonic tombstone after content cleanup.

`preparing` and `publication_unknown` fences pin post-cut retention at their recorded high-water. Published backups pin until valid retirement. Retirement-marker publication unknown leaves backup pinned.

Do not lower `retain_after_seq`; preservation comes from no-prune-unreleased behavior for in-cut dependencies and controlled-set high-water denominator for post-cut inventory.

Controller-owner `inference.erase` is local break-glass. Memory cannot call it. When caller cleanup unavailable, Memory records `owner_action_required` plus non-content call identity and waits for observed owner readback. Request alone is not effect.

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

Broader pattern creates separate provisional item linked to exact sources. It does not merge source IDs or rewrite historical handles. Split publishes new current items/relations while old handles remain exact.

Curation result is complete only when ordinary context/open/method consumers change. Unread report is not product behavior.

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

Prediction records expected observation before action, conditions and available check. Static dependency, co-change and causal explanation are distinct.

Research starts from retained Memory/exact local sources. External acquisition answers concrete remaining gap. Store compact findings, alternatives, coverage and exact report/source handles. Failed request, completed-uninformative and useful-partial are different outcomes. Do not loop merely because uncertainty remains.

## 14. Backup admission, publication, retirement and rollback

### 14.1 Admission/dependency cut and canonical plan

Before controlled backup:

1. stop new application mutations and controller-backed work;
2. close/drain the single controller-mutation owner so no call/cancel/release/retention send races the cut;
3. pause replay and reconcile active Store-write outcome;
4. persist every already-created call/cancel/release WriteId;
5. authenticate exact controller/client identity;
6. classify every call ID:
   - exact call/readback → `admitted` + `admission_seq`;
   - exact healthy absence/no sender → `retired_not_admitted`, never send again;
   - unavailable/ambiguous → `admission_unknown`, continuity gap;
7. reconcile created cancel/release from actual call state or retire proven-unsent mutation;
8. classify every admitted call:
   - `controller_closed` if backup is fully self-contained and no controller state/copy remains required;
   - otherwise `controller_dependent`;
9. record controller `high_water` and guaranteed `retain_after_seq`;
10. under brief spool lock capture exact spool cut/generation and immutable entry inventory, then release lock;
11. construct canonical immutable plan containing backup ID, expected manifest identity, selected root/schema/spool cut, controller/client/token/high-water/cut, admitted dependency classifications, retired attempts, disclosure and gaps;
12. compute `backup_plan_digest` excluding its own digest, publication state and later part/manifest digests;
13. durably publish/read back installation-scoped `fence.json` outside rollback Store roots;
14. only then publish backup parts and final manifest.

Final manifest repeats plan digest and actual inventories/digests. It never requires precommitted digest of itself. Store maintenance row is status mirror only.

### 14.2 Publication and retirement records

```text
backups/<backup-id>/
  fence.json
  parts/...
  manifest.json
  abort.json?
  retire.json?
```

Derived states:

```text
preparing
publication_unknown
published
aborted_before_publish
retired
```

- exact fence + valid matching manifest + no retire → published/restorable;
- exact fence + final absent + partial cleanup + valid abort → aborted-before-publish;
- fence without valid manifest/abort → preparing/publication-unknown;
- valid published backup + matching durable retire → retired/non-restorable;
- mismatch, abort+retire or ambiguity → publication-unknown.

Startup/restore/maintenance scans installation records before release, owner-cleanup handoff or retention advance. Store job/index is not authority.

### 14.3 Retention denominator

```text
required_retain_after_seq =
  minimum high_water among:
    published non-retired restorable backups
    unresolved preparing/publication-unknown fences
```

After controlled-set change is durable, create maintenance record with expected/new cut and precommitted retention WriteId, then call `inference.retention.advance` through controller-mutation owner. Lost reply reuses same ID. Advance before installation-file readback is invalid; failure to advance is conservative.

Do not lower monotonic cut for in-cut dependencies. They remain protected because release is fenced and controller cannot prune open/unreleased call/copies.

### 14.4 Backup retirement

Retirement is monotonic and separate from deletion:

1. require exact valid published backup;
2. serialize through backup-maintenance owner;
3. create `retire.json` binding backup ID, plan digest, observed manifest digest, retirement operation ID/reason and format version;
4. publish create-new/no-reparse with file/parent durability and exact readback;
5. only then exclude backup from restore and dependency/retention pin scans;
6. recompute release and high-water denominators;
7. perform content-bearing cleanup later while retaining retirement tombstone.

`abort.json` applies only to never-published candidate. Abort and retire are mutually exclusive. Retirement publication unknown keeps backup published and pinned. Repeated retirement is exact readback, not overwrite.

Retirement does not satisfy physical erasure while parts remain.

### 14.5 In-cut jobs after restore

```text
controller_closed
  restore from backup facts; controller row may be absent

controller_dependent
  exact call and required copy must remain;
  absence/mismatch is damaged/history_gap

retired_not_admitted
  old ID remains retired; fresh successor only after inventory

admission_unknown
  hold with inference disabled
```

Old backup never first-admits absent call ID. Backup with valid retirement marker is refused.

### 14.6 Post-cut calls

Capture one inventory high-water and page fixed interval:

```text
inference.list(after = backup_high_water,
               through = inventory_high_water)
```

Cursor binds controller/client, bounds, API version and page shape. If backup high-water below `retain_after_seq`, return `history_gap`; physical presence of some rows does not make interval complete.

Because absent cut attempts were retired, returned calls are outside backup's admitted set. Do not adopt results. With valid caller, use cancel/release-abandon after controlled-set dependency check. Without caller, retain owner-action-required debt until controller-local owner readback.

All new inference remains disabled until inventory completes and every row is dispositioned. Base remains usable. Controller/caller unavailability, admission unknown, publication/retirement unknown, missing dependent copy or history gap produces `external_work_inventory_unavailable`, never false empty or complete rollback.

### 14.7 Controlled-set removal and cleanup

When backup leaves restorable set:

1. publish/read back exact retire or abort record;
2. recompute dependent calls and high-water denominator;
3. clear release fence only for calls with no remaining dependency;
4. permit pending release only after immediate recheck under mutation owner;
5. advance retain cut separately from the new controlled set;
6. clean content-bearing files without deleting the monotonic retirement fact.

Crash before release/advance is conservative. Never clear pins by deleting authority files first.

## 15. Forgetting and erasure

Withdrawal changes guidance, not physical bytes.

Physical erasure:

1. publish monotonic deletion notice;
2. close affected mutation/replay admission;
3. reconcile active Store/replay/controller effects;
4. cancel/fence pending jobs;
5. retire every published controlled backup and abort every provisional candidate that marks affected call dependent;
6. physically delete their content-bearing parts before complete-erasure claim;
7. use caller cancel/release-abandon when caller valid;
8. otherwise record owner-action-required and wait for observed break-glass result;
9. delete current rows/blobs/spool/packet/job copies;
10. delete affected previous roots/candidates/backups wholly when selective offline rewrite absent;
11. retain explicit provider/off-machine/tombstone gaps.

Controller call above `retain_after_seq` may retain only bounded non-content membership tombstone after content deletion. Complete deletion of tombstone requires prior backup retirement and cut advancement.

Deletion fence/controller tombstone/backup retire marker prevents false reintroduction/inventory/restore but is not proof every controlled content copy is deleted. Complete erasure requires exact absence or explicit incomplete debt.

## 16. Failure diagnosis

Classify failed connected edge:

```text
host capture
relay/daemon IPC
Store/spool durability
work binding/source selection
controller identity/WriteId admission
backup admission closure
backup dependency classification
backup plan/fence publication
backup publication or retirement reconciliation
release/retention controlled-set scan
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
→ rollback-safe installation-scoped plan fence
→ monotonic retirement fact when backup leaves restorable set
→ dependency-aware release and retention
→ backup admission closure + restart/rollback reconciliation
```

Retention/backup evidence:

```text
backup contains admitted calls only
→ every admitted call is controller-closed or dependent
→ canonical plan digest has no self-reference
→ installation-scoped fence exists before backup parts
→ rollback cannot erase unresolved fence authority
→ rename/sync/readback unknown pins release and retention
→ published backup stays pinned until valid retire marker
→ partial file deletion cannot create false unpin
→ dependent call remains unreleased even below current cut
→ fixed-window list complete above cut
→ controller-closed call restores without controller row
→ valid abort/retire clears pins through exact controlled-set readback
→ physical cleanup remains separate from retirement
→ explicit history_gap/owner debt when guarantees unavailable
```

Source review, DTOs, schema execution and Clippy are not runtime qualification, but are required minimum checks during implementation.