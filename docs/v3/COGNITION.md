# Eliot Memory OS V3 — Cognition

**Revision 1.0-draft.21 · 2026-10-27 · normative algorithms used by V3.**

[Architecture](ARCHITECTURE.md) owns product/authority invariants. [Implementation](IMPLEMENTATION.md) owns runtime and persistence. [Inference Contract 0.16](INFERENCE-CONTRACT.md) owns the sole Memory↔controller call boundary. This document defines reconstruction, retrieval, learning, revision and self-improvement algorithms.

Nothing here implies model-weight training. Initial learning changes external memory, processing methods, context selection and bounded configuration.

## 0. Availability boundary

Base cognition works without controller inference:

- direct work-address reconstruction;
- exact/lexical retrieval;
- explicit notes, corrections and commitments;
- source/history opening;
- deterministic applicability/grounds handling;
- bounded context packing.

Model-assisted learning waits for controller V2 issue #200, V2 L0/L1 and Contract 0.16 P1a. Missing inference never disables Base.

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
9. Before sending release, obtain a current controlled-backup-set snapshot from the backup-set owner.

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

One controller-mutation owner serializes call admission, cancel, release and retention advance. One backup-set owner serializes backup IDs, installation-record transitions, restore leases and physical cleanup. Both are local owners around mutation/OS handles, not new services.

For each admitted in-cut call, backup stores:

```text
controller_closed
controller_dependent
```

`controller_closed` means backup contains exact terminal Memory-owned result/no-result and no future controller settlement, copy, cleanup or readback is required.

`controller_dependent` means backup still needs controller status, current/future result bytes or cleanup/readback.

The authoritative controlled set is reconstructed terminal-first from installation files:

```text
valid standalone retire -> retired/non-restorable
valid standalone abort  -> aborted-before-publish
fence + matching manifest + no terminal -> retained/restorable
fence + no manifest/terminal            -> preparing/publication-unknown
other ambiguity                           -> unresolved/fail closed
```

Release remains pending while any retained restorable backup or unresolved provisional fence marks the call dependent.

Abort/retire markers are self-contained immutable terminal tombstones after their creation prerequisites. They remain terminal after content cleanup and prevent backup-ID reuse. Surviving files that disagree, malformed markers or both terminal kinds fail closed.

`preparing` and `publication_unknown` fences pin post-cut retention at recorded high-water. Published backups pin until valid retirement. Terminal-marker publication unknown leaves state pinned.

Restore requires an exact read lease, not an initial scan. Retirement, abort and physical cleanup wait until candidate verification and final pre-cutover terminal-state recheck end.

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

## 14. Backup admission, terminal authority, restore lease and rollback

### 14.1 Admission/dependency/auxiliary cut and canonical plan

Before controlled backup:

1. stop new application mutations and controller-backed work;
2. close/drain the controller-mutation owner so no call/cancel/release/retention send races the cut;
3. pause replay and reconcile active Store-write outcome;
4. persist every already-created call/cancel/release/retention WriteId;
5. authenticate exact controller/client identity;
6. classify every call ID:
   - exact call/readback → `admitted` + `admission_seq`;
   - exact healthy absence/no sender → `retired_not_admitted`, never send again;
   - unavailable/ambiguous → `admission_unknown`, continuity gap;
7. classify every auxiliary mutation from current call/cut readback:
   - `effect_observed` when effect is visible or safely superseded;
   - `retired_not_sent` after exact no-send under drained owner;
   - `mutation_unknown` when readback is ambiguous;
8. classify every admitted call:
   - `controller_closed` if backup is fully self-contained and no controller state/copy remains required;
   - otherwise `controller_dependent`;
9. record controller `high_water` and guaranteed `retain_after_seq`;
10. under brief spool lock capture exact spool cut/generation and immutable entry inventory, then release lock;
11. obtain a fresh random non-reused backup ID from the backup-set owner;
12. construct canonical immutable plan containing backup ID, expected manifest identity, selected root/schema/spool cut, controller/client/token/high-water/cut, admitted dependencies, call/auxiliary dispositions, disclosure and gaps;
13. compute `backup_plan_digest` excluding its own digest, publication state and later part/manifest digests;
14. durably publish/read back installation-scoped `fence.json` outside rollback Store roots;
15. only then publish backup parts and final manifest.

Final manifest repeats plan digest and actual inventories/digests. It never requires precommitted digest of itself. Store maintenance row is status mirror only.

### 14.2 Installation records and terminal state

```text
backups/<backup-id>/
  fence.json?
  parts/...
  manifest.json?
  abort.json?
  retire.json?
```

Terminal markers contain bounded non-content backup/plan/fence identity, deterministic terminal operation ID, format and closed reason; retire also binds manifest digest.

Derived order:

```text
valid standalone retire -> retired/non-restorable
valid standalone abort  -> aborted-before-publish
fence + matching manifest + no terminal -> published/restorable
fence + no valid manifest/terminal      -> preparing/publication-unknown
malformed/mismatch/both terminal        -> unresolved/fail closed
```

Abort is created only after exact manifest absence, no live writer/lease and partial-content cleanup. Retire is created only for an exact published backup with no active restore lease. Once durable, the marker remains terminal after content cleanup. Backup ID is never reused.

Startup/restore/maintenance scans installation records before release, owner-cleanup handoff or retention advance. Store job/index is not authority.

### 14.3 Retention denominator

```text
required_retain_after_seq =
  minimum high_water among:
    published non-retired restorable backups
    unresolved preparing/publication-unknown fences
```

After controlled-set change is durable, recompute current desired cut, create a fresh maintenance record with expected/new cut and precommitted retention WriteId, then call `inference.retention.advance` through controller-mutation owner. Lost reply reuses same ID.

A restored pending retention intent is never sent from its row alone. Reconcile/retire it, then recompute from current installation records and current controller cut. Failure to advance is conservative.

Do not lower monotonic cut for in-cut dependencies. They remain protected because release is fenced and controller cannot prune open/unreleased call/copies.

### 14.4 Restore lease

Restore admission:

1. backup-set owner requires exact published non-retired state;
2. acquires one read lease and retained no-follow handles to fence, manifest and required parts;
3. blocks retire, abort and physical cleanup for that generation;
4. materializes and verifies a disposable candidate;
5. rechecks terminal records immediately before cutover while lease remains held;
6. commits selection cutover or abandons candidate;
7. releases lease.

Crash releases the in-process lease and startup discards the candidate. A scan without held lease is not restore authority.

### 14.5 In-cut jobs and auxiliary mutations after restore

```text
controller_closed
  restore from backup facts; controller row may be absent

controller_dependent
  exact call and required copy must remain;
  absence/mismatch is damaged/history_gap

retired_not_admitted
  old call ID remains retired

admission_unknown
  hold with inference disabled
```

Auxiliary IDs:

```text
effect_observed     retain observed effect, never resend ID
retired_not_sent    never send ID
mutation_unknown    hold until exact readback
```

Before ordinary job claims, reconcile restored maintenance mirrors against installation records and mark future-timeline/stale rows superseded. Such rows cannot create terminal records, clear pins or send release/retention.

After post-cut inventory, a still-needed cancel/release is recomputed from current call and controlled-set state. Retention target is recomputed from current installation records and controller cut. A new effect gets a fresh WriteId only then.

Old backup never first-admits an absent call or auxiliary ID.

### 14.6 Post-cut calls

Capture one inventory high-water and page fixed interval:

```text
inference.list(after = backup_high_water,
               through = inventory_high_water)
```

Cursor binds controller/client, bounds, API version and page shape. If backup high-water below `retain_after_seq`, return `history_gap`; physical presence of some rows does not make interval complete.

Because absent cut attempts were retired, returned calls are outside backup's admitted set. Do not adopt results. With valid caller, use recomputed cancel/release-abandon after controlled-set check. Without caller, retain owner-action-required debt until controller-local owner readback.

All new inference remains disabled until inventory completes and every row is dispositioned. Base remains usable. Controller/caller unavailability, call/auxiliary unknown, publication/terminal unknown, missing dependent copy or history gap produces `external_work_inventory_unavailable`, never false empty or complete rollback.

### 14.7 Controlled-set removal and cleanup

When backup leaves restorable set:

1. publish/read back exact terminal marker under backup-set owner;
2. recompute dependent calls and high-water denominator;
3. clear release fence only for calls with no remaining dependency;
4. permit pending release only after immediate mutation-owner recheck;
5. advance retain cut separately from current controlled set;
6. clean content-bearing files without deleting terminal tombstone.

Crash before release/advance is conservative. Never clear pins by deleting authority files first.

## 15. Forgetting and erasure

Withdrawal changes guidance, not physical bytes.

Physical erasure:

1. publish monotonic deletion notice;
2. close affected mutation/replay admission;
3. reconcile active Store/replay/controller effects;
4. cancel/fence pending jobs;
5. terminalize every published/provisional controlled backup that marks affected call dependent;
6. wait for any restore lease, then physically delete content-bearing files before complete-erasure claim;
7. use caller cancel/release-abandon when caller valid;
8. otherwise record owner-action-required and wait for observed break-glass result;
9. delete current rows/blobs/spool/packet/job copies;
10. delete affected previous roots/candidates/backups wholly when selective offline rewrite absent;
11. retain explicit provider/off-machine/terminal/membership-tombstone gaps.

Controller call above `retain_after_seq` may retain only bounded non-content membership tombstone after content deletion. Complete deletion of tombstone requires prior backup terminalization and cut advancement.

Deletion fence/controller tombstone/backup terminal marker prevents false reintroduction/inventory/restore but is not proof every controlled content copy is deleted. Complete erasure requires exact absence or explicit incomplete debt.

## 16. Failure diagnosis

Classify failed connected edge:

```text
host capture
relay/daemon IPC
Store/spool durability
work binding/source selection
controller identity/WriteId admission
backup call/auxiliary cut closure
backup dependency classification
backup id/plan/fence publication
terminal marker or cleanup reconciliation
restore lease/candidate cutover
restored Store mirror reconciliation
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
→ self-contained terminal backup state
→ restore lease through candidate verification/cutover recheck
→ dependency-aware release and retention
→ cut disposition for every caller mutation ID
→ restart/rollback reconciliation
```

Retention/backup evidence:

```text
backup contains admitted calls only
→ every call/auxiliary ID receives cut disposition
→ every admitted call is controller-closed or dependent
→ random backup ID is never reused
→ canonical plan digest has no self-reference
→ installation-scoped fence exists before backup parts
→ rollback cannot erase unresolved authority
→ publication unknown pins release and retention
→ standalone terminal marker survives content cleanup
→ restore lease prevents concurrent retirement/cleanup
→ stale Store mirror cannot alter installation state
→ dependent call remains unreleased even below current cut
→ fixed-window list complete above cut
→ controller-closed call restores without controller row
→ current effects are recomputed after rollback
→ explicit history_gap/owner debt when guarantees unavailable
```

Source review, DTOs, schema execution and Clippy are not runtime qualification, but are required minimum checks during implementation.