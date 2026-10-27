# Eliot Memory OS V3 — Cognition

**Revision 1.0-draft.22 · 2026-10-27 · normative algorithms used by V3.**

[Architecture](ARCHITECTURE.md) owns product and authority invariants. [Implementation](IMPLEMENTATION.md) owns runtime, schema and persistence. [Inference Contract 0.17](INFERENCE-CONTRACT.md) owns the sole Memory↔controller call boundary. This document defines reconstruction, retrieval, learning, revision and failure diagnosis.

Initial learning changes external memory, methods, context selection and bounded configuration. It does not imply model-weight training.

## 0. Availability boundary

Base cognition works without controller inference:

- direct work-address reconstruction;
- exact and lexical retrieval;
- explicit notes, corrections and commitments;
- source/history opening;
- deterministic applicability and grounds handling;
- bounded context packing.

Model-assisted learning waits for controller issue #200, V2 L0/L1 and Contract 0.17 P1a. Missing inference never disables Base.

## 1. Observations, claims and revisions

An observation preserves what a source supplied:

```text
occurrence identity
exact accepted bytes/blob
occurrence time + precision
receipt time
work/resource binding
locator
capture limits/redactions
source-supplied relations
disclosure
```

Observation is not a truth claim. Equal payloads from different occurrences remain different observations.

A semantic item is a revisable claim, method, explanation, commitment, prediction or project view. It retains current revision, origin/reuse/disclosure, conditions/exceptions, validity, grounds and separate support/exposure/influence states. Historical revisions remain exact-openable.

Original bytes, converted representation, excerpt, summary and semantic claim have distinct identities and explicit links.

## 2. Current-work reconstruction

Preferred address:

```text
project + workspace + actual host task identity
```

Fallback:

```text
project + workspace + actor/session
```

Path, branch, commit and resource version are observed environment, not task identity.

Algorithm:

1. resolve captured binding;
2. open current addressed goal/plan/progress/commitments;
3. add later observations bound to continuing work;
4. apply explicit corrections, withdrawal and supersession;
5. mark unresolved association/environment changes as gaps;
6. only then retrieve related experience.

A similar cancelled direction does not become current. Late results keep issue-time binding. Fork/transfer creates relations, not silent renaming.

## 3. Grounds and applicability

For one conclusion revision:

- links in one non-null group are required together;
- different groups are alternatives;
- ungrouped support is advisory;
- navigation links have no evidential Boolean meaning.

Unknown composition remains unknown. Cycles provide no independent support.

Applicability is:

```text
applicable
inapplicable
conditional_or_unknown
```

Evaluate material selectors, validity, resource/work version and explicit exceptions. Token overlap or vector similarity is never sufficient proof. Method and contraindication travel together.

A source correction/refutation/erasure triggers bounded reverse traversal over affected conclusion revisions. Load complete grounds groups before deciding impact.

## 4. Episode membership and coverage

An episode is a finite grouping over actual session/task/call/result relations. Freeze job input explicitly and distinguish:

```text
selected
supplied
processed
unavailable
remaining
```

There is no global processed bit. Useful partial output cannot mark omitted material complete. Replay of one occurrence does not create another experience.

## 5. Direct user updates

Notes and commitments are ordinary scoped Memory items with source observations. Display, acknowledgement, due time or notification does not resolve a commitment.

Structured correction is authoritative user intent about Memory content, not automatic truth about the world. One transaction verifies expected current revision, preserves history, publishes new revision, records source/grounds/replacement and coalesces affected work. Replay returns the prior result; stale expected revision conflicts.

## 6. Retrieval and context

### 6.1 Decision frame

```text
work address
observed resource versions
focused question
exact cues
constraints
budget
```

### 6.2 Independent candidate arms

Generate bounded candidates from:

- direct handles and current-work addresses;
- exact cues/aliases;
- lexical search over observation excerpts and Memory text;
- compatible vector space when enabled;
- grounds, contradictions and replacements;
- typed relations;
- local and eligible reusable methods.

Apply project/work scope before arm limits. Union before final selection. One arm's top-k cannot erase an exception found by another.

Lexical score ranks candidates only. It does not strengthen support or applicability.

### 6.3 Packing

Priority:

1. current goal/criteria/progress;
2. exact corrections and constraints;
3. open commitments;
4. applicable/conditional methods plus exceptions;
5. relevant episodes;
6. dissent, uncertainty and missing checks;
7. exact source handles.

If a complete qualified unit cannot fit, emit a faithful reduction plus handle or omit it with an explicit gap. Never drop negation, version or contraindication.

### 6.4 Handoff

```text
prepared
emitted through host contract
action-associated when observable
used/influential usually unknown
outcome observed
```

Do not infer use or success from packet creation. Context failure does not roll back capture.

## 7. Exact source opening

`open` requires one exact handle/locator and optional bounded range. It never reruns search, conversion, Research or inference to satisfy a historical handle.

Return exact requested/resolved identity, revision/representation, range/digest, current/history disposition, capture limitations, qualifications, relation descriptors, expansion handles, continuation and explicit missing/forbidden/erased/damaged/unsupported state.

Historical handles never fall forward. Empty selector is not broad retrieval.

## 8. Processing methods and jobs

A processing method is an ordinary versioned Memory item with purpose, instruction body, input/result contract, conditions/limitations and disclosure consequences.

First enable stores a real default method. Upgrade never overwrites an edited revision. Job claim freezes exact method revision and source coverage. A stored method with no consumer is knowledge, not improvement.

Automatic mode is `off | idle | background`. Profile may deny automatic calls. New committed input, correction or explicit question may trigger interpretation. Reads, packet creation, cleanup and accounting do not self-trigger another learning job.

For one `(project,purpose,target)`, allow one active job and one coalesced successor. Waiting is not failure.

## 9. Controller-backed job lifecycle

### 9.1 Stable identity and pre-send state

Before each caller mutation:

1. authenticate exact controller/client identity;
2. allocate and durably advance global ULID from installation state outside rollback roots;
3. persist the WriteId in the owning job/maintenance record;
4. only then send.

Live call recovery reuses the exact call method, ID and bytes. Mismatch is `id_conflict`. Provider uncertainty belongs to the retained call; never allocate another call ID to recover.

### 9.2 Result and cognitive states

1. read bounded non-content call status;
2. when result exists, range-read exact bytes;
3. verify length/digest;
4. durably publish a Memory result blob;
5. decode through a purpose-specific closed schema;
6. retain malformed/partial transport facts without cognitive success;
7. publish accepted revisions atomically;
8. create release intent only after verified copy or terminal no-result;
9. ask the daemon backup-set owner whether any controlled generation still depends on the call.

Cognitive result states:

```text
changes
no_change
partial
conflict_or_unknown
decode_failed
operational_failed
```

No-change is valid only after completed cognitive work on supplied input. Cleanup state is independent.

### 9.3 Cleanup authority

With valid caller, queued work may receive cancel, then release with one disposition:

```text
memory_copy_verified
terminal_without_result
abandon_for_erasure
```

Controller-owner break-glass erase is external authority. Memory records owner-action-required debt until non-content owner readback.

A useful revision may be consumed while cleanup remains incomplete; status and erasure expose the debt.

## 10. Backup admission and authority

### 10.1 Owner order

Daemon owns both controller-mutation and backup-set owners.

For a new backup:

```text
close/drain controller mutation
→ enter backup-set transition
→ classify all external IDs and capture exact controller/spool cut
→ build canonical plan
→ atomically publish final directory with fence already inside
→ leave transition
→ reopen controller mutation
```

This prevents release/retention from crossing a newly visible fence.

### 10.2 External-effect cut

Every created call ID becomes:

```text
admitted
retired_not_admitted
admission_unknown
```

Every cancel/release/retention ID becomes:

```text
effect_observed
retired_not_sent
mutation_unknown
```

Old backup never first-admits an absent call or auxiliary ID. After rollback, still-needed effects are recomputed from current call, controller cut and installation backup set; a new effect receives a fresh ID only after post-cut inventory.

Every admitted call is:

```text
controller_closed
controller_dependent
```

Closed means the backup is fully self-contained and no future controller settlement/copy/readback/cleanup is required. Otherwise it is dependent.

### 10.3 Plan and first visibility

Backup ID grammar:

```text
b_<32 lowercase hex characters>
```

The ID comes from 128 OS-random bits. Canonical plan contains the ID, expected manifest identity, root/schema/spool cut, controller/client/token/high-water/cut, admitted dependencies, retired attempts, disclosure and gaps. Digest excludes itself, publication state and later part/manifest digests.

The daemon writes the fence into a private same-parent temporary directory, flushes it, then atomically renames the directory without replacement to the final ID and flushes/reopens the parent/fence. Final directory never appears empty.

Pre-rename crash leaves non-pinning temp cleanup debt. Post-rename sync/readback uncertainty becomes `publication_unknown` and pins conservatively after reconciliation.

### 10.4 Terminal state

```text
valid standalone retire -> retired/non-restorable
valid standalone abort  -> aborted-before-publish
fence + matching manifest + no terminal -> published/restorable
fence + no valid manifest/terminal      -> preparing/publication_unknown
other ambiguity                         -> unresolved/fail closed
```

Abort/retire are self-contained terminal tombstones after exact prerequisites. They remain authoritative after content cleanup and prevent ID reuse. Terminalization is not erasure.

### 10.5 Restore lease

Daemon backup-set owner grants one lease over exact backup identity and retains no-follow handles to directory, fence, manifest and parts with delete sharing denied. The lease remains through candidate materialization, verification and final terminal-state recheck before cutover.

Supervisor owns candidate process/root only. It receives closed identity/digest intents. Retirement, abort and cleanup wait for the lease.

Daemon/channel loss makes supervisor kill/reap/discard the candidate before a new daemon or cutover. Supervisor loss is contained by the Job. A scan without a held lease is not restore authority.

### 10.6 Retention denominator

```text
required_retain_after_seq =
  minimum high_water among:
    published non-retired restorable backups
    unresolved preparing/publication_unknown fences
```

In-cut dependencies do not lower the monotonic cut; they remain unreleased. A restored pending retention row is never blindly sent. Current desired cut is recomputed from installation records and controller readback.

## 11. Exact rollback and external work

Restore never writes into the live root or invents merge of later Store rows. Healthy current Store first gets a safety backup; disaster mode records unavailable current inventory. Current deletion notices dominate backup. Current post-cut spool merges by exact bytes/disposition. Previous root remains until explicit retirement.

In-cut jobs:

```text
controller_closed       restore from backup facts
controller_dependent    exact controller call/copy must remain
retired_not_admitted    old ID remains retired
admission_unknown       hold; inference disabled
```

Capture one post-cut inventory high-water and page fixed interval `(backup_high_water, inventory_high_water]`. Do not adopt post-cut results as restored cognition. Valid caller uses dependency-aware cancel/release-abandon; missing caller creates owner-action debt.

History gap, identity loss, unknown auxiliary mutation, ambiguous backup terminal state or missing dependent copy leaves `external_work_inventory_unavailable`. Base remains usable.

Store maintenance mirrors are reconciled against installation records before job claims. A restored future-timeline mirror is superseded and cannot create terminal records, clear pins or send old release/retention effects.

## 12. Consolidation, disagreement and improvement

Distinguish source replay, packet grouping, same-item revision, new synthesis, generalization and correction/split. A broader pattern creates a separate provisional item linked to exact sources; it does not merge source IDs or rewrite historical handles.

Disagreement belongs to a question, scope and time. Preserve alternatives and grounds, then select the cheapest useful distinguishing observation. Voting is not evidence. Prediction records expected observation before action.

Outcome attribution distinguishes method offered, handoff evidence, action observed, adherence known/inferred/unknown, criterion outcome and comparative benefit. One attributable attempt/criterion contributes once.

Method improvement locates the exact failed edge or revision, retains a concrete counterexample, revises conditions/body or creates scoped negative memory, preserves history and proves a later context/request consumes the new revision.

## 13. Forgetting and erasure

Withdrawal changes guidance, not bytes.

Physical erasure:

1. publish monotonic deletion notice;
2. close affected mutation/replay;
3. reconcile active Store/controller effects;
4. cancel/fence jobs;
5. terminalize every dependent backup and provisional candidate after leases finish;
6. physically delete their content-bearing parts;
7. use caller cancel/release-abandon where available;
8. otherwise retain owner-action debt;
9. delete current rows/blobs/spool/packet/job copies;
10. delete affected previous roots/candidates/backups wholly when selective offline rewrite is absent;
11. retain explicit provider/off-machine/tombstone gaps.

A controller call above retain cut may keep only bounded non-content membership tombstone after content deletion. Complete tombstone deletion requires prior backup terminalization and cut advancement.

## 14. Failure diagnosis and required evidence

Classify the failed edge:

```text
host capture
relay/daemon IPC
Store/spool durability
schema/migration/query DTO
work binding/source selection
controller identity/WriteId admission
backup cut and staged-directory publication
terminal-state reconciliation
restore lease/candidate custody
release/retention controlled-set scan
profile/disclosure/capacity
provider execution/readback
result copy/decoding
Memory publication
retrieval/packing
host delivery
use/outcome attribution
cleanup/erasure
```

Correct that edge. Do not manufacture another registry or report family to hide it.

Base evidence:

```text
real host event
→ Store commit or durable stage
→ replay when staged
→ restart
→ continuation/context or retrieval
→ exact source open
```

Backup evidence:

```text
final directory first visible with exact fence
→ every external ID has cut disposition
→ plan digest has no self-reference
→ table/blob/spool inventories match manifest
→ restore holds file lease through final recheck
→ crash cannot create false unpin or cut over stale candidate
→ terminal marker remains authoritative after cleanup
→ physical cleanup remains separate from terminalization
```

Learning evidence:

```text
stable caller + precommitted WriteId
→ one admitted call / at most one provider attempt
→ exact result or typed no-result/unknown
→ decoded revision or valid no-change
→ later context reads it
→ dependency-aware cleanup after restart/rollback
```