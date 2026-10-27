# Eliot Memory OS V3 — Cognition

**Revision 1.0-draft.23 · 2026-10-27 · normative algorithms used by V3.**

[Architecture](ARCHITECTURE.md) owns product and authority invariants. [Implementation](IMPLEMENTATION.md) owns runtime, schema and persistence. [Inference Contract 0.18](INFERENCE-CONTRACT.md) owns the sole Memory↔controller boundary. This document defines reconstruction, retrieval, learning, revision and failure diagnosis.

Initial learning changes external memory, methods, context selection and bounded configuration. It does not imply model-weight training.

## 0. Availability boundary

Base cognition works without controller inference:

- direct work-address reconstruction;
- exact and lexical retrieval;
- explicit notes, corrections and commitments;
- source/history opening;
- deterministic applicability and grounds handling;
- bounded context packing.

Model-assisted learning waits for controller issue #200, V2 L0/L1 and Contract 0.18 P1a. Missing inference never disables Base.

## 1. Observations, claims and revisions

An observation preserves source occurrence identity, exact accepted bytes/blob, occurrence/receipt times, work/resource binding, locator, capture limitations, source-supplied relations and disclosure. It records what a source supplied, not universal truth. Equal payloads from different occurrences remain separate.

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

Path, branch, commit and resource version are environment, not task identity.

Algorithm:

1. resolve captured binding;
2. open current addressed goal/plan/progress/commitments;
3. add later observations bound to continuing work;
4. apply explicit correction/withdrawal/supersession;
5. mark association/environment gaps;
6. only then retrieve related experience.

A similar cancelled direction does not become current. Late results keep issue-time binding. Fork/transfer creates relations, not silent renaming.

## 3. Grounds and applicability

For one conclusion revision:

- links in one non-null group are conjunctive;
- different groups are alternatives;
- ungrouped support is advisory;
- navigation is not evidence.

Unknown composition remains unknown. Cycles add no independent support.

Applicability is `applicable | inapplicable | conditional_or_unknown`. Evaluate material selectors, validity, resource/work version and exceptions. Token overlap or vector similarity is never sufficient proof. Method and contraindication travel together.

A correction/refutation/erasure triggers bounded reverse traversal over affected conclusion revisions. Load complete grounds groups before impact decision.

## 4. Episode membership and coverage

An episode is a finite grouping over actual session/task/call/result relations. Freeze job input and distinguish:

```text
selected
supplied
processed
unavailable
remaining
```

There is no global processed bit. Useful partial output cannot mark omitted material complete. Replay of one occurrence is not new experience.

## 5. Direct updates

Notes and commitments are ordinary scoped Memory items with source observations. Display, acknowledgement, due time or notification does not resolve a commitment.

Structured correction verifies expected current revision, preserves history, publishes the new revision, records source/grounds/replacement and coalesces affected work in one transaction. Replay returns the prior result; stale revision conflicts.

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

### 6.2 Candidate arms

Generate bounded candidates independently from direct handles/current-work addresses, exact cues/aliases, lexical search, compatible vectors, grounds/contradictions/replacements, typed relations and eligible methods. Apply project/work scope before arm limits; union before selection.

### 6.3 Lexical snapshot

Lexical search that ranks by BM25 uses one numbered match reference per scored field:

```text
WHERE search_text @0@ $query
SELECT ..., search::score(0) AS score
ORDER BY score DESC, canonical_id ASC
LIMIT $hard_limit
```

A score of zero is a valid match for a common term. Do not filter it as no-match.

BM25 inverse-document frequency and ordering change when the corpus changes. Therefore Base lexical retrieval is one bounded top-K Store statement snapshot per call. It has no durable page cursor. A later “more” request runs a new retrieval snapshot and records the new observed Store/schema/query version facts. Equal-score ordering is deterministic inside one snapshot through canonical ID.

Score ranks candidates only. It does not strengthen support, truth or applicability.

### 6.4 Packing

Priority:

1. current goal/criteria/progress;
2. exact corrections and constraints;
3. open commitments;
4. applicable/conditional methods plus exceptions;
5. relevant episodes;
6. dissent, uncertainty and missing checks;
7. exact source handles.

If a complete qualified unit cannot fit, emit a faithful reduction plus handle or omit it with an explicit gap. Never drop negation, version or contraindication.

### 6.5 Handoff

```text
prepared
emitted through host contract
action-associated when observable
used/influential usually unknown
outcome observed
```

Do not infer use/success from packet creation. Context failure does not roll back capture.

## 7. Exact open

`open` requires one exact handle/locator and optional bounded range. It never reruns search, conversion, Research or inference for a historical handle.

Return requested/resolved identity, revision/representation, range/digest, current/history disposition, capture limitations, qualifications, relation descriptors, expansion handles, continuation and explicit missing/forbidden/erased/damaged/unsupported state.

Historical handles never fall forward. Empty selector is not broad retrieval.

## 8. Processing methods and jobs

A processing method is an ordinary versioned Memory item with purpose, instruction body, input/result contract, conditions/limitations and disclosure consequences.

First enable stores a real default. Upgrade never overwrites an edited revision. Job claim freezes exact method and source coverage. A stored method with no consumer is not improvement.

Automatic mode is `off | idle | background`; profile may deny automatic calls. New committed input, correction or explicit question may trigger interpretation. Reads, packet creation, cleanup and accounting do not.

For one `(project,purpose,target)`, allow one active job and one coalesced successor. Waiting is not failure.

## 9. Controller-backed job lifecycle

### 9.1 Stable identity and live admission

Before each caller mutation:

1. authenticate exact controller/client identity;
2. allocate and durably advance global ULID outside rollback roots;
3. persist the WriteId in the owning job/maintenance record;
4. only then send.

Live recovery reuses the exact method, ID and bytes. Mismatch is `id_conflict`. Provider uncertainty remains with the retained call; never allocate a replacement call ID.

Admission state:

```text
prepared | admitted | retired_not_admitted | admission_unknown
```

### 9.2 Result and cognitive states

1. read bounded call status;
2. range-read exact result bytes when present;
3. verify length/digest;
4. durably publish a Memory result blob;
5. decode through a purpose-specific schema;
6. retain malformed/partial transport facts without cognitive success;
7. publish accepted revisions atomically;
8. create release only after verified copy or terminal no-result;
9. ask daemon backup-set owner whether any controlled generation still depends on the call.

Cognitive states:

```text
changes
no_change
partial
conflict_or_unknown
decode_failed
operational_failed
```

No-change requires completed cognitive work over supplied input. Cleanup is separate from cognitive outcome.

### 9.3 Cleanup authority

With valid caller, queued work may receive cancel, then release with `memory_copy_verified | terminal_without_result | abandon_for_erasure`.

Controller-owner break-glass erase is external authority. Memory records owner-action debt until non-content readback. A useful revision may be consumed while cleanup remains incomplete.

## 10. Backup admission and authority

### 10.1 Owner order

Daemon owns both controller-mutation and backup-set owners.

```text
close/drain controller mutation
→ enter backup-set transition
→ classify all external IDs and capture controller/spool cut
→ build canonical plan
→ atomically publish final directory with fence already inside
→ leave transition
→ reopen controller mutation
```

No release/retention can cross a newly visible fence.

### 10.2 External-effect cut

Call IDs become:

```text
admitted | retired_not_admitted | admission_unknown
```

Cancel/release/retention IDs become:

```text
effect_observed | retired_not_sent | mutation_unknown
```

Old backup never first-admits an absent ID. After rollback, still-needed effects are recomputed from current call, controller cut and installation backup set. A new effect receives a fresh ID only after post-cut inventory.

Every admitted call is `controller_closed` or `controller_dependent`.

### 10.3 Plan and first visibility

Backup ID is `b_` plus 32 lowercase hex characters from 128 OS-random bits. Canonical plan contains backup ID, expected manifest identity, root/schema/spool cut, controller/client/token/high-water/cut, dependencies, retired attempts, disclosure and gaps. Digest excludes itself, publication state and later part/manifest digests.

Daemon writes fence inside a private same-parent temp directory, flushes it, then atomically no-replace renames the directory to final ID and flushes/reopens parent/fence. Final directory never appears empty.

Pre-rename crash leaves non-pinning temp cleanup debt. Post-rename sync/readback uncertainty becomes `publication_unknown` and pins conservatively.

### 10.4 Terminal state

```text
valid standalone retire -> retired/non-restorable
valid standalone abort  -> aborted-before-publish
fence + matching manifest + no terminal -> published/restorable
fence + no valid manifest/terminal      -> preparing/publication_unknown
other ambiguity                         -> unresolved/fail closed
```

Abort/retire are self-contained terminal tombstones after exact prerequisites. They remain authoritative after content cleanup and prevent ID reuse. Terminalization is not erasure.

### 10.5 Bounded restore lease

Before candidate work, validate finite part count, per-part bytes, total bytes and canonical unique relative paths.

The whole restore keeps a logical lease plus final-directory/fence/manifest handles opened no-follow with read sharing only. It does not keep every part open.

For each part in manifest order:

1. open one no-follow read handle with write/delete sharing denied;
2. verify regular identity, relative path, exact length and digest;
3. copy and verify it into candidate;
4. close before the next part.

Logical owner blocks daemon retirement/cleanup. The active handle prevents replacement during read; digest catches pre-open substitution. Keep the logical lease and directory/fence/manifest handles through final terminal/manifest identity recheck before cutover.

Supervisor owns candidate process/root only. Daemon/channel loss forces supervisor to kill/reap/discard candidate before another daemon or cutover. A scan without a held lease is not restore authority.

### 10.6 Retention denominator

```text
required_retain_after_seq =
  minimum high_water among:
    published non-retired restorable backups
    unresolved preparing/publication_unknown fences
```

In-cut dependencies remain unreleased rather than lowering the monotonic cut. Restored pending retention rows are not blindly sent; desired cut is recomputed from installation records and controller readback.

## 11. Exact rollback and external work

Restore never writes into live root or invents merge of later rows. Healthy current Store first gets a safety backup; disaster mode records unavailable current inventory. Current deletion notices dominate backup; current post-cut spool merges by exact bytes/disposition; previous root remains until explicit retirement.

In-cut jobs:

```text
controller_closed       restore from backup facts
controller_dependent    exact controller call/copy must remain
retired_not_admitted    old ID stays retired
admission_unknown       inference disabled
```

Page one fixed post-cut interval `(backup_high_water, inventory_high_water]`. Do not adopt post-cut results as restored cognition. Valid caller performs dependency-aware cleanup; missing caller creates owner-action debt.

History gap, unknown auxiliary mutation, terminal ambiguity, restore-limit violation, missing dependent copy or identity loss leaves `external_work_inventory_unavailable`; Base remains usable.

Store maintenance mirrors are reconciled against installation records before job claims. Future-timeline mirrors cannot create terminal records, clear pins or send stale release/retention effects.

## 12. Consolidation, disagreement and improvement

Distinguish source replay, packet grouping, same-item revision, synthesis, generalization and correction/split. Broader patterns create separate provisional items linked to exact sources; they do not merge source IDs or rewrite history.

Disagreement belongs to a question, scope and time. Preserve alternatives/grounds and select the cheapest discriminating observation. Voting is not evidence. Prediction records expected observation before action.

Outcome attribution distinguishes method offered, handoff evidence, action observed, adherence known/inferred/unknown, criterion outcome and comparative benefit. One attributable attempt/criterion contributes once.

Method improvement identifies the exact failed edge or revision, retains a counterexample, revises conditions/body or creates scoped negative memory, preserves history and proves later context/request consumes the new revision.

## 13. Forgetting and erasure

Withdrawal changes guidance, not bytes.

Physical erasure publishes a deletion notice, closes affected mutation/replay, reconciles effects, fences jobs, terminalizes dependent backups after leases, deletes their content, uses caller cancel/release-abandon where available, otherwise retains owner-action debt, removes current rows/blobs/spool/packet/job copies and deletes affected previous roots/candidates/backups wholly when selective offline rewrite is absent.

A controller call above retain cut may keep bounded membership tombstone after content deletion. Complete tombstone deletion requires backup terminalization and prior cut advance.

## 14. Failure diagnosis and evidence

Classify the failed edge:

```text
host capture
relay/daemon IPC
Store/spool durability
schema wrapper/catalog/query DTO
work binding/source selection
lexical snapshot/packing
controller identity/WriteId admission
backup cut/first visibility
terminal reconciliation
restore limits/streaming lease/candidate custody
release/retention controlled set
profile/disclosure/provider readback
result copy/decoding/publication
host delivery/use/outcome attribution
cleanup/erasure
```

Correct that edge; do not add another registry or report family.

Base evidence:

```text
real event → Store commit or durable stage → replay → restart → context/retrieval → exact open
```

Backup evidence:

```text
final directory first visible with exact fence
→ finite limits admitted
→ every external ID dispositioned
→ parts streamed with bounded handles and exact digests
→ final lease recheck before cutover
→ crash cannot cut over stale candidate
→ terminal state survives cleanup
```

Learning evidence:

```text
stable caller + precommitted WriteId
→ one admitted call / at most one provider attempt
→ exact result or typed unknown
→ decoded revision or valid no-change
→ later context consumes it
→ dependency-aware cleanup after restart/rollback
```