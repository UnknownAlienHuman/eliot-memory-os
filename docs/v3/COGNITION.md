# Eliot Memory OS V3 — Cognition

**Revision 1.0-draft.14 · 2026-10-26 · normative algorithms used by V3.**

This document defines how Eliot reconstructs current work, resolves revisable knowledge, retrieves context, learns from outcomes and improves connected methods. It does not define extra services. State, execution and ownership are defined in [Implementation](IMPLEMENTATION.md). External model execution, caller identity, `WriteId`, profiles, controlled copies and cleanup are defined by [INFERENCE-CONTRACT](INFERENCE-CONTRACT.md).

## 1. Cognitive units

Eliot distinguishes:

- **observation** — what one source occurrence supplied;
- **source representation** — exact retained bytes or declared transformation;
- **episode** — useful connected slice of observations;
- **claim** — asserted value or explanation;
- **hypothesis** — uncertain explanation;
- **view** — saved answer over examined scope;
- **method** — reusable guidance with conditions;
- **processing method** — recipe consumed by one learning handler;
- **prediction** — expected future observation;
- **outcome** — observed result of an attempt;
- **continuation** — current work state;
- **context packet** — rendered decision-time projection over exact revisions;
- **unknown** — explicit missing fact or unresolved relation;
- **commitment** — something still owed in a recorded scope.

A source event, search segment and episode are different. Search segments locate material; they do not replace sources or define tasks. Receiving an assertion is an observation of that assertion, not verification of its contents. Distinct record IDs do not establish independent corroboration.

### 1.1 Occurrence identity is not content equality

A source occurrence is identified by the strongest native event identity available inside its bound host/session/task/resource scope. When no native event key exists, relay-generated capture command ID identifies the occurrence.

A digest verifies retained bytes. It does not merge two occurrences merely because their payloads are equal and does not become source identity unless the object is explicitly content-addressed.

Therefore:

- replaying the same command and bytes returns the same observation/result;
- replaying the same identity with different bytes or binding is conflict;
- two different event/command IDs with identical text remain two occurrences;
- summaries, packet inclusions and transformed representations of one event remain one underlying occurrence, not corroboration.

### 1.2 Capture limitations are part of the source account

Accepted source content is retained exactly within its declared bound. Host omission, host truncation, configured exclusion and explicit secret redaction are different facts and remain visible.

A search excerpt, normalized tool field or compact summary is a representation. It cannot silently replace the accepted body. A generic sanitizer does not establish that removed URLs, paths, endpoints or final messages were irrelevant.

## 2. Current work before similarity

A decision frame separates stable project/workspace/task identity from observed path, branch, resource versions and time.

Reconstruct current work in this order:

1. open continuation by exact task or actor/session address inside workspace;
2. load relevant observations outside recorded per-stream coverage;
3. apply explicit goal, plan and constraint corrections;
4. preserve completed work, abandoned alternatives, open commitments and unresolved effects;
5. only then retrieve similar prior work.

For the first Claude host, `SessionStart` supplies the continuation boundary and `UserPromptSubmit` supplies the next decision frame. The triggering event is captured independently from the packet returned to the host.

If no task identity exists, use the narrowest known session/workspace continuation. Do not attach interleaved events to the newest prompt merely because it is newest. Generated plans and summaries cannot silently revise sourced goals. Branch switch changes applicability, not identity of continuing work. Fork and transfer retain explicit relations.

A continuation revision contains:

- active goal and source;
- current direction or plan;
- completed actions and available results;
- abandoned approaches and reasons;
- open commitments and unknowns;
- next useful step;
- represented streams/segments and gaps;
- exact source handles.

A continuation never replaces original observations. Reading a tail is not publishing a summary or proving all streams processed. Late events retain the task/resource binding in which they arose.

A compact summary is a derived representation of preceding material. It may help reconstruct work, but does not erase or supersede sources because the host compacted them.

## 3. Claim identity and current-state resolution

A comparison group uses minimum material identity:

```text
project + relevant workspace/task scope
subject/resource
aspect
perspective
relevant time and known resource conditions
```

Perspective distinguishes intended behavior, observed implementation and proposed explanation. Different workspaces or versions may legitimately have different values.

`resolve_current(group, decision_time)`:

1. load accessible alternatives and exact revisions outside semantic top-k;
2. apply stated validity, known resource conditions and scoped replacements;
3. preserve alternatives whose conditions differ;
4. evaluate explicitly represented grounds;
5. return current alternatives, conflict or unknown;
6. include qualifications and history handles.

Last write, highest similarity, retrieval frequency and model confidence are not universal authority rules. Support, exposure and influence remain separate.

### 3.1 Replacement and withdrawal

Prepare replacement outside the transaction. Publish new revision, revision-specific grounds, scoped retirement and job result atomically.

Failed publication leaves prior committed state intact. Competing replacements revalidate current revision. Result for source version A does not become evidence about source version B merely because it was published later.

After A→B, withdrawing B does not automatically restore A. Return another supported alternative or unknown. Restoring A requires new evidence or correction of the original replacement decision.

### 3.2 Compound grounds

A grounds group belongs to one conclusion revision. Every declared member of one group is required for that derivation. Different groups are alternatives. Ungrouped support is advisory. Navigation carries no evidential Boolean meaning.

| Situation | Consequence |
|---|---|
| All required members remain usable for stated scope | Basis remains available; conclusion is not thereby certified |
| Required premise is refuted or condition inapplicable | That group cannot justify the conclusion here |
| Member or relevance unresolved | Group is unresolved, not true or false |
| Composition unknown or member erased | Do not infer support from remaining count |

For `(A and B) or C`, loss of B breaks the first group but not intact C. If all groups fail, the old conclusion lacks declared basis; that does not prove the opposite. Surviving basis does not erase direct counterevidence.

A newer edition does not automatically refute an old observation. Temporary source unavailability limits verification but does not make retained knowledge false. A live requirement that no longer holds affects current applicability.

Reconsider affected conclusions through indexed reverse links and finite jobs. Do not validate the whole graph before each read. Cyclic citations supply no independent support. Erasing a required premise must not shrink an AND group into a satisfied smaller group.

### 3.3 Time

Keep separate:

```text
occurrence time
stated validity/situation
receipt time
editorial revision time
```

Preserve unknown precision/timezone. Late import or new summary is not a fresh world observation. A real A→B→A sequence creates a new A occurrence rather than deduplicating into the first.

Historical questions may require historical source and editorial revisions. Do not answer “what was known then?” from only current heads. No automatic full historical-world reconstruction is required.

## 4. Host events, episodes, sources and coverage

The first Claude profile treats native events according to what they establish:

| Event | Establishes | Does not establish |
|---|---|---|
| `SessionStart` | session/continuation boundary and supplied source mode | packet emitted, read or used |
| `UserPromptSubmit` | one user prompt before model request | model followed returned context |
| `PostToolUse` | one tool call/result occurrence with native identity | whole-task success or independent corroboration |
| `PostToolUseFailure` | one started tool call failed/interrupted as reported | cause beyond supplied error or absence of external effect |
| `Stop` | host-supplied final main-agent response | factual correctness or acceptance |
| `SubagentStop` | final subagent response and agent identity | parent acceptance or independent handback success |
| `PostCompact` | one compact summary representation | replacement source truth or fresh world observation |
| `SessionEnd` | lifecycle boundary and reason | commitment resolution |

Group observations through actual host-native task/session/call/result/parent relationships. Keep a tool call with result and observed repair/check. A native tool or agent/message ID is stronger than timestamp proximity.

### 4.1 Episodes and finite input

An episode may be processed in finite portions while work continues. Freeze selected membership and actual segments/per-stream bounds. New observations enter a pending successor rather than mutating running input. Late child material or newly learned association can add uncovered source without reopening every stream.

Distinguish:

```text
material selected for a job
material actually supplied to inference
successfully processed coverage
```

Trimmed body, unexpanded handle or omitted segment is not covered. No-change covers only completed supplied input and purpose. Rereading background does not add independent support. There is no global processed bit.

When a compact lesson is selected, optional expansion follows useful source neighborhood: cause/action, result/error, repair/change and later check/outcome.

Timestamp proximity across unrelated streams does not create an episode. Missing counterparts remain explicit; useful independent material need not wait for every agent to finish.

### 4.2 Source and representation continuity

Source object, version and transformed representation remain distinct. Observed rename/copy/export/crop links retain exact input/output. Inferred continuity remains a hypothesis. Equal names, bytes or embeddings cannot merge logical sources.

Packet inclusion or handoff does not make packet text an independent source for every included fact. Replayed Eliot context is labelled derived context when captured later.

## 5. Project understanding

A project view is a versioned answer to one useful question over examined scope:

- purpose and boundaries;
- subsystem responsibility;
- API consumers;
- rationale and failed approaches;
- intended-versus-observed discrepancy.

A view records question, examined workspace/resource revisions, answer, source handles and gaps. Old cited files do not prove no new consumer exists. Membership-affecting changes qualify or dirty the view.

Refresh affected views only. Until refresh completes, serve the prior qualified view and direct source access. Checkout-specific views use distinct addresses; late synthesis cannot overwrite another checkout’s view. Stable project intent may be shared while implementation views differ.

## 6. Retrieval, exact open and context

### 6.1 Candidate generation

Generate candidates independently from:

- direct IDs and handles;
- exact current-work address;
- exact technical cues;
- full-text search;
- compatible vectors;
- claim alternatives;
- relevant typed relations;
- project-local methods;
- reusable methods eligible for current project.

Union before selection. A lexical candidate does not need vector score. Workspace/task selectors apply before per-arm limits. Historical cases retain original scope instead of becoming current state.

### 6.2 Applicability

Evaluate material conditions as:

```text
applicable
inapplicable
unknown_or_conditional
```

Typed observed values may decide simple conditions. Natural-language uncertainty remains conditional. Token overlap is not proof: `not committed` does not satisfy `committed`; mentioning a check is not evidence it ran.

Unknown applicability can yield conditional guidance plus a missing check. It does not require silence or permission denial.

### 6.3 Ranking

Rank relevance separately from support. Useful signals include exact match, lexical score, compatible vector similarity, recency where appropriate, relation purpose and current-task fit. Scores normalized within one result set are relative order, not calibrated probability.

### 6.4 Relation discovery and expansion

Relation discovery for an exact item is not semantic top-k. Opening one claim/method returns bounded descriptors for its material grounds, contradictions, replacements, exceptions and outcomes from the exact revision opened, even when caller did not know neighbor handles.

Load neighbor bodies only when they provide missing decision information: order, consumer, cause, outcome, repair or exception. Intermediate nodes need not repeat query words.

Bound discovery by scope, relation purpose, nodes/edges, bytes and work budget. A link for revision 2 does not automatically describe revision 3. Fixed relation cap without cursor is incomplete coverage.

### 6.5 Exact open

`open(handle, range?)` requires one nonempty exact handle or locator. Empty selector does not mean broad read. Search/navigation is separate.

- current semantic handle → current revision or explicit absent/withdrawn/erased;
- version handle → exact historical revision or missing/damaged, never current fallback;
- observation/source handle → retained accepted body/blob and actual locator;
- representation handle → exact retained transformation and relation to original;
- packet/result/report handle → exact retained bytes/section and stated generation/coverage.

An exact result states requested/resolved identity, returned range/digest, current/history status, capture limitations, qualifications, relation descriptors, expansion handles and exact disposition.

`truncated=true` requires valid continuation for omitted readable material or explicit non-pageable gap. Cursor binds exact object, revision, representation and options. Limit unit is explicit.

### 6.6 Packet packing

Pack semantic units:

- current work;
- exact constraints and corrections;
- applicable or conditional methods;
- relevant prior episode;
- dissent, unknowns and next checks;
- source handles.

Load material exceptions through recorded links before final packing. Keep exception with claim/method. If a unit cannot fit, return a concise faithful qualified form plus handle or omit the whole unit with stated gap. Never drop negation, version or contraindication.

Packet-local grouping may reduce repeated compatible guidance without merging stored IDs. Compare scope, time, perspective and conditions, not text hash alone. Grouping is not new evidence.

### 6.7 Packet retention and handoff

Packet builder records exact included revisions, rendered bytes/digest, budget and gaps before or alongside host emission according to Implementation.

Keep distinct:

```text
prepared
emitted through supported host channel
associated with a later action when observable
used or influential: unknown unless separately observed
```

A local file, packet ID or successful render does not prove handoff. Emission result establishes emission, not use. Later action can be associated by host-native correlation, but causality/adherence needs additional evidence.

For the first Claude profile, `SessionStart` and `UserPromptSubmit` return actual packet content. Service-status text is not packet content.

If packet construction fails, capture and explicit retrieval remain available. If emission fails after retention, keep prepared packet plus delivery gap. If host receives ephemeral context while retention failed, report the retention gap rather than claiming replayability.

## 7. First connected learning loop

The first learning purpose is `episode_learning`. It extracts useful claims or task-advice methods and may revise named items. Continuation synthesis, graph repair and recipe self-improvement are separate later purposes with their own consumers.

### 7.1 One job, one exact input

The handler receives:

| Input member | Content |
|---|---|
| `new_sources` | selected new observations/segments with request-local refs, source kind, actor/role, call/result association, exact text, scope/version, disclosure and capture limits |
| `background` | relevant older excerpts used for interpretation, explicitly not new occurrences |
| `existing_items` | small editable current claim/advice set with exact revisions, conditions, exceptions and contrary evidence |
| `recipe` | exact processing-method ID/revision and text |

The job retains request-local ref → exact handle/revision/range mapping. Include failures and read-only findings as well as successes. Label derived summaries, compact summaries and replayed Eliot context so they do not become new evidence.

### 7.2 Prepare before controller I/O

Before the first controller application call:

1. freeze exact members and ranges;
2. reduce disclosure over material actually supplied;
3. select configured controller inference profile;
4. build exact prompt and closed response schema;
5. build canonical semantic payload identity;
6. generate canonical ULID `inference_write_id`;
7. save `WriteId`, prompt bytes/blob, length, digest, profile, disclosure, limits, source mapping and exact recipe revision in the Memory job;
8. load installation’s exact `controller_id`, stable `controller_client_id`, selected `token_version` and credential reference;
9. authenticate controller V2 and require exact `client.identity` agreement;
10. only then invoke `inference.text` with the retained `WriteId`.

The `WriteId` exists durably before any possible provider admission. Raw token, token hash, routing key and provider credentials never enter the job or backup.

A missing, malformed or mismatched controller identity closes the connection before application mutation and sets a typed operational failure such as `caller_identity_unavailable`. It does not authorize owner/Agent/automation fallback or a new client.

### 7.3 Admission, retry and unknown

Controller call identity is:

```text
(controller_client_id, inference_write_id, method, canonical semantic payload)
```

After disconnect or restore, Memory invokes the same method with the same `WriteId` and exact bytes:

```text
same call exists             -> return current original call
valid absent ID              -> create first admission
same ID, different payload   -> id_conflict
expired/future ID            -> explicit operational failure
caller unavailable           -> no call; hold job
```

There is no separately discovered Operation ID and no durable `possible_send`/`proven_no_send` state.

Provider-send uncertainty belongs to the retained controller call. `sending` after crash is resolved by exact native readback or remains `unknown`. Memory never creates a new `WriteId` merely because no reply arrived.

### 7.4 Result read and decoding

When a result is present:

1. read bounded exact-caller ranges;
2. require stable call ID, digest and total length;
3. copy body durably into Memory blob/job;
4. verify complete digest/length;
5. decode from the retained Memory copy, not live controller response;
6. validate closed purpose schema and every source ref;
7. prepare publication outside Store transaction.

A provider body is not a valid cognitive result until the purpose decoder accepts it. Malformed output, missing refs, unknown operation, unsupported structure or truncation is operational/partial failure, not no-change.

Text result may propose:

```text
create item
revise exact current revision
no_change with exact completed coverage
partial with exact useful coverage and gaps
error with bounded non-content classification
```

Every proposal carries request-local source refs, conditions, exceptions, counterevidence and material scope. Model-generated IDs do not become Memory IDs or evidence.

### 7.5 Publication

One Store transaction:

1. revalidate target current revisions;
2. reject stale proposal or prepare controlled replay;
3. allocate any new Memory IDs once;
4. write history/current revisions;
5. write revision-specific links/grounds;
6. save typed job result and processed coverage;
7. settle active/pending slot;
8. commit.

Store conflict replays the retained decoded proposal or redecodes the retained Memory result, never the provider call.

A valid `no_change` marks only exact completed supplied coverage and purpose. It cannot cover omitted segments or background and cannot stand in for provider/admission/decoder failure.

### 7.6 Cleanup

After verified Memory copy and durable publication/no-change:

```text
inference.release(memory_copy_verified)
```

Terminal call with no possible result:

```text
inference.release(terminal_without_result)
```

Erasure of unresolved work:

```text
inference.release(abandon_for_erasure)
```

Cleanup state is independent of cognitive outcome. A useful Memory result remains usable if release fails, but cleanup debt remains visible and blocks complete erasure. A failed request may clean successfully without learning.

Controller owner erasure may use exact non-content call provenance but cannot read result bytes, adopt caller ownership or create a Memory result.

### 7.7 Automatic and pending work

Interpretation triggers only on new committed source, correction or explicit question—not on bookkeeping, retries, cleanup updates or result readback.

For one target/purpose:

```text
one active job
one coalesced pending successor
```

New material while active updates pending coverage, never mutates active frozen input. Waiting for idle/profile/disclosure/controller continuity is not attempt failure. `off | idle | background` modes are explicit; a profile may deny automatic use.

## 8. Embeddings and vector retrieval

Embedding jobs use `inference.embed` only after the text path is connected. Freeze one batch, role and profile. Result must provide exactly one position/error per `input_key` plus one effective vector-space identity:

```text
profile digest
adapter version
observed model
dimensions
role = query | document
```

Missing/duplicate/unresolvable position, inconsistent dimension, non-finite vector or shifted assignment fails. Never repair with zero vectors.

Store vector with exact Memory revision/representation and effective space. Query compares only compatible spaces. Vector failure does not disable lexical/exact retrieval or mutate source coverage.

## 9. Backup, restore and cognitive continuity

### 9.1 Backup cut

Before Memory backup controller cut:

1. stop new controller-backed admissions;
2. ensure every created call already has durable job `WriteId` and exact request identity;
3. reconcile active local submission/readback step to a typed state;
4. authenticate exact controller identity;
5. read and record per-client `high_water` and `earliest_retained_seq`.

The backup manifest retains in-cut job identities and high-water, never raw credential material.

### 9.2 Restore in-cut jobs

Each restored job uses the same `WriteId`, exact bytes and stable caller. Existing call returns its state/result; valid absent call gets first admission; payload conflict is damage; unavailable caller holds the job.

Do not invent a new request/caller to “recover” an old result.

### 9.3 Restore post-cut calls

Before **any new controller-backed inference**, page exact caller calls with `admission_seq > backup_high_water`.

These calls are out of restored target because restored Memory lacks their exact job/source/publication rows. Do not adopt their bodies as lessons, revisions or no-change. Each must become terminal and released or explicitly abandoned/erased; unknown provider effect remains unknown.

If `backup_high_water` precedes controller’s earliest retained sequence, return `history_gap`. Never interpret a retention gap as no post-cut calls.

If controller identity, credential or inventory is unavailable, keep inference disabled with `external_work_inventory_unavailable`; Base capture/retrieval may resume independently.

Deletion fences and controlled-copy erasure apply before any restored item can become current or be supplied again.

## 10. Outcome attribution and method revision

Where an external action can be correlated, retain the exact method revision offered or used. Otherwise preserve episode without invented attribution.

Distinguish:

```text
offered
emitted/handed off
action observed
adherence inferred | unknown
outcome observed
comparative benefit supported | unknown
```

One attributable attempt/criterion contributes once. Replayed hooks, summaries and packet echoes are not independent successes. Missing correlation limits evaluation; it does not block source capture or provisional learning.

A method revision may change only when retained outcome, counterexample, correction or explicit owner edit justifies it. Popularity, retrieval frequency and model self-confidence are not success measures.

## 11. Consolidation, split and forgetting

Keep distinct:

- replaying old input;
- grouping compatible results for one packet;
- revising a current item;
- synthesizing a broader method;
- splitting one overbroad item into scoped alternatives.

Consolidation does not rewrite original observations or old version handles. A synthesis has its own identity, scope, source links and conditions. Split preserves history and explicit replacement relations.

Forgetting changes a reader or influence state; rarity/use is not truth. Current readers follow current revision links and qualifications. Negative memory is scoped advisory guidance unless a separate explicit host guard is selected.

## 12. Recursive improvement

Self-improvement diagnoses the failed connected edge:

```text
capture
source/episode selection
controller admission
provider execution/readback
result copy/cleanup
decoding
publication
retrieval/ranking
packet delivery
actual use
applicability
method quality
```

Correct that edge instead of multiplying duplicate lessons or adding a global intelligence score.

Within repeatable work, Eliot may use Propose–Probe–Compose:

1. retain baseline and exact criterion;
2. propose a bounded reversible change;
3. choose the cheapest discriminating observation/probe;
4. compare one attributable contribution per attempt;
5. retain no-change or revert when evidence is insufficient;
6. publish a scoped revision only when supported.

A selected candidate is not automatically better. Irreversible effects are not repeated merely for comparison. A model never grants itself permissions or changes the user’s goal.

## 13. Disagreement, prediction, research and commitments

Disagreement belongs to a question, scope and time. Preserve rivals and grounds, then identify the cheapest useful distinguishing observation. One source lookup, agent or human decision may be enough. A panel or vote is not required.

Unresolved disagreement does not block unrelated work. A provisional choice records rationale and reconsideration trigger.

A prediction states expected observation before action, conditions and available check. Static dependency, co-change and causal explanation are not interchangeable.

Research begins with available memory and exact local sources. External acquisition is for a concrete remaining gap. Eliot Research owns execution/corpora; Memory stores compact findings, alternatives, coverage and exact handles.

A failed source request, completed but uninformative research and useful partial answer are different outcomes. Repeating uncertainty does not justify an endless research loop.

Commitments/problems are retained state, not notifications. Showing or acknowledging one does not resolve it; a passed due date does not complete it. Resolution follows a matching observed event or explicit owner change.

## 14. Algorithmic failure mapping

| Situation | Cognitive result |
|---|---|
| Source body omitted/truncated | retain limitation; omitted material not covered |
| Current-work association unknown | preserve source; limit continuation claims |
| Competing revisions under different conditions | preserve alternatives, not last-write winner |
| Required grounds member unresolved | grounds group unresolved |
| Profile/disclosure/capacity unavailable | operational waiting/failure, not no-change |
| Controller identity mismatch | no application call; hold job |
| Same `WriteId`, changed request | conflict/damage, never new call |
| Provider possible send lost | call unknown; no replay/new `WriteId` |
| Result malformed/truncated | failed or useful partial with exact gaps |
| Store publication conflict | replay retained result/proposal, not provider call |
| Release fails after Memory copy | cognitive result remains; cleanup debt visible |
| Restore finds post-cut calls | do not adopt; disposition before new inference |
| Restore inventory has retention gap | inference disabled; explicit `history_gap` |
| Packet rendered but not emitted | prepared + delivery gap |
| Advice emitted but use unknown | do not claim influence or success |

## 15. Evidence required

Cognitive capability exists only through a connected path.

Minimum continuation/context proof:

```text
real session A sources
→ exact continuation revision
→ restart
→ session B decision frame
→ actual emitted packet
→ exact source open
```

Minimum learning proof:

```text
real retained episode
→ frozen recipe/input + durable pre-send WriteId
→ one controller call/result-or-unknown
→ verified Memory copy and decoder
→ atomic revision/no-change/partial
→ later retrieval/packet changes
→ exact cleanup state
→ restart readback
```

Minimum rollback proof:

```text
backup controller high-water
→ later admitted controller call
→ restore backup
→ same-WriteId in-cut reconciliation
→ post-cut call listed or explicit history gap
→ no new inference until disposition
→ Base remains usable
```

A prompt fixture, parser test, schema execution, source review or model-looking output is not this evidence.
