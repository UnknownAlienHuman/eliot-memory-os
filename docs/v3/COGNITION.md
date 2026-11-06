# Eliot Memory OS V3 — Cognition

**Revision 1.0-draft.37 · 2026-11-06 · design algorithms, not runtime evidence.**

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
The exact time tuple is owned by [Implementation §4.7.1](IMPLEMENTATION.md#471-occurrence-time).

A semantic item is a revisable claim, method, explanation, commitment, prediction or
project view. Retain exact current/history revisions, origin/reuse/disclosure,
conditions/exceptions, validity, grounds and independent support/exposure/influence.
Original bytes, converted representation, excerpt, summary and claim have distinct
identities and explicit links. Preserve whose assertion it is and whether it concerns the
actual task, a hypothesis, quoted belief, test fixture or abandoned branch. Project/session
binding alone does not express that distinction. Use existing perspective, qualifications,
content and exact sources; uncertain ownership remains attributed evidence, not a shared fact.

## 2. Current-work reconstruction

Choose one admitted work address: `project + workspace + task_id` when the host supplies
an actual task; otherwise `project + workspace + actor_id + session_id`. IDs are already
source-qualified by the adapter. Fall back only when task identity is absent, never when
a task lookup is empty, denied or unavailable. Incomplete binding yields `binding_missing`,
not a project-wide search for a substitute goal. Path/branch/resource similarity and reuse
permission are not work membership; related experience remains separately qualified.

Use the existing memory address fields for the three singleton current-work views:

| Mode | `address_key`, using Implementation §4.4's H | Exact `address_kind` → packet role |
|---|---|---|
| Task | `H("work-task-v1", project, workspace_id, task_id)` | `work_task_goal` → `goal`; `work_task_plan` → `plan`; `work_task_progress` → `progress` |
| Session | `H("work-session-v1", project, workspace_id, actor_id, session_id)` | `work_session_goal` → `goal`; `work_session_plan` → `plan`; `work_session_progress` → `progress` |

These six reserved address kinds require `memory.kind=project_view`. The revision writer
checks the key against the admitted command binding before custody; the operation's
observation retains the readable tuple. The normal address_unique_key enforces one item
per slot. Lookup compares origin project, kind and both address fields, not a prefix or
bare task ID. Content is exact view text, not a JSON subdocument or model-parsed goal.
Missing/unavailable slots remain missing/unavailable; another kind, old revision, shared
view or similarly worded note cannot fill them. A stored plan is not completed progress.

Multiple commitments remain separate `commitment` items, not singleton view slots. For
this Base direct-update path, their work membership comes from the canonical create
`memory_change` observation's captured binding and original result (revision 1). The
scoped reader resolves those memory IDs and hydrates their current revisions; a later
editor's session does not move them. This internal membership lookup is not an evidence
or learning trigger. Missing/damaged creation binding withholds the association with
`qualification_missing`; do not invent it from text, reuse scope or the latest edit.

Resolve binding → current work slots and associated commitments → exact qualifications/
grounds → bounded observations of that work → current corrections/notices → related
experience. Receipt-time pagination is not a completeness checkpoint: delayed spool
inserts can sort before it (Implementation §5.2). Re-evaluate current slots on each new
invocation, and report bounded/truncated observation coverage rather than claiming all
intervening events were seen. Arrival order cannot overwrite a selected current view.

A similar cancelled direction is not current work. Late results retain issue-time
binding. Fork/transfer creates explicit relations, not silent renaming. A model summary
or suggested method cannot silently replace the user's goal/acceptance criteria. Retain
the source goal and an explicitly attributable amendment; an inference is not an amendment.

A staged command is custody, not a committed observation or revision. It cannot supply
an exact Memory citation, satisfy an expected revision or trigger learning. The live
prompt may remain explicit caller input, without claiming it was persisted. Report pending
capture when the committed view lacks it. Stream ingest sequence orders commits, not host
occurrences; use observed source sequence/parent relations for causality and label gaps.
Replay after an outage must not silently invent a newer user goal from arrival order.

### 2.1 Working model, not a transcript summary

Reconstruction should answer six decision questions. They are a content convention over
existing views/observations, not new columns, packet roles or a second task store.

| Question | Smallest useful content / existing owner |
|---|---|
| Goal | Desired outcome and acceptance criterion; current goal view plus attributable amendments. |
| Model | Relevant entities, dependencies and mechanism: what changes what, under which conditions; a scoped explanation/view with exact grounds. |
| State | What is true now, completed work and unresolved commitments; progress view and bound observations. |
| Tried | Action → expected/observed result → criterion → supported cause or unknown; original call/result links, including failures and exceptions. |
| Unknown | Decision-critical missing fact, conflicting evidence or unverified premise, plus the observation/source that could resolve it. |
| Next | One justified action or focused query and its expected useful result; plan view or explicitly attributed proposal, never a completed attempt. |

The host agent supplies a concise progress/goal/plan update; the existing adapter builds
the revision command (§5), without asking it to fill storage fields. Goal stays in its goal
slot, next step in plan, and state/model/tried/unknown in progress or linked explanations. Update after a meaningful result, correction, changed
premise or handoff; unchanged polls do not need a revision. Attach available exact grounds
and resource versions; retain attribution and label unsupported assertions/proposals. Base selects labelled source text and linked observations; it does
not infer a causal model, parse prose into authoritative fields or wait for a summarizer.
Call/result links establish the attempt pairing; a cause requires a separately attributed
explanation and its grounds.
Absent model/next-step content stays unknown. Optional §8 jobs use the same writer later.

A useful model permits a small conditional simulation: **given state S, action A should
produce O because M; observe E to distinguish alternatives**. Preserve whether M/O is an
observation, source assertion or hypothesis. Sequence, co-occurrence and model confidence
do not establish cause. Model only the decision-relevant part; unresolved alternatives
remain available through exact open. Any changed material resource revision or premise
requalifies affected advice under §3; unrelated work continues.

A linked or retrieved matching failure outranks generic similar history. Keep its conditions
and the changed premise that would justify trying again: an old failure is evidence, not a global
ban. Corrections revise the affected view before later reuse. The [research map](AUDIT-MAP.md#51-evidence-for-compact-understanding)
records why this design is selected and what the studies do not establish.

### 2.2 Prepare knowledge for use

Dreamer prepares reusable meaning before the next request; Base assembles it with the
current task facts. Retain exact evidence alongside coherent, scoped reusable units:

| Existing item | Retained evidence / prepared meaning |
|---|---|
| Observation / linked action-result | Exact state and action/result observations; occurrence/resource identities and both available sides of a transition, without inventing a missing state or cause. |
| Claim / explanation | Relevant fact or mechanism; dependencies, conditions, competing explanation and observation that distinguishes them. |
| Project view | The task's current working model (§2.1), with exact sources and unresolved changes; reference reusable explanations instead of copying a whole project history. |
| Advice method | When it applies → action/procedure → expected result → check → known failure/recovery. A result seen once remains scoped experience. |

Keep stable mechanisms separate from changing task state so one new result does not
force a rewrite of everything. Use existing subject/aspect, work/resource binding,
exact cues and links. Prepare the relation from an artifact, error or decision premise to
the relevant condition/experience even when their wording differs; Base follows that stored
relation without rediscovering its meaning. No universal ontology or new object hierarchy.
An item can generalize across tasks only within its stated conditions and reuse scope.

**Decision sufficiency** preserves what changes the action, consequence, applicability
or check: concrete referents, critical values/units/versions, negation, exceptions,
uncertainty and the distinguishing example. Source IDs locate evidence; they do not replace
its meaning in the text. Remove narration, not these distinctions. Dreamer compares
reductions with original evidence; this heuristic cannot prove future-query coverage.
Base checks selectors, qualifications and packing mechanically; missing knowledge
remains a focused question (§8.3).

## 3. Grounds and applicability

For one conclusion revision, links in a non-null grounds group are conjunctive;
different groups are alternatives; ungrouped support is advisory. Navigation is not
evidence; cycles add no independent support. Unknown composition stays unknown.
Load links for the selected exact conclusion revision, never combine current text with
historical grounds. An explicitly empty complete set differs from a failed/truncated
relation read. Persisted support_state records an assessment, not proof that its grounds
are currently available; a consumer relying on a group must resolve that complete group.

Applicability is `applicable | inapplicable | conditional_or_unknown`. Evaluate material
selectors, validity, work/resource version and exceptions. Token/vector similarity is
not sufficient. Methods and contraindications travel together. Base checks typed time,
work and resource facts; free-text conditions/exceptions remain data. A material condition
or exception not actually resolved keeps applicability `conditional_or_unknown`, not
`applicable` from an empty evaluator, keyword match or missing field. No evaluator DSL
or model call is required just to preserve that uncertainty.
[Implementation §4.7.2](IMPLEMENTATION.md#472-reuse-and-guidance-states) owns the persisted
reuse/support/exposure/influence vocabulary. Conditional applicability is not withdrawal;
a supported but withdrawn method is not eligible advice.

Correction/refutation/erasure triggers bounded reverse traversal over affected revisions.
Load complete required groups before deciding impact; a truncated traversal cannot
pretend that no additional affected conclusion exists.

## 4. Episode membership and coverage

An episode is a finite selection of existing observations, not a new table or lifecycle.
Its owning retrieval/job fixes the work address (§2), purpose, selection bounds and exact
source handles. Task membership alone does not join a tool result to an action: use the
captured call/parent/result relation. A late result keeps its issue-time binding. Missing
or contradictory correlation remains a gap, not a match by text or arrival proximity.

For a job, the first claim records that finite selection in existing `frozen_input_json`
under Implementation §4.7.3; `coverage_json` records its disposition. Each selected entry
names an exact observation or memory revision/hash and, for an excerpt, its byte range.
Memory/method revisions are contextual inputs, not additional episode occurrences. The
original object's hash does not claim that omitted bytes were supplied. Never replace
an exact input with `current`, a summary or a newly expanded search on reclaim. New input
belongs to the existing pending successor, not to a mutation of the claimed selection.

| Coverage term | Required meaning |
|---|---|
| `selected` | Unique exact entries in the frozen required input; the denominator for this job, not every event in the session. |
| `supplied` | Selected entries whose declared bytes are in the retained processor input, with their source mapping. Request construction does not prove provider receipt or internal model attention. |
| `processed` | Supplied entries accounted for by a decoded, accepted purpose-specific result. Neither a citation, transport success nor a model's unsupported completion claim adds an entry. |
| `unavailable` | Selected, unprocessed entries that cannot be supplied/used, with a bounded reason such as missing, damaged, denied or unsupported. Do not substitute another source. |
| `remaining` | Exactly selected minus processed, including unavailable entries. Derive it from identities; do not subtract unrelated counts or count unavailable twice. |

Thus processed is a subset of supplied, supplied of selected, and unavailable of
remaining. Repeated handles do not increase coverage; overlapping ranges never count
shared bytes twice or imply whole-body coverage. The decoder rejects unknown/out-of-set
processed entries and inconsistent totals rather than trusting a generated percentage.
Purpose-specific limits must bound both references and encoded input/result bytes before
that capability is enabled; a candidate-page cap alone is not an aggregate job limit.

Retain discovery limits separately from the frozen denominator. A complete finite
selection is not the complete conversation, task or all possible evidence. Unknown
unseen counts stay unknown; forbidden identities/counts do not leak in public coverage.
A deliberate narrower assignment may finish for that scope. Runtime truncation of its
required input cannot be relabelled a smaller successful job. Partial results preserve
useful accepted changes and exact remaining work; only complete required input permits
`changes` or `no_change` as a successful cognitive outcome (§9.2). For episode processing, an
authoritatively empty selection is local no-work, not a fabricated call or learned lesson.

There is no global processed bit. Coverage is relative to purpose, frozen method revision
and input, not an irreversible mark on observations. Reconciliation/replay preserves the
original result and coverage; re-analysis may revise knowledge but adds no new occurrence
or independent trial. Unresolved external effects still follow §9.1, not an automatic
replacement call because remaining work is nonempty.

## 5. Direct updates

An agent can save what it saw, changed, decided, tried or still doubts in ordinary text,
with optional exact sources. The adapter supplies work binding, occurrence identity and
internal defaults; categorization is not a prerequisite for capture. Explicit notes are
ordinary scoped items; ambiguous input remains an attributed observation, searchable
without Dreamer. Later preparation may structure it, not turn it into an unqualified fact.

The thin input surface belongs to [Implementation §7](IMPLEMENTATION.md#7-core-operations-and-host).
For an explicit correction/progress update, the adapter resolves the target and builds the
complete revision; preserve material qualifications and do not carry old support onto a
changed assertion without grounds. Display, acknowledgement, due time and notification
do not resolve a commitment.

Structured correction verifies expected current revision, preserves history, publishes
the revision/source/grounds/replacement and coalesces affected work in one transaction.
Exact replay returns the original result; stale revision conflicts. Store transaction
shape belongs to Implementation, not a separate cognitive persistence owner.
The [durable command](IMPLEMENTATION.md#75-durable-ingress-and-replay) precedes Store
send; a pending correction is not an accepted semantic state. After rollback, post-cut
corrections require the explicit adoption rule in Implementation §8.2, not automatic replay.

## 6. Retrieval and context

### 6.1 Decision frame

Bind work (§2), the current event or focused question, resource/version, exact cues,
constraints and budget. Automatic focus comes from the current event and bounded recent
accepted outcomes: touched artifact/symbol, actual error/result or changed work premise.
Recall does not depend on a well-worded query; incomplete event coverage stays explicit.
For resumption, use §2.1's six questions; a narrow lookup answers only that question with
its necessary state/qualifiers. A required premise is a supplied selector or an
attributed source claim, not an automatically invented checklist. Missing address,
model or source coverage stays explicit.

Keep receipt/occurrence, validity and mentioned-event time distinct (Implementation §4.7.1).
Explicit time filters use the matching known axis; model-inferred ranges remain cues.
Unknown mentioned-event dates cannot exclude otherwise relevant candidates. Timed wake-up
belongs to the host; without that event, recall waits for the next supported boundary.

### 6.2 Candidate arms

Use staged disclosure within one request budget, not every retrieval arm on every hook:

| Stage | Retrieve / stopping rule |
|---|---|
| Address / cue | Current work slots/commitments, direct handles and event-derived exact cues; hydrate their qualifications and linked attempts/decision dependencies. An unresolved material constraint/counterexample means partial or conditional context, not a covered decision. |
| Expand | For a remaining gap/cue, request bounded lexical, relation or method candidates; vectors only when enabled and useful. Follow the affected artifact/premise to prepared neighbors, not an unrestricted graph walk. |
| Open | The agent requests a selected exact source/revision or a focused follow-up question; reuse §7, without replaying the whole history. |

Apply scope before each arm limit; union requested arms before selection. Preserve
contradictions, replacements and required grounds for selected advice even on the cheap
path. Base routing follows explicit addresses/cues/gaps; it does not call a model to judge
its own understanding. An unresolved question may be returned instead of automatic expansion.

Report examined scope, arm states and gaps. Unused arms are `not_requested`; failed,
disabled and truncated arms retain their own states. Empty top-K means no match in that
finite query, not global absence. Reaching the deadline returns useful qualified partial
context; it never starts an unbounded search or blocks unrelated host work.

### 6.2.1 Proactive attention without repeated context

`baseline` rebuilds §2.1 after start/resume/compact, fork, work change or uncertain context
continuity; `update` carries a useful change and its necessary premises; `focused` answers
an explicit request, bypassing automatic deduplication. All use the same qualified sources.

In a live context, select new/changed relevant revisions, qualifications, corrections and
cue-linked outcomes. Repeat unchanged reads add nothing; unrelated observations do not
invalidate the whole view. Carry constraints, counterexamples and unresolved commitments
with the decision they affect. Withdrawal/unavailability of prior guidance is a change:
show its permitted qualification/gap, never forbidden content. No useful change means a
successful empty response, not another summary. Similarity cannot suppress corrections.

A bounded volatile cache holds source IDs/revisions and representation/qualification
digests per work/session/host-context continuity; no bodies or persistent delivery registry.
Mark only after a complete observed local write. It is a repetition hint, never truth,
authorization, host acceptance or use. Do not key it by every event ID or merge distinct
source occurrences. Explicit requests and source validation never depend on cache hits.

Serialize cache comparison → output completion/marking with one in-process per-context
permit, acquired within deadline without a Store transaction/delivery fence held.
Contention returns empty; independent capture continues, and the next boundary rebuilds
focus from accepted outcomes. Content mutations never wait for cache maintenance.

Recheck invalidates an affected source/notice entry only. Restart, ambiguous output,
compact/resume, fork, changed work/adapter/context or overflow resets the cache and requires
a baseline. On a replaceable host slot, replace it; on append-only hooks, state the complete
current value/qualification and supersede earlier guidance for that item. Different-item
replacement needs exact existing links, not similar prose. Each update supplies its own
sources/premises; if this is unreliable, send a baseline. Memory cannot remove old transcript text.

### 6.3 Lexical snapshot

Lexical ranking is one bounded top-K Store snapshot. Its BM25 corpus/order can change
between calls; there is no durable cross-call cursor. A later expansion is a new snapshot
with new observed Store/schema/query facts. Equal scores use canonical-ID tie-break.
A zero score remains a match; score proves neither support, truth nor applicability.
Exact SQL belongs to [Implementation §5.1](IMPLEMENTATION.md#51-exact-full-text-shape).

### 6.4 Packing

Rank corrections/constraints, current goal/model/state/next step, open commitments and
matching failures; then applicable advice, discriminating evidence and history. Keep
unknowns, counterevidence, qualifiers and handles with the claims they qualify.

Apply Implementation §4.7.2 before roles. Hidden items never enter automatic packets.
Only current open commitments get role `commitment`; resolved/cancelled items are history.
Only `method_role=advice` gets role `method`; processing recipes stay in §8 jobs. §2's slots
supply goal/plan/progress, not a text classifier; live input remains uncommitted.
Missing required state withholds that unit with a gap, never a default.

Base renders existing concise views or exact labelled excerpts. Dense semantic reductions
come from §2.1's explicit revision or §8's Dreamer preparation, never a hidden model call
while packing. Prefer addressed work and decision-relevant attempts, then newer receipt
time and canonical ID/revision. Deduplicate exact revision handles, not similar claims
or distinct events. Do not repeat the live prompt, generic instructions or unrelated logs.

Treat value plus negation, conditions, exceptions, validity and source handle as one
packing unit. Include it whole; otherwise use an existing qualified short representation
or omit it with an explicit gap. Do not invent a shorter paraphrase or drop a qualifier.
When a material premise/condition/counterexample occupies another selected unit, retain
its dependency with the guidance it qualifies. After any cut, keep that dependency complete,
use an existing short form carrying the decisive meaning, or omit the dependent guidance
with `packet_limit`. A bare uncertainty label/handle cannot replace a missing caveat.
Track only bounded presentation dependencies from selection's exact links; no inferred
edges or persisted group. Resolve support under §3 without loading every ground's body
into context. Independent useful units remain available.
Enforce [the Base byte cap](IMPLEMENTATION.md#451-first-base-limits) on actual emitted
UTF-8 bytes, including labels/handles/gaps. Reserve room for the gap summary first.
A byte count is not a token measurement: when the host requires an exact token budget,
use its admitted counter or report that capability unavailable, never a guessed PASS.

Aim for **2 KiB of model-visible brief text** on automatic hooks; this is a soft initial
design target, not measured performance or a new rejection limit. Expand when necessary
to preserve a decision-critical chain/qualification, within the existing 32 KiB final
response cap. Prefer fewer complete useful units to compressed words that lose meaning.

Retrieved text, documents, tool output and recalled model answers are evidence, not
new host/system instructions. Render them as attributed data with source/revision and
scope, separately from the selected processing recipe and current user request. Neither
quoted commands nor a model's claim of authorization can change permissions, disclosure,
provider route, execution budget or the user goal. Text delimiters alone do not enforce
this boundary; the application accepts only the owning operation's closed DTO/effects.

#### 6.4.1 Base packet encoding

`ContextPacketV1` is one closed data object owned by the existing context operation,
not an instruction protocol or a new packet service. Its exact top-level fields are
`format=1`, `packet_id`, `mode`, `binding`, `units` and `coverage`. Use Implementation §4.5's
canonical JSON, no floating-point fields, duplicate keys or unknown members. Unsupported
formats fail explicitly. Packet identity is an ordinary `o_` observation ID, not a new
ID namespace; allocate it once before preparing the output.

| Field | Required meaning |
|---|---|
| `mode` | `baseline`, `update` or `focused`, selected by §6.2.1; it changes presentation, not eligibility or evidence. |
| `binding` | `installation_id`, nonnegative integer `selection_generation`, `project`, `workspace_id`, `actor_id`, `session_id`, `host`, `host_version`, `adapter_version`, `event`; optional `task_id` and `native_request_key`. All other values are nonempty strings bounded by Implementation §4.5.1. The admitted adapter supplies versions/event mapping, not caller text. Missing task uses §2's session address. Missing session/work authority cannot fall back to a similar project's packet. |
| `units` | At most 32 ordered units under §6.4. Each has `role`, `representation`, `text`, `source` and `qualifiers`, plus `span` only for an excerpt. Roles are `goal`, `plan`, `constraint`, `progress`, `commitment`, `method`, `evidence`, `counterevidence`. Representations are `verbatim`, `excerpt`, `stored_reduction`, `live_input`. A stored reduction retains its own exact source identity; it is not generated while packing. |
| `source` | For persisted units: `{kind:"observation",id,sha256}` or `{kind:"memory",id,revision,sha256}`. Use exact-open `body_sha256` for an observation and `revision_sha256` for a memory ([Implementation §7.3](IMPLEMENTATION.md#73-exact-open-and-byte-ranges)); a memory content-only hash is insufficient. Resolve `current` before packing; revision is positive and exact. Only `live_input` has `source=null`, meaning explicitly uncommitted caller input, not an invented citation. |
| `qualifiers` | Closed projection of applicable source fields: `perspective`, `conditions_json`, `exceptions_json`, `valid_from_ms`, `valid_until_ms`, `support_state`, `exposure_state`, `influence_state`, `applicability`, `capture_limit_json`, plus required `commitment_state` for commitment sources, required `method_role` for method sources (`processing_purpose` exactly for processing), computed `current_withdrawal` for every persisted memory unit, and `preparation_state` for prepared synthesis regardless of its rendered representation (§8.2). Copy complete source qualifications; compute applicability by §3 and withdrawal by Implementation §10. Omit inapplicable fields; missing facts never receive permissive defaults. |
| `coverage` | `{consistency:"per_query",arms:[{name,state}],gaps:[code...]}`. Names: `addressed`, `exact`, `lexical`, `relations`, `methods`, `vectors`; each appears once. States: `complete`, `partial`, `unavailable`, `disabled`, `not_requested`. This initial packet does not claim a coherent cut across independent queries. |

`current_withdrawal` is `none | withdrawn`, evaluated from current notices inside the
final delivery fence. It is not the stored `influence_state` and is not part of the source
revision hash. A withdrawn item may appear only as explicitly qualified historical
`evidence`/`counterevidence`, never as an active goal, plan, constraint, progress, commitment or
method; withdrawal does not itself refute its content. If the notice state cannot be
established, withhold that unit with `qualification_missing`, not a default `none`.
Erased/forbidden content is never packed. Preserve this live qualification when including an older exact revision.

Gap codes are the bounded, sorted, duplicate-free set `binding_missing`, `capture_pending`,
`source_missing`, `source_changed`, `source_damaged`, `scope_withheld`, `arm_unavailable`,
`candidate_limit`, `packet_limit`, `token_counter_unavailable`, `qualification_missing`,
`preparation_pending`, `preparation_unknown`.
The complete required header/coverage must fit before adding units; otherwise return an
explicit context error without source bytes. Never enumerate forbidden source IDs, titles
or counts in gaps. Empty successful arms mean only no match in the requested finite scope;
empty units with an unavailable/partial arm do not become a successful empty retrieval.

Hydrate exact revisions and validate every source/hash before selecting its text. Text
comes from the observation's accepted UTF-8 body or the memory revision's `content`.
An excerpt also carries `span={offset,length}` in UTF-8 bytes of that field: checked
bounds, positive length and code-point boundaries must reproduce `text` exactly.
A non-text body needs an already stored exact representation, not conversion during
packing. An excerpt needs its full qualification unit; a handle alone does not preserve
a missing contraindication. Staged commands and a prior emitted packet are not independent source
support. Live input is attributed to the current caller, never made a persisted goal or
authorization merely because it appears in a packet. Do not serialize rank scores or
expose internal Store/spool paths as locators; legitimate captured text is not rewritten.

Measure the **final host response**, including escaping/envelope/identifiers/coverage,
against 32 KiB and any smaller admitted host cap. Every removal rechecks §6.4's presentation
dependencies before freezing output; never cut a string, selector or qualifier. If even
gap-only output exceeds the cap, emit no packet. Exact token caps require the admitted counter.

#### 6.4.2 Compact model-facing rendering

`ContextPacketV1` remains the internal validated object. The host receives its readable
projection, not nested packet JSON. The existing context operation owns a deterministic
renderer; no second store, mutable alias registry or summarizer is needed.

1. Header: `Memory context (attributed data)`, mode and work address. Packet ID,
   installation/adapter versions, hashes and rank diagnostics stay internal.
2. Render packet order as `role [n]: text`, with exact JSON-quoted text. Mark excerpt/reduction
   once and uncommitted input `[live]`. Number exact sources by first appearance. Group complete
   action/result units by captured pairing; retain identities and do not infer cause.
   Updates name the current guidance's exact revision and supersede earlier guidance for
   that item; history is never labelled current.
3. Render decision-relevant qualifications next to the unit: supplied perspective and
   actual/hypothetical scope, full nonempty conditions/exceptions, validity,
   uncertain/disputed/refuted support, conditional applicability,
   withdrawal/supersession, partial source and pending/unknown preparation. Repeated identical
   qualifications may appear once for an explicitly delimited group. Empty arrays and normal/
   active/non-withdrawn defaults stay internal; roles already express an open commitment or
   advice method. This is a fixed projection, not semantic paraphrasing or hidden qualification loss.
4. End with `[n]=observation:<id>` or `memory:<id>@<revision>`; put excerpt offset/length beside
   its unit. Reuse aliases only for the same exact source; live input has none. Resolve locally
   to that immutable selector for ordinary exact open, never send `[n]` to a packet service/API
   or substitute `current`.
5. Show answer/scope-relevant gaps; full arm/gap diagnostics stay internal unless requested.
   Recount wrapped bytes and recheck §6.4 dependencies after trimming; no isolated cut may
   leave advice without its decisive qualification.

A baseline is self-contained after lost context; an update follows §6.2.1 and uses only
its own source aliases. Explicit diagnostics may return the internal packet. If §6.5's
optional recording succeeds, historical packet open returns the exact prepared body,
binding and source links; a separate observed handoff establishes emission. Missing records
remain unavailable. Never persist a second full packet copy for unused backend inventory.

### 6.5 Handoff

The daemon prepares context; the narrow relay emits it for one live host invocation.
Capture, preparation, local emission, host acceptance, use and outcome are different facts.
Primary capture/revision keeps its durable contract. **Packet/handoff telemetry is optional:
its failure must not withhold valid context or delay the host.** It cannot roll back capture.

Inside the existing affected-delivery fence, immediately before output, recheck:

- live invocation/work/session and installation selection; current authorization,
  disclosure, suppression and the host's actual allowed destination (local IPC alone
  does not authorize remote forwarding; unknown destination withholds restricted text);
- exact source hashes and qualifiers/notices; current-guidance roles require the selected
  revision still current/eligible, addressed slot → same item/revision, and commitment
  membership. Historical evidence keeps its exact revision and current withdrawal state.

Historical hydration and the presentation cache cannot replace these checks. A changed
selection requires freshly rendered bytes; an ambiguous prior emission is never retried.
Revision/withdrawal/erasure/cutover closes the affected fence to new emissions and drains
existing ones; timeout means unresolved delivery. Keep the spool mutex out of host/Store
I/O. Release the fence **after output settles and before optional record storage**; a caller
timeout alone does not settle a possible writer. Later notices cannot recall emitted bytes.

| Local state | Meaning |
|---|---|
| `prepared` | Exact output built; no claim of retention, emission or host receipt. |
| `not_emitted` | The live owner knows no response byte crossed the host boundary. Missing telemetry does not establish this state. |
| `emitted` | The relay observed a complete local write/flush; not host parsing, model use, task success or independent support. |
| `unknown` | Partial write, lost completion/report or crash after possible output. No automatic regeneration/resend of those bytes. |

When recording is available, use existing operation-owned capture, bounded by its normal
policy/quota: `context_packet` has `observation_id=packet_id`, the exact final body/hash,
binding and links to unit sources; `context_handoff` has
`{format:1,packet_id,packet_sha256,state,reason}` and the same invocation binding.
Handoff state is `not_emitted | emitted | unknown`; reason is `binding_changed`,
`policy_withheld`, `source_changed`, `deadline`, `output_complete`, `output_failed` or
`interrupted`, consistent with what was observed. Record the packet before its referencing
handoff, without another queue/service or a required write on the output path. Generic
capture cannot forge either reserved kind. Every retained copy remains subject to capture
policy and source erasure; live input is not exempt.

A bounded best-effort submission to the existing daemon may lose telemetry. The relay
never waits for its Store commit or stays alive past the output deadline to save a receipt.
After loss, durable attribution stays unknown; exact historical packet open may be
unavailable. Neither a presentation-cache entry nor a later transcript echo repairs that
fact. An actual later host acknowledgement is a separate attributed observation.

One invocation has one emitter/attempt; short-write completion stays within it. Storage
retry reconciles only the same fact, never repeats output. Only a documented native request
key correlates redelivery; session/text/time similarity does not. Restart/spool/restore
**never dispatch old packets**: a fresh boundary reconstructs current context. No claim of
cross-process exactly-once output or automatic recall of host transcript copies follows.

#### 6.5.1 First Claude output boundary

Use admitted synchronous callbacks and one JSON response: `hookSpecificOutput.hookEventName`
is the received event; `hookSpecificOutput.additionalContext` is §6.4.2's brief string.
Return successful exit, without duplicate stdout, permission decisions or blocking fallback.
No selected update means the host's successful empty response. Diagnostics stay off stdout.

| Boundary | Automatic work |
|---|---|
| `SessionStart`, including startup/resume/compact | Fresh baseline; no old-packet replay. A fork uses its actual new binding. |
| `UserPromptSubmit` | Capture accepted input and rebuild affected focus/current work; emit a useful update or required baseline. Staged input stays explicitly uncommitted. |
| `PostToolUse`, `PostToolUseFailure` | Capture supplied result/error with original binding and call identity; extract actual artifact/error cues. Emit here only when the adapter has no admitted batch boundary. |
| `PostToolBatch`, when supported | After the parallel batch resolves and before the next model call, emit one combined update. Correlate its entries with captured tool calls, not new independent occurrences. |
| `Stop`, `SubagentStop`, `PostCompact`, `SessionEnd` | Capture supplied final text/summary/lifecycle data. Stop is not task acceptance; compaction summary is derived. Never wait for Dreamer or a clean exit to preserve earlier work. |

Select one tool-result emission path per installed adapter: batch when actually supported,
otherwise per-tool success/failure. Exact cue extraction is shared with preparation
([Implementation §7](IMPLEMENTATION.md#7-core-operations-and-host)); known dependency
activation needs no inference. Semantic model changes still use the ordinary revision
writer; installing hooks alone does not create understanding.

The [official hooks reference](https://code.claude.com/docs/en/hooks), read 2026-11-06,
documents `additionalContext` for these start/prompt/tool-result boundaries and
[`PostToolBatch`](https://code.claude.com/docs/en/hooks#posttoolbatch). Batch tool responses
are model-visible strings/content blocks, unlike structured `PostToolUse.tool_response`;
use each event's decoder. Failure-hook error text is not a stable error-code schema.
The [hooks guide](https://code.claude.com/docs/en/hooks-guide#re-inject-context-after-compaction)
places reinjection at `SessionStart(compact)`. These are documentation observations;
enable each callback only against its installed version's actual input/output contract.
`PreToolUse` follows the agent's choice of action; advice there is not guaranteed replanning.

[Transcript replay on resume](https://code.claude.com/docs/en/hooks#add-context-for-claude)
may include old context without rerunning its hook. Verified source correlation marks
that occurrence derived; text similarity or a forged marker cannot establish delivery.
An echo cannot strengthen its claim or trigger interpretation. Packet/handoff records
are operational provenance, excluded from new-experience triggers and ordinary candidate
arms; exact authorized inspection remains possible. Source erasure reaches their derived
copies through existing links.

#### 6.5.2 Connected implementation check

Implement this in Slice 2's existing context/host modules, after capture/open and durable
ingress. Use a disposable admitted host invocation and inspect actual output plus exact
source open. Check the following boundaries while connecting that path, not by adding a
new reporting framework or declaring a docs example to be runtime evidence:

| Case | Required result |
|---|---|
| New/compacted/uncertain context | Self-contained current baseline with exact sources; no dependence on old aliases or cache. |
| Long tool loop; repeated unchanged read | Artifact/error/result activates relevant prepared knowledge before the next supported model boundary; unchanged repetition emits nothing. |
| A selected source/qualification changes | Emit its complete correction and necessary premises; do not suppress it by item ID, similar words or prior presentation. |
| Packet/receipt storage fails | Valid context still emits within deadline; durable attribution remains unknown and no old output is replayed. |
| Same text, different work/session | No cross-binding packet reuse; distinct occurrences remain distinct. |
| Same task key in different workspaces, or two tasks in one session | Distinct work addresses; an empty/failed task lookup never widens to the whole session. |
| Resolved commitment or processing recipe selected as advice | Reclassify as qualified history or omit; preserve commitment/method state, never emit it as active work/advice. |
| Plan exists but progress slot is empty | Return plan as plan; do not claim execution, completion or an invented progress view. |
| Missing/truncated grounds or unevaluated exception | Not an empty successful assessment or unconditional advice; preserve the uncertainty and applicable coverage gap. |
| Current revision/policy changes before output | Revision publication and output share the affected fence; historical hydration cannot pass a current-revision check. Rebuild or withhold, never send stale positive guidance. |
| Withdrawn historical source with stored influence active | Preserve the exact revision hash and add current withdrawal qualification; never promote it to positive guidance. Missing notice authority is not `none`. |
| Oversized unit or exhausted retrieval arm | Preserve qualifiers or omit the unit with a gap; encode partial/unavailable truthfully and remain within the final-response cap. |
| Relay exits or response/report is lost | Capture stays committed; handoff is unknown where appropriate; restart emits no old packet. |
| Transcript replay / forged packet marker | No new evidence, method-success claim or model job from recaptured context; unverified attribution stays unknown. |

## 7. Exact open

Use [Implementation §7.3](IMPLEMENTATION.md#73-exact-open-and-byte-ranges) for closed
selectors, byte ranges, complete revision hashes and disposition-specific responses.
Do not rerun search, conversion, Research or inference to satisfy a historical handle.
An opaque locator is not another selector or permission; history never falls forward.
Non-content results do not expose source hashes, lengths or private qualifications;
Store/notice unavailability is an operation error, not `missing`. Relation expansion
uses the selected exact revision and its own bounded coverage, not guessed empty links.

## 8. Processing methods and jobs

A processing method is an ordinary versioned Memory item: purpose, instruction body,
input/result contract, conditions/limitations and disclosure consequences. First enable
stores a real default; upgrade never overwrites an edited revision. Job claim freezes
exact method and source coverage. A stored method without a consumer is not improvement.

### 8.1 Dreamer preparation

One finite job prepares a view, explanation or method for a named context/research
consumer, without speculative archive-wide synthesis:

1. **Collect.** Join captured events with supplied action/result/test identities, scope and
   resource versions. Deduplicate representations, never occurrences.
2. **Select.** Freeze changed primary facts, the exact prior view/method and needed original
   supporting/contradicting anchors. Reopen only spans needed to resolve material omissions;
   summaries add no independent support. Unavailable anchors leave qualified gaps, never
   invented facts or silently dropped conditions.
3. **Synthesize.** Distinguish state, observed transition, mechanism, procedure and unresolved
   alternatives. Preserve speaker/hypothetical scope; outcome alone does not establish cause.
   Never invent identities or support.
4. **Clean.** Revise the owning unit; remove narration, split incompatible conditions, retain
   counterexamples and discriminating checks. Derive search text from replacement content
   and observed exact cues through Implementation §7's shared normalizer.
5. **Publish.** Use §9.2 and the ordinary revision writer; the next context lookup consumes
   prepared text without inference.

Automatic mode is `off | idle | background`. New primary outcomes, test results, corrections
or agent-authored task handoffs coalesce into the work/view-targeted refresh. Repeated polling, packets,
injected echoes, cleanup and accounting cannot trigger it. Prefer current-work changes
and known repeated needs to speculative generalization; reuse and refresh cost determine
whether further preparation is worth doing, not a promise that background compute is free.
Capture/context retain foreground capacity. A burst updates one pending intent, not one
model call per event. Unused derived material may lose exposure without erasing its source.

`off` disables automatic preparation, not an explicit research request admitted by the
configured inference profile. For `(project,purpose,target)`, permit one active job and one
coalesced successor. Distinct explicit questions use distinct targets (§8.3). The host agent
and Dreamer share one revision writer/CAS: neither silently overwrites a newer direct edit;
inference never amends the user's goal by itself. Base remains useful with inference off.

[Implementation §4.7.3](IMPLEMENTATION.md#473-job-state-and-claim-ownership) owns scheduling
states, claim generations and terminal-result mapping; provider, cognitive and cleanup
states remain distinct. Keep reserved limits, measured usage and unknown usage distinct;
an absent provider measurement is not zero cost.

### 8.2 Prepared knowledge and newer evidence

A current revision is not proof that its synthesis includes newer facts. Apply this check
to prepared views, explanations and methods, including an exact-text rendering of them;
ordinary direct facts/goals do not become synthesis merely by being stored. Use exact
grounds, indexed preparation links/job coverage (§7.6 of Implementation) and newly
selected primary observations:

| Computed `preparation_state` | Reader behavior |
|---|---|
| `covered` | A completed accepted preparation/research result accounts for the requested finite input and this exact output revision. This is selection-relative coverage, not universal freshness. |
| `pending_input` | Known relevant input is not incorporated. Show the still-applicable view with the new evidence and a short pending qualification; do not wait for Dreamer. |
| `basis_changed` | A material premise changed, was refuted/withdrawn, or its bound resource has a new version. A version change alone is not refutation: requalify dependent advice under §3; unresolved impact stays conditional, established incompatibility becomes qualified history. |
| `unknown` | The preparation relation, input coverage or bounded lookup is insufficient. Keep that uncertainty; do not infer freshness from age, `current`, or an empty page. |

Accepted job coverage binds exact output revisions to accounted primary input. Direct views
are usable immediately; prose/grounds do not prove processing coverage. `no_change` may advance
same-view coverage; failed/partial/unknown work cannot. Retain unprocessed references in the
coalesced successor without automatically retrying an unknown call. Bounded indexed lookup
never scans historic jobs; exhaustion is `unknown`, and receipt order cannot exclude delayed
capture (§2). These computed qualifiers add no persisted state and do not gate unrelated
units or the agent's actions.

### 8.3 Research: an agent can ask Dreamer

Research is an explicit question-driven Dreamer job over retained knowledge, optionally
using acquired sources. It is not restricted to web search, a failed retrieval or a claimed
uncertainty threshold. The agent may ask for an explanation, synthesis, competing models,
missing evidence, a procedure or review of its own understanding whenever useful.

The caller submits a question, work scope and optional exact sources/previous answer.
Persist each turn as its own source observation; return its existing job handle immediately,
or wait only for the caller's finite requested interval. Job status/read exposes accepted
partial or final answer references, remaining questions and failure status. Exact open
uses the ordinary source/revision operation. A reply is a new request linked to the exact
previous question/answer, with its relevant delta; no permanent Dreamer session or full
transcript replay is needed. Different questions are never overwritten by coalescing.

The answer is a concise usable model/proposal, supporting sources, material alternatives
and the next discriminating query/check. Publish it as an ordinary scoped view/explanation;
it does not silently replace work goals. Reusable findings may also revise their owning
items. Unresolved evidence can produce a useful answer with a question back to the agent.
Status reads never restart work; cancellation uses existing job control.

When external evidence is needed, use the configured acquisition owner and capture its
result before including it in a new frozen input. A later result/follow-up is a new finite
job, not mutation of a running job's input. Missing acquisition does not disable local
analysis. Neither automatic hooks nor an unanswered question start an unbounded research loop.

## 9. Controller-backed job lifecycle

### 9.1 Stable identity and live admission

Consume only the exact admitted call/input. Unknown admission is unresolved, never a
new call ID. [Inference §§2/5–7](INFERENCE-CONTRACT.md#2-principal-credential-and-identities)
owns admission, rollback-safe identity, replay and read-only uncertain-effect lookup.

### 9.2 Result and cognitive states

Read bounded exact call status → range-read its result → verify digest/length → durably
publish the Memory result blob → decode the purpose-specific schema → publish each accepted
revision through the existing atomic writer → expose it to its consumer. Retain malformed/partial
transport facts without claiming cognitive completion.

```text
changes
no_change
partial
conflict_or_unknown
decode_failed
operational_failed
```

No-change requires an accepted purpose-specific result covering the entire frozen
required input under §4, with no semantic change to publish. Covering only the supplied
subset cannot complete omitted or unavailable selected entries. A refused profile,
missing result, unknown call, truncated input/output or failed decoder is not no-change.
A terminal partial result maps to Implementation §4.7.3's failed/partial outcome; unknown
admission/commit remains reconciliation, not a terminal failure used to release the slot.
The call's technical success does not prove the interpretation is supported.

Before publication, resolve cited source IDs/ranges against admitted supplied input or
an explicit authorized exact read; an ID in model JSON cannot create evidence. Recheck
expected revisions, current scope/disclosure and suppression/deletion notices. Unsupported
claims remain qualified proposals; fabricated sources or unauthorized effects reject.
An old job result cannot reinstate a withdrawn method or erased source.

Each item uses Implementation §7.4's single-item operation. A dependent edit names the
confirmed predecessor result; it cannot use a merely proposed revision. If a later edit
conflicts, retain independent accepted items and report partial coverage. Do not pretend
that several successful single-item writes were one atomic multi-item publication.

### 9.3 Cleanup authority

Release/cancel/retention follow [Inference §9](INFERENCE-CONTRACT.md#9-release-retention-and-erasure)
and [Implementation §8](IMPLEMENTATION.md#8-backup-set-owner-and-lifecycle). Accepted useful
revisions remain usable while cleanup debt is visible. Missing caller authority requires
owner action, never credential fallback.

## 10. Backup admission and authority

[Implementation §8](IMPLEMENTATION.md#8-backup-set-owner-and-lifecycle) owns the physical cut;
[Inference §8](INFERENCE-CONTRACT.md#8-memory-backup-interaction) owns external dependencies.
A closed job needs all exact retained facts/bodies and no pending settlement, publication
or external readback/cleanup; otherwise it remains dependent and release-pinned. Retired
IDs never run; unknown effects remain unknown. Backup records do not prove erasure.
Base backup does not require inference when no calls were admitted.

## 11. Exact rollback and external work

Restore exact backup cognition; [current notices](IMPLEMENTATION.md#10-erasure-rotation-and-observability)
dominate. Reconcile post-cut spool by exact identity/bytes; do not adopt unrelated future
results. Closed jobs use retained facts, dependent jobs their exact call/copy; retired
IDs remain retired. [Inference §10](INFERENCE-CONTRACT.md#10-restore-and-stale-mirrors) owns
inventory, uncertainty and mirror reconciliation. Missing history/identity/copies or
unresolved external effects keep inference unavailable while valid Base remains useful;
Store, lease and cutover failures separately block their affected operation.

## 12. Consolidation, disagreement and improvement

Distinguish source replay, packet grouping, same-item revision, synthesis, generalization
and correction/split. Broader patterns are separate provisional items linked to exact
sources; never merge source IDs or rewrite history.

### 12.1 Learning must change a later decision

The loop is **expected result → observed outcome → local diagnosis → changed knowledge
or processing method → later use → new outcome**. Tests, user corrections and failed tool
calls are ordinary primary observations. A plausible retrospective explanation remains
a hypothesis until its evidence discriminates it from alternatives.

| Failure located in the existing path | Smallest useful adaptation |
|---|---|
| Wrong fact/premise or changed artifact | Correct the owning claim/view, requalify dependent advice, retain the counterexample. |
| Useful knowledge was not retrieved | Repair exact cues, scope or links; do not rewrite a correct fact to compensate for a lookup defect. |
| Retrieved knowledge was lost in a long/noisy brief | Revise the short representation or exposure priority; preserve the decisive condition/example. |
| Procedure failed under a known condition | Narrow its applicability or revise its step/check/recovery; record what change would justify another attempt. |
| Dreamer repeatedly omitted, overgeneralized or misclassified evidence | Revise the existing processing recipe/input selection against those examples; subsequent jobs must consume that exact method revision. |

One success can yield useful scoped experience immediately; it does not establish a
universal rule. A factual repair or qualified hypothesis does not wait for promotion,
mandatory repeated execution or another evaluator service. A failure can immediately
narrow advice or motivate a provisional alternative. Claiming that a replacement is better
needs an attributable comparison with comparable criteria, scope and total cost. More
attempts or fitting the revision's own examples do not establish transferable benefit.
Preserve beneficial behavior and counterexamples; the latest candidate is not automatically
the best-supported one.

Optimize useful continuation, avoided repeated mistakes and total preparation/read/use
cost. Token reduction alone can hide lost evidence. Reuse observations may inform a
primary-outcome-driven job, but reads/emission cannot reward their own content or trigger
another learning pass. No reusable change means no new lesson; keep the source result.
Dreamer proposes knowledge/recipe edits, not tool execution or model-weight training.
Ordinary feedback such as “stale”, “missing”, “irrelevant” or a corrected result is useful
input through §5, not a required scorecard. Missing delivery telemetry limits attribution;
it does not forbid a grounded factual repair or an explicitly attributed user assessment.

### 12.2 Disagreement and attribution

Disagreement belongs to a question, scope and time. Preserve alternatives and grounds;
select the cheapest discriminating observation. Voting is not evidence. Predictions
retain expected observations before action.

Attribution uses existing source observations and exact revision links, not a success
counter or another acceptance authority. Its consumer is the ordinary method/claim
revision and later qualified context. Keep these facts separate:

| Fact | Evidence and limit |
|---|---|
| Method offered | Exact method revision and packet/invocation correlation; preparation/emission is only §6.5's fact, not use. |
| Action observed | Original execution/call identity and attributable action/result observations, with issue-time work binding. A proposed action is not an executed attempt. |
| Adherence | `known`, `inferred` or `unknown`, with its sources. Co-occurrence of advice and action does not establish following the method. |
| Criterion outcome | Exact criterion version, evaluated target/resource version and attributable result. A tool's exit/result and host acceptance of the task are separate observations. |
| Comparative benefit | An explicit comparison with its conditions and limitations. One success after advice does not establish that the advice caused it or outperformed an alternative. |

Resolve one attempt from its native execution/action-start identity and exact criterion
version. Copies, summaries, additional criteria or method associations do not multiply
physical trials; a distinct real execution does, even with equal bytes. Missing correlation
remains unknown rather than being inferred from text or timestamps. Attribute late results
to the method actually offered/used, not its newer revision. Preserve conflicting results;
arrival order, votes and a changed criterion cannot turn them into a prior success.
Missing outcomes/acceptance remain unknown; model self-report cannot supply owner acceptance.
Known partial results remain useful. Post-hoc comparisons are labelled retrospective.

On the connected path, inspect duplicate reports versus distinct attempts, contradictory
results, changed criteria/methods, an unavailable selected input and a later context that
actually uses the repair. A stale prepared answer must not hide the counterexample while
refresh runs. These are local semantic checks, not a new benchmark or success registry.

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
real event → policy admission → durable command → Store commit/replay → restart → context → exact open
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
| Embeddings | Exact source revision plus query/document role and compatible model/space → individually mapped vectors → optional retrieval arm | Each vector stays bound to its indexed revision; never relabel stale content as current. Missing/mismatched/failed input has no fabricated vector; exact/lexical lookup continues during refresh. |
| Research | Agent question/follow-up → §8.3 Dreamer job → concise answer/view and exact sources → agent/context; external acquisition only through its configured owner | Distinct questions survive; local analysis remains usable without external acquisition. Partial/unknown is not no-findings; no second research executor. |

Self-inspection uses the same source/open/status paths for Eliot's own documents and
operations; it does not create a separate self-model registry.

Adapters are chosen when their first writer and consumer are implemented. Historical
donor choices are research inputs, not authorization to add unused dependencies.
