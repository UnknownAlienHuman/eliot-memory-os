# Eliot Memory OS V3 — Cognition

**Revision 1.0-draft.31 · 2026-11-04 · design algorithms, not runtime evidence.**

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
identities and explicit links.

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
The [durable command](IMPLEMENTATION.md#75-durable-ingress-and-replay) precedes Store
send; a pending correction is not an accepted semantic state. After rollback, post-cut
corrections require the explicit adoption rule in Implementation §8.2, not automatic replay.

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

Prioritize current goal/criteria/plan/progress; exact corrections/constraints; open
commitments; applicable or conditional advice with exceptions; relevant episodes;
dissent/unknowns/missing checks; exact source handles.

Apply Implementation §4.7.2's eligibility before assigning a positive role. Hidden items
are excluded from automatic packets, not made public by relabeling them evidence.
Only a current `commitment` with `commitment_state=open` gets role `commitment`; resolved
or cancelled items may appear as qualified history, never an outstanding obligation.
Role `method` requires `method_role=advice`; processing recipes belong to §8's owning
job and cannot become ordinary recommendations. Persisted goal/plan/progress guidance
uses §2's current views, not a text classifier; live input stays explicitly uncommitted.
Missing required state withholds the unit with a gap, not a default.

Base renders selected structured fields and exact labelled excerpts; it does not need
an LLM to summarize them. Within the priority classes above, prefer addressed current
work, then newer observed receipt time, then canonical ID/revision as a deterministic
tie-break. Union duplicate exact revision handles, not similar text or distinct events.

Treat value plus negation, conditions, exceptions, validity and source handle as one
packing unit. Include it whole; otherwise use an existing qualified short representation
or omit it with an explicit gap. Do not invent a shorter paraphrase or drop a qualifier.
Enforce [the Base byte cap](IMPLEMENTATION.md#451-first-base-limits) on actual emitted
UTF-8 bytes, including labels/handles/gaps. Reserve room for the gap summary first.
A byte count is not a token measurement: when the host requires an exact token budget,
use its admitted counter or report that capability unavailable, never a guessed PASS.

Retrieved text, documents, tool output and recalled model answers are evidence, not
new host/system instructions. Render them as attributed data with source/revision and
scope, separately from the selected processing recipe and current user request. Neither
quoted commands nor a model's claim of authorization can change permissions, disclosure,
provider route, execution budget or the user goal. Text delimiters alone do not enforce
this boundary; the application accepts only the owning operation's closed DTO/effects.

#### 6.4.1 Base packet encoding

`ContextPacketV1` is one closed data object owned by the existing context operation,
not an instruction protocol or a new packet service. Its exact top-level fields are
`format=1`, `packet_id`, `binding`, `units` and `coverage`. Use Implementation §4.5's
canonical JSON, no floating-point fields, duplicate keys or unknown members. Unsupported
formats fail explicitly. Packet identity is an ordinary `o_` observation ID, not a new
ID namespace; allocate it once before preparing the output.

| Field | Required meaning |
|---|---|
| `binding` | `installation_id`, nonnegative integer `selection_generation`, `project`, `workspace_id`, `actor_id`, `session_id`, `host`, `host_version`, `adapter_version`, `event`; optional `task_id` and `native_request_key`. All other values are nonempty strings bounded by Implementation §4.5.1. The admitted adapter supplies versions/event mapping, not caller text. Missing task uses §2's session address. Missing session/work authority cannot fall back to a similar project's packet. |
| `units` | At most 32 ordered units under §6.4. Each has `role`, `representation`, `text`, `source` and `qualifiers`, plus `span` only for an excerpt. Roles are `goal`, `plan`, `constraint`, `progress`, `commitment`, `method`, `evidence`, `counterevidence`. Representations are `verbatim`, `excerpt`, `stored_reduction`, `live_input`. A stored reduction retains its own exact source identity; it is not generated while packing. |
| `source` | For persisted units: `{kind:"observation",id,sha256}` or `{kind:"memory",id,revision,sha256}`. Use exact-open `body_sha256` for an observation and `revision_sha256` for a memory ([Implementation §7.3](IMPLEMENTATION.md#73-exact-open-and-byte-ranges)); a memory content-only hash is insufficient. Resolve `current` before packing; revision is positive and exact. Only `live_input` has `source=null`, meaning explicitly uncommitted caller input, not an invented citation. |
| `qualifiers` | Closed projection of applicable source fields: `conditions_json`, `exceptions_json`, `valid_from_ms`, `valid_until_ms`, `support_state`, `exposure_state`, `influence_state`, `applicability`, `capture_limit_json`, plus required `commitment_state` for commitment sources, required `method_role` for method sources (`processing_purpose` exactly for processing), and computed `current_withdrawal` for every persisted memory unit. Copy the source's complete conditions/exceptions/limitations; compute applicability by §3 and withdrawal by Implementation §10. Omit fields inapplicable to that source kind; do not replace missing required facts with permissive values. |
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
`candidate_limit`, `packet_limit`, `token_counter_unavailable`, `qualification_missing`.
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

Measure the **final host response**, including JSON escaping, envelope, identifiers and
coverage, against the 32 KiB Base packet cap (and any smaller admitted host cap). Removing
a whole lowest-priority unit and updating gaps is allowed before freezing output; cutting
a JSON string, source selector or qualifier is not. If even the gap-only response exceeds
the cap, emit no packet. An exact host token cap still requires its admitted counter.

### 6.5 Handoff

The daemon prepares/records context; the narrow relay emits it for one live host
invocation. Capture completion, context preparation, local emission, host acceptance,
action association, use/influence and criterion outcome are separate facts. Context
failure never rolls back a committed capture or authorizes blocking the user's task.

Before returning output to the relay, retain the exact final host-response bytes as one
operation-owned `context_packet` observation, with `observation_id=packet_id`, ordinary
body length/hash, the binding above and derived links to the exact unit sources. Apply
capture exclusions to every retained copy, including live input and metadata. Reuse
existing capture/blob custody and its limits; do not add a packet table, delivery queue
or job. If the exact packet cannot be committed/read back before the host deadline,
return context unavailable; staged packet custody is not permission to emit it later.
Generic capture cannot forge this reserved kind or a delivery result. Its replay identity
is the packet ID; a native host key is correlation, not observation deduplication for
packet construction. A saved packet is preparation and possible-send intent, never
proof of emission.

Immediately before output, recheck the live invocation/session/work binding, installation
selection, current authorization/disclosure and suppression. A local host may forward
context to a remote provider: local IPC permission alone does not authorize that
forwarding. The admitted host profile must bound the allowed destination/disclosure;
unknown destination keeps restricted content withheld. For a memory unit selected as current
goal/plan/constraint/progress/commitment/method, verify that the current revision still
equals the selected revision and still passes the role's eligibility. For an addressed
view, recheck that the requested work slot resolves to that same item/revision; for a
commitment, recheck its creation binding and current permission to use that membership.
Historical open is not either check.
Revalidate exact source hashes, qualifications and current notices. A changed eligible
result requires rebuilding and a new packet ID, never changing bytes under the old one.
No retry follows an ambiguous prior emission.

The bounded emission participates in the existing affected-delivery fence used by
revision publication, withdrawal, erasure and cutover. Closing that fence rejects new emissions and drains
in-flight ones; a timeout leaves unresolved delivery, not completed erasure. Recheck
inside the fence, not only while constructing the packet. Do not hold the spool
publication mutex across host/Store I/O. Once local output I/O has stopped or settled,
release the delivery fence before queueing/persisting the handoff fact; its storage must
not be what a waiting revision needs to drain. A still-running possible writer is not
settled merely because its caller timed out. Bytes already handed to the host cannot be
recalled by a later notice; host-owned transcripts/copies remain explicit cleanup limits.

| Reported state | Required observation / recovery |
|---|---|
| `prepared` | Exact output built/retained; no claim about host receipt. After a discontinuity, a possibly returned packet without a terminal fact is `unknown`, not safe to resend. |
| `not_emitted` | The live owner knows no response byte crossed the host boundary, for example a binding/policy rejection before write. Retain a bounded reason; do not report this after a partial write. |
| `emitted` | The relay observed the complete local write/flush. This proves only emission to the local channel, not successful process exit, host parsing/acceptance, model use, task success or independent support. |
| `unknown` | Partial write, lost completion/report, cancellation or crash after possible output. Preserve identity/bytes; never regenerate or append the packet automatically. |

Record the actual local outcome as an immutable, operation-owned `context_handoff`
observation: `{format:1,packet_id,packet_sha256,state,reason}`. Here `state` is one of
`not_emitted`, `emitted`, `unknown`; absence is not a fourth successful result. `reason`
is `binding_changed`, `policy_withheld`, `source_changed`, `deadline`, `output_complete`,
`output_failed` or `interrupted`, consistent with the observed state. Its observation
binding identifies the same invocation/adapter and links to the packet observation;
`packet_sha256` is the recorded final output hash. A later host acknowledgement, association or outcome is a separate attributed
observation with exact correlation, not a rewrite or an upgrade inferred from exit zero.
Failure to retain this fact after output leaves durable status unknown even when the
live relay observed success. It cannot change the host response, block the turn or cause
another send. Retrying storage of the same fact never repeats host output.

For one live invocation there is one emitter and one bounded emission attempt; ordinary
short-write completion belongs to that attempt, not a new response. After interruption,
partial-output failure or an ambiguous result, do not restart the response. A documented
native request key may correlate a redelivery to the existing packet; session ID, prompt
text and time proximity are not such a key. Without a stable key there is no cross-process
exactly-once claim. In this first profile, restart, spool replay and backup restore may
reconcile/store packet facts, but **never dispatch old packets**. A new actual host
boundary may request freshly authorized context; it is not replay of an uncertain old
handoff. Read-only host acknowledgement can resolve an old unknown only when the installed
adapter actually supplies it; do not build a speculative acknowledgement endpoint.

#### 6.5.1 First Claude output boundary

Initial context emission uses only admitted synchronous `SessionStart` and
`UserPromptSubmit` callbacks; other selected events remain capture-only until separately
implemented. Emit one JSON response with `hookSpecificOutput.hookEventName` equal to the
received event and `hookSpecificOutput.additionalContext` containing the serialized
packet as a string. Use the documented successful exit, no extra plain-text duplicate,
permission decision, prompt replacement or blocking fallback. Diagnostics never share
stdout or echo private content. Event-specific mapping is ordinary adapter code, not a
new host capability registry.

The [official hooks reference](https://code.claude.com/docs/en/hooks#userpromptsubmit-decision-control),
read 2026-11-04, documents this context field. It also documents
[transcript replay on resume](https://code.claude.com/docs/en/hooks#add-context-for-claude):
old mid-session context can be replayed by the host without invoking the old hook again.
This is not fresh Memory validation or a new method outcome. These are documentation
observations, not qualification of an installed Claude version; enable each callback
only after observing its actual input/output contract on that version.

When context later appears in a transcript, preserve the occurrence but mark verified
injected/derived lineage by exact packet/source correlation. An unverified packet marker
in user/tool text does not establish delivery. Similar text is not deduplication, and an
echo cannot strengthen its own claim or retrigger interpretation. Packet/handoff records
are operational provenance, excluded from new-experience triggers and normal candidate
arms; exact authorized inspection remains possible. Source erasure reaches these derived
copies through their links, not a rule that operational records may keep private bodies.

#### 6.5.2 Connected implementation check

Implement this in Slice 2's existing context/host modules, after capture/open and durable
ingress. Use a disposable admitted host invocation and inspect actual output plus exact
source open. Check the following boundaries while connecting that path, not by adding a
new reporting framework or declaring a docs example to be runtime evidence:

| Case | Required result |
|---|---|
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

Automatic mode is `off | idle | background`; a profile may forbid automatic calls.
New primary committed input, correction or explicit question can trigger interpretation.
Reads, packet/handoff provenance, injected echoes, cleanup and accounting cannot. For `(project,purpose,target)`, permit
one active job and one coalesced successor. Waiting is not failure or retry authorization.
[Implementation §4.7.3](IMPLEMENTATION.md#473-job-state-and-claim-ownership) owns scheduling
states, claim generations and terminal-result mapping; provider, cognitive and cleanup
states must not be collapsed into that scheduler status.
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

After verified copy or terminal-no-result, request caller-authorized release only after
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
| Embeddings | Exact source revision plus query/document role and compatible model/space → individually mapped vectors → optional retrieval arm | Missing, mismatched or failed input has no fabricated zero/aggregate vector; exact/lexical Base remains available. |
| Research | Explicit finite acquisition request through the configured external owner → retained result, sources and terminal/partial status → ordinary interpretation | Unavailable source or failed request is not no-findings; Memory does not add another research executor. |

Self-inspection uses the same source/open/status paths for Eliot's own documents and
operations; it does not create a separate self-model registry.

Adapters are chosen when their first writer and consumer are implemented. Historical
donor choices are research inputs, not authorization to add unused dependencies.
