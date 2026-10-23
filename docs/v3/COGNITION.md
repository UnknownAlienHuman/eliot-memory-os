# Eliot Memory OS V3 — Cognition

**Revision 1.0-draft.5 · 2026-10-23 · normative algorithms used by the V3 implementation.**

This document defines how Eliot reconstructs current work, resolves revisable knowledge, retrieves useful context, learns from outcomes and improves connected methods. It does not define additional services. All state and work use the owners in [Implementation](IMPLEMENTATION.md).

## 1. Units of cognition

Eliot distinguishes:

- **observation** — what a source supplied;
- **episode** — a useful connected slice of observations;
- **claim** — an asserted value/explanation;
- **hypothesis** — an uncertain explanation;
- **view** — a saved answer about a project/source scope;
- **method** — reusable guidance with conditions;
- **prediction** — expected future observation;
- **outcome** — observed result of an attempt;
- **continuation** — current work state;
- **unknown** — an explicit missing fact or unresolved relation;
- **commitment** — something still owed in a recorded scope, separate from its notification.

A source event, search chunk and episode are different. Search chunks help locate material; they do not replace the source or define the task. Receiving an assertion is an observation of that assertion, not verification of its contents; distinct record IDs do not establish independent corroboration.

## 2. Decision frame and current work

The decision frame separates stable project/workspace/task identity from observed location, branch, resource versions and time. It also contains available session, goal, criteria, execution profile and context incarnation. Non-Git work uses the same distinctions without inventing a branch or commit.

Current work is reconstructed in this order:

1. open the continuation by stable task or actor/session address within its workspace;
2. read relevant observations outside its per-stream/segment coverage, including retained material newly associated with this work;
3. apply explicit goal/plan corrections;
4. preserve abandoned alternatives and open commitments;
5. only then retrieve similar prior work.

If no task identity exists, use the narrowest known session/workspace continuation. Do not attach interleaved events to the latest prompt merely because it is latest. Keep goal/criteria tied to their explicit user/host sources; generated plans and summaries cannot silently revise them. A Git branch switch changes environmental applicability, not the identity of a continuing task. A native conversation fork or explicit cross-workspace transfer has its own association; neither silently renames the source task.

A continuation revision contains:

- active goal;
- current plan;
- completed actions/results;
- abandoned approaches and reasons;
- open commitments/unknowns;
- next useful step;
- represented streams and observation IDs/segments or exact ranges, source handles and gaps.

A summary never replaces the original observations. Reading a tail is not publishing a new summary or proving that every stream was processed. Late observations retain the resource/task association in which they arose rather than inheriting today's session selection.

## 3. Claim identity and current-state resolution

A comparison group uses the minimum useful identity:

- project and material workspace/task scope;
- subject/resource;
- aspect;
- perspective;
- relevant time and known resource conditions.

Perspective distinguishes intended behavior, observed implementation and proposed explanation. Different workspaces or versions can legitimately have different values. Compare them before declaring contradiction, replacement or transfer; project membership alone is insufficient.

`resolve_current(group, decision_time)`:

1. load accessible alternatives and relevant revisions outside semantic top-k;
2. apply stated validity, known resource conditions and explicitly scoped replacements;
3. preserve alternatives whose conditions differ;
4. evaluate compound grounds when explicitly represented;
5. return current alternatives, conflict or unknown;
6. include qualifications and history handles.

Last write, highest similarity, retrieval frequency and model confidence are not universal authority rules. Support assessment, retrieval exposure and advisory influence remain separate from physical existence. Archiving changes exposure, not truth; inspection of withdrawn history does not restore its influence.

### 3.1 Replacement

Prepare a proposed replacement outside the transaction. Publish new revision, revision-specific grounds, scoped retirement and job result atomically.

A failed publication leaves the prior committed state intact. Competing replacements revalidate the current revision. A result for a particular source version may be retained for that version; it does not become current evidence about a different workspace or newer resource merely because publication happened later.

### 3.2 Withdrawal

After A→B, withdrawing B does not make A current automatically. Return another supported alternative or unknown. Restoring A requires new evidence or correction of the original replacement decision.

### 3.3 Multiple grounds

A grounds group belongs to one conclusion revision. Every declared member is required for that derivation; different explicitly alternative groups offer other derivations. Ungrouped support is not silently made necessary. Navigation, shared episode membership and repeated summaries do not create new evidence or independent alternatives.

Evaluate the recorded basis, not a universal truth score:

| Recorded situation | Consequence for that basis |
|---|---|
| Every required member remains usable for the stated scope | The declared basis remains available; this does not certify the conclusion |
| A required premise is known refuted or a required live condition is known inapplicable here | That group cannot justify the conclusion in this situation |
| A required member or its relevance is unresolved | That group is unresolved, not automatically true or false |
| No declared group exists, composition is unknown, or a required member disappeared | Do not obtain support from an empty set or from the remaining citation count |

For an explicit `(A and B) or C` derivation, loss of B does not erase an intact C basis. If all bases fail, the old conclusion lacks its declared justification; that does not prove the opposite conclusion. A surviving group also does not erase a direct counterexample to the conclusion: retain the conflict and examine it. If only unresolved bases remain, return the limitation or a conditional account instead of prohibiting all memory use.

Distinguish historical evidence from present requirements. A newer source edition does not automatically refute its old observation. Temporary inability to open a source does not make stored knowledge false, though it limits verification. A live requirement that no longer holds affects current applicability. Reduced exposure changes none of these facts. Refutation/correction must address what was actually used, not just a newer object with a similar name.

Reconsider changed grounds through the existing `memory`, `context` and job path in [Implementation §8.5](IMPLEMENTATION.md#85-reconsider-affected-grounds). Use indexed reverse links, preserve distinct groups and stop repeated visits within a cause. A cycle such as A citing B citing A is not independent support; consider a genuinely separate grounded alternative or leave the cyclic basis unresolved. Do not expand every possible proof combination or require full-graph validation before an ordinary read.

Erasing a required premise must not silently turn an AND group into a smaller, apparently satisfied group. Record the permitted loss-of-ground fact before removing its link. Support and permission to retain or disclose derived text remain separate: an alternative basis does not cleanse old text containing erased material. Unknown composition calls for targeted reconsideration, not an invented Boolean formula or a global quarantine.

### 3.4 Time

Keep distinct:

- occurrence time: when the source says an event happened;
- stated validity: the situation or interval a claim concerns;
- receipt time: when Eliot obtained it;
- editorial revision time: when Eliot changed the stored account.

Preserve unknown precision/timezone instead of substituting receipt time as occurrence. A late import or newly written summary does not become the newest world state. A real A→B→A sequence creates a new A occurrence; it is not deduplicated into the retired first A.

A question about what happened then and a question about what was known then may need different source/editorial revisions. Do not answer the latter by filtering today's heads alone. Use retained history and source handles or state the reconstruction limit; no automatic full historical-world rebuild is required. New information and known dependent-resource changes qualify the affected claims, not every item in the project. Absence of a later event is not proof that a service, file or external condition remained unchanged.

## 4. Episodes and source reconstruction

Use host-native call/result, task/session and parent relationships to group observations. Keep a tool call with its result and observed repair/check.

An episode can be interpreted in finite portions while work continues. New observations enter a pending successor rather than changing the running input. Each stream retains its own intake order. Freeze the selected membership and actual observation segments; a late child result or newly learned parent relationship can add previously uncovered material without reopening every other stream.

Selection, material actually supplied to a recipe, and committed processing coverage are distinct. A token-trimmed body, unexpanded handle or incomplete output does not count as processing the entire source. No-change covers only the completed input/purpose, and rereading earlier context does not add independent support. The concrete range, omission and successor rules are in [Implementation §10.1](IMPLEMENTATION.md#101-episode-input); there is no global processed bit on an observation.

When retrieval finds a compact lesson, optional expansion follows source links to the relevant episode neighborhood:

- preceding cause/action;
- result/error;
- repair/change;
- subsequent check/outcome.

Deduplicate overlapping expansion by source identity. Timestamp proximity across unrelated streams does not create one episode. Missing counterparts remain explicit; available useful material does not wait for a global all-agents-finished barrier.

A source object, its version, and a transformed representation are not one identity. Keep observed rename/copy/export/crop relations with their exact inputs and outputs; inferred continuity remains a hypothesis. Equal names, bytes or embeddings cannot merge objects or establish independent evidence. Old locators open the captured representation, including an actually retained dirty-file range, not a new file reached through a changed path. These are ordinary links and source reads under [Implementation §§3.1 and 4.7](IMPLEMENTATION.md#31-binding-work-without-a-scope-platform), not an object-identity service.

## 5. Project understanding

A project view is a versioned answer to a useful question over an examined scope.

Examples:

- purpose and boundaries;
- subsystem responsibilities;
- consumers of an API;
- why a decision was made;
- failed approaches in an area;
- current discrepancy between intended and observed behavior.

A view records:

- question/purpose;
- examined workspace/resource scope and source revisions;
- answer;
- source handles;
- completeness/gaps.

A list of old cited files does not prove that no new consumer exists. Membership-affecting changes mark the affected view dirty.

Refresh only affected views. Until refresh completes, serve the previous view with its qualification and direct source access. A known refuted part needs its actual correction/limitation, not merely a generic stale label. Checkout-specific views keep distinct addresses; late synthesis cannot overwrite another checkout's answer. Stable project intent can remain shared while implementation views differ.

## 6. Retrieval and context selection

### 6.1 Candidate generation

Generate candidates independently from:

- direct IDs/handles;
- current work address;
- exact cues;
- full-text search;
- compatible vectors;
- claim-group alternatives;
- relevant typed relations;
- project-local methods;
- reusable methods allowed for the current project.

Union candidates before final selection. A lexical-only candidate does not need a vector score. Current-state candidates use known workspace/task selectors before their limit; historical case selection retains original scope rather than presenting another instance's state as current. Exact source access remains available under existing access rules.

### 6.2 Applicability

For a method, evaluate material conditions as:

- applicable;
- inapplicable;
- unknown.

Observed typed values may decide simple conditions. Natural-language uncertainty remains conditional.

Token overlap is not proof. `not committed` does not satisfy `committed`; mentioning `cargo check` is not evidence it ran.

Unknown applicability may produce a conditional suggestion and the missing check. It does not require silence or a permission denial.

### 6.3 Ranking

Rank relevance separately from truth/support.

Useful signals may include exact match, lexical score, vector similarity, recency where appropriate, relation purpose and current task fit.

Scores normalized within one result set are relative order, not calibrated probability.

### 6.4 Relation expansion

Expand a relation only when it supplies missing information: order, consumer, cause, outcome, repair or exception.

Several selected relation types form a union. Intermediate nodes need not repeat query words.

Keep traversal finite by scope, relation purpose, nodes/edges and work budget. Do not scan the whole graph or re-embed unchanged nodes.

A relation about item A at revision 2 does not automatically describe A at revision 3. Current-context expansion and any relation-based ranking use the revision actually read; historical expansion uses the requested old revision. Replacing text does not copy old semantic links into the new account without a stated basis. Reader correctness cannot depend on whether an optional client happened to be initialized earlier in this process.

### 6.5 Packet packing

Pack semantic units:

- current work;
- exact constraints;
- applicable or explicitly conditional methods;
- relevant prior episodes;
- dissent/alternatives;
- unknowns and next checks;
- handles for detail.

Load a selected item's relevant exceptions through its recorded relations before final packing; they do not need their own high retrieval score. Keep the qualification with the claim. Candidate examination budget is larger than final display count. If selected material cannot fit, prefer a concise qualified unit or state the omission with expansion handles; do not make an unconditional recommendation by dropping its exception. The concrete reader/packing order is in [Implementation §7.3](IMPLEMENTATION.md#73-packing).

Display grouping can reduce repeated equivalent guidance without merging stored identities. Compare the actual content and material scope, time, perspective, conditions and exceptions, not a text hash alone. Keep the contributing handles and any distinct qualifications; uncertain equivalence remains separate or explicitly related. A summary can replace detail in this packet only within its represented scope. A relevant exception in a source still accompanies it. Grouping is packet-local, never a new count of independent evidence or a permanent alias redirect.

## 7. Interpretation and revision

A Dreamer interpretation job receives finite observations/source segments, related current items and the selected method revision.

Allowed output:

- create an item;
- update a named item;
- create/update a view;
- add/remove/qualify links;
- identify conflict/unknown;
- keep/no-change.

Application checks:

- parseable shape;
- actual input/target membership;
- current addressed revisions;
- current job claim;
- permitted source route.

These checks do not prove semantic truth. A configured handler may publish ordinary provisional revisions automatically; doing so does not grant permissions or certify external task completion.

A direct structured user correction may update memory without Dreamer.

### 7.1 Consolidate without merging source identities

Use the smallest change that supplies the missing behavior:

| Situation | Operation and consumer |
|---|---|
| Same source event replayed | Existing capture identity returns the prior result; no new evidence or inference. |
| Repeated wording in the current packet | Group compatible guidance under §6.5 while retaining its source handles. No stored-ID merge. |
| New detail about the same addressed claim or method | Revise that item and its conditions; subsequent context/request reads the new revision. |
| Several episodes suggest a broader pattern | Create a separate provisional claim, method or view with links to the exact contributing versions. Sources remain distinct. |
| Existing synthesis conflates different cases | Correct or split that derived account under §7.3; do not delete the underlying episodes. |

The first curation implementation does not union source IDs, rewrite every inbound link to a chosen survivor, or build permanent equivalence classes. A shared hash may shortlist equal text, not establish the same event, object or proposition. Same words about different services or API versions remain distinct. Physical byte deduplication, when provided by storage, changes none of those identities.

### 7.2 Find a useful change from actual content

Start from the changed episode/item and a finite neighborhood selected by exact subject/cues, current claim group, known links and lexical candidates; vectors can enrich that selection. Compare contents and conditions before deciding to keep, revise or synthesize. An input must not require writer-supplied `duplicate_of`, `scope_match` or a preassigned usefulness label to be examined. Known structured equality needs no model; semantic generalization can use the configured curation recipe. Ambiguity may remain a relation or alternative instead of forcing a merge.

Supply relevant source passages and counterexamples to that recipe, not just existing summaries. Its new pattern states the conditions and limits actually inferred. Repetition of one source through several summaries adds no independent support. One useful episode can yield conditional advice; broad effectiveness is not established by many similar sentences. No full-corpus pairwise comparison, mandatory transfer experiment or minimum record count precedes the first useful lesson.

Reuse a known addressed target or the previously saved result for that job/input. Retry preserves created IDs. Later processing can update that item rather than append another paraphrase. Do not claim global semantic uniqueness from these identity rules: independently created similar items can remain candidates for a later focused review, without blocking new capture.

### 7.3 Publish and repair a derived account

A transformation carries the exact input/source versions, addressed edits with expected revisions, stable IDs for creates, and the selected per-output grounds/conditions. These are the existing job result and publication inputs, not a separate merge ledger. Apply one dependent set of creates, revisions, explicit retirements, links and job outcome through the caller-owned transaction in [Implementation §§5.3–5.4](IMPLEMENTATION.md#53-publish_revision). A storage conflict retries that saved proposal; a genuine target change uses the existing reconciliation path. Neither silently repeats the inference.

Synthesizing C from A and B normally adds C; it does not retire A and B. A deliberate retirement names its exact scope and reason. Each output receives only its relevant sources and exceptions. Do not distribute every old link to every split output, carry historical outcome credit onto a different method, or widen reuse scope merely because the new text is more general. Unknown attribution remains a gap. History retains old text and old links; current queries consume the new revision's links. New derived text uses the ordinary lexical/vector maintenance path, not a second entity database to synchronize.

To repair a false synthesis, open its retained inputs and actual correction, then narrow its current revision or create separately scoped outputs and withdraw the erroneous guidance in the same dependent publication. Reuse still-valid original items when possible. If an original has since changed, preserve that later change rather than restoring an old snapshot over it. This is a new corrective revision, not automatic resurrection or a universal undo stack.

A conclusion grounded in the erroneous revision is reconsidered through [Implementation §8.5](IMPLEMENTATION.md#85-reconsider-affected-grounds). A conclusion grounded directly in an unchanged original is not invalidated merely because presentation changed. Unknown dependent mappings are not bulk-rewired to a new output; retain the specific qualification and address them separately. The corrected material is usable without waiting for the whole dependency walk. Exact old handles still open their own retained versions, not a redirected survivor presented as the original.

### 7.4 Required next reader

An implemented curation improvement must reach ordinary context, source expansion or the next selected method request. Successful no-change remains valid and does not require inventing a revision. Fewer preview findings or an applied-action count alone does not establish cleaner recall. Check the same relevant request before and after an implemented change, including the exception and the original sources; this is a product observation, not a new approval gate before provisional use.

Example: A records a failure under API v1, B a successful repair under v2, and C incorrectly says the method always fails. A correction narrows C or replaces it with the two scoped accounts. The next v2 context receives the applicable repair rather than the universal warning; a historical v1 query can still open A. Merely deleting C, hiding a preview row or increasing B's score does not complete that repair. This is a design example, not an executed V3 result.

## 8. Methods and learning

### 8.1 Method contents

A method contains:

- trigger/situation;
- useful action;
- material conditions;
- exceptions/counterexamples;
- expected observation;
- sources;
- origin and reuse scope.

It is eligible for provisional use immediately when appropriate.

### 8.2 Method consumption

A text-interpretation job selects its processing method by implemented purpose and project configuration, not by similarity to arbitrary task advice. First use has a real bundled recipe saved as an ordinary method; it does not need an earlier model call to create the method that permits learning. Initialization, selection and upgrade behavior are defined in [Implementation §10.3](IMPLEMENTATION.md#103-method-consumer).

The claim freezes method ID/revision. The request builder opens that exact body and inserts it into the actual request. New revisions affect later jobs; retries retain the selected method. Encoding uses its provider profile, and deterministic work needs no prompt recipe. A method changes behavior through this consumer, not by being stored or receiving a higher score.

### 8.3 Outcome reduction

For each exact method revision, actual attempt and criterion/checked target, retain one current contribution with sources, offered/delivered facts, observed action, adherence, coverage, result and cost/competing failures. These are an ordinary `memory` outcome and its history, not another outcome store. Native event identity prevents replay duplication; attempt/criterion identity prevents counting two reports about one result as two trials.

A packet establishes what was offered, not which method caused the outcome. Missing association remains unknown; useful raw experience is still retained. An explicit correction replaces the addressed contribution. Unresolved incompatible reports remain disagreement. A no-change reduction adds neither a contribution nor a revision; multiple criteria in one attempt are not independent attempts. A missing diagnostic is success only when a relevant complete check covered the target.

Feedback must reach a consumer. A relevant counterexample accompanies the method in context; materially new feedback may revise that method through the existing interpretation job. The next context/request consumes the revised conditions or recipe. This works for successful repairs and cheaper paths as well as failures. A score update, log entry or new proposal without such a consumer is not the completed learning loop. No experiment or approval is required before showing a useful provisional qualification.

### 8.4 Transfer

Search current-project methods and eligible reusable methods. Preserve origin, disclosure limits and counterexamples.

Transfer can be conditional from one useful case. A claim of broad effectiveness requires later comparable outcomes; it is not a prerequisite for provisional advice.

### 8.5 No-change

A successful no-change completes the job for its exact input and method. Reuse it until relevant inputs/methods change.

Invalid output, missing sources, partial processing and provider failure are not no-change. No-change is not an obligatory agent report after every external action.

## 9. Recursive improvement

### 9.1 Task-local loop

Propose a focused method change, probe it on repeatable or otherwise appropriate work, and compose supported parts or keep the baseline.

Do not repeat irreversible external effects merely to compare candidates.

### 9.2 Cross-task loop

Retain what the comparison taught about improving:

- diagnostic cue;
- attempted change;
- observed contrast;
- conditions and counterexamples;
- reason to reuse or avoid that approach.

Future improvement jobs retrieve applicable lessons. They do not inherit the entire previous task-specific prompt or workspace.

### 9.3 Self-diagnosis

Classify a failure at the first supported step:

1. capture;
2. interpretation;
3. retrieval;
4. delivery;
5. use;
6. applicability;
7. method quality.

Correct the supported step. Do not create more copies of the same lesson when packing was the failure. Do not globally block diagnosis because one earlier repair failed.

## 10. Disagreement and prediction

A disagreement record identifies the question, scope, alternatives, grounds and counterevidence.

Choose the cheapest useful discriminating observation. One source lookup may resolve it. Additional agents are optional and add value only through new evidence or analysis.

A provisional choice records:

- chosen alternative;
- reason;
- unresolved dissent;
- reconsideration condition.

A prediction records the expected observation before action, conditions and the check. Later observations mark hit, miss, partial or unknown.

## 11. Anticipation and attention

An anticipation is a conditional method/claim about a future risk or opportunity.

It becomes ordinary advisory context when its trigger is relevant. Expiry means the warning is no longer automatically surfaced; it does not fabricate the event outcome.

Commitments and unresolved contradictions are memory state. Notification and acknowledgement do not resolve them. Resolution requires the relevant observed event or explicit user decision. A due date passing is not resolution. [Implementation §11.4](IMPLEMENTATION.md#114-commitments-and-attention-without-another-task-manager) connects ordinary commitment records to scoped context and the inbox, independently of optional notifications.

## 12. Research

Research starts from a concrete open question and the currently known material.

Possible results:

- useful answer;
- useful partial answer;
- completed but uninformative;
- acquisition failure;
- no-change on unchanged inputs.

Store findings, alternatives, source handles, examined coverage and gaps. Do not treat an empty sample as universal absence.

New material can reopen a question. Repeating the same uncertainty without new inputs does not.

## 13. Forgetting and correction

Use the operation that matches the reason, not one universal decay score:

| Reason | Change and reader |
|---|---|
| Repeated material crowds a packet | Packet-local grouping/shortening under §6.5; no truth or source mutation. |
| A view is verbose or outdated | Revise the view from retained inputs; preserve material exceptions, open commitments and source handles. |
| Guidance no longer applies in a named situation | Narrow its conditions or withdraw that scoped influence with a reason; context uses the qualification. |
| Owner-selected archival/retention | Change exposure or remove the specified retained data through the existing control path. Archival is not refutation. |
| Material must be erased | Use [Implementation §12.1](IMPLEMENTATION.md#121-deletion); hiding search results is not physical erasure. |

Low use does not lower factual support; frequent retrieval does not raise it. Missing use/outcome telemetry is not evidence of uselessness. Do not erase an uncommon counterexample, unresolved commitment or source needed by a retained explanation merely because its last-access time is old. A model may propose a narrower view or exposure change without gaining authority to purge source bytes. Storage limits and retention remain explicit owner settings, not an invented learned truth threshold.

Negative memory is also revisable. A changed environment or a relevant successful attempt may narrow an avoidance rule; compare the actual action, version and conditions. Passage of time, an unrelated success or disappearance of one diagnostic is not evidence that the original failure is fixed. Preserve that failure episode and its historical warning while current context receives the qualified rule. Eliot does not rerun irreversible actions simply to extinguish a warning.

Ordinary guidance queries honor withdrawal and scope before ranking; explicit history/source inspection can still open permitted archived material without reviving its influence. A transformed summary is a view, not an independent observation. Corrections and splits use §7.3, so the benefit reaches the next reader rather than stopping at a lifecycle label.

## 14. Placement

| Algorithm | Existing owner |
|---|---|
| source capture and episode links | `memory` + `adapters` |
| current-state resolution and grounds | `memory` |
| candidate generation, applicability and packing | `context` |
| interpretation, consolidation/split, methods, outcomes and recursive improvement | `learning`, publishing through `memory`/Store |
| finite work, no-change and successor input | `jobs` |
| model/tool/source execution | `adapters` to controller/research/source tools |
| correction, deletion, backup and direct owner actions | `control` |

No additional WorldModel service, Truth registry, Skill registry, Ontology manager, Learning-state database or cognitive scheduler is required.
