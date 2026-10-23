# Eliot Memory OS V3 — Cognition

**Revision 1.0-draft.2 · 2026-10-23 · normative algorithms used by the V3 implementation.**

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
- **unknown** — an explicit missing fact or unresolved relation.

A source event, search chunk and episode are different. Search chunks help locate material; they do not replace the source or define the task.

## 2. Decision frame and current work

The decision frame contains available project, workspace, task, session, branch, goal, criteria, selected resources, execution profile and context incarnation.

Current work is reconstructed in this order:

1. open the addressed task/session/branch continuation;
2. read relevant observations outside its per-stream/segment coverage, including retained material newly associated with this work;
3. apply explicit goal/plan corrections;
4. preserve abandoned alternatives and open commitments;
5. only then retrieve similar prior work.

If no task identity exists, use the narrowest known session/workspace continuation. Do not attach interleaved events to the latest prompt merely because it is latest.

A continuation revision contains:

- active goal;
- current plan;
- completed actions/results;
- abandoned approaches and reasons;
- open commitments/unknowns;
- next useful step;
- represented streams and observation IDs/segments or exact ranges, source handles and gaps.

A summary never replaces the original observations. Reading a tail is not publishing a new summary or proving that every stream was processed.

## 3. Claim identity and current-state resolution

A comparison group uses the minimum useful identity:

- scope;
- subject/resource;
- aspect;
- perspective;
- relevant time.

Perspective distinguishes intended behavior, observed implementation and proposed explanation.

`resolve_current(group, decision_time)`:

1. load accessible alternatives and relevant revisions outside semantic top-k;
2. apply validity intervals and explicit replacements;
3. preserve alternatives whose conditions differ;
4. evaluate compound grounds when explicitly represented;
5. return current alternatives, conflict or unknown;
6. include qualifications and history handles.

Last write, highest similarity, retrieval frequency and model confidence are not universal authority rules.

### 3.1 Replacement

Prepare a proposed replacement outside the transaction. Publish new revision, revision-specific grounds, scoped retirement and job result atomically.

A failed publication leaves the prior committed state intact. Competing replacements revalidate the current revision.

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

Preserve:

- occurrence/validity time;
- receipt time;
- revision time.

A late import of old evidence does not become the newest world state. A real A→B→A sequence creates a new A occurrence; it is not deduplicated into the retired first A.

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
- examined source scope and revisions;
- answer;
- source handles;
- completeness/gaps.

A list of old cited files does not prove that no new consumer exists. Membership-affecting changes mark the affected view dirty.

Refresh only affected views. Until refresh completes, serve the previous view with its qualification and direct source access. A known refuted part needs its actual correction/limitation, not merely a generic stale label.

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

Union candidates before final selection. A lexical-only candidate does not need a vector score.

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

### 6.5 Packet packing

Pack semantic units:

- current work;
- exact constraints;
- applicable methods;
- relevant prior episodes;
- dissent/alternatives;
- unknowns and next checks;
- handles for detail.

Preserve material exceptions. Candidate examination budget is larger than final display count. If selected material cannot fit, state what was omitted and provide expansion handles.

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

These checks do not prove semantic truth.

A direct structured user correction may update memory without Dreamer.

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

A model-based job selects its processing method by implemented purpose and project configuration, not by similarity to arbitrary task advice. First use has a real bundled recipe saved as an ordinary method; it does not need an earlier model call to create the method that permits learning. Initialization, selection and upgrade behavior are defined in [Implementation §10.3](IMPLEMENTATION.md#103-method-consumer).

The claim freezes method ID/revision. The request builder opens that exact body and inserts it into the actual request. New revisions affect later jobs; retries retain the selected method. Deterministic work needs no model recipe. A method changes behavior through this consumer, not by being stored or receiving a higher score.

### 8.3 Outcome reduction

For each exact method revision, actual attempt and criterion/checked target, retain one current contribution with sources, offered/delivered facts, observed action, adherence, coverage, result and cost/competing failures. These are an ordinary `memory` outcome and its history, not another outcome store. Native event identity prevents replay duplication; attempt/criterion identity prevents counting two reports about one result as two trials.

A packet establishes what was offered, not which method caused the outcome. Missing association remains unknown; useful raw experience is still retained. An explicit correction replaces the addressed contribution. Unresolved incompatible reports remain disagreement. A no-change reduction adds neither a contribution nor a revision; multiple criteria in one attempt are not independent attempts. A missing diagnostic is success only when a relevant complete check covered the target.

Feedback must reach a consumer. A relevant counterexample accompanies the method in context; materially new feedback may revise that method through the existing interpretation job. The next context/request consumes the revised conditions or recipe. This works for successful repairs and cheaper paths as well as failures. A score update, log entry or new proposal without such a consumer is not the completed learning loop. No experiment or approval is required before showing a useful provisional qualification.

### 8.4 Transfer

Search current-project methods and eligible reusable methods. Preserve origin, disclosure limits and counterexamples.

Transfer can be conditional from one useful case. A claim of broad effectiveness requires later comparable outcomes; it is not a prerequisite for provisional advice.

### 8.5 No-change

A successful no-change completes the job for its exact input and method. Reuse it until relevant inputs/methods change.

Invalid output, missing sources, partial processing and provider failure are not no-change.

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

Commitments and unresolved contradictions are memory state. Notification and acknowledgement do not resolve them. Resolution requires the relevant observed event or explicit user decision.

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

Reducing exposure changes selection, not truth.

Withdrawing influence stops guidance but preserves permitted history.

Superseding/refuting publishes a reasoned revision.

Erasure removes the defined controlled scope and derivatives. It does not claim to recall external copies.

Compression must preserve material exceptions, open commitments and source handles. A summary is a view, not an independent observation.

## 14. Placement

| Algorithm | Existing owner |
|---|---|
| source capture and episode links | `memory` + `adapters` |
| current-state resolution and grounds | `memory` |
| candidate generation, applicability and packing | `context` |
| interpretation, methods, outcomes and recursive improvement | `learning` |
| finite work, no-change and successor input | `jobs` |
| model/tool/source execution | `adapters` to controller/research/source tools |
| correction, deletion, backup and direct owner actions | `control` |

No additional WorldModel service, Truth registry, Skill registry, Ontology manager, Learning-state database or cognitive scheduler is required.
