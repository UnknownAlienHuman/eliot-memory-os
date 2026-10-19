# Eliot Memory OS V3 — cognitive mechanisms

**Revision 0.3 · 2026-10-19 · implementation proposal, not working runtime.**

This chapter expands [Implementation](IMPLEMENTATION.md) §§2, 4, 7 and 8. It specifies transformations inside the existing `memory`, `context`, `learning` and `jobs` modules. It introduces no new daemon, database, ontology engine, agent swarm, or approval platform. [Architecture](ARCHITECTURE.md) retains product authority; [Audit §16](AUDIT.md#16-cognitive-audit-03) records the findings and donor limits.

## 1. One useful path and its owners

```text
host supplies a decision frame and admissible events
  -> capture immutable observations
  -> extract proposed meaning off the hot path
  -> reconcile identity, current state and contradictions
  -> compile applicable context from existing memory
  -> host chooses and performs its action
  -> retain the observed outcome
  -> update a local procedure and affected project views
```

`memory` owns observations and semantic revisions; `context` resolves and selects; `learning` reduces outcomes; `jobs` schedules finite transformations. The host/controller owns the actual task, execution and acceptance. The diagram does not require each arrow to be a process or a model call.

A decision frame contains the host task/goal revision when available, current workspace/resource and execution profile, decision purpose, and context incarnation. Fields that the host does not observe remain unknown. The adapter preserves the source of a goal update; a quoted requirement, retrieved document or agent guess cannot replace the user's current goal. A host without task IDs can use an adapter-owned session/task handle and expose uncertain correlation. It must not silently attach all interleaved work to the latest prompt.

Goal state and observed product state are different: "the API must return X" and "the API currently returns Y" can both be accurate descriptions of a discrepancy. Eliot must not reconcile them into whichever sentence was received last. An amended goal starts a new goal revision; old outcomes keep their original criteria.

## 2. Small claim identity, not a fixed world ontology

For a claim eligible for current-state resolution, retain the resolved subject/resource, aspect, value or exact content reference, perspective, scope, validity interval, and source/revision references already required by Implementation. Perspective distinguishes intended behavior, observed behavior and proposed explanation. Source context distinguishes an assertion about the subject from a quotation, example or hypothetical.

The **comparison key** is the necessary scope plus subject, aspect and perspective. For example: one workspace/API symbol, `return_shape`, observed behavior. This is a grouping key, not proof that two sentences mean the same thing. It need not be a universal list of predicates. Deterministic source adapters can supply exact keys; a model proposes semantic identity where needed. Ambiguous identity remains a provisional claim linked to its raw observation. It does not reject capture or create a forced merge.

Keep separate occurrences separate. Two identical failures on different attempts are two events; repeated exports of one event are not. Aliases and renames carry their evidence. Same spelling in another repository, branch or worktree is not the same resource by default. Uncommitted workspace state must not be labelled as identical to committed HEAD.

Do not implement natural-language understanding as an expanding table of personal topics and regexes. Regexes are appropriate for documented machine formats, exact diagnostic IDs and path syntax; they are insufficient evidence that quoted first-person prose describes the speaker. Equally, model interpretation is fallible data, not a privilege to rewrite source identity.

## 3. Resolve current state independently of relevance ranking

Implement `resolve_current` as one ordinary function over an explicitly scoped claim group. The caller supplies the requested time/perspective and source/profile observations; the result contains current alternatives, relevant history, unresolved conflict or missing information, and supporting handles. No model call is required on this read path.

1. Check visibility and allowed influence before considering content. Use only the already authorized comparison key; do not reveal an inaccessible alternative or its metadata.
2. Resolve exact source revisions and distinguish historical evidence from live applicability. Unknown observation time is not receipt time. An old import arriving today does not become today's truth.
3. Apply only validated revision/replacement links for the same comparison key and compatible temporal scope. A model can propose such links; shape validation alone does not make its semantic judgment infallible. A model-resolved view retains that evidential status and cannot silently override contradictory direct evidence.
4. Compare current candidates using the actual source contract: an explicit goal revision controls the intended goal; an exact source observation controls what was observed there. Do not impose a universal authority ranking that lets a code observation rewrite a human requirement.
5. Preserve non-conflicting values where the aspect is multi-valued. Preserve historical intervals when a value changed. Incompatible candidates that cannot be ordered remain a conflict with a proposed distinguishing observation, not a last-write-wins winner.
6. Return the relevant qualification with the selected value. A contradicted item is not a current fact merely because it ranked first in BM25 or vector search.

Retrieval first identifies candidate groups, then this function resolves the groups. Fetch relevant active alternatives/replacements by the indexed group key, not only the semantic top-k. A limit reached while enumerating a group means incomplete resolution. Return that limitation and a continuation handle rather than a confident value. Known constraints and current goal references still have their direct path outside general top-k.

The initial implementation needs an indexed grouping field and ordinary links, not a second "current truth" table with its own writer. A cached projection binds to the examined sources and query membership described below; it is not another authority.

## 4. Project understanding as a small set of revisable views

### 4.1 What the agent actually receives

Use ordinary memory revisions for three scales: project purpose/boundaries, subsystem map, and a selected area card. These are presentation scales, not mandatory storage layers or a card for every symbol. An area card answers: why this area exists; inputs/outputs and neighboring responsibilities; important invariants; relevant good/bad decisions; known gaps; and where to verify the claims.

Exact structure comes from manifests, directory metadata and a selected existing source tool. Meaning and analogies can be synthesized by Dreamer. Preserve the distinction between a documented design, an observed implementation and an inferred purpose. A generated map cannot turn its own inferred purpose into an owner-approved requirement.

On first contact, capture metadata and serve exact known facts immediately. Queue only the orientation work useful for the current task or requested area; expand other areas on demand or in permitted idle work. Do not require full-repository semantic onboarding before the first context response. A large repository can be partially understood without falsely calling its map complete.

### 4.2 Positive references do not detect new members

A view can become stale even when none of its cited files changed: a new API consumer, route, test or plugin may have appeared elsewhere. A list of positive dependencies alone cannot support a claim such as "all consumers are these three files".

Retain the **selection basis** for a set-valued view: the bounded source scope/query, its source-tool revision and examined revision, and whether enumeration was complete. This can be metadata on the existing view/job, not a generic query AST. When source changes can alter membership, mark the view dirty even if the previous matching files are unchanged. Negative claims require a defined and sufficiently examined scope; empty top-k never establishes absence.

Use the source adapter's directory/reference-query change information where available. A missed event, incomplete listing or unavailable provider invalidates the coverage claim, not every historical observation. Reconcile the affected scope; until then show a stale/incomplete view plus still-valid exact facts and handles. A filesystem watcher is a hint, not proof that no change occurred.

### 4.3 Dirty work without a rebuild storm

Use a stable target key such as `(project, area, view purpose)` and the existing job input/profile identity. Keep at most one running finite build and one coalesced pending successor for that target. Events update the desired source input for the successor; they do not restart a running model call forever. A repeated unchanged request reuses a valid result or a recorded no-change decision.

Before publication, recheck source membership, required live anchors, policy and current target revision. A stale build cannot overwrite a newer card. If unrelated inputs changed, do not invalidate unrelated views. Process an affected child before rebuilding a parent that actually depends on its semantic output; a bookkeeping timestamp alone does not force parent regeneration.

Capture, lexical lookup and exact error warnings do not wait for a semantic cluster. A single important failure or explicit unresolved commitment is already useful. Batching is an optimization of interpretation, not a prerequisite for remembering or surfacing a rare event.

A completed no-change decision covers only the examined input set and method profile. New evidence, a revised method or a relevant counterexample can make the target eligible again. Never use one permanent `processed=true` flag to exempt a fact from every future cognitive operation.

## 5. Retrieval cues and the context budget

Attach concrete searchable cues during capture/interpretation: resource IDs, paths, symbols, error codes, command families and explicit task classes. Prefer source adapters' identifiers; generated aliases remain proposed metadata. Do not invent a query that contains a future benchmark answer or treat training annotations as runtime memory.

At read time: bind the decision frame; find exact requirements/negative cases; retrieve candidate groups lexically and, when available, with compatible vectors; resolve current values; evaluate procedure applicability; pack the useful semantic units. Expensive synthesis runs separately. No per-tool LLM classifier is required to choose a known card.

Budget for the decision, not each stored record independently. When a current value is disputed, keep the qualification/counterevidence next to it; do not spend the last tokens on the positive sentence and drop its exception. If mandatory content cannot fit, expose an incomplete packet and the next needed observation. Progressive reveal revalidates both policy and current scope.

Measure bytes/tokens injected, expansions and repeated reconstruction work alongside task outcomes. Total input accounting must include material repeatedly resent with a host transcript where it can be observed. A shorter packet is not automatically a cheaper or more useful workflow. Existing fixed requirements are not removed to win a token metric.

## 6. Applicability before automatic learning

### 6.1 Three-valued matching

A procedure retains a small set of relevant preconditions: operation/task family, resource/API and tool profile where material, scope, exceptions and the observation needed to establish applicability. Use existing typed comparisons rather than a new predicate language. Keep rich semantic preconditions as labelled text when code cannot evaluate them reliably.

| Matching result | Allowed use |
|---|---|
| Applicable | Eligible narrow advisory under existing policy; no new per-record approval |
| Inapplicable | Do not recommend the concrete action in this frame; preserve historical evidence |
| Unknown | Offer the missing check or a clearly conditional hypothesis when useful; do not treat it as an established instruction or an enforced block |

Similarity finds a candidate; it never fills missing preconditions with `true`. A broad lesson such as "inspect the consumer before changing this API" can remain useful when a version-specific repair is inapplicable. The agent's next action still belongs to the host/controller.

A transferred procedure is evaluated in its new scope with permitted source material. New wording or a claimed abstraction cannot declassify private examples. Wider reuse and claims of effectiveness follow Implementation §7.4; this chapter does not silently promote every local advisory to global policy.

### 6.2 First concrete outcome criterion

For the initial API-change example, use a named criterion such as recurrence of the identified compatibility failure under the declared API/consumer and verifier profile. Where capture permits, record whether the relevant definition and consumer were available before the edit. Availability is not proof that the model understood or obeyed them.

Do not use final task PASS as a surrogate for this criterion. A network outage or a failure in an unrelated subsystem does not prove that the API procedure was harmful. Conversely, a different failing criterion cannot be hidden merely because the selected API error disappeared.

Keep adherence, target-criterion outcome and attribution separately qualified. A direct counterexample can narrow an applicable rule; an unrelated or uncorrelated failure remains unassigned. There is no reward spread across every memory item in a packet and no automatic punishment of every delivered procedure.

The comparison key includes procedure revision, task/operation family, relevant source/tool profile and criterion/evaluator revision. Use only the dimensions that change the claim being evaluated. Keep observational support separate from a controlled estimate of benefit. Exact outcome contributions remain unique as in Implementation §7.3; an amended outcome replaces its contribution.

### 6.3 Stopping self-reinforcement and wasted work

A derived summary is not new independent evidence for itself. Re-reading the same episode, regenerating a paraphrase or invoking Dreamer again on the same input cannot increase support. Recompute only when input membership, a relevant source/method profile, an outcome or an explicit request changed.

Do not decay a rarely used invariant or negative case merely because recent activity concerned another area. Limit normal exposure and backlog by usefulness and retention policy; do not confuse lack of retrieval with falsity. Retain a specific reason when a candidate is deferred, superseded or found to add no information.

Cross-domain analogy can propose a more general procedure, but support remains the underlying independent cases. A chain of abstractions does not multiply that support. Restrict candidate search to selected dirty/new procedures and bounded comparable groups before considering an expensive whole-corpus sweep.

## 7. Attention, prediction and cognitive failure

An unresolved contradiction, commitment or observation gap is an ordinary memory item with its relevant task/scope and resolution condition. A new notification, successful delivery or acknowledgement does not resolve it. Close or supersede it using the actual outcome or an authorized goal change, without creating another task manager.

A prediction names the expected observable effect before an action, the conditions and the criterion that can check it. Use configured tool/verifier observations where they exist. Store hit/miss/partial/unknown with the source evidence; no universal causal-graph solver or new expression language is needed. A successful sequence is suggestive evidence, not automatically an intervention-controlled causal result.

## 8. Implementation placement and future walkthroughs

| Existing owner | Small addition |
|---|---|
| `memory` | Comparison-key/perspective metadata, explicit replacement and selection-basis references |
| `context` | `resolve_current`, three-valued procedure applicability, qualified packet assembly |
| `learning` | Criterion-specific outcome reduction and independent-case grouping |
| `jobs` | Target-key coalescing, finite source membership, no-change and successor handling |
| `adapters` | Source/goal provenance, actual changed-scope/query coverage and available action correlation |

No separate `WorldModelService`, `TruthRegistry`, `OntologyManager`, `LearningStateView` or cognitive scheduler is required.

| Case | Required behavior |
|---|---|
| An old event is imported after a newer correction | Receipt time does not restore the old value as current |
| Same symbol name exists in two worktrees | Resolve inside the bound workspace, not by name alone |
| Documentation requires X; code currently does Y | Preserve intended and observed views and their discrepancy |
| Two authoritative claims cannot be ordered | Expose conflict and a discriminating check, not a ranking winner |
| Relevant alternative lies outside semantic top-k | Keyed resolution fetches it, or marks enumeration incomplete |
| A new consumer appears without edits to cited files | Selection-membership change makes the view dirty |
| Many edits arrive during one Dreamer build | Keep one finite running build and one coalesced successor |
| One rare severe failure has no semantic neighbors | Preserve and surface it without waiting for a cluster |
| A quoted first-person example arrives in a user message | Preserve its role; do not turn it into the user's state |
| A procedure's profile is missing | Return conditional advice/missing check, not an asserted match |
| A delivered procedure co-occurs with unrelated failure | Do not assign causal harm without a matching criterion |
| The same summary is repeatedly summarized | No new independent support or unbounded self-triggered jobs |
| Goal changes between attempts | Keep original outcomes/criteria; reconstruct the new goal explicitly |
| A card is stale and its model route is down | Still serve valid exact observations with visible coverage gaps |

These are documentation walkthroughs, not an executed V3 test suite.

## 9. Source decisions

- [V1 current-value resolution, §4.12](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Canonical_Master.md#412-deterministic-current-value-resolution): preserve scoped deterministic resolution, not its old DTO hierarchy.
- [V1 Understanding Layer mission and principles](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Understanding_Layer_Engineering_Task_v1_4.md#L14-L120): preserve reconstruction, cues, small views and dirty tracking; reject claims that injection proves use or that every cognitive write must await complete cue classification.
- [DCPM, 2606.09483v1, §§2.2–2.5](https://arxiv.org/html/2606.09483v1): use revision trajectories and offline abstraction as mechanisms. Its cognitive hierarchy is not a required process hierarchy; its cross-domain sweep has quadratic pair comparisons. QA/personalization results are not evidence of causal improvement on coding work.
- [Hy-Memory optional canonical-state helpers](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/system2_agent.py#L72-L346): a source-backed counterexample to topic-specific regexes as general understanding. The branch is disabled by default in the inspected source; the isolated helper accepts quoted/example first-person equipment text. This is not a reproduced deployment failure.
- [Hy writer paper, 2610.22196v1, §5.3](https://arxiv.org/html/2610.22196v1): two preceding chunks describe reward annotation context, not a universal production-writer requirement. Keep pipeline parameters justified by their actual purpose.
- [LongMemEval, 2410.10813v2, §3.2](https://arxiv.org/html/2410.10813v2): knowledge update, temporal reasoning and abstention must be evaluated separately. This motivates failure categories, not importing benchmark user-attribute ontologies into Eliot.
