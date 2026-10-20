# Eliot Memory OS V3 — cognitive mechanisms

**Revision 0.15 · 2026-10-20 · implementation proposal, not working runtime.**

This chapter implements [Architecture](ARCHITECTURE.md) inside the modules of [Implementation](IMPLEMENTATION.md). Revision 0.15 adds targeted relation expansion and distinguishes working-context continuation from durable learning. [Audit §29](AUDIT.md#29-magma-and-letta-relations-and-continuation-015) separates the inspected MAGMA/Letta mechanisms from these Eliot choices; the [map](AUDIT-MAP.md) records coverage. Existing storage, retrieval and jobs own the changes; no new service or approval stage is introduced.

## 1. One useful path and its owners

```text
host goal and observed events
 -> preserve source observations
 -> propose meaning off the hot path
 -> reconcile current claims and relevant history
 -> assemble applicable context
 -> host chooses and performs an action
 -> retain the observed outcome
 -> update procedures, project views and improvement experience
```

`memory` owns observations/revisions, `context` selects and resolves, `learning` reduces outcomes, `jobs` schedules finite transformations. Actual task execution and acceptance stay in the host/controller. An arrow is not a new process or mandatory model call.

The decision frame carries available goal/task revision, workspace/resource, purpose, execution profile and context incarnation. Unknown host fields remain unknown. Interleaved work is not all assigned to the latest prompt. Quoted requirements and retrieved text do not replace the user's goal. Intended behavior and observed implementation may disagree without either observation being erased.

A source event, a search chunk and a working episode are different units. Split a large log or document with ordinary source-aware text utilities when indexing needs smaller inputs; retain the original event and chunk order. This does not require a generative model or establish a new task boundary. Group useful work from available host session/task/call links and turn boundaries, keeping a tool call with its result and later repair where observed. An ongoing episode can be interpreted in finite portions; it need not wait for formal task completion. Refine ambiguous semantic grouping later when useful, rather than installing a compulsory episode-classification stage before capture or recall.

## 2. Small claim identity, not a fixed world ontology

Group a claim by the necessary scope, subject/resource, aspect and perspective. Retain content or exact value reference, applicable time and sources. Perspective separates intended behavior, observed behavior and proposed explanation; source context separates assertion, quote, example and hypothetical.

The comparison key locates candidates, not proof of equivalence. Exact source adapters can provide it; models can propose uncertain semantic aliases. Ambiguous meaning stays linked to the raw observation rather than rejecting capture or forcing a merge. No universal predicate catalogue is required.

One lesson can have several retrieval entrances: a resource cue, a topic label, an area view and a meaningful related-note link. They point to its ordinary identity, not to separately copied lessons. Updating the lesson therefore updates what each entrance opens. Navigation labels and inferred recall clues remain separate from the underlying observation; a hierarchy of materialized paths is not required.

Continuing a task can update its progress summary; it does not supersede every fact or exception from the preceding session. A replacement identifies the claim/aspect and temporal scope it changes. Silence about an old condition is not evidence that it ended. Independent identical occurrences remain independent; repeated exports of one occurrence do not. A job can produce several distinct lessons. Its ID groups processing, not semantic identity. Update a named lesson by its own ID/revision; do not collapse different conditions merely because two lessons share a job or a similarly worded core. Count distinct source episodes, not repeated references in one batch.

Keep original source spelling separate from comparison forms. Same symbol name in another worktree is not the same resource. Do not label dirty workspace state as committed HEAD. Regexes fit documented machine fields and diagnostics, not a growing catalogue of personal topics: a quoted first-person sentence is not necessarily the speaker's state.

## 3. Resolve current state independently of relevance ranking

`resolve_current` is one ordinary function over an explicitly scoped claim group. It returns supported current alternatives, relevant history, conflict or unknown, with the corresponding source handles.

1. Consider only accessible content with the appropriate influence; hidden alternatives are not leaked as metadata.
2. Resolve time and perspective. Receipt time does not make an old import current; historical evidence is not an expired live dependency.
3. Apply supported replacement/revision links within the comparison group and their stated interval. A model proposal retains its evidential limits.
4. Use actual source semantics: a user goal defines intent, a code observation describes code. Do not invent a universal authority ranking that lets one rewrite the other.
5. Keep non-conflicting multiple values. Preserve unresolved incompatible alternatives instead of choosing a last writer or highest vector score.
6. Return qualifications with the selected claim. Incomplete enumeration is not a confident singleton result.

Retrieval finds groups; indexed lookup then fetches relevant active alternatives and replacements outside the semantic top-k. Limits return partial resolution and continuation handles. Goals and exact constraints retain a direct path. A cache binds to examined source revisions and membership; it is not another current-truth writer.

For changing state, preserve both when the source says the state applied and when Eliot learned of it. Contradiction candidates may concern the same subject/aspect with a different value or target: a database migration cannot be found by searching only the new subject–target pair. Equal text is not necessarily the same occurrence; a real A→B→A sequence needs the new A interval, not reuse of a retired A merely because its wording matches. Known dates can order the affected history with ordinary comparisons; unknown dates do not prevent storing or recalling qualified knowledge.

### 3.1 Publish a replacement as one memory change

Prepare content and optional summaries outside the transaction. In the existing memory write transaction, recheck relevant predecessors, group/time, current inputs and job; publish the new revision, required links, scoped retirement, necessary follow-up jobs and readback result together. A failed commit leaves the preceding committed state intact. A lost acknowledgement uses the same mutation identity.

Never retire the only active value, wait for a model, then insert its successor. Optional history synthesis or embedding cannot make primary preservation dependent on model availability. New revisions remain exact/lexically accessible while an index is pending. Concurrent replacement proposals revalidate the changed group; slower arrival is not permission to overwrite a new head.

### 3.2 Withdrawal does not resurrect a retired value

After A→B, refuting, hiding or erasing B does not prove A current again. Preserve permitted scoped retirement/validity in the ordinary revision history, including export. Return remaining justified alternatives or unknown/conflict. Reinstating A's value needs fresh evidence or an explicit correction of the earlier replacement, not an index rebuild or Doctor action.

An uncommitted attempted replacement is different: it never retired A. If erasure cannot retain enough permitted transition metadata, resolution stays unknown until fresh admissible evidence exists; do not reconstruct deleted material or expose hidden alternatives.

### 3.3 History can have several predecessors

Follow all relevant permitted predecessor edges using a visited set and bounded frontier. Bound nodes/edges and expose remaining branches, missing sources or cycles. Selecting one predecessor by time at each step silently loses a merge branch; a depth limit does not detect omitted siblings.

Chronological presentation does not change the graph into a chain. Shared ancestors count once, distinct branches remain distinct. A partial history can be useful when labelled partial; it cannot establish complete premises for a replacement. Ordinary indexed links and traversal suffice.

## 4. Project understanding as a small set of revisable views

### 4.1 What the agent receives

Use memory revisions for project purpose/boundaries, a subsystem map and a selected area card. These are scales of presentation, not a mandatory layer or card for every symbol. An area card explains purpose, input/output, neighbors, invariants, relevant decisions, known gaps and where to check them.

A useful view can be a saved answer to a recurring question: “How does this subsystem work?”, “What decisions govern this API?”, or “Which approaches failed here?”. Store the question, examined scope, answer and source handles in that ordinary view. Read the available answer and refresh it through existing jobs when relevant material changes; do not generate a fresh report on every request or require a card for every resource. An explicit user request or a repeatedly useful task question can justify the view without a manual curation ceremony.

Structure comes from manifests and existing source tools; meaning and analogies may use Dreamer. Documented intent, observed implementation and inferred purpose stay distinguishable. Do not turn a generated explanation into an owner-approved requirement.

Serve available exact facts immediately on first contact. Build the useful task/area orientation and expand other areas on demand or permitted idle work. Full-repository onboarding is not a prerequisite for the first context response.

### 4.2 Positive references do not detect new members

A map of all consumers can become stale when a new consumer appears, even if every old cited file is unchanged. Retain the selection basis of a set-valued view: examined scope/query, relevant source-tool and source revision, and completeness. This is view metadata, not a query AST.

Membership-affecting changes, missed events and incomplete listing invalidate the coverage claim for that view. Reconcile the affected scope while retaining valid historical observations and exact facts. A watcher is a hint, not proof that nothing changed. An empty top-k does not establish absence.

Relevant change includes correction and removal, not only a newer insertion timestamp. Reuse the application's existing mutation/source-change events to refresh affected views, including changes to sources that the view actually read. No separate freshness service or synchronous proof is required. A failed refresh leaves the last useful qualified view and direct source lookup available; it does not disable ordinary memory.

### 4.3 Dirty work without a rebuild storm

Use a stable target such as project/area/view purpose. Keep one finite running build and one coalesced pending successor for that target in the existing queue. Changes update the successor instead of repeatedly aborting paid work. Reuse a valid unchanged result or no-change decision.

Recheck relevant source membership, target and restrictions before publication. A stale result cannot overwrite a newer view. Rebuild parents only when a material child result changed; bookkeeping timestamps alone do not regenerate the whole pyramid. A completed decision covers its actual input/method, not every future use of those facts.

A single important failure or commitment is already useful. Exact capture and warning delivery do not wait for a semantic cluster. Batching saves interpretation cost; it is not permission to forget rare events.

## 5. Retrieval cues and the context budget

Use concrete resource IDs, paths, symbols, diagnostic codes, command families and task classes from actual sources. Proposed aliases do not supply authority or future benchmark answers.

Bind the decision frame; find exact constraints/negative cases; retrieve independent lexical/vector candidates; resolve claim groups; check procedure applicability; pack semantic units. A synchronous per-tool LLM classifier is unnecessary. Rich synthesis runs as separate work.

Keep counterevidence and limiting conditions next to the claim. When essential material cannot fit, expose the incomplete packet and useful expansion/check rather than dropping only the inconvenient exception. Revealed handles recheck current scope and availability.

Measure injection, repeated transcript input and reconstruction effort alongside outcome. Shorter text is not automatically less total cost. Do not withhold an explicit user requirement to improve a token metric.

### 5.1 Independent candidates, not a dense-only lexical reranker

Exact and lexical arms query eligible primary data without prior ANN admission or a dense-score threshold. Merge IDs afterward and retain each arm's origin. A lexical-only hit can remain useful when vectors are absent. Incompatible score scales are not directly compared as if they meant the same thing.

Source-derived exact values need a searchable path; preservation in hidden details is insufficient when the relevant record cannot first be found. Use bounded cues, native lexical lookup and explicit source-neighborhood expansion/search, not embeddings of every raw log. Report uncaptured/unindexed scope rather than universal absence.

The [SurrealDB reference](https://surrealdb.com/docs/learn/data-models/vector-search/similarity-search) describes filtered vector plans and index-assisted prefiltering; [EXPLAIN](https://surrealdb.com/docs/reference/query-language/clauses/explain) exposes actual plans. Inspect the selected server/schema/query before adding a workaround. Supported predicates do not prove complete semantic recall or application source validity.

### 5.2 Select useful candidates before packing

Read searchable current records and the relevant history, not a fixed oldest prefix of physical records. A later lesson or correction must remain discoverable after the corpus grows; direct ID lookup must not depend on a whole-project scan. Page broad enumeration with the existing Store.

Keep candidate examination separate from the final packet budget. When high-ranked candidates are unsuitable, consider the next candidates within the request's normal work budget, then pack the useful results. Three displayed items does not mean inspect only three before applicability. A stopped scan describes its examined scope; it does not prove that the entire memory contains nothing useful.

Useful related notes join the candidate set before the final packet selection; appending them after a full top-k list and truncating that list again would make the links ineffective. Retain the relation's reason and qualifications, not an all-to-all similarity mesh. Rank fusion and optional reranking order this union. A score divided by the best score in that particular result set is relative ordering, not a calibrated probability of relevance, truth or applicability; the best of a weak set can still score 1.0.

Use available task facts and concrete cues without requiring a complete TaskMeaningFrame. Filled form fields do not prove understanding or the absence of useful experience. Explicit memory requests, relevant resources and recent corrections remain direct retrieval inputs. Optional semantic ranking can improve selection, but ordinary recall does not wait for a model to certify it. A short follow-up such as “continue” uses the available active goal, selected resources and nearby original turns rather than searching only that word or invoking a mandatory query-rewriting agent. Keep the latest request when shortening this context; avoid recycling previously injected memory as the new query's evidence.

Read relevant lessons independently of project-map preparation. An unavailable map does not turn stored episodes into an empty experience set. Ordinary context includes useful provisional methods with their qualifications; a comparison or certification mode is not the route required to see newly learned advice. Evaluation controls may deliberately hide memory for an experiment, but must not decide normal product exposure.

A selected method must contribute something the agent can use: the proposed action and its material condition or exception, plus a handle for details. A list of skill IDs, scores and verifier names alone is not a delivered procedure. Expand the actual saved record through the existing `open` path when needed; inspection must not fabricate a demonstration card for the requested ID. Estimate the text actually sent, rather than charging the full administrative record and then returning only its ID. No separate skill-delivery service is needed.

### 5.3 Recover the episode, not just the matching fragment

A short fact, cue or summary is a search entrypoint, not a replacement for its source. When the decision needs an example or explanation, follow its source handle to the actual episode and a small relevant neighborhood. A matching failure may need the following repair and check, not only the preceding conversation. Use episode/session order and available action/result links; nearby timestamps across unrelated work do not create one story.

Deduplicate overlapping expansions by source identity and preserve their order. Rank the useful episode context when a reranker is already available; ordinary source expansion does not require one. Deliver the compact lesson first when sufficient, and expose the episode through existing `open`/context expansion when useful. Native queries and existing source links implement this; no second episodic store or dedicated context-expansion service is needed.

### 5.4 Recall clues without a mandatory navigation ritual

An orientation view can include the useful current answer and a few related handles with short descriptions of when their detail matters. “When changing this API's return type” explains a reason to open a consumer-repair lesson; it is not a permission rule or a condition that must be proven before reading. The same lesson can be reached from the API, a failure code or a project-area view without copying its text into each location.

Use normal context selection to surface relevant clues, then existing `open` for detail. The agent need not guess an exact URI, read a complete tree or perform a compulsory boot/read-confirm sequence before work. Missing a clue never prevents raw capture or direct search. The useful rendering is plain content and links, not a second memory hierarchy or a model call per navigation step.

### 5.5 Expand the relation that supplies missing information

Start with ordinary exact/lexical/vector candidates. When an answer needs order, a consumer, an explanation or an outcome, follow the corresponding existing typed relation from those records. Select actual types, subtypes and direction with a normal indexed query; several requested types form a union, not mutually exclusive classifier branches. A useful direct answer does not require graph traversal or a model-selected query plan.

An intermediate node can matter because of the relation even when it does not repeat the question's words. Do not make every hop pass an exact-word or monotonically increasing similarity test. Keep the expansion finite through the relevant scope, purpose and existing work budget; do not compensate by scanning all nodes or links. Reuse stored compatible embeddings for unchanged content instead of encoding every visited node again. No second graph store or in-memory mirror is required.

Pack the useful connection with its qualification: question/answer, failure/repair or claim/exception. Expansion that is appended behind an already full list and cut off again does not reach the agent. A compact explanation with source handles can suffice; no fixed quota of graph nodes is mandated. An inferred causal link retains its status as an explanation, not an observed causal proof.

### 5.6 Continuation is not durable learning

A continuation view answers what the current work is, what actually happened, what remains open and which source handles recover important detail. Preserve the user's goal, relevant exact identifiers, recent corrections and pending action/result distinctions. It can summarize an older portion while recent source events remain available; mark partial material rather than inventing the omitted middle. This uses the existing project/session view, not a second task database.

The host/controller owns its conversation window and compaction. Eliot supplies useful continuation/context at supported boundaries; it does not run another independent host transcript eviction mechanism. Its own captured source events remain the basis for later lookup and interpretation. A summary is a derived representation of those events, not a fresh observation or additional support for a lesson.

Durable learning asks what will help another suitable attempt. It may use the relevant original slice and current methods through an existing Dreamer job, but neither every compaction nor every continuation requires another reflection. Explicitly re-examining an old slice can improve an analogy without counting the slice again as independent experience. A known changed episode does not require a separate model to select it from every conversation in the archive.

## 6. Applicability before automatic learning

### 6.1 Three-valued matching

A procedure retains only material preconditions: task/action family, relevant API/resource/tool profile, scope, exceptions and how a missing condition could be observed. Existing typed comparisons are enough for simple cases; uncertain semantic conditions remain labelled text rather than a new predicate language.

| Result | Use |
|---|---|
| Applicable | Eligible advisory under current configuration, without per-record approval |
| Inapplicable | Do not recommend that concrete action here; retain its historical evidence |
| Unknown | Offer a conditional analogy or useful missing check; do not present it as established or enforce a block |

Similarity finds a candidate; it does not supply missing preconditions. Token overlap is not a truth test: “transaction not committed” does not satisfy “transaction committed”, and mentioning “run cargo check” is not its result. Keep versions and negation intact. Use observed typed values when available; an unobserved natural-language condition stays conditional rather than being classified as false from absent words. Neither unknowns nor requested checks are positive evidence. This calls for useful qualified advice, not a general predicate prover or a model call before every tool. A general method such as checking a consumer before changing an API can survive the loss of a version-specific repair.

Provisional transfer to another permitted situation can be automatic. Applicability, allowed disclosure and demonstrated benefit are separate questions. Independent comparative evidence is needed for a broad effectiveness claim, not for every useful conditional suggestion. A more abstract formulation does not declassify its private source material. See Implementation §7.2.

### 6.2 First concrete outcome criterion

For the API example, compare recurrence of the named compatibility failure under the relevant API/consumer and verifier profile. Where observable, retain whether the definition and consumer were available before editing; availability is not proof that the model understood them.

Do not use final task PASS as the only criterion. An unrelated network/subsystem failure does not prove the procedure harmful. Conversely, disappearance of this diagnostic must not hide another real failure.

Absence of a diagnostic is not a pass if the check stopped earlier, skipped the consumer, examined another revision or produced incomplete output. Retain target/profile, necessary coverage and result completeness in the existing outcome. Distinguish supported pass, supported failure, inconclusive attempted check and unobserved check. A captured matching failure can support that criterion without asserting that all other checks completed.

A deliberately negative diagnostic probe is not automatically a forbidden action. Preserve tool outcome and costs even when its implication for the procedure is unknown. Separate adherence, criterion outcome and attribution. One packet's task reward is not distributed to every item.

The comparison uses procedure revision, relevant task/source/tool conditions and criterion/evaluator revision. Amended results replace the corresponding unique contribution. Ordinary outcome fields implement this; no evidence-schema platform is needed.

### 6.3 Stopping self-reinforcement and wasted work

The same episode, a paraphrase and a summary of that summary are not independent evidence. Recompute when relevant input membership, method, outcome or explicit request changed. A service timestamp or read does not itself create new cognitive work.

Do not feed Eliot's injected context back as a fresh observation to interpret. The adapter knows what it inserted: preserve a reference to that delivery where useful, but exclude the copied block from new learning input. When importing an exported transcript, use its origin/role metadata or the adapter's own explicit markers rather than a semantic classifier that tries to delete vaguely similar text. Keep new user corrections, newly observed tool results and the agent's subsequent report with their actual provenance. A human quotation or a model paraphrase is not automatically independent corroboration; this rule prevents mechanical echo, not every possible mistaken attribution.

Rarely retrieved invariants and negative cases do not become false from inactivity. Exposure and retention may change without rewriting support. Cross-domain abstractions retain the underlying independent cases, not a multiplied count of intermediate links.

### 6.4 Cross-domain induction without forced unification

Find a useful correspondence for a future decision, not a universal rule for every nearby record. Outputs are ordinary analogies, proposed procedures/revisions, justified links or no-change. Original episodes and scoped procedures remain addressable.

A similarity edge suggests a pair; a connected component groups candidate work. Neither proves common conditions or mutual equivalence. Do not replace this mistake with mandatory expensive clique proofs. Inspect the actual relations proposed within a finite group; a result can use a subset, preserve alternatives or find no generalization.

Before attaching a case to an existing method, compare the relevant action/effect, uncertainty, conditions, exceptions and outcome. Exact structured correspondence needs no model; unresolved semantic correspondence can receive bounded interpretation. With several existing generalizations, choosing the first set element is not a policy. Sorting IDs fixes order, not meaning.

Shared sources and high cosine do not make two texts equivalent. One episode can contain competing rules and exceptions. Deduplicate actual replay or supported equivalence; otherwise retain the distinction. Carrying source IDs while discarding the important condition is not lossless compression.

Transfer maps relevant roles and conditions rather than merely removing domain nouns. Retrying a read-only request differs from replaying an unknown external effect. The useful abstraction names that distinction and readback where needed, not “always retry timeout”. Keep the concrete source repair beside the conditional analogy. Do not invent a psychological profile when an engineering method is the useful object.

Publish interdependent changes through the existing memory transaction and job result. Missing required links cannot be called a completed transformation; an independent valid subset must be explicitly partial. Navigation links do not become positive evidence just by existing. Conditional low-risk advice remains automatic; it does not silently become a host prohibition or new disclosure permission.

### 6.5 Bound the whole induction, not only its first query

Use one finite source-ID/revision set for the job's detail reads, feature lookup and prompt. A later “all records with vectors” query cannot silently replace it. Recheck current restrictions at actual dispatch/publication.

An opaque ID is not source content. Hydrate permitted selected records, defer the affected result, or accurately reduce the input while accounting for omitted scope. Partial work is valid; invented evidence is not.

Bound nodes, examined pair/neighbor work, loaded data, prompt and output links. A limit on the first query does not bound a later all-corpus matrix or all-to-all links. Start with existing indexed retrieval and finite candidates; small exact pair comparisons are also reasonable. No second vector engine or per-observation cross-domain sweep is required.

Continue remaining scope using the same job mechanism, a stable cursor or explicit next membership. Do not mark unexamined sources processed or repeatedly serve only the first page. New inputs belong to a coalesced pending successor, not endless cancellation of paid inference.

### 6.6 Reuse no-change and version derived features

A successful “no useful generalization” completes the job for its examined inputs/method. Unchanged triggers reuse it. New evidence, revised method, material counterexample or explicit re-evaluation can reopen work. This is not a new negative-result store or a permanent exclusion of an observation from every purpose.

No-change differs from invalid output, missing sources, partial scope and provider failure. An empty successful result does not need a semantic revision just to report activity. A missing parsed response or a context-limit error does not establish successful interpretation. Keep the reason on the existing work item and retry an appropriately smaller or corrected input when useful; do not block raw capture or unrelated recall. If independent interpretations are deliberately separate, completion of one does not mark all purposes complete. This is ordinary job progress, not another evidence ledger.

Optional abstract/behavioral features reuse existing derived-content and embedding identity: bind derived text to its actual sources/abstractor, then its vector to text revision and encoder. A bare `has_feature` Boolean does not establish compatibility. Changing the abstractor need not re-embed unchanged original memory.

Start with existing lexical/vector procedure retrieval. A second representation is optional, justified by useful missed transfers and its recurring cost, not a mandatory model call per observation. Edge counts and abstraction depth are not intelligence metrics.

### 6.7 Two recursive loops from Harness2

**Donor D44:** [Harness2 at 1cfe254e](https://github.com/google-research/harness2/tree/1cfe254e8d25b15f37048c3730134686abe60335). Reuse its mechanism, not its Python benchmark engine, filesystem library or fixed rollout quota.

**Task-local loop — Propose, Probe, Compose.** Select a concrete weakness from existing traces and a method revision. Propose a focused change; when useful, compare general execution practice and domain-specific practice separately. Probe under matching material conditions through the controller or a local pure-function comparison. Inspect actual changed behavior and delivered result, not just the new instruction text. Compose supported parts, revise conflicts or keep the baseline. Record the chosen revision, contrasting attempts, reason and limitations.

The first implementation can use one relevant proposal rather than unconditionally requesting both donor proposal roles. Parallel alternatives and sequential refinement are optional uses of the same finite job mechanism. Success means the named transformation/observation occurred, not that an improver response existed. A chosen candidate may remain provisional. Early no-change, insufficient informative evidence or exhausted permitted work can end a cycle without producing a compulsory lesson.

**Cross-task loop — learn how to improve.** After the local cycle, retain a memory procedure describing the diagnostic cue, change attempted, observed contrast, conditions/counterexamples and why to reuse or avoid that improvement approach. Link the chosen method/artifact revision and underlying attempts. Future Dreamer work retrieves these lessons to choose better proposals, probes and composition, rather than only retrieving the previous task's answer.

Keep the improvement recipe and criteria stable during a comparison. Update its reusable lessons afterward. The next task starts from its appropriate current baseline and selectively reuses applicable material; it does not blindly inherit every previous task-specific prompt, script or exception. The loop changes external memory/methods, not model weights or the user's goal.

**Smaller than the donor.** `memory` stores method and improvement-lesson revisions; `learning` reduces observations; `jobs` holds finite progress; controller executes model/harness work. Use existing IDs and source handles, not a second library database, task graph, reflection scheduler or agent for every recursion level. Pure replay/copies and suitable local calculations are cheap probes. Real irreversible external actions are not repeated simply for a better comparison.

The donor's published task experiment counts 4k rollouts and 3k improvement stages, with selection/reflection and retries separately accounted. Those are experiment conventions, not a production duty to spend that amount. Count all actual Eliot/controller work and preserve no-change reuse. Do not rerun the full harness whenever a cheap memory comparison is sufficient.

The inspected donor final-selection pool excludes reference executions, although a composition itself can preserve its input tree. Eliot keeps the actual baseline/no-change eligible at adoption. Anonymized model preference, a successful syntax check or a completed reflection is not independent proof of improvement. Uncertain contrast remains labelled evidence, useful for provisional adaptation without a promotion ceremony.

For interpretation, provide a short question and the relevant episode, current method and available output/source handles. Like Harness2's evidence files, these handles let the model inspect details without putting the entire archive into its initial prompt. A partial tool observation must be labelled partial; a filename is not its contents. Existing `open` or a controller workspace adapter can expose the selected material. Copying every past harness and log into every call is not required.

Reuse of an old proposal is not a fresh model execution. When serving an execution cache, compare the request's actual model/route and material method settings with its stored metadata, or use a new run namespace; no signed compatibility certificate is needed. A change of model does not invalidate remembered lessons. It only prevents an old output being presented as a newly observed run of the new model. If the caller accepts reuse, retain the original provenance and do not count another independent outcome.

### 6.8 One episode to a useful next attempt

The minimum learning path is an actual episode or correction, a useful retained lesson, and its availability in the next relevant context. It does not require a Raw→Case→Schema→TransferValidated→Procedure promotion chain. A useful observation, conditional method and demonstrated improvement are different claims, not compulsory production stages.

**Input.** The host adapter captures actual tool responses, check results and user corrections with their available session/task/call association. It does not invent a new project, a successful verifier or completed steps to fill an outcome type. An agent's report remains a report with its source, not an independently observed execution. When correlation is absent, keep the material in its known session rather than assigning it to whichever task is newest. This is ordinary event data, not a proof certificate.

Group the material already saved for the episode; coalescing a work signal never drops earlier observations. A meaningful failure, successful repair, cheaper successful path or explicit request can trigger interpretation. Do not require a formal task ID, verifier or known causal explanation before remembering useful material. Background work uses the observed episode boundary or saved unprocessed portion; it need not wait for a ceremonial whole-task completion.

For native event intake, append the new identified events and interpret the saved unprocessed portion with only the earlier context needed to understand it. Do not continually reconstruct and resend the full transcript. A complete imported document revision and an appended event batch are different inputs: a tail is not a replacement for the whole source. Unchanged source parts can reuse prior extraction when the method is unchanged; explicit re-interpretation under a changed method remains possible. Equal text in independent events is not a duplicate delivery. Reuse the existing source IDs, revisions and job progress, not a new document-reconciliation platform.

**Interpretation.** When meaning is not explicit, one ordinary Dreamer job receives the relevant episode slice, optional feedback and a small set of related existing lessons. It proposes a concise observation/method, an amendment of a named lesson, or no change. The output explains the situation, useful next action and material limitations with source handles; these are useful contents, not a compulsory questionnaire. An explicit user correction or already structured rule may be saved directly without another model call. One episode can justify a provisional suggestion; it cannot by itself establish a general causal law.

For incremental updates, find the current item for the same subject/aspect and its closest relevant alternatives before deciding to create a sibling. Use existing keys and retrieval; answer-oriented reranking need not determine this update candidate set. Preserve other facets, conditions and historical occurrences. Related new material can share one interpretation batch and one deduplicated set of existing records; batch compatible embedding requests rather than making a request for every fragment. This is reuse of the current jobs/controller, not an obligatory second consolidation stage after every lesson. Inference and calculation remain allowed; label a derived conclusion instead of presenting it as a verbatim source fact.

The same interpretation may improve an older lesson's recall clues, contextual explanation or a specific relation to another lesson. Address the actual returned record IDs, never their positions in a ranked result list. Keep original evidence separate from these revisable search descriptions. Apply useful descriptions to the lexical fields and, when appropriate, the derived embedding input that retrieval really uses; changing an unused tag is not an improved memory path. Update the affected records only, using the existing Store and embedding jobs rather than a whole-corpus re-add or a separate evolution agent.

Select existing lessons relevant to this episode, not the first fixed-size page of the oldest records. One interpretation can extract several useful aspects; do not multiply calls by every message and every predeclared category by default. Categories can organize results without becoming mandatory independent pipelines. A valid useful result is searchable immediately; optional additional interpretations can proceed separately without withholding it.

**Storage and use.** Save the result as ordinary searchable memory and make it eligible for normal advisory context immediately under its stated scope. Read it independently of map/graph readiness. No separate skill activation, certification mode or evaluator approval is required. At the next matching resource/task/decision boundary, show the useful instruction and exception, with episode expansion when needed. A missing prerequisite can produce a conditional suggestion or the next useful check instead of silence. A missing execution verifier may prevent claiming a verified result; it does not by itself prevent reading the method. Advice and executing a packaged tool action remain separate operations.

**Revision.** A later observed outcome, contradiction or correction updates the relevant lesson and retains its history. Replayed input does not add independent support. A no-change response keeps the current text; an empty proposed replacement is not permission to erase it. Change the named method or context instruction, not the user's goal or the entire agent prompt. No useful new lesson is a legitimate result and does not create an obligatory reflection paragraph.

**Worked design example, not a runtime result.** An API change breaks a consumer. The saved episode contains the signature change, failed check, consumer repair and later successful check. Dreamer can retain “inspect consumers before changing this API; check the affected consumer after the edit,” linked to those observations. A subsequent relevant edit receives that note before planning. Its later result supplies a new observation; a skipped check supplies none. If the cause was never established, the original failed/successful sequence remains useful as an example without a fabricated explanation. A directly stated user correction can follow the same read path sooner, without waiting for this analysis.

The existing `capture`/`record_outcome` functions supply inputs, `jobs` invokes Dreamer when needed, `memory` stores the lesson, and `context` delivers it. Listing and opening methods use those stored records; demonstrations belong outside the product path. The first implementation must connect these owners, not merely expose form/abstract/promote tools that require an external agent to supply every semantic step. Missing an automatic producer or the ordinary context consumer is an unfinished loop even when all record types exist.

## 7. Attention, prediction and cognitive failure

A contradiction, commitment or missing observation is an ordinary memory item with scope and a resolution condition. Notification, delivery and acknowledgement do not resolve it. Use the actual result or explicit goal revision; do not create another task manager.

Predictions name an expected observable effect before an action, conditions and an available criterion. Store hit, miss, partial or unknown with the result. A successful sequence is evidence worth inspecting, not automatically an intervention-controlled causal claim.

Reduce unnecessary proactive exposure before inventing physical memory tiers: use a compact current lesson instead of repeatedly injecting all of its episodes, and reveal details when requested or relevant. Available recency/access signals may adjust this presentation, but do not change truth, supersession or deletion by themselves. A rarely encountered failure can become immediately relevant to the addressed resource; an explicit user requirement or unresolved commitment does not expire because it was seldom read.

Missing or evicted access statistics mean unknown usage, not proven inactivity since time zero. Reading a note is neither successful use nor confirmation. Keep permitted historical sources searchable even when they stop occupying ordinary orientation. Compression, source retention and owner-requested erasure follow their existing distinct operations; no mandatory HOT/WARM/COLD databases, decay daemon or global score is needed to reduce repetition.

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

The fourteen cases above belong to revision 0.3. Revision 0.4 adds:

| Case | Required behavior |
|---|---|
| Replacement preparation or insertion fails | No committed retirement without its replacement; preserve the preceding committed state |
| Two replacements race on one predecessor | Revalidate the group; do not apply the slower result as a last-writer winner |
| Replacement is committed but embedding is unavailable | New revision remains readable and lexically findable; indexing is visibly pending |
| A successor is refuted or erased | No implicit resurrection of its retired predecessor |
| Two predecessors converge into a later revision | Preserve both history branches or expose bounded traversal incompleteness |
| Exact diagnostic lies outside the dense candidate pool | Independent lexical/exact retrieval can still find it |
| A session continues without mentioning an earlier exception | Continuation does not silently supersede the exception |
| Verifier stops before exercising the target consumer | No positive learning outcome from the absent target diagnostic |

Revision 0.5 adds:

| Case | Required behavior |
|---|---|
| A resembles B and B resembles C, but A does not resemble C | Treat the component as candidates, not one proven common rule |
| A collision group has two existing generalizations | Do not attach everything to the first target; retain alternatives or justify a specific transformation |
| Detail/feature lookup discovers nodes outside the finite job input | Do not expand work or claim complete coverage silently |
| A selected source cannot be hydrated | Defer or accurately reduce the input; an opaque ID is not source content |
| Repeated unchanged induction returns no proposal | Reuse the completed no-change result without another automatic paid call |
| The abstraction method changes but the original embedding model does not | Refresh affected derived representations, not every original vector |
| Two notes share provenance but have different retry conditions | Preserve the distinction instead of treating overlap as semantic equality |
| One prerequisite evidence link fails during a claimed transformation | Do not report the complete transformation as applied; use the existing atomic/explicit partial boundary |

Revision 0.6 adds:

| Case | Required behavior |
|---|---|
| All improved candidates are worse or uninformative | The actual baseline/no-change remains eligible |
| An adopted output has no supported improvement lesson | Do not require a new experience entry or invent benefit |
| A next task differs materially from the previous one | Select applicable lessons, not the whole last harness |
| The improvement recipe changes during a comparison | Keep the comparison attributable; apply the new recipe in a later round |
| A probe would repeat an irreversible external action | Use a suitable replay/copy or omit that probe, not blind execution |
| The same finalized reflection is delivered twice | One lesson/update and outcome contribution, not another recursive trigger |

These are documentation walkthroughs, not an executed V3 test suite.

## 9. Source decisions

- [V1 current-value resolution, §4.12](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Canonical_Master.md#412-deterministic-current-value-resolution): preserve scoped deterministic resolution, not its old DTO hierarchy.
- [V1 Understanding Layer mission and principles](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Understanding_Layer_Engineering_Task_v1_4.md#L14-L120): preserve reconstruction, cues, small views and dirty tracking; reject claims that injection proves use or that every cognitive write must await complete cue classification.
- [DCPM, 2606.09483v1, §§2.2–2.5](https://arxiv.org/html/2606.09483v1): use revision trajectories and offline abstraction as mechanisms. Its cognitive hierarchy is not a required process hierarchy; its cross-domain sweep has quadratic pair comparisons. QA/personalization results are not evidence of causal improvement on coding work.
- [Hy-Memory optional canonical-state helpers](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/system2_agent.py#L72-L346): a source-backed counterexample to topic-specific regexes as general understanding. The branch is disabled by default in the inspected source; the isolated helper accepts quoted/example first-person equipment text. This is not a reproduced deployment failure.
- [Hy writer paper, 2610.22196v1, §5.3](https://arxiv.org/html/2610.22196v1): two preceding chunks describe reward annotation context, not a universal production-writer requirement. Keep pipeline parameters justified by their actual purpose.
- [LongMemEval, 2410.10813v2, §3.2](https://arxiv.org/html/2410.10813v2): knowledge update, temporal reasoning and abstention must be evaluated separately. This motivates failure categories, not importing benchmark user-attribute ontologies into Eliot.

- [Hy coding reconciliation](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/coding/fact_reconciler.py#L737-L889) and [storage](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/coding/store.py): borrow explicit history and scoped candidate ideas, not retire-before-insert or dense-only lexical availability. The pinned source permits several superseded facts while its ancestor helper selects one predecessor; the audit distinguishes source facts and isolated SQL probes from a full deployment test.

- [Hy cross-domain sweeper](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/cross_domain_sweeper.py) and [optional schema compaction](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/system2_tools.py#L84-L209): candidate discovery is not justified merge or lossless compression. Audit §18 separates pinned source facts, synthetic control-flow probes and V3 proposals. Do not carry over an unbounded second enumeration or count association edges as independent support.

- [Harness2 recursion](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/recursion.py), [selection/reflection](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/selection.py), [library](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/library.py), [ledger](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/ledger.py), and [experiment guide](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/docs/EXPERIMENTS.md): take the two improvement loops and execution contrasts, not finals-only adoption or a fixed experimental workload. [Paper 2610.14224v1](https://arxiv.org/html/2610.14224v1) distinguishes adopted configuration from verified optimality. No donor experiment was run in this pass.

- [LangMem D16 prompt-memory implementation](https://github.com/langchain-ai/langmem/blob/48e3c11f5bb527282c7d5339c6a87a0b35abccfc/src/langmem/prompts/stateless.py) and [response contract](https://github.com/langchain-ai/langmem/blob/48e3c11f5bb527282c7d5339c6a87a0b35abccfc/src/langmem/prompts/prompt.py): take trajectory/feedback-based scoped proposals; honor no-change instead of blindly replacing a method with `new_prompt`. Audit §24 distinguishes these source findings from model/runtime experiments.

- [V2 actual packet caller](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-app/src/mcp_stdio/task_handlers.rs#L195-L460), [MCP skill surface](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-app/src/mcp_stdio/skill.rs), and [skill packet/proof helpers](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-engine/src/skill.rs#L640-L735): distinguish actual consumers, synthesized demonstration output and observed execution. Do not port the fixture-producing facade or make project-map availability a condition for reading experience.
- [Harness2 context](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/context.py#L1-L260) and [proposer](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/proposer.py): take short missions with expandable real evidence. Reuse of cached output must retain its actual execution identity; a changed configured model is not established by old response bytes. See Audit §25 for the source scope and benchmark-directory mitigation.
- [Hindsight consolidation](https://github.com/vectorize-io/hindsight/blob/c5f585f8f8568ed0677eb2e70fe830c4c483e2a2/hindsight-api-slim/hindsight_api/engine/consolidation/consolidator.py), [facet instructions](https://github.com/vectorize-io/hindsight/blob/c5f585f8f8568ed0677eb2e70fe830c4c483e2a2/hindsight-api-slim/hindsight_api/engine/consolidation/prompts.py) and [saved mental-model queries](https://github.com/vectorize-io/hindsight/blob/c5f585f8f8568ed0677eb2e70fe830c4c483e2a2/hindsight-docs/docs/developer/api/mental-models.mdx): take selective incremental updates, compatible batching and saved useful questions. The donor's synthesized `observation` is not Eliot's raw observation; source counts are not independent successful attempts.
- [MemMachine declarative retrieval](https://github.com/MemMachine/MemMachine/blob/d5a39a8e774e977fb1e6c22efb03555c4e51e05e/packages/server/src/memmachine_server/episodic_memory/declarative_memory/declarative_memory.py): take derivative-to-source lookup and contextual episode expansion, not its entire backend topology or an embedding prerequisite for primary capture.
- [Graphiti edge resolution](https://github.com/getzep/graphiti/blob/3cc723cd292eb5c2ac5ea2c5539270b8e1b6389f/graphiti_core/utils/maintenance/edge_operations.py): take affected-fact updates and temporal distinctions. Duplicate candidates and contradiction candidates need not have the same endpoints; wording alone does not establish the same temporal occurrence. Audit §26 records the limits of the inspected path.
- [MemMachine text segmenter](https://github.com/MemMachine/MemMachine/blob/d5a39a8e774e977fb1e6c22efb03555c4e51e05e/packages/server/src/memmachine_server/episodic_memory/event_memory/segmenter/text_segmenter.py), [deriver](https://github.com/MemMachine/MemMachine/blob/d5a39a8e774e977fb1e6c22efb03555c4e51e05e/packages/server/src/memmachine_server/episodic_memory/event_memory/deriver/text_deriver.py) and [semantic ingestion](https://github.com/MemMachine/MemMachine/blob/d5a39a8e774e977fb1e6c22efb03555c4e51e05e/packages/server/src/memmachine_server/semantic_memory/semantic_ingestion.py): distinguish cheap indexing units from interpreted episodes; do not inherit per-message/category calls, an oldest-prefix update context or partial work labelled fully ingested. See Audit §27 for the actual caller/storage scope.
- [Hindsight OpenCode content](https://github.com/vectorize-io/hindsight/blob/c5f585f8f8568ed0677eb2e70fe830c4c483e2a2/hindsight-integrations/opencode/src/content.ts), [hooks](https://github.com/vectorize-io/hindsight/blob/c5f585f8f8568ed0677eb2e70fe830c4c483e2a2/hindsight-integrations/opencode/src/hooks.ts) and [retain orchestration](https://github.com/vectorize-io/hindsight/blob/c5f585f8f8568ed0677eb2e70fe830c4c483e2a2/hindsight-api-slim/hindsight_api/engine/retain/orchestrator.py): take known injected-context exclusion, role-aware input and incremental work. The examined plugin reads chat text rather than all tool outcomes; donor delta processing is conditional, not a guarantee for every backend or retain mode.
- [A-MEM paper v11, §§3.1–3.4](https://arxiv.org/html/2502.12110v11) and [library memory_system.py](https://github.com/agiresearch/A-mem/blob/ceffb860f0712bbae97b184d440df62bc910ca8d/agentic_memory/memory_system.py): take local evolution of useful descriptions/relations, not search-rank IDs or neighbors discarded after packing. The research mechanism and this library's actual retrieval are distinct; its benchmark experiments were not reproduced.
- [Nocturne models](https://github.com/Dataojitori/nocturne_memory/blob/1858957bf797722a9b731fb197bd9530f7ae67e4/backend/db/models.py) and [system views](https://github.com/Dataojitori/nocturne_memory/blob/1858957bf797722a9b731fb197bd9530f7ae67e4/backend/system_views.py): take stable content identity and short recall clues pointing to real content. `disclosure` here means when to recall, not authorization. No mandatory boot ritual or forced conflict elimination is imported.
- [Subcog retrieval](https://github.com/zircote/subcog/blob/0cd2d4f0cff04938c9f865353fbfefa1b4e3f754/src/services/recall.rs), [lifecycle service](https://github.com/zircote/subcog/blob/0cd2d4f0cff04938c9f865353fbfefa1b4e3f754/src/services/consolidation.rs) and [score model](https://github.com/zircote/subcog/blob/0cd2d4f0cff04938c9f865353fbfefa1b4e3f754/src/models/consolidation.rs): take independent native retrieval and retained summary sources; distinguish relative ranking, observed usefulness and lifecycle decisions. Audit §28 gives the limited arithmetic/source findings rather than a claim about every deployed Subcog path.
- [MAGMA actual query and traversal](https://github.com/FredJiang0324/MAGMA/blob/467cb70b67ac337b22fdb42194d37c04ad701b62/memory/query_engine.py): take question-relevant typed relations, not mandatory full scans, repeated encoding or query-word gates on every intermediate node. The inspected caller uses adaptive traversal; the neighboring probabilistic helper is not assumed to be that caller's implementation.
- [Letta local compaction](https://github.com/letta-ai/letta-code/blob/e8073d4e475ab7f56e76f9aaeea81a7618a92575/src/backend/local/compaction.ts), [actual caller](https://github.com/letta-ai/letta-code/blob/e8073d4e475ab7f56e76f9aaeea81a7618a92575/src/backend/local/local-backend.ts#L680-L950), and [reflection input](https://github.com/letta-ai/letta-code/blob/e8073d4e475ab7f56e76f9aaeea81a7618a92575/src/cli/helpers/reflection-transcript.ts#L1-L250): distinguish context continuation from learning reusable knowledge. Eliot provides source-linked continuation without becoming a second host context manager. Full automatic/server reflection execution was not qualified in this pass; see Audit §29.
