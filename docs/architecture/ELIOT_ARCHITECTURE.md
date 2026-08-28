# ELIOT Architecture
## Architecture of Intent, Understanding, and a Resilient Agent System

**Version:** 4.5-draft
**Date:** 2026-08-12
**Status:** candidate for canonical adoption
**Normative pair:** `ELIOT_ARCHITECTURE.md` + `ELIOT_IMPLEMENTATION.md`
**English edition:** 2026-08-28; semantic-preserving English revision of the re-audited integrated baseline

**Transition rule:** Until the new Implementation is adopted, earlier documents remain valid sources for concrete contracts of the existing system. When meanings conflict, development of the new system follows this Architecture. Any incompatibility is recorded as a migration gap, not resolved by silently choosing the more convenient text.

> **ELIOT exists so replaceable people and agents can preserve, restore, verify, and improve correct understanding across long-running work.**

Understanding is not an end in itself. It matters only when it helps complete a real task, create or verify an artifact, make a better decision, survive failure, and continue without losing meaning.

ELIOT assumes that:

```text
people and models make mistakes;
agents lose context and violate instructions;
data can be wrong or poisoned;
tools can be narrow or misconfigured;
modules fail;
rules can become more harmful than the errors they were meant to prevent;
complete knowledge, truth, and reliability are unattainable.
```

Modern agents also work more reliably with a bounded, causally coherent workset than with a vast unstructured context. This is an empirical limit of current cognitive routes, not a permanent law about code size. The Architecture therefore requires decomposability, minimally sufficient context, and verifiable boundaries, but sets no fixed size for a Module, file, package, or agent team.

ELIOT is therefore not built as an infallible fortress. It is built as a **resilient cognitive system**:

```text
goal and contact with reality
→ observations and competing models
→ inquiry, experiment, or action
→ artifacts and outcomes
→ comparison, correction, and recovery
→ better cognitive inheritance.
```

ELIOT combines four functions:

```text
Memory OS — preserves and develops cognitive inheritance;
Harness   — connects tasks, agents, tools, authority, and verification;
Smart     — supports understanding, orientation, graphs, and Dreamer;
Meta      — observes system quality, diagnoses drift, and converts outcomes and recovery into Improvement Candidates; Doctor performs bounded repairs.
```

A small resilient Kernel maintains identity, the canonical transition boundary, fencing, health, and recovery. It is not a second intelligence.

For a working agent, ELIOT is simple:

```text
solve the primary task rather than administer memory;
obtain a sufficient view before a material decision;
report material observations, decisions, failures, and outcomes;
use ELIOT for inquiry, coordination, verification, and recovery;
do not claim more certainty or completion than the evidence supports.
```

For initial orientation, this page, A1, and A16.3 are sufficient. Use A0 as the compass when rules conflict; open the remaining sections according to the current task and failure boundary.

---
# A0. Constitutional Meaning and Interpretation Rules

## A0.1. Purpose of the Architecture

The Architecture is neither an executable code nor a catalog of future structures. It is a **decision compass**. It records:

```text
what problem ELIOT solves;
what outcomes are valuable;
which properties must survive technology changes;
why the core principles were chosen;
how to act under conflict, failure, and incomplete knowledge;
where the Implementation may experiment.
```

The Architecture matters most when the Implementation faces a choice. It must make the following questions answerable:

```text
which option best preserves ELIOT's intent;
which local optimization damages the system;
which rule is obsolete;
where a Hard Boundary is required and where recovery is preferable;
whether a mechanism helps people and agents or merely serves its own ceremony;
whether the system can survive a local failure without losing its goal, evidence, or control;
which defect requires an Architecture change rather than another workaround.
```

Conformance is determined by preserved intent and observable outcomes, not by the number of prescriptions followed.

**ARCH-INTENT-01 — Intent outranks literal compliance.** A rule is useful only while it advances the purpose for which it was introduced. A rule that repeatedly blocks correct work or reproduces the original failure mode must be challenged, narrowed, or changed openly.

**Why:** real agent work always exceeds any rule written in advance; literal discipline without understanding turns safeguards into failure sources.

**Under conflict:** A0.3 Hard Boundaries remain intact. Everything else permits Governed Challenge, reversible deviation, and outcome verification. Citing Intent never authorizes a working agent to bypass controls silently: every deviation must be explicit, scoped, within already granted authority, and assigned an owner, review, and outcome.

## A0.2. Hierarchy of Architectural Decisions

| Class | Meaning |
|---|---|
| **Architectural Intent** | The ultimate goal and rationale; the primary guide under conflict |
| **Theory** | An explanation of cognition, memory, resilience, and learning; it does not impose one mechanism |
| **Invariant** | A property a healthy system preserves or restores over its trajectory |
| **Hard Boundary** | A narrow boundary around authority, secrets, irreversible effects, proof, or canonical integrity; enforced fail-closed |
| **Contract** | An observable capability obligation; degradation under failure must be explicit |
| **Guardrail** | A preferred defense against a known error class; challenge and scoped deviation remain possible |
| **Default** | The currently preferred mechanism; replaceable without changing Intent |
| **Policy** | A governed human decision about privacy, risk, cost, models, or operations |
| **Experiment** | A reversible hypothesis test with an evaluator, stop condition, and rollback |
| **Empirical Profile** | Versioned knowledge about a specific model, harness, toolset, and workload combination |
| **Metric** | A measure of a property that must not become the system's objective |
| **Example** | An illustration with no independent normative force |

`ARCH-*` entries are durable **decision anchors**. They restore meaning and support the conformance map, but must not turn every working boundary into ceremony. Normative force does not follow from words such as "must" alone; it follows from the decision class, rationale, and observable property. A listed mechanism is not permanent unless it is a Hard Boundary.

An Invariant is evaluated over a trajectory. A temporary error is tolerable when it is:

```text
detected;
localized;
not granted hidden authority;
recorded as evidence;
covered by recovery or honest escalation.
```

## A0.3. Hard Boundaries

Fail-closed behavior is required only where an error could create irreversible effects or hidden control capture:

```text
hidden creation or expansion of authority;
hidden alteration of the user's ultimate goal;
an untraceable irreversible or external effect;
a false VERIFIED_COMPLETE or other proof claim;
hidden rewriting of provenance or history;
restoration of revoked influence after recovery;
a second ungoverned canonical owner or write path;
secrets or prohibited data crossing a privacy boundary.
```

Other failures default to:

```text
buffering;
isolation;
bounded influence;
branch or snapshot;
retry with new evidence;
alternative route;
repair;
quarantine;
escalation.
```

ELIOT safety depends not only on preventing errors, but also on surviving them without losing control.

## A0.4. Conflict Resolution

First determine whether a Hard Boundary is affected. If so, stop the dependent effect until explicit authority or recovery exists. Otherwise, treat the conflict as information.

| Question | Decisive basis |
|---|---|
| What happened | Observation, artifact, evidence, and an applicable verifier |
| What it means | Competing models, causal analysis, and Concilium |
| What the goal and acceptable risk are | The authorized human, after clarification when needed |
| What is currently permitted | Authority, WorkScope, privacy and cost policy, and actual integration capability |
| How to realize the principle | Intent and Contract, then the simplest reversible mechanism |
| Which model is better | Discriminative evidence and practical outcomes, not vote count |
| What to do when evidence is insufficient | Preserve the unknown; choose a probe, reversible trial, or safe partial progress |

Order of preference among admissible choices:

```text
1. preserve the stated goal and user agency without overriding evidence or Hard Boundaries;
2. improve the correctness and repairability of understanding;
3. prefer an observable, reversible, and recoverable path;
4. preserve provenance, alternatives, and dissent;
5. localize blast radius and cost;
6. choose the simpler mechanism.
```

## A0.5. Concilium

**Concilium** is a governed deliberation among people, agents, models, and tools. Its purpose is not voting, but finding errors in the shared picture.

Concilium separates observations from interpretations, exposes shared Evidence Lineage and common-mode failures, states the strongest objections and rival predictions, and proposes discriminative tests and provisional options. The designated Main Agent or Human decision owner decides; dissent and review conditions are preserved.

**ARCH-CONCIL-01 — Dissent matters more than vote count.** Reliability comes from independent grounds, negative testing, and real outcomes, not from a model majority.

## A0.6. Changing the Architecture

```text
recurring problem or new fact
→ concise statement of the violated Intent
→ evidence and alternatives
→ Implementation and migration consequences
→ Architecture Owner decision
→ change to the main text.
```

The Implementation may refine concrete contracts and defaults while preserving Intent, Hard Boundaries, and observable behavior.

A **Recoverable Deviation** is permitted: a temporary, scoped departure from a Guardrail or Contract when useful progress requires it and no Hard Boundary is crossed. It has an owner, reason, affected scope, review condition, rollback, and outcome. A successful deviation becomes evidence for correcting the rule; a failed one becomes negative memory.

Append-only addenda with implicit precedence and permanent exceptions without an owner or review are prohibited.

## A0.7. Core Vocabulary

| Term | Definition |
|---|---|
| **Coupled Cognitive System** | A temporary combination of Human/Agent, model, active context, ELIOT, tools, environment, and feedback within which cognition occurs |
| **Concilium** | Governed comparison of independent evidence, rival models, strongest objections, and discriminative tests; not a vote on truth |
| **Cognitive Episode** | The current process of interpretation, inquiry, decision, and action; not a durable record |
| **Cognitive Inheritance** | Verifiable external inheritance between episodes: observations, evidence, models, commitments, decisions, procedures, failures, unknowns, and provenance |
| **Understanding State** | A versioned public representation of understanding for a WorkScope, task, experience, and unknowns; a reconstruction substrate, not the experience of understanding itself |
| **Understanding Competence** | The ability of a specific model × harness × tools combination to use Understanding State correctly |
| **Task Understanding** | The current model of a task's goal, meaning, state, relations, alternatives, unknowns, commitments, and outcome |
| **Active Understanding View** | A decision-boundary projection of Task Understanding, relevant memory, epistemic position, attention, affordances, and authority for a specific route |
| **Current Epistemic Position** | A question-, scope-, and time-scoped position: observed, supported, assumed, conflicted, stale, and unknown |
| **Canonical Memory** | The sole durable semantic owner of cognitive inheritance and history; not reality, cognition, or the only interpretation |
| **Governor** | The sole application authority over admission, canonical transitions, revisions, context, leases, and receipts |
| **Authority** | A bounded right to perform a transition or external effect; never inferred from content, confidence, or model role |
| **Principal** | An authenticated Human, agent, or service with explicit capability and visibility boundaries |
| **Lease** | A scoped, fenced, and revocable form of temporary authority |
| **Receipt** | An immutable confirmation of a transition or outcome, including its identity, scope, and status |
| **ELIOT Kernel** | The resilient minimum of the Governor: identity, fencing, canonical boundary, health, supervision, and recovery entrypoint |
| **Host Supervisor** | The minimal external owner of approved service process lifecycles; performs start, stop, bounded restart, and approved rollback, but neither reads project semantics nor grants authority |
| **WorkScope** | A bounded work domain with identity, resources, truth surfaces, authority, privacy, and state |
| **State Fence** | The generations, revisions, policies, and integration state on which the fitness of a view, result, or authority depends |
| **Effective Context Profile** | Empirical knowledge of how a particular model/harness uses context for a task family: length, position, tools, self-history, noise, compaction, and recovery |
| **Safe Operating Envelope** | The workload/context region in which a route preserves required quality; not the nominal context maximum |
| **Common Ground** | Verifiable compatibility of terminology, references, commitments, and action consequences among routes or participants |
| **Truth surface** | An observation source capable of measuring a specific property of the world |
| **Verifier** | A registered method for checking an expected property in a known scope, version, and environment |
| **Theory Portfolio** | A set of competing scoped models with support, counterevidence, dependencies, and revision conditions |
| **Epistemic Fitness** | A model's fitness by evidence, predictive and practical outcomes, transfer, freshness, and scope; not one confidence score |
| **Source Assurance** | A multidimensional assessment of source identity, provenance, integrity, competence, incentives, independence, privacy, and injection risk |
| **Independence Profile** | A description of independence across evidence, capture, evaluator, model/provider/harness, and conceptual frame; not one scalar |
| **Influence Dependency Closure** | Derived views, procedures, packets, and decisions whose current influence depends on a source, tool, or verifier |
| **Semantic Contamination** | Incorrect, manipulative, or overgeneralized information despite intact structure and lineage |
| **Structural Corruption** | Damage to canonical integrity, ordering, provenance, storage, or authority state |
| **Module** | A replaceable capability with an owner, inputs and outputs, dependencies, health, failure domain, and recovery boundary |
| **Micro-module** | The smallest independently understandable, verifiable, and replaceable capability with one causal responsibility and one lifecycle owner; its physical form and size belong to the Implementation or an Empirical Profile |
| **Functional Capability Cell** | The causal unit of one coherent capability: one lifecycle owner, one public contract surface, one owner for each mutable state it owns, an independently invocable proof surface, and a declared replacement boundary. It may be stateless or span several source modules or crates; physical packaging is not its identity |
| **Independent Proof Surface** | The ability to verify a Module through its public contract and observable effects without running the entire system; such proof is not product proof |
| **Agent Work Unit** | Bounded work for one agent: one primary causal property or owner, exact scope, minimally sufficient context, expected artifact or evidence, verifier, budget, and stop condition |
| **Product Pulse** | The smallest real end-to-end path able to detect when locally correct Module changes break the overall product outcome |
| **Experimental Contour** | An isolated, capability-bounded, and replaceable environment for an unverified capability; its sandbox, process, or runtime technology belongs to the Implementation |
| **Module Registry** | A versioned registry of Modules, dependencies, health, compatibility, failure domains, and repair recipes |
| **Tool Definition** | A versioned cognitive input: name, description, schema, defaults, examples, permissions, and side-effect semantics |
| **Problem State** | Durable state for an operational, cognitive, integration, or data-quality problem, with evidence, owner, and resolution condition |
| **Incident** | A severe Problem State affecting integrity, authority, security, critical telemetry, or a dangerous unresolved effect |
| **Quarantine** | Reversible isolation of content, an operation, or a Module from current influence or effects, with an owner and release condition |
| **Governance Profile** | A vector of actual observation, enforcement, and supervision capabilities; not a marketing label for an integration |
| **Session** | A temporary identity-bound connection among a principal, harness, WorkScope, task, authority, and telemetry; losing it does not destroy durable work |
| **Task Controller** | Temporary responsibility for the current plan revision of one task; a Main Agent or authorized Human may hold it, but it creates no factual, policy, or architecture authority |
| **Route Continuation State** | Temporary provider- or harness-bound continuation state for one cognitive route; it may support resume but is neither knowledge, evidence, nor transferable authority |
| **Ordering Scope** | The smallest domain in which conflicting transitions must be ordered |
| **Coordination Scope** | A declared union of Ordering Scopes for a multi-scope transition or saga |
| **Authority Epoch** | The generation of the active authority holder; output from an old owner after restart or reassignment is stale |
| **Durable Job** | A long-running operation with identity, owner, State Fence, checkpoint, budget, cancellation, outcome, and receipt |
| **Critical Attention** | A material obligation that remains active until resolution, authorized waiver, or supersession |
| **Control Reserve** | Capacity unavailable to normal workload and reserved for cancellation, fencing, telemetry, attention/problem transitions, and recovery |
| **Recovery Directive** | A structured failure response: reason, preserved state, permitted next step, and required authority |
| **Conflict Directive** | A concise operational view of a conflict: observations, rival models, common lineage, unresolved residue, decision owner, and useful probe |
| **Recovery View** | A minimal non-semantic projection of health, unavailable guarantees, last-known-good state, pending recovery intents, and a manual entrypoint when the normal control path fails |
| **Operational Recovery State** | Bounded non-semantic durable state for pending operations, checkpoints, fencing, and recovery reconciliation |
| **Dreamer** | An instrumental AI service that runs bounded model, agent, or swarm jobs for curation, orientation, and research synthesis; neither an owner nor an authority |
| **Watchdog** | An independent supervision daemon for liveness, protocol discipline, security, and recovery. It runs continuously during ELIOT's declared active interval; outside use, during maintenance, or during recovery, it may stop after preserving cursors and wake state. It is not a semantic oracle |
| **Researcher** | The governed information-work plane: selects inquiry protocol and evidence grade; admits external sources to a scoped inquiry evidence set; maintains source portfolio, coverage denominator, and claim audit. Pluggable providers perform acquisition, parsing, indexing, and retrieval. Researcher neither interprets nor owns authority |
| **Inquiry Protocol** | The declared method for one question: effort, evidence, lane, and stop condition; selected by task structure rather than work label |
| **Evidence Grade** | The declared rigor level for one information task; defines required lanes, verifier, coverage, and audit |
| **Architecture Knowledge** | The exact adopted Architecture, rationale, IDs, and change procedure as load-bearing ELIOT self-knowledge |

The vocabulary contains only cross-cutting, load-bearing concepts. A local term is defined once in its own section and does not create a parallel ontology.

## A0.8. Progressive Conformance

Before claiming durable or recoverable operation, ELIOT requires:

```text
one canonical history and write path;
provenance, scope, authority, and receipts for material transitions;
forward revision and a verifiable recovery entrypoint;
a distinction among observation, interpretation, unknown, and verified result;
no false done claim or hidden degradation;
bounded resources and actionable failure.
```

The first useful vertical spine is:

```text
one real agent bridge;
natural capture of observations without ontology knowledge;
one WorkScope and task state;
a basic Active Understanding View;
at least one world/task event that reactively delivers relevant memory or obligation;
one truth/verifier route;
an honest finish outcome;
minimal supervision and restart;
a Problem/notification path for both agent and Human.
```

Basic supervision belongs in the first spine. Basic Dreamer Orientation is the first Smart depth added after a reliable capture/retrieval loop; advanced security audit, research, graphs, large swarms, deep recovery, and Meta experiments come later. When the WorkScope is ELIOT itself, applicable Architecture Knowledge already belongs in the basic Active Understanding View. Missing capability is labeled honestly and does not block independent value.

The vertical spine is the first useful slice, not complete ELIOT. Full conformance means Memory OS, Harness, Smart, and Meta form a closed, observable loop under the declared Governance Profile, with missing capabilities and guarantees visible. The live conformance map in A6.7, not a count of completed items, establishes conformance.

**ARCH-DEV-01 — Working system before broad hardening.** Build a real end-to-end cognitive loop first; add tests and depth in response to observed failure modes.

## A0.9. Current Strategic Defaults

ELIOT is a local-first system for mainstream desktop users, primarily on Windows.

Current strategy:

| Default | Rationale |
|---|---|
| Rust for the daemon and control plane | Memory safety, predictable native concurrency, low overhead, and suitability for a long-lived local service |
| Hybrid canonical storage such as SurrealDB | Graph, document, temporal, and structured state should remain under one governed owner rather than diverging stores |
| Windows-first operations | Primary users and agent tools run on Windows; a local-first product must operate as a first-class service there |
| Models, agents, and tools from multiple vendors | Capability contracts reduce lock-in and permit changes in cognitive and failure profile without rewriting ELIOT |

These are Defaults, not permanent Invariants. Replacement is permitted when the Architecture, migration path, and demonstrated operational benefit are preserved. Micro-modularity, isolation, staged promotion, and hot-path discipline are architectural properties; concrete language packages, sandbox or component runtimes, and process technologies are only current Implementation mappings.

---
# A1. Mission and Theoretical Core

## A1.1. Primary Purpose

ELIOT maintains **continuous, correctable understanding** across replaceable people, models, agents, and sessions.

Understanding is neither stored text nor a context packet. It appears as the ability to:

```text
identify what exists and what it means;
restore the goal, boundaries, and current situation;
see relations, dynamics, and causal alternatives;
distinguish evidence, hypothesis, unknown, and norm;
predict intervention consequences;
choose an inquiry or action;
verify the result and revise the model.
```

ELIOT preserves public material and organization that support such understanding. Current cognition arises in coupled activity.

**ARCH-CORE-00 — Work must accumulate.** Every consequential work episode must leave the system better able to perform the next compatible work, or explicitly show why available evidence does not yet justify a behavior change.

**Why:** without this requirement, long-running agent work produces artifacts but not competence. A trace, transcript, stored outcome, completed task, or new report is not learning by itself.

**Under conflict:** accumulation never authorizes the system to alter the user's goal, values, authority, or Hard Boundaries. An observed outcome must either change the next strategy through inspectable state or receive an explicit, evidence-backed no-change disposition.

**ARCH-CORE-01 — Understanding continuity first.** Every ELIOT organ serves the preservation, restoration, and correction of decision-relevant understanding.

## A1.2. Why This Is Not RAG

```text
RAG:
query → similar fragments → prompt.

ELIOT:
goal + world contact + cognitive inheritance
→ scoped competing models and current epistemic position
→ inquiry or action under authority
→ real outcome
→ revision, recovery, and reusable learning.
```

RAG, embeddings, full-text search, and graph retrieval may be ELIOT tools. They do not solve:

```text
unknown unknowns;
current applicability of old memory;
the distinction between observation and interpretation;
causality and alternatives;
continuity of commitments;
authority and finish;
poisoned influence;
outcome-based learning.
```

When a system only retrieves chunks and shortens prompts, a simpler RAG system is cheaper and more correct.

## A1.3. Core Postulates

1. Cognition arises from the combination of participants, representations, tools, and environment.
2. Memory preserves cognitive inheritance, not a finished thought.
3. Reality is external; ELIOT maintains only defeasible epistemic positions.
4. Understanding is scoped, plural, action-oriented, and revisable.
5. Decision-relevant correctness matters more than additional compactness.
6. Intent guides rules; Hard Boundaries protect only genuinely irreversible boundaries.
7. Errors by agents, modules, and memory are normal operating conditions.
8. Knowledge develops through inquiry, predictions, practical outcomes, and revision.
9. Dissent and negative evidence are productive Concilium resources.
10. Humans, models, and deterministic tools have different competencies and blind spots.
11. Attention and context are bounded causal interventions.
12. Action may be pragmatic or epistemic.
13. Causal models remain defeasible and are compared through discriminating observations.
14. Security assumes defenses may be breached and limits the consequences.
15. Resilience preserves the possibility of cognition after disturbance.
16. Model replacement transfers inheritance, not tacit strategy.
17. Learning has multiple levels and is not reducible to weight changes.
18. Forgetting governs accessibility and influence without rewriting factual support.
19. ELIOT must know its Architecture, implementation state, and limits.
20. ELIOT assists people and agents instead of turning their work into system administration.
21. Depth is added in layers; the Kernel and canonical history are not rewritten for every improvement.
22. Work must decompose into decision-sufficient worksets, but the Architecture sets no universal Module or context size.
23. An unverified capability first receives bounded influence and an independent replacement boundary; tighter integration must be earned through evidence.
24. A swarm is a durable pipeline of bounded attempts, not one endless shared agent conversation.
25. Testing, debugging, and recovery belong to the working feedback loop and Meta-learning, not to a separate pre-release ceremony.

## A1.4. Four Planes

```text
Memory OS — evidence, continuity, memory functions, retrieval, revision, and forgetting;
Harness — task framing, tools, agents, swarm, authority, verification, and finish;
Smart — Understanding State, graphs, inquiry, Context Compiler, and Dreamer;
Meta — Watchdog, Doctor, self-model, evaluation, recovery learning, and Improvement Candidates.
```

They form one feedback loop. No plane receives independent value authority or final-decision authority.

**ARCH-CORE-02 — Four planes, one governed loop.** Memory, orchestration, intelligence, and Meta reinforce one another while their powers remain separate.

Learning is not a fifth plane. It is a cross-cutting lifecycle through the four existing planes:

```text
capture experience          Memory OS / Harness
diagnose mechanism          Smart
adapt locally               Harness / Smart
execute and verify          Harness
consolidate                 Meta / Memory OS
promote or roll back        Meta / Governor
reactivate for future work  Smart / Harness
```

No stage creates a new owner. A stage with no owner among the four planes is an Architecture defect, not a reason to add another plane.

## A1.5. Boundaries

ELIOT is not:

```text
a new foundation model;
a universal DBMS;
a replacement for the host, IDE, terminal, or professional software;
an autonomous generator of ultimate goals;
a system that guarantees infallibility;
a continuous autonomous LLM loop;
a brain simulation;
a collective swarm subject;
a source of absolute truth.
```

ELIOT is an instrumental system for assisting and democratizing complex agent work. It should let a user without a large team or infrastructure obtain quality, continuity, and control that would otherwise require a mature engineering organization. Automatic multi-node replication of the canon is not a current obligation; if introduced, multiple physical nodes must preserve one logical owner and causal order.

**ARCH-HELP-01 — ELIOT reduces cognitive and operational load.** Internal complexity is justified only when it makes work simpler, more reliable, and more productive for the person and the primary agent.

---
# A2. Participants, Authority, and Modularity

## A2.1. Complementary Fallibility

| Participant | Strength | Typical failure |
|---|---|---|
| Human | Goals, values, context, legitimate authority | Incomplete knowledge, fatigue, conflicting preferences |
| Main Agent | Semantic synthesis, plans, alternatives | Hallucination, framing error, context loss, rationalization |
| Deterministic tool | Exact measurement of a defined property | Narrow competence, misconfiguration, absence of meaning |
| Governor | State, authority, lifecycle, receipts | Incomplete observability, implementation defect |
| Dreamer | Broad synthesis and hypothesis generation | Smooth false narrative, correlated model bias |
| Watchdog | Independent process and security observation | False positive, incomplete coverage |
| Verifier | Scoped proof | Wrong construct, stale environment, blind spot |

**ARCH-ROLE-01 — Authority is separated by function.** Observation, interpretation, authorization, and verification should not belong to one participant without necessity.

**ARCH-ROLE-02 — Responsibility follows competence and failure type.** No Human, model, or tool is a universal oracle.

**ARCH-AUTH-01 — Authority is explicit, scoped, and fenced.** Content, model confidence, and role names never create a right to perform a transition or effect; authority has an owner, scope, State Fence, and revocation path.

## A2.2. Roles

A role description defines function, not implicit permission. Every state change or effect requires applicable authority. Authority may be delegated in advance to a role, work item, policy, or lease and checked automatically; separate ceremony is needed only at a boundary of impact, uncertainty, or delegation. Anything outside granted authority is prohibited. General degradation of roles and services is governed by A13.11, not hidden exceptions here.

### Human Roles

- **Requester / Domain Owner** sets the goal, values, constraints, and acceptance criteria.
- **Architecture Owner** approves Architecture changes.
- **System Owner** manages installation, credentials, model routes, and system delegation.
- **WorkScope Owner** defines local policies, protected resources, and accepted verifiers.
- **Approver** authorizes an exact Critical action.
- **Recovery Principal** performs a narrow break-glass transition.

One person may hold several roles, but their authority does not merge automatically.

### Main Agent

Interprets meaning, develops competing models, selects inquiry or action, and proposes decisions. It creates no independent verification authority, policy, or factual proof.

### Task Controller

Owns the current plan revision and coordination of one task under the active Authority Epoch. The Main Agent usually carries this responsibility; a Human may assume it explicitly. The Task Controller does not own factual truth, Architecture, or system-wide policy.

### Governor and Kernel

The Governor is the sole application owner of canonical transitions, authority, task state, context compilation, and receipts. The Kernel is its minimal resilient core, not a second Governor.

### Canonical Memory

Preserves cognitive inheritance and history. It is neither an agent, truth source, nor policy owner.

### Truth Surfaces and Verifiers

A truth surface provides an observation about a specific property. A Verifier checks an expected property in a known scope. Neither defines the goal nor proves more than its Evaluation Contract.

### Harness and Agent Coordinator

The Harness connects the model, host, tools, and Governor. The Agent Coordinator manages the durable work graph, sessions, budgets, leases, and aggregation. Neither makes the substantive decision.

### Host Supervisor

Operates outside the shared process failure domain of the main services. It performs only start, stop, bounded restart, and approved rollback; it neither reads project semantics, forms a diagnosis, nor grants canonical authority.

### Watchdog and Doctor

The Watchdog independently observes liveness, protocol discipline, security, and integrity. The Doctor diagnoses Modules and performs only registered, bounded repairs.

### Dreamer

Runs bounded AI jobs for curation, orientation, research, and clarification. It owns no memory, policy, truth, or final decision.

### Workers, Auditors, Verifier Agents, Synthesis Agents, and Curators

Perform narrow work and return candidate artifacts and evidence. Their role does not elevate result authority.

### Human Control Plane

Displays canonical state and lets a person issue decisions, approvals, Dreamer or Watchdog questions, and recovery actions. It is not a second owner.

## A2.3. Modular Architecture

```text
0. Kernel
   identity, authority, fencing, canonical transition boundary,
   control scheduling, health, and recovery entrypoint.

1. Canonical state
   Memory OS, tasks, evidence, relations, history, receipts, and durable jobs.

2. Instrumental intelligence
   truth adapters, verifiers, code and dependency graphs, logs, and artifact inspection.

3. Cognitive intelligence
   Understanding State, Context Compiler, Dreamer, semantic curation, and calibration.

4. Harness and orchestration
   agent and tool gateway, swarm, work graph, leases, and result aggregation.

5. Surfaces
   agent protocols, Skills, ControlBoardView, Human interface, and reports.

External supervision
   Watchdog in a separate failure domain.
```

Functional layer, source boundary, runtime process, and deployment unit are separate dimensions. Many independently developed Modules do not require the same number of processes, services, or state owners. The Kernel supports all four functional planes without containing their depth. Canonical state primarily serves Memory OS and Harness; the instrumental and cognitive layers serve Smart; Watchdog, Doctor, and learning loops serve Meta. The Kernel owns the logical lifecycle and fencing of Modules; the external Host Supervisor performs the physical lifecycle of approved generations and remains available when the main process fails.

**Micro-modularity** means a material capability can be isolated as a bounded cell with:

```text
one causal responsibility and one lifecycle owner;
an explicit public contract, inputs, outputs, and owned mutable state;
allowed effects and an authority boundary;
typed dependency ports and one-way dependency direction;
an independent proof surface;
failure, replacement, migration, and removal boundaries.
```

A Micro-module may be a source module, package, sandboxed component, process, service, or remote worker. The Architecture does not prescribe its physical form. Internal dependencies of a material capability follow these layers:

```text
contract
→ domain or pure core
→ ports
→ adapters
→ service or lifecycle
→ agent or human surface.
```

This is a direction of responsibility, not a required directory layout. The core does not depend on a specific vendor, transport, store, sandbox, or UI; adapters gain no right to decide task truth, policy, or finish.

The Architecture sets no maximum size, line count, token count, file count, package count, or Module count. The current need for smaller causal worksets follows from model-context limits, parallel agent development, and failure localization. Split or merge decisions depend on the Effective Context Profile, dependency fan-out, build and test cost, failure isolation, replacement cost, and Product Pulse. Better models may permit larger units; observed drift may require further separation without changing the Architecture.

A new or materially changed capability first runs in the least-privileged **Experimental Contour** sufficient for its function:

```text
bounded sandboxed component — pure, capability-limited logic;
isolated worker — OS, tool, credential, or resource-heavy work;
integrated runtime generation — only after demonstrated benefit with equivalent conformance and recovery guarantees.
```

The Implementation selects concrete technologies. No contour is a mandatory maturity ladder: a capability may remain isolated permanently when that is simpler and sufficiently efficient. Promotion proceeds through contract and conformance, replay, effect-free shadow, bounded canary, active generation, drain and retire, or forward rollback. A published generation is immutable; an active Module does not rewrite itself in place.

The hot path contains only bounded, observable, and sufficiently stable operations over compatible state. Model reasoning, research, compilation, broad indexing, heavy verification, and curation run outside the synchronous decision boundary and publish versioned projections or receipts. Added depth must not silently increase hot-path latency or failure domain.

Dependencies are required, optional, or advisory. Failure of an optional Module reduces only the associated capability. The hard-dependency graph from the Kernel outward is acyclic. Isolation follows failure semantics: pure cancellable computation may share a runtime; untrusted, blocking, credential-bearing, resource-heavy, or crash-prone capability receives a stronger boundary.

**ARCH-MOD-01 — Small living Kernel.** Failure of an agent, model route, graph, Dreamer, UI, or adapter must not destroy canonical state or independent work.

**ARCH-MOD-02 — Depth is additive and micro-modular.** New depth is added through independently understandable, testable, and replaceable capability cells; their size and physical form remain empirical Implementation decisions.

**ARCH-MOD-03 — One causal responsibility, one owner, one proof, one replacement boundary.** A material capability has one causal and lifecycle owner; each mutable state it owns has exactly one owner; the capability has an independently invocable proof surface and a declared replacement boundary. A stateless capability declares the absence of mutable state explicitly. Physical packaging remains empirical; ownership does not.

**Why:** `ARCH-MOD-02` prevents premature size constraints but does not by itself expose blurred ownership. Loss of causal responsibility—not size—destroys independent verification, replacement, and failure localization.

**Violated when:** one mutable state has two owners; a stateful capability has no owner; a capability lacks independently invocable proof; changing one causal responsibility requires simultaneous edits across several owners without a declared contract wave; or the replacement boundary is unnamed.

**ARCH-PORT-01 — Organs and execution contours are replaceable.** Models, agents, harnesses, tools, storage, protocols, and isolation technologies are replaced through capability, conformance, migration, and failure contracts; public inheritance transfers, while tacit strategy is reevaluated.

---
# A3. WorkScope and a Changing World

A WorkScope may be:

```text
a Git repository;
an ordinary directory;
a document or media set;
a service or runtime;
a remote system;
a GUI or professional workspace;
a research corpus;
a composite workflow;
an ad hoc task.
```

Git is one truth surface, not a universal identity system.

A WorkScope contains:

```text
identity and owners;
resources and external systems;
Terrain;
truth surfaces and verifiers;
privacy and authority boundaries;
current generations and State Fence;
available and missing capabilities;
watchers and change signals.
```

At first contact, the Workspace Bootstrap Scanner builds a provisional profile from active roots, files, manifests, services, process state, host capabilities, and known integrations. It need not understand the project completely at once.

A change to a resource generation, task revision, policy, or integration state invalidates only dependent views, results, and leases. Independent state remains valid. Expansion, contraction, merge, split, or transfer of a WorkScope is an explicit transition: old evidence never acquires a new scope silently, while continuity is preserved through provenance and revalidation.

When an adapter is unavailable, ELIOT:

```text
finds another competent surface;
performs a direct read or cheap reversible probe;
accepts a human report as an observation;
narrows the claim or action;
records the unknown and representation gap;
blocks only the dependent effect.
```

A composite WorkScope does not promise hidden global atomicity. Cross-scope outcomes remain explicit.

**ARCH-SCOPE-01 — Scope before reuse.** Memory, authority, and proof are used only in the domain and version for which they have support.

---
# A4. Cognitive Inheritance and Memory

## A4.1. What ELIOT Stores

ELIOT memory is not a text warehouse, but a governed history of cognition and action.

Memory functions differ:

| Function | Preserves |
|---|---|
| Working/continuity | Active bindings, plans, blockers, alternatives, next boundary |
| Episodic | Anchored traces of events, actions, and outcomes |
| Semantic | Concepts, propositions, relations, and scoped models |
| Procedural | Procedures, Skills, verification, and transfer boundaries |
| Prospective | Commitments, deadlines, triggers, and deferred intentions |
| Source/epistemic | Provenance, competence, dependence, status, and validity |
| Normative/social | Goals, policies, precedents, and contested norms |
| Negative | Failures, avoidance, reopen conditions, and extinction conditions |

These functions may share one substrate. They do not require separate databases, but must remain semantically distinct.

## A4.2. Capture First, Organize Later

A working agent reports natural-language and structured observations:

```text
what it saw;
what it decided;
what it changed;
what failed;
what outcome it obtained;
what remains unknown;
what may matter later.
```

It need not know the internal ontology, table, relation, or lifecycle status.

The Governor adds available metadata: session, task, WorkScope, time, source, touched resources, State Fence, authority, and privacy. When the semantic type is unclear, the material is preserved as an **Observation Candidate**.

ELIOT prefers an imperfect observation with provenance to losing it because of poor form.

**ARCH-MEM-01 — Capture first.** The agent solves the primary task; ELIOT handles memory classification, linking, curation, and lifecycle.

## A4.3. Git-Like History and Recoverable Fallibility

ELIOT permits incorrect observations, hypotheses, summaries, and procedures. Semantic error is not structural corruption.

History principles:

```text
a raw source or episode is never rewritten silently;
a correction creates a forward revision or supersession;
rival theories may coexist on parallel branches;
merge follows evidence and practical tests;
a snapshot or backup creates a recovery point;
an error remains diagnostic material;
privacy erasure is a separate governed process.
```

Even poisoned memory may temporarily enter the canon as a Candidate. The system must bound its influence, revoke dependent representations, and recover without destroying forensic history.

**ARCH-MEM-02 — Semantic fallibility is recoverable.** Incorrect information may exist as visible, versioned, and revocable state; hidden rewriting of history or provenance is prohibited.

## A4.4. Information Lifecycle

Unified semantic flow:

```text
perceive
→ anchor source
→ capture observation
→ classify or retain as candidate
→ reconcile with existing state
→ store or revise
→ bind activation routes
→ retrieve or activate
→ compile Active View
→ use in inquiry or action
→ observe outcome
→ update epistemic position
→ consolidate or reconsolidate
→ adjust accessibility or influence
→ evaluate improvement.
```

This is a proof normal form, not a requirement to execute every stage synchronously for every read. A reversible probe may precede full curation. A material decision must be reconstructible through the applicable part of this chain.

An observation does not become a verified claim, instruction, procedure, policy, or proof merely because a model paraphrased, combined, or repeated it. A change of semantic role or status requires an explicit transition with provenance and a receipt.

**ARCH-LIFE-01 — No semantic teleportation.** No hidden transition exists among observation, interpretation, authority, and proof.

## A4.5. Evidence, Relations, and Continuity

Reusable memory has at least one observable activation route: world or task cue, commitment, relation, or scheduled review. Material without one remains cold inheritance; it is neither rejected nor lost.

A load-bearing record preserves:

```text
source and exact anchor;
question, scope, and time;
observation or proposition;
epistemic status;
support and counterevidence;
relations and dependencies;
conditions of applicability;
revision or revalidation route;
allowed influence.
```

Relations have type, direction, scope, provenance, and epistemic status. Similarity, co-change, sequence, and graph proximity do not create causality automatically.

Identity is type-relative. Renaming a file, restarting a service, or rewriting a procedure does not always create a new object; split and merge remain hypotheses until supported by evidence.

## A4.6. Memory Transformation

Summary, merge, episode synthesis, concept formation, procedure synthesis, and compaction are not neutral formatting. They must preserve:

```text
primary evidence;
lineage;
minority evidence and counterevidence;
uncertainty;
temporal and scope distinctions;
conditions of applicability;
a path back to sources.
```

Transformation quality is evaluated by coverage, preservation, faithfulness, lineage, and reversibility.

Where a fragment carries evidentiary weight, an exact quotation is preferable to a generative paraphrase. A paraphrase may alter wording, lose a qualification or negation, or combine claims from several sources; verifying it therefore requires a separate faithfulness check. An exact fragment preserves source wording, supports mechanical correspondence checks, and binds a claim to a specific location. Paraphrase remains useful for navigation and overview, but does not replace quotation in a conclusion's evidentiary basis.

**ARCH-MEM-03 — Derived memory does not replace evidence.** Dreamer, a model, or a deterministic compiler may create useful representations, but cannot elevate authority or destroy source history.

## A4.7. Accessibility, Support, Influence, and Erasure

Four properties are independent:

```text
whether the record exists;
how strongly it is epistemically supported;
how accessible it is to retrieval or attention;
what influence it is permitted to exert.
```

Forgetting governs accessibility and influence. Belief revision changes support. Privacy erasure changes physical existence.

Retrieval, citation, repetition, and model agreement do not strengthen memory by themselves.

**ARCH-MEM-04 — Retrieval is not reinforcement.** Future influence changes only through outcome-linked evidence, correction, or an explicit lifecycle decision.

---
# A5. Reality, Epistemic Position, and Theories

## A5.1. Reality and Observation

Reality is not stored inside ELIOT. ELIOT stores bounded observations and models.

Every observation has two independent attributes:

```text
Capture route:
self-reported | harness-observed | independently observed.

Evaluation status:
raw | screened | verifier-backed | contested | stale.
```

Verifier-backed does not mean independent. A human report is admissible as an observation with provenance, but not automatically as verification of an external fact.

## A5.2. Current Epistemic Position

For a specific question, scope, and time, ELIOT shows:

```text
direct observations;
supported models;
assumptions;
rival models;
conflicts;
stale or superseded positions;
unknowns;
required inquiry.
```

One canonical owner provides one transition history, not one mandatory interpretation.

A fresh observation always updates evidence state. It need not blindly replace a stable model: an outlier, transient, sensor error, or correlated failure creates a conflict and inquiry.

**ARCH-EPI-01 — Reality corrects; positions remain defeasible.** Current Epistemic Position is the best-supported working model, not an internal truth object.

## A5.3. Theory Portfolio and Epistemic Fitness

For a complex question, ELIOT preserves several competing models.

A theory gains weight from:

```text
independent evidence;
correct discriminative predictions;
successful practical tests;
transfer to a new scope after revalidation;
explanatory sufficiency without unnecessary assumptions.
```

A theory loses weight from:

```text
a failed prediction;
an error in a downstream artifact or procedure;
counterevidence;
poisoned or dependent lineage;
stale competence or scope;
correlated swarm or evaluator agreement.
```

Practical success is scoped and revocable. When a theory breaks dependent theories, procedures, or artifacts, it opens review rather than becoming dogma.

**ARCH-EPI-02 — Theories earn and lose weight through outcomes.** Knowledge develops through evidence, prediction, experiment, and correction; eloquence, age, and votes do not create truth.

## A5.4. Time and State Fence

Load-bearing state preserves:

```text
valid time;
known time;
transaction time;
resource generation;
task, policy, and integration revisions.
```

The Governor assigns canonical causal order. External timestamps remain observations. Lease expiry and local scheduling use monotonic-compatible clocks; a clock anomaly creates a Problem State and revalidation, not a silent authority extension.

A State Fence contains only dependencies capable of changing the decision. A change to an unrelated resource does not invalidate the entire task.

## A5.5. Verifier and Evaluation Contract

An Evaluation Contract defines:

```text
the property measured;
the scope, environment, and version;
permitted inputs and outputs;
uncertainty and freshness;
known failure modes;
conditions that make the result inapplicable.
```

The System Owner authorizes installation and credentials. The WorkScope Owner accepts local use. The Governor binds the verifier to an acceptance item and checks scope and freshness. Competence is demonstrated through outcomes, not registration.

As impact increases, the system relies less on the actor's self-report. A Critical result requires an observation or evaluation route outside the actor's failure domain when practical; otherwise, finish remains honestly degraded.

A model evaluator is admissible for a subjective property, but its model name does not make it independent.

## A5.6. Inquiry and Unknowns

An Unknown is a first-class state. It contains:

```text
the question;
why it matters;
the decision that depends on it;
the observation that would distinguish the alternatives;
the cheapest safe probe;
what is expected if the hypothesis is true and if it is false;
what counts as falsification;
how the model changes if the probe fails;
the inquiry stop condition.
```

ELIOT distinguishes pragmatic action from epistemic action. Inquiry is selected by discriminative power, expected information gain, risk, reversibility, cost, and opportunity cost.

Inquiry operates at four nested scales that must not be conflated:

```text
micro   candidate → verifier → exact counterexample → minimal repair → repeat;
meso    bounded work packet → independent verification → result admission;
macro   explanation review: which action most changes the decision;
outer   system learning from completed and verified runs.
```

If every local error sends work back to a general review of the goal, the organization is too coarse. If explanations are never reviewed, the system optimizes answers rather than understanding.

A correct result may be: "Evidence is insufficient; the safest useful next step is X."

## A5.7. Confirmatory and Exploratory Lanes

Exploration and confirmation are different modes of working with evidence. If a participant sees the data, invents an explanation from it, selects a method, and then declares confirmation, exploration silently becomes answer optimization. A load-bearing conclusion therefore follows one of two explicit lanes.

### Confirmatory Lane

Before result exposure, record the question, hypothesis, protocol, primary outcome, exclusion criteria, quality controls, decision rule, evaluator, and budget. After the freeze, do not silently change the primary metric, exclude an inconvenient case without a rule, weaken the claim, replace the evaluator after seeing the result, or hide failed runs. Declare deviations explicitly and label all subsequent analyses exploratory.

Acceptance in the confirmatory lane does not depend on result direction. A correctly obtained negative result is a complete outcome, not failed work.

### Exploratory Lane

Exploration may generate hypotheses, change the frame, vary analysis, and search for new representations. Its output remains an exploratory finding, not confirmation. Promotion to confirmatory status requires an independent basis: a new holdout, independent run, preregistered test, replication, formal proof, or another sufficient truth surface.

**ARCH-EPI-03 — Exploration cannot confirm itself on the same evidence.** Data that generated a hypothesis are not an independent confirming test of that hypothesis.

**Why:** this applies beyond statistics. Traces used to discover a repair are not a held-out regression; examples used to evolve a Skill are not the final evaluation; sources used to construct a causal account are not its independent validation; cases used to tune a simulator are not evidence of transfer to real load.

### Evidence Freeze

Before synthesis, freeze a revision of admitted evidence: what was included, what was excluded and why, which conflicts remain unresolved, and which research debts remain open. The synthesis author may not add a new fact silently outside admission. A report is a projection of the frozen revision, not a truth source; correcting wording must not require rewriting history.

### Coverage Denominator

Completeness and absence claims are valid only against a declared, frozen, and independently recheckable denominator. A top-k result, exhausted budget, stopped agent, or lack of new search results does not authorize a claim that nothing exists.

**ARCH-EPI-04 — Coverage requires a denominator.** A coverage or absence claim must name its scope, revision, and method by which the denominator can be checked independently.

### Rigor Is Selected, Not Inherited

Lanes, freeze, denominator, and claim audit are not a separate product. They form a rigor level selected for a specific information task according to impact and reversibility. A quick lookup and a full investigation use the same contour at different levels; the system must be able to raise the rigor prospectively for remaining work at any time rather than switch to another subsystem. Evidence already exposed retains its original lane and grade: raising rigor does not retroactively make it confirmatory and requires new independent support for a stronger claim.

---
# A6. Understanding State and System-Level Understanding

## A6.1. What Counts as Understanding

Decision-adequate understanding answers:

```text
what exists;
what it means and to whom;
why it exists;
how it is related;
how it changes;
why outcomes occur;
what is known and unknown;
which alternatives are plausible;
what an intervention is likely to cause;
what would distinguish competing explanations.
```

It may be incomplete. The defect is not an unknown, but a hidden unknown, false certainty, or loss of distinctions that could change the decision.

## A6.2. Representation, Episode, and Competence

- **Understanding State** is an inspectable public representation.
- **Cognitive Episode** is the interpretation and action occurring now.
- **Understanding Competence** is a route's ability to construct and apply a model.

Neither storage nor a model alone exhausts understanding. Without external state, cognition becomes amnesic; without active semantic judgment, it becomes an organized archive. Understanding State is a governed view and a set of rebuildable projections over Canonical Memory and current observations, not a second semantic store. WorkScope Understanding is scoped; the cross-scope System Self-Model is stored separately and does not transfer project claims automatically. Route Continuation State may support continuation of the same route, but hidden reasoning never becomes durable knowledge, proof, or a reward target; ELIOT preserves public rationale, evidence, and decision state.

**ARCH-UND-01 — Load-bearing understanding has a public expression.** A decision must be reconstructible from evidence, models, alternatives, unknowns, and rationale, not from hidden thought.

## A6.3. Layers of Understanding

```text
goal/value — what is required and why;
semantic — entities, roles, and meaning;
structural — boundaries, components, and dependencies;
dynamic — states, flows, and transitions;
causal — mechanisms, interventions, confounders, and counterfactuals;
normative — invariants, policies, commitments, and contested norms;
epistemic — evidence, rivals, unknowns, and source competence;
historical — decisions, failures, changes, and outcomes;
operational — current environment, capabilities, and degradation;
metacognitive — coverage, competence, bias, and calibration.
```

Meaning is not reducible to observed behavior. ELIOT distinguishes intended or declared meaning, institutional role, operational behavior, counterfactual consequences, and significance for different participants. Divergence among them is a model conflict, not a reason to select one layer silently.

The Concept Pyramid is a navigation projection:

```text
charter → system map → subsystem capsule → module or workflow card → exact evidence.
```

It is not understanding itself and may be rebuilt.

## A6.4. Graphs and Artifacts

ELIOT uses several graph planes:

```text
static code and dependency graph;
behavioral and co-change graph;
causal experience graph;
execution and task graph;
artifact-lineage graph;
concept and normative graph.
```

Tools anchor structure; agents interpret meaning; artifacts, tests, and outcomes correct both. Orientation is exact-first: a known handle, path, symbol, or artifact and its typed neighborhood precede broad semantic synthesis. A graph index is a derived projection, not a second owner.

**ARCH-GROUND-01 — Understanding is grounded in tools and artifacts.** A semantic model must remain connected to real files, symbols, services, documents, actions, and verifiers.

## A6.5. Causality

A causal model preserves:

```text
mechanism;
intervention;
predicted observable;
counterfactual;
possible confounders;
interacting causes;
temporal lag;
abstraction level;
rival explanations;
transfer boundary.
```

A successful outcome supports the effect, but not necessarily the claimed mechanism. A causal edge is hypothetical, supported, or observed-under-intervention.

A coherent narrative does not by itself demonstrate understanding. A causal or operational model earns trust by distinguishing rival explanations, preregistering an observable, and surviving an intervention, verifier, or real artifact outcome; mismatch corrects the model.

**ARCH-UND-02 — Causal understanding is tested by discriminative prediction and outcomes.** The test is not the elegance of an explanation, but its ability to distinguish alternatives, predict consequences, and correct itself against reality.

## A6.6. Correctness and Reconstruction Cost

Understanding State may be large. An Active View must be bounded, but never at the expense of decision-relevant correctness.

Priority order:

```text
fit to reality and evidence;
decision sufficiency;
visible uncertainty and alternatives;
timely accessibility and usability;
then reconstruction cost, latency, and token economy.
```

When understanding does not fit, ELIOT decomposes the task, exposes primary evidence, creates sequential views, or changes route. Silent loss is prohibited.

## A6.7. ELIOT Self-Knowledge

The Architecture is part of cognitive inheritance. The System Self-Model distinguishes:

```text
Constitutional — what ELIOT is intended to mean;
Implemented — what has actually been built;
Operational — what is currently available or degraded;
Experiential — incidents, repairs, and learned limits;
Epistemic — what is demonstrated, contested, or unknown about the system itself.
```

The exact adopted Architecture revision is normative. A summary, audit, code shape, or runtime behavior is a projection or evidence, not a source of constitutional authority.

Before a Material change to ELIOT itself, the Active View includes applicable principles, rationale, conformance gaps, and affected guarantees. Contact with an ELIOT Module or capability activates related Architecture anchors just as a project cue activates working memory.

Architecture Knowledge is a protected primary source. Dreamer briefs, audits, code comments, and summaries remain projections. A live conformance map binds Intent and `ARCH-*` anchors to an implementation owner, mechanism, failure behavior, and observable status; an Architecture change or divergent runtime invalidates dependent briefs and opens an explicit gap.

The Architecture revision digest and conformance state belong to integrity anchors and the recovery manifest.

After a model or harness change, **Common Ground** is checked: not only summaries, but goals, decisions, invariants, rival models, unknowns, commitments, and action consequences must survive. Public inheritance transfers; tacit competence and interpretation strategy require requalification.

**ARCH-SELF-01 — ELIOT knows its purpose and state.** The self-model supports diagnosis, recovery, and improvement, but never authorizes self-certification or unilateral Architecture changes.

---
# A7. Attention, Context, and Skills

## A7.1. Active Understanding View

A view is compiled for a specific `model × task × harness × tools × inference regime`.

Semantic order:

```text
goal, acceptance, and commitments;
blocking attention;
current epistemic position and rivals;
semantic and causal model;
done, open, deferred, and killed work;
invariants and negative memory;
unknowns and inquiries;
exact load-bearing evidence;
available and authorized affordances;
next action, expected observable, verifier, and stop condition.
```

A view uses one applicable State Fence or explicitly marks stale or incompatible sections.

At an action boundary, the system creates a concise **decision-local tail**: current goal, load-bearing position, exact atoms, do-not-use items, next action, expected observable, verifier, and stop or revision condition. Its layout is validated against the Effective Context Profile rather than frozen as permanent prompt magic.

**ARCH-CTX-01 — Decision sufficiency before size optimization.** Context must preserve distinctions that could change the decision, risk, verifier, or unknowns.

## A7.2. Attention

Selection considers:

```text
goal and commitment relevance;
expected decision delta and information gain;
risk, urgency, and irreversibility;
prediction error, novelty, and surprise;
negative memory and invariants;
minority evidence and counterevidence;
source competence and independence;
opportunity and switching cost;
route-specific usability.
```

The current frame may be wrong. High-impact work therefore preserves bounded exploration: rival-frame challenge, counterevidence search, and coverage-gap review.

## A7.3. Three Orientation Channels

### Push

World or task contact activates related memory through a file, symbol, error, command, service, document, deadline, commitment, or anomaly.

### Pull

The agent knows what it seeks and requests handles, facts, relations, or cases.

### Dreamer Orientation

The goal is known, but hidden relations and memory content are not; Dreamer builds a bounded, problem-oriented packet.

Default:

```text
current task or commitment
→ exact cue, entity, or path
→ typed relations
→ bounded retrieval
→ Dreamer synthesis.
```

Retrieval, graph activation, and Dreamer search only produce candidates. Admission to an Active View depends on scope, freshness, provenance, epistemic status, expected decision delta, risk, and cost. The reason for every material inclusion or suppression must be reconstructible.

**ARCH-CTX-04 — Retrieval proposes; Context Compiler admits.** A retrieved item gains no influence merely because it is similar or available.

**ARCH-CTX-02 — Observable state drives proactive memory.** Useful memory must not depend solely on whether the agent remembered to call recall.

On a host without event integration, push degrades to mandatory delivery at the next available boundary and a visible obligation; ELIOT does not pretend prevention exists when it does not.

**ARCH-CTX-03 — Decision locality is route-profiled.** Load-bearing control state is placed where a particular route uses it most reliably at the decision boundary; mechanical repetition does not increase epistemic support.

## A7.4. Context as Intervention

Inclusion, omission, ordering, repetition, and schema change inference. Every material element has a role:

```text
governing instruction;
authoritative state;
evidence;
hypothesis;
prior narrative;
rejected path;
affordance;
untrusted payload.
```

Untrusted content may influence through priming and framing even without authority. Provenance, placement, and repetition are therefore governed. Every material inclusion or suppression has a source handle and concise, explainable reason; otherwise Context Compiler errors cannot be diagnosed.

Semantic screening occurs before the hot boundary or asynchronously. Hot admission, attention, and authority gates do not wait for an LLM: they use persisted attributes or return a bounded inquiry or unknown. An unscreened item is available as quoted evidence or a handle, but cannot be the sole basis for a Critical action.

## A7.5. Critical Attention

Critical Attention is a durable obligation, not a message.

It has:

```text
owner;
affected scope and actions;
evidence;
delivery state;
resolution state;
deadline or review condition;
escalation route.
```

Acknowledgement means receipt, not resolution. Expiry changes the owner or channel; it does not delete the problem.

**ARCH-ATTN-01 — Critical Attention is state, not a message.** A blocking obligation persists until evidence-backed resolution, authorized waiver, or supersession.

## A7.6. Compaction and Resume

Compaction is a reconstructive transformation. Before the boundary, preserve:

```text
goal and commitments;
current and rival models;
done, deferred, and killed paths;
blockers and exact anchors;
pending verifiers;
next action;
State Fence;
explicit losses.
```

Resume distinguishes:

```text
exact continuation of the same route;
reconstruction from public inheritance;
clean reset.
```

They are not equivalent. Continuation state does not become knowledge or authority.

## A7.7. Governance Profile

An integration is described by a vector:

```text
Observation: absent | self-reported | host-observed | independently observed;
Enforcement: absent | advisory | interceptable | enforced;
Supervision: absent | self-monitored | watchdog-observed | independently supervised.
```

Policy may reduce the profile to a grade for a specific action class, but the Architecture defines no universal scalar. A claim is no stronger than its relevant weakest axis.

## A7.8. Effective Context and External Metacognition

Each material route and task family maintains an Effective Context Profile and Safe Operating Envelope. The Capability Registry in A11.3 defines the full dependency set; a change to any load-bearing dependency makes the profile provisional.

The Governor and Watchdog compute external signals:

```text
coverage — where understanding and evidence are sufficient, thin, or blind;
novelty — how far the task lies outside verified inheritance;
danger — hotspots, failures, and irreversible boundaries;
calibration — how well predictions and decisions match outcomes;
integration confidence — which observations and enforcement are actually available.
```

This is neither mind reading nor a single understanding score.

## A7.9. Context Economy

An Agent Work Unit is admitted to a route only when its Safe Operating Envelope can contain the current goal and acceptance criteria, applicable Intent and Hard Boundaries, the current capability contract, one-hop dependencies, exact evidence, tools and instructions, and sufficient reasoning and review margin. Nominal context maximum does not justify assigning an agent the entire system. If the decision-sufficient workset does not fit, decompose the task, compile a dependency view, or select a demonstrably better route.

The Architecture does not turn the current effective context into a permanent Module limit. Workset and Module size are Empirical Profiles that may change with the model, harness, tools, task family, and projection quality.

After correctness, measure reconstruction cost, avoided exploration, repeated context, latency, cost, human attention, and missing-context regret. Noncritical injection should be token-negative: it should replace more expensive independent orientation rather than merely add text. This metric never justifies losing decision-relevant distinctions.

## A7.10. Skills

A Skill should be concise:

```text
trigger;
intent;
immediate action;
required writeback or output;
stop or escalation;
where not to apply;
challenge path.
```

Deep semantics live in the Architecture, state, contracts, and tools. A Skill neither forces an agent to administer Memory OS nor serves as an enforcement boundary. For the Main Agent, the basic instruction kernel reduces to five actions: synchronize material state; report material observations, decisions, failures, and outcomes; act within visible authority; verify before claiming completion; challenge or escalate a false block. Conflicting instructions or Skills become explicit state and are resolved by source, authority, scope, and Intent—not by text order or the latest message.

**ARCH-SKL-01 — Instructions are intent-dense and recovery-oriented.** Few words, one meaning, a clear next step, and a clear exit from a false block.

---
# A8. Watchdog

## A8.1. Purpose

Watchdog is a separate daemon in an independent failure domain. It operates continuously and independently **during every declared active ELIOT interval**: while there is an observable Session or agent job, active work in a registered WorkScope, a maintenance or recovery operation, an external effect under supervision, or a supervision policy explicitly enabled by the user. When ELIOT is unused and no such obligation exists, Watchdog and the other processes may stop after preserving observation cursors, unresolved control state, and future wake intent. This does not weaken supervision: the system claims coverage only for the active interval it actually observes and exposes blind gaps explicitly.

It observes whether the ELIOT contour operates as declared:

```text
whether Kernel, Governor, Doctor, hooks, and integrations are alive;
whether ELIOT can observe agent actions;
whether observations and outcomes are arriving;
whether one failure repeats without new evidence;
whether the canonical path is bypassed;
whether queue pressure, stale state, or repair loops are growing;
whether a security, injection, or exfiltration signal appeared;
whether Architecture, Implementation, and runtime diverge.
```

Watchdog does not decide project semantics, task goal, factual conflicts, policy, or completion.

**ARCH-WDG-01 — Independent supervision.** At least part of liveness, process, workspace, and integration activity is observed outside Governor and primary-agent self-report throughout every interval for which ELIOT claims independent supervision. Observable use activates this contour; outside an active interval, an inactive Watchdog is not presented as observation or coverage.

## A8.2. Hybrid Structure

### Deterministic Layer

During an active supervised interval, it continuously and cheaply checks:

```text
processes and heartbeats;
hook cadence and sequence gaps;
workspace and filesystem activity;
protected process and path activity;
queue, storage, and budget pressure;
Module health and restart history;
version, configuration, and plugin registration;
authority epochs and stale owners;
telemetry completeness.
```

### Watchdog Agents

They run briefly for a specific question:

```text
explain an anomaly;
check conformance;
analyze a repeated failure;
perform a security audit;
form probe or repair alternatives;
prepare a concise brief for an agent or person.
```

They use inexpensive models under human-approved policy. For high-impact uncertainty, Watchdog may invoke a route from another vendor or model family, or Concilium—but not voting.

## A8.3. Signal, Problem, and Incident

```text
Signal — an observed deviation;
Problem State — a durable governed problem;
Incident — a severe problem involving integrity, authority, security,
           critical telemetry, or a dangerous unresolved effect.
```

A model assessment cannot open a blocker or Incident by itself. A deterministic rule, policy, or authorized Human decision does so.

A Signal preserves evidence and may be:

```text
informational;
warning;
blocking obligation;
incident candidate.
```

Processing, delivery, and resolution are independent. Acknowledgement does not close a problem.

## A8.4. Supervising Agent–ELIOT Interaction

A Material task expects an Interaction Heartbeat:

```text
session or task sync;
context boundary;
action intent;
material tool outcome;
failure;
verification;
finish attempt.
```

If an agent continues changing the workspace while observations disappear, Watchdog:

```text
records the gap;
downgrades supervision evidence;
requires resynchronization;
limits ELIOT-issued authority and verified finish for dependent high-impact work;
physically stops an external effect only where the actual Enforcement axis permits it;
notifies the Human when the problem persists.
```

The deterministic layer records observable divergence. Whether declared Intent remains preserved is a fallible assessment by a Watchdog Agent, Main Agent, or Human and creates no authority by itself. Departure from a Skill or cadence is a Signal, not an automatic violation, when task evidence and recovery remain sufficient.

**ARCH-WDG-02 — Watchdog supervises preservation of declared intent, observable outcomes, security, and recovery.** Its purpose is to detect loss of control and quality, not to enforce ceremony or become a semantic oracle.

## A8.5. Security Supervision

Watchdog monitors:

```text
prompt, tool, or memory injection;
authority laundering through a summary or tool echo;
unusual bulk rewriting of memory;
an attempt to write directly to storage;
a remote query with exfiltration intent;
secret exposure;
a poisoned source or resurrection after restore;
an invisible change of model, provider, or Tool Definition.
```

It assesses source and effect risk, but does not assign epistemic truth.

## A8.6. Recovery and Escalation

After a Module failure or repeated failure, Watchdog does not repeat one command indefinitely. It changes approach:

```text
a different diagnostic hypothesis;
a different tool or observation route;
a different model or vendor;
a bounded adversarial audit;
an alternate Module or route;
quarantine and Human escalation.
```

Critical information is delivered to the primary agent and Human Control Plane as a Diagnostic Brief: symptom, evidence, impact, attempted repairs, unknowns, and the next safe action.

---

# A9. Dreamer

## A9.1. What Dreamer Is

Dreamer is a separate supervised AI service or server. It uses a large LLM, short-lived agents, and, when necessary, a swarm where deterministic processing is insufficient.

Dreamer is not:

```text
Memory OS;
Governor;
a canonical writer;
the Researcher acquisition layer;
a universal supervisor;
a source of factual truth;
the owner of Architecture, policy, or completion;
an autonomous controller of spending.
```

The persistent element is the service role and its contract, not a continuously running process or LLM loop. Dreamer starts on demand for an active query, job, or maintenance obligation and may stop with ELIOT outside an active interval. Standard job loop:

```text
request or problem
→ bounded evidence bundle and State Fence
→ route, budget, and privacy decision
→ one agent or swarm
→ structured candidate + lineage + uncertainty
→ form, provenance, and loss checks
→ delivery to Main Agent, Human, or Governor
→ separate governed transition or rejection.
```

Dreamer always returns a candidate. Under human-approved policy, the Governor may automatically accept only mechanically verifiable, reversible changes to derived projection, organization, or activation metadata when sources, epistemic support, dissent, and meaning are preserved; no hard block is created; and an undo path remains. Semantic relations or merges, causal explanations, procedures, conflict resolution, changes to support or Current Epistemic Position, material forgetting, policy, authority, privacy, and promotion require a separate authorized decision or verifier-backed transition.

**ARCH-DRM-01 — Dreamer is an instrumented intelligence service.** It expands the hypothesis space and organizes knowledge, but returns candidates rather than authority.

## A9.2. Primary Modes

### Background Curation

Dreamer analyzes Observation Candidates, episodes, relations, contradictions, duplicates, failures, and procedures. Background jobs are selective, batched, checkpointed, and problem-driven; one observation does not create one LLM call. It proposes:

```text
classification and relation candidates;
episode reconstruction;
concept refinement;
duplicate or false-merge repair;
Failure Fingerprints;
procedure or Skill candidates;
reconsolidation and forgetting candidates;
Memory Repair Candidates.
```

### Interactive Orientation

A Main Agent or Human may ask:

```text
what ELIOT knows about this task;
which decisions, failures, and alternatives relate to this area;
which contradictions and gaps exist;
which ARCH principles are affected;
what we are likely missing;
which inquiry offers the greatest value.
```

Dreamer returns a problem-oriented packet, not a SQL or graph dump.

### Clarification

Dreamer may ask the active agent one concise question when an observation is material but unclear:

```text
what exactly was observed;
what the scope is;
whether it is fact or interpretation;
which outcome is linked to the decision;
when the experience becomes applicable again.
```

A Human is interrupted only when a human-owned decision is required: goal or value, approval, privacy or security, an irreversible effect, cost-envelope expansion, or high-impact ambiguity; or when the Human explicitly requested participation.

### Research Synthesis

Dreamer may:

```text
formulate a research question;
build rival hypotheses;
compare sources;
find contradictions and gaps;
run micro-audits and swarms;
synthesize a Research Brief;
propose discriminative experiments.
```

It works over governed sources and bounded source bundles. Acquisition, parsing, OCR, bulk logs or documents, indexing, and RAG are governed by Researcher, which defines protocol, source admissibility, and coverage discipline; pluggable providers perform the physical work—local search provider, external research federation, or manually supplied source. An unavailable provider is a coverage gap, not a Researcher failure. Raw corpora are not written directly into Cognitive Inheritance: ELIOT preserves bounded observations, source or artifact handles, and necessary exact excerpts.

Research depth is a selected rigor level, not a separate function. The same Researcher serves a quick lookup and a full investigation; the task's Evidence Grade defines the difference.

**ARCH-DRM-04 — Researcher acquires; Dreamer interprets; Governor governs.** Combining acquisition, synthesis, and canonical promotion under one owner creates an uncontrolled data and influence path.

## A9.3. Dreamer and Concilium

Dreamer does not smooth conflict into one narrative. A good result contains:

```text
strongest operational model;
rival models;
independent and shared evidence;
source dependence;
strong objections;
unknowns;
discriminative next steps;
conditions of invalidation.
```

**ARCH-DRM-02 — Dreamer expands and tests the hypothesis space.** Its value lies not in an elegant summary, but in finding hidden relations, alternatives, and useful inquiry.

## A9.4. Launching Agents and Swarms

Dreamer launches agents only through Agent Coordinator and human-approved policy:

```text
allowed models and providers;
local and external routes;
data classes;
job families;
cost envelope;
fan-out and depth;
deadline and stop conditions;
independent-review requirements.
```

Dreamer does not launch a swarm at its own discretion. When expected value does not justify the cost, it proposes a query or small job.

**ARCH-DRM-03 — Dreamer compute is human-governed.** Intellectual depth is controlled by budget, privacy, and explicit automation policy.

## A9.5. Interfaces and Outputs

Three surfaces are theoretically required:

```text
Main Agent ↔ Dreamer;
Human ↔ Dreamer;
Watchdog or system jobs ↔ Dreamer.
```

Typical requests:

```text
Orientation Query;
Memory Query;
Architecture Query;
Research Query;
Curation Request;
Conflict Analysis;
Memory Repair Request.
```

Typical results:

```text
Dream Packet;
Research Brief;
Architecture Brief;
Clarification Request;
Curation Candidate;
Conflict Brief.
```

Every result includes the question, WorkScope and State Fence, evidence handles, model synthesis separated from evidence, rivals, unknowns, coverage gaps, route and cost, and an invalidation condition.

## A9.6. Remote Dreamer

Future online access is permitted only as a bounded question surface. A remote client receives no:

```text
database credentials;
raw canonical browsing;
local filesystem or tools;
write or agent-launch authority;
unfiltered operational telemetry.
```

The gateway authenticates the principal, limits WorkScope and query class, filters inputs and outputs, does not execute embedded instructions, and forwards security signals to Watchdog.

---
# A10. Harness, Agents, Concilium, and Swarm

## A10.1. Agent Interaction Loop

This is a logical control loop, not a synchronous checklist. The Harness performs routine capture, state synchronization, and admission automatically; the agent is interrupted only at a boundary of material uncertainty, conflict, missing authority or verifier, or failure.

```text
1. Attach the session and WorkScope.
2. Restore task, commitments, and Active View.
3. Select an inquiry or action.
4. Record the expected observable for a Material causal decision.
5. Obtain applicable authority.
6. Execute the action through the Harness.
7. Record observations and effects.
8. Run the verifier or preserve the unknown.
9. Update task, memory, and Theory Portfolio.
10. End in one honest finish state.
```

On a host with hooks, this loop is reactive. On a tool-only host, ELIOT uses available boundaries, obligations, and finish discipline without pretending to have full control. A model, tool, or swarm call is justified when it is expected to produce new evidence, change a decision, create an artifact, or provide proof; otherwise it is unnecessary load. A rejected write or action attempt does not disappear silently: the response states the reason, what was preserved, whether retry is possible, which repair, probe, or authority is required, and what action is allowed next.

## A10.2. Impact and Authority

Impact is determined by effect, not by the agent's intent:

```text
Observe — no external change;
Reversible — small local rollback;
Material — changes behavior, several resources, or external state;
Critical — security, schema, credentials, or an irreversible or high-blast effect;
Forbidden — prohibited by an active Hard Boundary or Policy.
```

The Main Agent proposes a class. The Governor derives it from registered tool and effect profiles and affected resources. Uncertainty leads to a probe or temporarily more conservative class, not an indefinite prohibition.

**ARCH-ACT-01 — Effect defines impact and authority.** Risk follows actual affected resources, reversibility, observability, and external consequences—not the agent's confident rationale.

## A10.3. Action Model

A Material or Critical action requires a sufficient external model:

```text
intent and affected scope;
preconditions;
expected effect or observable;
invariants and known failures;
rollback or compensation;
verifier;
stop or revision condition.
```

Existing state may assemble it automatically. The Architecture does not require a ritual essay from the agent. Decision rationale, alternatives, and revisit condition are recorded at the decision boundary; a later explanation is stored as a retrospective hypothesis, not as the original reason.

Contract depth forms a gradient:

```text
Primitive — observation, read, or reversible probe;
Standard — Material action with scope, expected outcome, and verifier;
Deep/Audit — Critical, novel, or highly ambiguous work with rivals, independent challenge, and recovery plan.
```

Depth follows impact and uncertainty, not a habit of writing the maximum contract for every command.

## A10.4. Delegation

Every **Agent Work Unit** receives:

```text
one primary causal property and one primary owner;
an exact question and expected artifact or evidence;
a link to the current goal and acceptance criteria;
a frozen contract revision and applicable Architecture and Implementation handles;
minimally sufficient context: one-hop dependencies, known failures, and exact anchors;
read, write, and impact scope, allowed effects, and explicit non-goals;
the old failing behavior, representation gap, or missing capability;
a discriminator or verifier and proof ceiling;
role, authority, State Fence, budget, checkpoint, cancellation, and stop condition;
a structured output and integration owner.
```

"Small work" means causal closure, not a small number of files or lines. If one defect crosses several owners, decompose it into a contract or evidence unit, independent Module units, an edge or integration unit, and a Product Pulse; never give one agent a hidden cross-system mandate.

An agent may return a Contract Challenge when the selected owner is wrong, the discriminator measures a proxy, the contract is contradictory, or the required proof is unattainable within the granted scope. A challenge is not refusal and is routed to the Task Controller or Concilium.

Within one active task, exactly one Task Controller owns the current plan revision for the Authority Epoch. One mutable artifact scope has one writer; read-only research or audit lanes may run in parallel. Workers do not integrate their own results automatically: a separate integration owner revalidates the State Fence, affected edges, and product outcome. No shared mutable plan exists implicitly.

Goals, instructions, and constraints preserve source, authority, scope, and status: active, superseded, expired, or conflicting. A new instruction is not silently layered over an old one; an unresolved conflict limits only dependent actions and creates an interruption or reframing boundary.

## A10.5. Concilium and Conflicts

A conflict is local. It blocks only transitions that depend on the unresolved issue.

Types:

```text
factual;
scope or time;
semantic or causal;
state or write;
authority;
Watchdog ↔ Agent;
Architecture ↔ Implementation;
testimony or mental state.
```

A Conflict Directive shows observations, candidates, common lineage, unresolved residue, a useful probe, decision owner, and temporarily admissible actions.

Evidence and practical tests outrank consensus. A provisional decision is permitted under explicit risk; dissent is preserved with a revision trigger.

## A10.6. Agent Swarm and Pipeline Work

A swarm is used when decomposition and expected additional coverage justify orchestration cost. A Main Agent or Dreamer requests it only through Agent Coordinator and applicable human policy. A model may propose a plan, but a durable execution graph exists only after dependencies, ownership, effects, budgets, privacy, stop conditions, and proof paths are checked. Free-form group chat is not a control plane.

ELIOT supports at least two compatible pipelines.

Research pipeline:

```text
Map or Audit
→ independent Challenge or Falsification
→ Reduce or Synthesis
→ decision or new inquiry
→ Verify.
```

Engineering pipeline:

```text
Contract or Evidence
→ parallel Module or Capability work
→ affected Edge or Integration proof
→ Product Pulse
→ promotion, rollback, or Mechanism Review.
```

A Main Agent may launch hundreds of narrow exact audits, followed by separate challenge, synthesis, and implementation branches; scale never removes the bounded scope of each Agent Work Unit. When practical, a primary independent auditor does not receive sibling conclusions before submitting its own result; disclosure of later findings explicitly changes the Independence Profile.

A Swarm Plan defines the objective, immutable work-graph revision, budgets, privacy, routes, independence profile, WIP limits, stop conditions, and aggregation and integration owners. Each worker receives a minimum decision-sufficient packet:

```text
shared immutable root: goal, relevant Architecture, current epistemic position;
role and exact work unit;
one-hop contracts and relations plus load-bearing evidence;
allowed tools and effects, non-goals, verifier, and stop condition;
just-in-time fired memory.
```

A whole-project dump and full transcripts of other agents are not defaults. A Structured Result returns artifacts, evidence, uncertainty, unresolved questions, proposed effects, and Evidence Lineage; prose may be an artifact but does not replace these fields.

Confidence depends on:

```text
unique coverage;
Evidence Lineage;
independent observation and evaluation routes;
different failure domains;
different conceptual frames;
strong negative findings.
```

One hundred agents using one packet do not create one hundred confirmations. Synthesis preserves dissent, minority findings, and gaps; it gains no authority to integrate an artifact or declare truth.

Partial verified results survive failure of one branch. Replanning replaces only affected branches. Swarm history remains a trace, but epistemic support for any branch remains defeasible and may be revoked after stale scope, invalid verifier, poisoned shared root, or dependent Evidence Lineage.

**ARCH-SWM-01 — Swarm is a bounded, context-minimal evidence pipeline.** Each attempt performs defined work in a verifiable stage; a swarm expands coverage and capability but never becomes collective truth, a shared-chat control plane, or value authority.

## A10.7. Long-Running Work

Work lasting hours or weeks lives in durable state:

```text
tasks and commitments;
work graph;
Durable Jobs;
checkpoints;
State Fences and Authority Epochs;
Decision, Unknown, Failure, and Artifact ledgers;
Coordination Events;
budgets and progress trends.
```

Assignments, claims, heartbeats, checkpoints, cancellations, and results exist as durable idempotent Coordination Events bound to the work item, causal predecessor, State Fence, and Authority Epoch. A retry uses the same identity; reassignment fences the previous owner first.

Loss of agent context, coordinator, or process does not destroy confirmed work. At reconciliation boundaries, the system reviews State Fences, open Problems and Conflicts, stalled branches, budgets, invalidated evidence, and the next safe action; Watchdog initiates review on drift, not only timeout.

**ARCH-SWM-02 — Swarm coordination survives agents and retries.** Coordination is durable, idempotent, and epoch-fenced; a process is not the sole carrier of an assignment or result.

**ARCH-LONG-01 — Long work lives in durable state.** A session and model route are replaceable executors, not the sole carriers of plan, evidence, and commitments.

## A10.8. Verification and Finish

Finish states:

```text
VERIFIED_COMPLETE;
PARTIAL;
BLOCKED;
FAILED_VERIFICATION;
DEGRADED_NO_PROOF;
UNSAFE_TO_FINISH;
CANCELLED;
SUPERSEDED.
```

Only `VERIFIED_COMPLETE` is called a completed task. Other states honestly preserve artifacts, effects, gaps, and continuation.

Professional work is confirmed by an artifact, admissible method and environment, and an appropriate evaluator—not by plausible prose. An artifact may be code, document, spreadsheet, report, image or video, GUI state, service, or research result; proof matches its modality and required shape.

**ARCH-FIN-01 — Completion is proof-bearing.** ELIOT supports progress under incompleteness but never turns partial progress into done.

---
# A11. Human Control and System Configuration

## A11.1. Human Authority and Fallibility

A Human defines values, goals, acceptable risk, and legitimacy, but may:

```text
lack facts;
change their mind;
hold conflicting roles;
fail to read evidence;
succumb to automation bias;
lose situational awareness.
```

ELIOT therefore not only preserves human authority, but also helps clarify preferences, compare alternatives, and restore state without an active model.

## A11.2. Initial Setup

The trust root is created through deterministic human interaction. The Installation Survey discovers possible agents, harnesses, tools, IDEs, model routes, adapters, and verifiers through safe metadata and version probes.

An unverified executable receives no secrets or elevated authority.

Setup asks only for decisions that materially change privacy, cost, authority, or access to external systems. Everything else receives clear, reversible, visible defaults; advanced configuration remains optional.

The user selects:

```text
which integrations to enable;
which models and routes to use for Main Agent, Workers, Auditors, Watchdog, Dreamer, and evaluation;
local and external data boundaries;
job, task, and period budgets;
which Dreamer and Watchdog jobs may run automatically;
swarm fan-out and depth;
who may approve Critical actions;
whether Remote Dreamer is permitted.
```

A Setup Agent may explain choices after the trust root exists, but creates no authority and writes no configuration without human confirmation.

## A11.3. Capability Registry

The Registry stores observed capability:

```text
installation identity and version;
transport, lifecycle, hooks, and tool coverage;
model route, cost, privacy, and availability;
competence and context profiles;
verifier validity and freshness;
failure-domain and evidence-independence profile;
known biases and failure signatures;
health and allowed WorkScopes and principals.
```

Profile dependencies include model and provider version, inference regime, harness, Tool Definitions, context policy, evaluator, and relevant data distribution. A change to any of them makes dependent profiles provisional until requalification.

## A11.4. ControlBoardView

One canonical, role-filtered projection serves the Main Agent, Watchdog, Dreamer, Human UI, and read-only API.

It shows:

```text
active tasks, plans, swarms, and checkpoints;
Current Epistemic Position, rivals, and unknowns;
conflicts and Critical Attention;
verification and finish readiness;
Governance Profile;
Module, model, tool, storage, and integration health;
Problem or Incident, repair, and recovery state;
memory health and blind areas;
cost and privacy state;
Improvement Candidates;
active goals, commitments, and the safe next action.
```

A Human may inspect evidence; acknowledge or resolve attention; approve, pause, cancel, or replan a task or swarm; challenge a rule; launch a Dreamer or Watchdog query; and perform a recovery action.

## A11.5. Notifications

Notifications have severity, owner, evidence, deduplication, cooldown, acknowledgement, and resolution state. Every unresolved Action-required or Critical item remains in a persistent inbox regardless of a transient toast or channel.

```text
Critical — integrity, security, unknown external effect, or unrecoverable loss of control;
Action required — approval, blocked task, or credential or integration failure;
Warning — repeated agent failure, hook loss, queue pressure, or stale backup or profile;
Info — verified completion, onboarding, or audit or research report.
```

Delivery is not resolution. Alert fatigue and missed notifications are measured.

**ARCH-HUM-01 — Human remains in control without constant micromanagement.** ELIOT automates ceremony while preserving a comprehensible picture, decision points, and the ability to intervene at any stage.

---
# A12. Security, Provenance, and Bounded Influence

## A12.1. Security Assumes Breach

ELIOT does not assume that prompt injection, poisoned memory, a malicious Tool Definition, or a compromised model will always be detected in advance.

Defense is layered:

```text
Hard Boundaries;
buffering;
separation of instruction, data, evidence, and authority;
origin-bound provenance;
bounds on allowed influence and effects;
multiple independent routes;
quarantine and revocation;
backup, restore, and recovery;
Watchdog observation;
Human escalation.
```

**ARCH-SEC-01 — Assume compromise; preserve control and recovery.** Security succeeds when a breach gains no hidden authority, has a bounded blast radius, is detectable, and is reversible.

## A12.2. Principal, Session, and Visibility

Identity is not a model's self-declared string. The harness or installation boundary establishes the principal and binds it to a Session, WorkScope, capabilities, visibility, and Authority Epoch.

Conceptual Session lifecycle:

```text
attach → active → suspended → detached | expired | revoked.
```

Every read, Active View, model bundle, notification, and write is filtered by principal, WorkScope, visibility, and policy. Unknown identity means minimum privilege and no Material authority.

## A12.3. One Governed Write Path

An agent, Dreamer, Watchdog Agent, Doctor, or external service receives no direct canonical write path.

```text
proposal or observation
→ admission and provenance
→ governed transition
→ canonical receipt.
```

A logically single semantic transition atomically binds event and history, current projections, affected revisions, and receipt. If the substrate cannot provide shared atomicity across several scopes or external effects, the system uses an explicit staged or saga transition with visible partial outcomes.

Direct storage access, a shell or database-protocol bypass, or a second writer is a security and integrity problem regardless of how plausible the content appears.

**ARCH-SEC-02 — One canonical transition path.** A recovery interface may preserve intent and evidence, but cannot become a hidden second Governor.

## A12.4. Source Assurance and Injection

A source is assessed on independent axes:

```text
identity and provenance;
integrity and freshness;
domain competence;
incentives and track record;
evidence independence;
privacy and sensitivity;
instruction-injection risk;
deception, exfiltration, and persistence risk;
allowed epistemic use;
allowed effects;
required verifier;
quarantine or review.
```

Instruction Taint asks whether content may command the system. Origin Assurance asks where an observation came from. Semantic Screening asks whether the content was checked for contradiction, overgeneralization, and hidden instruction. These properties remain distinct.

Embedded text never becomes an instruction by virtue of its content. An authenticated Human creates a new direct instruction record within their authority rather than "sanitizing" the source document. Suspicious material need not be deleted: it is isolated, retains provenance, and may be sent to Dreamer for semantic analysis and Watchdog for security analysis in a bounded bundle without elevated influence.

## A12.5. Origin-Bound Influence

A summary, tool echo, agent restatement, Dreamer merge, compaction, or repetition by several agents preserves the source's authority ceiling.

When a source, Tool Definition, verifier, or derived item is found poisoned, revoked, wrong-scope, or invalid, **Influence Dependency Closure** applies:

```text
history and forensic lineage are preserved;
current support and allowed influence are removed;
dependent packets, indexes, procedures, swarm findings, and confidence claims are invalidated;
restore or reindex does not restore influence;
independent evidence may restore support locally.
```

Revocation propagates through explicit dependency closure, not similarity. Incomplete lineage creates scoped quarantine or an unknown, not global memory deletion.

**ARCH-SEC-03 — Influence remains tied to origin and is revocable.** Transformation does not launder provenance or authority.

## A12.6. External Model Routes and Secrets

A model job contains a question, bounded inputs, State Fence, privacy class, route class, budget, deadline, allowed effects, cancellation, and receipt.

Secret and credential lifecycle:

```text
minimum scope visibility;
no transmission to a model, logs, or memory without explicit need;
rotation or revocation after compromise;
no command-line or plaintext leakage;
backup and restore at the same privacy level;
human confirmation before expanding external transmission.
```

Provider fallback never expands data access or cost silently. Provider-native memory is treated as an external source or feed with its own retention and deletion semantics; it does not become a canonical owner, policy, or current support without normal ELIOT reconciliation.

**ARCH-SEC-04 — Model output remains a candidate until a governed transition accepts its effect.** A model role, number of agreeing routes, or confident format creates no authority, factual support, or completion.

Remote Dreamer is a separate external principal and read-oriented semantic surface. It receives no local tools, database handles, write authority, or agent-launch authority.

## A12.7. Skills, Guards, and Challenge

Skills and prompts help, but are not security boundaries.

Defense against a fallible agent:

```text
remove unnecessary ceremony;
automatically capture obvious observations;
enforce Hard Boundaries instrumentally;
observe bypasses and telemetry gaps;
provide a Recovery or Conflict Directive;
provide a legitimate challenge path.
```

A Governed Challenge contains the rule, false block, evidence, a narrower boundary or probe, owner, and review horizon. Independent work continues. When no Hard Boundary is affected, a Recoverable Deviation is permitted.

## A12.8. Privacy Erasure

Privacy erasure is a separate governed process. Within technical and legal limits, it propagates to canonical payload, projections, indexes, Operational Recovery State, Route Continuation State, provider-side copies, backups, and the restore path.

The purge ledger preserves a non-revealing record and deletion scope without reconstructing the content. Restore applies the purge ledger before cutover.

**ARCH-PRIV-01 — Erasure removes future availability without rewriting unrelated history.** Deletion cannot be replaced by suppression, and erased content cannot be resurrected from backup.

---
# A13. Resilience, Recovery, and Observability

## A13.1. Let It Fail Locally

ELIOT follows **let it crash**, but never treats it as indifference to data.

```text
a process or agent may die;
an operation may finish partially;
a Module may be quarantined;
a model result may be wrong;
a queue may reject work.
```

The following must survive failure:

```text
canonical history;
confirmed artifacts and evidence;
ownership and State Fences;
independent work;
Problem State;
recovery entrypoint;
the ability to continue or stop honestly.
```

Resilience has three distinct goals: operational resilience preserves processes, state, and effects; epistemic resilience does not turn missing data into false certainty; cognitive resilience preserves goals, alternatives, commitments, and the ability to continue inquiry.

**ARCH-RES-01 — Fail locally, recover globally.** Failure of an optional capability reduces capability rather than destroying all of ELIOT.

## A13.2. Kernel and Failure Domains

A minimally live Kernel can:

```text
withhold unsupported authority;
preserve or safely freeze canonical state;
show health and unavailable guarantees;
accept cancellation or recovery requests;
fence stale owners;
manage independent Module lifecycles.
```

The Kernel does not depend on a model call, Dreamer, graph, external provider, UI, or one adapter.

The Host Supervisor operates outside the shared process failure domain of Kernel, Watchdog, and Doctor. It starts, stops, and bounded-restarts approved services, but neither reads project semantics nor selects a repair hypothesis. Kernel, Watchdog, and Doctor have separate service identities and restart budgets; repeated failure of any one becomes a Problem State rather than an endless restart loop.

The final honest boundary is platform failure: if the Host Supervisor, operating system or machine, and fallback notification path are all lost, ELIOT does not promise to report its own total disappearance. Recovery is then manual or platform-level.

## A13.3. Module Supervision and Doctor

A Module lifecycle supports:

```text
start;
health and readiness check;
quiesce or drain;
checkpoint;
restart or rebuild;
replace or roll back;
quarantine;
retire.
```

Replacement:

```text
stop new work
→ checkpoint or drain
→ fence the old Authority Epoch
→ replace
→ health and evaluation
→ resume or roll back.
```

Normal promotion path for an experimental capability:

```text
contract and conformance
→ recorded replay
→ effect-free shadow
→ bounded canary
→ active generation
→ drain and retire or forward rollback.
```

A shadow performs no external effect and changes no canonical state, scheduling, policy, or memory influence; it produces divergence evidence. Promotion into a more integrated or hot-path contour requires not only correctness, but measurable benefit, a compatible failure envelope, and demonstrated rollback. Last-known-good means compatible with durable formats, policy, and recovery state—not merely a generation that once started successfully.

Doctor operates from the Module Registry, Problem State, Diagnostic Brief, and registered repair recipes. Doctor itself is an ordinary supervised Module: the Host Supervisor may restore its last-known-good build, and repeated failure escalates without asking Doctor to "heal itself."

Repair classes:

```text
automatic-safe — idempotent restart or reconnect, cache or index rebuild, stale-session cleanup;
guarded — configuration, credential, integration, schema or data repair, and cutover through approved recovery intent and canonical transition;
diagnose-only — corruption, unknown ownership, unclear external effect, or repeated failure.
```

Doctor never writes canonical state directly. It forms a repair intent, performs only the authorized infrastructure effect, and returns evidence; the applicable semantic transition is performed by the Governor or Kernel recovery boundary.

A repair has an attempt budget, cooldown, verification, and receipt. Once the budget is exhausted, automation stops, the Module is quarantined, and the problem escalates.

**ARCH-RES-02 — Self-repair is bounded and verified.** Doctor neither guesses indefinitely nor becomes a second writer.

## A13.4. Problem Lifecycle

```text
OPEN
→ TRIAGED
→ DIAGNOSING | CONTAINED | REPAIRING
→ VERIFYING
→ RESOLVED | ACCEPTED_RISK | SUPERSEDED | QUARANTINED.
```

New evidence may reopen a problem. The owner has a review or lease condition; loss of the owner triggers reassignment or escalation rather than closure.

A Signal, restart, notification, or acknowledgement is not resolution.

If the Governor is unavailable, Kernel or Watchdog stores only `problem/incident intent` and an evidence locator in Operational Recovery State; the canonical Problem State is created after reconciliation.

## A13.5. Bounded Resources and Control Reserve

Queues, buffers, jobs, model calls, agents, and outage spools are bounded.

Under saturation:

```text
new work receives backpressure;
an accepted operation preserves identity;
background work yields to interactive work and verification;
noncritical enrichment is dropped first;
one poison operation moves to dead-letter or quarantine;
independent Ordering Scopes continue;
false acceptance is prohibited.
```

Admission and scheduling isolate budgets by Module, principal, task, and swarm: one branch cannot displace independent work or Control Reserve.

Control Reserve protects capacity for:

```text
cancellation and fencing;
health and critical telemetry;
Critical Attention, Problem, and Incident transitions;
persistent notification inbox;
safe shutdown;
recovery.
```

Reserve exists at every relevant bottleneck, not merely as high priority. Its loss is recorded through a last-resort path outside normal workload. If that path is also unavailable, the system explicitly loses its control guarantee.

## A13.6. Operational Recovery State

When the canon is unavailable, only the following may be stored:

```text
operation identity and opaque envelope or artifact locator;
idempotency, sequence, and reconciliation state;
job checkpoint and cancellation;
Authority Epoch and suspended leases;
Module health and restart attempts;
problem and incident intents;
Recovery Manifest, backup pointers, and integrity anchors.
```

ORS does not interpret content as claims, decisions, Current Epistemic Position, or project graph, and grants no authority. Privacy and provenance remain intact. When the canon returns, operations are reconciled by receipt before replay. An unknown commit or external-effect outcome is first resolved through operation identity and observations; blind retry is prohibited.

## A13.7. Backups, Restore, and Migration

A backup includes canonical state, referenced immutable artifacts, policy and configuration snapshots, required pending operational state, purge ledger, Architecture revision digest, manifest, and checksums.

Restore occurs in an isolated area and verifies:

```text
schema and format compatibility;
provenance and integrity;
privacy purge and revocation closure;
semantic inheritance preservation;
Authority Epoch monotonicity;
external-effect reconciliation.
```

Cutover requires separate authority. Old sessions, leases, approvals, and epochs do not revive. The new Authority Epoch lineage must be strictly newer than every observed value, or globally distinct when a shared maximum cannot be demonstrated.

Canonical migration is a governed transformation, not an ordinary restart:

```text
backup and isolated rehearsal;
coverage, preservation, and faithfulness proof;
compatibility window;
checkpoint and resume;
explicit irreversible boundary;
Human authority;
rollback or recovery plan.
```

**ARCH-RES-03 — Recovery cannot resurrect invalid state.** Backup, restore, reindex, and migration preserve history, purge, revocation, and fencing.

## A13.8. Integrity

Periodic integrity review checks:

```text
canonical references and receipts;
ordering and epoch consistency;
provenance and dependency closure;
revocation and purge propagation;
Architecture digest and conformance map;
backup recoverability;
projection rebuildability.
```

It creates a Problem State and repair plan; it never resolves a semantic conflict silently.

External integrity anchors store a digest or identity, not a copy of semantic memory, and help detect rollback or history rewriting.

## A13.9. Concurrency and Durable Execution

Rule:

```text
parallel where independent;
ordered where causal.
```

One canonical write authority does not mean one global writer thread: independent Ordering Scopes execute concurrently through bounded lanes or tasks, while causally conflicting transitions are ordered.

Conflicting transitions in one Ordering Scope have one owner. A multi-scope operation declares its Coordination Scope in advance and uses deterministic ordering or an explicit saga with visible partial outcomes.

No transaction, exclusive owner, or global lock may be held during unbounded model, tool, or network wait. First record intent and State Fence, then perform external work, then reconcile idempotently under fencing.

A Durable Job has identity, owner, checkpoint, budget, cancellation, State Fence, and outcome. At-least-once execution is permitted only for idempotent, fenced, or reconciled effects.

Job completion is not Task completion:

```text
COMPLETED job → candidate artifact or result;
PARTIAL, FAILED, CANCELLED, or STALE job → coverage gap or replanning;
Task VERIFIED_COMPLETE → only through acceptance verification.
```

**ARCH-ORD-01 — Parallel where independent; ordered where causal.** Concurrency increases throughput but does not remove the single owner of conflicting state, fencing, or reconciliation.

## A13.10. Observability and Diagnostic Brief

The system distinguishes:

```text
Operational logs — diagnostics; may rotate;
Metrics — aggregates and trends;
Durable audit — authority, transitions, receipts, and incidents;
Reports — Human and agent projections.
```

An elegant report does not prove a transition; absence of a log line does not invalidate a receipt. Operational logs do not become Cognitive Inheritance automatically: only anchored observations and diagnostic evidence enter memory, while bulk external logs or documents require the Researcher acquisition path. Loss of lifecycle, authority, material-action, verification, Incident, or Critical Attention telemetry becomes a Problem State, downgrades demonstrable guarantees, and cannot be closed by a retrospective model narrative.

An agent should not have to search raw logs for an unknown problem. For a crash, timeout, deadlock, failed verification, unknown outcome, or regression, ELIOT preserves a reproducible Failure Capsule: exact Product, Task, and Attempt identity; State Fence; input and artifact generations; event tail; tool and process identities; effect disposition; raw evidence handles; applicable seed, schedule, or failpoint; minimal rerun; and current hypotheses.

From it, ELIOT compiles a Diagnostic Brief:

```text
symptom and severity;
affected Module, WorkScope, and tasks;
causal timeline and evidence handles;
correlated changes and graph relations;
prior failures and attempted repairs;
unknowns;
next discriminator, probe, repair, or escalation.
```

Correlation remains a hypothesis until supported by intervention or evaluation evidence. Repeated debugging begins with a reproducible discriminator, not another broad log review.

**ARCH-OBS-01 — Logs, metrics, audit, and reports are distinct.** Diagnostic flow helps explain a problem, but authority and transition facts are established by receipts and evidence.

## A13.11. Degradation by Subtraction

| Failure | What remains |
|---|---|
| Model or Dreamer unavailable | Deterministic memory, state, tools, and partial work |
| Adapter or truth surface unavailable | Another surface, a probe, or an explicit unknown |
| Verifier unavailable | Work may continue; verified finish is unavailable |
| Watchdog unavailable | Supervision profile is downgraded; policy limits ELIOT authority and verified finish within the actual Enforcement axis |
| Host Supervisor unavailable | Running services may continue; automatic process recovery is unavailable; Watchdog opens a Problem State |
| Kernel unavailable, Host Supervisor alive | Normal authority and effects stop; approved restart, rollback, and fallback notification occur outside the semantic path |
| Doctor unavailable | Normal work continues; automatic repair is unavailable |
| Optional Module failed | Local capability degrades; Kernel and independent work survive |
| Governor application unavailable, Kernel alive | Fencing, cancellation, ORS, and Recovery View; no new semantic or Material authority |
| Canonical store unavailable | Bounded operational staging only; no semantic promotion or verified finish |
| Operational Recovery State unavailable | No durable pending acceptance, outage checkpoint, or automated replay claim; new affected work is rejected with a visible recovery boundary |
| Agent or Coordinator unavailable | Durable work and checkpoints survive; ownership is reassigned |
| Human unavailable | Safely delegated work may continue; approvals and value decisions wait |
| Budget exhausted | Paid jobs stop; verified partial work and the coverage gap remain |

**ARCH-RES-04 — Degradation is visible and local.** The system reduces promises before presenting incomplete state as complete.

## A13.12. Recovery as Learning

Every material failure preserves:

```text
symptom and scope;
competing hypotheses;
repairs or routes tried;
observed delta;
useful model, tool, or vendor;
unresolved cause;
a change candidate for a Skill, Module, procedure, or Architecture.
```

A repeated failure must change the hypothesis or method, not merely increase retry count.

**ARCH-RES-05 — Recovery produces reusable knowledge.** Repair improves the next diagnosis, but one successful repair does not become a universal procedure without transfer evidence.

---
# A14. Learning, Meta, and System Development

## A14.1. Learning Levels

ELIOT distinguishes:

| Level | What changes |
|---|---|
| Memory update | Episode, observation, commitment, or outcome |
| Epistemic learning | Support, scope, rivals, and Current Epistemic Position |
| Procedural learning | Procedure, Skill, route, and recovery behavior |
| Conceptual learning | Categories, ontology boundaries, and analogies |
| Strategic or metacognitive learning | Inquiry, decomposition, context, and evaluator strategy |
| Institutional learning | Policy, Module contracts, governance, and Architecture |
| Parametric learning | Model weights in an external training process |

ELIOT primarily changes external inheritance. Weight training may complement this loop but does not replace it.

**ARCH-LEARN-01 — Learning changes external inheritance through grounded outcomes.** Future behavior changes only through evidence-linked revision, procedure, routing, policy candidate, or other inspectable state.

**ARCH-LEARN-02 — Learn online; promote globally only under proof.** Within an active task, ELIOT may update task-local strategy, working memory, and a behavioral overlay at safe checkpoints before the next materially compatible attempt. Cross-task, system-wide, production, and normative influence remains candidate-only until the update passes applicable current-applicability, activation and adherence, outcome, retention and transfer, evaluator-validity, authority, Product Pulse, and rollback gates.

**Why:** using one learning speed for local correction and system change either makes local correction impractically slow or system change dangerously fast.

**Under conflict:** rapid plasticity is permitted where blast radius is local and reversible; wider influence requires stronger evidence. Benefit in the current task does not demonstrate transfer; transfer does not demonstrate retention; retention grants no normative authority.

## A14.2. Consolidation and Reconsolidation

```text
Primary consolidation:
new episode → candidate concept, model, or procedure
→ validation and transfer test.

Reconsolidation:
reactivated derived knowledge + new outcome or evidence
→ revise meaning, scope, support, or activation.
```

A raw episode is not rewritten. One new outcome first changes local scope or support; broad promotion requires repeated or independent evidence.

Stability–plasticity prevents two extremes:

```text
a new case does not become doctrine immediately;
old high-use knowledge does not block contradictory evidence.
```

## A14.3. Negative Memory and Extinction

Failure memory contains a trigger, failed action, outcome, violated invariant, scope, reopen condition, and extinction condition.

An exact deterministic trigger may block. Semantic similarity creates a warning or inquiry obligation, not an automatic hard block.

After the environment changes, safe re-exposure may confirm, narrow, or extinguish an old avoidance response. The original failure episode remains.

## A14.4. Forgetting and Memory Ecology

Forgetting operators:

```text
suppress or demote accessibility;
compress with a loss and lineage record;
archive or quarantine;
extinguish obsolete activation;
post-supersession demotion;
privacy purge under a separate contract.
```

Low use does not reduce factual support. Frequent retrieval does not strengthen a record. Popularity does not delete minority evidence.

Memory health measures:

```text
stale reuse;
false promotion;
wrong-scope reuse;
negative transfer;
poisoned influence;
cue overload;
false activation or block;
missing-context regret;
compaction loss;
capture, curation, and restore cost;
failures prevented and decisions improved.
```

Influence distinguishes stages: `present → attended → interpreted → used → causally helpful`. Delivery, citation, and confident rationale do not demonstrate contribution without downstream outcome or counterfactual evidence.

**Memory gravity** marks records or narratives that dominate context out of proportion to their evidence and utility. It creates a narrowing or suppression candidate, not automatic deletion of minority evidence.

## A14.5. Meta-Learning

Learning begins inside the execution loop. Meta does not create learning from nothing; it decides which already observed local learning deserves broader and more durable influence. There are therefore two loops.

### Inner Loop — Learning During Work

Runs inside an active task: fast, local, and reversible.

```text
attempt
→ trace, outcome, and applicable verifier
→ attribution: which mechanism explains the result and with what ceiling
→ task-local delta to strategy, context, procedure, or route
→ delta admitted to the current overlay
→ next compatible attempt compiled with that delta
→ activation, adherence, decision delta, and outcome become observable.
```

This loop changes only task-local state with a bounded blast radius and explicit rollback. It does not change the goal, acceptance criteria, authority, privacy, cost ceiling, evaluator, sealed holdout, production generation, or its own promotion decision.

After material new evidence appears, another materially equivalent attempt is inadmissible without an explicit reason. Valid reasons include stochastic replication, noise estimation, exact defect reproduction, controlled comparison, recovery proof, and verifier calibration. "Try again" is not a reason. When no strategy change is justified, the system records an evidence-backed no-change or exhaustion disposition rather than repeating the path.

### Outer Loop — Consolidation and Promotion

Runs across tasks, more slowly and on stronger evidence:

```text
recurring or high-value local delta
→ scoped Improvement Candidate
→ isolated candidate, fixed replay, shadow, or canary
→ held-out, retention, claimed transfer, and Product Pulse
→ promote, narrow, reject, or roll back.
```

A problem is not the only trigger. Learning must also follow an unexpected success, a cheaper alternative route, correct abstention, useful environment discovery, effective decomposition, correct verifier selection, successful transfer, or discovery that a procedure is unnecessary.

An Improvement Candidate contains evidence, validity scope, owner, expected delta, risk, rollout, rollback, and stop condition. Advice may be immediate, task-level, system-level, or architecture-level.

By default, Meta advises the Main Agent or Human. A change is prepared as a separate candidate in an isolated Experimental Contour, tested on fixed replay and affected proofs, and then, when needed, passed through shadow or canary and reversible cutover. The active generation remains immutable until governed promotion. Only preauthorized, local, reversible tuning changes with canary and rollback may apply automatically.

The Meta loop itself is evaluated by verified delta, activation, adherence, adoption, regressions, false positives, noise, cost, and Product Pulse impact; useless advice is demoted or archived. Code, schema, authority, verifier definitions, privacy, Architecture, and destructive forgetting never change automatically.

**ARCH-META-01 — Self-improvement is advisory, isolated, and falsifiable.** ELIOT improves from evidence of real work through candidates, replay, shadow or canary, and rollback—not by confidently rewriting the active system.

## A14.6. Evaluation

The system distinguishes:

```text
Production path — what created decisions, actions, and outcome;
Measurement path — how outcome became a score or quality claim;
Optimization-feedback path — how evaluation changes the future system.
```

An evaluator is assessed for construct, criterion, ecological, consequential, temporal, and comparative validity. A same-family model judge is not automatically independent. A performance claim applies to the complete combination of model, harness, memory and context state, tools, evaluator, environment, policy, budget, and Human involvement—not to a model name alone.

For self-learning, update quality alone is insufficient. Measure separately the update's quality, activation in the next compatible attempt, adherence over a long trajectory, decision change, and outcome benefit. A stronger proposer does not guarantee proportional benefit: the bottleneck may be retrieval, route competence, or the update itself. One aggregate score hides the actual bottleneck.

Decision quality is not reducible to a lucky outcome; evaluate available evidence, alternatives, reasoning discipline, risk, and calibration.

## A14.7. Cost Authority

The System Owner sets available routes, global privacy and cost ceilings, and automation policy. The Requester sets task budget and preferences within those bounds; the Task Controller may only narrow them. Governor and Agent Coordinator account for actual consumption from provider and tool receipts attributed to a task, job, or swarm.

When the budget is exhausted:

```text
no new paid job starts;
active work is checkpointed;
verified partial work is preserved;
the coverage gap and options remain visible;
an unauthorized expensive fallback is prohibited.
```

**ARCH-ECON-01 — Cost is authority.** Intelligence has a price; no system service creates a bill without an owner and envelope.

## A14.8. Development Doctrine

ELIOT is designed with the assumption that fallible agents will implement it and may optimize the nearest test, expression, or status. Task decomposition, testing, and integration must therefore preserve the causal link from user goal and acceptance to observable outcome.

Normal development loop:

```text
1. Build the minimum vertical spine in A0.8 and use it in real work.
2. Select one causal property and its actual production owner and path.
3. Record the old failing behavior or missing capability and its discriminator.
4. Decompose work into Contract or Evidence, Module, and Edge or Integration units.
5. Perform bounded parallel work on independent Modules.
6. Obtain Module Proof, then affected Edge Proof.
7. Run the smallest Product Pulse able to detect architectural drift.
8. Promote, narrow, roll back, or open Mechanism Review.
9. Record the outcome in memory, tests, Skills, and repair or decomposition candidates.
10. Remove ceremony and mechanisms that produce no decision delta.
```

Every supported Module has an independently invocable proof surface. This does not require a fixed size, separate process, or fully independent compilation universe. Independence means a clear contract, bounded fixtures or environment, reproducible entrypoint, exact failure attribution, and known proof ceiling.

Proof levels remain distinct:

```text
Module Proof — capability behind its own contract;
Edge Proof — real provider and consumer interaction or runtime boundary;
Product Proof — end-to-end user or agent outcome;
Release Proof — accepted Product Identity, recovery, and distribution boundary.
```

A local PASS is not promoted automatically. Product Pulse specifically checks whether many local greens have combined into a system-level failure.

Testing and debugging are continuous and proportional to change closure:

```text
the changed Module and its contract;
affected dependency and consumer edges;
selected recovery, security, and concurrency paths;
the full release matrix only for a matching blast radius or release.
```

The first test repair begins with a discriminator that fails on the exact old path. Zero executed expected tests is not PASS. An agent changing implementation does not weaken oracle, fixture truth, tolerance, or verifier semantics in the same work unit without a separate decision and review. Concurrency, retries, cutovers, and recovery use deterministic simulation or fault injection where it distinguishes interleavings; simulation never replaces at least one real-edge or live proof.

Testing during work does not mean rewriting the active generation in place. A candidate Module is tested in an isolated environment, replay, shadow, or canary; background tests cannot displace active work, Control Reserve, or Human attention. A failure creates a Failure Capsule and the next discriminator, not merely another broad suite.

A test is valuable when it:

```text
distinguishes competing implementation hypotheses;
protects already observed value;
checks an effect, integration, recovery, or migration;
prevents recurrence of a real failure;
catches proxy success before it becomes a product regression.
```

Counts of Modules, tests, phases, reports, or certificates are not progress without Product Proof. Topology and test strategy are themselves Improvement Candidates and change according to agent success, context usability, build and test cost, escaped failures, and Product Pulse.

**ARCH-DEV-02 — Depth grows through independently testable layers under stable intent.** ELIOT is not rewritten wholesale for every new model or runtime technique; Modules, proofs, and promotion contours evolve from observed value and failure evidence.

## A14.9. Architecture Coherence Review

Before adopting Architecture or Implementation, check:

```text
whether the primary purpose of understanding is preserved;
whether Intent has become literalism;
whether a second owner or hidden authority exists;
whether evidence, model output, and proof are conflated;
whether failures remain localized;
whether recovery and learning loops exist;
whether the Implementation is locked to a current vendor;
whether tests and reports have replaced real work;
whether Module and work-unit size follows empirical outcomes rather than a permanent threshold;
whether each swarm worker receives minimum decision-sufficient context rather than a whole-project dump;
whether local Module proofs close through affected edges and Product Pulse;
whether a person can understand system state and intervene;
whether a new agent can briefly explain the mission, applicable Intent and Hard Boundaries, current goal, and next proof without reading the full history.
```

An audit is a fault list and evidence, not a third normative book. Watchdog, Dreamer, and external auditors may produce findings; the Architecture Owner accepts changes in the main text.

---
# A15. End-to-End Scenarios

Scenarios test meaning already defined. They do not impose a protocol or schema.

| Event | ELIOT behavior | Proof or outcome |
|---|---|---|
| New WorkScope without Git | Bootstrap Scanner builds a provisional scope, available surfaces, and gaps | Agent receives basic orientation; unknowns are visible |
| Agent does not know what to search for | Push from world or task cues, then Dreamer Orientation | Relevant history and relations with provenance, not a generic search dump |
| Agent submits a poorly typed observation | Capture as Observation Candidate; curate later | Source is preserved without a false status |
| Dreamer proposes a false merge or procedure | Result remains a candidate or reversible derived projection; sources, dissent, and undo path are preserved | No hidden epistemic promotion; the error becomes curation evidence |
| Agent works but stops reporting observations | Watchdog compares workspace activity with Interaction Heartbeat | Gap, resynchronization, reduced Governance Profile, and Human warning if persistent |
| Two agents disagree | Concilium separates evidence and frames and launches a discriminative audit | Provisional choice plus preserved dissent and revision trigger |
| Large swarm audits a project | Durable work graph, bounded micro-audits, challenge, synthesis, and verify stages | Unique coverage, Evidence Lineage, gaps, and partial results |
| Agent repeats a known failure | Exact fingerprint requires new evidence or probe; semantic match warns | Prevented recurrence or false-activation learning |
| Guardrail creates a false block | Governed Challenge and Recoverable Deviation when no Hard Boundary is affected | Outcome changes the rule or negative memory |
| Poisoned memory is discovered late | Revoke source influence through dependency closure; quarantine affected views | History preserved, current support removed, clean reevaluation |
| Prompt injection arrives through a Dream query, document, or Tool Definition | Content remains data, effects stay bounded, and Watchdog receives a security signal | No hidden authority or secret exfiltration; source lineage preserved |
| Optional Module fails | Supervisor degrades locally and restarts, rebuilds, or quarantines | Kernel and independent work continue |
| Governor application fails while Kernel survives | New authority and effects stop; fencing, ORS, Recovery View, and restart remain | No split brain; reconciliation precedes resume |
| Queue or storage pressure | Backpressure, shedding, Control Reserve, and poison-item quarantine | No false acceptance; control and recovery survive |
| Repair repeatedly fails | Doctor changes hypothesis or route, exhausts its budget, and escalates | No restart storm; Problem history and next action remain |
| Long session is compacted or restarted | Checkpoint goals, rivals, commitments, losses, and State Fence | Reconstruction from inheritance without reviving a killed plan |
| Model or harness is replaced | Public inheritance transfers; competence and context profiles are requalified | Same commitments and evidence without inherited tacit confidence |
| Verifier is unavailable | Work may continue under explicit uncertainty | No `VERIFIED_COMPLETE` for the dependent acceptance item |
| Human misses a notification | Attention remains active; channel or owner escalates | Acknowledgement remains distinct from resolution |
| Initial setup finds an untrusted executable | Metadata probe only; no secrets or elevated authority before confirmation | Capability is discovered, not trusted |
| Privacy erasure is requested | Purge current state, projections, ORS, backups, and provider copies; update purge ledger | Restore cannot resurrect data |
| Backup is restored after failure | Isolated restore plus integrity, purge, revocation, and epoch checks; separate cutover | No old leases, poisoned influence, or stale authority |
| Canonical migration is interrupted | Resume from checkpoint or roll back the isolated copy; normal authority remains bounded | Cognitive-inheritance preservation proof and migration receipt |
| ELIOT code conflicts with Architecture | Self-model exposes a conformance gap; Dreamer or Watchdog provides a brief | Fix Implementation or make an explicit Architecture change; never hide drift |
| New experimental Module is needed during active work | Capability receives an isolated contour, independent proof, replay, shadow, and canary; active generation stays immutable | No unproven effect on the live task; reversible promotion or rollback receipt |
| Swarm implements several independent Modules | Contract or Evidence wave freezes interfaces; workers receive bounded work units; a separate owner integrates | Module proofs plus affected Edge proofs and Product Pulse, without a shared mutable plan |
| All local Module tests pass but Product Pulse fails | Promotion stops; Watchdog records development drift; Concilium or Mechanism Review revisits owner, contract, or hypothesis | Local PASS cannot mask product regression; new discriminator is bound to the real path |
| Agent Work Unit does not fit the route's Safe Operating Envelope | Decompose the task, compile a projection, or choose another qualified route; Module size itself is not a violation | Decision-relevant context and reasoning margin are preserved without a universal size ceiling |
| Meta proposes an optimization after the stack changed | Candidate becomes stale outside its validity scope | New canary before reuse; old result remains historical evidence |

---

# A16. Core Architectural Decisions

## A16.1. Decision Anchors

This is a navigation index. Full meaning, rationale, and conflict behavior remain in the corresponding section; a concise row is not a second edition of the decision.

| ID | Class | Decision |
|---|---|---|
| `ARCH-INTENT-01` | Invariant | Intent outranks literal compliance |
| `ARCH-CONCIL-01` | Invariant | Dissent and falsification matter more than vote count |
| `ARCH-DEV-01` | Contract | Working vertical spine before broad hardening |
| `ARCH-CORE-00` | Invariant | Work must become cumulative |
| `ARCH-CORE-01` | Invariant | Understanding continuity first |
| `ARCH-CORE-02` | Invariant | Four planes, one governed loop |
| `ARCH-HELP-01` | Invariant | ELIOT reduces cognitive and operational load |
| `ARCH-ROLE-01` | Invariant | Observation, interpretation, authorization, and verification are separated |
| `ARCH-ROLE-02` | Invariant | Responsibility follows competence and failure type |
| `ARCH-AUTH-01` | Invariant | Authority is explicit, scoped, and fenced |
| `ARCH-MOD-01` | Invariant | Small living Kernel; local Module failure does not kill the system |
| `ARCH-MOD-02` | Contract | Depth grows through independently testable Micro-modules; physical size and form remain empirical |
| `ARCH-MOD-03` | Invariant | One causal responsibility: one owner per mutable state, one proof surface, one replacement boundary |
| `ARCH-PORT-01` | Invariant | Organs and execution contours are replaceable; public inheritance transfers, tacit strategy is requalified |
| `ARCH-SCOPE-01` | Invariant | Scope before reuse |
| `ARCH-MEM-01` | Contract | Capture first; ELIOT organizes later |
| `ARCH-MEM-02` | Invariant | Semantic fallibility is recoverable through forward revision |
| `ARCH-MEM-03` | Invariant | Derived memory preserves evidence and lineage |
| `ARCH-MEM-04` | Invariant | Retrieval is not reinforcement; forgetting is not belief revision |
| `ARCH-LIFE-01` | Invariant | No semantic teleportation among observation, interpretation, authority, and proof |
| `ARCH-EPI-01` | Invariant | Reality corrects; epistemic positions remain defeasible |
| `ARCH-EPI-02` | Contract | Theories earn and lose weight through outcomes |
| `ARCH-EPI-03` | Invariant | Exploration cannot confirm itself on the same evidence |
| `ARCH-EPI-04` | Contract | Coverage requires a declared, frozen, and recheckable denominator |
| `ARCH-UND-01` | Invariant | Load-bearing understanding has a public inspectable form |
| `ARCH-UND-02` | Contract | Causal understanding is tested by discriminative prediction and outcomes |
| `ARCH-GROUND-01` | Contract | Models remain tied to tools, graphs, artifacts, and verifiers |
| `ARCH-SELF-01` | Contract | ELIOT maintains evidence-linked self-knowledge without self-certification |
| `ARCH-CTX-01` | Contract | Decision sufficiency before context optimization |
| `ARCH-CTX-02` | Contract | Observable state drives proactive memory |
| `ARCH-CTX-03` | Contract | Decision locality is route-profiled |
| `ARCH-CTX-04` | Contract | Retrieval proposes candidates; Context Compiler admits influence |
| `ARCH-ATTN-01` | Contract | Critical Attention is state, not a message |
| `ARCH-SKL-01` | Contract | Skills are concise, intent-dense, and challengeable |
| `ARCH-WDG-01` | Contract | Independent supervision |
| `ARCH-WDG-02` | Contract | Watchdog supervises preservation of declared intent, observable outcomes, security, and recovery |
| `ARCH-DRM-01` | Invariant | Dreamer is an AI service, not an owner or authority |
| `ARCH-DRM-02` | Contract | Dreamer expands hypothesis space and orientation |
| `ARCH-DRM-03` | Contract | Dreamer agents and swarms are human-governed by budget and policy |
| `ARCH-DRM-04` | Invariant | Researcher acquires, Dreamer interprets, Governor governs |
| `ARCH-ACT-01` | Contract | Effect defines impact and authority |
| `ARCH-SWM-01` | Contract | Swarm is a bounded, context-minimal staged evidence pipeline |
| `ARCH-SWM-02` | Contract | Swarm coordination is durable, idempotent, and epoch-fenced |
| `ARCH-LONG-01` | Invariant | Long work lives in durable state |
| `ARCH-FIN-01` | Invariant | Completion is proof-bearing; other finish states remain explicit |
| `ARCH-HUM-01` | Invariant | Human retains value authority and practical control |
| `ARCH-SEC-01` | Invariant | Assume compromise; preserve control and recovery |
| `ARCH-SEC-02` | Invariant | One governed canonical transition path |
| `ARCH-SEC-03` | Invariant | Influence remains origin-bound and revocable |
| `ARCH-SEC-04` | Invariant | Model output remains a candidate until governed transition |
| `ARCH-PRIV-01` | Contract | Erasure propagates and is not undone by restore |
| `ARCH-RES-01` | Invariant | Fail locally, recover globally |
| `ARCH-RES-02` | Contract | Self-repair is bounded and verified |
| `ARCH-RES-03` | Invariant | Restore or migration cannot resurrect invalid state |
| `ARCH-ORD-01` | Invariant | Parallel where independent; ordered where causal |
| `ARCH-OBS-01` | Invariant | Logs, metrics, audit, and reports are distinct |
| `ARCH-RES-04` | Invariant | Degradation is visible and local |
| `ARCH-RES-05` | Contract | Recovery produces reusable knowledge |
| `ARCH-LEARN-01` | Invariant | Learning changes external inheritance through grounded outcomes |
| `ARCH-LEARN-02` | Contract | Learn online within a task; promote globally only under proof |
| `ARCH-META-01` | Contract | Self-improvement is advisory, isolated, evidence-driven, and falsifiable |
| `ARCH-ECON-01` | Contract | Cost is an authority boundary |
| `ARCH-DEV-02` | Contract | Depth grows through independently testable layers, Edge proofs, and Product Pulses |

## A16.2. Anti-Patterns

```text
RAG, a summary, graph, or context size presented as understanding;
exploration presented as confirmation on the same evidence;
a coverage or absence claim without a denominator;
a report used as a truth source instead of a projection of frozen evidence;
a generative paraphrase replacing an exact quotation where the quotation carries evidentiary weight;
a rule followed at the expense of Intent and a working product;
Intent cited to justify a hidden bypass without evidence, owner, and review;
agent count, votes, or repeated lineage presented as truth;
one model or vendor as an irreplaceable cognition owner;
an agent forced to administer ontology instead of doing its primary work;
a semantic error treated as irreversible corruption of all memory;
a summary or compaction without sources, losses, and an undo path;
retrieval or repetition treated as reinforcement;
a giant context dump or silent truncation;
Dreamer, Watchdog, or a Synthesis Agent treated as authority;
Dreamer curation silently changing epistemic support, source history, or policy;
Researcher acquisition and Dreamer synthesis merged under one ungoverned owner;
Skills, prompts, or filters as the only security or enforcement boundary;
security premised on impenetrable armor;
Remote Dreamer with access to local databases or tools;
several canonical owners or a direct storage bypass;
failure of an optional Module taking down the Kernel;
a retry or restart loop without new evidence, budget, and escalation;
a recovery spool used as a second semantic memory;
restore reviving revoked influence, deleted data, or old authority;
a notification, acknowledgement, or restart treated as resolution;
self-improvement without an owner, canary, proof, and rollback;
tests, phases, and reports replacing a real vertical spine;
the first vertical spine presented as completed four-plane ELIOT;
a fixed Module size or count treated as constitutional law;
source module, package, process, and service conflated into one boundary;
an unbounded shared-chat swarm or whole-project context for every worker;
locally green Module tests without affected Edge Proof and Product Pulse;
an unverified prototype receiving live authority or hot-path influence immediately;
an active generation rewriting itself without candidate, replay, shadow or canary, and rollback;
append-only normative documentation and hidden precedence;
a specific vendor, benchmark, or mechanism treated as a permanent Invariant.
```

## A16.3. Final Formula

```text
ELIOT = durable governed cognitive inheritance
      + plural scoped understanding corrected by reality
      + proactive attention and route-specific Active Views
      + Harness for agents, tools, swarm, authority, and proof
      + Dreamer for bounded synthesis, orientation, and research
      + Watchdog and Doctor for supervision, recovery, and security
      + Concilium, practical trials, and advisory Meta-learning
      + micro-modular layered capabilities with isolated prototype promotion
      + context-minimal agent pipelines, independent proofs, and Product Pulses
      + Human value authority and control
      + a small resilient Kernel that survives local failure.
```

ELIOT succeeds not when it stores more data, writes more rules, creates more Modules, or runs more agents. It succeeds when a person and agent can restore sufficient understanding, perform bounded and meaningful work, verify Modules and real edges, observe the product outcome, survive error, and improve the next iteration without rewriting the entire system.
