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

