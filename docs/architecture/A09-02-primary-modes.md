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

