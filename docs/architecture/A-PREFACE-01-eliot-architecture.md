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
