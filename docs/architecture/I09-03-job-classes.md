## I9.3. Job classes

### Orientation

```text
What does ELIOT know about goal/scope?
Which decisions/failures/unknowns matter?
What hidden relations may change the next action?
Which Architecture anchors and Implementation contracts/defaults apply?
```

Output: `DreamPacket`.

### Curation

```text
classify candidates;
propose relations;
reconstruct episodes;
identify duplicates/false merges;
propose concepts/procedures/failure fingerprints;
propose accessibility/influence changes;
identify memory pollution and missing provenance.
```

Output: `CurationCandidateSet`.

### Clarification

Creates one short question to active agent:

```text
ambiguous observation;
missing scope;
observation vs interpretation unclear;
missing outcome/reuse condition;
contradictory decisions.
```

Question includes why answer matters and safe fallback if unanswered.

### Research synthesis

Works on governed `ResearchPack` or source handles:

```text
rival hypotheses;
source portfolio and independence;
claim/counterclaim matrix;
unknowns and discriminative questions;
Concilium plan;
research brief with uncertainty.
```

Acquisition/parsing/indexing is governed by Researcher and executed by admitted providers (I21); Dreamer receives only governed source handles and bundles.

`ResearchPack` is the acquisition/synthesis boundary:

```yaml
ResearchPack:
  question_and_scope:
  source_handles_and_source_cards:
  acquisition_route_and_time:
  authority_freshness_competence:
  independence_and_shared_lineage:
  privacy_and_allowed_use:
  coverage_and_missing_source_classes:
  state_fence_and_invalidation:
```

Dreamer returns a `ResearchBrief` that keeps claims, counterclaims, exact citations, source dependence, unknowns and recommended probes separate. It cannot convert the pack into project truth by prose quality.

### Architecture/self query

Produces two authority-separated projections from exact accepted sources and current conformance state:

```text
ArchitectureBrief
  applicable ARCH-*;
  intent and rationale;
  affected guarantees and Hard Boundaries;
  unresolved Architecture questions;
  exact accepted Architecture revision and source digest.

ImplementationBrief
  applicable I-sections, contracts, DEFAULTs and Research Gates;
  concrete owners, protocols, state and failure behavior;
  supported / partial / absent / deviated mechanisms;
  migration and compatibility constraints;
  exact accepted Implementation revision and source digest.
```

Architecture has semantic precedence. Implementation explains the currently accepted realization and may expose a gap, DEFAULT or experiment; it cannot reinterpret Architecture silently. Code, tests and runtime observations update conformance evidence but do not replace either accepted source. A combined answer keeps the two projections visibly separate and opens a conformance Problem State when Architecture, Implementation and observed runtime disagree.


### Development diagnosis

Analyzes a bounded set of development evidence:

```text
Product Objective and current product gap;
sequence of repairs and changed paths;
failed/passed discriminators;
actual runtime/source identities;
open conformance gaps;
activity artifacts without product delta;
related FailureFingerprints and prior attempts.
```

Returns:

```text
rival root-cause hypotheses;
common-mode assumptions;
likely proxy metrics and local-optimum loops;
minimum discriminating experiment;
proposed repair scope and owner;
which guardrails or rules should be challenged, narrowed, or retained.
```

Output remains a candidate. Dreamer creates no feature freeze, changes no rule class, closes no defect, and assigns no product status.

### System maintenance and self-improvement planning

Dreamer consumes bounded self-scope observations and prepares a `MaintenancePlanCandidate`:

```text
curation/compaction/reconsolidation candidate;
context/Skill/tool-surface improvement;
route/capability requalification;
backup/index/module/integration maintenance;
configuration change intent;
new diagnostic experiment or Mechanism Review;
Human escalation with the smallest useful decision packet.
```

It does not execute maintenance directly. `eliotd`/Agent Coordinator/installer/Doctor own execution under the relevant policy and leases.

### Agent orchestration planning

Dreamer may translate a Human/Main-Agent objective into a `CognitiveWorkPlanCandidate` naming work units, required competence, route classes, context/evidence budgets, independence, descendant limits and synthesis/verifier paths. The deterministic TaskGraphCompiler and Governor decide what becomes executable. Dreamer may choose “one strong agent”, “several cheap scouts”, “external main agent with visible native children”, or “no model job; ask one question/probe” according to expected value and current policy.

### Configuration assistance

Dreamer may explain current settings and produce the `ConfigurationChangeIntent` of I3.10 from a natural-language request or diagnosed problem. It never edits the active snapshot itself and cannot raise cost, privacy, remote access, authority or automatic-launch ceilings without the owning Human role.

