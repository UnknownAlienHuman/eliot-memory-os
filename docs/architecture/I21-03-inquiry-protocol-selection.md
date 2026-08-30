## I21.3. Inquiry protocol selection

A single generic pipeline for every question is the most common failure of research automation. The protocol is chosen from the structure of the question.

```yaml
InquiryProtocolProfile:
  profile_id_and_revision:
  question_and_intended_decision_or_artifact:
  protocol:
    lookup | evidence_review | causal_diagnosis | formal_proof |
    program_synthesis | architecture_decision | algorithm_search |
    empirical_discovery | theory_development | decision_support
  evidence_grade:
  lane: confirmatory | exploratory | mixed_with_declared_split
  truth_surfaces_and_admissible_providers:
  coverage_goal: exploratory | representative | high_recall | exhaustive
  hypothesis_policy: alternatives_required | counter_search_required | falsification_required
  independence_and_blinding_policy:
  fidelity_ceiling:
  budget_deadline_and_stop_rule:
  output_contract_and_reopen_conditions:
```

Selection inputs are task features, not task vocabulary: sequential dependency, branch independence, shared mutable state, verifier cost and strength, specialist discoverability, horizon, uncertainty and risk. The same inputs feed `RecipePlanner` (I10.15), so protocol and staffing are chosen consistently rather than by two competing heuristics.

Protocol choice is a Default, not a Hard Boundary: it may be changed mid-run with a recorded reason, and the change invalidates only obligations that depended on the previous protocol. In a confirmatory lane, a change outside registered deviations also invalidates the registration; subsequent analysis is exploratory until a new registration is frozen before new outcome exposure.

