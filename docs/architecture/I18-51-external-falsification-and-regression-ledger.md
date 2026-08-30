## I18.51. External falsification and regression ledger

Detailed audit question IDs, donor-source headings, historical finding numbers and reproduction transcripts live in an external content-addressed evidence ledger, not in this normative book. The active Implementation sees only compiled obligations whose current owner and trigger are known:

```yaml
FalsificationObligation:
  property_and_current_contract_ref:
  source_finding_and_exact_evidence_refs:
  current_product_identity_and_support_status:
  old_failing_path_or_counterexample:
  discriminator_and_expected_observable:
  applicable_proof_ceiling:
  activation_trigger_budget_and_expiry:
  invalidation_and_retirement_condition:
```

An audit inventory or numbered research question does not become a test merely because it exists. The ledger compiler deduplicates obligations by causal property/owner, preserves each source lineage and emits only `ACTIVE` obligations into the affected `ModuleTestCapsule` or `ProductEvaluationPlan`. Historical names such as W4/F/D identifiers remain evidence handles and never appear in the agent hotset unless the current work unit needs the underlying counterexample.

Coverage counts prove only that source findings were dispositioned. Closure requires an executable discriminator on the exact current identity, or an explicit disposition of `ImplementationSupport = TARGET` with `EvidenceExecutionStatus = NOT_EXECUTED`, or `ImplementationSupport = STALE`.


