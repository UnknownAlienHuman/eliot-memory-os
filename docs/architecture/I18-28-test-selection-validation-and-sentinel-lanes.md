## I18.28. Test-selection validation and sentinel lanes

Affected-test selection is itself fallible. ELIOT validates it through bounded counterchecks:

```text
historical regression/escape corpus;
rotating sample of predicted-unaffected module/edge tests;
contract-consumer tests after public schema/type changes;
periodic broader canary on representative Product Identity;
comparison of selected plan with actual later failures;
release full matrix.
```

A sentinel failure updates BuildTestGraph/Impact rules and may invalidate prior selection evidence. Sentinel sampling is bounded and profile-driven; it is not a hidden full suite after every change.

Selection quality metrics:

```text
false-negative escaped dependency;
false-positive test cost;
selected-plan precision/recall on known changes;
time to first useful failure;
number of unrelated packages/processes started;
```


Every load-bearing selector produces a `TestSelectionValidityReceipt`:

```yaml
TestSelectionValidityReceipt:
  candidate_change_and_selector_profile:
  comparator_kind: FULL_DEPENDENT | FULL_SUITE | HISTORICAL_FAULT |
                   MUTATION | SAMPLED_SENTINEL
  raw_selected_and_reference_sets:
  omitted_and_extra_tests:
  actual_failure_or_fault_outcomes:
  labels: STABLE_FAILURE | FLAKY | INFRA | UNKNOWN
  de_flake_and_retry_policy:
  reference_sampling_probability:
  precision_recall_set_disagreement_and_uncertainty:
  offline_selection_and_online_execution_cost:
  selector_and_verifier_granularity:
```

No published selection percentage becomes a portable threshold. Selection accelerates local feedback; it never replaces an independent release proof, and an unknown/flaky comparator cannot be silently scored as a selector success.

