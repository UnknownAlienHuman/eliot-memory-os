## I17.4. Causal Change Unit

A normal development unit closes one causal property and is small enough for independent review.

```yaml
CausalChangeUnit:
  product_objective:
  failing_or_missing_property:
  actual_runtime_path:
  hypothesis_and_rivals:
  discriminator_before_code:
  owner_and_scope:
  allowed_changes:
  forbidden_drive_by_changes:
  expected_observable:
  verifier_and_product_effect:
  rollback:
  writeback_if_supported_or_refuted:
```

Rules:

```text
bug repair starts with a discriminator that fails on the exact old path;
no unrelated cleanup/refactor in the same unit;
second repair of the same class requires Mechanism Review;
review challenges scope, authority and causal mechanism before style;
merge requires live proof at the lowest real boundary able to discriminate;
failure produces FailureFingerprint, test, rule/deviation update,
Improvement Candidate or explicit accepted non-action — never report only.
```

