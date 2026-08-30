## I6.9. Recoverable implementation deviation

`ImplementationDeviation` is the concrete record implementing Architecture's `Recoverable Deviation`; it is not a separate exception doctrine.

```yaml
ImplementationDeviation:
  deviation_id:
  from_contract_or_default:
  scope:
  owner:
  reason_and_evidence:
  hard_boundaries_checked:
  expected_benefit:
  risk:
  rollback:
  review_condition:
  outcome_ref:
  disposition: active | promoted | rejected | expired
```

Deviations are not permanent exceptions.

---

