## I8.12. Restart budgets

Per process/module manifest:

```yaml
RestartPolicy:
  max_attempts_in_window:
  window:
  backoff:
  jitter:
  reset_after_healthy:
  quarantine_after_exhaustion:
  escalation_target:
```

DEFAULT process sequence: immediate once, short backoff, then increasing bounded backoff. Exact numbers live in config and fault profiles.

Repeated repair/restart without new evidence stops automatically.

