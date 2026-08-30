## I11.5. Persistent notifications

Severity:

```text
Critical      — integrity/security/unknown external effect/control loss;
ActionRequired— approval, blocked task, failed credential/repair;
Warning       — degraded hooks, repeated failures, stale backup, pressure;
Info          — verified completion, maintenance result, update available.
```

Each notification:

```yaml
Notification:
  notification_id:
  severity:
  subject:
  summary:
  evidence_handles:
  affected_scope:
  owner:
  required_action:
  deadline_or_review:
  dedup_key:
  delivery_channels:
  acknowledgement:
  resolution_ref:
```

Delivery and resolution are separate.

