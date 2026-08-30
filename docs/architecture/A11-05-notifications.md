## A11.5. Notifications

Notifications have severity, owner, evidence, deduplication, cooldown, acknowledgement, and resolution state. Every unresolved Action-required or Critical item remains in a persistent inbox regardless of a transient toast or channel.

```text
Critical — integrity, security, unknown external effect, or unrecoverable loss of control;
Action required — approval, blocked task, or credential or integration failure;
Warning — repeated agent failure, hook loss, queue pressure, or stale backup or profile;
Info — verified completion, onboarding, or audit or research report.
```

Delivery is not resolution. Alert fatigue and missed notifications are measured.

**ARCH-HUM-01 — Human remains in control without constant micromanagement.** ELIOT automates ceremony while preserving a comprehensible picture, decision points, and the ability to intervene at any stage.

---
