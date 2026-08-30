## I16.16. No-progress, loop and external telemetry projections

No-progress detector observes evidence/artifact/state deltas, not prose volume. Useful progress includes a new relevant entity, hypothesis with evidence, test/repro result, accepted patch delta, resolved finding or verifier outcome.

Detection ladder:

```text
telemetry warning
→ ask route to report bounded blocker state
→ suspend lane and create Diagnostic Brief
→ Task Controller/Dreamer/Watchdog review
→ cancel and reconcile
→ alternate route or Human escalation.
```

Repeated normalized `(tool, args, error)` tuples, child-spawn cascades, parent waiting on dead child and rising usage without evidence trigger the same bounded breaker. Automatic endless `continue` is forbidden.

OpenTelemetry/OpenInference export is an optional redacted projection of canonical ELIOT events. It is not canonical storage and may not receive prompts, tool arguments, secrets or raw native traces unless policy explicitly permits them.


