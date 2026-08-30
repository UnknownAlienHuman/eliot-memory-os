## I12.2. Capture path

Agent-facing `eliot.observe` accepts natural content with optional hint:

```yaml
ObservationInput:
  text_or_structured_payload:
  hint: observation | decision | failure | outcome | unknown | reuse_candidate | auto
  task_id: optional
  affected_resources: optional
  expected_reuse_note: optional
  source_handles: optional
```

Governor auto-attaches:

```text
principal/session/model route;
WorkScope/task;
time and State Fence;
touched paths/entities/tools;
origin and instruction taint;
privacy/visibility;
exact action/tool lineage.
```

No observation is rejected only because the agent chose wrong kind. Invalid authority/privacy/scope can reject effect, but raw safe capture becomes candidate when possible.

