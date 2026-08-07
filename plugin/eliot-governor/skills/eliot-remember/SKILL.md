---
name: eliot-remember
description: "Build governed ELIOT project memory"
---

# ELIOT remember

## Meta principle

Data building is a first-class output. Preserve project facts and observed
Governor behavior with provenance, scope, freshness, and epistemic status. Use
`eliot_write_cognitive_observation` for facts, diagnostics, timings, dirty
snapshots, and corrections; use `eliot_agent_candidate_submit` for one reusable
finding, kept `candidate_only` until controller reconciliation.

Save only novel reusable material:

- `claim`: a fact with an evidence boundary.
- `decision`: a chosen path and the conditions that could reverse it.
- `failure_fingerprint`: symptom, cause, and proven fix.
- `skill`: a repeatable procedure with a clear trigger.

Ask exactly: **when will this matter again and what will be on screen at that
moment?** Put the answer in `expected_reuse_note`.

Call `eliot_agent_candidate_submit` with a retry-stable `write_id`, `topic`,
`statement`, all applicability and negative-constraint arrays,
`provenance_refs`, `freshness_rule`, and `expected_reuse_note`. Let the plugin
derive cue bindings only when the session has a reusable touched cue; otherwise
provide explicit file or symbol bindings.

After every write, call exact `eliot_fetch_l2` with the returned handle and
`at_least_revision`. Verify that the handle is returned, missing/forbidden lists
are empty, the stored payload matches, and task relations are present. A receipt
without exact readback is incomplete writeback evidence.

For a decision, retain the rationale:

```text
chosen_because: one discriminating reason
alternatives: the rejected viable paths
revisit_when: a concrete condition changes
```

Do not copy recalled material into a new candidate and do not save a task
summary merely because the task ended. Do not use raw database access for
ordinary plugin data building.
