---
name: eliot-remember
description: "Save a lesson, decision or failure to memory"
---

# ELIOT remember

Save only novel reusable material:

- `claim`: a fact with an evidence boundary.
- `decision`: a chosen path and the conditions that could reverse it.
- `failure_fingerprint`: symptom, cause, and proven fix.
- `skill`: a repeatable procedure with a clear trigger.

Ask exactly: **when will this matter again and what will be on screen at that
moment?** Put the answer in `expected_reuse_note`.

Call `eliot_agent_candidate_submit` with `statement`, `kind`, and
`expected_reuse_note`. Cue bindings are derived from paths and symbols touched
in this session; add explicit bindings only when auto-bind has no applicable
cue. Use `dry_run:true` when unsure about the form.

For a decision, retain the rationale:

```text
chosen_because: one discriminating reason
alternatives: the rejected viable paths
revisit_when: a concrete condition changes
```

Do not copy recalled material into a new candidate and do not save a task
summary merely because the task ended.
