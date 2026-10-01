---
name: eliot-remember
description: "Build governed ELIOT project memory"
---

# ELIOT remember

Preserve facts and observed Governor behavior with provenance, scope, freshness and epistemic status.

Use `eliot_write_cognitive_observation` for facts, diagnostics, timings, dirty snapshots and corrections. Use `eliot_agent_candidate_submit` for a reusable finding; keep it `candidate_only` until controller reconciliation.

Save only novel reusable material: `claim` (bounded fact), `decision` (choice and reversal conditions), `failure_fingerprint` (symptom, cause, proven fix), or `skill` (repeatable procedure and trigger). Ask exactly: **when will this matter again and what will be on screen at that moment?** Put the answer in `expected_reuse_note`.

Submit with retry-stable `write_id`, `topic`, `statement`, applicability/negative-constraint arrays, `provenance_refs`, `freshness_rule` and `expected_reuse_note`. Derive cues only from a reusable cue touched this session; otherwise provide explicit file/symbol bindings.

After every write, call exact `eliot_fetch_l2` with the returned handle and `at_least_revision`. Verify the handle returned, missing/forbidden lists empty, stored payload matches and task relations exist. A receipt without exact readback is incomplete.

For decisions retain `chosen_because`, `alternatives` and `revisit_when`. Never copy recalled material or task summaries into candidates. Do not use raw DB for plugin data building.
