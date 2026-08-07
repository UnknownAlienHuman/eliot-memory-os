---
name: eliot-work
description: "Verify ELIOT work and build governed project memory"
---

# ELIOT work

## Meta principle

Every material task produces (1) verified Governor/plugin and system behavior,
and (2) reusable project data: current facts, history, failures, timings,
decisions, and procedures, with provenance and freshness.

Use only Governor `eliot_*` tools; never bypass them with raw database access.
Resolve project identity first. After each write require its receipt plus exact
`eliot_fetch_l2` at that revision. Record schema/projection/readback failures and
plugin wall time separately from product/verifier time. Ground data in current
source and history; label dirty and legacy evidence. Retry once only after a
changed condition.

Start working; context arrives with the first successful ELIOT call. For a
material change:

1. Call `eliot_compile_packet_l3` with `goal`. Read the packet and verifier.
   Edit the returned `frame_stub`, preserving its revision.
2. Make the change. On an error or failed test, check `ul_fired` for a matching
   episode before debugging from scratch.
3. Run the packet verifier. Do not replace it with model judgment.

Worked fixture — values prefixed `EDIT:` are the five model-owned edits:

```json
{
  "stub_rev": 7,
  "frame_stub": {
    "task_id": "01930000-0000-7000-8000-000000000001",
    "intent": "EDIT: repair bounded parser",
    "expected_observable": "EDIT: parser fixture passes",
    "next_allowed_action": "EDIT: change parser.rs only",
    "active_plan": ["EDIT: patch", "verify"],
    "completed_work": [],
    "killed_paths": [],
    "causal_bridge": [
      {"from":"goal","to":"parser::decode","relation":"EDIT: owned_by"}
    ],
    "negative_memory_checked": true,
    "stop_condition": "mapped verifier passes",
    "verifier": "cargo test -p fixture parser"
  }
}
```

Keep every other field supplied by the server. If a capsule header begins
`[STALE ...]`, verify it against current code before relying on it.
