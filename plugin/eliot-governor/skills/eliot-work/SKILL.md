---
name: eliot-work
description: "Material code change in an ELIOT project"
---

# ELIOT work

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
