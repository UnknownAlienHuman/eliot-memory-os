---
name: eliot-work
description: "Verify ELIOT work and build governed project memory"
---

# ELIOT work

Material work yields verified system/plugin behavior and reusable project data (facts, history, failures, timings, decisions, procedures) with provenance and freshness.

Use only Governor `eliot_*` tools; never use raw DB. Resolve project identity first. Every write needs its receipt and exact `eliot_fetch_l2` at that revision. Separate schema, projection and readback errors and plugin time from product/verifier time. Ground data in current source/history; label dirty or legacy evidence. Retry once only after a changed condition.

Start work; context arrives with the first successful ELIOT call. For material changes:

1. Call `eliot_compile_packet_l3` with `goal`; read packet and verifier. Edit returned `frame_stub`, preserving its revision. Edit only the five model-owned fields: `intent`, `expected_observable`, `next_allowed_action`, `active_plan`, and `causal_bridge`; keep every server-supplied field.
2. Make the change. On error or failed test, check `ul_fired` for a matching episode before debugging from scratch.
3. Run the packet verifier; model judgment cannot replace it.

If a capsule begins `[STALE ...]`, verify it against current code before relying on it.
