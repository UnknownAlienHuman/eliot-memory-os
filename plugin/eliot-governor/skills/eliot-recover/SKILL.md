---
name: eliot-recover
description: "Recover from ELIOT failures and preserve reusable evidence"
---

# ELIOT recover

## Meta principle

A failure in the plugin/system loop is both a problem to diagnose and data to
preserve. Capture the operation, normalized input shape, error, side-effect
status, projection/revision, client-observed wall time, exact source or run
reference, and the condition changed before retry. Keep product latency,
verifier body/wall time, build overhead, provider time, and plugin control time
as separate dimensions.

1. Inspect `ul_fired`. If a matching episode applies, try its fix path first.
   When it prevents recurrence, acknowledge the handle with
   `influence_class=prevented_repeated_failure` and the real run reference.
2. If nothing matches, call `eliot_write_cognitive_observation` with the
   normalized error or diagnostic in `payload`, then continue debugging.
3. After solving it, submit a `failure_fingerprint`. Its statement is three
   short lines: symptom, cause, proven fix.
4. Verify every new observation or candidate by exact `eliot_fetch_l2`
   readback at the committed revision. Preserve superseded causes as history and
   add a superseding observation; do not silently overwrite them.

Never claim that memory changed the outcome without a downstream reference.
One discriminative retry after a changed condition is useful; an identical
retry is not evidence. Do not bypass a plugin failure with raw database access.
