---
name: eliot-recover
description: "A test failed or an error appeared"
---

# ELIOT recover

1. Inspect `ul_fired`. If a matching episode applies, try its fix path first.
   When it prevents recurrence, acknowledge the handle with
   `influence_class=prevented_repeated_failure` and the real run reference.
2. If nothing matches, call `eliot_write_cognitive_observation` with the
   normalized error or diagnostic in `payload`, then continue debugging.
3. After solving it, submit a `failure_fingerprint`. Its statement is three
   short lines: symptom, cause, proven fix.

Never claim that memory changed the outcome without a downstream reference.
One discriminative retry after a changed condition is useful; an identical
retry is not evidence.
