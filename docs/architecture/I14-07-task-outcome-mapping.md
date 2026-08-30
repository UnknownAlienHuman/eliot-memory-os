## I14.7. Task outcome mapping

| Job/run outcome | Task consequence |
|---|---|
| COMPLETED | candidate artifact/result; acceptance only after applicable verifier |
| PARTIAL | task remains active or may finish `PARTIAL` with explicit coverage |
| FAILED | alternate plan/retry may run; task status depends on acceptance and evidence |
| CANCELLED | task remains active or receives authorized `CANCELLED` outcome |
| STALE | result excluded; replan/requeue; never proof |
| UNKNOWN_OUTCOME | dependent effects/finish pause until reconciliation or explicit accepted risk |
| DEFERRED_CAPACITY | task remains active; may wait, narrow, approve budget or select another route at a new attempt boundary |

Job completion never equals task completion automatically.

