---
name: eliot-finish
description: "Finishing an ELIOT task"
---

# ELIOT finish

Run the packet's verifier against the current accepted artifact scope. Report
failed, skipped, stale, or unknown checks honestly.

Ack every payload-injected item you acted on:

- changed action: `used_and_changed_action` plus outcome ref;
- verified work: `used_for_verification` plus outcome ref;
- prevented recurrence: `prevented_repeated_failure` plus run ref;
- not used: `seen_but_not_used` or `loaded_without_delta`;
- stale/wrong scope: `suppressed_as_stale` or
  `suppressed_as_wrong_scope`.

Submit only non-obvious reusable lessons through `eliot-remember`. Then stop:
do not write summaries into memory and do not restate the diff as a lesson.
