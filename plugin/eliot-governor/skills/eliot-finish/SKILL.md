---
name: eliot-finish
description: "Verify ELIOT work and memory writeback"
---

# ELIOT finish

## Meta principle

Finish has two acceptance surfaces:

1. the requested project/system behavior was checked with the owning verifier;
2. novel project knowledge and plugin self-test evidence were written through
   the Governor and fetched back exactly with `eliot_fetch_l2`.

For new records, report the receipt, revision, exact returned handles,
missing/forbidden lists, lifecycle/projection state, and independent readback
when available. Keep product SLO, test body/wall, build overhead, provider time,
and plugin response time distinct. Run read-only curation preview when data was
added; never auto-promote weak or sleep output. Ordinary data building must not
bypass the Governor with raw database access.

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
do not write summaries into memory and do not restate the diff as a lesson. If
the canonical trace, verifier, projection, or reconciliation authority is
missing, leave the task/candidate open and report partial status instead of
manufacturing completion.
