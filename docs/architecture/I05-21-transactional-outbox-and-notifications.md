## I5.21. Transactional outbox and notifications

Domain transition, receipt, revision and outbox intent commit atomically. Outbox delivery is at-least-once and idempotent.

```text
subscriber lag never blocks canonical commit;
undelivered rows remain queryable;
resource/job/mailbox notifications carry sequence;
projection/cue/cache consumers checkpoint cursor;
outbox mismatch opens projection-health Problem State.
```

Sender WAL/outbox state does not prove that a sink accepted or applied an item. The existing event/receipt owner records sink-side phases:

```text
ARRIVED
→ CLAIMED under consumer generation/claim fence
→ APPLIED | REJECTED | UNKNOWN
→ READBACK_CONFIRMED | IRRECONCILABLE.
```

`arrival_fence` prevents replay from an obsolete producer lineage; `claim_fence` prevents two consumer generations from applying the same logical item concurrently. Cursor advancement is bound to the declared sink phase. Crash after sender commit but before sink-owned acceptance remains `UNKNOWN`; it is reconciled by stable operation/effect identity and sink readback, never inferred from timeout or missing acknowledgement.

Raw DB changefeeds are not an agent surface. A future changefeed may optimize the outbox only after equivalence proof.

