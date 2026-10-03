# Active continuation map

Source baseline: `b7e9e334569639a6290baeacf82bf44941def506`. Machine-readable state: [BLOCK-MAP.tsv](BLOCK-MAP.tsv).

This revision contains 28 issue records: two READY source assignments, one WAIT
consumer and 25 RECHECK records. It is not a refreshed 577-issue completion count.
The complete historical inventory is preserved in STOP-BLOCK-MAP.tsv, unchanged.
Unlisted issues remain unreviewed and can be considered next; none is implicitly READY,
DONE, or blocked on the completion of this entire audit.

## Ready to implement after live preflight

| Issue | Manager | Remaining source obligation |
|---|---|---|
| #1943 | M-KERNEL | Connect existing role-capability policy to authenticated admission/transition; no second engine. |
| #2691 | M-STORE | Supervised no-client snapshot expiry and bounded budget diagnostics. |

The scopes in PLAN.tsv are disjoint, including direct tests/manifests. Root-only and
#5021 paths are excluded. These are assignment checks, not runtime proof.

## What is no longer an executable blocker

`t-`, numeric counters, missing-document placeholders and historical issue mentions
are not dependency edges. OR corrections were review input; only the explicit
current rows above are source-work assignments. In particular, #1678 must not be
assigned from the old assertion that an async coordinator is absent: current main
already contains admission_reservation_saga.rs. Its actual remaining producer/receipt
join requires inspection. #11's closed state is not a future event to wait for.

The eight historical cycle groups are held as bounded ownership-review work in
STITCH-PLAN.md, not imported into the scheduler. Their edges must be classified,
not deleted merely to claim an acyclic architecture. Every active `depends_on` is
explicit; no parser infers dependencies from prose or from the evidence URL.

## Data contract

`state`: READY = source assignment selected; WAIT = named deliverable not released;
RECHECK = inspect current evidence/ownership before assigning source changes.
`kind`: WIRING, PROOF or REVIEW. `items` refer to the issue's existing requirements,
not separately delivered mini-issues. `depends_on` is a JSON string array; the current
consumer #1701 waits on `1678:active-owner-evidence`, not on closure of all #1678 tests.

Only root updates this map and its READY projection in PLAN.tsv. A new READY row must
have a matching assignment, full scope and current evidence. A source change, new
comment or altered dependency invalidates only affected entries. No automatic issue
closure follows from these planning states.
