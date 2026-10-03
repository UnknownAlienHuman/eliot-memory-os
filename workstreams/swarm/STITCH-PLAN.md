# Shared seams — ownership is not whole-issue dependency

No entry changes product contracts. SOURCE means a bounded source inspection;
BODY means the current issue partition was read but the full source/thread join is
not verified. BODY and HISTORICAL findings are not implementation-ready certifications.

## Source-checked seams

- #1943: authenticated admission/transition -> existing ApplicationSession role
  policy -> issued capability and prior-context revocation -> operation enforcement.
  M-KERNEL owns the shared IPC/Kernel turns. Role labels do not mint authority.
- #2691: S-03 owner lifetime -> adapter maintenance entry -> existing bounded expiry
  and retirement -> diagnostics. M-STORE preserves #2688/#2689 shared state; those
  issues cannot independently rewrite backup_snapshot.rs concurrently.
- #1678/#1701: the async admission_reservation_saga.rs coordinator already exists.
  Verify the exact current active-reservation output needed by #1701. A missing
  currentness check in planning is RECHECK, not proof of an unavailable dependency.
  Reuse the owner verifier; don't recreate the coordinator or wait for all #1678 tests.
- #1884/#1888: reuse main's CPU-rate implementation. Isolate #1888 from archived
  mixed CB work; one platform-file writer for manifest/Job cleanup integration.
- #2701: #929 check(Path) -> strict accepted-result validation -> CheckedInventory ->
  closure report. M-TOOLS owns the two named scripts. Root alone refreshes the global
  generated boundary inventory on the combined source; no competing scanner/authority.

## Body-verified cycle partitions: exact outputs before closure

| Pair | Existing ownership and required handoff | Write collision to resolve |
|---|---|---|
| #8 / #1746 | #8 bootstrap response contract; #1746 real owner-source assembly/delivery. Reuse the existing response. A missing producer does not make the existing response undefined. Verify the emitted owner-bound response in the consumer before final integration. | Bootstrap/Bridge composition; one shared-file writer. |
| #1229 / #3004 | #1229 dependency-policy preparation entrypoint supplies declared inputs; #3004 invokes it for the compile gate. Preparation is not a policy verdict. Release the consumer when its actual required input contract is present; CI execution is separate evidence. | Preparation scripts/profile and workflow owner; no workflow edits delegated by this plan. |
| #1767 / #2893 | #1767 retains portfolio/denominator/accounting ownership. #2893 owns the exact no-match/source-record/evaluator-evidence join. #1762 supplies live composition; #1765 owns final release audit. Agree the existing typed input, implement the no-match check, then integrate #1767's consumer and existing release owner; never wait for the parent to close first. | evidence_portfolio.rs and shared receipt adapter; one sequential writer, separate issue deliveries. |

The coverage pair does NOT license local evaluation receipts or I/O in the pure
assessor. Missing vetted records, complete predicate evidence or a genuine empty-scope
contract stays Unproven. Package Proven does not authorize release. #2893 explicitly
states these boundaries; do not fix the cycle by bypassing them. The full current
comments/source of these three pairs still need verification before source assignment.

## Other historical cycle groups — no guessed issue order

#18/#2892/#2968: host wiring versus packaging/disposition versus post-assembly proof.
#1126/#1699/#2567/#2866: exact execution/admission output and consumer-specific handoff.
#1762/#1769: existing inquiry/source-admission producer and restricted consumer.
#1789/#1791: authoritative transition versus plan/context projection.
#1934/#2561/#2731/#2732, with #2729/#2730: privacy, retained event/projection,
stream authority, bounded handoff, sequencing, acknowledgement and recovery. Use one
writer for shared Kernel/ORS/protocol turns, not one independent writer per issue.

Every real wait names consumer item, producer output, exact type/operation and
observable release condition. Internal item order, parent acceptance and related links
are not hard dependencies. Do not drop an unverified edge to obtain a green DAG.

## Decisions to verify, not presumed missing contracts

#332 layout; #1968 pair/Blob identity boundary; #1844 R2 vocabulary; #2882 part 5;
#238 Context-cell owner; #956 concrete purge/publication ports. Check the actual
canonical section and current producer first. An omitted issue owner is assignment
work, not automatically an Architecture decision. These do not hold independent scopes.
