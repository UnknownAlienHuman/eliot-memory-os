# Shared seams — ownership is not whole-issue dependency

No entry changes product contracts. SOURCE / SOURCE_SUBSET mean bounded source inspection, not full issue acceptance;
BODY means the current issue partition was read but the full source/thread join is
not verified. BODY and HISTORICAL findings are not implementation-ready certifications.

## Source-checked seams

- #1943: authenticated admission/transition -> existing ApplicationSession role
  policy -> issued capability and prior-context revocation -> operation enforcement.
  M-KERNEL owns the shared IPC/Kernel turns. Role labels do not mint authority.
- #2691: S-03 owner lifetime -> adapter maintenance entry -> existing bounded expiry
  and retirement -> diagnostics. M-STORE preserves #2688/#2689 shared state; those
  issues cannot independently rewrite backup_snapshot.rs concurrently.
- #1678/#1701: the async coordinator exists, but production eliotd admission,
  activation and dispatch ports still refuse unconditionally. Map each method to
  the existing authenticated owner operation and retained result. The daemon-launch
  reservation check is not proof of this native-worker attempt join. The complete
  prospective scope includes eliotd/worker consumers, outside #1943's initial claim;
  root must assign those paths explicitly. No second saga or whole-parent test wait.
- #2643: CreateContext's fresh nonce -> current identity validator -> actual client
  -> fresh State Fence -> business request. The validator currently applies the
  incompatible business digest rule to the handshake. Keep non-handshake digest/fence
  and legacy-recovery guards intact. Both UI read/effect callers are affected; the
  existing tests/Eliot.Operator.Tests harness is present. Reconcile the current
  closed wire and shared #2644/#1137 files before an implementation assignment.
- #1884/#1888: reuse main's CPU-rate implementation. Isolate #1888 from archived
  mixed CB work; one platform-file writer for manifest/Job cleanup integration.
- #2701: #929 check(Path) -> strict accepted-result validation -> CheckedInventory ->
  closure report. M-TOOLS owns the two named scripts. Root alone refreshes the global
  generated boundary inventory on the combined source; no competing scanner/authority.

## Existing PR collisions at dispatch

All 26 initially open PR IDs and their complete changed-file lists were screened:
17 owner-authored plus 9 Jules PRs. #2707 was then closed without merge because its
sole script-registration row is already in main; the follow-up query reports 25 open.
This is complete PR-path coverage for that read, NOT a complete issue/code audit or
proof of live writers. PLAN.tsv carries the selected scopes' conflicting_prs and
an explicit dispatch_gate; READY alone never authorizes a claim.

| Retained candidate | Kernel-scope paths | Store-scope paths | Required reconciliation |
|---|---:|---:|---|
| #2369 @ f4f65557106d | 18 | 0 | Compare the old 146-file runtime join with current owner deliveries; do not reapply the whole branch. |
| #3811 @ 0112b59c3b6b | 3 | 4 | Integration-candidate dispatch/catalogue/apply; serialize with #3812. |
| #3812 @ f371ca8958fa | 3 | 4 | Mailbox dispatch/catalogue/apply; preserve its separate requirements. |
| #3869 @ bce9207b52a2 | 4 | 5 | Actual diff has 44 files, including Kernel/protocol and S-03 composition/lifetime; title is not scope. |
| #4490 @ 29d22677f26a | 5 | 0 | Restore transport and Store gateway must share their real integration owner. |
| #4599 @ 0ea687a3fdf5 | 2 | 0 | Retain diagnostic evidence separately; compare already-delivered shutdown/source repairs. |
| #4845 @ 8f03723f826d | 3 | 0 | Actual delta is Kernel restore/dispatch, despite its docs/Watchdog description. |

No screened PR touches either selected #2701 script. That removes this PR-path
obstruction only; actual local claims and required reads still need preflight.
For Kernel/Store, RECONCILE_PR_SCOPE forbids issuing the current broad claim until
root records adoption of reviewed residuals, a genuinely disjoint narrowed scope, or
explicit old-writer release with unmatched work retained. Full historical PR closure
is not required for disjoint work. A filename intersection is not proof that all
hunks remain new: compare merge-base, candidate and current main before disposition.
No author attribution of inherited hunks is inferred from a PR title or file list.

Reconcile current IDs before reusing this screen; obtain actual all-page filenames,
including old/new names for renames. Refresh a changed head or changed selected scope.
Store the claimed candidate identity and disposition at the controller, not a count
alone. Scope must also cover shared contracts/manifests/generated outputs; this
filename scan is not proof that every semantic integration edge is independent.

## Reviewed integration holds

- #4999 @ d4dfbbe4870a is draft with REQUEST_CHANGES. Its evidence verifier fallback
  manufactures premutation reading attestation and recognizes fixture prose to retain
  selected negative results. Do not merge or reuse that fallback; candidate byte
  recomputation cannot establish who read before editing. Restore uniform absent-block
  refusal and actual author-produced evidence. Other doc corrections require their
  own comparison with #5021/#4688, not blanket acceptance or rejection.
  Evidence: PR #4999 review 5398877744; full gate/CI execution was not performed.
- #3058 @ f93239dec051 is draft with a source-review hold, not a blocking self-review.
  Its five-field materializer predates current RecordedRevocation V2. Port unmatched
  #686 work to real commit-fence/namespace/bounds/coverage/digest producers; preserve
  #2966 recovery decisions. Do not restore V1 or fill new coordinates with defaults.
  Evidence: PR #3058 review 5398880483; no Rust compiler run or full #686 audit.

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
