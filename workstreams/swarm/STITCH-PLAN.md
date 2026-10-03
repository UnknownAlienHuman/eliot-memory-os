# Integration seams and PR dispositions

This file records only cross-assignment joins and candidate dispositions. It is not
product authority and not a second dispatch queue. Canonical sections are linked from
`PLAN.md`. Source observations below bind
`main@b7e9e334569639a6290baeacf82bf44941def506`; refresh changed inputs before
dispatch. No row proves that a local or external writer has stopped.

## READY set — no shared files

| Issue | Owner -> consumer path | Exact-file rule |
|---|---|---|
| #3980 | `SurrealServerConfig` validator -> Governor config / supervisor / RPC client, before effects | Four legacy files only; no modern Store or retirement dependency |
| #2691 | S-03 lifetime -> adapter maintenance owner -> expiry/retirement -> diagnostics | Five PLAN files; preserve #2688/#2689 and compatibility code |
| #2643 | fresh `get_context` nonce -> current identity guard -> client -> owner fence -> business request | Two C# files; MainViewModel/journal/Rust remain read-only |
| #2701 | #929 `check(Path)` -> strict result validator -> `CheckedInventory` -> closure report | Two scripts; root alone refreshes combined generated inventory |

All 13 selected paths are pairwise disjoint. The prior complete PR filename screen
contained no contact with #3980, #2643 or #2701. That is an observed snapshot, not a
current runner claim. Recheck new/changed heads and actual controller claims.

## #2691 — exact-file reconciliation, not whole-PR waiting

The former two-subtree reservation is replaced by the five files in `PLAN.tsv`.
#3811/#3812 change `apply/*`, not those five files, and are not snapshot prerequisites.

#3869 at `bce9207b52a29cfa0b2439d69c4235a49fe27fd4` contacts three selected files.
Every hunk in those files was compared with the checked `main`:

| Shared file | #3869 material already present in main |
|---|---|
| `bins/eliot-store-surreal/src/lib.rs` | `install_compatibility_decision` re-export |
| `bins/eliot-store-surreal/src/main.rs` | imports, compatibility input constants, typed health projection, installation/path helpers and early run branch |
| `bins/eliot-store-surreal/src/diagnostics.rs` | `CompatibilityVerdict` import, decision/health types and projection |

**Disposition: `PRESERVE_MAIN` for those hunks only.** No #3869 merge is required
before snapshot maintenance. Do not replay old whole-file bytes. A live writer still
requires explicit transfer because different lines of one file are not independent
claims. The other 41 paths, whole-file equivalence, runtime correctness and whole-PR
supersession were not established; #3869 remains open and unaccepted.

## #1943 — canonical producer missing; no Kernel reservation

### Existing source that must be preserved

- `crates/kernel/eliot-ipc/src/role_lease.rs` contains a local closed role policy and
  in-memory capability context.
- `ApplicationSession` can admit/transition/clear that context.
- the real agent-bridge activation creates and attaches `ApplicationSession`.
- canonical authority already flows through Governor compilation,
  `MechanicalAuthoritySubset`, Kernel activation/revocation and current
  GovernanceProfile publication.

### Confirmed missing join

No current owner operation supplies the local `WorkScopePolicy`,
`DelegatedAuthority`, role transition or `IndependenceDowngrade`; searches find those
types only in `eliot-ipc` and its tests. No production caller invokes
`admit_role_capability` / `transition_role_capability`, and no real plan/work/evaluation
boundary calls the local authorization method. `AgentActivationResolvedBinding` and
free-form swarm `assigned_role` do not carry or prove this authority.

### Required producer output

Before a #1943 writer claim, the canonical owner path must expose one current activated
role assignment/transition projection containing:

```text
principal/session/task/work-item/WorkScope/route;
role and narrowed operation set;
GovernanceProfile revision;
State Fence and authority/lease epoch;
issue/expiry/current revocation;
canonical source/content commitment;
prior-context supersession;
explicit verifier-to-mutating-role independence downgrade when applicable;
Kernel activation receipt.
```

This is a narrow owner output, not a wait for every #1794 acceptance test. It must be
compiled through the existing mechanical-authority path, not minted from a role label
inside Kernel.

### Release

After that exact output exists, root may assign the finite consumer closure:
authenticated projection read -> `ApplicationSession` bind/transition -> prior-context
revocation -> real operation enforcement. Publish exact files only then. Until release,
#1943 is `RECHECK`, owns no paths and does not block unrelated Kernel work.

## #1701 — existing saga, incompatible/missing Fabric owner legs

### Existing source that must be preserved

- `bins/eliot-kernel/src/admission_reservation_saga.rs` is the canonical
  receipt-readback, admit/activate and recovery owner for an already staged reservation.
- daemon frame dispatch admits `admission_reservation.admit`.
- the native-worker path already refuses rejected/revoked claims before start and
  retains unknown process-start outcomes instead of blanket reset/release.

### Confirmed missing join

The production `eliotd` Fabric ports still report `Missing`:

```text
ProductionAdmissionAuthorityPort::stage_reservation
ProductionAdmissionAuthorityPort::commit_admission
ProductionActivationAuthorityPort::activate
ProductionDispatchEgressPort::emit
```

This is not solved by calling the saga from a unit struct:

- Fabric asks synchronously to stage from `SwarmDefinition`;
- Kernel admit/activate accepts only an exact reservation already staged and bound to
  work item plus proposed attempt;
- the owner call is authenticated and asynchronous;
- dispatch has no accepted retention/executor owner operation.

The daemon-launch reservation guard covers a different contour. A local `Bound`
constant, copied `Active` snapshot, injected success or `block_on` wrapper would create
false authority.

### Required outputs

Freeze these existing-owner interfaces before assigning code:

```text
A. durable stage request/result binding definition, work item, proposed attempt,
   claim/executable/route/resource identities, deadline, epoch/fence and reservation;
B. daemon authenticated client result for admission_reservation.admit, including
   canonical receipt/outbox proof and activation receipt;
C. dispatch-egress operation retaining the original dispatch identity and consuming
   the same active reservation/attempt, with unknown-outcome reconciliation;
D. accepted asynchronous composition boundary for A-C.
```

When A-D exist, assign exact `eliotd` adapter files and actual Kernel/native-worker
consumers in one serialized turn. A producer output can release the consumer before
#1678/#1679/#1680 close, but absent owner state cannot be fabricated locally.
#1701 remains `RECHECK`, owns no broad subtree and does not stop Store/tools work.

## Other reviewed seams

- #1678: the async coordinator exists. Recheck the actual stage/receipt/activation
  producer join; do not create another saga.
- #1884/#1888: reuse main's CPU-rate implementation. One platform-file writer owns
  any remaining manifest/Job cleanup join.
- #686/#3058: current `RecordedRevocation` is V2. Do not restore the old five-field
  materializer or default new provenance coordinates.
- #818: its current Valid/READY output is not dispatch clearance; repair the existing
  oracle, not a second scheduler/checker.

## Retained PR decisions

- **#4999 @ `d4dfbbe4870a` — REQUEST_CHANGES.** Reject the missing-evidence
  synthesizer and fixture-prose exceptions. Final-byte recomputation cannot attest
  premutation reading. Genuine producer evidence plus I18.27 oracle review remain
  required; unrelated documentation corrections are separate.
- **#3058 @ `f93239dec051` — source-review hold.** Port unmatched #686 work to
  current V2 commit-fence/namespace/bounds/coverage/digest producers; preserve #2966
  recovery decisions. Do not restore V1 or fill evidence with defaults.
- **#2707 — closed without merge.** Its only registration row already exists on
  `main`; no source or parent acceptance follows from closure.

The previous 26-PR filename screen and obsolete broad-scope counts remain in
[the inspected revision](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/3aa7cc157fee31ffc0c64531b00013a62dc6babf/workstreams/swarm/STITCH-PLAN.md).
They are evidence of that read, not current locks. Compare merge-base, candidate and
current `main` before adopting unmatched work; titles and author identity do not define
scope.

## Historical dependency groups — review, not launch order

| Group | Boundary still requiring current source/thread verification |
|---|---|
| #8 / #1746 | existing bootstrap response vs real owner-source assembly/delivery |
| #1229 / #3004 | dependency-policy preparation inputs vs compile-gate consumer |
| #1767 / #2893 | portfolio/denominator owner vs exact no-match/source/evaluator evidence |
| #18 / #2892 / #2968 | host wiring vs packaging/disposition vs assembled-product proof |
| #1126 / #1699 / #2567 / #2866 | exact execution/admission output and consumer handoff |
| #1762 / #1769 | inquiry/source-admission producer and restricted consumer |
| #1789 / #1791 | authoritative transition vs plan/context projection |
| #1934 / #2561 / #2731 / #2732; #2729 / #2730 | privacy/event/stream/handoff/ack/recovery sequencing |

The first three groups were body-reviewed; their complete current source/thread joins
are not certified. Do not delete an unverified edge to manufacture a DAG. For coverage,
no fabricated evaluation receipt, I/O inside the pure assessor, or promotion of package
verdict to release authority.

Decision leads remain #332 layout, #1968 pair/Blob identity, #1844 R2 vocabulary,
#2882 part 5, #238 Context-cell owner and #956 purge/publication ports. Check canonical
sections and current producers before declaring a missing contract.

## Release rule

A real wait names the consumer item, exact producer output/type/operation and observable
release condition. Issue linkage, internal checklist order and final parent acceptance
are not interchangeable prerequisites. Record disposition in the existing controller
ledger; transfer physical files explicitly. After integration, refresh only affected
consumers/findings. Independent cleared work continues.


## Seams from the review of 2026-10-03 15:22

The lanes recorded 559 seams in `STITCH-20261003.tsv` (seam, issues, shared files or outputs, PR, disposition, evidence). Files written by several READY rows (sequenced into different waves):

| file | issues |
|---|---|
| `crates/kernel/eliot-ors/src/store.rs` | #269 #1953 #2627 #2763 #2764 #2798 #2863 #2885 |
| `bins/eliot-host/src/lib.rs` | #891 #961 #1953 #2737 |
| `crates/governor/eliot-governor/src/composition.rs` | #1191 #2380 #2663 #2962 |
| `bins/eliot-agent-bridge/src/lib.rs` | #1939 #2570 #2799 #2800 |
| `crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml` | #88 #1025 #2738 |
| `bins/eliot-host/src/backup_cutover.rs` | #961 #2737 #2738 |
| `crates/kernel/eliot-installation/src/tests.rs` | #1138 #1148 #3001 |
| `crates/governor/eliot-authority/src/grants.rs` | #1142 #2962 #2976 |
| `crates/governor/eliot-governor/src/owner_closure_provider.rs` | #1142 #2962 #2976 |
| `bins/eliotd/src/lib.rs` | #1191 #1910 #2663 |
| `bins/eliot-wasm-host/src/request_loop.rs` | #1956 #2786 #2896 |
| `bins/eliotd/src/daemon_runtime.rs` | #2559 #2560 #2647 |
| `crates/kernel/eliot-kernel-service/src/store_gateway.rs` | #2763 #2764 #2971 |
| `crates/governor/eliot-canonical/src/lib.rs` | #63 #2570 |
| `crates/storage/eliot-store-memory/src/lib.rs` | #63 #2859 |
| `bins/eliot-kernel/src/lib.rs` | #88 #2627 |
| `bins/eliot-watchdog/tests/spool_backup.rs` | #458 #955 |
| `crates/smart/eliot-dreamer-conflict-analysis/src/lib.rs` | #673 #2870 |
| `bins/eliot-store-surreal/src/lib.rs` | #742 #1933 |
| `crates/storage/eliot-store-api/src/lib.rs` | #950 #2859 |
| `crates/kernel/eliot-ors/tests/restore_journal.rs` | #957 #2653 |
| `bins/eliot-kernel/src/backup_capture.rs` | #959 #2863 |
| `Cargo.lock` | #974 #2857 |
| `crates/storage/eliot-store-surreal-adapter/src/apply.rs` | #989 #1933 |
| `crates/governor/eliot-skill/src/lib.rs` | #1191 #2663 |
| `crates/governor/eliot-skill/src/activation.rs` | #1191 #2663 |
| `bins/eliotd/src/skill_dispatch.rs` | #1191 #2663 |
| `crates/surfaces/eliot-agent-bridge-core/src/lib.rs` | #1191 #2799 |
| `bins/eliot-agent-bridge/src/hook_intake.rs` | #1219 #4601 |
| `bins/eliot-kernel/src/daemon_request_dispatch.rs` | #1905 #2875 |
| `bins/eliotd/src/startup_readiness.rs` | #2560 #2647 |
| `crates/kernel/eliot-kernel-service/src/wasm_dispatch.rs` | #2568 #2786 |
| `crates/storage/eliot-store-surreal-adapter/src/backup_restore.rs` | #2666 #2859 |
| `crates/storage/eliot-store-surreal-adapter/src/backup_snapshot.rs` | #2688 #2689 |
| `crates/kernel/eliot-kernel-service/src/commit_recovery.rs` | #2763 #2764 |
| `crates/kernel/eliot-ors/src/store/backup_snapshot.rs` | #2885 #2967 |
| `crates/governor/eliot-governor/src/owner_closure_feed.rs` | #2962 #2976 |
