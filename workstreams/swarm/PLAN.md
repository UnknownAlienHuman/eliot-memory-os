# Selected source work

`PLAN.tsv` is the machine-readable selection. This file is the human execution packet.
Use **one row and one matching card only**. Do not load the other cards, the full
BLOCK-MAP, or unrelated Issue history into the worker context.

## Controller preflight — before giving a card to a manager

1. Re-read current `main`, the selected Issue/thread, its PLAN row and applicable PR heads.
2. Check only the row's exact files against selected-but-unstarted work, live claims and PR
   deltas. Transfer or stop an intersecting writer explicitly; unrelated runners continue.
3. Create one manager worktree and one fresh Issue branch from the published base.
4. Route all exact mutable paths together with `scripts/docs_read.py`; the manager reads the
   complete verified bundle and nearest `AGENTS.md` before mutation.
5. Record the claim in the existing controller ledger: Issue, manager/session, worktree,
   branch, base SHA and exact files. `READY` alone is not a claim or launch receipt.

A manager edits only `EDIT`. `READ ONLY` identifies the smallest consumers needed to keep
the product path intact; it is not extra write scope. A newly discovered path requires a
root scope amendment before writing.

## Executor return — one compact handoff

Return exactly:

```text
issue / manager:
base SHA / candidate SHA:
changed files:
entry -> owner -> consumer path:
implemented residual:
preserved invariants:
commands actually run and exits:
deferred post-assembly acceptance:
remaining exact blocker or NONE:
```

Do not paste the Issue, documentation bundle, test logs or a diary into the repository.
Code and production wiring come first. Passing format/compile/Clippy is source evidence,
not behavioral acceptance.

---

## M-LEGACY — #3980

**Canonical:** [I15.4 secrets](../../docs/architecture/I15-04-secrets.md#i154-secrets);
[Appendix P boundaries](../../docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md#appendix-p-rust-public-boundary-interfaces).

**EDIT — exactly four files**

```text
crates/eliot-types/src/config.rs
crates/eliot-types/src/error.rs
crates/eliot-store/src/surreal_server.rs
crates/eliot-store/src/surreal_rpc.rs
```

**READ ONLY:** `crates/eliot-app/src/config.rs` and the current callers of
`SurrealServerConfig`.

**START:** `GovernorConfig::validate`,
`SurrealServerSupervisor::validate_admission`, and `SurrealRpcTransport::connect`.
The first accepts loopback-looking prefixes; the other two do not enforce the complete
local-only grammar before effects.

**MAKE:** one reusable full-grammar validator on `SurrealServerConfig`; all three
entrypoints call it before credentials, paths, process or socket work. Accept only the
already-documented literal bind and `ws://127.0.0.1:<valid-port>/rpc` form. Reject
userinfo, alternate host, trailing path, query, fragment, controls, whitespace and
missing/invalid/out-of-range ports.

**DO NOT:** add a dependency, normalize an external address to loopback, weaken the
reserved Store collision guard, revive legacy runtime, touch the modern Store daemon,
or echo the rejected URI/bind value in diagnostics.

**CHECK NOW:** scoped format, minimal Clippy for `eliot-types` / `eliot-store`, and
`git diff --check`. State every command and exit honestly.

**DEFER:** the existing valid-route and negative connection/secret-canary acceptance
from #3980 until product assembly. Do not close the whole Issue from source checks.

**DONE FOR INTEGRATION WHEN:** one predicate is consumed at all three real pre-effect
boundaries, reserved Store isolation is unchanged, and the four-file diff has no
unexplained changes.

---

## M-STORE — #2691

**Canonical:** [I14.3 reserve](../../docs/architecture/I14-03-control-reserve.md#i143-control-reserve);
[I5.16 evidence](../../docs/architecture/I05-16-common-durable-fields.md#i516-common-durable-fields);
[I5.13 backup](../../docs/architecture/I05-13-backup-and-restore.md#i513-backup-and-restore);
[I5.27 identity](../../docs/architecture/I05-27-canonical-operation-identity-and-effect-identity.md#i527-canonical-operation-identity-and-effect-identity).

**EDIT — exactly five files**

```text
crates/storage/eliot-store-surreal-adapter/src/backup_snapshot.rs
crates/storage/eliot-store-surreal-adapter/src/lib.rs
bins/eliot-store-surreal/src/lib.rs
bins/eliot-store-surreal/src/main.rs
bins/eliot-store-surreal/src/diagnostics.rs
```

**READ ONLY:** current snapshot API/receipt contracts and #2688/#2689 implementation
spans. `apply/*`, Store API, Cargo, manifests and compatibility policy are outside scope.

**START:** private `snapshot_owner_maintenance_tick` already performs bounded
expiry/retirement but has no supervised caller when clients disappear. Existing budget
accounting does not expose the requested bounded high-water and remaining-capacity view.

**MAKE:** S-03 process lifetime -> `StoreComposition` -> one narrow adapter method ->
the existing bounded expiry/retirement owner -> bounded diagnostics. Drive it while the
pipe is idle as well as after requests. The owner starts it, supplies the established
clock domain, and stops/joins it on every exit before dependent state is dropped.
Expose high-water/remaining values for the already-accounted dimensions without
turning estimates into claimed RSS/heap measurement.

**DO NOT:** add a detached service/task, second registry, new database, full-map scan on
every tick, silent eviction, reset-to-zero recovery, widened capacity, or a second
writer for #2688/#2689 state. Do not reapply #3869 compatibility hunks.

**CHECK NOW:** scoped format, minimal Clippy for the adapter/S-03 packages, and
`git diff --check`. Verify the five-file diff preserves the compatibility code already
on `main`.

**DEFER:** bounded idle-expiry, cancellation, retained-receipt and diagnostic behavior
proofs until assembly. An absent lifecycle caller is implementation work, not
`TEST-PHASE`.

**DONE FOR INTEGRATION WHEN:** idle lifetime reaches the existing maintenance owner,
shutdown cannot leave the driver detached, diagnostics are bounded, and exact
incarnation/replay/interruption/terminal-receipt semantics remain intact.

---

## M-OPERATOR — #2643

**Canonical:** [I11.12 UserAutomation](../../docs/architecture/I11-12-userautomation.md#i1112-userautomation);
[I7.20 failure identity](../../docs/architecture/I07-20-agent-facing-error-contract.md#i720-agent-facing-error-contract);
[I5.27 identity](../../docs/architecture/I05-27-canonical-operation-identity-and-effect-identity.md#i527-canonical-operation-identity-and-effect-identity).

**EDIT — exactly two files**

```text
apps/Eliot.Operator/Protocol/UserAutomationContracts.cs
apps/Eliot.Operator/Services/GovernorPipeClient.cs
```

**READ ONLY:** `MainViewModel`, pending journal and current Rust UserAutomation owner
contracts.

**START:** `CreateContext()` intentionally mints a fresh nonce, but
`ValidateCurrentIdentity()` applies the business-operation digest rule before the
client can send that closed `get_context` request.

**MAKE:** distinguish only `UserAutomationGetContextOperation` at the existing
validation boundary. It still requires valid key syntax, a fresh nonce and no
`expected_state_fence`. Every business operation still requires
`idempotency_key == DeriveIdempotencyKey(operation)` and the original closed fence.
Keep the client validation call; correct only its adjacent contract comment.

**DO NOT:** replace the nonce with a constant/hash, exempt every read operation, relax
strict decoding, re-encode retained legacy bytes, recompute pending identities, or
change MainViewModel/journal/Rust production files.

**CHECK NOW:** the repository's existing locked Operator build/format command and
`git diff --check`. This is C# work; do not substitute Clippy or create a harness.

**DEFER:** cross-language field-set and retained-recovery behavioral acceptance until
assembly. The narrow fix does not certify the whole UserAutomation runtime.

**DONE FOR INTEGRATION WHEN:** both UI read/effect flows can obtain the owner context,
business/current-recovery identity checks are unchanged, and superseded records remain
withheld under their exact original bytes and keys.

---

## M-TOOLS — #2701

**Canonical:** [I18.27 oracle ownership](../../docs/architecture/I18-27-oracle-ownership-and-test-change-governance.md#i1827-oracle-ownership-and-test-change-governance).

**EDIT — exactly two files**

```text
scripts/audit-serde-boundary-closure.py
scripts/serde_boundary_inventory.py
```

The second file changes only if the accepted #929 API itself must change.

**READ ONLY:** audit comment `5908785311`, recheck `5963910318`, the #929 result
contract and existing fixtures.

**START:** the current accepted-result validator still permits malformed identity,
counts, digest/ceiling/vocabulary and row shapes.

**MAKE:** implement the existing audit items 1–7 and preserve item 9 in the existing
validator. Keep exactly one `check(Path)` call. Validate closed identity/count/digest/
vocabulary/row shape before constructing `CheckedInventory`; retain valid
`unknown`/`needs-repair` findings and distinct inventory/closure digests.

**DO NOT:** create a second scanner, sync/fallback during ordinary checking, edit Rust,
workflows or generated TOML, refresh the global inventory from this branch, or
synthesize documentation evidence.

**CHECK NOW:** Python syntax, the existing scoped CLI/self-checks applicable to these
two scripts, and `git diff --check`. Report commands and exits.

**DEFER:** item-8 regression acceptance and the single combined-source global generated
inventory refresh to the root integration owner.

**DONE FOR INTEGRATION WHEN:** malformed accepted #929 results fail before
`CheckedInventory`, valid findings survive, and the two-file diff does not introduce
another acquisition or authority path.

---

# Not dispatchable yet — exact release outputs

These entries reserve no code files and do not block the four READY cards above.

## #1943 — role capability admission and transition

The local `eliot-ipc::role_lease` engine and `ApplicationSession` methods exist, but
current production source has no owner-issued role assignment/transition record feeding
them and no operation boundary consuming `role_capability().authorize(...)`. The local
`WorkScopePolicy`, `DelegatedAuthority` and downgrade structs are not canonical owner
evidence. A role label, `assigned_role`, or caller-built allow set must not mint
authority.

**Release output required before a writer claim:**

```text
owner-issued role assignment or role-transition identity;
exact principal/session/task/work-item/WorkScope/route binding;
current GovernanceProfile revision and State Fence;
authority/lease epoch, issue/expiry and current revocation state;
role-default operation set narrowed by owner WorkScope and delegation;
prior-context revocation/supersession;
explicit IndependenceProfile downgrade record for verifier -> mutating role;
canonical source/content commitment and Kernel activation receipt.
```

The output must be represented by the existing canonical authority path
(`eliotd` mechanical compilation -> `MechanicalAuthoritySubset` -> Kernel activation),
not by a second token engine or an `eliot-ipc` self-assertion. Once that producer exists,
split a narrow consumer unit: attach the activated projection to the exact
`ApplicationSession`, revoke the prior context on transition, and enforce it at the real
plan/work/evaluation operation boundaries. Until then #1943 remains `RECHECK`; it
holds no Kernel subtree.

## #1701 — fabric admission to native-worker dispatch

Preserve `admission_reservation_saga.rs`: it already performs canonical receipt
readback plus admit/activate for an **already staged** reservation. Preserve the merged
native-worker unknown-outcome/default-reset repair.

The current Fabric seams still do not line up with those owners:
`stage_reservation(&SwarmDefinition)` is a synchronous definition-level request, while
the Kernel saga requires an exact durable reservation already bound to work item and
proposed attempt; `admission_reservation.admit` is an authenticated asynchronous owner
operation; dispatch egress has no accepted owner binding. Trait presence or a local
`Bound` constant cannot bridge these facts.

**Release outputs to freeze before a writer claim:**

```text
1. exact owner stage request/result that binds definition/work item/proposed attempt,
   claim/executable/route/resource identities, epoch/fence/deadline and reservation id;
2. daemon-side authenticated client projection for the existing
   admission_reservation.admit result, including canonical and activation receipts;
3. dispatch-egress owner operation that durably retains the original dispatch identity,
   consumes the same active reservation/attempt binding, and preserves unknown outcome;
4. explicit async composition boundary or accepted async port revision—never
   block_on inside a synchronous port or a copied active snapshot.
```

After those outputs exist, assign exact `eliotd` adapters plus the actual Kernel/worker
consumer files in one serialized turn. Do not wait for whole #1678/#1679/#1680 test
closure, but do not fabricate their missing owner state either. #1701 remains
`RECHECK` and holds no broad `eliotd`/Kernel/native-worker reservation.


---

## Review of 2026-10-03 15:22 (root + lanes OR, W4, CB, K1, K2; main cac8ef382)

Reviewed 445 issues: READY 187, WAIT 159, PRESERVE 43, ESCALATE 43, CLOSE-CANDIDATE 13.
126 READY rows were added to `PLAN.tsv` with a card each in `cards/<issue>.md` (the same card format: EDIT / READ ONLY / START / MAKE / DO NOT / CHECK NOW / DEFER / DONE). Waves: wave 1: 90, wave 2: 22, wave 3: 8, wave 4: 2, wave 5: 1, wave 6: 2, wave 7: 1. Inside a wave no two rows share a write path, and the four cards already in flight (#3980, #2691, #2643, #2701) hold their files through wave 1; a row's open dependencies sit in earlier waves. Mechanical checks done by root: card present, write_paths a JSON list and present on main (NEW paths are listed in the merge), dependencies READY or closed. Cards were written by the reviewing lanes and are NOT root-verified line by line: the controller preflight of CONTINUATION.md still applies to every row.

- Not dispatchable yet: `WAIT.tsv` (missing producer output or MISSING-CONTRACT with the release condition).
- Owner decisions: `ESCALATE.tsv` (43 issues).
- Close candidates (every item shown done; root closes with evidence after a check): #259 #481 #862 #976 #990 #1376 #1754 #1779 #1903 #1963 #2613 #2699 #4634.
- Seams: `STITCH-20261003.tsv`; files shared by several READY rows: `OVERLAPS-20261003.tsv`.


---

## Review of 2026-10-03 17:13 (root + lanes OR, W4, CB, K1, K2; main 8fb0a426f)

Reviewed 524 issues: READY 225, WAIT 188, ESCALATE 54, PRESERVE 44, CLOSE-CANDIDATE 13.
72 READY rows were added to `PLAN.tsv` with a card each in `cards/<issue>.md` (the same card format: EDIT / READ ONLY / START / MAKE / DO NOT / CHECK NOW / DEFER / DONE). Waves: wave 1: 25, wave 2: 15, wave 3: 7, wave 4: 9, wave 5: 5, wave 6: 4, wave 7: 3, wave 8: 1, wave 9: 2, wave 10: 1. Inside a wave no two rows share a write path, and the four cards already in flight (#3980, #2691, #2643, #2701) hold their files through wave 1; a row's open dependencies sit in earlier waves. Mechanical checks done by root: card present, write_paths a JSON list and present on main (NEW paths are listed in the merge), dependencies READY or closed. Cards were written by the reviewing lanes and are NOT root-verified line by line: the controller preflight of CONTINUATION.md still applies to every row.

- Not dispatchable yet: `WAIT.tsv` (missing producer output or MISSING-CONTRACT with the release condition).
- Owner decisions: `ESCALATE.tsv` (54 issues).
- Close candidates (every item shown done; root closes with evidence after a check): #259 #481 #862 #976 #990 #1376 #1754 #1779 #1903 #1963 #2613 #2699 #4634.
- Seams: `STITCH-20261003.tsv`; files shared by several READY rows: `OVERLAPS-20261003.tsv`.
