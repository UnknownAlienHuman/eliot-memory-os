# #963 — lane W3, session: which three items are open, and what actually blocks them

**Product delta: ZERO FILES.** No product file is changed by this delivery, and none should be:
every open item's code already exists on an unmerged branch, and the one thing a writer could
still add would either duplicate that code or mint owner-issued material that no owner has issued.

- Base: `origin/main@747a3a46451ba0c8839716b67c759cd85dbab114`
- Branch: `feat/963-remaining-three` (this worktree, `W3-963r`), created from fresh `origin/main`.
- `git diff --check` clean. No cargo run. No test, no `#[test]`, no `#[allow]` added.
- Findings below were re-verified after `origin/main` moved `fc3ce021` -> `747a3a464`; the four
  intervening commits touch none of the files this audit cites (verified by `git diff --name-only`),
  and every symbol claim below was re-measured on the new head.

---

## 1. WHICH THREE ARE OPEN

`CHECKLIST.json` carries 38 rows. Exactly **three** are non-MET and **PARTIAL** — the three `AUD`
rows of external audit `5847488787`:

| id | text | state |
|---|---|---|
| **AUD1** | obtain the owner-issued `RestoreJournalAdmission` and admitted isolated destination binding from their existing #962/#958 owners | PARTIAL |
| **AUD2** | invoke `backup_restore_with_ors_journal` through the production handler under the original operation identity | PARTIAL |
| **AUD3** | persist/reconcile the actual restore result and return its exact receipt/proof level | PARTIAL |

Every other non-MET row is **TEST-PHASE** (`W4`, `W5`, `W6`, `W11`, `A14`, `A18`), which is a
runtime-proof / owner-decision state barred by the NO-TESTS order of 2026-09-25, not open code work.
So the queue's `rem=3` is exactly AUD1/AUD2/AUD3.

---

## 2. ANCHOR AUDIT — TWO OF THE THREE `impl` ANCHORS DO NOT RESOLVE ON `origin/main`

This is the part that had to come first, because a wrong anchor makes an item unverifiable rather
than open.

| row | anchor as written | resolves on `origin/main`? |
|---|---|---|
| AUD1 `impl` | `bins/eliot-kernel/src/restore_destination_admission.rs::admitted_isolated_destination` | **NO — the file does not exist at all** |
| AUD2 `impl` | `bins/eliot-kernel/src/backup_restore.rs::KernelBackupRestore::restore_with_ors_journal` | YES |
| AUD3 `impl` | `bins/eliot-kernel/src/backup_restore.rs::KernelBackupRestore::bind_plan_operation` | **NO — the symbol does not exist** |

Measurements:

- `git cat-file -e origin/main:bins/eliot-kernel/src/restore_destination_admission.rs` -> `fatal:
  path ... does not exist`. It is a **new file added by the unmerged** AUD1 commit.
- `git grep -w admitted_isolated_destination origin/main` -> **0 hits**. `git log --all -S` returns
  exactly **one** commit, `b93c62b5e` — the unmerged AUD1 head. Never on main.
- `git grep -w bind_plan_operation origin/main` -> **0 hits**. `git log --all -S` returns exactly
  **one** commit, `2fe6fba0c` — the unmerged journal-identity head. Never on main.
- `git grep -w require_restore_receipt_claim origin/main` -> **0 hits**; `git log --all -S` returns
  three commits, all on unmerged branches (`650e83a45`, `6b237db29`, `5862d2b42`).
- `git grep -w rehearsal_band origin/main` -> **0 hits** (three unmerged commits).

**These are not merely stale pointers; they are anchors into unmerged code presented as if they
were main-resident.** AUD1's anchor names a file that exists only on one branch, and AUD3's names a
function that exists only on one branch. Corrected anchors for main-resident code:

| row | main-resident `impl` that actually carries the item | main-resident `caller` |
|---|---|---|
| AUD1 | `bins/eliot-kernel/src/backup_restore.rs::KernelBackupRestore::check_destination_admission` | `bins/eliot-kernel/src/request_dispatch.rs::handle_backup_restore_test` (as written — resolves) |
| AUD3 | `bins/eliot-kernel/src/backup_restore.rs::KernelBackupRestore::admit_restore_journal` | `bins/eliot-kernel/src/request_dispatch.rs::handle_backup_restore_test` (as written — resolves) |

`check_destination_admission` is the right AUD1 anchor because it is where the admission is actually
re-verified on main (`backup_restore.rs:3053`, called at `:3770`), and its `Ok(())`-on-`None` arm is
the exact defect the item names. `admit_restore_journal` is the right AUD3 anchor because it is where
the plan identity the journal is keyed by is established on main (`backup_restore.rs:938`, called
from `restore_with_ors_journal:1040` and from `request_dispatch.rs:3554`).

### Caller reachability, production vs test counted separately

This is the distinction that has produced wrong conclusions, so each `caller` was traced and counted
in `src/` and `tests/` independently:

- `request_dispatch.rs::handle_backup_restore_test` — declared `:3475`, **exactly one** call site
  `:4028`, inside `dispatch_backup_frame`. Production: **1**, tests: **0**. Resolves.
- `request_dispatch.rs::KernelComposition::dispatch_backup_frame` — declared `:3964`, **one** call
  site `frame_dispatch.rs:1311`, inside `dispatch_frame_inner`. Production: **1**, tests: **0**.
  Resolves.
- `frame_dispatch.rs::KernelComposition::dispatch_frame` — declared `:744`; `dispatch_frame_inner`
  declared `:825`. Both resolve. (Checklist rows W4/W5 name these with `caller`/`impl` roles swapped
  relative to their own definitions, but every symbol resolves and both are production-reached.)
- TEST-PHASE rows audited too: `lib.rs::CommandArguments::validate` (`:270`), `main.rs::
  render_backup_outcome`, `backup.rs::apply_cancellation`, `backup.rs::envelope_keys`,
  `request_dispatch.rs::is_backup_operation` — all resolve, all production-reached.

**On the brief's example:** `AgentFabric::restore_snapshot_json` is not a #963 symbol and appears in
no #963 checklist. The real symbol on main is
`crates/agent/eliot-agent-coordinator/src/core.rs:3924::restore_snapshot_json` (1 hit,
`git grep -w`), i.e. an `AgentCoordinator` method, exactly as the brief described. It belongs to
issues 1108/1700, not to this lane.

---

## 3. MERGED vs UNMERGED — EVERY DELIVERED BRANCH IS UNMERGED

`git merge-base --is-ancestor <sha> origin/main`, exit 1 for **all** of them. Nothing in this issue's
delivered set is on main.

| branch / sha | merged? | what it carries |
|---|---|---|
| `fix/963-structural-proof-ceiling-W3k15@1dcee5c82` | **UNMERGED** | AUD6 rung placement via a TOTAL vocabulary; `ArchiveValid` -> `BackupStage::Requested` |
| `fix/963-restore-journal-identity@7ab9ea6f2` (tip; `b59fe28aa` was the earlier lease-guarded force) | **UNMERGED** | AUD3 journal stream keyed by operation identity |
| `fix/963-receipt-claim-cli@eaa5fd1e8` | **UNMERGED** | CLI restore-evidence projection |
| `fix/963-operator-receipt-not-admitted@5ccac85dd` | **UNMERGED** | doc scoping |
| `docs/false-claim-audit@c5f8f617` | **UNMERGED** | corrected false claims across the backup surface |
| `docs/restore-reachability-claim@98995f81` | **UNMERGED** | corrected restore-engine reachability claims |
| `fix/963-destination-admission-evidence-W3k14@08634eab` | **UNMERGED** | AUD1 destination half |
| `fix/963-audit-admission-binding-W3k12@e30d97ffd` | **UNMERGED** | CLI receipt-claim gate |
| `fix/963-restore-observation-floor-W3@ce2523fc3` | **UNMERGED** | observation floor |
| `fix/955-destination-gate-prose@9853a2459` | **UNMERGED** | destination-gate prose (related) |
| `fix/960-restore-port-wiring@53b828ce7` | **UNMERGED** | restore port over the role-bound interface (related) |
| `fix/963-restore-composition-caller-W3k13@981ae169a` | **UNMERGED** | restore composition under the original operation identity |

**All twelve merge CLEAN onto current `origin/main`** (`git merge-tree --write-tree` exit 0 for each).
That is the single most actionable fact in this delivery: nothing here needs a rebase before root
can take it, so every PARTIAL row is a MERGE decision, not a code decision.

---

## 4. THE THREE ITEMS, ITEM BY ITEM — WHAT IS ALREADY SATISFIED, AND THE PRECISE MISSING OWNER

### AUD1 — destination admission binding
- **Conjunct 1 (`RestoreJournalAdmission`): MET ON MAIN.** `request_dispatch.rs:3554` calls
  `composition.backup_restore().admit_restore_journal(...)`, reached from `handle_backup_restore_test`.
- **Conjunct 2 (admitted isolated destination): DELIVERED, NOT MERGED** — `b93c62b5e`
  (`restore_destination_admission.rs`, 722 new lines). It closes the real hole: main's
  `check_destination_admission` (`backup_restore.rs:3053`) returns `Ok(())` when
  `manifest_evidence` is `None`, which is exactly the production front door's value.
- **MISSING OWNER: root's merge of `fix/963-destination-admission-evidence-W3k14`.** That branch's own
  precondition is also unmerged: `eliot_installation::PreparedDestinationAdmission` is produced by
  `2b45a5088` / `6e4f2c3f5` (#958), and `git grep -w PreparedDestinationAdmission origin/main` returns
  **0 hits**. So AUD1 needs **#958 merged first**, then W3k14. I verified `b93c62b5e`'s merge-base with
  #958 is `dd6a7d441` and `git merge-base --is-ancestor 2b45a5088 b93c62b5e` exits **1** — #958 is
  *not* an ancestor of the #963 branch; they are siblings and must be merged in that order.

### AUD2 — invoke the composition under the original operation identity
- **Invocation half: MET ON MAIN.** `request_dispatch.rs:3572` calls
  `composition.backup_restore_with_ors_journal(...)`, reached from `:4028 handle_backup_restore_test`
  <- `frame_dispatch.rs:1311 dispatch_backup_frame`. `rehearsed_reply` has exactly one producer,
  inside the `Ok(outcome)` arm.
- **Identity half: DELIVERED, NOT MERGED** — `2fe6fba0c` (and `7ab9ea6f2`) key the journal by the
  frame's own operation identity via `KernelBackupRestore::bind_plan_operation`.
- **The refutation in the checklist's own `reason` still holds on main and is still true**: on main,
  `journal_key()` is `sha256((plan_id, bundle_sha256))` with
  `plan_id = format!("restore-plan-{}", bundle.manifest.backup_id)`
  (`crates/storage/eliot-backup/src/lib.rs:1379` and `:1409`), and
  `operation_id: format!("restore-operation-{}", plan.plan_id)` (`backup_restore.rs:3579`). Two frames
  with byte-identical bundles and different `idempotency_key`s therefore derive the same durable
  stream, and the second reads back the first's `final_receipt`. I confirmed all three line numbers on
  the current head.
- **MISSING OWNER: root's merge of `fix/963-restore-journal-identity`.** No writer work remains, and
  no writer should re-derive this: `crates/storage/eliot-backup` is **unmodified** by that branch, so
  writing it here would create a second keying scheme.

### AUD3 — persist/reconcile the actual restore result and return its exact receipt/proof level
- **Journal-identity half: DELIVERED, NOT MERGED** — same branch as AUD2 (`2fe6fba0c`).
- **CLI receipt-claim half: DELIVERED, NOT MERGED, and on THREE unmerged branches** —
  `require_restore_receipt_claim` is present on `fix/963-audit-admission-binding-W3k12` (8 refs) and
  `fix/963-restore-observation-floor-W3` (7 refs), and absent from `eaa5fd1e8` and `1dcee5c82`. It is a
  different crate (`crates/surfaces/eliot-cli`) from the four kernel files the kernel-side port
  touches, which is why it was never folded into that port.
- **MISSING OWNER: root's merge of `fix/963-audit-admission-binding-W3k12` (or
  `fix/963-restore-observation-floor-W3`), which is the same merge decision as AUD2's second half.**

---

## 5. THE ONE FINDING THAT CHANGES WHAT ROOT SHOULD DO NEXT

**`fix/963-receipt-claim-cli@eaa5fd1e8` and `fix/963-structural-proof-ceiling-W3k15@1dcee5c82` are
siblings that both rewrite `crates/surfaces/eliot-cli/src/backup.rs::rehearsal_band`, and they
DISAGREE on the `ArchiveValid` arm. `eaa5fd1e8` still carries the exact defect an adversarial
verifier refuted in this issue's own AUD6 work.**

Measured:

```
git merge-base eaa5fd1e8 1dcee5c82  ->  3036b19a688d484f250cbf513aa62fe3586ceb2e
git merge-base --is-ancestor eaa5fd1e8 1dcee5c82  ->  exit 1   (neither contains the other)
```

`eaa5fd1e8:backup.rs` `rehearsal_band`:

```rust
/// ... the ladder stops at `Verified` and the strongest
/// honest reading is a candidate artifact. Placing it higher would claim
/// a restore step this rung never reached.
VerifyClassCeiling::ArchiveValid => (
    BackupStage::Verified,            // <-- the REFUTED placement
    ProofCeiling::CandidateArtifact,
    EffectClass::Candidate,
),
```

`1dcee5c82:backup.rs` `rehearsal_band`, same arm:

```rust
/// This rung places NO lifecycle advance, and that is a correction ...
/// `BackupStage::attesting_roles` says otherwise:
/// `Verified` is attested by `BackupRole::Verifier`, and this operation is
/// a restore rehearsal answered by the restore owner, which does not hold
/// the verifier role. ...
VerifyClassCeiling::ArchiveValid => (
    BackupStage::Requested,           // <-- the CORRECTED placement
    ProofCeiling::CandidateArtifact,
    EffectClass::Candidate,
),
```

This is precisely the hard constraint on this task: **a rung must never place a lifecycle stage whose
`attesting_roles` the answering role does not hold.** `eaa5fd1e8` places `BackupStage::Verified`, whose
`attesting_roles` names `BackupRole::Verifier`, on an operation answered by the RESTORE owner.

**Consequence for root: `eaa5fd1e8` and `1dcee5c82` cannot both be taken as-is.** `eaa5fd1e8` is the
newer *branch* (4 commits, tip `eaa5fd1e8`) but is a **sibling, not a descendant**, so it never
picked up the fix. If `eaa5fd1e8` is merged first and `1dcee5c82` is dropped, the refuted defect
returns; if `1dcee5c82` is merged first, `eaa5fd1e8` will conflict in the same function and its own
`ArchiveValid` arm must be dropped, not merged. **Recommend: take `1dcee5c82`'s `rehearsal_band` as
the authority and cherry-pick only the receipt-evidence work off `eaa5fd1e8`.** I did not attempt
that port: it is a cross-branch reconciliation inside one function with two contested bodies, it is
root's merge decision, and the manager builds.

I re-verified on the new head `747a3a464` that this disagreement is still live: `rehearsal_band` has
**0** hits on main, so neither version is on main and nothing has silently superseded the other.

---

## 6. AUDIT OF THE OTHER NON-MET ROWS (TEST-PHASE) — ALL ANCHORS RESOLVE, ALL PRODUCTION-REACHED

No anchor defect found in any of them, which is worth stating because this lane's anchors have been
wrong repeatedly and it is the TEST-PHASE half that is clean:

| row | `impl` resolves | `caller` resolves | production / test callers of the caller |
|---|---|---|---|
| W4 | `backup.rs::parse_backup_create` YES | `lib.rs::CommandArguments::validate` YES (`:270`) | production only |
| W5 | `frame_dispatch.rs::KernelComposition::dispatch_frame_inner` YES (`:825`) | `frame_dispatch.rs::KernelComposition::dispatch_frame` YES (`:744`) | production only |
| W6 | `backup.rs::BackupOperationOutcome` YES | `main.rs::render_backup_outcome` YES | production only |
| W11 | `backup.rs::apply_cancellation` YES | `main.rs::render_backup_outcome` YES | production only |
| A14 | `backup.rs::envelope_keys` YES | `backup.rs::backup_create` YES | production + tests, counted separately |
| A18 | `request_dispatch.rs::is_backup_operation` YES | `request_dispatch.rs::dispatch_backup_frame` YES | production only |

Their status is correctly TEST-PHASE: the declared test artifacts
(`crates/surfaces/eliot-cli/tests/backup.rs`, `bins/eliot-kernel/tests/backup_dispatch.rs`,
`crates/surfaces/eliot-cli/tests/data/backup/`) do not exist and the NO-TESTS order bars creating
them. That is a runtime-proof state, not missing product code, and it is not this lane's to close.

---

## 7. THE TWO KNOWN BLOCKERS — CONFIRMED, NOT ATTEMPTED

**The four absent rescue files are UNWIREABLE, not superseded.** Confirmed and not re-attempted:
`backup_coordination.rs`, `backup_restore_admission.rs`, `backup_restore_driver.rs`,
`restore_coordination_builder.rs` from rescue head `59255f3b2f72`, and
`bins/eliot-kernel/src/backup_owner_clients.rs` exists on main as a **different file** (#962
Host/Watchdog clients). Porting would delete a merged issue's implementation. Root decision required;
this delivery takes no position beyond confirming the collision still holds on `747a3a464`.

**The #958 destination-admission channel is BLOCKED and is TWO decisions.** Confirmed by measurement,
not by reading the brief:

- `BackupCallerAuth::authenticate` (`bins/eliot-host/src/backup_preparation.rs:5137`) is a standing
  always-refuse returning `Err(PreparationError::InvalidRequest { field: "caller_auth", ... })`. Its own
  doc says the implementation that fills it "must not change this method's signature or callers".
- `HostComposition::backup_dispatch_prepare` (`bins/eliot-host/src/lib.rs:6842`) still refuses, and
  `git grep -n "owner_manifest_binding" origin/main` returns **exactly one hit** — the definition at
  `backup_preparation.rs:4841`, **zero callers**. So no legitimate `owner_manifest_binding` call site
  can exist yet, confirming the caller-auth decision precedes the evidence channel.
- Nothing was minted, synthesized or defaulted. No `DestinationManifestEvidence` and no
  `manifest_evidence` was constructed, defaulted or commented into existence anywhere in this
  delivery. This delivery contains **zero** product lines.

---

## 8. WHAT A WRITER COULD STILL ADD, AND WHY I DID NOT

The only writer-shaped work remaining would be a CLI-side false-claim correction on main. Main's
`crates/surfaces/eliot-cli/src/backup.rs::apply_accepted_exit` (`backup.rs:2434`) writes a hardcoded
obligation string asserting the owner's answer carries "no capture receipt, no restore-step result, no
reconciliation and no cutover admission", while main's `rehearsed_reply`
(`request_dispatch.rs`) answers `ok` carrying the owner's whole `RestoreReceipt` in a `receipt` field.
**That claim is false on main.** I verified it is present on main and on `docs/false-claim-audit`, and
**absent** on all three CLI fix branches.

I did not fix it here, for two measured reasons:

1. **It is already fixed three times over on unmerged branches** (`fix/963-receipt-claim-cli`,
   `fix/963-structural-proof-ceiling-W3k15`, `fix/963-restore-observation-floor-W3`,
   `fix/963-audit-admission-binding-W3k12`). Writing it again would be the duplication the brief
   forbids, and would create a fourth variant to reconcile against the contested `rehearsal_band`.
2. The correct fix is not a comment edit: it is `require_restore_receipt_claim`, which decodes the
   owner's receipt and enforces five fail-closed relations against it. That is precisely AUD3's
   outstanding CLI half, and it belongs with the AUD3 merge decision.

---

## 9. WHAT I COULD NOT DECIDE

1. **Which of `eaa5fd1e8` / `1dcee5c82` root takes.** Both rewrite `rehearsal_band`; they disagree on
   `ArchiveValid`; neither is on main. Section 5 states the recommendation and the reason, but the
   merge order and the cherry-pick are root's.
2. **Whether `fix/963-audit-admission-binding-W3k12` or `fix/963-restore-observation-floor-W3` is the
   AUD3 CLI half to keep.** They are siblings with overlapping content (8 vs 7 references to
   `require_restore_receipt_claim`), and I did not diff them function-by-function.
3. **The `backup_owner_clients.rs` ruling** (RESCUE-DISPOSITION-W3.md's "ROOT DECISION NEEDED"). Not
   mine; I only confirmed the collision is unchanged on the current head.
4. **Whether the AUD7 `UserMode` profile defect** recorded in that same file is in any lane. Reported
   there, not here, and not this issue.