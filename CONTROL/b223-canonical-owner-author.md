# CONTROL — B223 canonical owner implementation (design worker continues)

- Branch: `codex/b223-canonical-owner-20260922` (new worktree
  `C:/Development/Rust/projects/eliot-swarm/b223-canonical-owner-20260922`,
  base `origin/main@8ce704a9`; no push/merge — root alone).
- Code commit: `c06ca79dbaf32d69f6ba1e70541d42355027f5ca` (this note follows
  as second commit; see §9).
- Scope (4 files, all in this lane; nothing else touched):
  - NEW `crates/foundation/eliot-observation-contracts/src/experience_records.rs`
  - EDIT `crates/foundation/eliot-observation-contracts/src/lib.rs` (+3 lines mod/use)
  - NEW `crates/governor/eliot-observation/src/bank_admission.rs`
  - EDIT `crates/governor/eliot-observation/src/lib.rs` (+1 line `pub mod`)
- No new crate. No revived `SystemExperienceOwner`. No store-bridge,
  adapter, kernel, Smart, or normative-doc mutation.

## 1. Documentation routing (before mutation)

All four routes PASS with non-baseline matches; bundles opened and required
items read (normative sections attested: A04, A12.3, A13-family via bundle,
A14.4, I02-17, I05-04/05-06/05-19, I16-23, storage+governor+observation
AGENTS.md; prior-session continuity: I04-08, I05-14, I05-20, I05-24, I12-25
read against the same `origin/main@8ce704a9` bytes):

- foundation: receipt `c685c7…85504` superseded → `7bcabf39…5a60e7c68`,
  routes `[generic-source, memory-context]`, bundle `65b4c9f0…e52717`.
- governor/observation: receipt `d08057e8…9ed92212`,
  routes `[generic-source, memory-context]`, bundle `1bcb276f…63610108`.
- store-api: receipt `a740298b…790ba8521`,
  routes `[generic-source, canonical-storage]`, bundle `81675757…c67583ec`.
- eliot-read: receipt `a7420e0b…03c7d1`,
  routes `[generic-source, memory-context]`, bundle `4995ef8a…970b4f5f`.
- Pair key throughout: `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`.
- `.eliot/` bundles/receipts are worktree-local and uncommitted (never in Git).

## 2. What was built (real code, not inventory)

Foundation (`experience_records.rs`, own version
`EXPERIENCE_RECORD_CONTRACT_VERSION = 0.1.0`; frozen r5 envelopes untouched):

- `ExperienceBankRecord::admit/validate/compute_digest` — Canonical-Memory
  owned self-scope entry: handle, `bank_revision`, non-empty unique
  `source_journal_refs` (≤64), scope, fence, `ProjectionCoverage` reuse,
  `PrivacyRetentionDisclosure` reuse, predecessor ≠ handle, bounded summary,
  measured `byte_length`, owner-computed `digest`. Digest/length are
  computed, never caller-supplied.
- `AgentFeedbackRecord::admit/validate/compute_digest` — origin
  (`ProducerTrace`), mandatory `consent_ref` (empty fails closed),
  closed `FeedbackClass` (`UserCorrection | OutcomeDelta |
  UsefulnessSignal | CoverageComplaint`, mapped to I04-08 kinds and I16-23
  counter-metrics), optional `subject_event_ref`, scope/fence/retention,
  bounded note. Candidate-only by construction (no verdict/score field).
- `revision_cursor(source_id)` on both records → owner-issued
  `SourceRevisionHandle` (`revision` = owner counter, `content_sha256` =
  record digest, `byte_length` = measured preimage). Projection lanes
  receive cursors; they cannot mint them — no forged admitted-source bytes.
- `bank_record_ref / feedback_record_ref` — exact shared
  record→`ExperienceRecordRef` constructors (handle + cursor + scope/fence
  echoes). **B-worker contract:** resolve these refs only; never rebuild
  cursors from parts.
- `resolve_retention_read` + `ExperienceRetentionReadPosture`
  (`Readable | RetentionBlocked{carried refs} | UnknownPolicy{echoed ref}`)
  — root decision 4 implemented: unknown/stale refs yield `UnknownPolicy`
  (explicit gap → caller emits coverage gap, material unavailable); holds
  yield `RetentionBlocked` with caller-supplied refs only. No default, no
  fabricated expiry. Maps to erasure `TargetDisposition::RetentionBlocked`
  / I05-14 `RETENTION_BLOCKED` without importing the security lane.
- `BANK_COMMIT_OPERATION = "ExperienceBankCommit"`,
  `FEEDBACK_COMMIT_OPERATION = "AgentFeedbackCommit"`,
  `COMMIT_TRANSITION_CLASS = "capture_candidate"`, `COMMIT_MAX_EFFECT`
  (candidate-only) — manifest declarations for the #19 lane (§6).

Governor (`bank_admission.rs`, `pub mod bank_admission`):

- `admit_bank_record / admit_feedback_record` — pure admission (Governor
  pre-checks → foundation `admit`). No DB write.
- `supply_bank_refs / supply_feedback_refs` — owner projection supplier;
  envelope scope/fence agreement fails closed before assembly.
- `assemble_bank_projection / assemble_feedback_projection` — **first real
  production callers** of frozen `BankProjection::assemble` /
  `FeedbackProjection::assemble` (previously only Smart test fixtures).
- `revalidate_{bank,feedback,journal}_projection_for_consumer` —
  consumer-edge re-resolution (frozen validate + scope equality + fence
  compatibility) mirroring Smart acceptance **without importing any Smart
  crate** (dependency direction preserved: Smart → Governor only).
- Source constants: `BANK_SOURCE_ID = "governor.experience-bank"`,
  `FEEDBACK_SOURCE_ID = "governor.agent-feedback"`.

## 3. Real production callers (no tests run per brief; callers are code)

- `assemble_bank_projection` → `supply_bank_refs` → `bank_record_ref` →
  `BankProjection::assemble`; same chain for feedback. Journal edge:
  `revalidate_journal_projection_for_consumer` binds durable-audit
  (`GetAuditRange` contour) envelopes at the consumer fence.
- No test, smoke, or self-test executed (brief prohibition). No new tests
  added.

## 4. Check evidence (dedicated targets, actual exit codes)

- `cargo check --locked --offline -p eliot-observation-contracts` → EXIT 0.
- `cargo check --locked --offline -p eliot-observation` → EXIT 0.
- Post-fmt re-check `-p eliot-observation-contracts -p eliot-observation`
  → EXIT 0 (`Finished dev profile`, no warnings shown).
- `cargo fmt -p … -- --check`: my files clean after `rustfmt --edition
  2024` on the two new files. Pre-existing drift left untouched:
  `experience_projection.rs` fmt diffs (rustfmt-version drift, not mine);
  `cargo fmt --all` fails workspace-wide with pre-existing os error 206
  (path too long), unrelated to this change.
- `CARGO_TARGET_DIR=<worktree>/target/b223-owner` (worktree-local,
  gitignored).

## 5. Ownership / isolation

- B worker (`finish-b-223-owner-consumer`, `work/223-owner-consumer`)
  currently holds only untracked `crates/smart/eliot-experience-provider/`
  — zero file overlap with §0 scope. B owns freeze/Smart/provider; shared
  signatures are §2 `bank_record_ref / feedback_record_ref` + frozen
  `assemble()` (unchanged).
- Store `NamedReadOperation` / `NamedMutationOperation` enums NOT touched:
  ~24 files across store/kernel/governor match on them (adapters, gateway,
  bridge) — other writers' lanes. Registration is proposed as narrow
  hunks below for root/#19 serialization.
- Normative prose (I05-14) NOT mutated: outside routed families; exact
  paragraph proposed below for root serialization with the store hunks.

## 6. Exact store/read registration hunks (proposed, #19 lane + root)

Reads follow the live `GetAuditRange` precedent exactly: declared with
`NO_PARAMETERS`, scope via the request envelope, **not** added to
`ACTIVATED_READS` (activation + adapter handlers + edge proof stay #19):

```rust
// operation_parameters.rs :: named_read_operation_name — append:
NamedReadOperation::GetExperienceBankRange => "GetExperienceBankRange",
NamedReadOperation::GetAgentFeedbackRange => "GetAgentFeedbackRange",
// operation_parameters.rs :: named_read_operation_by_name — append:
b"GetExperienceBankRange" => Some(NamedReadOperation::GetExperienceBankRange),
b"GetAgentFeedbackRange" => Some(NamedReadOperation::GetAgentFeedbackRange),
// operation_parameters.rs :: declared_read_parameters — extend NO_PARAMETERS arm:
| NamedReadOperation::GetMailbox
| NamedReadOperation::GetAuditRange
| NamedReadOperation::GetExperienceBankRange
| NamedReadOperation::GetAgentFeedbackRange => &NO_PARAMETERS,
// (enum declaration in store-api lib.rs: add both variants; doc comment:
//  "declared, activation and adapter handlers deferred to #19 edge proof.")
```

Writes (closed mutations; #19 declares transition-class/effect manifests):

```rust
// named_mutation_operation_name / by_name — append:
NamedMutationOperation::CommitExperienceBank => "CommitExperienceBank",
NamedMutationOperation::CommitAgentFeedback => "CommitAgentFeedback",
// parameter schema mirrors AppendAuditEvent discipline: required
// `record_digest` (64 hex), `record_revision`, `scope_digest`,
// `fence_digest`, `idempotency_key`; transition class capture_candidate;
// max effect: candidate-only (COMMIT_MAX_EFFECT, §2).
```

Read facade (`eliot-read`, #1119 lineage): extend `requires_scope` and
`operation_matches_intent` (`HistoricalReconstruction`, `Provenance`) with
both variants, mirroring the `GetAuditRange` arms at `lib.rs:1155,1170,1176`.

## 7. Exact I05-14 paragraph (proposed, root to serialize)

> A `retention_policy_ref` carried by an observation/event envelope is an
> opaque handle minted by the admitting owner. The read edge resolves it
> against the Governor-published retention schedule in force at the
> governing `StateFence`. An unknown or stale ref resolves to the explicit
> `UnknownPolicy` gap posture: the caller emits a coverage gap and treats
> the material as unavailable under the existing `RETENTION_BLOCKED`
> axis; no default retention, expiry, permission, or erasure schedule is
> fabricated. A known ref under schedule hold resolves to
> `RetentionBlocked` carrying only schedule-issued hold, policy, and
> review/expiry refs. The schedule is versioned Governor configuration;
> the bridge executes holds/erasure and invents no policy.

## 8. Remaining post-build acceptance (not this work unit)

1. #19 lane: register §6 hunks, adapter handlers, activation, crash/
   idempotency/unknown-outcome fixtures; durable bank/feedback execution.
2. B worker: Smart `assess_self_quality` over Governor-supplied envelopes;
   provider edge + Product Pulse (#11).
3. Journal leg: durable-audit → `JournalProjection` assembly from
   `GetAuditRange` reads (in-memory journal alone never claimed as owner
   records).
4. Activation of §6 reads + §7 prose serialization by root.

## 9. Commits / hashes

- Code commit SHA: `c06ca79dbaf32d69f6ba1e70541d42355027f5ca` (4 files,
  +1040; branch `codex/b223-canonical-owner-20260922`, base
  `origin/main@8ce704a9`).
- No push (root alone per brief). No secrets in commits/logs.
- Open questions from design now closed except: bank durable execution
  (→ #19 via §6) and feedback producer onboarding (admission source
  contract delivered here; live producers wire in edge wave).
