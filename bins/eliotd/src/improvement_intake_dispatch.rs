//! Production improvement-intake dispatch for `eliotd` (issue #1867 W1,
//! I12.24).
//!
//! This is the production caller for the advisory candidate/brief intake. The
//! daemon run loop reaches it through [`crate::daemon_runtime`]'s retained
//! `ImprovementIntakeFlight`, starting from a live Governor maintenance
//! observation. This intake remains distinct from the full
//! `ImprovementRouteRequest` pipeline, which has no production request source.
//!
//! # The evidence is a real observation this daemon already made
//!
//! The single evidence source is the daemon's OWN live
//! [`eliot_maintenance::AutomationTriggerDecision`] produced by
//! [`crate::DaemonComposition::evaluate_maintenance_trigger`]
//! (`maintenance_trigger_evaluator.rs::DaemonComposition::evaluate_maintenance_trigger`),
//! which the run loop already evaluates per cadence. That decision carries the
//! Governor owner's real `trigger_id`, `family`, `scope_ref`, `reason`,
//! `decision` and `admits_job`, and is bound to the observed evidence
//! references the trigger site passed in. Nothing here invents an observation:
//! every ref below is derived from that decision's own fields.
//!
//! The evidence source is DERIVED from that decision's own closed fields by
//! [`maintenance_evidence_source`], not asserted. It previously claimed
//! [`eliot_improvement::EvidenceSource::Watchdog`] for every decision, which
//! mislabelled the recorded lineage: a conformance-audit family and a
//! security/dependency-scan family both recorded themselves as Watchdog
//! signals, so a later reader could not tell what kind of occurrence the
//! evidence was. The derivation — and why no `Watchdog` label survives it —
//! are documented on that function.
//!
//! Since #1867 W2/A1 that derivation is LIVE for the conformance source rather
//! than only declared: the daemon names the observed family at each trigger
//! site instead of hardcoding one (`daemon_runtime::maintenance_observation`
//! takes the family as a parameter), so a real declared-capability conformance
//! gap observed at the startup or improvement-intake sites reaches
//! [`conformance_diagnosis_evidence`] below and enters the funnel through the
//! Self-Quality conformance-diagnosis contract.
//!
//! # What is still NOT connected, measured rather than asserted
//!
//! W2 also names attempts/evaluators, campaign closure, security incidents,
//! accepted implementation deviations, complaints, Watchdog, Dreamer and
//! Concilium suggestions. On this tree only the first and the conformance
//! diagnosis are reachable, and the reasons are recorded per-arm on
//! [`maintenance_evidence_source`]: a family census shows the only families any
//! production trigger site can name are [`crate::SELF_OBSERVED_FAMILY`] and
//! `MaintenanceFamily::DonorConformance`, so every other source needs a
//! producer that does not exist yet rather than a match arm that is missing
//! here. The security-incident arm is annotated at the arm itself with the
//! receipt and trigger site that would make it live; Watchdog, Dreamer and
//! Concilium have no arm and are annotated as such. None is filled from a
//! substitute value.
//!
//! # A1's SECOND disjunct has no honest producer, and the arm is NOT written
//!
//! A1 reads "A real conformance diagnosis **or real repeated verifier
//! failure** produces a durable deduplicated improvement candidate and a brief
//! containing the stated evidence, risk, benefit, owner, cost, reversible next
//! step, and unknowns." The FIRST disjunct is live through
//! [`conformance_diagnosis_evidence`]. The SECOND has no arm here, deliberately,
//! and this section records why so the next owner does not re-derive it and
//! re-introduce a dead one.
//!
//! ## The signal exists at the closure seam and is DISCARDED before it persists
//!
//! The Governor's learning-closure owner derives the repeated-failure signal
//! correctly. `observed_activities` emits
//! `LifecycleActivity::RepeatedFailureSignature` exactly when the durable
//! terminal job row is `TestdJobState::Failed` AND its physical attempt count
//! exceeds one (`crates/governor/eliot-governor/src/learning_closure.rs:582-588`),
//! and `derive_boundaries` refuses an ordinary read and an empty activity set
//! first (`:483-491`). So the signal is real.
//!
//! It is then collapsed, and the collapse is what makes it unreachable here:
//!
//! 1. `close_attempt` persists `boundaries[0]`
//!    (`learning_closure.rs:492-495`) — "The first derived boundary in the closed
//!    nine-value order names the record". `derive_boundaries` returns
//!    `ConsequentialBoundary::ALL` order (`crates/smart/eliot-learning-delta/src/
//!    boundary.rs:233-236`), where `VerifierOutcome` is index 1 and
//!    `RepeatedFailureSignature` is index 3 (`boundary.rs:49-58`).
//! 2. `verifier_finished` is ALWAYS true on the production path.
//!    `observed_activities` is called with
//!    `fact.verification_run.finished_at.is_some()`
//!    (`learning_closure.rs:854-859`), the only production construction of a
//!    canonical `VerificationRun` is `evaluate_testd_verification_current` →
//!    `eliot_verifier::evaluate_current`, which hardcodes `finished_at: Some(…)`
//!    (`crates/instrument/eliot-verifier/src/lib.rs:838`), and
//!    `read_verifier_execution_fact` returns `Err` when the fact is ABSENT
//!    (`crates/governor/eliot-governor/src/composition.rs:3212-3221`), so
//!    `close_attempt_learning` errors out rather than committing with a
//!    `verifier_finished` of `false`.
//! 3. `observed_activities` never pushes `MaterialImplementationAttempt` (index
//!    0), so nothing sorts before the always-present `VerifierOutcome`.
//!
//! Therefore `boundaries[0] == VerifierOutcome` for EVERY committed record, and
//! `StoredLearningDelta::consequential_boundary` is always `"verifier_outcome"`.
//! A TestD job with `attempts = 3`, `state = Failed` and a real nextest receipt
//! still commits `"verifier_outcome"`. An arm comparing that field against
//! `"repeated_failure_signature"` can never fire on any production input.
//!
//! ## The record also cannot express FAILURE, which is the second half of the gap
//!
//! Even a persisted `RepeatedFailureSignature` would not be enough for a
//! "repeated VERIFIER FAILURE" claim, because the record does not carry the
//! verifier's verdict. The run's `outcome` is consumed by
//! `close_disposition_for` (`learning_closure.rs:607-633`) and only its
//! three-value `AttemptCloseDisposition` reaches `StoredLearningDelta::disposition`
//! via `as_stored()`; on the production path `derived` is hardcoded `false`
//! (`learning_closure.rs:866`), so a conclusive run closes as `INVALID_EVIDENCE`
//! and a non-conclusive one as `INCONCLUSIVE`. Neither distinguishes
//! `VerificationOutcome::Pass` from `VerificationOutcome::Fail`, which is the same
//! fact A1's second disjunct names. The record's `evidence_refs` carry the
//! verifier run id and raw artifacts (`learning_closure.rs:663-676`) but no
//! verdict, and `strategy_fingerprint` is computed from plan and invocation
//! binding alone (`:641-659`), so neither can be read as one.
//!
//! ## What the fix needs, and why it is not in this file
//!
//! Two changes in `crates/governor/eliot-governor/src/learning_closure.rs`,
//! neither of which this module may make:
//!
//! 1. persist the derived boundary SET rather than `boundaries[0]`, so
//!    `RepeatedFailureSignature` survives onto `StoredLearningDelta`; and
//! 2. carry the verifier's `Pass`/`Fail` verdict onto the record, so a consumer
//!    can tell a repeated failure from a repeated success.
//!
//! `StoredLearningDelta` has one `consequential_boundary` field
//! (`crates/smart/eliot-learning-delta/src/stored.rs:214`), so (1) is a contract
//! change in that crate as well, not a field this dispatch layer can add.
//!
//! ## What is deliberately NOT done here
//!
//! No arm, no match pattern, and no `EvidenceSource::Attempt` relabelling stands
//! in for the missing signal. The three available substitutes were each measured
//! and each rejected: comparing the collapsed boundary is dead on arrival (above);
//! deriving failure from `disposition` cannot separate `Pass` from `Fail`; and
//! reading a verdict out of `evidence_refs` would name a verifier the record
//! never names, which is the misattribution this file exists to remove.
//!
//! The correct label once (1) and (2) exist is [`EvidenceSource::EvaluatorVerdict`],
//! through the existing `eliot_improvement::sourced_evidence_from_repeated_verifier_failure`
//! (`crates/meta/eliot-improvement/src/evidence_sources.rs:118-142`), which
//! already exists, is the closed set's own spelling for a verifier verdict, and
//! currently has no caller. It is not wired speculatively against a record that
//! cannot yet carry what it needs.
//!
//! The decision now also carries its origin —
//! [`eliot_maintenance::AutomationTriggerDecision::trigger`] is copied verbatim
//! from the evaluated trigger — so the three suggestion sources are no longer
//! blocked by a missing field. They remain unselected because the ONE
//! observation this intake is handed is built from
//! `MaintenanceTriggerOrigin::IdleTransition`, which maps to
//! `MaintenanceTrigger::Policy` and can never read `WatchdogProblem`,
//! `Dreamer` or `Concilium`. The per-source remaining step, which now differs
//! sharply between them, is recorded on [`maintenance_evidence_source`].
//!
//! # The durable port is the existing Governor/Kernel named mutation
//!
//! The owner-actionable artifact (candidate revision + brief + owner decision)
//! is committed through the EXISTING
//! [`crate::DaemonComposition::commit_learning_record`] seam, which is the one
//! Governor-owned caller of
//! [`eliot_governor::commit_learning_record`] and the only path that reaches
//! the closed `RecordLearningRecord` mutation
//! ([`eliot_store_api::LearningRecordKind::Candidate`]). No second write
//! path, store client or durability scheme is introduced here, and no
//! in-memory `BoundedBacklog` state is treated as durable: the backlog is a
//! per-pass REGISTRY rebuilt from the committed records on every pass (see
//! below), so the committed records are the only durable artifact.
//!
//! # What deduplication is and is NOT guaranteed here
//!
//! The candidate identity IS content-derived
//! ([`eliot_improvement::ImprovementCandidate::new`]), so a repeat of the same
//! observation produces the same `candidate_id` and therefore the same
//! `improvement-candidate:<id>` HANDLE. The IN-MEMORY registry converges on one
//! entry per candidate for that reason, and
//! [`crate::improvement_dedup_read::restored_registry`] re-establishes it on
//! every pass from the committed rows.
//!
//! It did NOT previously converge to one STORE row, and this claim used to say
//! it did. It does not, and the reason is the brief: the committed document
//! carries `artifact.brief` verbatim ([`commit_improvement_artifact`]), and
//! [`eliot_improvement::brief_at_safe_boundary`] mints `brief_id` as a fresh
//! `Uuid::now_v7()` and stamps `created_at` with `OffsetDateTime::now_utc()` on
//! every call (`crates/meta/eliot-improvement/src/brief.rs:326,337`). The store
//! keys a learning row by `(record_kind, handle, record_digest)`
//! (`surreal_learning.rs::learning_row_key`), and the presented
//! `record_digest` is the digest of those exact document bytes
//! ([`commit_improvement_artifact`]). A fresh `brief_id` is therefore a fresh
//! digest, a fresh row id, and a `CREATE` rather than the compare-and-set the
//! adapter performs on an existing one
//! (`surreal_learning.rs:189`). One cadence tick over one unchanged occurrence
//! appends one new row under one unchanged handle. The improvement owner's own
//! crate records this as the expected behaviour rather than a defect — "a
//! re-commit under a new digest legitimately produces a second row for the same
//! candidate" (`candidate_bounds.rs:640-646`) — and the read side tolerates it
//! by keeping the highest `candidate.revision` per `candidate_id`
//! (`restored_registry`, `improvement_dedup_read.rs:652-663`).
//!
//! Stated plainly because the previous claim was the opposite and would have
//! been believed: the durable rows accumulate per tick; the convergence is
//! real only in the registry rebuilt from them. This is also the precondition
//! publication cannot yet meet — see "The brief reaches no owner, and the
//! contour that would carry it is absent" below.
//!
//! The registry is REBUILT from this daemon's own committed rows, through the
//! existing authenticated read route
//! ([`crate::improvement_dedup_read::read_candidate_scope`] →
//! [`crate::improvement_dedup_read::restored_registry`]), so the
//! evidence-lineage merge branch of `admit_reporting_pressure` is reachable
//! against entries an EARLIER pass or an earlier process committed, and not
//! only within one pass. The merge RESULT is made durable in its own right by
//! [`commit_lineage_merge_receipt`], which the next pass reads back as the
//! surviving entry rather than rebuilding from the pre-merge candidate row.
//!
//! What is deliberately NOT claimed:
//! `DurableCandidateRecord::into_entry`
//! (`crates/meta/eliot-improvement/src/candidate_bounds.rs`) rebuilds
//! `TrackedCandidate::merged_from` empty and takes the restored
//! entry's `value` from the bound's `min_value` floor rather than from a
//! per-candidate assessment, because the committed candidate document records
//! neither. So the absorbed-id list a merge accumulated, and a per-candidate
//! value a `LowValue` archival would need, are not restored across a restart;
//! the unioned evidence lineage IS, because it lives in the candidate's own
//! `evidence_refs`. The statement is limited to what the code does.
//!
//! # Promotion stays refused, by construction, not by omission
//!
//! The intake's promotion-grade budget gate
//! ([`eliot_improvement::require_matched_budget_for_promotion`]) is NOT
//! satisfied here, because this daemon runs no experiment and therefore
//! holds no real matched-budget live shadow/canary evidence. This module
//! consequently uses the advisory composition of the same
//! `eliot-improvement` owners — [`eliot_improvement::candidate_from_evidence`],
//! [`eliot_improvement::brief_at_safe_boundary`] and
//! [`crate::improvement_intake::record_brief_decision`] — rather than
//! calling [`eliot_improvement::intake_from_evidence`], whose unconditional
//! `require_matched_budget_for_promotion` call would demand fabricated
//! canary refs. This is the honest advisory state I12.24:74-80 describes:
//! "advisory … default; changes nothing until owner acts", and a
//! replay-only candidate that cannot promote. `BLOCKED-BY` promoting this
//! path through `intake_from_evidence` needs an owner that publishes real
//! matched-budget live shadow/canary evidence
//! ([`eliot_improvement::BudgetProof::live_shadow_refs`] /
//! [`::live_canary_refs`]); none exists in this workspace. W1's reachability
//! requirement — a real production caller consuming real evidence and
//! emitting a durably committed owner-actionable artifact — is met without
//! weakening that gate, which stays closed.

//! # The bounded backlog is a GOVERNED admission, not a daemon literal
//!
//! Before this module took the governed path, the only production
//! [`CandidateBoundPolicy`] was a hardcoded literal in this file
//! (`max_active: 8, min_value: 0.0, governor_authority_ref: "eliotd.maintenance",
//! policy_revision: 1`) and it was enforced through the registry-only
//! [`BoundedBacklog::admit`], which performs no authority check at all. The
//! named "Governor authority" was a `const IMPROVEMENT_OWNER` in this file, so
//! the bound was never compared with a live issuance — a bound that no owner
//! decided and that nothing could invalidate.
//!
//! It is now read from the maintenance (`G-19`) decision record through the
//! EXISTING maintenance admission path and enforced against a real
//! owner-issued permit:
//!
//! ```text
//! GovernorOwners::maintenance::improvement_admission_policy   (eliot-maintenance, G-19)
//!   → eliot_maintenance::resolve_candidate_surface_bound       (owner record vs enforced bound)
//!   → issue_learning_admission                                 (eliot-governor, live owner checks)
//!   → CandidateBoundPolicy::validate_governed                  (authority == permit.authority_ref)
//!   → BoundedBacklog::admit_reporting_pressure                 (W1 + W3)
//! ```
//!
//! Three properties of that chain are the guarantee, and each is a CONTENT
//! comparison against the owner's own record rather than a shape check:
//!
//! 1. The bound NUMBERS come from the G-19 policy record. This module
//!    spells none of them: [`maintenance_bound`] reads
//!    `ImprovementAdmissionPolicy::candidate_bounds`, and a surface with no
//!    entry is refused ([`ImprovementBoundError::NoBoundForSurface`]) instead
//!    of defaulted.
//! 2. The bound the daemon will ENFORCE is compared back against the owner's
//!    recorded bound by [`eliot_maintenance::resolve_candidate_surface_bound`]
//!    — `max_active` and `min_value` field by field, with `min_value`
//!    compared by bit pattern so a re-spelled float cannot slip through. A
//!    disagreement is refused with the disagreeing field named.
//! 3. The bound's OWNING AUTHORITY is compared against a live
//!    owner-issued [`LearningAdmissionPermit`]'s `authority_ref` by
//!    [`CandidateBoundPolicy::validate_governed`], which runs inside
//!    [`BoundedBacklog::admit_reporting_pressure`]. A constant that merely
//!    *names* an authority cannot pass that check; only a permit the Governor
//!    minted under the live epoch/generation can.
//!
//! No new scheduler, root record, table, task graph, evaluator or promotion
//! authority is introduced (I12.24:314): the bound is a field group on the
//! existing G-19 admission policy record, read through the existing
//! maintenance owner.
//!
//! # The recorded disposition is the DAEMON's own, and no owner ingress exists
//!
//! I12.24:65 places "decision owner selects reject / investigate / work item /
//! experiment" AFTER the brief reaches one, and this module records a
//! disposition on every pass. What it records is the DAEMON's own
//! non-authoritative triage of its own observation, under the daemon's own
//! harness-established identity ([`SERVICE_NAME`]) — never an owner's selection,
//! because no owner's selection can reach this process. Measured on this tree
//! rather than assumed:
//!
//! | candidate ingress surface | measured result |
//! |---|---|
//! | listener / socket / stdin in `bins/eliotd` | ZERO. `TcpListener`, `UnixListener`, `UnixStream`, `read_line`, `accept(` and `stdin()` match nothing under `bins/eliotd` |
//! | the daemon's only transport | OUTBOUND. `daemon_kernel_client.rs:1885 connect_authenticated_kernel_front_door` is the authenticated named-pipe CLIENT. `eliotd` dials the Kernel; nothing dials `eliotd` |
//! | the daemon's pull queues | REAL, but wrong-typed. `local_read_claim` (`frame_dispatch.rs:1451`), `task_controller_claim` (`:1498`), `campaign_packet_claim` (`:1500`) and `finish_claim` (`:1506`) are genuine Kernel→daemon routes, and each carries one fixed attempt type. None carries a brief decision, and adding one is a Kernel operation plus a store record kind |
//! | `eliot_user_automation` / `UserAutomationOperation` | never reaches `eliotd`: `git grep -c user_automation -- bins/eliotd` is 0. Served inside the Kernel, which dispatches a wake to the Host |
//! | the `DecideImprovementBrief` operation itself | the vocabulary entry is closed, authenticated and live — `daemon_request_dispatch.rs:4214` binds `intent.principal_ref` from `authenticated_user_automation_principal(session)` — and it is REFUSED at both ends: the automation Store answers `StoreError::UnknownOperation` (`user_automation_store.rs:954`) and the operator route answers `TransportError::SessionFenced` (`daemon_request_dispatch.rs:4208-4213`) |
//! | a durable decision an owner could write for the daemon to read | none. The daemon's read client admits a closed set of named reads (`kernel_context_read_client.rs:190-249`) and `GetUserAutomationState` is not among them; and the only row the daemon re-reads is its OWN `Candidate` artifact, written by this same pass under the same record key, so an owner cannot pre-empt it |
//!
//! Two consequences follow, and both are stated rather than worked around:
//!
//! 1. **The disposition recorded here is the daemon's own.** `Reject` and
//!    `Investigate` are both non-mutating, so recording one authorizes nothing
//!    (I12.24:82: "advisory … default; changes nothing until owner acts"), and
//!    the artifact is truthful about WHO chose it. What is not true of it is that
//!    an owner chose it.
//! 2. **`OwnerDecisionKind::Reject` remains unreachable from a real,
//!    non-constant source**, and so do `WorkItem` and `Experiment`. That is not
//!    repaired here, because every available substitute is a fabrication: the
//!    maintenance owner's own `AutomationDecision` (`eliot-maintenance/src/lib.rs:184`)
//!    decides whether to run a maintenance JOB and never saw this brief; the
//!    observed closure's `actor_id` is the principal that EXECUTED the
//!    consequential attempt and selected nothing; and the `G-19` admission
//!    authority issues learning-admission PERMITS, which is a different act from
//!    selecting a disposition over a brief. Mapping any of them onto this
//!    vocabulary would record an owner's decision that owner never made — the
//!    misattribution [`maintenance_evidence_source`] exists to remove, reached
//!    from the other direction.
//!
//! # The exact missing route, named
//!
//! Reaching I12.24:65 needs three artifacts in three other owners' files:
//!
//! 1. a Kernel dispatch arm that COMMITS the authenticated decision as a durable
//!    row, beside `dispatch_user_automation_operator_transition`
//!    (`bins/eliot-kernel/src/daemon_request_dispatch.rs:4242`), replacing the
//!    `SessionFenced` refusal at `:4208-4213` for this one operation. It is
//!    refused today because the automation Store owns no ordering scope a brief
//!    can join, which is correct; the commit belongs to the improvement owner's
//!    own canonical record, not to the automation Store.
//! 2. a Kernel queue the daemon can claim, beside the existing pull legs in
//!    `DaemonKernelClient` (`daemon_kernel_client.rs:2130` is the first,
//!    `claim_local_read_pair_async`; `claim_finish_pair_async` at `:2395` is the
//!    last), carrying the committed decision's `brief_id`, its closed decision
//!    string, and the principal the Session authenticated.
//! 3. the daemon-side poll, in `daemon_runtime::run_improvement_intake`
//!    (`bins/eliotd/src/daemon_runtime.rs:4791` is the guarded phase it would
//!    have to precede) — outside this change's two files — which maps the closed
//!    decision string onto [`OwnerDecisionKind`] FAILING CLOSED on an unmapped
//!    value, and calls this module with the claimed principal as the owner.
//!
//! Until (1) and (2) exist, no code in this repository can make an owner's
//! selection reach `record_owner_decision`, and this module will not pretend
//! otherwise.
//!
//! # The brief reaches no owner, and the contour that would carry it is absent
//!
//! The three artifacts above are the DECISION half of I12.24:65. The BRIEF half
//! — the arrow that has to arrive first, "concise Improvement Brief to active
//! Main Agent or Human at a safe boundary", whose load-bearing sentence is
//! I12.24:74: "The named decision owner does not search raw metrics" — is
//! missing in a way that is measured here rather than assumed, because it is not
//! the same gap and it is upstream of the three above.
//!
//! ## What the brief is today: a field of this daemon's own row
//!
//! [`commit_improvement_artifact`] already writes the brief verbatim into the
//! `Candidate` learning record's canonical JSON document, as
//! `{"candidate", "brief", "owner_decision", "enforced_bound",
//! "governed_admission_digest"}`. So all eight I12.24:74 fields plus
//! `brief_id` ARE durable, byte-for-byte, through the one governed seam. What
//! is absent is any route by which a decision OWNER reaches that row. Measured
//! on this tree:
//!
//! | candidate owner-facing surface | measured result |
//! |---|---|
//! | `LearningRecordKind` vocabulary | CLOSED at six variants — `Delta`, `Overlay`, `Closure`, `ActivationReceipt`, `Candidate`, `ViewRef` (`learning_store.rs:100-113`). There is NO `Brief` kind, so the brief cannot become a first-class durable record without a store-contract change this file does not own |
//! | who reads `GetLearningRecordRange` for `Candidate` | the DAEMON ONLY. Three production call sites exist and every one filters a different kind: `improvement_dedup_read.rs:379` asks for `Candidate` and re-proves the daemon's own committed row (its `:849` check is a self-consistency proof of that row, not an owner reading it); `skill_evidence_read.rs:171` and `negative_memory_action_gate.rs:419` both ask for `ActivationReceipt`. `git grep -l GetLearningRecordRange -- "*.cs" -- bins/eliot/src` returns nothing: no Operator surface and no CLI reads any learning record |
//! | ControlBoard | the `items` vector is a LITERAL `Vec::new()` (`controlboard_adapters.rs:987`), and the comment above it states why: the Governor owners carry no ControlBoard visibility/privacy/epistemic facts and inventing rows "would be a privacy expansion" (`controlboard_projection.rs:23-29`). A brief has no `BoardItem` to land in, and `BoardItem` itself carries no field for benefit, risk, cost, unknowns, or `brief_id` (`eliot-controlboard/src/lib.rs:467-478`) |
//! | the ControlBoard read edge | not reachable either. `controlboard.read` is admitted by no host request: `daemon_runtime.rs:4144` records that "nothing in this repository presents a host request naming this capability" |
//! | the canonical notification record | REAL, durable, and Human-read — it is the one owner-facing surface that genuinely exists, and it is the honest candidate. But its closed shape ([`eliot_kernel_core::Notification`], `notification_state.rs:317-337`) has `subject`, `summary`, `evidence_handles`, `affected_scope`, `owner`, `required_action` and no slot for likely benefit, risk, cost, next reversible step, unknowns, or `brief_id`. The brief would have to be re-spelled into `summary` prose, which is the "re-spelled into a log string" failure I12.24:74 exists to prevent, and the record's own `dedup_key` is derived from the maintenance decision (`automation_failure_key`), not from the brief — so two briefs over one trigger would collide onto one record or churn `IdentityConflict` |
//! | the notification emitter's reachability | it is a free function in another file, `emit_blocked_automation_notification` (`notification_state_emit.rs:582`), reached from the health-heartbeat arm `note_blocked_automation_notification` (`daemon_runtime.rs:2641`). It is not reachable from this module and its signature takes an `AutomationTriggerDecision`, not a brief |
//! | Host / operator console | `host_console_protocol.rs` serves exactly `Status` and `Stop`; `apps/Eliot.Operator` reads `controlboard.read` and the runtime-status contract only. Neither names a learning record, a brief, or `DecideImprovementBrief` |
//!
//! ## The two artifacts a publication would need, in two other owners
//!
//! 1. a durable WRITE the brief's own fields can occupy without re-spelling.
//!    The existing `Candidate` document already carries them, so this half is
//!    nearly free — but the record's KEY is the candidate id
//!    (`improvement-candidate:<candidate_id>`), so an owner addressing a BRIEF
//!    has no handle to name. Naming one needs either a `Brief` variant in the
//!    closed [`eliot_store_api::LearningRecordKind`] set (`learning_store.rs`,
//!    `eliot-store-api`) or a stable brief-keyed handle, and the second is
//!    blocked by the digest churn measured above: with a fresh `brief_id` per
//!    pass there is no stable brief identity to key on.
//! 2. an owner-facing READ that projects that record to a Human or an active
//!    Main Agent. The one contour that could carry it without a new owner is
//!    the ControlBoard `items` projection, and that is exactly the projection
//!    the Governor deliberately refuses to populate (the privacy-expansion note
//!    cited above). Filling it is the ControlBoard/privacy owner's decision,
//!    not this dispatch layer's.
//!
//! Neither is in this file, and neither can be honestly faked here. A
//! `tracing` span field carrying `brief_id` (`daemon_runtime.rs:5340`) is a
//! diagnostic, not a publication: nothing outside this process reads it, and no
//! owner can act on it. So this module states the gap and stops.
//!
//! What I12.24:82 already guarantees keeps this honest in the meantime: the
//! recorded disposition is `Investigate`, one of the kinds `is_non_mutating`
//! admits, so nothing here changes a surface while the publication contour is
//! absent.
//!
//! # Archive receipts are durable dispositions, not diagnostics (W3)
//!
//! The governed admission returns the [`ArchivedCandidate`] receipts the
//! bound-relief path produced. Each is committed through the SAME
//! [`DaemonComposition::commit_learning_record`] seam and the SAME closed
//! [`eliot_store_api::LearningRecordKind`] this module already uses for the
//! candidate itself, so an archived candidate's summary, cause and recorded
//! [`ImprovementLifecycle`] disposition become durable evidence. No new record
//! kind, table, or write path is added: `Candidate` is the closed kind that
//! covers "recording never performs promotion", and an archive receipt is a
//! record about a candidate.
//!
//! # Cross-task carryover is issued and verified here (W5)
//!
//! [`CrossTaskCarryover::verify`] and the Governor's
//! [`issue_cross_task_admission`](eliot_governor::LearningAdmissionPermit::issue_cross_task_admission)
//! had no non-test caller, so no production code could mint or present a
//! cross-task admission. [`issue_cross_task_carryover`] and
//! [`verify_cross_task_carryover`] are that production path: the first issues
//! the SECOND, distinct admission for a foreign target task through the same
//! live owner checks, the second re-verifies both permits against live owner
//! state and constructs the owner-verified [`CrossTaskCarryover`] a consumer
//! binds to. It uses the Governor-owned record — never the weaker
//! string-typed `eliot_learning_contracts::activation::CrossTaskAdmission`
//! that `candidate_bounds.rs` names as the shape being replaced.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_contracts::StateFence;
use eliot_governor::{
    CrossTaskAdmissionError, CrossTaskAdmissionRecord, LearningAdmissionClaim,
    LearningAdmissionError, LearningAdmissionPermit, VerifiedLearningAdmission,
    issue_learning_admission, verify_learning_admission,
};
use eliot_improvement::candidate_bounds::{
    AdmitOutcome, AdmitReport, ArchivedCandidate, BoundedBacklog, CandidateBoundPolicy,
    CrossTaskCarryover, TrackedCandidate,
};
use eliot_improvement::{
    ChangeDescriptor, EvidenceSource, ImprovementBrief, ImprovementCandidate, ImprovementError,
    ImprovementLifecycle, ImprovementSurface, OwnerDecision, OwnerDecisionKind, ReplayPlan,
    SafeBoundary, SourcedEvidence, brief_at_safe_boundary, candidate_from_evidence,
    check_class_gate, classify, sourced_evidence,
};
use eliot_maintenance::{
    IMPROVEMENT_ADMISSION_AUTHORITY, IMPROVEMENT_CANDIDATE_BOUNDS_REVISION,
    ImprovementAdmissionPolicy, ImprovementBoundError, ImprovementSurfaceBound,
    ImprovementTargetSurface, resolve_candidate_surface_bound,
};
use eliot_protocol::RequestIdentity;
use eliot_receipts::RequestBinding;
use eliot_store_api::{
    LearningRecordKind, ScopeId, canonical_json_bytes, learning_record_commit_params,
    learning_record_mutation_request,
};
use thiserror::Error;

use super::{DaemonComposition, SERVICE_NAME};

/// Closed improvement surface this daemon's own self-quality-debt observations
/// concern, named in the maintenance (`G-19`) closed surface vocabulary so the
/// bound this daemon enforces can be read from the owner's record by key.
const IMPROVEMENT_SURFACE: ImprovementSurface = ImprovementSurface::Memory;

/// The maintenance (`G-19`) closed name of [`IMPROVEMENT_SURFACE`].
///
/// Resolved through the owner's own closed vocabulary rather than spelled as a
/// string, so a surface rename cannot silently leave this daemon looking up a
/// bound under a name the owner no longer defines.
const IMPROVEMENT_SURFACE_NAME: ImprovementTargetSurface = ImprovementTargetSurface::Memory;

/// The candidate's owning decision authority, and the authority the bound is
/// owned by: maintenance (`G-19`), read from
/// [`eliot_maintenance::IMPROVEMENT_ADMISSION_AUTHORITY`] rather than declared
/// here.
///
/// The same value is the learning admission permit's `authority_ref`, which is
/// what makes [`CandidateBoundPolicy::validate_governed`] a real check: the
/// bound's owner is compared against a Governor-minted permit, so this constant
/// cannot admit anything by itself. `ASSUMPTION:` the candidate's
/// `owner_and_decision_authority` is the maintenance admission owner rather
/// than the daemon's service name, because I12.24 requires the decision owner
/// to be the authority that admits the candidate, and `G-19` is declared the
/// sole admission owner for `meta.learning.closure` and
/// `meta.improvement.promotion_input` candidates
/// (`crates/governor/eliot-maintenance/src/improvement_admission.rs:3-4`).
/// It names an ADMISSION authority and nothing else, and is deliberately not
/// the `owner` of the recorded decision below: that value names the principal
/// that SELECTED the disposition, and no admission authority has selected one.
/// See "The recorded disposition is the DAEMON's own, and no owner ingress
/// exists" in the module documentation.
const IMPROVEMENT_OWNER: &str = IMPROVEMENT_ADMISSION_AUTHORITY;

/// Closed store scope for durable improvement-candidate learning records.
///
/// This is the same fixed `governor` scope the Skill lifecycle/evidence owner
/// rows already use (`skill_evidence_read.rs::LIFECYCLE_SCOPE`), so the
/// improvement candidate lands in the Governor-owned scope rather than
/// inventing a second scope.
const IMPROVEMENT_SCOPE: &str = "governor";

/// Deadlines bounding one durable learning-record commit ingress, in Unix
/// milliseconds, matching the retained daemon transport's own operation bound
/// (`experience_runtime.rs::COMMIT_INGRESS_DEADLINE_MS`).
const IMPROVEMENT_COMMIT_DEADLINE_MS: u64 = 30_000;

/// Owner-assessed expected value of one maintenance-debt improvement candidate.
///
/// This is the ASSESSMENT, not the bound: `CandidateBoundPolicy::min_value` is
/// the floor read from the owner's record and is never spelled here, and
/// `max_active` is likewise the owner's. `ASSUMPTION:` a maintenance-debt
/// candidate is worth the neutral `1.0` — the daemon runs no experiment and
/// holds no measured benefit, so it claims neither more nor less, and the value
/// only orders the backlog (I12.24:297) and decides the `LowValue` archive
/// cause against the OWNER's floor. A candidate whose owner assesses less than
/// that floor is refused by the bound, and the daemon's own number is then
/// irrelevant to the outcome.
const IMPROVEMENT_CANDIDED_VALUE: f64 = 1.0;

/// Source campaign identity the daemon's improvement learning belongs to.
///
/// A real, stable, owner-scoped identity rather than a per-observation value:
/// the learning this daemon produces is one maintenance campaign's, and a
/// cross-task carryover is defined as carrying THAT campaign's learning to
/// another task, so a per-observation campaign id would make no carryover
/// representable. `ASSUMPTION:` the daemon's maintenance cadence is one
/// campaign; the daemon has no campaign-creation path of its own, and the
/// admission's own `scope_ref` (the observed maintenance scope) is what
/// distinguishes one observation from another.
const IMPROVEMENT_CAMPAIGN: &str = "eliotd.maintenance.improvement";

/// The independent evaluator that must verify any experiment the maintenance
/// admission owner releases one of these candidates to.
///
/// Named here as the revalidation's evaluator because the maintenance
/// evaluation IS the independent observation that raised the candidate; a
/// revalidation claiming a different evaluator is compared field-by-field
/// against the minted permit and refused, so this value cannot be a free-text
/// pass.
const IMPROVEMENT_EVALUATOR: &str = "maintenance-trigger-evaluator";

/// Typed failures of the production improvement-intake dispatch.
#[derive(Debug, Error)]
pub enum ImprovementDispatchError {
    /// The `eliot-improvement` owner rejected the candidate, brief, or
    /// decision assembly for this real observation.
    #[error("improvement intake: {0}")]
    Improvement(#[from] ImprovementError),
    /// The bounded-backlog registry refused the candidate.
    #[error("improvement backlog: {0}")]
    Backlog(String),
    /// The maintenance (`G-19`) decision record refused the bound this daemon
    /// would enforce: the surface has no owner-decided bound, the bound is
    /// unusable, or the enforced bound disagrees with the owner's own record.
    #[error("improvement bound: {0}")]
    Bound(#[from] ImprovementBoundError),
    /// The live Governor refused to issue or re-verify the learning admission
    /// this governed path requires. The typed owner error travels unchanged,
    /// so "not admitting", "stale epoch", "generation drift", "digest
    /// mismatch" and "fence drift" stay distinguishable.
    #[error("improvement learning admission: {0}")]
    Admission(#[from] LearningAdmissionError),
    /// The Governor refused the distinct cross-task admission, or the
    /// cross-task record failed re-verification. The typed
    /// [`CrossTaskAdmissionError`] travels unchanged.
    #[error("improvement cross-task admission: {0}")]
    CrossTask(#[from] CrossTaskAdmissionError),
    /// The Self-Quality conformance contract refused the diagnosis this
    /// observation would have produced, or the finding had no usable refs for
    /// the improvement funnel. The typed [`eliot_self_quality::SelfQualityError`]
    /// travels unchanged, so a #971 contract rejection and a missing
    /// improvement-mapping ref stay distinguishable here rather than collapsing
    /// into one opaque string.
    #[error("improvement self-quality conformance diagnosis: {0}")]
    SelfQuality(#[from] eliot_self_quality::SelfQualityError),
    /// The durable learning-record commit was refused.
    #[error("improvement learning-record commit: {0}")]
    Commit(String),
    /// The store scope or record identity is not a valid contract value.
    #[error("improvement contract value: {0}")]
    Contract(String),
}

/// One assembled, owner-actionable improvement artifact over a real
/// observation, ready to be made durable.
///
/// Every field is a function of the observed maintenance decision, and the
/// `ImprovementBrief` carries the exact content I12.24:74 requires a decision
/// owner to read (problem, evidence, likely benefit, risk, proposed owner,
/// cost, next reversible step, unknowns) — so that content needs no raw-metric
/// search once it REACHES an owner.
///
/// Stated precisely, because the previous wording of this field claimed the
/// owner does not search raw metrics, and that is not yet true: no
/// owner-facing contour reads this artifact. It is committed verbatim into the
/// `Candidate` record and read back only by this daemon's own deduplication
/// read. The CONTENT is complete; the DELIVERY is absent, and the missing
/// contour is measured and named under "The brief reaches no owner, and the
/// contour that would carry it is absent" in the module documentation.
#[derive(Clone, Debug)]
pub struct ImprovementArtifact {
    /// The evidence-bound candidate admitted to the deduplication registry.
    pub candidate: ImprovementCandidate,
    /// Owner-actionable brief at the safe boundary.
    pub brief: ImprovementBrief,
    /// Recorded, non-mutating owner decision over that brief.
    pub decision: OwnerDecision,
}

/// Assembles the deduplicated improvement candidate, the owner-actionable
/// brief, and the recorded owner decision from one real maintenance-trigger
/// observation.
///
/// The decision's own `trigger_id`, `family`, `scope_ref`, `reason` and
/// `decision` are the evidence lineage, so two evaluations of the same
/// failure under the same admitted fence deduplicate by content
/// (`BoundedBacklog::admit` merges on overlapping lineage) rather than
/// minting a fresh candidate per observation.
///
/// `state_fence` is the daemon's own admitted Kernel fence for this pass; it
/// becomes the candidate's `validity_scope` (see [`admitted_fence_ref`]), so
/// the artifact is only ever admitted under the same authority epoch and
/// resource generation the observation was evaluated under.
///
/// This performs no durability, no promotion and no activation: it returns the
/// artifact, and the caller commits it through
/// [`crate::DaemonComposition::commit_learning_record`].
///
/// `observed_closures` is the single Governor-owned learning-closure image
/// ([`eliot_governor::CanonicalLearningDeltaStore`]) this daemon already holds,
/// reached as `DaemonComposition::learning_closure().store()`. It is read here,
/// under whatever guard the caller holds, so the brief's safe boundary is an
/// owner-observed consequential boundary rather than a formatted literal (see
/// the `SafeBoundary::from_observed_closure` call below).
pub fn assemble_improvement_artifact(
    decision: &eliot_maintenance::AutomationTriggerDecision,
    state_fence: &StateFence,
    observed_closures: &eliot_governor::CanonicalLearningDeltaStore,
) -> Result<ImprovementArtifact, ImprovementDispatchError> {
    // Evidence lineage: the decision's own stable identity, never a fresh
    // per-observation value, so a repeat deduplicates.
    let evidence_refs = maintenance_evidence_refs(decision);
    let trace_refs = vec![format!("maintenance-family:{}", decision.family)];
    // `MaintenanceFamily` carries a `Display` impl (its canonical SCREAMING
    // spelling); `AutomationDecision` and `DecisionReason` are `Debug`-only
    // closed owner enums and gain no `Display` here, so they are named by
    // their derived variant spelling instead.
    let trigger = maintenance_trigger_text(decision);
    // The replay plan is diagnostic-only (I12.24:76-77): the fixed replay,
    // holdout and transfer legs are the decision's own canonical refs, and the
    // counter metrics name what must not regress. Promotion is separately
    // refused by the intake's budget gate, which this advisory path does not
    // attempt to satisfy.
    let replay_plan = maintenance_replay_plan(decision, &evidence_refs);
    let admitted_scope = admitted_fence_ref(state_fence)?;
    // The evidence bundle is selected by the DERIVED source, not asserted
    // (issue #1867 W2). Every source but one is the maintenance occurrence
    // itself, and is assembled by the funnel's own validated constructor. The
    // conformance-audit source is different in kind: I12.24:50 names the
    // trigger "Architecture/Implementation/runtime conformance gap", so that
    // evidence enters the funnel through the Self-Quality conformance
    // diagnosis contract, which owns the finding's inert owner handoff
    // (`eliot_self_quality::conformance_evidence`), rather than being labelled
    // as a maintenance occurrence and losing the conformance owner, the
    // priority axis and the invalidation set the finding recorded. Both arms
    // terminate in the same `eliot_improvement::sourced_evidence` validation,
    // so neither can bypass it.
    let evidence = match maintenance_evidence_source(decision) {
        EvidenceSource::ConformanceDiagnosis => {
            conformance_diagnosis_evidence(decision, &trigger, &admitted_scope)?
        }
        source => sourced_evidence(
            source,
            &evidence_refs,
            &trace_refs,
            &trigger,
            &[format!(
                "unproven-blocked-automation:{}",
                decision.trigger_id
            )],
            &admitted_scope,
            IMPROVEMENT_OWNER,
        )?,
    };

    let mut candidate = candidate_from_evidence(
        SERVICE_NAME,
        IMPROVEMENT_SURFACE,
        &format!(
            "evaluate and resolve the blocked maintenance family {} at {}",
            decision.family, decision.scope_ref
        ),
        &evidence,
        replay_plan,
        BTreeMap::new(),
        &format!("maintenance-family:{}", decision.family),
        &format!("maintenance-canary:{}", decision.trigger_id),
        &format!("maintenance-rollback:{}", decision.trigger_id),
        &format!("maintenance-stop:{}", decision.trigger_id),
    )?;
    // Admitted intake is triaged for owner review, exactly as the intake
    // path does, so the durable record carries the owner-decision lifecycle.
    candidate.transition_lifecycle(ImprovementLifecycle::Triaged)?;

    // The application-class boundary is enforced HERE, in the production
    // assembly, not only inside `prepare_intake` (issue #1867 W5). Before this
    // the gate had no production caller at all: `classify` and
    // `check_class_gate` were reachable only from `intake_from_evidence`, which
    // this daemon deliberately does not call because its budget gate would
    // demand fabricated canary refs. The class is therefore decided here from
    // the candidate's OWN recorded surface, and a candidate whose recorded
    // surface the owner forbids to the advisory class is refused rather than
    // assembled.
    //
    // Stated plainly so this call is not read as broader than it is: the
    // candidate assembled above records [`IMPROVEMENT_SURFACE`] (`Memory`),
    // which is not a protected surface, so on the live maintenance path the
    // class taken is `Advisory` and the gate passes. What the gate buys here is
    // that the class is a FUNCTION of the candidate's recorded surface rather
    // than of literals — a candidate carrying `Verifier` or `Scheduler` is
    // refused. See `enforce_advisory_class_gate` for the exact ceiling,
    // including the two classes this path cannot represent at all.
    enforce_advisory_class_gate(&candidate)?;

    // The safe boundary is READ, not spelled. It used to be two formatted
    // strings (a constant owner and a constant `boundary:{scope_ref}`), which
    // satisfied `SafeBoundary::validate` while observing nothing at all: the
    // check proved nothing about the operation it claims to gate.
    // `SafeBoundary::from_observed_closure` takes both values from a record the
    // Governor's learning-closure owner actually committed from owner-recorded
    // lifecycle activities (`crates/governor/eliot-governor/src/
    // learning_closure.rs:483`), and that boundary is derived by
    // `derive_boundaries`, which refuses an ordinary read and an empty activity
    // set before anything is committed, per I12.24:181.
    //
    // STATED PLAINLY, because it changes what this pass does: `store` is read
    // from already-committed in-process state and performs no exchange, but an
    // EMPTY closure image is `ImprovementError::UnsafeBoundary`, so this pass
    // now commits nothing until a consequential attempt has actually been
    // closed in this process. That is the fail-closed direction I12.24:64
    // requires — a brief must not reach an owner as though a boundary had been
    // observed when none was — and the refusal is reported as a typed
    // `ImprovementDispatchError::Improvement` by the caller, not swallowed.
    let boundary = SafeBoundary::from_observed_closure(observed_closures)?;

    // The brief's decision information is a PROJECTION OF THAT SAME OBSERVED
    // RECORD, not the raw maintenance trigger text. I12.24:74 requires the
    // named decision owner to read the problem, evidence, likely benefit, risk,
    // cost, next reversible step and unknowns without searching raw metrics;
    // repeating the trigger text satisfied the letter of that and none of its
    // purpose, because it said nothing about what the closure actually
    // recorded.
    //
    // `load` is the same mutex-guarded read `from_observed_closure` just
    // performed on the same image, under the composition guard the caller
    // already holds (`daemon_runtime::improvement_intake_artifact`), and this
    // guarded phase commits nothing, so the newest record here is the record
    // whose `actor_id` and `consequential_boundary` the boundary above names.
    // It is read a second time because the two-string `SafeBoundary` cannot
    // carry the record itself: `eliot-improvement` has no `eliot-learning-delta`
    // edge, so widening `SafeBoundary` to hold one would be a new dependency
    // for a value the brief only needs to quote. The record TYPE is not named
    // here either — `eliotd` has no `eliot-learning-delta` dependency — so it is
    // read by inference and through the record's own accessors. An unreadable
    // or empty image is the same typed `UnsafeBoundary` refusal the boundary
    // constructor returns for the same condition, never a substituted value.
    let observed = newest_observed_closure(observed_closures)?;
    // The durable lineage handle and canonical digest the record itself
    // committed, so the owner can read exactly this closure without searching.
    let (observed_artifact, observed_digest) = (
        observed.lineage_artifact.clone(),
        observed.lineage_digest.clone(),
    );
    // What the observed closure actually concluded about behaviour, read
    // through the record's own predicates rather than re-spelled here.
    let observed_effect = observed_behaviour_effect(&observed);
    // The two values below are the boundary's OWN observed strings, so the
    // boundary this brief describes and the boundary it is gated on are
    // literally the same value.
    let principal = boundary.observed_principal_ref();
    let boundary_ref = boundary.observed_boundary_ref();
    let unknowns = observed_unknowns(&observed, decision.family);

    // Why the brief names the OBSERVED principal, and which brief fields the
    // closure record cannot supply, is stated in the module documentation
    // above under "One principal, two roles".
    let brief = brief_at_safe_boundary(
        &candidate,
        &format!(
            "{trigger}; the learning closure this brief is gated on committed durable delta \
             {observed_artifact} (digest {observed_digest}) for attempt {} of campaign {} on \
             route {}, at consequential boundary {boundary_ref} by principal {principal}, over {} \
             observed evidence ref(s)",
            observed.attempt_id,
            observed.campaign_id,
            observed.route_id,
            observed.evidence_ref_count,
        ),
        &format!(
            "the blocked family {} is evaluated on every cadence and cannot start, and the \
             closure this brief is gated on {observed_effect}; giving that family a start route \
             removes a blocked evaluation per cadence",
            decision.family
        ),
        &format!(
            "advisory only; no authority, privacy, finish or durability effect is taken, and the \
             observed boundary {boundary_ref} is not modified by it"
        ),
        principal,
        "one owner triage pass over the stored brief; the observed closure record carries no \
         cost, compute or Human-attention field, so the cost of the decision itself is the only \
         cost this brief can state",
        &format!(
            "triage maintenance trigger {} against the observed boundary {boundary_ref}",
            decision.trigger_id
        ),
        unknowns,
        &boundary,
    )?;

    let decision_record = record_daemon_disposition(&brief, decision.family)?;

    // Deduplication and bounded admission are NOT done here. They need the
    // live Governor owner (a real permit whose authority the bound is checked
    // against), which this pure assembly deliberately does not take; the
    // governed admission is `admit_improvement_artifact`, whose single
    // production caller is `daemon_runtime::run_improvement_intake`.
    Ok(ImprovementArtifact {
        candidate,
        brief,
        decision: decision_record,
    })
}

/// Records the DAEMON'S OWN non-authoritative disposition over the brief it just
/// assembled, and names it as such.
///
/// This is the production caller of the bridge's `record_brief_decision`, which
/// previously had none, and it is still non-mutating: `Investigate` is one of the
/// two kinds `is_non_mutating` admits, and recording it changes no surface, which
/// is I12.24:82's "advisory … default; changes nothing until owner acts" observed
/// rather than asserted.
///
/// # The owner is the daemon, and deliberately NOT `IMPROVEMENT_OWNER`
///
/// The `owner` used to be [`IMPROVEMENT_OWNER`], the maintenance (`G-19`)
/// admission authority, on the reasoning that this field names the principal
/// that RECORDED the disposition and the maintenance owner is that principal
/// because it issued the permit this candidate was assembled under. That
/// reasoning was wrong, and it is the same error this issue exists to remove,
/// read from the other side. Issuing a learning-admission permit is a different
/// act from selecting a disposition over a brief: the `G-19` owner admitted the
/// CANDIDATE to the bounded backlog, and it never saw this brief, never read it,
/// and chose nothing about it. Recording its name against a disposition it did
/// not select is precisely the false attribution A12.02:3 forbids — "Identity is
/// not a model's self-declared string" — with the failure running the other way:
/// not a model inventing an identity, but a real principal's name attached to a
/// decision that principal never made. A later reader of
/// `improvement_dedup_read` takes that field at its word, so the false
/// attribution is not harmless; it is a durable claim about a real owner.
///
/// The owner recorded now is the only principal that genuinely selected this
/// disposition: the daemon itself, under its own service identity
/// ([`SERVICE_NAME`]). That identity is not self-declared — A12.02:3 is "Identity
/// is not a model's self-declared string" — it is the installed service's own,
/// named by the composition and carried on every request identity this daemon
/// commits (`improvement_commit_identity` below binds it as both `product_id` and
/// `source_id`), and the exchange it makes over is authenticated in the other
/// direction too: the Kernel front door proves this daemon's peer SID, session
/// identity and artifact digest before the connection is used
/// (`daemon_kernel_client.rs:1878-1908`). It grants nothing either way —
/// `is_non_mutating` is what makes the record advisory. A note that says "the
/// daemon triaged this and no owner has ruled on it" is a smaller claim than the
/// one it replaces, and it is a TRUE one.
///
/// It is deliberately NOT the brief's `proposed_owner` either. That field names
/// the principal proposed to DECIDE (the observed boundary's `actor_id`, read
/// from a committed closure record); this field names the principal that DID
/// record a disposition. The daemon is not proposed to decide its own brief, so
/// conflating the two would overwrite the one route an owner's decision has a
/// named place to arrive through.
///
/// The four dispositions remain unreachable from an owner's selection, and
/// `OwnerDecisionKind::Reject` in particular is not produced anywhere in
/// `bins/`. The measurement of every candidate ingress surface, and the exact
/// route that is missing and where it would attach, are recorded in the module
/// documentation above under "The recorded disposition is the DAEMON's own, and
/// no owner ingress exists". Nothing here substitutes a fabricated caller for it.
///
/// `family` is the maintenance family this pass evaluated, and it appears only
/// in the note text; the disposition it selects does not depend on it.
fn record_daemon_disposition(
    brief: &eliot_improvement::ImprovementBrief,
    family: eliot_maintenance::MaintenanceFamily,
) -> Result<OwnerDecision, ImprovementDispatchError> {
    crate::improvement_intake::record_brief_decision(
        brief,
        SERVICE_NAME,
        OwnerDecisionKind::Investigate,
        &format!(
            "the daemon triaged blocked maintenance family {family} at its own initiative; this \
             disposition selects nothing and no owner has ruled on this brief, because no \
             owner-issued ingress reaches this process"
        ),
    )
    .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))
}

/// The evidence lineage this observation raises, over the decision's own
/// stable identity.
///
/// Never a fresh per-observation value: the refs are the decision's own
/// `trigger_id` and `scope_ref`, so two evaluations of the same occurrence
/// under the same admitted fence carry the same lineage and deduplicate.
fn maintenance_evidence_refs(
    decision: &eliot_maintenance::AutomationTriggerDecision,
) -> Vec<String> {
    vec![
        format!("maintenance-trigger:{}", decision.trigger_id),
        format!("maintenance-scope:{}", decision.scope_ref),
    ]
}

/// The trigger statement the decision's own closed fields make.
///
/// `MaintenanceFamily` carries a `Display` impl (its canonical SCREAMING
/// spelling); `AutomationDecision` and `DecisionReason` are `Debug`-only
/// closed owner enums and gain no `Display` here, so they are named by their
/// derived variant spelling instead.
fn maintenance_trigger_text(decision: &eliot_maintenance::AutomationTriggerDecision) -> String {
    format!(
        "maintenance automation {} evaluated {:?} for reason {:?}",
        decision.family, decision.decision, decision.reason
    )
}

/// The diagnostic-only replay plan for this observation (I12.24:76-77).
///
/// The fixed replay, holdout and transfer legs are the decision's own canonical
/// refs, and the counter metric names what must not regress. Promotion is
/// separately refused by the budget gate, which this advisory path does not
/// attempt to satisfy.
fn maintenance_replay_plan(
    decision: &eliot_maintenance::AutomationTriggerDecision,
    evidence_refs: &[String],
) -> ReplayPlan {
    ReplayPlan {
        fixed_replay_refs: evidence_refs.to_vec(),
        holdout_refs: vec![format!("maintenance-holdout:{}", decision.trigger_id)],
        transfer_refs: vec![format!("maintenance-transfer:{}", decision.scope_ref)],
        counter_metric_names: vec!["blocked_maintenance_runs".to_owned()],
        verifier_refs: vec![format!("maintenance-evaluator:{}", decision.family)],
    }
}

/// The material one observed closure contributes to the brief.
///
/// Owned, not borrowed: the record TYPE cannot be named here — neither `eliotd`
/// nor `eliot-improvement` has an `eliot-learning-delta` edge, and adding one for
/// a value the brief only quotes would be a new dependency. The closure's
/// accessors are read through inference and their results carried by value, so
/// nothing in this module depends on the record's concrete type.
struct ObservedClosure {
    /// Durable lineage handle and canonical digest the record committed.
    lineage_artifact: String,
    lineage_digest: String,
    /// The closed attempt this observation belongs to.
    attempt_id: String,
    /// The campaign that attempt belonged to.
    campaign_id: String,
    /// The route the closed attempt ran.
    route_id: String,
    /// How many evidence refs the record itself observed.
    evidence_ref_count: usize,
    /// The record's own predicate on whether it proposed a behaviour change.
    carries_behavioural_proposal: bool,
    /// Whether the record names a prior-attempt lineage to retry against.
    has_retry_lineage: bool,
}

/// Reads the newest committed closure record, refusing when there is none.
///
/// The same mutex-guarded read [`SafeBoundary::from_observed_closure`] performs
/// on the same image, under the composition guard the caller already holds, so
/// both see the same newest record. An unreadable or empty image is the same
/// typed [`ImprovementError::UnsafeBoundary`] refusal, never a substituted
/// value.
fn newest_observed_closure(
    observed_closures: &eliot_governor::CanonicalLearningDeltaStore,
) -> Result<ObservedClosure, ImprovementError> {
    let (observed_records, _observed_version) = observed_closures
        .load()
        .map_err(|_| ImprovementError::UnsafeBoundary)?;
    let observed = observed_records
        .last()
        .ok_or(ImprovementError::UnsafeBoundary)?;
    let (lineage_artifact, lineage_digest) = observed.lineage_ref();
    Ok(ObservedClosure {
        lineage_artifact: lineage_artifact.to_string(),
        lineage_digest: lineage_digest.to_owned(),
        attempt_id: observed.attempt_id.as_str().to_owned(),
        campaign_id: observed.campaign_id.as_str().to_owned(),
        route_id: observed.route_id.clone(),
        evidence_ref_count: observed.evidence_refs.len(),
        carries_behavioural_proposal: observed.carries_behavioural_proposal(),
        has_retry_lineage: observed.lineage_for_retry().is_some(),
    })
}

/// What the observed closure actually concluded about behaviour.
///
/// Read through the record's own predicate (`carries_behavioural_proposal`)
/// rather than re-spelled at the call site, so the brief reports what the
/// closure committed rather than what this dispatch layer would have chosen.
/// Both arms are equally truthful statements about the record; neither is a
/// prediction.
fn observed_behaviour_effect(observed: &ObservedClosure) -> &'static str {
    if observed.carries_behavioural_proposal {
        "and proposes a next-behaviour change for the next attempt"
    } else {
        "and closed with no next-behaviour change proposed"
    }
}

/// The unknowns the observed closure could not resolve, plus the one it cannot
/// speak to at all.
///
/// Unknowns are the states the record could NOT resolve. The maintenance
/// start-route question is kept because it is real and no closure record answers
/// it. `require_refs` in [`eliot_improvement::ImprovementBrief::validate`]
/// still hard-requires a non-empty list.
fn observed_unknowns(
    observed: &ObservedClosure,
    family: eliot_maintenance::MaintenanceFamily,
) -> Vec<String> {
    let mut unknowns = vec![format!(
        "unknown whether maintenance family {} has a start route",
        family
    )];
    if !observed.has_retry_lineage {
        unknowns.push(format!(
            "the observed closure of campaign {} records no prior-attempt lineage, so it \
             establishes no repeated-strategy comparison",
            observed.campaign_id
        ));
    }
    unknowns
}

/// Enforces the I12.24 application-class boundary over a real candidate
/// (issue #1867 W5).
///
/// # The descriptor is the candidate's own recorded content
///
/// [`ImprovementCandidate::target_surface`] is the candidate's OWN closed
/// surface record, and it is the only class evidence this path holds. The
/// descriptor is therefore built by
/// [`ChangeDescriptor::from_recorded_surface`], the crate's own constructor for
/// exactly this situation:
///
/// - `touches_protected` is [`eliot_improvement::is_prohibited_tuning_surface`]
///   over that surface, so it is a comparison of the candidate's recorded
///   surface against the owner's closed rule, not a spelled literal. A
///   candidate recorded on [`ImprovementSurface::Verifier`] or
///   [`ImprovementSurface::Scheduler`] classifies as `Protected` and is refused
///   below, because the owner class for those surfaces requires an explicit
///   owner decision and a corresponding migration/proof (I12.24:93) and this
///   path holds neither. `ASSUMPTION:` those two surfaces map to `Protected`
///   rather than to `CodeModuleConfig`, because I12.24:93 names `verifier` and
///   `authority` in the protected class and I12.24:87-88 names
///   `verifier definition` and `Kernel/Watchdog reserve` as never-tuning — so
///   the owner-decision route the crate's own
///   [`eliot_improvement::is_prohibited_tuning_surface`] names for them is the
///   protected one. `Protected` is also the stricter of the two routes that
///   function allows, so the mapping fails closed.
/// - `bounded_tuning` and `has_work_item_ref` are NOT spelled on this call at
///   all, and cannot be: that constructor exposes no parameter for them,
///   precisely because this path holds no evidence for either. I12.24:85 admits
///   pre-authorized tuning only "inside a declared safe range" and the
///   I12.24:20-38 `ImprovementCandidate` schema lists no safe range, so there
///   is nothing to read; I12.24:90 admits code/module/config delivery as a
///   "normal work item", and I12.24:65 places that work item after "decision
///   owner selects reject / investigate / work item / experiment", so the
///   candidate assembled here carries none. `ASSUMPTION:` this path therefore
///   cannot honestly select either class, and the correct outcome is to say so
///   rather than to mint a `true`: the `PreAuthorizedTuning` and
///   `CodeModuleConfig` classes are NOT REACHABLE here, structurally, because
///   the only descriptor this path can build has no way to claim them. A
///   future change that wants either has to add the safe range or the real work
///   item to the candidate first; until then there is nothing for this gate to
///   refuse on those two classes, and this comment does not claim otherwise.
///
/// [`ImprovementCandidate::advisory_only`] is deliberately NOT used as a class
/// flag. It is a real recorded field, but it is not the same thing as these
/// three: `validate_base` refuses any candidate whose `advisory_only` is false
/// (`ImprovementError::SelfPromotionForbidden`), so it is a self-promotion
/// invariant that is already enforced upstream on every candidate, not
/// evidence about which of the four I12.24 classes this change belongs to.
/// Reading it as a class input would re-derive a fact the owner already
/// guarantees and would misreport the class boundary as content-bound when the
/// class content is the surface record above.
///
/// # What the gate actually refuses
///
/// [`check_class_gate`] is asked for the material this path really holds:
/// `rollback_ref` is the candidate's own recorded `rollback`;
/// `owner_approved` is `false` and `migration_proof_ref` is `None` because
/// this path holds no owner decision and no migration/proof, and
/// `work_item_ref` is `None` because the candidate records no work item.
/// Those absences are the fail-closed direction: a candidate whose recorded
/// surface classifies as `Protected` is refused with
/// [`ImprovementError::ApplicationClassViolation`] rather than assembled, and
/// `live_experiments_on_surface` is `0` — this path starts no experiment — but
/// it is not read, because the tuning class is not representable above.
///
/// The refusal is therefore content-bound: it turns on the surface the
/// candidate actually records. It is not a claim that every class upgrade is
/// caught, and no such claim is made here.
fn enforce_advisory_class_gate(
    candidate: &ImprovementCandidate,
) -> Result<(), ImprovementDispatchError> {
    let change = ChangeDescriptor::from_recorded_surface(candidate.target_surface);
    let class = classify(&change);
    check_class_gate(class, &change, 0, &candidate.rollback, None, false, None)?;
    Ok(())
}

/// The I12.24 evidence source this daemon's own maintenance decision belongs
/// to (issue #1867 W2).
///
/// DERIVED from the closed fields the Governor's own decision carries, so the
/// recorded source is a fact about the observation rather than an assumption.
/// Every observation this function labels is the same KIND of occurrence: the
/// maintenance owner's evaluation of one real maintenance trigger — an attempt
/// at admitting that maintenance job together with the outcome it produced.
/// I12.24:43 names that trigger "repeated failure/repair or no-progress loop",
/// the closed I12.24 set spells it [`EvidenceSource::Attempt`], and this
/// issue's own source list names "actual attempts/evaluators" among the sources
/// this path must connect. So the two families whose occurrence is something
/// else carry their own label, and everything else is an attempt:
///
/// - `MaintenanceFamily::SecurityDependencyScan` is the daemon's
///   security/dependency incident family, and I12.24:49 names "security
///   incident". It is still UNREACHABLE from this daemon, and the reason is
///   measured rather than assumed: the only site that observes anything close
///   to a dependency or manifest identity is the store-health poll
///   (`daemon_runtime.rs`, the `AdmittedObservation` trigger), and what it
///   observes is `StoreHealth::manifest_digest` — the store API's own
///   operation-manifest identity — while that family's registered observation
///   is the pinned-scanner canonical receipt from
///   `scripts/verify-dependency-policy.py` and its registered execution owner
///   is recorded as unavailable because "no eliotd Kernel operation or Rust
///   owner exposes a scan result to the daemon"
///   (`maintenance_family_catalog.rs:1441-1457`). That site's origin also maps
///   to `MaintenanceTrigger::WatchdogProblem`, which is not one of that
///   entry's registered origins (`Human`, `Policy`, `Installation`). Naming
///   the family there would claim a scan nobody ran, so this arm stays
///   unreachable until a real scan receipt is surfaced to the daemon.
/// - `MaintenanceFamily::DonorConformance` is the conformance-audit family,
///   and I12.24:50 names "Architecture/Implementation/runtime conformance gap",
///   which the closed set spells [`EvidenceSource::ConformanceDiagnosis`]. It
///   is REACHABLE: the daemon names it at the sites whose own evidence is a
///   declared-capability conformance gap — the two startup trigger sites and
///   the improvement-intake observation, through
///   `daemon_runtime::conformance_observed_family` (issue #1867 W2/A1). That
///   is what makes [`conformance_diagnosis_evidence`] a live projection rather
///   than an unreachable one.
/// - every other family is the attempt itself, and the set of families that can
///   reach this function is EXACTLY [`crate::SELF_OBSERVED_FAMILY`] and
///   `MaintenanceFamily::DonorConformance`. That is measured, not assumed: the
///   sole caller of `assemble_improvement_artifact` is
///   `daemon_runtime::improvement_intake_artifact` (`daemon_runtime.rs:4813`),
///   it is the only caller of `run_improvement_intake`, and the one observation
///   that function is ever handed is built by
///   `daemon_runtime::improvement_intake_observation` — whose family is
///   `daemon_runtime::conformance_observed_family` (issue #1867 W2/A1) and
///   whose origin is `MaintenanceTriggerOrigin::IdleTransition`. So the
///   residual resolves to `SelfQualityDebt` and to nothing else, which is the
///   measured reason the remaining I12.24 sources have no arm here rather than
///   a judgement about them. What the residual covers is the DECISION, not the
///   family: `AutomationDecision::Start` admits the job, `Suggest` preserves a
///   recommendation instead, `Defer` holds it for a later eligible window,
///   `Block` and `Escalate` deny or escalate it, and `SuppressDuplicate`
///   records that equivalent work is already active. Each of those is an
///   outcome this daemon itself produced, and none of them is a Watchdog
///   suggestion.
///
/// # Why no decision reaching this function is a `Watchdog` observation
///
/// [`EvidenceSource::Watchdog`] is I12.24:54's "Dreamer/Watchdog/Concilium
/// suggestion", and this function still cannot select it. The reason is NOT the
/// one this file previously gave, and the previous reason is now false.
///
/// What used to be true, and is not any more: the decision carried no
/// origin at all. [`eliot_maintenance::AutomationTriggerDecision`]
/// (`crates/governor/eliot-maintenance/src/lib.rs:304-336`) now carries
/// `trigger: MaintenanceTrigger` (`:323`), copied verbatim from
/// `MaintenanceTriggerInput::trigger` at both construction sites
/// (`lib.rs:762` and `lib.rs:1123`) and never selected, widened or defaulted
/// there. The origin is therefore READABLE on the decision this function
/// receives, and the arm is missing a producer rather than a field.
///
/// What is still true, and is what blocks the arm: the observation this
/// dispatch records is built from `MaintenanceTriggerOrigin::IdleTransition`
/// (`daemon_runtime::improvement_intake_observation`, `daemon_runtime.rs:5690`),
/// and the origin→trigger map is exhaustive over the four-member origin enum
/// (`maintenance_trigger_evaluator.rs:122-128`), so that origin maps to
/// `MaintenanceTrigger::Policy` — never `WatchdogProblem`. A policy-driven
/// occurrence is not a Watchdog suggestion, and the decision's own
/// `trigger` field now says so out loud instead of being silent about it.
/// That is the whole of the remaining gap, and it is a one-line change in
/// another owner's file; see "The exact remaining step" below.
///
/// The residual this function used to carry claimed
/// [`EvidenceSource::Watchdog`] for every decision that was neither of the two
/// named families nor a refusal, which covered `Suggest`, `Defer`, `Start` and
/// `SuppressDuplicate`. The refusal test it consulted admitted only `Block` and
/// `Escalate`, although the owner's evaluator pairs `Defer` — never `Block` —
/// with `NotIdle`, `OutsideSchedule`, `RouteUnavailable`, `BudgetUnavailable`
/// and `UserSessionRequired`
/// (`crates/governor/eliot-maintenance/src/lib.rs:628-643`), so it could in
/// fact match `AutomationOff` alone. A label the decision's own content cannot
/// support is the misattribution this issue exists to remove, so the residual
/// is dropped rather than renamed.
///
/// `ASSUMPTION:` I12.24:40-55 names no separate "maintenance" variant, and the
/// decision's `trigger` field carries an I14.22 job origin
/// (`MaintenanceTrigger`), not an I12.24 evidence source — so the three
/// I12.24 sources stay unreachable from this daemon rather than being
/// mislabelled here.
///
/// The contract half of that ceiling is now CLOSED and no longer part of the
/// reason. `AutomationTriggerDecision::trigger` exists and travels verbatim
/// (`lib.rs:323`, copied at `lib.rs:762` and `lib.rs:1123`), so "the origin does
/// not travel with the decision" is no longer true of any of the three. What
/// remains is per-source, and each remaining step is recorded at the source
/// below: an observation whose origin is not `IdleTransition` reaching this
/// intake. The honest outcome here is the `Attempt` label above plus that
/// stated ceiling, not a refusal to classify a live observation.
///
/// # The three sources with NO arm, and the producer each waits for
///
/// [`EvidenceSource::Watchdog`], [`EvidenceSource::Dreamer`] and
/// [`EvidenceSource::Concilium`] are the W2 sources that are not merely an
/// unreachable arm but an ABSENT one: the match below has no pattern that could
/// produce them, while the closed vocabulary does carry all three honestly
/// (`evidence_sources.rs:29-31`). They no longer share the reason the
/// `ASSUMPTION` above used to give them, because that reason is discharged.
/// What each still lacks is its own producer, and the remaining step differs
/// per source:
///
/// - `Watchdog` is the CLOSEST of the three, and its remaining step is now a
///   single origin at a single site rather than a missing contract field.
///   Measured on this tree, not assumed:
///
///   1. The origin that denotes a Watchdog/Doctor occurrence,
///      `MaintenanceTriggerOrigin::AdmittedObservation`, is live and has exactly
///      ONE construction site in this daemon
///      (`daemon_runtime.rs:2868`, the store-health poll). The origin→trigger
///      map is exhaustive over the four-member origin enum
///      (`maintenance_trigger_evaluator.rs:122-128`), and only
///      `AdmittedObservation` maps to `MaintenanceTrigger::WatchdogProblem`, so
///      that one site is the only producer of a `WatchdogProblem` decision.
///   2. That decision does not reach this function. It is consumed at
///      `daemon_runtime.rs:2902-2906` by
///      `note_blocked_automation_notification` and
///      `publish_maintenance_source_results`; it is never handed to
///      `run_improvement_intake` (`:5260`), whose only call site is
///      `maybe_start_improvement_intake` (`:5797`).
///   3. The one observation that DOES reach this function is built at
///      `daemon_runtime::improvement_intake_observation` (`:5684`), which names
///      `MaintenanceTriggerOrigin::IdleTransition` unconditionally (`:5690`).
///      The intake is therefore the sole consumer of that one origin, and the
///      decision it assembles over carries `MaintenanceTrigger::Policy`.
///
///   **The exact remaining step**, now that the origin travels on the decision:
///   a trigger site that hands this intake an observation built from
///   `MaintenanceTriggerOrigin::AdmittedObservation`. The site already exists
///   and already builds exactly such an observation
///   (`daemon_runtime.rs:2868`); what is absent is a route carrying it from
///   there into `improvement_intake_observation`. Once that route exists, this
///   function can select [`EvidenceSource::Watchdog`] by comparing
///   `decision.trigger` against [`MaintenanceTrigger::WatchdogProblem`] — a
///   value it now holds, and the one value in the closed origin map that means
///   "Watchdog/Doctor problem recipe"
///   (`maintenance_trigger_evaluator.rs:118-119`). Until then the arm would be
///   dead on a value the live path provably cannot carry, so it is not wired.
/// - `Dreamer` needs a Dreamer that SUGGESTS work, and its gap is LARGER than
///   the Watchdog one in a way the origin map settles. `MaintenanceTrigger` has
///   a `Dreamer` member (`lib.rs:184-185`), but NO origin maps to it: the
///   exhaustive map at `maintenance_trigger_evaluator.rs:122-128` names only
///   `Policy`, `Onboarding` and `WatchdogProblem`. So unlike `Watchdog`, a
///   `Dreamer` decision cannot be produced by re-routing an existing origin —
///   it needs a NEW `MaintenanceTriggerOrigin` member, which is a vocabulary
///   this issue does not own. Independently, no Dreamer instance proposes
///   anything to this daemon: the route is owner-declared and unassigned on
///   this base, an omitted Dreamer route resolving to `RouteState::Unassigned`
///   with no paid route (`eliot_config::first_run::decide_first_run`).
/// - `Concilium` needs a deliberation verdict with a route into this intake,
///   and its gap is largest of the three: `MaintenanceTrigger` has NO
///   `Concilium` member at all, so a Concilium verdict could not be carried on
///   the decision even if the field were consulted. A vocabulary claim with no
///   producer behind it is the mirror of the misattribution this function
///   exists to remove, so none is added here. The funnel's request source is
///   also absent (see this module's header on `ImprovementRouteRequest` having
///   no production request source), so a verdict has no path into
///   `assemble_improvement_artifact` at all.
///
/// None is filled here because none has a producer this file could read without
/// inventing the observation it claims. Filling any of them from a decision
/// would reinstate exactly the misattribution the removed residual was — and
/// with `trigger` now readable, that misattribution would be materially easier
/// to commit by accident, which is the reason the `Watchdog` arm waits for a
/// route rather than being wired speculatively against a field that exists but
/// can only ever read `Policy` here.
pub fn maintenance_evidence_source(
    decision: &eliot_maintenance::AutomationTriggerDecision,
) -> EvidenceSource {
    use eliot_maintenance::MaintenanceFamily;
    match decision.family {
        // DEAD ARM — kept, not wired. Measured unreachable on this tree, and
        // the precise missing producer is recorded here so the next owner does
        // not re-derive it. Reaching it needs a decision whose `family` is
        // `SecurityDependencyScan`, and the family is the CALLER's real
        // observation, so the producer this arm waits for is a trigger site
        // that observes a security/dependency scan receipt and names the
        // family. No such site exists:
        //
        // 1. No scan is performed for this daemon. The family's registered
        //    observation is the "scripts/verify-dependency-policy.py
        //    pinned-scanner canonical receipt" and its registered execution
        //    owner is recorded unavailable because "no eliotd Kernel operation
        //    or Rust owner exposes a scan result to the daemon"
        //    (`maintenance_family_catalog.rs:1448-1449`). Producing the receipt
        //    is a `scripts/` and dependency-policy owner's job, not this
        //    dispatch layer's.
        // 2. The one daemon site whose trigger origin IS the Watchdog/Doctor
        //    problem origin (`MaintenanceTriggerOrigin::AdmittedObservation`,
        //    `maintenance_trigger_evaluator.rs:126`) is the store-health poll
        //    (`daemon_runtime.rs:2868-2876`), and it observes
        //    `StoreHealth::manifest_digest` — the store API's own
        //    operation-manifest identity — naming `SELF_OBSERVED_FAMILY`. That
        //    is not a scanner receipt, and it is ineligible for this family
        //    twice over: the observed value is the wrong kind of fact, and the
        //    origin is not among this entry's registered origins (`Human`,
        //    `Policy`, `Installation`; `maintenance_family_catalog.rs:1444`).
        //    The decision that site produces now carries
        //    `MaintenanceTrigger::WatchdogProblem` on its own `trigger` field,
        //    which makes the ineligibility CHECKABLE rather than assumed: the
        //    origin reads back as a Watchdog/Doctor problem, and that is
        //    precisely not a scanner receipt. Naming the family there would
        //    claim a scan nobody ran.
        // 3. The exhaustive family census confirms the gap is total, not a
        //    missing match arm: the only `MaintenanceFamily` values any
        //    production trigger site names are `SELF_OBSERVED_FAMILY`
        //    (`SelfQualityDebt`) and `MaintenanceFamily::DonorConformance`
        //    (`maintenance_trigger_evaluator.rs:372`, and
        //    `daemon_runtime::conformance_observed_family`).
        //
        // What would make it reachable, concretely: an admitted owner that
        // surfaces the pinned-scanner receipt (advisory set digest, policy
        // finding set digest, scanner identity and executable digest) to this
        // daemon as a `MaintenanceObservation` evidence set, AND a trigger site
        // that names `SecurityDependencyScan` at an origin its catalog entry
        // registers. Either half alone still leaves the arm dead: a receipt
        // with no family-naming site reaches nothing, and a family-naming site
        // with no receipt claims a scan nobody ran. The arm is not deleted
        // because `EvidenceSource::SecurityIncident` is a real I12.24:49
        // source and the family's registered observation is exactly a scan
        // receipt — the vocabulary and the catalog both already name it; only
        // the producer is missing.
        MaintenanceFamily::SecurityDependencyScan => EvidenceSource::SecurityIncident,
        MaintenanceFamily::DonorConformance => EvidenceSource::ConformanceDiagnosis,
        _ => EvidenceSource::Attempt,
    }
}

/// Projects one conformance-audit observation into the Self-Quality
/// conformance-diagnosis evidence bundle the improvement funnel takes
/// (issue #1867 W2/A1, I12.24:50).
///
/// # Why the Self-Quality contract and not a label
///
/// [`maintenance_evidence_source`] classifies the observation; this function
/// is what the classification MEANS. A conformance-audit occurrence is not a
/// maintenance occurrence with a different tag, so the evidence that enters
/// the funnel is the finding the conformance owner recorded: the routed owner,
/// the priority axis, the constraint refs and the invalidation set all come
/// from the decision's own closed fields, and the finding is assembled and
/// validated by `eliot_self_quality::conformance_evidence` through the
/// normative `validate_handoff` and then the funnel's own `sourced_evidence`.
/// Nothing here fabricates a cause: every symptom ref is projected as an
/// `unproven-symptom:{ref}` hypothesis, so a diagnosis never states a proven
/// cause it did not observe.
///
/// # Every ref is a decision field, never a literal
///
/// * `handoff_ref` is the Governor owner's own `trigger_id`;
/// * symptom and evidence refs are that same `trigger_id` and the decision's
///   own `scope_ref`, so two evaluations of the same occurrence converge on one
///   finding rather than minting a new one per cadence tick;
/// * the problem ref is the decision's own `family`;
/// * the constraint ref names the family's own evaluator, the same identity
///   `ReplayPlan::verifier_refs` binds;
/// * the invalidation set is the admitted fence ref
///   ([`admitted_fence_ref`]), so the finding is explicitly invalidated when
///   the authority epoch or resource generation it was observed under moves.
///
/// Each ref set is unique by construction, which `validate_handoff` requires
/// (`make_handoff` sorts but does not de-duplicate).
fn conformance_diagnosis_evidence(
    decision: &eliot_maintenance::AutomationTriggerDecision,
    trigger_problem_or_metric: &str,
    validity_scope: &str,
) -> Result<SourcedEvidence, ImprovementDispatchError> {
    use eliot_self_quality::{ConformanceDiagnosis, SelfQualityHandoffOwner};
    let finding = ConformanceDiagnosis {
        handoff_ref: format!("self-quality-handoff:{}", decision.trigger_id),
        // The routing table's own default owner for a conformance-dimension
        // finding with no counterevidence and no special family
        // (`routing.rs::route_owner`, rules 1-9 miss, rule 10 default), i.e.
        // the owner a real conformance finding reaches.
        //
        // `route_owner` itself is NOT called here, and the reason is measured
        // on this tree rather than assumed. It takes a
        // `SelfQualityObservation`, whose every variant wraps an
        // `ObservationCore`
        // (`crates/foundation/eliot-conformance-contracts/src/self_quality.rs:362-376`),
        // and that core has ten required fields. Most of them are owner-binding,
        // window and measurement facts this daemon does not hold and cannot
        // honestly produce at any trigger site: `OwnerBinding`
        // (`owner_ref`, `schema_ref`, `revision_ref`, `content_digest`),
        // `ObservationWindow` (`observed_from_ms`, `observed_to_ms`,
        // `environment_ref`, `platform_ref`, `toolchain_ref`), the `metric`
        // measurement (`value`, `unit_ref`, `normalization_ref`,
        // `population_ref`, `presence`) and the declared `completeness`
        // denominators. The daemon's real observation is a maintenance
        // decision: a `trigger_id`, a `family`, a `scope_ref` and the observed
        // evidence identities. Manufacturing a window, a platform, a toolchain
        // or a metric normalization to satisfy the constructor would fabricate
        // precisely the observation the owner routing is supposed to read, so
        // the default is named instead and the routing table is not
        // circumvented by re-deriving a different one.
        //
        // `ASSUMPTION:` the named default is the owner `route_owner` would
        // return for the finding recorded here, and the precedence table makes
        // that checkable without holding the observation: rule 1 needs
        // non-empty counterevidence (this handoff carries none), rules 2-8 key
        // on the six family names `RECOVERY`, `ERASURE_INFLUENCE`,
        // `SECURITY_PRIVACY`, `HUMAN_ATTENTION`, `COST_QUOTA`, `PRODUCT`,
        // `PERFORMANCE_RESOURCES`, `MEMORY_PROVENANCE`,
        // `RECOVERY_COMPATIBILITY` and `SOURCE_BUILD` (this finding's family
        // is a maintenance `DONOR_CONFORMANCE`, which is none of them), and
        // rule 9 needs a `LearningQuality`/`ContextQuality` dimension or an
        // `Inconclusive`/`Missing` status (this is a conformance-dimension
        // finding reached through a blocking maintenance decision). Rules 1-9
        // therefore miss and rule 10 is the default. If a future change makes
        // this finding a `SECURITY_PRIVACY` or `COST_QUOTA` one, the owner
        // must be routed, not defaulted.
        owner: SelfQualityHandoffOwner::DevelopmentDiagnosis675,
        priority: conformance_priority(decision),
        symptom_refs: vec![format!("maintenance-trigger:{}", decision.trigger_id)],
        problem_refs: vec![format!("maintenance-family:{}", decision.family)],
        evidence_refs: vec![
            format!("maintenance-trigger:{}", decision.trigger_id),
            format!("maintenance-scope:{}", decision.scope_ref),
        ],
        missing_evidence_refs: Vec::new(),
        applicability_refs: vec![format!("maintenance-scope:{}", decision.scope_ref)],
        constraint_refs: vec![format!("maintenance-evaluator:{}", decision.family)],
        invalidation_set: vec![validity_scope.to_owned()],
        trigger_problem_or_metric: trigger_problem_or_metric.to_owned(),
        validity_scope: validity_scope.to_owned(),
    };
    Ok(eliot_self_quality::sourced_evidence_from_conformance_diagnosis(&finding)?)
}

/// The priority axis this daemon assigns a conformance finding, DERIVED from
/// the Governor owner's own closed decision rather than spelled.
///
/// `ASSUMPTION:` the maintenance `AutomationDecision` names the urgency the
/// owner itself assigned: `Escalate` is documented as "Escalate to a Human or
/// recovery owner" (`eliot-maintenance/src/lib.rs:194`) and `Block` as
/// "Policy, route, budget or session requirements deny execution" (`:192`), so
/// those two map to `Urgent` and `High` and every remaining decision
/// (`Start`, `Suggest`, `Defer`, `SuppressDuplicate`, none of which hands the
/// occurrence to a Human or a recovery owner) maps to `Medium`. I12.24 does
/// not name a priority for conformance evidence, and priority is an independent
/// axis that never substitutes for status or severity
/// (`self_quality.rs:176-177`), so this derives the owner's escalation and
/// claims nothing about severity.
fn conformance_priority(
    decision: &eliot_maintenance::AutomationTriggerDecision,
) -> eliot_self_quality::Priority {
    use eliot_maintenance::AutomationDecision;
    use eliot_self_quality::Priority;
    match decision.decision {
        AutomationDecision::Escalate => Priority::Urgent,
        AutomationDecision::Block => Priority::High,
        _ => Priority::Medium,
    }
}

/// The bound the maintenance (`G-19`) owner decides for this surface, read
/// through the existing maintenance admission path.
///
/// Three reads, in order, and none of them can fall back to a value this
/// module spells:
///
/// 1. the owner's own admission policy record, obtained from the live
///    `G-19` maintenance owner on the Governor composition;
/// 2. the owner's recorded bound for `IMPROVEMENT_SURFACE_NAME`, which must
///    exist (an absent bound is [`ImprovementBoundError::NoBoundForSurface`],
///    never a default);
/// 3. the `CandidateBoundPolicy` this daemon will actually enforce, whose
///    `max_active` and `min_value` are then compared back against the owner's
///    recorded values by [`resolve_candidate_surface_bound`] and whose
///    `governor_authority_ref` is the owner's own `external_owner_id`.
///
/// `policy_revision` is the owner's own bound-set revision
/// ([`eliot_maintenance::IMPROVEMENT_CANDIDATE_BOUNDS_REVISION`]), so rotating
/// the owner's decision also rotates the admission epoch `archive_cause_for`
/// compares against, which is what makes an entry admitted under a superseded
/// bound decision stale and archivable.
///
/// This adds no scheduler, root record, or table (I12.24:314): it is a read of
/// the existing G-19 admission policy record through the existing maintenance
/// owner.
pub fn maintenance_bound(
    policy: &ImprovementAdmissionPolicy,
) -> Result<CandidateBoundPolicy, ImprovementDispatchError> {
    let enforced = CandidateBoundPolicy {
        target_surface: IMPROVEMENT_SURFACE,
        // Read from the owner record, then checked back against it below. These
        // two reads are one value: `resolve_candidate_surface_bound` returns the
        // owner's bound only when the enforced bound equals it field by field,
        // so a mismatch is a refusal rather than a silent correction.
        max_active: usize::try_from(decided_bound(policy).max_active).map_err(|_| {
            ImprovementBoundError::InvalidBound("max_active is out of range for this surface")
        })?,
        min_value: decided_bound(policy).min_value,
        governor_authority_ref: policy.external_owner_id.trim().to_owned(),
        policy_revision: IMPROVEMENT_CANDIDATE_BOUNDS_REVISION,
    };
    let surface = IMPROVEMENT_SURFACE_NAME;
    let decided = resolve_candidate_surface_bound(
        policy,
        surface,
        &ImprovementSurfaceBound {
            target_surface: surface,
            max_active: u32::try_from(enforced.max_active).map_err(|_| {
                ImprovementBoundError::InvalidBound("max_active is out of range for this surface")
            })?,
            min_value: enforced.min_value,
        },
    )?;
    Ok(CandidateBoundPolicy {
        target_surface: IMPROVEMENT_SURFACE,
        max_active: usize::try_from(decided.max_active).map_err(|_| {
            ImprovementBoundError::InvalidBound("max_active is out of range for this surface")
        })?,
        min_value: decided.min_value,
        governor_authority_ref: policy.external_owner_id.trim().to_owned(),
        policy_revision: IMPROVEMENT_CANDIDATE_BOUNDS_REVISION,
    })
}

/// The owner's recorded bound for this surface, or the refusal for having none.
///
/// Split out so `maintenance_bound` reads the owner's decision once and then
/// checks the value it will enforce against it. The `u32 → usize` widening is
/// total on every platform this daemon builds for, and the `try_from` keeps it
/// honest where it is not.
fn decided_bound(policy: &ImprovementAdmissionPolicy) -> ImprovementSurfaceBound {
    policy
        .candidate_bounds
        .iter()
        .copied()
        .find(|bound| bound.target_surface == IMPROVEMENT_SURFACE_NAME)
        .unwrap_or(ImprovementSurfaceBound {
            target_surface: IMPROVEMENT_SURFACE_NAME,
            // An absent bound is a refusal, so this value is never reached
            // with a live policy: it exists only to give `unwrap_or` a
            // well-typed arm, and `max_active: 0` is itself refused by
            // `resolve_candidate_surface_bound`'s shape check, so a policy
            // record that lost its bound entry cannot yield an enforced bound
            // through this path.
            max_active: 0,
            min_value: 0.0,
        })
}

/// The bound-admission operation reference for one real maintenance decision.
///
/// Derived from the decision's own stable identity, so a repeat of the same
/// observation is admitted under the same operation — which is what makes the
/// G-19 policy record for that operation stable across passes, and therefore
/// what makes the bound a decision about a recurring problem rather than about
/// one evaluation. It is a reference, not a scope: the operation the policy
/// binds is the admission operation, while the candidate's own
/// `validity_scope` remains the admitted fence (see [`admitted_fence_ref`]).
pub fn improvement_bound_operation(
    decision: &eliot_maintenance::AutomationTriggerDecision,
) -> String {
    format!(
        "maintenance-improvement-admission:{}:{}",
        decision.family, decision.trigger_id
    )
}

/// The bound-admission idempotency key for one real maintenance decision.
///
/// The key is derived from the decision's own `trigger_id` and `scope_ref` —
/// the same two fields the candidate's evidence lineage is built from — so
/// two identical observations converge on one policy record and one admission
/// rather than minting a fresh pair per pass.
pub fn improvement_bound_idempotency_key(
    decision: &eliot_maintenance::AutomationTriggerDecision,
) -> String {
    format!(
        "maintenance-improvement-admission:{}@{}",
        decision.trigger_id, decision.scope_ref
    )
}

/// Result of the governed improvement admission over one real observation.
#[derive(Clone, Debug)]
pub struct GovernedImprovementAdmission {
    /// Outcome of the bound-enforced admission or lineage merge.
    pub report: AdmitReport,
    /// The bound that was enforced, as read from the owner's decision record.
    /// Carried so the durable record states WHICH bound admitted the candidate.
    pub bound: CandidateBoundPolicy,
    /// The live owner-issued permit the bound was checked against. Its digest
    /// is the owner-issued identity of that admission and travels into the
    /// durable record, so the persisted artifact names the admission it was
    /// admitted under rather than only that some admission happened.
    pub admission_digest: String,
    /// The surviving backlog entry exactly as
    /// [`BoundedBacklog::admit_reporting_pressure`] left it, when this
    /// admission deduplicated by evidence lineage; `None` when the candidate
    /// was admitted as a new active entry.
    ///
    /// This is the merge RESULT, not the merge event. `report.outcome` already
    /// states that a merge happened and names both candidates; this carries
    /// what the merge produced — the unioned evidence and source lineage, the
    /// `merged_from` absorbed-id list, the retained assessed value and owner,
    /// the retained admission authority, and the advanced candidate revision.
    /// Without it the commit path holds only the INCOMING candidate and the
    /// accumulated lineage a merge built is lost when the pass ends
    /// (I12.24:297: "Duplicates merge by evidence lineage").
    ///
    /// It is captured HERE, inside the only place that still holds the
    /// backlog: `BoundedBacklog` owns its entries privately and the commit
    /// function receives no backlog, so this is the one seam from which the
    /// post-merge entry is reachable. `None` is never reachable for a
    /// [`AdmitOutcome::Merged`] outcome — a merge whose surviving entry could
    /// not be read back is refused, not reported as an admission without one.
    pub merged_survivor: Option<TrackedCandidate>,
}

/// Admit one assembled improvement artifact into the bounded backlog through
/// the GOVERNED path (W1 + W3).
///
/// `governor` is the live owner handle, `policy` the maintenance (`G-19`)
/// decision record read from that composition's maintenance owner, and
/// `state_fence` the daemon's own admitted Kernel fence for this pass. The
/// permit is minted HERE, from a claim whose `authority_ref` is the policy's
/// own owner id, so the bound's owner and the permit's owner are the same
/// value by construction and cannot drift apart silently.
///
/// The chain, and what each step proves:
///
/// 1. [`maintenance_bound`] reads the owner's bound and checks the enforced
///    bound back against it (W1: the numbers are the owner's, not a literal).
/// 2. [`issue_learning_admission`] mints the permit under the live Governor's
///    admitting-state, authority-epoch and generation checks.
/// 3. [`verify_learning_admission`] re-binds that permit to the live owner
///    state and to the exact fence this pass observed, producing the
///    [`VerifiedLearningAdmission`] the backlog gates require. A
///    `VerifiedLearningAdmission` is constructible only here, so no caller can
///    present an admission it did not earn.
/// 4. [`BoundedBacklog::admit_reporting_pressure`] runs
///    [`CandidateBoundPolicy::validate_governed`], which compares the bound's
///    `governor_authority_ref` against the verified permit's `authority_ref`
///    (W1: the owner is checked against a live issuance, not against a
///    constant), and then enforces the bound, merging by evidence lineage or
///    relieving a full bound through the explicit summarized archive
///    transition (W3).
/// 5. [`merged_survivor_entry`] reads the surviving entry back out of the
///    backlog on the merge branch. This is the only seam that still holds the
///    backlog, so the post-merge state is carried out on
///    [`GovernedImprovementAdmission::merged_survivor`] rather than recomputed
///    later from a value the commit path does not hold.
///
/// The `ArchivedCandidate` receipts travel back in the returned
/// [`AdmitReport`] for the caller to make durable; nothing is dropped here.
/// This performs no promotion, no activation and no write of its own.
pub fn admit_improvement_artifact(
    governor: &eliot_governor::Governor,
    policy: &ImprovementAdmissionPolicy,
    backlog: &mut BoundedBacklog,
    artifact: &ImprovementArtifact,
    state_fence: &StateFence,
) -> Result<GovernedImprovementAdmission, ImprovementDispatchError> {
    let bound = maintenance_bound(policy)?;
    let claim = improvement_admission_claim(policy, state_fence);
    let permit = issue_learning_admission(governor, &claim)?;
    let verified = verify_learning_admission(governor, &permit, state_fence)?;
    let report = backlog
        .admit_reporting_pressure(
            artifact.candidate.clone(),
            IMPROVEMENT_CANDIDED_VALUE,
            Some(IMPROVEMENT_OWNER.to_owned()),
            &verified,
        )
        .map_err(|error| ImprovementDispatchError::Backlog(error.to_string()))?;
    let merged_survivor = merged_survivor_entry(&report, backlog)?;
    Ok(GovernedImprovementAdmission {
        report,
        bound,
        admission_digest: permit.digest().to_owned(),
        merged_survivor,
    })
}

/// Reads the SURVIVING backlog entry out of the registry on the merge branch
/// (W3, I12.24:297).
///
/// [`AdmitOutcome::Merged`] states that an incoming candidate deduplicated into
/// an existing one and names both ids, but the state the merge BUILT — the
/// unioned `evidence_refs`/`source_trace_refs`, the `merged_from` absorbed-id
/// list, the retained assessed value and owner, the retained admission
/// authority and the advanced candidate revision, all written by
/// [`BoundedBacklog`]'s own merge transition — lives on the entry, and the
/// entry is the only place it exists. So it is read here, while the backlog is
/// still in hand, and travels back on
/// [`GovernedImprovementAdmission::merged_survivor`] for the commit path to
/// make durable.
///
/// `None` means the outcome was [`AdmitOutcome::Admitted`]: nothing merged, so
/// there is no surviving entry to record. The opposite disagreement — a merge
/// whose surviving entry is not retrievable from the registry that just
/// performed it — is a REFUSAL, not a `None`. Returning `None` there would
/// drop the merge result silently and commit only the event, which is exactly
/// the loss this read closes.
fn merged_survivor_entry(
    report: &AdmitReport,
    backlog: &BoundedBacklog,
) -> Result<Option<TrackedCandidate>, ImprovementDispatchError> {
    let AdmitOutcome::Merged {
        surviving_candidate_id,
        absorbed_candidate_id,
    } = &report.outcome
    else {
        return Ok(None);
    };
    let survivor = backlog.entry_for(surviving_candidate_id).ok_or_else(|| {
        ImprovementDispatchError::Backlog(format!(
            "candidate {absorbed_candidate_id} was merged into {surviving_candidate_id}, \
             but the merged entry is not an active entry of the registry that performed the merge"
        ))
    })?;
    Ok(Some(survivor.clone()))
}

/// The closed learning-admission claim this daemon admits its own improvement
/// candidates under.
///
/// Every field is a real value this daemon or its owner holds, and the two
/// that carry authority are the OWNER's: `authority_ref` is the maintenance
/// admission owner's own id, which is what
/// [`CandidateBoundPolicy::validate_governed`] compares the bound's
/// `governor_authority_ref` against, and `scope_ref` is the decision's own
/// scope. `evaluator_ref` and `rollback_ref` name the maintenance evaluation
/// and rollback owners the same policy record declares, so the five revalidated
/// values a cross-task admission re-checks are this campaign's real ones
/// rather than placeholders.
///
/// The claim binds the candidate subject (`candidate_id`) so the resulting
/// permit authorizes at most this exact candidate.
fn improvement_admission_claim(
    policy: &ImprovementAdmissionPolicy,
    state_fence: &StateFence,
) -> LearningAdmissionClaim {
    LearningAdmissionClaim {
        schema_version: eliot_governor::LEARNING_ADMISSION_SCHEMA_VERSION,
        source_campaign_id: IMPROVEMENT_CAMPAIGN.to_owned(),
        target_task_id: format!("maintenance-improvement:{SERVICE_NAME}"),
        fence: state_fence.clone(),
        overlay_id: None,
        candidate_id: None,
        scope_ref: policy.operation_ref.clone(),
        authority_ref: policy.external_owner_id.clone(),
        retention_ref: policy.idempotency_key.clone(),
        evaluator_ref: IMPROVEMENT_EVALUATOR.to_owned(),
        rollback_ref: policy.rollback_owner_id.clone(),
    }
}

/// A revalidation claim for carrying one campaign's admitted learning into a
/// different target task (W5, I12.24:295).
///
/// This is the OWNER's revalidation, expressed as a claim the Governor admits
/// or refuses. It is not proof: the distinctness rule, the live epoch and
/// generation checks, and the per-field comparison of the revalidated values
/// against the minted permit all happen inside
/// [`issue_cross_task_admission`](eliot_governor::LearningAdmissionPermit::issue_cross_task_admission)
/// and
/// [`verify_cross_task_admission`](eliot_governor::LearningAdmissionPermit::verify_cross_task_admission).
#[derive(Clone, Debug)]
pub struct CrossTaskCarryoverRequest {
    /// The distinct target task the learning is being carried to. MUST differ
    /// from the local admission's target task; the Governor refuses otherwise
    /// with `TargetNotForeign`.
    pub target_task_id: String,
    /// Revalidated scope for the target task.
    pub scope_ref: String,
    /// Revalidated decision authority for the target task.
    pub authority_ref: String,
    /// Revalidated retention material for the target task.
    pub retention_ref: String,
    /// Revalidated evaluator for the target task.
    pub evaluator_ref: String,
    /// Revalidated rollback path for the target task.
    pub rollback_ref: String,
}

/// Owner-issued cross-task admission, verified against live owner state.
///
/// `carryover` is the [`CrossTaskCarryover`] a consumer binds to; its fields
/// are private, so this value can exist only because the Governor produced both
/// halves. `record` is the verified record as the Governor verifier returned
/// it, not the presented one.
pub struct VerifiedCrossTaskCarryover<'a> {
    /// The distinct cross-task admission a consumer may bind to.
    pub carryover: CrossTaskCarryover<'a>,
    /// The owner-verified record, exactly as re-verification returned it.
    pub record: &'a CrossTaskAdmissionRecord,
}

/// The distinct, owner-issued cross-task admission the Governor minted.
///
/// Both halves are owner-issued and neither is constructible outside the
/// Governor: `permit` is the SECOND [`LearningAdmissionPermit`] for the foreign
/// target task, and `record` is the owner-issued
/// [`CrossTaskAdmissionRecord`] whose `admission_id` is a canonical digest over
/// both issuance digests. They are returned together so a caller can RETAIN
/// them and later present them to
/// [`verify_cross_task_carryover`], which needs them to outlive this call.
pub struct IssuedCrossTaskAdmission {
    /// The distinct cross-task admission for the foreign target task.
    pub permit: LearningAdmissionPermit,
    /// The owner-issued record binding the local and cross-task admissions.
    pub record: CrossTaskAdmissionRecord,
}

/// Issue one distinct cross-task admission under a live Governor permit (W5).
///
/// This is the issuance half of the production path I12.24:295 names: "Cross-
/// task carryover requires a new governed admission that revalidates scope,
/// authority, retention, evaluator, and rollback." It performs
/// [`issue_cross_task_admission`](eliot_governor::LearningAdmissionPermit::issue_cross_task_admission),
/// which mints the SECOND admission for the foreign target task through the
/// same live owner checks as any other admission — no bypass, no revalidation
/// mode on the owner — and returns the owner-issued record. The revalidation
/// values are a claim, never proof: unusable text, a non-admitting Governor, a
/// stale epoch or generation, a re-spelled subject or campaign, an admission
/// that is not distinct, or a revalidation that names the local task are each
/// refused with their typed [`CrossTaskAdmissionError`] before any permit
/// exists.
///
/// The returned halves are retained by the caller so they can be presented to
/// [`verify_cross_task_carryover`] — the verification half, which re-verifies
/// BOTH permits against live owner state and re-checks the record field by
/// field. Issuance alone authorizes nothing.
///
/// The Governor-owned record is the only cross-task representation used here.
/// The weaker string-typed `eliot_learning_contracts::activation::CrossTaskAdmission`
/// that `candidate_bounds.rs` names as the shape being replaced is not
/// touched, and no second cross-task scheme is introduced.
pub fn issue_cross_task_carryover(
    governor: &eliot_governor::Governor,
    local: &LearningAdmissionPermit,
    revalidation: &CrossTaskCarryoverRequest,
    cross_task_fence: &StateFence,
) -> Result<IssuedCrossTaskAdmission, ImprovementDispatchError> {
    // The claim is the owner's revalidation of the five values plus the same
    // source campaign and the same influence subject, which is what the
    // distinctness rule requires a real carryover to hold.
    let claim = LearningAdmissionClaim {
        schema_version: eliot_governor::LEARNING_ADMISSION_SCHEMA_VERSION,
        source_campaign_id: local.source_campaign_id().to_owned(),
        target_task_id: revalidation.target_task_id.clone(),
        fence: cross_task_fence.clone(),
        overlay_id: local.overlay_id().map(str::to_owned),
        candidate_id: local.candidate_id().map(str::to_owned),
        scope_ref: revalidation.scope_ref.clone(),
        authority_ref: revalidation.authority_ref.clone(),
        retention_ref: revalidation.retention_ref.clone(),
        evaluator_ref: revalidation.evaluator_ref.clone(),
        rollback_ref: revalidation.rollback_ref.clone(),
    };
    let (permit, record) = local.issue_cross_task_admission(governor, &claim)?;
    Ok(IssuedCrossTaskAdmission { permit, record })
}

/// Verify an issued cross-task admission against live owner state and build
/// the [`CrossTaskCarryover`] a consumer binds to (W5).
///
/// This is the verification half, and it is where the five revalidated values
/// are compared as CONTENT against the owner-issued permit rather than shape-
/// checked. It performs:
///
/// 1. [`CrossTaskCarryover::verify`], which re-verifies BOTH permits against
///    live owner state through the same
///    [`verify_learning_admission`] checks — the LOCAL one against
///    `local_fence` (this pass's own fence) and the cross-task one against
///    `cross_task_fence` (the foreign task's) — rebinding each to the live
///    owner epoch/generation, recomputing each digest, and requiring the
///    Governor to be admitting. A rotated epoch or a drifted fence refuses
///    here, before any record is trusted.
/// 2. the record rules against the two already-verified handles: shape,
///    distinctness (a different ticket digest AND a different target task),
///    `admission_id` RECOMPUTED from the two verified issuance digests, the
///    record's two digests equal to the two permits' digests, and the five
///    revalidated values (`scope_ref`, `authority_ref`, `retention_ref`,
///    `evaluator_ref`, `rollback_ref`) equal — FIELD BY FIELD, with the
///    disagreeing field named in `RevalidationMismatch` — to the values the
///    cross-task permit binds.
///
/// That field-by-field step is the guarantee, not a shape check: a well-formed
/// record that re-spells any of the five is refused, and a revalidation that
/// merely copies the local admission is refused structurally
/// (`NotDistinctAdmission`).
///
/// The two handles arrive as `&'a VerifiedLearningAdmission<'a>` because
/// obtaining one already required a prior `verify_learning_admission` against
/// the live Governor; this call re-confirms that against live state and then
/// re-checks the record, so a stale anchor cannot buy a carryover. The
/// returned [`VerifiedCrossTaskCarryover`] holds only Governor-produced values:
/// the `CrossTaskCarryover`'s fields are private, so it can exist only because
/// it was built here from two verified permits and a re-checked record.
pub fn verify_cross_task_carryover<'a>(
    governor: &eliot_governor::Governor,
    local_verified: &'a VerifiedLearningAdmission<'a>,
    cross_task_verified: &'a VerifiedLearningAdmission<'a>,
    issued: &'a IssuedCrossTaskAdmission,
    local_fence: &StateFence,
    cross_task_fence: &StateFence,
) -> Result<VerifiedCrossTaskCarryover<'a>, ImprovementDispatchError> {
    // `CrossTaskCarryover::verify` re-verifies BOTH permits against live owner
    // state internally (each against the fence of its own task) and re-checks
    // the record field by field, so the two `VerifiedLearningAdmission` handles
    // are the anchor the record is checked against. Their existence already
    // required a prior `verify_learning_admission` against the live Governor,
    // and this call re-confirms it — a stale anchor cannot be re-used here.
    let carryover = CrossTaskCarryover::verify(
        governor,
        local_verified,
        cross_task_verified,
        &issued.record,
        local_fence,
        cross_task_fence,
    )?;
    Ok(VerifiedCrossTaskCarryover {
        carryover,
        record: carryover.record(),
    })
}

/// Renders the daemon's own admitted fence as the candidate's stable
/// `validity_scope` reference.
///
/// The improvement candidate's admitted boundary is the real Kernel fence this
/// dispatch observed the maintenance decision under, not a string that only
/// claims to be one: both components the maintenance owner treats as
/// distinct are carried verbatim — the lineage-aware authority epoch (the
/// exact `(lineage_id, sequence)` tuple, per
/// `epoch_identity.rs::EpochId::is_same_authority`) and the monotonic resource
/// generation. A candidate is therefore only ever read back as valid under the
/// same admitted authority and generation that produced it.
fn admitted_fence_ref(state_fence: &StateFence) -> Result<String, ImprovementDispatchError> {
    state_fence
        .validate()
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    Ok(format!(
        "admitted-fence:{}/{}@{}",
        state_fence.authority_epoch.lineage_id.as_str(),
        state_fence.authority_epoch.sequence,
        state_fence.resource_generation.value()
    ))
}

/// Derives the admitted commit ingress for one durable improvement record.
///
/// Mirrors `experience_runtime.rs::derive_commit_ingress`: the request
/// metadata is derived from the daemon's own admitted fence and the
/// idempotency key is the owner-derived record key, so an identical
/// observation replays convergently under the same key. `record_key` names
/// which record this ingress is for, so the candidate's own commit and each
/// archive receipt's commit are distinct, independently idempotent operations
/// rather than one key reused across two different documents.
fn improvement_commit_identity(
    record_key: &str,
    state_fence: &StateFence,
) -> Result<RequestIdentity, ImprovementDispatchError> {
    let now = super::unix_ms_i64();
    let metadata = eliot_contracts::RequestMetadata {
        request_id: eliot_contracts::RequestId::new(format!("{SERVICE_NAME}:{record_key}"))
            .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?,
        session_id: None,
        task_id: None,
        product_id: eliot_contracts::ProductId::new(SERVICE_NAME)
            .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?,
        source_id: eliot_contracts::SourceId::new(SERVICE_NAME)
            .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?,
        state_fence: state_fence.clone(),
        clock: eliot_contracts::ClockReading {
            valid_time_ms: Some(now),
            known_time_ms: Some(now),
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    metadata
        .validate()
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    Ok(RequestIdentity {
        request: RequestBinding {
            metadata,
            state_fence: state_fence.clone(),
        },
        idempotency_key: record_key.to_owned(),
        deadline_unix_ms: super::unix_ms().saturating_add(IMPROVEMENT_COMMIT_DEADLINE_MS),
        cancellation_id: format!("{record_key}:cancel"),
    })
}

/// Commits one assembled improvement artifact durably through the existing
/// Governor/Kernel `RecordLearningRecord` named mutation, together with the
/// governed admission that bounded it and every archive receipt that
/// admission produced.
///
/// The record kind is the closed
/// [`eliot_store_api::LearningRecordKind::Candidate`]; the record document is
/// the canonical JSON of the candidate + brief + owner decision + the bound
/// that admitted it + the owner-issued admission digest, and the presented
/// `record_digest` is that exact canonical bytes, so the digest IS the
/// immutable revision identity. Durability goes exclusively through
/// [`DaemonComposition::commit_learning_record`]; no second write path and no
/// store client is opened here.
///
/// `admitted.bound` and `admitted.admission_digest` travel INTO the record, so
/// the durable artifact names the owner-decided bound it was admitted under and
/// the owner-issued admission that enforced it. Without those two fields a
/// stored record would assert only that some admission happened, which is the
/// W1 guarantee this path exists to make durable.
///
/// `admitted.report.archived` is committed as ONE additional `Candidate`
/// record per receipt, after the candidate's own commit. Each such record
/// carries that receipt's `cause`, evidence-derived `summary`, merged
/// provenance, canonical evidence lineage, archived revision, and the
/// [`ImprovementLifecycle`] the archive transition actually reached — so an
/// archived candidate's disposition is a durable, reviewable fact rather than
/// a process-local receipt that disappears with the backlog (W3; I12.24:291
/// "Silence is not a disposition, because it hides lost learning").
///
/// `admitted.merged_survivor` is committed, between the candidate's own commit
/// and the archive receipts, as ONE additional `Candidate` record whenever the
/// admission deduplicated by evidence lineage. Without it the daemon durably
/// records THAT a merge happened but never WHAT was merged: the record above
/// carries the INCOMING candidate, while the surviving entry — enriched by the
/// merge with the unioned lineage and the absorbed-id list — exists only in the
/// registry, so the next pass rebuilds from the incoming candidate and the
/// unioned lineage is gone. [`commit_lineage_merge_receipt`] states the shape;
/// `improvement_dedup_read::restored_registry` reads it back.
///
/// Receipt commits are sequenced after the candidate commit and are
/// individually idempotent under their own key, so a receipt committed on one
/// pass converges on a later pass instead of duplicating. A refused receipt
/// commit is a typed `Commit` error carrying the archive that could not be made
/// durable, and the receipts committed before it stay committed: this is a
/// partial commit, and it is visible as such rather than hidden.
pub async fn commit_improvement_artifact(
    composition: &mut DaemonComposition,
    artifact: &ImprovementArtifact,
    admitted: &GovernedImprovementAdmission,
    state_fence: &StateFence,
) -> Result<(eliot_store_api::WriteReceipt, bool), ImprovementDispatchError> {
    let record = serde_json::json!({
        "candidate": artifact.candidate,
        "brief": artifact.brief,
        "owner_decision": artifact.decision,
        "enforced_bound": admitted.bound,
        "governed_admission_digest": admitted.admission_digest,
    });
    let record_bytes = canonical_json_bytes(&record)
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    let record_json = String::from_utf8(record_bytes)
        .map_err(|_| ImprovementDispatchError::Contract("record is not utf-8".to_owned()))?;
    let record_digest = eliot_contracts::sha256_hex(record_json.as_bytes());
    let scope_digest = eliot_contracts::sha256_hex(IMPROVEMENT_SCOPE.as_bytes());
    let fence_digest = eliot_contracts::sha256_hex(format!("{state_fence:?}").as_bytes());
    let record_key = format!("improvement-candidate:{}", artifact.candidate.candidate_id);
    let request = learning_record_mutation_request(learning_record_commit_params(
        LearningRecordKind::Candidate,
        record_key.clone(),
        record_json,
        record_digest,
        scope_digest,
        fence_digest,
        record_key.clone(),
    ));
    let identity = improvement_commit_identity(&record_key, state_fence)?;
    let scope = ScopeId::new(IMPROVEMENT_SCOPE)
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    // The durable commit is the whole point of this path: any refusal is a
    // typed diagnostic, never a silent drop.
    let (receipt, effective) = composition
        .commit_learning_record(
            &identity,
            request,
            scope.clone(),
            // Proof refs: the candidate's own evidence lineage, verbatim.
            artifact.candidate.evidence_refs.clone(),
            None,
            false,
            false,
            Vec::new(),
            Vec::new(),
        )
        .await
        .map_err(|error| ImprovementDispatchError::Commit(error.to_string()))?;
    // The merge result, before the archive receipts: the surviving entry is
    // what the NEXT pass rebuilds its registry from, so it is made durable
    // before any relief disposition is.
    match (&admitted.report.outcome, admitted.merged_survivor.as_ref()) {
        (AdmitOutcome::Admitted { .. }, None) => {}
        (
            AdmitOutcome::Merged {
                absorbed_candidate_id,
                ..
            },
            Some(survivor),
        ) => {
            commit_lineage_merge_receipt(
                composition,
                survivor,
                absorbed_candidate_id,
                &scope,
                state_fence,
            )
            .await?;
        }
        (outcome, _) => {
            // `admit_improvement_artifact` refuses to produce this pair, so it
            // is unreachable in practice; committing the candidate and silently
            // skipping a merge result it cannot describe is not an option, so
            // the disagreement is a typed refusal.
            return Err(ImprovementDispatchError::Backlog(format!(
                "the admission outcome {outcome:?} does not agree with the merge state this commit must record"
            )));
        }
    }
    for archived in &admitted.report.archived {
        commit_archive_receipt(composition, archived, &scope, state_fence).await?;
    }
    Ok((receipt, effective))
}

/// Commits the SURVIVING entry of one evidence-lineage merge as a durable
/// learning record (W3, I12.24:297).
///
/// # What this record is for, and what a record without it would be
///
/// The candidate's own record commits the INCOMING candidate. When the
/// admission deduplicated by evidence lineage, the state that makes the
/// deduplication durable is the SURVIVOR: the entry the merge unioned the
/// incoming lineage into, with its absorbed-id bookkeeping, its retained
/// assessed value, owner and admission authority, and its advanced candidate
/// revision. Committing only the event would leave the daemon asserting that a
/// merge happened while the next pass rebuilt its registry from the pre-merge
/// candidate row — so the unioned lineage a merge produced is lost, and the
/// merge is indistinguishable from two independent candidates that merely
/// co-exist. I12.24:297 says "Duplicates merge by evidence lineage", so the
/// lineage a merge accumulated is the merge's own result and it is committed
/// here.
///
/// # The committed document
///
/// `{merged_survivor, absorbed_candidate_id}` where `merged_survivor` is the
/// surviving [`TrackedCandidate`] verbatim. It is committed verbatim rather
/// than projected onto a narrower shape because it IS the registry entry:
/// `ImprovementCandidate`, the unioned `evidence_refs` and
/// `source_trace_refs`, the `merged_from` absorbed-id list, the retained
/// `value`/`owner`/`admitted_under_authority`, the `lineage_digest` the merge
/// recomputed over the union, and the advanced `revision`. A projection would
/// have to restate which of those the merge produced, and every field omitted
/// would be a field a merge could accumulate and lose.
///
/// No extra digest is added: the record's own `lineage_digest` is the digest of
/// the union, and `admitted_under_authority` is the Governor authority the
/// merge was admitted under. The owner-issued admission digest for the same
/// admission is already durable on the candidate's own record.
///
/// `Candidate` is the same closed kind the candidate and the archive receipts
/// use and no new kind is added. The handle and idempotency key are derived
/// from the surviving entry's OWN identity — its candidate id plus the revision
/// the merge advanced it to — so re-observing the same merge converges on one
/// record instead of appending a duplicate, and a later merge of the same
/// surviving candidate is a distinct, additional record rather than an
/// overwrite of the earlier accumulated state.
///
/// A refused commit is a typed `Commit` error naming the surviving candidate
/// and the one it absorbed, and the candidate's own commit stays committed:
/// this is the same partial-commit behaviour the archive receipts already
/// document, not a rollback.
async fn commit_lineage_merge_receipt(
    composition: &mut DaemonComposition,
    survivor: &TrackedCandidate,
    absorbed_candidate_id: &str,
    scope: &ScopeId,
    state_fence: &StateFence,
) -> Result<eliot_store_api::WriteReceipt, ImprovementDispatchError> {
    let record = serde_json::json!({
        "merged_survivor": survivor,
        "absorbed_candidate_id": absorbed_candidate_id,
    });
    let record_bytes = canonical_json_bytes(&record)
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    let record_json = String::from_utf8(record_bytes)
        .map_err(|_| ImprovementDispatchError::Contract("record is not utf-8".to_owned()))?;
    let record_digest = eliot_contracts::sha256_hex(record_json.as_bytes());
    let scope_digest = eliot_contracts::sha256_hex(IMPROVEMENT_SCOPE.as_bytes());
    let fence_digest = eliot_contracts::sha256_hex(format!("{state_fence:?}").as_bytes());
    let record_key = lineage_merge_record_key(survivor);
    let request = learning_record_mutation_request(learning_record_commit_params(
        LearningRecordKind::Candidate,
        record_key.clone(),
        record_json,
        record_digest,
        scope_digest,
        fence_digest,
        record_key.clone(),
    ));
    let identity = improvement_commit_identity(&record_key, state_fence)?;
    // Proof refs: the SURVIVING entry's own evidence refs, which are the union
    // the merge produced, so the receipt cites the accumulated lineage rather
    // than the incoming candidate's.
    let (receipt, _effective) = composition
        .commit_learning_record(
            &identity,
            request,
            scope.clone(),
            survivor.candidate.evidence_refs.clone(),
            None,
            false,
            false,
            Vec::new(),
            Vec::new(),
        )
        .await
        .map_err(|error| {
            ImprovementDispatchError::Commit(format!(
                "the merge of {} into surviving candidate {} at revision {} could not be made durable: {error}",
                absorbed_candidate_id, survivor.candidate.candidate_id, survivor.candidate.revision
            ))
        })?;
    Ok(receipt)
}

/// The closed store handle and idempotency key of one lineage-merge receipt.
///
/// Derived from the surviving entry's own `candidate_id` and the
/// `candidate.revision` the merge advanced it to, both of which the merge
/// transition produced, so the key is a function of the merge rather than of
/// the pass that observed it. An identical replay of the same merge converges
/// on one record instead of appending a duplicate accumulated state.
fn lineage_merge_record_key(survivor: &TrackedCandidate) -> String {
    format!(
        "improvement-merge:{}@{}",
        survivor.candidate.candidate_id, survivor.candidate.revision
    )
}

/// Commits one [`ArchivedCandidate`] receipt as a durable learning record.
///
/// `Candidate` is the closed kind that fits and no new kind is added: this is
/// a record about a candidate, and the closed set already covers candidates
/// with the same "recording never performs promotion" property. The handle and
/// idempotency key are the receipt's OWN identity — candidate id plus the
/// archived revision the transition produced — so the same archive of the same
/// candidate converges under one key across passes and a candidate archived
/// again at a later revision is a distinct, additional receipt rather than an
/// overwrite of the earlier disposition.
async fn commit_archive_receipt(
    composition: &mut DaemonComposition,
    archived: &ArchivedCandidate,
    scope: &ScopeId,
    state_fence: &StateFence,
) -> Result<eliot_store_api::WriteReceipt, ImprovementDispatchError> {
    let record = serde_json::json!({
        "archived_candidate": archived,
        "disposition": archived.archived_lifecycle,
    });
    let record_bytes = canonical_json_bytes(&record)
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    let record_json = String::from_utf8(record_bytes)
        .map_err(|_| ImprovementDispatchError::Contract("record is not utf-8".to_owned()))?;
    let record_digest = eliot_contracts::sha256_hex(record_json.as_bytes());
    let scope_digest = eliot_contracts::sha256_hex(IMPROVEMENT_SCOPE.as_bytes());
    let fence_digest = eliot_contracts::sha256_hex(format!("{state_fence:?}").as_bytes());
    let record_key = archive_record_key(archived);
    let request = learning_record_mutation_request(learning_record_commit_params(
        LearningRecordKind::Candidate,
        record_key.clone(),
        record_json,
        record_digest,
        scope_digest,
        fence_digest,
        record_key.clone(),
    ));
    let identity = improvement_commit_identity(&record_key, state_fence)?;
    // Proof refs: the archived candidate's own canonical evidence lineage, so
    // the receipt cites exactly the evidence whose retention review produced
    // it.
    let (receipt, _effective) = composition
        .commit_learning_record(
            &identity,
            request,
            scope.clone(),
            archived.evidence_lineage.clone(),
            None,
            false,
            false,
            Vec::new(),
            Vec::new(),
        )
        .await
        .map_err(|error| {
            ImprovementDispatchError::Commit(format!(
                "archived candidate {} at revision {} could not be made durable: {error}",
                archived.candidate_id, archived.archived_revision
            ))
        })?;
    Ok(receipt)
}

/// The closed store handle and idempotency key of one archive receipt.
///
/// Derived from the receipt's own `candidate_id` and `archived_revision`, both
/// of which the archive transition produced, so the key is a function of the
/// transition rather than of the pass that observed it. An identical replay of
/// the same transition therefore converges on one record instead of appending a
/// duplicate disposition.
fn archive_record_key(archived: &ArchivedCandidate) -> String {
    format!(
        "improvement-archive:{}@{}",
        archived.candidate_id, archived.archived_revision
    )
}
