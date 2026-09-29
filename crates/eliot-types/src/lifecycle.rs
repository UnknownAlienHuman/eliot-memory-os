//! Lifecycle, forgetting, admission and ecology contracts.
//!
//! #708 FROZEN FIELD INVENTORY (issue-wide, nine-file domain)
//!
//! This is the W1 freeze for the whole #708 domain, anchored here because
//! `lifecycle.rs` is one of the nine in-scope owner files. Every row is a
//! *directly or effectively defaulted* field: the direct `#[serde(default)]`
//! form, the helper form `default = "fn"`, the `default + skip_serializing_if`
//! pair, the container/`Option`-with-default form, and the `flatten` /
//! `alias` / `untagged` trial-accept forms. Historic default counts are not the
//! denominator; these rows are.
//!
//! Columns: `file::type.field` | wire name | form | boundary | semantic class |
//! Rust default | absence valid? | empty valid? | decision.
//!
//! ## CORRECTED in this increment (compatible requiredness correction)
//!
//! Emitted bytes unchanged in every case: `Serialize` was not touched anywhere
//! and no `skip_serializing_if` was added or removed. Absent key is now the
//! existing typed error owner, `serde::de::Error::missing_field`, which names
//! the exact field; no new error schema was manufactured.
//!
//! - `cognition.rs::MaterialPacketFrame.{invariant_refs, waived_invariants,
//!   prediction_confidence, predicted_changed_paths, predicted_failing_verifiers}`
//!   | same | direct | `eliot.packet` PUBLISHED schema -> `tools/list` |
//!   packet prediction/invariant block | `[]`/`None` | yes (today) | yes |
//!   **RETAINED as a breaking candidate, NOT corrected.** This type derives
//!   `JsonSchema` and `mcp_contract.rs::compile_packet_input_schema` (`:150`)
//!   serializes `schemars::schema_for!(CompilePacketToolInput)`, so the
//!   published `required` set is *generated from* these `serde` attributes:
//!   removing `default` adds five names to it and changes `tools/list` for every
//!   connected agent. Two in-tree facts confirm the required set does not
//!   already contain them and that the correction would break this crate's own
//!   owner: `crates/eliot-types/tests/ul_contract_schema.rs::t01_schema_required_set_is_exact`
//!   pins the exact `material_frame` required set as 16 names excluding these
//!   five, and `mcp_contract.rs::compile_packet_minimal_example` (`:155`) — the
//!   `minimal_valid_example` returned to agents on invalid tool input
//!   (`crates/eliot-app/src/mcp_stdio/input_validation.rs:28`, `:43`;
//!   `crates/eliot-app/src/mcp_stdio/task_handlers.rs:206`) — omits all five and
//!   must keep decoding (`ul_contract_schema.rs:95`). Required owner is
//!   `crates/surfaces/eliot-mcp` (`src/schema.rs::descriptor`) plus the
//!   `eliot.packet` catalogue bump; base SHA in the #708 report. An earlier
//!   attempt at this increment asserted the opposite (that the published
//!   required set already contained these five) and was reverted against this
//!   evidence.
//! - `cognition.rs::CausalCandidate.{assigned_check, intervention_outcomes}` |
//!   same | direct | internal record | verifier-binding / outcome history |
//!   `None`/`[]` | no | yes (explicit empty) | REQUIRED. `None` is a state
//!   `validate_for_critical_action` and `validate_intervention_history` branch
//!   on, so absence must be stated, not defaulted.
//! - `cognition.rs::TaskCognitionView.{experience_priors, negative_memory,
//!   procedural_skills}` | same | direct | operator pipe projection |
//!   prior-failure/negative-memory/skill section | `[]`/`default()` | no | yes |
//!   REQUIRED. Sole producer `eliot-app/src/mcp_stdio/operator.rs::dispatch_operator_snapshot`.
//! - `cognition.rs::MemoryInspectorView.{lifecycle, experience_cases,
//!   experience_patterns, applicability_decisions, negative_transfer,
//!   cognitive_lab_results, failure_localization}` | same | direct | operator
//!   pipe projection | store-completeness claims | `default()`/`[]` | no | yes |
//!   REQUIRED. Same sole producer; a defaulted read claims a *completeness*
//!   about canonical memory the projection never made.
//! - `cognition.rs::AgentRoutingView.{host_sessions, task_role_leases,
//!   controller_leases, operation_jobs, agent_results, agent_result_dispositions,
//!   work_items, work_leases, worktree_leases, work_conflicts}` | same | direct
//!   | operator pipe projection | authority / lease / write scope | `[]` | no |
//!   yes | REQUIRED. The A0.3 direction: a defaulted read must not present
//!   "no live worktree lease" or "no controller lease".
//! - `cognition.rs::AutonomyRunView.{route_decision_refs, recovery_event_refs,
//!   model_invocations_used, tool_calls_used, wall_time_used_seconds,
//!   cost_or_tokens_used, pause_resume_reassignment_refs, completion_proof}` |
//!   same | direct | operator pipe projection | budget denominators, cost
//!   authority, ordering, proof | `0`/`None`/`[]` | no | yes | REQUIRED.
//!   `0` is a measured-zero claim about consumption never recorded.
//! - `cognition.rs::OperatorSnapshot.{project_refs, backup_inventory, incidents,
//!   log_handles}` | same | direct | operator pipe projection | scope /
//!   recovery visibility / incident evidence | `[]` | no | yes | REQUIRED.
//! - `memory.rs::TaskAcceptanceItem.verification_scope_hash` | same | direct |
//!   canonical | acceptance-to-verifier-scope binding | `None` | no | yes (null)
//!   | REQUIRED. Producers `eliot-app/src/mcp_stdio/runtime_handlers.rs::acceptance_item`
//!   and `protocol_tests.rs` write it explicitly.
//! - `memory.rs::ActionSourceScope.artifact_paths` | same | direct | canonical
//!   | resource scope of the provenance set | `[]` | no | yes (explicit
//!   no-artifact scope) | REQUIRED. Producers
//!   `eliot-app/src/mcp_stdio/runtime_handlers.rs::action_source_scope` (:941,
//!   :966) and `memory_grant.rs` (:477).
//! - `memory.rs::TaskContractInput.{action_provenance, verification_scopes,
//!   completion_proof}` and `memory.rs::TaskContract.{action_provenance,
//!   verification_scopes, completion_proof}` | same | direct | canonical task
//!   record | provenance / verifier scope / proof | `None`/`[]` | no | yes |
//!   REQUIRED.
//! - `memory.rs::VerificationRun.{claim_id, project_id, task_id, write_id,
//!   memory_revision, verifier}` | same | direct | canonical, read back by
//!   `eliot-store/src/canonical_store.rs::verification_run_by_id` (:4012) |
//!   evidence subject + scope + verifier identity | `None`/`""` | no | yes
//!   (null) | REQUIRED. `verifier: ""` next to `result: Passed` is a
//!   VERIFIED_COMPLETE-shaped claim with no verifier. **This is the one
//!   breaking consumer candidate inside the nine files** and it is recorded
//!   rather than softened: a `VerificationRun` row already persisted by an
//!   older writer that never carried these six keys will now fail to decode at
//!   `verification_run_by_id`. That is the intended W2/W4 direction — previously
//!   buggy permissiveness is not promised compatibility, and no alias,
//!   `untagged` or default helper re-accepts it — but it is a data-migration
//!   question, not a code question. The write-side sibling
//!   `VerificationRunInput` (`:798`) has the identical shape with no `default`
//!   at all, so every current writer already states all six; the affected
//!   population is historical rows only. Required owner for the backfill: the
//!   `eliot-store` writer that persists `NamedSurqlOp::VerificationRunById`
//!   rows; base SHA in the #708 report. This lane is product code only and did
//!   not run a migration.
//! - `memory.rs::RecallL0Request.{lifecycle_audit, task_class_cues, scope_refs,
//!   concept_refs}` (`task_id` keeps its paired `skip_serializing_if`) | same |
//!   direct | retrieval request | retention/erasure scope + retrieval scope |
//!   `false`/`[]` | no | yes | REQUIRED. `lifecycle_audit: false` silently
//!   narrowed recall to live memory — a retention-relevant scope reduction by
//!   omission. Sole request shape of `CanonicalStore::recall_l0`; every
//!   construction site already writes all seven fields.
//! - `memory.rs::UnderstandingProof.{code_task, codecortex_report_refs,
//!   files_to_change, files_to_inspect, causal_bridge_from_goal_to_code,
//!   blast_radius_acknowledged, skill_refs, skill_application_rationales,
//!   skill_anti_scope_acknowledgements, skill_required_inputs,
//!   skill_verifier_plan_refs}` | same | direct | agent-facing input +
//!   `protocol_support.rs::understanding_proof_schema` | gate inputs, write set,
//!   skill grounding, blast-radius acknowledgement | `false`/`[]`/`""` | no |
//!   yes | REQUIRED. Producer `eliot-app/src/action_plan.rs` (:288-310) writes
//!   the full literal. Compatibility note: unlike `MaterialPacketFrame` this
//!   type does NOT derive `JsonSchema`, and the published proof schema is a
//!   hand-written `json_schema` list
//!   (`crates/eliot-app/src/mcp_stdio/protocol_support.rs::understanding_proof_schema`,
//!   :115-147) whose `required` array already names the fields that are already
//!   non-optional here. Because the published `required` set is authored
//!   separately and is not generated from these `serde` attributes, removing
//!   `default` here does not move the published schema. (The authored `required`
//!   list is itself only a partial subset — it omits `code_task`,
//!   `codecortex_report_refs`, `files_to_change`, `files_to_inspect`,
//!   `causal_bridge_from_goal_to_code` and `blast_radius_acknowledged` — so the
//!   published schema advertises a laxer shape than the decoder now enforces.
//!   That divergence is a pre-existing inconsistency in the schema author, not
//!   introduced here, and its owner is `protocol_support.rs`; recorded as an
//!   open item in the #708 report.)
//! - `memory.rs::UnderstandingProofReceipt.{code_task, codecortex_report_refs,
//!   files_to_change, files_to_inspect}` | same | direct | gate receipt | the
//!   decision's own stated inputs | `false`/`[]` | no | yes | REQUIRED.
//!   Producer `eliot-engine/src/context.rs` (:2183).
//!
//! ## RETAINED as legitimate internal defaults, with caller evidence
//!
//! Each row is field-specific and is invalidated by a source or caller change.
//! None is a package-wide or file-wide exemption.
//!
//! - `memory.rs::TaskContractInput.memory_grant_redemptions` and
//!   `memory.rs::TaskContract.memory_grant_redemptions` | same | direct +
//!   `skip_serializing_if = "Vec::is_empty"` | canonical | memory-grant
//!   consumption | `[]` | yes | yes | RETAINED. The paired
//!   `skip_serializing_if` means this type's own wire declares "no opaque offer
//!   was consumed" by omitting the key, so absent and explicitly-empty are one
//!   declared fact. Removing `default` would make the type unable to read back
//!   its own bytes — a canonical byte change, not a requiredness correction.
//! - `memory.rs::RecallL0Request.task_id` | `task_id` | direct +
//!   `skip_serializing_if = "Option::is_none"` | retrieval request | task
//!   narrowing | `None` | yes | n/a | RETAINED, same paired-disposition
//!   reason.
//! - `mcp_contract.rs::AgentCandidateSubmitInput.{where_applicable,
//!   where_not_applicable, negative_constraints, cue_bindings, auto_bind,
//!   curation}` | same | direct | published legacy candidate-submit wire
//!   (`agent_candidate_input_schema`) | statement boundaries / capture-first
//!   optionality / enrichment requests | `[]`/`None` | yes | yes | RETAINED.
//!   `cue_bindings` is pinned OUT of the published `required` set by
//!   `agent_candidate_input_schema` (:262-289) and asserted by
//!   `crates/eliot-types/tests/ul_cue_normalize.rs::t03_candidate_schema_roundtrip`;
//!   the other five cannot create a grant, scope, effect or receipt by omission.
//! - `mcp_contract.rs::AgentCandidateCurationInput.*` (24 fields) | same |
//!   direct | curation payload inside the above | relations, safety
//!   judgements, tri-state judgements, evidence vectors, advisory metadata |
//!   `None`/`false`/`[]` | yes | yes | RETAINED per field. Retained `false`
//!   on `protected` / `unsafe_instruction` is fail-closed (omission grants no
//!   protection and suppresses no safety flag); the tri-state judgements
//!   (`scope_match`, `evidence_sufficient`, `reopen_condition_met`) keep
//!   `Option`, which is exactly the W3-required absent / present-empty / value
//!   representation.
//! - `mcp_contract.rs::ObserveInput.hint` (with `alias = "kind"`),
//!   `mcp_contract.rs::ObserveInput.task_id`,
//!   `mcp_contract.rs::ObserveInput.affected_resources`,
//!   `mcp_contract.rs::ObserveInput.source_handles`,
//!   `mcp_contract.rs::ObserveInput.expected_reuse_note`,
//!   `mcp_contract.rs::ObserveInput.write_id`,
//!   `mcp_contract.rs::ObserveInput.schema_version` (helper
//!   `default_observe_schema_version`) | same | direct, `alias`, and helper |
//!   published `eliot.observe` tool schema ->
//!   `tools/list` `schema_sha256` | agent capture input, task selector,
//!   explicit no-authority sets, wire version | `ObserveHint::Auto` / `None` /
//!   `[]` / current version | yes | yes | RETAINED, but `hint`'s `alias` and
//!   `schema_version`'s helper are recorded W4 DEFECTS, not tolerances — see
//!   the two field-level comments in `mcp_contract.rs` and the BLOCKED-BY rows
//!   in the #708 report. `affected_resources` / `source_handles` are explicit
//!   no-authority sets whose empty value is a real answer.
//! - `lifecycle.rs::ForgettingPolicy.{effective_at, expires_at, approval_ref}` |
//!   same | direct (`with = "time::serde::rfc3339::option"` for the two
//!   timestamps) | lifecycle policy | optional effectiveness/approval data |
//!   `None` | yes | n/a | RETAINED. Every identity, reason, operator, scope and
//!   admission-effect field on this record is already required; `decision` on
//!   `MemoryVitalityScore`/`MemoryGravity` is likewise already required so a
//!   missing field cannot decode into `KeepHot` admission.
//! - `lifecycle.rs::MemoryVitalityScore.{beneficial_use_count,
//!   prevented_failure_count, correct_verifier_selection_count,
//!   negative_transfer_count, contradiction_count, context_cost_tokens,
//!   maintenance_cost_units, minority_importance_millis, freshness_millis,
//!   scope_fit_millis, utility_millis, harm_millis}` and
//!   `lifecycle.rs::MemoryGravity.activation_pressure_millis` | same | direct |
//!   lifecycle report | benefit/cost counters and fixed-point scores | `0` | yes
//!   | yes | RETAINED. Direction is monotone understating: a defaulted counter
//!   can only reduce measured benefit or increase apparent cost, never
//!   manufacture either. Producers
//!   `eliot-engine/src/memory_lifecycle.rs::score`/`gravity` (:629, :703) and
//!   `eliot-engine/src/memory_distillation.rs::score` (:420).
//! - `lifecycle.rs::MemoryStateTransition.{reactivation_condition, approval_ref,
//!   write_receipt}` | same | direct (`write_receipt` also
//!   `skip_serializing_if = "Option::is_none"`) | lifecycle transition |
//!   optional reactivation/approval/receipt | `None` | yes | n/a | RETAINED.
//!   `write_receipt` keeps the paired form: absence is exactly "this lifecycle
//!   write has not been receipted", and the paired `skip_serializing_if` is the
//!   owner's declared representation of that fact. Producers
//!   `eliot-engine/src/memory_lifecycle.rs` (:104, :150).
//! - `eval.rs::EvalSuite.frozen_at`, `eval.rs::EvalRun.finished_at` | same |
//!   direct (`with = "time::serde::rfc3339::option"`) | eval record | optional
//!   timestamps | `None` | yes | n/a | RETAINED. An unfrozen suite and an
//!   unfinished run are both coherent states.
//! - `eval.rs::EvalIntegrityFingerprintSet.{oracle_version, product_identity}`,
//!   `eval.rs::EvalCaseResult.integrity_fingerprints`,
//!   `eval.rs::EvalBaseline.integrity_fingerprints` | same | direct | eval
//!   evidence | evaluator-identity freshness | `""`/`None` | yes | n/a |
//!   RETAINED and *fail-closed by construction*: `""` never equals a real
//!   version or product identity, so `is_stale_against` reports stale rather
//!   than fresh, and `None` is documented as unknown, never as a freshness
//!   claim. `EvalBaseline`'s own comment records the named additive boundary
//!   (I5.22) that admits pre-retention baselines.
//! - `cognitive_field.rs::CognitiveFieldProviderPlan.{role_evidence_plan_hash,
//!   seal_attempt_id, authority_activation_ref, runtime_manifest_sha256,
//!   artifact_manifest_sha256}` | same | direct + `skip_serializing_if` |
//!   `plan_hash`-sealed published plan | meta/seal/authority-activation data |
//!   `None` | yes | n/a | RETAINED as a BLOCKED-BY digest-seal constraint, not a
//!   tolerance. `plan_hash` is this record's own seal
//!   (`crates/eliot-app/src/cognitive_field_runner.rs::validate_provider_plan_hash`
//!   recomputes it as blake3 over `serde_json::to_vec` of the struct with only
//!   `plan_hash` cleared, :8355), so changing which keys are emitted changes the
//!   bytes the seal covers and invalidates every published `provider-plan.json`;
//!   removing `default` also breaks all eight read sites including quarantine.
//!   Required owner is that `plan_hash` owner, outside this issue's file scope.
//! - `antigravity.rs::AntigravityRealReport.visibility` | `visibility` |
//!   direct, paired with `skip_serializing_if` | provider report projection |
//!   optional disclosure layer | `None` | yes | n/a | RETAINED. Absent key
//!   and explicit `null` carry the same fact here (no visibility report was
//!   produced), so the three-way distinction is not lost; it lives inside
//!   `AntigravityVisibilityReport`.
//! - `memory.rs` and `cognition.rs` `canonical_receipt` / `write_receipt` /
//!   `preview` / `result_payload` / `corpus_profile` / `managed_root` /
//!   `lifecycle_state` / `lifecycle_badge` / `continuation` / `projection_revision`
//!   `Option` fields carrying `default + skip_serializing_if = "Option::is_none"`
//!   | same | direct + `skip_serializing_if` | varied | optional receipt,
//!   projection, pagination or lifecycle-badge bindings | `None` | yes | n/a |
//!   RETAINED. In every one of these the paired `skip_serializing_if` is the
//!   owner's declared statement that "this optional binding was not produced",
//!   and the type's own serialization omits the key in exactly that case, so
//!   absent and explicit-null are one fact on this wire and a receipt's absence
//!   never authenticates canonical storage (the per-field comment says so).
//!
//! ## Effective defaults that are NOT serde attributes (W1 helper/container forms)
//!
//! Complete by-construction scan of the nine files, so the denominator is the
//! rows above plus this section and not a historic `serde(default)` count:
//!
//! - **Helper form `default = "fn"` — all 3 live sites in the domain, frozen
//!   individually.** `cognition.rs:1191` `OperatorQueryRequest.expand_depth`
//!   (`default_operator_graph_depth` -> `1`); `memory.rs:2006`
//!   `CompilePacketL3Request.max_tokens`
//!   (`default_context_packet_preferred_tokens` -> `DEFAULT_CONTEXT_PACKET_PREFERRED_TOKENS`
//!   = 1800); `mcp_contract.rs:472` `ObserveInput.schema_version`
//!   (`default_observe_schema_version`). `expand_depth` is the one of the three
//!   that is a *scope* field: it is decoded by
//!   `crates/eliot-app/src/mcp_stdio/operator.rs:736`
//!   (`serde_json::from_value::<OperatorQueryRequest>`) directly from agent
//!   arguments, and an omitted key silently became depth 1, so a caller that
//!   asked for a graph slice could not distinguish "one level" from "did not ask".
//!   It is RETAINED here, not because the default is right but because
//!   `OperatorQueryRequest` is a *caller parameter bag* whose other five
//!   defaulted members (`filter`, `query_operation`, `query_parameters`,
//!   `result_mode`, `selected_ref`) are all agent-optional by design and whose
//!   `page_size`/`cursor` siblings are already required — making only
//!   `expand_depth` required would break the agent request shape for a
//!   pagination depth, and the whole bag is re-authored by
//!   `crates/eliot-app/src/mcp_stdio/operator.rs::dispatch_operator_query`.
//!   Required owner: the `eliot.operator_query` tool contract
//!   (`crates/eliot-app/src/mcp_stdio/operator.rs`), outside this issue's file
//!   scope. `max_tokens` is RETAINED: the published `eliot.packet` schema pins
//!   it OUT of `required` and asserts its published `default` value
//!   (`crates/eliot-types/tests/ul_contract_schema.rs::t02_packet_budget_is_an_optional_preferred_target`,
//!   which reads `budget_schema["default"]` and the `caller-preferred` /
//!   `hard ceiling` description, and `:93-99` decodes the minimal example and
//!   asserts the default applies). `schema_version` is the W4 defect already
//!   recorded above.
//! - **Container / `Option`-with-default form.** The paired
//!   `default + skip_serializing_if` rows listed above are this form; each is
//!   field-specific and named. No container-level `#[serde(default)]` (a
//!   `#[serde(default)]` on the container attribute rather than a field) exists
//!   in any of the nine files.
//! - **Untagged form: NONE.** Verified by source scan across all nine files:
//!   the only textual matches for `untagged` are the word inside this comment
//!   and doc prose. There is no `#[serde(untagged)]` in the domain, so there is
//!   no untagged trial-accept form to freeze and no untagged-enum legacy path
//!   to close. (This corrects the previous increment's blanket claim, which was
//!   written as a guess rather than a scan result.)
//! - `memory.rs::FetchAtomsL2Response.*`, `memory.rs::RecallL0Response.*`,
//!   `memory.rs::ContextPacketL3.*`, `memory.rs::CodeCortexPacketView.*`,
//!   `memory.rs::MemoryApplicabilityPacketView.*`, `memory.rs::` skill and
//!   completion records, `cognition.rs::` packet/view records: these carry a
//!   large block of direct defaults that are *packet-assembly* sections rather
//!   than authority-bearing fields. `ContextPacketL3` in particular is written by
//!   one builder (`eliot-engine/src/context.rs:1795`, a full literal) and is
//!   re-read from disk by `eliot-app/src/mcp_stdio/task_handlers.rs::latest_task_packet`
//!   (:3047) and by the active-packet authority response (:1230, :1473). Its
//!   defaults are left in place in this increment: they are packet *content*
//!   sections, the empty value is a real answer for each, and correcting them
//!   requires a durability/compat decision on already-written packet files that
//!   this issue's remaining budget cannot make honestly. Carried as an open
//!   item in the #708 report, not as a completion claim.
//! - `mcp_contract.rs::CompilePacketToolInput`: the one `flatten` in the
//!   nine-file domain. It has a hand-written `Deserialize`
//!   (`CompilePacketToolInputVisitor`) that already rejects duplicate keys while
//!   reading the raw map and rejects unknown keys before typed output, and it
//!   defaults `material_frame` / `memory_mode` to `None` as genuinely optional
//!   enrichment. The `default`s are consistent with the visitor; the visitor is
//!   the actual decoder and it does not reintroduce any default. No change.
//! - `delegation.rs` and `provider_invocation.rs` have zero remaining
//!   `serde(default)` occurrences; their requiredness decisions are recorded in
//!   the field-level doc comments already present on those types.
//! - `antigravity.rs` and `eval.rs` have no unaccounted sites: their only
//!   remaining `serde(default)` rows are the retained ones named above.
//!
//! ## Proof ceiling of this freeze
//!
//! Source-attested and caller-evidenced only. This lane is product code only: no
//! `#[test]` was added, no new file under `tests/` was created, and **no cargo
//! command was run at all** — not build, check, clippy, fmt, clean or test. The
//! manager owns fmt + clippy and supplies the exact errors. Every "REQUIRED"
//! row above has a named in-tree producer that was read and confirmed to write
//! the key explicitly, including the `None` / empty / `false` cases. Every
//! "RETAINED" row is a field-specific exemption with its caller evidence, not a
//! type- or file-wide one, and the schemars-`required` interaction that
//! disqualified the `MaterialPacketFrame` row was checked by reading
//! `compile_packet_input_schema` and the two tests that pin that wire. The
//! runtime proof that a missing key now actually fails is filed as the T1-T20
//! test matrix, status TEST-PHASE, in the #708 CHECKLIST.

use crate::{EpistemicStatus, ProjectId, TaskId, WriteReceiptRef};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryLifecycleState {
    #[default]
    Active,
    Dormant,
    Suppressed,
    Archived,
    Quarantined,
    Forgotten,
    Restored,
    HardDeleted,
    // Legacy states remain readable while new transitions use the normalized
    // lifecycle above.
    Demoted,
    Superseded,
    CompressedInto,
    Poisoned,
    RetainedForAudit,
    ReactivationCandidate,
    Stale,
}

/// Decoder: derived and closed. The kept `#[serde(default)]` fields are optional
/// effectiveness/approval data that decode as absent; every identity, reason,
/// operator, scope and admission-effect field stays required.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForgettingPolicy {
    pub policy_id: String,
    pub project_id: ProjectId,
    pub target_ref: String,
    pub reason: ForgettingReason,
    pub operator: ForgettingOperator,
    pub evidence_refs: Vec<String>,
    pub rollback_or_tombstone_ref: Option<String>,
    pub reactivation_condition: Option<ReactivationCondition>,
    pub expected_current_state: MemoryLifecycleState,
    pub observed_epistemic_status: EpistemicStatus,
    pub scope: Vec<String>,
    pub precondition_refs: Vec<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub effective_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub expected_admission_effect: MemoryEcologyDecision,
    pub reversible: bool,
    pub requires_admin_approval: bool,
    #[serde(default)]
    pub approval_ref: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgettingReason {
    Stale,
    Superseded,
    LowUtility,
    Poisoned,
    Privacy,
    Duplicate,
    WrongScope,
    NegativeTransfer,
    FalseActivation,
    ContextBloat,
    VerifierContradicted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgettingOperator {
    Compress,
    Demote,
    Suppress,
    Supersede,
    Archive,
    Forget,
    Restore,
    Purge,
    // Legacy operators remain readable during schema migration.
    MarkPoisoned,
    RetainAuditOnly,
}

impl ForgettingOperator {
    pub const fn all_l10() -> &'static [Self] {
        &[
            Self::Compress,
            Self::Demote,
            Self::Suppress,
            Self::Supersede,
            Self::Archive,
            Self::Forget,
            Self::Restore,
            Self::Purge,
        ]
    }

    pub const fn all_i0() -> &'static [Self] {
        &[
            Self::Suppress,
            Self::Demote,
            Self::Supersede,
            Self::Archive,
            Self::Compress,
            Self::MarkPoisoned,
            Self::RetainAuditOnly,
        ]
    }
}

pub type RevisionOperator = ForgettingOperator;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryEcologyDecision {
    #[default]
    KeepHot,
    KeepHandleOnly,
    Demote,
    Suppress,
    SplitPattern,
    RequireRevalidation,
    Archive,
    Quarantine,
    ForgetCandidate,
    PurgeRequiresAdmin,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactivationCondition {
    pub condition_id: String,
    pub description: String,
    pub required_evidence_refs: Vec<String>,
    pub required_current_truth_change: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionDeltaRecord {
    pub decision_ref: String,
    pub changed_outcome: bool,
    pub utility_delta: f64,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
}

/// Decoder: derived and closed. `decision` stays required on the wire: a missing
/// field must not decode into `KeepHot` admission. The zero `#[serde(default)]`
/// counters keep historical records readable and can only understate observed
/// benefit, never fabricate it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryVitalityScore {
    pub memory_ref: String,
    pub project_id: ProjectId,
    pub reuse_count: u64,
    pub decision_delta_history: Vec<DecisionDeltaRecord>,
    pub verification_success_count: u64,
    pub verification_failure_count: u64,
    pub stale_hits: u64,
    pub false_activation_count: u64,
    #[serde(default)]
    pub beneficial_use_count: u64,
    #[serde(default)]
    pub prevented_failure_count: u64,
    #[serde(default)]
    pub correct_verifier_selection_count: u64,
    #[serde(default)]
    pub negative_transfer_count: u64,
    #[serde(default)]
    pub contradiction_count: u64,
    #[serde(default)]
    pub context_cost_tokens: u64,
    #[serde(default)]
    pub maintenance_cost_units: u64,
    #[serde(default)]
    pub minority_importance_millis: i64,
    #[serde(default)]
    pub freshness_millis: i64,
    #[serde(default)]
    pub scope_fit_millis: i64,
    #[serde(default)]
    pub utility_millis: i64,
    #[serde(default)]
    pub harm_millis: i64,
    pub decision: MemoryEcologyDecision,
    // Compatibility projections for older lifecycle reports. Current decisions use the fixed
    // point fields above.
    pub recency_score: f64,
    pub scope_fit_score: f64,
    pub utility_score: f64,
    pub harm_score: f64,
    #[serde(with = "time::serde::rfc3339")]
    pub computed_at: OffsetDateTime,
}

/// Decoder: derived and closed. `decision` stays required on the wire: a missing
/// field must not decode into `KeepHot` admission. The zero
/// `activation_pressure_millis` default keeps older records readable and can
/// only understate pressure, never fabricate it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryGravity {
    pub memory_ref: String,
    #[serde(default)]
    pub activation_pressure_millis: i64,
    pub decision: MemoryEcologyDecision,
    // Compatibility projection for I0 reports.
    pub activation_pressure: f64,
    pub why_it_keeps_appearing: Vec<String>,
    pub harm_or_utility: String,
    pub suppression_needed: bool,
    pub evidence_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub computed_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryStateTransition {
    pub transition_id: String,
    pub project_id: ProjectId,
    pub target_ref: String,
    pub from_state: MemoryLifecycleState,
    pub to_state: MemoryLifecycleState,
    pub operator: ForgettingOperator,
    pub reason: ForgettingReason,
    pub policy_ref: String,
    pub evidence_refs: Vec<String>,
    pub precondition_refs: Vec<String>,
    pub expected_admission_effect: MemoryEcologyDecision,
    #[serde(default)]
    pub reactivation_condition: Option<ReactivationCondition>,
    pub reversible: bool,
    #[serde(default)]
    pub approval_ref: Option<String>,
    pub performed_by: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupersessionReceipt {
    pub supersession_id: String,
    pub project_id: ProjectId,
    pub old_ref: String,
    pub new_ref: String,
    pub reason: String,
    pub evidence_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressionReceipt {
    pub suppression_id: String,
    pub project_id: ProjectId,
    pub target_ref: String,
    pub reason: ForgettingReason,
    pub scope: Vec<String>,
    pub reactivation_condition: Option<ReactivationCondition>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemotionReceipt {
    pub demotion_id: String,
    pub project_id: ProjectId,
    pub target_ref: String,
    pub old_status: String,
    pub new_status: String,
    pub reason: ForgettingReason,
    pub evidence_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveReceipt {
    pub archive_id: String,
    pub project_id: ProjectId,
    pub target_ref: String,
    pub reason: ForgettingReason,
    pub retained_for_audit: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Decoder: derived and closed. `status` and `pinned` are contract-required
/// protection state and must be present on the wire.
///
/// `pinned` was `#[serde(default = "default_true")]`, so an omitted key decoded
/// as `true` — and `pinned: true` is the *strongest* minority protection
/// `MinorityLifecycleService::minority_is_pinned` recognises (it additionally
/// requires `status == Open`, no `resolved_by_ref` and an unexpired
/// `suppression_forbidden_until`). A default of `true` therefore manufactured
/// protection from an absent field, which is the reverse of the ordinary
/// default-direction concern: it is the one default here that would have let a
/// truncated record claim a guard it never recorded. `status` defaulted to
/// `Open`, pairing with it to produce a fully-protected record from two absent
/// keys. Both are now required; omission fails with the derived typed
/// missing-field error (the existing owner, same pattern as the merged
/// #722/#3155 and #708/#3437 increments).
///
/// Compatibility: this record is persisted through `eliot-store`'s canonical
/// projection (`canonical_projection_views.rs`,
/// `minority_pressure: Vec<CanonicalRecord<MinorityPressureRecord>>`). The one
/// current producer, `mcp_stdio/operator.rs:3595`, sets `status: Open` and
/// `pinned: true` explicitly, and `Serialize` is untouched, so accepted and
/// emitted bytes are unchanged. The previously documented "older records"
/// tolerance is withdrawn: no named/versioned legacy decoder exists for this
/// record and none may be invented (W4), so such a record now fails loudly.
///
/// `release_condition`, `resolved_by_ref` and `write_receipt` keep explicit
/// `Option` presence: an absent key, an explicit `null` and a value stay three
/// distinguishable states, and none of them can resolve pressure or admit
/// suppression. `write_receipt` in particular also keeps
/// `skip_serializing_if`, because the store stamps it back after
/// serialization and the canonical bytes on disk omit the key when it is
/// `None`; dropping `default` there would make a store-written record
/// unreadable by its own type (the round-trip trap).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinorityPressureRecord {
    pub minority_record_id: String,
    pub project_id: ProjectId,
    pub minority_claim_ref: String,
    pub majority_claim_ref: Option<String>,
    pub why_minority_matters: String,
    pub discriminative_probe: Option<String>,
    pub status: MinorityPressureStatus,
    pub pinned: bool,
    pub release_condition: Option<String>,
    pub resolved_by_ref: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub suppression_forbidden_until: Option<OffsetDateTime>,
    pub evidence_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MinorityPressureStatus {
    #[default]
    Open,
    Resolved,
    Expired,
    AcceptedRisk,
}

pub type MemoryAuditSuspension = MinorityPressureRecord;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryTrajectoryCorrectness {
    pub trajectory_id: String,
    pub target_ref: String,
    pub transition_refs: Vec<String>,
    pub expected_admission_effect: MemoryEcologyDecision,
    pub observed_admission_effect: MemoryEcologyDecision,
    pub correct: bool,
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityMemoryIndex {
    pub index_id: String,
    pub project_id: ProjectId,
    pub host_id: String,
    pub task_family: String,
    pub capability: String,
    pub attempts: u64,
    pub verified_successes: u64,
    pub verified_failures: u64,
    pub negative_transfers: u64,
    pub median_latency_ms: u64,
    pub evidence_refs: Vec<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_verified_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryInfluenceReport {
    pub report_id: String,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub packet_id: Option<String>,
    pub included_refs: Vec<String>,
    pub suppressed_refs: Vec<String>,
    pub demoted_refs: Vec<String>,
    pub superseded_refs: Vec<String>,
    pub archived_refs: Vec<String>,
    pub minority_preserved_refs: Vec<String>,
    pub missing_context_regret_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<MemoryInfluenceOutcome>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryInfluenceOutcome {
    pub changed_action_or_tool: String,
    pub verifier: String,
    pub avoided_path: String,
    pub downstream_outcome: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryLifecycleDecision {
    Allow,
    RequireEvidence,
    RequireSupersedingRecord,
    ProtectMinorityEvidence,
    DenyPurgeInI0,
    DenyTruthMutation,
    DenyUnsafeSuppression,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryLifecyclePacketView {
    pub suppressed_refs: Vec<String>,
    pub demoted_refs: Vec<String>,
    pub superseded_refs: Vec<String>,
    pub archived_refs: Vec<String>,
    pub minority_preserved_refs: Vec<String>,
    pub lifecycle_warnings: Vec<String>,
}

impl Default for MemoryLifecyclePacketView {
    fn default() -> Self {
        Self {
            suppressed_refs: Vec::new(),
            demoted_refs: Vec::new(),
            superseded_refs: Vec::new(),
            archived_refs: Vec::new(),
            minority_preserved_refs: Vec::new(),
            lifecycle_warnings: vec!["memory lifecycle policy active".to_owned()],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryLifecycleStatusReport {
    pub component: String,
    pub project_id: ProjectId,
    pub target_ref: String,
    pub state: MemoryLifecycleState,
    pub related_receipts: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryLifecycleProposalReport {
    pub component: String,
    pub policy: ForgettingPolicy,
    pub decision: MemoryLifecycleDecision,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryLifecycleApplyReport {
    pub component: String,
    pub decision: MemoryLifecycleDecision,
    pub transition: Option<MemoryStateTransition>,
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryLifecycleReport {
    pub component: String,
    pub statuses: Vec<MemoryLifecycleStatusReport>,
    pub proposals: Vec<MemoryLifecycleProposalReport>,
    pub influence: Option<MemoryInfluenceReport>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryPressureReport {
    pub duplicate_pressure: String,
    pub stale_activation_pressure: String,
    pub skill_distractor_pressure: String,
    pub open_lifecycle_proposals: usize,
    pub suppressed_recent_regret: usize,
}
