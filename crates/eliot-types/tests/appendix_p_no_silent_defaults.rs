#![allow(clippy::expect_used)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use eliot_types::cognition::CausalCandidate;
use eliot_types::memory::{
    DEFAULT_CONTEXT_PACKET_PREFERRED_TOKENS, MemoryApplicabilityPacketView, MemoryProvenanceView,
};
use eliot_types::{
    ActionSourceScope, AgentCandidateCurationInput, AgentCandidateSubmitInput, AgentRoutingView,
    AntigravityRun, AntigravityRunState, AntigravitySafetyReceipt, AutonomyRunContract,
    AutonomyRunView, COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION, CognitiveFieldProviderCallPlan,
    CognitiveFieldProviderEvidenceReceipt, CognitiveFieldProviderPlan,
    CognitiveFieldProviderProjection, CompilePacketL3Request, CompilePacketToolInput,
    DelegationRequest, EvalCaseResult, EvalIntegrityFingerprintSet, EvalRun, EvalSuite,
    ForgettingOperator, ForgettingPolicy, MaterialPacketFrame, MemoryEcologyDecision,
    MemoryGravity, MemoryHandlePreview, MemoryInspectorView, MemoryLifecycleState,
    MemoryStateTransition, MemoryVitalityScore, MetaIsolationRejectionRecord,
    MetaPolicyExecutionReceipt, OBSERVE_INPUT_SCHEMA_VERSION, ObserveHint, ObserveInput,
    OperatorCommandReceipt, OperatorQueryRequest, OperatorResultMode, OperatorSnapshot,
    ProviderCallBudgetState, ProviderCallLedger, ProviderCallReservation,
    ProviderCallReservationState, ProviderInvocationAttempt, RecallL0Request, StrictJsonErrorKind,
    TaskAcceptanceItem, TaskCognitionView, TaskContract, TaskContractInput, UnderstandingProof,
    UnderstandingProofReceipt, VerificationRun, WorkLease, WorktreeLease, WorktreeLeaseState,
    strict_json_value,
};
// The names case 18 reaches through a construction path rather than a decode.
// Every one of them is a type or function that publishes `Default`, or a
// constructor/helper that states a key the decoder would otherwise refuse to
// receive, in the nine frozen production files.
use eliot_types::{
    AntigravityCapabilities, AntigravityResponseProtocolReceipt, AuthorityPermission,
    AuthorityProfile, BlackboardScope, COGNITIVE_JUDGE_SCHEMA_VERSION,
    COGNITIVE_UNDERSTANDING_SCHEMA_VERSION, CodeCortexScopeBinding, CognitiveJudgeResult,
    CognitiveProjectionReadState, CognitiveUnderstandingAnswer, DecisionLocalitySuffix,
    DelegationState, EpistemicPacketState, L0CollapsedDuplicateTrace, L0FeatureScore, L0RankTrace,
    L0SuppressionTrace, MemoryConfidence, MemoryCurationCorpusProfile, MemoryLifecyclePacketView,
    MetaCandidateChangeClass, MetaExperimentDecision, MinorityPressureStatus,
    NegativeMemoryGateInput, OPERATOR_CONTRACT_MANIFEST, OPERATOR_SCHEMA_VERSION,
    OperatorProjectionFilter, RecallConflictObservation, WorktreeLeaseKind,
    minimal_cognitive_judge_result, minimal_cognitive_understanding_answer,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn without(mut value: Value, field: &str) -> Value {
    value
        .as_object_mut()
        .expect("fixture must be an object")
        .remove(field);
    value
}
fn rejects_missing<T: DeserializeOwned + std::fmt::Debug>(value: Value, field: &str) {
    assert!(
        serde_json::from_value::<T>(without(value, field)).is_err(),
        "missing {field} must be rejected"
    );
}
fn work_lease_wire() -> Value {
    json!({
        "work_lease_id": "00000000-0000-7000-8000-000000000001",
        "work_item_id": "00000000-0000-7000-8000-000000000002",
        "agent_session_id": "00000000-0000-7000-8000-000000000003",
        "agent_id": "00000000-0000-7000-8000-000000000004",
        "project_id": "00000000-0000-7000-8000-000000000005",
        "task_id": "00000000-0000-7000-8000-000000000006",
        "role": "implementer",
        "state": "granted",
        "epoch": 0,
        "scope": {
            "repo_root": "C:/repo",
            "read_set": [],
            "write_set": ["crates/eliot-types/src/memory.rs"],
            "verifier_set": ["cargo test"],
            "authority": {"permissions": ["read", "write"]},
            "risk_tier": "low",
            "max_files": 1,
            "requires_active_work_lease": true
        },
        "decision": {
            "kind": "granted",
            "reason": "no_conflict",
            "message": "accepted",
            "work_lease_id": null,
            "conflicting_lease_ids": [],
            "expires_at": null
        },
        "conflict_refs": [],
        "granted_at": "2026-09-07T12:00:00Z",
        "expires_at": "2026-09-07T12:00:01Z",
        "renewed_at": null,
        "released_at": null,
        "revoked_at": null,
        "write_receipt": null
    })
}
fn provider_call_plan_wire() -> Value {
    json!({
        "call_number": 1,
        "call_id": "call-1",
        "role": "codex_worker",
        "host": "codex",
        "requested_model": "gpt-test",
        "expected_provider_executable_sha256": "exec-sha",
        "prompt_ref": "prompt-1",
        "prompt_sha256": "prompt-sha",
        "canonical_schema_sha256": "schema-sha",
        "provider_schema_sha256": "provider-schema-sha",
        "provider_smoke": true,
        "counts_against_cap": true,
        "executions": [],
        "runtime_contract_ref": "runtime-contract-1",
        "runtime_contract_sha256": "runtime-sha",
        "adapter_id": "adapter-1",
        "adapter_version": "1",
        "execution_request_ref": "request-1",
        "execution_request_sha256": "request-sha"
    })
}
fn safety_receipt_wire() -> Value {
    json!({
        "typed_argv": ["agy", "--json"],
        "prompt_hash_blake3": "prompt-sha",
        "shell_false": true,
        "stdin_devnull": true,
        "process_group_kill_on_timeout": true,
        "timeout_ms": 1000,
        "max_output_bytes": 1024,
        "effective_cwd": "C:/repo",
        "env_fixed_vars": [],
        "env_dropped_names": [],
        "model_observation": null
    })
}
// ---------------------------------------------------------------------
// #708 case 1..20 support.
//
// The 20 numbered cases below drive real `serde_json` decodes against the
// nine-file boundary types.
//
// Scanner scope, stated accurately: the case-15/16 oracle IS a package-local
// source scan, because the card requires one (`cards/708.md`). It re-acquires
// the nine production files the shipped inventory already reads, and re-derives
// from source the field-level `default`/bypass facts that
// `scripts/serde_boundary_inventory.py` also derives. What it reuses rather
// than re-derives is the shipped CLASSIFICATION VOCABULARY: the oracle reads
// that script at run time and asserts against its own `DISPOSITIONS` set for
// equality, and probes its protected dimensions, bypass shapes and
// unsupported-syntax markers by name. `DISPOSITIONS` equality is the load-
// bearing coupling; the string probes are weaker than they look. The
// UNSUPPORTED-SYNTAX HANDLING itself is the script's by transcription rather
// than by probe: `mask_rust` fails closed on the same six conditions the
// script's `_mask_rust` raises on, `discovered_unsupported_macros` applies both
// of the script's macro patterns with its `unknown`/`BLOCKED`/`NOT_SAFE` grade,
// and `manual_decoder_impls` matches `_MANUAL_IMPL_RE` rather than the literal
// `Deserialize<'de>`. Each of those transcriptions is behavioural, so the
// `unresolved == 0` assertion is no longer the only behavioural half: the
// unsupported-macro denominator fails closed at zero and each site it finds is
// held to the script's own grade, which case 15 reads out of `_classify` at run
// time. So: one scanner, in this file, not a second shipped inventory.
//
// Oracle ownership (I18-27:3, "every acceptance oracle has an owner and
// origin"). Nothing here creates authority by assertion; each constant below
// states where its authority comes from:
//   - `EXPECTED_DEFAULT_SITE_COUNT`, the paired/helper/manual/bypass counts
//     and `DEFAULT_SITE_EXCEPTIONS`: derived by the scan below from the nine
//     production files, and cross-checked against the frozen field inventory in
//     `crates/eliot-types/src/lifecycle.rs` (its per-file zero counts, its
//     three helper-form sites, its untagged-NONE and single-flatten findings),
//     with the disposition vocabulary owned by
//     `scripts/serde_boundary_inventory.py:93`.
//   - `EXPECTED_BARE_OPTION_SITE_COUNT` and its line list: derived by the same
//     scan from the serde rule that a missing `Option<T>` decodes to `None`
//     (`serde::private::de::missing_field`), with no other authority.
//   - `EXPECTED_UNSUPPORTED_MACRO_SITE_COUNT`: zero, with the same authority as
//     the script's refusal to classify unsupported syntax at all. It is a
//     separate class from `DEFAULT_SITE_EXCEPTIONS`, because a macro site names
//     no field and case 16 admits no `unknown` disposition there.
//   - `EXPECTED_SPECIFIC_OWNER_ROWS` / `EXPECTED_OWNER_FILES` /
//     `BREAKING_CANDIDATE_OWNER_MAP`: owner for each deferred breaking
//     candidate is the named file; the base-object column records `n/a`
//     because no resolvable object identity exists for those rows.
//   - the case-20 completeness cross-check: `crates/eliot-types/src/lifecycle.rs`
//     frozen inventory, as pinned by case 16.
// ---------------------------------------------------------------------

/// The nine-file domain this issue owns, in the order the frozen field
/// inventory names them.
const NINE_FILES: &[&str] = &[
    "cognition.rs",
    "memory.rs",
    "delegation.rs",
    "lifecycle.rs",
    "eval.rs",
    "mcp_contract.rs",
    "provider_invocation.rs",
    "antigravity.rs",
    "cognitive_field.rs",
];

/// The frozen field-level `serde(default)` denominator in the nine-file
/// domain. Cases 15 and 16 both fail closed against this number, so a new
/// default site cannot enter without a field-exact exception row and a removed
/// one cannot leave a stale row behind.
const EXPECTED_DEFAULT_SITE_COUNT: usize = 176;

/// The frozen `absent-becomes-none` denominator: the named members of a `struct`
/// item in the nine-file domain whose declared type is a bare `Option<...>`
/// carrying neither `#[serde(default)]` nor `#[serde(deserialize_with = ...)]`
/// (directly or through `with = "..."`). Case 15 fails closed against this
/// number and against the `file:line` list below it, so a member that gains or
/// loses the shape cannot move without being enumerated here.
///
/// Scope is stated so the number is checkable: every named member of every
/// `struct` item in the nine files, which is the same scope
/// `discovered_default_sites` reads for the default class. Seven of the 264 are
/// non-`pub` members of two `pub struct`s that do not derive `Deserialize`
/// (`ProviderDeclaredBudget`, `ProviderTimeoutProfile`); they are kept because
/// the class is a statement about the declaration, not about a published wire.
const EXPECTED_BARE_OPTION_SITE_COUNT: usize = 264;

/// The frozen `file:line` list behind `EXPECTED_BARE_OPTION_SITE_COUNT`, in
/// `NINE_FILES` order. A site that moves, appears or disappears changes this
/// list, so the oracle fails closed on drift rather than only on a size change.
/// `mcp_contract.rs` and `cognitive_field.rs` are listed empty on purpose: every
/// `Option` member in those two files carries a serde token, so a new bare one
/// fails the comparison.
#[rustfmt::skip]
const EXPECTED_BARE_OPTION_SITE_LINES: [(&str, &[usize]); 9] = [
    ("cognition.rs", &[
        112, 343, 344, 367, 671, 821, 831, 832, 838, 842, 863, 910, 939, 954, 969, 1001, 1003, 1145, 1148, 1149, 1170, 1176, 1177, 1192, 1248, 1249, 1250, 1251, 1252, 1253, 1254, 1261, 1262, 1265, 1316, 1317, 1338, 1340, 1353, 1354, 1355, 1356, 1357, 1378, 1465, 1466, 1567, 1569, 1571, 1587,
    ]),
    ("memory.rs", &[
        237, 238, 261, 262, 263, 264, 455, 456, 457, 501, 510, 511, 530, 531, 544, 556, 558, 608, 619, 756, 758, 761, 762, 825, 900, 903, 904, 908, 909, 928, 954, 1227, 1247, 1249, 1397, 1769, 1857, 1858, 2082, 2083, 2084, 2085, 2187, 2442, 2443, 2444, 2459, 2467, 2485, 2571, 2621, 2622, 2626, 2627, 2628, 2629, 2648, 2650, 2651, 2654, 2763, 2779, 2800, 2801, 2802, 2814, 2824, 2825, 2911, 2912, 2919, 2920, 3015, 3024, 3075, 3107, 3137, 3140, 3162, 3163, 3169, 3170, 3184, 3186, 3251, 3277, 3289, 3312, 3313, 3367, 3368, 3374, 3380, 3442, 3476, 3497, 3508, 3519, 3537, 3550, 3551, 3552, 3553, 3581,
    ]),
    ("delegation.rs", &[
        31, 112, 115, 116, 117, 134, 179, 180, 181, 182, 184, 235, 289, 291,
    ]),
    ("lifecycle.rs", &[
        391, 392, 493, 626, 696, 698, 701, 702, 763, 764, 851, 852, 861,
    ]),
    ("eval.rs", &[
        35, 65, 141, 455, 458, 474, 478, 479, 611, 649, 812,
    ]),
    ("mcp_contract.rs", &[]),
    ("provider_invocation.rs", &[
        115, 162, 165, 166, 167, 168, 169, 188, 189, 190, 191, 192, 211, 212, 226, 227, 228,
        465, 466, 467, 468, 536, 552, 553, 554, 574, 585, 588,
    ]),
    ("antigravity.rs", &[
        11, 49, 53, 63, 67, 76, 93, 104, 105, 109, 131, 265, 293, 294, 317, 323, 335, 356, 442,
        444, 446, 447, 509, 510, 613, 630, 631, 655, 656, 660, 767, 769, 770, 771, 779, 795,
        798, 868, 869, 886, 887, 888, 915, 916,
    ]),
    ("cognitive_field.rs", &[]),
];

/// The three effectively-defaulted sites that use `default = "<helper>"` rather
/// than `default`, detected by shape.
const EXPECTED_HELPER_DEFAULT_SITES: [&str; 3] = [
    "cognition.rs::OperatorQueryRequest.expand_depth",
    "memory.rs::CompilePacketL3Request.max_tokens",
    "mcp_contract.rs::ObserveInput.schema_version",
];

/// The paired `default, skip_serializing_if = "..."` rows, detected by shape.
const EXPECTED_PAIRED_DEFAULT_SITE_COUNT: usize = 44;

/// The frozen `unsupported-macro` denominator in the nine-file domain: zero. A
/// serde-like macro here generates deserialization neither this oracle nor the
/// shipped inventory can read, which is why the inventory grades such a site
/// `unknown` and blocks it rather than classifying it. Case 15 fails closed on
/// the first one, the same way it fails closed on a new default site: the
/// denominator only moves with a deliberate decision, never by drift.
const EXPECTED_UNSUPPORTED_MACRO_SITE_COUNT: usize = 0;

/// The classification vocabulary owned by `scripts/serde_boundary_inventory.py`.
/// Case 15 asserts this equals the script's own `DISPOSITIONS`.
const FROZEN_DISPOSITIONS: [&str; 6] = [
    "current-closed",
    "named-legacy",
    "exact-internal",
    "specific-owner",
    "needs-repair",
    "unknown",
];

/// The one field-exact exception set whose removal needs a named owner outside
/// this issue's file scope. Case 16 asserts it cannot broaden.
const EXPECTED_SPECIFIC_OWNER_ROWS: [&str; 16] = [
    "cognition.rs::MaterialPacketFrame.invariant_refs",
    "cognition.rs::MaterialPacketFrame.predicted_changed_paths",
    "cognition.rs::MaterialPacketFrame.predicted_failing_verifiers",
    "cognition.rs::MaterialPacketFrame.prediction_confidence",
    "cognition.rs::MaterialPacketFrame.waived_invariants",
    "cognition.rs::OperatorQueryRequest.expand_depth",
    "cognitive_field.rs::CognitiveFieldProviderPlan.artifact_manifest_sha256",
    "cognitive_field.rs::CognitiveFieldProviderPlan.authority_activation_ref",
    "cognitive_field.rs::CognitiveFieldProviderPlan.role_evidence_plan_hash",
    "cognitive_field.rs::CognitiveFieldProviderPlan.runtime_manifest_sha256",
    "cognitive_field.rs::CognitiveFieldProviderPlan.seal_attempt_id",
    "mcp_contract.rs::AgentCandidateSubmitInput.cue_bindings",
    "mcp_contract.rs::CompilePacketToolInput.material_frame",
    "mcp_contract.rs::CompilePacketToolInput.memory_mode",
    "mcp_contract.rs::ObserveInput.schema_version",
    "memory.rs::CompilePacketL3Request.max_tokens",
];

/// The owner files the deferred decisions belong to. Sorted, and equal to the
/// deduplicated owner column of `BREAKING_CANDIDATE_OWNER_MAP`; case 20 asserts
/// that equality, so a new owner cannot appear without being listed here.
const EXPECTED_OWNER_FILES: [&str; 6] = [
    "crates/eliot-app/src/cognitive_field_runner.rs",
    "crates/eliot-app/src/mcp_stdio/catalog.rs",
    "crates/eliot-app/src/mcp_stdio/operator.rs",
    "crates/eliot-app/src/mcp_stdio/protocol_support.rs",
    "crates/eliot-store/src/canonical_store.rs",
    "crates/surfaces/eliot-mcp/src/schema.rs",
];

/// The case-20 owner map: every breaking candidate the requiredness work
/// deferred, the published base object it was measured against, the decision
/// that blocks it, and the file that owns that decision.
///
/// Every base column reads `n/a`. No published base object identity for these
/// candidates is resolvable in this repository - `git cat-file -e <id>^{commit}`
/// fails for each one in a full, non-shallow clone - so recording an object id
/// here would be an unverifiable claim that reads as authoritative. `n/a` is the
/// honest value, the map's own case-20 assertion accepts it explicitly, and the
/// blocking decision plus the owning file carry the contract the map exists to
/// record. A real base id must be supplied by the owner who can resolve it.
const BREAKING_CANDIDATE_OWNER_MAP: &[(&str, &str, &str, &str)] = &[
    (
        "MaterialPacketFrame.{invariant_refs,waived_invariants,prediction_confidence,predicted_changed_paths,predicted_failing_verifiers}",
        "n/a",
        "the published eliot.packet schema's generated required set; no base object is recorded for this row",
        "crates/surfaces/eliot-mcp/src/schema.rs",
    ),
    (
        "CompilePacketToolInput.{material_frame,memory_mode}",
        "n/a",
        "NOT a deferred breaking candidate: the frozen inventory (lifecycle.rs:324-330) records these two defaults as consistent with the hand-written CompilePacketToolInputVisitor and says \"No change\", because that visitor is the actual decoder and does not reintroduce any default. The published eliot.packet schema's required set is the surface that would observe any change; the frozen record declines the deferral.",
        "crates/surfaces/eliot-mcp/src/schema.rs",
    ),
    (
        "RecallL0Request.task_id",
        "n/a",
        "NOT a breaking-candidate deferral: the frozen inventory retains this paired row on its own paired-disposition reasoning and does not call it a breaking candidate - only the MaterialPacketFrame row uses that wording (lifecycle.rs:27). The eliot_recall_l0 catalogue holds the published required set that would observe a change.",
        "crates/eliot-app/src/mcp_stdio/catalog.rs",
    ),
    (
        "OperatorQueryRequest.expand_depth",
        "n/a",
        "the eliot.operator_query tool contract named by the frozen inventory (lifecycle.rs:289-292), whose 1..=3 range check at operator.rs:743 is the evidence this row cites; the catalogue holds only the tool name string",
        "crates/eliot-app/src/mcp_stdio/operator.rs",
    ),
    (
        "CompilePacketL3Request.max_tokens",
        "n/a",
        "the published eliot.packet schema's pinned-out-of-required default, whose evidence is the schema projection itself and ul_contract_schema.rs::t02_packet_budget_is_an_optional_preferred_target; the frozen inventory names no file, and the previous owner cited here held no occurrence of this key",
        "crates/surfaces/eliot-mcp/src/schema.rs",
    ),
    (
        "ObserveInput.schema_version",
        "n/a",
        "the published eliot.observe schema's versioned registry migration",
        "crates/surfaces/eliot-mcp/src/schema.rs",
    ),
    (
        "ObserveInput.hint (W3 protected-field defect, incl. the retained `kind` alias)",
        "n/a",
        "the eliot.observe catalogue boundary and the #706/#831 Cue-kind alias owner",
        "crates/eliot-app/src/mcp_stdio/protocol_support.rs",
    ),
    (
        "VerificationRun historical rows",
        "n/a",
        "the eliot.verifier catalogue and the store owner's historical-row policy",
        "crates/eliot-store/src/canonical_store.rs",
    ),
    (
        "AgentCandidateSubmitInput.cue_bindings",
        "n/a",
        "the eliot.remember candidate-capture catalogue's published required set",
        "crates/eliot-app/src/mcp_stdio/catalog.rs",
    ),
    (
        "published eliot.observe / eliot.packet wire shapes (contract.rs types, not the nine-file types)",
        "n/a",
        "surfaces/eliot-mcp declares its own ObserveInput as a kind-tagged enum (contract.rs:330) and its own two-field PacketInput (contract.rs:212); neither is the nine-file ObserveInput struct this oracle scans, and PacketInput.material_refs carries a serde(default) outside the nine-file denominator. Both surfaces are READ ONLY for this card, so the divergence is deferred to their owner.",
        "crates/surfaces/eliot-mcp/src/schema.rs",
    ),
    (
        "CognitiveFieldProviderPlan.{role_evidence_plan_hash,seal_attempt_id,authority_activation_ref,runtime_manifest_sha256,artifact_manifest_sha256}",
        "n/a",
        "the plan_hash owner's blake3 digest over the emitted keys: removing a skip_serializing_if changes the sealed bytes",
        "crates/eliot-app/src/cognitive_field_runner.rs",
    ),
];

/// The thirteen members this delivery changed to a required-nullable shape, one
/// row each: the `file::Type.member` key, the `file:line` that declares it in
/// the current production source, and a SHORT justification that says either
/// why the member is NOT a breaking candidate or which owner owns it.
///
/// This is the row set the deferred owner map does NOT pin. Only the five
/// `VerificationRun` members have a map row, and that row names no field, so the
/// other eight could not fail the case-20 completeness check even if nobody had
/// classified them: both sides of that check are hand-maintained constants in
/// this file, which is what makes an unclassified breaking candidate
/// structurally invisible to it.
///
/// Every justification below was checked against the producer it names. Where
/// no producer exists, the row says so instead of claiming compatibility that
/// was not verified: `CausalCandidate` has no in-tree construction surface at
/// all, and no in-tree Rust source writes a stored `VerificationRun`. Case 20
/// asserts that each row carries a justification, that the stated `file:line`
/// really declares that member with the required-nullable decoder, and that
/// every repository path a justification names exists on disk with the same
/// `is_file()` check the map rows use.
const CHANGED_REQUIRED_NULLABLE_MEMBERS: &[(&str, &str, &str)] = &[
    (
        "cognition.rs::CausalCandidate.assigned_check",
        "cognition.rs:387",
        "NOT a breaking candidate: CausalCandidate has no in-tree struct literal, no constructor and no producer at all - searching every crate source finds only its own declaration and its own impl - and it publishes no JsonSchema, so no accepted byte set changes.",
    ),
    (
        "cognition.rs::AutonomyRunView.cost_or_tokens_used",
        "cognition.rs:1118",
        "NOT a breaking candidate: the one in-tree producer, crates/eliot-app/src/mcp_stdio/autonomy.rs::autonomy_run_projection, builds the whole view at :246 and states this key as Some(...) at :281, so every current projection already carries it.",
    ),
    (
        "cognition.rs::AutonomyRunView.completion_proof",
        "cognition.rs:1121",
        "NOT a breaking candidate: the same producer states this key explicitly at crates/eliot-app/src/mcp_stdio/autonomy.rs:286, cloning the recorded graph proof rather than leaving it unset.",
    ),
    (
        "memory.rs::TaskAcceptanceItem.verification_scope_hash",
        "memory.rs:253",
        "NOT a breaking candidate: every in-tree TaskAcceptanceItem literal states the key, including crates/eliot-app/src/mcp_stdio/runtime_handlers.rs:428 and the eliot-engine test fixtures, and the struct is deny_unknown_fields with no published schema.",
    ),
    (
        "memory.rs::TaskContractInput.action_provenance",
        "memory.rs:493",
        "NOT a breaking candidate: the in-tree write-side producers state it explicitly, at crates/eliot-app/src/mcp_stdio/runtime_handlers.rs:453 and crates/eliot-app/src/mcp_stdio/task.rs:1265, as None or as the resolved provenance set.",
    ),
    (
        "memory.rs::TaskContractInput.completion_proof",
        "memory.rs:500",
        "NOT a breaking candidate: the same producers state it explicitly, at crates/eliot-app/src/mcp_stdio/runtime_handlers.rs:458 and crates/eliot-app/src/mcp_stdio/task.rs:1270.",
    ),
    (
        "memory.rs::TaskContract.action_provenance",
        "memory.rs:533",
        "NOT a breaking candidate: the durable write path states it on every UPSERT of the stored record, at crates/eliot-store/src/surql/apply_write_envelope.surql:245, so the canonical row always carries the key.",
    ),
    (
        "memory.rs::TaskContract.completion_proof",
        "memory.rs:543",
        "NOT a breaking candidate: the same UPSERT states it explicitly at crates/eliot-store/src/surql/apply_write_envelope.surql:250.",
    ),
    (
        "memory.rs::VerificationRun.claim_id",
        "memory.rs:1948",
        "OWNED, not verified compatible: the deferred 'VerificationRun historical rows' row of the map above, whose owner is crates/eliot-store/src/canonical_store.rs - no in-tree Rust source writes the record, so a stored row that never carried the binding is that owner's historical-row policy.",
    ),
    (
        "memory.rs::VerificationRun.project_id",
        "memory.rs:1950",
        "OWNED, not verified compatible: the same deferred historical-rows row, owned by crates/eliot-store/src/canonical_store.rs, which reads the stored record back and no in-tree Rust source writes.",
    ),
    (
        "memory.rs::VerificationRun.task_id",
        "memory.rs:1952",
        "OWNED, not verified compatible: the same deferred historical-rows row, owned by crates/eliot-store/src/canonical_store.rs, which reads the stored record back and no in-tree Rust source writes.",
    ),
    (
        "memory.rs::VerificationRun.write_id",
        "memory.rs:1954",
        "OWNED, not verified compatible: the same deferred historical-rows row, owned by crates/eliot-store/src/canonical_store.rs, which reads the stored record back and no in-tree Rust source writes.",
    ),
    (
        "memory.rs::VerificationRun.memory_revision",
        "memory.rs:1956",
        "OWNED, not verified compatible: the same deferred historical-rows row, owned by crates/eliot-store/src/canonical_store.rs, which reads the stored record back and no in-tree Rust source writes.",
    ),
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn corpus(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("appendix-p-defaults")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("corpus document {name} must be readable: {error}"))
}

fn decode_fixture<T: DeserializeOwned>(name: &str) -> T {
    serde_json::from_str(&corpus(name))
        .unwrap_or_else(|error| panic!("corpus document {name} must decode: {error}"))
}

/// A raw wire document with one member replaced by the given JSON fragment, so
/// absent, explicit null and a stated value stay three separate decodes.
fn with_field(raw: &str, field: &str, replacement: &str) -> String {
    let mut document: Value = serde_json::from_str(raw)
        .unwrap_or_else(|error| panic!("the corpus document must parse: {error}"));
    let value: Value = serde_json::from_str(replacement)
        .unwrap_or_else(|error| panic!("the replacement fragment must parse: {error}"));
    document
        .as_object_mut()
        .unwrap_or_else(|| panic!("the corpus document must be a JSON object"))
        .insert(field.to_owned(), value);
    serde_json::to_string(&document)
        .unwrap_or_else(|error| panic!("the re-encoded document must serialize: {error}"))
}

fn assert_refused<T: DeserializeOwned + std::fmt::Debug>(raw: &str, field: &str, fixture: &str) {
    match serde_json::from_str::<T>(raw) {
        Ok(_) => panic!("{fixture} must refuse a missing `{field}`"),
        Err(error) => assert!(
            error.to_string().contains(field),
            "{fixture}: the typed error must name `{field}`, got: {error}"
        ),
    }
}

/// A closed control vocabulary refuses an out-of-set value, and its refusal
/// names the value rather than the member.
fn assert_refusal_names<T: DeserializeOwned + std::fmt::Debug>(raw: &str, token: &str, what: &str) {
    match serde_json::from_str::<T>(raw) {
        Ok(_) => panic!("{what} must be refused"),
        Err(error) => assert!(
            error.to_string().contains(token),
            "{what}: the refusal must name {token}, got: {error}"
        ),
    }
}

/// Whether a dotted/indexed path exists in a decoded document, used to prove
/// that a nested-missing fixture really carries its enclosing structure.
fn reaches(document: &Value, path: &str) -> bool {
    let mut current = document;
    for segment in path.split('.') {
        let (name, index) = match segment.split_once('[') {
            Some((name, rest)) => (
                name,
                rest.trim_end_matches(']')
                    .parse::<usize>()
                    .unwrap_or(usize::MAX),
            ),
            None => (segment, usize::MAX),
        };
        if !name.is_empty() {
            let Some(next) = current.get(name) else {
                return false;
            };
            current = next;
        }
        if index != usize::MAX {
            let Some(next) = current.get(index) else {
                return false;
            };
            current = next;
        }
    }
    true
}

fn blake3_hex(bytes: &[u8]) -> String {
    let digest = blake3::hash(bytes);
    let mut text = String::with_capacity(64);
    for byte in digest.as_bytes() {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// The keys whose absence this oracle classifies as a declared fact rather than
/// an error, on one type: the union of its `#[serde(default)]` sites and its
/// bare-`Option` sites. Case 19 uses it, so the tolerated omissions are read from
/// the same two scans cases 15 and 16 assert against rather than from a second
/// hand-maintained list.
///
/// A member carrying `deserialize_with` - directly, or through `with = "..."` -
/// is NOT in this set even when its declared type is `Option<T>`: `serde_derive`
/// emits a typed `missing_field` *error* for that shape, so its absence really
/// is refused and case 19 can still demand it.
fn absence_tolerant_keys_for(type_name: &str) -> Vec<String> {
    let marker = format!("::{type_name}.");
    let default_sites = discovered_default_sites();
    let bare_option_sites = discovered_bare_option_sites();
    let mut keys: Vec<&str> = default_sites.iter().map(|site| site.key.as_str()).collect();
    keys.extend(bare_option_sites.iter().map(|site| site.key.as_str()));
    keys.into_iter()
        .filter(|key| key.contains(&marker))
        .map(|key| key.rsplit('.').next().unwrap_or_default().to_owned())
        .collect()
}

/// Every key the golden document states that the oracle does not classify as
/// absence-tolerant must be required: removing it fails the decode. This is the
/// bounded-mutation property, with the tolerated set bound to the scan.
///
/// The tolerated set is the union of the two absence classes the scan records -
/// the `#[serde(default)]` sites and the bare-`Option` sites - because those are
/// exactly the two shapes whose absence serde does not turn into an error. Every
/// other key the golden states, including a required-nullable member that carries
/// `deserialize_with`, still has to refuse removal.
///
/// Proof structure, stated plainly: this helper is not an independent witness of
/// requiredness. It derives its tolerated omissions from the same
/// `discovered_default_sites()` / `discovered_bare_option_sites()` scans cases 15
/// and 16 assert against, so a member that later gains `#[serde(default)]`, or
/// loses a `deserialize_with`, is silently skipped here and only cases 15/16 fail.
/// The independence this case does add is per-document: every non-tolerant key
/// the golden states must refuse removal, and the 19-member
/// `CognitiveFieldProviderCallPlan` loop below is checked field by field.
fn assert_fixture_declares_every_required_key<T: DeserializeOwned + std::fmt::Debug>(
    fixture: &str,
    type_name: &str,
) {
    let document: Value = serde_json::from_str(&corpus(fixture))
        .unwrap_or_else(|error| panic!("corpus document {fixture} must parse: {error}"));
    let object = document
        .as_object()
        .unwrap_or_else(|| panic!("corpus document {fixture} must be a JSON object"));
    let tolerated = absence_tolerant_keys_for(type_name);
    let mut required = 0usize;
    for key in object.keys() {
        if tolerated.iter().any(|name| name == key) {
            continue;
        }
        required += 1;
        rejects_missing::<T>(document.clone(), key.as_str());
    }
    assert!(
        required > 0,
        "{fixture} must state at least one required key of {type_name}"
    );
}

// ---------------------------------------------------------------------
// The case-15/16 source oracle. It shares the shipped inventory script's
// classification vocabulary, and it transcribes the script's
// unsupported-syntax handling rather than shipping a second version of it:
// `mask_rust` fails closed on the six conditions `_mask_rust` raises on,
// `discovered_unsupported_macros` applies both of the script's macro patterns
// with the grade `_classify` gives that kind, and `manual_decoder_impls`
// matches `_MANUAL_IMPL_RE`. Each transcription names its script line, and
// case 15 reads the vocabulary back out of the script at run time so the copy
// cannot drift silently. Each of the two absence classes it records is
// discovered in one masked pass over the nine production files, computed once
// per process behind a `OnceLock`, so the tolerated set case 19 derives from is
// literally the frozen scan rather than a re-reading of the same source per
// type.
// ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DefaultForm {
    /// `#[serde(default)]` on a field.
    Direct,
    /// `#[serde(default = "<helper>")]`, an effectively defaulted field.
    Helper,
    /// `#[serde(default, skip_serializing_if = "...")]`.
    Paired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DefaultSite {
    /// `file::Type.field`, field-exact.
    key: String,
    form: DefaultForm,
    paired: bool,
}

fn nine_file_source(file: &str) -> String {
    let path = workspace_root()
        .join("crates")
        .join("eliot-types")
        .join("src")
        .join(file);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{file} must be readable: {error}"))
}

/// The nine frozen production files as `(file, source)` pairs, which is the
/// exact input every scan below walks. Every scan is written against
/// `(file_name, source_text)` rather than against this list, so pointing one at
/// a scanner fixture under `tests/data/appendix-p-scanner/` supplies the same
/// shape and there is exactly one copy of each rule.
fn nine_file_sources() -> Vec<(&'static str, String)> {
    NINE_FILES
        .iter()
        .map(|file| (*file, nine_file_source(file)))
        .collect()
}

/// The `skip_serializing_if` and `serialize_with` attribute NAMES that appear
/// inside the body of one named `struct`, each with the `file:line` it was read
/// at, sorted.
///
/// This is not a second oracle and it classifies nothing. It reuses `mask_rust`,
/// which blanks comments and string literals while preserving byte offsets, and
/// `struct_body_spans`, which already locates every named struct body in that
/// same masked text. Masking is what makes the answer exact rather than
/// approximate: a doc comment that names an attribute cannot be mistaken for a
/// declaration, and neither can a literal inside `with = "..."`. What survives
/// masking inside one struct body is the attribute name the source really spells
/// on a member.
///
/// Only those two names are looked for, and only inside one struct body. `with`
/// is deliberately outside this helper's vocabulary: it is a third, older token
/// this `Serialize` derivation already carried before the change case 12 is
/// about, and reading it here would turn a statement about this delivery into a
/// statement about the type's whole history.
fn serializing_attribute_names_in(file: &str, type_name: &str) -> Vec<(String, usize)> {
    let raw = nine_file_source(file);
    let masked = mask_rust(&raw);
    let (_, start, end) = struct_body_spans(&masked)
        .into_iter()
        .find(|(name, ..)| name.as_str() == type_name)
        .unwrap_or_else(|| panic!("{file} must still declare a struct named {type_name}"));
    let body = &masked[start..=end];
    let mut found: Vec<(String, usize)> = Vec::new();
    for name in ["serialize_with", "skip_serializing_if"] {
        let mut from = 0usize;
        while from < body.len() {
            let Some(at) = body[from..].find(name) else {
                break;
            };
            let at = at + from;
            found.push((name.to_owned(), line_of(&raw, start + at)));
            from = at + name.len();
        }
    }
    found.sort();
    found
}

/// The one way this oracle refuses source it cannot read. The detail strings
/// are the shipped inventory's own: `_mask_rust` in
/// `scripts/serde_boundary_inventory.py` raises
/// `InventoryError("MALFORMED_RUST_SOURCE", detail)`, and its stated purpose is
/// failing loudly "instead of silently mis-scanning". The script has a report to
/// write, so it turns the raise into one `unreadable-source` row per file that
/// `_classify` (:1901-1914) grades `unknown`, `BLOCKED` and `NOT_SAFE`; a test
/// has a failure, so the same condition ends the scan here, named by the line
/// and column it was found at.
fn malformed_source(detail: &str, bytes: &[u8], at: usize) -> ! {
    let at = at.min(bytes.len());
    let mut line = 1usize;
    for byte in &bytes[..at] {
        if *byte == b'\n' {
            line += 1;
        }
    }
    let column = match bytes[..at].iter().rposition(|byte| *byte == b'\n') {
        Some(newline) => at - newline,
        None => at + 1,
    };
    let message = format!("malformed-rust-source: {detail} at line {line}, column {column}");
    panic!("a nine-file source must mask cleanly: {message}")
}

/// The length of the character literal whose opening quote is at `at`, or `None`
/// when these bytes are a lifetime tick or a stray quote instead. `_mask_rust`
/// matches `'(?:\\.|[^'\\\n])'` for a character literal (:623) and its byte-char
/// form `b'(?:\\.|[^'\\])'` (:594); `byte_char` selects the second of the two.
///
/// The two patterns differ in the UNESCAPED branch only: `[^'\\]` in the byte
/// form admits a raw newline that `[^'\\\n]` in the plain form excludes, and
/// that is the only decision `byte_char` makes here. Neither form admits an
/// ESCAPED newline, because `\\.` cannot match one in either pattern and the
/// script passes no `re.DOTALL`, so the escaped check below is unconditional.
fn quoted_char_literal_len(bytes: &[u8], at: usize, byte_char: bool) -> Option<usize> {
    let first = bytes.get(at + 1).copied()?;
    if first == b'\\' {
        let escaped = bytes.get(at + 2).copied()?;
        if escaped == b'\n' {
            return None;
        }
        return (bytes.get(at + 3) == Some(&b'\'')).then_some(4);
    }
    if first == b'\'' || (first == b'\n' && !byte_char) {
        return None;
    }
    (bytes.get(at + 2) == Some(&b'\'')).then_some(3)
}

/// Blanks a `"…"` literal whose opening quote the caller has already written at
/// `at - 1`, preserving newlines and byte offsets, and returns the offset just
/// past its closing quote. `None` when the literal reaches a newline or the end
/// of source without closing: `_mask_rust` stops there and raises rather than
/// blanking the rest of the file.
fn mask_quoted_literal(bytes: &[u8], out: &mut [u8], at: usize) -> Option<usize> {
    let mut cursor = at;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => {
                out[cursor] = b' ';
                cursor += 1;
                if cursor < bytes.len() {
                    if bytes[cursor] == b'\n' {
                        out[cursor] = b'\n';
                    }
                    cursor += 1;
                }
            }
            b'"' => {
                out[cursor] = b' ';
                return Some(cursor + 1);
            }
            b'\n' => {
                out[cursor] = b'\n';
                return None;
            }
            _ => {
                out[cursor] = b' ';
                cursor += 1;
            }
        }
    }
    None
}

/// Blanks a raw literal from `at`, whose body starts at `body` and whose
/// terminator is one `"` followed by `hashes` more `#`, and returns the offset
/// just past that terminator. `None` when the terminator never appears:
/// `_mask_rust` searches the whole remainder of the file for it (:640, :652)
/// and raises when that search fails, so an unclosed raw string stops this scan
/// too.
fn mask_raw_literal(
    bytes: &[u8],
    out: &mut [u8],
    at: usize,
    body: usize,
    hashes: usize,
) -> Option<usize> {
    let terminator: Vec<u8> = std::iter::once(b'"')
        .chain(std::iter::repeat_n(b'#', hashes))
        .collect();
    let found = bytes[body..]
        .windows(terminator.len())
        .position(|window| window == terminator)?;
    let end = body + found + terminator.len();
    for (source, slot) in bytes[at..end].iter().zip(&mut out[at..end]) {
        if *source == b'\n' {
            *slot = b'\n';
        }
    }
    Some(end)
}

/// Blanks every comment and string literal while preserving byte offsets, so a
/// `serde(default)` mentioned in a doc comment can never become a scan hit.
///
/// Unreadable source fails closed, on exactly the six conditions `_mask_rust`
/// raises on: an unclosed byte-string literal (:591), byte-char literal (:596),
/// string literal (:620), raw string literal (:642), raw byte string (:654) or
/// block comment (:665). Each of those is a shape that otherwise blanks to
/// end-of-line and keeps reading the rest of the file as code, which is what
/// "instead of silently mis-scanning" names.
///
/// One rule is copied rather than re-derived, because it is what makes raising
/// safe here: a `'` that opens no character literal is a lifetime tick or a
/// stray quote, and `_mask_rust` (:622-633) KEEPS it so the surrounding code
/// stays visible to discovery. Without that rule,
/// `impl<'de> Deserialize<'de> for T` (the one hand-written decoder in the
/// nine-file domain) would read as an unclosed literal.
#[allow(clippy::too_many_lines)]
fn mask_rust(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = vec![b' '; bytes.len()];
    let mut index = 0usize;
    let mut line_comment = false;
    let mut block_depth = 0usize;
    let mut block_start = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        if line_comment {
            if byte == b'\n' {
                line_comment = false;
                out[index] = b'\n';
            }
            index += 1;
            continue;
        }
        if block_depth > 0 {
            if byte == b'/' && next == Some(b'*') {
                block_depth += 1;
                out[index] = b' ';
                out[index + 1] = b' ';
                index += 2;
            } else if byte == b'*' && next == Some(b'/') {
                block_depth -= 1;
                out[index] = b' ';
                out[index + 1] = b' ';
                index += 2;
            } else if byte == b'\n' {
                out[index] = b'\n';
                index += 1;
            } else {
                out[index] = b' ';
                index += 1;
            }
            continue;
        }
        if byte == b'/' && next == Some(b'/') {
            line_comment = true;
            out[index] = b' ';
            out[index + 1] = b' ';
            index += 2;
            continue;
        }
        if byte == b'/' && next == Some(b'*') {
            block_depth = 1;
            block_start = index;
            out[index] = b' ';
            out[index + 1] = b' ';
            index += 2;
            continue;
        }
        if byte == b'b' && next == Some(b'"') {
            let start = index;
            out[index] = b' ';
            out[index + 1] = b' ';
            let Some(end) = mask_quoted_literal(bytes, &mut out, index + 2) else {
                malformed_source("unclosed byte-string literal", bytes, start);
            };
            index = end;
            continue;
        }
        if byte == b'b' && next == Some(b'\'') {
            let start = index;
            let Some(length) = quoted_char_literal_len(bytes, index + 1, true) else {
                malformed_source("unclosed byte-char literal", bytes, start);
            };
            for slot in &mut out[index..=index + length] {
                *slot = b' ';
            }
            index += length + 1;
            continue;
        }
        if byte == b'"' {
            let start = index;
            out[index] = b' ';
            let Some(end) = mask_quoted_literal(bytes, &mut out, index + 1) else {
                malformed_source("unclosed string literal", bytes, start);
            };
            index = end;
            continue;
        }
        if byte == b'\'' {
            if let Some(length) = quoted_char_literal_len(bytes, index, false) {
                for slot in &mut out[index..index + length] {
                    *slot = b' ';
                }
                index += length;
            } else {
                out[index] = byte;
                index += 1;
            }
            continue;
        }
        // `_mask_rust` reads `r(#*)"` (:635) and `br(#*)"` (:647) at the `r`, so
        // in the script the raw-byte branch is unreachable: the raw-string branch
        // matches the `r"` of a `br"…"` first and leaves its `b` as code. The
        // unclosed-raw-byte condition it states (:654) is mirrored here by
        // anchoring both shapes at the `b`, which keeps an unclosed `br"…"` from
        // being read as ordinary code.
        if byte == b'r' || (byte == b'b' && next == Some(b'r')) {
            let prefix = if byte == b'r' { 1 } else { 2 };
            let mut probe = index + prefix;
            while bytes.get(probe) == Some(&b'#') {
                probe += 1;
            }
            if bytes.get(probe) == Some(&b'"') {
                let hashes = probe - (index + prefix);
                let detail = if prefix == 1 {
                    "unclosed raw string literal"
                } else {
                    "unclosed raw byte string"
                };
                let Some(end) = mask_raw_literal(bytes, &mut out, index, probe + 1, hashes) else {
                    malformed_source(detail, bytes, index);
                };
                index = end;
                continue;
            }
        }
        out[index] = byte;
        index += 1;
    }
    if block_depth > 0 {
        malformed_source("unclosed block comment", bytes, block_start);
    }
    String::from_utf8(out)
        .unwrap_or_else(|error| panic!("masked Rust source must stay valid UTF-8: {error}"))
}

/// Byte spans of every `#[serde(..)]` attribute in masked source. Masking has
/// blanked every string literal, so a paren count is exact here.
fn serde_attribute_spans(masked: &str) -> Vec<(usize, usize)> {
    let bytes = masked.as_bytes();
    let mut spans = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'#' || bytes.get(index + 1) != Some(&b'[') {
            index += 1;
            continue;
        }
        let mut probe = index + 2;
        while probe < bytes.len() && bytes[probe].is_ascii_whitespace() {
            probe += 1;
        }
        if masked.get(probe..probe + 5) != Some("serde") {
            index += 1;
            continue;
        }
        let mut cursor = probe + 5;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'(') {
            index += 1;
            continue;
        }
        let mut depth = 0usize;
        let mut close = cursor;
        while close < bytes.len() {
            match bytes[close] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            close += 1;
        }
        let mut after = close + 1;
        while after < bytes.len() && bytes[after].is_ascii_whitespace() {
            after += 1;
        }
        if close < bytes.len() && bytes.get(after) == Some(&b']') {
            spans.push((index, after + 1));
            index = after + 1;
            continue;
        }
        index += 1;
    }
    spans
}

/// Splits a serde attribute body into identifier and `=` tokens, so
/// `default = "helper"` is distinguishable from `default, skip_serializing_if`.
fn serde_tokens(body: &str) -> Vec<&str> {
    body.split(|character: char| {
        !(character.is_alphanumeric() || character == '_' || character == '=')
    })
    .filter(|token| !token.is_empty())
    .collect()
}

/// The field an attribute declares, or `None` for a container attribute and for
/// any shape this oracle cannot resolve.
fn field_name_after(masked: &str, from: usize) -> Option<String> {
    let bytes = masked.as_bytes();
    let mut index = from;
    loop {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes.get(index) == Some(&b'#') && bytes.get(index + 1) == Some(&b'[') {
            let mut close = index + 1;
            while close < bytes.len() && bytes[close] != b']' {
                close += 1;
            }
            if close >= bytes.len() {
                return None;
            }
            index = close + 1;
            continue;
        }
        break;
    }
    if masked.get(index..index + 3) == Some("pub") {
        index += 3;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes.get(index) == Some(&b'(') {
            let mut close = index;
            while close < bytes.len() && bytes[close] != b')' {
                close += 1;
            }
            if close >= bytes.len() {
                return None;
            }
            index = close + 1;
        }
    }
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    let start = index;
    while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_') {
        index += 1;
    }
    if index == start {
        return None;
    }
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    if bytes.get(index) != Some(&b':') {
        return None;
    }
    Some(masked[start..index].to_owned())
}

fn enclosing_type_name(masked: &str, before: usize) -> Option<String> {
    let head = &masked[..before];
    let bytes = head.as_bytes();
    let mut found: Option<String> = None;
    let mut index = 0usize;
    while index < bytes.len() {
        let previous_is_identifier =
            index > 0 && (bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'_');
        let length = if !previous_is_identifier && head.get(index..index + 6) == Some("struct") {
            6
        } else if !previous_is_identifier && head.get(index..index + 4) == Some("enum") {
            4
        } else {
            index += 1;
            continue;
        };
        // The rule set `struct_body_spans` states for the same keyword, in the same
        // order and the same vocabulary, so the two walks cannot disagree about
        // what a `struct`/`enum` token is. Three shapes must not read as a type:
        // a path segment (`clippy::struct_excessive_bools`), a bare `.` on the
        // same shape - the sibling does not need it, but this helper also matches
        // `enum`, and `.enumerate()` would otherwise read the name `erate` - and a
        // field name that merely begins with the keyword (`structured_bytes`).
        let qualified = index > 0 && matches!(bytes[index - 1], b':' | b'.');
        if qualified {
            index += 1;
            continue;
        }
        let mut cursor = index + length;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let start = cursor;
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
        {
            cursor += 1;
        }
        if cursor == start {
            index = cursor.max(index + 1);
            continue;
        }
        let ends_a_declaration = match bytes.get(cursor) {
            None => true,
            Some(byte) => {
                *byte == b'{'
                    || *byte == b'('
                    || *byte == b';'
                    || *byte == b'<'
                    || byte.is_ascii_whitespace()
            }
        };
        // A name whose body already closed before `before` is not the enclosing
        // type, so recording it would be a silently wrong name; `None` is what
        // makes the caller's `<unresolved-enclosing-type>` sentinel fire.
        let closed_before_caller = bytes[cursor..].contains(&b'}');
        if !ends_a_declaration || closed_before_caller {
            index += 1;
            continue;
        }
        found = Some(head[start..cursor].to_owned());
        index = cursor.max(index + 1);
    }
    found
}

/// The `#[serde(default)]` sites of ONE source, in `serde_attribute_spans`
/// order and named with `file` exactly as the nine-file aggregation names them.
fn default_sites_in(file: &str, raw: &str) -> Vec<DefaultSite> {
    let mut sites = Vec::new();
    let masked = mask_rust(raw);
    assert_eq!(
        masked.len(),
        raw.len(),
        "{file}: masking must preserve byte offsets"
    );
    for (start, end) in serde_attribute_spans(&masked) {
        let body = &raw[start..end];
        let tokens = serde_tokens(body);
        if !tokens.contains(&"default") {
            continue;
        }
        let paired = tokens.contains(&"skip_serializing_if");
        let helper = tokens
            .windows(2)
            .any(|pair| pair[0] == "default" && pair[1] == "=");
        let form = if helper {
            DefaultForm::Helper
        } else if paired {
            DefaultForm::Paired
        } else {
            DefaultForm::Direct
        };
        let prefix = format!("{file}::");
        let Some(type_name) = enclosing_type_name(&masked, start) else {
            sites.push(DefaultSite {
                key: format!("{prefix}<unresolved-enclosing-type>"),
                form,
                paired,
            });
            continue;
        };
        // A container attribute, or any shape this oracle cannot
        // resolve, is recorded as unresolved rather than skipped: the
        // shipped inventory treats the same situation as incomplete
        // evidence, and case 15 fails closed on it.
        let Some(field) = field_name_after(&masked, end) else {
            sites.push(DefaultSite {
                key: format!("{prefix}{type_name}.<unresolved-member>"),
                form,
                paired,
            });
            continue;
        };
        sites.push(DefaultSite {
            key: format!("{prefix}{type_name}.{field}"),
            form,
            paired,
        });
    }
    sites
}

/// The `#[serde(default)]` sites in the nine-file domain, computed once per
/// process. `#[test]` functions run in parallel threads, so the cell has to be
/// the concurrent one; case 19 asks for this scan once per covered type.
fn discovered_default_sites() -> Vec<DefaultSite> {
    static SITES: OnceLock<Vec<DefaultSite>> = OnceLock::new();
    SITES
        .get_or_init(|| {
            let mut sites: Vec<DefaultSite> = nine_file_sources()
                .iter()
                .flat_map(|source| default_sites_in(source.0, &source.1))
                .collect();
            sites.sort_by(|left, right| left.key.cmp(&right.key));
            sites
        })
        .clone()
}

// ---------------------------------------------------------------------
// The second absence class. serde's derive emits `missing_field(name)?` for a
// member with neither a default nor a `deserialize_with`, and `missing_field`
// returns a `MissingFieldDeserializer` whose `deserialize_option` calls
// `visit_none`. A bare `Option<T>` member is therefore NOT required on the wire:
// removing it decodes as `None`.
//
// The inverse shape is required, and the scan keeps the two apart. A member
// carrying `deserialize_with` - directly, or through `with = "..."`, which
// expands to both directions - makes serde_derive emit a typed `missing_field`
// *error* instead, so its absence really is refused even though its declared
// type is `Option<T>`.
// ---------------------------------------------------------------------

/// One `absent-becomes-none` site, named in this test's own vocabulary. It is
/// not a disposition: nothing here is exempt from it, and the shipped
/// inventory's `DISPOSITIONS` is untouched.
#[derive(Clone, Debug, Eq, PartialEq)]
struct BareOptionSite {
    /// `file::Type.field`, field-exact.
    key: String,
    file: &'static str,
    /// 1-based line of the member declaration in its own file.
    line: usize,
}

/// One member declaration of a `struct` body, with the serde tokens that apply
/// to it.
struct MemberDeclaration {
    /// Enclosing `struct` name, as the same scan reads it for default sites.
    type_name: String,
    field: String,
    declared_type: String,
    /// Byte offset of the declaration; masking is byte-preserving, so this is
    /// the same offset in the unmasked source.
    offset: usize,
    tokens: Vec<String>,
}

/// The offset of the `}` that closes the `{` at `open`, or `None` when the
/// source ends first. Every string literal is already blanked, so a depth count
/// is exact here for the same reason it is exact in `serde_attribute_spans`.
fn matching_delimiter(masked: &str, open: usize, opener: u8, closer: u8) -> Option<usize> {
    let bytes = masked.as_bytes();
    let mut depth = 0i32;
    let mut cursor = open;
    while cursor < bytes.len() {
        if bytes[cursor] == opener {
            depth += 1;
        } else if bytes[cursor] == closer {
            depth -= 1;
            if depth == 0 {
                return Some(cursor);
            }
        }
        cursor += 1;
    }
    None
}

/// The offset just past the `]` that closes the `#[...]` group at `from`, or
/// `None` when the group is never closed. Any `]` inside the group came from a
/// string literal, and masking blanked those.
fn attribute_group_end(masked: &str, from: usize) -> Option<usize> {
    let bytes = masked.as_bytes();
    let mut close = from + 1;
    while close < bytes.len() {
        if bytes[close] == b']' {
            return Some(close + 1);
        }
        close += 1;
    }
    None
}

/// The byte span of every named `struct` body in masked source, as
/// `(type name, first member offset, closing brace offset)`, in source order.
/// A tuple struct has no named members and is skipped; a shape this oracle
/// cannot resolve is skipped here and counted by case 15 through the frozen
/// per-file line list.
fn struct_body_spans(masked: &str) -> Vec<(String, usize, usize)> {
    let bytes = masked.as_bytes();
    let mut bodies = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let previous_is_identifier =
            index > 0 && (bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'_');
        if previous_is_identifier || masked.get(index..index + 6) != Some("struct") {
            index += 1;
            continue;
        }
        let mut cursor = index + 6;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let name_start = cursor;
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
        {
            cursor += 1;
        }
        if cursor == name_start {
            index += 1;
            continue;
        }
        let name = masked[name_start..cursor].to_owned();
        // A `struct` that is a path segment rather than a declaration, such as
        // `clippy::struct_excessive_bools` inside an `#[allow]`, must not be read
        // as a type. Two shapes rule it out: a `::` qualifier in front, and a
        // name that does not end on a declaration boundary.
        let qualified = index > 0 && bytes[index - 1] == b':';
        let ends_a_declaration = match bytes.get(cursor) {
            None => true,
            Some(byte) => {
                *byte == b'{'
                    || *byte == b'('
                    || *byte == b';'
                    || *byte == b'<'
                    || byte.is_ascii_whitespace()
            }
        };
        if qualified || !ends_a_declaration {
            index += 1;
            continue;
        }
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b'(') {
            let Some(close) = matching_delimiter(masked, cursor, b'(', b')') else {
                index += 1;
                continue;
            };
            cursor = close + 1;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if bytes.get(cursor) == Some(&b';') {
                index += 1;
                continue;
            }
        }
        let mut depth = 0i32;
        let mut open = None;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'<' => depth += 1,
                b'>' => depth -= 1,
                b'{' if depth <= 0 => {
                    open = Some(cursor);
                    break;
                }
                b';' if depth <= 0 => break,
                _ => {}
            }
            cursor += 1;
        }
        let Some(open) = open else {
            index += 1;
            continue;
        };
        let Some(close) = matching_delimiter(masked, open, b'{', b'}') else {
            index += 1;
            continue;
        };
        bodies.push((name, open + 1, close));
        index = close + 1;
    }
    bodies
}

/// Advance past a declaration shape this oracle cannot resolve, up to and
/// including the next top-level `,`.
fn skip_unresolved_member(masked: &str, end: usize, from: usize) -> usize {
    let bytes = masked.as_bytes();
    let mut cursor = from;
    let mut depth = 0i32;
    while cursor < end {
        match bytes[cursor] {
            b'<' | b'(' | b'[' | b'{' => depth += 1,
            b'>' | b')' | b']' | b'}' => depth -= 1,
            b',' if depth <= 0 => return cursor + 1,
            _ => {}
        }
        cursor += 1;
    }
    end
}

/// Every named member declaration of one `struct` body.
///
/// This is the same masked source, the same `serde_attribute_spans` set and the
/// same `serde_tokens` tokenizer `discovered_default_sites` uses, walked from the
/// struct body rather than from an attribute. Reading it in this direction is
/// what lets the scan classify a member that carries no attribute at all, which
/// is the whole shape of the `absent-becomes-none` class.
fn struct_member_declarations(
    masked: &str,
    raw: &str,
    spans: &[(usize, usize)],
    body: (usize, usize),
    type_name: &str,
) -> Vec<MemberDeclaration> {
    let bytes = masked.as_bytes();
    let (start, end) = body;
    let mut members = Vec::new();
    let mut pending: Vec<String> = Vec::new();
    let mut span_cursor = spans.partition_point(|span| span.1 <= start);
    let mut cursor = start;
    while cursor < end {
        while cursor < end && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= end {
            break;
        }
        if bytes[cursor] == b',' {
            cursor += 1;
            continue;
        }
        if bytes[cursor] == b'#' && bytes.get(cursor + 1) == Some(&b'[') {
            let Some(close) = attribute_group_end(masked, cursor) else {
                break;
            };
            cursor = close;
            continue;
        }
        while span_cursor < spans.len() && spans[span_cursor].1 <= cursor {
            let (span_start, span_end) = spans[span_cursor];
            pending.extend(
                serde_tokens(&raw[span_start..span_end])
                    .into_iter()
                    .map(str::to_owned),
            );
            span_cursor += 1;
        }
        let offset = cursor;
        if masked.get(cursor..cursor + 3) == Some("pub") {
            cursor += 3;
            while cursor < end && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if bytes.get(cursor) == Some(&b'(') {
                let Some(close) = matching_delimiter(masked, cursor, b'(', b')') else {
                    break;
                };
                cursor = close + 1;
                while cursor < end && bytes[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
            }
        }
        let name_start = cursor;
        while cursor < end && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_') {
            cursor += 1;
        }
        if cursor == name_start {
            cursor = skip_unresolved_member(masked, end, cursor);
            pending.clear();
            continue;
        }
        let field = masked[name_start..cursor].to_owned();
        while cursor < end && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b':') {
            cursor = skip_unresolved_member(masked, end, cursor);
            pending.clear();
            continue;
        }
        cursor += 1;
        let type_start = cursor;
        let mut depth = 0i32;
        while cursor < end {
            match bytes[cursor] {
                b'<' | b'(' | b'[' => depth += 1,
                b'>' | b')' | b']' => depth -= 1,
                b',' if depth <= 0 => break,
                _ => {}
            }
            cursor += 1;
        }
        members.push(MemberDeclaration {
            type_name: type_name.to_owned(),
            field,
            declared_type: masked[type_start..cursor].trim().to_owned(),
            offset,
            tokens: std::mem::take(&mut pending),
        });
        cursor += 1;
    }
    members
}

/// Whether a declared member type is a bare `Option<...>` rather than a type
/// whose name merely begins with those six letters.
fn declares_bare_option(declared_type: &str) -> bool {
    declared_type
        .strip_prefix("Option")
        .is_some_and(|rest| rest.trim_start().starts_with('<'))
}

/// Whether a member carries the one serde token that makes its declared type
/// irrelevant to requiredness: `deserialize_with`, `with` (which expands to both
/// directions) or `default`.
fn suppresses_absent_becomes_none(tokens: &[String]) -> bool {
    tokens
        .iter()
        .any(|token| matches!(token.as_str(), "default" | "deserialize_with" | "with"))
}

/// The 1-based line of a byte offset, counted on the unmasked source: masking
/// blanks the newlines inside a block comment, so the masked copy is byte
/// aligned but not line aligned.
fn line_of(raw: &str, offset: usize) -> usize {
    let mut line = 1usize;
    for byte in &raw.as_bytes()[..offset] {
        if *byte == b'\n' {
            line += 1;
        }
    }
    line
}

/// The `absent-becomes-none` sites of ONE source, in ascending source order.
fn bare_option_sites_in(file: &'static str, raw: &str) -> Vec<BareOptionSite> {
    let mut sites = Vec::new();
    let masked = mask_rust(raw);
    assert_eq!(
        masked.len(),
        raw.len(),
        "{file}: masking must preserve byte offsets"
    );
    let spans = serde_attribute_spans(&masked);
    for (type_name, open, close) in struct_body_spans(&masked) {
        for member in struct_member_declarations(&masked, raw, &spans, (open, close), &type_name) {
            if !declares_bare_option(&member.declared_type)
                || suppresses_absent_becomes_none(&member.tokens)
            {
                continue;
            }
            sites.push(BareOptionSite {
                key: format!("{}::{}.{}", file, member.type_name, member.field),
                file,
                line: line_of(raw, member.offset),
            });
        }
    }
    sites
}

/// Every `absent-becomes-none` site in the nine-file domain: a named member of a
/// `struct` item whose declared type is a bare `Option<...>` and which carries
/// neither `default` nor `deserialize_with`/`with`. Discovered in the same masked
/// pass as the default sites and cached the same way, so case 19's tolerated set
/// and case 15's frozen denominator are one reading of one source.
///
/// The result is in `NINE_FILES` order and, inside one file, in ascending source
/// order, so it is already grouped per file with ascending lines. That is the
/// order the frozen `file:line` list is compared in.
fn discovered_bare_option_sites() -> Vec<BareOptionSite> {
    static SITES: OnceLock<Vec<BareOptionSite>> = OnceLock::new();
    SITES
        .get_or_init(|| {
            nine_file_sources()
                .iter()
                .flat_map(|source| bare_option_sites_in(source.0, &source.1))
                .collect()
        })
        .clone()
}

/// The bypass shapes present on field attributes in the nine-file domain,
/// named with the shipped inventory's shape vocabulary.
fn declared_bypass_shapes() -> Vec<String> {
    let mut shapes = Vec::new();
    for file in NINE_FILES {
        let raw = nine_file_source(file);
        let masked = mask_rust(&raw);
        for (start, end) in serde_attribute_spans(&masked) {
            let tokens = serde_tokens(&raw[start..end]);
            for shape in ["flatten", "untagged", "alias", "manual-visitor"] {
                if tokens.contains(&shape) {
                    shapes.push(format!("{file}:{shape}"));
                }
            }
        }
    }
    shapes.sort();
    shapes
}

/// One `unsupported-macro` site in the nine-file domain, carrying the shipped
/// inventory's classification for that kind.
///
/// `_MACRO_UNSUPPORTED_RE` (:682) and `_MAKE_MACRO_CALL_RE` (:683) are the two
/// patterns the script folds into one `unsupported-macro` row per site
/// (:1236-1288), and `_classify` (:1901-1914) gives every such row the same
/// grade whatever it matched: `unknown`, `BLOCKED`, `NOT_SAFE`.
///
/// The two paths are separate on purpose. This class has no field-exact member
/// to name - a macro site is a position, not a field - so it is never a row in
/// `DEFAULT_SITE_EXCEPTIONS`, and case 16 holds that table to dispositions the
/// oracle can defend per field. Case 15 asserts the separation directly, so the
/// two cannot be merged later without an explicit decision.
#[derive(Debug, Eq, PartialEq)]
struct UnsupportedMacroSite {
    /// `file:<line>:<macro name>`.
    key: String,
    /// The shipped kind: `unsupported-macro` (:1263).
    kind: &'static str,
    /// The shipped disposition for that kind: `unknown` (:1903).
    disposition: &'static str,
    /// The shipped repair readiness for that kind: `BLOCKED` (:1906).
    repair_readiness: &'static str,
    /// The shipped safety for that kind: `NOT_SAFE` (:1908).
    safety: &'static str,
}

/// Whether a byte may start an identifier, which is what both of the script's
/// macro patterns require of the name they capture.
fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

/// Whether a byte may continue an identifier.
fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The offset of the first byte at or after `at` that is not ASCII whitespace.
/// `_MANUAL_IMPL_RE` (:672) and `_MACRO_UNSUPPORTED_RE` (:682) both separate
/// their tokens with `\s*`, which spans lines.
fn skip_whitespace(bytes: &[u8], at: usize) -> usize {
    let mut cursor = at;
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    cursor
}

/// The `unsupported-macro` sites in the nine-file domain, discovered from the
/// masked source exactly as the script discovers them.
///
/// One name can only reach `_MACRO_UNSUPPORTED_RE` if it carries `serde`, `deser`
/// or `Deser` AT AN OFFSET PAST ITS FIRST CHARACTER: the pattern opens with
/// `[A-Za-z_]`, so `serde!(..)` alone does not match while `my_deser!(..)` does.
/// Both patterns and that offset rule are mirrored here, including the second
/// pattern's three whole names, because `serde_derive_magic` carries none of the
/// three substrings and is therefore reachable only through it.
///
/// Sites are deduplicated by name and line, as the script dedups the overlap
/// between its two patterns (:1244). The nine-file read sorts them like every
/// other discovered list in this file; a single-source read keeps source order,
/// which for one file is already ascending.
fn discovered_unsupported_macros() -> Vec<UnsupportedMacroSite> {
    let sources = nine_file_sources();
    let mut sites =
        unsupported_macros_in(sources.iter().map(|source| (source.0, source.1.as_str())));
    sites.sort_by(|left, right| left.key.cmp(&right.key));
    sites
}

/// The `unsupported-macro` sites of the given `(file, source)` pairs, in source
/// order. The dedup set spans the whole call, so the overlap between the two
/// patterns is folded once per `(name, line)` exactly as the script folds it.
fn unsupported_macros_in<'a>(
    sources: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Vec<UnsupportedMacroSite> {
    let mut sites = Vec::new();
    let mut seen: Vec<(String, usize)> = Vec::new();
    for (file, raw) in sources {
        let masked = mask_rust(raw);
        let bytes = masked.as_bytes();
        let mut index = 0usize;
        while index < bytes.len() {
            if !is_identifier_byte(bytes[index]) {
                index += 1;
                continue;
            }
            let start = index;
            let mut end = index;
            while end < bytes.len() && is_identifier_byte(bytes[end]) {
                end += 1;
            }
            let name = masked[start..end].to_owned();
            let tail = name.get(1..).unwrap_or_default();
            let serde_like = is_identifier_start(bytes[start])
                && ["serde", "deser", "Deser"]
                    .iter()
                    .any(|needle| tail.contains(*needle));
            let make_macro = ["make_deser", "make_serde", "serde_derive_magic"]
                .iter()
                .any(|candidate| *candidate == name);
            index = end;
            if !(serde_like || make_macro) {
                continue;
            }
            let mut cursor = skip_whitespace(bytes, end);
            if bytes.get(cursor).copied() != Some(b'!') {
                continue;
            }
            cursor = skip_whitespace(bytes, cursor + 1);
            if !matches!(bytes.get(cursor).copied(), Some(b'(' | b'[' | b'{')) {
                continue;
            }
            let line = line_of(raw, start);
            let entry = (name, line);
            if seen.contains(&entry) {
                continue;
            }
            seen.push(entry.clone());
            sites.push(UnsupportedMacroSite {
                key: format!("{file}:{line}:{}", entry.0),
                kind: "unsupported-macro",
                disposition: "unknown",
                repair_readiness: "BLOCKED",
                safety: "NOT_SAFE",
            });
        }
    }
    sites
}

/// Every offset an optional `<…>` generic argument list opening at `at` could
/// end at, in the order `_MANUAL_IMPL_RE` tries them: its `[^;{}]*` run is
/// greedy, so the longest run whose next byte is a `>` is tried first, and the
/// run may cross a line because `[^;{}]` excludes only `;`, `{` and `}`.
///
/// An empty result means the optional group cannot match here, which is the
/// regex's own outcome: `\s*Deserialize` cannot consume a `<`.
fn generic_argument_ends(bytes: &[u8], at: usize) -> Vec<usize> {
    if bytes.get(at).copied() != Some(b'<') {
        return Vec::new();
    }
    let mut run_end = at + 1;
    while run_end < bytes.len() && !matches!(bytes[run_end], b';' | b'{' | b'}') {
        run_end += 1;
    }
    bytes[at + 1..run_end]
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'>')
        .map(|(relative, _)| at + 1 + relative + 1)
        .rev()
        .collect()
}

/// Whether the bytes at `at` spell `word`, which every literal this oracle
/// matches is ASCII.
fn spells(bytes: &[u8], at: usize, word: &str) -> bool {
    bytes
        .get(at..at + word.len())
        .is_some_and(|slice| slice == word.as_bytes())
}

/// The offset just past the identifier at `at`, or `None` when no identifier
/// starts there. `_MANUAL_IMPL_RE` spells both of its name positions
/// `[A-Za-z_][A-Za-z0-9_]*`.
fn identifier_end(bytes: &[u8], at: usize) -> Option<usize> {
    if !is_identifier_start(bytes.get(at).copied()?) {
        return None;
    }
    let mut end = at + 1;
    while end < bytes.len() && is_identifier_byte(bytes[end]) {
        end += 1;
    }
    Some(end)
}

/// The offset just past the type name of the `Deserialize … for T` tail that
/// follows at `cursor`, or `None`. `_MANUAL_IMPL_RE` allows any lifetime in the
/// argument list, on this line or the next.
fn deserialize_for_end(bytes: &[u8], cursor: usize) -> Option<usize> {
    let at = skip_whitespace(bytes, cursor);
    if !spells(bytes, at, "Deserialize") {
        return None;
    }
    let after_name = skip_whitespace(bytes, at + "Deserialize".len());
    let mut candidates = generic_argument_ends(bytes, after_name);
    candidates.push(after_name);
    for candidate in candidates {
        let at = skip_whitespace(bytes, candidate);
        if !spells(bytes, at, "for") {
            continue;
        }
        if let Some(end) = type_name_end(bytes, skip_whitespace(bytes, at + "for".len())) {
            return Some(end);
        }
    }
    None
}

/// The offset just past the type name of the `impl … Deserialize … for T`
/// header that starts at `at`, or `None` when these bytes are not one. This is
/// `_MANUAL_IMPL_RE` (:672) read without a regex engine, including its greedy
/// optional-argument order.
fn manual_deserialize_impl_end(bytes: &[u8], at: usize) -> Option<usize> {
    let head = skip_whitespace(bytes, at + "impl".len());
    let mut candidates = generic_argument_ends(bytes, head);
    candidates.push(head);
    candidates
        .into_iter()
        .find_map(|candidate| deserialize_for_end(bytes, candidate))
}

/// The offset just past the possibly `::`-qualified type name at `at`, or `None`
/// when none starts there. `_MANUAL_IMPL_RE` allows whitespace after each `::`.
fn type_name_end(bytes: &[u8], at: usize) -> Option<usize> {
    let mut cursor = identifier_end(bytes, at)?;
    while bytes.get(cursor).copied() == Some(b':') && bytes.get(cursor + 1).copied() == Some(b':') {
        cursor = identifier_end(bytes, skip_whitespace(bytes, cursor + 2))?;
    }
    Some(cursor)
}

/// Whether the byte at `offset` is the first non-whitespace byte on its line.
/// This is the `impl` anchor, and it is the only thing standing between a
/// derive line or a doc comment that names the trait and a counted decoder,
/// because this read is unmasked. The script has the same concern and answers it
/// by masking comments away before it matches.
fn starts_its_own_line(bytes: &[u8], offset: usize) -> bool {
    bytes[..offset]
        .iter()
        .rev()
        .take_while(|byte| **byte != b'\n' && **byte != b'\r')
        .all(u8::is_ascii_whitespace)
}

/// The hand-written `Deserialize` implementations in the nine-file domain, the
/// `manual-visitor` bypass shape, one `file:line` per site.
///
/// This is `_MANUAL_IMPL_RE` (:672) - `impl`, an optional argument list,
/// `Deserialize`, its own optional argument list, `for`, and a possibly
/// qualified type name - so a decoder written with a different lifetime, or with
/// its impl header split across lines, is found by shape and not only by the
/// spelling `Deserialize<'de>`.
///
/// Read from the unmasked source, as before: this oracle's own mask keeps a
/// lifetime tick (`mask_rust`) but blanking and re-deriving the impl header is
/// not worth a second copy of the masking rules here. The `impl` anchor is kept
/// for the reason given on `starts_its_own_line`.
/// The hand-written decoders of the given `(file, source)` pairs, in source
/// order. The nine-file read sorts them; a single-source read is already in
/// ascending order for one file, so nothing else changes.
fn manual_decoder_impls_in<'a>(
    sources: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Vec<String> {
    let mut found = Vec::new();
    for (file, raw) in sources {
        let bytes = raw.as_bytes();
        let mut cursor = 0usize;
        while let Some(relative) = raw[cursor..].find("impl") {
            let offset = cursor + relative;
            match manual_deserialize_impl_end(bytes, offset) {
                Some(end) if starts_its_own_line(bytes, offset) => {
                    found.push(format!("{file}:{}", line_of(raw, offset)));
                    cursor = end;
                }
                _ => cursor = offset + "impl".len(),
            }
        }
    }
    found
}

fn manual_decoder_impls() -> Vec<String> {
    let sources = nine_file_sources();
    let mut found =
        manual_decoder_impls_in(sources.iter().map(|source| (source.0, source.1.as_str())));
    found.sort();
    found
}

fn python_block(script: &str, marker: &str, terminator: &str) -> String {
    let start = script
        .find(marker)
        .unwrap_or_else(|| panic!("{marker} must exist in scripts/serde_boundary_inventory.py"));
    let rest = &script[start + marker.len()..];
    let end = rest.find(terminator).unwrap_or_else(|| {
        panic!("{marker} must be closed by {terminator} in the inventory script")
    });
    rest[..end].to_owned()
}

fn quoted_literals(block: &str) -> Vec<String> {
    let bytes = block.as_bytes();
    let mut literals = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        let start = index + 1;
        let mut close = start;
        while close < bytes.len() && bytes[close] != b'"' {
            close += 1;
        }
        literals.push(block[start..close].to_owned());
        index = close + 1;
    }
    literals
}

fn sorted(values: &[String]) -> Vec<String> {
    let mut owned = values.to_vec();
    owned.sort();
    owned
}

/// Every one of the thirteen members this delivery changed to a required-nullable
/// shape is accounted for individually: a deferred owner-map row names its type or
/// the row carries a stated justification, the `file:line` it states really
/// declares that member carrying the required-nullable decoder, and every
/// repository path a justification names exists on disk.
///
/// It is a separate function because it proves a different property from the
/// owner-map checks its leading comment contrasts against - completeness of the
/// changed members rather than completeness of the map - and `case_20` calls it
/// directly beneath those checks.
fn assert_changed_required_nullable_members_are_accounted_for() {
    // The thirteen members this delivery changed to a required-nullable shape.
    // The checks above cannot see them: they compare this file's own
    // hand-maintained constants against each other, and the only map row that
    // names a changed type at all ("VerificationRun historical rows") names no
    // field, so a changed member nobody classified could not fail any of them.
    // Each member below is therefore accounted for explicitly, by a map row or by
    // a justification that says why it is not a breaking candidate or which owner
    // owns it.
    let mut changed_keys: Vec<String> = CHANGED_REQUIRED_NULLABLE_MEMBERS
        .iter()
        .map(|(key, ..)| (*key).to_owned())
        .collect();
    changed_keys.sort();
    changed_keys.dedup();
    assert_eq!(
        changed_keys.len(),
        13,
        "the changed required-nullable members must stay thirteen distinct file::Type.member keys, one per changed member"
    );
    for (key, location, justification) in CHANGED_REQUIRED_NULLABLE_MEMBERS {
        let member = key.rsplit('.').next().unwrap_or_default();
        let type_name = key.rsplit('.').nth(1).unwrap_or_default();
        // A map row counts as covering this member when it names the member's
        // TYPE. Matching on the type rather than on the member name is what keeps
        // `VerificationRun.task_id` from passing on the unrelated
        // `RecallL0Request.task_id` row; the row that does cover the five
        // `VerificationRun` members names the type and no field, which is why the
        // justification below is required of all thirteen either way.
        let named_by_a_map_row = BREAKING_CANDIDATE_OWNER_MAP
            .iter()
            .any(|(candidate, ..)| candidate.contains(type_name));
        assert!(
            named_by_a_map_row || !justification.trim().is_empty(),
            "{key} is a member this delivery made required-nullable and is named by neither a deferred owner-map row nor a stated justification"
        );
        assert!(
            !justification.trim().is_empty(),
            "{key} must carry a justification: why it is not a breaking candidate, or which owner owns it"
        );
        // The stated declaration has to be real, and it has to be the member the
        // required-nullable correction was made on. A `file:line` that drifts, or
        // that names a member which is not carrying the decoder, fails here rather
        // than leaving the row looking like evidence.
        let (file, line) = location
            .split_once(':')
            .unwrap_or_else(|| panic!("{key} must state its declaration as one file:line"));
        let declared_line = line
            .parse::<usize>()
            .unwrap_or_else(|error| panic!("{key}: {line} is not a line number: {error}"));
        assert!(
            declared_line >= 2,
            "{key}: the required-nullable attribute sits on the line above its member"
        );
        let source = nine_file_source(file);
        let declared = source
            .lines()
            .nth(declared_line - 1)
            .unwrap_or_else(|| panic!("{file}:{declared_line} must exist for {key}"));
        assert!(
            declared.contains(&format!("pub {member}:")),
            "{key} must be declared at {location}, got: {declared}"
        );
        let attribute = source.lines().nth(declared_line - 2).unwrap_or_default();
        assert!(
            attribute.contains("deserialize_required_nullable"),
            "{key} must carry the required-nullable decoder on the line above {location}, got: {attribute}"
        );
        // Every repository path a justification names must exist, with the same
        // on-disk check the map rows above use. A justification that cites a
        // producer nobody can open is not evidence.
        for token in justification.split(|character: char| {
            !(character.is_alphanumeric()
                || character == '/'
                || character == '.'
                || character == '_'
                || character == '-')
        }) {
            if !token.starts_with("crates/") {
                continue;
            }
            assert!(
                workspace_root().join(token).is_file(),
                "{key}: the justification names {token}, which must exist on disk"
            );
        }
    }
}
/// The field-exact exception table: one row per discovered default site in
/// the nine-file domain, with the disposition that records why it stays.
/// `current-closed` is a paired optional or a coherent-absence row on a
/// closed type, `exact-internal` is packet, projection or score content
/// with named in-tree callers, `specific-owner` needs a named owner outside
/// this issue's file scope, and `named-legacy` is the one legacy wire name
/// its named boundary still admits.
const DEFAULT_SITE_EXCEPTIONS: &[(&str, &str)] = &[
    (
        "cognition.rs::MaterialPacketFrame.invariant_refs",
        "specific-owner",
    ),
    (
        "cognition.rs::MaterialPacketFrame.waived_invariants",
        "specific-owner",
    ),
    (
        "cognition.rs::MaterialPacketFrame.prediction_confidence",
        "specific-owner",
    ),
    (
        "cognition.rs::MaterialPacketFrame.predicted_changed_paths",
        "specific-owner",
    ),
    (
        "cognition.rs::MaterialPacketFrame.predicted_failing_verifiers",
        "specific-owner",
    ),
    (
        "cognition.rs::UnderstandingOutcomeRecord.canonical_receipt",
        "current-closed",
    ),
    (
        "cognition.rs::MemoryInfluenceTrace.canonical_receipt",
        "current-closed",
    ),
    (
        "cognition.rs::MemoryDecisionReceipt.canonical_receipt",
        "current-closed",
    ),
    (
        "cognition.rs::ContextCargoReceipt.canonical_receipt",
        "current-closed",
    ),
    (
        "cognition.rs::NegativeMemoryDecisionReceipt.canonical_receipt",
        "current-closed",
    ),
    (
        "cognition.rs::AutonomyRunTransitionReceipt.canonical_receipt",
        "current-closed",
    ),
    (
        "cognition.rs::TaskCognitionView.task_meaning",
        "current-closed",
    ),
    (
        "cognition.rs::MemoryInspectorView.corpus_profile",
        "current-closed",
    ),
    (
        "cognition.rs::AutonomyRecoveryRecord.write_receipt",
        "current-closed",
    ),
    (
        "cognition.rs::OperatorQueryRequest.filter",
        "exact-internal",
    ),
    (
        "cognition.rs::OperatorQueryRequest.query_operation",
        "exact-internal",
    ),
    (
        "cognition.rs::OperatorQueryRequest.query_parameters",
        "exact-internal",
    ),
    (
        "cognition.rs::OperatorQueryRequest.result_mode",
        "exact-internal",
    ),
    (
        "cognition.rs::OperatorQueryRequest.selected_ref",
        "exact-internal",
    ),
    (
        "cognition.rs::OperatorQueryRequest.expand_depth",
        "specific-owner",
    ),
    (
        "cognition.rs::OperatorProjectionPage.result_payload",
        "current-closed",
    ),
    (
        "cognition.rs::OperatorCommandReceipt.preview",
        "current-closed",
    ),
    (
        "cognition.rs::OperatorControlRequest.canonical_receipt",
        "current-closed",
    ),
    (
        "memory.rs::ActionProvenanceSet.memory_delivery_refs",
        "current-closed",
    ),
    (
        "memory.rs::ActionProvenanceSet.memory_grant_refs",
        "current-closed",
    ),
    (
        "memory.rs::TaskContractInput.memory_grant_redemptions",
        "current-closed",
    ),
    (
        "memory.rs::TaskContract.memory_grant_redemptions",
        "current-closed",
    ),
    ("memory.rs::RecallL0Request.task_id", "current-closed"),
    (
        "memory.rs::RecallL0Response.projection_revision",
        "current-closed",
    ),
    (
        "memory.rs::RecallL0Response.projection_state",
        "exact-internal",
    ),
    (
        "memory.rs::RecallL0Response.memory_confidence",
        "exact-internal",
    ),
    ("memory.rs::RecallL0Response.rank_trace", "exact-internal"),
    ("memory.rs::RecallL0Response.conflict", "exact-internal"),
    (
        "memory.rs::L0RankTrace.collapsed_duplicates",
        "exact-internal",
    ),
    ("memory.rs::L0FeatureScore.exact_cue", "exact-internal"),
    (
        "memory.rs::L0FeatureScore.concept_relation",
        "exact-internal",
    ),
    ("memory.rs::L0FeatureScore.freshness_fit", "exact-internal"),
    (
        "memory.rs::L0FeatureScore.negative_memory_value",
        "exact-internal",
    ),
    (
        "memory.rs::L0FeatureScore.known_decision_delta",
        "exact-internal",
    ),
    (
        "memory.rs::L0FeatureScore.prior_beneficial_use",
        "exact-internal",
    ),
    (
        "memory.rs::L0FeatureScore.verification_value",
        "exact-internal",
    ),
    ("memory.rs::L0FeatureScore.context_cost", "exact-internal"),
    ("memory.rs::L0FeatureScore.stale_penalty", "exact-internal"),
    (
        "memory.rs::L0FeatureScore.contradiction_penalty",
        "exact-internal",
    ),
    ("memory.rs::L0FeatureScore.harm_penalty", "exact-internal"),
    (
        "memory.rs::L0FeatureScore.repetition_penalty",
        "exact-internal",
    ),
    (
        "memory.rs::L0FeatureScore.distraction_penalty",
        "exact-internal",
    ),
    (
        "memory.rs::FetchAtomsL2Request.continuation",
        "current-closed",
    ),
    (
        "memory.rs::FetchAtomsL2Response.ul_artifacts",
        "exact-internal",
    ),
    (
        "memory.rs::FetchAtomsL2Response.canonical_memory_pages",
        "exact-internal",
    ),
    (
        "memory.rs::FetchAtomsL2Response.requested_handles",
        "exact-internal",
    ),
    (
        "memory.rs::FetchAtomsL2Response.returned_handles",
        "exact-internal",
    ),
    (
        "memory.rs::FetchAtomsL2Response.missing_handles",
        "exact-internal",
    ),
    (
        "memory.rs::FetchAtomsL2Response.forbidden_handles",
        "exact-internal",
    ),
    (
        "memory.rs::FetchAtomsL2Response.continuation",
        "current-closed",
    ),
    (
        "memory.rs::MemoryHandlePreview.lifecycle_state",
        "current-closed",
    ),
    (
        "memory.rs::MemoryHandlePreview.lifecycle_badge",
        "current-closed",
    ),
    ("memory.rs::ToolObservation.write_id", "current-closed"),
    (
        "memory.rs::CompilePacketL3Request.max_tokens",
        "specific-owner",
    ),
    (
        "memory.rs::GovernedGitScope.ancestor_commits",
        "exact-internal",
    ),
    (
        "memory.rs::GovernedGitScope.artifact_refs",
        "exact-internal",
    ),
    (
        "memory.rs::MemoryProvenanceView.evidence_refs",
        "exact-internal",
    ),
    (
        "memory.rs::MemoryProvenanceView.artifact_refs",
        "exact-internal",
    ),
    (
        "memory.rs::MemoryApplicabilityPacketView.current_git_scope",
        "current-closed",
    ),
    (
        "memory.rs::MemoryApplicabilityPacketView.decisions",
        "exact-internal",
    ),
    (
        "memory.rs::MemoryApplicabilityPacketView.inclusion_reasons",
        "exact-internal",
    ),
    (
        "memory.rs::MemoryApplicabilityPacketView.suppression_reasons",
        "exact-internal",
    ),
    (
        "memory.rs::MemoryApplicabilityPacketView.revalidation_reasons",
        "exact-internal",
    ),
    ("memory.rs::ContextPacketL3.packet_id", "exact-internal"),
    (
        "memory.rs::ContextPacketL3.task_execution_class",
        "exact-internal",
    ),
    (
        "memory.rs::ContextPacketL3.project_understanding",
        "current-closed",
    ),
    (
        "memory.rs::ContextPacketL3.memory_confidence",
        "exact-internal",
    ),
    (
        "memory.rs::ContextPacketL3.acceptance_items",
        "exact-internal",
    ),
    (
        "memory.rs::ContextPacketL3.current_truth_snapshot",
        "current-closed",
    ),
    (
        "memory.rs::ContextPacketL3.epistemic_state",
        "exact-internal",
    ),
    ("memory.rs::ContextPacketL3.active_plan", "exact-internal"),
    (
        "memory.rs::ContextPacketL3.completed_work",
        "exact-internal",
    ),
    ("memory.rs::ContextPacketL3.killed_paths", "exact-internal"),
    ("memory.rs::ContextPacketL3.causal_bridge", "exact-internal"),
    (
        "memory.rs::ContextPacketL3.memory_decisions",
        "exact-internal",
    ),
    (
        "memory.rs::ContextPacketL3.experience_priors",
        "exact-internal",
    ),
    (
        "memory.rs::ContextPacketL3.memory_need_decision",
        "current-closed",
    ),
    (
        "memory.rs::ContextPacketL3.decision_locality_suffix",
        "exact-internal",
    ),
    (
        "memory.rs::ContextPacketL3.packet_quality",
        "current-closed",
    ),
    (
        "memory.rs::ContextPacketL3.memory_applicability",
        "exact-internal",
    ),
    (
        "memory.rs::ContextPacketL3.historical_memory",
        "exact-internal",
    ),
    ("memory.rs::ContextPacketL3.codecortex", "current-closed"),
    (
        "memory.rs::ContextPacketL3.memory_lifecycle",
        "exact-internal",
    ),
    (
        "memory.rs::ContextPacketL3.procedural_skills",
        "exact-internal",
    ),
    (
        "memory.rs::CodeCortexPacketView.scope_binding",
        "exact-internal",
    ),
    ("memory.rs::ActionRequest.skill_refs", "exact-internal"),
    (
        "memory.rs::ActionRequest.skill_activation_decisions",
        "exact-internal",
    ),
    ("memory.rs::ActionLease.skill_refs", "exact-internal"),
    ("memory.rs::CompletionProof.skill_refs", "exact-internal"),
    (
        "memory.rs::CompletionProof.skill_execution_proof_refs",
        "exact-internal",
    ),
    (
        "memory.rs::CodeCortexReport.scope_binding",
        "exact-internal",
    ),
    ("memory.rs::WorkItem.verifier_run_refs", "exact-internal"),
    (
        "memory.rs::WorkItem.candidate_review_refs",
        "exact-internal",
    ),
    ("memory.rs::WorktreeLease.kind", "current-closed"),
    ("memory.rs::WorktreeLease.managed_root", "current-closed"),
    (
        "lifecycle.rs::ForgettingPolicy.effective_at",
        "exact-internal",
    ),
    (
        "lifecycle.rs::ForgettingPolicy.expires_at",
        "exact-internal",
    ),
    (
        "lifecycle.rs::ForgettingPolicy.approval_ref",
        "exact-internal",
    ),
    (
        "lifecycle.rs::MemoryVitalityScore.beneficial_use_count",
        "exact-internal",
    ),
    (
        "lifecycle.rs::MemoryVitalityScore.prevented_failure_count",
        "exact-internal",
    ),
    (
        "lifecycle.rs::MemoryVitalityScore.correct_verifier_selection_count",
        "exact-internal",
    ),
    (
        "lifecycle.rs::MemoryVitalityScore.negative_transfer_count",
        "exact-internal",
    ),
    (
        "lifecycle.rs::MemoryVitalityScore.contradiction_count",
        "exact-internal",
    ),
    (
        "lifecycle.rs::MemoryVitalityScore.context_cost_tokens",
        "exact-internal",
    ),
    (
        "lifecycle.rs::MemoryVitalityScore.maintenance_cost_units",
        "exact-internal",
    ),
    (
        "lifecycle.rs::MemoryVitalityScore.minority_importance_millis",
        "exact-internal",
    ),
    (
        "lifecycle.rs::MemoryVitalityScore.freshness_millis",
        "exact-internal",
    ),
    (
        "lifecycle.rs::MemoryVitalityScore.scope_fit_millis",
        "exact-internal",
    ),
    (
        "lifecycle.rs::MemoryVitalityScore.utility_millis",
        "exact-internal",
    ),
    (
        "lifecycle.rs::MemoryVitalityScore.harm_millis",
        "exact-internal",
    ),
    (
        "lifecycle.rs::MemoryGravity.activation_pressure_millis",
        "exact-internal",
    ),
    (
        "lifecycle.rs::MemoryStateTransition.reactivation_condition",
        "exact-internal",
    ),
    (
        "lifecycle.rs::MemoryStateTransition.approval_ref",
        "exact-internal",
    ),
    (
        "lifecycle.rs::MemoryStateTransition.write_receipt",
        "current-closed",
    ),
    (
        "lifecycle.rs::MinorityPressureRecord.write_receipt",
        "current-closed",
    ),
    (
        "lifecycle.rs::MemoryTrajectoryCorrectness.write_receipt",
        "current-closed",
    ),
    (
        "lifecycle.rs::CapabilityMemoryIndex.last_verified_at",
        "exact-internal",
    ),
    (
        "lifecycle.rs::CapabilityMemoryIndex.write_receipt",
        "current-closed",
    ),
    (
        "lifecycle.rs::MemoryInfluenceReport.outcome",
        "current-closed",
    ),
    (
        "lifecycle.rs::MemoryInfluenceReport.write_receipt",
        "current-closed",
    ),
    ("eval.rs::EvalSuite.frozen_at", "exact-internal"),
    ("eval.rs::EvalRun.finished_at", "exact-internal"),
    (
        "eval.rs::EvalIntegrityFingerprintSet.oracle_version",
        "exact-internal",
    ),
    (
        "eval.rs::EvalIntegrityFingerprintSet.product_identity",
        "exact-internal",
    ),
    (
        "eval.rs::EvalCaseResult.integrity_fingerprints",
        "exact-internal",
    ),
    (
        "eval.rs::HarnessExperimentRecord.disposition_receipt",
        "current-closed",
    ),
    (
        "eval.rs::EvalBaseline.integrity_fingerprints",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::CompilePacketToolInput.material_frame",
        "specific-owner",
    ),
    (
        "mcp_contract.rs::CompilePacketToolInput.memory_mode",
        "specific-owner",
    ),
    (
        "mcp_contract.rs::AgentCandidateSubmitInput.where_applicable",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateSubmitInput.where_not_applicable",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateSubmitInput.negative_constraints",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateSubmitInput.cue_bindings",
        "specific-owner",
    ),
    (
        "mcp_contract.rs::AgentCandidateSubmitInput.auto_bind",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateSubmitInput.curation",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.duplicate_of",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.semantic_duplicate_of",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.semantic_equivalence_verified",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.scope_match",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.wrong_scope_for",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.utility_score",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.utility_delta",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.repeat_count",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.repeated_with",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.evidence_sufficient",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.superseded_by",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.stale_reason_ref",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.protected",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.current_truth",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.audit_required",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.reopen_condition_met",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.unsafe_instruction",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.unsafe_evidence_refs",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.role",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.lifecycle",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.authority",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.evidence_refs",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::AgentCandidateCurationInput.counterevidence_refs",
        "exact-internal",
    ),
    (
        // A RECORDED DEFECT, not a sanctioned boundary: see case 9. `I07-20:14`
        // admits an alias only at a migration or compatibility boundary, and this
        // one is neither - `mcp_contract.rs:378-384` records it as a W4 defect
        // that APPENDIX-P's fail-closed rule is violated by, blocked on the
        // renaming owner outside this card's scope. The disposition stays
        // `named-legacy` because the card forbids correcting the retained row.
        "mcp_contract.rs::ObserveInput.hint",
        "named-legacy",
    ),
    ("mcp_contract.rs::ObserveInput.task_id", "exact-internal"),
    (
        "mcp_contract.rs::ObserveInput.affected_resources",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::ObserveInput.source_handles",
        "exact-internal",
    ),
    (
        "mcp_contract.rs::ObserveInput.expected_reuse_note",
        "exact-internal",
    ),
    ("mcp_contract.rs::ObserveInput.write_id", "exact-internal"),
    (
        "mcp_contract.rs::ObserveInput.schema_version",
        "specific-owner",
    ),
    (
        "antigravity.rs::AntigravityRealReport.visibility",
        "current-closed",
    ),
    (
        "cognitive_field.rs::CognitiveFieldProviderPlan.role_evidence_plan_hash",
        "specific-owner",
    ),
    (
        "cognitive_field.rs::CognitiveFieldProviderPlan.seal_attempt_id",
        "specific-owner",
    ),
    (
        "cognitive_field.rs::CognitiveFieldProviderPlan.authority_activation_ref",
        "specific-owner",
    ),
    (
        "cognitive_field.rs::CognitiveFieldProviderPlan.runtime_manifest_sha256",
        "specific-owner",
    ),
    (
        "cognitive_field.rs::CognitiveFieldProviderPlan.artifact_manifest_sha256",
        "specific-owner",
    ),
];

// WORK_UNIT_CASE: 708/1
#[test]
fn case_01_valid_current_golden_decodes_every_changed_boundary_type() {
    // Case 1: one valid current golden per changed boundary type in the nine-file
    // domain, decoded through the crate's own serde path.
    //
    // "Golden" means the wire shape of the NINE-FILE type named in the assertion,
    // not the published agent-facing surface. For two of the published tools the
    // two are different types: `surfaces/eliot-mcp/src/contract.rs:330` declares
    // its own `ObserveInput` as a `kind`-tagged enum and `:212` its own
    // two-field `PacketInput`, neither of which is the `ObserveInput` struct or
    // `CompilePacketToolInput` exercised here. Those surfaces are READ ONLY for
    // this card; case 20's owner map records the divergence and its owner
    // (`crates/surfaces/eliot-mcp/src/schema.rs`) instead of this case pretending
    // to cover them.
    // Case 1: a valid current golden wire document for every changed boundary
    // type in the nine-file domain. Each line is a real `serde_json` decode
    // call, not a source-attribute assertion.
    let _: WorkLease = decode_fixture("work_lease_positive.json");
    let _: ProviderCallLedger = decode_fixture("provider_call_ledger_positive.json");
    let _: AutonomyRunContract = decode_fixture("autonomy_run_contract_positive.json");
    let _: ForgettingPolicy = decode_fixture("forgetting_policy_positive.json");
    let _: MemoryStateTransition = decode_fixture("memory_state_transition_positive.json");
    let _: AntigravityRun = decode_fixture("antigravity_run_positive.json");
    let _: AntigravitySafetyReceipt = decode_fixture("antigravity_safety_receipt_positive.json");
    let _: CognitiveFieldProviderCallPlan =
        decode_fixture("cognitive_field_provider_call_plan_positive.json");
    let _: CognitiveFieldProviderEvidenceReceipt =
        decode_fixture("cognitive_field_provider_evidence_receipt_positive.json");
    let _: CognitiveFieldProviderProjection =
        decode_fixture("cognitive_field_provider_projection_positive.json");
    let plan: CognitiveFieldProviderPlan =
        decode_fixture("cognitive_field_provider_plan_positive.json");
    assert_eq!(
        plan.schema_version,
        COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION
    );
    let _: CausalCandidate = decode_fixture("causal_candidate_positive.json");
    let _: TaskCognitionView = decode_fixture("task_cognition_view_positive.json");
    let _: MemoryInspectorView = decode_fixture("memory_inspector_view_positive.json");
    let _: AgentRoutingView = decode_fixture("agent_routing_view_positive.json");
    let _: AutonomyRunView = decode_fixture("autonomy_run_view_positive.json");
    let _: OperatorSnapshot = decode_fixture("operator_snapshot_positive.json");
    // `WorktreeLease` carries two paired defaults (`memory.rs:3207` `kind`,
    // `memory.rs:3212` `managed_root`) and one bare `Option` (`memory.rs:3221`
    // `write_receipt`), so its named positive document OMITS the two defaults -
    // which is what makes case 17 able to show the defaults applying - and
    // STATES the bare `Option` explicitly, because its absence would decode.
    let worktree: WorktreeLease = decode_fixture("worktree_lease_positive.json");
    assert_eq!(worktree.state, WorktreeLeaseState::Active);
    assert!(worktree.write_receipt.is_none());
    let _: TaskAcceptanceItem = decode_fixture("task_acceptance_item_positive.json");
    let _: ActionSourceScope = decode_fixture("action_source_scope_positive.json");
    let _: TaskContract = decode_fixture("task_contract_positive.json");
    let _: TaskContractInput = decode_fixture("task_contract_input_positive.json");
    let _: VerificationRun = decode_fixture("verification_run_positive.json");
    let _: RecallL0Request = decode_fixture("recall_l0_request_positive.json");
    let _: UnderstandingProof = decode_fixture("understanding_proof_positive.json");
    let _: UnderstandingProofReceipt = decode_fixture("understanding_proof_receipt_positive.json");
    let _: DelegationRequest = decode_fixture("delegation_request_positive.json");
    let _: ProviderInvocationAttempt = decode_fixture("provider_invocation_attempt_positive.json");
    let _: MaterialPacketFrame = decode_fixture("material_packet_frame_positive.json");
    let _: AgentCandidateSubmitInput = decode_fixture("agent_candidate_submit_input_positive.json");
    let _: AgentCandidateCurationInput =
        decode_fixture("agent_candidate_curation_input_positive.json");
    let _: ObserveInput = decode_fixture("observe_input_positive.json");
    let _: CompilePacketToolInput = decode_fixture("compile_packet_tool_input_positive.json");
    let _: CompilePacketL3Request = decode_fixture("compile_packet_l3_request_positive.json");
    let _: EvalSuite = decode_fixture("eval_suite_positive.json");
    let _: EvalCaseResult = decode_fixture("eval_case_result_positive.json");
    let _: MemoryVitalityScore = decode_fixture("memory_vitality_score_positive.json");
    let _: MemoryHandlePreview = decode_fixture("memory_handle_preview_positive.json");
    let _: OperatorQueryRequest = decode_fixture("operator_query_request_positive.json");
    let _: OperatorCommandReceipt = decode_fixture("operator_command_receipt_positive.json");
    // Two `eval.rs` members are documented as required on the wire by the
    // declaration doc above each type (eval.rs:586-590 and :629-636) and had no
    // golden of their own, so the omission was covered by no document at all.
    // Both types are derive-decoded and closed, and neither carries a
    // `serde(default)` or a hand-written decoder.
    let _: MetaIsolationRejectionRecord =
        decode_fixture("meta_isolation_rejection_record_positive.json");
    let _: MetaPolicyExecutionReceipt =
        decode_fixture("meta_policy_execution_receipt_positive.json");
}

// WORK_UNIT_CASE: 708/2
#[test]
#[allow(clippy::too_many_lines)]
fn case_02_omitted_contract_required_changed_field_fails_with_the_named_error() {
    // Case 2: dropping one contract-required key from a valid current golden
    // must fail, and the typed error owner must name that key.
    //
    // "Contract-required" here means the decoder really refuses the absence. It
    // used to be narrower than the arm list: three keys this case included could
    // not be refused at all, because a bare `Option<T>` decodes an absent key as
    // `None`, so the case asserted the decode instead. Those three members, and
    // ten more that carried the same bare shape, now carry
    // `#[serde(deserialize_with = "deserialize_required_nullable")]`, so the
    // refusals below are real; the closing block names the shape and all
    // thirteen `file:line` sites.
    let lease = work_lease_wire();
    let complete: WorkLease =
        serde_json::from_value(lease.clone()).expect("complete work lease wire");
    assert_eq!(complete.epoch, 0);
    rejects_missing::<WorkLease>(lease, "epoch");

    assert_refused::<WorkLease>(
        &corpus("work_lease_missing_epoch.json"),
        "epoch",
        "work_lease_missing_epoch.json",
    );
    assert_refused::<ProviderCallLedger>(
        &corpus("provider_call_ledger_missing_budgets.json"),
        "budgets",
        "provider_call_ledger_missing_budgets.json",
    );
    assert_refused::<AutonomyRunContract>(
        &corpus("autonomy_run_contract_missing_recovery_policy_ref.json"),
        "recovery_policy_ref",
        "autonomy_run_contract_missing_recovery_policy_ref.json",
    );
    assert_refused::<ForgettingPolicy>(
        &corpus("forgetting_policy_missing_precondition_refs.json"),
        "precondition_refs",
        "forgetting_policy_missing_precondition_refs.json",
    );
    assert_refused::<MemoryStateTransition>(
        &corpus("memory_state_transition_missing_expected_admission_effect.json"),
        "expected_admission_effect",
        "memory_state_transition_missing_expected_admission_effect.json",
    );
    assert_refused::<AntigravityRun>(
        &corpus("antigravity_run_missing_response_protocol_receipt.json"),
        "response_protocol_receipt",
        "antigravity_run_missing_response_protocol_receipt.json",
    );
    assert_refused::<AntigravitySafetyReceipt>(
        &corpus("antigravity_safety_receipt_missing_model_observation.json"),
        "model_observation",
        "antigravity_safety_receipt_missing_model_observation.json",
    );
    assert_refused::<CognitiveFieldProviderCallPlan>(
        &corpus("cognitive_field_provider_call_plan_missing_runtime_contract_ref.json"),
        "runtime_contract_ref",
        "cognitive_field_provider_call_plan_missing_runtime_contract_ref.json",
    );
    assert_refused::<CognitiveFieldProviderEvidenceReceipt>(
        &corpus("cognitive_field_provider_evidence_receipt_missing_runtime_contract_sha256.json"),
        "runtime_contract_sha256",
        "cognitive_field_provider_evidence_receipt_missing_runtime_contract_sha256.json",
    );
    assert_refused::<CognitiveFieldProviderProjection>(
        &corpus("cognitive_field_provider_projection_missing_runtime_contract_sha256.json"),
        "runtime_contract_sha256",
        "cognitive_field_provider_projection_missing_runtime_contract_sha256.json",
    );
    assert_refused::<CognitiveFieldProviderPlan>(
        &corpus("cognitive_field_provider_plan_missing_seal_generation.json"),
        "seal_generation",
        "cognitive_field_provider_plan_missing_seal_generation.json",
    );
    assert_refused::<TaskCognitionView>(
        &corpus("task_cognition_view_missing_experience_priors.json"),
        "experience_priors",
        "task_cognition_view_missing_experience_priors.json",
    );
    assert_refused::<MemoryInspectorView>(
        &corpus("memory_inspector_view_missing_applicability_decisions.json"),
        "applicability_decisions",
        "memory_inspector_view_missing_applicability_decisions.json",
    );
    assert_refused::<AgentRoutingView>(
        &corpus("agent_routing_view_missing_worktree_leases.json"),
        "worktree_leases",
        "agent_routing_view_missing_worktree_leases.json",
    );
    assert_refused::<AutonomyRunView>(
        &corpus("autonomy_run_view_missing_tool_calls_used.json"),
        "tool_calls_used",
        "autonomy_run_view_missing_tool_calls_used.json",
    );
    assert_refused::<OperatorSnapshot>(
        &corpus("operator_snapshot_missing_incidents.json"),
        "incidents",
        "operator_snapshot_missing_incidents.json",
    );
    assert_refused::<ActionSourceScope>(
        &corpus("action_source_scope_missing_artifact_paths.json"),
        "artifact_paths",
        "action_source_scope_missing_artifact_paths.json",
    );
    assert_refused::<TaskContract>(
        &corpus("task_contract_missing_verification_scopes.json"),
        "verification_scopes",
        "task_contract_missing_verification_scopes.json",
    );
    assert_refused::<VerificationRun>(
        &corpus("verification_run_missing_verifier.json"),
        "verifier",
        "verification_run_missing_verifier.json",
    );
    assert_refused::<RecallL0Request>(
        &corpus("recall_l0_request_missing_lifecycle_audit.json"),
        "lifecycle_audit",
        "recall_l0_request_missing_lifecycle_audit.json",
    );
    assert_refused::<UnderstandingProof>(
        &corpus("understanding_proof_missing_blast_radius_acknowledged.json"),
        "blast_radius_acknowledged",
        "understanding_proof_missing_blast_radius_acknowledged.json",
    );
    assert_refused::<UnderstandingProofReceipt>(
        &corpus("understanding_proof_receipt_missing_files_to_change.json"),
        "files_to_change",
        "understanding_proof_receipt_missing_files_to_change.json",
    );
    assert_refused::<DelegationRequest>(
        &corpus("delegation_request_missing_origin_chain.json"),
        "origin_chain",
        "delegation_request_missing_origin_chain.json",
    );
    assert_refused::<ProviderInvocationAttempt>(
        &corpus("provider_invocation_attempt_missing_timeout_class.json"),
        "timeout_class",
        "provider_invocation_attempt_missing_timeout_class.json",
    );
    assert_refused::<MetaIsolationRejectionRecord>(
        &corpus("meta_isolation_rejection_record_missing_source_experiment_ref.json"),
        "source_experiment_ref",
        "meta_isolation_rejection_record_missing_source_experiment_ref.json",
    );
    assert_refused::<MetaPolicyExecutionReceipt>(
        &corpus("meta_policy_execution_receipt_missing_operator_command_ref.json"),
        "operator_command_ref",
        "meta_policy_execution_receipt_missing_operator_command_ref.json",
    );

    // ---------------------------------------------------------------------
    // THIRTEEN rows this case asserts a refusal for BEFORE the production
    // change, and the refusals are now the truth. Six of them were delivered
    // first and were then described as the complete set; a refutation pass run
    // AFTER that delivery found SEVEN more members of exactly the same shape,
    // so the earlier completeness claim was wrong. It is corrected here rather
    // than left standing: the thirteen sites are all listed below and all
    // thirteen are asserted in this case. A reader must not take thirteen for
    // six - the two `file:line` lists that existed before this edit are both
    // wrong, one for being incomplete and neither for being a bound.
    //
    // All thirteen members were each declared as a bare `Option<...>` with no
    // serde attribute at all. serde's derive emitted `missing_field(name)?` for
    // that shape, and `missing_field` hands back a `MissingFieldDeserializer`
    // whose `deserialize_option` visits `None`, so an ABSENT key silently
    // decoded as "this record states no such binding" on authority-bearing
    // fields: an unassigned check, an unbound acceptance item, an
    // unprovenanced task contract, an unproved completion, an unstated run
    // cost, and a verification run bound to no claim, no project, no task, no
    // write and no memory revision.
    //
    // Each now carries
    // `#[serde(deserialize_with = "deserialize_required_nullable")]` - the
    // field-exact attribute, one per member, with the shared decoder body
    // (`Option::<T>::deserialize(deserializer)`) doing nothing that reintroduces
    // a default. With `deserialize_with` and no `serde(default)`, serde_derive's
    // `expr_is_missing` no longer routes the member to `missing_field`, so the
    // derived visitor hits `missing_field(name)?` FIRST and that is a typed
    // ERROR; the decoder body is reached only for a key that IS present, where
    // it keeps handling a stated value and an explicit `null` exactly as before.
    // The frozen field inventory in `crates/eliot-types/src/lifecycle.rs`
    // ("#708 FROZEN FIELD INVENTORY") names all thirteen REQUIRED, which is what
    // makes the refusals correct rather than merely stricter.
    //
    // The thirteen sites, at their current declarations:
    //   cognition.rs:387   CausalCandidate.assigned_check
    //   memory.rs:253      TaskAcceptanceItem.verification_scope_hash
    //   memory.rs:493      TaskContractInput.action_provenance
    //   memory.rs:500      TaskContractInput.completion_proof
    //   memory.rs:533      TaskContract.action_provenance
    //   memory.rs:543      TaskContract.completion_proof
    //   cognition.rs:1118  AutonomyRunView.cost_or_tokens_used
    //   cognition.rs:1121  AutonomyRunView.completion_proof
    //   memory.rs:1948     VerificationRun.claim_id
    //   memory.rs:1950     VerificationRun.project_id
    //   memory.rs:1952     VerificationRun.task_id
    //   memory.rs:1954     VerificationRun.write_id
    //   memory.rs:1956     VerificationRun.memory_revision
    // `Serialize` was not touched and no `skip_serializing_if` was added to any
    // of the thirteen, so emitted bytes are unchanged and case 12's canonical
    // round trip still holds; only the ACCEPTED set narrowed, which is the
    // compatible requiredness correction the thirteen declaration docs already
    // claim.
    //
    // Three of the six FIRST-round documents predate this work -
    // `causal_candidate_missing_assigned_check.json`,
    // `task_acceptance_item_missing_verification_scope_hash.json` and
    // `task_contract_input_missing_action_provenance.json` - and were previously
    // asserted by this very case to DECODE with the member `None`.
    // `task_contract_input_missing_completion_proof.json` and
    // `task_contract_missing_completion_proof.json` arrived with the first
    // production change, and `task_contract_missing_action_provenance.json` was
    // written afterwards, because `TaskContract.action_provenance` had no
    // omission fixture of its own at all. The seven REFUTATION-pass documents
    // arrived with the second production change; each one is its positive with
    // exactly that one member removed and every other value unchanged, which is
    // what lets this case read the refusal as the requiredness change and not as
    // a fixture defect.
    //
    // None of the thirteen is an `absent-becomes-none` site any more: each
    // carries `deserialize_with`, which `discovered_bare_option_sites` skips by
    // the same rule that already keeps the `deserialize_with` members of
    // `ProviderInvocationAttempt` out of the list. So
    // `EXPECTED_BARE_OPTION_SITE_COUNT` falls from 277 to 264 - the first six
    // members took it to 271 and the seven the refutation pass found took it the
    // rest of the way - case 19's tolerated set loses all thirteen keys and
    // therefore demands their refusal, and the assertion that these keys stay
    // enumerated absent-becomes-none sites - which this block used to end with -
    // is deleted rather than inverted.
    // ---------------------------------------------------------------------
    assert_refused::<CausalCandidate>(
        &corpus("causal_candidate_missing_assigned_check.json"),
        "assigned_check",
        "causal_candidate_missing_assigned_check.json",
    );
    assert_refused::<TaskAcceptanceItem>(
        &corpus("task_acceptance_item_missing_verification_scope_hash.json"),
        "verification_scope_hash",
        "task_acceptance_item_missing_verification_scope_hash.json",
    );
    assert_refused::<TaskContractInput>(
        &corpus("task_contract_input_missing_action_provenance.json"),
        "action_provenance",
        "task_contract_input_missing_action_provenance.json",
    );
    assert_refused::<TaskContractInput>(
        &corpus("task_contract_input_missing_completion_proof.json"),
        "completion_proof",
        "task_contract_input_missing_completion_proof.json",
    );
    assert_refused::<TaskContract>(
        &corpus("task_contract_missing_action_provenance.json"),
        "action_provenance",
        "task_contract_missing_action_provenance.json",
    );
    assert_refused::<TaskContract>(
        &corpus("task_contract_missing_completion_proof.json"),
        "completion_proof",
        "task_contract_missing_completion_proof.json",
    );
    // The seven arms the refutation pass added, in the order the closing block
    // lists them. Each is the same claim as the six above and for the same
    // reason: the member used to decode an absent key as `None`, and now refuses
    // it with a typed `missing_field` naming the member.
    assert_refused::<AutonomyRunView>(
        &corpus("autonomy_run_view_missing_cost_or_tokens_used.json"),
        "cost_or_tokens_used",
        "autonomy_run_view_missing_cost_or_tokens_used.json",
    );
    assert_refused::<AutonomyRunView>(
        &corpus("autonomy_run_view_missing_completion_proof.json"),
        "completion_proof",
        "autonomy_run_view_missing_completion_proof.json",
    );
    assert_refused::<VerificationRun>(
        &corpus("verification_run_missing_claim_id.json"),
        "claim_id",
        "verification_run_missing_claim_id.json",
    );
    assert_refused::<VerificationRun>(
        &corpus("verification_run_missing_project_id.json"),
        "project_id",
        "verification_run_missing_project_id.json",
    );
    assert_refused::<VerificationRun>(
        &corpus("verification_run_missing_task_id.json"),
        "task_id",
        "verification_run_missing_task_id.json",
    );
    assert_refused::<VerificationRun>(
        &corpus("verification_run_missing_write_id.json"),
        "write_id",
        "verification_run_missing_write_id.json",
    );
    assert_refused::<VerificationRun>(
        &corpus("verification_run_missing_memory_revision.json"),
        "memory_revision",
        "verification_run_missing_memory_revision.json",
    );
}

// WORK_UNIT_CASE: 708/3
#[test]
fn case_03_optional_members_keep_absent_null_and_value_distinguishable() {
    // Case 3: a required-nullable member refuses absence and accepts an
    // explicit null or a value; a retained paired member keeps absent and
    // explicit null as one declared fact and still differs from a value.
    let safety = safety_receipt_wire();
    let _: AntigravitySafetyReceipt =
        serde_json::from_value(safety.clone()).expect("complete safety receipt");
    rejects_missing::<AntigravitySafetyReceipt>(safety, "model_observation");
    let _: AntigravitySafetyReceipt = decode_fixture("antigravity_safety_receipt_positive.json");
    let observed: AntigravitySafetyReceipt = serde_json::from_str(&with_field(
            &serde_json::to_string(&safety_receipt_wire()).expect("safety receipt text"),
            "model_observation",
            r#"{"requested_model":"gpt-test","observed_model":"gpt-test","authority":"cli_authenticated_runtime_log","authenticated_runtime":true,"backend_propagation_observed":true,"stream_started_after_selection":true}"#,
        ),
    )
    .expect("explicit model observation decodes");
    assert!(observed.model_observation.is_some());

    // The ten required-nullable outcome fields on the invocation journal record
    // refuse absence and accept an explicit null.
    let attempt_raw = corpus("provider_invocation_attempt_positive.json");
    let attempt: Value = serde_json::from_str(&attempt_raw)
        .expect("the complete journal record parses as a wire document");
    for field in [
        "provider_route_policy",
        "timeout_class",
        "process_reap_receipt",
        "process_timed_out",
        "process_cancelled",
        "process_worker_error",
        "stdout_total_bytes",
        "stderr_total_bytes",
        "stdout_truncated",
        "stderr_truncated",
    ] {
        // The absence has to be produced per member: one intact document cannot
        // be refused ten times, because serde reports the first missing member in
        // declaration order and stops there.
        rejects_missing::<ProviderInvocationAttempt>(attempt.clone(), field);
        let nulled = with_field(&attempt_raw, field, "null");
        let _: ProviderInvocationAttempt = serde_json::from_str(&nulled).unwrap_or_else(|error| {
            panic!("explicit null {field} must decode as a stated absence: {error}")
        });
    }
    // Seven of them keep the valued state distinct from both other states.
    for (field, fragment) in [
        ("timeout_class", "\"spawn_timeout\""),
        ("process_timed_out", "true"),
        ("stdout_total_bytes", "7"),
        ("process_worker_error", "\"worker exited\""),
        // The three falsy and empty valued states. `0`, `false` and `""` are
        // values, not a fifth spelling of absence: each decodes to the value
        // itself, which is what the arm below checks against the decoded record.
        ("stdout_total_bytes", "0"),
        ("process_timed_out", "false"),
        ("process_worker_error", "\"\""),
    ] {
        let valued = with_field(&attempt_raw, field, fragment);
        let _: ProviderInvocationAttempt = serde_json::from_str(&valued)
            .unwrap_or_else(|error| panic!("explicit value {field} must decode: {error}"));
    }
    // The explicitly empty value is a fourth state, distinct from both an absent
    // key (refused, by the loop above) and an explicit null (`None`, by the loop
    // above that one), so a reader cannot confuse "zero was measured", "the
    // process was not timed out" and "a worker error text was recorded but is
    // empty" with "nothing was ever recorded".
    //
    // `RecallL0Request.task_id` cannot carry this arm: it is `Option<TaskId>`, a
    // uuid newtype, so `""` is refused by the TaskId parser instead of preserved
    // as an empty value. The empty `String` member used here is
    // `ProviderInvocationAttempt.process_worker_error`.
    let zeroed: ProviderInvocationAttempt =
        serde_json::from_str(&with_field(&attempt_raw, "stdout_total_bytes", "0"))
            .expect("an explicit zero is a stated measurement, not an absent one");
    assert_eq!(zeroed.stdout_total_bytes, Some(0));
    let not_timed_out: ProviderInvocationAttempt =
        serde_json::from_str(&with_field(&attempt_raw, "process_timed_out", "false"))
            .expect("an explicit false is a stated outcome, not an absent one");
    assert_eq!(not_timed_out.process_timed_out, Some(false));
    let emptied: ProviderInvocationAttempt =
        serde_json::from_str(&with_field(&attempt_raw, "process_worker_error", "\"\""))
            .expect("an explicit empty string is a stated value, not an absent one");
    assert_eq!(emptied.process_worker_error.as_deref(), Some(""));

    // The retained paired row: absent and explicit null are one fact, and both
    // differ from a stated value.
    let recall_raw = corpus("recall_l0_request_positive.json");
    let absent: RecallL0Request = decode_fixture("recall_l0_request_positive.json");
    assert!(absent.task_id.is_none());
    let stated_null: RecallL0Request =
        serde_json::from_str(&with_field(&recall_raw, "task_id", "null"))
            .expect("explicit null task_id decodes");
    assert!(stated_null.task_id.is_none());
    let stated_value: RecallL0Request = serde_json::from_str(&with_field(
        &recall_raw,
        "task_id",
        "\"00000000-0000-7000-8000-000000000009\"",
    ))
    .expect("stated task_id decodes");
    assert!(stated_value.task_id.is_some());

    // The verification run's subject/scope block is six members and not one of
    // them is absence-tolerant any more. `verifier` is a plain `String`
    // (memory.rs:1957) and refuses absence outright; the other five -
    // `claim_id`, `project_id`, `task_id`, `write_id` and `memory_revision` -
    // are corrected required-nullable members declared at memory.rs:1948-1956,
    // each carrying `#[serde(deserialize_with = "deserialize_required_nullable")]`,
    // so their absence is REFUSED with the typed error naming the member, and an
    // explicit null is what states "bound to nothing".
    // That is what this arm records: the required member refuses absence, and
    // the five required-nullable members take a stated null - or a stated value,
    // which the positive fixture carries for `project_id`. None of the six still
    // needs a bare-`Option` entry: the five carry `deserialize_with`, which is
    // the token `discovered_bare_option_sites` skips by the same rule it uses
    // for every other corrected member, and `verifier` is not an `Option` at
    // all, so the frozen `memory.rs` slice names none of them.
    assert_refused::<VerificationRun>(
        &corpus("verification_run_missing_verifier.json"),
        "verifier",
        "verification_run_missing_verifier.json",
    );
    let unbound: VerificationRun = decode_fixture("verification_run_explicit_nulls.json");
    assert!(unbound.claim_id.is_none());
    assert!(unbound.project_id.is_none());
    assert!(unbound.task_id.is_none());
    assert!(unbound.write_id.is_none());
    assert!(unbound.memory_revision.is_none());
    assert_eq!(unbound.verifier, "verifier-1");
    let bound: VerificationRun = decode_fixture("verification_run_positive.json");
    assert!(bound.project_id.is_some());
    assert_eq!(bound.verifier, "verifier-1");
}

// WORK_UNIT_CASE: 708/4
#[test]
fn case_04_empty_is_refused_only_where_the_field_contract_requires_it() {
    // Case 4: an empty value is refused exactly where the owning contract
    // declares it nonempty, and every explicitly complete empty denominator and
    // no-authority set stays valid. There is no general empty-value ban.
    let candidate: CausalCandidate = decode_fixture("causal_candidate_positive.json");
    assert!(candidate.validate_material().is_ok());
    let emptied = with_field(
        &corpus("causal_candidate_positive.json"),
        "mechanism",
        "\"\"",
    );
    let empty_candidate: CausalCandidate =
        serde_json::from_str(&emptied).expect("an empty string still decodes");
    assert!(
        empty_candidate.validate_material().is_err(),
        "the contractually nonempty mechanism must stay refused when empty"
    );

    // The second nonempty refusal, on two other members of the same type and not
    // on the one above, because one refusal cannot tell "this field's contract
    // requires nonempty" apart from "this decoder refuses empty strings".
    // `calibration` is named in the A6.5 nonempty set at cognition.rs:467 and a
    // bounded inquiry's description is refused at :471-475, and the second of
    // those is the member this delivery made required-nullable. Both refusals are
    // asserted against the error text, so neither arm can pass on an unrelated
    // failure, and both decode first: emptiness is refused by the contract, not
    // by the wire format.
    let uncalibrated: CausalCandidate = serde_json::from_str(&with_field(
        &corpus("causal_candidate_positive.json"),
        "calibration",
        "\"\"",
    ))
    .expect("an empty calibration string still decodes");
    let calibration_error = uncalibrated
        .validate_material()
        .expect_err("a contractually nonempty calibration must stay refused when empty");
    assert!(
        calibration_error
            .to_string()
            .contains("calibration must be nonblank"),
        "the refusal must be the calibration contract's own: {calibration_error}"
    );
    let empty_inquiry: CausalCandidate = serde_json::from_str(&with_field(
        &corpus("causal_candidate_positive.json"),
        "assigned_check",
        r#"{"kind":"bounded_inquiry","description":""}"#,
    ))
    .expect("an empty bounded inquiry still decodes");
    let inquiry_error = empty_inquiry
        .validate_material()
        .expect_err("an assigned bounded inquiry must state what it will check");
    assert!(
        inquiry_error
            .to_string()
            .contains("empty assigned bounded inquiry"),
        "the refusal must be the bounded-inquiry contract's own: {inquiry_error}"
    );

    // The discriminating control for those three refusals: a genuinely optional
    // `String` accepts `""` and preserves it. `ObserveInput.expected_reuse_note`
    // is declared optional agent-supplied guidance behind `#[serde(default)]`
    // (mcp_contract.rs:431-434) and its own module doc states that this member and
    // `write_id` "are genuinely optional agent choices" (mcp_contract.rs:388-390),
    // so no nonempty rule applies to it anywhere and its exception row is frozen.
    // An explicitly empty note is therefore a stated value here, and the absent
    // key asserted further below is a different fact.
    let empty_note: ObserveInput = serde_json::from_str(&with_field(
        &corpus("observe_input_positive.json"),
        "expected_reuse_note",
        "\"\"",
    ))
    .expect("an explicitly empty optional note decodes");
    assert_eq!(empty_note.expected_reuse_note.as_deref(), Some(""));

    let ledger: ProviderCallLedger = decode_fixture("provider_call_ledger_positive.json");
    assert!(ledger.budgets.is_empty());
    assert!(ledger.reservations.is_empty());

    let routing: AgentRoutingView = decode_fixture("agent_routing_view_positive.json");
    assert!(routing.controller_leases.is_empty());
    assert!(routing.work_conflicts.is_empty());

    let observe: ObserveInput = decode_fixture("observe_input_positive.json");
    assert!(observe.affected_resources.is_empty());
    assert!(observe.source_handles.is_empty());
    assert!(observe.expected_reuse_note.is_none());

    let tool_input: CompilePacketToolInput =
        decode_fixture("compile_packet_tool_input_positive.json");
    assert!(tool_input.material_frame.is_none());
    assert!(tool_input.memory_mode.is_none());
    assert!(tool_input.request.candidate_handles.is_empty());

    let policy: ForgettingPolicy = decode_fixture("forgetting_policy_positive.json");
    assert!(policy.evidence_refs.is_empty());
    assert!(policy.scope.is_empty());
    assert!(policy.precondition_refs.is_empty());
}

// WORK_UNIT_CASE: 708/5
#[test]
fn case_05_nested_missing_member_is_refused_and_located() {
    // Case 5: a missing member nested inside an array element or a nested
    // object is refused, and the typed error still names the member.
    assert_refused::<CognitiveFieldProviderPlan>(
        &corpus("nested_missing_cognitive_provider_plan_call_adapter_id.json"),
        "adapter_id",
        "nested_missing_cognitive_provider_plan_call_adapter_id.json",
    );
    assert_refused::<OperatorSnapshot>(
        &corpus("nested_missing_operator_snapshot_worktree_lease_worktree_path.json"),
        "worktree_path",
        "nested_missing_operator_snapshot_worktree_lease_worktree_path.json",
    );
    assert_refused::<AgentRoutingView>(
        &corpus("nested_missing_agent_routing_view_work_lease_epoch.json"),
        "epoch",
        "nested_missing_agent_routing_view_work_lease_epoch.json",
    );

    // The same documents really do carry the enclosing structure, so the
    // refusal above is about the nested member and not about a broken document.
    let snapshot: Value = serde_json::from_str(&corpus(
        "nested_missing_operator_snapshot_worktree_lease_worktree_path.json",
    ))
    .expect("nested snapshot document parses");
    assert!(reaches(&snapshot, "routing.worktree_leases[0]"));
    assert!(!reaches(
        &snapshot,
        "routing.worktree_leases[0].worktree_path"
    ));
    let plan: Value = serde_json::from_str(&corpus(
        "nested_missing_cognitive_provider_plan_call_adapter_id.json",
    ))
    .expect("nested plan document parses");
    assert!(reaches(&plan, "calls[0].runtime_contract_ref"));
    assert!(!reaches(&plan, "calls[0].adapter_id"));
}

// WORK_UNIT_CASE: 708/6
#[test]
fn case_06_unknown_top_level_and_nested_members_are_refused() {
    // Case 6: the closed shapes refuse an unknown member at the top level, in a
    // nested object, and on the hand-written visitor.
    assert_refused::<TaskContract>(
        &corpus("task_contract_unknown_top_level_field.json"),
        "granted_authority",
        "task_contract_unknown_top_level_field.json",
    );
    assert_refused::<OperatorSnapshot>(
        &corpus("operator_snapshot_unknown_nested_field.json"),
        "controller_authority",
        "operator_snapshot_unknown_nested_field.json",
    );
    assert_refused::<CompilePacketToolInput>(
        &corpus("compile_packet_tool_input_unknown_field.json"),
        "write_authority",
        "compile_packet_tool_input_unknown_field.json",
    );
}

// WORK_UNIT_CASE: 708/7
#[test]
fn case_07_repeated_members_are_rejected_at_decode_time() {
    // Case 7: a repeated member is refused at decode time by
    // `strict_json::strict_json_value`, which is the decoder-callsite owner, and
    // by the derived and hand-written decodes that follow it.
    // One of these four documents repeats `policy_ref`, a member
    // `ForgettingPolicy` itself does not declare - it belongs to
    // `MemoryStateTransition` (lifecycle.rs:589). That is deliberate: the strict
    // gate has to classify a repeated member as `DuplicateKey` even on a
    // document a typed decode would also reject for a different reason, which is
    // why this arm asserts the error KIND and not a member name.
    for fixture in [
        "duplicate_member_forgetting_policy_policy_ref.json",
        "duplicate_member_verification_run_verifier_empty.json",
        "duplicate_nested_member_work_lease_scope_permissions.json",
        "compile_packet_tool_input_duplicate_material_frame.json",
    ] {
        let bytes = corpus(fixture).into_bytes();
        let error = strict_json_value(&bytes, bytes.len())
            .expect_err("a repeated member must be refused at decode time");
        assert_eq!(
            error.kind,
            StrictJsonErrorKind::DuplicateKey,
            "{fixture} must report a repeated member, not a malformed document"
        );
    }

    // The same bytes are what a lenient `Value` read would collapse, which is
    // the reason the strict decoder exists.
    let lenient: Value = serde_json::from_str(&corpus(
        "duplicate_member_verification_run_verifier_empty.json",
    ))
    .expect("a lenient value read still parses");
    assert_eq!(
        lenient.get("verifier").and_then(Value::as_str),
        Some(""),
        "the lenient read collapses the repeated member to the last value"
    );
    // The derived `WorkLease` decoder cannot refuse a repeated member: serde_json
    // feeds both `permissions` members to the derived visitor and the last one
    // wins, exactly as the crate records for a derived `flatten` decoder at
    // `mcp_contract.rs:31-32`. This arm therefore states the harm the strict gate
    // exists to prevent, and the hand-written visitor below is the one that
    // refuses a repeat by name.
    let collapsed: WorkLease = serde_json::from_str(&corpus(
        "duplicate_nested_member_work_lease_scope_permissions.json",
    ))
    .expect("a derived struct decode does not refuse a repeated member");
    assert_eq!(
        serde_json::to_value(&collapsed).expect("the collapsed lease re-encodes")["scope"]["authority"]
            ["permissions"],
        json!(["read", "write"]),
        "the derived read collapses the repeated member to the last value"
    );
    // `material_frame` itself carries `#[serde(default)]` (mcp_contract.rs:22-23),
    // so it is not a required member; what refuses this document is the
    // hand-written visitor's duplicate-member arm, which names the repeated key
    // (mcp_contract.rs:87) precisely because a derived `flatten` decoder would
    // keep the last duplicate instead.
    let repeated_frame = corpus("compile_packet_tool_input_duplicate_material_frame.json");
    let frame_error = serde_json::from_str::<CompilePacketToolInput>(&repeated_frame)
        .expect_err("the hand-written visitor must refuse a repeated member");
    assert!(
        frame_error.to_string().contains("material_frame"),
        "the visitor must name the repeated member: {frame_error}"
    );

    // A duplicate-free document still passes the same gate.
    let clean = corpus("forgetting_policy_positive.json").into_bytes();
    let _: Value = strict_json_value(&clean, clean.len())
        .expect("a duplicate-free document must pass the strict decoder");
}

// WORK_UNIT_CASE: 708/8
#[test]
fn case_08_out_of_set_control_vocabulary_fails_and_no_version_gate_exists() {
    // Case 8 covers ONE of this issue's two sub-requirements and now says which,
    // because the version half of the name it used to carry was false.
    //
    // COVERED — a CLOSED CONTROL VOCABULARY SPELLING outside the frozen set is
    // refused by the current decoder. Five arms, unchanged, and no legacy
    // decoder, alias or default is introduced to accept any of them.
    //
    // NOT COVERED, because there is nothing to test — VERSION REJECTION of an
    // unsupported current or legacy version. I searched all nine frozen
    // production files for a version gate, meaning any comparison of a version
    // against a constant and any refusal conditioned on a version. Across all
    // nine files that search returns exactly two hits and BOTH are prose in doc
    // comments, not code:
    //   - mcp_contract.rs:368 and mcp_contract.rs:444, which each describe a gate
    //     owned by `crates/eliot-app/src/mcp_stdio/verification.rs::
    //     dispatch_observe`, a different crate and not one of the nine files.
    // The single version COMPARISON that does exist in the nine files is
    // cognition.rs:1585-1587, inside the `#[cfg(test)] mod contract_tests` of
    // the production file: it asserts the shipped operator-contract manifest's
    // `schema_version` equals `OPERATOR_SCHEMA_VERSION`. That is a version PIN
    // over a shipped string, it is publicly reachable, and it is asserted below
    // — but it refuses nothing and gates no decode, so it is not the gate the
    // old name claimed. The arms below therefore establish the OPPOSITE of the
    // old name: an out-of-set version is accepted and carried, not refused.
    let run: AntigravityRun = decode_fixture("antigravity_run_positive.json");
    assert_eq!(run.state, AntigravityRunState::Succeeded);
    assert_refusal_names::<AntigravityRun>(
        &corpus("antigravity_run_unsupported_state_spelling.json"),
        "SUCCEEDED",
        "a control variant outside the frozen set",
    );
    assert_refusal_names::<ProviderInvocationAttempt>(
        &corpus("provider_invocation_attempt_unsupported_state.json"),
        "PROCESS_TERMINAL_V2",
        "a control variant outside the frozen set",
    );
    assert_refusal_names::<MemoryStateTransition>(
        &corpus("memory_state_transition_legacy_state_outside_vocabulary.json"),
        "retired_demoted",
        "a state spelling outside the frozen set",
    );
    let observe: ObserveInput = decode_fixture("observe_input_positive.json");
    assert_eq!(observe.hint, ObserveHint::Auto);
    assert_refusal_names::<ObserveInput>(
        &corpus("observe_input_unsupported_hint_spelling.json"),
        "Auto",
        "a hint spelling outside the frozen set",
    );

    // An unsupported version is not refused. Substituting it into an otherwise
    // valid current document still decodes, and the decoded value differs from
    // the current decode in the version and in nothing else, which is what a
    // type with no version gate looks like from the outside.
    let retagged: ObserveInput = serde_json::from_str(&with_field(
        &corpus("observe_input_positive.json"),
        "schema_version",
        "\"eliot.observe-v0\"",
    ))
    .expect("an out-of-set version is refused by nothing in this crate");
    assert_eq!(retagged.schema_version, "eliot.observe-v0");
    let mut only_the_version_changed = observe.clone();
    only_the_version_changed.schema_version = "eliot.observe-v0".to_owned();
    assert_eq!(
        retagged, only_the_version_changed,
        "the out-of-set version changes the value and nothing else, so no gate read it"
    );
    let unsupported_version: ObserveInput =
        decode_fixture("observe_input_unsupported_schema_version.json");
    assert_ne!(
        unsupported_version.schema_version, OBSERVE_INPUT_SCHEMA_VERSION,
        "the unsupported fixture must stay off the named current boundary"
    );

    // The second version fact, and the only version behaviour this crate does
    // enforce: the PRIVATE helper `default_observe_schema_version`
    // (mcp_contract.rs:476), wired by `#[serde(default = "...")]` at
    // mcp_contract.rs:472, silently promotes an OMITTED version to the current
    // one. So omission is upgraded to the current boundary while an explicit
    // out-of-set value is carried as written. The helper is private, so this is
    // a wire-side promotion, not a public construction path; case 18 records the
    // same helper from the construction side.
    let omitted: ObserveInput = serde_json::from_value(without(
        serde_json::from_str(&corpus("observe_input_positive.json"))
            .expect("the observe fixture must parse"),
        "schema_version",
    ))
    .expect("omitting the version is not refused either");
    assert_eq!(
        omitted.schema_version, OBSERVE_INPUT_SCHEMA_VERSION,
        "the helper must promote an omitted version to the current one"
    );

    // The one version assertion in the nine files that is publicly reachable.
    // A pin over a shipped string, not a decode gate.
    let manifest: Value =
        serde_json::from_str(OPERATOR_CONTRACT_MANIFEST).expect("the operator manifest must parse");
    assert_eq!(
        manifest.get("schema_version").and_then(Value::as_str),
        Some(OPERATOR_SCHEMA_VERSION),
        "the shipped operator contract manifest carries the pinned schema version"
    );
}

// WORK_UNIT_CASE: 708/9
#[test]
fn case_09_legacy_payloads_decode_only_through_their_named_boundary() {
    // Case 9: retained legacy vocabulary decodes through the current closed
    // decoder, and the one alias this decoder carries is a RECORDED DEFECT, not a
    // sanctioned boundary. `mcp_contract.rs:378-384` states it outright: the
    // current decoder "trial-accepts the same classification hint under two
    // names", APPENDIX-P requires the current decoder to fail closed on a closed
    // control variant, removal needs the renaming owner
    // (`crates/surfaces/eliot-mcp/src/core.rs::decode_protected_request_bytes`),
    // and #708 forbids compensating with an alias, `untagged` or a default. The
    // card also lists `ObserveInput.{hint,schema_version}` among the retained
    // rows this delivery must NOT correct. So the row stays, the disposition
    // stays, and this arm documents the defect rather than endorsing it: it
    // proves the alias is REACHABLE today, so a reviewer can see the trial-accept
    // that has to be closed by its owner. Note the consequence: case 15's
    // fail-closed bypass list pins `mcp_contract.rs:alias` as part of the current
    // state, so the owner's fix will have to update that freeze deliberately.
    // No `untagged` or new trial-accept path is added here.
    let legacy: MemoryStateTransition =
        decode_fixture("memory_state_transition_legacy_from_state.json");
    assert_eq!(legacy.from_state, MemoryLifecycleState::Demoted);
    assert_eq!(legacy.to_state, MemoryLifecycleState::Suppressed);
    let current: MemoryStateTransition = decode_fixture("memory_state_transition_positive.json");
    assert_eq!(current.from_state, MemoryLifecycleState::Active);

    let aliased: ObserveInput = decode_fixture("observe_input_legacy_kind_alias.json");
    assert_eq!(aliased.hint, ObserveHint::ReuseCandidate);
    let named: ObserveInput = decode_fixture("observe_input_positive.json");
    assert_eq!(named.hint, ObserveHint::Auto);
    assert_refusal_names::<ObserveInput>(
        &corpus("observe_input_unsupported_hint_spelling.json"),
        "Auto",
        "a hint spelling outside the frozen set",
    );

    // The legacy operators the lifecycle vocabulary still reads are decoded by
    // the same closed enum, and nothing outside it is reachable.
    let mut legacy_operator: MemoryStateTransition =
        decode_fixture("memory_state_transition_positive.json");
    legacy_operator.operator = ForgettingOperator::MarkPoisoned;
    let re_encoded = serde_json::to_string(&legacy_operator).expect("lifecycle wire re-encodes");
    let decoded: MemoryStateTransition =
        serde_json::from_str(&re_encoded).expect("a retained legacy operator still decodes");
    assert_eq!(decoded.operator, ForgettingOperator::MarkPoisoned);
    let unsupported_operator = re_encoded.replace("\"mark_poisoned\"", "\"retire\"");
    assert!(
        serde_json::from_str::<MemoryStateTransition>(&unsupported_operator).is_err(),
        "a control operator outside the frozen vocabulary must be refused"
    );
}

// WORK_UNIT_CASE: 708/10
#[test]
fn case_10_safe_and_impossible_migration_derivations_are_separated() {
    // Case 10: a derivation that can be made safely is only ever made from a
    // stated wire value, and one that cannot be made safely fails loudly
    // instead of being invented.
    let safe: VerificationRun = decode_fixture("verification_run_explicit_nulls.json");
    assert!(safe.claim_id.is_none());
    assert!(safe.project_id.is_none());
    assert!(safe.memory_revision.is_none());
    assert_eq!(safe.verifier, "verifier-1");
    assert_refused::<VerificationRun>(
        &corpus("verification_run_missing_verifier.json"),
        "verifier",
        "verification_run_missing_verifier.json",
    );

    // `epoch: 0` is a legal value that the wire cannot distinguish from an
    // omitted key, so presence is the only safe derivation.
    let lease_raw = corpus("work_lease_positive.json");
    let explicit_zero = with_field(&lease_raw, "epoch", "0");
    let zeroed: WorkLease =
        serde_json::from_str(&explicit_zero).expect("an explicit zero epoch decodes");
    assert_eq!(zeroed.epoch, 0);
    assert_refused::<WorkLease>(
        &corpus("work_lease_missing_epoch.json"),
        "epoch",
        "work_lease_missing_epoch.json",
    );

    // The authority-free legacy surface keeps its single named null, so its
    // omission stays a legal stored shape while its authority surface does not.
    let authority_free: RecallL0Request = decode_fixture("recall_l0_request_positive.json");
    assert!(authority_free.task_id.is_none());
    assert!(authority_free.lifecycle_audit);
    assert_refused::<RecallL0Request>(
        &corpus("recall_l0_request_missing_lifecycle_audit.json"),
        "lifecycle_audit",
        "recall_l0_request_missing_lifecycle_audit.json",
    );
}

// WORK_UNIT_CASE: 708/11
#[test]
fn case_11_smuggling_every_authority_scope_effect_or_privacy_field_fails() {
    // Case 11: each direction an omitted key could smuggle is refused, and the
    // no-authority sets that state emptiness honestly stay valid.
    // Authority.
    assert_refused::<AgentRoutingView>(
        &corpus("agent_routing_view_missing_worktree_leases.json"),
        "worktree_leases",
        "agent_routing_view_missing_worktree_leases.json",
    );
    // Scope.
    assert_refused::<TaskContract>(
        &corpus("task_contract_missing_verification_scopes.json"),
        "verification_scopes",
        "task_contract_missing_verification_scopes.json",
    );
    assert_refused::<ActionSourceScope>(
        &corpus("action_source_scope_missing_artifact_paths.json"),
        "artifact_paths",
        "action_source_scope_missing_artifact_paths.json",
    );
    // Effect and cost.
    assert_refused::<AutonomyRunView>(
        &corpus("autonomy_run_view_missing_tool_calls_used.json"),
        "tool_calls_used",
        "autonomy_run_view_missing_tool_calls_used.json",
    );
    assert_refused::<UnderstandingProof>(
        &corpus("understanding_proof_missing_blast_radius_acknowledged.json"),
        "blast_radius_acknowledged",
        "understanding_proof_missing_blast_radius_acknowledged.json",
    );
    // Privacy and retention.
    assert_refused::<RecallL0Request>(
        &corpus("recall_l0_request_missing_lifecycle_audit.json"),
        "lifecycle_audit",
        "recall_l0_request_missing_lifecycle_audit.json",
    );
    // Completeness, ordering and recovery visibility.
    assert_refused::<MemoryInspectorView>(
        &corpus("memory_inspector_view_missing_applicability_decisions.json"),
        "applicability_decisions",
        "memory_inspector_view_missing_applicability_decisions.json",
    );
    assert_refused::<OperatorSnapshot>(
        &corpus("operator_snapshot_missing_incidents.json"),
        "incidents",
        "operator_snapshot_missing_incidents.json",
    );
    // Receipt. `AntigravityRun.response_protocol_receipt` is a plain
    // `AntigravityResponseProtocolReceipt` member with no serde attribute
    // (antigravity.rs:778), so an omitted key is a typed error rather than a
    // receipt that reads back as "the response protocol proved nothing". This arm
    // is the receipt-bearing member the smuggling list was missing: every arm
    // above proves an omitted identity, scope, effect, privacy or completion key
    // is refused, and none of them proves the same for a proof receipt.
    assert_refused::<AntigravityRun>(
        &corpus("antigravity_run_missing_response_protocol_receipt.json"),
        "response_protocol_receipt",
        "antigravity_run_missing_response_protocol_receipt.json",
    );
    // `WorktreeLease.worktree_path` is a bare `PathRef` with no serde attribute,
    // so its absence is a typed error. Case 5 proves the same member refused when
    // the lease is nested inside an operator snapshot; this arm proves it on the
    // lease's own named document, so the negative does not depend on the
    // enclosing structure.
    assert_refused::<WorktreeLease>(
        &corpus("worktree_lease_missing_worktree_path.json"),
        "worktree_path",
        "worktree_lease_missing_worktree_path.json",
    );
    // Proof identity.
    assert_refused::<VerificationRun>(
        &corpus("verification_run_missing_verifier.json"),
        "verifier",
        "verification_run_missing_verifier.json",
    );
    // The no-authority set that states emptiness honestly stays valid.
    let observe: ObserveInput = decode_fixture("observe_input_positive.json");
    assert!(observe.affected_resources.is_empty());
    let ledger: ProviderCallLedger = decode_fixture("provider_call_ledger_positive.json");
    assert!(ledger.reservations.is_empty());
}

// WORK_UNIT_CASE: 708/12
#[test]
fn case_12_compatible_current_canonical_bytes_are_unchanged() {
    // Case 12: an accepted current canonical document round-trips to exactly the
    // bytes it was admitted from, so the requiredness correction changed no
    // emitted bytes.
    let canonical = corpus("forgetting_policy_canonical_bytes.json");
    let policy: ForgettingPolicy =
        serde_json::from_str(&canonical).expect("canonical lifecycle bytes decode");
    let re_encoded = serde_json::to_vec(&policy).expect("canonical lifecycle bytes re-encode");
    assert_eq!(
        String::from_utf8(re_encoded.clone()).expect("canonical bytes are UTF-8"),
        canonical.trim_end(),
        "an accepted current canonical document must re-encode byte-identically"
    );
    // The byte comparison above proves round-trip stability of a document this
    // delivery's own author wrote. What used to follow it - a decoded field
    // against the value that produced the bytes it was decoded from, twice -
    // cannot fail once that comparison holds, so both self-comparisons and the
    // round-trip binding they needed are removed and replaced by a property of
    // the DECODE, checked against this oracle's own absence classification:
    // every member `ForgettingPolicy` classifies as absence-tolerant must be
    // stated in the canonical document, so no retained default manufactured a
    // value inside the bytes under test, and each stated null must decode to
    // `None` rather than to a value the decoder invented.
    let canonical_keys: Vec<String> = serde_json::from_str::<Value>(&canonical)
        .expect("the canonical lifecycle document parses as a wire document")
        .as_object()
        .expect("the canonical lifecycle document must be a JSON object")
        .keys()
        .cloned()
        .collect();
    for key in absence_tolerant_keys_for("ForgettingPolicy") {
        assert!(
            canonical_keys.iter().any(|stated| stated == &key),
            "{key} is absence-tolerant, so the canonical bytes must state it rather than let a default supply it"
        );
    }
    assert!(policy.reactivation_condition.is_none());
    assert!(policy.rollback_or_tombstone_ref.is_none());
    assert!(policy.approval_ref.is_none());

    // A paired retained member keeps the store-written bytes stable: the emitted
    // document omits it and still reads back through its own type.
    let transition: MemoryStateTransition = decode_fixture("memory_state_transition_positive.json");
    let transition_bytes =
        serde_json::to_string(&transition).expect("lifecycle transition re-encodes");
    assert!(!transition_bytes.contains("write_receipt"));
    // The two plain `#[serde(default)]` rows are always emitted, so a stored
    // document states their absence instead of dropping the member.
    assert!(transition_bytes.contains("\"reactivation_condition\":null"));
    assert!(transition_bytes.contains("\"approval_ref\":null"));
    let reread: MemoryStateTransition = serde_json::from_str(&transition_bytes)
        .expect("store-written bytes read back through their own type");
    assert!(reread.write_receipt.is_none());
    // The same replacement as above, for the same reason: the transition's
    // `transition_id` self-comparison against the value it was produced from
    // cannot fail once the emitted document is fixed, so it is removed and what is
    // asserted instead is the emitted KEY SET against the oracle's absence
    // classification. A member that gains `default` silently joins the tolerated
    // set, and a member that gains `skip_serializing_if` silently leaves the
    // emitted keys; both fail here.
    let emitted_keys: Vec<String> = serde_json::from_str::<Value>(&transition_bytes)
        .expect("the emitted transition parses as a wire document")
        .as_object()
        .expect("the emitted transition must be a JSON object")
        .keys()
        .cloned()
        .collect();
    let tolerated = absence_tolerant_keys_for("MemoryStateTransition");
    assert_eq!(
        sorted(&tolerated),
        vec![
            "approval_ref".to_owned(),
            "reactivation_condition".to_owned(),
            "write_receipt".to_owned(),
        ],
        "the transition's absence-tolerant members must stay exactly these three"
    );
    for key in &tolerated {
        assert_eq!(
            emitted_keys.iter().any(|stated| stated == key),
            key != "write_receipt",
            "{key}: a plain `default` member is always emitted; only the paired retained member may be omitted"
        );
    }
    assert_refused::<MemoryStateTransition>(
        &corpus("memory_state_transition_missing_expected_admission_effect.json"),
        "expected_admission_effect",
        "memory_state_transition_missing_expected_admission_effect.json",
    );
    let _: ForgettingPolicy = decode_fixture("forgetting_policy_positive.json");

    // Why the emitted bytes did not change: no `Serialize` behaviour was touched
    // on either type, and that is a fact about the declaration, read out of the
    // production source rather than out of this file. `ForgettingPolicy` spells
    // neither attribute on any member, so nothing here can suppress or rewrite
    // an emitted key.
    assert_eq!(
        serializing_attribute_names_in("lifecycle.rs", "ForgettingPolicy"),
        Vec::new(),
        "ForgettingPolicy must declare no skip_serializing_if and no serialize_with: a suppression here would change the canonical bytes"
    );
    // `MemoryStateTransition` is NOT in that shape and is not pretended into it:
    // it keeps exactly one retained paired member whose `skip_serializing_if` is
    // precisely what the store-written bytes above omit. The claim asserted for
    // it is the exact one - no `serialize_with` anywhere, and exactly one
    // `skip_serializing_if`, on `write_receipt` at lifecycle.rs:601. A second
    // suppression on any other member would change which keys this type emits,
    // so both the count and the line are pinned.
    assert_eq!(
        serializing_attribute_names_in("lifecycle.rs", "MemoryStateTransition"),
        vec![("skip_serializing_if".to_owned(), 601)],
        "MemoryStateTransition must keep exactly its one retained paired suppression, on write_receipt"
    );
}

// WORK_UNIT_CASE: 708/13
#[test]
fn case_13_the_seal_covers_the_retained_default_keys_and_refuses_a_missing_seal_key() {
    // RENAMED. The previous name ended `_so_migration_is_required`, which
    // claimed a migration this case does not perform and that nothing in the
    // crate can perform. The new name claims only what the body below proves:
    // the sealed provider plan's own digest recomputes over exactly the emitted
    // keys, so its retained defaults are a digest-seal constraint rather than a
    // compatibility tolerance, and a missing seal key is refused outright. The
    // migration this issue's case 13 asks about is stated, in full, at the end
    // of this body, together with its owner and the evidence that it is absent.
    let plan: CognitiveFieldProviderPlan =
        decode_fixture("cognitive_field_provider_plan_positive.json");
    assert_eq!(
        plan.schema_version,
        COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION
    );
    let mut material = plan.clone();
    material.plan_hash.clear();
    let material_bytes = serde_json::to_vec(&material).expect("plan material serializes");
    assert_eq!(
        format!("blake3:{}", blake3_hex(&material_bytes)),
        plan.plan_hash,
        "the plan seal must recompute over the emitted keys with plan_hash cleared"
    );
    rejects_missing::<CognitiveFieldProviderPlan>(
        serde_json::from_str(&corpus("cognitive_field_provider_plan_positive.json"))
            .expect("plan wire document parses"),
        "planned_reused_roles",
    );
    assert_refused::<CognitiveFieldProviderPlan>(
        &corpus("cognitive_field_provider_plan_missing_plan_hash.json"),
        "plan_hash",
        "cognitive_field_provider_plan_missing_plan_hash.json",
    );
    assert_refused::<CognitiveFieldProviderPlan>(
        &corpus("cognitive_field_provider_plan_missing_seal_generation.json"),
        "seal_generation",
        "cognitive_field_provider_plan_missing_seal_generation.json",
    );

    // Stating one retained seal key changes the sealed bytes, so removing its
    // default would invalidate a published plan rather than relax it.
    let mut sealed = material.clone();
    sealed.seal_attempt_id = Some("attempt-1".to_owned());
    let sealed_bytes = serde_json::to_vec(&sealed).expect("sealed plan material serializes");
    assert_ne!(
        sealed_bytes, material_bytes,
        "a retained seal key must stay inside the digest preimage"
    );
    assert!(
        !material_bytes
            .windows(9)
            .any(|window| window == b"seal_atte".as_slice())
    );

    // The version gate on this record is its owner's, so the type refuses no
    // version by itself; the unsupported fixture therefore decodes and is kept
    // off the named boundary. It is deliberately not its own seal:
    // `schema_version` sits inside the sealed preimage, so changing only the
    // version already invalidates the digest, and asserting the two documents
    // share a `plan_hash` would assert a property of how the corpus file was
    // written rather than of the decoder. The owner's gate is
    // `crates/eliot-app/src/cognitive_field_runner.rs:8354-8364`, whose
    // `validate_provider_plan_hash` compares `plan.schema_version` against
    // `COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION` at :8356 — outside this
    // crate, so no arm here can assert it.
    let unsupported: CognitiveFieldProviderPlan =
        decode_fixture("cognitive_field_provider_plan_unsupported_schema_version.json");
    assert_ne!(
        unsupported.schema_version,
        COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION
    );

    // THE MIGRATION THIS CASE'S ISSUE NUMBER ASKS ABOUT, STATED AS REQUIRED AND
    // NOT IMPLEMENTED. `docs/architecture/I05-22-schema-and-migration-rules.md`
    // requires "core schema is explicit and versioned", "migration
    // IDs/checksums are immutable after release", "additive/forward-compatible
    // change is preferred", and "rollback class is declared". `CognitiveFieldProviderPlan`
    // (crates/eliot-types/src/cognitive_field.rs:442-465) keeps five members on
    // `#[serde(default, skip_serializing_if = "Option::is_none")]` — at :450,
    // :452, :455, :457 and :459 — and the arms above prove those members sit
    // INSIDE the `plan_hash` preimage. So removing any one of them is not a
    // compatible requiredness correction: it changes the sealed bytes and
    // invalidates every plan already published under this schema version.
    //
    // What that obliges, and what does not exist anywhere in this repository:
    //   - a named schema version bump off `eliot-cognitive-field-provider-plan-v1`,
    //     because I5.22 makes a migration checksum immutable after release and
    //     the current preimage cannot be edited in place;
    //   - a forward-repair migration that re-seals every already-published plan
    //     under the new emitted key set and re-emits `plan_hash`, since the
    //     sealed artifacts live outside the type and are addressed by
    //     generation (`sealed/<generation>`, crates/eliot-app/src/
    //     cognitive_field_runner.rs:2233), not by this record;
    //   - a migration ID and a schema snapshot plus receipt per I5.22, and a
    //     DECLARED ROLLBACK CLASS, which this record does not have today;
    //   - and nothing else: no `Default`, alias or `untagged` compensation,
    //     which this issue forbids.
    //
    // EVIDENCE THAT NONE OF IT EXISTS, so this is a statement about the tree and
    // not a guess: a case-insensitive search of the plan's owner,
    // `crates/eliot-app/src/cognitive_field_runner.rs`, for `reseal`, `re-seal`
    // or `migrat` returns zero matches (rg exit 1). The owner exposes only
    // `provider_plan_without_hash` (:9032), `validate_provider_plan_hash`
    // (:8354) and `next_seal_generation` (:1737), and no migration identifier,
    // snapshot or rollback class appears on the record or in its owner.
    //
    // OWNER of the unimplemented migration: `crates/eliot-app/src/
    // cognitive_field_runner.rs` together with the record type at
    // `crates/eliot-types/src/cognitive_field.rs:442`. Its own field table
    // already records the same dependency at cognitive_field.rs:438-439 — the
    // `role_evidence_plan_hash` row "needs a migration decision from the
    // `plan_hash` owner, which lives outside this issue's file scope".
}

// WORK_UNIT_CASE: 708/14
#[test]
fn case_14_replay_cannot_collapse_a_missing_and_an_empty_member() {
    // Case 14: a stored document replayed through its own type cannot turn a
    // missing member into an empty one, or an omitted one into a stated value.
    let bound: VerificationRun = decode_fixture("verification_run_positive.json");
    let bound_bytes = serde_json::to_string(&bound).expect("verification run serializes");
    let unbound: VerificationRun = decode_fixture("verification_run_explicit_nulls.json");
    let unbound_bytes = serde_json::to_string(&unbound).expect("verification run serializes");
    assert_ne!(
        bound_bytes, unbound_bytes,
        "a stated binding and a stated absence must not replay to one document"
    );
    let replayed: VerificationRun =
        serde_json::from_str(&unbound_bytes).expect("the replayed document still decodes");
    assert!(replayed.claim_id.is_none());
    assert_eq!(replayed.verifier, unbound.verifier);

    // The retained paired row declares absent and explicit null as one fact, and
    // the replayed bytes are the same document for both.
    let recall_raw = corpus("recall_l0_request_positive.json");
    let absent: RecallL0Request = decode_fixture("recall_l0_request_positive.json");
    let stated_null: RecallL0Request =
        serde_json::from_str(&with_field(&recall_raw, "task_id", "null"))
            .expect("explicit null task_id decodes");
    let absent_bytes = serde_json::to_string(&absent).expect("recall request serializes");
    let null_bytes = serde_json::to_string(&stated_null).expect("recall request serializes");
    assert_eq!(
        absent_bytes, null_bytes,
        "the retained paired row declares one fact for absent and explicit null"
    );
    assert!(!absent_bytes.contains("task_id"));
    let stated_value: RecallL0Request = serde_json::from_str(&with_field(
        &recall_raw,
        "task_id",
        "\"00000000-0000-7000-8000-000000000009\"",
    ))
    .expect("stated task_id decodes");
    let value_bytes = serde_json::to_string(&stated_value).expect("recall request serializes");
    assert_ne!(value_bytes, absent_bytes);
    assert!(value_bytes.contains("task_id"));

    // The lifecycle transition keeps absent and explicit null as one stored
    // fact, and a value changes the replayed document.
    let transition_raw = corpus("memory_state_transition_positive.json");
    let transition_null: MemoryStateTransition =
        serde_json::from_str(&with_field(&transition_raw, "approval_ref", "null"))
            .expect("explicit null approval_ref decodes");
    let transition_value: MemoryStateTransition = serde_json::from_str(&with_field(
        &transition_raw,
        "approval_ref",
        "\"approval-1\"",
    ))
    .expect("stated approval_ref decodes");
    let transition: MemoryStateTransition = decode_fixture("memory_state_transition_positive.json");
    assert!(transition.approval_ref.is_none());
    assert!(transition_null.approval_ref.is_none());
    assert_eq!(transition_value.approval_ref.as_deref(), Some("approval-1"));
    assert_ne!(
        serde_json::to_string(&transition).expect("transition serializes"),
        serde_json::to_string(&transition_value).expect("transition serializes")
    );
}

// WORK_UNIT_CASE: 708/15
#[test]
#[allow(clippy::too_many_lines)]
fn case_15_the_source_oracle_reuses_the_shipped_inventory_vocabulary() {
    // Case 15: the package-local source oracle over the default sites. It reads
    // the classification vocabulary and the unsupported-syntax handling out of
    // `scripts/serde_boundary_inventory.py` instead of owning a second copy.
    // This is a source-scan oracle; the decode proof it guards is the one the
    // other nineteen cases execute against this crate's own types.
    let policy: ForgettingPolicy = decode_fixture("forgetting_policy_positive.json");
    assert_eq!(policy.policy_id, "policy-1");

    let script = std::fs::read_to_string(
        workspace_root()
            .join("scripts")
            .join("serde_boundary_inventory.py"),
    )
    .unwrap_or_else(|error| {
        panic!("the shipped serde-boundary inventory script must be readable: {error}")
    });

    let dispositions = quoted_literals(&python_block(&script, "DISPOSITIONS = (", ")"));
    let protected = quoted_literals(&python_block(&script, "PROTECTED_FIELDS = frozenset(", ")"));
    let bypass = quoted_literals(&python_block(&script, "BYPASS_SHAPES = frozenset(", ")"));

    // The classification vocabulary is the script's, compared as a set.
    let owned: Vec<String> = FROZEN_DISPOSITIONS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    assert_eq!(
        sorted(&dispositions),
        sorted(&owned),
        "the oracle's disposition vocabulary must be the shipped inventory's"
    );
    for dimension in [
        "identity",
        "scope",
        "authority",
        "provenance",
        "privacy",
        "retry",
        "receipt",
        "finish",
        "completeness",
    ] {
        assert!(
            protected.iter().any(|value| value == dimension),
            "the shipped protected dimensions must keep {dimension}"
        );
    }
    for shape in ["flatten", "untagged", "alias", "manual-visitor"] {
        assert!(
            bypass.iter().any(|value| value == shape),
            "the shipped bypass shapes must keep {shape}"
        );
    }

    // The unsupported-syntax handling is the script's too: the same evidence
    // prefix and the same unreadable-source kind. These two probes are the WEAK
    // half of that claim - a comment anywhere in the script would satisfy them -
    // so they are stated as what they are, with messages, and the BEHAVIOURAL
    // half of the claim is the `unresolved == 0` assertion below, which is the
    // same rule the script applies: an unresolved site is incomplete, never
    // clean.
    assert!(
        script.contains("unsupported-macro: "),
        "the shipped inventory must keep its unsupported-macro evidence prefix"
    );
    assert!(
        script.contains("unreadable-source"),
        "the shipped inventory must keep its unreadable-source kind"
    );

    // The three patterns this oracle mirrors are the script's own, by name:
    // `_MACRO_UNSUPPORTED_RE` (:682) and `_MAKE_MACRO_CALL_RE` (:683), folded
    // into one `unsupported-macro` row per site there (:1236-1288), and
    // `_MANUAL_IMPL_RE` (:672). Weak probes for the same reason as the two above,
    // and stated as such.
    for pattern in [
        "_MACRO_UNSUPPORTED_RE",
        "_MAKE_MACRO_CALL_RE",
        "_MANUAL_IMPL_RE",
    ] {
        assert!(
            script.contains(pattern),
            "the shipped inventory must keep {pattern}: the oracle mirrors it"
        );
    }
    // The classification those rows carry is read out of the script's own
    // `_classify` branch for `unreadable-source` and `unsupported-macro` rather
    // than restated here: an `unknown` row is `BLOCKED` and `NOT_SAFE`, and that
    // is the grade `discovered_unsupported_macros` puts on every site it finds.
    let unknown_branch = python_block(
        &script,
        "if kind in (\"unreadable-source\", \"unsupported-macro\"):\n        return {",
        "\n    if test_scope:",
    );
    for value in [
        "\"disposition\": \"unknown\"",
        "\"repair_readiness\": \"BLOCKED\"",
        "\"safety\": \"NOT_SAFE\"",
    ] {
        assert!(
            unknown_branch.contains(value),
            "the shipped unknown classification must keep {value}: {unknown_branch}"
        );
    }

    let sites = discovered_default_sites();
    let unresolved = sites
        .iter()
        .filter(|site| site.key.contains("<unresolved"))
        .count();
    assert_eq!(
        unresolved, 0,
        "an unresolvable default site is incomplete evidence, never a clean scan"
    );
    assert_eq!(
        sites.len(),
        EXPECTED_DEFAULT_SITE_COUNT,
        "the discovered default-site denominator must equal the frozen count"
    );

    // Direct, helper and paired forms are each detected by shape, not by name.
    // The names are compared as a set: the scan order is the sorted site key,
    // and the frozen list is written in the nine-file domain order.
    let helpers: Vec<String> = sites
        .iter()
        .filter(|site| site.form == DefaultForm::Helper)
        .map(|site| site.key.as_str().to_owned())
        .collect();
    let expected_helpers: Vec<String> = EXPECTED_HELPER_DEFAULT_SITES
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    assert_eq!(
        sorted(&helpers),
        sorted(&expected_helpers),
        "a helper-shaped default is an effectively defaulted field and must stay enumerated"
    );
    let paired = sites
        .iter()
        .filter(|site| site.form == DefaultForm::Paired)
        .count();
    assert_eq!(
        paired, EXPECTED_PAIRED_DEFAULT_SITE_COUNT,
        "the paired skip_serializing_if rows must stay enumerable"
    );
    assert!(sites.iter().any(|site| site.form == DefaultForm::Direct));

    // The second absence class, `absent-becomes-none`: named members of a
    // `struct` item whose declared type is a bare `Option<...>` with neither
    // `default` nor `deserialize_with`/`with`. serde cannot refuse these, so
    // this is the other half of what case 19 is allowed to tolerate. It is named
    // here and nowhere else: the shipped inventory's `DISPOSITIONS` is untouched,
    // and none of these sites is exempt from the class.
    //
    // The frozen denominator is asserted twice over: once as a size, and once as
    // a per-file `file:line` list, so a member that moves fails even when the
    // total is unchanged.
    let bare = discovered_bare_option_sites();
    assert_eq!(
        bare.len(),
        EXPECTED_BARE_OPTION_SITE_COUNT,
        "the absent-becomes-none denominator must equal the frozen count"
    );
    let discovered_lines: Vec<(&str, Vec<usize>)> = NINE_FILES
        .iter()
        .map(|file| {
            (
                *file,
                bare.iter()
                    .filter(|site| site.file == *file)
                    .map(|site| site.line)
                    .collect(),
            )
        })
        .collect();
    let frozen_lines: Vec<(&str, Vec<usize>)> = EXPECTED_BARE_OPTION_SITE_LINES
        .iter()
        .map(|(file, lines)| (*file, (*lines).to_vec()))
        .collect();
    assert_eq!(
        discovered_lines, frozen_lines,
        "every absent-becomes-none site must stay enumerated at its own file:line"
    );
    for site in &bare {
        let key = site.key.as_str();
        let segments: Vec<&str> = key.split("::").collect();
        assert_eq!(segments.len(), 2, "{key} must name one file and one member");
        let member = segments[1];
        assert!(
            member.contains('.') && !member.contains('*'),
            "{key} must name one field exactly, never a type-wide wildcard"
        );
    }
    // The two classes are disjoint by construction: a site carrying a default
    // token is a default site, never a bare-`Option` one, so case 19's tolerated
    // set is a union and never a double count that could hide a member.
    assert!(
        !discovered_default_sites()
            .iter()
            .any(|site| bare.iter().any(|bare_site| bare_site.key == site.key)),
        "a default site and an absent-becomes-none site must never be the same field"
    );
    // The shape this class excludes is the shape that really is required: a
    // member carrying `default`, or a `deserialize_with`/`with` on an
    // `Option<T>`, still has a refusal on absence and must not appear here.
    // `AntigravitySafetyReceipt.model_observation` carries `deserialize_with`,
    // `ProviderInvocationAttempt` carries ten more, and the `with =
    // "time::serde::rfc3339::option"` members are required for the same reason.
    for key in [
        "antigravity.rs::AntigravitySafetyReceipt.model_observation",
        "provider_invocation.rs::ProviderInvocationAttempt.provider_route_policy",
        "provider_invocation.rs::ProviderInvocationAttempt.timeout_class",
        "provider_invocation.rs::ProviderInvocationAttempt.process_reap_receipt",
        "provider_invocation.rs::ProviderInvocationAttempt.process_timed_out",
        "provider_invocation.rs::ProviderInvocationAttempt.process_cancelled",
        "provider_invocation.rs::ProviderInvocationAttempt.process_worker_error",
        "provider_invocation.rs::ProviderInvocationAttempt.stdout_total_bytes",
        "provider_invocation.rs::ProviderInvocationAttempt.stderr_total_bytes",
        "provider_invocation.rs::ProviderInvocationAttempt.stdout_truncated",
        "provider_invocation.rs::ProviderInvocationAttempt.stderr_truncated",
        "memory.rs::WorkLease.released_at",
        "memory.rs::WorkLease.revoked_at",
        "antigravity.rs::AntigravityRun.completed_at",
        "provider_invocation.rs::ProviderInvocationAttempt.dispatch_started_at",
    ] {
        assert!(
            !bare.iter().any(|site| site.key == key),
            "{key} carries a default or a deserialize_with/with, so its absence really is refused"
        );
    }

    // The bypass shapes on the nine-file domain, using the script's own shape
    // vocabulary: eight named compat `alias` rows on the antigravity smoke and
    // scope spellings, one `alias` and one `flatten` on the flat tool input, no
    // `untagged`, and the single hand-written visitor that owns that input.
    assert_eq!(
        declared_bypass_shapes(),
        vec![
            "antigravity.rs:alias".to_owned(),
            "antigravity.rs:alias".to_owned(),
            "antigravity.rs:alias".to_owned(),
            "antigravity.rs:alias".to_owned(),
            "antigravity.rs:alias".to_owned(),
            "antigravity.rs:alias".to_owned(),
            "antigravity.rs:alias".to_owned(),
            "antigravity.rs:alias".to_owned(),
            "mcp_contract.rs:alias".to_owned(),
            "mcp_contract.rs:flatten".to_owned(),
        ],
        "a new flatten, untagged or alias shape must fail closed"
    );

    // Unsupported syntax: a serde-like macro in the nine-file domain generates
    // deserialization this oracle cannot read, which is the one condition the
    // shipped inventory refuses to classify at all. There are none today, and
    // the first one must fail closed.
    //
    // The rule is that every discovered site carries the script's grade
    // (`unknown`/`BLOCKED`/`NOT_SAFE`) and names no exception-table row, because a
    // macro site names a position rather than a field. This arm used to be a loop
    // over the discovered sites, which could not execute: the frozen denominator
    // is zero, so the loop body was dead code and neither of its two assertions
    // could ever fail. What is asserted now is the premise that rule rests on -
    // the discovered set is empty - which is the only statement about the
    // nine-file domain that is true today, and which still fails closed the moment
    // a macro site appears. Because the set is empty, "no site violates the grade
    // rule" and "no site names an exception row" hold vacuously HERE, not
    // verified here.
    //
    // The rule is not dropped, it is executed against real sites elsewhere in this
    // file: the scanner-fixture case at the end of this file points this same
    // scanner at `tests/data/appendix-p-scanner/unsupported_macro_site.rs`, whose
    // one real site is discovered there and compared against the grade and kind
    // that site declares. So the grade rule is tested; only its zero-site
    // statement in this case is stated as the premise instead of faked as a loop.
    let macros = discovered_unsupported_macros();
    assert!(
        macros.is_empty(),
        "the discovered unsupported-macro set must be empty, because every site in it would carry the shipped grade and no exception row, and no such site exists: {macros:?}"
    );
    assert_eq!(
        macros.len(),
        EXPECTED_UNSUPPORTED_MACRO_SITE_COUNT,
        "a serde-like macro in the nine-file domain is unsupported syntax this oracle cannot resolve: {macros:?}"
    );

    let manual = manual_decoder_impls();
    assert_eq!(
        manual.len(),
        1,
        "a new hand-written decoder in the nine-file domain must fail closed: {manual:?}"
    );
    assert!(
        manual[0].starts_with("mcp_contract.rs:"),
        "the one hand-written decoder in the nine-file domain is the flat tool input: {manual:?}"
    );
}

// WORK_UNIT_CASE: 708/16
#[test]
fn case_16_every_default_site_has_a_field_exact_exception() {
    // Case 16: the oracle fails closed. Every discovered default site carries a
    // field-exact exception with a disposition from the shipped vocabulary, and
    // a file-wide or type-wide exception is not an acceptable key.
    let frame: MaterialPacketFrame = decode_fixture("material_packet_frame_retained_omitted.json");
    assert!(frame.invariant_refs.is_empty());
    let stated: MaterialPacketFrame = decode_fixture("material_packet_frame_positive.json");
    assert!(stated.invariant_refs.is_empty());

    let sites = discovered_default_sites();
    assert_eq!(sites.len(), EXPECTED_DEFAULT_SITE_COUNT);

    let exceptions: Vec<&str> = DEFAULT_SITE_EXCEPTIONS
        .iter()
        .map(|(key, _disposition)| *key)
        .collect();
    assert_eq!(
        exceptions.len(),
        EXPECTED_DEFAULT_SITE_COUNT,
        "the exception table must carry exactly one row per discovered default site"
    );

    let discovered: Vec<&str> = sites.iter().map(|site| site.key.as_str()).collect();
    for key in &discovered {
        assert!(
            exceptions.contains(key),
            "{key} is a default site with no field-exact exception"
        );
    }
    for key in &exceptions {
        assert!(
            discovered.contains(key),
            "{key} is an exception row with no default site in the scanned domain"
        );
        let segments: Vec<&str> = key.split("::").collect();
        assert_eq!(segments.len(), 2, "{key} must name one file and one member");
        let member = segments[1];
        assert!(
            member.contains('.') && !member.contains('*'),
            "{key} must name one field exactly, never a type-wide wildcard"
        );
    }

    let disposition_names: Vec<String> = DEFAULT_SITE_EXCEPTIONS
        .iter()
        .map(|(_key, disposition)| (*disposition).to_owned())
        .collect();
    for disposition in &disposition_names {
        assert!(
            FROZEN_DISPOSITIONS.contains(&disposition.as_str()),
            "{disposition} is not one of the shipped dispositions"
        );
        assert_ne!(
            disposition, "unknown",
            "an unknown disposition is incomplete evidence, never a clean row"
        );
    }
    let mut owners: Vec<&str> = DEFAULT_SITE_EXCEPTIONS
        .iter()
        .filter(|(_key, disposition)| *disposition == "specific-owner")
        .map(|(key, _disposition)| *key)
        .collect();
    owners.sort_unstable();
    assert_eq!(
        owners,
        EXPECTED_SPECIFIC_OWNER_ROWS.to_vec(),
        "the specific-owner exception set must not broaden without its named owner"
    );
}

// WORK_UNIT_CASE: 708/17
#[test]
fn case_17_reviewed_legitimate_internal_defaults_are_retained() {
    // Case 17: the retained rows still decode, with the exact semantics each
    // row declares.
    //
    // NOT ASSERTED IN THIS CASE, recorded here so the gap lives in the test and
    // not only in a report: required item 17 asks that every retained legitimate
    // internal default be "bounded by caller evidence", and NO case in this file
    // asserts any caller evidence at all. What the arms below assert is that each
    // retained row still decodes to its declared value; every citation of a
    // caller is prose, in this comment block, in the frozen field inventory, or
    // in a production doc comment, and none of them is checked from source here.
    // What would be required: a per-row `(field, caller_file, caller_symbol)`
    // constant naming, for each retained row, the exact current caller that
    // supplies the default or relies on it, plus a source assertion that each
    // named caller still exists and still reads that member - so a caller that
    // moves or drops the read invalidates its own exemption instead of leaving a
    // stale row behind. That is a second inventory over caller sites rather than
    // an addition to this one, and it is deliberately not built here: against a
    // file that already carries thirteen derived constants, a hand-kept caller
    // table would assert compatibility that nothing re-checks.
    //
    // `ObserveInput.hint` keeps the `named-legacy` disposition, and that label
    // names a boundary that does not exist. The member carries
    // `#[serde(default, alias = "kind")]`, so the decoder trial-accepts a `"kind"`
    // spelling, and an evidence pass over the workspace found no named legacy
    // decoder, versioned migration, provenance record or loss/assumption note
    // anywhere for that spelling: the only writer of the key emits the canonical
    // `"hint"` (`crates/eliot-app/src/mcp_stdio/verification.rs:86`), `schemars`
    // never reads an alias, and the `legacy` mentions in that file concern the
    // candidate-submit route and the quarantined verifier lane, not this alias. So
    // the disposition label asserts a compatibility boundary that no owner has
    // ever named - the W4 defect `mcp_contract.rs:378-384` records. Recorded here
    // as a comment only: neither the disposition string nor the row is changed
    // here, because removing the alias is the #706/#831 renaming owner's decision,
    // not this file's.
    //
    // Retained breaking candidates: they decode today and their five missing
    // keys take their declared defaults.
    let omitted: MaterialPacketFrame =
        decode_fixture("material_packet_frame_retained_omitted.json");
    assert!(omitted.invariant_refs.is_empty());
    assert!(omitted.waived_invariants.is_empty());
    assert!(omitted.prediction_confidence.is_none());
    assert!(omitted.predicted_changed_paths.is_empty());
    assert!(omitted.predicted_failing_verifiers.is_empty());

    // Paired optional members: absent and explicit null stay one fact.
    let preview: MemoryHandlePreview = decode_fixture("memory_handle_preview_positive.json");
    assert!(preview.lifecycle_state.is_none());
    assert!(preview.lifecycle_badge.is_none());

    // Monotone counters: an older record understates benefit and can never
    // fabricate it.
    let stated: MemoryVitalityScore = decode_fixture("memory_vitality_score_positive.json");
    assert_eq!(stated.decision, MemoryEcologyDecision::KeepHot);
    assert_eq!(stated.beneficial_use_count, 2);
    let understated: MemoryVitalityScore =
        decode_fixture("memory_vitality_score_counters_omitted.json");
    assert_eq!(understated.beneficial_use_count, 0);
    assert_eq!(understated.context_cost_tokens, 0);
    assert_eq!(understated.decision, MemoryEcologyDecision::KeepHot);

    // Fail-closed freshness: a record predating a dimension reads as empty and
    // therefore compares stale.
    let current: EvalIntegrityFingerprintSet =
        decode_fixture("eval_integrity_fingerprint_set_positive.json");
    assert_eq!(current.oracle_version, "");
    assert_eq!(current.product_identity, "");
    assert!(current.is_stale_against(&EvalIntegrityFingerprintSet {
        oracle_version: "0.4.0".to_owned(),
        product_identity: "eliot".to_owned(),
        ..current.clone()
    }));
    let case_result: EvalCaseResult = decode_fixture("eval_case_result_positive.json");
    assert!(case_result.integrity_fingerprints.is_none());

    // Coherent absence: an unstated run boundary stays absent.
    let suite: EvalSuite = decode_fixture("eval_suite_positive.json");
    assert!(suite.frozen_at.is_none());
    let run: EvalRun = decode_fixture("eval_run_positive.json");
    assert!(run.finished_at.is_some());
    let gravity: MemoryGravity = decode_fixture("memory_gravity_positive.json");
    assert_eq!(gravity.activation_pressure_millis, 0);
    assert_eq!(gravity.decision, MemoryEcologyDecision::KeepHot);

    // Helper defaults: the owner-declared values are the frozen constants.
    let query: OperatorQueryRequest = decode_fixture("operator_query_request_positive.json");
    assert_eq!(query.expand_depth, 1);
    assert_eq!(query.result_mode, OperatorResultMode::Human);
    let packet: CompilePacketL3Request = decode_fixture("compile_packet_l3_request_positive.json");
    assert_eq!(packet.max_tokens, DEFAULT_CONTEXT_PACKET_PREFERRED_TOKENS);

    // The retained capture-first defaults, including the trial-accept the field
    // table records rather than hides.
    let observe: ObserveInput = decode_fixture("observe_input_positive.json");
    assert_eq!(observe.schema_version, OBSERVE_INPUT_SCHEMA_VERSION);
    assert!(observe.write_id.is_none());
    let submit: AgentCandidateSubmitInput =
        decode_fixture("agent_candidate_submit_input_positive.json");
    assert!(submit.cue_bindings.is_empty());
    let curation: AgentCandidateCurationInput =
        decode_fixture("agent_candidate_curation_input_positive.json");
    assert_eq!(curation.duplicate_of, None);
    assert!(!curation.protected);

    let recall: RecallL0Request = decode_fixture("recall_l0_request_positive.json");
    assert!(recall.task_id.is_none());
}

// WORK_UNIT_CASE: 708/18
#[test]
#[allow(clippy::too_many_lines)]
fn case_18_constructor_and_helper_paths_cannot_bypass_requiredness() {
    // Case 18 is two DIFFERENT questions, and the comment this one replaces
    // answered neither of them. It claimed "no public constructor, helper or
    // `Default` path supplies a required key". That was false, and the arms
    // below are what makes it false.
    //
    //   1. DECODER: does the decoder refuse a document that omits a required
    //      key? The 39 arms that follow are this question ONLY, and they answer
    //      yes for every one of those 39 types.
    //   2. CONSTRUCTION: can a public path manufacture the value anyway? Thirty
    //      types in the nine frozen files publish `Default` — twenty structs
    //      (eighteen derived, plus `impl Default` at lifecycle.rs:813 and
    //      antigravity.rs:484) and ten fieldless enums — and for SEVENTEEN of
    //      the twenty structs that `Default` supplies every required key the
    //      empty-object refusal depends on. An empty object is refused and
    //      `<Type>::default()` is accepted, so on those seventeen types
    //      `Default` IS a requiredness bypass. For the other three the wire has
    //      no required key at all, so there is nothing there to bypass, and each
    //      of those arms says so rather than manufacturing a failure.
    //
    // Every construction arm below builds the value through the REAL public
    // path and asserts what is actually true of it, in one of the four shapes
    // the block names: supplies-every-required-key, supplies-nothing-to-bypass,
    // states-a-key-the-decoder-would-refuse, or supplies-a-control-value. Nothing
    // here weakens an assertion to make a name fit, and nothing here claims a
    // path is safe that the arms have not checked.

    // The two assertion shapes the construction arms below use. They are nested
    // items so their scope is exactly this case, they are declared before any
    // statement so nothing sits between declarations, and neither can pass
    // vacuously: the member count is what stops "the `Default` path wrote
    // nothing" from reading as success, and the re-decode is what stops a
    // hand-written shape from standing in for the real manufactured one.
    fn default_states_exactly<T: serde::Serialize + DeserializeOwned>(
        defaulted: &T,
        members: usize,
    ) {
        let wire = serde_json::to_value(defaulted).expect("the type serializes");
        assert_eq!(
            wire.as_object()
                .expect("the type serializes as a JSON object")
                .len(),
            members,
            "the Default path must state exactly the members this arm names"
        );
        serde_json::from_value::<T>(wire).expect("the manufactured document must decode");
    }

    fn default_names_variant<T>(defaulted: T, spelling: &str)
    where
        T: Copy + serde::Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let wire = serde_json::to_value(defaulted).expect("the variant serializes");
        assert_eq!(
            wire,
            json!(spelling),
            "the default variant has exactly one wire spelling"
        );
        assert_eq!(
            serde_json::from_value::<T>(wire).expect("that spelling decodes"),
            defaulted,
            "the manufactured control value is a value the wire accepts"
        );
        assert!(
            serde_json::from_value::<T>(json!({})).is_err(),
            "a document that names no variant is still refused"
        );
    }

    assert!(serde_json::from_value::<WorkLease>(json!({})).is_err());
    assert!(serde_json::from_value::<ProviderCallLedger>(json!({})).is_err());
    assert!(serde_json::from_value::<AutonomyRunContract>(json!({})).is_err());
    assert!(serde_json::from_value::<ForgettingPolicy>(json!({})).is_err());
    assert!(serde_json::from_value::<MemoryStateTransition>(json!({})).is_err());
    assert!(serde_json::from_value::<AntigravityRun>(json!({})).is_err());
    assert!(serde_json::from_value::<AntigravitySafetyReceipt>(json!({})).is_err());
    assert!(serde_json::from_value::<CognitiveFieldProviderCallPlan>(json!({})).is_err());
    assert!(serde_json::from_value::<CognitiveFieldProviderEvidenceReceipt>(json!({})).is_err());
    assert!(serde_json::from_value::<CognitiveFieldProviderProjection>(json!({})).is_err());
    assert!(serde_json::from_value::<CognitiveFieldProviderPlan>(json!({})).is_err());
    assert!(serde_json::from_value::<CausalCandidate>(json!({})).is_err());
    assert!(serde_json::from_value::<TaskCognitionView>(json!({})).is_err());
    assert!(serde_json::from_value::<MemoryInspectorView>(json!({})).is_err());
    assert!(serde_json::from_value::<AgentRoutingView>(json!({})).is_err());
    assert!(serde_json::from_value::<AutonomyRunView>(json!({})).is_err());
    assert!(serde_json::from_value::<OperatorSnapshot>(json!({})).is_err());
    assert!(serde_json::from_value::<TaskAcceptanceItem>(json!({})).is_err());
    assert!(serde_json::from_value::<ActionSourceScope>(json!({})).is_err());
    assert!(serde_json::from_value::<TaskContract>(json!({})).is_err());
    assert!(serde_json::from_value::<TaskContractInput>(json!({})).is_err());
    assert!(serde_json::from_value::<VerificationRun>(json!({})).is_err());
    assert!(serde_json::from_value::<RecallL0Request>(json!({})).is_err());
    assert!(serde_json::from_value::<UnderstandingProof>(json!({})).is_err());
    assert!(serde_json::from_value::<UnderstandingProofReceipt>(json!({})).is_err());
    assert!(serde_json::from_value::<DelegationRequest>(json!({})).is_err());
    assert!(serde_json::from_value::<ProviderInvocationAttempt>(json!({})).is_err());
    assert!(serde_json::from_value::<MaterialPacketFrame>(json!({})).is_err());
    assert!(serde_json::from_value::<AgentCandidateSubmitInput>(json!({})).is_err());
    assert!(serde_json::from_value::<AgentCandidateCurationInput>(json!({})).is_err());
    assert!(serde_json::from_value::<ObserveInput>(json!({})).is_err());
    assert!(serde_json::from_value::<CompilePacketToolInput>(json!({})).is_err());
    assert!(serde_json::from_value::<CompilePacketL3Request>(json!({})).is_err());
    assert!(serde_json::from_value::<EvalSuite>(json!({})).is_err());
    assert!(serde_json::from_value::<EvalCaseResult>(json!({})).is_err());
    assert!(serde_json::from_value::<MemoryVitalityScore>(json!({})).is_err());
    assert!(serde_json::from_value::<MemoryHandlePreview>(json!({})).is_err());
    assert!(serde_json::from_value::<OperatorQueryRequest>(json!({})).is_err());
    assert!(serde_json::from_value::<OperatorCommandReceipt>(json!({})).is_err());

    // ---- CONSTRUCTION, shape 1: derived `Default` on a struct whose wire HAS
    // required keys. The empty object is refused and `Default` supplies every
    // one of those keys, so on each of these types `Default` is a requiredness
    // bypass. That is the finding, stated as a finding.

    // cognition.rs:117 `EpistemicPacketState` — four required keys.
    assert!(serde_json::from_value::<EpistemicPacketState>(json!({})).is_err());
    default_states_exactly(&EpistemicPacketState::default(), 4);
    // cognition.rs:126 `DecisionLocalitySuffix` — eight required keys, four of
    // them vectors and four of them strings including `next_allowed_action`.
    assert!(serde_json::from_value::<DecisionLocalitySuffix>(json!({})).is_err());
    default_states_exactly(&DecisionLocalitySuffix::default(), 8);
    assert!(
        DecisionLocalitySuffix::default()
            .next_allowed_action
            .is_empty()
    );
    // cognition.rs:154 `MaterialPacketFrame` — sixteen required keys plus the
    // five retained prediction/invariant `#[serde(default)]` members at
    // cognition.rs:214-231, so `Default` writes all twenty-one. The corpus
    // document states the same twenty-one.
    assert!(serde_json::from_value::<MaterialPacketFrame>(json!({})).is_err());
    default_states_exactly(&MaterialPacketFrame::default(), 21);
    // cognition.rs:771 `NegativeMemoryGateInput` — six required keys, and
    // `Default` supplies `fingerprint` as an empty string, i.e. a negative-memory
    // gate keyed on no fingerprint.
    assert!(serde_json::from_value::<NegativeMemoryGateInput>(json!({})).is_err());
    default_states_exactly(&NegativeMemoryGateInput::default(), 6);
    assert!(NegativeMemoryGateInput::default().fingerprint.is_empty());
    // cognition.rs:1414 `MemoryCurationCorpusProfile` — five required keys, two
    // of them through the duplicate-rejecting map decoder at cognition.rs:1380,
    // which `Default` satisfies with an empty map.
    assert!(serde_json::from_value::<MemoryCurationCorpusProfile>(json!({})).is_err());
    default_states_exactly(&MemoryCurationCorpusProfile::default(), 5);
    // memory.rs:999 `RecallConflictObservation` — two required keys, and here the
    // fabricated VALUE is the whole point: the member's own doc comment at
    // memory.rs:1000-1001 says `false` means "the owner never looked, not that it
    // looked and found none". `Default` states that never-looked answer with no
    // owner having looked.
    assert!(serde_json::from_value::<RecallConflictObservation>(json!({})).is_err());
    default_states_exactly(&RecallConflictObservation::default(), 2);
    assert!(
        !RecallConflictObservation::default().observed,
        "the Default path states that the owner never looked"
    );
    assert!(
        RecallConflictObservation::default().conflicted().is_none(),
        "and it reports no conflict answer at all"
    );
    // memory.rs:1083 `L0RankTrace` — ten members, nine of them required.
    assert!(serde_json::from_value::<L0RankTrace>(json!({})).is_err());
    default_states_exactly(&L0RankTrace::default(), 10);
    assert!(L0RankTrace::default().query.is_empty());
    assert!(!L0RankTrace::default().no_useful_memory);
    // memory.rs:1100 `L0FeatureScore` — twenty-four members, eleven required.
    assert!(serde_json::from_value::<L0FeatureScore>(json!({})).is_err());
    default_states_exactly(&L0FeatureScore::default(), 24);
    assert!(L0FeatureScore::default().handle.is_empty());
    // memory.rs:1143 `L0SuppressionTrace` — `handle` and `reason`, both required,
    // and `Default` supplies both as EMPTY STRINGS: a suppression trace that names
    // no handle and states no reason.
    assert!(serde_json::from_value::<L0SuppressionTrace>(json!({})).is_err());
    default_states_exactly(&L0SuppressionTrace::default(), 2);
    assert!(L0SuppressionTrace::default().handle.is_empty());
    assert!(L0SuppressionTrace::default().reason.is_empty());
    // memory.rs:1151 `L0CollapsedDuplicateTrace` — three required keys.
    assert!(serde_json::from_value::<L0CollapsedDuplicateTrace>(json!({})).is_err());
    default_states_exactly(&L0CollapsedDuplicateTrace::default(), 3);
    assert!(
        L0CollapsedDuplicateTrace::default()
            .authoritative_handle
            .is_empty()
    );
    // memory.rs:2781 `CodeCortexScopeBinding` — five required keys, and `Default`
    // supplies `branch`, `commit` and `dirty_state_hash` as empty strings, i.e. a
    // scope binding naming no branch, no commit and no dirty-state proof.
    assert!(serde_json::from_value::<CodeCortexScopeBinding>(json!({})).is_err());
    default_states_exactly(&CodeCortexScopeBinding::default(), 5);
    assert!(
        CodeCortexScopeBinding::default()
            .dirty_state_hash
            .is_empty()
    );
    // memory.rs:3346 `BlackboardScope` — four required keys, all vectors.
    assert!(serde_json::from_value::<BlackboardScope>(json!({})).is_err());
    default_states_exactly(&BlackboardScope::default(), 4);
    // delegation.rs:189 `ProviderCallLedger` — two required keys, and `Default`
    // supplies both as empty vectors: it manufactures a ledger asserting that no
    // budget and no reservation exists, with no owner having said so. This is the
    // type the replaced comment named first, and it is the clearest counter-example.
    assert!(serde_json::from_value::<ProviderCallLedger>(json!({})).is_err());
    default_states_exactly(&ProviderCallLedger::default(), 2);
    assert!(ProviderCallLedger::default().budgets.is_empty());
    assert!(ProviderCallLedger::default().reservations.is_empty());
    // delegation.rs:255 `DelegationState` — fifteen required keys, every one a
    // vector, every one supplied empty.
    assert!(serde_json::from_value::<DelegationState>(json!({})).is_err());
    default_states_exactly(&DelegationState::default(), 15);
    // lifecycle.rs:813 `impl Default for MemoryLifecyclePacketView` — a PUBLIC
    // hand-written impl, not a derive. It supplies all six required keys AND
    // fabricates a lifecycle warning no owner wrote.
    assert!(serde_json::from_value::<MemoryLifecyclePacketView>(json!({})).is_err());
    default_states_exactly(&MemoryLifecyclePacketView::default(), 6);
    assert_eq!(
        MemoryLifecyclePacketView::default().lifecycle_warnings,
        vec!["memory lifecycle policy active".to_owned()],
        "the Default impl states a lifecycle warning that no owner wrote"
    );
    // antigravity.rs:484 `impl Default for AntigravityCapabilities` — the other
    // PUBLIC hand-written impl. It supplies all fourteen required keys and sets
    // `text_output_supported` TRUE while every other capability is false, so it is
    // a positive capability claim no probe produced.
    assert!(serde_json::from_value::<AntigravityCapabilities>(json!({})).is_err());
    default_states_exactly(&AntigravityCapabilities::default(), 14);
    assert!(
        AntigravityCapabilities::default().text_output_supported,
        "the Default impl asserts that text output is supported"
    );
    assert!(
        !AntigravityCapabilities::default().dangerously_skip_permissions_seen,
        "and asserts the permission bypass was never seen"
    );
    // antigravity.rs:751 `AntigravityResponseProtocolReceipt` — four required
    // booleans, on the surface its own doc comment at antigravity.rs:748-749
    // calls "the stable serialized proof surface for the smoke protocol".
    // `Default` supplies all four as `false`, i.e. a protocol proof on which no
    // check was satisfied.
    assert!(serde_json::from_value::<AntigravityResponseProtocolReceipt>(json!({})).is_err());
    default_states_exactly(&AntigravityResponseProtocolReceipt::default(), 4);
    assert!(
        !AntigravityResponseProtocolReceipt::default().expected_smoke_marker_seen,
        "the Default impl asserts the expected smoke marker was not seen"
    );

    // ---- CONSTRUCTION, shape 2: derived `Default` on a struct whose wire has NO
    // required key. `Default` still supplies every member, but there was never a
    // required key to bypass, so these arms state that instead of claiming a
    // bypass they cannot show.

    // cognition.rs:1245 `OperatorProjectionFilter` — every member is a bare
    // `Option<String>`, so absence already decodes under this file's own
    // absent-becomes-none rule and `{}` is accepted outright.
    assert!(serde_json::from_value::<OperatorProjectionFilter>(json!({})).is_ok());
    default_states_exactly(&OperatorProjectionFilter::default(), 7);
    // memory.rs:2075 `MemoryProvenanceView` — four bare `Option<String>` members
    // plus two `#[serde(default)]` vectors, so `{}` is accepted.
    assert!(serde_json::from_value::<MemoryProvenanceView>(json!({})).is_ok());
    default_states_exactly(&MemoryProvenanceView::default(), 6);
    // memory.rs:2099 `MemoryApplicabilityPacketView` — all five members carry
    // `#[serde(default)]`, so `{}` is accepted, and the `skip_serializing_if` at
    // memory.rs:2100 keeps `current_git_scope` out of the manufactured document:
    // four stated members out of five declared, which is why this arm says four.
    assert!(serde_json::from_value::<MemoryApplicabilityPacketView>(json!({})).is_ok());
    default_states_exactly(&MemoryApplicabilityPacketView::default(), 4);

    // ---- CONSTRUCTION, shape 3: public constructors and helpers that state a key
    // the decoder would otherwise refuse to receive.

    // memory.rs:2953 `AuthorityProfile::read_only()` and memory.rs:2959
    // `bounded_write()` supply the required `permissions` key the empty object is
    // refused for, so an authority profile exists with no wire document behind it.
    assert!(serde_json::from_value::<AuthorityProfile>(json!({})).is_err());
    default_states_exactly(&AuthorityProfile::read_only(), 1);
    assert!(AuthorityProfile::read_only().allows(AuthorityPermission::Read));
    assert!(!AuthorityProfile::read_only().allows(AuthorityPermission::Write));
    assert!(AuthorityProfile::bounded_write().allows_write());
    // cognitive_field.rs:667 `minimal_cognitive_understanding_answer()` and
    // cognitive_field.rs:711 `minimal_cognitive_judge_result()` supply EVERY
    // required key of their records, `schema_version` included, and mint a fresh
    // `ProjectId::new_v7()` / `TaskId::new_v7()` on every call, so no identity in
    // either record is owner-stated.
    assert!(serde_json::from_value::<CognitiveUnderstandingAnswer>(json!({})).is_err());
    default_states_exactly(&minimal_cognitive_understanding_answer(), 32);
    assert_eq!(
        minimal_cognitive_understanding_answer().schema_version,
        COGNITIVE_UNDERSTANDING_SCHEMA_VERSION
    );
    assert!(serde_json::from_value::<CognitiveJudgeResult>(json!({})).is_err());
    default_states_exactly(&minimal_cognitive_judge_result(), 9);
    assert_eq!(
        minimal_cognitive_judge_result().schema_version,
        COGNITIVE_JUDGE_SCHEMA_VERSION
    );
    // mcp_contract.rs:472 with mcp_contract.rs:476 — the ONE helper-default form
    // in the nine files. The helper is PRIVATE, so this is not a public
    // construction path and this arm does not claim it is; it is the helper path.
    // `#[serde(default = "default_observe_schema_version")]` supplies an OMITTED
    // `ObserveInput::schema_version` with the CURRENT version, so a document that
    // omits the version is silently promoted onto the current boundary.
    let helper_promoted: ObserveInput = serde_json::from_value(without(
        serde_json::from_str(&corpus("observe_input_positive.json"))
            .expect("the observe fixture must parse"),
        "schema_version",
    ))
    .expect("an omitted version is supplied by the helper rather than refused");
    assert_eq!(
        helper_promoted.schema_version, OBSERVE_INPUT_SCHEMA_VERSION,
        "the helper supplies the omitted version key with the current version"
    );

    // ---- CONSTRUCTION, shape 4: fieldless enums. Here `Default` supplies a
    // control VALUE, not a map key. Whether that value can reach a record at all
    // is decided solely by whether the parent member carries
    // `#[serde(default)]`, so every enum below is classified.

    // REACHABLE — the parent member is `#[serde(default)]`, so an omitted key
    // becomes exactly this manufactured variant:
    //   cognition.rs:1294 `OperatorResultMode`, parent member
    //     `OperatorQueryRequest::result_mode` at cognition.rs:1270;
    //   memory.rs:1045 `CognitiveProjectionReadState`, parent members
    //     `RecallL0Response::projection_state` at memory.rs:1029 and two others;
    //   memory.rs:1062 `MemoryConfidence`, parent members
    //     `RecallL0Response::memory_confidence` at memory.rs:1032 and
    //     `ContextPacketL3::memory_confidence` at memory.rs:2127;
    //   memory.rs:3202 `WorktreeLeaseKind`, parent member
    //     `WorktreeLease::kind` at memory.rs:3236;
    //   mcp_contract.rs:482 `ObserveHint`, parent member `ObserveInput::hint` at
    //     mcp_contract.rs:421.
    default_names_variant(OperatorResultMode::default(), "human");
    default_names_variant(CognitiveProjectionReadState::default(), "unavailable");
    default_names_variant(MemoryConfidence::default(), "none");
    default_names_variant(WorktreeLeaseKind::default(), "linked_git_worktree");
    default_names_variant(ObserveHint::default(), "auto");
    // Two of the five are proved reachable against real wire documents rather
    // than asserted from source: both corpus documents omit the member, so the
    // decoder installed the `Default` value.
    let defaulted_query: OperatorQueryRequest =
        decode_fixture("operator_query_request_positive.json");
    assert_eq!(
        defaulted_query.result_mode,
        OperatorResultMode::default(),
        "the corpus request omits result_mode, so the wire installed this exact default"
    );
    let defaulted_lease: WorktreeLease = decode_fixture("worktree_lease_positive.json");
    assert_eq!(
        defaulted_lease.kind,
        WorktreeLeaseKind::default(),
        "the corpus lease omits kind, so the wire installed this exact default"
    );

    // NOT REACHABLE — the parent member is REQUIRED, so the decoder refuses a
    // document that omits it and this `Default` supplies no key at all:
    //   lifecycle.rs:358 `MemoryLifecycleState`, parent member
    //     `MemoryStateTransition::from_state` at lifecycle.rs:585;
    //   lifecycle.rs:473 `MemoryEcologyDecision`, parent member
    //     `MemoryStateTransition::expected_admission_effect` at lifecycle.rs:592;
    //   eval.rs:504 `MetaExperimentDecision`, parent member
    //     `MetaIsolationRejectionRecord::decision` at eval.rs:601.
    default_names_variant(MemoryLifecycleState::default(), "active");
    default_names_variant(MemoryEcologyDecision::default(), "KEEP_HOT");
    default_names_variant(MetaExperimentDecision::default(), "INSUFFICIENT_EVIDENCE");
    let transition: Value = serde_json::from_str(&corpus("memory_state_transition_positive.json"))
        .expect("the transition fixture must parse");
    rejects_missing::<MemoryStateTransition>(transition.clone(), "from_state");
    rejects_missing::<MemoryStateTransition>(transition, "expected_admission_effect");
    rejects_missing::<MetaIsolationRejectionRecord>(
        serde_json::from_str(&corpus("meta_isolation_rejection_record_positive.json"))
            .expect("the rejection fixture must parse"),
        "decision",
    );

    // UNCLASSIFIED AGAINST A WIRE DOCUMENT — no corpus document in this crate
    // states `MinorityPressureRecord::status` (lifecycle.rs:699, struct at
    // lifecycle.rs:692) or `HarnessExperimentRecord::change_class` (eval.rs:460,
    // struct at eval.rs:451), so these two arms claim only what is true from
    // source: the `Default` is one named variant with one spelling, and a
    // document naming no variant is refused. They deliberately do NOT claim the
    // parent requires the key or defaults it, because no assertion here can
    // establish which.
    default_names_variant(MinorityPressureStatus::default(), "open");
    default_names_variant(MetaCandidateChangeClass::default(), "admission_rule");

    // A complete owner-written budget state still decodes: the gate is the decoder,
    // not a helper, and the owner has to state every member.
    let budget: ProviderCallBudgetState = serde_json::from_value(json!({
        "campaign_id": "campaign-1",
        "schema_version": "eliot.provider-call-budget-v1",
        "max_calls": 1,
        "next_slot_index": 0,
        "reserved_slots": 0,
        "dispatched_slots": 0,
        "terminal_slots": 0,
        "remaining_calls": 1,
        "revision": 1,
        "closed": false,
        "updated_at": "2026-09-07T12:00:00Z"
    }))
    .expect("a complete owner-written budget state decodes");
    assert_eq!(budget.remaining_calls, 1);

    let reservation_state = ProviderCallReservationState::Completed;
    assert!(
        serde_json::from_value::<ProviderCallReservation>(json!({ "state": reservation_state }))
            .is_err(),
        "a control value alone must not construct a reservation"
    );

    // The public validators read only what the decoder produced, so no helper
    // can stand in for a required member.
    let candidate: CausalCandidate = decode_fixture("causal_candidate_positive.json");
    assert!(candidate.validate_material().is_ok());
    let mut unchecked = candidate.clone();
    unchecked.assigned_check = None;
    assert!(unchecked.validate_material().is_ok());
    assert!(
        unchecked.critical_action_check().is_err(),
        "the critical-action gate must still demand its assigned check"
    );

    // An owner-written complete lease wire still decodes: the gate is the
    // decoder, not a helper.
    let lease: WorktreeLease = serde_json::from_value(json!({
        "worktree_lease_id": "00000000-0000-7000-8000-000000000001",
        "project_id": "00000000-0000-7000-8000-000000000002",
        "task_id": "00000000-0000-7000-8000-000000000003",
        "work_item_id": "00000000-0000-7000-8000-000000000004",
        "work_lease_id": "00000000-0000-7000-8000-000000000005",
        "holder_session_id": "00000000-0000-7000-8000-000000000006",
        "repo_root": "C:/repo",
        "worktree_path": "C:/repo/.worktrees/k2",
        "branch_name": "lane/K2",
        "base_commit": "commit-1",
        "allowed_read_set": [],
        "allowed_write_set": [],
        "state": "active",
        "issued_at": "2026-09-07T12:00:00Z",
        "expires_at": "2026-09-07T12:00:01Z",
        "cleaned_at": null,
        "write_receipt": null,
    }))
    .expect("a complete worktree lease wire decodes");
    assert!(lease.managed_root.is_none());

    let _ = decode_fixture::<AgentRoutingView>("agent_routing_view_positive.json");
    let _ = decode_fixture::<MaterialPacketFrame>("material_packet_frame_positive.json");
    let _ = decode_fixture::<MemoryHandlePreview>("memory_handle_preview_positive.json");
    let _ = decode_fixture::<CognitiveFieldProviderCallPlan>(
        "cognitive_field_provider_call_plan_positive.json",
    );
    let _ = decode_fixture::<AutonomyRunContract>("autonomy_run_contract_positive.json");
    let _ = decode_fixture::<ProviderCallLedger>("provider_call_ledger_positive.json");
    let _ = decode_fixture::<WorkLease>("work_lease_positive.json");
    let _ = decode_fixture::<CompilePacketToolInput>("compile_packet_tool_input_positive.json");
}

// WORK_UNIT_CASE: 708/19
#[test]
#[allow(clippy::too_many_lines)]
fn case_19_bounded_mutations_cannot_create_a_valid_object() {
    // Case 19: for every changed type, removing any key the golden document
    // states as required must fail. The tolerated keys are exactly the ones the
    // case-15 oracle classifies as absence-tolerant on that type: its
    // `#[serde(default)]` sites plus its bare-`Option` sites, the two shapes
    // whose absence serde cannot turn into an error.
    assert_fixture_declares_every_required_key::<WorkLease>(
        "work_lease_positive.json",
        "WorkLease",
    );
    assert_fixture_declares_every_required_key::<ProviderCallLedger>(
        "provider_call_ledger_positive.json",
        "ProviderCallLedger",
    );
    assert_fixture_declares_every_required_key::<AutonomyRunContract>(
        "autonomy_run_contract_positive.json",
        "AutonomyRunContract",
    );
    assert_fixture_declares_every_required_key::<ForgettingPolicy>(
        "forgetting_policy_positive.json",
        "ForgettingPolicy",
    );
    assert_fixture_declares_every_required_key::<MemoryStateTransition>(
        "memory_state_transition_positive.json",
        "MemoryStateTransition",
    );
    assert_fixture_declares_every_required_key::<AntigravityRun>(
        "antigravity_run_positive.json",
        "AntigravityRun",
    );
    assert_fixture_declares_every_required_key::<AntigravitySafetyReceipt>(
        "antigravity_safety_receipt_positive.json",
        "AntigravitySafetyReceipt",
    );
    assert_fixture_declares_every_required_key::<CognitiveFieldProviderCallPlan>(
        "cognitive_field_provider_call_plan_positive.json",
        "CognitiveFieldProviderCallPlan",
    );
    assert_fixture_declares_every_required_key::<CognitiveFieldProviderEvidenceReceipt>(
        "cognitive_field_provider_evidence_receipt_positive.json",
        "CognitiveFieldProviderEvidenceReceipt",
    );
    assert_fixture_declares_every_required_key::<CognitiveFieldProviderProjection>(
        "cognitive_field_provider_projection_positive.json",
        "CognitiveFieldProviderProjection",
    );
    assert_fixture_declares_every_required_key::<CausalCandidate>(
        "causal_candidate_positive.json",
        "CausalCandidate",
    );
    assert_fixture_declares_every_required_key::<TaskCognitionView>(
        "task_cognition_view_positive.json",
        "TaskCognitionView",
    );
    assert_fixture_declares_every_required_key::<MemoryInspectorView>(
        "memory_inspector_view_positive.json",
        "MemoryInspectorView",
    );
    assert_fixture_declares_every_required_key::<AgentRoutingView>(
        "agent_routing_view_positive.json",
        "AgentRoutingView",
    );
    assert_fixture_declares_every_required_key::<AutonomyRunView>(
        "autonomy_run_view_positive.json",
        "AutonomyRunView",
    );
    assert_fixture_declares_every_required_key::<OperatorSnapshot>(
        "operator_snapshot_positive.json",
        "OperatorSnapshot",
    );
    assert_fixture_declares_every_required_key::<TaskAcceptanceItem>(
        "task_acceptance_item_positive.json",
        "TaskAcceptanceItem",
    );
    assert_fixture_declares_every_required_key::<ActionSourceScope>(
        "action_source_scope_positive.json",
        "ActionSourceScope",
    );
    assert_fixture_declares_every_required_key::<TaskContract>(
        "task_contract_positive.json",
        "TaskContract",
    );
    assert_fixture_declares_every_required_key::<TaskContractInput>(
        "task_contract_input_positive.json",
        "TaskContractInput",
    );
    assert_fixture_declares_every_required_key::<VerificationRun>(
        "verification_run_positive.json",
        "VerificationRun",
    );
    assert_fixture_declares_every_required_key::<RecallL0Request>(
        "recall_l0_request_positive.json",
        "RecallL0Request",
    );
    assert_fixture_declares_every_required_key::<UnderstandingProof>(
        "understanding_proof_positive.json",
        "UnderstandingProof",
    );
    assert_fixture_declares_every_required_key::<UnderstandingProofReceipt>(
        "understanding_proof_receipt_positive.json",
        "UnderstandingProofReceipt",
    );
    assert_fixture_declares_every_required_key::<DelegationRequest>(
        "delegation_request_positive.json",
        "DelegationRequest",
    );
    assert_fixture_declares_every_required_key::<ProviderInvocationAttempt>(
        "provider_invocation_attempt_positive.json",
        "ProviderInvocationAttempt",
    );
    assert_fixture_declares_every_required_key::<AgentCandidateSubmitInput>(
        "agent_candidate_submit_input_positive.json",
        "AgentCandidateSubmitInput",
    );
    assert_fixture_declares_every_required_key::<AgentCandidateCurationInput>(
        "agent_candidate_curation_input_positive.json",
        "AgentCandidateCurationInput",
    );
    assert_fixture_declares_every_required_key::<ObserveInput>(
        "observe_input_positive.json",
        "ObserveInput",
    );
    assert_fixture_declares_every_required_key::<CompilePacketToolInput>(
        "compile_packet_tool_input_positive.json",
        "CompilePacketToolInput",
    );
    assert_fixture_declares_every_required_key::<CompilePacketL3Request>(
        "compile_packet_l3_request_positive.json",
        "CompilePacketL3Request",
    );
    assert_fixture_declares_every_required_key::<EvalSuite>(
        "eval_suite_positive.json",
        "EvalSuite",
    );
    assert_fixture_declares_every_required_key::<EvalCaseResult>(
        "eval_case_result_positive.json",
        "EvalCaseResult",
    );
    // `MetaIsolationRejectionRecord` (eval.rs:591-604) declares nine members and
    // the scan records neither a default site nor a bare-`Option` site on it, so
    // every stated key is required and the helper's `required` count is 9.
    // `MetaPolicyExecutionReceipt` (eval.rs:637-652) declares eleven, of which
    // `resulting_candidate` (eval.rs:649) is the one bare `Option` this type
    // keeps on purpose - the frozen `eval.rs` slice of
    // `EXPECTED_BARE_OPTION_SITE_LINES` already enumerates it - so the stated
    // document is fully required except for that one, and the count is 10.
    assert_fixture_declares_every_required_key::<MetaIsolationRejectionRecord>(
        "meta_isolation_rejection_record_positive.json",
        "MetaIsolationRejectionRecord",
    );
    assert_fixture_declares_every_required_key::<MetaPolicyExecutionReceipt>(
        "meta_policy_execution_receipt_positive.json",
        "MetaPolicyExecutionReceipt",
    );
    assert_fixture_declares_every_required_key::<MemoryVitalityScore>(
        "memory_vitality_score_positive.json",
        "MemoryVitalityScore",
    );
    assert_fixture_declares_every_required_key::<OperatorCommandReceipt>(
        "operator_command_receipt_positive.json",
        "OperatorCommandReceipt",
    );

    // The two execution-binding shapes whose full key sets were fixed in this
    // issue are exercised key by key on the owner-written wire.
    let call_plan = provider_call_plan_wire();
    let plan: CognitiveFieldProviderCallPlan =
        serde_json::from_value(call_plan.clone()).expect("complete sealed call plan");
    for field in [
        "call_number",
        "call_id",
        "role",
        "host",
        "requested_model",
        "expected_provider_executable_sha256",
        "prompt_ref",
        "prompt_sha256",
        "canonical_schema_sha256",
        "provider_schema_sha256",
        "provider_smoke",
        "counts_against_cap",
        "executions",
        "runtime_contract_ref",
        "runtime_contract_sha256",
        "adapter_id",
        "adapter_version",
        "execution_request_ref",
        "execution_request_sha256",
    ] {
        rejects_missing::<CognitiveFieldProviderCallPlan>(call_plan.clone(), field);
    }
    assert_eq!(plan.runtime_contract_ref, "runtime-contract-1");
}

// WORK_UNIT_CASE: 708/20
#[test]
fn case_20_the_deferred_owner_map_is_complete_and_outside_this_scope() {
    // Case 20: the owner map for every breaking candidate the requiredness work
    // deferred. Each owner file exists, none of them is one of the nine frozen
    // production files, and the sealed plan whose digest they own is the
    // document under test.
    let plan: CognitiveFieldProviderPlan =
        decode_fixture("cognitive_field_provider_plan_positive.json");
    assert_eq!(
        plan.schema_version,
        COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION
    );

    assert!(!BREAKING_CANDIDATE_OWNER_MAP.is_empty());
    // Completeness, the property the card asks for and nothing enforced until
    // now: every `specific-owner` exception row must have an entry in this map.
    // Case 16 pins those rows as a frozen set, so a `specific-owner` disposition
    // without a recorded owner is otherwise invisible - exactly what happened
    // for `AgentCandidateSubmitInput.cue_bindings`.
    for owner_row in EXPECTED_SPECIFIC_OWNER_ROWS {
        let field = owner_row.rsplit('.').next().unwrap_or(owner_row);
        assert!(
            BREAKING_CANDIDATE_OWNER_MAP
                .iter()
                .any(|(candidate, ..)| candidate.contains(field)),
            "{owner_row} is a specific-owner exception with no entry in the deferred owner map"
        );
    }
    let mut owners: Vec<&str> = BREAKING_CANDIDATE_OWNER_MAP
        .iter()
        .map(|(_candidate, _base, _blocking, owner)| *owner)
        .collect();
    owners.sort_unstable();
    owners.dedup();
    assert_eq!(
        owners,
        EXPECTED_OWNER_FILES.as_slice(),
        "the deferred owner set must not change without its named owner"
    );
    for entry in BREAKING_CANDIDATE_OWNER_MAP {
        let (candidate, base, blocking, owner) = *entry;
        assert!(
            !candidate.is_empty() && !blocking.is_empty(),
            "every deferred candidate names its candidate and its blocking decision"
        );
        // This branch is unreachable today: every row's base column reads `n/a`,
        // because no published base object identity for these candidates is
        // resolvable in this repository. It is kept, not deleted, because it is
        // the validator for the next hand-edit: a row that does record a real
        // base object id must record a full 40-character hex id, and this is the
        // only place that says so. Stated here so nobody reads the passing run as
        // evidence that a base id was checked.
        if base != "n/a" {
            assert!(
                base.len() == 40 && base.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "{candidate} must record a full base object id or the explicit n/a"
            );
        }
        let owner_path = workspace_root().join(owner);
        assert!(
            owner_path.is_file(),
            "{owner} must exist: it owns a deferred decision for {candidate}"
        );
        assert!(
            !owner.starts_with("crates/eliot-types/src/"),
            "{candidate} must not be deferred back into the frozen nine-file domain"
        );
    }
    assert_changed_required_nullable_members_are_accounted_for();
}

// ---------------------------------------------------------------------
// The scanner fixtures under `crates/eliot-types/tests/data/appendix-p-scanner/`.
//
// They are READ SOURCES for the scanners above, never compilation targets.
// Cargo's integration-test auto-discovery takes only `tests/*.rs` and
// `tests/*/main.rs`, so five of these thirteen files deliberately do not
// compile and none of them is ever built; this case reads their bytes and hands
// them to the same `(file_name, source_text)` entry points the nine frozen
// production files use. There is no second scanner here and no call into
// `scripts/serde_boundary_inventory.py`: that script owns the classification
// vocabulary and the unsupported-syntax handling, and this oracle stays
// package-local exactly as the file header states.
//
// Each fixture's first line(s) are a machine-readable header. The thirteen
// headers do not carry an identical field set and this code does not invent
// one: the seven site fixtures state every denominator plus `keys=`, the six
// negative-source controls state `raise=` and `detail=` and one of them adds
// `masked=clean`, and the unsupported-macro control adds a key, a kind and a
// grade. A field a fixture does not state is not compared.
// ---------------------------------------------------------------------

/// Every `.rs` fixture in that directory. The count is frozen at the thirteen
/// files the directory holds, and `case_21` asserts the directory against this
/// list, so a fourteenth fixture cannot sit unread again.
const SCANNER_FIXTURES: [&str; 13] = [
    "bare_option_site.rs",
    "clean_source_no_sites.rs",
    "decoys_no_false_positives.rs",
    "direct_default_site.rs",
    "helper_default_site.rs",
    "paired_skip_if.rs",
    "unterminated_block_comment.rs",
    "unterminated_byte_char.rs",
    "unterminated_byte_string.rs",
    "unterminated_char.rs",
    "unterminated_raw_string.rs",
    "unterminated_string.rs",
    "unsupported_macro_site.rs",
];

/// The fixture directory, resolved through `workspace_root()` the same way
/// `nine_file_source` resolves the nine frozen production files.
fn scanner_fixture_dir() -> PathBuf {
    workspace_root()
        .join("crates")
        .join("eliot-types")
        .join("tests")
        .join("data")
        .join("appendix-p-scanner")
}

fn scanner_fixture(name: &str) -> String {
    let path = scanner_fixture_dir().join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("scanner fixture {name} must be readable: {error}"))
}

/// One scanner fixture's parsed header. A field the fixture does not state is
/// `None`, and is not compared.
#[derive(Default)]
struct ScannerFixtureHeader {
    default: Option<usize>,
    form: Option<String>,
    helper: Option<usize>,
    paired: Option<usize>,
    bare_option: Option<usize>,
    unsupported_macro: Option<usize>,
    unresolved: Option<usize>,
    manual_visitor: Option<usize>,
    raise: Option<String>,
    detail: Option<String>,
    masked: Option<String>,
    keys: Option<Vec<String>>,
    bare_option_line: Option<String>,
    unsupported_macro_key: Option<String>,
    kind: Option<String>,
    grade: Option<String>,
}

/// The `name=value` fields of one comment line, or an empty vector when the line
/// is prose. A line qualifies when its first token opens a `name=value` field
/// with a non-empty value and every later token either opens another such field
/// or continues the previous field's value. That is what keeps
/// `detail=unclosed block comment` one value, and what stops the header exactly
/// where the prose starts: a prose line whose first word carries no `=` yields
/// nothing, while a prose token written as `default=` with an empty value is a
/// rejection rather than a field.
fn scanner_fixture_header_fields(body: &str) -> Vec<(String, String)> {
    let is_a_field_name = |name: &str| {
        !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    };
    let mut fields: Vec<(String, String)> = Vec::new();
    for token in body.split_whitespace() {
        match token.split_once('=') {
            Some((key, first)) if is_a_field_name(key) && !first.is_empty() => {
                fields.push((key.to_owned(), first.to_owned()));
            }
            Some(_) => return Vec::new(),
            None => match fields.last_mut() {
                Some((_key, value)) => {
                    value.push(' ');
                    value.push_str(token);
                }
                None => return Vec::new(),
            },
        }
    }
    fields
}

fn scanner_fixture_header(name: &str, source: &str) -> ScannerFixtureHeader {
    let mut header = ScannerFixtureHeader::default();
    let mut opened = false;
    for line in source.lines() {
        let Some(comment) = line.trim().strip_prefix("//") else {
            continue;
        };
        let comment = comment.trim();
        let fields = if opened {
            scanner_fixture_header_fields(comment)
        } else {
            match comment.strip_prefix("EXPECTED:") {
                Some(rest) => {
                    opened = true;
                    scanner_fixture_header_fields(rest.trim())
                }
                None => continue,
            }
        };
        if fields.is_empty() {
            break;
        }
        for (key, value) in fields {
            let count = || -> usize {
                value.parse::<usize>().unwrap_or_else(|error| {
                    panic!("{name}: counter `{key}={value}` must be a count: {error}")
                })
            };
            match key.as_str() {
                "default" => header.default = Some(count()),
                "helper" => header.helper = Some(count()),
                "paired" => header.paired = Some(count()),
                "bare-option" => header.bare_option = Some(count()),
                "unsupported-macro" => header.unsupported_macro = Some(count()),
                "unresolved" => header.unresolved = Some(count()),
                "manual-visitor" => header.manual_visitor = Some(count()),
                "form" => header.form = Some(value.clone()),
                "raise" => header.raise = Some(value.clone()),
                "detail" => header.detail = Some(value.clone()),
                "masked" => header.masked = Some(value.clone()),
                "kind" => header.kind = Some(value.clone()),
                "grade" => header.grade = Some(value.clone()),
                "bare-option-line" => header.bare_option_line = Some(value.clone()),
                "unsupported-macro-key" => header.unsupported_macro_key = Some(value.clone()),
                "keys" => {
                    header.keys = Some(if value == "(none)" {
                        Vec::new()
                    } else {
                        value.split(',').map(str::to_owned).collect()
                    });
                }
                other => panic!("{name}: counter `{other}` is not a scanner-fixture header field"),
            }
        }
    }
    assert!(opened, "{name} must state a `// EXPECTED:` header line");
    header
}

/// What `mask_rust` did to one fixture: the masked copy, or the message it failed
/// closed with. `mask_rust` refuses through `panic!` - it is the scanner, not a
/// parser over untrusted input - so the refusal is observed here instead of
/// changing `mask_rust`'s signature and every caller with it. `catch_unwind`
/// still runs the panic hook, so each of the five refusals prints its message;
/// that output is the evidence, not noise to suppress.
fn mask_scanner_fixture(name: &str, source: &str) -> Result<String, String> {
    match std::panic::catch_unwind(|| mask_rust(source)) {
        Ok(masked) => Ok(masked),
        Err(refusal) => {
            let message = refusal
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| {
                    refusal
                        .downcast_ref::<&str>()
                        .map(|text| (*text).to_owned())
                })
                .unwrap_or_default();
            assert!(
                message.contains("malformed-rust-source"),
                "{name}: masking must fail closed only through `malformed_source`: {message}"
            );
            Err(message)
        }
    }
}

/// The `detail` half of a `malformed-rust-source` message, which
/// `malformed_source` writes as
/// `malformed-rust-source: {detail} at line {line}, column {column}`.
fn raise_detail(message: &str) -> Option<String> {
    let (_, rest) = message.split_once("malformed-rust-source: ")?;
    Some(
        rest.split(" at line ")
            .next()
            .unwrap_or_default()
            .to_owned(),
    )
}

/// Compares the `raise`, `detail` and `masked` half of one fixture's header
/// against what `mask_rust` did, and hands back the masked copy when the fixture
/// masks cleanly. A fixture that fails closed on masking states no counters, so
/// its comparison IS the refusal and this returns `None` rather than reading a
/// masked copy it never got.
fn assert_scanner_fixture_mask(
    name: &str,
    source: &str,
    header: &ScannerFixtureHeader,
) -> Option<String> {
    let masked = mask_scanner_fixture(name, source);
    let raise = header.raise.as_deref().unwrap_or_else(|| {
        panic!("{name}: counter `raise` must be stated by every fixture header")
    });
    let masked = match masked {
        Err(message) => {
            assert_eq!(
                raise, "malformed-rust-source",
                "{name}: counter `raise` must name the shipped refusal kind"
            );
            assert_eq!(
                raise_detail(&message).as_deref(),
                header.detail.as_deref(),
                "{name}: counter `detail` must name the condition `mask_rust` refused on"
            );
            return None;
        }
        Ok(masked) => masked,
    };
    assert_eq!(
        raise, "none",
        "{name}: counter `raise` must stay `none` for a source that masks cleanly"
    );
    assert_eq!(
        header.detail.as_deref(),
        Some("none"),
        "{name}: counter `detail` must stay `none` for a source that masks cleanly"
    );
    if let Some(expected) = header.masked.as_deref() {
        assert_eq!(
            expected, "clean",
            "{name}: counter `masked` may only state `clean`"
        );
        assert_eq!(
            masked.len(),
            source.len(),
            "{name}: counter `masked` must preserve byte offsets"
        );
        assert_eq!(
            masked.matches('\'').count(),
            source.matches('\'').count(),
            "{name}: counter `masked` must keep every lifetime tick and stray quote verbatim"
        );
    }
    Some(masked)
}

/// Compares the count and shape counters one fixture's header states against
/// this file's own scanners run over that fixture's source, including the
/// `form=` split of the discovered default site and the `keys=` spelling.
///
/// `name` is `&'static str` because `BareOptionSite` records it, so every
/// discovered site is named by a fixture's own file name exactly as the
/// nine-file aggregation names its sites by their file names.
fn assert_scanner_fixture_counts(name: &'static str, source: &str, header: &ScannerFixtureHeader) {
    let defaults = default_sites_in(name, source);
    let bare = bare_option_sites_in(name, source);
    let macros = unsupported_macros_in([(name, source)]);
    let manual = manual_decoder_impls_in([(name, source)]);
    let unresolved = defaults
        .iter()
        .filter(|site| site.key.contains("<unresolved"))
        .count();
    let shape = |site: &DefaultSite| match site.form {
        DefaultForm::Direct => "direct",
        DefaultForm::Helper => "helper",
        DefaultForm::Paired => "paired",
    };
    for (counter, expected, observed) in [
        ("default", header.default, defaults.len()),
        (
            "helper",
            header.helper,
            defaults
                .iter()
                .filter(|site| site.form == DefaultForm::Helper)
                .count(),
        ),
        (
            "paired",
            header.paired,
            defaults
                .iter()
                .filter(|site| site.form == DefaultForm::Paired)
                .count(),
        ),
        ("bare-option", header.bare_option, bare.len()),
        ("unsupported-macro", header.unsupported_macro, macros.len()),
        ("unresolved", header.unresolved, unresolved),
        ("manual-visitor", header.manual_visitor, manual.len()),
    ] {
        if let Some(expected) = expected {
            assert_eq!(
                observed, expected,
                "{name}: counter `{counter}` must equal the header value"
            );
        }
    }
    if let Some(expected) = header.form.as_deref() {
        assert_eq!(
            defaults.first().map_or("none", shape),
            expected,
            "{name}: counter `form` must name the shape of the discovered default site"
        );
    }
    if let Some(expected) = &header.keys {
        let mut discovered: Vec<String> = defaults.iter().map(|site| site.key.clone()).collect();
        discovered.extend(bare.iter().map(|site| site.key.clone()));
        assert_eq!(
            sorted(&discovered),
            sorted(expected),
            "{name}: counter `keys` must name each site in the oracle's `<file>::<Type>.<member>` spelling"
        );
    }
}

/// Compares the per-site naming counters: the `file:line` of the one discovered
/// `absent-becomes-none` site, the key of the one discovered macro site, and the
/// shipped kind and grade that site carries.
fn assert_scanner_fixture_site_names(
    name: &str,
    header: &ScannerFixtureHeader,
    bare: &[BareOptionSite],
    macros: &[UnsupportedMacroSite],
) {
    if let Some(expected) = &header.bare_option_line {
        let discovered: Vec<String> = bare
            .iter()
            .map(|site| format!("{}:{}", site.file, site.line))
            .collect();
        assert_eq!(
            discovered,
            vec![expected.clone()],
            "{name}: counter `bare-option-line` must name the discovered site at its own file:line"
        );
    }
    if let Some(expected) = &header.unsupported_macro_key {
        let discovered: Vec<String> = macros.iter().map(|site| site.key.clone()).collect();
        assert_eq!(
            discovered,
            vec![expected.clone()],
            "{name}: counter `unsupported-macro-key` must name the discovered macro site"
        );
    }
    for site in macros {
        if let Some(expected) = header.kind.as_deref() {
            assert_eq!(
                site.kind, expected,
                "{name}: counter `kind` must carry the shipped kind of every macro site"
            );
        }
        if let Some(expected) = header.grade.as_deref() {
            assert_eq!(
                format!(
                    "{}/{}/{}",
                    site.disposition, site.repair_readiness, site.safety
                ),
                expected,
                "{name}: counter `grade` must carry the shipped grade of every macro site"
            );
        }
    }
}

/// Compares every counter one scanner fixture's header states against this
/// file's own scanners run over that fixture's source.
fn assert_scanner_fixture_matches_header(name: &'static str, source: &str) {
    let header = scanner_fixture_header(name, source);
    if assert_scanner_fixture_mask(name, source, &header).is_none() {
        return;
    }
    let bare = bare_option_sites_in(name, source);
    let macros = unsupported_macros_in([(name, source)]);
    assert_scanner_fixture_counts(name, source, &header);
    assert_scanner_fixture_site_names(name, &header, &bare, &macros);
}

/// The six negative-source controls, each of which must do exactly what its own
/// header declares. Five refuse a source the mask cannot read, each with its OWN
/// detail: a blanket "anything unterminated raises" would pass those five and is
/// not what these files are for. The sixth declares the opposite outcome and is
/// the control that makes the other five specific - a quote that opens no
/// character literal is a lifetime tick or a stray quote, and the mask keeps it
/// so the surrounding code stays visible to discovery.
fn assert_scanner_fixture_negative_controls() {
    for (name, detail) in [
        (
            "unterminated_block_comment.rs",
            Some("unclosed block comment"),
        ),
        (
            "unterminated_byte_char.rs",
            Some("unclosed byte-char literal"),
        ),
        (
            "unterminated_byte_string.rs",
            Some("unclosed byte-string literal"),
        ),
        (
            "unterminated_raw_string.rs",
            Some("unclosed raw string literal"),
        ),
        ("unterminated_string.rs", Some("unclosed string literal")),
        ("unterminated_char.rs", None),
    ] {
        let source = scanner_fixture(name);
        let observed = mask_scanner_fixture(name, &source)
            .err()
            .and_then(|message| raise_detail(&message));
        assert_eq!(
            observed.as_deref(),
            detail,
            "{name}: counter `detail` must name the condition this control declares"
        );
    }
}

/// The zero control, stated rather than inferred. `clean_source_no_sites.rs`
/// declares a `#[serde(rename_all = "snake_case")]` container attribute on a
/// struct whose three members are `String`, `u32` and `bool`. Masking must find
/// that attribute span and find no `default` token inside it, the bare-`Option`
/// denominator must stay empty, and no other class may reach a site. This is the
/// property that proves the oracle invents nothing, and it is the reason the
/// other twelve fixtures are worth reading at all.
fn assert_scanner_fixture_clean_control() {
    let name = "clean_source_no_sites.rs";
    let source = scanner_fixture(name);
    let masked = mask_scanner_fixture(name, &source)
        .expect("clean_source_no_sites.rs: counter `raise` must stay `none`");
    assert_eq!(
        serde_attribute_spans(&masked).len(),
        1,
        "clean_source_no_sites.rs: counter `default` needs its container attribute span to be found and to carry no default token"
    );
    let defaults = default_sites_in(name, &source);
    let bare = bare_option_sites_in(name, &source);
    let macros = unsupported_macros_in([(name, source.as_str())]);
    let manual = manual_decoder_impls_in([(name, source.as_str())]);
    for (counter, observed) in [
        ("default", defaults.len()),
        (
            "helper",
            defaults
                .iter()
                .filter(|site| site.form == DefaultForm::Helper)
                .count(),
        ),
        (
            "paired",
            defaults
                .iter()
                .filter(|site| site.form == DefaultForm::Paired)
                .count(),
        ),
        ("bare-option", bare.len()),
        ("unsupported-macro", macros.len()),
        (
            "unresolved",
            defaults
                .iter()
                .filter(|site| site.key.contains("<unresolved"))
                .count(),
        ),
        ("manual-visitor", manual.len()),
    ] {
        assert_eq!(
            observed, 0,
            "clean_source_no_sites.rs: counter `{counter}` must find no site"
        );
    }
}

/// The fixture files the scanner fixtures directory holds, sorted.
fn scanner_fixture_names_on_disk() -> Vec<String> {
    let directory = scanner_fixture_dir();
    let mut names: Vec<String> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| {
            panic!(
                "the scanner fixture directory {} must be readable: {error}",
                directory.display()
            )
        })
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("a scanner fixture entry must be readable: {error}"))
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

#[test]
fn case_21_scanner_fixtures_pin_the_oracle_negative_controls() {
    // Case 21 is the consumer the issue's requirement "Include positive/negative
    // scanner fixtures" asks for: before this test the thirteen files under
    // `tests/data/appendix-p-scanner/` were read by nothing, so their headers
    // stated an expectation no code checked. Each is now a source this file's own
    // scanners are pointed at, and each header counter is compared against what
    // those scanners actually found. The scanner is the same one cases 15, 16 and
    // 19 use, parameterised by `(file_name, source_text)`; nothing is re-derived
    // here and `scripts/serde_boundary_inventory.py` is never called at run time,
    // because that script owns the classification vocabulary and the
    // unsupported-syntax handling and this oracle is package-local by design.
    //
    // No `// WORK_UNIT_CASE` marker sits above this function on purpose: the issue
    // freezes the denominator at exactly 1..20, so this test is additional
    // evidence for those cases rather than a twenty-first case.
    //
    // First, the directory is exactly the thirteen fixtures read below. Both
    // directions are asserted, so a fixture added to the directory fails here
    // instead of becoming unread, and a fixture removed from the directory fails
    // as a missing file.
    assert_eq!(
        scanner_fixture_names_on_disk(),
        SCANNER_FIXTURES,
        "every scanner fixture on disk must be read by this case, and this case must read only those"
    );

    // Every header counter, compared against this file's own scanners.
    for name in SCANNER_FIXTURES {
        let source = scanner_fixture(name);
        assert_scanner_fixture_matches_header(name, &source);
    }

    // The six negative-source controls, then the zero control: between them they
    // show that the five refusals are specific and that nothing is invented.
    assert_scanner_fixture_negative_controls();
    assert_scanner_fixture_clean_control();
}
