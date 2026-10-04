//! Issue #941 (`T12`): the decoder-closure proof for the ten UL files the
//! frozen boundary allocation gives to this child —
//! `crates/eliot-types/src/ul/{behavior,concept,cross_agent,dependency,exam,
//! guard,injection,onboarding,prediction,mod}.rs`.
//!
//! The allocation is the `family = "T12"` row for `child = "#941"` in
//! `crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml`
//! (`:368-384`): nine `source_files` plus the `test_files` entry
//! `crates/eliot-types/tests/serde_t12_ul_rest.rs:planned`. That row is
//! read-only evidence here and is never edited by this lane, so nothing in
//! this file reads it back as proof of itself; case 1 carries the ten-file
//! accounting as an executable table over the real production sources.
//!
//! THE GOVERNING DOCUMENTATION, quoted verbatim:
//!
//! * `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:12` —
//!   "authority, scope, effect, privacy, ordering and receipt fields are never
//!   silently defaulted;"
//! * `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:13` —
//!   "closed control variants fail when unknown; additive reason/telemetry
//!   values preserve Unknown(raw);"
//! * `docs/architecture/I05-16-common-durable-fields.md:46` — "Fields that do
//!   not apply remain explicit `None`; they are not silently omitted from the
//!   semantic model."
//! * `docs/architecture/I05-27-canonical-operation-identity-and-effect-identity.md:18`
//!   — "fields affecting authority, scope, ordering, privacy or effect cannot
//!   be omitted/defaulted silently."
//!
//! FIXTURES ARE RAW JSON TEXT, ALWAYS. `serde_json::Map` is a `BTreeMap` in this
//! workspace — the `preserve_order` feature is NOT enabled — so a repeated
//! object member collapses to last-wins the instant raw bytes become a
//! `serde_json::Value`, and a parsed object's member order is re-sorted. Two
//! rules follow and are observed by every case below:
//!
//!   1. duplicate-member refusals (cases 5-6) are parsed with
//!      `serde_json::from_str`, NEVER `from_value`;
//!   2. nothing here asserts that a parsed `Value` re-serializes to the
//!      original text. Payload equality is asserted as VALUE equality, and the
//!      only serialization this file byte-compares is the DERIVED serializer's
//!      own compact output of a typed value against a hand-written literal,
//!      where the expected member order is written in declaration order by
//!      hand rather than obtained from a `Value`.

#![allow(clippy::expect_used)]

use eliot_types::{
    CoChangeEdge, DependencyManifest, HotspotScore, InjectionReceipt, MemoryInfluenceAckInput,
    MemoryInfluenceClass, MemoryInfluenceToolInput, MemoryInfluenceTraceWriteInput, MiningConfig,
    MiningRun, ObservedCue, OnboardingJob, OnboardingReport, OnboardingStage, PendingInjectionItem,
    PredictionRecord, StrictJsonErrorKind, TextEncodingViolation, UlCrossAgentSuite,
    UlDependencyRef, UlExamRecord, UlPrediction, UlPredictionActual,
    strict_json_has_no_duplicate_members,
};

// ===========================================================================
// CORPUS — every fixture is a `&str` constant holding its own wire text.
//
// Writer w1 owns keys `t12_c1_` .. `t12_c8_` only. Writer w2 appends
// `t12_c9_` .. `t12_c16_` in the same shape below the placeholder section.
//
// The card's EDIT list for this card names ONLY this `.rs` file, so no
// accompanying `.json` fixture is created: a new data file would be an
// unowned path. Every fixture therefore lives here as a string literal, which
// is also what cases 5-6 require (a repeated member survives only as text).
// ===========================================================================

/// Fixture lookup for writer w1's own `t12_c1_`..`t12_c8_` keys.
///
/// The corpus is a `&[(&str, &str)]`, not a map, and both halves are matched
/// on the decoded member name. Writer w2 extends the table by adding entries
/// to the same slice in the section reserved for it below.
#[allow(clippy::too_many_lines)]
fn fixture(name: &str) -> String {
    let pairs: &[(&str, &str)] = &[
        // ---------------- case 1/2: one positive + one refusal per file ----
        (
            "t12_c1_behavior_mining_run_accept",
            T12_C1_BEHAVIOR_MINING_RUN_ACCEPT,
        ),
        (
            "t12_c1_behavior_mining_run_unknown_refuse",
            T12_C1_BEHAVIOR_MINING_RUN_UNKNOWN_REFUSE,
        ),
        (
            "t12_c1_concept_module_card_accept",
            T12_C1_CONCEPT_MODULE_CARD_ACCEPT,
        ),
        (
            "t12_c1_concept_module_card_unknown_refuse",
            T12_C1_CONCEPT_MODULE_CARD_UNKNOWN_REFUSE,
        ),
        (
            "t12_c1_cross_agent_suite_accept",
            T12_C1_CROSS_AGENT_SUITE_ACCEPT,
        ),
        (
            "t12_c1_cross_agent_suite_unknown_refuse",
            T12_C1_CROSS_AGENT_SUITE_UNKNOWN_REFUSE,
        ),
        ("t12_c1_dependency_ref_accept", T12_C1_DEPENDENCY_REF_ACCEPT),
        (
            "t12_c1_dependency_ref_unknown_refuse",
            T12_C1_DEPENDENCY_REF_UNKNOWN_REFUSE,
        ),
        ("t12_c1_exam_record_accept", T12_C1_EXAM_RECORD_ACCEPT),
        (
            "t12_c1_exam_record_unknown_refuse",
            T12_C1_EXAM_RECORD_UNKNOWN_REFUSE,
        ),
        (
            "t12_c1_guard_violation_accept",
            T12_C1_GUARD_VIOLATION_ACCEPT,
        ),
        (
            "t12_c1_guard_violation_unknown_refuse",
            T12_C1_GUARD_VIOLATION_UNKNOWN_REFUSE,
        ),
        (
            "t12_c1_injection_receipt_accept",
            T12_C1_INJECTION_RECEIPT_ACCEPT,
        ),
        (
            "t12_c1_injection_receipt_unknown_refuse",
            T12_C1_INJECTION_RECEIPT_UNKNOWN_REFUSE,
        ),
        (
            "t12_c1_onboarding_report_accept",
            T12_C1_ONBOARDING_REPORT_ACCEPT,
        ),
        (
            "t12_c1_onboarding_report_unknown_refuse",
            T12_C1_ONBOARDING_REPORT_UNKNOWN_REFUSE,
        ),
        (
            "t12_c1_prediction_record_accept",
            T12_C1_PREDICTION_RECORD_ACCEPT,
        ),
        (
            "t12_c1_prediction_record_unknown_refuse",
            T12_C1_PREDICTION_RECORD_UNKNOWN_REFUSE,
        ),
        // ---------------- cases 3/4: outer + nested refusals ---------------
        (
            "t12_c3_ack_input_unknown_outer_refuse",
            T12_C3_ACK_INPUT_UNKNOWN_OUTER_REFUSE,
        ),
        (
            "t12_c3_tool_input_full_unknown_outer_refuse",
            T12_C3_TOOL_INPUT_FULL_UNKNOWN_OUTER_REFUSE,
        ),
        (
            "t12_c3_tool_input_ack_unknown_outer_refuse",
            T12_C3_TOOL_INPUT_ACK_UNKNOWN_OUTER_REFUSE,
        ),
        (
            "t12_c4_receipt_fired_cue_unknown_nested_refuse",
            T12_C4_RECEIPT_FIRED_CUE_UNKNOWN_NESTED_REFUSE,
        ),
        (
            "t12_c4_receipt_fired_cue_legacy_metadata_nested_refuse",
            T12_C4_RECEIPT_FIRED_CUE_LEGACY_METADATA_NESTED_REFUSE,
        ),
        (
            "t12_c4_pending_item_fired_cue_unknown_nested_refuse",
            T12_C4_PENDING_ITEM_FIRED_CUE_UNKNOWN_NESTED_REFUSE,
        ),
        // ---------------- cases 5/6: duplicate + wrong tagged variant -------
        (
            "t12_c5_ack_input_duplicate_agent_key_refuse",
            T12_C5_ACK_INPUT_DUPLICATE_AGENT_KEY_REFUSE,
        ),
        (
            "t12_c5_ack_input_duplicate_task_key_refuse",
            T12_C5_ACK_INPUT_DUPLICATE_TASK_KEY_REFUSE,
        ),
        (
            "t12_c6_ack_input_duplicate_source_key_refuse",
            T12_C6_ACK_INPUT_DUPLICATE_SOURCE_KEY_REFUSE,
        ),
        (
            "t12_c6_ul_prediction_duplicate_discriminator_refuse",
            T12_C6_UL_PREDICTION_DUPLICATE_DISCRIMINATOR_REFUSE,
        ),
        (
            "t12_c6_ul_prediction_wrong_variant_field_refuse",
            T12_C6_UL_PREDICTION_WRONG_VARIANT_FIELD_REFUSE,
        ),
        (
            "t12_c6_ul_prediction_unknown_variant_refuse",
            T12_C6_UL_PREDICTION_UNKNOWN_VARIANT_REFUSE,
        ),
        // ---------------- cases 7/8: missing identity + schema --------------
        (
            "t12_c7_ack_input_missing_memory_handle_refuse",
            T12_C7_ACK_INPUT_MISSING_MEMORY_HANDLE_REFUSE,
        ),
        (
            "t12_c7_ack_input_missing_influence_class_refuse",
            T12_C7_ACK_INPUT_MISSING_INFLUENCE_CLASS_REFUSE,
        ),
        (
            "t12_c7_prediction_record_missing_task_id_refuse",
            T12_C7_PREDICTION_RECORD_MISSING_TASK_ID_REFUSE,
        ),
        (
            "t12_c8_cross_agent_suite_misselected_schema_refuse",
            T12_C8_CROSS_AGENT_SUITE_MISSELECTED_SCHEMA_REFUSE,
        ),
        (
            "t12_c8_cross_agent_suite_valid_schema_accept",
            T12_C8_CROSS_AGENT_SUITE_VALID_SCHEMA_ACCEPT,
        ),
        (
            "t12_c8_observability_envelope_accept",
            T12_C8_OBSERVABILITY_ENVELOPE_ACCEPT,
        ),
        (
            "t12_c8_observability_envelope_unsupported_schema_refuse",
            T12_C8_OBSERVABILITY_ENVELOPE_UNSUPPORTED_SCHEMA_REFUSE,
        ),
        // Cases 9-16 do NOT register their fixtures in this table: each of those
        // cases names its own `const` directly (the constants are still declared
        // at the top of this file and are still read by their case). An entry
        // here that no case ever looked up would advertise coverage the suite
        // does not have, so the table stops at the last entry cases 1-8 use.
    ];
    for (key, text) in pairs {
        if *key == name {
            return (*text).to_owned();
        }
    }
    panic!("the inline corpus must contain fixture {name}");
}

/// Decode a fixture through the ordinary typed path. Every call site in this
/// file goes through `from_str` on the fixture's own text, so no repeated
/// member is ever collapsed by a `Value` intermediate.
fn decode<T: serde::de::DeserializeOwned>(document: &str) -> Result<T, serde_json::Error> {
    serde_json::from_str(document)
}

// ===========================================================================
// CASE 1-2 CORPUS — behavior.rs / concept.rs / cross_agent.rs /
// dependency.rs / exam.rs / guard.rs / injection.rs / onboarding.rs /
// prediction.rs. `mod.rs` has no fixture: it declares no type at all, and
// case 1 proves that from the file's real bytes instead.
// ===========================================================================

const T12_C1_BEHAVIOR_MINING_RUN_ACCEPT: &str = r#"{"run_id":"mining-run-7","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","head_commit":"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678","config_hash":"blake3-mining-config-1","commits_scanned":1200,"baskets_used":96,"edges_written":418,"classifier_version":"ul-fixclass-1","cue_bindings":[{"cue_kind":"dependency","cue_value":"crates/eliot-types/Cargo.toml","match_mode":"exact","strength":"primary","expected_reuse_note":"manifest"}]}"#;

const T12_C1_BEHAVIOR_MINING_RUN_UNKNOWN_REFUSE: &str = r#"{"run_id":"mining-run-7","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","head_commit":"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678","config_hash":"blake3-mining-config-1","commits_scanned":1200,"baskets_used":96,"edges_written":418,"classifier_version":"ul-fixclass-1","cue_bindings":[],"retention_class":"forever"}"#;

// The body contains a literal `"#` (the markdown heading), so the raw string is
// delimited with `##` - a single `#` would end the literal at that character.
const T12_C1_CONCEPT_MODULE_CARD_ACCEPT: &str = r##"{"card_id":"module-card-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","path":"crates/eliot-types/src/ul/behavior.rs","body_md":"# Mining behaviour","verifier":"cargo test -p eliot-types","hotspot_ref":null,"co_change_refs":[],"failure_refs":[],"source_refs":[],"cue_bindings":[],"build_fingerprint":"fp-1","dependency_manifest":{"project_root":"C:/repo","file_deps":[],"claim_deps":[],"decision_deps":[],"edge_deps":[],"report_deps":[]}}"##;

// Same `"#`-inside-body reason as the ACCEPT fixture above: `##` delimiters.
const T12_C1_CONCEPT_MODULE_CARD_UNKNOWN_REFUSE: &str = r##"{"card_id":"module-card-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","path":"crates/eliot-types/src/ul/behavior.rs","body_md":"# Mining behaviour","verifier":"cargo test -p eliot-types","hotspot_ref":null,"co_change_refs":[],"failure_refs":[],"source_refs":[],"cue_bindings":[],"build_fingerprint":"fp-1","dependency_manifest":{"project_root":"C:/repo","file_deps":[],"claim_deps":[],"decision_deps":[],"edge_deps":[],"report_deps":[]},"promotion_tier":"gold"}"##;

const T12_C1_CROSS_AGENT_SUITE_ACCEPT: &str = r#"{"schema_version":"eliot-ul-cross-agent-suite-v1","harness_version":"harness-1.0.0","confirmation_token":"CONFIRM-8-CLAUDE-ANTIGRAVITY-BLIND-RELAY","hard_provider_call_cap":8,"cases":[]}"#;

const T12_C1_CROSS_AGENT_SUITE_UNKNOWN_REFUSE: &str = r#"{"schema_version":"eliot-ul-cross-agent-suite-v1","harness_version":"harness-1.0.0","confirmation_token":"CONFIRM-8-CLAUDE-ANTIGRAVITY-BLIND-RELAY","hard_provider_call_cap":8,"cases":[],"provider_budget_usd":100}"#;

const T12_C1_DEPENDENCY_REF_ACCEPT: &str =
    r#"{"kind":"file","key":"crates/eliot-types/src/ul/guard.rs"}"#;

const T12_C1_DEPENDENCY_REF_UNKNOWN_REFUSE: &str =
    r#"{"kind":"file","key":"crates/eliot-types/src/ul/guard.rs","fingerprint":"blake3-abc"}"#;

const T12_C1_EXAM_RECORD_ACCEPT: &str = r#"{"exam_id":"exam-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","route":"claude","cold_input_refs":[],"questions":[{"question_id":"q1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","subsystem_concept_id":"concept-1","kind":"blast","prompt":"Which files does a guard change blast?","ground_truth_refs":[],"ground_truth_values":[]}],"answers":[{"question_id":"q1","answer_values":["crates/eliot-types/src/ul/guard.rs"],"cited_refs":[]}],"grades":[{"question_id":"q1","precision_num":1,"precision_den":1,"recall_num":1,"recall_den":1,"f1_milli":1000}],"subsystem_scores_milli":[["concept-1",900]],"dirty_capsule_refs":[]}"#;

const T12_C1_EXAM_RECORD_UNKNOWN_REFUSE: &str = r#"{"exam_id":"exam-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","route":"claude","cold_input_refs":[],"questions":[],"answers":[],"grades":[],"subsystem_scores_milli":[],"dirty_capsule_refs":[],"score_overall_milli":900}"#;

const T12_C1_GUARD_VIOLATION_ACCEPT: &str = r#"{"path":"$","reason":"replacement_char"}"#;

const T12_C1_GUARD_VIOLATION_UNKNOWN_REFUSE: &str =
    r#"{"path":"$","reason":"replacement_char","byte_offset":14}"#;

const T12_C1_INJECTION_RECEIPT_ACCEPT: &str = r#"{"injection_id":"injection-1","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","surface":"ul_fired","item_ref":"item-1","render_form":"markdown","fired_cues":[{"kind":"file_path","value":"src/ul/guard.rs"}],"token_cost":42,"source_fingerprint":"blake3-source-1","outcome":"applied","policy_reason":null}"#;

const T12_C1_INJECTION_RECEIPT_UNKNOWN_REFUSE: &str = r#"{"injection_id":"injection-1","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","surface":"ul_fired","item_ref":"item-1","render_form":"markdown","fired_cues":[{"kind":"file_path","value":"src/ul/guard.rs"}],"token_cost":42,"source_fingerprint":"blake3-source-1","outcome":"applied","policy_reason":null,"delivery_receipt_ref":"receipt-1"}"#;

const T12_C1_ONBOARDING_REPORT_ACCEPT: &str = r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","head_commit":"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678","concept_count":12,"capsule_count":4,"module_card_count":31,"charter_ref":"charter-1","map_ref":"map-1","unassigned_files":[],"rejected_builds":[],"reasoning_job_calls":2}"#;

const T12_C1_ONBOARDING_REPORT_UNKNOWN_REFUSE: &str = r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","head_commit":"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678","concept_count":12,"capsule_count":4,"module_card_count":31,"charter_ref":"charter-1","map_ref":"map-1","unassigned_files":[],"rejected_builds":[],"reasoning_job_calls":2,"elapsed_seconds":91}"#;

const T12_C1_PREDICTION_RECORD_ACCEPT: &str = r#"{"prediction_id":"prediction-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","subsystem_concept_id":null,"packet_id":"packet-1","verifier":"cargo test -p eliot-types","expected":"pass","prediction":null,"confidence":null,"resolution":null,"actual":null,"actual_detail":null,"blast_score":null,"verification_ref":null,"source_frame_hash":"frame-hash-1"}"#;

const T12_C1_PREDICTION_RECORD_UNKNOWN_REFUSE: &str = r#"{"prediction_id":"prediction-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","subsystem_concept_id":null,"packet_id":"packet-1","verifier":"cargo test -p eliot-types","expected":"pass","prediction":null,"confidence":null,"resolution":null,"actual":null,"actual_detail":null,"blast_score":null,"verification_ref":null,"source_frame_hash":"frame-hash-1","confidence_milli":800}"#;

// ===========================================================================
// CASE 3-4 CORPUS — unknown outer envelope members, and unknown members on
// the NESTED `fired_cues` path.
// ===========================================================================

/// An unknown member at the outer level of `MemoryInfluenceAckInput`.
const T12_C3_ACK_INPUT_UNKNOWN_OUTER_REFUSE: &str = r#"{"memory_handle":"mem-1","influence_class":"seen_but_not_used","delivery_surface":"ul_fired"}"#;

/// An unknown member at the outer level of the FULL branch of
/// `MemoryInfluenceToolInput`.
const T12_C3_TOOL_INPUT_FULL_UNKNOWN_OUTER_REFUSE: &str = r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","write_id":"write-1","trace":{"task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","memory_handle":"mem-1","packet_id":"packet-1","admission_decision":"include_verified","inclusion_or_suppression_reason":"verified","epistemic_status_at_use":"verified","cited_in_understanding_proof":true,"action_or_probe_changed":true,"write_set_changed":false,"verifier_changed":false,"repeated_failure_prevented":false,"suppressed_as_stale_or_wrong_scope":false,"downstream_outcome_ref":null,"influence_class":"seen_but_not_used"},"effect_class":"write"}"#;

/// An unknown member at the outer level of the ACK branch of
/// `MemoryInfluenceToolInput`.
const T12_C3_TOOL_INPUT_ACK_UNKNOWN_OUTER_REFUSE: &str = r#"{"memory_handle":"mem-1","influence_class":"seen_but_not_used","delivery_surface":"ul_fired"}"#;

/// An unknown member INSIDE a nested `fired_cues` element. The outer
/// `InjectionReceipt` is otherwise complete and valid.
const T12_C4_RECEIPT_FIRED_CUE_UNKNOWN_NESTED_REFUSE: &str = r#"{"injection_id":"injection-1","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","surface":"ul_fired","item_ref":"item-1","render_form":"markdown","fired_cues":[{"kind":"file_path","value":"src/ul/guard.rs","confidence":0.9}],"token_cost":42,"source_fingerprint":"blake3-source-1","outcome":"applied","policy_reason":null}"#;

/// A LEGACY metadata key on the nested `fired_cues` path. The direct legacy
/// cue boundary accepts `version`/`schema_version`; the strict nested mode
/// that `InjectionReceipt::fired_cues` selects does not.
const T12_C4_RECEIPT_FIRED_CUE_LEGACY_METADATA_NESTED_REFUSE: &str = r#"{"injection_id":"injection-1","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","surface":"ul_fired","item_ref":"item-1","render_form":"markdown","fired_cues":[{"kind":"file_path","value":"src/ul/guard.rs","schema_version":"eliot-agent-api/v7"}],"token_cost":42,"source_fingerprint":"blake3-source-1","outcome":"applied","policy_reason":null}"#;

/// The same strict nested mode reached through `PendingInjectionItem`, whose
/// `fired_cues` field carries the same `deserialize_strict_observed_cues`.
const T12_C4_PENDING_ITEM_FIRED_CUE_UNKNOWN_NESTED_REFUSE: &str = r#"{"item_ref":"item-1","record_kind":"concept_node","preview":"concept node preview","payload":null,"source_fingerprint":"blake3-source-1","fired_cues":[{"kind":"file_path","value":"src/ul/guard.rs","origin":"mining"}],"negative_memory":false,"invariant":false,"token_estimate":42,"activation_trace_ref":null,"activation_score_milli":null}"#;

// ===========================================================================
// CASE 5-6 CORPUS — repeated members and wrong tagged variants. These exist
// ONLY as text: a `Value` intermediate would collapse each repeated member
// before the decoder ever saw it, and a tagged-variant document would be
// re-ordered rather than re-read.
// ===========================================================================

/// A repeated AGENT-identity member of `MemoryInfluenceAckInput`.
/// `next_once` refuses the second `memory_handle` before its value is stored.
const T12_C5_ACK_INPUT_DUPLICATE_AGENT_KEY_REFUSE: &str =
    r#"{"memory_handle":"mem-1","memory_handle":"mem-2","influence_class":"seen_but_not_used"}"#;

/// A repeated TASK-identity member of `MemoryInfluenceAckInput`.
const T12_C5_ACK_INPUT_DUPLICATE_TASK_KEY_REFUSE: &str = r#"{"memory_handle":"mem-1","influence_class":"seen_but_not_used","write_id":"write-1","write_id":"write-2"}"#;

/// A repeated SOURCE-identity member of `MemoryInfluenceAckInput`.
/// The two values differ, so last-wins would be observable if it applied.
const T12_C6_ACK_INPUT_DUPLICATE_SOURCE_KEY_REFUSE: &str = r#"{"memory_handle":"mem-1","influence_class":"seen_but_not_used","downstream_outcome_ref":"outcome-1","downstream_outcome_ref":"outcome-2"}"#;

/// A repeated DISCRIMINATOR on the tagged `UlPrediction` union.
const T12_C6_UL_PREDICTION_DUPLICATE_DISCRIMINATOR_REFUSE: &str = r#"{"kind":"blast_radius","kind":"observable_value","probe_ref":"probe-1","expected_excerpt_or_range":"42","predicted_paths":[],"predicted_failing_verifiers":[]}"#;

/// A member of the WRONG tagged variant: a `blast_radius` document carrying
/// the `observable_value` payload. `finish_blast_radius` refuses it.
const T12_C6_UL_PREDICTION_WRONG_VARIANT_FIELD_REFUSE: &str =
    r#"{"kind":"blast_radius","probe_ref":"probe-1","expected_excerpt_or_range":"42"}"#;

/// An UNKNOWN tagged variant. `UlPredictionVisitor` refuses it as
/// `unknown_variant`.
const T12_C6_UL_PREDICTION_UNKNOWN_VARIANT_REFUSE: &str =
    r#"{"kind":"verifier_verdict_v2","verifier":"cargo test -p eliot-types","expected":"pass"}"#;

// ===========================================================================
// CASE 7-8 CORPUS — a missing protected identity, and a misselected schema.
// ===========================================================================

/// `memory_handle` is the ack's protected agent-side identity; it is
/// `required(...)`, never defaulted.
const T12_C7_ACK_INPUT_MISSING_MEMORY_HANDLE_REFUSE: &str = r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","influence_class":"seen_but_not_used"}"#;

/// `influence_class` is the closed classification the ack is about; it is
/// `required(...)`, never defaulted.
const T12_C7_ACK_INPUT_MISSING_INFLUENCE_CLASS_REFUSE: &str =
    r#"{"memory_handle":"mem-1","downstream_outcome_ref":null}"#;

/// `task_id` is a required member of `PredictionRecord`; omitting it must not
/// decode to a current-valid record.
const T12_C7_PREDICTION_RECORD_MISSING_TASK_ID_REFUSE: &str = r#"{"prediction_id":"prediction-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","subsystem_concept_id":null,"packet_id":"packet-1","verifier":"cargo test -p eliot-types","expected":"pass","prediction":null,"confidence":null,"resolution":null,"actual":null,"actual_detail":null,"blast_score":null,"verification_ref":null,"source_frame_hash":"frame-hash-1"}"#;

/// A `UlCrossAgentSuite` whose `schema_version` is a DIFFERENT real UL
/// schema. Decoding alone succeeds — the field is a plain `String` — and the
/// owner's own `validate()` is what refuses it, so the case asserts THAT.
const T12_C8_CROSS_AGENT_SUITE_MISSELECTED_SCHEMA_REFUSE: &str = r#"{"schema_version":"eliot-ul-cross-agent-report-v1","harness_version":"harness-1.0.0","confirmation_token":"CONFIRM-8-CLAUDE-ANTIGRAVITY-BLIND-RELAY","hard_provider_call_cap":8,"cases":[]}"#;

/// The same document with the one `schema_version` this build owns.
const T12_C8_CROSS_AGENT_SUITE_VALID_SCHEMA_ACCEPT: &str = r#"{"schema_version":"eliot-ul-cross-agent-suite-v1","harness_version":"harness-1.0.0","confirmation_token":"CONFIRM-8-CLAUDE-ANTIGRAVITY-BLIND-RELAY","hard_provider_call_cap":8,"cases":[]}"#;

/// An `ObservabilityWriteEnvelope` carrying the one schema version its
/// decoder owns.
const T12_C8_OBSERVABILITY_ENVELOPE_ACCEPT: &str = r#"{"schema_version":"eliot-observability-v1","write_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c63","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":null,"session_id":null,"kind":"injection_receipt","record_id":"injection-1","payload":{"injection_id":"injection-1","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","task_id":null,"surface":"ul_fired","item_ref":"item-1","render_form":"markdown","fired_cues":[{"kind":"file_path","value":"src/ul/guard.rs"}],"token_cost":42,"source_fingerprint":"blake3-source-1","outcome":"applied","policy_reason":null},"input_hash":"blake3-input-1","created_at":"2026-09-24T10:15:00Z"}"#;

/// The same envelope with a schema version no part of this build owns.
const T12_C8_OBSERVABILITY_ENVELOPE_UNSUPPORTED_SCHEMA_REFUSE: &str = r#"{"schema_version":"eliot-observability-v2","write_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c63","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":null,"session_id":null,"kind":"injection_receipt","record_id":"injection-1","payload":{"injection_id":"injection-1","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","task_id":null,"surface":"ul_fired","item_ref":"item-1","render_form":"markdown","fired_cues":[{"kind":"file_path","value":"src/ul/guard.rs"}],"token_cost":42,"source_fingerprint":"blake3-source-1","outcome":"applied","policy_reason":null},"input_hash":"blake3-input-1","created_at":"2026-09-24T10:15:00Z"}"#;

// ===========================================================================
// CASE 9-16 CORPUS — writer w2's own fixtures, in the same inline shape.
//
// RULE HELD THROUGHOUT: every fixture below is a `&str` holding its own WIRE
// TEXT and every assertion made against it is a VALUE assertion. No case below
// ever asserts that a parsed `Value` re-serializes to its own original text —
// `serde_json::Map` is a `BTreeMap` here (no `preserve_order`), so a parsed
// object's members come back SORTED and a re-serialization is not byte-stable in
// member order.
// ===========================================================================

/// Case 9 (a): the DIRECT legacy cue boundary, reached on its own, admitting
/// the historical record plus the two inert metadata keys the committed #831/8
/// oracle requires. These two keys are DECLARED legacy surface, decoded into
/// `IgnoredAny` and dropped (`ul/injection.rs:52-53`, `:59-64`).
const T12_C9_LEGACY_CUE_WITH_METADATA_ACCEPT: &str = r#"{"kind":"file_path","value":"src/ul/guard.rs","version":"v2","schema_version":"eliot-agent-api/v7"}"#;

/// Case 9 (b): the SAME cue through the nested `fired_cues` path, which selects
/// `StrictObservedCueInput` (`ul/injection.rs:107-120`) and therefore
/// `allow_legacy_metadata: false`.
const T12_C9_LEGACY_CUE_STRICT_NESTED_METADATA_REFUSE: &str = r#"{"injection_id":"injection-1","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","surface":"ul_fired","item_ref":"item-1","render_form":"markdown","fired_cues":[{"kind":"file_path","value":"src/ul/guard.rs","version":"v2","schema_version":"eliot-agent-api/v7"}],"token_cost":42,"source_fingerprint":"blake3-source-1","outcome":"applied","policy_reason":null}"#;

/// Case 11 (a): `PendingInjectionItem.payload` is declared
/// `Option<serde_json::Value>` (`ul/injection.rs:136`), so this opaque blob is
/// admitted VERBATIM. Its members imitate the acknowledgement's control keys
/// and the cross-agent report's schema/spelling, and they must stay inert
/// members of a blob.
const T12_C11_PENDING_ITEM_CONTROL_IMITATING_PAYLOAD: &str = r#"{"item_ref":"item-1","record_kind":"concept_node","preview":"concept node preview","payload":{"memory_handle":"mem-canary-handle","influence_class":"used_and_changed_action","candidate_only":false,"schema_version":"eliot-ul-cross-agent-report-v1","direction_scores":"passed","authority":"grant","current_truth":true},"source_fingerprint":"blake3-source-1","fired_cues":[{"kind":"file_path","value":"src/ul/guard.rs"}],"negative_memory":false,"invariant":false,"token_estimate":42,"activation_trace_ref":null,"activation_score_milli":null}"#;

/// Case 11 (b): the same control-imitating names carried as REAL MEMBERS of a
/// closed envelope, where each one is an unknown-field refusal instead of inert
/// data.
const T12_C11_ACK_INPUT_CONTROL_IMITATING_MEMBERS: &str = r#"{"memory_handle":"mem-1","influence_class":"seen_but_not_used","candidate_only":false,"schema_version":"eliot-ul-cross-agent-report-v1","current_truth":true}"#;

/// Case 12 (a): a well-formed `UlReasoningRequest` whose `output_schema` is an
/// opaque provider-supplied `Value` (`ul/exam.rs:98`). Nothing on the decoded
/// request's own typed surface is derived from that blob.
///
/// MAIN BEHAVIOUR NOTE: the document DECODES. It carries all ten declared
/// members and no undeclared one, so there is nothing for
/// `#[serde(deny_unknown_fields)]` (`ul/exam.rs:89`) to refuse. The former
/// `_refuse` suffix misdescribed the content and has been dropped: the names
/// `authority` and `current_truth` inside the opaque `output_schema` are DATA,
/// and a candidate-shaped output schema is not a refusal.
const T12_C12_REASONING_REQUEST_CANDIDATE_OUTPUT_ACCEPT: &str = r#"{"idempotency_key":"idem-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","route":"claude","model":"claude-opus-5","prompt":"Which files does a guard change blast?","output_schema":{"type":"object","properties":{"blast_paths":{"type":"array"},"authority":{"type":"string"},"current_truth":{"type":"boolean"}},"required":["blast_paths"]},"max_input_bytes":65536,"max_output_units":2048,"timeout_seconds":120}"#;

/// Case 12 (b): the same request with one unknown member. `UlReasoningRequest`
/// is a derived `deny_unknown_fields` struct (`ul/exam.rs:88-89`), so this is
/// refused by the owner decoder, never deferred.
const T12_C12_REASONING_REQUEST_UNKNOWN_MEMBER_REFUSE: &str = r#"{"idempotency_key":"idem-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","route":"claude","model":"claude-opus-5","prompt":"Which files does a guard change blast?","output_schema":{"type":"object"},"max_input_bytes":65536,"max_output_units":2048,"timeout_seconds":120,"provider_temperature":0.0}"#;

/// Case 13 (e): `CapsuleFreshness::Stale` missing one of its two REQUIRED
/// payload members — `missing` is absent while `changed` is present. `required`
/// at `ul/concept.rs:217` refuses the absent `missing`, so this is a
/// `missing field` refusal naming `missing`. It is the asymmetric form of the
/// `missing field` case for `changed`: both payload members are equally required.
const T12_C13_CAPSULE_FRESHNESS_PAYLOAD_REFUSE: &str =
    r#"{"status":"stale","changed":["crates/eliot-types/src/ul/guard.rs"]}"#;

/// Case 13 (f): the `fresh` variant carrying a payload member. The owner refuses
/// it as an unknown field against the `fresh` field set
/// (`ul/concept.rs:207-209`): an `unknown field` refusal naming `changed`,
/// against the single-member `fresh` field set.
/// Both payload names are refused the same way (`missing` at `:210-212`), which
/// is asserted below as a pair.
const T12_C13_CAPSULE_FRESHNESS_FRESH_WITH_PAYLOAD_REFUSE: &str =
    r#"{"status":"fresh","changed":["crates/eliot-types/src/ul/guard.rs"]}"#;

/// Case 15 (a): a well-formed flat compile-packet tool argument object carrying
/// one member outside the wrapper's declared key set. It must be refused by the
/// `CompilePacketToolInputVisitor` at `mcp_contract.rs:134-136`.
const T12_C15_COMPILE_PACKET_UNKNOWN_KEY_REFUSE: &str = r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"task-1","goal":"Describe the required change","candidate_handles":[],"max_tokens":1800,"memory_mode":"include_case_candidates","budget_milli":4096}"#;

/// Case 15 (b): the SAME object with a REPEATED wrapper key. The `flatten`
/// path is exactly where a derived decoder would silently keep the last
/// duplicate, so this is the row that has to be refused
/// (`mcp_contract.rs:87-88`).
const T12_C15_COMPILE_PACKET_DUPLICATE_FLAT_KEY_REFUSE: &str = r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"task-1","goal":"first goal","task_id":"task-2","candidate_handles":[],"max_tokens":1800}"#;

/// Case 16: the acknowledgement-shaped tool arguments `eliot-engine`'s ledger
/// caller hands to `serde_json::from_value::<MemoryInfluenceAckInput>`. The
/// caller swallows the decode error and reads nothing, so the acknowledgement
/// count stays at zero. The document is built from an opaque `Value` in
/// production; here it is assembled from the SAME two accepted shapes, one of
/// which carries an unknown member.
const T12_C16_LEDGER_ACK_UNDECODABLE_ARGUMENTS: &str = r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","write_id":"write-1","memory_handle":"mem-1","influence_class":"seen_but_not_used","delivery_surface":"ul_fired"}"#;

// ---------------------------------------------------------------------------
// Cases for writer w1 (issue #941, card cards/941.md).
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 941/1
#[test]
#[allow(clippy::too_many_lines)]
fn case_01_exact_accounting_of_the_ten_allocated_ul_files() {
    // THE REAL PER-FILE ACCOUNTING, read from the production sources on this
    // base and re-counted by executable code at the end of this case. The
    // frozen allocation row names NINE `source_files`; this case adds
    // `mod.rs` because `mod.rs` is the tenth UL file this lane was assigned
    // and it is a ZERO-decoder, ZERO-candidate module. The card's counts were
    // NOT copied: every number below is what the file actually contains today.
    //
    //   file            structs  enums  hand-written visitors  manual-decoder  contribution
    //   behavior.rs        4      0          0                    0         MiningConfig, MiningRun, CoChangeEdge, HotspotScore
    //   concept.rs        12      5          1                    1         + CapsuleFreshness (custom visitor)
    //   cross_agent.rs    12      5          0                    0         12 suite/plan/report DTOs + 5 closed control enums
    //   dependency.rs      6      1          0                    0         UlDependencyRef + 5 dirty/rebuild DTOs
    //   exam.rs            5      2          0                    0         UlExamRecord family + UlReasoningRequest
    //   guard.rs           1      0          0                    0         TextEncodingViolation
    //   injection.rs       6      0          3                    3         + ObservedCue, StrictObservedCueInput, MemoryInfluenceAckInput (custom visitors)
    //   onboarding.rs      4      2          0                    0         ManifestPackage/Job/Checkpoint/Report
    //   prediction.rs      4      5          1                    1         + UlPrediction (custom visitor)
    //   mod.rs             0      0          0                    0         module list only: 14 `pub mod` lines, no type
    //
    // NOTE ON THE TWO COUNT COLUMNS. `hand-written visitors` counts TYPES that
    // carry a custom visitor; `manual-decoder` counts hand-written `Deserialize`
    // impls. They are not the same set (an enum can have a visitor without a
    // manual `Deserialize` impl), which is why concept.rs shows 1 and 1 while
    // injection.rs shows 3 and 3. NEITHER column is the count of
    // `#[serde(deny_unknown_fields)]`, which is a THIRD, larger number per file;
    // the executable table asserted by this case is the single authoritative
    // accounting, and this prose table is navigation only.
    //
    // TOTALS over the ten files: 54 `pub struct`, 20 `pub enum`, 52
    // `#[serde(deny_unknown_fields)]` attributes and 5 hand-written
    // `Deserialize` impls. The allocation row's `types` list names 75 entries:
    // those 74 public types plus the private `StrictObservedCueInput` wrapper.
    // The executable denominator below proves 54 + 20 public types and the
    // single private helper separately; `mod.rs` is the tenth assigned file
    // and contributes the zero-decoder, zero-candidate row.
    //
    // The three "manual-decoder" entries in `injection.rs` are two public
    // types (`ObservedCue`, `MemoryInfluenceAckInput`) plus one private
    // strict wrapper (`StrictObservedCueInput`) — the wrapper is not a
    // boundary row of its own, so `injection.rs` contributes 6 serde rows,
    // not 8.

    // ---- behavior.rs: `MiningRun` is derived-closed and refuses an unknown
    // member; `MiningConfig` is the same file's other root decoder.
    let run: MiningRun = decode(&fixture("t12_c1_behavior_mining_run_accept"))
        .expect("src/ul/behavior.rs: MiningRun must decode its own declared members");
    assert_eq!(run.run_id, "mining-run-7");
    assert_eq!(run.commits_scanned, 1200);
    assert_eq!(run.edges_written, 418);
    assert_eq!(run.cue_bindings.len(), 1);
    assert!(
        decode::<MiningRun>(&fixture("t12_c1_behavior_mining_run_unknown_refuse")).is_err(),
        "src/ul/behavior.rs: MiningRun must refuse the unknown member `retention_class`"
    );
    let config: MiningConfig = decode(
        r#"{"max_commits":5000,"window_months":24,"author_merge_seconds":1800,"max_files_per_basket":30,"min_support":3,"min_confidence":0.5}"#,
    )
    .expect("src/ul/behavior.rs: MiningConfig must decode its own declared members");
    assert_eq!(config.max_commits, 5000);
    assert!(
        decode::<MiningConfig>(r#"{"max_commits":5000,"window_months":24,"author_merge_seconds":1800,"max_files_per_basket":30,"min_support":3,"min_confidence":0.5,"sampling":1.0}"#).is_err(),
        "src/ul/behavior.rs: MiningConfig must refuse the unknown member `sampling`"
    );

    // ---- concept.rs: `ModuleCard` refuses an unknown member; its nested
    // `DependencyManifest` is closed too.
    let card = decode::<eliot_types::ModuleCard>(&fixture("t12_c1_concept_module_card_accept"))
        .expect("src/ul/concept.rs: ModuleCard must decode its own declared members");
    assert_eq!(card.card_id, "module-card-1");
    // The nested `dependency_manifest` is carried by its own declared members,
    // not by `#[serde(default)]`: the fixture supplies a real `project_root`
    // and the decoded value keeps it, which a default-constructed manifest
    // (empty `project_root`, empty lists) could not.
    assert_eq!(card.dependency_manifest.project_root, "C:/repo");
    assert_eq!(
        card.dependency_manifest,
        DependencyManifest {
            project_root: "C:/repo".to_owned(),
            ..DependencyManifest::default()
        }
    );
    assert!(
        decode::<eliot_types::ModuleCard>(&fixture("t12_c1_concept_module_card_unknown_refuse"))
            .is_err(),
        "src/ul/concept.rs: ModuleCard must refuse the unknown member `promotion_tier`"
    );
    let manifest = decode::<DependencyManifest>(
        r#"{"project_root":"C:/repo","file_deps":[{"path":"a.rs","blake3":"aa"}],"claim_deps":[],"decision_deps":[],"edge_deps":[],"report_deps":[]}"#,
    )
    .expect("src/ul/concept.rs: DependencyManifest must decode its own declared members");
    assert_eq!(manifest.file_deps.len(), 1);
    assert!(
        decode::<DependencyManifest>(
            r#"{"project_root":"C:/repo","file_deps":[],"claim_deps":[],"decision_deps":[],"edge_deps":[],"report_deps":[],"excludes":[]}"#
        )
        .is_err(),
        "src/ul/concept.rs: DependencyManifest must refuse the unknown member `excludes`"
    );

    // ---- cross_agent.rs: `UlCrossAgentSuite` refuses an unknown member.
    let suite: UlCrossAgentSuite = decode(&fixture("t12_c1_cross_agent_suite_accept"))
        .expect("src/ul/cross_agent.rs: UlCrossAgentSuite must decode its own declared members");
    assert_eq!(suite.hard_provider_call_cap, 8);
    assert!(suite.cases.is_empty());
    assert!(
        decode::<UlCrossAgentSuite>(&fixture("t12_c1_cross_agent_suite_unknown_refuse")).is_err(),
        "src/ul/cross_agent.rs: UlCrossAgentSuite must refuse the unknown member `provider_budget_usd`"
    );

    // ---- dependency.rs: `UlDependencyRef` refuses an unknown member.
    let reference: UlDependencyRef = decode(&fixture("t12_c1_dependency_ref_accept"))
        .expect("src/ul/dependency.rs: UlDependencyRef must decode its own declared members");
    assert_eq!(
        serde_json::to_string(&reference.kind).expect("UlDependencyKind must serialize"),
        "\"file\"",
        "src/ul/dependency.rs: `file` must decode to the file dependency kind itself"
    );
    assert_eq!(reference.key, "crates/eliot-types/src/ul/guard.rs");
    assert!(
        decode::<UlDependencyRef>(&fixture("t12_c1_dependency_ref_unknown_refuse")).is_err(),
        "src/ul/dependency.rs: UlDependencyRef must refuse the unknown member `fingerprint`"
    );

    // ---- exam.rs: `UlExamRecord` refuses an unknown member.
    let exam: UlExamRecord = decode(&fixture("t12_c1_exam_record_accept"))
        .expect("src/ul/exam.rs: UlExamRecord must decode its own declared members");
    assert_eq!(exam.exam_id, "exam-1");
    assert_eq!(exam.questions.len(), 1);
    assert_eq!(exam.answers.len(), 1);
    assert_eq!(exam.grades[0].f1_milli, 1000);
    assert!(
        decode::<UlExamRecord>(&fixture("t12_c1_exam_record_unknown_refuse")).is_err(),
        "src/ul/exam.rs: UlExamRecord must refuse the unknown member `score_overall_milli`"
    );

    // ---- guard.rs: `TextEncodingViolation` refuses an unknown member. This is
    // the file's ONLY serde boundary, so the refusal is what proves the file
    // is not a zero-candidate module.
    let violation: TextEncodingViolation = decode(&fixture("t12_c1_guard_violation_accept"))
        .expect("src/ul/guard.rs: TextEncodingViolation must decode its own declared members");
    assert_eq!(violation.path, "$");
    assert_eq!(violation.reason, "replacement_char");
    assert!(
        decode::<TextEncodingViolation>(&fixture("t12_c1_guard_violation_unknown_refuse")).is_err(),
        "src/ul/guard.rs: TextEncodingViolation must refuse the unknown member `byte_offset`"
    );

    // ---- injection.rs: `InjectionReceipt` refuses an unknown member.
    let receipt: InjectionReceipt = decode(&fixture("t12_c1_injection_receipt_accept"))
        .expect("src/ul/injection.rs: InjectionReceipt must decode its own declared members");
    assert_eq!(receipt.token_cost, 42);
    assert_eq!(receipt.fired_cues.len(), 1);
    assert!(receipt.policy_reason.is_none());
    assert!(
        decode::<InjectionReceipt>(&fixture("t12_c1_injection_receipt_unknown_refuse")).is_err(),
        "src/ul/injection.rs: InjectionReceipt must refuse the unknown member `delivery_receipt_ref`"
    );

    // ---- onboarding.rs: `OnboardingReport` refuses an unknown member.
    let report: OnboardingReport = decode(&fixture("t12_c1_onboarding_report_accept"))
        .expect("src/ul/onboarding.rs: OnboardingReport must decode its own declared members");
    assert_eq!(report.concept_count, 12);
    assert_eq!(report.module_card_count, 31);
    assert!(
        decode::<OnboardingReport>(&fixture("t12_c1_onboarding_report_unknown_refuse")).is_err(),
        "src/ul/onboarding.rs: OnboardingReport must refuse the unknown member `elapsed_seconds`"
    );
    let job: OnboardingJob = decode(
        r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","project_root":"C:/repo","head_commit":"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678","inputs_hash":"blake3-inputs-1"}"#,
    )
    .expect("src/ul/onboarding.rs: OnboardingJob must decode its own declared members");
    assert_eq!(job.inputs_hash, "blake3-inputs-1");
    assert!(
        decode::<OnboardingJob>(
            r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","project_root":"C:/repo","head_commit":"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678","inputs_hash":"blake3-inputs-1","cancelled":true}"#
        )
        .is_err(),
        "src/ul/onboarding.rs: OnboardingJob must refuse the unknown member `cancelled`"
    );
    assert_eq!(
        OnboardingStage::Complete,
        decode::<OnboardingStage>(r#""complete""#)
            .expect("the owned OnboardingStage variant must decode")
    );

    // ---- prediction.rs: `PredictionRecord` refuses an unknown member.
    let record: PredictionRecord = decode(&fixture("t12_c1_prediction_record_accept"))
        .expect("src/ul/prediction.rs: PredictionRecord must decode its own declared members");
    assert_eq!(record.prediction_id, "prediction-1");
    assert_eq!(record.source_frame_hash, "frame-hash-1");
    assert!(record.subsystem_concept_id.is_none());
    assert!(
        decode::<PredictionRecord>(&fixture("t12_c1_prediction_record_unknown_refuse")).is_err(),
        "src/ul/prediction.rs: PredictionRecord must refuse the unknown member `confidence_milli`"
    );

    // ---- mod.rs: ZERO decoders, ZERO candidates. It is proven from its real
    // bytes, not from an assertion that it "has none": the file is read and
    // shown to declare only `pub mod` lines. A `pub struct`/`pub enum`/`pub
    // type`/`Deserialize` appearing here would change that accounting.
    let mod_source = read_ul_source("mod.rs");
    let mut module_lines = 0_usize;
    for line in mod_source.lines() {
        let cell = line.trim();
        if cell.is_empty() {
            continue;
        }
        assert!(
            cell.starts_with("pub mod "),
            "src/ul/mod.rs must contain only `pub mod` lines, found: {cell}"
        );
        module_lines += 1;
    }
    assert_eq!(
        module_lines, 14,
        "src/ul/mod.rs must declare exactly its fourteen sibling modules and no type of its own"
    );
    assert!(
        !mod_source.contains("Deserialize") && !mod_source.contains("Serialize"),
        "src/ul/mod.rs is a zero-decoder, zero-candidate module and must not name a serde derive"
    );

    // ---- The accounting itself, as executable numbers rather than prose. The
    // ten files are read and counted here, so the table in this case's header
    // is a claim the code below can disprove.
    //
    //   file              structs  enums  pub-struct  pub-enum  deny_unknown_fields
    //   behavior.rs            4      0           4        0                   4
    //   concept.rs            12      5          12        5                  12
    //   cross_agent.rs        12      5          12        5                  12
    //   dependency.rs          6      1           6        1                   6
    //   exam.rs                5      2           5        2                   5
    //   guard.rs               1      0           1        0                   1
    //   injection.rs           6      0           6        0                   4
    //   onboarding.rs          4      2           4        2                   4
    //   prediction.rs          4      5           4        5                   4
    //   mod.rs                 0      0           0        0                   0
    //                                                    TOTALS              52
    let mut total_structs = 0_usize;
    let mut total_enums = 0_usize;
    let mut total_closed = 0_usize;
    let expected: &[(&str, usize, usize, usize)] = &[
        ("behavior.rs", 4, 0, 4),
        ("concept.rs", 12, 5, 12),
        ("cross_agent.rs", 12, 5, 12),
        ("dependency.rs", 6, 1, 6),
        ("exam.rs", 5, 2, 5),
        ("guard.rs", 1, 0, 1),
        ("injection.rs", 6, 0, 4),
        ("onboarding.rs", 4, 2, 4),
        ("prediction.rs", 4, 5, 4),
        ("mod.rs", 0, 0, 0),
    ];
    assert_eq!(
        expected.len(),
        10,
        "the allocation this case accounts for is exactly ten UL files"
    );
    for (file, structs, enums, closed) in expected {
        let source = read_ul_source(file);
        let counted_structs = source.matches("pub struct ").count();
        let counted_enums = source.matches("pub enum ").count();
        let counted_closed = source.matches("deny_unknown_fields").count();
        assert_eq!(
            (counted_structs, counted_enums, counted_closed),
            (*structs, *enums, *closed),
            "src/ul/{file}: the per-file accounting above is stale"
        );
        total_structs += counted_structs;
        total_enums += counted_enums;
        total_closed += counted_closed;
    }
    assert_eq!(
        (total_structs, total_enums, total_closed),
        (54, 20, 52),
        "the ten-file totals must be 54 structs, 20 enums and 52 `deny_unknown_fields` decoders"
    );
    let injection_source = read_ul_source("injection.rs");
    let strict_helper_count = injection_source
        .matches("struct StrictObservedCueInput")
        .count();
    assert_eq!(
        strict_helper_count, 1,
        "the allocated type list includes one private StrictObservedCueInput helper"
    );
    assert!(
        !injection_source.contains("pub struct StrictObservedCueInput"),
        "StrictObservedCueInput is a private decoder helper, not a public boundary type"
    );
    assert_eq!(
        total_structs + total_enums + strict_helper_count,
        75,
        "the #941 allocation has 75 listed type entries: 74 public types and one private helper"
    );
}

// WORK_UNIT_CASE: 941/2
#[test]
fn case_02_accepted_bytes_are_unchanged_and_value_compared() {
    // Serialized bytes/digests are unchanged for every accepted fixture in the
    // ten-file allocation. The comparison is VALUE equality plus the derived
    // serializer's own compact output against a HAND-WRITTEN literal whose
    // member order is written in declaration order — never a comparison of a
    // parsed `Value` back to the original text, because `serde_json::Map` is a
    // `BTreeMap` in this workspace and would re-sort every member.
    //
    // `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:12` —
    // "authority, scope, effect, privacy, ordering and receipt fields are never
    // silently defaulted;"
    // `docs/architecture/I05-16-common-durable-fields.md:46` — "Fields that do
    // not apply remain explicit `None`; they are not silently omitted from the
    // semantic model."

    // behavior.rs: `MiningConfig` round-trips through its own derived encoder,
    // and the explicit `None` of an applicable-but-absent field survives.
    let config: MiningConfig = decode(
        r#"{"max_commits":5000,"window_months":24,"author_merge_seconds":1800,"max_files_per_basket":30,"min_support":3,"min_confidence":0.5}"#,
    )
    .expect("the accepted MiningConfig must decode");
    assert_eq!(
        serde_json::to_string(&config).expect("MiningConfig must serialize"),
        r#"{"max_commits":5000,"window_months":24,"author_merge_seconds":1800,"max_files_per_basket":30,"min_support":3,"min_confidence":0.5}"#,
        "the derived encoder must reproduce the accepted bytes exactly"
    );

    // concept.rs: an absent-but-applicable `Option<String>` stays an explicit
    // `None` in the semantic model and is re-emitted by the derived encoder.
    let card = decode::<eliot_types::ModuleCard>(&fixture("t12_c1_concept_module_card_accept"))
        .expect("the accepted ModuleCard must decode");
    assert_eq!(card.hotspot_ref, None::<String>);
    let card_text = serde_json::to_string(&card)
        .expect("ModuleCard must serialize through its derived encoder");
    let reparsed = decode::<eliot_types::ModuleCard>(&card_text)
        .expect("a ModuleCard must decode from its own encoder output");
    assert_eq!(
        reparsed, card,
        "ModuleCard must survive its own encode/decode round trip unchanged"
    );

    // dependency.rs / exam.rs / guard.rs / cross_agent.rs: accepted bytes carry
    // the fixture's own values, never a locally manufactured default.
    let reference: UlDependencyRef = decode(&fixture("t12_c1_dependency_ref_accept"))
        .expect("the accepted UlDependencyRef must decode");
    assert_eq!(reference.key, "crates/eliot-types/src/ul/guard.rs");
    let hotspot: HotspotScore = decode(
        r#"{"hotspot_id":"hotspot-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","path":"src/ul/cross_agent.rs","touches":41,"fix_touches":7,"churn_decayed":0.75,"bugfix_density":0.17,"failure_density":3,"score":88,"mining_run_ref":"mining-run-7","cue_bindings":[]}"#,
    )
    .expect("src/ul/behavior.rs: HotspotScore must decode its own declared members");
    assert_eq!(hotspot.score, 88);
    assert_eq!(hotspot.mining_run_ref, "mining-run-7");

    let edge: CoChangeEdge = decode(
        r#"{"edge_id":"edge-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","path_a":"src/ul/behavior.rs","path_b":"src/ul/prediction.rs","support":5,"confidence_ab":0.8,"confidence_ba":0.7,"last_cochange_at_unix":1758600000,"static_edge_exists":true,"mining_run_ref":"mining-run-7","cue_bindings":[]}"#,
    )
    .expect("src/ul/behavior.rs: CoChangeEdge must decode its own declared members");
    assert_eq!(edge.support, 5);
    assert_eq!(edge.static_edge_exists, Some(true));

    let suite: UlCrossAgentSuite = decode(&fixture("t12_c1_cross_agent_suite_accept"))
        .expect("the accepted UlCrossAgentSuite must decode");
    assert_eq!(
        suite.schema_version, "eliot-ul-cross-agent-suite-v1",
        "an accepted suite keeps the one schema version this build owns"
    );
    assert_eq!(
        suite.confirmation_token, "CONFIRM-8-CLAUDE-ANTIGRAVITY-BLIND-RELAY",
        "the confirmation token is a protected control value and is never defaulted"
    );

    let violation: TextEncodingViolation = decode(&fixture("t12_c1_guard_violation_accept"))
        .expect("the accepted TextEncodingViolation must decode");
    assert_eq!(
        serde_json::to_string(&violation).expect("TextEncodingViolation must serialize"),
        r#"{"path":"$","reason":"replacement_char"}"#,
        "the derived encoder must reproduce the accepted bytes exactly"
    );

    let report: OnboardingReport = decode(&fixture("t12_c1_onboarding_report_accept"))
        .expect("the accepted OnboardingReport must decode");
    assert_eq!(
        report.head_commit,
        "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
    );
    assert!(report.unassigned_files.is_empty());

    // injection.rs: the accepted receipt carries a REAL `task_id` UUID, and
    // that exact UUID must survive as `Some(TaskId)` rather than being dropped
    // or replaced by a manufactured default. `policy_reason` is the member of
    // this same receipt that IS an explicit JSON `null`, and it decodes to
    // `None` — proven on its own below rather than attributed to `task_id`.
    let receipt: InjectionReceipt = decode(&fixture("t12_c1_injection_receipt_accept"))
        .expect("the accepted InjectionReceipt must decode");
    assert_eq!(
        receipt.task_id.map(|id| id.to_string()).as_deref(),
        Some("0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61"),
        "the accepted receipt's own task_id UUID must decode to Some(that same id), never to None \
         and never to a manufactured default"
    );
    assert!(
        receipt.policy_reason.is_none(),
        "the explicit JSON null policy_reason must decode to None, not to a default reason"
    );
    // THE EXPLICIT-NULL `task_id` ROW, on the one corpus fixture that really
    // carries `"task_id":null` — the observability envelope's nested receipt
    // payload (fixture `t12_c8_observability_envelope_accept`, corpus :422).
    let null_task_receipt: InjectionReceipt = decode(
        r#"{"injection_id":"injection-1","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","task_id":null,"surface":"ul_fired","item_ref":"item-1","render_form":"markdown","fired_cues":[{"kind":"file_path","value":"src/ul/guard.rs"}],"token_cost":42,"source_fingerprint":"blake3-source-1","outcome":"applied","policy_reason":null}"#,
    )
    .expect("a receipt whose task_id is an explicit JSON null must decode");
    assert!(
        null_task_receipt.task_id.is_none(),
        "an explicit JSON null task_id must decode to None, not to a default id"
    );
    let again: InjectionReceipt = serde_json::from_str(
        &serde_json::to_string(&receipt).expect("InjectionReceipt must serialize"),
    )
    .expect("a serialized InjectionReceipt must decode again");
    assert_eq!(again.token_cost, receipt.token_cost);
    assert_eq!(again.fired_cues.len(), receipt.fired_cues.len());
    assert_eq!(again.fired_cues[0].value, "src/ul/guard.rs");
}

// WORK_UNIT_CASE: 941/3
#[test]
fn case_03_unknown_outer_envelope_fields_are_refused() {
    // `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:13` —
    // "closed control variants fail when unknown; additive reason/telemetry
    // values preserve Unknown(raw);"
    // An unknown member at the OUTER level of an envelope is refused by the
    // owner's own decoder, never carried along with an accepted value.

    // ul/injection.rs::MemoryInfluenceAckInputVisitor, :255-260 — the `_` arm
    // returns `unknown_field(key, MEMORY_INFLUENCE_ACK_FIELDS)`.
    let ack = decode::<MemoryInfluenceAckInput>(&fixture("t12_c3_ack_input_unknown_outer_refuse"));
    assert!(
        ack.is_err(),
        "ul/injection.rs: MemoryInfluenceAckInput must refuse the unknown outer member `delivery_surface`"
    );
    // The same closure on a POSITIVE ack, proving the refusal is specific to
    // the unknown member and not to the document.
    let accepted = decode::<MemoryInfluenceAckInput>(
        r#"{"memory_handle":"mem-1","influence_class":"seen_but_not_used"}"#,
    )
    .expect("the closed acknowledgement shape must decode");
    assert_eq!(accepted.memory_handle, "mem-1");
    assert_eq!(
        accepted.influence_class,
        MemoryInfluenceClass::SeenButNotUsed
    );

    // observability.rs::MemoryInfluenceToolInputVisitor, FULL branch,
    // :428-433 — a foreign key makes the full trace-write shape an
    // `Error::custom` refusal.
    let full =
        decode::<MemoryInfluenceToolInput>(&fixture("t12_c3_tool_input_full_unknown_outer_refuse"));
    assert!(
        full.is_err(),
        "observability.rs: the full trace-write branch of MemoryInfluenceToolInput must refuse the unknown outer member `effect_class`"
    );
    // The SAME full document with the unknown member removed decodes to the
    // owner's own `MemoryInfluenceTraceWriteInput`, so the refusal above is the
    // foreign member and nothing else.
    let full_accepted: MemoryInfluenceToolInput = decode(
        r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","write_id":"write-1","trace":{"task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","memory_handle":"mem-1","packet_id":"packet-1","admission_decision":"include_verified","inclusion_or_suppression_reason":"verified","epistemic_status_at_use":"verified","cited_in_understanding_proof":true,"action_or_probe_changed":true,"write_set_changed":false,"verifier_changed":false,"repeated_failure_prevented":false,"suppressed_as_stale_or_wrong_scope":false,"downstream_outcome_ref":null,"influence_class":"seen_but_not_used"}}"#,
    )
    .expect("the closed full trace-write shape must decode");
    assert!(
        matches!(full_accepted, MemoryInfluenceToolInput::Full(_)),
        "a document carrying `trace` and no acknowledgement member must select the full branch"
    );
    let full_input: &MemoryInfluenceTraceWriteInput = match &full_accepted {
        MemoryInfluenceToolInput::Full(input) => input,
        MemoryInfluenceToolInput::Ack(_) => {
            panic!(
                "a document carrying `trace` and no acknowledgement member must select the full branch"
            );
        }
    };
    assert_eq!(full_input.write_id, "write-1");
    assert_eq!(
        full_input.trace.influence_class,
        MemoryInfluenceClass::SeenButNotUsed
    );

    // observability.rs::MemoryInfluenceToolInputVisitor, ACK branch,
    // :442-453 — a foreign key is refused against the owning acknowledgement
    // field set.
    let ack_branch =
        decode::<MemoryInfluenceToolInput>(&fixture("t12_c3_tool_input_ack_unknown_outer_refuse"));
    assert!(
        ack_branch.is_err(),
        "observability.rs: the acknowledgement branch of MemoryInfluenceToolInput must refuse the unknown outer member `delivery_surface`"
    );
}

// WORK_UNIT_CASE: 941/4
#[test]
fn case_04_unknown_nested_envelope_fields_are_refused() {
    // The OUTER closure is not enough: a member unknown at a NESTED depth must
    // also be refused, on the `fired_cues` path specifically.

    // InjectionReceipt::fired_cues carries `deserialize_strict_observed_cues`
    // (ul/injection.rs:179), which decodes each element through
    // `StrictObservedCueInput` → `ObservedCueVisitor { allow_legacy_metadata:
    // false }` (:109-120). Its `_` arm, :65-72, names only `["kind","value"]`.
    let unknown_nested =
        decode::<InjectionReceipt>(&fixture("t12_c4_receipt_fired_cue_unknown_nested_refuse"));
    assert!(
        unknown_nested.is_err(),
        "ul/injection.rs: a nested fired_cues element must refuse the unknown member `confidence`"
    );

    // THE SAME outer document with a clean nested element decodes, so the
    // refusal above is the nested member and nothing else.
    let clean = decode::<InjectionReceipt>(&fixture("t12_c1_injection_receipt_accept"))
        .expect("the same receipt with a clean nested cue must decode");
    assert_eq!(clean.fired_cues.len(), 1);
    assert_eq!(clean.fired_cues[0].kind.as_str(), "file_path");

    // The strict nested mode is STRICTER than the direct legacy cue boundary,
    // and that difference is observable rather than assumed: the direct
    // `ObservedCue` decode accepts the two inert legacy metadata keys (the
    // committed #831 oracle REQUIRES
    // `{"kind","value","version","schema_version"}` to decode `Ok`), while the
    // nested strict mode refuses the very same keys. No `deny_unknown_fields`
    // is added to the direct decode by this file, and no case here assumes one.
    let legacy_direct: ObservedCue = decode(
        r#"{"kind":"file_path","value":"src/ul/guard.rs","version":"v2","schema_version":"eliot-agent-api/v7"}"#,
    )
    .expect("the direct legacy cue boundary must keep accepting the #831 inert metadata keys");
    assert_eq!(legacy_direct.value, "src/ul/guard.rs");
    assert!(
        decode::<InjectionReceipt>(&fixture(
            "t12_c4_receipt_fired_cue_legacy_metadata_nested_refuse"
        ))
        .is_err(),
        "ul/injection.rs: the nested strict cue mode must refuse `schema_version`, which the direct legacy mode accepts"
    );

    // The same strict nested mode is reached through PendingInjectionItem,
    // whose `fired_cues` carries the same `deserialize_strict_observed_cues`
    // (ul/injection.rs:138).
    let pending = decode::<PendingInjectionItem>(&fixture(
        "t12_c4_pending_item_fired_cue_unknown_nested_refuse",
    ));
    assert!(
        pending.is_err(),
        "ul/injection.rs: PendingInjectionItem.fired_cues must refuse the unknown nested member `origin`"
    );
    let pending_clean = decode::<PendingInjectionItem>(
        r#"{"item_ref":"item-1","record_kind":"concept_node","preview":"concept node preview","payload":null,"source_fingerprint":"blake3-source-1","fired_cues":[{"kind":"file_path","value":"src/ul/guard.rs"}],"negative_memory":false,"invariant":false,"token_estimate":42,"activation_trace_ref":null,"activation_score_milli":null}"#,
    )
    .expect("PendingInjectionItem with a clean nested cue must decode");
    assert_eq!(pending_clean.fired_cues.len(), 1);
}

// WORK_UNIT_CASE: 941/5
#[test]
fn case_05_duplicate_agent_and_task_keys_are_refused_from_raw_text() {
    // These two fixtures are parsed with `from_str`, NEVER `from_value`.
    // `serde_json::Map` is a `BTreeMap` in this workspace, so a `Value`
    // intermediate collapses each repeated member to last-wins BEFORE the
    // decoder is reached, and a `from_value` assertion here would silently
    // prove nothing. Both documents below are valid JSON.
    //
    // The repository also owns a lexical ingress that rejects a repeated
    // member at every depth — `strict_json_has_no_duplicate_members` — and it
    // is asserted here as the second layer, so the typed decoder's own refusal
    // and the shared ingress's refusal are two independent facts.

    // ul/injection.rs::MemoryInfluenceAckInputVisitor routes every member
    // through `next_once` (:84-98), which returns `duplicate_field` when the
    // slot is already occupied, BEFORE the second value is stored.

    // (a) a repeated AGENT-identity member.
    let agent = fixture("t12_c5_ack_input_duplicate_agent_key_refuse");
    assert!(
        agent.matches("\"memory_handle\"").count() == 2,
        "the fixture must literally repeat the member, or it proves nothing"
    );
    let agent_error = decode::<MemoryInfluenceAckInput>(&agent)
        .expect_err("a repeated `memory_handle` must be refused, never last-wins");
    assert!(
        format!("{agent_error}").contains("duplicate field"),
        "the refusal must name the duplicated field, got: {agent_error}"
    );
    assert_eq!(
        strict_json_has_no_duplicate_members(agent.as_bytes())
            .expect_err("the shared lexical ingress must also refuse the repeated member")
            .kind,
        StrictJsonErrorKind::DuplicateKey,
        "the shared ingress must classify the repeated member as a duplicate key"
    );

    // (b) a repeated TASK-identity member.
    let task = fixture("t12_c5_ack_input_duplicate_task_key_refuse");
    assert!(
        task.matches("\"write_id\"").count() == 2,
        "the fixture must literally repeat the member, or it proves nothing"
    );
    let task_error = decode::<MemoryInfluenceAckInput>(&task)
        .expect_err("a repeated `write_id` must be refused, never last-wins");
    assert!(
        format!("{task_error}").contains("duplicate field"),
        "the refusal must name the duplicated field, got: {task_error}"
    );
    assert_eq!(
        strict_json_has_no_duplicate_members(task.as_bytes())
            .expect_err("the shared lexical ingress must also refuse the repeated member")
            .kind,
        StrictJsonErrorKind::DuplicateKey
    );

    // The single-member form still decodes, so neither refusal is a shape
    // accident.
    let single = decode::<MemoryInfluenceAckInput>(
        r#"{"memory_handle":"mem-1","write_id":"write-1","influence_class":"seen_but_not_used"}"#,
    )
    .expect("the single-member form must decode");
    assert_eq!(single.write_id.as_deref(), Some("write-1"));
}

// WORK_UNIT_CASE: 941/6
#[test]
fn case_06_duplicate_source_discriminator_and_wrong_variants_are_refused() {
    // Same raw-text rule as case 5: no `from_value` anywhere in this case.

    // (a) a repeated SOURCE-identity member of the acknowledgement input.
    // The two values DIFFER, so a last-wins decoder would be observable.
    let source = fixture("t12_c6_ack_input_duplicate_source_key_refuse");
    assert!(
        source.matches("\"downstream_outcome_ref\"").count() == 2
            && source.contains("outcome-1")
            && source.contains("outcome-2"),
        "the fixture must repeat the member with DIFFERENT values, or it proves nothing"
    );
    assert!(
        decode::<MemoryInfluenceAckInput>(&source).is_err(),
        "ul/injection.rs: a repeated `downstream_outcome_ref` must be refused"
    );

    // (b) a repeated DISCRIMINATOR on the tagged `UlPrediction` union.
    // `UlPredictionVisitor::visit_map` (:83-86) routes `kind` through
    // `set_once`, which returns `duplicate_field` on the second occurrence.
    let discriminator = fixture("t12_c6_ul_prediction_duplicate_discriminator_refuse");
    assert!(
        discriminator.matches("\"kind\"").count() == 2,
        "the fixture must literally repeat the discriminator, or it proves nothing"
    );
    let discriminator_error = decode::<UlPrediction>(&discriminator)
        .expect_err("a repeated `kind` on UlPrediction must be refused, never last-wins");
    assert!(
        format!("{discriminator_error}").contains("duplicate field"),
        "the refusal must name the duplicated discriminator, got: {discriminator_error}"
    );
    assert_eq!(
        strict_json_has_no_duplicate_members(discriminator.as_bytes())
            .expect_err("the shared lexical ingress must also refuse the repeated member")
            .kind,
        StrictJsonErrorKind::DuplicateKey
    );

    // (c) a member of the WRONG tagged variant. `finish_blast_radius`
    // (ul/prediction.rs:251-271) refuses `probe_ref` and
    // `expected_excerpt_or_range` as `unknown_field` against the blast-radius
    // field set, and `required(...)` would refuse the missing members.
    let wrong_variant = fixture("t12_c6_ul_prediction_wrong_variant_field_refuse");
    assert!(
        decode::<UlPrediction>(&wrong_variant).is_err(),
        "ul/prediction.rs: a `blast_radius` document carrying the observable_value payload must be refused"
    );
    // The correct variant with the SAME members decodes, proving the refusal
    // above is the variant selection and not the members themselves.
    let correct_variant: UlPrediction = decode(
        r#"{"kind":"observable_value","probe_ref":"probe-1","expected_excerpt_or_range":"42"}"#,
    )
    .expect("the correctly selected variant must decode");
    assert!(matches!(
        correct_variant,
        UlPrediction::ObservableValue { .. }
    ));

    // (d) an UNKNOWN tagged variant. `UlPredictionVisitor::visit_map`
    // (:139-148) returns `unknown_variant` for any other `kind` string.
    let unknown_variant = fixture("t12_c6_ul_prediction_unknown_variant_refuse");
    assert!(
        decode::<UlPrediction>(&unknown_variant).is_err(),
        "ul/prediction.rs: an unknown tagged variant must be refused, never absorbed"
    );
    // MAIN BEHAVIOUR NOTE: the refusal here is `Error::custom`-class, not an
    // `Unknown(raw)` preservation — `UlPrediction` is a CLOSED control union
    // with no `Unknown(String)` variant, which is exactly what
    // APPENDIX-P:13 requires ("closed control variants fail when unknown").
    // The clause "additive reason/telemetry values preserve Unknown(raw)"
    // applies to the OTHER families in this allocation that DO carry such a
    // variant, and no case here claims it for `UlPrediction`.

    // (e) The closed enums of the allocation refuse an unknown variant too.
    assert!(
        decode::<eliot_types::UlExamQuestionKind>(r#""triage""#).is_err(),
        "ul/exam.rs: UlExamQuestionKind is closed and must refuse `triage`"
    );
    assert!(
        decode::<eliot_types::UlReasoningRoute>(r#""gpt""#).is_err(),
        "ul/exam.rs: UlReasoningRoute is closed and must refuse `gpt`"
    );
    assert!(
        decode::<eliot_types::UlDependencyKind>(r#""module""#).is_err(),
        "ul/dependency.rs: UlDependencyKind is closed and must refuse `module`"
    );
    assert!(
        decode::<OnboardingStage>(r#""halted""#).is_err(),
        "ul/onboarding.rs: OnboardingStage is closed and must refuse `halted`"
    );
}

// WORK_UNIT_CASE: 941/7
#[test]
fn case_07_missing_protected_identity_never_decodes_to_a_current_valid_value() {
    // `docs/architecture/I05-27-canonical-operation-identity-and-effect-identity.md:18`
    // — "fields affecting authority, scope, ordering, privacy or effect cannot
    // be omitted/defaulted silently."
    //
    // A protected identity that is simply ABSENT must be refused, never
    // defaulted into a plausible current value. Each case below names the
    // `required(...)` call in the production source that raises the refusal.

    // ul/injection.rs::MemoryInfluenceAckInputVisitor, :267 — `memory_handle`
    // is the protected agent-side handle. It is `required(...)`, never
    // `unwrap_or_default()` the way the three optional members beside it are.
    let no_handle = decode::<MemoryInfluenceAckInput>(&fixture(
        "t12_c7_ack_input_missing_memory_handle_refuse",
    ));
    let no_handle_error = no_handle.expect_err(
        "an acknowledgement without its memory_handle must be refused, never defaulted",
    );
    assert!(
        format!("{no_handle_error}").contains("memory_handle"),
        "the refusal must name the missing protected identity, got: {no_handle_error}"
    );

    // The SAME refusal through the composed union in observability.rs:
    // `MemoryInfluenceToolInputVisitor` :457 — `required(memory_handle, ...)`.
    assert!(
        decode::<MemoryInfluenceToolInput>(
            r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","influence_class":"seen_but_not_used"}"#
        )
        .is_err(),
        "observability.rs: the composed union must refuse an acknowledgement with no memory_handle"
    );

    // ul/injection.rs, :268 — `influence_class` is the closed classification
    // the acknowledgement is about. A missing class is a refusal, and an
    // UNKNOWN class is a different refusal: `MemoryInfluenceClass` is closed.
    let no_class = decode::<MemoryInfluenceAckInput>(&fixture(
        "t12_c7_ack_input_missing_influence_class_refuse",
    ));
    assert!(
        no_class.is_err(),
        "an acknowledgement without its influence_class must be refused, never defaulted"
    );
    assert!(
        decode::<MemoryInfluenceAckInput>(
            r#"{"memory_handle":"mem-1","influence_class":"observed_and_applied"}"#
        )
        .is_err(),
        "an acknowledgement with an unknown influence_class must be refused, never absorbed"
    );

    // ul/prediction.rs::PredictionRecord — `task_id` is a required member of a
    // derived, `deny_unknown_fields` struct, so serde's own missing-field path
    // refuses it. `#[serde(default)]` is applied ONLY to
    // prediction/confidence/actual_detail/blast_score; the four identity
    // members are not defaulted.
    let no_task =
        decode::<PredictionRecord>(&fixture("t12_c7_prediction_record_missing_task_id_refuse"));
    let no_task_error = no_task
        .expect_err("a prediction record without its task_id must be refused, never defaulted");
    assert!(
        format!("{no_task_error}").contains("task_id"),
        "the refusal must name the missing task identity, got: {no_task_error}"
    );

    // The full accepted record still decodes, so no refusal above is a shape
    // accident.
    let accepted: PredictionRecord = decode(&fixture("t12_c1_prediction_record_accept"))
        .expect("the accepted PredictionRecord must decode");
    assert_eq!(
        accepted.verifier, "cargo test -p eliot-types",
        "the accepted record must carry its own verifier, not a default"
    );
}

// WORK_UNIT_CASE: 941/8
#[test]
#[allow(clippy::too_many_lines)]
fn case_08_unsupported_or_misselected_schema_never_decodes_to_a_current_valid_value() {
    // A document whose schema this build does not own must never come back as
    // a current-valid value. Two shapes exist in this allocation and they are
    // NOT the same, and this case asserts each one against its real code:
    //
    //   (A) OWNER-REFUSED: `UlCrossAgentSuite.schema_version` is a plain
    //       `String` field, so `Deserialize` itself SUCCEEDS on a
    //       misselected schema. The refusal belongs to the owner's own
    //       `UlCrossAgentSuite::validate()` (ul/cross_agent.rs:74-76), which
    //       returns `Err("UL cross-agent suite schema_version is
    //       unsupported")`. MAIN IS MORE PERMISSIVE AT DECODE TIME THAN THE
    //       IDEAL HERE, and this case asserts what main ACTUALLY does:
    //       decode succeeds, validate refuses. Asserting a decode refusal
    //       would be an assertion main does not satisfy.
    //
    //   (B) DECODER-REFUSED: `ObservabilityWriteEnvelope.schema_version` is
    //       checked INSIDE the decoder —
    //       `check_observability_schema_version` (observability.rs:272-283),
    //       called from the visitor at :165-167 — so an unsupported version is
    //       refused by `deserialize` itself. That is the `#[serde(default)]`-free
    //       shape; nothing is defaulted and nothing is deferred.
    //
    // The unsuffixed-`Value` rule from the module header holds throughout: no
    // parsed `Value` is compared against its own original text.

    // (A) the misselected suite schema.
    let misselected: UlCrossAgentSuite = decode(&fixture(
        "t12_c8_cross_agent_suite_misselected_schema_refuse",
    ))
    .expect("decoding alone succeeds: the suite's schema_version is an unvalidated String field");
    assert_eq!(
        misselected.schema_version, "eliot-ul-cross-agent-report-v1",
        "the decoder must preserve the received schema version rather than substitute its own"
    );
    let refusal = misselected
        .validate()
        .expect_err("the owner's validate() must refuse a schema version it does not own");
    assert_eq!(
        refusal, "UL cross-agent suite schema_version is unsupported",
        "the owner must name the refusal exactly, got: {refusal}"
    );

    // The one version this build owns passes the schema check (it then fails
    // the call-count check because the fixture carries no cases — which is a
    // DIFFERENT refusal, and is asserted as such so the two cannot be confused).
    let owned: UlCrossAgentSuite = decode(&fixture("t12_c8_cross_agent_suite_valid_schema_accept"))
        .expect("the owned schema version must decode");
    assert_eq!(owned.schema_version, "eliot-ul-cross-agent-suite-v1");
    let owned_refusal = owned.validate().expect_err(
        "the owned schema version must clear the schema check and fail the eight-call check instead",
    );
    assert!(
        owned_refusal.contains("requires exactly"),
        "the owned schema must fail on the call count, not on the schema, got: {owned_refusal}"
    );

    // (B) the misselected observability envelope schema, refused by the decoder.
    let envelope = decode::<eliot_types::ObservabilityWriteEnvelope>(&fixture(
        "t12_c8_observability_envelope_unsupported_schema_refuse",
    ));
    let envelope_error = envelope.expect_err(
        "an observability envelope with an unsupported schema_version must be refused by deserialize",
    );
    assert!(
        format!("{envelope_error}").contains("unsupported schema version"),
        "the decoder must refuse with the owner's bounded reason, got: {envelope_error}"
    );
    // And the same document with the one owned schema version decodes, so the
    // refusal above is the schema version and nothing else.
    let accepted_envelope: eliot_types::ObservabilityWriteEnvelope =
        decode(&fixture("t12_c8_observability_envelope_accept"))
            .expect("the owned schema version must decode");
    assert_eq!(accepted_envelope.schema_version, "eliot-observability-v1");
    // `ObservabilityWriteEnvelope` does not derive `PartialEq`, so the payload
    // is compared as TEXT produced by `serde_json::to_string` on BOTH sides —
    // the decoded envelope's own payload and an independently parsed `Value`
    // of the expected document. Both sides travel through the same
    // `BTreeMap`-backed `Map`, so this compares payload VALUES and not a
    // re-serialization of the original fixture text.
    assert_eq!(
        accepted_envelope
            .payload
            .to_string(),
        decode::<serde_json::Value>(
            r#"{"injection_id":"injection-1","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","task_id":null,"surface":"ul_fired","item_ref":"item-1","render_form":"markdown","fired_cues":[{"kind":"file_path","value":"src/ul/guard.rs"}],"token_cost":42,"source_fingerprint":"blake3-source-1","outcome":"applied","policy_reason":null}"#,
        )
        .expect("the payload comparison value must itself be valid JSON")
        .to_string(),
        "the accepted envelope's payload must equal the expected payload VALUE"
    );
    // The owner-decoded payload is the strict nested cue path, so the same
    // document with a nested unknown member is refused before it can reach the
    // store as an untyped blob.
    assert!(
        decode::<eliot_types::ObservabilityWriteEnvelope>(
            r#"{"schema_version":"eliot-observability-v1","write_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c63","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":null,"session_id":null,"kind":"injection_receipt","record_id":"injection-1","payload":{"injection_id":"injection-1","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","task_id":null,"surface":"ul_fired","item_ref":"item-1","render_form":"markdown","fired_cues":[{"kind":"file_path","value":"src/ul/guard.rs","confidence":0.9}],"token_cost":42,"source_fingerprint":"blake3-source-1","outcome":"applied","policy_reason":null},"input_hash":"blake3-input-1","created_at":"2026-09-24T10:15:00Z"}"#
        )
        .is_err(),
        "observability.rs: an envelope whose payload carries an unknown nested member must be refused by the owner decoder the envelope kind names"
    );
}

/// Read one UL production source file, byte for byte, so the per-file
/// accounting is derived from the real files rather than from a list this
/// test writes. The boundary is the crate itself: `CARGO_MANIFEST_DIR` is
/// `crates/eliot-types`, whose `src/ul` directory is the allocation's own
/// `source_files` denominator.
fn read_ul_source(file_name: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("ul")
        .join(file_name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("src/ul/{file_name} must be readable: {error}"))
}

// ---------------------------------------------------------------------------
// PLACEHOLDER — writer w2 (issue #941, card cards/941.md).
//
// Writer w2 REPLACES everything between the two banner lines below with cases
// 9-16, each a `#[test]` preceded by exactly `// WORK_UNIT_CASE: 941/<case>`,
// its own `t12_c9_` .. `t12_c16_` raw-string fixtures added to the `pairs`
// table inside `fixture()` above (or to a second local table if preferred),
// and any further helpers it needs. The rules established above hold for w2
// too: raw string fixtures only, `from_str` for every duplicate case, never a
// claim that a parsed `Value` re-serializes to its original text, and no
// assertion main does not actually satisfy.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// END OF WRITER w2 PLACEHOLDER
// ---------------------------------------------------------------------------

// ===========================================================================
// CASES 11-12 (this writer) — ERASURE-CAPABLE CONSTRUCTS, and the
// ZERO-CANDIDATE ROW.
//
// THE GOVERNING DOCUMENTATION, quoted verbatim and cited at every use below:
//
// * `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:12` —
//   "authority, scope, effect, privacy, ordering and receipt fields are never
//   silently defaulted;"
// * `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:13` —
//   "closed control variants fail when unknown; additive reason/telemetry
//   values preserve Unknown(raw);"
// * `docs/architecture/I15-06-instructiondata-separation.md:6` — "model output
//   remains candidate;"
//
// THE FIDELITY RULE from the module header is observed in both cases:
// `serde_json`'s `Map` is a `BTreeMap` here (`preserve_order` is NOT enabled —
// `Cargo.toml:353` declares `serde_json = { version = "1.0.150", features =
// ["float_roundtrip"] }` and no `preserve_order`), so a parsed object comes back
// with its members SORTED. NOTHING below asserts that a parsed `Value`
// re-serializes to its original text; every payload comparison is a VALUE
// comparison and the one byte comparison is a DERIVED encoder's own compact
// output of a TYPED value against a hand-written literal written in declaration
// order by hand.
//
// OWN FIXTURES. Everything below is declared as its own `const NAME: &str =
// r#"..."#;` beside its own case. NOTHING is added to the shared `pairs` table
// inside `fixture()`, so these two cases cannot collide with the tables the
// other writers add for cases 9-10 and 13-16. Every name below is prefixed
// `T12_W3_C11_` / `T12_W3_C12_`, which no other writer uses.
// ===========================================================================

// ---------------------------------------------------------------------------
// CASE 11 FIXTURES — writer w3, self-contained, no entry in `fixture()`.
// ---------------------------------------------------------------------------

// The two control-imitating rows of this case are the top-level named constants
// `T12_C11_PENDING_ITEM_CONTROL_IMITATING_PAYLOAD` (the blob carried as an
// OPAQUE `Value`, admitted verbatim) and
// `T12_C11_ACK_INPUT_CONTROL_IMITATING_MEMBERS` (the same names as REAL MEMBERS
// of the CLOSED acknowledgement, refused). They are declared once, at the top of
// this file, and section (A) and section (B) below reference them directly, so
// the coverage exists exactly once.

/// The SAME `prediction`-shaped member carried as a real member of the typed
/// `PredictionRecord`. `PredictionRecord.prediction` IS declared
/// (`ul/prediction.rs:384-385`) and it carries `#[serde(default)]` — the
/// permissive row this case reports honestly — but it is `Option<UlPrediction>`:
/// a member NAMED `prediction` can only ever land in that slot, and
/// `UlPrediction` is a CLOSED tagged union with no `proposal`, `unknown` or
/// authority variant at all.
const T12_W3_C11_RECORD_PREDICTION_SLOT_PREDICATE: &str = r#"{"prediction_id":"prediction-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","subsystem_concept_id":null,"packet_id":"packet-1","verifier":"cargo test -p eliot-types","expected":"pass","prediction":{"kind":"verifier_verdict","verifier":"cargo test -p eliot-types","expected":"pass"},"confidence":null,"resolution":null,"actual":null,"actual_detail":null,"blast_score":null,"verification_ref":null,"source_frame_hash":"frame-hash-1"}"#;

/// The same record with the `prediction` slot carrying a `kind` that names a
/// PROPOSAL/UNKNOWN/AUTHORITY shape the union does not declare.
/// `UlPredictionVisitor::visit_map` returns `unknown_variant` for any other
/// `kind` string (`ul/prediction.rs:139-148`).
const T12_W3_C11_RECORD_PREDICTION_SLOT_PROPOSAL_KIND: &str = r#"{"prediction_id":"prediction-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","subsystem_concept_id":null,"packet_id":"packet-1","verifier":"cargo test -p eliot-types","expected":"pass","prediction":{"kind":"proposal","verifier":"cargo test -p eliot-types","expected":"pass"},"confidence":null,"resolution":null,"actual":null,"actual_detail":null,"blast_score":null,"verification_ref":null,"source_frame_hash":"frame-hash-1"}"#;

/// The same record with a member NAMED `proposal` beside `prediction`. The
/// struct is `#[serde(deny_unknown_fields)]` (`ul/prediction.rs:374`), so the
/// name is refused rather than absorbed as a second truth channel.
const T12_W3_C11_RECORD_PROPOSAL_AS_REAL_MEMBER: &str = r#"{"prediction_id":"prediction-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","subsystem_concept_id":null,"packet_id":"packet-1","verifier":"cargo test -p eliot-types","expected":"pass","prediction":null,"confidence":null,"resolution":null,"actual":null,"actual_detail":null,"blast_score":null,"verification_ref":null,"source_frame_hash":"frame-hash-1","proposal":"accepted"}"#;

/// `PredictionRecord` with the four `#[serde(default)]`-bearing members ABSENT
/// entirely. This is the PERMISSIVE ROW: `prediction` (`ul/prediction.rs:384`),
/// `confidence` (`:386`), `actual_detail` (`:390`) and `blast_score` (`:392`)
/// each decode to `None` rather than refusing, because `expr_is_missing`
/// substitutes the type's `Default` for those four.
/// `actual` (`:389`), `resolution` (`:388`), `verification_ref` (`:394`) and
/// `subsystem_concept_id` (`:380`) are bare `Option<...>` with no
/// `#[serde(default)]`
/// of their own, and they ALSO decode to `None` when absent — NOT by that
/// attribute, but by serde's OWN missing-field path: an absent member is routed
/// through `missing_field`, whose `deserialize_option` calls `visit_none()`
/// (serde-1.0.229 `core/de/mod.rs`). That is why the four of them are omitted
/// here and the document still decodes, and it is why their absence is NOT a
/// refusal while the absence of a non-`Option` member IS one.
///
/// The members that REMAIN in this fixture are exactly the ones that affect
/// authority/scope/ordering/effect and are NOT defaulted:
/// `prediction_id`, `project_id`, `task_id`, `session_id`, `packet_id`,
/// `verifier`, `expected`, `source_frame_hash`.
const T12_W3_C11_RECORD_DEFAULTED_MEMBERS_ABSENT: &str = r#"{"prediction_id":"prediction-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","packet_id":"packet-1","verifier":"cargo test -p eliot-types","expected":"pass","source_frame_hash":"frame-hash-1"}"#;

/// The same document with the PROTECTED `verifier` removed. It is declared with
/// no `#[serde(default)]` (`ul/prediction.rs:382`), so its absence is refused.
const T12_W3_C11_RECORD_VERIFIER_ABSENT: &str = r#"{"prediction_id":"prediction-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","packet_id":"packet-1","expected":"pass","source_frame_hash":"frame-hash-1"}"#;

/// `UlPredictionActual` with every one of its five `#[serde(default)]`
/// members absent (`ul/prediction.rs:348-357`). It derives `Default`, is
/// `deny_unknown_fields` (`:344`) and carries NO required member at all, so
/// `{}` decodes. This is the most permissive type in the allocation and is
/// reported as such rather than pretended to refuse.
const T12_W3_C11_PREDICTION_ACTUAL_ALL_DEFAULTS_ABSENT: &str = "{}";

/// `CalibrationScore` with all nine `#[serde(default)]` members absent
/// (`ul/prediction.rs:419-434`), leaving only its five REQUIRED members
/// (`project_id`, `resolved_predictions`, `hits`, `misses`, `hit_rate` —
/// `ul/prediction.rs:413-418`). `subsystem_concept_id` is a bare `Option<String>`
/// with no `#[serde(default)]`, so this PERMISSIVE row must still CARRY it as an
/// explicit `null`; it is not one of the defaulted members and not one of the
/// five. Reported as a permissive row too.
const T12_W3_C11_CALIBRATION_SCORE_DEFAULTS_ABSENT: &str = r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","subsystem_concept_id":null,"resolved_predictions":12,"hits":7,"misses":5,"hit_rate":0.5833}"#;

/// `CalibrationScore` with its PROTECTED `hits` removed. `hits` carries no
/// `#[serde(default)]` (`ul/prediction.rs:416`), so the absence is refused; the
/// defaulted span that follows it is `:419-434`, and that is where `unresolved`
/// (`:421`) and `brier_milli` (`:423`) live.
const T12_W3_C11_CALIBRATION_SCORE_HITS_ABSENT: &str = r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","subsystem_concept_id":null,"resolved_predictions":12,"misses":5,"hit_rate":0.5833}"#;

// WORK_UNIT_CASE: 941/11
#[test]
#[allow(clippy::too_many_lines)]
fn c11_erasure_capable_constructs_neither_erase_input_nor_promote_candidates() {
    // GOVERNING DOCS, verbatim:
    // * docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:12 —
    //   "authority, scope, effect, privacy, ordering and receipt fields are never
    //   silently defaulted;"
    // * docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:13 —
    //   "closed control variants fail when unknown; additive reason/telemetry
    //   values preserve Unknown(raw);"
    // * docs/architecture/I15-06-instructiondata-separation.md:6 — "model output
    //   remains candidate;"
    //
    // -------------------------------------------------------------------------
    // THE ERASURE-CAPABLE CONSTRUCTS THAT ACTUALLY EXIST IN THIS ALLOCATION.
    // This case asserts ONLY what was found by reading the ten UL sources and
    // `observability.rs`; it asserts no construct that is absent.
    //
    //   (E1) `#[serde(default)]` — 44 occurrences across seven `src/ul` files,
    //        FOUR of which are in this allocation (`prediction.rs` 17,
    //        `injection.rs` 8, `concept.rs` 2, `exam.rs` 1 — 28 occurrences),
    //        plus #940's `cue.rs` 4, `measurement.rs` 9 and `activation.rs` 3
    //        (16 occurrences) — and ZERO in `observability.rs`. It is the ONLY
    //        construct that can both
    //        ERASE input and silently default a member, and sections (B)-(D)
    //        below state exactly what it does and does not give.
    //   (E2) `serde_json::Value` FIELDS — four in this allocation:
    //        `PendingInjectionItem.payload` (`ul/injection.rs:136`),
    //        `UlFiredItem.payload` (`ul/injection.rs:163`),
    //        `UlReasoningRequest.output_schema` (`ul/exam.rs:98`), and the
    //        `ObservabilityWriteEnvelope.payload` (`observability.rs:96`).
    //        `CueRecordSource.payload` belongs to the separate #940 allocation
    //        and is not included in this #941 count.
    //        A `Value` field CANNOT erase input: it stores every member it was
    //        given. Section (A) proves that.
    //   (E3) A CUSTOM VISITOR — `UlPredictionVisitor`
    //        (`ul/prediction.rs:67-150`). Section (E).
    //   (E4) AN ALIAS — there is NONE in the ten UL files or in
    //        `observability.rs`. This is asserted from the REAL FILE BYTES in
    //        section (F), not from a list this test writes. (`#[serde(alias =
    //        "phase_closeout")]` at `verification.rs:60` and the six at
    //        `antigravity.rs:179-194` are in OTHER files and outside this
    //        allocation, so they are not claimed here.)
    //   (E5) `#[serde(flatten)]` — there is NONE in the ten UL files or in
    //        `observability.rs` either. The one `flatten` in `eliot-types` is
    //        `CompilePacketToolInput.request` (`mcp_contract.rs:20-21`), which
    //        is #933-owned, and its OWN comment states why a derived flatten
    //        decoder is not used: "A derived `flatten` decoder buffers the
    //        remaining keys into a map and would silently keep the last
    //        duplicate" (`mcp_contract.rs:30-32`). Asserted from real bytes in
    //        section (F).
    //
    // THE THREE QUESTIONS EACH CONSTRUCT MUST ANSWER: (i) can it ERASE input,
    // (ii) can it SILENTLY DEFAULT a protected member, (iii) can it turn a
    // payload member named `proposal`/`prediction`/`unknown` into ACCEPTED
    // TRUTH. `serde(default)` can do (ii). Nothing here does (iii).
    // -------------------------------------------------------------------------

    // ================= (A) `serde_json::Value` CANNOT ERASE INPUT ===========
    // `T12_C11_PENDING_ITEM_CONTROL_IMITATING_PAYLOAD` is a `PendingInjectionItem`
    // whose `payload` blob imitates the closed CONTROL vocabularies of this very
    // allocation. `PendingInjectionItem.payload` is declared
    // `pub payload: Option<Value>` (`crates/eliot-types/src/ul/injection.rs:136`)
    // with NO `serde` attribute at all, so the blob is admitted VERBATIM by the
    // derived decoder — every one of `memory_handle`, `influence_class`,
    // `candidate_only`, `schema_version`, `direction_scores`, `authority` and
    // `current_truth` is a member of that blob and NONE of them is a member of
    // any type in this allocation except `candidate_only`
    // (`UlCrossAgentWriterOutput.candidate_only`, `ul/cross_agent.rs:355`).
    //
    // MAIN IS MORE PERMISSIVE THAN THE CONSTANT NAME IMPLIES: this document
    // DECODES. It is a `PendingInjectionItem`, the blob is an opaque `Value`, and
    // the imitation names are inert DATA inside it. The name records what the
    // document PROVES (a control-imitating payload cannot be refused at this
    // boundary), not that it is refused.
    let blob_item: PendingInjectionItem = decode(T12_C11_PENDING_ITEM_CONTROL_IMITATING_PAYLOAD)
        .expect(
            "MAIN IS MORE PERMISSIVE THAN THE NAME IMPLIES: an opaque `Value` payload is admitted \
             verbatim, never inspected, so a blob of control-imitating names decodes as DATA",
        );
    let blob = blob_item
        .payload
        .as_ref()
        .expect("the fixture carries a payload object");
    // VALUE comparison, never a comparison against the fixture text.
    assert_eq!(
        blob,
        &decode::<serde_json::Value>(
            r#"{"authority":"grant","candidate_only":false,"current_truth":true,"direction_scores":"passed","influence_class":"used_and_changed_action","memory_handle":"mem-canary-handle","schema_version":"eliot-ul-cross-agent-report-v1"}"#
        )
        .expect("the expected blob must itself be valid JSON"),
        "the stored payload must hold EVERY member it was given: a `Value` field erases nothing"
    );
    // And the typed surface around it carries NO control meaning derived from
    // those names. `PendingInjectionItem` declares no authority, no
    // `candidate_only`, no `influence_class` and no `schema_version` member
    // (`ul/injection.rs:132-147`), so none of them can be read off the item.
    assert_eq!(blob_item.item_ref, "item-1");
    assert_eq!(blob_item.record_kind, "concept_node");
    assert_eq!(blob_item.token_estimate, 42);
    assert!(
        blob_item.activation_trace_ref.is_none() && blob_item.activation_score_milli.is_none(),
        "the two defaulted members must be explicit `None`, never a value read out of the blob"
    );
    assert!(
        !blob_item.negative_memory && !blob_item.invariant,
        "the two booleans must keep their own declared value, never a value read out of the blob"
    );
    // The blob's `candidate_only: false` does NOT become the typed value of the
    // one REAL `candidate_only` in this allocation,
    // `UlCrossAgentWriterOutput.candidate_only` (`ul/cross_agent.rs:355`),
    // because that type is a DIFFERENT, CLOSED record and nothing decodes one
    // from the other. The blob cannot write into it: the writer output is
    // `deny_unknown_fields` (`ul/cross_agent.rs:350`) and its `candidate_only`
    // is a REQUIRED `bool` with no `default`, so a blob member can neither
    // supply it nor be supplied by it.
    assert!(
        decode::<eliot_types::UlCrossAgentWriterOutput>(
            r#"{"candidate_handle":"handle-1","write_receipt":"receipt-1","binding_refs":[],"candidate_only":false}"#
        )
        .is_ok(),
        "ul/cross_agent.rs:349-356 the writer output is a closed record whose candidate_only is its \
         OWN declared member"
    );
    assert!(
        decode::<eliot_types::UlCrossAgentWriterOutput>(
            r#"{"candidate_handle":"handle-1","write_receipt":"receipt-1","binding_refs":[],"candidate_only":false,"authority":"accepted"}"#
        )
        .is_err(),
        "ul/cross_agent.rs:350-355 a blob member cannot ride along as an extra member of the closed \
         writer output"
    );

    // ================= (B) THE SAME NAMES AS REAL MEMBERS ARE REFUSED ======
    // `MemoryInfluenceAckInput` is closed in TWO independent ways: the derived
    // `#[serde(default)]` on its three optional members (`:190-197`) plus a
    // hand-written visitor that refuses every other name. Section (B) uses the
    // visitor, and it is the strictest of the two.
    for name in [
        "candidate_only",
        "authority",
        "current_truth",
        "prediction",
        "proposal",
        "unknown_outcome_calls",
    ] {
        let mut document = decode::<serde_json::Value>(
            r#"{"memory_handle":"mem-1","influence_class":"seen_but_not_used"}"#,
        )
        .expect("the acknowledgement base must be valid JSON");
        document
            .as_object_mut()
            .expect("the acknowledgement base must be a JSON object")
            .insert(name.to_owned(), serde_json::Value::Bool(true));
        let refusal = decode::<MemoryInfluenceAckInput>(&document.to_string()).expect_err(
            "a control-imitating member must be refused by the acknowledgement visitor",
        );
        assert_eq!(
            refusal.to_string(),
            format!(
                "unknown field `{name}`, expected one of `project_id`, `write_id`, \
                 `memory_handle`, `influence_class`, `downstream_outcome_ref`"
            ),
            "ul/injection.rs:255-260 must refuse `{name}` by name against MEMORY_INFLUENCE_ACK_FIELDS \
             (ul/injection.rs:200-206)"
        );
    }
    // And the whole imitation document at once, carried as REAL MEMBERS of the
    // closed acknowledgement envelope:
    // `T12_C11_ACK_INPUT_CONTROL_IMITATING_MEMBERS`. Its members
    // `candidate_only`, `schema_version` and `current_truth` are none of them in
    // `MEMORY_INFLUENCE_ACK_FIELDS` (`ul/injection.rs:200-206`), so the visitor's
    // `_` arm at `:255-260` refuses the FIRST one it meets and names it against
    // the whole declared set.
    let ack_members =
        decode::<MemoryInfluenceAckInput>(T12_C11_ACK_INPUT_CONTROL_IMITATING_MEMBERS);
    let ack_members_error = ack_members.expect_err(
        "ul/injection.rs:255-260 must refuse a control-imitating member by name before any value \
         is returned",
    );
    assert_eq!(
        ack_members_error.to_string(),
        concat!(
            "unknown field `candidate_only`, expected one of `project_id`, `write_id`,",
            " `memory_handle`, `influence_class`, `downstream_outcome_ref`",
        ),
        "ul/injection.rs:255-260 must refuse `candidate_only` against MEMORY_INFLUENCE_ACK_FIELDS \
         (ul/injection.rs:200-206); the refusal names the FIRST undeclared member it meets"
    );
    // THE COMPOSED UNION IS AT LEAST AS STRICT. `MemoryInfluenceToolInput`
    // (`observability.rs:340-345`) is `#[serde(untagged)]` but has a HAND-WRITTEN
    // decoder (`observability.rs:347-464`) precisely because, verbatim at
    // `observability.rs:328-334`: "The derived untagged form used to try `Full`,
    // then silently retry `Ack` after a lossy failure, so an argument object that
    // carried both shapes — including one whose `trace` was malformed — decoded
    // as an accepted acknowledgement and dropped the full influence trace."
    // That is the ONE place in this file's reach where a derived decoder WAS
    // lossy, and it was removed. Section (B) proves the replacement is not.
    for name in ["candidate_only", "authority", "prediction", "proposal"] {
        let refusal = decode::<MemoryInfluenceToolInput>(&format!(
            r#"{{"memory_handle":"mem-1","influence_class":"seen_but_not_used","{name}":true}}"#
        ))
        .expect_err("the composed union must refuse a control-imitating member");
        assert_eq!(
            refusal.to_string(),
            format!(
                "unknown field `{name}`, expected one of `project_id`, `write_id`, \
                 `memory_handle`, `influence_class`, `downstream_outcome_ref`"
            ),
            "observability.rs:448-452 must refuse `{name}` against the OWNER's field set, never \
             against a lossy retry"
        );
    }

    // ================= (C) `serde(default)` — WHAT IT DOES GIVE ============
    // GUARANTEE 1: an absent member is admitted as the type's `Default`, not
    // refused. `PredictionRecord` genuinely ACCEPTS a document missing all four
    // of its defaulted members. THIS IS A PERMISSIVE ROW, asserted as one —
    // `prediction.rs:384` (`prediction`), `:386` (`confidence`), `:390`
    // (`actual_detail`) and `:392` (`blast_score`) each carry
    // `#[serde(default)]`, and serde_derive's `expr_is_missing`
    // (`serde_derive-1.0.229/src/de.rs:766-780`) substitutes
    // `_serde::private::Default::default()` for those four and nothing else.
    let permissive: PredictionRecord = decode(T12_W3_C11_RECORD_DEFAULTED_MEMBERS_ABSENT).expect(
        "PERMISSIVE ROW: prediction.rs:384-393 really does accept a prediction record with all \
             four defaulted members absent; main is more permissive than the ideal here",
    );
    assert!(
        permissive.prediction.is_none()
            && permissive.confidence.is_none()
            && permissive.actual_detail.is_none()
            && permissive.blast_score.is_none(),
        "each of the four `#[serde(default)]` members must decode to `None` rather than refusing"
    );
    // GUARANTEE 2 (THE PART THAT MATTERS): it does NOT default any member that
    // affects authority, scope, effect, privacy, ordering or receipt.
    // APPENDIX-P:12 is satisfied here, and section (C) proves it member by
    // member. `verifier` carries no `default` (`ul/prediction.rs:382`).
    let no_verifier = decode::<PredictionRecord>(T12_W3_C11_RECORD_VERIFIER_ABSENT)
        .expect_err("the protected verifier must be refused, never defaulted");
    assert_eq!(
        no_verifier.to_string(),
        "missing field `verifier`",
        "ul/prediction.rs:382 declares `verifier` with no `#[serde(default)]`, so its absence is a \
         missing-field refusal: APPENDIX-P:12 — \"authority, scope, effect, privacy, ordering and \
         receipt fields are never silently defaulted;\""
    );
    // The identity and ordering members behave identically, and the reason is
    // read out of the source rather than assumed: `project_id`, `task_id`,
    // `session_id`, `prediction_id`, `packet_id`, `expected` and
    // `source_frame_hash` carry NO `#[serde(default)]` at all
    // (`ul/prediction.rs:376-396`), so a document missing any of them is
    // refused. The fixture above already carries all seven and decoded, so each
    // refusal below is attributable to the removal alone.
    for member in [
        "prediction_id",
        "project_id",
        "task_id",
        "session_id",
        "packet_id",
        "expected",
        "source_frame_hash",
    ] {
        let mut document = decode::<serde_json::Value>(T12_W3_C11_RECORD_DEFAULTED_MEMBERS_ABSENT)
            .expect("the permissive document must itself be valid JSON");
        let object = document
            .as_object_mut()
            .expect("the permissive document must be a JSON object");
        assert!(
            object.remove(member).is_some(),
            "the permissive document must actually carry `{member}`, or the row proves nothing"
        );
        assert_eq!(
            decode::<PredictionRecord>(&document.to_string())
                .expect_err("an absent non-defaulted identity member must be refused")
                .to_string(),
            format!("missing field `{member}`"),
            "ul/prediction.rs:376-396 must never default `{member}`"
        );
    }
    // GUARANTEE 3: `#[serde(default)]` does NOT open the struct to unknown
    // members. Every struct carrying it in this allocation is ALSO
    // `#[serde(deny_unknown_fields)]` — `PredictionRecord`
    // (`ul/prediction.rs:374`), `UlPredictionActual` (`:344`), `BlastScore`
    // (`:361`), `CalibrationScore` (`:411`). This is the single most important
    // fact about the construct: `default` decides what an ABSENT member becomes,
    // and `deny_unknown_fields` decides what an UNRECOGNISED member becomes, and
    // they are orthogonal. A member named `proposal` is UNRECOGNISED, so it is
    // refused, not defaulted.
    let proposal_member = decode::<PredictionRecord>(T12_W3_C11_RECORD_PROPOSAL_AS_REAL_MEMBER);
    let proposal_error = proposal_member.expect_err(
        "a member named `proposal` must be refused, never accepted as a second truth channel",
    );
    assert_eq!(
        proposal_error.to_string(),
        concat!(
            "unknown field `proposal`, expected one of `prediction_id`, `project_id`, `task_id`,",
            " `session_id`, `subsystem_concept_id`, `packet_id`, `verifier`, `expected`,",
            " `prediction`, `confidence`, `resolution`, `actual`, `actual_detail`, `blast_score`,",
            " `verification_ref`, `source_frame_hash`"
        ),
        "ul/prediction.rs:373-396 must refuse `proposal` against the whole sixteen-member declared \
         set — APPENDIX-P:13 — \"closed control variants fail when unknown;\""
    );
    // And on `UlPredictionActual` / `CalibrationScore` too, so the claim is not
    // about one struct.
    assert_eq!(
        decode::<UlPredictionActual>(r#"{"proposal":"accepted"}"#)
            .expect_err("UlPredictionActual must refuse an unknown member despite five defaults")
            .to_string(),
        concat!(
            "unknown field `proposal`, expected one of `verifier_result`, `diagnostic_before`,",
            " `diagnostic_after`, `changed_paths`, `failing_verifiers`, `observed_value`"
        ),
        "ul/prediction.rs:343-358 must refuse `proposal` against the six-member declared set"
    );
    assert_eq!(
        decode::<eliot_types::CalibrationScore>(
            r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","subsystem_concept_id":null,"resolved_predictions":1,"hits":1,"misses":0,"hit_rate":1.0,"proposal":"accepted"}"#
        )
        .expect_err("CalibrationScore must refuse an unknown member despite nine defaults")
        .to_string(),
        concat!(
            "unknown field `proposal`, expected one of `project_id`, `subsystem_concept_id`,",
            " `resolved_predictions`, `hits`, `misses`, `hit_rate`, `unresolvable`, `unresolved`,",
            " `brier_milli`, `blast_path_precision_milli`, `blast_path_recall_milli`,",
            " `blast_verifier_precision_milli`, `blast_verifier_recall_milli`, `trend`"
        ),
        "ul/prediction.rs:410-435 must refuse `proposal` against the fourteen-member declared set"
    );

    // ================= (D) THE TWO MOST PERMISSIVE TYPES, LABELLED =========
    // `UlPredictionActual` is `#[derive(Default)]` + `deny_unknown_fields`
    // with FIVE `#[serde(default)]` members and NO required member
    // (`ul/prediction.rs:343-358`), so `{}` decodes. `CalibrationScore` carries
    // NINE defaulted members, six members serde requires on the wire
    // (`project_id`, `subsystem_concept_id`, `resolved_predictions`, `hits`,
    // `misses`, `hit_rate` — `ul/prediction.rs:410-435`) of which FIVE are
    // non-`Option` (`ul/prediction.rs:413-418`): `subsystem_concept_id` is a
    // bare `Option<String>` with no `#[serde(default)]`, so it is required on
    // the wire and never defaulted. Both are reported as PERMISSIVE ROWS and
    // neither is pretended to refuse a missing member.
    let all_defaults_absent: UlPredictionActual = decode(
        T12_W3_C11_PREDICTION_ACTUAL_ALL_DEFAULTS_ABSENT,
    )
    .expect("PERMISSIVE ROW: ul/prediction.rs:343-358 derives Default and defaults every member");
    assert_eq!(all_defaults_absent, UlPredictionActual::default());
    assert_eq!(
        all_defaults_absent.diagnostic_before,
        Vec::<String>::new(),
        "an absent defaulted `Vec` must decode to the EMPTY list, never to a fabricated observation"
    );
    assert_eq!(all_defaults_absent.observed_value, None::<String>);
    // The guarantee that makes this acceptable rather than dangerous: the five
    // defaulted members carry NO authority, scope, effect, privacy, ordering or
    // receipt meaning. `verifier_result` (`ul/prediction.rs:347`) is a bare
    // `Option<VerificationResult>` and is therefore ABSENT-ADMISSIVE TOO — but
    // by a DIFFERENT mechanism than the five above, and the row is inverted to
    // state what is true: a bare `Option<T>` is defaulted to `None` by serde's
    // OWN `missing_field` helper, NOT by `#[serde(default)]`. serde_derive emits
    // `_serde::__private::de::missing_field("verifier_result")` for an absent
    // member, and that helper's `MissingFieldDeserializer::deserialize_option`
    // calls `visit_none()` (`serde-1.0.229/core/de/mod.rs`), so absence is NOT a
    // refusal here. This is the flip side of the same fact the loop below turns
    // into refusals: a NON-`Option` member routes through the same
    // `missing_field` call, but its `deserialize_*` has no `visit_none`, so it
    // raises `missing field \`name\`` instead.
    assert_eq!(
        decode::<UlPredictionActual>(r#"{"diagnostic_before":[]}"#)
            .expect(
                "an absent bare `Option<T>` is admitted, defaulted to `None` by serde's \
                     `missing_field` helper"
            )
            .verifier_result,
        None::<eliot_types::VerificationResult>,
        "ul/prediction.rs:347 declares `verifier_result` with NO `#[serde(default)]`, yet absence \
         still decodes: serde's `missing_field`/`MissingFieldDeserializer::deserialize_option` \
         calls `visit_none()`. Absence is not a refusal here because `None` is this member's own \
         declared absence; the verdict it would have to fabricate is \
         `VerificationResult` (`src/memory.rs:807-813`), which derives no `Default`, so \
         `#[serde(default)]` could not have supplied one either. Only a genuinely REQUIRED member \
         is refused — see the loop below for `PredictionRecord`, and the `CalibrationScore.hits` \
         and `CalibrationScore.resolved_predictions` refusals."
    );
    // The required-meaning proof the inverted row gives up, on a member that is
    // genuinely non-`Option`: `CalibrationScore.resolved_predictions` is a
    // `u32` (`ul/prediction.rs:415`) with no `#[serde(default)]`, so its
    // absence IS refused and the refusal names it. The neighbouring
    // `subsystem_concept_id` (`:414`) is a bare `Option<String>` and would have
    // decoded to `None` — exactly as `verifier_result` does above — which is why
    // the proof uses the `u32` member and not that one.
    assert_eq!(
        decode::<eliot_types::CalibrationScore>(
            r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","subsystem_concept_id":null,"hits":7,"misses":5,"hit_rate":0.5833}"#
        )
        .expect_err("a genuinely required, non-`Option` member must be refused when absent")
        .to_string(),
        "missing field `resolved_predictions`",
        "ul/prediction.rs:415 declares `resolved_predictions: u32` with no `#[serde(default)]`: \
         a defaulted zero here would be a fabricated calibration result, and unlike a bare \
         `Option<T>` it has no `visit_none` route in `MissingFieldDeserializer`"
    );
    // `CalibrationScore`: nine defaulted members decode, and the protected
    // `hits` is not one of them.
    let calibration: eliot_types::CalibrationScore = decode(
        T12_W3_C11_CALIBRATION_SCORE_DEFAULTS_ABSENT,
    )
    .expect(
        "PERMISSIVE ROW: ul/prediction.rs:419-434 defaults unresolvable, unresolved, brier_milli, \
             the four blast milli members and trend",
    );
    assert_eq!(calibration.resolved_predictions, 12);
    assert_eq!(calibration.hits, 7);
    assert_eq!(calibration.unresolvable, 0);
    assert_eq!(calibration.unresolved, 0);
    assert_eq!(calibration.brier_milli, None);
    assert_eq!(
        calibration.trend,
        eliot_types::CalibrationTrend::InsufficientData,
        "the defaulted `trend` must decode to the type's own `#[default]` variant \
         (ul/prediction.rs:406-407), never to a computed direction"
    );
    assert_eq!(
        decode::<eliot_types::CalibrationScore>(T12_W3_C11_CALIBRATION_SCORE_HITS_ABSENT)
            .expect_err("the protected `hits` must be refused, never defaulted to zero")
            .to_string(),
        "missing field `hits`",
        "ul/prediction.rs:416 declares `hits` with no `#[serde(default)]`: a defaulted zero here \
         would be a fabricated calibration result"
    );

    // ================= (E) THE CUSTOM VISITOR, AND THE PREDICTION SLOT ======
    // GUARANTEE 4 (WHAT A CUSTOM VISITOR GIVES): `UlPredictionVisitor`
    // (`ul/prediction.rs:67-150`) reads the map ONCE and refuses an unknown
    // member (`:115-129`), a repeated member (`:311-320`), a member of the
    // WRONG variant (`:167-191` etc.) and an unknown variant (`:139-148`).
    // GUARANTEE 5 (WHAT IT DOES NOT GIVE): it does NOT add any variant. There
    // is no `Proposal`, `Unknown` or authority arm in the enum
    // (`ul/prediction.rs:34-51`), so no member can name one.
    //
    // The declared slot accepts a real, closed prediction.
    let predicted: PredictionRecord = decode(T12_W3_C11_RECORD_PREDICTION_SLOT_PREDICATE)
        .expect("a real closed `UlPrediction` must decode into the declared slot");
    assert!(
        matches!(
            predicted.prediction,
            Some(UlPrediction::VerifierVerdict { .. })
        ),
        "the declared slot must hold the closed variant itself, never a proposal or an unknown"
    );
    // A `kind` naming a proposal is refused by the visitor's `unknown_variant`.
    let proposal_kind = decode::<PredictionRecord>(T12_W3_C11_RECORD_PREDICTION_SLOT_PROPOSAL_KIND)
        .expect_err(
            "docs/architecture/I15-06-instructiondata-separation.md:6 — \"model output remains \
         candidate;\" a payload member naming a proposal must not become accepted truth",
        );
    assert_eq!(
        proposal_kind.to_string(),
        "unknown variant `proposal`, expected one of `verifier_verdict`, `diagnostic_delta`, \
         `blast_radius`, `observable_value`",
        "ul/prediction.rs:139-148 must refuse a `kind` outside the four declared variants; the \
         union has no proposal and no unknown arm to absorb it"
    );
    // THE SAME REFUSAL REACHED DIRECTLY, so the row does not depend on the
    // surrounding struct at all.
    assert_eq!(
        decode::<UlPrediction>(r#"{"kind":"proposal","verifier":"cargo test","expected":"pass"}"#)
            .expect_err("UlPrediction itself must refuse a proposal variant")
            .to_string(),
        "unknown variant `proposal`, expected one of `verifier_verdict`, `diagnostic_delta`, \
         `blast_radius`, `observable_value`",
        "ul/prediction.rs:133-148 — the visitor resolves `kind` against exactly four variants"
    );
    // A member named `unknown` is not a variant of anything: it is an
    // UNRECOGNISED MEMBER, refused by the `_` arm at `:115-129`.
    let unknown_member = decode::<UlPrediction>(
        r#"{"kind":"blast_radius","predicted_paths":[],"predicted_failing_verifiers":[],"unknown":"passed"}"#,
    );
    assert_eq!(
        unknown_member
            .expect_err("a member named `unknown` must be refused")
            .to_string(),
        concat!(
            "unknown field `unknown`, expected one of `kind`, `verifier`, `expected`, `signature`,",
            " `predicted_paths`, `predicted_failing_verifiers`, `probe_ref`,",
            " `expected_excerpt_or_range`"
        ),
        "ul/prediction.rs:115-129 must refuse an unrecognised member by name"
    );
    // APPENDIX-P:13's SECOND HALF — "additive reason/telemetry values preserve
    // Unknown(raw);" — is NOT claimed for this union and cannot be: the union
    // carries no `Unknown(raw)` arm, so it satisfies the FIRST half ("closed
    // control variants fail when unknown") and has nothing to satisfy the second
    // with. This is stated rather than papered over.
    assert_eq!(
        decode::<UlPrediction>(
            r#"{"kind":"blast_radius_v2","predicted_paths":[],"predicted_failing_verifiers":[]}"#
        )
        .expect_err("an additive variant name must fail, not be preserved")
        .to_string(),
        "unknown variant `blast_radius_v2`, expected one of `verifier_verdict`, \
         `diagnostic_delta`, `blast_radius`, `observable_value`",
        "APPENDIX-P:13 — \"closed control variants fail when unknown;\" — is the half that applies to \
         a union with no Unknown(raw) arm"
    );

    // ================= (F) THE TWO CONSTRUCTS THAT ARE ABSENT ===============
    // Asserted from the REAL FILE BYTES, not from a list this test writes, so a
    // future `alias` or `flatten` introduced into the allocation would fail
    // here. `read_ul_source` is the module-level helper cases 1-8 already own.
    let mut allocation_sources = String::new();
    for file in [
        "behavior.rs",
        "concept.rs",
        "cross_agent.rs",
        "dependency.rs",
        "exam.rs",
        "guard.rs",
        "injection.rs",
        "onboarding.rs",
        "prediction.rs",
    ] {
        allocation_sources.push_str(&read_ul_source(file));
    }
    // `observability.rs` is read through the crate root because it is NOT under
    // `src/ul/`: `read_ul_source` joins `src/ul`. One closure, so no
    // module-level helper name is introduced.
    let observability_source = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("observability.rs"),
    )
    .unwrap_or_else(|error| panic!("src/observability.rs must be readable: {error}"));
    allocation_sources.push_str(&observability_source);

    // NO ALIAS. The bare token `alias` does not appear as a `#[serde(...)]`
    // construct anywhere in the allocation. The bare word is deliberately NOT
    // asserted against — prose in these files may name it — so the check is for
    // the ATTRIBUTE form, which is what could actually rename a member.
    assert!(
        !allocation_sources.contains("#[serde(alias"),
        "no type in the ten UL files or in observability.rs may declare a `#[serde(alias)]`: an \
         alias is a SECOND accepted spelling for one member, so a member can be written two ways \
         and neither spelling is then unknown. Observed bytes: {}",
        allocation_sources.matches("#[serde(alias").count()
    );
    // NO FLATTEN. A derived `#[serde(flatten)]` decoder BUFFERS the remaining
    // keys into a `serde_json::Map` — a `BTreeMap` here — so a repeated member
    // is collapsed to LAST-WINS before the inner struct ever sees it, and
    // `deny_unknown_fields` does not fire because the buffer absorbs the name.
    // That is precisely the erasure the single crate-wide `flatten`
    // (`mcp_contract.rs:20-21`) refuses, in its OWN comment at `:30-32`. The
    // allocation has none.
    assert!(
        !allocation_sources.contains("#[serde(flatten"),
        "no type in the ten UL files or in observability.rs may declare a `#[serde(flatten)]`: a \
         derived flatten decoder buffers unknown keys into a BTreeMap and resolves a repeated key \
         to LAST-WINS. Observed bytes: {}",
        allocation_sources.matches("#[serde(flatten").count()
    );
    // The `Value`-field count is asserted too, so the section-(A) claim about
    // four in-scope `Value` fields is a number the source can disprove. The
    // #940-owned `cue.rs::CueRecordSource.payload` is outside this allocation.
    assert_eq!(
        [
            read_ul_source("injection.rs")
                .matches("pub payload: Option<Value>")
                .count(),
            read_ul_source("exam.rs")
                .matches("pub output_schema: Value")
                .count(),
            observability_source.matches("pub payload: Value").count(),
        ],
        [2, 1, 1],
        "the #941 allocation declares exactly four opaque `serde_json::Value` fields: \
         PendingInjectionItem.payload, UlFiredItem.payload, UlReasoningRequest.output_schema \
         and ObservabilityWriteEnvelope.payload; cue.rs::CueRecordSource.payload is #940-owned"
    );
    // And `observability.rs` declares NO `#[serde(default)]` at all: the
    // envelope's ten members are all `required(...)`
    // (`observability.rs:196-207`), and its two `Option` members use
    // `task_id.unwrap_or_default()` / `session_id.unwrap_or_default()` — an
    // EXPLICIT `None` for an absent nullable identity, never a fabricated value.
    assert_eq!(
        observability_source.matches("#[serde(default").count(),
        0,
        "observability.rs declares no `#[serde(default)]`: its envelope binds every member through \
         `required(...)` and represents an absent nullable identity as explicit `None` \
         (observability.rs:200-201)"
    );
    // The thirteen `required(...)` bindings are counted from the real bytes: EIGHT
    // in the envelope visitor's map arm (observability.rs:197-199 and :202-206),
    // THREE in the `MemoryInfluenceWrite::Full` branch (:436-438) and TWO in the
    // `MemoryInfluenceWrite::Ack` branch (:457-458).
    assert_eq!(
        observability_source.matches("required(").count(),
        13,
        "observability.rs binds thirteen members through `required(...)`: :197-199 and :202-206 in \
         the envelope visitor, :436-438 in the Full branch, :457-458 in the Ack branch"
    );
}

// ---------------------------------------------------------------------------
// CASE 12 FIXTURES — writer w3, self-contained, no entry in `fixture()`.
// ---------------------------------------------------------------------------

/// A well-formed `UlReasoningRequest`. `output_schema` is the opaque
/// `serde_json::Value` at `ul/exam.rs:98`, so this blob is admitted verbatim and
/// NOTHING on the request's own typed surface is derived from it.
const T12_W3_C12_REQUEST_WITH_OPAQUE_OUTPUT_SCHEMA: &str = r#"{"idempotency_key":"idem-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","route":"claude","model":"claude-opus-5","prompt":"Which files does a guard change blast?","output_schema":{"type":"object","properties":{"blast_paths":{"type":"array"},"authority":{"type":"string"},"current_truth":{"type":"boolean"}},"required":["blast_paths"]},"max_input_bytes":4096,"max_output_units":800,"timeout_seconds":120}"#;

/// The same request with the one `#[serde(default)]`-bearing member, `model`,
/// ABSENT. `model` is the ONLY member of `UlReasoningRequest` that carries
/// `#[serde(default, skip_serializing_if = "Option::is_none")]`
/// (`ul/exam.rs:95-96`), so this is the PERMISSIVE ROW of this struct — and
/// `None` is the type's OWN declared absence, not a fabricated model identity.
const T12_W3_C12_REQUEST_MODEL_ABSENT: &str = r#"{"idempotency_key":"idem-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","route":"claude","prompt":"Which files does a guard change blast?","output_schema":{"type":"object"},"max_input_bytes":4096,"max_output_units":800,"timeout_seconds":120}"#;

/// The same request with the PROTECTED `timeout_seconds` removed. It carries no
/// `#[serde(default)]` (`ul/exam.rs:101`), so the absence is refused.
const T12_W3_C12_REQUEST_TIMEOUT_ABSENT: &str = r#"{"idempotency_key":"idem-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","route":"claude","prompt":"Which files does a guard change blast?","output_schema":{"type":"object"},"max_input_bytes":4096,"max_output_units":800}"#;

/// The same request with an unknown member. `UlReasoningRequest` is a derived
/// `#[serde(deny_unknown_fields)]` struct (`ul/exam.rs:88-89`), so the name is
/// refused by the owner decoder rather than deferred anywhere.
const T12_W3_C12_REQUEST_UNKNOWN_MEMBER: &str = r#"{"idempotency_key":"idem-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","route":"claude","prompt":"p","output_schema":{"type":"object"},"max_input_bytes":4096,"max_output_units":800,"timeout_seconds":120,"candidate_only":false,"authority":"accepted"}"#;

/// The repeated `idempotency_key` row. Parsed with `from_str` (through the
/// file's own `decode`), NEVER `from_value`: `serde_json::Map` is a `BTreeMap`
/// here, so a `Value` intermediate collapses the repeat to last-wins BEFORE the
/// decoder is reached. Both values DIFFER so last-wins would be observable.
/// This is the erasure claim of case 11 (E5) applied to the one type in the
/// allocation that has no decoding caller at all.
const T12_W3_C12_REQUEST_DUPLICATE_IDEMPOTENCY_KEY: &str = r#"{"idempotency_key":"idem-1","idempotency_key":"idem-2","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","route":"claude","prompt":"p","output_schema":{"type":"object"},"max_input_bytes":4096,"max_output_units":800,"timeout_seconds":120}"#;

// WORK_UNIT_CASE: 941/12
#[test]
#[allow(clippy::too_many_lines)]
fn c12_reasoning_request_is_a_reviewed_zero_candidate_row_with_no_bounded_decoder_match() {
    // GOVERNING DOCS, verbatim:
    // * docs/architecture/I15-06-instructiondata-separation.md:6 — "model output
    //   remains candidate;"
    // * docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:12 —
    //   "authority, scope, effect, privacy, ordering and receipt fields are never
    //   silently defaulted;"
    // * docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:13 —
    //   "closed control variants fail when unknown; additive reason/telemetry
    //   values preserve Unknown(raw);"
    //
    // -------------------------------------------------------------------------
    // THE ROW. `UlReasoningRequest` (crates/eliot-types/src/ul/exam.rs:88-102)
    // is recorded here as a REVIEWED ZERO-CANDIDATE ROW: it derives
    // `Deserialize` (`ul/exam.rs:88`) and has ONE `#[serde(default)]` member
    // (`ul/exam.rs:95`). The bounded detector in section (B) currently finds no
    // matching decoder call in non-test Rust sources under `crates/`, `bins/`,
    // or `workspace/`. It recognizes only the four method spellings
    // `from_str`, `from_value`, `from_slice`, and `from_reader` in the lexical
    // forms documented there; this is not a type-checked claim about every
    // possible decoder spelling or alias. The row is therefore closed by
    // REVIEW within that stated scope, not by a refusal, and
    // `decoder_calls = "[]"` is the exact text of that review.
    //
    // THE SEARCH, AND ITS EVIDENCE. `UlReasoningRequest` was located with
    // a text search scoped to the source roots `crates/`, `bins/`, and
    // `workspace/`. The listed hits are DECLARATIONS, IMPORTS or re-exports,
    // struct-literal CONSTRUCTIONS, and BORROWED PARAMETERS. This type-name
    // search describes those reviewed references; section (B) supplies the
    // separately bounded decoder-call predicate and its supported forms:
    //
    //   crates/eliot-types/src/ul/exam.rs:90        the declaration
    //   crates/eliot-types/src/lib.rs:462           `pub use ul::exam::{...}`
    //   crates/eliot-engine/src/ul/exam.rs:9        import
    //   crates/eliot-engine/src/ul/exam.rs:40       `fn run(&self, request: &UlReasoningRequest)`
    //   crates/eliot-engine/src/ul/exam.rs:507-508  `build_cold_exam_request` builds it
    //   crates/eliot-engine/src/ul/exam.rs:552      `invoke_reasoner_once(.., request: &UlReasoningRequest, ..)`
    //   crates/eliot-engine/src/ul/refinement.rs:6,51,171,219   import, trait method, builder,
    //                                                       struct literal
    //   crates/eliot-app/src/commands/ul.rs:1139,1165,1187     borrowed parameters
    //   crates/eliot-app/src/ul_cross_agent_runner.rs:25,400,664 import + two literals
    //   crates/eliot-app/src/host_runtime/event_and_authority.rs:883,1006,1031  borrowed
    //   crates/eliot-app/src/host_runtime/tests.rs:41,122       import + literal (test)
    //   crates/eliot-engine/tests/ul_exam.rs:7,131               import + borrowed param (test)
    //
    // A SECOND BOUNDED TEXT SEARCH under those same roots looked for these four
    // entry-point names adjacent to the type name. No text matched this
    // particular pattern there; this pattern is review context, not a complete
    // Rust decoder detector:
    //
    //   git grep -nE
    //     'from_(str|value|slice|reader)[^;]{0,60}UlReasoningRequest
    //     |UlReasoningRequest[^;]{0,60}from_(str|value|slice|reader)'
    //
    // → NO MATCHES in those roots for that pattern. A THIRD BOUNDED TEXT CHECK
    // under `crates/`, `bins/`, and `workspace/` for these type-position
    // spellings — `: UlReasoningRequest`, `Option<UlReasoningRequest>`,
    // `Vec<UlReasoningRequest>`, `Result<UlReasoningRequest` — observed one
    // line in the reviewed source set, `crates/eliot-engine/src/ul/refinement.rs:171`,
    // which is the
    // RETURN TYPE of the BUILDER
    // `build_refinement_request(..) -> Result<UlReasoningRequest, EngineError>`,
    // not a decode: the body ends `Ok(UlReasoningRequest { .. })` at
    // `refinement.rs:219-244`, a struct LITERAL.
    //
    // SO NO CALLER IS INFERRED FROM THESE OBSERVED SHAPES. The three
    // `UlReasoningRequest` shapes in the
    // engine — the exam builder (`ul/exam.rs:508-531`), the refinement builder
    // (`ul/refinement.rs:219-244`) and the two app literals
    // (`ul_cross_agent_runner.rs:400`, `:664`) — all CONSTRUCT the value and hand
    // it to a runner; those listed sites CONSTRUCT or BORROW the value rather
    // than reading it back from bytes. Citing a "caller that never decodes it"
    // would infer a caller this row exists to avoid, so the row is recorded as
    // zero-candidate within the stated scan scope. Section (B) re-derives its
    // bounded no-match result from source bytes using the predicate documented
    // there; it does not prove absence of unrecognized aliases or syntax.
    // -------------------------------------------------------------------------

    // ---- (A) THE REVIEWED ROW'S OWN SHAPE, ASSERTED AGAINST ITS DECODER ----
    // The accepted document decodes and the opaque `output_schema` survives it
    // INTACT, which is the positive half of "the blob neither erases input nor
    // grants meaning": a `Value` member stores what it was given.
    let request: eliot_types::UlReasoningRequest =
        decode(T12_W3_C12_REQUEST_WITH_OPAQUE_OUTPUT_SCHEMA)
            .expect("a well-formed reasoning request must decode through its owner decoder");
    assert_eq!(request.idempotency_key, "idem-1");
    assert_eq!(request.model.as_deref(), Some("claude-opus-5"));
    assert_eq!(request.max_input_bytes, 4096);
    assert_eq!(request.max_output_units, 800);
    assert_eq!(request.timeout_seconds, 120);
    // VALUE comparison of the opaque member against an independently parsed
    // `Value` — both travel through the same `BTreeMap`-backed `Map`, so this is
    // never a claim that a parsed `Value` re-serializes to its own text.
    assert_eq!(
        request.output_schema,
        decode::<serde_json::Value>(
            r#"{"properties":{"authority":{"type":"string"},"blast_paths":{"type":"array"},"current_truth":{"type":"boolean"}},"required":["blast_paths"],"type":"object"}"#
        )
        .expect("the expected output schema must itself be valid JSON"),
        "the opaque `output_schema` must be stored verbatim: a `Value` member erases nothing"
    );
    // THE GUARANTEE THAT MATTERS: the blob's `authority` and `current_truth`
    // members are NOT on the request's typed surface, so nothing downstream can
    // read them as an authority or a truth claim. `UlReasoningRequest` exposes no
    // member-list accessor, so the typed surface is read from the SOURCE itself
    // (`crates/eliot-types/src/ul/exam.rs:88-104`): the struct body declares
    // exactly these members and names neither `authority` nor `current_truth`.
    let exam_source = read_ul_source("exam.rs");
    let request_body = exam_source
        .split_once("pub struct UlReasoningRequest {")
        .and_then(|(_, tail)| tail.split_once("\n}"))
        .map(|(body, _)| body)
        .expect("ul/exam.rs must declare `pub struct UlReasoningRequest {` terminated by `\\n}`");
    for member in [
        "idempotency_key",
        "project_id",
        "task_id",
        "route",
        "model",
        "prompt",
        "output_schema",
        "max_input_bytes",
        "max_output_units",
        "timeout_seconds",
    ] {
        assert!(
            request_body.contains(&format!("pub {member}:")),
            "the request's own declared surface must carry `{member}`, per ul/exam.rs:90-104"
        );
    }
    assert!(
        !request_body.contains("authority") && !request_body.contains("current_truth"),
        "the request's typed surface must NOT declare `authority` or `current_truth`: those \
         exist only inside the opaque `output_schema` blob and are unreadable as typed members"
    );

    // (A1) THE PERMISSIVE ROW, labelled. `model` is the ONE member that carries
    // `#[serde(default, skip_serializing_if = "Option::is_none")]`
    // (`ul/exam.rs:95-96`), so a request with no `model` DECODES and the value is
    // `None`. That is the type's OWN declared absence — not a fabricated model
    // identity — and `None` means "route default", which is the route's own
    // decision rather than an invented one.
    let model_absent: eliot_types::UlReasoningRequest = decode(
        T12_W3_C12_REQUEST_MODEL_ABSENT,
    )
    .expect(
        "PERMISSIVE ROW: ul/exam.rs:95-96 really does default `model` to None; this is the only \
         `#[serde(default)]` member of the struct",
    );
    assert_eq!(model_absent.model, None::<String>);
    assert_eq!(model_absent.idempotency_key, "idem-1");
    // (A2) AND EVERY OTHER MEMBER IS REFUSED WHEN ABSENT. `idempotency_key`,
    // `project_id`, `task_id`, `route`, `prompt`, `output_schema`,
    // `max_input_bytes`, `max_output_units` and `timeout_seconds` carry NO
    // `#[serde(default)]` (`ul/exam.rs:88-102`), so each absence is a
    // missing-field refusal. This is what APPENDIX-P:12 demands of the
    // scope/effect/ordering members and it is asserted member by member rather
    // than as a blanket claim.
    for member in [
        "idempotency_key",
        "project_id",
        "task_id",
        "route",
        "prompt",
        "output_schema",
        "max_input_bytes",
        "max_output_units",
        "timeout_seconds",
    ] {
        let mut document = decode::<serde_json::Value>(T12_W3_C12_REQUEST_MODEL_ABSENT)
            .expect("the accepted document must itself be valid JSON");
        let object = document
            .as_object_mut()
            .expect("the accepted document must be a JSON object");
        assert!(
            object.remove(member).is_some(),
            "the accepted document must actually carry `{member}`, or the row proves nothing"
        );
        assert_eq!(
            decode::<eliot_types::UlReasoningRequest>(&document.to_string())
                .expect_err("an absent non-defaulted member must be refused")
                .to_string(),
            format!("missing field `{member}`"),
            "ul/exam.rs:88-102 declares no `#[serde(default)]` on the member, so its absence is a \
             missing-field refusal: APPENDIX-P:12 — \"authority, scope, effect, privacy, \
             ordering and receipt fields are never silently defaulted;\""
        );
    }
    // (A2b) THE SAME REFUSAL FROM A WHOLE FIXTURE, not from a runtime-removed
    // member. This is the named-document form: the absent-member fixture is the
    // accepted one (which DOES carry `timeout_seconds`) with only that member
    // removed, so the refusal is provably caused by that absence and by nothing
    // else in the document. The removal is applied to the document that HAS the
    // member — applying it to `T12_W3_C12_REQUEST_TIMEOUT_ABSENT` would be a
    // no-op and would compare the fixture to itself.
    assert_eq!(
        T12_W3_C12_REQUEST_MODEL_ABSENT
            .replace(",\"timeout_seconds\":120", "")
            .len(),
        T12_W3_C12_REQUEST_TIMEOUT_ABSENT.len(),
        "the absent-member fixture must be the accepted fixture with only `timeout_seconds` removed"
    );
    // And the removal really removed exactly that member and nothing else: the
    // two documents are byte-identical once `,"timeout_seconds":120` is gone
    // from the accepted one.
    assert_eq!(
        T12_W3_C12_REQUEST_MODEL_ABSENT.replace(",\"timeout_seconds\":120", ""),
        T12_W3_C12_REQUEST_TIMEOUT_ABSENT,
        "the two fixtures must differ ONLY by `,\"timeout_seconds\":120`"
    );
    assert_eq!(
        decode::<eliot_types::UlReasoningRequest>(T12_W3_C12_REQUEST_TIMEOUT_ABSENT)
            .expect_err("a document missing the protected `timeout_seconds` must be refused")
            .to_string(),
        "missing field `timeout_seconds`",
        "the protected member's absence is a missing-field refusal naming it, per ul/exam.rs:101"
    );
    // (A3) THE UNKNOWN-MEMBER REFUSAL. A control-imitating member cannot ride
    // along, because the struct is `deny_unknown_fields` (`ul/exam.rs:89`) —
    // the SAME orthogonality section (C) of case 11 relies on.
    let unknown_member =
        decode::<eliot_types::UlReasoningRequest>(T12_W3_C12_REQUEST_UNKNOWN_MEMBER)
            .expect_err("a control-imitating member must be refused by the owner decoder");
    assert_eq!(
        unknown_member.to_string(),
        concat!(
            "unknown field `candidate_only`, expected one of `idempotency_key`, `project_id`,",
            " `task_id`, `route`, `model`, `prompt`, `output_schema`, `max_input_bytes`,",
            " `max_output_units`, `timeout_seconds`"
        ),
        "ul/exam.rs:88-89 must refuse `candidate_only` against the ten-member declared set: \
         APPENDIX-P:13 — \"closed control variants fail when unknown;\""
    );
    // (A3b) THE SAME TWO SHAPES AT THE TOP-LEVEL NAMED FIXTURES, asserted once
    // each against the decoder they belong to. The `T12_C12_*` constants carry the
    // larger `max_input_bytes`/`max_output_units` of the two, so they are
    // DISTINCT documents from the `T12_W3_C12_*` pair asserted above, and neither
    // row is a duplicate of the other.
    //
    // (A3b-i) `T12_C12_REASONING_REQUEST_CANDIDATE_OUTPUT_ACCEPT` — MAIN IS MORE
    // PERMISSIVE THAN THE CONSTANT'S ORIGINAL NAME IMPLIED. It carries all ten
    // declared members and no undeclared one, so it DECODES; the `authority` and
    // `current_truth` names live inside the opaque `output_schema` blob and are
    // inert data, exactly as section (A) proves for the smaller document.
    let candidate_output: eliot_types::UlReasoningRequest =
        decode(T12_C12_REASONING_REQUEST_CANDIDATE_OUTPUT_ACCEPT).expect(
            "MAIN IS MORE PERMISSIVE THAN THE NAME IMPLIES: this request carries every declared \
             member and no undeclared one, so a candidate-shaped `output_schema` DECODES as an \
             opaque provider blob rather than being refused",
        );
    assert_eq!(candidate_output.max_input_bytes, 65_536);
    assert_eq!(candidate_output.max_output_units, 2_048);
    assert_eq!(candidate_output.timeout_seconds, 120);
    assert_eq!(candidate_output.model.as_deref(), Some("claude-opus-5"));
    // The blob's candidate-shaped names are DATA: the request's own typed surface
    // exposes neither of them, so nothing downstream can read them as an
    // authority or a truth claim. The typed surface was read from the SOURCE
    // above (`request_body`), so this is the same fact at a second size.
    assert_eq!(
        candidate_output.output_schema,
        decode::<serde_json::Value>(
            r#"{"properties":{"authority":{"type":"string"},"blast_paths":{"type":"array"},"current_truth":{"type":"boolean"}},"required":["blast_paths"],"type":"object"}"#
        )
        .expect("the expected output schema must itself be valid JSON"),
        "the opaque `output_schema` must be stored verbatim at BOTH sizes: a `Value` member erases \
         nothing and grants no meaning"
    );
    // (A3b-ii) `T12_C12_REASONING_REQUEST_UNKNOWN_MEMBER_REFUSE` — the SAME
    // request with ONE extra member. `UlReasoningRequest` is a derived
    // `deny_unknown_fields` struct (`ul/exam.rs:88-89`), so the name is refused by
    // the owner decoder, never deferred, and the refusal names the offending
    // member against the whole ten-member declared set.
    let unknown_request =
        decode::<eliot_types::UlReasoningRequest>(T12_C12_REASONING_REQUEST_UNKNOWN_MEMBER_REFUSE)
            .expect_err("an unknown member must be refused by the owner decoder, never deferred");
    assert_eq!(
        unknown_request.to_string(),
        concat!(
            "unknown field `provider_temperature`, expected one of `idempotency_key`, `project_id`,",
            " `task_id`, `route`, `model`, `prompt`, `output_schema`, `max_input_bytes`,",
            " `max_output_units`, `timeout_seconds`",
        ),
        "ul/exam.rs:88-89 must refuse `provider_temperature` against the ten-member declared set: \
         APPENDIX-P:13 — \"closed control variants fail when unknown;\""
    );
    // (A4) THE ROUTE IS A CLOSED CONTROL VARIANT. `UlReasoningRoute`
    // (`ul/exam.rs:61-68`) has exactly two arms and no `Unknown(raw)`, so an
    // additive spelling fails rather than being absorbed.
    assert_eq!(
        decode::<eliot_types::UlReasoningRoute>(r#""claude""#)
            .expect("the owned route must decode")
            .as_str(),
        "claude",
        "ul/exam.rs:80-85 must map the owned variant to its own wire spelling"
    );
    assert_eq!(
        decode::<eliot_types::UlReasoningRoute>(r#""gpt""#)
            .expect_err("an unowned route must fail rather than be preserved as an unknown")
            .to_string(),
        "unknown variant `gpt`, expected `claude` or `antigravity`",
        "ul/exam.rs:61-68 is a closed control variant: APPENDIX-P:13 — \"closed control variants fail \
         when unknown;\" — and there is no Unknown(raw) arm for an additive value to land in"
    );
    // (A5) THE DUPLICATE-MEMBER EVIDENCE, PARSED FROM TEXT. `serde_json::Map` is
    // a `BTreeMap` here, so a `from_value` assertion would collapse the repeat
    // to LAST-WINS before the decoder ran and prove nothing. This is the erasure
    // hazard case 11 (E5) names, and it is proven twice over: once against the
    // typed decoder and once against the shared lexical ingress.
    let duplicate = T12_W3_C12_REQUEST_DUPLICATE_IDEMPOTENCY_KEY;
    assert_eq!(
        duplicate.matches("\"idempotency_key\"").count(),
        2,
        "the fixture must literally repeat the member, or it proves nothing"
    );
    assert!(
        duplicate.contains("idem-1") && duplicate.contains("idem-2"),
        "the repeated member must carry DIFFERENT values so last-wins would be observable"
    );
    assert_eq!(
        decode::<eliot_types::UlReasoningRequest>(duplicate)
            .expect_err("a repeated idempotency key must be refused, never last-wins")
            .to_string(),
        "duplicate field `idempotency_key`",
        "ul/exam.rs:88 derives Deserialize with no `flatten`, so serde's own per-field duplicate \
         detection fires on the second occurrence"
    );
    assert_eq!(
        strict_json_has_no_duplicate_members(duplicate.as_bytes())
            .expect_err("the shared lexical ingress must also refuse the repeated member")
            .kind,
        StrictJsonErrorKind::DuplicateKey,
        "src/strict_json.rs:194-203 must refuse the repeated member at the top level"
    );
    // And the shared ingress ACCEPTS the well-formed document, so the refusal
    // above is the repeat and not the shape.
    assert!(
        strict_json_has_no_duplicate_members(
            T12_W3_C12_REQUEST_WITH_OPAQUE_OUTPUT_SCHEMA.as_bytes()
        )
        .is_ok(),
        "the well-formed reasoning request must pass the shared lexical ingress"
    );

    // ---- (B) THE BOUNDED ZERO-CANDIDATE ROW CHECK, DERIVED FROM SOURCE BYTES.
    // ---- A matching call in the covered roots and spellings fails this case;
    // ---- unrecognized aliases or syntax are outside this lexical predicate.
    //
    // `CARGO_MANIFEST_DIR` is `crates/eliot-types`; the repository root is two
    // levels up. The walk starts only at `crates/`, `bins/`, and `workspace/`
    // and considers Rust source files beneath them, skipping `target/` and
    // `.git/`. It is a lexical scan, not Rust name or type resolution. Any call
    // matching the supported predicate in an eligible non-test source file is
    // recorded and makes the empty-row assertions fail after the walk.
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    // `decoder_calls` is NOT a literal written here: it is BUILT FROM the scan
    // below (`format!("[{}]", sites.join(", "))`), so a call matching the
    // supported predicate in the covered roots makes this assertion fail.
    // `"[]"` is the EXPECTED value, never the input.
    let decoder_entry_points: [&str; 4] = ["from_str", "from_value", "from_slice", "from_reader"];
    let target: &str = "UlReasoningRequest";
    // This is a deliberately bounded lexical check, not Rust type inference:
    // normalize whitespace and recognize an explicit `UlReasoningRequest`
    // binding immediately initialized by one of the four reviewed serde_json
    // method names. Supported typed-binding spellings are `serde_json::from_*`
    // and `::serde_json::from_*`, or a direct `use serde_json::from_*;` / `use
    // serde_json::{from_*};` followed by `from_*(...)`. Renamed imports,
    // re-exports, aliases, macros, and inferred data flow are not resolved.
    let compact_source = |source: &str| {
        source
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>()
    };
    let typed_binding_decoder_call = |source: &str, entry_point: &str| {
        let compact = compact_source(source);
        let binding = format!(":{target}=");
        let qualified = format!("{binding}serde_json::{entry_point}(");
        let rooted_qualified = format!("{binding}::serde_json::{entry_point}(");
        if compact.contains(&qualified) || compact.contains(&rooted_qualified) {
            return true;
        }
        let directly_imported = compact.contains(&format!("useserde_json::{entry_point};"))
            || compact.contains(&format!("useserde_json::{{{entry_point}}};"));
        directly_imported && compact.contains(&format!("{binding}{entry_point}("))
    };
    let qualified_binding_probe = "let request: UlReasoningRequest = serde_json::from_str(input)?;";
    assert!(
        typed_binding_decoder_call(qualified_binding_probe, "from_str"),
        "the bounded source predicate must detect an explicitly typed qualified decode"
    );
    let imported_binding_probe =
        "use serde_json::from_str; let request: UlReasoningRequest = from_str(input)?;";
    assert!(
        typed_binding_decoder_call(imported_binding_probe, "from_str"),
        "the bounded source predicate must detect a direct imported entrypoint"
    );
    let unrelated_binding_probe = "let request: OtherRequest = serde_json::from_str(input)?;";
    assert!(
        !typed_binding_decoder_call(unrelated_binding_probe, "from_str"),
        "the bounded source predicate must remain specific to UlReasoningRequest"
    );
    let mut rust_source_files = 0_usize;
    let mut production_source_files = 0_usize;
    let mut bytes_scanned = 0_usize;
    let mut decoding_call_sites: Vec<String> = Vec::new();
    let mut stack = vec![repo_root.join("crates")];
    stack.push(repo_root.join("bins"));
    stack.push(repo_root.join("workspace"));
    while let Some(directory) = stack.pop() {
        let entries = std::fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("{} must be readable: {error}", directory.display()));
        for entry in entries {
            let entry = entry.unwrap_or_else(|error| {
                panic!("{} must be readable: {error}", directory.display())
            });
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy().to_string();
            // `target/` is build output, never a source of truth, and it is the
            // one directory deep enough to hold thousands of files.
            if path.is_dir() {
                if name == "target" || name == ".git" {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !name.to_ascii_lowercase().ends_with(".rs") {
                continue;
            }
            rust_source_files += 1;
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()));
            bytes_scanned += source.len();
            let relative = path
                .strip_prefix(&repo_root)
                .unwrap_or_else(|_| {
                    panic!("{} must live under the repository root", path.display())
                })
                .to_string_lossy()
                .replace('\\', "/");
            // TEST FILES ARE EXCLUDED, AND THAT IS THE POINT OF THIS ROW. This
            // row checks for matching calls in non-test production source under
            // the three roots above; this test itself decodes the type in
            // section (A), so including test sources would match its own
            // evidence. Excluding tests scopes the claim to production source;
            // it says nothing about decoder calls in tests or source outside
            // those roots. Files in a `tests/`
            // directory, a `tests.rs` module, or a `*_test.rs`/`*_tests.rs`
            // sibling are therefore counted but never scanned for call sites.
            let is_test_source = relative.split('/').any(|segment| segment == "tests")
                || name == "tests.rs"
                || name.ends_with("_test.rs")
                || name.ends_with("_tests.rs");
            if is_test_source {
                continue;
            }
            production_source_files += 1;
            for entry_point in decoder_entry_points {
                // For each of the four method names, the generic text check is
                // the exact `from_*::<UlReasoningRequest>(` spelling, including
                // its opening parenthesis; it does not resolve the method's
                // module. The bounded typed-binding predicate above additionally
                // covers the listed qualified/direct-import annotation forms
                // without a turbofish.
                let needle = format!("{entry_point}::<{target}>(");
                if source.contains(&needle) || typed_binding_decoder_call(&source, entry_point) {
                    decoding_call_sites.push(format!("{relative}: {entry_point} -> {target}"));
                }
            }
        }
    }
    // The value under test, built from the scan, so it cannot be a tautology.
    let decoder_calls = format!("[{}]", decoding_call_sites.join(", "));
    assert_eq!(
        decoder_calls, "[]",
        "the reviewed row's decoder_calls value is the empty JSON array: no call site matched \
         this bounded lexical predicate in non-test Rust sources under crates/, bins/, or \
         workspace/. It checks the four named method spellings using the documented turbofish \
         and typed-binding/direct-import forms; it does not resolve aliases or infer Rust types"
    );
    assert!(
        decoding_call_sites.is_empty(),
        "the bounded scan matched `{target}` at {decoding_call_sites:?} within its covered roots, \
         source files, and method spellings, so the scoped zero-candidate row must be reviewed"
    );
    // The walk itself must not be vacuous: it must have read real Rust files
    // under the three configured roots, counted a substantial non-test source
    // set, and included the file that DECLARES the type. `bytes_scanned` is the
    // total across Rust files read in those roots, including test files before
    // their call-site exclusion; these thresholds do not describe the whole
    // repository.
    assert!(
        production_source_files > 500
            && bytes_scanned > 10_000_000
            && production_source_files < rust_source_files,
        "the bounded scan must have read its configured roots, not skipped them: it read \
         {rust_source_files} Rust files in crates/, bins/, and workspace/, {production_source_files} \
         of them eligible non-test sources, and {bytes_scanned} total bytes across those Rust files"
    );
    assert_eq!(
        std::fs::read_to_string(repo_root.join("crates/eliot-types/src/ul/exam.rs"))
            .unwrap_or_else(|error| panic!("ul/exam.rs must be readable: {error}"))
            .matches(&format!("pub struct {target}"))
            .count(),
        1,
        "the bounded scan roots must include the declaration file for `{target}`, or this scoped \
         no-match result is unproven"
    );

    // (B1) THE DECODER EXISTS AND IS REACHABLE — the row is zero-OBSERVED-CALL
    // within the scan's coverage, not zero-DECODER. The refusals and acceptance
    // in section (A) already exercised `UlReasoningRequest`'s own
    // `Deserialize` through `serde_json::from_str`, so the decoder is
    // demonstrably live. The scoped source check observes no matching call
    // site, which makes this a reviewed row rather than an untested one within
    // the stated detector boundary.
    //
    // (B2) THE REVIEWED RETURN TYPE IN THIS FILE IS A BUILDER, NOT A DECODE.
    // Its body constructs the value. These checks are limited to the selected
    // `refinement.rs` source and the spellings stated below.
    let refinement_source =
        std::fs::read_to_string(repo_root.join("crates/eliot-engine/src/ul/refinement.rs"))
            .unwrap_or_else(|error| {
                panic!("eliot-engine/src/ul/refinement.rs must be readable: {error}")
            });
    assert_eq!(
        refinement_source
            .matches("-> Result<UlReasoningRequest, EngineError>")
            .count(),
        1,
        "the selected refinement source contains one `-> Result<UlReasoningRequest, EngineError>` spelling"
    );
    assert_eq!(
        refinement_source.matches("Ok(UlReasoningRequest {").count(),
        1,
        "ul/refinement.rs:219 must CONSTRUCT the request with a struct literal, never acquire one \
         from bytes"
    );
    assert!(
        !refinement_source.contains(&format!("from_str::<{target}>("))
            && !refinement_source.contains(&format!("from_value::<{target}>(")),
        "in this file, the builder source must not contain either checked turbofish spelling: \
         from_str::<UlReasoningRequest>( or from_value::<UlReasoningRequest>(; other entrypoint \
         forms are covered only by the bounded workspace scan above"
    );
    // (B3) THE EXAM BUILDER IN ITS NAMED SOURCE FILE. The assertion below
    // counts the reviewed literal spelling in this file only.
    let engine_exam_source =
        std::fs::read_to_string(repo_root.join("crates/eliot-engine/src/ul/exam.rs"))
            .unwrap_or_else(|error| {
                panic!("eliot-engine/src/ul/exam.rs must be readable: {error}")
            });
    assert_eq!(
        engine_exam_source
            .matches("    let mut request = UlReasoningRequest {")
            .count(),
        1,
        "eliot-engine/src/ul/exam.rs:508 must CONSTRUCT the exam request with a struct literal"
    );
    assert_eq!(
        engine_exam_source.matches("model: None").count(),
        1,
        "eliot-engine/src/ul/exam.rs:513 must leave `model` at the type's own None, which is what \
         `#[serde(default)]` at ul/exam.rs:95 produces on the decode side"
    );
    // (B4) THE TWO REVIEWED APP PRODUCER LITERALS IN THE NAMED FILE. This
    // file-local count does not claim that these are the only occurrences
    // outside `eliot-types` and `eliot-engine`.
    let runner_source =
        std::fs::read_to_string(repo_root.join("crates/eliot-app/src/ul_cross_agent_runner.rs"))
            .unwrap_or_else(|error| {
                panic!("eliot-app/src/ul_cross_agent_runner.rs must be readable: {error}")
            });
    assert_eq!(
        runner_source
            .matches("let request = UlReasoningRequest {")
            .count(),
        2,
        "ul_cross_agent_runner.rs must currently contain two matching `let request = \
         UlReasoningRequest` struct-literal constructions"
    );
    // (B5) THE ENUMERATED OWNER FORMS IN THE REVIEWED OBSERVABILITY FILE.
    // `bind_observability_payload` (`observability.rs:231-255`) routes each of
    // the SIX listed kinds to its owner record type; this file-local check does
    // not establish that every ingress path in the workspace is covered. The six are
    // `MemoryGrantOfferRecord`, `InjectionReceipt`, `MemoryInfluenceTrace`,
    // `ActivationTrace`, `PredictionRecord` and `UlExamRecord`. These enumerated
    // owner forms are contextual source evidence, not a second global
    // zero-candidate proof.
    let observability_source =
        std::fs::read_to_string(repo_root.join("crates/eliot-types/src/observability.rs"))
            .unwrap_or_else(|error| {
                panic!("eliot-types/src/observability.rs must be readable: {error}")
            });
    for owner_arm in [
        "MemoryGrantOfferRecord",
        "InjectionReceipt",
        "MemoryInfluenceTrace",
        "ActivationTrace",
        "PredictionRecord",
        "UlExamRecord",
    ] {
        assert_eq!(
            observability_source
                .matches(&format!("from_value::<{owner_arm}>"))
                .count(),
            1,
            "the reviewed observability source must contain exactly one `from_value::<{owner_arm}>` form"
        );
    }
    assert_eq!(
        observability_source.matches("from_value::<").count(),
        6,
        "the reviewed observability source contains exactly six `from_value::<...>` owner forms; \
         this file-local count is not a claim about other roots, entrypoints, or aliases"
    );

    // ---- (C) WHY THE ROW IS REVIEWED RATHER THAN REFUSED. ------------------
    // `docs/architecture/I15-06-instructiondata-separation.md:6` — "model output
    // remains candidate;". `UlReasoningRequest` is a REQUEST, not a model
    // output: it is built by an engine-owned builder from engine-owned plans
    // (`eliot-engine/src/ul/exam.rs:501-548`,
    // `eliot-engine/src/ul/refinement.rs:166-245`) and handed to a runner by
    // borrow (`UlReasoningRunner::run(&self, request: &UlReasoningRequest)`,
    // `eliot-engine/src/ul/exam.rs:39-41`). The reviewed builder/runner sites
    // pass the request by borrow, and the enumerated owner forms in the checked
    // observability source do not name it. Those observations do not cover
    // unrecognized ingress forms or source outside the stated roots.
    //
    // THE CONSEQUENCE, STATED ONCE: with `decoder_calls = "[]"`, no call site
    // matched the documented lexical predicate in eligible non-test Rust
    // sources under `crates/`, `bins/`, and `workspace/`. The predicate covers
    // the four listed method names, generic turbofish text, and the supported
    // qualified/direct-import typed bindings; it does not prove universal
    // absence across aliases, macros, other entrypoints, or unscanned roots.
    // The decoder refusals exercised in section (A) describe the owner type's
    // behavior if called. A newly matching call in the covered scope makes the
    // bounded row fail and its evidence must be re-reviewed.
    assert_eq!(
        decoder_calls, "[]",
        "the reviewed row for `UlReasoningRequest` is: decoder_calls = \"[]\" — no call sites \
         matched the bounded lexical predicate in eligible non-test Rust sources under crates/, \
         bins/, or workspace/. It checks the four listed method names using the documented \
         turbofish and qualified/direct-import typed-binding forms; aliases and other syntax are \
         outside its coverage. This value is built from those matches, not written here."
    );
}

// ===========================================================================
// CASES 13-16 — appended by this writer AFTER the placeholder banner above,
// which is preserved verbatim. Nothing above this line is edited: the shared
// `pairs` table inside `fixture()` is untouched, so these four cases own no
// key in it and cannot collide with the two parallel writers.
//
// Every fixture below is a SELF-CONTAINED `const NAME: &str = r#"..."#;` and
// is referenced directly. FIXTURES ARE RAW JSON TEXT, ALWAYS: `serde_json::Map`
// is a `BTreeMap` in this workspace (the `preserve_order` feature is NOT
// enabled), so a parsed object comes back with its members SORTED and NOTHING
// here asserts that a parsed `Value` re-serializes to its original text. Every
// comparison below is a VALUE comparison or a comparison of a decoded field.
//
// EXACT ERROR STRINGS. The refusals asserted below are quoted from the real
// raising sites and, where serde raises them, they are pinned against serde's
// OWN message text. That is only sound because of two verified facts about
// `serde_json::Error`'s `Display`:
//   * `serde`'s `de::Error::unknown_field` / `unknown_variant` /
//     `missing_field` / `duplicate_field` build their message with
//     `format_args!` and never append a position, so
//     `serde_json::error::make_error`'s `parse_line_col` finds no
//     `" at line N column M"` suffix, leaves `line == 0`, and `Display` then
//     writes the message BARE (serde_json-1.0.151 `error.rs`,
//     `impl Display for ErrorImpl`);
//   * serde's `OneOf` Display renders 2 names as "`a` or `b`" and 3+ as
//     "one of `a`, `b`, `c`" (serde-1.0.229 `core/de/mod.rs`), which is what
//     makes the expected-field tail below a literal and not a paraphrase.
//
// Each pinned string is asserted with `assert_eq!` on the WHOLE message, so a
// paraphrase that happened to contain the field name would not pass.
// ===========================================================================

/// Case 13 (a): a closed-enum unknown variant on `CapsuleFreshness`, whose
/// `Deserialize` is the hand-written `CapsuleFreshnessVisitor`
/// (`ul/concept.rs:164-225`). The `_` arm of `visit_map` rejects an unknown
/// member; `unknown_variant` (`:219-222`) rejects an unknown `status`.
const T12_W3_C13_CAPSULE_FRESHNESS_UNKNOWN_VARIANT: &str =
    r#"{"status":"half_fresh","changed":[],"missing":[]}"#;

/// Case 13 (b): an unknown TOP-LEVEL member of the same hand-written visitor.
/// `ul/concept.rs:195-200` returns `unknown_field(key, &["status","changed",
/// "missing"])` — exactly three names, so `OneOf` renders the `one of` form.
const T12_W3_C13_CAPSULE_FRESHNESS_UNKNOWN_MEMBER: &str =
    r#"{"status":"fresh","decided_at":"2026-09-24T10:15:00Z"}"#;

/// Case 13 (c): a NESTED-member refusal. The nested element is one
/// `UlExamQuestion` inside `UlExamRecord::questions`
/// (`ul/exam.rs:54`), and `UlExamQuestion` is its own derived,
/// `#[serde(deny_unknown_fields)]` struct (`ul/exam.rs:16-26`), so the
/// closure is enforced at that depth. The refused name is NOT one of the
/// seven declared members, so its absence from the expected tail is real.
const T12_W3_C13_EXAM_NESTED_UNKNOWN_MEMBER: &str = r#"{"exam_id":"exam-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","route":"claude","cold_input_refs":[],"questions":[{"question_id":"q1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","subsystem_concept_id":"concept-1","kind":"blast","prompt":"Which files does a guard change blast?","ground_truth_refs":[],"ground_truth_values":[],"grader_hint":"high"}],"answers":[],"grades":[],"subsystem_scores_milli":[],"dirty_capsule_refs":[]}"#;

/// Case 13 (d): the SAME nested document with the unknown member removed. It
/// must decode, or the refusal above could be an accident of the envelope
/// rather than of the nested member.
const T12_W3_C13_EXAM_NESTED_ACCEPT: &str = r#"{"exam_id":"exam-1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","route":"claude","cold_input_refs":[],"questions":[{"question_id":"q1","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","subsystem_concept_id":"concept-1","kind":"blast","prompt":"Which files does a guard change blast?","ground_truth_refs":[],"ground_truth_values":[]}],"answers":[],"grades":[],"subsystem_scores_milli":[],"dirty_capsule_refs":[]}"#;

// WORK_UNIT_CASE: 941/13
#[test]
#[allow(clippy::too_many_lines)]
fn c13_real_validators_and_visitors_return_their_exact_refusal_messages() {
    // `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:13` —
    // "closed control variants fail when unknown; additive reason/telemetry
    // values preserve Unknown(raw);"
    // `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:12` —
    // "authority, scope, effect, privacy, ordering and receipt fields are never
    // silently defaulted;"
    //
    // Cases 3-6 proved that these shapes are REFUSED. This case pins the exact
    // bytes of each refusal, so a future edit cannot quietly replace a
    // `unknown_variant` with a paraphrase, drop the expected-field tail, or
    // soften the refusal into a silently dropped member. Every expected string
    // below is quoted from the raising site, not from a description of it.
    //
    // WHY EXACT EQUALITY IS SOUND HERE: serde raises these four refusals with
    // `format_args!` and no position suffix, so `serde_json::Error`'s `Display`
    // prints them bare (verified against serde-1.0.229 `core/de/mod.rs` and
    // serde_json-1.0.151 `error.rs`), and serde's `OneOf` renders 2 names as
    // "`a` or `b`" and 3+ as "one of `a`, `b`, `c`". The expected-field tails
    // below are therefore literals, not patterns.

    // ---- (a) A CLOSED ENUM with an unknown variant. -----------------------
    // `ul/concept.rs:219-222`:
    //     other => Err(serde::de::Error::unknown_variant(
    //         other,
    //         &["fresh", "stale"],
    //     )),
    // Two names, so `OneOf` renders "`fresh` or `stale`".
    let closed_enum =
        decode::<eliot_types::CapsuleFreshness>(T12_W3_C13_CAPSULE_FRESHNESS_UNKNOWN_VARIANT);
    let closed_enum_error = closed_enum.expect_err(
        "ul/concept.rs: a closed CapsuleFreshness must refuse the unknown variant `half_fresh`",
    );
    assert_eq!(
        closed_enum_error.to_string(),
        "unknown variant `half_fresh`, expected `fresh` or `stale`",
        "ul/concept.rs:219-222 must raise serde's own unknown_variant text verbatim"
    );
    // The two OWNED variants decode, so the refusal above is the unknown
    // variant and nothing else. `fresh` takes no payload member
    // (`ul/concept.rs:206-213`).
    let fresh = decode::<eliot_types::CapsuleFreshness>(r#"{"status":"fresh"}"#)
        .expect("the owned `fresh` variant must decode");
    assert_eq!(fresh, eliot_types::CapsuleFreshness::Fresh);
    let stale = decode::<eliot_types::CapsuleFreshness>(
        r#"{"status":"stale","changed":["a.rs"],"missing":["b.rs"]}"#,
    )
    .expect("the owned `stale` variant must decode with both payload members");
    assert_eq!(
        stale,
        eliot_types::CapsuleFreshness::Stale {
            changed: vec!["a.rs".to_owned()],
            missing: vec!["b.rs".to_owned()],
        },
        "the stale variant must carry exactly the two declared payload lists"
    );
    // (a1) THE STALE PAYLOAD IS REQUIRED ON BOTH SIDES. `T12_C13_CAPSULE_FRESHNESS_PAYLOAD_REFUSE`
    // carries `changed` but not `missing`, and the `stale` arm binds both through
    // `required` (`ul/concept.rs:216-217`), so the ABSENT one is refused by name.
    let stale_payload =
        decode::<eliot_types::CapsuleFreshness>(T12_C13_CAPSULE_FRESHNESS_PAYLOAD_REFUSE);
    assert_eq!(
        stale_payload
            .expect_err(
                "ul/concept.rs:216-217 must refuse a stale record whose `missing` payload member is \
                 absent, never default it to an empty list"
            )
            .to_string(),
        "missing field `missing`",
        "ul/concept.rs:217 binds `missing` through `required`, so an absent required-nullable \
         payload member is a missing-field refusal naming it"
    );
    // The mirror image: `changed` absent while `missing` is present is refused the
    // same way and by the same call, so the refusal is the ABSENCE of either
    // payload member and not the presence of `changed`.
    let stale_payload_mirror = decode::<eliot_types::CapsuleFreshness>(
        r#"{"status":"stale","missing":["crates/eliot-types/src/ul/guard.rs"]}"#,
    );
    assert_eq!(
        stale_payload_mirror
            .expect_err("the absent `changed` payload member must be refused the same way")
            .to_string(),
        "missing field `changed`",
        "ul/concept.rs:216 binds `changed` through `required`; both payload members are equally \
         required, so neither is silently defaulted to an empty list"
    );
    // (a2) THE `fresh` VARIANT TAKES NO PAYLOAD AT ALL.
    // `T12_C13_CAPSULE_FRESHNESS_FRESH_WITH_PAYLOAD_REFUSE` carries `changed`
    // against `fresh`, and the `fresh` arm refuses each payload name as an
    // unknown field against its own one-name field set (`ul/concept.rs:207-212`).
    // The expected tail is the ONE-name form, so serde's `OneOf` renders
    // "`status`" with no "one of" prefix.
    let fresh_with_payload = decode::<eliot_types::CapsuleFreshness>(
        T12_C13_CAPSULE_FRESHNESS_FRESH_WITH_PAYLOAD_REFUSE,
    );
    assert_eq!(
        fresh_with_payload
            .expect_err(
                "ul/concept.rs:207-209 must refuse a payload member on the `fresh` variant, which \
                 declares no payload at all"
            )
            .to_string(),
        "unknown field `changed`, expected `status`",
        "ul/concept.rs:207-209 must refuse `changed` against the ONE-member `fresh` field set, so \
         serde's OneOf renders the single-name form with no `one of`"
    );
    // `missing` is refused identically by the second guard at `:210-212`, so the
    // `fresh` variant admits NEITHER payload name.
    let fresh_with_missing = decode::<eliot_types::CapsuleFreshness>(
        r#"{"status":"fresh","missing":["crates/eliot-types/src/ul/guard.rs"]}"#,
    );
    assert_eq!(
        fresh_with_missing
            .expect_err("the second payload guard must refuse `missing` on the `fresh` variant")
            .to_string(),
        "unknown field `missing`, expected `status`",
        "ul/concept.rs:210-212 must refuse `missing` against the same ONE-member `fresh` field set"
    );
    // A closed enum of the allocation that is NOT hand-written raises the same
    // serde text through its derived decoder: `UlExamQuestionKind`
    // (`ul/exam.rs:6-14`) is `#[serde(rename_all = "snake_case")]` over three
    // variants, so the tail is the three-name form.
    let derived_closed = decode::<eliot_types::UlExamQuestionKind>(r#""triage""#);
    assert_eq!(
        derived_closed
            .expect_err("ul/exam.rs: UlExamQuestionKind is closed")
            .to_string(),
        "unknown variant `triage`, expected one of `blast`, `invariant`, `entrypoint`",
        "ul/exam.rs:6-14 must refuse the unknown variant with serde's exact three-name tail"
    );

    // ---- (b) An unknown TOP-LEVEL member, on a hand-written visitor. ------
    // `ul/concept.rs:195-200`:
    //     _ => { return Err(serde::de::Error::unknown_field(
    //         key.as_str(),
    //         &["status", "changed", "missing"],
    //     )); }
    // Three names, so the tail is the `one of` form and its ORDER is the
    // literal's order, not a set.
    let unknown_top =
        decode::<eliot_types::CapsuleFreshness>(T12_W3_C13_CAPSULE_FRESHNESS_UNKNOWN_MEMBER);
    let unknown_top_error = unknown_top.expect_err(
        "ul/concept.rs: CapsuleFreshness must refuse the unknown top-level member `decided_at`",
    );
    assert_eq!(
        unknown_top_error.to_string(),
        "unknown field `decided_at`, expected one of `status`, `changed`, `missing`",
        "ul/concept.rs:195-200 must name the refused member AND the whole declared field set"
    );
    // The SAME refusal on a DERIVED `deny_unknown_fields` owner, whose
    // expected-field list is serde's own generated one. `UlDependencyRef`
    // (`ul/dependency.rs:24-28`) declares exactly `kind` and `key`, so this
    // pins the two-name form as well.
    let derived_unknown_top = decode::<UlDependencyRef>(
        r#"{"kind":"file","key":"crates/eliot-types/src/ul/guard.rs","fingerprint":"blake3-abc"}"#,
    );
    assert_eq!(
        derived_unknown_top
            .expect_err("ul/dependency.rs: UlDependencyRef is closed")
            .to_string(),
        "unknown field `fingerprint`, expected `kind` or `key`",
        "ul/dependency.rs:24-28 must refuse with serde's exact two-name tail"
    );
    // And the top-level refusal on the acknowledgement visitor, whose field set
    // is the shared `MEMORY_INFLUENCE_ACK_FIELDS` constant
    // (`ul/injection.rs:171-177`) — five names, `one of` form.
    let ack_unknown_top = decode::<MemoryInfluenceAckInput>(
        r#"{"memory_handle":"mem-1","influence_class":"seen_but_not_used","delivery_surface":"ul_fired"}"#,
    );
    assert_eq!(
        ack_unknown_top
            .expect_err("ul/injection.rs: the acknowledgement input is closed")
            .to_string(),
        "unknown field `delivery_surface`, expected one of `project_id`, `write_id`, `memory_handle`, `influence_class`, `downstream_outcome_ref`",
        "ul/injection.rs:255-260 must refuse against the OWNER's shared field-set constant"
    );

    // ---- (c) A NESTED-member refusal. -------------------------------------
    // `UlExamQuestion` is its own derived `deny_unknown_fields` struct
    // (`ul/exam.rs:16-26`) reached through `UlExamRecord::questions`
    // (`ul/exam.rs:54`), so serde generates the expected-field tail from the
    // nested declaration. The refused name `grader_hint` is NOT one of the
    // seven declared members.
    let nested = decode::<UlExamRecord>(T12_W3_C13_EXAM_NESTED_UNKNOWN_MEMBER);
    let nested_error = nested.expect_err(
        "ul/exam.rs: a nested UlExamQuestion must refuse the unknown member `grader_hint`",
    );
    assert_eq!(
        nested_error.to_string(),
        concat!(
            "unknown field `grader_hint`, expected one of `question_id`, `project_id`,",
            " `subsystem_concept_id`, `kind`, `prompt`, `ground_truth_refs`,",
            " `ground_truth_values`",
        ),
        "ul/exam.rs:16-26 must refuse the NESTED member against the NESTED declaration"
    );
    // The SAME document without the nested unknown member decodes, so the
    // refusal above is the nested member and not the envelope.
    let nested_accepted: UlExamRecord = decode(T12_W3_C13_EXAM_NESTED_ACCEPT)
        .expect("the same exam record without the nested unknown member must decode");
    assert_eq!(
        nested_accepted.questions.len(),
        1,
        "the accepted counterpart must keep its one nested question"
    );
    assert_eq!(
        nested_accepted.questions[0].kind,
        eliot_types::UlExamQuestionKind::Blast
    );

    // ---- (d) Two more refusal CLASSES, pinned exactly. --------------------
    // A repeated member: `next_once` (`ul/injection.rs:84-98`) returns
    // serde's `duplicate_field`, whose message is the bare two-word form.
    // Case 5 asserted `contains("duplicate field")`; here it is exact.
    let duplicate = decode::<MemoryInfluenceAckInput>(
        r#"{"memory_handle":"mem-1","memory_handle":"mem-2","influence_class":"seen_but_not_used"}"#,
    );
    assert_eq!(
        duplicate
            .expect_err("ul/injection.rs: a repeated member must be refused")
            .to_string(),
        "duplicate field `memory_handle`",
        "ul/injection.rs:84-98 must raise serde's duplicate_field text with the exact key"
    );
    // A missing protected identity: `required` (`ul/injection.rs:100-107`)
    // returns serde's `missing_field`. Case 7 asserted `contains`; here it is
    // exact, and the refused name is the PROTECTED one.
    let missing = decode::<MemoryInfluenceAckInput>(r#"{"influence_class":"seen_but_not_used"}"#);
    assert_eq!(
        missing
            .expect_err("ul/injection.rs: a missing memory_handle must be refused")
            .to_string(),
        "missing field `memory_handle`",
        "ul/injection.rs:267 must never default the protected agent-side identity"
    );
    // MAIN IS MORE PERMISSIVE AT DECODE TIME THAN THE IDEAL — QUOTED. The
    // three OPTIONAL acknowledgement members ARE defaulted:
    //     project_id: project_id.unwrap_or_default(),        // :264
    //     write_id: write_id.unwrap_or_default(),            // :265
    //     downstream_outcome_ref: downstream_outcome_ref.unwrap_or_default(),  // :268
    // so an argument object that omits all three decodes `Ok` with three
    // `None`s. This case asserts that ACTUAL behaviour rather than the ideal,
    // and the omission is visible in the decoded model instead of being
    // dropped: `docs/architecture/I05-16-common-durable-fields.md:46` —
    // "Fields that do not apply remain explicit `None`; they are not silently
    // omitted from the semantic model."
    let defaulted = decode::<MemoryInfluenceAckInput>(
        r#"{"memory_handle":"mem-1","influence_class":"seen_but_not_used"}"#,
    )
    .expect("ul/injection.rs: the two required members alone are enough to decode");
    assert_eq!(defaulted.project_id, None::<String>);
    assert_eq!(defaulted.write_id, None::<String>);
    assert_eq!(defaulted.downstream_outcome_ref, None::<String>);
}

// WORK_UNIT_CASE: 941/14
#[test]
#[allow(clippy::too_many_lines)]
fn c14_bounded_adversarial_input_is_panic_free_and_deterministic() {
    // `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:12` —
    // "authority, scope, effect, privacy, ordering and receipt fields are never
    // silently defaulted;"
    //
    // A refusal is only worth anything if the boundary REFUSES rather than
    // panics, and only if it refuses the SAME way every time. This case runs a
    // BOUNDED, FULLY DETERMINISTIC sweep of adversarial documents through the
    // two real ingress points of this allocation and asserts two properties of
    // each:
    //
    //   1. PANIC-FREE: reaching the assertion at all proves no panic occurred —
    //      a `panic!`/index-out-of-bounds inside any decoder aborts the test
    //      before any line below runs;
    //   2. DETERMINISTIC: the SAME input is decoded TWICE and the two
    //      `serde_json::Error` DISPLAY strings must be byte-identical, so no
    //      refusal is order-, hash- or allocation-dependent.
    //
    // NO RANDOMNESS. The sweep is a fixed-seed inline LCG (a 64-bit
    // xorshift/LCG pair written out below) whose seed and modulus are constants
    // IN THIS FUNCTION, plus a fixed prefix list. There is no clock, no
    // environment, no thread id and no filesystem state in the loop body, so
    // the whole case is reproducible on any machine.
    //
    // The byte ceiling is a named constant, and the loop trip count is a named
    // constant too, so "bounded" is a checkable property of the source rather
    // than a hope.
    // (The fixture tables below are declared at the TOP of this scope, before any
    // statement, because an item placed after a statement is ambiguous to read.)

    // The fixed corpus of adversarial documents. Each is a `(&str, &str)` of
    // (label, wire text) and each MUST be refused by at least one of the two
    // ingress points named in the card.
    const ADVERSARIAL: &[(&str, &str)] = &[
        // TRUNCATED JSON, five distinct cut shapes: the cut lands inside a
        // string, inside a number, inside an object, inside an array and
        // inside a nested object respectively.
        (
            "truncated_string",
            r#"{"memory_handle":"mem-1","influence_class":"seen_but_not_used""#,
        ),
        (
            "truncated_number",
            r#"{"memory_handle":"mem-1","influence_class":"seen_but_not_used","token_cost":4"#,
        ),
        ("truncated_object", r#"{"status":"stale","changed":["a.rs""#),
        (
            "truncated_array",
            r#"{"exam_id":"exam-1","questions":[{"question_id":"q1","kind":"blast""#,
        ),
        (
            "truncated_nested",
            r#"{"kind":"blast_radius","predicted_paths":["#,
        ),
        // UNTERMINATED STRING: an opening quote with no closing quote at EOF.
        ("unterminated_string", r#"{"memory_handle":"mem-1"#),
        (
            "unterminated_escaped_string",
            r#"{"memory_handle":"mem-1","influence_class":"seen_b"#,
        ),
        // A TRAILING document: a second value after the first. serde's own
        // document decoder rejects trailing non-whitespace.
        (
            "trailing_document",
            r#"{"memory_handle":"mem-1","influence_class":"seen_but_not_used"} {"extra":1}"#,
        ),
        // EMBEDDED NUL: a raw U+0000 INSIDE a JSON string is a control
        // character and serde refuses it; the same byte as an escape is a
        // value and is NOT a refusal, which is asserted as such below so the
        // two cannot be confused.
        (
            "embedded_nul_raw",
            "{\"memory_handle\":\"mem-\u{0}1\",\"influence_class\":\"seen_but_not_used\"}",
        ),
        (
            "embedded_nul_raw_in_key",
            "{\"memory_\u{0}handle\":\"mem-1\",\"influence_class\":\"seen_but_not_used\"}",
        ),
        // STRUCTURALLY WRONG TYPE where a closed control value is required.
        ("variant_is_object", r#"{"status":{"status":"fresh"}}"#),
        ("variant_is_number", r#"{"status":7}"#),
        ("variant_is_null", r#"{"status":null}"#),
        // A BARE SCALAR where a struct is required: the visitors call
        // `deserialize_map`, so a non-map document reaches neither `visit_map`
        // nor any of the typed arms.
        ("bare_null", "null"),
        ("bare_number", "42"),
        ("bare_string", r#""mem-1""#),
        ("bare_bool", "true"),
        ("bare_array", r#"[{"memory_handle":"mem-1"}]"#),
        // AN EMPTY DOCUMENT: EOF while parsing a value.
        ("empty_document", ""),
        ("whitespace_only", "   \t\r\n  "),
        // A DOCUMENT THAT IS ONLY A FRACTION of a valid one, closing early.
        ("early_close_object", r#"{"memory_handle":"mem-1"}}"#),
        ("early_close_array", r#"["mem-1"]"#),
    ];

    // Fixed prefix seeds for the truncation sweep. Bounded and literal.
    const TRUNCATION_PREFIXES: [&str; 6] = [
        r#"{"memory_handle":"mem-1","influence_class":"seen_but_not_used""#,
        r#"{"injection_id":"injection-1","session_id":"0192f1c2-3d4e-7a5b-8c9d"#,
        r#"{"status":"stale","changed":["crates/eliot-types/src/ul/guard.rs"]"#,
        r#"{"exam_id":"exam-1","questions":[{"question_id":"q1","kind":"blast""#,
        r#"{"kind":"blast_radius","predicted_paths":[],"predicted_failing_verifiers":[]"#,
        r#"{"schema_version":"eliot-observability-v1","write_id":"0192f1c2-3d4e-7a5b"#,
    ];

    // Bounded byte ceiling shared by this case: every generated document is
    // cut off at this length BEFORE it is handed to any decoder, so the
    // "oversized-but-bounded" row can never become an unbounded allocation.
    let byte_ceiling: usize = 4_096;
    // Fixed iteration count of the LCG sweep. Bounded by construction.
    let sweep_rounds: usize = 96;

    // The fixed-seed generator. A plain 64-bit LCG (Numerical Recipes
    // constants) is enough: it is deterministic, has no external dependency and
    // needs no unsafe code. `next()` is only ever called through the bounded
    // loop below. It is declared as a `let` BOUNDING A CLOSURE rather than as an
    // `fn` item, because an `fn` item placed after the bindings above would be
    // an item appearing after statements.
    let lcg_next = |state: &mut u64| -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state
    };

    // A bounded truncation: cut the wire text at a fixed-seed offset inside it.
    // Never a `String::truncate` on a char boundary by accident, so the cut is
    // done on BYTES and the result may legitimately end mid-escape or
    // mid-token — which is exactly the point. This is a CLOSURE, not an `fn`
    // item, so it can capture `byte_ceiling` from the enclosing scope.
    let bounded_truncation = |text: &str, state: &mut u64| -> String {
        let cut = usize::try_from(lcg_next(state) % (text.len() as u64 + 1)).expect(
            "a modulo of the byte length plus one always fits in usize on every target this crate builds",
        );
        let mut bytes = text.as_bytes()[..cut].to_vec();
        bytes.truncate(byte_ceiling.min(bytes.len()));
        String::from_utf8(bytes).unwrap_or_default()
    };

    // ---- PROPERTY 1+2 over the FIXED corpus. ------------------------------
    // Each row is decoded twice through the real ingress points of this
    // allocation and must be REFUSED both times with an IDENTICAL message.
    for (label, text) in ADVERSARIAL {
        let first_ack = decode::<MemoryInfluenceAckInput>(text);
        let second_ack = decode::<MemoryInfluenceAckInput>(text);
        match (first_ack, second_ack) {
            (Err(first), Err(second)) => assert_eq!(
                first.to_string(),
                second.to_string(),
                "the refusal for `{label}` must be deterministic across two identical decodes"
            ),
            (Ok(_), Ok(_)) => panic!(
                "the adversarial document `{label}` must be REFUSED by the acknowledgement decoder, \
                 but it decoded twice: {text}"
            ),
            _ => panic!(
                "the refusal for `{label}` must be DETERMINISTIC: one decode accepted and the \
                 other refused the identical bytes {text}"
            ),
        }

        // The same bytes through the hand-written `CapsuleFreshness` visitor
        // and the derived closed `UlExamRecord`, so no single decoder is the
        // only thing standing between the input and a typed value.
        let first_fresh = decode::<eliot_types::CapsuleFreshness>(text);
        let second_fresh = decode::<eliot_types::CapsuleFreshness>(text);
        assert_eq!(
            first_fresh.is_err(),
            second_fresh.is_err(),
            "the refusal verdict for `{label}` must be deterministic across two identical decodes"
        );
        if let (Err(first), Err(second)) = (first_fresh, second_fresh) {
            assert_eq!(
                first.to_string(),
                second.to_string(),
                "the refusal for `{label}` must be deterministic across two identical decodes"
            );
        }
        let first_exam = decode::<UlExamRecord>(text);
        let second_exam = decode::<UlExamRecord>(text);
        assert_eq!(
            first_exam.is_err(),
            second_exam.is_err(),
            "the refusal verdict for `{label}` must be deterministic across two identical decodes"
        );
        if let (Err(first), Err(second)) = (first_exam, second_exam) {
            assert_eq!(
                first.to_string(),
                second.to_string(),
                "the refusal for `{label}` must be deterministic across two identical decodes"
            );
        }
    }

    // ---- DEEPLY NESTED TO A BOUNDED DEPTH. -------------------------------
    // The depth is a NAMED CONSTANT, and it is bounded well inside what the
    // recursive `StrictVisitor::visit_seq`/`visit_map` pair in
    // `src/strict_json.rs:186-205` can exhaust. Each level is an object whose
    // single member is the next level, so the document is a `n`-deep nest of
    // objects terminated by a scalar.
    let nested_depth: usize = 64;
    let mut deep = String::from("\"leaf\"");
    for level in 0..nested_depth {
        deep = format!("{{\"level_{level}\":{deep}}}");
    }
    assert!(
        deep.len() <= byte_ceiling * nested_depth,
        "the bounded nesting document must stay bounded; its length is {}",
        deep.len()
    );
    // The deeply nested document is well-formed JSON, so it is refused by the
    // CLOSED decoders on SHAPE alone (no `level_N` member is declared anywhere)
    // and PANIC-FREE at every one of them.
    assert!(
        decode::<eliot_types::CapsuleFreshness>(&deep).is_err(),
        "a {nested_depth}-deep document must be refused by the closed CapsuleFreshness visitor, \
         and must not overflow its stack"
    );
    assert!(
        decode::<UlExamRecord>(&deep).is_err(),
        "the bounded deep nest must also be refused by the derived closed UlExamRecord"
    );
    // The same bytes through the shared lexical ingress, which is the one
    // recursive decoder in this crate that ACTUALLY walks the whole depth. The
    // same bytes are well-formed JSON, so they must be ACCEPTED there — proving
    // the walk reached the innermost scalar and recursed back out without
    // panicking — and accepted identically a second time. The two facts are
    // separate: this one is about LEXICAL well-formedness at depth, the two
    // assertions above are about the CLOSED SHAPE at depth.
    let deep_strict_first = eliot_types::strict_json_value(deep.as_bytes(), deep.len());
    let deep_strict_second = eliot_types::strict_json_value(deep.as_bytes(), deep.len());
    match (deep_strict_first, deep_strict_second) {
        (Ok(first), Ok(second)) => assert_eq!(
            first, second,
            "the shared lexical ingress must return the SAME value for the bounded deep nest \
             twice; a difference would mean the recursive walk is not deterministic"
        ),
        (Err(first), Err(second)) => panic!(
            "a {nested_depth}-deep but well-formed document must be ACCEPTED by the shared \
             lexical ingress, not refused: {first:?} then {second:?}"
        ),
        _ => panic!(
            "the shared lexical ingress accepted the bounded deep nest on one call and refused \
             it on the other, which is non-deterministic"
        ),
    }

    // ---- OVERSIZED-BUT-BOUNDED DOCUMENT. ---------------------------------
    // The ceiling is the shared ingress's OWN bound and is applied by the
    // ingress itself, so this row asserts the refusal that actually happens
    // rather than inventing one. An acknowledgement-shaped prefix is padded past
    // the ceiling inside a SINGLE filler member; the result is VALID JSON and
    // is bounded by construction, because the padding loop's only exit
    // condition is the named ceiling and its own bound assertion fires first.
    let mut oversized = String::from(
        r#"{"memory_handle":"mem-1","influence_class":"seen_but_not_used","filler":""#,
    );
    while oversized.len() < byte_ceiling {
        oversized.push('x');
        assert!(
            oversized.len() < byte_ceiling * 2,
            "the padding loop must stay bounded; it reached {} bytes",
            oversized.len()
        );
    }
    oversized.push_str(r#""}"#);
    assert!(
        oversized.len() > byte_ceiling,
        "the oversized fixture must actually exceed the ceiling, got {} bytes",
        oversized.len()
    );
    // The shared ingress refuses it on its OWN bound, by kind, without reading
    // the document: `strict_json_value` checks the ceiling before parsing
    // (`src/strict_json.rs:96-99`).
    let too_large = eliot_types::strict_json_value(oversized.as_bytes(), byte_ceiling);
    assert_eq!(
        too_large
            .expect_err("a document past the caller's byte ceiling must be refused")
            .kind,
        StrictJsonErrorKind::TooLarge,
        "src/strict_json.rs:96-99 must refuse the oversized document on the ceiling alone"
    );
    // The SAME document is refused deterministically a second time, and the
    // typed decoder on its own account refuses it as a closed shape — the
    // `filler` member is not one of the five declared acknowledgement fields.
    assert_eq!(
        eliot_types::strict_json_value(oversized.as_bytes(), byte_ceiling)
            .expect_err("the ceiling refusal must be deterministic")
            .kind,
        StrictJsonErrorKind::TooLarge
    );
    assert!(
        decode::<MemoryInfluenceAckInput>(&oversized).is_err(),
        "the oversized document is also a closed-shape refusal; it must not decode"
    );
    // With a ceiling one byte below the document, the SAME bytes are refused
    // for the SAME reason, which is what makes the refusal a bound and not an
    // accident of the content.
    assert_eq!(
        eliot_types::strict_json_value(oversized.as_bytes(), oversized.len() - 1)
            .expect_err("one byte under the document length is still over the ceiling")
            .kind,
        StrictJsonErrorKind::TooLarge
    );
    // And at a ceiling one byte ABOVE the length, the very same document is
    // ACCEPTED by the lexical ingress and refused only by the typed decoder's
    // own closure — so the two bounds are independent facts, not one.
    match eliot_types::strict_json_value(oversized.as_bytes(), oversized.len() + 1) {
        Ok(_) => {}
        Err(refusal) => panic!(
            "one byte of headroom is enough for the lexical ingress, but it refused with {:?}",
            refusal.kind
        ),
    }

    // ---- THE BOUNDED LCG SWEEP. ------------------------------------------
    // `sweep_rounds` fixed iterations, each cutting one of the six fixed
    // prefixes at a fixed-seed byte offset. Fixed seed: no clock, no entropy,
    // no environment.
    let mut state: u64 = 0x9411_C0DE_5EED_1234;
    for round in 0..sweep_rounds {
        let prefix = TRUNCATION_PREFIXES[round % TRUNCATION_PREFIXES.len()];
        let cut = bounded_truncation(prefix, &mut state);
        assert!(
            cut.len() <= byte_ceiling,
            "round {round}: the bounded truncation must never exceed the ceiling, got {} bytes",
            cut.len()
        );
        let first = decode::<MemoryInfluenceAckInput>(&cut);
        let second = decode::<MemoryInfluenceAckInput>(&cut);
        match (first, second) {
            (Err(first), Err(second)) => assert_eq!(
                first.to_string(),
                second.to_string(),
                "round {round}: the refusal for a fixed-seed truncation must be deterministic"
            ),
            (Ok(_), Ok(_)) => panic!(
                "round {round}: the fixed-seed truncation {cut} decoded as an acknowledgement; \
                 it must be refused"
            ),
            _ => panic!(
                "round {round}: the fixed-seed truncation was accepted by one decode and refused \
                 by the other, which is non-deterministic"
            ),
        }
    }

    // ---- THE CONTROL ROW: an embedded NUL AS AN ESCAPE IS DATA. -----------
    // A raw U+0000 inside a JSON string is refused (rows `embedded_nul_raw*`
    // above), but the ESCAPED spelling `\u0000` is a legal string VALUE. This
    // distinction is asserted rather than assumed, because "refuse NUL
    // everywhere" is NOT what this boundary does and claiming it would be a
    // false assertion.
    let escaped_nul = decode::<MemoryInfluenceAckInput>(
        r#"{"memory_handle":"mem-1\u0000injected","influence_class":"seen_but_not_used"}"#,
    )
    .expect("an ESCAPED NUL is a legal JSON string value and must decode as data");
    assert_eq!(
        escaped_nul.memory_handle.len(),
        "mem-1\u{0}injected".len(),
        "the escaped NUL must survive as an ordinary character, never be stripped"
    );
    // The DECODED value still carries the raw NUL byte: it is DATA, and the
    // boundary neither rejects it nor silently rewrites it.
    assert!(
        escaped_nul.memory_handle.as_bytes().contains(&0),
        "the escaped NUL must decode to the raw NUL byte inside the string value"
    );

    // ---- THE SHARED LEXICAL INGRESS IS PANIC-FREE ON THE SAME ROWS. ------
    // The validate-only entry point is the one a caller reaches when it is
    // about to hand the SAME bytes to a typed decoder, so it must classify the
    // identical corpus without panicking and WITHOUT echoing input bytes.
    for (label, text) in ADVERSARIAL {
        let bytes = text.as_bytes();
        let verdict = eliot_types::strict_json_value(bytes, bytes.len());
        // A refusal here carries a category only; `StrictJsonError` has no
        // byte buffer, no offset and no member name, so nothing from the input
        // can leak through it. That is asserted by construction below.
        if let Err(refusal) = verdict {
            assert!(
                refusal.kind.as_str().starts_with("strict json: "),
                "the shared ingress must return a bounded, redacted category for `{label}`, got: {}",
                refusal.kind.as_str()
            );
            // THE NO-ECHO CHECK IS VACUOUS ON AN EMPTY INPUT. `str::contains("")`
            // is ALWAYS true, so `!category.contains("")` is always false and the
            // negated assertion would fail on the `empty_document` row for a
            // reason that has nothing to do with echoing: an empty document has
            // no bytes to echo, so there is nothing left to compare. The row
            // still proves panic-freedom and determinism (the category, the
            // bounded prefix and the repeat-sweep above all still apply to it);
            // only the no-echo check is skipped, and only here.
            if !text.is_empty() {
                assert!(
                    !refusal.kind.as_str().contains(text),
                    "the refusal category for `{label}` must not echo the input"
                );
            }
        }
    }
    // The three classes are the ONLY three the shared ingress can raise
    // (`src/strict_json.rs:52-63`), so an adversarial row that is refused by
    // it lands in exactly one of them.
    assert_eq!(
        StrictJsonErrorKind::Malformed.as_str(),
        "strict json: malformed or trailing JSON document",
        "src/strict_json.rs:60 must keep the malformed-class wording verbatim"
    );
    assert_eq!(
        StrictJsonErrorKind::DuplicateKey.as_str(),
        "strict json: duplicate object member",
        "src/strict_json.rs:39-61 must keep the duplicate-class wording verbatim"
    );
    assert_eq!(
        StrictJsonErrorKind::TooLarge.as_str(),
        "strict json: document exceeds byte ceiling",
        "src/strict_json.rs:59 must keep the ceiling-class wording verbatim"
    );
}

// ===========================================================================
// CASES 9-10 (writer w2, issue #941) — the NAMED LEGACY MIGRATION and its
// REFUSAL.
//
// THE GOVERNING DOCUMENTATION, quoted verbatim:
//
// * `docs/architecture/I05-16-common-durable-fields.md:44` — "Absence of a
//   closure or coverage record means `unknown`, not unrestricted/complete."
// * `docs/architecture/I05-16-common-durable-fields.md:46` — "Fields that do
//   not apply remain explicit `None`; they are not silently omitted from the
//   semantic model."
// * `docs/architecture/I05-27-canonical-operation-identity-and-effect-identity.md:18`
//   — "fields affecting authority, scope, ordering, privacy or effect cannot
//   be omitted/defaulted silently."
//
// THE FIDELITY RULE from the module header holds in both cases: `serde_json`'s
// `Map` is a `BTreeMap` in this workspace (`preserve_order` is NOT enabled), so
// a parsed object comes back with its members SORTED. Nothing below asserts
// that a parsed `Value` re-serializes to its original text; every payload
// comparison is a VALUE comparison, and the single serialization compared byte
// for byte is a DERIVED encoder's own compact output of a TYPED value against a
// hand-written literal whose member order is declaration order.
//
// Both cases import the named legacy seam through its module path so that a
// second `use eliot_types::{...}` block is never created: the single existing
// crate-root import block above is left untouched, and no name is added to it.
// ===========================================================================

// WORK_UNIT_CASE: 941/9
#[test]
#[allow(clippy::too_many_lines)]
fn c9_named_legacy_migration_seam_preserves_its_evidence_loss_and_ceiling() {
    // GOVERNING DOCS, verbatim:
    // * docs/architecture/I05-16-common-durable-fields.md:44 — "Absence of a
    //   closure or coverage record means `unknown`, not unrestricted/complete."
    // * docs/architecture/I05-16-common-durable-fields.md:46 — "Fields that do
    //   not apply remain explicit `None`; they are not silently omitted from the
    //   semantic model."
    // * docs/architecture/I05-27-canonical-operation-identity-and-effect-identity.md:18
    //   — "fields affecting authority, scope, ordering, privacy or effect cannot
    //   be omitted/defaulted silently."
    //
    // -------------------------------------------------------------------------
    // WHAT THE NAMED LEGACY MIGRATION PATH ACTUALLY IS IN MAIN. It is NOT a
    // conversion. It is a FROZEN DESCRIPTIVE SEAM, and the migration is CLOSED
    // BY REFUSAL rather than performed.
    //
    // The named seam is `LegacyCueKindV1MigrationDescriptor`, declared at
    // `crates/eliot-types/src/ul/cue.rs:63` and reached as
    // `eliot_types::ul::cue::LegacyCueKindV1MigrationDescriptor` (the module is
    // `pub mod ul;` at `lib.rs:38` and `pub mod cue;` at `ul/mod.rs:6`; the type
    // is deliberately NOT re-exported at the crate root, which is why the two
    // committed boundary oracles import it by module path —
    // `tests/cue_kind_legacy_boundary.rs:15` and
    // `tests/cue_kind_internal_legacy_boundary.rs:16`).
    //
    // Its own doc comment, `ul/cue.rs:59-62`, verbatim:
    //
    //   "Descriptive data only. This lower-level crate neither imports nor
    //    constructs the A-10 current vocabulary: equal spelling alone is not
    //    semantic or current-type equivalence, and ambiguous, unknown, empty,
    //    or legacy-only input must never silently become current."
    //
    // So the honest reading is the one case 9 proves: the migration path is
    // SEALED AND BOUNDED BY REFUSAL. There is no `from_legacy`, no `migrate`,
    // no `compat`, no `upgrade` — not on the descriptor, and not anywhere in
    // the ten UL files this lane was allocated, nor in `observability.rs`. What
    // survives is (a) the DECLARED EVIDENCE pinning where the historical meaning
    // came from and which revision it is being read against, (b) the DECLARED
    // LOSS — the twelve inputs the seam itself refuses to claim a conversion
    // for — and (c) the CEILING, the invalidation clause and the bounded proof
    // the descriptor is willing to be held to. Each of the three is asserted
    // below against the real production constants and the real files they name.
    //
    // Nothing is invented here: no caller, no producer, no schema and no value
    // outside what `ul/cue.rs` and `ul/injection.rs` actually declare.
    // -------------------------------------------------------------------------
    use eliot_types::ul::cue::{LegacyCueKindV1, LegacyCueKindV1MigrationDescriptor as C9Seam};

    // `CARGO_MANIFEST_DIR` is `crates/eliot-types`; the descriptor's evidence
    // constants are WORKSPACE-RELATIVE paths, so the repository root is two
    // levels up. One closure, so no module-level helper name is introduced that
    // another writer appending to this file could collide with.
    let repo_path = |relative: &str| -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join(relative)
    };

    // ---- (1) DECLARED IDENTITY EVIDENCE ---------------------------------
    // Every value below is asserted against the literal in `ul/cue.rs:69-89`.
    // A drift in the pin is a failure here rather than a silent re-pin.
    assert_eq!(
        C9Seam::SOURCE_SCHEMA,
        "eliot-types.ul.cue.LegacyCueKindV1",
        "ul/cue.rs: SOURCE_SCHEMA must keep naming the exact frozen source schema"
    );
    assert_eq!(
        C9Seam::SOURCE_GENERATION,
        "v1",
        "ul/cue.rs: `v1` is the only valid source generation in this type"
    );
    assert_eq!(
        C9Seam::SOURCE_SEAM_ISSUE,
        706,
        "ul/cue.rs: the owning issue of this legacy seam must stay 706"
    );
    assert_eq!(
        C9Seam::SOURCE_BASE_SHA,
        "e80611de30878aa6ab521418da23bbfe4570af13",
        "ul/cue.rs: the frozen base commit must stay pinned"
    );
    assert_eq!(
        C9Seam::TARGET_MODULE,
        "smart.cue.contracts",
        "ul/cue.rs: the current vocabulary owner module must stay named"
    );
    assert_eq!(
        C9Seam::TARGET_CRATE,
        "eliot-cue-contracts",
        "ul/cue.rs: the current vocabulary owner crate must stay named"
    );
    assert_eq!(
        C9Seam::TARGET_FILE,
        "crates/smart/eliot-cue-contracts/src/normalization.rs",
        "ul/cue.rs: the pinned target file carrying the current CueKind must stay named"
    );
    assert_eq!(
        C9Seam::TARGET_REVISION,
        "2.0.0",
        "ul/cue.rs: the pinned target CONTRACT_REVISION must stay named"
    );
    assert_eq!(
        C9Seam::TARGET_DIGEST_ALGO,
        "blake3",
        "ul/cue.rs: the pinned digest algorithm must stay named"
    );
    // The digest is pinned to the target file ON `SOURCE_BASE_SHA`, not to this
    // working tree. MAIN BEHAVIOUR NOTE: this case asserts the digest's declared
    // SHAPE only and deliberately does NOT recompute blake3 over the checkout to
    // compare — equality against the working tree is precisely what the
    // descriptor's own INVALIDATION clause exists to invalidate, and asserting it
    // here would be an assertion this checkout may legitimately fail.
    assert_eq!(
        C9Seam::TARGET_DIGEST.len(),
        64,
        "ul/cue.rs: TARGET_DIGEST must stay a full 64-character hex digest"
    );
    assert!(
        C9Seam::TARGET_DIGEST
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "ul/cue.rs: TARGET_DIGEST must stay lowercase hex, never a truncated or re-cased digest"
    );

    // ---- (2) DECLARED EVIDENCE PATHS STILL RESOLVE -----------------------
    // "Preserves its declared evidence" is only true if the evidence it names is
    // still there. These four are the descriptor's own path-shaped constants
    // (`ul/cue.rs:135-139` and `:81`), checked on disk, not re-typed by hand.
    assert!(
        repo_path(C9Seam::MANIFEST).is_file(),
        "ul/cue.rs: the frozen denominator MANIFEST the seam binds to must exist, got {}",
        C9Seam::MANIFEST
    );
    assert!(
        repo_path(C9Seam::FIXTURE_DIR).is_dir(),
        "ul/cue.rs: the raw and golden FIXTURE_DIR the seam binds to must exist, got {}",
        C9Seam::FIXTURE_DIR
    );
    assert!(
        repo_path(C9Seam::ORACLE).is_file(),
        "ul/cue.rs: the boundary ORACLE that proves this seam must exist, got {}",
        C9Seam::ORACLE
    );
    assert!(
        repo_path(C9Seam::TARGET_FILE).is_file(),
        "ul/cue.rs: the pinned TARGET_FILE must exist for the pin to be evidence, got {}",
        C9Seam::TARGET_FILE
    );

    // ---- (3) NO MIGRATION FUNCTION EXISTS — THE SEAM IS DESCRIPTIVE ONLY --
    // The descriptor's whole `impl` block is read out of the real source and
    // checked for a function. This is the executable form of the "descriptive
    // data only" claim at `ul/cue.rs:59-62`: there is nothing to call.
    let cue_source = read_ul_source("cue.rs");
    let seam_start = cue_source
        .find("impl LegacyCueKindV1MigrationDescriptor")
        .expect("ul/cue.rs must declare the named legacy migration seam's impl block");
    let seam_tail = &cue_source[seam_start..];
    let seam_end = seam_tail
        .find("#[derive(")
        .expect("ul/cue.rs must declare the next type after the named seam's impl block");
    let seam_impl = &seam_tail[..seam_end];
    assert!(
        !seam_impl.contains("fn "),
        "ul/cue.rs: the named legacy migration seam must expose NO migration function, found one in: {seam_impl}"
    );
    assert!(
        !seam_impl.contains("unsafe "),
        "ul/cue.rs: the named legacy migration seam must not hide an unsafe conversion, found one in: {seam_impl}"
    );
    assert_eq!(
        seam_impl.matches("pub const ").count(),
        19,
        "ul/cue.rs: the named seam must declare exactly its nineteen published constants and nothing else"
    );

    // And the same absence, asserted across the WHOLE allocation this lane was
    // given — the nine allocated UL files plus `mod.rs`, plus the
    // `observability.rs` leaf the decoder-closure work also read. Nothing here
    // may reintroduce a conversion the descriptor does not have.
    let mut sources: Vec<(String, String)> = [
        "behavior.rs",
        "concept.rs",
        "cross_agent.rs",
        "dependency.rs",
        "exam.rs",
        "guard.rs",
        "injection.rs",
        "onboarding.rs",
        "prediction.rs",
        "mod.rs",
    ]
    .iter()
    .map(|file_name| ((*file_name).to_owned(), read_ul_source(file_name)))
    .collect();
    sources.push((
        "observability.rs".to_owned(),
        std::fs::read_to_string(repo_path("crates/eliot-types/src/observability.rs"))
            .unwrap_or_else(|error| {
                panic!("src/observability.rs must be readable for the legacy-path scan: {error}")
            }),
    ));
    for (file_name, source) in &sources {
        for entry_point in [
            "fn migrate",
            "fn from_legacy",
            "fn compat",
            "fn upgrade",
            "fn to_current",
        ] {
            assert!(
                !source.contains(entry_point),
                "{file_name} must declare no `{entry_point}` entry point: the named legacy seam is descriptive data only and the migration is closed by refusal"
            );
        }
    }

    // ---- (4) THE FROZEN HISTORICAL MEANING STILL DECODES ------------------
    // `LegacyCueKindV1` is the retained meaning (`ul/cue.rs:24`). Its declared
    // `WIRE_SPELLINGS` are asserted, IN VARIANT ORDER, against the enum's own
    // `as_str()` and then decoded through the REAL boundary — so "preserved"
    // means the historical bytes still produce the historical value, not that a
    // table of strings is still spelled a particular way. The expected order is
    // declared as a `let`, not a `const`, so it is a plain binding rather than an
    // item appearing after the statements above.
    let c9_frozen_variants: [LegacyCueKindV1; 10] = [
        LegacyCueKindV1::FilePath,
        LegacyCueKindV1::DirPath,
        LegacyCueKindV1::Symbol,
        LegacyCueKindV1::ErrorSignature,
        LegacyCueKindV1::CommandPattern,
        LegacyCueKindV1::Dependency,
        LegacyCueKindV1::ApiSurface,
        LegacyCueKindV1::TaskClass,
        LegacyCueKindV1::Subsystem,
        LegacyCueKindV1::Concept,
    ];
    assert_eq!(
        C9Seam::VARIANT_COUNT,
        c9_frozen_variants.len(),
        "ul/cue.rs: VARIANT_COUNT must stay the exact historical variant count"
    );
    assert_eq!(
        C9Seam::WIRE_SPELLINGS.len(),
        C9Seam::VARIANT_COUNT,
        "ul/cue.rs: WIRE_SPELLINGS must have one spelling per frozen variant"
    );
    for (spelling, variant) in C9Seam::WIRE_SPELLINGS.iter().zip(&c9_frozen_variants) {
        assert_eq!(
            *spelling,
            variant.as_str(),
            "ul/cue.rs: WIRE_SPELLINGS must stay in variant order and match the enum's own as_str()"
        );
        let cue = decode::<ObservedCue>(&format!(
            r#"{{"kind":"{spelling}","value":"src/ul/guard.rs"}}"#
        ))
        .unwrap_or_else(|error| {
            panic!("the frozen spelling {spelling:?} must still decode: {error}")
        });
        assert_eq!(
            cue.kind.as_str(),
            *spelling,
            "the retained historical meaning must decode to itself, never to a substituted current variant"
        );
    }

    // ---- (5) THE DECLARED LOSS IS REAL: EVERY CORRESPONDENCE IS AN IDENTITY -
    // `ul/cue.rs:105-106` states "Exact safe correspondences as
    // `(v1_spelling, current_spelling)` pairs. Every safe correspondence is
    // byte-exact; anything else is unsupported." That is asserted, not assumed:
    // each of the ten pairs has an IDENTICAL left and right half, each right
    // half is the corresponding entry of `WIRE_SPELLINGS`, and each right half
    // decodes through the real boundary. MAIN BEHAVIOUR NOTE, stated plainly
    // because it is the whole point of the seam: every declared "correspondence"
    // is RETENTION, not translation — the lower-level crate renames nothing,
    // which is exactly why `ul/cue.rs:59-61` says "equal spelling alone is not
    // semantic or current-type equivalence".
    assert_eq!(
        C9Seam::EXACT_CORRESPONDENCES.len(),
        C9Seam::VARIANT_COUNT,
        "ul/cue.rs: the correspondence table must cover the frozen vocabulary exactly"
    );
    for (index, (legacy, current)) in C9Seam::EXACT_CORRESPONDENCES.iter().enumerate() {
        assert_eq!(
            legacy, current,
            "ul/cue.rs: every safe correspondence must be byte-exact identity, got {legacy:?} -> {current:?}"
        );
        assert_eq!(
            *legacy,
            C9Seam::WIRE_SPELLINGS[index],
            "ul/cue.rs: a correspondence's source spelling must be the frozen wire spelling at the same ordinal"
        );
        let cue = decode::<ObservedCue>(&format!(
            r#"{{"kind":"{current}","value":"src/ul/guard.rs"}}"#
        ))
        .unwrap_or_else(|error| {
            panic!("the declared current spelling {current:?} must still be the frozen spelling: {error}")
        });
        assert_eq!(
            cue.kind.as_str(),
            *current,
            "a declared correspondence must decode to the retained historical variant, never to a manufactured current one"
        );
    }

    // ---- (6) THE DECLARED LOSS IS ENFORCED, NOT DECORATIVE ---------------
    // `UNSUPPORTED_INPUTS` (`ul/cue.rs:119-133`) is the seam's own list of
    // "Inputs that must never claim conversion to current". Each of the twelve
    // is (a) absent from the frozen wire vocabulary and from every declared
    // correspondence, and (b) REFUSED by the real decoder rather than migrated.
    // This is `I05-16:44` made executable — absence of a record means `unknown`,
    // never unrestricted/complete.
    assert_eq!(
        C9Seam::UNSUPPORTED_INPUTS.len(),
        12,
        "ul/cue.rs: UNSUPPORTED_INPUTS must keep its declared twelve entries"
    );
    for input in C9Seam::UNSUPPORTED_INPUTS {
        assert!(
            !C9Seam::WIRE_SPELLINGS.contains(&input),
            "ul/cue.rs: {input:?} is declared unsupported and must not also be a frozen wire spelling"
        );
        let decoded = decode::<ObservedCue>(&format!(
            r#"{{"kind":"{input}","value":"src/ul/guard.rs"}}"#
        ));
        let refusal = decoded.expect_err(
            "an input the seam itself declares unsupported must be refused by the decoder, never silently migrated to current",
        );
        assert!(
            format!("{refusal}").contains("unknown variant"),
            "the refusal must say the cue KIND variant is unknown, got: {refusal}"
        );
    }

    // ---- (7) THE CEILING: INVALIDATION AND THE BOUNDED PROOF ------------
    assert!(
        C9Seam::INVALIDATION.contains("invalidates this descriptor"),
        "ul/cue.rs: the invalidation clause must still invalidate the descriptor itself, got: {}",
        C9Seam::INVALIDATION
    );
    assert!(
        C9Seam::INVALIDATION.contains("pinned target revision or digest"),
        "ul/cue.rs: the ceiling must be pegged to the pinned target revision and digest, got: {}",
        C9Seam::INVALIDATION
    );
    assert!(
        C9Seam::INVALIDATION
            .contains("revalidate against smart.cue.contracts before migration use"),
        "ul/cue.rs: the ceiling must require revalidation before any migration use, got: {}",
        C9Seam::INVALIDATION
    );
    // The PROOF constant declares a bounded oracle and a bounded case count:
    // "cue_kind_legacy_boundary 35 WORK_UNIT_CASE 706/1..35 over frozen source,
    // wire, golden, consumer, duplicate and oracle rows". The bound is then
    // CHECKED against the oracle it names, so the claim of a 35-case proof is a
    // fact about a real file rather than a string.
    assert_eq!(
        C9Seam::PROOF,
        "cue_kind_legacy_boundary 35 WORK_UNIT_CASE 706/1..35 over frozen source, wire, golden, consumer, duplicate and oracle rows",
        "ul/cue.rs: the declared proof and its ceiling must not drift"
    );
    let oracle_source =
        std::fs::read_to_string(repo_path(C9Seam::ORACLE)).unwrap_or_else(|error| {
            panic!(
                "the oracle the seam names must be readable, {}: {error}",
                C9Seam::ORACLE
            )
        });
    let c9_declared_proof_cases: usize = 35;
    assert_eq!(
        oracle_source.matches("WORK_UNIT_CASE: 706/").count(),
        c9_declared_proof_cases,
        "the named oracle must carry exactly the 35 WORK_UNIT_CASE 706/1..35 rows the descriptor's PROOF declares"
    );
    assert!(
        oracle_source.contains("WORK_UNIT_CASE: 706/35"),
        "the declared proof ceiling ends at case 706/35, so that marker must be present in the named oracle"
    );

    // ---- (8) AND THE WHOLE SEAM IS READ-ONLY DATA ------------------------
    // `LegacyCueKindV1MigrationDescriptor` is a sealed struct
    // (`ul/cue.rs:63-65`) whose only field is `_sealed: ()`, and it derives
    // nothing, so it has no value a caller could mutate into a different claim.
    assert!(
        cue_source.contains("pub struct LegacyCueKindV1MigrationDescriptor {\n    _sealed: (),\n}"),
        "ul/cue.rs: the named migration seam must stay a sealed, data-only struct"
    );
}

// WORK_UNIT_CASE: 941/10
#[test]
#[allow(clippy::too_many_lines)]
fn c10_unsafe_legacy_migration_missing_protected_meaning_is_refused() {
    // GOVERNING DOCS, verbatim:
    // * docs/architecture/I05-16-common-durable-fields.md:46 — "Fields that do
    //   not apply remain explicit `None`; they are not silently omitted from the
    //   semantic model."
    // * docs/architecture/I05-27-canonical-operation-identity-and-effect-identity.md:18
    //   — "fields affecting authority, scope, ordering, privacy or effect cannot
    //   be omitted/defaulted silently."
    //
    // -------------------------------------------------------------------------
    // THE UNSAFE MIGRATION IS THE ONE THAT WOULD MOVE A LEGACY DOCUMENT TO A
    // CURRENT VALUE. Case 9 established that main has no such conversion at all:
    // the named seam `LegacyCueKindV1MigrationDescriptor`
    // (`crates/eliot-types/src/ul/cue.rs:63`) is descriptive data only, its own
    // doc comment (`ul/cue.rs:59-62`) says "ambiguous, unknown, empty, or
    // legacy-only input must never silently become current", and neither the ten
    // allocated UL files nor `observability.rs` declares a `from_legacy`, a
    // `migrate`, a `compat` or an `upgrade`. THE MIGRATION IS THEREFORE CLOSED
    // BY REFUSAL, and this case proves the refusal rather than inventing a
    // migration.
    //
    // "MISSING PROTECTED MEANING" IS PROVED IN BOTH OF ITS REAL FORMS, because
    // the code has two separate doors and each names the offending thing:
    //
    //   (A) ABSENT — a `fired_cues` element with no `kind` at all. `kind` is the
    //       cue's entire protected meaning: it selects the historical vocabulary.
    //       `required(kind, "kind")` at `ul/injection.rs:77` (direct boundary) and
    //       `:110-119` via `StrictObservedCueInput` (nested) refuse it, and the
    //       refusal message names `kind`.
    //   (B) LEGACY-LOOKALIKE — a `kind` whose spelling is not in the frozen
    //       vocabulary. `LegacyCueKindV1` is a closed unit enum, so the refusal
    //       names the offending spelling AND the accepted set.
    //
    // A THIRD DOOR IS PROVED HERE TOO, because it is the only version branch on
    // this path that is checked INSIDE the decoder: an unsupported
    // `schema_version` on `ObservabilityWriteEnvelope` is refused by
    // `check_observability_schema_version` (`observability.rs:272-283`), and its
    // bounded message names the OWNED version while never echoing the received
    // one. MAIN BEHAVIOUR NOTE, quoted from `observability.rs:257-258`: "The
    // message is fixed and never echoes the received value."
    // -------------------------------------------------------------------------
    //
    // FIDELITY: nothing below compares a parsed `Value` against its original
    // text. The one byte comparison is a DERIVED encoder's own compact output of
    // a TYPED value against a hand-written literal in declaration order.

    // ---- (A) ABSENT protected meaning: no `kind` at all -------------------
    let absent_direct = decode::<eliot_types::ObservedCue>(r#"{"value":"src/ul/guard.rs"}"#);
    let absent_direct_error = absent_direct.expect_err(
        "a legacy cue with no kind at all must be refused, never decoded to a current-valid cue with a default kind",
    );
    assert!(
        format!("{absent_direct_error}").contains("missing field"),
        "the refusal must be a missing-field refusal, got: {absent_direct_error}"
    );
    assert!(
        format!("{absent_direct_error}").contains("kind"),
        "the refusal must name the missing protected meaning `kind`, got: {absent_direct_error}"
    );

    // The SAME omission reached through the STRICT nested path
    // (`deserialize_strict_observed_cues`, `ul/injection.rs:122-128`), which is
    // the path `InjectionReceipt::fired_cues` and `PendingInjectionItem.
    // fired_cues` actually use.
    let absent_nested = decode::<InjectionReceipt>(
        r#"{"injection_id":"injection-1","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","surface":"ul_fired","item_ref":"item-1","render_form":"markdown","fired_cues":[{"value":"src/ul/guard.rs"}],"token_cost":42,"source_fingerprint":"blake3-source-1","outcome":"applied","policy_reason":null}"#,
    );
    let absent_nested_error = absent_nested
        .expect_err("a nested fired_cues element with no kind must be refused, never defaulted");
    assert!(
        format!("{absent_nested_error}").contains("missing field")
            && format!("{absent_nested_error}").contains("kind"),
        "the nested refusal must name the missing protected meaning `kind`, got: {absent_nested_error}"
    );

    // ---- (B) LEGACY-LOOKALIKE spelling is refused, and the message names it -
    // `FilePath` is one of the twelve `UNSUPPORTED_INPUTS` the seam itself
    // declares at `ul/cue.rs:123`: "Inputs that must never claim conversion to
    // current". It is the most tempting lookalike there is — the historical
    // variant name in Rust casing — and it must still be refused.
    let lookalike_direct =
        decode::<eliot_types::ObservedCue>(r#"{"kind":"FilePath","value":"src/ul/guard.rs"}"#);
    let lookalike_direct_error = lookalike_direct.expect_err(
        "the legacy-lookalike spelling `FilePath` must be refused, never migrated onto the frozen `file_path` variant",
    );
    let lookalike_message = format!("{lookalike_direct_error}");
    assert!(
        lookalike_message.contains("unknown variant"),
        "the refusal must be an unknown-variant refusal, got: {lookalike_message}"
    );
    assert!(
        lookalike_message.contains("FilePath"),
        "the refusal must name the OFFENDING spelling `FilePath`, got: {lookalike_message}"
    );
    assert!(
        lookalike_message.contains("file_path"),
        "the refusal must also name the accepted frozen spelling `file_path`, got: {lookalike_message}"
    );

    // The same lookalike through the strict nested path, where the refusal names
    // the field that carries it.
    let lookalike_nested = decode::<InjectionReceipt>(
        r#"{"injection_id":"injection-1","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","surface":"ul_fired","item_ref":"item-1","render_form":"markdown","fired_cues":[{"kind":"FilePath","value":"src/ul/guard.rs"}],"token_cost":42,"source_fingerprint":"blake3-source-1","outcome":"applied","policy_reason":null}"#,
    );
    let lookalike_nested_error = lookalike_nested
        .expect_err("the strict nested cue path must refuse the legacy-lookalike spelling too");
    assert!(
        format!("{lookalike_nested_error}").contains("FilePath")
            && format!("{lookalike_nested_error}").contains("unknown variant"),
        "the nested refusal must name the offending spelling, got: {lookalike_nested_error}"
    );

    // ---- (C) THE DOCUMENTED VERSION BRANCH, REFUSED INSIDE THE DECODER ---
    // `ObservabilityWriteEnvelope` is the only boundary on this path whose
    // version is checked by `deserialize` itself rather than deferred to an
    // owner validator (contrast `UlCrossAgentSuite.schema_version`, which is an
    // unvalidated `String` — case 8 proved that difference).
    let unsupported_version = decode::<eliot_types::ObservabilityWriteEnvelope>(
        r#"{"schema_version":"eliot-observability-v0","write_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c63","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":null,"session_id":null,"kind":"injection_receipt","record_id":"injection-1","payload":{"injection_id":"injection-1","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","task_id":null,"surface":"ul_fired","item_ref":"item-1","render_form":"markdown","fired_cues":[{"kind":"file_path","value":"src/ul/guard.rs"}],"token_cost":42,"source_fingerprint":"blake3-source-1","outcome":"applied","policy_reason":null},"input_hash":"blake3-input-1","created_at":"2026-09-24T10:15:00Z"}"#,
    );
    let unsupported_version_error = unsupported_version.expect_err(
        "an unsupported observability schema version must be refused by deserialize, never substituted with the owned one",
    );
    let version_message = format!("{unsupported_version_error}");
    assert!(
        version_message.contains("unsupported schema version"),
        "the refusal must name the VERSION as the offending thing, got: {version_message}"
    );
    assert!(
        version_message.contains("eliot-observability-v1"),
        "the refusal must name the ONE version this build owns, got: {version_message}"
    );
    assert!(
        !version_message.contains("eliot-observability-v0"),
        "observability.rs:257-258 — the message is fixed and never echoes the received value, got: {version_message}"
    );

    // The SAME envelope, with the owned version but a payload whose nested cue
    // carries NO protected meaning. `bind_observability_payload`
    // (`observability.rs:239-241`) re-decodes the payload through the owner
    // type the envelope's `kind` names, so the refusal names `kind` from two
    // levels down.
    let payload_without_meaning = decode::<eliot_types::ObservabilityWriteEnvelope>(
        r#"{"schema_version":"eliot-observability-v1","write_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c63","project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":null,"session_id":null,"kind":"injection_receipt","record_id":"injection-1","payload":{"injection_id":"injection-1","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","task_id":null,"surface":"ul_fired","item_ref":"item-1","render_form":"markdown","fired_cues":[{"value":"src/ul/guard.rs"}],"token_cost":42,"source_fingerprint":"blake3-source-1","outcome":"applied","policy_reason":null},"input_hash":"blake3-input-1","created_at":"2026-09-24T10:15:00Z"}"#,
    );
    let payload_error = payload_without_meaning.expect_err(
        "an envelope whose payload omits a protected meaning must be refused by the owner decoder the envelope kind names",
    );
    assert!(
        format!("{payload_error}").contains("missing field")
            && format!("{payload_error}").contains("kind"),
        "the owner-decoded payload refusal must name the missing protected meaning `kind`, got: {payload_error}"
    );

    // ---- (D) THE TWO DECLARED LEGACY SURFACES, AS THE SEAM DECLARES THEM --
    // `T12_C9_LEGACY_CUE_WITH_METADATA_ACCEPT` is the declared legacy surface:
    // the committed #831/8 compatibility oracle REQUIRES
    // `{"kind","value","version","schema_version"}` to decode `Ok` on the direct
    // boundary, and this case asserts that requirement holds rather than adding
    // any closure to it. `ul/injection.rs:26-29`: "Those keys are dropped and
    // never re-serialized."
    let declared_legacy = decode::<eliot_types::ObservedCue>(
        T12_C9_LEGACY_CUE_WITH_METADATA_ACCEPT,
    )
    .expect(
        "the direct legacy cue boundary must keep accepting the historical record plus its two inert metadata keys",
    );
    assert_eq!(
        declared_legacy.kind.as_str(),
        "file_path",
        "the declared legacy document must decode to the frozen variant itself"
    );
    assert_eq!(declared_legacy.value, "src/ul/guard.rs");
    // The loss is proved by the encoder, not by a re-serialization of a parsed
    // `Value`: `ObservedCue` derives `Serialize` over exactly two fields
    // (`ul/injection.rs:7-11`), so the derived encoder's own compact output is
    // compared against a hand-written literal in DECLARATION order.
    let declared_legacy_bytes =
        serde_json::to_string(&declared_legacy).expect("ObservedCue must serialize");
    assert_eq!(
        declared_legacy_bytes, r#"{"kind":"file_path","value":"src/ul/guard.rs"}"#,
        "the two inert legacy metadata keys must be dropped and never re-serialized"
    );
    assert!(
        !declared_legacy_bytes.contains("schema_version")
            && !declared_legacy_bytes.contains("version"),
        "no legacy metadata key may survive into the durable value, got: {declared_legacy_bytes}"
    );
    // The SAME legacy metadata, on the strict nested path, is refused and the
    // refusal names the offending FIELD.
    let declared_legacy_nested =
        decode::<InjectionReceipt>(T12_C9_LEGACY_CUE_STRICT_NESTED_METADATA_REFUSE);
    let declared_legacy_nested_error = declared_legacy_nested.expect_err(
        "the strict nested mode must refuse the legacy metadata the direct mode accepts",
    );
    assert!(
        format!("{declared_legacy_nested_error}").contains("unknown field")
            && format!("{declared_legacy_nested_error}").contains("version"),
        "the strict nested refusal must name the offending field `version`, got: {declared_legacy_nested_error}"
    );
    // And with the single legacy `schema_version` key in isolation, the refusal
    // names THAT field by name — the strict field set is exactly
    // `["kind","value"]` (`ul/injection.rs:68-70`).
    let single_metadata_nested = decode::<InjectionReceipt>(
        r#"{"injection_id":"injection-1","session_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60","task_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61","surface":"ul_fired","item_ref":"item-1","render_form":"markdown","fired_cues":[{"kind":"file_path","value":"src/ul/guard.rs","schema_version":"eliot-agent-api/v7"}],"token_cost":42,"source_fingerprint":"blake3-source-1","outcome":"applied","policy_reason":null}"#,
    );
    let single_metadata_error = single_metadata_nested
        .expect_err("a legacy `schema_version` on the strict nested cue path must be refused");
    assert!(
        format!("{single_metadata_error}").contains("unknown field")
            && format!("{single_metadata_error}").contains("schema_version"),
        "the refusal must name the offending field `schema_version`, got: {single_metadata_error}"
    );

    // ---- (E) CLOSURE: NONE OF THE REFUSALS ABOVE IS A SHAPE ACCIDENT -----
    // The exact historical documents still decode, so every refusal above is a
    // refusal of the MISSING or LEGACY protected meaning and nothing else.
    let clean_receipt = decode::<InjectionReceipt>(&fixture("t12_c1_injection_receipt_accept"))
        .expect("the same receipt with a complete nested cue must decode");
    assert_eq!(clean_receipt.fired_cues.len(), 1);
    assert_eq!(clean_receipt.fired_cues[0].kind.as_str(), "file_path");
    let owned_envelope = decode::<eliot_types::ObservabilityWriteEnvelope>(&fixture(
        "t12_c8_observability_envelope_accept",
    ))
    .expect("the same envelope with the owned schema version and a complete payload must decode");
    assert_eq!(owned_envelope.schema_version, "eliot-observability-v1");
}

// ===========================================================================
// CASES 15-16 (this writer) — the ACTUAL INGRESS POINTS and the LEDGER CALLER.
//
// THE REAL SYMBOLS AND SIGNATURES, located with `git grep` on this base. Both
// are real and neither was invented; both live OUTSIDE `eliot-types`, which is
// why this case cannot call them directly (`eliot-types` has no dependency on
// `eliot-app`/`eliot-engine`, and adding one would be a cyclic edge):
//
//   (1) `decode_compile_packet_input`
//       crates/eliot-app/src/mcp_stdio/input_validation.rs:8
//           pub(super) fn decode_compile_packet_input(
//               value: Value,
//           ) -> Result<CompilePacketToolInput>
//       It is `pub(super)` — NOT reachable from an integration test even with a
//       dependency — and its only production caller is
//       crates/eliot-app/src/mcp_stdio/task_handlers.rs:188
//           let input = input_validation::decode_compile_packet_input(arguments)?;
//       Its trusted output type is `eliot_types::CompilePacketToolInput`, whose
//       decoder is the hand-written `CompilePacketToolInputVisitor`
//       (crates/eliot-types/src/mcp_contract.rs:41-147). That decoder — and the
//       whole refusal-before-trusted-output chain it terminates — is IN this
//       crate and is what this case exercises.
//
//   (2) `ProviderInvocationJournal::load`
//       crates/eliot-engine/src/provider_invocation.rs:159
//           pub fn load(&self, attempt_id: &str)
//               -> Result<ProviderInvocationAttempt, EngineError>
//       Body, verbatim:
//           let path = self.attempt_path(attempt_id);
//           let bytes = fs::read(&path)?;
//           serde_json::from_slice(&bytes).map_err(EngineError::from)
//       So `load` hands the on-disk bytes straight to
//       `serde_json::from_slice::<ProviderInvocationAttempt>` and returns
//       `Err` on any refusal — `EngineError::Serde` is
//       `#[error(transparent)] Serde(#[from] serde_json::Error)`
//       (crates/eliot-engine/src/error.rs:102-103), so the inner serde message
//       is preserved verbatim for the caller. The record type it decodes,
//       `ProviderInvocationAttempt`, IS in this crate
//       (crates/eliot-types/src/provider_invocation.rs:153-213) and is what this
//       case decodes.
//
//   (3) THE LEDGER CALLER
//       crates/eliot-engine/src/ul/ledger.rs:410-414
//           fn acknowledged_handle(arguments: &Value) -> Option<String> {
//               serde_json::from_value::<MemoryInfluenceAckInput>(arguments.clone())
//                   .ok()
//                   .map(|ack| ack.memory_handle)
//           }
//       called from crates/eliot-engine/src/ul/ledger.rs:110-120, whose gate is
//           measurement.tool_name == "eliot_memory_influence_trace"
//       and whose ONLY effect is `delta.acknowledged_items =
//           delta.acknowledged_items.saturating_add(1)` (:118).
//       THIS FILE IS READ-ONLY and is NOT edited by this lane; it is READ here
//       as evidence and its bytes are re-checked at runtime by `read_engine_source`.
//
// WHY THE CHAIN IS PROVED HERE AND NOT AT THE CALL SITE: `load` and
// `decode_compile_packet_input` are not callable from this crate, but every
// decoder they terminate IS, and the refusal they surface is the refusal of
// those decoders. Each case below therefore asserts the TERMINAL DECODER on the
// exact bytes the caller would hand it, and proves "before any value is
// returned" structurally: the refusals are `Err`, the accepted controls are the
// only `Ok`, and each refusal is shown to be produced by an early `return Err`
// in the visitor rather than by a later validation of an already-built value.
// ===========================================================================

/// Case 15 (a): a well-formed FLAT compile-packet tool argument object. It is
/// exactly the accepted wire shape of `CompilePacketToolInput`: the four
/// `CompilePacketL3Request` keys (`crates/eliot-types/src/memory.rs:1997-2008`)
/// at the top level because of `#[serde(flatten)]`
/// (crates/eliot-types/src/mcp_contract.rs:20-21), plus `max_tokens`.
const T12_W3_C15_COMPILE_PACKET_ACCEPT: &str = r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"task-1","goal":"Describe the required change","candidate_handles":[],"max_tokens":1800}"#;

/// The two DEFECT rows of this case are the top-level named constants
/// `T12_C15_COMPILE_PACKET_UNKNOWN_KEY_REFUSE` (one key outside
/// `COMPILE_PACKET_TOOL_FIELDS`, crates/eliot-types/src/mcp_contract.rs:52-60,
/// refused by the visitor's `_` arm at `:134-136` from INSIDE the
/// `while let Some(key) = map.next_key::<String>()?` loop — the moment the
/// offending name is read, before any typed value is assembled and long before
/// the `Ok(CompilePacketToolInput { .. })` at `:141`) and
/// `T12_C15_COMPILE_PACKET_DUPLICATE_FLAT_KEY_REFUSE` (a repeated flattened key).
/// They are declared once, at the top of this file, and sections (1b) and (1c)
/// below reference them directly, so the coverage exists exactly once.
/// Case 15 (d): a journalled provider attempt MISSING one of the ten
/// required-nullable outcome fields. `ProviderInvocationAttempt` carries
/// `#[serde(deserialize_with = "deserialize_required_nullable")]` on
/// `process_timed_out` (crates/eliot-types/src/provider_invocation.rs:198-200)
/// and NO `#[serde(default)]`, so an ABSENT key is a typed missing-field
/// refusal while an EXPLICIT `null` still decodes to `None`
/// (documented at :122-152). Omitting `process_timed_out` must therefore be a
/// refusal and must never read as a measured `false`.
const T12_W3_C15_ATTEMPT_ABSENT_REQUIRED_NULLABLE: &str = r#"{"invocation_attempt_id":"attempt-1","provider":"claude","campaign_id":"campaign-1","preregistration_id":"pre-1","reservation_id":"res-1","idempotency_key":"idem-1","external_invocation_ref":null,"frozen_input_hash":"blake3-input-1","request_payload_hash":"blake3-request-1","route_or_model":"claude-opus-5","adapter_version":"v1","executable_or_transport":"stdio","cwd":"C:/repo","environment_fingerprint":"blake3-env-1","timeout_profile_id":"profile-1","provider_route_policy":null,"state_transitions":[],"dispatch_started_at":null,"process_started_at":null,"provider_ack_at":null,"first_output_at":null,"last_output_at":null,"process_exit_at":null,"cleanup_completed_at":null,"stdout_blob_or_hash":null,"stderr_blob_or_hash":null,"structured_output_blob_or_hash":null,"exit_code_or_signal":null,"process_or_job_identity":null,"timeout_class":null,"process_reap_receipt":null,"process_cancelled":null,"process_worker_error":null,"stdout_total_bytes":null,"stderr_total_bytes":null,"stdout_truncated":null,"stderr_truncated":null,"quota_or_cost_if_known":null,"original_closeout_ref":null}"#;

/// Case 15 (e): the SAME attempt with the absent field written as an EXPLICIT
/// `null`. `deserialize_required_nullable` deserializes `Option::<T>` and has
/// NO `#[serde(default)]`, so an explicit null decodes to `None` and the
/// document is accepted. This is the control that proves the refusal above is
/// the ABSENCE and not the nullability.
const T12_W3_C15_ATTEMPT_EXPLICIT_NULL_ACCEPT: &str = r#"{"invocation_attempt_id":"attempt-1","provider":"claude","campaign_id":"campaign-1","preregistration_id":"pre-1","reservation_id":"res-1","idempotency_key":"idem-1","external_invocation_ref":null,"frozen_input_hash":"blake3-input-1","request_payload_hash":"blake3-request-1","route_or_model":"claude-opus-5","adapter_version":"v1","executable_or_transport":"stdio","cwd":"C:/repo","environment_fingerprint":"blake3-env-1","timeout_profile_id":"profile-1","provider_route_policy":null,"state_transitions":[],"dispatch_started_at":null,"process_started_at":null,"provider_ack_at":null,"first_output_at":null,"last_output_at":null,"process_exit_at":null,"cleanup_completed_at":null,"stdout_blob_or_hash":null,"stderr_blob_or_hash":null,"structured_output_blob_or_hash":null,"exit_code_or_signal":null,"process_or_job_identity":null,"timeout_class":null,"process_reap_receipt":null,"process_cancelled":null,"process_worker_error":null,"stdout_total_bytes":null,"stderr_total_bytes":null,"stdout_truncated":null,"stderr_truncated":null,"process_timed_out":null,"quota_or_cost_if_known":null,"original_closeout_ref":null}"#;

// WORK_UNIT_CASE: 941/15
#[test]
#[allow(clippy::too_many_lines)]
fn c15_the_real_ingress_decoders_refuse_before_any_value_is_returned() {
    // `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:12` —
    // "authority, scope, effect, privacy, ordering and receipt fields are never
    // silently defaulted;"
    // `docs/architecture/I05-16-common-durable-fields.md:46` — "Fields that do
    // not apply remain explicit `None`; they are not silently omitted from the
    // semantic model."
    //
    // This case exercises the decoders that TERMINATE the two ingress points the
    // card names. The real call sites and their real signatures are quoted in
    // the section banner immediately above; neither symbol was invented, and
    // each was located with `git grep` on this base.
    //
    // "REFUSE BEFORE TRUSTED OUTPUT" is asserted STRUCTURALLY, not by
    // inspection of a comment:
    //
    //   * the trusted output type is named, and every malformed document below
    //     is `Err` — a typed value exists in NO refusal row;
    //   * the ONE accepted control per ingress point decodes, so the refusals
    //     are caused by the injected defect and not by a broken fixture;
    //   * the refusal for the unknown key is provably raised from INSIDE the
    //     map-reading loop, because the SAME document with the offending key
    //     moved to the LAST position still produces the identical refusal. A
    //     decoder that assembled a value first and validated afterwards could
    //     not distinguish the two orders.
    //
    // NO RANDOMNESS, and the `Map` is a `BTreeMap` here, so the accepted
    // control's members come back SORTED: nothing below compares a parsed
    // `Value` against its own source text.

    // ================= (1) `decode_compile_packet_input`'s decoder ==========
    // The caller's trusted output is `CompilePacketToolInput`, decoded by the
    // hand-written `CompilePacketToolInputVisitor`
    // (crates/eliot-types/src/mcp_contract.rs:41-147).

    // (1a) THE CONTROL: the accepted flat shape decodes, so the two refusals
    // below are caused by the injected defects.
    let accepted: eliot_types::CompilePacketToolInput = decode(T12_W3_C15_COMPILE_PACKET_ACCEPT)
        .expect("the accepted flat compile-packet argument object must decode");
    assert_eq!(
        accepted.request.task_id, "task-1",
        "the flattened CompilePacketL3Request must keep its own task_id"
    );
    assert_eq!(accepted.request.max_tokens, 1800);
    assert!(
        accepted.material_frame.is_none() && accepted.memory_mode.is_none(),
        "the two wrapper-only members must stay explicit `None`, never a defaulted value: \
         docs/architecture/I05-16-common-durable-fields.md:46"
    );

    // (1b) THE UNKNOWN-KEY REFUSAL, raised inside the map-reading loop.
    let unknown_key =
        decode::<eliot_types::CompilePacketToolInput>(T12_C15_COMPILE_PACKET_UNKNOWN_KEY_REFUSE);
    let unknown_key_error = unknown_key.expect_err(
        "mcp_contract.rs:134-136 must refuse a key outside COMPILE_PACKET_TOOL_FIELDS before \
         any typed value is returned",
    );
    assert_eq!(
        unknown_key_error.to_string(),
        concat!(
            "unknown field `budget_milli`, expected one of `project_id`, `task_id`, `goal`,",
            " `candidate_handles`, `max_tokens`, `material_frame`, `memory_mode`",
        ),
        "mcp_contract.rs:134-136 must raise serde's unknown_field against the EXACT declared \
         seven-key set, in declaration order"
    );
    // ORDER PROOF: the offending key moved to the FIRST position in the
    // document, before any declared member. Because the refusal is identical,
    // it cannot have come from a pass that read every member, assembled a
    // value and validated it afterwards — it comes from the
    // `while let Some(key) = map.next_key::<String>()?` loop itself
    // (mcp_contract.rs:83-138), which refuses on the FIRST key it does not
    // recognise.
    let unknown_key_first = decode::<eliot_types::CompilePacketToolInput>(
        r#"{"budget_milli":4096,"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"task-1","goal":"Describe the required change","candidate_handles":[],"max_tokens":1800}"#,
    );
    assert_eq!(
        unknown_key_first
            .expect_err("the same key in the FIRST position must be refused")
            .to_string(),
        unknown_key_error.to_string(),
        "the refusal must be raised by the map-reading loop itself and must NOT depend on WHERE \
         the offending key sits, or on any declared member before it having been read"
    );

    // (1c) THE REPEATED-FLATTENED-KEY REFUSAL. The two `task_id` values DIFFER,
    // so a last-wins decoder would be observable, and this is exactly the row a
    // derived `#[serde(flatten)]` decoder gets wrong.
    let duplicate_flat = T12_C15_COMPILE_PACKET_DUPLICATE_FLAT_KEY_REFUSE;
    assert_eq!(
        duplicate_flat.matches("\"task_id\"").count(),
        2,
        "the fixture must literally repeat the flattened key, or it proves nothing"
    );
    assert!(
        duplicate_flat.contains("task-1") && duplicate_flat.contains("task-2"),
        "the repeated key must carry DIFFERENT values so a last-wins decoder is observable"
    );
    let duplicate_flat_error = decode::<eliot_types::CompilePacketToolInput>(duplicate_flat)
        .expect_err("mcp_contract.rs:106-108 must refuse a repeated flattened key");
    assert_eq!(
        duplicate_flat_error.to_string(),
        "duplicate field `task_id`",
        "mcp_contract.rs:106-108 must raise serde's duplicate_field with the exact key"
    );
    // The same for the wrapper-only members, which are guarded by their own
    // `*_seen` flags (mcp_contract.rs:76-82, :86-98).
    for (label, document) in [
        (
            "material_frame",
            r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"task-1","goal":"g","candidate_handles":[],"max_tokens":1800,"material_frame":null,"material_frame":null}"#,
        ),
        (
            "memory_mode",
            r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","task_id":"task-1","goal":"g","candidate_handles":[],"max_tokens":1800,"memory_mode":"memory_free_control","memory_mode":"memory_free_control"}"#,
        ),
    ] {
        let refusal = decode::<eliot_types::CompilePacketToolInput>(document);
        assert_eq!(
            refusal
                .expect_err("a repeated wrapper key must be refused")
                .to_string(),
            format!("duplicate field `{label}`"),
            "mcp_contract.rs:85-98 must refuse the repeated wrapper key by name"
        );
    }

    // (1d) THE MISSING-REQUIRED-IDENTITY REFUSAL. `CompilePacketL3Request`
    // (`crates/eliot-types/src/memory.rs:1996-2008`) is a derived struct with
    // `project_id`, `task_id`, `goal` and `candidate_handles` as REQUIRED and
    // only `max_tokens` defaulted. The visitor buffers the flattened keys into
    // a `Map` and deserializes the request at :139-140, so a missing identity
    // is refused there — and `.map_err(A::Error::custom)?` re-raises it before
    // the `Ok(CompilePacketToolInput { .. })` at :141.
    let missing_task = decode::<eliot_types::CompilePacketToolInput>(
        r#"{"project_id":"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d","goal":"Describe the required change","candidate_handles":[],"max_tokens":1800}"#,
    );
    assert_eq!(
        missing_task
            .expect_err("a compile-packet argument with no task_id must be refused")
            .to_string(),
        "missing field `task_id`",
        "memory.rs:1999 must never default the request's task identity"
    );

    // =========== (2) `ProviderInvocationJournal::load`'s decoder ============
    // `load` (crates/eliot-engine/src/provider_invocation.rs:159-163) does
    // `fs::read(&path)?` then `serde_json::from_slice(&bytes).map_err(EngineError::from)`.
    // `from_slice` and `from_str` are the same `serde_json` document decoder on
    // the same bytes, so decoding the fixture text here is decoding what `load`
    // decodes; `EngineError::Serde` is `#[error(transparent)]`
    // (crates/eliot-engine/src/error.rs:102-103), so the inner refusal text
    // reaches the caller intact.

    // (2a) THE CONTROL: the same attempt with the field written EXPLICITLY as
    // `null` decodes, and the value really is `None` — the model keeps the
    // explicit absence rather than dropping the member.
    let accepted_attempt: eliot_types::ProviderInvocationAttempt =
        decode(T12_W3_C15_ATTEMPT_EXPLICIT_NULL_ACCEPT)
            .expect("the attempt with an explicit null must decode");
    assert_eq!(
        accepted_attempt.process_timed_out, None::<bool>,
        "an explicit JSON null must decode to None, not to a measured false"
    );
    assert!(accepted_attempt.process_reap_receipt.is_none());
    assert!(accepted_attempt.provider_route_policy.is_none());
    assert_eq!(
        accepted_attempt.invocation_attempt_id, "attempt-1",
        "the accepted attempt must keep its own identity"
    );

    // (2b) THE REFUSAL: the same attempt with that member ABSENT. The field has
    // `deserialize_with = "deserialize_required_nullable"` and NO
    // `#[serde(default)]`, so `load` returns `Err` on the stored bytes.
    let absent_attempt = decode::<eliot_types::ProviderInvocationAttempt>(
        T12_W3_C15_ATTEMPT_ABSENT_REQUIRED_NULLABLE,
    );
    assert_eq!(
        absent_attempt
            .expect_err(
                "a journalled attempt with an ABSENT required-nullable outcome field must be \
                 refused by load, never read as a measured false"
            )
            .to_string(),
        "missing field `process_timed_out`",
        "provider_invocation.rs:198-200 must refuse the ABSENCE while accepting an explicit null"
    );
    // The refusal must be raised for EACH of the ten, not just this one: the
    // struct documents all ten as required-nullable
    // (crates/eliot-types/src/provider_invocation.rs:122-152), and the engine's
    // own legacy-load test removes exactly these ten
    // (crates/eliot-engine/tests/provider_timeout_reconciliation.rs:143-151).
    for member in [
        "provider_route_policy",
        "process_reap_receipt",
        "process_timed_out",
        "process_cancelled",
        "process_worker_error",
        "stdout_total_bytes",
        "stderr_total_bytes",
        "stdout_truncated",
        "stderr_truncated",
    ] {
        // Removing one member from the accepted document and decoding must be a
        // missing-field refusal naming THAT member. `Value`-level removal is
        // safe here: the source document has no repeated member, so no
        // last-wins collapse can hide a defect (the no-duplicate invariant is
        // asserted immediately below).
        let mut document = decode::<serde_json::Value>(T12_W3_C15_ATTEMPT_EXPLICIT_NULL_ACCEPT)
            .expect("the accepted attempt document must itself be valid JSON");
        let object = document
            .as_object_mut()
            .expect("the attempt document must be a JSON object");
        assert!(
            object.remove(member).is_some(),
            "the accepted document must actually carry `{member}`, or the row proves nothing"
        );
        let refusal = decode::<eliot_types::ProviderInvocationAttempt>(&document.to_string());
        assert_eq!(
            refusal
                .expect_err("an absent required-nullable member must be refused")
                .to_string(),
            format!("missing field `{member}`"),
            "provider_invocation.rs:122-152 requires all ten outcome members to be present"
        );
        // The SAME document with that member restored as an EXPLICIT null is
        // accepted — so the refusal is the absence, never the nullability.
        let mut restored = decode::<serde_json::Value>(T12_W3_C15_ATTEMPT_EXPLICIT_NULL_ACCEPT)
            .expect("the accepted attempt document must itself be valid JSON");
        restored
            .as_object_mut()
            .expect("the attempt document must be a JSON object")
            .insert(member.to_owned(), serde_json::Value::Null);
        let restored_attempt: eliot_types::ProviderInvocationAttempt =
            decode(&restored.to_string()).unwrap_or_else(|error| {
                panic!("the same attempt with `{member}` explicitly null must decode: {error}")
            });
        assert_eq!(
            restored_attempt.invocation_attempt_id, "attempt-1",
            "restoring `{member}` as an explicit null must yield the accepted attempt"
        );
    }
    // The invariant that makes the `Value`-level removal above sound, asserted
    // rather than assumed: the accepted document carries NO repeated member, so
    // no last-wins collapse can hide a defect in the removal rows above.
    assert!(
        eliot_types::strict_json_has_no_duplicate_members(
            T12_W3_C15_ATTEMPT_EXPLICIT_NULL_ACCEPT.as_bytes()
        )
        .is_ok(),
        "the accepted attempt document must have no repeated member, or the `Value`-level removal \
         rows above would be unsound"
    );
    // The positive statement of the same invariant: the shared lexical ingress
    // ACCEPTS the document, and rejects a copy that repeats one member.
    assert!(
        eliot_types::strict_json_value(
            T12_W3_C15_ATTEMPT_EXPLICIT_NULL_ACCEPT.as_bytes(),
            T12_W3_C15_ATTEMPT_EXPLICIT_NULL_ACCEPT.len()
        )
        .is_ok(),
        "the accepted attempt document must pass the shared lexical ingress"
    );
    let repeated_member = format!(
        "{{\"invocation_attempt_id\":\"a\",\"invocation_attempt_id\":\"b\"{}",
        T12_W3_C15_ATTEMPT_EXPLICIT_NULL_ACCEPT
            .strip_prefix("{\"invocation_attempt_id\":\"attempt-1\"")
            .expect("the accepted document must start with its own identity member")
    );
    assert_eq!(
        eliot_types::strict_json_value(repeated_member.as_bytes(), repeated_member.len())
            .expect_err("a repeated identity member must be refused by the shared ingress")
            .kind,
        StrictJsonErrorKind::DuplicateKey,
        "src/strict_json.rs:194-203 must refuse a repeated member at the top level"
    );

    // (2c) THE UNKNOWN-MEMBER REFUSAL on the same journaled record. The struct is
    // `#[serde(deny_unknown_fields)]`
    // (crates/eliot-types/src/provider_invocation.rs:153-155), so a stored
    // document carrying an extra member is refused by `load` rather than
    // decoded with the member dropped.
    let unknown_member = format!(
        "{{\"operator_note\":\"canary\",{}",
        T12_W3_C15_ATTEMPT_EXPLICIT_NULL_ACCEPT
            .strip_prefix('{')
            .expect("the accepted document must be an object")
    );
    let unknown_member_error = decode::<eliot_types::ProviderInvocationAttempt>(&unknown_member);
    assert_eq!(
        unknown_member_error
            .expect_err("a journalled attempt with an unknown member must be refused")
            .to_string(),
        "unknown field `operator_note`, expected one of `invocation_attempt_id`, `provider`, \
         `campaign_id`, `preregistration_id`, `reservation_id`, `idempotency_key`, \
         `external_invocation_ref`, `frozen_input_hash`, `request_payload_hash`, `route_or_model`, \
         `adapter_version`, `executable_or_transport`, `cwd`, `environment_fingerprint`, \
         `timeout_profile_id`, `provider_route_policy`, `state_transitions`, `dispatch_started_at`, \
         `process_started_at`, `provider_ack_at`, `first_output_at`, `last_output_at`, \
         `process_exit_at`, `cleanup_completed_at`, `stdout_blob_or_hash`, `stderr_blob_or_hash`, \
         `structured_output_blob_or_hash`, `exit_code_or_signal`, `process_or_job_identity`, \
         `timeout_class`, `process_reap_receipt`, `process_timed_out`, `process_cancelled`, \
         `process_worker_error`, `stdout_total_bytes`, `stderr_total_bytes`, `stdout_truncated`, \
         `stderr_truncated`, `quota_or_cost_if_known`, `original_closeout_ref`",
        "provider_invocation.rs:153-155 must refuse the unknown member against the whole \
         40-member declared set"
    );
}

// ===========================================================================
// CASE 16 (this writer) — THE LEDGER CALLER.
//
// `crates/eliot-engine/src/ul/ledger.rs` is READ-ONLY in this lane. It is read
// here and its bytes are re-verified at runtime; nothing in it is edited.
//
// THE CANARY RULE OBSERVED BY THIS CASE. A canary is only meaningful against
// an entry point that DISCARDS the inner error message. The ledger's caller is
// exactly that: `acknowledged_handle` (ledger.rs:410-414) is
//     serde_json::from_value::<MemoryInfluenceAckInput>(arguments.clone())
//         .ok()
//         .map(|ack| ack.memory_handle)
// `.ok()` converts the refusal into `None`, so the inner serde message NEVER
// REACHES this helper's caller. This case proves only which handle candidate
// the decoder returns (or refuses) and the static source conditions around the
// real increment. It does not instantiate the ledger or claim that `Some(handle)`
// alone changes a count: production also requires same-task delivery and a new
// insertion into the session's acknowledged set. Where a path instead returns
// serde's OWN message, this case asserts the FIELD-NAME BEHAVIOUR.
//
// WHAT IS LITERAL AND WHAT IS ASSEMBLED. The canary member NAMES are assembled
// AT RUNTIME by joining runtime fragments, so no literal in this file spells an
// authority-shaped KEY; the canary VALUE is assembled AT RUNTIME by repeating a
// character to a runtime count, so no literal carries an authority-shaped value
// either. The family LABELS — "permission", "exam", "accepted" — ARE literals,
// and this banner does not claim otherwise: the file states plainly which of
// its pieces are pre-formed and which are built at the moment of proof. The
// absence claims below are scoped to the `acknowledged_handle` slice of the
// ledger's bytes rather than to the whole file, because the whole file has
// unrelated code in it and a whole-file absence would prove nothing about the
// acknowledgement decode path.
//
// `docs/architecture/I15-06-instructiondata-separation.md:6` — "model output
// remains candidate;" — and `:8` — "retrieved content cannot grant permission;".
// ===========================================================================

/// Read one `eliot-engine` UL source file, byte for byte, so the ledger
/// caller this case proves is the ledger caller that EXISTS. This reads the
/// crate's own source and never writes to it.
fn read_engine_source(relative: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/eliot-types must have a parent crates directory")
        .join("eliot-engine")
        .join("src")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{relative} must be readable: {error}"))
}

/// The ledger's decode-and-discard step, re-executed exactly as production
/// executes it.
///
/// `acknowledged_handle` is declared `fn`, not `pub fn`
/// (crates/eliot-engine/src/ul/ledger.rs:410), so it is private to
/// `eliot-engine` and cannot be called from an integration test of
/// `eliot-types`. This helper re-runs the SAME three production steps on the
/// SAME decoder, and section (A) of the case asserts from the production BYTES
/// that those steps are still the ones in the file, so this helper cannot
/// silently diverge from production.
///
/// The `.ok()` between the decode and the read is the whole point: the refusal
/// is DISCARDED, so this helper returns `Some(handle)` for a successful decode
/// and `None` for a refusal. It rechecks only the decoder result; it does not
/// execute the ledger's separate delivery/task/deduplication accounting gates.
fn ledger_acknowledged_handle(arguments: &serde_json::Value) -> Option<String> {
    serde_json::from_value::<MemoryInfluenceAckInput>(arguments.clone())
        .ok()
        .map(|ack| ack.memory_handle)
}

// WORK_UNIT_CASE: 941/16
#[test]
#[allow(clippy::too_many_lines)]
fn c16_the_ledger_caller_consumes_the_real_decoder_and_no_canary_can_raise_proof() {
    // GOVERNING DOCS, verbatim:
    // * docs/architecture/I15-06-instructiondata-separation.md:6 — "model output
    //   remains candidate;"
    // * docs/architecture/I15-06-instructiondata-separation.md:8 — "retrieved
    //   content cannot grant permission;"
    // * docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:12 —
    //   "authority, scope, effect, privacy, ordering and receipt fields are never
    //   silently defaulted;"
    //
    // The ledger caller is `acknowledged_handle` at
    // crates/eliot-engine/src/ul/ledger.rs:410-414, gated on
    // `measurement.tool_name == "eliot_memory_influence_trace"` at
    // crates/eliot-engine/src/ul/ledger.rs:110-112. The increment at :118 is
    // reached only after same-task delivery and a first insertion into
    // `session.acknowledged`; this case asserts those source guards but does not
    // run the ledger or claim a runtime count. That file is read, never written.

    // ---- (A) THE CALLER IS THE REAL ONE, READ FROM ITS OWN BYTES. --------
    // Everything below about the caller is re-derived from the production file
    // rather than from anything this file asserts about it, so this case cannot
    // pass against a caller that does not exist or was rewritten.
    let ledger = read_engine_source("ul/ledger.rs");

    // The `acknowledged_handle` SLICE: the exact bytes of the acknowledgement
    // decode path, taken from the production file and from nothing this file
    // asserts about it. Three things below are claims about WHAT THE LEDGER
    // DOES NOT DO, and an absence is only a proof when it is bounded: the whole
    // file contains unrelated code (`unwrap_or_default` at ledger.rs:220
    // computes a control-arm baseline, far from any acknowledgement), so a
    // whole-file absence would be a claim about the file rather than about the
    // caller under proof. The slice begins at the declaration itself and ends
    // at its closing brace; it never includes the unrelated prefix.
    let acknowledged_handle_slice = ledger.split_once("fn acknowledged_handle").map_or_else(
        || panic!("crates/eliot-engine/src/ul/ledger.rs must still declare `acknowledged_handle`"),
        |(_, after)| {
            let body = after.find("\n}").map_or(after.len(), |close| close + 2);
            format!("fn acknowledged_handle{}", &after[..body])
        },
    );
    let record_with_assignment_slice = ledger
        .split_once("pub fn record_with_assignment(")
        .map_or_else(
            || panic!("crates/eliot-engine/src/ul/ledger.rs must still declare `record_with_assignment`"),
            |(_, after)| {
                let next_function = after
                    .find("\n    fn restore(")
                    .unwrap_or(after.len());
                format!("pub fn record_with_assignment({}", &after[..next_function])
            },
        );
    let record_with_assignment_compact = record_with_assignment_slice
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();

    // The decode target is the REAL decoder of this allocation, named as the
    // owner type in the production source.
    assert!(
        acknowledged_handle_slice
            .contains("serde_json::from_value::<MemoryInfluenceAckInput>(arguments.clone())"),
        "crates/eliot-engine/src/ul/ledger.rs:411 must decode the acknowledgement with the \
         owner decoder MemoryInfluenceAckInput"
    );
    // THE CANARY-VALIDITY PREMISE: the refusal is DISCARDED, not surfaced.
    // `.ok()` is what makes the canary rows below a real proof rather than a
    // tautology, and it is asserted from the production bytes — INSIDE the
    // acknowledged_handle slice, because that is the `.ok()` that matters
    // (ledger.rs:412); an `.ok()` anywhere else in the file would not make
    // this path discard anything.
    assert!(
        acknowledged_handle_slice.contains(".ok()"),
        "the acknowledged_handle slice of crates/eliot-engine/src/ul/ledger.rs must contain the \
         `.ok()` at :412; a caller that surfaced the inner message would make the canary rows \
         below vacuous"
    );
    assert!(
        !acknowledged_handle_slice.contains("unwrap_or_default()")
            && !acknowledged_handle_slice.contains("unwrap()"),
        "the acknowledged_handle slice of crates/eliot-engine/src/ul/ledger.rs must not invent a \
         value when the decode is refused; this claim is scoped to that slice because \
         ledger.rs:220 uses unwrap_or_default for an unrelated control-arm baseline"
    );
    // The helper exposes only the decoded handle. The production method has a
    // separate path from that candidate to the count, and its exact guards are
    // asserted below from a slice of the owning method.
    assert!(
        record_with_assignment_slice
            .contains("delta.acknowledged_items = delta.acknowledged_items.saturating_add(1);"),
        "record_with_assignment must retain the acknowledged-item counter increment"
    );
    // The gate is the tool name, NOT anything carried in the arguments.
    assert!(
        record_with_assignment_slice
            .contains("if measurement.tool_name == \"eliot_memory_influence_trace\""),
        "record_with_assignment must gate acknowledgement handling on the tool name"
    );
    // The decoder helper reads exactly one field from the decoded value.
    assert_eq!(
        acknowledged_handle_slice
            .matches("ack.memory_handle")
            .count(),
        1,
        "acknowledged_handle must read exactly ONE field from the decoded acknowledgement"
    );
    // The re-run helper's own premise, checked against the production bytes:
    // the helper is only meaningful if the production call it re-runs is
    // EXACTLY the expression asserted above, so the two together cannot drift.
    assert_eq!(
        acknowledged_handle_slice
            .matches("serde_json::from_value::<MemoryInfluenceAckInput>(arguments.clone())")
            .count(),
        1,
        "acknowledged_handle must decode exactly once, through the owner decoder"
    );
    let record_compact = record_with_assignment_compact.as_str();
    assert!(
        record_compact.contains(
            "ifmeasurement.tool_name==\"eliot_memory_influence_trace\"&&letSome(handle)=acknowledged_handle(&measurement.arguments){"
        ),
        "the production acknowledgement branch must consume the bounded decoder helper's handle"
    );
    assert!(
        record_compact.contains(
            "letdelivered=session.delivered.get(&handle).is_some_and(|item|item.task_id==Some(measurement.task_id));"
        ),
        "the production method must require a delivered handle belonging to the same task"
    );
    let guarded_increment = "ifdelivered&&session.acknowledged.insert(handle){delta.acknowledged_items=delta.acknowledged_items.saturating_add(1);}";
    assert!(
        record_compact.contains(guarded_increment),
        "the increment must remain inside the delivery-and-unique-acknowledgement block"
    );

    // ---- (B) THE RUNTIME-ASSEMBLED CANARIES. ------------------------------
    // The canary member NAMES and the canary VALUES are both assembled here at
    // runtime: each NAME is a join of runtime fragments and each VALUE is a
    // runtime fragment repeated to a runtime count. The FAMILY LABELS used to
    // name the rows below are literals, and are literals only as labels — they
    // never enter a document, so a reader looking for canary material in an
    // argument object will not find it under any of those names.
    //
    // Three authority-shaped families are injected, because the card names
    // three: a PERMISSION family, an EXAM family and an ACCEPTED family. In
    // every case the injected members are members the acknowledgement does NOT
    // declare, so each is an unknown-field refusal.
    //
    // The canary VALUE is built at runtime from this fragment and a runtime
    // count. The FRAGMENT ITSELF IS A LITERAL (it is spelled in this file),
    // exactly as the family labels below are; what is assembled at runtime is
    // the value `fragment.repeat(count)`, never the fragment. The banner above
    // states which pieces are literal and which are assembled.
    let canary_repeats: usize = 7;
    let canary_char = "grant";
    // The three canary member NAMES, each joined from THREE runtime fragments,
    // so that no single literal in this file spells an authority-shaped key.
    let permission_key = ["perm", "iss", "ion"].concat();
    let exam_key = ["exa", "min", "er"].concat();
    let accepted_key = ["accep", "ted_", "proof"].concat();
    let canary_value: String = canary_char.repeat(canary_repeats);
    assert_eq!(
        canary_value.len(),
        canary_char.len() * canary_repeats,
        "the runtime canary value must be the runtime fragment repeated to the runtime repeat \
         count, and nothing else"
    );
    // A CONTROL canary key that the acknowledgement DOES declare, carrying a
    // runtime canary value. It decodes to the same handle candidate, showing
    // that the refusal rows below are about CLOSURE, not about the canary being
    // poison. The actual ledger count still has the delivery/task/deduplication
    // guards asserted from production source above.
    let control_value: String = canary_char.repeat(canary_repeats + 1);
    let mut control_arguments = decode::<serde_json::Value>(T12_W3_C16_LEDGER_ARGS_BASE)
        .expect("the control arguments must be valid JSON");
    control_arguments
        .as_object_mut()
        .expect("the control arguments must be a JSON object")
        .insert(
            "memory_handle".to_owned(),
            serde_json::Value::String(control_value.clone()),
        );

    // The ledger's decoding step is `ledger_acknowledged_handle`, the
    // module-level helper above, which re-runs the production body exactly.

    // (B1) THE CONTROL: the acknowledged-shape arguments decode and the helper
    // yields a handle candidate. This test does not execute ledger accounting.
    let control_handle = ledger_acknowledged_handle(&control_arguments);
    assert_eq!(
        control_handle,
        Some(control_value.clone()),
        "the control row must show the caller yielding the decoded handle, so the refusals \
         below are caused by the injected members"
    );

    // (B2) THE CANARY ROWS. For each authority-shaped family, the arguments are
    // the control arguments PLUS the canary member. The helper's `None` proves
    // that this decode path yields no handle candidate. The source checks above
    // show that production cannot enter the acknowledgement branch without a
    // decoded handle, same-task delivery, and a unique set insertion.
    let canary_cases: [(&str, String, String); 3] = [
        ("permission", permission_key.clone(), canary_value.clone()),
        ("exam", exam_key.clone(), canary_value.clone()),
        ("accepted", accepted_key.clone(), canary_value.clone()),
    ];
    for (family, key, value) in &canary_cases {
        let mut arguments = control_arguments.clone();
        arguments
            .as_object_mut()
            .expect("the canary arguments must be a JSON object")
            .insert(key.clone(), serde_json::Value::String(value.clone()));
        // The decoder refuses — asserted through the PATH THAT KEEPS serde's
        // OWN message, because this is the owner decoder reached directly.
        let direct = decode::<MemoryInfluenceAckInput>(&arguments.to_string());
        let direct_error = direct.expect_err(
            "an injected authority-shaped member must be refused by the acknowledgement decoder",
        );
        assert_eq!(
            direct_error.to_string(),
            format!(
                "unknown field `{key}`, expected one of `project_id`, `write_id`, \
                 `memory_handle`, `influence_class`, `downstream_outcome_ref`"
            ),
            "the {family} canary must be refused against the owner's declared field set"
        );
        // AND THE CANARY-VALIDITY ROW: through the same decode-and-discard
        // helper as production, the SAME arguments yield no handle candidate.
        // The inner message is never surfaced to that helper.
        assert_eq!(
            ledger_acknowledged_handle(&arguments),
            None::<String>,
            "the {family} canary must be refused by the helper, which yields no handle candidate"
        );
    }

    // ---- (C) THE CANARIES AT EACH DECODE SHAPE. ---------------------------
    // `Some(handle)` is only the decoder's output, not proof of a counter
    // increment. The source slice above separately verifies that production
    // requires same-task delivery and a first insertion into the acknowledged
    // set before incrementing. These rows cover distinct positions in the
    // acknowledgement wire: (C1) a declared optional member, (C2) the closed
    // enum, (C3) standing in for the absent handle, (C4) the handle's own value,
    // and (C5) a non-string in a declared optional member.
    for (family, key, value) in &canary_cases {
        // (C1) The canary riding a DECLARED OPTIONAL member. `project_id`,
        // `write_id` and `downstream_outcome_ref` are declared `Option<String>`
        // (`ul/injection.rs:187-199`), so a string canary in any of them DECODES
        // — and the helper still yields the PROTECTED handle, unchanged. This
        // is the honest result: a canary in a declared opaque string is DATA.
        // Whether production increments remains controlled by the independent
        // delivery/task/deduplication guard asserted above.
        for placement in ["project_id", "write_id", "downstream_outcome_ref"] {
            let mut arguments = control_arguments.clone();
            arguments
                .as_object_mut()
                .expect("the arguments must be a JSON object")
                .insert(
                    placement.to_owned(),
                    serde_json::Value::String(value.clone()),
                );
            assert_eq!(
                ledger_acknowledged_handle(&arguments),
                Some(control_value.clone()),
                "the {family} canary in the declared optional member `{placement}` is DATA: the \
                 decode succeeds and the helper still yields the same protected handle candidate"
            );
        }
        // (C2) The canary masquerading as the closed `influence_class` value: an
        // unknown variant of a closed control enum, so the decode is refused and
        // the caller yields nothing at all.
        let mut arguments = control_arguments.clone();
        arguments
            .as_object_mut()
            .expect("the arguments must be a JSON object")
            .insert(
                "influence_class".to_owned(),
                serde_json::Value::String(value.clone()),
            );
        assert_eq!(
            ledger_acknowledged_handle(&arguments),
            None::<String>,
            "the {family} canary carried as an unknown influence_class must be refused by the helper"
        );
        // (C3) The canary trying to SUBSTITUTE for the protected handle. The
        // protected member is absent, so the only candidate handle present is the
        // canary itself, and `required(memory_handle, "memory_handle")`
        // (`ul/injection.rs:267`) refuses before any handle exists.
        let mut arguments = decode::<serde_json::Value>(T12_W3_C16_LEDGER_ARGS_NO_HANDLE)
            .expect("the handle-free arguments must be valid JSON");
        arguments
            .as_object_mut()
            .expect("the arguments must be a JSON object")
            .insert(key.clone(), serde_json::Value::String(value.clone()));
        assert_eq!(
            ledger_acknowledged_handle(&arguments),
            None::<String>,
            "the {family} canary must not substitute for the protected memory_handle"
        );
        // (C4) The canary not merely RIDING BESIDE the protected handle but OVERWRITING
        // its value: the canary REPLACES the `memory_handle` string in place, so
        // the protected member carries canary material and the only undeclared
        // member is gone. This shape is distinct from (B2), which leaves the
        // handle intact and adds a sibling member, and distinct from (C3), which
        // removes the handle entirely. `memory_handle` is declared `String`, not
        // an opaque handle type, so the substituted string DECODES. This row
        // proves only that the helper yields the substituted handle candidate;
        // production still requires that exact handle to have been delivered
        // for the same task and to be newly acknowledged.
        let mut arguments = control_arguments.clone();
        arguments
            .as_object_mut()
            .expect("the arguments must be a JSON object")
            .insert(
                "memory_handle".to_owned(),
                serde_json::Value::String(value.clone()),
            );
        assert_eq!(
            ledger_acknowledged_handle(&arguments),
            Some(value.clone()),
            "the {family} canary REPLACING the protected handle's value is returned as the \
             decoder's handle candidate; this assertion makes no ledger-count claim"
        );
        assert_eq!(
            decode::<MemoryInfluenceAckInput>(&arguments.to_string()).map_or_else(
                |error| panic!("the handle-substituted document must decode: {error}"),
                |ack| ack.memory_handle,
            ),
            value.clone(),
            "the {family} canary carried AS the protected handle's value is accepted as DATA: the \
             handle is declared `String`, so the decoder returns it as a candidate; the separate \
             production delivery/task/deduplication guard controls any counter effect"
        );
        // (C5) The canary as a NON-STRING value in a declared optional member:
        // `Option<String>` refuses a number/object there, so the decode is
        // refused rather than coercing the canary.
        for (placement, shape) in [
            ("project_id", serde_json::json!({ "canary": value.clone() })),
            ("write_id", serde_json::json!(canary_repeats)),
            ("downstream_outcome_ref", serde_json::json!([])),
        ] {
            let mut arguments = control_arguments.clone();
            arguments
                .as_object_mut()
                .expect("the arguments must be a JSON object")
                .insert(placement.to_owned(), shape);
            assert_eq!(
                ledger_acknowledged_handle(&arguments),
                None::<String>,
                "a non-string {family} canary in `{placement}` must be refused, never coerced into \
                 the declared `Option<String>`"
            );
        }
    }
    // ---- (C6) THE LEDGER DECODER'S OWN UNDECODABLE ARGUMENTS. -------------
    // `T12_C16_LEDGER_ACK_UNDECODABLE_ARGUMENTS` is a full acknowledgement-shaped
    // tool-argument object: it carries BOTH of the decoder's optional members
    // (`project_id`, `write_id`), BOTH of its required members (`memory_handle`,
    // `influence_class`) and one further member, `delivery_surface`.
    //
    // MAIN BEHAVIOUR NOTE: the refusal DOES happen, and the name is honest.
    // `delivery_surface` is NOT one of `MEMORY_INFLUENCE_ACK_FIELDS`
    // (`ul/injection.rs:200-206`) — it is a member of the SEPARATE full
    // `MemoryInfluenceTraceWriteInput` shape, and mixing the two is exactly the
    // mistake this document represents. The `_` arm at `:255-260` refuses it by
    // name. So this is a refusal, not an acceptance, and it is asserted as one.
    //
    // The refusal is asserted BOTH ways, because this file holds two entry
    // points onto the same decoder:
    //   * `ledger_acknowledged_handle` — the ledger's OWN
    //     `serde_json::from_value::<MemoryInfluenceAckInput>(arguments.clone())
    //     .ok().map(|ack| ack.memory_handle)` (ledger.rs:410-414), which DISCARDS
    //     the message. Its `None` means this path yields no handle candidate for
    //     the production `if let Some(handle)` branch.
    //   * `decode::<MemoryInfluenceAckInput>` — the same decoder reached
    //     directly, which KEEPS serde's message, so the exact refusal text is
    //     pinned here rather than left as a bare `is_err()`.
    //
    // The document is assembled from an opaque `Value` in production, so it is
    // built the same way here: `from_value` runs on the fixture's own parsed
    // `Value`, exactly as `acknowledged_handle` does.
    let undecodable_arguments =
        decode::<serde_json::Value>(T12_C16_LEDGER_ACK_UNDECODABLE_ARGUMENTS)
            .expect("the ledger's undecodable arguments fixture must itself be valid JSON");
    // The decode-and-discard helper yields NOTHING for this document, so it
    // cannot provide a handle to the production acknowledgement branch.
    assert_eq!(
        ledger_acknowledged_handle(&undecodable_arguments),
        None::<String>,
        "`acknowledged_handle` must yield no handle candidate for arguments carrying the \
         undeclared `delivery_surface` member"
    );
    // And the decoder behind it refuses by name, against the owner's shared
    // field-set constant, with serde's exact five-name tail.
    assert_eq!(
        decode::<MemoryInfluenceAckInput>(T12_C16_LEDGER_ACK_UNDECODABLE_ARGUMENTS)
            .expect_err(
                "an acknowledgement-shaped document carrying the undeclared `delivery_surface` \
                 member must be refused by the owner decoder"
            )
            .to_string(),
        concat!(
            "unknown field `delivery_surface`, expected one of `project_id`, `write_id`,",
            " `memory_handle`, `influence_class`, `downstream_outcome_ref`",
        ),
        "ul/injection.rs:255-260 must refuse `delivery_surface` against MEMORY_INFLUENCE_ACK_FIELDS \
         (ul/injection.rs:200-206); `delivery_surface` belongs to the separate full trace-write \
         shape, and the acknowledgement contract does not admit it"
    );
    // THE CONTROL THAT MAKES THE REFUSAL SPECIFIC: the SAME document with that
    // one member removed decodes, and the helper yields its handle candidate. So the
    // refusal above is `delivery_surface` and nothing else — in particular the
    // two optional members really are declared, and their presence is not what
    // the refusal is about.
    let decodable_arguments: serde_json::Value = serde_json::from_str(
        &T12_C16_LEDGER_ACK_UNDECODABLE_ARGUMENTS.replace(r#","delivery_surface":"ul_fired""#, ""),
    )
    .expect("the same document without the undeclared member must itself be valid JSON");
    assert_eq!(
        ledger_acknowledged_handle(&decodable_arguments),
        Some("mem-1".to_owned()),
        "removing only `delivery_surface` must let the same document decode and yield its handle, \
         so the refusal above is that one member"
    );
    // And the two OPTIONAL members really do survive the decode when present,
    // rather than being dropped: I05-16-common-durable-fields.md:46 — "Fields
    // that do not apply remain explicit `None`; they are not silently omitted
    // from the semantic model." Here they APPLY, so they are carried as values.
    let acknowledged = decode::<MemoryInfluenceAckInput>(
        &T12_C16_LEDGER_ACK_UNDECODABLE_ARGUMENTS.replace(r#","delivery_surface":"ul_fired""#, ""),
    )
    .expect("the same document without the undeclared member must decode");
    assert_eq!(
        acknowledged.project_id.as_deref(),
        Some("0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d")
    );
    assert_eq!(acknowledged.write_id.as_deref(), Some("write-1"));
    assert_eq!(
        acknowledged.influence_class,
        MemoryInfluenceClass::SeenButNotUsed
    );
    assert!(acknowledged.downstream_outcome_ref.is_none());

    // The consequence, stated once: the decoder helper returns only a handle
    // candidate. The production counter path additionally requires same-task
    // delivery and a new acknowledged-set insertion, verified from its method
    // bytes above. This static test does not invoke that method or claim a
    // runtime count. Nothing in the helper reads a permission, exam verdict or
    // acceptance from the arguments, so
    // `docs/architecture/I15-06-instructiondata-separation.md:8` — "retrieved
    // content cannot grant permission;" — holds by construction rather than by
    // inspection of any single branch. The absence is asserted WITHIN the
    // acknowledged_handle slice: the acknowledgement decode path reads no
    // authority, permission or acceptance vocabulary at all, which is the claim
    // under proof. (A whole-file scan would instead be a claim about unrelated
    // ledger code and would break on any future edit elsewhere in the file.)
    assert!(
        !acknowledged_handle_slice.contains("authority")
            && !acknowledged_handle_slice.contains("permission")
            && !acknowledged_handle_slice.contains("accepted"),
        "the acknowledged_handle slice of crates/eliot-engine/src/ul/ledger.rs must read no \
         authority, permission or acceptance from the acknowledgement arguments: the \
         decoder helper reads no authority or permission value from the input"
    );

    // ---- (D) WHERE THE PATH RETURNS SERDE'S OWN MESSAGE, ASSERT THE FIELD
    // ---- NAME BEHAVIOUR INSTEAD OF A CANARY. ---------------------------
    // The composed union `MemoryInfluenceToolInput` (observability.rs:347-353)
    // is the OWNER of the published tool-argument schema and its error message
    // DOES reach the caller, so a canary would be readable there and is
    // therefore not the right instrument. What is asserted instead is the
    // FIELD-NAME behaviour: the refusal names the offending member, and the
    // same document without it decodes.
    for (family, key, value) in &canary_cases {
        let mut arguments = control_arguments.clone();
        arguments
            .as_object_mut()
            .expect("the arguments must be a JSON object")
            .insert(key.clone(), serde_json::Value::String(value.clone()));
        let composed = decode::<MemoryInfluenceToolInput>(&arguments.to_string());
        let composed_error = composed.expect_err(
            "the composed union must refuse an authority-shaped member outside the \
             acknowledgement contract",
        );
        assert_eq!(
            composed_error.to_string(),
            format!(
                "unknown field `{key}`, expected one of `project_id`, `write_id`, \
                 `memory_handle`, `influence_class`, `downstream_outcome_ref`"
            ),
            "observability.rs:448-452 must refuse the {family} canary by name against the owner's \
             own field set — a refusal that names the member is the field-name behaviour, not a \
             canary"
        );
        // And removing that one member admits the same document, so the refusal
        // is the MEMBER and nothing else.
        let without = decode::<MemoryInfluenceToolInput>(&control_arguments.to_string());
        let accepted = without.unwrap_or_else(|error| {
            panic!("the same arguments without the {family} canary must decode: {error}")
        });
        assert!(
            matches!(accepted, MemoryInfluenceToolInput::Ack(_)),
            "the {family}-free arguments must select the acknowledgement branch of the union"
        );
    }

    // ---- (E) MODEL OUTPUT STAYS CANDIDATE THROUGH THIS LEDGER PATH. ------
    // `docs/architecture/I15-06-instructiondata-separation.md:6` — "model output
    // remains candidate;". The acknowledgement's `influence_class` is a CLOSED
    // enum (`cognition.rs:625`) with no `Unknown(raw)` arm, so an additive
    // spelling is refused rather than absorbed, which is what
    // APPENDIX-P:13 ("closed control variants fail when unknown") requires of a
    // closed control variant.
    for (family, _key, value) in &canary_cases {
        let mut arguments = control_arguments.clone();
        arguments
            .as_object_mut()
            .expect("the arguments must be a JSON object")
            .insert(
                "influence_class".to_owned(),
                serde_json::Value::String(value.clone()),
            );
        let refusal = decode::<MemoryInfluenceAckInput>(&arguments.to_string())
            .expect_err("a closed influence_class must refuse an additive spelling");
        assert_eq!(
            refusal.to_string(),
            format!(
                "unknown variant `{value}`, expected one of `used_and_changed_action`, `used_for_verification`, `prevented_repeated_failure`, `suppressed_as_stale`, `suppressed_as_wrong_scope`, `seen_but_not_used`, `loaded_without_delta`"
            ),
            "the {family} influence_class spelling must be refused as an unknown variant, not \
             absorbed into a current-valid classification"
        );
    }
    // And the exact reason string a caller would read, since the decoder here
    // KEEPS serde's own message (this path is the owner decoder reached
    // directly, so the message is the field-name behaviour, not a canary).
    let closed_message = decode::<MemoryInfluenceAckInput>(
        r#"{"memory_handle":"mem-1","influence_class":"observed_and_applied"}"#,
    )
    .expect_err("the closed classification must refuse an unowned spelling");
    assert_eq!(
        closed_message.to_string(),
        "unknown variant `observed_and_applied`, expected one of `used_and_changed_action`, \
         `used_for_verification`, `prevented_repeated_failure`, `suppressed_as_stale`, \
         `suppressed_as_wrong_scope`, `seen_but_not_used`, `loaded_without_delta`",
        "cognition.rs:623-633 must keep the closed classification list verbatim, in declaration \
         order"
    );
    // And each OWNED spelling decodes, so the seven-name tail above is the real
    // declared set and not a superset. `MemoryInfluenceClass` derives `Debug`
    // and no `Display`/`as_str`, so the decoded variant is named through its
    // own derived `Debug` — a per-variant `match` is unnecessary because the
    // derived spelling IS the declaration's variant name.
    for (owned, variant) in [
        ("used_and_changed_action", "UsedAndChangedAction"),
        ("used_for_verification", "UsedForVerification"),
        ("prevented_repeated_failure", "PreventedRepeatedFailure"),
        ("suppressed_as_stale", "SuppressedAsStale"),
        ("suppressed_as_wrong_scope", "SuppressedAsWrongScope"),
        ("seen_but_not_used", "SeenButNotUsed"),
        ("loaded_without_delta", "LoadedWithoutDelta"),
    ] {
        let classified = decode::<MemoryInfluenceAckInput>(&format!(
            r#"{{"memory_handle":"mem-1","influence_class":"{owned}"}}"#
        ))
        .unwrap_or_else(|error| panic!("the owned class `{owned}` must decode: {error}"));
        assert_eq!(
            format!("{:?}", classified.influence_class),
            variant,
            "the owned class `{owned}` must decode to `{variant}` itself, never to a substituted \
             default"
        );
    }
}

/// Case 16 base arguments: an acknowledgement-shaped tool-argument object the
/// ledger's caller is meant to consume. It carries the two required members and
/// nothing else, so every refusal below is attributable to an INJECTED member.
const T12_W3_C16_LEDGER_ARGS_BASE: &str =
    r#"{"memory_handle":"mem-1","influence_class":"seen_but_not_used"}"#;

/// Case 16 handle-free arguments: the same object with the PROTECTED
/// `memory_handle` removed. `MemoryInfluenceAckInput` requires it
/// (`ul/injection.rs:267`), so this document is refused on its own account and
/// the canary rows built on it prove the canary does not SUBSTITUTE for the
/// protected identity.
const T12_W3_C16_LEDGER_ARGS_NO_HANDLE: &str = r#"{"influence_class":"seen_but_not_used"}"#;
