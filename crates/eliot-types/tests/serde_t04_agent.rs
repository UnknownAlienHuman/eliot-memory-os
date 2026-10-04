//! Issue #933 (`F-DENY-T04`, child `#933` of family `T04`): the allocated
//! decoder proof for the whole 54-type T04 slice -
//! `crates/eliot-types/src/adapter.rs`,
//! `crates/eliot-types/src/external_agent.rs`,
//! `crates/eliot-types/src/mcp_contract.rs` and
//! `crates/eliot-types/src/provider_invocation.rs` - and the sixteen preserved
//! acceptance cases, one marker per case.
//!
//! NOTHING IN THIS FILE HAS BEEN EXECUTED BY ITS WRITER. Not one test below has
//! been run, compiled or linted by the agent that wrote it. Every assertion
//! states what the delivered decoder is FOR, derived by reading the production
//! source, not what it was observed to do at runtime. A green run of this file
//! is compatible with every assertion in it being wrong, and nothing here may
//! be read as an execution result, a case tally or a pass count.
//!
//! Fixtures are stored as RAW JSON TEXT inside
//! `crates/eliot-types/tests/data/serde_t04_agent_mcp.json` and handed to the
//! deserializer unparsed. A `serde_json::Value` intermediate collapses a
//! repeated object member before the decoder ever sees it, so it could not
//! prove case 5; every decoder call in this file therefore receives the stored
//! string itself. NO `Value` EVER REACHES A DECODER in this file, and that is the
//! whole claim. The `Value` uses are exactly two kinds, both of them AFTER the fact:
//!
//! - WITNESSES that parse a document which was ALREADY decoded from its own raw
//!   text, purely to compare one decoded field against the fixture's own stored
//!   value - `member_value` and everything built on it, plus case 5's
//!   `collapsed`/`repeats` pair; and
//! - RE-ENCODINGS of an already-decoded value, compared as bytes: case 9's legacy
//!   round trip and case 15's completeness-variant round trip each decode
//!   `serde_json::to_string(..)` of a value they already hold.
//!
//! No fixture is normalized, re-serialized or pre-processed before a decoder sees
//! it. Where this file parses a stored document at all, that parse is a
//! comparison and never an input to a decoder.
//!
//! Requirements the fixture container (`serde_t04_agent_mcp.json`, another
//! writer's file) must satisfy for this file's assertions to be exact:
//!
//! - every `fixtures` value is a JSON STRING holding wire text, never a nested
//!   object or array;
//! - `c2_<Type>_canonical` for a plain `enum` holds EXACTLY the derived
//!   serializer's own output for one variant - a bare JSON string with no
//!   whitespace, e.g. `"health_check"` - because cases 6, 12 and 15 assert that
//!   the decoded variant re-encodes to the stored bytes;
//! - `c2_ProviderInvocationOutcome_canonical` is the ONE canonical fixture of a
//!   STRUCT reached through `assert_enum_spelling`, and it is a JSON OBJECT, not a
//!   bare variant string: `ProviderInvocationOutcome` is a struct
//!   (`crates/eliot-types/src/provider_invocation.rs:531`), so case 6's call for
//!   that name compares the re-encoded document to the stored bytes and pins no
//!   spelling;
//! - a refusal fixture that injects one member repeats that member's key
//!   literally in the text; the exact keys and tags are pinned in
//!   `INJECTED_MEMBERS`, `INJECTED_TAGS` and `MISSING_MEMBERS` below, and case 1
//!   asserts that each of those fixtures really carries its pinned key;
//! - a fixture's suffix says what the file asserts of it, and there are EXACTLY TWO
//!   refusal-shaped suffix families, neither of them `..._malformed` (that spelling is
//!   gone after round 2):
//!   - `..._refuse` - the named type's OWN decoder REFUSES the document. This covers
//!     an unknown member, an unknown or wrong-typed control tag, a repeated member, a
//!     missing required member and a wrong-typed bare value alike; `c6` (c) is the
//!     wrong-typed case and `c14` owns the repeated-member case.
//!   - `..._text` - a BOUNDED MALFORMED INPUT handed to a decoder as raw text, which
//!     is asserted to FAIL, or to decode, WITHOUT a panic, unwind or abort. Case 14
//!     asserts this inside `catch_unwind`. No `_text` fixture is required to be
//!     refused for a NAMED reason, which is why none of them claims one.
//!     Every fixture whose name carries neither suffix is asserted to be ACCEPTED, and
//!     the acceptances say so in their own names (`..._accepted`, `..._observed`,
//!     `..._canonical`, `..._default`);
//! - `c16_ProviderRoutePolicyBinding_canonical` is the canonical policy's own
//!   binding: the same `policy_id` and the same `policy_hash_blake3`.
//!
//! RECONCILIATION ROUND (writer W6) - the container and this file were written
//! independently and their fixture names drifted apart, so both halves were
//! brought onto ONE name set. What changed, and why, so a reader of either file
//! sees the same history:
//!
//! - There is deliberately NO `c2_CompilePacketToolInput_canonical` counterpart for
//!   the visitor: `CompilePacketToolInputVisitor` is a PRIVATE
//!   `serde::de::Visitor` (`crates/eliot-types/src/mcp_contract.rs:50`), not a
//!   `Deserialize`, so NO wire document is of that type. Case 13 therefore reads
//!   `c2_CompilePacketToolInput_canonical` - the document that visitor accepts -
//!   and cases 1 and 2 assert the visitor's ABSENCE instead of skipping it
//!   silently. No fixture is invented for it and no key is aliased to fake one.
//! - `c13_area_compile_packet_tool_input_permitted_keys` is DELETED. It held a copy
//!   of the Rust SOURCE of `COMPILE_PACKET_TOOL_FIELDS`
//!   (`crates/eliot-types/src/mcp_contract.rs:52-60`), which is not wire text, and
//!   a private `const` is not observable from a test anyway. The same permitted
//!   list is asserted from `PERMITTED_PACKET_KEYS` against the decoder's OWN
//!   refusal message in case 13 and against the published schema in case 16.
//! - `c3_area_unknown_outer_member_in_capability_manifest_refuse` is DELETED. Its
//!   claim is case 3's (an unknown OUTER member) but its document is a
//!   `CapabilityManifest`, whose frozen home case is case 4, so asserting it in
//!   case 3 would either touch a type case 3 does not bind or move the frozen home
//!   case. Case 3 asserts the outer-member refusal on the two types it binds, and
//!   case 4 asserts `CapabilityManifest`'s own unknown-member refusal: no assertion
//!   is lost.
//! - `c10_area_legacy_cognitive_contract_through_current_decoder_refuse` is
//!   DELETED. It was byte-identical to `c2_CognitiveProviderRuntimeContract_canonical`
//!   and did NOT refuse on version grounds: `schema_version` is a plain `String`
//!   (`external_agent.rs:176`). Case 9 hands the legacy canonical itself to the
//!   CURRENT decoder and asserts the refusal that actually occurs.
//! - The six byte-identical case-8 pairs were collapsed onto the
//!   `c8_<Type>_unsupported_schema_version` key of each pair; the `c8_area_*`
//!   duplicate of each pair was DELETED, because the survivor already carries the
//!   whole claim and a byte-identical twin asserts nothing the survivor does not.
//! - Six keys were RENAMED so each names the type whose decoder raises the
//!   refusal and the depth at which the injected member really sits:
//!   `c4_AdapterRequest_context_unknown_member_refuse` (an `AdapterRequest`
//!   document, not an `AdapterContext` document),
//!   `c4_CapabilityManifest_authority_profile_unknown_member_refuse` (a
//!   `CapabilityManifest` document, not an `AdapterAuthorityProfile` one),
//!   `c4_CapabilityManifest_unknown_capability_tag_refuse` (the enum's tag is
//!   reachable only through the manifest that carries it),
//!   `c6_ProviderReconciliationRecord_unknown_method_tag_refuse` (same reason:
//!   `ProviderReconciliationMethod` is reachable only through its record),
//!   `c14_area_duplicate_top_level_member_text` (a plain top-level repeat, neither
//!   deep nor nested), and the two `c4_AdapterHealth_unknown_member_refuse` /
//!   `c4_AdapterResult_observation_unknown_member_refuse` documents, whose injected
//!   key is now spelled `c4_unknown_member`.
//! - ROUND-2 CORRECTIONS, after a second-opinion measurement of the fixture texts
//!   themselves:
//!   - `c4_AdapterObservation_unknown_member_refuse` is DELETED and
//!     `c4_AdapterResult_observation_unknown_member_refuse` is ADDED. The deleted
//!     document was a BARE `AdapterObservation` with no `observations` array, so
//!     decoding it as `AdapterResult` stopped at ``missing field `observation_id` ``
//!     and the `unknown field` needle could never match `c4_unknown_member`. It was
//!     also case 3's claim, not case 4's. The replacement is
//!     `c2_AdapterResult_canonical` with ONE entry in its `observations` array
//!     carrying `c4_unknown_member`, so the refusal comes from
//!     `AdapterObservation`'s own `deny_unknown_fields`
//!     (`crates/eliot-types/src/adapter.rs:196-197`) at DEPTH TWO. Case 4 decodes it
//!     as `AdapterResult`, which is what it is.
//!   - `c6_wrong_typed_status_tag_malformed` is RENAMED
//!     `c6_wrong_typed_status_tag_refuse`, byte for byte. It was the only one of the
//!     stored keys whose suffix was neither `_refuse` nor `_text`, and `malformed`
//!     overstated a document that IS valid JSON and IS refused - as a wrong TYPE, not
//!     as malformed input. `c14_area_top_level_number_text` keeps its name and its
//!     distinct claim: the same three bytes refused as a STRUCT by `AdapterError`
//!     instead of as an enum by `AdapterResultStatus`.
//! - `meta.known_unused` lists any fixture this file does not read, one clause of
//!   reason each. It is EMPTY: this file reads every fixture in the container.
//!
//! The four production files are READ-ONLY here. Nothing in this file edits a
//! production declaration, adds a `pub use`, widens a `pub` or changes a schema.
//! Every type this file names is already reachable through the `eliot_types`
//! boundary and is imported exactly as a downstream crate would import it, with
//! two declared exceptions:
//!
//! - `CognitiveProviderRuntimeContract` is in no crate-root re-export block; it is
//!   named through its declaring module path,
//!   `eliot_types::external_agent::legacy`, which `crates/eliot-types/src/lib.rs:15`
//!   publishes as `pub mod external_agent` and
//!   `crates/eliot-types/src/external_agent.rs:247` publishes as `pub mod legacy`;
//! - `CompilePacketToolInputVisitor` is `struct CompilePacketToolInputVisitor;`
//!   with no `pub` (`crates/eliot-types/src/mcp_contract.rs:50`), so it is NOT
//!   reachable from this file at all. It is not widened here (the card forbids
//!   it). Case 13 asserts its exact behaviour through the
//!   `CompilePacketToolInput` decoder that constructs it, which is the only
//!   observable surface it has.
//!
//! Rules exercised (verbatim):
//! - `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:12` -
//!   "authority, scope, effect, privacy, ordering and receipt fields are never
//!   silently defaulted;"
//! - `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:13` -
//!   "closed control variants fail when unknown; additive reason/telemetry
//!   values preserve Unknown(raw);"
//! - `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:11` -
//!   "major incompatibility fails before effects; additive minor compatibility
//!   is declared explicitly;"
//! - `docs/architecture/I05-16-common-durable-fields.md:46` - "Fields that do
//!   not apply remain explicit `None`; they are not silently omitted from the
//!   semantic model."
//! - `docs/architecture/I05-27-canonical-operation-identity-and-effect-identity.md:18`
//!   - "fields affecting authority, scope, ordering, privacy or effect cannot be
//!     omitted/defaulted silently."
//!
//! KNOWN NON-CLEAN, never a pass in this file (the card forbids repairing them
//! here): `ObserveInput.hint` carries `#[serde(default, alias = "kind")]`, so the
//! CURRENT decoder trial-accepts one closed control variant under two names, and
//! `ObserveInput.schema_version` carries a helper default, so an omitted key is
//! silently promoted to the current version. Both are recorded in the container's
//! `known_non_clean` array, asserted there as the non-clean behaviour the source
//! declares in case 12, and handed off to their named owner. No assertion in this
//! file reports either path as clean.
//!
//! `AdapterError.code` is a FREE REASON STRING
//! (`crates/eliot-types/src/adapter.rs:174`), not a closed enum. Case 14 asserts
//! that an arbitrary reason code decodes as data and says so in words. No
//! assertion here treats it as a closed variant.

#![allow(clippy::expect_used)]

use eliot_types::external_agent::legacy::{
    COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION, COGNITIVE_RUNTIME_PREFLIGHT_SCHEMA_VERSION,
    CognitiveProviderRuntimeContract,
};
use eliot_types::memory::DEFAULT_CONTEXT_PACKET_PREFERRED_TOKENS;
use eliot_types::{
    AdapterAuthorityProfile, AdapterCapability, AdapterClass, AdapterContext, AdapterError,
    AdapterHealth, AdapterLimits, AdapterObservation, AdapterRequest, AdapterResult,
    AdapterResultStatus, AdapterState, AgentCandidateCurationInput, AgentCandidateSubmitInput,
    CapabilityManifest, CompilePacketToolInput, ExternalAgentExecutionRequest,
    ExternalAgentPurpose, ExternalResultCompletenessReceipt, OBSERVE_INPUT_SCHEMA_VERSION,
    OPERATION_AUTHORITY_SCHEMA_VERSION, ObserveHint, ObserveInput, OperationAuthorityCloseReceipt,
    OperationAuthorityCloseRequest, OperationAuthorityOpenReceipt, OperationAuthorityOpenRequest,
    OperationAuthorityTerminalOutcome, PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION,
    PROVIDER_RUNTIME_PREFLIGHT_SCHEMA_VERSION, ProcessExecutionPolicy, ProviderAuthenticationState,
    ProviderDeclaredBudget, ProviderExecutionEvidence, ProviderFailureIncident,
    ProviderIdentityCheck, ProviderInvocationAttempt, ProviderInvocationOutcome,
    ProviderInvocationOutcomeClass, ProviderInvocationState, ProviderInvocationTransition,
    ProviderMcpServerContract, ProviderMcpToolProfileBinding, ProviderReconciliationMethod,
    ProviderReconciliationRecord, ProviderResultCompleteness, ProviderRootCauseStatus,
    ProviderRoutePolicy, ProviderRoutePolicyBinding, ProviderRouteReadinessGate,
    ProviderRouteReadinessVerdict, ProviderRuntimeContract, ProviderRuntimePreflightReceipt,
    ProviderStructuredOutputMode, ProviderTimeoutClass, ProviderTimeoutProfile,
    agent_candidate_input_schema, compile_packet_input_schema, compile_packet_minimal_example,
    observe_input_schema,
};

// ---------------------------------------------------------------------------
// The fixture container and its two contract-fixed helpers.
// ---------------------------------------------------------------------------

/// The container file's own TEXT, read with `std::fs::read_to_string` and
/// returned with no parsing, re-serialization or normalization of any kind. This
/// is the ONLY route on which the container's physical member order is
/// observable, so it is the route every order claim in this file is read
/// through.
fn corpus_text() -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("serde_t04_agent_mcp.json");
    std::fs::read_to_string(&path).expect("serde_t04_agent_mcp.json must exist")
}

/// The raw fixture corpus, read exactly as
/// `crates/eliot-types/tests/data/serde_t04_agent_mcp.json` stores it. The
/// `Value` only carries the strings out of this loader; what reaches the
/// deserializer is the stored wire text itself, byte for byte, with every
/// repeated object member intact.
fn corpus() -> serde_json::Value {
    serde_json::from_str(&corpus_text()).expect("serde_t04_agent_mcp.json must be valid JSON")
}

/// One fixture's own text, byte for byte, with no re-serialization: a repeated
/// member and the exact member order both survive, which a `Value` round trip
/// would destroy.
fn raw(name: &str) -> String {
    corpus()
        .get("fixtures")
        .and_then(|fixtures| fixtures.get(name))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("the corpus must contain fixture {name}"))
        .to_owned()
}

/// The 54 allocated type names, exactly as the container's `meta.types` records
/// them. The inventory itself is frozen and owned elsewhere; this only reads the
/// copy the container carries so the two cannot drift silently.
fn meta_types() -> Vec<String> {
    corpus()
        .get("meta")
        .and_then(|meta| meta.get("types"))
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("the corpus must carry `meta.types`"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("`meta.types` must hold strings"))
                .to_owned()
        })
        .collect()
}

/// The allocated types whose home case is `case`. `case` is the full marker
/// slug, `933/c<N>_<slug>`. The table is this file's own half of the binding:
/// each entry is asserted against what the home-case test actually decodes or
/// refuses, so the binding is executable rather than a comment.
fn types_bound_to_case(case: &str) -> Vec<String> {
    TYPE_HOME_CASE
        .iter()
        .filter(|(_, home_case)| *home_case == case)
        .map(|(type_name, _)| (*type_name).to_owned())
        .collect()
}

/// The sixteen case markers. The slugs themselves are this delivery's own naming
/// convention, NOT an external authority: no `cards/933.md` exists and these
/// `933/c<N>_<slug>` strings appear nowhere else in the repository outside this
/// file. The issue's case table fixes the case NUMBERS and the required observable
/// results; it does not fix these slugs. Case 1 asserts this list is what the
/// marker lines in this file use, that no case is discharged twice and that no case
/// is missing a type or a binding.
const CASE_MARKERS: [&str; 16] = [
    "933/c1_allocation_complete",
    "933/c2_unchanged_valid_bytes",
    "933/c3_unknown_outer_field_refused",
    "933/c4_unknown_nested_field_refused",
    "933/c5_duplicate_keys_refused",
    "933/c6_wrong_or_unknown_tags_refused",
    "933/c7_missing_or_empty_required_ids_refused",
    "933/c8_unsupported_versions_refused",
    "933/c9_explicit_legacy_migration_preserves_evidence",
    "933/c10_unsafe_migration_refuses",
    "933/c11_opaque_data_cannot_smuggle_control_meaning",
    "933/c12_ambiguous_alias_default_cannot_grant_authority",
    "933/c13_exact_exceptions_invalidate_on_use_change",
    "933/c14_bounded_malformed_inputs_panic_free",
    "933/c15_decoders_refuse_before_trusted_output_no_candidate_finish",
    "933/c16_scope_schema_routing_dependencies_visibility_unchanged",
];

/// The frozen T04 allocation: all 54 allocated types, each bound to the ONE home
/// case that owns it. Every case calls `assert_case_binding` with exactly the types
/// it OWNS, in both directions, so a type cannot be bound to a case that does not
/// name it, and a case cannot name a type the table does not bind to it. A case may
/// still decode a type another case owns - a carrier, or a type whose own member is
/// the subject - and every such decode is recorded by `assert_also_decodes`, which
/// names the real owner so the binding is never implied rather than stated.
/// `CompilePacketToolInputVisitor` is bound to case 13 by its OBSERVABLE decoder,
/// not by a Rust path: see the header.
const TYPE_HOME_CASE: [(&str, &str); 54] = [
    ("AdapterRequest", "933/c3_unknown_outer_field_refused"),
    ("AdapterResult", "933/c3_unknown_outer_field_refused"),
    ("AdapterContext", "933/c4_unknown_nested_field_refused"),
    (
        "AdapterError",
        "933/c14_bounded_malformed_inputs_panic_free",
    ),
    (
        "AdapterResultStatus",
        "933/c6_wrong_or_unknown_tags_refused",
    ),
    ("AdapterState", "933/c6_wrong_or_unknown_tags_refused"),
    (
        "AdapterAuthorityProfile",
        "933/c4_unknown_nested_field_refused",
    ),
    ("AdapterCapability", "933/c4_unknown_nested_field_refused"),
    ("AdapterClass", "933/c6_wrong_or_unknown_tags_refused"),
    ("AdapterHealth", "933/c4_unknown_nested_field_refused"),
    (
        "AdapterLimits",
        "933/c7_missing_or_empty_required_ids_refused",
    ),
    ("AdapterObservation", "933/c4_unknown_nested_field_refused"),
    ("CapabilityManifest", "933/c4_unknown_nested_field_refused"),
    (
        "ProcessExecutionPolicy",
        "933/c7_missing_or_empty_required_ids_refused",
    ),
    (
        "ExternalAgentExecutionRequest",
        "933/c7_missing_or_empty_required_ids_refused",
    ),
    (
        "ExternalAgentPurpose",
        "933/c6_wrong_or_unknown_tags_refused",
    ),
    (
        "OperationAuthorityOpenRequest",
        "933/c7_missing_or_empty_required_ids_refused",
    ),
    (
        "OperationAuthorityOpenReceipt",
        "933/c4_unknown_nested_field_refused",
    ),
    (
        "OperationAuthorityCloseRequest",
        "933/c7_missing_or_empty_required_ids_refused",
    ),
    (
        "OperationAuthorityCloseReceipt",
        "933/c4_unknown_nested_field_refused",
    ),
    (
        "OperationAuthorityTerminalOutcome",
        "933/c6_wrong_or_unknown_tags_refused",
    ),
    (
        "ProviderRuntimeContract",
        "933/c10_unsafe_migration_refuses",
    ),
    (
        "CognitiveProviderRuntimeContract",
        "933/c9_explicit_legacy_migration_preserves_evidence",
    ),
    (
        "ProviderRuntimePreflightReceipt",
        "933/c8_unsupported_versions_refused",
    ),
    (
        "ProviderExecutionEvidence",
        "933/c15_decoders_refuse_before_trusted_output_no_candidate_finish",
    ),
    (
        "ProviderAuthenticationState",
        "933/c6_wrong_or_unknown_tags_refused",
    ),
    (
        "ProviderMcpServerContract",
        "933/c11_opaque_data_cannot_smuggle_control_meaning",
    ),
    (
        "ProviderMcpToolProfileBinding",
        "933/c11_opaque_data_cannot_smuggle_control_meaning",
    ),
    (
        "ProviderStructuredOutputMode",
        "933/c6_wrong_or_unknown_tags_refused",
    ),
    (
        "ExternalResultCompletenessReceipt",
        "933/c15_decoders_refuse_before_trusted_output_no_candidate_finish",
    ),
    (
        "ProviderInvocationOutcome",
        "933/c6_wrong_or_unknown_tags_refused",
    ),
    (
        "ProviderInvocationOutcomeClass",
        "933/c6_wrong_or_unknown_tags_refused",
    ),
    (
        "ProviderInvocationState",
        "933/c6_wrong_or_unknown_tags_refused",
    ),
    (
        "ProviderInvocationTransition",
        "933/c6_wrong_or_unknown_tags_refused",
    ),
    (
        "ProviderTimeoutClass",
        "933/c7_missing_or_empty_required_ids_refused",
    ),
    (
        "ProviderTimeoutProfile",
        "933/c7_missing_or_empty_required_ids_refused",
    ),
    (
        "CompilePacketToolInput",
        "933/c11_opaque_data_cannot_smuggle_control_meaning",
    ),
    (
        "CompilePacketToolInputVisitor",
        "933/c13_exact_exceptions_invalidate_on_use_change",
    ),
    (
        "ObserveInput",
        "933/c12_ambiguous_alias_default_cannot_grant_authority",
    ),
    (
        "ObserveHint",
        "933/c12_ambiguous_alias_default_cannot_grant_authority",
    ),
    (
        "AgentCandidateSubmitInput",
        "933/c15_decoders_refuse_before_trusted_output_no_candidate_finish",
    ),
    (
        "AgentCandidateCurationInput",
        "933/c15_decoders_refuse_before_trusted_output_no_candidate_finish",
    ),
    (
        "ProviderInvocationAttempt",
        "933/c7_missing_or_empty_required_ids_refused",
    ),
    (
        "ProviderRoutePolicy",
        "933/c16_scope_schema_routing_dependencies_visibility_unchanged",
    ),
    (
        "ProviderRoutePolicyBinding",
        "933/c16_scope_schema_routing_dependencies_visibility_unchanged",
    ),
    (
        "ProviderRouteReadinessGate",
        "933/c7_missing_or_empty_required_ids_refused",
    ),
    (
        "ProviderRouteReadinessVerdict",
        "933/c6_wrong_or_unknown_tags_refused",
    ),
    (
        "ProviderDeclaredBudget",
        "933/c7_missing_or_empty_required_ids_refused",
    ),
    (
        "ProviderIdentityCheck",
        "933/c6_wrong_or_unknown_tags_refused",
    ),
    (
        "ProviderFailureIncident",
        "933/c6_wrong_or_unknown_tags_refused",
    ),
    (
        "ProviderRootCauseStatus",
        "933/c6_wrong_or_unknown_tags_refused",
    ),
    (
        "ProviderReconciliationMethod",
        "933/c6_wrong_or_unknown_tags_refused",
    ),
    (
        "ProviderReconciliationRecord",
        "933/c6_wrong_or_unknown_tags_refused",
    ),
    (
        "ProviderResultCompleteness",
        "933/c15_decoders_refuse_before_trusted_output_no_candidate_finish",
    ),
];

/// The three `known_non_clean` identifiers the container must carry. Case 12 asserts
/// every row exists, is complete, and is the recorded handoff for a path this lane
/// must NOT repair.
///
/// The third row, `no_t04_decoder_enforces_schema_version`, is the version half of the
/// same statement case 8 makes executable: no decoder of the four T04 files compares
/// `schema_version` against its constant, because the member is a plain `String` on
/// every version-bearing surface (`crates/eliot-types/src/external_agent.rs:36`, `:82`,
/// `:176`, `:228`, and `:262` for the legacy contract). An unsupported version is
/// therefore ACCEPTED as data and never promoted, and the comparison lives in
/// `eliot-app` / `eliot-engine` CALLERS. The first two rows are this lane's own
/// named-owner handoff for `ObserveInput.hint`'s `alias = "kind"` and
/// `ObserveInput.schema_version`'s helper default.
const KNOWN_NON_CLEAN_IDS: [&str; 3] = [
    "c12_observe_hint_alias",
    "c12_observe_schema_version_default",
    "no_t04_decoder_enforces_schema_version",
];

/// The member key each unknown-field refusal fixture injects, paired with that
/// fixture's corpus key. Case 1 asserts that every one of these fixtures carries
/// its pinned key, so a fixture that forgot the injection cannot pass a
/// refusal case by being broken for some other reason.
const INJECTED_MEMBERS: [(&str, &str); 13] = [
    (
        "c3_AdapterRequest_unknown_outer_member_refuse",
        "c3_unknown_outer_member",
    ),
    (
        "c3_AdapterResult_unknown_outer_member_refuse",
        "c3_unknown_outer_member",
    ),
    (
        "c4_AdapterRequest_context_unknown_member_refuse",
        "c4_unknown_nested_member",
    ),
    (
        "c4_CapabilityManifest_authority_profile_unknown_member_refuse",
        "c4_unknown_nested_member",
    ),
    (
        "c4_AdapterHealth_unknown_member_refuse",
        "c4_unknown_member",
    ),
    (
        "c4_AdapterResult_observation_unknown_member_refuse",
        "c4_unknown_member",
    ),
    (
        "c4_CapabilityManifest_unknown_nested_member_refuse",
        "c4_unknown_nested_member",
    ),
    (
        "c4_OperationAuthorityOpenReceipt_unknown_nested_member_refuse",
        "c4_unknown_nested_member",
    ),
    (
        "c4_OperationAuthorityCloseReceipt_unknown_nested_member_refuse",
        "c4_unknown_nested_member",
    ),
    (
        "c4_CapabilityManifest_unknown_capability_tag_refuse",
        "c4_unknown_capability",
    ),
    (
        "c11_ProviderMcpServerContract_unknown_member_refuse",
        "c11_unknown_mcp_server_member",
    ),
    (
        "c11_ProviderMcpToolProfileBinding_unknown_member_refuse",
        "c11_unknown_mcp_profile_member",
    ),
    (
        "c11_CompilePacketToolInput_unknown_member_refuse",
        "c11_unknown_flat_member",
    ),
];

/// The unknown-VARIANT tag each unknown-variant refusal fixture injects, paired with
/// that fixture's corpus key, and pinned so case 1 can prove the injection is really
/// there. EVERY row here is a value OUTSIDE a closed set of spelled variants, read by
/// a decoder that fails closed on it, and the second element is that exact out-of-set
/// spelling. For a plain `enum` the corpus value is a bare JSON string; for the four
/// struct fixtures it sits at a nested member
/// (`ProviderInvocationTransition`, `ProviderFailureIncident` and
/// `ProviderReconciliationRecord`, plus `ProviderInvocationOutcome` through its own
/// nested `ProviderInvocationOutcomeClass`).
///
/// TWO REFUSAL FIXTURES ARE DELIBERATELY NOT IN THIS TABLE, because neither injects an
/// unknown variant and putting them here would have made the table claim something
/// false about them:
///
/// - `c6_ProviderIdentityCheck_wrong_typed_matched_refuse` injects a wrong TYPE into a
///   DECLARED member: `matched` is a real member of `ProviderIdentityCheck`
///   (`Option<bool>`, `crates/eliot-types/src/provider_invocation.rs:554`), and the
///   document states it as the JSON string `"true"`. Nothing about it is an unknown
///   variant - `ProviderIdentityCheck` has no variants at all - so its key is a
///   DECLARED member name and case 6 (b) pins it there.
/// - `c6_wrong_typed_status_tag_refuse` is the three-byte document `933` handed to
///   `AdapterResultStatus` as a bare, UNQUOTED, non-variant token. Its "tag" is the
///   whole document, so a `contains("933")` precondition would have been satisfied by
///   the substring appearing anywhere in any fixture; case 6 (c) pins the whole
///   document instead.
const INJECTED_TAGS: [(&str, &str); 15] = [
    (
        "c6_AdapterResultStatus_unknown_tag_refuse",
        "c6_unknown_result_status",
    ),
    (
        "c6_AdapterState_unknown_tag_refuse",
        "c6_unknown_adapter_state",
    ),
    (
        "c6_AdapterClass_unknown_tag_refuse",
        "c6_unknown_adapter_class",
    ),
    (
        "c6_ExternalAgentPurpose_unknown_tag_refuse",
        "c6_unknown_external_agent_purpose",
    ),
    (
        "c6_OperationAuthorityTerminalOutcome_unknown_tag_refuse",
        "c6_unknown_terminal_outcome",
    ),
    (
        "c6_ProviderAuthenticationState_unknown_tag_refuse",
        "c6_unknown_authentication_state",
    ),
    (
        "c6_ProviderStructuredOutputMode_unknown_tag_refuse",
        "c6_unknown_structured_output_mode",
    ),
    (
        "c6_ProviderInvocationOutcomeClass_unknown_tag_refuse",
        "c6_unknown_outcome_class",
    ),
    (
        "c6_ProviderInvocationState_unknown_tag_refuse",
        "C6_UNKNOWN_INVOCATION_STATE",
    ),
    (
        "c6_ProviderRouteReadinessVerdict_unknown_tag_refuse",
        "c6_unknown_readiness_verdict",
    ),
    (
        "c6_ProviderRootCauseStatus_unknown_tag_refuse",
        "c6_unknown_root_cause_status",
    ),
    (
        "c6_ProviderReconciliationRecord_unknown_method_tag_refuse",
        "c6_unknown_reconciliation_method",
    ),
    (
        "c6_ProviderInvocationTransition_unknown_to_tag_refuse",
        "C6_UNKNOWN_INVOCATION_STATE",
    ),
    (
        "c6_ProviderFailureIncident_unknown_root_cause_status_tag_refuse",
        "c6_unknown_root_cause_status",
    ),
    (
        "c6_ProviderReconciliationRecord_unknown_completeness_tag_refuse",
        "c6_unknown_completeness",
    ),
];

/// The required member each missing-member refusal fixture omits, paired with
/// that fixture's corpus key. `c7_OperationAuthorityOpenRequest_empty_task_id_refuse`
/// is deliberately absent: it carries an EMPTY value rather than omitting a
/// member, and case 7 asserts that separately. `c7_ExternalAgentExecutionRequest_absent_max_turns_or_steps_refuse`
/// is absent for a different reason, read from the source: the member of that name
/// still occurs inside `launch_contract`, so only the top level is checked, and case
/// 7 checks it there.
const MISSING_MEMBERS: [(&str, &str); 8] = [
    (
        "c7_AdapterLimits_absent_circuit_breaker_failures_refuse",
        "circuit_breaker_failures",
    ),
    (
        "c7_ProcessExecutionPolicy_absent_allowed_executables_refuse",
        "allowed_executables",
    ),
    (
        "c7_OperationAuthorityOpenRequest_absent_idempotency_key_refuse",
        "idempotency_key",
    ),
    (
        "c7_OperationAuthorityCloseRequest_absent_role_lease_id_refuse",
        "role_lease_id",
    ),
    (
        "c7_ProviderTimeoutProfile_absent_policy_version_refuse",
        "policy_version",
    ),
    (
        "c7_ProviderInvocationAttempt_absent_timeout_class_refuse",
        "timeout_class",
    ),
    (
        "c7_ProviderRouteReadinessGate_absent_last_successful_smoke_ref_refuse",
        "last_successful_smoke_ref",
    ),
    (
        "c7_ProviderDeclaredBudget_absent_cancellation_grace_ms_refuse",
        "cancellation_grace_ms",
    ),
];

/// The exact permitted key list of the flat compile-packet tool input, spelled
/// once. It is `COMPILE_PACKET_TOOL_FIELDS`
/// (`crates/eliot-types/src/mcp_contract.rs:52-60`): the wrapper's own two
/// members plus the five current `CompilePacketL3Request` members. Case 13
/// compares the decoder's own refusal message against this list and case 16
/// compares the published schema's property set against it, so the decoder, the
/// visitor's arms and the published schema cannot drift apart unnoticed.
const PERMITTED_PACKET_KEYS: [&str; 7] = [
    "project_id",
    "task_id",
    "goal",
    "candidate_handles",
    "max_tokens",
    "material_frame",
    "memory_mode",
];

/// The exact member names this file injects or omits, spelled once so an
/// assertion names the exact key instead of an anonymous "an unknown member".
/// Every value here is a key that really occurs in the container's own fixture
/// text, because `assert_named_refusal` requires the refusal message to name it.
const NESTED_REQUEST_MEMBER: &str = "request";
const UNKNOWN_PACKET_MEMBER: &str = "unexpected_packet_scope";
const MISSING_PACKET_MEMBER: &str = "goal";
const TASK_ID_MEMBER: &str = "task_id";
const ALIAS_HINT_MEMBER: &str = "kind";
const CANONICAL_HINT_MEMBER: &str = "hint";
const UNKNOWN_HINT_MEMBER: &str = "c12_unknown_observe_member";
const SCHEMA_VERSION_MEMBER: &str = "schema_version";
const OBSOLETE_SCHEMA_VERSION_MEMBER: &str = "schema_version_v1";
const LEGACY_CONTRACT_MEMBER: &str = "cognitive_provider_runtime_v1";
const MAX_TOKENS_MEMBER: &str = "max_tokens";
const CANDIDATE_ONLY_MEMBER: &str = "candidate_only";
const PROTECTED_MEMBER: &str = "protected";
const UNSAFE_INSTRUCTION_MEMBER: &str = "unsafe_instruction";

/// The one allocated type with NO wire document of its own, and the reason, read
/// from the source rather than a gap left by a run: it is a private
/// `serde::de::Visitor`, not a `Deserialize`
/// (`crates/eliot-types/src/mcp_contract.rs:50`), so
/// `c2_CompilePacketToolInputVisitor_canonical` does not and must not exist.
const PRIVATE_VISITOR_TYPE: &str = "CompilePacketToolInputVisitor";

/// This file's own TEXT, so "no stored fixture is unnamed here" is a check this file
/// can FAIL, not a comparison of two hand-typed lists.
///
/// WHY THE PREVIOUS MECHANISM WAS VACUOUS, measured: it compared a hand-copied
/// `READ_FIXTURE_KEYS` array against the container's own `fixtures` keys, and that
/// array was referenced at exactly two places - both inside
/// `assert_no_silent_orphans` - and never at a single `raw()` call site. Adding one
/// key to the container, adding the same key to the hand-copied array and bumping its
/// declared length left EVERY assertion passing, because nothing connected the array
/// to any read. Case 1(d) iterates `meta.types`, never fixture keys, so it could not
/// catch the addition either. The array was a second transcription of the container
/// that the container's owner could satisfy without this file ever naming the key.
///
/// This constant removes the second transcription. The expectation is now derived from
/// the FILE ITSELF and from the CONTAINER: a stored fixture is covered only if its
/// exact key token appears in this file's source, which is the same property that
/// makes a `raw("...")` read of it possible.
const SOURCE: &str = include_str!("serde_t04_agent.rs");

/// Every fixture key the container stores, as it stores them. Read through the
/// container's own `fixtures` object, never through a table kept beside it.
fn container_fixture_keys() -> Vec<String> {
    corpus()
        .get("fixtures")
        .and_then(serde_json::Value::as_object)
        .expect("the corpus must carry a `fixtures` object")
        .keys()
        .cloned()
        .collect()
}

/// NO SILENT ORPHANS, checked against something that can fail.
///
/// Both directions are derived from the FILE or the CONTAINER, never from a second
/// hand-typed copy:
///
/// 1. every key the container stores must be NAMED in this file's own text, because
///    that is what a `raw()` read of it is - a fixture no line of this file names is
///    a fixture no test reads, i.e. a silent orphan;
/// 2. every key `meta.known_unused` declares unused must be genuinely NOT named here,
///    so the escape hatch cannot quietly become a second home for a live fixture; and
/// 3. `meta.known_unused` must be empty, because (1) leaves no fixture unread.
fn assert_no_silent_orphans(meta: &serde_json::Value) {
    let declared = meta
        .get("known_unused")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("the corpus must record a `meta.known_unused` list"));
    for entry in declared {
        let key = entry
            .get("fixture")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("every `meta.known_unused` entry needs a `fixture`"));
        assert!(
            entry
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|reason| !reason.trim().is_empty()),
            "the `meta.known_unused` entry for {key} must give one clause of reason"
        );
        let token = format!("\"{key}\"");
        assert!(
            !SOURCE.contains(token.as_str()),
            "{key} is listed as unused but this file DOES name it, so the declaration is stale"
        );
    }
    let container_keys = container_fixture_keys();
    assert!(
        !container_keys.is_empty(),
        "the container must store at least one fixture"
    );
    // The NINETEEN canonical fixtures this file reads through a CONSTRUCTED name are
    // named by the same `format!("c2_{type_name}_canonical")` that cases 1(d) and 2
    // sweep, so their keys are not spelled out as literals anywhere. That set is derived
    // here from `meta.types` - the container's own inventory - so it is a fact about the
    // CONTAINER, not a second transcription of it. Everything else must be spelled out
    // literally, because a literal `raw("...")` is the only other way this file reads.
    let constructed_canonicals: Vec<String> = meta_types()
        .iter()
        .map(|type_name| format!("c2_{type_name}_canonical"))
        .collect();
    for key in &container_keys {
        let token = format!("\"{key}\"");
        let read_by_literal = SOURCE.contains(token.as_str());
        let read_by_construction = constructed_canonicals.iter().any(|name| name == key);
        assert!(
            read_by_literal || read_by_construction,
            "the container stores fixture {key}, but NO line of this file names it and it is \
             not the `c2_<Type>_canonical` of an allocated type, so no test reads it: that is \
             a silent orphan. Either a test must read {key}, or the container must drop it and \
             list it in `meta.known_unused` with one clause of reason"
        );
    }
    assert_eq!(
        declared.len(),
        0,
        "every stored fixture is named by this file, so `meta.known_unused` must be empty, \
         not a stale list: {declared:?}"
    );
}

// ---------------------------------------------------------------------------
// Decode and comparison helpers.
// ---------------------------------------------------------------------------

/// The one decode entry point this file uses: the stored raw text goes straight
/// into the deserializer, with no intermediate document of any kind.
fn decode<T: serde::de::DeserializeOwned>(document: &str) -> Result<T, serde_json::Error> {
    serde_json::from_str(document)
}

/// A WITNESS parse, used only to compare an already-decoded field against the
/// fixture's own value. It never feeds a decoder.
fn witness(document: &str) -> serde_json::Value {
    serde_json::from_str(document).unwrap_or_else(|error| {
        panic!("a stored fixture must parse as JSON for comparison: {error}")
    })
}

/// One member of a fixture document, owned. The document is parsed HERE, so no
/// borrow of a local can escape; the member is cloned out and every caller gets
/// its own `Value`, which is the one convention this file uses for a raw
/// witness. A fixture whose text is not valid JSON at all (case 14) is never
/// read through this.
fn member_value(document: &str, key: &str) -> serde_json::Value {
    witness(document)
        .get(key)
        .cloned()
        .unwrap_or_else(|| panic!("the fixture must carry a member `{key}`"))
}

fn member(document: &str, key: &str) -> String {
    member_value(document, key)
        .as_str()
        .unwrap_or_else(|| panic!("fixture member `{key}` must be a string"))
        .to_owned()
}

fn member_number(document: &str, key: &str) -> u64 {
    member_value(document, key)
        .as_u64()
        .unwrap_or_else(|| panic!("fixture member `{key}` must be a non-negative integer"))
}

/// The same read for a field declared `usize` (`CompilePacketL3Request::max_tokens`),
/// so the comparison is between two `usize` values and not a `usize`/`u64` pair.
fn member_usize(document: &str, key: &str) -> usize {
    usize::try_from(member_number(document, key))
        .unwrap_or_else(|_| panic!("fixture member `{key}` must fit a usize"))
}

/// A member that is legitimately an integer or an explicit `null`, so an absent
/// observation and a stated one stay different facts
/// (I05-16-common-durable-fields.md:46).
fn member_number_or_null(document: &str, key: &str) -> Option<i64> {
    let value = member_value(document, key);
    if value.is_null() {
        return None;
    }
    Some(
        value
            .as_i64()
            .unwrap_or_else(|| panic!("fixture member `{key}` must be an integer or null")),
    )
}

fn member_bool(document: &str, key: &str) -> bool {
    member_value(document, key)
        .as_bool()
        .unwrap_or_else(|| panic!("fixture member `{key}` must be a boolean"))
}

fn member_texts(document: &str, key: &str) -> Vec<String> {
    member_value(document, key)
        .as_array()
        .unwrap_or_else(|| panic!("fixture member `{key}` must be an array"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("fixture member `{key}` must hold only strings"))
                .to_owned()
        })
        .collect()
}

/// How many times the raw text carries `"<key>"`. A repeated member is exactly
/// what a `Value` intermediate would have collapsed, so this count is the proof
/// that the raw route saw something the value route could not.
fn repeats(document: &str, key: &str) -> usize {
    let needle = format!("\"{key}\"");
    document.matches(needle.as_str()).count()
}

/// Assert that the types this case OWNS are exactly the types this case names.
///
/// `touched` is the list of allocated types this case claims as its HOME BINDING, and
/// both directions are asserted:
///
/// 1. every type named in `touched` is bound to `case` by the frozen allocation, so a
///    case cannot claim a type the table gives to another case; and
/// 2. every type the frozen allocation binds to `case` is named in `touched`, so an
///    allocated type cannot be left with a home case that never says it owns it.
///
/// Direction 2 needed its own assertion rather than falling out of the length check: an
/// equal length plus direction 1 does NOT imply it, because a `touched` list that
/// repeats one name satisfies both while an owned type goes unnamed.
///
/// WHAT THIS DOES NOT CLAIM, which is the whole point of the wording: `touched` is not
/// every type whose decoder runs anywhere in the test body. A case may legitimately
/// decode a type another case owns - a carrier type decoded only to reach a nested
/// decoder, or a type whose own member is the subject - and that decode is recorded by
/// `assert_also_decodes`, which names the real owner. Carriers are therefore NOT listed
/// here, because the binding belongs to the type that refused.
fn assert_case_binding(case: &str, touched: &[&str]) {
    let bound = types_bound_to_case(case);
    assert_eq!(
        bound.len(),
        touched.len(),
        "case {case} must own exactly the types it names: the table binds {bound:?}, the test names {touched:?}"
    );
    for name in touched {
        assert!(
            bound.iter().any(|entry| entry.as_str() == *name),
            "case {case} names {name}, which the frozen allocation does not bind to it; bound there: {bound:?}"
        );
    }
    // `bound` is a `Vec<String>` and `touched` is a `&[&str]`, so `name` here is a
    // `&String` while `touched.contains(..)` is `[&str]::contains` and wants a
    // `&&str`. The `.as_str()` in the argument is what reconciles the two: passing
    // `name` directly is a type error, not a missing comparison.
    for name in &bound {
        assert!(
            touched.contains(&name.as_str()),
            "the frozen allocation binds {name} to {case}, so that case must name it as one of \
             the types it owns; it names {touched:?}"
        );
    }
}

/// Assert that this case ALSO decodes `type_name`, WITHOUT claiming it as owned here.
///
/// `TYPE_HOME_CASE` gives every allocated type exactly ONE home case, so a case may
/// legitimately decode a type another case owns: case 11 reads
/// `ProviderRuntimeContract`'s own `nonsecret_environment` member, and that type's home
/// binding is case 10. `assert_case_binding` deliberately does not cover that - it claims
/// only the types a case OWNS - so this helper is where such a decode is recorded, and it
/// records the OWNER with it. Without it a case would decode a type it has no claim on
/// and say nothing about where the claim actually lives.
///
/// Three facts are checked, so neither this comment nor the caller can go stale: the
/// canonical fixture really decodes as the named type; the frozen allocation really
/// carries that type at all; and it really binds it to `owner_case` specifically. If the
/// table ever moves a type to a different home, this fails HERE, at the call site that
/// decodes it, instead of leaving a case quietly reading another case's type.
///
/// No value is compared here: the claim is that the decode happens on this case's behalf.
/// What the decoded value proves is the owning case's business, through
/// `assert_bytes_unchanged` or through its own member comparisons.
fn assert_also_decodes<T>(type_name: &str, owner_case: &str)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let fixture = format!("c2_{type_name}_canonical");
    let stored = raw(&fixture);
    let _decoded: T = decode(&stored)
        .unwrap_or_else(|error| panic!("{fixture} must decode as {type_name}: {error}"));
    let owner = TYPE_HOME_CASE
        .iter()
        .find(|(name, _)| *name == type_name)
        .map_or_else(
            || panic!("{type_name} is decoded here, so it must appear in the frozen allocation"),
            |(_, case)| *case,
        );
    assert_eq!(
        owner, owner_case,
        "{type_name} is decoded by this case, but the frozen allocation gives it the home \
         binding {owner}, not {owner_case}: pass the case that really owns it, so this call \
         cannot outlive the table it names"
    );
}

/// The canonical fixture of an allocated STRUCT round-trips: the stored text
/// decodes, and a second decode/re-encode cycle reproduces the first cycle's
/// bytes exactly, so a value's re-encoded form is a fixed point. Every failure
/// message names the STORED DOCUMENT (`c2_<Type>_canonical`) as well as the
/// type, so a failure identifies which fixture to look at. NO DIGEST is computed
/// here: the two encodings are compared as BYTES, which is the whole claim, and
/// a digest recomputed over two byte strings that `assert_eq!` has already
/// compared would restate it rather than evidence it.
///
/// The ONE helper for this claim, used by every case that binds a struct type -
/// cases 3, 4, 6, 7, 8, 10, 11, 12, 14, 15 and 16 - and by case 2's own
/// byte-stability sweep over one representative type per production file. The
/// plain `enum` types use `assert_enum_spelling` instead, which pins one
/// variant's wire spelling in both directions rather than a fixed point.
/// `ProviderInvocationOutcome` is a STRUCT, not an enum, and uses that helper
/// too; for that type the call is a document round trip against the stored bytes,
/// as its own documentation states.
fn assert_bytes_unchanged<T>(type_name: &str)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let fixture = format!("c2_{type_name}_canonical");
    let stored = raw(&fixture);
    assert!(
        !stored.is_empty(),
        "the canonical fixture {fixture} must not be empty"
    );
    let first: T = decode(&stored)
        .unwrap_or_else(|error| panic!("{fixture} must decode as {type_name}: {error}"));
    let once = serde_json::to_string(&first)
        .unwrap_or_else(|error| panic!("{type_name} must re-encode: {error}"));
    let second: T = decode(&once)
        .unwrap_or_else(|error| panic!("the re-encoded {type_name} must decode again: {error}"));
    let twice = serde_json::to_string(&second)
        .unwrap_or_else(|error| panic!("the re-decoded {type_name} must re-encode: {error}"));
    assert_eq!(
        twice, once,
        "{fixture}: a second decode/re-encode cycle must not move a single byte"
    );
    assert_eq!(
        serde_json::to_string(&first).expect("re-encoding must succeed"),
        once,
        "{fixture}: encoding one value twice must move no byte"
    );
}

/// The canonical fixture of an allocated plain `enum` round-trips to its own
/// stored bytes: the derived serializer's output for one variant is exactly the
/// bare JSON string the container stores, which pins that variant's wire
/// spelling in both directions.
///
/// The helper is generic over `DeserializeOwned + Serialize` and makes no claim
/// about which kind it is handed, so exactly ONE call in this file passes it a
/// STRUCT: `ProviderInvocationOutcome`
/// (`crates/eliot-types/src/provider_invocation.rs:531`), which has fourteen
/// public members (`:532-545`), no variant and no wire spelling. Its canonical
/// fixture is therefore a JSON OBJECT, and for that call the assertion is a
/// whole-document round trip - the decoded struct re-encodes to exactly the
/// stored bytes. That is what the call proves there, and it is a real assertion
/// binding that allocation row, which is why the call is kept under this name
/// rather than renamed or dropped.
fn assert_enum_spelling<T>(type_name: &str)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let fixture = format!("c2_{type_name}_canonical");
    let stored = raw(&fixture);
    let value: T = decode(&stored)
        .unwrap_or_else(|error| panic!("{fixture} must decode as {type_name}: {error}"));
    assert_eq!(
        serde_json::to_string(&value).expect("the decoded variant must re-encode"),
        stored,
        "{type_name} must re-encode to the exact stored wire spelling of its variant"
    );
}

/// Assert that a refusal is a REFUSAL, not a different failure wearing the same
/// fixture: the text really carries the injected token, the decode really fails,
/// and the message really is of the named kind and names that token.
fn assert_named_refusal<T>(fixture_name: &str, token: &str, needle: &str)
where
    T: serde::de::DeserializeOwned,
{
    let text = raw(fixture_name);
    assert!(
        text.contains(token),
        "{fixture_name} must actually carry the token `{token}` under test"
    );
    let Err(error) = decode::<T>(&text) else {
        panic!("{fixture_name} must be refused");
    };
    let message = error.to_string();
    assert!(
        message.contains(needle),
        "{fixture_name} must be refused as `{needle}`, got: {message}"
    );
    assert!(
        message.contains(token),
        "{fixture_name}'s refusal must name `{token}`, got: {message}"
    );
}

/// Assert that a document which really OMITS `member` is refused BY NAME with a
/// missing-field error - the omission counterpart of `assert_named_refusal`.
///
/// The two helpers differ in the precondition each one PROVES, and getting them
/// backwards turns a correct fixture into a failing test. `assert_named_refusal`
/// proves the token is PRESENT, which is exactly right for an INJECTION fixture and
/// exactly wrong for an OMISSION fixture: a document built by deleting one member
/// carries that member's name nowhere, so a `text.contains(member)` precondition can
/// never hold for it. This helper therefore proves the quoted member name is ABSENT
/// from the stored text, that the decode really fails, that the message is a
/// `missing field` refusal, and that the refusal names the member anyway - which is
/// what serde's own `missing field` error does: it quotes the absent member's key, so
/// the name is available from the message alone even though it is gone from the
/// document.
fn assert_omitted_member_refusal<T>(fixture_name: &str, member: &str)
where
    T: serde::de::DeserializeOwned,
{
    let text = raw(fixture_name);
    assert!(
        !text.contains(&format!("\"{member}\"")),
        "{fixture_name} must actually OMIT `{member}`, and must not carry it at any depth"
    );
    let Err(error) = decode::<T>(&text) else {
        panic!("{fixture_name} must be refused for the absent member `{member}`");
    };
    let message = error.to_string();
    assert!(
        message.contains("missing field"),
        "{fixture_name} must be refused as `missing field`, got: {message}"
    );
    assert!(
        message.contains(member),
        "{fixture_name}'s refusal must name the absent member `{member}`, got: {message}"
    );
}

/// The name of the ONE top-level member whose key this document carries twice, or
/// `None` when no member repeats or more than one does.
///
/// Used only where a fixture names the SHAPE of the repeated member rather than its
/// name - the audit's "duplicate null/value keys reject" rows, which differ only in
/// whether the repeated member is a bool or a number. Deriving the name from the
/// stored text is what lets those rows keep a real "exactly twice" proof instead of
/// asserting a hand-typed key the container might not have repeated.
fn resolve_repeated_member(document: &str) -> Option<String> {
    let object = witness(document);
    let object = object.as_object()?;
    let repeated: Vec<&String> = object
        .keys()
        .filter(|key| repeats(document, key) == 2)
        .collect();
    match repeated.as_slice() {
        [only] => Some((*only).clone()),
        _ => None,
    }
}

/// Assert that a fixture is ACCEPTED by the delivered decoder, and return the
/// decoded value so the caller can compare its fields against the fixture text.
fn assert_accepted<T>(fixture_name: &str) -> T
where
    T: serde::de::DeserializeOwned,
{
    let text = raw(fixture_name);
    decode(&text).unwrap_or_else(|error| panic!("{fixture_name} must be accepted: {error}"))
}

// WORK_UNIT_CASE: 933/c1_allocation_complete
#[test]
#[allow(clippy::too_many_lines)]
fn c1_allocation_complete_across_the_four_in_scope_files() {
    // (a) The container itself, on the fixed shape the contract requires.
    let container = corpus();
    let meta = container
        .get("meta")
        .unwrap_or_else(|| panic!("the corpus must carry `meta`"));
    assert_eq!(
        meta.get("issue").and_then(serde_json::Value::as_u64),
        Some(933),
        "the corpus must name issue 933"
    );
    assert_eq!(
        meta.get("family").and_then(serde_json::Value::as_str),
        Some("T04"),
        "the corpus must name family T04"
    );
    assert_eq!(
        meta.get("case_count").and_then(serde_json::Value::as_u64),
        Some(16),
        "the corpus must record the sixteen preserved acceptance cases"
    );
    assert_eq!(
        meta.get("allocated_type_count")
            .and_then(serde_json::Value::as_u64),
        Some(54),
        "the corpus must record the 54 allocated types"
    );
    assert!(
        meta.get("inventory")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .contains("#933"),
        "the corpus must name the frozen inventory allocation it claims to cover"
    );
    assert!(
        meta.get("raw_bytes_rule")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .contains("string"),
        "the corpus must record the raw-bytes rule: a repeated member survives only inside a string"
    );
    // NO SILENT ORPHANS: every fixture key in the container is read by this file,
    // and anything that were not would have to be listed in `meta.known_unused`
    // with one clause of reason rather than quietly left behind.
    assert_no_silent_orphans(meta);
    let mut top_level_keys: Vec<&str> = container.as_object().map_or_else(
        || panic!("the corpus must be a JSON object"),
        |object| object.keys().map(String::as_str).collect(),
    );
    top_level_keys.sort_unstable();
    assert_eq!(
        top_level_keys,
        vec!["fixtures", "known_non_clean", "meta"],
        "the container must carry exactly `meta`, `fixtures` and `known_non_clean`. The keys are \
         compared as a SET, and the expected set is written in the order a decoded map yields \
         them: `serde_json::Map` is a `BTreeMap` unless serde_json's `preserve_order` feature is \
         enabled (serde_json-1.0.151/src/map.rs:3, \"By default the map is backed by a \
         BTreeMap\", and :24), no manifest in this workspace enables it or depends on indexmap, so \
         `keys()` iterates ALPHABETICALLY for any container, written in any order"
    );
    // The ORDER claim, read from the container's own bytes and never from a
    // decoded `Value`, because the decoded map above cannot carry it. Each token
    // is located by its FIRST occurrence in the stored text: `meta` is the
    // container's first member, so no other key can precede it, and each later
    // token is preceded only by members the container writes before it - a
    // nested or quoted mention of a token would still come after that token's
    // own top-level member. The offsets compared here are therefore the offsets
    // the container was physically written at.
    let stored = corpus_text();
    let top_level_offset = |key: &str| {
        let token = format!("\"{key}\"");
        stored
            .find(&token)
            .unwrap_or_else(|| panic!("the container must carry a top-level key `{key}`"))
    };
    let (meta_at, fixtures_at, known_non_clean_at) = (
        top_level_offset("meta"),
        top_level_offset("fixtures"),
        top_level_offset("known_non_clean"),
    );
    assert!(
        meta_at < fixtures_at && fixtures_at < known_non_clean_at,
        "the container must physically carry `meta`, then `fixtures`, then `known_non_clean`. \
         Measured offsets in the stored text were meta {meta_at}, fixtures {fixtures_at}, \
         known_non_clean {known_non_clean_at}; a decoded map could not have shown this, because \
         it is BTreeMap-backed and iterates alphabetically"
    );

    // (b) The 54 allocated names: this file's table and the container's
    // `meta.types` must be the same set, with no duplicate on either side.
    let from_container = meta_types();
    let from_table: Vec<String> = TYPE_HOME_CASE
        .iter()
        .map(|(type_name, _)| (*type_name).to_owned())
        .collect();
    assert_eq!(from_container.len(), 54, "`meta.types` must name 54 types");
    assert_eq!(
        from_table.len(),
        54,
        "the allocation table must carry 54 rows"
    );
    let mut container_sorted = from_container.clone();
    container_sorted.sort();
    let mut table_sorted = from_table.clone();
    table_sorted.sort();
    assert_eq!(
        table_sorted, container_sorted,
        "this file's allocation table and the container's `meta.types` must be the same 54 names"
    );
    let mut container_unique = container_sorted.clone();
    container_unique.dedup();
    assert_eq!(
        container_unique.len(),
        from_container.len(),
        "`meta.types` must not repeat a type"
    );
    let mut table_unique = table_sorted.clone();
    table_unique.dedup();
    assert_eq!(
        table_unique.len(),
        from_table.len(),
        "the allocation table must not repeat a type"
    );

    // (c) Every case is discharged by exactly one marker, and the markers are the
    // sixteen fixed slugs. Each home-case test below re-asserts its own row.
    let mut homes: Vec<&str> = TYPE_HOME_CASE.iter().map(|(_, case)| *case).collect();
    homes.sort_unstable();
    let mut unique_homes = homes.clone();
    unique_homes.dedup();
    for home in &unique_homes {
        assert!(
            CASE_MARKERS.contains(home),
            "every home case in the table must be one of the sixteen fixed markers, got {home}"
        );
    }
    let mut area_cases = 0_usize;
    for marker in CASE_MARKERS {
        let owned = types_bound_to_case(marker).len();
        if marker.starts_with("933/c1_")
            || marker.starts_with("933/c2_")
            || marker.starts_with("933/c5_")
        {
            area_cases += 1;
            assert_eq!(
                owned, 0,
                "{marker} is an area case: it owns no allocated type's home binding"
            );
        } else {
            assert!(owned > 0, "{marker} must own at least one allocated type");
        }
    }
    assert_eq!(
        unique_homes.len() + area_cases,
        CASE_MARKERS.len(),
        "the home cases and the area cases between them must account for all sixteen markers: {unique_homes:?} plus {area_cases} area cases"
    );

    // (d) Every allocated type has a canonical raw-byte fixture, and every
    // refusal fixture really carries the key or tag this file asserts about it.
    assert!(
        types_bound_to_case("933/c1_allocation_complete").is_empty(),
        "case 1 owns no allocated type"
    );
    for type_name in &from_container {
        let fixture = format!("c2_{type_name}_canonical");
        if type_name.as_str() == PRIVATE_VISITOR_TYPE {
            // ASSERTED, NOT SKIPPED: this allocation row has NO wire document of
            // its own, because the type is a private `serde::de::Visitor` and not
            // a `Deserialize`. Case 13 discharges it through the decoder that
            // constructs it, so no fixture is invented for it here and the
            // container must stay without one.
            assert!(
                corpus()
                    .get("fixtures")
                    .and_then(|fixtures| fixtures.get(&fixture))
                    .is_none(),
                "{PRIVATE_VISITOR_TYPE} is a private Visitor, not a Deserialize: the container \
                 must NOT carry a wire document named {fixture}"
            );
            continue;
        }
        assert!(
            !raw(&fixture).is_empty(),
            "{fixture} must exist and must not be empty"
        );
    }
    for (fixture_name, key) in INJECTED_MEMBERS {
        assert!(
            raw(fixture_name).contains(key),
            "{fixture_name} must actually inject `{key}`"
        );
    }
    for (fixture_name, tag) in INJECTED_TAGS {
        assert!(
            raw(fixture_name).contains(tag),
            "{fixture_name} must actually carry the unknown tag `{tag}`"
        );
    }
    for (fixture_name, key) in MISSING_MEMBERS {
        assert!(
            !raw(fixture_name).contains(&format!("\"{key}\"")),
            "{fixture_name} must actually OMIT `{key}`"
        );
    }

    // (e) The four-file allocation is proved by decoding, not by the existence of
    // a file: one representative type per production file, out of raw stored text.
    let request_text = raw("c2_AdapterRequest_canonical");
    decode::<AdapterRequest>(&request_text)
        .expect("crates/eliot-types/src/adapter.rs: the canonical AdapterRequest must decode");
    // The claim "the canonical AdapterRequest decodes AND carries its own request_id"
    // belongs to case 3, which is the case that BINDS `AdapterRequest`; it is asserted
    // there against this same document. Case 1 owns only the four-file reachability
    // proof, so it decodes and does not restate another case's claim.
    let contract_text = raw("c2_ProviderRuntimeContract_canonical");
    let contract: ProviderRuntimeContract = decode(&contract_text)
        .expect("src/external_agent.rs: the canonical ProviderRuntimeContract must decode");
    assert_eq!(
        contract.schema_version,
        member(&contract_text, SCHEMA_VERSION_MEMBER),
        "src/external_agent.rs: the decoded contract must carry its own schema_version"
    );
    let observe_text = raw("c2_ObserveInput_canonical");
    let observe: ObserveInput =
        decode(&observe_text).expect("src/mcp_contract.rs: the canonical ObserveInput must decode");
    assert_eq!(
        observe.text_or_structured_payload,
        member_value(&observe_text, "text_or_structured_payload"),
        "src/mcp_contract.rs: the decoded ObserveInput must carry its own payload"
    );
    let attempt_text = raw("c2_ProviderInvocationAttempt_canonical");
    let attempt: ProviderInvocationAttempt = decode(&attempt_text)
        .expect("src/provider_invocation.rs: the canonical attempt must decode");
    assert_eq!(
        attempt.invocation_attempt_id,
        member(&attempt_text, "invocation_attempt_id"),
        "src/provider_invocation.rs: the decoded attempt must carry its own id"
    );
}

// WORK_UNIT_CASE: 933/c2_unchanged_valid_bytes
#[test]
#[allow(clippy::too_many_lines)]
fn c2_current_valid_bytes_and_digests_round_trip_unchanged() {
    // Case 2 owns no allocated type's home binding: it is the byte-stability case
    // over the current canonical documents, one or more representatives per
    // production file. The NAME above keeps this delivery's frozen wording for
    // the issue's `c2_unchanged_valid_bytes` case; no digest is computed in this
    // file, and the stability claim is the encoded BYTES, compared directly.
    assert!(
        types_bound_to_case("933/c2_unchanged_valid_bytes").is_empty(),
        "case 2 binds no allocated type"
    );
    assert_bytes_unchanged::<AdapterRequest>("AdapterRequest");
    assert_bytes_unchanged::<AdapterResult>("AdapterResult");
    assert_bytes_unchanged::<ProviderRuntimeContract>("ProviderRuntimeContract");
    assert_bytes_unchanged::<CognitiveProviderRuntimeContract>("CognitiveProviderRuntimeContract");
    assert_bytes_unchanged::<CompilePacketToolInput>("CompilePacketToolInput");
    assert_bytes_unchanged::<ObserveInput>("ObserveInput");
    assert_bytes_unchanged::<AgentCandidateSubmitInput>("AgentCandidateSubmitInput");
    assert_bytes_unchanged::<ProviderInvocationAttempt>("ProviderInvocationAttempt");
    assert_bytes_unchanged::<ProviderReconciliationRecord>("ProviderReconciliationRecord");
    assert_bytes_unchanged::<ExternalResultCompletenessReceipt>(
        "ExternalResultCompletenessReceipt",
    );

    // Every stored canonical fixture is a JSON document as written: the raw route
    // needs no repair step before a decoder sees it.
    for type_name in meta_types() {
        // The private visitor has no wire document and none may be invented; its
        // byte behaviour is case 13's, through `CompilePacketToolInput`.
        if type_name.as_str() == PRIVATE_VISITOR_TYPE {
            continue;
        }
        let stored = raw(&format!("c2_{type_name}_canonical"));
        let parsed = witness(&stored);
        assert!(
            parsed.is_object() || parsed.is_string(),
            "the canonical fixture of {type_name} must be a JSON object or a bare variant string"
        );
    }

    // The `max_tokens` default and the flat `CompilePacketToolInput` layout are
    // OBSERVABLE BEHAVIOUR and are asserted from the canonical document's own
    // bytes here as well as in case 11, which owns the type's binding.
    let packet_text = raw("c2_CompilePacketToolInput_canonical");
    let packet: CompilePacketToolInput =
        decode(&packet_text).expect("the canonical flat compile-packet document must decode");
    assert_eq!(
        packet.request.max_tokens,
        member_usize(&packet_text, MAX_TOKENS_MEMBER),
        "the flat packet's `max_tokens` must decode to the top-level member's own value"
    );
    assert!(
        !packet_text.contains(&format!("\"{NESTED_REQUEST_MEMBER}\"")),
        "the flat packet layout has no nested `request` object on the wire"
    );
}

// WORK_UNIT_CASE: 933/c3_unknown_outer_field_refused
#[test]
#[allow(clippy::too_many_lines)]
fn c3_unknown_protected_top_level_field_refused() {
    assert_case_binding(
        "933/c3_unknown_outer_field_refused",
        &["AdapterRequest", "AdapterResult"],
    );
    assert_bytes_unchanged::<AdapterRequest>("AdapterRequest");
    assert_bytes_unchanged::<AdapterResult>("AdapterResult");

    // (a) AdapterRequest, the outermost allocated request envelope. Its
    // `deny_unknown_fields` (`crates/eliot-types/src/adapter.rs:145`) is what makes
    // this a refusal at all: without it a derived struct would silently drop the
    // injected member and keep going.
    let canonical = raw("c2_AdapterRequest_canonical");
    let tampered = raw("c3_AdapterRequest_unknown_outer_member_refuse");
    assert_ne!(
        tampered, canonical,
        "the injected document must actually differ from the canonical one"
    );
    assert_named_refusal::<AdapterRequest>(
        "c3_AdapterRequest_unknown_outer_member_refuse",
        "c3_unknown_outer_member",
        "unknown field",
    );
    // (b) AdapterResult, the outermost allocated result envelope; its nested
    // observation and error members are case 4's and case 14's business.
    assert_ne!(
        raw("c3_AdapterResult_unknown_outer_member_refuse"),
        raw("c2_AdapterResult_canonical"),
        "the injected result document must actually differ from the canonical one"
    );
    assert_named_refusal::<AdapterResult>(
        "c3_AdapterResult_unknown_outer_member_refuse",
        "c3_unknown_outer_member",
        "unknown field",
    );
    // Control: without the injected member both documents decode, so the refusals
    // above are caused by the unknown key and not by an otherwise-broken fixture.
    let accepted_request: AdapterRequest =
        decode(&canonical).expect("the canonical request must decode");
    assert_eq!(
        accepted_request.request_id,
        member(&canonical, "request_id"),
        "the accepted counterpart must carry the document's own request_id"
    );
    let accepted_result: AdapterResult =
        decode(&raw("c2_AdapterResult_canonical")).expect("the canonical result must decode");
    assert_eq!(
        accepted_result.status,
        AdapterResultStatus::Succeeded,
        "the accepted counterpart must keep its own single `succeeded` status variant"
    );
    assert!(
        canonical.contains("request_id"),
        "the canonical document must really carry the member the control compares"
    );
    // (e) VALUE ASSERTION, so `AdapterResult`'s row here is not a refusal and a
    // self-consistency round trip alone: the decoded result carries the document's
    // own identity member, compared against that document's own text.
    let result_text = raw("c2_AdapterResult_canonical");
    let result: AdapterResult = decode(&result_text).expect("the canonical result must decode");
    assert_eq!(
        result.result_id,
        member(&result_text, "result_id"),
        "the decoded result must carry the document's own result id"
    );
}

// WORK_UNIT_CASE: 933/c4_unknown_nested_field_refused
#[test]
#[allow(clippy::too_many_lines)]
fn c4_unknown_protected_nested_field_refused() {
    assert_case_binding(
        "933/c4_unknown_nested_field_refused",
        &[
            "AdapterContext",
            "AdapterAuthorityProfile",
            "AdapterCapability",
            "AdapterHealth",
            "AdapterObservation",
            "CapabilityManifest",
            "OperationAuthorityOpenReceipt",
            "OperationAuthorityCloseReceipt",
        ],
    );

    // (a) AdapterContext at DEPTH TWO: an AdapterRequest document whose injected
    // member sits inside `context`. The refusal therefore comes from
    // AdapterContext's own `deny_unknown_fields`
    // (`crates/eliot-types/src/adapter.rs:126`), not from the envelope's. The
    // fixture is named for the CARRIER document it really is, not for a
    // standalone `AdapterContext` document.
    let nested_context = raw("c4_AdapterRequest_context_unknown_member_refuse");
    assert!(
        nested_context.contains("c4_unknown_nested_member"),
        "the fixture must actually inject the unknown nested member"
    );
    assert_named_refusal::<AdapterRequest>(
        "c4_AdapterRequest_context_unknown_member_refuse",
        "c4_unknown_nested_member",
        "unknown field",
    );
    assert_ne!(
        nested_context,
        raw("c3_AdapterRequest_unknown_outer_member_refuse"),
        "the nested-injection fixture must differ from the outer-injection fixture"
    );
    assert_bytes_unchanged::<AdapterContext>("AdapterContext");

    // (b) AdapterAuthorityProfile at DEPTH TWO: a CapabilityManifest document whose
    // injected member sits inside `authority_profile`. The fixture is named for
    // that carrier, and the refusal is AdapterAuthorityProfile's own
    // (`crates/eliot-types/src/adapter.rs:69`).
    assert_named_refusal::<CapabilityManifest>(
        "c4_CapabilityManifest_authority_profile_unknown_member_refuse",
        "c4_unknown_nested_member",
        "unknown field",
    );
    assert_bytes_unchanged::<AdapterAuthorityProfile>("AdapterAuthorityProfile");
    assert_bytes_unchanged::<CapabilityManifest>("CapabilityManifest");

    // (c) AdapterObservation at DEPTH TWO: an `AdapterResult` document whose injected
    // member sits inside ONE ENTRY of its `observations` array, so the refusal is
    // `AdapterObservation`'s own `deny_unknown_fields`
    // (`crates/eliot-types/src/adapter.rs:196-197`) and not the envelope's
    // (`adapter.rs:179-180`). The fixture is built from `c2_AdapterResult_canonical`,
    // NOT from the c3 outer-injection variant, so the only difference from a document
    // this case already accepts is that one nested member. The bare
    // `c4_AdapterObservation_unknown_member_refuse` key is DELETED: that document was a
    // top-level `AdapterObservation` with no `observations` array at all, so it was
    // case 3's claim (an unknown top-level member), not this case's, and decoding it as
    // `AdapterResult` stopped at `missing field \`observation_id\`` before ever reaching
    // the injected member.
    let nested_observation = raw("c4_AdapterResult_observation_unknown_member_refuse");
    assert!(
        nested_observation.contains("c4_unknown_member"),
        "the fixture must actually inject `c4_unknown_member` inside an observations entry"
    );
    assert_eq!(
        witness(&nested_observation)
            .get("observations")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(1),
        "the fixture must carry exactly one observations entry, so the injection is the \
         only difference from the canonical result"
    );
    assert_ne!(
        nested_observation,
        raw("c3_AdapterResult_unknown_outer_member_refuse"),
        "the nested-observation fixture must differ from the outer-injection fixture"
    );
    assert_named_refusal::<AdapterResult>(
        "c4_AdapterResult_observation_unknown_member_refuse",
        "c4_unknown_member",
        "unknown field",
    );
    assert_bytes_unchanged::<AdapterObservation>("AdapterObservation");

    // (d) The remaining nested surfaces refuse at their own object level: for their
    // consumers the named type IS the nested level, so the fixture is a document of
    // the named type itself with one unknown member at its own top level - which is
    // why its injected key is `c4_unknown_member` and not a "nested" spelling.
    assert_named_refusal::<AdapterHealth>(
        "c4_AdapterHealth_unknown_member_refuse",
        "c4_unknown_member",
        "unknown field",
    );
    assert_bytes_unchanged::<AdapterHealth>("AdapterHealth");
    assert_named_refusal::<OperationAuthorityOpenReceipt>(
        "c4_OperationAuthorityOpenReceipt_unknown_nested_member_refuse",
        "c4_unknown_nested_member",
        "unknown field",
    );
    assert_bytes_unchanged::<OperationAuthorityOpenReceipt>("OperationAuthorityOpenReceipt");
    assert_named_refusal::<OperationAuthorityCloseReceipt>(
        "c4_OperationAuthorityCloseReceipt_unknown_nested_member_refuse",
        "c4_unknown_nested_member",
        "unknown field",
    );
    assert_bytes_unchanged::<OperationAuthorityCloseReceipt>("OperationAuthorityCloseReceipt");
    // The same rule inside `CapabilityManifest` itself: an unknown member in its
    // own nested `limits` object.
    assert_named_refusal::<CapabilityManifest>(
        "c4_CapabilityManifest_unknown_nested_member_refuse",
        "c4_unknown_nested_member",
        "unknown field",
    );

    // (e) AdapterCapability is a closed control variant, not a struct: an unknown
    // capability tag is refused by the enum's own decoder.
    assert_enum_spelling::<AdapterCapability>("AdapterCapability");
    assert_named_refusal::<CapabilityManifest>(
        "c4_CapabilityManifest_unknown_capability_tag_refuse",
        "c4_unknown_capability",
        "unknown variant",
    );
    let canonical_capability = raw("c2_AdapterCapability_canonical");
    assert!(
        !canonical_capability.trim_start().starts_with('{'),
        "the canonical AdapterCapability fixture must be a bare variant string, not an object"
    );

    // (f) VALUE ASSERTIONS, so no row above is a self-consistency round trip alone:
    // each of the seven STRUCT types this case binds is decoded from its own
    // canonical fixture and compared, member by member, against the very text the
    // container stores for that member. `AdapterCapability` is the eighth type this
    // case binds and the only plain enum among them; it is already pinned to its own
    // stored bytes in (e).
    let context_text = raw("c2_AdapterContext_canonical");
    let context: AdapterContext =
        decode(&context_text).expect("the canonical AdapterContext document must decode");
    assert_eq!(
        context.trace_id,
        member(&context_text, "trace_id"),
        "the decoded context must carry the document's own trace id"
    );
    let authority_text = raw("c2_AdapterAuthorityProfile_canonical");
    let authority: AdapterAuthorityProfile =
        decode(&authority_text).expect("the canonical authority-profile document must decode");
    assert_eq!(
        authority.can_write_truth,
        member_bool(&authority_text, "can_write_truth"),
        "the decoded authority profile must carry the document's own truth flag"
    );
    let manifest_text = raw("c2_CapabilityManifest_canonical");
    let manifest: CapabilityManifest =
        decode(&manifest_text).expect("the canonical manifest document must decode");
    assert_eq!(
        manifest.adapter_id,
        member(&manifest_text, "adapter_id"),
        "the decoded manifest must carry the document's own adapter id"
    );
    assert_eq!(
        manifest.enabled_by_default,
        member_bool(&manifest_text, "enabled_by_default"),
        "the decoded manifest must carry the document's own enabled-by-default flag"
    );
    let health_text = raw("c2_AdapterHealth_canonical");
    let health: AdapterHealth =
        decode(&health_text).expect("the canonical health document must decode");
    assert_eq!(
        health.adapter_id,
        member(&health_text, "adapter_id"),
        "the decoded health must carry the document's own adapter id"
    );
    // ONE representative TIME-ENCODED member, pinned to the encoding its own
    // attribute demands. `AdapterHealth.checked_at` carries
    // `#[serde(with = "time::serde::rfc3339")]`
    // (`crates/eliot-types/src/adapter.rs:239-240`), so it is the FIELD's
    // serializer - not `OffsetDateTime`'s own human-readable `Serialize` - that has
    // to reproduce the member text the fixture stores. The member is therefore read
    // back out of the re-encoded DOCUMENT, so the attribute is what is compared and
    // nothing here invents a plausible-looking timestamp of its own.
    let health_reencoded = serde_json::to_string(&health).expect("the health must re-encode");
    assert_eq!(
        witness(&health_reencoded)
            .get("checked_at")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("the re-encoded health must carry `checked_at`")),
        member(&health_text, "checked_at"),
        "`AdapterHealth.checked_at` must re-encode to the fixture's own rfc3339 text"
    );
    let observation_text = raw("c2_AdapterObservation_canonical");
    let observation: AdapterObservation =
        decode(&observation_text).expect("the canonical observation document must decode");
    assert_eq!(
        observation.observation_id,
        member(&observation_text, "observation_id"),
        "the decoded observation must carry the document's own observation id"
    );
    let open_receipt_text = raw("c2_OperationAuthorityOpenReceipt_canonical");
    let open_receipt: OperationAuthorityOpenReceipt =
        decode(&open_receipt_text).expect("the canonical open receipt document must decode");
    assert_eq!(
        open_receipt.state_hash,
        member(&open_receipt_text, "state_hash"),
        "the decoded open receipt must carry the document's own state hash"
    );
    let close_receipt_text = raw("c2_OperationAuthorityCloseReceipt_canonical");
    let close_receipt: OperationAuthorityCloseReceipt =
        decode(&close_receipt_text).expect("the canonical close receipt document must decode");
    assert_eq!(
        close_receipt.state_hash,
        member(&close_receipt_text, "state_hash"),
        "the decoded close receipt must carry the document's own state hash"
    );
}

// WORK_UNIT_CASE: 933/c5_duplicate_keys_refused
#[test]
#[allow(clippy::too_many_lines)]
fn c5_duplicate_invocation_discriminator_identity_authority_keys_refused() {
    assert!(
        types_bound_to_case("933/c5_duplicate_keys_refused").is_empty(),
        "case 5 is an area case and binds no allocated type"
    );

    // Every document here is VALID JSON TEXT that repeats one object member - the
    // one thing a `serde_json::Value` intermediate cannot represent. Each row's
    // raw-text facts are therefore something only the raw route could see: the text
    // carries the member twice, while a value parse of the SAME text yields one
    // occurrence and could never raise the refusal below.
    let duplicates: [(&str, &str, &str); 14] = [
        (
            "c5_AdapterRequest_duplicate_request_id_refuse",
            "request_id",
            "invocation identity",
        ),
        (
            "c5_area_repeated_status_discriminator_in_adapter_result_refuse",
            "status",
            "discriminator",
        ),
        (
            "c5_ExternalAgentExecutionRequest_duplicate_prompt_sha256_refuse",
            "prompt_sha256",
            "identity digest",
        ),
        (
            "c5_OperationAuthorityOpenRequest_duplicate_idempotency_key_refuse",
            "idempotency_key",
            "authority key",
        ),
        (
            "c5_ProviderInvocationAttempt_duplicate_frozen_input_hash_refuse",
            "frozen_input_hash",
            "frozen invocation input digest",
        ),
        (
            "c5_area_repeated_purpose_in_operation_authority_open_request_refuse",
            "purpose",
            "control variant",
        ),
        (
            "c5_area_repeated_result_completeness_in_reconciliation_record_refuse",
            "result_completeness",
            "completeness control variant",
        ),
        (
            "c5_area_repeated_policy_id_in_provider_route_policy_binding_refuse",
            "policy_id",
            "route binding identity",
        ),
        (
            "c5_area_repeated_schema_version_in_provider_runtime_contract_refuse",
            "schema_version",
            "wire version",
        ),
        (
            "c5_area_repeated_max_tokens_in_compile_packet_tool_input_refuse",
            "max_tokens",
            "token target",
        ),
        (
            "c5_area_repeated_task_id_in_compile_packet_tool_input_refuse",
            "task_id",
            "request identity",
        ),
        (
            "c5_area_repeated_memory_mode_in_compile_packet_tool_input_refuse",
            "memory_mode",
            "wrapper memory-mode",
        ),
        (
            "c5_ProviderInvocationAttempt_duplicate_null_then_value_bool_refuse",
            "<the repeated bool member, resolved from the document>",
            "required-nullable bool",
        ),
        (
            "c5_ProviderInvocationAttempt_duplicate_null_then_value_number_refuse",
            "<the repeated number member, resolved from the document>",
            "required-nullable number",
        ),
    ];
    for (fixture_name, key, role) in duplicates {
        let text = raw(fixture_name);
        // The two OWNER-AUDIT rows state their repeated member's SHAPE, not its name,
        // because the audit item is "duplicate null/value keys reject" for a
        // required-nullable member and the two documents differ only in whether the
        // repeated member is a bool or a number. Their member names are resolved from
        // the documents themselves rather than hand-typed, so each row still proves a
        // REAL repeat of exactly one member instead of asserting a key the container
        // might not have repeated.
        let key: String = if key.starts_with('<') {
            resolve_repeated_member(&text).unwrap_or_else(|| {
                panic!("{fixture_name} must repeat exactly one member, or the refusal below is unproven")
            })
        } else {
            key.to_owned()
        };
        assert_eq!(
            repeats(&text, &key),
            2,
            "{fixture_name} must repeat the {role} member `{key}` exactly twice in its raw text"
        );
        // The lossy route, shown to be lossy on the very same bytes: a value parse
        // keeps ONE occurrence and re-renders a document without the repeat.
        let collapsed = witness(&text);
        assert!(
            collapsed.get(key.as_str()).is_some(),
            "a `Value` parse of {fixture_name} sees ONE `{key}`, which is exactly why the raw route is required"
        );
        assert_ne!(
            text,
            serde_json::to_string(&collapsed).expect("the witness must re-render"),
            "a `Value` round trip would rewrite {fixture_name} and lose the repeat"
        );
    }

    // The eleven distinct decoders, named individually so each refusal is attributed
    // to the type that raises it rather than to one shared helper. serde's derived
    // struct decoder reports the repeat while it reads the raw map, before it can
    // keep either occurrence, and `CompilePacketToolInput`'s manual visitor carries
    // its own explicit `duplicate_field` guards (`crates/eliot-types/src/mcp_contract.rs:78-133`).
    assert_named_refusal::<AdapterRequest>(
        "c5_AdapterRequest_duplicate_request_id_refuse",
        "request_id",
        "duplicate field",
    );
    assert_named_refusal::<AdapterResult>(
        "c5_area_repeated_status_discriminator_in_adapter_result_refuse",
        "status",
        "duplicate field",
    );
    assert_named_refusal::<ExternalAgentExecutionRequest>(
        "c5_ExternalAgentExecutionRequest_duplicate_prompt_sha256_refuse",
        "prompt_sha256",
        "duplicate field",
    );
    assert_named_refusal::<OperationAuthorityOpenRequest>(
        "c5_OperationAuthorityOpenRequest_duplicate_idempotency_key_refuse",
        "idempotency_key",
        "duplicate field",
    );
    assert_named_refusal::<OperationAuthorityOpenRequest>(
        "c5_area_repeated_purpose_in_operation_authority_open_request_refuse",
        "purpose",
        "duplicate field",
    );
    assert_named_refusal::<ProviderInvocationAttempt>(
        "c5_ProviderInvocationAttempt_duplicate_frozen_input_hash_refuse",
        "frozen_input_hash",
        "duplicate field",
    );
    assert_named_refusal::<ProviderReconciliationRecord>(
        "c5_area_repeated_result_completeness_in_reconciliation_record_refuse",
        "result_completeness",
        "duplicate field",
    );
    assert_named_refusal::<ProviderRoutePolicyBinding>(
        "c5_area_repeated_policy_id_in_provider_route_policy_binding_refuse",
        "policy_id",
        "duplicate field",
    );
    assert_named_refusal::<ProviderRuntimeContract>(
        "c5_area_repeated_schema_version_in_provider_runtime_contract_refuse",
        "schema_version",
        "duplicate field",
    );
    assert_named_refusal::<CompilePacketToolInput>(
        "c5_area_repeated_max_tokens_in_compile_packet_tool_input_refuse",
        "max_tokens",
        "duplicate field",
    );
    assert_named_refusal::<CompilePacketToolInput>(
        "c5_area_repeated_task_id_in_compile_packet_tool_input_refuse",
        "task_id",
        "duplicate field",
    );
    assert_named_refusal::<CompilePacketToolInput>(
        "c5_area_repeated_memory_mode_in_compile_packet_tool_input_refuse",
        "memory_mode",
        "duplicate field",
    );
    // The audit's "duplicate null/value keys reject" item, on the required-nullable
    // members. These are the documents where one member appears TWICE - the first
    // occurrence `null`, the second a value - which is the shape that would let an
    // "absent means nothing recorded" fact silently become a recorded one if the
    // decoder kept the later occurrence. It does not: a DERIVED struct decoder emits
    // `duplicate_field(name)` while reading the raw map, per field
    // (`serde_derive-1.0.229/src/de/struct_.rs:266-273`), which is why last-wins
    // applies only to members typed `serde_json::Value` or a map type
    // (`serde_json-1.0.151/src/value/de.rs:136-145`) and not here.
    for (fixture_name, kind) in [
        (
            "c5_ProviderInvocationAttempt_duplicate_null_then_value_bool_refuse",
            "bool",
        ),
        (
            "c5_ProviderInvocationAttempt_duplicate_null_then_value_number_refuse",
            "number",
        ),
    ] {
        let text = raw(fixture_name);
        let member = resolve_repeated_member(&text).unwrap_or_else(|| {
            panic!("{fixture_name} must repeat exactly ONE member for this row to mean anything")
        });
        let token = format!("\"{member}\"");
        let first = text
            .find(token.as_str())
            .expect("the resolved member was found by `repeats`");
        let second = text[first + token.len()..]
            .find(token.as_str())
            .map(|offset| offset + first + token.len())
            .expect("the resolved member occurs twice");
        // The JSON value that follows an occurrence, up to the next `,` or `}`.
        let value_after = |from: usize| {
            text[from..]
                .trim_start()
                .trim_start_matches(':')
                .trim_start()
                .split([',', '}'])
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned()
        };
        assert_eq!(
            value_after(first + token.len()),
            "null",
            "{fixture_name}: the FIRST occurrence of the repeated {kind} member `{member}` must \
             be an explicit null"
        );
        assert_ne!(
            value_after(second + token.len()),
            "null",
            "{fixture_name}: the SECOND occurrence of `{member}` must be a real {kind} value, or \
             this is not the null-then-value shape"
        );
        let Err(duplicate_error) = decode::<ProviderInvocationAttempt>(&text) else {
            panic!("{fixture_name} must be refused: a repeated member is never last-wins here")
        };
        let duplicate_message = duplicate_error.to_string();
        assert!(
            duplicate_message.contains("duplicate field"),
            "{fixture_name} must be refused as `duplicate field`, got: {duplicate_message}"
        );
        assert!(
            duplicate_message.contains(member.as_str()),
            "{fixture_name}'s refusal must name the repeated member `{member}`, got: \
             {duplicate_message}"
        );
    }

    // `c5_ExternalAgentExecutionRequest_duplicate_prompt_sha256_refuse` is the one row in
    // this family whose document was, until the container owner inserted a missing
    // separating comma, INVALID JSON rather than valid JSON carrying a repeat - and an
    // invalid document would have been refused for the wrong reason, proving nothing
    // about duplicates. Both halves of the claim are therefore asserted on its own
    // bytes, before the shared loop above treats it like any other row: the text PARSES,
    // and `prompt_sha256` occurs exactly twice in it.
    let prompt_sha_text = raw("c5_ExternalAgentExecutionRequest_duplicate_prompt_sha256_refuse");
    assert!(
        serde_json::from_str::<serde_json::Value>(&prompt_sha_text).is_ok(),
        "the duplicate-prompt-digest document must be VALID JSON: a repeat is representable \
         as text and is exactly what the raw route preserves"
    );
    assert_eq!(
        repeats(&prompt_sha_text, "prompt_sha256"),
        2,
        "the duplicate-prompt-digest document must carry `prompt_sha256` exactly twice"
    );

    // Control: each canonical counterpart, with each member once, decodes. The
    // canonical `AdapterRequest` carries its own invocation id, and that claim is
    // case 3's (it is the case that BINDS `AdapterRequest`); here the same document is
    // decoded only to show that the refusal above is caused by the repeat and not by an
    // otherwise-undecodable counterpart.
    assert_accepted::<AdapterRequest>("c2_AdapterRequest_canonical");
    let result: AdapterResult = assert_accepted("c2_AdapterResult_canonical");
    assert_eq!(
        result.status,
        AdapterResultStatus::Succeeded,
        "the accepted counterpart must keep its own single `succeeded` status"
    );
    let open_text = raw("c2_OperationAuthorityOpenRequest_canonical");
    let open_request: OperationAuthorityOpenRequest =
        decode(&open_text).expect("the canonical operation-authority request must decode");
    assert_eq!(
        open_request.schema_version,
        member(&open_text, SCHEMA_VERSION_MEMBER),
        "the accepted counterpart must keep the document's own schema_version"
    );
}

// WORK_UNIT_CASE: 933/c6_wrong_or_unknown_tags_refused
#[test]
#[allow(clippy::too_many_lines)]
fn c6_wrong_or_unknown_control_tags_refused() {
    assert_case_binding(
        "933/c6_wrong_or_unknown_tags_refused",
        &[
            "AdapterResultStatus",
            "AdapterState",
            "AdapterClass",
            "ExternalAgentPurpose",
            "OperationAuthorityTerminalOutcome",
            "ProviderAuthenticationState",
            "ProviderStructuredOutputMode",
            "ProviderInvocationOutcome",
            "ProviderInvocationOutcomeClass",
            "ProviderInvocationState",
            "ProviderRouteReadinessVerdict",
            "ProviderRootCauseStatus",
            "ProviderReconciliationMethod",
            "ProviderInvocationTransition",
            "ProviderIdentityCheck",
            "ProviderFailureIncident",
            "ProviderReconciliationRecord",
        ],
    );

    // (a) TWELVE plain control enums and ONE struct, asserted in one block by
    // one generic call - NOT because the kinds are the same, and the block does
    // not claim they are.
    //
    // The twelve enums are closed `rename_all` enums with no catch-all variant,
    // so an unknown wire spelling cannot become a defaulted variant (APPENDIX-P
    // line 13), and each spelling is pinned in both directions by re-encoding to
    // the stored bytes: `c2_<Type>_canonical` holds a bare JSON string and the
    // decoded variant re-encodes to exactly those stored bytes.
    //
    // The thirteenth name, `ProviderInvocationOutcome`, is NOT an enum and NOT a
    // closed control variant. It is a STRUCT
    // (`crates/eliot-types/src/provider_invocation.rs:531`, with
    // `#[serde(deny_unknown_fields)]` at `:530` and fourteen public members at
    // `:532-545`), so it has NO wire spelling and NO variant to pin, and its
    // canonical fixture `c2_ProviderInvocationOutcome_canonical` is a JSON OBJECT
    // rather than a bare string. The `assert_enum_spelling` call on it therefore
    // asserts a STRUCT ROUND TRIP - the decoded struct re-encodes to exactly the
    // stored document bytes - and nothing about a spelling. Its closedness claim
    // is the refusal below instead: an unknown `outcome_class` value is refused by
    // `ProviderInvocationOutcome`'s own nested `ProviderInvocationOutcomeClass`
    // decoder (`provider_invocation.rs:55`), which IS a closed enum.
    assert_enum_spelling::<AdapterResultStatus>("AdapterResultStatus");
    assert_enum_spelling::<AdapterState>("AdapterState");
    assert_enum_spelling::<AdapterClass>("AdapterClass");
    assert_enum_spelling::<ExternalAgentPurpose>("ExternalAgentPurpose");
    assert_enum_spelling::<OperationAuthorityTerminalOutcome>("OperationAuthorityTerminalOutcome");
    assert_enum_spelling::<ProviderAuthenticationState>("ProviderAuthenticationState");
    assert_enum_spelling::<ProviderStructuredOutputMode>("ProviderStructuredOutputMode");
    assert_enum_spelling::<ProviderInvocationOutcome>("ProviderInvocationOutcome");
    assert_enum_spelling::<ProviderInvocationOutcomeClass>("ProviderInvocationOutcomeClass");
    assert_enum_spelling::<ProviderInvocationState>("ProviderInvocationState");
    assert_enum_spelling::<ProviderRouteReadinessVerdict>("ProviderRouteReadinessVerdict");
    assert_enum_spelling::<ProviderRootCauseStatus>("ProviderRootCauseStatus");
    assert_enum_spelling::<ProviderReconciliationMethod>("ProviderReconciliationMethod");

    assert_named_refusal::<AdapterResultStatus>(
        "c6_AdapterResultStatus_unknown_tag_refuse",
        "c6_unknown_result_status",
        "unknown variant",
    );
    assert_named_refusal::<AdapterState>(
        "c6_AdapterState_unknown_tag_refuse",
        "c6_unknown_adapter_state",
        "unknown variant",
    );
    assert_named_refusal::<AdapterClass>(
        "c6_AdapterClass_unknown_tag_refuse",
        "c6_unknown_adapter_class",
        "unknown variant",
    );
    assert_named_refusal::<ExternalAgentPurpose>(
        "c6_ExternalAgentPurpose_unknown_tag_refuse",
        "c6_unknown_external_agent_purpose",
        "unknown variant",
    );
    assert_named_refusal::<OperationAuthorityTerminalOutcome>(
        "c6_OperationAuthorityTerminalOutcome_unknown_tag_refuse",
        "c6_unknown_terminal_outcome",
        "unknown variant",
    );
    assert_named_refusal::<ProviderAuthenticationState>(
        "c6_ProviderAuthenticationState_unknown_tag_refuse",
        "c6_unknown_authentication_state",
        "unknown variant",
    );
    assert_named_refusal::<ProviderStructuredOutputMode>(
        "c6_ProviderStructuredOutputMode_unknown_tag_refuse",
        "c6_unknown_structured_output_mode",
        "unknown variant",
    );
    assert_named_refusal::<ProviderInvocationOutcome>(
        "c6_ProviderInvocationOutcome_unknown_outcome_class_tag_refuse",
        "c6_unknown_outcome_class",
        "unknown variant",
    );
    assert_named_refusal::<ProviderInvocationOutcomeClass>(
        "c6_ProviderInvocationOutcomeClass_unknown_tag_refuse",
        "c6_unknown_outcome_class",
        "unknown variant",
    );
    assert_named_refusal::<ProviderInvocationState>(
        "c6_ProviderInvocationState_unknown_tag_refuse",
        "C6_UNKNOWN_INVOCATION_STATE",
        "unknown variant",
    );
    assert_named_refusal::<ProviderRouteReadinessVerdict>(
        "c6_ProviderRouteReadinessVerdict_unknown_tag_refuse",
        "c6_unknown_readiness_verdict",
        "unknown variant",
    );
    assert_named_refusal::<ProviderRootCauseStatus>(
        "c6_ProviderRootCauseStatus_unknown_tag_refuse",
        "c6_unknown_root_cause_status",
        "unknown variant",
    );
    // `ProviderReconciliationMethod` is only reachable through the record that
    // carries it, so its unknown tag is asserted through that record below.

    // (b) The four structs whose closed nested variant must also fail closed.
    assert_bytes_unchanged::<ProviderInvocationTransition>("ProviderInvocationTransition");
    assert_named_refusal::<ProviderInvocationTransition>(
        "c6_ProviderInvocationTransition_unknown_to_tag_refuse",
        "C6_UNKNOWN_INVOCATION_STATE",
        "unknown variant",
    );
    assert_bytes_unchanged::<ProviderIdentityCheck>("ProviderIdentityCheck");
    // `ProviderIdentityCheck.matched` is `Option<bool>`
    // (`crates/eliot-types/src/provider_invocation.rs:554`, read on line 554 as
    // `pub matched: Option<bool>,` in the struct opened at `:550`): a quoted string
    // is a TYPE refusal, not an unknown-variant one, and is asserted as such.
    // `ProviderIdentityCheck` is a STRUCT with no variants, so this row is NOT in
    // `INJECTED_TAGS` - that table is for out-of-set VARIANT spellings, and naming a
    // declared member there would have said `matched` was an unknown variant. It is
    // pinned here instead, and specifically: the quoted member VALUE is asserted, so
    // the row cannot be satisfied by the substring `true` occurring somewhere else in
    // the document.
    let matched_text = raw("c6_ProviderIdentityCheck_wrong_typed_matched_refuse");
    assert!(
        matched_text.contains("\"matched\":\"true\""),
        "the fixture must really state the DECLARED member `matched` as the quoted string \
         \"true\", which is a wrong-typed value for an `Option<bool>`"
    );
    assert_named_refusal::<ProviderIdentityCheck>(
        "c6_ProviderIdentityCheck_wrong_typed_matched_refuse",
        "true",
        "invalid type",
    );
    assert_bytes_unchanged::<ProviderFailureIncident>("ProviderFailureIncident");
    assert_named_refusal::<ProviderFailureIncident>(
        "c6_ProviderFailureIncident_unknown_root_cause_status_tag_refuse",
        "c6_unknown_root_cause_status",
        "unknown variant",
    );
    assert_bytes_unchanged::<ProviderReconciliationRecord>("ProviderReconciliationRecord");
    assert_named_refusal::<ProviderReconciliationRecord>(
        "c6_ProviderReconciliationRecord_unknown_completeness_tag_refuse",
        "c6_unknown_completeness",
        "unknown variant",
    );
    assert_named_refusal::<ProviderReconciliationRecord>(
        "c6_ProviderReconciliationRecord_unknown_method_tag_refuse",
        "c6_unknown_reconciliation_method",
        "unknown variant",
    );

    // (c) A WRONG-TYPED tag: a bare JSON number where a string variant is required
    // is not coerced into one. The stored document is `933`, which is VALID JSON -
    // that is why the key says `_refuse` and not `_text`, and why it is not in case
    // 14's `catch_unwind` family. The KIND of refusal is the point of this row, and it
    // is NOT `invalid type`: `serde_json::Deserialize for AdapterResultStatus` is the
    // derived enum decoder, and its `deserialize_enum` visits the map-or-unit arm
    // (`serde_json-1.0.151/src/de.rs`), which for a number that is not a unit variant
    // returns `Error::ExpectedSomeValue` - serde's `expected value` - rather than a
    // type mismatch. So the needle asserted below is the message the pinned
    // `serde_json` actually produces, and a bare token reaching the enum decoder is
    // evidence that the enum is closed at the TOKEN level, not only that it is typed.
    //
    // THIS ROW IS NOT IN `INJECTED_TAGS`. That table pins out-of-set VARIANT spellings
    // for fixtures that inject one into a larger document; here the injected token IS
    // the entire document, so a `contains("933")` precondition would have been
    // vacuous - the substring `933` occurs in dozens of the container's other fixtures
    // and inside this one's own family. The check below is therefore on the WHOLE
    // document: it is exactly the three bytes `933`, unquoted, with nothing else in it.
    // That is also what makes the "not a quoted variant" assertion below meaningful.
    let wrong_type = raw("c6_wrong_typed_status_tag_refuse");
    assert_eq!(
        wrong_type.trim(),
        "933",
        "the wrong-typed fixture must be EXACTLY the bare three-byte token `933` and nothing \
         else: its injected value is the whole document, not a member of one"
    );
    assert!(
        !wrong_type.trim_start().starts_with('"'),
        "the wrong-typed fixture must be an unquoted JSON value, not a quoted variant"
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(&wrong_type).is_ok(),
        "the wrong-typed fixture must be VALID JSON: it is refused for its TYPE, not because \
         it is malformed, which is exactly what its `_refuse` suffix claims"
    );
    let Err(wrong_error) = decode::<AdapterResultStatus>(&wrong_type) else {
        panic!("a numeric value must not decode as a closed string variant");
    };
    let wrong_message = wrong_error.to_string();
    assert!(
        wrong_message.contains("expected value"),
        "a bare non-unit token reaching a derived enum decoder is refused as \
         `expected value`, not as `invalid type`, got: {wrong_message}"
    );

    // (d) The canonical spellings themselves are closed and ENUMERATED by the
    // refusal, so adding a variant later moves this assertion.
    let status_text = raw("c6_AdapterResultStatus_unknown_tag_refuse");
    let Err(status_error) = decode::<AdapterResultStatus>(&status_text) else {
        panic!("an unknown status tag must be refused");
    };
    let status_message = status_error.to_string();
    for spelled in ["succeeded", "transport_failure", "unsupported_capability"] {
        assert!(
            status_message.contains(spelled),
            "the refusal must enumerate the closed variants, including `{spelled}`, got: {status_message}"
        );
    }

    // (e) VALUE ASSERTIONS, so the five STRUCT types this case binds are not bound
    // by a self-consistency round trip alone: each is decoded from its own canonical
    // fixture and compared, member by member, against the very text the container
    // stores for that member. The twelve closed enums are already pinned to their
    // own stored bytes by (a), and `ProviderInvocationOutcome` - the thirteenth
    // name in (a) and a struct - is one of the five rows here.
    let outcome_text = raw("c2_ProviderInvocationOutcome_canonical");
    let outcome: ProviderInvocationOutcome =
        decode(&outcome_text).expect("the canonical outcome document must decode");
    assert_eq!(
        outcome.outcome_id,
        member(&outcome_text, "outcome_id"),
        "the decoded outcome must carry the document's own outcome id"
    );
    assert_eq!(
        outcome.dispatch_proven,
        member_bool(&outcome_text, "dispatch_proven"),
        "the decoded outcome must carry the document's own dispatch-proven flag"
    );
    let transition_text = raw("c2_ProviderInvocationTransition_canonical");
    let transition: ProviderInvocationTransition =
        decode(&transition_text).expect("the canonical transition document must decode");
    assert_eq!(
        transition.transition_id,
        member(&transition_text, "transition_id"),
        "the decoded transition must carry the document's own transition id"
    );
    assert_eq!(
        transition.evidence_refs,
        member_texts(&transition_text, "evidence_refs"),
        "the decoded transition must carry the document's own evidence refs"
    );
    let identity_text = raw("c2_ProviderIdentityCheck_canonical");
    let identity: ProviderIdentityCheck =
        decode(&identity_text).expect("the canonical identity-check document must decode");
    assert_eq!(
        identity.field,
        member(&identity_text, "field"),
        "the decoded identity check must carry the document's own field name"
    );
    let incident_text = raw("c2_ProviderFailureIncident_canonical");
    let incident: ProviderFailureIncident =
        decode(&incident_text).expect("the canonical failure-incident document must decode");
    assert_eq!(
        incident.incident_id,
        member(&incident_text, "incident_id"),
        "the decoded failure incident must carry the document's own incident id"
    );
    let record_text = raw("c2_ProviderReconciliationRecord_canonical");
    let record: ProviderReconciliationRecord =
        decode(&record_text).expect("the canonical reconciliation record must decode");
    assert_eq!(
        record.reconciliation_id,
        member(&record_text, "reconciliation_id"),
        "the decoded reconciliation record must carry the document's own id"
    );
    assert_eq!(
        record.unresolved_questions,
        member_texts(&record_text, "unresolved_questions"),
        "the decoded reconciliation record must carry the document's own questions"
    );
}

// WORK_UNIT_CASE: 933/c7_missing_or_empty_required_ids_refused
#[test]
#[allow(clippy::too_many_lines)]
fn c7_missing_or_empty_required_identifiers_refused() {
    const REQUIRED_NULLABLE_BOOLS: [&str; 4] = [
        "process_timed_out",
        "process_cancelled",
        "stdout_truncated",
        "stderr_truncated",
    ];
    const REQUIRED_NULLABLE_NUMBERS: [&str; 2] = ["stdout_total_bytes", "stderr_total_bytes"];

    assert_case_binding(
        "933/c7_missing_or_empty_required_ids_refused",
        &[
            "AdapterLimits",
            "ProcessExecutionPolicy",
            "ExternalAgentExecutionRequest",
            "OperationAuthorityOpenRequest",
            "OperationAuthorityCloseRequest",
            "ProviderTimeoutClass",
            "ProviderTimeoutProfile",
            "ProviderInvocationAttempt",
            "ProviderRouteReadinessGate",
            "ProviderDeclaredBudget",
        ],
    );
    assert_bytes_unchanged::<AdapterLimits>("AdapterLimits");
    assert_bytes_unchanged::<ProcessExecutionPolicy>("ProcessExecutionPolicy");
    assert_bytes_unchanged::<ExternalAgentExecutionRequest>("ExternalAgentExecutionRequest");
    assert_bytes_unchanged::<OperationAuthorityOpenRequest>("OperationAuthorityOpenRequest");
    assert_bytes_unchanged::<OperationAuthorityCloseRequest>("OperationAuthorityCloseRequest");
    assert_enum_spelling::<ProviderTimeoutClass>("ProviderTimeoutClass");
    assert_bytes_unchanged::<ProviderTimeoutProfile>("ProviderTimeoutProfile");
    assert_bytes_unchanged::<ProviderInvocationAttempt>("ProviderInvocationAttempt");
    assert_bytes_unchanged::<ProviderRouteReadinessGate>("ProviderRouteReadinessGate");
    assert_bytes_unchanged::<ProviderDeclaredBudget>("ProviderDeclaredBudget");

    // (a) Eight omitted required members, each named by its own refusal. A plain
    // `Option<T>` member is NOT in this list: it decodes an absent key as `None`,
    // so an absent-key refusal exists only for a non-optional member or for one
    // carrying `deserialize_required_nullable`.
    //
    // These use `assert_omitted_member_refusal`, NOT `assert_named_refusal`, and the
    // distinction is load-bearing: `assert_named_refusal` proves its token is PRESENT
    // in the document, which is the truth for an injection fixture and the opposite of
    // the truth here. Eight of these nine documents carry their member's name NOWHERE
    // (measured against the stored texts), so a presence precondition would fail on a
    // correct fixture.
    assert_omitted_member_refusal::<AdapterLimits>(
        "c7_AdapterLimits_absent_circuit_breaker_failures_refuse",
        "circuit_breaker_failures",
    );
    assert_omitted_member_refusal::<ProcessExecutionPolicy>(
        "c7_ProcessExecutionPolicy_absent_allowed_executables_refuse",
        "allowed_executables",
    );
    assert_omitted_member_refusal::<OperationAuthorityOpenRequest>(
        "c7_OperationAuthorityOpenRequest_absent_idempotency_key_refuse",
        "idempotency_key",
    );
    assert_omitted_member_refusal::<OperationAuthorityCloseRequest>(
        "c7_OperationAuthorityCloseRequest_absent_role_lease_id_refuse",
        "role_lease_id",
    );
    assert_omitted_member_refusal::<ProviderTimeoutProfile>(
        "c7_ProviderTimeoutProfile_absent_policy_version_refuse",
        "policy_version",
    );
    assert_omitted_member_refusal::<ProviderRouteReadinessGate>(
        "c7_ProviderRouteReadinessGate_absent_last_successful_smoke_ref_refuse",
        "last_successful_smoke_ref",
    );
    assert_omitted_member_refusal::<ProviderDeclaredBudget>(
        "c7_ProviderDeclaredBudget_absent_cancellation_grace_ms_refuse",
        "cancellation_grace_ms",
    );

    // (a2) `ExternalAgentExecutionRequest.max_turns_or_steps` is omitted at the
    // REQUEST's own top level; the same member name still occurs inside the
    // `launch_contract` object, so the omission is checked where it is claimed
    // rather than by a whole-document text search, and
    // `assert_omitted_member_refusal` cannot be used here because it deliberately
    // requires the name to be absent at EVERY depth.
    let absent_turns = raw("c7_ExternalAgentExecutionRequest_absent_max_turns_or_steps_refuse");
    assert!(
        member_value(&absent_turns, "launch_contract")
            .get("max_turns_or_steps")
            .is_some(),
        "the nested launch contract must still carry its own `max_turns_or_steps`"
    );
    assert!(
        witness(&absent_turns).get("max_turns_or_steps").is_none(),
        "the top-level request member must be the one that is absent"
    );
    let Err(turns_error) = decode::<ExternalAgentExecutionRequest>(&absent_turns) else {
        panic!("a request whose own `max_turns_or_steps` is absent must be refused");
    };
    let turns_message = turns_error.to_string();
    assert!(
        turns_message.contains("missing field") && turns_message.contains("max_turns_or_steps"),
        "the refusal must be a missing-field refusal naming the request's own \
         `max_turns_or_steps`, got: {turns_message}"
    );

    // (a3) An EMPTY closed variant is not an identifier and not a variant:
    // `ProviderTimeoutClass` has no catch-all, so the empty string is refused.
    let empty_variant = raw("c7_ProviderTimeoutClass_empty_variant_refuse");
    assert_eq!(
        empty_variant, "\"\"",
        "the fixture must be exactly the empty JSON string"
    );
    assert!(
        decode::<ProviderTimeoutClass>(&empty_variant).is_err(),
        "an empty closed-variant string must not decode as a timeout class"
    );

    // (b) An ABSENT `timeout_class` is a typed missing-field failure, not a silent
    // `None`: the field carries `deserialize_required_nullable` with NO
    // `serde(default)` (`crates/eliot-types/src/provider_invocation.rs:193-194`), so
    // a record that never recorded a timeout cannot read as if it had. The same key
    // PRESENT and explicitly null still decodes to None, which is the absent /
    // present distinction this case preserves (I05-16-common-durable-fields.md:46).
    assert_omitted_member_refusal::<ProviderInvocationAttempt>(
        "c7_ProviderInvocationAttempt_absent_timeout_class_refuse",
        "timeout_class",
    );
    let attempt_text = raw("c2_ProviderInvocationAttempt_canonical");
    let attempt: ProviderInvocationAttempt =
        decode(&attempt_text).expect("the canonical attempt must decode");
    assert_eq!(
        attempt.timeout_class.is_none(),
        member_number_or_null(&attempt_text, "timeout_class").is_none(),
        "the decoded `timeout_class` must be None exactly when the document carries an explicit null"
    );

    // (c) An EMPTY required identifier. `TaskId`/`ProjectId`/`AgentSessionId` are
    // transparent `Uuid` newtypes (`crates/eliot-types/src/ids.rs:7-53`), so an
    // empty string is not an identifier at all and must not decode as one.
    let empty = raw("c7_OperationAuthorityOpenRequest_empty_task_id_refuse");
    assert!(
        empty.contains(&format!("\"{TASK_ID_MEMBER}\":\"\"")),
        "the fixture must actually carry an empty `{TASK_ID_MEMBER}` value"
    );
    assert!(
        decode::<OperationAuthorityOpenRequest>(&empty).is_err(),
        "an empty required identifier must not decode as a UUID identifier"
    );
    let canonical_open = raw("c2_OperationAuthorityOpenRequest_canonical");
    let accepted: OperationAuthorityOpenRequest =
        decode(&canonical_open).expect("the canonical document's real identifier must decode");
    assert_eq!(
        accepted.task_id.as_uuid().to_string(),
        member(&canonical_open, TASK_ID_MEMBER),
        "the accepted counterpart must carry the canonical document's own identifier"
    );

    // (d) A FREE-STRING identifier has no such floor, and that is recorded here as
    // the decoder's behaviour as read from the source, not as a refusal it
    // performs:
    // `OperationAuthorityOpenRequest.idempotency_key` is a plain `String`
    // (`crates/eliot-types/src/external_agent.rs:48`), so an empty one decodes. NO
    // T04 decoder refuses an empty plain-String identifier.
    let empty_key = raw("c7_OperationAuthorityOpenRequest_empty_free_string_id_accepted");
    let free_string: OperationAuthorityOpenRequest =
        decode(&empty_key).expect("a plain-String identifier has no UUID floor");
    assert!(
        free_string.idempotency_key.is_empty(),
        "an empty plain-String identifier decodes to an empty string; no T04 decoder refuses it"
    );

    // =========================================================================
    // (f) THE OWNER-AUDIT "LATER ACCEPTANCE" LIST, discharged item by item.
    //
    // Owner-audit comment 5886155113 specified, verbatim: "remove each named key
    // individually and get missing-field refusal; explicit null still succeeds;
    // true/false/zero/nonzero remain distinct; duplicate null/value keys reject;
    // valid current serialization remains identical; unrelated optional fields remain
    // optional; the existing journal load observes the same rule." This block
    // discharges the five fixture-observable items; the sixth ("valid current
    // serialization remains identical") is the byte round trip asserted for every
    // canonical document by `assert_bytes_unchanged` at the top of this case, and the
    // seventh (the journal load) is a CALLER outside this crate's file scope, noted
    // below rather than asserted.
    //
    // THE TEN MEMBERS under test are the ones that carry
    // `deserialize_required_nullable` (`crates/eliot-types/src/provider_invocation.rs:7`)
    // and NO `serde(default)`, applied to `ProviderInvocationAttempt`
    // (`:155`). Each is named here with its own declaration line:
    //   `provider_route_policy`     `:171-172`  Option<ProviderRoutePolicyBinding>
    //   `timeout_class`             `:193-194`  Option<ProviderTimeoutClass>
    //   `process_reap_receipt`      `:195-196`  Option<ProcessReapReceipt>
    //   `process_timed_out`         `:197-198`  Option<bool>
    //   `process_cancelled`         `:199-200`  Option<bool>
    //   `process_worker_error`      `:201-202`  Option<String>
    //   `stdout_total_bytes`        `:203-204`  Option<u64>
    //   `stderr_total_bytes`        `:205-206`  Option<u64>
    //   `stdout_truncated`          `:207-208`  Option<bool>
    //   `stderr_truncated`          `:209-210`  Option<bool>
    // The ELEVENTH member of the same shape in this slice is
    // `ProviderRouteReadinessGate.last_successful_smoke_ref`
    // (`crates/eliot-types/src/provider_invocation.rs:653-654`), whose own omission
    // refusal is asserted in (a) above and whose explicit null is asserted in (f2).
    // =========================================================================

    // (f1) "remove each named key individually and get missing-field refusal" - the
    // nine members that had NO such row before this increment, one document each,
    // each the canonical attempt with EXACTLY ONE member deleted and nothing else
    // changed. `timeout_class` and the gate's `last_successful_smoke_ref` are reused
    // from (a)/(b) rather than duplicated.
    for (fixture_name, member) in [
        (
            "c7_ProviderInvocationAttempt_absent_provider_route_policy_refuse",
            "provider_route_policy",
        ),
        (
            "c7_ProviderInvocationAttempt_absent_process_reap_receipt_refuse",
            "process_reap_receipt",
        ),
        (
            "c7_ProviderInvocationAttempt_absent_process_timed_out_refuse",
            "process_timed_out",
        ),
        (
            "c7_ProviderInvocationAttempt_absent_process_cancelled_refuse",
            "process_cancelled",
        ),
        (
            "c7_ProviderInvocationAttempt_absent_process_worker_error_refuse",
            "process_worker_error",
        ),
        (
            "c7_ProviderInvocationAttempt_absent_stdout_total_bytes_refuse",
            "stdout_total_bytes",
        ),
        (
            "c7_ProviderInvocationAttempt_absent_stderr_total_bytes_refuse",
            "stderr_total_bytes",
        ),
        (
            "c7_ProviderInvocationAttempt_absent_stdout_truncated_refuse",
            "stdout_truncated",
        ),
        (
            "c7_ProviderInvocationAttempt_absent_stderr_truncated_refuse",
            "stderr_truncated",
        ),
    ] {
        assert_omitted_member_refusal::<ProviderInvocationAttempt>(fixture_name, member);
    }

    // (f2) "explicit null still succeeds" - the same ten members PRESENT and
    // explicitly `null`. `deserialize_required_nullable` deserializes
    // `Option::<T>::deserialize` (`provider_invocation.rs:7-13`), so an explicit null
    // is the ONLY way a member may be absent in meaning while present on the wire;
    // that is the absent/present distinction I05-16 requires
    // (`docs/architecture/I05-16-common-durable-fields.md:46`).
    let all_null_text =
        raw("c7_ProviderInvocationAttempt_all_required_nullable_explicit_null_accepted");
    for member in [
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
        assert!(
            member_value(&all_null_text, member).is_null(),
            "the all-explicit-null document must carry `{member}` PRESENT and explicitly null"
        );
    }
    let all_null: ProviderInvocationAttempt = decode(&all_null_text)
        .expect("all ten required-nullable members present and explicitly null must decode");
    assert!(
        all_null.provider_route_policy.is_none()
            && all_null.timeout_class.is_none()
            && all_null.process_reap_receipt.is_none()
            && all_null.process_timed_out.is_none()
            && all_null.process_cancelled.is_none()
            && all_null.process_worker_error.is_none()
            && all_null.stdout_total_bytes.is_none()
            && all_null.stderr_total_bytes.is_none()
            && all_null.stdout_truncated.is_none()
            && all_null.stderr_truncated.is_none(),
        "each of the ten must decode to None from an EXPLICIT null, never to a default value"
    );
    // The eleventh member of the same shape, on the gate, from its own canonical
    // document: `ProviderRouteReadinessGate.last_successful_smoke_ref`
    // (`provider_invocation.rs:653-654`) is stated null on the wire and reads as None.
    let gate_canonical_text = raw("c2_ProviderRouteReadinessGate_canonical");
    let gate_canonical: ProviderRouteReadinessGate =
        decode(&gate_canonical_text).expect("the canonical readiness-gate document must decode");
    assert!(
        member_value(&gate_canonical_text, "last_successful_smoke_ref").is_null()
            && gate_canonical.last_successful_smoke_ref.is_none(),
        "the gate's eleventh required-nullable member must also decode from an explicit null"
    );

    // (f3) "true/false/zero/nonzero remain distinct" - the four bool members and the
    // two numeric members are stated in TWO documents that give them DIFFERENT values,
    // and each document decodes to its own value. The point is that neither
    // `false`/`0` nor `true`/non-zero is coerced, defaulted, or normalised into the
    // other, so a recorded fact and an unrecorded fact stay different on the wire.
    let false_zero_text =
        raw("c7_ProviderInvocationAttempt_required_nullable_false_and_zero_accepted");
    let true_nonzero_text =
        raw("c7_ProviderInvocationAttempt_required_nullable_true_and_nonzero_accepted");
    let false_zero: ProviderInvocationAttempt =
        decode(&false_zero_text).expect("the false/zero document must decode");
    let true_nonzero: ProviderInvocationAttempt =
        decode(&true_nonzero_text).expect("the true/non-zero document must decode");
    for member in REQUIRED_NULLABLE_BOOLS {
        assert!(
            member_value(&false_zero_text, member).as_bool() == Some(false)
                && member_value(&true_nonzero_text, member).as_bool() == Some(true),
            "the two documents must give `{member}` DIFFERENT boolean values, or they prove \
             nothing about coercion"
        );
    }
    for member in REQUIRED_NULLABLE_NUMBERS {
        let zero = member_number(&false_zero_text, member);
        let nonzero = member_number(&true_nonzero_text, member);
        assert_eq!(
            zero, 0,
            "`{member}` must be stated as zero in the false/zero document"
        );
        assert_ne!(
            nonzero, 0,
            "`{member}` must be stated as a NON-ZERO number in the true/non-zero document"
        );
    }
    // The decoded values follow the documents, member by member, and the two decoded
    // attempts are not interchangeable.
    assert_eq!(
        (
            false_zero.process_timed_out,
            false_zero.process_cancelled,
            false_zero.stdout_truncated,
            false_zero.stderr_truncated
        ),
        (Some(false), Some(false), Some(false), Some(false)),
        "every bool member of the false/zero document must decode to Some(false), never None \
         and never defaulted"
    );
    assert_eq!(
        (
            true_nonzero.process_timed_out,
            true_nonzero.process_cancelled,
            true_nonzero.stdout_truncated,
            true_nonzero.stderr_truncated
        ),
        (Some(true), Some(true), Some(true), Some(true)),
        "every bool member of the true/non-zero document must decode to Some(true), never None \
         and never defaulted"
    );
    assert_eq!(
        (false_zero.stdout_total_bytes, false_zero.stderr_total_bytes),
        (Some(0), Some(0)),
        "both byte counts of the false/zero document must decode to Some(0), not None"
    );
    assert_eq!(
        (
            true_nonzero.stdout_total_bytes,
            true_nonzero.stderr_total_bytes
        ),
        (
            Some(member_number(&true_nonzero_text, "stdout_total_bytes")),
            Some(member_number(&true_nonzero_text, "stderr_total_bytes"))
        ),
        "both byte counts of the true/non-zero document must decode to their own stated \
         non-zero numbers"
    );

    // (f4) "unrelated optional fields remain optional" - the GENUINELY OPTIONAL members,
    // i.e. the `Option<T>` members that do NOT carry `deserialize_required_nullable`
    // and carry no `serde(default)`, so an absent key reads as `None` by serde's own
    // `missing_field` rule for `Option<T>` (`serde-1.0.229/src/private/de.rs:24-44`).
    // Named here with their declaration lines, all in
    // `crates/eliot-types/src/provider_invocation.rs` inside the struct opened at
    // `:155`: `external_invocation_ref` `:162`, `route_or_model` `:165`,
    // `adapter_version` `:166`, `executable_or_transport` `:167`, `cwd` `:168`,
    // `environment_fingerprint` `:169`, `dispatch_started_at` `:175`,
    // `process_started_at` `:177`, `provider_ack_at` `:179`, `first_output_at` `:181`,
    // `last_output_at` `:183`, `process_exit_at` `:185`, `cleanup_completed_at` `:187`,
    // `stdout_blob_or_hash` `:188`, `stderr_blob_or_hash` `:189`,
    // `structured_output_blob_or_hash` `:190`, `exit_code_or_signal` `:191`,
    // `process_or_job_identity` `:192`, `quota_or_cost_if_known` `:211` and
    // `original_closeout_ref` `:212`.
    //
    // The fixture is the canonical attempt with those members removed. It must DECODE.
    // Which subset the container actually removed is deliberately NOT asserted here:
    // the claim this row owns is the RULE, that an absent genuinely-optional member is
    // still optional, and that is checked for every named member without constraining
    // the container's choice of which ones to drop.
    let optional_text =
        raw("c7_ProviderInvocationAttempt_genuinely_optional_members_absent_accepted");
    let optional: ProviderInvocationAttempt = decode(&optional_text)
        .expect("an attempt with its genuinely optional members absent must still decode");
    assert!(
        optional.external_invocation_ref.is_none()
            && optional.route_or_model.is_none()
            && optional.adapter_version.is_none()
            && optional.executable_or_transport.is_none()
            && optional.cwd.is_none()
            && optional.environment_fingerprint.is_none()
            && optional.dispatch_started_at.is_none()
            && optional.process_started_at.is_none()
            && optional.provider_ack_at.is_none()
            && optional.first_output_at.is_none()
            && optional.last_output_at.is_none()
            && optional.process_exit_at.is_none()
            && optional.cleanup_completed_at.is_none()
            && optional.stdout_blob_or_hash.is_none()
            && optional.stderr_blob_or_hash.is_none()
            && optional.structured_output_blob_or_hash.is_none()
            && optional.exit_code_or_signal.is_none()
            && optional.process_or_job_identity.is_none()
            && optional.quota_or_cost_if_known.is_none()
            && optional.original_closeout_ref.is_none(),
        "every genuinely optional member must read as None whether the document omits it or \
         states it null, while the ten required-nullable members stay required"
    );
    // The required side of the same document is untouched: every non-optional member is
    // still there, and the ten required-nullable members are still PRESENT, so this
    // row is not passing because the document is simply broken.
    for member in [
        "invocation_attempt_id",
        "provider",
        "campaign_id",
        "preregistration_id",
        "reservation_id",
        "idempotency_key",
        "frozen_input_hash",
        "request_payload_hash",
        "timeout_profile_id",
        "state_transitions",
    ] {
        assert!(
            !member_value(&optional_text, member).is_null(),
            "the optional-members document must still carry the required member `{member}`"
        );
    }
    assert_eq!(
        optional.invocation_attempt_id,
        member(&optional_text, "invocation_attempt_id"),
        "the accepted optional-members document must carry its own invocation id"
    );

    // (f5) THE SEVENTH audit item, "the existing journal load observes the same rule",
    // is NOT asserted here and is not invented here: it is a CALLER's behaviour, not a
    // decoder's. What this crate can show is the decoder side it would observe - the
    // eleven members above are the ones
    // `ProviderRouteReadinessService::evaluate`
    // (`crates/eliot-engine/src/provider_invocation.rs`, the only producer, which the
    // declaration comment at `provider_invocation.rs:630-633` states sets all ten
    // explicitly) must state, and an omission from any of them is a loud failure rather
    // than a silent `None`. That is recorded here as the standing statement, not as an
    // assertion about a crate this file does not depend on.

    // (e) VALUE ASSERTIONS, so no row below is a self-consistency round trip alone:
    // each type is decoded from its own canonical fixture and compared, member by
    // member, against the very text the container stores for that member. These are
    // the rows this case binds that had no decoded-value comparison anywhere:
    // `AdapterLimits`, `ProcessExecutionPolicy`, `ExternalAgentExecutionRequest`,
    // `ProviderRouteReadinessGate` and `ProviderTimeoutProfile`.
    // `ProviderTimeoutProfile` has PRIVATE fields (`:462-478`) but publishes public
    // accessors (`:481-526`), so those accessors are the legal observation here and
    // no field access is attempted.
    let limits_text = raw("c2_AdapterLimits_canonical");
    let limits: AdapterLimits =
        decode(&limits_text).expect("the canonical limits document must decode");
    assert_eq!(
        limits.timeout_ms,
        member_number(&limits_text, "timeout_ms"),
        "the decoded limits must carry the document's own timeout"
    );
    let process_policy_text = raw("c2_ProcessExecutionPolicy_canonical");
    let process_policy: ProcessExecutionPolicy =
        decode(&process_policy_text).expect("the canonical process-policy document must decode");
    assert_eq!(
        process_policy.allowed_executables,
        member_texts(&process_policy_text, "allowed_executables"),
        "the decoded process policy must carry the document's own allowed executables"
    );
    let execution_text = raw("c2_ExternalAgentExecutionRequest_canonical");
    let execution: ExternalAgentExecutionRequest =
        decode(&execution_text).expect("the canonical execution-request document must decode");
    assert_eq!(
        execution.prompt_ref,
        member(&execution_text, "prompt_ref"),
        "the decoded execution request must carry the document's own prompt ref"
    );
    let gate_text = raw("c2_ProviderRouteReadinessGate_canonical");
    let gate: ProviderRouteReadinessGate =
        decode(&gate_text).expect("the canonical readiness-gate document must decode");
    assert_eq!(
        gate.readiness_gate_id,
        member(&gate_text, "readiness_gate_id"),
        "the decoded readiness gate must carry the document's own gate id"
    );
    assert_eq!(
        gate.reasons,
        member_texts(&gate_text, "reasons"),
        "the decoded readiness gate must carry the document's own reasons"
    );
    let timeout_profile_text = raw("c2_ProviderTimeoutProfile_canonical");
    let timeout_profile: ProviderTimeoutProfile =
        decode(&timeout_profile_text).expect("the canonical timeout profile must decode");
    assert_eq!(
        timeout_profile.profile_id(),
        member(&timeout_profile_text, "profile_id"),
        "the decoded timeout profile must carry the document's own profile id"
    );
    assert_eq!(
        timeout_profile.cancellation_grace_ms(),
        member_number(&timeout_profile_text, "cancellation_grace_ms"),
        "the decoded timeout profile must carry the document's own grace value"
    );
    // `ProviderDeclaredBudget` is deliberately NOT read here: every one of its eight
    // fields is private AND it publishes no accessor at all (only the `new` and
    // `with_*` builders at `crates/eliot-types/src/provider_invocation.rs:235-285`),
    // so there is NO legal way to observe a decoded value against the fixture text.
    // Its refusal and round-trip rows above are all it can be bound by.
}

// WORK_UNIT_CASE: 933/c8_unsupported_versions_refused
#[test]
#[allow(clippy::too_many_lines)]
fn c8_unsupported_versions_are_not_promoted_and_cannot_hide_in_an_unknown_member() {
    assert_case_binding(
        "933/c8_unsupported_versions_refused",
        &["ProviderRuntimePreflightReceipt"],
    );
    assert_bytes_unchanged::<ProviderRuntimePreflightReceipt>("ProviderRuntimePreflightReceipt");

    // (a) The supported versions are the exported constants' own values, read from
    // `crates/eliot-types/src/external_agent.rs:13-31`, `:14` and
    // `crates/eliot-types/src/mcp_contract.rs:16`, never from a literal the decoder
    // would have to agree with by accident.
    assert_eq!(
        PROVIDER_RUNTIME_PREFLIGHT_SCHEMA_VERSION, "eliot-provider-runtime-preflight-v1",
        "the supported preflight schema version is the constant's value"
    );
    assert_eq!(
        PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION, "eliot-provider-runtime-v2",
        "the supported runtime contract schema version is the constant's value"
    );
    assert_eq!(
        OPERATION_AUTHORITY_SCHEMA_VERSION, "eliot-operation-authority-v1",
        "the supported operation-authority schema version is the constant's value"
    );
    assert_eq!(
        OBSERVE_INPUT_SCHEMA_VERSION, "eliot.observe-v1",
        "the supported observe schema version is the constant's value"
    );
    let canonical_text = raw("c2_ProviderRuntimePreflightReceipt_canonical");
    assert_eq!(
        member(&canonical_text, SCHEMA_VERSION_MEMBER),
        PROVIDER_RUNTIME_PREFLIGHT_SCHEMA_VERSION,
        "the canonical preflight receipt must carry the supported schema version on the wire"
    );

    // (b) STATED FROM SOURCE, NOT A PASS: inside these decoders `schema_version` is
    // DATA, not
    // a validated field. An unsupported version therefore DECODES and is kept
    // verbatim - it is never silently promoted to the supported constant, and no
    // assertion here claims the decoder refuses it. The refusal of an unsupported
    // major version is owned by the consuming dispatcher (for `eliot.observe`,
    // `dispatch_observe`), which is outside this crate's file scope; APPENDIX-P line
    // 11's "major incompatibility fails before effects" is discharged there, not
    // here.
    let unsupported = raw("c8_ProviderRuntimePreflightReceipt_unsupported_schema_version");
    let kept = member(&unsupported, SCHEMA_VERSION_MEMBER);
    assert_ne!(
        kept, PROVIDER_RUNTIME_PREFLIGHT_SCHEMA_VERSION,
        "the fixture must actually carry an unsupported version"
    );
    let decoded: ProviderRuntimePreflightReceipt =
        decode(&unsupported).expect("an unsupported version STRING is not refused by this decoder");
    assert_eq!(
        decoded.schema_version, kept,
        "the decoded receipt must keep its own unsupported version verbatim, never promoted"
    );
    let re_encoded = serde_json::to_string(&decoded).expect("the decoded receipt must re-encode");
    assert!(
        re_encoded.contains(&kept),
        "re-encoding must preserve the unsupported version too"
    );

    // (c) What IS refused here: an unsupported version smuggled in under an unknown
    // member name. `deny_unknown_fields` closes the envelope, so the version cannot
    // re-enter through a different key either.
    let renamed = raw("c8_ProviderRuntimePreflightReceipt_version_member_renamed_refuse");
    assert!(
        renamed.contains(OBSOLETE_SCHEMA_VERSION_MEMBER),
        "the fixture must carry the obsolete version under an unknown member name"
    );
    assert!(
        !renamed.contains(&format!("\"{SCHEMA_VERSION_MEMBER}\"")),
        "the fixture must NOT carry the supported version member name at all"
    );
    assert_named_refusal::<ProviderRuntimePreflightReceipt>(
        "c8_ProviderRuntimePreflightReceipt_version_member_renamed_refuse",
        OBSOLETE_SCHEMA_VERSION_MEMBER,
        "unknown field",
    );

    // (d) The same statement about the other version-bearing surfaces, each named by
    // its own type. `schema_version` is a plain `String` on each of them
    // (`crates/eliot-types/src/external_agent.rs:36`, `:82`, `:176`), so an
    // unsupported version is DATA on every one of them: it is kept verbatim and is
    // never promoted. Each fixture really carries an unsupported version, checked
    // against the exported constant rather than against a literal.
    //
    // RECORDED, NOT CLAIMED: none of these three types is owned by case 8.
    // `TYPE_HOME_CASE` gives `OperationAuthorityOpenRequest` and
    // `OperationAuthorityCloseRequest` the home binding
    // `933/c7_missing_or_empty_required_ids_refused` and `ProviderRuntimeContract` the
    // home binding `933/c10_unsafe_migration_refuses`. Case 8's binding list therefore
    // stays exactly the one type it owns, `ProviderRuntimePreflightReceipt`, and each of
    // these three decodes is recorded here with its real owner so the file never implies
    // a binding it does not have.
    assert_also_decodes::<OperationAuthorityOpenRequest>(
        "OperationAuthorityOpenRequest",
        "933/c7_missing_or_empty_required_ids_refused",
    );
    assert_also_decodes::<OperationAuthorityCloseRequest>(
        "OperationAuthorityCloseRequest",
        "933/c7_missing_or_empty_required_ids_refused",
    );
    assert_also_decodes::<ProviderRuntimeContract>(
        "ProviderRuntimeContract",
        "933/c10_unsafe_migration_refuses",
    );
    let open_text = raw("c8_OperationAuthorityOpenRequest_unsupported_schema_version");
    let open_version = member(&open_text, SCHEMA_VERSION_MEMBER);
    assert_ne!(
        open_version, OPERATION_AUTHORITY_SCHEMA_VERSION,
        "the open-request fixture must carry its own unsupported version"
    );
    let open: OperationAuthorityOpenRequest =
        decode(&open_text).expect("an unsupported operation-authority version is kept verbatim");
    assert_eq!(
        open.schema_version, open_version,
        "the decoded open request must keep its own unsupported version verbatim"
    );
    let close_text = raw("c8_OperationAuthorityCloseRequest_unsupported_schema_version");
    let close_version = member(&close_text, SCHEMA_VERSION_MEMBER);
    assert_ne!(
        close_version, OPERATION_AUTHORITY_SCHEMA_VERSION,
        "the close-request fixture must carry its own unsupported version"
    );
    let close: OperationAuthorityCloseRequest =
        decode(&close_text).expect("an unsupported operation-authority version is kept verbatim");
    assert_eq!(
        close.schema_version, close_version,
        "the decoded close request must keep its own unsupported version verbatim"
    );
    let contract_text = raw("c8_ProviderRuntimeContract_unsupported_schema_version");
    let contract_version = member(&contract_text, SCHEMA_VERSION_MEMBER);
    assert_ne!(
        contract_version, PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION,
        "the runtime-contract fixture must carry its own unsupported version"
    );
    let contract: ProviderRuntimeContract =
        decode(&contract_text).expect("an unsupported runtime-contract version is kept verbatim");
    assert_eq!(
        contract.schema_version, contract_version,
        "the decoded contract must keep its own unsupported version verbatim"
    );

    // (e) THE FACT, STATED PLAINLY, with its citations. NO T04 DECODER ENFORCES
    // `schema_version`. On every version-bearing surface in this slice the member is a
    // plain `String` - `OperationAuthorityOpenRequest`
    // (`crates/eliot-types/src/external_agent.rs:36`),
    // `OperationAuthorityCloseRequest` (`:82`), `ProviderRuntimeContract` (`:176`),
    // `ProviderRuntimePreflightReceipt` (`:228`), and the legacy
    // `CognitiveProviderRuntimeContract` (`:262`) - and none of them carries
    // `deserialize_with`, `try_from` or any other validating attribute. A derived
    // decoder therefore cannot compare it against anything, so an unsupported version
    // is ACCEPTED as data and kept verbatim, exactly as (b) and (d) assert above and
    // for the legacy surface in case 9. The version comparison lives in the CONSUMERS,
    // `eliot-app` and `eliot-engine`, not in these decoders; for `eliot.observe` the
    // enforcing site is `dispatch_observe`
    // (`crates/eliot-app/src/mcp_stdio/verification.rs`, recorded at
    // `crates/eliot-types/src/mcp_contract.rs:442-445`).
    //
    // No decoder refusal is faked here. Asserting that these decoders refuse an
    // unsupported version would assert something they do not do, and the case would
    // then be red for a true statement about a different component.
    //
    // CROSS-REFERENCE: this is recorded as a non-clean row in the container's
    // `known_non_clean` array under the id `no_t04_decoder_enforces_schema_version`
    // (`KNOWN_NON_CLEAN_IDS`, third entry), and case 12 asserts that row exists,
    // names its owner and carries the same citations. The two halves are one handoff:
    // this case is the executable observation, the row is the recorded ownership.
    // The LIMIT of the damage, as the row must state it: the damage is ambiguity about
    // WHICH version was stated, not a grant - none of these types turns a version
    // string into authority, scope, effect or a receipt, and the consumers that do
    // compare it are unchanged by this lane.
}

// WORK_UNIT_CASE: 933/c9_explicit_legacy_migration_preserves_evidence
#[test]
#[allow(clippy::too_many_lines)]
fn c9_named_legacy_surface_decodes_evidence_and_the_current_contract_refuses_it() {
    assert_case_binding(
        "933/c9_explicit_legacy_migration_preserves_evidence",
        &["CognitiveProviderRuntimeContract"],
    );

    // The legacy surface is EXPLICIT and NAMED
    // (`crates/eliot-types/src/external_agent.rs:244-247`: "Report-only
    // compatibility surface for evidence created before the unified provider
    // runtime contract"). It is a separate type behind its own schema-version
    // constant - not an alias, not an `untagged` form, not a helper default on the
    // current type - and this lane adds none. The ceiling is preserved: decoding
    // historical evidence grants no runtime authority, constructs no current
    // contract, asserts no product support and promotes nothing; it is at best
    // CURRENT_UNVERIFIED (I00-05).
    assert_eq!(
        COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION, "eliot-cognitive-provider-runtime-v1",
        "the legacy cognitive contract's schema version is the constant's own value"
    );
    assert_eq!(
        COGNITIVE_RUNTIME_PREFLIGHT_SCHEMA_VERSION, "eliot-cognitive-runtime-preflight-v1",
        "the legacy cognitive preflight receipt's schema version is the constant's own value"
    );
    assert_ne!(
        COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION, PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION,
        "the legacy and current contract versions must DIFFER, or this is not a migration boundary"
    );

    // (a) The legacy evidence decodes, and every digest and ceiling it carried is
    // preserved byte for byte: nothing is re-derived, re-hashed or upgraded on read.
    // Its canonical fixture is `c2_CognitiveProviderRuntimeContract_canonical`: the
    // legacy type's own home fixture, because it IS a document of that type. It is
    // NOT a separate `c9_...` copy: a byte-identical second key under a name that
    // claimed a refusal would be a fixture asserting something it cannot show. The
    // SAME text is handed to a second decoder below, which is what (c) needs.
    let legacy_text = raw("c2_CognitiveProviderRuntimeContract_canonical");
    assert!(
        corpus()
            .get("fixtures")
            .and_then(|fixtures| fixtures
                .get("c10_area_legacy_cognitive_contract_through_current_decoder_refuse"))
            .is_none(),
        "the byte-identical `c10_area_...through_current_decoder_refuse` twin is deleted: \
         a legacy document is not refused on VERSION grounds by the current decoder, so a \
         fixture named for that refusal would claim a property the decoder does not have"
    );
    let legacy: CognitiveProviderRuntimeContract =
        decode(&legacy_text).expect("the legacy cognitive contract document must decode");
    assert_eq!(
        legacy.schema_version, COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION,
        "the legacy document must carry its own legacy schema version"
    );
    assert_eq!(
        legacy.runtime_contract_sha256,
        member(&legacy_text, "runtime_contract_sha256"),
        "the legacy contract's own contract digest must survive decoding unchanged"
    );
    assert_eq!(
        legacy.provider_executable_sha256,
        member(&legacy_text, "provider_executable_sha256"),
        "the legacy contract's executable digest must survive decoding unchanged"
    );
    assert_eq!(
        legacy.expected_mcp_tool_names,
        member_texts(&legacy_text, "expected_mcp_tool_names"),
        "the legacy tool ceiling must survive decoding unchanged"
    );
    assert_eq!(
        legacy.forbidden_mcp_server_names,
        member_texts(&legacy_text, "forbidden_mcp_server_names"),
        "the legacy server ceiling must survive decoding unchanged"
    );
    let legacy_twice: CognitiveProviderRuntimeContract =
        decode(&serde_json::to_string(&legacy).expect("the legacy contract must re-encode"))
            .expect("the re-encoded legacy contract must decode again");
    assert_eq!(
        serde_json::to_string(&legacy_twice).expect("the re-decoded contract must re-encode"),
        serde_json::to_string(&legacy).expect("the legacy contract must re-encode"),
        "reading legacy evidence twice must produce the same bytes every time"
    );

    // (b) The legacy preflight evidence decodes through the SAME decoder as the
    // current receipt, and that is a fact read from the source, not a boundary
    // this lane created: `legacy::CognitiveRuntimePreflightReceipt` is a TYPE ALIAS
    // (`pub type CognitiveRuntimePreflightReceipt = ProviderRuntimePreflightReceipt;`,
    // `crates/eliot-types/src/external_agent.rs:277`), so the fixture below cannot
    // and does not evidence a separate legacy boundary - it evidences that one
    // decoder accepts both version strings as data. Only the version STRING keeps
    // the legacy document distinguishable, and it is asserted to.
    let legacy_preflight_text = raw("c9_area_legacy_cognitive_runtime_preflight_receipt");
    let legacy_preflight: ProviderRuntimePreflightReceipt =
        decode(&legacy_preflight_text).expect("the legacy preflight receipt must decode");
    assert_eq!(
        legacy_preflight.schema_version, COGNITIVE_RUNTIME_PREFLIGHT_SCHEMA_VERSION,
        "the legacy preflight receipt must keep its own legacy schema version"
    );
    assert_ne!(
        legacy_preflight.schema_version, PROVIDER_RUNTIME_PREFLIGHT_SCHEMA_VERSION,
        "the legacy receipt must not present itself as the current preflight version"
    );
    assert_eq!(
        legacy_preflight.runtime_contract_sha256,
        member(&legacy_preflight_text, "runtime_contract_sha256"),
        "the legacy receipt's contract digest must survive decoding unchanged"
    );

    // (c) The SAFE direction of the migration, stated as the refusal the assertion
    // below expects and not as a version refusal: the current unified decoder is
    // handed the very same
    // legacy document and refuses it for a MISSING-MEMBER reason. `schema_version`
    // is a plain `String` on both types (`crates/eliot-types/src/external_agent.rs:176`
    // and `:262`), so no version comparison happens here at all; the legacy
    // representation lacks `mcp_tool_profile`
    // (`crates/eliot-types/src/external_agent.rs:197`), which the current contract
    // requires, and serde reports the FIRST missing required member in declaration
    // order - so exactly that one name appears. No current authority is
    // manufactured from old evidence.
    let Err(current_error) = decode::<ProviderRuntimeContract>(&legacy_text) else {
        panic!("the current contract must refuse the legacy representation");
    };
    let current_message = current_error.to_string();
    assert!(
        current_message.contains("missing field"),
        "the current contract's refusal must be a missing-member refusal, got: {current_message}"
    );
    assert!(
        current_message.contains("mcp_tool_profile"),
        "the refusal must name the unified member the legacy document lacks, got: {current_message}"
    );

    // (d) The legacy type is itself CLOSED, exactly like the current one: an
    // unknown member in the legacy representation is refused by the legacy
    // decoder's own `deny_unknown_fields`
    // (`crates/eliot-types/src/external_agent.rs:260`).
    assert_named_refusal::<CognitiveProviderRuntimeContract>(
        "c9_CognitiveProviderRuntimeContract_unknown_member_refuse",
        "c9_unknown_legacy_member",
        "unknown field",
    );
    // The legacy version STRING is again data, kept verbatim rather than promoted -
    // that is case 8's claim, asserted there once for this rule and cross-referenced
    // here rather than restated. What THIS case owns is the document-specific fact for
    // the legacy surface: the unsupported-version document differs from the legacy
    // CANONICAL in exactly the version member, so the unsupported value moved no
    // digest, no ceiling and no member of the legacy representation.
    let legacy_unsupported = raw("c8_CognitiveProviderRuntimeContract_unsupported_schema_version");
    let legacy_unsupported_version = member(&legacy_unsupported, SCHEMA_VERSION_MEMBER);
    assert_ne!(
        legacy_unsupported_version, COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION,
        "the fixture must actually carry an unsupported legacy version"
    );
    let legacy_unsupported_witness = witness(&legacy_unsupported);
    let legacy_canonical_witness = witness(&legacy_text);
    let legacy_differing: Vec<&str> = legacy_unsupported_witness
        .as_object()
        .expect("the legacy unsupported-version document must be a JSON object")
        .keys()
        .filter(|key| legacy_unsupported_witness.get(key) != legacy_canonical_witness.get(key))
        .map(String::as_str)
        .collect();
    assert_eq!(
        legacy_differing,
        vec![SCHEMA_VERSION_MEMBER],
        "an unsupported legacy version must change EXACTLY the version member of the \
         legacy representation and nothing else, got: {legacy_differing:?}"
    );
}

// WORK_UNIT_CASE: 933/c10_unsafe_migration_refuses
#[test]
#[allow(clippy::too_many_lines)]
fn c10_unsafe_migration_shapes_refuse_and_the_only_default_is_fail_closed() {
    assert_case_binding(
        "933/c10_unsafe_migration_refuses",
        &["ProviderRuntimeContract"],
    );
    assert_bytes_unchanged::<ProviderRuntimeContract>("ProviderRuntimeContract");
    let canonical_text = raw("c2_ProviderRuntimeContract_canonical");
    assert_eq!(
        member(&canonical_text, SCHEMA_VERSION_MEMBER),
        PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION,
        "the canonical contract must carry the current schema version on the wire"
    );

    // (a) An unsafe migration is a document that claims TWO generations at once: the
    // current members plus a revived legacy member. The current type's
    // `deny_unknown_fields` (`crates/eliot-types/src/external_agent.rs:174-175`)
    // refuses it, so a half-migrated or double-versioned contract never reaches a
    // caller as if it were current.
    let double = raw("c10_ProviderRuntimeContract_legacy_member_present_refuse");
    assert!(
        double.contains(SCHEMA_VERSION_MEMBER) && double.contains(LEGACY_CONTRACT_MEMBER),
        "the fixture must carry BOTH the current version member and the revived legacy member"
    );
    assert_ne!(
        double, canonical_text,
        "the double-generation fixture must actually differ from the canonical contract"
    );
    assert_named_refusal::<ProviderRuntimeContract>(
        "c10_ProviderRuntimeContract_legacy_member_present_refuse",
        LEGACY_CONTRACT_MEMBER,
        "unknown field",
    );

    // (b) `schema_version` itself is NOT defaulted on this type
    // (`crates/eliot-types/src/external_agent.rs:176` carries no `serde` attribute),
    // so a document that drops it is refused by name rather than accepted as an
    // unversioned contract. The document OMITS the member -
    // `assert_omitted_member_refusal` proves the key is absent from the stored text and
    // that the refusal names it, which is the property here. `assert_named_refusal`
    // could not be used: it proves its token is PRESENT, which is the opposite of what
    // an omission fixture is.
    assert_omitted_member_refusal::<ProviderRuntimeContract>(
        "c10_ProviderRuntimeContract_absent_schema_version_refuse",
        SCHEMA_VERSION_MEMBER,
    );

    // (c) The current contract's own control member is not defaulted INTO a grant:
    // `candidate_only` carries `#[serde(default)]`
    // (`crates/eliot-types/src/external_agent.rs:218-219`), so an omitted key decodes
    // as `false` - the fail-closed direction. Recorded as the behaviour the source
    // declares, asserted below and not yet run; it is the only default on this
    // control surface case 10 relies on.
    let absent = raw("c10_ProviderRuntimeContract_absent_candidate_only_default");
    assert!(
        !absent.contains(CANDIDATE_ONLY_MEMBER),
        "the fixture must actually OMIT `candidate_only`"
    );
    let decoded: ProviderRuntimeContract =
        decode(&absent).expect("a contract without `candidate_only` decodes to the false default");
    assert!(
        !decoded.candidate_only,
        "an omitted `candidate_only` must decode to `false`, never to a grant"
    );
    assert_eq!(
        decoded.runtime_contract_sha256,
        member(&absent, "runtime_contract_sha256"),
        "every other protected digest must survive the omitted control member unchanged"
    );

    // (d) A present `candidate_only: true` is kept as written and is not itself a
    // refusal: candidate marking is DATA, and it confers no Finish authority. The
    // candidate-canary claim is case 15's, at the documents that actually carry a
    // finish shape. The canonical contract already carries `candidate_only: true`,
    // so its own bytes are the fixture for this row.
    let candidate_text = canonical_text.clone();
    let candidate: ProviderRuntimeContract =
        decode(&candidate_text).expect("`candidate_only: true` is data and decodes");
    assert!(
        candidate.candidate_only,
        "a present `candidate_only: true` must decode to true, unchanged"
    );
    assert_eq!(
        candidate.schema_version,
        member(&candidate_text, SCHEMA_VERSION_MEMBER),
        "the marked candidate must still carry its own schema version"
    );
}

// WORK_UNIT_CASE: 933/c11_opaque_data_cannot_smuggle_control_meaning
#[test]
#[allow(clippy::too_many_lines)]
fn c11_opaque_payloads_stay_inert_and_the_flat_packet_layout_is_observable() {
    assert_case_binding(
        "933/c11_opaque_data_cannot_smuggle_control_meaning",
        &[
            "ProviderMcpServerContract",
            "ProviderMcpToolProfileBinding",
            "CompilePacketToolInput",
        ],
    );
    assert_bytes_unchanged::<ProviderMcpServerContract>("ProviderMcpServerContract");
    assert_bytes_unchanged::<ProviderMcpToolProfileBinding>("ProviderMcpToolProfileBinding");
    assert_bytes_unchanged::<CompilePacketToolInput>("CompilePacketToolInput");

    // (a) ProviderMcpServerContract's `command`, `args` and `cwd` are plain strings
    // and vectors of strings. A command string carrying shell- and
    // authority-imitating text decodes verbatim, and the two effect booleans keep
    // the DOCUMENT's own values: an opaque payload cannot flip `required` or
    // `enabled`, and no field of this struct interprets the string.
    let opaque_text = raw("c11_ProviderMcpServerContract_opaque_command_accepted");
    let opaque: ProviderMcpServerContract =
        decode(&opaque_text).expect("an opaque command string is accepted as data");
    assert_eq!(
        opaque.command,
        member(&opaque_text, "command"),
        "the opaque command must decode to the document's own bytes"
    );
    assert_eq!(
        opaque.required,
        member_bool(&opaque_text, "required"),
        "the opaque command must not change the contract's own `required` effect flag"
    );
    assert_eq!(
        opaque.enabled,
        member_bool(&opaque_text, "enabled"),
        "the opaque command must not change the contract's own `enabled` effect flag"
    );
    assert_eq!(
        opaque.executable_sha256,
        member(&opaque_text, "executable_sha256"),
        "the executable digest must survive the opaque payload unchanged"
    );

    // (b) ProviderMcpToolProfileBinding's digest is verifiable DATA, not an
    // authority. THE POINT OF THIS ROW IS THAT THE DECODER PERFORMS NO VERIFICATION
    // AT ALL: `Deserialize` for this type is derived and carries
    // `#[serde(deny_unknown_fields)]`
    // (`crates/eliot-types/src/external_agent.rs:139-141`) with no digest check, so a
    // document whose `profile_hash_blake3` matches nothing still DECODES. Only the
    // separate `hash_is_valid` accessor
    // (`crates/eliot-types/src/external_agent.rs:167-170`) reports the mismatch, and it
    // neither grants nor denies anything.
    //
    // There is deliberately NO comparison of `hash_is_valid()` against a
    // re-implementation of `hash_is_valid`'s own body here: that body IS
    // `ProviderMcpToolProfileBinding::new(profile_id, tool_names)
    // .profile_hash_blake3 == self.profile_hash_blake3`, so any such comparison
    // restates the accessor instead of evidencing it, and would pass no matter which
    // decoder ran. The two real observations below are the tampered document decoding
    // to its own stored digest, and `hash_is_valid()` REPORTING `false` for it.
    let tampered_text = raw("c11_ProviderMcpToolProfileBinding_tampered_digest_observed");
    let tampered: ProviderMcpToolProfileBinding = decode(&tampered_text)
        .expect("a wrong digest is still ACCEPTED: the decoder performs no verification");
    assert_eq!(
        tampered.profile_hash_blake3,
        member(&tampered_text, "profile_hash_blake3"),
        "the tampered digest must decode to the document's own value, unverified"
    );
    assert!(
        !tampered.hash_is_valid(),
        "`hash_is_valid` must report the tampered digest as unverifiable, not grant it"
    );

    // (c) THE FLAT `CompilePacketToolInput` LAYOUT, as observable behaviour: the
    // wrapper keys and the flattened `CompilePacketL3Request` keys share ONE object,
    // and there is no nested `request` member.
    let packet_text = raw("c2_CompilePacketToolInput_canonical");
    let packet: CompilePacketToolInput =
        decode(&packet_text).expect("the canonical flat compile-packet document must decode");
    assert!(
        !packet_text.contains(&format!("\"{NESTED_REQUEST_MEMBER}\"")),
        "the flat layout has no nested `request` object"
    );
    assert_eq!(
        packet.request.goal,
        member(&packet_text, "goal"),
        "the request's `goal` must decode from the TOP-LEVEL member of the same object"
    );
    assert_eq!(
        packet.request.task_id,
        member(&packet_text, "task_id"),
        "the request's `task_id` must decode from the TOP-LEVEL member of the same object"
    );
    assert_eq!(
        packet.request.project_id.as_uuid().to_string(),
        member(&packet_text, "project_id"),
        "the request's `project_id` must decode from the TOP-LEVEL member of the same object"
    );

    // (d) `max_tokens`' DEFAULT, as observable behaviour: an omitted key decodes to
    // the exported preferred-target default, and a present key decodes to the
    // document's own number. The default is asserted against the constant, never
    // against a literal. This is the card MAKE clause's second half, kept
    // observable in the case that owns the type as well as in case 2.
    assert_eq!(
        DEFAULT_CONTEXT_PACKET_PREFERRED_TOKENS, 1_800,
        "the preferred-target default is the exported constant's own value"
    );
    assert_eq!(
        packet.request.max_tokens,
        member_usize(&packet_text, MAX_TOKENS_MEMBER),
        "a present `max_tokens` must decode to the document's own number"
    );
    let explicit_text = raw("c11_area_mcp_flat_packet_explicit_max_tokens");
    let explicit: CompilePacketToolInput =
        decode(&explicit_text).expect("the explicitly-sized flat packet must decode");
    assert_eq!(
        explicit.request.max_tokens,
        member_usize(&explicit_text, MAX_TOKENS_MEMBER),
        "an explicit `max_tokens` must decode to the document's own number"
    );
    // The two documents carry DIFFERENT numbers, and each decodes to its own. Neither
    // is the exported default: the default is 1_800 and both explicit targets are
    // asserted against their own document text above, so the property this row owns is
    // that the decoder COERCES NEITHER of them - not that two packets agree.
    assert_ne!(
        member_usize(&packet_text, MAX_TOKENS_MEMBER),
        member_usize(&explicit_text, MAX_TOKENS_MEMBER),
        "the two explicit-token documents must really carry different numbers, or this row \
         proves nothing about either one"
    );
    assert_ne!(
        packet.request.max_tokens, DEFAULT_CONTEXT_PACKET_PREFERRED_TOKENS,
        "the canonical packet's own explicit target must NOT be coerced to the default"
    );
    assert_ne!(
        explicit.request.max_tokens, DEFAULT_CONTEXT_PACKET_PREFERRED_TOKENS,
        "the explicitly-sized packet's own target must NOT be coerced to the default"
    );
    let default_text = raw("c11_area_mcp_flat_packet_max_tokens_default");
    assert!(
        !default_text.contains(MAX_TOKENS_MEMBER),
        "the default fixture must actually OMIT `max_tokens`"
    );
    let defaulted: CompilePacketToolInput =
        decode(&default_text).expect("a flat packet without `max_tokens` must decode");
    assert_eq!(
        defaulted.request.max_tokens, DEFAULT_CONTEXT_PACKET_PREFERRED_TOKENS,
        "an omitted `max_tokens` must decode to the exported preferred-target default"
    );

    // (e) The one permitted shape is refused if it nests instead: a document whose
    // `request` is an OBJECT hits the visitor's unknown-member arm
    // (`crates/eliot-types/src/mcp_contract.rs:134-136`), so a second layout cannot
    // be introduced through the same tool input.
    let nested_text = raw("c11_CompilePacketToolInput_nested_request_object_refuse");
    assert!(
        nested_text.contains(&format!("\"{NESTED_REQUEST_MEMBER}\":{{")),
        "the fixture must actually nest `{NESTED_REQUEST_MEMBER}` as an object"
    );
    assert_named_refusal::<CompilePacketToolInput>(
        "c11_CompilePacketToolInput_nested_request_object_refuse",
        NESTED_REQUEST_MEMBER,
        "unknown field",
    );

    // (f) Opaque candidate handles stay data: handles imitating authority text decode
    // as the strings they are, and no other field of the input moves.
    let handles_text = raw("c11_CompilePacketToolInput_opaque_candidate_handles_accepted");
    let handles: CompilePacketToolInput =
        decode(&handles_text).expect("opaque candidate handles are accepted as data");
    assert_eq!(
        handles.request.candidate_handles,
        member_texts(&handles_text, "candidate_handles"),
        "opaque candidate handles must decode to the document's own strings, unchanged"
    );
    assert_eq!(
        handles.request.goal,
        member(&handles_text, "goal"),
        "an opaque handle list must not change the packet's own goal"
    );
    assert_eq!(
        handles.request.max_tokens,
        member_usize(&handles_text, MAX_TOKENS_MEMBER),
        "an opaque handle list must not change the packet's own token target"
    );

    // (g) The same envelope rule on the three remaining opaque-bearing documents: an
    // unknown member is refused by each type's own `deny_unknown_fields`, so the
    // documents above could not smuggle a control member in either.
    assert_named_refusal::<CompilePacketToolInput>(
        "c11_CompilePacketToolInput_unknown_member_refuse",
        "c11_unknown_flat_member",
        "unknown field",
    );
    assert_named_refusal::<ProviderMcpServerContract>(
        "c11_ProviderMcpServerContract_unknown_member_refuse",
        "c11_unknown_mcp_server_member",
        "unknown field",
    );
    assert_named_refusal::<ProviderMcpToolProfileBinding>(
        "c11_ProviderMcpToolProfileBinding_unknown_member_refuse",
        "c11_unknown_mcp_profile_member",
        "unknown field",
    );

    // (h) THE MAP-TYPED MEMBERS, which are the real opaque-carrier risk in this slice:
    // a `BTreeMap<String, String>` has no closed key set and no typed values, so it is
    // where a control-looking key could hide. It does not.
    // `ProviderRuntimeContract.nonsecret_environment` is declared
    // `BTreeMap<String, String>` at `crates/eliot-types/src/external_agent.rs:194`, and
    // the same declaration appears on the legacy contract at `:269`. Both are behind
    // the envelope's `deny_unknown_fields` (`:174-175`), so neither can gain a
    // sibling member either. A map KEY has no decoder of its own: `serde_json` maps it
    // to whatever `String` it is, and no code on this boundary reads a key. So a key
    // spelled `authority`, `finish` or `protected` is DATA, and the proof is that the
    // decoded map holds exactly the document's own pairs and that the document's real
    // control members did not move.
    let inert_text =
        raw("c11_ProviderRuntimeContract_nonsecret_environment_authority_keys_inert_accepted");
    // RECORDED, NOT CLAIMED: this block decodes `ProviderRuntimeContract`, and case 11
    // does NOT own that type - `TYPE_HOME_CASE` gives it the home binding
    // `933/c10_unsafe_migration_refuses`, which is case 10's row. `assert_also_decodes`
    // records the decode and asserts that the owner really is case 10, so case 11's
    // binding list stays exactly the three types it owns.
    assert_also_decodes::<ProviderRuntimeContract>(
        "ProviderRuntimeContract",
        "933/c10_unsafe_migration_refuses",
    );
    let inert: ProviderRuntimeContract =
        decode(&inert_text).expect("control-looking environment keys are accepted as opaque data");
    let inert_environment = member_value(&inert_text, "nonsecret_environment");
    let inert_pairs = inert_environment
        .as_object()
        .expect("`nonsecret_environment` must be a JSON object of string pairs");
    for control_key in ["authority", "finish", "protected"] {
        assert!(
            inert_pairs.contains_key(control_key),
            "the fixture must really carry a control-looking key `{control_key}` in \
             `nonsecret_environment`"
        );
        assert_eq!(
            inert
                .nonsecret_environment
                .get(control_key)
                .map(String::as_str),
            inert_pairs
                .get(control_key)
                .and_then(serde_json::Value::as_str),
            "`{control_key}` must decode to the document's own string value, as data"
        );
    }
    // The whole map, member for member: the decoded map is the document's own map and
    // not one entry more or less, so a control-looking key gained no special standing.
    assert_eq!(
        inert.nonsecret_environment.len(),
        inert_pairs.len(),
        "the decoded `nonsecret_environment` must hold exactly the document's own entries"
    );
    for (key, value) in inert_pairs {
        assert_eq!(
            inert.nonsecret_environment.get(key).map(String::as_str),
            value.as_str(),
            "`nonsecret_environment[{key}]` must decode to the document's own value"
        );
    }
    // The contract's REAL control members are untouched by the map's contents: the map
    // is data, so it cannot move the effect flags or the version.
    assert_eq!(
        inert.candidate_only,
        member_bool(&inert_text, CANDIDATE_ONLY_MEMBER),
        "an environment map carrying control-looking keys must not change the contract's \
         own `candidate_only` flag"
    );
    assert_eq!(
        inert.permission_profile,
        member(&inert_text, "permission_profile"),
        "an environment map carrying control-looking keys must not change the contract's \
         own `permission_profile`"
    );
    assert_eq!(
        inert.schema_version,
        member(&inert_text, SCHEMA_VERSION_MEMBER),
        "an environment map carrying control-looking keys must not change the contract's \
         own `schema_version`"
    );
    // And the same envelope rule as (g): the document carrying the map is closed, so
    // the map is not a licence to add a top-level member either.
    assert_ne!(
        inert_text,
        raw("c2_ProviderRuntimeContract_canonical"),
        "the control-looking-environment document must really differ from the canonical one"
    );
}

// WORK_UNIT_CASE: 933/c12_ambiguous_alias_default_cannot_grant_authority
#[test]
#[allow(clippy::too_many_lines)]
fn c12_observe_alias_and_helper_default_are_recorded_non_clean_not_passes() {
    assert_case_binding(
        "933/c12_ambiguous_alias_default_cannot_grant_authority",
        &["ObserveInput", "ObserveHint"],
    );
    assert_bytes_unchanged::<ObserveInput>("ObserveInput");
    assert_enum_spelling::<ObserveHint>("ObserveHint");

    // (a0) THE ISSUE'S "UNTAGGED FORMS" CLAUSE HAS NO WIRE FORM IN THIS SLICE, and that
    // is a MEASURED FACT, not an omission. I searched the four T04 files for the word
    // `untagged` and found it ONLY inside doc-comment prose:
    // `crates/eliot-types/src/mcp_contract.rs:274`, `:418` and `:465`, in sentences
    // that say no `untagged` form is being added. There is NO
    // `#[serde(untagged)]` attribute anywhere in
    // `crates/eliot-types/src/adapter.rs`,
    // `crates/eliot-types/src/external_agent.rs`,
    // `crates/eliot-types/src/mcp_contract.rs` or
    // `crates/eliot-types/src/provider_invocation.rs`, so there is no ambiguous
    // try-each-shape decode on this boundary for an alias, a default or an untagged
    // form to hide in.
    //
    // NO FIXTURE IS INVENTED FOR THIS CLAUSE. There is no document that could
    // demonstrate an untagged form, because none exists to demonstrate; a fabricated
    // one would assert a decoder feature this slice does not have. The clause is
    // discharged as this measured statement plus the fact that every ambiguous path
    // that DOES exist - the alias in (b) and the helper default in (c) - is recorded
    // non-clean below and asserted as such.
    //
    // (The interface recorded the three prose occurrences as `:277`, `:420` and `:465`;
    // the search above finds them at `:274`, `:418` and `:465`. The two earlier lines
    // differ by three and two lines. The measured positions are the ones cited here,
    // because a citation that points at the wrong line is worse than a differing one.)

    // ============================== WORDS FIRST =============================
    // The three paths exercised below are KNOWN NON-CLEAN. They are recorded here as
    // the behaviour the source declares and the assertions below are written to
    // check, and handed off to their named owner. They are NOT passes,
    // NOT clean paths, and this card repairs none of them.
    //
    // 1. `ObserveInput.hint` carries `#[serde(default, alias = "kind")]`
    //    (`crates/eliot-types/src/mcp_contract.rs:420`). The CURRENT decoder
    //    trial-accepts ONE closed control variant under TWO names, which APPENDIX-P
    //    line 13 forbids ("closed control variants fail when unknown"). No named
    //    legacy boundary anywhere in the workspace admits the `kind` spelling, so
    //    the alias is an unsanctioned trial-accept, not a retained compatibility
    //    row. Owner: the generated inventory row
    //    (`crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml`,
    //    `owner = "#692"`, `repair_child = "#933"`) with `eliot-app` coordinating.
    // 2. `ObserveInput.schema_version` carries the helper default
    //    `default = "default_observe_schema_version"` (`mcp_contract.rs:472-473`,
    //    helper at `:476-478`),
    //    so an OMITTED key is silently promoted to the current version. The version
    //    IS enforced later by `dispatch_observe`, outside this crate's file scope;
    //    making the key required would move the published `eliot.observe`
    //    `inputSchema` required set every connected agent sees, which is an
    //    APPENDIX-P major incompatibility owned by the catalogue owner. Same
    //    named-owner handoff.
    //
    // What case 12 can and does assert is the LIMIT of the damage: neither path
    // GRANTS authority. `ObserveInput` has no authority, effect, permission, scope,
    // receipt or Finish field at all, so an accepted alias or a promoted version
    // changes nothing about what the caller may do; it only makes the document
    // ambiguous about which name and which version were stated. Every other unknown
    // key is still refused, and (e) below asserts it.
    // =======================================================================

    // (a) The container records both rows, complete, under the fixed identifiers.
    let rows = corpus()
        .get("known_non_clean")
        .and_then(serde_json::Value::as_array)
        .expect("the corpus must carry a `known_non_clean` array")
        .clone();
    let row_ids: Vec<String> = rows
        .iter()
        .map(|row| {
            row.get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("every known_non_clean row needs an `id`"))
                .to_owned()
        })
        .collect();
    for id in KNOWN_NON_CLEAN_IDS {
        assert!(
            row_ids.iter().any(|row_id| row_id == id),
            "the corpus must record the known non-clean row {id}; it has {row_ids:?}"
        );
        let row = rows
            .iter()
            .find(|row| row.get("id").and_then(serde_json::Value::as_str) == Some(id))
            .unwrap_or_else(|| panic!("the corpus must carry the row {id}"));
        for field in ["path", "property", "observed", "why_not_clean", "owner"] {
            let text = row
                .get(field)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("known_non_clean row {id} must carry `{field}`"));
            assert!(
                !text.trim().is_empty(),
                "known_non_clean row {id} must state a non-empty `{field}`"
            );
        }
    }

    // (b) The alias trial-accept, ASSERTED AS THE NON-CLEAN PROPERTY THE SOURCE
    // DECLARES. `"kind"` is asserted below to decode to the very
    // same closed variant the canonical `"hint"` spelling names: one variant, two
    // accepted names.
    let alias_text = raw("c12_area_observe_input_hint_legacy_kind_alias");
    assert!(
        alias_text.contains(ALIAS_HINT_MEMBER) && !alias_text.contains(CANONICAL_HINT_MEMBER),
        "the alias fixture must use the alias spelling and NOT the canonical one"
    );
    let aliased: ObserveInput =
        decode(&alias_text).expect("the `kind` alias IS accepted by the current decoder");
    assert_eq!(
        aliased.hint,
        ObserveHint::Decision,
        "the alias spelling must decode to the very variant the canonical spelling names"
    );
    let canonical_hint_text = raw("c12_ObserveInput_hint_canonical_spelling_accepted");
    assert!(
        canonical_hint_text.contains(CANONICAL_HINT_MEMBER),
        "the control fixture must use the canonical `hint` spelling"
    );
    let canonical_hint: ObserveInput =
        decode(&canonical_hint_text).expect("the canonical `hint` spelling must decode");
    assert_eq!(
        canonical_hint.hint, aliased.hint,
        "one closed variant, two accepted names: this is the recorded non-clean property"
    );
    // The closed enum itself is still closed: a `hint` VALUE outside it is refused
    // by `ObserveHint`'s own decoder, so the non-clean property is one extra NAME
    // for an existing variant and not a new variant.
    assert_named_refusal::<ObserveHint>(
        "c12_ObserveHint_unknown_tag_refuse",
        "c12_unknown_observe_hint",
        "unknown variant",
    );

    // (c) The helper default, ASSERTED AS THE NON-CLEAN PROPERTY THE SOURCE
    // DECLARES: an omitted `schema_version` is asserted below to be
    // promoted to the current version.
    let absent_text = raw("c12_area_observe_input_absent_schema_version_helper_default");
    assert!(
        !absent_text.contains(SCHEMA_VERSION_MEMBER),
        "the default fixture must actually OMIT `schema_version`"
    );
    let promoted: ObserveInput =
        decode(&absent_text).expect("an omitted `schema_version` decodes to the helper default");
    assert_eq!(
        promoted.schema_version, OBSERVE_INPUT_SCHEMA_VERSION,
        "an omitted `schema_version` is promoted to the current version - KNOWN NON-CLEAN"
    );

    // (d) THE FOREIGN VERSION, as what this case owns: `ObserveInput.schema_version` is a
    // plain `String` (`crates/eliot-types/src/mcp_contract.rs:472-473`), so a foreign
    // value is DATA here and the refusal belongs to `dispatch_observe`
    // (`crates/eliot-app/src/mcp_stdio/verification.rs`, recorded at
    // `mcp_contract.rs:442-445`), outside this crate's file scope. The
    // "unsupported version is kept verbatim and never promoted" RULE is asserted once,
    // in case 8 (b) and (d), which owns it; asserting it a third time here would give
    // three cases the same observable. What this case asserts instead is the
    // document-specific fact: the foreign-version observation differs from the
    // canonical one in EXACTLY the version member, so the foreign value moved nothing
    // else in the document, and it is not one of the five exported constants.
    let foreign_text = raw("c8_ObserveInput_unsupported_schema_version");
    let foreign_value = member(&foreign_text, SCHEMA_VERSION_MEMBER);
    assert_ne!(
        foreign_value, OBSERVE_INPUT_SCHEMA_VERSION,
        "the fixture must actually carry a foreign version"
    );
    for (name, constant) in [
        (
            "PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION",
            PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION,
        ),
        (
            "PROVIDER_RUNTIME_PREFLIGHT_SCHEMA_VERSION",
            PROVIDER_RUNTIME_PREFLIGHT_SCHEMA_VERSION,
        ),
        (
            "OPERATION_AUTHORITY_SCHEMA_VERSION",
            OPERATION_AUTHORITY_SCHEMA_VERSION,
        ),
        (
            "COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION",
            COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION,
        ),
        (
            "COGNITIVE_RUNTIME_PREFLIGHT_SCHEMA_VERSION",
            COGNITIVE_RUNTIME_PREFLIGHT_SCHEMA_VERSION,
        ),
    ] {
        assert_ne!(
            foreign_value, constant,
            "the foreign version must not be any exported current version, including \
             {name}"
        );
    }
    let canonical_observe_text = raw("c2_ObserveInput_canonical");
    let foreign_witness = witness(&foreign_text);
    let canonical_observe_witness = witness(&canonical_observe_text);
    let differing: Vec<&str> = foreign_witness
        .as_object()
        .expect("the foreign-version document must be a JSON object")
        .keys()
        .filter(|key| foreign_witness.get(key) != canonical_observe_witness.get(key))
        .map(String::as_str)
        .collect();
    assert_eq!(
        differing,
        vec![SCHEMA_VERSION_MEMBER],
        "an unsupported version must change EXACTLY the version member of the observation \
         and nothing else, got: {differing:?}"
    );

    // (e) The limit that IS clean: every other unknown key is refused, so an unknown
    // key stays distinct from the alias.
    assert_named_refusal::<ObserveInput>(
        "c12_ObserveInput_unknown_member_refuse",
        UNKNOWN_HINT_MEMBER,
        "unknown field",
    );

    // (f) Opaque payloads cannot smuggle CONTROL meaning either: the observation
    // payload and a candidate statement may carry authority- and finish-imitating
    // text, and it decodes verbatim as the inert `Value`/string it is. Neither
    // document gains a field, and neither `ObserveInput` nor the candidate input
    // has an authority, effect or Finish member for such text to reach.
    let observe_payload_text = raw("c12_area_observe_payload_control_keys");
    let observe_payload: ObserveInput = decode(&observe_payload_text)
        .expect("control-imitating observation payload text is accepted as opaque data");
    assert_eq!(
        observe_payload.text_or_structured_payload,
        member_value(&observe_payload_text, "text_or_structured_payload"),
        "the control-imitating payload must decode verbatim, unchanged and inert"
    );
    assert_eq!(
        observe_payload.hint,
        ObserveHint::Auto,
        "an opaque payload must not have moved the observation's own hint"
    );
    let candidate_payload_text = raw("c12_area_agent_candidate_payload_control_keys");
    let candidate_payload: AgentCandidateSubmitInput = decode(&candidate_payload_text)
        .expect("control-imitating candidate statement text is accepted as opaque data");
    assert_eq!(
        candidate_payload.statement,
        member(&candidate_payload_text, "statement"),
        "the control-imitating statement must decode verbatim, unchanged and inert"
    );

    // (g) Neither accepted path changed any other member of the document.
    assert_eq!(
        aliased.text_or_structured_payload,
        member_value(&alias_text, "text_or_structured_payload"),
        "the alias trial-accept must not rewrite the observation payload"
    );
    assert_eq!(
        promoted.text_or_structured_payload,
        member_value(&absent_text, "text_or_structured_payload"),
        "the promoted version must not rewrite the observation payload"
    );
}

// WORK_UNIT_CASE: 933/c13_exact_exceptions_invalidate_on_use_change
#[test]
#[allow(clippy::too_many_lines)]
fn c13_flat_packet_exceptions_are_exact_and_invalidate_on_use_change() {
    assert_case_binding(
        "933/c13_exact_exceptions_invalidate_on_use_change",
        &["CompilePacketToolInputVisitor"],
    );

    // `CompilePacketToolInputVisitor` is `struct CompilePacketToolInputVisitor;` with
    // NO `pub` (`crates/eliot-types/src/mcp_contract.rs:50`), so this file CANNOT
    // name it and does not widen it to: `crates/eliot-types/src/lib.rs` is read-only
    // here and the card forbids widening a visibility. It is bound to this case
    // through the only observable surface it has - it is the visitor that
    // `CompilePacketToolInput::deserialize` constructs (`mcp_contract.rs:41-48`), so
    // every assertion below is written to be run as an assertion about that
    // visitor. Nothing in this test has been executed by its writer.
    //
    // THE COUPLING AS READ FROM SOURCE, stated here because this case exists
    // for it:
    // `COMPILE_PACKET_TOOL_FIELDS` (`mcp_contract.rs:52-60`) lists the wrapper's own
    // two members (`material_frame`, `memory_mode`) plus the five CURRENT
    // `CompilePacketL3Request` members (`crates/eliot-types/src/memory.rs:2027-2038`:
    // `project_id`, `task_id`, `goal`, `candidate_handles`, `max_tokens`), and those
    // five request keys are additionally hard-coded as `match` arms
    // (`mcp_contract.rs:99-133`) whose values are buffered into the map handed to
    // `CompilePacketL3Request::deserialize` (`mcp_contract.rs:139-140`). The permitted
    // list is therefore TIGHTLY COUPLED to another owner's declaration: adding,
    // renaming, removing or retyping ANY `CompilePacketL3Request` member silently
    // invalidates this decoder - the key would fall through to the unknown-member
    // arm, or a wrapper key would be consumed by the request - and the published
    // schema would then disagree with the decoder. #933 owns no correction of
    // `CompilePacketL3Request` (card DO NOT). This test is the standing statement of
    // that coupling, not a drift detector.

    // (a) The visitor's own accepted document carries exactly the seven permitted
    // keys, once each: the mechanical statement of the permitted list.
    //
    // THE FIX, and it is in this file and not in the container: there is NO
    // `c2_CompilePacketToolInputVisitor_canonical`, because the visitor is not a
    // `Deserialize` and no wire document is of that type. Reading one would make
    // `raw()` panic on a missing key, and no fixture was invented to paper over
    // that. The document the visitor ACCEPTS is
    // `c2_CompilePacketToolInput_canonical`, and that is what is read here. The
    // allocation row stays bound to this case through this decoder, and case 1
    // asserts the absent key's absence so the row cannot be "satisfied" later by
    // a fabricated one.
    assert!(
        corpus()
            .get("fixtures")
            .and_then(|fixtures| fixtures.get("c2_CompilePacketToolInputVisitor_canonical"))
            .is_none(),
        "the private visitor has no wire document, so the container must not carry one"
    );
    // The visitor's own accepted document carries exactly the seven permitted
    // keys, once each: the mechanical statement of the permitted list.
    let canonical_text = raw("c2_CompilePacketToolInput_canonical");
    for key in PERMITTED_PACKET_KEYS {
        assert_eq!(
            repeats(&canonical_text, key),
            1,
            "the visitor's accepted document must carry the permitted key `{key}` exactly once"
        );
    }
    assert_eq!(
        repeats(&canonical_text, NESTED_REQUEST_MEMBER),
        0,
        "the visitor's accepted document must not nest `{NESTED_REQUEST_MEMBER}`"
    );
    let accepted: CompilePacketToolInput =
        decode(&canonical_text).expect("the visitor's accepted document must decode");
    assert_eq!(
        accepted.request.goal,
        member(&canonical_text, "goal"),
        "the visitor must route the flattened `goal` key into the request"
    );
    // WHAT IS COMPARED HERE IS EXACTLY PRESENCE-OR-NULLNESS, and that is deliberate.
    // Both wrapper members are typed `Option<..>`, so `Some(..)` and `None` are the
    // only two observable outcomes, and the canonical document states both as explicit
    // `null` - which is the I05-16 shape ("Fields that do not apply remain explicit
    // `None`; they are not silently omitted", `docs/architecture/I05-16-common-durable-fields.md:46`).
    // The assertion therefore states that a PRESENT null decodes to `None`. It does
    // NOT distinguish an absent key from a present null, and it does not claim to: an
    // absent key and a present null are the same fact at this boundary, which is the
    // property this case owns - the visitor forwards the wrapper key to the wrapper
    // type rather than consuming it into the request.
    assert_eq!(
        accepted.material_frame.is_none(),
        member_value(&canonical_text, "material_frame").is_null(),
        "the visitor's own wrapper key must decode to None exactly when the document states \
         a present null - a presence/nullness comparison, which is all this member offers"
    );
    assert_eq!(
        accepted.memory_mode.is_none(),
        member_value(&canonical_text, "memory_mode").is_null(),
        "the visitor's own wrapper key must decode to None exactly when the document states \
         a present null - a presence/nullness comparison, which is all this member offers"
    );

    // (b) The exact permitted list, read back out of the visitor's OWN refusal
    // message: an unknown key is refused and the message enumerates exactly these
    // seven names, which is the list the arms and the constant both encode.
    let unknown_text = raw("c13_CompilePacketToolInput_unknown_packet_key_refuse");
    assert!(
        unknown_text.contains(UNKNOWN_PACKET_MEMBER),
        "the fixture must actually inject the unknown packet key"
    );
    assert_named_refusal::<CompilePacketToolInput>(
        "c13_CompilePacketToolInput_unknown_packet_key_refuse",
        UNKNOWN_PACKET_MEMBER,
        "unknown field",
    );
    let Err(unknown_error) = decode::<CompilePacketToolInput>(&unknown_text) else {
        panic!("an unknown packet key must be refused by the visitor");
    };
    let unknown_message = unknown_error.to_string();
    for key in PERMITTED_PACKET_KEYS {
        assert!(
            unknown_message.contains(key),
            "the visitor's refusal must enumerate the permitted key `{key}`, got: {unknown_message}"
        );
    }

    // (c) The visitor's duplicate-member check, which a derived `flatten` decoder
    // could not perform: the raw map is read key by key and a repeat is refused
    // BEFORE any insertion (`mcp_contract.rs:86-133`), so "first occurrence wins" is
    // impossible on this boundary.
    let duplicate_text = raw("c13_CompilePacketToolInput_duplicate_key_refuse");
    assert!(
        repeats(&duplicate_text, "project_id") >= 2,
        "the fixture must repeat a permitted key in its raw text"
    );
    assert_named_refusal::<CompilePacketToolInput>(
        "c13_CompilePacketToolInput_duplicate_key_refuse",
        "project_id",
        "duplicate field",
    );

    // (d) The request side is still typed: a permitted key the request itself
    // requires must be present, so the visitor's key routing cannot conjure a
    // request. `mcp_contract.rs:139-140` re-deserializes the buffered map through
    // `CompilePacketL3Request`, whose own required members and
    // `deny_unknown_fields` apply.
    //
    // The document OMITS the required key `{MISSING_PACKET_MEMBER}` -
    // `pub goal: String` at `crates/eliot-types/src/memory.rs:2027-2030`, with no
    // `serde(default)` - and the refusal therefore NAMES it. That is why this row
    // uses `assert_omitted_member_refusal` and not `assert_named_refusal`: the latter
    // proves its token is PRESENT in the document, which is exactly what an omission
    // fixture is not, so the two assertions above and below used to contradict each
    // other - one asserting the key is absent and the next demanding it be present.
    let missing_text = raw("c13_CompilePacketToolInput_missing_required_key_refuse");
    assert!(
        !missing_text.contains(&format!("\"{MISSING_PACKET_MEMBER}\"")),
        "the fixture must actually OMIT the required request key `{MISSING_PACKET_MEMBER}`"
    );
    assert_omitted_member_refusal::<CompilePacketToolInput>(
        "c13_CompilePacketToolInput_missing_required_key_refuse",
        MISSING_PACKET_MEMBER,
    );
}

// WORK_UNIT_CASE: 933/c14_bounded_malformed_inputs_panic_free
#[test]
#[allow(clippy::too_many_lines)]
fn c14_bounded_malformed_inputs_are_panic_free_and_code_is_a_free_reason_string() {
    const NUL_MEMBER: &str = "c14_embedded_nul\u{0}_member";

    assert_case_binding(
        "933/c14_bounded_malformed_inputs_panic_free",
        &["AdapterError"],
    );
    assert_bytes_unchanged::<AdapterError>("AdapterError");

    // Eight bounded malformed inputs, each handed to the decoder as raw text inside
    // `catch_unwind`: the claim under test is not only that they fail but that they
    // fail WITHOUT a panic, unwind or abort. Every one of these documents is stored
    // verbatim as wire text; two of them are not JSON at all, which is exactly why
    // the container must store them as strings.
    let malformed: [(&str, &str); 8] = [
        ("c14_area_truncated_object_text", "a truncated object"),
        ("c14_area_not_json_text", "text that is not JSON at all"),
        ("c14_area_empty_input_text", "the empty input"),
        ("c14_area_top_level_array_text", "a top-level array"),
        ("c14_area_top_level_number_text", "a top-level number"),
        (
            "c14_area_non_object_top_level_text",
            "a bare top-level string",
        ),
        ("c14_area_deep_nested_value_text", "deep nesting"),
        (
            "c14_area_embedded_nul_escape_text",
            "an escaped NUL inside a MEMBER NAME",
        ),
    ];
    for (fixture_name, shape) in malformed {
        let text = raw(fixture_name);
        // `catch_unwind` returns `Ok` when nothing unwound, so `Ok(Err(..))` is the
        // claimed outcome: a refusal with no panic. A panic payload would surface
        // here as `Err`.
        let inner = std::panic::catch_unwind(|| decode::<AdapterError>(&text))
            .unwrap_or_else(|_| panic!("{fixture_name} ({shape}) must not panic"));
        let Err(error) = inner else {
            panic!("{fixture_name} ({shape}) must be refused, not decoded");
        };
        assert!(
            !error.to_string().trim().is_empty(),
            "{fixture_name} must report a non-empty error instead of panicking"
        );
    }

    // (a1) THE NUL-IN-MEMBER-NAME ROW, asserted to the NEW truth, which is the
    // opposite of what this fixture used to prove and had to be corrected. The
    // document is
    // `{"code":"a","message":"933-c14-nul","retryable":false,"c14_embedded_nul\u{0}_member":true}`:
    // a VALID JSON object whose unknown member NAME carries an embedded NUL. It used
    // to place the NUL inside `code`'s VALUE (`{"code":"933\u{0}c14",...}`), which is a
    // perfectly legal `AdapterError` - `AdapterError.code` is a plain `String`
    // (`crates/eliot-types/src/adapter.rs:174`) and `\u0000` is a legal JSON escape - so
    // the case gated that row with `let Err(error) = inner else { panic!(...) }` and
    // would have PANICKED on a document that decoded.
    //
    // What is true NOW, and what is asserted here: the document is REFUSED, because
    // `AdapterError` carries `#[serde(deny_unknown_fields)]`
    // (`crates/eliot-types/src/adapter.rs:172`) and the NUL-bearing member is unknown to
    // it; and the refusal NAMES that member. The three declared members are all
    // present, so this refusal is not a missing-field failure wearing the same
    // document - it is the unknown-member arm.
    let nul_text = raw("c14_area_embedded_nul_escape_text");
    assert!(
        nul_text.contains(&format!("\"{NUL_MEMBER}\"")),
        "the fixture must really carry a member whose NAME embeds a NUL"
    );
    let nul_witness = witness(&nul_text);
    for declared in ["code", "message", "retryable"] {
        assert!(
            nul_witness.get(declared).is_some(),
            "the NUL fixture must still carry the declared member `{declared}`, so its \
             refusal is an unknown-member refusal and not a missing-field one"
        );
    }
    let nul_members = nul_witness
        .as_object()
        .expect("the NUL fixture must be a JSON object")
        .len();
    assert_eq!(
        nul_members, 4,
        "the NUL fixture must carry exactly three declared members plus the injected one"
    );
    let Err(nul_error) = decode::<AdapterError>(&nul_text) else {
        panic!("a document with an unknown member whose name embeds a NUL must be refused")
    };
    let nul_message = nul_error.to_string();
    assert!(
        nul_message.contains("unknown field"),
        "the refusal must be the unknown-member arm, got: {nul_message}"
    );
    assert!(
        nul_message.contains(NUL_MEMBER),
        "the refusal must name the member carrying the embedded NUL, got: {nul_message}"
    );

    // The store is still usable after every malformed input: a panic inside a
    // decoder would have unwound past it, so this clean decode is the second half of
    // the panic-free claim.
    let after_text = raw("c2_AdapterError_canonical");
    let after: AdapterError = decode(&after_text).expect("a valid error must still decode");
    assert_eq!(
        after.code,
        member(&after_text, "code"),
        "a valid error must still decode after the malformed inputs"
    );

    // A missing required member is a refusal, not a panic, and an unknown member is
    // refused by name: `AdapterError`'s three members carry no serde attribute at
    // all (`crates/eliot-types/src/adapter.rs:173-176`), which is exactly why an absent
    // one is a missing-field failure rather than a default.
    //
    // The `absent_retryable` document OMITS `retryable` (`pub retryable: bool`,
    // `crates/eliot-types/src/adapter.rs:171-177`, no serde attribute), so its refusal
    // NAMES the member it never carried. `assert_omitted_member_refusal` proves both
    // halves - the quoted key is absent from the stored text, and the message names it -
    // which `assert_named_refusal` cannot do here, because it proves its token is
    // PRESENT. The row below it is the opposite shape, an UNKNOWN member that IS in the
    // document, and that is the one `assert_named_refusal` is for.
    assert_omitted_member_refusal::<AdapterError>(
        "c14_AdapterError_absent_retryable_refuse",
        "retryable",
    );
    assert_named_refusal::<AdapterError>(
        "c14_AdapterError_unknown_member_refuse",
        "c14_unknown_error_member",
        "unknown field",
    );
    // A repeated top-level member is refused while the raw map is read, which is
    // another bounded malformed shape and one only the raw route can present.
    assert_named_refusal::<AdapterError>(
        "c14_area_duplicate_top_level_member_text",
        "code",
        "duplicate field",
    );

    // `AdapterError.code` is a FREE REASON STRING
    // (`crates/eliot-types/src/adapter.rs:174`), NOT a closed enum - the card forbids
    // asserting it as one. So an arbitrary reason code decodes as data. That is
    // asserted as the behaviour the source declares, NOT as a clean closed
    // boundary: an unknown
    // reason is neither refused nor mapped onto Unknown(raw); it is simply carried.
    let arbitrary_text = raw("c2_AdapterError_canonical");
    let arbitrary: AdapterError = decode(&arbitrary_text)
        .expect("an arbitrary reason code is carried as a free string, not refused");
    assert_eq!(
        arbitrary.code,
        member(&arbitrary_text, "code"),
        "the free reason string must decode to the document's own text"
    );
    assert_eq!(
        arbitrary.retryable,
        member_bool(&arbitrary_text, "retryable"),
        "the retryable flag must decode to the document's own value"
    );
}

// WORK_UNIT_CASE: 933/c15_decoders_refuse_before_trusted_output_no_candidate_finish
#[test]
#[allow(clippy::too_many_lines)]
fn c15_evidence_and_candidate_documents_refuse_before_any_trusted_output_or_finish() {
    assert_case_binding(
        "933/c15_decoders_refuse_before_trusted_output_no_candidate_finish",
        &[
            "ProviderExecutionEvidence",
            "ExternalResultCompletenessReceipt",
            "ProviderResultCompleteness",
            "AgentCandidateSubmitInput",
            "AgentCandidateCurationInput",
        ],
    );
    assert_bytes_unchanged::<ProviderExecutionEvidence>("ProviderExecutionEvidence");
    assert_bytes_unchanged::<ExternalResultCompletenessReceipt>(
        "ExternalResultCompletenessReceipt",
    );
    assert_enum_spelling::<ProviderResultCompleteness>("ProviderResultCompleteness");
    assert_bytes_unchanged::<AgentCandidateSubmitInput>("AgentCandidateSubmitInput");
    assert_bytes_unchanged::<AgentCandidateCurationInput>("AgentCandidateCurationInput");

    // (a) ProviderExecutionEvidence keeps every ambiguous fact AS IT WAS WRITTEN, whatever
    // those facts happen to be. THE CANONICAL FIXTURE IS NOT AN AMBIGUOUS ONE: it
    // carries `exit_code: 0` and `unknown_outcome: false`
    // (measured from the stored text), so the row is not "an unknown outcome with a
    // null exit code stays unknown". What the row actually asserts is the general
    // property: each member decodes to the value the document wrote, so the decoder
    // neither promotes a stated outcome nor normalises the exit code, and the
    // comparisons below are made against the document's own text rather than against
    // any expected reading. The genuinely ambiguous case is (e), the provider's
    // self-reported completeness.
    let evidence_text = raw("c2_ProviderExecutionEvidence_canonical");
    let evidence: ProviderExecutionEvidence =
        decode(&evidence_text).expect("the canonical execution evidence must decode");
    assert_eq!(
        evidence.unknown_outcome,
        member_bool(&evidence_text, "unknown_outcome"),
        "the evidence's own unknown-outcome flag must decode unchanged"
    );
    assert_eq!(
        evidence.exit_code.map(i64::from),
        member_number_or_null(&evidence_text, "exit_code"),
        "the evidence's own exit code must decode unchanged, an explicit null included"
    );
    assert_eq!(
        evidence.terminal_status,
        member(&evidence_text, "terminal_status"),
        "the evidence's own terminal status text must survive decoding unchanged"
    );
    assert_eq!(
        evidence.runtime_contract_sha256,
        member(&evidence_text, "runtime_contract_sha256"),
        "the evidence's contract digest must survive decoding unchanged"
    );

    // (b) A candidate canary CANNOT assert Finish or any other trusted output, because
    // NONE OF THESE FIVE TYPES HAS A FINISH MEMBER: `ProviderExecutionEvidence`
    // (`crates/eliot-types/src/external_agent.rs:313-348`, closed by
    // `deny_unknown_fields` at `:311-312`), `ExternalResultCompletenessReceipt`
    // (`crates/eliot-types/src/provider_invocation.rs:582`),
    // `AgentCandidateSubmitInput` and `AgentCandidateCurationInput` (both in
    // `crates/eliot-types/src/mcp_contract.rs`, each closed by
    // `deny_unknown_fields`), and `ProviderResultCompleteness`
    // (`provider_invocation.rs:86`, a closed four-variant enum). So the only way a
    // finish member could appear on any of them is as an unknown member, and each type
    // refuses one by name.
    //
    // WHAT THE FIXTURES ACTUALLY CARRY, precisely, because no fixture in the container
    // injects a member literally named `finish` and this file does not pretend one
    // does: the four refusals below inject `c15_unknown_nested_member`,
    // `c15_unknown_completeness_member`, `c15_unknown_candidate_member` and
    // `c15_unknown_curation_member` respectively. Each is an unexpected member on a
    // document whose type has no finish member, which is the general shape a `finish`
    // member would have to take; the concrete claim proved is that an unexpected
    // TRUSTED-OUTPUT-shaped member on these four documents is refused by name. No
    // fixture named `..._finish_...` exists, and none is invented here.
    //
    // The rule this case rests on is I15.6, read on
    // `docs/architecture/I15-06-instructiondata-separation.md:6` - "model output
    // remains candidate;" and `:8` - "retrieved content cannot grant permission;"
    // (I15.6 is the section opened at
    // `docs/architecture/I15-06-instructiondata-separation.md:1`). Nothing in the
    // evidence, the receipt or the candidate input can read back as a grant.
    assert_named_refusal::<ProviderExecutionEvidence>(
        "c15_ProviderExecutionEvidence_unknown_nested_member_refuse",
        "c15_unknown_nested_member",
        "unknown field",
    );
    assert_named_refusal::<ExternalResultCompletenessReceipt>(
        "c15_ExternalResultCompletenessReceipt_unknown_member_refuse",
        "c15_unknown_completeness_member",
        "unknown field",
    );
    assert_named_refusal::<AgentCandidateSubmitInput>(
        "c15_AgentCandidateSubmitInput_unknown_member_refuse",
        "c15_unknown_candidate_member",
        "unknown field",
    );
    assert_named_refusal::<AgentCandidateCurationInput>(
        "c15_AgentCandidateCurationInput_unknown_member_refuse",
        "c15_unknown_curation_member",
        "unknown field",
    );

    // (c) Completeness is DATA and cannot be upgraded by the decoder: an incomplete
    // receipt keeps every one of its own booleans, and `normalization_allowed` is
    // not turned on by an incomplete answer.
    let completeness_text = raw("c2_ExternalResultCompletenessReceipt_canonical");
    let completeness: ExternalResultCompletenessReceipt =
        decode(&completeness_text).expect("the canonical completeness receipt must decode");
    assert_eq!(
        completeness.required_fields_present,
        member_bool(&completeness_text, "required_fields_present"),
        "`required_fields_present` must decode to the document's own value"
    );
    assert_eq!(
        completeness.truncation_detected,
        member_bool(&completeness_text, "truncation_detected"),
        "`truncation_detected` must decode to the document's own value"
    );
    assert_eq!(
        completeness.stream_closed_cleanly,
        member_bool(&completeness_text, "stream_closed_cleanly"),
        "`stream_closed_cleanly` must decode to the document's own value"
    );
    assert_eq!(
        completeness.result_complete,
        member_bool(&completeness_text, "result_complete"),
        "`result_complete` must decode to the document's own value and never be upgraded"
    );
    assert_eq!(
        completeness.normalization_allowed,
        member_bool(&completeness_text, "normalization_allowed"),
        "`normalization_allowed` must decode to the document's own value"
    );
    assert_eq!(
        completeness.parser_version,
        member(&completeness_text, "parser_version"),
        "the receipt's own parser version must survive decoding unchanged"
    );

    // (d) ProviderResultCompleteness is a closed four-variant enum whose wire
    // spelling is pinned in both directions by `assert_enum_spelling`, and reading
    // it is a fixed point: no decoder here maps one completeness variant onto
    // another, so the receipt's own boolean and this enum stay independent facts.
    assert_named_refusal::<ProviderResultCompleteness>(
        "c15_ProviderResultCompleteness_unknown_tag_refuse",
        "c15_unknown_completeness_tag",
        "unknown variant",
    );
    let completeness_text_variant = raw("c2_ProviderResultCompleteness_canonical");
    let variant: ProviderResultCompleteness =
        decode(&completeness_text_variant).expect("the canonical completeness variant must decode");
    let variant_again: ProviderResultCompleteness =
        decode(&serde_json::to_string(&variant).expect("the decoded variant must re-encode"))
            .expect("the re-encoded completeness variant must decode again");
    assert_eq!(
        variant_again, variant,
        "reading a completeness variant twice must produce the same variant"
    );
    assert_eq!(
        completeness_text_variant,
        serde_json::to_string(&variant).expect("the decoded variant must re-encode"),
        "the completeness variant must re-encode to its own stored wire spelling"
    );

    // (e) A provider's SELF-REPORTED completeness is data and cannot upgrade itself:
    // the evidence keeps its own terminal status and structured output verbatim,
    // and the receipt that says "complete" is a separate document the provider
    // wrote, not a decision this decoder makes.
    let self_reported_text = raw("c15_area_provider_self_reported_completeness");
    let self_reported: ProviderExecutionEvidence = decode(&self_reported_text)
        .expect("a self-reported complete provider result still decodes as evidence");
    assert_eq!(
        self_reported.terminal_status,
        member(&self_reported_text, "terminal_status"),
        "the provider's own terminal status must survive decoding unchanged"
    );
    assert_eq!(
        self_reported.structured_output,
        Some(member_value(&self_reported_text, "structured_output")),
        "the provider's own structured output must survive decoding unchanged"
    );
    assert!(
        !self_reported.unknown_outcome,
        "a self-reported complete result decodes to exactly what the provider wrote, \
         never to a promoted outcome"
    );
    let self_reported_receipt_text = raw("c15_area_provider_self_reported_completeness_receipt");
    let self_reported_receipt: ExternalResultCompletenessReceipt =
        decode(&self_reported_receipt_text)
            .expect("the provider's own completeness receipt decodes as data");
    assert_eq!(
        self_reported_receipt.result_complete,
        member_bool(&self_reported_receipt_text, "result_complete"),
        "`result_complete` is the receipt's own claim, decoded unchanged"
    );
    assert_eq!(
        self_reported_receipt.normalization_allowed,
        member_bool(&self_reported_receipt_text, "normalization_allowed"),
        "`normalization_allowed` is the receipt's own claim, decoded unchanged"
    );

    // (f) A candidate submission cannot promote itself: an unexpected promotion
    // member is refused, so the curated-candidate wire has no promotion switch.
    let submit_text = raw("c2_AgentCandidateSubmitInput_canonical");
    let submit: AgentCandidateSubmitInput =
        decode(&submit_text).expect("the canonical candidate submission must decode");
    assert_eq!(
        submit.provenance_refs,
        member_texts(&submit_text, "provenance_refs"),
        "the submission's own provenance refs must survive decoding unchanged"
    );
    assert_eq!(
        submit.freshness_rule,
        member(&submit_text, "freshness_rule"),
        "the submission's own freshness rule must survive decoding unchanged"
    );

    // (g) The curation defaults this lane relies on are FAIL-CLOSED, recorded as the
    // behaviour the source declares and the assertions below are written to check:
    // an omitted `protected` is asserted NOT to be protected and an omitted
    // `unsafe_instruction` is NOT flagged, so no omission can grant protection or
    // suppress a safety flag. The inverse defect - defaulting either flag to `true`
    // - would be an escalation and is NOT what the delivered decoder does.
    let curation_text = raw("c15_AgentCandidateCurationInput_absent_protected_default");
    assert!(
        !curation_text.contains(PROTECTED_MEMBER)
            && !curation_text.contains(UNSAFE_INSTRUCTION_MEMBER),
        "the fixture must actually OMIT both curation flags"
    );
    let curation: AgentCandidateCurationInput =
        decode(&curation_text).expect("a curation payload without the two flags must decode");
    assert!(
        !curation.protected,
        "an omitted `protected` must decode to `false`, never to protection"
    );
    assert!(
        !curation.unsafe_instruction,
        "an omitted `unsafe_instruction` must decode to `false`, never suppressing the flag"
    );
    assert_eq!(
        curation.handle,
        member(&curation_text, "handle"),
        "every other curation member must survive the two defaults unchanged"
    );
}

// WORK_UNIT_CASE: 933/c16_scope_schema_routing_dependencies_visibility_unchanged
#[test]
#[allow(clippy::too_many_lines)]
fn c16_routing_schema_and_visibility_are_unchanged_by_this_lane() {
    assert_case_binding(
        "933/c16_scope_schema_routing_dependencies_visibility_unchanged",
        &["ProviderRoutePolicy", "ProviderRoutePolicyBinding"],
    );
    assert_bytes_unchanged::<ProviderRoutePolicy>("ProviderRoutePolicy");
    assert_bytes_unchanged::<ProviderRoutePolicyBinding>("ProviderRoutePolicyBinding");

    // (a) The route policy is routing data, unchanged: every accessor agrees with
    // the canonical document's own members, and the digest binds the policy to the
    // route it was declared for.
    let policy_text = raw("c2_ProviderRoutePolicy_canonical");
    let policy: ProviderRoutePolicy =
        decode(&policy_text).expect("the canonical route policy must decode");
    assert_eq!(
        policy.policy_id(),
        member(&policy_text, "policy_id"),
        "the policy's own id must survive decoding unchanged"
    );
    assert_eq!(
        policy.policy_hash_blake3(),
        member(&policy_text, "policy_hash_blake3"),
        "the policy's own blake3 digest must survive decoding unchanged"
    );
    assert_eq!(
        policy.host().as_str(),
        member(&policy_text, "host"),
        "the policy's own host must survive decoding unchanged"
    );
    assert_eq!(
        policy.operation_class(),
        member(&policy_text, "operation_class"),
        "the policy's own operation class must survive decoding unchanged"
    );
    assert_eq!(
        policy.output_limit_bytes(),
        member_number(&policy_text, "output_limit_bytes"),
        "the policy's own output limit must survive decoding unchanged"
    );
    assert_eq!(
        policy.incremental_output_supported(),
        member_bool(&policy_text, "incremental_output_supported"),
        "the policy's own incremental-output flag must decode unchanged"
    );
    assert_eq!(
        policy.status_lookup_supported(),
        member_bool(&policy_text, "status_lookup_supported"),
        "the policy's own status-lookup flag must decode unchanged"
    );
    let profile = policy.timeout_profile();
    let profile_witness = witness(&policy_text)
        .get("timeout_profile")
        .cloned()
        .expect("the canonical policy must carry a nested timeout_profile object");
    let profile_id = profile_witness
        .get("profile_id")
        .cloned()
        .expect("the nested profile must carry a `profile_id`");
    assert_eq!(
        profile.profile_id().to_owned(),
        profile_id.as_str().expect("`profile_id` must be a string"),
        "the nested timeout profile's own id must survive decoding unchanged"
    );
    let absolute = profile_witness
        .get("absolute_runtime_deadline_ms")
        .and_then(serde_json::Value::as_u64)
        .expect("the nested profile must carry a numeric absolute deadline");
    assert_eq!(
        profile.absolute_runtime_deadline_ms(),
        absolute,
        "the nested timeout profile's own absolute deadline must survive decoding unchanged"
    );
    let spawn = profile_witness
        .get("spawn_deadline_ms")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    assert_eq!(
        profile.spawn_deadline_ms(),
        spawn.as_u64(),
        "the nested timeout profile's own spawn deadline must survive decoding unchanged"
    );

    // (b) The binding is the policy's own two identity members, and it is the SAME
    // binding the attempt and evidence records carry: the attempt at
    // `crates/eliot-types/src/provider_invocation.rs:171-172` and the evidence at
    // `crates/eliot-types/src/external_agent.rs:315`, each read as
    // `provider_route_policy: Option<ProviderRoutePolicyBinding>` /
    // `provider_route_policy: ProviderRoutePolicyBinding`.
    let binding_text = raw("c2_ProviderRoutePolicyBinding_canonical");
    let binding: ProviderRoutePolicyBinding =
        decode(&binding_text).expect("the canonical route policy binding must decode");
    assert_eq!(
        binding.policy_id,
        policy.policy_id(),
        "the binding must be the canonical policy's own id"
    );
    assert_eq!(
        binding.policy_hash_blake3,
        policy.policy_hash_blake3(),
        "the binding must be the canonical policy's own digest"
    );
    assert_eq!(
        binding.policy_id,
        member(&binding_text, "policy_id"),
        "the binding document must carry its own policy id"
    );

    // (c) The digest is verifiable only AT the declaration site. The decoder
    // performs no verification, so a binding whose digest matches nothing is still
    // accepted as data; the verification site is
    // `ProviderRoutePolicy::for_route`/`route_policy_hash`
    // (`provider_invocation.rs:301-440`), which this lane does not touch. Asserting a
    // refusal here would assert something the decoder does not do.
    let unverifiable_text = raw("c16_ProviderRoutePolicyBinding_unverifiable_digest_accepted");
    let unverifiable: ProviderRoutePolicyBinding = decode(&unverifiable_text)
        .expect("an unverifiable digest is still accepted: the decoder verifies nothing");
    assert_eq!(
        unverifiable.policy_hash_blake3,
        member(&unverifiable_text, "policy_hash_blake3"),
        "the unverifiable digest must decode to the document's own text, unverified"
    );
    // Both documents are closed, so an unverifiable digest is not a licence to add
    // members either: an unknown member on either shape is refused by name.
    assert_named_refusal::<ProviderRoutePolicyBinding>(
        "c16_ProviderRoutePolicyBinding_unknown_member_refuse",
        "c16_unknown_binding_member",
        "unknown field",
    );
    assert_named_refusal::<ProviderRoutePolicy>(
        "c16_ProviderRoutePolicy_unknown_nested_member_refuse",
        "c16_unknown_nested_member",
        "unknown field",
    );

    // (d) SCHEMA UNCHANGED: the published compile-packet schema's property set is
    // exactly the visitor's permitted key list asserted in case 13, and it has no
    // nested `request` property. If either side moved, this assertion moves. The
    // rule this rests on is handle I7.6, read on
    // `docs/architecture/I07-06-mcp-surface.md:50` - "Tool input/output schemas are
    // generated from the same `serde`/`schemars` contract types used by EBP clients.
    // Hand-written MCP schemas, separate field names or host-specific semantic forks
    // are forbidden." (I7.6 is the section opened at
    // `docs/architecture/I07-06-mcp-surface.md:1`.) That is why the schema's property
    // set is compared against the decoder's OWN permitted list here instead of
    // against a literal written into this test.
    let schema = compile_packet_input_schema();
    let properties = schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .expect("the published compile-packet schema must carry a `properties` object");
    let mut property_names: Vec<String> = properties.keys().cloned().collect();
    property_names.sort();
    let mut permitted: Vec<String> = PERMITTED_PACKET_KEYS
        .iter()
        .map(|key| (*key).to_owned())
        .collect();
    permitted.sort();
    assert_eq!(
        property_names, permitted,
        "the published schema's property set must equal the decoder's permitted key list"
    );
    assert!(
        !properties.contains_key(NESTED_REQUEST_MEMBER),
        "the published schema must describe the flat layout, with no nested `{NESTED_REQUEST_MEMBER}` property"
    );
    assert!(
        observe_input_schema()
            .as_object()
            .is_some_and(|schema| schema.contains_key("properties")),
        "the published `eliot.observe` schema must still be a generated schema object"
    );
    assert!(
        agent_candidate_input_schema()
            .as_object()
            .is_some_and(|schema| schema.contains_key("properties")),
        "the published candidate-submit schema must still be a generated schema object"
    );
    assert!(
        compile_packet_minimal_example().is_object(),
        "the published minimal example must still be a flat object"
    );

    // (e) SCOPE UNCHANGED, MADE OBSERVABLE. The frozen allocation is a real, readable
    // FILE, so "this lane did not move the T04 type set" is not prose: the T04
    // allocation block's own `types = [...]` array is read out of it and compared as a
    // SET against the container's `meta.types`. If the two ever drift, one of them
    // moved and this assertion moves with it.
    //
    // The file is read relative to `CARGO_MANIFEST_DIR` (this test target's manifest is
    // `crates/eliot-types/Cargo.toml`), so the path is
    // `crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml`
    // reached as `../foundation/eliot-contracts/...`.
    //
    // IT FAILS LOUDLY IF IT CANNOT BE READ. There is no `if let Ok(..)`, no skip and
    // no early return: a silently unreadable inventory would turn this row into a
    // green assertion that proved nothing, which is the failure mode this whole case
    // exists to rule out.
    let inventory_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("foundation")
        .join("eliot-contracts")
        .join("tests")
        .join("data")
        .join("shipped_serde_boundaries.toml");
    let inventory_text = std::fs::read_to_string(&inventory_path).unwrap_or_else(|error| {
        panic!(
            "the frozen allocation {} must be readable for case 16's scope check: {error}",
            inventory_path.display()
        )
    });
    // The T04 block is the one allocation whose header names both `child = \"#933\"`
    // and `family = \"T04\"`. Both are required, so a future sibling block cannot be
    // picked up by accident, and the search stops at the NEXT `[[allocations]]` header
    // so the `types` array cannot be read out of a different block.
    let block_start = inventory_text
        .find("[[allocations]]")
        .expect("the frozen allocation file must carry at least one `[[allocations]]` block");
    let mut t04_block: Option<(usize, &str)> = None;
    let mut cursor = block_start;
    while let Some(next) = inventory_text[cursor..].find("[[allocations]]") {
        let header_at = cursor + next;
        let body_end = header_at + "[[allocations]]".len();
        let block_end = inventory_text[body_end..]
            .find("[[allocations]]")
            .map_or(inventory_text.len(), |offset| body_end + offset);
        let header = &inventory_text[header_at..block_end];
        if header.contains("child = \"#933\"") && header.contains("family = \"T04\"") {
            t04_block = Some((body_end, header));
            break;
        }
        cursor = body_end;
    }
    let (_, t04_header) = t04_block.unwrap_or_else(|| {
        panic!(
            "the frozen allocation file must carry a T04 block with `child = \"#933\"`; \
             {} has none",
            inventory_path.display()
        )
    });
    let types_line = t04_header
        .lines()
        .find(|line| line.trim_start().starts_with("types = ["))
        .unwrap_or_else(|| panic!("the T04 allocation block must carry a `types = [...]` array"));
    let inventory_types: Vec<String> = types_line
        .trim()
        .trim_start_matches("types = ")
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|name| name.trim().trim_matches('"').to_owned())
        .filter(|name| !name.is_empty())
        .collect();
    assert_eq!(
        inventory_types.len(),
        54,
        "the frozen T04 allocation must name 54 types, read from the file itself"
    );
    let mut inventory_sorted = inventory_types.clone();
    inventory_sorted.sort();
    inventory_sorted.dedup();
    assert_eq!(
        inventory_sorted.len(),
        inventory_types.len(),
        "the frozen T04 allocation must not repeat a type name"
    );
    let mut container_sorted = meta_types();
    container_sorted.sort();
    assert_eq!(
        inventory_sorted, container_sorted,
        "the frozen allocation's T04 type set and the container's `meta.types` must be the \
         same 54 names: that is what makes this lane's SCOPE UNCHANGED observable rather \
         than asserted in words"
    );

    // (f) DEPENDENCIES AND VISIBILITY UNCHANGED, in words because they are
    // NOT RUNTIME-OBSERVABLE from inside an integration test target, and this file
    // does not pretend otherwise. (e) above is the part of this case that IS
    // observable, and it is observable precisely because the frozen allocation is a
    // file on disk. A dependency edge is a `Cargo.toml` relationship and a visibility
    // is a `pub` keyword: neither has any runtime surface a test could read, so both
    // stay prose with `file:line` citations.
    //
    // DEPENDENCIES: this lane adds no dependency at all. `crates/eliot-types/Cargo.toml`
    // and `crates/eliot-types/Cargo.lock`'s entry for this package are unchanged, and
    // this file adds no `use` beyond what its siblings already needed - the one new
    // reach is `std::fs` and `std::path`, both already used by `corpus_text` above, so
    // no second parser framework and no `Value` pre-processing stage enters the
    // package.
    //
    // VISIBILITY: `CompilePacketToolInputVisitor` is `struct
    // CompilePacketToolInputVisitor;` with NO `pub`
    // (`crates/eliot-types/src/mcp_contract.rs:50`), so it is NOT reachable from this
    // file and is not widened to make it so - `crates/eliot-types/src/lib.rs` is
    // read-only here. Case 13 discharges its behaviour through the only surface it has,
    // the `CompilePacketToolInput` decoder that constructs it
    // (`mcp_contract.rs:41-48`). `CognitiveProviderRuntimeContract` is reachable only
    // through `eliot_types::external_agent::legacy`, which `lib.rs:15` and
    // `external_agent.rs:247` publish; no re-export block is added or widened.
    //
    // This lane adds exactly
    // two files: one integration test target and its raw-byte fixture container. It
    // edits no production declaration, no `Cargo.toml`, no `Cargo.lock`, no `lib.rs`
    // re-export block, no `crates/surfaces/eliot-mcp/**` file, no tool catalogue
    // entry, no routing/permission/Finish policy, and no provider execution or
    // visibility code. It adds no second parser framework and no `Value`
    // pre-processing stage: the only decode entry point this file uses is
    // `serde_json::from_str` over the stored raw text, and every `Value` in this
    // file is a post-decode witness. Every name it imports was already reachable
    // through the `eliot_types` boundary, except the two the header declares: the
    // legacy module path for `CognitiveProviderRuntimeContract`, and
    // `CompilePacketToolInputVisitor`, which stays private and is asserted only
    // through the decoder that constructs it. The card's own non-goals - repairing
    // `ObserveInput.hint`'s `alias = "kind"`, repairing `schema_version`'s helper
    // default, and treating `AdapterError.code` as a closed enum - are untouched and
    // are recorded in cases 12 and 14 instead.
}
