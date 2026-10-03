//! Issue #932 (`F-DENY-T03`): the allocated 16-case decoder proof for the T03
//! slice - `eliot-types/src/{host.rs,config.rs,secret_boundary.rs}`.
//!
//! The production half of #932 is already on `main`: closed derived decoders,
//! wire-required protected state/generation/epoch fields, approved config
//! defaults retained with owner evidence, and `secret_boundary.rs` a correct
//! no-op. These cases are the executed proof that those decoders refuse what
//! they must and preserve what they must.
//!
//! Fixtures are stored as RAW JSON TEXT and handed to the deserializer
//! unparsed. A `serde_json::Value` intermediate collapses a repeated object
//! member before the decoder ever sees it, so it could not prove case 5; every
//! refusal case therefore feeds raw bytes.
//!
//! No synthetic canary value is stored in this file or in the fixture corpus.
//! The canary of case 15 is assembled at runtime, so no canary material ever
//! becomes persisted evidence.

#![allow(clippy::expect_used)]

use eliot_types::{
    AgentHostId, AgentResultDisposition, AgentResultEnvelope, AgentResultStatus, AgentRole,
    AgentSessionHostBinding, AgentSessionState, AuthorityLeaseLifetime, AuthorityLeaseState,
    ConfigError, CredentialProviderKind, DelegationCalibrationConfig, GovernorConfig,
    HostEventEnvelope, HostLaunchContract, MAX_SECRET_BOUNDARY_BYTES, OperationJob,
    OperationJobState, RuntimeSupervisionConfig, SCHEMA_VERSION, SecretBoundaryRule,
    SecretBoundaryViolation, SurrealServerConfig, TaskRoleLease, UlConfig, inspect_secret_bytes,
};

/// The raw fixture corpus. Every fixture is stored as a STRING value holding its
/// wire text, because a fixture that repeats an object member - a valid JSON
/// document, but one no decoder may accept - would be rewritten by a bare
/// `{"key": {…}}` corpus: storing the text keeps both occurrences intact all the
/// way to the decoder. The malformed bytes of case 14 are inline literals, not
/// stored entries.
fn corpus() -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("serde_t03_host_config.json");
    let text = std::fs::read_to_string(&path).expect("serde_t03_host_config.json must exist");
    serde_json::from_str(&text).expect("serde_t03_host_config.json must be valid JSON")
}

/// A fixture's own text, byte for byte, with no re-serialization: a repeated
/// member and the derived member order both survive, which a `Value` round trip
/// would destroy.
fn raw(name: &str) -> String {
    corpus()
        .get(name)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("the corpus must contain fixture {name}"))
        .to_owned()
}

/// HOST fixtures.
fn host_raw(name: &str) -> String {
    raw(name)
}

/// CONFIG fixtures.
fn config_raw(name: &str) -> String {
    raw(name)
}

fn decode_host<T: serde::de::DeserializeOwned>(document: &str) -> Result<T, serde_json::Error> {
    serde_json::from_str(document)
}

fn decode_config<T: serde::de::DeserializeOwned>(document: &str) -> Result<T, serde_json::Error> {
    serde_json::from_str(document)
}

// ---------------------------------------------------------------------------
// Cases for writer w1 (issue #932, card cards/932.md).
// ---------------------------------------------------------------------------

const W1_UNKNOWN_BINDING_MEMBER: &str = "w1_unknown_binding_member";
const W1_UNKNOWN_LEASE_MEMBER: &str = "w1_unknown_lease_member";
const W1_UNKNOWN_LAUNCH_MEMBER: &str = "w1_unknown_launch_member";
const W1_UNKNOWN_CONFIG_MEMBER: &str = "w1_unknown_config_member";
const W1_UNKNOWN_HOST_IDENTITY_MEMBER: &str = "w1_unknown_host_identity_member";
const W1_UNKNOWN_DB_SURREAL_MEMBER: &str = "w1_unknown_db_surreal_member";
const W1_UNKNOWN_CAPABILITIES_MEMBER: &str = "w1_unknown_capabilities_member";
const W1_UNKNOWN_SECRET_RULE_VARIANT: &str = "w1_unknown_secret_rule_variant";

/// The canonical derived serialization of the known-good
/// `AgentSessionHostBinding` fixture: compact, with member keys in exactly the
/// order the derived serializer emits them (declaration order). Case 2 compares
/// `serde_json::to_string` against this independently written literal and
/// against the corpus copy, so the comparison is never value-against-itself.
const W1_CANONICAL_BINDING_JSON: &str = "{\"agent_session_id\":\"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d\",\"host_identity\":{\"host_id\":\"opencode\",\"implementation_name\":\"opencode 0.9.4\",\"client_instance_id\":\"client-instance-7f3a\"},\"capability_envelope\":{\"capabilities\":[\"plan.execute\",\"fs.write\",\"test.run\"],\"structured_output\":true,\"resumable\":true,\"interactive\":false,\"supervised\":true},\"bound_project_id\":\"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c60\",\"bound_task_id\":\"0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c61\",\"task_role_lease_refs\":[\"lease-role-1\",\"lease-role-2\"],\"state\":\"active\",\"generation\":7,\"owner_operation_id\":\"op-0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c62\",\"disconnected_at\":null,\"disconnect_reason\":null}";

/// Case 1: the allocated slice of T03 decoder declarations resolves across
/// exactly the three in-scope production files, and nothing else. The
/// allocation is a property of the INVENTORY, not of a list this test writes,
/// so it is stated here and carried by the three per-file REFUSAL proofs below:
/// the `family = "T03"` / `source_files` row for child `#932` in
/// `crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml`
/// names exactly
/// `crates/eliot-types/src/host.rs`, `crates/eliot-types/src/config.rs` and
/// `crates/eliot-types/src/secret_boundary.rs` — no fourth file. Existence of
/// those files alone proves nothing, so each one is proved by the REFUSAL its
/// representative decoder makes: `host.rs::AgentSessionHostBinding` and
/// `config.rs::GovernorConfig` refuse an unknown member key, and the third
/// file's representative decoder `secret_boundary.rs::SecretBoundaryRule` is a
/// closed enum that refuses an unknown variant.
// WORK_UNIT_CASE: 932/c1_allocation_complete
#[test]
fn c1_allocation_complete_across_the_three_in_scope_files() {
    // crates/eliot-types/src/host.rs
    let binding: AgentSessionHostBinding =
        decode_host(&host_raw("w1_c1_agent_session_host_binding_positive"))
            .expect("the positive AgentSessionHostBinding fixture must decode against src/host.rs");
    assert_eq!(
        binding.generation, 7,
        "the decoded host.rs binding must carry its own wire generation, not a fabricated one"
    );
    assert!(
        decode_host::<AgentSessionHostBinding>(&host_raw(
            "w1_c1_agent_session_host_binding_unknown_top_level_refuse"
        ))
        .is_err(),
        "src/host.rs: AgentSessionHostBinding must refuse the unknown top-level member key `{W1_UNKNOWN_BINDING_MEMBER}`"
    );

    // crates/eliot-types/src/config.rs
    let config: GovernorConfig = decode_config(&config_raw("w1_c1_governor_config_positive"))
        .expect("the positive GovernorConfig fixture must decode against src/config.rs");
    assert_eq!(
        config.schema_version, "1",
        "the decoded config.rs document must carry its own schema_version"
    );
    assert!(
        decode_config::<GovernorConfig>(&config_raw(
            "w1_c1_governor_config_unknown_top_level_refuse"
        ))
        .is_err(),
        "src/config.rs: GovernorConfig must refuse the unknown top-level member key `{W1_UNKNOWN_CONFIG_MEMBER}`"
    );

    // crates/eliot-types/src/secret_boundary.rs
    let rule: SecretBoundaryRule = decode_host(&raw("w1_c1_secret_boundary_rule_accept")).expect(
        "the accepted SecretBoundaryRule variant must decode against src/secret_boundary.rs",
    );
    assert_eq!(
        rule,
        SecretBoundaryRule::StructuredToken,
        "src/secret_boundary.rs: `structured_token` must still decode to its own variant"
    );
    assert!(
        decode_host::<SecretBoundaryRule>(&raw(
            "w1_c1_secret_boundary_rule_unknown_variant_refuse"
        ))
        .is_err(),
        "src/secret_boundary.rs: SecretBoundaryRule is a closed enum and must refuse the unknown variant `{W1_UNKNOWN_SECRET_RULE_VARIANT}`"
    );
}

/// Case 2: valid bytes are accepted and unchanged. The known-good
/// `AgentSessionHostBinding` fixture is decoded, its field values are checked
/// against the fixture's own numbers/enums (not against defaults), and the
/// derived serializer's output is byte-compared against the canonical expected
/// string held in the corpus (`w1_c2_binding_canonical`) and against the
/// independently written literal `W1_CANONICAL_BINDING_JSON`.
// WORK_UNIT_CASE: 932/c2_unchanged_valid_bytes
#[test]
fn c2_unchanged_valid_bytes_round_trip_byte_stably() {
    let stored_bytes = host_raw("w1_c2_binding_canonical");
    assert_eq!(
        stored_bytes, W1_CANONICAL_BINDING_JSON,
        "the corpus bytes of `w1_c2_binding_canonical` must be the canonical derived serialization (compact, derived member order), not a re-serialized Value"
    );

    let decoded: AgentSessionHostBinding = decode_host(&stored_bytes)
        .expect("the canonical AgentSessionHostBinding fixture must decode");
    assert_eq!(
        decoded.generation, 7,
        "`generation` must decode to the fixture's own number 7, not a fabricated value"
    );
    assert_eq!(
        decoded.state,
        AgentSessionState::Active,
        "`state` must decode to the fixture's own `active` variant, not a locally manufactured one"
    );
    // `AgentSessionState::Active` IS this type's derive default, so the equality
    // above cannot by itself distinguish a decoded value from a fabricated one.
    // Case 7 proves a MISSING `state` is refused outright, which is what closes
    // that gap; this assertion only pins that the honest value survives.
    assert_eq!(
        AgentSessionState::default(),
        AgentSessionState::Active,
        "the derive default of this state enum is Active, which is why the refusal proof in case 7 \
         carries the weight here"
    );
    assert_eq!(
        decoded.agent_session_id.to_string(),
        "0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c5d",
        "`agent_session_id` must decode to the fixture's own identifier"
    );
    assert_eq!(
        decoded.host_identity.host_id,
        AgentHostId::OpenCode,
        "nested `host_identity.host_id` must decode to the fixture's own `opencode` variant"
    );
    assert_eq!(
        decoded.capability_envelope.capabilities.len(),
        3,
        "nested `capability_envelope.capabilities` must carry all three fixture entries"
    );
    assert_eq!(
        decoded.capability_envelope.capabilities[0], "plan.execute",
        "nested `capability_envelope.capabilities[0]` must be the fixture's own `plan.execute`"
    );
    assert_eq!(
        decoded.task_role_lease_refs.len(),
        2,
        "`task_role_lease_refs` must keep both fixture references"
    );
    assert_eq!(
        decoded.owner_operation_id.as_deref(),
        Some("op-0192f1c2-3d4e-7a5b-8c9d-0e1f2a3b4c62"),
        "`owner_operation_id` must decode to the fixture's own operation id"
    );
    assert!(
        decoded.disconnected_at.is_none() && decoded.disconnect_reason.is_none(),
        "an `active` binding must keep its explicit `null` disconnect members as `None`"
    );

    let reserialized = serde_json::to_string(&decoded)
        .expect("AgentSessionHostBinding must serialize back to JSON text");
    assert_eq!(
        reserialized, W1_CANONICAL_BINDING_JSON,
        "the derived serializer's bytes must equal the canonical expected string exactly"
    );
    assert_eq!(
        reserialized, stored_bytes,
        "decode/re-encode must leave the valid bytes unchanged"
    );

    let redigested: AgentSessionHostBinding =
        decode_host(&reserialized).expect("the re-serialized binding must decode again");
    assert_eq!(
        serde_json::to_string(&redigested).expect("the redigested binding must serialize again"),
        reserialized,
        "a second decode/re-encode cycle must not move a single byte: the digest is stable"
    );

    let lease: TaskRoleLease = decode_host(&host_raw("w1_c2_task_role_lease_positive"))
        .expect("the known-good TaskRoleLease fixture must decode as valid bytes");
    assert_eq!(
        lease.state,
        AuthorityLeaseState::Active,
        "TaskRoleLease `state` must decode to the fixture's own `active` variant"
    );
    assert_eq!(
        lease.lifetime,
        AuthorityLeaseLifetime::OperationBound,
        "TaskRoleLease `lifetime` must decode to the fixture's own explicit `operation_bound`, not the `Legacy` default"
    );
    assert_eq!(
        lease.epoch, 3,
        "TaskRoleLease `epoch` must decode to the fixture's own number 3"
    );
    assert_eq!(
        lease.generation, 7,
        "TaskRoleLease `generation` must decode to the fixture's own number 7"
    );
    assert_eq!(
        lease.role,
        AgentRole::Implementer,
        "TaskRoleLease `role` must decode to the fixture's own `implementer` variant"
    );
}

/// Case 3: an unknown TOP-LEVEL member key is refused by each of the three
/// host decoders, and the very same fixture without that key decodes, so the
/// refusal is caused by the unknown key and not by an otherwise-broken
/// fixture.
// WORK_UNIT_CASE: 932/c3_unknown_top_level_field_refused
#[test]
fn c3_unknown_top_level_field_refused_by_each_host_decoder() {
    // AgentSessionHostBinding
    let binding: AgentSessionHostBinding =
        decode_host(&host_raw("w1_c1_agent_session_host_binding_positive"))
            .expect("the same AgentSessionHostBinding fixture without the unknown key must decode");
    assert_eq!(
        binding.generation, 7,
        "the accepted counterpart must keep the fixture's own generation 7"
    );
    assert!(
        decode_host::<AgentSessionHostBinding>(&host_raw(
            "w1_c1_agent_session_host_binding_unknown_top_level_refuse"
        ))
        .is_err(),
        "AgentSessionHostBinding must refuse the unknown top-level member key `{W1_UNKNOWN_BINDING_MEMBER}`"
    );

    // TaskRoleLease
    let lease: TaskRoleLease = decode_host(&host_raw("w1_c2_task_role_lease_positive"))
        .expect("the same TaskRoleLease fixture without the unknown key must decode");
    assert_eq!(
        lease.epoch, 3,
        "the accepted TaskRoleLease counterpart must keep the fixture's own epoch 3"
    );
    assert!(
        decode_host::<TaskRoleLease>(&host_raw("w1_c3_task_role_lease_unknown_top_level_refuse"))
            .is_err(),
        "TaskRoleLease must refuse the unknown top-level member key `{W1_UNKNOWN_LEASE_MEMBER}`"
    );

    // HostLaunchContract
    let launch: HostLaunchContract = decode_host(&host_raw("w1_c3_launch_contract_positive"))
        .expect("the same HostLaunchContract fixture without the unknown key must decode");
    assert_eq!(
        launch.role_lease_epoch, 3,
        "the accepted HostLaunchContract counterpart must keep the fixture's own role_lease_epoch 3"
    );
    assert_eq!(
        launch.operation_generation, 7,
        "the accepted HostLaunchContract counterpart must keep the fixture's own operation_generation 7"
    );
    assert!(
        decode_host::<HostLaunchContract>(&host_raw(
            "w1_c3_launch_contract_unknown_top_level_refuse"
        ))
        .is_err(),
        "HostLaunchContract must refuse the unknown top-level member key `{W1_UNKNOWN_LAUNCH_MEMBER}`"
    );
}

/// Case 4: an unknown member key INSIDE a nested struct/object is refused.
///
/// `AgentSessionHostBinding` and `GovernorConfig` own nested closed structs, so
/// the unknown key goes inside `host_identity`, inside `db.surreal`, and
/// inside `db.surreal.capabilities`. `TaskRoleLease` and `HostLaunchContract`
/// own NO nested struct (every member is a string, a number, an `Option`, an
/// id newtype or a closed enum), so they have no nested position into which an
/// unknown key could be injected. For those two the card's coverage is instead
/// the protected member itself: a JSON OBJECT is supplied at a protected SCALAR
/// member (`generation`, `role_lease_epoch`) and must be REFUSED rather than
/// coerced into a map/`Value`. The inner names of those two fixtures
/// (`w1_object_at_lease_generation` and `w1_object_at_launch_role_lease_epoch`)
/// mark the position only: they are NOT unknown-key fixtures and their inner
/// names are never read by serde. Each negative is paired with its positive
/// counterpart.
// WORK_UNIT_CASE: 932/c4_unknown_nested_field_refused
#[test]
fn c4_unknown_nested_field_refused_by_each_allocated_decoder() {
    // AgentSessionHostBinding: unknown key inside nested `host_identity`.
    let binding: AgentSessionHostBinding = decode_host(&host_raw("w1_c2_binding_canonical"))
        .expect(
            "the same AgentSessionHostBinding fixture without the nested unknown key must decode",
        );
    assert_eq!(
        binding.host_identity.client_instance_id, "client-instance-7f3a",
        "the accepted counterpart must keep the fixture's own host_identity.client_instance_id"
    );
    assert!(
        decode_host::<AgentSessionHostBinding>(&host_raw("w1_c4_host_identity_nested_refuse"))
            .is_err(),
        "nested `host_identity` must refuse the unknown member key `{W1_UNKNOWN_HOST_IDENTITY_MEMBER}`"
    );

    // TaskRoleLease: an object supplied at the protected scalar `generation`.
    let lease: TaskRoleLease = decode_host(&host_raw("w1_c2_task_role_lease_positive"))
        .expect("the same TaskRoleLease fixture with the scalar `generation` must decode");
    assert_eq!(
        lease.generation, 7,
        "the accepted TaskRoleLease counterpart must keep the fixture's own generation 7"
    );
    // The substituted object carries a REAL member name (`role_lease_id`, which
    // both structs declare), so an unknown-field refusal cannot mask the type
    // mismatch: `invalid type` is the only reason this document can be refused.
    let object_at_generation =
        decode_host::<TaskRoleLease>(&host_raw(
            "w1_c4_task_role_lease_object_at_generation_refuse"
        ))
        .expect_err(
            "TaskRoleLease owns no nested struct, so an object at `generation` must be refused, not coerced: the protected u64 member must not decode from a map",
        );
    assert!(
        object_at_generation.to_string().contains("invalid type"),
        "the refusal must be the member-type mismatch, not an unknown field, got: {object_at_generation}"
    );

    // HostLaunchContract: an object supplied at the protected scalar
    // `role_lease_epoch`.
    let launch: HostLaunchContract = decode_host(&host_raw("w1_c3_launch_contract_positive"))
        .expect(
            "the same HostLaunchContract fixture with the scalar `role_lease_epoch` must decode",
        );
    assert_eq!(
        launch.role_lease_epoch, 3,
        "the accepted HostLaunchContract counterpart must keep the fixture's own role_lease_epoch 3"
    );
    let object_at_epoch =
        decode_host::<HostLaunchContract>(&host_raw(
            "w1_c4_launch_contract_object_at_role_lease_epoch_refuse"
        ))
        .expect_err(
            "HostLaunchContract owns no nested struct, so an object at `role_lease_epoch` must be refused, not coerced: the protected u64 member must not decode from a map",
        );
    assert!(
        object_at_epoch.to_string().contains("invalid type"),
        "the refusal must be the member-type mismatch, not an unknown field, got: {object_at_epoch}"
    );

    // GovernorConfig: unknown key inside nested `db.surreal` ...
    let config: GovernorConfig = decode_config(&config_raw("w1_c1_governor_config_positive"))
        .expect("the same GovernorConfig fixture without the nested unknown key must decode");
    assert_eq!(
        config.db.surreal.ns, "eliot",
        "the accepted counterpart must keep the fixture's own db.surreal.ns"
    );
    assert!(
        decode_config::<GovernorConfig>(&config_raw("w1_c4_config_db_surreal_nested_refuse"))
            .is_err(),
        "nested `db.surreal` must refuse the unknown member key `{W1_UNKNOWN_DB_SURREAL_MEMBER}`"
    );

    // ... and inside nested `db.surreal.capabilities`.
    let config: GovernorConfig = decode_config(&config_raw("w1_c1_governor_config_positive"))
        .expect("the same GovernorConfig fixture without the nested unknown key must decode");
    assert!(
        config.db.surreal.capabilities.deny_all,
        "the accepted counterpart must keep the fixture's own db.surreal.capabilities.deny_all"
    );
    assert!(
        decode_config::<GovernorConfig>(&config_raw("w1_c4_config_capabilities_nested_refuse"))
            .is_err(),
        "nested `db.surreal.capabilities` must refuse the unknown member key `{W1_UNKNOWN_CAPABILITIES_MEMBER}`"
    );
}

/// ADDITION (outside cases 1-4): `TaskRoleLease.lifetime` is the one member in
/// this fragment that FABRICATES a value instead of carrying one. `host.rs`
/// declares it `#[serde(default)]`, and `AuthorityLeaseLifetime`'s own `Default`
/// is `Legacy` — the honest marker for rows predating the field. So an ABSENT
/// `lifetime` decodes silently, and that silent decode is the thing to pin: it
/// must yield the declared legacy marker, never an invented `operation_bound`,
/// while every other protected member still decodes to its own literal.
// WORK_UNIT_CASE: 932/c3b_absent_lifetime_is_declared_legacy
#[test]
fn c3b_absent_lifetime_decodes_to_the_declared_legacy_marker() {
    let lease: TaskRoleLease = decode_host(&host_raw("w1_c3b_task_role_lease_absent_lifetime")).expect(
        "a TaskRoleLease fixture with NO `lifetime` member must decode: `lifetime` is `#[serde(default)]`",
    );
    assert_eq!(
        lease.lifetime,
        AuthorityLeaseLifetime::Legacy,
        "an absent `lifetime` must decode to the declared `AuthorityLeaseLifetime::Legacy` default, the honest legacy marker, never a fabricated `operation_bound`"
    );
    assert_eq!(
        lease.generation, 7,
        "the absent-`lifetime` decode must still carry the fixture's own `generation` 7: the default must not perturb the protected wire members"
    );
    assert_eq!(
        lease.epoch, 3,
        "the absent-`lifetime` decode must still carry the fixture's own `epoch` 3"
    );
    assert_eq!(
        lease.state,
        AuthorityLeaseState::Active,
        "the absent-`lifetime` decode must still carry the fixture's own `state` `active`"
    );
    assert_eq!(
        lease.role_lease_id, "lease-role-1",
        "the absent-`lifetime` decode must still carry the fixture's own `role_lease_id`"
    );
    assert_ne!(
        lease.lifetime,
        AuthorityLeaseLifetime::OperationBound,
        "an absent `lifetime` must NOT be silently upgraded to `operation_bound`: only an explicit wire value may assert the modern lifetime"
    );
}

// ---------------------------------------------------------------------------
// Cases for writer w2 (issue #932, card cards/932.md).
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 932/c5_duplicate_protected_key_refused
#[test]
#[allow(clippy::too_many_lines)]
fn c5_duplicate_protected_key_refused() {
    // Duplicate rejection here is LAYERED, and both layers are exercised.
    //
    // Layer 1 (lexical, depth-wide): the repository owns a separate,
    // duplicate-rejecting ingress -- `eliot_types::strict_json_has_no_duplicate_members`
    // (and `strict_json_value`), owned by #2985 -- which observes object
    // members through its own `MapAccess` before a `Value` is built, so a
    // repeated member is a hard error at EVERY object depth, including nested
    // objects inside arrays, and its rejection carries no input byte, offset
    // or member value.
    //
    // Layer 2 (typed, this slice): `serde_json::from_str` into a
    // `#[derive(Deserialize)]` struct drives serde's `MapAccess` directly, and
    // serde_derive DOES emit per-field duplicate detection for a non-flatten
    // struct: a repeated KNOWN member hits `Error::duplicate_field` and is
    // refused, reported as `Category::Data`. It is not last-wins. What the
    // derived path cannot see is a duplicate at a depth it does not bind, and
    // a `serde_json::Value` intermediate collapses duplicates to last-wins the
    // instant raw bytes become a `Value`, which is why every fixture below is
    // fed as RAW JSON TEXT with no `from_value`/`from_reader` hop.
    //
    // In each pair the two duplicate values DIFFER (`active`/`revoked`,
    // `1`/`999999`, `"1"`/`"2"`), so nothing about the fixture shape, the
    // member types, or the surrounding document can explain the refusal.

    /// Layer 1: the lexical owner of depth-wide duplicate rejection. Wraps
    /// `eliot_types::strict_json_has_no_duplicate_members` so the case pins the
    /// repository's shared ingress rather than re-implementing a scan, and
    /// asserts the bounded, redacted rejection contract of that owner.
    fn w2_assert_duplicate_refused_lexically(
        label: &str,
        member: &str,
        raw_text: &str,
        duplicate_values: [&str; 2],
    ) {
        let expected_refusal =
            format!("{label}: a repeated object member must be refused by the strict JSON ingress");
        let refusal = eliot_types::strict_json_has_no_duplicate_members(raw_text.as_bytes())
            .expect_err(&expected_refusal);
        assert_eq!(
            refusal.kind,
            eliot_types::StrictJsonErrorKind::DuplicateKey,
            "{label}: the refusal must be the DuplicateKey category, got: {refusal}"
        );

        // The rejection is a category only: it carries no input byte, no
        // offset, and no member value. The exact wording belongs to #2985, so
        // only the redaction GUARANTEE is asserted here, not that owner's text.
        let rendered = refusal.to_string();
        assert_eq!(
            rendered,
            eliot_types::StrictJsonErrorKind::DuplicateKey.as_str(),
            "{label}: `Display` must agree with the kind's own stable bounded string, and that \
             string must be a category label rather than the offending input"
        );
        assert!(
            !rendered.is_empty(),
            "{label}: the refusal must render a bounded category label"
        );
        assert!(
            !rendered.contains(member),
            "{label}: the refusal must not leak the duplicated member name `{member}`, got: \
             {rendered}"
        );
        assert!(
            !rendered.contains("at line") && !rendered.contains("column"),
            "{label}: the refusal must not leak an offset, got: {rendered}"
        );
        // Neither occurrence of the duplicated member's VALUE may appear.
        for value in duplicate_values {
            assert!(
                !rendered.contains(value),
                "{label}: the refusal must not leak the duplicated value `{value}`, got: \
                 {rendered}"
            );
        }
    }

    /// Layer 2: the typed decoder refuses the repeated KNOWN member at the
    /// map-access stage, naming that member. Pinned by category plus message
    /// prefix so the refusal is attributed to duplicate detection specifically
    /// and not to an unrelated later failure; the position suffix is
    /// deliberately not pinned.
    fn w2_assert_duplicate_refused_by_map_access(
        label: &str,
        member: &str,
        error: &serde_json::Error,
    ) {
        assert_eq!(
            error.classify(),
            serde_json::error::Category::Data,
            "{label}: the duplicate must be refused at the map-access stage, which reports it as \
             a data error, got: {error}"
        );
        let message = error.to_string();
        assert!(
            message.starts_with("duplicate field"),
            "{label}: the refusal must be the duplicate-member refusal, not some other data \
             error, got: {message}"
        );
        assert!(
            message.contains(member),
            "{label}: the refusal must name the duplicated member `{member}`, got: {message}"
        );
    }

    // (a) TaskRoleLease: `"state"` twice, both values valid `AuthorityLeaseState`
    // variants; the attacker tries to make the decoder pick the attacker's.
    let duplicate_state = raw("w2_task_role_lease_duplicate_state");
    w2_assert_duplicate_refused_lexically(
        "TaskRoleLease duplicate `state`",
        "state",
        &duplicate_state,
        ["active", "revoked"],
    );
    let duplicate_state_error = decode_host::<TaskRoleLease>(&duplicate_state).expect_err(
        "TaskRoleLease with a duplicated protected `state` member must be refused, never resolved \
         to either `active` or `revoked` by a first-wins or last-wins member map",
    );
    w2_assert_duplicate_refused_by_map_access(
        "TaskRoleLease duplicate `state`",
        "state",
        &duplicate_state_error,
    );
    let honest_state = raw("w2_task_role_lease_state_active");
    let decoded: TaskRoleLease =
        decode_host(&honest_state).expect("TaskRoleLease with a single honest `state` must decode");
    assert_eq!(
        decoded.state,
        AuthorityLeaseState::Active,
        "removing the duplicate `state` member must yield the honest single value `active`, \
         proving the refusal above is caused by the duplicate and nothing else"
    );

    // (b) AgentResultEnvelope: `"role_lease_epoch"` twice, `1` then `999999`.
    let duplicate_epoch = raw("w2_result_envelope_duplicate_role_lease_epoch");
    w2_assert_duplicate_refused_lexically(
        "AgentResultEnvelope duplicate `role_lease_epoch`",
        "role_lease_epoch",
        &duplicate_epoch,
        ["1", "999999"],
    );
    let duplicate_epoch_error = decode_host::<AgentResultEnvelope>(&duplicate_epoch).expect_err(
        "AgentResultEnvelope with a duplicated protected `role_lease_epoch` member must be \
         refused, never resolved to epoch 1 or epoch 999999",
    );
    w2_assert_duplicate_refused_by_map_access(
        "AgentResultEnvelope duplicate `role_lease_epoch`",
        "role_lease_epoch",
        &duplicate_epoch_error,
    );
    let honest_epoch = raw("w2_result_envelope_role_lease_epoch_1");
    let decoded_envelope: AgentResultEnvelope = decode_host(&honest_epoch)
        .expect("AgentResultEnvelope with a single honest `role_lease_epoch` must decode");
    assert_eq!(
        decoded_envelope.role_lease_epoch, 1,
        "removing the duplicate `role_lease_epoch` member must yield the honest epoch 1, never \
         the attacker's 999999"
    );

    // (c) GovernorConfig: `"schema_version"` twice, `"1"` then `"2"`.
    let duplicate_version = raw("w2_config_duplicate_schema_version");
    w2_assert_duplicate_refused_lexically(
        "GovernorConfig duplicate `schema_version`",
        "schema_version",
        &duplicate_version,
        ["\"1\"", "\"2\""],
    );
    let duplicate_version_error = decode_config::<GovernorConfig>(&duplicate_version).expect_err(
        "GovernorConfig with a duplicated `schema_version` member must be refused, never resolved \
         to the supported \"1\" or the unsupported \"2\"",
    );
    w2_assert_duplicate_refused_by_map_access(
        "GovernorConfig duplicate `schema_version`",
        "schema_version",
        &duplicate_version_error,
    );
    let honest_version = raw("w2_config_schema_version_1");
    let decoded_config: GovernorConfig = decode_config(&honest_version)
        .expect("GovernorConfig with a single honest `schema_version` must decode");
    assert_eq!(
        decoded_config.schema_version, "1",
        "removing the duplicate `schema_version` member must yield the supported version \"1\""
    );
}

// WORK_UNIT_CASE: 932/c6_unknown_tag_or_payload_refused
#[test]
fn c6_unknown_tag_or_payload_refused() {
    // Canonical APPENDIX-P rule: a closed control variant fails when unknown.
    // Every refusal below is paired with its valid counterpart, so the refusal
    // is shown to be about the tag/payload and not about the fixture shape.

    // (a) Closed enum `AgentResultStatus`: an unknown variant spelling on the
    // `status` member of an otherwise closed, minimal envelope.
    let unknown_status = raw("w2_result_envelope_status_unknown_variant");
    assert!(
        decode_host::<AgentResultEnvelope>(&unknown_status).is_err(),
        "AgentResultEnvelope.status = \"succeeded_unknown\" is not an AgentResultStatus variant \
         and must be refused, never coerced to a neighbouring variant"
    );
    let valid_status = raw("w2_result_envelope_status_succeeded");
    let decoded_envelope: AgentResultEnvelope =
        decode_host(&valid_status).expect("AgentResultEnvelope.status = \"succeeded\" must decode");
    assert_eq!(
        decoded_envelope.status,
        AgentResultStatus::Succeeded,
        "the valid counterpart must decode to the `succeeded` variant"
    );

    // (b) Closed enum `AuthorityLeaseState` on the protected `state` member.
    let unknown_state = raw("w2_task_role_lease_state_unknown_variant");
    assert!(
        decode_host::<TaskRoleLease>(&unknown_state).is_err(),
        "TaskRoleLease.state = \"activated\" is not an AuthorityLeaseState variant and must be \
         refused, never accepted as `active`"
    );
    let known_state = raw("w2_task_role_lease_state_revoked");
    let decoded_lease: TaskRoleLease =
        decode_host(&known_state).expect("TaskRoleLease.state = \"revoked\" must decode");
    assert_eq!(
        decoded_lease.state,
        AuthorityLeaseState::Revoked,
        "the valid counterpart must decode to the `revoked` variant"
    );

    // (c) Type/payload shape mismatch on a protected field: `generation` is a
    // `u64`, so an object payload must be refused rather than read through some
    // other shape.
    let object_generation = raw("w2_task_role_lease_generation_object_payload");
    // The object payload carries a REAL member name (`role_lease_id`, which
    // TaskRoleLease declares), so an unknown-field refusal cannot mask the type
    // mismatch: `invalid type` is the only reason this document can be refused.
    let object_generation_error = decode_host::<TaskRoleLease>(&object_generation).expect_err(
        "TaskRoleLease.generation given an object payload must be refused; a u64 field must \
         never be filled from an object",
    );
    assert!(
        object_generation_error.to_string().contains("invalid type"),
        "the refusal must be the member-type mismatch, not an unknown field, got: \
         {object_generation_error}"
    );
    let scalar_generation = raw("w2_task_role_lease_generation_scalar");
    let decoded_scalar: TaskRoleLease = decode_host(&scalar_generation)
        .expect("TaskRoleLease.generation given a u64 payload must decode");
    assert_eq!(
        decoded_scalar.generation, 7,
        "the valid counterpart must decode the scalar u64 generation 7"
    );

    // (c2) Payload shape mismatch on a closed field of a different shape:
    // `candidate_only` is a `bool`, given an array payload instead.
    let array_candidate_only = raw("w2_result_envelope_candidate_only_array_payload");
    assert!(
        decode_host::<AgentResultEnvelope>(&array_candidate_only).is_err(),
        "AgentResultEnvelope.candidate_only given an array payload must be refused; a bool \
         field must never be filled from an array"
    );
    let scalar_candidate_only = raw("w2_result_envelope_candidate_only_bool");
    let decoded_flag: AgentResultEnvelope = decode_host(&scalar_candidate_only)
        .expect("AgentResultEnvelope.candidate_only given a bool payload must decode");
    assert!(
        decoded_flag.candidate_only,
        "the valid counterpart must decode the boolean candidate_only = true"
    );
}

// WORK_UNIT_CASE: 932/c7_missing_or_empty_identity_refused
#[test]
fn c7_missing_or_empty_identity_refused() {
    // `TaskRoleLease.state`, `.generation` and `.epoch` carry no serde default,
    // so a missing member must be refused rather than decoding as
    // `Active` / `0`. The identity members are NOT uniform: what each one
    // refuses is exactly what its type can refuse, and nothing more is claimed.
    //
    // Exact, publicly observable classification, so a refusal is pinned to the
    // missing/empty member and cannot be satisfied by some unrelated late
    // failure: every refusal must be a `Category::Data` error whose message
    // names the offending member or the type expectation it failed, and an
    // empty identity must not be reported as an absent member.
    //
    // Only the public error API is used (`classify`/`to_string`):
    // `serde_json::error::ErrorCode` is crate-private, so the refusal is pinned
    // by category plus the reported message instead.

    // (a) `state` entirely ABSENT.
    let missing_state = decode_host::<TaskRoleLease>(&raw("w2_task_role_lease_missing_state"))
        .expect_err("TaskRoleLease.state is wire-required and must be refused when absent");
    assert!(
        missing_state.is_data(),
        "the missing `state` member must be refused by the deserializer as a data error, never \
         decoded as AuthorityLeaseState::Active"
    );
    assert!(
        missing_state.to_string().contains("state"),
        "the missing-field refusal must name `state`, got: {missing_state}"
    );

    // (b) `generation` ABSENT: must not become generation 0.
    let missing_generation = decode_host::<TaskRoleLease>(&raw(
        "w2_task_role_lease_missing_generation",
    ))
    .expect_err("TaskRoleLease.generation is wire-required and must be refused when absent");
    assert!(
        missing_generation.is_data(),
        "the missing `generation` member must be refused as a data error, never decoded as \
         generation 0"
    );
    assert!(
        missing_generation.to_string().contains("generation"),
        "the missing-field refusal must name `generation`, got: {missing_generation}"
    );

    // (c) `epoch` ABSENT: must not become epoch 0.
    let missing_epoch = decode_host::<TaskRoleLease>(&raw("w2_task_role_lease_missing_epoch"))
        .expect_err("TaskRoleLease.epoch is wire-required and must be refused when absent");
    assert!(
        missing_epoch.is_data(),
        "the missing `epoch` member must be refused as a data error, never decoded as epoch 0"
    );
    assert!(
        missing_epoch.to_string().contains("epoch"),
        "the missing-field refusal must name `epoch`, got: {missing_epoch}"
    );

    // (d) `role_lease_id` present but EMPTY STRING. This member is a plain
    // `String` with no validator, so the decoder honestly ACCEPTS it and yields
    // "". That is the boundary, stated as a property: an empty protected
    // identity is NOT refused by this decoder, so no such claim is made here.
    // Non-emptiness for `role_lease_id` is a caller-layer rule this type cannot
    // enforce, and asserting a refusal would assert something untrue.
    let empty_lease_id: TaskRoleLease = decode_host(&raw("w2_task_role_lease_empty_role_lease_id"))
        .expect(
            "TaskRoleLease.role_lease_id is a plain String with no validator, so an empty value \
             decodes; asserting a refusal here would assert something the type cannot do",
        );
    assert_eq!(
        empty_lease_id.role_lease_id, "",
        "an empty `role_lease_id` must decode to the empty string, never to a fabricated lease \
         handle; a plain String carries no non-empty rule of its own"
    );

    // (e) `agent_session_id` present but EMPTY STRING. `AgentSessionId` is a
    // transparent `Uuid` newtype, so the empty string is refused by the
    // newtype's own parse and never becomes a session identity.
    let empty_session_id =
        decode_host::<TaskRoleLease>(&raw("w2_task_role_lease_empty_agent_session_id")).expect_err(
            "TaskRoleLease.agent_session_id is required and must be refused when empty, never \
             accepted as an empty session identity",
        );
    assert_eq!(
        empty_session_id.classify(),
        serde_json::error::Category::Data,
        "an empty `agent_session_id` must be refused as a data error, never accepted as a valid \
         session, got: {empty_session_id}"
    );
    // serde_derive adds no field-name context for a newtype member, so the
    // message names the UUID parse failure rather than the field. The vendored
    // `uuid` reports an empty string as a zero-length parse failure
    // ("invalid length: found 0") through `E::custom`, which serde_json renders
    // verbatim after "invalid value: string \"\"," - with no ", expected "
    // clause, because `custom` supplies the complete message itself.
    let session_message = empty_session_id.to_string();
    assert!(
        session_message.contains("UUID parsing failed: invalid length: found 0"),
        "the refusal must name the UUID parse failure that rejected the empty identity, got: \
         {session_message}"
    );
    assert!(
        !session_message.contains("agent_session_id"),
        "the newtype refusal carries no field-name context, so `agent_session_id` must NOT be \
         claimed in the message; got: {session_message}"
    );
    assert!(
        !session_message.contains("missing field"),
        "an empty `agent_session_id` must not be reported as an absent member, got: \
         {session_message}"
    );

    // The full valid fixture still decodes, and carries real values rather than
    // fabricated defaults.
    let decoded: TaskRoleLease = decode_host(&raw("w2_task_role_lease_state_active"))
        .expect("the complete TaskRoleLease fixture must decode");
    assert_eq!(
        decoded.state,
        AuthorityLeaseState::Active,
        "the complete fixture must decode its `state` member from the wire"
    );
    assert_eq!(
        decoded.generation, 7,
        "the complete fixture must decode generation 7"
    );
    assert_eq!(decoded.epoch, 3, "the complete fixture must decode epoch 3");
    assert_eq!(
        decoded.role_lease_id, "lease-1",
        "the complete fixture must decode the lease identity from the wire"
    );
}

// WORK_UNIT_CASE: 932/c8_unsupported_schema_version_refused
#[test]
fn c8_unsupported_schema_version_refused() {
    // The expectation is derived from the shipped constant, not hard-coded: the
    // unsupported value below is only unsupported because `SCHEMA_VERSION` is
    // "1", and the pin on that constant is what keeps the fixture's "2"
    // genuinely unsupported.
    assert_eq!(
        SCHEMA_VERSION, "1",
        "this case pins the shipped schema version; if it changes, the unsupported value in \
         w2_config_schema_version_2 must change with it"
    );
    let expected = SCHEMA_VERSION.to_owned();
    assert!(
        expected.len() == 1 && expected.chars().all(|digit| digit.is_ascii_digit()),
        "the expected schema version must be a single ASCII-digit token, got {expected:?}"
    );
    let bumped = (expected.as_bytes()[0] - b'0' + 1) as char;
    assert!(
        bumped != expected.chars().next().expect("length checked above"),
        "the derived unsupported version must differ from the expected version"
    );
    let unsupported = bumped.to_string();

    // (a) The byte decoder itself still succeeds: `schema_version` is a plain
    // `String` member, so an unsupported version is carried, not refused, by
    // deserialization. This is stated explicitly so a later reader does not
    // mistake decode-level acceptance for acceptance of the configuration.
    let decoded: GovernorConfig = decode_config(&raw("w2_config_schema_version_2")).expect(
        "an unsupported schema_version is carried as a plain String by the byte decoder; \
             refusal belongs to validate(), not to deserialization",
    );
    assert_eq!(
        decoded.schema_version, unsupported,
        "the unsupported version must be carried verbatim into the decoded struct"
    );

    // (b) The refusal is `validate`'s, and specifically the FIRST check it runs.
    let Err(error) = decoded.validate() else {
        panic!("schema_version {unsupported:?} must be refused by GovernorConfig::validate");
    };
    let ConfigError::UnsupportedSchemaVersion { expected, actual } = error else {
        panic!("the refusal must be ConfigError::UnsupportedSchemaVersion, got {error:?}");
    };
    assert_eq!(
        expected, SCHEMA_VERSION,
        "the reported `expected` must be the shipped schema version constant"
    );
    assert_eq!(
        actual, unsupported,
        "the reported `actual` must be the unsupported version that was refused"
    );

    // The supported version is the positive control: same bytes, same decoder,
    // same validate path, accepted.
    let supported: GovernorConfig = decode_config(&raw("w2_config_schema_version_1"))
        .expect("the supported schema_version fixture must decode");
    assert_eq!(
        supported.schema_version, SCHEMA_VERSION,
        "the supported fixture must carry SCHEMA_VERSION on the wire"
    );
    assert!(
        supported.validate().is_ok(),
        "the supported schema_version fixture must validate, proving the refusal above is \
         specific to the unsupported version and not to the fixture"
    );
}

// ---------------------------------------------------------------------------
// Cases for writer w3 (issue #932, card cards/932.md).
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 932/c9_declared_legacy_migration_preserves_evidence
#[test]
fn w3_c9_declared_legacy_migration_preserves_evidence() {
    // (a) The declared legacy migration for a role lease. A row written before
    // the `lifetime` field existed omits the key; the derived decoder applies
    // `#[serde(default)]`, and the default is the NAMED legacy marker
    // `AuthorityLeaseLifetime::Legacy`. That is evidence preserved, not a
    // silently-upgraded current-generation lease.
    let lease: TaskRoleLease = decode_host(&raw("w3_task_role_lease_no_lifetime"))
        .expect("a role lease row that predates `lifetime` must still decode");

    assert_eq!(
        lease.lifetime,
        AuthorityLeaseLifetime::Legacy,
        "absent `lifetime` must decode to the named legacy marker AuthorityLeaseLifetime::Legacy, \
         never to a current-generation lifetime"
    );
    assert_eq!(
        lease.lifetime,
        AuthorityLeaseLifetime::default(),
        "the `lifetime` default the decoder applies must be the type's own Legacy default"
    );
    assert_ne!(
        lease.lifetime,
        AuthorityLeaseLifetime::Persistent,
        "an absent `lifetime` must never be promoted to the current Persistent lifetime"
    );
    assert_ne!(
        lease.lifetime,
        AuthorityLeaseLifetime::OperationBound,
        "an absent `lifetime` must never be promoted to the current OperationBound lifetime"
    );
    assert_ne!(
        lease.lifetime,
        AuthorityLeaseLifetime::SealBound,
        "an absent `lifetime` must never be promoted to the current SealBound lifetime"
    );

    // The legacy default dragged nothing else with it: every other protected
    // field is exactly the literal the legacy row carried.
    assert_eq!(lease.role_lease_id, "lease-w3-0001", "role_lease_id");
    assert_eq!(lease.epoch, 7, "epoch");
    assert_eq!(lease.generation, 42, "generation");
    assert_eq!(lease.state, AuthorityLeaseState::Consumed, "state");
    assert_ne!(
        lease.state,
        AuthorityLeaseState::default(),
        "the state read off the wire must not be the derive default Active"
    );

    // The wire row omitted `lifetime`, so the decoder's declared default
    // supplied it; re-rendering the value states `lifetime = legacy` again, so
    // the legacy classification survives the round trip instead of being lost.
    let rendered = serde_json::to_value(&lease).expect("TaskRoleLease re-renders");
    assert_eq!(
        rendered.get("lifetime"),
        Some(&serde_json::json!("legacy")),
        "the decoded lease must state `lifetime = legacy` on the wire"
    );

    // (b) The declared legacy migration for credential storage. A
    // `SurrealServerConfig` that says nothing about credentials resolves to the
    // secure authority (`WindowsCredentialManager`), never to the legacy
    // password file; selecting the password file is a deliberate, gated
    // migration step that must be written out explicitly.
    let surreal: SurrealServerConfig =
        decode_host(&raw("w3_surreal_server_credential_fields_absent"))
            .expect("a SurrealServerConfig with no credential fields must still decode");

    assert_eq!(
        surreal.credential_provider,
        CredentialProviderKind::WindowsCredentialManager,
        "an absent credential_provider must resolve to the secure WindowsCredentialManager"
    );
    assert_ne!(
        surreal.credential_provider,
        CredentialProviderKind::LegacyPasswordFile,
        "an absent credential_provider must never silently select the legacy password file"
    );
    assert_eq!(
        surreal.credential_id, "surreal-runtime/local-dev",
        "absent credential_id must decode to the documented default id"
    );
    assert_eq!(
        surreal.password_file, "%LOCALAPPDATA%/Eliot/secrets/surreal_root_password.txt",
        "absent password_file must decode to the documented default path, unused while the \
         provider is WindowsCredentialManager"
    );
}

// WORK_UNIT_CASE: 932/c10_unsafe_migration_refused
#[test]
fn w3_c10_unsafe_migration_refused() {
    // (a) The unsafe migration, half written out. A config that names the
    // legacy `LegacyPasswordFile` provider must also name the file; with the
    // empty string that no key-presence check can catch, `validate` refuses.
    let unsafe_migration: GovernorConfig = decode_config(&raw(
        "w3_governor_config_legacy_provider_empty_password_file",
    ))
    .expect("the unsafe-migration document decodes; validate is what must refuse it");

    assert_eq!(
        unsafe_migration.db.surreal.credential_provider,
        CredentialProviderKind::LegacyPasswordFile,
        "the fixture really did select the legacy password-file provider"
    );
    // No substitution: the empty string survives decode verbatim. Nothing
    // fabricates a password file on the way to the refusal.
    assert!(
        unsafe_migration.db.surreal.password_file.is_empty(),
        "decode must not fabricate db.surreal.password_file, got {:?}",
        unsafe_migration.db.surreal.password_file
    );

    assert!(
        matches!(
            unsafe_migration.validate(),
            Err(ConfigError::EmptyField {
                field: "db.surreal.password_file"
            })
        ),
        "an explicitly selected LegacyPasswordFile provider with an empty password_file must be \
         refused as db.surreal.password_file"
    );

    // The refusal changes nothing: the document keeps every field it declared, so
    // no unsafe migration is quietly adopted and nothing was rewritten to make
    // it validate.
    assert_eq!(
        unsafe_migration.schema_version, "1",
        "schema_version must survive the refusal unchanged"
    );
    assert_eq!(
        unsafe_migration.db.surreal.user, "root",
        "db.surreal.user must survive the refusal unchanged"
    );
    assert_eq!(
        unsafe_migration.db.surreal.password_file, "",
        "the empty db.surreal.password_file must still be empty after the refusal"
    );
    assert!(
        unsafe_migration.validate().is_err(),
        "the refusal must be stable, not a one-shot"
    );

    // (b) The unsafe migration named as a schema upgrade. A config that declares
    // a schema this build does not implement is refused, not up-converted.
    let unsupported: GovernorConfig = decode_config(&raw("w3_governor_config_unsupported_schema"))
        .expect("the unsupported-schema document decodes as data");
    assert_eq!(
        unsupported.schema_version, "2",
        "the fixture really did declare an unsupported schema_version"
    );
    assert!(
        matches!(
            unsupported.validate(),
            Err(ConfigError::UnsupportedSchemaVersion { .. })
        ),
        "schema_version \"2\" must be refused as unsupported, never migrated"
    );
    assert_eq!(
        unsupported.schema_version, "2",
        "the refusal must not rewrite schema_version to the supported \"1\""
    );
    let Err(ConfigError::UnsupportedSchemaVersion { expected, actual }) = unsupported.validate()
    else {
        panic!("schema_version \"2\" must be refused as UnsupportedSchemaVersion");
    };
    assert_eq!(
        actual, "2",
        "the refusal must report the actual schema_version"
    );
    assert_eq!(
        expected, "1",
        "the refusal must name the schema_version this build requires"
    );

    // (c) An unapproved provider kind. `DpapiProtectedFile` decodes (it is a
    // declared enum variant) and is refused by `validate` as an unsupported
    // provider, rather than being quietly replaced by an approved one.
    let unapproved: GovernorConfig = decode_config(&raw("w3_governor_config_unapproved_provider"))
        .expect("the unapproved-provider document decodes as data");
    assert_eq!(
        unapproved.db.surreal.credential_provider,
        CredentialProviderKind::DpapiProtectedFile,
        "the fixture really did select the unapproved DpapiProtectedFile provider"
    );
    assert!(
        matches!(
            unapproved.validate(),
            Err(ConfigError::UnsupportedCredentialProvider { .. })
        ),
        "DpapiProtectedFile must be refused as an unsupported credential provider"
    );
    assert_eq!(
        unapproved.db.surreal.credential_provider,
        CredentialProviderKind::DpapiProtectedFile,
        "the refusal must not rewrite db.surreal.credential_provider to an approved provider"
    );
}

// WORK_UNIT_CASE: 932/c11_no_flatten_or_value_erasure
#[test]
#[allow(clippy::too_many_lines)]
fn w3_c11_no_flatten_or_value_erasure() {
    // (a) SOURCE SURFACE, asserted at runtime against the crate's own bytes.
    // These are real checks against `src/*.rs`: they fail the moment anyone adds
    // a `#[serde(flatten` attribute to one of these three files. The bare token
    // `flatten` is deliberately NOT asserted against -- these files name it in
    // their own decoder doc comments, which is the documentation of the
    // property, not a violation of it.
    let sources: [(&str, &str); 3] = [
        (
            "src/host.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/host.rs")),
        ),
        (
            "src/config.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config.rs")),
        ),
        (
            "src/secret_boundary.rs",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/secret_boundary.rs"
            )),
        ),
    ];

    // `host.rs` and `config.rs` declare the closed decoders; if a deny were
    // dropped the negative `flatten` check below would still pass vacuously, so
    // each deny is asserted to be present.
    for (path, src) in [
        ("src/host.rs", sources[0].1),
        ("src/config.rs", sources[1].1),
    ] {
        assert!(
            src.contains("#[serde(deny_unknown_fields)]"),
            "{path} must carry #[serde(deny_unknown_fields)] on its wire structs"
        );
    }

    for (path, src) in sources {
        assert!(
            !src.contains("#[serde(flatten"),
            "{path} must declare no #[serde(flatten)] attribute"
        );
    }

    // The inbound half of the same claim, proven soundly: `SecretBoundaryViolation`
    // names itself throughout its own file, so the property checked here is the
    // DECLARED derive list on the struct itself -- it carries `Copy` and no
    // `Deserialize`. (Searched only as a locating offset, never as a
    // file-wide absence claim.)
    let boundary_src = sources[2].1;
    let struct_offset = boundary_src
        .find("pub struct SecretBoundaryViolation")
        .expect("src/secret_boundary.rs must still declare `pub struct SecretBoundaryViolation`");
    let derive_block = &boundary_src[..struct_offset];
    // Anchor on the nearest `#[derive` rather than a fixed-size tail, so added
    // doc comment above the struct cannot push `Copy` out of the window and make
    // the `Deserialize` absence check vacuously true.
    let derive_start = derive_block.rfind("#[derive").expect(
        "src/secret_boundary.rs must declare `SecretBoundaryViolation` behind a derive list",
    );
    let derive_list = &derive_block[derive_start..];
    assert!(
        derive_list.contains("Copy"),
        "the derive list preceding `pub struct SecretBoundaryViolation` must carry Copy, got \
         {derive_list:?}"
    );
    assert!(
        !derive_list.contains("Deserialize"),
        "the derive list preceding `pub struct SecretBoundaryViolation` must NOT carry \
         Deserialize: it has no Deserialize impl and must never become a decodable inbound type, \
         got {derive_list:?}"
    );

    // (b) BEHAVIOURAL. The SAME valid `TaskRoleLease` decoded twice: once from
    // raw JSON text, once from a `serde_json::Value` built by hand from the same
    // fields. Both paths run the derived, untagged, flatten-free decoder, and the
    // two results are equal, so neither erases or differently defaults a
    // protected field (`role_lease_id`, `epoch`, `state`, `generation`,
    // `lifetime`, `capability_scope`, `expires_at`).
    let from_text: TaskRoleLease = decode_host(&raw("w3_task_role_lease_full"))
        .expect("the complete role lease must decode from raw JSON text");
    let from_value: TaskRoleLease = decode_host(&w3_task_role_lease_value().to_string())
        .expect("the hand-built Value re-serialised to text must decode through the same decoder");

    assert_eq!(
        from_value, from_text,
        "a Value-built document must decode to exactly the same TaskRoleLease as the raw text"
    );

    // The protected fields survive the Value path with their literal wire
    // values, none defaulted and none erased.
    assert_eq!(from_value.role_lease_id, "lease-w3-0001", "role_lease_id");
    assert_eq!(from_value.epoch, 7, "epoch");
    assert_eq!(from_value.generation, 42, "generation");
    assert_eq!(from_value.state, AuthorityLeaseState::Consumed, "state");
    assert_eq!(
        from_value.lifetime,
        AuthorityLeaseLifetime::Persistent,
        "lifetime"
    );
    assert_eq!(
        from_value.capability_scope,
        vec!["read".to_owned(), "write".to_owned()],
        "capability_scope"
    );
    let expires = from_value.expires_at.to_string();
    assert!(
        expires.starts_with("2026-09-23 12:00:00") && expires.ends_with("+00:00:00"),
        "expires_at must survive the Value path as the same UTC instant, got {expires}"
    );

    // Neither path erases input: an UNKNOWN member key is still refused by both.
    // Were a `flatten`/`Value` erasure introduced, this is what would fail.
    let mut tampered_value = w3_task_role_lease_value();
    tampered_value
        .as_object_mut()
        .expect("the lease fixture must be a JSON object")
        .insert(
            "w3_unexpected_member".to_owned(),
            serde_json::json!("w3-value"),
        );
    assert!(
        decode_host::<TaskRoleLease>(&tampered_value.to_string()).is_err(),
        "an unknown member key must still be refused on the Value path"
    );

    let text = raw("w3_task_role_lease_full");
    let tampered_text = text.replace(
        "\"state\":\"consumed\"",
        "\"state\":\"consumed\",\"w3_unexpected_member\":\"w3-text\"",
    );
    assert_ne!(
        tampered_text, text,
        "the tampered text must actually carry the injected unknown member key"
    );
    assert!(
        decode_host::<TaskRoleLease>(&tampered_text).is_err(),
        "an unknown member key must still be refused on the raw-text path"
    );
}

// WORK_UNIT_CASE: 932/c12_ambiguous_fallback_refused_approved_defaults_survive
#[test]
#[allow(clippy::too_many_lines)]
fn w3_c12_ambiguous_fallback_refused_approved_defaults_survive() {
    // (a) AMBIGUOUS. `state` and `generation` are required on the wire. Neither
    // has an approved default, so a missing value is refused rather than
    // fabricated as `Active` or `0`.
    let text = raw("w3_task_role_lease_full");
    assert!(
        text.contains("\"state\":\"consumed\""),
        "the base fixture must carry `state`, or the removals below are vacuous"
    );
    assert!(
        text.contains("\"generation\":42"),
        "the base fixture must carry `generation`"
    );
    // Control: the untouched document decodes, so every refusal below is caused
    // by the removed member and not by a fixture that was already broken.
    decode_host::<TaskRoleLease>(&text)
        .expect("the unaltered base document must decode, or the refusals below would be vacuous");

    let without_state = text.replace("\"state\":\"consumed\",", "");
    assert_ne!(
        without_state, text,
        "removing `state` must actually change the document"
    );
    assert!(
        decode_host::<TaskRoleLease>(&without_state).is_err(),
        "a TaskRoleLease missing `state` must be refused, never fabricated as \
         AuthorityLeaseState::Active"
    );

    let without_generation = text.replace("\"generation\":42,", "");
    assert_ne!(
        without_generation, text,
        "removing `generation` must actually change the document"
    );
    assert!(
        decode_host::<TaskRoleLease>(&without_generation).is_err(),
        "a TaskRoleLease missing `generation` must be refused, never fabricated as 0"
    );

    // The other protected authority fields carry no default either.
    let without_epoch = text.replace("\"epoch\":7,", "");
    assert_ne!(
        without_epoch, text,
        "removing `epoch` must actually change the document"
    );
    assert!(
        decode_host::<TaskRoleLease>(&without_epoch).is_err(),
        "a TaskRoleLease missing `epoch` must be refused, never fabricated as 0"
    );
    let without_id = text.replace("\"role_lease_id\":\"lease-w3-0001\",", "");
    assert_ne!(
        without_id, text,
        "removing `role_lease_id` must actually change the document"
    );
    assert!(
        decode_host::<TaskRoleLease>(&without_id).is_err(),
        "a TaskRoleLease missing `role_lease_id` must be refused"
    );

    // (b) SURVIVE. The three approved defaulted sections stay defaulted: a
    // config that omits `supervision`, `delegation_calibration` and `ul`
    // entirely still decodes, and each section is exactly its own `Default`.
    let approved_defaults_raw = raw("w3_governor_config_approved_defaults_absent");
    let defaulted: GovernorConfig = decode_config(&approved_defaults_raw)
        .expect("a config with supervision/delegation_calibration/ul all absent must still decode");

    assert_eq!(
        defaulted.supervision,
        RuntimeSupervisionConfig::default(),
        "an absent `supervision` section must decode to RuntimeSupervisionConfig::default()"
    );
    assert_eq!(
        defaulted.supervision.watchdog_interval_ms, 2_000,
        "supervision.watchdog_interval_ms must be the documented 2000 ms default"
    );

    assert_eq!(
        defaulted.delegation_calibration,
        DelegationCalibrationConfig::default(),
        "an absent `delegation_calibration` section must decode to \
         DelegationCalibrationConfig::default()"
    );
    assert_eq!(
        defaulted.ul,
        UlConfig::default(),
        "an absent `ul` section must decode to UlConfig::default()"
    );
    assert_eq!(
        defaulted.ul.activation.enable_min_edges, 500,
        "ul.activation.enable_min_edges must be the documented 500 default"
    );

    // The approved defaults grant no configuration authority of their own: the
    // document is a byte-for-byte rendering of `GovernorConfig::default()`, and
    // policy still applies on top of it.
    assert_eq!(
        defaulted,
        GovernorConfig::default(),
        "the approved-defaults document must decode to exactly GovernorConfig::default()"
    );
    assert!(
        defaulted.validate().is_ok(),
        "the approved-defaults config must still pass validate(): the defaults do not weaken policy"
    );

    // (c) AMBIGUOUS CONFIG COUNTERPART. `service` and `db` have no approved
    // default: a config that omits either is refused as a MISSING FIELD, not
    // fabricated. The key is GENUINELY removed from the parsed document (a
    // rename would instead be refused as an unknown field, which proves
    // `deny_unknown_fields` and nothing about defaults).
    //
    // Control: the same fixture, untouched, decodes.
    let approved_defaults: GovernorConfig = decode_config(&approved_defaults_raw).expect(
        "the control decode of the unmodified approved-defaults document must succeed before \
         its keys are removed",
    );
    assert_eq!(
        approved_defaults, defaulted,
        "the control decode and the earlier decode of the same bytes must agree"
    );

    for key in ["service", "db"] {
        let mut document: serde_json::Value = serde_json::from_str(&approved_defaults_raw).expect(
            "the approved-defaults fixture must parse as a JSON document before a key is removed",
        );
        let removed = document
            .as_object_mut()
            .expect("the approved-defaults fixture must be a JSON object")
            .remove(key);
        assert!(
            removed.is_some(),
            "the approved-defaults fixture must really carry the top-level `{key}` key, so its \
             removal below is not vacuous"
        );
        let without_key = serde_json::to_string(&document).expect("the pruned document re-renders");

        let Err(error) = decode_config::<GovernorConfig>(&without_key) else {
            panic!("a GovernorConfig without `{key}` must be refused: no approved default for it");
        };
        let message = error.to_string();
        assert!(
            message.contains("missing field") && message.contains(key),
            "a GovernorConfig without `{key}` must be refused for a MISSING FIELD naming `{key}`, \
             not for an unknown field and not by fabrication, got {message:?}"
        );
    }

    // (d) The counterpart of the approved credential defaults. Absence is
    // approved; presence with nothing behind it is not.
    //
    // DISCLOSURE. This is a documented PERMISSIVE DEFAULT on main, not a
    // fabricated value: `SurrealServerConfig::password_file` carries
    // `#[serde(default = "default_surreal_password_file")]`, whose default is
    // the non-empty path below, and `validate` only refuses a LegacyPasswordFile
    // provider whose `password_file` is EMPTY. So selecting the legacy provider
    // while omitting `password_file` is ACCEPTED here, and this case asserts
    // that real behaviour. The card's "unsafe migration is refused" claim is
    // therefore provable only through an EXPLICIT empty value -- which is case
    // 10(a), `w3_c10_unsafe_migration_refused`, asserted there rather than
    // duplicated here.
    let legacy_but_absent: GovernorConfig = decode_config(&raw(
        "w3_governor_config_legacy_provider_credential_fields_absent",
    ))
    .expect("a config naming LegacyPasswordFile with no credential fields decodes");
    assert_eq!(
        legacy_but_absent.db.surreal.credential_provider,
        CredentialProviderKind::LegacyPasswordFile,
        "the fixture really did select the legacy provider explicitly"
    );
    assert_eq!(
        legacy_but_absent.db.surreal.password_file,
        "%LOCALAPPDATA%/Eliot/secrets/surreal_root_password.txt",
        "the omitted password_file must decode to the documented non-empty default path, never a \
         fabricated or empty one"
    );
    assert_eq!(
        legacy_but_absent.db.surreal.credential_id, "surreal-runtime/local-dev",
        "the omitted credential_id must decode to the documented default id"
    );
    assert!(
        legacy_but_absent.validate().is_ok(),
        "main accepts the legacy provider with the DOCUMENTED DEFAULT password_file, because that \
         default is non-empty; the genuine refusal of an unsafe migration needs an explicitly \
         empty password_file, asserted in case 10(a)"
    );
}

/// The same wire document, hand-built as a `serde_json::Value` rather than parsed
/// from text, for the case 11(b) two-path equality proof.
fn w3_task_role_lease_value() -> serde_json::Value {
    serde_json::json!({
        "role_lease_id": "lease-w3-0001",
        "task_id": "00000000-0000-7000-8000-000000000002",
        "agent_session_id": "00000000-0000-7000-8000-000000000003",
        "role": "implementer",
        "capability_scope": ["read", "write"],
        "expires_at": "2026-09-23T12:00:00Z",
        "epoch": 7,
        "state": "consumed",
        "lifetime": "persistent",
        "generation": 42,
        "issued_at": "2026-09-23T11:00:00Z",
        "activated_at": "2026-09-23T11:30:00Z",
        "consumed_at": "2026-09-23T12:30:00Z"
    })
}

// ---------------------------------------------------------------------------
// Cases for writer w4b (issue #932, card cards/932.md).
// ---------------------------------------------------------------------------

/// The unknown member keys injected below, named once so that every refusal
/// assertion can quote the exact key that caused it. No fixture carries any of
/// them: each is introduced by the test, into a copy of a known-good document.
const W4B_RECEIPT_MEMBER: &str = "w4b_unknown_receipt_member";
const W4B_DISPOSITION_RECEIPT_MEMBER: &str = "w4b_unknown_disposition_receipt_member";
const W4B_HOST_OUTPUT_TAIL: &str = "\"output_or_error_ref\":\"w4b clean operator summary\"";

/// Length of the source window a named exception is required to carry. The
/// window is anchored on the token that NAMES the exception and extends forward
/// from it, so it covers only that exception's own doc comment: every
/// `Invalidate-on-change:` line on `main` lies within ~250 bytes after its
/// token, while the following declaration begins well beyond that. Anchoring at
/// the token rather than at the start of the doc block is what makes deleting a
/// marker line actually fail the assertion instead of being swept over by a
/// window wide enough to reach the next item.
const W4B_DOC_WINDOW_BYTES: usize = 320;

// WORK_UNIT_CASE: 932/c13_exceptions_invalidate_on_change
#[test]
fn w4b_c13_exceptions_invalidate_on_change() {
    let host_src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/host.rs"));

    // (a) SOURCE, executable. Each decoder exception on `src/host.rs` is
    // EXEMPT from the flat deny on the grounds that its remaining condition is
    // recorded as invalidate-on-change. This proves the recording is actually
    // there, attached to the exception it belongs to.
    //
    // The check is window-scoped around the token, not a file-wide search, so
    // deleting a single `Invalidate-on-change:` line fails it: the marker would
    // no longer fall inside the doc window of its own token. A bare
    // `host_src.contains("Invalidate-on-change")` would instead keep passing off
    // the unrelated occurrences elsewhere in the file, which is why no such
    // global pre-check is made here.
    for (token, window) in [
        ("T07/#936", w4_doc_window(host_src, "T07/#936")),
        ("T04/#933", w4_doc_window(host_src, "T04/#933")),
        ("T08/#937", w4_doc_window(host_src, "T08/#937")),
        ("Owner: #371", w4_doc_window(host_src, "Owner: #371")),
    ] {
        assert!(
            window.contains("Invalidate-on-change"),
            "the decoder exception named `{token}` on src/host.rs must carry its own \
             Invalidate-on-change condition in the doc block that names it, got: {window:?}"
        );
    }

    // The T07/#936 exception is specifically about this binding type, so its
    // window must name the type as well as the condition.
    let t07_window = w4_doc_window(host_src, "T07/#936");
    assert!(
        t07_window.contains("AgentSessionHostBinding"),
        "the T07/#936 exception window must name AgentSessionHostBinding, the type whose \
         nesting is the stated exception, got: {t07_window:?}"
    );

    // The other two exception windows must name the things their conditions
    // depend on: T08/#937 closes the nested type, and Owner: #371 points at the
    // upstream ingress that is deliberately not edited here.
    let t08_window = w4_doc_window(host_src, "T08/#937");
    assert!(
        t08_window.contains("WriteReceiptRef"),
        "the T08/#937 exception window must name the nested type WriteReceiptRef whose \
         deny_unknown_fields is what it delegates to, got: {t08_window:?}"
    );
    let owner_window = w4_doc_window(host_src, "Owner: #371");
    assert!(
        owner_window.contains("normalize"),
        "the Owner: #371 exception window must name the upstream `normalize` ingress its \
         condition is stated against, got: {owner_window:?}"
    );

    // (b) BEHAVIOURAL. The T08/#937 exception is a DELEGATED DENY: neither
    // `AgentResultEnvelope` nor `AgentResultDisposition` closes the nested
    // `canonical_receipt` itself, both delegating to
    // `memory.rs::WriteReceiptRef`'s `#[serde(deny_unknown_fields)]`. A doc
    // comment is not a control, so the delegation is proved by execution.
    let receipt: Result<AgentResultEnvelope, _> =
        decode_host(&raw("w4b_result_envelope_canonical_receipt"));
    let receipt =
        receipt.expect("the AgentResultEnvelope with a populated canonical_receipt must decode");

    // `canonical_receipt` is OPTIONAL and `#[serde(default)]`, so its absence is
    // a declared condition rather than a demonstration of the nested deny. The
    // probe therefore takes the document that OMITS the key and injects an
    // unknown member INSIDE `canonical_receipt` -- exactly what the T08/#937
    // deny exists to refuse.
    assert!(
        receipt.canonical_receipt.is_some(),
        "the control fixture must really carry a populated canonical_receipt, or the \
         nested-deny proof below would be vacuous"
    );

    let carrier = raw("w4b_result_envelope_no_canonical_receipt");
    let tampered_receipt = w4_inject_receipt_member(&carrier, W4B_RECEIPT_MEMBER);
    assert_ne!(
        tampered_receipt, carrier,
        "the injection must actually change the document"
    );
    let Err(receipt_error) = decode_host::<AgentResultEnvelope>(&tampered_receipt) else {
        panic!(
            "an unknown member `{W4B_RECEIPT_MEMBER}` inside canonical_receipt must be refused \
             by the T08/#937 delegated deny on WriteReceiptRef"
        );
    };
    assert_eq!(
        receipt_error.classify(),
        serde_json::error::Category::Data,
        "the injected unknown member `{W4B_RECEIPT_MEMBER}` must be refused by the nested \
         deny_unknown_fields itself (a data error), not by a syntax or truncation failure, \
         got: {receipt_error}"
    );

    // The `AgentResultDisposition` half of the same delegated deny.
    let disposition: Result<AgentResultDisposition, _> =
        decode_host(&raw("w4b_result_disposition_canonical_receipt"));
    let disposition = disposition
        .expect("the AgentResultDisposition with a populated canonical_receipt must decode");
    assert!(
        disposition.canonical_receipt.is_some(),
        "the control disposition fixture must really carry a populated canonical_receipt"
    );

    let disposition_carrier = raw("w4b_result_disposition_no_canonical_receipt");
    let tampered_disposition =
        w4_inject_receipt_member(&disposition_carrier, W4B_DISPOSITION_RECEIPT_MEMBER);
    assert_ne!(
        tampered_disposition, disposition_carrier,
        "the injection must actually change the disposition document"
    );
    let Err(disposition_error) = decode_host::<AgentResultDisposition>(&tampered_disposition)
    else {
        panic!(
            "an unknown member `{W4B_DISPOSITION_RECEIPT_MEMBER}` inside canonical_receipt must \
             be refused on AgentResultDisposition too"
        );
    };
    assert_eq!(
        disposition_error.classify(),
        serde_json::error::Category::Data,
        "the injected unknown member `{W4B_DISPOSITION_RECEIPT_MEMBER}` must be refused by the \
         nested deny_unknown_fields itself, got: {disposition_error}"
    );
}

/// The source window that must carry `token`'s invalidate-on-change condition:
/// the `///` doc line the token sits on, and the `W4B_DOC_WINDOW_BYTES` that
/// follow the TOKEN itself. Bounding the window from the token - not from the
/// start of the doc comment - is what makes this a per-exception check: the
/// condition has to be stated next to the exception that claims it, so deleting
/// that one line moves it out of the window and fails here, while a later
/// item's doc comment can no longer be swept in to satisfy it. Panics if the
/// token is absent, so a renamed or deleted exception is a loud failure rather
/// than a silently skipped check.
fn w4_doc_window<'a>(source: &'a str, token: &str) -> &'a str {
    let offset = source
        .find(token)
        .unwrap_or_else(|| panic!("src/host.rs must still carry the exception token `{token}`"));
    let line_start = source[..offset].rfind('\n').map_or(0, |index| index + 1);
    let doc_start = source[..line_start]
        .rfind("\n/// ")
        .map_or(0, |index| index + 1);
    let end = offset
        .saturating_add(W4B_DOC_WINDOW_BYTES)
        .min(source.len());
    // Both offsets come from `find`/`rfind`, so both are char boundaries; the
    // forward bound is additionally checked to keep a sliced window from
    // splitting a multi-byte character.
    assert!(
        source.is_char_boundary(end),
        "the source window for `{token}` must not split a character"
    );
    &source[doc_start..end]
}

/// Injects one unknown member inside `canonical_receipt` of an envelope that
/// OMITS the `canonical_receipt` key: that key is
/// `#[serde(default)] pub canonical_receipt: Option<WriteReceiptRef>`, so it is
/// written back out here together with the injected member, and the injected
/// member lands inside the closed `WriteReceiptRef` object.
fn w4_inject_receipt_member(document: &str, member: &str) -> String {
    assert!(
        !document.contains("\"canonical_receipt\""),
        "the carrier document must omit the optional `canonical_receipt` key, so that the \
         injected member is what makes the key appear"
    );
    let injection = format!(
        "\"canonical_receipt\":{{\"receipt_id\":\"01920000-0000-7000-8000-0000000000a1\",\"write_id\":\"01920000-0000-7000-8000-0000000000a2\",\"{member}\":\"w4b\"}}"
    );
    let Some(anchor) = document.find('}') else {
        panic!("the carrier document must be a JSON object");
    };
    let (head, tail) = document.split_at(anchor);
    let separator = if head.trim_end().ends_with(',') {
        ""
    } else {
        ","
    };
    format!("{head}{separator}{injection}{tail}")
}

// WORK_UNIT_CASE: 932/c14_bounded_malformed_input_panic_free
#[test]
fn w4b_c14_bounded_malformed_input_panic_free() {
    // (a) EMPTY. Zero bytes are not a secret and must not trip the bound.
    assert_eq!(
        inspect_secret_bytes(&[]),
        Ok(()),
        "an empty slice is not oversized and carries no scanner marker, so it must be Ok"
    );

    // (b) EXACTLY AT THE BOUND. The check is `bytes.len() > MAX`, so the slice
    // whose length equals the bound is still admissible.
    let at_bound = vec![b'a'; MAX_SECRET_BOUNDARY_BYTES];
    assert_eq!(at_bound.len(), MAX_SECRET_BOUNDARY_BYTES);
    assert_eq!(
        inspect_secret_bytes(&at_bound),
        Ok(()),
        "a benign ASCII slice of exactly MAX_SECRET_BOUNDARY_BYTES must be Ok, because the \
         bound is exclusive"
    );

    // (c) ONE BYTE OVER THE BOUND. Only the size may be the reason: the same
    // filler byte, with no marker, one byte longer.
    let over_bound = vec![b'a'; MAX_SECRET_BOUNDARY_BYTES + 1];
    assert_eq!(over_bound.len(), MAX_SECRET_BOUNDARY_BYTES + 1);
    let over_violation = inspect_secret_bytes(&over_bound)
        .expect_err("one byte over MAX_SECRET_BOUNDARY_BYTES must be refused");
    assert_eq!(
        over_violation.rule,
        SecretBoundaryRule::OutputTooLarge,
        "one byte over the bound must be refused as OutputTooLarge and nothing else"
    );

    // (d) ARBITRARY BINARY. The scanner is ASCII-oriented and must survive
    // bytes that are not text at all, including NUL and high bytes.
    let binary: [u8; 4] = [0xff, 0xfe, 0x00, 0x80];
    assert_eq!(
        inspect_secret_bytes(&binary),
        Ok(()),
        "arbitrary non-text bytes with no marker must pass the scanner without a panic"
    );
    let binary_sweep: Vec<u8> = (0u16..=255)
        .map(|byte| u8::try_from(byte % 256).expect("0..=255 always fits in a u8"))
        .collect();
    assert_eq!(
        inspect_secret_bytes(&binary_sweep),
        Ok(()),
        "every byte value 0x00..=0xFF in one buffer must pass the scanner without a panic"
    );

    // (e) TRUNCATED JSON is a decoder concern, and the decoder must classify it
    // as end-of-input rather than as bad data.
    let truncated = "{\"state\":";
    let Err(truncated_error) = decode_host::<Vec<String>>(truncated) else {
        panic!("the truncated document `{{\"state\":` must be refused");
    };
    assert_eq!(
        truncated_error.classify(),
        serde_json::error::Category::Eof,
        "a truncated document must be refused as Category::Eof, got: {truncated_error}"
    );

    // (f) VALID BUT WRONG-TYPED. An object where a `Vec<String>` is required is
    // refused as a data error, not silently coerced or emptied.
    let wrong_typed = "{\"state\":\"consumed\"}";
    let Err(wrong_typed_error) = decode_host::<Vec<String>>(wrong_typed) else {
        panic!("a JSON object supplied where a Vec<String> is required must be refused");
    };
    assert_eq!(
        wrong_typed_error.classify(),
        serde_json::error::Category::Data,
        "a wrong-typed member must be refused as Category::Data, got: {wrong_typed_error}"
    );

    // (g) DEEP NESTING. 64 levels is inside `serde_json`'s 128-level nesting
    // limit, so the outcome is pinned to a Category like its siblings: a
    // `Category::Data` refusal from the typed decoder, not the `Syntax`
    // classification that a tripped recursion guard would produce.
    let deep = w4_deeply_nested(64);
    let deep_error = decode_host::<Vec<String>>(&deep)
        .err()
        .or_else(|| decode_host::<serde_json::Value>(&deep).err());
    let Some(deep_error) = deep_error else {
        panic!("64 levels of nesting must produce a typed decode result rather than a panic");
    };
    assert_eq!(
        deep_error.classify(),
        serde_json::error::Category::Data,
        "64 levels of nesting must reach the typed decoder (Category::Data) rather than the \
         recursion guard (Category::Syntax), got: {deep_error}"
    );

    // (h) THE OVERSIZED CASE IS GENERATED AT RUNTIME. An 8.4 MB fixture
    // committed into the repository is not acceptable evidence: it would bloat
    // every future `git` operation to support one size assertion, and its bytes
    // would dwarf the code that checks them. The payload is built from a real,
    // known-good `OperationJob` document, so the oversized input is ordinary
    // wire content and nothing about it is new.
    let oversized = w4_oversized_operation_job();
    assert!(
        oversized.len() > MAX_SECRET_BOUNDARY_BYTES,
        "the generated payload must actually be over the bound, got {} bytes",
        oversized.len()
    );
    let oversized_violation =
        inspect_secret_bytes(&oversized).expect_err("the oversized payload must be refused");
    assert_eq!(
        oversized_violation.rule,
        SecretBoundaryRule::OutputTooLarge,
        "the generated oversized payload must be refused as OutputTooLarge"
    );
    // Control: the FIRST MAX_SECRET_BOUNDARY_BYTES bytes of the same document are
    // admissible, so the refusal above is a consequence of the size alone.
    let trimmed = oversized
        .get(..MAX_SECRET_BOUNDARY_BYTES)
        .expect("the oversized payload is longer than the bound");
    assert_eq!(
        inspect_secret_bytes(trimmed),
        Ok(()),
        "the first MAX_SECRET_BOUNDARY_BYTES bytes of the same document must be Ok, so the \
         refusal above is caused by the size alone"
    );
}

/// The depth-`depth` nesting fixture for case 14(g). `serde_json`'s default
/// nesting limit is 128, so 64 is inside it and the decode reaches a typed
/// conclusion instead of the recursion guard.
fn w4_deeply_nested(depth: usize) -> String {
    let open = "[".repeat(depth);
    let close = "]".repeat(depth);
    format!("{open}{close}")
}

/// The oversize fixture, built at runtime. See case 14(h): an 8.4 MB committed
/// fixture is not acceptable evidence for a size predicate.
fn w4_oversized_operation_job() -> Vec<u8> {
    let template = raw("w4b_operation_job_base");
    let job: OperationJob = decode_host(&template)
        .expect("the OperationJob template must decode before it is inflated");
    assert_eq!(job.idempotency_key, "idem-w4b-0001");

    let anchor = "\"idempotency_key\":\"idem-w4b-0001\"";
    assert!(
        template.contains(anchor),
        "the template must carry the anchor the inflation replaces"
    );
    let head_len = template.len() - anchor.len();

    // The filler is the pure byte `a`, so no scanner marker can appear in a run
    // of `a` and OutputTooLarge is the only rule that can possibly match.
    let filler_len = MAX_SECRET_BOUNDARY_BYTES + 1 - head_len;
    let filler: Vec<u8> = vec![b'a'; filler_len];
    let mut payload = Vec::with_capacity(head_len + anchor.len() + filler_len);
    payload.extend_from_slice(&template.as_bytes()[..head_len]);
    payload.extend_from_slice(anchor.as_bytes());
    payload.extend_from_slice(&filler);
    payload
}

// WORK_UNIT_CASE: 932/c15_byte_decoder_rejects_first_diagnostics_canary_free
#[test]
#[allow(clippy::too_many_lines)]
fn w4b_c15_byte_decoder_rejects_first_diagnostics_canary_free() {
    // (a) ORDERING. The same wire document is used twice: first the trusted
    // fragment decodes, so a genuine value genuinely exists for it; then the
    // SAME document plus an appended secret marker is refused while it is still
    // raw bytes, with no decoder in the path at all. What this proves is that
    // the scanner refuses a payload the decoder would otherwise have accepted -
    // not that any production caller sequences them, which is out of this
    // decoder slice.
    let trusted = raw("w4b_host_event_envelope");
    let decoded: HostEventEnvelope = decode_host(&trusted)
        .expect("the host event fragment must decode, so a trusted value exists for it");
    assert_eq!(decoded.event_kind, "tool.completed");
    assert_eq!(
        inspect_secret_bytes(trusted.as_bytes()),
        Ok(()),
        "the trusted fragment must itself be scanner-clear"
    );

    let anchor_at = trusted.find(W4B_HOST_OUTPUT_TAIL).unwrap_or_else(|| {
        panic!("the trusted fragment must carry the injection anchor `{W4B_HOST_OUTPUT_TAIL}`")
    });
    // The marker is embedded after the document's LAST closing brace, so the
    // payload IS the valid document with bytes appended: the scanner sees
    // exactly the trusted wire text plus the marker, and the decoder would have
    // accepted the same fragment.
    let last_brace = trusted
        .rfind('}')
        .unwrap_or_else(|| panic!("the trusted fragment must be a JSON object"));
    assert!(
        anchor_at < last_brace,
        "the trusted fragment must really carry `{W4B_HOST_OUTPUT_TAIL}` inside the document (at \
         byte {anchor_at}), before its closing brace at byte {last_brace}, or appending a marker \
         would not extend a document the decoder had accepted"
    );
    assert_eq!(
        last_brace,
        trusted.len() - 1,
        "the trusted fragment must end at its own closing brace, or appending a marker would \
         break the document instead of extending it"
    );
    let with_marker = format!("{trusted}\nAuthorization: Bearer {}", w4b_canary());
    assert!(
        with_marker.starts_with(&trusted),
        "the marked payload must begin with the complete trusted fragment"
    );
    assert!(
        with_marker.len() > trusted.len(),
        "the marked payload must be longer than the trusted fragment, or the marker was not \
         embedded"
    );
    let marked_violation = inspect_secret_bytes(with_marker.as_bytes()).expect_err(
        "the payload with the embedded marker must be refused while it is still raw bytes, \
         before any decoder is offered it",
    );
    // The marked payload is this same document with a marker appended after its
    // closing brace, so it is exactly the trusted wire text plus the secret: the
    // decoder would have accepted the fragment, and the scanner is what refuses
    // the extension -- while the bytes are still raw, with no decoder in the path
    // at all. The decoder is never offered the marked bytes in this case.
    assert_eq!(
        marked_violation.rule,
        SecretBoundaryRule::AuthorizationHeader,
        "the embedded marker must be refused as AuthorizationHeader"
    );

    // (b) CANARY-FREE DIAGNOSTICS. The canary is assembled at runtime, so the
    // substring searched for below never appears contiguously in this source or
    // in any fixture, and no canary value is persisted as evidence anywhere.
    let canary = w4b_canary();
    assert_eq!(canary, format!("CANARY{}_2f8a41", "_DO_NOT_LEAK"));
    assert!(
        canary.len() >= 24,
        "the canary must be long enough that a leak of it would be unmistakable"
    );

    for (rule, payload) in [
        (
            SecretBoundaryRule::AuthorizationHeader,
            format!("Authorization: Bearer {canary}"),
        ),
        (
            SecretBoundaryRule::CredentialAssignment,
            format!("client_secret=\"{canary}\""),
        ),
        (
            SecretBoundaryRule::StructuredToken,
            format!("eyJ{canary}.eyJ{canary}.sig{canary}"),
        ),
    ] {
        let violation: SecretBoundaryViolation = inspect_secret_bytes(payload.as_bytes())
            .expect_err("the payload must be refused for the rule under test");
        assert_eq!(
            violation.rule, rule,
            "the payload must trip the rule under test"
        );

        let display = format!("{violation}");
        let debug = format!("{violation:?}");
        let rule_text = violation.rule.as_str();
        let error_text = inspect_secret_bytes(payload.as_bytes())
            .expect_err("re-inspecting the payload must fail again")
            .to_string();

        for (surface, rendered) in [
            ("Display", display.as_str()),
            ("Debug", debug.as_str()),
            ("as_str()", rule_text),
            ("std::error::Error", error_text.as_str()),
        ] {
            assert!(
                !rendered.contains(&canary),
                "the {surface} surface of a {rule} violation must not contain the canary value"
            );
        }

        // `Display` is pinned to the exact expected string, which is what proves
        // the violation exposes the CATEGORY and nothing else.
        assert_eq!(
            display,
            format!("secret boundary rejected content: {rule_text}"),
            "a violation must render as exactly `secret boundary rejected content: <rule>`, \
             proving it carries neither a value nor a digest of the rejected bytes"
        );
        assert!(
            debug.len() <= 96,
            "a Debug rendering that named the payload would grow with the payload, got {} bytes",
            debug.len()
        );
        assert_eq!(
            format!("{rule}"),
            rule.as_str(),
            "a rule must render as its own snake_case category"
        );
    }
}

/// The canary value, assembled at runtime from two parts that never appear
/// adjacent in this source or in any fixture, so no fixture carries it and
/// nothing persists it as evidence.
fn w4b_canary() -> String {
    format!("CANARY{}_2f8a41", "_DO_NOT_LEAK")
}

// WORK_UNIT_CASE: 932/c16_scope_policy_dependencies_visibility_unchanged
#[test]
#[allow(clippy::too_many_lines)]
fn w4b_c16_scope_policy_dependencies_visibility_unchanged() {
    // (a) DEPENDENCIES. The scope's manifest must carry exactly the crates the
    // decoders need. Presence and ABSENCE are both asserted by name against the
    // manifest's own `[dependencies]` TABLE, so a false guarantee is caught:
    // adding a crypto, regex or TOML dependency here later fails instead of
    // quietly widening the scope. The claim is deliberately scoped to eliot-types'
    // OWN DIRECT dependencies - several of these crates are present elsewhere in
    // the workspace graph, and this decoder slice neither adds nor forbids them
    // transitively.
    let manifest = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    for crate_name in [
        "blake3",
        "schemars",
        "serde",
        "serde_json",
        "thiserror",
        "time",
        "uuid",
    ] {
        assert!(
            manifest.contains(crate_name),
            "crates/eliot-types/Cargo.toml must carry the dependency `{crate_name}`"
        );
    }
    // The same presence/absence check, this time anchored on the manifest's own
    // dependency TABLE rather than a bare substring over the whole file, so a
    // crate name cannot be satisfied by a comment or a section header while a
    // real dependency entry slips past. `crates/eliot-types/Cargo.toml` declares
    // `[dependencies]` and then `[lints]`, so this is the whole table.
    let table = manifest
        .split("[dependencies]")
        .nth(1)
        .and_then(|after| after.split("[lints]").next())
        .expect(
            "crates/eliot-types/Cargo.toml must declare a [dependencies] table followed by the \
             next section",
        );
    assert!(
        table.contains("blake3.workspace = true"),
        "the [dependencies] table must really name the workspace dependencies this check reads"
    );
    // Compare the table's DEPENDENCY KEYS, not substrings of the whole file, so
    // neither a comment nor an unrelated line can satisfy a presence check or
    // trip an absence check. Every entry here is a workspace inheritance
    // (`blake3.workspace = true`), so the key is the segment before the first
    // `.` or `=`; splitting on `=` alone would keep `blake3.workspace` as the
    // key and match nothing.
    let declared = table
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with('['))
        .map(|line| {
            line.split(['=', '.'])
                .find(|part| !part.trim().is_empty())
                .unwrap_or(line)
                .trim()
        })
        .collect::<Vec<_>>();
    for crate_name in [
        "blake3",
        "schemars",
        "serde",
        "serde_json",
        "thiserror",
        "time",
        "uuid",
    ] {
        assert!(
            declared.contains(&crate_name),
            "`{crate_name}` must be a declared dependency of eliot-types, declared keys were \
             {declared:?}"
        );
    }
    for crate_name in [
        "sha2",
        "hmac",
        "ring",
        "aes-gcm",
        "chacha20poly1305",
        "regex",
        "toml",
    ] {
        assert!(
            !declared.contains(&crate_name),
            "`{crate_name}` must NOT be a direct dependency of eliot-types, declared keys were \
             {declared:?}"
        );
    }
    // The slice adds no dependency at all: the table is exactly the seven above.
    assert_eq!(
        declared.len(),
        7,
        "eliot-types must declare exactly the seven dependencies this slice relies on, found \
         {declared:?}"
    );

    // (b) VISIBILITY. `SecretBoundaryViolation` is category-only and has no
    // `Deserialize` impl, so it can never become an inbound wire type. The type
    // name occurs throughout its own file, so this is checked against the
    // DECLARED derive list on the struct itself, found by locating the struct and
    // inspecting the bytes immediately before it -- never as a file-wide absence
    // claim.
    let boundary_src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/secret_boundary.rs"
    ));
    let struct_offset = boundary_src
        .find("pub struct SecretBoundaryViolation")
        .expect("src/secret_boundary.rs must still declare `pub struct SecretBoundaryViolation`");
    let derive_block = &boundary_src[..struct_offset];
    // Anchor on the nearest `#[derive` rather than a fixed-size tail, so a longer
    // doc comment above the struct cannot push `Copy` out of the window and leave
    // the `Deserialize` absence check vacuously true.
    let derive_start = derive_block.rfind("#[derive").expect(
        "src/secret_boundary.rs must declare `SecretBoundaryViolation` behind a derive list",
    );
    let derive_list = &derive_block[derive_start..];
    assert!(
        derive_list.contains("Copy"),
        "the derive list preceding `pub struct SecretBoundaryViolation` must carry Copy, got: \
         {derive_list:?}"
    );
    assert!(
        !derive_list.contains("Deserialize"),
        "the derive list preceding `pub struct SecretBoundaryViolation` must NOT carry \
         Deserialize: it is category-only and must never become a decodable inbound type, got: \
         {derive_list:?}"
    );

    // The test module itself is not part of the crate's public surface.
    let lib_src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
    assert!(
        !lib_src.contains("serde_t03"),
        "src/lib.rs must not declare a `serde_t03` test module in its public surface"
    );
    assert!(
        !lib_src.contains("pub mod tests"),
        "src/lib.rs must not publish a tests module from the crate root"
    );

    // (c) POLICY. A `credential_provider` that is neither the current provider nor
    // the declared legacy one decodes as data and is refused by `validate`, rather
    // than being quietly replaced by an approved provider.
    let unapproved: GovernorConfig = decode_config(&raw("w4b_governor_config_unapproved_provider"))
        .expect("the unapproved-provider document decodes as data");
    assert_eq!(
        unapproved.db.surreal.credential_provider,
        CredentialProviderKind::DpapiProtectedFile,
        "the fixture must really carry the unapproved DpapiProtectedFile provider"
    );
    let Err(provider_error) = unapproved.validate() else {
        panic!("a non-current, non-legacy credential_provider must be refused by validate()");
    };
    assert!(
        matches!(
            provider_error,
            ConfigError::UnsupportedCredentialProvider { .. }
        ),
        "the refusal must be ConfigError::UnsupportedCredentialProvider, got: {provider_error:?}"
    );
    assert_eq!(
        unapproved.db.surreal.credential_provider,
        CredentialProviderKind::DpapiProtectedFile,
        "the refusal must not rewrite db.surreal.credential_provider to an approved provider"
    );

    // An empty REQUIRED field is refused by name, and nothing fabricates a value
    // to make the document validate.
    let empty_user: GovernorConfig = decode_config(&raw("w4b_governor_config_empty_surreal_user"))
        .expect("the empty-field document decodes as data");
    assert!(
        empty_user.db.surreal.user.is_empty(),
        "decode must not fabricate db.surreal.user, got {:?}",
        empty_user.db.surreal.user
    );
    let Err(empty_error) = empty_user.validate() else {
        panic!("an empty required field must be refused by validate()");
    };
    assert!(
        matches!(
            empty_error,
            ConfigError::EmptyField {
                field: "db.surreal.user"
            }
        ),
        "the refusal must be ConfigError::EmptyField naming db.surreal.user, got: {empty_error:?}"
    );

    // A supported schema version is the baseline the two refusals above are
    // measured against: neither fixture was refused for its schema.
    let baseline: GovernorConfig = decode_config(&raw("w4b_governor_config_baseline_valid"))
        .expect("the baseline document must decode");
    assert_eq!(baseline.schema_version, "1");
    assert!(
        baseline.validate().is_ok(),
        "the baseline config must pass validate(), or the two refusals above prove nothing \
         about policy"
    );

    // The same closedness, isolated: the same complete `OperationJob` document
    // decodes, and with exactly one unknown member added it is refused. The only
    // difference between the two documents is that member, so the refusal is the
    // deny and not a missing or mistyped field.
    let job_text = raw("w4b_operation_job_base");
    let job: OperationJob = decode_host(&job_text).expect("the OperationJob template must decode");
    assert_eq!(job.state, OperationJobState::Queued);
    assert_eq!(job.generation, 9);
    let tampered_job = job_text.replace("\"generation\":9", "\"generation\":9,\"w4b_unknown\":1");
    assert_ne!(
        tampered_job, job_text,
        "the injection must actually change the job document"
    );
    assert!(
        decode_host::<OperationJob>(&tampered_job).is_err(),
        "an unknown member key must be refused by OperationJob"
    );
}
