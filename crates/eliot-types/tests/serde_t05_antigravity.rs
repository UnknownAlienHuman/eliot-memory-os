//! Issue #934 (`F-DENY-T05`, child `#934` of family `T05`): the allocated
//! decoder proof for the T05 slice - `eliot-types/src/antigravity.rs` and
//! `eliot-types/src/antigravity_persistent.rs`. Writer w1 owns cases 1-8 of the
//! 16 allocated cases; writer w2 appends cases 9-16 to this same file and to the
//! same corpus.
//!
//! Fixtures are stored as RAW JSON TEXT and handed to the deserializer
//! unparsed. A `serde_json::Value` intermediate collapses a repeated object
//! member before the decoder ever sees it, so it could not prove case 5; every
//! refusal case therefore feeds raw bytes.
//!
//! The two production files are READ-ONLY here. Nothing in this file edits a
//! production declaration, and no test widens a visibility to make a name
//! reachable: every type this file names is already reachable through the
//! `eliot_types` boundary and is imported exactly as a downstream crate would
//! import it.
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
//!   - "fields affecting authority, scope, ordering, privacy or effect
//!     cannot be omitted or defaulted silently."
//! - The repaired field's own contract,
//!   `crates/eliot-types/src/antigravity.rs:717-724` - "Required on the wire:
//!   this is the observation that distinguishes a model-bound run from a merely
//!   request-authorized one, so an absent key must not decode as 'observed, and
//!   the answer was nothing'."

#![allow(clippy::expect_used)]

use eliot_types::{
    ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES, ANTIGRAVITY_PERSISTENT_MIN_FRAME_BYTES,
    ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION, AntigravityCommandContract,
    AntigravityEnablementReceipt, AntigravityFrameKind, AntigravityLiveSmokeRequest,
    AntigravityModelObservation, AntigravityModelObservationAuthority, AntigravityPersistentBounds,
    AntigravityPersistentCapabilities, AntigravityPersistentFrame,
    AntigravityPersistentLaunchContract, AntigravityPersistentLaunchReceipt, AntigravityRun,
    AntigravitySafetyReceipt,
};
// `hash_bytes_hex` and `fingerprint_hash_for` are NOT re-exported from the crate
// root (`crates/eliot-types/src/lib.rs:70-78` omits both), so they are named
// through their declaring module, which `crates/eliot-types/src/lib.rs:5`
// publishes as `pub mod antigravity_persistent`. That module path IS the existing
// exported name for them: no `pub use` was added and no `pub` was widened.
use eliot_types::antigravity_persistent::{fingerprint_hash_for, hash_bytes_hex};

/// The raw fixture corpus. Every fixture is stored as a STRING value holding its
/// wire text, because a fixture that repeats an object member - a valid JSON
/// document, but one no decoder may accept - would be rewritten by a bare
/// `{"key": {…}}` corpus: storing the text keeps both occurrences intact all the
/// way to the decoder. The malformed-by-shape bytes of cases 3-8 are stored
/// entries too, so every fixture this file decodes is named in one place.
fn corpus() -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("serde_t05_antigravity.json");
    let text = std::fs::read_to_string(&path).expect("serde_t05_antigravity.json must exist");
    serde_json::from_str(&text).expect("serde_t05_antigravity.json must be valid JSON")
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

/// The `AntigravitySafetyReceipt` (`crates/eliot-types/src/antigravity.rs`)
/// wire text. The receipt carries no version member of its own, so its boundary
/// is the derived `Deserialize` reached through the `eliot_types` boundary.
fn receipt_raw(name: &str) -> String {
    raw(name)
}

/// The `AntigravityPersistentFrame` (`crates/eliot-types/src/antigravity_persistent.rs`)
/// wire text, in the NDJSON-line form its real entrypoint consumes.
fn frame_raw(name: &str) -> String {
    raw(name)
}

fn decode_receipt<T: serde::de::DeserializeOwned>(document: &str) -> Result<T, serde_json::Error> {
    serde_json::from_str(document)
}

fn decode_frame<T: serde::de::DeserializeOwned>(document: &str) -> Result<T, serde_json::Error> {
    serde_json::from_str(document)
}

/// The outer envelope's member keys, in wire order, for the comparison that must
/// not itself decode through the type under test.
fn outer_member_keys(document: &str) -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(document)
        .expect("a stored receipt fixture must parse as a JSON document")
        .as_object()
        .expect("a stored receipt fixture must be a JSON object")
        .keys()
        .cloned()
        .collect()
}

/// The nested `model_observation` object's member keys, in wire order.
fn nested_member_keys(document: &str) -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(document)
        .expect("a stored receipt fixture must parse as a JSON document")
        .get("model_observation")
        .expect("this fixture must carry a `model_observation` member")
        .as_object()
        .expect("`model_observation` must be a JSON object in this fixture")
        .keys()
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Cases for writer w1 (issue #934, card cards/934.md).
// ---------------------------------------------------------------------------

/// The unknown member keys this file injects. They are spelled here so the
/// assertions name the exact key that must be refused rather than an anonymous
/// "an unknown member".
const W1_UNKNOWN_OUTER_MEMBER: &str = "c3_unknown_outer_member";
const W1_UNKNOWN_NESTED_MEMBER: &str = "c4_unknown_nested_member";
const W1_UNKNOWN_FRAME_KIND: &str = "c6_unknown_kind_variant";

/// The opening of the canonical receipt fixture's `model_observation` MEMBER, up
/// to and including the nested `requested_model` value. Case 7 uses it to prove
/// that its absent-key fixture differs from the canonical fixture by that member
/// and nothing else. It also pins the wire spelling of the nested
/// `requested_model` key, because `AntigravityModelObservationAuthority` has
/// exactly one variant and so is the receiver of that exact key/value pair.
const W1_MODEL_OBSERVATION_MEMBER: &str =
    "model_observation\":{\"requested_model\":\"gemini-3-pro\"";

/// Case 1: the allocation for child `#934` is exactly the two-file surface this
/// file decodes, and every type it names is reachable through the `eliot_types`
/// BOUNDARY without any visibility widening. Existence of the two files alone
/// proves nothing, so each is proved by the REFUSAL and the PRESENCE its
/// representative decoders make:
///
/// - `crates/eliot-types/src/antigravity.rs` - `AntigravitySafetyReceipt`
///   (a) decodes a current canonical document, (b) refuses an unknown outer
///   member, (c) refuses an absent `model_observation`, (d) exposes its nested
///   closed `AntigravityModelObservation` and the closed
///   `AntigravityModelObservationAuthority` variant by value, and (e) is the
///   `safety_receipt` embedded in `AntigravityRun`, which is itself reachable
///   here as a decodable type.
/// - `crates/eliot-types/src/antigravity_persistent.rs` -
///   `AntigravityPersistentFrame` (a) decodes a current frame line, (b) refuses
///   an unknown `kind` variant at its real entrypoint, and (c) shares its file
///   with the nested closed `AntigravityPersistentBounds` and the durable
///   `AntigravityPersistentLaunchReceipt`, both reachable by value. The nested
///   closed `AntigravityPersistentCapabilities` and the
///   `AntigravityPersistentLaunchContract` are w2's cases, which own those
///   types' own ingress (`from_json_str` / `from_json_slice`).
///
/// The exported names this file imports, and nothing else:
/// `AntigravityFrameKind`, `AntigravityModelObservation`,
/// `AntigravityModelObservationAuthority`, `AntigravityPersistentBounds`,
/// `AntigravityPersistentLaunchReceipt`, `AntigravityRun`,
/// `AntigravitySafetyReceipt`, `ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES`,
/// `ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION` - all re-exported by
/// `crates/eliot-types/src/lib.rs:46-78`.
/// The two fingerprint helpers are named through their module path, as stated at
/// the imports above.
// WORK_UNIT_CASE: 934/c1_allocation_complete
#[test]
#[allow(clippy::too_many_lines)]
fn c1_allocation_complete_across_the_two_in_scope_files() {
    // (a) crates/eliot-types/src/antigravity.rs - the receipt decodes.
    let receipt: AntigravitySafetyReceipt =
        decode_receipt(&receipt_raw("c1_safety_receipt_current_canonical"))
            .expect("the current canonical AntigravitySafetyReceipt fixture must decode");
    assert_eq!(
        receipt.timeout_ms, 120_000,
        "the decoded receipt must carry its own wire `timeout_ms`, not a fabricated one"
    );
    assert_eq!(
        receipt.effective_cwd, "C:/Development/Rust/projects/eliot-swarm",
        "`effective_cwd` must decode to the fixture's own path text (`PathRef` is a `String`)"
    );

    // (b) the same file refuses an unknown outer member.
    assert!(
        decode_receipt::<AntigravitySafetyReceipt>(&receipt_raw(
            "c3_safety_receipt_unknown_outer_member_refuse"
        ))
        .is_err(),
        "src/antigravity.rs: AntigravitySafetyReceipt must refuse the unknown outer member key `{W1_UNKNOWN_OUTER_MEMBER}`"
    );

    // (c) the same file refuses an absent `model_observation`: the repaired field
    // must not default into `Some`/`None` on its own.
    assert!(
        decode_receipt::<AntigravitySafetyReceipt>(&receipt_raw(
            "c7_safety_receipt_absent_model_observation_refuse"
        ))
        .is_err(),
        "src/antigravity.rs: AntigravitySafetyReceipt must refuse a document that omits `model_observation` entirely"
    );

    // (d) the file's own nested closed type and its closed control variant are
    // reachable by value through the same boundary.
    let observation: AntigravityModelObservation = decode_receipt::<AntigravitySafetyReceipt>(
        &receipt_raw("c1_safety_receipt_current_canonical"),
    )
    .expect("the canonical receipt must decode")
    .model_observation
    .expect("the canonical fixture carries a present model observation");
    assert_eq!(
        observation.authority,
        AntigravityModelObservationAuthority::CliAuthenticatedRuntimeLog,
        "the nested `authority` must decode to its own `cli_authenticated_runtime_log` variant"
    );
    assert_eq!(
        observation.requested_model, "gemini-3-pro",
        "the nested observation must carry the fixture's own requested model"
    );

    // (e) `AntigravityRun` (crates/eliot-types/src/antigravity.rs:760) embeds
    // `safety_receipt: AntigravitySafetyReceipt` at :774. The type-parameterized
    // decode below only compiles if `AntigravityRun` is reachable from this file
    // as a decodable type. An EMPTY document carries no members at all, so what it
    // proves is that the run's first declared member (`run_id`, :761) is required
    // on the wire — it does NOT exercise the struct's `deny_unknown_fields`
    // (antigravity.rs:759), because an unknown-member probe needs a populated
    // document, and that belongs to the full run fixtures. No run value is invented.
    let Err(run_error) = decode_receipt::<AntigravityRun>("{}") else {
        panic!("an empty document must not decode as an AntigravityRun");
    };
    assert!(
        run_error.to_string().contains("run_id"),
        "an empty document must be refused naming AntigravityRun's first required member, got: {run_error}"
    );

    // (a) crates/eliot-types/src/antigravity_persistent.rs - the frame decodes.
    let frame: AntigravityPersistentFrame =
        decode_frame(&frame_raw("c2_frame_response_current_canonical"))
            .expect("the current canonical AntigravityPersistentFrame line must decode");
    assert_eq!(
        frame.seq, 7,
        "the decoded frame must carry its own wire `seq`, not a fabricated one"
    );

    // (b) the same file refuses an unknown control variant at its real entrypoint.
    assert_eq!(
        AntigravityPersistentFrame::from_ndjson_line(
            &frame_raw("c6_frame_unknown_kind_variant_refuse"),
            ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES,
        ),
        Err("malformed frame".to_owned()),
        "src/antigravity_persistent.rs: AntigravityFrameKind is a closed control variant and must refuse the unknown kind `{W1_UNKNOWN_FRAME_KIND}` as `malformed frame`"
    );

    // (c) the same file's nested closed bounds and its durable launch receipt are
    // reachable by value, reached the way AntigravityPersistentFrame is reached:
    // raw stored text into the derived decoder.
    let bounds: AntigravityPersistentBounds = decode_frame(&raw("c1_persistent_bounds_canonical"))
        .expect("the AntigravityPersistentBounds document must decode");
    assert_eq!(
        bounds.max_frames, 256,
        "the nested bounds must carry the document's own `max_frames`"
    );
    assert!(
        bounds.validate().is_ok(),
        "that same bounds document must pass the existing AntigravityPersistentBounds::validate"
    );
    let launch_receipt: AntigravityPersistentLaunchReceipt =
        decode_frame(&raw("c1_persistent_launch_receipt_canonical"))
            .expect("the AntigravityPersistentLaunchReceipt document must decode");
    assert_eq!(
        launch_receipt.contract_version, ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION,
        "the durable launch receipt must carry the supported schema version"
    );
    assert!(
        launch_receipt.shell_free && launch_receipt.env_allowlisted,
        "the durable launch receipt must keep both of its own `true` effect facts"
    );
}

/// Case 2: valid current bytes are accepted and UNCHANGED. Each canonical
/// fixture this case uses IS the derived serializer's own output for that value
/// (compact, declaration member order), so decode -> re-encode -> decode must
/// move no byte. Replay identity therefore survives a full cycle: the receipt's
/// bytes, the frame's NDJSON line and the two existing fingerprint functions all
/// stay fixed for fixed input.
/// APPENDIX-P-rust-public-boundary-interfaces.md:14 - "canonical hashes use
/// normalized versioned serialization".
// WORK_UNIT_CASE: 934/c2_unchanged_valid_bytes
#[test]
#[allow(clippy::too_many_lines)]
fn c2_valid_current_bytes_round_trip_byte_stably() {
    // (a) The receipt.
    let receipt_bytes = receipt_raw("c1_safety_receipt_current_canonical");
    let receipt: AntigravitySafetyReceipt = decode_receipt(&receipt_bytes)
        .expect("the canonical AntigravitySafetyReceipt fixture must decode");
    assert!(
        receipt.shell_false && receipt.stdin_devnull && receipt.process_group_kill_on_timeout,
        "the three protected execution booleans must all decode to the fixture's own `true`"
    );
    assert_eq!(
        receipt.max_output_bytes, 262_144,
        "`max_output_bytes` must decode to the fixture's own number"
    );
    assert_eq!(
        receipt.env_fixed_vars,
        vec![
            ("AGY_CLI_DISABLE_AUTO_UPDATE".to_owned(), "1".to_owned()),
            ("AGY_CLI_HIDE_ACCOUNT_INFO".to_owned(), "1".to_owned()),
        ],
        "`env_fixed_vars` must decode to the fixture's own ordered name/value pairs"
    );
    assert_eq!(
        receipt.env_dropped_names,
        vec!["AGY_API_KEY".to_owned(), "USERPROFILE".to_owned()],
        "`env_dropped_names` must decode to the fixture's own ordered names"
    );
    let observation = receipt
        .model_observation
        .as_ref()
        .expect("the canonical fixture carries a present model observation");
    assert_eq!(
        observation.observed_model, "gemini-3-pro",
        "`observed_model` must be the fixture's own value, not a fabricated one"
    );
    assert!(
        observation.authenticated_runtime
            && observation.backend_propagation_observed
            && observation.stream_started_after_selection,
        "the three observation booleans must decode to the fixture's own `true`"
    );

    let reserialized = serde_json::to_string(&receipt)
        .expect("AntigravitySafetyReceipt must serialize back to text");
    assert_eq!(
        reserialized, receipt_bytes,
        "decode/re-encode must leave the valid receipt bytes unchanged"
    );
    let redigested: AntigravitySafetyReceipt =
        decode_receipt(&reserialized).expect("the re-serialized receipt must decode again");
    assert_eq!(
        serde_json::to_string(&redigested).expect("the redigested receipt must serialize again"),
        reserialized,
        "a second decode/re-encode cycle must not move a single byte"
    );

    // The explicit-`None` shape is equally canonical: a required-nullable field
    // that does not apply stays an explicit `null` member and still round-trips
    // byte-stably (I05-16-common-durable-fields.md:46 - "Fields that do not apply
    // remain explicit `None`; they are not silently omitted from the semantic
    // model.").
    let null_bytes = receipt_raw("c2_safety_receipt_explicit_null_canonical");
    let null_receipt: AntigravitySafetyReceipt =
        decode_receipt(&null_bytes).expect("the explicit-null receipt fixture must decode");
    assert!(
        null_receipt.model_observation.is_none(),
        "an explicit `null` model_observation must decode as None, never as an invented observation"
    );
    assert_eq!(
        serde_json::to_string(&null_receipt)
            .expect("the explicit-null receipt must serialize again"),
        null_bytes,
        "the explicit-`null` receipt must round-trip to the same bytes"
    );

    // (b) The frame. `to_ndjson_line` (antigravity_persistent.rs:330) appends the
    // NDJSON newline to the derived serializer's own line.
    let frame_bytes = frame_raw("c2_frame_response_current_canonical");
    let frame: AntigravityPersistentFrame = decode_frame(&frame_bytes)
        .expect("the canonical AntigravityPersistentFrame line must decode");
    assert_eq!(
        frame.frame_version, ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION,
        "the decoded frame must carry its own `frame_version`, equal to the supported constant"
    );
    assert_eq!(
        frame.kind,
        AntigravityFrameKind::Response,
        "`kind` must decode to the fixture's own `response` variant"
    );
    let line = frame
        .to_ndjson_line()
        .expect("a valid frame must serialize to an NDJSON line");
    assert_eq!(
        line,
        format!("{frame_bytes}\n"),
        "`to_ndjson_line` must emit the canonical frame line plus exactly one newline"
    );
    let from_line =
        AntigravityPersistentFrame::from_ndjson_line(&line, ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES)
            .expect("the re-emitted NDJSON line must decode at the real entrypoint");
    assert_eq!(
        from_line, frame,
        "frame_version, seq, kind and payload must all survive the to_ndjson_line/from_ndjson_line round trip"
    );
    assert_eq!(
        from_line.frame_version, ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION,
        "`frame_version` must survive the NDJSON round trip unchanged"
    );
    assert_eq!(
        from_line.seq, 7,
        "`seq` must survive the NDJSON round trip unchanged"
    );
    assert_eq!(
        from_line.kind,
        AntigravityFrameKind::Response,
        "`kind` must survive the NDJSON round trip unchanged"
    );
    assert_eq!(
        from_line
            .to_ndjson_line()
            .expect("the re-decoded frame must serialize to an NDJSON line again"),
        line,
        "a second to_ndjson_line cycle must not move a single byte: replay identity is stable"
    );

    // (c) The existing fingerprint functions, unchanged by this slice, are stable
    // for fixed input. They are exercised, never replaced.
    let fixed = b"eliot-antigravity-fingerprint-input";
    let digest = hash_bytes_hex(fixed);
    assert_eq!(
        digest,
        hash_bytes_hex(fixed),
        "`hash_bytes_hex` must be stable for identical bytes"
    );
    assert_eq!(
        digest.len(),
        64,
        "a blake3 hex digest is 64 characters; the fingerprint must keep that shape"
    );
    assert_eq!(
        digest, "1807249a5d3131b35ea40a2b3d9122a0936d7324768ae9312822df3b60599cd6",
        "hash_bytes_hex must keep its current BLAKE3 output for the fixed input"
    );
    assert_ne!(
        digest,
        hash_bytes_hex(b"eliot-antigravity-fingerprint-inpu"),
        "`hash_bytes_hex` must still discriminate different inputs"
    );
    let executable = "C:/tools/agy/agy.exe";
    let version = "1.12.3";
    let help = "Usage: agy [OPTIONS]";
    assert_eq!(
        fingerprint_hash_for(executable, version, help),
        "c4dda57d490ab36eed638f553ab94832affde7e9370fcc2255ee92ec8dc12379",
        "fingerprint_hash_for must keep its current output for the existing fixed input"
    );
    assert_eq!(
        fingerprint_hash_for(executable, version, help),
        fingerprint_hash_for(executable, version, help),
        "`fingerprint_hash_for` must be stable for identical (executable, version, help)"
    );
    assert_ne!(
        fingerprint_hash_for(executable, version, help),
        fingerprint_hash_for(executable, version, "Usage: agy"),
        "`fingerprint_hash_for` must still discriminate a different help text"
    );
}

/// Case 3: an unknown TOP-LEVEL (outer envelope) member is refused by the
/// receipt. The refusal fixture is the valid document of case 2 with exactly one
/// extra member appended, and the valid document without it decodes, so the
/// refusal is caused by the unknown key and not by an otherwise-broken fixture.
/// APPENDIX-P-rust-public-boundary-interfaces.md:13 - "closed control variants
/// fail when unknown".
// WORK_UNIT_CASE: 934/c3_unknown_outer_field_refused
#[test]
fn c3_unknown_protected_outer_member_refused() {
    let tampered = receipt_raw("c3_safety_receipt_unknown_outer_member_refuse");
    assert!(
        tampered.contains(W1_UNKNOWN_OUTER_MEMBER),
        "the refusal fixture must actually carry the unknown member `{W1_UNKNOWN_OUTER_MEMBER}`"
    );
    let Err(error) = decode_receipt::<AntigravitySafetyReceipt>(&tampered) else {
        panic!("an unknown OUTER member must be refused by AntigravitySafetyReceipt");
    };
    let message = error.to_string();
    assert!(
        message.contains(W1_UNKNOWN_OUTER_MEMBER),
        "the refusal must name the offending member, got: {message}"
    );
    // serde's `unknown_field` message enumerates the struct's whole expected-field
    // list, so `model_observation` DOES appear in it. The discriminating claim is
    // therefore the message's identity, not the mere absence of that name: the
    // refusal must BE the unknown-field error naming the injected member.
    assert!(
        message.starts_with(&format!("unknown field `{W1_UNKNOWN_OUTER_MEMBER}`")),
        "the refusal must be the unknown OUTER member, not the repaired absent key, got: {message}"
    );
    // Control: the same document without the unknown member decodes.
    let receipt: AntigravitySafetyReceipt =
        decode_receipt(&receipt_raw("c1_safety_receipt_current_canonical"))
            .expect("the same receipt without the unknown member must decode");
    assert_eq!(
        receipt.timeout_ms, 120_000,
        "the accepted counterpart must keep the fixture's own `timeout_ms`"
    );
}

/// Case 4: an unknown member nested inside `model_observation` is refused too.
/// The nested `AntigravityModelObservation` carries its own
/// `#[serde(deny_unknown_fields)]` (crates/eliot-types/src/antigravity.rs:730),
/// so the closedness is enforced at that depth and not merely at the envelope.
/// The fixture's OUTER key set is identical to the valid document's, which is
/// what makes the refusal the nested struct's and not the envelope's.
/// APPENDIX-P-rust-public-boundary-interfaces.md:12 - "authority, scope, effect,
/// privacy, ordering and receipt fields are never silently defaulted".
// WORK_UNIT_CASE: 934/c4_unknown_nested_field_refused
#[test]
fn c4_unknown_protected_nested_member_refused() {
    let tampered = receipt_raw("c4_safety_receipt_unknown_nested_member_refuse");
    let valid = receipt_raw("c1_safety_receipt_current_canonical");
    assert!(
        tampered.contains(W1_UNKNOWN_NESTED_MEMBER),
        "the refusal fixture must actually carry the unknown nested member `{W1_UNKNOWN_NESTED_MEMBER}`"
    );
    assert_ne!(
        tampered, valid,
        "the injection must actually change the receipt document"
    );
    let Err(error) = decode_receipt::<AntigravitySafetyReceipt>(&tampered) else {
        panic!("an unknown NESTED member must be refused by AntigravitySafetyReceipt");
    };
    let message = error.to_string();
    assert!(
        message.contains(W1_UNKNOWN_NESTED_MEMBER),
        "the refusal must name the offending nested member, got: {message}"
    );

    // Only the nested object differs: the outer envelope key set is identical, so
    // the refusal above came from the nested closed struct.
    let tampered_outer = outer_member_keys(&tampered);
    let valid_outer = outer_member_keys(&valid);
    assert_eq!(
        tampered_outer, valid_outer,
        "only the nested object may differ; the outer envelope key set must be identical"
    );
    assert!(
        !valid_outer.contains(&W1_UNKNOWN_NESTED_MEMBER.to_owned()),
        "the valid document must not carry the injected nested member"
    );
    assert!(
        nested_member_keys(&tampered).contains(&W1_UNKNOWN_NESTED_MEMBER.to_owned()),
        "the injected member must sit inside the nested observation object"
    );
    assert_eq!(
        nested_member_keys(&tampered).len(),
        7,
        "the nested observation must carry its own six members plus the unknown one"
    );
}

/// Case 5: a REPEATED member - valid JSON text, illegal on the wire - is
/// refused at the raw decode, at the control key of a frame and at two protected
/// receipt members. This is the case that requires stored text: a
/// `serde_json::Value` built in Rust collapses the repeat before the decoder
/// sees it, so the refusal could not be proved from a value.
///
/// `from_ndjson_line` maps every serde error to the single opaque class
/// `"malformed frame"` (`antigravity_persistent.rs:349`), so the frame half asserts
/// that class; the receipt halves reach the derived decoder directly and so
/// assert serde's own message, which names the repeated field.
// WORK_UNIT_CASE: 934/c5_duplicate_protected_key_refused
#[test]
fn c5_duplicate_control_identity_and_cursor_keys_refused() {
    // (a) The frame repeats `frame_version` - the frame's own version control key.
    let repeated_frame = frame_raw("c5_frame_repeated_frame_version_refuse");
    assert!(
        repeated_frame.matches("\"frame_version\"").count() == 2,
        "the refusal fixture must repeat `frame_version` exactly twice"
    );
    assert!(
        decode_frame::<AntigravityPersistentFrame>(&repeated_frame).is_err(),
        "a repeated frame_version must be refused by the raw derived decode"
    );
    assert_eq!(
        AntigravityPersistentFrame::from_ndjson_line(
            &repeated_frame,
            ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES,
        ),
        Err("malformed frame".to_owned()),
        "the real frame entrypoint must refuse a repeated frame_version as `malformed frame`"
    );
    // Control: the same frame with each member once decodes.
    let frame: AntigravityPersistentFrame =
        decode_frame(&frame_raw("c2_frame_response_current_canonical"))
            .expect("the same frame with each member once must decode");
    assert_eq!(
        frame.frame_version, ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION,
        "the accepted counterpart must keep the supported frame_version"
    );

    // The cursor is a second protected control key: keep its repeated wire
    // member raw through the real NDJSON entrypoint so the first value cannot
    // win by way of an intermediate JSON map.
    let repeated_seq = frame_raw("c5_frame_repeated_seq_refuse");
    assert_eq!(
        repeated_seq.matches("\"seq\"").count(),
        2,
        "the refusal fixture must repeat the seq key exactly twice"
    );
    assert_eq!(
        AntigravityPersistentFrame::from_ndjson_line(
            &repeated_seq,
            ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES,
        ),
        Err("malformed frame".to_owned()),
        "the real entrypoint must refuse a repeated seq key as malformed frame"
    );

    // deny_unknown_fields must be exercised at the same raw outer-frame seam.
    let unknown_outer = frame_raw("c5_frame_unknown_outer_member_refuse");
    assert!(
        unknown_outer.contains("c5_unknown_outer_member"),
        "the unknown-frame fixture must carry its injected outer member"
    );
    assert_eq!(
        AntigravityPersistentFrame::from_ndjson_line(
            &unknown_outer,
            ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES,
        ),
        Err("malformed frame".to_owned()),
        "the real entrypoint must refuse an unknown outer frame member as malformed frame"
    );

    // (b) The receipt repeats `prompt_hash_blake3` - a protected identity digest.
    let repeated_prompt = receipt_raw("c5_safety_receipt_repeated_prompt_hash_refuse");
    assert!(
        repeated_prompt.matches("\"prompt_hash_blake3\"").count() == 2,
        "the refusal fixture must repeat `prompt_hash_blake3` exactly twice"
    );
    let Err(prompt_error) = decode_receipt::<AntigravitySafetyReceipt>(&repeated_prompt) else {
        panic!("a repeated prompt_hash_blake3 must be refused by AntigravitySafetyReceipt");
    };
    let prompt_message = prompt_error.to_string();
    assert!(
        prompt_message.contains("duplicate field"),
        "the refusal must be a duplicate-member refusal, got: {prompt_message}"
    );
    assert!(
        prompt_message.contains("prompt_hash_blake3"),
        "the refusal must name the repeated field, got: {prompt_message}"
    );

    // (c) The receipt repeats `model_observation` - the protected
    // required-nullable key, twice, which is exactly the "first occurrence wins"
    // hazard that raw text refuses and a value cannot express.
    let repeated_observation = receipt_raw("c5_safety_receipt_repeated_model_observation_refuse");
    assert!(
        repeated_observation
            .matches("\"model_observation\"")
            .count()
            == 2,
        "the refusal fixture must repeat `model_observation` exactly twice"
    );
    let Err(observation_error) = decode_receipt::<AntigravitySafetyReceipt>(&repeated_observation)
    else {
        panic!("a repeated model_observation must be refused by AntigravitySafetyReceipt");
    };
    let observation_message = observation_error.to_string();
    assert!(
        observation_message.contains("duplicate field"),
        "the refusal must be a duplicate-member refusal, got: {observation_message}"
    );
    assert!(
        observation_message.contains("model_observation"),
        "the refusal must name the repeated field, got: {observation_message}"
    );
}

/// Case 6: an unknown closed control variant is refused at the real frame
/// entrypoint, `AntigravityPersistentFrame::from_ndjson_line`, and a payload
/// that does not match the declared `payload` type is exercised at the same
/// entrypoint.
///
/// MAIN IS MORE PERMISSIVE THAN THE IDEAL on the second half, and this case
/// asserts what main ACTUALLY does rather than a refusal that does not happen.
/// The declared payload type is `serde_json::Value`
/// (`crates/eliot-types/src/antigravity_persistent.rs:298`), and a JSON string IS a
/// valid `serde_json::Value`, so the string-payload document is admitted as an
/// inert, byte-bounded frame. The code this rests on is the comment at
/// `antigravity_persistent.rs:315-327` - "Eliot currently owns no payload schema for
/// any frame kind, so each retains its payload as opaque, bounded vendor JSON ...
/// No payload key or value grants session, permission, or terminal authority" -
/// together with the serialized-byte bound in `validate`. A payload's JSON TYPE
/// therefore confers no authority on this boundary, and asserting a refusal there
/// would assert something the decoder does not do.
///
/// The card's other half IS refused: an unknown `kind` string cannot become a
/// defaulted variant, because `AntigravityFrameKind` is a closed
/// `#[serde(rename_all = "snake_case")]` enum with no catch-all variant
/// (`antigravity_persistent.rs:283-290`) and `from_ndjson_line` maps that serde
/// failure to the single opaque class `"malformed frame"`
/// (`antigravity_persistent.rs:349`).
/// APPENDIX-P-rust-public-boundary-interfaces.md:13 - "closed control variants
/// fail when unknown".
// WORK_UNIT_CASE: 934/c6_unknown_tag_or_payload_refused
#[test]
fn c6_unknown_or_mismatched_tag_or_payload_refused() {
    // (a) The unknown control variant is refused as a MALFORMED frame - not
    // accepted with a defaulted kind.
    let unknown_kind = frame_raw("c6_frame_unknown_kind_variant_refuse");
    assert!(
        unknown_kind.contains(W1_UNKNOWN_FRAME_KIND),
        "the refusal fixture must actually carry the unknown kind `{W1_UNKNOWN_FRAME_KIND}`"
    );
    assert!(
        decode_frame::<AntigravityPersistentFrame>(&unknown_kind).is_err(),
        "the raw derived decode must refuse the unknown AntigravityFrameKind variant"
    );
    assert_eq!(
        AntigravityPersistentFrame::from_ndjson_line(
            &unknown_kind,
            ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES,
        ),
        Err("malformed frame".to_owned()),
        "the real frame entrypoint must refuse the unknown kind as `malformed frame`"
    );

    // (b) The wrong-typed payload, at the real entrypoint: admitted, because the
    // declared type accepts any JSON value. What is pinned here is that admission
    // grants nothing and loses nothing: the kind, the cursor and the payload's own
    // value all survive unchanged, and the frame still passes the existing
    // `validate`, including its byte bound.
    let mistyped_payload = frame_raw("c6_frame_payload_string_admitted_inert");
    let admitted = AntigravityPersistentFrame::from_ndjson_line(
        &mistyped_payload,
        ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES,
    )
    .expect("a JSON string IS a serde_json::Value, so main admits this inert payload");
    assert_eq!(
        admitted.kind,
        AntigravityFrameKind::Event,
        "the admitted frame must keep its own `event` kind, not a defaulted one"
    );
    assert_eq!(
        admitted.seq, 9,
        "the admitted frame must keep its own `seq` cursor value"
    );
    assert!(
        admitted.payload.is_string(),
        "the admitted payload must be retained as the opaque string it was on the wire"
    );
    assert!(
        admitted
            .validate(ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES)
            .is_ok(),
        "the admitted frame must pass the existing validate(), including its byte bound"
    );

    // (c) The mismatch that IS refused, at the same entrypoint: a frame whose
    // `payload` MEMBER is missing. There is no `serde(default)` and no `Option` on
    // the declared field (antigravity_persistent.rs:298), so no payload is ever
    // invented for a frame, and no frame is ever accepted without its payload
    // (APPENDIX-P-rust-public-boundary-interfaces.md:12 - "authority, scope,
    // effect, privacy, ordering and receipt fields are never silently
    // defaulted"; I05-27-...:18 for the ordering/`seq` consequence).
    let mut without_payload: serde_json::Value =
        serde_json::from_str(&frame_raw("c2_frame_response_current_canonical"))
            .expect("the canonical frame must parse before its payload member is removed");
    let removed = without_payload
        .as_object_mut()
        .expect("the canonical frame must be a JSON object")
        .remove("payload");
    assert!(
        removed.is_some(),
        "the canonical frame must really carry a `payload` member, so its removal is not vacuous"
    );
    let without_payload_text =
        serde_json::to_string(&without_payload).expect("the payload-pruned frame must re-render");
    let Err(payload_error) = decode_frame::<AntigravityPersistentFrame>(&without_payload_text)
    else {
        panic!("a frame without its `payload` member must be refused");
    };
    assert!(
        payload_error.to_string().contains("payload"),
        "the refusal must name the missing `payload`, got: {payload_error}"
    );
    assert_eq!(
        AntigravityPersistentFrame::from_ndjson_line(
            &without_payload_text,
            ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES,
        ),
        Err("malformed frame".to_owned()),
        "the real frame entrypoint must refuse a frame without its payload as `malformed frame`"
    );
}

/// Case 7 - THE KEY CASE (the repaired defect, audit 5887246875): the valid
/// receipt document with ONLY `model_observation` deleted must be REFUSED, and
/// the error must name `model_observation`.
///
/// The production field carries
/// `#[serde(deserialize_with = "deserialize_required_nullable_model_observation")]`
/// with NO `serde(default)` (crates/eliot-types/src/antigravity.rs:725), so the
/// derived visitor reports the missing field before that custom body is ever
/// consulted, and the custom body's
/// `Option::<AntigravityModelObservation>::deserialize` handles only a present
/// value or an explicit `null` (crates/eliot-types/src/antigravity.rs:694-701).
/// Had the `default` been present, an absent key would decode as `None` -
/// "observed, and the answer was nothing" - which
/// I05-27-canonical-operation-identity-and-effect-identity.md:18 forbids
/// ("fields affecting authority, scope, ordering, privacy or effect cannot be
/// omitted/defaulted silently") and which
/// APPENDIX-P-rust-public-boundary-interfaces.md:12 requires ("authority, scope,
/// effect, privacy, ordering and receipt fields are never silently defaulted").
///
/// The same document with the key PRESENT and explicitly `null` decodes as `None`,
/// which is the absent/present distinction case 7 exists to preserve
/// (I05-16-common-durable-fields.md:46).
// WORK_UNIT_CASE: 934/c7_missing_protected_meaning_refused
#[test]
fn c7_missing_model_observation_cannot_default_into_a_valid_current_value() {
    let without_key = receipt_raw("c7_safety_receipt_absent_model_observation_refuse");
    let with_key = receipt_raw("c1_safety_receipt_current_canonical");
    // Only the `model_observation` member differs between the two documents:
    // cutting the canonical fixture at that member's opening and closing it
    // reproduces the absent-key fixture's bytes exactly.
    let member = format!(",\"{W1_MODEL_OBSERVATION_MEMBER}");
    let (head, tail) = with_key.rsplit_once(&member).unwrap_or_else(|| {
        panic!("the canonical fixture must carry `{W1_MODEL_OBSERVATION_MEMBER}` as a member")
    });
    assert!(
        !tail.is_empty() && tail.ends_with('}'),
        "the split must find the member's opening and the object's closing brace"
    );
    assert_eq!(
        without_key,
        format!("{head}}}"),
        "the absent-key fixture must be the canonical fixture with only `model_observation` removed"
    );
    assert!(
        !without_key.contains("\"model_observation\""),
        "the absent-key fixture must not carry `model_observation` at all"
    );

    // THE ASSERTION: the absent key is a refusal that NAMES the field.
    let Err(error) = decode_receipt::<AntigravitySafetyReceipt>(&without_key) else {
        panic!(
            "a receipt without `model_observation` must NOT decode: it must not default to None"
        );
    };
    let message = error.to_string();
    assert!(
        message.contains("model_observation"),
        "the refusal must name `model_observation`, got: {message}"
    );
    assert!(
        message.contains("missing field"),
        "the refusal must be a missing-field refusal, got: {message}"
    );

    // The same document with the key PRESENT and explicitly null is accepted and
    // decodes to an explicit `None` - never to a fabricated observation.
    let explicit_null = receipt_raw("c7_safety_receipt_explicit_null_model_observation_accept");
    let null_receipt: AntigravitySafetyReceipt = decode_receipt(&explicit_null)
        .expect("an explicit `null` model_observation must still decode");
    assert!(
        null_receipt.model_observation.is_none(),
        "an explicit `null` must decode as an explicit `None`"
    );
    assert_eq!(
        null_receipt.timeout_ms, 120_000,
        "the accepted null-key counterpart must keep the fixture's own remaining members"
    );

    // A complete run reaches the required-nullable member through its actual
    // nested receipt. Its current canonical bytes round-trip unchanged.
    let full_run_bytes = raw("c7_run_full_model_observation_canonical");
    let full_run: AntigravityRun = decode_receipt(&full_run_bytes)
        .expect("a complete run with a full nested model observation must decode");
    assert!(
        full_run.safety_receipt.model_observation.is_some(),
        "the complete run must carry its own nested model observation"
    );
    assert_eq!(
        serde_json::to_string(&full_run).expect("the complete run must serialize again"),
        full_run_bytes,
        "the complete run with a nested model observation must round-trip byte for byte"
    );

    // The paired run fixture differs only by the nested required-nullable key.
    // Compare as JSON values to prove that no other run or receipt member moved.
    let absent_nested_run_bytes = raw("c7_run_absent_nested_model_observation_refuse");
    let mut expected_absent: serde_json::Value = serde_json::from_str(&full_run_bytes)
        .expect("the complete run fixture must parse before its nested key is removed");
    let removed = expected_absent
        .get_mut("safety_receipt")
        .and_then(serde_json::Value::as_object_mut)
        .expect("the complete run must carry a safety_receipt object")
        .remove("model_observation");
    assert!(
        removed.is_some(),
        "the complete run must really carry safety_receipt.model_observation"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&absent_nested_run_bytes)
            .expect("the absent-key run fixture must remain valid JSON text"),
        expected_absent,
        "the refusal run fixture must differ only by the nested model_observation key"
    );
    let Err(run_error) = decode_receipt::<AntigravityRun>(&absent_nested_run_bytes) else {
        panic!("a complete run without nested model_observation must be refused");
    };
    assert!(
        run_error.to_string().contains("model_observation"),
        "the nested-run refusal must name model_observation, got: {run_error}"
    );
}

/// Case 8: an unsupported frame version cannot quietly become the supported
/// constant. `AntigravityPersistentFrame::validate`
/// (crates/eliot-types/src/antigravity_persistent.rs:302) compares
/// `frame_version` against `ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION` and returns
/// exactly `"frame_version mismatch"`. Every positive frame fixture in this file
/// carries the constant's own value, so the two documents differ in that one key
/// and nothing else.
///
/// APPENDIX-P-rust-public-boundary-interfaces.md:11 - "major incompatibility fails
/// before effects; additive minor compatibility is declared explicitly".
/// I05-27-...:18 - a version that affects effect identity is never defaulted.
// WORK_UNIT_CASE: 934/c8_unsupported_version_refused
#[test]
fn c8_unsupported_or_legacy_frame_version_refused_not_defaulted() {
    // The supported value is the constant's own value, which every positive
    // frame fixture in this corpus is written against - not a hard-coded literal
    // the decoder would have to agree with by accident.
    assert_eq!(
        ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION, "1",
        "the supported persistent frame version is the constant's value"
    );
    let valid_frame = frame_raw("c2_frame_response_current_canonical");
    let legacy_frame = frame_raw("c8_frame_unsupported_version_refuse");
    assert_eq!(
        valid_frame
            .matches(ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION)
            .count(),
        1,
        "the supported frame must carry the constant's value exactly once"
    );
    assert_ne!(
        valid_frame, legacy_frame,
        "the unsupported-version fixture must actually differ from the valid frame"
    );

    // (a) At the real entrypoint: the refusal is the version mismatch, and it is
    // returned before the frame is admitted.
    let entrypoint_error = AntigravityPersistentFrame::from_ndjson_line(
        &legacy_frame,
        ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES,
    )
    .expect_err("an unsupported frame_version must be refused at the real entrypoint");
    assert_eq!(
        entrypoint_error, "frame_version mismatch",
        "the refusal must be exactly `frame_version mismatch` (antigravity_persistent.rs:304), got: {entrypoint_error}"
    );

    // (b) The same check, isolated on `validate`, for a frame that DID decode as
    // data: the version is refused by policy, not by the byte-level parse, and the
    // decoded value keeps its own unsupported string rather than being rewritten.
    let legacy: AntigravityPersistentFrame = decode_frame(&legacy_frame)
        .expect("the unsupported-version text still parses as a frame document");
    assert_eq!(
        legacy.frame_version, "2",
        "the decoded frame must carry the fixture's own unsupported version, untouched"
    );
    assert_eq!(
        legacy.validate(ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES),
        Err("frame_version mismatch".to_owned()),
        "`validate` must refuse the unsupported version with exactly `frame_version mismatch`"
    );

    // (c) Control: the supported frame passes the same check, so the refusals
    // above are the version and not an oversized or otherwise invalid frame.
    let supported: AntigravityPersistentFrame =
        decode_frame(&valid_frame).expect("the supported frame must decode");
    assert_eq!(
        supported.frame_version, ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION,
        "the supported frame must decode to its own version string"
    );
    assert!(
        supported
            .validate(ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES)
            .is_ok(),
        "the supported frame must pass validate, or the refusals above prove nothing"
    );
}

// ---------------------------------------------------------------------------
// Cases for writer w2 (issue #934, card cards/934.md), cases 9-16.
// ---------------------------------------------------------------------------

/// The declared compatibility aliases this file pins, spelled exactly as the
/// derive declares them with `#[serde(alias = "...")]`, so an assertion names
/// the alias under test instead of an anonymous "a legacy spelling".
const W2_ALIAS_ENABLEMENT_AUDIT: &str = "enabled_for_read_only_smoke";
const W2_ALIAS_ENABLEMENT_CANDIDATE: &str = "enabled_for_worktree_candidate_smoke";
const W2_ALIAS_SCOPE_AUDIT: &str = "read_only_smoke_only";
const W2_ALIAS_SCOPE_CANDIDATE: &str = "worktree_candidate_smoke_only";
const W2_ALIAS_SMOKE_MODE_AUDIT: &str = "read_only_audit";
const W2_ALIAS_SMOKE_MODE_CANDIDATE: &str = "worktree_candidate_no_apply";
const W2_ALIAS_WORKDIR_AUDIT: &str = "controller_repo_read_only";
const W2_ALIAS_WORKDIR_CANDIDATE: &str = "worktree_for_candidate_implementation";

/// The derived CANONICAL (primary) spellings of the very same variants. An
/// alias that merely decodes is worth nothing unless it decodes to the SAME
/// variant the canonical spelling names, so every alias case asserts against
/// these: each type derives `Serialize`, so a decoded alias value re-encodes to
/// its canonical spelling.
const W2_CANONICAL_ENABLEMENT_AUDIT: &str = "enabled_for_disposable_worktree_audit";
const W2_CANONICAL_ENABLEMENT_CANDIDATE: &str = "enabled_for_disposable_worktree_candidate_smoke";
const W2_CANONICAL_SCOPE_AUDIT: &str = "disposable_worktree_audit_only";
const W2_CANONICAL_SCOPE_CANDIDATE: &str = "disposable_worktree_candidate_only";
const W2_CANONICAL_SMOKE_MODE_AUDIT: &str = "disposable_worktree_audit";
const W2_CANONICAL_SMOKE_MODE_CANDIDATE: &str = "disposable_worktree_candidate_no_apply";
const W2_CANONICAL_WORKDIR_AUDIT: &str = "disposable_worktree_for_audit";
const W2_CANONICAL_WORKDIR_CANDIDATE: &str = "disposable_worktree_for_candidate_implementation";

/// The control-imitating payload member names cases 11-12 inject. They are
/// spelled once so an assertion names the exact key that must stay inert.
const W2_NESTED_MEMBER_KEY: &str = "nested";
const W2_TERMINAL_MEMBER_KEY: &str = "terminal";
const W2_APPROVED_BY_MEMBER_KEY: &str = "approved_by";

/// The frame fixtures carrying the shared control-imitating payload, one per
/// kind (case 12). These are CORPUS KEYS, read through `frame_raw`, so the
/// payload literal lives in the corpus once instead of being duplicated here.
const W2_FRAME_FIXTURES: [(&str, &str); 4] = [
    ("request", "c12_frame_request_control_payload"),
    ("response", "c12_frame_response_control_payload"),
    ("event", "c12_frame_event_control_payload"),
    ("error", "c12_frame_error_control_payload"),
];

/// The prompt-hash digest the case-10 fixtures carry: a stable, non-secret
/// value, so the control's assertion names the fixture's own digest.
const W2_PROMPT_HASH_FIXTURE: &str =
    "2020202020202020202020202020202020202020202020202020202020202020";

/// The pre-parse refusals for the stored boundary pair, which sit one byte apart
/// at their own explicit 512-byte bound.
const W2_NDJSON_OVERSIZED_STORED: &str = "ndjson line oversized 512 > 511";
const W2_NDJSON_OVERSIZED_STORED_OVER: &str = "ndjson line oversized 513 > 512";

/// The pre-parse refusal for a line exactly one byte over the production bound.
/// Derived from `ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES` (`65_536`) below.
const W2_NDJSON_OVERSIZED_AT: &str = "ndjson line oversized 65537 > 65536";

/// The exact launch-policy refusals case 16 pins
/// (antigravity_persistent.rs:204-205 and :155-156).
const W2_SHELL_REFUSAL: &str = "persistent launch must be shell-free (shell=false)";
const W2_TOTAL_BELOW_FRAME_REFUSAL: &str = "max_total_bytes must be >= max_frame_bytes";

/// The re-serialized byte length of a frame, for case 14's `validate` refusal.
/// `validate` measures exactly this (antigravity_persistent.rs:306-307), so the
/// assertion names the real serialized length instead of a guessed literal.
fn w2_serialized_len(frame: &AntigravityPersistentFrame) -> usize {
    serde_json::to_vec(frame)
        .expect("a decoded frame must re-serialize for the byte-bound check")
        .len()
}

/// Case 9: the DECLARED compatibility aliases decode, on real carriers, to the
/// very variants their canonical spellings name. `#[serde(alias = "...")]`
/// (antigravity.rs:179-181, :192-194, :252-253, :572-573) admits a legacy wire
/// spelling for a closed control variant; it does NOT admit a new variant, and
/// it never silently defaults an unknown spelling. So an alias is an additive
/// MINOR compatibility that is declared explicitly, on the same closed variant
/// the canonical spelling names.
/// APPENDIX-P-rust-public-boundary-interfaces.md:11 - "additive minor
/// compatibility is declared explicitly".
// WORK_UNIT_CASE: 934/c9_declared_compatibility_aliases
#[test]
#[allow(clippy::too_many_lines)]
fn c9_declared_compatibility_aliases_decode_to_their_canonical_variants() {
    // (a) AntigravityEnablementState and AntigravityEnablementScope, on the real
    // `AntigravityEnablementReceipt` carrier.
    let audit_text = raw("c9_enablement_state_audit_alias");
    assert!(
        audit_text.contains(W2_ALIAS_ENABLEMENT_AUDIT),
        "the fixture must actually carry the enablement-state alias under test"
    );
    assert!(
        audit_text.contains(W2_ALIAS_SCOPE_AUDIT),
        "the fixture must actually carry the scope alias under test"
    );
    let audit_alias: AntigravityEnablementReceipt =
        decode_receipt(&audit_text).expect("the `enabled_for_read_only_smoke` alias must decode");
    assert_eq!(
        serde_json::to_value(audit_alias.requested_state)
            .expect("the aliased state must re-encode"),
        serde_json::json!(W2_CANONICAL_ENABLEMENT_AUDIT),
        "the audit alias must decode to the variant the CANONICAL spelling `enabled_for_disposable_worktree_audit` names"
    );
    assert_eq!(
        serde_json::to_value(audit_alias.approval_scope).expect("the aliased scope must re-encode"),
        serde_json::json!(W2_CANONICAL_SCOPE_AUDIT),
        "the `read_only_smoke_only` scope alias must decode to the variant the CANONICAL spelling names"
    );
    // The carrier's remaining protected members survive the alias decode: the
    // alias widened nothing and defaulted nothing.
    assert_eq!(
        serde_json::to_value(audit_alias.previous_state)
            .expect("the previous state must re-encode"),
        serde_json::json!("ready_disabled"),
        "the aliased document must keep its own previous state"
    );
    assert!(
        audit_alias.expires_at.is_none(),
        "an explicit `null` expires_at must stay an explicit None, never an invented deadline"
    );
    assert_eq!(
        audit_alias.reasons,
        vec!["c9 alias carrier for the audit grant".to_owned()],
        "the alias decode must keep the document's own reason list"
    );

    let candidate_text = raw("c9_enablement_state_candidate_alias");
    assert!(
        candidate_text.contains(W2_ALIAS_ENABLEMENT_CANDIDATE)
            && candidate_text.contains(W2_ALIAS_SCOPE_CANDIDATE),
        "the fixture must actually carry both candidate aliases under test"
    );
    let candidate_alias: AntigravityEnablementReceipt = decode_receipt(&candidate_text)
        .expect("the `enabled_for_worktree_candidate_smoke` alias must decode");
    assert_eq!(
        serde_json::to_value(candidate_alias.requested_state)
            .expect("the aliased state must re-encode"),
        serde_json::json!(W2_CANONICAL_ENABLEMENT_CANDIDATE),
        "the candidate alias must decode to the variant the CANONICAL spelling names"
    );
    assert_eq!(
        serde_json::to_value(candidate_alias.approval_scope)
            .expect("the aliased scope must re-encode"),
        serde_json::json!(W2_CANONICAL_SCOPE_CANDIDATE),
        "the `worktree_candidate_smoke_only` scope alias must decode to the variant the CANONICAL spelling names"
    );

    // (b) AntigravityLiveSmokeMode's `read_only_audit` alias, on the real
    // `AntigravityLiveSmokeRequest` carrier. `ProjectId`/`WorkLeaseId` are
    // `#[serde(transparent)]` newtypes over a `Uuid` (ids.rs:7-23), so this
    // fixture's refs are real UUID text and the decode below is a real decode -
    // a non-UUID ref would be refused by the Uuid parse and prove nothing about
    // the alias.
    let smoke_text = raw("c9_live_smoke_request_audit_alias");
    assert!(
        smoke_text.contains(W2_ALIAS_SMOKE_MODE_AUDIT),
        "the fixture must actually carry the live-smoke mode alias under test"
    );
    let smoke: AntigravityLiveSmokeRequest = decode_receipt(&smoke_text)
        .expect("the `read_only_audit` alias must decode on AntigravityLiveSmokeRequest");
    assert_eq!(
        serde_json::to_value(smoke.mode).expect("the aliased mode must re-encode"),
        serde_json::json!(W2_CANONICAL_SMOKE_MODE_AUDIT),
        "the `read_only_audit` mode alias must decode to DisposableWorktreeAudit, re-encoding to the CANONICAL spelling"
    );
    assert!(
        smoke.worktree_lease_ref.is_none(),
        "an explicit `null` worktree_lease_ref must stay an explicit None, never an invented lease"
    );
    assert_eq!(
        smoke.expected_marker, "c9-marker",
        "the alias decode must keep the request's own expected marker"
    );

    let candidate_smoke_text = raw("c9_live_smoke_request_candidate_alias");
    assert!(
        candidate_smoke_text.contains(W2_ALIAS_SMOKE_MODE_CANDIDATE),
        "the candidate request fixture must carry the retained live-smoke alias"
    );
    let candidate_smoke: AntigravityLiveSmokeRequest = decode_receipt(&candidate_smoke_text)
        .expect("the worktree_candidate_no_apply alias must decode on the live-smoke request");
    assert_eq!(
        serde_json::to_value(candidate_smoke.mode).expect("the candidate mode must re-encode"),
        serde_json::json!(W2_CANONICAL_SMOKE_MODE_CANDIDATE),
        "the candidate live-smoke alias must re-encode to its declared canonical spelling"
    );

    // (c) AntigravityWorkdirPolicy's `controller_repo_read_only` alias, nested
    // inside the real `AntigravityCommandContract` carrier, whose nested closed
    // structs keep their `deny_unknown_fields`, so the alias really is admitted
    // at that depth.
    let contract_text = raw("c9_command_contract_workdir_audit_alias");
    assert!(
        contract_text.contains(W2_ALIAS_WORKDIR_AUDIT),
        "the fixture must actually carry the workdir-policy alias under test"
    );
    let contract: AntigravityCommandContract = decode_receipt(&contract_text)
        .expect("the `controller_repo_read_only` alias must decode on AntigravityCommandContract");
    assert_eq!(
        serde_json::to_value(contract.workdir_policy).expect("the policy must re-encode"),
        serde_json::json!(W2_CANONICAL_WORKDIR_AUDIT),
        "the aliased workdir policy must re-encode to the CANONICAL spelling `disposable_worktree_for_audit`"
    );
    assert!(
        contract.dangerous_flags_forbidden && contract.json_output_required,
        "the aliased contract must keep both of its own `true` effect facts"
    );

    let candidate_contract_text = raw("c9_command_contract_workdir_candidate_alias");
    assert!(
        candidate_contract_text.contains(W2_ALIAS_WORKDIR_CANDIDATE),
        "the candidate contract fixture must carry the retained workdir-policy alias"
    );
    let candidate_contract: AntigravityCommandContract = decode_receipt(&candidate_contract_text)
        .expect("the candidate workdir alias must decode on the command contract");
    assert_eq!(
        serde_json::to_value(candidate_contract.workdir_policy)
            .expect("the candidate workdir policy must re-encode"),
        serde_json::json!(W2_CANONICAL_WORKDIR_CANDIDATE),
        "the candidate workdir alias must re-encode to its declared canonical spelling"
    );

    // (d) The alias is DECLARED and CLOSED: an UNDECLARED spelling of the very
    // same member is still refused, so an alias never turns a closed control
    // variant into an open string. `AntigravityEnablementState` has no catch-all
    // variant, and no alias widens the carrier's `deny_unknown_fields`.
    let unknown_state = audit_text.replace(
        &format!("\"requested_state\":\"{W2_ALIAS_ENABLEMENT_AUDIT}\""),
        "\"requested_state\":\"c9_unknown_enablement_state\"",
    );
    assert_ne!(
        unknown_state, audit_text,
        "the unknown-state injection must actually change the document"
    );
    assert!(
        decode_receipt::<AntigravityEnablementReceipt>(&unknown_state).is_err(),
        "an UNDECLARED enablement-state spelling must still be refused: an alias is not an open string"
    );
}

/// Case 10: absent IDENTITY meaning is refused. `prompt_hash_blake3` is the
/// protected replay-identity digest (antigravity.rs:708) and carries no
/// `serde(default)` and no `Option`, so a document that omits it cannot decode
/// as "prompt hash: nothing". This is the absent-key rule case 7 proves for
/// `model_observation`, applied to the other protected member, and it is what
/// stops a replay identity from being silently defaulted.
/// APPENDIX-P-rust-public-boundary-interfaces.md:12 - "authority, scope, effect,
/// privacy, ordering and receipt fields are never silently defaulted";
/// I05-27-...:18 - an identity-affecting field cannot be omitted/defaulted.
// WORK_UNIT_CASE: 934/c10_absent_identity_refused
#[test]
fn c10_absent_replay_identity_prompt_hash_refused() {
    // Control: the same receipt WITH the digest decodes and keeps its own value.
    let current = receipt_raw("c10_safety_receipt_current_canonical");
    let receipt: AntigravitySafetyReceipt = decode_receipt(&current)
        .expect("the current canonical AntigravitySafetyReceipt fixture must decode");
    assert_eq!(
        receipt.prompt_hash_blake3, W2_PROMPT_HASH_FIXTURE,
        "the decoded receipt must keep the fixture's own prompt-hash digest"
    );

    // The refusal fixture is the canonical document with ONLY that member
    // removed, so the refusal below can only be caused by that member.
    let absent = receipt_raw("c10_safety_receipt_absent_prompt_hash_refuse");
    assert!(
        !absent.contains("prompt_hash_blake3"),
        "the refusal fixture must NOT carry the prompt-hash member at all"
    );
    assert_eq!(
        outer_member_keys(&absent).len(),
        outer_member_keys(&current).len() - 1,
        "the refusal fixture must be the canonical document with exactly one member removed"
    );

    // THE ASSERTION: the absent identity member is a refusal that NAMES it.
    let Err(error) = decode_receipt::<AntigravitySafetyReceipt>(&absent) else {
        panic!(
            "a receipt without `prompt_hash_blake3` must NOT decode: replay identity cannot be defaulted"
        );
    };
    let message = error.to_string();
    assert!(
        message.contains("prompt_hash_blake3"),
        "the refusal must name `prompt_hash_blake3`, got: {message}"
    );
    assert!(
        message.contains("missing field"),
        "the refusal must be a missing-field refusal, got: {message}"
    );

    // Control: an EXPLICIT `null` model_observation - the OTHER required-nullable
    // member - still decodes alongside a present digest. So the refusal above is
    // the ABSENT identity member and not a document this decoder rejects
    // wholesale.
    let null_observation: AntigravitySafetyReceipt = decode_receipt(&receipt_raw(
        "c10_safety_receipt_explicit_null_observation_canonical",
    ))
    .expect("an explicit `null` model_observation with a present digest must decode");
    assert!(
        null_observation.model_observation.is_none(),
        "an explicit `null` model_observation must decode as an explicit None"
    );
    assert_eq!(
        null_observation.prompt_hash_blake3, W2_PROMPT_HASH_FIXTURE,
        "the accepted null-observation counterpart must keep the same digest"
    );
}

/// Case 11: an OPAQUE payload whose members IMITATE control keys is admitted as
/// inert data and grants nothing. `payload` is declared `serde_json::Value`
/// (`antigravity_persistent.rs:298`), so the frame keeps the payload verbatim; what
/// this case pins is that a payload member named like an authority key is just a
/// member of an opaque blob. NOTHING on the frame's own typed surface
/// (`frame_version`, `seq`, `kind`) is derived from the payload, so the imitated
/// `terminal` / `authority` / `session_id` names cannot become frame state.
///
/// PAYLOAD COMPARISON IS A VALUE COMPARISON, NEVER A RE-SERIALIZED-TEXT
/// COMPARISON: `serde_json::Map` is a `BTreeMap` in this workspace (the
/// `preserve_order` feature is NOT enabled - see
/// `crates/eliot-types/src/strict_json.rs:3-8`), so a payload decoded into a
/// `Value` comes back with its members SORTED and any re-serialized text differs
/// from the stored wire text even though the value is identical.
// WORK_UNIT_CASE: 934/c11_payload_control_keys_are_inert_data
#[test]
fn c11_opaque_payload_imitating_control_keys_grants_no_authority() {
    let line = frame_raw("c11_frame_request_control_key_payload");
    let frame =
        AntigravityPersistentFrame::from_ndjson_line(&line, ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES)
            .expect("a control-imitating payload is still a valid opaque frame line");

    // The frame's own typed control surface carries ONLY the declared members;
    // the payload cannot contribute one of them.
    assert_eq!(
        frame.kind,
        AntigravityFrameKind::Request,
        "the frame keeps its own `request` kind"
    );
    assert_eq!(frame.seq, 21, "the frame keeps its own `seq` cursor");
    assert_eq!(
        frame.frame_version, ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION,
        "the frame keeps the supported frame_version"
    );

    // The payload is retained as the VALUE that was on the wire, member for
    // member. This is the correct form of the claim on this boundary: comparing
    // re-serialized payload TEXT against the stored wire text would be FALSE for
    // any payload whose wire member order is not already sorted.
    assert_eq!(
        frame.payload,
        serde_json::json!({
            "session_id": "c11_payload_session_id",
            "permission": "c11_payload_permission",
            "authority": "granted",
            "nested": {"terminal": true, "approved_by": "c11_payload_nested"},
        }),
        "the control-imitating payload must be retained as its own opaque VALUE, member for member"
    );

    // The imitated control names live ONLY inside the opaque payload; none of
    // them is a member of the frame itself.
    let outer = outer_member_keys(&line);
    for imitated in [
        W2_NESTED_MEMBER_KEY,
        W2_TERMINAL_MEMBER_KEY,
        W2_APPROVED_BY_MEMBER_KEY,
    ] {
        assert!(
            !outer.contains(&imitated.to_owned()),
            "the imitated control member `{imitated}` must NOT be a member of the frame itself"
        );
    }

    // A payload that CLAIMS terminal authority still passes the same validate:
    // admission grants nothing and denies nothing.
    assert!(
        frame
            .validate(ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES)
            .is_ok(),
        "an inert control-imitating payload must pass the same bounded validate as any payload"
    );

    // The nested payload object survives as a VALUE too (same members, possibly
    // sorted member order), which is the honest form of the nested round-trip
    // claim on this boundary.
    let nested = frame
        .payload
        .get(W2_NESTED_MEMBER_KEY)
        .and_then(serde_json::Value::as_object)
        .expect("the payload must retain its nested object");
    assert_eq!(
        nested.get(W2_TERMINAL_MEMBER_KEY),
        Some(&serde_json::Value::Bool(true)),
        "the nested `terminal` claim must be retained as inert data, never promoted to frame state"
    );
    assert_eq!(
        nested.get(W2_APPROVED_BY_MEMBER_KEY),
        Some(&serde_json::Value::String("c11_payload_nested".to_owned())),
        "the nested `approved_by` claim must stay inert payload data too"
    );
}

/// Case 12: ALL FOUR frame kinds retain a control-imitating payload as inert
/// data. `AntigravityFrameKind` is a closed enum, and `validate`'s per-kind
/// disposition comment (antigravity_persistent.rs:315-327) treats every kind
/// identically - "Request/Response/Event/Error: retain as inert data" - so no
/// kind is privileged by a payload claiming authority, and none is refused for
/// one either. Each fixture is bounded and passes the same `validate`.
///
/// Payload comparisons are VALUE comparisons for the same sorted-key
/// `BTreeMap` reason as case 11.
// WORK_UNIT_CASE: 934/c12_every_kind_retains_control_keys_inertly
#[test]
fn c12_all_four_kinds_retain_control_imitating_payloads_as_inert_data() {
    // The shared control-imitating payload, stored once in the corpus.
    let control_payload =
        serde_json::json!({"status": "completed", "authority": "granted", "terminal": true});
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&raw("c12_payload_control_keys"))
            .expect("the shared control-imitating payload fixture must parse"),
        control_payload,
        "the shared control-imitating payload must be the stored VALUE, not its re-serialized text"
    );

    // Every kind, with its own frame fixture carrying that payload. The loop is
    // over a fixed four-element table, so it is deterministic and bounded.
    for (kind_name, fixture) in W2_FRAME_FIXTURES {
        let line = frame_raw(fixture);
        let frame = AntigravityPersistentFrame::from_ndjson_line(
            &line,
            ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES,
        )
        .unwrap_or_else(|e| {
            panic!("the {kind_name} control-imitating frame must be admitted: {e}")
        });
        assert_eq!(
            serde_json::to_value(frame.kind).expect("the kind must re-encode"),
            serde_json::json!(kind_name),
            "the `{kind_name}` frame must keep its own kind variant"
        );
        assert_eq!(
            frame.payload, control_payload,
            "the `{kind_name}` payload claiming `authority`/`terminal` must stay inert data"
        );
        assert!(
            frame
                .validate(ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES)
                .is_ok(),
            "the `{kind_name}` frame must pass the same bounded validate as any payload"
        );
    }
}

/// Case 13: the DECODE DECISION rests on two pieces of production code, pinned
/// here by their own text, read from the corpus as stored source fragments. This
/// is the contract pin: the comments and the pre-parse byte check it quotes are
/// the exact text in `crates/eliot-types/src/antigravity_persistent.rs`. Reading
/// them from the corpus means a change to production wording fails HERE, in the
/// test that cites it, instead of silently drifting from the comment it claims
/// to pin.
///
/// The fragments are Rust SOURCE text, not wire text, which is why they are
/// their own corpus entries and are read with `raw` rather than decoded into a
/// typed value.
// WORK_UNIT_CASE: 934/c13_decode_disposition_documented
#[test]
fn c13_the_disposition_and_pre_parse_check_the_decode_decision_rests_on_are_pinned() {
    // (a) The per-kind disposition comment: every kind retains its payload as
    // opaque bounded vendor JSON, and no payload key or value grants session,
    // permission, or terminal authority.
    let disposition = raw("c13_disposition_block");
    for required in [
        "Explicit per-kind payload disposition",
        "Request: retain as inert data",
        "Response: retain as inert data",
        "Event: retain as inert data",
        "Error: retain as inert data",
        "No payload key or value grants session, permission, or terminal",
        "inert data",
        "from_ndjson_line separately bounds raw-line bytes before",
    ] {
        assert!(
            disposition.contains(required),
            "the pinned disposition comment must still carry `{required}`"
        );
    }

    // (b) The pre-parse byte check `from_ndjson_line` applies to the RAW line
    // bytes before parsing - the very check case 14 lands a line exactly on.
    let pre_parse = raw("c13_pre_parse_byte_check");
    assert!(
        pre_parse.contains("if line.len() > max_frame_bytes"),
        "the pinned pre-parse check must still compare the RAW line length before parsing"
    );
    assert!(
        pre_parse.contains("ndjson line oversized"),
        "the pinned pre-parse check must still emit the `ndjson line oversized` refusal"
    );

    // (c) The claim cases 11, 12 and 15 make is exactly the one this comment
    // makes: admission is inert, and the byte bound is enforced pre-parse. The
    // comment is the contract; the value comparisons in those cases are the proof.
    assert!(
        disposition.contains("Cumulative stream bounds and acquisition deadlines belong"),
        "the disposition must continue to place cumulative stream bounds and acquisition deadlines with their upstream owners"
    );
}

/// Case 14: the PRE-PARSE byte bound, landed EXACTLY on it and one byte over,
/// plus the bounds validators' declared minimum and maximum. `from_ndjson_line`
/// checks `line.len() > max_frame_bytes` on the RAW line bytes BEFORE parsing
/// (antigravity_persistent.rs:337-344). At EXACTLY the bound, `65536 > 65536` is
/// FALSE, so the frame is ADMITTED; one byte over it is refused with the exact
/// `ndjson line oversized 65537 > 65536`. That `>` - not `>=` - is the boundary
/// this case pins, and it is a strict-inequality check, so the at-bound case must
/// be asserted as an ADMISSION.
///
/// The two boundary lines are BUILT at runtime by repeating a bounded filler
/// until the serialized line is exactly `ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES`
/// long, so the "exactly on the bound" claim is derived from the production
/// constant and cannot drift from it. No 65 KB literal is stored anywhere.
// WORK_UNIT_CASE: 934/c14_pre_parse_byte_bound_exact_and_over
#[test]
#[allow(clippy::too_many_lines)]
fn c14_pre_parse_byte_bound_admits_at_bound_and_refuses_one_over() {
    let bound = ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES;

    // The canonical event frame with an empty `blob` payload; its length is the
    // fixed overhead the filler must make up.
    let skeleton =
        "{\"frame_version\":\"1\",\"seq\":42,\"kind\":\"event\",\"payload\":{\"blob\":\"\"}}";
    let skeleton_len = skeleton.len();
    // Split so the filler lands INSIDE the blob string: `prefix` ends after
    // `"blob":"` and `suffix` is the blob's closing quote plus the two braces.
    let prefix = &skeleton[..skeleton.len() - 3];
    let suffix = &skeleton[skeleton.len() - 3..];
    assert_eq!(
        suffix, "\"}}",
        "the split must leave the blob close quote and both braces"
    );
    assert!(
        prefix.ends_with("\"blob\":\""),
        "the split must end just INSIDE the blob string, at its opening quote"
    );
    let at_bound = format!("{prefix}{}{suffix}", "c".repeat(bound - skeleton_len));
    let one_over = format!("{prefix}{}{suffix}", "c".repeat(bound + 1 - skeleton_len));
    assert_eq!(
        at_bound.len(),
        bound,
        "the at-bound line must be EXACTLY ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES long"
    );
    assert_eq!(
        one_over.len(),
        bound + 1,
        "the one-over line must be exactly one byte longer than the bound"
    );

    // (a) EXACTLY on the bound: `line.len() > max_frame_bytes` is `>`, so at the
    // bound the line is ADMITTED. A `>=` here would refuse a frame the bound
    // admits, and that off-by-one is what this case exists to prevent.
    let at_bound_frame = AntigravityPersistentFrame::from_ndjson_line(&at_bound, bound)
        .expect("a line EXACTLY at the pre-parse byte bound must be ADMITTED, not refused");
    assert_eq!(
        at_bound_frame.seq, 42,
        "the admitted at-bound frame keeps its own cursor"
    );
    assert_eq!(
        at_bound_frame.kind,
        AntigravityFrameKind::Event,
        "the admitted at-bound frame keeps its own kind"
    );
    assert_eq!(
        at_bound_frame
            .payload
            .get("blob")
            .and_then(serde_json::Value::as_str)
            .map(str::len),
        Some(bound - skeleton_len),
        "the admitted at-bound frame keeps its whole bounded payload"
    );

    // (b) The same exclusive-bound fact on the STORED pair, at their own small
    // explicit bound. These two fixtures are the same frame whose blob differs by
    // exactly one `c`, so at a 512-byte bound the shorter line is ADMITTED and the
    // longer is refused - and at 511 BOTH are refused, which isolates the refusal
    // as the raw-line byte bound rather than a property of either payload.
    let stored_at = frame_raw("c14_line_exactly_at_bound");
    let stored_over = frame_raw("c14_line_one_byte_over_bound");
    assert_eq!(
        stored_over.len(),
        stored_at.len() + 1,
        "the two stored boundary lines must differ by exactly one byte"
    );
    assert!(
        AntigravityPersistentFrame::from_ndjson_line(&stored_at, 512).is_ok(),
        "a stored line EXACTLY at its own 512-byte bound must be ADMITTED"
    );
    assert_eq!(
        AntigravityPersistentFrame::from_ndjson_line(&stored_at, 511),
        Err(W2_NDJSON_OVERSIZED_STORED.to_owned()),
        "one byte BELOW the stored line's own length must refuse it by the pre-parse check"
    );
    assert_eq!(
        AntigravityPersistentFrame::from_ndjson_line(&stored_over, 512),
        Err(W2_NDJSON_OVERSIZED_STORED_OVER.to_owned()),
        "the stored one-byte-over line must be refused at the stored 512-byte bound"
    );

    // (c) ONE BYTE over the PRODUCTION bound: refused by the pre-parse check,
    // before any parsing, with the exact refusal naming the two real lengths.
    assert_eq!(
        AntigravityPersistentFrame::from_ndjson_line(&one_over, bound),
        Err(W2_NDJSON_OVERSIZED_AT.to_owned()),
        "a line one byte over the pre-parse bound must be refused as `ndjson line oversized 65537 > 65536`"
    );
    // The refusal names the lengths the check actually measured, so it is the
    // pre-parse byte check and not some later parse failure. This inspects the
    // error the ENTRYPOINT actually returned, not a locally written constant.
    let over_bound_refusal = AntigravityPersistentFrame::from_ndjson_line(&one_over, bound)
        .expect_err("a line one byte over the pre-parse bound must be refused before any parsing");
    assert!(
        over_bound_refusal.starts_with("ndjson line oversized"),
        "the over-bound refusal must be the pre-parse byte refusal, not a parse refusal, got: {over_bound_refusal}"
    );
    assert!(
        !over_bound_refusal.contains("malformed"),
        "the over-bound refusal must be the pre-parse byte refusal, not a parse refusal, got: {over_bound_refusal}"
    );

    // (d) The STORED over-bound frame fixture is under the PRODUCTION bound and
    // is therefore admitted as opaque data: what the bound refuses is a size
    // violation, not a payload's content.
    let over_stored = AntigravityPersistentFrame::from_ndjson_line(
        &frame_raw("c14_frame_over_serialized_bound_refuse"),
        ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES,
    )
    .expect("the stored over-bound fixture is under the production byte bound, so it is admitted");
    assert!(
        over_stored
            .validate(ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES)
            .is_ok(),
        "the stored over-bound fixture, admitted under the production bound, must still pass validate"
    );

    // (e) The SERIALIZED-frame byte bound is a separate check, inside `validate`
    // (antigravity_persistent.rs:306-314). The same frame that passes at the
    // production bound is refused at a tighter bound, with the refusal naming its
    // real re-serialized length.
    let oversized: AntigravityPersistentFrame =
        decode_frame(&frame_raw("c14_frame_over_serialized_bound_refuse"))
            .expect("the over-bound frame must still parse as data");
    assert_eq!(
        oversized.validate(ANTIGRAVITY_PERSISTENT_MIN_FRAME_BYTES),
        Err(format!(
            "frame oversized {} > {}",
            w2_serialized_len(&oversized),
            ANTIGRAVITY_PERSISTENT_MIN_FRAME_BYTES
        )),
        "a frame whose serialized form exceeds a tight bound must be refused by validate, naming its serialized length"
    );

    // (f) A 200-deep nested payload is refused: `serde_json`'s recursion limit is
    // 128, so the refusal comes from the parse and surfaces at the real
    // entrypoint as the single opaque class `malformed frame`. The raw line is
    // only 456 bytes - well under the byte bound - which is what makes this a
    // depth refusal rather than another byte-bound refusal.
    let nested = frame_raw("c14_frame_nested_200_deep_refuse");
    assert_eq!(
        nested.matches('[').count(),
        200,
        "the refusal fixture must really carry 200 levels of nesting"
    );
    assert!(
        nested.len() < ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES,
        "the nested fixture must be under the byte bound, so its refusal cannot be the byte check"
    );
    assert_eq!(
        AntigravityPersistentFrame::from_ndjson_line(
            &nested,
            ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES,
        ),
        Err("malformed frame".to_owned()),
        "a 200-deep nested payload must be refused as `malformed frame` by the recursion limit"
    );

    // (g) An embedded NUL escape in a payload is admitted and retained as its
    // own single-NUL string: a valid JSON escape, not a truncation or a refusal.
    let nul = AntigravityPersistentFrame::from_ndjson_line(
        &frame_raw("c14_frame_embedded_nul_escape_accept"),
        ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES,
    )
    .expect("an embedded NUL escape is valid JSON and must be admitted as opaque data");
    assert_eq!(
        nul.payload,
        serde_json::json!("\u{0}"),
        "the admitted NUL payload must be retained as its own single-NUL VALUE"
    );

    // (h) The bounds validators' declared minimum and maximum both PASS: every
    // closed range here is inclusive at BOTH ends, so neither edge is refused.
    let min_bounds: AntigravityPersistentBounds =
        decode_receipt(&raw("c14_bounds_at_declared_minimum_canonical"))
            .expect("the declared-minimum bounds document must decode");
    assert!(
        min_bounds.validate().is_ok(),
        "the declared-minimum bounds must pass validate: the range is inclusive at its lower edge"
    );
    let max_bounds: AntigravityPersistentBounds =
        decode_receipt(&raw("c14_bounds_at_declared_maximum_canonical"))
            .expect("the declared-maximum bounds document must decode");
    assert!(
        max_bounds.validate().is_ok(),
        "the declared-maximum bounds must pass validate: the range is inclusive at its upper edge"
    );
}

/// Case 15: a PROVIDER SELF-REPORT - a payload that CLAIMS `verified: true`,
/// `caller_approved: true` and `declared_status: "completed"` - is retained as
/// opaque data and is NOT promoted to any frame fact. This is case 11/12's rule
/// in its sharpest form: the provider's own claim is data, not authority.
/// Nothing on `AntigravityPersistentFrame` reads it, so the frame keeps only
/// its declared four members and its own `kind`/`seq`/`frame_version`.
///
/// Both fixtures are compared as VALUES (sorted-key `BTreeMap`), never as
/// re-serialized text.
// WORK_UNIT_CASE: 934/c15_provider_self_report_is_inert_data
#[test]
fn c15_provider_self_report_claims_are_retained_as_inert_data_only() {
    for (kind, fixture) in [
        ("response", "c15_frame_response_provider_self_report"),
        ("error", "c15_frame_error_provider_self_report"),
    ] {
        let line = frame_raw(fixture);
        let frame = AntigravityPersistentFrame::from_ndjson_line(
            &line,
            ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES,
        )
        .unwrap_or_else(|e| panic!("the {kind} self-report frame must be admitted: {e}"));

        assert_eq!(
            serde_json::to_value(frame.kind).expect("the kind must re-encode"),
            serde_json::json!(kind),
            "the `{kind}` self-report frame keeps its own kind variant"
        );
        // The self-report's claims are the payload's VALUE, retained verbatim.
        assert_eq!(
            frame.payload,
            serde_json::json!({
                "declared_status": "completed",
                "verified": true,
                "caller_approved": true,
            }),
            "the `{kind}` self-report's verified/caller_approved claims must stay inert payload data"
        );

        // NONE of the self-report's claim names became a member of the frame,
        // which stays exactly the four declared members.
        let outer = outer_member_keys(&line);
        assert_eq!(
            outer.len(),
            4,
            "the `{kind}` frame must carry exactly its four declared members"
        );
        for claim in ["verified", "caller_approved", "declared_status"] {
            assert!(
                !outer.contains(&claim.to_owned()),
                "the self-report claim `{claim}` must NOT become a member of the frame itself"
            );
        }
        assert!(
            frame
                .validate(ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES)
                .is_ok(),
            "the `{kind}` self-report frame must pass the same bounded validate as any payload"
        );
    }
}

/// Case 16: the launch/bounds validators this slice must KEEP REUSING. The
/// `AntigravityPersistentLaunchContract::from_json_str` /
/// `from_json_slice` and `AntigravityPersistentLaunchReceipt::from_json_str`
/// ingress points (antigravity_persistent.rs:267-280 and :377-384) run the
/// EXISTING launch policy, unchanged, and refuse exactly what that policy
/// refuses: a shell-enabled launch, and a `max_total_bytes` below
/// `max_frame_bytes`. The nested closed `AntigravityPersistentCapabilities` is
/// decoded by value to prove that type's own closedness is still reachable
/// through the boundary.
///
/// Every refusal asserted here is one the real validator ACTUALLY produces -
/// verified against the production source, not an idealized refusal.
// WORK_UNIT_CASE: 934/c16_launch_and_bounds_validators_reused
#[test]
#[allow(clippy::too_many_lines)]
fn c16_launch_contract_and_capabilities_ingress_refuses_what_policy_forbids() {
    // (a) The canonical contract is admitted by the real ingress and keeps its
    // own facts: shell-free, NDJSON both ways, absolute executable, allowlisted
    // env, in-range bounds - so the refusals below are policy and not an
    // otherwise-broken fixture.
    let contract_text = raw("c16_launch_contract_current_canonical");
    let contract = AntigravityPersistentLaunchContract::from_json_str(&contract_text)
        .expect("the canonical launch contract must pass the real from_json_str ingress");
    assert!(
        !contract.shell,
        "the admitted contract must be shell-free, or the shell refusal below proves nothing"
    );
    assert_eq!(
        contract.contract_version, ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION,
        "the admitted contract must carry the supported schema version"
    );
    assert!(
        contract.bounds.validate().is_ok(),
        "the admitted contract's own bounds must pass validate"
    );
    // The byte-oriented ingress agrees with the string one - existing behaviour,
    // exercised and never replaced.
    assert_eq!(
        AntigravityPersistentLaunchContract::from_json_slice(contract_text.as_bytes()),
        Ok(contract.clone()),
        "from_json_slice and from_json_str must admit the IDENTICAL contract value"
    );

    // (b) A shell-enabled launch is REFUSED by the real validator
    // (antigravity_persistent.rs:204-205). The refusal is the exact production
    // string, not a paraphrase.
    assert_eq!(
        AntigravityPersistentLaunchContract::from_json_str(&raw(
            "c16_launch_contract_shell_true_refuse"
        )),
        Err(W2_SHELL_REFUSAL.to_owned()),
        "a shell-enabled persistent launch must be refused as `persistent launch must be shell-free (shell=false)`"
    );
    // The refusal is the SHELL policy and not a decode failure: the same
    // document reaches the policy stage, proven by the one-bit difference.
    assert_eq!(
        raw("c16_launch_contract_shell_true_refuse").replace("\"shell\":true", "\"shell\":false"),
        contract_text,
        "the shell refusal fixture must be the canonical contract with ONLY `shell` flipped"
    );

    // (c) A contract whose `max_total_bytes` is BELOW `max_frame_bytes` is
    // REFUSED by the nested bounds validator (antigravity_persistent.rs:155-156),
    // reached through the same ingress.
    assert_eq!(
        AntigravityPersistentLaunchContract::from_json_str(&raw(
            "c16_launch_contract_total_below_frame_refuse"
        )),
        Err(W2_TOTAL_BELOW_FRAME_REFUSAL.to_owned()),
        "a contract whose max_total_bytes is below max_frame_bytes must be refused as `max_total_bytes must be >= max_frame_bytes`"
    );
    // The refusal really is the nested bounds check, isolated on the bound value
    // itself rather than only through the contract that carries it.
    let mut impossible: AntigravityPersistentBounds = contract.bounds.clone();
    impossible.max_total_bytes = impossible.max_frame_bytes - 1;
    assert_eq!(
        impossible.validate(),
        Err(W2_TOTAL_BELOW_FRAME_REFUSAL.to_owned()),
        "the refusal must be the nested bounds validator's own, isolated on the bounds value"
    );

    // (d) The durable launch receipt's OWN ingress is reused unchanged, and the
    // receipt keeps its own shell-free / env-allowlisted facts.
    let receipt = AntigravityPersistentLaunchReceipt::from_json_str(&raw(
        "c1_persistent_launch_receipt_canonical",
    ))
    .expect("the durable launch receipt must pass the real from_json_str ingress");
    assert!(
        receipt.shell_free && receipt.env_allowlisted,
        "the admitted launch receipt must keep both of its own `true` effect facts"
    );
    // Its unknown-member refusal is the existing one, not an invented policy.
    let receipt_with_unknown = raw("c1_persistent_launch_receipt_canonical")
        .replace("\"shell_free\":true", "\"c16_unknown_receipt_member\":true");
    assert_ne!(
        receipt_with_unknown,
        raw("c1_persistent_launch_receipt_canonical"),
        "the unknown-receipt-member injection must actually change the document"
    );
    assert_eq!(
        AntigravityPersistentLaunchReceipt::from_json_str(&receipt_with_unknown),
        Err("malformed launch receipt".to_owned()),
        "the launch receipt ingress must refuse an unknown member as `malformed launch receipt`"
    );

    // (e) The nested closed `AntigravityPersistentCapabilities` is decodable by
    // value through the same boundary: the type's own closedness is unchanged.
    let capabilities_text = raw("c16_persistent_capabilities_canonical");
    let capabilities: AntigravityPersistentCapabilities = decode_receipt(&capabilities_text)
        .expect("the nested AntigravityPersistentCapabilities document must decode");
    assert!(
        capabilities.prompt_arg && capabilities.json_output,
        "the capabilities must keep the document's own `true` support facts"
    );
    // Closed at that depth: an unknown member on the nested capabilities struct
    // is refused by its own `deny_unknown_fields`.
    let unknown_capability = capabilities_text.replace(
        "\"prompt_arg\":true",
        "\"prompt_arg\":true,\"c16_unknown_capability_member\":true",
    );
    assert_ne!(
        unknown_capability, capabilities_text,
        "the unknown-capability injection must actually change the document"
    );
    assert!(
        decode_receipt::<AntigravityPersistentCapabilities>(&unknown_capability).is_err(),
        "the nested closed AntigravityPersistentCapabilities must refuse an unknown member"
    );
}
