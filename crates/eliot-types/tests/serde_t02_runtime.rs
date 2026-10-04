//! Issue #931 (`F-DENY-T02`), audit comment 5932756267 item 6: the raw-byte
//! acceptance target for the runtime, supervision and service-health wire
//! decoders whose repair this issue owns. The rows here are the ones the audit
//! comment and the issue body's blocking-defect repair list (items 4 and 6)
//! name together: zero root PID, zero descendant PID, duplicate/unsorted PID,
//! empty/oversized path/hash/detail, and a positive valid receipt, plus the
//! `Some("")` optional-protected-identifier class on
//! `OperationRuntimeCheckpoint` and `RuntimeOperationDetail`.
//!
//! Fixtures are stored as RAW JSON TEXT and handed to the deserializer
//! unparsed. A `serde_json::Value` intermediate collapses a repeated object
//! member before the decoder ever sees it, so it could not prove a case that
//! differs only in a byte the decoder must see; every refusal case therefore
//! feeds raw bytes.
//!
//! The raw fixture corpus. Every fixture is stored as a STRING value holding its
//! wire text, because a fixture that repeats an object member - a valid JSON
//! document, but one no decoder may accept - would be rewritten by a bare
//! `{"key": {.}}` corpus: storing the text keeps both occurrences intact all the
//! way to the decoder. Here the corpus nests each case under `cases` and each
//! case carries its wire text in `text`, alongside the `kind`, `expect` and
//! `why` the corpus owner recorded.
//!
//! Scope and honesty of this file:
//! - The SIXTEEN full #931 acceptance obligations are DEFERRED by the work card
//!   and are not written here. What is here is only the audit-comment-6 row set.
//! - `crates/eliot-types/src/runtime_supervision.rs` and
//!   `crates/eliot-types/tests/data/serde_t02_runtime.json` are READ-ONLY to
//!   this file. Nothing here edits a production declaration, and no test widens
//!   a visibility to make a name reachable: every type this file names is
//!   already reachable through the `eliot_types` boundary and is imported
//!   exactly as a downstream crate would import it.
//! - NOTHING IN THIS FILE HAS BEEN EXECUTED. Every assertion below states what
//!   the decoder is FOR, not what it was observed to do. A green run of this
//!   file is compatible with every assertion in it being wrong, and nothing here
//!   may be read as an execution result, a case tally or a pass count.
//!
//! Rules exercised (verbatim):
//! - `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:12` -
//!   "authority, scope, effect, privacy, ordering and receipt fields are never
//!   silently defaulted;"
//! - `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:13` -
//!   "closed control variants fail when unknown; additive reason/telemetry
//!   values preserve Unknown(raw);"
//! - `docs/architecture/I05-16-common-durable-fields.md:46` - "Fields that do
//!   not apply remain explicit `None`; they are not silently omitted from the
//!   semantic model."
//! - `docs/architecture/I07-20-agent-facing-error-contract.md:24-26` - the
//!   registry carries `DESCENDANT_CLOSURE_INCOMPLETE` under state/conflict, and
//!   `:42-46` carries `PROCESS_TREE_CLEANUP_FAILED` under instrument/evidence:
//!   an untrusted descendant capture and a proven incomplete one are two
//!   different facts, which is why the fail-closed clause below is asserted
//!   separately from the refusal rows.

#![allow(clippy::expect_used)]

use eliot_types::{
    DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION, DescendantsAtRootExit, OperationRuntimeCheckpoint,
    ProcessReapReceipt, RuntimeOperationDetail,
};

/// The raw fixture corpus, read exactly as
/// `crates/eliot-types/tests/data/serde_t02_runtime.json` stores it. The
/// `Value` only carries the strings out of this loader; what reaches the
/// deserializer is the stored wire text itself, byte for byte.
fn corpus() -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("serde_t02_runtime.json");
    let text = std::fs::read_to_string(&path).expect("serde_t02_runtime.json must exist");
    serde_json::from_str(&text).expect("serde_t02_runtime.json must be valid JSON")
}

/// One case's own wire text, byte for byte, with no re-serialization: the
/// derived member order and any byte the decoder must see both survive, which a
/// `Value` round trip would destroy.
fn raw(case_id: &str) -> String {
    corpus()
        .get("cases")
        .and_then(|cases| cases.get(case_id))
        .and_then(|case| case.get("text"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("the corpus must contain case {case_id}"))
        .to_owned()
}

fn decode_receipt(document: &str) -> Result<ProcessReapReceipt, serde_json::Error> {
    serde_json::from_str(document)
}

fn decode_checkpoint(document: &str) -> Result<OperationRuntimeCheckpoint, serde_json::Error> {
    serde_json::from_str(document)
}

fn decode_operation_detail(document: &str) -> Result<RuntimeOperationDetail, serde_json::Error> {
    serde_json::from_str(document)
}

/// The `refused` receipt document with ONLY its `descendants_at_root_exit`
/// member replaced by the member stored in `valid`, spliced as text.
///
/// It exists so the zero-root-PID row can attribute its refusal: without a
/// second, otherwise-identical document that is expected to decode, a bare
/// `is_err()` proves nothing at all, because any other malformed member of the
/// same document would be an equally good explanation. This is a string splice
/// and not a re-serialization - no JSON value is parsed and re-emitted on the
/// way to the decoder - so no member is collapsed, reordered or rewritten.
fn receipt_with_capture_from(refused: &str, valid: &str) -> String {
    const MEMBER: &str = "\"descendants_at_root_exit\":";
    let refused_at = refused
        .find(MEMBER)
        .unwrap_or_else(|| panic!("the refused receipt must carry the {MEMBER} member"))
        + MEMBER.len();
    let valid_at = valid
        .find(MEMBER)
        .unwrap_or_else(|| panic!("the valid receipt must carry the {MEMBER} member"))
        + MEMBER.len();
    let mut spliced = String::with_capacity(refused.len() + valid.len());
    spliced.push_str(&refused[..refused_at]);
    spliced.push_str(&valid[valid_at..]);
    spliced
}

/// Row `pos_valid_capture`: for a receipt whose descendant capture is a legal
/// `Captured` record, the decoder must accept the raw bytes, the decoded
/// capture must satisfy its own `DescendantsAtRootExit::validate`, and the
/// receipt must report `proves_complete_reap() == true`. This is the baseline
/// every refusal row below differs from, so it is also the row that would fail
/// first if the repair over-refused.
/// APPENDIX-P-rust-public-boundary-interfaces.md:12 - receipt fields are never
/// silently defaulted, so a legal receipt must survive unchanged.
// WORK_UNIT_CASE: 931/c_pos_valid_capture
#[test]
fn c_pos_valid_capture_decodes_validates_and_proves_complete_reap() {
    let receipt: ProcessReapReceipt = decode_receipt(&raw("pos_valid_capture"))
        .expect("the positive captured-receipt fixture must decode");
    assert_eq!(
        receipt.operation_id, "op-1",
        "the decoded receipt must carry the document's own `operation_id`, not a fabricated one"
    );
    assert_eq!(
        receipt.root_pid,
        Some(10),
        "the decoded receipt must carry the document's own `root_pid`"
    );
    let capture: &DescendantsAtRootExit = &receipt.descendants_at_root_exit;
    let DescendantsAtRootExit::Captured(captured) = capture else {
        panic!("the positive fixture carries a `captured` capture, not another variant")
    };
    assert_eq!(
        captured.schema_version, DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION,
        "the decoded capture must carry the schema version this build owns"
    );
    assert_eq!(
        captured.root_pid, 10,
        "the decoded capture must carry the document's own non-zero capture `root_pid`"
    );
    assert!(
        capture.validate().is_ok(),
        "the decoded capture must pass its own existing `DescendantsAtRootExit::validate`"
    );
    assert!(
        receipt.proves_complete_reap(),
        "a receipt carrying a legal capture and every other positive fact must report a complete reap"
    );
}

/// Row `refuse_zero_root_pid_in_capture`: for the audit's reproducible
/// counterexample, whose single illegal value is the capture's `root_pid` of 0,
/// the decoder must refuse. The second half of the row exists to make the
/// refusal attributable: the SAME document with that one member replaced by the
/// valid capture must decode, so nothing else in the document can be the reason.
/// The task's counterexample JSON is stored verbatim in the corpus, including
/// the receipt-level `root_pid` of `null`, and this row is what establishes
/// that a `null` receipt-level optional PID is clean input.
// WORK_UNIT_CASE: 931/c_refuse_zero_root_pid_capture
#[test]
fn c_refuse_zero_root_pid_capture_is_attributable_to_the_capture() {
    let refused = raw("refuse_zero_root_pid_in_capture");
    assert!(
        decode_receipt(&refused).is_err(),
        "a capture whose `root_pid` is 0 can never be a legal capture, so the receipt that carries it must be refused at the decoder"
    );
    let repaired = receipt_with_capture_from(&refused, &raw("pos_valid_capture"));
    let receipt: ProcessReapReceipt = decode_receipt(&repaired).expect(
        "the same document with only `descendants_at_root_exit` replaced by a legal capture must decode, otherwise the refusal above is not attributable to the zero capture `root_pid`",
    );
    assert!(
        receipt.root_pid.is_none(),
        "the spliced receipt must keep the refused document's own receipt-level `root_pid`, so the row also covers a `null` optional receipt PID"
    );
    assert!(
        receipt.descendants_at_root_exit.validate().is_ok(),
        "the capture that replaced the illegal one is the valid capture and must validate"
    );
}

/// Row `refuse_zero_descendant_pid`: for the `pid != 0` bound on a descendant
/// snapshot, the decoder must refuse a capture whose single descendant's `pid`
/// is 0 and which differs from the baseline capture in nothing else.
/// `crates/eliot-types/src/runtime_supervision.rs` keeps this bound in
/// `validate_snapshot`, and this row exists so the bound cannot stay opt-in.
// WORK_UNIT_CASE: 931/c_refuse_zero_descendant_pid
#[test]
fn c_refuse_zero_descendant_pid() {
    assert!(
        decode_receipt(&raw("refuse_zero_descendant_pid")).is_err(),
        "a descendant snapshot whose `pid` is 0 is not a process, so the capture carrying it must be refused at the decoder"
    );
}

/// Row `refuse_duplicate_descendant_pid`: for the no-duplicate-descendant-PID
/// bound, the decoder must refuse a capture whose two otherwise-valid
/// descendants repeat the same `pid`.
/// APPENDIX-P-rust-public-boundary-interfaces.md:12 - a receipt's process
/// identity is never silently defaulted, so a list that cannot describe one
/// process set is refused rather than truncated or deduplicated.
// WORK_UNIT_CASE: 931/c_refuse_duplicate_descendant_pid
#[test]
fn c_refuse_duplicate_descendant_pid() {
    assert!(
        decode_receipt(&raw("refuse_duplicate_descendant_pid")).is_err(),
        "two descendant snapshots with the same `pid` are a duplicate that no decoder may collapse, so the capture must be refused at the decoder"
    );
}

/// Row `refuse_unsorted_descendants`: for the sorted-descendant-list bound, the
/// decoder must refuse a capture whose two distinct valid descendants arrive in
/// descending `pid` order, rather than sorting them and decoding a value whose
/// bytes differ from the bytes read.
// WORK_UNIT_CASE: 931/c_refuse_unsorted_descendants
#[test]
fn c_refuse_unsorted_descendants() {
    assert!(
        decode_receipt(&raw("refuse_unsorted_descendants")).is_err(),
        "a descendant list that is not sorted by `pid` must be refused at the decoder, not reordered into a value whose bytes differ from the bytes read"
    );
}

/// Row `refuse_descendant_pid_equals_root_pid`: for the `pid != root_pid` bound,
/// the decoder must refuse a capture that lists the root process itself as one
/// of its own descendants.
// WORK_UNIT_CASE: 931/c_refuse_descendant_pid_equals_root_pid
#[test]
fn c_refuse_descendant_pid_equals_root_pid() {
    assert!(
        decode_receipt(&raw("refuse_descendant_pid_equals_root_pid")).is_err(),
        "a descendant snapshot whose `pid` equals the capture's own `root_pid` names the root, not a descendant, so the capture must be refused at the decoder"
    );
}

/// Row `refuse_empty_image_path`: for the non-empty `image_path` bound, the
/// decoder must refuse a capture whose single descendant has an empty image
/// path. An empty path is an absent process identity, not a weaker one.
// WORK_UNIT_CASE: 931/c_refuse_empty_image_path
#[test]
fn c_refuse_empty_image_path() {
    assert!(
        decode_receipt(&raw("refuse_empty_image_path")).is_err(),
        "a descendant snapshot with an empty `image_path` is an absent process identity, so the capture must be refused at the decoder"
    );
}

/// Row `refuse_oversized_image_path`: for the `MAX_DESCENDANT_IMAGE_PATH_CHARS`
/// bound, the decoder must refuse a capture whose single descendant's
/// `image_path` exceeds that bound, so a malformed or hostile path cannot
/// become a trusted process identity.
// WORK_UNIT_CASE: 931/c_refuse_oversized_image_path
#[test]
fn c_refuse_oversized_image_path() {
    assert!(
        decode_receipt(&raw("refuse_oversized_image_path")).is_err(),
        "a descendant snapshot whose `image_path` exceeds the documented bound must be refused at the decoder"
    );
}

/// Row `refuse_empty_image_sha256`: for the non-empty optional `image_sha256`
/// bound, the decoder must refuse a capture whose single descendant PRESENTS
/// the digest as the empty string rather than omitting it. This is the row
/// where an absent value and an empty value must not be the same value.
// WORK_UNIT_CASE: 931/c_refuse_empty_image_sha256
#[test]
fn c_refuse_empty_image_sha256() {
    assert!(
        decode_receipt(&raw("refuse_empty_image_sha256")).is_err(),
        "a present-but-empty `image_sha256` is an absent digest spelled as a value, so the capture must be refused at the decoder rather than decoded as an unknown digest"
    );
}

/// Row `refuse_oversized_image_sha256`: for the
/// `MAX_DESCENDANT_IMAGE_SHA256_CHARS` bound, the decoder must refuse a capture
/// whose single descendant's `image_sha256` exceeds that bound.
// WORK_UNIT_CASE: 931/c_refuse_oversized_image_sha256
#[test]
fn c_refuse_oversized_image_sha256() {
    assert!(
        decode_receipt(&raw("refuse_oversized_image_sha256")).is_err(),
        "a descendant snapshot whose `image_sha256` exceeds the documented bound must be refused at the decoder"
    );
}

/// Row `refuse_oversized_detail`: for the `MAX_DESCENDANT_DETAIL_CHARS` bound on
/// a `failed` capture, the decoder must refuse a well-shaped failure record
/// whose `detail` exceeds that bound while its optional `root_pid` is non-zero.
/// This is the bound that keeps the failure path bounded rather than
/// open-ended.
// WORK_UNIT_CASE: 931/c_refuse_oversized_detail
#[test]
fn c_refuse_oversized_detail() {
    assert!(
        decode_receipt(&raw("refuse_oversized_detail")).is_err(),
        "a `failed` capture whose `detail` exceeds the documented bound must be refused at the decoder"
    );
}

/// Row `refuse_unknown_schema_version`: for the pinned descendant-capture
/// `schema_version`, the decoder must refuse a capture that declares the next
/// generation of the version literal rather than the one this build owns.
/// APPENDIX-P-rust-public-boundary-interfaces.md:11 - major incompatibility
/// fails before effects; an unowned capture layout must not decode and then be
/// read as evidence.
// WORK_UNIT_CASE: 931/c_refuse_unknown_schema_version
#[test]
fn c_refuse_unknown_schema_version() {
    assert!(
        decode_receipt(&raw("refuse_unknown_schema_version")).is_err(),
        "a capture whose `schema_version` is not the one this build owns must be refused at the decoder, not decoded as the current layout"
    );
}

/// Row `refuse_unknown_nested_field`: the `deny_unknown_fields` row. The
/// decoder must refuse a capture that carries exactly one member the capture
/// struct does not declare, alongside an otherwise legal capture.
/// APPENDIX-P-rust-public-boundary-interfaces.md:12 - a member that this build
/// does not own is not silently dropped on its way to a trusted value.
// WORK_UNIT_CASE: 931/c_refuse_unknown_nested_field
#[test]
fn c_refuse_unknown_nested_field() {
    assert!(
        decode_receipt(&raw("refuse_unknown_nested_field")).is_err(),
        "the capture struct is closed, so an undeclared nested member must be refused at the decoder instead of being silently dropped"
    );
}

/// Row `pos_valid_failed_capture`: for the `failed` capture shape as a
/// well-formed record - a bounded `detail`, a non-zero optional `root_pid` and
/// a declared error-kind spelling - the decoder must SUCCEED. A well-formed
/// failure record is legal evidence of an unsuccessful capture attempt, and
/// refusing it would destroy the honest record of "the capture did not
/// complete". Whether that record then proves a reap is the separate
/// fail-closed row below.
// WORK_UNIT_CASE: 931/c_pos_valid_failed_capture
#[test]
fn c_pos_valid_failed_capture() {
    let receipt: ProcessReapReceipt = decode_receipt(&raw("pos_valid_failed_capture"))
        .expect("the positive failed-capture fixture is a legal record and must decode");
    let DescendantsAtRootExit::Failed(failed) = &receipt.descendants_at_root_exit else {
        panic!("the positive fixture carries a `failed` capture, not another variant")
    };
    assert_eq!(
        failed.schema_version, DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION,
        "the decoded failure record must carry the schema version this build owns"
    );
    assert_eq!(
        failed.root_pid,
        Some(10),
        "the decoded failure record must carry the document's own non-zero optional `root_pid`"
    );
    assert!(
        receipt.descendants_at_root_exit.validate().is_ok(),
        "a well-formed failure record must pass its own existing `DescendantsAtRootExit::validate`"
    );
}

/// Row `c_failed_capture_does_not_prove_reap`, also keyed on
/// `pos_valid_failed_capture`: the fail-closed clause. A receipt whose
/// descendant capture is a well-formed `Failed` record must report
/// `proves_complete_reap() == false`, even though every clause the earlier
/// counterexample relied on is satisfied by this very document. The row is
/// written so the legacy predicate's own conditions are asserted FIRST and
/// hold, which is what makes the row discriminating: a decoder-level refusal
/// alone cannot satisfy it, because the document decodes.
/// I07-20 carries `DESCENDANT_CLOSURE_INCOMPLETE` under state/conflict and
/// `PROCESS_TREE_CLEANUP_FAILED` under instrument/evidence, so "the capture did
/// not complete" and "cleanup is proven complete" are two different facts and
/// not one boolean; this row is where that distinction is asserted.
// WORK_UNIT_CASE: 931/c_failed_capture_does_not_prove_reap
#[test]
fn c_failed_capture_does_not_prove_reap() {
    let receipt: ProcessReapReceipt = decode_receipt(&raw("pos_valid_failed_capture"))
        .expect("this row needs the failed-capture fixture to decode; a refusal cannot express it");
    // Every clause the pre-repair `proves_complete_reap` inspected, asserted
    // first so the next assertion is not vacuously true.
    assert_eq!(
        receipt.process_count_after, 0,
        "the failed-capture fixture must satisfy the pre-repair `process_count_after == 0` clause"
    );
    assert!(
        receipt.stdout_closed
            && receipt.stderr_closed
            && receipt.all_tasks_joined
            && receipt.forced_termination
            && receipt.terminal_error_codes.is_empty(),
        "the failed-capture fixture must satisfy every other pre-repair `proves_complete_reap` clause, so the only thing left to decide the row is the descendant capture"
    );
    assert!(
        !receipt.proves_complete_reap(),
        "a receipt whose descendant capture is a well-formed `Failed` record carries no descendant-closure evidence, so it must not prove a complete reap; the caller's cleanup predicate reads this as authoritative"
    );
}

/// Row `pos_checkpoint_no_optionals`: for explicit absence on every optional
/// identifier of `OperationRuntimeCheckpoint`, the decoder must SUCCEED and the
/// decoded value must report each of them absent.
/// I05-16:46 - "Fields that do not apply remain explicit `None`; they are not
/// silently omitted from the semantic model." This row is the accept-side
/// counterpart of the five empty-string refusal rows below: it is what proves
/// those five rows are refusing an empty IDENTIFIER rather than an absent
/// field.
// WORK_UNIT_CASE: 931/c_pos_checkpoint_no_optionals
#[test]
fn c_pos_checkpoint_no_optionals() {
    let checkpoint: OperationRuntimeCheckpoint =
        decode_checkpoint(&raw("pos_checkpoint_no_optionals"))
            .expect("the explicit-absence checkpoint fixture must decode");
    assert_eq!(
        checkpoint.operation_id, "op-1",
        "the decoded checkpoint must carry the document's own `operation_id`"
    );
    assert_eq!(
        checkpoint.generation, 1,
        "the decoded checkpoint must carry the document's own `generation`"
    );
    assert!(
        checkpoint.invocation_id.is_none()
            && checkpoint.adapter_id.is_none()
            && checkpoint.job_object_name.is_none()
            && checkpoint.role_lease_id.is_none()
            && checkpoint.runtime_contract_sha256.is_none(),
        "every optional identifier in this fixture is spelled as JSON `null`, so the decoded checkpoint must report all five absent rather than empty"
    );
}

/// Row `refuse_checkpoint_empty_invocation_id`: an optional `invocation_id`
/// present as the empty string is an absent identifier, so the decoder must
/// refuse the checkpoint rather than decode it as `Some("")`.
/// APPENDIX-P-rust-public-boundary-interfaces.md:12 - authority and scope
/// fields are never silently defaulted, and an empty string is the value a
/// defaulted field takes.
// WORK_UNIT_CASE: 931/c_refuse_checkpoint_empty_invocation_id
#[test]
fn c_refuse_checkpoint_empty_invocation_id() {
    assert!(
        decode_checkpoint(&raw("refuse_checkpoint_empty_invocation_id")).is_err(),
        "an optional `invocation_id` spelled as the empty string is an absent identifier, so the checkpoint must be refused at the decoder instead of decoding as `Some(\"\")`"
    );
}

/// Row `refuse_checkpoint_empty_adapter_id`: an optional `adapter_id` present as
/// the empty string is an absent identifier, so the decoder must refuse the
/// checkpoint rather than decode it as `Some("")`.
// WORK_UNIT_CASE: 931/c_refuse_checkpoint_empty_adapter_id
#[test]
fn c_refuse_checkpoint_empty_adapter_id() {
    assert!(
        decode_checkpoint(&raw("refuse_checkpoint_empty_adapter_id")).is_err(),
        "an optional `adapter_id` spelled as the empty string is an absent identifier, so the checkpoint must be refused at the decoder instead of decoding as `Some(\"\")`"
    );
}

/// Row `refuse_checkpoint_empty_job_object_name`: an optional
/// `job_object_name` present as the empty string names no job object, so the
/// decoder must refuse the checkpoint rather than decode it as `Some("")`.
// WORK_UNIT_CASE: 931/c_refuse_checkpoint_empty_job_object_name
#[test]
fn c_refuse_checkpoint_empty_job_object_name() {
    assert!(
        decode_checkpoint(&raw("refuse_checkpoint_empty_job_object_name")).is_err(),
        "an optional `job_object_name` spelled as the empty string names no job object, so the checkpoint must be refused at the decoder instead of decoding as `Some(\"\")`"
    );
}

/// Row `refuse_checkpoint_empty_role_lease_id`: an optional `role_lease_id`
/// present as the empty string carries no lease, so the decoder must refuse the
/// checkpoint rather than decode it as `Some("")` beside a present
/// `role_lease_epoch`.
// WORK_UNIT_CASE: 931/c_refuse_checkpoint_empty_role_lease_id
#[test]
fn c_refuse_checkpoint_empty_role_lease_id() {
    assert!(
        decode_checkpoint(&raw("refuse_checkpoint_empty_role_lease_id")).is_err(),
        "an optional `role_lease_id` spelled as the empty string carries no lease, so the checkpoint must be refused at the decoder instead of decoding as `Some(\"\")` beside a present epoch"
    );
}

/// Row `refuse_checkpoint_empty_runtime_contract_sha256`: an optional
/// `runtime_contract_sha256` present as the empty string is an absent digest
/// rather than a weaker one, so the decoder must refuse the checkpoint rather
/// than decode it as `Some("")`.
/// APPENDIX-P-rust-public-boundary-interfaces.md:12 - receipt fields are never
/// silently defaulted, and an empty digest is the value a defaulted digest
/// takes.
// WORK_UNIT_CASE: 931/c_refuse_checkpoint_empty_runtime_contract_sha256
#[test]
fn c_refuse_checkpoint_empty_runtime_contract_sha256() {
    assert!(
        decode_checkpoint(&raw("refuse_checkpoint_empty_runtime_contract_sha256")).is_err(),
        "an optional `runtime_contract_sha256` spelled as the empty string is an absent digest, so the checkpoint must be refused at the decoder instead of decoding as `Some(\"\")`"
    );
}

/// Row `pos_operation_detail_no_lease`: for explicit absence of the optional
/// lease on a `RuntimeOperationDetail`, the decoder must SUCCEED and the decoded
/// value must report both lease members absent. It is the accept-side
/// counterpart of the empty-`role_lease_id` refusal row below.
// WORK_UNIT_CASE: 931/c_pos_operation_detail_no_lease
#[test]
fn c_pos_operation_detail_no_lease() {
    let detail: RuntimeOperationDetail =
        decode_operation_detail(&raw("pos_operation_detail_no_lease"))
            .expect("the explicit-absence operation-detail fixture must decode");
    assert_eq!(
        detail.operation_id, "op-1",
        "the decoded detail must carry the document's own `operation_id`"
    );
    assert!(
        detail.role_lease_id.is_none() && detail.role_lease_epoch.is_none(),
        "both lease members in this fixture are spelled as JSON `null`, so the decoded detail must report them absent rather than empty"
    );
}

/// Row `refuse_operation_detail_empty_role_lease_id`: an optional
/// `role_lease_id` on `RuntimeOperationDetail` present as the empty string is
/// an absent identifier, so the decoder must refuse the detail rather than
/// decode it as `Some("")` beside a present `role_lease_epoch`.
// WORK_UNIT_CASE: 931/refuse_operation_detail_empty_role_lease_id
#[test]
fn refuse_operation_detail_empty_role_lease_id() {
    assert!(
        decode_operation_detail(&raw("refuse_operation_detail_empty_role_lease_id")).is_err(),
        "an optional `role_lease_id` on a RuntimeOperationDetail spelled as the empty string is an absent identifier, so the detail must be refused at the decoder instead of decoding as `Some(\"\")` beside a present epoch"
    );
}
