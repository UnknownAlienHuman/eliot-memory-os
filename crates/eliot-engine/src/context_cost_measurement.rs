//! Closed, versioned Context-cost measurement payload accepted by the memory
//! utility ledger.
//!
//! Audit 5932050795 defect 4 named this seam: the previous reader probed an
//! arbitrary `serde_json::Value` for five fragments and admitted the STU it
//! found. These types replace the probes with a real deserialization into a
//! closed schema, so an extra, mutated or unexpected fragment is refused
//! instead of admitted on the strength of whatever a probe happened to look
//! for.
//!
//! The convention is the crate family's own, not a new one:
//! `eliot_context_contracts::SerializedContextMeasurement`, `StuEstimate` and
//! `TokenizerObservation` (`crates/smart/eliot-context-contracts/src/measurement.rs`)
//! are `#[serde(deny_unknown_fields)]` structs with plain required fields, and
//! every other closed boundary in `eliot-types/src/distillation.rs` (starting at
//! `MemoryUtilitySourceRecord`) is the same. There is no `#[serde(default)]`, no
//! `#[serde(alias)]` and no `Option`-means-absent field here, so a missing
//! fragment stays missing evidence instead of being invented.
//!
//! Two facts constrain the schema, and they are load-bearing rather than
//! incidental:
//!
//! 1. `actual_tokens` must be a REQUIRED key whose value is explicitly JSON
//!    `null`. Under the five-probe reader, omission was already refused
//!    (`is_some_and(Value::is_null)` is false for an absent key). Modelling it
//!    as `Option<Value>` would silently re-admit omission, so it is
//!    `serde_json::Value` and a missing key stays a deserialization error.
//! 2. `stu_estimate` must be a CLOSED object, not a bare `value` probe. Reading
//!    `stu_estimate.value` with `.get()` ignored an `empirical` flag or any
//!    sibling fragment; `ContextCostStuEstimate` now names both members that the
//!    #704 owner defines for the same estimate (`value`, `empirical`), so a
//!    payload cannot claim an STU while carrying an unreviewed sibling.
//!
//! The admitted number is the #704 conservative Source Token Unit. It is
//! returned as an explicitly STU-named value, never as a token count, and its
//! accumulation is checked rather than saturating: an unrepresentable total is a
//! typed `ContextError::Overflow` refusal, so an overflow can never become a
//! huge policy cost and cross a demotion threshold.
//!
//! Corrected-evidence note (AUD4): this closes the adapter against the five
//! fragments the audit enumerated and no further. The audit's wider repairs -
//! validating serializer version/options/profile digest, rendered byte length,
//! content digest, estimator identity, target/item identity and invalidation
//! through #704/#584's accepted validator - need bindings the emitted payload
//! does not carry, and adding fields to a closed schema that no producer emits
//! would invent evidence. They are not faked here and remain open; see
//! CHECKLIST AUD4 in control-20260923-impl/v2/issues/880.
//!
//! The producer gap is worth stating plainly rather than leaving implied: the
//! only in-repo producer of a memory measurement wire object is
//! `measurement_wire` at `crates/eliot-app/src/mcp_stdio.rs:371-377`, and it
//! emits exactly `{unit, status, actual_tokens: null}` - it emits no
//! `adapter_revision`, no `serializer_id` and no `stu_estimate`. This contract
//! therefore has no in-repo producer, which is why the three keys it requires
//! were introduced without an emitted counterpart. That is unchanged by this
//! work: the five probes this replaces required the same three keys, so the
//! accepted fragment set is the same, merely closed rather than probed. The
//! consequence is that a real receipt body carrying no `measurement` object
//! reads as unmeasured (`None`, so `context_cost_tokens` stays zero meaning
//! "unmeasured", not "cheap") and the `ContextTokenCost` policy path never
//! receives a number from production data at all. Emitting this contract is an
//! `eliot-app` owner change, outside this work unit.

use eliot_context_contracts::ContextError;
use serde::Deserialize;
use serde_json::Value;

/// The one accepted Context-cost adapter revision.
///
/// A payload that does not declare exactly this revision is not measured. There
/// is no trial decoding across revisions.
pub const CONTEXT_COST_ADAPTER_REVISION: &str = "eliot-context-cost/v1";

/// The one serializer this adapter admits.
pub const CONTEXT_COST_SERIALIZER_ID: &str = "serde_json";

/// The #704 owner spelling of the conservative-STU measurement status.
///
/// `eliot_context_contracts::MeasurementStatus` serializes with
/// `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]`, so `ConservativeStu` is
/// `CONSERVATIVE_STU`. The field stays a `String` rather than the owner's enum
/// so that an unsupported status is a refused measurement rather than a
/// deserialization panic.
pub const CONTEXT_COST_STATUS_CONSERVATIVE_STU: &str = "CONSERVATIVE_STU";

/// The accepted conservative-STU estimate carried by one measurement payload.
///
/// Closed: it admits exactly the two members the #704 owner defines for the same
/// estimate in `eliot_context_contracts::StuEstimate` (`value`, `empirical`),
/// and refuses any other member instead of reading past it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContextCostStuEstimate {
    /// The conservative Source Token Unit count.
    pub value: u64,
    /// Always false: an STU estimate is unvalidated planning evidence and never
    /// proves route fit. Carried explicitly so a payload cannot present the
    /// estimate as an observed count.
    pub empirical: bool,
}

/// The closed Context-cost measurement object read from a source-record payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContextCostMeasurement {
    /// The accepted adapter revision; see [`CONTEXT_COST_ADAPTER_REVISION`].
    pub adapter_revision: String,
    /// The canonical serializer identity; see [`CONTEXT_COST_SERIALIZER_ID`].
    pub serializer_id: String,
    /// The owner measurement status; see [`CONTEXT_COST_STATUS_CONSERVATIVE_STU`].
    pub measurement_status: String,
    /// The exact tokenizer observation, which this seam cannot produce.
    ///
    /// It must be present and explicitly `null`. An actual-token claim needs its
    /// own route/model/tokenizer binding over these bytes; without one it stays
    /// unknown and is never a synthesized count, a zero or a minimum one.
    pub actual_tokens: Value,
    /// The conservative STU estimate this payload contributes.
    pub stu_estimate: ContextCostStuEstimate,
}

impl ContextCostMeasurement {
    /// Whether this payload declares every accepted revision and status marker.
    ///
    /// Revision and status are compared here rather than deserialized into the
    /// owner's enums so that a future revision is a refused measurement, not a
    /// decode failure that reads as corruption.
    #[must_use]
    pub fn declares_accepted_revision(&self) -> bool {
        self.adapter_revision == CONTEXT_COST_ADAPTER_REVISION
            && self.serializer_id == CONTEXT_COST_SERIALIZER_ID
            && self.measurement_status == CONTEXT_COST_STATUS_CONSERVATIVE_STU
    }

    /// Whether this payload claims an actual token count without a binding.
    ///
    /// A present, non-null `actual_tokens` is a claim this seam cannot admit, so
    /// it refuses the whole payload instead of reading the STU out of it.
    #[must_use]
    pub fn claims_unbound_actual_tokens(&self) -> bool {
        !self.actual_tokens.is_null()
    }
}

/// The conservative STU this payload contributes, or `None` when it is not an
/// admissible measurement.
///
/// An absent, malformed, unversioned or unsupported payload yields `None`
/// (unknown), never zero, one, or a legacy bare estimate. The typed failure path
/// is the accumulation in [`checked_context_cost_add`], which uses
/// `ContextError::Overflow` rather than a silent saturation.
#[must_use]
pub fn canonical_context_cost_from_payload(payload: &Value) -> Option<u64> {
    let measure: ContextCostMeasurement = serde_json::from_value(payload.get("measurement")?.clone()).ok()?;
    if !measure.declares_accepted_revision() || measure.claims_unbound_actual_tokens() {
        return None;
    }
    Some(measure.stu_estimate.value)
}

/// Add one measured STU to a running total without saturating.
///
/// An unrepresentable total is refused as `ContextError::Overflow`, the same
/// typed failure this crate's byte accumulation already uses, instead of
/// silently becoming `u64::MAX` and reading as an enormous policy cost.
pub fn checked_context_cost_add(current: u64, measured: u64) -> Result<u64, ContextError> {
    current.checked_add(measured).ok_or(ContextError::Overflow)
}