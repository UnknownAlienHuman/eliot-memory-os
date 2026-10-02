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
//! Admission route (AUD4 repair 5). Closing the reader against unknown fragments
//! was not sufficient, because the ADMISSION route stayed open: `memory_distillation`
//! read this number as `entry.context_cost_tokens > 512` and proposed
//! `MemoryDistillationAction::Demote`, so a self-reported `stu_estimate.value`
//! with no binding to bytes, content, digest or identity still reached a
//! lifecycle decision. The audit's rule is "no one scalar threshold may consume
//! all three" - observed tokens, conservative STU and unknown - and the bare
//! `> 512` comparison consumed all three indiscriminately.
//!
//! What the crossing value actually was, established from the payload's own
//! fields and not from the field's name: before this change
//! `declares_accepted_revision` required `measurement_status ==
//! "CONSERVATIVE_STU"` and `claims_unbound_actual_tokens` required
//! `actual_tokens` to be exactly JSON `null`, so EVERY value that could reach
//! `> 512` was an unvalidated STU. Observed tokens were unreachable and unknown
//! was simply `None`. That is the audit's finding precisely: the audit's
//! self-reported `stu_estimate.value = 9_000` "is admitted, exceeds 512, and
//! reaches `Demote`". The owner agrees about what an STU is worth:
//! `SerializedContextMeasurement::proves_fit`
//! (`crates/smart/eliot-context-contracts/src/measurement.rs:189-191`) groups
//! `ConservativeStu` with `Unknown` and `Unavailable` and refuses to let any of
//! them decide fit, so an STU is not a capacity-deciding observation.
//!
//! So the value now carries its proven status instead of being flattened to a
//! bare `u64`: [`ContextCostObservation`] pairs `value` with `proven`, and only a
//! `proven: true` observation may enter `context_cost_tokens`. That is what makes
//! the `> 512` comparison consult the measurement's proven status rather than
//! the raw number: the field it reads is, by construction, populated only when a
//! bound measurement produced it. The scalar, its name and its threshold are
//! unchanged, and `512` is not retuned.
//!
//! Why the owner's own `EXACT_TOKENIZER` status is admitted here. Before this
//! change the seam had exactly one admissible status, so a status gate on the
//! scalar would have been a constant `false` - that would DISABLE the demotion
//! policy rather than constrain it, which is not a closure. Admitting the
//! owner's existing proven status keeps the gate genuinely conditional: a
//! payload carrying a real route-tokenizer observation is believed and can drive
//! the threshold, and one carrying only an STU cannot. Both statuses are the
//! owner's values from
//! `crates/smart/eliot-context-contracts/src/measurement.rs:12-18`; neither is a
//! new wire field, and `actual_tokens` and `stu_estimate` were already members
//! of this closed schema.
//!
//! The unit honesty matters here and is enforced rather than described: a proven
//! observation reports the observed `actual_tokens` count, never the STU beside
//! it, so an unvalidated estimate can never be relabelled as an observed token
//! count on the way into the scalar.
//!
//! `empirical: true` is refused (audit's second related fact). It was accepted
//! despite the `Always false` doc comment on [`ContextCostStuEstimate::empirical`],
//! and no test covered it. An STU that presents itself as empirically observed
//! claims an observation this seam cannot have, so it is refused by
//! `claims_unproven_empirical_stu`, matching this crate's own rule at
//! `crates/eliot-engine/src/context_contracts.rs:166`. That refusal IS load
//! bearing for the closure: without it an `empirical: true` STU could present
//! itself as the bound observation and reach `Demote`.
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
//! RESIDUAL, reported rather than faked: this seam still cannot PRODUCE a bound
//! measurement. `EXACT_TOKENIZER` is admitted here so the status gate is
//! genuinely conditional rather than a constant `false`, but nothing in the
//! repository emits a route-bound tokenizer observation for a memory record,
//! so in production the arm still never fires on cost. Closing that last gap -
//! a producer plus the serializer/profile/content bindings the audit's wider
//! repairs demand - is `eliot-app` and #704/#584 owner work outside this unit,
//! and it is not faked here. What this change does guarantee is the enforced
//! property the audit asked for: an UNBOUND value can no longer reach `Demote`
//! through this seam, whichever producer later appears.
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

/// The #704 owner spelling of the tokenizer-proven measurement status.
///
/// This is `eliot_context_contracts::MeasurementStatus::ExactTokenizer`
/// (`crates/smart/eliot-context-contracts/src/measurement.rs:15`) under the same
/// `SCREAMING_SNAKE_CASE` spelling. It is named for the owner's existing value,
/// not coined here, and it is the status `SerializedContextMeasurement::proves_fit`
/// accepts alongside `ExactUtf8` (`:181-188`) while refusing `ConservativeStu`,
/// `Unknown` and `Unavailable` (`:189-191`).
///
/// It is admitted here only together with a real `actual_tokens` count. That is
/// the whole point of AUD4 repair 5: without it the seam has exactly one
/// admissible state, every admitted value is an unvalidated STU, and a status
/// gate on the scalar would be a constant `false` that disables the demotion
/// policy instead of constraining it. Admitting the owner's proven status is
/// what lets the `> 512` comparison be genuinely conditional.
pub const CONTEXT_COST_STATUS_EXACT_TOKENIZER: &str = "EXACT_TOKENIZER";

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
    ///
    /// This is now enforced, not only documented: `empirical: true` is refused
    /// by `claims_unproven_empirical_stu` and the payload contributes nothing.
    /// See the module note on why that refusal is load bearing.
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
    /// The owner measurement status.
    ///
    /// Admitted values are the owner's own
    /// [`CONTEXT_COST_STATUS_CONSERVATIVE_STU`] (unvalidated planning evidence,
    /// NOT fit-proving) and [`CONTEXT_COST_STATUS_EXACT_TOKENIZER`] (a genuine
    /// route-tokenizer observation, fit-proving). Any other status is refused.
    pub measurement_status: String,
    /// The exact tokenizer observation.
    ///
    /// Under `CONSERVATIVE_STU` it must be present and explicitly `null`: an
    /// unvalidated STU carries no actual-token count, and a non-null claim
    /// without its own route/model/tokenizer binding is refused rather than
    /// believed. Under `EXACT_TOKENIZER` it must be a real number, which is the
    /// value this seam admits to the scalar policy field.
    pub actual_tokens: Value,
    /// The conservative STU estimate this payload contributes.
    pub stu_estimate: ContextCostStuEstimate,
}

impl ContextCostMeasurement {
    /// Whether this payload declares the accepted revision and serializer.
    ///
    /// Revision and serializer are compared here rather than deserialized into
    /// the owner's enums so that a future revision is a refused measurement, not
    /// a decode failure that reads as corruption. The measurement status is
    /// checked separately, because the two admitted statuses carry different
    /// amounts of proof.
    #[must_use]
    pub fn declares_accepted_revision(&self) -> bool {
        self.adapter_revision == CONTEXT_COST_ADAPTER_REVISION
            && self.serializer_id == CONTEXT_COST_SERIALIZER_ID
    }

    /// Whether this payload's declared status is the unvalidated STU estimate.
    #[must_use]
    pub fn declares_conservative_stu(&self) -> bool {
        self.measurement_status == CONTEXT_COST_STATUS_CONSERVATIVE_STU
    }

    /// Whether this payload's declared status is a proven tokenizer observation.
    #[must_use]
    pub fn declares_exact_tokenizer(&self) -> bool {
        self.measurement_status == CONTEXT_COST_STATUS_EXACT_TOKENIZER
    }

    /// Whether this payload claims an actual token count without a binding.
    ///
    /// Under the conservative-STU status there is no route tokenizer behind the
    /// number, so a present, non-null `actual_tokens` is a claim this seam cannot
    /// admit and it refuses the whole payload instead of reading the STU out of
    /// it. Under the exact-tokenizer status a real count is the bound evidence
    /// itself and is not "unbound".
    #[must_use]
    pub fn claims_unbound_actual_tokens(&self) -> bool {
        self.declares_conservative_stu() && !self.actual_tokens.is_null()
    }

    /// Whether this STU presents itself as empirically observed.
    ///
    /// An STU estimate is unvalidated planning evidence; nothing in this contract
    /// observes a route tokenizer, so `empirical: true` is a payload claiming an
    /// observation that does not exist behind it. It is refused here for the
    /// same reason `SkillContextEnvelopeMeasurement::validate` refuses it at
    /// `crates/eliot-engine/src/context_contracts.rs:166`
    /// (`|| self.stu_estimate.empirical` -> `ContextError::UnknownMeasurement`).
    /// That is this crate's own established convention, not a new rule, and it
    /// is also what the `#704` owner means by "never proves route fit"
    /// (`crates/smart/eliot-context-contracts/src/measurement.rs:93`).
    #[must_use]
    pub fn claims_unproven_empirical_stu(&self) -> bool {
        self.stu_estimate.empirical
    }

    /// Whether this measurement is a proven, capacity-deciding observation.
    ///
    /// `True` only for a real tokenizer observation under the exact-tokenizer
    /// status. A conservative STU is `false` even at an enormous value, because
    /// the owner groups `ConservativeStu` with `Unknown` and `Unavailable` in
    /// `SerializedContextMeasurement::proves_fit`
    /// (`crates/smart/eliot-context-contracts/src/measurement.rs:189-191`) and
    /// refuses to let any of them decide fit.
    ///
    /// This is the predicate that keeps an unvalidated STU from being read as a
    /// policy decision: `deterministic_item_finding` and `vitality_from_ledger`
    /// gate their `> 512` comparison on the scalar carrying only proven values.
    #[must_use]
    pub fn proves_cost_disposition(&self) -> bool {
        self.declares_exact_tokenizer() && self.actual_tokens.is_u64()
    }

    /// The Context cost this payload carries, in the unit it declared.
    ///
    /// For a proven observation this is the observed `actual_tokens` count, and
    /// otherwise it is the conservative STU estimate. Returning the STU for a
    /// proven payload would relabel an unvalidated estimate as an observed
    /// count, which is the exact confusion the audit named, so the proven value
    /// is taken from the tokenizer observation instead. `as_u64` yields `None`
    /// for anything that is not an in-range unsigned number, in which case this
    /// falls back to the STU and `proves_cost_disposition` is `false` anyway.
    ///
    /// Only meaningful on an [`Self::is_admissible`] payload; a caller reads this
    /// together with [`Self::proves_cost_disposition`] to know which unit the
    /// number is in.
    #[must_use]
    pub fn proven_value(&self) -> u64 {
        self.actual_tokens
            .as_u64()
            .unwrap_or(self.stu_estimate.value)
    }

    /// Whether every requirement for admitting this payload is met.
    ///
    /// Both admitted statuses must additionally be internally consistent: the
    /// conservative-STU form must carry `actual_tokens: null` and a non-empirical
    /// STU, and the exact-tokenizer form must carry a real `actual_tokens` number
    /// (its bound proof). Anything inconsistent is refused as unknown evidence.
    #[must_use]
    pub fn is_admissible(&self) -> bool {
        if !self.declares_accepted_revision() || self.claims_unbound_actual_tokens() {
            return false;
        }
        if self.claims_unproven_empirical_stu() {
            return false;
        }
        if self.declares_conservative_stu() {
            // The unvalidated form must present no actual-token count.
            return self.actual_tokens.is_null();
        }
        if self.declares_exact_tokenizer() {
            // The proven form must present the real observed count.
            return self.actual_tokens.is_u64();
        }
        // An unsupported status is never measured.
        false
    }
}

/// One admissible Context-cost measurement, with its proven status attached.
///
/// The `value` alone is not a decision. `proven` is what tells the caller whether
/// that number is a capacity-deciding observation or an unvalidated planning
/// estimate, and it is carried alongside the value precisely so a consumer cannot
/// read the bare number and lose the status that gives it meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextCostObservation {
    /// The conservative STU the payload declares.
    pub value: u64,
    /// Whether this value is a proven, bound observation (see
    /// [`ContextCostMeasurement::proves_cost_disposition`]).
    pub proven: bool,
}

/// Read the Context-cost measurement a payload carries, with its proven status.
///
/// An absent, malformed, unversioned or unsupported payload yields `None`
/// (unknown), never zero, one, or a legacy bare estimate. An admissible payload
/// reports `proven: true` only for a bound tokenizer observation; a conservative
/// STU is read but reports `proven: false`, because it is real evidence that is
/// not a capacity-deciding one. Only a `proven: true` observation may enter the
/// scalar policy field that `deterministic_item_finding` and
/// `vitality_from_ledger` compare against, so an unvalidated STU can never be
/// read as a decision. The typed arithmetic failure path is
/// [`checked_context_cost_add`], which uses `ContextError::Overflow` rather than
/// a silent saturation.
#[must_use]
pub fn canonical_context_cost_observation(payload: &Value) -> Option<ContextCostObservation> {
    let measure: ContextCostMeasurement =
        serde_json::from_value(payload.get("measurement")?.clone()).ok()?;
    if !measure.is_admissible() {
        return None;
    }
    Some(ContextCostObservation {
        value: measure.proven_value(),
        proven: measure.proves_cost_disposition(),
    })
}

/// Add one measured STU to a running total without saturating.
///
/// An unrepresentable total is refused as `ContextError::Overflow`, the same
/// typed failure this crate's byte accumulation already uses, instead of
/// silently becoming `u64::MAX` and reading as an enormous policy cost.
pub fn checked_context_cost_add(current: u64, measured: u64) -> Result<u64, ContextError> {
    current.checked_add(measured).ok_or(ContextError::Overflow)
}
