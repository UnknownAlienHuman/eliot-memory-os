use crate::{ProjectId, SkillId, TaskId, VerifierPlan, WriteReceiptRef};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillCardV2 {
    pub skill_id: SkillId,
    pub name: String,
    pub purpose: String,
    pub level: SkillLevel,
    pub lifecycle_state: SkillLifecycleState,
    pub applies_when: Vec<SkillScopeRule>,
    pub does_not_apply_when: Vec<SkillScopeRule>,
    pub required_inputs: Vec<SkillInputRequirement>,
    pub ordered_steps: Vec<SkillStep>,
    pub required_tools_and_capabilities: Vec<SkillToolRequirement>,
    pub expected_outputs: Vec<SkillOutputSpec>,
    pub verification_plan: VerifierPlan,
    pub stop_conditions: Vec<String>,
    pub known_failure_modes: Vec<SkillFailureMode>,
    pub rollback_or_recovery: Option<String>,
    pub source_trace_refs: Vec<String>,
    pub replay_result_refs: Vec<String>,
    pub success_count: u64,
    pub failure_count: u64,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_verified_at: Option<OffsetDateTime>,
    pub version: String,
    pub owner: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillLevel {
    Metadata,
    Procedure,
    Executable,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillLifecycleState {
    #[default]
    Candidate,
    Active,
    Stale,
    Archived,
    Quarantined,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillScopeRule {
    pub rule_id: String,
    pub description: String,
    pub positive_examples: Vec<String>,
    pub negative_examples: Vec<String>,
    pub required_evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillInputRequirement {
    pub name: String,
    pub description: String,
    pub required: bool,
    pub source: SkillInputSource,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillInputSource {
    UserPrompt,
    CurrentState,
    CodeCortexReport,
    WorkLease,
    ActionLease,
    VerifierPlan,
    MemoryHandle,
    BlackboardItem,
    MailboxMessage,
    Manual,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillStep {
    pub step_id: String,
    pub order: u32,
    pub instruction: String,
    pub expected_observation: Option<String>,
    pub required_tool_or_capability: Option<String>,
    pub stop_if_fails: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillToolRequirement {
    pub capability: String,
    pub required: bool,
    pub allowed_tools: Vec<String>,
    pub forbidden_tools: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillOutputSpec {
    pub name: String,
    pub description: String,
    pub evidence_required: bool,
    pub verifier_required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillFailureMode {
    pub failure_id: String,
    pub description: String,
    pub detection_signal: String,
    pub mitigation: String,
    pub negative_memory_refs: Vec<String>,
}

/// The one named boundary of [`SkillContextMeasurementProjection`].
///
/// A versioned projection, not an open record: every other `schema_version`
/// is refused rather than read under the same field names (#880 AUD2, repair 1
/// and 5). It is a version string, not a threshold, cap or policy number.
pub const SKILL_CONTEXT_MEASUREMENT_SCHEMA_VERSION: &str = "eliot-skill-context-measurement/v1";

/// Closed unit of one projected Skill context measurement.
///
/// The unit is carried by the type and never inferred from a field name or
/// from the magnitude of a number. `Stu` is the only unit a Skill envelope
/// reaches without an executed route tokenizer, so a value published under
/// this projection can never be read as an observed token count.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SkillContextMeasurementUnit {
    /// Conservative Source Token Units over the exact serialized bytes.
    Stu,
    /// Exact tokens observed by an executed route tokenizer. Not reachable
    /// from an envelope measurement; named so a claim of it must be refused.
    TokenizerTokens,
    /// The measurement is not present. Absence is typed here, never encoded
    /// inside the numeric value domain.
    Unavailable,
}

/// Why a projected measurement carries its value, or why it does not.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SkillContextMeasurementStatus {
    /// An explicitly permitted unvalidated STU: it is planning evidence and
    /// proves no route fit.
    UnvalidatedStu,
    /// The measurement owner could not produce an observation. `value` is
    /// `None`; this is never zero, cheap or preferred.
    Unavailable,
}

/// Exact route/model/tokenizer observation over the measured bytes.
///
/// `None` on the current path: no tokenizer ran over a `SkillCardV2`
/// envelope, so an actual-token claim is refused rather than approximated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillContextTokenizerObservation {
    pub tokenizer_id: String,
    pub tokenizer_version: String,
    pub tokenizer_hash: String,
    pub tokens: u64,
}

/// Typed unit-qualified projection of one Skill context measurement.
///
/// This is the owner replacement for the bare `Option<u64>` / `u64` / `i64`
/// scalars the Skill lifecycle, influence and curation outputs used to carry
/// (#880 AUD2). Before this type, an unvalidated STU travelled under a field
/// named `context_cost`, `estimated_context_cost` and
/// `context_cost_delta_tokens`, and "unmeasured" travelled as `u64::MAX` in
/// the same `u64` field as a measured value - a sentinel a consumer could
/// add, sum, compare against a budget or persist as an enormous cost. Here
/// absence is [`SkillContextMeasurementStatus::Unavailable`] with
/// `value: None`, the unit is [`SkillContextMeasurementUnit`], and the
/// projected value is sealed to the evidence it was derived from by
/// [`SkillContextMeasurementProjection::value_digest`], so a free-form
/// reference string can no longer stand in for the binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillContextMeasurementProjection {
    pub schema_version: String,
    /// Skill identity the bytes were measured for, with its revision.
    pub skill_ref: String,
    pub skill_version: String,
    /// The measured value, in `unit`. `None` only for `Unavailable`.
    pub value: Option<u64>,
    pub unit: SkillContextMeasurementUnit,
    pub status: SkillContextMeasurementStatus,
    /// Whether the value was calibrated against an observation.
    pub empirical: bool,
    /// Exact serialized UTF-8 byte length the value was derived from.
    pub rendered_utf8_bytes: u64,
    pub serializer_id: String,
    pub serializer_version: String,
    pub serializer_options_digest: String,
    pub serializer_profile_digest: String,
    /// Digest of the exact serialized bytes, from the measurement owner.
    pub content_digest: String,
    /// Absent actual-token observation: the estimated-versus-actual
    /// distinction is a recorded field, not an inference from a magnitude.
    pub actual_tokens: Option<SkillContextTokenizerObservation>,
    /// blake3 seal over this whole projected body, `content_digest` included,
    /// in the fixed length-prefixed order of [`Self::seal`].
    ///
    /// This is the projection's own seal, not the content digest: it binds the
    /// projected value to the evidence it was derived from, so a stored cost
    /// cannot be edited, relabelled or re-pointed at another Skill's bytes
    /// without invalidating itself.
    pub value_digest: String,
}

/// Why a projected measurement was refused.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SkillContextMeasurementError {
    #[error("skill context measurement schema_version `{actual}` is not `{expected}`")]
    UnsupportedSchemaVersion { expected: String, actual: String },

    #[error("skill context measurement field {0} must not be empty")]
    EmptyField(&'static str),

    #[error("skill context measurement field {0} must be a 64-character hex digest")]
    MalformedDigest(&'static str),

    #[error("skill context measurement {0} is not accepted by its own unit and status")]
    UnitStatusMismatch(&'static str),

    #[error("skill context measurement value_digest does not bind this projected body")]
    ValueDigestMismatch,

    #[error(
        "skill context measurement unit {claimed} cannot carry a tokenizer observation ({observed})"
    )]
    UnitNotRefutedByObservation { claimed: &'static str, observed: &'static str },

    #[error("skill context measurement aggregation overflowed the projected total")]
    ValueOverflow,
}

/// Seal one field and its value into the projection's blake3 hasher.
///
/// Length-prefixed in a fixed order so no pair of adjacent fields can be
/// transposed into the same digest.
fn seal_skill_context_field(hasher: &mut blake3::Hasher, field: &str, value: &str) {
    for part in [field, value] {
        let length = u64::try_from(part.len()).unwrap_or(u64::MAX);
        hasher.update(&length.to_le_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.update(&[0x1f_u8]);
}

/// Marker for an absent optional field inside the seal, chosen so it cannot
/// equal any value a projected field could actually carry.
const SKILL_CONTEXT_SEAL_ABSENT: &str = "\u{0}absent";

/// Seal one numeric field whose value is produced here rather than owned by
/// the projection.
///
/// The borrowed fields seal straight from their `&str`, because the projection
/// owns them. These three - `value`, `empirical`'s byte length and
/// `rendered_utf8_bytes` - are computed from the projection rather than stored,
/// so each is formatted into one owned buffer and sealed from it. That is what
/// keeps the sealed field order in [`SkillContextMeasurementProjection::seal`]
/// a flat sequence of one call per field instead of a table that has to hold
/// `String` for every row to keep its numeric rows in it.
fn seal_skill_context_number(hasher: &mut blake3::Hasher, field: &str, value: u64) {
    let formatted = value.to_string();
    seal_skill_context_field(hasher, field, &formatted);
}

fn is_hex_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl SkillContextMeasurementProjection {
    /// Seal the projected body, value, unit and status included.
    ///
    /// The seal is blake3 over the body fields in a fixed, length-prefixed
    /// order, so mutating a value, relabelling a unit or promoting an
    /// unvalidated STU to an observed token count invalidates it instead of
    /// being accepted under the same field names (#880 AUD2, repairs 2 and 3:
    /// "a free-form reference string is insufficient").
    #[must_use]
    fn seal(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        seal_skill_context_field(&mut hasher, "schema_version", &self.schema_version);
        seal_skill_context_field(&mut hasher, "skill_ref", &self.skill_ref);
        seal_skill_context_field(&mut hasher, "skill_version", &self.skill_version);
        // `value` is `None` only for an unavailable projection, which the seal
        // records as the absent marker rather than as a number: an absent
        // measurement can never seal to the same digest as a measured zero.
        match self.value {
            Some(value) => seal_skill_context_number(&mut hasher, "value", value),
            None => seal_skill_context_field(&mut hasher, "value", SKILL_CONTEXT_SEAL_ABSENT),
        }
        seal_skill_context_field(&mut hasher, "unit", self.unit_label());
        seal_skill_context_field(&mut hasher, "status", self.status_label());
        seal_skill_context_number(&mut hasher, "empirical", u64::from(self.empirical));
        seal_skill_context_number(
            &mut hasher,
            "rendered_utf8_bytes",
            self.rendered_utf8_bytes,
        );
        seal_skill_context_field(&mut hasher, "serializer_id", &self.serializer_id);
        seal_skill_context_field(&mut hasher, "serializer_version", &self.serializer_version);
        seal_skill_context_field(
            &mut hasher,
            "serializer_options_digest",
            &self.serializer_options_digest,
        );
        seal_skill_context_field(
            &mut hasher,
            "serializer_profile_digest",
            &self.serializer_profile_digest,
        );
        seal_skill_context_field(&mut hasher, "content_digest", &self.content_digest);
        match &self.actual_tokens {
            Some(tokenizer) => {
                hasher.update(&[1_u8]);
                seal_skill_context_field(&mut hasher, "tokenizer_id", &tokenizer.tokenizer_id);
                seal_skill_context_field(
                    &mut hasher,
                    "tokenizer_version",
                    &tokenizer.tokenizer_version,
                );
                seal_skill_context_field(
                    &mut hasher,
                    "tokenizer_hash",
                    &tokenizer.tokenizer_hash,
                );
                seal_skill_context_number(&mut hasher, "tokens", tokenizer.tokens);
            }
            None => hasher.update(&[0_u8]),
        }
        hasher.finalize().to_hex().to_string()
    }

    /// The unit this projection's value is expressed in.
    fn unit_label(self) -> &'static str {
        match self.unit {
            SkillContextMeasurementUnit::Stu => "STU",
            SkillContextMeasurementUnit::TokenizerTokens => "TOKENIZER_TOKENS",
            SkillContextMeasurementUnit::Unavailable => "UNAVAILABLE",
        }
    }

    fn status_label(self) -> &'static str {
        match self.status {
            SkillContextMeasurementStatus::UnvalidatedStu => "UNVALIDATED_STU",
            SkillContextMeasurementStatus::Unavailable => "UNAVAILABLE",
        }
    }

    /// Compute the seal that binds this projected body.
    #[must_use]
    pub fn compute_value_digest(&self) -> String {
        self.seal()
    }

    /// Validate the closed record, its unit/status pairing and its seal.
    ///
    /// Fails closed: an unsupported version, a malformed digest, a unit that
    /// does not match its own value and status, a tokenizer observation under a
    /// non-tokenizer unit, or a body that no longer matches its recorded
    /// `value_digest` is refused rather than read.
    ///
    /// # Errors
    ///
    /// Returns the typed reason the projection is not readable as evidence.
    pub fn validate(&self) -> Result<(), SkillContextMeasurementError> {
        if self.schema_version != SKILL_CONTEXT_MEASUREMENT_SCHEMA_VERSION {
            return Err(SkillContextMeasurementError::UnsupportedSchemaVersion {
                expected: SKILL_CONTEXT_MEASUREMENT_SCHEMA_VERSION.to_owned(),
                actual: self.schema_version.clone(),
            });
        }
        for (field, value) in [
            ("skill_ref", self.skill_ref.as_str()),
            ("skill_version", self.skill_version.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(SkillContextMeasurementError::EmptyField(field));
            }
        }
        // Absence is typed. A measured value must name the serializer and
        // profile it was measured under and bind the exact bytes; an
        // unavailable projection carries no such evidence and is required to
        // carry none, so "not measured" cannot be dressed in a borrowed
        // binding. The identity of the Skill the measurement was requested
        // for is carried either way and is never itself evidence.
        let expected_unit = match self.status {
            SkillContextMeasurementStatus::UnvalidatedStu => SkillContextMeasurementUnit::Stu,
            SkillContextMeasurementStatus::Unavailable => SkillContextMeasurementUnit::Unavailable,
        };
        if self.unit != expected_unit {
            return Err(SkillContextMeasurementError::UnitStatusMismatch("unit"));
        }
        if self.value.is_some() != requires_measured_value(self.status) {
            return Err(SkillContextMeasurementError::UnitStatusMismatch("value"));
        }
        if self.actual_tokens.is_some() && self.unit != SkillContextMeasurementUnit::TokenizerTokens
        {
            return Err(SkillContextMeasurementError::UnitNotRefutedByObservation {
                claimed: "non-tokenizer",
                observed: "present",
            });
        }
        if self.status == SkillContextMeasurementStatus::UnvalidatedStu {
            for (field, value) in [
                ("serializer_id", self.serializer_id.as_str()),
                ("serializer_version", self.serializer_version.as_str()),
            ] {
                if value.trim().is_empty() {
                    return Err(SkillContextMeasurementError::EmptyField(field));
                }
            }
            for (field, value) in [
                (
                    "serializer_options_digest",
                    self.serializer_options_digest.as_str(),
                ),
                (
                    "serializer_profile_digest",
                    self.serializer_profile_digest.as_str(),
                ),
                ("content_digest", self.content_digest.as_str()),
            ] {
                if !is_hex_digest(value) {
                    return Err(SkillContextMeasurementError::MalformedDigest(field));
                }
            }
        }
        if let Some(tokenizer) = &self.actual_tokens {
            if tokenizer.tokenizer_id.trim().is_empty()
                || tokenizer.tokenizer_version.trim().is_empty()
            {
                return Err(SkillContextMeasurementError::EmptyField("actual_tokens"));
            }
            if !is_hex_digest(&tokenizer.tokenizer_hash) {
                return Err(SkillContextMeasurementError::MalformedDigest(
                    "actual_tokens.tokenizer_hash",
                ));
            }
        }
        if self.seal() != self.value_digest {
            return Err(SkillContextMeasurementError::ValueDigestMismatch);
        }
        Ok(())
    }

    /// The measured value in its declared unit, for a caller that has
    /// validated the projection.
    ///
    /// `None` for an unavailable projection. Callers that have not validated
    /// the record are reading a claim; the value cannot be promoted to an
    /// actual token count by this method.
    #[must_use]
    pub fn validated_value(&self) -> Option<u64> {
        self.validate().ok().and_then(|()| self.value)
    }

    /// The conservative STU this projection published, if it published one.
    ///
    /// Returns `None` for an unavailable projection, so a caller cannot read
    /// an absent measurement as a cost of zero.
    #[must_use]
    pub fn stu_value(&self) -> Option<u64> {
        match self.status {
            SkillContextMeasurementStatus::UnvalidatedStu
                if self.unit == SkillContextMeasurementUnit::Stu =>
            {
                self.validated_value()
            }
            SkillContextMeasurementStatus::UnvalidatedStu
            | SkillContextMeasurementStatus::Unavailable => None,
        }
    }

    /// Typed absence when the measurement is unavailable or unknown.
    ///
    /// This is the replacement for the `u64::MAX` sentinel: it names the
    /// unavailable state in the type and keeps a number out of the field
    /// entirely, so an unmeasured envelope can no longer be added to,
    /// compared against a budget, or persisted as an enormous cost. The
    /// unavailable projection still names the Skill it was asked about, so
    /// "not measured" is not the same record as "no Skill".
    ///
    /// The identity fields are named as measured - they are the Skill the
    /// measurement was requested for - while no measurement evidence is
    /// invented for it: value, byte length, serializer/profile and content
    /// digest are all absent, and
    /// [`SkillContextMeasurementError::EmptyField`] is what refuses the
    /// binding of a projection whose measurement failed.
    #[must_use]
    pub fn unavailable(skill_ref: &SkillId, skill_version: &str) -> Self {
        Self::sealed(Self {
            schema_version: SKILL_CONTEXT_MEASUREMENT_SCHEMA_VERSION.to_owned(),
            skill_ref: skill_ref.to_string(),
            skill_version: skill_version.to_owned(),
            value: None,
            unit: SkillContextMeasurementUnit::Unavailable,
            status: SkillContextMeasurementStatus::Unavailable,
            empirical: false,
            rendered_utf8_bytes: 0,
            serializer_id: String::new(),
            serializer_version: String::new(),
            serializer_options_digest: String::new(),
            serializer_profile_digest: String::new(),
            content_digest: String::new(),
            actual_tokens: None,
            value_digest: String::new(),
        })
    }

    /// Publish a sealed projection of a measured value, computing its digest.
    #[must_use]
    pub fn sealed(mut projection: Self) -> Self {
        projection.value_digest = projection.compute_value_digest();
        projection
    }
}

/// Whether a status may carry a measured value.
const fn requires_measured_value(status: SkillContextMeasurementStatus) -> bool {
    matches!(
        status,
        SkillContextMeasurementStatus::UnvalidatedStu
    )
}

/// Aggregate the STU projections of several Skill envelopes.
///
/// Checked: an overflow is typed [`SkillContextMeasurementError::ValueOverflow`]
/// rather than saturating into a value that reads as an enormous measured
/// cost (#880 AUD2 repair 2). The result stays in the unit and status of its
/// parts and never crosses into a token claim. `Ok(None)` means no part carried
/// a measured STU, which is typed absence rather than a total of zero.
pub fn sum_skill_context_stu(
    projections: &[SkillContextMeasurementProjection],
) -> Result<Option<SkillContextMeasurementProjection>, SkillContextMeasurementError> {
    let measured: Vec<&SkillContextMeasurementProjection> = projections
        .iter()
        .filter(|projection| projection.status == SkillContextMeasurementStatus::UnvalidatedStu)
        .collect();
    let Some(first) = measured.first() else {
        return Ok(None);
    };
    // One binding for the aggregate: every part is a total over the same
    // serializer, profile and measurement contract, so the sum inherits that
    // binding and seals its own value over the ordered chain of the parts'
    // own content digests. A part measured under another serializer or
    // profile cannot be folded into this total unnoticed.
    for projection in &measured {
        projection.validate()?;
        if projection.serializer_id != first.serializer_id
            || projection.serializer_version != first.serializer_version
            || projection.serializer_options_digest != first.serializer_options_digest
            || projection.serializer_profile_digest != first.serializer_profile_digest
        {
            return Err(SkillContextMeasurementError::UnitStatusMismatch(
                "serializer_profile",
            ));
        }
    }
    let mut total = 0_u64;
    let mut rendered_utf8_bytes = 0_u64;
    let mut chain_hasher = blake3::Hasher::new();
    for projection in &measured {
        let value = projection
            .value
            .ok_or(SkillContextMeasurementError::UnitStatusMismatch("value"))?;
        total = total
            .checked_add(value)
            .ok_or(SkillContextMeasurementError::ValueOverflow)?;
        rendered_utf8_bytes = rendered_utf8_bytes
            .checked_add(projection.rendered_utf8_bytes)
            .ok_or(SkillContextMeasurementError::ValueOverflow)?;
        seal_skill_context_field(
            &mut chain_hasher,
            "content_digest",
            &projection.content_digest,
        );
    }
    Ok(Some(SkillContextMeasurementProjection::sealed(
        SkillContextMeasurementProjection {
            schema_version: SKILL_CONTEXT_MEASUREMENT_SCHEMA_VERSION.to_owned(),
            skill_ref: format!(
                "aggregate-of-{}",
                measured
                    .iter()
                    .map(|projection| projection.skill_ref.as_str())
                    .collect::<Vec<_>>()
                    .join("+")
            ),
            skill_version: SKILL_CONTEXT_MEASUREMENT_SCHEMA_VERSION.to_owned(),
            value: Some(total),
            unit: SkillContextMeasurementUnit::Stu,
            status: SkillContextMeasurementStatus::UnvalidatedStu,
            empirical: false,
            rendered_utf8_bytes,
            serializer_id: first.serializer_id.clone(),
            serializer_version: first.serializer_version.clone(),
            serializer_options_digest: first.serializer_options_digest.clone(),
            serializer_profile_digest: first.serializer_profile_digest.clone(),
            content_digest: chain_hasher.finalize().to_hex().to_string(),
            actual_tokens: None,
            value_digest: String::new(),
        },
    )))
}

/// Decoder: derived and closed. The `#[serde(default)]` evidence vectors and
/// optional promotion fields are kept: missing historical holdout, transfer,
/// source or approval data decodes as absent, never as promotion evidence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillLifecycleRecord {
    pub record_id: String,
    pub skill_ref: SkillId,
    pub state: SkillLifecycleState,
    pub uses: u64,
    pub successes: u64,
    pub failures: u64,
    /// Unit-qualified measurement of this record's Skill envelope.
    ///
    /// Was `Option<u64>` named `context_cost` and carrying a bare unvalidated
    /// STU, with `None` meaning "measurement absent" and no record of the
    /// unit, status or evidence the number came from (#880 AUD2). The
    /// projection carries the unit, the status, the exact byte length, the
    /// serializer/profile/content binding and the seal over its own value, so
    /// a stored cost can no longer be read as an actual token count.
    pub context_measurement: SkillContextMeasurementProjection,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_verified: Option<OffsetDateTime>,
    pub where_applies: Vec<SkillScopeRule>,
    pub where_not_apply: Vec<SkillScopeRule>,
    pub promotion_evidence: Vec<String>,
    #[serde(default)]
    pub source_case_refs: Vec<String>,
    #[serde(default)]
    pub source_pattern_refs: Vec<String>,
    #[serde(default)]
    pub mechanism_refs: Vec<String>,
    #[serde(default)]
    pub local_check_refs: Vec<String>,
    #[serde(default)]
    pub transfer_evidence_refs: Vec<String>,
    #[serde(default)]
    pub holdout_evidence_refs: Vec<String>,
    #[serde(default)]
    pub negative_transfer_refs: Vec<String>,
    #[serde(default)]
    pub promotion_outcome: Option<ProcedurePromotionOutcome>,
    #[serde(default)]
    pub rollback_ref: Option<String>,
    pub demotion_reason: Option<String>,
    pub archive_or_restore_receipt: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcedurePromotionOutcome {
    Promoted,
    KeptTransferValidated,
    SplitNarrower,
    Demoted,
    Rejected,
    NotReadyForProcedure,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillNeedEstimate {
    pub estimate_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub candidate_skill: SkillId,
    pub necessity: f64,
    pub utility: f64,
    pub distractor_risk: f64,
    pub verdict: SkillNeedVerdict,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillNeedVerdict {
    Include,
    Exclude,
    RequireMoreContext,
    AuditOnly,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillDistractorFilter {
    pub filter_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub skills_considered: Vec<SkillId>,
    pub skills_included: Vec<SkillId>,
    pub distractors_removed: Vec<SkillId>,
    pub reasons: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillExecutionProof {
    pub proof_id: String,
    pub skill_ref: SkillId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub steps_used: Vec<String>,
    pub skipped_steps: Vec<String>,
    pub outputs: Vec<String>,
    pub verifier_refs: Vec<String>,
    pub outcome: SkillExecutionOutcome,
    pub failure_mode_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillExecutionOutcome {
    Succeeded,
    Failed,
    Partial,
    AbortedByStopCondition,
    NotApplicable,
    NegativeTransfer,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillInteractionMatrix {
    pub matrix_id: String,
    pub project_id: ProjectId,
    pub skills: Vec<SkillId>,
    pub conflicts: Vec<SkillConflict>,
    pub required_ordering: Vec<SkillOrderingRule>,
    pub mutual_exclusion: Vec<Vec<SkillId>>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillConflict {
    pub conflict_id: String,
    pub skill_a: SkillId,
    pub skill_b: SkillId,
    pub reason: String,
    pub resolution_policy: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillOrderingRule {
    pub before: SkillId,
    pub after: SkillId,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillInfluenceReport {
    pub report_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub packet_id: Option<String>,
    pub skills_considered: Vec<SkillId>,
    pub skills_included: Vec<SkillId>,
    pub skills_excluded: Vec<SkillId>,
    pub skills_executed: Vec<SkillId>,
    pub execution_proofs: Vec<String>,
    /// Unit-qualified total over the reported Skills' canonical envelopes.
    ///
    /// Was `estimated_context_cost: u64` and carried a sum of unvalidated STU
    /// values, with an absent or failed measurement written as `u64::MAX` in
    /// the same field a measured total used - an ordinary `u64` a consumer
    /// could add, sum, compare against a budget or persist as an enormous
    /// cost (#880 AUD2). Absence is now
    /// [`SkillContextMeasurementStatus::Unavailable`] with `value: None`;
    /// no control state is encoded in the numeric domain.
    pub context_measurement: SkillContextMeasurementProjection,
    pub observed_decision_delta: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillActivationDecision {
    Allow,
    ExcludeNotApplicable,
    ExcludeMissingInputs,
    ExcludeMissingVerifier,
    ExcludeLifecycleState,
    ExcludeConflict,
    ExcludeNegativeMemory,
    AuditOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillActivationRecord {
    pub skill_ref: SkillId,
    pub decision: SkillActivationDecision,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProceduralSkillPacketView {
    pub included_skills: Vec<SkillId>,
    pub excluded_skills: Vec<SkillId>,
    pub activation_decisions: Vec<SkillActivationRecord>,
    pub distractors_removed: Vec<SkillId>,
    pub required_verifiers: Vec<String>,
    pub anti_scope_warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillCuratorRun {
    pub run_id: String,
    pub project_id: ProjectId,
    pub project: String,
    pub status: SkillCuratorRunStatus,
    pub dry_run: bool,
    pub skills_scanned: Vec<SkillId>,
    pub usage_sources: Vec<String>,
    pub proposals: Vec<SkillCurationProposal>,
    pub rejected_actions: Vec<SkillCurationRejectedAction>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillCuratorRunStatus {
    DryRunComplete,
    Complete,
    Partial,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillCurationProposal {
    pub proposal_id: String,
    pub project_id: ProjectId,
    pub skill_ref: SkillId,
    pub skill_name: String,
    pub action: SkillCurationAction,
    pub reason: SkillCurationReason,
    pub expected_effect: SkillCurationExpectedEffect,
    pub risks: Vec<SkillCurationRisk>,
    pub rollback_plan: SkillCurationRollbackPlan,
    pub replay_requirement: SkillReplayRequirement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<SkillPatchProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge: Option<SkillMergeProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split: Option<SkillSplitProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<SkillArchiveProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine: Option<SkillQuarantineProposal>,
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_decision: Option<SkillCurationGateDecision>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillCurationAction {
    Keep,
    Patch,
    Merge,
    Split,
    Archive,
    Quarantine,
    Promote,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillCurationReason {
    RepeatedSuccess,
    MissingWhereNotApply,
    LowUtilityHighCost,
    NegativeTransfer,
    OverbroadSkill,
    DuplicateSkill,
    ManualReview,
}

/// A signed curation effect measured in conservative Source Token Units.
///
/// The value is typed into its unit: it cannot be read as a token count,
/// because reading it requires naming `Stu`. The unit travels in the name and
/// in the type, so the wire name can no longer claim tokens for an STU
/// arithmetic result (#880 AUD2 repair 4).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SkillContextStuDelta(pub i64);

impl SkillContextStuDelta {
    /// The zero delta, in STU. Zero means "this proposal changes no measured
    /// envelope", which is distinct from "the envelope was not measured": an
    /// unmeasured envelope yields [`Option::None`] at the projection, not a
    /// zero STU claim.
    pub const ZERO: Self = Self(0);

    /// Scale this STU delta by a positive divisor, preserving the sign.
    #[must_use]
    pub const fn divided_by_stu(self, divisor: i64) -> Self {
        Self(self.0 / divisor)
    }

    /// Negate this STU delta.
    #[must_use]
    pub const fn negated_stu(self) -> Self {
        Self(self.0.saturating_neg())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillCurationExpectedEffect {
    pub summary: String,
    pub utility_delta: f64,
    /// Signed curation effect over the Skill envelope, in conservative STU.
    ///
    /// Was `context_cost_delta_tokens: i64`, a field whose wire name claimed
    /// tokens for a value `expected_context_delta` derived from unvalidated
    /// STU with no route/model/tokenizer evidence (#880 AUD2). Retyped rather
    /// than merely renamed so the unit is carried by the type: a caller must
    /// name `SkillContextStuDelta` to hold the number. No actual-token delta
    /// exists on this path, so none is expressed.
    pub context_cost_delta_stu: SkillContextStuDelta,
    pub risk_delta: f64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillCurationRisk {
    pub severity: String,
    pub description: String,
    pub mitigation: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillCurationRollbackPlan {
    pub steps: Vec<String>,
    pub restores_previous_skill: bool,
    pub retained_audit_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillReplayRequirement {
    pub required: bool,
    pub reason: String,
    pub replay_marker: Option<String>,
    pub verifier_refs: Vec<String>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillPatchProposal {
    pub target_skill: SkillId,
    pub patch_summary: String,
    pub candidate_content_ref: String,
    pub narrows_scope: bool,
    pub broadens_scope: bool,
    pub removes_anti_scope: bool,
    pub weakens_verifier: bool,
    pub reviewer_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillMergeProposal {
    pub source_skills: Vec<SkillId>,
    pub merged_skill_name: String,
    pub duplicate_evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillSplitProposal {
    pub source_skill: SkillId,
    pub split_names: Vec<String>,
    pub scope_boundaries: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillArchiveProposal {
    pub target_skill: SkillId,
    pub retained_for_audit: bool,
    pub memory_policy_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillQuarantineProposal {
    pub target_skill: SkillId,
    pub negative_transfer_refs: Vec<String>,
    pub memory_policy_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillCurationGateDecision {
    pub proposal_id: String,
    pub decision: SkillCurationDecisionKind,
    pub reasons: Vec<SkillCurationGateReason>,
    pub allowed_action: Option<SkillCurationAction>,
    pub reviewer_required: bool,
    pub replay_required: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillCurationDecisionKind {
    Allow,
    AllowReadOnly,
    RequireReview,
    RequireReplay,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillCurationGateReason {
    ActionAllowed,
    ReadOnlyReportAllowed,
    AutoPromotionDenied,
    MissingReplayForScopeBroadening,
    RemovingAntiScopeDenied,
    VerifierWeakeningDenied,
    MissingEvidence,
    IncidentLockdown,
    SafeArchiveAllowed,
    SafeQuarantineAllowed,
    SafePatchAllowed,
    DestructiveDeleteDenied,
    UnsupportedAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillCurationReceipt {
    pub receipt_id: String,
    pub proposal_id: String,
    pub project_id: ProjectId,
    pub skill_ref: SkillId,
    pub action: SkillCurationAction,
    pub applied: bool,
    pub summary: String,
    pub rollback_plan: SkillCurationRollbackPlan,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillCurationRejectedAction {
    pub proposal_id: String,
    pub attempted_action: SkillCurationAction,
    pub reason: SkillCurationGateReason,
    #[serde(with = "time::serde::rfc3339")]
    pub rejected_at: OffsetDateTime,
}
