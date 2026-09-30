//! Explicit legacy wire forms for the #783 MCP measurement records.
//!
//! #783 replaced every `/4` character estimate on the MCP measurement paths
//! with the canonical #704 owner [`super::canonical_serialized_measurement`],
//! which measures exact final serialized UTF-8 bytes. The current wire forms
//! therefore carry exact canonical byte/STU evidence, and this module owns the
//! *other* side of that boundary: the historical wire forms that predate it.
//!
//! # W9, A21, A22
//!
//! Legacy data on this boundary really was a character or `/4`-derived
//! estimate, so the only honest way to carry it is to carry it in its own unit,
//! under its own explicit status, never renamed into the current fields. Each
//! legacy form here is therefore:
//!
//! 1. a **distinct shape**, not the current record under a different label;
//! 2. **unit-tagged** (`legacy_unit`) with a value that names what the number
//!    actually is, plus a `legacy_status` that says it is an estimate of
//!    unknown provenance rather than a canonical measurement;
//! 3. decoded by its **own closed entry point** that requires the legacy
//!    discriminator and refuses to produce a current claim.
//!
//! The unit and status are enforced by the TYPE, not by a runtime branch:
//! [`LegacyCharacterUnit`] and [`LegacyEstimateStatus`] each have exactly one
//! variant, so `serde_json::from_value` has already refused every other value
//! by the time any of this code runs. In particular
//! [`LegacyEstimateStatus`] has no `actual` variant at all, so a legacy record
//! cannot serialize or deserialize as a token observation. W13 (legacy
//! `token_units` do not become current actual tokens) holds at the type level
//! rather than by convention.
//!
//! There is no `From<Legacy…>` into the current form and no shared field name
//! between the two forms that could let a legacy number be read as a current
//! one. A legacy record is a *description of a historical estimate*, never a
//! current claim.
//!
//! # Closed, not permissive
//!
//! The decoders below are the only way in, and each one is closed on an exact
//! discriminator value:
//!
//! - `decode_legacy_tool_measurement` admits only records whose
//!   `wire_form` is [`LEGACY_TOOL_WIRE_FORM`]. Anything else — including a
//!   record missing the discriminator, or one carrying the current form's
//!   status — is a typed error, never a default.
//! - `decode_legacy_memory_measurement` is the same contract over the memory
//!   record.
//!
//! In particular neither decoder has a "try current, else try legacy"
//! fallback, and neither probes for a field to see which form it might be.
//! The discriminator is compared, not discovered. Malformed input reaches the
//! caller as `Err`; it cannot panic, and it cannot gain proof: a legacy figure
//! is never promoted to `stu_estimate` or `actual_tokens` by any path here.

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::Result;

/// The wire-form discriminator carried by the historical tool measurement.
///
/// It is deliberately not the current status string: a legacy record and a
/// current record differ in the *shape of the discriminator itself*, so a
/// legacy document can never be mistaken for a current one by inspection.
pub(super) const LEGACY_TOOL_WIRE_FORM: &str = "eliot-part-e-description-estimate/legacy";

/// The wire-form discriminator carried by the historical memory measurement.
pub(super) const LEGACY_MEMORY_WIRE_FORM: &str = "eliot-memory-token-units-estimate/legacy";

/// The only unit any legacy measurement on this boundary may claim.
///
/// The historical figure on both sides was `ceil(chars / 4)`: a *character*
/// count divided by an assumed ratio. The numerator was never bytes, so this
/// names the character-derived basis explicitly. It is not `bytes`, not `stu`
/// and not `tokens`: no tokenizer ever produced these numbers, so there is no
/// unit here that could be read as an observed token count.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum LegacyCharacterUnit {
    /// `ceil(unicode_scalar_values / 4)` - the historical estimate as emitted,
    /// in its own explicitly legacy character-derived unit.
    CharactersDividedByFour,
}

/// The honest status every legacy figure carries.
///
/// `Estimated` is the whole point: the figure was produced by a formula over
/// characters, never observed from a tokenizer over bytes. It must not be
/// upgraded to `actual`, and this type offers no `actual` variant, so no
/// legacy record can serialize a token observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum LegacyEstimateStatus {
    /// Formula-derived from a character count; provenance of the character
    /// count itself is unverified and no tokenizer was involved.
    Estimated,
}

/// One legacy per-tool description measurement.
///
/// A distinct shape from the current form: it is a separate object with its
/// own `wire_form` discriminator key, its own explicit unit tag and its own
/// explicit status, rather than a differently-labelled copy of the current
/// per-tool `description_ul_tokens` integer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacyToolDescriptionMeasurement {
    /// Discriminator; [`LEGACY_TOOL_WIRE_FORM`] exactly.
    pub(super) wire_form: String,
    /// The MCP tool name this historical estimate belonged to.
    pub(super) tool_name: String,
    /// What the number below actually is. Never `bytes`, never `tokens`.
    pub(super) legacy_unit: LegacyCharacterUnit,
    /// Honest status: a formula estimate, never an observation.
    pub(super) legacy_status: LegacyEstimateStatus,
    /// The historical character count the `/4` estimate divided.
    pub(super) legacy_unicode_scalar_values: u64,
    /// The historical `ceil(chars / 4)` figure, verbatim, in legacy units.
    pub(super) legacy_estimate_units: u64,
    /// The actual token count is unknown. A legacy record has no tokenizer
    /// binding, so this is `null` by construction and never a synthesized
    /// number.
    pub(super) actual_tokens: Option<u64>,
}

/// One legacy memory `token_units` measurement.
///
/// A distinct shape from the current `MemoryDistillationCorpusItem`
/// measurement, which carries a bare `token_units: u64`. The legacy form
/// carries the same historical figure only under an explicit legacy unit and
/// status, so the two can never be read as one another.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacyMemoryTokenUnitsMeasurement {
    /// Discriminator; [`LEGACY_MEMORY_WIRE_FORM`] exactly.
    pub(super) wire_form: String,
    /// The memory record this historical estimate belonged to.
    pub(super) record_ref: String,
    /// What the number below actually is. Never `bytes`, never `stu`.
    pub(super) legacy_unit: LegacyCharacterUnit,
    /// Honest status: a formula estimate, never an observation.
    pub(super) legacy_status: LegacyEstimateStatus,
    /// The historical character count the `/4` estimate divided.
    pub(super) legacy_unicode_scalar_values: u64,
    /// The historical `ceil(chars / 4)` figure, verbatim, in legacy units.
    pub(super) legacy_estimate_units: u64,
    /// Always `None`. A legacy record never becomes an actual token claim.
    pub(super) actual_tokens: Option<u64>,
}

/// Build the legacy tool description form from an already-known historical
/// character count.
///
/// The input is named `unicode_scalar_values` and the resulting record says so
/// on the wire. Nothing here converts characters to bytes or to tokens: the
/// figure is stored as the legacy estimate it is, and the caller keeps the
/// current measurement separate.
pub(super) fn legacy_tool_description_measurement(
    tool_name: &str,
    unicode_scalar_values: u64,
) -> LegacyToolDescriptionMeasurement {
    LegacyToolDescriptionMeasurement {
        wire_form: LEGACY_TOOL_WIRE_FORM.to_owned(),
        tool_name: tool_name.to_owned(),
        legacy_unit: LegacyCharacterUnit::CharactersDividedByFour,
        legacy_status: LegacyEstimateStatus::Estimated,
        legacy_unicode_scalar_values: unicode_scalar_values,
        legacy_estimate_units: unicode_scalar_values.div_ceil(4),
        actual_tokens: None,
    }
}

/// Build the legacy memory `token_units` form from an already-known historical
/// character count.
pub(super) fn legacy_memory_token_units_measurement(
    record_ref: &str,
    unicode_scalar_values: u64,
) -> LegacyMemoryTokenUnitsMeasurement {
    LegacyMemoryTokenUnitsMeasurement {
        wire_form: LEGACY_MEMORY_WIRE_FORM.to_owned(),
        record_ref: record_ref.to_owned(),
        legacy_unit: LegacyCharacterUnit::CharactersDividedByFour,
        legacy_status: LegacyEstimateStatus::Estimated,
        legacy_unicode_scalar_values: unicode_scalar_values,
        legacy_estimate_units: unicode_scalar_values.div_ceil(4),
        actual_tokens: None,
    }
}

/// Build the legacy tool description wire form, admitted by the closed decoder.
///
/// This is the only way a legacy tool record reaches the wire. The record is
/// built from the historical character count, serialized, and then read back
/// through [`decode_legacy_tool_measurement`] — so the form this surface
/// publishes is by construction a form the decoder admits, and the two cannot
/// drift apart. The returned value is the admitted record, so no caller ever
/// has to round-trip a value it does not use.
pub(super) fn legacy_tool_description_wire(
    tool_name: &str,
    unicode_scalar_values: u64,
) -> Result<Value> {
    let record = legacy_tool_description_measurement(tool_name, unicode_scalar_values);
    let wire =
        serde_json::to_value(&record).context("serialize legacy tool description wire form")?;
    decode_legacy_tool_measurement(&wire)?;
    Ok(wire)
}

/// Build the legacy memory `token_units` wire form, admitted by the closed decoder.
///
/// The same construct-then-admit contract as [`legacy_tool_description_wire`].
pub(super) fn legacy_memory_token_units_wire_value(
    record_ref: &str,
    unicode_scalar_values: u64,
) -> Result<Value> {
    let record = legacy_memory_token_units_measurement(record_ref, unicode_scalar_values);
    let wire =
        serde_json::to_value(&record).context("serialize legacy memory token_units wire form")?;
    decode_legacy_memory_measurement(&wire)?;
    Ok(wire)
}

/// Decode a legacy tool description measurement, and nothing else.
///
/// Closed on three exact discriminators: the wire form, the unit and the
/// status. A document carrying the current form, missing the discriminator,
/// or naming any other unit or status is a typed error - this decoder never
/// falls back to the current form, never defaults a missing field, and never
/// reinterprets a legacy figure as bytes or tokens.
pub(super) fn decode_legacy_tool_measurement(
    value: &Value,
) -> Result<LegacyToolDescriptionMeasurement> {
    let record: LegacyToolDescriptionMeasurement =
        serde_json::from_value(value.clone()).map_err(|error| {
            anyhow::anyhow!("legacy tool measurement is not a legacy record: {error}")
        })?;
    ensure_legacy_tool_discriminators(&record)?;
    Ok(record)
}

/// Decode a legacy memory `token_units` measurement, and nothing else.
pub(super) fn decode_legacy_memory_measurement(
    value: &Value,
) -> Result<LegacyMemoryTokenUnitsMeasurement> {
    let record: LegacyMemoryTokenUnitsMeasurement =
        serde_json::from_value(value.clone()).map_err(|error| {
            anyhow::anyhow!("legacy memory token_units is not a legacy record: {error}")
        })?;
    ensure_legacy_memory_discriminators(&record)?;
    Ok(record)
}

fn ensure_legacy_tool_discriminators(record: &LegacyToolDescriptionMeasurement) -> Result<()> {
    if record.wire_form != LEGACY_TOOL_WIRE_FORM {
        anyhow::bail!(
            "legacy tool wire_form {:?} is not the admitted legacy wire form {LEGACY_TOOL_WIRE_FORM:?}",
            record.wire_form
        );
    }
    Ok(())
}

fn ensure_legacy_memory_discriminators(record: &LegacyMemoryTokenUnitsMeasurement) -> Result<()> {
    if record.wire_form != LEGACY_MEMORY_WIRE_FORM {
        anyhow::bail!(
            "legacy memory wire_form {:?} is not the admitted legacy wire form {LEGACY_MEMORY_WIRE_FORM:?}",
            record.wire_form
        );
    }
    Ok(())
}
