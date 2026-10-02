//! Explicit legacy wire forms for the #783 MCP measurement records.
//!
//! #783 removed the last local `/4` character estimator from the MCP
//! measurement paths: no MCP measurement path takes a character count, and
//! every figure published here is measured by the canonical #704 owner
//! [`super::canonical_serialized_measurement`] over the exact final
//! serialized UTF-8 bytes the caller already holds, so these records carry
//! canonical `STU = ceil(bytes / 3)` evidence exactly like the
//! current wire forms. What this module still owns is the *shape* those
//! historical records were published in: a form that predates the current
//! measurement and is therefore kept separate, separately named and
//! separately decoded.
//!
//! # W9, A21, A22
//!
//! A legacy record's *shape* is a historical fact that cannot be re-measured,
//! so the only honest way to carry it is to carry it under its own unit tag and
//! its own explicit status, never renamed into the current fields. Each legacy
//! form here is therefore:
//!
//! 1. a **distinct shape**, not the current record under a different label;
//! 2. **unit-tagged** (`legacy_unit`) with a value that names what the number
//!    actually is, plus a `legacy_status` that says it is an unvalidated
//!    planning estimate rather than a tokenizer observation;
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
//! There is no `From<Legacy…>` into the current form, and the two forms are
//! told apart by *wire shape and discriminator*, not by field names. Note
//! honestly that one field name IS deliberately shared:
//! [`LegacyMemoryTokenUnitsMeasurement::record_ref`] and
//! `MemoryDistillationCorpusItem::record_ref` carry the same value
//! (`"canonical:<record_id>"`), so `record_ref` is the intentional join key a
//! consumer uses to pair a legacy figure with the current corpus item for the
//! same record. That shared key is a correlation handle, never a channel for
//! the numbers: the legacy figure lives under `legacy_unit` / `legacy_status`
//! and has no field a current decoder reads. A legacy record is a *description
//! of a historical estimate*, never a current claim.
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
//! is never promoted to an observed token count by any path here.

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
/// #783 retired the historical `ceil(chars / 4)` estimator, so the number a
/// legacy record now carries is the canonical #704 planning unit produced by
/// [`super::canonical_serialized_measurement`]: `ceil(exact serialized UTF-8
/// bytes / 3)`. This names that basis explicitly. It is still not an observed
/// token count: no tokenizer ran on either leg, so no variant here can be read
/// as a token observation, and the enum deliberately has no such variant.
///
/// The *shape* - a separate wire form beside the current measurement, never
/// merged into it - is the only thing that stays historical. The number inside
/// it is measured on exactly the same serialized bytes as the current figure it
/// sits beside.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum LegacyCharacterUnit {
    /// The canonical #704 `STU = ceil(serialized UTF-8 bytes / 3)` estimate,
    /// measured by the canonical owner over the record's own exact serialized
    /// bytes. Retained under this historical type name so the legacy wire form
    /// keeps its exact shape; it is no longer a `/4` character ratio.
    CanonicalStuEstimate,
}

/// The honest status every legacy figure carries.
///
/// `Estimated` is the whole point: the figure is a conservative STU planning
/// estimate over exact bytes, never an observation from a tokenizer. It must
/// not be upgraded to `actual`, and this type offers no `actual` variant, so no
/// legacy record can serialize a token observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum LegacyEstimateStatus {
    /// Canonical #704 STU estimate over exact serialized bytes; no tokenizer
    /// was involved, so the actual count stays unknown rather than becoming a
    /// fabricated number.
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
    /// What the number below actually is. Never an observed `tokens` count;
    /// it is the [`LegacyCharacterUnit`] planning unit beside it.
    pub(super) legacy_unit: LegacyCharacterUnit,
    /// Honest status: an unvalidated planning estimate, never an observation.
    pub(super) legacy_status: LegacyEstimateStatus,
    /// The exact serialized UTF-8 byte length the canonical owner measured.
    pub(super) legacy_serialized_bytes: u64,
    /// The canonical #704 `ceil(bytes / 3)` figure over exactly those bytes.
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
    /// What the number below actually is. Never an observed `tokens` count;
    /// it is the [`LegacyCharacterUnit`] planning unit beside it.
    pub(super) legacy_unit: LegacyCharacterUnit,
    /// Honest status: an unvalidated planning estimate, never an observation.
    pub(super) legacy_status: LegacyEstimateStatus,
    /// The exact serialized UTF-8 byte length the canonical owner measured.
    pub(super) legacy_serialized_bytes: u64,
    /// The canonical #704 `ceil(bytes / 3)` figure over exactly those bytes.
    pub(super) legacy_estimate_units: u64,
    /// Always `None`. A legacy record never becomes an actual token claim.
    pub(super) actual_tokens: Option<u64>,
}

/// Build the legacy tool description form from the record's exact serialized
/// UTF-8 bytes.
///
/// #783. The input is `serialized`: the final bytes the caller measures, not a
/// character count. The canonical #704 owner
/// [`super::canonical_serialized_measurement`] is the only thing that turns
/// those bytes into a number, so this record's figure is `ceil(bytes / 3)`
/// measured by that owner and can never be reproduced by a local ratio.
///
/// A byte-denominated record given only a character count would have to invent
/// the missing bytes, so all three call sites pass real serialized bytes: the
/// per-tool description slice, the concatenated combined descriptions, and the
/// memory adapter's own `serde_json` serialization of the record body. Nothing
/// here converts characters to bytes or to tokens, and a caller with no
/// serialized bytes has no honest way to build this record at all - it reaches a
/// typed error rather than a fabricated estimate.
pub(super) fn legacy_tool_description_measurement(
    tool_name: &str,
    serialized: &[u8],
) -> Result<LegacyToolDescriptionMeasurement> {
    let measurement = super::canonical_serialized_measurement(serialized)
        .context("canonical measurement for the legacy tool description wire form")?;
    Ok(LegacyToolDescriptionMeasurement {
        wire_form: LEGACY_TOOL_WIRE_FORM.to_owned(),
        tool_name: tool_name.to_owned(),
        legacy_unit: LegacyCharacterUnit::CanonicalStuEstimate,
        legacy_status: LegacyEstimateStatus::Estimated,
        legacy_serialized_bytes: measurement.byte_len,
        legacy_estimate_units: measurement.stu_estimate,
        actual_tokens: None,
    })
}

/// Build the legacy memory `token_units` form from the record's exact
/// serialized UTF-8 bytes.
///
/// #783. Same construct-from-real-bytes contract as
/// [`legacy_tool_description_measurement`], and the same canonical #704 owner.
pub(super) fn legacy_memory_token_units_measurement(
    record_ref: &str,
    serialized: &[u8],
) -> Result<LegacyMemoryTokenUnitsMeasurement> {
    let measurement = super::canonical_serialized_measurement(serialized)
        .context("canonical measurement for the legacy memory token_units wire form")?;
    Ok(LegacyMemoryTokenUnitsMeasurement {
        wire_form: LEGACY_MEMORY_WIRE_FORM.to_owned(),
        record_ref: record_ref.to_owned(),
        legacy_unit: LegacyCharacterUnit::CanonicalStuEstimate,
        legacy_status: LegacyEstimateStatus::Estimated,
        legacy_serialized_bytes: measurement.byte_len,
        legacy_estimate_units: measurement.stu_estimate,
        actual_tokens: None,
    })
}

/// Build the legacy tool description wire form, admitted by the closed decoder.
///
/// This is the only way a legacy tool record reaches the wire. The record is
/// built from the caller's exact serialized bytes by the canonical #704 owner,
/// serialized, and then read back through [`decode_legacy_tool_measurement`] —
/// so the form this surface publishes is by construction a form the decoder
/// admits, and the two cannot drift apart. The returned value is the admitted
/// record, so no caller ever has to round-trip a value it does not use.
pub(super) fn legacy_tool_description_wire(tool_name: &str, serialized: &[u8]) -> Result<Value> {
    let record = legacy_tool_description_measurement(tool_name, serialized)?;
    let wire =
        serde_json::to_value(&record).context("serialize legacy tool description wire form")?;
    decode_legacy_tool_measurement(&wire)?;
    Ok(wire)
}

/// Build the legacy memory `token_units` wire form, admitted by the closed decoder.
///
/// The same construct-then-admit contract as [`legacy_tool_description_wire`],
/// over the same canonical #704 owner.
pub(super) fn legacy_memory_token_units_wire_value(
    record_ref: &str,
    serialized: &[u8],
) -> Result<Value> {
    let record = legacy_memory_token_units_measurement(record_ref, serialized)?;
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
/// reinterprets a legacy figure as an observed token count.
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

#[cfg(test)]
mod legacy_wire_canonical_owner_tests {
    use super::*;
    use crate::mcp_stdio::canonical_serialized_measurement;
    use serde_json::json;

    /// One multi-byte CJK scalar: three UTF-8 bytes, one `char`. It is the
    /// multiplier this module's fixtures use so the two candidate owners are
    /// driven far apart by construction.
    const CJK_SCALAR: &str = "\u{4f60}\u{597d}\u{4e16}\u{754c}";

    /// A multi-byte payload where the retired `ceil(chars / 4)` estimator and
    /// the canonical `ceil(bytes / 3)` owner disagree by a wide margin.
    ///
    /// 40 CJK scalars are 120 UTF-8 bytes, so the retired character estimator
    /// published 10 units where the canonical owner publishes 40. The two
    /// assertions below pin BOTH of those numbers exactly, so a leg that
    /// reverted to dividing a character count by four could not satisfy this
    /// fixture: `120 / 3 = 40` and `40 / 4 = 10` are far apart, and the
    /// `assert_ne!` records that separation rather than trusting it.
    ///
    /// This is a function rather than a `const` because `str::repeat` yields a
    /// `String`; a `const &str` would not compile. A test fixture is the
    /// honest place for that allocation: the production path below never
    /// divides a character count at all.
    fn cjk_description() -> String {
        CJK_SCALAR.repeat(10)
    }

    /// Positive case, tool-description leg: the legacy figure is the canonical
    /// owner's own value over the caller's exact serialized bytes.
    ///
    /// This drives the real production builder, so it proves the whole leg
    /// (`legacy_tool_description_wire` -> canonical owner -> closed decoder)
    /// rather than a reconstruction of it.
    #[test]
    fn tool_description_legacy_figure_comes_from_the_canonical_owner() -> Result<()> {
        let description = cjk_description();
        let serialized = description.as_bytes();
        let canonical = canonical_serialized_measurement(serialized)?;
        assert_eq!(canonical.byte_len, 120);
        assert_eq!(canonical.stu_estimate, 40);
        // The retired character estimator published 10 for this payload. Both
        // numbers are pinned exactly, so neither owner can be satisfied by the
        // other's expression.
        assert_eq!(description.chars().count(), 40);
        assert_ne!(canonical.stu_estimate, 10);

        let wire = legacy_tool_description_wire("eliot_current_state", serialized)?;
        assert_eq!(wire["legacy_serialized_bytes"], json!(120));
        assert_eq!(wire["legacy_estimate_units"], json!(canonical.stu_estimate));
        assert_eq!(wire["legacy_unit"], json!("canonical_stu_estimate"));
        assert_eq!(wire["legacy_status"], json!("estimated"));
        assert_eq!(wire["actual_tokens"], Value::Null);
        // The legacy figure and the current figure are bound to one payload, so
        // they cannot drift: the byte length on the wire is the very length the
        // canonical owner measured, not a re-counted character basis.
        assert_eq!(wire["legacy_serialized_bytes"], json!(canonical.byte_len));
        Ok(())
    }

    /// Refusal case, tool-description leg: the closed decoder still refuses the
    /// current form and the retired unit tag rather than admitting them.
    ///
    /// #783 changed the number's owner, not the boundary: a legacy record is
    /// still the only thing these decoders admit, and a retired `/4` unit tag
    /// is now an unnamed value rather than an accepted one.
    #[test]
    fn tool_description_decoder_refuses_current_form_and_retired_unit() {
        let description = cjk_description();
        let serialized = description.as_bytes();
        let admitted = legacy_tool_description_wire("eliot_current_state", serialized)
            .expect("canonical bytes are admitted");

        let mut current_form = admitted.clone();
        current_form["wire_form"] = json!("eliot-part-e-description-estimate/current");
        assert!(
            decode_legacy_tool_measurement(&current_form).is_err(),
            "the decoder must not admit the current wire form"
        );

        let mut retired_unit = admitted.clone();
        retired_unit["legacy_unit"] = json!("characters_divided_by_four");
        assert!(
            decode_legacy_tool_measurement(&retired_unit).is_err(),
            "the retired /4 unit tag must not be admitted"
        );

        // The record this module does build is still admitted, so the
        // refusals above are discrimination rather than a blanket failure.
        assert!(decode_legacy_tool_measurement(&admitted).is_ok());
    }

    /// Positive case, memory leg: the legacy figure is the canonical owner's
    /// own value over the record's exact serialized bytes.
    #[test]
    fn memory_legacy_figure_comes_from_the_canonical_owner() -> Result<()> {
        let payload = json!({ "note": cjk_description() });
        let serialized = serde_json::to_vec(&payload)?;
        let canonical = canonical_serialized_measurement(&serialized)?;
        assert_eq!(canonical.byte_len, 131);
        assert_eq!(canonical.stu_estimate, 44);
        // The retired character estimator published 13 for this payload; the
        // canonical owner publishes 44 over the very same bytes. Both are
        // pinned exactly, so neither expression can satisfy this fixture.
        assert_eq!(String::from_utf8(serialized.clone())?.chars().count(), 51);
        assert_ne!(canonical.stu_estimate, 13);

        let wire = legacy_memory_token_units_wire_value("canonical:record-1", &serialized)?;
        assert_eq!(wire["legacy_serialized_bytes"], json!(131));
        assert_eq!(wire["legacy_estimate_units"], json!(44));
        assert_eq!(wire["legacy_unit"], json!("canonical_stu_estimate"));
        assert_eq!(wire["legacy_status"], json!("estimated"));
        assert_eq!(wire["actual_tokens"], Value::Null);
        Ok(())
    }

    /// Refusal case, memory leg: the memory decoder is closed on the same terms
    /// as the tool decoder, including the retired unit tag.
    #[test]
    fn memory_decoder_refuses_current_form_and_retired_unit() {
        let payload = json!({ "note": cjk_description() });
        let serialized = serde_json::to_vec(&payload).expect("fixture payload serializes");
        let admitted = legacy_memory_token_units_wire_value("canonical:record-1", &serialized)
            .expect("canonical bytes are admitted");

        let mut current_form = admitted.clone();
        current_form["wire_form"] = json!("eliot-memory-token-units-estimate/current");
        assert!(
            decode_legacy_memory_measurement(&current_form).is_err(),
            "the decoder must not admit the current wire form"
        );

        let mut retired_unit = admitted.clone();
        retired_unit["legacy_unit"] = json!("characters_divided_by_four");
        assert!(
            decode_legacy_memory_measurement(&retired_unit).is_err(),
            "the retired /4 unit tag must not be admitted"
        );

        assert!(decode_legacy_memory_measurement(&admitted).is_ok());
    }

    /// A payload the canonical owner refuses must never reach the legacy wire.
    ///
    /// The legacy forms are byte-denominated, so a non-UTF-8 payload has no
    /// honest byte measurement. It has to be a typed failure rather than a
    /// fabricated estimate - the failure mode that made the old `/4`
    /// character estimator attractive in the first place.
    #[test]
    fn non_utf8_payload_is_refused_by_the_canonical_owner() {
        let invalid = [0xff_u8, 0xfe, 0xfd];
        assert!(
            legacy_tool_description_wire("eliot_current_state", &invalid).is_err(),
            "non-UTF-8 bytes must not become a legacy estimate"
        );
        assert!(
            legacy_memory_token_units_wire_value("canonical:record-1", &invalid).is_err(),
            "non-UTF-8 bytes must not become a legacy estimate"
        );
    }
}
