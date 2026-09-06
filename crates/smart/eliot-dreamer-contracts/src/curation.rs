//! Closed curation-kind and payload contracts.
//!
//! Cell `smart.dreamer.contracts` (Level-0, candidate-only, fail-closed).
//! Owns the exact 11 wire kinds of `I9.6 CurationCandidate`, one closed
//! payload schema per kind, and the wire-kind to handler-family spelling map.
//! No handler, screening, runtime, or provider behavior lives here.

use crate::error::ContractViolation;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Canonical wire spellings of all 11 curation kinds, in canonical order.
pub const CURATION_WIRE_KINDS: &[&str] = &[
    "classification",
    "relation",
    "episode",
    "concept",
    "procedure",
    "failure",
    "merge",
    "split",
    "reconsolidation",
    "accessibility",
    "repair",
];

/// Closed curation-kind discriminator (`I9.6 CurationCandidate.kind`).
///
/// Exactly 11 variants. Family-level spellings (`structure_repair`,
/// `memory_repair`) and architecture job spellings are wire kinds of nothing
/// and are rejected by [`parse_kind`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CurationKind {
    Classification,
    Relation,
    Episode,
    Concept,
    Procedure,
    Failure,
    Merge,
    Split,
    Reconsolidation,
    Accessibility,
    Repair,
}

impl CurationKind {
    /// Returns the canonical wire spelling of this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Classification => "classification",
            Self::Relation => "relation",
            Self::Episode => "episode",
            Self::Concept => "concept",
            Self::Procedure => "procedure",
            Self::Failure => "failure",
            Self::Merge => "merge",
            Self::Split => "split",
            Self::Reconsolidation => "reconsolidation",
            Self::Accessibility => "accessibility",
            Self::Repair => "repair",
        }
    }
}

/// Parses a wire spelling into its closed kind.
///
/// # Errors
///
/// Returns [`ContractViolation::UnknownVariant`] with `field == "wire_kind"`
/// for family spellings (`structure_repair`, `memory_repair`), architecture
/// subtype spellings, and every other unknown value.
pub fn parse_kind(value: &str) -> Result<CurationKind, ContractViolation> {
    match value {
        "classification" => Ok(CurationKind::Classification),
        "relation" => Ok(CurationKind::Relation),
        "episode" => Ok(CurationKind::Episode),
        "concept" => Ok(CurationKind::Concept),
        "procedure" => Ok(CurationKind::Procedure),
        "failure" => Ok(CurationKind::Failure),
        "merge" => Ok(CurationKind::Merge),
        "split" => Ok(CurationKind::Split),
        "reconsolidation" => Ok(CurationKind::Reconsolidation),
        "accessibility" => Ok(CurationKind::Accessibility),
        "repair" => Ok(CurationKind::Repair),
        _ => Err(ContractViolation::UnknownVariant {
            field: "wire_kind",
            value: value.to_owned(),
        }),
    }
}

/// Closed classification payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassificationPayload {
    pub label: String,
    pub confidence_bps: u32,
}

/// Closed relation payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationPayload {
    pub from_handle: String,
    pub to_handle: String,
    pub relation: String,
}

/// Closed episode payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpisodePayload {
    pub episode: String,
    pub observed_at_ms: u64,
}

/// Closed concept payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptPayload {
    pub concept: String,
    pub definition: String,
}

/// Closed procedure payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcedurePayload {
    pub procedure: String,
    pub steps: u32,
}

/// Closed failure payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailurePayload {
    pub fingerprint: String,
    pub signature: String,
}

/// Closed merge payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergePayload {
    pub left: String,
    pub right: String,
    pub merged: String,
}

/// Closed split payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SplitPayload {
    pub whole: String,
    pub first: String,
    pub second: String,
}

/// Closed reconsolidation payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconsolidationPayload {
    pub target: String,
    pub update: String,
}

/// Closed accessibility payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccessibilityPayload {
    pub handle: String,
    pub note: String,
}

/// Closed repair payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepairPayload {
    pub target: String,
    pub repair: String,
}

/// Exactly one closed payload per wire kind, discriminated by `kind`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CurationPayload {
    Classification(ClassificationPayload),
    Relation(RelationPayload),
    Episode(EpisodePayload),
    Concept(ConceptPayload),
    Procedure(ProcedurePayload),
    Failure(FailurePayload),
    Merge(MergePayload),
    Split(SplitPayload),
    Reconsolidation(ReconsolidationPayload),
    Accessibility(AccessibilityPayload),
    Repair(RepairPayload),
}

fn non_blank(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if value.trim().is_empty() {
        return Err(ContractViolation::Malformed {
            field,
            reason: "must be non-blank".to_owned(),
        });
    }
    Ok(())
}

impl CurationPayload {
    /// Returns the wire kind carried by this payload.
    #[must_use]
    pub fn kind(&self) -> CurationKind {
        match self {
            Self::Classification(_) => CurationKind::Classification,
            Self::Relation(_) => CurationKind::Relation,
            Self::Episode(_) => CurationKind::Episode,
            Self::Concept(_) => CurationKind::Concept,
            Self::Procedure(_) => CurationKind::Procedure,
            Self::Failure(_) => CurationKind::Failure,
            Self::Merge(_) => CurationKind::Merge,
            Self::Split(_) => CurationKind::Split,
            Self::Reconsolidation(_) => CurationKind::Reconsolidation,
            Self::Accessibility(_) => CurationKind::Accessibility,
            Self::Repair(_) => CurationKind::Repair,
        }
    }

    /// Validates intrinsic bounds: every text field is non-blank and
    /// `confidence_bps` stays within `0..=10000`.
    ///
    /// # Errors
    ///
    /// Returns a [`ContractViolation`] on the first blank field or when
    /// `confidence_bps` exceeds 10000 basis points.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        match self {
            Self::Classification(p) => {
                non_blank(&p.label, "label")?;
                if p.confidence_bps > 10_000 {
                    return Err(ContractViolation::OutOfBounds {
                        field: "confidence_bps",
                        min: 0,
                        max: 10_000,
                        got: i64::from(p.confidence_bps),
                    });
                }
            }
            Self::Relation(p) => {
                non_blank(&p.from_handle, "from_handle")?;
                non_blank(&p.to_handle, "to_handle")?;
                non_blank(&p.relation, "relation")?;
            }
            Self::Episode(p) => {
                non_blank(&p.episode, "episode")?;
            }
            Self::Concept(p) => {
                non_blank(&p.concept, "concept")?;
                non_blank(&p.definition, "definition")?;
            }
            Self::Procedure(p) => {
                non_blank(&p.procedure, "procedure")?;
            }
            Self::Failure(p) => {
                non_blank(&p.fingerprint, "fingerprint")?;
                non_blank(&p.signature, "signature")?;
            }
            Self::Merge(p) => {
                non_blank(&p.left, "left")?;
                non_blank(&p.right, "right")?;
                non_blank(&p.merged, "merged")?;
            }
            Self::Split(p) => {
                non_blank(&p.whole, "whole")?;
                non_blank(&p.first, "first")?;
                non_blank(&p.second, "second")?;
            }
            Self::Reconsolidation(p) => {
                non_blank(&p.target, "target")?;
                non_blank(&p.update, "update")?;
            }
            Self::Accessibility(p) => {
                non_blank(&p.handle, "handle")?;
                non_blank(&p.note, "note")?;
            }
            Self::Repair(p) => {
                non_blank(&p.target, "target")?;
                non_blank(&p.repair, "repair")?;
            }
        }
        Ok(())
    }
}

/// Routes raw JSON to exactly the payload schema named by `kind`.
///
/// The `kind` tag is peeked before full decoding (no trial-decoding across
/// schemas), so a payload tagged with any other kind is rejected without
/// attempting a coercing decode.
///
/// # Errors
///
/// Returns [`ContractViolation::KindPayload`] when the embedded tag differs
/// from `kind`, and [`ContractViolation::Malformed`] when the JSON is not a
/// valid payload of the tagged kind.
pub fn route_payload(kind: CurationKind, json: &str) -> Result<CurationPayload, ContractViolation> {
    #[derive(Deserialize)]
    struct KindTag {
        kind: CurationKind,
    }
    let tag: KindTag = serde_json::from_str(json).map_err(|err| ContractViolation::Malformed {
        field: "curation_payload",
        reason: err.to_string(),
    })?;
    if tag.kind != kind {
        return Err(ContractViolation::KindPayload(format!(
            "expected payload for {}, found {}",
            kind.as_str(),
            tag.kind.as_str()
        )));
    }
    serde_json::from_str(json).map_err(|err| ContractViolation::Malformed {
        field: "curation_payload",
        reason: err.to_string(),
    })
}

/// Maps a wire kind to its handler-family spelling.
///
/// The ten family spellings collapse the eleven wire kinds: `merge` and
/// `split` both map to `structure_repair`, `repair` maps to `memory_repair`,
/// and every other kind maps to its own spelling. `registry.rs` converts
/// these spellings into [`crate::registry::CurationFamily`].
#[must_use]
pub const fn kind_family(kind: CurationKind) -> &'static str {
    match kind {
        CurationKind::Classification => "classification",
        CurationKind::Relation => "relation",
        CurationKind::Episode => "episode",
        CurationKind::Concept => "concept",
        CurationKind::Procedure => "procedure",
        CurationKind::Failure => "failure",
        CurationKind::Merge | CurationKind::Split => "structure_repair",
        CurationKind::Reconsolidation => "reconsolidation",
        CurationKind::Accessibility => "accessibility",
        CurationKind::Repair => "memory_repair",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn valid_payload(kind: CurationKind) -> CurationPayload {
        match kind {
            CurationKind::Classification => {
                CurationPayload::Classification(ClassificationPayload {
                    label: "memory".to_owned(),
                    confidence_bps: 9_000,
                })
            }
            CurationKind::Relation => CurationPayload::Relation(RelationPayload {
                from_handle: "h-from".to_owned(),
                to_handle: "h-to".to_owned(),
                relation: "refines".to_owned(),
            }),
            CurationKind::Episode => CurationPayload::Episode(EpisodePayload {
                episode: "ep-7".to_owned(),
                observed_at_ms: 1_700_000_000_000,
            }),
            CurationKind::Concept => CurationPayload::Concept(ConceptPayload {
                concept: "fence".to_owned(),
                definition: "state dependency".to_owned(),
            }),
            CurationKind::Procedure => CurationPayload::Procedure(ProcedurePayload {
                procedure: "rotate".to_owned(),
                steps: 3,
            }),
            CurationKind::Failure => CurationPayload::Failure(FailurePayload {
                fingerprint: "fp-1".to_owned(),
                signature: "sig-1".to_owned(),
            }),
            CurationKind::Merge => CurationPayload::Merge(MergePayload {
                left: "a".to_owned(),
                right: "b".to_owned(),
                merged: "ab".to_owned(),
            }),
            CurationKind::Split => CurationPayload::Split(SplitPayload {
                whole: "ab".to_owned(),
                first: "a".to_owned(),
                second: "b".to_owned(),
            }),
            CurationKind::Reconsolidation => {
                CurationPayload::Reconsolidation(ReconsolidationPayload {
                    target: "mem-1".to_owned(),
                    update: "refresh".to_owned(),
                })
            }
            CurationKind::Accessibility => CurationPayload::Accessibility(AccessibilityPayload {
                handle: "h-1".to_owned(),
                note: "captioned".to_owned(),
            }),
            CurationKind::Repair => CurationPayload::Repair(RepairPayload {
                target: "mem-2".to_owned(),
                repair: "relink".to_owned(),
            }),
        }
    }

    // WORK_UNIT_CASE: 578/21
    #[test]
    fn case_21_wire_kinds_exact_order_and_roundtrip() {
        assert_eq!(
            CURATION_WIRE_KINDS,
            &[
                "classification",
                "relation",
                "episode",
                "concept",
                "procedure",
                "failure",
                "merge",
                "split",
                "reconsolidation",
                "accessibility",
                "repair",
            ]
        );
        assert_eq!(CURATION_WIRE_KINDS.len(), 11);
        for spelling in CURATION_WIRE_KINDS {
            let kind = parse_kind(spelling).expect("known wire kind");
            assert_eq!(kind.as_str(), *spelling);
            let json = serde_json::to_string(&kind).expect("serialize kind");
            assert_eq!(json, format!("\"{spelling}\""));
            let back: CurationKind = serde_json::from_str(&json).expect("deserialize kind");
            assert_eq!(back, kind);
        }
    }

    // WORK_UNIT_CASE: 578/24
    #[test]
    fn case_24_merge_split_distinct_but_same_family() {
        assert_ne!(CurationKind::Merge, CurationKind::Split);
        assert_eq!(CurationKind::Merge.as_str(), "merge");
        assert_eq!(CurationKind::Split.as_str(), "split");
        assert_eq!(kind_family(CurationKind::Merge), "structure_repair");
        assert_eq!(kind_family(CurationKind::Split), "structure_repair");
        let merge = valid_payload(CurationKind::Merge);
        let split = valid_payload(CurationKind::Split);
        assert_ne!(merge, split);
        assert_eq!(merge.kind(), CurationKind::Merge);
        assert_eq!(split.kind(), CurationKind::Split);
    }

    // WORK_UNIT_CASE: 578/25
    #[test]
    fn case_25_family_spellings_rejected_as_wire_kinds() {
        for spelling in ["structure_repair", "memory_repair", "other"] {
            let err = parse_kind(spelling).expect_err("must reject");
            assert_eq!(
                err,
                ContractViolation::UnknownVariant {
                    field: "wire_kind",
                    value: spelling.to_owned(),
                }
            );
            let json = format!("\"{spelling}\"");
            let decoded: Result<CurationKind, _> = serde_json::from_str(&json);
            assert!(decoded.is_err(), "serde must reject {spelling}");
        }
    }

    // WORK_UNIT_CASE: 578/26
    #[test]
    fn case_26_no_architecture_subtypes_as_wire_kinds() {
        for spelling in [
            "a39",
            "a-39",
            "architecture_self_query",
            "classification_v2",
            "",
            "MERGE",
        ] {
            let err = parse_kind(spelling).expect_err("must reject");
            assert_eq!(
                err,
                ContractViolation::UnknownVariant {
                    field: "wire_kind",
                    value: spelling.to_owned(),
                }
            );
        }
    }

    // WORK_UNIT_CASE: 578/27
    #[test]
    fn case_27_valid_payload_for_every_wire_kind() {
        assert_eq!(CURATION_WIRE_KINDS.len(), 11);
        for spelling in CURATION_WIRE_KINDS {
            let kind = parse_kind(spelling).expect("known wire kind");
            let payload = valid_payload(kind);
            assert_eq!(payload.kind(), kind);
            payload.validate().expect("valid payload");
            let json = serde_json::to_string(&payload).expect("serialize");
            assert!(json.contains(&format!("\"kind\":\"{spelling}\"")));
            let routed = route_payload(kind, &json).expect("route");
            assert_eq!(routed, payload);
            let direct: CurationPayload = serde_json::from_str(&json).expect("direct decode");
            assert_eq!(direct, payload);
        }
    }

    // WORK_UNIT_CASE: 578/28
    #[test]
    fn case_28_wrong_kind_payload_pairing_rejected() {
        let kind = CurationKind::Classification;
        let json = serde_json::to_string(&valid_payload(kind)).expect("serialize");
        let err = route_payload(CurationKind::Relation, &json).expect_err("tag mismatch must fail");
        assert!(
            matches!(err, ContractViolation::KindPayload(_)),
            "unexpected: {err:?}"
        );
        // Internally-tagged decode keeps the true variant: no silent coercion.
        let direct: CurationPayload = serde_json::from_str(&json).expect("direct decode");
        assert_eq!(direct.kind(), CurationKind::Classification);
        assert_ne!(direct.kind(), CurationKind::Relation);
        // Malformed input is malformed, not a kind/payload mismatch.
        let malformed = route_payload(kind, "{not json").expect_err("malformed must fail");
        assert!(
            matches!(
                malformed,
                ContractViolation::Malformed {
                    field: "curation_payload",
                    ..
                }
            ),
            "unexpected: {malformed:?}"
        );
        // Unknown tag spelling is an unknown wire kind, surfaced as malformed
        // JSON for the payload envelope (serde rejects the tag first).
        let unknown_tag =
            route_payload(kind, r#"{"kind":"other"}"#).expect_err("unknown tag must fail");
        assert!(
            matches!(unknown_tag, ContractViolation::Malformed { .. }),
            "unexpected: {unknown_tag:?}"
        );
        // Blank fields and out-of-range confidence fail intrinsic validation.
        let blank = CurationPayload::Classification(ClassificationPayload {
            label: "  ".to_owned(),
            confidence_bps: 9_000,
        });
        assert!(blank.validate().is_err());
        let overconfident = CurationPayload::Classification(ClassificationPayload {
            label: "memory".to_owned(),
            confidence_bps: 10_001,
        });
        assert_eq!(
            overconfident.validate().expect_err("must fail"),
            ContractViolation::OutOfBounds {
                field: "confidence_bps",
                min: 0,
                max: 10_000,
                got: 10_001,
            }
        );
    }
}
