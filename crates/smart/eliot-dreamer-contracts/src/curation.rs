//! Closed curation-kind and payload contracts.
//!
//! Cell `smart.dreamer.contracts` (Level-0, candidate-only, fail-closed).
//! Owns the exact 11 wire kinds of `I9.6 CurationCandidate`, one closed
//! payload schema per kind, and the wire-kind to handler-family spelling map.
//! No handler, screening, runtime, or provider behavior lives here.

use crate::error::{ContractViolation, check_text};
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

/// Exact mutation/semantic target set plus the distinct immutable evidence/reference set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetEvidence {
    pub targets: Vec<String>,
    pub evidence_refs: Vec<String>,
}
impl TargetEvidence {
    pub fn validate(&self, kind_spelling: &'static str) -> Result<(), ContractViolation> {
        if self.targets.is_empty() {
            return Err(ContractViolation::MissingField("targets"));
        }
        for h in &self.targets {
            check_text(h, "targets", MAX_TEXT)?;
        }
        for h in &self.evidence_refs {
            check_text(h, "evidence_refs", MAX_TEXT)?;
        }
        for h in &self.targets {
            if self.evidence_refs.iter().any(|e| e == h) {
                return Err(ContractViolation::KindPayload(std::format!(
                    "{kind_spelling} target {h} must not appear in immutable evidence"
                )));
            }
        }
        Ok(())
    }
}

/// Closed classification payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassificationPayload {
    pub label: String,
    pub confidence_bps: u32,
    pub target_evidence: TargetEvidence,
}

/// Closed relation payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationPayload {
    pub from_handle: String,
    pub to_handle: String,
    pub relation: String,
    pub target_evidence: TargetEvidence,
}

/// Closed episode payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpisodePayload {
    pub episode: String,
    pub observed_at_ms: u64,
    pub target_evidence: TargetEvidence,
}

/// Closed concept payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptPayload {
    pub concept: String,
    pub definition: String,
    pub target_evidence: TargetEvidence,
}

/// Closed procedure payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcedurePayload {
    pub procedure: String,
    pub steps: u32,
    pub target_evidence: TargetEvidence,
}

/// Closed failure payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailurePayload {
    pub fingerprint: String,
    pub signature: String,
    pub target_evidence: TargetEvidence,
}

/// Closed merge payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergePayload {
    pub left: String,
    pub right: String,
    pub merged: String,
    pub target_evidence: TargetEvidence,
}

/// Closed split payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SplitPayload {
    pub whole: String,
    pub first: String,
    pub second: String,
    pub target_evidence: TargetEvidence,
}

/// Closed reconsolidation payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconsolidationPayload {
    pub target: String,
    pub update: String,
    pub target_evidence: TargetEvidence,
}

/// Closed accessibility payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccessibilityPayload {
    pub handle: String,
    pub note: String,
    pub target_evidence: TargetEvidence,
}

/// Closed repair payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepairPayload {
    pub target: String,
    pub repair: String,
    pub target_evidence: TargetEvidence,
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

/// Max bytes admitted for any curation text field.
const MAX_TEXT: usize = 256;

fn check_subjects(
    subjects: &[&String],
    facets: &TargetEvidence,
    kind: &'static str,
) -> Result<(), ContractViolation> {
    for subject in subjects {
        if !facets.targets.contains(subject) {
            return Err(ContractViolation::KindPayload(std::format!(
                "{kind} subject {subject} must be a declared target"
            )));
        }
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

    /// Validates intrinsic bounds plus the target/evidence split.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        match self {
            Self::Classification(p) => {
                check_text(&p.label, "label", MAX_TEXT)?;
                if p.confidence_bps > 10_000 {
                    return Err(ContractViolation::OutOfBounds {
                        field: "confidence_bps",
                        min: 0,
                        max: 10_000,
                        got: i64::from(p.confidence_bps),
                    });
                }
                p.target_evidence.validate("classification")?;
            }
            Self::Relation(p) => {
                check_text(&p.from_handle, "from_handle", MAX_TEXT)?;
                check_text(&p.to_handle, "to_handle", MAX_TEXT)?;
                check_text(&p.relation, "relation", MAX_TEXT)?;
                p.target_evidence.validate("relation")?;
                check_subjects(
                    &[&p.from_handle, &p.to_handle],
                    &p.target_evidence,
                    "relation",
                )?;
            }
            Self::Episode(p) => {
                check_text(&p.episode, "episode", MAX_TEXT)?;
                p.target_evidence.validate("episode")?;
            }
            Self::Concept(p) => {
                check_text(&p.concept, "concept", MAX_TEXT)?;
                check_text(&p.definition, "definition", MAX_TEXT)?;
                p.target_evidence.validate("concept")?;
            }
            Self::Procedure(p) => {
                check_text(&p.procedure, "procedure", MAX_TEXT)?;
                p.target_evidence.validate("procedure")?;
            }
            Self::Failure(p) => {
                check_text(&p.fingerprint, "fingerprint", MAX_TEXT)?;
                check_text(&p.signature, "signature", MAX_TEXT)?;
                p.target_evidence.validate("failure")?;
            }
            Self::Merge(p) => {
                check_text(&p.left, "left", MAX_TEXT)?;
                check_text(&p.right, "right", MAX_TEXT)?;
                check_text(&p.merged, "merged", MAX_TEXT)?;
                p.target_evidence.validate("merge")?;
                check_subjects(&[&p.left, &p.right, &p.merged], &p.target_evidence, "merge")?;
            }
            Self::Split(p) => {
                check_text(&p.whole, "whole", MAX_TEXT)?;
                check_text(&p.first, "first", MAX_TEXT)?;
                check_text(&p.second, "second", MAX_TEXT)?;
                p.target_evidence.validate("split")?;
                check_subjects(
                    &[&p.whole, &p.first, &p.second],
                    &p.target_evidence,
                    "split",
                )?;
            }
            Self::Reconsolidation(p) => {
                check_text(&p.target, "target", MAX_TEXT)?;
                check_text(&p.update, "update", MAX_TEXT)?;
                p.target_evidence.validate("reconsolidation")?;
                check_subjects(&[&p.target], &p.target_evidence, "reconsolidation")?;
            }
            Self::Accessibility(p) => {
                check_text(&p.handle, "handle", MAX_TEXT)?;
                check_text(&p.note, "note", MAX_TEXT)?;
                p.target_evidence.validate("accessibility")?;
                check_subjects(&[&p.handle], &p.target_evidence, "accessibility")?;
            }
            Self::Repair(p) => {
                check_text(&p.target, "target", MAX_TEXT)?;
                check_text(&p.repair, "repair", MAX_TEXT)?;
                p.target_evidence.validate("repair")?;
                check_subjects(&[&p.target], &p.target_evidence, "repair")?;
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn facets(&self) -> &TargetEvidence {
        match self {
            Self::Classification(p) => &p.target_evidence,
            Self::Relation(p) => &p.target_evidence,
            Self::Episode(p) => &p.target_evidence,
            Self::Concept(p) => &p.target_evidence,
            Self::Procedure(p) => &p.target_evidence,
            Self::Failure(p) => &p.target_evidence,
            Self::Merge(p) => &p.target_evidence,
            Self::Split(p) => &p.target_evidence,
            Self::Reconsolidation(p) => &p.target_evidence,
            Self::Accessibility(p) => &p.target_evidence,
            Self::Repair(p) => &p.target_evidence,
        }
    }
}

/// Routes raw JSON to the payload named by `kind`: tag peeked, decoded,
/// validated; wrong/invalid kind/payload fails before routing with no
/// caller-side `validate` needed.
///
/// # Errors
///
/// Returns `KindPayload` on mismatch, `Malformed` on bad JSON/payload.
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
    let payload: CurationPayload =
        serde_json::from_str(json).map_err(|err| ContractViolation::Malformed {
            field: "curation_payload",
            reason: err.to_string(),
        })?;
    payload.validate()?;
    Ok(payload)
}

/// Maps a wire kind to its handler-family spelling (`merge`/`split` collapse
/// to `structure_repair`; see [`crate::registry::CurationFamily`]).
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

/// Samples distinct targets and evidence for tests.
#[cfg(test)]
pub(crate) fn sample_facets() -> TargetEvidence {
    TargetEvidence {
        targets: vec!["a".to_owned(), "b".to_owned(), "ab".to_owned()],
        evidence_refs: vec!["e-1".to_owned()],
    }
}

/// Samples a valid payload per kind from discriminant-routed wire JSON.
#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) fn sample_payload(kind: CurationKind) -> CurationPayload {
    route_payload(kind, sample_wire(kind)).expect("sample wire decodes")
}

#[cfg(test)]
fn sample_wire(kind: CurationKind) -> &'static str {
    match kind {
        CurationKind::Classification => {
            r#"{"kind":"classification","label":"memory","confidence_bps":9000,"target_evidence":{"targets":["a","b","ab"],"evidence_refs":["e-1"]}}"#
        }
        CurationKind::Relation => {
            r#"{"kind":"relation","from_handle":"a","to_handle":"b","relation":"refines","target_evidence":{"targets":["a","b","ab"],"evidence_refs":["e-1"]}}"#
        }
        CurationKind::Episode => {
            r#"{"kind":"episode","episode":"ep-7","observed_at_ms":1700000000000,"target_evidence":{"targets":["a","b","ab"],"evidence_refs":["e-1"]}}"#
        }
        CurationKind::Concept => {
            r#"{"kind":"concept","concept":"fence","definition":"state dependency","target_evidence":{"targets":["a","b","ab"],"evidence_refs":["e-1"]}}"#
        }
        CurationKind::Procedure => {
            r#"{"kind":"procedure","procedure":"rotate","steps":3,"target_evidence":{"targets":["a","b","ab"],"evidence_refs":["e-1"]}}"#
        }
        CurationKind::Failure => {
            r#"{"kind":"failure","fingerprint":"fp-1","signature":"sig-1","target_evidence":{"targets":["a","b","ab"],"evidence_refs":["e-1"]}}"#
        }
        CurationKind::Merge => {
            r#"{"kind":"merge","left":"a","right":"b","merged":"ab","target_evidence":{"targets":["a","b","ab"],"evidence_refs":["e-1"]}}"#
        }
        CurationKind::Split => {
            r#"{"kind":"split","whole":"ab","first":"a","second":"b","target_evidence":{"targets":["a","b","ab"],"evidence_refs":["e-1"]}}"#
        }
        CurationKind::Reconsolidation => {
            r#"{"kind":"reconsolidation","target":"a","update":"refresh","target_evidence":{"targets":["a","b","ab"],"evidence_refs":["e-1"]}}"#
        }
        CurationKind::Accessibility => {
            r#"{"kind":"accessibility","handle":"a","note":"captioned","target_evidence":{"targets":["a","b","ab"],"evidence_refs":["e-1"]}}"#
        }
        CurationKind::Repair => {
            r#"{"kind":"repair","target":"a","repair":"relink","target_evidence":{"targets":["a","b","ab"],"evidence_refs":["e-1"]}}"#
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

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
        let merge = sample_payload(CurationKind::Merge);
        let split = sample_payload(CurationKind::Split);
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
            let payload = sample_payload(kind);
            assert_eq!(payload.kind(), kind);
            payload.validate().expect("valid payload");
            let json = serde_json::to_string(&payload).expect("serialize");
            assert!(json.contains(&format!("\"kind\":\"{spelling}\"")));
            let routed = route_payload(kind, &json).expect("route");
            assert_eq!(routed, payload);
            assert!(!payload.facets().targets.is_empty());
            assert!(
                payload
                    .facets()
                    .targets
                    .iter()
                    .all(|t| !payload.facets().evidence_refs.contains(t))
            );
            assert_eq!(routed.facets(), payload.facets());
            let direct: CurationPayload = serde_json::from_str(&json).expect("direct decode");
            assert_eq!(direct, payload);
        }
    }

    // WORK_UNIT_CASE: 578/28
    #[test]
    fn case_28_wrong_kind_payload_pairing_rejected() {
        let kind = CurationKind::Classification;
        let json = serde_json::to_string(&sample_payload(kind)).expect("serialize");
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
        let blank_rt = sample_wire(kind).replace("memory", "  ");
        assert!(matches!(
            route_payload(kind, &blank_rt),
            Err(ContractViolation::MissingField(_))
        ));
        let long_rt = sample_wire(kind).replace("memory", &"a".repeat(257));
        assert!(matches!(
            route_payload(kind, &long_rt),
            Err(ContractViolation::OutOfBounds { .. })
        ));
        let ctrl_rt = sample_wire(kind).replace("memory", "a\u{0}b");
        assert!(matches!(
            route_payload(kind, &ctrl_rt),
            Err(ContractViolation::Malformed { .. })
        ));
        // Blank fields and out-of-range confidence fail intrinsic validation.
        let blank = CurationPayload::Classification(ClassificationPayload {
            label: "  ".to_owned(),
            confidence_bps: 9_000,
            target_evidence: sample_facets(),
        });
        assert!(blank.validate().is_err());
        let overconfident = CurationPayload::Classification(ClassificationPayload {
            label: "memory".to_owned(),
            confidence_bps: 10_001,
            target_evidence: sample_facets(),
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
        // A target reused as immutable evidence breaks the target/evidence split.
        let json = sample_wire(CurationKind::Merge)
            .replace("\"evidence_refs\":[\"e-1\"]", "\"evidence_refs\":[\"a\"]");
        let payload: CurationPayload = serde_json::from_str(&json).expect("decodes");
        assert!(matches!(
            payload.validate(),
            Err(ContractViolation::KindPayload(_))
        ));
        // Foreign subjects fail per bound variant; value-only kinds pass opaquely.
        for wire in CURATION_WIRE_KINDS {
            let kind = parse_kind(wire).expect("known kind");
            let json = sample_wire(kind).replace("[\"a\",\"b\",\"ab\"]", "[\"zzz\"]");
            let payload: CurationPayload = serde_json::from_str(&json).expect("decodes");
            let bound = matches!(
                kind,
                CurationKind::Relation
                    | CurationKind::Merge
                    | CurationKind::Split
                    | CurationKind::Reconsolidation
                    | CurationKind::Accessibility
                    | CurationKind::Repair
            );
            if bound {
                assert!(matches!(
                    payload.validate(),
                    Err(ContractViolation::KindPayload(_))
                ));
            } else {
                assert!(payload.validate().is_ok());
            }
        }
        // An empty target set authorizes nothing.
        let json = sample_wire(CurationKind::Merge).replace("[\"a\",\"b\",\"ab\"]", "[]");
        let payload: CurationPayload = serde_json::from_str(&json).expect("decodes");
        assert!(matches!(
            payload.validate(),
            Err(ContractViolation::MissingField("targets"))
        ));
    }
}
