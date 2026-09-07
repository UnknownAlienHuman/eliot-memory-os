//! Closed curation-kind and payload contracts.
//! Cell `smart.dreamer.contracts` (Level-0, candidate-only, fail-closed).
//! Owns the exact 11 wire kinds of `I9.6 CurationCandidate`, one closed payload
//! schema per kind, and the wire-kind to handler-family spelling map.

use crate::error::{ContractViolation, check_text, check_vec_bound, closed_wire_enum};
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

closed_wire_enum!(free CurationKind, parse_kind, field = "wire_kind", [
    Classification => "classification",
    Relation => "relation",
    Episode => "episode",
    Concept => "concept",
    Procedure => "procedure",
    Failure => "failure",
    Merge => "merge",
    Split => "split",
    Reconsolidation => "reconsolidation",
    Accessibility => "accessibility",
    Repair => "repair",
]);

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
        check_vec_bound(self.targets.len(), MAX_TARGETS, "targets")?;
        check_vec_bound(self.evidence_refs.len(), MAX_EVIDENCE_REFS, "evidence_refs")?;
        for h in &self.targets {
            check_text(h, "targets", MAX_TEXT)?;
        }
        for h in &self.evidence_refs {
            check_text(h, "evidence_refs", MAX_TEXT)?;
        }
        let mut ordered = self.targets.clone();
        ordered.sort();
        ordered.dedup();
        if ordered.len() != self.targets.len() {
            return Err(ContractViolation::BindingMismatch {
                field: "targets",
                reason: "duplicate target".to_owned(),
            });
        }
        let mut ordered_evidence = self.evidence_refs.clone();
        ordered_evidence.sort();
        ordered_evidence.dedup();
        if ordered_evidence.len() != self.evidence_refs.len() {
            return Err(ContractViolation::BindingMismatch {
                field: "evidence_refs",
                reason: "duplicate evidence ref".to_owned(),
            });
        }
        if let Some(h) = self.targets.iter().find(|h| self.evidence_refs.contains(h)) {
            return Err(ContractViolation::KindPayload(std::format!(
                "{kind_spelling} target {h} must not appear in immutable evidence"
            )));
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
/// Max targets admitted in any target/evidence set.
const MAX_TARGETS: usize = 1_024;
/// Max evidence refs admitted in any target/evidence set.
const MAX_EVIDENCE_REFS: usize = 1_024;
/// Max bytes admitted for any routed payload envelope.
const MAX_PAYLOAD_JSON: usize = 1_048_576;

fn check_subjects(
    subjects: &[&String],
    facets: &TargetEvidence,
    kind: &'static str,
) -> Result<(), ContractViolation> {
    facets.validate(kind)?;
    if let Some(subject) = subjects.iter().find(|s| !facets.targets.contains(s)) {
        return Err(ContractViolation::KindPayload(std::format!(
            "{kind} subject {subject} must be a declared target"
        )));
    }
    Ok(())
}

impl CurationPayload {
    fn parts(&self) -> (CurationKind, &TargetEvidence) {
        match self {
            Self::Classification(p) => (CurationKind::Classification, &p.target_evidence),
            Self::Relation(p) => (CurationKind::Relation, &p.target_evidence),
            Self::Episode(p) => (CurationKind::Episode, &p.target_evidence),
            Self::Concept(p) => (CurationKind::Concept, &p.target_evidence),
            Self::Procedure(p) => (CurationKind::Procedure, &p.target_evidence),
            Self::Failure(p) => (CurationKind::Failure, &p.target_evidence),
            Self::Merge(p) => (CurationKind::Merge, &p.target_evidence),
            Self::Split(p) => (CurationKind::Split, &p.target_evidence),
            Self::Reconsolidation(p) => (CurationKind::Reconsolidation, &p.target_evidence),
            Self::Accessibility(p) => (CurationKind::Accessibility, &p.target_evidence),
            Self::Repair(p) => (CurationKind::Repair, &p.target_evidence),
        }
    }

    /// Returns the wire kind carried by this payload.
    #[must_use]
    pub fn kind(&self) -> CurationKind {
        self.parts().0
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
                let facets = &p.target_evidence;
                check_subjects(&[&p.from_handle, &p.to_handle], facets, "relation")?;
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
                check_subjects(&[&p.left, &p.right, &p.merged], &p.target_evidence, "merge")?;
            }
            Self::Split(p) => {
                check_text(&p.whole, "whole", MAX_TEXT)?;
                check_text(&p.first, "first", MAX_TEXT)?;
                check_text(&p.second, "second", MAX_TEXT)?;
                let facets = &p.target_evidence;
                check_subjects(&[&p.whole, &p.first, &p.second], facets, "split")?;
            }
            Self::Reconsolidation(p) => {
                check_text(&p.target, "target", MAX_TEXT)?;
                check_text(&p.update, "update", MAX_TEXT)?;
                check_subjects(&[&p.target], &p.target_evidence, "reconsolidation")?;
            }
            Self::Accessibility(p) => {
                check_text(&p.handle, "handle", MAX_TEXT)?;
                check_text(&p.note, "note", MAX_TEXT)?;
                check_subjects(&[&p.handle], &p.target_evidence, "accessibility")?;
            }
            Self::Repair(p) => {
                check_text(&p.target, "target", MAX_TEXT)?;
                check_text(&p.repair, "repair", MAX_TEXT)?;
                check_subjects(&[&p.target], &p.target_evidence, "repair")?;
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn facets(&self) -> &TargetEvidence {
        self.parts().1
    }

    fn facets_eq(a: &TargetEvidence, b: &TargetEvidence) -> bool {
        crate::error::sorted_set_eq(&a.targets, &b.targets)
            && crate::error::sorted_set_eq(&a.evidence_refs, &b.evidence_refs)
    }

    /// Compares full semantic equality across kind, scalars, and facets.
    ///
    /// Fail-closed on enum growth: every outer arm is explicit, so adding a
    /// variant breaks compilation until it is compared here. The inner
    /// wildcard rejects cross-kind pairs behind the kind check.
    #[must_use]
    pub(crate) fn semantic_eq(&self, other: &Self) -> bool {
        match self {
            Self::Classification(a) => match other {
                Self::Classification(b) => {
                    a.label == b.label
                        && a.confidence_bps == b.confidence_bps
                        && Self::facets_eq(&a.target_evidence, &b.target_evidence)
                }
                _ => false,
            },
            Self::Relation(a) => match other {
                Self::Relation(b) => {
                    a.from_handle == b.from_handle
                        && a.to_handle == b.to_handle
                        && a.relation == b.relation
                        && Self::facets_eq(&a.target_evidence, &b.target_evidence)
                }
                _ => false,
            },
            Self::Episode(a) => match other {
                Self::Episode(b) => {
                    a.episode == b.episode
                        && a.observed_at_ms == b.observed_at_ms
                        && Self::facets_eq(&a.target_evidence, &b.target_evidence)
                }
                _ => false,
            },
            Self::Concept(a) => match other {
                Self::Concept(b) => {
                    a.concept == b.concept
                        && a.definition == b.definition
                        && Self::facets_eq(&a.target_evidence, &b.target_evidence)
                }
                _ => false,
            },
            Self::Procedure(a) => match other {
                Self::Procedure(b) => {
                    a.procedure == b.procedure
                        && a.steps == b.steps
                        && Self::facets_eq(&a.target_evidence, &b.target_evidence)
                }
                _ => false,
            },
            Self::Failure(a) => match other {
                Self::Failure(b) => {
                    a.fingerprint == b.fingerprint
                        && a.signature == b.signature
                        && Self::facets_eq(&a.target_evidence, &b.target_evidence)
                }
                _ => false,
            },
            Self::Merge(a) => match other {
                Self::Merge(b) => {
                    a.left == b.left
                        && a.right == b.right
                        && a.merged == b.merged
                        && Self::facets_eq(&a.target_evidence, &b.target_evidence)
                }
                _ => false,
            },
            Self::Split(a) => match other {
                Self::Split(b) => {
                    a.whole == b.whole
                        && a.first == b.first
                        && a.second == b.second
                        && Self::facets_eq(&a.target_evidence, &b.target_evidence)
                }
                _ => false,
            },
            Self::Reconsolidation(a) => match other {
                Self::Reconsolidation(b) => {
                    a.target == b.target
                        && a.update == b.update
                        && Self::facets_eq(&a.target_evidence, &b.target_evidence)
                }
                _ => false,
            },
            Self::Accessibility(a) => match other {
                Self::Accessibility(b) => {
                    a.handle == b.handle
                        && a.note == b.note
                        && Self::facets_eq(&a.target_evidence, &b.target_evidence)
                }
                _ => false,
            },
            Self::Repair(a) => match other {
                Self::Repair(b) => {
                    a.target == b.target
                        && a.repair == b.repair
                        && Self::facets_eq(&a.target_evidence, &b.target_evidence)
                }
                _ => false,
            },
        }
    }
}

/// Routes raw JSON to the payload named by `kind`: tag peeked, decoded, validated;
/// wrong/invalid kind/payload fails before routing (no caller-side `validate` needed).
///
/// # Errors
///
/// Returns `KindPayload` on mismatch, `Malformed` on bad JSON/payload.
pub fn route_payload(kind: CurationKind, json: &str) -> Result<CurationPayload, ContractViolation> {
    #[derive(Deserialize)]
    struct KindTag {
        kind: CurationKind,
    }
    if json.len() > MAX_PAYLOAD_JSON {
        return Err(ContractViolation::Malformed {
            field: "curation_payload",
            reason: "payload envelope exceeds byte bound".to_owned(),
        });
    }
    let malformed = |err: serde_json::Error| ContractViolation::Malformed {
        field: "curation_payload",
        reason: err.to_string(),
    };
    let tag: KindTag = serde_json::from_str(json).map_err(&malformed)?;
    if tag.kind != kind {
        return Err(ContractViolation::KindPayload(format!(
            "expected payload for {}, found {}",
            kind.as_str(),
            tag.kind.as_str()
        )));
    }
    let payload: CurationPayload = serde_json::from_str(json).map_err(malformed)?;
    payload.validate()?;
    Ok(payload)
}

/// Maps a wire kind to its handler-family spelling (see [`crate::registry::CurationFamily`]).
#[must_use]
pub const fn kind_family(kind: CurationKind) -> &'static str {
    crate::registry::family_of(kind).as_str()
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
    route_payload(kind, &sample_wire(kind)).expect("sample wire decodes")
}

#[cfg(test)]
fn sample_wire(kind: CurationKind) -> String {
    let body = match kind {
        CurationKind::Classification => r#""label":"memory","confidence_bps":9000"#,
        CurationKind::Relation => r#""from_handle":"a","to_handle":"b","relation":"refines""#,
        CurationKind::Episode => r#""episode":"ep-7","observed_at_ms":1700000000000"#,
        CurationKind::Concept => r#""concept":"fence","definition":"state dependency""#,
        CurationKind::Procedure => r#""procedure":"rotate","steps":3"#,
        CurationKind::Failure => r#""fingerprint":"fp-1","signature":"sig-1""#,
        CurationKind::Merge => r#""left":"a","right":"b","merged":"ab""#,
        CurationKind::Split => r#""whole":"ab","first":"a","second":"b""#,
        CurationKind::Reconsolidation => r#""target":"a","update":"refresh""#,
        CurationKind::Accessibility => r#""handle":"a","note":"captioned""#,
        CurationKind::Repair => r#""target":"a","repair":"relink""#,
    };
    std::format!(
        r#"{{"kind":"{kind_tag}",{body},"target_evidence":{{"targets":["a","b","ab"],"evidence_refs":["e-1"]}}}}"#,
        kind_tag = kind.as_str()
    )
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
            let facets = payload.facets();
            assert!(!facets.targets.is_empty());
            assert!(
                facets
                    .targets
                    .iter()
                    .all(|t| !facets.evidence_refs.contains(t))
            );
            assert_eq!(routed.facets(), payload.facets());
            let direct: CurationPayload = serde_json::from_str(&json).expect("direct decode");
            assert_eq!(direct, payload);
        }
    }

    // WORK_UNIT_CASE: 578/28
    #[test]
    fn case_28_wrong_kind_payload_pairing_rejected() {
        use ContractViolation::*;
        use CurationKind::*;
        let kind = Classification;
        let json = serde_json::to_string(&sample_payload(kind)).expect("serialize");
        let err = route_payload(CurationKind::Relation, &json).expect_err("tag mismatch must fail");
        assert!(matches!(err, ContractViolation::KindPayload(_)));
        let direct: CurationPayload = serde_json::from_str(&json).expect("direct decode");
        assert_eq!(direct.kind(), CurationKind::Classification);
        assert_ne!(direct.kind(), CurationKind::Relation);
        let malformed = route_payload(kind, "{not json").expect_err("malformed must fail");
        assert!(matches!(malformed, ContractViolation::Malformed { .. }));
        let unknown_tag = route_payload(kind, r#"{"kind":"other"}"#).expect_err("tag must fail");
        assert!(matches!(unknown_tag, ContractViolation::Malformed { .. }));
        let blank_rt = sample_wire(kind).replace("memory", "  ");
        let err = route_payload(kind, &blank_rt).expect_err("blank must fail");
        assert!(matches!(err, ContractViolation::MissingField(_)));
        let long_rt = sample_wire(kind).replace("memory", &"a".repeat(257));
        let err = route_payload(kind, &long_rt).expect_err("overlong must fail");
        assert!(matches!(err, ContractViolation::OutOfBounds { .. }));
        let ctrl_rt = sample_wire(kind).replace("memory", "a\u{0}b");
        let err = route_payload(kind, &ctrl_rt).expect_err("control must fail");
        assert!(matches!(err, ContractViolation::Malformed { .. }));
        let json = sample_wire(kind).replace("memory", "  ");
        let blank: CurationPayload = serde_json::from_str(&json).expect("decodes");
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
        let json = sample_wire(CurationKind::Merge)
            .replace("\"evidence_refs\":[\"e-1\"]", "\"evidence_refs\":[\"a\"]");
        let payload: CurationPayload = serde_json::from_str(&json).expect("decodes");
        let err = payload.validate().expect_err("overlap must fail");
        assert!(matches!(err, ContractViolation::KindPayload(_)));
        let json = sample_wire(kind).replace("[\"a\",\"b\",\"ab\"]", "[\"a\",\"a\"]");
        let payload: CurationPayload = serde_json::from_str(&json).expect("decodes");
        let r = payload.validate();
        assert!(matches!(r, Err(BindingMismatch { field: g, .. }) if g == "targets"));
        let json = sample_wire(kind).replace("[\"e-1\"]", "[\"e-1\",\"e-1\"]");
        let payload: CurationPayload = serde_json::from_str(&json).expect("decodes");
        let r = payload.validate();
        assert!(matches!(r, Err(BindingMismatch { field: g, .. }) if g == "evidence_refs"));
        let oversize = "x".repeat(MAX_PAYLOAD_JSON + 1);
        let err = route_payload(kind, &oversize).expect_err("oversize must fail");
        assert!(matches!(err, ContractViolation::Malformed { .. }));
        let flooded = TargetEvidence {
            targets: vec!["a".to_owned(); MAX_TARGETS + 1],
            evidence_refs: Vec::new(),
        };
        let r = flooded.validate("classification");
        assert!(matches!(r, Err(OutOfBounds { field: g, .. }) if g == "targets"));
        let flooded_evidence = TargetEvidence {
            targets: vec!["a".to_owned()],
            evidence_refs: vec!["e".to_owned(); MAX_EVIDENCE_REFS + 1],
        };
        let r = flooded_evidence.validate("classification");
        assert!(matches!(r, Err(OutOfBounds { field: g, .. }) if g == "evidence_refs"));
        for wire in CURATION_WIRE_KINDS {
            let kind = parse_kind(wire).expect("known kind");
            let json = sample_wire(kind).replace("[\"a\",\"b\",\"ab\"]", "[\"zzz\"]");
            let payload: CurationPayload = serde_json::from_str(&json).expect("decodes");
            if matches!(
                kind,
                Classification | Episode | Concept | Procedure | Failure
            ) {
                assert!(payload.validate().is_ok());
            } else {
                let err = payload.validate().expect_err("foreign subject must fail");
                assert!(matches!(err, ContractViolation::KindPayload(_)));
            }
        }
        let json = sample_wire(CurationKind::Merge).replace("[\"a\",\"b\",\"ab\"]", "[]");
        let payload: CurationPayload = serde_json::from_str(&json).expect("decodes");
        let err = payload.validate().expect_err("empty targets must fail");
        assert!(matches!(err, ContractViolation::MissingField("targets")));
    }
}
