//! Typed curation-handler registry and invocation protocol.
//!
//! Cell `smart.dreamer.contracts` (Level-0, candidate-only, fail-closed).
//! Owns the ten handler families covering the eleven wire kinds, handler
//! descriptor closure (every kind covered exactly once), and the typed
//! request/result envelope that preserves kind, family, and common
//! identities end to end. Owns no handler logic, dispatch, or runtime.

use crate::candidate::CandidateDisposition;
use crate::curation::{CurationKind, CurationPayload};
use crate::error::{ContractViolation, check_text};
use crate::screen::ScreenBinding;
use eliot_contracts::StateFence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical family spellings, in canonical order.
pub const CURATION_FAMILIES: &[&str] = &[
    "classification",
    "relation",
    "episode",
    "concept",
    "procedure",
    "failure",
    "structure_repair",
    "reconsolidation",
    "accessibility",
    "memory_repair",
];

/// Closed handler family: ten families cover the eleven wire kinds.
///
/// `Merge` and `Split` share `StructureRepair`; `Repair` is `MemoryRepair`.
/// Wire-only spellings (`merge`, `split`, `repair`) are never families.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CurationFamily {
    Classification,
    Relation,
    Episode,
    Concept,
    Procedure,
    Failure,
    StructureRepair,
    Reconsolidation,
    Accessibility,
    MemoryRepair,
}

impl CurationFamily {
    /// Returns the canonical family spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Classification => "classification",
            Self::Relation => "relation",
            Self::Episode => "episode",
            Self::Concept => "concept",
            Self::Procedure => "procedure",
            Self::Failure => "failure",
            Self::StructureRepair => "structure_repair",
            Self::Reconsolidation => "reconsolidation",
            Self::Accessibility => "accessibility",
            Self::MemoryRepair => "memory_repair",
        }
    }
}

/// Parses a family spelling into its closed family.
///
/// # Errors
///
/// Returns [`ContractViolation::UnknownVariant`] with `field == "family"`
/// for wire-only spellings (`merge`, `split`, `repair`) and every other
/// unknown value.
pub fn parse_family(value: &str) -> Result<CurationFamily, ContractViolation> {
    match value {
        "classification" => Ok(CurationFamily::Classification),
        "relation" => Ok(CurationFamily::Relation),
        "episode" => Ok(CurationFamily::Episode),
        "concept" => Ok(CurationFamily::Concept),
        "procedure" => Ok(CurationFamily::Procedure),
        "failure" => Ok(CurationFamily::Failure),
        "structure_repair" => Ok(CurationFamily::StructureRepair),
        "reconsolidation" => Ok(CurationFamily::Reconsolidation),
        "accessibility" => Ok(CurationFamily::Accessibility),
        "memory_repair" => Ok(CurationFamily::MemoryRepair),
        _ => Err(ContractViolation::UnknownVariant {
            field: "family",
            value: value.to_owned(),
        }),
    }
}

/// Maps a wire kind to its handler family.
///
/// Identity for the first six kinds plus reconsolidation and accessibility;
/// `Merge | Split` collapse to `StructureRepair`, `Repair` to `MemoryRepair`.
#[must_use]
pub const fn family_of(kind: CurationKind) -> CurationFamily {
    match kind {
        CurationKind::Classification => CurationFamily::Classification,
        CurationKind::Relation => CurationFamily::Relation,
        CurationKind::Episode => CurationFamily::Episode,
        CurationKind::Concept => CurationFamily::Concept,
        CurationKind::Procedure => CurationFamily::Procedure,
        CurationKind::Failure => CurationFamily::Failure,
        CurationKind::Merge | CurationKind::Split => CurationFamily::StructureRepair,
        CurationKind::Reconsolidation => CurationFamily::Reconsolidation,
        CurationKind::Accessibility => CurationFamily::Accessibility,
        CurationKind::Repair => CurationFamily::MemoryRepair,
    }
}

/// Returns exactly the canonical wire-kind set a family handler must accept.
#[must_use]
pub fn family_kinds(family: CurationFamily) -> &'static [CurationKind] {
    match family {
        CurationFamily::Classification => &[CurationKind::Classification],
        CurationFamily::Relation => &[CurationKind::Relation],
        CurationFamily::Episode => &[CurationKind::Episode],
        CurationFamily::Concept => &[CurationKind::Concept],
        CurationFamily::Procedure => &[CurationKind::Procedure],
        CurationFamily::Failure => &[CurationKind::Failure],
        CurationFamily::StructureRepair => &[CurationKind::Merge, CurationKind::Split],
        CurationFamily::Reconsolidation => &[CurationKind::Reconsolidation],
        CurationFamily::Accessibility => &[CurationKind::Accessibility],
        CurationFamily::MemoryRepair => &[CurationKind::Repair],
    }
}

const MAX_TEXT: usize = 128;

fn sorted_kinds(mut kinds: Vec<CurationKind>) -> Vec<CurationKind> {
    kinds.sort_by_key(|kind| kind.as_str());
    kinds.dedup();
    kinds
}

fn check_fence(fence: &StateFence) -> Result<(), ContractViolation> {
    fence
        .validate()
        .map_err(|err| ContractViolation::BindingMismatch {
            field: "state_fence",
            reason: err.to_string(),
        })
}

/// Rejects a screen-owned value that drifts from the typed request.
fn bind_screen(field: &'static str, got: &str, want: &str) -> Result<(), ContractViolation> {
    if got != want {
        return Err(ContractViolation::BindingMismatch {
            field,
            reason: "screen binding field must match request".to_owned(),
        });
    }
    Ok(())
}

/// A single typed handler descriptor: one family, one handler identity, and
/// exactly that family's canonical kind set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurationHandlerDescriptor {
    pub family: CurationFamily,
    pub handler_id: String,
    pub accepted_kinds: Vec<CurationKind>,
}

impl CurationHandlerDescriptor {
    /// Validates identity bounds and exact canonical kind coverage.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_text(&self.handler_id, "handler_id", MAX_TEXT)?;
        if self.accepted_kinds.is_empty() {
            return Err(ContractViolation::Malformed {
                field: "accepted_kinds",
                reason: "must accept at least one kind".to_owned(),
            });
        }
        let expected = sorted_kinds(family_kinds(self.family).to_vec());
        let actual = sorted_kinds(self.accepted_kinds.clone());
        if actual != expected || actual.len() != self.accepted_kinds.len() {
            let want: Vec<&str> = expected.iter().map(|k| k.as_str()).collect();
            let got: Vec<&str> = self.accepted_kinds.iter().map(|k| k.as_str()).collect();
            return Err(ContractViolation::BindingMismatch {
                field: "accepted_kinds",
                reason: format!(
                    "family {} requires exactly {want:?}, got {got:?}",
                    self.family.as_str()
                ),
            });
        }
        Ok(())
    }
}

/// Closed set of handler descriptors with non-overlapping kind coverage.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurationHandlerRegistry {
    pub handlers: Vec<CurationHandlerDescriptor>,
}

impl CurationHandlerRegistry {
    /// Creates an empty registry (covers nothing until handlers register).
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Registers one descriptor after intrinsic and cross-handler checks.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation::Registry`] when the descriptor is
    /// invalid, when `handler_id` is already registered (a changed
    /// descriptor under the same id is a conflict, an identical one a
    /// duplicate), or when any accepted kind is already covered.
    pub fn register(
        &mut self,
        descriptor: CurationHandlerDescriptor,
    ) -> Result<(), ContractViolation> {
        descriptor
            .validate()
            .map_err(|err| ContractViolation::Registry(format!("invalid descriptor: {err}")))?;
        if let Some(existing) = self
            .handlers
            .iter()
            .find(|h| h.handler_id == descriptor.handler_id)
        {
            if *existing == descriptor {
                return Err(ContractViolation::Registry(format!(
                    "duplicate handler_id: {}",
                    descriptor.handler_id
                )));
            }
            return Err(ContractViolation::Registry(format!(
                "changed descriptor for handler_id: {}",
                descriptor.handler_id
            )));
        }
        for kind in &descriptor.accepted_kinds {
            if let Some(owner) = self
                .handlers
                .iter()
                .find(|h| h.accepted_kinds.contains(kind))
            {
                return Err(ContractViolation::Registry(format!(
                    "kind {} already covered by handler_id: {}",
                    kind.as_str(),
                    owner.handler_id
                )));
            }
        }
        self.handlers.push(descriptor);
        Ok(())
    }

    /// Validates exact closure: descriptors valid, eleven kinds covered once.
    pub fn validate_closure(&self) -> Result<(), ContractViolation> {
        for descriptor in &self.handlers {
            descriptor
                .validate()
                .map_err(|err| ContractViolation::Registry(format!("invalid descriptor: {err}")))?;
        }
        let mut covered: Vec<CurationKind> = Vec::new();
        for descriptor in &self.handlers {
            for kind in &descriptor.accepted_kinds {
                if covered.contains(kind) {
                    return Err(ContractViolation::Registry(format!(
                        "overlapping coverage for kind: {}",
                        kind.as_str()
                    )));
                }
                covered.push(*kind);
            }
        }
        let covered = sorted_kinds(covered);
        let mut all = Vec::new();
        for family in [
            CurationFamily::Classification,
            CurationFamily::Relation,
            CurationFamily::Episode,
            CurationFamily::Concept,
            CurationFamily::Procedure,
            CurationFamily::Failure,
            CurationFamily::StructureRepair,
            CurationFamily::Reconsolidation,
            CurationFamily::Accessibility,
            CurationFamily::MemoryRepair,
        ] {
            all.extend_from_slice(family_kinds(family));
        }
        let all = sorted_kinds(all);
        if covered != all {
            let missing: Vec<&str> = all
                .iter()
                .filter(|kind| !covered.contains(kind))
                .map(|k| k.as_str())
                .collect();
            return Err(ContractViolation::Registry(format!(
                "incomplete coverage, missing kinds: {missing:?}"
            )));
        }
        Ok(())
    }

    /// Returns the sha256 hex digest over sorted `family:handler_id` lines.
    #[must_use]
    pub fn digest(&self) -> String {
        let mut lines: Vec<String> = self
            .handlers
            .iter()
            .map(|h| format!("{}:{}", h.family.as_str(), h.handler_id))
            .collect();
        lines.sort();
        format!("{:x}", Sha256::digest(lines.join("\n").as_bytes()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AtomicityMode {
    AllOrNothing,
    PerMember,
}

/// Complete target/member denominator under one atomicity mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetDenominator {
    pub mode: AtomicityMode,
    pub members: Vec<String>,
    pub expected_total: u32,
}

impl TargetDenominator {
    /// Validates exact member coverage against `expected_total`.
    ///
    /// # Errors
    ///
    /// Returns a [`ContractViolation`] on length, blank, or duplicate members.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if self.members.len() != self.expected_total as usize {
            return Err(ContractViolation::BindingMismatch {
                field: "members",
                reason: "denominator members must exactly cover expected_total".to_owned(),
            });
        }
        for m in &self.members {
            check_text(m, "members", MAX_TEXT)?;
        }
        let mut ordered = self.members.clone();
        ordered.sort();
        ordered.dedup();
        if ordered.len() != self.members.len() {
            return Err(ContractViolation::BindingMismatch {
                field: "members",
                reason: "duplicate denominator member".to_owned(),
            });
        }
        Ok(())
    }
}

/// Injected handler port: one descriptor bound to a port identity.
/// No discovery, no default family, no concrete handler.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurationHandlerPort {
    pub port_id: String,
    pub descriptor: CurationHandlerDescriptor,
}

impl CurationHandlerPort {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_text(&self.port_id, "port_id", MAX_TEXT)?;
        self.descriptor.validate()
    }
}

/// Typed invocation envelope for the A-31 seam: kind, family, job identities,
/// fence, payload, denominator, and optional screen binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypedCurationHandlerRequest {
    pub request_id: String,
    pub receipt_id: String,
    pub source_snapshot: String,
    pub source_revision: String,
    pub profile: String,
    pub kind: CurationKind,
    pub family: CurationFamily,
    pub job_id: String,
    pub scope_id: String,
    pub task_id: String,
    pub state_fence: StateFence,
    pub payload: CurationPayload,
    pub denominator: TargetDenominator,
    pub screen_binding: Option<ScreenBinding>,
}

impl TypedCurationHandlerRequest {
    /// Validates identities, agreement, fence, denominator, and screen binding.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation`] on drift, unscreened targets, or bad bindings.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_text(&self.request_id, "request_id", MAX_TEXT)?;
        check_text(&self.receipt_id, "receipt_id", MAX_TEXT)?;
        check_text(&self.job_id, "job_id", MAX_TEXT)?;
        check_text(&self.source_snapshot, "source_snapshot", MAX_TEXT)?;
        check_text(&self.scope_id, "scope_id", MAX_TEXT)?;
        check_text(&self.source_revision, "source_revision", MAX_TEXT)?;
        check_text(&self.task_id, "task_id", MAX_TEXT)?;
        check_text(&self.profile, "profile", MAX_TEXT)?;
        if self.family != family_of(self.kind) {
            return Err(ContractViolation::KindPayload(format!(
                "kind {} belongs to family {}, not {}",
                self.kind.as_str(),
                family_of(self.kind).as_str(),
                self.family.as_str()
            )));
        }
        if self.payload.kind() != self.kind {
            return Err(ContractViolation::KindPayload(format!(
                "payload carries kind {}, request declares {}",
                self.payload.kind().as_str(),
                self.kind.as_str()
            )));
        }
        check_fence(&self.state_fence)?;
        self.payload.validate()?;
        self.denominator.validate()?;
        let targets = &self.payload.facets().targets;
        if !targets.iter().all(|t| self.denominator.members.contains(t)) {
            return Err(ContractViolation::BindingMismatch {
                field: "targets",
                reason: "payload targets outside complete denominator".to_owned(),
            });
        }
        if self.denominator.mode == AtomicityMode::AllOrNothing
            && targets.len() != self.denominator.members.len()
        {
            return Err(ContractViolation::BindingMismatch {
                field: "targets",
                reason: "all-or-nothing targets must equal the denominator".to_owned(),
            });
        }
        if let Some(binding) = &self.screen_binding {
            binding.validate()?;
            if !self
                .payload
                .facets()
                .targets
                .iter()
                .all(|t| binding.screened_targets.contains(t))
            {
                return Err(ContractViolation::ScreenIneligible(
                    "payload adds unscreened target".to_owned(),
                ));
            }
            bind_screen("request_id", &self.request_id, binding.request_id.as_str())?;
            bind_screen("receipt_id", &self.receipt_id, binding.receipt_id.as_str())?;
            bind_screen(
                "source_snapshot",
                &self.source_snapshot,
                &binding.source_snapshot,
            )?;
            bind_screen(
                "source_revision",
                &self.source_revision,
                &binding.source_revision,
            )?;
            bind_screen("profile", &self.profile, &binding.profile)?;
            if binding.task_id != self.task_id
                || binding.scope_id != self.scope_id
                || binding.state_fence != self.state_fence
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "screen_binding",
                    reason: "screen binding task/scope/fence must match request".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Typed result envelope: preserves the request's kind, family, and common
/// identities, and carries sha256 identity digests of request and result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypedCurationHandlerResult {
    pub request_id: String,
    pub kind: CurationKind,
    pub family: CurationFamily,
    pub disposition: CandidateDisposition,
    pub handler_id: String,
    pub request_digest: String,
    pub result_digest: String,
}

fn check_digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if value.len() != 64
        || !value.bytes().all(|b| b.is_ascii_hexdigit())
        || value.bytes().any(|b| b.is_ascii_uppercase())
    {
        return Err(ContractViolation::Malformed {
            field,
            reason: "must be 64-character lowercase hex sha256".to_owned(),
        });
    }
    Ok(())
}

impl TypedCurationHandlerResult {
    /// Validates preserved identities and digest shapes.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation::KindPayload`] when kind/family no longer
    /// agree, and malformed violations for blank identities or digests that
    /// are not lowercase sha256 hex.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_text(&self.request_id, "request_id", MAX_TEXT)?;
        check_text(&self.handler_id, "handler_id", MAX_TEXT)?;
        if self.family != family_of(self.kind) {
            return Err(ContractViolation::KindPayload(format!(
                "kind {} belongs to family {}, not {}",
                self.kind.as_str(),
                family_of(self.kind).as_str(),
                self.family.as_str()
            )));
        }
        check_digest(&self.request_digest, "request_digest")?;
        check_digest(&self.result_digest, "result_digest")?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::curation::{CURATION_WIRE_KINDS, MergePayload, parse_kind, sample_payload};
    use crate::draft::ValidatedCurationItem;
    use eliot_contracts::{AuthorityEpoch, ReceiptId, RequestId, ResourceGeneration, sha256_hex};

    fn fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }

    fn descriptor(
        family: CurationFamily,
        id: &str,
        kinds: Vec<CurationKind>,
    ) -> CurationHandlerDescriptor {
        CurationHandlerDescriptor {
            family,
            handler_id: id.to_owned(),
            accepted_kinds: kinds,
        }
    }

    fn full_registry() -> CurationHandlerRegistry {
        let mut registry = CurationHandlerRegistry::new();
        for (family, id) in [
            (CurationFamily::Classification, "acc-cls"),
            (CurationFamily::Relation, "acc-rel"),
            (CurationFamily::Episode, "acc-ep"),
            (CurationFamily::Concept, "acc-con"),
            (CurationFamily::Procedure, "acc-proc"),
            (CurationFamily::Failure, "acc-fail"),
            (CurationFamily::StructureRepair, "acc-sr"),
            (CurationFamily::Reconsolidation, "acc-recon"),
            (CurationFamily::Accessibility, "acc-a11y"),
            (CurationFamily::MemoryRepair, "acc-mr"),
        ] {
            registry
                .register(descriptor(family, id, family_kinds(family).to_vec()))
                .expect("fixture descriptor");
        }
        registry
    }

    fn sample_request() -> TypedCurationHandlerRequest {
        TypedCurationHandlerRequest {
            request_id: "req-1".to_owned(),
            receipt_id: "rcpt-1".to_owned(),
            source_snapshot: "snap-1".to_owned(),
            source_revision: "rev-1".to_owned(),
            profile: "default".to_owned(),
            kind: CurationKind::Merge,
            family: CurationFamily::StructureRepair,
            job_id: "job-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            task_id: "task-1".to_owned(),
            state_fence: fence(),
            payload: CurationPayload::Merge(MergePayload {
                left: "a".to_owned(),
                right: "b".to_owned(),
                merged: "ab".to_owned(),
                target_evidence: crate::curation::sample_facets(),
            }),
            denominator: TargetDenominator {
                mode: AtomicityMode::AllOrNothing,
                members: vec!["a".to_owned(), "b".to_owned(), "ab".to_owned()],
                expected_total: 3,
            },
            screen_binding: None,
        }
    }

    fn kind_request(kind: CurationKind, wire: &str) -> TypedCurationHandlerRequest {
        let payload = sample_payload(kind);
        let targets = payload.facets().targets.clone();
        let mut members = targets.clone();
        members.push("extra".to_owned());
        let mut request = sample_request();
        request.request_id = wire.to_owned();
        request.kind = kind;
        request.family = family_of(kind);
        request.payload = payload;
        request.denominator.members = members;
        request.denominator.expected_total = 4;
        request.denominator.mode = AtomicityMode::PerMember;
        request.receipt_id = "rcpt-screen".to_owned();
        request.source_snapshot = "snap-1".to_owned();
        request.source_revision = "rev-1".to_owned();
        request.profile = "default".to_owned();
        request.screen_binding = Some(ScreenBinding {
            request_id: RequestId::new(wire).expect("request id"),
            receipt_id: ReceiptId::new("rcpt-screen").expect("receipt id"),
            screened_targets: targets,
            source_snapshot: "snap-1".to_owned(),
            source_revision: "rev-1".to_owned(),
            profile: "default".to_owned(),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence: fence(),
        });
        request
    }

    // WORK_UNIT_CASE: 578/22
    #[test]
    fn case_22_ten_families_exact_order_and_roundtrip() {
        assert_eq!(
            CURATION_FAMILIES,
            &[
                "classification",
                "relation",
                "episode",
                "concept",
                "procedure",
                "failure",
                "structure_repair",
                "reconsolidation",
                "accessibility",
                "memory_repair",
            ]
        );
        assert_eq!(CURATION_FAMILIES.len(), 10);
        for spelling in CURATION_FAMILIES {
            let family = parse_family(spelling).expect("known family");
            assert_eq!(family.as_str(), *spelling);
            let json = serde_json::to_string(&family).expect("serialize");
            assert_eq!(json, format!("\"{spelling}\""));
            let back: CurationFamily = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, family);
        }
        // Wire-only spellings are never families.
        for spelling in ["merge", "split", "repair", "other"] {
            let err = parse_family(spelling).expect_err("must reject");
            assert_eq!(
                err,
                ContractViolation::UnknownVariant {
                    field: "family",
                    value: spelling.to_owned(),
                }
            );
        }
    }

    // WORK_UNIT_CASE: 578/23
    #[test]
    fn case_23_eleven_kinds_map_to_ten_families() {
        let kinds = [
            CurationKind::Classification,
            CurationKind::Relation,
            CurationKind::Episode,
            CurationKind::Concept,
            CurationKind::Procedure,
            CurationKind::Failure,
            CurationKind::Merge,
            CurationKind::Split,
            CurationKind::Reconsolidation,
            CurationKind::Accessibility,
            CurationKind::Repair,
        ];
        assert_eq!(kinds.len(), 11);
        let mut families: Vec<CurationFamily> = kinds.iter().map(|k| family_of(*k)).collect();
        families.sort_by_key(|f| f.as_str());
        families.dedup();
        assert_eq!(families.len(), 10);
        for spelling in CURATION_FAMILIES {
            let family = parse_family(spelling).expect("known family");
            assert!(
                families.contains(&family),
                "family {spelling} has no kind mapping to it"
            );
        }
        // Spot-check the collapsing arms of the mapping.
        assert_eq!(
            family_of(CurationKind::Merge),
            family_of(CurationKind::Split)
        );
        assert_eq!(
            family_of(CurationKind::Merge),
            CurationFamily::StructureRepair
        );
        assert_eq!(
            family_of(CurationKind::Repair),
            CurationFamily::MemoryRepair
        );
        assert_eq!(
            family_of(CurationKind::Classification),
            CurationFamily::Classification
        );
    }

    // WORK_UNIT_CASE: 578/29
    #[test]
    fn case_29_validated_item_preserves_receipt_source_target_ceilings() {
        use crate::draft::valid_receipt;
        let receipt = valid_receipt(&sha256_hex(b"draft"), fence());
        receipt.validate().expect("valid receipt");
        let item = ValidatedCurationItem {
            receipt: receipt.clone(),
            kind_spelling: "merge".to_owned(),
            family_spelling: "structure_repair".to_owned(),
            source_digest: sha256_hex(b"curation-source"),
            target_denominator: "scope-1:2-of-2".to_owned(),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            budget_note: "within dimension".to_owned(),
            state_fence: fence(),
        };
        item.validate().expect("valid item");
        let wire = serde_json::to_string(&item).expect("serialize");
        let back: ValidatedCurationItem = serde_json::from_str(&wire).expect("roundtrip");
        back.validate().expect("roundtrip valid");
        assert_eq!(back, item);
        assert_eq!(
            back.receipt.preservation_digest,
            sha256_hex(b"preservation")
        );
        assert_eq!(back.receipt.budget_digest, sha256_hex(b"budget"));
        for (from, to) in [
            ("task-1", ""),
            ("scope-1", ""),
            ("\"merge\"", "\"mergeX\""),
            ("structure_repair", "structure_repairX"),
            ("source_digest\":\"", "source_digest\":\"zz"),
            ("scope-1:2-of-2", ""),
            ("within dimension", ""),
        ] {
            let mutated = wire.replacen(from, to, 1);
            let parsed: ValidatedCurationItem = serde_json::from_str(&mutated).expect("parse");
            assert!(
                parsed.validate().is_err(),
                "mutation {from}->{to} must fail"
            );
        }
        let mut fenced = item.clone();
        fenced.state_fence = StateFence::new(
            AuthorityEpoch::genesis(),
            ResourceGeneration::new(2).expect("counter"),
        );
        assert!(fenced.validate().is_err());
    }

    // WORK_UNIT_CASE: 578/30
    #[test]
    fn case_30_valid_ten_family_registry_closes() {
        let registry = full_registry();
        assert_eq!(registry.handlers.len(), 10);
        registry.validate_closure().expect("full coverage");
        // A structure_repair handler accepts exactly merge plus split.
        let sr = registry
            .handlers
            .iter()
            .find(|h| h.family == CurationFamily::StructureRepair)
            .expect("structure_repair handler");
        assert_eq!(
            sorted_kinds(sr.accepted_kinds.clone()),
            sorted_kinds(vec![CurationKind::Merge, CurationKind::Split])
        );
        // Every other family accepts exactly its single kind.
        for handler in &registry.handlers {
            if handler.family == CurationFamily::StructureRepair {
                continue;
            }
            assert_eq!(
                handler.accepted_kinds,
                family_kinds(handler.family).to_vec()
            );
            assert_eq!(handler.accepted_kinds.len(), 1);
        }
        // Explicit-discriminant routing per wire kind; all-or-nothing rejects subsets.
        for wire in CURATION_WIRE_KINDS {
            let kind = parse_kind(wire).expect("known wire kind");
            let request = kind_request(kind, wire);
            request.validate().expect("kind request");
            assert_eq!(request.family, family_of(kind));
            let mut strict = request.clone();
            strict.denominator.mode = AtomicityMode::AllOrNothing;
            let err = strict
                .validate()
                .expect_err("all-or-nothing rejects subsets");
            assert!(matches!(err, ContractViolation::BindingMismatch { .. }));
        }
    }

    // WORK_UNIT_CASE: 578/31
    #[test]
    fn case_31_missing_duplicate_overlap_rejected() {
        // Missing: empty registry cannot close.
        let empty = CurationHandlerRegistry::new();
        assert!(matches!(
            empty.validate_closure(),
            Err(ContractViolation::Registry(_))
        ));
        // Partial registry cannot close either.
        let mut partial = CurationHandlerRegistry::new();
        partial
            .register(descriptor(
                CurationFamily::Classification,
                "h-cls",
                vec![CurationKind::Classification],
            ))
            .expect("first registration");
        assert!(matches!(
            partial.validate_closure(),
            Err(ContractViolation::Registry(_))
        ));
        // Duplicate: identical descriptor under the same id.
        let mut registry = CurationHandlerRegistry::new();
        let first = descriptor(
            CurationFamily::Relation,
            "h-rel",
            vec![CurationKind::Relation],
        );
        registry
            .register(first.clone())
            .expect("first registration");
        let err = registry.register(first).expect_err("duplicate must fail");
        assert!(
            matches!(err, ContractViolation::Registry(_)),
            "unexpected: {err:?}"
        );
        // Overlap: a second handler covering an already-covered kind.
        let overlap = descriptor(
            CurationFamily::Classification,
            "h-cls-2",
            vec![CurationKind::Classification],
        );
        let mut registry = CurationHandlerRegistry::new();
        registry
            .register(descriptor(
                CurationFamily::Classification,
                "h-cls-1",
                vec![CurationKind::Classification],
            ))
            .expect("first registration");
        // `h-cls-2` is intrinsically valid but overlaps `h-cls-1`.
        overlap.validate().expect("overlap fixture is valid alone");
        let err = registry.register(overlap).expect_err("overlap must fail");
        assert!(
            matches!(err, ContractViolation::Registry(_)),
            "unexpected: {err:?}"
        );
    }

    // WORK_UNIT_CASE: 578/32
    #[test]
    fn case_32_changed_same_id_descriptor_conflicts() {
        let mut registry = CurationHandlerRegistry::new();
        registry
            .register(descriptor(
                CurationFamily::Episode,
                "h-ep",
                vec![CurationKind::Episode],
            ))
            .expect("first registration");
        let changed = descriptor(CurationFamily::Concept, "h-ep", vec![CurationKind::Concept]);
        changed.validate().expect("changed fixture is valid alone");
        let err = registry.register(changed).expect_err("changed must fail");
        assert!(
            matches!(err, ContractViolation::Registry(ref msg) if msg.contains("changed")),
            "unexpected: {err:?}"
        );
        // The original descriptor is untouched by the failed registration.
        assert_eq!(registry.handlers.len(), 1);
        assert_eq!(registry.handlers[0].family, CurationFamily::Episode);
    }

    // WORK_UNIT_CASE: 578/33
    #[test]
    fn case_33_digest_independent_of_insertion_order() {
        let first = full_registry();
        let mut reversed = CurationHandlerRegistry::new();
        let mut handlers = first.handlers.clone();
        handlers.reverse();
        for handler in handlers {
            reversed.register(handler).expect("fixture descriptor");
        }
        assert_eq!(first.digest(), reversed.digest());
        assert_eq!(first.digest().len(), 64);
        // Different content digests differently.
        let mut other = first.clone();
        other.handlers[0].handler_id = "acc-cls-renamed".to_owned();
        assert_ne!(first.digest(), other.digest());
    }

    // WORK_UNIT_CASE: 578/34
    #[test]
    fn case_34_request_result_preserve_identities() {
        let request = sample_request();
        request.validate().expect("valid request");
        let request_json = serde_json::to_string(&request).expect("serialize request");
        let request_back: TypedCurationHandlerRequest =
            serde_json::from_str(&request_json).expect("roundtrip request");
        assert_eq!(request_back, request);

        let result = TypedCurationHandlerResult {
            request_id: request.request_id.clone(),
            kind: request.kind,
            family: request.family,
            disposition: crate::candidate::CandidateDisposition::Candidate,
            handler_id: "acc-sr".to_owned(),
            request_digest: sha256_hex(request_json.as_bytes()),
            result_digest: sha256_hex(b"merge-candidate-ab"),
        };
        result.validate().expect("valid result");
        let result_json = serde_json::to_string(&result).expect("serialize result");
        let result_back: TypedCurationHandlerResult =
            serde_json::from_str(&result_json).expect("roundtrip result");
        result_back
            .validate()
            .expect("roundtripped result stays valid");
        assert_eq!(result_back, result);
        assert_eq!(result_back.request_id, request_back.request_id);
        assert_eq!(result_back.kind, request_back.kind);
        assert_eq!(result_back.family, request_back.family);
        // Candidate results encode no targets and no application.
        for key in ["targets", "screen_binding", "denominator"] {
            assert!(!result_json.contains(key), "result must not encode {key}");
        }

        let drifted = TypedCurationHandlerResult {
            kind: CurationKind::Repair,
            ..result.clone()
        };
        assert!(matches!(
            drifted.validate(),
            Err(ContractViolation::KindPayload(_))
        ));
        // Uppercase or truncated digests are malformed, not digests.
        let bad_digest = TypedCurationHandlerResult {
            result_digest: "AB".to_owned(),
            ..result
        };
        assert!(matches!(
            bad_digest.validate(),
            Err(ContractViolation::Malformed { .. })
        ));

        // Denominator exactness: wrong total, dupes, and outside targets fail.
        let mut wrong_total = sample_request();
        wrong_total.denominator.expected_total = 99;
        let err = wrong_total.validate().expect_err("wrong total must fail");
        assert!(matches!(err, ContractViolation::BindingMismatch { .. }));
        let mut dupe = sample_request();
        dupe.denominator.members = vec!["a".to_owned(), "a".to_owned(), "b".to_owned()];
        let err = dupe.validate().expect_err("duplicate member must fail");
        assert!(matches!(
            err,
            ContractViolation::BindingMismatch {
                field: "members",
                ..
            }
        ));
        let mut outside = sample_request();
        outside.denominator.members = vec!["x".to_owned()];
        outside.denominator.expected_total = 1;
        assert!(outside.validate().is_err());
        assert_screened_dispatch_fails();
    }

    fn assert_screened_dispatch_fails() {
        // Screened dispatch: unscreened targets and foreign task/scope/fence fail.
        let screened = kind_request(CurationKind::Merge, "req-screened");
        screened.validate().expect("screened request");
        let mut unscreened = screened.clone();
        if let Some(binding) = unscreened.screen_binding.as_mut() {
            binding.screened_targets.retain(|t| t != "ab");
        }
        let err = unscreened
            .validate()
            .expect_err("unscreened target must fail");
        assert!(matches!(err, ContractViolation::ScreenIneligible(_)));
        let mut foreign_task = screened.clone();
        if let Some(binding) = foreign_task.screen_binding.as_mut() {
            binding.task_id = "task-9".to_owned();
        }
        let err = foreign_task.validate().expect_err("foreign task must fail");
        assert!(matches!(err, ContractViolation::BindingMismatch { .. }));
        let mut foreign_scope = screened.clone();
        if let Some(binding) = foreign_scope.screen_binding.as_mut() {
            binding.scope_id = "scope-9".to_owned();
        }
        let err = foreign_scope
            .validate()
            .expect_err("foreign scope must fail");
        assert!(matches!(err, ContractViolation::BindingMismatch { .. }));
        let mut foreign_fence = screened.clone();
        if let Some(binding) = foreign_fence.screen_binding.as_mut() {
            binding.state_fence = StateFence::new(
                AuthorityEpoch::genesis(),
                ResourceGeneration::new(2).expect("counter"),
            );
        }
        let err = foreign_fence
            .validate()
            .expect_err("foreign fence must fail");
        assert!(matches!(err, ContractViolation::BindingMismatch { .. }));
        for f in [
            "request_id",
            "receipt_id",
            "source_snapshot",
            "source_revision",
            "profile",
        ] {
            let mut bad = screened.clone();
            match f {
                "request_id" => bad.request_id = "req-x".to_owned(),
                "receipt_id" => bad.receipt_id = "rcpt-x".to_owned(),
                "source_snapshot" => bad.source_snapshot = "snap-x".to_owned(),
                "source_revision" => bad.source_revision = "rev-x".to_owned(),
                _ => bad.profile = "other".to_owned(),
            }
            let err = bad
                .validate()
                .expect_err("binding field mismatch must fail");
            assert!(
                matches!(err, ContractViolation::BindingMismatch { field, .. } if field == f),
                "field {f} must fail closed"
            );
        }
    }
}
