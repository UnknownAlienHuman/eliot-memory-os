//! Typed curation-handler registry and invocation protocol.
//!
//! Cell `smart.dreamer.contracts` (Level-0, candidate-only, fail-closed).
//! Owns the ten handler families covering the eleven wire kinds, handler
//! descriptor closure (every kind covered exactly once), and the typed
//! request/result envelope that preserves kind, family, and common
//! identities end to end. Owns no handler logic, dispatch, or runtime.

use crate::candidate::CandidateDisposition;
use crate::curation::{CurationKind, CurationPayload};
use crate::error::{
    ContractViolation, check_fence, check_text, check_vec_bound, closed_wire_enum, is_hex64_lower,
};
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

closed_wire_enum!(free CurationFamily, parse_family, field = "family", [
    Classification => "classification",
    Relation => "relation",
    Episode => "episode",
    Concept => "concept",
    Procedure => "procedure",
    Failure => "failure",
    StructureRepair => "structure_repair",
    Reconsolidation => "reconsolidation",
    Accessibility => "accessibility",
    MemoryRepair => "memory_repair",
]);

closed_wire_enum!(family_map CurationKind => CurationFamily, [
    Classification => [Classification],
    Relation => [Relation],
    Episode => [Episode],
    Concept => [Concept],
    Procedure => [Procedure],
    Failure => [Failure],
    StructureRepair => [Merge, Split],
    Reconsolidation => [Reconsolidation],
    Accessibility => [Accessibility],
    MemoryRepair => [Repair],
]);

const MAX_TEXT: usize = 128;

fn sorted_kinds(mut kinds: Vec<CurationKind>) -> Vec<CurationKind> {
    kinds.sort_by_key(|kind| kind.as_str());
    kinds.dedup();
    kinds
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

/// Shared request-side screen compatibility: screen eligibility, screened
/// target coverage, five request/receipt/snapshot/revision/profile bindings,
/// and the task/scope/fence triple. Shared with draft acceptance.
pub(crate) fn check_screen_compat(
    request: &TypedCurationHandlerRequest,
    screen: &ScreenBinding,
) -> Result<(), ContractViolation> {
    screen.validate()?;
    if !request
        .payload
        .facets()
        .targets
        .iter()
        .all(|t| screen.screened_targets.contains(t))
    {
        return Err(ContractViolation::ScreenIneligible(
            "payload adds unscreened target".to_owned(),
        ));
    }
    bind_screen(
        "request_id",
        &request.request_id,
        screen.request_id.as_str(),
    )?;
    bind_screen(
        "receipt_id",
        &request.receipt_id,
        screen.receipt_id.as_str(),
    )?;
    let snap = (&request.source_snapshot, &screen.source_snapshot);
    let rev = (&request.source_revision, &screen.source_revision);
    bind_screen("source_snapshot", snap.0, snap.1)?;
    bind_screen("source_revision", rev.0, rev.1)?;
    bind_screen("profile", &request.profile, &screen.profile)?;
    if screen.task_id != request.task_id
        || screen.scope_id != request.scope_id
        || screen.state_fence != request.state_fence
    {
        return Err(ContractViolation::BindingMismatch {
            field: "screen_binding",
            reason: "screen binding task/scope/fence must match request".to_owned(),
        });
    }
    Ok(())
}

/// Cross-envelope item/request agreement: kind, target subset,
/// all-or-nothing equality, and whole-denominator equality.
///
/// Family is skipped by transitivity: item and request validation each
/// enforce kind↔family, so kind equality implies family agreement.
/// Evidence is skipped: each side enforces target∩evidence disjointness
/// plus bundle membership, leaving no principled cross direction.
pub(crate) fn check_curation_request_compat(
    kind: CurationKind,
    payload: &CurationPayload,
    denominator: &TargetDenominator,
    request: &TypedCurationHandlerRequest,
) -> Result<(), ContractViolation> {
    if kind != request.kind {
        return Err(ContractViolation::KindPayload(std::format!(
            "curation item kind {} does not match handler request kind {}",
            kind.as_str(),
            request.kind.as_str()
        )));
    }
    let item_targets = &payload.facets().targets;
    let request_targets = &request.payload.facets().targets;
    let covered = item_targets.iter().all(|t| request_targets.contains(t));
    if !covered {
        return Err(ContractViolation::BindingMismatch {
            field: "targets",
            reason: "curation item targets must not exceed handler request targets".to_owned(),
        });
    }
    let sets_equal = crate::error::sorted_set_eq(item_targets, request_targets);
    if request.denominator.mode == AtomicityMode::AllOrNothing && !sets_equal {
        return Err(ContractViolation::BindingMismatch {
            field: "targets",
            reason: "all-or-nothing request targets must equal item targets".to_owned(),
        });
    }
    if denominator != &request.denominator {
        return Err(ContractViolation::BindingMismatch {
            field: "denominator",
            reason: "curation item denominator must equal handler request denominator".to_owned(),
        });
    }
    if !payload.semantic_eq(&request.payload) {
        return Err(ContractViolation::BindingMismatch {
            field: "payload",
            reason: "curation item payload must equal handler request payload".to_owned(),
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
            let family = self.family.as_str();
            return Err(ContractViolation::BindingMismatch {
                field: "accepted_kinds",
                reason: format!("family {family} requires exactly {want:?}, got {got:?}"),
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
        Self::default()
    }

    /// Registers one descriptor after intrinsic and cross-handler checks.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation::Registry`] when the descriptor is
    /// invalid, when `handler_id` is already registered (a changed
    /// descriptor under the same id is a conflict, an identical one a
    /// duplicate), or when any accepted kind is already covered.
    pub fn register(&mut self, d: CurationHandlerDescriptor) -> Result<(), ContractViolation> {
        if let Err(err) = d.validate() {
            return Err(ContractViolation::Registry(format!(
                "invalid descriptor: {err}"
            )));
        }
        if let Some(existing) = self.handlers.iter().find(|h| h.handler_id == d.handler_id) {
            if *existing == d {
                return Err(ContractViolation::Registry(format!(
                    "duplicate handler_id: {}",
                    d.handler_id
                )));
            }
            return Err(ContractViolation::Registry(format!(
                "changed descriptor for handler_id: {}",
                d.handler_id
            )));
        }
        for kind in &d.accepted_kinds {
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
        self.handlers.push(d);
        Ok(())
    }

    /// Validates exact closure: descriptors valid, eleven kinds covered once.
    pub fn validate_closure(&self) -> Result<(), ContractViolation> {
        for descriptor in &self.handlers {
            if let Err(err) = descriptor.validate() {
                return Err(ContractViolation::Registry(format!(
                    "invalid descriptor: {err}"
                )));
            }
        }
        let mut seen_ids: Vec<&str> = Vec::new();
        for descriptor in &self.handlers {
            if seen_ids.contains(&descriptor.handler_id.as_str()) {
                return Err(ContractViolation::Registry(format!(
                    "duplicate handler_id: {}",
                    descriptor.handler_id
                )));
            }
            seen_ids.push(&descriptor.handler_id);
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
        for spelling in CURATION_FAMILIES {
            if let Ok(family) = parse_family(spelling) {
                all.extend_from_slice(family_kinds(family));
            }
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
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation::Registry`] unless the registry is closed.
    #[must_use = "digest errors on open registries; handle the Result"]
    pub fn digest(&self) -> Result<String, ContractViolation> {
        if let Err(err) = self.validate_closure() {
            return Err(ContractViolation::Registry(format!(
                "digest requires closed registry: {err}"
            )));
        }
        let mut lines: Vec<String> = Vec::new();
        for h in &self.handlers {
            lines.push(format!("{}:{}", h.family.as_str(), h.handler_id));
        }
        lines.sort();
        Ok(format!("{:x}", Sha256::digest(lines.join("\n").as_bytes())))
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

/// Max members admitted in any target denominator.
const MAX_DENOMINATOR_MEMBERS: usize = 1_024;

impl TargetDenominator {
    /// Validates exact member coverage against `expected_total`.
    ///
    /// # Errors
    ///
    /// Returns a [`ContractViolation`] on length, blank, or duplicate members.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        let total = self.expected_total as usize;
        check_vec_bound(total, MAX_DENOMINATOR_MEMBERS, "expected_total")?;
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
            && !crate::error::sorted_set_eq(targets, &self.denominator.members)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "targets",
                reason: "all-or-nothing targets must equal the denominator".to_owned(),
            });
        }
        let Some(binding) = &self.screen_binding else {
            return Err(ContractViolation::ScreenIneligible(
                "typed dispatch requires an eligible screen binding".to_owned(),
            ));
        };
        check_screen_compat(self, binding)
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
    if !is_hex64_lower(value) {
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
use eliot_contracts::{AuthorityEpoch, ReceiptId, RequestId, ResourceGeneration};

#[cfg(test)]
pub(crate) fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) fn sample_binding() -> ScreenBinding {
    ScreenBinding {
        request_id: RequestId::new("req-1").expect("request id"),
        receipt_id: ReceiptId::new("rcpt-1").expect("receipt id"),
        screened_targets: vec!["a".to_owned(), "b".to_owned(), "ab".to_owned()],
        source_snapshot: "snap-1".to_owned(),
        source_revision: "rev-1".to_owned(),
        profile: "default".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        state: crate::screen::ScreenState::Eligible,
        result_digest: "a".repeat(64),
        item_digest: "b".repeat(64),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::curation::{CURATION_WIRE_KINDS, parse_kind, sample_payload};
    use crate::draft::{ValidatedCurationItem, valid_receipt};
    use crate::job::{Requester, RequesterOrigin};
    use eliot_contracts::{AuthorityEpoch, ReceiptId, RequestId, ResourceGeneration, sha256_hex};

    fn bumped_fence() -> StateFence {
        let gen2 = ResourceGeneration::new(2).expect("counter");
        StateFence::new(AuthorityEpoch::genesis(), gen2)
    }
    fn descriptor(f: CurationFamily, id: &str, k: Vec<CurationKind>) -> CurationHandlerDescriptor {
        CurationHandlerDescriptor {
            family: f,
            handler_id: id.to_owned(),
            accepted_kinds: k,
        }
    }

    fn denom_all() -> TargetDenominator {
        TargetDenominator {
            mode: AtomicityMode::AllOrNothing,
            members: vec!["a".to_owned(), "b".to_owned(), "ab".to_owned()],
            expected_total: 3,
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
            let desc = descriptor(family, id, family_kinds(family).to_vec());
            registry.register(desc).expect("fixture descriptor");
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
            payload: sample_payload(CurationKind::Merge),
            denominator: denom_all(),
            screen_binding: Some(sample_binding()),
        }
    }

    fn binding_of(r: &mut TypedCurationHandlerRequest) -> &mut ScreenBinding {
        r.screen_binding.as_mut().expect("binding")
    }
    fn screened_with(
        b: &TypedCurationHandlerRequest,
        f: impl FnOnce(&mut ScreenBinding),
    ) -> TypedCurationHandlerRequest {
        let mut r = b.clone();
        f(binding_of(&mut r));
        r
    }
    fn kind_request(kind: CurationKind, wire: &str) -> TypedCurationHandlerRequest {
        let payload = sample_payload(kind);
        let targets = payload.facets().targets.clone();
        let mut request = sample_request();
        request.request_id = wire.to_owned();
        request.kind = kind;
        request.family = family_of(kind);
        request.payload = payload;
        request.denominator.members = [targets.clone(), vec!["extra".to_owned()]].concat();
        request.denominator.expected_total = 4;
        request.denominator.mode = AtomicityMode::PerMember;
        request.receipt_id = "rcpt-screen".to_owned();
        let mut binding = sample_binding();
        binding.request_id = RequestId::new(wire).expect("request id");
        binding.receipt_id = ReceiptId::new("rcpt-screen").expect("receipt id");
        binding.screened_targets = targets;
        request.screen_binding = Some(binding);
        request
    }

    // WORK_UNIT_CASE: 578/22
    #[test]
    fn case_22_ten_families_exact_order_and_roundtrip() {
        let want = "classification,relation,episode,concept,procedure,failure,structure_repair,reconsolidation,accessibility,memory_repair";
        assert_eq!(CURATION_FAMILIES.join(","), want);
        assert_eq!(CURATION_FAMILIES.len(), 10);
        for spelling in CURATION_FAMILIES {
            let family = parse_family(spelling).expect("known family");
            let json = serde_json::to_string(&family).expect("serialize");
            let back: CurationFamily = serde_json::from_str(&json).expect("deserialize");
            assert!(family.as_str() == *spelling && back == family);
            assert_eq!(json, format!("\"{spelling}\""));
        }
        for spelling in ["merge", "split", "repair", "other"] {
            let err = parse_family(spelling).expect_err("must reject");
            let want = ContractViolation::UnknownVariant {
                field: "family",
                value: spelling.into(),
            };
            assert_eq!(err, want);
        }
    }

    // WORK_UNIT_CASE: 578/23
    #[test]
    fn case_23_eleven_kinds_map_to_ten_families() {
        assert_eq!(CURATION_WIRE_KINDS.len(), 11);
        let mut families: Vec<CurationFamily> = CURATION_WIRE_KINDS
            .iter()
            .map(|w| family_of(parse_kind(w).expect("known wire kind")))
            .collect();
        families.sort_by_key(|f| f.as_str());
        families.dedup();
        assert_eq!(families.len(), 10);
        for spelling in CURATION_FAMILIES {
            let family = parse_family(spelling).expect("known family");
            let found = families.contains(&family);
            assert!(found, "family {spelling} has no kind mapping to it");
        }
        let merge = family_of(CurationKind::Merge);
        let split = family_of(CurationKind::Split);
        assert_eq!(merge, split);
        assert_eq!(merge, CurationFamily::StructureRepair);
        let repair = family_of(CurationKind::Repair);
        assert_eq!(repair, CurationFamily::MemoryRepair);
        let classification = family_of(CurationKind::Classification);
        assert_eq!(classification, CurationFamily::Classification);
    }

    // WORK_UNIT_CASE: 578/29
    #[test]
    fn case_29_validated_item_preserves_receipt_source_target_ceilings() {
        let receipt = valid_receipt(&sha256_hex(b"draft"), fence());
        receipt.validate().expect("valid receipt");
        let item = ValidatedCurationItem {
            receipt: receipt.clone(),
            kind_spelling: "merge".to_owned(),
            family_spelling: "structure_repair".to_owned(),
            payload: crate::curation::sample_payload(CurationKind::Merge),
            denominator: denom_all(),
            source_digest: sha256_hex(b"curation-source"),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence: fence(),
            budget_note: "within dimension".to_owned(),
            job_digest: "d".repeat(64),
            requester: Requester {
                origin: RequesterOrigin::Human,
                principal: "alice".to_owned(),
                session: None,
            },
        };
        item.validate().expect("valid item");
        let wire = serde_json::to_string(&item).expect("serialize");
        let back: ValidatedCurationItem = serde_json::from_str(&wire).expect("roundtrip");
        back.validate().expect("roundtrip valid");
        assert!(back == item && back.receipt.preservation_digest == sha256_hex(b"preservation"));
        assert_eq!(back.receipt.budget_digest, sha256_hex(b"budget"));
        let members = "\"members\":[\"a\",\"b\",\"ab\"]";
        let members_x = "\"members\":[\"a\",\"b\",\"x\"]";
        for (from, to) in [
            ("task-1", ""),
            ("scope-1", ""),
            ("\"merge\"", "\"mergeX\""),
            ("structure_repair", "structure_repairX"),
            ("source_digest\":\"", "source_digest\":\"zz"),
            (members, members_x),
            ("within dimension", ""),
        ] {
            let mutated = wire.replacen(from, to, 1);
            let parsed: ValidatedCurationItem = serde_json::from_str(&mutated).expect("parse");
            let ok = parsed.validate().is_ok();
            assert!(!ok, "mutation {from}->{to} must fail");
        }
        let mut fenced = item.clone();
        fenced.state_fence = bumped_fence();
        assert!(fenced.validate().is_err());
    }

    // WORK_UNIT_CASE: 578/30
    #[test]
    fn case_30_valid_ten_family_registry_closes() {
        let registry = full_registry();
        assert_eq!(registry.handlers.len(), 10);
        registry.validate_closure().expect("full coverage");
        let sr = registry
            .handlers
            .iter()
            .find(|h| h.family == CurationFamily::StructureRepair)
            .expect("structure_repair handler");
        let got = sorted_kinds(sr.accepted_kinds.clone());
        let want = sorted_kinds(vec![CurationKind::Merge, CurationKind::Split]);
        assert_eq!(got, want);
        for handler in &registry.handlers {
            if handler.family == CurationFamily::StructureRepair {
                continue;
            }
            let want = family_kinds(handler.family).to_vec();
            assert!(handler.accepted_kinds == want && handler.accepted_kinds.len() == 1);
        }
        for wire in CURATION_WIRE_KINDS {
            let kind = parse_kind(wire).expect("known wire kind");
            let request = kind_request(kind, wire);
            request.validate().expect("kind request");
            assert_eq!(request.family, family_of(kind));
            let mut strict = request.clone();
            strict.denominator.mode = AtomicityMode::AllOrNothing;
            let res = strict.validate();
            let err = res.expect_err("all-or-nothing rejects subsets");
            assert!(matches!(err, ContractViolation::BindingMismatch { .. }));
            let mut dup = sample_request();
            dup.payload = sample_payload(CurationKind::Merge);
            if let CurationPayload::Merge(inner) = &mut dup.payload {
                inner.target_evidence.targets = vec!["a".to_owned(), "a".to_owned()];
            }
            dup.denominator.members = vec!["a".to_owned(), "b".to_owned()];
            dup.denominator.expected_total = 2;
            let err = dup.validate().expect_err("duplicate targets must fail");
            assert!(matches!(err, ContractViolation::BindingMismatch { .. }));
        }
        let item = ValidatedCurationItem {
            receipt: valid_receipt(&sha256_hex(b"draft"), fence()),
            kind_spelling: "merge".to_owned(),
            family_spelling: "structure_repair".to_owned(),
            payload: sample_payload(CurationKind::Merge),
            denominator: TargetDenominator {
                mode: AtomicityMode::PerMember,
                members: [denom_all().members, vec!["extra".to_owned()]].concat(),
                expected_total: 4,
            },
            source_digest: sha256_hex(b"curation-source"),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence: fence(),
            budget_note: "within dimension".to_owned(),
            job_digest: "d".repeat(64),
            requester: Requester {
                origin: RequesterOrigin::Human,
                principal: "alice".to_owned(),
                session: None,
            },
        };
        item.validate().expect("per-member item subset accepts");
        let mut strict_item = item.clone();
        strict_item.denominator.mode = AtomicityMode::AllOrNothing;
        let err = strict_item
            .validate()
            .expect_err("all-or-nothing item subset rejects");
        assert!(matches!(err, ContractViolation::BindingMismatch { .. }));
    }

    // WORK_UNIT_CASE: 578/31
    #[test]
    fn case_31_missing_duplicate_overlap_rejected() {
        let empty = CurationHandlerRegistry::new();
        let err = empty.validate_closure().expect_err("empty must fail");
        assert!(matches!(err, ContractViolation::Registry(_)));
        let mut partial = CurationHandlerRegistry::new();
        let kinds = vec![CurationKind::Classification];
        partial
            .register(descriptor(CurationFamily::Classification, "h-cls", kinds))
            .expect("first registration");
        let res = partial.validate_closure();
        assert!(matches!(res, Err(ContractViolation::Registry(_))));
        let mut registry = CurationHandlerRegistry::new();
        let kinds = vec![CurationKind::Relation];
        let first = descriptor(CurationFamily::Relation, "h-rel", kinds);
        let dup = first.clone();
        registry.register(first).expect("first registration");
        let err = registry.register(dup).expect_err("duplicate must fail");
        assert!(matches!(err, ContractViolation::Registry(_)));
        let kinds = vec![CurationKind::Classification];
        let overlap = descriptor(CurationFamily::Classification, "h-cls-2", kinds);
        let mut registry = CurationHandlerRegistry::new();
        let kinds = vec![CurationKind::Classification];
        registry
            .register(descriptor(CurationFamily::Classification, "h-cls-1", kinds))
            .expect("first registration");
        overlap.validate().expect("overlap fixture is valid alone");
        let err = registry.register(overlap).expect_err("overlap must fail");
        assert!(matches!(err, ContractViolation::Registry(_)));
        let wire = serde_json::to_string(&full_registry()).expect("serialize");
        let raw: CurationHandlerRegistry =
            serde_json::from_str(&wire.replacen("acc-rel", "acc-cls", 1)).expect("parse");
        let err = raw.validate_closure().expect_err("same-id must fail");
        assert!(
            matches!(err, ContractViolation::Registry(m) if m.contains("duplicate handler_id"))
        );
        let mut identical = full_registry();
        identical.handlers.push(identical.handlers[0].clone());
        let err = identical
            .validate_closure()
            .expect_err("identical dup must fail");
        assert!(
            matches!(err, ContractViolation::Registry(m) if m.contains("duplicate handler_id"))
        );
    }

    // WORK_UNIT_CASE: 578/32
    #[test]
    fn case_32_changed_same_id_descriptor_conflicts() {
        let mut registry = CurationHandlerRegistry::new();
        let kinds = vec![CurationKind::Episode];
        registry
            .register(descriptor(CurationFamily::Episode, "h-ep", kinds))
            .expect("first registration");
        let changed = descriptor(CurationFamily::Concept, "h-ep", vec![CurationKind::Concept]);
        changed.validate().expect("changed fixture is valid alone");
        let r = registry.register(changed);
        assert!(matches!(r, Err(ContractViolation::Registry(ref m)) if m.contains("changed")));
        assert_eq!(registry.handlers.len(), 1);
        assert_eq!(registry.handlers[0].family, CurationFamily::Episode);
    }

    // WORK_UNIT_CASE: 578/33
    #[test]
    fn case_33_digest_independent_of_insertion_order() {
        let first = full_registry();
        let mut reversed = CurationHandlerRegistry::new();
        for handler in first.handlers.iter().rev().cloned() {
            reversed.register(handler).expect("fixture descriptor");
        }
        assert!(CurationHandlerRegistry::new().digest().is_err());
        let mut partial = CurationHandlerRegistry::new();
        partial
            .register(first.handlers[0].clone())
            .expect("fixture descriptor");
        assert!(partial.digest().is_err(), "partial-open digest must fail");
        let first_digest = first.digest().expect("closed registry");
        let reversed_digest = reversed.digest().expect("closed registry");
        assert!(first_digest == reversed_digest && first_digest.len() == 64);
        let mut other = first.clone();
        other.handlers[0].handler_id = "acc-cls-renamed".to_owned();
        assert_ne!(first_digest, other.digest().expect("closed registry"));
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
        let res = result_back.validate();
        res.expect("roundtripped result stays valid");
        assert!(result_back == result && result_back.request_id == request_back.request_id);
        assert!(result_back.kind == request_back.kind && result_back.family == request_back.family);
        for key in ["targets", "screen_binding", "denominator"] {
            assert!(!result_json.contains(key), "result must not encode {key}");
        }

        let drifted = TypedCurationHandlerResult {
            kind: CurationKind::Repair,
            ..result.clone()
        };
        let err = drifted.validate().expect_err("kind drift must fail");
        assert!(matches!(err, ContractViolation::KindPayload(_)));
        let bad_digest = TypedCurationHandlerResult {
            result_digest: "AB".to_owned(),
            ..result
        };
        let err = bad_digest.validate().expect_err("bad digest must fail");
        assert!(matches!(err, ContractViolation::Malformed { .. }));

        let mut wrong_total = sample_request();
        wrong_total.denominator.expected_total = 99;
        let err = wrong_total.validate().expect_err("wrong total must fail");
        assert!(matches!(err, ContractViolation::BindingMismatch { .. }));
        for mode in [AtomicityMode::AllOrNothing, AtomicityMode::PerMember] {
            let empty = TargetDenominator {
                mode,
                members: Vec::new(),
                expected_total: 0,
            };
            assert!(empty.validate().is_ok(), "empty denominator must validate");
        }
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
        let mut huge = sample_request();
        huge.denominator.expected_total = 1_025;
        let err = huge.validate().expect_err("huge total must fail");
        assert!(matches!(
            err,
            ContractViolation::OutOfBounds {
                field: "expected_total",
                ..
            }
        ));
        let mut max = sample_request();
        max.job_id = "j".repeat(128);
        max.validate().expect("128-char identity is the bound");
        let mut over = sample_request();
        over.job_id = "j".repeat(129);
        let err = over.validate().expect_err("overlong identity must fail");
        assert!(matches!(err, ContractViolation::OutOfBounds { .. }));
        let mut control = sample_request();
        control.job_id = "a\u{0}b".to_owned();
        let err = control.validate().expect_err("control identity must fail");
        assert!(matches!(err, ContractViolation::Malformed { .. }));
        assert_screened_dispatch_fails();
    }

    fn assert_screened_dispatch_fails() {
        let screened = kind_request(CurationKind::Merge, "req-screened");
        screened.validate().expect("screened request");
        let unscreened = screened_with(&screened, |b| b.screened_targets.retain(|t| t != "ab"));
        let res = unscreened.validate();
        let err = res.expect_err("unscreened target must fail");
        assert!(matches!(err, ContractViolation::ScreenIneligible(_)));
        for which in ["task", "scope", "fence"] {
            let mut bad = screened.clone();
            match which {
                "task" => binding_of(&mut bad).task_id = "task-9".to_owned(),
                "scope" => binding_of(&mut bad).scope_id = "scope-9".to_owned(),
                _ => binding_of(&mut bad).state_fence = bumped_fence(),
            }
            let err = bad.validate().expect_err("foreign binding must fail");
            assert!(matches!(err, ContractViolation::BindingMismatch { .. }));
        }
        let mut missing = screened.clone();
        missing.screen_binding = None;
        let err = missing.validate().expect_err("missing binding must fail");
        assert!(matches!(err, ContractViolation::ScreenIneligible(_)));
        let mut protected = screened.clone();
        binding_of(&mut protected).state = crate::screen::ScreenState::Protected;
        let err = protected.validate().expect_err("protected must fail");
        assert!(matches!(err, ContractViolation::ScreenIneligible(_)));
        let truncated = screened_with(&screened, |b| b.result_digest.truncate(63));
        let err = truncated.validate().expect_err("truncated must fail");
        assert!(matches!(err, ContractViolation::ScreenIneligible(_)));
        let max_target = screened_with(&screened, |b| b.screened_targets.push("t".repeat(256)));
        assert!(max_target.validate().is_ok());
        let over_target = screened_with(&screened, |b| b.screened_targets.push("t".repeat(257)));
        let err = over_target.validate().expect_err("oversize must fail");
        assert!(matches!(err, ContractViolation::OutOfBounds { .. }));
        let control_target =
            screened_with(&screened, |b| b.screened_targets.push("a\u{0}b".to_owned()));
        let err = control_target.validate().expect_err("control must fail");
        assert!(matches!(err, ContractViolation::Malformed { .. }));
        let mut capped = screened.clone();
        let binding = capped.screen_binding.as_mut().expect("binding");
        binding
            .screened_targets
            .extend((0..1021).map(|i| format!("t-{i:04}")));
        assert!(capped.validate().is_ok());
        let mut over = screened.clone();
        binding_of(&mut over).screened_targets = vec!["s".to_owned(); 1025];
        let err = over.validate().expect_err("1025 targets must fail");
        assert!(matches!(err, ContractViolation::OutOfBounds { .. }));
        let mut kilo = screened.clone();
        binding_of(&mut kilo).screened_targets = vec!["y".repeat(1024); 1024];
        let targets = &kilo
            .screen_binding
            .as_ref()
            .expect("binding")
            .screened_targets;
        let folded = targets
            .iter()
            .map(String::len)
            .fold(0usize, usize::saturating_add);
        assert_eq!(folded, targets.iter().map(String::len).sum::<usize>());
        let err = kilo.validate().expect_err("1KiB items fail per-item");
        assert!(matches!(
            err,
            ContractViolation::OutOfBounds { max: 256, .. }
        ));
        let mut over_bytes = kilo.clone();
        binding_of(&mut over_bytes).screened_targets[0] = "y".repeat(1025);
        let err = over_bytes.validate().expect_err("cap plus one must fail");
        assert!(matches!(
            err,
            ContractViolation::OutOfBounds { max: 1_048_576, .. }
        ));
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
            let res = bad.validate();
            let err = res.expect_err("binding field mismatch must fail");
            assert!(
                matches!(err, ContractViolation::BindingMismatch { field, .. } if field == f),
                "field {f} must fail closed"
            );
        }
    }
}
