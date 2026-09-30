//! Indivisible-unit binding for Context admission.
//!
//! I12.13 budgets every semantic role in whole, addressable units and forbids
//! cutting a tool call/result pair, an evidence edge, a source identity, a URL
//! or a JSON object into a syntactically valid but semantically false fragment.
//! This module binds that rule to the owner-issued unit/member metadata of
//! #1727 ([`BoundaryMetadataSet`]) and to nothing else.
//!
//! Two properties are established here, and both are consumed by the existing
//! `prepare_floor` -> `select_required` -> `select_optional` path rather than
//! by a second whole-unit selection:
//!
//! 1. **Group closure.** An atom that belongs to an indivisible unit is selected
//!    together with every member the owner declares for that unit. The
//!    admission path already admits or omits a closure as a unit, so extending
//!    the closure with the owner's declared members is what makes a partial
//!    group impossible.
//! 2. **Whole-unit establishment.** A candidate is a complete unit only where
//!    its own envelope says `Complete` + `Exact` with no degradation applied. A
//!    degraded unit may still be admitted, but only as the exact expansion
//!    handle its owner envelope names. Anything else takes the whole group's
//!    allowed disposition: a typed incomplete result on the required path and a
//!    truthful omission on the optional path.
//!
//! The unit kind, the declared denominator, the membership and the completeness
//! of a candidate are read from the owner's envelope. `AtomRepresentation::Whole`
//! is a content tag and is never evidence of any of them.
//!
//! `Batch` is deliberately not treated as indivisible. Its members are
//! independently described units, which is what makes a truthful optional
//! omission of one member possible; I12.13 names the call/result pair and the
//! evidence edge as the indivisible forms, not a batch.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use eliot_context_contracts::{
    AdmissionInput, AtomRepresentation, BoundaryCompleteness, BoundaryDenominator,
    BoundaryDisposition, BoundaryMemberReference, BoundaryMetadataEnvelope, BoundaryMetadataSet,
    BoundaryPrecision, BoundaryUnitKind, BoundaryValidationLimits, ContextCandidate, ContextError,
    RepresentationKind,
};
use eliot_contracts::ArtifactId;

/// Upper bound on the members one indivisible group closure may pull in.
///
/// This mirrors the closure bounds the admission path already applies to its own
/// dependency closures, so a pathological group graph fails closed in the same
/// place and with the same error shape.
const MAX_UNIT_GROUP_CLOSURE: usize = 4096;

/// The validated owner evidence the pure compiler consumes to bind groups.
///
/// This is plain owner data, never an IO client: the unit/member metadata the
/// producing owner issued, plus the resource bounds this projection site
/// validates it under. The boundary contract itself refuses zero limits, so a
/// caller cannot make the validation vacuous by supplying none.
pub struct UnitGroupContext<'a> {
    /// The exact owner-issued unit/member metadata for this decision.
    pub boundaries: &'a BoundaryMetadataSet,
    /// The bounds this projection site validates that metadata under.
    pub limits: &'a BoundaryValidationLimits,
}

/// What one candidate's own envelope establishes about its whole unit.
struct AtomUnit {
    /// The owner's declared whole set for this unit, empty when it declares
    /// none.
    group: BTreeSet<ArtifactId>,
    /// Whether the owner established a complete, exact whole unit.
    complete: bool,
    /// Whether the owner established an exact-handle-only whole unit.
    handle_only: bool,
    /// The exact expansion handles this unit's owner envelope names.
    expansion_refs: BTreeSet<ArtifactId>,
}

/// The owner's unit/member metadata, joined to this input's candidates.
pub(crate) struct UnitGroupBinding {
    units: BTreeMap<ArtifactId, AtomUnit>,
}

/// Whether this unit kind may not be split across records.
const fn is_indivisible(kind: BoundaryUnitKind) -> bool {
    matches!(
        kind,
        BoundaryUnitKind::CallResultPair | BoundaryUnitKind::EvidenceEdge
    )
}

impl UnitGroupBinding {
    /// Validate the owner-issued metadata and join it to this input.
    ///
    /// Every comparison is against something this decision did not choose. The
    /// set is validated by its own contract, each envelope must carry this
    /// decision's binding, each candidate must resolve to exactly one envelope,
    /// an envelope source that names a different immutable snapshot is refused,
    /// and every member the owner declares for an indivisible unit must resolve
    /// to an envelope in the same set. A member that resolves to nothing is
    /// refused here instead of being dropped, because silently dropping a
    /// declared member is exactly the partial group admission this exists to
    /// prevent.
    pub(crate) fn bind(
        input: &AdmissionInput,
        context: &UnitGroupContext<'_>,
    ) -> Result<Self, ContextError> {
        context.boundaries.validate(context.limits)?;

        let mut envelopes: BTreeMap<&ArtifactId, &BoundaryMetadataEnvelope> = BTreeMap::new();
        for unit in &context.boundaries.units {
            // Unit metadata describing another decision is not evidence about
            // this one, whatever shape it has.
            if unit.binding != input.binding {
                return Err(ContextError::InvalidFence);
            }
            if envelopes.insert(&unit.unit_id, unit).is_some() {
                return Err(ContextError::Duplicate("unit_group.unit_ids"));
            }
        }

        // The declared denominator of every indivisible unit, indexed by member.
        let mut declared: BTreeMap<ArtifactId, BTreeSet<ArtifactId>> = BTreeMap::new();
        for unit in &context.boundaries.units {
            if !is_indivisible(unit.unit_kind) {
                continue;
            }
            let BoundaryDenominator::Declared(members) = &unit.coverage.denominator else {
                return Err(ContextError::WholeUnitRequired);
            };
            let group: BTreeSet<ArtifactId> = members
                .iter()
                .map(|member| match &member.reference {
                    BoundaryMemberReference::SourceMember { member_id, .. } => {
                        member_id.clone()
                    }
                    BoundaryMemberReference::ChildUnit { unit_id } => unit_id.clone(),
                })
                .collect();
            for member in &group {
                if !envelopes.contains_key(member) {
                    return Err(ContextError::MissingField("unit_group.member_envelope"));
                }
                declared
                    .entry(member.clone())
                    .or_default()
                    .extend(group.iter().cloned());
            }
        }

        let mut units = BTreeMap::new();
        for candidate in &input.candidates.candidates {
            let envelope = envelopes
                .get(&candidate.atom_id)
                .ok_or(ContextError::MissingField("unit_group.candidate_envelope"))?;
            // The envelope must describe THIS candidate's exact immutable source.
            if let Some(source) = &envelope.source
                && (source.snapshot_id != candidate.source.snapshot_id
                    || source.revision != candidate.source.revision
                    || source.content_sha256 != candidate.source.content_sha256)
            {
                return Err(ContextError::IdentityConflict);
            }
            let complete = envelope.completeness == BoundaryCompleteness::Complete
                && envelope.precision == BoundaryPrecision::Exact
                && envelope.disposition.is_none();
            let handle_only = envelope
                .disposition
                .is_some_and(|record| record.disposition == BoundaryDisposition::ExactHandleOnly);
            units.insert(
                candidate.atom_id.clone(),
                AtomUnit {
                    group: declared.get(&candidate.atom_id).cloned().unwrap_or_default(),
                    complete,
                    handle_only,
                    expansion_refs: envelope.expansion_refs.iter().cloned().collect(),
                },
            );
        }
        Ok(Self { units })
    }

    /// Whether the candidate's own representation may be admitted at all.
    ///
    /// `Whole` is a content tag, not evidence, so it is accepted only where the
    /// owner's envelope establishes a complete, exact unit with no degradation.
    /// A degraded unit is admitted only as the exact expansion handle the owner
    /// itself named, which is what makes its content, accessibility and
    /// lifetime established by their owners rather than asserted here. I12.13
    /// forbids mixing exact and degraded fields so that the unit reads as
    /// complete, so an extractive or summary form of a degraded unit is refused
    /// rather than admitted as a complete member of its group.
    pub(crate) fn admits_representation(&self, candidate: &ContextCandidate) -> bool {
        let Some(unit) = self.units.get(&candidate.atom_id) else {
            return false;
        };
        match candidate.representation.kind() {
            RepresentationKind::Whole
            | RepresentationKind::Extractive
            | RepresentationKind::Summary => unit.complete,
            RepresentationKind::Handle => {
                unit.complete || self.establishes_handle(candidate, unit)
            }
        }
    }

    /// Whether the owner envelope names the candidate's own handle as the exact
    /// way this unit may be reopened.
    fn establishes_handle(&self, candidate: &ContextCandidate, unit: &AtomUnit) -> bool {
        let AtomRepresentation::Handle { handle } = &candidate.representation else {
            return false;
        };
        unit.handle_only && unit.expansion_refs.contains(handle)
    }

    /// Expand a selected set with every member of each indivisible group it
    /// touches.
    ///
    /// The walk is transitive and bounded, because an indivisible unit may be
    /// declared inside another one; the boundary contract has already proved
    /// that child graph acyclic and within its own depth bound.
    pub(crate) fn group_closure(
        &self,
        roots: &BTreeSet<ArtifactId>,
    ) -> Result<BTreeSet<ArtifactId>, ContextError> {
        let mut closure = roots.clone();
        let mut queue: VecDeque<ArtifactId> = roots.iter().cloned().collect();
        while let Some(atom_id) = queue.pop_front() {
            let Some(unit) = self.units.get(&atom_id) else {
                continue;
            };
            for member in &unit.group {
                if closure.insert(member.clone()) {
                    queue.push_back(member.clone());
                }
            }
            if closure.len() > MAX_UNIT_GROUP_CLOSURE {
                return Err(ContextError::Bounds {
                    field: "unit_group.closure",
                });
            }
        }
        Ok(closure)
    }
}