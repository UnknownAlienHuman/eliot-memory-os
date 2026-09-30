//! Owner-neutral original assembly parameters, result and intrinsic boundary validation.

use crate::{
    ActiveUnderstandingView, AdmittedContextSet, BOUNDARY_METADATA_SCHEMA_REVISION,
    BoundaryMetadataEnvelope, BoundaryMetadataSet, BoundaryUnitKind, BoundaryValidationLimits,
    ContextError, DecisionContextIncomplete, MeasurementStatus, RenderedAtom,
};
use eliot_contracts::{ArtifactId, ContractVersion, canonical_json_bytes, sha256_hex};
use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;

/// Caller-owned immutable parameters for one A-18 projection.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AssemblyPolicy {
    /// Digest of the state fence used by the admission decision.
    pub fence_digest: String,
    /// Maximum canonical rendered payload bytes accepted by this route.
    pub max_serialized_bytes: u64,
    /// Required serializer identity for the injected measurement.
    pub serializer_id: String,
    /// Required serializer revision for the injected measurement.
    pub serializer_version: String,
    /// Required serializer-options digest.
    pub serializer_options_digest: String,
    /// Required route identity.
    pub route_id: String,
    /// Required model/tokenizer route identity.
    pub model_id: String,
    /// Measurement status qualified for this route; this prototype supports
    /// only exact UTF-8 bytes, while tokenizer/STU observations remain data.
    pub measurement_status: MeasurementStatus,
}

impl AssemblyPolicy {
    /// Validates the original assembly parameters without supplying defaults.
    pub fn validate(&self) -> Result<(), AssemblyError> {
        validate_digest(&self.fence_digest, "assembly.fence_digest")?;
        if self.max_serialized_bytes == 0 {
            return Err(AssemblyError::Bounds("assembly.max_serialized_bytes"));
        }
        for (value, field) in [
            (&self.serializer_id, "assembly.serializer_id"),
            (&self.serializer_version, "assembly.serializer_version"),
            (&self.route_id, "assembly.route_id"),
            (&self.model_id, "assembly.model_id"),
        ] {
            if value.len() > 1_048_576 {
                return Err(AssemblyError::Bounds(field));
            }
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(AssemblyError::Contract(ContextError::InvalidField(field)));
            }
        }
        validate_digest(
            &self.serializer_options_digest,
            "assembly.serializer_options_digest",
        )?;
        if self.measurement_status != MeasurementStatus::ExactUtf8 {
            return Err(AssemblyError::Contract(ContextError::UnknownMeasurement));
        }
        Ok(())
    }
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), AssemblyError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(AssemblyError::Contract(ContextError::InvalidDigest(field)));
    }
    Ok(())
}

/// Failure while projecting an admitted set into the canonical A-15 view.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AssemblyError {
    /// An A-15 contract rejected the supplied value.
    #[error("context contract rejected assembly: {0}")]
    Contract(#[from] ContextError),
    /// An input or measured output exceeded this package's bounded workset.
    #[error("assembly field exceeds its bound: {0}")]
    Bounds(&'static str),
    /// The measurement did not describe the exact canonical rendered payload.
    #[error("measurement does not bind to the canonical rendered payload: {0}")]
    MeasurementMismatch(&'static str),
    /// The upstream Safety Floor is incomplete and remains explicit.
    #[error("admitted context is incomplete")]
    Incomplete(Box<DecisionContextIncomplete>),
    /// Quality evidence cannot support a complete projection.
    ///
    /// Both halves are retained and neither replaces the other: the card is the
    /// complete twelve-dimension accounting, including every failed, unknown,
    /// degraded and not-applicable result, and the refusal is the typed
    /// operation-scoped answer - which operation was requested, whether it was
    /// blocked by a dimension or by an unresolved applicability input, and the
    /// exact blocking results with the evidence each still lacks. A consumer
    /// that only saw the card would have to re-derive the refusal; a consumer
    /// that only saw the refusal would lose the dimensions that did not block.
    #[error("quality evidence cannot support a complete projection")]
    QualityIncomplete(Box<crate::QualityScorecard>, Box<crate::QualityRefusal>),
}

/// Deterministic caller-supplied resource bounds for one boundary projection.
///
/// Assembly owns these values because it is the projection site; the contract still
/// enforces them, and rejects zero limits itself rather than trusting this site.
pub fn assembly_boundary_limits() -> BoundaryValidationLimits {
    BoundaryValidationLimits {
        max_units: 4096,
        max_depth: 32,
        max_members_per_unit: 1024,
        max_total_members: 262_144,
        max_references_per_unit: 256,
        max_metadata_bytes: 8 * 1024 * 1024,
    }
}

/// Reassemble a packed boundary set and prove it still describes this view.
///
/// Three independent sides meet here, and no two of them come from the same
/// producer: the packed bytes, the binding value recorded before transport
/// (which incorporates the upstream admission receipt digest), and this crate's
/// own reconstruction from the rendered atoms it holds. A substituted envelope, a
/// reordered member, a duplicated unit, or a lost unit therefore fails on the
/// side that did not produce it. Lengths are compared as well as memberships,
/// because two copies of one identity collapse in a set and a duplicate would
/// otherwise go unnoticed.
pub fn read_back_boundaries(
    packed: &[u8],
    recorded_binding: &str,
    admitted_receipt_digest: &str,
    output_digest: &str,
    rendered: &[RenderedAtom],
) -> Result<BoundaryMetadataSet, ContextError> {
    let reconstructed = BoundaryMetadataSet::unpack(packed, &assembly_boundary_limits())?;
    verify_boundary_binding(
        recorded_binding,
        admitted_receipt_digest,
        output_digest,
        &reconstructed,
    )?;
    verify_against_rendered(&reconstructed, rendered)?;
    Ok(reconstructed)
}

/// Check that a reassembled set describes exactly the rendered units.
fn verify_against_rendered(
    boundaries: &BoundaryMetadataSet,
    rendered: &[RenderedAtom],
) -> Result<(), ContextError> {
    let mut expected: BTreeMap<&ArtifactId, &RenderedAtom> = BTreeMap::new();
    for atom in rendered {
        if expected.insert(&atom.atom_id, atom).is_some() {
            return Err(ContextError::Duplicate("boundary.readback.rendered_ids"));
        }
    }
    if expected.is_empty() {
        return if boundaries.units.is_empty() {
            Ok(())
        } else {
            Err(ContextError::SelectionIntegrityMismatch)
        };
    }

    let mut seen: BTreeMap<&ArtifactId, &BoundaryMetadataEnvelope> = BTreeMap::new();
    for unit in &boundaries.units {
        if unit.unit_kind != BoundaryUnitKind::Unit {
            continue;
        }
        if seen.insert(&unit.unit_id, unit).is_some() {
            return Err(ContextError::Duplicate("boundary.readback.unit_ids"));
        }
    }
    if seen.len() != expected.len() {
        return Err(ContextError::SelectionIntegrityMismatch);
    }

    let mut orders: Vec<u64> = Vec::with_capacity(seen.len());
    for (unit_id, atom) in &expected {
        let unit = seen
            .get(unit_id)
            .ok_or(ContextError::SelectionIntegrityMismatch)?;
        let source = unit
            .source
            .as_ref()
            .ok_or(ContextError::MissingField("boundary.readback.source"))?;
        if source.snapshot_id != atom.source_id
            || source.revision != atom.source_revision
            || source.content_sha256 != atom.source_digest
        {
            return Err(ContextError::IdentityConflict);
        }
        let order = unit
            .source_order
            .ok_or(ContextError::MissingField("boundary.readback.source_order"))?;
        orders.push(order);
    }
    orders.sort_unstable();
    orders.dedup();
    if orders.len() != expected.len() || orders.first() != Some(&0) {
        return Err(ContextError::SelectionIntegrityMismatch);
    }
    Ok(())
}

/// Bind boundary metadata into one output identity checked against the admission
/// receipt, the rendered output identity, and the boundary set's own recorded
/// digest.
///
/// The three inputs are produced by different owners: the admission receipt is
/// sealed upstream, the output digest is computed over the rendered atoms, and the
/// boundary digest is recorded over the envelopes and ordered member relations.
/// This binding is what makes altered boundary metadata change the bound output
/// identity instead of being invisible to it.
pub fn boundary_binding_digest(
    admitted_receipt_digest: &str,
    output_digest: &str,
    boundaries: &BoundaryMetadataSet,
) -> Result<String, ContextError> {
    if boundaries.boundary_digest.is_empty() {
        return Err(ContextError::MissingField("boundary.boundary_digest"));
    }
    if boundaries.canonical_digest()? != boundaries.boundary_digest {
        return Err(ContextError::SelectionIntegrityMismatch);
    }
    let mut unsigned = boundaries.clone();
    unsigned.boundary_digest = String::new();
    let bytes = canonical_json_bytes(&BoundaryBindingPayload {
        schema_version: BOUNDARY_METADATA_SCHEMA_REVISION,
        admitted_receipt_digest,
        output_digest,
        boundaries: &unsigned,
    })
    .map_err(|_| ContextError::InvalidField("boundary.binding_payload"))?;
    Ok(sha256_hex(&bytes))
}

/// Reject a binding digest that does not match what this assembly actually holds.
///
/// The digest is recomputed from the current admitted receipt, output identity and
/// boundary payload, so an altered envelope, a reordered member, or substituted
/// source revision fails here rather than passing a self-consistent but wrong
/// value.
pub fn verify_boundary_binding(
    expected_digest: &str,
    admitted_receipt_digest: &str,
    output_digest: &str,
    boundaries: &BoundaryMetadataSet,
) -> Result<(), ContextError> {
    let derived = boundary_binding_digest(admitted_receipt_digest, output_digest, boundaries)?;
    if derived != expected_digest {
        return Err(ContextError::SelectionIntegrityMismatch);
    }
    Ok(())
}

#[derive(Serialize)]
struct BoundaryBindingPayload<'a> {
    schema_version: ContractVersion,
    admitted_receipt_digest: &'a str,
    output_digest: &'a str,
    boundaries: &'a BoundaryMetadataSet,
}

/// Complete projection result retaining the exact A-15 accounting evidence
/// that the compact view schema represents only through omission identities.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ActiveUnderstandingViewResult {
    /// Canonical rendered candidate view.
    pub view: ActiveUnderstandingView,
    /// Exact admitted records, admissions, floor and economy retained for reconstruction.
    pub admitted: AdmittedContextSet,
    /// Exact bytes handed to the measurement callback.
    pub serialized_bytes: Vec<u8>,
    /// Boundary metadata for every rendered unit, plus the exact member relation.
    ///
    /// This is the round-trip half of the assembly result: readback can compare the
    /// declared source identities, per-unit scope/fence and admitted source order
    /// against what it reconstructed, instead of trusting a concatenated string.
    /// Its recorded digest is validated against the payload held, and
    /// `boundary_binding` binds it into the output identity together with the
    /// upstream admission receipt digest.
    pub boundaries: crate::BoundaryMetadataSet,
    /// Exact digest binding the admission receipt, the rendered output identity,
    /// and the boundary metadata into one output identity.
    ///
    /// A consumer re-checks it with `ActiveUnderstandingViewResult::verify_boundaries`
    /// rather than trusting the field: it is recomputed from what the consumer holds.
    pub boundary_binding: String,
}

impl ActiveUnderstandingViewResult {
    /// Re-check this result's boundary binding against the values it holds.
    ///
    /// The digest is recomputed from the retained admission receipt, the rendered
    /// output identity, and the boundary payload held here, so a substituted
    /// envelope, a reordered member, or a foreign source revision fails even when
    /// each object would still validate on its own.
    pub fn verify_boundaries(&self) -> Result<(), AssemblyError> {
        verify_boundary_binding(
            &self.boundary_binding,
            &self.admitted.economy.receipt_digest,
            &self.view.output_digest,
            &self.boundaries,
        )?;
        self.boundaries.validate(&assembly_boundary_limits())?;
        self.round_trip_boundary_bytes()
    }

    /// Round-trips the packed bytes against the binding recorded at production.
    ///
    /// `boundary_binding` was recorded before any transport and is bound to the
    /// upstream admission receipt, so the comparison is against the value the
    /// owner admitted - not against a digest derived from the bytes being read
    /// back, which would agree with itself.
    fn round_trip_boundary_bytes(&self) -> Result<(), AssemblyError> {
        read_back_boundaries(
            &self.boundaries.pack()?,
            &self.boundary_binding,
            &self.admitted.economy.receipt_digest,
            &self.view.output_digest,
            &self.view.rendered,
        )
        .map(|_| ())
        .map_err(AssemblyError::Contract)
    }
}
