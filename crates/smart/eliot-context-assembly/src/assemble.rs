//! Public assembly operation and its explicit phases.

use eliot_context_contracts::{
    ActiveUnderstandingView, AdmittedContextSet, ContextError, ContextRecipe,
    DownstreamHeadroomRequest, DownstreamHeadroomResult, HeadroomAttempt, HeadroomDimension,
    HeadroomRefusal, HeadroomReleaseInstruction, MeasurementStatus, QualityOperation,
    QualityRefusal, QualityRefusalKind, QualityScorecard, SerializedContextMeasurement,
};
use thiserror::Error;

use crate::{AssemblyError, boundary, bounds, measurement, render};

/// Stable local ordering revision for the A-15 canonical rendered payload.
pub const ASSEMBLY_ORDERING_REVISION: &str = "a18.role-provider-atom.v1";

/// Caller-owned immutable parameters for one A-18 projection.
#[derive(Clone, Debug, Eq, PartialEq)]
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
    fn validate(&self) -> Result<(), AssemblyError> {
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
            if value.len() > bounds::MAX_TEXT_BYTES {
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

/// The typed refusal this assembly owner returns instead of an assembled packet.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("downstream headroom handoff refused: {attempt}")]
pub struct HeadroomHandoffRefusal {
    /// The attempted recipe and omissions preserved across the refusal.
    pub attempt: HeadroomAttempt,
    /// The release instructions the owner must still execute for the permits it
    /// issued, so a failed publication cannot strand a reservation silently.
    ///
    /// An unknown downstream effect yields the same instruction as a known one:
    /// the owner reconciles it, and this crate never invents a safe release.
    pub releases: Vec<HeadroomReleaseInstruction>,
}

/// Recheck the actual output and handoff against its reservation.
///
/// I12.13: bind economy/View to the same budget, recipe and headroom evidence,
/// include serialized wrappers, advertised tools and retained metadata in the
/// final measurement, and prevent dependent action-ready publication on a stale
/// or revoked reservation, a changed route/serializer/profile, or a post-render
/// overflow, while preserving the attempted recipe and omissions in a typed
/// result.
///
/// The recheck is pure: it reads the assembled result, the recipe, the
/// reservation evidence and the caller's observed clock, and performs no I/O.
/// The reservation owner stays the only party that can release or reconcile the
/// permits named in the returned instructions, which is what makes failure,
/// cancellation and downstream completion all terminate the reservation through
/// the owner that issued it.
pub fn recheck_headroom_handoff(
    assembled: &ActiveUnderstandingViewResult,
    recipe: &ContextRecipe,
    request: &DownstreamHeadroomRequest,
    headroom: &DownstreamHeadroomResult,
    now_ms: u64,
) -> Result<Vec<HeadroomReleaseInstruction>, HeadroomHandoffRefusal> {
    let attempted_recipe_digest = recipe.recipe_sha256.clone();
    let reason_ref = assembled.admitted.floor.rule_evidence.clone();
    let release_instructions = || {
        request
            .demands
            .iter()
            .filter_map(|demand| headroom.reservation(demand.dimension))
            .map(|reservation| HeadroomReleaseInstruction {
                permit_id: reservation.permit_id.clone(),
                operation_id: reservation.operation_id.clone(),
                condition: request.release.clone(),
            })
            .collect()
    };
    let withhold = |refusal: HeadroomRefusal| HeadroomHandoffRefusal {
        attempt: HeadroomAttempt {
            attempted_recipe_digest: attempted_recipe_digest.clone(),
            omissions: assembled.admitted.economy.omissions.clone(),
            refusal,
        },
        // The owner still holds every permit it issued, so the release duty
        // exists on the refusal path too and must not be dropped.
        releases: release_instructions(),
    };
    // The boundary round trip proves the delivered units against the upstream
    // admission receipt before anything here reads the packet as final.
    assembled.verify_boundaries().map_err(|_| {
        withhold(HeadroomRefusal::IdentityChanged {
            reason: reason_ref.clone(),
        })
    })?;
    // The final measurement must describe the exact canonical rendered payload,
    // which is where the serialized wrappers, advertised tools and retained
    // metadata already are. A view whose measurement is not that exact payload
    // is not a packet whose overflow any reservation could have covered.
    assembled.view.validate().map_err(|_| {
        withhold(HeadroomRefusal::IdentityChanged {
            reason: reason_ref.clone(),
        })
    })?;
    // Economy, View and reservation resolve to one recipe and one route.
    if assembled.view.recipe_digest != recipe.recipe_sha256
        || assembled.admitted.economy.recipe_digest != recipe.recipe_sha256
        || request.recipe_digest != recipe.recipe_sha256
        || assembled.view.measurement.route_id != request.route_id
        || assembled.view.measurement.serializer_id != request.serializer_id
    {
        return Err(withhold(HeadroomRefusal::IdentityChanged {
            reason: reason_ref.clone(),
        }));
    }
    headroom
        .validate_against(request, &assembled.view.binding, now_ms)
        .map_err(|error| {
            let refusal = match error {
                ContextError::StaleFloor | ContextError::InvalidFence => HeadroomRefusal::Stale {
                    reason: reason_ref.clone(),
                },
                ContextError::CapacityExceeded | ContextError::Overflow => {
                    HeadroomRefusal::PostRenderOverflow {
                        reason: reason_ref.clone(),
                    }
                }
                _ => HeadroomRefusal::IdentityChanged {
                    reason: reason_ref.clone(),
                },
            };
            withhold(refusal)
        })?;
    // Post-render overflow against the reserved envelope: the exact rendered
    // payload plus the referenced output and review reserves must still fit the
    // route capacity the reservation was compiled under.
    //
    // The envelope compared against is the *recipe's* declared capacity, and the
    // economy receipt's recorded allocations must equal it. The floor's own
    // `capacity` is a caller-supplied Safety Floor envelope that nothing proves
    // equal this recipe's, so measuring the rendered payload against it would
    // check the overflow against an envelope the reservation was never issued
    // for.
    let declared = &recipe.capacity;
    let allocations = &assembled.admitted.economy.allocations;
    if allocations.route_capacity != declared.route_capacity
        || allocations.fixed_overhead != declared.fixed_overhead
        || allocations.output_reserve != declared.output_reserve
        || allocations.review_reserve != declared.review_reserve
    {
        return Err(withhold(HeadroomRefusal::IdentityChanged {
            reason: reason_ref.clone(),
        }));
    }
    let reserved = declared
        .fixed_overhead
        .checked_add(declared.output_reserve)
        .and_then(|value| value.checked_add(declared.review_reserve))
        .and_then(|value| value.checked_add(assembled.view.measurement.rendered_utf8_bytes))
        .ok_or_else(|| {
            withhold(HeadroomRefusal::PostRenderOverflow {
                reason: reason_ref.clone(),
            })
        })?;
    if reserved > declared.route_capacity {
        return Err(withhold(HeadroomRefusal::PostRenderOverflow {
            reason: reason_ref.clone(),
        }));
    }
    // Every demanded dimension must still be granted under the live fence. An
    // unknown downstream effect names the exact limiting dimensions rather than
    // resolving into an invented safe release.
    let limiting: Vec<HeadroomDimension> = request
        .demands
        .iter()
        .map(|demand| demand.dimension)
        .filter(|dimension| headroom.reservation(*dimension).is_none())
        .collect();
    if !limiting.is_empty() {
        return Err(withhold(HeadroomRefusal::Unavailable {
            dimensions: limiting,
        }));
    }
    Ok(release_instructions())
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

/// Builds and self-validates the selection proof for one assembled view.
///
/// Extracted so the membership and identity checks read as one step: the proof
/// is what claims rendered membership is exactly admitted membership, and its
/// own `validate` is the only place that claim is checked. See #251 - the two
/// id sets must come from independent projections, and `validate` also compares
/// lengths so a duplicated id cannot collapse inside a set.
///
/// The admitted identities are therefore read here from the admission owner's
/// set, and the caller supplies only the rendered ones. Passing one list for
/// both would make the equality a comparison of a list with a copy of itself,
/// which no atom the projection dropped, added or duplicated could violate.
/// `AdmittedContextSet::validate` refuses any record that is not `Include` or
/// `HandleOnly` and `render` projects every record, so for a valid admitted set
/// the two sets are equal; only the recorded order of `admitted_ids` differs
/// from the presentation order of the projection.
fn selection_proof(
    admitted: &AdmittedContextSet,
    rendered_ids: &[eliot_contracts::ArtifactId],
    output_digest: &str,
) -> Result<eliot_context_contracts::SelectionIntegrityProof, AssemblyError> {
    let selection = eliot_context_contracts::SelectionIntegrityProof {
        binding: admitted.binding.clone(),
        admitted_ids: admitted
            .records
            .iter()
            .map(|record| record.candidate.atom_id.clone())
            .collect(),
        rendered_ids: rendered_ids.to_vec(),
        omission_evidence: admitted.economy.displaced.clone(),
        output_digest: output_digest.to_owned(),
    };
    selection.validate()?;
    Ok(selection)
}

/// The exact output identity one assembly of this admitted set will produce.
///
/// I12.13 grades a rendered packet, so `QualityScorecard::output` must name the
/// final representation through `rendered_digest` — the ordered rendered
/// payload, not the pre-pruning candidate set. That digest is produced here and
/// nowhere else, and `assemble_active_view` consumes the scorecard as an input
/// to its quality gate. A caller therefore has to know the rendered digest
/// before it can grade, while the rendered digest only exists once the admitted
/// set has been rendered. This is the one value that closes that order, and it
/// is returned by the same two functions `assemble_active_view` itself uses, so
/// the digest a card is built against and the digest assembly later compares are
/// one derivation rather than two that must agree.
///
/// It is a read of the admitted set and the recipe. It grants nothing, admits
/// nothing and changes no state: the values it returns are recomputed and
/// re-compared by `require_graded_output` when the real assembly runs, so a
/// caller cannot launder a mismatched card through this function.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedOutputIdentity {
    /// `ActiveUnderstandingView::canonical_output_digest` of the ordered
    /// rendered payload this stage will produce for this admitted set.
    pub output_digest: String,
    /// The canonical digest of the state fence that render is bound to.
    pub fence_digest: String,
}

/// The one render-and-match derivation, shared by the pre-render identity and
/// by the assembly itself.
///
/// `fence_digest` is passed in rather than recomputed so the caller's already
/// validated fence value is the one that binds the render, and so this function
/// adds no second computation of it.
fn render_and_match(
    admitted: &AdmittedContextSet,
    recipe: &ContextRecipe,
    fence_digest: &str,
) -> Result<(Vec<eliot_context_contracts::RenderedAtom>, String, Vec<u8>), AssemblyError> {
    let rendered = render::render(admitted);
    let (output_digest, bytes) = measurement::canonical_matches(
        &admitted.binding,
        &recipe.recipe_sha256,
        fence_digest,
        &rendered,
    )?;
    Ok((rendered, output_digest, bytes))
}

/// The output identity [`assemble_active_view`] will produce for this admitted
/// set, obtained without grading it.
///
/// The caller needs this to build the `QualityScorecard` that
/// `assemble_active_view` requires, and it needs it before that call because the
/// card names the rendered output. The admission and recipe are validated with
/// their own owners' validators first, and the render is the same
/// `render::render` + `measurement::canonical_matches` pair the assembly runs, so
/// the value returned here is the value the assembly later recomputes and
/// compares rather than an independent prediction of it.
///
/// # Errors
///
/// Returns [`AssemblyError`] when the admitted set or the recipe fails its own
/// closed contract, when they are not bound to one another, or when the render
/// cannot be canonicalised. Nothing is defaulted and no empty identity is
/// returned: a caller that cannot learn the real rendered digest must not grade.
pub fn rendered_output_identity(
    admitted: &AdmittedContextSet,
    recipe: &ContextRecipe,
) -> Result<RenderedOutputIdentity, AssemblyError> {
    recipe.validate()?;
    if recipe.binding != admitted.binding {
        return Err(AssemblyError::Contract(ContextError::IdentityConflict));
    }
    admitted.validate()?;
    let fence_digest =
        eliot_context_contracts::canonical_fence_digest(&admitted.binding.state_fence)?;
    let (_, output_digest, _) = render_and_match(admitted, recipe, &fence_digest)?;
    Ok(RenderedOutputIdentity {
        output_digest,
        fence_digest,
    })
}

/// Assemble one exact admitted set using one injected measurement call.
///
/// The callback receives the exact canonical A-15 rendered payload bytes and
/// is invoked once. This prototype accepts only exact UTF-8 byte measurement;
/// tokenizer and STU observations remain data for a later qualified route.
pub fn assemble_active_view<F>(
    admitted: &AdmittedContextSet,
    recipe: &ContextRecipe,
    quality: QualityScorecard,
    policy: &AssemblyPolicy,
    measure: F,
) -> Result<ActiveUnderstandingViewResult, AssemblyError>
where
    F: FnOnce(&[u8]) -> Result<SerializedContextMeasurement, ContextError>,
{
    preflight(admitted, recipe, &quality, policy)?;
    recipe.validate()?;
    if recipe.binding != admitted.binding || recipe.capacity != admitted.floor.capacity {
        return Err(AssemblyError::Contract(ContextError::IdentityConflict));
    }
    admitted.validate()?;
    if admitted.economy.recipe_digest != recipe.recipe_sha256 {
        return Err(AssemblyError::Contract(ContextError::IdentityConflict));
    }
    if admitted.economy.measurement.digest != admitted.canonical_payload_digest()? {
        return Err(AssemblyError::Contract(ContextError::IdentityConflict));
    }
    validate_recipe_membership(admitted, recipe)?;
    if quality.binding != admitted.binding {
        return Err(AssemblyError::Contract(ContextError::InvalidFence));
    }
    let allocations = &admitted.economy.allocations;
    let capacity = &admitted.floor.capacity;
    if allocations.route_capacity != capacity.route_capacity
        || allocations.fixed_overhead != capacity.fixed_overhead
        || allocations.output_reserve != capacity.output_reserve
        || allocations.review_reserve != capacity.review_reserve
    {
        return Err(AssemblyError::Contract(ContextError::EconomyMismatch));
    }
    if let Some(incomplete) = admitted.floor.incomplete()? {
        return Err(AssemblyError::Incomplete(Box::new(incomplete)));
    }
    // One readiness rule for this consumer. The typed refusal is returned, not
    // discarded: the caller receives the operation it asked for, whether it was
    // blocked by a dimension result or by an unresolved applicability input, and
    // the exact blocking results, instead of a generic quality error it would
    // have to re-derive. A card that is not even structurally valid is still a
    // contract rejection unless the owner reported it as quality incompleteness.
    if let Err(refusal) = quality.suitability(QualityOperation::Compile, &[]) {
        if refusal.kind == QualityRefusalKind::InvalidScorecard {
            quality.validate().map_err(AssemblyError::Contract)?;
        }
        return Err(AssemblyError::QualityIncomplete(
            Box::new(quality),
            Box::new(refusal),
        ));
    }
    let expected_fence_digest =
        eliot_context_contracts::canonical_fence_digest(&admitted.binding.state_fence)?;
    if policy.fence_digest != expected_fence_digest {
        return Err(AssemblyError::Contract(ContextError::InvalidFence));
    }
    // Preserve boundaries before presentation sorting. This projection is the
    // membership-changing transform the shared boundary contract is about: it emits
    // one envelope per rendered unit plus the exact input-to-output member relation,
    // keyed to the admitted source order rather than the role/provider sort below.
    let boundaries = boundary::project_assembly_boundaries(admitted, recipe)?;
    let (rendered, output_digest, bytes) =
        render_and_match(admitted, recipe, &expected_fence_digest)?;
    require_graded_output(
        &quality,
        admitted,
        &recipe.recipe_sha256,
        &expected_fence_digest,
        &output_digest,
    )?;
    let final_bytes =
        u64::try_from(bytes.len()).map_err(|_| AssemblyError::Contract(ContextError::Overflow))?;
    if final_bytes > policy.max_serialized_bytes {
        return Err(AssemblyError::Bounds("assembly.final_bytes"));
    }
    let measured = measure(&bytes)?;
    let measured = measurement::verify(
        measured,
        &admitted.binding,
        &bytes,
        &output_digest,
        &admitted.floor.capacity,
        policy,
        policy.max_serialized_bytes,
    )?;
    let rendered_ids: Vec<_> = rendered.iter().map(|atom| atom.atom_id.clone()).collect();
    let selection = selection_proof(admitted, &rendered_ids, &output_digest)?;
    let view = ActiveUnderstandingView {
        binding: admitted.binding.clone(),
        admitted_ids: selection.admitted_ids.clone(),
        rendered,
        selection,
        quality,
        measurement: measured,
        output_digest,
        recipe_digest: recipe.recipe_sha256.clone(),
        fence_digest: expected_fence_digest,
    };
    view.validate_against(admitted)?;
    // Binding the boundary metadata into the output identity is a separate step so
    // the three owner-produced inputs stay visible: the admission receipt sealed
    // upstream, the rendered output identity, and the boundary envelopes with their
    // ordered member relations. Altered boundary metadata therefore changes the
    // bound output identity instead of being invisible to it.
    let boundary_binding = boundary::boundary_binding_digest(
        &admitted.economy.receipt_digest,
        &view.output_digest,
        &boundaries,
    )?;
    Ok(ActiveUnderstandingViewResult {
        view,
        admitted: admitted.clone(),
        serialized_bytes: bytes,
        boundaries,
        boundary_binding,
    })
}

/// Require that the card graded the exact output this assembly just produced.
///
/// The card is compared against the recipe revision, the fence, the admitted
/// set's own canonical payload digest, the ordered rendered payload digest and
/// the omission handles. Every one of those is the packet's own recorded value,
/// recomputed by its existing owner, and the scorecard is an input to none of
/// them, so grading the final representation and hashing that representation
/// stay two ordered steps rather than a receipt containing its own output hash.
///
/// A card swapped in from another same-fence packet with a different recipe or
/// membership records a different value here, so it is refused with the card
/// retained: the caller receives the exact grades that were rejected instead of
/// a fabricated success.
fn require_graded_output(
    quality: &QualityScorecard,
    admitted: &AdmittedContextSet,
    recipe_digest: &str,
    fence_digest: &str,
    rendered_digest: &str,
) -> Result<(), AssemblyError> {
    if quality.output.recipe_digest != recipe_digest
        || quality.output.fence_digest != fence_digest
        || quality.output.admitted_digest != admitted.canonical_payload_digest()?
        || quality.output.rendered_digest != rendered_digest
        || quality.output.omission_handles != admitted.economy.displaced
    {
        return Err(AssemblyError::QualityIncomplete(
            Box::new(quality.clone()),
            Box::new(QualityRefusal {
                kind: QualityRefusalKind::InvalidScorecard,
                operation: QualityOperation::Compile,
                blocking: Vec::new(),
                unresolved_applicability: Vec::new(),
            }),
        ));
    }
    Ok(())
}

fn preflight(
    admitted: &AdmittedContextSet,
    recipe: &ContextRecipe,
    quality: &QualityScorecard,
    policy: &AssemblyPolicy,
) -> Result<(), AssemblyError> {
    policy.validate()?;
    bounds::admitted(admitted)?;
    bounds::recipe(recipe)?;
    bounds::quality(quality)
}

fn validate_recipe_membership(
    admitted: &AdmittedContextSet,
    recipe: &ContextRecipe,
) -> Result<(), AssemblyError> {
    if recipe.mandatory_roles.len() != admitted.floor.mandatory_roles.len()
        || recipe
            .mandatory_roles
            .iter()
            .any(|role| !admitted.floor.mandatory_roles.contains(role))
    {
        return Err(AssemblyError::Contract(ContextError::DenominatorMismatch));
    }
    for slot in &admitted.floor.providers.requested {
        let matching = recipe
            .denominator
            .requested
            .iter()
            .any(|candidate| candidate == slot);
        if !matching {
            return Err(AssemblyError::Contract(ContextError::DenominatorMismatch));
        }
    }
    for record in &admitted.records {
        let candidate = &record.candidate;
        let slot = recipe
            .denominator
            .dispositions
            .iter()
            .find(|disposition| disposition.slot == candidate.provider_role)
            .ok_or(AssemblyError::Contract(ContextError::DenominatorMismatch))?;
        if slot.state != candidate.availability {
            return Err(AssemblyError::Contract(ContextError::IdentityConflict));
        }
        let role_policy = recipe
            .role_policies
            .iter()
            .find(|policy| policy.role == candidate.provider_role.role)
            .ok_or(AssemblyError::Contract(ContextError::IdentityConflict))?;
        if role_policy.loss_policy != candidate.loss_policy
            || !role_policy
                .allowed_representations
                .contains(&candidate.representation.kind())
        {
            return Err(AssemblyError::Contract(ContextError::WholeUnitRequired));
        }
    }
    Ok(())
}

/// Complete projection result retaining the exact A-15 accounting evidence
/// that the compact view schema represents only through omission identities.
#[derive(Clone, Debug, Eq, PartialEq)]
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
    pub boundaries: eliot_context_contracts::BoundaryMetadataSet,
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
        boundary::verify_boundary_binding(
            &self.boundary_binding,
            &self.admitted.economy.receipt_digest,
            &self.view.output_digest,
            &self.boundaries,
        )?;
        self.boundaries
            .validate(&boundary::assembly_boundary_limits())?;
        self.round_trip_boundary_bytes()
    }

    /// Round-trips the packed bytes against the binding recorded at production.
    ///
    /// `boundary_binding` was recorded before any transport and is bound to the
    /// upstream admission receipt, so the comparison is against the value the
    /// owner admitted - not against a digest derived from the bytes being read
    /// back, which would agree with itself.
    fn round_trip_boundary_bytes(&self) -> Result<(), AssemblyError> {
        boundary::read_back_boundaries(
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
