//! Assembled view and intrinsic selection-integrity proof.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, ContractVersion, SourceId, canonical_json_bytes, sha256_hex};
use eliot_evidence::{Assertability, EpistemicStatus};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AdmittedAtom, AdmittedContextSet, AtomAvailability, AuthorityClass, ContextBinding,
    ContextError, ContextExecutionIdentity, ContextRecipe, LossPolicy, MeasurementRef,
    PrivacyClass, ProofBinding, QualityDimension, QualityDimensionResult, QualityOperation,
    QualityRefusal, QualityRefusalKind, QualityScorecard, QualitySuitability,
    SerializedContextMeasurement,
};

/// Rendered projection of one admitted atom, retaining all load-bearing fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RenderedAtom {
    pub atom_id: ArtifactId,
    pub role: crate::SemanticRole,
    pub source_id: ArtifactId,
    pub source_identity: SourceId,
    pub source_owner: crate::ProviderId,
    pub source_revision: String,
    pub source_digest: String,
    pub source_predecessor: Option<ArtifactId>,
    pub provider: crate::ProviderId,
    pub representation: crate::AtomRepresentation,
    pub availability: AtomAvailability,
    pub protected: bool,
    pub privacy: PrivacyClass,
    pub authority: AuthorityClass,
    pub loss_policy: LossPolicy,
    pub status: EpistemicStatus,
    pub assertability: Assertability,
    pub measurement: MeasurementRef,
    pub dependencies: Vec<ArtifactId>,
    pub proof: ProofBinding,
}

impl RenderedAtom {
    /// Project an admitted candidate without changing any load-bearing field.
    pub fn from_admitted(atom: &AdmittedAtom) -> Self {
        Self {
            atom_id: atom.candidate.atom_id.clone(),
            role: atom.candidate.provider_role.role,
            source_id: atom.candidate.source.snapshot_id.clone(),
            source_identity: atom.candidate.source.source_id.clone(),
            source_owner: atom.candidate.source.owner.clone(),
            source_revision: atom.candidate.source.revision.clone(),
            source_digest: atom.candidate.source.content_sha256.clone(),
            source_predecessor: atom.candidate.source.predecessor.clone(),
            provider: atom.candidate.provider_role.provider.clone(),
            representation: atom.candidate.representation.clone(),
            availability: atom.candidate.availability,
            protected: atom.candidate.protected,
            privacy: atom.candidate.privacy,
            authority: atom.candidate.authority,
            loss_policy: atom.candidate.loss_policy,
            status: atom.candidate.status,
            assertability: atom.candidate.assertability,
            measurement: atom.candidate.measurement.clone(),
            dependencies: atom.candidate.dependencies.clone(),
            proof: atom.candidate.proof.clone(),
        }
    }
}

#[derive(Serialize)]
struct CanonicalRenderedPayload<'a> {
    schema_version: ContractVersion,
    binding: &'a ContextBinding,
    recipe_digest: &'a str,
    fence_digest: &'a str,
    rendered: &'a [RenderedAtom],
}

/// Proof that rendered membership is exactly admitted membership.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionIntegrityProof {
    pub binding: ContextBinding,
    pub admitted_ids: Vec<ArtifactId>,
    pub rendered_ids: Vec<ArtifactId>,
    pub omission_evidence: Vec<ArtifactId>,
    pub output_digest: String,
}

impl SelectionIntegrityProof {
    /// Validate exact set equality with one occurrence per identity.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        let admitted: BTreeSet<_> = self.admitted_ids.iter().cloned().collect();
        let rendered: BTreeSet<_> = self.rendered_ids.iter().cloned().collect();
        if admitted.len() != self.admitted_ids.len()
            || rendered.len() != self.rendered_ids.len()
            || admitted != rendered
        {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        if self.omission_evidence.len() > 256 {
            return Err(ContextError::Bounds {
                field: "selection.omission_evidence",
            });
        }
        crate::validate_digest(&self.output_digest, "selection.output_digest")
    }
}

/// Immutable Active Understanding View assembled from an admitted set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActiveUnderstandingView {
    pub binding: ContextBinding,
    pub admitted_ids: Vec<ArtifactId>,
    pub rendered: Vec<RenderedAtom>,
    pub selection: SelectionIntegrityProof,
    pub quality: QualityScorecard,
    pub measurement: SerializedContextMeasurement,
    /// Revisions that produced these exact delivered bytes.
    ///
    /// #1724 W4/W5. The rendered ordering, serializer identity/options, route
    /// and model all change the output, and this view is the record a consumer
    /// receives, so the execution is named here rather than being implied by a
    /// crate constant. It is cross-checked against the independently recorded
    /// `measurement` in `validate`, so an execution identity that does not
    /// describe this view's own measurement is refused rather than trusted.
    pub execution: ContextExecutionIdentity,
    pub output_digest: String,
    pub recipe_digest: String,
    /// Digest of the approved reusable Context policy revision this View was
    /// compiled under, read unchanged from the recipe instance's own recorded
    /// `DecisionRevision::policy_sha256`.
    ///
    /// #1724 W5. This is the cross-record half of the recipe binding:
    /// `validate_against` compares it with `AdmittedContextSet::economy`'s own
    /// recorded value, so a View, a scorecard and an economy receipt produced
    /// under different approved policy revisions cannot be joined by hashing
    /// each of them.
    pub policy_sha256: String,
    pub fence_digest: String,
}

impl ActiveUnderstandingView {
    fn canonical_payload<'a>(
        binding: &'a ContextBinding,
        recipe_digest: &'a str,
        fence_digest: &'a str,
        rendered: &'a [RenderedAtom],
    ) -> CanonicalRenderedPayload<'a> {
        CanonicalRenderedPayload {
            schema_version: crate::CONTEXT_CONTRACT_VERSION,
            binding,
            recipe_digest,
            fence_digest,
            rendered,
        }
    }

    /// Compute the digest of the ordered serialized rendered payload.
    pub fn canonical_output_digest(
        binding: &ContextBinding,
        recipe_digest: &str,
        fence_digest: &str,
        rendered: &[RenderedAtom],
    ) -> Result<String, ContextError> {
        let payload = Self::canonical_payload(binding, recipe_digest, fence_digest, rendered);
        let bytes = canonical_json_bytes(&payload)
            .map_err(|_| ContextError::InvalidField("view.canonical_payload"))?;
        Ok(sha256_hex(&bytes))
    }

    /// Return the exact UTF-8 length of the canonical serialized payload.
    pub fn canonical_output_utf8_bytes(
        binding: &ContextBinding,
        recipe_digest: &str,
        fence_digest: &str,
        rendered: &[RenderedAtom],
    ) -> Result<u64, ContextError> {
        let payload = Self::canonical_payload(binding, recipe_digest, fence_digest, rendered);
        let bytes = canonical_json_bytes(&payload)
            .map_err(|_| ContextError::InvalidField("view.canonical_payload"))?;
        u64::try_from(bytes.len()).map_err(|_| ContextError::Overflow)
    }

    /// Assemble a view by projection only; membership is never selected here.
    pub fn assemble(
        admitted: &AdmittedContextSet,
        quality: QualityScorecard,
        measurement: SerializedContextMeasurement,
        execution: ContextExecutionIdentity,
        output_digest: String,
        recipe_digest: String,
        fence_digest: String,
    ) -> Result<Self, ContextError> {
        admitted.validate()?;
        quality.validate()?;
        measurement.validate()?;
        if quality.binding != admitted.binding || measurement.context != admitted.binding {
            return Err(ContextError::InvalidFence);
        }
        let selected: Vec<_> = admitted
            .records
            .iter()
            .filter(|record| {
                matches!(
                    record.disposition,
                    crate::AdmissionDisposition::Include | crate::AdmissionDisposition::HandleOnly
                )
            })
            .map(RenderedAtom::from_admitted)
            .collect();
        // The admitted identities are read from the admitted set, and the
        // rendered identities from the projection. Deriving both from the
        // projection would make the equality this proof records a comparison of
        // one list with a copy of itself, which no dropped member can violate.
        let admitted_ids: Vec<ArtifactId> = admitted
            .records
            .iter()
            .filter(|record| {
                matches!(
                    record.disposition,
                    crate::AdmissionDisposition::Include | crate::AdmissionDisposition::HandleOnly
                )
            })
            .map(|record| record.candidate.atom_id.clone())
            .collect();
        let rendered_ids: Vec<ArtifactId> =
            selected.iter().map(|atom| atom.atom_id.clone()).collect();
        let derived_output_digest = Self::canonical_output_digest(
            &admitted.binding,
            &recipe_digest,
            &fence_digest,
            &selected,
        )?;
        if output_digest != derived_output_digest {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        drop(output_digest);
        let selection = SelectionIntegrityProof {
            binding: admitted.binding.clone(),
            admitted_ids: admitted_ids.clone(),
            rendered_ids,
            omission_evidence: admitted.economy.displaced.clone(),
            output_digest: derived_output_digest.clone(),
        };
        selection.validate()?;
        crate::validate_digest(&derived_output_digest, "view.output_digest")?;
        crate::validate_digest(&recipe_digest, "view.recipe_digest")?;
        crate::validate_digest(&fence_digest, "view.fence_digest")?;
        let view = Self {
            binding: admitted.binding.clone(),
            admitted_ids,
            rendered: selected,
            selection,
            quality,
            measurement,
            execution,
            output_digest: derived_output_digest,
            recipe_digest,
            policy_sha256: admitted.economy.policy_sha256.clone(),
            fence_digest,
        };
        view.validate_against(admitted)?;
        Ok(view)
    }

    /// Validate every rendered field against the exact admitted record.
    pub fn validate_against(&self, admitted: &AdmittedContextSet) -> Result<(), ContextError> {
        admitted.validate()?;
        self.validate()?;
        if self.binding != admitted.binding {
            return Err(ContextError::InvalidFence);
        }
        // The admitted economy receipt carries the recipe commitment produced by
        // admission.  A view built from a different recipe must not validate
        // against this admitted set, so the two digests are compared here rather
        // than only hashed into the view's own payload.
        //
        // #1724 W5: the SAME comparison is made for the approved reusable policy
        // revision, on both records. `recipe_digest` identifies one compilation's
        // instance and says nothing about which approved policy it was issued
        // under; `policy_sha256` is that fact on each side, produced by
        // different stages (admission read it off the instance it admitted, the
        // assembly read it off the recipe it rendered). Neither value is an input
        // to a digest the other is checked against, so a View and a receipt
        // issued under different policy revisions are refused here even when
        // both are individually well-formed and share a task, attempt, scope,
        // decision and fence.
        if self.recipe_digest != admitted.economy.recipe_digest
            || self.policy_sha256 != admitted.economy.policy_sha256
        {
            return Err(ContextError::IdentityConflict);
        }
        // The admitted half of the scorecard's output binding, compared against
        // the admitted set's own canonical payload digest and its own displaced
        // list. Both sides are independent records: the digest is recomputed by
        // the existing admitted-set owner over the admitted records, and the
        // expected omissions are the admitted set's, not the scorecard's copy.
        // A card graded against a different admitted set therefore cannot
        // validate against this one even when the two share a task, attempt,
        // scope, decision and fence.
        if self.quality.output.admitted_digest != admitted.canonical_payload_digest()?
            || self.quality.output.omission_handles != admitted.economy.displaced
        {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        let expected_omissions: BTreeSet<_> = admitted.economy.displaced.iter().cloned().collect();
        let actual_omissions: BTreeSet<_> =
            self.selection.omission_evidence.iter().cloned().collect();
        if expected_omissions != actual_omissions {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        let expected: Vec<_> = admitted
            .records
            .iter()
            .filter(|record| {
                matches!(
                    record.disposition,
                    crate::AdmissionDisposition::Include | crate::AdmissionDisposition::HandleOnly
                )
            })
            .collect();
        if expected.len() != self.rendered.len() {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        for record in expected {
            let rendered = self
                .rendered
                .iter()
                .find(|atom| atom.atom_id == record.candidate.atom_id)
                .ok_or(ContextError::SelectionIntegrityMismatch)?;
            if rendered.role != record.candidate.provider_role.role
                || rendered.provider != record.candidate.provider_role.provider
                || rendered.source_id != record.candidate.source.snapshot_id
                || rendered.source_identity != record.candidate.source.source_id
                || rendered.source_owner != record.candidate.source.owner
                || rendered.source_revision != record.candidate.source.revision
                || rendered.source_digest != record.candidate.source.content_sha256
                || rendered.source_predecessor != record.candidate.source.predecessor
                || rendered.representation != record.candidate.representation
                || rendered.availability != record.candidate.availability
                || rendered.protected != record.candidate.protected
                || rendered.privacy != record.candidate.privacy
                || rendered.authority != record.candidate.authority
                || rendered.loss_policy != record.candidate.loss_policy
                || rendered.status != record.candidate.status
                || rendered.assertability != record.candidate.assertability
                || rendered.measurement != record.candidate.measurement
                || rendered.dependencies != record.candidate.dependencies
                || rendered.proof != record.candidate.proof
            {
                return Err(ContextError::SelectionIntegrityMismatch);
            }
        }
        Ok(())
    }

    /// The source revisions this view's delivered atoms were read from.
    ///
    /// The independent expected set for
    /// `QualityOutputBinding::evidence_revisions`: one revision per distinct
    /// source snapshot actually present in the rendered projection, deduplicated
    /// and in canonical order. It is derived from the delivered atoms rather
    /// than from the card, so a card cannot satisfy it by restating its own
    /// list, and it is a set because repeating one revision is one revision, not
    /// two observations.
    ///
    /// The revision identity is the source snapshot identity
    /// (`RenderedAtom::source_id`), not the free-text `source_revision` label:
    /// two labels could agree while naming different snapshots, and the snapshot
    /// identity is the value `validate_against` already proves back to
    /// `AdmittedAtom::candidate.source.snapshot_id`.
    fn observed_source_revisions(&self) -> Vec<ArtifactId> {
        let distinct: BTreeSet<ArtifactId> = self
            .rendered
            .iter()
            .map(|atom| atom.source_id.clone())
            .collect();
        distinct.into_iter().collect()
    }

    /// Check this exact view's readiness for one requested dependent decision
    /// or effect, using the one shared rule.
    ///
    /// [`ActiveUnderstandingView::validate`] stays structural integrity. This is
    /// the separate, operation-scoped readiness fact a direct View consumer
    /// reads, so a deserialized view cannot reach an effect by satisfying
    /// structure alone. The view is validated first, so a refusal names a view
    /// that describes no gradeable packet as
    /// [`QualityRefusalKind::InvalidScorecard`] instead of quietly returning a
    /// grade from a mutated view.
    pub fn suitability(
        &self,
        operation: QualityOperation,
        additional_required: &[QualityDimension],
    ) -> Result<QualitySuitability, QualityRefusal> {
        self.validate().map_err(|_| QualityRefusal {
            kind: QualityRefusalKind::InvalidScorecard,
            operation,
            blocking: Vec::new(),
            unresolved_applicability: Vec::new(),
        })?;
        self.quality.suitability(operation, additional_required)
    }

    /// Detect any post-assembly mutation or injected non-admitted content.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        self.selection.validate()?;
        // The view carries its own `fence_digest`, so re-hashing that string
        // only proves internal consistency.  Recompute it from the State Fence
        // the view claims to have been compiled against, so a well-shaped but
        // unrelated digest cannot be re-sealed into a valid view.
        let expected_fence_digest = crate::canonical_fence_digest(&self.binding.state_fence)?;
        if self.fence_digest != expected_fence_digest {
            return Err(ContextError::InvalidFence);
        }
        let derived_output_digest = Self::canonical_output_digest(
            &self.binding,
            &self.recipe_digest,
            &self.fence_digest,
            &self.rendered,
        )?;
        if self.selection.output_digest != derived_output_digest
            || self.output_digest != derived_output_digest
        {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        self.quality.validate()?;
        self.measurement.validate()?;
        // The execution that produced these bytes, compared against the view's
        // own independently recorded measurement. The two are separate records
        // written by different steps (the assembly owner states the ordering and
        // serializer it applied; the measurement owner reports what it
        // measured), and neither is an input to a digest the other is checked
        // against, so a view carrying one execution identity and another
        // measurement is refused here.
        self.execution.binds_measurement(&self.measurement)?;
        // The rendered half of the scorecard's output binding, compared against
        // the rendered half of this view. `derived_output_digest` is the one
        // existing canonical digest of the ordered rendered payload and it
        // reads only `{schema_version, binding, recipe_digest, fence_digest,
        // rendered}` — the scorecard is not an input to it, so binding the
        // grade to the final representation is not circular. Because the recipe
        // digest and the rendered bytes are both in that input, a card graded on
        // a different recipe or a different membership yields a different
        // recorded value and is rejected here even when the fence matches.
        if self.quality.output.recipe_digest != self.recipe_digest
            || self.quality.output.fence_digest != self.fence_digest
            || self.quality.output.rendered_digest != derived_output_digest
        {
            return Err(ContextError::QualityIncomplete);
        }
        // The serializer/route half of the output binding, compared against the
        // execution this view was actually produced under. `execution` is the
        // assembly owner's own record of the policy it applied, and
        // `binds_measurement` above already compared it against the
        // independently recorded measurement, so this is a third record
        // disagreeing with the card rather than the card compared with itself.
        // Two compilations of identical bytes under different serializer,
        // options or route identities are different outputs, and a card that
        // names the wrong one is refused.
        if self.quality.output.serializer_id != self.execution.serializer_id
            || self.quality.output.serializer_version != self.execution.serializer_version
            || self.quality.output.serializer_options_digest
                != self.execution.serializer_options_digest
            || self.quality.output.route_id != self.execution.route_id
        {
            return Err(ContextError::QualityIncomplete);
        }
        // The source-revision half. Every revision the card claims it graded
        // from must be a revision this packet actually carries. The expected
        // set is derived from the rendered projection, not from the card, and
        // `validate_against` already proves each rendered `source_id` equals
        // its admitted record's `source.snapshot_id`, so a card citing a
        // foreign or never-observed source revision is refused while a card
        // citing a genuine one passes. The comparison runs in this direction —
        // claimed ⊆ observed — because that is the guarantee: it makes a
        // valid-looking handle without a current observation unable to bind.
        // It deliberately does not demand the reverse, which would make a
        // re-sealed packet that legitimately gained a source ungradeable by
        // the seed card it was legitimately re-graded under.
        let observed_revisions = self.observed_source_revisions();
        if self
            .quality
            .output
            .evidence_revisions
            .iter()
            .any(|claimed| !observed_revisions.contains(claimed))
        {
            return Err(ContextError::QualityIncomplete);
        }
        // A dimension that reports a pass may only cite an observation this
        // packet actually recorded. `MeasurementRef::validate` above proved
        // each cited handle is well formed, which is a shape check; this
        // compares the CONTENT of every cited measurement against the
        // measurement identities carried by the delivered atoms, which is what
        // makes a valid-looking handle without a current observation unable to
        // pass. The expected set is the rendered atoms' own records, so a
        // dimension cannot satisfy this by citing its own list twice.
        //
        // Membership is by VALUE (`MeasurementRef` is a digest plus a serializer
        // identity and implements neither `Ord` nor `Hash`, so it cannot be a
        // set key). Both fields are compared, so a cited handle that matches on
        // one and differs on the other is not a member.
        let observed_measurements: Vec<&MeasurementRef> =
            self.rendered.iter().map(|atom| &atom.measurement).collect();
        for result in &self.quality.results {
            if result.state.is_pass()
                && result.measurements.iter().any(|cited| {
                    !observed_measurements.iter().any(|observed| {
                        observed.digest == cited.digest && observed.serializer == cited.serializer
                    })
                })
            {
                return Err(ContextError::QualityIncomplete);
            }
        }
        if self.selection.binding != self.binding
            || self.quality.binding != self.binding
            || self.measurement.context != self.binding
        {
            return Err(ContextError::InvalidFence);
        }
        let rendered_bytes = Self::canonical_output_utf8_bytes(
            &self.binding,
            &self.recipe_digest,
            &self.fence_digest,
            &self.rendered,
        )?;
        if self.measurement.envelope_digest != derived_output_digest
            || self.measurement.rendered_utf8_bytes != rendered_bytes
        {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        let rendered_ids = self
            .rendered
            .iter()
            .map(|atom| atom.atom_id.clone())
            .collect::<Vec<_>>();
        if rendered_ids != self.selection.rendered_ids
            || self.admitted_ids != self.selection.admitted_ids
        {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        if self.rendered.iter().any(|atom| {
            atom.representation.validate().is_err()
                || atom.source_digest.len() != 64
                || atom.measurement.validate().is_err()
        }) {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        crate::validate_digest(&self.output_digest, "view.output_digest")?;
        crate::validate_digest(&self.recipe_digest, "view.recipe_digest")?;
        crate::validate_digest(&self.policy_sha256, "view.policy_sha256")?;
        crate::validate_digest(&self.fence_digest, "view.fence_digest")
    }
}

/// The retained result of a compilation that did not complete.
///
/// #1726 W6. An incomplete compilation is not an absent one: the recipe that
/// was actually attempted, the exact handles that were available, and the
/// COMPLETE set of failed and unknown dimension results all survive the
/// refusal, because the next thing a reader needs is precisely which dimension
/// lacks which evidence — not an empty error and not a successful
/// [`ActiveUnderstandingView`] standing in for a compilation that did not happen.
///
/// This is a retention record, not a packet. It carries no rendered bytes and
/// no measurement, so it cannot be consumed as a packet: there is no
/// `ActiveUnderstandingView` inside it that some downstream reader might treat
/// as assembled and acted on. Converting it to a packet is the job of a
/// reevaluation, which produces a new record and leaves this one intact.
///
/// The two existing vocabularies are reused rather than a third failure type
/// introduced: the grade is a [`QualityScorecard`] carrying the existing
/// [`QualityDimensionState`] per dimension, and the reason is the existing
/// [`QualityRefusal`]. There is no new pass/fail vocabulary here, only a place
/// to keep both of them after a refusal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IncompleteCompilation {
    /// Exact task/attempt/scope/decision/fence the attempt was made under.
    pub binding: ContextBinding,
    /// The recipe this compilation actually attempted, retained whole.
    ///
    /// The recipe revision and its approved policy digest are what a
    /// reevaluation must be re-decided against, so the attempted recipe
    /// survives the refusal instead of being reduced to a message. It is the
    /// recipe this attempt was made with, not a successful one: nothing here
    /// claims the recipe produced a packet.
    pub attempted_recipe: ContextRecipe,
    /// Canonical digest of [`Self::attempted_recipe`].
    ///
    /// This is the recipe's own `recipe_sha256`, which
    /// [`ContextRecipe::canonical_policy_digest`] re-derives from the policy
    /// shape with the digest field itself zeroed. It is recorded beside the
    /// recipe so a reader can compare this attempt against a later
    /// reevaluation without re-deriving it, and it is re-derived in
    /// [`Self::validate`] rather than trusted, so a deserialized record whose
    /// digest does not describe the recipe beside it is refused.
    pub attempted_recipe_digest: String,
    /// Exact handles the admitted set did make available.
    ///
    /// These are the identities the compilation could reach — the exact
    /// references a reader can still go and open. They are the "retain exact
    /// handle only" disposition, and they are recorded as the admitted set's
    /// own member identities rather than as the caller's list, so the retained
    /// handles are what this attempt actually had.
    pub available_handles: Vec<ArtifactId>,
    /// Omission handles the attempt recorded for the material it did not carry.
    ///
    /// Read from the admitted set's own displaced list by the constructor, so
    /// it is the attempt's accounting and not a restatement.
    pub omitted_handles: Vec<ArtifactId>,
    /// The COMPLETE twelve-dimension card, refused rather than truncated.
    ///
    /// Every failed, unknown, degraded, not-applicable and invalidated result
    /// stays here with the evidence it lacks. Nothing is dropped so the record
    /// fits a smaller payload, and a reader that sees only the blocking results
    /// is not shown the dimensions that passed.
    pub quality: QualityScorecard,
    /// The typed operation-scoped refusal that stopped the compilation.
    pub refusal: QualityRefusal,
}

impl IncompleteCompilation {
    /// Retain one refused compilation attempt.
    ///
    /// The expected sets here are derived from what the attempt actually holds,
    /// never from the caller's lists: the recipe digest is recomputed by the
    /// recipe's own `canonical_policy_digest`, the available handles are the
    /// admitted set's own member identities, and the omitted handles are the
    /// admitted set's own displaced list. A caller that supplies a card, a
    /// refusal and a set of "the handles I had" gets the handles this attempt
    /// really had instead.
    ///
    /// `quality` and `refusal` are checked against each other and against the
    /// retained binding before this constructor returns: a card that does not
    /// describe this binding and recipe, or a refusal that names no blocked
    /// dimension and no unresolved applicability input, cannot become a
    /// retained record that reads as a real refusal of a real attempt.
    pub fn retain(
        binding: &ContextBinding,
        attempted_recipe: &ContextRecipe,
        admitted: &AdmittedContextSet,
        quality: QualityScorecard,
        refusal: QualityRefusal,
    ) -> Result<Self, ContextError> {
        binding.validate()?;
        attempted_recipe.validate()?;
        admitted.validate()?;
        if attempted_recipe.binding != *binding || admitted.binding != *binding {
            return Err(ContextError::IdentityConflict);
        }
        // The card must grade THIS attempt: same binding, and the same
        // compilation identity the retained recipe carries. A card graded
        // against a different recipe or fence is not a diagnosis of this one.
        if quality.binding != *binding
            || quality.output.recipe_digest != attempted_recipe.recipe_sha256
        {
            return Err(ContextError::IdentityConflict);
        }
        quality.validate()?;
        // The refusal must be a refusal of the same attempt, naming the same
        // binding through the card it was read from. An `InvalidScorecard`
        // refusal is a structural rejection rather than a diagnosis of a real
        // grade, so it is not retained as one: this record exists to keep a
        // genuine incomplete grade readable.
        if refusal.kind == QualityRefusalKind::InvalidScorecard {
            return Err(ContextError::QualityIncomplete);
        }
        if refusal.blocking.is_empty() && refusal.unresolved_applicability.is_empty() {
            return Err(ContextError::QualityIncomplete);
        }
        // The retained handles are the admitted set's own member identities,
        // deduplicated and in canonical order. Derived here rather than accepted
        // from the caller, so the record cannot claim a handle this attempt
        // never had or silently omit one it did.
        let available_handles: Vec<ArtifactId> = admitted
            .records
            .iter()
            .map(|record| record.candidate.atom_id.clone())
            .collect::<BTreeSet<ArtifactId>>()
            .into_iter()
            .collect();
        let omitted_handles = admitted.economy.displaced.clone();
        let record = Self {
            binding: binding.clone(),
            attempted_recipe_digest: attempted_recipe.recipe_sha256.clone(),
            attempted_recipe: attempted_recipe.clone(),
            available_handles,
            omitted_handles,
            quality,
            refusal,
        };
        record.validate()?;
        Ok(record)
    }

    /// Every dimension result that did not reach an observed pass.
    ///
    /// This is the complete failed/unknown set for the retained attempt, in
    /// canonical dimension order, derived from the card's own results against
    /// the contract owner's [`QualityDimensionResult::is_current_pass`] rather
    /// than against the refusal's `blocking` list. The refusal names what
    /// blocked ONE operation; this names every dimension that is not a current
    /// pass, which is the wider set a diagnostic reader needs. A dimension that
    /// failed but does not block the requested operation is still here, and an
    /// invalidated result is here too: its grade is historical, not current.
    #[must_use]
    pub fn incomplete_results(&self) -> Vec<QualityDimensionResult> {
        self.quality
            .results
            .iter()
            .filter(|result| !result.is_current_pass())
            .cloned()
            .collect()
    }

    /// Whether this retained record is still bound to the compilation it
    /// describes.
    ///
    /// Invalidation is not a new scheme here: it is the existing binding.
    /// A route, governing-instruction, source, task or verifier change alters
    /// the recipe revision, the state fence or the evidence revisions this
    /// attempt was made under, so a reevaluation under changed inputs produces
    /// a DIFFERENT record and this one must not be read as describing it. The
    /// historical evidence stays on the card and is still visible; only its
    /// currency is decided here.
    ///
    /// The comparison is against the three values the compilation was actually
    /// made under — the binding, the attempted recipe digest and the fence
    /// digest the card recorded — read off the caller that holds the new ones.
    /// It is the same set of fields the existing scorecard-binding and view
    /// validation already compare, so a change to any of them produces a new
    /// record rather than a stale one read as current.
    #[must_use]
    pub fn still_current_for(
        &self,
        binding: &ContextBinding,
        recipe_digest: &str,
        fence_digest: &str,
    ) -> bool {
        self.binding == *binding
            && self.attempted_recipe_digest == recipe_digest
            && self.quality.output.fence_digest == fence_digest
    }

    /// Split this attempt's non-passing results by what the requested operation
    /// actually requires of them.
    ///
    /// #1726 A6. "Optional" and "mandatory" are not a flag a producer sets on a
    /// dimension: they are a closed function of the requested operation, read
    /// from the contract owner's own
    /// [`QualityOperation::required_dimensions`], exactly as
    /// [`QualityScorecard::suitability`] reads it. A caller therefore cannot
    /// declare an inconvenient dimension optional and cannot declare a
    /// required one optional to make a refusal disappear.
    ///
    /// The two halves of A6 are separated here, on independent grounds:
    ///
    /// * `mandatory` is every non-passing result the operation independently
    ///   requires. These are the results that must not be traded away, and a
    ///   *failed* one among them is a real failure — no optional uncertainty
    ///   elsewhere in the card can absorb it, because the two are read from
    ///   disjoint parts of the requirement and one is never subtracted from the
    ///   other. The refusal is what stops the dependent action, and the
    ///   operation's required set is not reducible by an unrelated result.
    /// * `optional` is every non-passing result the operation does not
    ///   require. These are the informational uncertainties. They stay visible
    ///   and they stay reported, and they do not appear in `mandatory` — so
    ///   their presence never has to be argued about to let independent safe
    ///   work that the operation does not depend on proceed.
    ///
    /// The two lists partition [`Self::incomplete_results`]: nothing is dropped
    /// and nothing appears twice, so a reader can count the failures and the
    /// uncertainties separately without re-deriving the split.
    #[must_use]
    pub fn incomplete_results_by_requirement(
        &self,
        operation: QualityOperation,
        additional_required: &[QualityDimension],
    ) -> (Vec<QualityDimensionResult>, Vec<QualityDimensionResult>) {
        // The mandatory set is read from the contract owner and unioned with
        // the recipe-selected blockers. Union is the only combining operation,
        // so a recipe can add a required dimension and never remove one.
        let required: BTreeSet<QualityDimension> = operation
            .required_dimensions()
            .iter()
            .chain(additional_required)
            .copied()
            .collect();
        let mut mandatory = Vec::new();
        let mut optional = Vec::new();
        for result in self.incomplete_results() {
            if required.contains(&result.dimension) {
                mandatory.push(result);
            } else {
                optional.push(result);
            }
        }
        (mandatory, optional)
    }

    /// The mandatory results this attempt is missing for one operation.
    ///
    /// A6's first half, stated as the property it has: an optional dimension's
    /// uncertainty is not in this list, so it cannot conceal a mandatory
    /// failure that is, and a mandatory failure is not hidden merely because
    /// some unrelated dimension is also uncertain. The list is empty exactly
    /// when every dimension the operation independently requires reached an
    /// observed current pass.
    ///
    /// This is the first element of
    /// [`Self::incomplete_results_by_requirement`], named for the caller that
    /// only needs the half. A caller that also has to report the
    /// informational uncertainties calls that method instead, so the two
    /// readings are the same function and cannot drift apart.
    #[must_use]
    pub fn mandatory_failures(
        &self,
        operation: QualityOperation,
        additional_required: &[QualityDimension],
    ) -> Vec<QualityDimensionResult> {
        self.incomplete_results_by_requirement(operation, additional_required)
            .0
    }

    /// Validate the retained record against its own contents.
    ///
    /// Structural integrity of the retention, not suitability: a retained
    /// incomplete compilation is a real record of a real refusal, and the fact
    /// that it is incomplete is what it is for. The card is validated by
    /// `QualityScorecard::validate`, the recipe by its own `validate`, and the
    /// binding by its own; the cross-record checks are the recipe digest
    /// re-derived from the recipe held, the handles compared against the
    /// independent declaration each claims, and the refusal checked to name the
    /// attempt rather than an unrelated operation.
    ///
    /// This says nothing about whether the attempt is still CURRENT against a
    /// later compilation. That is [`Self::still_current_for`], and it needs the
    /// new values a reevaluation was made under, which this record does not
    /// have: a self-consistent record that has since been superseded still
    /// validates, because the historical evidence it carries is meant to stay
    /// readable.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        // `ContextRecipe::validate` already re-derives `recipe_sha256` from the
        // policy shape, so the recipe held here cannot be an altered one. The
        // retained digest is checked against that same re-derivation rather
        // than trusted, because a deserialized record can carry a digest that
        // does not describe the recipe beside it.
        self.attempted_recipe.validate()?;
        if self.attempted_recipe_digest != self.attempted_recipe.canonical_policy_digest()? {
            return Err(ContextError::IdentityConflict);
        }
        if self.attempted_recipe.binding != self.binding {
            return Err(ContextError::IdentityConflict);
        }
        self.quality.validate()?;
        if self.quality.binding != self.binding
            || self.quality.output.recipe_digest != self.attempted_recipe_digest
        {
            return Err(ContextError::IdentityConflict);
        }
        // Self-currency: the record must still be bound to the compilation it
        // names. `still_current_for` compares the same three values a later
        // reevaluation would, so a route/instruction/source/task/verifier
        // change makes a record historical and it is never re-sealed as current.
        if !self.still_current_for(
            &self.binding,
            &self.attempted_recipe_digest,
            &self.quality.output.fence_digest,
        ) {
            return Err(ContextError::InvalidFence);
        }
        if self.attempted_recipe.binding != self.binding {
            return Err(ContextError::IdentityConflict);
        }
        self.quality.validate()?;
        if self.quality.binding != self.binding
            || self.quality.output.recipe_digest != self.attempted_recipe_digest
        {
            return Err(ContextError::IdentityConflict);
        }
        // A refusal that blocks nothing is not a diagnosis; retaining one would
        // let a caller present a structurally-rejected card as a graded
        // incomplete attempt.
        if self.refusal.kind == QualityRefusalKind::InvalidScorecard
            || (self.refusal.blocking.is_empty()
                && self.refusal.unresolved_applicability.is_empty())
        {
            return Err(ContextError::QualityIncomplete);
        }
        // Both handle lists are sets, checked here rather than only at
        // construction because this struct is deserializable: a repeated handle
        // states no additional fact, so a padded list cannot pose as wider
        // coverage.
        let mut available: BTreeSet<&ArtifactId> = BTreeSet::new();
        for handle in &self.available_handles {
            if !available.insert(handle) {
                return Err(ContextError::Duplicate("incomplete.available_handles"));
            }
        }
        let mut omitted: BTreeSet<&ArtifactId> = BTreeSet::new();
        for handle in &self.omitted_handles {
            if !omitted.insert(handle) {
                return Err(ContextError::Duplicate("incomplete.omitted_handles"));
            }
        }
        // Every omission handle the card claims must be one this attempt
        // actually recorded as displaced. The comparison runs claimed ⊆
        // recorded, the same direction the existing scorecard-binding checks
        // use, because that is the guarantee: a card cannot account for an
        // omission this attempt did not make. The reverse is deliberately not
        // demanded — the assembly owner raises this refusal for a reason that
        // can precede its own admitted-set comparison, and a retained attempt
        // is still a truthful record of what was tried when its card and its
        // admitted set are compared at different stages of one compilation.
        if self
            .quality
            .output
            .omission_handles
            .iter()
            .any(|claimed| !omitted.contains(claimed))
        {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        Ok(())
    }

    /// Show this retained attempt for a read-only diagnostic display.
    ///
    /// A2. Diagnostic display is the one operation that requires nothing, so
    /// the same packet that cannot enable a dependent action is still shown —
    /// with its limitation *stated*, not flattened. This returns both halves a
    /// honest display needs: the granted [`QualitySuitability`], which carries
    /// the applicability inputs that remain unresolved, and the COMPLETE set of
    /// results that are not current observed passes, so the displayed
    /// limitation is every dimension this attempt did not clear, not only the
    /// ones that happened to block the operation the compiler asked about.
    ///
    /// Returning `Ok` grants no authority and no action readiness; it is the
    /// read-only path, and the accompanying results say exactly how far the
    /// attempt got. The same record is refused for
    /// [`QualityOperation::DependentAction`], which is what "shown
    /// diagnostically" is meant to distinguish from.
    pub fn diagnostic_display(
        &self,
    ) -> Result<(QualitySuitability, Vec<QualityDimensionResult>), ContextError> {
        self.validate()?;
        let suitability = self
            .quality
            .suitability(QualityOperation::DiagnosticDisplay, &[])
            .map_err(|_| ContextError::QualityIncomplete)?;
        Ok((suitability, self.incomplete_results()))
    }
}
