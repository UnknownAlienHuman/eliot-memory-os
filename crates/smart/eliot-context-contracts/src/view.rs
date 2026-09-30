//! Assembled view and intrinsic selection-integrity proof.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ArtifactId, ContractVersion, SourceId, canonical_json_bytes, sha256_hex};
use eliot_evidence::{Assertability, EpistemicStatus};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AdmittedAtom, AdmittedContextSet, AtomAvailability, AuthorityClass, ContextBinding,
    ContextError, ContextExecutionIdentity, LossPolicy, MeasurementRef, PrivacyClass, ProofBinding,
    QualityDimension, QualityOperation, QualityRefusal, QualityRefusalKind, QualityScorecard,
    QualitySuitability, SerializedContextMeasurement,
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

    /// Validate every rendered field against the exact admitted record, and the
    /// grade against the exact admitted set it was read from.
    ///
    /// This is the admitted-set-anchored half of the output binding: it joins
    /// the scorecard's recorded admitted digest, omission handles and
    /// source/evidence revisions against this admitted set's own values, so a
    /// card graded against a different admitted set, recipe or source set is
    /// refused even when both share one task, attempt, scope, decision and
    /// fence. [`ActiveUnderstandingView::validate`] remains the part a
    /// deserialized view can check on its own.
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
        // The source/evidence-revision join. The admitted records are the
        // authority on which source snapshots a grade may be read from, so the
        // expected set is derived here from `AdmittedContextSet::records` and
        // not from the scorecard's own list: a card that never observed one of
        // the admitted sources, or that claims a source this packet does not
        // carry, is refused instead of passing on unrelated nonempty handles.
        // The set is the distinct `source.snapshot_id` of every admitted
        // record, which is exactly the recorded meaning of
        // `QualityOutputBinding::evidence_revisions`.
        //
        // A revision that moved is caught by the checks around this one, not by
        // this set: every rendered atom's `source_revision` is compared against
        // its own admitted record below, and `canonical_payload_digest` above
        // hashes the admitted records themselves, so a changed source revision
        // changes a recorded digest or a compared field and is rejected.
        let expected_revisions: BTreeSet<ArtifactId> = admitted
            .records
            .iter()
            .map(|record| record.candidate.source.snapshot_id.clone())
            .collect();
        let graded_revisions: BTreeSet<ArtifactId> = self
            .quality
            .output
            .evidence_revisions
            .iter()
            .cloned()
            .collect();
        if expected_revisions != graded_revisions {
            return Err(ContextError::QualityIncomplete);
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
            missing_evidence: BTreeMap::new(),
        })?;
        self.quality.suitability(operation, additional_required)
    }

    /// Detect any post-assembly mutation or injected non-admitted content.
    ///
    /// This is the self-contained half of the grade/output binding: it joins the
    /// scorecard's recorded recipe, fence, rendered digest, source/evidence
    /// revisions and omission handles against this view's own values, so a
    /// deserialized or mutated view cannot carry a grade that belongs to a
    /// different packet. [`ActiveUnderstandingView::validate_against`] is the
    /// other half, the join against the admitted set itself.
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
// #1726: the grade is bound to this exact representation's own source
        // and omission handles, not only to a pre-pruning candidate set.
        //
        // This is the self-contained half of that binding, so a deserialized
        // view with no admitted set in hand still detects the change. The
        // compared side is the scorecard's recorded `evidence_revisions` and
        // `omission_handles`; the expected sides are two independent records
        // this view already carries — its own rendered source snapshots (via
        // `observed_source_revisions`) and its own selection-proof omission
        // evidence. A card graded against a different membership, a different
        // source set or a different omission set records different values here
        // and is rejected, which is what makes a route, source, task or verifier
        // change invalidate a grade instead of leaving it silently current.
        // Nothing is re-hashed as a substitute for validating the recorded
        // value: the card's recorded values are compared against the view's own
        // values, and the canonical rendered digest above remains the single
        // existing owner of the final-representation identity.
        //
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
        // The source-revision half, against this representation's own source
        // snapshots. Every revision the card claims it graded from must be a
        // revision this packet actually carries. The expected set is derived
        // from the rendered projection, not from the card, and `validate_against`
        // already proves each rendered `source_id` equals its admitted record's
        // `source.snapshot_id`, so a card citing a foreign or never-observed
        // source revision is refused while a card citing a genuine one passes.
        // The comparison runs in this direction — claimed ⊆ observed — because
        // that is the guarantee: it makes a valid-looking handle without a
        // current observation unable to bind. It deliberately does not demand
        // the reverse, which would make a re-sealed packet that legitimately
        // gained a source ungradeable by the seed card it was legitimately
        // re-graded under.
        //
        // #1726: this is deliberately ONE-WAY where the rescue's version was
        // two-way. Demanding the reverse here would refuse a re-sealed packet
        // that legitimately gained a source, which is the case the comment
        // above names; the rescue's bidirectional equality is recovered where it
        // is sound, in `validate_against` against the admitted set itself.
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
// #1726: the omission half of the same binding, which the checks above
        // do not cover. The card's recorded `omission_handles` are compared
        // against this representation's own selection-proof omission evidence —
        // a second record the view carries, written by the selection proof and
        // not copied from the card. A card graded against a different omission set
        // records different values here and is refused. The source half of the
        // rescue's bidirectional equality is deliberately NOT restored here,
        // because main's one-way `claimed ⊆ observed` comparison above is the
        // stricter guarantee for a re-sealable packet; this adds only the part
        // main did not already check.
        if self.quality.output.omission_handles != self.selection.omission_evidence {
            return Err(ContextError::QualityIncomplete);
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
