//! Governor semantic admission for a receipt-backed observed change.
//! Reads acquire evidence; only this explicit admission call can write.

use std::collections::BTreeMap;

use eliot_canonical::{CanonicalWriteEnvelope, epistemic_revision::epistemic_revision_command};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_epistemic_contracts::{
    ClaimMap, CoverageDenominator, CoverageReceipt, EpistemicPositionCandidate,
    EpistemicTransition, PositionId, PositionRequest, PositionRevision,
};
use eliot_evidence::ObservationRecord;
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    CanonicalReadClient, EventProjectionRelationIntents, NamedMutationOperation,
    NamedReadOperation, NamedReadRequest, OrderingHeadExpectation, ReadConsistency,
    RevisionHeadExpectation, ScopeRevisionView, SecurityContext, TransitionClass, WriteReceipt,
    WriteReceiptStatus,
    epistemic_revision::{EpistemicCommit, EpistemicPositionReadback},
    generated_operation_manifests, operation_manifest_set_digest, validate_store_receipt_envelope,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    CanonicalAdmissionOwner, CompositionError, CompositionReadiness, KernelTransitionPort,
};

#[cfg(test)]
#[path = "../../../storage/eliot-store-api/tests/support/epistemic_envelope.rs"]
mod store_fixture;

/// Frozen proposal inputs survive retry unchanged. The capture envelope is
/// checked against a real Kernel receipt before its bytes enter the resolver.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedEpistemicProposal {
    pub position: PositionId,
    pub expected_position_revision: Option<PositionRevision>,
    pub request: PositionRequest,
    pub candidate: EpistemicPositionCandidate,
    pub transition: EpistemicTransition,
    pub denominator: CoverageDenominator,
    pub coverage: CoverageReceipt,
    pub claims: ClaimMap,
    pub captured_observation: CanonicalWriteEnvelope,
    pub source_heads: ScopeRevisionView,
}

/// Borrow of existing owners; there is no separate epistemic state owner.
pub struct GovernorEpistemicComposition<'a, P: ?Sized, R: ?Sized> {
    pub(crate) canonical: &'a CanonicalAdmissionOwner,
    pub(crate) activation: crate::GovernorActivationSnapshot,
    pub(crate) kernel: &'a P,
    pub(crate) reads: &'a R,
    pub(crate) readiness: CompositionReadiness,
}

impl<'a, P: ?Sized, R: ?Sized> GovernorEpistemicComposition<'a, P, R> {
    /// Borrows the canonical admission owner, activation snapshot, Kernel
    /// transition port, read client, and readiness without touching
    /// `composition.rs`.
    ///
    /// Daemon wiring builds this from the public
    /// `GovernorComposition::owners()` (for `&CanonicalAdmissionOwner`),
    /// `read_unique_agent_activation(now)` (for the activation snapshot),
    /// `readiness()`, plus the daemon-held `Arc<DaemonKernelClient>` (as the
    /// `&P: KernelTransitionPort`) and a `KernelContextReadClient` (as the
    /// `&R: CanonicalReadClient`). This mirrors the landed T11.1
    /// `DaemonComposition::context_read_client` attach-style accessor, which
    /// avoids `composition.rs` churn held by DISPATCH-R1-GOVERNOR.
    #[must_use]
    pub const fn borrow(
        canonical: &'a CanonicalAdmissionOwner,
        activation: crate::GovernorActivationSnapshot,
        kernel: &'a P,
        reads: &'a R,
        readiness: CompositionReadiness,
    ) -> Self {
        Self {
            canonical,
            activation,
            kernel,
            reads,
            readiness,
        }
    }
}

fn refused(error: impl std::fmt::Display) -> CompositionError {
    CompositionError::Owner(format!("epistemic admission: {error}"))
}

fn digest(value: &impl Serialize) -> Result<String, CompositionError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(refused)
}

impl<P: KernelTransitionPort + ?Sized, R: CanonicalReadClient + ?Sized>
    GovernorEpistemicComposition<'_, P, R>
{
    async fn read(
        &self,
        proposal: &ObservedEpistemicProposal,
        operation: NamedReadOperation,
        parameters: BTreeMap<String, Value>,
    ) -> Result<Value, CompositionError> {
        let response = self
            .reads
            .execute_named(NamedReadRequest {
                operation,
                scope_id: Some(proposal.source_heads.scope_id.clone()),
                consistency: ReadConsistency::ExactFence,
                state_fence: proposal.request.fence.clone(),
                parameters,
            })
            .await
            .map_err(refused)?;
        response.validate().map_err(refused)?;
        if response.operation != operation || response.state_fence != proposal.request.fence {
            return Err(refused("named read changed operation or fence"));
        }
        Ok(response.payload)
    }

    async fn current(
        &self,
        proposal: &ObservedEpistemicProposal,
    ) -> Result<Option<EpistemicPositionReadback>, CompositionError> {
        let value = self
            .read(
                proposal,
                NamedReadOperation::GetCurrentEpistemicPosition,
                BTreeMap::from([("position".to_owned(), json!(proposal.position.as_str()))]),
            )
            .await?;
        serde_json::from_value(value).map_err(refused)
    }

    fn envelope(
        identity: &RequestIdentity,
        proposal: &ObservedEpistemicProposal,
    ) -> Result<CanonicalWriteEnvelope, CompositionError> {
        let manifest =
            operation_manifest_set_digest(&generated_operation_manifests().map_err(refused)?)
                .map_err(refused)?;
        let command = epistemic_revision_command(
            proposal.position.clone(),
            proposal.expected_position_revision,
            &proposal.transition,
            &proposal.candidate,
        )?;
        Ok(CanonicalWriteEnvelope {
            operation_id: proposal.request.operation_id.clone(),
            request: identity.request.metadata.clone(),
            idempotency_key: identity.idempotency_key.clone(),
            scope_id: proposal.source_heads.scope_id.clone(),
            task_id: Some(proposal.request.task_id.as_str().to_owned()),
            transition_class: TransitionClass::Epistemic,
            requested_effect_ceiling: TransitionClass::Epistemic.maximum_effect(),
            admission_contract_set_digest: digest(proposal)?,
            operation_manifest_digest: manifest,
            semantic_commands: vec![command],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: vec![
                    eliot_store_api::EventId::new(proposal.request.operation_id.as_str())
                        .map_err(refused)?,
                ],
                projection_kinds: vec!["CurrentEpistemicPosition".to_owned()],
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: proposal
                .request
                .records
                .iter()
                .map(|handle| handle.as_str().to_owned())
                .collect(),
            expected_revision_heads: proposal
                .source_heads
                .revision_heads
                .iter()
                .map(|head| RevisionHeadExpectation {
                    key: head.key.clone(),
                    expected_revision: head.revision,
                    state_fence: head.state_fence.clone(),
                })
                .collect(),
            expected_ordering_heads: proposal
                .source_heads
                .ordering_heads
                .iter()
                .map(|head| OrderingHeadExpectation {
                    scope: head.scope.clone(),
                    expected_sequence: head.sequence,
                    state_fence: head.state_fence.clone(),
                })
                .collect(),
        })
    }

    async fn acquired_observation(
        &self,
        proposal: &ObservedEpistemicProposal,
    ) -> Result<ObservationRecord, CompositionError> {
        let capture = &proposal.captured_observation;
        let prepared = capture.prepare()?;
        let receipt = self
            .kernel
            .receipt(capture.operation_id.clone())
            .await?
            .ok_or_else(|| refused("source capture has no external receipt"))?;
        validate_store_receipt_envelope(&capture.request, &prepared, &receipt).map_err(refused)?;
        if receipt.status != WriteReceiptStatus::Committed
            || capture.scope_id != proposal.source_heads.scope_id
            || capture.request.state_fence != proposal.request.fence
            || capture.semantic_commands.len() != 1
            || capture.semantic_commands[0].operation != NamedMutationOperation::CaptureObservation
        {
            return Err(refused(
                "source capture is not committed in this scope/fence",
            ));
        }
        let command = &capture.semantic_commands[0];
        let subject = command
            .parameters
            .get("subject")
            .and_then(Value::as_str)
            .ok_or_else(|| refused("capture has no exact observation bytes"))?;
        let pack = self
            .read(
                proposal,
                NamedReadOperation::GetEvidencePack,
                BTreeMap::from([
                    ("subject".to_owned(), json!(subject)),
                    ("max_records".to_owned(), json!("32")),
                ]),
            )
            .await?;
        let records = pack["records"]
            .as_array()
            .ok_or_else(|| refused("missing evidence records"))?;
        if pack["version"] != 1
            || pack["subject"] != subject
            || pack["scope_id"] != proposal.request.scope
            || pack["provenance"]["truncated"] != false
            || records.is_empty()
            || pack["provenance"]["returned"].as_u64() != Some(records.len() as u64)
            || pack["provenance"]["matched_total"].as_u64() != Some(records.len() as u64)
            || pack["provenance"]["state_fence"] != json!(proposal.request.fence)
            || records.iter().any(|row| {
                row["operation"] != "CaptureObservation"
                    || row["parameters"] != json!(command.parameters)
            })
        {
            return Err(refused("incomplete or substituted evidence read"));
        }
        let observation: ObservationRecord = serde_json::from_str(subject).map_err(refused)?;
        if observation.source_id != capture.request.source_id {
            return Err(refused("observation source differs from captured request"));
        }
        if observation.evidence.provenance.source_id != observation.source_id {
            return Err(refused(
                "observation provenance source differs from its source identity",
            ));
        }
        Self::validate_coverage(proposal, &receipt, subject, &observation)?;
        Ok(observation)
    }

    fn validate_coverage(
        proposal: &ObservedEpistemicProposal,
        receipt: &WriteReceipt,
        subject: &str,
        observation: &ObservationRecord,
    ) -> Result<(), CompositionError> {
        let capture = &proposal.captured_observation;
        let denominator = &proposal.denominator;
        let coverage = &proposal.coverage;
        let snapshot = receipt.require_reconciliation_envelope().map_err(refused)?;
        let manifest =
            operation_manifest_set_digest(&generated_operation_manifests().map_err(refused)?)
                .map_err(refused)?;
        let query = format!(
            "GetEvidencePack:subject-sha256={}",
            sha256_hex(subject.as_bytes())
        );
        if denominator.class != "ObservationRecord"
            || denominator.schema != "eliot.evidence.observation.v1"
            || denominator.revision != digest(&proposal.source_heads)?
            || denominator.snapshot.snapshot_id != snapshot.identity.receipt_id.as_str()
            || denominator.snapshot.owner != capture.request.source_id
            || !denominator.exclusions.is_empty()
            || denominator.bounds.truncated
            || denominator.bounds.offset != 0
            || denominator.bounds.total != 1
            || denominator.roles != std::collections::BTreeSet::from(["observed-source".to_owned()])
            || coverage.query.query_text != query
            || coverage.query.query_revision != manifest.as_str()
            || coverage.frontier.frontier_id != proposal.request.scope
            || coverage.frontier.frontier_revision != digest(&proposal.source_heads)?
            || coverage.policy != manifest.as_str()
            || !coverage.groups.is_empty()
            || !coverage.omissions.is_empty()
            || coverage.members.len() != 1
            || coverage.members[0].member != observation.observation_id
            || coverage.members[0].role != "observed-source"
            || coverage.members[0].disposition
                != eliot_epistemic_contracts::MemberDisposition::Observed
        {
            return Err(refused(
                "coverage does not describe the actual bounded source read",
            ));
        }
        Ok(())
    }

    /// Explicit producer → owner-local resolver → closed semantic admission →
    /// Canonical → Kernel → Store → exact external receipt/current readback.
    pub async fn admit_observed_change(
        &self,
        identity: &RequestIdentity,
        proposal: &ObservedEpistemicProposal,
    ) -> Result<EpistemicPositionReadback, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        identity.validate().map_err(refused)?;
        proposal.source_heads.validate().map_err(refused)?;
        if self.canonical.state_fence() != &proposal.request.fence
            || identity.request.metadata.state_fence != proposal.request.fence
            || identity.request.metadata.request_id != proposal.request.request_id
            || identity.idempotency_key != proposal.request.idempotency_key
            || proposal.request.scope != proposal.source_heads.scope_id.as_str()
        {
            return Err(refused("request/owner binding mismatch"));
        }
        let envelope = Self::envelope(identity, proposal)?;
        let prepared = self.canonical.prepare(&envelope)?;
        let commit = EpistemicCommit::from_prepared(&envelope.request, &prepared)
            .map_err(refused)?
            .ok_or_else(|| refused("missing epistemic payload"))?;
        // An exact retry reconciles its persisted identity before checking heads
        // that the first commit necessarily advanced. Changed bytes fail here.
        if let Some(receipt) = self
            .kernel
            .receipt(proposal.request.operation_id.clone())
            .await?
        {
            commit.readback(&receipt).map_err(refused)?;
            return self.read_committed(proposal, &receipt).await;
        }
        if self.activation.task_revision != proposal.request.revision.value()
            || self.activation.task_id != proposal.request.task_id
            || self.activation.state_fence != proposal.request.fence
            || self.activation.work_scope_id != proposal.request.scope
            || identity
                .request
                .metadata
                .session_id
                .as_ref()
                .map(eliot_contracts::SessionId::as_str)
                != Some(self.activation.session_id.as_str())
            || self.canonical.scope() != &proposal.source_heads
        {
            return Err(refused("stale task or owner read closure"));
        }
        self.check_heads(proposal).await?;
        let before = self.current(proposal).await?;
        match &before {
            None if proposal.expected_position_revision.is_none()
                && proposal.candidate.predecessor.is_none() => {}
            Some(position)
                if position.positions.first().is_some_and(|view| {
                    Some(view.admission.position_revision) == proposal.expected_position_revision
                }) && proposal
                    .candidate
                    .predecessor
                    .as_ref()
                    .is_some_and(|predecessor| {
                        predecessor.as_str() == position.candidate.digest
                    }) => {}
            _ => return Err(refused("stale position predecessor")),
        }
        let observation = self.acquired_observation(proposal).await?;
        Self::validate_semantics(proposal, before.as_ref(), &observation)?;
        self.check_heads(proposal).await?;
        let receipt = match self.canonical.commit(self.kernel, identity, envelope).await {
            Ok(receipt) => receipt,
            Err(error) => match self
                .kernel
                .receipt(proposal.request.operation_id.clone())
                .await?
            {
                Some(receipt) => receipt,
                None => return Err(error), // Unknown never causes a second execution.
            },
        };
        commit.readback(&receipt).map_err(refused)?;
        self.read_committed(proposal, &receipt).await
    }

    fn validate_semantics(
        proposal: &ObservedEpistemicProposal,
        before: Option<&EpistemicPositionReadback>,
        observation: &ObservationRecord,
    ) -> Result<(), CompositionError> {
        let candidate = eliot_epistemic::propose_observed_candidate(
            &proposal.request,
            observation,
            &proposal.denominator,
            &proposal.claims,
            proposal.candidate.predecessor.clone(),
            (proposal.candidate.disclosure, proposal.candidate.privacy),
        )
        .map_err(refused)?;
        if candidate != proposal.candidate {
            return Err(refused(
                "proposal differs from the source-derived candidate",
            ));
        }
        candidate
            .validate_closed(
                (
                    &proposal.request,
                    &proposal.denominator,
                    &proposal.coverage,
                    &proposal.claims,
                ),
                (&[], &[], &[]),
            )
            .map_err(refused)?;
        if proposal.denominator.members != proposal.request.records
            || proposal.coverage.proof_digest != digest(observation)?
        {
            return Err(refused("coverage does not name the acquired evidence"));
        }
        proposal
            .transition
            .validate_closed(
                &proposal.request,
                &candidate,
                before.map_or(&[], |value| value.candidate.support.as_slice()),
                &candidate.support,
            )
            .map_err(refused)?;
        Ok(())
    }

    async fn check_heads(
        &self,
        proposal: &ObservedEpistemicProposal,
    ) -> Result<(), CompositionError> {
        let heads: ScopeRevisionView = serde_json::from_value(
            self.read(
                proposal,
                NamedReadOperation::GetScopeRevisionView,
                BTreeMap::new(),
            )
            .await?,
        )
        .map_err(refused)?;
        if heads != proposal.source_heads {
            return Err(refused("source heads changed during acquisition"));
        }
        Ok(())
    }

    async fn read_committed(
        &self,
        proposal: &ObservedEpistemicProposal,
        receipt: &WriteReceipt,
    ) -> Result<EpistemicPositionReadback, CompositionError> {
        let readback = self
            .current(proposal)
            .await?
            .ok_or_else(|| refused("committed position is absent"))?;
        if readback.receipt != *receipt
            || readback.candidate != proposal.candidate
            || readback.transition != proposal.transition
        {
            return Err(refused("current position differs from this exact commit"));
        }
        Ok(readback)
    }
}

#[cfg(test)]
mod adaptation_tests {
    use super::*;
    use eliot_epistemic_contracts::{
        ClaimVerdict, CoverageDenominatorParams, DenominatorKind, DisclosureClass,
        PaginationBounds, PositionAssertability, PositionRequestParams, PrivacyHandling,
        SnapshotRef, SupportResult,
    };
    use eliot_evidence::{
        Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
        EvidenceFreshness, LifecycleState, Provenance,
    };
    use std::collections::BTreeSet;
    type ProofResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    /// Pure semantic fixture; it asserts no external receipt or daemon proof.
    fn inputs() -> ProofResult<(
        ObservationRecord,
        PositionRequest,
        CoverageDenominator,
        ClaimMap,
    )> {
        let envelope = super::store_fixture::envelope("adaptation", "position", None, None)?;
        let commit = EpistemicCommit::from_prepared(&envelope.request, &envelope.prepare()?)?
            .ok_or("fixture contains no epistemic operation")?;
        let candidate = commit.payload.candidate;
        let observation = ObservationRecord {
            observation_id: eliot_contracts::ArtifactId::new("observed-source")?,
            source_id: eliot_contracts::SourceId::new("source")?,
            subject: "sensor reports a warm room".to_owned(),
            content: "reported reading: 26 C; calibration not verified".to_owned(),
            observed_at: eliot_contracts::ClockReading {
                valid_time_ms: Some(1000),
                known_time_ms: Some(1000),
                transaction_sequence: None,
                monotonic_ns: None,
            },
            evidence: EvidenceEnvelope {
                authority: EvidenceAuthority::SourceIdentity,
                freshness: EvidenceFreshness::ExactCandidate,
                coverage: EvidenceCoverage::CompleteForScope,
                status: EpistemicStatus::Observed,
                assertability: Assertability::NonAssertableUnverified,
                provenance: Provenance {
                    source_id: eliot_contracts::SourceId::new("source")?,
                    capture_route: "test.observed-source".to_owned(),
                    scope: candidate.scope.clone(),
                    raw_handle: Some("observed-source".to_owned()),
                    revision: Some("source-v1".to_owned()),
                },
                verification: None,
                state_fence: candidate.fence.clone(),
            },
            lifecycle: LifecycleState::Active,
        };
        observation.validate()?;
        let request = PositionRequest::new(PositionRequestParams {
            question: observation.subject.clone(),
            request_id: candidate.request_id.clone(),
            operation_id: candidate.operation_id.clone(),
            idempotency_key: candidate.idempotency_key.clone(),
            work_scope: candidate.work_scope.clone(),
            proposition: candidate.proposition.clone(),
            task_id: candidate.task_id.clone(),
            attempt_id: candidate.attempt_id.clone(),
            revision: candidate.revision,
            scope: candidate.scope.clone(),
            validity: candidate.support[0].validity.clone(),
            fence: candidate.fence.clone(),
            records: BTreeSet::from([observation.observation_id.clone()]),
        })?;
        let coverage = CoverageDenominator::new(CoverageDenominatorParams {
            class: "ObservationRecord".to_owned(),
            schema: "eliot.evidence.observation.v1".to_owned(),
            revision: "source-v1".to_owned(),
            scope: request.scope.clone(),
            fence: request.fence.clone(),
            members: request.records.clone(),
            roles: BTreeSet::from(["observed-source".to_owned()]),
            query: None,
            frontier: None,
            snapshot: SnapshotRef::new("pure-test-source", observation.source_id.clone())?,
            exclusions: Vec::new(),
            bounds: PaginationBounds::new(0, 1, 1, false)?,
            validity: request.validity.clone(),
            kind: DenominatorKind::CompleteScope,
        })?;
        let mut claim = candidate.claims[0].clone();
        claim.statement_digest = digest(&observation.subject)?;
        claim.coverage_digest.clone_from(&coverage.digest);
        let claims = ClaimMap::new(
            candidate.manifest,
            BTreeSet::from([claim.claim.clone()]),
            vec![claim],
            Vec::new(),
            BTreeSet::new(),
        )?;
        Ok((observation, request, coverage, claims))
    }

    fn propose(
        observation: &ObservationRecord,
        request: &PositionRequest,
        coverage: &CoverageDenominator,
        claims: &ClaimMap,
    ) -> Result<EpistemicPositionCandidate, eliot_epistemic_contracts::ContractError> {
        eliot_epistemic::propose_observed_candidate(
            request,
            observation,
            coverage,
            claims,
            None,
            (DisclosureClass::Open, PrivacyHandling::Unrestricted),
        )
    }

    #[test]
    fn observed_bytes_produce_withheld_candidate_and_exact_proof() -> ProofResult {
        let (observation, request, coverage, claims) = inputs()?;
        let candidate = propose(&observation, &request, &coverage, &claims)?;
        assert_eq!(candidate.support[0].result, SupportResult::Unknown);
        assert_eq!(candidate.claims[0].verdict, ClaimVerdict::Withheld);
        assert_eq!(
            candidate.proposed_assertability,
            PositionAssertability::UnknownWithheldQuarantined
        );
        assert!(candidate.verifier.is_none());
        assert_eq!(candidate.proof_digest, digest(&observation)?);
        assert_eq!(candidate.support[0].handles, request.records);
        let mut changed = observation.clone();
        changed.content = "reported reading: 27 C; calibration not verified".to_owned();
        let next = propose(&changed, &request, &coverage, &claims)?;
        assert_ne!(next.digest, candidate.digest);
        assert_ne!(next.proof_digest, candidate.proof_digest);
        assert_eq!(next.support[0].result, SupportResult::Unknown);
        Ok(())
    }

    #[test]
    fn changed_source_identity_scope_or_freshness_cannot_reuse_the_inquiry() -> ProofResult {
        let (observation, request, coverage, claims) = inputs()?;
        let mut changed = observation.clone();
        changed.observation_id = eliot_contracts::ArtifactId::new("another-source")?;
        assert!(propose(&changed, &request, &coverage, &claims).is_err());
        changed = observation.clone();
        changed.subject = "different proposition".to_owned();
        assert!(propose(&changed, &request, &coverage, &claims).is_err());
        changed = observation.clone();
        changed.evidence.provenance.scope = "another-scope".to_owned();
        assert!(propose(&changed, &request, &coverage, &claims).is_err());
        changed = observation;
        changed.evidence.freshness = EvidenceFreshness::KnownOlderSnapshot;
        assert!(propose(&changed, &request, &coverage, &claims).is_err());
        Ok(())
    }

    #[test]
    fn model_authority_and_accepted_claim_cannot_launder_an_observation() -> ProofResult {
        let (mut observation, request, coverage, claims) = inputs()?;
        observation.evidence.authority = EvidenceAuthority::ModelInterpretation;
        assert!(propose(&observation, &request, &coverage, &claims).is_err());
        observation.evidence.authority = EvidenceAuthority::SourceIdentity;
        let mut accepted = claims.entries[0].clone();
        accepted.verdict = ClaimVerdict::Accepted;
        accepted.audit = eliot_epistemic_contracts::ClaimAuditOutcome::Supported;
        let claims = ClaimMap::new(
            claims.manifest,
            BTreeSet::from([accepted.claim.clone()]),
            vec![accepted],
            Vec::new(),
            BTreeSet::new(),
        )?;
        assert!(propose(&observation, &request, &coverage, &claims).is_err());
        Ok(())
    }
}
