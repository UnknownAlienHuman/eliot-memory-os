//! Governor-owned, source-validated epistemic inputs for Orientation.

use eliot_context_candidates::ProjectionState;
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_epistemic_contracts::{
    CurrentEpistemicPosition, Currentness, EpistemicPositionCandidate,
};
use eliot_evidence::ObservationRecord;
use eliot_read::{DeclaredResultSelector, ReadCoverage, ReadIdentity};
use eliot_store_api::{
    NamedReadOperation, ReadConsistency, WriteReceipt, WriteReceiptStatus,
    epistemic_revision::EpistemicPositionReadback,
};
use serde_json::{Value, json};
use thiserror::Error;

use crate::{ContextReconstructionRequest, RoleAcquisition, SevenRoleInputs};

/// Typed refusal from binding the original evidence and position reads.
/// Each variant preserves which retained owner record failed.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum EpistemicOrientationReadError {
    /// The original immutable context selector failed owner validation.
    #[error("original context read request is invalid")]
    InvalidRequest,
    /// The request and retained before/after read closure differ.
    #[error("context read closure mismatch at {field}")]
    ReadClosureMismatch { field: &'static str },
    /// A required named role is partial, absent, stale, or otherwise refused.
    #[error("required {role} role is not complete: {state:?}")]
    RoleNotComplete {
        role: &'static str,
        state: ProjectionState,
    },
    /// A completed role did not retain its original read identity.
    #[error("complete {role} role has no retained ReadIdentity")]
    MissingReadIdentity { role: &'static str },
    /// A retained identity does not bind the requested operation/read closure.
    #[error("{role} ReadIdentity mismatch at {field}")]
    ReadIdentityMismatch {
        role: &'static str,
        field: &'static str,
    },
    /// The original evidence read used another selector bound.
    #[error("evidence ReadIdentity does not retain the requested selector bound")]
    EvidenceBoundMismatch,
    /// The exact original native position readback was not retained.
    #[error("original position readback is absent")]
    MissingPositionReadback,
    /// The position role has no original payload.
    #[error("original position read payload is absent")]
    MissingPositionPayload,
    /// The original position payload could not be decoded as its native owner type.
    #[error("original position payload does not decode")]
    InvalidPositionPayload,
    /// The retained position payload and native decoded readback diverge.
    #[error("position payload/readback mismatch at {field}")]
    PositionReadbackMismatch { field: &'static str },
    /// The original position readback has no Current view in its exact slot.
    #[error("position readback has no admitted Current view")]
    MissingCurrentPosition,
    /// The original admitted Current view fails its owner's validation.
    #[error("original admitted Current view is invalid")]
    InvalidCurrentPosition,
    /// The original receipt, selector, scope, or admitted view do not join.
    #[error("position admission mismatch at {field}")]
    PositionAdmissionMismatch { field: &'static str },
    /// The original receipt digest does not match its exact candidate preimage.
    #[error("original candidate digest mismatch at {field}")]
    CandidateDigestMismatch { field: &'static str },
    /// Exact canonical bytes for an original source preimage could not be formed.
    #[error("original source preimage is not canonical at {field}")]
    Canonicalization { field: &'static str },
    /// The original evidence role has no payload.
    #[error("original evidence read payload is absent")]
    MissingEvidencePayload,
    /// The original evidence response is incomplete or bound to another read.
    #[error("original evidence response mismatch at {field}")]
    EvidencePayloadMismatch { field: &'static str },
    /// The exact source row was absent from the retained response.
    #[error("original evidence read row is absent")]
    MissingEvidenceRow,
    /// The retained row is not the exact captured observation request.
    #[error("original evidence row mismatch at {field}")]
    EvidenceRowMismatch { field: &'static str },
    /// The exact selected evidence subject is not a native observation record.
    #[error("exact evidence subject is not an ObservationRecord")]
    InvalidObservationPayload,
    /// The original decoded source observation fails its owner's validation.
    #[error("original source observation is invalid")]
    InvalidObservation,
    /// The source observation does not close the original candidate proof.
    #[error("source observation binding mismatch at {field}")]
    ObservationBindingMismatch { field: &'static str },
}

/// Original values retained together after Governor validates the native
/// position read and exact source-evidence read from one context acquisition.
///
/// The request, readback, role rows, omissions, identities, dependency heads,
/// and fence remain borrowed from the source acquisition. The decoded
/// observation is derived only from the exact returned evidence subject.
/// This type cannot be deserialized or constructed outside this crate.
#[derive(Clone, Debug)]
pub struct EpistemicOrientationRead<'a> {
    request: &'a ContextReconstructionRequest,
    role_inputs: &'a SevenRoleInputs,
    readback: &'a EpistemicPositionReadback,
    observation: ObservationRecord,
}

impl<'a> EpistemicOrientationRead<'a> {
    pub(crate) fn from_context_readback(
        request: &'a ContextReconstructionRequest,
        role_inputs: &'a SevenRoleInputs,
    ) -> Result<Self, EpistemicOrientationReadError> {
        request
            .validate()
            .map_err(|_| EpistemicOrientationReadError::InvalidRequest)?;
        if request.scope_id != role_inputs.scope_id {
            return Err(EpistemicOrientationReadError::ReadClosureMismatch { field: "scope_id" });
        }
        if role_inputs.heads_before != role_inputs.heads_after {
            return Err(EpistemicOrientationReadError::ReadClosureMismatch {
                field: "before/after dependency heads",
            });
        }
        if role_inputs.heads_before.scope_id != role_inputs.scope_id {
            return Err(EpistemicOrientationReadError::ReadClosureMismatch {
                field: "dependency-head scope",
            });
        }
        if role_inputs.heads_before.state_fence != role_inputs.state_fence {
            return Err(EpistemicOrientationReadError::ReadClosureMismatch {
                field: "dependency-head state fence",
            });
        }

        validated_role_identity(
            &role_inputs.epistemic,
            NamedReadOperation::GetCurrentEpistemicPosition,
            request,
            role_inputs,
        )?;
        let evidence = &role_inputs.evidence;
        validated_role_identity(
            evidence,
            NamedReadOperation::GetEvidencePack,
            request,
            role_inputs,
        )?;

        let readback = role_inputs
            .epistemic_readback
            .as_ref()
            .ok_or(EpistemicOrientationReadError::MissingPositionReadback)?;
        let position_payload = role_inputs
            .epistemic
            .payload
            .as_ref()
            .ok_or(EpistemicOrientationReadError::MissingPositionPayload)?;
        let decoded_readback: EpistemicPositionReadback =
            serde_json::from_value(position_payload.clone())
                .map_err(|_| EpistemicOrientationReadError::InvalidPositionPayload)?;
        if decoded_readback != *readback {
            return Err(EpistemicOrientationReadError::PositionReadbackMismatch {
                field: "retained decoded payload",
            });
        }
        if readback.schema != eliot_store_api::epistemic_revision::EPISTEMIC_REVISION_SCHEMA {
            return Err(EpistemicOrientationReadError::PositionReadbackMismatch {
                field: "schema",
            });
        }
        if readback.receipt.status != WriteReceiptStatus::Committed {
            return Err(EpistemicOrientationReadError::PositionReadbackMismatch {
                field: "committed receipt status",
            });
        }
        if readback.receipt.operation_id != readback.candidate.operation_id {
            return Err(EpistemicOrientationReadError::PositionReadbackMismatch {
                field: "receipt operation id",
            });
        }
        if readback.receipt.idempotency_key != readback.candidate.idempotency_key {
            return Err(EpistemicOrientationReadError::PositionReadbackMismatch {
                field: "receipt idempotency key",
            });
        }
        if readback.receipt.state_fence != readback.candidate.fence {
            return Err(EpistemicOrientationReadError::PositionReadbackMismatch {
                field: "receipt state fence",
            });
        }
        if readback.candidate.validate().is_err() {
            return Err(EpistemicOrientationReadError::PositionReadbackMismatch {
                field: "original candidate contract",
            });
        }
        if readback.transition.validate().is_err() {
            return Err(EpistemicOrientationReadError::PositionReadbackMismatch {
                field: "original transition contract",
            });
        }
        if readback.positions.len() != 1 {
            return Err(EpistemicOrientationReadError::PositionReadbackMismatch {
                field: "current position cardinality",
            });
        }
        if readback.candidate.claims.len() != 1 {
            return Err(EpistemicOrientationReadError::PositionReadbackMismatch {
                field: "candidate claim cardinality",
            });
        }
        let position = readback
            .positions
            .first()
            .ok_or(EpistemicOrientationReadError::MissingCurrentPosition)?;
        position
            .validate()
            .map_err(|_| EpistemicOrientationReadError::InvalidCurrentPosition)?;
        let receipt_envelope =
            readback
                .receipt
                .require_reconciliation_envelope()
                .map_err(
                    |_| EpistemicOrientationReadError::PositionReadbackMismatch {
                        field: "receipt reconciliation envelope",
                    },
                )?;
        for (mismatch, field) in [
            (
                position.currentness != Currentness::Current,
                "position currentness",
            ),
            (!position.supersession.is_empty(), "position supersession"),
            (
                position.claim != readback.candidate.claims[0].claim,
                "admitted claim",
            ),
            (
                position.admission.position.as_str() != request.epistemic_position.as_str(),
                "position selector",
            ),
            (
                position.admission.payload_digest != readback.candidate.digest,
                "original payload digest",
            ),
            (
                position.admission.scope != readback.candidate.scope,
                "admitted scope",
            ),
            (
                position.admission.fence != readback.candidate.fence,
                "admitted state fence",
            ),
            (
                position.admission.coverage_digest != readback.candidate.coverage_digest,
                "coverage digest",
            ),
            (
                position.admission.proof_digest != readback.candidate.proof_digest,
                "proof digest",
            ),
            (
                position.admission.receipt_id != receipt_envelope.identity.receipt_id,
                "original receipt id",
            ),
            (
                readback.candidate.scope.as_str() != role_inputs.scope_id.as_str(),
                "candidate scope",
            ),
            (
                readback.candidate.fence != role_inputs.state_fence,
                "candidate state fence",
            ),
        ] {
            if mismatch {
                return Err(EpistemicOrientationReadError::PositionAdmissionMismatch { field });
            }
        }

        let support_digest = digest(&readback.candidate.support, "support")?;
        let conflict_digest = digest(&readback.candidate.conflict_digests, "conflict digests")?;
        if position.admission.evidence_digest != support_digest
            || position.admission.conflict_digest != conflict_digest
        {
            return Err(EpistemicOrientationReadError::CandidateDigestMismatch {
                field: "support or conflict preimage",
            });
        }

        let payload = evidence
            .payload
            .as_ref()
            .ok_or(EpistemicOrientationReadError::MissingEvidencePayload)?;
        let rows = payload.get("records").and_then(Value::as_array).ok_or(
            EpistemicOrientationReadError::EvidencePayloadMismatch {
                field: "records array",
            },
        )?;
        if payload.get("version").and_then(Value::as_u64) != Some(1)
            || payload.get("subject").and_then(Value::as_str)
                != Some(request.evidence_subject.as_str())
            || payload.get("scope_id").and_then(Value::as_str) != Some(request.scope_id.as_str())
            || payload["provenance"]["state_fence"] != json!(role_inputs.state_fence)
            || payload["provenance"]["truncated"] != false
            || payload["provenance"]["returned"].as_u64() != Some(1)
            || payload["provenance"]["matched_total"].as_u64() != Some(1)
            || rows.len() != 1
        {
            return Err(EpistemicOrientationReadError::EvidencePayloadMismatch {
                field: "version, subject, scope, provenance, or exact row count",
            });
        }
        let row = rows
            .first()
            .ok_or(EpistemicOrientationReadError::MissingEvidenceRow)?;
        let expected_parameters = json!({"subject": request.evidence_subject});
        if row.get("operation").and_then(Value::as_str) != Some("CaptureObservation") {
            return Err(EpistemicOrientationReadError::EvidenceRowMismatch { field: "operation" });
        }
        if row.get("parameters") != Some(&expected_parameters) {
            return Err(EpistemicOrientationReadError::EvidenceRowMismatch {
                field: "exact source selector",
            });
        }
        let observation: ObservationRecord = serde_json::from_str(&request.evidence_subject)
            .map_err(|_| EpistemicOrientationReadError::InvalidObservationPayload)?;
        observation
            .validate()
            .map_err(|_| EpistemicOrientationReadError::InvalidObservation)?;
        let candidate = &readback.candidate;
        if candidate.proof_digest != digest(&observation, "observation")? {
            return Err(EpistemicOrientationReadError::ObservationBindingMismatch {
                field: "original observation proof digest",
            });
        }
        if candidate.support.len() != 1 || candidate.support[0].handles.len() != 1 {
            return Err(EpistemicOrientationReadError::ObservationBindingMismatch {
                field: "single original support handle",
            });
        }
        if !candidate.support[0]
            .handles
            .contains(&observation.observation_id)
        {
            return Err(EpistemicOrientationReadError::ObservationBindingMismatch {
                field: "source observation handle",
            });
        }
        if candidate.support[0].proof_digest != candidate.proof_digest {
            return Err(EpistemicOrientationReadError::ObservationBindingMismatch {
                field: "support proof digest",
            });
        }
        if observation.evidence.provenance.scope.as_str() != role_inputs.scope_id.as_str() {
            return Err(EpistemicOrientationReadError::ObservationBindingMismatch {
                field: "source observation scope",
            });
        }
        if observation.evidence.state_fence != role_inputs.state_fence {
            return Err(EpistemicOrientationReadError::ObservationBindingMismatch {
                field: "source observation state fence",
            });
        }

        Ok(Self {
            request,
            role_inputs,
            readback,
            observation,
        })
    }

    /// The exact candidate present in the original native position readback.
    pub fn candidate(&self) -> &EpistemicPositionCandidate {
        &self.readback.candidate
    }

    /// The sole Current view issued from that candidate by storage readback.
    pub fn current_position(&self) -> Option<&CurrentEpistemicPosition> {
        self.readback.positions.first()
    }

    /// The original external committed write receipt retained by storage.
    pub fn committed_receipt(&self) -> &WriteReceipt {
        &self.readback.receipt
    }

    /// The exact source observation decoded from the retained evidence read.
    pub fn observation(&self) -> &ObservationRecord {
        &self.observation
    }

    /// The original storage readback, including its committed receipt.
    pub fn readback(&self) -> &EpistemicPositionReadback {
        self.readback
    }

    /// The exact original selector request used for the context acquisition.
    pub fn context_request(&self) -> &ContextReconstructionRequest {
        self.request
    }

    /// All original role rows, omissions, read identities, dependency heads,
    /// and the state fence from the same Governor read closure.
    pub fn role_inputs(&self) -> &SevenRoleInputs {
        self.role_inputs
    }

    /// The original evidence-read identity, including dependencies and fence.
    pub fn evidence_read_identity(&self) -> Option<&ReadIdentity> {
        self.role_inputs.evidence.identity.as_ref()
    }
}

fn validated_role_identity<'a>(
    role: &'a RoleAcquisition,
    operation: NamedReadOperation,
    request: &ContextReconstructionRequest,
    role_inputs: &SevenRoleInputs,
) -> Result<&'a ReadIdentity, EpistemicOrientationReadError> {
    let role_name = match operation {
        NamedReadOperation::GetCurrentEpistemicPosition => "epistemic position",
        NamedReadOperation::GetEvidencePack => "evidence",
        _ => "orientation source",
    };
    if !matches!(&role.state, ProjectionState::Complete) {
        return Err(EpistemicOrientationReadError::RoleNotComplete {
            role: role_name,
            state: role.state.clone(),
        });
    }
    if role.operation != operation {
        return Err(EpistemicOrientationReadError::ReadIdentityMismatch {
            role: role_name,
            field: "named operation",
        });
    }
    let identity = role
        .identity
        .as_ref()
        .ok_or(EpistemicOrientationReadError::MissingReadIdentity { role: role_name })?;
    for (mismatch, field) in [
        (identity.operation() != operation, "operation"),
        (identity.scope_id() != Some(&request.scope_id), "scope"),
        (
            identity.state_fence() != &role_inputs.state_fence,
            "state fence",
        ),
        (
            identity.consistency() != ReadConsistency::ExactFence,
            "read consistency",
        ),
        (
            identity.declared_dependency_revisions() != &request.dependency_revisions,
            "declared dependency revisions",
        ),
        (
            identity.observed_revision_heads() != role.revision_heads.as_slice(),
            "observed revision heads",
        ),
        (
            identity.ordering().heads() != role_inputs.heads_before.ordering_heads.as_slice(),
            "ordering heads",
        ),
        (
            !dependencies_match(identity, request, role_inputs),
            "dependency read closure",
        ),
    ] {
        if mismatch {
            return Err(EpistemicOrientationReadError::ReadIdentityMismatch {
                role: role_name,
                field,
            });
        }
    }
    if operation == NamedReadOperation::GetEvidencePack
        && !matches!(
            identity.coverage(),
            ReadCoverage::BoundedByDeclaredSelector {
                selector: DeclaredResultSelector::MaxRecords,
                declared_bound,
            } if declared_bound == request.evidence_max_records
        )
    {
        return Err(EpistemicOrientationReadError::EvidenceBoundMismatch);
    }
    Ok(identity)
}

fn dependencies_match(
    identity: &ReadIdentity,
    request: &ContextReconstructionRequest,
    role_inputs: &SevenRoleInputs,
) -> bool {
    if request.dependency_revisions.is_empty()
        || identity.observed_revision_heads().len() != request.dependency_revisions.len()
    {
        return false;
    }
    request.dependency_revisions.iter().all(|(key, revision)| {
        identity.observed_revision_heads().iter().any(|head| {
            &head.key == key
                && head.revision == *revision
                && head.state_fence == role_inputs.state_fence
        }) && role_inputs.heads_before.revision_heads.iter().any(|head| {
            &head.key == key
                && head.revision == *revision
                && head.state_fence == role_inputs.state_fence
        })
    })
}

fn digest<T: serde::Serialize>(
    value: &T,
    field: &'static str,
) -> Result<String, EpistemicOrientationReadError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|_| EpistemicOrientationReadError::Canonicalization { field })?;
    Ok(sha256_hex(&bytes))
}
