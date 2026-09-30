//! Governor-owned, source-validated epistemic inputs for Orientation.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_epistemic_contracts::{
    CurrentEpistemicPosition, Currentness, EpistemicPositionCandidate,
};
use eliot_evidence::ObservationRecord;
use eliot_store_api::{
    WriteReceipt, WriteReceiptStatus, epistemic_revision::EpistemicPositionReadback,
};

/// Original values retained together after Governor validates an observed
/// proposal against its committed store readback.
///
/// This type intentionally has no serde implementation or public constructor:
/// consumers can borrow the candidate, admitted view, original committed
/// receipt and source observation only from the Governor acquisition path.
#[derive(Clone, Debug)]
pub struct EpistemicOrientationRead {
    readback: EpistemicPositionReadback,
    observation: ObservationRecord,
}

impl EpistemicOrientationRead {
    pub(crate) fn from_validated_source(
        readback: EpistemicPositionReadback,
        observation: ObservationRecord,
    ) -> Result<Self, &'static str> {
        if readback.receipt.status != WriteReceiptStatus::Committed
            || readback.candidate.validate().is_err()
            || observation.validate().is_err()
        {
            return Err("source readback is not a validated committed observation");
        }
        if readback.positions.len() != 1 || readback.candidate.claims.len() != 1 {
            return Err("observed orientation requires one original claim and view");
        }
        let Some(position) = readback.positions.first() else {
            return Err("committed source readback has no current position");
        };
        if position.validate().is_err()
            || position.currentness != Currentness::Current
            || !position.supersession.is_empty()
            || position.claim != readback.candidate.claims[0].claim
            || position.admission.payload_digest != readback.candidate.digest
            || position.admission.scope != readback.candidate.scope
            || position.admission.fence != readback.candidate.fence
            || position.admission.coverage_digest != readback.candidate.coverage_digest
            || position.admission.proof_digest != readback.candidate.proof_digest
        {
            return Err("admitted view differs from its original candidate");
        }
        let evidence_bytes = canonical_json_bytes(&readback.candidate.support)
            .map_err(|_| "candidate support preimage is not canonical")?;
        if position.admission.evidence_digest != sha256_hex(&evidence_bytes) {
            return Err("admitted evidence digest differs from original support");
        }
        let conflict_bytes = canonical_json_bytes(&readback.candidate.conflict_digests)
            .map_err(|_| "candidate conflict preimage is not canonical")?;
        if position.admission.conflict_digest != sha256_hex(&conflict_bytes) {
            return Err("admitted conflict digest differs from original conflicts");
        }
        let observation_bytes = canonical_json_bytes(&observation)
            .map_err(|_| "original observation preimage is not canonical")?;
        if readback.candidate.proof_digest != sha256_hex(&observation_bytes) {
            return Err("candidate proof digest differs from original observation");
        }
        Ok(Self {
            readback,
            observation,
        })
    }

    /// The original candidate exactly present in the validated store readback.
    pub fn candidate(&self) -> &EpistemicPositionCandidate {
        &self.readback.candidate
    }

    /// The sole Current view issued from that candidate by storage readback.
    pub fn current_position(&self) -> Option<&CurrentEpistemicPosition> {
        self.readback.positions.first()
    }

    /// The original external committed write receipt retained by storage readback.
    pub fn committed_receipt(&self) -> &WriteReceipt {
        &self.readback.receipt
    }

    /// The exact source observation re-acquired and validated by Governor.
    pub fn observation(&self) -> &ObservationRecord {
        &self.observation
    }

    /// The full original storage readback, including candidate, transition,
    /// admitted views and external receipt.
    pub fn readback(&self) -> &EpistemicPositionReadback {
        &self.readback
    }
}
