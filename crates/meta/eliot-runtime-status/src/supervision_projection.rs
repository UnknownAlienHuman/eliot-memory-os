//! Supervision evidence projection — pure read-only evidence.
//!
//! Architecture: contract -> pure core -> ports; A13.10 reports/evidence are non-authority.
//! Implementation: bounded `FunctionalCapabilityCell`; I16.1 projections-not-truth.
//! Explicitly read-only with no lifecycle, SCM, write, or semantic authority.

use eliot_contracts::sha256_hex;
use eliot_runtime_contracts::{LeaseState, SupervisionLeaseIncarnationBinding};
use serde::{Deserialize, Serialize};

/// Provider-neutral, read-only projection of one fully verified current
/// supervision incarnation. This value is evidence only and grants no
/// mutation or lease authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentSupervisionEvidence {
    pub incarnation: SupervisionLeaseIncarnationBinding,
    pub incarnation_sha256: String,
    pub ors_state: LeaseState,
    pub ors_projection: eliot_ors::SupervisionLeaseProjection,
    pub ors_record_id: String,
    pub ors_revision: u64,
    pub ors_receipt_sha256: String,
    pub lease_payload_sha256: String,
    pub lease_envelope_sha256: String,
    pub trust_anchor_fingerprint: String,
    pub verification_context_sha256: String,
    pub watchdog_publication_sha256: String,
}

impl CurrentSupervisionEvidence {
    /// Revalidates the public evidence shape without treating it as authority.
    pub fn validate(&self) -> Result<(), String> {
        self.incarnation
            .validate()
            .map_err(|error| format!("supervision incarnation is invalid: {error}"))?;
        if self.ors_state != LeaseState::Active
            || self.ors_projection != eliot_ors::SupervisionLeaseProjection::Active
            || self.ors_record_id.trim().is_empty()
            || self.ors_revision == 0
        {
            return Err("supervision evidence is not an exact Active ORS head".to_owned());
        }
        for (name, value) in [
            ("incarnation_sha256", &self.incarnation_sha256),
            ("ors_receipt_sha256", &self.ors_receipt_sha256),
            ("lease_payload_sha256", &self.lease_payload_sha256),
            ("lease_envelope_sha256", &self.lease_envelope_sha256),
            ("trust_anchor_fingerprint", &self.trust_anchor_fingerprint),
            (
                "verification_context_sha256",
                &self.verification_context_sha256,
            ),
            (
                "watchdog_publication_sha256",
                &self.watchdog_publication_sha256,
            ),
        ] {
            if !super::is_sha256_hex(value) {
                return Err(format!("{name} is not a lowercase SHA-256 digest"));
            }
        }
        let incarnation_bytes = serde_json::to_vec(&self.incarnation)
            .map_err(|error| format!("supervision incarnation encoding failed: {error}"))?;
        if sha256_hex(&incarnation_bytes) != self.incarnation_sha256 {
            return Err("incarnation digest does not bind the exact typed value".to_owned());
        }
        Ok(())
    }
}
