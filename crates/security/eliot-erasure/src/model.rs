use std::collections::BTreeSet;

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_evidence::EvidenceEnvelope;
use eliot_security_contracts::{PurgeLedgerEntry, PurgeLocation, PurgeState};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A request contains references and policy evidence, never the private value
/// being erased.  `approval_digest` binds the operator approval to this exact
/// request and is deliberately not reversible into the erased content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErasureRequest {
    pub request_id: String,
    pub subject_ref: String,
    pub scope: String,
    pub locations: Vec<PurgeLocation>,
    pub expected_revision: u64,
    pub approval_digest: String,
    pub evidence: Vec<EvidenceEnvelope>,
    pub state_fence: StateFence,
}

impl ErasureRequest {
    pub fn validate(&self) -> Result<(), ErasureError> {
        text(&self.request_id, "request_id")?;
        text(&self.subject_ref, "subject_ref")?;
        text(&self.scope, "scope")?;
        self.state_fence
            .validate()
            .map_err(|_| ErasureError::InvalidField("state_fence"))?;
        if self.locations.is_empty() {
            return Err(ErasureError::EmptyLocations);
        }
        let mut locations = BTreeSet::new();
        for location in &self.locations {
            if !locations.insert(location_code(*location)) {
                return Err(ErasureError::DuplicateLocation);
            }
        }
        digest(&self.approval_digest, "approval_digest")?;
        for evidence in &self.evidence {
            evidence
                .validate()
                .map_err(|_| ErasureError::InvalidEvidence)?;
            if evidence.state_fence != self.state_fence {
                return Err(ErasureError::FenceMismatch);
            }
        }
        Ok(())
    }

    pub fn request_digest(&self) -> Result<String, ErasureError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self).map_err(|_| ErasureError::Canonicalization)?;
        Ok(sha256_hex(&bytes))
    }
}

/// The backend is the existing storage/evidence owner.  Implementations must
/// make `erase` and `append_purge_ledger` durable in their own transaction
/// boundary; this orchestration layer never caches or duplicates that state.
pub trait ErasureBackend {
    type Error: std::error::Error + Send + Sync + 'static;

    fn current_revision(&self, subject_ref: &str, scope: &str) -> Result<u64, Self::Error>;

    /// Removes every requested location and returns the locations actually
    /// removed.  A successful result is required to be exact, not a subset.
    fn erase(
        &mut self,
        subject_ref: &str,
        scope: &str,
        locations: &[PurgeLocation],
    ) -> Result<Vec<PurgeLocation>, Self::Error>;

    fn append_purge_ledger(&mut self, entry: PurgeLedgerEntry) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErasureReceipt {
    pub request_id: String,
    pub request_digest: String,
    pub purge: PurgeLedgerEntry,
}

/// Executes one exact-fence erasure against the already-authoritative backend.
pub fn execute<B: ErasureBackend>(
    backend: &mut B,
    request: &ErasureRequest,
) -> Result<ErasureReceipt, ErasureError> {
    request.validate()?;
    let request_digest = request.request_digest()?;
    let revision = backend
        .current_revision(&request.subject_ref, &request.scope)
        .map_err(|error| ErasureError::Backend(Box::new(error)))?;
    if revision != request.expected_revision {
        return Err(ErasureError::RevisionMismatch {
            expected: request.expected_revision,
            observed: revision,
        });
    }

    let erased = backend
        .erase(&request.subject_ref, &request.scope, &request.locations)
        .map_err(|error| ErasureError::Backend(Box::new(error)))?;
    ensure_exact_locations(&request.locations, &erased)?;
    let tombstone_digest = tombstone_digest(request, &request_digest);
    let purge = PurgeLedgerEntry {
        purge_id: format!("purge-{}", request_digest),
        subject_ref: request.subject_ref.clone(),
        scope: request.scope.clone(),
        purged_locations: erased,
        tombstone_digest,
        state: PurgeState::Purged,
        state_fence: request.state_fence.clone(),
        revision,
    };
    purge.validate().map_err(|_| ErasureError::InvalidLedger)?;
    backend
        .append_purge_ledger(purge.clone())
        .map_err(|error| ErasureError::Backend(Box::new(error)))?;
    Ok(ErasureReceipt {
        request_id: request.request_id.clone(),
        request_digest,
        purge,
    })
}

fn ensure_exact_locations(
    requested: &[PurgeLocation],
    erased: &[PurgeLocation],
) -> Result<(), ErasureError> {
    let requested: BTreeSet<_> = requested.iter().copied().map(location_code).collect();
    let erased: BTreeSet<_> = erased.iter().copied().map(location_code).collect();
    if requested != erased {
        return Err(ErasureError::IncompleteErasure);
    }
    Ok(())
}

fn tombstone_digest(request: &ErasureRequest, request_digest: &str) -> String {
    let material = format!(
        "{}\0{}\0{}\0{}\0{}",
        request_digest,
        request.subject_ref,
        request.scope,
        request.expected_revision,
        request
            .locations
            .iter()
            .map(|location| location_code(*location).to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    sha256_hex(material.as_bytes())
}

fn location_code(location: PurgeLocation) -> u8 {
    match location {
        PurgeLocation::CanonicalPayload => 0,
        PurgeLocation::Projection => 1,
        PurgeLocation::Index => 2,
        PurgeLocation::Blob => 3,
        PurgeLocation::OperationalRecovery => 4,
        PurgeLocation::ProviderCopy => 5,
        PurgeLocation::BackupRestorePath => 6,
        PurgeLocation::RouteContinuation => 7,
    }
}

fn text(value: &str, field: &'static str) -> Result<(), ErasureError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(ErasureError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn digest(value: &str, field: &'static str) -> Result<(), ErasureError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(ErasureError::InvalidField(field))
    }
}

#[derive(Debug, Error)]
pub enum ErasureError {
    #[error("invalid erasure field: {0}")]
    InvalidField(&'static str),
    #[error("erasure request has no locations")]
    EmptyLocations,
    #[error("erasure request contains a duplicate location")]
    DuplicateLocation,
    #[error("erasure evidence is invalid")]
    InvalidEvidence,
    #[error("erasure evidence and request use different state fences")]
    FenceMismatch,
    #[error("erasure request cannot be canonically serialized")]
    Canonicalization,
    #[error("erasure revision mismatch: expected {expected}, observed {observed}")]
    RevisionMismatch { expected: u64, observed: u64 },
    #[error("backend did not erase the exact requested locations")]
    IncompleteErasure,
    #[error("generated purge ledger entry is invalid")]
    InvalidLedger,
    #[error("erasure backend failed: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}
