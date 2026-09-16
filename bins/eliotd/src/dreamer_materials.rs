//! Read-only Dreamer orientation material helper (T12-06, integration #702, semantic #18).
//!
//! Architecture: A2.3 (contract → ports → adapters layering); A0.3 hard boundaries stay
//! fail-closed. Implementation: T12-06 source/result handoff join.
//!
//! This module owns no admission, ledger, provider, or blob authority. It resolves already-named
//! source bytes through the Governor named-read boundary (`ReadService` over the daemon's
//! [`KernelContextReadClient`](super::KernelContextReadClient)), checks the S-04 receipt shape
//! (exact byte length plus SHA-256 digest) over the resolved bytes, freezes one canonical
//! orientation manifest, and enforces the independent fence/budget/privacy/route gates. A private
//! or unadmitted source, a stale fence, or a digest/length mismatch fails closed before any queue
//! admission or model work.
//!
//! `ReadApi::state`/`resource` expansion is deliberately not duplicated here: every `ReadService`
//! facade funnels through the same `execute_named` boundary, and the daemon read client admits
//! only the live evidence-pack query today. Source resolution therefore uses the
//! [`LocalReadPort::evidence_query`](eliot_read::LocalReadPort::evidence_query) path; additional
//! named operations stay with their catalogue owners (MGR04, #19).

use eliot_contracts::{RequestMetadata, StateFence, canonical_json_bytes, sha256_hex};
use eliot_read::{LocalReadPort, ReadError};
use eliot_store_api::ScopeId;
use serde::Serialize;
use thiserror::Error;

/// Closed privacy membership for first-profile Orientation materials.
///
/// Only governed-internal sources are admitted; anything else (including a private source) fails
/// closed. Remote acquisition stays deferred per the T12-06 slice.
pub const ORIENTATION_MATERIAL_PRIVACY_ADMITTED: &[&str] = &["governed-internal"];
/// Closed route membership for first-profile Orientation materials.
///
/// Only the local governed route is admitted; the remote gateway stays deferred per the T12-06
/// slice.
pub const ORIENTATION_MATERIAL_ROUTE_ADMITTED: &[&str] = &["local-governed"];
/// First-profile cap on admitted source claims per Orientation intake.
pub const ORIENTATION_MATERIAL_MAX_SOURCES: u32 = 8;
/// First-profile cap on resolved bytes per admitted source claim.
pub const ORIENTATION_MATERIAL_MAX_SOURCE_BYTES: u64 = 64 * 1024;
/// First-profile cap on resolved bytes across all admitted source claims.
pub const ORIENTATION_MATERIAL_MAX_TOTAL_BYTES: u64 = 256 * 1024;
/// Bounded evidence-pack expansion per source claim resolution.
pub const ORIENTATION_EVIDENCE_MAX_RECORDS: u32 = 16;

/// Failures of the read-only material gates. Messages name the failed gate only and never echo
/// supplied handles, digests, or bytes.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DreamerMaterialsError {
    /// No source claim was supplied; an empty source list proves nothing.
    #[error("orientation intake requires at least one admitted source claim")]
    EmptySources,
    /// Two claims name the same source handle.
    #[error("orientation source claims contain a duplicate handle")]
    DuplicateSource,
    /// The scope binding is blank or malformed.
    #[error("orientation scope binding is invalid")]
    Scope,
    /// A source handle is blank or malformed.
    #[error("orientation source handle is invalid")]
    SourceHandle,
    /// An expected digest is not a 64-character lowercase hex SHA-256.
    #[error("orientation source digest is not a lowercase SHA-256 hex value")]
    DigestShape,
    /// Resolved bytes do not match the admitted digest.
    #[error("orientation source bytes do not match the admitted digest")]
    DigestMismatch,
    /// Resolved bytes do not match the admitted length.
    #[error("orientation source bytes do not match the admitted length")]
    LengthMismatch,
    /// A privacy class is outside the admitted membership.
    #[error("orientation source privacy class is not admitted")]
    Privacy,
    /// A route class is outside the admitted membership.
    #[error("orientation source route class is not admitted")]
    Route,
    /// A budget bound is zero, inverted, or above the first-profile caps.
    #[error("orientation material budget is invalid")]
    Budget,
    /// The claims do not fit the supplied budget.
    #[error("orientation source claims exceed the material budget")]
    BudgetExceeded,
    /// The expected length is zero or above the per-source cap.
    #[error("orientation source length is out of bounds")]
    LengthBounds,
    /// The fence does not equal the admitted fence.
    #[error("orientation material fence does not match the admitted fence")]
    FenceMismatch,
    /// Byte accounting overflowed.
    #[error("orientation material byte accounting overflowed")]
    Overflow,
    /// Canonical manifest encoding failed.
    #[error("orientation manifest encoding failed")]
    ManifestEncoding,
    /// A named read failed or its response did not bind the admitted fence.
    #[error("orientation source resolution failed")]
    Resolution(#[from] ReadError),
}

/// One admitted source claim for an Orientation intake.
///
/// The claim is caller-supplied shape, not proof of admission: the adapter resolves the named
/// source through the Governor read boundary and compares the resolved bytes against
/// `expected_digest`/`expected_byte_length` before any queue admission. `AdmittedOrientationJob`
/// (unadmitted `eliot-dreamer-orientation` leaf, GAP-1) is not referenced; this shape uses only
/// admitted leaves and types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedSourceClaim {
    /// Exact evidence subject resolved through the named-read boundary.
    pub source_handle: String,
    /// Admitted SHA-256 (64 lowercase hex) over the canonical resolved bytes.
    pub expected_digest: String,
    /// Admitted exact byte length of the canonical resolved bytes.
    pub expected_byte_length: u64,
    /// Closed privacy membership; see [`ORIENTATION_MATERIAL_PRIVACY_ADMITTED`].
    pub privacy_class: String,
    /// Closed route membership; see [`ORIENTATION_MATERIAL_ROUTE_ADMITTED`].
    pub route_class: String,
}

impl AdmittedSourceClaim {
    /// Validates claim shape without resolving any bytes.
    pub fn validate(&self) -> Result<(), DreamerMaterialsError> {
        validate_handle(&self.source_handle)?;
        if !is_lower_sha256(&self.expected_digest) {
            return Err(DreamerMaterialsError::DigestShape);
        }
        if self.expected_byte_length == 0
            || self.expected_byte_length > ORIENTATION_MATERIAL_MAX_SOURCE_BYTES
        {
            return Err(DreamerMaterialsError::LengthBounds);
        }
        if !ORIENTATION_MATERIAL_PRIVACY_ADMITTED.contains(&self.privacy_class.as_str()) {
            return Err(DreamerMaterialsError::Privacy);
        }
        if !ORIENTATION_MATERIAL_ROUTE_ADMITTED.contains(&self.route_class.as_str()) {
            return Err(DreamerMaterialsError::Route);
        }
        Ok(())
    }
}

/// Independent byte/source bounds for one Orientation intake.
///
/// Enforced by this join in addition to any caller-supplied admission budget; the two are never
/// conflated (admission budget units carry owner semantics this module does not interpret).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrientationMaterialBudget {
    /// Maximum admitted source claims.
    pub max_sources: u32,
    /// Maximum resolved bytes across all claims.
    pub max_total_bytes: u64,
    /// Maximum resolved bytes per claim.
    pub max_source_bytes: u64,
}

impl OrientationMaterialBudget {
    /// Validates budget shape against the first-profile caps.
    pub fn validate(&self) -> Result<(), DreamerMaterialsError> {
        if self.max_sources == 0
            || self.max_sources > ORIENTATION_MATERIAL_MAX_SOURCES
            || self.max_total_bytes == 0
            || self.max_total_bytes > ORIENTATION_MATERIAL_MAX_TOTAL_BYTES
            || self.max_source_bytes == 0
            || self.max_source_bytes > ORIENTATION_MATERIAL_MAX_SOURCE_BYTES
            || self.max_source_bytes > self.max_total_bytes
        {
            return Err(DreamerMaterialsError::Budget);
        }
        Ok(())
    }

    /// Checks that every claim fits the budget without resolving bytes.
    pub fn fits(&self, claims: &[AdmittedSourceClaim]) -> Result<(), DreamerMaterialsError> {
        let count =
            u64::from(u32::try_from(claims.len()).map_err(|_| DreamerMaterialsError::Budget)?);
        if count > u64::from(self.max_sources) {
            return Err(DreamerMaterialsError::BudgetExceeded);
        }
        let mut total = 0_u64;
        for claim in claims {
            if claim.expected_byte_length > self.max_source_bytes {
                return Err(DreamerMaterialsError::BudgetExceeded);
            }
            total = total
                .checked_add(claim.expected_byte_length)
                .ok_or(DreamerMaterialsError::Overflow)?;
            if total > self.max_total_bytes {
                return Err(DreamerMaterialsError::BudgetExceeded);
            }
        }
        Ok(())
    }
}

/// One frozen canonical manifest over admitted Orientation materials.
///
/// Handles are sorted and the digest covers scope, admitted fence, handles, digests, and total
/// bytes, so any substitution changes the digest. The manifest records what was admitted; only a
/// resolved-byte comparison (see [`verify_resolved_bytes`]) proves the bytes match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenOrientationManifest {
    /// Scope the manifest was frozen for.
    pub scope_id: String,
    /// Admitted fence the manifest was frozen against.
    pub state_fence: StateFence,
    /// Sorted admitted source handles.
    pub source_handles: Vec<String>,
    /// Digests aligned with `source_handles`.
    pub source_digests: Vec<String>,
    /// Sum of admitted byte lengths.
    pub total_bytes: u64,
    /// Canonical digest over scope, fence, handles, digests, and total bytes.
    pub manifest_digest: String,
}

impl FrozenOrientationManifest {
    /// Validates frozen shape, including the digest binding.
    pub fn validate(&self) -> Result<(), DreamerMaterialsError> {
        validate_scope(&self.scope_id)?;
        if self.source_handles.is_empty() {
            return Err(DreamerMaterialsError::EmptySources);
        }
        if self.source_handles.len() != self.source_digests.len() {
            return Err(DreamerMaterialsError::ManifestEncoding);
        }
        let mut sorted = self.source_handles.clone();
        sorted.sort();
        if sorted != self.source_handles {
            return Err(DreamerMaterialsError::ManifestEncoding);
        }
        if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(DreamerMaterialsError::DuplicateSource);
        }
        for digest in &self.source_digests {
            if !is_lower_sha256(digest) {
                return Err(DreamerMaterialsError::DigestShape);
            }
        }
        let expected = manifest_digest(
            &self.scope_id,
            &self.state_fence,
            &self.source_handles,
            &self.source_digests,
            self.total_bytes,
        )?;
        if expected != self.manifest_digest {
            return Err(DreamerMaterialsError::DigestMismatch);
        }
        Ok(())
    }
}

/// Freezes one canonical manifest after validating every gate.
///
/// Fails closed on an empty claim set, a malformed claim, a duplicate handle, a budget
/// violation, or an unencodable shape. No bytes are resolved here; resolution and its
/// digest comparison happen per claim in [`resolve_source_claim`].
pub fn freeze_orientation_manifest(
    scope_id: &str,
    admitted_fence: &StateFence,
    claims: &[AdmittedSourceClaim],
    budget: &OrientationMaterialBudget,
) -> Result<FrozenOrientationManifest, DreamerMaterialsError> {
    validate_scope(scope_id)?;
    if claims.is_empty() {
        return Err(DreamerMaterialsError::EmptySources);
    }
    budget.validate()?;
    for claim in claims {
        claim.validate()?;
    }
    budget.fits(claims)?;
    let mut ordered: Vec<&AdmittedSourceClaim> = claims.iter().collect();
    ordered.sort_by(|left, right| left.source_handle.cmp(&right.source_handle));
    if ordered
        .windows(2)
        .any(|pair| pair[0].source_handle == pair[1].source_handle)
    {
        return Err(DreamerMaterialsError::DuplicateSource);
    }
    let mut total = 0_u64;
    for claim in &ordered {
        total = total
            .checked_add(claim.expected_byte_length)
            .ok_or(DreamerMaterialsError::Overflow)?;
    }
    let source_handles: Vec<String> = ordered
        .iter()
        .map(|claim| claim.source_handle.clone())
        .collect();
    let source_digests: Vec<String> = ordered
        .iter()
        .map(|claim| claim.expected_digest.clone())
        .collect();
    let manifest_digest = manifest_digest(
        scope_id,
        admitted_fence,
        &source_handles,
        &source_digests,
        total,
    )?;
    Ok(FrozenOrientationManifest {
        scope_id: scope_id.to_owned(),
        state_fence: admitted_fence.clone(),
        source_handles,
        source_digests,
        total_bytes: total,
        manifest_digest,
    })
}

/// Verifies resolved bytes against one admitted claim (S-04 receipt shape: exact length plus
/// SHA-256 digest over the canonical bytes).
pub fn verify_resolved_bytes(
    claim: &AdmittedSourceClaim,
    bytes: &[u8],
) -> Result<(), DreamerMaterialsError> {
    claim.validate()?;
    let observed = u64::try_from(bytes.len()).map_err(|_| DreamerMaterialsError::Overflow)?;
    if observed != claim.expected_byte_length {
        return Err(DreamerMaterialsError::LengthMismatch);
    }
    if sha256_hex(bytes) != claim.expected_digest {
        return Err(DreamerMaterialsError::DigestMismatch);
    }
    Ok(())
}

/// Resolves one admitted source claim through the Governor named-read boundary and verifies the
/// resolved bytes against the claim.
///
/// The payload digest is computed over the canonical JSON encoding of the resolved evidence
/// payload; admission must bind that same encoding. The response fence must equal the context
/// fence, otherwise resolution fails closed.
pub async fn resolve_source_claim(
    reads: &impl LocalReadPort,
    ctx: &RequestMetadata,
    scope: &ScopeId,
    claim: &AdmittedSourceClaim,
) -> Result<Vec<u8>, DreamerMaterialsError> {
    claim.validate()?;
    let result = reads
        .evidence_query(
            ctx,
            scope.clone(),
            claim.source_handle.clone(),
            ORIENTATION_EVIDENCE_MAX_RECORDS,
        )
        .await?;
    if result.state_fence != ctx.state_fence {
        return Err(DreamerMaterialsError::FenceMismatch);
    }
    let bytes = canonical_json_bytes(&result.payload)
        .map_err(|_| DreamerMaterialsError::ManifestEncoding)?;
    verify_resolved_bytes(claim, &bytes)?;
    Ok(bytes)
}

fn validate_scope(value: &str) -> Result<(), DreamerMaterialsError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(DreamerMaterialsError::Scope);
    }
    Ok(())
}

fn validate_handle(value: &str) -> Result<(), DreamerMaterialsError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(DreamerMaterialsError::SourceHandle);
    }
    Ok(())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Serialize)]
struct ManifestDigestShape<'a> {
    scope_id: &'a str,
    state_fence: &'a StateFence,
    source_handles: &'a [String],
    source_digests: &'a [String],
    total_bytes: u64,
}

fn manifest_digest(
    scope_id: &str,
    fence: &StateFence,
    handles: &[String],
    digests: &[String],
    total_bytes: u64,
) -> Result<String, DreamerMaterialsError> {
    let shape = ManifestDigestShape {
        scope_id,
        state_fence: fence,
        source_handles: handles,
        source_digests: digests,
        total_bytes,
    };
    let bytes =
        canonical_json_bytes(&shape).map_err(|_| DreamerMaterialsError::ManifestEncoding)?;
    Ok(sha256_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    use eliot_contracts::{EpochId, EpochLineageId, RequestId, ResourceGeneration};
    use eliot_read::{
        BranchEnvironmentScope, FreshnessPolicy, ProvenanceDisposition, QueryIntent, QueryMode,
        QueryResult, ReadProvenance, RequiredAssurance, TimeScope,
    };
    use eliot_store_api::{NamedReadOperation, ReadConsistency};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_fence() -> Result<StateFence, Box<dyn std::error::Error>> {
        Ok(StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE)?,
                NonZeroU64::new(1).ok_or("nonzero test sequence")?,
            )?,
            ResourceGeneration::new(1)?,
        ))
    }

    fn test_budget() -> OrientationMaterialBudget {
        OrientationMaterialBudget {
            max_sources: 4,
            max_total_bytes: 8 * 1024,
            max_source_bytes: 4 * 1024,
        }
    }

    fn test_claim(handle: &str, bytes: &[u8]) -> AdmittedSourceClaim {
        AdmittedSourceClaim {
            source_handle: handle.to_owned(),
            expected_digest: sha256_hex(bytes),
            expected_byte_length: u64::try_from(bytes.len()).unwrap_or(0),
            privacy_class: "governed-internal".to_owned(),
            route_class: "local-governed".to_owned(),
        }
    }

    #[test]
    fn freeze_sorts_handles_and_binds_scope_fence_and_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let fence = test_fence()?;
        let first = test_claim("evidence-b", b"second-bytes");
        let second = test_claim("evidence-a", b"first-bytes");
        let manifest =
            freeze_orientation_manifest("scope-one", &fence, &[first, second], &test_budget())?;
        assert_eq!(manifest.source_handles, vec!["evidence-a", "evidence-b"]);
        assert_eq!(manifest.scope_id, "scope-one");
        assert_eq!(manifest.state_fence, fence);
        assert_eq!(
            manifest.total_bytes,
            u64::try_from("first-bytes".len() + "second-bytes".len())?
        );
        manifest.validate()?;
        let reordered = freeze_orientation_manifest(
            "scope-one",
            &fence,
            &[
                test_claim("evidence-a", b"first-bytes"),
                test_claim("evidence-b", b"second-bytes"),
            ],
            &test_budget(),
        )?;
        assert_eq!(manifest.manifest_digest, reordered.manifest_digest);
        Ok(())
    }

    #[test]
    fn freeze_rejects_empty_duplicate_and_unadmitted_claims()
    -> Result<(), Box<dyn std::error::Error>> {
        let fence = test_fence()?;
        let budget = test_budget();
        let empty: Vec<AdmittedSourceClaim> = Vec::new();
        assert_eq!(
            freeze_orientation_manifest("scope-one", &fence, &empty, &budget).map(|_| ()),
            Err(DreamerMaterialsError::EmptySources)
        );
        let claim = test_claim("evidence-a", b"bytes");
        assert_eq!(
            freeze_orientation_manifest("scope-one", &fence, &[claim.clone(), claim], &budget)
                .map(|_| ()),
            Err(DreamerMaterialsError::DuplicateSource)
        );
        let mut private = test_claim("evidence-a", b"bytes");
        private.privacy_class = "private".to_owned();
        assert_eq!(
            freeze_orientation_manifest("scope-one", &fence, &[private], &budget).map(|_| ()),
            Err(DreamerMaterialsError::Privacy)
        );
        let mut remote = test_claim("evidence-a", b"bytes");
        remote.route_class = "remote-direct".to_owned();
        assert_eq!(
            freeze_orientation_manifest("scope-one", &fence, &[remote], &budget).map(|_| ()),
            Err(DreamerMaterialsError::Route)
        );
        let mut broken = test_claim("evidence-a", b"bytes");
        broken.expected_digest = "not-a-digest".to_owned();
        assert_eq!(
            freeze_orientation_manifest("scope-one", &fence, &[broken], &budget).map(|_| ()),
            Err(DreamerMaterialsError::DigestShape)
        );
        assert_eq!(
            freeze_orientation_manifest(
                "  ",
                &fence,
                &[test_claim("evidence-a", b"bytes")],
                &budget
            )
            .map(|_| ()),
            Err(DreamerMaterialsError::Scope)
        );
        Ok(())
    }

    #[test]
    fn freeze_enforces_budget_before_any_resolution() -> Result<(), Box<dyn std::error::Error>> {
        let fence = test_fence()?;
        let tight = OrientationMaterialBudget {
            max_sources: 1,
            max_total_bytes: 8 * 1024,
            max_source_bytes: 4 * 1024,
        };
        let claims = vec![
            test_claim("evidence-a", b"bytes-a"),
            test_claim("evidence-b", b"bytes-b"),
        ];
        assert_eq!(
            freeze_orientation_manifest("scope-one", &fence, &claims, &tight).map(|_| ()),
            Err(DreamerMaterialsError::BudgetExceeded)
        );
        let invalid = OrientationMaterialBudget {
            max_sources: 0,
            max_total_bytes: 8 * 1024,
            max_source_bytes: 4 * 1024,
        };
        assert_eq!(
            freeze_orientation_manifest("scope-one", &fence, &claims, &invalid).map(|_| ()),
            Err(DreamerMaterialsError::Budget)
        );
        Ok(())
    }

    #[test]
    fn resolved_bytes_must_match_length_and_digest() -> Result<(), Box<dyn std::error::Error>> {
        let claim = test_claim("evidence-a", b"exact-bytes");
        verify_resolved_bytes(&claim, b"exact-bytes")?;
        assert_eq!(
            verify_resolved_bytes(&claim, b"tampered-bytes"),
            Err(DreamerMaterialsError::LengthMismatch)
        );
        let mut short = claim.clone();
        short.expected_byte_length = 5;
        assert_eq!(
            verify_resolved_bytes(&short, b"exact-bytes"),
            Err(DreamerMaterialsError::LengthMismatch)
        );
        let same_length = b"exact-bytfz";
        assert_eq!(same_length.len(), b"exact-bytes".len());
        assert_eq!(
            verify_resolved_bytes(&claim, same_length),
            Err(DreamerMaterialsError::DigestMismatch)
        );
        Ok(())
    }

    /// Test-only read port answering from caller-held bytes. The payload is derived from the
    /// held bytes on every call, never canned per test: a test double can only answer an
    /// already-shaped query, never admit one itself.
    struct AnsweringReadPort {
        fence: StateFence,
        payload: serde_json::Value,
    }

    impl AnsweringReadPort {
        fn query_result(&self, _scope: ScopeId, _subject: &str) -> QueryResult {
            QueryResult {
                intent: QueryIntent {
                    mode: QueryMode::Verification,
                    time_scope: TimeScope::EvidenceWindow,
                    branch_environment_scope: BranchEnvironmentScope::LocalEnvironment,
                    freshness_policy: FreshnessPolicy::ExactCapturedRecords,
                    required_assurance: RequiredAssurance::VerifierEvidence,
                },
                operation: NamedReadOperation::GetEvidencePack,
                state_fence: self.fence.clone(),
                revision_heads: Vec::new(),
                payload: self.payload.clone(),
                provenance: ReadProvenance {
                    handles: Vec::new(),
                    disposition: ProvenanceDisposition::Unavailable,
                },
                consistency: ReadConsistency::Eventual,
            }
        }
    }

    impl LocalReadPort for AnsweringReadPort {
        async fn evidence_query(
            &self,
            ctx: &RequestMetadata,
            scope: ScopeId,
            subject: String,
            max_records: u32,
        ) -> Result<eliot_read::QueryResult, ReadError> {
            if max_records == 0 || subject.trim().is_empty() {
                return Err(ReadError::InvalidField {
                    field: "test query".to_owned(),
                    reason: "test double requires a subject and bound".to_owned(),
                });
            }
            if ctx.state_fence != self.fence {
                return Err(ReadError::ResponseMismatch);
            }
            Ok(self.query_result(scope, &subject))
        }

        async fn projection_inputs(
            &self,
            _ctx: &RequestMetadata,
            _scope: ScopeId,
            _packet_ref: Option<String>,
            _material_refs: Vec<String>,
        ) -> Result<eliot_read::QueryResult, ReadError> {
            Err(ReadError::Store(
                eliot_store_api::StoreError::Unavailable.into(),
            ))
        }
    }

    fn test_context(fence: &StateFence) -> Result<RequestMetadata, Box<dyn std::error::Error>> {
        use eliot_contracts::{ClockReading, ProductId, SourceId};
        Ok(RequestMetadata {
            request_id: RequestId::new("eliotd:test:dreamer:materials")?,
            session_id: None,
            task_id: None,
            product_id: ProductId::new("eliotd")?,
            source_id: SourceId::new("eliotd")?,
            state_fence: fence.clone(),
            clock: ClockReading {
                valid_time_ms: None,
                known_time_ms: None,
                transaction_sequence: None,
                monotonic_ns: None,
            },
        })
    }

    #[tokio::test]
    async fn resolution_verifies_fence_and_digest_over_live_port()
    -> Result<(), Box<dyn std::error::Error>> {
        let fence = test_fence()?;
        let payload =
            serde_json::json!({"records": [{"capture_index": 0}], "subject": "evidence-a"});
        let bytes = canonical_json_bytes(&payload)?;
        let claim = test_claim("evidence-a", &bytes);
        let scope = ScopeId::new("scope-one")?;
        let ctx = test_context(&fence)?;
        let reads = AnsweringReadPort {
            fence: fence.clone(),
            payload: payload.clone(),
        };
        let resolved = resolve_source_claim(&reads, &ctx, &scope, &claim).await?;
        assert_eq!(resolved, bytes);
        let mut altered = bytes.clone();
        if let Some(first) = altered.first_mut() {
            *first ^= 0x01;
        }
        let mut wrong_digest = claim.clone();
        wrong_digest.expected_digest = sha256_hex(&altered);
        assert_eq!(
            wrong_digest.expected_byte_length,
            claim.expected_byte_length
        );
        assert_eq!(
            resolve_source_claim(&reads, &ctx, &scope, &wrong_digest)
                .await
                .map(|_| ()),
            Err(DreamerMaterialsError::DigestMismatch)
        );
        let other_fence = StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE)?,
                NonZeroU64::new(2).ok_or("nonzero test sequence")?,
            )?,
            ResourceGeneration::new(1)?,
        );
        let stale_ctx = test_context(&other_fence)?;
        assert_eq!(
            resolve_source_claim(&reads, &stale_ctx, &scope, &claim)
                .await
                .map(|_| ()),
            Err(DreamerMaterialsError::Resolution(
                ReadError::ResponseMismatch
            ))
        );
        Ok(())
    }
}
