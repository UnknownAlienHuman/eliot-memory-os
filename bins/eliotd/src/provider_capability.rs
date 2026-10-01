//! Production provider-capability adapter (issue #1108, item A5).
//!
//! One production admission adapter over the accepted Kernel / native-worker /
//! G-11 receipt owner. [`admit_provider_capability`] builds the sealed
//! coordinator capability
//! ([`AdmittedProviderCapability`](eliot_agent_coordinator::AdmittedProviderCapability))
//! from a session-bound [`ProviderAdmission`](crate::provider_admission::ProviderAdmission),
//! never from caller strings.
//!
//! I10.15: "admission is a fail-closed saga rather than a fictitious
//! cross-store transaction" — "1. `AgentCoordinator` revalidates dependencies,
//! State Fence, recipe, route evidence and policy. 2. Kernel stages an
//! inactive `AdmissionReservation` in ORS for the exact work item". I10.11:
//! each adapter "returns candidate artifact, raw native events and provider
//! receipt", and "The logical receipt never proves that a provider call
//! occurred". Accordingly evidence is bound by comparing content with the
//! exact operation at hand (claim/attempt/operation identities, binding
//! digests, revisions, worker generation, presented fence), and the originals
//! are validated with their existing `validate()` owners — never recomputed
//! locally. Digest equality against the durable ORS row stays Kernel-side per
//! effecting operation through the authenticated capability wire operation;
//! provider acknowledgement, process exit, and model output remain attempt
//! evidence only, never Task Finish.
//!
//! I10.15: "No silent mid-attempt failover." A content mismatch under one
//! identity is the typed [`FabricError::IdentityConflict`] residual, never a
//! substitution, retry under another route, or new attempt. I15.4 carries
//! over from the admission port: identities, digests, revisions, fences, and
//! sequence only — raw credentials never enter state, receipts, or
//! diagnostics. Issue #265 catalogue/quota/liveness observations ride only in
//! the health half: selection/health input, never admission.
//!
//! Closed factory admission (issue #1108 A4): this adapter resolves the
//! durable owner row as `OwnerLoadedClaimRow` through
//! `DaemonKernelClient::load_provider_claim_row_async` under the exact
//! `claim_id`, then admits through `AdmittedProviderFactory::new` + `admit`,
//! so the agreement gate observes production material and fails closed with
//! `StaleProviderBinding` unless every presented identity, digest,
//! generation, and fence digest equals the Kernel/ORS-loaded owner row. No
//! row is rebuilt here from presented halves: that would make the factory
//! gate tautological. Production Verified therefore rests on the
//! construction-time Binding probe plus the factory row agreement plus the
//! per-proof receipt/payload checks.

use eliot_agent_coordinator::{AdmittedProviderCapability, AdmittedProviderFactory};
use eliot_contracts::fences_match_exact;

use crate::agent_fabric::FabricError;
use crate::daemon_kernel_client::DaemonKernelClient;
use crate::provider_admission::ProviderAdmission;
use crate::solo_agent_driver::SoloClaimedHalves;

/// Builds the sealed coordinator capability for the exact operation at hand
/// (issue #1108, item A5).
///
/// Content comparison first: every presented field in the session-bound
/// admission must equal the operation-presented halves the driver is
/// currently driving (`claimed`). Only then is the durable owner row resolved
/// through the authenticated Kernel claim-row read under the exact `claim_id`,
/// and the admission halves are forwarded into the closed
/// [`AdmittedProviderFactory`](eliot_agent_coordinator::AdmittedProviderFactory),
/// which proves them equal to the loaded owner row before the existing
/// presented/owner capability boundary judges shape, coherence, and currency.
/// The capability is therefore bound to installation (session facts),
/// principal/session (session binding), route and capacity revisions,
/// worker generation, Authority Epoch, State Fence, and freshness (live fence
/// re-queried per admission construction) — and to this operation's exact
/// identities and digests, witnessed against the durable row.
///
/// # Errors
///
/// Returns [`FabricError::IdentityConflict`] when the bound admission content
/// differs from the operation at hand in identity, claim/attempt/operation
/// identity, binding digest, revision, worker generation, or presented fence;
/// returns [`FabricError::Contract`] when the Kernel row read fails closed
/// (no live session, transport refusal, unsealed or misbound reply);
/// otherwise returns the factory/coordinator owner rejection unchanged
/// (row disagreement as `StaleProviderBinding`, shape, coherence, or
/// stale/revoked binding) through [`FabricError::Coordinator`].
pub async fn admit_provider_capability(
    kernel: &DaemonKernelClient,
    admission: &ProviderAdmission,
    claimed: &SoloClaimedHalves,
) -> Result<AdmittedProviderCapability, FabricError> {
    let material = admission.material();
    let matches_operation = material.identity == claimed.identity
        && material.claim_id == claimed.claim_id
        && material.attempt_id == claimed.attempt_id
        && material.operation_id == claimed.operation_id
        && material.binding_digest == claimed.binding_digest
        && material.executable_digest == claimed.executable_digest
        && material.route_revision == claimed.route_revision
        && material.capacity_revision == claimed.capacity_revision
        && material.worker_generation == claimed.worker_generation
        && material.minimum_event_sequence == claimed.minimum_event_sequence
        && fences_match_exact(&material.presented_fence, &claimed.presented_fence);
    if !matches_operation {
        return Err(FabricError::IdentityConflict(
            "provider admission content does not match the operation at hand; \
             no substitution, retry, or route change"
                .to_owned(),
        ));
    }
    let loaded = kernel
        .load_provider_claim_row_async(&material.claim_id)
        .await
        .map_err(|error| {
            FabricError::Contract(format!("provider claim-row read refused: {error}"))
        })?;
    Ok(AdmittedProviderFactory::new(loaded).admit(
        material.identity.clone(),
        material.claim_id.clone(),
        material.attempt_id.clone(),
        material.operation_id.clone(),
        material.binding_digest.clone(),
        material.executable_digest.clone(),
        material.route_revision.clone(),
        material.capacity_revision.clone(),
        material.worker_generation,
        material.presented_fence.clone(),
        material.expectation.clone(),
        material.live_fence.clone(),
        material.health.clone(),
        material.minimum_event_sequence,
    )?)
}
