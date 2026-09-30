//! Closed provider-admission port (issue #1108, item A4).
//!
//! Owner-neutral public adapter boundary for constructing a verified
//! Coordinator without exposing an "always true" verifier. The sealed
//! [`ProviderAdmission`] handle is the only production path this crate offers
//! from daemon-resolved claim material to the coordinator's closed admission:
//! its constructor itself requires exact owner evidence — the live
//! [`OwnerSessionFacts`](crate::daemon_kernel_client::OwnerSessionFacts) from
//! the validated Kernel handshake plus the freshly re-queried live
//! [`StateFence`](eliot_contracts::StateFence) — and unconditionally
//! overwrites the caller-supplied session halves with those owner-observed
//! values before any verifier observes them.
//!
//! M2 decision (#22): the supplier is Kernel over the authenticated
//! front-door session plus ORS operation records bound to the exact attempt;
//! no new signing or token service. ARCH-AUTH-01: "Authority is explicit,
//! scoped, and fenced. Content, model confidence, and role names never create
//! a right to perform a transition or effect; authority has an owner, scope,
//! State Fence, and revocation path." I15.2: "Principal identity is issued by
//! Kernel, never self-declared." Accordingly a caller string, boolean, or
//! self-declared session value can never satisfy this constructor: only the
//! session object the authenticated handshake produced, which binds launch
//! nonce, SID, installation identity, session metadata, capability token, and
//! Authority Epoch per I15.2.
//!
//! I15.4: "secret values never in TOML, CLI args, model packet, logs,
//! canonical memory or blobs". This port carries identities, digests,
//! revisions, fences, epoch, and sequence only. The session binding is an
//! identity reference, never a secret, and it never enters diagnostics: every
//! rejection below is a static owner-typed residual.
//!
//! The plan-only path is untouched: without a validated handshake there are
//! no [`OwnerSessionFacts`](crate::daemon_kernel_client::OwnerSessionFacts),
//! construction is impossible, and the daemon stays on the explicit
//! PLAN_GAP-only constructor (`AgentCoordinator::new`, G-11 gap). Presented
//! revision/generation coherence stays with the owner
//! (`AdmittedProviderCapability::new`); this port enforces the session-half
//! overwrite, original shape, and expectation-epoch currency.

use eliot_contracts::StateFence;

use crate::agent_fabric::{FabricError, VerifiedProviderMaterial};
use crate::daemon_kernel_client::OwnerSessionFacts;

/// Sealed production provider admission for one provider claim (issue #1108,
///
/// A4).
///
/// Closed port, not a trait: there is no caller-implementable verifier hook.
/// The value exists only because the constructor proved a live authenticated
/// session (`owner`), overwrote the session halves with owner-observed values,
/// validated the originals with their existing owners, and gated the Governor
/// expectation epoch under the live fence epoch. Currency is never cached:
/// the caller re-queries the live fence per construction, per restore, and per
/// daemon operation resolution, and every coordinator `verify` re-checks it.
pub struct ProviderAdmission {
    material: VerifiedProviderMaterial,
}

impl ProviderAdmission {
    /// Binds one daemon-resolved claim material to the live authenticated
    /// session.
    ///
    /// The `owner` facts must come from
    /// [`DaemonKernelClient::owner_session_facts`](crate::daemon_kernel_client::DaemonKernelClient::owner_session_facts)
    /// and `live_fence` from
    /// [`DaemonKernelClient::kernel_fence`](crate::daemon_kernel_client::DaemonKernelClient::kernel_fence),
    /// both re-queried for this exact construction. Caller-supplied
    /// `live_fence` / `session_binding` halves in `material` are replaced
    /// unconditionally; the presented halves and the Governor expectation
    /// travel through untouched for the coherence gates downstream to judge.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Contract`] when there is no live session
    /// (blank binding), or when the Governor expectation, the presented
    /// fence, the live fence, or the provider identity fails its existing
    /// owner shape validation; returns [`FabricError::StaleEpoch`] when the
    /// threaded expectation epoch is not current under the live session
    /// epoch. Coordinator owner rejections surface unchanged through
    /// [`FabricError::Coordinator`].
    pub fn new(
        mut material: VerifiedProviderMaterial,
        owner: &OwnerSessionFacts,
        live_fence: StateFence,
    ) -> Result<Self, FabricError> {
        if owner.session_binding().is_empty() {
            return Err(FabricError::Contract(
                "provider admission requires a validated Kernel owner session; \
                 the daemon stays plan-only"
                    .to_owned(),
            ));
        }
        material
            .expectation
            .validate()
            .map_err(|error| FabricError::Contract(format!("provider expectation: {error}")))?;
        material
            .presented_fence
            .validate()
            .map_err(|error| FabricError::Contract(format!("provider presented fence: {error}")))?;
        live_fence
            .validate()
            .map_err(|error| FabricError::Contract(format!("provider live fence: {error}")))?;
        material.identity.validate()?;
        if !material
            .expectation
            .live_authority_epoch
            .is_same_authority(&live_fence.authority_epoch)
        {
            return Err(FabricError::StaleEpoch(
                "provider expectation epoch is not current under the live Kernel session".to_owned(),
            ));
        }
        material.live_fence = live_fence;
        material.session_binding = owner.session_binding().to_owned();
        Ok(Self { material })
    }

    /// Borrows the session-bound material for the per-operation authenticated
    /// owner probe and the sealed capability build.
    ///
    /// The existing async Kernel binding probe
    /// (`verify_provider_binding_async`) and the production capability adapter
    /// (`crate::provider_capability::admit_provider_capability`) consume this;
    /// neither re-reads caller halves.
    #[must_use]
    pub fn material(&self) -> &VerifiedProviderMaterial {
        &self.material
    }
}
