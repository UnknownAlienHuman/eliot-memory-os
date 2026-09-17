//! Governor local read serving adapter (HANDOFF-LRR-GOV, #18).
//!
//! Per-call factory over [`DaemonComposition::context_read_client`]:
//! builds the `KernelContextReadClient` for the caller-held
//! [`DaemonKernelClient`], wraps it in the Governor `ReadService`, and
//! answers through [`LocalReadPort`]. The composition retains no client and
//! no thread, so a Governor refresh surfaces as an exact fence mismatch
//! instead of silent divergence.
//!
//! Caller chain: MGR01 kernel caller -> this factory -> `ReadService` over
//! `KernelContextReadClient` -> store-backed `QueryResult` consumer
//! (projection via `eliot-mcp`, persistence via the existing ORS result
//! path).
//!
//! Production edges out of this module:
//! [`forward_admitted_local_read`] forwards one admitted `eliot.query` pair
//! to the Kernel `local_read` leg over the retained authenticated session
//! and returns the persisted result body; [`serve_admitted_local_read`]
//! serves one admitted pair through the local twin
//! ([`KernelContextReadClient::execute_local_read`] over
//! [`LocalReadPort::evidence_query`]) and returns the exact evidence record.
//!
//! Query is fully live (`Verification` + `GetEvidencePack`); projection
//! inputs stay port-shape fail-closed `Unavailable` until MGR04 (#19)
//! activates the storage operation.

use std::sync::Arc;

use eliot_contracts::{RequestMetadata, StateFence};
use eliot_governor::KernelPortError;
use eliot_protocol::{HostRequestEnvelope, HostRequestResultBody, LocalReadAttempt};
use eliot_read::{LocalReadPort, QueryResult, ReadError, ReadService, StoreReadFailure};
use eliot_store_api::ScopeId;

use super::{DaemonComposition, DaemonKernelClient, KernelContextReadClient};

/// Forwards one admitted `eliot.query` pair to the Kernel `local_read` leg.
///
/// Production kernel-caller bridge over the retained authenticated session:
/// the pair proves its closed linkage and fence binding inside
/// [`DaemonKernelClient::local_read_async`], travels as the `"local_read"`
/// operation with the Kernel-issued attempt capability, and the persisted
/// result body behind the admitted receipt+record returns carrying that same
/// attempt for the submit leg. Kernel remains the admission, read, and
/// persistence authority; this function performs no admission decision and no
/// consistency algorithm. A wrong fence or malformed pair fails closed before
/// any transport; a packet admission carries no result body by design.
pub async fn forward_admitted_local_read(
    kernel: &DaemonKernelClient,
    envelope: HostRequestEnvelope,
    tool: serde_json::Value,
    attempt: LocalReadAttempt,
) -> Result<HostRequestResultBody, KernelPortError> {
    kernel.local_read_async(envelope, tool, attempt).await
}

/// Serves one admitted `eliot.query` pair through the Governor read port.
///
/// Production local-serving edge twinning the Kernel admission mirror: the
/// closed capability gate runs before any read, the envelope fence must equal
/// the caller-observed admitted fence, and the closed selectors serve exactly
/// one bounded [`LocalReadPort::evidence_query`] whose answer must echo the
/// evidence operation and the admitted fence. Returns the exact evidence
/// record, never a bare admission. `eliot.packet` stays admission-only
/// (`Unavailable`, MGR04 #19); a wrong fence or a substituted answer fails
/// closed, never `Ok`-empty.
///
/// The port and the fence stay per-call parameters (rather than retained
/// state) so the composition retains no client and no thread.
pub async fn serve_admitted_local_read(
    reads: &impl LocalReadPort,
    admitted_fence: &StateFence,
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<QueryResult, ReadError> {
    KernelContextReadClient::execute_local_read(reads, admitted_fence, envelope, tool).await
}

/// Answers one bounded Governor evidence query through the local read port.
///
/// Threads the admitted fence via `ctx`, the explicit trusted `scope`, the
/// exact `subject`, and the explicit `max_records` bound. Returns the exact
/// record/provenance on success; a wrong fence or an over-bound request is
/// refused fail-closed.
pub async fn answer_evidence_query(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    ctx: &RequestMetadata,
    scope: ScopeId,
    subject: String,
    max_records: u32,
) -> Result<QueryResult, ReadError> {
    let client = composition
        .context_read_client(kernel)
        .map_err(|_| ReadError::Store(StoreReadFailure::Unavailable))?;
    let service = ReadService::new(client);
    service
        .evidence_query(ctx, scope, subject, max_records)
        .await
}

/// Answers one Governor projection-inputs read (port-shape only).
///
/// Validates `packet_ref` / `material_refs` and the facade request shape,
/// then fails closed with a typed `Unavailable` store error until MGR04
/// (#19) activates the storage operation. Never `Ok`-empty, never canned.
pub async fn answer_projection_inputs(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    ctx: &RequestMetadata,
    scope: ScopeId,
    packet_ref: Option<String>,
    material_refs: Vec<String>,
) -> Result<QueryResult, ReadError> {
    let client = composition
        .context_read_client(kernel)
        .map_err(|_| ReadError::Store(StoreReadFailure::Unavailable))?;
    let service = ReadService::new(client);
    service
        .projection_inputs(ctx, scope, packet_ref, material_refs)
        .await
}
