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
//! Query is fully live (`Verification` + `GetEvidencePack`); projection
//! inputs stay port-shape fail-closed `Unavailable` until MGR04 (#19)
//! activates the storage operation.

use std::sync::Arc;

use eliot_contracts::RequestMetadata;
use eliot_read::{LocalReadPort, QueryResult, ReadError, ReadService};
use eliot_store_api::ScopeId;

use super::{DaemonComposition, DaemonKernelClient};

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
        .map_err(|error| ReadError::Store(error.to_string()))?;
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
        .map_err(|error| ReadError::Store(error.to_string()))?;
    let service = ReadService::new(client);
    service
        .projection_inputs(ctx, scope, packet_ref, material_refs)
        .await
}
