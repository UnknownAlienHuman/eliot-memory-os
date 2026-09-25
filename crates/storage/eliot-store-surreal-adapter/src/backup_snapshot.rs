//! Coherent bounded snapshot capture over the `SurrealDB` bridge (issue #951).
//!
//! Owner-issued consistency points only: [`begin_snapshot`] binds one frozen
//! capture point (source identity, schema generation, fence, ordered
//! denominator, bounds, expiry) after the readiness/generation/fence gate,
//! [`read_snapshot_page`] serves deterministic logical-order pages under that
//! same point, and [`end_snapshot`] closes with an owner-issued receipt. Any
//! drift (newer generation), expiry, duration overrun, fence change, or
//! cursor/continuation mismatch fails closed and releases the capture-owned
//! registry entry; the registry map itself is never cleared wholesale.
//!
//! Reads only: this module never acquires `adapter.write_lock`, issues no
//! DDL/migration, performs no restore, and defines no archive format. Every
//! provider statement is a fixed adapter-owned `const`; bindings carry only
//! allowlisted scalars (here: none — the point probe takes no parameters),
//! and errors/receipts carry digests and static text, never provider payload
//! or credentials.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use eliot_store_api::{
    MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_MEMBERS, MAX_SNAPSHOT_PAGE_MEMBERS, MAX_SNAPSHOT_PAGES,
    RequestMeta, SnapshotBeginRequest, SnapshotCompleteness, SnapshotCursor, SnapshotEndReceipt,
    SnapshotHandle, SnapshotMember, SnapshotPage, StoreError, canonical_json_bytes, sha256_hex,
};
use serde::Deserialize;
use serde_json::Map;

use crate::SurrealStoreAdapter;
use crate::error::AdapterError;

/// Closed named-operation label for binding one snapshot consistency point.
pub(crate) const SNAPSHOT_BEGIN_OPERATION: &str = "snapshot.begin";
/// Closed named-operation label for reading one page under a bound point.
pub(crate) const SNAPSHOT_PAGE_OPERATION: &str = "snapshot.page";
/// Closed named-operation label for closing a capture with an end receipt.
pub(crate) const SNAPSHOT_END_OPERATION: &str = "snapshot.end";

/// Fixed adapter-owned point-observation statement: the schema-meta
/// generation projection owned by [`crate::schema`]. Referenced, not
/// restated, so the physical table name keeps its single owner.
const SNAPSHOT_POINT_STATEMENT: &str = crate::schema::READ_SCHEMA_META;

/// Members served per page: the closed per-page ceiling from `backup_io`.
const SNAPSHOT_PAGE_CHUNK: u64 = MAX_SNAPSHOT_PAGE_MEMBERS as u64;

/// One shape of the point-probe projection used for generation binding.
#[derive(Deserialize)]
struct GenerationProbe {
    generation: String,
}

/// Frozen per-handle capture state. No `Debug` impl by design: registry
/// contents never render into logs or errors.
struct SnapshotState {
    begin: SnapshotBeginRequest,
    observed_generation: String,
    ordered_members: Vec<SnapshotMember>,
    total_bytes: u64,
    total_pages: u64,
    pages_served: u64,
    members_served: u64,
    bytes_served: u64,
    last_digest: String,
    opened_at_ms: u64,
}

/// Module-private capture registry keyed by handle digest.
fn registry() -> &'static Mutex<HashMap<String, SnapshotState>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, SnapshotState>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_registry()
-> Result<std::sync::MutexGuard<'static, HashMap<String, SnapshotState>>, StoreError> {
    registry().lock().map_err(|_| StoreError::Unavailable)
}

/// Reports whether a capture can no longer serve: owner expiry passed (or
/// non-positive, which is fail-closed expired) or the capture duration bound
/// is overrun. `try_from` keeps the `i64` expiry conversion exact.
fn is_retired(
    expires_at_unix_ms: i64,
    opened_at_ms: u64,
    max_duration_ms: u64,
    now_ms: u64,
) -> bool {
    if expires_at_unix_ms <= 0 {
        return true;
    }
    if !u64::try_from(expires_at_unix_ms).is_ok_and(|expiry| expiry >= now_ms) {
        return true;
    }
    now_ms.saturating_sub(opened_at_ms) > max_duration_ms
}

/// Drops every entry whose owner-issued window has passed. Scoped cleanup
/// only; live entries are never touched.
fn purge_expired(states: &mut HashMap<String, SnapshotState>, now_ms: u64) {
    states.retain(|_, state| {
        !is_retired(
            state.begin.expires_at_unix_ms,
            state.opened_at_ms,
            state.begin.bounds.max_duration_ms,
            now_ms,
        )
    });
}

/// Gates on readiness/generation (no fallback client, no ambient DB) and then
/// observes the live schema generation through one fixed parameterized
/// adapter-owned statement.
///
/// `operation` selects the closed `snapshot.*` label for this call. The
/// statement takes no parameters; the binding map is empty so no caller value
/// can reach the provider. Unlisted operation names stay on the facade
/// session inside [`crate::client::query`]; only reads are issued here.
async fn observe_live_generation(
    adapter: &SurrealStoreAdapter,
    operation: &'static str,
) -> Result<String, StoreError> {
    let transport = crate::apply::client(adapter)
        .await
        .map_err(AdapterError::into_store_error)?;
    crate::apply::ensure_ready(adapter, transport)
        .await
        .map_err(AdapterError::into_store_error)?;
    let mut response = crate::client::query(
        transport,
        &adapter.config,
        operation,
        SNAPSHOT_POINT_STATEMENT,
        Map::new(),
    )
    .await
    .map_err(AdapterError::into_store_error)?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        if errors
            .iter()
            .all(|error| crate::client::is_absent_table(error))
        {
            return Err(StoreError::Unavailable);
        }
        return Err(StoreError::MissingReceiptEnvelope);
    }
    let probe: Option<GenerationProbe> =
        response.take(0).map_err(AdapterError::into_store_error)?;
    match probe {
        Some(probe)
            if !probe.generation.is_empty() && !probe.generation.chars().any(char::is_control) =>
        {
            Ok(probe.generation)
        }
        _ => Err(StoreError::Unavailable),
    }
}

/// Removes exactly the capture-owned entry. The map itself is never cleared.
fn release_owned(states: &mut HashMap<String, SnapshotState>, digest: &str) {
    states.remove(digest);
}

/// Opens a coherent capture under one owner-issued consistency point.
pub(crate) async fn begin_snapshot(
    adapter: &SurrealStoreAdapter,
    ctx: &RequestMeta,
    request: SnapshotBeginRequest,
) -> Result<SnapshotHandle, StoreError> {
    ctx.validate().map_err(StoreError::Foundation)?;
    request.validate()?;
    if ctx.state_fence != request.scope.state_fence {
        return Err(StoreError::FenceMismatch);
    }
    if request.source.installation_id != adapter.config.installation_id {
        return Err(StoreError::InvalidField {
            field: "snapshot.installation_id",
            reason: "source is not this installation",
        });
    }
    let observed = observe_live_generation(adapter, SNAPSHOT_BEGIN_OPERATION).await?;
    if observed != adapter.config.expected_schema_generation.as_str() {
        return Err(StoreError::Unavailable);
    }

    let snapshot_digest = request.compute_digest()?;
    let mut ordered_members = request.denominator.members.clone();
    ordered_members.sort_by_key(SnapshotMember::logical_identity);

    let member_count = ordered_members.len() as u64;
    if member_count > request.bounds.max_members || member_count > MAX_SNAPSHOT_MEMBERS as u64 {
        return Err(StoreError::PayloadTooLarge);
    }
    let total_bytes = ordered_members.iter().fold(0_u64, |total, member| {
        total.saturating_add(member.residency.byte_count)
    });
    if total_bytes > request.bounds.max_bytes || total_bytes > MAX_SNAPSHOT_BYTES {
        return Err(StoreError::PayloadTooLarge);
    }
    // One work unit per member; the per-request ceiling is enforced here and
    // the frozen global ceiling through `bounds.validate()` above.
    if member_count > request.bounds.max_work {
        return Err(StoreError::PayloadTooLarge);
    }
    let total_pages = member_count.div_ceil(SNAPSHOT_PAGE_CHUNK);
    if total_pages > request.bounds.max_pages || total_pages > MAX_SNAPSHOT_PAGES {
        return Err(StoreError::PayloadTooLarge);
    }

    let handle = SnapshotHandle {
        consistency_point: format!("snapshot-point:{snapshot_digest}"),
        snapshot_digest: snapshot_digest.clone(),
        operation_id: request.operation.operation_id.clone(),
        idempotency_key: request.operation.idempotency_key.clone(),
    };
    handle.validate()?;

    let mut states = lock_registry()?;
    if states.contains_key(&snapshot_digest) {
        // Deterministic replay of the same begin request: keep the in-flight
        // capture (and its served-page progress) instead of rebinding it.
        return Ok(handle);
    }
    states.insert(
        snapshot_digest.clone(),
        SnapshotState {
            begin: request,
            observed_generation: observed,
            ordered_members,
            total_bytes,
            total_pages,
            pages_served: 0,
            members_served: 0,
            bytes_served: 0,
            last_digest: snapshot_digest,
            opened_at_ms: crate::write_execution::current_time_ms(),
        },
    );
    Ok(handle)
}

/// Verifies that a cursor resumes exactly the next unserved page of this
/// capture with cumulative bounds intact (never reset, never skipped).
fn check_cursor(state: &SnapshotState, cursor: &SnapshotCursor) -> Result<(), StoreError> {
    if cursor.page_index != state.pages_served {
        return Err(StoreError::InvalidField {
            field: "snapshot.page_index",
            reason: "continuation must advance exactly one page",
        });
    }
    if cursor.cumulative_members != state.members_served
        || cursor.cumulative_bytes != state.bytes_served
    {
        return Err(StoreError::InvalidField {
            field: "snapshot.cumulative_bytes",
            reason: "continuation must not reset cumulative bounds",
        });
    }
    Ok(())
}

/// Slices the next page out of a drift-verified capture, advances its served
/// progress, and chains the predecessor digest. Runs under the registry lock
/// with no awaits inside.
fn serve_next_page(
    states: &mut HashMap<String, SnapshotState>,
    digest: &str,
    handle: SnapshotHandle,
    cursor: SnapshotCursor,
) -> Result<SnapshotPage, StoreError> {
    let Some(state) = states.get_mut(digest) else {
        return Err(StoreError::InvalidField {
            field: "snapshot.snapshot_digest",
            reason: "unknown snapshot handle",
        });
    };
    // Served progress is contiguous from index zero, so the served member
    // count doubles as the next slice start; `try_from` keeps the
    // `u64`-to-`usize` conversion exact.
    let start = usize::try_from(state.members_served).map_err(|_| StoreError::PayloadTooLarge)?;
    let chunk = usize::try_from(SNAPSHOT_PAGE_CHUNK).map_err(|_| StoreError::PayloadTooLarge)?;
    let end = start.saturating_add(chunk).min(state.ordered_members.len());
    if start >= state.ordered_members.len() || start >= end {
        release_owned(states, digest);
        return Err(StoreError::Unavailable);
    }
    let state = states.get_mut(digest).ok_or(StoreError::Unavailable)?;
    let members = state.ordered_members[start..end].to_vec();
    let page_bytes = members.iter().fold(0_u64, |total, member| {
        total.saturating_add(member.residency.byte_count)
    });
    let cumulative_members = state.members_served.saturating_add(members.len() as u64);
    let cumulative_bytes = state.bytes_served.saturating_add(page_bytes);
    if cumulative_members > state.begin.bounds.max_members
        || cumulative_bytes > state.begin.bounds.max_bytes
        || cumulative_bytes > MAX_SNAPSHOT_BYTES
    {
        release_owned(states, digest);
        return Err(StoreError::PayloadTooLarge);
    }
    let is_last = end >= state.ordered_members.len();
    let next_cursor = if is_last {
        None
    } else {
        Some(SnapshotCursor {
            handle_digest: digest.to_owned(),
            page_index: state.pages_served.saturating_add(1),
            cumulative_members,
            cumulative_bytes,
        })
    };
    let page = SnapshotPage {
        handle,
        cursor,
        members,
        cumulative_bytes,
        cumulative_work: cumulative_members,
        is_last,
        predecessor_digest: state.last_digest.clone(),
        next_cursor,
    };
    page.validate()?;
    page.validate_for_begin(&state.begin)?;
    let page_digest = sha256_hex(
        &canonical_json_bytes(&page)
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    );
    state.pages_served = state.pages_served.saturating_add(1);
    state.members_served = cumulative_members;
    state.bytes_served = cumulative_bytes;
    state.last_digest = page_digest;
    Ok(page)
}

/// Reads one bounded page of an open capture under its bound point.
pub(crate) async fn read_snapshot_page(
    adapter: &SurrealStoreAdapter,
    ctx: &RequestMeta,
    handle: SnapshotHandle,
    cursor: SnapshotCursor,
) -> Result<SnapshotPage, StoreError> {
    ctx.validate().map_err(StoreError::Foundation)?;
    handle.validate()?;
    cursor.validate()?;
    if cursor.handle_digest != handle.snapshot_digest {
        return Err(StoreError::InvalidField {
            field: "snapshot.cursor",
            reason: "cursor does not belong to this snapshot handle",
        });
    }
    let digest = handle.snapshot_digest.clone();
    let now_ms = crate::write_execution::current_time_ms();
    {
        let mut states = lock_registry()?;
        let Some(state) = states.get(&digest) else {
            return Err(StoreError::InvalidField {
                field: "snapshot.snapshot_digest",
                reason: "unknown snapshot handle",
            });
        };
        if is_retired(
            state.begin.expires_at_unix_ms,
            state.opened_at_ms,
            state.begin.bounds.max_duration_ms,
            now_ms,
        ) {
            release_owned(&mut states, &digest);
            return Err(StoreError::Unavailable);
        }
        if ctx.state_fence != state.begin.scope.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        check_cursor(state, &cursor)?;
        if state.ordered_members.is_empty() {
            // Known-empty capture: explicit typed refusal, never a silent or
            // fabricated page. Close via `end_snapshot` for the complete
            // zero-member accounting path.
            return Err(StoreError::Empty {
                field: "snapshot.members",
            });
        }
        if state.pages_served.saturating_add(1) > state.begin.bounds.max_pages
            || state.pages_served.saturating_add(1) > MAX_SNAPSHOT_PAGES
        {
            return Err(StoreError::PayloadTooLarge);
        }
        purge_expired(&mut states, now_ms);
    }

    // No registry lock is held across this provider await. A failed probe
    // releases only the capture-owned entry, never the whole map.
    let observed = observe_live_generation(adapter, SNAPSHOT_PAGE_OPERATION)
        .await
        .inspect_err(|_| {
            if let Ok(mut states) = registry().lock() {
                release_owned(&mut states, &digest);
            }
        })?;

    let mut states = lock_registry()?;
    let Some(state) = states.get(&digest) else {
        return Err(StoreError::InvalidField {
            field: "snapshot.snapshot_digest",
            reason: "unknown snapshot handle",
        });
    };
    if observed != state.observed_generation {
        // The source moved under the bound point: never mix a newer point.
        release_owned(&mut states, &digest);
        return Err(StoreError::Unavailable);
    }
    check_cursor(state, &cursor)?;
    serve_next_page(&mut states, &digest, handle, cursor)
}

/// Closes a capture with an owner-issued end receipt and removes its entry.
pub(crate) async fn end_snapshot(
    adapter: &SurrealStoreAdapter,
    ctx: &RequestMeta,
    handle: SnapshotHandle,
) -> Result<SnapshotEndReceipt, StoreError> {
    ctx.validate().map_err(StoreError::Foundation)?;
    handle.validate()?;
    let digest = handle.snapshot_digest.clone();
    let now_ms = crate::write_execution::current_time_ms();
    {
        let mut states = lock_registry()?;
        let Some(state) = states.get(&digest) else {
            return Err(StoreError::InvalidField {
                field: "snapshot.snapshot_digest",
                reason: "unknown snapshot handle",
            });
        };
        if is_retired(
            state.begin.expires_at_unix_ms,
            state.opened_at_ms,
            state.begin.bounds.max_duration_ms,
            now_ms,
        ) {
            release_owned(&mut states, &digest);
            return Err(StoreError::Unavailable);
        }
        if ctx.state_fence != state.begin.scope.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        purge_expired(&mut states, now_ms);
    }

    // No registry lock is held across this provider await. A failed probe
    // releases only the capture-owned entry, never the whole map.
    let observed = observe_live_generation(adapter, SNAPSHOT_END_OPERATION)
        .await
        .inspect_err(|_| {
            if let Ok(mut states) = registry().lock() {
                release_owned(&mut states, &digest);
            }
        })?;

    let mut states = lock_registry()?;
    let Some(state) = states.get(&digest) else {
        return Err(StoreError::InvalidField {
            field: "snapshot.snapshot_digest",
            reason: "unknown snapshot handle",
        });
    };
    if observed != state.observed_generation {
        release_owned(&mut states, &digest);
        return Err(StoreError::Unavailable);
    }
    let complete = state.members_served == state.ordered_members.len() as u64
        && state.bytes_served == state.total_bytes
        && state.pages_served == state.total_pages;
    let receipt = SnapshotEndReceipt {
        handle,
        operation: state.begin.operation.clone(),
        member_count: state.members_served,
        byte_count: state.bytes_served,
        completeness: if complete {
            SnapshotCompleteness::Complete
        } else {
            SnapshotCompleteness::Partial
        },
        validation_revision: 1,
    };
    receipt.validate()?;
    release_owned(&mut states, &digest);
    Ok(receipt)
}
