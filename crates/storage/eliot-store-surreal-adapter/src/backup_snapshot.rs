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
    SnapshotHandle, SnapshotMember, SnapshotPage, StateFence, StoreError, canonical_json_bytes,
    sha256_hex,
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

/// Members served per page: the closed per-page ceiling from `backup_io`.
const SNAPSHOT_PAGE_CHUNK: u64 = MAX_SNAPSHOT_PAGE_MEMBERS as u64;

/// Static error field for a canonical source class composition defect.
const SNAPSHOT_CLASS_FIELD: &str = "snapshot.classes";

/// Enumeration revision bound into every end receipt.
///
/// The receipt's validation revision names the canonical-enumeration revision
/// that produced the observed denominator, so a receipt can never be read as
/// evidence of a later or earlier enumeration shape.
const SNAPSHOT_VALIDATION_REVISION: u64 = 1;

/// Domain separator for the owner-issued consistency point.
///
/// I5.27 binds canonical identity over a domain separator, so a capture handle
/// can never be confused with another capability's evidence. The separator is
/// the public capability this fixed registry implements, owned by
/// `eliot-store-api` and surfaced by the registry.
const SNAPSHOT_CONSISTENCY_POINT_DOMAIN: &str = crate::client::snapshot_capability();

/// One declared canonical source class and its single disposition in a capture.
///
/// The enumeration below is declared here, not in [`crate::schema`], because
/// `schema.rs` is the single owner of the physical *names* and this module is
/// the single owner of what a bounded backup capture *does* with each declared
/// class. It only references `crate::schema::table::*` and
/// `crate::schema::READ_SCHEMA_META` / `READ_FENCE`; it adds no name, no DDL
/// and no migration.
pub(crate) enum CanonicalSourceClass {
    /// Read in the one member transaction and captured as a snapshot member.
    Member {
        /// Physical table name owned by [`crate::schema`].
        table: &'static str,
    },
    /// Read as the capture point itself; never a member.
    CapturePoint {
        /// Physical table name owned by [`crate::schema`].
        table: &'static str,
        /// Fixed adapter-owned point read owned by [`crate::schema`].
        statement: &'static str,
    },
    /// Declared by the single owner but not defined by the admitted
    /// `SCHEMA_DDL_V2` generation.
    ///
    /// `SurrealAdapterConfig::validate` pins
    /// `expected_schema_generation == GENERATION_V2`, and `SCHEMA_DDL_V2`
    /// (`schema.rs`) defines exactly the eleven tables below the
    /// [`CanonicalSourceClass::CapturePoint`] rows plus the nine
    /// [`CanonicalSourceClass::Member`] rows. Every remaining table is added by
    /// an additive delta DDL that no admitted migration path reaches: the
    /// erasure delta is `#[allow(dead_code)]` (`schema.rs`
    /// `MIGRATION_ID_V2_TO_V3`) and the notification/resource/automation/
    /// experience deltas are the same shape. Reading an undefined table inside
    /// one `BEGIN … COMMIT` batch aborts the whole transaction (see the
    /// recorded provider observations in `apply/read_boundary.rs`), so
    /// including these rows would make every capture fail on an admitted
    /// store. Each therefore has exactly one disposition — declared, not
    /// captured — instead of being silently omitted or reported as an
    /// undeclared exclusion.
    OutsideAdmittedGeneration {
        /// Physical table name owned by [`crate::schema`].
        table: &'static str,
    },
}

/// Every canonical source class the single owner declares, in canonical order.
pub(crate) const CANONICAL_SOURCE_CLASSES: &[CanonicalSourceClass] = &[
    CanonicalSourceClass::CapturePoint {
        table: crate::schema::table::SCHEMA_META,
        statement: crate::schema::READ_SCHEMA_META,
    },
    CanonicalSourceClass::Member {
        table: crate::schema::table::WRITE_RECEIPT,
    },
    CanonicalSourceClass::Member {
        table: crate::schema::table::REVISION_HEAD,
    },
    CanonicalSourceClass::Member {
        table: crate::schema::table::ORDERING_HEAD,
    },
    CanonicalSourceClass::Member {
        table: crate::schema::table::CANONICAL_EVENT,
    },
    CanonicalSourceClass::Member {
        table: crate::schema::table::PROJECTION_RECORD,
    },
    CanonicalSourceClass::Member {
        table: crate::schema::table::RELATION_RECORD,
    },
    CanonicalSourceClass::Member {
        table: crate::schema::table::OUTBOX_EVENT,
    },
    CanonicalSourceClass::Member {
        table: crate::schema::table::RECOVERY_OWNER,
    },
    CanonicalSourceClass::Member {
        table: crate::schema::table::RECOVERY_JOB,
    },
    CanonicalSourceClass::CapturePoint {
        table: crate::schema::table::CANONICAL_FENCE,
        statement: crate::schema::READ_FENCE,
    },
    CanonicalSourceClass::OutsideAdmittedGeneration {
        table: crate::schema::table::ERASURE_INTENT,
    },
    CanonicalSourceClass::OutsideAdmittedGeneration {
        table: crate::schema::table::ERASURE_OUTCOME,
    },
    CanonicalSourceClass::OutsideAdmittedGeneration {
        table: crate::schema::table::NOTIFICATION_RECORD,
    },
    CanonicalSourceClass::OutsideAdmittedGeneration {
        table: crate::schema::table::REACTIVE_SESSION,
    },
    CanonicalSourceClass::OutsideAdmittedGeneration {
        table: crate::schema::table::RESOURCE_SNAPSHOT,
    },
    CanonicalSourceClass::OutsideAdmittedGeneration {
        table: crate::schema::table::AUTOMATION_REVISION,
    },
    CanonicalSourceClass::OutsideAdmittedGeneration {
        table: crate::schema::table::AUTOMATION_CURRENT,
    },
    CanonicalSourceClass::OutsideAdmittedGeneration {
        table: crate::schema::table::AUTOMATION_INVOCATION,
    },
    CanonicalSourceClass::OutsideAdmittedGeneration {
        table: crate::schema::table::AUTOMATION_FAILURE,
    },
    CanonicalSourceClass::OutsideAdmittedGeneration {
        table: crate::schema::table::AUTOMATION_LAST_FAILURE,
    },
    CanonicalSourceClass::OutsideAdmittedGeneration {
        table: crate::schema::table::EXPERIENCE_BANK,
    },
    CanonicalSourceClass::OutsideAdmittedGeneration {
        table: crate::schema::table::EXPERIENCE_FEEDBACK,
    },
];

/// The capture-point reads, in the exact order the pinned batches issue them:
/// the schema generation first, then the canonical fence.
pub(crate) fn capture_point_statements() -> impl Iterator<Item = &'static str> {
    CANONICAL_SOURCE_CLASSES
        .iter()
        .filter_map(|class| match class {
            CanonicalSourceClass::CapturePoint { statement, .. } => Some(*statement),
            CanonicalSourceClass::Member { .. }
            | CanonicalSourceClass::OutsideAdmittedGeneration { .. } => None,
        })
}

/// The physical tables the pinned member batch reads, in order.
pub(crate) fn captured_member_tables() -> impl Iterator<Item = &'static str> {
    CANONICAL_SOURCE_CLASSES
        .iter()
        .filter_map(|class| match class {
            CanonicalSourceClass::Member { table } => Some(*table),
            CanonicalSourceClass::CapturePoint { .. }
            | CanonicalSourceClass::OutsideAdmittedGeneration { .. } => None,
        })
}

/// Reports whether the admitted baseline generations define `table` exactly.
///
/// Both single-owner baselines are consulted so a v1 store is never read as
/// missing a table the v2 baseline added. The marker carries the trailing
/// space, so `relation_record_extra` can never satisfy `relation_record`.
fn defines_admitted_table(table: &str) -> bool {
    let marker = format!("DEFINE TABLE {table} ");
    crate::schema::SCHEMA_DDL_V2.contains(&marker) || crate::schema::SCHEMA_DDL.contains(&marker)
}

/// Walks every declared canonical source class and proves its one disposition.
///
/// Fails closed when the composition drifts from the single owner: a class
/// declared outside the admitted generation that a baseline DDL actually
/// defines would be silently dropped from the capture, and a capture point
/// whose pinned read does not name its own table would bind the wrong point.
/// Both are composition defects, not caller input, so both are refused before
/// any provider I/O instead of being absorbed into a later error.
fn verify_canonical_source_classes() -> Result<(), StoreError> {
    let mut verified = 0_usize;
    for class in CANONICAL_SOURCE_CLASSES {
        match class {
            CanonicalSourceClass::Member { table } => {
                if !defines_admitted_table(table) {
                    return Err(StoreError::InvalidField {
                        field: SNAPSHOT_CLASS_FIELD,
                        reason: "captured class is not defined by the admitted generation",
                    });
                }
            }
            CanonicalSourceClass::CapturePoint { table, statement } => {
                if !statement.contains(*table) {
                    return Err(StoreError::InvalidField {
                        field: SNAPSHOT_CLASS_FIELD,
                        reason: "capture point read does not name its own table",
                    });
                }
            }
            CanonicalSourceClass::OutsideAdmittedGeneration { table } => {
                if defines_admitted_table(table) {
                    return Err(StoreError::InvalidField {
                        field: SNAPSHOT_CLASS_FIELD,
                        reason: "declared class is defined by the admitted generation",
                    });
                }
            }
        }
        verified += 1;
    }
    // Every declared class carries exactly one disposition, so the walk always
    // covers the whole enumeration; the guard keeps that a checked property
    // rather than an assumption.
    if verified != CANONICAL_SOURCE_CLASSES.len() {
        return Err(StoreError::InvalidField {
            field: SNAPSHOT_CLASS_FIELD,
            reason: "canonical source class enumeration is not total",
        });
    }
    Ok(())
}

/// The schema-meta projection of the bound point.
#[derive(Deserialize)]
struct PointSchemaMeta {
    generation: String,
}

/// The canonical-fence projection of the bound point.
#[derive(Deserialize)]
struct PointFence {
    state_fence: StateFence,
    next_commit_sequence: u64,
    next_outbox_sequence: u64,
}

/// One frozen capture point: the exact owner-issued state a capture is bound to.
///
/// This replaces the previous bare generation string. I5.6 step 5 requires the
/// admission gate to "verify State Fence, authority and expected current
/// revisions", so every page and the end receipt re-verify the whole point: the
/// fence, both allocated sequences, and the schema generation. A generation-only
/// comparison let a committed transition between two pages pass unnoticed.
#[derive(Clone, PartialEq)]
struct CapturePoint {
    state_fence: StateFence,
    next_commit_sequence: u64,
    next_outbox_sequence: u64,
    schema_generation: String,
}

/// Frozen per-handle capture state. No `Debug` impl by design: registry
/// contents never render into logs or errors.
struct SnapshotState {
    begin: SnapshotBeginRequest,
    point: CapturePoint,
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
/// reads the whole bound capture point through the fixed adapter-owned
/// statement registered for `operation` in [`crate::client::backup_snapshot`].
///
/// `operation` must be a member of the closed `snapshot.*` vocabulary: the
/// registry is validated first, so an unlisted name can never reach the
/// provider, and the statement is resolved from the registry rather than
/// restated here. The statement takes no parameters; the binding map is empty
/// so no caller value can reach the provider. The schema generation and the
/// canonical fence are read in the one transaction, so the two halves of the
/// point are one observation.
async fn observe_capture_point(
    adapter: &SurrealStoreAdapter,
    operation: &'static str,
) -> Result<CapturePoint, StoreError> {
    let statement = crate::client::fixed_snapshot_statement(operation)
        .map_err(AdapterError::into_store_error)?;
    crate::client::validate_snapshot_operation(operation)
        .map_err(AdapterError::into_store_error)?;
    let transport = crate::apply::client(adapter)
        .await
        .map_err(AdapterError::into_store_error)?;
    crate::apply::ensure_ready(adapter, transport)
        .await
        .map_err(AdapterError::into_store_error)?;
    let mut response =
        crate::client::query(transport, &adapter.config, operation, statement, Map::new())
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
    // `SurrealDB` 3 retains the `BEGIN TRANSACTION` result at index 0, so the
    // schema-meta projection is index 1 and the canonical-fence projection
    // index 2 — the same offsets `apply::read_boundary` uses for the identical
    // batch shape.
    let meta: Option<PointSchemaMeta> = response.take(1).map_err(AdapterError::into_store_error)?;
    let fence: Option<PointFence> = response.take(2).map_err(AdapterError::into_store_error)?;
    parse_capture_point(meta, fence)
}

/// Decodes one point observation, failing closed on a blank or control-bearing
/// generation and on an absent fence. A half-observed point is never a usable
/// consistency point, so neither half is defaulted.
fn parse_capture_point(
    meta: Option<PointSchemaMeta>,
    fence: Option<PointFence>,
) -> Result<CapturePoint, StoreError> {
    let generation = meta.map(|meta| meta.generation).unwrap_or_default();
    if generation.is_empty() || generation.chars().any(char::is_control) {
        return Err(StoreError::Unavailable);
    }
    let fence = fence.ok_or(StoreError::Unavailable)?;
    fence
        .state_fence
        .validate()
        .map_err(StoreError::Foundation)?;
    Ok(CapturePoint {
        state_fence: fence.state_fence,
        next_commit_sequence: fence.next_commit_sequence,
        next_outbox_sequence: fence.next_outbox_sequence,
        schema_generation: generation,
    })
}

/// Binds the caller's claimed source identity to the admitted store identity.
///
/// I5.6 steps 2 and 5: validate the envelope and canonical request identity,
/// then verify authority and expected current state. Each mismatch is a typed
/// [`StoreError::InvalidField`] naming a static field and reason, so no caller
/// text crosses the boundary.
///
/// `source.generation` is bound to the resource generation inside the
/// owner-issued state fence that the same request carries and that the store
/// has just verified live. That is the only honest binding available: this
/// adapter owns no live resource-generation counter (`SurrealAdapterConfig`
/// holds `SchemaGeneration`, a migration version *string*, not a counter), so
/// the claim is anchored to the verified fence rather than compared against an
/// invented provider counter.
fn bind_source_identity(
    adapter: &SurrealStoreAdapter,
    point: &CapturePoint,
    request: &SnapshotBeginRequest,
) -> Result<(), StoreError> {
    let (active_store, active_installation) =
        crate::backup_restore::active_store_identity(&adapter.config);
    if request.source.installation_id != active_installation {
        return Err(StoreError::InvalidField {
            field: "snapshot.installation_id",
            reason: "source is not this installation",
        });
    }
    if request.source.store_id != active_store {
        return Err(StoreError::InvalidField {
            field: "snapshot.store_id",
            reason: "source is not the active store database",
        });
    }
    if request.source.schema != point.schema_generation {
        return Err(StoreError::InvalidField {
            field: "snapshot.schema",
            reason: "source is not the observed schema generation",
        });
    }
    if request.source.generation != request.scope.state_fence.resource_generation {
        return Err(StoreError::InvalidField {
            field: "snapshot.generation",
            reason: "source generation must match the bound state fence generation",
        });
    }
    if request.scope.state_fence != point.state_fence {
        return Err(StoreError::FenceMismatch);
    }
    Ok(())
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
    verify_canonical_source_classes()?;
    let point = observe_capture_point(adapter, SNAPSHOT_BEGIN_OPERATION).await?;
    if point.schema_generation != adapter.config.expected_schema_generation.as_str() {
        return Err(StoreError::Unavailable);
    }
    bind_source_identity(adapter, &point, &request)?;

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
        consistency_point: format!("{SNAPSHOT_CONSISTENCY_POINT_DOMAIN}:{snapshot_digest}"),
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
            point,
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
    let observed = observe_capture_point(adapter, SNAPSHOT_PAGE_OPERATION)
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
    if observed != state.point {
        // The source moved under the bound point: never mix a newer point.
        release_owned(&mut states, &digest);
        return Err(StoreError::Unavailable);
    }
    // The provider round trip is inside the capture's own duration bound, so
    // the window is re-checked after the await. Without this a slow round trip
    // served a page from a capture whose owner window had already closed.
    if is_retired(
        state.begin.expires_at_unix_ms,
        state.opened_at_ms,
        state.begin.bounds.max_duration_ms,
        crate::write_execution::current_time_ms(),
    ) {
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
    let observed = observe_capture_point(adapter, SNAPSHOT_END_OPERATION)
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
    if observed != state.point {
        release_owned(&mut states, &digest);
        return Err(StoreError::Unavailable);
    }
    // The provider round trip is inside the capture's own duration bound, so
    // the window is re-checked after the await before the receipt is issued.
    let retired = is_retired(
        state.begin.expires_at_unix_ms,
        state.opened_at_ms,
        state.begin.bounds.max_duration_ms,
        crate::write_execution::current_time_ms(),
    );
    let complete = state.members_served == state.ordered_members.len() as u64
        && state.bytes_served == state.total_bytes
        && state.pages_served == state.total_pages;
    let receipt = SnapshotEndReceipt {
        handle,
        operation: state.begin.operation.clone(),
        member_count: state.members_served,
        byte_count: state.bytes_served,
        completeness: if complete && !retired {
            SnapshotCompleteness::Complete
        } else {
            SnapshotCompleteness::Partial
        },
        validation_revision: SNAPSHOT_VALIDATION_REVISION,
    };
    receipt.validate()?;
    release_owned(&mut states, &digest);
    Ok(receipt)
}
