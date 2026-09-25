//! Coherent bounded snapshot capture over the `SurrealDB` bridge (issue #951).
//!
//! The denominator is read from the provider, never taken from the caller.
//! [`begin_snapshot`] runs the pinned member batch in one
//! `BEGIN TRANSACTION;` … `COMMIT TRANSACTION;` sequence, binds the point that
//! batch observed (schema generation, canonical fence, both allocated
//! sequences) after the readiness/generation/fence/source-identity gate,
//! reconciles the caller's declared denominator against the observed set as a
//! claim to be verified, and freezes the served set, totals, bounds and expiry.
//! [`read_snapshot_page`] and [`end_snapshot`] re-verify the whole point on
//! every call, before and after the provider await.
//!
//! One release discipline: [`CaptureRelease`] releases exactly the capture-owned
//! entry on every exit path of a page or end call, including a future dropped
//! while the provider await is in flight. The registry map is never cleared
//! wholesale. A capture that stopped being servable — window closed, point
//! moved, page bound reached, set exhausted — records its exact partial
//! evidence with [`mark_interruption`] and keeps its entry, so
//! [`end_snapshot`] issues a real `Partial`/`Expired` receipt carrying the
//! exact served counts instead of deleting the only record of what was served.
//!
//! Reads only: this module never acquires `adapter.write_lock`, issues no
//! DDL/migration, performs no restore, and defines no archive format. Every
//! provider statement is a fixed adapter-owned `&'static str` composed from the
//! single-owner consts in [`crate::schema`]; no snapshot statement carries a
//! binding, so no caller value can reach the provider, and errors/receipts carry
//! digests and static text, never provider payload or credentials.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Mutex, OnceLock};

use eliot_store_api::{
    BlobResidency, BlobResidencyDomain, MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_MEMBERS,
    MAX_SNAPSHOT_PAGE_MEMBERS, MAX_SNAPSHOT_PAGES, RequestMeta, SnapshotBeginRequest,
    SnapshotCompleteness, SnapshotCursor, SnapshotDenominator, SnapshotEndReceipt, SnapshotHandle,
    SnapshotMember, SnapshotMemberType, SnapshotPage, StateFence, StoreError, canonical_json_bytes,
    sha256_hex,
};
use serde::Deserialize;
use serde_json::{Map, Value};

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

/// Bounded static text for a canonical serialization failure inside this
/// module. A provider or serde message never crosses the boundary (I5.1: the
/// bridge "returns receipts and exact errors").
const SNAPSHOT_SERIALIZATION_REASON: &str = "canonical snapshot serialization failed";

/// Maps a canonical serialization failure to bounded static text.
fn snapshot_serialization_error(_error: serde_json::Error) -> StoreError {
    StoreError::Serialization(SNAPSHOT_SERIALIZATION_REASON.to_owned())
}

/// Redacts a store error so no record, query or credential prose crosses.
///
/// Follows the `crate::backup_restore::redact_store_error` pattern: the only
/// variant that can carry foreign text is replaced with bounded static text,
/// and every typed variant — whose fields are already static or bounded digests
/// — passes through unchanged, so no typed failure is collapsed.
fn redact_snapshot_error(error: StoreError) -> StoreError {
    match error {
        StoreError::Serialization(_) => {
            StoreError::Serialization(SNAPSHOT_SERIALIZATION_REASON.to_owned())
        }
        other => other,
    }
}

/// Runs the pinned statement for `operation` and redacts the failure it returns.
///
/// The statement is resolved from the closed registry and the operation is
/// validated against it first, so an unlisted name never reaches the provider.
async fn run_pinned_snapshot_query(
    adapter: &SurrealStoreAdapter,
    operation: &'static str,
) -> Result<crate::client::RpcResults, StoreError> {
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
    crate::client::query(transport, &adapter.config, operation, statement, Map::new())
        .await
        .map_err(AdapterError::into_store_error)
        .map_err(redact_snapshot_error)
}

/// Domain separator for the owner-issued consistency point.
///
/// I5.27 binds canonical identity over a domain separator, so a capture handle
/// can never be confused with another capability's evidence. The separator is
/// the public capability this fixed registry implements, owned by
/// `eliot-store-api` and surfaced by the registry.
const SNAPSHOT_CONSISTENCY_POINT_DOMAIN: &str = crate::client::snapshot_capability();

/// Canonical encoding version of the owner-issued consistency point.
///
/// I5.27: "Canonical encoding is deterministic and versioned; fields affecting
/// authority, scope, ordering, privacy or effect cannot be omitted/defaulted
/// silently." A bare `snapshot-point:<digest>` token carried no encoding
/// version, so a reader could not tell which encoding produced it.
const SNAPSHOT_CONSISTENCY_POINT_VERSION: &str = "eliot.snapshot.consistency-point.v1";

/// Builds the versioned, domain-separated owner-issued consistency point.
///
/// The token binds the encoding version, the capability that owns the capture
/// as its domain separator, and the exact begin-request digest.
fn consistency_point(snapshot_digest: &str) -> String {
    format!(
        "{SNAPSHOT_CONSISTENCY_POINT_VERSION}:{SNAPSHOT_CONSISTENCY_POINT_DOMAIN}:{snapshot_digest}"
    )
}

/// Versioned canonical encoding of the member identity and ordering shape.
///
/// I5.27: "Canonical encoding is deterministic and versioned; fields affecting
/// authority, scope, ordering, privacy or effect cannot be omitted/defaulted
/// silently." A member identity is therefore `<version>:<class token>:<versioned
/// residency domain>:<digest of the row's own key fields>` — never a derived
/// `Debug` rendering and never a caller string.
const MEMBER_ID_VERSION: &str = "eliot.snapshot.member.v1";

/// Versioned canonical token for one blob-residency domain.
///
/// I5.2 and `crates/storage/AGENTS.md`: "deduplication never crosses
/// privacy/retention/erasure domains by digest alone". The domain token, not a
/// derived rendering, is what orders and identifies members, so equal bytes in
/// two domains never collapse onto one identity.
const fn domain_key(domain: BlobResidencyDomain) -> &'static str {
    match domain {
        BlobResidencyDomain::InlineCanonical => "inline-canonical.v1",
        BlobResidencyDomain::ContentBlob => "content-blob.v1",
        BlobResidencyDomain::ExternalReference => "external-reference.v1",
    }
}

/// How one captured class points at another captured class.
///
/// A typed edge is only a `SnapshotMemberType::Reference` member when its
/// target is resolvable inside the same observed capture; an unresolvable edge
/// is refused, never reported as an omitted table.
pub(crate) struct MemberReference {
    /// Row field naming the target record's key.
    key_field: &'static str,
    /// Physical table of the target class, owned by [`crate::schema`].
    target_table: &'static str,
}

/// The captured shape of one admitted canonical source class.
///
/// The residency domain comes from the physical origin of the row, never from
/// its content: an inline canonical row is `InlineCanonical`, a row carrying
/// verbatim captured bytes is `ContentBlob`, and a typed edge row is
/// `ExternalReference`.
pub(crate) struct MemberClass {
    /// Versioned canonical class token.
    token: &'static str,
    /// Physical table name owned by [`crate::schema`].
    table: &'static str,
    /// Member type this class contributes.
    member_type: SnapshotMemberType,
    /// Residency domain implied by the physical origin of the class.
    domain: BlobResidencyDomain,
    /// Row key fields that name this record, read from the row itself.
    key_fields: &'static [&'static str],
    /// Store-owned content-digest column carried forward as the member
    /// residency digest. Never recomputed here: this crate is not a
    /// Blob-root owner, so no residency digest can be re-derived.
    digest_field: Option<&'static str>,
    /// The typed edge this class contributes, when it is a reference.
    reference: Option<MemberReference>,
}

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
    Member(MemberClass),
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
///
/// A13.7: "A backup includes canonical state, referenced immutable artifacts,
/// policy and configuration snapshots, required pending operational state,
/// purge ledger, Architecture revision digest, manifest, and checksums." This
/// enumeration is the bounded-surreal-adapter's share of that list: the nine
/// admitted canonical tables, the two point singletons, and the twelve classes
/// the admitted generation does not define.
pub(crate) const CANONICAL_SOURCE_CLASSES: &[CanonicalSourceClass] = &[
    CanonicalSourceClass::CapturePoint {
        table: crate::schema::table::SCHEMA_META,
        statement: crate::schema::READ_SCHEMA_META,
    },
    CanonicalSourceClass::Member(MemberClass {
        token: "write-receipt",
        table: crate::schema::table::WRITE_RECEIPT,
        member_type: SnapshotMemberType::Record,
        domain: BlobResidencyDomain::InlineCanonical,
        key_fields: &["operation_id"],
        digest_field: None,
        reference: None,
    }),
    CanonicalSourceClass::Member(MemberClass {
        token: "revision-head",
        table: crate::schema::table::REVISION_HEAD,
        member_type: SnapshotMemberType::Record,
        domain: BlobResidencyDomain::InlineCanonical,
        key_fields: &["revision_key"],
        digest_field: None,
        reference: None,
    }),
    CanonicalSourceClass::Member(MemberClass {
        token: "ordering-head",
        table: crate::schema::table::ORDERING_HEAD,
        member_type: SnapshotMemberType::Record,
        domain: BlobResidencyDomain::InlineCanonical,
        key_fields: &["ordering_scope"],
        digest_field: None,
        reference: None,
    }),
    CanonicalSourceClass::Member(MemberClass {
        token: "canonical-event",
        table: crate::schema::table::CANONICAL_EVENT,
        member_type: SnapshotMemberType::Record,
        domain: BlobResidencyDomain::InlineCanonical,
        key_fields: &["event_id"],
        digest_field: None,
        reference: None,
    }),
    CanonicalSourceClass::Member(MemberClass {
        token: "projection-record",
        table: crate::schema::table::PROJECTION_RECORD,
        member_type: SnapshotMemberType::Record,
        domain: BlobResidencyDomain::InlineCanonical,
        key_fields: &["publication_id"],
        digest_field: None,
        reference: None,
    }),
    // A typed relation row is an edge into another canonical record: the edge
    // carries no inline payload of its own and its target is named by the
    // immutable commit that created it.
    CanonicalSourceClass::Member(MemberClass {
        token: "relation-record",
        table: crate::schema::table::RELATION_RECORD,
        member_type: SnapshotMemberType::Reference,
        domain: BlobResidencyDomain::ExternalReference,
        key_fields: &["relation_id"],
        digest_field: None,
        reference: Some(MemberReference {
            key_field: "operation_id",
            target_table: crate::schema::table::WRITE_RECEIPT,
        }),
    }),
    CanonicalSourceClass::Member(MemberClass {
        token: "outbox-event",
        table: crate::schema::table::OUTBOX_EVENT,
        member_type: SnapshotMemberType::Record,
        domain: BlobResidencyDomain::InlineCanonical,
        key_fields: &["outbox_id"],
        digest_field: None,
        reference: None,
    }),
    // The operational-recovery rows hold an opaque locator or immutable
    // payload bytes plus the store-owned value digest, so the digest is
    // carried forward rather than recomputed.
    CanonicalSourceClass::Member(MemberClass {
        token: "recovery-owner",
        table: crate::schema::table::RECOVERY_OWNER,
        member_type: SnapshotMemberType::Record,
        domain: BlobResidencyDomain::InlineCanonical,
        key_fields: &["namespace", "key"],
        digest_field: Some("value_digest"),
        reference: None,
    }),
    CanonicalSourceClass::Member(MemberClass {
        token: "recovery-job",
        table: crate::schema::table::RECOVERY_JOB,
        member_type: SnapshotMemberType::Record,
        domain: BlobResidencyDomain::InlineCanonical,
        key_fields: &["namespace", "key"],
        digest_field: Some("value_digest"),
        reference: None,
    }),
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
            CanonicalSourceClass::Member(_)
            | CanonicalSourceClass::OutsideAdmittedGeneration { .. } => None,
        })
}

/// The physical tables the pinned member batch reads, in order.
pub(crate) fn captured_member_tables() -> impl Iterator<Item = &'static str> {
    captured_member_classes().map(|member| member.table)
}

/// The captured classes, in the exact order the pinned member batch reads them.
fn captured_member_classes() -> impl Iterator<Item = &'static MemberClass> {
    CANONICAL_SOURCE_CLASSES
        .iter()
        .filter_map(|class| match class {
            CanonicalSourceClass::Member(member) => Some(member),
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
            CanonicalSourceClass::Member(member) => {
                if !defines_admitted_table(member.table) {
                    return Err(StoreError::InvalidField {
                        field: SNAPSHOT_CLASS_FIELD,
                        reason: "captured class is not defined by the admitted generation",
                    });
                }
                // A typed edge is a `Reference` member exactly when it declares
                // a resolvable target inside the admitted generation, so a
                // member type can never disagree with its reference shape.
                if member.reference.is_some()
                    != (member.member_type == SnapshotMemberType::Reference)
                {
                    return Err(StoreError::InvalidField {
                        field: SNAPSHOT_CLASS_FIELD,
                        reason: "reference class and member type disagree",
                    });
                }
                if let Some(reference) = &member.reference
                    && !defines_admitted_table(reference.target_table)
                {
                    return Err(StoreError::InvalidField {
                        field: SNAPSHOT_CLASS_FIELD,
                        reason: "reference target is not defined by the admitted generation",
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
    /// Proof that the canonical enumeration ran. `None` means the denominator
    /// is not proven, so the only legal completeness is partial.
    enumeration: Option<EnumerationEvidence>,
    /// Exact partial evidence recorded when the capture stopped being
    /// servable. Never deleted: it is the receipt's `Partial`/`Expired`
    /// provenance.
    interruption: Option<CaptureInterruption>,
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
    let mut response = run_pinned_snapshot_query(adapter, operation).await?;
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
    let meta: Option<PointSchemaMeta> = response
        .take(1)
        .map_err(AdapterError::into_store_error)
        .map_err(redact_snapshot_error)?;
    let fence: Option<PointFence> = response
        .take(2)
        .map_err(AdapterError::into_store_error)
        .map_err(redact_snapshot_error)?;
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

/// One observed canonical enumeration at a single bound point.
struct Enumeration {
    /// The point the members were observed at, from the same transaction.
    point: CapturePoint,
    /// Proof that the canonical enumeration actually ran.
    evidence: EnumerationEvidence,
    /// Members in versioned logical order.
    members: Vec<SnapshotMember>,
}

/// Proof that the canonical enumeration actually ran over every admitted
/// canonical class.
#[derive(Clone, Copy)]
struct EnumerationEvidence {
    /// Admitted canonical classes the pinned member batch returned.
    classes_read: usize,
    /// Canonical rows the pinned member batch returned across those classes.
    members_read: usize,
}

impl EnumerationEvidence {
    /// Reports whether this observation is an authoritative known-zero
    /// denominator.
    ///
    /// A13.7 and `SnapshotValidationReceipt::validate`: a known-zero count
    /// requires a complete authoritative denominator. Here that means the pinned
    /// member batch read every admitted canonical class and every one of them
    /// returned zero rows — never "nothing was found" inferred from a
    /// denominator the caller declared empty.
    fn is_authoritative_zero(self) -> bool {
        self.members_read == 0 && self.classes_read == captured_member_classes().count()
    }
}

/// Runs the pinned member batch and returns the point plus every class's rows.
///
/// The point is re-read inside the same transaction as the members, so the
/// denominator this binds is observed at exactly the fence the capture claims.
/// Result offsets are fixed: 0 is the retained `BEGIN TRANSACTION` result, 1 the
/// schema generation, 2 the canonical fence, then one whole-record array per
/// captured class in declaration order.
async fn read_enumeration(
    adapter: &SurrealStoreAdapter,
) -> Result<(CapturePoint, Vec<Vec<Map<String, Value>>>), StoreError> {
    let mut response =
        run_pinned_snapshot_query(adapter, crate::client::SNAPSHOT_MEMBERS_OPERATION).await?;
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
    let meta: Option<PointSchemaMeta> = response
        .take(1)
        .map_err(AdapterError::into_store_error)
        .map_err(redact_snapshot_error)?;
    let fence: Option<PointFence> = response
        .take(2)
        .map_err(AdapterError::into_store_error)
        .map_err(redact_snapshot_error)?;
    let point = parse_capture_point(meta, fence)?;
    let mut rows = Vec::new();
    for offset in 0..captured_member_classes().count() {
        let offset = offset + 3;
        let class_rows: Vec<Map<String, Value>> = response
            .take(offset)
            .map_err(AdapterError::into_store_error)
            .map_err(redact_snapshot_error)?;
        rows.push(class_rows);
    }
    Ok((point, rows))
}

/// Digest of the exact canonical bytes of one observed row.
fn row_content_digest(row: &Map<String, Value>) -> Result<String, StoreError> {
    let bytes = canonical_json_bytes(row).map_err(snapshot_serialization_error)?;
    Ok(sha256_hex(&bytes))
}

/// The versioned, domain-qualified member identity of one observed row.
///
/// The digest covers only the row's own key fields, so identity is stable under
/// unrelated column changes while still being constructed from the row rather
/// than from any caller string.
fn row_member_id(class: &MemberClass, row: &Map<String, Value>) -> Result<String, StoreError> {
    let mut key = Map::new();
    for field in class.key_fields {
        let value = row.get(*field).ok_or(StoreError::InvalidField {
            field: "snapshot.member_id",
            reason: "captured row does not carry its declared key field",
        })?;
        if !value.is_string() {
            return Err(StoreError::InvalidField {
                field: "snapshot.member_id",
                reason: "captured row key field is not store-owned text",
            });
        }
        key.insert((*field).to_owned(), value.clone());
    }
    let key_digest = sha256_hex(&canonical_json_bytes(&key).map_err(snapshot_serialization_error)?);
    Ok(format!(
        "{MEMBER_ID_VERSION}:{}:{}:{key_digest}",
        class.token,
        domain_key(class.domain),
    ))
}

/// The joined key of one observed row under its own class.
fn row_joined_key(class: &MemberClass, row: &Map<String, Value>) -> Result<String, StoreError> {
    let mut parts = Vec::with_capacity(class.key_fields.len());
    for field in class.key_fields {
        parts.push(
            row.get(*field)
                .and_then(Value::as_str)
                .ok_or(StoreError::InvalidField {
                    field: "snapshot.member_id",
                    reason: "captured row does not carry its declared key field",
                })?,
        );
    }
    Ok(parts.join("\u{1f}"))
}

/// The store-owned content digest carried forward as the residency digest.
///
/// A13.7 and `crates/storage/AGENTS.md`: a Blob residency digest cannot be
/// re-derived here (this crate is not a Blob-root owner), so the store's own
/// digest column is carried forward opaquely and the digest of the exact
/// captured canonical bytes is the fallback. The residency *domain* — never the
/// digest — is what keeps same-content-different-domain members distinct.
fn row_residency_digest(
    class: &MemberClass,
    row: &Map<String, Value>,
    content_digest: &str,
) -> String {
    class
        .digest_field
        .and_then(|field| row.get(field))
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value))
        .unwrap_or(content_digest)
        .to_owned()
}

/// Reports whether `value` is a lowercase hexadecimal SHA-256 digest.
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Maps one observed row of one captured class to its snapshot member.
fn member_for_row(
    class: &MemberClass,
    row: &Map<String, Value>,
) -> Result<SnapshotMember, StoreError> {
    let content_digest = row_content_digest(row)?;
    let member_id = row_member_id(class, row)?;
    let residency_digest = row_residency_digest(class, row, &content_digest);
    let bytes = canonical_json_bytes(row).map_err(snapshot_serialization_error)?;
    let byte_count = u64::try_from(bytes.len())
        .map_err(|_| StoreError::PayloadTooLarge)?
        .max(1);
    Ok(SnapshotMember {
        member_id,
        member_type: class.member_type,
        content_digest,
        residency: BlobResidency {
            domain: class.domain,
            residency_digest,
            byte_count,
        },
        reference_digest: None,
    })
}

/// Enumerates every admitted canonical source class at one bound point.
///
/// This is the provider-read denominator: the caller's declared denominator is
/// a claim checked against this set, never the source of the counts, the page
/// count or the served ordering. Members are returned in versioned logical
/// order — class token, then versioned residency domain, then member identity —
/// so ordering never depends on incidental provider row order (I5.27).
async fn enumerate_canonical_members(
    adapter: &SurrealStoreAdapter,
) -> Result<Enumeration, StoreError> {
    let (point, class_rows) = read_enumeration(adapter).await?;
    let rows_by_key = observed_row_keys(&class_rows)?;
    let mut members = resolve_member_references(&class_rows, &rows_by_key)?;
    members.sort_by(|left, right| {
        (left.0, left.1, left.2.member_id.as_str()).cmp(&(
            right.0,
            right.1,
            right.2.member_id.as_str(),
        ))
    });
    let members = members
        .into_iter()
        .map(|(_, _, member)| member)
        .collect::<Vec<_>>();
    validate_reference_closure(&members)?;
    let evidence = EnumerationEvidence {
        classes_read: class_rows.len(),
        members_read: members.len(),
    };
    Ok(Enumeration {
        point,
        evidence,
        members,
    })
}

/// Indexes every observed row by its own class table and joined key.
///
/// A row whose key cannot be read is a fail-closed enumeration failure, never a
/// silent entry with a defaulted digest: a defaulted key would let a typed edge
/// resolve to the wrong member.
fn observed_row_keys(
    class_rows: &[Vec<Map<String, Value>>],
) -> Result<BTreeMap<(&'static str, String), String>, StoreError> {
    let mut keys = BTreeMap::new();
    for (class, rows) in captured_member_classes().zip(class_rows) {
        for row in rows {
            keys.insert(
                (class.table, row_joined_key(class, row)?),
                row_content_digest(row)?,
            );
        }
    }
    Ok(keys)
}

/// Builds every member and resolves each typed edge against the observed set.
///
/// An edge whose target is absent from the observed capture is refused with an
/// exact typed failure. A13.7 / ARCH-RES-03: recovery cannot resurrect invalid
/// state, so a dangling edge is never reported as a broad "omitted table"
/// exclusion.
fn resolve_member_references(
    class_rows: &[Vec<Map<String, Value>>],
    rows_by_key: &BTreeMap<(&'static str, String), String>,
) -> Result<Vec<(&'static str, &'static str, SnapshotMember)>, StoreError> {
    let mut members = Vec::new();
    for (class, rows) in captured_member_classes().zip(class_rows) {
        for row in rows {
            let member = member_for_row(class, row)?;
            let reference = match &class.reference {
                None => None,
                Some(reference) => {
                    let target_key = row
                        .get(reference.key_field)
                        .and_then(Value::as_str)
                        .ok_or(StoreError::InvalidField {
                            field: "snapshot.reference_digest",
                            reason: "typed edge does not name its target key",
                        })?
                        .to_owned();
                    let digest = rows_by_key
                        .get(&(reference.target_table, target_key))
                        .ok_or(StoreError::InvalidField {
                            field: "snapshot.reference_digest",
                            reason: "typed edge target is not in the observed capture",
                        })?;
                    Some(digest.clone())
                }
            };
            let mut member = member;
            member.reference_digest = reference;
            member.validate()?;
            members.push((class.token, domain_key(class.domain), member));
        }
    }
    Ok(members)
}

/// Validates the canonical reference closure of one observed member set.
///
/// The snapshot analogue of `crate::backup_restore::validate_reference_closure`:
/// every `SnapshotMemberType::Reference` member must name the exact
/// `content_digest` of another member in the same capture. This is an
/// independent re-proof over a different observation than the enumeration used
/// (the key index), so a member set that lost its target still fails closed.
fn validate_reference_closure(members: &[SnapshotMember]) -> Result<(), StoreError> {
    let present: BTreeSet<&str> = members
        .iter()
        .map(|member| member.content_digest.as_str())
        .collect();
    for member in members {
        if member.member_type != SnapshotMemberType::Reference {
            continue;
        }
        let Some(reference) = member.reference_digest.as_deref() else {
            return Err(StoreError::InvalidField {
                field: "snapshot.reference_digest",
                reason: "reference member requires a reference digest",
            });
        };
        if !present.contains(reference) || reference == member.content_digest {
            return Err(StoreError::IdentityConflict);
        }
    }
    Ok(())
}

/// Reconciles the caller's claimed denominator against the observed member set.
///
/// The claimed denominator is evidence, not truth: a missing, extra, duplicated
/// or conflicting member refuses the capture instead of being absorbed into the
/// served accounting.
fn reconcile_denominator(
    observed: &[SnapshotMember],
    claimed: &SnapshotDenominator,
) -> Result<(), StoreError> {
    let mut by_id: BTreeMap<&str, &SnapshotMember> = BTreeMap::new();
    for member in observed {
        if by_id.insert(member.member_id.as_str(), member).is_some() {
            return Err(StoreError::Duplicate {
                field: "snapshot.members",
            });
        }
    }
    for claim in &claimed.members {
        match by_id.get(claim.member_id.as_str()) {
            None => {
                return Err(StoreError::InvalidField {
                    field: "snapshot.members",
                    reason: "claimed member is absent from the observed capture",
                });
            }
            Some(member) if *member == claim => {}
            Some(_) => return Err(StoreError::IdentityConflict),
        }
    }
    let claimed_ids: BTreeSet<&str> = claimed
        .members
        .iter()
        .map(|member| member.member_id.as_str())
        .collect();
    for member in observed {
        if !claimed_ids.contains(member.member_id.as_str()) {
            return Err(StoreError::InvalidField {
                field: "snapshot.members",
                reason: "observed member is absent from the claimed denominator",
            });
        }
    }
    Ok(())
}

/// Exact partial evidence for a capture that can no longer serve.
///
/// A13.7 and ARCH-RES-03: recovery cannot resurrect invalid state, and a
/// capture that stopped half way is exactly the state an operator must be able
/// to see. The evidence is recorded on the capture instead of being deleted, so
/// `end_snapshot` can issue an exact `Partial`/`Expired` receipt carrying the
/// real served counts.
struct CaptureInterruption {
    /// Static reason the capture stopped being servable.
    reason: &'static str,
    /// Pages served before the interruption.
    pages_served: u64,
    /// Members served before the interruption.
    members_served: u64,
    /// Bytes served before the interruption.
    bytes_served: u64,
}

/// The owner-issued window or duration bound closed under the capture.
const INTERRUPTION_WINDOW_CLOSED: &str = "owner capture window closed";
/// The bound consistency point moved because the canonical store advanced.
const INTERRUPTION_POINT_MOVED: &str = "bound consistency point moved";
/// The per-request page bound was reached before the observed set was served.
const INTERRUPTION_PAGE_BOUND: &str = "served page bound exceeded";
/// The observed member set has no further page to serve.
const INTERRUPTION_CAPTURE_EXHAUSTED: &str = "no further page is available";

/// Records the exact partial evidence on the capture-owned entry.
///
/// The entry is deliberately kept: the entry is the only place the served
/// counters still exist, and deleting it is what previously destroyed the exact
/// partial evidence on both the page and the end path.
fn mark_interruption(
    states: &mut HashMap<String, SnapshotState>,
    digest: &str,
    reason: &'static str,
) {
    if let Some(state) = states.get_mut(digest) {
        state.interruption = Some(CaptureInterruption {
            reason,
            pages_served: state.pages_served,
            members_served: state.members_served,
            bytes_served: state.bytes_served,
        });
    }
}

/// Releases exactly the capture-owned entry on every exit path of a page or end
/// call, including a future dropped while the provider await is in flight.
///
/// This replaces the three inconsistent release sites. The crate has no
/// `CancellationToken` and no `tokio::select!`, so a dropped future is the only
/// observable cancellation; the guard's `Drop` runs on that path too. It takes
/// the registry lock only for the removal, never across an await (I5.7), and it
/// closes only capture-owned state: `client::session_pool` returns a pooled slot
/// on `Drop` without poisoning it, so an in-flight response is possible and the
/// capture entry is released regardless of any slot health assumption.
struct CaptureRelease {
    digest: String,
    armed: bool,
}

impl CaptureRelease {
    /// Arms release for the capture named by `digest`.
    fn arm(digest: String) -> Self {
        Self {
            digest,
            armed: true,
        }
    }

    /// Keeps the capture-owned entry because the capture is still live and the
    /// exact partial evidence must survive for a later `end_snapshot`.
    fn retain(&mut self) {
        self.armed = false;
    }
}

impl Drop for CaptureRelease {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut states) = registry().lock() {
            release_owned(&mut states, &self.digest);
        }
    }
}

/// The typed refusal for a handle that names no open capture.
fn unknown_snapshot_handle() -> StoreError {
    StoreError::InvalidField {
        field: "snapshot.snapshot_digest",
        reason: "unknown snapshot handle",
    }
}

/// Reports whether a capture can no longer serve at `now_ms`.
fn capture_is_retired(state: &SnapshotState, now_ms: u64) -> bool {
    is_retired(
        state.begin.expires_at_unix_ms,
        state.opened_at_ms,
        state.begin.bounds.max_duration_ms,
        now_ms,
    )
}

/// Drops every entry whose owner-issued window has passed, except `keep`.
///
/// Scoped cleanup only; live entries and the requested capture are never
/// touched, so a closed window can still be answered with an exact receipt.
fn purge_expired_except(states: &mut HashMap<String, SnapshotState>, now_ms: u64, keep: &str) {
    states.retain(|digest, state| digest == keep || !capture_is_retired(state, now_ms));
}

/// Reports whether one capture proved the complete authoritative denominator
/// and served all of it.
///
/// A complete capture requires the caller's declared completeness, a canonical
/// enumeration that actually ran, an authoritative known-zero when nothing was
/// observed, and exact served accounting. If the enumeration never ran, the
/// only legal completeness is partial — `SnapshotValidationReceipt::validate`
/// requires a complete authoritative denominator for a known-zero count.
fn is_complete_capture(state: &SnapshotState) -> bool {
    let enumeration_ran = state.enumeration.is_some();
    let known_zero = state
        .enumeration
        .is_some_and(EnumerationEvidence::is_authoritative_zero);
    state.begin.denominator.is_complete
        && enumeration_ran
        && state.ordered_members.is_empty() == known_zero
        && state.members_served == state.ordered_members.len() as u64
        && state.bytes_served == state.total_bytes
        && state.pages_served == state.total_pages
}

/// The exact completeness and served accounting of one closing capture.
///
/// When an interruption was recorded, the frozen counts it carries are the
/// receipt's counts. No page can be served once a capture stopped being
/// servable, so the interruption record is the authoritative partial evidence
/// rather than a second copy of the live counters, and any disagreement between
/// the two is a genuine receipt defect.
fn closing_accounting(
    state: &SnapshotState,
    expired: bool,
    moved: bool,
) -> Result<(SnapshotCompleteness, u64, u64), StoreError> {
    let (members_served, bytes_served) = match &state.interruption {
        None => (state.members_served, state.bytes_served),
        Some(interruption) => {
            if interruption.pages_served > state.total_pages
                || interruption.members_served != state.members_served
                || interruption.bytes_served != state.bytes_served
            {
                return Err(StoreError::InvalidReceipt);
            }
            (interruption.members_served, interruption.bytes_served)
        }
    };
    let window_closed = expired
        || state
            .interruption
            .as_ref()
            .is_some_and(|interruption| interruption.reason == INTERRUPTION_WINDOW_CLOSED);
    let completeness = if window_closed {
        SnapshotCompleteness::Expired
    } else if moved || state.interruption.is_some() {
        SnapshotCompleteness::Partial
    } else if is_complete_capture(state) {
        SnapshotCompleteness::Complete
    } else {
        SnapshotCompleteness::Partial
    };
    Ok((completeness, members_served, bytes_served))
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
    request.validate().map_err(redact_snapshot_error)?;
    if ctx.state_fence != request.scope.state_fence {
        return Err(StoreError::FenceMismatch);
    }
    verify_canonical_source_classes()?;
    // The denominator is read from the provider, in one coherent transaction
    // with the point it claims, and the claimed denominator is reconciled
    // against it. The caller never supplies the served set.
    let enumeration = enumerate_canonical_members(adapter).await?;
    let point = enumeration.point;
    if point.schema_generation != adapter.config.expected_schema_generation.as_str() {
        return Err(StoreError::Unavailable);
    }
    bind_source_identity(adapter, &point, &request)?;
    let ordered_members = enumeration.members;
    let evidence = enumeration.evidence;
    reconcile_denominator(&ordered_members, &request.denominator)?;
    // An empty observed set is only a bindable denominator when the
    // enumeration actually read every admitted canonical class and found
    // nothing. A declared-empty denominator with no provider evidence is not a
    // zero-member capture; it is refused.
    if ordered_members.is_empty() && !evidence.is_authoritative_zero() {
        return Err(StoreError::Empty {
            field: "snapshot.members",
        });
    }

    let snapshot_digest = request.compute_digest().map_err(redact_snapshot_error)?;

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
        consistency_point: consistency_point(&snapshot_digest),
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
            enumeration: Some(evidence),
            interruption: None,
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
        // The observed set is exhausted. The exact partial evidence is recorded
        // instead of being deleted, so a closing receipt can still state what
        // was served.
        mark_interruption(states, digest, INTERRUPTION_CAPTURE_EXHAUSTED);
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
        mark_interruption(states, digest, INTERRUPTION_PAGE_BOUND);
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
    page.validate_for_begin(&state.begin)
        .map_err(redact_snapshot_error)?;
    let page_digest =
        sha256_hex(&canonical_json_bytes(&page).map_err(snapshot_serialization_error)?);
    state.pages_served = state.pages_served.saturating_add(1);
    state.members_served = cumulative_members;
    state.bytes_served = cumulative_bytes;
    state.last_digest = page_digest;
    Ok(page)
}

/// Validates one page request against the live capture without any provider
/// I/O. Runs under the registry lock with no awaits inside.
///
/// When the capture can no longer serve, the exact partial evidence is recorded
/// and the entry deliberately retained, so a later `end_snapshot` can still
/// issue an honest `Expired` or `Partial` receipt instead of deleting the only
/// record of what was served.
fn prepare_page(
    states: &mut HashMap<String, SnapshotState>,
    digest: &str,
    ctx: &RequestMeta,
    cursor: &SnapshotCursor,
    now_ms: u64,
) -> Result<(), StoreError> {
    purge_expired_except(states, now_ms, digest);
    let Some(state) = states.get(digest) else {
        return Err(unknown_snapshot_handle());
    };
    let retired = capture_is_retired(state, now_ms);
    let next_page = state.pages_served.saturating_add(1);
    let over_page_bound =
        next_page > state.begin.bounds.max_pages || next_page > MAX_SNAPSHOT_PAGES;
    let known_empty = state.ordered_members.is_empty();
    if retired {
        mark_interruption(states, digest, INTERRUPTION_WINDOW_CLOSED);
        return Err(StoreError::Unavailable);
    }
    if ctx.state_fence != state.begin.scope.state_fence {
        return Err(StoreError::FenceMismatch);
    }
    check_cursor(state, cursor)?;
    if known_empty {
        // Authoritatively known-empty capture: explicit typed refusal, never a
        // silent or fabricated page. Close via `end_snapshot` for the complete
        // zero-member accounting path.
        return Err(StoreError::Empty {
            field: "snapshot.members",
        });
    }
    if over_page_bound {
        mark_interruption(states, digest, INTERRUPTION_PAGE_BOUND);
        return Err(StoreError::PayloadTooLarge);
    }
    Ok(())
}

/// Re-verifies the bound point after the provider await and serves the page, or
/// records the exact partial evidence that ends the capture.
fn finish_page(
    digest: &str,
    observed: &CapturePoint,
    handle: SnapshotHandle,
    cursor: SnapshotCursor,
    guard: &mut CaptureRelease,
) -> Result<SnapshotPage, StoreError> {
    let mut states = lock_registry()?;
    let (moved, retired) = {
        let state = states.get(digest).ok_or_else(unknown_snapshot_handle)?;
        (
            observed != &state.point,
            capture_is_retired(state, crate::write_execution::current_time_ms()),
        )
    };
    if moved {
        // The source moved under the bound point: never mix a newer point, and
        // keep the exact partial evidence for the closing receipt.
        mark_interruption(&mut states, digest, INTERRUPTION_POINT_MOVED);
        return Err(StoreError::Unavailable);
    }
    if retired {
        mark_interruption(&mut states, digest, INTERRUPTION_WINDOW_CLOSED);
        return Err(StoreError::Unavailable);
    }
    // The point still holds and the capture is still live: keep the entry so
    // the capture can continue and close with a receipt.
    guard.retain();
    let state = states.get(digest).ok_or_else(unknown_snapshot_handle)?;
    check_cursor(state, &cursor)?;
    serve_next_page(&mut states, digest, handle, cursor)
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
    {
        let mut states = lock_registry()?;
        prepare_page(
            &mut states,
            &digest,
            ctx,
            &cursor,
            crate::write_execution::current_time_ms(),
        )?;
    }
    // No registry lock is held across this provider await (I5.7). The guard
    // releases exactly the capture-owned entry on every exit path of this call,
    // including a future dropped while the await is in flight.
    let mut guard = CaptureRelease::arm(digest.clone());
    let observed = observe_capture_point(adapter, SNAPSHOT_PAGE_OPERATION).await?;
    finish_page(&digest, &observed, handle, cursor, &mut guard)
}

/// Builds and validates the closing receipt, then releases the capture entry.
///
/// `observed` is `None` when the owner window had already closed: the point is
/// then deliberately not re-read, because a receipt must not claim the source
/// stayed still across a window this store no longer vouches for.
fn close_capture(
    digest: &str,
    observed: Option<&CapturePoint>,
    handle: SnapshotHandle,
) -> Result<SnapshotEndReceipt, StoreError> {
    let mut states = lock_registry()?;
    let (expired, moved) = {
        let state = states.get(digest).ok_or_else(unknown_snapshot_handle)?;
        (
            observed.is_none()
                || capture_is_retired(state, crate::write_execution::current_time_ms()),
            observed.is_some_and(|point| point != &state.point),
        )
    };
    if expired {
        mark_interruption(&mut states, digest, INTERRUPTION_WINDOW_CLOSED);
    } else if moved {
        mark_interruption(&mut states, digest, INTERRUPTION_POINT_MOVED);
    }
    let receipt = {
        let state = states.get(digest).ok_or_else(unknown_snapshot_handle)?;
        let (completeness, members_served, bytes_served) =
            closing_accounting(state, expired, moved)?;
        SnapshotEndReceipt {
            handle,
            operation: state.begin.operation.clone(),
            member_count: members_served,
            byte_count: bytes_served,
            completeness,
            validation_revision: SNAPSHOT_VALIDATION_REVISION,
        }
    };
    receipt.validate()?;
    release_owned(&mut states, digest);
    Ok(receipt)
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
    let retired = {
        let mut states = lock_registry()?;
        purge_expired_except(
            &mut states,
            crate::write_execution::current_time_ms(),
            &digest,
        );
        let state = states.get(&digest).ok_or_else(unknown_snapshot_handle)?;
        if ctx.state_fence != state.begin.scope.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        capture_is_retired(state, crate::write_execution::current_time_ms())
    };
    let observed = if retired {
        // A closed window still owes the caller an exact partial receipt.
        None
    } else {
        let mut guard = CaptureRelease::arm(digest.clone());
        let observed = observe_capture_point(adapter, SNAPSHOT_END_OPERATION).await?;
        guard.retain();
        Some(observed)
    };
    close_capture(&digest, observed.as_ref(), handle)
}
