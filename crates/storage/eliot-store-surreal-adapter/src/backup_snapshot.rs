//! Coherent bounded snapshot capture over the `SurrealDB` bridge (issue #951).
//!
//! The denominator is read from the provider, never taken from the caller.
//! [`begin_snapshot`] runs the fixed member batch in one
//! `BEGIN TRANSACTION;` … `COMMIT TRANSACTION;` sequence, binds the point that
//! batch observed (schema generation, canonical fence, both allocated
//! sequences) after the principal/readiness/generation/fence/source-identity
//! gate, reconciles the caller's declared denominator and scope against the
//! observed set as claims to be verified, and freezes the served set, totals,
//! bounds and expiry. [`read_snapshot_page`] and [`end_snapshot`] re-verify the
//! whole point on every call, before and after the provider await.
//!
//! The scope half is derived from the same observation: the exported projection
//! is the `revision_head`/`ordering_head` values the provider returned at the
//! bound point, reconciled against the request and bound into the owner-issued
//! consistency point by digest. A claim the provider contradicts is refused; a
//! head it has no row for, or has outside the request, is exact per-key scope
//! evidence. See [`observed_scope_projection`] for the record-level limit this
//! honest projection does not claim to cover.
//!
//! One release discipline: [`CaptureRelease`] releases exactly the capture-owned
//! entry on every exit path of a page or end call, including a future dropped
//! while the provider await is in flight. The registry map is never cleared
//! wholesale. A capture that stopped being servable - window closed, point
//! moved, page bound reached, set exhausted, provider read failed - records its
//! exact partial evidence with [`mark_interruption`] and keeps its entry, so
//! [`end_snapshot`] issues a real receipt carrying the exact served counts
//! instead of deleting the only record of what was served. A provider read
//! failure is the one transient reason: a later close that still observes the
//! exact bound point clears it through [`clear_transient_interruption`], because
//! a transport failure observed nothing about the source. A recorded
//! interruption is terminal for serving, but never for closing.
//!
//! Reads only: this module never acquires `adapter.write_lock`, issues no
//! DDL/migration, performs no restore, and defines no archive format. Every
//! provider statement is a fixed adapter-owned `&'static str` assembled at
//! first use from the single-owner consts in [`crate::schema`] (see
//! `client::backup_snapshot::intern` for why it is not a `const`); no snapshot
//! statement carries a binding, so no caller value can reach the provider, and
//! errors/receipts carry digests and static text, never provider payload or
//! credentials.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use eliot_store_api::{
    BlobResidency, BlobResidencyDomain, MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_MEMBERS,
    MAX_SNAPSHOT_PAGE_MEMBERS, MAX_SNAPSHOT_PAGES, OrderingHead, RequestMeta, RevisionHead,
    SnapshotBeginRequest, SnapshotCompleteness, SnapshotCursor, SnapshotDenominator,
    SnapshotEndReceipt, SnapshotHandle, SnapshotMember, SnapshotMemberType, SnapshotPage,
    StateFence, StoreError, canonical_json_bytes, sha256_hex,
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

/// Static error field for an observed scope-projection defect.
const SCOPE_PROJECTION_FIELD: &str = "snapshot.scope_projection";

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
/// as its domain separator, the exact begin-request digest, and the digest of
/// the scope projection *observed* at the bound point. The caller cannot mint
/// any of these: the request digest and the observed projection are the only
/// two inputs, and the second is read from the provider, not from the request.
fn consistency_point(snapshot_digest: &str, scope_projection_digest: &str) -> String {
    format!(
        "{SNAPSHOT_CONSISTENCY_POINT_VERSION}:{SNAPSHOT_CONSISTENCY_POINT_DOMAIN}:{snapshot_digest}:{scope_projection_digest}"
    )
}

/// Static error field for the capture principal check.
const SNAPSHOT_PRINCIPAL_FIELD: &str = "snapshot.principal";

/// Binds the one principal a capture can act as and proves the caller cannot
/// select another one.
///
/// `eliot_store_api::RequestMeta` carries no principal field
/// (`request_id`/`session_id`/`task_id`/`product_id`/`source_id`/
/// `state_fence`/`clock`), and `SnapshotBeginRequest` carries none either, so
/// there is no caller-supplied principal in this capture path to compare. The
/// acting principal is therefore exactly one value:
/// `SurrealAdapterConfig::username`, the value
/// `client::session::authenticate_provider` signs in with once per session
/// (`client/session.rs`) and the only principal the single provider owner ever
/// authenticates. This function states that explicitly instead of leaving it
/// implied, and fails closed with the named typed error
/// [`SNAPSHOT_PRINCIPAL_FIELD`] when the invariant does not hold.
///
/// Two properties are checked, both observable from inside this crate:
///
/// 1. the configured principal is an admissible single token, so a capture can
///    never open under a blank or control-bearing principal;
/// 2. the pinned statement for the requested operation carries no `$`
///    binding placeholder. `run_pinned_snapshot_query` always sends an empty
///    binding map, so a statement that did carry a placeholder would have
///    nothing to fill it with — this is the only channel through which a
///    caller value, and therefore a caller-chosen principal, could reach the
///    provider at this seam, so it is checked rather than assumed.
///
/// The missing contract is real and is not invented here: `RequestMeta` has no
/// principal field, so "schema/generation/fence/principal mismatch rejected"
/// can only be satisfied for the first three. A caller-selected principal
/// needs an `eliot-store-api` contract owner outside this leaf.
fn bind_capture_principal(
    adapter: &SurrealStoreAdapter,
    operation: &'static str,
) -> Result<(), StoreError> {
    let principal = adapter.config.username.as_str();
    if principal.is_empty() || principal.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field: SNAPSHOT_PRINCIPAL_FIELD,
            reason: "acting principal is not the adapter's single authenticated principal",
        });
    }
    let statement = crate::client::fixed_snapshot_statement(operation)
        .map_err(AdapterError::into_store_error)?;
    if statement.contains('$') {
        return Err(StoreError::InvalidField {
            field: SNAPSHOT_PRINCIPAL_FIELD,
            reason: "pinned snapshot statement is not bound-free and could admit a caller principal",
        });
    }
    Ok(())
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
    /// generation's own baseline.
    ///
    /// `SurrealAdapterConfig::validate` pins `expected_schema_generation` to
    /// `GENERATION_V2` today, and the v2 baseline (`schema.rs`) defines exactly
    /// the eleven tables this enumeration reads: the two
    /// [`CanonicalSourceClass::CapturePoint`] rows plus the nine
    /// [`CanonicalSourceClass::Member`] rows. The twelve classes below are not
    /// among them. Reading a table the admitted generation does not define
    /// inside one `BEGIN … COMMIT` batch aborts the whole transaction (see the
    /// recorded provider observations in `apply/read_boundary.rs`), so capturing
    /// these rows would make every capture fail on an admitted store. Each
    /// therefore has exactly one disposition — declared, not captured — instead
    /// of being silently omitted or reported as an undeclared exclusion, and
    /// `verify_canonical_source_classes` proves that 1:1 against the single
    /// owner's own table list.
    ///
    /// This disposition is a property of the *admitted* generation, not of the
    /// table. The additive v3 baseline re-defines `erasure_intent` and
    /// `erasure_outcome`, so under a v3 pin those two rows are no longer outside
    /// the admitted generation and the census refuses that pin instead of
    /// dropping the erasure ledger from a v3 store's capture; a bridge that
    /// admits v3 must give them captured [`CanonicalSourceClass::Member`]
    /// dispositions first.
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
    // Continuations are short-lived owner capabilities, not canonical state.
    // Backups omit active records, terminal tombstones, and the quota guard;
    // this capture census alone does not guarantee whether existing target
    // rows are retained or cleared by a separate restore path. Every use still
    // verifies the retained request and current canonical snapshot binding.
    CanonicalSourceClass::OutsideAdmittedGeneration {
        table: crate::schema::table::AUTOMATION_CONTINUATION,
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

/// The baseline DDL of the schema generation a capture is admitted against.
///
/// [`crate::schema`] stays the single owner of every physical name and every
/// baseline DDL (A2.3); this only *selects* among the baselines it already
/// ships. Naming the generation here instead of restating one baseline is the
/// whole point: a census run against a baseline other than the admitted one
/// reclassifies real tables, and it does so silently. A generation this crate
/// ships no baseline for is refused rather than guessed at.
fn admitted_generation_ddl(generation: &str) -> Option<&'static str> {
    if generation == crate::schema::GENERATION_V2 {
        Some(crate::schema::SCHEMA_DDL_V2)
    } else if generation == crate::schema::GENERATION_V3 {
        Some(crate::schema::SCHEMA_DDL_V3)
    } else {
        None
    }
}

/// Reports whether the admitted generation's baseline defines `table` exactly.
///
/// The admitted generation is the one `SurrealAdapterConfig::validate` pins in
/// `expected_schema_generation` and that `begin_snapshot` re-checks the observed
/// generation against, so a capture never runs against another generation, and
/// this census is therefore run against that same generation's baseline. Only
/// that baseline is evidence of what a capture may read: the superseded
/// first-generation baseline is deliberately *not* consulted, even though it is a
/// strict superset of the v2 table set — it defines `erasure_intent`,
/// `erasure_outcome`, `notification_record`, `reactive_session`,
/// `resource_snapshot`, the three captured automation tables, `experience_bank`
/// and `experience_feedback`, so OR-ing it in would make every one of those
/// declared classes read as admitted and the census would refuse every capture
/// before any provider I/O. The marker carries the trailing space, so
/// `relation_record_extra` can never satisfy `relation_record`.
///
/// The v3 baseline is additive over v2 and re-defines the two erasure tables, so
/// a bridge that ever admits v3 must give those two classes a captured
/// disposition instead of the declared-outside one they carry today; until it
/// does, `verify_canonical_source_classes` refuses that pin as the composition
/// defect it is, rather than reading v2's baseline and silently omitting the
/// erasure ledger from a v3 store's capture.
fn admitted_generation_defines(ddl: &'static str, table: &str) -> bool {
    let marker = format!("DEFINE TABLE {table} ");
    ddl.contains(&marker)
}

/// Walks every declared canonical source class and proves its one disposition.
///
/// Fails closed when the composition drifts from the single owner: a class
/// declared outside the admitted generation that the admitted baseline actually
/// defines would be silently dropped from the capture, and a capture point
/// whose pinned read does not name its own table would bind the wrong point.
/// Both are composition defects, not caller input, so both are refused before
/// any provider I/O instead of being absorbed into a later error.
///
/// The census runs against the baseline of the generation the adapter itself
/// admits, never against a generation restated in this module: the pin belongs to
/// `SurrealAdapterConfig`, and reading a different baseline here would classify
/// real tables against the wrong owner without any error.
///
/// The census denominator is [`crate::schema::table::ALL_TABLES`], not this
/// enumeration. The previous guard incremented a counter once per loop
/// iteration and compared it against the enumeration's own length, so it
/// always held: adding a new `schema::table` const would have produced an
/// incomplete census with no error. Coverage is now checked in both
/// directions against the single owner's own list — every owner table has
/// exactly one disposition, and every disposition names an owner table — so a
/// table that is added, renamed, duplicated or dropped is a typed refusal
/// before any provider I/O.
fn verify_canonical_source_classes(generation: &str) -> Result<(), StoreError> {
    let Some(ddl) = admitted_generation_ddl(generation) else {
        return Err(StoreError::InvalidField {
            field: SNAPSHOT_CLASS_FIELD,
            reason: "admitted schema generation has no baseline in the schema owner",
        });
    };
    let mut disposed: BTreeSet<&'static str> = BTreeSet::new();
    for class in CANONICAL_SOURCE_CLASSES {
        let table = match class {
            CanonicalSourceClass::Member(member) => {
                if !admitted_generation_defines(ddl, member.table) {
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
                    && !admitted_generation_defines(ddl, reference.target_table)
                {
                    return Err(StoreError::InvalidField {
                        field: SNAPSHOT_CLASS_FIELD,
                        reason: "reference target is not defined by the admitted generation",
                    });
                }
                member.table
            }
            CanonicalSourceClass::CapturePoint { table, statement } => {
                if !statement.contains(*table) {
                    return Err(StoreError::InvalidField {
                        field: SNAPSHOT_CLASS_FIELD,
                        reason: "capture point read does not name its own table",
                    });
                }
                *table
            }
            CanonicalSourceClass::OutsideAdmittedGeneration { table } => {
                if admitted_generation_defines(ddl, table) {
                    return Err(StoreError::InvalidField {
                        field: SNAPSHOT_CLASS_FIELD,
                        reason: "declared class is defined by the admitted generation",
                    });
                }
                *table
            }
        };
        // Exactly one disposition per single-owner table: a second disposition
        // for the same table would silently drop one of them from the census.
        if !disposed.insert(table) {
            return Err(StoreError::InvalidField {
                field: SNAPSHOT_CLASS_FIELD,
                reason: "canonical source class has more than one disposition",
            });
        }
        // ... and every disposition must name a table the single owner really
        // declares, so a stale or invented physical name cannot be captured.
        if !crate::schema::table::ALL_TABLES.contains(&table) {
            return Err(StoreError::InvalidField {
                field: SNAPSHOT_CLASS_FIELD,
                reason: "disposition names a table the single owner does not declare",
            });
        }
    }
    // Every table the single owner declares is covered by a disposition, so a
    // newly declared class cannot join the census incomplete.
    for table in crate::schema::table::ALL_TABLES {
        if !disposed.contains(table) {
            return Err(StoreError::InvalidField {
                field: SNAPSHOT_CLASS_FIELD,
                reason: "canonical source class has no disposition",
            });
        }
    }
    // The census is exactly 1:1 with the owner's table count. Together with the
    // two directions above this also proves the owner list itself has no
    // duplicate name, which a per-iteration counter never could.
    if disposed.len() != crate::schema::table::ALL_TABLES.len() {
        return Err(StoreError::InvalidField {
            field: SNAPSHOT_CLASS_FIELD,
            reason: "canonical source class census is not one-to-one with the single owner",
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

/// Frozen per-capture state. No `Debug` impl by design: registry contents
/// never render into logs or errors.
///
/// The entry is keyed by the handle digest, but the digest is only an index: the
/// authority is [`SnapshotState::issued`], the complete owner-issued handle
/// retained once at begin. Every page and end request is compared against it,
/// and every emitted handle is read back from it, so a presented object can
/// never stand in for the issued one.
struct SnapshotState {
    /// The exact handle this capture was opened under, retained once.
    ///
    /// Constructed only after the source observation is validated. A digest
    /// alone is an index and a commitment, not the identity: the consistency
    /// point and the operation/idempotency pair are the other three fields.
    issued: SnapshotHandle,
    /// Monotonic incarnation of this registry entry.
    ///
    /// Owner-issued by [`next_incarnation`]; never a timestamp and never derived
    /// from caller input. A post-provider-read request re-checks it so a request
    /// that began against one capture cannot advance the successor that reused
    /// the same digest.
    incarnation: u64,
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

/// Issues the next capture incarnation identity.
///
/// Owner-issued and monotonic. It is deliberately not a timestamp and not
/// derived from any caller value: the only property the post-await re-check
/// needs is that two different registry entries never share one, and a
/// process-local counter proves that without importing a clock.
fn next_incarnation() -> u64 {
    static NEXT_INCARNATION: AtomicU64 = AtomicU64::new(1);
    NEXT_INCARNATION.fetch_add(1, Ordering::Relaxed)
}

/// Compares a presented handle with the retained owner-issued handle.
///
/// All four fields are compared. The digest is checked too, but a digest match
/// alone is not acceptance: a shape-valid handle whose `consistency_point`,
/// `operation_id` or `idempotency_key` was substituted carries the right index
/// and the wrong capture. A substituted consistency point is a bounded
/// field-level contradiction; a substituted operation or idempotency field is
/// [`StoreError::IdentityConflict`], the I05-27 cause for one operation id under
/// a different identity.
///
/// The caller must run this before any mutation, so a refusal advances no
/// counter, records no interruption, arms no guard, clears no transient state
/// and closes nothing.
fn require_retained_handle(
    state: &SnapshotState,
    presented: &SnapshotHandle,
) -> Result<(), StoreError> {
    if presented.consistency_point != state.issued.consistency_point {
        return Err(StoreError::InvalidField {
            field: "snapshot.consistency_point",
            reason: "presented handle is not the owner-issued handle for this capture",
        });
    }
    if presented.operation_id != state.issued.operation_id
        || presented.idempotency_key != state.issued.idempotency_key
    {
        return Err(StoreError::IdentityConflict);
    }
    if presented.snapshot_digest != state.issued.snapshot_digest {
        return Err(StoreError::InvalidField {
            field: "snapshot.snapshot_digest",
            reason: "presented handle is not the owner-issued handle for this capture",
        });
    }
    Ok(())
}

/// Resolves a replayed begin against the retained owner decision.
///
/// `Ok(Some(handle))` is an exact replay: the same canonical bytes are already
/// open, so the original handle and the original progress are returned and the
/// source is not read again. `Ok(None)` means the logical begin is unclaimed and
/// the caller must open a new capture.
///
/// A different canonical input under an already claimed operation/idempotency
/// namespace is [`StoreError::IdentityConflict`]. The registry is keyed by the
/// request digest, so on its own it cannot see that collision at all — the scan
/// is what makes the namespace claim observable. A deliberate refresh needs its
/// own new logical capture; it never resets the open one.
fn retained_begin_handle(
    digest: &str,
    request: &SnapshotBeginRequest,
) -> Result<Option<SnapshotHandle>, StoreError> {
    let states = lock_registry()?;
    for (claimed, state) in states.iter() {
        if claimed != digest
            && state.issued.operation_id == request.operation.operation_id
            && state.issued.idempotency_key == request.operation.idempotency_key
        {
            return Err(StoreError::IdentityConflict);
        }
    }
    Ok(states.get(digest).map(|state| state.issued.clone()))
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
/// The generation claim is bound in two separately named steps, because they
/// prove different things:
///
/// * the `StateFenceMismatch` comparison below compares the caller's fence to
///   the fence the store just read live. That is an observation of provider
///   state;
/// * [`check_request_generation_coherence`] compares two *caller-supplied*
///   fields of one request to each other. It is a request-internal coherence
///   check, and this module deliberately does not present it as a provider
///   observation. It is kept because the two checks together bind the claimed
///   generation transitively to the live-verified fence, and removing it would
///   let a request carry a generation unrelated to the fence it claims.
///
/// The gap this leaves is real and is not papered over: no owner-issued live
/// resource-generation counter exists to observe. `SurrealAdapterConfig` holds
/// `SchemaGeneration`, a migration version *string* pinned to `GENERATION_V2`
/// (`config.rs`), not a counter, and the store API carries no such field on
/// `SnapshotSourceIdentity`'s provider side. Binding a claimed generation to
/// an independently observed provider counter needs a contract owner outside
/// this leaf.
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
    if request.scope.state_fence != point.state_fence {
        return Err(StoreError::FenceMismatch);
    }
    check_request_generation_coherence(request)
}

/// Refuses a request whose claimed source generation disagrees with the
/// generation inside the state fence the very same request carries.
///
/// This is a request-internal coherence check over two caller-supplied fields.
/// It is *not* an observation of live provider state and is not named as one:
/// see the [`bind_source_identity`] contract note for the full split and for
/// the owner-issued resource-generation counter this adapter does not have.
/// It runs after the live fence comparison, so the fence it reads is already
/// proven equal to the fence the store just observed.
fn check_request_generation_coherence(request: &SnapshotBeginRequest) -> Result<(), StoreError> {
    if request.source.generation != request.scope.state_fence.resource_generation {
        return Err(StoreError::InvalidField {
            field: "snapshot.generation",
            reason: "source generation must match the request's own state fence generation",
        });
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
    /// The scope projection observed at the same point.
    scope: ObservedScopeProjection,
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
///
/// A class that came back with more rows than the capture's own global member
/// ceiling ([`crate::client::MEMBER_CLASS_ROW_LIMIT`]) is certainly truncated —
/// the statement reads one row past the ceiling precisely so that this is
/// decidable — so its denominator is unknown rather than merely large. That is
/// refused here, at the observation boundary, instead of being carried into
/// [`reconcile_denominator`] as a short class: a truncated class would otherwise
/// let a capture bind a denominator smaller than the store's, which is exactly
/// the "truncation is explicit" requirement of the capture contract. A class
/// holding exactly the ceiling is complete and is served normally.
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
        if class_rows.len() > crate::client::MEMBER_CLASS_ROW_LIMIT {
            return Err(StoreError::PayloadTooLarge);
        }
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
    request: &SnapshotBeginRequest,
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
    // The scope projection is derived from the same observation as the
    // denominator, so the exported projection and the served members describe
    // exactly one point.
    let scope = observed_scope_projection(&class_rows, &point, request)?;
    let evidence = EnumerationEvidence {
        classes_read: class_rows.len(),
        members_read: members.len(),
    };
    Ok(Enumeration {
        point,
        evidence,
        members,
        scope,
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

/// Versioned canonical encoding of the observed scope projection.
///
/// I5.27: the projection is a digest-bound owner record, so a reader can tell
/// which encoding produced it and cannot confuse a scope export with a full
/// capture.
const SCOPE_PROJECTION_VERSION: &str = "eliot.snapshot.scope-projection.v1";

/// Row field carrying one head record's own typed body.
const HEAD_BODY_FIELD: &str = "body";

/// The scope projection observed at the bound point, exported as its canonical
/// digest.
///
/// Required implementation: "for the requested full or scope projection" and
/// "Scope-export exclusion needs exact scope evidence, not a broad omitted
/// table". This is the scope half of the capture: it is derived from the
/// `revision_head` / `ordering_head` rows the member batch *observed* at the
/// bound point, never from `request.scope` alone, and the caller's claim is
/// reconciled against it. A claim the provider contradicts is a typed refusal
/// (see [`reconcile_scope_projection`]); a head the provider simply has no row
/// for, or has for a key outside the request, is recorded as exact per-key
/// scope evidence in the exported digest rather than as a broad table
/// exclusion.
///
/// Honest limit, not papered over: the admitted generation's canonical tables
/// (`schema.rs` `SCHEMA_DDL_V2`) carry no uniform `scope_id` column, so this
/// projection covers the scope-defining head records. It does *not* filter the
/// canonical record set to the requested scope, because no physical column
/// supports that filter. Record-level scope export needs a schema owner
/// outside this leaf.
struct ObservedScopeProjection {
    /// Canonical digest of the observed heads and the exact per-key boundary.
    digest: String,
}

/// The two head classes' observed rows, split by the single owner's table names.
struct ObservedHeadRows<'rows> {
    /// Every observed `revision_head` row.
    revisions: Vec<&'rows Map<String, Value>>,
    /// Every observed `ordering_head` row.
    orderings: Vec<&'rows Map<String, Value>>,
}

/// Splits the observed member rows into the two head classes, by the physical
/// table the single owner declares. Classes that are not heads are skipped, so
/// a new member class cannot be mistaken for a head.
fn observed_head_rows(class_rows: &[Vec<Map<String, Value>>]) -> ObservedHeadRows<'_> {
    let mut revisions = Vec::new();
    let mut orderings = Vec::new();
    for (class, rows) in captured_member_classes().zip(class_rows) {
        let target = if class.table == crate::schema::table::REVISION_HEAD {
            &mut revisions
        } else if class.table == crate::schema::table::ORDERING_HEAD {
            &mut orderings
        } else {
            continue;
        };
        target.extend(rows);
    }
    ObservedHeadRows {
        revisions,
        orderings,
    }
}

/// Decodes one observed head row's own typed body.
///
/// The body is what the canonical write path stored
/// (`apply/atomic_write.rs` binds `{"revision_key": …, "body": <RevisionHead>}`
/// and `{"ordering_scope": …, "body": <OrderingHead>}`), so the head is read
/// from the row the provider returned rather than re-derived from the index
/// column.
fn head_body<T: serde::de::DeserializeOwned>(row: &Map<String, Value>) -> Result<T, StoreError> {
    let body = row.get(HEAD_BODY_FIELD).ok_or(StoreError::InvalidField {
        field: SCOPE_PROJECTION_FIELD,
        reason: "observed head row does not carry its typed body",
    })?;
    serde_json::from_value(body.clone()).map_err(snapshot_serialization_error)
}

/// Reads one observed `revision_head` row and proves it belongs to this point.
///
/// The physical index column is cross-checked against the head's own key, and
/// the head's fence against the fence the store just observed: a head written
/// under another fence is not evidence about this point.
fn observed_revision_head(
    row: &Map<String, Value>,
    point: &CapturePoint,
) -> Result<RevisionHead, StoreError> {
    let head: RevisionHead = head_body(row)?;
    head.validate()?;
    if head.state_fence != point.state_fence {
        return Err(StoreError::FenceMismatch);
    }
    let index_key =
        row.get("revision_key")
            .and_then(Value::as_str)
            .ok_or(StoreError::InvalidField {
                field: SCOPE_PROJECTION_FIELD,
                reason: "observed revision row does not carry its index key",
            })?;
    if index_key != head.key.as_str() {
        return Err(StoreError::IdentityConflict);
    }
    Ok(head)
}

/// Reads one observed `ordering_head` row and proves it belongs to this point.
fn observed_ordering_head(
    row: &Map<String, Value>,
    point: &CapturePoint,
) -> Result<OrderingHead, StoreError> {
    let head: OrderingHead = head_body(row)?;
    head.validate()?;
    if head.state_fence != point.state_fence {
        return Err(StoreError::FenceMismatch);
    }
    let index_scope =
        row.get("ordering_scope")
            .and_then(Value::as_str)
            .ok_or(StoreError::InvalidField {
                field: SCOPE_PROJECTION_FIELD,
                reason: "observed ordering row does not carry its index scope",
            })?;
    if index_scope != head.scope.as_str() {
        return Err(StoreError::IdentityConflict);
    }
    Ok(head)
}

/// Reconciles the caller's claimed scope against the observed projection.
///
/// A *conflict* is an observed head the request contradicts: the request names
/// the key, the provider has the key, and the revision/sequence or the fence
/// disagrees. That is a typed refusal, never a silently narrowed projection.
///
/// A head the provider has no row for is not a conflict: the per-key absence is
/// exact scope evidence, and the exported projection simply does not contain
/// that key. This is what keeps a capture of a store that has never written a
/// head legal, which `SnapshotBeginRequest::validate` otherwise could not
/// express, because it requires a non-empty `scope.revision_heads` on every
/// request.
fn reconcile_scope_projection(
    observed_revisions: &[RevisionHead],
    observed_orderings: &[OrderingHead],
    request: &SnapshotBeginRequest,
) -> Result<(), StoreError> {
    let by_key: BTreeMap<&str, &RevisionHead> = observed_revisions
        .iter()
        .map(|head| (head.key.as_str(), head))
        .collect();
    for claimed in &request.scope.revision_heads {
        if let Some(observed) = by_key.get(claimed.key.as_str())
            && *observed != claimed
        {
            return Err(StoreError::IdentityConflict);
        }
    }
    let by_scope: BTreeMap<&str, &OrderingHead> = observed_orderings
        .iter()
        .map(|head| (head.scope.as_str(), head))
        .collect();
    for claimed in &request.scope.ordering_heads {
        if let Some(observed) = by_scope.get(claimed.scope.as_str())
            && *observed != claimed
        {
            return Err(StoreError::IdentityConflict);
        }
    }
    Ok(())
}

/// Builds the canonical scope-projection document.
///
/// The document states the exported projection (`revision_heads`,
/// `ordering_heads` are the *observed* values for the requested keys) plus the
/// exact per-key boundary: which requested keys the provider has no row for,
/// and which observed keys lie outside the request. That is what makes a
/// scope-export exclusion exact rather than a broad omitted table.
///
/// Every list is ordered by its own store-owned key, so the digest never
/// depends on incidental provider row order (I5.27).
fn scope_projection_document(
    request: &SnapshotBeginRequest,
    observed_revisions: &[RevisionHead],
    observed_orderings: &[OrderingHead],
) -> Map<String, Value> {
    let claimed_revisions: BTreeSet<&str> = request
        .scope
        .revision_heads
        .iter()
        .map(|head| head.key.as_str())
        .collect();
    let claimed_orderings: BTreeSet<&str> = request
        .scope
        .ordering_heads
        .iter()
        .map(|head| head.scope.as_str())
        .collect();
    let revision_keys: BTreeSet<&str> = observed_revisions
        .iter()
        .map(|head| head.key.as_str())
        .collect();
    let ordering_scopes: BTreeSet<&str> = observed_orderings
        .iter()
        .map(|head| head.scope.as_str())
        .collect();
    let keys_absent_from = |keys: &BTreeSet<&str>, present: &BTreeSet<&str>| -> Value {
        Value::Array(
            keys.iter()
                .filter(|key| !present.contains(**key))
                .map(|key| Value::String((*key).to_owned()))
                .collect(),
        )
    };
    Map::from_iter([
        (
            "version".to_owned(),
            Value::String(SCOPE_PROJECTION_VERSION.to_owned()),
        ),
        (
            "scope_id".to_owned(),
            Value::String(request.scope.scope_id.as_str().to_owned()),
        ),
        (
            "revision_heads".to_owned(),
            Value::Array(
                observed_revisions
                    .iter()
                    .filter(|head| claimed_revisions.contains(head.key.as_str()))
                    .map(|head| {
                        Value::Array(vec![
                            Value::String(head.key.as_str().to_owned()),
                            Value::from(head.revision),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "ordering_heads".to_owned(),
            Value::Array(
                observed_orderings
                    .iter()
                    .filter(|head| claimed_orderings.contains(head.scope.as_str()))
                    .map(|head| {
                        Value::Array(vec![
                            Value::String(head.scope.as_str().to_owned()),
                            Value::from(head.sequence),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "unobserved_revision_keys".to_owned(),
            keys_absent_from(&claimed_revisions, &revision_keys),
        ),
        (
            "unobserved_ordering_scopes".to_owned(),
            keys_absent_from(&claimed_orderings, &ordering_scopes),
        ),
        (
            "out_of_scope_revision_keys".to_owned(),
            keys_absent_from(&revision_keys, &claimed_revisions),
        ),
        (
            "out_of_scope_ordering_scopes".to_owned(),
            keys_absent_from(&ordering_scopes, &claimed_orderings),
        ),
    ])
}

/// Refuses two observed heads for the same key.
///
/// The admitted DDL declares a unique index per head key, so a duplicate means
/// the observation is not faithful and no projection may be exported from it.
fn ensure_unique_head_keys(
    observed_revisions: &[RevisionHead],
    observed_orderings: &[OrderingHead],
) -> Result<(), StoreError> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for key in observed_revisions
        .iter()
        .map(|head| head.key.as_str())
        .chain(observed_orderings.iter().map(|head| head.scope.as_str()))
    {
        if !seen.insert(key) {
            return Err(StoreError::Duplicate {
                field: SCOPE_PROJECTION_FIELD,
            });
        }
    }
    Ok(())
}

/// Digests the observed scope projection and its exact per-key boundary.
fn observed_scope_projection(
    class_rows: &[Vec<Map<String, Value>>],
    point: &CapturePoint,
    request: &SnapshotBeginRequest,
) -> Result<ObservedScopeProjection, StoreError> {
    let heads = observed_head_rows(class_rows);
    let mut observed_revisions = heads
        .revisions
        .iter()
        .map(|row| observed_revision_head(row, point))
        .collect::<Result<Vec<_>, _>>()?;
    let mut observed_orderings = heads
        .orderings
        .iter()
        .map(|row| observed_ordering_head(row, point))
        .collect::<Result<Vec<_>, _>>()?;
    // Logical order, never incidental provider row order (I5.27).
    observed_revisions.sort_by(|left, right| left.key.as_str().cmp(right.key.as_str()));
    observed_orderings.sort_by(|left, right| left.scope.as_str().cmp(right.scope.as_str()));
    ensure_unique_head_keys(&observed_revisions, &observed_orderings)?;
    reconcile_scope_projection(&observed_revisions, &observed_orderings, request)?;
    let document = scope_projection_document(request, &observed_revisions, &observed_orderings);
    let digest =
        sha256_hex(&canonical_json_bytes(&document).map_err(snapshot_serialization_error)?);
    Ok(ObservedScopeProjection { digest })
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
/// A provider read of the bound point failed, so the capture cannot say the
/// point still holds. Bounded static text: no provider prose, no payload.
const INTERRUPTION_PROVIDER_FAILED: &str = "bound point read failed";

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

/// Records the interruption a provider failure leaves behind, then keeps the
/// entry.
///
/// A transport or RPC failure is not evidence that the capture served nothing:
/// the pages already handed out are exact partial evidence an operator must be
/// able to see, and `end_snapshot` still owes the caller a receipt carrying
/// them. The guard therefore stays *armed* across the provider await — a
/// future dropped mid-await still releases the capture-owned entry through
/// `Drop`, which is the only observable cancellation in this crate — and this
/// helper disarms it only on the failure path, after the frozen counters have
/// been recorded. The reason is bounded static text, so no provider message
/// crosses the boundary. A poisoned registry lock still retains the entry:
/// keeping the evidence is the safe direction when it cannot be annotated.
fn retain_with_interruption(guard: &mut CaptureRelease, digest: &str) {
    if let Ok(mut states) = registry().lock() {
        mark_interruption(&mut states, digest, INTERRUPTION_PROVIDER_FAILED);
    }
    guard.retain();
}

/// Clears a recorded provider failure once a later bound-point read proves the
/// point still holds.
///
/// `INTERRUPTION_PROVIDER_FAILED` is the one transient reason: a transport or
/// RPC blip records no fact about the source, so a later owner read returning
/// the exact bound point is fresh evidence that the capture never lost its
/// consistency. Keeping the record anyway permanently downgraded a capture that
/// had in fact served everything to `Partial`, which is not what actually
/// completed.
///
/// Every other reason records a durable condition and stays terminal, so this
/// never clears it: `INTERRUPTION_POINT_MOVED` (the source advanced),
/// `INTERRUPTION_WINDOW_CLOSED` (the owner window or duration bound closed),
/// `INTERRUPTION_PAGE_BOUND` (a bound was reached before the set was served) and
/// `INTERRUPTION_CAPTURE_EXHAUSTED` (no further page exists).
///
/// Clearing removes no evidence. While any interruption stands, `prepare_page`
/// and `finish_page` both refuse before `serve_next_page` can reach the
/// counters, so the frozen counts are the live counts by construction; the
/// receipt therefore reports exactly the same numbers it would have reported
/// with the record left in place, and `is_complete_capture` still has to pass
/// before the closing receipt may say `Complete`.
fn clear_transient_interruption(states: &mut HashMap<String, SnapshotState>, digest: &str) {
    let Some(state) = states.get_mut(digest) else {
        return;
    };
    let transient = state
        .interruption
        .as_ref()
        .is_some_and(|interruption| interruption.reason == INTERRUPTION_PROVIDER_FAILED);
    if transient {
        state.interruption = None;
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
    // The acting principal is named, not assumed, before any protected read.
    bind_capture_principal(adapter, SNAPSHOT_BEGIN_OPERATION)?;
    verify_canonical_source_classes(adapter.config.expected_schema_generation.as_str())?;
    // Resolve the exact logical begin through the registry BEFORE the source is
    // read. An exact replay returns the retained handle and the retained
    // progress; re-enumerating here would present a second observation as the
    // old capture, and the consistency point embeds the observed scope digest,
    // so the replayed handle would differ from the one actually in force.
    let snapshot_digest = request.compute_digest().map_err(redact_snapshot_error)?;
    if let Some(retained) = retained_begin_handle(&snapshot_digest, &request)? {
        return Ok(retained);
    }
    // The denominator and the scope projection are read from the provider, in one
    // coherent transaction with the point they claim, and the caller's claims are
    // reconciled against what was observed. The caller never supplies the served
    // set.
    let enumeration = enumerate_canonical_members(adapter, &request).await?;
    let point = enumeration.point;
    if point.schema_generation != adapter.config.expected_schema_generation.as_str() {
        return Err(StoreError::Unavailable);
    }
    bind_source_identity(adapter, &point, &request)?;
    let ordered_members = enumeration.members;
    let evidence = enumeration.evidence;
    let scope_digest = enumeration.scope.digest;
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

    // Constructed only now, after the source observation is validated, and
    // retained with the entry rather than returned as a throwaway value.
    let handle = SnapshotHandle {
        // The owner-issued point binds the caller's claim *and* the scope
        // projection read back from the provider, so a reader of the handle can
        // tell which projection was actually exported.
        consistency_point: consistency_point(&snapshot_digest, &scope_digest),
        snapshot_digest: snapshot_digest.clone(),
        operation_id: request.operation.operation_id.clone(),
        idempotency_key: request.operation.idempotency_key.clone(),
    };
    handle.validate()?;

    let mut states = lock_registry()?;
    if let Some(state) = states.get(&snapshot_digest) {
        // Another begin for the same logical request claimed this capture while
        // this one was enumerating. The retained decision is authoritative: a
        // deliberate refresh needs its own new logical capture, never a reset of
        // the open one, and an expired or retired replay keeps its original
        // window because the entry is left exactly as it is.
        return Ok(state.issued.clone());
    }
    states.insert(
        snapshot_digest.clone(),
        SnapshotState {
            issued: handle.clone(),
            incarnation: next_incarnation(),
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
///
/// The page's handle is read back from the retained owner-issued handle, never
/// from the object the caller presented: the caller has already been proven to
/// hold the issued identity, so echoing its own copy would prove nothing.
fn serve_next_page(
    states: &mut HashMap<String, SnapshotState>,
    digest: &str,
    cursor: SnapshotCursor,
) -> Result<SnapshotPage, StoreError> {
    let Some(state) = states.get_mut(digest) else {
        return Err(unknown_snapshot_handle());
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
        handle: state.issued.clone(),
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
/// The presented handle is resolved against the retained owner-issued handle
/// FIRST, and the resolved incarnation is returned so the post-await path can
/// prove it is still serving the same capture. A mismatched handle therefore
/// advances no counter, records no interruption, arms no guard, clears no
/// transient state and closes nothing; independent expiry maintenance also does
/// not run for a request that does not target a real capture under its own
/// identity.
///
/// When the capture can no longer serve, the exact partial evidence is recorded
/// and the entry deliberately retained, so a later `end_snapshot` can still
/// issue an honest `Expired` or `Partial` receipt instead of deleting the only
/// record of what was served.
fn prepare_page(
    states: &mut HashMap<String, SnapshotState>,
    digest: &str,
    presented: &SnapshotHandle,
    ctx: &RequestMeta,
    cursor: &SnapshotCursor,
    now_ms: u64,
) -> Result<u64, StoreError> {
    let Some(state) = states.get(digest) else {
        return Err(unknown_snapshot_handle());
    };
    require_retained_handle(state, presented)?;
    let incarnation = state.incarnation;
    purge_expired_except(states, now_ms, digest);
    let state = states.get(digest).ok_or_else(unknown_snapshot_handle)?;
    let retired = capture_is_retired(state, now_ms);
    let next_page = state.pages_served.saturating_add(1);
    let over_page_bound =
        next_page > state.begin.bounds.max_pages || next_page > MAX_SNAPSHOT_PAGES;
    let known_empty = state.ordered_members.is_empty();
    if retired {
        mark_interruption(states, digest, INTERRUPTION_WINDOW_CLOSED);
        return Err(StoreError::Unavailable);
    }
    if state.interruption.is_some() {
        // A recorded interruption is terminal: the capture can no longer claim
        // the bound point still holds, and the frozen counters the interruption
        // carries are the receipt's counts. Serving another page would move
        // those counters past the recorded ones, so the entry is kept exactly
        // as it is and `end_snapshot` issues the partial receipt.
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
    Ok(incarnation)
}

/// Resolves a page/end claim against the live owner entry.
///
/// Returns the typed refusal when the claim no longer describes the entry that
/// occupies the digest: the entry was replaced (a different incarnation), or the
/// presented handle is not the one it was issued under.
fn resolve_page_claim(
    states: &HashMap<String, SnapshotState>,
    digest: &str,
    presented: &SnapshotHandle,
    incarnation: u64,
) -> Result<(), StoreError> {
    let state = states.get(digest).ok_or_else(unknown_snapshot_handle)?;
    if state.incarnation != incarnation {
        return Err(StoreError::IdentityConflict);
    }
    require_retained_handle(state, presented)
}

/// Re-verifies the bound point after the provider await and serves the page, or
/// records the exact partial evidence that ends the capture.
///
/// The claim is re-resolved against owner state, not only against the provider:
/// exact handle equality does not prove the entry was not replaced while the
/// await was in flight, so the incarnation the pre-read claim was validated
/// against is re-checked too.
///
/// A refusal here disarms the release guard first. The guard is armed across the
/// provider await and releases BY DIGEST, so leaving it armed on a mismatch would
/// delete whichever entry now occupies that digest — the successor this check
/// exists to protect.
fn finish_page(
    digest: &str,
    observed: &CapturePoint,
    presented: &SnapshotHandle,
    incarnation: u64,
    cursor: SnapshotCursor,
    guard: &mut CaptureRelease,
) -> Result<SnapshotPage, StoreError> {
    let mut states = lock_registry()?;
    if let Err(error) = resolve_page_claim(&states, digest, presented, incarnation) {
        guard.retain();
        return Err(error);
    }
    let (moved, retired, interrupted) = {
        let state = states.get(digest).ok_or_else(unknown_snapshot_handle)?;
        (
            observed != &state.point,
            capture_is_retired(state, crate::write_execution::current_time_ms()),
            state.interruption.is_some(),
        )
    };
    if interrupted {
        // The capture was already interrupted between the pre-await validation
        // and this observation; the recorded evidence stands.
        return Err(StoreError::Unavailable);
    }
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
    serve_next_page(&mut states, digest, cursor)
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
    // The same single-principal invariant is proved on the continuation, not
    // only at begin: a page is protected data too.
    bind_capture_principal(adapter, SNAPSHOT_PAGE_OPERATION)?;
    let digest = handle.snapshot_digest.clone();
    let incarnation = {
        let mut states = lock_registry()?;
        prepare_page(
            &mut states,
            &digest,
            &handle,
            ctx,
            &cursor,
            crate::write_execution::current_time_ms(),
        )?
    };
    // No registry lock is held across this provider await (I5.7). The guard is
    // armed across it, so a future dropped while the await is in flight still
    // releases exactly the capture-owned entry; only a provider failure that
    // actually returns disarms it, and only after recording the exact partial
    // evidence the pages already served left behind.
    let mut guard = CaptureRelease::arm(digest.clone());
    let observed = match observe_capture_point(adapter, SNAPSHOT_PAGE_OPERATION).await {
        Ok(point) => point,
        Err(error) => {
            retain_with_interruption(&mut guard, &digest);
            return Err(error);
        }
    };
    finish_page(&digest, &observed, &handle, incarnation, cursor, &mut guard)
}

/// Builds and validates the closing receipt, then releases the capture entry.
///
/// `observed` is `None` when the owner window had already closed: the point is
/// then deliberately not re-read, because a receipt must not claim the source
/// stayed still across a window this store no longer vouches for.
///
/// A fresh observation that equals the bound point exactly is the evidence that
/// a recorded provider failure was only a transport blip, so that one transient
/// record is cleared before completeness is computed. Every other interruption
/// reason, and every `moved`/`expired` observation, stays terminal.
///
/// The receipt's handle comes from the retained owner-issued handle, so the
/// receipt and its operation identity describe the same capture by
/// construction rather than by agreement between two caller-reachable values.
///
/// The claim is re-resolved after the provider await, exactly as the page path
/// does. Without that, a close that began against one capture would clear a
/// successor's recorded interruption, issue a receipt built from the successor's
/// identity and counters, and then delete the successor's entry.
fn close_capture(
    digest: &str,
    observed: Option<&CapturePoint>,
    presented: &SnapshotHandle,
    incarnation: u64,
) -> Result<SnapshotEndReceipt, StoreError> {
    let mut states = lock_registry()?;
    resolve_page_claim(&states, digest, presented, incarnation)?;
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
    } else {
        // The bound point still holds on a fresh owner read, so a recorded
        // provider failure never observed anything about the source. A capture
        // that really did serve every member of its denominator closes
        // `Complete`; one that did not still closes `Partial` through
        // `is_complete_capture`.
        clear_transient_interruption(&mut states, digest);
    }
    let receipt = {
        let state = states.get(digest).ok_or_else(unknown_snapshot_handle)?;
        let (completeness, members_served, bytes_served) =
            closing_accounting(state, expired, moved)?;
        SnapshotEndReceipt {
            handle: state.issued.clone(),
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
    // The closing receipt is owner-issued evidence about protected data, so the
    // same single-principal invariant is proved before it can be issued.
    bind_capture_principal(adapter, SNAPSHOT_END_OPERATION)?;
    let digest = handle.snapshot_digest.clone();
    let (retired, incarnation) = {
        let mut states = lock_registry()?;
        // The target request is resolved against the retained owner-issued
        // handle before any maintenance runs, so a mismatched handle purges
        // nothing, interrupts nothing and closes nothing. The incarnation this
        // claim was validated against is carried across the provider await.
        {
            let state = states.get(&digest).ok_or_else(unknown_snapshot_handle)?;
            require_retained_handle(state, &handle)?;
        }
        purge_expired_except(
            &mut states,
            crate::write_execution::current_time_ms(),
            &digest,
        );
        let state = states.get(&digest).ok_or_else(unknown_snapshot_handle)?;
        if ctx.state_fence != state.begin.scope.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        (
            capture_is_retired(state, crate::write_execution::current_time_ms()),
            state.incarnation,
        )
    };
    let observed = if retired {
        // A closed window still owes the caller an exact partial receipt.
        None
    } else {
        let mut guard = CaptureRelease::arm(digest.clone());
        let observed = match observe_capture_point(adapter, SNAPSHOT_END_OPERATION).await {
            Ok(point) => {
                guard.retain();
                point
            }
            Err(error) => {
                // The end read failed, so no receipt can claim the point held
                // across this close. The capture-owned entry is still the only
                // record of what was served, so it is kept with its exact
                // partial evidence and the caller may retry `end_snapshot`.
                retain_with_interruption(&mut guard, &digest);
                return Err(error);
            }
        };
        Some(observed)
    };
    close_capture(&digest, observed.as_ref(), &handle, incarnation)
}
