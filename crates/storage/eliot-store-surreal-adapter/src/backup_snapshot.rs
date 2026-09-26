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
//! Three lifetimes, one owner. A capture entry separates:
//!
//! * the retained capture identity and progress ([`SnapshotState`]) — the
//!   issued handle, bound point, served counters, interruption ledger and the
//!   immutable terminal receipt, which outlive every individual call;
//! * the heavyweight member payload ([`CapturePayload`]) and the one retained
//!   page response ([`SnapshotState::last_page`]), freed by the accounted
//!   payload-to-terminal transition while the entry above survives;
//! * the in-flight call claim ([`CaptureCallClaim`]) — private, non-cloneable,
//!   bound to the capture incarnation, the request kind and the progress
//!   revision it was validated against.
//!
//! Every page and end call acquires its own claim after validation, so calls on
//! one capture are serialized by the claim slot and are additionally re-verified
//! against an explicit progress revision after the provider await. A digest is
//! only an index: no post-await counter movement or interruption is applied
//! without the matching incarnation, claim and revision, and no registry mutex
//! is ever held across provider IO (I5.7).
//!
//! Every exit settles only its own claim. Explicit completion applies the
//! matching transition and then disarms the claim. Drop releases the local claim
//! and preserves prior capture evidence: an unpolled future performed nothing,
//! and cancellation while awaiting a point observation proves neither source
//! movement nor a stable point nor zero served pages. Drop therefore records no
//! interruption, issues no provider call and deletes no entry; poisoned or
//! unreadable bookkeeping leaves the claim occupied as an observable recovery
//! limitation, never as successful cleanup.
//!
//! Interruptions merge instead of overwriting. A capture that stopped being
//! servable — window closed, point moved, page bound reached, set exhausted,
//! provider read failed — keeps its entry and its exact partial evidence in
//! [`CaptureInterruption`], whose bounded reason ledger retains the first causal
//! failure plus whatever later outcome evidence is necessary. A point movement
//! or window expiry stays terminal for serving and for completeness, so an
//! unrelated transient provider error can neither replace it nor later be
//! cleared into `Complete`. Re-observing the exact original point resolves only
//! the single unresolved transient-read condition, keeping that reason in the
//! ledger and leaving every served counter unchanged.
//!
//! The close transition is accounted, not destructive. A closed capture freezes
//! one immutable [`SnapshotEndReceipt`] derived from the authoritative
//! denominator, the original handle, the exact served counters and the actual
//! source/window observations, then frees the heavy payload. Expiry maintenance
//! of another capture performs the same accounted transition instead of deleting
//! its only evidence, and the bounded terminal record is released only after its
//! replay horizon has ended. An exact repeated end is answered from that record;
//! a failed observation leaves the close pending with its recovery identity and
//! never fabricates a stable-point receipt.
//!
//! What this module does *not* claim: the served counters are local accounting of
//! what this adapter constructed, not proof that the caller received a page or
//! that a full backup is durable (I5.13: backup existence is not recovery
//! proof; I5.27: a committed intent never proves the effect occurred). An exact
//! repeated page cursor is answered from the retained response owner; a cursor
//! that is not an exact repeat is refused rather than skipped forward, zeroed or
//! recaptured under the old identity. The registry is process memory: nothing
//! here is restart-persistent unless it is handed to and acknowledged by the
//! existing durable backup/evidence owner, and no new snapshot database exists
//! here.
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
///
/// The three lifetimes are separate members, not one blob: identity/progress
/// and the interruption ledger live here for the whole capture, the heavyweight
/// payload and the retained page response are freed by the terminal transition,
/// and the in-flight call claim is owned by exactly one call at a time.
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
    /// servable. Never deleted while the entry lives: it is the receipt's
    /// `Partial`/`Expired` provenance.
    interruption: Option<CaptureInterruption>,
    /// The single in-flight page/end claim, or `None` when no call owns this
    /// capture right now. At most one call can be inside a provider await for
    /// this entry, which is what makes a post-await result attributable.
    claim: Option<CaptureClaimSlot>,
    /// Monotonic progress revision of this entry.
    ///
    /// Bumped by every accepted transition that changes observable progress:
    /// a served page, a recorded interruption, a resolved transient read and
    /// the terminal close. A claim is bound to the revision it was validated
    /// against, so a result computed for a different progress state cannot be
    /// applied to this one.
    progress_revision: u64,
    /// The heavyweight observed member payload. `None` after the accounted
    /// terminal transition freed it; a capture with no payload never
    /// constructs fresh capture data under its old identity.
    payload: Option<CapturePayload>,
    /// The last page this owner constructed, retained as the same-cursor
    /// replay source for a response the caller may have lost. Bounded by one
    /// page and freed by the terminal transition.
    last_page: Option<SnapshotPage>,
    /// The immutable terminal close result, retained for an exact repeated end
    /// inside its bounded replay horizon.
    terminal: Option<RetainedClose>,
    total_bytes: u64,
    total_pages: u64,
    /// Pages this adapter constructed and accounted locally. This is local
    /// accounting of constructed responses, not proof of transport delivery
    /// to the backup consumer and not proof of durability.
    pages_served: u64,
    /// Members accounted locally in those pages.
    members_served: u64,
    /// Bytes accounted locally in those pages.
    bytes_served: u64,
    last_digest: String,
    opened_at_ms: u64,
}

/// The heavyweight member payload of a live capture.
///
/// It is separated from [`SnapshotState`] so the accounted terminal transition
/// can free it while the identity, progress, interruption and terminal evidence
/// around it survive.
struct CapturePayload {
    /// The observed members in the frozen served order.
    ordered_members: Vec<SnapshotMember>,
}

/// The immutable terminal close result plus its bounded replay horizon.
struct RetainedClose {
    /// The exact receipt this owner issued for this capture. It is never
    /// recomputed and never rewritten, so an exact repeated end returns the
    /// same evidence rather than a second derivation.
    receipt: SnapshotEndReceipt,
    /// Owner-issued horizon: the capture's own declared duration bound. Inside
    /// it an exact repeated end is answered from this record; after it the
    /// bounded record is released by maintenance and no receipt is fabricated
    /// for a capture whose payload is already gone.
    retained_until_ms: u64,
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

/// Issues the next in-flight call-claim identity.
///
/// Owner-issued and monotonic, for the same reason as [`next_incarnation`]: the
/// post-await re-check only needs a value that identifies exactly one claim
/// slot, so a released or replaced claim can never be mistaken for the call that
/// is still awaiting the provider.
fn next_claim_id() -> u64 {
    static NEXT_CLAIM_ID: AtomicU64 = AtomicU64::new(1);
    NEXT_CLAIM_ID.fetch_add(1, Ordering::Relaxed)
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
///
/// Interruptions merge instead of overwriting: `reasons` is an ordered, bounded
/// ledger whose index 0 is the first causal failure. A later writer only ever
/// appends, so an unrelated transient failure can never displace the terminal
/// reason that actually stopped the capture, and the outcome evidence that
/// matters is kept next to the cause.
struct CaptureInterruption {
    /// Ordered bounded reason ledger; index 0 is the first causal failure.
    reasons: Vec<InterruptionReason>,
    /// Set once an exact reread of the original bound point resolved the one
    /// outstanding transient read condition. The reason itself stays in the
    /// ledger and every frozen counter below stays unchanged, so resolving a
    /// transport blip never erases the history of the failure.
    transient_resolved: bool,
    /// Pages served when the first reason was recorded.
    pages_served: u64,
    /// Members served when the first reason was recorded.
    members_served: u64,
    /// Bytes served when the first reason was recorded.
    bytes_served: u64,
}

impl CaptureInterruption {
    /// Reports whether a retained reason keeps the capture from `Complete`.
    ///
    /// A resolved transient read never blocks: it observed nothing about the
    /// source. Every other retained reason blocks, including a terminal
    /// point/window condition recorded after a later transient failure, which
    /// is exactly the case a single-slot reason could not express.
    fn blocks_completeness(&self) -> bool {
        if self.reasons.iter().any(|reason| reason.is_terminal()) {
            // A point movement or a window expiry is never resolved away, not
            // even when an unrelated transient failure was recorded first and
            // the point reread cleanly afterwards.
            return true;
        }
        // A resolved transient read observed nothing about the source, so it
        // stops blocking. An unresolved one still blocks, and so does any
        // structural reason retained beside it.
        self.reasons
            .iter()
            .any(|reason| !reason.is_transient_read() || !self.transient_resolved)
    }

    /// Reports whether the owner window closed under this capture.
    fn window_closed(&self) -> bool {
        self.reasons.contains(&InterruptionReason::WindowClosed)
    }
}

/// One static reason a capture can no longer serve.
///
/// The closed vocabulary replaces the previous single `&'static str` reason
/// slot: a closed enum is bounded reason storage by construction, and it makes
/// "terminal" and "observed nothing about the source" properties of the reason
/// rather than string comparisons at each use. No provider prose and no
/// captured payload is part of any reason, so nothing foreign can reach an
/// operator through this ledger.
#[derive(Clone, Copy, Eq, PartialEq)]
enum InterruptionReason {
    /// The owner-issued window or duration bound closed under the capture.
    WindowClosed,
    /// The bound consistency point moved because the canonical store advanced.
    PointMoved,
    /// The per-request page bound was reached before the observed set was
    /// served.
    PageBound,
    /// The observed member set has no further page to serve.
    CaptureExhausted,
    /// A read of the bound point failed, so the capture cannot say the point
    /// still holds.
    ProviderReadFailed,
}

impl InterruptionReason {
    /// Reports whether this reason is terminal for serving and for completeness.
    const fn is_terminal(self) -> bool {
        matches!(self, Self::WindowClosed | Self::PointMoved)
    }

    /// Reports whether this reason observed nothing at all about the source.
    const fn is_transient_read(self) -> bool {
        matches!(self, Self::ProviderReadFailed)
    }
}

/// Ceiling on one capture's merged reason ledger.
///
/// The closed reason vocabulary is five entries, so this bound is never reached
/// by a real capture; it exists so the ledger is bounded storage by
/// construction, and the earliest evidence is what survives when it is.
const MAX_INTERRUPTION_REASONS: usize = 8;

/// Merges one interruption reason into the capture's retained evidence.
///
/// The entry is deliberately kept: the entry is the only place the served
/// counters still exist, and deleting it is what previously destroyed the exact
/// partial evidence on both the page and the end path. The merge is monotone —
/// nothing is ever replaced — so the first causal failure stays the reason of
/// record and a later, unrelated failure is retained beside it instead of
/// overwriting it and then being cleared.
///
/// A claim from another incarnation never annotates this entry: a replaced
/// capture keeps its own evidence untouched.
fn merge_interruption(
    states: &mut HashMap<String, SnapshotState>,
    digest: &str,
    incarnation: u64,
    reason: InterruptionReason,
) {
    let Some(state) = states.get_mut(digest) else {
        return;
    };
    if state.incarnation != incarnation {
        return;
    }
    if let Some(entry) = state.interruption.as_mut() {
        if !entry.reasons.contains(&reason) && entry.reasons.len() < MAX_INTERRUPTION_REASONS {
            entry.reasons.push(reason);
        }
        return;
    }
    let interruption = CaptureInterruption {
        reasons: vec![reason],
        transient_resolved: false,
        pages_served: state.pages_served,
        members_served: state.members_served,
        bytes_served: state.bytes_served,
    };
    state.interruption = Some(interruption);
    state.progress_revision = state.progress_revision.saturating_add(1);
}

/// Resolves the single outstanding transient read condition, if that is all the
/// ledger holds.
///
/// `InterruptionReason::ProviderReadFailed` is the one reason that observed
/// nothing about the source: a transport or RPC blip records no fact about the
/// store, so a later owner read returning the exact bound point is fresh
/// evidence that the capture never lost its consistency. Keeping the record
/// permanently would downgrade a capture that had in fact served everything to
/// `Partial`, which is not what actually completed.
///
/// The resolution is deliberately narrow. It applies only when the transient
/// read is the *sole* recorded reason, it never removes that reason from the
/// ledger, it never touches the frozen counters, and it never resolves a reason
/// that merely happens to appear after a terminal one: `INTERRUPTION_POINT_MOVED`
/// (the source advanced), `INTERRUPTION_WINDOW_CLOSED` (the owner window or
/// duration bound closed), `INTERRUPTION_PAGE_BOUND` and
/// `INTERRUPTION_CAPTURE_EXHAUSTED` all stay terminal forever.
fn resolve_transient_read(
    states: &mut HashMap<String, SnapshotState>,
    digest: &str,
    incarnation: u64,
) {
    let Some(state) = states.get_mut(digest) else {
        return;
    };
    if state.incarnation != incarnation {
        return;
    }
    let Some(entry) = state.interruption.as_mut() else {
        return;
    };
    if entry.reasons.len() != 1 || !entry.reasons[0].is_transient_read() || entry.transient_resolved
    {
        return;
    }
    entry.transient_resolved = true;
    // The served counters are untouched; only the completeness eligibility
    // changes, which is itself observable progress.
    state.progress_revision = state.progress_revision.saturating_add(1);
}

/// Which kind of request holds a capture's in-flight claim.
#[derive(Clone, Copy, Eq, PartialEq)]
enum CaptureCallKind {
    /// A [`read_snapshot_page`] call.
    Page,
    /// An [`end_snapshot`] call.
    End,
}

/// The registry's record of the one in-flight call claim on a capture.
struct CaptureClaimSlot {
    /// Owner-issued identity of this single in-flight claim.
    claim_id: u64,
    /// The kind of request that holds the claim.
    kind: CaptureCallKind,
    /// The progress revision the claim was validated against.
    expected_revision: u64,
}

/// Private, non-cloneable claim over one page or end call on one capture.
///
/// The claim is bound to the capture incarnation, the request kind and the
/// progress revision it was validated against, so a post-await result can be
/// applied only to the exact owner it was computed for. It is not `Clone`, not
/// `Copy` and carries no public capability: only the call that acquired it can
/// settle it, and its `Drop` releases exactly its own claim slot.
struct CaptureCallClaim {
    /// Digest of the claimed capture, the registry index for the slot.
    digest: String,
    /// Incarnation the claim was validated against.
    incarnation: u64,
    /// The kind of request this claim belongs to.
    kind: CaptureCallKind,
    /// Identity of this single in-flight claim.
    claim_id: u64,
    /// The progress revision this claim was validated against.
    expected_revision: u64,
    /// Set once the matching transition was applied and the slot released.
    settled: bool,
}

impl CaptureCallClaim {
    /// Settles the claim after its matching transition was applied.
    ///
    /// Explicit completion disarms the local claim only after the state
    /// transition it belongs to, so an exit that fails before its transition
    /// leaves the claim armed and `Drop` releases it.
    fn settle(&mut self, states: &mut HashMap<String, SnapshotState>) {
        release_claim_slot(states, &self.digest, self.claim_id);
        self.settled = true;
    }
}

impl Drop for CaptureCallClaim {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        // A released claim is the only thing this destructor does. It proves
        // nothing about the source: an unpolled future performed nothing, and
        // cancellation while awaiting a point observation establishes neither
        // source movement nor a stable point nor zero served pages. So prior
        // evidence — served counters, interruption ledger, retained terminal
        // receipt — is preserved exactly as it is, no interruption is recorded,
        // no provider call is issued, and no entry is deleted.
        let Ok(mut states) = registry().lock() else {
            // Poisoned bookkeeping is an observable recovery limitation, not
            // successful cleanup: the slot stays occupied, so the next call sees
            // a typed conflict instead of a capture that silently lost its
            // evidence.
            return;
        };
        release_claim_slot(&mut states, &self.digest, self.claim_id);
    }
}

/// Releases exactly one call's claim slot, and nothing else.
///
/// A slot that no longer carries this claim id belongs to a successor, so this
/// can neither release a successor's claim nor annotate or delete it.
fn release_claim_slot(states: &mut HashMap<String, SnapshotState>, digest: &str, claim_id: u64) {
    let Some(state) = states.get_mut(digest) else {
        return;
    };
    if state
        .claim
        .as_ref()
        .is_some_and(|slot| slot.claim_id == claim_id)
    {
        state.claim = None;
    }
}

/// Re-verifies that a claim still describes the exact owner it was acquired for.
///
/// The check is deliberately explicit and layered rather than digest-shaped: a
/// digest match alone cannot prove which entry or which progress state the
/// awaiting call belongs to.
fn resolve_claim(state: &SnapshotState, claim: &CaptureCallClaim) -> Result<(), StoreError> {
    if state.incarnation != claim.incarnation {
        // The entry under this digest is a different capture entirely.
        return Err(StoreError::IdentityConflict);
    }
    let Some(slot) = state.claim.as_ref() else {
        return Err(StoreError::RevisionConflict);
    };
    if slot.claim_id != claim.claim_id
        || slot.kind != claim.kind
        || slot.expected_revision != claim.expected_revision
    {
        return Err(StoreError::RevisionConflict);
    }
    if state.progress_revision != claim.expected_revision {
        // The capture moved to another progress state while this call awaited
        // the provider, so its result belongs to an earlier revision.
        return Err(StoreError::RevisionConflict);
    }
    Ok(())
}

/// The typed refusal while another call still owns the capture's claim.
///
/// A close that answers here cannot know the final counts, because the live
/// page claim may still advance them, and a second page call cannot know which
/// progress state it would extend. `eliot_store_api::StoreError` has no pending
/// variant, so the typed conflict it does offer for a call that does not own
/// the capture's current progress revision is used instead of inventing one
/// here.
fn capture_claim_pending() -> StoreError {
    StoreError::RevisionConflict
}

/// Records the interruption a returned provider failure leaves behind, then
/// settles only this call's claim.
///
/// A transport or RPC failure is not evidence that the capture served nothing:
/// the pages already accounted are exact partial evidence an operator must be
/// able to see, and `end_snapshot` still owes the caller a receipt carrying
/// them. It is also not evidence that the source moved, which is why the reason
/// is the transient one and why it is merged into the ledger rather than
/// replacing whatever the ledger already holds.
///
/// A poisoned registry lock is not treated as successful cleanup: the claim is
/// left unsettled, so its `Drop` cannot certify anything either, and the
/// capture keeps its entry and its evidence.
fn record_provider_read_failure(claim: &mut CaptureCallClaim) {
    let Ok(mut states) = registry().lock() else {
        return;
    };
    let owned = states
        .get(&claim.digest)
        .is_some_and(|state| resolve_claim(state, claim).is_ok());
    if !owned {
        // The claim no longer describes this entry's current owner: a replaced
        // or closed capture keeps its own evidence untouched.
        return;
    }
    merge_interruption(
        &mut states,
        &claim.digest,
        claim.incarnation,
        InterruptionReason::ProviderReadFailed,
    );
    claim.settle(&mut states);
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

/// Applies the accounted expiry transition to every capture but `keep`.
///
/// This is not a deletion pass any more. A retired capture is converted into the
/// same terminal record an explicit close would produce — the exact served
/// counters it reached, an `Expired` completeness, its identity and its
/// interruption ledger retained, its heavy payload freed — so an operator can
/// still read what a capture that nobody closed actually served. Only after that
/// accounted transition, and only for a capture whose replay horizon has ended,
/// is the bounded record released.
///
/// A capture with a live call claim is skipped entirely: no claim may lose the
/// payload it is currently serving from, and #2691's supervised sweep reaches the
/// same transition later.
fn account_expired_captures(states: &mut HashMap<String, SnapshotState>, now_ms: u64, keep: &str) {
    let expired: Vec<String> = states
        .iter()
        .filter(|(digest, state)| {
            digest.as_str() != keep
                && state.claim.is_none()
                && state.terminal.is_none()
                && capture_is_retired(state, now_ms)
        })
        .map(|(digest, _)| digest.clone())
        .collect();
    for digest in expired {
        account_expiry(states, &digest);
    }
    release_expired_terminal_records(states, now_ms);
}

/// Performs the accounted payload-to-terminal transition for one retired capture.
///
/// The bound point is deliberately not re-read for a capture whose owner window
/// has closed: a receipt must not claim the source stayed still across a window
/// this store no longer vouches for, so no stable-point receipt is fabricated.
fn account_expiry(states: &mut HashMap<String, SnapshotState>, digest: &str) {
    let Some(state) = states.get(digest) else {
        return;
    };
    let incarnation = state.incarnation;
    let Some(receipt) = expiry_receipt(state) else {
        // A ledger whose frozen counters disagree with the live counters is a
        // receipt defect. This module never answers a defect by deleting
        // evidence: the entry is kept exactly as it is and the next maintenance
        // pass retries the same transition.
        return;
    };
    retain_terminal_close(states, digest, incarnation, receipt);
}

/// Derives the expiry receipt of one retired capture from retained evidence.
fn expiry_receipt(state: &SnapshotState) -> Option<SnapshotEndReceipt> {
    let (completeness, members_served, bytes_served) =
        closing_accounting(state, true, false).ok()?;
    build_end_receipt(state, completeness, members_served, bytes_served).ok()
}

/// Releases bounded terminal records whose replay horizon has ended.
///
/// This is the only place a capture entry is removed, and it removes only a
/// terminal record whose owner replay horizon has passed and whose no live claim
/// can still be using. A live capture, a claimed capture and a retained receipt
/// inside its horizon are all left alone.
fn release_expired_terminal_records(states: &mut HashMap<String, SnapshotState>, now_ms: u64) {
    let expired: Vec<String> = states
        .iter()
        .filter(|(_, state)| {
            state.claim.is_none()
                && state
                    .terminal
                    .as_ref()
                    .is_some_and(|closed| now_ms > closed.retained_until_ms)
        })
        .map(|(digest, _)| digest.clone())
        .collect();
    for digest in expired {
        states.remove(&digest);
    }
}

/// Reports whether one capture proved the complete authoritative denominator
/// and served all of it.
///
/// A complete capture requires the caller's declared completeness, a canonical
/// enumeration that actually ran, an authoritative known-zero when nothing was
/// observed, and exact served accounting. If the enumeration never ran, the
/// only legal completeness is partial — `SnapshotValidationReceipt::validate`
/// requires a complete authoritative denominator for a known-zero count.
///
/// A capture whose payload was already reclaimed cannot be complete: the
/// denominator it would have to prove is gone, and absence of a coverage record
/// means unknown, not complete.
fn is_complete_capture(state: &SnapshotState) -> bool {
    let enumeration_ran = state.enumeration.is_some();
    let known_zero = state
        .enumeration
        .is_some_and(EnumerationEvidence::is_authoritative_zero);
    let Some(payload) = state.payload.as_ref() else {
        return false;
    };
    state.begin.denominator.is_complete
        && enumeration_ran
        && payload.ordered_members.is_empty() == known_zero
        && state.members_served == payload.ordered_members.len() as u64
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
            .is_some_and(CaptureInterruption::window_closed);
    // A retained reason blocks completeness unless it is the single transient
    // read that a later exact reread of the original bound point resolved. A
    // terminal point movement or window expiry, and any reason recorded beside a
    // transient failure, keep the capture partial.
    let blocked = moved
        || state
            .interruption
            .as_ref()
            .is_some_and(CaptureInterruption::blocks_completeness);
    let completeness = if window_closed {
        SnapshotCompleteness::Expired
    } else if blocked {
        SnapshotCompleteness::Partial
    } else if is_complete_capture(state) {
        SnapshotCompleteness::Complete
    } else {
        SnapshotCompleteness::Partial
    };
    Ok((completeness, members_served, bytes_served))
}

/// Builds and validates the closing receipt from retained owner state.
///
/// The handle and the operation identity come from the retained owner-issued
/// state, never from the object the caller presented, so the receipt and its
/// operation identity describe the same capture by construction rather than by
/// agreement between two caller-reachable values.
fn build_end_receipt(
    state: &SnapshotState,
    completeness: SnapshotCompleteness,
    members_served: u64,
    bytes_served: u64,
) -> Result<SnapshotEndReceipt, StoreError> {
    let receipt = SnapshotEndReceipt {
        handle: state.issued.clone(),
        operation: state.begin.operation.clone(),
        member_count: members_served,
        byte_count: bytes_served,
        completeness,
        validation_revision: SNAPSHOT_VALIDATION_REVISION,
    };
    receipt.validate()?;
    Ok(receipt)
}

/// Freezes the terminal close result and releases the heavy payload.
///
/// The receipt is derived first and stored whole, so the retained evidence
/// always exists before the payload it was derived from is released: a crash or
/// a cancellation between the two leaves the capture live with its payload
/// still intact, never a closed capture with no record of what it served.
fn retain_terminal_close(
    states: &mut HashMap<String, SnapshotState>,
    digest: &str,
    incarnation: u64,
    receipt: SnapshotEndReceipt,
) {
    let Some(state) = states.get_mut(digest) else {
        return;
    };
    if state.incarnation != incarnation || state.terminal.is_some() {
        return;
    }
    // The replay horizon is the capture's own declared duration bound, not an
    // invented window: inside it an exact repeated end is answered from this
    // record, and after it maintenance releases the bounded record.
    let retained_until_ms = state
        .opened_at_ms
        .saturating_add(state.begin.bounds.max_duration_ms);
    state.payload = None;
    state.last_page = None;
    state.progress_revision = state.progress_revision.saturating_add(1);
    state.terminal = Some(RetainedClose {
        receipt,
        retained_until_ms,
    });
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
            claim: None,
            progress_revision: 1,
            payload: Some(CapturePayload { ordered_members }),
            last_page: None,
            terminal: None,
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

/// Records one interruption under `claim`, settles only that claim, and returns
/// `refusal`.
///
/// The exact partial evidence is merged before the claim is released, so an exit
/// that ends the capture always leaves the reason of record behind, and the
/// caller's counters can no longer move: the merge is only ever applied under a
/// claim this call still owns. Each reason keeps its own typed refusal, so a
/// structural bound still reports the bound rather than a generic refusal.
fn interrupt_capture(
    states: &mut HashMap<String, SnapshotState>,
    claim: &mut CaptureCallClaim,
    reason: InterruptionReason,
    refusal: StoreError,
) -> StoreError {
    merge_interruption(states, &claim.digest, claim.incarnation, reason);
    claim.settle(states);
    refusal
}

/// Slices the next page out of a drift-verified capture, advances its served
/// progress, and chains the predecessor digest. Runs under the registry lock
/// with no awaits inside.
///
/// The page's handle is read back from the retained owner-issued handle, never
/// from the object the caller presented: the caller has already been proven to
/// hold the issued identity, so echoing its own copy would prove nothing.
///
/// Only the claiming call can reach the counters, and the claim is settled after
/// the transition rather than before it, so the served page and the released
/// claim are one accounted step.
fn serve_next_page(
    states: &mut HashMap<String, SnapshotState>,
    claim: &mut CaptureCallClaim,
    cursor: SnapshotCursor,
) -> Result<SnapshotPage, StoreError> {
    let Some(state) = states.get(&claim.digest) else {
        return Err(unknown_snapshot_handle());
    };
    if state.incarnation != claim.incarnation {
        return Err(StoreError::IdentityConflict);
    }
    // A duplicate cursor can never advance twice: it must name exactly the next
    // unserved page with cumulative bounds intact.
    check_cursor(state, &cursor)?;
    let Some(payload) = state.payload.as_ref() else {
        // The payload was already reclaimed by the accounted terminal
        // transition. Absence of live payload must never create fresh capture
        // data under the old identity.
        return Err(StoreError::RevisionConflict);
    };
    // Served progress is contiguous from index zero, so the served member
    // count doubles as the next slice start; `try_from` keeps the
    // `u64`-to-`usize` conversion exact.
    let start = usize::try_from(state.members_served).map_err(|_| StoreError::PayloadTooLarge)?;
    let chunk = usize::try_from(SNAPSHOT_PAGE_CHUNK).map_err(|_| StoreError::PayloadTooLarge)?;
    let total_members = payload.ordered_members.len();
    let end = start.saturating_add(chunk).min(total_members);
    if start >= total_members || start >= end {
        // The observed set is exhausted. The exact partial evidence is recorded
        // instead of being deleted, so a closing receipt can still state what
        // was served.
        return Err(interrupt_capture(
            states,
            claim,
            InterruptionReason::CaptureExhausted,
            StoreError::Unavailable,
        ));
    }
    let members = payload.ordered_members[start..end].to_vec();
    let state = states.get(&claim.digest).ok_or(StoreError::Unavailable)?;
    let page_bytes = members.iter().fold(0_u64, |total, member| {
        total.saturating_add(member.residency.byte_count)
    });
    let cumulative_members = state.members_served.saturating_add(members.len() as u64);
    let cumulative_bytes = state.bytes_served.saturating_add(page_bytes);
    if cumulative_members > state.begin.bounds.max_members
        || cumulative_bytes > state.begin.bounds.max_bytes
        || cumulative_bytes > MAX_SNAPSHOT_BYTES
    {
        return Err(interrupt_capture(
            states,
            claim,
            InterruptionReason::PageBound,
            StoreError::PayloadTooLarge,
        ));
    }
    let is_last = end >= total_members;
    let next_cursor = if is_last {
        None
    } else {
        Some(SnapshotCursor {
            handle_digest: claim.digest.clone(),
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
    let state = states
        .get_mut(&claim.digest)
        .ok_or(StoreError::Unavailable)?;
    state.pages_served = state.pages_served.saturating_add(1);
    state.members_served = cumulative_members;
    state.bytes_served = cumulative_bytes;
    state.last_digest = page_digest;
    // The response this owner constructed is retained for a same-cursor replay,
    // so a page response the caller lost is answered with the exact page rather
    // than with a skipped cursor or zeroed counters. It is bounded by one page
    // and freed by the terminal transition.
    state.last_page = Some(page.clone());
    state.progress_revision = state.progress_revision.saturating_add(1);
    claim.settle(states);
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
/// What one page request found before any provider observation.
enum PageAdmission {
    /// The exact page this owner already constructed for this exact cursor. No
    /// provider I/O, no counter movement and no new capture data.
    Replay(SnapshotPage),
    /// A private claim over the capture that only this call may settle.
    Claimed(CaptureCallClaim),
}

/// Reports whether `cursor` is an exact repeat of the retained page response.
///
/// The response owner for a page is this module's own retained last page, so an
/// exact repeated cursor is answered from it. A cursor that is not an exact
/// repeat is not a replay: it falls through to `check_cursor`, which refuses it
/// rather than skipping forward, zeroing counters or recapturing data under the
/// old identity.
fn is_replay_cursor(page: &SnapshotPage, cursor: &SnapshotCursor) -> bool {
    page.cursor == *cursor
}

/// Validates one page request against the live capture without any provider
/// I/O, and acquires this call's claim. Runs under the registry lock with no
/// awaits inside.
///
/// The presented handle is resolved against the retained owner-issued handle
/// FIRST, and the claim is acquired only after that resolution. A mismatched
/// handle therefore advances no counter, records no interruption, takes no claim
/// and closes nothing; independent expiry maintenance also does not run for a
/// request that does not target a real capture under its own identity.
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
) -> Result<PageAdmission, StoreError> {
    let Some(state) = states.get(digest) else {
        return Err(unknown_snapshot_handle());
    };
    require_retained_handle(state, presented)?;
    let incarnation = state.incarnation;
    account_expired_captures(states, now_ms, digest);
    let state = states.get(digest).ok_or_else(unknown_snapshot_handle)?;
    if state.terminal.is_some() {
        // The capture is closed and retains only its terminal receipt. New page
        // delivery stops here: the payload is gone, and a page is never
        // fabricated for a closed capture.
        return Err(StoreError::RevisionConflict);
    }
    // An exact repeat of the last served cursor is answered from the retained
    // response even when the capture has since stopped being servable: the page
    // was already constructed and accounted, so returning it delivers no new
    // data and moves no counter.
    if let Some(page) = state.last_page.as_ref()
        && is_replay_cursor(page, cursor)
    {
        return Ok(PageAdmission::Replay(page.clone()));
    }
    if state.claim.is_some() {
        // Another call is inside its provider await for this capture. Its result
        // may still advance the progress this request would extend, so the
        // request reports a typed conflict instead of racing it.
        return Err(capture_claim_pending());
    }
    let retired = capture_is_retired(state, now_ms);
    let next_page = state.pages_served.saturating_add(1);
    let over_page_bound =
        next_page > state.begin.bounds.max_pages || next_page > MAX_SNAPSHOT_PAGES;
    let known_empty = state
        .payload
        .as_ref()
        .is_none_or(|payload| payload.ordered_members.is_empty());
    if retired {
        merge_interruption(
            states,
            digest,
            incarnation,
            InterruptionReason::WindowClosed,
        );
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
        merge_interruption(states, digest, incarnation, InterruptionReason::PageBound);
        return Err(StoreError::PayloadTooLarge);
    }
    let expected_revision = state.progress_revision;
    let claim_id = next_claim_id();
    let state = states.get_mut(digest).ok_or_else(unknown_snapshot_handle)?;
    state.claim = Some(CaptureClaimSlot {
        claim_id,
        kind: CaptureCallKind::Page,
        expected_revision,
    });
    Ok(PageAdmission::Claimed(CaptureCallClaim {
        digest: digest.to_owned(),
        incarnation,
        kind: CaptureCallKind::Page,
        claim_id,
        expected_revision,
        settled: false,
    }))
}

/// Re-verifies the bound point after the provider await and serves the page, or
/// records the exact partial evidence that ends the capture.
///
/// The claim is re-resolved against owner state, not only against the provider:
/// exact handle equality does not prove the entry was not replaced while the
/// await was in flight, so the incarnation, the claim slot, the request kind and
/// the expected progress revision are all re-checked. A claim that no longer
/// owns this entry annotates nothing and deletes nothing — its `Drop` can only
/// release a slot that still carries its own claim id, never a successor's.
fn finish_page(
    claim: &mut CaptureCallClaim,
    observed: &CapturePoint,
    cursor: SnapshotCursor,
) -> Result<SnapshotPage, StoreError> {
    let mut states = lock_registry()?;
    let (moved, retired, interrupted) = {
        let state = states
            .get(&claim.digest)
            .ok_or_else(unknown_snapshot_handle)?;
        resolve_claim(state, claim)?;
        (
            observed != &state.point,
            capture_is_retired(state, crate::write_execution::current_time_ms()),
            state.interruption.is_some(),
        )
    };
    if interrupted {
        // The capture was already interrupted between the pre-await validation
        // and this observation; the recorded evidence stands and this call
        // settles only its own claim.
        claim.settle(&mut states);
        return Err(StoreError::Unavailable);
    }
    if moved {
        // The source moved under the bound point: never mix a newer point, and
        // keep the exact partial evidence for the closing receipt.
        return Err(interrupt_capture(
            &mut states,
            claim,
            InterruptionReason::PointMoved,
            StoreError::Unavailable,
        ));
    }
    if retired {
        return Err(interrupt_capture(
            &mut states,
            claim,
            InterruptionReason::WindowClosed,
            StoreError::Unavailable,
        ));
    }
    // The point still holds and the capture is still live: serve the page, which
    // advances the progress and settles this claim as one accounted step.
    serve_next_page(&mut states, claim, cursor)
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
    let admission = {
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
    let mut claim = match admission {
        // The retained response answers an exact repeated cursor without any
        // provider read and without touching progress.
        PageAdmission::Replay(page) => return Ok(page),
        PageAdmission::Claimed(claim) => claim,
    };
    // No registry lock is held across this provider await (I5.7). The private
    // claim is the only in-flight ownership while it is: a future dropped here
    // releases exactly this claim and preserves every piece of prior evidence,
    // because a cancelled observation proves nothing about the source. Only a
    // provider failure that actually returns records an interruption, and it
    // records it under this claim before settling it.
    let observed = match observe_capture_point(adapter, SNAPSHOT_PAGE_OPERATION).await {
        Ok(point) => point,
        Err(error) => {
            record_provider_read_failure(&mut claim);
            return Err(error);
        }
    };
    finish_page(&mut claim, &observed, cursor)
}

/// Freezes the terminal close result of one claimed capture.
///
/// `observed` is `None` when the owner window had already closed: the point is
/// then deliberately not re-read, because a receipt must not claim the source
/// stayed still across a window this store no longer vouches for. No
/// stable-point receipt is ever fabricated from a failed or skipped
/// observation.
///
/// A fresh observation that equals the bound point exactly is the evidence that
/// a recorded provider failure was only a transport blip, so only that one
/// unresolved transient condition is resolved — after the recorded terminal
/// reasons, never instead of them. Every other interruption reason, and every
/// `moved`/`expired` observation, stays terminal, so a permanent interruption
/// followed by a transient failure and a successful reread can never be closed
/// `Complete`.
///
/// The claim is re-resolved after the provider await, exactly as the page path
/// does. Without that, a close that began against one capture would resolve a
/// successor's recorded interruption and issue a receipt built from the
/// successor's identity and counters.
fn close_capture(
    claim: &mut CaptureCallClaim,
    observed: Option<&CapturePoint>,
) -> Result<SnapshotEndReceipt, StoreError> {
    let mut states = lock_registry()?;
    let (expired, moved) = {
        let state = states
            .get(&claim.digest)
            .ok_or_else(unknown_snapshot_handle)?;
        resolve_claim(state, claim)?;
        (
            observed.is_none()
                || capture_is_retired(state, crate::write_execution::current_time_ms()),
            observed.is_some_and(|point| point != &state.point),
        )
    };
    if expired {
        merge_interruption(
            &mut states,
            &claim.digest,
            claim.incarnation,
            InterruptionReason::WindowClosed,
        );
    } else if moved {
        merge_interruption(
            &mut states,
            &claim.digest,
            claim.incarnation,
            InterruptionReason::PointMoved,
        );
    } else {
        // The bound point still holds on a fresh owner read, so a recorded
        // provider failure never observed anything about the source. A capture
        // that really did serve every member of its denominator closes
        // `Complete`; one that did not still closes `Partial` through
        // `is_complete_capture`.
        resolve_transient_read(&mut states, &claim.digest, claim.incarnation);
    }
    let receipt = {
        let state = states
            .get(&claim.digest)
            .ok_or_else(unknown_snapshot_handle)?;
        let (completeness, members_served, bytes_served) =
            closing_accounting(state, expired, moved)?;
        build_end_receipt(state, completeness, members_served, bytes_served)?
    };
    // The immutable result is frozen before the payload it was derived from is
    // released, and the claim is settled only after that accounted step.
    retain_terminal_close(
        &mut states,
        &claim.digest,
        claim.incarnation,
        receipt.clone(),
    );
    claim.settle(&mut states);
    Ok(receipt)
}

/// What one close request found before any provider observation.
enum CloseAdmission {
    /// The immutable terminal receipt this owner already issued, returned
    /// verbatim inside its replay horizon.
    Replay(SnapshotEndReceipt),
    /// A private claim over the capture, plus whether the owner window had
    /// already closed — in which case the bound point is deliberately not
    /// re-read.
    Claimed(CaptureCallClaim, bool),
}

/// Resolves a close request against the live owner entry and acquires its claim.
///
/// An exact repeated end is answered from the retained terminal record rather
/// than by observing the source again, so a lost close response replays the same
/// receipt inside its horizon. After the horizon the record is released and no
/// receipt is fabricated: the capture's payload is already gone, and a fresh
/// derivation would be a new claim about a capture that no longer exists.
fn prepare_close(
    states: &mut HashMap<String, SnapshotState>,
    digest: &str,
    presented: &SnapshotHandle,
    ctx: &RequestMeta,
    now_ms: u64,
) -> Result<CloseAdmission, StoreError> {
    let Some(state) = states.get(digest) else {
        return Err(unknown_snapshot_handle());
    };
    require_retained_handle(state, presented)?;
    let incarnation = state.incarnation;
    account_expired_captures(states, now_ms, digest);
    let state = states.get(digest).ok_or_else(unknown_snapshot_handle)?;
    if let Some(closed) = state.terminal.as_ref() {
        if now_ms > closed.retained_until_ms {
            return Err(StoreError::ReceiptNotFound);
        }
        return Ok(CloseAdmission::Replay(closed.receipt.clone()));
    }
    if state.claim.is_some() {
        // A page or end call is still inside its provider await for this
        // capture, so the final counts are not yet stable. Reporting them now
        // would state numbers a late page can still change.
        return Err(capture_claim_pending());
    }
    if ctx.state_fence != state.begin.scope.state_fence {
        return Err(StoreError::FenceMismatch);
    }
    let window_closed = capture_is_retired(state, now_ms);
    let expected_revision = state.progress_revision;
    let claim_id = next_claim_id();
    let state = states.get_mut(digest).ok_or_else(unknown_snapshot_handle)?;
    state.claim = Some(CaptureClaimSlot {
        claim_id,
        kind: CaptureCallKind::End,
        expected_revision,
    });
    Ok(CloseAdmission::Claimed(
        CaptureCallClaim {
            digest: digest.to_owned(),
            incarnation,
            kind: CaptureCallKind::End,
            claim_id,
            expected_revision,
            settled: false,
        },
        window_closed,
    ))
}

/// Closes a capture with an owner-issued end receipt.
///
/// The receipt is retained with the capture inside a bounded replay horizon, so
/// an exact repeated close replays it and the heavy payload is reclaimed instead
/// of the entry being deleted along with the only record of what was served.
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
    let admission = {
        let mut states = lock_registry()?;
        // The target request is resolved against the retained owner-issued
        // handle before any maintenance runs, so a mismatched handle accounts
        // nothing, interrupts nothing and closes nothing. The claim acquired
        // here is carried across the provider await.
        prepare_close(
            &mut states,
            &digest,
            &handle,
            ctx,
            crate::write_execution::current_time_ms(),
        )?
    };
    let (mut claim, window_closed) = match admission {
        CloseAdmission::Replay(receipt) => return Ok(receipt),
        CloseAdmission::Claimed(claim, window_closed) => (claim, window_closed),
    };
    let observed = if window_closed {
        // A closed window still owes the caller an exact receipt, and that
        // receipt must not claim the source stayed still across a window this
        // store no longer vouches for: the bound point is deliberately not
        // re-read.
        None
    } else {
        match observe_capture_point(adapter, SNAPSHOT_END_OPERATION).await {
            Ok(point) => Some(point),
            Err(error) => {
                // The close read failed, so no receipt can claim the point held
                // across this close. The exact evidence stays retained under
                // this claim, the caller may retry `end_snapshot`, and a
                // stable-point receipt is never fabricated from a failed read.
                record_provider_read_failure(&mut claim);
                return Err(error);
            }
        }
    };
    close_capture(&mut claim, observed.as_ref())
}
