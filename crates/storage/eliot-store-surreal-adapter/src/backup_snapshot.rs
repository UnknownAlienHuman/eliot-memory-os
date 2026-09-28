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
//! Aggregate admission is bounded, not just per capture. A per-capture limit
//! does not bound a process-lifetime registry, so this owner charges a finite
//! multidimensional budget vector ([`CaptureBudget`]) for begins in progress,
//! live captures, retained payload/metadata bytes, terminal/tombstone entries and
//! bytes, transient enumeration/response bytes, in-flight page/close calls and
//! expiry cleanup work. The vector and the capture map are fields of the *same*
//! value behind the *same* mutex, so a begin reserves before it enumerates and
//! concurrent begins cannot each pass an unlocked size check.
//!
//! That same acquisition also makes a logical begin single-owner. An in-progress
//! begin records a claim on the exact request digest *and* on the
//! operation/idempotency namespace it claims ([`BeginProgressClaim`]): a
//! concurrent identical begin is answered with the existing typed pending outcome
//! instead of enumerating a second observation and presenting it as the same
//! capture, and a different canonical input under an already claimed namespace is
//! refused as an identity conflict. A digest index alone cannot detect the second
//! case, which is why the claimed namespace travels with the entry and is
//! compared. A deliberate refresh therefore needs its own new logical capture —
//! it never resets the open one — and a replay after expiry or retirement keeps
//! its historical identity and cannot renew the window.
//!
//! What the charges are and are not. They are conservative, versioned *charges*
//! of the structures this owner retains, derived from the existing named
//! per-capture limits in `eliot_store_api::backup_io` plus
//! [`PER_MEMBER_CHARGE_BYTES`]; they are not a heap measurement and no RSS claim
//! is made from serialized size. The transport's only finite limit on the
//! enumeration call is `query_timeout_ms` in *time*: it carries no response
//! ceiling, and the whole provider response is already decoded into
//! `serde_json::Value` before this module sees any of it. That decode is
//! unbounded and nothing here bounds it. What is bounded is everything this
//! module builds on top of the decoded rows — see [`read_enumeration`] and
//! [`decoded_class_bytes`].
//!
//! Reclamation does not depend on client traffic. Every installed capture
//! registers a retirement deadline in the owner's expiry frontier
//! ([`CaptureRegistry::expiry`]), and every retained terminal record registers
//! its own bounded release deadline, so a bounded pass ([`run_expiry_pass`])
//! reclaims both by walking only the deadlines that have come due — never the
//! whole registry under the lock. That pass runs opportunistically from `begin`,
//! which a begin-only client still reaches, and from page/end, and the
//! supervised owner can drive the same entry point
//! ([`snapshot_owner_maintenance_tick`]) when no request arrives at all.
//! Retirement and evidence retention stay distinct: the heavy payload and the
//! retained page response are freed while identity, source point, served
//! accounting, interruption ledger and the final receipt survive, and the
//! terminal-record space a capture needs for that transition is reserved *before*
//! the capture is opened, so full normal capacity can never be the reason
//! cleanup cannot proceed. The map is process memory and nothing here is
//! restart-persistent.
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
    BlobResidency, BlobResidencyDomain, EcxfExportRequest, MAX_RECOVERY_RECORD_BYTES,
    MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_MEMBERS, MAX_SNAPSHOT_PAGE_MEMBERS, MAX_SNAPSHOT_PAGES,
    OperationId, OperationIdentity, OrderingHead, RequestMeta, RevisionHead, ScopeId,
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

/// One logical source class returned by the coherent ECXF source capture.
///
/// Each record is the canonical JSON encoding of the complete row returned by
/// the fixed `snapshot.members` batch. Records are sorted by the adapter-owned
/// logical member identity, not by provider row order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcxfSourceClassCapture {
    /// Stable logical class token from the adapter's closed source-class list.
    pub class_token: String,
    /// Canonical bytes for every observed row in this class.
    pub records: Vec<Vec<u8>>,
}

/// Why the observed source rows cannot currently prove a complete ECXF view.
///
/// These are explicit evidence gaps, not zero counts or empty source values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcxfCaptureGap {
    /// The adapter has no complete scope-to-record closure for the requested scope.
    RequestedScopeClosureUnproven,
    /// The admitted v2 schema does not capture the source erasure/purge ledger.
    SourcePurgeLedgerUnavailable,
    /// The adapter is not the `BlobStore` owner and cannot read sealed bytes or
    /// prove residency-key reachability.
    BlobStoreEvidenceUnavailable,
    /// Architecture and `NormativePair` source identity receipts are owned
    /// outside this adapter.
    ExternalSourceIdentityEvidenceUnavailable,
    /// The adapter has no durable source-side ECXF export receipt.
    SourceExportReceiptUnavailable,
}

/// Exact transaction observation available to the ECXF composition owner.
///
/// This carries real canonical source rows and the fence observed beside them,
/// while explicitly remaining partial. It must not be projected to a complete
/// ECXF source view until every `missing_evidence` item is supplied by its
/// owning component and the requested scope closure is established.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcxfSourceCapture {
    /// Requested logical operation identity for which the capture was requested.
    pub identity: OperationIdentity,
    /// Scope requested by the caller; its source closure is not yet proven.
    pub scope_id: ScopeId,
    /// State fence observed in the same fixed transaction as `source_classes`.
    pub state_fence: StateFence,
    /// Schema generation observed in that transaction.
    pub schema_generation: String,
    /// Next commit sequence observed in that transaction.
    pub next_commit_sequence: u64,
    /// Next outbox sequence observed in that transaction.
    pub next_outbox_sequence: u64,
    /// Provider rows retained as canonical JSON source bytes by logical class.
    pub source_classes: Vec<EcxfSourceClassCapture>,
    /// Completeness of the ECXF view, not merely success of the DB transaction.
    pub completeness: SnapshotCompleteness,
    /// Concrete evidence still required before export can be complete.
    pub missing_evidence: Vec<EcxfCaptureGap>,
}

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
    /// Blob-root owner, so no residency digest can be re-derived. `Some` also
    /// declares that the row carries a payload column the recorded digest
    /// attests, which `row_residency_digest` checks; `None` means the class has
    /// no owner-issued residency digest and the member carries the digest of its
    /// own captured canonical bytes.
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
    CanonicalSourceClass::OutsideAdmittedGeneration {
        table: crate::schema::table::LEARNING_RECORD,
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
    /// When the owner-issued window opened, observed *before* the expensive
    /// setup of the begin that installed this capture.
    ///
    /// Elapsed-duration accounting starts here, so a slow setup cannot grant a
    /// fresh insertion a new full duration.
    opened_at_ms: u64,
    /// Bytes this entry currently charges against the aggregate retained-byte
    /// dimension: the settled actual payload and retained-page allowance, or
    /// zero once the accounted terminal transition freed them. The begin's
    /// worst-case reservation is settled into this field at publish, and it is
    /// released only when the payload is actually freed or the entry removed.
    charged_capture_bytes: u64,
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

/// Conservative per-member retention charge, in bytes.
///
/// **No document names this value.** It is derived from the exact identifier
/// shapes this module builds — [`MEMBER_ID_VERSION`] (21 bytes) plus a class
/// token, plus a [`domain_key`] token, plus a 64-character SHA-256 digest, plus
/// one `content_digest` and one `residency_digest` string — and rounded up to
/// 512 bytes to cover the per-allocation headers, `String` capacities and `Vec`
/// element slots one member costs. It bounds a *charge*; it is not a heap
/// measurement and no RSS claim is made from it.
const PER_MEMBER_CHARGE_BYTES: u64 = 512;

/// Worst-case retained bytes one admitted capture may hold.
///
/// Derived entirely from existing named limits: [`MAX_SNAPSHOT_BYTES`] of
/// source content, plus the per-member identity allowance for a full
/// [`MAX_SNAPSHOT_MEMBERS`] denominator and for the one retained page response
/// at [`MAX_SNAPSHOT_PAGE_MEMBERS`]. This is the "worst-case admitted
/// allowance" a begin reserves before the provider is read, so a capture that
/// is admitted can never later exceed what admission already accounted for.
const RESERVED_CAPTURE_BYTES: u64 = MAX_SNAPSHOT_BYTES
    + (MAX_SNAPSHOT_MEMBERS as u64 * PER_MEMBER_CHARGE_BYTES)
    + RETAINED_PAGE_BYTES;

/// Bytes the one retained page response is charged.
///
/// Derived from the existing named per-page ceiling
/// [`MAX_SNAPSHOT_PAGE_MEMBERS`] × [`PER_MEMBER_CHARGE_BYTES`]: a live capture
/// holds at most one retained page response, and it is freed by the accounted
/// terminal transition.
const RETAINED_PAGE_BYTES: u64 = MAX_SNAPSHOT_PAGE_MEMBERS as u64 * PER_MEMBER_CHARGE_BYTES;

/// Worst-case transient enumeration/response bytes one in-progress begin holds.
///
/// Derived from the existing named content ceiling [`MAX_SNAPSHOT_BYTES`]: the
/// decoded provider enumeration is refused as soon as its observed rows exceed
/// it (see [`read_enumeration`]), so no admitted begin can transiently hold
/// more than this.
const RESERVED_ENUMERATION_BYTES: u64 = MAX_SNAPSHOT_BYTES;

/// Bytes one retained terminal/tombstone record is charged.
///
/// **No document names this value.** It is derived from the retained record's
/// own shape: the owner-issued handle's four identity strings, the operation
/// identity, the end receipt's counters and completeness tag, and the bounded
/// [`MAX_INTERRUPTION_REASONS`]-entry reason ledger — eight bounded strings at
/// [`PER_MEMBER_CHARGE_BYTES`] each, doubled to cover the registry key and the
/// receipt body, then rounded to 8 KiB.
const TERMINAL_ENTRY_BYTES: u64 = 8 * 1024;

/// Bounded capture begins that may hold a reservation at once.
///
/// **No document names this aggregate count.** Owner default: it admits
/// independent begin-only clients enough concurrency to make progress while
/// keeping the worst-case admitted allowance of
/// [`BUDGET_MAX_LIVE_CAPTURES`] × [`RESERVED_CAPTURE_BYTES`] the true ceiling
/// on concurrent enumeration work.
const BUDGET_MAX_BEGINS_IN_PROGRESS: u64 = 4;

/// Bounded live captures installed in the registry at once.
///
/// **No document names this aggregate count.** Owner default, chosen as the
/// smallest value that keeps a real backup session (open, several pages, close)
/// serviceable next to a second one while still bounding the retained set to
/// [`BUDGET_MAX_RETAINED_BYTES`].
const BUDGET_MAX_LIVE_CAPTURES: u64 = 8;

/// Bounded retained capture payload and metadata bytes.
///
/// **No document names this aggregate byte budget.** Owner default: exactly the
/// worst-case allowance of every live capture, so the retained-byte dimension
/// is derived from [`RESERVED_CAPTURE_BYTES`] rather than chosen independently.
const BUDGET_MAX_RETAINED_BYTES: u64 = BUDGET_MAX_LIVE_CAPTURES * RESERVED_CAPTURE_BYTES;

/// Bounded retained terminal/tombstone entries.
///
/// **No document names this aggregate count.** Owner default, four times
/// [`BUDGET_MAX_LIVE_CAPTURES`]: every live capture holds its terminal-record
/// space from begin, so a saturated registry can still close every capture it
/// admitted instead of being unable to reclaim one.
const BUDGET_MAX_TERMINAL_ENTRIES: u64 = 4 * BUDGET_MAX_LIVE_CAPTURES;

/// Bounded retained terminal/tombstone bytes.
///
/// Derived from [`BUDGET_MAX_TERMINAL_ENTRIES`] × [`TERMINAL_ENTRY_BYTES`], so
/// the byte dimension is never chosen independently of the entry dimension.
const BUDGET_MAX_TERMINAL_BYTES: u64 = BUDGET_MAX_TERMINAL_ENTRIES * TERMINAL_ENTRY_BYTES;

/// Bounded page/close calls in flight across the whole registry.
///
/// **No document names this aggregate count.** Owner default, twice the live
/// capture ceiling: every live capture admits exactly one in-flight claim, so
/// this dimension is the aggregate statement of that per-capture rule and is
/// never the tighter of the two.
const BUDGET_MAX_ACTIVE_PAGE_CALLS: u64 = 2 * BUDGET_MAX_LIVE_CAPTURES;

/// Bounded expiry work one maintenance pass may perform.
///
/// **No document names this value.** Owner default: the pass walks only the
/// deadlines that have actually come due, so this bounds the pass without
/// bounding the registry.
const BUDGET_MAX_CLEANUP_STEPS: u64 = 32;

/// The one dimension this owner accounts separately, and the exact static field
/// a refusal of it names.
///
/// I14.3: "Reserve accounting is multidimensional. Admission checks the exact
/// bottleneck vector rather than one scalar percentage; exhaustion of CPU,
/// memory, pipe bytes, ORS writes, disk queue or handles may independently close
/// normal/background admission while preserving the applicable recovery/control
/// lane. Each disposition names the exhausted resource and the work shed,
/// deferred or quarantined." The field names the resource; the paired reason
/// names the work that was shed and the condition that makes a retry valid.
///
/// The `snapshot.budget.v1.` prefix in every field below is the versioned
/// identity of this charge model, I5.27: "Canonical
/// encoding is deterministic and versioned". A refusal therefore names both the
/// exhausted dimension and the charge model that refused it, so a future
/// re-version of the vector cannot be read as the same verdict. The version is
/// carried by the field name alone: this module mints no extra signature,
/// digest, receipt, nonce or generation to carry it.
#[derive(Clone, Copy, Eq, PartialEq)]
enum BudgetDimension {
    /// Begins holding a reservation but not yet installed.
    BeginsInProgress,
    /// Installed captures still holding a member payload.
    LiveCaptures,
    /// Retained member payload and metadata bytes.
    RetainedBytes,
    /// Retained terminal/tombstone entries.
    TerminalEntries,
    /// Retained terminal/tombstone bytes.
    TerminalBytes,
    /// Transient enumeration/response bytes held by an in-progress begin.
    EnumerationBytes,
    /// Page/close calls currently inside their provider await.
    ActivePageCalls,
    /// Expiry maintenance work one pass may still perform.
    CleanupSteps,
}

impl BudgetDimension {
    /// The exact exhausted dimension named in the bounded error surface.
    const fn field(self) -> &'static str {
        match self {
            Self::BeginsInProgress => "snapshot.budget.v1.begins_in_progress",
            Self::LiveCaptures => "snapshot.budget.v1.live_captures",
            Self::RetainedBytes => "snapshot.budget.v1.retained_bytes",
            Self::TerminalEntries => "snapshot.budget.v1.terminal_entries",
            Self::TerminalBytes => "snapshot.budget.v1.terminal_bytes",
            Self::EnumerationBytes => "snapshot.budget.v1.enumeration_bytes",
            Self::ActivePageCalls => "snapshot.budget.v1.active_page_calls",
            Self::CleanupSteps => "snapshot.budget.v1.cleanup_steps",
        }
    }

    /// The retry/cleanup condition that makes a retry of this dimension valid.
    const fn reason(self) -> &'static str {
        match self {
            Self::BeginsInProgress => {
                "concurrent capture begins hold every in-progress slot; retry once a begin publishes or is refused"
            }
            Self::LiveCaptures => {
                "every live capture slot is reserved or installed; close a capture or let one expire, then retry"
            }
            Self::RetainedBytes => {
                "retained capture bytes are saturated; close a capture or let one expire to free its payload, then retry"
            }
            Self::TerminalEntries => {
                "retained terminal record slots are saturated; retry once an expired terminal record is released"
            }
            Self::TerminalBytes => {
                "retained terminal record bytes are saturated; retry once an expired terminal record is released"
            }
            Self::EnumerationBytes => {
                "in-progress enumerations hold every transient byte slot; retry once one publishes or is refused"
            }
            Self::ActivePageCalls => {
                "in-flight page and close calls hold every call slot; retry once one settles"
            }
            Self::CleanupSteps => {
                "one bounded expiry maintenance pass is saturated; retry on a later begin or supervised tick"
            }
        }
    }
}

/// Names one exhausted budget dimension and its valid retry condition.
fn budget_refusal(dimension: BudgetDimension) -> StoreError {
    StoreError::InvalidField {
        field: dimension.field(),
        reason: dimension.reason(),
    }
}

/// Static error field for capture accounting that can no longer be trusted.
const CAPTURE_BUDGET_UNUSABLE_FIELD: &str = "snapshot.budget.v1.accounting";

/// Static error reason for capture accounting that can no longer be trusted.
///
/// The refusal closes new admission. It never certifies zero usage: no counter
/// is reset and no entry is cleared to recover availability.
const CAPTURE_BUDGET_UNUSABLE_REASON: &str = "capture accounting could not be reconciled; new admission stays closed and the recorded charges are unchanged";

/// One finite, owner-issued budget dimension: a hard limit and a running charge.
struct Charge {
    dimension: BudgetDimension,
    limit: u64,
    charged: u64,
}

impl Charge {
    const fn new(dimension: BudgetDimension, limit: u64) -> Self {
        Self {
            dimension,
            limit,
            charged: 0,
        }
    }

    /// Reserves `units`, refusing rather than overcommitting.
    ///
    /// Checked arithmetic: a reservation that would overflow is a refusal, never
    /// a wrapped charge that understates the load.
    fn reserve(&mut self, units: u64) -> Result<(), StoreError> {
        let next = self
            .charged
            .checked_add(units)
            .ok_or_else(|| budget_refusal(self.dimension))?;
        if next > self.limit {
            return Err(budget_refusal(self.dimension));
        }
        self.charged = next;
        Ok(())
    }

    /// Releases `units` this owner actually held.
    ///
    /// `false` means the release exceeded the recorded charge, which is an
    /// ownership or reconciliation defect. It is never absorbed: the recorded
    /// charge is left exactly as it is — never zeroed — so the defect stays
    /// visible instead of becoming fabricated headroom.
    fn release(&mut self, units: u64) -> bool {
        if units > self.charged {
            return false;
        }
        self.charged -= units;
        true
    }

    /// Settles a worst-case reservation to the charge actually transferred.
    ///
    /// The actual charge is always at most the reservation, so this can only
    /// shrink the dimension; it never grows it and never re-arms headroom a
    /// caller already exhausted.
    fn settle_to(&mut self, reserved: u64, actual: u64) {
        debug_assert!(
            actual <= reserved,
            "a settled charge may only shrink below its worst-case reservation"
        );
        self.charged = self.charged.saturating_sub(reserved);
        self.charged = self.charged.saturating_add(actual.min(reserved));
    }
}

/// The finite aggregate budget vector this owner accounts against.
///
/// One value, guarded by the same mutex as the capture map: there is no second
/// lock, no second registry and no second writer. Admission reads and charges
/// this vector under that one lock, so two concurrent begins cannot both pass
/// an unlocked size check.
struct CaptureBudget {
    begins_in_progress: Charge,
    live_captures: Charge,
    retained_bytes: Charge,
    terminal_entries: Charge,
    terminal_bytes: Charge,
    enumeration_bytes: Charge,
    active_page_calls: Charge,
    cleanup_steps: Charge,
    /// Sticky: set when a charge could not be reconciled. New admission stays
    /// closed until the process restarts, and no counter is reset to recover
    /// availability.
    unusable: bool,
}

impl CaptureBudget {
    /// The finite validated owner default. Never an unlimited fallback: every
    /// dimension is a literal finite limit, and the two derived byte dimensions
    /// are computed from the named per-capture limits above.
    const fn owner_default() -> Self {
        Self {
            begins_in_progress: Charge::new(
                BudgetDimension::BeginsInProgress,
                BUDGET_MAX_BEGINS_IN_PROGRESS,
            ),
            live_captures: Charge::new(BudgetDimension::LiveCaptures, BUDGET_MAX_LIVE_CAPTURES),
            retained_bytes: Charge::new(BudgetDimension::RetainedBytes, BUDGET_MAX_RETAINED_BYTES),
            terminal_entries: Charge::new(
                BudgetDimension::TerminalEntries,
                BUDGET_MAX_TERMINAL_ENTRIES,
            ),
            terminal_bytes: Charge::new(BudgetDimension::TerminalBytes, BUDGET_MAX_TERMINAL_BYTES),
            enumeration_bytes: Charge::new(
                BudgetDimension::EnumerationBytes,
                BUDGET_MAX_LIVE_CAPTURES * RESERVED_ENUMERATION_BYTES,
            ),
            active_page_calls: Charge::new(
                BudgetDimension::ActivePageCalls,
                BUDGET_MAX_ACTIVE_PAGE_CALLS,
            ),
            cleanup_steps: Charge::new(BudgetDimension::CleanupSteps, BUDGET_MAX_CLEANUP_STEPS),
            unusable: false,
        }
    }

    /// Reserves `units` against one dimension.
    fn reserve(&mut self, dimension: BudgetDimension, units: u64) -> Result<(), StoreError> {
        self.charge_mut(dimension).reserve(units)
    }

    /// Releases `units` against one dimension, or marks accounting unusable.
    ///
    /// A release larger than the recorded charge never zeroes anything: the
    /// charge stands and admission closes (I14.3 fail-closed).
    fn release(&mut self, dimension: BudgetDimension, units: u64) {
        if !self.charge_mut(dimension).release(units) {
            self.unusable = true;
        }
    }

    /// Fails closed when the accounting itself cannot be trusted.
    fn refuse_if_unusable(&self) -> Result<(), StoreError> {
        if self.unusable {
            return Err(StoreError::InvalidField {
                field: CAPTURE_BUDGET_UNUSABLE_FIELD,
                reason: CAPTURE_BUDGET_UNUSABLE_REASON,
            });
        }
        Ok(())
    }

    fn charge_mut(&mut self, dimension: BudgetDimension) -> &mut Charge {
        match dimension {
            BudgetDimension::BeginsInProgress => &mut self.begins_in_progress,
            BudgetDimension::LiveCaptures => &mut self.live_captures,
            BudgetDimension::RetainedBytes => &mut self.retained_bytes,
            BudgetDimension::TerminalEntries => &mut self.terminal_entries,
            BudgetDimension::TerminalBytes => &mut self.terminal_bytes,
            BudgetDimension::EnumerationBytes => &mut self.enumeration_bytes,
            BudgetDimension::ActivePageCalls => &mut self.active_page_calls,
            BudgetDimension::CleanupSteps => &mut self.cleanup_steps,
        }
    }
}

/// One retirement/release deadline a capture owes the expiry frontier.
///
/// The frontier is a deadline index, not a cursor: a pass reads only the
/// deadlines that have actually come due, so the whole registry is never walked
/// under the lock on any call. An entry that a pass cannot act on yet stays in
/// the index, so a sweep can never silently forget it.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct ExpiryDeadline {
    at_ms: u64,
    stage: ExpiryStage,
    digest: String,
}

/// Which accounted step a due deadline authorises.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum ExpiryStage {
    /// The owner window closed: run the accounted payload-to-terminal transition.
    Retire,
    /// The retained terminal record's replay horizon ended: release the entry.
    Release,
}

/// Computes a fail-closed deadline from an observed base and a declared span.
///
/// An overflow means the observation is not trustworthy, so the deadline comes
/// due immediately rather than never. `saturating_add` would return
/// `u64::MAX` and make the entry permanently un-retirable, which is exactly the
/// unbounded lease this refuses.
fn fail_closed_deadline(base_ms: u64, span_ms: u64) -> u64 {
    base_ms.checked_add(span_ms).unwrap_or(0)
}

/// The module-private capture registry, its aggregate budget and its expiry
/// frontier — one mutable owner behind one mutex.
///
/// The map is reached through `Deref`/`DerefMut` so the existing entry-level
/// transitions read exactly as they always did; the budget and the frontier are
/// additional fields of the *same* value, guarded by the *same* lock. There is
/// deliberately no second lock, no second registry and no second writer. The
/// in-progress begin index is such a field too, for the same reason: one
/// acquisition resolves the retained decision, records the claim and reserves the
/// allowance, so a begin cannot be admitted twice.
struct CaptureRegistry {
    captures: HashMap<String, SnapshotState>,
    /// Logical begins that hold an in-progress claim and are not yet installed.
    begins_in_progress: HashMap<String, BeginProgressClaim>,
    budget: CaptureBudget,
    /// Ordered deadlines so a maintenance pass is bounded by the work that is
    /// actually due, not by the size of the registry.
    expiry: std::collections::BTreeSet<ExpiryDeadline>,
}

impl std::ops::Deref for CaptureRegistry {
    type Target = HashMap<String, SnapshotState>;

    fn deref(&self) -> &Self::Target {
        &self.captures
    }
}

impl std::ops::DerefMut for CaptureRegistry {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.captures
    }
}

/// Module-private capture registry keyed by handle digest.
fn registry() -> &'static Mutex<CaptureRegistry> {
    static REGISTRY: OnceLock<Mutex<CaptureRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        Mutex::new(CaptureRegistry {
            captures: HashMap::new(),
            begins_in_progress: HashMap::new(),
            budget: CaptureBudget::owner_default(),
            expiry: std::collections::BTreeSet::new(),
        })
    })
}

fn lock_registry() -> Result<std::sync::MutexGuard<'static, CaptureRegistry>, StoreError> {
    registry().lock().map_err(|_| StoreError::Unavailable)
}

/// One in-flight begin's claim on a logical begin that is not yet installed.
///
/// The index is keyed by the exact request digest, so an identical begin finds
/// its entry and learns the logical begin is already owned. A digest key alone
/// cannot see a *different* canonical input claiming the same
/// operation/idempotency namespace, so the claimed namespace travels with the
/// entry and the namespace check compares it — that comparison is what makes
/// "changed input under the same logical begin" a conflict rather than a second
/// capture.
///
/// An entry exists only while its owning begin is in flight. It cannot be
/// replaced while held: a begin records its claim only after finding neither an
/// installed capture nor a live claim under its digest, and only that same begin
/// removes it.
struct BeginProgressClaim {
    /// The operation identity the owning begin claimed.
    operation_id: OperationId,
    /// The idempotency key the owning begin claimed.
    idempotency_key: String,
}

/// Reserves one genuinely new begin's whole allowance and its in-progress claim,
/// atomically.
///
/// Every dimension is reserved under the one registry lock the caller already
/// holds, so two concurrent distinct begins cannot both pass an unlocked size
/// check: the second observes the first's charges and is refused with the exact
/// exhausted dimension. The units reserved here are, in order:
///
/// * one in-progress begin;
/// * one live-capture slot;
/// * the worst-case admitted allowance of [`RESERVED_CAPTURE_BYTES`];
/// * the worst-case transient enumeration allowance of
///   [`RESERVED_ENUMERATION_BYTES`];
/// * one terminal-record entry *and* its bytes, so a registry whose normal
///   capacity is full can still complete the payload-to-terminal transition for
///   every capture it admitted.
///
/// The in-progress claim is recorded last, after every charge succeeded, so a
/// begin refused by the budget leaves no claim behind and can never wedge the
/// logical begin it did not own.
fn reserve_begin(
    registry: &mut CaptureRegistry,
    digest: &str,
    request: &SnapshotBeginRequest,
) -> Result<BeginReservation, StoreError> {
    let budget = &mut registry.budget;
    budget.reserve(BudgetDimension::BeginsInProgress, 1)?;
    if let Err(error) = reserve_capture_units(budget) {
        budget.release(BudgetDimension::BeginsInProgress, 1);
        return Err(error);
    }
    registry.begins_in_progress.insert(
        digest.to_owned(),
        BeginProgressClaim {
            operation_id: request.operation.operation_id.clone(),
            idempotency_key: request.operation.idempotency_key.clone(),
        },
    );
    Ok(BeginReservation {
        digest: digest.to_owned(),
        capture_bytes: RESERVED_CAPTURE_BYTES,
        settled: false,
    })
}

/// Reserves the four per-capture dimensions a begin owns, in a fixed order.
///
/// Split from [`reserve_begin`] only so the already-taken in-progress unit can
/// be returned exactly once on the failure path; both run inside the one
/// acquisition.
fn reserve_capture_units(budget: &mut CaptureBudget) -> Result<(), StoreError> {
    budget.reserve(BudgetDimension::LiveCaptures, 1)?;
    if let Err(error) = budget.reserve(BudgetDimension::RetainedBytes, RESERVED_CAPTURE_BYTES) {
        budget.release(BudgetDimension::LiveCaptures, 1);
        return Err(error);
    }
    if let Err(error) = budget.reserve(
        BudgetDimension::EnumerationBytes,
        RESERVED_ENUMERATION_BYTES,
    ) {
        budget.release(BudgetDimension::RetainedBytes, RESERVED_CAPTURE_BYTES);
        budget.release(BudgetDimension::LiveCaptures, 1);
        return Err(error);
    }
    // Terminal-record space is reserved *before* the capture is opened, so full
    // normal capacity can never be the reason a cleanup cannot proceed.
    budget.reserve(BudgetDimension::TerminalEntries, 1)?;
    if let Err(error) = budget.reserve(BudgetDimension::TerminalBytes, TERMINAL_ENTRY_BYTES) {
        budget.release(BudgetDimension::TerminalEntries, 1);
        budget.release(
            BudgetDimension::EnumerationBytes,
            RESERVED_ENUMERATION_BYTES,
        );
        budget.release(BudgetDimension::RetainedBytes, RESERVED_CAPTURE_BYTES);
        budget.release(BudgetDimension::LiveCaptures, 1);
        return Err(error);
    }
    Ok(())
}

/// The units and the in-progress claim one begin holds, released or transferred
/// exactly once.
///
/// The reservation is taken before the provider is read and owned across that
/// await. It is not `Clone` and no registry mutex is ever held across the await
/// it spans (I5.7); a future dropped here releases exactly its own units and
/// claim and touches nothing else in the registry.
///
/// Every path settles it exactly once: rejection, cancellation, a
/// publish-versus-cancel race and the publish-time duplicate that answers from a
/// successor's retained handle all reach `Drop` armed, and only a successful
/// publish reaches [`BeginReservation::settle`].
struct BeginReservation {
    /// The exact request digest this begin claimed, the in-progress index key.
    digest: String,
    /// Bytes this reservation holds against the retained-byte dimension.
    capture_bytes: u64,
    /// Set once the units and the claim have been transferred to an installed
    /// capture.
    settled: bool,
}

impl BeginReservation {
    /// Transfers the reservation to the capture just installed.
    ///
    /// The retained-byte dimension settles from the worst-case admitted
    /// allowance down to the actual retained charge, which can only shrink it.
    /// The transient enumeration allowance is released, because the decoded
    /// observation is dropped before the member payload is installed. The
    /// in-progress unit and the in-progress claim are released together with the
    /// publish, because the installed capture now owns this logical begin; a
    /// replay arriving after this point reads the retained handle instead of an
    /// in-progress claim. The live-capture slot and the reserved terminal-record
    /// space are *kept* charged: they are the installed capture's own units now,
    /// and the entry releases them when its payload is actually freed and when the
    /// entry is actually removed.
    fn settle(&mut self, states: &mut CaptureRegistry, actual_capture_bytes: u64) {
        release_begin_claim(states, &self.digest);
        states
            .budget
            .retained_bytes
            .settle_to(self.capture_bytes, actual_capture_bytes);
        self.capture_bytes = actual_capture_bytes;
        states.budget.release(
            BudgetDimension::EnumerationBytes,
            RESERVED_ENUMERATION_BYTES,
        );
        states.budget.release(BudgetDimension::BeginsInProgress, 1);
        self.settled = true;
    }
}

impl Drop for BeginReservation {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        // Poisoned accounting is an observable recovery limitation, not
        // successful cleanup: the units and the claim stay recorded, so
        // admission stays backpressured and the logical begin stays claimed
        // rather than silently gaining headroom or admitting a second begin over
        // a capture whose owner can no longer be named.
        let Ok(mut registry) = registry().lock() else {
            return;
        };
        release_begin_claim(&mut registry, &self.digest);
        release_capture_units(&mut registry.budget, self.capture_bytes);
        registry
            .budget
            .release(BudgetDimension::BeginsInProgress, 1);
    }
}

/// Removes exactly one in-progress begin's claim, and nothing else.
///
/// An entry is inserted only when the digest is unclaimed and is removed only by
/// the begin that inserted it, so this can neither release a concurrent begin's
/// claim nor clear one that was never recorded.
fn release_begin_claim(registry: &mut CaptureRegistry, digest: &str) {
    registry.begins_in_progress.remove(digest);
}

/// Returns every unit a begin reservation owns, in the reverse of the order it
/// was taken.
fn release_capture_units(budget: &mut CaptureBudget, capture_bytes: u64) {
    budget.release(BudgetDimension::TerminalBytes, TERMINAL_ENTRY_BYTES);
    budget.release(BudgetDimension::TerminalEntries, 1);
    budget.release(
        BudgetDimension::EnumerationBytes,
        RESERVED_ENUMERATION_BYTES,
    );
    budget.release(BudgetDimension::RetainedBytes, capture_bytes);
    budget.release(BudgetDimension::LiveCaptures, 1);
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
    states: &CaptureRegistry,
    digest: &str,
    request: &SnapshotBeginRequest,
) -> Result<Option<SnapshotHandle>, StoreError> {
    for (claimed, state) in &states.captures {
        if claimed != digest
            && state.issued.operation_id == request.operation.operation_id
            && state.issued.idempotency_key == request.operation.idempotency_key
        {
            return Err(StoreError::IdentityConflict);
        }
    }
    Ok(states
        .captures
        .get(digest)
        .map(|state| state.issued.clone()))
}

/// Resolves a begin against the in-progress claims the owner already holds.
///
/// This is the in-flight half of [`retained_begin_handle`]: the registry entry
/// answers a replay of an *installed* capture, this answers a concurrent second
/// begin of a logical capture whose owner is still enumerating. `Ok(())` means
/// the logical begin is unclaimed and the caller may open it.
///
/// Two refusals, both already-typed and both reached before any enumeration:
///
/// * a different canonical input under an already claimed
///   operation/idempotency namespace is [`StoreError::IdentityConflict`]. This
///   is the I5.27 rule — "Reusing an idempotency key with a different canonical
///   request hash returns `IDENTITY_CONFLICT` and performs no transition" — and
///   the digest key alone cannot detect it, which is why the claimed namespace
///   travels with the entry and is compared here.
/// * the exact repeated begin whose owner is still enumerating is
///   [`capture_claim_pending`], the same typed pending outcome a page or end call
///   gets while it does not own the capture's current progress. Its owner has
///   issued no handle yet, so the honest answer is that the capture is pending:
///   re-enumerating current data here would present a second observation as the
///   old capture, and returning a handle derived from it would hand out an
///   identity this owner never issued.
fn claim_begin(
    states: &CaptureRegistry,
    digest: &str,
    request: &SnapshotBeginRequest,
) -> Result<(), StoreError> {
    for (claimed, progress) in &states.begins_in_progress {
        if claimed != digest
            && progress.operation_id == request.operation.operation_id
            && progress.idempotency_key == request.operation.idempotency_key
        {
            return Err(StoreError::IdentityConflict);
        }
    }
    if states.begins_in_progress.contains_key(digest) {
        return Err(capture_claim_pending());
    }
    Ok(())
}

/// Reports whether a capture can no longer serve: owner expiry passed (or
/// non-positive, which is fail-closed expired) or the capture duration bound
/// is overrun. `try_from` keeps the `i64` expiry conversion exact.
///
/// Both deadline conventions of this module are preserved exactly as they
/// already were: the absolute expiry is **inclusive** — a capture whose expiry
/// equals the observation is still live — and the terminal replay horizon is
/// **exclusive**, released only once the observation is strictly past it.
///
/// A backward or unknown clock observation is fail-closed expired rather than
/// granted a fresh duration. `saturating_sub` would map a backward reading to
/// zero elapsed time and hand the capture another full lease on every step, so
/// the direction is checked explicitly instead.
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
    if now_ms < opened_at_ms {
        return true;
    }
    now_ms - opened_at_ms > max_duration_ms
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

/// Refuses a request whose claimed source is not this adapter's own admitted
/// store, before any protected read happens.
///
/// These two quarters need no observation at all: the active store and
/// installation identities are pure configuration
/// (`active_store_identity` returns `(config.database, config.installation_id)`).
/// They are therefore decidable from the adapter's own config alone, and I5.6
/// admission step 2 ("validate schema, envelope, size and canonical request
/// identity") together with step 7 ("normalize paths/resources and
/// privacy/source visibility") requires them to be *refused*, not detected after
/// the fact. Leaving them to run only after the canonical member batch would let
/// all nine member classes be read from the provider and materialised in memory
/// before a request naming a foreign database is refused — a real but late
/// refusal, late by exactly one protected read.
///
/// [`bind_source_identity`] calls this as its first step, so the rule has one
/// owner: the two comparisons are not restated there, and the observed quarters
/// (schema generation and state fence) still run after the capture point exists,
/// because only a live observation can decide those.
fn check_active_source_identity(
    adapter: &SurrealStoreAdapter,
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
    Ok(())
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
    check_active_source_identity(adapter, request)?;
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
    let mut observed_bytes: u64 = 0;
    for offset in 0..captured_member_classes().count() {
        let offset = offset + 3;
        let class_rows: Vec<Map<String, Value>> = response
            .take(offset)
            .map_err(AdapterError::into_store_error)
            .map_err(redact_snapshot_error)?;
        if class_rows.len() > crate::client::MEMBER_CLASS_ROW_LIMIT {
            return Err(StoreError::PayloadTooLarge);
        }
        // The transient size bound, enforced here — at the observation boundary,
        // before any further materialization. The decoded observation is charged
        // and checked against the existing named content ceiling
        // [`MAX_SNAPSHOT_BYTES`] as each class arrives, so a store larger than the
        // supported capture is refused as a whole rather than truncated into a
        // smaller-but-complete-looking denominator.
        observed_bytes = observed_bytes.saturating_add(decoded_class_bytes(&class_rows));
        if observed_bytes > MAX_SNAPSHOT_BYTES {
            return Err(StoreError::PayloadTooLarge);
        }
        rows.push(class_rows);
    }
    Ok((point, rows))
}

/// Captures the adapter-owned canonical source rows and their exact fence for
/// an ECXF request.
///
/// The rows and fence come from the same fixed `BEGIN`/`COMMIT` member batch.
/// Caller values never enter the provider statement. The request's scope is
/// retained but not treated as a filter: this adapter cannot prove the full
/// scope-to-record closure, so the returned capture is always explicitly
/// `Partial` and lists the missing purge, `BlobStore` and external identity
/// evidence. The ECXF exporter must refuse to build or publish from it until
/// those gaps are resolved by their owners.
pub async fn capture_ecxf_source(
    adapter: &SurrealStoreAdapter,
    request: &EcxfExportRequest,
) -> Result<EcxfSourceCapture, StoreError> {
    request.validate()?;
    bind_capture_principal(adapter, crate::client::SNAPSHOT_MEMBERS_OPERATION)?;
    verify_canonical_source_classes(adapter.config.expected_schema_generation.as_str())?;

    let (point, class_rows) = read_enumeration(adapter).await?;
    if point.schema_generation != adapter.config.expected_schema_generation.as_str() {
        return Err(StoreError::Unavailable);
    }
    if point.state_fence != request.context.state_fence {
        return Err(StoreError::FenceMismatch);
    }

    let mut total_source_bytes = 0_u64;
    let source_classes = captured_member_classes()
        .zip(class_rows)
        .map(|(class, rows)| {
            let records = canonical_source_rows(class, &rows)?;
            for record in &records {
                total_source_bytes = total_source_bytes.saturating_add(
                    u64::try_from(record.len()).map_err(|_| StoreError::PayloadTooLarge)?,
                );
                if total_source_bytes > MAX_SNAPSHOT_BYTES {
                    return Err(StoreError::PayloadTooLarge);
                }
            }
            Ok(EcxfSourceClassCapture {
                class_token: class.token.to_owned(),
                records,
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;

    Ok(EcxfSourceCapture {
        identity: request.identity.clone(),
        scope_id: request.scope_id.clone(),
        state_fence: point.state_fence,
        schema_generation: point.schema_generation,
        next_commit_sequence: point.next_commit_sequence,
        next_outbox_sequence: point.next_outbox_sequence,
        source_classes,
        completeness: SnapshotCompleteness::Partial,
        missing_evidence: vec![
            EcxfCaptureGap::RequestedScopeClosureUnproven,
            EcxfCaptureGap::SourcePurgeLedgerUnavailable,
            EcxfCaptureGap::BlobStoreEvidenceUnavailable,
            EcxfCaptureGap::ExternalSourceIdentityEvidenceUnavailable,
            EcxfCaptureGap::SourceExportReceiptUnavailable,
        ],
    })
}

/// Produces deterministic canonical row bytes under the adapter-owned member
/// identity and refuses duplicate identities instead of preserving ambiguous
/// provider ordering as apparent source order.
fn canonical_source_rows(
    class: &MemberClass,
    rows: &[Map<String, Value>],
) -> Result<Vec<Vec<u8>>, StoreError> {
    let mut observed_bytes = 0_u64;
    let mut identified = rows
        .iter()
        .map(|row| {
            let member_id = row_member_id(class, row)?;
            let bytes = canonical_json_bytes(row).map_err(snapshot_serialization_error)?;
            observed_bytes = observed_bytes.saturating_add(
                u64::try_from(bytes.len()).map_err(|_| StoreError::PayloadTooLarge)?,
            );
            if observed_bytes > MAX_SNAPSHOT_BYTES {
                return Err(StoreError::PayloadTooLarge);
            }
            Ok((member_id, bytes))
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    identified.sort_by(|left, right| left.0.cmp(&right.0));
    if identified.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(StoreError::Duplicate {
            field: "ecxf.source_rows",
        });
    }
    Ok(identified.into_iter().map(|(_, bytes)| bytes).collect())
}

/// Charges the decoded representation of one provider class result.
///
/// This is a *charge*, not a heap measurement: `serde_json::to_string` re-encodes
/// the exact decoded structure this function already holds, without
/// canonicalization, so key ordering can only move the number and the claim stays
/// a bounded charge of the observed rows. A row that cannot be re-encoded is not
/// measurable, so it is charged out rather than charged as free.
///
/// Unbounded decode, named explicitly: the transport's only finite limits on this
/// call are `query_timeout_ms` in *time* and nothing at all in *bytes*
/// (`client/session.rs` carries no response-size ceiling), and
/// `RpcResults::from_value` has already decoded the whole provider response into
/// `serde_json::Value` before this module sees any of it. Nothing here bounds that
/// decode, and the registry's counter does not either. What this bound does prove
/// is narrower and real: every structure this module *builds on top of* the
/// decoded rows — the member vector, the key index, the reference closure, the
/// scope projection and the retained page copies — is refused before it is
/// materialized.
fn decoded_class_bytes(rows: &[Map<String, Value>]) -> u64 {
    rows.iter().fold(0_u64, |total, row| {
        let charge = match serde_json::to_string(row) {
            Ok(encoded) => u64::try_from(encoded.len()).unwrap_or(u64::MAX),
            Err(_) => u64::MAX,
        };
        total.saturating_add(charge)
    })
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

/// The payload column a `recovery_owner`/`recovery_job` row's recorded store-owned
/// digest attests.
///
/// Read by its physical column name rather than by decoding the row into
/// `eliot_store_api::RecoveryRecord`: the member batch reads whole records with
/// `SELECT *`, so a row also carries the provider's record `id`, which
/// `RecoveryRecord`'s `deny_unknown_fields` would refuse.
const RECOVERY_PAYLOAD_FIELD: &str = "payload";

/// The residency evidence of one observed row.
///
/// A13.7 and `crates/storage/AGENTS.md`: a Blob residency digest cannot be
/// re-derived here (this crate is not a Blob-root owner). A class that declares a
/// store-owned digest column therefore carries that column's recorded value, and
/// that recorded value is checked against the row's own recorded payload rather
/// than being accepted on shape or replaced by a fresh checksum. A recorded
/// digest that does not describe the captured payload refuses the capture; a
/// recorded value that cannot be read refuses it too, because inventing a digest
/// here would certify bytes no owner ever attested.
///
/// A class with no declared digest column has no owner-issued residency digest,
/// so the digest of the row's own exact canonical bytes is carried forward, which
/// is the same value `row_content_digest` computes for the member's
/// `content_digest`. The residency *domain* — never the digest — is what keeps
/// same-content-different-domain members distinct.
fn row_residency_digest(
    class: &MemberClass,
    row: &Map<String, Value>,
    content_digest: &str,
) -> Result<String, StoreError> {
    let Some(field) = class.digest_field else {
        return Ok(content_digest.to_owned());
    };
    // The recorded digest is read from the row's own declared column and
    // compared with the digest of the row's own recorded payload — the same
    // digest-versus-payload comparison `eliot_store_api::RecoveryRecord::validate`
    // applies to this exact column pair, and the one `backup_restore.rs` and
    // `apply/read_boundary.rs` already apply to these two tables. The row is NOT
    // decoded into `RecoveryRecord` itself: the member batch reads whole records
    // with `SELECT *`, so the row also carries the provider's record `id`, which
    // `RecoveryRecord`'s `deny_unknown_fields` would refuse. Reading the two
    // declared columns is what keeps the comparison possible at all.
    //
    // Two consequences are deliberate. The digest is never replaced by one
    // recomputed over what this crate holds: a fresh checksum over the same
    // bytes is not a check of the recorded one, and a recorded value that cannot
    // be read is refused rather than invented. And only the digest-versus-payload
    // comparison is applied here, not the whole owner check, because
    // `revision`, the address text, the schema text and the state fence are not
    // this leaf's fields to interpret — they are `recovery_*` operational state
    // whose validity is the write path's and the restore path's concern.
    let recorded = row
        .get(field)
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "snapshot.residency_digest",
            reason: "captured row does not carry its declared store-owned digest column",
        })?;
    let payload = row
        .get(RECOVERY_PAYLOAD_FIELD)
        .and_then(Value::as_array)
        .ok_or(StoreError::InvalidField {
            field: "snapshot.payload",
            reason: "captured row does not carry its declared payload column",
        })?;
    let payload = payload
        .iter()
        .map(|byte| {
            byte.as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or(StoreError::InvalidField {
                    field: "snapshot.payload",
                    reason: "captured payload is not a byte sequence",
                })
        })
        .collect::<Result<Vec<u8>, StoreError>>()?;
    if payload.is_empty() || payload.len() > MAX_RECOVERY_RECORD_BYTES {
        return Err(StoreError::Empty {
            field: "snapshot.payload",
        });
    }
    if sha256_hex(&payload) != recorded {
        return Err(StoreError::InvalidField {
            field: "snapshot.residency_digest",
            reason: "recorded store-owned digest does not describe the captured payload",
        });
    }
    Ok(recorded.to_owned())
}

/// Maps one observed row of one captured class to its snapshot member.
fn member_for_row(
    class: &MemberClass,
    row: &Map<String, Value>,
) -> Result<SnapshotMember, StoreError> {
    let content_digest = row_content_digest(row)?;
    let member_id = row_member_id(class, row)?;
    let residency_digest = row_residency_digest(class, row, &content_digest)?;
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
/// `content_digest` of another member in the same capture.
///
/// It is not a second, independent proof of closure, and the two checks it does
/// run are not equal in strength. The closure itself is discharged by the
/// key-index resolution in [`resolve_member_references`], which refuses a typed
/// edge whose target is absent from the observed rows; and the
/// reference/member-type coupling is discharged by the `member.validate()` that
/// every member already passed on the way out of that same function. What is
/// left here, and what the key index genuinely cannot express, is the
/// self-reference case: a `Reference` member whose own `content_digest` is the
/// digest it claims to point at, which would make an edge its own target. The
/// missing-reference arm is retained so the invariant is checked at the point
/// the closure is claimed, not only at the point the member is built.
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

/// Refuses two observed heads for the same key within one head table.
///
/// The admitted DDL declares one unique index per head table — `rh_key` over
/// `revision_key` on `revision_head` and `oh_scope` over `ordering_scope` on
/// `ordering_head` — and the API treats the two key spaces as distinct
/// (`ScopeRevisionView::validate` uniques each vector separately). A
/// `revision_head` keyed `"main"` and an `ordering_head` scoped `"main"` are
/// therefore not a duplicate. Each key is checked against its own table's
/// observed set, so a reported duplicate means the observation contradicts a
/// unique index that table declares, and no projection may be exported from it.
fn ensure_unique_head_keys(
    observed_revisions: &[RevisionHead],
    observed_orderings: &[OrderingHead],
) -> Result<(), StoreError> {
    let mut revision_keys: BTreeSet<&str> = BTreeSet::new();
    for head in observed_revisions {
        if !revision_keys.insert(head.key.as_str()) {
            return Err(StoreError::Duplicate {
                field: SCOPE_PROJECTION_FIELD,
            });
        }
    }
    let mut ordering_scopes: BTreeSet<&str> = BTreeSet::new();
    for head in observed_orderings {
        if !ordering_scopes.insert(head.scope.as_str()) {
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
    states: &mut CaptureRegistry,
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
fn resolve_transient_read(states: &mut CaptureRegistry, digest: &str, incarnation: u64) {
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
    fn settle(&mut self, states: &mut CaptureRegistry) {
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
/// can neither release a successor's claim nor annotate or delete it, and the
/// aggregate in-flight-call charge is returned only for the slot this claim id
/// actually owned. That identity check is what makes the publish-versus-cancel
/// and page-versus-retire races charge-correct: a late release of a superseded
/// claim releases nothing, because the units it would have released were
/// already returned by the release that cleared the slot.
fn release_claim_slot(registry: &mut CaptureRegistry, digest: &str, claim_id: u64) {
    let Some(state) = registry.captures.get_mut(digest) else {
        return;
    };
    if state
        .claim
        .as_ref()
        .is_some_and(|slot| slot.claim_id == claim_id)
    {
        state.claim = None;
        registry.budget.release(BudgetDimension::ActivePageCalls, 1);
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
/// progress state it would extend. The same outcome answers a concurrent begin
/// whose logical capture is still being enumerated by its owner (see
/// [`claim_begin`]): the owning begin has issued no handle yet, so the honest
/// answer is a pending capture rather than a handle from a second observation.
/// A `RevisionConflict` applies only while another claim owns the current
/// progress revision. A failed point observation by the owning end claim is a
/// separate case and returns `SnapshotClosePending` with its recovery identity.
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
/// replacing whatever the ledger already holds. When the claim is an end call,
/// the exact issued handle and served member/byte totals are captured under the
/// same lock before the claim is settled, so the caller can resume this close.
///
/// A poisoned registry lock is not treated as successful cleanup: the claim is
/// left unsettled, so its `Drop` cannot certify anything either, and the
/// capture keeps its entry and its evidence.
fn record_provider_read_failure(
    claim: &mut CaptureCallClaim,
) -> Option<(SnapshotHandle, u64, u64)> {
    let Ok(mut states) = registry().lock() else {
        return None;
    };
    let owned = states
        .get(&claim.digest)
        .is_some_and(|state| resolve_claim(state, claim).is_ok());
    if !owned {
        // The claim no longer describes this entry's current owner: a replaced
        // or closed capture keeps its own evidence untouched.
        return None;
    }
    merge_interruption(
        &mut states,
        &claim.digest,
        claim.incarnation,
        InterruptionReason::ProviderReadFailed,
    );
    let recovery_identity = if claim.kind == CaptureCallKind::End {
        states.get(&claim.digest).map(|state| {
            (
                state.issued.clone(),
                state.members_served,
                state.bytes_served,
            )
        })
    } else {
        None
    };
    claim.settle(&mut states);
    recovery_identity
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

/// Runs one bounded pass of the owner-lifecycle expiry maintenance.
///
/// This is the narrow owner-lifecycle entry point: it needs no provider I/O, no
/// page, no end and no caller-supplied handle, so the supervised owner can tick
/// it when clients have disappeared and no request arrives at all. It is
/// fail-closed and idempotent — ticking it twice, or racing it with a request,
/// applies the same accounted transitions at most once each.
pub(crate) fn snapshot_owner_maintenance_tick(now_ms: u64) -> Result<(), StoreError> {
    let mut states = lock_registry()?;
    states.budget.refuse_if_unusable()?;
    run_expiry_pass(&mut states, now_ms, None);
    Ok(())
}

/// Applies at most one bounded pass of due expiry work.
///
/// The pass is bounded twice over, and both bounds are owner-issued: it visits
/// only deadlines that have actually come due in the [`CaptureRegistry::expiry`]
/// index, never the whole registry, and it performs at most
/// [`BUDGET_MAX_CLEANUP_STEPS`] accounted steps. A capture with a live call
/// claim is skipped — no claim may lose the payload it is currently serving —
/// and its deadline stays in the index, so skipping never forgets it.
fn run_expiry_pass(states: &mut CaptureRegistry, now_ms: u64, keep: Option<&str>) {
    // The work this pass performs is itself a charged dimension, so an
    // unbounded sweep cannot hide inside the accounting: the whole
    // allowance is taken before any step and the whole allowance is
    // returned when the pass ends. A saturated cleanup dimension is a
    // refusal, never a silent full pass.
    //
    // The returned amount is the *reserved* allowance, not the steps this
    // pass happened to perform. Steps are the bound the loop enforces, not
    // a transfer that outlives the pass, so nothing holds the charge once
    // the pass is over. Returning only `steps` would leave the unspent
    // remainder charged forever, and the first pass — which in a fresh
    // process finds no due deadline and performs none — would saturate the
    // dimension before any work was done, so every later pass, tick, page
    // and close would be refused at the guard above.
    if states
        .budget
        .reserve(BudgetDimension::CleanupSteps, BUDGET_MAX_CLEANUP_STEPS)
        .is_err()
    {
        return;
    }
    let mut steps = 0_u64;
    while steps < BUDGET_MAX_CLEANUP_STEPS {
        let due = states
            .expiry
            .iter()
            .find(|deadline| deadline.at_ms <= now_ms && keep != Some(deadline.digest.as_str()))
            .cloned();
        let Some(deadline) = due else {
            break;
        };
        // The entry is removed from the frontier only once the accounted step
        // for it is taken; a step that declines to act re-arms the deadline, so
        // unresolved evidence is retried instead of being forgotten or evicted.
        states.expiry.remove(&deadline);
        steps = steps.saturating_add(1);
        let settled = match deadline.stage {
            ExpiryStage::Retire => account_expiry(states, &deadline.digest, now_ms),
            ExpiryStage::Release => release_terminal_record(states, &deadline.digest, now_ms),
        };
        if !settled {
            states.expiry.insert(deadline);
        }
    }
    states
        .budget
        .release(BudgetDimension::CleanupSteps, BUDGET_MAX_CLEANUP_STEPS);
}

/// Performs the accounted payload-to-terminal transition for one retired
/// capture. Reports whether the frontier may drop this deadline.
///
/// `now_ms` is the same observation the pass compared the deadline against, so
/// one pass reads the clock once and the frontier index and the retirement
/// decision cannot disagree.
///
/// The bound point is deliberately not re-read for a capture whose owner window
/// has closed: a receipt must not claim the source stayed still across a window
/// this store no longer vouches for, so no stable-point receipt is fabricated.
fn account_expiry(states: &mut CaptureRegistry, digest: &str, now_ms: u64) -> bool {
    let Some(state) = states.captures.get(digest) else {
        // Nothing is installed under this digest, so there is no evidence and no
        // owner to act for: the deadline retires.
        return true;
    };
    if state.terminal.is_some() {
        // Already through the accounted transition; its own replay horizon
        // deadline governs the entry from here.
        return true;
    }
    if state.claim.is_some() {
        // A live call claim is still serving from this payload. The deadline is
        // re-armed and retried, so a claim can never be starved of its data and
        // never loses it either.
        return false;
    }
    if !capture_is_retired(state, now_ms) {
        return false;
    }
    let incarnation = state.incarnation;
    let Some(receipt) = expiry_receipt(state) else {
        // A ledger whose frozen counters disagree with the live counters is a
        // receipt defect. This module never answers a defect by deleting
        // evidence: the entry is kept exactly as it is and the next maintenance
        // pass retries the same transition.
        return false;
    };
    retain_terminal_close(states, digest, incarnation, receipt);
    true
}

/// Derives the expiry receipt of one retired capture from retained evidence.
fn expiry_receipt(state: &SnapshotState) -> Option<SnapshotEndReceipt> {
    let (completeness, members_served, bytes_served) =
        closing_accounting(state, true, false).ok()?;
    build_end_receipt(state, completeness, members_served, bytes_served).ok()
}

/// Releases one bounded terminal record whose replay horizon has ended.
///
/// This is the only place a capture entry is removed, and it removes only a
/// terminal record whose owner replay horizon has passed and whose no live claim
/// can still be using. A live capture, a claimed capture and a retained receipt
/// inside its horizon are all left alone, and the terminal-record units this
/// entry's own begin reserved are returned only here, when the entry actually
/// goes away. Reports whether the frontier may drop this deadline.
fn release_terminal_record(states: &mut CaptureRegistry, digest: &str, now_ms: u64) -> bool {
    let releasable = states.captures.get(digest).is_some_and(|state| {
        state.claim.is_none()
            && state
                .terminal
                .as_ref()
                .is_some_and(|closed| now_ms > closed.retained_until_ms)
    });
    if !releasable {
        // Either the entry is gone, still live, still claimed, or still inside
        // its replay horizon. The horizon is exclusive at the exact instant it
        // passes, matching the close path, so the deadline is re-armed and
        // retried rather than released early.
        return false;
    }
    states.captures.remove(digest);
    // The heavy payload was already freed by the accounted terminal transition,
    // so its retained bytes were returned there. Only the two terminal-record
    // dimensions are released now, and only because the record itself is gone.
    states.budget.release(BudgetDimension::TerminalEntries, 1);
    states
        .budget
        .release(BudgetDimension::TerminalBytes, TERMINAL_ENTRY_BYTES);
    true
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
///
/// This is where retirement and evidence retention stay distinct: the heavy
/// payload and the retained page response are freed, while the exact identity,
/// bound source point, served accounting, interruption ledger and the final
/// receipt all survive. The aggregate charges follow the data exactly — the
/// live-capture slot and the retained payload bytes are returned, and the
/// terminal-record units the begin reserved stay charged *because the retained
/// record is what now holds them*, until the record itself is released.
fn retain_terminal_close(
    states: &mut CaptureRegistry,
    digest: &str,
    incarnation: u64,
    receipt: SnapshotEndReceipt,
) {
    let Some(state) = states.captures.get_mut(digest) else {
        return;
    };
    if state.incarnation != incarnation || state.terminal.is_some() {
        return;
    }
    // The replay horizon is the capture's own declared duration bound, not an
    // invented window: inside it an exact repeated end is answered from this
    // record, and after it maintenance releases the bounded record. It is
    // computed from the observation taken *before* the expensive setup, so a
    // slow setup shortens the horizon instead of extending it.
    let retained_until_ms =
        fail_closed_deadline(state.opened_at_ms, state.begin.bounds.max_duration_ms);
    let charged_capture_bytes = state.charged_capture_bytes;
    state.payload = None;
    state.last_page = None;
    state.charged_capture_bytes = 0;
    state.progress_revision = state.progress_revision.saturating_add(1);
    state.terminal = Some(RetainedClose {
        receipt,
        retained_until_ms,
    });
    states.budget.release(BudgetDimension::LiveCaptures, 1);
    states
        .budget
        .release(BudgetDimension::RetainedBytes, charged_capture_bytes);
    // The retained record's own bounded release is now due from the expiry
    // frontier, so reclamation of a closed capture does not depend on any
    // further page or end traffic.
    states.expiry.insert(ExpiryDeadline {
        at_ms: retained_until_ms,
        stage: ExpiryStage::Release,
        digest: digest.to_owned(),
    });
}

/// The frozen totals one reconciled observation produced.
///
/// Only the two aggregates the installed entry retains; the served set itself
/// stays in the payload and is never copied here.
struct ReconciledObservation {
    /// Summed observed content bytes of the denominator.
    total_bytes: u64,
    /// Pages the frozen served set occupies at the closed per-page ceiling.
    total_pages: u64,
}

/// Reconciles one observed enumeration against the request and the admitted
/// generation, and freezes the totals the installed entry retains.
///
/// Every per-capture limit enforced here is an existing named one
/// ([`MAX_SNAPSHOT_MEMBERS`], [`MAX_SNAPSHOT_BYTES`], [`MAX_SNAPSHOT_PAGES`])
/// or the caller's own declared bound. None of them is relaxed by the aggregate
/// budget: the aggregate budget decides whether a capture may be *admitted*, and
/// this decides whether an admitted observation is *servable*.
fn reconcile_observation(
    adapter: &SurrealStoreAdapter,
    enumeration: &Enumeration,
    request: &SnapshotBeginRequest,
) -> Result<ReconciledObservation, StoreError> {
    let point = &enumeration.point;
    if point.schema_generation != adapter.config.expected_schema_generation.as_str() {
        return Err(StoreError::Unavailable);
    }
    bind_source_identity(adapter, point, request)?;
    let ordered_members = &enumeration.members;
    reconcile_denominator(ordered_members, &request.denominator)?;
    // An empty observed set is only a bindable denominator when the enumeration
    // actually read every admitted canonical class and found nothing. A
    // declared-empty denominator with no provider evidence is not a zero-member
    // capture; it is refused.
    if ordered_members.is_empty() && !enumeration.evidence.is_authoritative_zero() {
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
    // One work unit per member; the per-request ceiling is enforced here and the
    // frozen global ceiling through `bounds.validate()` in request validation.
    if member_count > request.bounds.max_work {
        return Err(StoreError::PayloadTooLarge);
    }
    let total_pages = member_count.div_ceil(SNAPSHOT_PAGE_CHUNK);
    if total_pages > request.bounds.max_pages || total_pages > MAX_SNAPSHOT_PAGES {
        return Err(StoreError::PayloadTooLarge);
    }
    Ok(ReconciledObservation {
        total_bytes,
        total_pages,
    })
}

/// Refuses a new begin whose requested lifetime cannot be honoured, before any
/// provider enumeration and before any budget is reserved.
///
/// Two independent refusals, both static-text typed. The first is the request's
/// own window: already expired, or shorter than the adapter's real per-RPC
/// timeout, which is `SurrealAdapterConfig::query_timeout_ms` and the only bound
/// this module actually has on a provider call (`client/session.rs` bounds every
/// RPC by exactly that duration and carries no byte ceiling). A deadline check
/// after an uninterruptible call is not a bound on that call, so a window that
/// cannot even cover one round trip is refused rather than admitted.
fn refuse_unservable_window(
    adapter: &SurrealStoreAdapter,
    request: &SnapshotBeginRequest,
    started_at_ms: u64,
) -> Result<(), StoreError> {
    if is_retired(
        request.expires_at_unix_ms,
        started_at_ms,
        request.bounds.max_duration_ms,
        started_at_ms,
    ) {
        return Err(StoreError::InvalidField {
            field: "snapshot.expires_at_unix_ms",
            reason: "requested capture window has already expired",
        });
    }
    if request.bounds.max_duration_ms < adapter.config.query_timeout_ms {
        return Err(StoreError::InvalidField {
            field: "snapshot.bounds.max_duration_ms",
            reason: "capture window is shorter than one adapter query timeout, so no page can be served",
        });
    }
    Ok(())
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
    // Local elapsed-duration accounting starts here, *before* the expensive
    // setup below, so a slow principal check, source-class census or expiry pass
    // cannot hand a fresh insertion a new full duration. The same observation
    // becomes this capture's `opened_at_ms`, so the window this request asked for
    // is the window it actually gets.
    let started_at_ms = crate::write_execution::current_time_ms();
    // An already-expired or unservable request is refused before any provider
    // enumeration, so it performs no enumeration and creates no live capture at
    // all. A retained expired begin stays reachable as history through the replay
    // path below; replay cannot renew it and cannot admit a new live capture.
    refuse_unservable_window(adapter, &request, started_at_ms)?;
    // The acting principal is named, not assumed, before any protected read.
    bind_capture_principal(adapter, crate::client::SNAPSHOT_MEMBERS_OPERATION)?;
    // A request naming a foreign installation or store is refused here, before
    // the canonical member batch is read. The remaining source quarters need the
    // live capture point and are bound after enumeration, in
    // `reconcile_observation` -> `bind_source_identity`, which re-runs this same
    // check as its first step.
    check_active_source_identity(adapter, &request)?;
    verify_canonical_source_classes(adapter.config.expected_schema_generation.as_str())?;
    // Bounded opportunistic maintenance: `begin` is the one path a client that
    // never pages and never closes still reaches, so expiry progresses on
    // begin-only traffic. The supervised owner can drive the same pass through
    // [`snapshot_owner_maintenance_tick`] when no request arrives at all.
    snapshot_owner_maintenance_tick(started_at_ms)?;
    let snapshot_digest = request.compute_digest().map_err(redact_snapshot_error)?;
    // Resolve the exact logical begin AND reserve its whole allowance and its
    // single-owner claim under one acquisition of the one registry lock. An exact
    // replay returns the retained handle and the retained progress without
    // enumerating and without charging anything; a concurrent identical begin is
    // answered with the typed pending outcome because its owner is already
    // enumerating this very capture; a different canonical input under an already
    // claimed operation/idempotency namespace is refused. Only a genuinely new
    // begin reserves, and because the check and the reservation share one
    // acquisition, two concurrent begins cannot both pass an unlocked size check
    // and two cannot both enumerate the same logical capture.
    let mut reservation = {
        let mut states = lock_registry()?;
        states.budget.refuse_if_unusable()?;
        if let Some(retained) = retained_begin_handle(&states, &snapshot_digest, &request)? {
            return Ok(retained);
        }
        claim_begin(&states, &snapshot_digest, &request)?;
        reserve_begin(&mut states, &snapshot_digest, &request)?
    };
    // The reservation is owned across this await and returned exactly once on
    // every exit below: an error, a cancellation, or a publish-versus-cancel
    // race all reach its `Drop` armed. No registry mutex is held here (I5.7).
    let enumeration = match enumerate_canonical_members(adapter, &request).await {
        Ok(enumeration) => enumeration,
        Err(error) => return Err(error),
    };
    let observation = reconcile_observation(adapter, &enumeration, &request)?;
    let point = enumeration.point;
    let ordered_members = enumeration.members;
    let evidence = enumeration.evidence;
    let scope_digest = enumeration.scope.digest;
    // Recheck the lifetime budget before publishing. A begin that spent its whole
    // window inside enumeration must not be installed as a fresh capture with a
    // new full duration; the reservation is returned by `Drop` on this path.
    if is_retired(
        request.expires_at_unix_ms,
        started_at_ms,
        request.bounds.max_duration_ms,
        crate::write_execution::current_time_ms(),
    ) {
        return Err(StoreError::InvalidField {
            field: "snapshot.bounds.max_duration_ms",
            reason: "capture window elapsed during source enumeration",
        });
    }
    // The actual retained charge: the observed content denominator plus the
    // worst-case allowance for the one retained page response this owner will
    // hold. It is always at most the reserved worst case, so settling the
    // reservation into it can only shrink the dimension.
    let actual_capture_bytes = observation.total_bytes.saturating_add(RETAINED_PAGE_BYTES);

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

    // One more acquisition for the publish. The incarnation and the entry's
    // absence are both rechecked under it, so a successor that claimed this
    // logical request while this call enumerated is never overwritten; this call
    // returns that successor's retained handle and releases only its own
    // reservation — units and in-progress claim — through `Drop`.
    let mut states = lock_registry()?;
    states.budget.refuse_if_unusable()?;
    if let Some(state) = states.captures.get(&snapshot_digest) {
        // Another begin for the same logical request claimed this capture while
        // this one was enumerating. The retained decision is authoritative: a
        // deliberate refresh needs its own new logical capture, never a reset of
        // the open one, and an expired or retired replay keeps its original
        // window because the entry is left exactly as it is.
        return Ok(state.issued.clone());
    }
    // The retirement deadline is registered before the entry becomes visible, so
    // a capture is never installed without a frontier entry that will reclaim it
    // even if no page or end call ever arrives.
    let retire_at_ms = fail_closed_deadline(started_at_ms, request.bounds.max_duration_ms)
        .min(u64::try_from(request.expires_at_unix_ms).unwrap_or(0));
    states.captures.insert(
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
            total_bytes: observation.total_bytes,
            total_pages: observation.total_pages,
            pages_served: 0,
            members_served: 0,
            bytes_served: 0,
            last_digest: snapshot_digest.clone(),
            opened_at_ms: started_at_ms,
            charged_capture_bytes: actual_capture_bytes,
        },
    );
    states.expiry.insert(ExpiryDeadline {
        at_ms: retire_at_ms,
        stage: ExpiryStage::Retire,
        digest: snapshot_digest,
    });
    reservation.settle(&mut states, actual_capture_bytes);
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
    states: &mut CaptureRegistry,
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
    states: &mut CaptureRegistry,
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
    ///
    /// Boxed because a `SnapshotPage` is far larger than a claim, and this
    /// value is returned by value from the admission step: without the box the
    /// whole admission result carries the page's size on every claim path too.
    Replay(Box<SnapshotPage>),
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
    states: &mut CaptureRegistry,
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
    run_expiry_pass(states, now_ms, Some(digest));
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
        return Ok(PageAdmission::Replay(Box::new(page.clone())));
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
    // The in-flight call slot is an aggregate dimension, so the aggregate is
    // refused *before* this call's claim slot is installed. A refusal here
    // leaves the capture exactly as it was: no claim, no progress movement, no
    // interruption.
    states.budget.reserve(BudgetDimension::ActivePageCalls, 1)?;
    states
        .captures
        .get_mut(digest)
        .ok_or_else(unknown_snapshot_handle)?
        .claim = Some(CaptureClaimSlot {
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
        PageAdmission::Replay(page) => return Ok(*page),
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
            let _ = record_provider_read_failure(&mut claim);
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
    states: &mut CaptureRegistry,
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
    run_expiry_pass(states, now_ms, Some(digest));
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
    // The same aggregate in-flight call slot the page path reserves, refused
    // before this close's claim slot exists. Recovery and control capacity is
    // preserved by construction: the terminal transition a close performs needs
    // no in-flight call slot, and its terminal-record space was reserved at
    // begin, so a saturated call dimension can never block reclamation.
    states.budget.reserve(BudgetDimension::ActivePageCalls, 1)?;
    states
        .captures
        .get_mut(digest)
        .ok_or_else(unknown_snapshot_handle)?
        .claim = Some(CaptureClaimSlot {
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
                // this claim, the caller may retry `end_snapshot` with the
                // original owner-issued handle and exact served counts. A
                // stable-point receipt is never fabricated from a failed read.
                if let Some((handle, members_served, bytes_served)) =
                    record_provider_read_failure(&mut claim)
                {
                    return Err(StoreError::SnapshotClosePending {
                        handle,
                        members_served,
                        bytes_served,
                    });
                }
                return Err(error);
            }
        }
    };
    close_capture(&mut claim, observed.as_ref())
}
