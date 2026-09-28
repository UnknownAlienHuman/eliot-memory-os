//! Kernel-owned binding of Store writes to durable ORS reservations (issue #992).
//!
//! Architecture traceability: `I5.7` keeps one ORS coordinator for uncommitted
//! precedence (`reserve -> eligible -> execute -> finalize/release` over one
//! monotonic `reservation_order`) and the canonical Store for committed heads;
//! `I5.4` keeps the admitted [`PreparedTransition`][eliot_store_api::PreparedTransition]
//! the immutable semantic unit; `I5.27` binds operation identity over canonical
//! bytes; `I14.21` preserves `Executing`/`Reconciling` identity until exact
//! receipt reconciliation; `I14.3` keeps cancellation and reconciliation on the
//! protected reserve; `I7.20` requires typed failures that preserve operation
//! identity without leaking payload material.
//!
//! ## Owner table
//!
//! ```text
//! Owner                              Evidence
//! ---------------------------------- ------------------------------------------
//! ORS (`RedbRecoveryStore`)          uncommitted reservation order, scope
//!                                    sequences, lifecycle states, envelopes;
//!                                    bound evidence provider verifies heads
//!                                    and reconciliation inside ORS
//! Store (`CanonicalStoreClient`)     committed heads and `WriteReceipt`s with
//!                                    the reconciliation envelope (#991)
//! #990 projection                    byte-exact reservation binding carried
//!                                    across the authenticated boundary
//! This module                         composition of the three above: no new
//!                                    reservation database, scheduler, epoch
//!                                    issuer, semantic admission, receipt
//!                                    issuer, or second state owner
//! ```
//!
//! ## Construction rule
//!
//! [`CompositionReservation::bind`] takes only the composition-owned ORS
//! handle (whose canonical evidence provider was bound at composition by
//! `open_with_evidence`) and the active writer epoch. It never accepts a
//! caller-supplied verifier, an unrelated ORS handle as authority, or a
//! claimed issuer: a token minted by a foreign ORS is unknown to this ORS and
//! fails at the first lifecycle call, and an ORS opened without evidence
//! fails reservation with a canonical-evidence error. Both are proved by the
//! `992/2` suite.
//!
//! ## Compatible profile rule
//!
//! The per-operation [`ReservationSeed`] must be compatible with the live
//! composition authority: the owner writer epoch must name the exact fence
//! lineage and sequence, the seed operation must equal the admitted Store
//! operation, and the observed head set must exactly cover the admitted
//! transition scopes with matching sequences. Anything else fails closed
//! before any ORS or Store mutation. Wall-clock expiry enforcement stays with
//! the scheduler owner; the adapter preserves the ordered owner-supplied
//! creation/expiry pair and rejects an inverted pair.
//!
//! ## Staged payload protection (fail-closed, `I5.2`)
//!
//! ORS requires both a provider-protected payload and a durable
//! `RecoveryWriteBinding` joining that exact payload to the authenticated
//! `VersionedWriteSubmission` and prepared transition. The legacy
//! [`ReservationSeed`] has no authenticated write intent, and a caller-provided
//! key label or byte vector is not proof that an installation-owned provider
//! protected it. This composition has no authorized arbitrary-payload
//! protector or canonical-write admission limits, so
//! [`reserve_for_transition`] validates the transition and seed shape then
//! returns `Unsupported` before any ORS mutation. That refusal is never
//! `ACCEPTED_PENDING` evidence. W3 remains partial until the missing owners
//! supply both contracts; no key, cipher, cap, or payload evidence is invented
//! here.
//!
//! ## Startup recovery over the same envelopes
//!
//! [`reconcile_staged_writes_at_startup`] is the read side for retained ORS
//! records (including records staged by earlier or external owners), and it is
//! the I1.11 step 6 owner for them:
//! every unresolved reservation is enumerated by operation identity, observed
//! against its exact canonical Store receipt through the same named
//! authenticated gateway ([`StartupReceiptRoute`]) every other receipt
//! observation in this crate uses, and revalidated through
//! [`RedbRecoveryStore::verify_staged_envelope`]. A corrupted or unreadable
//! staged payload keeps a durable [`eliot_ors::RecoveryProblem`] and stays
//! available for disposition; nothing is decoded, re-hashed, defaulted to
//! plaintext, or deleted, and an unresolved reservation is never retried or
//! force-released. It runs whether or not a producer exists, because the ORS
//! rows it reads outlive the process that wrote them.
//!
//! ## Send ordering (no orphaned tokens)
//!
//! ```text
//! reserve -> eligible -> [admission lease] -> project -> send once ->
//!   Ok(Committed)   -> begin_execute_after_send -> reconcile -> Finalized
//!   Ok(not-applied) -> begin_execute_after_send -> reconcile -> Released (+gap)
//!   Err(unknown)    -> begin_execute_after_send -> mark_unknown -> Reconciling
//!   Err(refused)    -> release (still Eligible, proved no effect)
//! ```
//!
//! `begin_execute_after_send` runs only after the single send resolves and
//! requires the typed [`ResolvedSendOutcome`] evidence binding the exact
//! reservation operation, so a refused backend never strands an `Executing`
//! reservation without receipt evidence. The pre-send two-argument call no
//! longer exists: it fails to compile, and mismatched evidence fails closed
//! at runtime without touching ORS. Cancellation before possible submission
//! releases only `Reserved`/`Eligible` tokens; once `Executing`/`Reconciling`,
//! release is rejected and identity is preserved until exact receipt
//! reconciliation.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use eliot_contracts::{EpochId, RequestMetadata, StateFence};
use eliot_ors::{
    CanonicalDisposition, CanonicalReconciliation, CanonicalScopeObservation, EpochIdentity,
    EpochLineage, OpaqueLabel, OperationIdentity as OrsOperationIdentity,
    OperationalCurrentRecoveryCursor, OperationalPhase, OperationalRecoveryStore,
    RecoveryInboxDisposition, RecoveryInboxRecoveryCursor, RecoveryInventorySnapshot,
    RecoveryInventorySource, RecoveryProblem, RecoveryProblemRecoveryCursor, RedbRecoveryStore,
    ReservationRecord, ReservationState, StateFenceSnapshot, WriteIdempotencyRecoveryCursor,
    WriteReservationRecoveryCursor, WriterReservationToken,
};
use eliot_receipts::{ReceiptDispositionKind, ReceiptKind};
use eliot_store_api::{
    CAPABILITY_RESERVED_WRITE, CanonicalRequestView, OperationId, OrderingHeadExpectation,
    OrderingScopeId, PreparedTransition, ReceiptEnvelope, ReservedScopeBinding,
    ReservedWriteRequest, RevisionHeadExpectation, WriteAdmissionParams, WriteAdmissionProjection,
    WriteReceipt, WriteReceiptStatus, WriterEpochBinding, prepared_transition_digest, sha256_hex,
    verify_canonical_request_hash,
};

/// Key-provider label carried on reservation envelopes.
///
/// Labels only; no secret bytes live here or cross this boundary. This names
/// the identity a caller *asks* the installation secret provider to resolve,
/// and it is deliberately NOT the name of the protection primitive: nothing in
/// this workspace resolves this label, so a well-formed reference built from it
/// is not proof of key availability, retrievability, or authenticated
/// decoding. The staging boundary in [`reserve_for_transition`] therefore never
/// treats the label as evidence of protection — `refuse_plaintext_payload`
/// independently proves the staged bytes are not the admitted plaintext — and
/// `RedbRecoveryStore::verify_staged_envelope` revalidates the envelope's own
/// recorded digest without ever resolving it.
///
/// The value is unchanged from the reservation contract's established key
/// reference, which `tests/data/store_write_reservation.json` and the existing
/// `store_write_reservation_tests` fixtures assert.
pub const RESERVATION_KEY_PROVIDER: &str = "kernel-reservation-key";
/// Requested key name under [`RESERVATION_KEY_PROVIDER`] for store-write
/// reservations.
///
/// Same caveat as the provider label: a key reference becomes evidence only
/// when the installation secret provider resolves it, never from the string
/// itself.
pub const RESERVATION_KEY_NAME: &str = "store-write-reservation-v1";
/// Visibility label preserved on every reservation envelope without
/// interpretation by ORS.
pub const RESERVATION_VISIBILITY: &str = "owner-only";
/// Reason label recorded when a send resolves to a still-unknown outcome.
pub const UNKNOWN_OUTCOME_REASON: &str = "store-unknown-outcome";

const STARTUP_RECOVERY_INVENTORY_SOURCES: [&str; 5] = [
    "ors.reservations",
    "ors.operational_current",
    "ors.recovery_inbox",
    "ors.recovery_problems",
    "ors.write_idempotency",
];

/// Exact page coverage for one independently revisioned ORS startup source.
///
/// `coverage_sha256` binds the source revision, stable snapshot digest, every
/// exclusive cursor, each safe page summary digest, and the explicit terminal
/// marker. Reservation coverage includes the empty reservation-order and
/// operation-index phases because each returned continuation contributes to
/// the same chain.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct StartupRecoverySourceCoverage {
    /// Durable ORS source named by the page API.
    pub source: &'static str,
    /// Source revision held constant for every page in this scan.
    pub source_revision: u64,
    /// Number of bounded pages consumed, including empty index-verification
    /// pages returned by the reservation cursor.
    pub page_count: u64,
    /// Number of safe summary records returned by this source.
    pub record_count: u64,
    /// Serialized digest of the exact first cursor supplied to ORS.
    pub start_cursor_sha256: String,
    /// Serialized digest of the cursor consumed by the final complete page.
    pub terminal_cursor_sha256: String,
    /// Digest chaining all page cursors, row summaries, and completion markers.
    pub coverage_sha256: String,
    /// True only when ORS returned an explicit complete page with no cursor.
    pub complete: bool,
}

/// Full five-source ORS inventory evidence used by the Kernel startup gate.
///
/// Every source has its own bounded cursor chain, and all chains share one
/// atomic revision snapshot. The final validation happens after all five
/// sources reach explicit exhaustion. These fields are not deserializable, so
/// a caller cannot construct a ready proof from reported counts.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct StartupRecoveryInventoryCoverage {
    /// Digest binding the five revisions captured before paging began.
    pub snapshot_sha256: String,
    /// Exact per-source page and cursor coverage in the fixed ORS order.
    pub sources: Vec<StartupRecoverySourceCoverage>,
    /// Whether ORS revalidated all five revisions after every page completed.
    pub snapshot_revalidated: bool,
}

impl StartupRecoveryInventoryCoverage {
    fn is_complete(&self) -> bool {
        self.snapshot_revalidated
            && self.snapshot_sha256.len() == 64
            && self.sources.len() == STARTUP_RECOVERY_INVENTORY_SOURCES.len()
            && self
                .sources
                .iter()
                .zip(STARTUP_RECOVERY_INVENTORY_SOURCES)
                .all(|(source, expected)| {
                    source.source == expected
                        && source.page_count > 0
                        && source.start_cursor_sha256.len() == 64
                        && source.terminal_cursor_sha256.len() == 64
                        && source.coverage_sha256.len() == 64
                        && source.complete
                })
    }
}

/// Boxed named-gateway receipt observation for one startup record.
pub type StartupReceiptObservation<'a> =
    Pin<Box<dyn Future<Output = Result<Option<WriteReceipt>, ReservationWriteError>> + Send + 'a>>;

/// The named authenticated canonical-Store receipt path the startup scan must
/// cross (issue #1713, item 6).
///
/// `A12.3` states: "Direct storage access, a shell or database-protocol bypass,
/// or a second writer is a security and integrity problem regardless of how
/// plausible the content appears", and `I14.21` states: "Kernel queries
/// `WriteReceipt` by idempotency key". Every other receipt observation in this
/// crate reaches the canonical receipt through the one named gateway, which
/// takes the flight slot, refuses a fenced rebind, validates the fence, checks
/// the active route before and after the query, and validates the receipt's
/// own operation and fence binding. This port exists so the startup scan can
/// reach that same method; it declares no second implementation of those
/// checks, and a refusal crosses as an error, never as an absent receipt.
pub trait StartupReceiptRoute: Send + Sync {
    /// Observes one canonical receipt by exact operation identity under the
    /// exact state fence the staged operation was admitted with.
    fn observe_receipt<'a>(
        &'a self,
        state_fence: &'a StateFence,
        operation_id: OperationId,
    ) -> StartupReceiptObservation<'a>;
}

/// Recovers the exact admitted State Fence from one reservation token.
///
/// [`WriterReservationToken::state_fence`] is an
/// [`StateFenceSnapshot`] - the ORS contour - while the named gateway takes the
/// canonical [`StateFence`]. The snapshot is validated first, so the digest and
/// the canonical JSON it recorded are proven, and only then is that exact
/// recorded JSON decoded back into the canonical type. Nothing is defaulted or
/// substituted: a token that does not record a decodable canonical fence
/// refuses, and the live fence is never passed off as an older token's own.
fn admitted_state_fence(
    token: &WriterReservationToken,
) -> Result<StateFence, ReservationWriteError> {
    token
        .state_fence
        .validate()
        .map_err(ReservationWriteError::Ors)?;
    serde_json::from_str::<StateFence>(token.state_fence.canonical_json.as_str()).map_err(
        |error| ReservationWriteError::Binding {
            operation_id: token.operation_id.as_str().to_owned(),
            detail: format!(
                "the reservation's recorded state fence does not decode to a canonical State Fence: {error}"
            ),
        },
    )
}

/// Typed failure for reserved-write binding, dispatch, and reconciliation.
///
/// Every variant preserves the operation identity it refuses; no variant
/// carries payload bytes, digests, or secret material. ORS and Store failures
/// pass through unchanged so tests and operators match the exact owner error.
#[derive(Debug, thiserror::Error)]
pub enum ReservationWriteError {
    /// Admitted shape refused before any ORS or Store mutation.
    #[error("reserved write admission refused for operation {operation_id}: {detail}")]
    Admission {
        /// Admitted operation the refusal preserves.
        operation_id: String,
        /// Exact refused property.
        detail: String,
    },
    /// Reservation binding mismatch: the presented evidence does not bind the
    /// exact admitted transition, fence, scope set, or token.
    #[error("reserved write binding mismatch for operation {operation_id}: {detail}")]
    Binding {
        /// Admitted operation the refusal preserves.
        operation_id: String,
        /// Exact mismatched binding.
        detail: String,
    },
    /// The Store backend has no reserved-write capability. This is explicit
    /// unsupported behavior, never a silent unreserved `Apply` fallback.
    #[error("reserved write unsupported for operation {operation_id}: {detail}")]
    Unsupported {
        /// Admitted operation the refusal preserves.
        operation_id: String,
        /// Exact missing capability.
        detail: String,
    },
    /// The send resolved to a still-unknown outcome. The reservation is
    /// `Reconciling` (or still `Eligible` when execution never started) and
    /// must be reconciled by exact receipt evidence, never retried blindly.
    #[error("reserved write outcome unknown for operation {operation_id}: {detail}")]
    Unknown {
        /// Admitted operation the report preserves.
        operation_id: String,
        /// Exact unknown observation.
        detail: String,
    },
    /// Durable ORS lifecycle refusal, preserved verbatim.
    #[error(transparent)]
    Ors(#[from] eliot_ors::OrsError),
    /// Store contract refusal, preserved verbatim.
    #[error(transparent)]
    Store(#[from] eliot_store_api::StoreError),
}

/// Composition-bound reservation owner: the one owned ORS handle plus the
/// active writer epoch from trusted Kernel composition.
///
/// There is deliberately no constructor accepting an evidence provider, a
/// second ORS handle, or a claimed epoch: the evidence provider stays bound
/// inside the ORS handle, and the writer epoch must be the composition-active
/// one or every lifecycle call fails with the owner error.
pub struct CompositionReservation {
    ors: Arc<RedbRecoveryStore>,
    writer_epoch: EpochLineage,
}

impl CompositionReservation {
    /// Binds the composition-owned ORS handle and active writer epoch.
    ///
    /// The epoch lineage edge is validated without granting epoch authority;
    /// currency against the live fence is re-checked at every transition
    /// boundary, never once here.
    pub fn bind(
        ors: Arc<RedbRecoveryStore>,
        writer_epoch: EpochLineage,
    ) -> Result<Self, ReservationWriteError> {
        writer_epoch
            .validate()
            .map_err(ReservationWriteError::Ors)?;
        Ok(Self { ors, writer_epoch })
    }

    /// Returns the bound active writer epoch.
    pub fn writer_epoch(&self) -> &EpochLineage {
        &self.writer_epoch
    }

    /// Returns the exact current writer identity checked at every lifecycle step.
    fn writer_identity(&self) -> &EpochIdentity {
        &self.writer_epoch.current
    }
}

/// Caller-observed canonical head evidence for one ordering scope.
///
/// The digest restates owner-observed canonical head bytes; this type allocates
/// no sequence and mints no digest. Sequences are cross-checked against the
/// admitted `OrderingHeadExpectation` set at reservation time.
#[derive(Clone, Debug)]
pub struct ObservedHead {
    /// Ordering scope under reservation.
    pub scope: String,
    /// Expected head sequence the reservation extends; must be non-zero and
    /// must equal the admitted expectation for the scope.
    pub expected_sequence: u64,
    /// Digest of the exact observed canonical head bytes (lowercase SHA-256).
    pub expected_head_digest: String,
    /// Owner revision-head observation, if any.
    pub revision_head: Option<String>,
}

impl ObservedHead {
    fn validate(&self) -> Result<(), ReservationWriteError> {
        if self.scope.trim().is_empty()
            || self.scope.chars().any(char::is_control)
            || self.scope.len() > 1024
        {
            return Err(ReservationWriteError::Admission {
                operation_id: String::new(),
                detail: "observed head scope must be non-blank bounded text".to_owned(),
            });
        }
        if self.expected_sequence == 0 {
            return Err(ReservationWriteError::Admission {
                operation_id: String::new(),
                detail: format!(
                    "observed head sequence must be non-zero for scope {}",
                    self.scope
                ),
            });
        }
        if self.expected_head_digest.len() != 64
            || self
                .expected_head_digest
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(ReservationWriteError::Admission {
                operation_id: String::new(),
                detail: format!(
                    "observed head digest must be lowercase SHA-256 for scope {}",
                    self.scope
                ),
            });
        }
        if let Some(revision) = &self.revision_head
            && (revision.trim().is_empty() || revision.chars().any(char::is_control))
        {
            return Err(ReservationWriteError::Admission {
                operation_id: String::new(),
                detail: format!(
                    "observed revision head must be non-blank text for scope {}",
                    self.scope
                ),
            });
        }
        Ok(())
    }
}

/// Per-operation reservation inputs supplied by the Kernel caller.
///
/// Identity and head evidence must be exactly compatible with the admitted
/// transition and expected-head sets; [`reserve_for_transition`] checks every
/// binding before any ORS mutation. The payload bytes are caller-owned opaque
/// bytes that the ORS stores under its `Encrypted` claim; ORS binds them with
/// its own integrity digest and length and never interprets them. Supplying
/// the admitted transition's plaintext canonical bytes is refused there, so a
/// caller cannot stage plaintext under an encrypted label.
#[derive(Clone, Debug)]
pub struct ReservationSeed {
    /// ORS reservation identity label; unique per operation.
    pub reservation_id: String,
    /// Store operation identity; must equal the admitted transition's
    /// operation id exactly, binding the ORS operation to the Store operation.
    pub operation_id: String,
    /// Recovery owner identity preserved without granting authority.
    pub recovery_owner: String,
    /// Caller-owned opaque bytes staged under the key reference below. They
    /// are the installation secret owner's protected bytes: this module never
    /// encrypts, mints key material, or derives a second encoding.
    pub payload_bytes: Vec<u8>,
    /// Key provider label the installation secret provider is asked to resolve
    /// (no secret bytes, and no claim that such a provider exists).
    pub key_provider: String,
    /// Key name label under that provider (no secret bytes).
    pub key_name: String,
    /// Visibility label preserved without interpretation.
    pub visibility: String,
    /// Owner creation time in Unix milliseconds.
    pub created_at_ms: i64,
    /// Owner known time in Unix milliseconds; must not precede creation.
    pub known_at_ms: i64,
    /// Owner expiry time in Unix milliseconds; must follow creation.
    pub expires_at_ms: i64,
    /// Complete observed head set covering the admitted transition scopes.
    pub heads: Vec<ObservedHead>,
}

impl ReservationSeed {
    fn validate(&self, operation_id: &str) -> Result<(), ReservationWriteError> {
        let label = |value: &str, field: &'static str| {
            if value.trim().is_empty() || value.chars().any(char::is_control) || value.len() > 1024
            {
                return Err(ReservationWriteError::Admission {
                    operation_id: operation_id.to_owned(),
                    detail: format!("reservation seed {field} must be non-blank bounded text"),
                });
            }
            Ok(())
        };
        label(&self.reservation_id, "reservation_id")?;
        label(&self.operation_id, "operation_id")?;
        label(&self.recovery_owner, "recovery_owner")?;
        label(&self.key_provider, "key_provider")?;
        label(&self.key_name, "key_name")?;
        label(&self.visibility, "visibility")?;
        if self.operation_id != operation_id {
            return Err(ReservationWriteError::Binding {
                operation_id: operation_id.to_owned(),
                detail: "reservation seed operation must equal the admitted transition operation"
                    .to_owned(),
            });
        }
        if self.payload_bytes.is_empty() {
            return Err(ReservationWriteError::Admission {
                operation_id: operation_id.to_owned(),
                detail: "reservation seed payload must be non-empty opaque bytes".to_owned(),
            });
        }
        if self.known_at_ms < self.created_at_ms {
            return Err(ReservationWriteError::Admission {
                operation_id: operation_id.to_owned(),
                detail: "reservation seed known time must not precede creation".to_owned(),
            });
        }
        if self.expires_at_ms <= self.created_at_ms {
            return Err(ReservationWriteError::Admission {
                operation_id: operation_id.to_owned(),
                detail:
                    "reservation seed expiry must follow creation; wall timestamps alone are not authority"
                        .to_owned(),
            });
        }
        if self.heads.is_empty() || self.heads.len() > eliot_ors::MAX_RECOVERY_PAGE as usize {
            return Err(ReservationWriteError::Admission {
                operation_id: operation_id.to_owned(),
                detail: "reservation seed must carry a bounded non-empty head set".to_owned(),
            });
        }
        let mut seen = BTreeSet::new();
        for head in &self.heads {
            head.validate().map_err(|error| match error {
                ReservationWriteError::Admission { detail, .. } => {
                    ReservationWriteError::Admission {
                        operation_id: operation_id.to_owned(),
                        detail,
                    }
                }
                other => other,
            })?;
            if !seen.insert(head.scope.clone()) {
                return Err(ReservationWriteError::Admission {
                    operation_id: operation_id.to_owned(),
                    detail: "reservation seed heads must not repeat a scope".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// A reserved token with the creation time the #990 projection seals.
///
/// The token alone does not carry creation time, so reservation returns this
/// bundle: projection takes it back instead of a re-supplied timestamp that
/// could fork the token digest.
#[derive(Debug)]
pub struct SealedReservation {
    /// Immutable ORS-issued token checked at every lifecycle step.
    pub token: WriterReservationToken,
    /// Owner creation time sealed into the projection.
    pub created_at_ms: i64,
}

/// Validates the exact admitted transition, scope set, and expected heads
/// shared by reservation and gateway admission.
///
/// Mirrors the `KernelStoreGateway::apply` gates (source rule excepted: the
/// caller rule lives at the gateway boundary, the binding rules live here):
/// context/transition validation, fence equality, canonical request-hash
/// recompute over the exact values about to be bound, and exact scope/head
/// coverage with one shared fence.
fn validate_admitted(
    context: &RequestMetadata,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<(), ReservationWriteError> {
    let operation_id = transition.identity.operation_id.as_str().to_owned();
    let admission = |detail: String| ReservationWriteError::Admission {
        operation_id: operation_id.clone(),
        detail,
    };
    context
        .validate()
        .map_err(|error| admission(error.to_string()))?;
    transition
        .validate()
        .map_err(|error| admission(error.to_string()))?;
    if transition.state_fence != context.state_fence {
        return Err(admission(
            "transition state fence does not match request metadata".to_owned(),
        ));
    }
    let view = CanonicalRequestView::from_apply(
        context,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
    );
    verify_canonical_request_hash(&view, &transition.identity.canonical_request_hash)
        .map_err(|error| admission(error.to_string()))?;
    let mut declared: Vec<&str> = transition
        .ordering_scopes
        .iter()
        .map(OrderingScopeId::as_str)
        .collect();
    declared.sort_unstable();
    declared.dedup();
    if declared.len() != transition.ordering_scopes.len() {
        return Err(admission(
            "transition ordering scopes must not repeat a scope".to_owned(),
        ));
    }
    let mut expected: Vec<&str> = expected_ordering_heads
        .iter()
        .map(|head| head.scope.as_str())
        .collect();
    expected.sort_unstable();
    if expected != declared {
        return Err(admission(
            "expected ordering heads must exactly cover the transition ordering scopes".to_owned(),
        ));
    }
    for head in expected_ordering_heads {
        head.validate()
            .map_err(|error| admission(error.to_string()))?;
        if head.state_fence != context.state_fence {
            return Err(admission(
                "expected ordering head fence must equal the admitted fence".to_owned(),
            ));
        }
    }
    for head in expected_revision_heads {
        head.validate()
            .map_err(|error| admission(error.to_string()))?;
        if head.state_fence != context.state_fence {
            return Err(admission(
                "expected revision head fence must equal the admitted fence".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Refuses the legacy, unversioned reservation route before any ORS mutation.
///
/// A canonical reservation now requires a durable `RecoveryWriteBinding`
/// derived from the authenticated `VersionedWriteSubmission` and its exact
/// prepared transition. `ReservationSeed` has neither the stable write intent
/// nor a typed authenticated submission, and the composition has no
/// installation-owned payload protector that could prove its bytes and key
/// reference. This legacy signature therefore cannot safely construct the ORS
/// request. It validates the complete transition and seed shape, then refuses
/// before `stage_and_reserve`; callers must not interpret this as staging or
/// `ACCEPTED_PENDING` evidence (issue #1713 W3 remains partial).
pub fn reserve_for_transition(
    _owner: &CompositionReservation,
    seed: &ReservationSeed,
    context: &RequestMetadata,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<SealedReservation, ReservationWriteError> {
    let operation_id = transition.identity.operation_id.as_str().to_owned();
    validate_admitted(
        context,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
    )?;
    seed.validate(&operation_id)?;
    Err(ReservationWriteError::Unsupported {
        operation_id,
        detail: "the legacy reservation seed has no authenticated versioned write intent or ORS write binding, and no installation-owned payload protector is available; no ORS mutation was attempted".to_owned(),
    })
}

/// Projects exactly one eligible token to the #990 sealed request sent through #991.
///
/// The projection mapping is exhaustive and canonical: token order, scope set
/// with reserved sequences, writer lineage, fence, source mirror, owner times,
/// and both recomputed digests. A transition mutated after reservation fails
/// here with a digest mismatch; an exact replay projects the identical bytes.
pub fn project_reserved_write(
    sealed: &SealedReservation,
    context: &RequestMetadata,
    transition: &PreparedTransition,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
) -> Result<ReservedWriteRequest, ReservationWriteError> {
    let operation_id = transition.identity.operation_id.as_str().to_owned();
    validate_admitted(
        context,
        transition,
        &expected_revision_heads,
        &expected_ordering_heads,
    )?;
    let token = &sealed.token;
    if token.operation_id.as_str() != operation_id {
        return Err(ReservationWriteError::Binding {
            operation_id,
            detail: "token operation does not match the admitted transition operation".to_owned(),
        });
    }
    let observed_sequence = token.state_fence.observed_authority_epoch;
    let fenced = StateFenceSnapshot::capture(&context.state_fence, observed_sequence)
        .map_err(ReservationWriteError::Ors)?;
    if fenced != token.state_fence {
        return Err(ReservationWriteError::Binding {
            operation_id: operation_id.clone(),
            detail: "admitted fence does not match the reservation fence".to_owned(),
        });
    }
    let transition_digest = prepared_transition_digest(transition)?;
    if transition_digest != token.prepared_transition_sha256 {
        return Err(ReservationWriteError::Binding {
            operation_id,
            detail:
                "transition content changed after reservation; exact replay is required, rebind is refused"
                    .to_owned(),
        });
    }
    let writer_epoch = &token.writer_epoch;
    let scopes = token
        .scopes
        .iter()
        .map(|scope| {
            Ok(ReservedScopeBinding {
                scope: OrderingScopeId::new(scope.scope.as_str()).map_err(|error| {
                    ReservationWriteError::Binding {
                        operation_id: transition.identity.operation_id.as_str().to_owned(),
                        detail: format!("reserved scope identity is invalid: {error}"),
                    }
                })?,
                reserved_sequence: scope.reserved_sequence,
                expected_sequence: scope.expected_head.sequence,
                expected_head_digest: scope.expected_head.head_sha256.clone(),
            })
        })
        .collect::<Result<Vec<_>, ReservationWriteError>>()?;
    let params = WriteAdmissionParams {
        reservation_id: token.reservation_id.as_str().to_owned(),
        reservation_order: token.reservation_order,
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        scopes,
        writer_epoch: WriterEpochBinding {
            lineage_id: writer_epoch.current.lineage_id.as_str().to_owned(),
            epoch: writer_epoch.current.epoch,
            predecessor_lineage_id: writer_epoch
                .predecessor
                .as_ref()
                .map(|prior| prior.lineage_id.as_str().to_owned()),
            predecessor_epoch: writer_epoch.predecessor.as_ref().map(|prior| prior.epoch),
        },
        state_fence: context.state_fence.clone(),
        source_id: context.source_id.as_str().to_owned(),
        created_at_ms: sealed.created_at_ms,
        expires_at_ms: token.expires_at_ms,
        recovery_owner: token.recovery_owner.as_str().to_owned(),
    };
    let admission = WriteAdmissionProjection::bind(transition, params)?;
    let request = ReservedWriteRequest {
        context: context.clone(),
        transition: transition.clone(),
        admission,
        expected_revision_heads,
        expected_ordering_heads,
    };
    request.validate()?;
    Ok(request)
}

/// Advances a head reservation to eligibility after all predecessors close.
///
/// A missing predecessor fails with the owner `PredecessorPending` error and
/// dispatches nothing. No admission lease, Kernel lock, provider permit, or
/// protected-control resource is held: this is a bounded ORS-local check.
pub fn ensure_eligible(
    owner: &CompositionReservation,
    token: &WriterReservationToken,
) -> Result<ReservationRecord, ReservationWriteError> {
    Ok(owner.ors.mark_eligible(token)?)
}

/// Starts execution only after the single Store send resolved, under the
/// exact immutable writer epoch.
///
/// The `send` evidence must bind this token's operation: it proves the caller
/// observed the single send resolve before `Executing` is entered, so a
/// refused backend can never strand an `Executing` reservation without
/// receipt evidence. A mismatched evidence object fails closed here without
/// touching ORS. A stale executor fails with the owner `StaleWriterEpoch`
/// error and can neither execute nor finalize another generation's token.
///
/// The evidence is unforgeable outside the crate: [`ResolvedSendOutcome`]
/// fields are private and its only production constructor
/// ([`ResolvedSendOutcome::after_resolved_send`]) is `pub(crate)`, called
/// exclusively from the two resolved-send match arms in `store_gateway.rs`
/// after the transport future returns. External lifecycle callers cannot mint
/// it; the explicitly test-only [`ResolvedSendOutcome::mint_for_test`] is
/// compiled only under `cfg(test)` and is absent from every non-test build,
/// including ordinary debug dependency builds. White-box lifecycle proofs
/// therefore live in crate unit tests; a downstream-shaped `compile_fail`
/// doctest on [`ResolvedSendOutcome`] proves external callers cannot name the
/// mint.
pub fn begin_execute_after_send(
    owner: &CompositionReservation,
    token: &WriterReservationToken,
    send: &ResolvedSendOutcome,
) -> Result<ReservationRecord, ReservationWriteError> {
    if send.operation_id() != token.operation_id.as_str() {
        return Err(ReservationWriteError::Binding {
            operation_id: token.operation_id.as_str().to_owned(),
            detail: "post-send evidence operation does not match the reservation operation"
                .to_owned(),
        });
    }
    Ok(owner.ors.begin_execute(token, owner.writer_identity())?)
}

/// Typed evidence that the single Store send for one reservation resolved.
///
/// Unforgeable capability: the struct fields are private, so no caller outside
/// this crate can construct a value. The only production constructor is the
/// `pub(crate)` [`ResolvedSendOutcome::after_resolved_send`], which the
/// gateway's bounded post-send path calls after the transport future returns
/// (the `Ok` receipt arm and the still-unknown arm of `apply_reserved`); the
/// deterministically-refused-without-effect path never reaches execution (it
/// releases the still-`Eligible` token instead), so no constructor exists for
/// it by construction. [`begin_execute_after_send`] re-checks the binding and
/// fails closed on mismatch without touching ORS, so a pre-send caller
/// holding only `(owner, token)` cannot advance execution: there is no public
/// constructor to mint, and a mismatched evidence object is refused at
/// runtime. The former `for_token` public constructor and the documentary
/// `ResolvedSendKind` (which never participated in the transition contract)
/// are removed.
///
/// Lifecycle proofs that drive ORS directly live in crate unit tests and use
/// the explicitly test-only [`ResolvedSendOutcome::mint_for_test`], which
/// exists only under `cfg(test)` and is absent from every non-test build,
/// including ordinary debug dependency builds. No downstream or integration
/// caller can name it:
///
/// ```compile_fail
/// // Post-send evidence cannot be minted outside the crate in any non-test
/// // build, including an ordinary debug dependency build.
/// let _ = eliot_kernel_service::ResolvedSendOutcome::mint_for_test;
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedSendOutcome {
    operation_id: String,
    _sealed: (),
}

impl ResolvedSendOutcome {
    /// Mints post-send evidence bound to one reservation token's operation.
    ///
    /// Crate-internal: the only production callers are the two resolved-send
    /// match arms in `store_gateway.rs`, invoked after the transport future
    /// returns. Lifecycle callers outside the crate cannot reach this
    /// constructor.
    pub(crate) fn after_resolved_send(token: &WriterReservationToken) -> Self {
        Self {
            operation_id: token.operation_id.as_str().to_owned(),
            _sealed: (),
        }
    }

    /// TEST-ONLY post-send evidence mint for lifecycle proofs.
    ///
    /// Compiled only under `cfg(test)` (crate unit tests) and absent from
    /// every non-test build, including ordinary debug dependency builds.
    /// Production code must never call this: the gateway mints evidence only
    /// after the transport future returns via
    /// [`ResolvedSendOutcome::after_resolved_send`].
    #[cfg(test)]
    pub(crate) fn mint_for_test(token: &WriterReservationToken) -> Self {
        Self::after_resolved_send(token)
    }

    /// Returns the bound operation identity.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

/// Releases work that has not executed under the exact writer epoch.
///
/// Valid only from `Reserved`/`Eligible`: before-send cancellation releases
/// exactly this token and nothing else. From `Executing`/`Reconciling` the
/// owner rejects with `InvalidTransition`, preserving identity until exact
/// receipt reconciliation: cancellation, timeout, or socket replacement can
/// never finalize or free such a reservation.
pub fn cancel_before_send(
    owner: &CompositionReservation,
    token: &WriterReservationToken,
) -> Result<ReservationRecord, ReservationWriteError> {
    Ok(owner.ors.release(token, owner.writer_identity())?)
}

/// Records one staged `PreparedTransition` this build refuses to execute as a
/// visible durable Recovery Problem (issue #1927, I05-06).
///
/// Called when the single send resolved to a determinate refusal because the
/// plan's recorded contract or operation manifest lies outside current
/// admissible support. No external effect occurred, so the reserved order is
/// still safely disposable and the caller releases it as usual - but I05-06
/// requires the plan itself to stay staged and enter visible recovery instead
/// of being reinterpreted by newer code, so the refusal is recorded durably
/// first, keyed by the staged operation identity.
///
/// Recording before the release matters: the retention reads the staged
/// operation's own epoch, fence, recovery owner and reservation identity, so
/// the problem cannot disagree with what was actually staged. It carries no
/// payload bytes, and an unresolved problem blocks normal writer readiness
/// until an explicit canonical receipt or owner disposition resolves it.
pub fn retain_unsupported_prepared_plan(
    owner: &CompositionReservation,
    token: &WriterReservationToken,
    detail: &str,
) -> Result<eliot_ors::RecoveryProblem, ReservationWriteError> {
    Ok(owner
        .ors
        .retain_unsupported_prepared_transition(&token.operation_id, detail)?)
}

/// Marks an ambiguous effect non-replayable until canonical reconciliation.
///
/// Called when the single send resolves to a still-unknown outcome after
/// execution started. The scope recovery block closes dependent allocation
/// while leaving unrelated scopes eligible.
pub fn mark_unknown_outcome(
    owner: &CompositionReservation,
    token: &WriterReservationToken,
) -> Result<ReservationRecord, ReservationWriteError> {
    let reason = OpaqueLabel::new(UNKNOWN_OUTCOME_REASON).map_err(ReservationWriteError::Ors)?;
    Ok(owner
        .ors
        .mark_unknown(token, owner.writer_identity(), reason)?)
}

/// Builds the exact receipt-evidence closure for one token from a verified
/// Store receipt, without mutating ORS.
///
/// The receipt must be the committed-or-terminally-not-applied answer to the
/// same operation: operation identity, fence snapshot, scope/sequence
/// coverage, and the envelope binding are all re-checked here, and the owner
/// re-checks them again with its evidence provider at [`finalize_reservation`].
/// A terminally-not-applied status (`Rejected`, `Cancelled`, `DeadLetter`)
/// releases only when the verified reconciliation envelope explicitly proves
/// the operation was not applied (envelope kind `Failure` or `Cancelled`);
/// any other envelope kind (including `Success`, `Partial`, or `Unknown`)
/// yields [`ReservationWriteError::Unknown`] and retains the reservation for
/// reconciliation instead of releasing it. A receipt without a
/// reconciliation envelope (still unknown) fails here and stays distinct from
/// proved-not-applied. This constructs evidence, never authority: only
/// [`finalize_reservation`] closes the token.
pub fn reconcile_receipt(
    token: &WriterReservationToken,
    receipt: &WriteReceipt,
) -> Result<CanonicalReconciliation, ReservationWriteError> {
    let operation_id = token.operation_id.as_str().to_owned();
    receipt.validate().map_err(|error| {
        if error == eliot_store_api::StoreError::MissingReceiptEnvelope {
            ReservationWriteError::Unknown {
                operation_id: operation_id.clone(),
                detail: "Store receipt carries no reconciliation envelope; outcome stays unknown"
                    .to_owned(),
            }
        } else {
            ReservationWriteError::Store(error)
        }
    })?;
    let envelope = receipt.require_reconciliation_envelope().map_err(|error| {
        if error == eliot_store_api::StoreError::MissingReceiptEnvelope {
            ReservationWriteError::Unknown {
                operation_id: operation_id.clone(),
                detail: "Store receipt carries no reconciliation envelope; outcome stays unknown"
                    .to_owned(),
            }
        } else {
            ReservationWriteError::Store(error)
        }
    })?;
    let disposition = match receipt.status {
        WriteReceiptStatus::Committed => CanonicalDisposition::Committed,
        WriteReceiptStatus::Rejected
        | WriteReceiptStatus::Cancelled
        | WriteReceiptStatus::DeadLetter => match envelope.core.disposition.kind() {
            ReceiptDispositionKind::Failure | ReceiptDispositionKind::Cancelled => {
                CanonicalDisposition::Rejected
            }
            _ => {
                return Err(ReservationWriteError::Unknown {
                    operation_id: operation_id.clone(),
                    detail: "Store receipt envelope does not prove the operation was not applied; outcome stays unknown"
                        .to_owned(),
                });
            }
        },
    };
    check_receipt_token_binding(token, receipt, envelope, &operation_id)?;
    let receipt_id = OpaqueLabel::new(envelope.identity.receipt_id.as_str())
        .map_err(ReservationWriteError::Ors)?;
    let scopes = token
        .scopes
        .iter()
        .map(|reserved| CanonicalScopeObservation {
            scope: reserved.scope.clone(),
            prior_head: reserved.expected_head.clone(),
            committed_sequence: reserved.reserved_sequence,
            committed_head_sha256: envelope.identity.canonical_sha256.clone(),
            committed_revision_head: None,
            receipt_id: receipt_id.clone(),
        })
        .collect();
    Ok(CanonicalReconciliation {
        reservation_id: token.reservation_id.clone(),
        operation_id: token.operation_id.clone(),
        reservation_order: token.reservation_order,
        state_fence: token.state_fence.clone(),
        recovery_owner: token.recovery_owner.clone(),
        scopes,
        receipt: envelope.clone(),
        disposition,
    })
}

/// Re-checks the same-operation binding between a verified receipt and a
/// token: operation identity (receipt and envelope), fence snapshot, exact
/// scope/sequence coverage, and the single-scope causal sequence.
///
/// Staging step shared with [`reconcile_receipt`] so the constructor stays a
/// composition of audited checks rather than one long body.
fn check_receipt_token_binding(
    token: &WriterReservationToken,
    receipt: &WriteReceipt,
    envelope: &ReceiptEnvelope,
    operation_id: &str,
) -> Result<(), ReservationWriteError> {
    let binding = |detail: &str| ReservationWriteError::Binding {
        operation_id: operation_id.to_owned(),
        detail: detail.to_owned(),
    };
    if receipt.operation_id.as_str() != operation_id {
        return Err(binding(
            "Store receipt operation does not match the reservation operation",
        ));
    }
    if envelope.core.operation.operation_id.as_str() != operation_id {
        return Err(binding(
            "receipt envelope operation does not match the reservation operation",
        ));
    }
    let write_binding = token
        .write_binding
        .as_ref()
        .ok_or_else(|| binding("reservation has no retained versioned write binding"))?;
    write_binding.validate().map_err(|error| {
        binding(&format!(
            "retained versioned write binding is invalid: {error}"
        ))
    })?;
    if write_binding.operation_id.as_str() != operation_id
        || write_binding.operation_id != token.operation_id
        || write_binding.idempotency_key.as_str() != receipt.idempotency_key
        || write_binding.idempotency_key.as_str() != envelope.core.operation.idempotency_key
        || write_binding.canonical_request_sha256 != receipt.canonical_request_hash
        || write_binding.prepared_transition_sha256 != token.prepared_transition_sha256
        || write_binding.authority_epoch != token.writer_epoch
        || write_binding.state_fence != token.state_fence
        || write_binding.admission_contract_set_digest.is_empty()
    {
        return Err(binding(
            "retained write identity does not match the token and canonical receipt",
        ));
    }
    if write_binding.operation_manifest_digest.as_str()
        != receipt.operation_manifest_digest.as_str()
    {
        return Err(binding(
            "canonical receipt operation manifest differs from the retained write binding",
        ));
    }
    let mut bound_scopes: Vec<_> = write_binding
        .ordering_scopes
        .iter()
        .map(|scope| scope.as_str())
        .collect();
    let mut token_scopes: Vec<_> = token
        .scopes
        .iter()
        .map(|scope| scope.scope.as_str())
        .collect();
    let mut receipt_scopes: Vec<_> = receipt
        .ordering_sequences
        .iter()
        .map(|head| (head.scope.as_str(), head.sequence))
        .collect();
    let mut reserved_sequences: Vec<_> = token
        .scopes
        .iter()
        .map(|scope| (scope.scope.as_str(), scope.reserved_sequence))
        .collect();
    bound_scopes.sort_unstable();
    token_scopes.sort_unstable();
    receipt_scopes.sort_unstable();
    reserved_sequences.sort_unstable();
    if bound_scopes != token_scopes || receipt_scopes != reserved_sequences {
        return Err(binding(
            "canonical receipt scope sequences do not exactly match the retained write scope set",
        ));
    }
    let fenced = StateFenceSnapshot::capture(
        &receipt.state_fence,
        envelope.core.authority.authority_epoch.sequence.get(),
    )
    .map_err(ReservationWriteError::Ors)?;
    if fenced != token.state_fence
        || fenced != write_binding.state_fence
        || envelope.core.authority.authority_epoch.lineage_id.as_str()
            != write_binding.authority_epoch.current.lineage_id.as_str()
        || envelope.core.authority.authority_epoch.sequence.get()
            != write_binding.authority_epoch.current.epoch
    {
        return Err(binding(
            "Store receipt fence does not match the reservation fence",
        ));
    }
    let transition_artifact_id = format!("store-transition:{operation_id}");
    let mut transition_artifacts = envelope
        .core
        .artifacts
        .iter()
        .filter(|artifact| artifact.artifact_id.as_str() == transition_artifact_id);
    let Some(transition_artifact) = transition_artifacts.next() else {
        return Err(binding(
            "canonical receipt omits the retained prepared-transition artifact",
        ));
    };
    if transition_artifacts.next().is_some()
        || transition_artifact.role != ReceiptKind::Operation
        || transition_artifact.sha256 != write_binding.prepared_transition_sha256
        || transition_artifact.source_revision.as_deref()
            != Some(write_binding.operation_manifest_digest.as_str())
    {
        return Err(binding(
            "canonical receipt prepared-transition artifact or manifest differs from the retained write binding",
        ));
    }
    let disposition_matches = match receipt.status {
        WriteReceiptStatus::Committed => matches!(
            envelope.core.disposition.kind(),
            ReceiptDispositionKind::Success | ReceiptDispositionKind::Partial
        ),
        WriteReceiptStatus::Rejected
        | WriteReceiptStatus::Cancelled
        | WriteReceiptStatus::DeadLetter => matches!(
            envelope.core.disposition.kind(),
            ReceiptDispositionKind::Failure | ReceiptDispositionKind::Cancelled
        ),
    };
    if !disposition_matches {
        return Err(ReservationWriteError::Unknown {
            operation_id: operation_id.to_owned(),
            detail: "canonical receipt disposition does not prove the observed terminal outcome; reservation remains unresolved".to_owned(),
        });
    }
    if receipt.ordering_sequences.len() != token.scopes.len() {
        return Err(binding(
            "Store receipt scope set does not cover the reserved scope set",
        ));
    }
    for reserved in &token.scopes {
        let covered = receipt.ordering_sequences.iter().any(|head| {
            head.scope.as_str() == reserved.scope.as_str()
                && head.sequence == reserved.reserved_sequence
        });
        if !covered {
            return Err(binding("Store receipt misses a reserved scope sequence"));
        }
    }
    // No envelope-causal restatement is demanded here, deliberately. The
    // reserved-order binding is established above on the receipt body
    // (scope set plus per-scope sequences), and the envelope operation,
    // fence and structural validity are checked by the caller chain.
    // A single-scope causal equality against the reserved sequence would
    // require the producer to state a non-genesis chain position, but the
    // canonical causal model admits non-genesis positions only with a
    // parent link (`CausalBinding::validate`: "non-genesis receipt
    // requires a parent"), the closed store issuance carries genesis, and
    // no consumer reads the envelope causal. Demanding the restatement
    // therefore rejects every live receipt while proving nothing the body
    // checks do not already prove (issue #2031 native cases 15/19).
    Ok(())
}

/// Closes an executing/unknown reservation from exact receipt evidence.
///
/// `Committed` finalizes; terminally-not-applied (`Rejected`, including the
/// dead-letter gap) releases with the terminal receipt bound. The owner
/// verifies the reconciliation through the composition-bound evidence provider
/// and advances all token scopes atomically. Partial release, a stale
/// executor, and another generation's token are rejected by the owner.
pub fn finalize_reservation(
    owner: &CompositionReservation,
    reconciliation: &CanonicalReconciliation,
) -> Result<ReservationRecord, ReservationWriteError> {
    Ok(owner.ors.reconcile(reconciliation)?)
}

/// Lists every unresolved (non-terminal) reservation ordered by the ORS
/// recovery projection.
///
/// Pages the bounded recovery cursor to exhaustion: every continuation is
/// followed until no truncation signal remains, so a restart/rebind observes
/// the complete unresolved set before admitting new eligible work. Recovery
/// pages advance over strictly increasing reservation orders, so the loop
/// always progresses; the per-page bound only limits one read, never the
/// reported set.
///
/// Used on restart/rebind to recover every affected token and original
/// operation before new eligible writes, and by migration drain to account for
/// all reservations without forced release.
pub fn unresolved_reservations(
    owner: &CompositionReservation,
    limit: u16,
) -> Result<Vec<ReservationRecord>, ReservationWriteError> {
    let mut unresolved = Vec::new();
    let mut after_order = 0u64;
    loop {
        let cursor = eliot_ors::RecoveryCursor::new(after_order, limit)
            .map_err(ReservationWriteError::Ors)?;
        let page = owner.ors.recover_page(cursor)?;
        unresolved.extend(page.records.into_iter().filter(|record| {
            !matches!(
                record.state,
                eliot_ors::ReservationState::Finalized | eliot_ors::ReservationState::Released
            )
        }));
        match page.next_after_order {
            Some(next) => after_order = next,
            None => break,
        }
    }
    Ok(unresolved)
}

/// Derives the composition writer epoch from the exact live fence tuple.
///
/// Helper for the gateway boundary: the lineage label and sequence come from
/// the trusted composition fence, never from caller text. The predecessor
/// edge stays empty here; succession edges are owned by the epoch authority,
/// not by this binding.
pub fn writer_epoch_for_fence(
    context: &RequestMetadata,
) -> Result<EpochLineage, ReservationWriteError> {
    writer_epoch_for_fence_from_epoch(&context.state_fence.authority_epoch)
}

/// Derives the composition writer epoch from one live authority epoch.
///
/// Used where no admitted fence is presented (cancellation, drain): the epoch
/// comes from the live composition authority observed under the service lock,
/// never from caller text.
pub fn writer_epoch_for_fence_from_epoch(
    epoch: &EpochId,
) -> Result<EpochLineage, ReservationWriteError> {
    Ok(EpochLineage {
        current: EpochIdentity {
            lineage_id: OpaqueLabel::new(epoch.lineage_id.as_str())
                .map_err(ReservationWriteError::Ors)?,
            epoch: epoch.sequence.get(),
        },
        predecessor: None,
    })
}

/// Reads one bounded ORS recovery page without filtering.
///
/// Used by migration drain to account for every reservation, including the
/// truncation signal, before exclusivity.
pub fn recovery_page(
    owner: &CompositionReservation,
    limit: u16,
) -> Result<RecoveryPage, ReservationWriteError> {
    let cursor = RecoveryCursor::new(0, limit).map_err(ReservationWriteError::Ors)?;
    Ok(owner.ors.recover_page(cursor)?)
}

/// Builds the composition-owned reservation seed for one admitted transition.
///
/// This is the only payload producer this crate has, and it exists because the
/// two honest `I5.2` payload shapes resolve to one of them here: the staged
/// bytes are the admitted transition's own canonical JSON, sealed by the
/// installation secret owner `I15.4` names
/// ([`WindowsPlatform::protect_secret`](eliot_platform_windows::WindowsPlatform::protect_secret)),
/// so the `RecoveryPayload::Encrypted` claim ORS is told is true. An earlier
/// revision of this function refused instead; an earlier revision of the file
/// staged the admitted plaintext under the same `Encrypted` label, which I5.2
/// forbids and which `refuse_plaintext_payload` still refuses independently
/// before any ORS mutation. This revision adds no cipher, no key material and
/// no second encoding.
///
/// The operation identity is the admitted one, byte for byte, and the ORS
/// reservation label is derived from that same identity rather than supplied
/// beside it, so no caller can pair one operation's identity with another
/// operation's reservation. DPAPI seals are freshly randomized per call, so a
/// re-seeded replay of the same operation identity produces different
/// ciphertext; the durable envelope stays the one ORS already holds for that
/// reservation id, and this function never rewrites it. `heads` is the head
/// set the caller observed; [`reserve_for_transition`] independently re-derives
/// the same scope/sequence comparison against the admitted expectations and
/// refuses a mismatch, so this list is evidence, never the authority.
///
/// A platform that cannot protect (no DPAPI, no user scope) refuses here with
/// the preserved operation identity. It never falls back to plaintext, and it
/// never downgrades the envelope to the root-transition-only
/// `RecoveryPayload::CanonicalRequest` variant.
///
/// This producer has no production caller, and that is recorded rather than
/// worked around: the only route that consumes a seed is
/// `KernelStoreGateway::apply_reserved`, which no live route reaches, and
/// `ReservationSeed { .. }` is constructed nowhere else in production. It is
/// kept honest here so that when the reserved route becomes reachable the
/// producer is already correct rather than a refusal. The four searched
/// negatives that keep the route unreachable — the Store's uninstalled
/// reserved-write execution generation, the unadvertised
/// `CAPABILITY_RESERVED_WRITE`, the missing production source for
/// [`ObservedHead::expected_head_digest`], and ORS's unbound
/// `CanonicalEvidenceProvider` — are each cited with file and line at the live
/// canonical write call site in
/// `bins/eliot-kernel/src/daemon_request_dispatch.rs`.
pub fn gateway_seed(
    platform: &eliot_platform_windows::WindowsPlatform,
    transition: &PreparedTransition,
    recovery_owner: &str,
    created_at_ms: i64,
    known_at_ms: i64,
    expires_at_ms: i64,
    heads: &[ObservedHead],
) -> Result<ReservationSeed, ReservationWriteError> {
    let operation_id = transition.identity.operation_id.as_str().to_owned();
    let plaintext = eliot_contracts::canonical_json_bytes(transition).map_err(|error| {
        ReservationWriteError::Admission {
            operation_id: operation_id.clone(),
            detail: format!("admitted transition canonical bytes do not encode: {error}"),
        }
    })?;
    let protected = platform.protect_secret(&plaintext).map_err(|error| {
        ReservationWriteError::Unsupported {
            operation_id: operation_id.clone(),
            detail: format!(
                "reservation for operation {operation_id} and recovery owner {recovery_owner} \
                 (created {created_at_ms}, known {known_at_ms}, expires {expires_at_ms}, {} \
                 reserved scopes) was not staged: the installation secret provider could not \
                 protect the admitted payload ({error}); the envelope is never staged as \
                 plaintext",
                heads.len()
            ),
        }
    })?;
    Ok(ReservationSeed {
        reservation_id: operation_id.clone(),
        operation_id,
        recovery_owner: recovery_owner.to_owned(),
        payload_bytes: protected.as_bytes().to_vec(),
        key_provider: RESERVATION_KEY_PROVIDER.to_owned(),
        key_name: RESERVATION_KEY_NAME.to_owned(),
        visibility: RESERVATION_VISIBILITY.to_owned(),
        created_at_ms,
        known_at_ms,
        expires_at_ms,
        heads: heads.to_vec(),
    })
}

/// Kernel-visible reserved submission: one validated closed reserved-write
/// request selecting the exact Store reserved-write capability (issue #2031).
///
/// Carries the `#990` sealed admission binding across the Kernel-to-Store
/// boundary together with the `#991` capability identity, so capability gates
/// (wire `StoreRequest::capability`, session admission, scheduler profile)
/// observe the same value the Store backend enforces. The request is validated
/// at construction; no second serializer exists and no fallback to unreserved
/// `Apply` is possible through this type. The capability is the Store
/// declaration itself ([`CAPABILITY_RESERVED_WRITE`]): API presence is not
/// readiness, and the capability stays unadvertised until a backend with an
/// accepted scheduler advertises it. Kernel submissions always name it, so a
/// session without the admitted capability refuses before dispatch while
/// ordinary operations keep flowing.
#[derive(Clone, Debug)]
pub struct ReservedSubmission {
    request: ReservedWriteRequest,
}

impl ReservedSubmission {
    /// Wraps one closed reserved-write request after validating its shape.
    ///
    /// Shape failures preserve the owner `StoreError`; nothing is staged,
    /// sent, or reconciled here.
    pub fn new(request: ReservedWriteRequest) -> Result<Self, ReservationWriteError> {
        request.validate()?;
        Ok(Self { request })
    }

    /// Projects one sealed reservation into a submission carrying the reserved
    /// capability.
    ///
    /// Runs the exact `#990` projection shared with the gateway path, then
    /// validates once more at the boundary. A transition mutated after
    /// reservation fails here.
    pub fn from_sealed(
        sealed: &SealedReservation,
        context: &RequestMetadata,
        transition: &PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<Self, ReservationWriteError> {
        Self::new(project_reserved_write(
            sealed,
            context,
            transition,
            expected_revision_heads,
            expected_ordering_heads,
        )?)
    }

    /// Exact Store capability this submission selects.
    pub fn capability(&self) -> &'static str {
        CAPABILITY_RESERVED_WRITE
    }

    /// Borrows the closed reserved-write request.
    pub fn request(&self) -> &ReservedWriteRequest {
        &self.request
    }

    /// Releases the owned closed request for the single authenticated send.
    pub fn into_request(self) -> ReservedWriteRequest {
        self.request
    }
}

/// One persisted reservation still unresolved at startup (I1.11 step 6).
///
/// A reference, never authority: identity, scopes, lifecycle state and
/// recovery owner are restated so the Kernel can gate step 6 without
/// reading ORS itself. The `reason` uses fixed vocabulary
/// (`awaiting store receipt`, `fence mismatch`) so the report stays a
/// bounded diagnostic, not an error log.
#[derive(Clone, Debug)]
pub struct StartupPendingOperation {
    /// Store operation identity.
    pub operation_id: String,
    /// ORS reservation identity that owns the operation.
    pub reservation_id: String,
    /// ORS-assigned reservation order.
    pub reservation_order: u64,
    /// Reserved scope identities, sorted.
    pub scopes: Vec<String>,
    /// Lifecycle state observed during the scan.
    pub state: ReservationState,
    /// Recovery owner preserved from the token.
    pub recovery_owner: String,
    /// Fixed-vocabulary blocking reason.
    pub reason: String,
}

/// One persisted reservation whose outcome is ambiguous at startup.
///
/// Unknown covers `Reconciling` tokens and any token whose Store receipt
/// observation is absent or refuses reconciliation: the outcome stays
/// unresolved, never retried, never replayed, never force-released.
#[derive(Clone, Debug)]
pub struct StartupUnknownOperation {
    /// Store operation identity.
    pub operation_id: String,
    /// ORS reservation identity that owns the operation.
    pub reservation_id: String,
    /// ORS-assigned reservation order.
    pub reservation_order: u64,
    /// Reserved scope identities, sorted.
    pub scopes: Vec<String>,
    /// Lifecycle state observed during the scan.
    pub state: ReservationState,
    /// Recovery owner preserved from the token.
    pub recovery_owner: String,
    /// Fixed-vocabulary ambiguity reason (`no store receipt`,
    /// `reconciliation refused`).
    pub reason: String,
}

/// Step-6 readiness verdict over a startup reconciliation report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupReconciliationReadiness {
    /// The reservation and control obligation checks are exhausted, the
    /// revision-bound inventory covered all five ORS sources, and there is no
    /// unresolved reservation or active control obligation.
    Ready,
    /// A reservation or active control obligation remains unresolved, a
    /// bounded scan did not reach exhaustion, or cursor coverage disagrees
    /// with the rows observed. Since ORS does not yet provide a typed mapping
    /// from checkpoint/inbox subjects to affected scopes, any such obligation
    /// conservatively keeps dependent normal writes behind step 6; the
    /// independent recovery control path remains available.
    Blocked,
}

/// Bounded reconciliation report over the ORS startup obligation sources.
///
/// Produced by [`reconcile_pending_at_startup`] from the persisted ORS
/// reservation, operational-current, recovery-inbox, recovery-problem and
/// write-idempotency pages, plus exact canonical Store receipt observations
/// read through the named authenticated gateway. Every source is paged to
/// explicit exhaustion under one five-revision snapshot and the snapshot is
/// revalidated after the final page. A missing or ambiguous receipt leaves its
/// token unresolved and reported; nothing is synthesized, retried, or released
/// to pass.
#[derive(Clone, Debug)]
pub struct StartupReconciliation {
    /// Live fence the scan ran under; Kernel matches it exactly.
    pub fence: StateFence,
    /// Digest over the fence, bounded lookup trace, final inventory coverage,
    /// reservation outcomes, and control-obligation sample/counts.
    pub digest: String,
    /// Revision-bound coverage of every ORS startup inventory source.
    pub inventory_coverage: StartupRecoveryInventoryCoverage,
    /// Number of active reservation rows actually processed by the partial
    /// keyset lookup. Full-source coverage is recorded separately in
    /// `inventory_coverage`.
    pub scanned: u64,
    /// Exhaustive five-source preflight coverage established before any
    /// receipt-driven ORS mutation.
    pub preflight_inventory_coverage: StartupRecoveryInventoryCoverage,
    /// Number of bounded reservation pages consumed by the partial keyset
    /// lookup; this is not a full-inventory page count.
    pub reservation_lookup_page_count: u64,
    /// Number of primary reservation rows returned by the partial keyset
    /// lookup, including terminal rows and rows seen before own mutations.
    pub reservation_lookup_record_count: u64,
    /// Rolling digest over each partial lookup page, its snapshot, opaque
    /// cursor, reservation identities, and explicit continuation.
    pub reservation_lookup_digest: String,
    /// Whether the final partial keyset suffix reached explicit exhaustion.
    /// This field never establishes full-source coverage.
    pub reservation_lookup_suffix_exhausted: bool,
    /// Absolute difference between final active-row and reported unresolved
    /// counts. Identity equality is reported separately.
    pub unresolved_count_delta: u64,
    /// Whether the ordered unresolved outcome identity stream matches the
    /// independent full-inventory active reservation stream.
    pub unresolved_identity_match: bool,
    /// Exact number of active checkpoint records in the frozen inventory.
    pub job_checkpoint_record_count: u64,
    /// Sorted sample of active checkpoint subjects, capped at `page_size`.
    pub job_checkpoint_ref_sample: Vec<String>,
    /// Exact number of active delivery-cursor records in the frozen inventory.
    pub delivery_cursor_record_count: u64,
    /// Sorted sample of active delivery-cursor subjects, capped at `page_size`.
    pub delivery_cursor_ref_sample: Vec<String>,
    /// Exact number of imported recovery-inbox records in the frozen inventory.
    pub recovery_inbox_record_count: u64,
    /// Sorted sample of imported recovery-inbox identities, capped at `page_size`.
    pub recovery_inbox_ref_sample: Vec<String>,
    /// Maximum row count requested for each bounded source page.
    pub page_size: u16,
    /// Bounded sample of unresolved non-unknown operations, capped at
    /// `page_size` entries.
    pub pending: Vec<StartupPendingOperation>,
    /// Exact number of unresolved non-unknown operations.
    pub pending_count: u64,
    /// Bounded sample of ambiguous operations, capped at `page_size` entries.
    pub unknown: Vec<StartupUnknownOperation>,
    /// Exact number of ambiguous operations, including rows not present in
    /// the bounded sample.
    pub unknown_count: u64,
    /// Exact number of nonterminal reservation rows in the final inventory.
    pub active_reservation_count: u64,
    /// Bounded sample of durable Recovery Problems from the final inventory.
    pub retained_problem_sample: Vec<eliot_ors::RecoveryProblem>,
    /// Exact number of durable Recovery Problem rows in the final inventory.
    pub retained_problem_count: u64,
    /// Exact number of unresolved durable Recovery Problem rows.
    pub unresolved_retained_problem_count: u64,
}

impl StartupReconciliation {
    /// Returns the verdict for this report: `Ready` requires every ORS source
    /// to have complete cursor coverage under one final-revalidated snapshot,
    /// an exhausted partial lookup, matching unresolved/active identity
    /// streams, a valid page size, and no pending, unknown, active reservation
    /// or unresolved retained problem. Any active checkpoint, delivery-cursor,
    /// or imported inbox obligation also blocks the dependent normal-write
    /// gate. ORS does not yet expose subject-to-scope mapping, so this is a
    /// conservative global step-6 gate; per-scope reopening remains partial.
    pub fn readiness(&self) -> StartupReconciliationReadiness {
        if self.inventory_coverage.is_complete()
            && self.preflight_inventory_coverage.is_complete()
            && self.page_size > 0
            && self.reservation_lookup_suffix_exhausted
            && self.unresolved_count_delta == 0
            && self.unresolved_identity_match
            && self.active_reservation_count == 0
            && self.pending_count == 0
            && self.unknown_count == 0
            && self.job_checkpoint_record_count == 0
            && self.delivery_cursor_record_count == 0
            && self.recovery_inbox_record_count == 0
            && self.unresolved_retained_problem_count == 0
        {
            StartupReconciliationReadiness::Ready
        } else {
            StartupReconciliationReadiness::Blocked
        }
    }
}

/// Per-record outcome of one startup reconciliation step.
enum StartupRecordOutcome {
    /// Exact receipt observed, reconciled and finalized: no report entry.
    Resolved,
    /// Unresolved, non-unknown: reported pending with a fixed reason.
    Pending { reason: String },
    /// Ambiguous: reported unknown with a fixed reason.
    Unknown { reason: String },
}

/// Observes the exact Store receipt for one persisted reservation and
/// reconciles it where the receipt resolves. Records minted under a
/// different writer epoch than the bound owner are never touched. A
/// failed check (transport/ORS) is an error, never a guessed outcome.
///
/// The receipt is read through the named authenticated gateway
/// ([`StartupReceiptRoute`]), never through the raw `CanonicalStoreClient`
/// trait call, and it is read under the exact fence the token itself recorded
/// (issue #1713, item 6). A gateway refusal is a failed check and propagates
/// as an error; it is never reported as an absent receipt, a rejection, or a
/// safely absent operation.
async fn reconcile_one_record(
    owner: &CompositionReservation,
    route: &dyn StartupReceiptRoute,
    record: &ReservationRecord,
) -> Result<StartupRecordOutcome, ReservationWriteError> {
    let token = &record.token;
    // Legacy ORS rows remain readable so startup can report them, but their
    // missing original submission binding cannot authorize receipt lookup or
    // reconciliation under a guessed identity.
    let Some(write_binding) = token.write_binding.as_ref() else {
        return Ok(StartupRecordOutcome::Pending {
            reason: "missing retained write binding".to_owned(),
        });
    };
    write_binding
        .validate()
        .map_err(ReservationWriteError::Ors)?;
    // Same-authority rule: only tokens minted under the bound writer
    // epoch are eligible here. Anything else (restart under a new
    // epoch, foreign writer) is reported pending and never touched.
    if &token.writer_epoch != owner.writer_epoch() {
        return Ok(StartupRecordOutcome::Pending {
            reason: "fence mismatch".to_owned(),
        });
    }
    let operation_id = OperationId::new(token.operation_id.as_str()).map_err(|error| {
        ReservationWriteError::Binding {
            operation_id: token.operation_id.as_str().to_owned(),
            detail: format!("startup scan cannot address the reservation: {error}"),
        }
    })?;
    let state_fence = admitted_state_fence(token)?;
    let observed = route.observe_receipt(&state_fence, operation_id).await?;
    let Some(receipt) = observed else {
        if record.state == ReservationState::Reconciling {
            return Ok(StartupRecordOutcome::Unknown {
                reason: "no store receipt".to_owned(),
            });
        }
        return Ok(StartupRecordOutcome::Pending {
            reason: "awaiting store receipt".to_owned(),
        });
    };
    match reconcile_receipt(token, &receipt)
        .and_then(|reconciliation| finalize_reservation(owner, &reconciliation))
    {
        Ok(_) => Ok(StartupRecordOutcome::Resolved),
        Err(_) => {
            if record.state == ReservationState::Reconciling {
                Ok(StartupRecordOutcome::Unknown {
                    reason: "reconciliation refused".to_owned(),
                })
            } else {
                Ok(StartupRecordOutcome::Pending {
                    reason: "reconciliation refused".to_owned(),
                })
            }
        }
    }
}

fn reservation_state_name(state: ReservationState) -> &'static str {
    match state {
        ReservationState::Reserved => "reserved",
        ReservationState::Eligible => "eligible",
        ReservationState::Executing => "executing",
        ReservationState::Reconciling => "reconciling",
        ReservationState::Finalized => "finalized",
        ReservationState::Released => "released",
    }
}

fn startup_reservation_scan_entry(
    token: &WriterReservationToken,
    state: ReservationState,
    outcome: &str,
) -> String {
    let mut entry = String::new();
    append_startup_digest_field(&mut entry, token.operation_id.as_str());
    append_startup_digest_field(&mut entry, token.reservation_id.as_str());
    append_startup_digest_field(&mut entry, &token.reservation_order.to_string());
    append_startup_digest_field(&mut entry, reservation_state_name(state));
    append_startup_digest_field(&mut entry, token.recovery_owner.as_str());
    append_startup_digest_field(&mut entry, token.writer_epoch.current.lineage_id.as_str());
    append_startup_digest_field(&mut entry, &token.writer_epoch.current.epoch.to_string());
    match &token.writer_epoch.predecessor {
        Some(predecessor) => {
            append_startup_digest_field(&mut entry, "predecessor");
            append_startup_digest_field(&mut entry, predecessor.lineage_id.as_str());
            append_startup_digest_field(&mut entry, &predecessor.epoch.to_string());
        }
        None => append_startup_digest_field(&mut entry, "no-predecessor"),
    }
    append_startup_digest_field(&mut entry, &token.state_fence.sha256);
    append_startup_digest_field(
        &mut entry,
        &token.state_fence.observed_authority_epoch.to_string(),
    );
    append_startup_digest_field(&mut entry, &token.prepared_transition_sha256);
    let mut scope_bindings: Vec<_> = token.scopes.iter().collect();
    scope_bindings.sort_unstable_by(|left, right| left.scope.as_str().cmp(right.scope.as_str()));
    append_startup_digest_field(&mut entry, &scope_bindings.len().to_string());
    for scope in scope_bindings {
        append_startup_digest_field(&mut entry, scope.scope.as_str());
        append_startup_digest_field(&mut entry, &scope.reserved_sequence.to_string());
        append_startup_digest_field(&mut entry, &scope.expected_head.sequence.to_string());
        append_startup_digest_field(&mut entry, &scope.expected_head.head_sha256);
        match &scope.expected_head.revision_head {
            Some(revision_head) => {
                append_startup_digest_field(&mut entry, "revision-head");
                append_startup_digest_field(&mut entry, revision_head);
            }
            None => append_startup_digest_field(&mut entry, "no-revision-head"),
        }
    }
    append_startup_digest_field(&mut entry, outcome);
    entry
}

fn append_startup_digest_field(encoded: &mut String, value: &str) {
    encoded.push_str(&value.len().to_string());
    encoded.push(':');
    encoded.push_str(value);
}

fn extend_startup_digest_chain(previous_sha256: &str, entry: &str) -> String {
    let mut material = String::new();
    append_startup_digest_field(&mut material, previous_sha256);
    append_startup_digest_field(&mut material, entry);
    sha256_hex(material.as_bytes())
}

fn startup_scan_integrity_error(
    record_type: &'static str,
    reason: impl Into<String>,
) -> ReservationWriteError {
    ReservationWriteError::Ors(eliot_ors::OrsError::IntegrityProblem {
        record_type,
        reason: reason.into(),
    })
}

struct StartupRecoveryInventoryScan {
    coverage: StartupRecoveryInventoryCoverage,
    active_reservation_count: u64,
    active_identity_sha256: String,
    job_checkpoint_record_count: u64,
    job_checkpoint_ref_sample: Vec<String>,
    delivery_cursor_record_count: u64,
    delivery_cursor_ref_sample: Vec<String>,
    recovery_inbox_record_count: u64,
    recovery_inbox_ref_sample: Vec<String>,
    retained_problem_sample: Vec<RecoveryProblem>,
    retained_problem_count: u64,
    unresolved_retained_problem_count: u64,
}

/// Keeps a sorted sample whose resident set never exceeds the page-size cap;
/// exact source totals are counted separately while scanning.
fn add_bounded_reference_sample(sample: &mut BTreeSet<String>, value: &str, limit: u16) {
    if sample.contains(value) || sample.len() < usize::from(limit) {
        sample.insert(value.to_owned());
    }
}

fn increment_recovery_record_count(
    count: &mut u64,
    source: &'static str,
) -> Result<(), ReservationWriteError> {
    *count = count.checked_add(1).ok_or_else(|| {
        startup_scan_integrity_error(source, "startup obligation record count overflowed")
    })?;
    Ok(())
}

struct StartupRecoverySourceCoverageBuilder {
    source: &'static str,
    source_revision: u64,
    snapshot_sha256: String,
    page_count: u64,
    record_count: u64,
    start_cursor_sha256: Option<String>,
    expected_cursor_sha256: Option<String>,
    terminal_cursor_sha256: Option<String>,
    chain_sha256: String,
    complete: bool,
}

/// Trace of the mutable, partial reservation lookup used to reconcile rows.
/// It records exact page/row counts and a rolling page digest while retaining
/// only the opaque continuation needed for the current bounded sweep.
struct StartupReservationLookupTrace {
    page_count: u64,
    record_count: u64,
    chain_sha256: String,
    expected_cursor_sha256: Option<String>,
    last_reservation_id: Option<String>,
}

impl StartupReservationLookupTrace {
    fn new() -> Self {
        Self {
            page_count: 0,
            record_count: 0,
            chain_sha256: sha256_hex(b"eliot.kernel.startup-reservation-lookup.v1"),
            expected_cursor_sha256: None,
            last_reservation_id: None,
        }
    }

    fn observe_page(
        &mut self,
        snapshot: &RecoveryInventorySnapshot,
        cursor_sha256: &str,
        page: &eliot_ors::WriteReservationRecoveryPage,
        limit: u16,
    ) -> Result<(), ReservationWriteError> {
        if page.coverage != eliot_ors::WriteReservationRecoveryCoverage::PrimaryRowsFromStartAfter
            || page.source_revision != snapshot.reservation_revision
            || page.snapshot_sha256 != snapshot.snapshot_sha256
            || page.records.len() > usize::from(limit)
            || page.complete != page.next_cursor.is_none()
        {
            return Err(startup_scan_integrity_error(
                "startup_reservation_lookup_page",
                "partial reservation lookup page metadata disagrees with its snapshot or cursor",
            ));
        }
        if let Some(expected) = &self.expected_cursor_sha256
            && expected != cursor_sha256
        {
            return Err(startup_scan_integrity_error(
                "startup_reservation_lookup_cursor",
                "partial reservation continuation differs from the prior page",
            ));
        }
        if page.records.is_empty() && !page.complete {
            return Err(startup_scan_integrity_error(
                "startup_reservation_lookup_cursor",
                "partial reservation page made no primary-key progress",
            ));
        }
        for record in &page.records {
            let reservation_id = record.token.reservation_id.as_str();
            if self
                .last_reservation_id
                .as_deref()
                .is_some_and(|last| reservation_id <= last)
            {
                return Err(startup_scan_integrity_error(
                    "startup_reservation_lookup_cursor",
                    "partial reservation rows repeated or moved behind the exclusive keyset cursor",
                ));
            }
            self.last_reservation_id = Some(reservation_id.to_owned());
        }
        let next_cursor_sha256 = page
            .next_cursor
            .as_ref()
            .map(|cursor| startup_serialized_sha256(cursor, "startup_reservation_lookup_cursor"))
            .transpose()?;
        if next_cursor_sha256.as_deref() == Some(cursor_sha256) {
            return Err(startup_scan_integrity_error(
                "startup_reservation_lookup_cursor",
                "partial reservation cursor did not advance",
            ));
        }
        let page_records_sha256 =
            startup_serialized_sha256(&page.records, "startup_reservation_lookup_records")?;
        let row_count = u64::try_from(page.records.len()).map_err(|_| {
            startup_scan_integrity_error(
                "startup_reservation_lookup_page",
                "partial reservation page row count exceeds its coverage counter",
            )
        })?;
        self.page_count = self.page_count.checked_add(1).ok_or_else(|| {
            startup_scan_integrity_error(
                "startup_reservation_lookup_page",
                "partial reservation page count overflowed",
            )
        })?;
        self.record_count = self.record_count.checked_add(row_count).ok_or_else(|| {
            startup_scan_integrity_error(
                "startup_reservation_lookup_page",
                "partial reservation row count overflowed",
            )
        })?;
        let mut page_material = String::new();
        for field in [
            "primary_rows_from_start_after".to_owned(),
            snapshot.snapshot_sha256.clone(),
            page.source_revision.to_string(),
            cursor_sha256.to_owned(),
            row_count.to_string(),
            page_records_sha256,
            page.complete.to_string(),
            next_cursor_sha256
                .clone()
                .unwrap_or_else(|| "complete".to_owned()),
        ] {
            append_startup_digest_field(&mut page_material, &field);
        }
        self.chain_sha256 = extend_startup_digest_chain(&self.chain_sha256, &page_material);
        self.expected_cursor_sha256 = next_cursor_sha256;
        Ok(())
    }

    fn restart_after_owner_mutation(&mut self) {
        // The prior opaque cursor belongs to a revision that an owner mutation
        // just changed. A fresh snapshot starts after the last returned key.
        self.expected_cursor_sha256 = None;
    }
}

impl StartupRecoverySourceCoverageBuilder {
    fn new(source: &'static str, source_revision: u64, snapshot_sha256: &str) -> Self {
        let mut seed = String::from("eliot.kernel.startup-recovery-source.v1\n");
        for field in [
            source.to_owned(),
            source_revision.to_string(),
            snapshot_sha256.to_owned(),
        ] {
            append_startup_digest_field(&mut seed, &field);
        }
        Self {
            source,
            source_revision,
            snapshot_sha256: snapshot_sha256.to_owned(),
            page_count: 0,
            record_count: 0,
            start_cursor_sha256: None,
            expected_cursor_sha256: None,
            terminal_cursor_sha256: None,
            chain_sha256: sha256_hex(seed.as_bytes()),
            complete: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_page<C: serde::Serialize, R: serde::Serialize>(
        &mut self,
        snapshot: &RecoveryInventorySnapshot,
        cursor_sha256: String,
        source_revision: u64,
        page_snapshot_sha256: &str,
        records: &[R],
        next_cursor: Option<&C>,
        complete: bool,
        limit: u16,
    ) -> Result<(), ReservationWriteError> {
        if source_revision != snapshot.revision_for(recovery_source(self.source))
            || source_revision != self.source_revision
            || page_snapshot_sha256 != snapshot.snapshot_sha256
            || records.len() > usize::from(limit)
        {
            return Err(startup_scan_integrity_error(
                "startup_recovery_inventory_page",
                format!(
                    "{} page metadata or row count disagrees with its snapshot",
                    self.source
                ),
            ));
        }
        if complete != next_cursor.is_none() {
            return Err(startup_scan_integrity_error(
                "startup_recovery_inventory_cursor",
                format!(
                    "{} page completion disagrees with its continuation",
                    self.source
                ),
            ));
        }
        if let Some(expected) = &self.expected_cursor_sha256
            && expected != &cursor_sha256
        {
            return Err(startup_scan_integrity_error(
                "startup_recovery_inventory_cursor",
                format!(
                    "{} continuation did not match the prior page cursor",
                    self.source
                ),
            ));
        }
        if self.page_count == 0 {
            self.start_cursor_sha256 = Some(cursor_sha256.clone());
        }
        let next_cursor_sha256 = next_cursor
            .map(|cursor| startup_serialized_sha256(cursor, "startup_recovery_inventory_cursor"))
            .transpose()?;
        if let Some(next) = &next_cursor_sha256
            && next == &cursor_sha256
        {
            return Err(startup_scan_integrity_error(
                "startup_recovery_inventory_cursor",
                format!(
                    "{} continuation did not advance its opaque cursor",
                    self.source
                ),
            ));
        }
        let records_sha256 =
            startup_serialized_sha256(&records, "startup_recovery_inventory_records")?;
        let row_count = u64::try_from(records.len()).map_err(|_| {
            startup_scan_integrity_error(
                "startup_recovery_inventory_page",
                format!(
                    "{} page row count exceeds its coverage counter",
                    self.source
                ),
            )
        })?;
        self.page_count = self.page_count.checked_add(1).ok_or_else(|| {
            startup_scan_integrity_error(
                "startup_recovery_inventory_page",
                format!("{} page count overflowed", self.source),
            )
        })?;
        self.record_count = self.record_count.checked_add(row_count).ok_or_else(|| {
            startup_scan_integrity_error(
                "startup_recovery_inventory_page",
                format!("{} record count overflowed", self.source),
            )
        })?;
        let mut page_material = String::new();
        for field in [
            cursor_sha256.clone(),
            row_count.to_string(),
            records_sha256,
            complete.to_string(),
            next_cursor_sha256
                .clone()
                .unwrap_or_else(|| "complete".to_owned()),
        ] {
            append_startup_digest_field(&mut page_material, &field);
        }
        let mut next_chain_material = String::new();
        append_startup_digest_field(&mut next_chain_material, &self.chain_sha256);
        append_startup_digest_field(&mut next_chain_material, &page_material);
        self.chain_sha256 = sha256_hex(next_chain_material.as_bytes());
        self.expected_cursor_sha256 = next_cursor_sha256;
        self.terminal_cursor_sha256 = Some(cursor_sha256);
        self.complete = complete;
        Ok(())
    }

    fn finish(self) -> Result<StartupRecoverySourceCoverage, ReservationWriteError> {
        if self.page_count == 0 || !self.complete || self.expected_cursor_sha256.is_some() {
            return Err(startup_scan_integrity_error(
                "startup_recovery_inventory_coverage",
                format!("{} did not reach explicit exhaustion", self.source),
            ));
        }
        let start_cursor_sha256 = self.start_cursor_sha256.ok_or_else(|| {
            startup_scan_integrity_error(
                "startup_recovery_inventory_coverage",
                format!("{} has no initial cursor", self.source),
            )
        })?;
        let terminal_cursor_sha256 = self.terminal_cursor_sha256.ok_or_else(|| {
            startup_scan_integrity_error(
                "startup_recovery_inventory_coverage",
                format!("{} has no terminal cursor", self.source),
            )
        })?;
        Ok(StartupRecoverySourceCoverage {
            source: self.source,
            source_revision: self.source_revision,
            page_count: self.page_count,
            record_count: self.record_count,
            start_cursor_sha256,
            terminal_cursor_sha256,
            coverage_sha256: self.chain_sha256,
            complete: self.complete,
        })
    }
}

fn recovery_source(source: &'static str) -> RecoveryInventorySource {
    match source {
        "ors.reservations" => RecoveryInventorySource::Reservations,
        "ors.operational_current" => RecoveryInventorySource::OperationalCurrent,
        "ors.recovery_inbox" => RecoveryInventorySource::RecoveryInbox,
        "ors.recovery_problems" => RecoveryInventorySource::RecoveryProblems,
        "ors.write_idempotency" => RecoveryInventorySource::WriteIdempotency,
        _ => unreachable!("source is selected by the fixed startup inventory list"),
    }
}

fn startup_serialized_sha256<T: serde::Serialize>(
    value: &T,
    record_type: &'static str,
) -> Result<String, ReservationWriteError> {
    let encoded = serde_json::to_vec(value).map_err(|error| {
        startup_scan_integrity_error(
            record_type,
            format!("safe inventory data failed encoding: {error}"),
        )
    })?;
    Ok(sha256_hex(&encoded))
}

/// Enumerates every revision-bound ORS source to explicit exhaustion.
///
/// Each request is limited to one owner-defined page. The cursors returned by
/// ORS are passed back verbatim, including empty reservation-index phases.
/// Every page is bound to the same five-source revision snapshot and a final
/// snapshot validation closes the whole inventory before the caller can use it.
fn scan_startup_recovery_inventory(
    ors: &RedbRecoveryStore,
    limit: u16,
) -> Result<StartupRecoveryInventoryScan, ReservationWriteError> {
    let snapshot = ors.begin_recovery_inventory_snapshot()?;
    snapshot.validate()?;
    let mut coverage = Vec::with_capacity(STARTUP_RECOVERY_INVENTORY_SOURCES.len());
    let mut active_reservation_count = 0_u64;
    let mut active_identity_sha256 = sha256_hex(b"eliot.kernel.startup-reservation-identities.v1");
    let mut job_checkpoint_refs = BTreeSet::new();
    let mut job_checkpoint_record_count = 0_u64;
    let mut delivery_cursor_refs = BTreeSet::new();
    let mut delivery_cursor_record_count = 0_u64;
    let mut recovery_inbox_refs = BTreeSet::new();
    let mut recovery_inbox_record_count = 0_u64;
    let mut retained_problem_sample = Vec::new();
    let mut retained_problem_count = 0_u64;
    let mut unresolved_retained_problem_count = 0_u64;

    let mut reservation_cursor = WriteReservationRecoveryCursor::start(snapshot.clone(), limit)?;
    let mut reservation_coverage = StartupRecoverySourceCoverageBuilder::new(
        STARTUP_RECOVERY_INVENTORY_SOURCES[0],
        snapshot.reservation_revision,
        &snapshot.snapshot_sha256,
    );
    loop {
        let cursor_sha256 =
            startup_serialized_sha256(&reservation_cursor, "startup_recovery_inventory_cursor")?;
        let page = ors.scan_write_reservations(reservation_cursor)?;
        if page.coverage != eliot_ors::WriteReservationRecoveryCoverage::FullInventory {
            return Err(startup_scan_integrity_error(
                "startup_recovery_inventory_coverage",
                "full startup scan received a partial reservation suffix page",
            ));
        }
        reservation_coverage.observe_page(
            &snapshot,
            cursor_sha256,
            page.source_revision,
            &page.snapshot_sha256,
            &page.records,
            page.next_cursor.as_ref(),
            page.complete,
            limit,
        )?;
        for record in &page.records {
            if record.state.is_terminal() {
                continue;
            }
            active_reservation_count =
                active_reservation_count.checked_add(1).ok_or_else(|| {
                    startup_scan_integrity_error(
                        "startup_reservation_coverage",
                        "active reservation count overflowed",
                    )
                })?;
            let identity =
                startup_reservation_scan_entry(&record.token, record.state, "unresolved");
            active_identity_sha256 =
                extend_startup_digest_chain(&active_identity_sha256, &identity);
        }
        let complete = page.complete;
        if complete {
            break;
        }
        reservation_cursor = page.next_cursor.ok_or_else(|| {
            startup_scan_integrity_error(
                "startup_recovery_inventory_cursor",
                "reservation page omitted its required continuation",
            )
        })?;
    }
    coverage.push(reservation_coverage.finish()?);

    let mut operational_cursor = OperationalCurrentRecoveryCursor::start(snapshot.clone(), limit)?;
    let mut operational_coverage = StartupRecoverySourceCoverageBuilder::new(
        STARTUP_RECOVERY_INVENTORY_SOURCES[1],
        snapshot.operational_current_revision,
        &snapshot.snapshot_sha256,
    );
    loop {
        let cursor_sha256 =
            startup_serialized_sha256(&operational_cursor, "startup_recovery_inventory_cursor")?;
        let page = ors.scan_operational_current(operational_cursor)?;
        operational_coverage.observe_page(
            &snapshot,
            cursor_sha256,
            page.source_revision,
            &page.snapshot_sha256,
            &page.records,
            page.next_cursor.as_ref(),
            page.complete,
            limit,
        )?;
        for entry in &page.records {
            if entry.kind.as_str() == "job_checkpoint" && entry.phase == OperationalPhase::Active {
                increment_recovery_record_count(
                    &mut job_checkpoint_record_count,
                    "startup_job_checkpoint_coverage",
                )?;
                add_bounded_reference_sample(
                    &mut job_checkpoint_refs,
                    entry.subject_id.as_str(),
                    limit,
                );
            }
            if entry.kind.as_str() == "delivery_cursor" && entry.phase == OperationalPhase::Active {
                increment_recovery_record_count(
                    &mut delivery_cursor_record_count,
                    "startup_delivery_cursor_coverage",
                )?;
                add_bounded_reference_sample(
                    &mut delivery_cursor_refs,
                    entry.subject_id.as_str(),
                    limit,
                );
            }
        }
        let complete = page.complete;
        if complete {
            break;
        }
        operational_cursor = page.next_cursor.ok_or_else(|| {
            startup_scan_integrity_error(
                "startup_recovery_inventory_cursor",
                "operational-current page omitted its required continuation",
            )
        })?;
    }
    coverage.push(operational_coverage.finish()?);

    let mut inbox_cursor = RecoveryInboxRecoveryCursor::start(snapshot.clone(), limit)?;
    let mut inbox_coverage = StartupRecoverySourceCoverageBuilder::new(
        STARTUP_RECOVERY_INVENTORY_SOURCES[2],
        snapshot.recovery_inbox_revision,
        &snapshot.snapshot_sha256,
    );
    loop {
        let cursor_sha256 =
            startup_serialized_sha256(&inbox_cursor, "startup_recovery_inventory_cursor")?;
        let page = ors.scan_recovery_inbox(inbox_cursor)?;
        inbox_coverage.observe_page(
            &snapshot,
            cursor_sha256,
            page.source_revision,
            &page.snapshot_sha256,
            &page.records,
            page.next_cursor.as_ref(),
            page.complete,
            limit,
        )?;
        for entry in &page.records {
            if entry.disposition == RecoveryInboxDisposition::Imported {
                increment_recovery_record_count(
                    &mut recovery_inbox_record_count,
                    "startup_recovery_inbox_coverage",
                )?;
                add_bounded_reference_sample(
                    &mut recovery_inbox_refs,
                    entry.item_id.as_str(),
                    limit,
                );
            }
        }
        let complete = page.complete;
        if complete {
            break;
        }
        inbox_cursor = page.next_cursor.ok_or_else(|| {
            startup_scan_integrity_error(
                "startup_recovery_inventory_cursor",
                "recovery-inbox page omitted its required continuation",
            )
        })?;
    }
    coverage.push(inbox_coverage.finish()?);

    let mut problem_cursor = RecoveryProblemRecoveryCursor::start(snapshot.clone(), limit)?;
    let mut problem_coverage = StartupRecoverySourceCoverageBuilder::new(
        STARTUP_RECOVERY_INVENTORY_SOURCES[3],
        snapshot.recovery_problem_revision,
        &snapshot.snapshot_sha256,
    );
    loop {
        let cursor_sha256 =
            startup_serialized_sha256(&problem_cursor, "startup_recovery_inventory_cursor")?;
        let page = ors.scan_recovery_problems(problem_cursor)?;
        problem_coverage.observe_page(
            &snapshot,
            cursor_sha256,
            page.source_revision,
            &page.snapshot_sha256,
            &page.records,
            page.next_cursor.as_ref(),
            page.complete,
            limit,
        )?;
        for problem in page.records {
            retained_problem_count = retained_problem_count.checked_add(1).ok_or_else(|| {
                startup_scan_integrity_error(
                    "startup_recovery_problem_coverage",
                    "retained problem count overflowed",
                )
            })?;
            if !problem.is_resolved() {
                unresolved_retained_problem_count = unresolved_retained_problem_count
                    .checked_add(1)
                    .ok_or_else(|| {
                        startup_scan_integrity_error(
                            "startup_recovery_problem_coverage",
                            "unresolved retained problem count overflowed",
                        )
                    })?;
            }
            if retained_problem_sample.len() < usize::from(limit) {
                retained_problem_sample.push(problem);
            }
        }
        if page.complete {
            break;
        }
        problem_cursor = page.next_cursor.ok_or_else(|| {
            startup_scan_integrity_error(
                "startup_recovery_inventory_cursor",
                "recovery-problems page omitted its required continuation",
            )
        })?;
    }
    coverage.push(problem_coverage.finish()?);

    let mut idempotency_cursor = WriteIdempotencyRecoveryCursor::start(snapshot.clone(), limit)?;
    let mut idempotency_coverage = StartupRecoverySourceCoverageBuilder::new(
        STARTUP_RECOVERY_INVENTORY_SOURCES[4],
        snapshot.write_idempotency_revision,
        &snapshot.snapshot_sha256,
    );
    loop {
        let cursor_sha256 =
            startup_serialized_sha256(&idempotency_cursor, "startup_recovery_inventory_cursor")?;
        let page = ors.scan_write_idempotency(idempotency_cursor)?;
        idempotency_coverage.observe_page(
            &snapshot,
            cursor_sha256,
            page.source_revision,
            &page.snapshot_sha256,
            &page.records,
            page.next_cursor.as_ref(),
            page.complete,
            limit,
        )?;
        let complete = page.complete;
        if complete {
            break;
        }
        idempotency_cursor = page.next_cursor.ok_or_else(|| {
            startup_scan_integrity_error(
                "startup_recovery_inventory_cursor",
                "write-idempotency page omitted its required continuation",
            )
        })?;
    }
    coverage.push(idempotency_coverage.finish()?);

    ors.validate_recovery_inventory_snapshot(&snapshot)?;
    Ok(StartupRecoveryInventoryScan {
        coverage: StartupRecoveryInventoryCoverage {
            snapshot_sha256: snapshot.snapshot_sha256,
            sources: coverage,
            snapshot_revalidated: true,
        },
        active_reservation_count,
        active_identity_sha256,
        job_checkpoint_record_count,
        job_checkpoint_ref_sample: job_checkpoint_refs.into_iter().collect(),
        delivery_cursor_record_count,
        delivery_cursor_ref_sample: delivery_cursor_refs.into_iter().collect(),
        recovery_inbox_record_count,
        recovery_inbox_ref_sample: recovery_inbox_refs.into_iter().collect(),
        retained_problem_sample,
        retained_problem_count,
        unresolved_retained_problem_count,
    })
}

/// Reconciles persisted nonterminal ORS reservations against exact canonical
/// Store receipts at startup. Before any receipt-driven ORS mutation, it pages
/// and revalidates all five revision-bound inventory sources. Operational
/// checkpoint/delivery references and imported inbox identities are derived
/// from their durable owner records, not a new empty projection ledger.
///
/// For every non-terminal reservation in the fully enumerated source, this
/// observes the exact Store receipt by operation identity through the
/// named authenticated gateway ([`StartupReceiptRoute`]): a committed
/// (or terminally not-applied, receipt-proven) answer reconciles and
/// finalizes through the real receipt path, so resolved work leaves no
/// trace in the report. Records minted under a different writer epoch
/// than the bound owner are reported pending with `fence mismatch` and
/// never touched — cross-epoch disposition belongs to the
/// cutover/rebind owner, not to startup. A missing receipt, a refused
/// reconciliation, or a gateway/ORS failure of the check itself is
/// reported honestly: unknown outcomes stay unresolved, and a failed
/// check is an error, never a synthetic empty report.
///
/// `limit` is the per-page row bound. An exhaustive five-source preflight runs
/// before receipt effects; a separate primary-row suffix lookup then resumes
/// after each page whose active rows may have changed ORS. The suffix trace is
/// diagnostic only. A second exhaustive five-source scan from the beginning
/// validates final readiness, including both reservation index phases. No
/// whole-store ceiling is inferred from a short page. ORS corruption, source
/// movement, a malformed or missing continuation, or failed final revision
/// validation returns an error and cannot be interpreted as zero rows.
pub async fn reconcile_pending_at_startup(
    owner: &CompositionReservation,
    fence: &StateFence,
    route: &dyn StartupReceiptRoute,
    limit: u16,
) -> Result<StartupReconciliation, ReservationWriteError> {
    reconcile_pending_at_startup_inner(owner, fence, route, limit, None).await
}

/// Streaming accumulator for the staged-envelope evidence emitted while the
/// reservation reconciliation walks one active record at a time.
#[derive(Default)]
struct StartupStagedProjection {
    envelopes: Vec<StartupStagedEnvelope>,
    envelope_count: u64,
    problems: Vec<StartupEnvelopeProblem>,
    problem_count: u64,
}

async fn reconcile_pending_at_startup_inner(
    owner: &CompositionReservation,
    fence: &StateFence,
    route: &dyn StartupReceiptRoute,
    limit: u16,
    mut staged_projection: Option<&mut StartupStagedProjection>,
) -> Result<StartupReconciliation, ReservationWriteError> {
    // Establish an exhaustive, revision-stable preflight before any receipt
    // lookup can mutate ORS. The mutable reservation lookup below is a
    // separate primary-row suffix traversal; it cannot mint this coverage.
    let preflight_inventory_coverage = {
        let preflight_inventory = scan_startup_recovery_inventory(&owner.ors, limit)?;
        preflight_inventory.coverage
    };

    let mut pending = Vec::new();
    let mut pending_count = 0_u64;
    let mut unknown = Vec::new();
    let mut unknown_count = 0_u64;
    let mut after_reservation_id: Option<String> = None;
    let mut scanned = 0_u64;
    let mut outcome_chain = sha256_hex(b"eliot.kernel.startup-reservation-outcomes.v1");
    let mut unresolved_identity_sha256 =
        sha256_hex(b"eliot.kernel.startup-reservation-identities.v1");
    let mut lookup = StartupReservationLookupTrace::new();
    let mut after_page_snapshot: Option<RecoveryInventorySnapshot> = None;
    let mut reservation_cursor: Option<WriteReservationRecoveryCursor> = None;
    let mut reservation_lookup_suffix_exhausted = false;

    loop {
        if reservation_cursor.is_none() {
            let snapshot = owner.ors.begin_recovery_inventory_snapshot()?;
            snapshot.validate()?;
            reservation_cursor = Some(WriteReservationRecoveryCursor::start_after(
                snapshot.clone(),
                after_reservation_id.as_deref(),
                limit,
            )?);
            after_page_snapshot = Some(snapshot);
        }
        let cursor = reservation_cursor.take().ok_or_else(|| {
            startup_scan_integrity_error(
                "startup_reservation_lookup_cursor",
                "partial reservation lookup omitted its cursor",
            )
        })?;
        let snapshot = after_page_snapshot.as_ref().ok_or_else(|| {
            startup_scan_integrity_error(
                "startup_reservation_lookup_snapshot",
                "partial reservation lookup omitted its snapshot",
            )
        })?;
        let cursor_sha256 =
            startup_serialized_sha256(&cursor, "startup_reservation_lookup_cursor")?;
        let page = owner.ors.scan_write_reservations(cursor)?;
        lookup.observe_page(snapshot, &cursor_sha256, &page, limit)?;
        let page_has_active_rows = page
            .records
            .iter()
            .any(|record| !record.state.is_terminal());
        let page_last_reservation_id = page
            .records
            .last()
            .map(|record| record.token.reservation_id.as_str().to_owned());

        for record in &page.records {
            if record.state.is_terminal() {
                continue;
            }
            let token = &record.token;
            let operation_id = token.operation_id.as_str().to_owned();
            let reservation_id = token.reservation_id.as_str().to_owned();
            let mut scopes: Vec<String> = token
                .scopes
                .iter()
                .map(|scope| scope.scope.as_str().to_owned())
                .collect();
            scopes.sort_unstable();
            let recovery_owner = token.recovery_owner.as_str().to_owned();
            let entry = reconcile_one_record(owner, route, record).await?;
            let outcome_for_digest = match &entry {
                StartupRecordOutcome::Resolved => "resolved".to_owned(),
                StartupRecordOutcome::Pending { reason } => format!("pending:{reason}"),
                StartupRecordOutcome::Unknown { reason } => format!("unknown:{reason}"),
            };
            let mut outcome_entry = String::new();
            append_startup_digest_field(&mut outcome_entry, &snapshot.snapshot_sha256);
            append_startup_digest_field(
                &mut outcome_entry,
                &startup_reservation_scan_entry(token, record.state, &outcome_for_digest),
            );
            outcome_chain = extend_startup_digest_chain(&outcome_chain, &outcome_entry);
            scanned = scanned.checked_add(1).ok_or_else(|| {
                startup_scan_integrity_error(
                    "startup_reservation_coverage",
                    "reconciled reservation count overflowed",
                )
            })?;
            match entry {
                StartupRecordOutcome::Resolved => {}
                StartupRecordOutcome::Pending { reason } => {
                    pending_count = pending_count.checked_add(1).ok_or_else(|| {
                        startup_scan_integrity_error(
                            "startup_reservation_coverage",
                            "pending reservation count overflowed",
                        )
                    })?;
                    let identity =
                        startup_reservation_scan_entry(token, record.state, "unresolved");
                    unresolved_identity_sha256 =
                        extend_startup_digest_chain(&unresolved_identity_sha256, &identity);
                    if let Some(projection) = staged_projection.as_deref_mut() {
                        record_staged_obligation(
                            owner,
                            projection,
                            &operation_id,
                            &reservation_id,
                            token.reservation_order,
                            record.state,
                            limit,
                        )?;
                    }
                    if pending.len() < usize::from(limit) {
                        pending.push(StartupPendingOperation {
                            operation_id,
                            reservation_id: token.reservation_id.as_str().to_owned(),
                            reservation_order: token.reservation_order,
                            scopes,
                            state: record.state,
                            recovery_owner,
                            reason,
                        });
                    }
                }
                StartupRecordOutcome::Unknown { reason } => {
                    unknown_count = unknown_count.checked_add(1).ok_or_else(|| {
                        startup_scan_integrity_error(
                            "startup_reservation_coverage",
                            "unknown reservation count overflowed",
                        )
                    })?;
                    let identity =
                        startup_reservation_scan_entry(token, record.state, "unresolved");
                    unresolved_identity_sha256 =
                        extend_startup_digest_chain(&unresolved_identity_sha256, &identity);
                    if let Some(projection) = staged_projection.as_deref_mut() {
                        record_staged_obligation(
                            owner,
                            projection,
                            &operation_id,
                            &reservation_id,
                            token.reservation_order,
                            record.state,
                            limit,
                        )?;
                    }
                    if unknown.len() < usize::from(limit) {
                        unknown.push(StartupUnknownOperation {
                            operation_id,
                            reservation_id: token.reservation_id.as_str().to_owned(),
                            reservation_order: token.reservation_order,
                            scopes,
                            state: record.state,
                            recovery_owner,
                            reason,
                        });
                    }
                }
            }
        }

        if page.complete {
            reservation_lookup_suffix_exhausted = true;
            break;
        }
        if page_has_active_rows {
            after_reservation_id = page_last_reservation_id;
            if after_reservation_id.is_none() {
                return Err(startup_scan_integrity_error(
                    "startup_reservation_lookup_cursor",
                    "active page has no final primary reservation key",
                ));
            }
            lookup.restart_after_owner_mutation();
            after_page_snapshot = None;
        } else {
            reservation_cursor = page.next_cursor;
            if reservation_cursor.is_none() {
                return Err(startup_scan_integrity_error(
                    "startup_reservation_lookup_cursor",
                    "incomplete partial reservation page omitted its continuation",
                ));
            }
        }
    }

    // This second exhaustive scan is the only post-reconciliation inventory
    // used for readiness. Its from-start cursor covers the whole reservation
    // table and both indexes independently of the partial lookup trace.
    let final_inventory = scan_startup_recovery_inventory(&owner.ors, limit)?;
    let reported_unresolved = pending_count.checked_add(unknown_count).ok_or_else(|| {
        startup_scan_integrity_error(
            "startup_reservation_coverage",
            "reported unresolved reservation count exceeds its coverage counter",
        )
    })?;
    let unresolved_count_delta = final_inventory
        .active_reservation_count
        .abs_diff(reported_unresolved);
    let unresolved_identity_match = unresolved_count_delta == 0
        && unresolved_identity_sha256 == final_inventory.active_identity_sha256;
    let mut digest_input = String::new();
    for field in [
        "ors.startup_recovery_inventory.v1".to_owned(),
        fence.authority_epoch.lineage_id.as_str().to_owned(),
        fence.authority_epoch.sequence.get().to_string(),
        fence.resource_generation.value().to_string(),
        scanned.to_string(),
        limit.to_string(),
        outcome_chain,
        lookup.page_count.to_string(),
        lookup.record_count.to_string(),
        lookup.chain_sha256.clone(),
        reservation_lookup_suffix_exhausted.to_string(),
        final_inventory.active_reservation_count.to_string(),
        pending_count.to_string(),
        unknown_count.to_string(),
        unresolved_count_delta.to_string(),
        unresolved_identity_match.to_string(),
    ] {
        append_startup_digest_field(&mut digest_input, &field);
    }
    append_startup_digest_field(
        &mut digest_input,
        &startup_serialized_sha256(
            &preflight_inventory_coverage,
            "startup_recovery_preflight_coverage",
        )?,
    );
    append_startup_digest_field(
        &mut digest_input,
        &startup_serialized_sha256(
            &final_inventory.coverage,
            "startup_recovery_inventory_coverage",
        )?,
    );
    for (count, refs) in [
        (
            final_inventory.job_checkpoint_record_count,
            &final_inventory.job_checkpoint_ref_sample,
        ),
        (
            final_inventory.delivery_cursor_record_count,
            &final_inventory.delivery_cursor_ref_sample,
        ),
        (
            final_inventory.recovery_inbox_record_count,
            &final_inventory.recovery_inbox_ref_sample,
        ),
    ] {
        append_startup_digest_field(&mut digest_input, &count.to_string());
        append_startup_digest_field(&mut digest_input, &refs.len().to_string());
        for reference in refs {
            append_startup_digest_field(&mut digest_input, reference);
        }
    }
    let digest = sha256_hex(digest_input.as_bytes());
    Ok(StartupReconciliation {
        fence: fence.clone(),
        digest,
        inventory_coverage: final_inventory.coverage,
        scanned,
        preflight_inventory_coverage,
        reservation_lookup_page_count: lookup.page_count,
        reservation_lookup_record_count: lookup.record_count,
        reservation_lookup_digest: lookup.chain_sha256,
        reservation_lookup_suffix_exhausted,
        unresolved_count_delta,
        unresolved_identity_match,
        job_checkpoint_record_count: final_inventory.job_checkpoint_record_count,
        job_checkpoint_ref_sample: final_inventory.job_checkpoint_ref_sample,
        delivery_cursor_record_count: final_inventory.delivery_cursor_record_count,
        delivery_cursor_ref_sample: final_inventory.delivery_cursor_ref_sample,
        recovery_inbox_record_count: final_inventory.recovery_inbox_record_count,
        recovery_inbox_ref_sample: final_inventory.recovery_inbox_ref_sample,
        page_size: limit,
        pending,
        pending_count,
        unknown,
        unknown_count,
        active_reservation_count: final_inventory.active_reservation_count,
        retained_problem_sample: final_inventory.retained_problem_sample,
        retained_problem_count: final_inventory.retained_problem_count,
        unresolved_retained_problem_count: final_inventory.unresolved_retained_problem_count,
    })
}

/// Fixed payload-shape label for one owner-validated staged envelope.
///
/// The `Encrypted` and `ImmutableLocator` labels are restated from the shape ORS
/// itself holds; `canonical-request` is unreachable for a reservation envelope
/// (I5.2 admits only the key/ciphertext or immutable-locator form there) and is
/// named only so this projection stays total instead of silently reclassifying
/// an unexpected shape.
fn staged_payload_kind(payload: &eliot_ors::RecoveryPayload) -> &'static str {
    match payload {
        eliot_ors::RecoveryPayload::Encrypted { .. } => "encrypted",
        eliot_ors::RecoveryPayload::ImmutableLocator { .. } => "immutable-locator",
        eliot_ors::RecoveryPayload::CanonicalRequest { .. } => "canonical-request",
    }
}

/// One staged `RecoveryPayloadEnvelope` enumerated by the startup recovery scan
/// (issue #1925, I5.2/I5.6).
///
/// A reference to owner-validated evidence, never a payload: the staged bytes
/// stay inside ORS and are not read, copied, decoded, or returned here. The
/// reported `payload_sha256`/`payload_length` are the envelope's OWN recorded
/// bindings, restated only after the owner decoded the envelope, compared its
/// identity against the requested operation, and ran
/// `RecoveryPayloadEnvelope::validate` over the recorded payload and recorded
/// digest. Nothing is re-hashed here, so this projection can never replace the
/// recorded integrity proof with a fresh checksum of what the reader holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupStagedEnvelope {
    /// Operation identity the envelope was enumerated and validated under.
    pub operation_id: String,
    /// ORS-assigned reservation order of the owning reservation.
    pub reservation_order: u64,
    /// Lifecycle state the reconciliation scan observed for that reservation.
    pub state: ReservationState,
    /// Envelope contract version the owner validated.
    pub contract_version: u16,
    /// Fixed payload-shape label (`encrypted` or `immutable-locator`).
    pub payload_kind: &'static str,
    /// Owner-recorded integrity digest of the staged payload.
    pub payload_sha256: String,
    /// Owner-recorded length of the staged payload.
    pub payload_length: u64,
    /// Authority-epoch lineage the envelope is bound to.
    pub authority_epoch_lineage: String,
    /// Authority-epoch sequence the envelope is bound to.
    pub authority_epoch_sequence: u64,
    /// State-fence digest the envelope is bound to.
    pub state_fence_sha256: String,
}

/// Typed cause retained when an unresolved staged envelope cannot be verified.
#[derive(Debug)]
pub enum StartupEnvelopeProblemCause {
    /// ORS retained a durable Recovery Problem for this operation.
    RecoveryProblemRetained { reported_operation_id: String },
    /// ORS could not persist the Recovery Problem. Both the original read
    /// failure and the recorder failure remain typed and available to callers.
    RecoveryProblemRecordFailed {
        reported_operation_id: eliot_ors::OperationIdentity,
        reported_reservation_id: eliot_ors::OperationIdentity,
        original: Box<eliot_ors::OrsError>,
        recorder: Box<eliot_ors::OrsError>,
    },
}

/// One staged operation whose envelope could not be validated at startup.
///
/// The outer identity binds the problem to the reservation being inspected;
/// `cause` retains the exact ORS cause without converting it into a generic
/// error code or claiming a Recovery Problem exists when its write failed.
#[derive(Debug)]
pub struct StartupEnvelopeProblem {
    /// Operation identity whose staged envelope failed validation.
    pub operation_id: String,
    /// ORS reservation identity that owns the operation.
    pub reservation_id: String,
    /// ORS-assigned reservation order of the owning reservation.
    pub reservation_order: u64,
    /// Exact owner result for this failed validation.
    pub cause: StartupEnvelopeProblemCause,
}

fn record_staged_obligation(
    owner: &CompositionReservation,
    projection: &mut StartupStagedProjection,
    operation_id: &str,
    reservation_id: &str,
    reservation_order: u64,
    state: ReservationState,
    sample_limit: u16,
) -> Result<(), ReservationWriteError> {
    let identity = OrsOperationIdentity::new(operation_id).map_err(ReservationWriteError::Ors)?;
    match owner.ors.verify_staged_envelope(&identity) {
        Ok(envelope) => {
            increment_recovery_record_count(
                &mut projection.envelope_count,
                "startup_staged_envelope_coverage",
            )?;
            if projection.envelopes.len() < usize::from(sample_limit) {
                projection.envelopes.push(StartupStagedEnvelope {
                    operation_id: operation_id.to_owned(),
                    reservation_order,
                    state,
                    contract_version: envelope.contract_version,
                    payload_kind: staged_payload_kind(&envelope.payload),
                    payload_sha256: envelope.payload_sha256,
                    payload_length: envelope.payload_length,
                    authority_epoch_lineage: envelope
                        .authority_epoch
                        .current
                        .lineage_id
                        .as_str()
                        .to_owned(),
                    authority_epoch_sequence: envelope.authority_epoch.current.epoch,
                    state_fence_sha256: envelope.state_fence.sha256,
                });
            }
        }
        Err(eliot_ors::OrsError::RecoveryProblemRetained {
            operation_id: reported,
        }) => {
            increment_recovery_record_count(
                &mut projection.problem_count,
                "startup_staged_envelope_problem_coverage",
            )?;
            if projection.problems.len() < usize::from(sample_limit) {
                projection.problems.push(StartupEnvelopeProblem {
                    operation_id: operation_id.to_owned(),
                    reservation_id: reservation_id.to_owned(),
                    reservation_order,
                    cause: StartupEnvelopeProblemCause::RecoveryProblemRetained {
                        reported_operation_id: reported,
                    },
                });
            }
        }
        Err(eliot_ors::OrsError::RecoveryProblemRecordFailed {
            operation_id: reported_operation_id,
            reservation_id: reported_reservation_id,
            original,
            recorder,
        }) => {
            increment_recovery_record_count(
                &mut projection.problem_count,
                "startup_staged_envelope_problem_coverage",
            )?;
            if projection.problems.len() < usize::from(sample_limit) {
                projection.problems.push(StartupEnvelopeProblem {
                    operation_id: operation_id.to_owned(),
                    reservation_id: reservation_id.to_owned(),
                    reservation_order,
                    cause: StartupEnvelopeProblemCause::RecoveryProblemRecordFailed {
                        reported_operation_id,
                        reported_reservation_id,
                        original,
                        recorder,
                    },
                });
            }
        }
        Err(error) => return Err(ReservationWriteError::Ors(error)),
    }
    Ok(())
}

/// Bounded startup verdict over the staged write envelopes (I1.11 step 6,
/// I5.2/I5.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StagedWriteReadiness {
    /// Every enumerated staged envelope validated by hash, every reservation
    /// reached its canonical receipt, and no Recovery Problem is retained.
    Ready,
    /// A reservation/control obligation is unresolved, a staged envelope
    /// failed validation, a Recovery Problem is unresolved, or the bounded
    /// scan did not reach exhaustion. Normal writes stay gated until exact
    /// reconciliation or an explicit disposition.
    Blocked,
}

/// Bounded startup recovery report over the durable staged write envelopes
/// (issue #1925, I5.2/I5.6).
///
/// This is the read side of the same envelope the reserved write route stages:
/// every operation the scan left unresolved is re-enumerated by identity, its
/// envelope is revalidated by the owner, and its outcome is either a canonical
/// receipt (closed inside [`reconcile_pending_at_startup`]) or a visible
/// Recovery Problem. It adds no payload decoding, no second state owner, and no
/// expiry: a retained problem and an unresolved reservation both stay exactly
/// as ORS holds them.
#[derive(Debug)]
pub struct StagedWriteRecovery {
    /// Reservation-level reconciliation, including its exact scan digest.
    pub reservations: StartupReconciliation,
    /// Final full-source snapshot after receipt reconciliation and envelope
    /// verification have completed.
    pub inventory_coverage: StartupRecoveryInventoryCoverage,
    /// Bounded sample of staged envelopes the scan enumerated and the owner
    /// validated by hash.
    pub envelopes: Vec<StartupStagedEnvelope>,
    /// Exact number of staged envelopes the owner validated.
    pub envelope_count: u64,
    /// Bounded sample of operations whose staged envelope failed validation.
    pub problems: Vec<StartupEnvelopeProblem>,
    /// Exact number of staged envelope validation problems.
    pub problem_count: u64,
    /// Bounded sample of durable Recovery Problems in operation-identity
    /// order. The full source count and coverage digest remain in the final
    /// inventory proof.
    pub retained_problems: Vec<eliot_ors::RecoveryProblem>,
    /// Total Recovery Problem rows exhaustively enumerated from ORS.
    pub retained_problem_count: u64,
    /// Unresolved Recovery Problem rows across the full source.
    pub unresolved_retained_problem_count: u64,
}

impl StagedWriteRecovery {
    /// Returns the step-6 verdict for the staged envelopes and their
    /// reservations.
    ///
    /// Any source that lacks explicit exhaustion or a final stable-revision
    /// check is `Blocked`; a partial read cannot certify that unknown rows are
    /// absent. An unresolved reservation, failed envelope, or unresolved
    /// retained problem also keeps the verdict `Blocked` (issue #1713, item 5).
    #[must_use]
    pub fn readiness(&self) -> StagedWriteReadiness {
        if self.inventory_coverage.is_complete()
            && self.reservations.readiness() == StartupReconciliationReadiness::Ready
            && self.problem_count == 0
            && self.unresolved_retained_problem_count == 0
        {
            StagedWriteReadiness::Ready
        } else {
            StagedWriteReadiness::Blocked
        }
    }
}

/// Enumerates and reconciles the durable staged write envelopes at startup
/// (issue #1925, I1.11 step 6, I5.2/I5.6).
///
/// An exhaustive preflight and final revision-bound inventory, the partial
/// reservation lookup trace, and the exact Store receipt route:
///
/// ```text
/// preflight inventory                -> five source pages share a frozen
///                                      revision and are fully revalidated;
/// partial reservation lookup         -> bounded primary-key pages resume after
///                                      pages whose active rows may mutate ORS;
/// receipt reconciliation             -> each active reservation is observed
///                                      by exact identity and receipt evidence;
/// verify_staged_envelope              -> each unresolved envelope is owner
///                                      validated, with failures retained;
/// final inventory                    -> fresh full-from-start five-source
///                                      coverage proves post-reconciliation state.
/// ```
///
/// A failed check is an error, never a synthetic empty report: an unreadable
/// ORS, an envelope whose Recovery Problem could not be retained at all, or a
/// failure of the named gateway receipt lookup all propagate, so the caller
/// keeps step 6 incomplete rather than claiming a clean scan. The one
/// exception is a staged operation whose durable Recovery Problem the owner
/// already holds: that is reported as a visible problem, and a failure to
/// retain that problem is reported as `recovery-problem-not-retained` rather
/// than as an absent or clean operation.
///
/// `limit` is the bounded page size, not a whole-store row ceiling. Every
/// source continues through its opaque cursor until ORS declares completion;
/// a source that moves, corrupts, omits a continuation, or fails final snapshot
/// validation returns an error and cannot lower the denominator. Nothing here
/// interprets a payload, resolves a key, or deletes a staged record.
pub async fn reconcile_staged_writes_at_startup(
    owner: &CompositionReservation,
    fence: &StateFence,
    route: &dyn StartupReceiptRoute,
    limit: u16,
) -> Result<StagedWriteRecovery, ReservationWriteError> {
    let mut projection = StartupStagedProjection::default();
    let reservations =
        reconcile_pending_at_startup_inner(owner, fence, route, limit, Some(&mut projection))
            .await?;
    let inventory_coverage = reservations.inventory_coverage.clone();
    let retained_problems = reservations.retained_problem_sample.clone();
    let retained_problem_count = reservations.retained_problem_count;
    let unresolved_retained_problem_count = reservations.unresolved_retained_problem_count;
    Ok(StagedWriteRecovery {
        reservations,
        inventory_coverage,
        envelopes: projection.envelopes,
        envelope_count: projection.envelope_count,
        problems: projection.problems,
        problem_count: projection.problem_count,
        retained_problems,
        retained_problem_count,
        unresolved_retained_problem_count,
    })
}
