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
//! ORS is handed every staged payload as `RecoveryPayload::Encrypted { key,
//! ciphertext }`, and `I5.2` states the obligation plainly: "The installation
//! secret provider owns the key reference. `expires_at` is a cleanup horizon
//! only after a terminal reconciliation/disposition; unresolved operations,
//! unknown external effects and active checkpoints cannot expire
//! automatically. Decryption failure, missing key or hash mismatch creates a
//! Recovery Problem; plaintext fallback and silent deletion are forbidden."
//! The envelope variant is therefore a claim, and the bytes under it must
//! really be protected. This module does not weaken that claim:
//!
//! ```text
//! plaintext transition bytes  -> refused before any ORS mutation
//! caller-supplied seed bytes  -> the caller's claim; ORS re-binds its own
//!                                digest/length and the Kernel adds no second
//!                                encoding, cipher, or key
//! ```
//!
//! The check is exact and keyless because it needs to be: the admitted
//! transition's canonical JSON bytes and its protected encoding cannot
//! coincide, so a payload that is byte-identical to the canonical bytes is a
//! *provable* false `Encrypted` label, not a heuristic guess. Such a seed is
//! refused in [`reserve_for_transition`] before `stage_and_reserve`, so any
//! envelope, index entry, and recovery reference already retained for that
//! reservation stay exactly as they are: nothing is deleted, downgraded to the
//! root-transition-only `RecoveryPayload::CanonicalRequest` variant, or
//! rewritten as plaintext, and the refusal names no payload byte.
//!
//! The bytes are sealed by the installation secret owner `I15.4` names for the
//! first Windows line: `WindowsPlatform::protect_secret` in
//! `eliot_platform_windows` is the DPAPI user-scope protection primitive, and
//! that crate is already a production dependency of this one. [`gateway_seed`]
//! asks that owner for protected bytes and hands ORS the reference it sealed
//! against; this module adds no second encoding, no cipher, and no key
//! material.
//!
//! Reversing the seal is not done here, and this module does not claim
//! otherwise: no caller in this workspace unprotects a staged envelope. The
//! read side ([`reconcile_staged_writes_at_startup`]) revalidates each envelope
//! through `RedbRecoveryStore::verify_staged_envelope`, which compares the
//! envelope's ORIGINAL recorded digest against its ORIGINAL recorded payload and
//! never decodes it, so the `MissingKey` / `DecryptionFailure` arms of
//! `RedbRecoveryStore::report_recovery_problem` have no producer on this route.
//! What I5.2 forbids is still preserved here: nothing in this module reads a
//! staged envelope as plaintext, recomputes a digest in place of checking the
//! recorded one, or deletes a staged record.
//!
//! ## Startup recovery over the same envelopes
//!
//! [`reconcile_staged_writes_at_startup`] is the read side of the envelope
//! [`reserve_for_transition`] stages, and it is the I1.11 step 6 owner for it:
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
    AcceptedPending, CanonicalDisposition, CanonicalReconciliation, CanonicalScopeObservation,
    EpochIdentity, EpochLineage, ExpectedOrderingHead, OpaqueLabel,
    OperationIdentity as OrsOperationIdentity, OperationalRecoveryStore, RecoveryAccessClass,
    RecoveryCursor, RecoveryEnvelopeContext, RecoveryOwner, RecoveryPage, RecoveryPayload,
    RecoveryPayloadEnvelope, RecoveryWriteBinding, RedbRecoveryStore, ReservationRecord,
    ReservationRequest, ReservationState, ScopeReservationRequest, StateFenceSnapshot,
    WriterReservationToken,
};
use eliot_platform::SecretReference;
use eliot_receipts::ReceiptDispositionKind;
use eliot_store_api::{
    CAPABILITY_RESERVED_WRITE, CanonicalRequestView, NamedMutationOperation, OperationId,
    OrderingHeadExpectation, OrderingScopeId, OriginalWriteSubmission, PreparedTransition,
    ReceiptEnvelope, ReservedScopeBinding, ReservedWriteRequest, RevisionHeadExpectation,
    WriteAdmissionParams, WriteAdmissionProjection, WriteReceipt, WriteReceiptStatus,
    WriterEpochBinding, prepared_transition_digest, sha256_hex, verify_canonical_request_hash,
};

use crate::canonical_store_evidence::CanonicalStoreEvidence;

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
/// Owner-only visibility label retained for the established reservation test
/// fixture. Production callers provide the complete admitted class through
/// [`ReservationSeed::recovery_access_class`].
pub const RESERVATION_VISIBILITY: &str = "owner-only";
/// Reason label recorded when a send resolves to a still-unknown outcome.
pub const UNKNOWN_OUTCOME_REASON: &str = "store-unknown-outcome";

const STARTUP_RESERVATION_SCAN_SOURCE: &str = "ors.pending_reservations";
const STARTUP_CONTROL_SCAN_SOURCE: &str = "ors.control_projection";

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
/// The evidence provider must be the same instance bound inside the ORS handle;
/// the writer epoch must be the composition-active one or every lifecycle
/// call fails with the owner error.
pub struct CompositionReservation {
    ors: Arc<RedbRecoveryStore>,
    writer_epoch: EpochLineage,
    evidence: Option<Arc<CanonicalStoreEvidence>>,
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
        Ok(Self {
            ors,
            writer_epoch,
            evidence: None,
        })
    }

    /// Binds the composition ORS handle, current writer epoch, and the same
    /// canonical Store evidence provider installed in that ORS handle.
    ///
    /// Production reservation and recovery routes use this constructor so an
    /// actual authenticated Store observation can be scoped around each local
    /// ORS transaction. The legacy constructor remains evidence-unbound and
    /// fails closed when the ORS provider requires owner evidence.
    pub fn bind_with_evidence(
        ors: Arc<RedbRecoveryStore>,
        writer_epoch: EpochLineage,
        evidence: Arc<CanonicalStoreEvidence>,
    ) -> Result<Self, ReservationWriteError> {
        let mut owner = Self::bind(ors, writer_epoch)?;
        owner.evidence = Some(evidence);
        Ok(owner)
    }

    /// Returns the bound active writer epoch.
    pub fn writer_epoch(&self) -> &EpochLineage {
        &self.writer_epoch
    }

    /// Revalidates and returns the exact staged envelope for one operation.
    ///
    /// This is an identity-keyed read only. The ORS owner checks its recorded
    /// digest and all envelope bindings before returning the original payload;
    /// this layer never interprets or decrypts those bytes.
    pub fn verify_staged_envelope(
        &self,
        operation_id: &OrsOperationIdentity,
    ) -> Result<RecoveryPayloadEnvelope, ReservationWriteError> {
        self.ors
            .verify_staged_envelope(operation_id)
            .map_err(ReservationWriteError::Ors)
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
    /// Exact privacy, visibility, and instruction-taint verdict admitted by
    /// the owner for this pending payload. Reservation preserves it unchanged.
    pub recovery_access_class: RecoveryAccessClass,
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
        self.recovery_access_class
            .validate()
            .map_err(ReservationWriteError::Ors)?;
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

/// Checks the bound writer epoch against the exact live fence tuple.
///
/// Same-authority rule (Implements #64): the epoch sequence must equal the
/// fence authority sequence and the lineage label must equal the fence
/// lineage. Equal sequences across lineages stay unrelated and fail closed.
fn check_epoch_against_fence(
    writer_epoch: &EpochLineage,
    context: &RequestMetadata,
    operation_id: &str,
) -> Result<u64, ReservationWriteError> {
    let fence_epoch = &context.state_fence.authority_epoch;
    let observed = fence_epoch.sequence.get();
    if writer_epoch.current.epoch != observed
        || writer_epoch.current.lineage_id.as_str() != fence_epoch.lineage_id.as_str()
    {
        return Err(ReservationWriteError::Binding {
            operation_id: operation_id.to_owned(),
            detail: "bound writer epoch is outside the admitted fence authority".to_owned(),
        });
    }
    Ok(observed)
}

/// Refuses a seed whose `Encrypted` payload is the admitted transition's own
/// plaintext canonical bytes.
///
/// ORS is told these bytes are ciphertext under an installation-owned key
/// reference, so byte identity with the canonical transition JSON is a
/// provable false label rather than a guess: no protected encoding of the same
/// bytes can equal them. `I5.2` forbids exactly this ("plaintext fallback and
/// silent deletion are forbidden"), so the refusal happens here, before any
/// ORS mutation — an envelope, index entry, and recovery reference already
/// retained for the reservation stay untouched, and the refusal carries the
/// operation identity plus a fixed sentence, never a payload byte.
///
/// The complement of this check (proving the bytes really are the installation
/// owner's protected encoding) needs the key and therefore the installation
/// secret owner, which this composition does not carry; see the module
/// "Staged payload protection" section.
fn refuse_plaintext_payload(
    seed: &ReservationSeed,
    transition: &PreparedTransition,
    operation_id: &str,
) -> Result<(), ReservationWriteError> {
    let plaintext = eliot_contracts::canonical_json_bytes(transition).map_err(|error| {
        ReservationWriteError::Admission {
            operation_id: operation_id.to_owned(),
            detail: format!("admitted transition canonical bytes do not encode: {error}"),
        }
    })?;
    if seed.payload_bytes == plaintext {
        return Err(ReservationWriteError::Admission {
            operation_id: operation_id.to_owned(),
            detail:
                "reservation seed payload is the admitted transition's plaintext canonical bytes; \
                 a payload staged as encrypted must carry installation-secret-owner protected \
                 bytes and the envelope is retained untouched"
                    .to_owned(),
        });
    }
    Ok(())
}

/// Atomically reserves every admitted scope through the actual ORS operation,
/// or none.
///
/// The single `stage_and_reserve` write transaction assigns one monotonic
/// `reservation_order` across all scopes; a failure anywhere (duplicate scope,
/// head mismatch, stale epoch, unbound evidence) reserves nothing. The exact
/// replay of an existing reservation id returns the durable token unchanged;
/// changed content under the same id is rejected later at projection time, not
/// silently rebound here.
///
/// The staged payload must be the installation secret owner's protected bytes:
/// [`refuse_plaintext_payload`] rejects the admitted transition's plaintext
/// before anything is staged, so `accepted_pending` is never backed by a
/// payload ORS was told was encrypted and was not.
///
/// The exact owner-admitted privacy, visibility, and instruction-taint class
/// travels with the payload. This reservation layer neither derives nor changes
/// those values from the prepared transition.
pub fn reserve_for_transition(
    owner: &CompositionReservation,
    seed: &ReservationSeed,
    context: &RequestMetadata,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<SealedReservation, ReservationWriteError> {
    reserve_for_transition_inner(
        owner,
        seed,
        context,
        transition,
        (expected_revision_heads, expected_ordering_heads),
        None,
        false,
    )
    .map(|(sealed, _)| sealed)
}

/// Reserves a `CaptureObservation` transition while binding the exact original
/// public Observe submission that produced it. Other transition kinds cannot
/// claim this capture identity, and `CaptureObservation` cannot enter ORS through
/// the source-less wrapper above.
pub fn reserve_for_transition_with_original_submission(
    owner: &CompositionReservation,
    seed: &ReservationSeed,
    context: &RequestMetadata,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
    original_submission: &OriginalWriteSubmission,
) -> Result<SealedReservation, ReservationWriteError> {
    reserve_for_transition_inner(
        owner,
        seed,
        context,
        transition,
        (expected_revision_heads, expected_ordering_heads),
        Some(original_submission),
        false,
    )
    .map(|(sealed, _)| sealed)
}

pub(crate) fn accept_reservation_for_transition_with_original_submission(
    owner: &CompositionReservation,
    seed: &ReservationSeed,
    context: &RequestMetadata,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
    original_submission: &OriginalWriteSubmission,
) -> Result<(SealedReservation, AcceptedPending), ReservationWriteError> {
    let (sealed, accepted) = reserve_for_transition_inner(
        owner,
        seed,
        context,
        transition,
        (expected_revision_heads, expected_ordering_heads),
        Some(original_submission),
        true,
    )?;
    let accepted = accepted.ok_or_else(|| ReservationWriteError::Binding {
        operation_id: transition.identity.operation_id.as_str().to_owned(),
        detail: "ORS did not return its durable accepted-stage readback".to_owned(),
    })?;
    Ok((sealed, accepted))
}

/// Advances a reservation from `Eligible` to `Executing` before the first
/// possible Store send. A crash after this transaction is receipt-only on
/// recovery; callers must never infer that no effect occurred from the
/// absence of a response.
pub(crate) fn claim_execute_before_send(
    owner: &CompositionReservation,
    token: &WriterReservationToken,
) -> Result<ReservationRecord, ReservationWriteError> {
    Ok(owner.ors.claim_execute(token, owner.writer_identity())?)
}

fn reserve_for_transition_inner(
    owner: &CompositionReservation,
    seed: &ReservationSeed,
    context: &RequestMetadata,
    transition: &PreparedTransition,
    head_expectations: (&[RevisionHeadExpectation], &[OrderingHeadExpectation]),
    original_submission: Option<&OriginalWriteSubmission>,
    accept_after_stage: bool,
) -> Result<(SealedReservation, Option<AcceptedPending>), ReservationWriteError> {
    let (expected_revision_heads, expected_ordering_heads) = head_expectations;
    let operation_id = transition.identity.operation_id.as_str().to_owned();
    validate_original_submission(transition, original_submission, &operation_id)?;
    validate_admitted(
        context,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
    )?;
    seed.validate(&operation_id)?;
    refuse_plaintext_payload(seed, transition, &operation_id)?;
    let observed_sequence = check_epoch_against_fence(&owner.writer_epoch, context, &operation_id)?;
    validate_observed_heads(seed, expected_ordering_heads, &operation_id)?;
    let (request, transition_digest) = build_reservation_request(
        owner,
        seed,
        context,
        transition,
        observed_sequence,
        original_submission,
    )?;
    let (token, accepted) = if accept_after_stage {
        let accepted = owner.ors.accept_after_stage(request)?;
        let record = reservation_record_by_operation(owner, &accepted.operation_id)?;
        let token = record.token;
        if accepted.reservation_id != token.reservation_id
            || accepted.operation_id != token.operation_id
            || accepted.reservation_order != token.reservation_order
            || accepted.prepared_transition_sha256 != token.prepared_transition_sha256
            || accepted.write_binding
                != token
                    .write_binding
                    .clone()
                    .ok_or_else(|| ReservationWriteError::Binding {
                        operation_id: operation_id.clone(),
                        detail: "accepted ORS record has no original write binding".to_owned(),
                    })?
        {
            return Err(ReservationWriteError::Binding {
                operation_id,
                detail: "ORS accepted-stage evidence differs from its durable reservation token"
                    .to_owned(),
            });
        }
        (token, Some(accepted))
    } else {
        (owner.ors.stage_and_reserve(request)?, None)
    };
    if token.reservation_order == 0
        || token.prepared_transition_sha256 != transition_digest
        || token.operation_id.as_str() != seed.operation_id
    {
        return Err(ReservationWriteError::Binding {
            operation_id,
            detail: "ORS token does not bind the admitted reservation inputs".to_owned(),
        });
    }
    Ok((
        SealedReservation {
            token,
            created_at_ms: seed.created_at_ms,
        },
        accepted,
    ))
}

fn validate_original_submission(
    transition: &PreparedTransition,
    original_submission: Option<&OriginalWriteSubmission>,
    operation_id: &str,
) -> Result<(), ReservationWriteError> {
    let has_capture = transition
        .named_operations
        .iter()
        .any(|operation| operation.operation == NamedMutationOperation::CaptureObservation);
    match (has_capture, original_submission) {
        (true, None) => Err(ReservationWriteError::Admission {
            operation_id: operation_id.to_owned(),
            detail:
                "CaptureObservation reservation requires its original public Observe submission"
                    .to_owned(),
        }),
        (false, Some(_)) => Err(ReservationWriteError::Admission {
            operation_id: operation_id.to_owned(),
            detail: "original Observe submission is only valid for CaptureObservation".to_owned(),
        }),
        (_, Some(source)) => source
            .validate()
            .map_err(|error| ReservationWriteError::Admission {
                operation_id: operation_id.to_owned(),
                detail: format!("original Observe submission is invalid: {error}"),
            }),
        (false, None) => Ok(()),
    }
}

fn validate_observed_heads(
    seed: &ReservationSeed,
    expected_ordering_heads: &[OrderingHeadExpectation],
    operation_id: &str,
) -> Result<(), ReservationWriteError> {
    let mut observed: Vec<(&str, u64)> = seed
        .heads
        .iter()
        .map(|head| (head.scope.as_str(), head.expected_sequence))
        .collect();
    observed.sort_unstable();
    let mut declared: Vec<(&str, u64)> = expected_ordering_heads
        .iter()
        .map(|head| (head.scope.as_str(), head.expected_sequence))
        .collect();
    declared.sort_unstable();
    if observed != declared {
        return Err(ReservationWriteError::Binding {
            operation_id: operation_id.to_owned(),
            detail:
                "observed head set must exactly cover the admitted scopes with matching sequences"
                    .to_owned(),
        });
    }
    Ok(())
}

fn build_reservation_request(
    owner: &CompositionReservation,
    seed: &ReservationSeed,
    context: &RequestMetadata,
    transition: &PreparedTransition,
    observed_sequence: u64,
    original_submission: Option<&OriginalWriteSubmission>,
) -> Result<(ReservationRequest, String), ReservationWriteError> {
    let operation_id = transition.identity.operation_id.as_str().to_owned();
    let fence_snapshot = StateFenceSnapshot::capture(&context.state_fence, observed_sequence)
        .map_err(ReservationWriteError::Ors)?;
    let envelope = RecoveryPayloadEnvelope::encrypted(
        RecoveryEnvelopeContext {
            operation_or_checkpoint_id: OrsOperationIdentity::new(&seed.operation_id)
                .map_err(ReservationWriteError::Ors)?,
            privacy_and_visibility_class: seed.recovery_access_class.clone(),
            authority_epoch: owner.writer_epoch.clone(),
            state_fence: fence_snapshot,
            created_at_ms: seed.created_at_ms,
            known_at_ms: seed.known_at_ms,
            expires_at_ms: Some(seed.expires_at_ms),
        },
        SecretReference::new(seed.key_provider.clone(), seed.key_name.clone()).map_err(
            |error| ReservationWriteError::Admission {
                operation_id: operation_id.clone(),
                detail: format!("reservation seed key reference is invalid: {error}"),
            },
        )?,
        seed.payload_bytes.clone(),
    )
    .map_err(ReservationWriteError::Ors)?;
    let transition_digest = prepared_transition_digest(transition)?;
    let envelope = match original_submission {
        Some(source) => {
            bind_original_write_submission(envelope, source, owner, transition, &transition_digest)?
        }
        None => envelope,
    };
    let mut scopes: Vec<ScopeReservationRequest> = seed
        .heads
        .iter()
        .map(|head| {
            Ok(ScopeReservationRequest {
                scope: OpaqueLabel::new(head.scope.clone()).map_err(ReservationWriteError::Ors)?,
                expected_head: ExpectedOrderingHead {
                    sequence: head.expected_sequence,
                    head_sha256: head.expected_head_digest.clone(),
                    revision_head: head.revision_head.clone(),
                },
            })
        })
        .collect::<Result<_, ReservationWriteError>>()?;
    scopes.sort_by(|left, right| left.scope.cmp(&right.scope));
    let request = ReservationRequest {
        reservation_id: OpaqueLabel::new(seed.reservation_id.clone())
            .map_err(ReservationWriteError::Ors)?,
        envelope,
        writer_epoch: owner.writer_epoch.clone(),
        scopes,
        prepared_transition_sha256: transition_digest.clone(),
        expires_at_ms: seed.expires_at_ms,
        recovery_owner: RecoveryOwner::new(seed.recovery_owner.clone())
            .map_err(ReservationWriteError::Ors)?,
    };
    Ok((request, transition_digest))
}

pub(crate) fn reservation_record_by_operation(
    owner: &CompositionReservation,
    operation_id: &OrsOperationIdentity,
) -> Result<ReservationRecord, ReservationWriteError> {
    owner
        .ors
        .load_write_reservation_by_operation(operation_id)?
        .ok_or_else(|| ReservationWriteError::Binding {
            operation_id: operation_id.as_str().to_owned(),
            detail: "durable ORS operation index omitted its reservation record".to_owned(),
        })
}

fn bind_original_write_submission(
    envelope: RecoveryPayloadEnvelope,
    source: &OriginalWriteSubmission,
    owner: &CompositionReservation,
    transition: &PreparedTransition,
    transition_digest: &str,
) -> Result<RecoveryPayloadEnvelope, ReservationWriteError> {
    let RecoveryPayload::Encrypted { key, .. } = &envelope.payload else {
        return Err(ReservationWriteError::Admission {
            operation_id: transition.identity.operation_id.as_str().to_owned(),
            detail: "CaptureObservation reservation requires the exact protected encrypted payload"
                .to_owned(),
        });
    };
    let ordering_scopes = transition
        .ordering_scopes
        .iter()
        .map(|scope| {
            OpaqueLabel::new(scope.as_str().to_owned()).map_err(ReservationWriteError::Ors)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let write_binding = RecoveryWriteBinding {
        write_envelope_protocol_version: source.protocol_version,
        recovery_envelope_contract_version: envelope.contract_version,
        recovery_access_class: envelope.privacy_and_visibility_class.clone(),
        payload_created_at_ms: envelope.created_at_ms,
        payload_known_at_ms: envelope.known_at_ms,
        payload_expires_at_ms: envelope.expires_at_ms,
        operation_id: envelope.operation_or_checkpoint_id.clone(),
        write_intent_id: OpaqueLabel::new(source.write_intent_id.clone())
            .map_err(ReservationWriteError::Ors)?,
        idempotency_key: OpaqueLabel::new(transition.identity.idempotency_key.clone())
            .map_err(ReservationWriteError::Ors)?,
        canonical_request_sha256: transition.identity.canonical_request_hash.clone(),
        prepared_transition_sha256: transition_digest.to_owned(),
        ordering_scopes,
        admission_contract_set_digest: transition.admission_contract_set_digest.clone(),
        operation_manifest_digest: OpaqueLabel::new(
            transition.operation_manifest_digest.as_str().to_owned(),
        )
        .map_err(ReservationWriteError::Ors)?,
        authority_epoch: owner.writer_epoch.clone(),
        state_fence: envelope.state_fence.clone(),
        protected_payload_sha256: envelope.payload_sha256.clone(),
        protected_payload_length: envelope.payload_length,
        payload_key_reference: key.clone(),
        write_response_mode: Some(source.response_mode.clone()),
    };
    write_binding
        .validate()
        .map_err(ReservationWriteError::Ors)?;
    envelope
        .with_write_binding(write_binding)
        .map_err(ReservationWriteError::Ors)
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
    project_reserved_write_inner(
        sealed,
        context,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
        None,
    )
}

fn project_reserved_write_inner(
    sealed: &SealedReservation,
    context: &RequestMetadata,
    transition: &PreparedTransition,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
    original_write_submission: Option<OriginalWriteSubmission>,
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
        original_write_submission,
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

/// Waits for one exact staged reservation to pass the durable eligibility
/// transition, using the current identity owned by this composition binding.
pub async fn wait_until_eligible(
    owner: &CompositionReservation,
    token: &WriterReservationToken,
) -> Result<ReservationRecord, ReservationWriteError> {
    Ok(owner
        .ors
        .wait_until_eligible(token, owner.writer_identity())
        .await?)
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
    let fenced = StateFenceSnapshot::capture(
        &receipt.state_fence,
        envelope.core.authority.authority_epoch.sequence.get(),
    )
    .map_err(ReservationWriteError::Ors)?;
    if fenced != token.state_fence {
        return Err(binding(
            "Store receipt fence does not match the reservation fence",
        ));
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
/// The caller supplies the exact admitted recovery access class; this function
/// does not derive or default its privacy, visibility, or instruction taint.
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
pub fn gateway_seed(
    platform: &eliot_platform_windows::WindowsPlatform,
    transition: &PreparedTransition,
    mut seed: ReservationSeed,
) -> Result<ReservationSeed, ReservationWriteError> {
    let operation_id = transition.identity.operation_id.as_str().to_owned();
    let plaintext = eliot_contracts::canonical_json_bytes(transition).map_err(|error| {
        ReservationWriteError::Admission {
            operation_id: operation_id.clone(),
            detail: format!("admitted transition canonical bytes do not encode: {error}"),
        }
    })?;
    if seed.payload_bytes != plaintext {
        return Err(ReservationWriteError::Admission {
            operation_id,
            detail: "legacy reservation seed bytes must equal the admitted transition encoding"
                .to_owned(),
        });
    }
    let protected = platform.protect_secret(&plaintext).map_err(|error| {
        ReservationWriteError::Unsupported {
            operation_id: operation_id.clone(),
            detail: format!(
                "reservation for operation {operation_id} and recovery owner {} \
                 (created {}, known {}, expires {}, {} reserved scopes) was not staged: the \
                 installation secret provider could not protect the admitted payload ({error}); \
                 the envelope is never staged as plaintext",
                seed.recovery_owner,
                seed.created_at_ms,
                seed.known_at_ms,
                seed.expires_at_ms,
                seed.heads.len()
            ),
        }
    })?;
    seed.payload_bytes = protected.as_bytes().to_vec();
    gateway_seed_from_protected_original_operation(transition, seed)
}

/// Builds a reservation seed from the Kernel-protected bytes of the complete
/// original Store apply operation. The Kernel owns serialization, protection,
/// and recovery decryption; this boundary preserves those bytes unchanged and
/// binds them to the admitted transition's operation identity.
pub fn gateway_seed_from_protected_original_operation(
    transition: &PreparedTransition,
    seed: ReservationSeed,
) -> Result<ReservationSeed, ReservationWriteError> {
    let operation_id = transition.identity.operation_id.as_str().to_owned();
    if seed.reservation_id != operation_id {
        return Err(ReservationWriteError::Admission {
            operation_id,
            detail: "reservation seed label must equal the original Store operation identity"
                .to_owned(),
        });
    }
    seed.validate(&operation_id)?;
    Ok(seed)
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

    /// Projects one `CaptureObservation` reservation and carries its exact
    /// original public Observe submission through the authenticated Store
    /// boundary unchanged.
    pub fn from_sealed_with_original_submission(
        sealed: &SealedReservation,
        context: &RequestMetadata,
        transition: &PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
        original_submission: &OriginalWriteSubmission,
    ) -> Result<Self, ReservationWriteError> {
        original_submission
            .validate()
            .map_err(|error| ReservationWriteError::Admission {
                operation_id: transition.identity.operation_id.as_str().to_owned(),
                detail: format!("original Observe submission is invalid: {error}"),
            })?;
        if !transition
            .named_operations
            .iter()
            .any(|operation| operation.operation == NamedMutationOperation::CaptureObservation)
        {
            return Err(ReservationWriteError::Admission {
                operation_id: transition.identity.operation_id.as_str().to_owned(),
                detail: "original Observe submission is only valid for CaptureObservation"
                    .to_owned(),
            });
        }
        let request = project_reserved_write_inner(
            sealed,
            context,
            transition,
            expected_revision_heads,
            expected_ordering_heads,
            Some(original_submission.clone()),
        )?;
        Self::new(request)
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
    /// The ORS pending-reservation scan and the ORS control-projection coverage
    /// scan are both exhausted and there is no unresolved row. This still does
    /// not certify the complete W5 startup gate: the protected ORS root is not
    /// opened or integrity-checked and no projection is rebuilt.
    Ready,
    /// A reservation remains unresolved, or either bounded scan did not reach
    /// exhaustion, or a cursor coverage field disagrees with the rows observed.
    Blocked,
}

/// Bounded reconciliation report over the ORS startup obligation sources.
///
/// Produced by [`reconcile_pending_at_startup`] from the persisted ORS
/// reservation recovery pages, the ORS control projection pages, plus exact
/// canonical Store receipt observations read through the named authenticated
/// gateway. A missing or ambiguous receipt leaves its token unresolved and
/// reported; nothing is synthesized, retried, or released to pass. Retained
/// Problems are enumerated by [`reconcile_staged_writes_at_startup`], which
/// also reports them; this report does not open or integrity-check the
/// protected ORS root, rebuild projections, or certify the full W5 startup
/// readiness gate.
#[derive(Clone, Debug)]
pub struct StartupReconciliation {
    /// Live fence the scan ran under; Kernel matches it exactly.
    pub fence: StateFence,
    /// Digest over the fence, both scan sources, every cursor coverage field
    /// and every returned reservation identity/outcome and control obligation
    /// reference.
    pub digest: String,
    /// Number of nonterminal reservation rows returned and examined, bounded by
    /// `scan_limit`.
    pub scanned: u64,
    /// Exact reservation source covered by this report:
    /// `ors.pending_reservations`.
    pub scan_source: &'static str,
    /// Exclusive starting cursor used for the first reservation page.
    pub cursor_start_after_order: u64,
    /// Last reservation order returned by the reservation scan, if any.
    pub last_reservation_order: Option<u64>,
    /// ORS continuation cursor when the whole-scan bound stopped the reservation
    /// scan.
    pub next_after_order: Option<u64>,
    /// True when more pending reservations exist after the whole-scan bound.
    pub truncated: bool,
    /// Exact control-projection source covered by this report:
    /// `ors.control_projection`.
    pub control_scan_source: &'static str,
    /// Exclusive starting cursor used for the first control-projection page.
    pub control_cursor_start_after_order: u64,
    /// Nonterminal reservation orders the control-projection cursor covered.
    pub control_scanned: u64,
    /// ORS continuation cursor when the whole-scan bound stopped the
    /// control-projection scan.
    pub control_next_after_order: Option<u64>,
    /// True when more control-projection rows exist after the whole-scan bound.
    pub control_truncated: bool,
    /// Active durable job-checkpoint subjects the control projection published.
    pub job_checkpoint_refs: Vec<String>,
    /// Active delivery-cursor subjects the control projection published.
    pub delivery_cursor_refs: Vec<String>,
    /// Imported recovery-inbox item identities the control projection
    /// published.
    pub recovery_inbox_refs: Vec<String>,
    /// Whole-scan ceiling supplied by the caller; receipt lookups never exceed
    /// this count. Individual page sizes also respect the ORS page ceiling.
    pub scan_limit: u16,
    /// Unresolved non-unknown operations.
    pub pending: Vec<StartupPendingOperation>,
    /// Ambiguous operations that must stay unresolved.
    pub unknown: Vec<StartupUnknownOperation>,
}

impl StartupReconciliation {
    /// Returns the verdict for this report: `Ready` requires both sources to
    /// have consistent cursor coverage, both bounded scans to be exhausted, and
    /// the pending/unknown sets to be empty. A control obligation that is merely
    /// present does not block: what must be unproven is its coverage, not its
    /// existence. A truncated, corrupt or non-advancing control scan is a
    /// failed check, never an empty answer (issue #1713, item 5).
    pub fn readiness(&self) -> StartupReconciliationReadiness {
        let cursor_coverage_is_consistent = self.scan_source == STARTUP_RESERVATION_SCAN_SOURCE
            && self.scan_limit > 0
            && self.cursor_start_after_order == 0
            && self.scanned <= u64::from(self.scan_limit)
            && (self.scanned == 0) == self.last_reservation_order.is_none()
            && if self.truncated {
                self.next_after_order.is_some()
                    && self.next_after_order == self.last_reservation_order
            } else {
                self.next_after_order.is_none()
            };
        let control_coverage_is_consistent = self.control_scan_source
            == STARTUP_CONTROL_SCAN_SOURCE
            && self.control_cursor_start_after_order == 0
            && self.control_scanned <= u64::from(self.scan_limit)
            && self.control_truncated == self.control_next_after_order.is_some();
        if cursor_coverage_is_consistent
            && control_coverage_is_consistent
            && !self.truncated
            && !self.control_truncated
            && self.pending.is_empty()
            && self.unknown.is_empty()
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
    // Same-authority rule: only tokens minted under the bound writer
    // epoch are eligible here. Anything else (restart under a new
    // epoch, foreign writer) is reported pending and never touched.
    if token.writer_epoch.current.lineage_id.as_str()
        != owner.writer_epoch().current.lineage_id.as_str()
        || token.writer_epoch.current.epoch != owner.writer_epoch().current.epoch
    {
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
    let finalized = reconcile_receipt(token, &receipt).and_then(|reconciliation| {
        let evidence = owner.evidence.as_ref().ok_or_else(|| {
            ReservationWriteError::Ors(eliot_ors::OrsError::CanonicalEvidence(
                "startup receipt has no shared canonical Store evidence provider".to_owned(),
            ))
        })?;
        evidence.with_store_receipt(token, &reconciliation, &receipt, || {
            finalize_reservation(owner, &reconciliation)
        })?
    });
    match finalized {
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

fn startup_scan_integrity_error(
    record_type: &'static str,
    reason: impl Into<String>,
) -> ReservationWriteError {
    ReservationWriteError::Ors(eliot_ors::OrsError::IntegrityProblem {
        record_type,
        reason: reason.into(),
    })
}

fn startup_reservation_scan_integrity_error(reason: impl Into<String>) -> ReservationWriteError {
    startup_scan_integrity_error("startup_reservation_cursor", reason)
}

struct StartupReservationPageScan {
    cursor_start_after_order: u64,
    scanned: u16,
    last_reservation_order: Option<u64>,
    next_after_order: Option<u64>,
    truncated: bool,
    records: Vec<ReservationRecord>,
}

fn scan_startup_reservation_pages(
    owner: &CompositionReservation,
    limit: u16,
) -> Result<StartupReservationPageScan, ReservationWriteError> {
    let cursor_start_after_order = 0;
    let mut after_order = cursor_start_after_order;
    let mut scanned = 0u16;
    let mut last_reservation_order = None;
    let mut next_after_order = None;
    let mut truncated = false;
    let mut records = Vec::new();

    loop {
        let remaining = limit - scanned;
        let page_limit = remaining.min(eliot_ors::MAX_RECOVERY_PAGE);
        let cursor = RecoveryCursor::new(after_order, page_limit)?;
        let page = owner.ors.recover_page(cursor)?;
        let page_record_count = page.records.len();
        if page_record_count > usize::from(page_limit) {
            return Err(startup_reservation_scan_integrity_error(format!(
                "page returned {page_record_count} rows for limit {page_limit}"
            )));
        }

        let mut page_last_order = None;
        for record in &page.records {
            let order = record.token.reservation_order;
            if order <= after_order || page_last_order.is_some_and(|previous| order <= previous) {
                return Err(startup_reservation_scan_integrity_error(format!(
                    "reservation order {order} did not advance exclusive cursor {after_order}"
                )));
            }
            page_last_order = Some(order);
        }

        if let Some(next) = page.next_after_order
            && (page_record_count != usize::from(page_limit)
                || page_last_order != Some(next)
                || next <= after_order)
        {
            return Err(startup_reservation_scan_integrity_error(format!(
                "continuation cursor {next} does not match the last row of a full page after {after_order}"
            )));
        }

        let page_covered = u16::try_from(page_record_count).map_err(|_| {
            startup_reservation_scan_integrity_error("page row count exceeds the bounded counter")
        })?;
        scanned += page_covered;
        if page_last_order.is_some() {
            last_reservation_order = page_last_order;
        }
        records.extend(page.records);

        match page.next_after_order {
            Some(next) if scanned == limit => {
                truncated = true;
                next_after_order = Some(next);
                break;
            }
            Some(next) => after_order = next,
            None => break,
        }
    }

    Ok(StartupReservationPageScan {
        cursor_start_after_order,
        scanned,
        last_reservation_order,
        next_after_order,
        truncated,
        records,
    })
}

/// One bounded pass over the ORS control projection's durable obligations.
///
/// The control page returns the checkpoint, delivery-cursor and recovery-inbox
/// references the owner rebuilt from validated durable records, together with
/// the reservation-order continuation its own recovery page used. Those
/// references are a whole-table publication rather than a cursor-bounded
/// window, so the scan unions and de-duplicates them instead of summing them:
/// a reference seen on three pages is one obligation, not three.
struct StartupControlPageScan {
    cursor_start_after_order: u64,
    scanned: u16,
    next_after_order: Option<u64>,
    truncated: bool,
    job_checkpoint_refs: Vec<String>,
    delivery_cursor_refs: Vec<String>,
    recovery_inbox_refs: Vec<String>,
}

/// Pages the ORS control projection to exhaustion under the same exclusive
/// cursor, page ceiling and whole-scan bound as the reservation scan
/// (issue #1713, item 5).
///
/// A page that returns more rows than the bound allows, or a continuation
/// cursor that does not strictly advance past the cursor it followed, is a
/// corrupt or missing page and fails the whole scan: coverage is never
/// reported as smaller than it is, and never as an empty answer.
fn scan_startup_control_projection_pages(
    ors: &RedbRecoveryStore,
    limit: u16,
) -> Result<StartupControlPageScan, ReservationWriteError> {
    let cursor_start_after_order = 0;
    let mut after_order = cursor_start_after_order;
    let mut scanned = 0u16;
    let mut next_after_order = None;
    let mut truncated = false;
    let mut job_checkpoint_refs: BTreeSet<String> = BTreeSet::new();
    let mut delivery_cursor_refs: BTreeSet<String> = BTreeSet::new();
    let mut recovery_inbox_refs: BTreeSet<String> = BTreeSet::new();

    loop {
        let remaining = limit - scanned;
        let page_limit = remaining.min(eliot_ors::MAX_RECOVERY_PAGE);
        let cursor = RecoveryCursor::new(after_order, page_limit)?;
        let (projection, next) = ors.control_projection_page(cursor).map_err(|error| {
            startup_scan_integrity_error(
                "startup_control_projection_cursor",
                format!("control projection page after {after_order} is unreadable: {error}"),
            )
        })?;
        let page_row_count = projection.pending_operation_refs.len();
        if page_row_count > usize::from(page_limit) {
            return Err(startup_scan_integrity_error(
                "startup_control_projection_cursor",
                format!(
                    "control projection page returned {page_row_count} rows for limit {page_limit}"
                ),
            ));
        }
        if let Some(next) = next
            && (page_row_count != usize::from(page_limit) || next <= after_order)
        {
            return Err(startup_scan_integrity_error(
                "startup_control_projection_cursor",
                format!(
                    "continuation cursor {next} does not advance a full control projection page after {after_order}"
                ),
            ));
        }
        scanned = scanned
            .checked_add(u16::try_from(page_row_count).map_err(|_| {
                startup_scan_integrity_error(
                    "startup_control_projection_cursor",
                    "control projection page row count exceeds the bounded counter",
                )
            })?)
            .ok_or_else(|| {
                startup_scan_integrity_error(
                    "startup_control_projection_cursor",
                    "control projection coverage overflowed the whole-scan bound",
                )
            })?;
        job_checkpoint_refs.extend(projection.job_checkpoint_refs);
        delivery_cursor_refs.extend(projection.delivery_cursor_refs);
        recovery_inbox_refs.extend(projection.recovery_inbox_refs);

        match next {
            Some(next) if scanned == limit => {
                truncated = true;
                next_after_order = Some(next);
                break;
            }
            Some(next) => after_order = next,
            None => break,
        }
    }

    Ok(StartupControlPageScan {
        cursor_start_after_order,
        scanned,
        next_after_order,
        truncated,
        job_checkpoint_refs: job_checkpoint_refs.into_iter().collect(),
        delivery_cursor_refs: delivery_cursor_refs.into_iter().collect(),
        recovery_inbox_refs: recovery_inbox_refs.into_iter().collect(),
    })
}

/// Binds the control-projection coverage into the startup scan digest.
///
/// The source, the exclusive cursor and its continuation, the truncation flag,
/// the covered row count and every observed obligation reference go into the
/// same digest as the reservation rows, so a partial obligation scan can never
/// be digest-indistinguishable from a complete one.
fn append_control_coverage_digest(encoded: &mut String, control: &StartupControlPageScan) {
    for field in [
        STARTUP_CONTROL_SCAN_SOURCE.to_owned(),
        control.cursor_start_after_order.to_string(),
        control
            .next_after_order
            .map_or_else(|| "none".to_owned(), |order| order.to_string()),
        control.scanned.to_string(),
        control.truncated.to_string(),
        control.job_checkpoint_refs.len().to_string(),
        control.delivery_cursor_refs.len().to_string(),
        control.recovery_inbox_refs.len().to_string(),
    ] {
        append_startup_digest_field(encoded, &field);
    }
    for refs in [
        &control.job_checkpoint_refs,
        &control.delivery_cursor_refs,
        &control.recovery_inbox_refs,
    ] {
        for reference in refs {
            append_startup_digest_field(encoded, reference);
        }
    }
}

/// Reconciles persisted pending/unknown ORS reservations against exact
/// canonical Store receipts at startup, and covers the ORS control projection's
/// durable checkpoint/inbox obligations. This helper still does not open or
/// integrity-check the protected ORS root, rebuild projections, or certify the
/// full W5 startup gate.
///
/// For every non-terminal reservation up to the caller's whole-scan `limit`,
/// this observes the exact Store receipt by operation identity through the
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
/// The same whole-scan bound then pages the ORS control projection so the
/// job-checkpoint, delivery-cursor and recovery-inbox obligations its owner
/// publishes reach the startup gate with their own cursor and coverage
/// accounting instead of being silently absent (issue #1713, item 5).
///
/// Bounds: `limit` is the whole-scan ceiling, not a page size. Each ORS request
/// is additionally capped at `MAX_RECOVERY_PAGE`; no more than `limit` rows are
/// collected and no more than `limit` Store receipts are observed. A continued
/// cursor at that ceiling sets `truncated` and `control_truncated`, records
/// exact cursor coverage and blocks this report's verdict. ORS corruption and
/// malformed, missing, repeated or non-progressing continuation pages fail
/// closed in either scan.
pub async fn reconcile_pending_at_startup(
    owner: &CompositionReservation,
    fence: &StateFence,
    route: &dyn StartupReceiptRoute,
    limit: u16,
) -> Result<StartupReconciliation, ReservationWriteError> {
    let scan = scan_startup_reservation_pages(owner, limit)?;
    let control = scan_startup_control_projection_pages(&owner.ors, limit)?;
    let mut pending = Vec::new();
    let mut unknown = Vec::new();
    let mut scan_entries = Vec::with_capacity(scan.records.len());
    for record in &scan.records {
        let token = &record.token;
        let operation_id = token.operation_id.as_str().to_owned();
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
        scan_entries.push(startup_reservation_scan_entry(
            token,
            record.state,
            &outcome_for_digest,
        ));
        match entry {
            StartupRecordOutcome::Resolved => {}
            StartupRecordOutcome::Pending { reason } => pending.push(StartupPendingOperation {
                operation_id,
                reservation_order: token.reservation_order,
                scopes,
                state: record.state,
                recovery_owner,
                reason,
            }),
            StartupRecordOutcome::Unknown { reason } => unknown.push(StartupUnknownOperation {
                operation_id,
                reservation_order: token.reservation_order,
                scopes,
                state: record.state,
                recovery_owner,
                reason,
            }),
        }
    }
    let scanned = u64::from(scan.scanned);
    let control_scanned = u64::from(control.scanned);
    let mut digest_input = String::new();
    for field in [
        STARTUP_RESERVATION_SCAN_SOURCE.to_owned(),
        fence.authority_epoch.lineage_id.as_str().to_owned(),
        fence.authority_epoch.sequence.get().to_string(),
        fence.resource_generation.value().to_string(),
        scan.cursor_start_after_order.to_string(),
        scan.last_reservation_order
            .map_or_else(|| "none".to_owned(), |order| order.to_string()),
        scan.next_after_order
            .map_or_else(|| "none".to_owned(), |order| order.to_string()),
        scanned.to_string(),
        limit.to_string(),
        scan.truncated.to_string(),
        scan_entries.len().to_string(),
    ] {
        append_startup_digest_field(&mut digest_input, &field);
    }
    for entry in &scan_entries {
        append_startup_digest_field(&mut digest_input, entry);
    }
    // The control-projection coverage is bound here too: a truncated or
    // partial obligation scan must not be digest-indistinguishable from a
    // complete one.
    append_control_coverage_digest(&mut digest_input, &control);
    let digest = sha256_hex(digest_input.as_bytes());
    Ok(StartupReconciliation {
        fence: fence.clone(),
        digest,
        scanned,
        scan_source: STARTUP_RESERVATION_SCAN_SOURCE,
        cursor_start_after_order: scan.cursor_start_after_order,
        last_reservation_order: scan.last_reservation_order,
        next_after_order: scan.next_after_order,
        truncated: scan.truncated,
        control_scan_source: STARTUP_CONTROL_SCAN_SOURCE,
        control_cursor_start_after_order: control.cursor_start_after_order,
        control_scanned,
        control_next_after_order: control.next_after_order,
        control_truncated: control.truncated,
        job_checkpoint_refs: control.job_checkpoint_refs,
        delivery_cursor_refs: control.delivery_cursor_refs,
        recovery_inbox_refs: control.recovery_inbox_refs,
        scan_limit: limit,
        pending,
        unknown,
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

/// One staged operation whose envelope could not be validated at startup.
///
/// I5.2 requires a durable Recovery Problem here, never plaintext fallback and
/// never silent deletion. `recovery-problem-retained` names the case where ORS
/// retained that problem before returning `RecoveryProblemRetained`, and the
/// staged record stays available for disposition.
/// `recovery-problem-not-retained` names the case where retaining the problem
/// failed as well: no durable Problem exists for this operation, so it keeps
/// its exact recovery reference in the reservation report and is never reported
/// absent or clean. `reason` uses a fixed vocabulary so the report stays a
/// bounded diagnostic, not an error log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupEnvelopeProblem {
    /// Operation identity whose staged envelope failed validation.
    pub operation_id: String,
    /// ORS-assigned reservation order of the owning reservation.
    pub reservation_order: u64,
    /// Fixed-vocabulary cause (`recovery-problem-retained` or
    /// `recovery-problem-not-retained`).
    pub reason: &'static str,
}

/// Bounded startup verdict over the staged write envelopes (I1.11 step 6,
/// I5.2/I5.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StagedWriteReadiness {
    /// Every enumerated staged envelope validated by hash, every reservation
    /// reached its canonical receipt, and no Recovery Problem is retained.
    Ready,
    /// A reservation is unresolved, a staged envelope failed validation, a
    /// Recovery Problem is retained, or the bounded scan did not reach
    /// exhaustion. Normal writes stay gated until exact reconciliation or an
    /// explicit disposition.
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
#[derive(Clone, Debug)]
pub struct StagedWriteRecovery {
    /// Reservation-level reconciliation, including its exact scan digest.
    pub reservations: StartupReconciliation,
    /// Staged envelopes the scan enumerated and the owner validated by hash.
    pub envelopes: Vec<StartupStagedEnvelope>,
    /// Operations whose staged envelope failed validation.
    pub problems: Vec<StartupEnvelopeProblem>,
    /// Every durable Recovery Problem ORS retains, in operation-identity order.
    pub retained_problems: Vec<eliot_ors::RecoveryProblem>,
}

impl StagedWriteRecovery {
    /// Returns the step-6 verdict for the staged envelopes and their
    /// reservations.
    ///
    /// A bounded scan that stopped early is `Blocked`: a partial read has not
    /// proven anything about the rows it did not reach, so it can never certify
    /// readiness. A retained-problem listing that filled the whole-scan ceiling
    /// is the same shape: an unseen retained Problem cannot be shown to be
    /// resolved, so coverage is unproven and the verdict stays `Blocked`
    /// (issue #1713, item 5).
    #[must_use]
    pub fn readiness(&self) -> StagedWriteReadiness {
        if self.reservations.readiness() == StartupReconciliationReadiness::Ready
            && self.problems.is_empty()
            && self.retained_problems.len() < usize::from(self.reservations.scan_limit)
            && self
                .retained_problems
                .iter()
                .all(eliot_ors::RecoveryProblem::is_resolved)
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
/// Three owner-scoped reads, all over the composition-bound ORS and the exact
/// Store the writer used:
///
/// ```text
/// reconcile_pending_at_startup  -> each unresolved reservation is observed by
///                                  exact operation identity and either closed
///                                  by its canonical receipt or reported
///                                  pending/unknown (never force-released);
/// verify_staged_envelope        -> each reported operation's envelope is
///                                  re-read and revalidated by the owner, and a
///                                  failure leaves a durable Recovery Problem;
/// list_recovery_problems        -> every retained problem is reported so a
///                                  staged payload stays visible for
///                                  disposition instead of being dropped.
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
/// Bounds: `limit` is the whole-scan ceiling for both the reservation scan and
/// the retained-problem listing, exactly as in
/// [`reconcile_pending_at_startup`]. Nothing here interprets a payload, resolves
/// a key, or deletes a staged record.
pub async fn reconcile_staged_writes_at_startup(
    owner: &CompositionReservation,
    fence: &StateFence,
    route: &dyn StartupReceiptRoute,
    limit: u16,
) -> Result<StagedWriteRecovery, ReservationWriteError> {
    let reservations = reconcile_pending_at_startup(owner, fence, route, limit).await?;
    let mut envelopes = Vec::new();
    let mut problems = Vec::new();
    // Pending and unknown are the same operation population read from the two
    // report vectors, so the envelope pass visits each identity once.
    let unresolved = reservations
        .pending
        .iter()
        .map(|entry| {
            (
                entry.operation_id.as_str(),
                entry.reservation_order,
                entry.state,
            )
        })
        .chain(reservations.unknown.iter().map(|entry| {
            (
                entry.operation_id.as_str(),
                entry.reservation_order,
                entry.state,
            )
        }));
    for (operation_id, reservation_order, state) in unresolved {
        let identity =
            OrsOperationIdentity::new(operation_id).map_err(ReservationWriteError::Ors)?;
        match owner.ors.verify_staged_envelope(&identity) {
            Ok(envelope) => envelopes.push(StartupStagedEnvelope {
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
            }),
            // The owner already retained a durable Recovery Problem for this
            // staged operation; the record stays available for disposition and
            // is reported instead of being read, replaced, or dropped here.
            Err(eliot_ors::OrsError::RecoveryProblemRetained { .. }) => {
                problems.push(StartupEnvelopeProblem {
                    operation_id: operation_id.to_owned(),
                    reservation_order,
                    reason: "recovery-problem-retained",
                });
            }
            // Retaining that Recovery Problem failed too (issue #1713, item 4).
            // The item forbids claiming a durable Problem was created and
            // forbids calling the operation safely absent, so the operation is
            // reported as an unrecorded problem under its exact recovery
            // reference. Its reservation stays in the pending/unknown report
            // from the pass above, so step 6 stays `Blocked`.
            Err(eliot_ors::OrsError::IntegrityProblem {
                record_type: "recovery_problem_record",
                ..
            }) => {
                problems.push(StartupEnvelopeProblem {
                    operation_id: operation_id.to_owned(),
                    reservation_order,
                    reason: "recovery-problem-not-retained",
                });
            }
            Err(error) => return Err(ReservationWriteError::Ors(error)),
        }
    }
    let retained_problems = owner.ors.list_recovery_problems(limit)?;
    Ok(StagedWriteRecovery {
        reservations,
        envelopes,
        problems,
        retained_problems,
    })
}
