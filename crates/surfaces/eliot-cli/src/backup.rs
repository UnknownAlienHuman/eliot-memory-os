//! Typed backup command surface (issue #963).
//!
//! Thin client adapters for the three backup catalogue commands: parse
//! bounded operator fields, build the closed kernel payload, delegate
//! through the correlated [`KernelClient`] front door, and decode the
//! typed reply into a closed [`BackupOperationOutcome`]. This crate never
//! opens transports beyond the client, never mints authority, and never
//! interprets a payload as canonical state: every cross-boundary fact is
//! re-checked here (command echo, idempotency echo, status, and exact
//! result shape) before it becomes a response.
//!
//! Wire contract mirror: the Kernel backup route
//! (`bins/eliot-kernel/src/request_dispatch.rs`) carries the exact
//! operation selectors and payload shapes used here; a mismatch on
//! either side refuses before effects. The typed fields travel in the
//! typed `CommandArguments` variants and in the operation payload, so an
//! empty payload can never select scope or destination silently: the
//! payload only exists after the closed parser admitted every field.
//!
//! Empty payloads never select scope or destination silently: create
//! requires an explicit scope descriptor and closed class, verify and
//! restore-test require explicit bundle bytes, restore-test additionally
//! requires explicit target descriptors, authorization bytes,
//! provisioning attestations, and an explicit introductions array.
//! Unknown outcomes stay unknown with their operation identity for
//! same-operation reconciliation — never success, never blind retry.
//!
//! The closed archive class and the proven backup lifecycle level come
//! from the protocol owner (`eliot_protocol::backup::BackupClassWire` and
//! `eliot_protocol::backup::BackupStage`), never from a second local
//! vocabulary. I5.13 fixes the operator class tokens in lower snake case
//! while the protocol enum's serde spelling is `SCREAMING_SNAKE_CASE`, so
//! [`backup_class`] is the one documented spelling decoder for both
//! spellings; the Kernel route carries the mirrored decoder for the same
//! reason, because a binary crate cannot import a surface crate.
//!
//! The verification level behind a verify reply is the owner's answer too,
//! never a second local vocabulary. [`VerifyProofLevel`] is the ONE typed owner
//! of that vocabulary on this surface: it carries the stable wire spelling, the
//! exhaustive decoder, and the relation between the level and the owner's
//! capture evidence, so a level and the evidence it requires are declared
//! together instead of in two hand-maintained tables. The outcome state is
//! decided from the owner's level alone:
//! [`VerifyProofLevel::ProvenanceBound`] or
//! [`VerifyProofLevel::ClassQualified`] is what [`BACKUP_STATE_VERIFIED`]
//! means, while a [`VerifyProofLevel::StructuralCandidate`] archive — bytes
//! that decode, validate and relate internally while carrying no retained
//! capture receipt — is an untrusted candidate reported as
//! [`BACKUP_STATE_CANDIDATE`]. Backup existence is not recovery proof
//! (I5.13): a `canonical_only_degraded` archive is never advertised as
//! operational recovery, a `scope_export` archive is not an installation
//! backup, and a self-consistent caller-authored checksum is not capture
//! provenance. The owner's class ceiling, capture receipt and
//! archived-fence relation are echoed under closed checks with absence kept
//! explicit, never inferred from the archive's own prose and never
//! defaulted, and no outcome here claims decryptability, isolated restore
//! success or cutover authority.
//!
//! A closed set is a vocabulary, not a proof, so [`require_proven_claim`] also
//! checks the COMPLETE relation between those members: a
//! provenance-bound/class-qualified level or a `capture-owner-proven` archived
//! fence REQUIRES the owner-issued capture receipt that proves it, a
//! structural candidate REQUIRES that receipt's absence, and a level this
//! surface cannot relate is refused rather than reported. A provenance-bound
//! level additionally REQUIRES the verifier-issued validity attestation, so a
//! RECOGNIZED level with missing owner evidence is refused rather than
//! downgraded to something weaker. A class ceiling that needs operational
//! authority a read-only verify does not hold is refused through
//! [`VerifyClassCeiling::requires_operational_authority`]. A claim that fails
//! any of those relations is reported as a [`BACKUP_STATE_REFUSED`] outcome
//! naming the exact missing owner evidence, never as a verified archive and
//! never silently dropped.
//!
//! The create path is bounded the same way and reports strictly less. Its
//! Kernel route admits the bounded descriptors and then admits the CALLER
//! through the transport's own proved peer identity and front-door capability —
//! the same admission the capture owner itself consumes — before naming the
//! absent capture-owner behaviour. So an unadmitted session is fenced rather
//! than answered, and an admitted one receives a typed refusal. That refusal is
//! a statement about the REQUEST's next step, never about an ARCHIVE: a handler
//! that read its own arguments back has validated the request, not the
//! archive, and `archive_id`, `verification_level`, `class_ceiling`,
//! `capture_receipt`, `archive_fence_relation`, `archive_fence_proof`,
//! `target_compatibility` and `result_identity` therefore all stay explicitly
//! absent. Only `requested_class` and `requested_scope` are reported, and they
//! are echoes of the operator's own request. Because the create route refuses
//! BEFORE any effect, `next_reconciliation` says there is nothing to reconcile
//! and the same operation may be re-run once the owner exists; reporting an
//! uncertain effect that provably never happened would be the I14.21 error in
//! its mirror image.
//!
//! A proof is only as good as the request it answers, so the verify path binds
//! the NESTED result identity rather than trusting the envelope echo.
//! [`BackupResultIdentity`] carries the operation that produced the answer, the
//! canonical request digest, the durable-row namespace, the owner-proved
//! archive digest and the two owner-issued evidence references, and
//! [`require_result_identity`] compares them against the request before any of
//! them is reported. The outer `idempotency_key` is a TRANSPORT correlation and
//! is explicitly not sufficient: it is the same value on a replay, on a
//! reconciliation of a predecessor's row, and on a substituted answer, so a
//! result that carried nothing else could not tell those three apart. An
//! answer that omits its identity, carries another operation's identity, or
//! claims a level its owner evidence does not back is refused — never reported
//! under the correlation it happened to arrive on.
//!
//! The advertised protocol effect classification and proof ceiling are not
//! restated here either. [`catalogued_ceiling`] reads them from the closed
//! `CommandSpec` row through the same catalogue lookup
//! `CommandResponse::validate_for` uses, and [`respond`] then runs that same
//! parity check on this path. `eliot backup` does not travel through
//! `CommandCatalogue::dispatch`, so without both steps the backup surface
//! would report a classification no catalogue row states and no check would
//! compare: one classification owner, checked, never a second literal.
//!
//! A declared ceiling is a bound, not a projection, so the returned answer is
//! related to that bound before anything is rendered. The restore-test path
//! does this through [`restore_test_claim`] and
//! [`require_restore_test_ceiling`]: the reply's own `status` is graded into
//! the stage it evidences, and the protocol owners' own
//! [`ProofCeiling::is_at_most`], [`EffectClass`] ordering and
//! [`BackupStage::can_advance`] relations decide whether that answer is
//! admitted or refused. An answer above the declared ceiling is refused
//! through [`refuse_unproven_claim`] like any other unproven claim, so a
//! richer future owner response is projected when it is within the ceiling and
//! refused — never rendered as success — when it is not.
//!
//! The isolated restore-test path is the one route here whose owner is the
//! RESTORE coordinator rather than the capture owner, and it reports that
//! owner's own persisted result rather than a transport observation. An `ok`
//! reply carries the coordinator's `RestoreReceipt`, decoded by
//! [`restore_receipt_evidence`] through the RESTORE owner's own closed
//! vocabulary [`BACKUP_RESTORE_EVIDENCE_LEVELS`] and proved by
//! [`require_restore_evidence`] before [`BACKUP_STATE_REHEARSED`] is reported.
//! The relation that proof enforces is the A13.7 boundary made executable on
//! this surface: a rehearsal receipt that claims a cutover, claims operational
//! readiness, or carries a proof level requiring owner evidence this command
//! does not hold is a typed refusal, never a rendered success.
//!
//! It also enforces the relation between the receipt's TWO class-bearing
//! answers, which is the owner's own rather than a rule invented here. The
//! restore owner derives `evidence_level` and `canonical_only` from a single
//! `bundle.manifest.class`, so the two are two projections of one class and
//! only three pairs exist;
//! [`RestoreAuthorityClaim::canonical_only_pair_refusal`] checks the pair rather
//! than trusting either field alone. Decoding `canonical_only`
//! without checking it would prove nothing — it would let a receipt claim a
//! degraded or scope archive's ceiling while asserting a full archive, or the
//! reverse, which is exactly the substitution I5.13 forbids. A reply that
//! carries no decodable receipt at all is a typed result mismatch, so an
//! `ok` that is only a transport acknowledgement cannot be reported as a
//! rehearsal.

use std::fmt::Write as _;

use eliot_contracts::EpochLineageId;
use eliot_protocol::RequestIdentity;
use eliot_protocol::backup::{BackupClassWire, BackupStage};
use eliot_receipts::{EffectClass, ProofCeiling};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use super::{
    CliError, CommandArguments, CommandCatalogue, CommandId, CommandRequest, CommandResponse,
    CommandResult,
    kernel_client::{KernelClient, KernelClientError},
};

/// Closed backup create operation selector (mirrored by the Kernel
/// backup route; the string only selects the entry, never authority).
pub const BACKUP_CREATE_OPERATION: &str = "backup.create";
/// Closed backup verify operation selector (mirrored by the Kernel
/// backup route).
pub const BACKUP_VERIFY_OPERATION: &str = "backup.verify";
/// Closed isolated restore-test operation selector (mirrored by the
/// Kernel backup route; rehearsal only, never cutover).
pub const BACKUP_RESTORE_TEST_OPERATION: &str = "backup.restore-test";

/// Maximum inline bundle bytes admitted in one backup payload.
///
/// Derived from the 4 MiB frame ceiling: JSON hex inflation doubles
/// input bytes on the wire, so 1 MiB of archive bytes stays within
/// budget with envelope headroom. Mirrors the Kernel bound byte-exact;
/// larger archives refuse on both sides instead of truncating.
pub const BACKUP_WIRE_BYTES_MAX: usize = 1_048_576;
/// Maximum inline destination-authorization bytes: mirrors the Kernel
/// destination verifier's 16 KiB cap.
pub const BACKUP_AUTH_BYTES_MAX: usize = 16_384;
/// Maximum operator text field length (scope descriptors, identities).
pub const BACKUP_TEXT_MAX: usize = 256;
/// Maximum console-presented capability introductions admitted in one
/// restore-test payload.
///
/// Mirrors `eliot_ors::MAX_RECOVERY_PAGE` (256) byte-exact with the
/// Kernel bound; the Kernel exact-set check stays authoritative and
/// refuses anything the live owner page cannot verify.
pub const BACKUP_INTRODUCTIONS_MAX: usize = 256;

/// Bounded outcome state of a typed backup result: the archive was
/// verified and its identities were proved.
pub const BACKUP_STATE_VERIFIED: &str = "verified";
/// Bounded outcome state: the request shape failed its closed validation
/// and no owner was named.
pub const BACKUP_STATE_INVALID: &str = "invalid";
/// Bounded outcome state: a closed owner refused the admitted request
/// and named the exact missing owner.
pub const BACKUP_STATE_REFUSED: &str = "refused";
/// Bounded outcome state: the rehearsal proved its gates and execution
/// is blocked on a named owner input.
pub const BACKUP_STATE_BLOCKED: &str = "blocked";
/// Bounded outcome state of an unproven transport outcome: the request
/// may already have reached the Kernel, so the only safe next action is
/// same-operation reconciliation.
pub const BACKUP_STATE_UNKNOWN: &str = "unknown";
/// Bounded outcome state of a capture owner that cancelled, carrying the
/// owner's unconfirmed cleanup state.
///
/// This state is NOT [`BACKUP_STATE_INVALID`] and never was intended to be
/// reached through it. A cancellation is not a request-shape failure: before
/// issue #963 the Kernel reported one through its `invalid` envelope with a
/// `backup.class`/`backup.verify` field, so this surface set a missing
/// obligation of "invalid field: …", the owner cleanup state was dropped
/// entirely, and an operator could not tell an owner cancellation from a
/// malformed class token. A cancellation now has its own wire status and its
/// own state, so the owner cleanup state survives into both projections.
///
/// The proven lifecycle level never advances past [`BackupStage::Requested`]
/// here: a cancelled capture proves no verification level, and I5.13 keeps
/// backup existence from being recovery proof in any case.
///
/// The same limit as on the Kernel side, stated here so neither projection can
/// be read as a claim about an observed event: no production capture owner can
/// currently emit a cancellation (`KernelBackupCapture::verify_only` returns
/// only `Complete` or `Incomplete`), so this arm decodes a state the Kernel
/// does not yet produce. It is a correct mapping of the published vocabulary,
/// not a repaired incident.
pub const BACKUP_STATE_CANCELLED: &str = "cancelled";

/// Bounded outcome state of a structurally valid archive that carries no
/// retained capture provenance.
///
/// I5.13 keeps backup existence from being recovery proof, and a
/// self-consistent decode of caller-supplied bytes is weaker still: the
/// owner did prove this archive's identity and class, so both are reported,
/// but the outcome claims no verified lifecycle level. This state is
/// deliberately not [`BACKUP_STATE_VERIFIED`], which now means only that
/// the owner accepted [`VerifyProofLevel::ProvenanceBound`] or
/// [`VerifyProofLevel::ClassQualified`].
pub const BACKUP_STATE_CANDIDATE: &str = "candidate";

/// Bounded outcome state of an isolated restore-test whose owner reached the
/// journalled restore coordinator and returned its OWN persisted receipt.
///
/// This state is reserved for an answer that carries the owner's receipt, the
/// owner's evidence level and the owner's phase log, all decoded and
/// closed-checked by [`require_restore_evidence`]. A reply that arrives without
/// them is NOT this state: it is either a typed mismatch or the unproven
/// [`BACKUP_STATE_UNKNOWN`] exit, because a successful transport is not restore
/// proof.
///
/// What this state deliberately does NOT say, in the owner's own words rather
/// than this surface's: it is not readiness and it is not cutover.
/// [`RestoreEvidenceLevel`] reaches `OperationallyValidated` only through an
/// owner-issued [`OperationalValidationEvidence`] for the exact isolated root
/// and `Cutover` only through a separate Human/System Owner authorization, and
/// A13.7 keeps cutover a separate authority no rehearsal reaches. So the receipt
/// this state reports is a rehearsal receipt, and `operational_recovery_ready`
/// and `cutover_performed` are carried as the owner's own values and checked to
/// be absent — an owner answer that claims either is REFUSED here rather than
/// rendered, because this command never asks for either.
pub const BACKUP_STATE_REHEARSED: &str = "rehearsed";

/// Closed restore-proof-level vocabulary this surface accepts from the RESTORE
/// owner's own receipt.
///
/// This is the wire spelling of `eliot_backup::RestoreEvidenceLevel`, whose
/// serde form is `snake_case` (`crates/storage/eliot-backup/src/lib.rs`), and it
/// is mirrored here for the same reason [`VerifyProofLevel`] is: the owner lives
/// in a crate this surface does not depend on, so the surface owns the spelling
/// and the exhaustive decoder and refuses a value outside it rather than
/// coercing one.
///
/// Membership is not a claim this surface may make. The two highest members are
/// exactly the two a rehearsal must never be reported as: `operationally_
/// validated` needs owner-issued operational validation evidence this command
/// does not hold, and `cutover` needs a separate Human/System Owner
/// authorization. [`require_restore_evidence`] refuses both outright.
pub const BACKUP_RESTORE_EVIDENCE_LEVELS: [&str; 5] = [
    "archive_valid",
    "isolated_import_complete",
    "reconciliation_required",
    "operationally_validated",
    "cutover",
];

/// Closed owner-cleanup-state vocabulary this surface accepts from a
/// cancellation reply.
///
/// The single member is the only cleanup answer that currently exists, and it
/// is a NEGATIVE fact rather than a clean bill of health: both cancellation
/// carriers in the Kernel capture owner (`CaptureState::Cancelled` and
/// `KernelCaptureError::Cancelled`) are unit variants that carry no cleanup
/// evidence at all, so the truthful report is that cleanup was not supplied and
/// is therefore UNCONFIRMED. A value outside this array is a typed result
/// mismatch, never success: this surface will not accept a cleanup claim it
/// cannot name, and it will not invent a `clean` value for an owner that never
/// sent one. A second member becomes available only when an owner actually
/// supplies cleanup evidence.
pub const BACKUP_OWNER_CLEANUP_STATES: [&str; 1] = [BACKUP_OWNER_CLEANUP_NOT_SUPPLIED];

/// The one owner cleanup state a cancellation can carry today: the owner
/// reported a cancellation and supplied no cleanup evidence.
///
/// Mirrors the Kernel's own literal for the same fact, for the same reason
/// [`BACKUP_CREATE_MISSING_OWNER`] mirrors its refusal: the Kernel route states
/// it in its reply and this surface states it here, and a drift between the two
/// is refused here rather than silently accepted. It is deliberately not a
/// "clean" spelling - an operator must not read it as proof the capture target
/// was torn down.
pub const BACKUP_OWNER_CLEANUP_NOT_SUPPLIED: &str = "not-supplied";

/// Closed cancellation reason-code vocabulary this surface accepts from a
/// cancellation reply.
///
/// The single member is `CANCELLATION_UNCONFIRMED` from the additive reason-code
/// registry documented in
/// `docs/architecture/I07-20-agent-facing-error-contract.md` (route/integration
/// group), which I7.20 states is a projection rather than a control enum that
/// every surface must exhaustively match. This array is therefore the set of
/// cancellation causes this route can BOUND AND NAME, not a mirror of the whole
/// registry: a cancellation carrying any other code is a typed result mismatch
/// here rather than a silently accepted cause, and no code is invented locally.
/// A future cancellation cause is added to the I7.20 document first and to this
/// array second.
pub const BACKUP_CANCELLATION_REASON_CODES: [&str; 1] = [BACKUP_REASON_CANCELLATION_UNCONFIRMED];

/// The exact I7.20 reason code a cancellation carries when the owner supplied
/// no cleanup evidence.
///
/// Mirrors the Kernel's own literal for the same cause, for the same reason
/// [`BACKUP_CREATE_MISSING_OWNER`] mirrors its refusal. It names an UNCONFIRMED
/// cleanup rather than a failed one, because no cleanup failure was observed:
/// the owner reported a cancellation and said nothing about cleanup, so
/// claiming cleanup failed would invent an observation the owner never made.
pub const BACKUP_REASON_CANCELLATION_UNCONFIRMED: &str = "CANCELLATION_UNCONFIRMED";

/// How one proof level stands to the owner's capture evidence.
///
/// A closed set of level strings is a VOCABULARY, not a proof. This is the
/// second half of the answer a level must give, and it is declared once,
/// beside the level it describes, so a level and the evidence it requires
/// cannot drift apart as two hand-maintained tables.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureEvidenceRelation {
    /// The level is a provenance claim and therefore REQUIRES the owner-issued
    /// capture receipt AND the verifier-issued validity attestation that prove
    /// it. Either one absent means the level is refused, never reported.
    RequiresOwnerEvidence,
    /// The level proves structural self-consistency only and therefore
    /// REQUIRES that the owner-issued evidence be ABSENT. A candidate that
    /// carries a receipt is claiming provenance it does not have.
    RequiresOwnerEvidenceAbsence,
}

/// The ONE typed owner of this surface's verification proof vocabulary.
///
/// There is deliberately no "undefined" member. A level with no stated relation
/// would need a fallible table, and this is the structural reason the old
/// fallible shape is gone: [`VerifyProofLevel::capture_evidence`] is total over
/// every level, so a level CANNOT be added without stating the evidence it
/// requires, and [`require_proven_claim`] matches the two relations
/// exhaustively with no arm to fall through. An unnamed relation is not a
/// relation, and the type now makes one unrepresentable rather than refusing it
/// at runtime.
///
/// It replaces the three level literals and the `BACKUP_LEVELS` string array
/// this module used to keep in parallel with the owner's
/// `CaptureEvidenceLevel` (issue #2862, I8). It is deliberately a typed owner
/// rather than a
/// re-export of that enum: the owner lives in `eliot-kernel`, a BINARY crate,
/// and a surface crate cannot import one. So this owns the wire spelling, the
/// exhaustive decoder and the capture-evidence relation, and the Kernel route
/// keeps the mirrored decoder for the same reason it already mirrors
/// [`backup_class`] — two owners of one spelling, each side refusing a drift
/// rather than assuming agreement.
///
/// Membership is not proof. Every member carries its relation in
/// [`Self::capture_evidence`], and [`require_proven_claim`] refuses a member
/// whose relation the owner's own answer does not satisfy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerifyProofLevel {
    /// The exact submitted bytes decode, validate and relate internally as
    /// one archive. This level proves structural self-consistency and nothing
    /// more: not that those bytes came from a retained capture, not that a
    /// capture owner published them, not that any class ceiling was reached,
    /// and not that the archive is restorable (I5.13: backup existence is not
    /// recovery proof). An archive carrying this level is an untrusted
    /// candidate.
    StructuralCandidate,
    /// The verified bytes are bound to a retained capture artifact and to the
    /// owner-issued publication receipt naming it. This proves capture
    /// provenance for the named archive and nothing beyond it: no key
    /// availability, no decryptability, no isolated restore success and no
    /// cutover authority (I5.13 restore steps; A13.7 requires separate
    /// authority for cutover).
    ProvenanceBound,
    /// Provenance-bound AND qualified by the owner for this archive's class
    /// and compatibility. This adds the owner's qualification to
    /// [`Self::ProvenanceBound`] and proves no Product readiness.
    ClassQualified,
}

impl VerifyProofLevel {
    /// Every level this surface admits, so the closed set is enumerated by
    /// the type rather than beside it.
    const ALL: [Self; 3] = [
        Self::StructuralCandidate,
        Self::ProvenanceBound,
        Self::ClassQualified,
    ];

    /// Stable owner/wire spelling of this level.
    ///
    /// Mirrors the owner's `CaptureEvidenceLevel::as_wire_name` for the reason
    /// [`backup_class`] mirrors the protocol class spelling: a surface crate
    /// cannot import the Kernel's binary crate, so each side states the one
    /// spelling and a drift between them is refused rather than assumed.
    const fn wire_name(self) -> &'static str {
        match self {
            Self::StructuralCandidate => "structurally-valid-candidate",
            Self::ProvenanceBound => "provenance-bound-capture",
            Self::ClassQualified => "class-qualified",
        }
    }

    /// Decodes one wire level, or `None` when the owner named a level this
    /// surface cannot bound.
    ///
    /// The decoder is derived from [`Self::ALL`] and [`Self::wire_name`], so it
    /// is exhaustive by construction: adding a level to the type adds it to the
    /// decoder, and a level with no decoder arm does not exist.
    fn from_wire(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|level| level.wire_name() == value)
    }

    /// The COMPLETE relation between this level and the owner's capture
    /// evidence, declared on the level itself.
    const fn capture_evidence(self) -> CaptureEvidenceRelation {
        match self {
            Self::StructuralCandidate => CaptureEvidenceRelation::RequiresOwnerEvidenceAbsence,
            Self::ProvenanceBound | Self::ClassQualified => {
                CaptureEvidenceRelation::RequiresOwnerEvidence
            }
        }
    }
}

/// The ONE typed owner of the class-ceiling vocabulary this surface accepts,
/// mirroring the owner's `RestoreEvidenceLevel` snake-case spelling.
///
/// The ceiling is the owner's answer about how far this archive actually
/// reaches and is never derived here from the class token: I5.13 makes
/// `full_recovery`, `canonical_only_degraded` and `scope_export` different
/// recovery claims, and only the owning receipt knows which one it proved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerifyClassCeiling {
    /// The bundle passed archive/build verification only.
    ArchiveValid,
    /// The isolated root imported bytes, purge, receipts and projections with
    /// no active authority.
    IsolatedImportComplete,
    /// Import is staged but external effects remain unresolved; operational
    /// claims and cutover are forbidden.
    ReconciliationRequired,
    /// The exact owner issued bounded validation evidence for the isolated
    /// root, outside the backup library.
    OperationallyValidated,
    /// A separate Human/System Owner authorization, outside the backup
    /// library, which never emits it.
    Cutover,
}

impl VerifyClassCeiling {
    /// Stable owner/wire spelling of this ceiling.
    const fn wire_name(self) -> &'static str {
        match self {
            Self::ArchiveValid => "archive_valid",
            Self::IsolatedImportComplete => "isolated_import_complete",
            Self::ReconciliationRequired => "reconciliation_required",
            Self::OperationallyValidated => "operationally_validated",
            Self::Cutover => "cutover",
        }
    }

    /// Decodes one wire ceiling, or `None` when the owner named a ceiling this
    /// surface cannot bound. A value is never coerced to a nearby rung.
    fn from_wire(value: &str) -> Option<Self> {
        [
            Self::ArchiveValid,
            Self::IsolatedImportComplete,
            Self::ReconciliationRequired,
            Self::OperationallyValidated,
            Self::Cutover,
        ]
        .into_iter()
        .find(|ceiling| ceiling.wire_name() == value)
    }

    /// Whether REACHING this ceiling needs authority a read-only
    /// `backup.verify` does not hold and this surface may not render.
    ///
    /// This is the boundary the owner's own `RestoreEvidenceLevel` documents
    /// and its `permits_operational_readiness` draws: the levels the backup
    /// library emits never qualify, while `operationally_validated` needs
    /// owner-issued bounded validation evidence and `cutover` a separate
    /// Human/System Owner authorization. A13.7 keeps both with the isolated
    /// restore owner, and `BackupStage::can_advance` is the protocol's own
    /// statement that a verified archive reaches `Verified` and no further rung
    /// of that ladder. A verify answer carrying one of the two rungs above
    /// `reconciliation_required` is therefore IMPOSSIBLE here, and is refused
    /// rather than rendered — an owner that over-claimed must not be able to
    /// advertise operational recovery off this path.
    const fn requires_operational_authority(self) -> bool {
        matches!(self, Self::OperationallyValidated | Self::Cutover)
    }
}

/// Closed STRUCTURAL archived-fence relation vocabulary this surface accepts
/// from a verify reply, mirroring the owner's `ArchiveFenceRelation`
/// kebab-case spelling.
///
/// A13.7 requires an archive's fence to be validated against the authority
/// history rather than demanded to equal the live fence, so the owner states
/// the exact relation between the archived fence VALUE and this target. A
/// relation outside this set is a typed result mismatch rather than a silent
/// pass, and an unknown future value is never coerced to "current" or
/// "invalid".
const BACKUP_ARCHIVE_FENCE_RELATIONS: [&str; 6] = [
    "exact-fence-value",
    "same-authority-older",
    "same-authority-newer",
    "same-authority-divergent",
    "unrelated-lineage",
    "incomparable-or-unknown",
];

/// The ONE typed owner of the archived-fence PROOF vocabulary, mirroring the
/// owner's `ArchiveFenceProof` kebab-case spelling.
///
/// This is a separate axis from the structural relation and is what stops a
/// structurally exact or same-lineage value from being printed as proven
/// installation history: without a capture-owner receipt the only honest
/// qualifier is [`Self::StructuralOnly`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArchiveFenceProof {
    /// Reports the archived fence VALUE only, with no claim about who produced
    /// it. The honest qualifier when no capture owner has vouched for the
    /// fence, which is why it is not a weaker spelling of the same fact: it
    /// declines a provenance claim instead of making one.
    StructuralOnly,
    /// Names a capture owner as the origin of the archived fence. This is a
    /// PROVENANCE claim on its own axis, so it is admitted only together with
    /// the owner-issued capture receipt that proves it — see
    /// [`require_proven_claim`]. A level or a relation printed beside it is
    /// not a substitute: neither names a capture owner.
    CaptureOwnerProven,
}

impl ArchiveFenceProof {
    /// Stable owner/wire spelling of this proof qualifier.
    const fn wire_name(self) -> &'static str {
        match self {
            Self::StructuralOnly => "structural-only",
            Self::CaptureOwnerProven => "capture-owner-proven",
        }
    }

    /// Decodes one wire proof qualifier, or `None` when the owner named a
    /// qualifier this surface cannot bound.
    fn from_wire(value: &str) -> Option<Self> {
        [Self::StructuralOnly, Self::CaptureOwnerProven]
            .into_iter()
            .find(|proof| proof.wire_name() == value)
    }

    /// Whether this qualifier is a provenance claim and therefore REQUIRES the
    /// owner-issued capture receipt that names a capture owner.
    ///
    /// The converse is deliberately NOT required — a capture receipt for the
    /// archive says nothing about who produced the archived fence VALUE, so an
    /// honest `structural-only` qualifier beside a receipt stays admissible and
    /// refusing it would forbid a truthful future answer.
    const fn requires_capture_receipt(self) -> bool {
        matches!(self, Self::CaptureOwnerProven)
    }
}

/// The capture owner a create refusal names while the capture owner cannot be
/// reached.
///
/// A create is refused with `plan_gap` while the capture owner's capture entry
/// is unreachable, and the Kernel's create route writes that owner into the
/// refusal verbatim. This constant mirrors that literal so the create reply's
/// one domain identity is checkable instead of merely readable: a refusal
/// naming any other owner is a domain-identity mismatch, not this operation's
/// answer.
///
/// The two literals are separate owners of the same spelling, not a shared
/// contract: the Kernel route states it in its refusal and this surface
/// states it here. When the capture owner lands and the create reply becomes a
/// real capture answer, both sides must change together; until then a drift
/// between them is refused here rather than silently accepted. This surface
/// must not mint an owner, a receipt or a class to keep the check passing.
pub const BACKUP_CREATE_MISSING_OWNER: &str = "backup-capture-owner (#959)";

/// Failure of one thin backup delegation: transport problems stay
/// transport errors (with their operation identity for same-operation
/// reconciliation); client-side problems reuse the catalogue [`CliError`].
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BackupClientError {
    /// Authenticated transport failed or returned an unknown outcome.
    #[error("backup transport failure: {0}")]
    Transport(KernelClientError),
    /// Catalogue client validation failed.
    #[error("backup client failure: {0}")]
    Client(CliError),
}

fn non_blank(value: &str, field: &'static str) -> Result<(), CliError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CliError::InvalidArgument { field });
    }
    if value.len() > BACKUP_TEXT_MAX {
        return Err(CliError::InvalidArgument { field });
    }
    Ok(())
}

fn hex_bytes(value: &str, field: &'static str, max_bytes: usize) -> Result<(), CliError> {
    if value.len() > max_bytes.saturating_mul(2) {
        return Err(CliError::InvalidArgument { field });
    }
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CliError::InvalidArgument { field });
    }
    Ok(())
}

/// Requires a lowercase 64-character hex digest.
///
/// The predicate is exactly the private `lowercase_sha256` predicate of
/// `crates/foundation/eliot-protocol/src/backup.rs:220`; `eliot_protocol`
/// exposes no public digest validator, so the identical expression is
/// reused instead of inventing a second digest rule here.
fn hex64(value: &str, field: &'static str) -> Result<(), CliError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CliError::InvalidArgument { field });
    }
    Ok(())
}

/// Decodes the operator class token into the closed protocol class
/// vocabulary.
///
/// [`BackupClassWire`] is the only class set this surface admits; an
/// unknown token decodes to `None` and refuses instead of falling back to
/// a default class. I5.13 fixes the operator/wire tokens as
/// `full_recovery`, `canonical_only_degraded`, and `scope_export` while the
/// protocol enum's serde spelling is `SCREAMING_SNAKE_CASE`, so the two
/// spellings are bound in this one decoder and nowhere else.
///
/// [`BackupClassWire::validate_transition`] is deliberately not applied to
/// the requested class: a request carries a declared class only, and the
/// evidenced class belongs to the owning capture or verification receipt.
/// Binding an evidenced value to a request would fabricate a receipt.
fn backup_class(token: &str) -> Option<BackupClassWire> {
    match token {
        "full_recovery" => Some(BackupClassWire::FullRecovery),
        "canonical_only_degraded" => Some(BackupClassWire::CanonicalOnlyDegraded),
        "scope_export" => Some(BackupClassWire::ScopeExport),
        _ => None,
    }
}

/// Typed backup create arguments: explicit scope descriptor plus the
/// closed class vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupCreateParams {
    /// Capture scope descriptor (required, bounded, never defaulted).
    pub scope_descriptor: String,
    /// Archive class exactly as the operator typed it; already admitted
    /// against the closed protocol class vocabulary.
    pub class: String,
}

/// Typed backup verify arguments: explicit archive bytes (bounded hex).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupVerifyParams {
    /// Archive bytes as lowercase hex (bounded by [`BACKUP_WIRE_BYTES_MAX`]).
    pub bundle_hex: String,
}

/// Typed isolated restore-test arguments: explicit archive, explicit
/// authorization, explicit target, explicit provisioning attestations,
/// explicit console-presented introductions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupRestoreTestParams {
    /// Archive bytes as lowercase hex (bounded by [`BACKUP_WIRE_BYTES_MAX`]).
    pub bundle_hex: String,
    /// Host-issued destination authorization bytes as lowercase hex
    /// (bounded by [`BACKUP_AUTH_BYTES_MAX`]).
    pub authorization_hex: String,
    /// Isolated-restore target identity (required, never defaulted).
    pub target_id: String,
    /// Target authority lineage UUID text.
    pub target_lineage: String,
    /// Target authority sequence, nonzero.
    pub target_sequence: u64,
    /// Target resource generation, nonzero.
    pub target_generation: u64,
    /// Provisioned isolated destination store identity.
    pub dest_store_id: String,
    /// Capture residency denominator digest.
    pub residency_denominator_digest: String,
    /// Source snapshot digest the restore replays.
    pub source_snapshot_digest: String,
    /// Capture operation that produced the source snapshot.
    pub capture_operation_id: String,
    /// Console-presented capability introductions as owner-shaped JSON
    /// objects (explicit array, may be explicitly empty; typed decode and
    /// exact-set verification run Kernel-side against live owner readback).
    pub introductions: Vec<Value>,
}

/// Parses bounded backup create arguments. No defaults: a missing scope
/// or class refuses instead of selecting production scope silently.
pub fn parse_backup_create(
    scope_descriptor: &str,
    class: &str,
) -> Result<BackupCreateParams, CliError> {
    non_blank(scope_descriptor, "backup.scope_descriptor")?;
    if backup_class(class).is_none() {
        return Err(CliError::InvalidArgument {
            field: "backup.class",
        });
    }
    Ok(BackupCreateParams {
        scope_descriptor: scope_descriptor.to_owned(),
        class: class.to_owned(),
    })
}

/// Parses bounded backup verify arguments.
pub fn parse_backup_verify(bundle_hex: &str) -> Result<BackupVerifyParams, CliError> {
    hex_bytes(bundle_hex, "backup.bundle_hex", BACKUP_WIRE_BYTES_MAX)?;
    if bundle_hex.is_empty() {
        return Err(CliError::InvalidArgument {
            field: "backup.bundle_hex",
        });
    }
    Ok(BackupVerifyParams {
        bundle_hex: bundle_hex.to_owned(),
    })
}

/// Parses bounded restore-test arguments. Every binding is explicit:
/// empty archive, authorization, target, or provisioning refuses, and
/// the console-presented introductions arrive as an explicit JSON array
/// (explicitly empty allowed — never absent, never defaulted). The
/// destination must also be provably distinct from the restore target at
/// shape level; a destination equal to the target is not isolated.
#[allow(
    clippy::too_many_arguments,
    reason = "restore-test carries eleven independently validated bindings; grouping them would hide which exact field refused"
)]
pub fn parse_backup_restore_test(
    bundle_hex: &str,
    authorization_hex: &str,
    target_id: &str,
    target_lineage: &str,
    target_sequence: u64,
    target_generation: u64,
    dest_store_id: &str,
    residency_denominator_digest: &str,
    source_snapshot_digest: &str,
    capture_operation_id: &str,
    introductions: &[Value],
) -> Result<BackupRestoreTestParams, CliError> {
    parse_backup_verify(bundle_hex)?;
    hex_bytes(
        authorization_hex,
        "backup.destination_authorization_hex",
        BACKUP_AUTH_BYTES_MAX,
    )?;
    if authorization_hex.is_empty() {
        return Err(CliError::InvalidArgument {
            field: "backup.destination_authorization_hex",
        });
    }
    non_blank(target_id, "backup.target_id")?;
    EpochLineageId::new(target_lineage).map_err(|_| CliError::InvalidArgument {
        field: "backup.target_lineage",
    })?;
    if target_sequence == 0 {
        return Err(CliError::InvalidArgument {
            field: "backup.target_sequence",
        });
    }
    if target_generation == 0 {
        return Err(CliError::InvalidArgument {
            field: "backup.target_generation",
        });
    }
    non_blank(dest_store_id, "backup.dest_store_id")?;
    hex64(
        residency_denominator_digest,
        "backup.residency_denominator_digest",
    )?;
    hex64(source_snapshot_digest, "backup.source_snapshot_digest")?;
    non_blank(capture_operation_id, "backup.capture_operation_id")?;
    if introductions.len() > BACKUP_INTRODUCTIONS_MAX {
        return Err(CliError::InvalidArgument {
            field: "backup.introductions",
        });
    }
    for entry in introductions {
        if !entry.is_object() {
            return Err(CliError::InvalidArgument {
                field: "backup.introductions",
            });
        }
    }
    if target_id == dest_store_id {
        return Err(CliError::InvalidArgument {
            field: "restore.isolation",
        });
    }
    Ok(BackupRestoreTestParams {
        bundle_hex: bundle_hex.to_owned(),
        authorization_hex: authorization_hex.to_owned(),
        target_id: target_id.to_owned(),
        target_lineage: target_lineage.to_owned(),
        target_sequence,
        target_generation,
        dest_store_id: dest_store_id.to_owned(),
        residency_denominator_digest: residency_denominator_digest.to_owned(),
        source_snapshot_digest: source_snapshot_digest.to_owned(),
        capture_operation_id: capture_operation_id.to_owned(),
        introductions: introductions.to_vec(),
    })
}

/// The NESTED typed references that bind one public result to the request it
/// answers (issue #2862 instruction 9).
///
/// An outer idempotency echo is a transport correlation, not a result
/// identity: the envelope `idempotency_key` only says which frame this answer
/// came back on, and it is the SAME value on a replay, on a reconciliation of a
/// predecessor's row, and on a substituted answer. So a result that carried
/// nothing else could not tell those three apart.
///
/// These are the references that can: the operation that PRODUCED the answer
/// (which is the caller's own key on every non-reconciliation path and the
/// PREDECESSOR's key on a reconciliation, and this surface refuses any other
/// value), the canonical digest of the request bytes that produced it, the
/// durable-row namespace it was read from, the owner-proved digest of the
/// archive itself, the owner-issued capture receipt, and the verifier-issued
/// archive validity attestation.
///
/// They are typed references, not a human string, and they are echoed into
/// [`BackupOperationOutcome`] rather than rendered as prose: a reader of the
/// outcome can compare each reference itself, and this surface compares them
/// against the request in [`require_result_identity`] before any of them is
/// reported.
///
/// `validity_attestation` is `None` on every answer a verify owner produces
/// today, because no `BackupRole::Verifier` session issues one on this product.
/// That absence is the owner's own answer and is never a placeholder, and it is
/// exactly why [`VerifyProofLevel::ProvenanceBound`] and
/// [`VerifyProofLevel::ClassQualified`] are refused here: a recognized level
/// with missing owner evidence is not a weaker proof, it is an unbacked claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupResultIdentity {
    /// Operation that PRODUCED this answer, as the owner reported it, checked
    /// against this caller's own request identity by
    /// [`require_result_identity`]. Never taken from the envelope echo, which
    /// is a different fact.
    pub operation_id: String,
    /// Canonical digest of the exact request bytes this operation was admitted
    /// with, in the owner's 64-hex digest spelling. It is carried and
    /// shape-checked here and is NOT recomputed: re-deriving it over what this
    /// surface holds would replace the owner's identity proof with a fresh
    /// local value instead of checking the one the owner recorded.
    pub request_digest: String,
    /// 64-hex namespace digest of the durable row this answer was read from —
    /// the row key, not the caller's text. It is what keeps two principals'
    /// rows apart when they share a human operation key, so an answer that
    /// carries a namespace this caller cannot place is refused rather than
    /// reported as its own.
    pub operation_namespace: String,
    /// Owner-proved digest of the complete encoded archive, in the owner's own
    /// 64-hex spelling. Carried and shape-checked; deliberately not recomputed
    /// over the request's bytes, for the same reason as `request_digest`.
    pub archive_digest: String,
    /// Owner-issued publication receipt identity naming the retained capture
    /// artifact, or `null` when the owner issued none. Absence stays explicit
    /// and is never defaulted or inferred from the archive.
    pub capture_receipt: Option<String>,
    /// Verifier-issued archive validity attestation reference backing the
    /// reported proof level, or `null` when no verifier issued one. Never a
    /// synthesized attestation and never a stand-in for the capture receipt:
    /// the two are different owner facts and either one alone does not prove a
    /// provenance-bound claim.
    pub validity_attestation: Option<String>,
}

/// Closed typed result of one backup operation, and the single source of
/// both projections this surface renders.
///
/// Every field is bounded and owner-named: the routed operation, the
/// bounded outcome state, the requested class and the declared
/// source/destination identities exactly as the request carried them, the
/// stable operation identity, the effect class and proof ceiling actually
/// achieved, the proven backup lifecycle level, the owner's verification
/// level, class ceiling, capture receipt and archived-fence relation (or an
/// explicit absence where the routed command proves none), the cancellation
/// reason code and the owner cleanup state a cancellation carried, the gates
/// the Kernel proved, the missing or failed obligations, and the one safe next
/// reconciliation action. Archive bytes, key material, secrets, and
/// archived user data are structurally absent: a successful transport or
/// exit is not capture or restore proof, so a refused, blocked, invalid,
/// cancelled, or unproven outcome never reports a proven level.
///
/// The bounded outcome states this type admits are exactly
/// [`BACKUP_STATE_VERIFIED`], [`BACKUP_STATE_CANDIDATE`],
/// [`BACKUP_STATE_REHEARSED`], [`BACKUP_STATE_INVALID`],
/// [`BACKUP_STATE_REFUSED`], [`BACKUP_STATE_BLOCKED`] and
/// [`BACKUP_STATE_CANCELLED`]. Any other state is a typed result mismatch rather
/// than a locally invented one.
///
/// [`BACKUP_STATE_REHEARSED`] is the only one of these that reports a RESTORE
/// owner's persisted receipt rather than a capture owner's, and it is reached
/// only when the reply carries that receipt and
/// [`require_restore_evidence`] has proved it. It is not readiness and not
/// cutover: A13.7 keeps cutover a separate authority, and the receipt's own
/// `operational_recovery_ready` and `cutover_performed` fields are checked to be
/// absent rather than assumed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupOperationOutcome {
    /// Closed operation selector that was routed.
    pub operation: String,
    /// Bounded outcome state: one of [`BACKUP_STATE_VERIFIED`],
    /// [`BACKUP_STATE_CANDIDATE`], [`BACKUP_STATE_REHEARSED`],
    /// [`BACKUP_STATE_INVALID`], [`BACKUP_STATE_REFUSED`],
    /// [`BACKUP_STATE_BLOCKED`], or [`BACKUP_STATE_CANCELLED`].
    ///
    /// `verified` is reserved for an owner-accepted
    /// [`VerifyProofLevel::ProvenanceBound`] or
    /// [`VerifyProofLevel::ClassQualified`] level, because backup existence is
    /// not recovery proof (I5.13); a
    /// structurally valid archive with no retained capture provenance is
    /// [`BACKUP_STATE_CANDIDATE`], and a capture the owner cancelled is
    /// [`BACKUP_STATE_CANCELLED`] rather than a field-shape
    /// [`BACKUP_STATE_INVALID`].
    ///
    /// [`BACKUP_STATE_REHEARSED`] is the isolated-restore one: the RESTORE
    /// owner reached the journalled coordinator and returned its own persisted
    /// receipt, decoded by [`restore_receipt_evidence`] and proved by
    /// [`require_restore_evidence`]. It reports an isolated rehearsal and
    /// nothing more — not operational readiness, not cutover, not an activated
    /// destination.
    pub state: String,
    /// Requested archive class exactly as the operator typed it, or
    /// `null` when the routed command declares no class. Never a
    /// defaulted class.
    pub requested_class: Option<String>,
    /// Capture scope descriptor the request declared, or `null` when the
    /// routed command declares none. Never a guessed or defaulted
    /// production scope.
    pub requested_scope: Option<String>,
    /// Archive identity the outcome actually proved, or `null` while no
    /// owner has attested one. Never a fabricated archive identity.
    ///
    /// On [`BACKUP_STATE_REHEARSED`] this is the RESTORE owner's own persisted
    /// receipt identity, read out of the receipt it returned — the artifact that
    /// outcome actually proved is a restore receipt, not an archive, and the
    /// value is never composed from the request.
    pub archive_id: Option<String>,
    /// Stable operation identity for same-operation reconciliation: the
    /// correlated request's idempotency key, echoed from the request and
    /// never taken from the reply body.
    pub operation_id: String,
    /// Source identity the request declared, or `null` when the routed
    /// command declares none. Never a guessed production source
    /// installation.
    pub source_identity: Option<String>,
    /// Destination identity the request declared, or `null` when the
    /// routed command declares none. Never a default production
    /// destination.
    pub destination_identity: Option<String>,
    /// Effect class the routed operation actually achieved.
    pub effect: EffectClass,
    /// Proof ceiling the routed operation is bound to.
    pub proof_ceiling: ProofCeiling,
    /// Bounded backup lifecycle level actually proven. Backup existence
    /// is not recovery proof (I5.13), so a refused, blocked, or invalid
    /// outcome never advances past [`BackupStage::Requested`].
    pub proof_level: BackupStage,
    /// Owner's verification level for the archive this outcome reports, or
    /// `null` when the routed command proves no level. The owner's own
    /// answer, echoed through the one typed owner
    /// [`VerifyProofLevel::wire_name`]: never inferred by this surface from the
    /// archive bytes, never defaulted, and never promoted above the level the
    /// owner actually named. A level whose capture-evidence relation the
    /// owner's answer does not satisfy is never reported at all — see
    /// [`require_proven_claim`].
    ///
    /// On [`BACKUP_STATE_REHEARSED`] this holds the RESTORE owner's own
    /// `evidence_level` in the RESTORE owner's own spelling, decoded through
    /// [`BACKUP_RESTORE_EVIDENCE_LEVELS`] rather than the capture vocabulary —
    /// two owners, two closed sets, one field. The two members a rehearsal may
    /// never report (`operationally_validated`, `cutover`) are refused in
    /// [`require_restore_evidence`] instead of being echoed.
    pub verification_level: Option<String>,
    /// Owner's exact class ceiling for this archive, or `null` when the
    /// routed command proves none. The owner's own answer, echoed under a
    /// closed vocabulary check: never inferred here from the requested or
    /// evidenced class token and never defaulted, so a degraded class can
    /// never be reported at an operational-recovery ceiling.
    pub class_ceiling: Option<String>,
    /// Owner-issued publication receipt naming the retained capture
    /// artifact, or `null` when the owner issued none. Absence stays
    /// explicit: the owner's own answer, echoed under a bounded check, never
    /// inferred from the archive and never defaulted, so an unproven
    /// capture cannot look like a proven one. It is the human-facing echo of
    /// the same owner fact as [`Self::result_identity`]'s
    /// `capture_receipt`, and the two always agree.
    pub capture_receipt: Option<String>,
    /// Nested typed references binding this result to the request it answers,
    /// or `null` when the routed command answered no result at all (a refusal,
    /// a cancellation, an invalid request, a blocked rehearsal, or an unproven
    /// transport outcome).
    ///
    /// This is the answer's identity, and it is what an outer idempotency echo
    /// cannot supply: the operation that produced it, the canonical request
    /// digest, the durable-row namespace, the archive digest, and the two
    /// owner-issued evidence references. A `null` is always an explicit
    /// absence and never a synthesized identity, and a result carrying one is
    /// refused rather than reported — see [`require_result_identity`].
    pub result_identity: Option<BackupResultIdentity>,
    /// STRUCTURAL archived-fence relation the owner reported for this target,
    /// or `null` when the routed command proves none. The owner's own answer,
    /// echoed under the closed [`BACKUP_ARCHIVE_FENCE_RELATIONS`] check: a
    /// historical archive stays historical instead of being reported as corrupt
    /// for an older generation, and nothing here is inferred or defaulted. It
    /// is NOT target compatibility — see [`Self::target_compatibility`].
    pub archive_fence_relation: Option<String>,
    /// PROVENANCE qualifier for [`Self::archive_fence_relation`], echoed
    /// through the one typed owner [`ArchiveFenceProof::wire_name`]. A
    /// structural relation is never printed as proven installation history
    /// without it, and a `capture-owner-proven` qualifier is never printed
    /// without the owner-issued capture receipt that names a capture owner.
    pub archive_fence_proof: Option<String>,
    /// TARGET COMPATIBILITY as the RESTORE owner stated it, or `null` when no
    /// restore owner supplied one.
    ///
    /// The verify owner never fills this in: A13.7 keeps schema/build/key/
    /// purge/import/epoch compatibility, Authority Epoch monotonicity and
    /// cutover with the isolated restore owner. It is retained as an explicit
    /// optional field so this surface can print a real compatibility verdict
    /// when one exists, instead of rendering the structural relation under a
    /// compatibility label.
    pub target_compatibility: Option<String>,
    /// Exact reason code a cancelled owner answered with, or `null` when this
    /// outcome is not [`BACKUP_STATE_CANCELLED`].
    ///
    /// This is the capture owner's own cause as the Kernel relayed it, echoed
    /// under a closed check: never inferred here from the state, never
    /// defaulted onto a generic "failed", and never renamed. `null` means the
    /// routed command reported no cancellation - an outcome that is not
    /// `cancelled` has no cancellation reason code, and absence is reported
    /// explicitly rather than filled in.
    pub cancellation_reason_code: Option<String>,
    /// Owner cleanup state a cancelled owner reported, or `null` when this
    /// outcome is not [`BACKUP_STATE_CANCELLED`].
    ///
    /// This is the owner's own cleanup answer, echoed under the closed
    /// [`BACKUP_OWNER_CLEANUP_STATES`] check, and it is retained rather than
    /// dropped so a cancellation stays distinguishable from a malformed
    /// request. It is never inferred from the reason text and never defaulted
    /// to a clean value: an owner that supplied no cleanup evidence reports
    /// [`BACKUP_OWNER_CLEANUP_NOT_SUPPLIED`], which means cleanup is
    /// UNCONFIRMED, not that the target was torn down. `null` means the routed
    /// command proved no cancellation at all. Bounded owned text: no archive
    /// bytes, no key material, no secret and no archived user data.
    pub owner_cleanup_state: Option<String>,
    /// Gates the Kernel proved AND admitted, in pass order; empty when the
    /// command proves no rehearsal gate.
    ///
    /// Every name here is a gate the execution actually ran. A gate that needed
    /// owner-held state and did not run is never listed here: it reaches the
    /// operator as a named entry in `missing_obligations` instead, so this field
    /// cannot report a gate as passed that no owner admitted.
    pub gates_passed: Vec<String>,
    /// Bounded missing or failed obligations, each naming the exact owner
    /// or field the outcome is waiting on.
    pub missing_obligations: Vec<String>,
    /// The single safe next reconciliation action for this outcome. It
    /// always names the same operation identity and never proposes a
    /// second capture or a second restore.
    pub next_reconciliation: String,
    /// Bounded reason text. Never a secret and never archived user data.
    pub reason: String,
}

/// Bounded projection of an operation whose transport outcome is unproven.
///
/// This is deliberately a different closed type from
/// [`BackupOperationOutcome`]: an unknown transport outcome carries no
/// domain result at all, so it must not be able to borrow a domain
/// verdict. The only safe next action is to reconcile the same operation
/// identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupUnknownOutcome {
    /// Closed operation selector whose outcome is unproven.
    pub operation: String,
    /// Bounded state: always [`BACKUP_STATE_UNKNOWN`].
    pub state: String,
    /// Stable operation identity to reconcile; the correlated request's
    /// idempotency key, never a freshly minted one.
    pub operation_id: String,
    /// Bounded transport detail. Never a secret.
    pub detail: String,
    /// The single safe next action: reconcile this exact operation.
    pub next_reconciliation: String,
}

/// Builds the same-operation reconciliation projection for an unproven
/// transport outcome.
///
/// A request whose reply never arrived may already have been admitted by
/// the Kernel, so the only safe next action is to reconcile the *same*
/// operation identity. This projection never proposes a second capture or
/// a second restore, and it never reports success.
pub fn backup_unknown_outcome(
    operation: &str,
    request: &RequestIdentity,
    transport_detail: &str,
) -> BackupUnknownOutcome {
    BackupUnknownOutcome {
        operation: operation.to_owned(),
        state: BACKUP_STATE_UNKNOWN.to_owned(),
        operation_id: request.idempotency_key.clone(),
        detail: transport_detail.to_owned(),
        next_reconciliation: format!(
            "reconcile the same operation {}; a second {} is never a safe next action",
            request.idempotency_key.as_str(),
            operation
        ),
    }
}

/// Renders the bounded human projection of one typed backup outcome.
///
/// Every line is derived from the same [`BackupOperationOutcome`] value the
/// JSON projection serializes, so the two projections cannot disagree. The
/// renderer is bounded by construction: it prints only the operation, the
/// outcome state, the requested class and scope, the declared
/// source/destination identities, the archive identity, the operation
/// identity, the effect class and proof ceiling, the proven lifecycle
/// level, the owner's verification level, class ceiling, capture receipt and
/// target-compatibility relation when the routed command proved them, the
/// cancellation reason code and owner cleanup state when it reported a
/// cancellation, the gates, the missing obligations, the reason, and the one
/// next reconciliation action. An owner answer that is absent prints no line at
/// all, never an empty or invented value, so silence stays distinguishable
/// from a proven answer. It never prints archive bytes, key material,
/// secrets, or archived user data.
pub fn render_backup_outcome_human(outcome: &BackupOperationOutcome) -> String {
    let mut lines = String::with_capacity(512);
    let _ = writeln!(lines, "operation: {}", outcome.operation);
    let _ = writeln!(lines, "state: {}", outcome.state);
    let _ = writeln!(
        lines,
        "requested_class: {}",
        outcome.requested_class.as_deref().unwrap_or("not-declared")
    );
    let _ = writeln!(
        lines,
        "requested_scope: {}",
        outcome.requested_scope.as_deref().unwrap_or("not-declared")
    );
    // The proved-identity line is labelled by what the outcome actually proved.
    // On a rehearsal that is the RESTORE owner's persisted receipt, not an
    // archive, and printing it under `archive_id:` would misname the artifact an
    // operator is being told to trust. The label is chosen from the state, not
    // from the field, so the two cannot drift.
    if outcome.state == BACKUP_STATE_REHEARSED {
        let _ = writeln!(
            lines,
            "restore_receipt: {}",
            outcome.archive_id.as_deref().unwrap_or("not-proven")
        );
    } else {
        let _ = writeln!(
            lines,
            "archive_id: {}",
            outcome.archive_id.as_deref().unwrap_or("not-proven")
        );
    }
    let _ = writeln!(lines, "operation_id: {}", outcome.operation_id);
    let _ = writeln!(
        lines,
        "source: {}",
        outcome.source_identity.as_deref().unwrap_or("not-declared")
    );
    let _ = writeln!(
        lines,
        "destination: {}",
        outcome
            .destination_identity
            .as_deref()
            .unwrap_or("not-declared")
    );
    let _ = writeln!(
        lines,
        "effect: {} proof_ceiling: {}",
        serde_json::to_string(&outcome.effect).unwrap_or_else(|_| "unknown".to_owned()),
        serde_json::to_string(&outcome.proof_ceiling).unwrap_or_else(|_| "unknown".to_owned())
    );
    let _ = writeln!(
        lines,
        "proof_level: {}",
        serde_json::to_string(&outcome.proof_level).unwrap_or_else(|_| "UNKNOWN".to_owned())
    );
    // The owner's evidence answers print only when the routed command proved
    // them: an absent level, ceiling, receipt or fence relation stays silent
    // rather than printing an empty or invented value.
    if let Some(level) = &outcome.verification_level {
        let _ = writeln!(lines, "verification_level: {level}");
    }
    if let Some(ceiling) = &outcome.class_ceiling {
        let _ = writeln!(lines, "class_ceiling: {ceiling}");
    }
    if let Some(receipt) = &outcome.capture_receipt {
        let _ = writeln!(lines, "capture_receipt: {receipt}");
    }
    render_result_identity(&mut lines, outcome);
    // The archived fence's relation and its proof qualifier print as what they
    // are: a relation over fence VALUES plus where those values came from. A
    // target-compatibility verdict is a restore owner's answer and is printed
    // only when that owner actually supplied one.
    if let Some(relation) = &outcome.archive_fence_relation {
        let _ = writeln!(lines, "archive_fence_relation: {relation}");
    }
    if let Some(proof) = &outcome.archive_fence_proof {
        let _ = writeln!(lines, "archive_fence_proof: {proof}");
    }
    if let Some(compatibility) = &outcome.target_compatibility {
        let _ = writeln!(lines, "target_compatibility: {compatibility}");
    }
    // The cancellation's own two answers print only when the routed command
    // reported a cancellation. An absent reason code or owner cleanup state
    // stays silent rather than printing an empty, `unknown` or invented value,
    // and the cleanup line is deliberately the owner's own `not-supplied`
    // spelling: this renderer must never restate it as a clean target.
    if let Some(reason_code) = &outcome.cancellation_reason_code {
        let _ = writeln!(lines, "cancellation_reason_code: {reason_code}");
    }
    if let Some(cleanup_state) = &outcome.owner_cleanup_state {
        let _ = writeln!(lines, "owner_cleanup_state: {cleanup_state}");
    }
    if outcome.gates_passed.is_empty() {
        let _ = writeln!(lines, "gates_passed: none");
    } else {
        let _ = writeln!(lines, "gates_passed: {}", outcome.gates_passed.join(", "));
    }
    if outcome.missing_obligations.is_empty() {
        let _ = writeln!(lines, "missing_obligations: none");
    } else {
        for obligation in &outcome.missing_obligations {
            let _ = writeln!(lines, "missing_obligation: {obligation}");
        }
    }
    let _ = writeln!(lines, "reason: {}", outcome.reason);
    let _ = writeln!(
        lines,
        "next_reconciliation: {}",
        outcome.next_reconciliation
    );
    lines
}

/// Prints the result's own nested identity, or nothing when there is none.
///
/// The identity is printed from the same typed references the JSON projection
/// serializes, and only when a routed command answered a result at all: an
/// answer that is not bound to the request it answers has no identity to print,
/// and an absent identity stays absent rather than being filled in from the
/// envelope echo. The producing operation, the canonical request digest, the
/// durable-row namespace and the archive digest are what distinguish a replayed
/// answer from a substituted one, so an operator reads them beside the proof
/// level rather than beside prose.
fn render_result_identity(lines: &mut String, outcome: &BackupOperationOutcome) {
    let Some(identity) = &outcome.result_identity else {
        return;
    };
    let _ = writeln!(lines, "answer_operation_id: {}", identity.operation_id);
    let _ = writeln!(lines, "request_digest: {}", identity.request_digest);
    let _ = writeln!(
        lines,
        "operation_namespace: {}",
        identity.operation_namespace
    );
    let _ = writeln!(lines, "answer_archive_digest: {}", identity.archive_digest);
    if let Some(attestation) = &identity.validity_attestation {
        let _ = writeln!(lines, "validity_attestation: {attestation}");
    }
}

/// Renders the bounded human projection of one unproven transport
/// outcome, from the same [`BackupUnknownOutcome`] value the JSON
/// projection serializes.
pub fn render_backup_unknown_human(outcome: &BackupUnknownOutcome) -> String {
    let mut lines = String::with_capacity(256);
    let _ = writeln!(lines, "operation: {}", outcome.operation);
    let _ = writeln!(lines, "state: {}", outcome.state);
    let _ = writeln!(lines, "operation_id: {}", outcome.operation_id);
    let _ = writeln!(lines, "reason: {}", outcome.detail);
    let _ = writeln!(
        lines,
        "next_reconciliation: {}",
        outcome.next_reconciliation
    );
    lines
}

fn require_command(request: &CommandRequest, expected: CommandId) -> Result<(), CliError> {
    if request.command != expected {
        return Err(CliError::ArgumentCommandMismatch);
    }
    request.arguments.validate()
}

fn envelope_command(response: &Value, expected_operation: &str) -> Result<(), BackupClientError> {
    let command = response
        .get("command")
        .and_then(Value::as_str)
        .ok_or(BackupClientError::Client(CliError::ResultMismatch))?;
    if command != expected_operation {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    Ok(())
}

fn envelope_idempotency(
    response: &Value,
    identity: &RequestIdentity,
) -> Result<(), BackupClientError> {
    let key = response
        .get("idempotency_key")
        .and_then(Value::as_str)
        .ok_or(BackupClientError::Client(CliError::CorrelationMismatch))?;
    if key != identity.idempotency_key.as_str() {
        return Err(BackupClientError::Client(CliError::CorrelationMismatch));
    }
    Ok(())
}

/// Closed wire status vocabulary a backup reply may carry.
///
/// `ok` is the owner's success spelling and selects no outcome state by
/// itself. [`backup_verify`] reports [`BACKUP_STATE_VERIFIED`] only after
/// the owner names the [`VerifyProofLevel::ProvenanceBound`] or
/// [`VerifyProofLevel::ClassQualified`] level, and reports a
/// [`VerifyProofLevel::StructuralCandidate`] archive as
/// [`BACKUP_STATE_CANDIDATE`] instead of promoting it, because backup
/// existence is not recovery proof (I5.13). [`BACKUP_STATE_CANCELLED`] is a
/// refusal-shaped status, not a success one, and it is admitted here so an
/// owner cancellation decodes as its own typed outcome instead of arriving as
/// a malformed field. Any other status is a typed result mismatch, never
/// success.
const BACKUP_WIRE_OK: &str = "ok";

fn envelope_status(response: &Value) -> Result<&str, BackupClientError> {
    let status = response
        .get("status")
        .and_then(Value::as_str)
        .ok_or(BackupClientError::Client(CliError::ResultMismatch))?;
    if !matches!(
        status,
        BACKUP_WIRE_OK
            | BACKUP_STATE_INVALID
            | BACKUP_STATE_REFUSED
            | BACKUP_STATE_BLOCKED
            | BACKUP_STATE_CANCELLED
    ) {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    Ok(status)
}

/// Closed reply field set one operation admits.
///
/// The Kernel builds a reply from the base envelope plus exactly the fields
/// that operation answers, so a reply carrying any other key is a reply this
/// operation's contract does not describe. Reading only the named fields would
/// drop such a key silently, and that key may be a domain receipt, class,
/// source or destination the operation never claims to answer. It may also be
/// a shape diagnostic from a different reply kind entirely, which is refused
/// for the same reason: this operation has one answer shape, and a reply of
/// another shape is not this operation's answer.
fn envelope_keys(response: &Value, allowed: &[&str]) -> Result<(), BackupClientError> {
    let Some(object) = response.as_object() else {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    };
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    Ok(())
}

fn envelope_text<'a>(
    response: &'a Value,
    field: &'static str,
) -> Result<&'a str, BackupClientError> {
    response
        .get(field)
        .and_then(Value::as_str)
        .ok_or(BackupClientError::Client(CliError::ResultMismatch))
}

fn envelope_count(response: &Value, field: &'static str) -> Result<u64, BackupClientError> {
    response
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(BackupClientError::Client(CliError::ResultMismatch))
}

/// Reads one boolean field from a reply envelope.
///
/// A missing key and a non-boolean value are both a typed result mismatch: an
/// owner answer this surface cannot read as the flag it named is not an owner
/// answer. There is no default, so a flag is either the owner's own value or
/// the reply is refused — the two readiness flags this reads
/// (`operational_recovery_ready`, `cutover_performed`) are exactly the ones that
/// must never be assumed absent.
fn envelope_flag(response: &Value, field: &'static str) -> Result<bool, BackupClientError> {
    response
        .get(field)
        .and_then(Value::as_bool)
        .ok_or(BackupClientError::Client(CliError::ResultMismatch))
}

/// Reads one optional bounded string field from a reply envelope.
///
/// I10.8.6: absence is a fact only under a complete relation, so an absent
/// key or an explicit JSON `null` decodes to `None` and is reported as an
/// explicit absence rather than a synthesized identity — an owner that issued
/// no receipt must not look like one that did. Every other JSON type is a
/// typed result mismatch instead of a coerced string.
fn envelope_optional_text<'a>(
    response: &'a Value,
    field: &'static str,
) -> Result<Option<&'a str>, BackupClientError> {
    match response.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        Some(_) => Err(BackupClientError::Client(CliError::ResultMismatch)),
    }
}

/// The route one rehearsal reply says the execution actually admitted.
///
/// Two disjoint sets read together from the owner's own answer: the gates that
/// ran, and the gates the owner did not admit. Carrying both is the point — a
/// single list cannot say which gates ran without a reader inferring it from a
/// naming convention, and a naming convention is exactly what let a deferred
/// gate be reported as a passed one.
struct ExecutedRoute<'a> {
    /// Gates the execution ran and the owner admitted, in pass order.
    passed: &'a [String],
    /// Gates the owner did not admit, reported as outstanding obligations.
    not_admitted: &'a [String],
}

/// Reads the executed route out of one rehearsal reply, as two disjoint sets.
///
/// `gates_passed` must name at least one gate (a rehearsal that proved nothing
/// is not a rehearsal) and `gates_not_admitted` may be empty, but the two must
/// NOT overlap. That overlap check is the whole point of reading them together:
/// before this split, the two owner-held gates were emitted inside
/// `gates_passed` with a `-deferred` suffix, so the projection reported eight
/// "passed" gates of which two had provably not run, and a reader had no way to
/// tell a passed gate from a deferred one without parsing a suffix. A reply that
/// now lists one gate in both sets is exactly that contradiction reappearing, and
/// it is refused rather than rendered.
///
/// The returned pair is the route the EXECUTION admitted, read from the owner's
/// own answer. Neither set is checked against a list this surface holds, because
/// a gate list validated against a copy of the producer's own list proves
/// nothing about what ran; the only structural property asserted is the one the
/// producer can contradict, which is that a gate did not both run and not run.
fn envelope_executed_route(
    response: &Value,
) -> Result<(Vec<String>, Vec<String>), BackupClientError> {
    let passed = envelope_gate_list(response, "gates_passed")?;
    if passed.is_empty() {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    let not_admitted = envelope_gate_list(response, "gates_not_admitted")?;
    if passed.iter().any(|gate| not_admitted.contains(gate)) {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    Ok((passed, not_admitted))
}

/// Reads one bounded string array from a reply envelope.
///
/// Used for both gate lists and the owner's applied phase log: both are the
/// owner's own ordered list of what it did, both are read rather than
/// reconstructed, and both reject a non-string member rather than coercing one.
fn envelope_gate_list(
    response: &Value,
    field: &'static str,
) -> Result<Vec<String>, BackupClientError> {
    let gates = response
        .get(field)
        .and_then(Value::as_array)
        .ok_or(BackupClientError::Client(CliError::ResultMismatch))?;
    gates
        .iter()
        .map(|gate| {
            gate.as_str()
                .map(str::to_owned)
                .ok_or(BackupClientError::Client(CliError::ResultMismatch))
        })
        .collect()
}

/// The closed effect class and proof ceiling the catalogue advertises for one
/// routed backup command.
///
/// The three backup `CommandSpec` rows in `lib.rs` are the single source for
/// both values. This reads them through the same
/// `CommandCatalogue::find` lookup `CommandResponse::validate_for` uses, so a
/// catalogue edit that reclassifies a backup command changes what this surface
/// reports instead of silently diverging from it, and this module carries no
/// second effect-class or proof-ceiling literal for any backup command. A
/// command with no row is an unknown command, exactly as in the dispatch path.
fn catalogued_ceiling(
    command: CommandId,
) -> Result<(EffectClass, ProofCeiling), BackupClientError> {
    let spec = CommandCatalogue::current()
        .find(command)
        .map_err(BackupClientError::Client)?;
    Ok((spec.effect, spec.proof_ceiling))
}

fn respond(
    request: &CommandRequest,
    command: CommandId,
    outcome: &BackupOperationOutcome,
) -> Result<CommandResponse, BackupClientError> {
    if outcome.operation_id != request.request.idempotency_key.as_str() {
        return Err(BackupClientError::Client(CliError::CorrelationMismatch));
    }
    let response = CommandResponse {
        request: request.request.clone(),
        command,
        effect: outcome.effect,
        proof_ceiling: outcome.proof_ceiling,
        result: CommandResult::Forwarded {
            payload: serde_json::to_value(outcome)
                .map_err(|_| BackupClientError::Client(CliError::ResultMismatch))?,
        },
    };
    // `eliot backup` reaches the Kernel through its own front door and never
    // through `CommandCatalogue::dispatch`, so the closed effect-class and
    // proof-ceiling parity check that binds a catalogue row to its response is
    // run here rather than assumed. The two values were read from that same
    // row, so an honest catalogue stays consistent and an edited one refuses
    // instead of reporting a classification no row states.
    response
        .validate_for(CommandCatalogue::current(), request)
        .map_err(BackupClientError::Client)?;
    Ok(response)
}

/// The one safe next action for a given outcome.
///
/// A refused CREATE is separated out before the state match, and the reason is
/// effect ordering (I14.21), not wording. The create route's refusal is
/// pre-effect by construction: nothing was published, nothing was mutated, and
/// the reply answers with the caller's own operation identity, so there is NO
/// effect whose outcome could be uncertain and therefore nothing to reconcile.
/// Telling an operator to "reconcile the same operation" here would report an
/// effect that provably never happened, and would make them look for a
/// half-finished archive that was never started. The honest next action is that
/// the operation may be re-run once the named owner exists — the same operation
/// identity, not a second capture of a different scope.
///
/// Every other state keeps the existing shared wording, so verify and
/// restore-test are unchanged.
fn next_action(state: &str, operation: &str, operation_id: &str) -> String {
    if state == BACKUP_STATE_REFUSED && operation == BACKUP_CREATE_OPERATION {
        return format!(
            "no capture was started for operation {operation_id}, so there is nothing to reconcile; the refusal names the absent capture-owner behaviour, and the same operation may be re-run only after that owner exists"
        );
    }
    match state {
        BACKUP_STATE_INVALID => format!(
            "correct the refused field and resubmit operation {operation_id} once; no {operation} was started"
        ),
        BACKUP_STATE_VERIFIED => format!(
            "operation {operation_id} verified; backup existence is not recovery proof, so rehearse the isolated restore before treating it as a recovery point"
        ),
        BACKUP_STATE_CANDIDATE => format!(
            "operation {operation_id} reported a structurally valid but unproven archive candidate; an owner must bind those bytes to a retained capture receipt and a class ceiling before any recovery claim, and neither a second {operation} nor a restore is a safe next action"
        ),
        // A completed rehearsal is not a recovery point and not a cutover, so
        // the next action is the one that is true of it: read the owner's own
        // receipt, and treat the destination as still unactivated. A second
        // rehearsal is never proposed, because a rehearsal is idempotent on its
        // own operation identity and re-running it under a fresh key would
        // discard the receipt this one produced.
        BACKUP_STATE_REHEARSED => format!(
            "read the restore owner's receipt for operation {operation_id}; the rehearsal imported into an isolated destination and activated nothing, so cutover remains a separately authorized operation and a second {operation} under a fresh identity is never a safe next action"
        ),
        _ => format!(
            "reconcile the same operation {operation_id} after the named owner lands; a second {operation} is never a safe next action"
        ),
    }
}

/// Extracts the closed typed create arguments from the routed request.
fn create_params(request: &CommandRequest) -> Result<BackupCreateParams, BackupClientError> {
    let CommandArguments::BackupCreate {
        scope_descriptor,
        class,
    } = &request.arguments
    else {
        return Err(BackupClientError::Client(CliError::ArgumentCommandMismatch));
    };
    parse_backup_create(scope_descriptor, class).map_err(BackupClientError::Client)
}

/// Extracts the closed typed verify arguments from the routed request.
fn verify_params(request: &CommandRequest) -> Result<BackupVerifyParams, BackupClientError> {
    let CommandArguments::BackupVerify { bundle_hex } = &request.arguments else {
        return Err(BackupClientError::Client(CliError::ArgumentCommandMismatch));
    };
    parse_backup_verify(bundle_hex).map_err(BackupClientError::Client)
}

/// Extracts the closed typed restore-test arguments from the routed request.
fn restore_test_params(
    request: &CommandRequest,
) -> Result<BackupRestoreTestParams, BackupClientError> {
    let CommandArguments::BackupRestoreTest {
        bundle_hex,
        destination_authorization_hex,
        target_id,
        target_lineage,
        target_sequence,
        target_generation,
        dest_store_id,
        residency_denominator_digest,
        source_snapshot_digest,
        capture_operation_id,
        introductions,
    } = &request.arguments
    else {
        return Err(BackupClientError::Client(CliError::ArgumentCommandMismatch));
    };
    parse_backup_restore_test(
        bundle_hex,
        destination_authorization_hex,
        target_id,
        target_lineage,
        *target_sequence,
        *target_generation,
        dest_store_id,
        residency_denominator_digest,
        source_snapshot_digest,
        capture_operation_id,
        introductions,
    )
    .map_err(BackupClientError::Client)
}

/// Routes one backup create command through the correlated Kernel front
/// door.
///
/// Create requests an archive capture, so its effect class is the
/// catalogue's reversible-mutation request bound at the candidate-artifact
/// ceiling — never a read. The reply is GRADED by its own closed `status`, and
/// every arm decodes the answer the owner actually produced rather than reading
/// its own arguments back:
///
/// - `ok` is the capture owner's own answer. It is decoded through the SAME
///   decoder the verify path uses ([`verify_evidence`]), because it is the same
///   owner's `CaptureReport` projected by the same route helper — not a second
///   vocabulary — and it is proved by [`require_capture_publication_claim`]
///   before anything is reported;
/// - `refused` keeps the legacy closed refusal decoding byte-for-byte: the
///   `plan_gap` code and the pinned [`BACKUP_CREATE_MISSING_OWNER`] literal, so
///   compatibility does not depend on accepting an arbitrary extra field or an
///   arbitrary status string;
/// - `invalid` and `cancelled` project the owner's own typed reason, and a
///   cancellation keeps the owner's cleanup state instead of being flattened into
///   a field-shape failure.
///
/// # WHAT THIS PROJECTION MAY AND MAY NOT REPORT
///
/// A refusal carries `code`, `missing_owner` and `reason` only, and this surface
/// reports exactly that much. `archive_id`, `verification_level`,
/// `class_ceiling`, `capture_receipt`, `archive_fence_relation`,
/// `archive_fence_proof`, `target_compatibility`, `cancellation_reason_code`,
/// `owner_cleanup_state` and `result_identity` all stay `None` on that arm,
/// because no owner issued any of them. That is the whole point of the refusal
/// projection: a handler that read its own arguments back and reported success
/// would have validated the REQUEST, not the ARCHIVE, and putting a descriptor
/// into any of those fields is exactly the substitution this path refuses to
/// make.
///
/// On the `ok` arm those fields are the OWNER's answers, read out of the owner's
/// own report and never composed from the request: `requested_class` and
/// `requested_scope` stay the operator's own declaration even after
/// [`apply_verify_evidence`] projects the owner's evidenced class, because the
/// two are different facts.
///
/// `missing_obligations` on the refusal arm carries the owner the refusal names
/// AND the reason the route gave for naming it, so an operator reads WHICH
/// behaviour is absent rather than only which issue owns it. The proven level
/// never leaves [`BackupStage::Requested`] on any arm that no owner acted on: an
/// admitted-shape request that no owner published for has proved nothing about an
/// archive.
pub fn backup_create(
    client: &mut KernelClient,
    request: &CommandRequest,
) -> Result<CommandResponse, BackupClientError> {
    require_command(request, CommandId::BackupCreate).map_err(BackupClientError::Client)?;
    let params = create_params(request)?;
    let operation_id = request.request.idempotency_key.clone();
    // Create requests an archive capture, so the classification this operation
    // may reach is the catalogue's own reversible-mutation row at the
    // candidate-artifact ceiling — never a read, and never a second literal.
    let (effect, proof_ceiling) = catalogued_ceiling(CommandId::BackupCreate)?;
    client.set_request_identity(request.request.clone());
    // `transact_json` already sets `operation` as the envelope's routing
    // selector, so the body carries command fields only. Repeating the
    // selector inside the body would be a second routing selector the route
    // would then have to reconcile.
    let payload = json!({
        "scope_descriptor": params.scope_descriptor.as_str(),
        "class": params.class.as_str(),
    });
    let response = client
        .transact_json(BACKUP_CREATE_OPERATION, payload)
        .map_err(BackupClientError::Transport)?;
    envelope_command(&response, BACKUP_CREATE_OPERATION)?;
    envelope_idempotency(&response, &request.request)?;
    let wire_status = envelope_status(&response)?;
    // `ok` is the only status whose answer is a domain verdict, so it decides the
    // state itself and every other status keeps its own spelling. Nothing is
    // rendered before the arm below has decoded and proved what it needs.
    let state = match wire_status {
        BACKUP_WIRE_OK => BACKUP_STATE_UNKNOWN,
        other => other,
    };
    let mut outcome = undecided_create_outcome(&params, state, &operation_id, effect, proof_ceiling);
    match wire_status {
        BACKUP_WIRE_OK => {
            return apply_captured_archive(request, &response, outcome, &operation_id, &params);
        }
        BACKUP_STATE_REFUSED => {
            // A create refusal answers with the base envelope plus `code`,
            // `missing_owner` and `reason` and nothing else. Any other key is a
            // domain identity the create owner does not send, and a reply that
            // carries one must not project as this operation's own typed outcome.
            // This closed set is the LEGACY refusal decoding and it is unchanged:
            // compatibility is not bought with an arbitrary extra field or an
            // arbitrary status string.
            envelope_keys(
                &response,
                &[
                    "command",
                    "status",
                    "idempotency_key",
                    "code",
                    "missing_owner",
                    "reason",
                ],
            )?;
            if envelope_text(&response, "code")? != "plan_gap" {
                return Err(BackupClientError::Client(CliError::ResultMismatch));
            }
            // `missing_owner` is the one domain identity a create refusal actually
            // carries, so its value is the one domain check this path can make. A
            // refusal naming any other owner is a mismatch, not this operation's
            // answer; it is refused instead of being reported as a missing capture.
            let missing_owner = envelope_text(&response, "missing_owner")?.to_owned();
            if missing_owner != BACKUP_CREATE_MISSING_OWNER {
                return Err(BackupClientError::Client(CliError::ResultMismatch));
            }
            envelope_text(&response, "reason")?.clone_into(&mut outcome.reason);
            // Both the owner and the route's own reason for naming it. The owner
            // alone is a bare issue number; the reason is what tells an operator
            // which behaviour has to exist, and the refusal reason is bounded
            // owner-route text echoed verbatim, never prose invented here.
            outcome.missing_obligations = vec![missing_owner, outcome.reason.clone()];
        }
        BACKUP_STATE_INVALID => {
            envelope_text(&response, "reason")?.clone_into(&mut outcome.reason);
            outcome.missing_obligations = vec![format!("invalid field: {}", outcome.reason)];
        }
        BACKUP_STATE_CANCELLED => {
            // A cancellation is the owner's own answer, not a malformed field, so
            // it is decoded through the module's shared cancellation contract and
            // never flattened into the `invalid` arm above, which would report a
            // caller mistake and drop the owner's cleanup state. The next action
            // comes from the shared `next_action`, which keeps this refusal's
            // pre-effect reconciliation wording honest for CREATE.
            apply_cancellation(&mut outcome, &response, &operation_id)?;
        }
        // `envelope_status` refused every status outside the closed set above, so
        // this is the standing guard for a status added to that vocabulary without
        // a projection: an answer with no stated relation to this operation is not
        // an answer this surface may report.
        _ => return Err(BackupClientError::Client(CliError::ResultMismatch)),
    }
    respond(request, CommandId::BackupCreate, &outcome)
}

/// Builds the UNDECIDED create outcome, before any owner answer is projected.
///
/// Every owner-answer field starts absent, and that is the point: the reply has
/// been graded but nothing in it has been proved, so a field an arm does not
/// explicitly fill stays an explicit absence rather than an invented value.
/// `requested_class` and `requested_scope` are the ONE exception and they are
/// the request's own declaration, never an owner's answer — which is why the
/// `ok` arm restores them after [`apply_verify_evidence`] projects the owner's
/// evidenced class into the same field.
fn undecided_create_outcome(
    params: &BackupCreateParams,
    state: &str,
    operation_id: &str,
    effect: EffectClass,
    proof_ceiling: ProofCeiling,
) -> BackupOperationOutcome {
    BackupOperationOutcome {
        operation: BACKUP_CREATE_OPERATION.to_owned(),
        state: state.to_owned(),
        requested_class: Some(params.class.clone()),
        requested_scope: Some(params.scope_descriptor.clone()),
        archive_id: None,
        operation_id: operation_id.to_owned(),
        // The create payload carries no source or destination installation
        // identity, and the surface never guesses one: only the declared scope
        // above is reported.
        source_identity: None,
        destination_identity: None,
        effect,
        proof_ceiling,
        // Nothing has been proved yet. The `ok` arm advances this only through
        // the owner's own typed evidence level.
        proof_level: BackupStage::Requested,
        verification_level: None,
        class_ceiling: None,
        capture_receipt: None,
        result_identity: None,
        archive_fence_relation: None,
        archive_fence_proof: None,
        target_compatibility: None,
        // A refusal is not a cancellation: only the `cancelled` arm fills these
        // two, from the owner's own closed-checked answers.
        cancellation_reason_code: None,
        owner_cleanup_state: None,
        gates_passed: Vec::new(),
        missing_obligations: Vec::new(),
        next_reconciliation: next_action(state, BACKUP_CREATE_OPERATION, operation_id),
        reason: String::new(),
    }
}

/// Reports one `ok` create answer as the capture owner's own published result,
/// or refuses it.
///
/// This is the whole `ok` arm of [`backup_create`], and its order is the
/// guarantee:
///
/// 1. DECODE the owner's report through [`verify_evidence`] — the SAME decoder
///    the verify path uses, because both commands receive the same owner's
///    `CaptureReport` projected by the same route helper, so there is one closed
///    vocabulary for one owner answer and not one per command. A reply with no
///    decodable owner report is a typed result mismatch.
/// 2. PROVE the relation that distinguishes a PUBLISHED capture from a decoded
///    one ([`require_capture_publication_claim`]): the owner-issued publication
///    receipt is exactly what the owner's own evidence level says, present for a
///    level that claims provenance and absent for one that does not. A level
///    this surface cannot relate, or a class ceiling needing authority a capture
///    does not hold, is refused.
/// 3. PROJECT the owner's own answers ([`apply_verify_evidence`] and
///    [`apply_verified_level`]), and restore the request's own declared class and
///    scope, which are a different fact from the owner's evidenced class.
///
/// Step 3 happens after step 2 precisely so the state can never be reached by an
/// owner answer that did not clear the relation checks, and the outcome never
/// claims anything beyond the archive: backup existence is not recovery proof,
/// and cutover is a separate authority no capture performs.
fn apply_captured_archive(
    request: &CommandRequest,
    response: &Value,
    mut outcome: BackupOperationOutcome,
    operation_id: &str,
    params: &BackupCreateParams,
) -> Result<CommandResponse, BackupClientError> {
    let evidence = verify_evidence(response)?;
    if let Err(unproven) = require_capture_publication_claim(&evidence) {
        return refuse_unproven_claim(
            request,
            operation_id,
            CommandId::BackupCreate,
            outcome,
            unproven,
        );
    }
    apply_verify_evidence(&mut outcome, &evidence);
    apply_verified_level(&mut outcome, &evidence);
    // `apply_verify_evidence` projects the owner's EVIDENCED class into
    // `requested_class`, which is right for verify — where the request declares
    // no class — and wrong here. On create the operator's declared class and the
    // owner's evidenced class are two different facts, and the declared one is
    // what this field is documented to carry, so it is written back rather than
    // overwritten. The owner's evidenced class stays reported, in its own field,
    // through `class_ceiling` and `verification_level`.
    outcome.requested_class = Some(params.class.clone());
    outcome.requested_scope = Some(params.scope_descriptor.clone());
    outcome.next_reconciliation =
        next_action(&outcome.state, BACKUP_CREATE_OPERATION, operation_id);
    respond(request, CommandId::BackupCreate, &outcome)
}

/// Requires the capture owner's evidence level to be exactly what its own
/// publication receipt supports.
///
/// The relation is the owner's, read from the typed owner rather than from a
/// string arm beside it, and it is NOT the verify path's relation:
/// [`require_proven_claim`] demands the verifier-issued validity attestation as
/// well, because a read-only verification reaches the archive through a
/// `BackupRole::Verifier` session and no such owner issues one on this product.
/// A CAPTURE is the other contour: the capture owner publishes exactly once
/// through its own `PublicationPort` and issues the receipt itself, which is
/// what `CaptureReport::receipt_identity` records ("Publication receipt
/// identity, or the suspended-operations marker") and what
/// `CaptureEvidenceLevel::ProvenanceBoundCapture` names — "Bound to a retained
/// capture artifact handle plus its owner-issued publication receipt". So the
/// evidence a provenance-claiming level requires HERE is the publication receipt,
/// and demanding a verifier attestation no capture performs would refuse every
/// honest capture answer.
///
/// The class ceiling's reachability is the same relation the verify path applies,
/// through the same typed member: A13.7 requires separate authority for cutover
/// and keeps operational validation with the isolated restore owner, so a capture
/// answer naming either is IMPOSSIBLE and is refused rather than rendered.
fn require_capture_publication_claim(
    evidence: &VerifyEvidence<'_>,
) -> Result<(), UnprovenClaim> {
    // The archived fence's PROOF axis is a provenance claim about who produced
    // the fence value, so it is held to the same rule as the level that carries
    // one: naming a capture owner requires the owner-issued receipt that proves
    // that name. The converse is not required — a receipt for the archive says
    // nothing about who produced the archived fence VALUE.
    if evidence.archive_fence_proof.requires_capture_receipt() && evidence.capture_receipt.is_none()
    {
        return Err(UnprovenClaim {
            obligation: format!(
                "owner-issued capture receipt backing archive_fence_proof {} for archive {} (absent from the owner's own answer)",
                evidence.archive_fence_proof.wire_name(),
                evidence.bundle_id
            ),
            reason: format!(
                "owner claimed archive fence proof {} for archive {} with no capture receipt; a capture-owner-proven fence is a provenance claim about who produced the archived fence, and this surface reports none that no owner receipt backs",
                evidence.archive_fence_proof.wire_name(),
                evidence.bundle_id
            ),
        });
    }
    let present = evidence.capture_receipt.is_some();
    let refused = match evidence.level.capture_evidence() {
        CaptureEvidenceRelation::RequiresOwnerEvidence => !present,
        CaptureEvidenceRelation::RequiresOwnerEvidenceAbsence => present,
    };
    if refused {
        return Err(UnprovenClaim {
            obligation: format!(
                "an owner-issued publication receipt that {} the owner's claimed verification level {} for archive {}",
                match evidence.level.capture_evidence() {
                    CaptureEvidenceRelation::RequiresOwnerEvidence => "matches",
                    CaptureEvidenceRelation::RequiresOwnerEvidenceAbsence => {
                        "is absent from, as"
                    }
                },
                evidence.level.wire_name(),
                evidence.bundle_id
            ),
            reason: format!(
                "owner answered archive {} at verification level {} with capture_receipt {}; the capture owner publishes exactly once through its own publication port and issues that receipt itself, so a provenance-bound level without it — or a structural candidate claiming one — is not an answer its own constructor can produce, and it is refused rather than reported as a published archive",
                evidence.bundle_id,
                evidence.level.wire_name(),
                if present { "present" } else { "absent" }
            ),
        });
    }
    if evidence.class_ceiling.requires_operational_authority() {
        return Err(UnprovenClaim {
            obligation: format!(
                "a class ceiling this capture may reach for archive {} (the owner claimed {}, which needs owner-issued bounded validation evidence or a separate cutover authority that a backup.create does not hold)",
                evidence.bundle_id,
                evidence.class_ceiling.wire_name()
            ),
            reason: format!(
                "owner answered for archive {} at class ceiling {}; A13.7 requires separate authority for cutover and confines restore verification to an isolated area, so this capture operation cannot have reached that ceiling",
                evidence.bundle_id,
                evidence.class_ceiling.wire_name()
            ),
        });
    }
    Ok(())
}

/// Routes one backup verify command through the correlated Kernel front
/// door.
///
/// Verify performs bounded verification only: it can never restore, change
/// an installation, or select a cutover, and no outcome here claims
/// decryptability, isolated restore success or cutover authority. A
/// transport acknowledgement is never verification proof and backup
/// existence is not recovery proof (I5.13), so the outcome state is decided
/// by the owner's own level and not by this surface: the exact archive
/// identity, class, integrity digest and member counts decode first, then
/// the owner's verification level, class ceiling and archived-fence
/// relation are checked against their closed vocabularies with the capture
/// receipt's absence kept explicit. The complete relation BETWEEN those
/// answers is then checked by [`require_proven_claim`]: a
/// provenance-bound/class-qualified level, or a `capture-owner-proven`
/// archived fence, without the owner-issued capture receipt that proves it -
/// and a structural candidate that claims one - is reported as a
/// [`BACKUP_STATE_REFUSED`] outcome naming the exact missing owner evidence,
/// never as a verified archive. Only the
/// [`VerifyProofLevel::ProvenanceBound`] or [`VerifyProofLevel::ClassQualified`]
/// level reports [`BACKUP_STATE_VERIFIED`]; a
/// [`VerifyProofLevel::StructuralCandidate`] archive is reported as
/// [`BACKUP_STATE_CANDIDATE`] with the proven level left at
/// [`BackupStage::Requested`], because a self-consistent decode of
/// caller-supplied bytes is an untrusted candidate and not recovery proof. A
/// `plan_gap` refusal keeps the outcome incomplete instead of being promoted
/// to a verified archive, and a `cancelled` reply keeps the owner's own
/// cancellation reason code and owner cleanup state, so a cancellation is
/// reported as a cancellation - never as a field-shape
/// [`BACKUP_STATE_INVALID`] whose cleanup state was dropped, and never as an
/// archive that may simply be captured again.
pub fn backup_verify(
    client: &mut KernelClient,
    request: &CommandRequest,
) -> Result<CommandResponse, BackupClientError> {
    require_command(request, CommandId::BackupVerify).map_err(BackupClientError::Client)?;
    let params = verify_params(request)?;
    let operation_id = request.request.idempotency_key.clone();
    // Bounded verification is the catalogue's candidate row at the
    // candidate-artifact ceiling: verification proves an archive, never an
    // installation change, and the pair is read, never restated.
    let (effect, proof_ceiling) = catalogued_ceiling(CommandId::BackupVerify)?;
    client.set_request_identity(request.request.clone());
    let payload = json!({
        "bundle_hex": params.bundle_hex.as_str(),
    });
    let response = client
        .transact_json(BACKUP_VERIFY_OPERATION, payload)
        .map_err(BackupClientError::Transport)?;
    envelope_command(&response, BACKUP_VERIFY_OPERATION)?;
    envelope_idempotency(&response, &request.request)?;
    let wire_status = envelope_status(&response)?;
    // The owner's `ok` spelling is a transport-level acknowledgement and
    // selects no outcome state at all. The state is decided only after the
    // owner's evidence level decodes below, so `ok` starts from the
    // undecided placeholder and the `ok` arm always overwrites it before
    // anything is reported; that arm returns a typed error instead of
    // reporting one, and an unproven transport outcome has its own closed
    // [`BackupUnknownOutcome`] type.
    let state = match wire_status {
        BACKUP_WIRE_OK => BACKUP_STATE_UNKNOWN,
        other => other,
    };
    let mut outcome = BackupOperationOutcome {
        operation: BACKUP_VERIFY_OPERATION.to_owned(),
        state: state.to_owned(),
        // Verify declares no class and no scope: the evidenced class belongs
        // to the verification owner receipt, so nothing is requested here.
        requested_class: None,
        requested_scope: None,
        archive_id: None,
        operation_id: operation_id.clone(),
        // The verify reply contract declares no source or destination
        // installation identity, and the surface never invents one.
        source_identity: None,
        destination_identity: None,
        effect,
        proof_ceiling,
        proof_level: BackupStage::Requested,
        // The owner's verification evidence is unknown until its level
        // decodes, and no other status proves any of it: a refused, invalid,
        // cancelled or blocked reply reports all four as explicitly absent.
        verification_level: None,
        class_ceiling: None,
        capture_receipt: None,
        // Undecided until an `ok` reply's nested result identity has been
        // decoded AND bound to this request by `require_result_identity`. Every
        // other status answers no result, so the absence stays explicit.
        result_identity: None,
        archive_fence_relation: None,
        archive_fence_proof: None,
        target_compatibility: None,
        // Undecided until a `cancelled` reply carries the owner's own two
        // answers. Every other status reports both as explicitly absent, so a
        // non-cancellation never borrows a cleanup fact.
        cancellation_reason_code: None,
        owner_cleanup_state: None,
        gates_passed: Vec::new(),
        missing_obligations: Vec::new(),
        next_reconciliation: next_action(state, BACKUP_VERIFY_OPERATION, &operation_id),
        reason: String::new(),
    };
    match wire_status {
        BACKUP_WIRE_OK => {
            // A transport acknowledgement is not verification proof, so every
            // field the owner must answer is decoded and closed-checked here
            // before any state or proven level is reported.
            let evidence = verify_evidence(&response)?;
            // A proof is only as good as the request it answers. The nested
            // result identity is bound to the request BEFORE the claim is
            // graded, because an answer that is not about this request has no
            // level this surface may report at all: the outer idempotency echo
            // is a transport correlation and is explicitly not sufficient.
            if let Err(unproven) = require_result_identity(&evidence, &request.request) {
                return refuse_unproven_claim(
                    request,
                    &operation_id,
                    CommandId::BackupVerify,
                    outcome,
                    unproven,
                );
            }
            // A closed set is not a proof: the owner's own answers must agree.
            if let Err(unproven) = require_proven_claim(&evidence) {
                return refuse_unproven_claim(
                    request,
                    &operation_id,
                    CommandId::BackupVerify,
                    outcome,
                    unproven,
                );
            }
            apply_verify_evidence(&mut outcome, &evidence);
            apply_verified_level(&mut outcome, &evidence);
            outcome.next_reconciliation =
                next_action(&outcome.state, BACKUP_VERIFY_OPERATION, &operation_id);
        }
        BACKUP_STATE_INVALID => {
            envelope_text(&response, "reason")?.clone_into(&mut outcome.reason);
            let _ = envelope_text(&response, "field")?;
            outcome.missing_obligations = vec![format!("invalid field: {}", outcome.reason)];
        }
        BACKUP_STATE_CANCELLED => {
            // A cancellation is the owner's own answer, not a malformed field,
            // so it projects here instead of falling into the `invalid` arm
            // above, which reported it as a caller mistake and dropped the
            // owner's cleanup state.
            apply_cancellation(&mut outcome, &response, &operation_id)?;
        }
        BACKUP_STATE_REFUSED => {
            if envelope_text(&response, "code")? != "plan_gap" {
                return Err(BackupClientError::Client(CliError::ResultMismatch));
            }
            outcome.missing_obligations =
                vec![envelope_text(&response, "missing_owner")?.to_owned()];
            envelope_text(&response, "reason")?.clone_into(&mut outcome.reason);
        }
        _ => return Err(BackupClientError::Client(CliError::ResultMismatch)),
    }
    respond(request, CommandId::BackupVerify, &outcome)
}

/// One decoded verification answer, with every vocabulary closed.
///
/// The owner's evidence is read once, here, so the state decision downstream
/// cannot be reached with a half-decoded reply. Every string is the owner's
/// own answer bounded by a closed vocabulary this surface declares; nothing is
/// derived from the archive, inferred from a sibling field, or defaulted.
struct VerifyEvidence<'a> {
    /// Archive identity the owner proved.
    bundle_id: String,
    /// Archive class the owner proved, from the closed class set.
    class: &'a str,
    /// Evidence level the owner proved, decoded through the ONE typed owner
    /// [`VerifyProofLevel::from_wire`] so the level this surface checks is the
    /// same type it later matches on and reports.
    level: VerifyProofLevel,
    /// Exact class ceiling, decoded through the one typed owner
    /// [`VerifyClassCeiling::from_wire`] rather than kept as a bare string this
    /// surface would then have to re-interpret.
    class_ceiling: VerifyClassCeiling,
    /// STRUCTURAL archived-fence relation to this target, from
    /// [`BACKUP_ARCHIVE_FENCE_RELATIONS`].
    archive_fence_relation: &'a str,
    /// PROVENANCE qualifier for the relation, decoded through the one typed
    /// owner [`ArchiveFenceProof::from_wire`].
    archive_fence_proof: ArchiveFenceProof,
    /// Owner-issued publication receipt, or `None` when the owner issued none.
    capture_receipt: Option<&'a str>,
    /// Nested typed references binding this answer to the request it answers.
    /// Carried as a value, not re-derived here, so
    /// [`require_result_identity`] can compare the operation, the two digests
    /// and the evidence references against the request that produced it.
    result: BackupResultIdentity,
    /// Per-domain member counts, in the owner's own pass order.
    member_counts: Vec<String>,
}

/// Decodes and closed-checks every field a successful verify reply must answer.
///
/// A reply that is missing a field, carries an unknown vocabulary, or answers
/// with a value outside its closed set is a typed result mismatch rather than a
/// partially trusted outcome: this surface cannot bound evidence it cannot
/// name, and a caller-authored self-consistent checksum is not provenance.
/// Reading each field into its closed set is not the whole check. The relation
/// BETWEEN those fields is proved separately by [`require_proven_claim`], and
/// the relation between the answer and the REQUEST it answers is proved
/// separately by [`require_result_identity`]; this decoder's caller runs both
/// before any of them is reported.
fn verify_evidence(response: &Value) -> Result<VerifyEvidence<'_>, BackupClientError> {
    // The exact archive identity, the closed class and the integrity digest
    // shape come first: a reply that fails those is not a verification answer.
    let bundle_id = envelope_text(response, "bundle_id")?.to_owned();
    non_blank(&bundle_id, "backup.bundle_id").map_err(BackupClientError::Client)?;
    let class = envelope_text(response, "class")?;
    if backup_class(class).is_none() {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    let integrity_sha256 = envelope_text(response, "integrity_sha256")?.to_owned();
    hex64(&integrity_sha256, "backup.integrity_sha256").map_err(BackupClientError::Client)?;
    let member_counts = [
        ("blob_count", envelope_count(response, "blob_count")?),
        ("event_count", envelope_count(response, "event_count")?),
        ("receipt_count", envelope_count(response, "receipt_count")?),
    ]
    .into_iter()
    .map(|(field, count)| format!("{field}={count}"))
    .collect();
    let level = envelope_text(response, "verification_level")?;
    // Decoded through the one typed owner rather than tested against a parallel
    // string array: a level outside the type is a value this surface cannot
    // bound, and a level inside the type arrives already carrying the
    // capture-evidence relation [`require_proven_claim`] will enforce.
    let level = VerifyProofLevel::from_wire(level)
        .ok_or(BackupClientError::Client(CliError::ResultMismatch))?;
    // The class ceiling is echoed rather than derived from the class token:
    // only the owner knows which ceiling its own receipt reached. It is decoded
    // through its own typed owner so the reachability relation is a property of
    // the member rather than a second table keyed on a string.
    let class_ceiling = envelope_text(response, "class_ceiling")?;
    let class_ceiling = VerifyClassCeiling::from_wire(class_ceiling)
        .ok_or(BackupClientError::Client(CliError::ResultMismatch))?;
    // The archived fence's relation to this target and its proof qualifier, so a
    // historical archive stays historical instead of being refused for an older
    // generation, and an exact structural value is never printed as proven
    // installation history. Both are closed-checked: a value this surface cannot
    // name is a typed result mismatch, never a coerced "current".
    let archive_fence_relation = envelope_text(response, "archive_fence_relation")?;
    if !BACKUP_ARCHIVE_FENCE_RELATIONS.contains(&archive_fence_relation) {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    let archive_fence_proof = envelope_text(response, "archive_fence_proof")?;
    let archive_fence_proof = ArchiveFenceProof::from_wire(archive_fence_proof)
        .ok_or(BackupClientError::Client(CliError::ResultMismatch))?;
    let capture_receipt = envelope_optional_text(response, "capture_receipt")?;
    if let Some(receipt) = capture_receipt {
        non_blank(receipt, "backup.capture_receipt").map_err(BackupClientError::Client)?;
    }
    // The nested identity is decoded here, once, through the same closed reads
    // as every other field, so no caller can reach the state decision with a
    // half-decoded result identity. Whether those references agree with the
    // REQUEST is a separate question, asked by [`require_result_identity`],
    // because this function holds no request to compare them against.
    let result = decode_result_identity(response, &integrity_sha256, capture_receipt)?;
    Ok(VerifyEvidence {
        bundle_id,
        class,
        level,
        class_ceiling,
        archive_fence_relation,
        archive_fence_proof,
        capture_receipt,
        result,
        member_counts,
    })
}

/// Decodes the nested typed references that bind a verify answer to the request
/// it answers.
///
/// The outer `idempotency_key` is a TRANSPORT correlation and is explicitly not
/// this: it is the same value on a replay, on a reconciliation of a predecessor's
/// row, and on a substituted answer. These references are the ones that can tell
/// those apart, and each is shape-checked here without being recomputed:
/// re-deriving a digest over what this surface holds would replace the owner's
/// recorded identity with a fresh local value instead of checking the one the
/// owner recorded.
///
/// The archive digest and the capture receipt are the values the SAME reply
/// already projected as `integrity_sha256` and `capture_receipt`, read once and
/// carried into the identity rather than re-read, so the two cannot disagree
/// about which archive or receipt they name.
///
/// The validity attestation is read as an explicit absence. The verify route
/// projects no attestation today — no production `BackupRole::Verifier` session
/// issues one — and a decoder that invented a value to fill it would report
/// provenance the owner never issued. That absence is the owner's own answer and
/// is exactly what refuses a provenance-level claim in [`require_proven_claim`].
fn decode_result_identity(
    response: &Value,
    archive_digest: &str,
    capture_receipt: Option<&str>,
) -> Result<BackupResultIdentity, BackupClientError> {
    let operation_id = envelope_text(response, "operation_id")?.to_owned();
    non_blank(&operation_id, "backup.operation_id").map_err(BackupClientError::Client)?;
    let request_digest = envelope_text(response, "request_digest")?.to_owned();
    hex64(&request_digest, "backup.request_digest").map_err(BackupClientError::Client)?;
    let operation_namespace = envelope_text(response, "operation_namespace")?.to_owned();
    hex64(&operation_namespace, "backup.operation_namespace").map_err(BackupClientError::Client)?;
    let validity_attestation = envelope_optional_text(response, "validity_attestation")?;
    if let Some(attestation) = validity_attestation {
        non_blank(attestation, "backup.validity_attestation").map_err(BackupClientError::Client)?;
    }
    Ok(BackupResultIdentity {
        operation_id,
        request_digest,
        operation_namespace,
        archive_digest: archive_digest.to_owned(),
        capture_receipt: capture_receipt.map(str::to_owned),
        validity_attestation: validity_attestation.map(str::to_owned),
    })
}

/// Checks that one public result identity is bound to the request it answers.
///
/// This is the I9 check and it is deliberately NOT the envelope echo. I5.27
/// defines idempotency over canonical bytes rather than caller spelling, and the
/// Kernel projects `request_digest` and `operation_namespace` precisely so a
/// frame-level consumer can correlate an answer to its durable row; this surface
/// is that consumer. Three relations are checked, and each can only fail closed:
///
/// - The producing operation is this caller's own. The verify payload declares
///   no `successor_of`, so this path is never the reconciliation leg; an answer
///   naming a predecessor's operation is a substituted identity, not a
///   reconciliation.
/// - The namespace is a DIGEST and not caller text. If it equals the caller's
///   own human key the durable key is no longer a digest and two principals'
///   rows are no longer separable, so the answer is refused rather than
///   reported as this caller's own row.
/// - The two digests are DISTINCT. The request digest is a hash over the
///   accepted request and the namespace is the row key derived from it; if they
///   were the same value one binding would be standing in for the other, which
///   is exactly the single-echo answer I9 forbids.
///
/// None of these is recomputed. Each compares what the owner recorded.
fn require_result_identity(
    evidence: &VerifyEvidence<'_>,
    request: &RequestIdentity,
) -> Result<(), UnprovenClaim> {
    let identity = &evidence.result;
    if identity.operation_id != request.idempotency_key.as_str() {
        return Err(UnprovenClaim {
            obligation: format!(
                "a result identity naming the operation that produced this answer (it names {} for archive {}, and this request presented no successor delegation, so a predecessor's operation is a substituted identity and not a reconciliation)",
                identity.operation_id, evidence.bundle_id
            ),
            reason: format!(
                "owner answered for operation {} while this request presented operation {}; an outer idempotency echo is a transport correlation and cannot stand for the operation that produced the result",
                identity.operation_id,
                request.idempotency_key.as_str()
            ),
        });
    }
    if identity.operation_namespace == request.idempotency_key.as_str() {
        return Err(UnprovenClaim {
            obligation: format!(
                "a 64-hex durable-row namespace digest for archive {} (the owner echoed this caller's human operation key back as the row key, so the durable key is not a digest and cannot separate two principals' rows)",
                evidence.bundle_id
            ),
            reason: format!(
                "owner answered with operation_namespace {} for archive {}, which is this caller's own human operation key rather than a derived digest",
                identity.operation_namespace, evidence.bundle_id
            ),
        });
    }
    if identity.request_digest == identity.operation_namespace {
        return Err(UnprovenClaim {
            obligation: format!(
                "a canonical request digest and a durable-row namespace that are two separate bindings for archive {} (the owner answered with the same value {} for both, so one binding is standing in for the other)",
                evidence.bundle_id, identity.request_digest
            ),
            reason: format!(
                "owner answered for archive {} with request_digest and operation_namespace both equal to {}; the accepted request's canonical hash and its derived row key have different preimages and must not be one value",
                evidence.bundle_id, identity.request_digest
            ),
        });
    }
    Ok(())
}

/// One owner proof claim this surface cannot believe, carrying the exact
/// relation that failed.
///
/// A closed vocabulary is not a proof. Every field of a verify claim is the
/// owner's own answer, so the fields have to agree with each other before any
/// of them becomes a reported outcome; a claim whose own parts contradict each
/// other is the owner's answer failing to be one answer. The two bounded texts
/// are what the operator sees instead of a silently dropped or a
/// success-shaped result: [`Self::obligation`] names the exact owner evidence
/// the claim needs, and [`Self::reason`] names the claim that was refused.
struct UnprovenClaim {
    /// Bounded obligation naming the owner evidence the claim requires.
    obligation: String,
    /// Bounded reason naming the refused claim and the relation that refused it.
    reason: String,
}

/// Checks the COMPLETE relation between the proof-vocabulary members of one
/// decoded verify claim, instead of admitting each member on its own.
///
/// [`verify_evidence`] proves that every string is inside a closed set; this
/// proves that the set members agree. Before this check existed, a
/// [`VerifyProofLevel::ProvenanceBound`] or [`VerifyProofLevel::ClassQualified`]
/// reply carrying no capture receipt was reported as [`BACKUP_STATE_VERIFIED`],
/// a [`VerifyProofLevel::StructuralCandidate`] reply could carry a receipt it did
/// not earn, and an [`ArchiveFenceProof::CaptureOwnerProven`] fence could
/// be printed with no capture owner behind it at all. I5.13 keeps backup
/// existence from being recovery proof and a caller-authored self-consistent
/// checksum is not capture provenance, so a claim whose owner evidence is
/// absent, contradictory, or unrelatable is refused and reported at
/// [`BACKUP_STATE_REFUSED`] with the missing owner named - never reported at the
/// level it claimed.
///
/// The class ceiling's relation to the EVIDENCED CLASS is deliberately NOT
/// checked here. Its only typed owner is
/// `eliot_backup::RestoreEvidenceLevel::for_class`, reached through
/// `BackupClass::evidence_level`, and `eliot-cli` does not depend on
/// `eliot-backup`. Admitting that dependency, or mirroring its table here,
/// would put a second class-to-ceiling owner in a surface crate, so that half
/// of the relation is an owner decision and not a table this file may write.
/// The ceiling's relation to what a read-only verify may REACH is a different
/// question and is answered below, from the ceiling's own typed member.
fn require_proven_claim(evidence: &VerifyEvidence<'_>) -> Result<(), UnprovenClaim> {
    // The archived fence's PROOF axis is a provenance claim in its own right,
    // so it is held to the same rule as the level that carries one: naming a
    // capture owner requires the owner-issued receipt that proves that name.
    // The converse is deliberately NOT required - a capture receipt for the
    // archive says nothing about who produced the archived fence VALUE, so an
    // honest `structural-only` qualifier beside a receipt stays admissible and
    // refusing it would forbid a truthful future answer.
    if evidence.archive_fence_proof.requires_capture_receipt() && evidence.capture_receipt.is_none()
    {
        return Err(UnprovenClaim {
            obligation: format!(
                "owner-issued capture receipt backing archive_fence_proof {} for archive {} (absent from the owner's own answer)",
                evidence.archive_fence_proof.wire_name(),
                evidence.bundle_id
            ),
            reason: format!(
                "owner claimed archive fence proof {} for archive {} with no capture receipt; a capture-owner-proven fence is a provenance claim about who produced the archived fence, and this surface reports none that no owner receipt backs",
                evidence.archive_fence_proof.wire_name(),
                evidence.bundle_id
            ),
        });
    }
    // The level's own relation to the owner's evidence, read from the typed
    // owner rather than from a string arm beside it. This is the complete
    // relation, not a membership test: a level whose required evidence is
    // ABSENT is refused instead of downgraded, and a level whose relation
    // forbids that evidence is refused when it is PRESENT, because a candidate
    // that claims a receipt is claiming provenance it does not have.
    match evidence.level.capture_evidence() {
        CaptureEvidenceRelation::RequiresOwnerEvidence => {
            // A provenance-bound or class-qualified level is a claim about WHO
            // produced these bytes, and no production verifier issues the
            // attestation on this path. Refusing here is therefore not
            // conservative bookkeeping: it is the only honest report, because
            // the level's evidence cannot exist yet and a level string is not
            // itself a claim.
            for (present, obligation, description) in [
                (
                    evidence.capture_receipt.is_some(),
                    "owner-issued capture receipt matching archive {} and claimed verification level {} (absent from the owner's own answer)",
                    "owner claimed verification level {} for archive {} at class ceiling {} with no capture receipt; a provenance-bound or class-qualified level is a claim of retained capture provenance, and a self-consistent decode of caller-supplied bytes is not one",
                ),
                (
                    evidence.result.validity_attestation.is_some(),
                    "verifier-issued archive validity attestation backing archive {} and claimed verification level {} (absent from the owner's own answer; no BackupRole::Verifier session issues one on this product)",
                    "owner claimed verification level {} for archive {} with no verifier-issued validity attestation; a recognized proof level with missing owner evidence is an unbacked claim, not a weaker proof, and this surface refuses it instead of downgrading it",
                ),
            ] {
                if !present {
                    return Err(UnprovenClaim {
                        obligation: obligation.replacen("{}", &evidence.bundle_id, 1).replacen(
                            "{}",
                            evidence.level.wire_name(),
                            1,
                        ),
                        reason: description
                            .replacen("{}", evidence.level.wire_name(), 1)
                            .replacen("{}", &evidence.bundle_id, 1)
                            .replacen("{}", evidence.class_ceiling.wire_name(), 1),
                    });
                }
            }
        }
        CaptureEvidenceRelation::RequiresOwnerEvidenceAbsence => {
            if evidence.capture_receipt.is_some() {
                return Err(UnprovenClaim {
                    obligation: format!(
                        "owner-issued capture receipt is contradictory at claimed verification level {} for archive {}: a structural candidate proves no retained capture provenance, so this surface reports no level beside a receipt",
                        evidence.level.wire_name(),
                        evidence.bundle_id
                    ),
                    reason: format!(
                        "owner claimed verification level {} for archive {} AND supplied a capture receipt; those two answers are not one answer, and a candidate that claims a receipt is claiming provenance it does not have",
                        evidence.level.wire_name(),
                        evidence.bundle_id
                    ),
                });
            }
        } // No catch-all arm exists, and that is the guarantee rather than an
          // omission. `VerifyProofLevel::capture_evidence` is total over every
          // level, so there is no member this surface can decode but cannot
          // relate: adding a level forces its relation to be stated here, and the
          // compiler forces this match to handle it. The old fallible shape needed
          // a runtime "unrelatable level" refusal; the typed owner makes that
          // state unrepresentable instead.
    }
    // The class ceiling's REACHABILITY, as distinct from its spelling. A
    // read-only verify holds no authority to declare operational validation or
    // a cutover: A13.7 states that cutover requires separate authority and that
    // restore verification happens in an isolated area, and the owner's own
    // `RestoreEvidenceLevel` documents that neither of those rungs is something
    // the backup library emits. An answer naming one is IMPOSSIBLE on this path
    // and is refused rather than rendered, so an over-claiming owner cannot
    // advertise operational recovery off a verify command.
    if evidence.class_ceiling.requires_operational_authority() {
        return Err(UnprovenClaim {
            obligation: format!(
                "a class ceiling this read-only verification may reach for archive {} (the owner claimed {}, which needs owner-issued bounded validation evidence or a separate cutover authority that a backup.verify does not hold)",
                evidence.bundle_id,
                evidence.class_ceiling.wire_name()
            ),
            reason: format!(
                "owner answered for archive {} at class ceiling {}; A13.7 requires separate authority for cutover and confines restore verification to an isolated area, so this read-only operation cannot have reached that ceiling",
                evidence.bundle_id,
                evidence.class_ceiling.wire_name()
            ),
        });
    }
    Ok(())
}

/// Echoes the owner's decoded verify answers into one outcome, verbatim.
///
/// Every field below is the owner's own answer copied across unchanged: none is
/// derived from the archive, inferred from a sibling field, or defaulted, so
/// this projection cannot report a fact the reply did not carry. Target
/// compatibility is set explicitly absent because a verify reply never states
/// one, and absence stays distinguishable from a proven answer. The same
/// discipline as [`apply_cancellation`], and the same reason the state decision
/// downstream is a separate step: this projects evidence, it does not grade it.
fn apply_verify_evidence(outcome: &mut BackupOperationOutcome, evidence: &VerifyEvidence<'_>) {
    outcome.archive_id = Some(evidence.bundle_id.clone());
    outcome.requested_class = Some(evidence.class.to_owned());
    // The reported spellings come from the typed owners the answer was decoded
    // through, so what the operator reads is the same vocabulary the check
    // enforced rather than a second restatement of it.
    outcome.verification_level = Some(evidence.level.wire_name().to_owned());
    outcome.class_ceiling = Some(evidence.class_ceiling.wire_name().to_owned());
    outcome.archive_fence_relation = Some(evidence.archive_fence_relation.to_owned());
    outcome.archive_fence_proof = Some(evidence.archive_fence_proof.wire_name().to_owned());
    outcome.target_compatibility = None;
    outcome.capture_receipt = evidence.capture_receipt.map(str::to_owned);
    // The nested identity is projected as typed references, never as prose and
    // never re-derived from the envelope echo, so the JSON and human
    // projections carry the same bindings the checks above just enforced.
    outcome.result_identity = Some(evidence.result.clone());
    outcome.gates_passed.clone_from(&evidence.member_counts);
}

/// Projects one refused proof claim as this operation's typed refusal.
///
/// This is the module's existing refusal shape, not a new error scheme: the
/// outcome reports [`BACKUP_STATE_REFUSED`], names the exact owner evidence the
/// claim needed as its one missing obligation, carries the bounded reason, and
/// keeps the same operation identity for same-operation reconciliation. The
/// Projects the owner's own verified level onto the outcome.
///
/// The owner proved this archive's identity and class at every level it names, so
/// both are reported exactly as answered. The match is on the TYPED level and is
/// exhaustive over [`VerifyProofLevel`], so a level added to the vocabulary is a
/// compile error here rather than a silently unhandled state.
fn apply_verified_level(outcome: &mut BackupOperationOutcome, evidence: &VerifyEvidence<'_>) {
    match evidence.level {
        VerifyProofLevel::ProvenanceBound | VerifyProofLevel::ClassQualified => {
            BACKUP_STATE_VERIFIED.clone_into(&mut outcome.state);
            outcome.proof_level = BackupStage::Verified;
            outcome.reason = format!(
                "owner accepted verification level {} with class ceiling {}; backup existence is not recovery proof, so rehearse the isolated restore before treating it as a recovery point",
                evidence.level.wire_name(),
                evidence.class_ceiling.wire_name()
            );
        }
        VerifyProofLevel::StructuralCandidate => {
            // The proven level deliberately stays [`BackupStage::Requested`]: a
            // structurally valid archive without retained capture provenance is an
            // untrusted candidate, and naming the exact absent owner obligation
            // keeps that gap explicit.
            BACKUP_STATE_CANDIDATE.clone_into(&mut outcome.state);
            outcome.missing_obligations = vec![
                "retained capture artifact handle and owner-issued publication receipt (no artifact owner issues one on this path)"
                    .to_owned(),
            ];
            outcome.reason = format!(
                "owner reported structural candidate level {} with class ceiling {} and no retained capture provenance; the archive is an untrusted candidate, not a verified recovery point",
                evidence.level.wire_name(),
                evidence.class_ceiling.wire_name()
            );
        }
    }
}

/// routed `command` is the caller's own declaration and the operation selector
/// is read back from the outcome that is being refused, so a refusal can never
/// be reported under another operation's identity or name. No claimed evidence
/// field is echoed from a refused claim, so nothing the owner asserted about
/// its level, ceiling, receipt or fence is printed as proved, and a refusal is
/// never a success with only a `reason` string attached.
fn refuse_unproven_claim(
    request: &CommandRequest,
    operation_id: &str,
    command: CommandId,
    mut outcome: BackupOperationOutcome,
    unproven: UnprovenClaim,
) -> Result<CommandResponse, BackupClientError> {
    BACKUP_STATE_REFUSED.clone_into(&mut outcome.state);
    outcome.missing_obligations = vec![unproven.obligation];
    outcome.reason = unproven.reason;
    outcome.next_reconciliation = next_action(&outcome.state, &outcome.operation, operation_id);
    respond(request, command, &outcome)
}

/// One decoded cancellation answer, with every vocabulary closed.
///
/// The same shape and the same discipline as [`VerifyEvidence`]: every field
/// is the owner's own answer, read once here so the state decision downstream
/// cannot be reached with a half-decoded reply, and the two vocabulary-checked
/// answers are checked against closed sets this surface declares. Nothing is
/// derived from the reason text, inferred from the state, or defaulted.
struct CancellationEvidence<'a> {
    /// Exact cause the owner answered with, from
    /// [`BACKUP_CANCELLATION_REASON_CODES`].
    reason_code: &'a str,
    /// Owner's own cleanup state, from [`BACKUP_OWNER_CLEANUP_STATES`].
    owner_cleanup_state: &'a str,
    /// Owner's own bounded reason, kept verbatim rather than rewritten.
    reason: &'a str,
}

/// The one real obligation a cancelled capture leaves outstanding.
///
/// The owner cancelled and supplied no cleanup evidence, so what is missing is an
/// OWNER-SUPPLIED CLEANUP CONFIRMATION for this exact operation. It is
/// deliberately not phrased as an invalid field — a cancellation is not a caller
/// mistake — and deliberately not phrased as a re-capture: a second capture is
/// never a safe next action, so this names the same operation identity the
/// request carried and a retry reconciles rather than repeats.
fn cancellation_obligation(operation_id: &str) -> String {
    format!(
        "owner-supplied cleanup confirmation for the cancelled capture of operation {operation_id} (the owner supplied none: cleanup is unconfirmed, so the target must not be treated as clean)"
    )
}

/// Decodes and closed-checks the fields a cancellation reply must answer.
///
/// A reply missing a field, or answering with a value outside its closed set,
/// is a typed result mismatch rather than a partially trusted cancellation:
/// this surface will not relay a cleanup claim it cannot name, and it will not
/// substitute a clean one for a missing one. This is what keeps the owner
/// cleanup state RETAINED (issue #963) instead of dropped — before it, the same
/// owner answer arrived through the `invalid` envelope, where only `reason` and
/// `field` were read and the cleanup state was lost entirely.
fn cancellation_evidence(response: &Value) -> Result<CancellationEvidence<'_>, BackupClientError> {
    let reason_code = envelope_text(response, "code")?;
    if !BACKUP_CANCELLATION_REASON_CODES.contains(&reason_code) {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    let owner_cleanup_state = envelope_text(response, "owner_cleanup_state")?;
    if !BACKUP_OWNER_CLEANUP_STATES.contains(&owner_cleanup_state) {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    Ok(CancellationEvidence {
        reason_code,
        owner_cleanup_state,
        reason: envelope_text(response, "reason")?,
    })
}

/// Projects one decoded cancellation reply onto its outcome.
///
/// This owns the whole cancellation projection, so the state dispatch in
/// [`backup_verify`] and the cancellation arm of [`backup_restore_test`] decide
/// nothing about it and the owner cleanup state has exactly one place it can be
/// written. What it writes: the owner's own reason code and owner cleanup state,
/// carried verbatim from the closed-checked reply; the owner's own bounded
/// reason, kept rather than rewritten; the missing obligation naming the cleanup
/// confirmation that is actually outstanding; and `next_reconciliation` from the
/// same [`next_action`] helper every other state uses, so the same operation
/// identity is named and a second capture is still never proposed.
///
/// What it deliberately does NOT touch matters as much: `state` keeps the
/// reply's own `cancelled` spelling, and `proof_level` plus the four
/// verification-evidence fields stay `BackupStage::Requested` and explicitly
/// absent, so a cancelled capture can never be reported as a proven archive and
/// I5.13's "backup existence is not recovery proof" is not weakened by a
/// cancellation. A reply failing either closed check is a typed result
/// mismatch, and the outcome is left untouched rather than half-projected.
fn apply_cancellation(
    outcome: &mut BackupOperationOutcome,
    response: &Value,
    operation_id: &str,
) -> Result<(), BackupClientError> {
    let evidence = cancellation_evidence(response)?;
    outcome.cancellation_reason_code = Some(evidence.reason_code.to_owned());
    outcome.owner_cleanup_state = Some(evidence.owner_cleanup_state.to_owned());
    evidence.reason.clone_into(&mut outcome.reason);
    outcome.missing_obligations = vec![cancellation_obligation(operation_id)];
    // The operation selector is read back from the outcome being projected
    // rather than restated, so this shared projection names the same operation
    // the caller routed — the verify row for [`backup_verify`], the
    // restore-test row for the cancellation arm in [`backup_restore_test`] —
    // and a next action can never point at a different operation than the one
    // that produced it.
    outcome.next_reconciliation = next_action(&outcome.state, &outcome.operation, operation_id);
    Ok(())
}

/// Builds the UNDECIDED restore-test outcome, before any owner answer is
/// projected onto it.
///
/// Every owner-answer field starts absent, and that is the point: at this stage
/// the reply has been graded but nothing in it has been proved, so a field an
/// arm below does not explicitly fill stays an explicit absence rather than an
/// invented value. `proof_level` is the ONE exception and it is the graded stage
/// the returned status evidenced, which `require_restore_test_ceiling` has
/// already accepted as a legal advance before any arm runs.
///
/// Extracted so the command's flow (parse → grade → build → project) reads as
/// those four steps, and so the absence defaults are stated once with their
/// reasons instead of sitting inside a large match.
fn undecided_restore_outcome(
    params: &BackupRestoreTestParams,
    state: &str,
    operation_id: &str,
    effect: EffectClass,
    proof_ceiling: ProofCeiling,
    claim: &RestoreTestClaim,
) -> BackupOperationOutcome {
    BackupOperationOutcome {
        operation: BACKUP_RESTORE_TEST_OPERATION.to_owned(),
        state: state.to_owned(),
        requested_class: None,
        requested_scope: None,
        archive_id: None,
        operation_id: operation_id.to_owned(),
        // Exactly the identities the request DECLARED, and nothing more: the
        // capture operation the request named as the source of the snapshot,
        // and the destination store identity the request asked to restore
        // into. No owner provisioned, admitted or issued either one - the
        // Kernel rehearsed shape only - so the human projection prints them
        // under `source:`/`destination:` as the request's own claim, not as a
        // provisioned destination or an admitted source. Neither is defaulted.
        source_identity: Some(params.capture_operation_id.clone()),
        destination_identity: Some(params.dest_store_id.clone()),
        effect,
        proof_ceiling,
        // Graded from the reply, never assumed: the lifecycle stage the
        // returned status actually evidences, and the stage
        // `require_restore_test_ceiling` has accepted as a legal advance of
        // this operation's own ladder. A status that evidenced a later stage
        // than the surface may claim is refused and never reaches this line, so
        // the level here can never be a claim the reply did not make.
        proof_level: claim.stage,
        // No verification level, no class ceiling, no capture receipt and no
        // archived-fence relation is known yet. The capture operation identity
        // the request declared above is the request's own claim, never an
        // owner-issued verification answer, so all four stay explicitly absent.
        verification_level: None,
        class_ceiling: None,
        capture_receipt: None,
        // A rehearsal proves no archive result, so there is no result identity to
        // bind. It stays an explicit absence: the capture operation identity the
        // request declared above is the request's own claim, never an owner's
        // answer about a result this command did not produce.
        result_identity: None,
        archive_fence_relation: None,
        archive_fence_proof: None,
        target_compatibility: None,
        // Absent until the owner answers with a cancellation of its own: a
        // rehearsal is not a capture, and no other status here carries a
        // cancellation reason code or an owner cleanup state. Both stay
        // explicitly absent rather than borrowed from the blocked rehearsal's
        // own reason, and only the `cancelled` arm fills them, from the owner's
        // own closed-checked answers.
        cancellation_reason_code: None,
        owner_cleanup_state: None,
        gates_passed: Vec::new(),
        missing_obligations: Vec::new(),
        next_reconciliation: next_action(state, BACKUP_RESTORE_TEST_OPERATION, operation_id),
        reason: String::new(),
    }
}

/// Reports one `ok` restore-test answer as the restore owner's own rehearsal
/// result, or refuses it.
///
/// This is the whole `ok` arm of [`backup_restore_test`], extracted so the
/// command's own flow stays readable and so the decode/prove/project order is
/// one named thing rather than a sequence buried in a large match. The order is
/// the guarantee:
///
/// 1. DECODE the owner's persisted receipt ([`restore_receipt_evidence`]). A
///    reply with no decodable receipt is a typed result mismatch — an `ok` that
///    is only a transport acknowledgement must never render as a rehearsal.
/// 2. PROVE it ([`require_restore_evidence`]), which refuses readiness, cutover,
///    a level this command cannot hold, a `canonical_only`/level pair the
///    owner's own constructor cannot produce, and a receipt whose own persisted
///    destination is not the destination this operation admitted. A failure here
///    is this operation's typed refusal naming the relation, never a rendered
///    result.
/// 3. PROJECT the owner's own answers ([`apply_restore_receipt`]) and only then
///    set [`BACKUP_STATE_REHEARSED`].
///
/// Step 3 happens after step 2 precisely so the state can never be reached by a
/// receipt that did not clear the relation checks.
fn apply_rehearsed_restore(
    request: &CommandRequest,
    response: &Value,
    executed_route: Option<&ExecutedRoute<'_>>,
    mut outcome: BackupOperationOutcome,
    operation_id: &str,
    params: &BackupRestoreTestParams,
) -> Result<CommandResponse, BackupClientError> {
    let evidence = restore_receipt_evidence(response)?;
    if let Err(unproven) = require_restore_evidence(&evidence, params) {
        return refuse_unproven_claim(
            request,
            operation_id,
            CommandId::BackupRestoreTest,
            outcome,
            unproven,
        );
    }
    apply_restore_receipt(&mut outcome, &evidence);
    // `clone_from` rather than `= CONST.to_owned()`: the destination already
    // owns a `String`, so replacing its buffer wholesale would drop the existing
    // allocation for no gain.
    outcome
        .state
        .clone_from(&String::from(BACKUP_STATE_REHEARSED));
    // The gates the owner did NOT admit are still outstanding beside a completed
    // rehearsal: the destination-manifest admission and the no-cutover boundary
    // did not run, and a receipt does not change that. They are reported from
    // the owner's own `gates_not_admitted` so an operator reads how far the
    // route got next to what it proved.
    //
    // `gates_passed` is deliberately NOT overwritten here: the owner's applied
    // PHASE log is the stronger record of the same execution and was already
    // projected, so writing the Kernel's coarser gate list over it would discard
    // the more precise owner answer.
    if let Some(route) = executed_route {
        for gate in route.not_admitted {
            outcome
                .missing_obligations
                .push(format!("{RESTORE_TEST_GATE_OBLIGATION}: {gate}"));
        }
    }
    outcome.next_reconciliation =
        next_action(&outcome.state, BACKUP_RESTORE_TEST_OPERATION, operation_id);
    respond(request, CommandId::BackupRestoreTest, &outcome)
}

/// Routes one isolated restore-test command through the correlated Kernel
/// front door.
///
/// The rehearsal runs in full isolation and can never cut over, retire the
/// source, or select an installation change: this surface never asks for
/// one and the Kernel method has no cutover path, so no answer to this
/// command may be rendered as a cutover admission (A13.7 keeps cutover a
/// separate authority).
///
/// The proven level is GRADED from the returned reply, never assumed:
/// [`restore_test_claim`] derives the lifecycle stage the returned `status`
/// actually evidences, and [`require_restore_test_ceiling`] relates that
/// claim to the catalogue row this operation is declared under before any
/// state or level is reported. An answer above the declared proof ceiling or
/// effect class, or a stage that is not a legal advance on the protocol's own
/// ladder, is refused through the module's existing typed refusal and is
/// never rendered.
///
/// An `ok` reply is reported as the owner's own rehearsal result, because it IS
/// one: the Kernel route reaches `KernelComposition::backup_restore_with_ors_journal`,
/// which admits a durable ORS journal through `OrsRestoreJournalOwner::production`
/// and returns the journalled coordinator's own `RestoreReceipt`. That receipt
/// is decoded by [`restore_receipt_evidence`] and proved by
/// [`require_restore_evidence`] BEFORE the state is set, so an `ok` this surface
/// cannot bound is never rendered as a rehearsal — a receipt that fails to decode
/// is a typed result mismatch, and one claiming a cutover, readiness, or a level
/// this command cannot hold is a typed refusal naming the relation. A successful
/// transport that evidenced NO owner receipt is not a rehearsal at all, and a
/// reply in that shape is refused rather than rendered as an observation.
///
/// The stable operation identity — the correlated idempotency key, never a value
/// read back from the reply body — is what the owner lane reconciles.
/// The `backup.restore-test` wire payload, built from the validated request
/// parameters only.
///
/// This is a pure projection of what the caller asked for: every field below is
/// copied from the admitted request, and none is defaulted, derived from an
/// owner answer, or filled with a placeholder. It exists as a named seam so the
/// command's own flow - admit, send, read the owner's executed route, grade -
/// stays readable, and so a future field cannot be added here without the same
/// scrutiny as the grading that consumes it.
fn restore_test_payload(params: &BackupRestoreTestParams) -> Value {
    json!({
        "bundle_hex": params.bundle_hex.as_str(),
        "destination_authorization_hex": params.authorization_hex.as_str(),
        "target": {
            "target_id": params.target_id.as_str(),
            "target_lineage": params.target_lineage.as_str(),
            "target_sequence": params.target_sequence,
            "target_generation": params.target_generation,
        },
        "provisioning": {
            "dest_store_id": params.dest_store_id.as_str(),
            "residency_denominator_digest": params.residency_denominator_digest.as_str(),
            "source_snapshot_digest": params.source_snapshot_digest.as_str(),
            "capture_operation_id": params.capture_operation_id.as_str(),
        },
        "introductions": Value::Array(params.introductions.clone()),
    })
}

pub fn backup_restore_test(
    client: &mut KernelClient,
    request: &CommandRequest,
) -> Result<CommandResponse, BackupClientError> {
    require_command(request, CommandId::BackupRestoreTest).map_err(BackupClientError::Client)?;
    let params = restore_test_params(request)?;
    let operation_id = request.request.idempotency_key.clone();
    // The rehearsal is the catalogue's candidate row at the candidate-artifact
    // ceiling: a rehearsal is not a cutover, so the pair is read from the same
    // row the dispatch path compares against, never restated here.
    let (effect, proof_ceiling) = catalogued_ceiling(CommandId::BackupRestoreTest)?;
    client.set_request_identity(request.request.clone());
    let payload = restore_test_payload(&params);
    let response = client
        .transact_json(BACKUP_RESTORE_TEST_OPERATION, payload)
        .map_err(BackupClientError::Transport)?;
    envelope_command(&response, BACKUP_RESTORE_TEST_OPERATION)?;
    envelope_idempotency(&response, &request.request)?;
    let wire_status = envelope_status(&response)?;
    // The route the execution actually admitted is read ONCE, here, before the
    // reply is graded. It is the grading input for the `blocked` band AND the
    // reported outstanding-gate list for a completed rehearsal, because both are
    // facts about the same execution. It is read from the owner's own answer
    // rather than reconstructed from the status, so what this surface may claim
    // is set by gates that provably ran and by gates the owner provably did not
    // admit. A reply that does not carry the route at all yields `None`, which
    // only the `blocked` band accepts for grading, so a richer status can never
    // borrow another status's route to justify a ceiling. An `ok` reply that
    // carries no route is still rendered, with its own receipt, because the
    // receipt is the proof and the route is only the outstanding-gate list.
    let route_parts = if wire_status == BACKUP_STATE_BLOCKED || wire_status == BACKUP_WIRE_OK {
        Some(envelope_executed_route(&response)?)
    } else {
        None
    };
    let executed_route = route_parts
        .as_ref()
        .map(|(passed, not_admitted)| ExecutedRoute {
            passed: passed.as_slice(),
            not_admitted: not_admitted.as_slice(),
        });
    // The reply is graded BEFORE any state or proven level is decided, so no
    // owner answer below is projected on the strength of a status this surface
    // has not first related to the catalogue row read above.
    let claim = restore_test_claim(wire_status, executed_route.as_ref())?;
    // `ok` is the one status here that IS a domain verdict, because the Kernel
    // reached the journalled restore coordinator and answered with the
    // coordinator's own persisted `RestoreReceipt`. It is therefore the
    // `rehearsed` state — but only after that receipt has been decoded and
    // proved below. Until then the undecided placeholder stands, and a receipt
    // that fails to decode or fails its own relation never reaches a reported
    // state: it is either a typed refusal or a typed mismatch. So the mapping is
    // deliberately NOT written here, where nothing has checked the receipt yet.
    let state = match wire_status {
        BACKUP_WIRE_OK => BACKUP_STATE_UNKNOWN,
        other => other,
    };
    let mut outcome =
        undecided_restore_outcome(&params, state, &operation_id, effect, proof_ceiling, &claim);
    // The COMPLETE relation between the graded answer and the catalogue row is
    // checked here, before a single owner field is echoed: the refused branch
    // reports this operation's typed refusal with the exact relation that
    // refused it, and it carries no owner-echoed field, so an answer above the
    // declared ceiling can never render as this operation's outcome at all.
    if let Err(unproven) = require_restore_test_ceiling(&claim, wire_status, effect, proof_ceiling)
    {
        return refuse_unproven_claim(
            request,
            &operation_id,
            CommandId::BackupRestoreTest,
            outcome,
            unproven,
        );
    }
    match wire_status {
        BACKUP_STATE_BLOCKED => {
            if envelope_text(&response, "code")? != "plan_gap" {
                return Err(BackupClientError::Client(CliError::ResultMismatch));
            }
            // The route read above, which `restore_test_claim` already required
            // to be non-empty on the passed side and disjoint across both sides.
            // Only the admitted half is reported as `gates_passed`; the gates the
            // owner did NOT admit each become a bounded missing obligation,
            // because a gate no owner admitted is an outstanding obligation and
            // never a passed one.
            let route = executed_route
                .as_ref()
                .ok_or(BackupClientError::Client(CliError::ResultMismatch))?;
            outcome.gates_passed = route.passed.to_vec();
            // The Kernel's own owner name comes first, unresolved, exactly as
            // the reply wrote it. The declaration obligation is this surface's
            // own: the `source:`/`destination:` lines above are what the request
            // declared, and no owner provisioned, admitted or issued either
            // identity, so the projection must not read as a provisioned
            // destination or an admitted source.
            outcome.missing_obligations = vec![
                envelope_text(&response, "missing_owner")?.to_owned(),
                RESTORE_TEST_DECLARED_IDENTITY_OBLIGATION.to_owned(),
            ];
            for gate in route.not_admitted {
                outcome
                    .missing_obligations
                    .push(format!("{RESTORE_TEST_GATE_OBLIGATION}: {gate}"));
            }
            envelope_text(&response, "reason")?.clone_into(&mut outcome.reason);
        }
        BACKUP_STATE_INVALID | BACKUP_STATE_REFUSED => {
            envelope_text(&response, "reason")?.clone_into(&mut outcome.reason);
            let code = envelope_text(&response, "code")?.to_owned();
            outcome.missing_obligations = vec![format!("{state}: {code}")];
        }
        // The owner reached the journalled restore coordinator and returned its own
        // persisted receipt. The receipt is decoded and proved BEFORE the state
        // is decided, so an `ok` this surface cannot bound is never rendered as
        // a rehearsal: a receipt that fails to decode is a typed result mismatch,
        // and one that fails its own relation (claiming a cutover, claiming
        // readiness, or carrying a level this command cannot hold) is this
        // operation's typed refusal naming the exact relation. Only a receipt
        // that survives both becomes `rehearsed` with the owner's own answers.
        //
        // This arm deliberately REPLACED the old "a successful exit proves an
        // observation and nothing else" projection. That projection was correct
        // while the route answered `ok` without ever reaching the restore owner;
        // it is a defect now, because it reported "unknown" for a reply carrying
        // the coordinator's own persisted receipt and so threw the real owner
        // result away. An `ok` that carries NO decodable receipt is refused above
        // as a typed mismatch rather than rendered as an observation.
        BACKUP_WIRE_OK => {
            return apply_rehearsed_restore(
                request,
                &response,
                executed_route.as_ref(),
                outcome,
                &operation_id,
                &params,
            );
        }
        BACKUP_STATE_CANCELLED => {
            // A cancellation is the owner's own answer, not a malformed field,
            // so it is decoded through the same closed cleanup contract the
            // capture and verify paths use and never falls into the `invalid`
            // arm above, which reports a caller mistake and drops the owner's
            // own cleanup answer. The obligation that projection writes is the
            // module's shared one and still names the cancelled CAPTURE: the
            // substance it reports — cleanup evidence was not supplied, so
            // cleanup is unconfirmed — is exactly true here, and rewording that
            // shared string would change what the verify path prints, which is
            // outside this command's contract.
            apply_cancellation(&mut outcome, &response, &operation_id)?;
        }
        // `restore_test_claim` already refused every status outside the graded
        // closed set above, so this is the standing guard for a status added to
        // that vocabulary without a projection: an answer with no stated
        // relation to this operation is not an answer this surface may report.
        _ => return Err(BackupClientError::Client(CliError::ResultMismatch)),
    }
    respond(request, CommandId::BackupRestoreTest, &outcome)
}

/// The authority a restore receipt claims BEYOND an isolated rehearsal.
///
/// `operational_recovery_ready` and `cutover_performed` are not two loose
/// booleans to be checked independently — they are two spellings of one question:
/// *did this receipt reach past rehearsal into authority over the installation?*
/// Both are refused on this command, and their reasons differ, so they are named
/// as members rather than collapsed into a bare `bool` that would lose which one
/// the owner actually claimed.
///
/// The owner's own meanings, quoted from `crates/storage/eliot-backup/src/lib.rs`:
///
/// - `operational_recovery_ready`: *"always `false` from this library: only the
///   exact owner named in `OperationalValidationEvidence` may assert operational
///   readiness"*. This surface never requests that validation, so the claim is
///   refused.
/// - `cutover_performed`: *"is always `false` here"*, and A13.7 keeps cutover a
///   separate authority this command never asks for.
///
/// `RestoreReceipt::validate` refuses `cutover_performed` outright and refuses
/// `operational_recovery_ready` without `OperationallyValidated`; this surface
/// holds neither that evidence nor any cutover authority, so both are refused
/// UNCONDITIONALLY — the owner's own refusals, reached through this command's
/// narrower authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityBeyondRehearsal {
    /// The owner claimed operational readiness for the isolated root.
    ClaimsReadiness,
    /// The owner claimed a cutover was performed.
    ClaimsCutover,
    /// The owner claimed neither: the receipt stays inside the rehearsal.
    None,
}

impl AuthorityBeyondRehearsal {
    /// Reads the owner's two flags as the one relation they jointly express.
    ///
    /// Readiness is checked first because the owner's own validator checks it
    /// first, and because a receipt claiming BOTH is refused for the stronger
    /// claim. Both flags are read, never defaulted: a missing or non-boolean
    /// flag is a typed result mismatch in [`restore_receipt_evidence`], so this
    /// function cannot be reached with an absent flag.
    const fn from_owner_flags(operational_recovery_ready: bool, cutover_performed: bool) -> Self {
        if operational_recovery_ready {
            Self::ClaimsReadiness
        } else if cutover_performed {
            Self::ClaimsCutover
        } else {
            Self::None
        }
    }
}

/// What the restore owner's receipt claims about the RESTORE ITSELF, as one value.
///
/// These receipt fields are not independent facts: the owner derives them all from
/// the single `bundle.manifest.class` of the archive it restored
/// (`crates/storage/eliot-backup/src/lib.rs`, the receipt constructor at line
/// 2072 and `executor_canonical_only` at line 1882). Grouping them states that
/// relation in the type instead of leaving loose booleans that could be read
/// independently, and it gives the surface exactly one place to check the owner's
/// claim rather than several `if`s that each forget a case.
///
/// The two members:
///
/// - `canonical_only` is the owner's class statement: *"distinguishes
///   degraded/scope imports from full archives without upgrading them"*, derived
///   as `!matches!(class, FullRecovery)`. A `true` receipt is a DEGRADED or SCOPE
///   import — semantic data only. It is ENFORCED against `evidence_level` by
///   [`RestoreAuthorityClaim::canonical_only_pair_refusal`] inside
///   [`RestoreAuthorityClaim::refusal`], not merely carried.
/// - `rehearsal` is the owner's posture for this run. A rehearsal can never reach
///   cutover — `KernelBackupRestore::qualify_cutover` refuses one outright — so a
///   receipt that is not a rehearsal is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RestoreAuthorityClaim {
    /// Owner's `canonical_only`: the archive was degraded or scope-only.
    canonical_only: bool,
    /// Owner's `rehearsal` posture.
    rehearsal: bool,
    /// Everything the receipt claims past the rehearsal boundary.
    beyond_rehearsal: AuthorityBeyondRehearsal,
}

impl RestoreAuthorityClaim {
    /// The ONE typed refusal for everything the restore owner's receipt claims
    /// about authority, in the order the owner itself defines them.
    ///
    /// This is the module's existing typed refusal (`UnprovenClaim`, projected by
    /// [`refuse_unproven_claim`] as a [`BACKUP_STATE_REFUSED`] outcome naming the
    /// exact relation), and it is deliberately the ONLY reader of
    /// [`Self::canonical_only`]. A decoded owner field that lives in this type is
    /// therefore gated by this type: there is no second place a `canonical_only`
    /// could be decoded and then carried without being related to the rest of the
    /// receipt, which is the difference between enforcing the owner's derivation
    /// and merely decoding it.
    ///
    /// Four relations, each fail-closed, in this order:
    ///
    /// 1. the two flags that reach PAST the rehearsal boundary — readiness and
    ///    cutover. See [`AuthorityBeyondRehearsal`] for why both are refused
    ///    unconditionally rather than downgraded;
    /// 2. the posture: a receipt that is not a rehearsal is refused because A13.7
    ///    keeps cutover a separate authority and this command is rehearsal-only;
    /// 3. the proof-level BAND: `operationally_validated` requires owner-issued
    ///    operational validation evidence for the exact isolated root and
    ///    `cutover` a separate Human/System Owner authorization. Neither is a
    ///    member this command can hold, so both are refused BEFORE the class/level
    ///    agreement below — a level refused here never reaches it, which is why
    ///    the order is part of the contract and not an implementation detail;
    /// 4. `canonical_only` against the proof level, through
    ///    [`Self::canonical_only_pair_refusal`] — the owner's own single
    ///    derivation, enforced rather than carried.
    fn refusal(self, receipt_id: &str, evidence_level: &str) -> Option<UnprovenClaim> {
        match self.beyond_rehearsal {
            AuthorityBeyondRehearsal::ClaimsReadiness => Some(UnprovenClaim {
                obligation: "a restore receipt that does not report operational readiness"
                    .to_owned(),
                reason: format!(
                    "the owner returned receipt {receipt_id} reporting operational_recovery_ready=true; operational readiness is an owner-issued validation of the exact isolated root that this rehearsal never requested, so the claim is refused rather than echoed"
                ),
            }),
            AuthorityBeyondRehearsal::ClaimsCutover => Some(UnprovenClaim {
                obligation: "a rehearsal receipt that reports no cutover (the owner's own answer reports cutover_performed=true)".to_owned(),
                reason: format!(
                    "the owner returned receipt {receipt_id} for {BACKUP_RESTORE_TEST_OPERATION} whose receipt reports cutover_performed=true; A13.7 keeps cutover a separate authority a rehearsal never performs and this command never asks for one, so this receipt is refused rather than rendered"
                ),
            }),
            AuthorityBeyondRehearsal::None => None,
        }
        .or_else(|| {
            (!self.rehearsal).then(|| UnprovenClaim {
                obligation: "a receipt whose owner reports a rehearsal posture".to_owned(),
                reason: format!(
                    "the owner returned receipt {receipt_id} for {BACKUP_RESTORE_TEST_OPERATION} whose receipt reports rehearsal=false; this command is rehearsal-only and A13.7 keeps cutover a separate authority, so a non-rehearsal receipt is refused rather than rendered here"
                ),
            })
        })
        .or_else(|| Self::level_band_refusal(receipt_id, evidence_level))
        .or_else(|| self.canonical_only_pair_refusal(receipt_id, evidence_level))
    }

    /// Refuses the two members of the RESTORE owner's own level vocabulary that a
    /// rehearsal may never carry.
    ///
    /// They are members of `eliot_backup::RestoreEvidenceLevel`, so a receipt
    /// naming one decodes — and is then refused for the evidence it would require,
    /// which is exactly the distinction the typed refusal draws between "a level I
    /// cannot name" and "a level I can name but must not claim". Nothing below
    /// this arm is reached for them, so the class/level agreement is never asked
    /// about a level that is already out of band.
    fn level_band_refusal(receipt_id: &str, evidence_level: &str) -> Option<UnprovenClaim> {
        if !matches!(
            evidence_level,
            "operationally_validated" | "cutover"
        ) {
            return None;
        }
        Some(UnprovenClaim {
            obligation: format!(
                "a restore proof level this surface may report (the owner answered {evidence_level}, which requires owner evidence this rehearsal does not hold)"
            ),
            reason: format!(
                "the owner returned receipt {receipt_id} at evidence level {evidence_level}; that level requires owner-issued operational validation for the exact isolated root, or a separate Human/System Owner cutover authorization, neither of which this command requested or holds, so the level is refused rather than reported"
            ),
        })
    }

    /// Requires `canonical_only` to be the value the OWNER derives for the class
    /// the proof level reports.
    ///
    /// This is the owner's relation, quoted rather than invented. In
    /// `crates/storage/eliot-backup/src/lib.rs` the receipt constructor derives
    /// BOTH fields from one value, `bundle.manifest.class`:
    ///
    /// ```text
    /// evidence_level: RestoreEvidenceLevel::for_class(bundle.manifest.class),
    /// canonical_only: executor_canonical_only(bundle.manifest.class),
    /// ```
    ///
    /// and those two functions are exhaustive over the three classes:
    ///
    /// ```text
    /// for_class(FullRecovery)          = ReconciliationRequired   executor_canonical_only = false
    /// for_class(CanonicalOnlyDegraded) = IsolatedImportComplete   executor_canonical_only = true
    /// for_class(ScopeExport)           = IsolatedImportComplete   executor_canonical_only = true
    /// ```
    ///
    /// So `canonical_only` and `evidence_level` are not two independent answers —
    /// they are two projections of one class, and the table above is the complete
    /// set of pairs the owner can emit. `archive_valid` appears in neither column:
    /// it is a level the owner defines but never puts in a receipt, so a receipt
    /// carrying it is refused here rather than accepted as "some level I could not
    /// pair".
    ///
    /// Why this is ENFORCED rather than merely carried — which is the whole point
    /// of it living inside [`Self::refusal`] instead of beside it: a receipt
    /// claiming `canonical_only: false` at `isolated_import_complete` would say
    /// "this was a full-recovery archive" while reporting the degraded/scope
    /// ceiling, and the reverse would say "semantic data only" while claiming the
    /// full-recovery ceiling. Both are contradictions the owner's own constructor
    /// cannot produce, and this surface reports `evidence_level` and
    /// `canonical_only` to an operator as one answer, so an unchecked pair here
    /// would let a forged or mis-projected receipt render a degraded import as
    /// full-recovery evidence, or the reverse. The documented rule the owner's own
    /// comment on `executor_canonical_only` cites is that *"a degraded or scope
    /// archive preserves semantic data only and is never advertised as operational
    /// recovery"* — and the pair table above is that rule made checkable.
    ///
    /// The refusal itself is the module's existing typed one, so a receipt that
    /// fails this relation reports [`BACKUP_STATE_REFUSED`] naming the pair rather
    /// than a rendered rehearsal.
    fn canonical_only_pair_refusal(
        self,
        receipt_id: &str,
        evidence_level: &str,
    ) -> Option<UnprovenClaim> {
        let agrees = match evidence_level {
            // FullRecovery: `canonical_only == false`.
            "reconciliation_required" => !self.canonical_only,
            // CanonicalOnlyDegraded and ScopeExport: `canonical_only == true`.
            "isolated_import_complete" => self.canonical_only,
            // `archive_valid` is never paired with a receipt by the owner, so it has
            // no canonical_only value to agree with. Refused explicitly rather than
            // falling through, so a new level cannot be silently accepted here.
            _ => false,
        };
        if agrees {
            return None;
        }
        Some(UnprovenClaim {
            obligation: format!(
                "a receipt whose canonical_only={} agrees with the proof level {evidence_level} the owner derived from the same archive class",
                self.canonical_only
            ),
            reason: format!(
                "the owner returned receipt {receipt_id} reporting canonical_only={} at evidence level {evidence_level}; the restore owner derives both fields from one archive class (executor_canonical_only and RestoreEvidenceLevel::for_class), so that pair is not one its constructor can produce. I5.13 keeps a degraded or scope archive from being advertised as operational recovery, so a receipt whose class and level disagree is refused rather than reported",
                self.canonical_only
            ),
        })
    }
}

/// One decoded restore-owner receipt, with every vocabulary closed.
///
/// The Kernel projects [`eliot_backup::RestoreReceipt`] whole
/// (`serde_json::to_value(&outcome.receipt)` in `rehearsed_reply`), so these are
/// the RESTORE OWNER's own persisted fields rather than a surface restatement
/// of them. Every value is read once, here, before the state decision below can
/// be reached with a half-decoded receipt.
///
/// `receipt_id`, `plan_id`, `bundle_sha256` and `effect_receipt_sha256` are the
/// receipt's identity and its two digests; `evidence_level` is the owner's own
/// proof level decoded through [`BACKUP_RESTORE_EVIDENCE_LEVELS`]; and
/// `target_id` is the destination the owner PERSISTED, which
/// [`require_admitted_destination`] compares against the one this operation
/// admitted rather than merely reporting. The four authority booleans are
/// grouped into one [`RestoreAuthorityClaim`] because the owner derives them
/// together, and `canonical_only` is ENFORCED against `evidence_level` by
/// [`RestoreAuthorityClaim::canonical_only_pair_refusal`] rather than merely
/// carried.
struct RestoreReceiptEvidence<'a> {
    /// Owner's persisted receipt identity.
    receipt_id: &'a str,
    /// Owner's plan identity the receipt binds.
    plan_id: &'a str,
    /// Owner-persisted isolated destination identity the rehearsal imported into.
    ///
    /// The restore owner persists `plan.target.target_id` into every receipt it
    /// issues (`RestoreReceipt::target_id`, bound back to the plan by
    /// `validate_resumed_final_receipt`). It is therefore the owner's own answer
    /// about WHERE the import went, and it is compared against the destination
    /// this operation admitted in [`require_admitted_destination`] — never
    /// echoed as though declaring it were the same as proving it.
    target_id: &'a str,
    /// Digest of the exact archive the restore consumed.
    bundle_sha256: &'a str,
    /// Digest of the owner's terminal effect receipt.
    effect_receipt_sha256: &'a str,
    /// Owner's own proof level, in the owner's own snake_case spelling.
    evidence_level: &'a str,
    /// Everything the receipt claims about authority, as the owner derived it.
    authority: RestoreAuthorityClaim,
    /// Owner's applied phase log, in execution order.
    phase_log: Vec<String>,
    /// Owner's journal owner identity — the composition-owned durable ORS
    /// journal this restore ran on.
    journal_owner: &'a str,
}

/// Decodes and closed-checks the restore owner's persisted receipt.
///
/// A reply that is missing a field, or carries a value outside its closed set,
/// is a typed result mismatch rather than a partially trusted receipt: this
/// surface cannot bound evidence it cannot name, and a receipt identity that
/// failed to decode is exactly what must never be reported as a rehearsal.
///
/// The receipt is decoded as an object of its own because the owner nests it
/// under `receipt`; a non-object receipt is refused rather than read through.
fn restore_receipt_evidence(
    response: &Value,
) -> Result<RestoreReceiptEvidence<'_>, BackupClientError> {
    let receipt = response
        .get("receipt")
        .filter(|value| value.is_object())
        .ok_or(BackupClientError::Client(CliError::ResultMismatch))?;
    let receipt_id = envelope_text(receipt, "receipt_id")?;
    non_blank(receipt_id, "restore.receipt_id").map_err(BackupClientError::Client)?;
    let plan_id = envelope_text(receipt, "plan_id")?;
    non_blank(plan_id, "restore.plan_id").map_err(BackupClientError::Client)?;
    // The destination identity the receipt PERSISTS. Decoding it is not the check:
    // `require_admitted_destination` compares it against the destination this
    // operation admitted, because a receipt naming another destination is a
    // substituted answer rather than this operation's rehearsal result.
    let target_id = envelope_text(receipt, "target_id")?;
    non_blank(target_id, "restore.target_id").map_err(BackupClientError::Client)?;
    // The two digests are the owner's own commitments over the archive it
    // consumed and over its terminal effect receipt. They are shape-checked and
    // carried, deliberately NOT recomputed here: re-deriving them over what this
    // surface holds would replace the owner's recorded identity with a fresh
    // local value instead of checking the one the owner recorded.
    let bundle_sha256 = envelope_text(receipt, "bundle_sha256")?;
    hex64(bundle_sha256, "restore.bundle_sha256").map_err(BackupClientError::Client)?;
    let effect_receipt_sha256 = envelope_text(receipt, "effect_receipt_sha256")?;
    hex64(effect_receipt_sha256, "restore.effect_receipt_sha256")
        .map_err(BackupClientError::Client)?;
    // The level is decoded through the ONE closed owner vocabulary rather than
    // tested against a parallel string array: a level outside the set is a value
    // this surface cannot bound, and one inside it arrives carrying the
    // readiness relation `require_restore_evidence` enforces.
    let evidence_level = envelope_text(receipt, "evidence_level")?;
    if !BACKUP_RESTORE_EVIDENCE_LEVELS.contains(&evidence_level) {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    let canonical_only = envelope_flag(receipt, "canonical_only")?;
    let operational_recovery_ready = envelope_flag(receipt, "operational_recovery_ready")?;
    let cutover_performed = envelope_flag(receipt, "cutover_performed")?;
    // The phase log is the owner's own ordered record of what the journalled
    // engine applied, so it is read rather than reconstructed from the gates.
    let phase_log = envelope_gate_list(response, "phase_log")?;
    if phase_log.is_empty() {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    let journal_owner = envelope_text(response, "journal_owner")?;
    non_blank(journal_owner, "restore.journal_owner").map_err(BackupClientError::Client)?;
    let rehearsal = envelope_flag(response, "rehearsal")?;
    Ok(RestoreReceiptEvidence {
        receipt_id,
        plan_id,
        target_id,
        bundle_sha256,
        effect_receipt_sha256,
        evidence_level,
        authority: RestoreAuthorityClaim {
            canonical_only,
            rehearsal,
            beyond_rehearsal: AuthorityBeyondRehearsal::from_owner_flags(
                operational_recovery_ready,
                cutover_performed,
            ),
        },
        phase_log,
        journal_owner,
    })
}

/// Proves the COMPLETE relation between the restore owner's receipt, the
/// destination this operation admitted, and what a rehearsal is allowed to claim.
///
/// Two relations, each fail-closed, and each about a claim this surface would
/// otherwise make by omission:
///
/// - everything the RECEIPT claims about authority, through
///   [`RestoreAuthorityClaim::refusal`]: the rehearsal posture, the two flags that
///   would reach past it, the proof-level band, and the `canonical_only`/level
///   pair. That method is the only reader of every one of those decoded fields,
///   so none of them can be decoded and then carried without being related to
///   the rest of the receipt;
/// - the receipt's OWN persisted destination against the destination this
///   operation admitted ([`require_admitted_destination`]).
fn require_restore_evidence(
    evidence: &RestoreReceiptEvidence<'_>,
    params: &BackupRestoreTestParams,
) -> Result<(), UnprovenClaim> {
    // The receipt's own claims first, exactly as the owner's own
    // `RestoreReceipt::validate` orders them: readiness and cutover, then the
    // posture, then the level band, then the class/level agreement.
    if let Some(refusal) = evidence
        .authority
        .refusal(evidence.receipt_id, evidence.evidence_level)
    {
        return Err(refusal);
    }
    require_admitted_destination(evidence, params)
}

/// Requires the receipt to name the isolated destination THIS operation admitted.
///
/// A13.7 confines a rehearsal to an isolated area and the acceptance requires
/// that `restore-test` import "only into the admitted isolated destination". The
/// restore owner persists `plan.target.target_id` into every receipt it issues
/// (`RestoreReceipt::target_id`, and `validate_resumed_final_receipt` refuses a
/// resumed receipt whose `target_id` is not the current plan's), so the receipt's
/// `target_id` is the owner's own answer about where the import actually went.
///
/// It is compared against the destination the request admitted rather than
/// echoed, because a receipt that exists proves only that SOME rehearsal ran. The
/// request's `target_id` is this surface's own claim and is not authority — the
/// destination's own admission evidence is what the coordinator validated, and
/// `RESTORE_TEST_DECLARED_IDENTITY_OBLIGATION` still reports that this surface
/// proved no isolation. What this check does establish is that the receipt is
/// bound to THIS operation: a receipt naming a different destination is a
/// substituted answer and is refused rather than rendered as this command's
/// rehearsal.
fn require_admitted_destination(
    evidence: &RestoreReceiptEvidence<'_>,
    params: &BackupRestoreTestParams,
) -> Result<(), UnprovenClaim> {
    if evidence.target_id == params.target_id {
        return Ok(());
    }
    Err(UnprovenClaim {
        obligation: format!(
            "a restore receipt for the isolated destination this operation admitted ({}); the owner's receipt names {}",
            params.target_id, evidence.target_id
        ),
        reason: format!(
            "the owner returned receipt {} naming target {} while this request admitted isolated destination {}; the restore owner persists plan.target.target_id into every receipt it issues, so a receipt naming another destination is a substituted answer and is refused rather than reported as this operation's rehearsal",
            evidence.receipt_id, evidence.target_id, params.target_id
        ),
    })
}

/// Projects the restore owner's own receipt answers onto the outcome.
///
/// This writes only what the owner proved. Four of its answers map onto fields
/// this outcome already has, each for a stated reason and none by inference:
///
/// - `archive_id` is the OWNER's persisted receipt identity. The rehearsal's
///   result is a restore receipt, and that receipt is the artifact this outcome
///   actually proved — it is read out of the owner's own receipt, never
///   composed from the request.
/// - `verification_level` is the owner's own proof level in the owner's own
///   spelling, decoded through the one closed vocabulary
///   ([`BACKUP_RESTORE_EVIDENCE_LEVELS`]) and already bounded by
///   [`require_restore_evidence`].
/// - `capture_receipt` carries the same owner-issued receipt reference. The
///   field's own contract is "owner-issued reference naming the retained
///   artifact", and this IS one; it is echoed under a bounded check and is never
///   derived, defaulted, or inferred from the archive.
/// - `gates_passed` is the owner's applied PHASE log in its own execution order,
///   which is a stronger statement than the Kernel's coarser gate summary and is
///   read rather than reconstructed.
///
/// Two owner answers are deliberately NOT projected, and saying why is part of
/// the contract:
///
/// - `class_ceiling` stays `None`. The restore owner reports no capture class
///   ceiling. `canonical_only` is not promoted into one either: it is checked
///   against the owner's own derivation by
///   [`RestoreAuthorityClaim::canonical_only_pair_refusal`] and then reported as
///   the owner's own fact, so a degraded or scope import can never be rendered as
///   a full archive's evidence.
/// - `archive_fence_relation`, `archive_fence_proof` and `target_compatibility`
///   stay `None`. The receipt carries a restored fence, but this surface does not
///   re-derive a relation from it and A13.7 keeps compatibility with the isolated
///   restore owner's own validation; there is no owner answer here to echo.
fn apply_restore_receipt(
    outcome: &mut BackupOperationOutcome,
    evidence: &RestoreReceiptEvidence<'_>,
) {
    outcome.archive_id = Some(evidence.receipt_id.to_owned());
    outcome.verification_level = Some(evidence.evidence_level.to_owned());
    outcome.capture_receipt = Some(evidence.receipt_id.to_owned());
    // `clone_from` rather than `= x.clone()`: the destination already owns a
    // `Vec`, so replacing its buffer wholesale would drop the existing
    // allocation, which is the inefficiency the clone-then-assign form has.
    outcome.gates_passed.clone_from(&evidence.phase_log);
    // The remaining owner answers are reported as the receipt's own facts in the
    // bounded reason, so an operator reads WHICH archive, WHICH journal, WHICH
    // destination and WHICH archive class the receipt covers without this surface
    // minting a field for each. `canonical_only` is named here because it is the
    // owner's own statement about what kind of archive this was — semantic data
    // only, or a full archive — and an operator reading the proof level needs it
    // beside it, and it is named only because
    // [`RestoreAuthorityClaim::canonical_only_pair_refusal`] has already proved it
    // agrees with that proof level.
    outcome.reason = format!(
        "the restore owner returned receipt {} for plan {} over archive {} into isolated destination {} with effect receipt {} at evidence level {} with canonical_only={} on journal owner {}, having applied phases [{}]; the receipt reports rehearsal={} and reaches no authority beyond the rehearsal, so this is an isolated rehearsal result and not readiness or cutover",
        evidence.receipt_id,
        evidence.plan_id,
        evidence.bundle_sha256,
        evidence.target_id,
        evidence.effect_receipt_sha256,
        evidence.evidence_level,
        evidence.authority.canonical_only,
        evidence.journal_owner,
        evidence.phase_log.join(", "),
        evidence.authority.rehearsal
    );
}

/// The bounded classification ONE returned restore-test answer makes.
///
/// Today's Kernel restore-test reply carries no effect class, no proof ceiling
/// and no lifecycle-stage field: `handle_backup_restore_test` answers with the
/// base envelope plus, for a blocked rehearsal, `code`, `missing_owner`,
/// `reason`, `gates_passed` and `gates_not_admitted`
/// (`bins/eliot-kernel/src/request_dispatch.rs`). This claim is therefore graded
/// from what the reply DOES carry — its `status`, and the stage that status
/// together with the fields it is answered with actually evidences — and never
/// from a field the owner did not send. No digest, receipt or synthetic ceiling
/// is invented to make the relation look complete; the values below are the
/// protocol owners' own [`BackupStage`], [`ProofCeiling`] and [`EffectClass`]
/// members, and each arm names the strongest classification its status can
/// honestly be read as.
///
/// What bounds the `blocked` arm is [`envelope_executed_route`], not this table:
/// the band it may claim is reached only because the reply's admitted route was
/// read and checked to be disjoint from the route the owner did not admit, so
/// the ceiling is set by gates that provably ran rather than by a gate list this
/// surface restates.
///
/// What bounds the `ok` arm is [`require_restore_evidence`], and that is a
/// stronger bound than any gate list: the reply carries the restore OWNER's own
/// persisted `RestoreReceipt`, and the band is claimed only once that receipt's
/// readiness, cutover and proof-level relations have been checked against what a
/// rehearsal may report. The table says how strong a STATUS may be read; the
/// receipt decides whether this particular `ok` earned it.
struct RestoreTestClaim {
    /// Furthest lifecycle stage this answer actually evidences.
    stage: BackupStage,
    /// Strongest proof ceiling this answer may be read as.
    proof: ProofCeiling,
    /// Strongest effect class this answer may be read as.
    effect: EffectClass,
}

/// Grades one closed restore-test `status` into the bounded claim it may make.
///
/// The status is the only classification-bearing value the reply carries, so it
/// is the whole of the grading input, and each arm states why that status
/// evidences that much and no more. A status outside the graded closed set is a
/// typed result mismatch here, exactly as in [`envelope_status`]: a status this
/// surface cannot name is a status it cannot bound.
///
/// The `blocked` arm is additionally gated on the reply's OWN executed route
/// rather than on the status token alone, and that is what keeps this table from
/// being today's hard-coded limited state standing in for a structural check.
/// A `blocked` answer is graded at the candidate band only when the owner both
/// admitted at least one gate AND named at least one gate it did not admit: the
/// first is what earns the band and the second is what caps it. A `blocked`
/// reply that claims an empty not-admitted set is saying it refused while
/// admitting its whole route, and there is no reading of that which supports any
/// band above the observation floor, so it is refused rather than rendered at a
/// ceiling the owner's own answer contradicts.
///
/// The `ok` arm deliberately does NOT require a not-admitted gate the way
/// `blocked` does: a COMPLETED rehearsal is bounded by its receipt, not by a
/// shortfall. Its two owner-held gates stay reported as outstanding
/// obligations beside the result, so the band still stops at candidate — but a
/// missing gate is no longer what earns it.
fn restore_test_claim(
    status: &str,
    executed_route: Option<&ExecutedRoute<'_>>,
) -> Result<RestoreTestClaim, BackupClientError> {
    let claim = match status {
        // The rehearsal's shape gates ran for real and the reply enumerates the
        // ones that did, so this answer is bounded by exactly the band the
        // catalogue row declares: a candidate-shaped rehearsal with no owner
        // evidence behind it. A plan gap is the ABSENCE of a named owner, never
        // a lifecycle advance, so the evidenced stage stays `Requested` even
        // though the admitted gates passed. The gates the owner did NOT admit
        // are reported as obligations, not folded into this ceiling — they are
        // the reason the band stops where it does.
        BACKUP_STATE_BLOCKED => {
            let route =
                executed_route.ok_or(BackupClientError::Client(CliError::ResultMismatch))?;
            if route.not_admitted.is_empty() {
                return Err(BackupClientError::Client(CliError::ResultMismatch));
            }
            RestoreTestClaim {
                stage: BackupStage::Requested,
                proof: ProofCeiling::CandidateArtifact,
                effect: EffectClass::Candidate,
            }
        }
        // The owner's OWN persisted receipt is the whole basis of this arm, and
        // it is why `ok` is graded differently from a bare successful exit. The
        // Kernel reaches the journalled restore coordinator and returns
        // `rehearsed_reply` with the coordinator's own `RestoreReceipt`, so an
        // `ok` here means the isolated rehearsal really ran on the
        // composition-owned durable ORS journal under an owner-issued admission
        // and the owner persisted a receipt for it. That receipt is evidence the
        // blocked arm does not have, so this arm is graded at the candidate
        // band the catalogue row declares — the SAME band the blocked arm gets,
        // and deliberately no higher:
        //
        // - it is not `ScopedVerification`. A rehearsal receipt proves an
        //   isolated import, not a verified archive of the live installation, and
        //   I5.13 keeps backup existence from being recovery proof.
        // - `RehearsalComplete` is not claimed either, because
        //   `BackupStage::can_advance(Requested, RehearsalComplete)` is false on
        //   the protocol's own one-edge ladder: this command enters at the
        //   restore phases and never advanced through `Captured` or `Verified`,
        //   so the owner proved a restore result, not the capture ladder.
        //   `require_restore_test_ceiling` checks exactly this, so a future
        //   over-claim here is refused rather than rendered.
        //
        // The claim is not a promise that every gate ran: it is the strongest
        // reading the owner's receipt supports. `cutover-qualification` and the
        // destination-manifest admission are reported as not-admitted
        // obligations beside it, which is why the band stops at candidate.
        BACKUP_WIRE_OK => RestoreTestClaim {
            stage: BackupStage::Requested,
            proof: ProofCeiling::CandidateArtifact,
            effect: EffectClass::Candidate,
        },
        // Every other admitted status — an invalid request, a refusal, a
        // cancellation — reports that this operation did not run to any proven
        // lifecycle step. Under-claiming an effect is the safe direction of that
        // error: it can never report a mutation the owner did not state, and it
        // can never lift a cancelled answer into a proven one. A successful exit
        // is also not restore proof, which is why `ok` is NOT in this arm: it is
        // the one status whose reply carries the owner's own receipt, and
        // grading it here would throw that receipt away.
        BACKUP_STATE_INVALID | BACKUP_STATE_REFUSED | BACKUP_STATE_CANCELLED => RestoreTestClaim {
            stage: BackupStage::Requested,
            proof: ProofCeiling::Observation,
            effect: EffectClass::Read,
        },
        _ => return Err(BackupClientError::Client(CliError::ResultMismatch)),
    };
    Ok(claim)
}

/// Checks the COMPLETE relation between one graded restore-test answer and the
/// catalogue row this operation is declared under.
///
/// The three closed vocabularies are the protocol owners' own, so this is a
/// comparison between real returned classification and the real declared
/// ceiling rather than a local restatement of it: [`ProofCeiling::is_at_most`]
/// bounds the proof reading, `EffectClass`'s own ordering bounds the effect
/// reading, and [`BackupStage::can_advance`] bounds the lifecycle reading to
/// the legal edges of the one ladder that owns those stages. The declared pair
/// is the same [`catalogued_ceiling`] row the projection above reports, so a
/// catalogue edit that reclassifies this command changes what is admitted
/// instead of silently diverging from it.
///
/// An answer outside the declared ceiling is refused as this operation's typed
/// refusal naming the exact relation that refused it — never rendered at the
/// level it claimed, and never reported as a mismatch that hides whether the
/// owner over-claimed or merely answered in a shape this surface does not know.
fn require_restore_test_ceiling(
    claim: &RestoreTestClaim,
    status: &str,
    declared_effect: EffectClass,
    declared_proof: ProofCeiling,
) -> Result<(), UnprovenClaim> {
    if !claim.proof.is_at_most(declared_proof) {
        return Err(UnprovenClaim {
            obligation: format!(
                "a {status} answer to {BACKUP_RESTORE_TEST_OPERATION} whose strongest proof reading is at most {declared_proof:?} (absent from the owner's own answer: it reads as {:?})",
                claim.proof
            ),
            reason: format!(
                "owner answered {status} to {BACKUP_RESTORE_TEST_OPERATION} with a proof reading of {:?}, which is above the proof ceiling {:?} the catalogue declares for this command; an answer above the declared ceiling is refused rather than rendered",
                claim.proof, declared_proof
            ),
        });
    }
    if claim.effect > declared_effect {
        return Err(UnprovenClaim {
            obligation: format!(
                "a {status} answer to {BACKUP_RESTORE_TEST_OPERATION} whose strongest effect reading is at most {declared_effect:?} (absent from the owner's own answer: it reads as {:?})",
                claim.effect
            ),
            reason: format!(
                "owner answered {status} to {BACKUP_RESTORE_TEST_OPERATION} with an effect reading of {:?}, which is above the effect class {:?} the catalogue declares for this command; an isolated rehearsal reaches no effect its own row does not declare",
                claim.effect, declared_effect
            ),
        });
    }
    // A rehearsal starts at the requested stage: there is no ladder edge below
    // it, and the only stage this operation can never prove is an admitted
    // cutover, because this surface never asks for one and the Kernel method
    // has no cutover path.
    if !BackupStage::can_advance(BackupStage::Requested, claim.stage) {
        return Err(UnprovenClaim {
            obligation: format!(
                "a lifecycle stage this surface may render for {BACKUP_RESTORE_TEST_OPERATION}, reached by a legal advance from {:?} (absent from the owner's own answer: it reads as {:?})",
                BackupStage::Requested,
                claim.stage
            ),
            reason: format!(
                "owner answered {status} to {BACKUP_RESTORE_TEST_OPERATION} with lifecycle stage {:?}, which is not an advance of this operation's ladder from {:?}; cutover is a separate authority (A13.7) and a rehearsal never reaches it, so a stage above that ladder is refused rather than rendered",
                claim.stage,
                BackupStage::Requested
            ),
        });
    }
    Ok(())
}

/// This surface's own declaration obligation, reported beside the Kernel's
/// owner name when a restore-test rehearsal comes back `blocked`.
///
/// The `source:` and `destination:` lines of the human projection are exactly
/// what the request declared, and no owner provisioned that isolated
/// destination, admitted the durable journal, or issued either identity. The
/// field contract already admits a field-level obligation, so this fixed
/// bounded string states that obligation where an operator reads it, instead
/// of adding a new field to an outcome shared with create and verify. It is
/// not an owner answer, not a receipt, and it never mints an identity.
const RESTORE_TEST_DECLARED_IDENTITY_OBLIGATION: &str = "request-declared source and destination identities are not owner-provisioned or owner-admitted";

/// Prefix of the per-gate obligation reported for a gate the owner did NOT
/// admit, one entry per such gate.
///
/// The Kernel's `gates_not_admitted` names gates it did not run; each becomes
/// its own bounded `missing_obligation` so an operator reads which gate is
/// outstanding rather than being told only that "some" owner-held gate was
/// deferred. It is phrased as an obligation, not as a failure: the gate did not
/// run because the owner state it needs does not exist yet, and the projection
/// must not read as though the owner rejected it.
const RESTORE_TEST_GATE_OBLIGATION: &str = "rehearsal gate not admitted by any owner";
