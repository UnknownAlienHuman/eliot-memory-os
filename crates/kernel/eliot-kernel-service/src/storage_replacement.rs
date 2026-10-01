//! I5.11 storage replacement: the Kernel-owned `canonical_store` cutover
//! coordinator (issue #1872).
//!
//! Architecture traceability: `I5.11`
//! (`docs/architecture/I05-11-storage-replacement.md`) requires a candidate
//! store bridge to be installed, a snapshot imported, counts/hashes and
//! graph/projection invariants verified, both stores shadow-read, canonical
//! events tailed, affected writes quiesced, the final sequence reconciled, the
//! `canonical_store` `CapabilityRouteScope` cutover committed through the
//! Kernel Generation Registry, reads/writes canaried, the old store kept
//! read-only for a rollback window, and the old store retired only after backup
//! and a cutover receipt. `I5.11` also states the rollback rule this module
//! enforces: rollback switches generation back only if no irreversible
//! migration/effect occurred; otherwise it uses forward repair.
//!
//! `I5.10` names `ECXF/1` as the logical transfer format and states that an
//! export is tied to an `ExportFence`. [`StorageReplacementTransfer`] is the
//! typed record of one such exchange: the format identity, the digest of the
//! exact exported bytes, and the digest of the export fence the bytes were
//! taken at. The two stages that move data — I5.11 stage 2 and stage 5 — cannot
//! be recorded without it, and the cutover receipt binds it.
//!
//! `I14.14` owns the `CapabilityRouteScope`, the durable cutover record, the
//! in-flight disposition set, the rollback boundary and the receipt, and states
//! that the ORS commit is the durable linearization point while an irreversible
//! state migration requires forward repair or a separately proven rollback
//! path. `A13.3` supplies the promotion contour (shadow, bounded canary, active
//! generation, drain and retire or forward rollback) this module orders.
//!
//! ## Ordered stages
//!
//! ```text
//! install candidate store bridge
//!   -> import snapshot into candidate          (records its ECXF transfer)
//!   -> verify counts, hashes, graph/projection invariants
//!   -> shadow reads against both stores
//!   -> tail canonical events into candidate    (records its ECXF transfer)
//!   -> quiesce affected writes
//!   -> reconcile final sequence
//!   -> commit the canonical_store CapabilityRouteScope cutover through ORS
//!   -> canary reads/writes
//!   -> keep old store read-only for rollback window
//!   -> retire only after backup and cutover receipt
//! ```
//!
//! ## Division of responsibility
//!
//! ```text
//! Owner                           Evidence
//! ------------------------------- -------------------------------------------
//! This module (`StorageReplacement`) the I5.11 stage machine, the required
//!                                 ECXF transfer records, the per-stage
//!                                 recorded evidence, the irreversible-effect
//!                                 ledger and the cutover receipt
//! ORS (`eliot_ors`)               the committed `GenerationCutoverOwnership`
//!                                 row this coordinator re-derives its receipt
//!                                 from, its `GenerationCutoverOwnershipReceipt`,
//!                                 the in-flight dispositions, the route
//!                                 snapshot and the route-scope hash
//! Store / candidate bridge        the exported bytes and export fence, the
//!                                 imported snapshot, the verification and
//!                                 shadow-read comparison, the canary result,
//!                                 the read-only rollback window and the backup
//! ```
//!
//! ## Negative: the candidate cannot become canonical except through this
//! ## coordinator's receipt
//!
//! Established by this module:
//!
//! - The route scope is pinned *to the live Store route*. [`canonical_store_route_scope`]
//!   is the only scope a replacement is ever bound to; it is declared once
//!   through [`CapabilityRouteScope::declare`] and is never supplied by a
//!   caller, so no other four-tuple carrying the `canonical_store` capability
//!   string is reachable. Its module coordinate is
//!   [`CANONICAL_STORE_MODULE_ID`], which is [`crate::STORE_ROUTE_IDENTITY`] —
//!   the one route identity the Store bridge is registered and routed under —
//!   and not a literal. That matters because `declare` validates the *shape* of
//!   a four-tuple, never that the route is one anything uses: a scope pinned to
//!   a module id no live route carries still declares cleanly, but its
//!   `route_scope_hash` is then a key no committed cutover row could ever carry,
//!   [`committed_canonical_store_cutovers`] drops every real store cutover when
//!   filtering on it, [`canonical_store_route_owner`] answers `None` even after
//!   a genuine cutover committed, and the gateway's route gate admits the
//!   incumbent unchanged. Pinning the coordinate to the real route identity is
//!   what makes the gate below bind to the route rather than to a scope of this
//!   module's own invention.
//! - The cutover receipt is re-derived from ORS rather than asserted by a
//!   caller. [`StorageReplacement::commit_canonical_store_route_cutover`] loads
//!   the `GenerationCutoverOwnership` from the durable [`RedbRecoveryStore`] by
//!   its cutover identity and refuses anything that is not a committed row, so a
//!   hand-built record with a synthetic `state` and
//!   `linearization_record_id` can never reach a receipt.
//! - The receipt is a serializable, deny-unknown-fields record whose
//!   [`StorageReplacementCutoverReceipt::validate`] runs on the construction
//!   path before the coordinator stores it.
//! - A restart cannot silently reopen a closed rollback path.
//!   [`StorageReplacement::begin`] refuses a candidate generation that already
//!   owns the route through a committed cutover, and
//!   [`StorageReplacement::resume_after_committed_cutover`] reconstructs a
//!   replacement from the durable cutover receipt plus the ORS-committed record
//!   that receipt names, restoring the irreversible-effect ledger fixed at the
//!   cutover.
//! - A rollback cannot be obtained by presenting a *fresh* cutover frame either.
//!   The durable irreversibility decision is read on the switch itself, not only
//!   on the operation that reports a rollback: see
//!   [`StorageReplacement::refuse_unproven_generation_rollback`] and the Rollback
//!   section below.
//! - The two data-transfer stages cannot be recorded without the transfer
//!   record that binds the exact exported bytes and their export fence, and the
//!   cutover receipt binds that transfer, so a cutover cannot be proven against
//!   bytes the coordinator never saw.
//! - After a committed cutover, the Store gateway admits nothing against the
//!   incumbent generation. [`canonical_store_route_owner`] is the read side of
//!   the same committed row, and
//!   `KernelStoreGateway::require_active_store_generation` refuses every Store
//!   read and write — including the two that carry no caller fence and the
//!   borrowed client contour that reaches the retained client directly — unless
//!   this gateway's generation *is* the durable route's owner. A
//!   gateway for a non-owner generation can therefore be built and retained by
//!   any composition path, but it is not a writer or a reader of the canonical
//!   store, so the incumbent is served by nobody while the `I5.11` stage-10
//!   window is open, and only another committed cutover can serve it again.
//! - **Before** any cutover is committed, the durable owner still names one
//!   generation. The composition root establishes that owner once, through
//!   [`establish_canonical_store_route_owner`], before any Store gateway
//!   exists, so the initial state of every installation means "only the
//!   recorded initial generation" rather than "anything goes". That is what
//!   closes the configuration and restart legs of the negative in the
//!   pre-first-commit window: once the row exists, an operator who installs and
//!   activates an approved package generation carrying a NEW store bridge still
//!   reaches a gateway whose generation the durable owner does not name, and it
//!   is refused canonical reads and writes by the same gate that refuses a
//!   cut-over incumbent. Be precise about the one step in front of that: the
//!   writer is only reached when the durable owner answers `None`, so on an
//!   installation whose ORS predates this record the first composition writes
//!   whatever generation the Host descriptor then names. There is no earlier
//!   durable evidence to migrate that answer from, and the writer is
//!   write-once, so from the second composition onward the recorded name is the
//!   only one that can serve.
//!
//! - A candidate store bridge is admitted as a canonical Store **writer** only
//!   through the durable route owner. [`StorageReplacement::canonical_store_writer_admission`]
//!   reads [`canonical_store_route_owner`] — the ORS-backed owner, never the
//!   caller's claim or the composition's in-memory route snapshot — and admits
//!   only the generation that owner names, returning the typed
//!   [`CanonicalStoreWriterRefusal`] otherwise. The production composition
//!   connect
//!   (`bins/eliot-kernel/src/canonical_store_runtime.rs::KernelComposition::connect_canonical_store_inner`)
//!   consults it before it builds or retains a `KernelStoreGateway`, so an
//!   approved-but-uncommitted candidate bridge is never connected at all rather
//!   than connected and left to fail at its first Store operation. That is the
//!   difference the read/write gate cannot make on its own: refusing an
//!   operation is not the same as never holding the writer.
//!
//! **Not** established by this module, and stated here so no reader mistakes
//! this file for a safety net it is not:
//!
//! - The writer admission is enforced at the composition connect path only.
//!   `KernelComposition::rebind_store` (`bins/eliot-kernel/src/lib.rs`) is the
//!   second production `KernelStoreGateway::new` site; it mints its own
//!   unrelated `StoreRebindReceipt` and does not yet consult this admission, so
//!   a rebind to a non-owner generation is still stopped by the Store-layer
//!   route gate ([`StorageReplacement::canonical_store_writer_admission`] is the
//!   call it needs) rather than at construction. The row that names the owner after a cutover
//!   is written by the Kernel Generation Registry ingress
//!   (`bins/eliot-kernel/src/generation_control.rs::apply_authenticated_generation_cutover`)
//!   for exactly a completed replacement this coordinator re-derives through
//!   [`StorageReplacement::replay_recorded_stages`] and then re-derives its
//!   receipt from through [`StorageReplacement::commit_canonical_store_route_cutover`].
//!   The owner a composition establishes before that first cutover names no
//!   stage, no epoch transition and no receipt, and is replaced by that cutover
//!   and by nothing else.
//! - A cutover is still *committed* by the Kernel Generation Registry's owner,
//!   which writes the ORS `CUTOVER_OWNERSHIP` row — for this route, that owner is
//!   the admitted cutover ingress
//!   (`bins/eliot-kernel/src/generation_control.rs::apply_authenticated_generation_cutover`),
//!   and it writes the row only for a completed replacement this coordinator
//!   re-derives. This coordinator stages, orders and proves the replacement and
//!   re-derives its receipt from that row; it does not write it.
//! - The read-only rollback window (stage 10) is enforced on the Kernel side:
//!   once the cutover is committed the incumbent generation is not the active
//!   `canonical_store` generation, so the governed Store path admits nothing
//!   against it. What this module does not do is stop the Host or the retired
//!   Store process from serving that generation to a reader outside the Kernel
//!   gateway; `I5.11` names no mechanism for that, so it is not invented here.
//! - A stage's evidence is bounded opaque text, plus the transfer record for the
//!   two transferring stages. This module orders and records stages; it does not
//!   perform the import, verification, shadow read, tail, reconciliation, canary
//!   or backup, and it interprets no store payload.
//! - The per-stage evidence recorded before a cutover is not durable material
//!   and is not reconstructed by a resumed replacement; the durable material is
//!   the ORS-committed record and the cutover receipt.
//!
//! ## Typed ORS refusals
//!
//! [`RedbRecoveryStore`], [`GenerationCutoverOwnershipReceipt::from_committed`]
//! and [`CapabilityRouteScope::validate`] fail with a typed [`OrsError`], and
//! this module classifies every class of it onto the existing
//! [`KernelServiceError`] variants by class. A fence mismatch, an epoch-lineage
//! break, a stale writer epoch, a duplicate conflict, an invalid transition, a
//! field rejection and an unavailability therefore stay distinguishable at the
//! Kernel service boundary; only the classes that are text in the source type
//! reach [`KernelServiceError::Platform`]. No ORS class is collapsed into a
//! string or a generic code between the layers.
//!
//! ## Rollback
//!
//! [`StorageReplacement::rollback_disposition`] is a pure classifier over the
//! recorded irreversible effects. [`StorageReplacement::request_rollback`]
//! enforces it, and it does not decide from that ledger alone: it reloads the
//! ORS-committed cutover ownership row its own receipt names, and a row that
//! already records a forward-repair-required state migration refuses the request
//! even when the in-process ledger is silent, so the durable record of
//! irreversibility is the authority and the caller cannot obtain a permitted
//! generation rollback by declining to record an effect. While no irreversible
//! effect is recorded the generation rollback is admitted (and the route switch
//! itself is another committed cutover with a newer epoch, never a local flag
//! flip); once one is recorded the request is refused as
//! [`KernelServiceError::GenerationFenced`] and only the explicit forward-repair
//! path follows. A post-cutover irreversible effect is not yet in the committed
//! row and the ledger does not survive a restart; that residual gap is stated on
//! [`StorageReplacement::request_rollback`] and named there as the `I5.14`
//! durable-effect-ledger owner's, because inventing a second durable store for
//! it here would be a second canonical path beside the one that already exists.
//!
//! Reporting a rollback is not the same operation as performing one, so the same
//! rule is also gated where the route actually moves:
//! [`StorageReplacement::refuse_unproven_generation_rollback`] reads EVERY
//! committed row of the pinned route scope, not only its newest one, and refuses
//! a switch whose candidate generation is at or behind the `new_generation` of
//! any row recording a [`StateMigrationDecision::ForwardRepairRequired`]
//! decision — before the Kernel Generation Registry writes that cutover's own
//! row and before it asks the semantic gateway to switch. A refusal reported by
//! [`StorageReplacement::request_rollback`] while the live route keeps serving
//! the candidate proves nothing about the route; this is the gate that holds it.
//! Its decision is the durable history's, so a caller's own `migration` field
//! cannot mask a committed decision — neither by presenting
//! `migration: RetainCompatible` for its own row, nor by first committing an
//! ordinary forward cutover whose own row then reads as the newest decision.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use eliot_contracts::ResourceGeneration;
use eliot_ors::{
    CanonicalStoreRouteOwnership, CapabilityRouteScope, CutoverRouteSnapshot,
    GenerationCutoverOwnership, GenerationCutoverOwnershipReceipt, MAX_RECOVERY_PAGE, OrsError,
    RedbRecoveryStore, StateMigrationDecision,
};
use eliot_runtime_contracts::GenerationCutoverState;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{KernelServiceError, validate_text};

/// The capability whose route this coordinator is bound to.
///
/// A replacement is refused for any other capability: the I5.11 stage machine
/// governs the canonical Store route, not an arbitrary module capability.
pub const CANONICAL_STORE_CAPABILITY: &str = "canonical_store";

/// The pinned owning module identity of the canonical store capability route.
///
/// It names the store bridge whose generation this coordinator switches, and it
/// is the crate's existing [`crate::STORE_ROUTE_IDENTITY`] rather than a literal
/// declared here. That is the whole point of reusing it: this coordinate is
/// compared against `record.scope.module_id` of the committed ORS
/// `GenerationCutoverOwnership` row and its value is what
/// [`CapabilityRouteScope::declare`] hashes into `route_scope_hash`, which is
/// the key every committed row is filtered on by
/// [`committed_canonical_store_cutovers`]. A literal here that no live route
/// uses would still declare a scope successfully — `declare` validates shape,
/// not that the route exists — while producing a `route_scope_hash` that no
/// committed cutover could ever carry. The listing would then drop every real
/// store cutover, [`active_canonical_store_generation`] would answer `None`
/// even after a real cutover committed, and
/// `KernelStoreGateway::require_active_store_generation` would admit the
/// incumbent unchanged. Binding the coordinate to the one route identity the
/// Store bridge is actually registered and routed under is what makes the
/// negative hold rather than merely compile.
pub const CANONICAL_STORE_MODULE_ID: &str = crate::STORE_ROUTE_IDENTITY;

/// The pinned work scope of the canonical store capability route.
///
/// It is one of the four coordinates of [`canonical_store_route_scope`] and is
/// fixed here rather than chosen by a caller.
pub const CANONICAL_STORE_WORK_SCOPE: &str = "work";

/// The pinned effect domain of the canonical store capability route.
///
/// It is one of the four coordinates of [`canonical_store_route_scope`] and is
/// fixed here rather than chosen by a caller.
pub const CANONICAL_STORE_EFFECT_DOMAIN: &str = "effects";

/// The `I5.10` logical transfer format used for the snapshot import and the
/// canonical event tail.
///
/// It is the format identity every [`StorageReplacementTransfer`] must name.
pub const STORAGE_REPLACEMENT_TRANSFER_FORMAT: &str = "ECXF/1";

/// Declares the one `canonical_store` `CapabilityRouteScope` this coordinator
/// is bound to.
///
/// The four coordinates are declared here and the stable route-scope hash is
/// bound by [`CapabilityRouteScope::declare`]; no caller supplies a scope and
/// no route-scope hash is hand-computed. Every replacement, receipt and
/// ORS-committed record this module accepts is checked against this hash.
pub fn canonical_store_route_scope() -> Result<CapabilityRouteScope, KernelServiceError> {
    CapabilityRouteScope::declare(
        CANONICAL_STORE_MODULE_ID,
        CANONICAL_STORE_CAPABILITY,
        CANONICAL_STORE_WORK_SCOPE,
        CANONICAL_STORE_EFFECT_DOMAIN,
    )
    .map_err(|error| ors_refusal(&error))
}

/// Resolves the store generation a committed `I5.11` stage-8 cutover left
/// owning the pinned `canonical_store` capability route.
///
/// This is the read side of the stage-8 cutover alone. It answers through the
/// *existing* admitted owner rather than a rule of its own: the committed ORS
/// `CUTOVER_OWNERSHIP` rows are handed to [`CutoverRouteSnapshot::rebuild`], the
/// same reconstruction the Kernel's own recovery performs
/// (`bins/eliot-kernel/src/generation_recovery.rs::recover_cutover_ownership`), and
/// the active generation is read back from that snapshot's entry for the pinned
/// route-scope hash. The strictly newest committed epoch therefore wins, exactly
/// as `I14.14` requires ("rollback is another cutover with a newer epoch; an old
/// epoch is never reactivated"), and a pre-commit `Armed` candidate cannot
/// appear because the listing itself returns committed rows only. `None` means
/// no committed cutover has ever switched this route — not that this route has
/// no owner. The owner in every installation state is
/// [`canonical_store_route_owner`], which falls back to the established owner of
/// this scope so that the pre-first-commit window is decided by durable evidence
/// rather than by the composition's own ordering argument.
///
/// Every Store read and write is admitted against that owner rather than a
/// composition-fixed route snapshot. After a committed cutover the incumbent
/// generation is therefore no longer the owner, and the governed path can
/// neither read nor write it — which is what lets the old store stay
/// read-only for the `I5.11` stage-10 rollback window.
///
/// The read is bounded by [`MAX_RECOVERY_PAGE`], the bound ORS itself applies
/// to this listing, and ORS reports [`OrsError::ProjectionLimitExceeded`]
/// rather than truncating once the committed cutover rows reach it. That refusal
/// reaches the caller, so a route table grown past the bound closes this gate
/// instead of silently answering from a prefix. The bound is not raised here:
/// the listing belongs to the existing owner, and a second, larger read beside
/// it would be a second way to answer the same question.
pub fn active_canonical_store_generation(
    ors: &RedbRecoveryStore,
) -> Result<Option<ResourceGeneration>, KernelServiceError> {
    let scope = canonical_store_route_scope()?;
    let committed = committed_canonical_store_cutovers(ors, &scope)?;
    Ok(CutoverRouteSnapshot::rebuild(&committed)
        .map_err(|error| ors_refusal(&error))?
        .entry(&scope.route_scope_hash)
        .map(|entry| entry.active_generation))
}

/// Committed cutover ownership rows that belong to exactly the pinned
/// `canonical_store` route scope.
///
/// Rows of other capability routes are dropped before the snapshot is rebuilt,
/// so another module's committed cutover can neither answer this route's
/// question nor close this gate; the winner rule stays the snapshot's.
///
/// An ORS database written before the optional `CUTOVER_OWNERSHIP` table
/// existed reports the absence through [`OrsError::Storage`] rather than an
/// empty listing. Absence is a fact about the database, not about a route: the
/// table is created by the first staged cutover, so an absent one means no
/// cutover has ever been committed and therefore that no candidate generation
/// can own this route. This is the same compatibility reading the Kernel's own
/// recovery boundary makes (`bins/eliot-kernel/src/generation_recovery.rs`),
/// which notes that ORS exposes the absence only as a typed storage message and
/// therefore keeps the test at its own boundary; it is repeated here for the
/// same stated reason and is not a second rule. Any other storage refusal, and
/// every typed ORS class, still reaches the caller unchanged.
fn committed_canonical_store_cutovers(
    ors: &RedbRecoveryStore,
    scope: &CapabilityRouteScope,
) -> Result<Vec<GenerationCutoverOwnership>, KernelServiceError> {
    let committed = match ors.latest_committed_cutover_ownership(MAX_RECOVERY_PAGE) {
        Ok(committed) => committed,
        Err(error) if is_absent_cutover_ownership_table(&error) => return Ok(Vec::new()),
        Err(error) => return Err(ors_refusal(&error)),
    };
    Ok(committed
        .into_iter()
        .filter(|record| record.scope.route_scope_hash == scope.route_scope_hash)
        .collect())
}

/// Whether an ORS refusal is only the absence of the optional cutover
/// ownership table in a database that predates it.
///
/// ORS exposes the absence through its typed storage text and no other class,
/// so the message is matched exactly. A present table whose contents fail
/// validation is not this, and stays a refusal.
fn is_absent_cutover_ownership_table(error: &OrsError) -> bool {
    matches!(
        error,
        OrsError::Storage(message)
            if message.contains("Table 'ors_cutover_ownership_v1' does not exist")
    )
}

/// Whether an ORS refusal is only the absence of the optional established
/// route-owner table in a database that predates it.
///
/// The same compatibility reading as
/// [`is_absent_cutover_ownership_table`], for the same stated reason: the table
/// is materialised by the first composition that establishes the owner, so its
/// absence is a fact about the database and means only that no owner was ever
/// established. Every other storage refusal and every typed ORS class still
/// reaches the caller unchanged.
fn is_absent_route_ownership_table(error: &OrsError) -> bool {
    matches!(
        error,
        OrsError::Storage(message)
            if message.contains("Table 'ors_canonical_store_route_ownership_v1' does not exist")
    )
}

/// The generation that owns the pinned `canonical_store` capability route.
///
/// This is the question `I5.11` stage 8 decides and the question every Store
/// read and write is admitted against. It is answered through the existing
/// admitted owner and through nothing else:
///
/// 1. a committed `I5.11` stage-8 cutover for the pinned route scope, read
///    exactly as [`active_canonical_store_generation`] reads it — the strictly
///    newest committed epoch wins, and a pre-commit `Armed` candidate cannot
///    appear because the listing returns committed rows only; then
/// 2. the established owner of that same route scope,
///    [`CanonicalStoreRouteOwnership`], which is the record of the generation
///    the scope started at.
///
/// The second answer is what closes the pre-first-commit window. Without it,
/// "no committed cutover" is indistinguishable from "any generation may serve",
/// and that is the initial state of every installation, so an approved but
/// uncommitted candidate bridge could serve canonical reads and writes with no
/// stage evidence at all. With it, the initial state names exactly one
/// generation, and the only thing that may replace that name is a committed
/// `I5.11` stage-8 cutover — the one transition this coordinator exists to
/// govern.
///
/// `Ok(None)` now means only that no owner was ever established AND no cutover
/// was ever committed for this scope, which is the state of a database that has
/// not been composed by this build yet. It is not reachable on a composed
/// installation, because composition establishes the owner before any Store
/// gateway exists.
pub fn canonical_store_route_owner(
    ors: &RedbRecoveryStore,
) -> Result<Option<ResourceGeneration>, KernelServiceError> {
    if let Some(active) = active_canonical_store_generation(ors)? {
        return Ok(Some(active));
    }
    let scope = canonical_store_route_scope()?;
    let recorded = match ors.load_canonical_store_route_ownership(scope.route_scope_hash.as_str()) {
        Ok(recorded) => recorded,
        Err(error) if is_absent_route_ownership_table(&error) => None,
        Err(error) => return Err(ors_refusal(&error)),
    };
    Ok(recorded.map(|record| record.initial_generation))
}

/// Records, exactly once, that `initial_generation` is the approved initial
/// owner of the pinned `canonical_store` capability route scope.
///
/// This is the composition's half of the pre-first-commit window, and it is
/// deliberately write-once. The row it writes names a route scope that has never
/// been switched, so it carries no epoch transition, no in-flight disposition
/// set and no linearization identity, and it is not a cutover receipt. The
/// [`RedbRecoveryStore::commit_canonical_store_route_ownership`] writer refuses
/// a *different* generation for the same scope, so a configuration change or a
/// restart cannot move the owner of an un-cut-over route: re-presenting the
/// identical row is idempotent, and only a committed `I5.11` stage-8 cutover for
/// the same scope can change the answer [`canonical_store_route_owner`] gives.
///
/// The scope is this module's own pinned
/// [`canonical_store_route_scope`], and the writer re-validates its recorded
/// `route_scope_hash` against the key it is stored under, so no caller supplies
/// a scope and no scope hash is hand-computed.
pub fn establish_canonical_store_route_owner(
    ors: &RedbRecoveryStore,
    initial_generation: ResourceGeneration,
) -> Result<ResourceGeneration, KernelServiceError> {
    let scope = canonical_store_route_scope()?;
    scope.validate().map_err(|error| ors_refusal(&error))?;
    let record = CanonicalStoreRouteOwnership {
        route_scope_hash: scope.route_scope_hash,
        initial_generation,
    };
    ors.commit_canonical_store_route_ownership(&record)
        .map_err(|error| ors_refusal(&error))?;
    Ok(initial_generation)
}

/// The durable-owner admission that lets one candidate generation be connected
/// as a live canonical Store writer.
///
/// It is returned only by [`StorageReplacement::canonical_store_writer_admission`]
/// and only when the durable `canonical_store` route owner names that exact
/// generation. Carrying the owner generation makes the grant self-describing at
/// the composition boundary: the caller records which owner admitted it, so an
/// admitted connection is auditable without re-reading ORS. The scope is not
/// carried because it is this module's own pinned
/// [`canonical_store_route_scope`] and is never caller-supplied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalStoreWriterAdmission {
    /// The generation the durable route owner names, which is necessarily the
    /// candidate the caller asked to connect.
    pub durable_owner_generation: ResourceGeneration,
}

/// Why one candidate canonical Store generation may not be connected as a live
/// canonical Store writer.
///
/// This is the refusal half of
/// [`StorageReplacement::canonical_store_writer_admission`]. It is a separate
/// type rather than a bare `bool` so the two refusable facts stay apart: an
/// owner that could not be READ is not an owner that says no, and an owner that
/// names a different generation is not the absence of an owner. Each arm also
/// carries the generations it decided between, because the decision is only
/// auditable when the candidate that was refused and the generation that holds
/// the route are both visible, and the composition's own route snapshot
/// descends from the same Host descriptor as the candidate and therefore
/// cannot supply that contrast by itself.
///
/// [`A0.3`](docs/architecture/A00-03-hard-boundaries.md) lists "a second
/// ungoverned canonical owner or write path" in its fail-closed class, so no
/// arm of this type falls back to admitting the candidate.
// Only `Debug` is derived: the first arm carries a [`KernelServiceError`], and
// that enum is deliberately neither `Clone` nor comparable, so a refusal stays
// a single owned decision rather than a value that could be duplicated or
// compared into admitting.
#[derive(Debug)]
pub enum CanonicalStoreWriterRefusal {
    /// The durable route owner could not be read at all.
    ///
    /// The typed ORS refusal travels with it unchanged, so an unavailability
    /// stays distinguishable from an ownership answer across the layer
    /// boundary instead of collapsing into one string.
    DurableRouteOwnerUnreadable {
        /// The typed ORS refusal the durable owner read produced.
        source: KernelServiceError,
    },
    /// No owner is established for the pinned route scope and no committed
    /// cutover names one, so no generation is provably the canonical writer.
    ///
    /// On a composed installation this state is unreachable, because
    /// composition establishes the owner before any Store gateway exists
    /// ([`establish_canonical_store_route_owner`]). It is the state of a
    /// database this build has not composed, and it is refused rather than
    /// treated as "any generation may serve".
    NoDurableRouteOwner {
        /// The candidate generation the composition asked to connect.
        candidate_generation: ResourceGeneration,
    },
    /// The durable owner names a different generation than the candidate.
    ///
    /// This is the shape an approved-but-uncommitted candidate store bridge
    /// takes: the Host descriptor activated a new package generation, the route
    /// was rebuilt from it, and the durable pin stayed at the incumbent. A
    /// cut-over incumbent reaches the same arm for the same reason.
    NotTheDurableRouteOwner {
        /// The candidate generation the composition asked to connect.
        candidate_generation: ResourceGeneration,
        /// The generation the durable `canonical_store` route owner names.
        durable_owner_generation: ResourceGeneration,
    },
}

impl CanonicalStoreWriterRefusal {
    /// The bounded reason code for this refusal, safe for a diagnostic line.
    ///
    /// It names WHICH fact was missing — an unreadable owner, an absent owner,
    /// or a different owner — without carrying any generation or ORS material,
    /// so the three refusable facts stay distinguishable in the diagnostics
    /// ledger the same way the read/write gate keeps
    /// connectivity, process readiness and semantic freshness apart.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::DurableRouteOwnerUnreadable { .. } => "durable_route_owner_unreadable",
            Self::NoDurableRouteOwner { .. } => "no_durable_route_owner",
            Self::NotTheDurableRouteOwner { .. } => "not_the_durable_route_owner",
        }
    }
}

impl fmt::Display for CanonicalStoreWriterRefusal {
    /// The operator-visible refusal text.
    ///
    /// Every arm names the governed path that must be used instead, so an
    /// operator reading the refusal is told to run the `I5.11` stage-8 cutover
    /// rather than left to infer it from the absence of a connection.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DurableRouteOwnerUnreadable { source } => write!(
                f,
                "the durable canonical_store route owner could not be read ({source}); a \
                 candidate store bridge serves the canonical Store only through the governed \
                 I5.11 stage-8 canonical_store cutover committed by the Kernel Generation \
                 Registry, never by activating a package generation and restarting"
            ),
            Self::NoDurableRouteOwner {
                candidate_generation,
            } => write!(
                f,
                "canonical Store generation {} is not the durable canonical_store route owner \
                 because no owner is established and no committed cutover names one; establish \
                 it through the governed I5.11 stage-8 canonical_store cutover committed by the \
                 Kernel Generation Registry before connecting a candidate store bridge",
                candidate_generation.value()
            ),
            Self::NotTheDurableRouteOwner {
                candidate_generation,
                durable_owner_generation,
            } => write!(
                f,
                "canonical Store generation {} is not the durable canonical_store route owner, \
                 which is generation {}; serve a new store generation only through the governed \
                 I5.11 stage-8 canonical_store cutover committed by the Kernel Generation \
                 Registry (import, verify, shadow-read, tail, quiesce, reconcile, cutover, \
                 canary, read-only rollback window, retire), never by activating a package \
                 generation and restarting",
                candidate_generation.value(),
                durable_owner_generation.value()
            ),
        }
    }
}

/// One recorded `I5.10` exchange into the candidate store.
///
/// It is the typed record the coordinator carries in place of the exported
/// bytes themselves: the Kernel never holds or interprets a transfer payload.
/// It binds the logical transfer format, the exact exported bytes, and the
/// export fence those bytes were taken at.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageReplacementTransfer {
    /// The logical transfer format identity, which is
    /// [`STORAGE_REPLACEMENT_TRANSFER_FORMAT`].
    pub format: String,
    /// Lowercase SHA-256 digest of the exact exported transfer bytes.
    pub payload_digest: String,
    /// Lowercase SHA-256 digest over the `I5.10` export fence the bytes were
    /// taken at.
    pub export_fence_digest: String,
}

impl StorageReplacementTransfer {
    /// Validates the format identity and both bound digests.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        if self.format != STORAGE_REPLACEMENT_TRANSFER_FORMAT {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_transfer_format",
                reason: "the storage replacement transfer format is the I5.10 ECXF/1 exchange",
            });
        }
        validate_digest(
            &self.payload_digest,
            "storage_replacement_transfer_payload_digest",
        )?;
        validate_digest(
            &self.export_fence_digest,
            "storage_replacement_transfer_export_fence_digest",
        )
    }
}

/// One ordered I5.11 storage-replacement stage.
///
/// The discriminants are the I5.11 stage numbers, so the declared order is
/// also the only admissible order: [`StorageReplacementStage::predecessor`]
/// and [`StorageReplacementStage::next`] are exact neighbours and nothing may
/// skip or repeat one.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StorageReplacementStage {
    /// I5.11 stage 1: install candidate store bridge.
    InstallCandidateStoreBridge = 1,
    /// I5.11 stage 2: import snapshot into candidate.
    ImportSnapshotIntoCandidate = 2,
    /// I5.11 stage 3: verify counts, hashes, graph/projection invariants.
    VerifyCountsHashesAndInvariants = 3,
    /// I5.11 stage 4: run shadow reads against both stores.
    ShadowReadBothStores = 4,
    /// I5.11 stage 5: tail canonical events into candidate.
    TailCanonicalEventsIntoCandidate = 5,
    /// I5.11 stage 6: quiesce affected writes.
    QuiesceAffectedWrites = 6,
    /// I5.11 stage 7: reconcile final sequence.
    ReconcileFinalSequence = 7,
    /// I5.11 stage 8: commit the `canonical_store` `CapabilityRouteScope`
    /// cutover through the Kernel Generation Registry.
    CommitCanonicalStoreRouteCutover = 8,
    /// I5.11 stage 9: canary reads/writes.
    CanaryReadsAndWrites = 9,
    /// I5.11 stage 10: keep the old store read-only for the rollback window.
    ReadOnlyRollbackWindow = 10,
    /// I5.11 stage 11: retire the old store only after backup and cutover
    /// receipt.
    RetireAfterBackupAndCutoverReceipt = 11,
}

impl StorageReplacementStage {
    /// The eleven I5.11 stages in their required order.
    pub const ORDER: [Self; 11] = [
        Self::InstallCandidateStoreBridge,
        Self::ImportSnapshotIntoCandidate,
        Self::VerifyCountsHashesAndInvariants,
        Self::ShadowReadBothStores,
        Self::TailCanonicalEventsIntoCandidate,
        Self::QuiesceAffectedWrites,
        Self::ReconcileFinalSequence,
        Self::CommitCanonicalStoreRouteCutover,
        Self::CanaryReadsAndWrites,
        Self::ReadOnlyRollbackWindow,
        Self::RetireAfterBackupAndCutoverReceipt,
    ];

    /// The I5.11 stage number of this stage, from 1 through 11.
    #[must_use]
    pub const fn ordinal(self) -> usize {
        self as usize
    }

    /// Whether this stage moves `I5.10` transfer data into the candidate and
    /// therefore cannot be recorded without a [`StorageReplacementTransfer`].
    #[must_use]
    pub const fn transfers_data(self) -> bool {
        matches!(
            self,
            Self::ImportSnapshotIntoCandidate | Self::TailCanonicalEventsIntoCandidate
        )
    }

    /// The exact stage that must follow this one, or `None` once the old store
    /// has been retired.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::InstallCandidateStoreBridge => Some(Self::ImportSnapshotIntoCandidate),
            Self::ImportSnapshotIntoCandidate => Some(Self::VerifyCountsHashesAndInvariants),
            Self::VerifyCountsHashesAndInvariants => Some(Self::ShadowReadBothStores),
            Self::ShadowReadBothStores => Some(Self::TailCanonicalEventsIntoCandidate),
            Self::TailCanonicalEventsIntoCandidate => Some(Self::QuiesceAffectedWrites),
            Self::QuiesceAffectedWrites => Some(Self::ReconcileFinalSequence),
            Self::ReconcileFinalSequence => Some(Self::CommitCanonicalStoreRouteCutover),
            Self::CommitCanonicalStoreRouteCutover => Some(Self::CanaryReadsAndWrites),
            Self::CanaryReadsAndWrites => Some(Self::ReadOnlyRollbackWindow),
            Self::ReadOnlyRollbackWindow => Some(Self::RetireAfterBackupAndCutoverReceipt),
            Self::RetireAfterBackupAndCutoverReceipt => None,
        }
    }

    /// The exact stage that must have been recorded before this one, or `None`
    /// for the first stage.
    #[must_use]
    pub const fn predecessor(self) -> Option<Self> {
        match self {
            Self::InstallCandidateStoreBridge => None,
            Self::ImportSnapshotIntoCandidate => Some(Self::InstallCandidateStoreBridge),
            Self::VerifyCountsHashesAndInvariants => Some(Self::ImportSnapshotIntoCandidate),
            Self::ShadowReadBothStores => Some(Self::VerifyCountsHashesAndInvariants),
            Self::TailCanonicalEventsIntoCandidate => Some(Self::ShadowReadBothStores),
            Self::QuiesceAffectedWrites => Some(Self::TailCanonicalEventsIntoCandidate),
            Self::ReconcileFinalSequence => Some(Self::QuiesceAffectedWrites),
            Self::CommitCanonicalStoreRouteCutover => Some(Self::ReconcileFinalSequence),
            Self::CanaryReadsAndWrites => Some(Self::CommitCanonicalStoreRouteCutover),
            Self::ReadOnlyRollbackWindow => Some(Self::CanaryReadsAndWrites),
            Self::RetireAfterBackupAndCutoverReceipt => Some(Self::ReadOnlyRollbackWindow),
        }
    }

    /// The exact stage an operator-visible stage name selects, or `None` when
    /// the name is not one of the eleven I5.11 stages.
    ///
    /// This is the only name-to-stage direction, and it is resolved over
    /// [`Self::ORDER`] rather than written out a second time, so a caller's
    /// stage vocabulary cannot drift from the declared order or name a stage
    /// this coordinator does not have. It is what lets an admitted ingress
    /// select a stage from a wire name without this module growing a second
    /// stage spelling.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ORDER.into_iter().find(|stage| stage.name() == name)
    }

    /// The stable operator-visible stage name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InstallCandidateStoreBridge => "install_candidate_store_bridge",
            Self::ImportSnapshotIntoCandidate => "import_snapshot_into_candidate",
            Self::VerifyCountsHashesAndInvariants => "verify_counts_hashes_and_invariants",
            Self::ShadowReadBothStores => "shadow_read_both_stores",
            Self::TailCanonicalEventsIntoCandidate => "tail_canonical_events_into_candidate",
            Self::QuiesceAffectedWrites => "quiesce_affected_writes",
            Self::ReconcileFinalSequence => "reconcile_final_sequence",
            Self::CommitCanonicalStoreRouteCutover => "commit_canonical_store_route_cutover",
            Self::CanaryReadsAndWrites => "canary_reads_and_writes",
            Self::ReadOnlyRollbackWindow => "read_only_rollback_window",
            Self::RetireAfterBackupAndCutoverReceipt => "retire_after_backup_and_cutover_receipt",
        }
    }
}

impl fmt::Display for StorageReplacementStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One irreversible occurrence that closes the generation-rollback path.
///
/// `I5.11` allows switching generation back only when no irreversible
/// migration/effect occurred. These are the two occurrences the issue names;
/// the coordinator records them as an append-only set and never clears one,
/// because an observed irreversible effect cannot be un-observed.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum IrreversibleStorageEffect {
    /// The candidate's imported state cannot be reconciled back into the
    /// incumbent store, so a generation switch back would lose canonical data.
    IrreversibleMigration,
    /// A canonical or external effect was already issued through the candidate
    /// route, so the effect must be reconciled forward rather than undone.
    ExternalEffectIssued,
}

impl fmt::Display for IrreversibleStorageEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::IrreversibleMigration => "irreversible_migration",
            Self::ExternalEffectIssued => "external_effect_issued",
        })
    }
}

/// The disposition of one rollback request against the `canonical_store` route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageRollbackDisposition {
    /// No irreversible migration or external effect is recorded, so the route
    /// may switch back to the incumbent generation as another committed cutover
    /// with a newer epoch.
    GenerationRollbackPermitted,
    /// An irreversible migration or external effect is recorded. The request is
    /// refused as a generation rollback; `state` is the cutover state a refused
    /// rollback leaves behind, and forward repair is the only next transition.
    ForwardRepairRequired {
        /// The cutover state a refused rollback leaves behind.
        state: GenerationCutoverState,
    },
}

/// The durable cutover receipt of one governed storage replacement.
///
/// It names both store generations, the pinned `canonical_store` route scope,
/// the `I5.10` transfer the cutover is proven against, and the
/// ORS-committed cutover the route cutover was re-derived from. It is
/// constructed only by [`StorageReplacement::commit_canonical_store_route_cutover`],
/// which loads the ORS row rather than accepting one, and by
/// [`StorageReplacement::resume_after_committed_cutover`], which re-derives it
/// from that same row. [`Self::validate`] runs before the coordinator stores
/// the value, so a receipt can never precede the durable linearization point.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageReplacementCutoverReceipt {
    /// The replacement identity this receipt belongs to.
    pub replacement_id: String,
    /// The store generation that owned the route before the cutover.
    pub incumbent_generation: Option<ResourceGeneration>,
    /// The store generation that owns the route after the cutover.
    pub candidate_generation: ResourceGeneration,
    /// The pinned `canonical_store` `CapabilityRouteScope`.
    pub route_scope: CapabilityRouteScope,
    /// The `I5.10` transfer the cutover is proven against: the canonical event
    /// tail recorded at I5.11 stage 5, the last transfer into the candidate
    /// before write quiescence and final reconciliation.
    pub transfer: StorageReplacementTransfer,
    /// The ORS-committed cutover ownership receipt proving the linearization
    /// point.
    pub committed_cutover: GenerationCutoverOwnershipReceipt,
    /// The irreversible effects recorded when the cutover was committed.
    pub irreversible_effects: BTreeSet<IrreversibleStorageEffect>,
}

impl StorageReplacementCutoverReceipt {
    /// Validates every binding this receipt claims, including the pinned route
    /// scope, the two store generations, the transfer and the ORS linearization.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_text(&self.replacement_id, "storage_replacement_id")?;
        if self.incumbent_generation == Some(self.candidate_generation) {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_cutover_receipt_generations",
                reason: "a cutover receipt must name two distinct store generations",
            });
        }
        self.route_scope
            .validate()
            .map_err(|error| ors_refusal(&error))?;
        if self.route_scope.capability != CANONICAL_STORE_CAPABILITY
            || self.route_scope.route_scope_hash != canonical_store_route_scope()?.route_scope_hash
        {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_cutover_receipt_route_scope",
                reason: "a cutover receipt must name the pinned canonical_store route scope",
            });
        }
        self.transfer.validate()?;
        let committed = &self.committed_cutover;
        validate_text(
            &committed.linearization_record_id,
            "storage_replacement_cutover_receipt_linearization",
        )?;
        if committed.state != GenerationCutoverState::Committed {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_cutover_receipt_state",
                reason: "a cutover receipt requires a committed ORS cutover state",
            });
        }
        if committed.route_scope_hash != self.route_scope.route_scope_hash
            || committed.old_generation != self.incumbent_generation
            || committed.new_generation != self.candidate_generation
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "storage_replacement_cutover_receipt_binding",
            });
        }
        if (committed.migration == StateMigrationDecision::ForwardRepairRequired)
            == self.irreversible_effects.is_empty()
        {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_cutover_receipt_migration",
                reason: "the committed state migration must name forward repair exactly when an irreversible effect is recorded",
            });
        }
        Ok(())
    }
}

/// The Kernel-owned coordinator for one I5.11 storage replacement.
///
/// It owns the stage position, the per-stage recorded evidence, the two store
/// generations, the pinned route scope, the two required transfer records, the
/// irreversible-effect ledger and the cutover receipt. It stores no snapshot
/// bytes, no event tail and no canary result: those stay with the Store and the
/// candidate bridge and reach the coordinator only as the evidence a stage
/// records.
#[derive(Clone, Debug)]
pub struct StorageReplacement {
    replacement_id: String,
    scope: CapabilityRouteScope,
    incumbent_generation: Option<ResourceGeneration>,
    candidate_generation: ResourceGeneration,
    next_stage: Option<StorageReplacementStage>,
    evidence: BTreeMap<StorageReplacementStage, String>,
    snapshot_import: Option<StorageReplacementTransfer>,
    event_tail: Option<StorageReplacementTransfer>,
    irreversible_effects: BTreeSet<IrreversibleStorageEffect>,
    cutover: Option<GenerationCutoverOwnership>,
    receipt: Option<StorageReplacementCutoverReceipt>,
}

impl fmt::Display for StorageRollbackDisposition {
    /// The stable operator-visible disposition name.
    ///
    /// Same snake-case vocabulary [`StorageReplacementStage::name`] and
    /// [`IrreversibleStorageEffect`] already publish, so the disposition is
    /// projectable on an admitted reply without this module growing a second
    /// spelling beside the decision it names.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::GenerationRollbackPermitted => "generation_rollback_permitted",
            Self::ForwardRepairRequired { .. } => "forward_repair_required",
        })
    }
}

impl StorageReplacement {
    /// Admits exactly one canonical Store generation to be connected as a live
    /// canonical Store WRITER, or refuses it with the generation that does own
    /// the route.
    ///
    /// This is the writer-side admission that pairs with
    /// [`canonical_store_route_owner`]: where that function answers *which*
    /// generation owns the pinned `canonical_store` route scope, this one
    /// answers whether a specific candidate may act as the canonical writer.
    /// It exists because `KernelStoreGateway::new` is reachable from two
    /// production composition sites, and the read/write gate
    /// `require_active_store_generation` already refuses every Store operation
    /// a non-owner gateway could issue. A dead Store path is not an absent
    /// bridge: an approved-but-uncommitted candidate store bridge must not be
    /// constructed and *retained* as the composition's live canonical Store
    /// connection at all, because that is exactly the reachability
    /// [`A12.3`](docs/architecture/A12-03-one-governed-write-path.md) forbids
    /// and [`A0.3`](docs/architecture/A00-03-hard-boundaries.md) lists as a
    /// fail-closed class ("a second ungoverned canonical owner or write
    /// path"). Refusing at construction is strictly stronger than refusing at
    /// first use, and it is what makes the candidate bridge reachable *only*
    /// through the governed `I5.11` cutover workflow.
    ///
    /// ## The answer is read from durable state, never from the caller's claim
    ///
    /// The decision is made by [`canonical_store_route_owner`] alone, which
    /// reads:
    ///
    /// 1. the committed `CUTOVER_OWNERSHIP` rows for the pinned route-scope
    ///    hash, rebuilt through the same [`CutoverRouteSnapshot::rebuild`] the
    ///    Kernel's own recovery performs, so the strictly newest committed
    ///    epoch wins; then
    /// 2. the established [`CanonicalStoreRouteOwnership`] row, which is the
    ///    write-once record of the generation the scope started at.
    ///
    /// Both are ORS state written by an admitted owner — the Kernel Generation
    /// Registry ingress
    /// (`bins/eliot-kernel/src/generation_control.rs::apply_authenticated_generation_cutover`)
    /// for (1) and the one-time composition
    /// [`establish_canonical_store_route_owner`] for (2). `candidate_generation`
    /// is only ever *compared against* that answer; it is never a way to obtain
    /// it, and there is no parameter by which a caller could name the owner it
    /// wants. A composition that reads its own in-memory route snapshot gets no
    /// admission from it here, which is the whole point: the route snapshot and
    /// the candidate both descend from the Host descriptor, so a self-check
    /// between them is tautological, while this read is against a different
    /// durable owner that the Host chain never consults.
    ///
    /// ## Behaviour
    ///
    /// The generation the durable owner DOES name is admitted unchanged, so the
    /// normal boot — where composition established the owner from the same
    /// Host descriptor that registers the route — is unaffected. A candidate
    /// that is not the durable owner's generation is refused with
    /// [`CanonicalStoreWriterRefusal::NotTheDurableRouteOwner`], and an
    /// unreadable owner is refused with
    /// [`CanonicalStoreWriterRefusal::DurableRouteOwnerUnreadable`] carrying its
    /// typed ORS refusal rather than being treated as permission. No arm admits.
    ///
    /// # Errors
    ///
    /// Returns the typed [`CanonicalStoreWriterRefusal`] naming the candidate and,
    /// where the owner could be read, the generation that actually owns the
    /// route. Its `Display` names the governed `I5.11` stage-8 cutover the
    /// operator must run instead.
    pub fn canonical_store_writer_admission(
        ors: &RedbRecoveryStore,
        candidate_generation: ResourceGeneration,
    ) -> Result<CanonicalStoreWriterAdmission, CanonicalStoreWriterRefusal> {
        // `canonical_store_route_owner` declares and validates the pinned route
        // scope itself, so this admission never re-derives a scope and never
        // accepts one: there is no parameter a caller could use to point the
        // question at a route whose owner it likes.
        let owner = canonical_store_route_owner(ors).map_err(|source| {
            CanonicalStoreWriterRefusal::DurableRouteOwnerUnreadable { source }
        })?;
        match owner {
            Some(durable_owner_generation) if durable_owner_generation == candidate_generation => {
                Ok(CanonicalStoreWriterAdmission {
                    durable_owner_generation,
                })
            }
            Some(durable_owner_generation) => {
                Err(CanonicalStoreWriterRefusal::NotTheDurableRouteOwner {
                    candidate_generation,
                    durable_owner_generation,
                })
            }
            None => Err(CanonicalStoreWriterRefusal::NoDurableRouteOwner {
                candidate_generation,
            }),
        }
    }

    /// Starts one replacement bound to the pinned `canonical_store` capability
    /// route scope.
    ///
    /// The first stage to record is
    /// [`StorageReplacementStage::InstallCandidateStoreBridge`]; nothing about
    /// the candidate is active before its own evidence is recorded. A candidate
    /// generation that already owns the route through a committed cutover is
    /// refused, so a restarted process cannot reopen a replacement from the top:
    /// it must resume through [`Self::resume_after_committed_cutover`].
    pub fn begin(
        ors: &RedbRecoveryStore,
        replacement_id: impl Into<String>,
        incumbent_generation: Option<ResourceGeneration>,
        candidate_generation: ResourceGeneration,
    ) -> Result<Self, KernelServiceError> {
        let replacement_id = replacement_id.into();
        validate_text(&replacement_id, "storage_replacement_id")?;
        let scope = canonical_store_route_scope()?;
        if incumbent_generation == Some(candidate_generation) {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_candidate_generation",
                reason: "a replacement must select a distinct candidate store generation",
            });
        }
        let committed = committed_canonical_store_cutovers(ors, &scope)?;
        if committed
            .iter()
            .any(|record| record.new_generation == candidate_generation)
        {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_candidate_generation",
                reason: "the candidate generation already owns the canonical_store route through a committed cutover, so the replacement must be resumed from its durable cutover receipt",
            });
        }
        Ok(Self {
            replacement_id,
            scope,
            incumbent_generation,
            candidate_generation,
            next_stage: Some(StorageReplacementStage::InstallCandidateStoreBridge),
            evidence: BTreeMap::new(),
            snapshot_import: None,
            event_tail: None,
            irreversible_effects: BTreeSet::new(),
            cutover: None,
            receipt: None,
        })
    }

    /// Reconstructs a replacement after a restart from its durable material:
    /// the cutover receipt and the ORS-committed cutover record it names.
    ///
    /// The receipt is validated and then re-derived from ORS, so a receipt that
    /// does not match the durable row is refused. The reconstructed replacement
    /// starts at the stage after the committed cutover, carries the
    /// irreversible-effect ledger the receipt fixed at the cutover, and holds no
    /// per-stage evidence: evidence recorded before the cutover is not durable
    /// material.
    pub fn resume_after_committed_cutover(
        ors: &RedbRecoveryStore,
        replacement_id: impl Into<String>,
        incumbent_generation: Option<ResourceGeneration>,
        candidate_generation: ResourceGeneration,
        receipt: &StorageReplacementCutoverReceipt,
    ) -> Result<Self, KernelServiceError> {
        let replacement_id = replacement_id.into();
        validate_text(&replacement_id, "storage_replacement_id")?;
        receipt.validate()?;
        if receipt.replacement_id != replacement_id
            || receipt.incumbent_generation != incumbent_generation
            || receipt.candidate_generation != candidate_generation
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "storage_replacement_cutover_receipt_identity",
            });
        }
        let record = ors
            .load_cutover_ownership(&receipt.committed_cutover.cutover_id)
            .map_err(|error| ors_refusal(&error))?
            .ok_or(KernelServiceError::InvalidField {
                field: "storage_replacement_cutover_record",
                reason: "a resumed replacement requires its ORS-committed cutover ownership record",
            })?;
        if GenerationCutoverOwnershipReceipt::from_committed(&record)
            .map_err(|error| ors_refusal(&error))?
            != receipt.committed_cutover
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "storage_replacement_cutover_receipt_binding",
            });
        }
        Ok(Self {
            replacement_id,
            scope: receipt.route_scope.clone(),
            incumbent_generation,
            candidate_generation,
            next_stage: StorageReplacementStage::CommitCanonicalStoreRouteCutover.next(),
            evidence: BTreeMap::new(),
            snapshot_import: None,
            event_tail: Some(receipt.transfer.clone()),
            irreversible_effects: receipt.irreversible_effects.clone(),
            cutover: Some(record),
            receipt: Some(receipt.clone()),
        })
    }

    /// The replacement identity.
    #[must_use]
    pub fn replacement_id(&self) -> &str {
        &self.replacement_id
    }

    /// The pinned `canonical_store` `CapabilityRouteScope` this replacement is
    /// bound to.
    #[must_use]
    pub const fn route_scope(&self) -> &CapabilityRouteScope {
        &self.scope
    }

    /// The store generation that owned the route before this replacement.
    #[must_use]
    pub const fn incumbent_generation(&self) -> Option<ResourceGeneration> {
        self.incumbent_generation
    }

    /// The store generation that will own the route after the cutover.
    #[must_use]
    pub const fn candidate_generation(&self) -> ResourceGeneration {
        self.candidate_generation
    }

    /// The one stage that may be recorded next, or `None` once the old store
    /// has been retired.
    #[must_use]
    pub const fn next_stage(&self) -> Option<StorageReplacementStage> {
        self.next_stage
    }

    /// The evidence recorded for one already reached stage, if it was reached.
    #[must_use]
    pub fn evidence(&self, stage: StorageReplacementStage) -> Option<&str> {
        self.evidence.get(&stage).map(String::as_str)
    }

    /// Every stage reached so far with its recorded evidence, in I5.11 order.
    #[must_use]
    pub const fn recorded_evidence(&self) -> &BTreeMap<StorageReplacementStage, String> {
        &self.evidence
    }

    /// The `I5.10` transfer recorded for the snapshot import, if that stage was
    /// reached.
    #[must_use]
    pub const fn snapshot_import_transfer(&self) -> Option<&StorageReplacementTransfer> {
        self.snapshot_import.as_ref()
    }

    /// The `I5.10` transfer recorded for the canonical event tail, if that stage
    /// was reached.
    #[must_use]
    pub const fn event_tail_transfer(&self) -> Option<&StorageReplacementTransfer> {
        self.event_tail.as_ref()
    }

    /// The irreversible effects observed so far.
    #[must_use]
    pub const fn irreversible_effects(&self) -> &BTreeSet<IrreversibleStorageEffect> {
        &self.irreversible_effects
    }

    /// The ORS cutover ownership record, present only once the
    /// `canonical_store` route cutover has been committed.
    #[must_use]
    pub const fn cutover(&self) -> Option<&GenerationCutoverOwnership> {
        self.cutover.as_ref()
    }

    /// The cutover receipt, present only once the `canonical_store` route
    /// cutover has been committed.
    #[must_use]
    pub const fn cutover_receipt(&self) -> Option<&StorageReplacementCutoverReceipt> {
        self.receipt.as_ref()
    }

    /// Records the evidence of the exact next I5.11 stage and advances.
    ///
    /// A stage is reached only through its exact predecessor: a repeated,
    /// skipped or out-of-order stage is refused without recording anything, so
    /// the recorded evidence is a faithful account of what was actually done.
    /// The two transferring stages are recorded by
    /// [`Self::record_transfer_stage`], stage 8 is recorded by
    /// [`Self::commit_canonical_store_route_cutover`], and stage 11 is refused
    /// until a cutover receipt exists.
    pub fn record_stage(
        &mut self,
        stage: StorageReplacementStage,
        evidence: impl Into<String>,
    ) -> Result<StorageReplacementStage, KernelServiceError> {
        let evidence = evidence.into();
        validate_text(&evidence, "storage_replacement_evidence")?;
        if stage.transfers_data() {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_stage",
                reason: "a stage that transfers data is recorded together with its I5.10 transfer record",
            });
        }
        if stage == StorageReplacementStage::CommitCanonicalStoreRouteCutover {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_stage",
                reason: "the canonical_store route cutover is recorded by re-deriving its committed ORS cutover ownership record",
            });
        }
        self.require_exact_next(stage)?;
        if stage == StorageReplacementStage::RetireAfterBackupAndCutoverReceipt
            && self.receipt.is_none()
        {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_cutover_receipt",
                reason: "the incumbent store is retired only after backup and the cutover receipt",
            });
        }
        self.record_evidence(stage, evidence);
        Ok(stage)
    }

    /// Records the exact next data-transfering stage with the `I5.10` transfer
    /// it was performed with, and advances.
    ///
    /// The snapshot import (stage 2) and the canonical event tail (stage 5)
    /// cannot be recorded without the exact exported bytes' digest and the
    /// export fence they were taken at, so the transfer is part of reaching the
    /// stage rather than a note attached to it afterwards.
    pub fn record_transfer_stage(
        &mut self,
        stage: StorageReplacementStage,
        transfer: &StorageReplacementTransfer,
        evidence: impl Into<String>,
    ) -> Result<StorageReplacementStage, KernelServiceError> {
        let evidence = evidence.into();
        validate_text(&evidence, "storage_replacement_evidence")?;
        transfer.validate()?;
        match stage {
            StorageReplacementStage::ImportSnapshotIntoCandidate => {
                self.require_exact_next(stage)?;
                self.snapshot_import = Some(transfer.clone());
            }
            StorageReplacementStage::TailCanonicalEventsIntoCandidate => {
                self.require_exact_next(stage)?;
                self.event_tail = Some(transfer.clone());
            }
            _ => {
                return Err(KernelServiceError::InvalidField {
                    field: "storage_replacement_stage",
                    reason: "only the snapshot import and the canonical event tail transfer data into the candidate",
                });
            }
        }
        self.record_evidence(stage, evidence);
        Ok(stage)
    }

    /// Re-records the stages a completed replacement reached, in the order their
    /// owners reached them, and leaves the machine at the next unreached stage.
    ///
    /// This is the coordinator's own reconstruction of a *presented* completion,
    /// and it is reached only from the Kernel Generation Registry cutover ingress
    /// (`bins/eliot-kernel/src/generation_control.rs`), which is the one place
    /// that commits the ORS `CUTOVER_OWNERSHIP` row for this route. It is not a
    /// summary of a claim: each presented stage is recorded through
    /// [`Self::record_stage`] or [`Self::record_transfer_stage`], so the
    /// coordinator's own rules decide what is admissible — a skipped, repeated or
    /// out-of-order stage is refused by the exact-predecessor rule, a stage that
    /// moves data cannot be presented without its [`StorageReplacementTransfer`]
    /// and a non-transferring stage cannot smuggle one, and `I5.11` stage 8
    /// itself is refused here because it is recorded only by
    /// [`Self::commit_canonical_store_route_cutover`] against a committed ORS
    /// row. A completion that does not carry every stage before stage 8
    /// therefore cannot be positioned at the cutover at all, which the caller
    /// checks before it writes anything.
    ///
    /// [`StorageReplacementStage`] and [`StorageReplacementTransfer`] are the
    /// coordinator's own types, so the stage vocabulary and the transfer record
    /// cannot drift from the ones this module records with.
    pub fn replay_recorded_stages(
        &mut self,
        stages: &[(
            StorageReplacementStage,
            String,
            Option<StorageReplacementTransfer>,
        )],
    ) -> Result<(), KernelServiceError> {
        for (stage, evidence, transfer) in stages {
            if stage.transfers_data() != transfer.is_some() {
                return Err(KernelServiceError::InvalidField {
                    field: "storage_replacement_stage_transfer",
                    reason: "exactly the snapshot import and the canonical event tail carry an I5.10 transfer record",
                });
            }
            match transfer {
                Some(transfer) => {
                    self.record_transfer_stage(*stage, transfer, evidence.as_str())?;
                }
                None => {
                    self.record_stage(*stage, evidence.as_str())?;
                }
            }
        }
        Ok(())
    }

    /// Commits the `canonical_store` `CapabilityRouteScope` cutover through the
    /// Kernel Generation Registry (I5.11 stage 8) and publishes its receipt.
    ///
    /// The cutover record is not accepted from the caller: it is loaded from the
    /// durable ORS row named by `cutover_id`, so only a committed row can
    /// produce a receipt and a hand-built record with a synthetic state and
    /// linearization identity cannot. The row must be for this replacement's own
    /// pinned route scope and its own two store generations, and its declared
    /// state migration must name forward repair exactly when an irreversible
    /// effect is already recorded, so the committed record and the coordinator's
    /// own irreversible-effect ledger can never disagree about whether a
    /// generation rollback is still available. The receipt binds the canonical
    /// event tail transfer, so a cutover cannot be proven against bytes the
    /// coordinator never saw, and it is validated before it is stored.
    pub fn commit_canonical_store_route_cutover(
        &mut self,
        ors: &RedbRecoveryStore,
        cutover_id: &str,
        evidence: impl Into<String>,
    ) -> Result<StorageReplacementCutoverReceipt, KernelServiceError> {
        let evidence = evidence.into();
        validate_text(&evidence, "storage_replacement_evidence")?;
        validate_text(cutover_id, "storage_replacement_cutover_id")?;
        self.require_exact_next(StorageReplacementStage::CommitCanonicalStoreRouteCutover)?;
        let Some(transfer) = self.event_tail.clone() else {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_transfer",
                reason: "the canonical event tail must be transferred into the candidate before the route cutover",
            });
        };
        let record = ors
            .load_cutover_ownership(cutover_id)
            .map_err(|error| ors_refusal(&error))?
            .ok_or(KernelServiceError::InvalidField {
                field: "storage_replacement_cutover_record",
                reason: "the canonical_store route cutover must be an ORS-committed cutover ownership record",
            })?;
        if record.scope.route_scope_hash != self.scope.route_scope_hash {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "storage_replacement_route_scope",
            });
        }
        if record.old_generation != self.incumbent_generation
            || record.new_generation != self.candidate_generation
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "storage_replacement_store_generations",
            });
        }
        if (record.migration == StateMigrationDecision::ForwardRepairRequired)
            == self.irreversible_effects.is_empty()
        {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_migration",
                reason: "the declared state migration must name forward repair exactly when an irreversible effect is recorded",
            });
        }
        let committed_cutover = GenerationCutoverOwnershipReceipt::from_committed(&record)
            .map_err(|error| ors_refusal(&error))?;
        let receipt = StorageReplacementCutoverReceipt {
            replacement_id: self.replacement_id.clone(),
            incumbent_generation: self.incumbent_generation,
            candidate_generation: self.candidate_generation,
            route_scope: self.scope.clone(),
            transfer,
            committed_cutover,
            irreversible_effects: self.irreversible_effects.clone(),
        };
        receipt.validate()?;
        self.cutover = Some(record);
        self.record_evidence(
            StorageReplacementStage::CommitCanonicalStoreRouteCutover,
            evidence,
        );
        self.receipt = Some(receipt.clone());
        Ok(receipt)
    }

    /// Records that an irreversible migration or external effect occurred.
    ///
    /// The ledger only grows: an observed irreversible effect can never be
    /// un-observed, so this closes the generation-rollback path for the rest of
    /// the replacement's life.
    ///
    /// This records an observation; it is not itself the durable proof. The
    /// durable record of irreversibility is the committed ORS
    /// `GenerationCutoverOwnership` row's `migration` decision, and
    /// [`Self::request_rollback`] reads that row rather than trusting this
    /// in-memory set alone.
    pub fn record_irreversible_effect(&mut self, effect: IrreversibleStorageEffect) {
        self.irreversible_effects.insert(effect);
    }

    /// Classifies a rollback request without changing any state.
    ///
    /// This is the pure form of the `I5.11` rule; it reads only the recorded
    /// irreversible effects. It is a projection, not the decision:
    /// [`Self::request_rollback`] also consults the durable ORS cutover
    /// ownership row, so a caller cannot obtain a permitted generation rollback
    /// by simply declining to record an effect.
    #[must_use]
    pub fn rollback_disposition(&self) -> StorageRollbackDisposition {
        if self.irreversible_effects.is_empty() {
            StorageRollbackDisposition::GenerationRollbackPermitted
        } else {
            StorageRollbackDisposition::ForwardRepairRequired {
                state: GenerationCutoverState::FailedRequiresForwardCutover,
            }
        }
    }

    /// Answers one rollback request for the `canonical_store` route.
    ///
    /// The decision is anchored to a durable record written *before* rollback is
    /// ever offered, not to the caller's own bookkeeping. The ORS-committed
    /// [`GenerationCutoverOwnership`] row this replacement's receipt names is
    /// reloaded by cutover identity and re-derived, so a rollback can only be
    /// admitted against the very record the cutover receipt was built from. When
    /// the coordinator's ledger records no irreversible effect, that durable
    /// row's `migration` decision is the authority: a row that already names
    /// [`StateMigrationDecision::ForwardRepairRequired`] refuses the request
    /// even though the in-process ledger is silent, so a caller cannot obtain a
    /// permitted generation rollback by declining to record an effect. Any other
    /// mismatch between the row and the receipt is refused rather than read as
    /// an absence of irreversible effect.
    ///
    /// Once an irreversible effect is recorded — by the ledger or by the durable
    /// row — the request is refused as a generation rollback with
    /// [`KernelServiceError::GenerationFenced`] and only the forward-repair path
    /// named by [`Self::rollback_disposition`] follows. The rollback itself, when
    /// admitted, is another committed cutover with a newer epoch, never a local
    /// flag flip.
    ///
    /// A post-cutover irreversible effect is the one case this cannot prove: it
    /// is not yet in the committed row, and the `I5.11` documents name no
    /// durable record for an effect issued after the linearization point. The
    /// ledger still refuses the request in this process, and a restart that
    /// loses it is a gap the owner of the `I5.14` durable effect ledger has to
    /// close; it is named here rather than papered over with a second store.
    pub fn request_rollback(
        &self,
        ors: &RedbRecoveryStore,
    ) -> Result<StorageRollbackDisposition, KernelServiceError> {
        if let Some(receipt) = self.receipt.as_ref() {
            let record = ors
                .load_cutover_ownership(&receipt.committed_cutover.cutover_id)
                .map_err(|error| ors_refusal(&error))?
                .ok_or(KernelServiceError::InvalidField {
                    field: "storage_replacement_cutover_record",
                    reason: "a rollback decision requires the ORS-committed cutover ownership record the receipt names",
                })?;
            if GenerationCutoverOwnershipReceipt::from_committed(&record)
                .map_err(|error| ors_refusal(&error))?
                != receipt.committed_cutover
            {
                return Err(KernelServiceError::HandshakeMismatch {
                    field: "storage_replacement_cutover_receipt_binding",
                });
            }
            if self.irreversible_effects.is_empty()
                && record.migration == StateMigrationDecision::ForwardRepairRequired
            {
                return Err(KernelServiceError::GenerationFenced);
            }
        }
        match self.rollback_disposition() {
            StorageRollbackDisposition::GenerationRollbackPermitted if self.receipt.is_none() => {
                Err(KernelServiceError::InvalidField {
                    field: "storage_replacement_cutover_receipt",
                    reason: "the canonical_store route cutover is not committed, so no route was switched",
                })
            }
            StorageRollbackDisposition::GenerationRollbackPermitted => {
                Ok(StorageRollbackDisposition::GenerationRollbackPermitted)
            }
            StorageRollbackDisposition::ForwardRepairRequired { .. } => {
                Err(KernelServiceError::GenerationFenced)
            }
        }
    }

    /// Refuses a `canonical_store` route switch whose destination generation is
    /// at or behind a generation this route has already committed an
    /// irreversible migration into.
    ///
    /// `I5.11` states the whole rule: "Rollback switches generation back only if
    /// no irreversible migration/effect occurred; otherwise uses forward repair",
    /// and `I14.14` states the consequence — "Irreversible state migration
    /// requires forward repair or a separately proven rollback path". This is the
    /// switch-side half of that rule, and it is deliberately **not** the
    /// rollback-*reporting* half [`Self::request_rollback`] already answers. A
    /// report can be requested and answered while the live route keeps serving
    /// the candidate; only a refusal placed on the switch itself closes the
    /// route, because the switch is the operation that actually moves it. The
    /// production caller is the Kernel Generation Registry cutover ingress
    /// (`bins/eliot-kernel/src/generation_control.rs::KernelComposition::apply_authenticated_generation_cutover`),
    /// which runs it on both of its admission paths — a cutover identity with no
    /// committed row and one that already has one — before it writes any row and
    /// before the semantic gateway is asked to switch the live route.
    ///
    /// The decision is read from durable ORS rows, never from the request: the
    /// read is every committed `CUTOVER_OWNERSHIP` row of the pinned route scope
    /// *excluding* `cutover_id` — exactly the committed history that existed
    /// before this cutover identity was admitted. A staged (`Armed`) or
    /// fenced candidate cannot appear, because the listing itself returns
    /// committed rows only. Because the row being admitted is excluded rather
    /// than consulted, a caller that presents its own `migration` decision cannot
    /// place that row on top of the committed decision and be admitted: the
    /// gate runs before the row exists, so the caller's payload never becomes the
    /// durable answer at all.
    ///
    /// **Every row is scanned, not the newest one.** `I5.11` asks whether "no
    /// irreversible migration/effect occurred", and the subject of that question
    /// is the store this route serves, not one record. An irreversible migration
    /// or effect is a fact about the data: once a committed row of this scope
    /// carries it, every store generation at or behind that row's
    /// `new_generation` is a generation that lacks whatever the migration
    /// produced, and a later forward cutover does not un-occur it — the forward
    /// cutover moves the route to a *newer* store, it does not restore the older
    /// one. A newer row therefore never retracts an older row's decision: it is
    /// a decision about the transition that follows it, and reading only the
    /// newest row would let an ordinary forward cutover — one that legitimately
    /// presents an empty irreversible-effect ledger and so commits
    /// `RetainCompatible` — launder the earlier requirement out of view, after
    /// which a rollback to the pre-migration generation looks merely
    /// "one step back" and is admitted. That is the single reading the newest
    /// row alone would give, and it is not the guarantee: "no irreversible
    /// migration/effect occurred" is a statement about the whole committed
    /// history of the scope, so the predicate is an existential one — any
    /// committed row recording forward repair at or above the candidate
    /// generation refuses. No row's position in the route snapshot, and no
    /// epoch-winner resolution, can change that fact, so
    /// [`CutoverRouteSnapshot::rebuild`] is deliberately not used here to pick a
    /// winner the way [`active_canonical_store_generation`] does: the winner
    /// answers "who owns the route now", which is a different question from "has
    /// anything irreversible already happened to this route".
    ///
    /// [`StateMigrationDecision::ForwardRepairRequired`] is the
    /// irreversible-effect-bearing state by this module's own standing
    /// definition rather than a choice made here:
    /// [`StorageReplacementCutoverReceipt::validate`] and
    /// [`Self::commit_canonical_store_route_cutover`] both require it on a
    /// committed row *exactly* when the coordinator's irreversible-effect ledger
    /// is non-empty, so any other decision on a committed row of this scope is
    /// durable evidence that THAT cutover recorded no irreversible effect — never
    /// evidence about the cutovers before it.
    ///
    /// The refusal is [`KernelServiceError::GenerationFenced`] — the same typed
    /// refusal [`Self::request_rollback`] already returns for exactly this
    /// decision, and the typed class that means "this generation authority is
    /// fenced until forward recovery". Reusing it is what keeps the switch path
    /// and the reporting path indistinguishable when one of them is mislabelled.
    ///
    /// The comparison is `candidate <= record.new_generation` on
    /// [`ResourceGeneration`] (monotonic by construction), so the admitted
    /// switch is exactly the one that moves strictly past every forward-repair
    /// row: that is the forward repair both documents name, it moves the route
    /// forward under a newer epoch like any other cutover (`I14.14`: "Rollback is
    /// another cutover with a newer epoch"), and it is therefore admitted.
    /// Refusing that as well would leave a committed forward-repair requirement
    /// with no transition at all — not forward repair, but a permanently frozen
    /// route — so the gate refuses the rollback direction and leaves the forward
    /// direction open. The `<=` (rather than `<`) comparison also covers a switch
    /// that does not move the generation at all: such a frame names a
    /// destination that is itself the destination of the recorded irreversible
    /// migration, so a FRESH cutover identity naming that destination is refused
    /// here rather than passed on. That refusal is owned here, not by the
    /// coordinator: the coordinator's
    /// own rule in [`StorageReplacement::begin`] refuses a candidate that already
    /// owns the route through a committed cutover, and that rule runs later,
    /// after this one, on the other admission path.
    ///
    /// With no committed cutover for this scope there is no committed migration
    /// decision to read, so nothing is refused: the pre-first-commit window is
    /// decided by [`canonical_store_route_owner`], and a first cutover has no
    /// incumbent irreversible requirement to violate. An ORS database written
    /// before the optional `CUTOVER_OWNERSHIP` table existed is answered the same
    /// way, by [`committed_canonical_store_cutovers`]' own documented
    /// compatibility reading, which maps that single absent-table class onto an
    /// empty listing; that is a fact about the database — such a database has
    /// committed no cutover — and it is the same reading
    /// [`canonical_store_route_owner`] and the Kernel recovery boundary already
    /// make. It is deliberately NOT described as failing closed here, because it
    /// does not: it admits. Every other durable refusal - a projection bound,
    /// a storage or decode failure, any other typed ORS class - still reaches
    /// the caller as its existing `KernelServiceError` variant through
    /// `ors_refusal`, so those do close this gate. An integrity or
    /// invalid-transition class is no longer reachable HERE, because this scan
    /// does not rebuild a route snapshot; that invariant is enforced at the
    /// writer and read by `active_canonical_store_generation`.
    pub fn refuse_unproven_generation_rollback(
        ors: &RedbRecoveryStore,
        cutover_id: &str,
        candidate_generation: ResourceGeneration,
    ) -> Result<(), KernelServiceError> {
        let scope = canonical_store_route_scope()?;
        let unproven = committed_canonical_store_cutovers(ors, &scope)?
            .iter()
            .filter(|record| record.cutover_id != cutover_id)
            .any(|record| {
                record.migration == StateMigrationDecision::ForwardRepairRequired
                    && candidate_generation.value() <= record.new_generation.value()
            });
        if unproven {
            return Err(KernelServiceError::GenerationFenced);
        }
        Ok(())
    }

    /// Refuses any stage that is not the exact next unreached stage.
    fn require_exact_next(&self, stage: StorageReplacementStage) -> Result<(), KernelServiceError> {
        if self.evidence.contains_key(&stage) {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_stage",
                reason: "the stage is already recorded for this replacement",
            });
        }
        if self.next_stage != Some(stage) {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_stage",
                reason: "a storage replacement stage may only be reached through its exact predecessor",
            });
        }
        Ok(())
    }

    /// Records one stage's evidence and advances the machine past it.
    fn record_evidence(&mut self, stage: StorageReplacementStage, evidence: String) {
        self.evidence.insert(stage, evidence);
        self.next_stage = stage.next();
    }
}

/// Refuses anything that is not a lowercase SHA-256 digest.
fn validate_digest(value: &str, field: &'static str) -> Result<(), KernelServiceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

/// Projects one ORS refusal onto the existing [`KernelServiceError`] variants
/// without collapsing its class into a string.
///
/// Every current [`OrsError`] class is classified. A class that asserts the
/// presented ORS state does not match the required authority, fence, epoch,
/// owner or durable head becomes [`KernelServiceError::HandshakeMismatch`] with
/// a `field` naming that exact class, so it stays distinguishable from a field
/// rejection, a transition refusal and an unavailability. The remaining
/// bounded-field, bound, conflict and lifecycle classes become
/// [`KernelServiceError::InvalidField`] with a `field` naming that exact class;
/// [`OrsError::InvalidField`], which already carries both values, maps across
/// with both `&'static str` values verbatim. Only the classes that are strings
/// in the source type — a foundation contract text, a
/// storage/encoding/staging text, canonical-evidence text, a migration reason
/// and an integrity reason — reach [`KernelServiceError::Platform`], because
/// there is nothing typed left to preserve in them.
///
/// The match is exhaustive by construction: a new ORS class is a compile error
/// here rather than a silently stringified refusal.
fn store_contract_refusal(source: &eliot_store_api::StoreError) -> KernelServiceError {
    KernelServiceError::Core(eliot_kernel_core::KernelError::RecoveryState(
        OrsError::StoreContract(Box::new(source.clone())),
    ))
}

fn legacy_host_refusal() -> KernelServiceError {
    invalid_field("host_request_legacy_correlation")
}

fn ors_refusal(error: &OrsError) -> KernelServiceError {
    match error {
        OrsError::StoreContract(source) => store_contract_refusal(source),
        // The presented ORS state does not match the required authority,
        // fence, owner or durable head.
        OrsError::FenceMismatch => mismatch("authority_epoch_fence"),
        OrsError::EpochMismatch => mismatch("authority_epoch"),
        OrsError::InvalidEpochLineage => mismatch("epoch_lineage"),
        OrsError::StaleWriterEpoch => mismatch("writer_epoch"),
        OrsError::AuthorityHandoffNotFresh => mismatch("authority_handoff"),
        OrsError::RecoveryOwnerMismatch => mismatch("recovery_owner"),
        OrsError::OrderingHeadMismatch => mismatch("ordering_head"),
        OrsError::ReconciliationMismatch => mismatch("canonical_reconciliation"),
        OrsError::IncompatibleArtifact => mismatch("candidate_artifact"),
        OrsError::ProcessStreamRecoveryFamilyCursorMismatch { .. } => {
            mismatch("process_stream_recovery_cursor")
        }
        OrsError::WorkerReplayStaleStream { .. } => mismatch("worker_replay_stream"),
        OrsError::WorkerReplayAckMismatch { .. } => mismatch("worker_replay_ack"),
        OrsError::RecoverySnapshotMoved { .. } => mismatch("recovery_inventory_revision"),
        // An ORS field rejection already has this crate's exact refusal shape.
        OrsError::InvalidField { field, reason } => {
            KernelServiceError::InvalidField { field, reason }
        }
        // The free-form classes: their payload is text in the source type, so
        // this is the only place a string is honest.
        OrsError::Contract(_)
        | OrsError::CanonicalEvidence(_)
        | OrsError::MigrationRequired { .. }
        | OrsError::IntegrityProblem { .. }
        | OrsError::Storage(_)
        | OrsError::Encoding(_)
        | OrsError::StagingNotDurable(_) => KernelServiceError::Platform(error.to_string()),
        // Stale or unbound lease lineage is a presented-record mismatch.
        OrsError::SupervisionLeaseStaleRevision => mismatch("lease_revision_stale"),
        OrsError::SupervisionLeaseBindingMismatch => mismatch("lease_binding"),
        // Every remaining class is a bounded-field, bound, conflict or
        // lifecycle refusal with no authority claim to mismatch against.
        OrsError::BridgeEventCapacityExceeded(_) => invalid_field("bridge_event_capacity"),
        OrsError::BridgeRecoveryWindowCapacityExceeded => {
            invalid_field("bridge_recovery_window_capacity")
        }
        OrsError::BridgeRecoveryCutCapacityExceeded => {
            invalid_field("bridge_recovery_cut_capacity")
        }
        OrsError::UnsupportedContractVersion(_) => invalid_field("envelope_contract_version"),
        OrsError::PayloadTooLarge => invalid_field("payload_length"),
        OrsError::PayloadIntegrityMismatch => invalid_field("payload_integrity"),
        OrsError::InvalidExpiry => invalid_field("expiry_ordering"),
        OrsError::UnsafeExpiry => invalid_field("expiry_reconciliation"),
        OrsError::EmptyScopeSet => invalid_field("ordering_scopes_empty"),
        OrsError::DuplicateScope => invalid_field("ordering_scopes_duplicate"),
        OrsError::InvalidCursorLimit => invalid_field("recovery_cursor_limit"),
        OrsError::DuplicateConflict => invalid_field("durable_state_duplicate"),
        OrsError::AlreadyTerminalWrite(_) => invalid_field("reservation_already_terminal"),
        OrsError::ReservationNotFound => invalid_field("reservation_missing"),
        // An absent I1.9 Generation Registry row is a missing durable record,
        // not a presented-record mismatch: the ORS states it holds no record
        // for the key, and grants nothing to compare an epoch or fence against.
        OrsError::GenerationRegistryRecordNotFound => {
            invalid_field("generation_registry_record_missing")
        }
        OrsError::InvalidTransition => invalid_field("reservation_lifecycle"),
        OrsError::PredecessorPending => invalid_field("ordering_scope_predecessor"),
        OrsError::ScopeRecoveryRequired => invalid_field("ordering_scope_reconciliation"),
        OrsError::UnknownReceiptCannotResolve => invalid_field("unknown_receipt_resolution"),
        OrsError::InboxIntegrityMismatch => invalid_field("recovery_inbox_integrity"),
        OrsError::AuthoritySnapshotUnavailable => invalid_field("authority_snapshot"),
        OrsError::ProjectionLimitExceeded => invalid_field("operational_projection_bound"),
        OrsError::ProcessStreamRecoveryFamilyMoved { .. } => {
            invalid_field("process_stream_family_moved")
        }
        OrsError::SupervisionLeaseTicketConflict => invalid_field("lease_ticket_conflict"),
        OrsError::SupervisionLeaseTicketNotStaged => invalid_field("lease_ticket_not_staged"),
        OrsError::SupervisionLeaseTicketResolved => invalid_field("lease_ticket_resolved"),
        OrsError::SupervisionLeaseTicketNotExpired => invalid_field("lease_ticket_not_expired"),
        OrsError::SupervisionLeaseTicketExpired => invalid_field("lease_ticket_expired"),
        OrsError::SupervisionLeaseTicketAlreadyCommitted => invalid_field("lease_ticket_committed"),
        OrsError::InvalidSupervisionLeaseHistoryLimit => invalid_field("lease_history_limit"),
        OrsError::HostRequestIdentityConflict { .. } => invalid_field("host_request_identity"),
        OrsError::HostRequestLegacyCorrelationUnresolved => legacy_host_refusal(),
        OrsError::HostRequestAttemptLimitExceeded => invalid_field("host_request_attempt_limit"),
        OrsError::HostRequestAttemptExpired => invalid_field("host_request_attempt_expired"),
        OrsError::CampaignLearningStateViewConflict { .. } => {
            invalid_field("campaign_learning_state_view")
        }
        OrsError::CampaignSourcePublicationConflict { .. } => {
            invalid_field("campaign_source_publication")
        }
        OrsError::ActivationResultRetentionIdentityConflict { .. } => {
            invalid_field("activation_result_ticket")
        }
        OrsError::ActivationLifecycleIdentityConflict { .. } => {
            invalid_field("activation_lifecycle_ticket")
        }
        OrsError::ActivationLifecycleExpired { .. } => {
            invalid_field("activation_lifecycle_ticket_expired")
        }
        OrsError::ActivationLifecycleStateConflict { .. } => {
            invalid_field("activation_lifecycle_ticket_state")
        }
        OrsError::NativeWorkerClaimIdentityConflict { .. } => {
            invalid_field("native_worker_claim_identity")
        }
        OrsError::WorkerReplayIdentityConflict { .. } => invalid_field("worker_replay_identity"),
        OrsError::WorkerReplayIncomplete { .. } => invalid_field("worker_replay_suffix"),
        OrsError::VersionedArtifactConflict => invalid_field("versioned_artifact_conflict"),
        OrsError::ActiveExecutableReplacement => invalid_field("active_executable"),
        OrsError::VersionedArtifactNotFound => invalid_field("versioned_artifact_missing"),
        OrsError::VersionedArtifactNotDrained => invalid_field("versioned_artifact_draining"),
        OrsError::RecoveryProblemRetained { .. } => invalid_field("staged_payload_recovery"),
        // Neither write-staging failure is an admitted storage-replacement
        // outcome. If an ORS provider surfaces one here, close generation
        // authority until the original operation is reconciled by its owner.
        OrsError::StagingCommitOutcomeUnknown { .. }
        | OrsError::RecoveryProblemRecordFailed { .. } => KernelServiceError::GenerationFenced,
    }
}

/// Names one ORS mismatch class on the crate's typed mismatch refusal.
fn mismatch(field: &'static str) -> KernelServiceError {
    KernelServiceError::HandshakeMismatch { field }
}

/// Names one ORS field or bound refusal on the crate's typed field refusal.
///
/// The `field` is the ORS class name, so no two ORS refusals of this family read
/// alike. The shared reason states who refused: the durable ORS owner. A class
/// that carries its own reason — [`OrsError::InvalidField`] — keeps it verbatim
/// instead.
fn invalid_field(field: &'static str) -> KernelServiceError {
    KernelServiceError::InvalidField {
        field,
        reason: "rejected by the durable ORS owner",
    }
}
