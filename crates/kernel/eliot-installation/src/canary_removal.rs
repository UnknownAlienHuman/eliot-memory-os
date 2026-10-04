//! Governed canary removal contract and coordinator.
//!
//! Architecture `I3.15` owns the installation/remove transaction: removal is a
//! new durable operation under the same installation/Host authority, so this
//! module never rewrites a completed installation into a rollback and never
//! opens a second installation database. `I14.23` owns the drain ordering a
//! dependent stop/delete must follow, `I14.24`/`A13.2` own local containment
//! and the failure-domain split, `I5.19` owns the stable operation identity and
//! the `unknown_outcome`/`reconciling` discipline, `I7.20` owns the typed
//! disposition plus next permitted action, and `I15.4` owns the secret
//! boundary: no secret value, credential ciphertext or provider output crosses
//! a plan, an effect row, a durable progress entry, a printed plan envelope, a
//! terminal receipt or a status projection.
//!
//! Planning creates no file, secret, service, reservation or transaction row,
//! and `plan_canary_removal` resolves the target from the accepted installation
//! registry and the original transaction's own effect receipts by reading them
//! only: its one registry use is `RedbInstallationRegistry::load`
//! (`redb_state.rs:298`), a `begin_read` transaction, and the transaction side
//! reads through the coordinator's own `RedbInstallationTransactionStore`,
//! which holds a path and reaches redb only as a `ReadOnlyDatabase`
//! (`redb_state.rs:1040`), so no registry revision advances and no registry row
//! is written here. The registry FILE is the one thing planning is not read-only
//! about, and that is the seam's parameter type rather than this body:
//! `plan_canary_removal` takes `registry: &RedbInstallationRegistry`, that
//! struct's only redb field is a `Database` (`installation_registry.rs:92`)
//! which every constructor supplies (`redb_state.rs:140,154`), and the one
//! read-only registry entry point this crate publishes, `inspect_existing_at`
//! (`redb_state.rs:265`), returns an `ApprovedGenerationRegistry` VALUE whose
//! `ReadOnlyDatabase` is opened and dropped inside that call
//! (`redb_state.rs:291,294`), so no `&RedbInstallationRegistry` can be taken
//! from it — the registry therefore reaches this function as redb's exclusive
//! writer handle, and redb 4.1.0 `Drop for Database`
//! (`redb::db::Database::drop` → `ensure_allocator_state_table_and_trim`)
//! commits a quick-repair transaction that rewrites its own `allocator_state`
//! system table when that handle drops, once before this body runs and again
//! after it. That is redb's own bookkeeping, not a domain mutation: it advances
//! no revision and writes no registry row.
//! Admission records one durable removal operation together with the one
//! absolute deadline of its bounded reconcile wait, and execution revalidates
//! the retained resource identity immediately before each mutation, persists the
//! exact intent before the call and the observed result before advancing.
//!
//! The reconcile wait is bounded by that single recorded deadline rather than by
//! a caller-chosen or per-attempt budget. A resumed or retried reconcile reads
//! the same recorded deadline back, so a restart cannot hand the same removal a
//! second unbounded wait. Once the deadline is reached, both entry points refuse
//! to drive any further effect and return the untouched durable projection: the
//! non-terminal stage, the blocking effect and the unresolved
//! `CanaryRemovalEffectState::Unknown { pending_ref }` row all stay exactly as
//! observed. Expiry therefore produces visible incomplete recovery state and
//! can never author a green `Completed`; only a per-row authoritative readback
//! can.
//!
//! No row of the frozen denominator is closed by the plan. Admission opens every
//! row unresolved, and a row this owner drives is closed only on its own owner's
//! readback; the terminal registry retirement is proved by re-loading the
//! registry afterwards and by the owner-issued `CanaryRemovalTerminalReceipt`
//! this operation persists — never by the `revision + 1` arithmetic of the call
//! that issued it, which identifies no operation and would let an unrelated
//! registry mutation pass for this one's work.
//!
//! Two categories in that denominator are shared surfaces no owner in this
//! crate can observe from outside the plan, and this module names them instead
//! of inventing one: `CanaryEvidenceRoot` (a derived filesystem root the effect
//! port cannot address as a bare path) and `StoreObjects` (canonical Store/Blob
//! objects, whose owner this crate has no dependency on). Both rows are
//! classified `OutOfScope`: each stays in the denominator carrying the
//! owner-recorded identity and ownership evidence that show it is not this
//! removal's to destroy, and neither can be closed by a readback, because no
//! owner this crate can reach reports anything about them and evidence this
//! module minted for itself would only restate its own row identity and a
//! comparison that cannot fail is not a readback. That does NOT leave apply
//! free to proceed. `order_band` ranks such a row ahead of every row that can
//! mutate, `advance` drives it before any of them, and `readback_request`
//! answers it with `IncompleteObservation`, so a plan carrying these rows is
//! refused; what the classification buys is that the refusal is typed,
//! attributable and tied to a row that is still counted in the reported
//! denominator. `Unsupported` stays reserved for a required cleanup this owner
//! cannot perform and is caught earlier, by `revalidate_fence`'s own guard
//! before any row is driven. The two are different classifications with
//! different refusal sites and both refuse.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::approved_generation_registry::{
    PendingActivationTerminalDisposition, activation_terminal_digest,
};
use super::{
    ApprovedGenerationRegistry, ContractVersion, InstallationCoordinator, InstallationEffectAction,
    InstallationEffectObservation, InstallationEffectPort, InstallationEffectRequest,
    InstallationEpoch, InstallationError, InstallationStage, InstallationTransaction,
    InstallationTransactionStore, InstallerEffectPlan, ManagedEnvironmentAction,
    ManagedEnvironmentChangeRequest, PlatformHandle, PortOutcome, RedbInstallationRegistry,
    RedbInstallationTransactionStore, candidate_manifest_digest, effect_request, handle, handles,
    platform_error, port_pending, sha256_handle, sha256_hex, wall_clock_millis,
};

/// Wire discriminator for the canary-removal plan, its frozen effect graph and
/// the durable removal operation bound to the original installed transaction.
///
/// This revision is independent from the installation-transaction wire version,
/// so an existing installation transaction keeps its exact identity: a removal
/// is a separate durable record, not a rewritten install.
///
/// Version 2 makes the absolute reconcile deadline of the bounded reconcile
/// wait mandatory. Version 3 adds the `UserMode` supervision-authority credential
/// as a typed resource in the frozen removal graph. Older records require
/// explicit migration; neither deadlines nor resource classifications are
/// synthesized as defaults.
///
/// Version 3 also carries the `OutOfScope` action, which is purely additive: it
/// introduces a classification and does not change an existing one's meaning,
/// so it forces no revision of the wire version. A record admitted before it
/// existed still parses and still validates — but it is not silently resumed,
/// because `require_quiesced_owner_effects` now pins the two shared
/// owner-derived categories to `OutOfScope` and refuses an older record that
/// froze them as `Unsupported`. That is a refusal, not a silent reclassification:
/// nothing in this owner re-labels a frozen row, and no row is dropped.
pub const CANARY_REMOVAL_WIRE_VERSION: ContractVersion = ContractVersion::new(3, 0, 0);

/// Contract member of the printed canary-removal plan envelope.
///
/// The envelope is the one versioned document that carries a frozen plan from
/// planning into apply, so it names the installation contract this crate
/// implements. The `scope` member is deliberately NOT declared here: that label
/// belongs to the surface that publishes the document, so the owner carries the
/// caller's handle instead of restating its vocabulary.
const CANARY_REMOVAL_PLAN_CONTRACT: &str = "eliot.kernel.installation";

/// Status member of the printed canary-removal plan envelope.
///
/// It names the document kind, so a status projection, a plan envelope and a
/// terminal receipt can never be read as one another by accident.
const CANARY_REMOVAL_PLAN_STATUS: &str = "CANARY_REMOVAL_PLAN";

/// Canonical prefix of every derived canary-removal operation identity.
const CANARY_REMOVAL_OPERATION_PREFIX: &str = "canary-removal/v1:";

/// Attempts admitted for one removal row under one removal operation identity.
///
/// One first attempt plus exactly one retry is the whole bound: a reconcile
/// that proves the previous mutating call was not applied may re-issue the same
/// attempt under the same identity, and any further attempt requires a new,
/// separately admitted removal operation rather than a silent extra mutation.
const CANARY_REMOVAL_ROW_MAX_ATTEMPTS: u32 = 2;

/// Bounded wall-clock window in which one admitted canary-removal operation may
/// keep driving and reconciling its own removal rows.
///
/// The clock this window is measured against is the SYSTEM wall clock, and this
/// module has no other one: `wall_clock_millis` reads `SystemTime::now()`
/// against `UNIX_EPOCH` at every observation, so the clock is neither monotonic
/// nor injectable, and there is no seam in this crate that a caller or a test
/// can substitute. The one absolute shape it does share with the crate's bounded
/// SCM start convergence window is the recorded-deadline discipline below, not
/// the clock: that window's timestamp is a `now_ms` parameter on
/// `InstallationCoordinator::drive_effect_at` and
/// `drive_all_effects_until_blocked_at`, whose production callers pass the same
/// `wall_clock_millis()`, whereas this window is read by
/// `reconcile_budget_exhausted`, which takes only the operation and calls the
/// system clock itself. No proof in this crate can therefore substitute that
/// clock and expire this window on demand; a durable record whose recorded value
/// was built by hand is a forged record, not a deadline this owner moved.
///
/// The deadline is computed once from the observed clock when the operation is
/// admitted, persisted with the operation and never recomputed, and the durable
/// compare-and-save path refuses any change to it, so a resumed reconcile
/// re-derives its remaining window from that recorded deadline instead of
/// restarting the budget. What a non-monotonic clock does reopen is elapsed
/// time: the recorded value is an absolute instant, so a system clock that steps
/// backwards past it makes `reconcile_budget_exhausted` false again and re-opens
/// the window for THIS SAME removal identity, with no second admission and no new
/// identity. That is a property of the clock, not a budget this owner can bound.
///
/// Expiry is not a resolution: it only refuses to drive further, which
/// preserves the durable incomplete recovery and its blocking effect exactly as
/// observed.
const CANARY_REMOVAL_RECONCILE_TIMEOUT_MS: u64 = 30_000;

/// Closed set of resource categories one governed canary removal must account
/// for.
///
/// The set is closed on purpose. Every category the accepted registry or the
/// original transaction's effect receipts can describe has exactly one variant,
/// so a shared, preexisting or foreign category cannot silently leave the
/// removal denominator.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanaryRemovalResource {
    /// Exact staged generation tree below the shared packages staging root.
    GenerationPackageRoot,
    /// The `LocalService` Store credential provisioned for this generation.
    StoreCredential,
    /// The exact current-user supervision-authority credential provisioned by
    /// the original `UserMode` transaction.
    UserModeAuthorityCredential,
    /// One canonical SCM service registration admitted for this generation.
    ServiceRegistration,
    /// One canonical SCM service start admitted for this generation.
    ServiceStart,
    /// One installer-owned root created below the installation root.
    InstallationRoot,
    /// One protected ACL applied by the original transaction.
    InstallationAcl,
    /// Host-owned Phase-B live overlay materialized for this generation.
    PhaseBLiveOverlay,
    /// Per-installation canary evidence root derived from the runtime roots.
    ///
    /// The row is classified `OutOfScope`: it is a shared per-installation
    /// surface that is neither this removal's responsibility to remove nor
    /// anything an owner in this crate can prove, so it is named with its
    /// owner-recorded identity instead of being reported as retained and proved.
    CanaryEvidenceRoot,
    /// The canonical Store and Blob objects this generation wrote.
    ///
    /// The row is classified `OutOfScope`: `I3.15` gives the canonical Store
    /// later installation and capability observations rather than this
    /// transaction's operational authority, and this crate declares no Store or
    /// Blob dependency at all, so the objects are named with the generation's
    /// owner-recorded Store binding instead of being reported as retained and
    /// proved.
    StoreObjects,
    /// The approved-generation registry record for this generation.
    GenerationRegistryRecord,
}

/// Proven ownership of one planned removal resource.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanaryRemovalResourceOrigin {
    /// The original install transaction durably created this exact object.
    CreatedByInstallTransaction,
    /// The original install transaction adopted an already existing object.
    PreexistingAtInstall,
    /// Another durable owner, contour or generation owns this resource.
    ForeignToThisRemoval,
}

/// Intended action for one planned removal resource.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanaryRemovalAction {
    /// This owner removes the exact transaction-created identity.
    Remove,
    /// The resource survives this removal unchanged, and the owner that holds it
    /// reads it back before this operation may close.
    Retain,
    /// The resource is required for a complete removal, but this owner has no
    /// admitted removal path for it. It stays in the denominator and blocks
    /// apply; it is never dropped from the plan.
    Unsupported,
    /// The resource is a shared or preexisting surface that this removal is
    /// neither responsible to remove nor able to prove.
    ///
    /// Issue #1138's removal algorithm step 2 is the whole of this
    /// classification, and its three clauses separate three different things:
    /// "Classify shared/preexisting resources as retained; NAME ALL OUT-OF-SCOPE
    /// CATEGORIES WITH EVIDENCE. Unsupported required cleanup blocks apply—it
    /// must not disappear from the denominator." The first clause describes a
    /// shared surface this removal leaves alone AND reads back through its own
    /// owner, which is `Retain`; the second clause describes a category no owner
    /// in this crate can observe at all, which is this variant; the third names
    /// the required cleanup this owner cannot perform, which is `Unsupported`.
    /// All three clauses refuse rather than wave the removal through, at
    /// different sites and with different messages: the required cleanup is
    /// caught by the `Unsupported` guard in `revalidate_fence`, before any row is
    /// driven, while a row of this class is caught later, by `readback_request`
    /// inside the per-row drive. The two are different classifications with
    /// different refusal sites, not one that blocks and one that does not.
    ///
    /// A row of this class is NAMED in the denominator — with the
    /// owner-recorded identity that shows it is not this removal's to destroy,
    /// its ownership evidence and its reconciliation query all frozen in the
    /// plan — rather than dropped from it.
    ///
    /// It is deliberately never reported as `Retain` and proved. `Retain` is a
    /// READBACK outcome: the row's own owner reported the resource still present
    /// under its admitted identity, and this operation closes such a row only on
    /// that owner's verdict. No owner this crate can reach reports anything at
    /// all about these surfaces, so a `Retain` row here would advertise a proof
    /// that does not exist.
    ///
    /// Being classified `OutOfScope` therefore never lets the removal proceed:
    /// there is no owner readback that could be satisfied in place of the
    /// refusal, so the refusal stands. `order_band` ranks every row that names
    /// no installer effect and is not the terminal registry record into band 0,
    /// which is exactly the shape of these two rows, so `freeze_effect_graph`
    /// places them ahead of every row that can mutate; `advance` drives the
    /// first row that is not `Resolved`, and `CanaryRemovalOperation::validate`
    /// admits no disposition that could put one of them there, so a plan
    /// carrying these rows cannot get past one. `advance_row` routes every
    /// non-`Remove` row to `read_retained_row`, which calls `readback_request`
    /// before its first `port.reconcile`, and `readback_request` answers a row
    /// with no installer effect and no owner that can observe it with
    /// `InstallationError::IncompleteObservation`. `apply_canary_removal`
    /// therefore returns that typed refusal for every plan carrying these rows
    /// that reaches the drive: no owner is asked and no mutating call is issued,
    /// and the only durable write ahead of the refusal is the admission record
    /// `admit_or_resume` created.
    ///
    /// What the classification buys is three properties that hold BECAUSE of it,
    /// not in spite of it. The refusal is TYPED and ATTRIBUTABLE: it names the
    /// exact row and its closed category, where dropping the row would leave the
    /// denominator silently short and reporting one as `Retain` would forge a
    /// verdict. The row stays visible in the reported denominator: admission
    /// opens it `Pending`, `expected_stage` counts it in `open`, so `Completed`
    /// is unreachable while it stands, and `unknown_row` cannot be used to close
    /// it either because it has no external outcome to be unknown. And the reason
    /// it cannot be closed is carried in the plan as the owner-recorded identity
    /// and ownership evidence rather than asserted by a handle this module minted
    /// about itself.
    OutOfScope,
}

/// Postcondition one removal row must authoritatively prove.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanaryRemovalPostcondition {
    /// The exact previously admitted object is authoritatively absent.
    Absent,
    /// The resource is still present with its admitted identity.
    Retained,
}

/// Bounded execution contour for one removal row.
///
/// The bound counts attempts under this one removal operation identity only. A
/// proven not-applied attempt may be retried inside the bound; an unknown
/// outcome never creates a new operation identity and never silently spends
/// another attempt, it requires reconciliation first.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalEffectBound {
    /// Non-zero attempt currently committed for this row.
    pub attempt: u32,
    /// Maximum attempts admitted under this removal operation identity.
    pub max_attempts: u32,
}

impl CanaryRemovalEffectBound {
    const fn new() -> Self {
        Self {
            attempt: 1,
            max_attempts: CANARY_REMOVAL_ROW_MAX_ATTEMPTS,
        }
    }

    fn validate(self, field: &str) -> Result<(), InstallationError> {
        if self.attempt == 0 || self.max_attempts == 0 || self.attempt > self.max_attempts {
            return Err(InstallationError::InvalidField {
                field: field.to_owned(),
                reason: "must name a non-zero attempt inside a non-zero attempt bound".to_owned(),
            });
        }
        Ok(())
    }

    const fn next(self) -> Option<Self> {
        let attempt = self.attempt + 1;
        if attempt <= self.max_attempts {
            Some(Self {
                attempt,
                max_attempts: self.max_attempts,
            })
        } else {
            None
        }
    }
}

/// One frozen row of the complete canary-removal effect graph.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalEffect {
    /// Stable removal-effect identity, unique inside one plan.
    pub effect_id: PlatformHandle,
    /// Closed resource category this row accounts for.
    pub category: CanaryRemovalResource,
    /// Proven ownership of the resource.
    pub origin: CanaryRemovalResourceOrigin,
    /// Action this owner admits for the resource.
    pub action: CanaryRemovalAction,
    /// Exact external object identity this removal is admitted to remove.
    ///
    /// For every row backed by an original installer effect this is the
    /// identity that transaction durably recorded for that effect, so a
    /// substituted PID, path or service name cannot acquire ownership. For a
    /// row with no installer effect it is the exact approved identity the
    /// owning contour or registry projection admitted.
    pub resource_identity: PlatformHandle,
    /// Original effect receipt references proving creation or adoption.
    pub ownership_evidence: Vec<PlatformHandle>,
    /// Other admitted users that keep the resource alive.
    pub reference_users: Vec<PlatformHandle>,
    /// Removal effects that must be resolved before this row may start.
    pub prerequisites: Vec<PlatformHandle>,
    /// Postcondition this row must authoritatively prove.
    pub expected_postcondition: CanaryRemovalPostcondition,
    /// Queryable reconciliation handle owned by the resource's own owner.
    pub reconciliation_query: PlatformHandle,
    /// Bounded execution contour for this row.
    pub bound: CanaryRemovalEffectBound,
    /// Positional index of the original installer effect this row inverts.
    ///
    /// `None` marks a row this owner classifies and retires without an
    /// installer effect, which is the terminal registry record and the
    /// owner-derived contour rows.
    pub install_effect_index: Option<u32>,
}

impl CanaryRemovalEffect {
    fn validate(&self) -> Result<(), InstallationError> {
        for (value, field) in [
            (&self.effect_id, "canary_removal.effect.effect_id"),
            (
                &self.resource_identity,
                "canary_removal.effect.resource_identity",
            ),
            (
                &self.reconciliation_query,
                "canary_removal.effect.reconciliation_query",
            ),
        ] {
            handle(value, field)?;
        }
        handles(
            &self.ownership_evidence,
            "canary_removal.effect.ownership_evidence",
            true,
        )?;
        handles(
            &self.reference_users,
            "canary_removal.effect.reference_users",
            false,
        )?;
        handles(
            &self.prerequisites,
            "canary_removal.effect.prerequisites",
            false,
        )?;
        if self
            .ownership_evidence
            .iter()
            .any(|value| self.reference_users.iter().any(|user| user == value))
        {
            return Err(InstallationError::InvalidField {
                field: "canary_removal.effect.reference_users".to_owned(),
                reason: "ownership evidence must not double as a reference user".to_owned(),
            });
        }
        if self
            .prerequisites
            .iter()
            .any(|value| value == &self.effect_id)
        {
            return Err(InstallationError::InvalidField {
                field: "canary_removal.effect.prerequisites".to_owned(),
                reason: "a removal effect cannot require itself".to_owned(),
            });
        }
        self.bound.validate("canary_removal.effect.bound")?;
        let postcondition_matches = matches!(
            (self.action, self.expected_postcondition),
            (
                CanaryRemovalAction::Remove,
                CanaryRemovalPostcondition::Absent
            ) | (
                CanaryRemovalAction::Retain
                    | CanaryRemovalAction::Unsupported
                    | CanaryRemovalAction::OutOfScope,
                CanaryRemovalPostcondition::Retained
            )
        );
        if !postcondition_matches {
            return Err(InstallationError::IdentityConflict);
        }
        if self.action == CanaryRemovalAction::Remove
            && (self.origin != CanaryRemovalResourceOrigin::CreatedByInstallTransaction
                || !self.reference_users.is_empty())
        {
            return Err(InstallationError::IdentityConflict);
        }
        if self.origin == CanaryRemovalResourceOrigin::ForeignToThisRemoval
            && self.install_effect_index.is_some()
        {
            return Err(InstallationError::IdentityConflict);
        }
        // An out-of-scope row names a shared surface, and an installer-effect
        // index names one effect of the original install transaction's own
        // roster, which its own owner CAN observe. A row carrying both would
        // claim this removal is unable to prove a resource it in fact installed,
        // so the combination is refused here instead of being classified.
        if self.action == CanaryRemovalAction::OutOfScope && self.install_effect_index.is_some() {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// Quiesce and retirement evidence observed for the removal target.
///
/// Every member is derived from the accepted registry or the original
/// transaction's own durable state. No member is a caller-authored assurance,
/// so a deadline expiry or an empty list can never force a green cleanup.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalQuiesce {
    /// Active generation observed at plan time; the target never equals it.
    pub active_generation: Option<PlatformHandle>,
    /// Last-known-good generation observed at plan time.
    pub last_known_good_generation: Option<PlatformHandle>,
    /// Observed activation-owner handoff that keeps production serving a safe
    /// generation while the target stays retired, when the registry records
    /// one.
    ///
    /// The registry records a settled handoff in exactly one owner form: the
    /// attributable cutover operation that installed the serving generation,
    /// or the committed activation terminal digest carrying the Host-owned
    /// readiness fence observed for the serving generation. The two forms are
    /// mutually exclusive by registry construction — a pending-activation
    /// commit clears the cutover binding when it flips the active pointer,
    /// and a cutover is refused while a committed terminal names another
    /// generation — so the barrier is the handoff identity in whichever form
    /// the owner recorded it, bound to this installation and to a serving
    /// generation that is not the target. The cutover receipt alone is never
    /// treated as authority to retire: retirement stays the separately
    /// authorized terminal registry step this removal commits last. A registry
    /// with neither form — a staged but uncommitted activation, an abort, a
    /// foreign handoff, or no recorded handoff at all — yields `None`, which
    /// planning and admission both refuse. A removal without an observed safe
    /// serving handoff is never admitted.
    pub retirement_barrier: Option<PlatformHandle>,
    /// Original installer effects that were not authoritatively applied.
    pub open_install_effects: u32,
    /// Original transaction external changes without acknowledgement.
    pub pending_external_changes: u32,
    /// Generation currently staged in a pending activation, when one exists.
    pub pending_activation_generation: Option<PlatformHandle>,
}

impl CanaryRemovalQuiesce {
    fn validate(&self) -> Result<(), InstallationError> {
        for (value, field) in [
            (
                &self.active_generation,
                "canary_removal.quiesce.active_generation",
            ),
            (
                &self.last_known_good_generation,
                "canary_removal.quiesce.last_known_good_generation",
            ),
            (
                &self.retirement_barrier,
                "canary_removal.quiesce.retirement_barrier",
            ),
            (
                &self.pending_activation_generation,
                "canary_removal.quiesce.pending_activation_generation",
            ),
        ] {
            if let Some(value) = value {
                handle(value, field)?;
            }
        }
        Ok(())
    }
}

/// Exact build identity a removal is bound to.
///
/// Every member is an artifact digest taken from the accepted candidate
/// manifest. Removal never re-derives a build identity from a name, a
/// directory suffix, a version string or a caller boolean.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalBuildBinding {
    /// Approved Host image digest of the target generation.
    pub host_artifact_digest: PlatformHandle,
    /// Approved Kernel image digest of the target generation.
    pub kernel_artifact_digest: PlatformHandle,
    /// Approved Store bridge image digest of the target generation.
    pub store_bridge_artifact_digest: PlatformHandle,
    /// Approved canonical Store engine image digest of the target generation.
    pub canonical_store_artifact_digest: PlatformHandle,
}

impl CanaryRemovalBuildBinding {
    fn from_manifest(manifest: &super::CandidateManifest) -> Result<Self, InstallationError> {
        let binding = Self {
            host_artifact_digest: manifest.host_artifact_digest.clone(),
            kernel_artifact_digest: manifest.kernel_artifact_digest.clone(),
            store_bridge_artifact_digest: manifest.store_bridge_artifact_digest.clone(),
            canonical_store_artifact_digest: manifest.canonical_store_artifact_digest.clone(),
        };
        for (value, field) in [
            (
                &binding.host_artifact_digest,
                "canary_removal.build.host_artifact_digest",
            ),
            (
                &binding.kernel_artifact_digest,
                "canary_removal.build.kernel_artifact_digest",
            ),
            (
                &binding.store_bridge_artifact_digest,
                "canary_removal.build.store_bridge_artifact_digest",
            ),
            (
                &binding.canonical_store_artifact_digest,
                "canary_removal.build.canonical_store_artifact_digest",
            ),
        ] {
            sha256_handle(value, field)?;
        }
        Ok(binding)
    }
}

/// Read-only, versioned plan for removing one exact installed canary.
///
/// The plan is the complete finite denominator of the removal: every exact
/// resource identity the accepted registry or the original transaction can
/// describe has one row, so a closed resource category spans one row per
/// roster effect that names it, and every row that is not removed carries an
/// explicit `RETAINED`, `UNSUPPORTED` or `OUT_OF_SCOPE` action. Owner-derived
/// rows (`CanaryEvidenceRoot`, `StoreObjects`, `GenerationRegistryRecord`)
/// appear exactly once per `require_quiesced_owner_effects`, which runs at the
/// destructive gates rather than inside plan validation. Of those three,
/// `GenerationRegistryRecord` is removed and `CanaryEvidenceRoot` and
/// `StoreObjects` are classified `OUT_OF_SCOPE`: they are named with their
/// owner-recorded identity and evidence, and no owner in this crate can observe
/// them, so no owner verdict can close one. Both of those classifications
/// REFUSE the drive rather than wave it through, and they refuse at different
/// sites with different messages: a required cleanup this owner cannot perform
/// is `UNSUPPORTED` and is caught by the guard in `revalidate_fence` before any
/// row is driven, while an `OUT_OF_SCOPE` row is caught by `readback_request`
/// once `advance` reaches it — which is why `order_band` ranks it ahead of every
/// row that can mutate. A plan carrying either refuses to apply, and
/// `Completed` is unreachable while the row stands.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalPlan {
    /// Versioned wire discriminator for this plan.
    pub canary_removal_wire_version: ContractVersion,
    /// Durable removal operation identity bound to the installed transaction.
    pub removal_transaction_id: PlatformHandle,
    /// Original installation transaction that installed the target.
    pub install_transaction_id: PlatformHandle,
    /// Immutable installer plan digest of that original transaction.
    pub install_plan_digest: PlatformHandle,
    /// Installation identity, lineage and sequence of the target.
    pub installation_epoch: InstallationEpoch,
    /// Exact generation this plan removes.
    pub generation: PlatformHandle,
    /// Canonical digest of the accepted target candidate manifest.
    pub manifest_digest: PlatformHandle,
    /// Build identity of the target generation.
    pub build: CanaryRemovalBuildBinding,
    /// Registry revision this plan was resolved against.
    pub registry_revision: u64,
    /// Explicit canary-removal authorization and its request identity.
    pub request: ManagedEnvironmentChangeRequest,
    /// Observed quiesce and retirement evidence.
    pub quiesce: CanaryRemovalQuiesce,
    /// Complete frozen effect graph, ordered by execution dependency.
    pub effects: Vec<CanaryRemovalEffect>,
    /// Digest binding this whole plan to its single removal operation identity.
    pub plan_digest: PlatformHandle,
}

impl CanaryRemovalPlan {
    /// Recomputes the domain-separated plan digest over every plan member
    /// except the digest itself and each row's spent attempt counter.
    ///
    /// `bound.attempt` is durable PROGRESS, not plan identity.
    /// `commit_intent` spends one attempt of a row's own bound by writing the
    /// advanced bound back into the plan row, and the store freezes
    /// `plan_digest` for the life of the operation, so a digest that covered the
    /// counter would re-derive a different value than the recorded one on the very
    /// next `validate()` after a resume — refusing the operation before the store
    /// is ever reached. That is why the counter is normalized here instead of the
    /// digest being recomputed at the write: the frozen digest is the identity the
    /// durable record is keyed by, and re-deriving it per save would mint a second
    /// identity for one removal.
    ///
    /// Normalizing rather than dropping the member is deliberate. It keeps the
    /// digest total over `CanaryRemovalEffect` — no shadow projection of the row
    /// exists that could silently stop covering a field added to it later — and it
    /// keeps `bound.max_attempts`, the admitted execution contour, inside the
    /// digest, because that member does not move. What the normalization costs is
    /// exactly the numbering of the attempt, never the number of attempts this
    /// identity may spend: a caller that froze a higher starting attempt spends its
    /// contour sooner, not more.
    pub fn computed_digest(&self) -> Result<PlatformHandle, InstallationError> {
        #[derive(Serialize)]
        struct DigestInput<'a> {
            canary_removal_wire_version: ContractVersion,
            removal_transaction_id: &'a PlatformHandle,
            install_transaction_id: &'a PlatformHandle,
            install_plan_digest: &'a PlatformHandle,
            installation_epoch: &'a InstallationEpoch,
            generation: &'a PlatformHandle,
            manifest_digest: &'a PlatformHandle,
            build: &'a CanaryRemovalBuildBinding,
            registry_revision: u64,
            request: &'a ManagedEnvironmentChangeRequest,
            quiesce: &'a CanaryRemovalQuiesce,
            effects: &'a [CanaryRemovalEffect],
        }

        // Every frozen row is stamped with the plan-time attempt
        // `CanaryRemovalEffectBound::new()` gives it, so normalizing each row back
        // to exactly that makes the digest a function of the frozen plan alone,
        // whichever attempt this operation has since spent on a row.
        let frozen_attempt = CanaryRemovalEffectBound::new().attempt;
        let mut frozen_effects = self.effects.clone();
        for effect in &mut frozen_effects {
            effect.bound.attempt = frozen_attempt;
        }

        let bytes = super::canonical_json_bytes(&DigestInput {
            canary_removal_wire_version: self.canary_removal_wire_version,
            removal_transaction_id: &self.removal_transaction_id,
            install_transaction_id: &self.install_transaction_id,
            install_plan_digest: &self.install_plan_digest,
            installation_epoch: &self.installation_epoch,
            generation: &self.generation,
            manifest_digest: &self.manifest_digest,
            build: &self.build,
            registry_revision: self.registry_revision,
            request: &self.request,
            quiesce: &self.quiesce,
            effects: &frozen_effects,
        })
        .map_err(|error| InstallationError::InvalidField {
            field: "canary_removal.plan.plan_digest".to_owned(),
            reason: error.to_string(),
        })?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| platform_error(&error))
    }

    /// Validates the plan without performing any external effect.
    #[allow(
        clippy::too_many_lines,
        reason = "one stateless validator keeps the wire version, the removal identity, the digest \
                  re-derivation, the quiesce bounds, the retirement barrier, the frozen row order, \
                  every row's shape and every row's postcondition in a single auditable pass, and \
                  splitting it would scatter one decision across functions that each see only part \
                  of the plan"
    )]
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.canary_removal_wire_version != CANARY_REMOVAL_WIRE_VERSION {
            return Err(InstallationError::MigrationRequired {
                reason: format!(
                    "canary-removal plan wire {} cannot be read as {}",
                    self.canary_removal_wire_version, CANARY_REMOVAL_WIRE_VERSION
                ),
            });
        }
        if self.registry_revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "canary_removal.plan.registry_revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        for (value, field) in [
            (
                &self.removal_transaction_id,
                "canary_removal.plan.removal_transaction_id",
            ),
            (
                &self.install_transaction_id,
                "canary_removal.plan.install_transaction_id",
            ),
            (
                &self.install_plan_digest,
                "canary_removal.plan.install_plan_digest",
            ),
            (&self.generation, "canary_removal.plan.generation"),
        ] {
            handle(value, field)?;
        }
        sha256_handle(&self.manifest_digest, "canary_removal.plan.manifest_digest")?;
        sha256_handle(&self.plan_digest, "canary_removal.plan.plan_digest")?;
        self.installation_epoch.validate()?;
        self.request.validate()?;
        if self.request.action != ManagedEnvironmentAction::Remove
            || self.request.exact_candidate != self.generation
        {
            return Err(InstallationError::IdentityConflict);
        }
        // The removal identity is a pure function of the original installed
        // transaction and the target generation, so a plan whose identity was
        // derived from different inputs is a conflict; the matching identity
        // is the honest one by construction.
        if self.removal_transaction_id
            != canary_removal_operation_id(&self.install_transaction_id, &self.generation)?
        {
            return Err(InstallationError::IdentityConflict);
        }
        self.quiesce.validate()?;
        if self.quiesce.active_generation.as_ref() == Some(&self.generation)
            || self.quiesce.last_known_good_generation.as_ref() == Some(&self.generation)
            || self.quiesce.open_install_effects != 0
            || self.quiesce.pending_external_changes != 0
            || self.quiesce.pending_activation_generation.as_ref() == Some(&self.generation)
        {
            return Err(InstallationError::IncompleteObservation(
                "canary removal requires an observed retirement of the target from the active pointer, the last-known-good pointer, any pending activation and every open install effect"
                    .to_owned(),
            ));
        }
        if self.effects.is_empty() {
            return Err(InstallationError::InvalidField {
                field: "canary_removal.plan.effects".to_owned(),
                reason: "must contain the complete finite removal inventory".to_owned(),
            });
        }
        let mut identities = BTreeSet::new();
        let mut categories = BTreeSet::new();
        for effect in &self.effects {
            effect.validate()?;
            if !identities.insert(effect.effect_id.as_str()) {
                return Err(InstallationError::Duplicate {
                    kind: "canary removal effect".to_owned(),
                    identity: effect.effect_id.as_str().to_owned(),
                });
            }
            // One row names one exact resource identity, not one category: the
            // frozen graph carries one row per installer effect, so a category
            // spans as many rows as the roster holds effects for it (one
            // `CreateRoot`/`ApplyAcl` per hierarchy root, one
            // `RegisterService`/`StartService` per service role). Roster-row
            // exactness is carried by the identity uniqueness above and by
            // `require_complete_effect_coverage`; owner-derived rows carry
            // theirs via `require_quiesced_owner_effects` at the destructive
            // gates. Never by category uniqueness.
            categories.insert(effect.category);
        }
        for effect in &self.effects {
            if effect
                .prerequisites
                .iter()
                .any(|value| !identities.contains(value.as_str()))
            {
                return Err(InstallationError::IdentityConflict);
            }
        }
        if !categories.contains(&CanaryRemovalResource::GenerationRegistryRecord) {
            return Err(InstallationError::IncompleteObservation(
                "the terminal registry record must stay inside the removal denominator".to_owned(),
            ));
        }
        // The FROZEN ORDER is a property of the document, not only of the producer
        // that froze it. `plan_canary_removal` runs `order_effect_graph` before it
        // seals the digest, but `load_plan` accepts an untrusted import, and
        // `advance` selects the next row purely by array position. Without this
        // check a caller-supplied plan could place a mutating row ahead of a row
        // no owner can read back, and the guarantee `order_band` states - that such
        // a row is DETECTED before any destructive call - would hold only for
        // plans this owner produced. Re-deriving through the SAME function is the
        // whole check: no second ordering scheme and no new member.
        let mut ordered = self.effects.clone();
        order_effect_graph(&mut ordered);
        let frozen = ordered
            .iter()
            .map(|row| row.effect_id.as_str())
            .collect::<Vec<_>>();
        if self
            .effects
            .iter()
            .map(|row| row.effect_id.as_str())
            .ne(frozen)
        {
            return Err(InstallationError::IdentityConflict);
        }
        if self.computed_digest()? != self.plan_digest {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// Versioned wire envelope carrying one frozen canary-removal plan.
///
/// Planning creates no file, secret, service, reservation or transaction row and
/// produces this document; the only write planning performs is the redb
/// bookkeeping the module header discloses, and it comes from the registry
/// handle the planning seam admits, not from the pass this document records.
/// Apply accepts exactly this document and re-validates the plan it carries
/// before the first destructive call. The
/// envelope exists because a bare plan is not self-describing on a
/// pipe: without the fixed `contract`, `contract_version`, `status`, `completed`
/// and `scope` members, a plan file could be a completed planning pass, a status
/// projection or a terminal receipt and the owner would have to guess which.
///
/// No member of this envelope or of the plan it carries is a secret value,
/// credential ciphertext or provider output: every member is an identity
/// handle, a digest or a typed class, which is what lets both be printed and
/// persisted under `I15.4`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalPlanEnvelope {
    /// Contract this document belongs to; fixed to `CANARY_REMOVAL_PLAN_CONTRACT`.
    pub contract: PlatformHandle,
    /// Versioned wire discriminator this document was produced under.
    pub contract_version: ContractVersion,
    /// Document kind; fixed to `CANARY_REMOVAL_PLAN_STATUS`.
    pub status: PlatformHandle,
    /// Whether the planning pass that produced this document completed.
    ///
    /// Planning creates no file, secret, service, reservation or transaction row,
    /// so a completed envelope is the only shape the owner admits.
    pub completed: bool,
    /// Bounded effect scope label of the publishing surface.
    ///
    /// It is carried, not redefined: the owner checks only that the member is a
    /// well-formed non-empty handle, because the vocabulary of that label belongs
    /// to the surface that publishes the document, not to this crate.
    pub scope: PlatformHandle,
    /// The frozen, read-only removal plan this envelope carries.
    pub plan: CanaryRemovalPlan,
}

impl CanaryRemovalPlanEnvelope {
    /// Builds the completed envelope for one already-frozen plan.
    ///
    /// `scope` is the publishing surface's own bounded-effect label and is stored
    /// verbatim; this owner never derives or rewrites it. The envelope is
    /// validated here so a printed document is always one the owner admits.
    pub fn new(scope: PlatformHandle, plan: CanaryRemovalPlan) -> Result<Self, InstallationError> {
        let envelope = Self {
            contract: handle_ref(CANARY_REMOVAL_PLAN_CONTRACT)?,
            contract_version: CANARY_REMOVAL_WIRE_VERSION,
            status: handle_ref(CANARY_REMOVAL_PLAN_STATUS)?,
            completed: true,
            scope,
            plan,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Refuses any document whose fixed members or plan are not current.
    ///
    /// The plan's own `validate()` runs last and is therefore the final word: it
    /// re-derives the plan digest, the removal operation identity and the whole
    /// frozen effect graph from the document the caller handed over, so an
    /// envelope can never lend authority to a plan this owner would not admit
    /// itself.
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.plan.canary_removal_wire_version != CANARY_REMOVAL_WIRE_VERSION {
            return Err(InstallationError::MigrationRequired {
                reason: format!(
                    "canary-removal plan envelope carries plan wire {} and cannot be read as {}",
                    self.plan.canary_removal_wire_version, CANARY_REMOVAL_WIRE_VERSION
                ),
            });
        }
        // The envelope's own wire discriminator is checked against the same
        // constant the plan member is: a document that declares another wire
        // version is refused as a migration rather than admitted with the
        // mismatch silently ignored.
        if self.contract_version != CANARY_REMOVAL_WIRE_VERSION {
            return Err(InstallationError::MigrationRequired {
                reason: format!(
                    "canary-removal plan envelope declares wire {} and cannot be read as {}",
                    self.contract_version, CANARY_REMOVAL_WIRE_VERSION
                ),
            });
        }
        // Planning creates no file, secret, service, reservation or transaction
        // row, so an envelope claiming an incomplete planning pass is refused
        // rather than admitted as a partial plan.
        if !self.completed {
            return Err(InstallationError::InvalidField {
                field: "canary_removal.plan_envelope.completed".to_owned(),
                reason: "must be exactly true for a completed read-only planning pass".to_owned(),
            });
        }
        if self.status != handle_ref(CANARY_REMOVAL_PLAN_STATUS)?
            || self.contract != handle_ref(CANARY_REMOVAL_PLAN_CONTRACT)?
        {
            return Err(InstallationError::IdentityConflict);
        }
        handle(&self.scope, "canary_removal.plan_envelope.scope")?;
        self.plan.validate()
    }

    /// Returns the frozen plan this envelope carries.
    #[must_use]
    pub fn into_plan(self) -> CanaryRemovalPlan {
        self.plan
    }
}

/// Owner-issued terminal record of one committed canary removal.
///
/// The terminal registry retirement is the one irreversible step of a removal,
/// and `I5.19` admits exactly one way to learn that it committed: by its
/// operation identity, never by counting revisions. This receipt is that record.
/// It binds this removal operation identity to the generation it retired, the
/// registry revision the plan was admitted against, and the revision and content
/// digest of the projection the retirement actually produced, together with the
/// serving pointers and the survivor set observed in that same reloaded
/// projection.
///
/// Every member is an identity handle, a revision counter or a digest, so the
/// receipt is safe to persist, to re-read during recovery and to project in a
/// status disposition under `I15.4`. It carries no secret value, credential
/// ciphertext or provider output.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalTerminalReceipt {
    /// Versioned wire discriminator for this receipt.
    pub canary_removal_wire_version: ContractVersion,
    /// Sole durable removal operation identity this terminal record belongs to.
    pub removal_transaction_id: PlatformHandle,
    /// Exact generation this removal retired.
    pub generation: PlatformHandle,
    /// Registry revision the removal was admitted against.
    pub predecessor_registry_revision: u64,
    /// Registry revision the reloaded post-retirement projection carries.
    pub resulting_registry_revision: u64,
    /// Content digest of the reloaded post-retirement projection.
    pub resulting_registry_content_digest: PlatformHandle,
    /// Active generation observed in the reloaded projection.
    pub active_generation: Option<PlatformHandle>,
    /// Last-known-good generation observed in the reloaded projection.
    pub last_known_good_generation: Option<PlatformHandle>,
    /// Generations the reloaded projection still carries besides the target.
    pub surviving_generations: Vec<PlatformHandle>,
}

impl CanaryRemovalTerminalReceipt {
    /// Recomputes the domain-separated digest over every receipt member except
    /// the recorded registry content digest itself.
    ///
    /// The content digest is excluded for the same reason
    /// [`CanaryRemovalPlan::computed_digest`] excludes `plan_digest`: it is the
    /// digest of the projection this receipt describes, not a member of the
    /// receipt's own identity, so folding it back in would let a changed
    /// projection mint a matching receipt identity.
    pub fn computed_digest(&self) -> Result<PlatformHandle, InstallationError> {
        #[derive(Serialize)]
        struct DigestInput<'a> {
            canary_removal_wire_version: ContractVersion,
            removal_transaction_id: &'a PlatformHandle,
            generation: &'a PlatformHandle,
            predecessor_registry_revision: u64,
            resulting_registry_revision: u64,
            active_generation: &'a Option<PlatformHandle>,
            last_known_good_generation: &'a Option<PlatformHandle>,
            surviving_generations: &'a [PlatformHandle],
        }

        let bytes = super::canonical_json_bytes(&DigestInput {
            canary_removal_wire_version: self.canary_removal_wire_version,
            removal_transaction_id: &self.removal_transaction_id,
            generation: &self.generation,
            predecessor_registry_revision: self.predecessor_registry_revision,
            resulting_registry_revision: self.resulting_registry_revision,
            active_generation: &self.active_generation,
            last_known_good_generation: &self.last_known_good_generation,
            surviving_generations: &self.surviving_generations,
        })
        .map_err(|error| InstallationError::InvalidField {
            field: "canary_removal.terminal_receipt.resulting_registry_content_digest".to_owned(),
            reason: error.to_string(),
        })?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| platform_error(&error))
    }

    /// Validates one terminal receipt without consulting the registry.
    ///
    /// Every check here is a property of the receipt alone, so nothing here can
    /// establish that the receipt describes the owner's live projection. That
    /// separate question is answered by the caller, and this is what the two
    /// callers in this module actually do:
    ///
    /// * `terminal_receipt_recognises_retirement` re-reads the projection,
    ///   establishes the target's absence there, and applies `resulting_registry_revision`
    ///   only as a MONOTONITY FLOOR (`projection.revision() < that` refuses), because the
    ///   live projection may legitimately have advanced past the retirement.
    /// * `terminal_receipt_digest` re-reads the projection after the retirement and, when the
    ///   live projection still carries EXACTLY the revision this receipt recorded, compares the
    ///   recorded `resulting_registry_content_digest` against that projection's own identity
    ///   before the receipt is reused as terminal evidence.
    ///
    /// The recorded content digest is therefore load-bearing, and it is compared
    /// with the existing projection-identity scheme rather than recomputed here:
    /// `computed_digest` excludes it by design (see above), so a receipt whose
    /// digest does not match the registry it claims to describe keeps its own
    /// well-formed identity and is still refused by that comparison. The
    /// revision guard is not a weakening of it — a linear registry that has
    /// advanced past `resulting_registry_revision` is carrying unrelated
    /// activity, which is exactly the case the monotonicity floor exists to admit,
    /// and the terminal state on such a projection is proved independently by
    /// `terminal_proofs_hold`.
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.canary_removal_wire_version != CANARY_REMOVAL_WIRE_VERSION {
            return Err(InstallationError::MigrationRequired {
                reason: format!(
                    "canary-removal terminal receipt wire {} cannot be read as {}",
                    self.canary_removal_wire_version, CANARY_REMOVAL_WIRE_VERSION
                ),
            });
        }
        handle(
            &self.removal_transaction_id,
            "canary_removal.terminal_receipt.removal_transaction_id",
        )?;
        handle(
            &self.generation,
            "canary_removal.terminal_receipt.generation",
        )?;
        sha256_handle(
            &self.resulting_registry_content_digest,
            "canary_removal.terminal_receipt.resulting_registry_content_digest",
        )?;
        if self.predecessor_registry_revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "canary_removal.terminal_receipt.predecessor_registry_revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        // The retirement committed one revision past the projection the plan was
        // admitted against. A receipt that did not move the registry forward
        // describes no committed terminal effect.
        if self.resulting_registry_revision <= self.predecessor_registry_revision {
            return Err(InstallationError::InvalidField {
                field: "canary_removal.terminal_receipt.resulting_registry_revision".to_owned(),
                reason: "must be strictly greater than the predecessor registry revision"
                    .to_owned(),
            });
        }
        // A retired generation that still serves production or is still the
        // designated last-known-good contradicts the retirement this receipt
        // claims to record.
        if self.active_generation.as_ref() == Some(&self.generation)
            || self.last_known_good_generation.as_ref() == Some(&self.generation)
        {
            return Err(InstallationError::IdentityConflict);
        }
        handles(
            &self.surviving_generations,
            "canary_removal.terminal_receipt.surviving_generations",
            false,
        )?;
        for (index, generation) in self.surviving_generations.iter().enumerate() {
            if generation == &self.generation {
                return Err(InstallationError::IdentityConflict);
            }
            // Sorted order gives one survivor set exactly one serialization, so a
            // re-saved receipt under the same removal identity is byte-identical
            // and a reordered survivor set reads as a conflicting claim.
            if index > 0 && self.surviving_generations[index - 1].as_str() > generation.as_str() {
                return Err(InstallationError::InvalidField {
                    field: "canary_removal.terminal_receipt.surviving_generations".to_owned(),
                    reason: "must be sorted so one survivor set has one serialization".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Durable stage of one admitted canary-removal operation.
///
/// The stage is a pure projection of the durable per-row evidence, so a green
/// stage can never be written over an unresolved effect.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanaryRemovalStage {
    /// Removal intent is durable and no removal effect has started.
    Admitted,
    /// At least one removal effect is executing under its committed intent and
    /// none has been resolved yet.
    Executing,
    /// At least one effect outcome is unknown and requires reconciliation.
    Reconciling,
    /// Every resource outcome is observed and the terminal registry record is
    /// committed under the expected registry revision.
    Completed,
}

/// Authoritative resolution of one removal row.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanaryRemovalEffectDisposition {
    /// The exact previously admitted object is authoritatively absent.
    Absent,
    /// The removal mutation was issued and its postcondition was read back.
    Removed,
    /// The resource was intentionally left intact with its admitted identity.
    Retained,
}

/// Durable per-row state of one admitted canary-removal operation.
///
/// The `state` tag is the sole discriminant, and `deny_unknown_fields` makes the
/// three MEMBER-CARRYING variants strictly decoded: an `IntentCommitted`, a
/// `Resolved` or an `Unknown` payload is refused when it carries a key beside the
/// declared ones, and each member of those three reaches the durable record as the
/// exact field [`CanaryRemovalOperation::validate`] checks.
///
/// `Pending` is the one variant this attribute does NOT cover, and the gap is
/// serde's rather than this owner's. It is a UNIT variant, and serde derives an
/// internally tagged unit variant through its `InternallyTaggedUnitVisitor`, whose
/// `visit_map` consumes and discards every remaining key before returning
/// `Ok(())`. So `{"state":"PENDING","attempt":3}` decodes as `Pending` instead of
/// being refused, and no attribute placed on this enum changes that:
/// `deny_unknown_fields` is read where the STRUCT variants are deserialized and is
/// never consulted for a unit variant.
///
/// Nothing rides in that discarded key, which is why this is recorded rather than
/// fixed. The tag stays the only discriminant, so no other member of this enum can
/// be smuggled in beside it, and the one value that could have travelled there —
/// the spent attempt — enters the durable record only through `IntentCommitted`,
/// whose `attempt` is strictly decoded and is pinned by
/// [`CanaryRemovalOperation::validate`] to the plan row's own
/// [`CanaryRemovalEffect::bound`]. A `PENDING` payload naming an attempt therefore
/// records nothing at all, which is the honest outcome for a row that admits no
/// intent yet.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum CanaryRemovalEffectState {
    /// No removal intent has been committed for this row.
    ///
    /// A unit variant, so serde's internally tagged unit visitor accepts and
    /// discards any further key beside the `state` tag. See this enum's own
    /// documentation for exactly what that admits and why nothing rides in it.
    Pending,
    /// The exact intent was durably committed before the mutating call.
    IntentCommitted {
        /// Non-zero execution attempt inside the row bound.
        attempt: u32,
        /// Digest of the exact removal request authorized for this attempt.
        intent_digest: PlatformHandle,
    },
    /// Authoritative readback proved the row's exact postcondition.
    Resolved {
        /// Observed postcondition class.
        disposition: CanaryRemovalEffectDisposition,
        /// Evidence proving the postcondition.
        evidence: Vec<PlatformHandle>,
    },
    /// The external outcome is unknown and requires reconciliation.
    Unknown {
        /// Stable evidence or failure reference retained for recovery.
        pending_ref: PlatformHandle,
    },
}

/// One durable progress entry bound one-to-one to a frozen plan row.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalEffectProgress {
    /// Removal effect identity from the frozen plan.
    pub effect_id: PlatformHandle,
    /// Current durable state of this row.
    pub state: CanaryRemovalEffectState,
}

/// Durable governed canary-removal operation bound to the original installed
/// transaction.
///
/// The original installation transaction is never reopened, reset or rolled
/// back by this record. It stays the sole owner of the install history; this
/// record owns only the removal intent, the removal-to-install linkage, the
/// per-row durable progress and the terminal disposition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalOperation {
    /// Versioned wire discriminator for this durable operation.
    pub canary_removal_wire_version: ContractVersion,
    /// Sole durable removal operation identity.
    pub removal_transaction_id: PlatformHandle,
    /// The frozen read-only plan this operation executes.
    pub plan: CanaryRemovalPlan,
    /// Current durable removal stage.
    pub stage: CanaryRemovalStage,
    /// Ordered durable per-row progress, one entry per plan row.
    pub effect_progress: Vec<CanaryRemovalEffectProgress>,
    /// Exact removal effect that currently blocks the terminal disposition.
    pub blocking_effect_id: Option<PlatformHandle>,
    /// Absolute deadline of this operation's bounded reconcile wait, measured
    /// on the system wall clock.
    ///
    /// The clock is not injected and not test-controllable:
    /// [`super::wall_clock_millis`] is the system clock, so this member records
    /// an absolute instant that no caller and no test in this crate can choose.
    ///
    /// It is computed once at admission and never recomputed, and the durable
    /// compare-and-save path refuses a change to it, so a resumed reconcile
    /// re-derives its remaining window from this recorded value instead of
    /// restarting the budget. It is a bound on driving, not a resolution:
    /// reaching it leaves every unresolved row, the blocking effect and the
    /// non-terminal stage exactly as observed. Because the clock behind it is
    /// not monotonic, a backwards step re-opens the window for this same
    /// removal identity; only the recorded value is immutable, not elapsed time.
    pub reconcile_deadline_ms: u64,

    /// Durable state revision used by the durable compare-and-save path.
    ///
    /// This is a stored counter, not a clock: it is incremented by one per
    /// durable save and never re-derived from any time source, so unlike
    /// `reconcile_deadline_ms` above it is monotonic by construction and is not
    /// affected by a backwards system clock.
    pub revision: u64,
}

impl CanaryRemovalOperation {
    /// Admits one removal operation from an already validated plan.
    fn admit(plan: CanaryRemovalPlan) -> Result<Self, InstallationError> {
        plan.validate()?;
        let mut effect_progress = Vec::with_capacity(plan.effects.len());
        for effect in &plan.effects {
            // Every row of the denominator starts unresolved, whatever its
            // planned action. A `Retain`, `Unsupported` or `OutOfScope` row is
            // not closed by the plan: its `ownership_evidence` records who owns
            // the resource at plan time, which is not the same claim as having
            // read the resource back from that owner. Admitting such a row as
            // already resolved would let a plan-time string stand in for the
            // owner's own readback and would make `Completed` reachable without
            // ever touching the resource.
            effect_progress.push(CanaryRemovalEffectProgress {
                effect_id: effect.effect_id.clone(),
                state: CanaryRemovalEffectState::Pending,
            });
        }
        let operation = Self {
            canary_removal_wire_version: CANARY_REMOVAL_WIRE_VERSION,
            removal_transaction_id: plan.removal_transaction_id.clone(),
            plan,
            stage: CanaryRemovalStage::Admitted,
            effect_progress,
            blocking_effect_id: None,
            // The one deadline of the whole reconcile wait, taken once from the
            // observed clock at admission. It is never recomputed afterwards,
            // so neither a retry nor a resumed reconcile can restart it.
            reconcile_deadline_ms: wall_clock_millis()
                .saturating_add(CANARY_REMOVAL_RECONCILE_TIMEOUT_MS),
            revision: 1,
        };
        operation.validate()?;
        Ok(operation)
    }

    /// Validates the durable operation against its own frozen plan.
    #[allow(
        clippy::too_many_lines,
        reason = "one stateless validator keeps the wire version, the identity binding, every row, the \
                  two attempt-ordering rules, the blocking-effect rule and the derived stage in a \
                  single auditable pass, and splitting it would scatter one decision across functions \
                  that each see only part of the record"
    )]
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.canary_removal_wire_version != CANARY_REMOVAL_WIRE_VERSION {
            return Err(InstallationError::MigrationRequired {
                reason: format!(
                    "canary-removal operation wire {} cannot be read as {}",
                    self.canary_removal_wire_version, CANARY_REMOVAL_WIRE_VERSION
                ),
            });
        }
        if self.revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "canary_removal.revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        if self.reconcile_deadline_ms == 0 {
            return Err(InstallationError::InvalidField {
                field: "canary_removal.reconcile_deadline_ms".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        self.plan.validate()?;
        if self.removal_transaction_id != self.plan.removal_transaction_id {
            return Err(InstallationError::IdentityConflict);
        }
        if self.effect_progress.len() != self.plan.effects.len() {
            return Err(InstallationError::IncompleteObservation(
                "canary removal progress must stay one-to-one with its frozen plan".to_owned(),
            ));
        }
        for (effect, progress) in self.plan.effects.iter().zip(&self.effect_progress) {
            if progress.effect_id != effect.effect_id {
                return Err(InstallationError::IdentityConflict);
            }
            // The attempt this row may hold is bounded by the row's OWN frozen
            // contour, not by a crate constant: `CanaryRemovalEffectBound::validate`
            // admits any non-zero `max_attempts` and a plan document carrying a
            // wider one is admitted here on its own terms, so a window derived
            // from `CANARY_REMOVAL_ROW_MAX_ATTEMPTS` would refuse this owner's own
            // save the moment such a row legitimately reached its third attempt.
            // What bounds a single record is therefore only its contour.
            //
            // The ADVANCE rule - that the counter moves by at most one between two
            // records - is deliberately NOT here. This validator is STATELESS: it is
            // handed the proposed rows and has no memory of the rows this record
            // replaces, so it cannot see a delta at all. That rule belongs to the
            // store's transition floor, `validate_canary_removal_operation_transition`,
            // which is handed the decoded `current` record as well and is the only
            // place a delta exists to be checked. It is needed because
            // `CanaryRemovalPlan::computed_digest` normalises `attempt` back to the
            // plan-time value before hashing, so a record-to-record `plan_digest`
            // comparison is blind to this member by construction.
            let admissible = match &progress.state {
                // Admission opens every row unresolved, and a row only closes on
                // the outcome its own owner reported for it. `Pending` therefore
                // names "not yet read back", which every action admits; the
                // mutating states below stay exclusive to `Remove` rows so a
                // retained resource can never be checkpointed or cancelled.
                CanaryRemovalEffectState::Pending => true,
                CanaryRemovalEffectState::IntentCommitted {
                    attempt,
                    intent_digest,
                } => {
                    sha256_handle(intent_digest, "canary_removal.progress.intent_digest")?;
                    effect.action == CanaryRemovalAction::Remove
                        && *attempt > 0
                        && *attempt == effect.bound.attempt
                        && *attempt <= effect.bound.max_attempts
                }
                CanaryRemovalEffectState::Resolved {
                    disposition,
                    evidence,
                } => {
                    handles(evidence, "canary_removal.progress.evidence", true)?;
                    // `OutOfScope` is deliberately absent from the retained arm.
                    // `Resolved` is the state that records "an authoritative
                    // readback proved this row's exact postcondition", so admitting
                    // it here would make an out-of-scope row readable as retained
                    // and proved — the one thing its classification exists to
                    // prevent, since no owner in this crate can report anything
                    // about these surfaces. The row therefore cannot be closed by
                    // any disposition at all, and `unknown_row` cannot be used to
                    // close it either: it has no external outcome to be unknown.
                    matches!(
                        (effect.action, *disposition),
                        (
                            CanaryRemovalAction::Remove,
                            CanaryRemovalEffectDisposition::Absent
                                | CanaryRemovalEffectDisposition::Removed
                        ) | (
                            CanaryRemovalAction::Retain | CanaryRemovalAction::Unsupported,
                            CanaryRemovalEffectDisposition::Retained
                        )
                    )
                }
                CanaryRemovalEffectState::Unknown { pending_ref } => {
                    handle(pending_ref, "canary_removal.progress.pending_ref")?;
                    // A row this owner promised to leave intact has just as
                    // unobservable an external outcome as one it drove, so `Retain`
                    // is admitted beside `Remove` here. Refusing that pairing made
                    // `unknown_row` fail this very `validate()`, persist nothing and
                    // hand its caller a bare `IdentityConflict` instead of the typed
                    // reconciling disposition this state exists to record — so a
                    // drifted retained resource could not report itself at all.
                    // `Unsupported` and `OutOfScope` stay out: neither has an owner
                    // readback that could report anything, so neither can reach here.
                    matches!(
                        effect.action,
                        CanaryRemovalAction::Remove | CanaryRemovalAction::Retain
                    )
                }
            };
            if !admissible {
                return Err(InstallationError::IdentityConflict);
            }
        }
        if let Some(blocking) = &self.blocking_effect_id
            && !self
                .effect_progress
                .iter()
                .any(|progress| &progress.effect_id == blocking)
        {
            return Err(InstallationError::IdentityConflict);
        }
        // The one direction of `blocking_effect_id` this owner states, completing
        // the check above: an operation that carries a row whose external outcome
        // is unresolved HAS a blocking effect, and it is one of those unresolved
        // rows. A record that keeps an unknown outcome while naming no such row
        // projects a primary uncertainty through `CanaryRemovalStatus` with no
        // durable row to reconcile, and the whole content of the typed reconciling
        // disposition is that named row.
        //
        // The converse is deliberately NOT stated. `resolve_row` closes a row on
        // its owner's verdict without clearing `blocking_effect_id`, so a record
        // may still name a row that is no longer unresolved, and the store's own
        // transition floor admits exactly that reconciliation precisely because it
        // must never be narrower than this validator. Requiring an unresolved row
        // for every named id would refuse that save, and it closes no hole this
        // direction leaves open.
        //
        // It lives HERE, beside the row-identity check above, because this function
        // runs on BOTH sides of every durable operation: the store's decode calls
        // it on a loaded record, `compare_and_save` calls it on the proposed one
        // and `CanaryRemovalOperationVersion::of` calls it on the expected one. A
        // rule held only in the store's transition validator would leave an
        // ALREADY WRITTEN record whose blocking id was cleared permanently
        // readable through `load_canary_removal_operation` and
        // `canary_removal_status`, which never reach that validator at all.
        let carries_unknown = self
            .effect_progress
            .iter()
            .any(|progress| matches!(progress.state, CanaryRemovalEffectState::Unknown { .. }));
        if carries_unknown
            && !self.effect_progress.iter().any(|progress| {
                matches!(progress.state, CanaryRemovalEffectState::Unknown { .. })
                    && Some(&progress.effect_id) == self.blocking_effect_id.as_ref()
            })
        {
            return Err(InstallationError::IdentityConflict);
        }
        self.expected_stage()?;
        Ok(())
    }

    /// Derives the only stage the durable per-row evidence admits.
    ///
    /// The stage is never authored independently: a green stage over an
    /// unresolved effect is refused here and can never be persisted. `Completed`
    /// is admitted only when no row of the frozen denominator is still
    /// unresolved, which is what the terminal registry record's own resolution
    /// together with the authoritative readback of every other row achieves.
    ///
    /// EVERY row is counted, whatever its planned action. A retained, shared,
    /// preexisting or owner-derived row is part of the removal denominator, so
    /// leaving it out of these counters would let `Completed` be reached while
    /// such a row had never been read back from the owner that holds it. The
    /// three dispositions of a resolved row are therefore accounted for
    /// deliberately:
    ///
    /// * `Retained` is a readback outcome, not a plan-time decision: the row's
    ///   own owner reported the resource still present under its admitted
    ///   identity. It is closed and it is not evidence that this operation drove
    ///   a mutation, so it contributes to neither counter.
    /// * `Absent` asserts the POSTCONDITION and nothing else: the exact admitted
    ///   object is authoritatively absent, with the evidence its own owner
    ///   reported. It deliberately makes no claim about whether a removal
    ///   mutation was issued under this identity, because the durable row
    ///   cannot always answer that. Today `resolve_row` writes it from exactly
    ///   one site — the reconcile-before-execute pass in `advance_row` — and at
    ///   that site the row's prior durable state is `Pending` on a fresh drive
    ///   OR `IntentCommitted` on a resumed one, which already carries the
    ///   `intent_digest` recording that a mutating call WAS issued. So "the row
    ///   was still `Pending`" describes only half of today's writes; on a
    ///   resumed row a mutation was issued, and the disposition is still
    ///   `Absent` because the owner's verdict proves the postcondition and not
    ///   the attempt history.
    ///
    ///   This matters most for a future reconciliation of an `Unknown` row.
    ///   `unknown_row` OVERWRITES `IntentCommitted` with `Unknown { pending_ref }`,
    ///   which retains no attempt and no intent digest, so after an unknown
    ///   outcome whether a mutation was issued is unrecoverable from the durable
    ///   row. A reconciliation that reads the object back as authoritatively
    ///   absent with non-empty evidence must therefore write `Absent`, NOT
    ///   `Removed`: `Removed`'s own definition is that the removal mutation WAS
    ///   issued and read back, and on post-unknown evidence that is an assertion
    ///   about a fact this row no longer holds. `Absent` is the honest disposition
    ///   for a `Remove` row on that evidence, and it needs no relaxation of
    ///   `validate`, which already admits `Absent` for every `Remove` row.
    ///
    ///   The row's declared postcondition (`CanaryRemovalPostcondition::Absent`)
    ///   is satisfied either way, so it is closed and contributes nothing to
    ///   `open`; and it is not evidence that this operation drove work, so it
    ///   contributes nothing to `started` either.
    /// * `Removed` is closed for the same reason, but it *is* evidence that this
    ///   operation executed, so it keeps the stage at `Executing` while any other
    ///   row is still open. Counting a resolved row as open instead would keep
    ///   `open` above zero for every plan that removes anything, so `Completed`
    ///   would be unreachable and the terminal registry retirement could never
    ///   be recorded as a durable outcome. `Removed` is only ever the correct
    ///   disposition where this operation can point at the mutation it issued —
    ///   the post-execute readback in `advance_row`, and the terminal registry
    ///   record closed in `finish_with_readback` on the owner's own receipt. It
    ///   is never a fallback for an outcome this row cannot attribute.
    ///
    /// `open == 0` therefore means "no row of the removal denominator is still
    /// unresolved", which is what authorises the terminal commit. It does not
    /// mean "every resource was deleted": the terminal registry retirement is a
    /// record about the approved-generation activation record for this
    /// generation, and the independently retried idempotent path
    /// (`recover_canary_removal` returning an already `Completed` projection
    /// untouched) is what makes reaching it safe.
    fn expected_stage(&self) -> Result<(), InstallationError> {
        let mut open = 0_usize;
        let mut unknown = 0_usize;
        let mut started = 0_usize;
        for progress in &self.effect_progress {
            match progress.state {
                CanaryRemovalEffectState::Pending => open += 1,
                CanaryRemovalEffectState::IntentCommitted { .. } => {
                    open += 1;
                    started += 1;
                }
                // A resolved row is no longer open: its exact postcondition was
                // already read back from the resource's own owner. `Removed`
                // still proves that this operation executed, so it keeps the
                // stage at `Executing` while the terminal registry row is still
                // pending. See the method documentation for why each disposition
                // is accounted for the way it is.
                CanaryRemovalEffectState::Resolved {
                    disposition: CanaryRemovalEffectDisposition::Removed,
                    ..
                } => {
                    started += 1;
                }
                CanaryRemovalEffectState::Resolved {
                    disposition:
                        CanaryRemovalEffectDisposition::Absent
                        | CanaryRemovalEffectDisposition::Retained,
                    ..
                } => {}
                CanaryRemovalEffectState::Unknown { .. } => {
                    open += 1;
                    unknown += 1;
                    started += 1;
                }
            }
        }
        let expected = if unknown > 0 {
            CanaryRemovalStage::Reconciling
        } else if open == 0 {
            CanaryRemovalStage::Completed
        } else if started > 0 {
            CanaryRemovalStage::Executing
        } else {
            CanaryRemovalStage::Admitted
        };
        if self.stage != expected {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    fn project(&self) -> CanaryRemovalStatus {
        let mut resolved_effect_ids = Vec::new();
        let mut unresolved_effect_ids = Vec::new();
        let mut evidence_refs = Vec::new();
        let mut primary_uncertainty = None;
        let mut cleanup_uncertainty = None;
        for progress in &self.effect_progress {
            match &progress.state {
                CanaryRemovalEffectState::Resolved { evidence, .. } => {
                    resolved_effect_ids.push(progress.effect_id.clone());
                    evidence_refs.extend(evidence.iter().cloned());
                }
                CanaryRemovalEffectState::Unknown { pending_ref } => {
                    unresolved_effect_ids.push(progress.effect_id.clone());
                    if self.plan.effects.iter().any(|effect| {
                        effect.effect_id == progress.effect_id
                            && effect.category == CanaryRemovalResource::GenerationRegistryRecord
                    }) {
                        cleanup_uncertainty = Some(pending_ref.clone());
                    }
                    if primary_uncertainty.is_none() {
                        primary_uncertainty = Some(pending_ref.clone());
                    }
                }
                CanaryRemovalEffectState::Pending
                | CanaryRemovalEffectState::IntentCommitted { .. } => {
                    unresolved_effect_ids.push(progress.effect_id.clone());
                }
            }
        }
        // Completeness is judged against the whole frozen denominator, not only the
        // rows that happen to be removed: a retained, shared, preexisting or
        // owner-derived row that has not been read back yet still needs the
        // owner-driven pass, so this operation must not advertise the final
        // independent readback as the next permitted action.
        let denominator_resolved = self
            .effect_progress
            .iter()
            .all(|progress| matches!(progress.state, CanaryRemovalEffectState::Resolved { .. }));
        let next_permitted_action = match self.stage {
            CanaryRemovalStage::Completed => CanaryRemovalNextAction::Readback,
            CanaryRemovalStage::Reconciling if cleanup_uncertainty.is_some() => {
                CanaryRemovalNextAction::ManualRecovery
            }
            CanaryRemovalStage::Reconciling | CanaryRemovalStage::Executing => {
                if denominator_resolved {
                    CanaryRemovalNextAction::Readback
                } else {
                    CanaryRemovalNextAction::Reconcile
                }
            }
            CanaryRemovalStage::Admitted => CanaryRemovalNextAction::Reconcile,
        };
        CanaryRemovalStatus {
            removal_transaction_id: self.removal_transaction_id.clone(),
            install_transaction_id: self.plan.install_transaction_id.clone(),
            generation: self.plan.generation.clone(),
            plan_digest: self.plan.plan_digest.clone(),
            stage: self.stage,
            registry_revision: self.plan.registry_revision,
            resolved_effect_ids,
            unresolved_effect_ids,
            blocking_effect_id: self.blocking_effect_id.clone(),
            primary_uncertainty,
            cleanup_uncertainty,
            next_permitted_action,
            evidence_refs,
        }
    }
}

/// Next action the installation owner admits for one removal operation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanaryRemovalNextAction {
    /// Re-run the owner-driven readback and reconciliation for this operation.
    Reconcile,
    /// Re-run the independent final readback for this operation.
    Readback,
    /// The named blocking effect needs bounded manual recovery; no automatic
    /// retry is admitted under this removal operation identity.
    ManualRecovery,
}

/// Stable, secret-free disposition of one canary-removal operation.
///
/// Every member is an identity handle, a digest or a typed class. The
/// projection never carries a secret value, credential ciphertext, provider
/// output or an unretained raw path.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalStatus {
    /// Durable removal operation identity.
    pub removal_transaction_id: PlatformHandle,
    /// Original installation transaction this removal is bound to.
    pub install_transaction_id: PlatformHandle,
    /// Exact generation under removal.
    pub generation: PlatformHandle,
    /// Frozen plan digest this disposition was computed from.
    pub plan_digest: PlatformHandle,
    /// Durable removal stage.
    pub stage: CanaryRemovalStage,
    /// Registry revision the plan was admitted against.
    pub registry_revision: u64,
    /// Removal effects with an authoritative outcome.
    pub resolved_effect_ids: Vec<PlatformHandle>,
    /// Removal effects still requiring reconciliation or execution.
    pub unresolved_effect_ids: Vec<PlatformHandle>,
    /// Exact removal effect that currently blocks the terminal disposition.
    pub blocking_effect_id: Option<PlatformHandle>,
    /// Primary uncertainty retained for recovery.
    pub primary_uncertainty: Option<PlatformHandle>,
    /// Cleanup or diagnostic uncertainty retained beside the primary one.
    pub cleanup_uncertainty: Option<PlatformHandle>,
    /// The only action the owner admits next.
    pub next_permitted_action: CanaryRemovalNextAction,
    /// Non-secret evidence references retained for the resolved outcomes.
    pub evidence_refs: Vec<PlatformHandle>,
}

/// Revision/checksum version of one durable canary-removal record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanaryRemovalOperationVersion {
    pub(crate) revision: u64,
    pub(crate) checksum: String,
}

impl CanaryRemovalOperationVersion {
    /// Derives the durable version from a validated operation value.
    pub(crate) fn of(operation: &CanaryRemovalOperation) -> Result<Self, InstallationError> {
        operation.validate()?;
        let bytes =
            serde_json::to_vec(operation).map_err(|error| InstallationError::CorruptRegistry {
                reason: error.to_string(),
            })?;
        Ok(Self {
            revision: operation.revision,
            checksum: sha256_hex(&bytes),
        })
    }
}

/// Derives the one durable removal operation identity for one installed
/// generation.
///
/// The identity is a pure function of the original installed transaction and
/// the target generation, so a reused identity can only ever describe the same
/// removal inputs; changed inputs are refused instead of silently admitted.
pub fn canary_removal_operation_id(
    install_transaction_id: &PlatformHandle,
    generation: &PlatformHandle,
) -> Result<PlatformHandle, InstallationError> {
    handle(
        install_transaction_id,
        "canary_removal.install_transaction_id",
    )?;
    handle(generation, "canary_removal.generation")?;
    PlatformHandle::new(format!(
        "{CANARY_REMOVAL_OPERATION_PREFIX}{}:{}",
        install_transaction_id.as_str(),
        generation.as_str()
    ))
    .map_err(|error| platform_error(&error))
}

/// Resolves the exact installed canary target and returns the frozen,
/// read-only removal plan.
///
/// This step creates no file, secret, service, reservation or transaction row,
/// and its own registry use is a read: the accepted installation registry is
/// loaded exactly once through `RedbInstallationRegistry::load`
/// (`redb_state.rs:298`), which begins a read transaction, while the original
/// transaction and any already admitted removal record are read through the
/// store the coordinator already owns. What is not read-only is the registry
/// FILE, and the cause is this seam's parameter type plus the caller's
/// construction of it, never this body: `registry` is
/// `&RedbInstallationRegistry`, a type whose only redb field is a `Database`
/// and whose every constructor supplies one, so the caller hands in redb's
/// exclusive writer handle and redb 4.1.0
/// `Drop for Database` commits its own `allocator_state` quick-repair
/// transaction on drop — incurred before this body runs and again after it.
/// The module header carries that measured chain in full. A foreign,
/// ambiguous, replaced, production or last-known-good target is refused here,
/// before any destructive path exists. A target without an observed
/// activation-owner handoff to a serving safe generation is refused here as
/// well: without that owner evidence production cannot be proven safely served
/// elsewhere. A reused removal identity with changed
/// inputs is refused here as well, so a conflicting re-admission fails fast
/// at the plan boundary instead of only at apply.
#[allow(
    clippy::too_many_lines,
    reason = "read-only target resolution keeps every refusal in one auditable boundary"
)]
pub(crate) fn plan_canary_removal<P>(
    coordinator: &InstallationCoordinator<P, RedbInstallationTransactionStore>,
    registry: &RedbInstallationRegistry,
    request: &ManagedEnvironmentChangeRequest,
    generation: &PlatformHandle,
) -> Result<CanaryRemovalPlan, InstallationError>
where
    P: InstallationEffectPort,
{
    request.validate()?;
    if request.action != ManagedEnvironmentAction::Remove {
        return Err(InstallationError::InvalidField {
            field: "canary_removal.request.action".to_owned(),
            reason: "canary removal requires an explicit Remove authorization".to_owned(),
        });
    }
    if &request.exact_candidate != generation {
        return Err(InstallationError::IdentityConflict);
    }
    handle(generation, "canary_removal.generation")?;
    let projection = registry.load()?;
    projection.validate()?;
    let target = resolve_approved_generation(&projection, generation)?;
    if target.active
        || target.last_known_good
        || projection
            .active_generation()
            .is_some_and(|active| active == generation)
        || projection
            .last_known_good_generation()
            .is_some_and(|lkg| lkg == generation)
    {
        return Err(InstallationError::IncompleteObservation(format!(
            "generation {} serves production or is the designated last-known-good; removal requires an observed authorized handoff through the activation owner first",
            generation.as_str()
        )));
    }
    let install = coordinator
        .store()
        .load(target.approval.transaction_id())?
        .ok_or_else(|| InstallationError::TransactionNotFound {
            transaction_id: target.approval.transaction_id().as_str().to_owned(),
        })?;
    install.validate()?;
    if install.candidate_manifest.generation != *generation {
        return Err(InstallationError::IdentityConflict);
    }
    // The pending-activation refusal runs before the stage gate on purpose: a
    // pre-activation install with a held intent and no receipt yet passes
    // `install.validate()` (the intent is legal while activating) and must
    // meet this precise refusal instead of the generic stage message. Once
    // the receipt exists the check evaluates false and planning falls
    // through to the stage gate below.
    if install.has_pending_activation_projection_intent() {
        return Err(InstallationError::IncompleteObservation(
            "the activation owner still holds this transaction's pending activation intent"
                .to_owned(),
        ));
    }
    if install.stage() != InstallationStage::ActiveVerified {
        return Err(InstallationError::IncompleteObservation(format!(
            "canary removal requires an active-verified installation transaction, observed {:?}",
            install.stage()
        )));
    }
    // A held intent together with the committed activation receipt is retained
    // historical provenance, not a pending projection: the install history
    // stays owned by the original transaction and removal proceeds as a new
    // operation bound to it, never as a rewritten rollback.
    install.require_all_effects_applied()?;
    if !install.pending_external_changes.is_empty() {
        return Err(InstallationError::IncompleteObservation(
            "the installed transaction still carries unacknowledged external changes".to_owned(),
        ));
    }
    if install.installer_plan_digest != *target.approval.installer_plan_digest() {
        return Err(InstallationError::IdentityConflict);
    }
    let manifest_digest = candidate_manifest_digest(&target.manifest)?;
    if manifest_digest != candidate_manifest_digest(&install.candidate_manifest)? {
        return Err(InstallationError::IdentityConflict);
    }
    let survivors = surviving_generations(&projection, generation);
    let effects = freeze_effect_graph(&install, &survivors)?;
    // The serving handoff is observed here, read-only, from the owner's own
    // settled activation record for this installation. A registry with no
    // settled handoff — a staged but uncommitted activation, an abort, a
    // foreign handoff, or no recorded handoff at all — cannot prove production
    // is safely served elsewhere, so the target is refused at the plan
    // boundary before any destructive path exists.
    let retirement_barrier = observed_retirement_barrier(
        &projection,
        generation,
        &install.installation_epoch.installation,
    )?
    .ok_or_else(|| {
        InstallationError::IncompleteObservation(
            "canary removal requires an observed activation-owner handoff to a serving safe generation"
                .to_owned(),
        )
    })?;
    let quiesce = CanaryRemovalQuiesce {
        active_generation: projection.active_generation().cloned(),
        last_known_good_generation: projection.last_known_good_generation().cloned(),
        retirement_barrier: Some(retirement_barrier),
        open_install_effects: open_install_effect_count(&install)?,
        pending_external_changes: pending_external_change_count(&install)?,
        pending_activation_generation: projection
            .pending_activation
            .as_ref()
            .map(|pending| pending.manifest.generation.clone()),
    };
    let mut plan = CanaryRemovalPlan {
        canary_removal_wire_version: CANARY_REMOVAL_WIRE_VERSION,
        removal_transaction_id: canary_removal_operation_id(
            target.approval.transaction_id(),
            generation,
        )?,
        install_transaction_id: target.approval.transaction_id().clone(),
        install_plan_digest: install.installer_plan_digest.clone(),
        installation_epoch: install.installation_epoch.clone(),
        generation: generation.clone(),
        manifest_digest,
        build: CanaryRemovalBuildBinding::from_manifest(&install.candidate_manifest)?,
        registry_revision: projection.revision(),
        request: request.clone(),
        quiesce,
        effects,
        plan_digest: PlatformHandle::new("0".repeat(64)).map_err(|error| platform_error(&error))?,
    };
    plan.plan_digest = plan.computed_digest()?;
    plan.validate()?;
    // The admission fence fails fast at the plan boundary as well as durably
    // at apply: a removal already admitted for this exact target under
    // different inputs is an identity conflict here, mirroring
    // `admit_or_resume`. An identical digest proceeds so an idempotent re-plan
    // still resumes through the same operation identity.
    if let Some(existing) = coordinator
        .store()
        .load_canary_removal_for_generation(&plan.install_transaction_id, generation)?
    {
        existing.validate()?;
        if existing.plan.plan_digest != plan.plan_digest {
            return Err(InstallationError::IdentityConflict);
        }
    }
    Ok(plan)
}

/// Admits and drives one removal operation for an already frozen plan.
///
/// Admission revalidates the exact plan digest and the current registry
/// revision, records the removal intent durably and only then issues a
/// destructive call. A reused removal identity with changed inputs is an
/// identity conflict; an identical replay resumes the same operation.
///
/// The drive is additionally bounded by the operation's one recorded reconcile
/// deadline, so a replay of an already admitted plan can never buy a fresh
/// unbounded wait.
pub(crate) fn apply_canary_removal<P>(
    coordinator: &mut InstallationCoordinator<P, RedbInstallationTransactionStore>,
    registry: &RedbInstallationRegistry,
    plan: &CanaryRemovalPlan,
) -> Result<CanaryRemovalStatus, InstallationError>
where
    P: InstallationEffectPort,
{
    let mut operation = admit_or_resume(coordinator, plan)?;
    if reconcile_budget_exhausted(&operation) {
        return Ok(operation.project());
    }
    let install = revalidate_fence(coordinator, registry, &operation)?;
    advance(coordinator, registry, &mut operation, &install)?;
    operation.validate()?;
    Ok(operation.project())
}

/// Reconciles one already admitted removal operation.
///
/// Recovery reuses the same operation identity and the same per-row intent
/// digests. It reconciles before any further attempt and never admits a fresh
/// removal identity for an unresolved effect.
pub(crate) fn recover_canary_removal<P>(
    coordinator: &mut InstallationCoordinator<P, RedbInstallationTransactionStore>,
    registry: &RedbInstallationRegistry,
    removal_transaction_id: &PlatformHandle,
) -> Result<CanaryRemovalStatus, InstallationError>
where
    P: InstallationEffectPort,
{
    let mut operation = load_operation(coordinator, removal_transaction_id)?;
    if operation.stage == CanaryRemovalStage::Completed {
        return Ok(operation.project());
    }
    if reconcile_budget_exhausted(&operation) {
        return Ok(operation.project());
    }
    let install = revalidate_fence(coordinator, registry, &operation)?;
    advance(coordinator, registry, &mut operation, &install)?;
    operation.validate()?;
    Ok(operation.project())
}

/// Requires the frozen effect graph to account for the install transaction's
/// own effect roster exactly.
///
/// The expected set is the original transaction's `installer_effects`, which
/// the installation owner durably recorded, not any list supplied alongside the
/// removal request and not the plan's own rows. Every member of that roster
/// must have exactly one plan row naming that exact effect identity, and every
/// plan row that claims an installer effect must name a member of the roster at
/// that exact position. A missing member means an exact job, pending write,
/// ORS operation, outbox row or external effect that this removal would
/// checkpoint, cancel or resolve without ever naming it, so the removal is
/// refused here rather than reported as a complete quiesce.
fn require_complete_effect_coverage(
    install: &InstallationTransaction,
    plan: &CanaryRemovalPlan,
) -> Result<(), InstallationError> {
    // Expected set: the effect identities the installation owner durably
    // recorded for the installed transaction.
    let mut expected = BTreeSet::new();
    for effect in &install.installer_effects {
        expected.insert(effect.effect_id().as_str());
    }
    // Observed set: the identities the frozen graph claims for that roster,
    // each re-read from the roster position the row itself names. A row that
    // names no position, an out-of-range position, or a position whose recorded
    // identity differs from the row's own identity all fail here.
    let mut observed = BTreeSet::new();
    for row in &plan.effects {
        let Some(index) = row.install_effect_index else {
            continue;
        };
        let index = usize::try_from(index).map_err(|_| InstallationError::IdentityConflict)?;
        let effect = install
            .installer_effects
            .get(index)
            .ok_or(InstallationError::IncompleteObservation(
            "a removal effect names an installer effect the installed transaction does not have"
                .to_owned(),
        ))?;
        if effect.effect_id() != &row.effect_id {
            return Err(InstallationError::IdentityConflict);
        }
        if !observed.insert(row.effect_id.as_str()) {
            return Err(InstallationError::Duplicate {
                kind: "canary removal installer effect coverage".to_owned(),
                identity: row.effect_id.as_str().to_owned(),
            });
        }
    }
    if observed != expected {
        return Err(InstallationError::IncompleteObservation(
            "the frozen removal effect graph does not account for the installed transaction's own effect roster"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Quiesces the canary's own owner effects before any dependent stop/delete.
///
/// `I14.23` orders a governed drain as "revoke/finish expiring action
/// authority; request jobs/modules checkpoint/cancel; drain canonical writes and
/// reconcile pending receipts; flush audit/outbox/ORS", and `I14.24` states the
/// matching recovery obligations as "revoke session/leases; checkpoint task/work
/// graph" and "revoke broker/session launch leases". This function is the
/// installation owner's half of that drain, and it is deliberately built out of
/// the owners that already exist rather than a second revocation scheme: there
/// is no second lease table, no parallel session registry, no new token format
/// and no port method added for it.
///
/// Every identity below is derived from the install transaction's own durable
/// record, and the plan contributes the second, independent set. A checkpoint
/// over a guessed job list, or a caller-supplied set reconciled against itself,
/// proves nothing and is refused here because the two sets are compared rather
/// than self-compared.
///
/// The three clauses of the drain are:
///
/// * **Exact jobs.** `require_all_effects_applied` is the existing owner
///   validator for "every installer effect this transaction durably created is
///   authoritatively settled", and `require_complete_effect_coverage` is what
///   makes that exact by naming each of them in the frozen graph. Their removal
///   is then driven row by row through the existing `InstallationEffectPort`
///   with the existing `Rollback` action, so each row's postcondition is read
///   back from the resource's own owner rather than assumed.
/// * **Pending writes, ORS, outbox and possible external effects.** The
///   transaction's own `pending_external_changes` is the only accepted source of
///   that set, and it must both be empty and equal the count the frozen plan
///   recorded. A caller that presents a narrower set than the transaction owns
///   is an identity conflict, not a clean drain.
/// * **Canary leases, sessions and routes.** The authority that can admit this
///   canary's leases, sessions and routes is the transaction's own supervision
///   authority. Its stable lease scope identity is validated in either strict
///   binding state by the launch descriptor's own validator, which the re-loaded
///   transaction ran before this function was reached, and when the authority is
///   provisioned the existing owner's own `validate()` is run against the
///   ORIGINAL recorded receipt - the owner
///   compares its recorded `watchdog_admission_template_digest` and
///   `provision_receipt_digest` itself. Nothing here recomputes a fresh digest
///   to stand in for that check, and nothing re-mints a lease, session or route
///   token. The only claim this owner makes is the one it can prove from its own
///   record: the authority that would admit those authorities is bound to this
///   exact generation of this exact installation, so retiring the generation
///   retires them with it. A transaction still holding a genuinely pending
///   activation projection intent - the canary's own activation session
///   boundary in this owner, a held intent without the committed activation
///   receipt - is refused outright. A held intent together with that receipt
///   is retained historical provenance, not a pending projection.
///
/// The plan's declared `build` binding is compared against the same
/// re-derived binding here, so a plan cannot freeze artifact digests the
/// installed transaction does not carry.
///
/// The owner-derived rows are compared here, identity for identity AND action
/// for action, against the frozen plan. That is what stops a plan from naming a
/// substituted canary evidence root or a substituted Store/Blob object set and
/// still presenting itself as a complete owner-effect inventory, and it is what
/// pins the two shared surfaces with no owner readback to `OutOfScope` instead
/// of letting a plan present an unobservable surface as one this removal
/// retained and proved. The shared and foreign rows stay non-`Remove`, so no
/// plan can claim to delete another generation's durable state.
///
/// Every failure is a refusal that leaves the durable incomplete recovery and
/// its blocking effect exactly as observed. A canary whose lease authority is
/// foreign, whose provision receipt does not validate, or whose owner-effect
/// identities do not re-derive is never removed by this owner.
fn require_quiesced_owner_effects(
    install: &InstallationTransaction,
    plan: &CanaryRemovalPlan,
) -> Result<(), InstallationError> {
    // Exact jobs: the existing owner validator, not a list assembled here.
    install.require_all_effects_applied()?;
    // Pending writes, ORS, outbox and possible external effects: resolved, and
    // the resolved set is the transaction's own rather than the request's.
    if !install.pending_external_changes.is_empty() {
        return Err(InstallationError::IncompleteObservation(
            "the installed transaction still carries unacknowledged external changes".to_owned(),
        ));
    }
    if pending_external_change_count(install)? != plan.quiesce.pending_external_changes
        || open_install_effect_count(install)? != plan.quiesce.open_install_effects
    {
        return Err(InstallationError::IdentityConflict);
    }
    // The canary's live activation session boundary: a genuinely pending
    // intent means the activation owner can still project this generation, so
    // its leases, sessions and routes are not yet this removal's to retire. A
    // held intent together with the committed activation receipt is retained
    // historical provenance and does not block retirement.
    if install.has_pending_activation_projection_intent() {
        return Err(InstallationError::IncompleteObservation(
            "the activation owner still holds this transaction's pending activation intent"
                .to_owned(),
        ));
    }
    let launch = &install.candidate_manifest.runtime_launch;
    if launch.generation != install.candidate_manifest.generation {
        return Err(InstallationError::IdentityConflict);
    }
    if let super::SupervisionAuthorityBinding::Provisioned { authority } =
        &launch.supervision_authority
    {
        // The existing lease owner's own validator, run against the originally
        // recorded receipt rather than against a digest recomputed here.
        authority
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "canary_removal.owner_effects.supervision_authority".to_owned(),
                reason: error.to_string(),
            })?;
        // The existing owner's own Watchdog admission template, validated by the
        // owner. This is the lease admission template that carries the canary's
        // lease scope, generation and trust anchor.
        let template = authority.watchdog_admission_template().map_err(|error| {
            InstallationError::InvalidField {
                field: "canary_removal.owner_effects.watchdog_admission_template".to_owned(),
                reason: error.to_string(),
            }
        })?;
        template
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "canary_removal.owner_effects.watchdog_admission_template".to_owned(),
                reason: error.to_string(),
            })?;
        // The authority must be this canary's own, in this installation. A
        // neighbour's or a foreign installation's authority is refused here
        // instead of being revoked under the wrong identity.
        //
        // The lease scope is deliberately NOT compared here, and there is no
        // second comparison elsewhere that stands in for one.
        // `RuntimeLaunchDescriptor::supervision_lease_scope_id` returns
        // `SupervisionAuthorityBinding::scope_id`, which for a provisioned
        // binding returns `authority.supervision_lease_scope_id` itself, so a
        // comparison against `authority.supervision_lease_scope_id` compares
        // that one recorded value with itself and can never refuse anything. The
        // scope's own integrity belongs to the existing owners and is already
        // checked on this path: the `authority.validate()` above rejects a
        // blank, untrimmed or control-charactered scope and re-derives both
        // `watchdog_admission_template_digest` and `provision_receipt_digest`
        // against the ORIGINAL recorded receipt, and the launch descriptor's own
        // validator - which the re-loaded transaction ran before this function was
        // reached - validates the scope handle in either strict binding state.
        let installation = &plan.installation_epoch.installation;
        if authority.candidate_generation != plan.generation.as_str()
            || authority.trust_anchor.installation_id != installation.as_str()
        {
            return Err(InstallationError::IdentityConflict);
        }
    }
    // The plan's own build binding is re-derived here from the re-loaded
    // transaction and compared against the frozen member. `plan_digest` already
    // covers `build`, so a caller could otherwise freeze ANY host, kernel,
    // canonical-Store or Store-bridge digest and have apply admit the document:
    // nothing else in this module reads `plan.build`. Comparing it here makes
    // the "the exact build identity a removal is bound to" claim an enforced
    // one instead of a transitively-implied consequence of `manifest_digest`.
    if plan.build != CanaryRemovalBuildBinding::from_manifest(&install.candidate_manifest)? {
        return Err(InstallationError::IdentityConflict);
    }
    // The owner-derived rows, compared to the frozen plan. Each category must
    // appear exactly once, its identity must be the one this transaction's own
    // manifest derives, and the shared or foreign rows must carry exactly the
    // action this owner admits for them: `OutOfScope` for the two shared
    // surfaces no owner in this crate can observe, so no plan can present an
    // unobservable surface as a retained one this removal proved and no plan
    // can drop either one by classifying it as required cleanup this owner
    // cannot perform, and `Remove` only for the terminal registry record. The
    // check is on the row's PRESENCE and on its CLASSIFICATION together: a plan
    // that omits one of these two categories is refused exactly as a plan that
    // relabels one of them is. The plan's ownership claim is compared in the same
    // loop for the two categories whose claim is that re-derived identity, so a
    // substituted claim cannot ride in beside a correct identity.
    let expected_owners = [
        (
            CanaryRemovalResource::CanaryEvidenceRoot,
            install
                .candidate_manifest
                .runtime_launch
                .runtime_state_roots
                .canary_evidence_root()?,
            CanaryRemovalAction::OutOfScope,
        ),
        (
            // The Store identity is the generation's own owner-recorded Store
            // bridge binding, re-derived here from the transaction rather than
            // compared with the plan's own row, so a plan that froze a
            // substituted Store identity is refused here.
            CanaryRemovalResource::StoreObjects,
            CanaryRemovalBuildBinding::from_manifest(&install.candidate_manifest)?
                .store_bridge_artifact_digest,
            CanaryRemovalAction::OutOfScope,
        ),
        (
            CanaryRemovalResource::GenerationRegistryRecord,
            install.candidate_manifest.generation.clone(),
            CanaryRemovalAction::Remove,
        ),
    ];
    for (category, identity, action) in expected_owners {
        let mut rows = plan.effects.iter().filter(|row| row.category == category);
        let Some(row) = rows.next() else {
            return Err(InstallationError::IncompleteObservation(format!(
                "the frozen plan does not account for the canary's own {category:?} owner effect"
            )));
        };
        if rows.next().is_some() {
            return Err(InstallationError::Duplicate {
                kind: "canary removal owner-derived effect".to_owned(),
                identity: format!("{category:?}"),
            });
        }
        if row.resource_identity != identity || row.action != action {
            return Err(InstallationError::IdentityConflict);
        }
        // The plan's own ownership CLAIM is compared here as well, in this same
        // loop, through this same `IdentityConflict`, and only for the two
        // categories whose claim IS the identity this owner re-derives.
        //
        // Before this, `ownership_evidence` was read for SHAPE only —
        // non-empty and handle-valid, by `CanaryRemovalEffect::validate` — plus
        // disjointness from `reference_users`. Nothing compared it to anything
        // observed, so a plan whose owner-derived row carried an arbitrary,
        // owner-never-reported handle passed this fence as long as
        // `resource_identity` was right, and a string this module minted about
        // itself stood in for evidence. A synthetic handle is not evidence.
        //
        // The containment below is an equality in an untouched plan, not a new
        // rule about what evidence may be. `canary_evidence_row` mints
        // `ownership_evidence: vec![root]` from the very value it takes as
        // `resource_identity`, and `store_objects_row` mints
        // `vec![owner_recorded_store_binding]` from the very
        // `CanaryRemovalBuildBinding::from_manifest` member it takes as
        // `resource_identity`. Those are the two expressions re-derived at the
        // two entries above from the transaction the durable store holds, so a
        // plan this owner produced always contains them and an untouched plan is
        // never refused here.
        //
        // `GenerationRegistryRecord` is deliberately NOT constrained, because
        // its claim is not the owner's re-derived identity: `registry_record_row`
        // mints `canary-removal/evidence/registry-record:{generation}`, a handle
        // this module invented about itself whose only input is the generation,
        // while the identity re-derived for that category is the generation
        // itself. Requiring the generation in that row's evidence would refuse
        // this owner's own untouched plans, so the claim there stays
        // shape-checked only. What that row's evidence would take is the card's
        // own decision — an owner-issued terminal receipt binding the removal
        // operation id, generation, predecessor revision and resulting
        // revision/content digest, or `Unsupported` so the fence guard blocks
        // apply — and neither is a comparison this function may invent.
        if matches!(
            category,
            CanaryRemovalResource::CanaryEvidenceRoot | CanaryRemovalResource::StoreObjects
        ) && !row.ownership_evidence.contains(&identity)
        {
            return Err(InstallationError::IdentityConflict);
        }
    }
    Ok(())
}

/// Re-observes the admission fence and the retirement barrier against the
/// owner's current durable projection.
///
/// The entry-point fence in `revalidate_fence` runs once per apply or recover
/// call. That is not enough for "stop new canary admissions": a pending
/// activation for the dying generation staged after that observation would
/// otherwise be green-lit for every remaining destructive row of the same
/// drive. The same owner projection is therefore re-read immediately before
/// each mutating call, so a new admission, a return to production or
/// last-known-good, or a lost retirement handoff refuses that row instead of
/// being inherited from a stale observation.
///
/// The expected set here is the plan's own frozen quiesce evidence and the
/// owner's own registry projection, never a list supplied alongside the
/// removal request.
fn observe_admission_fence(
    projection: &ApprovedGenerationRegistry,
    plan: &CanaryRemovalPlan,
) -> Result<(), InstallationError> {
    projection.validate()?;
    if projection
        .active_generation()
        .is_some_and(|active| active == &plan.generation)
        || projection
            .last_known_good_generation()
            .is_some_and(|lkg| lkg == &plan.generation)
    {
        return Err(InstallationError::IncompleteObservation(
            "the removal target serves production or is last-known-good again".to_owned(),
        ));
    }
    if let Some(pending) = &projection.pending_activation
        && pending.manifest.generation == plan.generation
    {
        return Err(InstallationError::IncompleteObservation(
            "the removal target is staged in a pending activation".to_owned(),
        ));
    }
    // The serving handoff is re-observed in this same observation: the
    // recorded barrier must still be the handoff the owner currently records
    // for this installation with production served away from the target. A
    // superseding activation, a return of the target to a serving pointer, a
    // foreign handoff, or a lost handoff refuses the dependent stop/delete
    // instead of inheriting a stale observation, so no stop/delete is ever
    // issued for a target whose safe serving handoff this attempt did not see.
    let Some(recorded) = &plan.quiesce.retirement_barrier else {
        return Err(InstallationError::IncompleteObservation(
            "a dependent canary stop/delete requires the observed activation-owner retirement barrier"
                .to_owned(),
        ));
    };
    let observed = observed_retirement_barrier(
        projection,
        &plan.generation,
        &plan.installation_epoch.installation,
    )?;
    if observed.as_ref() != Some(recorded) {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(())
}

/// Reports whether this operation's one recorded reconcile deadline has passed.
///
/// The window is re-derived from the durable operation state, never from a
/// fresh per-call budget, so a resumed or retried reconcile can neither restart
/// nor extend the RECORDED value: the store's compare-and-save path refuses any
/// change to it, and this function takes only the operation, never a caller
/// supplied instant.
///
/// The bound it enforces is wall-clock, not elapsed time. The clock read here is
/// the system clock (see [`super::wall_clock_millis`]), so it is not monotonic
/// and not injectable; a system clock that steps backwards past the recorded
/// deadline makes this return false again and re-opens the window for this SAME
/// removal identity, with no new admission and no new identity. That is a
/// property of the clock, and it is not something this check can close.
///
/// Every path that could issue a destructive call consults this first: at expiry
/// the drive is refused and the durable incomplete recovery is preserved
/// unchanged.
fn reconcile_budget_exhausted(operation: &CanaryRemovalOperation) -> bool {
    wall_clock_millis() >= operation.reconcile_deadline_ms
}

/// Returns the stable read-only disposition of one removal operation.
pub(crate) fn canary_removal_status<P>(
    coordinator: &InstallationCoordinator<P, RedbInstallationTransactionStore>,
    removal_transaction_id: &PlatformHandle,
) -> Result<CanaryRemovalStatus, InstallationError>
where
    P: InstallationEffectPort,
{
    Ok(load_operation(coordinator, removal_transaction_id)?.project())
}

fn resolve_approved_generation<'a>(
    projection: &'a ApprovedGenerationRegistry,
    generation: &PlatformHandle,
) -> Result<&'a super::ApprovedGeneration, InstallationError> {
    let mut matches = projection
        .generations()
        .iter()
        .filter(|entry| &entry.manifest.generation == generation);
    let Some(entry) = matches.next() else {
        return Err(InstallationError::IncompleteObservation(format!(
            "generation {} is not an approved generation of this installation",
            generation.as_str()
        )));
    };
    if matches.next().is_some() {
        return Err(InstallationError::Duplicate {
            kind: "approved generation".to_owned(),
            identity: generation.as_str().to_owned(),
        });
    }
    Ok(entry)
}

/// Counts the original transaction's installer effects that are not
/// authoritatively applied.
///
/// The count is read from the transaction's own durable effect roster, so a
/// frozen plan can never record an empty open-effect set that the install
/// record itself does not admit.
fn open_install_effect_count(install: &InstallationTransaction) -> Result<u32, InstallationError> {
    let open = install
        .effect_progress()
        .iter()
        .filter(|progress| {
            !matches!(
                progress.state,
                super::InstallationEffectProgressState::Applied { .. }
            )
        })
        .count();
    u32::try_from(open).map_err(|_| {
        InstallationError::IncompleteObservation(
            "the installed transaction names more open installer effects than one removal can record"
                .to_owned(),
        )
    })
}

/// Counts the original transaction's unacknowledged external changes.
///
/// These are the exact pending writes, ORS operations, outbox rows and external
/// effects the install record still carries unresolved. The count is taken from
/// that record rather than from any list supplied alongside the removal request,
/// so a caller cannot present a narrower set than the transaction owns.
fn pending_external_change_count(
    install: &InstallationTransaction,
) -> Result<u32, InstallationError> {
    u32::try_from(install.pending_external_changes.len()).map_err(|_| {
        InstallationError::IncompleteObservation(
            "the installed transaction names more pending external changes than one removal can record"
                .to_owned(),
        )
    })
}

/// Observes the activation owner's settled handoff to the serving safe
/// generation for one installation, when the registry records one.
///
/// The caller reads the owner's current durable projection, never a list
/// supplied alongside the removal request. The handoff counts only when
/// production is served away from the removal target by this installation's
/// own activation owner:
///
/// * the attributable cutover binding whose operation installed the serving
///   generation, bound to this installation; the receipt's target is the
///   serving generation by registry invariant, so a binding that serves the
///   dying canary itself is no safe handoff;
/// * otherwise the committed activation terminal digest, which carries the
///   Host-owned readiness fence the activation owner observed for the serving
///   generation; an aborted terminal, a terminal without a readiness fence,
///   or a terminal for the dying canary itself is no safe handoff.
///
/// A caller-supplied replacement generation is never accepted here, and the
/// cutover receipt is never treated as retirement authority: it proves only
/// that the serving flip was committed under its operation identity, while
/// retirement stays the separately authorized terminal registry step. `None`
/// means the registry records no settled safe serving handoff — a staged but
/// uncommitted activation, an abort, a foreign handoff, or no handoff at
/// all — and every caller refuses it rather than defaulting it.
fn observed_retirement_barrier(
    projection: &ApprovedGenerationRegistry,
    generation: &PlatformHandle,
    installation: &PlatformHandle,
) -> Result<Option<PlatformHandle>, InstallationError> {
    if let Some(committed) = projection.committed_cutover_activation() {
        if committed.target_generation == *generation || committed.installation != *installation {
            return Ok(None);
        }
        return Ok(Some(committed.operation_id.clone()));
    }
    let Some(terminal) = projection.last_terminal_activation.as_ref() else {
        return Ok(None);
    };
    if terminal.disposition != PendingActivationTerminalDisposition::Committed
        || terminal.commit_fence.is_none()
        || terminal.generation == *generation
    {
        return Ok(None);
    }
    Ok(Some(activation_terminal_digest(terminal)?))
}

fn surviving_generations(
    projection: &ApprovedGenerationRegistry,
    generation: &PlatformHandle,
) -> Vec<PlatformHandle> {
    projection
        .generations()
        .iter()
        .map(|entry| entry.manifest.generation.clone())
        .filter(|candidate| candidate != generation)
        .collect()
}

/// Freezes the complete finite removal effect graph from the original
/// transaction's own effect receipts.
///
/// The classification is uniform and evidence-bound: a row is `REMOVE` only
/// when the original transaction durably created the exact identity and no
/// surviving generation still references it; a shared or preexisting row is
/// `RETAINED` with its ownership evidence; a transaction-created row this owner
/// has no admitted removal path for is `UNSUPPORTED` and therefore blocks
/// apply instead of leaving the denominator. The two shared surfaces appended
/// below, which no owner in this crate can read back at all, are `OUT_OF_SCOPE`:
/// named with their owner-recorded evidence, and neither removed nor proved.
#[allow(
    clippy::too_many_lines,
    reason = "all install effects are classified against one frozen removal denominator"
)]
fn freeze_effect_graph(
    install: &InstallationTransaction,
    survivors: &[PlatformHandle],
) -> Result<Vec<CanaryRemovalEffect>, InstallationError> {
    let mut rows = Vec::new();
    for (index, effect) in install.installer_effects.iter().enumerate() {
        let progress = install
            .effect_progress()
            .get(index)
            .ok_or(InstallationError::IdentityConflict)?;
        let (category, identity, shared, removal_supported) = match effect {
            InstallerEffectPlan::CreateRoot { .. } => (
                CanaryRemovalResource::InstallationRoot,
                applied_identity(progress)?,
                true,
                false,
            ),
            InstallerEffectPlan::ApplyAcl { .. } => (
                CanaryRemovalResource::InstallationAcl,
                applied_identity(progress)?,
                true,
                false,
            ),
            InstallerEffectPlan::StagePackage { .. } => (
                CanaryRemovalResource::GenerationPackageRoot,
                applied_identity(progress)?,
                false,
                true,
            ),
            InstallerEffectPlan::RegisterService { .. } => (
                CanaryRemovalResource::ServiceRegistration,
                applied_identity(progress)?,
                true,
                false,
            ),
            InstallerEffectPlan::StartService { .. } => (
                CanaryRemovalResource::ServiceStart,
                applied_identity(progress)?,
                true,
                false,
            ),
            InstallerEffectPlan::ProvisionStoreCredential { .. } => (
                CanaryRemovalResource::StoreCredential,
                applied_identity(progress)?,
                false,
                true,
            ),
            InstallerEffectPlan::ProvisionUserModeSupervisionAuthority { .. } => (
                CanaryRemovalResource::UserModeAuthorityCredential,
                applied_identity(progress)?,
                false,
                true,
            ),
            InstallerEffectPlan::MaterializePhaseB { .. } => (
                CanaryRemovalResource::PhaseBLiveOverlay,
                applied_identity(progress)?,
                true,
                false,
            ),
        };
        let created = matches!(
            progress.state,
            super::InstallationEffectProgressState::Applied {
                disposition: super::InstallationEffectDisposition::CreatedByTransaction,
                ..
            }
        );
        let origin = if created {
            CanaryRemovalResourceOrigin::CreatedByInstallTransaction
        } else {
            CanaryRemovalResourceOrigin::PreexistingAtInstall
        };
        let reference_users = if shared {
            survivors.to_vec()
        } else {
            Vec::new()
        };
        let action = classify_action(origin, !reference_users.is_empty(), removal_supported);
        rows.push(CanaryRemovalEffect {
            effect_id: effect.effect_id().clone(),
            category,
            origin,
            action,
            resource_identity: identity,
            ownership_evidence: ownership_evidence(install, index)?,
            reference_users,
            prerequisites: Vec::new(),
            expected_postcondition: if action == CanaryRemovalAction::Remove {
                CanaryRemovalPostcondition::Absent
            } else {
                CanaryRemovalPostcondition::Retained
            },
            reconciliation_query: reconciliation_query(install, index, action)?,
            bound: CanaryRemovalEffectBound::new(),
            install_effect_index: Some(u32::try_from(index).map_err(|_| {
                InstallationError::InvalidField {
                    field: "canary_removal.effect.install_effect_index".to_owned(),
                    reason: "installer effect index is out of range".to_owned(),
                }
            })?),
        });
    }
    rows.push(canary_evidence_row(install, survivors)?);
    rows.push(store_objects_row(install)?);
    rows.push(registry_record_row(&install.candidate_manifest.generation)?);
    order_effect_graph(&mut rows);
    Ok(rows)
}

fn classify_action(
    origin: CanaryRemovalResourceOrigin,
    referenced: bool,
    removal_supported: bool,
) -> CanaryRemovalAction {
    if origin != CanaryRemovalResourceOrigin::CreatedByInstallTransaction || referenced {
        CanaryRemovalAction::Retain
    } else if removal_supported {
        CanaryRemovalAction::Remove
    } else {
        CanaryRemovalAction::Unsupported
    }
}

fn applied_identity(
    progress: &super::InstallationEffectProgress,
) -> Result<PlatformHandle, InstallationError> {
    match &progress.state {
        super::InstallationEffectProgressState::Applied {
            external_identity, ..
        } => Ok(external_identity.clone()),
        _ => Err(InstallationError::IncompleteObservation(
            "canary removal requires an applied installer effect receipt".to_owned(),
        )),
    }
}

fn ownership_evidence(
    install: &InstallationTransaction,
    index: usize,
) -> Result<Vec<PlatformHandle>, InstallationError> {
    let progress = install
        .effect_progress()
        .get(index)
        .ok_or(InstallationError::IdentityConflict)?;
    let super::InstallationEffectProgressState::Applied {
        evidence,
        postcondition_digest,
        ..
    } = &progress.state
    else {
        return Err(InstallationError::IncompleteObservation(
            "canary removal requires an applied installer effect receipt".to_owned(),
        ));
    };
    let mut owned = vec![
        handle_ref(&format!(
            "canary-removal/evidence/install-effect:{}:{}",
            install.transaction_id.as_str(),
            install.installer_effects[index].effect_id().as_str()
        ))?,
        postcondition_digest.clone(),
    ];
    owned.extend(evidence.iter().cloned());
    Ok(owned)
}

fn reconciliation_query(
    install: &InstallationTransaction,
    index: usize,
    action: CanaryRemovalAction,
) -> Result<PlatformHandle, InstallationError> {
    let disposition = if action == CanaryRemovalAction::Remove {
        "remove"
    } else {
        "retain"
    };
    PlatformHandle::new(format!(
        "canary-removal/reconcile/{disposition}:{}:{}",
        install.transaction_id.as_str(),
        install.installer_effects[index].effect_id().as_str()
    ))
    .map_err(|error| platform_error(&error))
}

/// Freezes the `CanaryEvidenceRoot` row as `OutOfScope`, because no owner in
/// this crate can observe this root from outside the plan.
///
/// Issue #1138's removal algorithm step 2 requires the out-of-scope categories
/// to be NAMED WITH EVIDENCE rather than dropped from the denominator, and this
/// row is named: its category, its `ForeignToThisRemoval` origin, the exact root
/// the runtime topology derives, its reference users, its bound and its
/// reconciliation query are all frozen here and bound by `plan_digest`, so the
/// surface cannot disappear from the denominator and cannot be relabelled as
/// something this removal removed or proved.
///
/// The row stays in the denominator, and two of its members are still load-
/// bearing. Its `resource_identity` is the exact root the runtime topology
/// derives, and that identity is compared identity for identity against the
/// transaction the durable store holds — but `revalidate_fence` does not make
/// that comparison itself. The comparison lives in
/// `require_quiesced_owner_effects`, in its `expected_owners` loop, which
/// re-derives this category's root from the transaction; `revalidate_fence`
/// reaches it only by calling that function (as do
/// `reobserve_before_mutation` before each mutating call and
/// `finish_with_readback` before the terminal retirement). A plan that froze a
/// substituted root is therefore refused, by that function and not by the
/// entry-point fence's own text.
///
/// Its `ownership_evidence` is that same root, and the same loop requires it to
/// CONTAIN the re-derived root as well. That is an equality in an untouched plan
/// rather than a new rule: the `vec![root]` minted below is the very value taken
/// as `resource_identity`, so requiring it is what stops a plan from keeping the
/// admitted root while replacing the claim about who holds it with a handle no
/// owner ever reported.
///
/// Its `reference_users` are the survivor set this plan committed to keep, and
/// that set is the only record of it: THAT pin does live in `revalidate_fence`
/// itself, as the `planned_survivors(plan)? != observed_survivors(&projection,
/// plan)` comparison before the terminal commit, and `terminal_proofs_hold`
/// then requires every member of it to still be projected. What the row cannot
/// do is observe the root itself.
///
/// The readback it used to carry re-derived `canary_evidence_root()` from the
/// manifest the plan froze and compared it with the row the plan had set from
/// that very expression. `revalidate_fence` proves
/// `candidate_manifest_digest(&install.candidate_manifest)? == plan.manifest_digest`
/// before any row is driven, so that comparison could not fail. Deleting the
/// root from disk after planning leaves both sides byte-identical, which means
/// the readback could not observe the one thing it existed to observe.
///
/// `InstallationEffectPort` cannot supply the missing observation. Its complete
/// method set is: `fresh_service_registration_nonce`,
/// `fresh_ownership_secret_reference`, `prepare_ownership_secret`,
/// `prepare_user_mode_authority`, `has_prepared_user_mode_authority`,
/// `discard_prepared_user_mode_authority`, `provision_ownership_secret`,
/// `execute`, `execute_service`, `inspect`, `reconcile`,
/// `delete_ownership_secret` and `ownership_secret_absent`. Only `inspect` and
/// `reconcile` return an observation, both require an `&InstallationEffectRequest`,
/// and the only constructor of that request in this crate is `effect_request`,
/// which clones one entry of the original install transaction's own
/// `installer_effects` roster. No parameter of any of the thirteen methods is a
/// bare filesystem root path, and `InstallerEffectPlan` has no variant that names
/// one independently of a transaction-owned installer effect.
///
/// `reconcile` does read a root for real — the production adapter falls through
/// to `reconcile_primitive`, which calls `WindowsInstallerRootPrimitive::inspect`
/// on the requested root — but only for a request addressed to that row's own
/// `CreateRoot`/`ApplyAcl` effect, and the identity it reports is a digest over
/// the observed root object snapshot, never the root path. This row's
/// `resource_identity` IS a path, so that observation has nothing to be compared
/// against, and its `ForeignToThisRemoval` origin is refused outright by
/// `classify_observation`, which admits `Matching` only for a row this
/// transaction created or adopted. That row already exists: `freeze_effect_graph`
/// derives an `InstallationRoot` row from the same `CreateRoot` effect, and that
/// row carries exactly this comparison against the owner's own verdict. A second
/// row pointed at the same effect would duplicate one installer effect across two
/// rows, which `require_complete_effect_coverage` refuses.
///
/// So this owner records the surface, names the missing capability in the
/// classification itself, and reports it as out of scope rather than comparing a
/// string with itself.
fn canary_evidence_row(
    install: &InstallationTransaction,
    survivors: &[PlatformHandle],
) -> Result<CanaryRemovalEffect, InstallationError> {
    let root = install
        .candidate_manifest
        .runtime_launch
        .runtime_state_roots
        .canary_evidence_root()?;
    let reference_users = survivors.to_vec();
    let query = format!(
        "canary-removal/reconcile/canary-evidence-root:{}",
        install.transaction_id.as_str()
    );
    Ok(CanaryRemovalEffect {
        effect_id: handle_ref(&format!(
            "canary-removal/effect/canary-evidence-root:{}",
            install.transaction_id.as_str()
        ))?,
        category: CanaryRemovalResource::CanaryEvidenceRoot,
        origin: CanaryRemovalResourceOrigin::ForeignToThisRemoval,
        action: CanaryRemovalAction::OutOfScope,
        resource_identity: root.clone(),
        ownership_evidence: vec![root],
        reference_users,
        prerequisites: Vec::new(),
        expected_postcondition: CanaryRemovalPostcondition::Retained,
        reconciliation_query: PlatformHandle::new(query).map_err(|error| platform_error(&error))?,
        bound: CanaryRemovalEffectBound::new(),
        install_effect_index: None,
    })
}

/// Freezes the `StoreObjects` row as `OutOfScope`, because no Store or Blob
/// owner is reachable from this crate.
///
/// Issue #1138's removal algorithm step 2 requires the out-of-scope categories
/// to be NAMED WITH EVIDENCE rather than dropped from the denominator, and this
/// row is named: its category, its `ForeignToThisRemoval` origin, the
/// generation's own owner-recorded Store binding, its bound and its
/// reconciliation query are all frozen here and bound by `plan_digest`.
///
/// The row stays in the denominator with the generation's owner-recorded Store
/// binding as its identity, because it accounts for a resource this removal does
/// not destroy. That identity is still compared against the binding the
/// transaction the durable store holds derives, so a plan that froze a
/// substituted Store identity is refused — but `revalidate_fence` does not make
/// that comparison itself. The comparison lives in
/// `require_quiesced_owner_effects`, in its `expected_owners` loop, which
/// re-derives this category's Store binding from the transaction;
/// `revalidate_fence` reaches it only by calling that function (as do
/// `reobserve_before_mutation` before each mutating call and
/// `finish_with_readback` before the terminal retirement). What the row cannot
/// do is enumerate or observe the canonical Store and Blob objects a generation
/// actually wrote, and no readback may stand in for that.
///
/// The row's `ownership_evidence` is that same owner-recorded binding, and the
/// same loop requires it to CONTAIN the re-derived binding as well. In an
/// untouched plan that is an equality, not a new rule: the
/// `vec![owner_recorded_store_binding]` minted below is the very value taken as
/// `resource_identity`. That is what replaced the
/// `canary-removal/evidence/store-owner:{generation}` handle this card's DO NOT
/// calls out: a claim the owner minted about itself could only restate this
/// row's own identity and so could never fail, whereas the manifest's approved
/// Store bridge binding is an artifact digest the installation transaction
/// durably carried and that apply can therefore disagree with.
///
/// Why there is no owner readback, measured rather than assumed:
///
/// * `crates/kernel/eliot-installation/Cargo.toml` declares eliot-config,
///   eliot-contracts, eliot-ipc, eliot-platform, eliot-platform-windows,
///   eliot-protocol, eliot-runtime-contracts, redb, schemars, serde, `serde_json`,
///   sha2, thiserror and tokio. There is no Store or Blob dependency, so this
///   crate cannot name the canonical Store or Blob owner at all.
/// * `git grep -n "trait .*Store\|trait .*Blob" -- crates/kernel/eliot-installation/`
///   returns exactly one hit: `pub trait InstallationTransactionStore`, which is
///   the installation transaction store, not the canonical Store owner.
/// * The generation-scoped owner reads DO exist in this repository, in
///   `crates/storage/eliot-blob-api`: `BlobLiveSetProof` with its
///   `LiveSetCompleteness`, `BlobReachabilityRequest`/`BlobReachabilityView`,
///   `BlobGcRequest`/`BlobGcReceipt`, `BlobReferenceRequest`/
///   `BlobReferenceObservation`, `BlobHealth`, and `BlobLocator` carrying
///   `root_generation` and `path_generation`. They are fenced by a
///   `BlobRootLease` whose `root_generation` selects the generation, so a
///   Store/Blob row readback is a real capability in this repository — it is
///   simply not reachable from here. Adding this crate as a consumer of that API
///   is the bounded adapter extension the issue's own lane 3 requires to be
///   "serialized with its owner", so it is out of scope for this card and is not
///   done here.
/// * `I3.15` draws the same boundary in normative prose: "Canonical Store
///   receives only later installation/capability observations and policy
///   decisions, not the transaction's operational authority." Reading
///   generation-scoped canonical Store or Blob objects from here would make this
///   crate that owner, which the card forbids.
///
/// A handle this module minted for itself would be worth nothing: it could only
/// restate this row's own generation identity, so it could never fail when the
/// binding the plan froze stopped matching what the transaction holds. Evidence
/// that cannot fail is not evidence, and the row is therefore classified
/// `OutOfScope` and named with the evidence the owner actually recorded, instead
/// of being dropped from the denominator or reported as a retained surface this
/// removal proved.
fn store_objects_row(
    install: &InstallationTransaction,
) -> Result<CanaryRemovalEffect, InstallationError> {
    let generation = &install.candidate_manifest.generation;
    let owner_recorded_store_binding =
        CanaryRemovalBuildBinding::from_manifest(&install.candidate_manifest)?
            .store_bridge_artifact_digest;
    let query = format!("canary-removal/reconcile/store-owner:{generation}");
    Ok(CanaryRemovalEffect {
        effect_id: handle_ref(&format!("canary-removal/effect/store-objects:{generation}"))?,
        category: CanaryRemovalResource::StoreObjects,
        origin: CanaryRemovalResourceOrigin::ForeignToThisRemoval,
        action: CanaryRemovalAction::OutOfScope,
        resource_identity: owner_recorded_store_binding.clone(),
        ownership_evidence: vec![owner_recorded_store_binding],
        reference_users: Vec::new(),
        prerequisites: Vec::new(),
        expected_postcondition: CanaryRemovalPostcondition::Retained,
        reconciliation_query: PlatformHandle::new(query).map_err(|error| platform_error(&error))?,
        bound: CanaryRemovalEffectBound::new(),
        install_effect_index: None,
    })
}

/// Freezes the terminal `GenerationRegistryRecord` row, which is `Remove`.
///
/// Unlike the two `OutOfScope` rows beside it, this row's `ownership_evidence`
/// is NOT the owner's re-derived identity, so the `expected_owners` loop in
/// `require_quiesced_owner_effects` deliberately does not constrain it. The
/// handle minted below is one this module invented about itself from the
/// generation alone, while the identity re-derived for this category is the
/// generation itself, so requiring the generation to appear in this row's
/// evidence would refuse this owner's own untouched plans.
///
/// The row's real identity claim is proved elsewhere and by observation rather
/// than by a plan string: `resource_identity` is compared against the
/// transaction's own generation, and the terminal effect is proved by the
/// owner-issued `CanaryRemovalTerminalReceipt` binding this removal operation
/// id, the generation, the predecessor revision and the resulting revision and
/// content digest, re-read from the projection after the retirement. Replacing
/// this evidence handle with something an owner actually issued, or classifying
/// the row `Unsupported` so the existing fence guard blocks apply, is the card's
/// own decision and is not taken here.
fn registry_record_row(
    generation: &PlatformHandle,
) -> Result<CanaryRemovalEffect, InstallationError> {
    let evidence = PlatformHandle::new(format!(
        "canary-removal/evidence/registry-record:{generation}"
    ))
    .map_err(|error| platform_error(&error))?;
    let query = format!("canary-removal/reconcile/registry-record:{generation}");
    Ok(CanaryRemovalEffect {
        effect_id: handle_ref(&format!(
            "canary-removal/effect/registry-record:{generation}"
        ))?,
        category: CanaryRemovalResource::GenerationRegistryRecord,
        origin: CanaryRemovalResourceOrigin::CreatedByInstallTransaction,
        action: CanaryRemovalAction::Remove,
        resource_identity: generation.clone(),
        ownership_evidence: vec![evidence],
        reference_users: Vec::new(),
        prerequisites: Vec::new(),
        expected_postcondition: CanaryRemovalPostcondition::Absent,
        reconciliation_query: PlatformHandle::new(query).map_err(|error| platform_error(&error))?,
        bound: CanaryRemovalEffectBound::new(),
        install_effect_index: None,
    })
}

/// Orders the frozen graph so every prerequisite row precedes its dependent
/// row and the terminal registry record stays last.
///
/// The terminal registry record is the hand-off of control to the surviving
/// installer/Host owner, so it cannot commit before every resource outcome is
/// observed. Keeping it last is also what leaves the running coordinator, its
/// journal and its recovery key available until the final readback finishes.
///
/// EVERY row is placed by the same four-band key, not only the removed ones. A
/// retained, shared, preexisting or owner-derived row that was left unplaced
/// would sort behind the terminal record and then never be re-read before the
/// operation commits, so each row is ranked rather than given a fallback
/// position. Within one band, rows keep `effect_id` order so the frozen graph is
/// deterministic, and `prerequisites` is then exactly the set of rows positioned
/// before each row. See `order_band` for what the four bands are and why they
/// are in that order.
fn order_effect_graph(rows: &mut [CanaryRemovalEffect]) {
    rows.sort_by(|left, right| {
        order_band(left)
            .cmp(&order_band(right))
            .then_with(|| left.effect_id.cmp(&right.effect_id))
    });
    let order = rows
        .iter()
        .map(|row| row.effect_id.clone())
        .collect::<Vec<_>>();
    for row in rows.iter_mut() {
        row.prerequisites = order
            .iter()
            .take_while(|id| *id != &row.effect_id)
            .cloned()
            .collect();
    }
}

/// Execution band of one removal row, ordered by WHAT THE ROW CAN DO rather than
/// by what class it was given, because only a mutating row can make this drive
/// irreversible:
///
/// * **Band 0 — a row no owner this crate can reach can read back.** It carries no
///   installer effect and is not the terminal registry record, which is exactly
///   the shape `readback_request` refuses: there is no owner to ask and no
///   evidence any owner could report, so the drive cannot close it. `advance_row`
///   refuses such a row before it can reach `port.execute` — through
///   `read_retained_row` for a non-`Remove` row, and through its own
///   "names no installer effect" guard for a `Remove` one.
/// * **Band 1 — the only rows that mutate.** `Remove` with an installer effect is
///   the sole shape `advance_row` drives through `reobserve_before_mutation`,
///   `commit_intent` and `port.execute`.
/// * **Band 2 — read-only and readable.** A non-`Remove` row WITH an installer
///   effect is read once through the owner that holds the resource and closed as
///   `Retained`; it can neither mutate nor be refused for want of a readback.
/// * **Band 3 — the terminal registry record**, the hand-off of control.
///
/// Band 0 therefore precedes band 1 for the only reason that matters: a row that
/// cannot be read back is DETECTED before any destructive call is issued. While
/// `StoreObjects` and `CanaryEvidenceRoot` were `Unsupported`, `revalidate_fence`
/// refused them before any row was driven; classified `OutOfScope` they are no
/// longer a required cleanup, that fence does not fire for them, and the refusal
/// became `readback_request`'s inside the per-row drive. Ranking them beside the
/// `Remove` rows — behind them, as an action-only key puts them — would place that
/// refusal after every destructive row had already been driven, which is the
/// regression this order removes. Readable `Retain` rows keep their existing
/// position AFTER the mutating rows, so the only ordering change is the one the
/// refusal requires.
///
/// Every row falls into exactly one band, which is what guarantees that no row can
/// end up behind the terminal registry record.
fn order_band(row: &CanaryRemovalEffect) -> u8 {
    if row.category == CanaryRemovalResource::GenerationRegistryRecord {
        3
    } else if row.install_effect_index.is_none() {
        0
    } else if row.action == CanaryRemovalAction::Remove {
        1
    } else {
        2
    }
}

fn load_operation<P>(
    coordinator: &InstallationCoordinator<P, RedbInstallationTransactionStore>,
    removal_transaction_id: &PlatformHandle,
) -> Result<CanaryRemovalOperation, InstallationError>
where
    P: InstallationEffectPort,
{
    let operation = coordinator
        .store()
        .load_canary_removal_operation(removal_transaction_id)?
        .ok_or_else(|| InstallationError::TransactionNotFound {
            transaction_id: removal_transaction_id.as_str().to_owned(),
        })?;
    operation.validate()?;
    Ok(operation)
}

fn admit_or_resume<P>(
    coordinator: &mut InstallationCoordinator<P, RedbInstallationTransactionStore>,
    plan: &CanaryRemovalPlan,
) -> Result<CanaryRemovalOperation, InstallationError>
where
    P: InstallationEffectPort,
{
    plan.validate()?;
    if let Some(existing) = coordinator
        .store()
        .load_canary_removal_operation(&plan.removal_transaction_id)?
    {
        existing.validate()?;
        if existing.plan.plan_digest != plan.plan_digest {
            return Err(InstallationError::IdentityConflict);
        }
        return Ok(existing);
    }
    let operation = CanaryRemovalOperation::admit(plan.clone())?;
    coordinator
        .store_mut()
        .create_canary_removal_operation(&operation)?;
    Ok(operation)
}

/// Builds the one typed refusal for a frozen row this owner cannot drive.
///
/// The row is named, its closed category is named, and the missing OWNER
/// CAPABILITY is named, because those are the three different things a reader has
/// to tell apart.
///
/// The only row shape this builder refuses is a REQUIRED CLEANUP this owner
/// cannot perform: a transaction-owned resource the plan names as
/// `UNSUPPORTED`, which issue #1138's removal algorithm step 2 says "blocks
/// apply—it must not disappear from the denominator". It is deliberately the
/// ONLY arm left. `StoreObjects` and `CanaryEvidenceRoot` used to have their own
/// arms here because the frozen graph used to classify them `UNSUPPORTED`, which
/// made a shared surface look like a required cleanup. They no longer do: they
/// are `OUT_OF_SCOPE`, and `require_quiesced_owner_effects` runs before this
/// builder's caller and pins both categories to exactly that action. A row of
/// either category reaching this builder would already have been refused upstream,
/// so keeping arms for them here would be branches no plan can reach. The measured
/// reason each one needs no readback lives with its own row constructor:
/// `canary_evidence_row` names the thirteen-method `InstallationEffectPort` set
/// and the fact that its `resource_identity` is a path no port method accepts,
/// and `store_objects_row` names the absent Store/Blob dependency and the
/// generation-scoped reads that do exist in `crates/storage/eliot-blob-api` but
/// are unreachable from here, with the same `I3.15` boundary quoted in both.
///
/// The failure stays the existing `InstallationError::IncompleteObservation`:
/// the type is unchanged, there is no second refusal path and no wrapper enum,
/// because a required cleanup this owner cannot perform leaves the observation
/// incomplete rather than failed.
fn unsupported_cleanup_refusal(row: &CanaryRemovalEffect) -> InstallationError {
    InstallationError::IncompleteObservation(format!(
        "the frozen plan names a required cleanup this owner cannot perform: removal row {} carries \
         category {:?} as UNSUPPORTED because this owner has no admitted removal path for that \
         transaction-owned resource; apply is refused before any row is driven and no removal \
         evidence is minted for it. A SHARED or PREEXISTING surface this owner cannot observe is \
         not a required cleanup and is never refused here: it is named in the denominator as \
         OUT_OF_SCOPE instead",
        row.effect_id.as_str(),
        row.category
    ))
}

/// Revalidates the durable fence before any destructive action: the exact
/// installed transaction and its active-verified finished stage, the re-observed drain
/// evidence (applied effects, no pending external change, no held activation
/// intent), the current registry revision, the target's still-retired
/// position, any pending activation, and the required re-observed
/// activation-owner retirement handoff a dependent stop/delete has to follow.
///
/// A target the registry has ALREADY stopped carrying is recognised through the
/// same rule and never through its absence: either this identity's own
/// owner-issued terminal receipt is on file and passes every check, or this
/// operation's own pre-terminal rows are all resolved and the live projection
/// still proves the terminal state, which admits the repair that re-mints the
/// receipt a pre-receipt crash lost. Anything else refuses and names what is
/// missing. Both admitted states skip the admission fence and the revision pin
/// because the terminal step has already committed.
#[allow(
    clippy::too_many_lines,
    reason = "the pre-destructive fence keeps every drift check in one auditable boundary"
)]
fn revalidate_fence<P>(
    coordinator: &InstallationCoordinator<P, RedbInstallationTransactionStore>,
    registry: &RedbInstallationRegistry,
    operation: &CanaryRemovalOperation,
) -> Result<InstallationTransaction, InstallationError>
where
    P: InstallationEffectPort,
{
    let plan = &operation.plan;
    // The `Unsupported` guard runs below, against `already_retired`, so that a
    // REQUIRED CLEANUP this owner cannot perform blocks a NEW destructive drive
    // without stranding an operation whose terminal effect already committed.
    // See the guard at its own site for why that distinction is load bearing.
    let install = coordinator
        .store()
        .load(&plan.install_transaction_id)?
        .ok_or_else(|| InstallationError::TransactionNotFound {
            transaction_id: plan.install_transaction_id.as_str().to_owned(),
        })?;
    install.validate()?;
    if install.installer_plan_digest != plan.install_plan_digest
        || install.candidate_manifest.generation != plan.generation
        || candidate_manifest_digest(&install.candidate_manifest)? != plan.manifest_digest
    {
        return Err(InstallationError::IdentityConflict);
    }
    if install.stage() != InstallationStage::ActiveVerified {
        return Err(InstallationError::IdentityConflict);
    }
    // Quiesce is re-observed at fence time, not just at plan time: the drain
    // evidence (every installer effect authoritatively applied, no
    // unacknowledged external change, no activation intent still held by the
    // activation owner) must still hold immediately before a dependent
    // stop/delete, so a drift between planning and execution can never
    // green-light a destructive call. An incomplete drain stays a refusal and
    // preserves the durable incomplete recovery; it never forces a green
    // cleanup.
    //
    // `require_quiesced_owner_effects` is that whole observation in one place:
    // the exact jobs, the pending writes/ORS/outbox entries and the canary's own
    // lease/session/route authority, each compared against the transaction's own
    // durable record rather than against a list supplied with the request. The
    // plan's recorded quiesce counts are re-derived from the transaction's roster
    // inside it, so a plan can never be read as covering a narrower set of open
    // effects or pending writes/ORS/outbox rows than the transaction actually
    // owns.
    require_quiesced_owner_effects(&install, plan)?;
    // The frozen effect graph is checked against the install transaction's own
    // effect roster, which is the independent expected set: every installer
    // effect of the transaction must have exactly one plan row naming that
    // exact effect identity, and every plan row that claims an installer effect
    // must name one that exists. Comparing the graph against itself would
    // prove nothing and could not detect a dropped or substituted member.
    require_complete_effect_coverage(&install, plan)?;
    let projection = registry.load()?;
    projection.validate()?;
    // The target generation record is the one registry member a completed
    // removal may make absent, and only as its terminal step. Its absence is
    // therefore the observation that the terminal registry retirement already
    // committed before a crash lost this operation's final save — but absence
    // alone names no operation, so neither branch below treats it as a proof.
    // A receipt this owner issued for this exact removal identity is what
    // attributes the effect; when that receipt does not exist yet, the crash fell
    // BEFORE it was written and the attribution comes instead from this
    // operation's own resolved pre-terminal rows plus the live terminal proofs.
    // Registry drift that happened after the commit is unrelated activity and is
    // not drift of this removal, which is why neither branch reads a revision.
    let already_retired = match resolve_approved_generation(&projection, &plan.generation) {
        Ok(target) => {
            if target.active
                || target.last_known_good
                || projection
                    .active_generation()
                    .is_some_and(|active| active == &plan.generation)
                || projection
                    .last_known_good_generation()
                    .is_some_and(|lkg| lkg == &plan.generation)
            {
                return Err(InstallationError::IncompleteObservation(
                    "the removal target serves production or is last-known-good again".to_owned(),
                ));
            }
            false
        }
        Err(InstallationError::IncompleteObservation(_)) => {
            match terminal_receipt_recognises_retirement(coordinator, &projection, plan)? {
                TerminalRetirementEvidence::ReceiptOnFile => true,
                // A crash between the terminal commit and the receipt save leaves
                // the target absent with nothing on file. That absence names no
                // operation, so it is admitted ONLY when this operation's own
                // pre-terminal rows are already resolved and the live projection
                // still proves the terminal state: then the drive that re-enters
                // re-reads and re-mints the missing receipt instead of assuming
                // the effect, and issues no second destructive call.
                TerminalRetirementEvidence::NoReceiptOnFile => {
                    pre_receipt_crash_window_is_repairable(operation, &projection)?
                }
            }
        }
        Err(error) => return Err(error),
    };
    // One guard, and it refuses before any row is driven. It now refuses exactly
    // one shape: a REQUIRED CLEANUP this owner cannot perform, which issue
    // #1138's removal algorithm step 2 says "blocks apply—it must not disappear
    // from the denominator". The refusal names the blocking row's identity and
    // its closed category, and it says explicitly that a shared or preexisting
    // surface this owner cannot observe is not such a cleanup.
    //
    // What can still produce such a row, measured rather than assumed:
    // `freeze_effect_graph` cannot, at plan time. Every category whose
    // `removal_supported` is false — `CreateRoot`, `ApplyAcl`,
    // `RegisterService`, `StartService`, `MaterializePhaseB` — is also `shared`,
    // so its `reference_users` is the observed survivor set; and `plan_canary_removal`
    // refuses a target with no settled handoff to a serving generation other than
    // itself, which requires that generation to be present in the registry
    // (`approved_generation_registry.rs` `validate` and `validate_terminal_activation`),
    // so the survivor set is never empty and `classify_action` always returns
    // `Retain` for those rows. A SHARED surface is therefore never the producer.
    // The producer is an EXTERNALLY SUPPLIED PLAN: `apply_canary_removal` admits
    // whatever `CanaryRemovalPlanEnvelope` a caller hands it, `CanaryRemovalPlan::validate`
    // admits an `Unsupported` row on a transaction-created installer-effect
    // category, and `computed_digest` is public, so such a document is
    // constructible. This guard is that document's only production reader, which
    // is why the variant and the guard both stay.
    //
    // It is gated on `!already_retired` for the same reason the admission fence
    // and the revision pin are. A required cleanup this owner cannot perform
    // blocks a NEW destructive drive, which is what the issue requires: the row
    // stays in the denominator and apply refuses rather than minting evidence no
    // owner issued. It must NOT block the path that repairs an operation whose
    // terminal effect ALREADY committed. Refusing there would strand the
    // operation forever: the terminal registry commit and the owner-issued
    // receipt are separate durable writes, so a crash between them leaves an
    // absent target that only this path can reconcile. Blocking it would trade a
    // truthful refusal for an unrecoverable wedge and would make the card's own
    // crash-resume guarantee — recover the SAME operation by its terminal receipt
    // with no second destructive mutation — impossible to reach at all.
    if !already_retired
        && let Some(row) = plan
            .effects
            .iter()
            .find(|row| row.action == CanaryRemovalAction::Unsupported)
    {
        return Err(unsupported_cleanup_refusal(row));
    }
    // The admission fence is re-observed before the revision pin: a pending
    // activation staged for the dying generation after the plan was frozen is
    // a fence refusal naming the exact race, not a generic revision drift. All
    // other registry drift still conflicts below, so unrelated staging can
    // never green-light a destructive call either.
    if !already_retired {
        observe_admission_fence(&projection, plan)?;
    }
    if !already_retired && projection.revision() != plan.registry_revision {
        return Err(InstallationError::CompareAndSaveConflict {
            expected: plan.registry_revision,
            actual: projection.revision(),
        });
    }
    // The survivor set the plan committed to keep is PINNED on every path that can
    // reach `terminal_proofs_hold`, but the pin has two forms and only one of
    // them is an equality, because the registry state the two paths present is
    // not the same.
    //
    // Before this operation's terminal retirement commits, the revision pin above
    // makes THIS projection the exact projection the frozen plan was resolved
    // against, so the committed set is re-derived from the registry and must
    // EQUAL the set the plan carries in its `CanaryEvidenceRoot` row. That row is
    // the ONLY record of the plan-time survivor set and nothing else re-derives
    // it, so without this comparison a plan that silently dropped a survivor from
    // its own committed set would still pass the terminal proof: a SMALLER
    // committed set is trivially a subset of the live one, and the proof's
    // superset test can no longer distinguish "unrelated activity added a
    // generation this plan could not have named" from "this plan promised to keep
    // fewer generations than it did". That equality is the strong form, and it is
    // the only one available while the plan's own revision is still live.
    //
    // Once the retirement HAS committed, the plan-time projection no longer
    // exists to compare against: the target is already absent, the registry has
    // moved past `plan.registry_revision`, and unrelated activity may legitimately
    // have admitted or retired a generation in between. Demanding EQUALITY there
    // would re-introduce exactly the crash wedge the terminal receipt exists to
    // remove — the same reason `terminal_receipt_recognises_retirement` treats its
    // recorded revision as a monotonicity FLOOR rather than an equality. On that
    // path the committed set cannot be re-derived, so the strongest relation
    // available is the one `terminal_proofs_hold` applies: every generation the
    // plan promised to keep must still be projected. This same fence has ALREADY
    // applied exactly that relation, higher up, through
    // `pre_receipt_crash_window_is_repairable` — so the committed set is pinned
    // on this path too, and a survivor that vanished is refused here rather than
    // after a receipt was minted. Repeating the subset test at this site would be
    // a branch that cannot fail.
    if !already_retired && planned_survivors(plan)? != observed_survivors(&projection, plan) {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(install)
}

/// What this owner holds for its own removal identity once the target is
/// already absent from the live registry projection.
///
/// The distinction is the whole point: absence alone attributes nothing, so a
/// missing receipt is reported as a MISSING RECEIPT and never as a proof, and
/// the caller decides from this operation's own durable evidence whether the
/// pre-receipt crash window is repairable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalRetirementEvidence {
    /// This identity's own owner-issued terminal receipt is on file and passed
    /// every check below, so the terminal effect is attributed to this
    /// operation.
    ReceiptOnFile,
    /// No terminal receipt exists for this identity. This is NOT evidence that
    /// this removal committed anything; it only names what is missing.
    NoReceiptOnFile,
}

/// Recognises an already-retired target ONLY by this removal operation's own
/// owner-issued terminal receipt.
///
/// The target generation record is the one registry member a completed removal
/// may make absent, and only as its terminal step. Its absence is therefore the
/// evidence that the terminal retirement already committed — but absence proves
/// nothing about WHICH removal did it, so this owner reads the terminal receipt it
/// issued for this exact removal identity and lets that receipt, not the live
/// projection, carry the attribution. This is the same discipline the approved-
/// generation registry applies to a committed cutover: the pointer cannot tell a
/// replay from a different operation that selected the same target, so the
/// operation-bound receipt is the durable record that makes the effect
/// attributable.
///
/// Two bindings are stable under unrelated registry activity and are required:
/// the receipt names this plan's retired generation, and it records the registry
/// revision this plan was admitted against. The live projection's role is only
/// the monotonicity floor `receipt.resulting_registry_revision` records plus the
/// target's absence, which the caller already establishes; the recorded content
/// digest is not compared HERE, because a digest of the whole live projection
/// moves on any unrelated mutation and this gate must still resume this operation
/// after one. It is compared where the two are actually comparable — in
/// `terminal_receipt_digest`, against the projection the closing call reloaded,
/// and only while that projection still carries the revision the receipt recorded
/// — so a receipt that does not describe the registry it claims to describe still
/// cannot close the operation. The receipt's own digest is never recomputed here
/// to stand in for that check.
///
/// A `None` receipt is reported as [`TerminalRetirementEvidence::NoReceiptOnFile`], which
/// is a statement about this owner's records and not about the registry: absence
/// names no operation, so nothing here treats it as a committed effect. The
/// caller decides whether the operation's own durable per-row progress plus the
/// live terminal proofs make that missing record repairable, and it refuses
/// otherwise rather than driving a destructive pass or minting a receipt on the
/// strength of an absence.
fn terminal_receipt_recognises_retirement<P>(
    coordinator: &InstallationCoordinator<P, RedbInstallationTransactionStore>,
    projection: &ApprovedGenerationRegistry,
    plan: &CanaryRemovalPlan,
) -> Result<TerminalRetirementEvidence, InstallationError>
where
    P: InstallationEffectPort,
{
    let Some(receipt) = coordinator
        .store()
        .load_canary_removal_terminal_receipt(&plan.removal_transaction_id)?
    else {
        return Ok(TerminalRetirementEvidence::NoReceiptOnFile);
    };
    receipt.validate()?;
    if receipt.generation != plan.generation
        || receipt.predecessor_registry_revision != plan.registry_revision
    {
        return Err(InstallationError::IdentityConflict);
    }
    // Monotonicity, not equality: the retirement moved the registry forward to
    // `resulting_registry_revision`, so a live projection behind that floor is an
    // observation about the projection rather than a conflict with this removal's
    // inputs, while a projection that has advanced past it is exactly the
    // unrelated-activity case that must still resume this same operation.
    if projection.revision() < receipt.resulting_registry_revision {
        return Err(InstallationError::IncompleteObservation(format!(
            "the live registry revision {} is behind the terminal revision {} this removal already recorded",
            projection.revision(),
            receipt.resulting_registry_revision
        )));
    }
    Ok(TerminalRetirementEvidence::ReceiptOnFile)
}

/// Decides whether a crash between the terminal registry commit and this
/// operation's final save left a repairable operation behind.
///
/// The target's absence from the registry is NOT evidence here, exactly as
/// `terminal_receipt_recognises_retirement` refuses to treat it as one: absence
/// names no operation. What makes the repair lawful is this operation's OWN
/// durable per-row progress read together with the live terminal proofs:
///
/// * every row the frozen plan positions before the terminal registry record is
///   already `Resolved`, so the drive this call re-enters issues no mutating
///   call at all — `advance` finds nothing left to drive before the terminal
///   record, goes straight to the read-only re-proof, and the retirement block
///   in `finish_with_readback` is skipped because the record is already absent;
///   and
/// * the live projection still proves the terminal state this plan committed
///   to — target absent, serving pointers unchanged, and every survivor the
///   frozen plan committed to keep still projected by the reloaded registry.
///   That is a SUPERSET check, not an equality: a survivor that has VANISHED
///   fails it, while a generation unrelated activity added afterwards is not a
///   member the plan could have named and must not couple this proof to it.
///   This is the very check `finish_with_readback` applies to the projection it
///   reloads before minting anything.
///
/// Either condition failing keeps a typed refusal that says which one failed,
/// so this owner never drives a destructive pass and never mints a terminal
/// receipt on the strength of a target's absence.
fn pre_receipt_crash_window_is_repairable(
    operation: &CanaryRemovalOperation,
    projection: &ApprovedGenerationRegistry,
) -> Result<bool, InstallationError> {
    let terminal_row = terminal_registry_row_position(&operation.plan)?;
    let every_pre_terminal_row_resolved = operation
        .effect_progress
        .get(..terminal_row)
        .is_some_and(|rows| {
            rows.iter()
                .all(|progress| matches!(progress.state, CanaryRemovalEffectState::Resolved { .. }))
        });
    if !every_pre_terminal_row_resolved {
        return Err(InstallationError::IncompleteObservation(
            "the removal target is absent from the registry, this removal operation holds no committed terminal receipt for it, and a removal effect positioned before the terminal registry record is still unresolved; this owner will not drive a destructive pass, and will not mint a terminal receipt, on the strength of the target's absence alone"
                .to_owned(),
        ));
    }
    if !terminal_proofs_hold(projection, &operation.plan)? {
        return Err(InstallationError::IncompleteObservation(
            "the removal target is absent from the registry, this removal operation holds no committed terminal receipt for it, and the live registry no longer proves the terminal state this frozen plan committed to; this owner will not mint a terminal receipt on the strength of the target's absence alone"
                .to_owned(),
        ));
    }
    Ok(true)
}

/// Position of the one terminal registry record row in the frozen graph.
///
/// `order_band` places that category last, so this is the last position of the
/// frozen order. It is resolved by category rather than by position so the
/// per-row drive, the entry fence and the pre-receipt repair check all ask the
/// same question of the same plan instead of each carrying its own copy of the
/// rule.
fn terminal_registry_row_position(plan: &CanaryRemovalPlan) -> Result<usize, InstallationError> {
    plan.effects
        .iter()
        .position(|row| row.category == CanaryRemovalResource::GenerationRegistryRecord)
        .ok_or(InstallationError::IncompleteObservation(
            "the frozen plan lost its terminal registry record".to_owned(),
        ))
}

/// Reports whether one live projection proves the terminal state the frozen
/// plan committed to: the target absent, both serving pointers exactly as
/// planned, and every generation the plan promised to keep still carried.
///
/// This is the single terminal proof in this module and both callers apply it
/// to a projection they reloaded themselves — the entry fence to decide whether
/// a missing terminal receipt is repairable, and `finish_with_readback` before
/// it mints or reuses a receipt. The caller owns `projection.validate()`.
///
/// The observed side comes from a registry read and the expected side from the
/// frozen, digest-bound plan, so the comparison is independent of the projection
/// it checks rather than a copy of it.
///
/// The survivor comparison is a SUPERSET test, not equality, for the same reason
/// the recorded revision is a monotonicity floor rather than an equality: a
/// generation admitted or retired by unrelated registry activity after this
/// removal committed is not a survivor the plan could have named, so demanding
/// that the live set equal the frozen one would wedge recovery of an
/// already-committed terminal effect on activity that has nothing to do with it.
/// The frozen set is the set this removal committed to keep, so that is the set
/// that must still be present: a survivor that vanished fails the subset.
///
/// A subset test is only as trustworthy as the set it starts from, so the frozen
/// set is tied to a registry read on BOTH of the paths that reach this function,
/// by whichever relation each path can actually support:
///
/// * before this operation's terminal retirement commits, the entry fence
///   re-derives the survivor set from the projection the plan's own registry
///   revision identifies and refuses a plan whose committed set is not EXACTLY
///   that set (`revalidate_fence`). That equality is the strong form: it is what
///   detects a plan that dropped a survivor from its own committed set, which a
///   subset test cannot detect, because a dropped survivor leaves the remaining
///   set a valid subset.
/// * after the retirement has committed, the plan-time projection no longer
///   exists, so the committed set can no longer be re-derived and EQUALITY would
///   be unsupportable — the registry has moved on and unrelated activity may
///   legitimately have admitted or retired a generation, exactly as
///   `terminal_receipt_recognises_retirement`'s monotonicity floor already
///   admits. On that path the frozen set can only be required to still be
///   PRESENT, and the same entry fence has already required exactly that,
///   higher up, through `pre_receipt_crash_window_is_repairable`. So the expected
///   side of the superset test below is pinned on that path too, and a survivor
///   that vanished is refused before any receipt is minted rather than after.
fn terminal_proofs_hold(
    projection: &ApprovedGenerationRegistry,
    plan: &CanaryRemovalPlan,
) -> Result<bool, InstallationError> {
    if resolve_approved_generation(projection, &plan.generation).is_ok() {
        return Ok(false);
    }
    Ok(
        projection.active_generation() == plan.quiesce.active_generation.as_ref()
            && projection.last_known_good_generation()
                == plan.quiesce.last_known_good_generation.as_ref()
            && planned_survivors(plan)?.is_subset(&observed_survivors(projection, plan)),
    )
}

/// Drives the dependency-ordered removal effects and the terminal readback.
fn advance<P>(
    coordinator: &mut InstallationCoordinator<P, RedbInstallationTransactionStore>,
    registry: &RedbInstallationRegistry,
    operation: &mut CanaryRemovalOperation,
    install: &InstallationTransaction,
) -> Result<(), InstallationError>
where
    P: InstallationEffectPort,
{
    let registry_row = terminal_registry_row_position(&operation.plan)?;
    for _ in 0..operation.plan.effects.len() {
        let Some(position) = (0..operation.plan.effects.len()).find(|position| {
            !matches!(
                operation.effect_progress[*position].state,
                CanaryRemovalEffectState::Resolved { .. }
            )
        }) else {
            break;
        };
        if matches!(
            operation.effect_progress[position].state,
            CanaryRemovalEffectState::Unknown { .. }
        ) {
            break;
        }
        // The terminal registry record is not driven row by row: it carries no
        // installer effect, it is the hand-off of control, and its outcome is
        // whatever `finish_with_readback` commits after it re-reads every other
        // row. Leaving it unresolved here is what keeps it the last durable step.
        if position == registry_row {
            break;
        }
        advance_row(coordinator, registry, operation, install, position)?;
    }
    // The blocking effect is the FIRST unresolved-outcome row, and one pass over
    // the durable progress names it. A second scan behind an `.any(...)` over the
    // identical predicate could only ever find what that scan already proved, so
    // its `ok_or` was a branch that could not fire: this is the file's existing
    // `let Some(..) else` shape, and the returned `blocking` is the same row the
    // predicate selects.
    if let Some(blocking) = operation
        .effect_progress
        .iter()
        .find(|progress| matches!(progress.state, CanaryRemovalEffectState::Unknown { .. }))
    {
        operation.blocking_effect_id = Some(blocking.effect_id.clone());
        operation.validate()?;
        return Ok(());
    }
    if operation.effect_progress[..registry_row]
        .iter()
        .any(|progress| !matches!(progress.state, CanaryRemovalEffectState::Resolved { .. }))
    {
        operation.validate()?;
        return Ok(());
    }
    // The terminal record keeps the last position in the order, so this is a
    // completeness fence rather than a normal exit: if any row were ever
    // positioned behind the hand-off record, that row would have to be read back
    // after the surviving owner already took control. Refusing here keeps such a
    // plan short of the terminal commit instead of silently reordering around it.
    if operation.effect_progress[(registry_row + 1)..]
        .iter()
        .any(|progress| !matches!(progress.state, CanaryRemovalEffectState::Resolved { .. }))
    {
        operation.validate()?;
        return Ok(());
    }
    finish_with_readback(coordinator, registry, operation, install, registry_row)
}

/// Re-observes everything that could have changed since the entry-point fence,
/// immediately before one mutating call, and refuses that call if any of it did.
///
/// The entry fence observes these once per apply or recover call, so observing
/// them again here is what stops a change made *between two rows of one drive*
/// from being inherited from a now-stale observation:
///
/// * the operation's one recorded reconcile deadline, so a deadline expiring
///   between two rows refuses the next mutating call instead of letting the
///   drive run past its own bound to a terminal `Completed`;
/// * the admission fence, against a projection read now, so a canary admission
///   or a return to production or last-known-good staged between two rows
///   refuses this dependent stop/delete;
/// * the canary's own owner effects and the installer-effect coverage, against
///   a transaction re-loaded from the durable store rather than the one the
///   entry fence read, so a pending write, ORS operation, outbox row or possible
///   external effect, a lease/session/route authority rebound to a neighbour, or
///   a substituted owner-derived identity refuses this mutating call.
///
/// The re-loaded transaction is also compared back to the transaction the entry
/// fence admitted, so a substituted or replaced install transaction is refused
/// rather than quietly re-validated on its own terms.
///
/// Every check here fails closed and returns before any durable write, so a
/// refusal leaves the non-terminal stage, the blocking effect and every
/// unresolved row exactly as the previous rows left them.
fn reobserve_before_mutation(
    registry: &RedbInstallationRegistry,
    store: &RedbInstallationTransactionStore,
    operation: &CanaryRemovalOperation,
    install: &InstallationTransaction,
    row: &CanaryRemovalEffect,
) -> Result<(), InstallationError> {
    // The deadline is re-observed immediately before the mutating call, not
    // only at the entry-point fence. Expiry refuses the call and leaves the
    // durable projection exactly as the previous rows left it: the non-terminal
    // stage, the blocking effect and every unresolved `Unknown` row stay as
    // observed, so a deadline can never author a terminal `Completed` or a
    // clean cleanup.
    if reconcile_budget_exhausted(operation) {
        let unresolved = operation
            .effect_progress
            .iter()
            .filter(|progress| !matches!(progress.state, CanaryRemovalEffectState::Resolved { .. }))
            .count();
        return Err(InstallationError::IncompleteObservation(format!(
            "the bounded reconcile wait for removal {} expired with {} of {} removal effect(s) still unresolved; the exact blocking effect {} keeps this operation in incomplete recovery and no further mutating call is admitted under this operation identity",
            operation.removal_transaction_id.as_str(),
            unresolved,
            operation.plan.effects.len(),
            row.effect_id.as_str()
        )));
    }
    observe_admission_fence(&registry.load()?, &operation.plan)?;
    let observed_install = store.load(&operation.plan.install_transaction_id)?.ok_or(
        InstallationError::TransactionNotFound {
            transaction_id: operation.plan.install_transaction_id.as_str().to_owned(),
        },
    )?;
    observed_install.validate()?;
    if observed_install.transaction_id != install.transaction_id
        || observed_install.installer_plan_digest != operation.plan.install_plan_digest
        || observed_install.candidate_manifest.generation != operation.plan.generation
    {
        return Err(InstallationError::IdentityConflict);
    }
    require_quiesced_owner_effects(&observed_install, &operation.plan)?;
    require_complete_effect_coverage(&observed_install, &operation.plan)
}

/// Revalidates the retained resource identity, commits the exact intent before
/// the mutating call, and persists the observed result before advancing.
///
/// Immediately before the mutating call `reobserve_before_mutation` re-checks
/// the recorded reconcile deadline, the admission fence, the canary's own owner
/// effects and the installer-effect coverage, so none of them can be inherited
/// from the entry-point observation after changing mid-drive.
///
/// A row this plan does NOT remove takes the other branch entirely: it never
/// reaches `reobserve_before_mutation`, `commit_intent` or `port.execute`. It is
/// either read back once through the owner that holds it and resolved as
/// `Retained`, or — when no owner this crate can reach observes its surface —
/// refused by `readback_request`. `order_band` places such a row ahead of every
/// row that can mutate precisely so that this refusal lands before any destructive
/// call; that ordering is what keeps it a refusal rather than an ordering
/// regression. It is not by itself a claim that the drive can continue
/// afterwards, and it cannot: the same refusal recurs on every later drive of the
/// same identity, because the missing observation is a property of the row's
/// category rather than of the attempt.
/// Issuing a rollback for a resource the plan admitted as surviving would mutate
/// exactly the resource the plan promised to leave intact.
///
/// The destructive branch keeps reconcile-before-execute, the committed intent,
/// the mutating call, the post-call readback and both refusals in one function
/// because splitting them would scatter a single pre-destructive boundary across
/// two, which is the shape this file's other fences deliberately avoid.
#[allow(
    clippy::too_many_lines,
    reason = "the destructive branch keeps reconcile, intent, execute, readback and both refusals in one auditable boundary"
)]
fn advance_row<P>(
    coordinator: &mut InstallationCoordinator<P, RedbInstallationTransactionStore>,
    registry: &RedbInstallationRegistry,
    operation: &mut CanaryRemovalOperation,
    install: &InstallationTransaction,
    position: usize,
) -> Result<(), InstallationError>
where
    P: InstallationEffectPort,
{
    let row = operation
        .plan
        .effects
        .get(position)
        .ok_or(InstallationError::IdentityConflict)?
        .clone();
    if row.action != CanaryRemovalAction::Remove {
        return read_retained_row(coordinator, operation, position, &row);
    }
    let Some(index) = row.install_effect_index else {
        return Err(InstallationError::IncompleteObservation(format!(
            "removal row {} claims to remove a resource it names no installer effect for",
            row.effect_id.as_str()
        )));
    };
    let install_index = usize::try_from(index).map_err(|_| InstallationError::IdentityConflict)?;
    let resume = matches!(
        operation.effect_progress[position].state,
        CanaryRemovalEffectState::IntentCommitted { .. }
    );
    let attempt = row.bound;
    let request = effect_request(
        install,
        install_index,
        attempt.attempt,
        InstallationEffectAction::Rollback,
        Some(row.resource_identity.clone()),
    )?;
    let InstallationCoordinator { port, store } = coordinator;
    match port.reconcile(&request) {
        PortOutcome::Known(observed) => match classify_observation(&observed, &row) {
            RowClassification::Absent(evidence) => {
                if evidence.is_empty() {
                    return unknown_row(
                        store,
                        operation,
                        position,
                        readback_ref("unavailable", &row)?,
                    );
                }
                resolve_row(
                    store,
                    operation,
                    position,
                    CanaryRemovalEffectDisposition::Absent,
                    evidence,
                )?;
                return Ok(());
            }
            RowClassification::Matching => {}
            RowClassification::Conflict => return Err(InstallationError::IdentityConflict),
        },
        other => {
            unknown_row(
                store,
                operation,
                position,
                port_pending(other).map_err(|error| platform_error(&error))?,
            )?;
            return Ok(());
        }
    }
    // Everything that could have changed since the entry fence is re-observed
    // here, immediately before the mutating call, rather than inherited from
    // that one observation.
    reobserve_before_mutation(registry, store, operation, install, &row)?;
    let admitted_attempt = if resume {
        let Some(next) = attempt.next() else {
            return unknown_row(store, operation, position, exhausted_bound_ref(&row)?);
        };
        next
    } else {
        attempt
    };
    commit_intent(store, operation, position, admitted_attempt, &request)?;
    port.execute(&request);
    match port.reconcile(&request) {
        PortOutcome::Known(observed) => match classify_observation(&observed, &row) {
            RowClassification::Absent(evidence) => {
                if evidence.is_empty() {
                    unknown_row(
                        store,
                        operation,
                        position,
                        readback_ref("unavailable", &row)?,
                    )?;
                } else {
                    resolve_row(
                        store,
                        operation,
                        position,
                        CanaryRemovalEffectDisposition::Removed,
                        evidence,
                    )?;
                }
            }
            RowClassification::Matching => {
                unknown_row(
                    store,
                    operation,
                    position,
                    unproven_postcondition_ref(&row)?,
                )?;
            }
            RowClassification::Conflict => return Err(InstallationError::IdentityConflict),
        },
        other => unknown_row(
            store,
            operation,
            position,
            port_pending(other).map_err(|error| platform_error(&error))?,
        )?,
    }
    Ok(())
}

/// Reads one row this removal does not destroy back through the owner that holds
/// it, and closes it as `Retained` only on that owner's own verdict.
///
/// The transaction is re-loaded from the durable store inside this function, so
/// the identity compared here is the one the store holds now rather than the one
/// the entry-point fence happened to read. A row that cannot be classified stays
/// `Unknown` under the same removal identity with its blocking effect named, so
/// a retained resource that drifted between plan and readback blocks `Completed`
/// instead of passing on plan-time evidence.
fn read_retained_row<P>(
    coordinator: &mut InstallationCoordinator<P, RedbInstallationTransactionStore>,
    operation: &mut CanaryRemovalOperation,
    position: usize,
    row: &CanaryRemovalEffect,
) -> Result<(), InstallationError>
where
    P: InstallationEffectPort,
{
    let observed_install = reload_install(coordinator.store(), &operation.plan)?;
    match readback_request(&observed_install, row)? {
        RowReadback::InstallerEffect(request) => {
            let observed = match coordinator.port.reconcile(&request) {
                PortOutcome::Known(observed) => observed,
                other => {
                    unknown_row(
                        coordinator.store_mut(),
                        operation,
                        position,
                        port_pending(other).map_err(|error| platform_error(&error))?,
                    )?;
                    return Ok(());
                }
            };
            match classify_observation(&observed, row) {
                RowClassification::Matching => resolve_row(
                    coordinator.store_mut(),
                    operation,
                    position,
                    CanaryRemovalEffectDisposition::Retained,
                    matching_evidence(&observed),
                ),
                // A retained row whose owner reports a different object, or
                // reports the admitted object gone, has not proved its
                // `Retained` postcondition. That is drift, not progress.
                RowClassification::Absent(_) | RowClassification::Conflict => unknown_row(
                    coordinator.store_mut(),
                    operation,
                    position,
                    readback_ref("retained-unproven", row)?,
                ),
            }
        }
        RowReadback::TerminalRegistryRecord => {
            Err(InstallationError::IncompleteObservation(format!(
                "the terminal registry record {} cannot be read back as a retained row",
                row.effect_id.as_str()
            )))
        }
    }
}

/// Re-loads and re-validates the installed transaction from the durable store.
///
/// Every place in this module that compares an identity against the installation
/// transaction — the retained-row drive and the terminal pre-commit quiesce
/// observation — reads the transaction the store holds at that moment rather than
/// a value an earlier step threaded through the drive. A transaction replaced or
/// rebound mid-drive therefore refuses that comparison instead of being inherited
/// from an earlier observation.
///
/// The effect-port readbacks are the exception and stay as they were: a port
/// request is built from the transaction the entry fence admitted, because the
/// request's own effect position and bound attempt must address the row as this
/// operation admitted it.
fn reload_install(
    store: &RedbInstallationTransactionStore,
    plan: &CanaryRemovalPlan,
) -> Result<InstallationTransaction, InstallationError> {
    let install = store.load(&plan.install_transaction_id)?.ok_or(
        InstallationError::TransactionNotFound {
            transaction_id: plan.install_transaction_id.as_str().to_owned(),
        },
    )?;
    install.validate()?;
    Ok(install)
}

/// Reduces one classified readback to the evidence handles the owner reported.
///
/// This is the single evidence reducer for every readback a removal drive
/// accepts, and it is deliberately total over the three observation classes so
/// that the caller never has to re-derive which list an owner verdict carries:
///
/// * a still-present exact object contributes its `postcondition_digest` followed by the
///   owner's own `evidence`;
/// * an authoritatively absent object contributes its observed-precondition digest
///   followed by the owner's own `evidence` — the same handles, in the same order, the
///   removal path contributed before the per-row postcondition check existed, so a
///   removed row's recorded evidence is unchanged by that check;
/// * a mismatched observation contributes only its `pending_ref`, because a conflict is
///   a typed refusal rather than a proof and never reaches a resolved row.
fn matching_evidence(observed: &InstallationEffectObservation) -> Vec<PlatformHandle> {
    match observed {
        InstallationEffectObservation::Matching {
            evidence,
            postcondition_digest,
            ..
        } => {
            let mut recorded = vec![postcondition_digest.clone()];
            recorded.extend(evidence.iter().cloned());
            recorded
        }
        InstallationEffectObservation::Absent {
            observed_precondition,
            evidence,
            ..
        } => {
            let mut recorded = vec![observed_precondition.digest.clone()];
            recorded.extend(evidence.iter().cloned());
            recorded
        }
        InstallationEffectObservation::Mismatch { pending_ref } => vec![pending_ref.clone()],
    }
}

/// Reduces an accumulated readback list to distinct handles, keeping readback order.
///
/// Two rows' owners can legitimately report the same evidence handle, while the
/// durable per-row evidence requires unique handles; dropping the later repeats
/// keeps the list a faithful record of what was observed without letting a repeat
/// readback masquerade as a conflict.
fn unique_handles(values: Vec<PlatformHandle>) -> Vec<PlatformHandle> {
    let mut seen: BTreeSet<PlatformHandle> = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

/// Authoritative verdict one resource owner returned for one removal row.
enum RowClassification {
    /// The owner proved the exact previously admitted object absent, and reported
    /// the evidence that proves it.
    Absent(Vec<PlatformHandle>),
    /// The owner still reports the admitted object under its admitted identity.
    Matching,
    /// The owner proved something else, or could not prove the row's own identity.
    Conflict,
}

/// Authoritative readback classification for one removal row.
///
/// Absence is idempotent success only for the exact previously admitted object
/// with authoritative absence evidence. A readback that cannot classify the
/// object is an unknown outcome, and a readback proving a different object is
/// an identity conflict rather than an absent resource.
fn classify_observation(
    observed: &InstallationEffectObservation,
    row: &CanaryRemovalEffect,
) -> RowClassification {
    match observed {
        InstallationEffectObservation::Absent { evidence, .. } => {
            RowClassification::Absent(evidence.clone())
        }
        InstallationEffectObservation::Matching {
            disposition,
            external_identity,
            ..
        } => {
            // The owner must report the ownership class the FROZEN ROW itself
            // records, read from the install transaction's own effect receipt: a
            // row this transaction created can only read back as created by it,
            // and a row the transaction adopted can only read back as the
            // preexisting object it adopted. Both classes still require the exact
            // admitted external identity, so a substituted object is refused
            // either way. Requiring `CreatedByTransaction` unconditionally would
            // make the owner's honest answer for an adopted row a conflict, and
            // an adopted row would then never resolve at all.
            let ownership_matches = match row.origin {
                CanaryRemovalResourceOrigin::CreatedByInstallTransaction => {
                    *disposition == super::InstallationEffectDisposition::CreatedByTransaction
                }
                CanaryRemovalResourceOrigin::PreexistingAtInstall => {
                    *disposition == super::InstallationEffectDisposition::PreexistingMatching
                }
                CanaryRemovalResourceOrigin::ForeignToThisRemoval => false,
            };
            if !ownership_matches || external_identity != &row.resource_identity {
                RowClassification::Conflict
            } else {
                RowClassification::Matching
            }
        }
        InstallationEffectObservation::Mismatch { .. } => RowClassification::Conflict,
    }
}

fn exhausted_bound_ref(row: &CanaryRemovalEffect) -> Result<PlatformHandle, InstallationError> {
    handle_ref(&format!(
        "unknown:canary-removal-bound-exhausted:{}",
        row.effect_id.as_str()
    ))
}

fn unproven_postcondition_ref(
    row: &CanaryRemovalEffect,
) -> Result<PlatformHandle, InstallationError> {
    handle_ref(&format!(
        "unknown:canary-removal-unproven-postcondition:{}",
        row.effect_id.as_str()
    ))
}

fn readback_ref(
    kind: &str,
    row: &CanaryRemovalEffect,
) -> Result<PlatformHandle, InstallationError> {
    handle_ref(&format!(
        "unknown:canary-removal-readback-{kind}:{}",
        row.effect_id.as_str()
    ))
}

fn handle_ref(value: &str) -> Result<PlatformHandle, InstallationError> {
    PlatformHandle::new(value.to_owned()).map_err(|error| platform_error(&error))
}

/// Commits the exact removal intent before the mutating call.
///
/// The advanced bound is mirrored back into the plan row, so the row's durable
/// record of how many attempts this removal identity already spent on it stays in
/// one place and `CanaryRemovalOperation::validate`'s
/// `attempt == effect.bound.attempt` invariant holds for the write below. Writing
/// it there is safe against the frozen `plan_digest` only because
/// `CanaryRemovalPlan::computed_digest` normalizes this exact member back to its
/// plan-time value; removing that normalization would wedge every resumed attempt
/// at the `validate()` on the next line, before the store is reached.
fn commit_intent(
    store: &mut RedbInstallationTransactionStore,
    operation: &mut CanaryRemovalOperation,
    position: usize,
    attempt: CanaryRemovalEffectBound,
    request: &super::InstallationEffectRequest,
) -> Result<(), InstallationError> {
    let expected = CanaryRemovalOperationVersion::of(operation)?;
    let intent_digest = PlatformHandle::new(sha256_hex(&serde_json::to_vec(request).map_err(
        |error| InstallationError::InvalidField {
            field: "canary_removal.intent".to_owned(),
            reason: error.to_string(),
        },
    )?))
    .map_err(|error| platform_error(&error))?;
    operation.effect_progress[position].state = CanaryRemovalEffectState::IntentCommitted {
        attempt: attempt.attempt,
        intent_digest,
    };
    operation.plan.effects[position].bound = attempt;
    operation.stage = CanaryRemovalStage::Executing;
    operation.revision = next_revision(expected.revision)?;
    operation.validate()?;
    store.compare_and_save_canary_removal_operation(&expected, operation)
}

/// Closes one row with the disposition its own owner reported.
///
/// The disposition is a caller-supplied owner verdict, never a derivation from
/// the plan: `Absent` and `Removed` come from an effect port that proved the
/// exact admitted object gone, and `Retained` from an owner that reported it
/// still present under its admitted identity. `CanaryRemovalOperation::validate`
/// then refuses any pairing the frozen action does not admit.
fn resolve_row(
    store: &mut RedbInstallationTransactionStore,
    operation: &mut CanaryRemovalOperation,
    position: usize,
    disposition: CanaryRemovalEffectDisposition,
    evidence: Vec<PlatformHandle>,
) -> Result<(), InstallationError> {
    let expected = CanaryRemovalOperationVersion::of(operation)?;
    operation.effect_progress[position].state = CanaryRemovalEffectState::Resolved {
        disposition,
        evidence,
    };
    operation.revision = next_revision(expected.revision)?;
    operation.validate()?;
    store.compare_and_save_canary_removal_operation(&expected, operation)
}

fn unknown_row(
    store: &mut RedbInstallationTransactionStore,
    operation: &mut CanaryRemovalOperation,
    position: usize,
    pending_ref: PlatformHandle,
) -> Result<(), InstallationError> {
    let expected = CanaryRemovalOperationVersion::of(operation)?;
    operation.effect_progress[position].state = CanaryRemovalEffectState::Unknown { pending_ref };
    operation.blocking_effect_id = Some(operation.effect_progress[position].effect_id.clone());
    operation.stage = CanaryRemovalStage::Reconciling;
    operation.revision = next_revision(expected.revision)?;
    operation.validate()?;
    store.compare_and_save_canary_removal_operation(&expected, operation)
}

fn next_revision(expected: u64) -> Result<u64, InstallationError> {
    expected
        .checked_add(1)
        .ok_or_else(|| InstallationError::InvalidField {
            field: "canary_removal.revision".to_owned(),
            reason: "revision overflow".to_owned(),
        })
}

/// The owner readback selected for one frozen removal row.
///
/// Only an owner that exists appears here. A category no owner can answer for is
/// refused by `readback_request` rather than given a variant that would carry no
/// evidence.
enum RowReadback {
    /// Reconcile the exact installer effect through the effect port.
    ///
    /// The request is boxed because `InstallationEffectRequest` is far larger
    /// than the other shape, and an unboxed variant that size would make every
    /// copy of this enum — one per row, every drive — pay for the largest member.
    InstallerEffect(Box<InstallationEffectRequest>),
    /// Proved by the post-retirement registry reload, never before it.
    TerminalRegistryRecord,
}

/// Selects the owner readback for one already-executed plan row.
///
/// The row's own `install_effect_index` selects which exact effect of the
/// transaction is reconciled, and the row's own bound attempt and resource
/// identity supply the preconditions, so the readback is addressed to THIS row
/// rather than to a position in a list this loop happens to be walking.
///
/// The REQUEST SHAPE is derived from the row's own frozen `action`, so the two
/// call sites — the per-row retained-row drive and the terminal readback — can
/// never disagree about how a row is asked about:
///
/// * a `Remove` row is read back through the exact-identity ROLLBACK request it is
///   removed by. That is a genuine destructive-intent readback and the owner's
///   validator admits a rollback arm for every plan variant a `Remove` row can
///   name, because a `Remove` row only exists for a variant this owner supports
///   removing.
/// * a row this removal does NOT destroy is READ, not rolled back. Asking its
///   owner for a rollback would ask the owner to destroy a resource the plan
///   promised to leave intact, and the owner's own validator refusing that is the
///   validator being right: `InstallationEffectRequest::validate` has no rollback
///   arm for an `ApplyAcl` row at all, and none for a `CreateRoot` row without an
///   ownership secret, so every plan that retains a root or an ACL — which is
///   every plan, because `freeze_effect_graph` marks both shared and the survivor
///   set is never empty — would be refused before its terminal tail. Such a row is
///   therefore read back through the APPLY-shaped request the installation
///   transaction itself built and validated for that exact effect position when it
///   applied it: the same `InstallationEffectAction::Apply` with an absent
///   `expected_external_identity` the owner's own apply, reconcile-before-execute
///   and aborted-apply paths use. No arm was invented and no request field was
///   relaxed to reach it.
///
/// An apply-shaped request carries no expected external identity, so the
/// exact-identity guard sits in the VERDICT instead: `classify_observation` still
/// refuses the row unless the owner reports `Matching` with
/// `external_identity == row.resource_identity` AND the ownership class the row
/// itself records, so a substituted path, PID or service name is still a conflict
/// and can never become `Retained`.
///
/// A row with no installer effect is NOT skipped, and it is also never invented
/// for one. Each such category names the owner that can answer for it, and this
/// selector refuses the ones that name none: `GenerationRegistryRecord` is proved
/// by the post-retirement registry reload. `CanaryEvidenceRoot` and
/// `StoreObjects` are classified `OutOfScope` and name no such owner — no owner
/// in this crate can observe a bare filesystem root path or a generation-scoped
/// canonical Store/Blob object — so asking is impossible and this is the refusal
/// the drive says if such a row is ever reached here. It is deliberately NOT
/// `unsupported_cleanup_refusal`: that builder describes a required cleanup this
/// owner cannot perform, and a shared surface is not one. The two categories also
/// have their own measured reason written out beside their row constructors.
/// Any other category with no installer effect is refused too, because a row in
/// this denominator that no owner can be asked about would otherwise leave
/// `Completed` reachable without it.
fn readback_request(
    install: &InstallationTransaction,
    row: &CanaryRemovalEffect,
) -> Result<RowReadback, InstallationError> {
    let Some(index) = row.install_effect_index else {
        return match row.category {
            CanaryRemovalResource::GenerationRegistryRecord => {
                Ok(RowReadback::TerminalRegistryRecord)
            }
            other => Err(InstallationError::IncompleteObservation(format!(
                "removal row {} names category {other:?} with action {:?} and no installer effect \
                 to reconcile, and no owner this crate can reach observes that surface at all, so \
                 there is no readback to request and no evidence any owner could report for it",
                row.effect_id.as_str(),
                row.action
            ))),
        };
    };
    let install_index = usize::try_from(index).map_err(|_| InstallationError::IdentityConflict)?;
    let (action, expected_external_identity) = if row.action == CanaryRemovalAction::Remove {
        (
            InstallationEffectAction::Rollback,
            Some(row.resource_identity.clone()),
        )
    } else {
        (InstallationEffectAction::Apply, None)
    };
    Ok(RowReadback::InstallerEffect(Box::new(effect_request(
        install,
        install_index,
        row.bound.attempt,
        action,
        expected_external_identity,
    )?)))
}

/// Finishes by independent readback of the whole denominator, then commits the
/// terminal registry projection under the expected registry revision and proves
/// that commit from the owner's own reloaded projection.
///
/// The readback runs against each row's real owner and is separate from the
/// mutating call, so a green stage can never come from a lost response. It walks
/// EVERY row of `0..effects.len()`, including the retained, shared and preexisting
/// rows, so `Completed` cannot be reached while a resource the plan promised to
/// leave intact has never been observed. Each row is proved against the
/// postcondition the frozen plan declared for that row, so a retained row is
/// proved still present under its admitted identity and is never asked to be
/// absent. A row with no owner that can answer for it is not walked past either:
/// `readback_request` refuses it, so the operation stays short of the terminal
/// commit with its identity and unresolved rows intact. A row that CANNOT BE
/// PROVED does not merely return an empty evidence list either: the walk reports
/// `None`, the caller stops before the terminal registry commit, and the row's
/// typed `Unknown` disposition — original removal identity kept, blocking effect
/// named, safe next action recorded — is what this call reports. That is the
/// difference between "this denominator is fully observed" and "I could not
/// observe one row of it", and only the caller of the terminal registry retirement
/// must not confuse the two.
///
/// This tail is also the only place a terminal receipt can be minted, so it is
/// the repair path for a crash that lost that receipt: the per-row readback and
/// the post-retirement terminal proof below both re-run against projections this
/// call reloads, and the retirement block is skipped because the registry record
/// is already absent. Nothing here issues a mutating call on that path.
fn finish_with_readback<P>(
    coordinator: &mut InstallationCoordinator<P, RedbInstallationTransactionStore>,
    registry: &RedbInstallationRegistry,
    operation: &mut CanaryRemovalOperation,
    install: &InstallationTransaction,
    registry_row: usize,
) -> Result<(), InstallationError>
where
    P: InstallationEffectPort,
{
    // The terminal registry retirement is the ONE mutating call left in this
    // operation, so the walk above must have proved every row of the denominator
    // before control reaches it. `None` means it did not: one row could not be
    // proved, that row's typed `Unknown` disposition is already durable with the
    // original removal identity and its blocking effect, and the only correct
    // action here is to stop. Returning early is what keeps an unproved
    // denominator from retiring the registry — the terminal commit, the reload
    // below and the receipt mint are all unreachable on this path, which is the
    // whole reason the walk reports the difference rather than an empty list.
    let Some(mut readback_evidence) =
        prove_every_row_before_terminal(coordinator, operation, install, registry_row)?
    else {
        return Ok(());
    };
    // The terminal projection is the last durable step, and a crash anywhere
    // between its commit and this operation's final save is repaired by
    // RE-PROVING, never by assuming the effect. A crash BEFORE the receipt was
    // written leaves the target absent with nothing on file; the entry fence
    // admits exactly that state only when this operation's own pre-terminal rows
    // are all already resolved and the live projection still proves the terminal
    // state, so the drive below re-reads every row, re-proves the terminal state
    // against the projection it reloads here, and mints the missing receipt. A
    // crash AFTER the receipt was written reuses that originally recorded
    // receipt below instead of minting a second claim for the same committed
    // effect. Neither path issues a second terminal mutation: the retirement
    // block below is skipped precisely because the record is already absent, and
    // the per-row drive issued no mutating call to get here.
    let before = registry.load()?;
    if resolve_approved_generation(&before, &operation.plan.generation).is_ok() {
        // The terminal registry retirement is the one mutating call left in
        // this operation, and it is issued after the per-row readback loop, not
        // at the entry fence. Both the bounded reconcile deadline and the
        // admission fence are therefore re-observed here against a projection
        // read after that loop: a deadline that expires mid-readback, or a
        // canary admission or a return to production/last-known-good staged
        // after the last row, refuses this call instead of being inherited
        // from a stale entry-point observation. Neither refusal writes
        // anything, so the durable incomplete recovery survives unchanged.
        if reconcile_budget_exhausted(operation) {
            return Err(InstallationError::IncompleteObservation(format!(
                "the bounded reconcile wait for removal {} expired before the terminal registry retirement of generation {}; the exact blocking effect {} keeps this operation in incomplete recovery and no terminal commit is admitted under this operation identity",
                operation.removal_transaction_id.as_str(),
                operation.plan.generation.as_str(),
                operation.plan.effects[registry_row].effect_id.as_str()
            )));
        }
        observe_admission_fence(&before, &operation.plan)?;
        // The owner effects are re-observed here as well, against a transaction
        // re-loaded from the durable store, so a pending write, ORS operation,
        // outbox row or possible external effect, or a rebound lease/session/route
        // authority, staged during the per-row readback refuses the terminal
        // commit rather than being inherited from the entry observation. Like the
        // two refusals above, this one writes nothing.
        let observed_install = reload_install(coordinator.store(), &operation.plan)?;
        require_quiesced_owner_effects(&observed_install, &operation.plan)?;
        require_complete_effect_coverage(&observed_install, &operation.plan)?;
        let terminal = registry.mutate_atomic(operation.plan.registry_revision, |projection| {
            projection.retire_retired_generation(&operation.plan.generation)
        });
        match terminal {
            Ok(()) => {}
            // A registry that still projects this generation is a retained
            // cleanup uncertainty owned by the activation/registry owner, not a
            // crash: the blocking row stays durable so the next permitted
            // action is bounded manual recovery instead of a fresh destructive
            // attempt.
            Err(
                InstallationError::IncompleteObservation(_)
                | InstallationError::MigrationRequired { .. },
            ) => {
                return unknown_row(
                    coordinator.store_mut(),
                    operation,
                    registry_row,
                    readback_ref(
                        "registry-terminal-held",
                        &operation.plan.effects[registry_row],
                    )?,
                );
            }
            Err(error) => return Err(error),
        }
    }
    // The terminal effect is proved by re-loading the registry AFTER the
    // retirement and comparing what that independent projection actually says,
    // never by the revision arithmetic of the call that issued it. This is the
    // same `terminal_proofs_hold` check the entry fence applies when it decides
    // whether a missing receipt is repairable, so the repair path and the mint
    // path can never disagree about what the terminal state is.
    let current = registry.load()?;
    current.validate()?;
    if !terminal_proofs_hold(&current, &operation.plan)? {
        return unknown_row(
            coordinator.store_mut(),
            operation,
            registry_row,
            readback_ref(
                "registry-terminal-unproven",
                &operation.plan.effects[registry_row],
            )?,
        );
    }
    let receipt_digest = terminal_receipt_digest(coordinator, &current, operation)?;
    let expected = CanaryRemovalOperationVersion::of(operation)?;
    // The registry row's evidence is the digest of the owner-issued terminal
    // receipt, so the terminal effect is bound to this removal identity and to
    // the projection the retirement actually produced.
    readback_evidence.push(receipt_digest);
    operation.effect_progress[registry_row].state = CanaryRemovalEffectState::Resolved {
        disposition: CanaryRemovalEffectDisposition::Removed,
        evidence: unique_handles(readback_evidence),
    };
    operation.blocking_effect_id = None;
    operation.stage = CanaryRemovalStage::Completed;
    operation.revision = next_revision(expected.revision)?;
    operation.validate()?;
    coordinator
        .store_mut()
        .compare_and_save_canary_removal_operation(&expected, operation)
}

/// Re-reads EVERY row of the whole denominator through its own owner and returns
/// the accumulated readback evidence, or `None` when a row could not be proved.
///
/// This runs before the terminal registry mutation, so a row that cannot be
/// proved keeps the operation in the typed partial/unknown disposition with the
/// original removal identity, and no terminal commit is attempted on an
/// unproved denominator.
///
/// `Some(evidence)` means the WHOLE denominator was proved; `None` means it was
/// not, and the caller must not proceed as though it had. Returning an empty
/// vector instead would be indistinguishable from a denominator that proved
/// nothing, and this caller's next acts — the terminal registry retirement, the
/// post-retirement reload and the terminal receipt mint — are all irreversible
/// or durable. The `None` is what stops them.
///
/// Every row of `0..effects.len()` is walked. A row is never skipped and never
/// counted as proved without its own owner's verdict.
fn prove_every_row_before_terminal<P>(
    coordinator: &mut InstallationCoordinator<P, RedbInstallationTransactionStore>,
    operation: &mut CanaryRemovalOperation,
    install: &InstallationTransaction,
    registry_row: usize,
) -> Result<Option<Vec<PlatformHandle>>, InstallationError>
where
    P: InstallationEffectPort,
{
    let mut readback_evidence = Vec::new();
    for position in 0..operation.plan.effects.len() {
        let row = operation.plan.effects[position].clone();
        match readback_request(install, &row)? {
            RowReadback::InstallerEffect(request) => {
                let observed = match coordinator.port.reconcile(&request) {
                    PortOutcome::Known(observed) => observed,
                    other => {
                        unknown_row(
                            coordinator.store_mut(),
                            operation,
                            position,
                            port_pending(other).map_err(|error| platform_error(&error))?,
                        )?;
                        return Ok(None);
                    }
                };
                // Each row is proved against the postcondition the FROZEN PLAN
                // itself declared for that row, through the same classifier and
                // the same evidence reducer the per-row drive uses: a removed row
                // must read back authoritatively absent with evidence, and a
                // retained row must read back still present under its admitted
                // identity. Absence is the wrong question for a retained row —
                // demanding it would require removing exactly the resource the
                // plan promised to leave intact, so the terminal commit would be
                // unreachable for every plan that retains an installer effect.
                let proved = match (
                    row.expected_postcondition,
                    classify_observation(&observed, &row),
                ) {
                    (CanaryRemovalPostcondition::Absent, RowClassification::Absent(evidence)) => {
                        !evidence.is_empty()
                    }
                    (CanaryRemovalPostcondition::Retained, RowClassification::Matching) => true,
                    _ => false,
                };
                if !proved {
                    unknown_row(
                        coordinator.store_mut(),
                        operation,
                        position,
                        readback_ref("unproven-postcondition", &row)?,
                    )?;
                    return Ok(None);
                }
                readback_evidence.extend(matching_evidence(&observed));
            }
            RowReadback::TerminalRegistryRecord => {
                // The hand-off record has no pre-commit readback: it is proved by
                // the post-retirement reload below, and refusing here would make
                // that proof unreachable. This is the only position allowed to
                // carry it.
                if position != registry_row {
                    return Err(InstallationError::IncompleteObservation(format!(
                        "removal row {} claims to be the terminal registry record",
                        row.effect_id.as_str()
                    )));
                }
            }
        }
    }
    Ok(Some(readback_evidence))
}

/// Returns the digest of the owner-issued terminal receipt for this removal,
/// reusing an already recorded receipt and minting one only when none exists.
///
/// The terminal effect is attributed by that receipt, bound to this removal
/// identity, and never by the revision arithmetic of the call that issued it. A
/// receipt this identity ALREADY holds is the evidence and is validated against
/// the plan here — it is never reminted from the projection as it stands now,
/// because reminting would mint a second, different claim for an effect that
/// already committed and the store's immutable-receipt rule would then refuse
/// every later recovery of this operation under the same identity.
///
/// `current` is the projection this owner reloaded AFTER the terminal registry
/// mutation, so a minted receipt records what that mutation produced. It is also
/// the one site where a recorded receipt and the live projection coexist on the
/// path that closes the operation, so it is where the recorded registry CONTENT
/// DIGEST becomes load-bearing: see the comparison below.
fn terminal_receipt_digest<P>(
    coordinator: &mut InstallationCoordinator<P, RedbInstallationTransactionStore>,
    current: &ApprovedGenerationRegistry,
    operation: &CanaryRemovalOperation,
) -> Result<PlatformHandle, InstallationError>
where
    P: InstallationEffectPort,
{
    let recorded_receipt = coordinator
        .store()
        .load_canary_removal_terminal_receipt(&operation.removal_transaction_id)?;
    if let Some(recorded) = recorded_receipt {
        recorded.validate()?;
        if recorded.generation != operation.plan.generation
            || recorded.predecessor_registry_revision != operation.plan.registry_revision
        {
            return Err(InstallationError::IdentityConflict);
        }
        // The recorded content digest is compared against the LIVE projection
        // with the existing `registry_projection_identity` scheme that minted it
        // — never recomputed from the receipt — so a receipt whose digest does
        // not describe the registry it claims to describe cannot carry this
        // operation to `Completed`.
        //
        // The revision guard keeps that comparison honest rather than brittle.
        // While the live projection still carries EXACTLY the revision this
        // receipt recorded, both describe the same committed linear history and
        // the digests must be equal; a difference there is a substituted or
        // corrupted registry. A projection that has ADVANCED past
        // `resulting_registry_revision` is the case
        // `terminal_receipt_recognises_retirement` admits through its monotonicity
        // floor: it carries unrelated activity, the recorded digest describes a
        // projection that is no longer live, and there is nothing to compare it
        // against, so refusing there would re-introduce the crash wedge this
        // receipt exists to remove. On such a projection the terminal state is
        // proved independently by `terminal_proofs_hold`, from that live
        // projection's own target absence, serving pointers and survivor set.
        if current.revision() == recorded.resulting_registry_revision {
            let live_content_digest = super::registry_projection_identity(current)?;
            if recorded.resulting_registry_content_digest != live_content_digest {
                return Err(InstallationError::IncompleteObservation(format!(
                    "the terminal receipt recorded for removal {} describes registry revision {} with content digest {}, but the live registry at that same revision carries content digest {}; this owner will not close the operation on a receipt that does not describe the registry it claims to describe",
                    operation.removal_transaction_id.as_str(),
                    recorded.resulting_registry_revision,
                    recorded.resulting_registry_content_digest.as_str(),
                    live_content_digest.as_str()
                )));
            }
        }
        return recorded.computed_digest();
    }
    // The receipt's own validator requires one survivor set to have exactly one
    // serialization, and the registry stores generations in approval order, so
    // the set is sorted here instead of being handed over in an order the
    // receipt itself would refuse.
    let mut surviving = surviving_generations(current, &operation.plan.generation);
    surviving.sort();
    let receipt = CanaryRemovalTerminalReceipt {
        canary_removal_wire_version: CANARY_REMOVAL_WIRE_VERSION,
        removal_transaction_id: operation.removal_transaction_id.clone(),
        generation: operation.plan.generation.clone(),
        predecessor_registry_revision: operation.plan.registry_revision,
        resulting_registry_revision: current.revision(),
        resulting_registry_content_digest: super::registry_projection_identity(current)?,
        active_generation: current.active_generation().cloned(),
        last_known_good_generation: current.last_known_good_generation().cloned(),
        surviving_generations: surviving,
    };
    receipt.validate()?;
    let digest = receipt.computed_digest()?;
    // The receipt is written BEFORE the operation row is closed, so a crash in
    // between leaves a durable terminal record and an unresolved operation row
    // rather than a resolved row with no record behind it. Re-running the tail
    // finds that record and reuses it. The store's rule is write-once per
    // removal identity, so this mint is itself idempotent: a byte-identical
    // re-mint is accepted as a success and only a DIFFERING receipt under the
    // same identity is refused.
    coordinator
        .store_mut()
        .save_canary_removal_terminal_receipt(&receipt)?;
    Ok(digest)
}

/// Returns the observed set of surviving generations in a live projection.
///
/// This is the existing `surviving_generations` helper applied to the projection
/// the owner just reloaded, with the removal target excluded, so the observed
/// survivor set is derived by exactly the one function that produced the
/// plan-time set.
fn observed_survivors(
    projection: &ApprovedGenerationRegistry,
    plan: &CanaryRemovalPlan,
) -> BTreeSet<PlatformHandle> {
    surviving_generations(projection, &plan.generation)
        .into_iter()
        .collect()
}

/// Returns the survivor set the frozen plan committed to.
///
/// The expected set is read from the plan's own digest-bound
/// `CanaryEvidenceRoot` row, whose `reference_users` are the survivor set
/// `freeze_effect_graph` observed when the plan was frozen. Comparing the
/// reloaded registry against that frozen set is what makes the terminal check
/// independent of the projection being checked: the observed side comes from a
/// registry read, the expected side from an artifact whose identity the plan
/// digest already binds. `terminal_proofs_hold` requires this set to be present
/// in the reloaded projection, not to equal it, so unrelated registry activity
/// that adds a generation this plan could not have named does not wedge
/// recovery. Because the set comes from the plan rather than from the registry,
/// `revalidate_fence` re-derives it from the plan-time projection and refuses a
/// plan whose committed set does not match that projection exactly, on every
/// path that runs while the registry still carries the plan's own revision. Once
/// the terminal retirement has committed, that projection no longer exists, so
/// the set can only be required to still be present; the same fence has already
/// applied that relation through `pre_receipt_crash_window_is_repairable` before
/// `terminal_proofs_hold` can be reached. See the comment at that pin for why
/// equality is deliberately not demanded there.
fn planned_survivors(
    plan: &CanaryRemovalPlan,
) -> Result<BTreeSet<PlatformHandle>, InstallationError> {
    let row = plan
        .effects
        .iter()
        .find(|row| row.category == CanaryRemovalResource::CanaryEvidenceRoot)
        .ok_or(InstallationError::IncompleteObservation(
            "the frozen plan carries no canary-evidence row and therefore no survivor set it committed to"
                .to_owned(),
        ))?;
    Ok(row.reference_users.iter().cloned().collect())
}
