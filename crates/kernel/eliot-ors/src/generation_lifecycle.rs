//! I1.9: the Generation Registry lifecycle record for one
//! `{module_id, generation}`.
//!
//! I1.9 names the Generation Registry as the Kernel/ORS-owned record of
//! operational recovery state, and it states that a missing, stale or
//! incompatible `KernelExecutionManifest` means visible degradation and
//! escalation, "not an improvised restart". Issue #1884 external audit
//! comment 5946154380, section 5, adds the missing half: a durable
//! reconciliation row that nobody reads is not a degraded generation, so the
//! refusal must move the real lifecycle owner.
//!
//! [`GenerationLifecycleRecord`] is that owner-facing record. ORS is its single
//! writer; a launch, route cutover or new effect operation lease reads it and
//! asks the record rather than deciding for itself.
//!
//! What it does NOT prove:
//!
//! * It does not prove the Governor Module Catalog admitted anything. The
//!   sealed admission lives on [`crate::KernelExecutionManifest`], and
//!   `first_refusal_cause` is a rejection reason, never an admission.
//! * It does not prove a process was stopped, a route was withdrawn or a lease
//!   was revoked. It is the durable reason those must be refused; performing
//!   them is the launching path's job and it has no bypass around this record.
//! * It does not prove the recorded cause is the only cause. Later refusals
//!   append beside it in the escalation table; this record keeps the FIRST one
//!   so a second observation cannot erase the reason the generation degraded.
//! * It carries no `Default`, because a defaulted `Undegraded` would read as
//!   "no refusal outstanding" for a generation ORS has never observed.
//!
//! The lifecycle table records DEGRADATION, not the set of generations that
//! exist, so the ABSENCE of a row is not itself an answer about a generation.
//! [`ObservedGenerationLifecycle`] is the composed answer a gate reads instead:
//! it names which durable owner facts the answer rests on, and
//! [`ObservedGenerationLifecycle::compose`] is the single point that derives one
//! from those facts, so no consumer can invent an observation out of an absence.

use eliot_contracts::ResourceGeneration;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::execution_manifest::{KernelExecutionManifest, KernelReconciliationKind};
use crate::model::{OrsError, validate_text};

/// Durable schema version of the Generation Registry lifecycle record (I1.9).
pub const GENERATION_LIFECYCLE_SCHEMA_VERSION: u16 = 1;

/// The lifecycle disposition ORS records for one generation (I1.9).
///
/// The three values are ordered by how much authority they withhold, and the
/// order is load bearing: `transition_to_degraded` and
/// `transition_to_quarantined` walk it and never move backwards.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum GenerationDisposition {
    /// No manifest refusal is outstanding. Only this disposition admits a
    /// launch, a route, or a new effect operation lease.
    Undegraded,
    /// The generation is visibly degraded for a recorded manifest refusal:
    /// nothing is started for it, its routes are blocked and the defect is
    /// escalated.
    Degraded,
    /// The generation is quarantined for a recorded manifest refusal. This is
    /// the disposition the recorded manifest's quarantine rule produces once its
    /// bounded restart budget is spent, and it is stricter than `Degraded`.
    Quarantined,
}

/// The Generation Registry's durable lifecycle state for one generation
/// (I1.9).
///
/// This is the record a manifest refusal updates. It answers exactly one
/// question — may this generation be launched, routed, or issued a new effect
/// operation lease — and it answers it from ORS durable state rather than from
/// contemporaneous configuration or reconstructed desired state.
///
/// `recorded_at_ms` carries the time the FIRST recorded lifecycle observation
/// for this row was written: while the disposition is `Undegraded` it is when
/// ORS first recorded the generation in the Generation Registry, and from the
/// first degradation onward it is when that first refusal was observed. A later
/// observation never rewrites it, so the recorded disposition always names the
/// time it became true.
///
/// The transition methods are pure functions of `(previous, cause, time)`: they
/// read only `self` and their arguments, write only `self`, read no clock and no
/// store. That is what makes the rules below mechanically checkable instead of
/// a comment:
///
/// * a transition NEVER returns to `Undegraded` — there is no method that can,
///   and no argument that asks for it;
/// * `first_refusal_cause` keeps the FIRST recorded cause, so a later and
///   different refusal for the same generation appends its own escalation row
///   without erasing the reason this record degraded;
/// * a later `observed_at_ms` never rewrites `recorded_at_ms`;
/// * `Quarantined` is reachable only from `Degraded` or `Quarantined`, so a
///   generation ORS has never degraded is never quarantined by this record —
///   quarantine is the recorded manifest's own rule applied after degradation,
///   and reaching it from `Undegraded` here would fabricate that history.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationLifecycleRecord {
    /// Durable schema version of this record.
    pub schema_version: u16,
    /// Affected module identity.
    pub module_id: String,
    /// Affected generation identity.
    pub generation: ResourceGeneration,
    /// The lifecycle disposition ORS records for this generation.
    pub disposition: GenerationDisposition,
    /// The FIRST manifest refusal cause recorded for this generation. It is
    /// `None` exactly while the disposition is `Undegraded`, and it is never
    /// replaced by a later cause.
    pub first_refusal_cause: Option<KernelReconciliationKind>,
    /// Time the first recorded lifecycle observation for this row was written.
    pub recorded_at_ms: i64,
}

impl GenerationLifecycleRecord {
    /// Validates the record shape and its disposition/cause invariant.
    ///
    /// The invariant is the load-bearing check: a degraded or quarantined
    /// generation MUST carry the cause it degraded for, and an undegraded one
    /// MUST carry none. Both halves fail closed, because a degraded row with no
    /// cause cannot be audited and an undegraded row with a cause would report a
    /// refusal as outstanding while admitting launch, routes and new leases.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.schema_version != GENERATION_LIFECYCLE_SCHEMA_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.schema_version));
        }
        validate_text(&self.module_id, "generation_lifecycle_record_module_id")?;
        if self.recorded_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "generation_lifecycle_record_recorded_at_ms",
                reason: "must be greater than zero",
            });
        }
        match (self.disposition, self.first_refusal_cause) {
            (GenerationDisposition::Undegraded, Some(_)) => Err(OrsError::InvalidField {
                field: "generation_lifecycle_record_first_refusal_cause",
                reason: "an undegraded generation carries no manifest refusal cause",
            }),
            (GenerationDisposition::Degraded | GenerationDisposition::Quarantined, None) => {
                Err(OrsError::InvalidField {
                    field: "generation_lifecycle_record_first_refusal_cause",
                    reason: "a degraded or quarantined generation must record its cause",
                })
            }
            _ => Ok(()),
        }
    }

    /// Whether a launch of this generation may be attempted at all.
    ///
    /// True only for `Undegraded`. It does not authorize a launch: the launch
    /// path must additionally verify the sealed
    /// [`crate::KernelExecutionManifest`] and issue a sealed
    /// [`crate::BoundKernelExecutionManifest`].
    #[must_use]
    pub const fn admits_launch(&self) -> bool {
        matches!(self.disposition, GenerationDisposition::Undegraded)
    }

    /// Whether a NEW effect operation lease may be issued for this generation.
    ///
    /// True only for `Undegraded`. A degraded or quarantined generation may
    /// resume only an exact already-authorized operation an unexpired lease it
    /// already holds covers, through
    /// [`crate::verify_exact_effect_replay`]; this predicate is never that
    /// path.
    #[must_use]
    pub const fn admits_new_effect_leases(&self) -> bool {
        matches!(self.disposition, GenerationDisposition::Undegraded)
    }

    /// Whether this generation's routes are blocked.
    ///
    /// True for `Degraded` and `Quarantined`. A route cutover must refuse here
    /// rather than read the manifest directly, so a degraded generation cannot
    /// keep acting through a route that was cut before the refusal was recorded.
    #[must_use]
    pub const fn blocks_routes(&self) -> bool {
        !matches!(self.disposition, GenerationDisposition::Undegraded)
    }

    /// Records that this generation is degraded for `cause`.
    ///
    /// From `Undegraded` this moves the disposition to `Degraded`, records
    /// `cause` as the first refusal cause and stamps `recorded_at_ms` with
    /// `observed_at_ms`. From `Degraded` or `Quarantined` it changes nothing:
    /// the record is never downgraded, and the first cause is kept even when
    /// `cause` differs from it. The later cause is not discarded here — its own
    /// escalation row is appended by the writer that observed it.
    pub fn transition_to_degraded(&mut self, cause: KernelReconciliationKind, observed_at_ms: i64) {
        if !matches!(self.disposition, GenerationDisposition::Undegraded) {
            return;
        }
        self.disposition = GenerationDisposition::Degraded;
        self.first_refusal_cause = Some(cause);
        self.recorded_at_ms = observed_at_ms;
    }

    /// Records that this generation is quarantined for `cause`.
    ///
    /// From `Degraded` or `Quarantined` this moves the disposition to
    /// `Quarantined` and keeps the first refusal cause, so quarantine never
    /// erases why the generation degraded; `recorded_at_ms` keeps naming the
    /// first recorded observation. From `Undegraded` this changes nothing,
    /// because quarantine is the recorded manifest's own rule applied after a
    /// refusal, and quarantining a generation that never degraded would
    /// manufacture that history here.
    pub fn transition_to_quarantined(
        &mut self,
        cause: KernelReconciliationKind,
        observed_at_ms: i64,
    ) {
        if matches!(self.disposition, GenerationDisposition::Undegraded) {
            return;
        }
        // The quarantine observation is deliberately applied to no recorded
        // field: `recorded_at_ms` keeps naming the first recorded observation and
        // this record has no field for a later one. The value is dropped
        // explicitly so the transition is still a pure function of
        // `(previous, cause, time)` and the discarded clock is stated rather than
        // left as an unused parameter.
        let _ = observed_at_ms;
        self.disposition = GenerationDisposition::Quarantined;
        if self.first_refusal_cause.is_none() {
            self.first_refusal_cause = Some(cause);
        }
    }
}

/// What ORS positively observed about one generation's lifecycle, and what that
/// observation rests on.
///
/// The Generation Registry lifecycle table records DEGRADATION, not the set of
/// generations that exist, so "no lifecycle row" is not by itself an answer
/// about a generation. This type is the composed answer a gate reads instead,
/// and it names the durable owner facts that answer rests on:
///
/// * [`Self::Recorded`] rests on ONE fact: a `GENERATION_LIFECYCLES` row read
///   back for this exact `{module_id, generation}` that satisfied its own
///   `validate()`. The answer is that row's own recorded disposition, degradation
///   included — a manifest's presence never overrides a recorded `Degraded` or
///   `Quarantined` row.
/// * [`Self::AdmittedWithoutDegradation`] rests on TWO facts, one per registry:
///   NO degradation is recorded for this generation, AND a
///   `KERNEL_EXECUTION_MANIFESTS` row exists for the SAME `{module_id,
///   generation}` carrying an admitted manifest that satisfied its own
///   [`KernelExecutionManifest::validate`]. It composes to
///   [`GenerationDisposition::Undegraded`], and it is named rather than hidden
///   precisely because that composition is a positive claim resting on durable
///   owner data and not on an absence.
///
/// [`Self::AdmittedWithoutDegradation`] does NOT prove:
///
/// * that a process is running for this generation;
/// * that its routes are live, drained or cut;
/// * that the generation is healthy — the health and readiness contract is the
///   recorded manifest's, and it is observed elsewhere;
///
/// This is the I1.9 rule read across its two sides. "Missing, stale or
/// incompatible manifest means visible degradation and escalation, not an
/// improvised restart" is the refusal side, and it holds here because an
/// observation can only be composed from durable facts by [`Self::compose`],
/// which refuses an absent degradation record that has no admitted manifest
/// behind it, and because a caller that names a variant directly has to supply
/// that durable fact itself. An intact admitted manifest is the positive side: a
/// launch, route or exact replay within the recorded class may come from it.
///
/// This type is NOT a persisted row and never becomes one. It has no key, no
/// schema version, no `recorded_at_ms` of its own and no writer, nothing in this
/// crate writes it into `GENERATION_LIFECYCLES`, and [`Self::compose`] is a pure
/// function of its two arguments: it reads no clock, no store and nothing else
/// from its environment. A caller that wants the recorded row asks
/// [`Self::recorded`], which is `None` for the composed arm because no row was
/// found — that absence is the honest state, not a defect to repair.
///
/// This type deliberately has NO `Deserialize` implementation, for the same
/// reason [`crate::BoundKernelExecutionManifest`] has none: a deserializable
/// public enum would let a caller recover an observation from bytes and present
/// it as something ORS composed from durable readbacks, which is exactly the
/// fabricated-current-state defect this type exists to make impossible. The
/// variants are public because the store composes them from the two readbacks it
/// owns, not because a caller may assemble one.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedGenerationLifecycle {
    /// A durable `GENERATION_LIFECYCLES` row was read back for this exact
    /// module and generation and satisfied its own `validate()`.
    Recorded(GenerationLifecycleRecord),
    /// No degradation row exists, AND an admitted `KernelExecutionManifest` row
    /// exists for the SAME `{module_id, generation}` and satisfies its own
    /// `KernelExecutionManifest::validate()`.
    AdmittedWithoutDegradation,
}

impl ObservedGenerationLifecycle {
    /// Composes the one observation for one generation from its two arguments.
    ///
    /// This is THE single composition point: it is the only path that derives an
    /// observation from a pair of durable readbacks, so no consumer can invent an
    /// observation, compose a clearance out of an absence, or restate the
    /// disposition in a second spelling. It is a pure function — it reads no
    /// clock, no store and nothing else from its environment, defaults nothing,
    /// and synthesises no record.
    ///
    /// With `Some(record)`, the record IS the answer: it is validated through its
    /// own `validate()` and its typed failure is returned unchanged, then its
    /// `{module_id, generation}` must equal the manifest's own admitted pair or
    /// the composition is refused with a typed [`OrsError::InvalidField`] naming
    /// the disagreeing field. A recorded `Degraded` or `Quarantined` row STANDS:
    /// the manifest's presence never overrides a recorded degradation.
    ///
    /// With `None`, the caller asserts that an admitted manifest exists for this
    /// generation, and this function proves that assertion by running the
    /// manifest's own `validate()` and returning its typed failure unchanged. It
    /// composes [`Self::AdmittedWithoutDegradation`], which is the POSITIVE
    /// `Undegraded` answer two durable owner facts support. No degraded check
    /// runs on that path: there is no row to be degraded.
    pub fn compose(
        record: Option<GenerationLifecycleRecord>,
        manifest: &KernelExecutionManifest,
    ) -> Result<Self, OrsError> {
        let Some(record) = record else {
            manifest.validate()?;
            return Ok(Self::AdmittedWithoutDegradation);
        };
        record.validate()?;
        require_observed_generation_binding(&record, manifest)?;
        Ok(Self::Recorded(record))
    }

    /// The disposition this observation composes to.
    ///
    /// [`Self::AdmittedWithoutDegradation`] composes to
    /// [`GenerationDisposition::Undegraded`]. That IS its answer and it is why
    /// the variant is named rather than hidden: the composition is a positive
    /// claim about two durable facts, not the absence of a recorded state.
    #[must_use]
    pub const fn disposition(&self) -> GenerationDisposition {
        match self {
            Self::Recorded(record) => record.disposition,
            Self::AdmittedWithoutDegradation => GenerationDisposition::Undegraded,
        }
    }

    /// The recorded degradation, when one exists.
    ///
    /// `None` for [`Self::AdmittedWithoutDegradation`], which is the honest
    /// absence of a record: no `GENERATION_LIFECYCLES` row exists for this
    /// generation, and none was invented to answer for it.
    #[must_use]
    pub const fn recorded(&self) -> Option<&GenerationLifecycleRecord> {
        match self {
            Self::Recorded(record) => Some(record),
            Self::AdmittedWithoutDegradation => None,
        }
    }

    /// The recorded FIRST refusal cause, when a degradation was recorded.
    ///
    /// `None` when no degradation is recorded, including for
    /// [`Self::AdmittedWithoutDegradation`]. A later and different refusal for the
    /// same generation appends its own escalation row and never replaces the
    /// cause this returns.
    #[must_use]
    pub fn first_refusal_cause(&self) -> Option<KernelReconciliationKind> {
        match self {
            Self::Recorded(record) => record.first_refusal_cause,
            Self::AdmittedWithoutDegradation => None,
        }
    }

    /// Whether a launch of this generation may be attempted at all.
    ///
    /// True only when the observation composes to
    /// [`GenerationDisposition::Undegraded`]. It does not authorize a launch: the
    /// launch path must additionally verify the sealed
    /// [`KernelExecutionManifest`] and issue a sealed
    /// [`crate::BoundKernelExecutionManifest`].
    #[must_use]
    pub const fn admits_launch(&self) -> bool {
        match self {
            Self::Recorded(record) => record.admits_launch(),
            Self::AdmittedWithoutDegradation => true,
        }
    }

    /// Whether a NEW effect operation lease may be issued for this generation.
    ///
    /// True only when the observation composes to
    /// [`GenerationDisposition::Undegraded`]. A degraded or quarantined generation
    /// may resume only an exact already-authorized operation an unexpired lease it
    /// already holds covers, through [`crate::verify_exact_effect_replay`]; this
    /// predicate is never that path.
    #[must_use]
    pub const fn admits_new_effect_leases(&self) -> bool {
        match self {
            Self::Recorded(record) => record.admits_new_effect_leases(),
            Self::AdmittedWithoutDegradation => true,
        }
    }

    /// Whether this generation's routes are blocked.
    ///
    /// True for `Degraded` and `Quarantined`. A route cutover must refuse on this
    /// observation rather than read the manifest directly, so a degraded
    /// generation cannot keep acting through a route that was cut before the
    /// refusal was recorded.
    #[must_use]
    pub const fn blocks_routes(&self) -> bool {
        match self {
            Self::Recorded(record) => record.blocks_routes(),
            Self::AdmittedWithoutDegradation => false,
        }
    }

    /// Checks that this observation may be offered against exactly `manifest`.
    ///
    /// It refuses a recorded row that fails its own `validate()`, and it refuses
    /// a recorded row resolved for a DIFFERENT module or generation than the
    /// manifest it is offered against, so a readback for another generation can
    /// never authorize this one. The composed arm has no row to compare and
    /// therefore has nothing to refuse here: its admitted-manifest fact was
    /// validated by [`Self::compose`], on the manifest it was composed from.
    pub fn validate_against(&self, manifest: &KernelExecutionManifest) -> Result<(), OrsError> {
        let Some(record) = self.recorded() else {
            return Ok(());
        };
        record.validate()?;
        require_observed_generation_binding(record, manifest)
    }
}

/// Requires that one recorded lifecycle row names exactly the manifest's own
/// admitted `{module_id, generation}`.
///
/// Shared by [`ObservedGenerationLifecycle::compose`] and its `validate_against`,
/// so the composition and the validation of one observation can never disagree
/// about the same pair of inputs. The refusal is a typed
/// [`OrsError::InvalidField`] naming the disagreeing field, never a permissive
/// default: a row filed under another generation is not evidence about this one.
fn require_observed_generation_binding(
    record: &GenerationLifecycleRecord,
    manifest: &KernelExecutionManifest,
) -> Result<(), OrsError> {
    if record.module_id != manifest.admission.module_id {
        return Err(OrsError::InvalidField {
            field: "observed_generation_lifecycle_module_id",
            reason: "the recorded lifecycle row must name the manifest's own admitted module",
        });
    }
    if record.generation != manifest.admission.generation {
        return Err(OrsError::InvalidField {
            field: "observed_generation_lifecycle_generation",
            reason: "the recorded lifecycle row must name the manifest's own admitted generation",
        });
    }
    Ok(())
}
