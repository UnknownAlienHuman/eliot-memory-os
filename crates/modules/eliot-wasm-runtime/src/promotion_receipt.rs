//! `ComponentPromotionReceipt`: the evidence reference production promotion
//! consumes (I18.42).
//!
//! I18.42 requires that every multi-contour component shares one conformance
//! corpus across pure core, WASM and native process backends, and that
//! "Production promotion consumes a `ComponentPromotionReceipt` that
//! references all required evidence; it cannot infer success from a build or
//! one test suite."
//!
//! This module is that receipt. It is inert evidence, not authority: it names
//! the evidence a promotion decision consumes, and evaluates to
//! [`PromotionDisposition::Incomplete`] whenever a class the I18.42 contract
//! requires is missing. There is deliberately no path from "it compiled" to a
//! promotion verdict — [`check_component_promotion`] with no receipt at all is
//! `INCOMPLETE`, which is exactly the build-only case #1919 must reject.
//!
//! The two shipped component shapes are recorded honestly:
//!
//! - a **multi-contour** component carries the full cross-contour evidence set
//!   (one shared corpus, the covered backends, the interface digest, property
//!   and differential behaviour, capability denial, resource limits,
//!   cancellation/traps, deterministic replay, migration, shadow divergence,
//!   canary rollback with old-epoch rejection, and exact Wasmtime engine
//!   compatibility where a WASM contour applies);
//! - a **single-contour** component records that it has exactly one contour
//!   and requires no cross-contour evidence. It never fabricates a corpus or a
//!   second backend that does not exist.
//!
//! Every field below maps onto a required class named in I18.42 or in the
//! acceptance criteria of #1919. No class, digest, or bound beyond those two
//! sources is introduced.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::types::{RuntimeError, Sha256Digest};

/// Outcome of consuming a [`ComponentPromotionReceipt`] for production
/// promotion.
///
/// There is no "pass because it built" variant: a receipt that does not
/// reference every required class for its contour is `Incomplete`, never a
/// pass.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PromotionDisposition {
    /// Every evidence class required for this component's contour count is
    /// present and consistent. Promotion may consume this receipt.
    Complete,
    /// At least one required evidence class is absent or unevaluated, the
    /// receipt describes a different interface, or the contour count
    /// disagrees with the backends actually covered. A build, or any single
    /// suite, reaches only this disposition.
    Incomplete,
}

impl PromotionDisposition {
    /// Stable code for the disposition.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Complete => "PROMOTION_COMPLETE",
            Self::Incomplete => "PROMOTION_INCOMPLETE",
        }
    }

    /// Reports whether promotion may consume a receipt with this outcome.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// How many execution contours the shipped component actually serves.
///
/// This is the recorded inventory fact a receipt is evaluated against, not a
/// request. A component with one contour states so and requires no
/// cross-contour evidence.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContourCount {
    /// Exactly one contour: no cross-contour conformance corpus exists or is
    /// required.
    Single,
    /// More than one contour: the shared cross-contour corpus and every I18.42
    /// required class apply.
    Multi,
}

impl ContourCount {
    /// Derives the contour count from the number of distinct backends the
    /// component is actually served on.
    #[must_use]
    pub const fn of(backends: usize) -> Self {
        if backends > 1 { Self::Multi } else { Self::Single }
    }
}

/// One backend identity a component is actually served on.
///
/// This names the existing contour vocabulary. It is not a second contour
/// enum: [`ComponentBackend::IsolatedNativeProcess`],
/// [`ComponentBackend::WasmComponent`], and [`ComponentBackend::StaticNative`]
/// are the machine [`Contour`](crate::types::ExecutionContour) stages' host
/// contours as they serve a component. [`ComponentBackend::PureCore`] names the
/// pure reference core, which is a conformance reference rather than a
/// dispatch contour.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComponentBackend {
    /// The pure reference core (no engine, no process, no I/O).
    PureCore,
    /// The capability-limited WASM component contour.
    WasmComponent,
    /// The isolated native process contour.
    IsolatedNativeProcess,
    /// The static native release contour.
    StaticNative,
}

impl ComponentBackend {
    /// Stable wire identity for the backend.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PureCore => "PURE_CORE",
            Self::WasmComponent => "WASM_COMPONENT",
            Self::IsolatedNativeProcess => "ISOLATED_NATIVE_PROCESS",
            Self::StaticNative => "STATIC_NATIVE",
        }
    }
}

/// Exact engine compatibility for AOT/compiled-cache evidence.
///
/// I18.42 requires "AOT/cache compatibility with exact Wasmtime engine". This
/// records the exact engine identity the AOT/compiled-cache evidence was
/// produced under, so a cache built under one engine generation is never read
/// as evidence for another. The shape mirrors the existing
/// [`EngineBinding`](crate::types::EngineBinding) version pair; no second
/// engine identity is invented.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineCompatibility {
    /// Exact engine implementation identity.
    pub implementation_id: String,
    /// Exact engine version the AOT/compiled-cache evidence was produced
    /// under. Not a range and not a compatibility class.
    pub exact_version: String,
}

impl EngineCompatibility {
    /// Creates the exact engine binding that AOT/cache evidence must name.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidField`] when either identity is blank or
    /// over the text bound: an unnamed engine is not evidence.
    pub fn new(
        implementation_id: impl Into<String>,
        exact_version: impl Into<String>,
    ) -> Result<Self, RuntimeError> {
        let compatibility = Self {
            implementation_id: implementation_id.into(),
            exact_version: exact_version.into(),
        };
        compatibility.validate()?;
        Ok(compatibility)
    }

    fn validate(&self) -> Result<(), RuntimeError> {
        crate::types::validate_text(&self.implementation_id, "engine.implementation_id")?;
        crate::types::validate_text(&self.exact_version, "engine.exact_version")
    }
}

/// State export/import and incompatible-migration disposition.
///
/// I18.42 requires "state export/import and incompatible migration". A
/// component that exports and imports no state states that fact explicitly
/// rather than leaving the class absent, so an absent class always means "not
/// run" and never "nothing to do".
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MigrationDisposition {
    /// The component exports and imports no state; there is nothing to
    /// migrate. Stated, not omitted.
    Stateless,
    /// The recorded state contract exported, imported, and migrated cleanly.
    Compatible,
    /// The state contract is an incompatible migration and is refused at this
    /// interface digest.
    Incompatible,
}

impl MigrationDisposition {
    /// Reports whether this disposition admits promotion. An incompatible
    /// migration is evidence that blocks promotion, not a passing class.
    #[must_use]
    pub const fn admits_promotion(self) -> bool {
        matches!(self, Self::Stateless | Self::Compatible)
    }
}

/// Canary rollback and old-epoch rejection leg.
///
/// I18.42 requires "canary rollback and old-epoch rejection": a promotion is
/// only complete when rollback to the named generation is proven and an
/// old-epoch request is proven rejected.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackEvidence {
    /// The prior compatible generation that receives new requests on rollback.
    pub rollback_generation: String,
    /// The old-epoch request was rejected rather than served.
    pub old_epoch_rejected: bool,
}

impl RollbackEvidence {
    /// Creates the rollback leg evidence. `rollback_generation` must name a
    /// real prior generation.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidField`] when the generation is blank or
    /// over the text bound: a rollback to nothing is not a rollback leg.
    pub fn new(
        rollback_generation: impl Into<String>,
        old_epoch_rejected: bool,
    ) -> Result<Self, RuntimeError> {
        let evidence = Self {
            rollback_generation: rollback_generation.into(),
            old_epoch_rejected,
        };
        crate::types::validate_text(
            &evidence.rollback_generation,
            "rollback.rollback_generation",
        )?;
        Ok(evidence)
    }
}

/// The evidence classes I18.42 requires for a component with more than one
/// contour.
///
/// Each class is `None` when it was not produced, and each boolean is
/// "unevaluated" until the leg actually ran. Nothing here defaults to a pass.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossContourEvidence {
    /// The one conformance corpus shared across every contour of this
    /// component. Two contours compared without a shared corpus are not
    /// compared at all.
    pub shared_corpus_digest: Option<Sha256Digest>,
    /// The exact component interface digest the corpus ran against. It must
    /// equal the receipt's own interface digest.
    pub interface_digest: Option<Sha256Digest>,
    /// Every backend identity the shared corpus actually covered. A
    /// multi-contour component needs at least two.
    pub backend_identities: Vec<ComponentBackend>,
    /// Property and differential behaviour agreed across the covered
    /// backends.
    pub differential_agreed: Option<bool>,
    /// Capability denial held on every covered backend.
    pub capability_denial_held: Option<bool>,
    /// Memory/table/stack/output/host-call limits held on every covered
    /// backend.
    pub resource_limits_held: Option<bool>,
    /// Epoch/fuel cancellation and trap containment held on every covered
    /// backend.
    pub cancellation_and_trap_contained: Option<bool>,
    /// Deterministic replay: the corpus reproduced identical results.
    pub deterministic_replay: Option<bool>,
    /// State export/import and incompatible-migration disposition.
    pub migration: Option<MigrationDisposition>,
    /// Shadow divergence resolved.
    pub shadow_divergence_resolved: Option<bool>,
    /// Canary rollback and old-epoch rejection.
    pub rollback: Option<RollbackEvidence>,
    /// AOT/cache compatibility with the exact Wasmtime engine, where a WASM
    /// contour is covered.
    pub engine_compatibility: Option<EngineCompatibility>,
}

impl CrossContourEvidence {
    /// The first class blocking promotion, in I18.42 required-class order.
    /// `None` when every class this contour count requires is present and
    /// admitted.
    fn blocking(&self) -> Option<&'static str> {
        if self.shared_corpus_digest.is_none() {
            Some("shared_corpus_digest")
        } else if self.interface_digest.is_none() {
            Some("interface_digest")
        } else if self.backend_identities.len() < 2 {
            Some("backend_identities")
        } else if !self.differential_agreed.unwrap_or(false) {
            Some("differential_agreed")
        } else if !self.capability_denial_held.unwrap_or(false) {
            Some("capability_denial_held")
        } else if !self.resource_limits_held.unwrap_or(false) {
            Some("resource_limits_held")
        } else if !self.cancellation_and_trap_contained.unwrap_or(false) {
            Some("cancellation_and_trap_contained")
        } else if !self.deterministic_replay.unwrap_or(false) {
            Some("deterministic_replay")
        } else if !self.migration.is_some_and(MigrationDisposition::admits_promotion) {
            Some("migration")
        } else if !self.shadow_divergence_resolved.unwrap_or(false) {
            Some("shadow_divergence_resolved")
        } else if self
            .rollback
            .as_ref()
            .is_none_or(|rollback| !rollback.old_epoch_rejected)
        {
            Some("rollback")
        } else {
            None
        }
    }
}

/// The evidence a component's promotion receipt references.
///
/// Exactly one shape applies to a component, decided by the recorded
/// [`ContourCount`] of the component in the component/contour inventory. A
/// single-contour component records that fact; a multi-contour component
/// references the shared cross-contour evidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "contour_count")]
pub enum ComponentContourEvidence {
    /// Exactly one contour. No cross-contour corpus exists and none is
    /// fabricated; the single-contour fact is the recorded evidence.
    SingleContour,
    /// More than one contour: the shared corpus and every I18.42 required
    /// class apply.
    MultiContour(CrossContourEvidence),
}

impl ComponentContourEvidence {
    /// The first class blocking promotion, or `None` when the evidence is
    /// complete for this component's contour count.
    fn blocking(&self) -> Option<&'static str> {
        match self {
            Self::SingleContour => None,
            Self::MultiContour(evidence) => evidence.blocking(),
        }
    }

    /// The backends this evidence actually covered.
    const fn backend_identities(&self) -> &[ComponentBackend] {
        match self {
            Self::SingleContour => &[],
            Self::MultiContour(evidence) => &evidence.backend_identities,
        }
    }
}

/// The evidence reference production promotion consumes.
///
/// A receipt names one component, the exact interface digest its evidence was
/// produced against, the exact engine compatibility of the host it is being
/// promoted onto, and the evidence for that component's contour shape. It is
/// produced by whoever actually ran the evidence; it grants no promotion
/// authority by itself.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentPromotionReceipt {
    /// The promoted component identity.
    pub component_id: String,
    /// The exact interface digest this receipt's evidence was produced
    /// against. A receipt for another interface is not this receipt.
    pub interface_digest: Sha256Digest,
    /// The exact Wasmtime engine compatibility of the host this component is
    /// being promoted onto, where a WASM contour applies.
    pub host_engine_compatibility: Option<EngineCompatibility>,
    /// The contour shape this component actually ships, with its evidence.
    pub evidence: ComponentContourEvidence,
}

impl ComponentPromotionReceipt {
    /// Evaluates this receipt for production promotion.
    ///
    /// Returns [`PromotionDisposition::Complete`] only when every class I18.42
    /// requires for this component's contour shape is present and consistent:
    /// a shared conformance corpus, the exact interface digest the running
    /// host serves, at least two covered backends, agreed differential
    /// behaviour, capability denial, resource limits, cancellation and trap
    /// containment, deterministic replay, an admitting migration disposition,
    /// resolved shadow divergence, canary rollback with old-epoch rejection,
    /// and exact Wasmtime engine compatibility wherever a WASM contour applies.
    ///
    /// Every other case is [`PromotionDisposition::Incomplete`]: no receipt, an
    /// absent class, an unevaluated leg, a non-admitting migration, an
    /// interface digest that is not the one the corpus ran against, a contour
    /// count that disagrees with the backends actually covered, or engine
    /// compatibility that is absent or not the exact running engine.
    #[must_use]
    pub fn evaluate(&self) -> PromotionDisposition {
        if self.blocking_evidence().is_some() {
            PromotionDisposition::Incomplete
        } else {
            PromotionDisposition::Complete
        }
    }

    /// Returns the first evidence class blocking promotion, or `None` when
    /// this receipt is complete.
    ///
    /// The value is a stable class name only — no digest, path, or payload is
    /// echoed, so a promotion refusal cannot leak evidence through its error.
    #[must_use]
    pub fn blocking_evidence(&self) -> Option<&'static str> {
        if crate::types::validate_text(&self.component_id, "receipt.component_id").is_err() {
            return Some("component_id");
        }
        if self.contour_disagreement() {
            return Some("contour_count");
        }
        match &self.evidence {
            ComponentContourEvidence::MultiContour(evidence) => {
                if evidence.interface_digest.as_ref() != Some(&self.interface_digest) {
                    return Some("interface_digest");
                }
            }
            ComponentContourEvidence::SingleContour => {}
        }
        if let Some(blocking) = self.evidence.blocking() {
            return Some(blocking);
        }
        if self.engine_disagreement() {
            return Some("engine_compatibility");
        }
        None
    }

    /// The covered backend count must agree with the recorded contour count,
    /// so a receipt can never claim a multi-contour corpus for a component
    /// that serves one contour, or the reverse.
    fn contour_disagreement(&self) -> bool {
        let derived = ContourCount::of(self.evidence.backend_identities().len());
        let recorded = match self.evidence {
            ComponentContourEvidence::SingleContour => ContourCount::Single,
            ComponentContourEvidence::MultiContour(_) => ContourCount::Multi,
        };
        derived != recorded
    }

    /// Wherever a WASM contour is covered, the evidence's engine
    /// compatibility must be present and must be exactly the engine the
    /// running host serves. Without this, an AOT or compiled cache built under
    /// one Wasmtime generation could be read as evidence for another.
    fn engine_disagreement(&self) -> bool {
        let wasm_covered = self
            .evidence
            .backend_identities()
            .contains(&ComponentBackend::WasmComponent);
        if !wasm_covered {
            return false;
        }
        let ComponentContourEvidence::MultiContour(evidence) = &self.evidence else {
            return true;
        };
        match (&evidence.engine_compatibility, &self.host_engine_compatibility) {
            (Some(produced), Some(host)) => produced != host,
            _ => true,
        }
    }
}

/// The stable evidence class a promotion gate reports when it refuses.
///
/// A refusal carries a class name only, never evidence content.
pub type PromotionRefusal = &'static str;

/// One shipped component and the contours it is actually served on.
///
/// This is the inventory entry: it records which backends exist, not which
/// ones a suite happened to exercise. It is a compile-time constant read by
/// [`recorded_contour_count`], not a runtime-loaded document, so it carries
/// no deserialization surface.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentContourRecord {
    /// The shipped component identity.
    pub component_id: &'static str,
    /// The bundle binary that serves this component.
    pub served_by: &'static str,
    /// The backends the component is actually served on.
    pub backends: &'static [ComponentBackend],
}

impl ComponentContourRecord {
    /// The contour count implied by the recorded backends.
    #[must_use]
    pub const fn contour_count(&self) -> ContourCount {
        match self.backends.len() {
            0 | 1 => ContourCount::Single,
            _ => ContourCount::Multi,
        }
    }
}

/// The nine bundle binaries in the release claim boundary.
///
/// Each is a pure Rust / native-process binary. None of them is a component
/// served on more than one contour, and none is recorded as one here.
pub const NINE_BUNDLE_BINARIES: [&str; 9] = [
    "eliot",
    "eliot-host",
    "eliot-watchdog",
    "eliot-kernel",
    "eliot-store-surreal",
    "eliotd",
    "eliot-doctor",
    "eliot-testd",
    "eliot-native-worker",
];

/// The component/contour inventory for the shipped bundle.
///
/// `wasmtime` is a dependency of exactly one workspace crate
/// (`eliot-wasm-host`), so exactly one shipped component is served on more
/// than one contour: `component-1956` runs on the WASM contour under
/// `eliot-wasm-host` and is compared against the pure reference core in
/// `lifecycle` through [`compare_conformance`](crate::lifecycle::compare_conformance).
/// Every other bundle binary is recorded single-contour, and no cross-contour
/// evidence is fabricated for it.
pub const COMPONENT_CONTOUR_INVENTORY: &[ComponentContourRecord] = &[
    ComponentContourRecord {
        component_id: "component-1956",
        served_by: "eliot-wasm-host",
        backends: &[ComponentBackend::PureCore, ComponentBackend::WasmComponent],
    },
    ComponentContourRecord {
        component_id: "eliot",
        served_by: "eliot",
        backends: &[ComponentBackend::StaticNative],
    },
    ComponentContourRecord {
        component_id: "eliot-host",
        served_by: "eliot-host",
        backends: &[ComponentBackend::IsolatedNativeProcess],
    },
    ComponentContourRecord {
        component_id: "eliot-watchdog",
        served_by: "eliot-watchdog",
        backends: &[ComponentBackend::IsolatedNativeProcess],
    },
    ComponentContourRecord {
        component_id: "eliot-kernel",
        served_by: "eliot-kernel",
        backends: &[ComponentBackend::IsolatedNativeProcess],
    },
    ComponentContourRecord {
        component_id: "eliot-store-surreal",
        served_by: "eliot-store-surreal",
        backends: &[ComponentBackend::IsolatedNativeProcess],
    },
    ComponentContourRecord {
        component_id: "eliotd",
        served_by: "eliotd",
        backends: &[ComponentBackend::IsolatedNativeProcess],
    },
    ComponentContourRecord {
        component_id: "eliot-doctor",
        served_by: "eliot-doctor",
        backends: &[ComponentBackend::IsolatedNativeProcess],
    },
    ComponentContourRecord {
        component_id: "eliot-testd",
        served_by: "eliot-testd",
        backends: &[ComponentBackend::IsolatedNativeProcess],
    },
    ComponentContourRecord {
        component_id: "eliot-native-worker",
        served_by: "eliot-native-worker",
        backends: &[ComponentBackend::IsolatedNativeProcess],
    },
];

/// Returns the recorded inventory entry for one component identity.
#[must_use]
pub fn component_contours(component_id: &str) -> Option<&'static ComponentContourRecord> {
    COMPONENT_CONTOUR_INVENTORY
        .iter()
        .find(|record| record.component_id == component_id)
}

/// Returns the recorded contour count for one component identity, or `None`
/// when the component is not in the shipped inventory.
#[must_use]
pub fn recorded_contour_count(component_id: &str) -> Option<ContourCount> {
    component_contours(component_id).map(ComponentContourRecord::contour_count)
}

/// Returns the multi-contour components in the shipped inventory.
#[must_use]
pub fn multi_contour_components() -> impl Iterator<Item = &'static ComponentContourRecord> {
    COMPONENT_CONTOUR_INVENTORY
        .iter()
        .filter(|record| record.contour_count() == ContourCount::Multi)
}

/// The four lifecycle verdicts a promotion receipt's evidence must decide.
///
/// I18.42 requires shadow divergence and canary rollback as required classes,
/// so promotion cannot be gated on a quadruple that is permanently
/// un-evaluated. These are read from the receipt's own evidence: each is
/// `true` only when the corresponding class was produced and admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleVerdictBinding {
    /// Shadow divergence was produced and resolved.
    pub shadow: bool,
    /// Canary rollback was produced, with old-epoch rejection proven.
    pub canary: bool,
    /// Rollback leg was produced, with old-epoch rejection proven.
    pub rollback: bool,
    /// Migration disposition was produced and admits promotion.
    pub cutover: bool,
}

impl LifecycleVerdictBinding {
    /// Reads the four verdicts from a receipt's evidence.
    ///
    /// A single-contour component has no shadow/canary/rollback leg at all, so
    /// each verdict is `false` — honestly absent, not passed. A multi-contour
    /// component's verdicts are exactly its evidence: no leg, `false`.
    #[must_use]
    pub fn from_receipt(receipt: &ComponentPromotionReceipt) -> Self {
        let ComponentContourEvidence::MultiContour(evidence) = &receipt.evidence else {
            return Self {
                shadow: false,
                canary: false,
                rollback: false,
                cutover: false,
            };
        };
        let rollback = evidence
            .rollback
            .as_ref()
            .is_some_and(|rollback| rollback.old_epoch_rejected);
        Self {
            shadow: evidence.shadow_divergence_resolved.unwrap_or(false),
            canary: rollback,
            rollback,
            cutover: evidence
                .migration
                .is_some_and(MigrationDisposition::admits_promotion),
        }
    }

    /// The canonical tuple the promotion receipt digest binds, in the
    /// shadow/canary/rollback/cutover order both promotion verifiers use.
    #[must_use]
    pub const fn as_tuple(self) -> (bool, bool, bool, bool) {
        (self.shadow, self.canary, self.rollback, self.cutover)
    }
}

/// The promotion gate itself.
///
/// This is the point the acceptance criteria of #1919 require: a promotion
/// attempted with only a successful build arrives with `None` and is refused
/// as `INCOMPLETE`. A promotion succeeds only when the receipt references the
/// shared conformance evidence, the exact interface digest, the backend
/// identities, the cancellation and resource behaviour, the replay result, the
/// migration disposition, the rollback/old-epoch result, and the exact Wasmtime
/// engine compatibility wherever a WASM contour applies.
///
/// Returns the disposition and the blocking evidence class, which is `None`
/// only for a complete receipt.
#[must_use]
pub fn check_component_promotion(
    receipt: Option<&ComponentPromotionReceipt>,
) -> (PromotionDisposition, Option<PromotionRefusal>) {
    match receipt {
        None => (PromotionDisposition::Incomplete, Some("receipt")),
        Some(receipt) => (receipt.evaluate(), receipt.blocking_evidence()),
    }
}
