//! Deterministic cue projection contracts.
//!
//! Temporary compatibility facade (issue #40): canonical-preserving
//! normalization migrates to `eliot-cue-normalizer`, binding/index/activation
//! to their named cells. Snapshot construction (`CueSnapshot`/`CueRuntime`)
//! has no admitted cell yet and stays here until one is proposed. The facade
//! is retained without deletion until consumers migrate (after T8-A4).
//!
//! This crate owns neither memory nor the understanding model.  It stores only
//! references to canonical records and immutable graph edges supplied by their
//! owners.  A published snapshot is the sole input to matching and bounded
//! activation; invalidation is a revision fence, never a second truth store.
//!
//! ## Issue #1143 ledger — `SPLIT_AND_RETAIN_AS_TEMPORARY_FACADE`
//!
//! Authority: issue #1143 (owns only `eliot-cues` + `eliot-dreamer-core`;
//! `eliot-epistemic` is `RETAIN_AND_HARDEN_IN_PLACE` and out of scope) and
//! `crates/smart/cognitive-donor-map.toml` (`SPLIT_AND_RETAIN_AS_TEMPORARY_FACADE`
//! with targets `eliot-cue-contracts`, `eliot-cue-normalizer`, `eliot-cue-binding`,
//! `eliot-cue-index`, `eliot-cue-activation`). GAP (#40): snapshot construction
//! has no admitted cell yet — [`CueSnapshot`]/[`CueRuntime`] stay here until one
//! is proposed; no target name is invented here.
//!
//! LEDGER + EDGE MIGRATION ONLY this turn: no root turn (root `Cargo.toml`
//! members, `Cargo.lock`, generated indexes are a serialized residual owned by
//! the LEGACY-DELETE-last root turn), no deletions (`LEGACY-DELETE-last`).
//! Zero live Cargo reverse-deps and zero `use eliot_cues::` outside self were
//! re-verified; both are necessary but not sufficient — this ledger is the
//! sufficiency record (47 pub items below, one row each).
//!
//! Dispositions — exactly one per row:
//! - `MIGRATED-1143`: edge migrated this turn; differential fixture cited;
//!   facade item retained byte-identical until LEGACY-DELETE.
//! - `FIXTURE`: bounded compatibility fixture with expiry/removal condition.
//! - `DELETE-PROPOSED`: removal deferred to the LEGACY-DELETE-last root turn
//!   once the stated precondition closes. Never executed here.
//!
//! Current #94 owner cells: `eliot-cue-contracts` (vocabulary + identity,
//! functional cell `smart.cue.contracts`), `eliot-cue-normalizer` (A-11 shared
//! normalization, `smart.cue.normalizer`), `eliot-cue-binding` (A-12,
//! `smart.cue.binding`), `eliot-cue-index` (A-13, `smart.cue.index`),
//! `eliot-cue-activation` (A-14a, `smart.cue.activation`).
//!
//! | # | Facade item | Current #94 owner | Bounded fixture + expiry | Disposition |
//! |---|-------------|-------------------|--------------------------|-------------|
//! | 1 | `CONTRACT_NAME` | contracts hub identity | replay/diagnostic string; expires at LEGACY-DELETE | FIXTURE |
//! | 2 | `CONTRACT_VERSION` | contracts `CONTRACT_REVISION` ("2.0.0") | replay string; expires at LEGACY-DELETE | FIXTURE |
//! | 3 | `MAX_FIRED` | activation `ActivationBounds` | firing-cap differential; expires at LEGACY-DELETE | DELETE-PROPOSED once activation bounds own the cap |
//! | 4 | `MAX_SPREAD_DEPTH` | activation `ActivationProfile` | spread-depth differential (see D-CUE-3); expires at LEGACY-DELETE | DELETE-PROPOSED once profile owns depth |
//! | 5 | `MAX_FANOUT` | activation profile + contracts `MAX_RELATION_EDGES` | fanout differential; expires at LEGACY-DELETE | DELETE-PROPOSED once profile owns fanout |
//! | 6 | `ACTIVATION_THRESHOLD` | activation caller-supplied profile | threshold differential (see D-CUE-3); expires at LEGACY-DELETE | DELETE-PROPOSED; never promoted to a profile default |
//! | 7 | `CueKind` | contracts `normalization::CueKind` (vocabulary owner) | spelling projection; retained until CUEKIND-OWNER (#835/#706) alias sequencing lands | DELETE-PROPOSED after #835 + anchor repoint |
//! | 8 | `MatchMode` | contracts `normalization::MatchMode` | mode projection; expires at LEGACY-DELETE | DELETE-PROPOSED after anchor repoint |
//! | 9 | `CueStrength` | contracts `activation::ActivationStrength` + activation evaluation | strength projection; expires at LEGACY-DELETE | DELETE-PROPOSED after activation owns strength |
//! | 10 | `CueKind::allows` | contracts `normalization::mode_admissible` | admissibility differential; expires at LEGACY-DELETE | DELETE-PROPOSED after anchor repoint |
//! | 11 | `CueError` | contracts `CueContractError` (+ normalizer/activation errors) | error-mapping fixture; expires at LEGACY-DELETE | DELETE-PROPOSED after consumers use owner errors |
//! | 12 | `ObservedCue` | contracts `observation::ObservedCue` | observation-shape fixture; expires at LEGACY-DELETE | DELETE-PROPOSED after adapters use owner shape |
//! | 13 | `ObservedCue::normalize` | normalizer `normalize_cue`/`capture_cue`/`fire_cue` (A-11) | single-seam differential (see D-CUE-1); expires when adapters call A-11 | DELETE-PROPOSED after A-11 edge admitted |
//! | 14 | `ObservedCue::source_value` | contracts `CueSourceValue` (+ normalizer `source_value`) | lossless-spelling differential; expires at LEGACY-DELETE | DELETE-PROPOSED after adapters use owner shape |
//! | 15 | `CueKey` | contracts `CueComparisonKey` (+ `NormalizedCue`) | EDGE-CUE-1143 projection; retained byte-identical until LEGACY-DELETE | MIGRATED-1143 (`ledger_1143_*` in `tests/integrity.rs`) |
//! | 16 | `CueKey::new` | normalizer under legacy-fold policy (v1 replay) | v1-replay differential (see D-CUE-1); expires at v1-replay retirement | DELETE-PROPOSED after re-observation path owns intake |
//! | 17 | `CueKey::with_case_policy` | normalizer `CasePolicy` explicit branch | explicit-policy differential; expires at LEGACY-DELETE | FIXTURE until A-11 edge admitted |
//! | 18 | `CueKey::with_mode` | contracts `mode_admissible` | mode-gate differential; expires at LEGACY-DELETE | DELETE-PROPOSED after anchor repoint |
//! | 19 | `CueKey::comparison_key` | contracts `CueComparisonKey` | EDGE-CUE-1143 projection; retained byte-identical until LEGACY-DELETE | MIGRATED-1143 (`ledger_1143_*` in `tests/integrity.rs`) |
//! | 20 | `CueKey::mode` field | contracts `CueComparisonKey::mode` | covered by row 19 | MIGRATED-1143 (field of row 15) |
//! | 21 | `InvalidationCause` | contracts `invalidation::{InvalidationCause, SnapshotInvalidation}` | cause-mapping fixture; expires at LEGACY-DELETE | DELETE-PROPOSED after index owns invalidation |
//! | 22 | `CueRecord` | index `SnapshotMember` + binding `CueBindingCandidate` via `ClosedSnapshotRow` | row-shape fixture; expires at LEGACY-DELETE | DELETE-PROPOSED after index owns rows |
//! | 23 | `CueRecord::new` | index admission (legacy `cue:` id retained for replay) | replay-construction fixture (see D-CUE-2); expires at v1-replay retirement | FIXTURE until v1 replay retires |
//! | 24 | `CueRecord::row_id_v2` | contracts `cue_row_id` (frozen v2 identity) | EDGE-CUE-1143 identity differential; retained byte-identical until LEGACY-DELETE | MIGRATED-1143 (`ledger_1143_*` in `tests/integrity.rs`) |
//! | 25 | `CueRecord::migrate_v1` | contracts `ConversionDisposition::V1ReplayPreserved` | replay-bridge fixture; expires at v1-replay retirement | FIXTURE until v1 replay retires |
//! | 26 | `CueRecord::transition` | `eliot-evidence::LifecycleState` + index lifecycle rules | lifecycle-mapping fixture; expires at LEGACY-DELETE | DELETE-PROPOSED after index owns transitions |
//! | 27 | `CueRecord::invalidate` | contracts `SnapshotInvalidation` mapping | invalidation-mapping fixture; expires at LEGACY-DELETE | DELETE-PROPOSED after index owns invalidation |
//! | 28 | `Freshness` | contracts freshness labels (activation/index) | freshness-mapping fixture; expires at LEGACY-DELETE | DELETE-PROPOSED after activation/index own freshness |
//! | 29 | `Freshness::is_usable` | activation freshness check | usability differential; expires at LEGACY-DELETE | DELETE-PROPOSED after activation owns check |
//! | 30 | `Freshness::matches_revision` | index revision check | revision differential; expires at LEGACY-DELETE | DELETE-PROPOSED after index owns check |
//! | 31 | `ActivationEdge` | contracts `RelationEdge` + `SnapshotEdgeWeight` join | edge-shape fixture; expires at LEGACY-DELETE | DELETE-PROPOSED after snapshot closure owns edges |
//! | 32 | `V1RowMigration` | contracts `ConversionDisposition` | replay-bridge fixture; expires at v1-replay retirement | FIXTURE until v1 replay retires |
//! | 33 | `V1SnapshotMigration` | contracts `ConversionDisposition` + receipts `ProofCeiling::CandidateArtifact` | replay-bridge fixture (candidate ceiling, never admission); expires at v1-replay retirement | FIXTURE until v1 replay retires |
//! | 34 | `FiredCue` | contracts `activation::DirectActivation` | firing-shape fixture; expires at LEGACY-DELETE | DELETE-PROPOSED after activation owns result shape |
//! | 35 | `ActivationHit` | contracts `DerivedActivation`/`DirectActivation` | hit-shape fixture; expires at LEGACY-DELETE | DELETE-PROPOSED after activation owns result shape |
//! | 36 | `ActivationTrace` | contracts `activation::ActivationTrace` | trace-shape fixture; expires at LEGACY-DELETE | DELETE-PROPOSED after activation owns result shape |
//! | 37 | `FiringResult` | contracts `activation::ActivationResult` | result-shape fixture; expires at LEGACY-DELETE | DELETE-PROPOSED after activation owns result shape |
//! | 38 | `CueSnapshot` | NO admitted cell (#40 GAP: snapshot construction) | retained facade; expires when a snapshot cell is proposed + consumers migrate | FIXTURE (GAP-blocked; delete forbidden until cell exists) |
//! | 39 | `CueSnapshot::validate` | contracts snapshot validation + fence check | fence/ceiling differential; expires with row 38 | FIXTURE (GAP-blocked) |
//! | 40 | `CueSnapshot::validate_closed` | contracts `validate_closed_rows`/`validate_closed_weights` + `CueProjectionDenominator` | closed-validation differential (`closed_validation_*` tests); expires with row 38 | FIXTURE (GAP-blocked) |
//! | 41 | `CueSnapshot::migrate_v1_snapshot` | contracts `ConversionDisposition` batch | replay-bridge fixture (candidate ceiling); expires at v1-replay retirement | FIXTURE until v1 replay retires |
//! | 42 | `CueSnapshot::invalidate` | contracts `SnapshotInvalidation` | revision-fence differential; expires with row 38 | FIXTURE (GAP-blocked) |
//! | 43 | `CueRuntime` | NO admitted cell (#40 GAP) | retained evaluator; expires when a snapshot cell is proposed | FIXTURE (GAP-blocked; delete forbidden until cell exists) |
//! | 44 | `CueRuntime::new` | NO admitted cell (#40 GAP) | construction-gate fixture; expires with row 43 | FIXTURE (GAP-blocked) |
//! | 45 | `CueRuntime::snapshot` | NO admitted cell (#40 GAP) | accessor fixture; expires with row 43 | FIXTURE (GAP-blocked) |
//! | 46 | `CueRuntime::invalidated` | NO admitted cell (#40 GAP) | invalidation fixture; expires with row 43 | FIXTURE (GAP-blocked) |
//! | 47 | `CueRuntime::fire` | activation `evaluate_activation` (A-14a) | firing differential (see D-CUE-3/D-CUE-4); retained until snapshot cell + consumers migrate | DELETE-PROPOSED after snapshot cell exists and activation owns firing |
//!
//! ## EDGE-CUE-1143 (migrated this turn, candidate ceiling)
//!
//! Facade [`CueKey::comparison_key`] + [`CueRecord::row_id_v2`] project onto the
//! owner-neutral vocabulary (`eliot-cue-contracts::{CueComparisonKey, cue_row_id}`,
//! functional capability `smart.cue.contracts` per
//! `crates/smart/cognitive-crate-decisions.toml`). Differential fixtures
//! `ledger_1143_*` in `tests/integrity.rs` prove: (a) every facade kind/mode
//! projects to the owner spelling and validates under the owner
//! (`CueComparisonKey::validate`); (b) the facade v2 view equals the frozen
//! owner function byte-identically; (c) the owner path validates with aggregate
//! fallback unavailable (no `eliot_cues::` item constructed or called); (d) the
//! case-policy divergence stays explicit (D-CUE-1). #13 capability resolution
//! for this edge maps to `smart.cue.contracts` (representation) with proof in
//! the owner cell plus the facade differential here; full runtime/Product proof
//! stays with #1100/#11. Proof ceiling: `COGNITIVE_AGGREGATE_RETIREMENT_CANDIDATE`.
//!
//! ## Corrected divergences (explicit; never restored for output-match)
//!
//! - D-CUE-1: path values are unconditionally lowercased here (donor-map
//!   rejected overgeneralization). Retained byte-identical for v1 replay; the
//!   cell decides case per explicit policy (`with_case_policy`).
//! - D-CUE-2: v1 `cue:` (blake3 over scope+value+target) vs frozen v2 `cuev2:`
//!   (canonical-JSON/sha256 over scope+kind+mode+value+target+revision).
//!   Namespaces never collide; re-observation via the normalizer is the only v2
//!   path — v1 bytes retain no spelling to recover.
//! - D-CUE-3: facade firing numerals (`MAX_FIRED`/`MAX_SPREAD_DEPTH`/`MAX_FANOUT`/
//!   `ACTIVATION_THRESHOLD`) are retained constants, never promoted to
//!   activation-profile defaults (the profile is caller-supplied, unbenchmarked,
//!   never default-enabled).
//! - D-CUE-4: facade `CueStrength`/`Freshness` are local metadata only; admission
//!   strength and epistemic status (`Observed`/`Supported`/`Verified`) belong to
//!   the activation/index cells, never to this facade.
//!
//! ## Sequencing (read-only; not duplicated here)
//!
//! SHIM-SWEEP-SMART / CUEKIND-OWNER touch adjacent state: #833 (facade
//! conversion — landed as the header above), #835 (transitional `eliot-types`
//! `CueKind` alias removal) + #706 (migration denominator freeze) own alias
//! deletion sequencing, #246 owns canonical spelling/keys/identity, #598 owns
//! the A-11 normalizer, #804 owns the A-10 vocabulary. This turn is
//! ledger-first and pre-deletes nothing. Residual for the LEGACY-DELETE-last
//! root turn: root `Cargo.toml` member line, `Cargo.lock` own-entry, generated
//! doc indexes, `module.toml` donor anchors, shipped serde boundaries.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use blake3::Hasher;
use eliot_contracts::{ArtifactId, ContractVersion, StateFence};
use eliot_cue_contracts::{
    ConversionDisposition, CueComparisonKey, CueProjectionDenominator, CueSourceValue,
    ProofCeiling, cue_row_id,
};
use eliot_evidence::LifecycleState;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.smart.cues";
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
pub const MAX_FIRED: usize = 8;
pub const MAX_SPREAD_DEPTH: u8 = 2;
pub const MAX_FANOUT: usize = 20;
pub const ACTIVATION_THRESHOLD: u16 = 350;

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CueKind {
    FilePath,
    DirPath,
    Symbol,
    ErrorSignature,
    CommandPattern,
    Dependency,
    ApiSurface,
    TaskClass,
    Subsystem,
    Concept,
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    Exact,
    Prefix,
    Signature,
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CueStrength {
    Primary,
    Secondary,
}

impl CueKind {
    pub const fn allows(self, mode: MatchMode) -> bool {
        matches!(
            (self, mode),
            (Self::DirPath, MatchMode::Prefix)
                | (Self::ErrorSignature, MatchMode::Signature)
                | (_, MatchMode::Exact)
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum CueError {
    #[error("cue scope is blank or contains a control character")]
    InvalidScope,
    #[error("cue value is blank or contains a control character")]
    InvalidValue,
    #[error("{kind:?} cannot use {mode:?} matching")]
    InvalidMatch { kind: CueKind, mode: MatchMode },
    #[error("error signatures must be canonical sig: values")]
    InvalidSignature,
    #[error("cue record has no canonical target")]
    MissingTarget,
    #[error("cue record lifecycle transition from {from} to {to} is forbidden")]
    InvalidLifecycle {
        from: LifecycleState,
        to: LifecycleState,
    },
    #[error("cue snapshot is stale for the requested revision")]
    StaleSnapshot,
    #[error("cue snapshot fence is incompatible")]
    FenceMismatch,
    #[error("cue revision overflow")]
    RevisionOverflow,
    #[error("duplicate v2 row identity in cue snapshot")]
    DuplicateRowId,
    #[error("duplicate semantic binding in cue snapshot")]
    DuplicateSemanticBinding,
    #[error("activation edge cites an unknown endpoint")]
    UnknownEndpoint,
    #[error("activation edge weight exceeds unity")]
    InvalidWeight,
    #[error("activation edge fanout exceeds the bound")]
    ExcessFanout,
    #[error("cue snapshot disagrees with its projection denominator")]
    DenominatorMismatch,
}

fn valid_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

fn lower(value: &str) -> String {
    value.chars().flat_map(char::to_lowercase).collect()
}

/// One normalized observation supplied by a tool/event adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservedCue {
    pub scope: String,
    pub kind: CueKind,
    pub value: String,
}

impl ObservedCue {
    pub fn normalize(&self) -> Result<CueKey, CueError> {
        CueKey::new(&self.scope, self.kind, &self.value)
    }
    /// Records the lossless v2 source value for this observation.
    ///
    /// The spelling is the observed value verbatim. Comparison semantics stay
    /// in the key; a blank spelling or reference is rejected as
    /// [`CueError::InvalidValue`].
    pub fn source_value(
        &self,
        source_identity_ref: &str,
        comparison_policy_ref: &str,
    ) -> Result<CueSourceValue, CueError> {
        let value = CueSourceValue::new(
            self.value.clone(),
            source_identity_ref.to_owned(),
            comparison_policy_ref.to_owned(),
        );
        value.validate().map_err(|_| CueError::InvalidValue)?;
        Ok(value)
    }
}

/// The only identity used by a projection lookup.
#[derive(
    Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct CueKey {
    pub scope: String,
    pub kind: CueKind,
    pub value: String,
    pub mode: MatchMode,
}

impl CueKey {
    pub fn new(scope: &str, kind: CueKind, value: &str) -> Result<Self, CueError> {
        Self::new_with_case(scope, kind, value, true)
    }
    /// Builds a key under an explicit case policy for path and text sources.
    ///
    /// `case_sensitive` preserves case and folds separators only; insensitive
    /// keeps the legacy unconditional lowercase. Error signatures are always
    /// canonical-folded: an exact canonical signature has no case policy.
    /// [`CueKey::new`] is retained byte-identical for v1 replay.
    pub fn with_case_policy(
        scope: &str,
        kind: CueKind,
        value: &str,
        case_sensitive: bool,
    ) -> Result<Self, CueError> {
        Self::new_with_case(scope, kind, value, !case_sensitive)
    }
    fn new_with_case(
        scope: &str,
        kind: CueKind,
        value: &str,
        fold_case: bool,
    ) -> Result<Self, CueError> {
        if !valid_text(scope) {
            return Err(CueError::InvalidScope);
        }
        if !valid_text(value) {
            return Err(CueError::InvalidValue);
        }
        let mode = match kind {
            CueKind::DirPath => MatchMode::Prefix,
            CueKind::ErrorSignature => MatchMode::Signature,
            _ => MatchMode::Exact,
        };
        let normalized = if fold_case {
            normalize_value(kind, value)
        } else {
            normalize_value_with_case(kind, value, false)
        };
        if !valid_text(&normalized) {
            return Err(CueError::InvalidValue);
        }
        if kind == CueKind::ErrorSignature
            && (normalized.len() != 68
                || !normalized.starts_with("sig:")
                || !normalized[4..]
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
        {
            return Err(CueError::InvalidSignature);
        }
        Ok(Self {
            scope: scope.trim().to_owned(),
            kind,
            value: normalized,
            mode,
        })
    }
    pub fn with_mode(
        scope: &str,
        kind: CueKind,
        mode: MatchMode,
        value: &str,
    ) -> Result<Self, CueError> {
        let key = Self::new(scope, kind, value)?;
        if !kind.allows(mode) {
            return Err(CueError::InvalidMatch { kind, mode });
        }
        if mode == MatchMode::Signature
            && (key.value.len() != 68
                || !key.value.starts_with("sig:")
                || !key.value[4..]
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
        {
            return Err(CueError::InvalidSignature);
        }
        Ok(Self { mode, ..key })
    }
    /// Views this key as an explicit v2 comparison key.
    ///
    /// The stored value is already normalized comparison material; scope,
    /// kind, and mode travel unchanged. Source spelling is never recovered
    /// from a key — v1 bytes retain no spelling to recover.
    pub fn comparison_key(&self) -> CueComparisonKey {
        CueComparisonKey::new(
            self.scope.clone(),
            contracts_kind(self.kind),
            contracts_mode(self.mode),
            self.value.clone(),
        )
    }
}

/// Maps the facade kind to the owner-neutral v2 vocabulary.
fn contracts_kind(kind: CueKind) -> eliot_cue_contracts::CueKind {
    match kind {
        CueKind::FilePath => eliot_cue_contracts::CueKind::FilePath,
        CueKind::DirPath => eliot_cue_contracts::CueKind::DirPath,
        CueKind::Symbol => eliot_cue_contracts::CueKind::Symbol,
        CueKind::ErrorSignature => eliot_cue_contracts::CueKind::ErrorSignature,
        CueKind::CommandPattern => eliot_cue_contracts::CueKind::CommandPattern,
        CueKind::Dependency => eliot_cue_contracts::CueKind::Dependency,
        CueKind::ApiSurface => eliot_cue_contracts::CueKind::ApiSurface,
        CueKind::TaskClass => eliot_cue_contracts::CueKind::TaskClass,
        CueKind::Subsystem => eliot_cue_contracts::CueKind::Subsystem,
        CueKind::Concept => eliot_cue_contracts::CueKind::Concept,
    }
}

/// Maps the facade match mode to the owner-neutral v2 vocabulary.
fn contracts_mode(mode: MatchMode) -> eliot_cue_contracts::MatchMode {
    match mode {
        MatchMode::Exact => eliot_cue_contracts::MatchMode::Exact,
        MatchMode::Prefix => eliot_cue_contracts::MatchMode::Prefix,
        MatchMode::Signature => eliot_cue_contracts::MatchMode::Signature,
    }
}

/// Temporary facade seam for canonical-preserving normalization (issue #40).
///
/// Contract owner: `eliot-cue-normalizer` behind `eliot-cue-contracts`. Every
/// observation normalizes through this one seam until the
/// `eliot-cues -> eliot-cue-normalizer` compile edge is admitted; do not add a
/// second normalization copy. Known facade divergence, retained for fixture
/// equivalence: path values are unconditionally lowercased here, which the
/// donor map rejects as a destructive overgeneralization — the cell decides
/// case per policy.
fn normalize_value(kind: CueKind, value: &str) -> String {
    let value = value.trim().replace('\\', "/");
    match kind {
        CueKind::FilePath | CueKind::DirPath => normalize_path_value(&value),
        CueKind::Symbol => lower(&value.replace("::::", "::").replace(":::", "::")),
        _ => lower(&value.split_whitespace().collect::<Vec<_>>().join(" ")),
    }
}

/// Explicit-policy branch of the facade normalization seam.
///
/// `fold_case` selects the legacy unconditional lowercase (`true`, retained
/// for v1 replay) or case-preserving comparison material (`false`).
/// Separator folding and error-signature canonicalization always apply: an
/// exact canonical signature has no case policy.
fn normalize_value_with_case(kind: CueKind, value: &str, fold_case: bool) -> String {
    let value = value.trim().replace('\\', "/");
    match kind {
        CueKind::FilePath | CueKind::DirPath => normalize_path_value_with_case(&value, fold_case),
        CueKind::Symbol if fold_case => lower(&value.replace("::::", "::").replace(":::", "::")),
        CueKind::Symbol => value.replace("::::", "::").replace(":::", "::"),
        CueKind::ErrorSignature => lower(&value.split_whitespace().collect::<Vec<_>>().join(" ")),
        _ if fold_case => lower(&value.split_whitespace().collect::<Vec<_>>().join(" ")),
        _ => value.split_whitespace().collect::<Vec<_>>().join(" "),
    }
}

/// Path branch of the facade normalization seam: separator folding, `.`
/// removal and case folding in one deterministic order.
fn normalize_path_value(value: &str) -> String {
    normalize_path_value_with_case(value, true)
}

/// Explicit-policy path branch: separator folding and `.` removal always
/// apply; case folding follows the admitted source policy.
fn normalize_path_value_with_case(value: &str, fold_case: bool) -> String {
    let mut out = Vec::new();
    for part in value.split('/') {
        if !part.is_empty() && part != "." {
            out.push(part);
        }
    }
    let joined = out.join("/");
    if fold_case { lower(&joined) } else { joined }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationCause {
    Superseded,
    Stale,
    ScopeChanged,
    Deleted,
    Manual,
}

/// A projection row: target identity and lifecycle metadata, never target payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CueRecord {
    pub row_id: String,
    pub key: CueKey,
    pub target: ArtifactId,
    pub target_kind: String,
    pub strength: CueStrength,
    pub lifecycle: LifecycleState,
    pub negative_memory: bool,
    pub freshness: Freshness,
    pub source_revision: u64,
}

impl CueRecord {
    pub fn new(
        key: CueKey,
        target: ArtifactId,
        target_kind: String,
        strength: CueStrength,
        freshness: Freshness,
        source_revision: u64,
    ) -> Result<Self, CueError> {
        if target.as_str().trim().is_empty() {
            return Err(CueError::MissingTarget);
        }
        let mut h = Hasher::new();
        h.update(key.scope.as_bytes());
        h.update(key.value.as_bytes());
        h.update(target.as_str().as_bytes());
        Ok(Self {
            row_id: format!("cue:{}", &h.finalize().to_hex().to_string()[..32]),
            key,
            target,
            target_kind,
            strength,
            lifecycle: LifecycleState::Active,
            negative_memory: false,
            freshness,
            source_revision,
        })
    }
    /// Computes the frozen v2 row identity for this record.
    ///
    /// Binds scope, kind, mode, normalized comparison key, target identity,
    /// and the v2 identity-contract revision through the owner-neutral
    /// function. The legacy [`CueRecord::row_id`] is retained byte-identical
    /// for replay.
    pub fn row_id_v2(&self) -> Result<String, CueError> {
        let target = eliot_cue_contracts::TargetHandle::new(self.target.as_str())
            .map_err(|_| CueError::MissingTarget)?;
        cue_row_id(
            &self.key.scope,
            contracts_kind(self.key.kind),
            contracts_mode(self.key.mode),
            &self.key.value,
            &target,
        )
        .map_err(|_| CueError::InvalidValue)
    }
    /// Replay-only v1 migration for one record.
    ///
    /// V1 bytes retain only normalized material: source spelling is
    /// unrecoverable, so conversion is refused by construction and the legacy
    /// identity is preserved for replay. Re-observation through the
    /// normalizer is the only path to a v2 identity. Nothing on this record
    /// changes; in particular lifecycle, strength, freshness, and the
    /// negative-memory flag are untouched.
    pub fn migrate_v1(&self) -> V1RowMigration {
        V1RowMigration {
            legacy_row_id: self.row_id.clone(),
            disposition: ConversionDisposition::V1ReplayPreserved {
                legacy_row_id: self.row_id.clone(),
            },
        }
    }
    pub fn transition(&mut self, next: LifecycleState) -> Result<(), CueError> {
        if self.lifecycle != next
            && (self.lifecycle == LifecycleState::Extinguished
                || (self.lifecycle == LifecycleState::Archived
                    && next == LifecycleState::Suppressed))
        {
            return Err(CueError::InvalidLifecycle {
                from: self.lifecycle,
                to: next,
            });
        }
        self.lifecycle = next;
        Ok(())
    }
    #[allow(clippy::needless_pass_by_value)]
    pub fn invalidate(&mut self, cause: InvalidationCause) -> Result<(), CueError> {
        let next = match cause {
            InvalidationCause::Superseded | InvalidationCause::Deleted => {
                LifecycleState::Extinguished
            }
            InvalidationCause::Stale => LifecycleState::Archived,
            InvalidationCause::ScopeChanged | InvalidationCause::Manual => {
                LifecycleState::Suppressed
            }
        };
        self.transition(next)
    }
    fn eligible(&self, now: u64) -> bool {
        self.lifecycle.is_active() && self.freshness.is_usable(now)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    Unbounded,
    UntilRevision(u64),
    UntilUnixMs(u64),
}

impl Freshness {
    pub const fn is_usable(self, now: u64) -> bool {
        match self {
            Self::Unbounded | Self::UntilRevision(_) => true,
            Self::UntilUnixMs(deadline) => now <= deadline,
        }
    }
    pub const fn matches_revision(self, revision: u64) -> bool {
        match self {
            Self::Unbounded | Self::UntilUnixMs(_) => true,
            Self::UntilRevision(limit) => revision <= limit,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivationEdge {
    pub from: ArtifactId,
    pub to: ArtifactId,
    pub weight_milli: u16,
}

/// Replay-only v1 migration for one projection row.
///
/// Carries the preserved legacy identity and its explicit conversion
/// disposition. Never an admission and never a lifecycle, support,
/// applicability, accessibility, or influence claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct V1RowMigration {
    pub legacy_row_id: String,
    pub disposition: ConversionDisposition,
}

/// Replay-only v1 migration for one snapshot.
///
/// Every row keeps its v1 bytes and identity; `ceiling` reports the migration
/// proof ceiling, which is a candidate artifact — not admission, publication,
/// or delivery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct V1SnapshotMigration {
    pub rows: Vec<V1RowMigration>,
    pub ceiling: ProofCeiling,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FiredCue {
    pub key: CueKey,
    pub target: ArtifactId,
    pub strength: CueStrength,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivationHit {
    pub target: ArtifactId,
    pub score_milli: u16,
    pub depth: u8,
    pub path: Vec<ArtifactId>,
    pub direct: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivationTrace {
    pub seed_cues: Vec<CueKey>,
    pub hits: Vec<ActivationHit>,
    pub suppressed: Vec<ArtifactId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FiringResult {
    pub projection_revision: u64,
    pub fired: Vec<FiredCue>,
    pub activation: Vec<ActivationHit>,
    pub overflow: usize,
    pub trace: ActivationTrace,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CueSnapshot {
    pub revision: u64,
    pub fence: StateFence,
    pub records: Vec<CueRecord>,
    pub edges: Vec<ActivationEdge>,
}

impl CueSnapshot {
    pub fn validate(&self) -> Result<(), CueError> {
        self.fence.validate().map_err(|_| CueError::FenceMismatch)?;
        if self
            .records
            .iter()
            .any(|r| r.source_revision > self.revision)
        {
            return Err(CueError::StaleSnapshot);
        }
        Ok(())
    }
    /// Checks closed-snapshot invariants beyond fence and revision ceiling.
    ///
    /// Proves: the frozen denominator reconciles present records/edges
    /// against expected minus omitted counts; v2 row identities are unique;
    /// semantic bindings (kind, comparison value, target) are unique; every
    /// edge cites existing endpoints with unity-bounded weight and bounded
    /// per-node fanout. An explicitly partial denominator validates here; use
    /// [`CueProjectionDenominator::is_empty_complete`] to distinguish
    /// empty-complete from partial.
    pub fn validate_closed(&self, denominator: &CueProjectionDenominator) -> Result<(), CueError> {
        self.validate()?;
        denominator
            .validate()
            .map_err(|_| CueError::DenominatorMismatch)?;
        denominator
            .validate_against(self.records.len(), self.edges.len())
            .map_err(|_| CueError::DenominatorMismatch)?;
        let mut seen_ids = BTreeSet::new();
        for record in &self.records {
            if !seen_ids.insert(record.row_id_v2()?) {
                return Err(CueError::DuplicateRowId);
            }
        }
        let mut seen_semantic = BTreeSet::new();
        for record in &self.records {
            let semantic = (
                record.key.kind,
                record.key.value.clone(),
                record.target.clone(),
            );
            if !seen_semantic.insert(semantic) {
                return Err(CueError::DuplicateSemanticBinding);
            }
        }
        let endpoints: BTreeSet<_> = self.records.iter().map(|record| &record.target).collect();
        let mut fanout: BTreeMap<&ArtifactId, usize> = BTreeMap::new();
        for edge in &self.edges {
            if !endpoints.contains(&edge.from) || !endpoints.contains(&edge.to) {
                return Err(CueError::UnknownEndpoint);
            }
            if edge.weight_milli > 1000 {
                return Err(CueError::InvalidWeight);
            }
            let count = fanout.entry(&edge.from).or_insert(0);
            *count += 1;
            if *count > MAX_FANOUT {
                return Err(CueError::ExcessFanout);
            }
        }
        Ok(())
    }
    /// Replay-only v1 migration for this snapshot.
    ///
    /// Preserves every v1 row identity for replay and reports the migration
    /// ceiling. The snapshot itself is untouched.
    pub fn migrate_v1_snapshot(&self) -> V1SnapshotMigration {
        V1SnapshotMigration {
            rows: self.records.iter().map(CueRecord::migrate_v1).collect(),
            ceiling: ProofCeiling::CandidateArtifact,
        }
    }
    #[allow(clippy::needless_pass_by_value)]
    pub fn invalidate(
        &self,
        targets: &BTreeSet<ArtifactId>,
        cause: InvalidationCause,
        revision: u64,
    ) -> Result<Self, CueError> {
        if revision <= self.revision {
            return Err(CueError::StaleSnapshot);
        }
        let mut next = self.clone();
        next.revision = revision;
        for record in &mut next.records {
            if targets.contains(&record.target) {
                record.invalidate(cause.clone())?;
            }
        }
        Ok(next)
    }
}

/// Immutable projection evaluator.  Callers publish a rebuilt snapshot after
/// canonical commit; no method mutates canonical records or graph state.
#[derive(Clone, Debug)]
pub struct CueRuntime {
    snapshot: CueSnapshot,
}

impl CueRuntime {
    pub fn new(snapshot: CueSnapshot) -> Result<Self, CueError> {
        snapshot.validate()?;
        Ok(Self { snapshot })
    }
    pub fn snapshot(&self) -> &CueSnapshot {
        &self.snapshot
    }
    pub fn invalidated(
        &self,
        targets: &BTreeSet<ArtifactId>,
        cause: InvalidationCause,
        revision: u64,
    ) -> Result<Self, CueError> {
        Self::new(self.snapshot.invalidate(targets, cause, revision)?)
    }
    #[allow(clippy::too_many_lines)]
    pub fn fire(
        &self,
        observed: &[ObservedCue],
        revision: u64,
        now: u64,
    ) -> Result<FiringResult, CueError> {
        if revision < self.snapshot.revision {
            return Err(CueError::StaleSnapshot);
        }
        let keys = observed
            .iter()
            .map(ObservedCue::normalize)
            .collect::<Result<Vec<_>, _>>()?;
        let mut direct = Vec::new();
        for key in &keys {
            for record in &self.snapshot.records {
                if record.key.scope == key.scope
                    && record.key.kind == key.kind
                    && record.eligible(now)
                    && record.freshness.matches_revision(revision)
                    && ((record.key.mode == MatchMode::Prefix
                        && key.value.starts_with(&record.key.value))
                        || record.key.mode != MatchMode::Prefix && record.key.value == key.value)
                {
                    direct.push(FiredCue {
                        key: record.key.clone(),
                        target: record.target.clone(),
                        strength: record.strength,
                    });
                }
            }
        }
        direct.sort_by(|a, b| {
            a.target
                .cmp(&b.target)
                .then(a.strength.cmp(&b.strength))
                .then(a.key.cmp(&b.key))
        });
        direct.dedup_by(|a, b| a.target == b.target && a.key == b.key);
        let mut direct_targets = BTreeSet::new();
        for item in &direct {
            direct_targets.insert(item.target.clone());
        }
        let mut scores = BTreeMap::<ArtifactId, (u16, u8, Vec<ArtifactId>)>::new();
        for item in &direct {
            scores.insert(item.target.clone(), (1000, 0, vec![item.target.clone()]));
        }
        let mut frontier: Vec<(ArtifactId, u16, u8, Vec<ArtifactId>)> = direct
            .iter()
            .map(|x| (x.target.clone(), 1000, 0, vec![x.target.clone()]))
            .collect();
        while let Some((from, score, depth, path)) = frontier.pop() {
            if depth >= MAX_SPREAD_DEPTH {
                continue;
            }
            let mut edges: Vec<_> = self
                .snapshot
                .edges
                .iter()
                .filter(|e| e.from == from && e.weight_milli > 0)
                .collect();
            edges.sort_by(|a, b| b.weight_milli.cmp(&a.weight_milli).then(a.to.cmp(&b.to)));
            edges.truncate(MAX_FANOUT);
            for edge in edges {
                let child = score.saturating_mul(edge.weight_milli) / 1000 / 2;
                if child < ACTIVATION_THRESHOLD {
                    continue;
                }
                let mut next_path = path.clone();
                next_path.push(edge.to.clone());
                let replace = scores.get(&edge.to).is_none_or(|x| child > x.0);
                if replace {
                    scores.insert(edge.to.clone(), (child, depth + 1, next_path.clone()));
                    frontier.push((edge.to.clone(), child, depth + 1, next_path));
                }
            }
        }
        let mut activation = scores
            .into_iter()
            .map(|(target, (score, depth, path))| {
                let direct = direct_targets.contains(&target);
                ActivationHit {
                    target,
                    score_milli: score,
                    depth,
                    path,
                    direct,
                }
            })
            .collect::<Vec<_>>();
        activation.sort_by(|a, b| {
            b.direct
                .cmp(&a.direct)
                .then(b.score_milli.cmp(&a.score_milli))
                .then(a.target.cmp(&b.target))
        });
        let overflow = activation.len().saturating_sub(MAX_FIRED);
        let suppressed = activation
            .iter()
            .skip(MAX_FIRED)
            .map(|x| x.target.clone())
            .collect();
        activation.truncate(MAX_FIRED);
        Ok(FiringResult {
            projection_revision: self.snapshot.revision,
            fired: direct.iter().take(MAX_FIRED).cloned().collect(),
            activation: activation.clone(),
            overflow,
            trace: ActivationTrace {
                seed_cues: keys,
                hits: activation,
                suppressed,
            },
        })
    }
}
