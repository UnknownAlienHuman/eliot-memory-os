//! Deterministic cue projection contracts.
//!
//! This crate owns neither memory nor the understanding model.  It stores only
//! references to canonical records and immutable graph edges supplied by their
//! owners.  A published snapshot is the sole input to matching and bounded
//! activation; invalidation is a revision fence, never a second truth store.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use blake3::Hasher;
use eliot_contracts::{ArtifactId, ContractVersion, StateFence};
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
        let normalized = normalize_value(kind, value);
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
}

fn normalize_value(kind: CueKind, value: &str) -> String {
    let value = value.trim().replace('\\', "/");
    match kind {
        CueKind::FilePath | CueKind::DirPath => {
            let mut out = Vec::new();
            for part in value.split('/') {
                if !part.is_empty() && part != "." {
                    out.push(part);
                }
            }
            lower(&out.join("/"))
        }
        CueKind::Symbol => lower(&value.replace("::::", "::").replace(":::", "::")),
        _ => lower(&value.split_whitespace().collect::<Vec<_>>().join(" ")),
    }
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
    pub fn transition(&mut self, next: LifecycleState) -> Result<(), CueError> {
        if self.lifecycle != next
            && (self.lifecycle == LifecycleState::Extinguished
                || (self.lifecycle == LifecycleState::Archived
                    && next == LifecycleState::Suppressed)
                || matches!(
                    (self.lifecycle, next),
                    (
                        LifecycleState::Active
                            | LifecycleState::Quarantined
                            | LifecycleState::Suppressed,
                        LifecycleState::Extinguished
                    )
                ))
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
    #[allow(clippy::needless_pass_by_value)]
    pub fn invalidate(
        &self,
        targets: &BTreeSet<ArtifactId>,
        cause: InvalidationCause,
        revision: u64,
    ) -> Result<Self, CueError> {
        if revision < self.revision {
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
