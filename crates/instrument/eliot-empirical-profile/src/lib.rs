//! The sole owner of empirical, scope-bound instrument profiles.
//!
//! A profile is a projection of observations, never a verifier and never a
//! source of proof.  Samples are keyed by the complete execution identity so
//! that measurements from another target, profile, or scope cannot silently
//! influence a caller's estimate.  The owner keeps a bounded history and
//! publishes immutable snapshots with a deterministic revision digest.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::sync::{Arc, RwLock};

use eliot_instrument_api::{ExecutionStatus, InstrumentKind, VerificationOutcome};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.instrument.empirical-profile";
pub const CONTRACT_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const DEFAULT_SAMPLE_LIMIT: usize = 128;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProfileError {
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    #[error("sample limit must be greater than zero")]
    InvalidSampleLimit,
    #[error("observation has an invalid lifecycle: {0}")]
    InvalidObservation(&'static str),
    #[error("profile owner lock was poisoned")]
    LockPoisoned,
    #[error("profile serialization failed: {0}")]
    Serialization(String),
}

fn text(value: &str, field: &'static str) -> Result<(), ProfileError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(ProfileError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn digest<T: Serialize>(value: &T) -> Result<String, ProfileError> {
    let bytes =
        serde_json::to_vec(value).map_err(|e| ProfileError::Serialization(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut encoded, "{byte:02x}")
            .map_err(|error| ProfileError::Serialization(error.to_string()))?;
    }
    Ok(encoded)
}

/// Exact identity under which measurements may be pooled.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileKey {
    pub instrument: String,
    pub kind: InstrumentKind,
    pub profile: String,
    pub target: String,
    pub declared_scope: String,
}

impl ProfileKey {
    pub fn validate(&self) -> Result<(), ProfileError> {
        for (value, field) in [
            (&self.instrument, "instrument"),
            (&self.profile, "profile"),
            (&self.target, "target"),
            (&self.declared_scope, "declared_scope"),
        ] {
            text(value, field)?;
        }
        Ok(())
    }
}

impl Ord for ProfileKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            &self.instrument,
            kind_rank(self.kind),
            &self.profile,
            &self.target,
            &self.declared_scope,
        )
            .cmp(&(
                &other.instrument,
                kind_rank(other.kind),
                &other.profile,
                &other.target,
                &other.declared_scope,
            ))
    }
}

impl PartialOrd for ProfileKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn kind_rank(kind: InstrumentKind) -> u8 {
    match kind {
        InstrumentKind::Build => 0,
        InstrumentKind::Test => 1,
        InstrumentKind::Lint => 2,
        InstrumentKind::Inspect => 3,
        InstrumentKind::Verify => 4,
        InstrumentKind::Format => 5,
    }
}

/// One completed observation admitted by the profile owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmpiricalObservation {
    pub observation_id: String,
    pub invocation_id: String,
    pub key: ProfileKey,
    pub execution: ExecutionStatus,
    pub outcome: Option<VerificationOutcome>,
    pub elapsed_ms: u64,
    pub observed_at_ms: u64,
    pub source_digest: String,
}

impl EmpiricalObservation {
    pub fn validate(&self) -> Result<(), ProfileError> {
        for (value, field) in [
            (&self.observation_id, "observation_id"),
            (&self.invocation_id, "invocation_id"),
            (&self.source_digest, "source_digest"),
        ] {
            text(value, field)?;
        }
        self.key.validate()?;
        if self.observed_at_ms == 0 {
            return Err(ProfileError::InvalidObservation(
                "observed_at_ms must be non-zero",
            ));
        }
        if !self.execution.is_terminal() {
            return Err(ProfileError::InvalidObservation(
                "only terminal executions may be profiled",
            ));
        }
        if self.outcome == Some(VerificationOutcome::Pass)
            && !matches!(self.execution, ExecutionStatus::Succeeded)
        {
            return Err(ProfileError::InvalidObservation(
                "PASS requires succeeded execution",
            ));
        }
        Ok(())
    }
}

/// Stable aggregate statistics for one exact profile key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileStatistics {
    pub count: u64,
    pub total_elapsed_ms: u128,
    pub minimum_elapsed_ms: u64,
    pub maximum_elapsed_ms: u64,
    pub successful_count: u64,
    pub failed_count: u64,
    pub partial_count: u64,
    pub unknown_count: u64,
    pub blocked_count: u64,
    pub last_observed_at_ms: u64,
}

impl Default for ProfileStatistics {
    fn default() -> Self {
        Self {
            count: 0,
            total_elapsed_ms: 0,
            minimum_elapsed_ms: u64::MAX,
            maximum_elapsed_ms: 0,
            successful_count: 0,
            failed_count: 0,
            partial_count: 0,
            unknown_count: 0,
            blocked_count: 0,
            last_observed_at_ms: 0,
        }
    }
}

impl ProfileStatistics {
    fn add(&mut self, observation: &EmpiricalObservation) {
        self.count += 1;
        self.total_elapsed_ms = self
            .total_elapsed_ms
            .saturating_add(u128::from(observation.elapsed_ms));
        self.minimum_elapsed_ms = self.minimum_elapsed_ms.min(observation.elapsed_ms);
        self.maximum_elapsed_ms = self.maximum_elapsed_ms.max(observation.elapsed_ms);
        self.last_observed_at_ms = self.last_observed_at_ms.max(observation.observed_at_ms);
        match observation.outcome {
            Some(VerificationOutcome::Pass) => self.successful_count += 1,
            Some(VerificationOutcome::Fail) => self.failed_count += 1,
            Some(VerificationOutcome::Partial) => self.partial_count += 1,
            Some(VerificationOutcome::Unknown | VerificationOutcome::Cancelled) => {
                self.unknown_count += 1;
            }
            Some(VerificationOutcome::Blocked) | None => self.blocked_count += 1,
        }
    }

    pub fn mean_elapsed_ms(&self) -> Option<u64> {
        (self.count != 0).then(|| {
            let mean = (self.total_elapsed_ms / u128::from(self.count)).min(u128::from(u64::MAX));
            u64::try_from(mean).unwrap_or(u64::MAX)
        })
    }
}

/// Immutable, revisioned projection returned to readers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmpiricalProfile {
    pub key: ProfileKey,
    pub revision: String,
    pub statistics: ProfileStatistics,
    pub observations: Vec<EmpiricalObservation>,
}

impl EmpiricalProfile {
    fn new(key: ProfileKey, observations: Vec<EmpiricalObservation>) -> Result<Self, ProfileError> {
        let mut statistics = ProfileStatistics::default();
        for observation in &observations {
            statistics.add(observation);
        }
        let revision = digest(&(&key, &statistics, &observations))?;
        Ok(Self {
            key,
            revision,
            statistics,
            observations,
        })
    }
}

#[derive(Clone, Default)]
struct OwnedProfile {
    observations: VecDeque<EmpiricalObservation>,
}

/// Thread-safe empirical profile owner. It admits observations exactly once.
#[derive(Clone)]
pub struct EmpiricalProfileOwner {
    sample_limit: usize,
    profiles: Arc<RwLock<BTreeMap<ProfileKey, OwnedProfile>>>,
}

impl EmpiricalProfileOwner {
    pub fn new(sample_limit: usize) -> Result<Self, ProfileError> {
        if sample_limit == 0 {
            return Err(ProfileError::InvalidSampleLimit);
        }
        Ok(Self {
            sample_limit,
            profiles: Arc::new(RwLock::new(BTreeMap::new())),
        })
    }

    pub fn with_default_limit() -> Self {
        Self::new(DEFAULT_SAMPLE_LIMIT).unwrap_or_else(|_| unreachable!())
    }

    pub fn sample_limit(&self) -> usize {
        self.sample_limit
    }

    pub fn record(
        &self,
        observation: EmpiricalObservation,
    ) -> Result<EmpiricalProfile, ProfileError> {
        observation.validate()?;
        let mut profiles = self
            .profiles
            .write()
            .map_err(|_| ProfileError::LockPoisoned)?;
        let entry = profiles.entry(observation.key.clone()).or_default();
        if entry
            .observations
            .iter()
            .any(|item| item.observation_id == observation.observation_id)
        {
            return Self::snapshot_for(&observation.key, entry);
        }
        entry.observations.push_back(observation);
        while entry.observations.len() > self.sample_limit {
            entry.observations.pop_front();
        }
        Self::snapshot_for(
            &entry
                .observations
                .front()
                .map_or_else(|| unreachable!(), |o| o.key.clone()),
            entry,
        )
    }

    pub fn get(&self, key: &ProfileKey) -> Result<Option<EmpiricalProfile>, ProfileError> {
        key.validate()?;
        let profiles = self
            .profiles
            .read()
            .map_err(|_| ProfileError::LockPoisoned)?;
        profiles
            .get(key)
            .map(|entry| Self::snapshot_for(key, entry))
            .transpose()
    }

    pub fn snapshot(&self) -> Result<Vec<EmpiricalProfile>, ProfileError> {
        let profiles = self
            .profiles
            .read()
            .map_err(|_| ProfileError::LockPoisoned)?;
        profiles
            .iter()
            .map(|(key, entry)| Self::snapshot_for(key, entry))
            .collect()
    }

    fn snapshot_for(
        key: &ProfileKey,
        entry: &OwnedProfile,
    ) -> Result<EmpiricalProfile, ProfileError> {
        EmpiricalProfile::new(key.clone(), entry.observations.iter().cloned().collect())
    }
}

impl Default for EmpiricalProfileOwner {
    fn default() -> Self {
        Self::with_default_limit()
    }
}
