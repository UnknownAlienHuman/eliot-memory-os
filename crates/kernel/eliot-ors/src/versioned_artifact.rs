//! I1.6 + I1.12 + I14.14: immutable generation-addressed versioned artifacts.
//!
//! Issue #1971: versioned binaries are never replaced in place while running
//! (I1.6). Activation moves through registry/route indirection, prior
//! artifacts are retained until their generation drains and retires, and
//! cutover/rollback verifies the candidate hash plus I1.12 compatibility
//! evidence. Any update targeting the path of an active executable is
//! rejected. This module is pure domain logic: it owns no processes, store
//! handles, or canonical memory.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::{OrsError, sha256_hex, validate_digest, validate_text};
use eliot_contracts::canonical_json_bytes;

/// Generation-addressed immutable artifact identity.
///
/// The canonical layout follows I14.14:
/// `modules/<module_id>/<generation>/<artifact_hash>/module.exe`.
/// Launchers must use this exact path; activation swaps registry state, never
/// the bytes at the active path.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedArtifact {
    pub module_id: String,
    pub generation: u64,
    pub artifact_hash: String,
    pub artifact_path: String,
}

impl VersionedArtifact {
    /// Canonical generation-addressed path for one immutable artifact.
    #[must_use]
    pub fn canonical_path(module_id: &str, generation: u64, artifact_hash: &str) -> String {
        format!("modules/{module_id}/{generation}/{artifact_hash}/module.exe")
    }

    /// Constructs and validates one immutable artifact identity.
    pub fn new(
        module_id: impl Into<String>,
        generation: u64,
        artifact_hash: impl Into<String>,
        artifact_path: impl Into<String>,
    ) -> Result<Self, OrsError> {
        let artifact = Self {
            module_id: module_id.into(),
            generation,
            artifact_hash: artifact_hash.into(),
            artifact_path: artifact_path.into(),
        };
        artifact.validate()?;
        Ok(artifact)
    }

    /// Validates generation addressing and the immutable hash/path binding.
    ///
    /// The path must equal the canonical generation-addressed layout
    /// exactly: substring matching would admit a generation `1` artifact at
    /// a generation `10` path, or a suffixed copy (`module.exe.bak`) of the
    /// addressed bytes, silently breaking the on-disk identity the
    /// generation/hash record names.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.module_id, "versioned_artifact_module_id")?;
        if self.generation == 0 {
            return Err(OrsError::InvalidField {
                field: "versioned_artifact_generation",
                reason: "generation must be non-zero",
            });
        }
        validate_digest(&self.artifact_hash, "versioned_artifact_hash")?;
        validate_text(&self.artifact_path, "versioned_artifact_path")?;
        if self.artifact_path
            != Self::canonical_path(&self.module_id, self.generation, &self.artifact_hash)
        {
            return Err(OrsError::InvalidField {
                field: "versioned_artifact_path",
                reason: "path must be exactly the canonical generation-addressed layout",
            });
        }
        Ok(())
    }
}

/// I1.12 compatibility evidence required before cutover or rollback.
///
/// Rollback is limited to artifacts compatible with durable formats and epoch
/// lineage; "last known good" means verified compatible, not merely
/// previously launched.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityEvidence {
    pub durable_format_compatible: bool,
    pub epoch_lineage_compatible: bool,
}

impl CompatibilityEvidence {
    /// Fails closed unless every compatibility axis is proven.
    pub fn require(&self) -> Result<(), OrsError> {
        if self.durable_format_compatible && self.epoch_lineage_compatible {
            Ok(())
        } else {
            Err(OrsError::IncompatibleArtifact)
        }
    }
}

/// Lifecycle of one retained artifact generation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactGenerationState {
    Staged,
    Active,
    Draining,
    Retired,
}

/// Status projection identifying the active generation's exact artifact.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedArtifactStatus {
    pub module_id: String,
    pub generation: u64,
    pub artifact_hash: String,
    pub artifact_path: String,
    pub state: ArtifactGenerationState,
}

/// Durable ORS-side cutover evidence binding old and new artifact identity.
///
/// Status readers and ORS records carry this shape so the active generation's
/// exact hash and path are observable without trusting a live process.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedArtifactCutoverRecord {
    pub module_id: String,
    pub old_generation: Option<u64>,
    pub new_generation: u64,
    pub old_artifact_hash: Option<String>,
    pub old_artifact_path: Option<String>,
    pub new_artifact_hash: String,
    pub new_artifact_path: String,
    pub durable_format_compatible: bool,
    pub epoch_lineage_compatible: bool,
    pub record_sha256: String,
}

#[derive(Serialize)]
struct VersionedArtifactCutoverCore<'a> {
    module_id: &'a str,
    old_generation: Option<u64>,
    new_generation: u64,
    old_artifact_hash: Option<&'a str>,
    old_artifact_path: Option<&'a str>,
    new_artifact_hash: &'a str,
    new_artifact_path: &'a str,
    durable_format_compatible: bool,
    epoch_lineage_compatible: bool,
}

impl VersionedArtifactCutoverRecord {
    fn core(&self) -> VersionedArtifactCutoverCore<'_> {
        VersionedArtifactCutoverCore {
            module_id: &self.module_id,
            old_generation: self.old_generation,
            new_generation: self.new_generation,
            old_artifact_hash: self.old_artifact_hash.as_deref(),
            old_artifact_path: self.old_artifact_path.as_deref(),
            new_artifact_hash: &self.new_artifact_hash,
            new_artifact_path: &self.new_artifact_path,
            durable_format_compatible: self.durable_format_compatible,
            epoch_lineage_compatible: self.epoch_lineage_compatible,
        }
    }

    pub(crate) fn issue(
        module_id: String,
        old: Option<&VersionedArtifact>,
        new: &VersionedArtifact,
        evidence: CompatibilityEvidence,
    ) -> Result<Self, OrsError> {
        new.validate()?;
        if let Some(old) = old {
            old.validate()?;
        }
        let mut record = Self {
            module_id,
            old_generation: old.map(|artifact| artifact.generation),
            new_generation: new.generation,
            old_artifact_hash: old.map(|artifact| artifact.artifact_hash.clone()),
            old_artifact_path: old.map(|artifact| artifact.artifact_path.clone()),
            new_artifact_hash: new.artifact_hash.clone(),
            new_artifact_path: new.artifact_path.clone(),
            durable_format_compatible: evidence.durable_format_compatible,
            epoch_lineage_compatible: evidence.epoch_lineage_compatible,
            record_sha256: String::new(),
        };
        record.validate_shape()?;
        let bytes = canonical_json_bytes(&record.core())
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        record.record_sha256 = sha256_hex(&bytes);
        Ok(record)
    }

    fn validate_shape(&self) -> Result<(), OrsError> {
        validate_text(&self.module_id, "artifact_cutover_module_id")?;
        if self.new_generation == 0 {
            return Err(OrsError::InvalidField {
                field: "artifact_cutover_generation",
                reason: "new generation must be non-zero",
            });
        }
        if self.old_generation == Some(self.new_generation) {
            return Err(OrsError::InvalidField {
                field: "artifact_cutover_generation",
                reason: "cutover must select a distinct generation",
            });
        }
        validate_digest(&self.new_artifact_hash, "artifact_cutover_hash")?;
        validate_text(&self.new_artifact_path, "artifact_cutover_path")?;
        if let Some(old_hash) = &self.old_artifact_hash {
            validate_digest(old_hash, "artifact_cutover_old_hash")?;
        }
        if let Some(old_path) = &self.old_artifact_path {
            validate_text(old_path, "artifact_cutover_old_path")?;
        }
        if (self.old_generation.is_none()
            || self.old_artifact_hash.is_none()
            || self.old_artifact_path.is_none())
            && (self.old_generation.is_some()
                || self.old_artifact_hash.is_some()
                || self.old_artifact_path.is_some())
        {
            return Err(OrsError::InvalidField {
                field: "artifact_cutover_old",
                reason: "old generation identity must be fully present or absent",
            });
        }
        if let (Some(old_hash), Some(old_path)) = (&self.old_artifact_hash, &self.old_artifact_path)
            && (old_hash == &self.new_artifact_hash || old_path == &self.new_artifact_path)
        {
            return Err(OrsError::InvalidField {
                field: "artifact_cutover_new",
                reason: "update must produce a distinct versioned artifact path",
            });
        }
        Ok(())
    }

    /// Validates the record shape and its canonical digest.
    pub fn validate(&self) -> Result<(), OrsError> {
        self.validate_shape()?;
        validate_digest(&self.record_sha256, "artifact_cutover_sha256")?;
        let bytes = canonical_json_bytes(&self.core())
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        if sha256_hex(&bytes) != self.record_sha256 {
            return Err(OrsError::PayloadIntegrityMismatch);
        }
        Ok(())
    }
}

/// Typed retirement handoff for the file-deletion consumer.
///
/// Emitted only when a drained generation retires bound to the exact cutover
/// record that demoted it. The Host file owner deletes the named bytes; ORS
/// state no longer tracks them afterwards.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedArtifactRetirement {
    pub module_id: String,
    pub generation: u64,
    pub artifact_hash: String,
    pub artifact_path: String,
    /// Digest of the demoting cutover record this retirement is bound to.
    pub cutover_record_sha256: String,
    /// Always true on emission: only drained generations retire.
    pub drained: bool,
}

impl VersionedArtifactRetirement {
    /// Validates the retirement shape. The cutover binding itself is checked
    /// at emission (`retire_with_receipt`); this rejects malformed carriers.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.module_id, "artifact_retirement_module_id")?;
        if self.generation == 0 {
            return Err(OrsError::InvalidField {
                field: "artifact_retirement_generation",
                reason: "generation must be non-zero",
            });
        }
        validate_digest(&self.artifact_hash, "artifact_retirement_hash")?;
        validate_text(&self.artifact_path, "artifact_retirement_path")?;
        validate_digest(&self.cutover_record_sha256, "artifact_retirement_cutover")?;
        if !self.drained {
            return Err(OrsError::VersionedArtifactNotDrained);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetainedEntry {
    artifact: VersionedArtifact,
    state: ArtifactGenerationState,
    drained: bool,
}

/// Registry/indirection for immutable versioned artifacts (I1.6 + I14.14).
///
/// Activation swaps which generation is `Active`; it never overwrites the
/// bytes at the active path. Prior generations are retained as `Draining`
/// until drained, and only then eligible for `Retired`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VersionedArtifactRegistry {
    staged: BTreeMap<(String, u64), VersionedArtifact>,
    retained: BTreeMap<(String, u64), RetainedEntry>,
}

impl VersionedArtifactRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stages an immutable candidate without touching the active executable.
    ///
    /// Re-staging a retained identical artifact is an idempotent staging for
    /// rollback: the bytes stay where they are and the candidate becomes
    /// activatable again. Anything else that collides with retained or staged
    /// state fails closed.
    pub fn install_candidate(&mut self, artifact: VersionedArtifact) -> Result<(), OrsError> {
        artifact.validate()?;
        let key = (artifact.module_id.clone(), artifact.generation);
        if let Some(existing) = self.staged.get(&key) {
            if *existing == artifact {
                return Ok(());
            }
            return Err(OrsError::VersionedArtifactConflict);
        }
        if let Some(existing) = self.retained.get(&key) {
            if existing.artifact != artifact {
                return Err(OrsError::VersionedArtifactConflict);
            }
            self.staged.insert(key, artifact);
            return Ok(());
        }
        // I1.6 guard: no staged path may collide with a retained executable
        // (active or still-draining) unless it is the identical artifact.
        for entry in self.retained.values() {
            if entry.artifact.artifact_path == artifact.artifact_path && entry.artifact != artifact
            {
                return Err(OrsError::ActiveExecutableReplacement);
            }
        }
        for other in self.staged.values() {
            if other.artifact_path == artifact.artifact_path && *other != artifact {
                return Err(OrsError::VersionedArtifactConflict);
            }
        }
        self.staged.insert(key, artifact);
        Ok(())
    }

    /// Rejects any update targeting the path of an active executable.
    pub fn guard_replacement(&self, target_path: &str) -> Result<(), OrsError> {
        for entry in self.retained.values() {
            if entry.state == ArtifactGenerationState::Active
                && entry.artifact.artifact_path == target_path
            {
                return Err(OrsError::ActiveExecutableReplacement);
            }
        }
        Ok(())
    }

    /// Cuts over to a staged candidate after hash and I1.12 verification.
    ///
    /// The prior active generation is retained as `Draining`; its executable
    /// is left unchanged. Returns the durable cutover evidence binding the
    /// exact old and new hash/path pair.
    pub fn activate(
        &mut self,
        module_id: &str,
        generation: u64,
        candidate_hash: &str,
        evidence: &CompatibilityEvidence,
    ) -> Result<VersionedArtifactCutoverRecord, OrsError> {
        evidence.require()?;
        let key = (module_id.to_owned(), generation);
        let candidate = self
            .staged
            .get(&key)
            .ok_or(OrsError::VersionedArtifactNotFound)?
            .clone();
        candidate.validate()?;
        if candidate.artifact_hash != candidate_hash {
            return Err(OrsError::IncompatibleArtifact);
        }
        self.guard_replacement(&candidate.artifact_path)?;
        let active_key = self
            .retained
            .iter()
            .find(|((module, _), entry)| {
                module == module_id && entry.state == ArtifactGenerationState::Active
            })
            .map(|(key, _)| key.clone());
        if let Some(ref active_key) = active_key {
            let active = self
                .retained
                .get(active_key)
                .ok_or(OrsError::VersionedArtifactNotFound)?;
            if active.artifact.generation == generation
                || active.artifact.artifact_hash == candidate.artifact_hash
                || active.artifact.artifact_path == candidate.artifact_path
            {
                return Err(OrsError::VersionedArtifactConflict);
            }
        }
        let old = active_key.as_ref().and_then(|key| {
            self.retained.get_mut(key).map(|entry| {
                entry.state = ArtifactGenerationState::Draining;
                entry.drained = false;
                entry.artifact.clone()
            })
        });
        self.staged.remove(&key);
        self.retained.insert(
            key,
            RetainedEntry {
                artifact: candidate.clone(),
                state: ArtifactGenerationState::Active,
                drained: false,
            },
        );
        VersionedArtifactCutoverRecord::issue(
            module_id.to_owned(),
            old.as_ref(),
            &candidate,
            *evidence,
        )
    }

    /// Records that one draining generation finished its in-flight work.
    pub fn mark_drained(&mut self, module_id: &str, generation: u64) -> Result<(), OrsError> {
        let entry = self
            .retained
            .get_mut(&(module_id.to_owned(), generation))
            .ok_or(OrsError::VersionedArtifactNotFound)?;
        if entry.state != ArtifactGenerationState::Draining {
            return Err(OrsError::InvalidTransition);
        }
        entry.drained = true;
        Ok(())
    }

    /// Retires a drained generation; fails closed while it still drains.
    pub fn retire(
        &mut self,
        module_id: &str,
        generation: u64,
    ) -> Result<VersionedArtifact, OrsError> {
        let key = (module_id.to_owned(), generation);
        let entry = self
            .retained
            .get(&key)
            .ok_or(OrsError::VersionedArtifactNotFound)?;
        if entry.state == ArtifactGenerationState::Active {
            return Err(OrsError::VersionedArtifactNotDrained);
        }
        if entry.state != ArtifactGenerationState::Draining || !entry.drained {
            return Err(OrsError::VersionedArtifactNotDrained);
        }
        let entry = self
            .retained
            .remove(&key)
            .ok_or(OrsError::VersionedArtifactNotFound)?;
        Ok(entry.artifact)
    }

    /// Retires a drained generation bound to the exact cutover record that
    /// demoted it, returning the typed retirement handoff for the file-deletion
    /// consumer (Host owns artifact bytes; ORS never deletes files).
    ///
    /// The record must validate and name this exact generation, hash, and path
    /// as its demoted side; a mismatched record fails WITHOUT removing the
    /// entry, so a wrong receipt can never silently release bytes.
    pub fn retire_with_receipt(
        &mut self,
        module_id: &str,
        generation: u64,
        record: &VersionedArtifactCutoverRecord,
    ) -> Result<VersionedArtifactRetirement, OrsError> {
        record.validate()?;
        let key = (module_id.to_owned(), generation);
        let entry = self
            .retained
            .get(&key)
            .ok_or(OrsError::VersionedArtifactNotFound)?;
        if record.old_generation != Some(generation)
            || record.old_artifact_hash.as_deref() != Some(entry.artifact.artifact_hash.as_str())
            || record.old_artifact_path.as_deref() != Some(entry.artifact.artifact_path.as_str())
        {
            return Err(OrsError::InvalidField {
                field: "artifact_retirement_cutover",
                reason: "retirement must name the cutover that demoted this generation",
            });
        }
        let artifact = self.retire(module_id, generation)?;
        Ok(VersionedArtifactRetirement {
            module_id: module_id.to_owned(),
            generation: artifact.generation,
            artifact_hash: artifact.artifact_hash,
            artifact_path: artifact.artifact_path,
            cutover_record_sha256: record.record_sha256.clone(),
            drained: true,
        })
    }

    /// Returns the active generation's exact artifact hash and path.
    #[must_use]
    pub fn active_status(&self, module_id: &str) -> Option<VersionedArtifactStatus> {
        self.retained
            .iter()
            .find(|((module, _), entry)| {
                module == module_id && entry.state == ArtifactGenerationState::Active
            })
            .map(|(_, entry)| VersionedArtifactStatus {
                module_id: entry.artifact.module_id.clone(),
                generation: entry.artifact.generation,
                artifact_hash: entry.artifact.artifact_hash.clone(),
                artifact_path: entry.artifact.artifact_path.clone(),
                state: ArtifactGenerationState::Active,
            })
    }

    /// Returns one retained generation and its lifecycle state.
    #[must_use]
    pub fn retained_state(
        &self,
        module_id: &str,
        generation: u64,
    ) -> Option<(VersionedArtifact, ArtifactGenerationState, bool)> {
        self.retained
            .get(&(module_id.to_owned(), generation))
            .map(|entry| (entry.artifact.clone(), entry.state, entry.drained))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "focused acceptance proof uses direct assertions"
)]
mod tests {
    use super::*;

    fn artifact(module: &str, generation: u64, hash: &str) -> VersionedArtifact {
        VersionedArtifact::new(
            module,
            generation,
            hash,
            VersionedArtifact::canonical_path(module, generation, hash),
        )
        .expect("valid fixture artifact")
    }

    const COMPATIBLE: CompatibilityEvidence = CompatibilityEvidence {
        durable_format_compatible: true,
        epoch_lineage_compatible: true,
    };

    #[test]
    fn versioned_update_is_distinct_retains_prior_until_drain_and_rejects_in_place() {
        let hash_gen1 = "aa".repeat(32);
        let hash_gen2 = "bb".repeat(32);
        let mut registry = VersionedArtifactRegistry::new();

        // First generation activates and reports its exact identity.
        registry
            .install_candidate(artifact("mod-research", 1, &hash_gen1))
            .expect("stage gen1");
        let first = registry
            .activate("mod-research", 1, &hash_gen1, &COMPATIBLE)
            .expect("activate gen1");
        first.validate().expect("cutover evidence validates");
        let active = registry
            .active_status("mod-research")
            .expect("active status present");
        assert_eq!(active.generation, 1);
        assert_eq!(active.artifact_hash, hash_gen1);

        // Updating the active module produces a distinct versioned path and
        // leaves the prior executable retained as draining.
        registry
            .install_candidate(artifact("mod-research", 2, &hash_gen2))
            .expect("stage gen2");
        let cutover = registry
            .activate("mod-research", 2, &hash_gen2, &COMPATIBLE)
            .expect("activate gen2");
        cutover.validate().expect("cutover evidence validates");
        assert_eq!(cutover.new_artifact_hash, hash_gen2);
        assert_eq!(
            cutover.old_artifact_hash.as_deref(),
            Some(hash_gen1.as_str())
        );
        assert_ne!(
            cutover.new_artifact_path,
            cutover.old_artifact_path.unwrap()
        );
        let active = registry
            .active_status("mod-research")
            .expect("active status present");
        assert_eq!(active.generation, 2);
        assert_eq!(active.artifact_hash, hash_gen2);
        let (prior, state, drained) = registry
            .retained_state("mod-research", 1)
            .expect("prior generation retained");
        assert_eq!(state, ArtifactGenerationState::Draining);
        assert!(!drained);
        assert_eq!(prior.artifact_hash, hash_gen1);

        // In-place replacement of the running generation is rejected: the
        // active path is guarded, and re-staging the active generation
        // identity with different bytes conflicts instead of overwriting.
        let active_path = active.artifact_path.clone();
        assert!(matches!(
            registry.guard_replacement(&active_path),
            Err(OrsError::ActiveExecutableReplacement)
        ));
        let overwrite = VersionedArtifact::new(
            "mod-research",
            2,
            "cc".repeat(32),
            VersionedArtifact::canonical_path("mod-research", 2, &"cc".repeat(32)),
        )
        .expect("addressed overwrite fixture");
        assert!(matches!(
            registry.install_candidate(overwrite),
            Err(OrsError::VersionedArtifactConflict)
        ));

        // The prior generation cannot retire while it still drains.
        assert!(matches!(
            registry.retire("mod-research", 1),
            Err(OrsError::VersionedArtifactNotDrained)
        ));
        registry
            .mark_drained("mod-research", 1)
            .expect("drain prior generation");
        let retired = registry.retire("mod-research", 1).expect("retire drained");
        assert_eq!(retired.artifact_hash, hash_gen1);

        // I1.12: incompatible candidates never cut over.
        registry
            .install_candidate(artifact("mod-research", 4, &"dd".repeat(32)))
            .expect("stage gen4");
        assert!(matches!(
            registry.activate(
                "mod-research",
                4,
                &"dd".repeat(32),
                &CompatibilityEvidence {
                    durable_format_compatible: false,
                    epoch_lineage_compatible: true,
                },
            ),
            Err(OrsError::IncompatibleArtifact)
        ));
    }

    #[test]
    fn non_canonical_generation_paths_are_rejected() {
        // Generation substring: generation 1 must not validate at a
        // generation 10 path even though "1" is a substring of "10".
        let hash = "aa".repeat(32);
        assert!(
            VersionedArtifact::new(
                "mod-echo",
                1,
                hash.clone(),
                format!("modules/mod-echo/10/{hash}/module.exe")
            )
            .is_err()
        );
        // Suffix copy: the addressed bytes plus extra material are not the
        // canonical identity the record names.
        assert!(
            VersionedArtifact::new(
                "mod-echo",
                1,
                hash.clone(),
                format!("modules/mod-echo/1/{hash}/module.exe.bak"),
            )
            .is_err()
        );
        // Wrong module directory with matching generation and hash.
        assert!(
            VersionedArtifact::new(
                "mod-echo",
                1,
                hash.clone(),
                format!("modules/mod-other/1/{hash}/module.exe"),
            )
            .is_err()
        );
        // A different hash at the addressed path is not the named artifact.
        assert!(
            VersionedArtifact::new(
                "mod-echo",
                1,
                hash.clone(),
                VersionedArtifact::canonical_path("mod-echo", 1, &"bb".repeat(32)),
            )
            .is_err()
        );
        // The exact canonical layout still validates.
        artifact("mod-echo", 1, &hash)
            .validate()
            .expect("canonical path must validate");
    }

    #[test]
    fn rollback_to_drained_prior_reactivates_with_compatibility() {
        let hash_gen1 = "aa".repeat(32);
        let hash_gen2 = "bb".repeat(32);
        let mut registry = VersionedArtifactRegistry::new();
        registry
            .install_candidate(artifact("mod-engine", 1, &hash_gen1))
            .expect("stage gen1");
        registry
            .activate("mod-engine", 1, &hash_gen1, &COMPATIBLE)
            .expect("activate gen1");
        registry
            .install_candidate(artifact("mod-engine", 2, &hash_gen2))
            .expect("stage gen2");
        registry
            .activate("mod-engine", 2, &hash_gen2, &COMPATIBLE)
            .expect("activate gen2");
        assert_eq!(
            registry
                .active_status("mod-engine")
                .expect("active status present")
                .generation,
            2
        );
        // Rollback re-stages the retained identical prior and reactivates it:
        // the prior generation was never overwritten, only demoted.
        registry
            .install_candidate(artifact("mod-engine", 1, &hash_gen1))
            .expect("re-stage drained gen1");
        let rollback = registry
            .activate("mod-engine", 1, &hash_gen1, &COMPATIBLE)
            .expect("rollback to gen1");
        rollback.validate().expect("rollback evidence validates");
        assert_eq!(rollback.new_generation, 1);
        assert_eq!(rollback.old_generation, Some(2));
        assert_eq!(rollback.new_artifact_hash, hash_gen1);
        assert_eq!(
            rollback.old_artifact_hash.as_deref(),
            Some(hash_gen2.as_str())
        );
        assert_eq!(
            registry
                .active_status("mod-engine")
                .expect("active status present")
                .generation,
            1
        );
        let (_, state, _) = registry
            .retained_state("mod-engine", 2)
            .expect("gen2 retained");
        assert_eq!(state, ArtifactGenerationState::Draining);
        // An incompatible rollback attempt refuses and preserves the active
        // generation exactly: no partial state change.
        assert!(matches!(
            registry.activate(
                "mod-engine",
                2,
                &hash_gen2,
                &CompatibilityEvidence {
                    durable_format_compatible: true,
                    epoch_lineage_compatible: false,
                },
            ),
            Err(OrsError::IncompatibleArtifact)
        ));
        assert_eq!(
            registry
                .active_status("mod-engine")
                .expect("active status present")
                .generation,
            1
        );
    }

    fn two_generation_registry() -> (VersionedArtifactRegistry, VersionedArtifactCutoverRecord) {
        let hash_gen1 = "aa".repeat(32);
        let hash_gen2 = "bb".repeat(32);
        let mut registry = VersionedArtifactRegistry::new();
        registry
            .install_candidate(artifact("mod-sweeper", 1, &hash_gen1))
            .expect("stage gen1");
        registry
            .activate("mod-sweeper", 1, &hash_gen1, &COMPATIBLE)
            .expect("activate gen1");
        registry
            .install_candidate(artifact("mod-sweeper", 2, &hash_gen2))
            .expect("stage gen2");
        let cutover = registry
            .activate("mod-sweeper", 2, &hash_gen2, &COMPATIBLE)
            .expect("activate gen2");
        (registry, cutover)
    }

    #[test]
    fn retire_with_receipt_releases_only_cutover_bound_drained_generations() {
        let (mut registry, cutover) = two_generation_registry();
        // Still draining without the drained mark: no receipt, entry kept.
        assert!(matches!(
            registry.retire_with_receipt("mod-sweeper", 1, &cutover),
            Err(OrsError::VersionedArtifactNotDrained)
        ));
        assert!(registry.retained_state("mod-sweeper", 1).is_some());
        registry
            .mark_drained("mod-sweeper", 1)
            .expect("drain prior generation");
        let retirement = registry
            .retire_with_receipt("mod-sweeper", 1, &cutover)
            .expect("retire drained with receipt");
        retirement.validate().expect("retirement handoff validates");
        assert_eq!(retirement.generation, 1);
        assert_eq!(retirement.artifact_hash, "aa".repeat(32));
        assert_eq!(retirement.cutover_record_sha256, cutover.record_sha256);
        assert!(retirement.drained);
        // The bytes are released exactly once: the entry is gone afterwards.
        assert!(registry.retained_state("mod-sweeper", 1).is_none());
        // The active generation still reports its exact identity.
        let active = registry
            .active_status("mod-sweeper")
            .expect("active status present");
        assert_eq!(active.generation, 2);
    }

    #[test]
    fn retire_with_receipt_rejects_foreign_cutover_without_removal() {
        let (mut registry, _) = two_generation_registry();
        registry
            .mark_drained("mod-sweeper", 1)
            .expect("drain prior generation");
        // A well-formed cutover record from another lineage names different
        // hashes: it must not release these bytes.
        let (_, foreign_cutover) = (|| {
            let hash_a = "cc".repeat(32);
            let hash_b = "dd".repeat(32);
            let mut other = VersionedArtifactRegistry::new();
            other
                .install_candidate(artifact("mod-sweeper", 1, &hash_a))
                .expect("stage gen1");
            other
                .activate("mod-sweeper", 1, &hash_a, &COMPATIBLE)
                .expect("activate gen1");
            other
                .install_candidate(artifact("mod-sweeper", 2, &hash_b))
                .expect("stage gen2");
            let cutover = other
                .activate("mod-sweeper", 2, &hash_b, &COMPATIBLE)
                .expect("activate gen2");
            (other, cutover)
        })();
        assert!(
            registry
                .retire_with_receipt("mod-sweeper", 1, &foreign_cutover)
                .is_err()
        );
        assert!(registry.retained_state("mod-sweeper", 1).is_some());
        // Retiring the active generation itself is rejected (no cutover can
        // name an active generation as demoted) and the active entry survives.
        let (_, own_cutover) = two_generation_registry();
        assert!(
            registry
                .retire_with_receipt("mod-sweeper", 2, &own_cutover)
                .is_err()
        );
        assert_eq!(
            registry
                .active_status("mod-sweeper")
                .expect("active status present")
                .generation,
            2
        );
    }
}
