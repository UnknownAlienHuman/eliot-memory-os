//! Closed input-bundle schemas for provider-neutral Dreamer jobs.
//!
//! Cell `smart.dreamer.contracts`. Owns exact bundle, material and omission
//! shapes plus intrinsic wrapper/identity/bounds validation. Owns no bundle
//! assembly, fetching, grounding or validation behavior: those belong to the
//! A-04/A-05 composition that consumes these contracts.
//!
//! Job (`crate::job::DreamJobInput`) and budget (`crate::budget`) shapes live
//! in sibling modules and are never redefined here.

#![forbid(unsafe_code)]

use eliot_contracts::StateFence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ContractViolation, check_text};

/// Exact bundle schema version accepted by [`DreamInputBundle::validate`].
const BUNDLE_SCHEMA_VERSION: u32 = 1;
/// Maximum handle length, measured in bytes (`check_text` bound).
const MAX_HANDLE_CHARS: usize = 128;
/// Maximum materials accepted in one bundle.
const MAX_MATERIALS: usize = 1024;

/// Returns true when `value` is exactly 64 lowercase-or-uppercase hex digits.
fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Rejects blank/over-long/control handles (128-byte `check_text` bound).
fn check_handle(handle: &str) -> Result<(), ContractViolation> {
    check_text(handle, "handle", MAX_HANDLE_CHARS)
}

/// Maps a fence validation failure onto the closed contract error.
fn fence_error(err: &eliot_contracts::ContractError) -> ContractViolation {
    ContractViolation::BindingMismatch {
        field: "state_fence",
        reason: err.to_string(),
    }
}

/// Disposition of one bundle source on the closed wire spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceDisposition {
    /// Source must be present for the scope to count as complete.
    Required,
    /// Source may be absent without blocking completeness.
    Optional,
    /// Source is required only when its entry condition holds.
    Conditional,
    /// Source is explicitly excluded from this scope.
    Excluded,
}

/// Distinct terminal states of bundle-source availability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BundleStatus {
    /// Every required source is present.
    Complete,
    /// Some sources are present and the remainder are accounted omissions.
    Partial,
    /// The scope is known to have no sources at all.
    KnownEmpty,
    /// Assembly is blocked and cannot proceed yet.
    Blocked,
    /// The bundle snapshot is no longer current.
    Stale,
    /// No bundle snapshot could be produced.
    Unavailable,
    /// Assembly stopped because an independent budget dimension is exhausted.
    BudgetExhausted,
}

/// One material entry carried by a [`DreamInputBundle`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BundleMaterial {
    /// Opaque source handle, non-blank, at most 128 characters.
    pub handle: String,
    /// Why this source is (or is not) needed for the scope.
    pub disposition: SourceDisposition,
    /// Material size in bytes.
    pub bytes: u64,
    /// Lowercase SHA-256 digest of the canonical material bytes (64 hex).
    pub digest: String,
}

impl BundleMaterial {
    /// Validates intrinsic handle and digest bounds.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_handle(&self.handle)?;
        if !is_hex64(&self.digest) {
            return Err(ContractViolation::BindingMismatch {
                field: "material_digest",
                reason: "material digest must be 64 hex characters".to_string(),
            });
        }
        Ok(())
    }
}

/// Accounted omission of one bundle source.
///
/// An omission is either reversible (the source can still be fetched, so no
/// further justification is needed) or explicitly nonrecoverable (and then it
/// must carry the reason why recovery is impossible).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OmissionHandle {
    /// Opaque handle of the omitted source.
    pub handle: String,
    /// Human-readable reason for the omission.
    pub reason: String,
    /// True when the source can still be fetched on demand.
    pub reversible: bool,
    /// Scope this omission is bound to; must equal the bundle scope.
    pub scope_id: String,
    /// Task this omission is bound to; must equal the bundle task.
    pub task_id: String,
    /// Digest binding the omission record.
    pub digest: String,
    /// Required exactly when `reversible` is false: why recovery is impossible.
    pub nonrecoverable_reason: Option<String>,
}

impl OmissionHandle {
    /// Validates intrinsic bounds (identities 256B, reason/digest 1024B/256B) plus reversible-or-explicit rule.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_handle(&self.handle)?;
        check_text(&self.reason, "reason", 1024)?;
        check_text(&self.scope_id, "scope_id", 256)?;
        check_text(&self.task_id, "task_id", 256)?;
        check_text(&self.digest, "digest", 1024)?;
        if let Some(reason) = &self.nonrecoverable_reason {
            check_text(reason, "nonrecoverable_reason", 1024)?;
        }
        let reason_ok = self
            .nonrecoverable_reason
            .as_ref()
            .is_some_and(|reason| !reason.trim().is_empty());
        if !self.reversible && !reason_ok {
            return Err(ContractViolation::BindingMismatch {
                field: "nonrecoverable_reason",
                reason: "irreversible omission requires an explicit nonrecoverable reason"
                    .to_string(),
            });
        }
        Ok(())
    }
}

/// Completeness claim a [`DreamInputBundle`] makes about its scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BundleCompleteness {
    /// The bundle covers the whole scope; needs an authoritative denominator.
    CompleteForScope,
    /// The bundle covers part of the scope; the rest are accounted omissions.
    PartialForScope,
    /// The scope is known empty; needs an authoritative denominator.
    KnownEmpty,
    /// Completeness is not established by this bundle.
    Unknown,
}

/// Closed bundle of grounded input material for one Dreamer job.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamInputBundle {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Owning job identity.
    pub job_id: String,
    /// Scope this bundle covers.
    pub scope_id: String,
    /// Task this bundle is bound to.
    pub task_id: String,
    /// State fence captured before bundle assembly.
    pub state_fence: StateFence,
    /// SHA-256 of the canonical source manifest (64 hex).
    pub manifest_digest: String,
    /// Carried materials, at most 1024 entries.
    pub materials: Vec<BundleMaterial>,
    /// Accounted omissions for sources not carried as materials.
    pub omissions: Vec<OmissionHandle>,
    /// Completeness claim about the scope.
    pub completeness: BundleCompleteness,
    /// Exact denominator backing a complete/known-empty claim.
    pub authoritative_denominator: Option<String>,
}

impl DreamInputBundle {
    /// Validates intrinsic bounds, bindings and completeness rules.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if self.schema_version != BUNDLE_SCHEMA_VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "schema_version",
                min: 1,
                max: 1,
                got: i64::from(self.schema_version),
            });
        }
        check_text(&self.job_id, "job_id", 256)?;
        check_text(&self.scope_id, "scope_id", 256)?;
        check_text(&self.task_id, "task_id", 256)?;
        self.state_fence
            .validate()
            .map_err(|err| fence_error(&err))?;
        if !is_hex64(&self.manifest_digest) {
            return Err(ContractViolation::BindingMismatch {
                field: "manifest_digest",
                reason: "manifest digest must be 64 hex characters".to_string(),
            });
        }
        if self.materials.len() > MAX_MATERIALS {
            return Err(ContractViolation::OutOfBounds {
                field: "materials",
                min: 0,
                max: crate::error::len_i64(MAX_MATERIALS),
                got: crate::error::len_i64(self.materials.len()),
            });
        }
        for material in &self.materials {
            material.validate()?;
        }
        for omission in &self.omissions {
            omission.validate()?;
            if omission.scope_id != self.scope_id {
                return Err(ContractViolation::BindingMismatch {
                    field: "scope_id",
                    reason: "omission scope binding mismatch".to_string(),
                });
            }
            if omission.task_id != self.task_id {
                return Err(ContractViolation::BindingMismatch {
                    field: "task_id",
                    reason: "omission task binding mismatch".to_string(),
                });
            }
        }
        let mut seen: Vec<&str> = Vec::new();
        for handle in self
            .materials
            .iter()
            .map(|material| material.handle.as_str())
            .chain(
                self.omissions
                    .iter()
                    .map(|omission| omission.handle.as_str()),
            )
        {
            if seen.contains(&handle) {
                return Err(ContractViolation::BindingMismatch {
                    field: "handle",
                    reason: "duplicate bundle handle".to_string(),
                });
            }
            seen.push(handle);
        }
        match self.completeness {
            BundleCompleteness::CompleteForScope | BundleCompleteness::KnownEmpty => {
                match &self.authoritative_denominator {
                    Some(d) => check_text(d, "authoritative_denominator", 256)?,
                    None => {
                        return Err(ContractViolation::MissingField("authoritative_denominator"));
                    }
                }
            }
            BundleCompleteness::PartialForScope | BundleCompleteness::Unknown => {
                if let Some(d) = &self.authoritative_denominator {
                    check_text(d, "authoritative_denominator", 256)?;
                }
            }
        }
        Ok(())
    }
}

/// Finds the accounted omission for `handle`, or fails when it is not omitted.
pub fn omit_handle(
    bundle: &DreamInputBundle,
    handle: &str,
) -> Result<OmissionHandle, ContractViolation> {
    bundle
        .omissions
        .iter()
        .find(|omission| omission.handle == handle)
        .cloned()
        .ok_or_else(|| ContractViolation::BindingMismatch {
            field: "handle",
            reason: "no accounted omission for handle".to_string(),
        })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration, sha256_hex};

    fn valid_fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }

    fn valid_omission() -> OmissionHandle {
        OmissionHandle {
            handle: "source-b".to_string(),
            reason: "upstream unavailable".to_string(),
            reversible: true,
            scope_id: "scope-1".to_string(),
            task_id: "task-1".to_string(),
            digest: sha256_hex(b"omission-b"),
            nonrecoverable_reason: None,
        }
    }

    fn valid_bundle() -> DreamInputBundle {
        DreamInputBundle {
            schema_version: 1,
            job_id: "job-1".to_string(),
            scope_id: "scope-1".to_string(),
            task_id: "task-1".to_string(),
            state_fence: valid_fence(),
            manifest_digest: sha256_hex(b"manifest"),
            materials: vec![BundleMaterial {
                handle: "source-a".to_string(),
                disposition: SourceDisposition::Required,
                bytes: 12,
                digest: sha256_hex(b"source-a"),
            }],
            omissions: vec![valid_omission()],
            completeness: BundleCompleteness::PartialForScope,
            authoritative_denominator: None,
        }
    }

    // WORK_UNIT_CASE: 578/8
    #[test]
    fn bundle_rejects_bad_manifest_tampered_scope_and_invalid_fence() {
        // Wrong manifest: non-hex digest is rejected.
        let mut bad_manifest = valid_bundle();
        bad_manifest.manifest_digest = "not-a-digest".to_string();
        assert!(matches!(
            bad_manifest.validate(),
            Err(ContractViolation::BindingMismatch { .. })
        ));

        // Tampered scope: bundle scope no longer matches the omission binding.
        let mut tampered_scope = valid_bundle();
        tampered_scope.scope_id = "scope-2".to_string();
        assert!(tampered_scope.validate().is_err());

        // Tampered task: same binding rule guards the task identity.
        let mut tampered_task = valid_bundle();
        tampered_task.task_id = "task-2".to_string();
        assert!(tampered_task.validate().is_err());

        // Wrong source: blank material handle is rejected.
        let mut blank_handle = valid_bundle();
        blank_handle.materials[0].handle = "   ".to_string();
        assert!(blank_handle.validate().is_err());

        // Wrong source: corrupt material digest is rejected.
        let mut corrupt_digest = valid_bundle();
        corrupt_digest.materials[0].digest = "z".repeat(64);
        assert!(corrupt_digest.validate().is_err());

        // Duplicate handles across materials and omissions are rejected.
        let mut duplicate = valid_bundle();
        duplicate.omissions[0].handle = "source-a".to_string();
        assert!(duplicate.validate().is_err());

        // Invalid fence: epoch zero cannot cross the deserialization boundary,
        // so no bundle carrying it can ever validate.
        let fence_json = r#"{"authority_epoch":0,"resource_generation":1}"#;
        assert!(serde_json::from_str::<StateFence>(fence_json).is_err());

        // Same rejection holds at the full-bundle boundary.
        let wire = serde_json::to_string(&valid_bundle()).expect("fixture serializes");
        assert!(wire.contains("\"authority_epoch\":1"));
        let tampered = wire.replace("\"authority_epoch\":1", "\"authority_epoch\":0");
        assert!(tampered.contains("\"authority_epoch\":0"));
        assert!(serde_json::from_str::<DreamInputBundle>(&tampered).is_err());
        let mut over_handle = valid_bundle();
        over_handle.materials[0].handle = "h".repeat(129);
        assert!(over_handle.validate().is_err());
        let mut ctrl_handle = valid_bundle();
        ctrl_handle.materials[0].handle = "a\tb".to_string();
        assert!(ctrl_handle.validate().is_err());
        let mut over_id = valid_bundle();
        over_id.job_id = "j".repeat(257);
        assert!(over_id.validate().is_err());
    }

    // WORK_UNIT_CASE: 578/13
    #[test]
    fn valid_complete_bundle_roundtrips_exact_denominator() {
        let mut bundle = valid_bundle();
        bundle.completeness = BundleCompleteness::CompleteForScope;
        bundle.authoritative_denominator = Some("scope-1:2-of-2".to_string());
        assert!(bundle.validate().is_ok());

        let wire = serde_json::to_string(&bundle).expect("fixture serializes");
        let back: DreamInputBundle = serde_json::from_str(&wire).expect("fixture deserializes");
        assert!(back.validate().is_ok());
        assert_eq!(back, bundle);
        assert_eq!(
            back.authoritative_denominator.as_deref(),
            Some("scope-1:2-of-2")
        );
        let mut maxed = valid_bundle();
        maxed.materials[0].handle = "h".repeat(128);
        maxed.authoritative_denominator = Some("d".repeat(256));
        maxed.completeness = BundleCompleteness::CompleteForScope;
        assert!(maxed.validate().is_ok());
    }

    // WORK_UNIT_CASE: 578/14
    #[test]
    fn bundle_status_variants_are_distinct_and_roundtrip() {
        let variants = [
            BundleStatus::Complete,
            BundleStatus::Partial,
            BundleStatus::KnownEmpty,
            BundleStatus::Blocked,
            BundleStatus::Stale,
            BundleStatus::Unavailable,
            BundleStatus::BudgetExhausted,
        ];
        for (index, first) in variants.iter().enumerate() {
            for second in &variants[index + 1..] {
                assert_ne!(first, second);
            }
        }
        let mut wires: Vec<String> = Vec::new();
        for status in variants {
            let wire = serde_json::to_string(&status).expect("status serializes");
            let back: BundleStatus = serde_json::from_str(&wire).expect("status deserializes");
            assert_eq!(back, status);
            wires.push(wire);
        }
        wires.sort();
        wires.dedup();
        assert_eq!(wires.len(), variants.len());
    }

    // WORK_UNIT_CASE: 578/15
    #[test]
    fn complete_and_known_empty_require_authoritative_denominator() {
        let mut complete = valid_bundle();
        complete.completeness = BundleCompleteness::CompleteForScope;
        complete.authoritative_denominator = None;
        assert!(matches!(
            complete.validate(),
            Err(ContractViolation::MissingField("authoritative_denominator"))
        ));
        complete.authoritative_denominator = Some("scope-1:2-of-2".to_string());
        assert!(complete.validate().is_ok());

        let mut empty = valid_bundle();
        empty.materials.clear();
        empty.omissions.clear();
        empty.completeness = BundleCompleteness::KnownEmpty;
        empty.authoritative_denominator = None;
        assert!(empty.validate().is_err());
        empty.authoritative_denominator = Some("scope-1:empty".to_string());
        assert!(empty.validate().is_ok());

        assert!(valid_bundle().validate().is_ok());
    }

    // WORK_UNIT_CASE: 578/16
    #[test]
    fn omission_handle_requires_reversible_or_explicit_nonrecoverable() {
        let mut reversible = valid_omission();
        reversible.reversible = true;
        reversible.nonrecoverable_reason = None;
        assert!(reversible.validate().is_ok());

        let mut nonrecoverable = valid_omission();
        nonrecoverable.reversible = false;
        nonrecoverable.nonrecoverable_reason =
            Some("source retired; re-query impossible".to_string());
        assert!(nonrecoverable.validate().is_ok());

        let mut missing_reason = valid_omission();
        missing_reason.reversible = false;
        missing_reason.nonrecoverable_reason = None;
        assert!(matches!(
            missing_reason.validate(),
            Err(ContractViolation::BindingMismatch { .. })
        ));

        missing_reason.nonrecoverable_reason = Some("  ".to_string());
        assert!(missing_reason.validate().is_err());

        // The lookup helper resolves a recorded omission and fails otherwise.
        let bundle = valid_bundle();
        assert_eq!(
            omit_handle(&bundle, "source-b")
                .expect("omission present")
                .handle,
            "source-b"
        );
        assert!(omit_handle(&bundle, "source-a").is_err());
        assert!(omit_handle(&bundle, "no-such-source").is_err());
    }
}
