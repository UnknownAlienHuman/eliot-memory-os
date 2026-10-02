//! The declared retention policy set: the I3.11 `retention_and_backup_policy`
//! value that the schedule owner attests.
//!
//! I3.11 declares `retention_and_backup_policy:` in the `WorkScope` Profile, and
//! I3.9 fixes the layers that may carry it (`System Owner policy`,
//! `WorkScope Profile`) under one rule: "Lower layers may narrow authority,
//! privacy, cost or effects. They cannot expand a higher boundary unless the
//! higher layer explicitly delegates expansion." A retention policy ref is a
//! privacy/effect boundary, so this module implements exactly that rule over a
//! ref vocabulary instead of a numeric limit: the compiled vocabulary is the
//! broadest layer and the ceiling, and a narrower layer may only select a
//! subset of it. A ref vocabulary has no interval to delegate, so an undeclared
//! ref is refused rather than delegated.
//!
//! I3.10:62 ("destructive retention changes require the role that owns that
//! boundary") is why this set is admitted immutable configuration content and
//! never a caller-supplied list: the owner that holds the policy snapshot is the
//! only place the declared refs exist.
//!
//! The set is never empty. An empty attestation would make every
//! `resolve_retention_read` return `ExperienceRetentionReadPosture::UnknownPolicy`,
//! which is an always-refusing issuer rather than a policy, so both the narrowing
//! rule and the declaration refuse it here instead of publishing it.

use crate::{ConfigError, ConfigPolicySnapshot, non_blank};

/// The I3.11 `WorkScope` Profile field that declares retention and backup policy.
///
/// Every declared retention policy is admitted as one immutable
/// [`Setting`](crate::Setting) whose key is this field name, `.`, and the
/// policy ref, so a policy set is a set of typed setting rows with an owner
/// each, never one opaque blob.
pub const RETENTION_POLICY_SETTING_KEY: &str = "retention_and_backup_policy";

/// Separator between [`RETENTION_POLICY_SETTING_KEY`] and a declared policy ref.
const RETENTION_POLICY_SETTING_KEY_SEPARATOR: char = '.';

/// Bounded ceiling on one declared policy set.
pub const MAX_DECLARED_RETENTION_POLICY_REFS: usize = 16;

/// The I3.9 broadest layer's declared retention vocabulary.
///
/// This is a declaration, not a default discovered at runtime: it is the only
/// vocabulary any narrower layer may select from, and it is the set a snapshot
/// that declares nothing under [`RETENTION_POLICY_SETTING_KEY`] carries
/// forward, because an abstaining layer leaves the running value in place.
///
/// The one ref is the retention policy the Governor's own self-observation
/// admission already carries on its production path
/// (`observation_reconciliation.rs:369`, the verified-repair observation leg).
/// It is used here because it is the real ref the governed self-scope family
/// emits, not because it reads well: a compiled vocabulary that named no
/// production ref would attest nothing and make every retention-gated read
/// refuse, and a vocabulary that named a ref no producer emits would attest a
/// policy nothing is under. The `MaintenanceRecord` family's own derived identity
/// (`eliot.governor.maintenance:1.0.0`) is deliberately not reused here: it is
/// that family's contract ref, and one family's ref is not another family's
/// retention policy.
pub const COMPILED_SAFE_DEFAULT_RETENTION_POLICY_REFS: [&str; 1] = ["governor-retention"];

/// Returns the compiled safe default set as owned refs.
#[must_use]
pub fn compiled_default_retention_policy_refs() -> Vec<String> {
    COMPILED_SAFE_DEFAULT_RETENTION_POLICY_REFS
        .iter()
        .map(|policy_ref| (*policy_ref).to_owned())
        .collect()
}

/// Returns the immutable setting key that declares exactly one policy ref.
#[must_use]
pub fn retention_policy_setting_key(policy_ref: &str) -> String {
    format!("{RETENTION_POLICY_SETTING_KEY}{RETENTION_POLICY_SETTING_KEY_SEPARATOR}{policy_ref}")
}

/// Returns the retention policy ref a setting key declares.
///
/// `None` for every key that declares something other than one retention
/// policy, including the bare field name: a key must name the ref it declares,
/// so an unresolvable declaration is absence, never an empty ref.
#[must_use]
pub fn declared_retention_policy_ref(key: &str) -> Option<&str> {
    key.strip_prefix(RETENTION_POLICY_SETTING_KEY)?
        .strip_prefix(RETENTION_POLICY_SETTING_KEY_SEPARATOR)
}

/// Narrows a running retention policy set to a narrower layer's declared set.
///
/// I3.9:15 — a lower layer may narrow and may not expand. Every requested ref
/// must already be named by `running`; there is no delegation for a ref
/// vocabulary, so a ref outside the running set is refused instead of granted.
///
/// # Errors
///
/// Returns [`ConfigError::EmptyRetentionPolicySet`] when the requested set
/// declares no ref, [`ConfigError::TooManyRetentionPolicyRefs`] when it exceeds
/// [`MAX_DECLARED_RETENTION_POLICY_REFS`],
/// [`ConfigError::DuplicateRetentionPolicy`] when a ref is declared twice, and
/// [`ConfigError::UndeclaredRetentionPolicy`] when a ref is not in the running
/// set.
pub fn narrow_retention_policy_refs(
    running: &[String],
    requested: &[String],
) -> Result<Vec<String>, ConfigError> {
    if requested.is_empty() {
        return Err(ConfigError::EmptyRetentionPolicySet);
    }
    if requested.len() > MAX_DECLARED_RETENTION_POLICY_REFS {
        return Err(ConfigError::TooManyRetentionPolicyRefs {
            max: MAX_DECLARED_RETENTION_POLICY_REFS,
        });
    }
    let mut narrowed: Vec<String> = Vec::with_capacity(requested.len());
    for policy_ref in requested {
        if !running.iter().any(|known| known == policy_ref) {
            return Err(ConfigError::UndeclaredRetentionPolicy {
                policy_ref: policy_ref.clone(),
            });
        }
        if narrowed.iter().any(|seen| seen == policy_ref) {
            return Err(ConfigError::DuplicateRetentionPolicy {
                policy_ref: policy_ref.clone(),
            });
        }
        narrowed.push(policy_ref.clone());
    }
    Ok(narrowed)
}

/// The retention policy refs one admitted snapshot declares.
///
/// Every setting whose key declares a policy ref is read; each declared ref must
/// narrow the compiled vocabulary. A snapshot that declares none abstains, so it
/// carries the compiled safe default forward rather than an empty set.
///
/// # Errors
///
/// Returns [`ConfigError`] when a declared key names a blank or control-bearing
/// ref, a declared row has no `value_ref` to admit, or a declared ref does not
/// narrow the compiled vocabulary.
pub fn declared_retention_policy_refs(
    snapshot: &ConfigPolicySnapshot,
) -> Result<Vec<String>, ConfigError> {
    let mut declared: Vec<String> = Vec::new();
    for setting in &snapshot.settings {
        let Some(policy_ref) = declared_retention_policy_ref(&setting.key) else {
            continue;
        };
        non_blank(policy_ref, "retention_policy_ref")?;
        // The row must be an admitted setting, not a bare key: its `value_ref` and
        // `owner_ref` are the admitted reference and owning role for this policy.
        non_blank(&setting.value_ref, "setting.value_ref")?;
        non_blank(&setting.owner_ref, "setting.owner_ref")?;
        declared.push(policy_ref.to_owned());
    }
    if declared.is_empty() {
        return Ok(compiled_default_retention_policy_refs());
    }
    narrow_retention_policy_refs(&compiled_default_retention_policy_refs(), &declared)
}
