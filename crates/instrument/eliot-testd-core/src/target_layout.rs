//! Workspace/checkout/build-class binding of governed output roots.
//!
//! Issue #1806: this module is the narrow layout provider that binds one
//! owner-issued `(workspace, checkout, build class)` identity to the exact
//! external output root a governed launch may use. Derivation is pure and
//! deterministic — the same admitted inputs always resolve to the same root,
//! across restarts, with no ambient directories, no randomness, and no fresh
//! directory per request.
//!
//! The provider extends the existing [`TargetRoots`](super::TargetRoots)
//! authority; it never replaces it. [`verify_layout_binding`] reuses the
//! physical-owner path validation (`validate_root_identity`, reparse
//! refusal, canonical comparison, strict-descendant proof) and the full
//! [`TargetRoots::validate`](super::TargetRoots::validate) gate, so D0
//! `cache_root == target_root`, source disjointness, and the external
//! contour requirement hold unchanged for every bound root.
//!
//! Identity model (revision 1):
//!
//! * `workspace_id` / `checkout_id` are validated safe path components:
//!   lowercase `[a-z0-9-]`, bounded length, never a Windows reserved device
//!   name. Distinct valid identities therefore cannot alias one mutable
//!   root through separators, traversal, dot segments, or case folding.
//! * Registered owner identities (for example a Governor-issued
//!   `WorkspaceInstance` reference) arrive through
//!   [`TargetLayoutBinding::new`], which validates them strictly and refuses
//!   anything else with a typed error.
//! * Opaque owner material (an opaque project identity, a canonical source
//!   root) arrives through [`TargetLayoutBinding::derive_workspace_component`]
//!   and [`TargetLayoutBinding::derive_checkout_component`], which derive
//!   stable collision-resistant components. The derivation table is fixed by
//!   [`TARGET_LAYOUT_REVISION`](eliot_instrument_api::TARGET_LAYOUT_REVISION);
//!   a new table ships as a new revision with an explicit migration, never
//!   by silently reinterpreting revision-1 components.
//!
//! Cross-job exclusion is not inferred here: within one mutable root the
//! existing lease/claim owner serializes producers, exact-fingerprint
//! waiters reuse only verified artifact evidence, and
//! [`bound_roots_conflict`] lets a future scheduler detect two distinct
//! bindings aliasing one root. Cleanup stays with the existing owner;
//! selection never globally cleans a target directory to repair identity,
//! and a missing safe root is a typed refusal, never a repository
//! `target/` fallback.
//!
//! Root authority for a governed lane (issue #1897).
//!
//! `TargetRoots::validate` owns the one cache/target relation —
//! `cache_root == target_root` — and nothing here weakens or restates it. The
//! process environment resolver
//! ([`super::TestdProcessToolIntent::validate_for_roots`]) and the governed
//! Cargo environment
//! ([`GovernedWorkEnvelope::cargo_environment`]) both bind the same directory,
//! so the relation is one relation on all three surfaces.
//!
//! Two root authorities exist, and they are NOT reconciled into one derivation
//! today:
//!
//! * the pre-lane layout resolver [`derive_layout_path`], which resolves
//!   `<build-root>/<workspace-id>/<checkout-id>/<build-class>[/<fingerprint>]`
//!   from an owner-issued [`TargetLayoutBinding`]; and
//! * the governed work envelope's `derive_target_root`, which resolves
//!   `<local-app-data>/Eliot/build/<workspace-id>/<worktree-id>/<build-mode>/
//!   <fingerprint>`.
//!
//! They are not the same path: `BuildClass::dir_name()` and
//! `BuildMode::as_str()` are disjoint closed sets by design — the build class
//! is the output-kind discriminator, the build mode is the cache policy — and
//! the two bases are chosen by different owners. I2.22 is the most specific
//! governing document for the target-root shape, so for a lane that carries a
//! `GovernedWorkEnvelope` the envelope's `derive_target_root` is the ONE root
//! authority. [`verify_envelope_layout_binding`] is therefore how an enveloped
//! job is checked: the layout contributes the admitted build root and the
//! workspace/checkout identity, the envelope contributes the whole governed
//! root, and nothing is derived twice. [`verify_layout_binding`] remains the
//! check for a row admitted before a lane existed; it never selects a root for
//! an enveloped job.
//!
//! What this module does NOT decide, and leaves to the submitting owner: the
//! admitted `build_root` of an enveloped layout must be the envelope's own
//! build-root base (`<local-app-data>/Eliot\build`), because the governed root
//! must also be a strict descendant of the execution contour
//! ([`TargetRoots::validate`](super::TargetRoots::validate)) that the Kernel
//! issues. The productive TestD launch resolves that contour to the governed
//! build root for exactly this reason (the Kernel's productive TestD launch in
//! `bins/eliot-kernel/src/dispatch_launch.rs`, which resolves the contour from
//! `current_user_local_app_data_root`). A submission whose contour is elsewhere
//! still resolves two different roots, and the containment check above refuses
//! it rather than accepting it.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use eliot_build_test_graph::GovernedWorkEnvelope;

use super::{
    TargetRoots, TestdError, is_binding_digest, is_strict_descendant, validate_root_identity,
    validate_text,
};
pub use eliot_instrument_api::{BuildClass, TARGET_LAYOUT_REVISION};

/// Maximum length of one derived or admitted layout identity component.
const MAX_COMPONENT_LEN: usize = 64;
/// Length of the hex digest suffix in a derived component (128-bit strength).
const DERIVED_DIGEST_LEN: usize = 32;

/// Validates one workspace/checkout identity component for safe path use.
///
/// Lowercase-only output removes Windows case-aliasing, the charset removes
/// separators/dots/traversal, the bound removes path-length abuse, and the
/// reserved-name check removes Windows device-name creation failures.
/// Distinct inputs that pass this check always join to distinct components.
fn validate_layout_component(value: &str, field: &'static str) -> Result<(), TestdError> {
    validate_text(value, field)?;
    if value.len() > MAX_COMPONENT_LEN {
        return Err(TestdError::Invalid {
            field,
            reason: "layout identity component exceeds the bounded length",
        });
    }
    if !value
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err(TestdError::Invalid {
            field,
            reason: "layout identity component must use lowercase alphanumeric and dash only",
        });
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[value.len() - 1].is_ascii_alphanumeric() {
        return Err(TestdError::Invalid {
            field,
            reason: "layout identity component must start and end with an alphanumeric",
        });
    }
    if is_reserved_device_name(value) {
        return Err(TestdError::Invalid {
            field,
            reason: "layout identity component must not be a reserved device name",
        });
    }
    Ok(())
}

/// Whether a validated-lowercase component collides with a Windows device name.
fn is_reserved_device_name(value: &str) -> bool {
    match value.as_bytes() {
        b"con" | b"prn" | b"aux" | b"nul" => true,
        [b'c', b'o', b'm', digit] | [b'l', b'p', b't', digit] => digit.is_ascii_digit(),
        _ => false,
    }
}

/// Derives one stable safe component from opaque owner-issued material.
///
/// The derivation is deterministic over `(domain, material)`: the same
/// owner material always yields the same component, and distinct material
/// yields distinct components up to hash collision resistance. Blank or
/// control-bearing material is refused; it never yields a fallback.
fn derive_component(prefix: &str, domain: &str, material: &str) -> Result<String, TestdError> {
    validate_text(material, "layout_identity_material")?;
    let digest = eliot_contracts::sha256_hex(format!("{domain}\0{material}").as_bytes());
    Ok(format!("{prefix}-{}", &digest[..DERIVED_DIGEST_LEN]))
}

/// Immutable owner-issued binding of workspace/checkout/class to one layout.
///
/// The binding carries the effective resolved values: layout revision, the
/// admitted build root the layout derives under, both identity components,
/// the build class, and the `BuildFingerprint` digest when the producer
/// owns one. Filesystem truth is established only by [`verify_layout_binding`];
/// a constructed binding alone proves no root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetLayoutBinding {
    /// Layout derivation revision; must equal `TARGET_LAYOUT_REVISION`.
    pub layout_revision: u32,
    /// Admitted build root the layout derives under (installation mapping).
    pub build_root: String,
    /// Validated workspace identity component.
    pub workspace_id: String,
    /// Validated checkout (worktree) identity component.
    pub checkout_id: String,
    /// Governed build class selecting the class path level.
    pub build_class: BuildClass,
    /// Exact `BuildFingerprint` digest the bound output must satisfy, when
    /// the producer owns a fingerprint. It is also the final level of the
    /// derived root (see [`derive_layout_path`]), so it partitions the mutable
    /// root by build inputs rather than merely being compared after the fact.
    #[serde(default)]
    pub build_fingerprint: Option<String>,
}

impl TargetLayoutBinding {
    /// Binds owner-issued layout inputs, validating every value strictly.
    ///
    /// Registered identities that are not already safe components are
    /// refused here; opaque owner material must arrive through
    /// [`Self::derive_workspace_component`] or
    /// [`Self::derive_checkout_component`] instead.
    pub fn new(
        layout_revision: u32,
        build_root: impl Into<String>,
        workspace_id: impl Into<String>,
        checkout_id: impl Into<String>,
        build_class: BuildClass,
        build_fingerprint: Option<String>,
    ) -> Result<Self, TestdError> {
        let binding = Self {
            layout_revision,
            build_root: build_root.into(),
            workspace_id: workspace_id.into(),
            checkout_id: checkout_id.into(),
            build_class,
            build_fingerprint,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates shapes only: revision, identities, and fingerprint digest.
    ///
    /// Filesystem existence and root equality are established separately by
    /// [`verify_layout_binding`].
    pub fn validate(&self) -> Result<(), TestdError> {
        if self.layout_revision != TARGET_LAYOUT_REVISION {
            return Err(TestdError::Invalid {
                field: "target_layout.layout_revision",
                reason: "unsupported target layout revision",
            });
        }
        validate_text(&self.build_root, "target_layout.build_root")?;
        validate_layout_component(&self.workspace_id, "target_layout.workspace_id")?;
        validate_layout_component(&self.checkout_id, "target_layout.checkout_id")?;
        if let Some(fingerprint) = self.build_fingerprint.as_deref()
            && !is_binding_digest(fingerprint)
        {
            return Err(TestdError::Invalid {
                field: "target_layout.build_fingerprint",
                reason: "build fingerprint must be a lowercase SHA-256 digest",
            });
        }
        Ok(())
    }

    /// Derives the stable workspace component from opaque owner material.
    ///
    /// Revision-1 table: the Governor-issued opaque project identity.
    /// Registered `WorkspaceInstance` references (already safe components)
    /// pass through [`Self::new`] unchanged instead.
    pub fn derive_workspace_component(material: &str) -> Result<String, TestdError> {
        derive_component("ws", "eliot.target-layout.v1:workspace", material)
    }

    /// Derives the stable checkout component from opaque owner material.
    ///
    /// Revision-1 table: the canonical Governor-resolved source root. The
    /// full canonical path — not a branch name, shared Git directory,
    /// basename, or caller ID — distinguishes independent checkouts,
    /// including checkouts that share a branch or source commit.
    pub fn derive_checkout_component(material: &str) -> Result<String, TestdError> {
        derive_component("wt", "eliot.target-layout.v1:checkout", material)
    }

    /// Deterministic identity over every effective binding value.
    pub fn digest(&self) -> Result<String, TestdError> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            layout_revision: u32,
            build_root: &'a str,
            workspace_id: &'a str,
            checkout_id: &'a str,
            build_class: &'a str,
            build_fingerprint: Option<&'a str>,
        }
        let bytes = eliot_contracts::canonical_json_bytes(&Canonical {
            layout_revision: self.layout_revision,
            build_root: &self.build_root,
            workspace_id: &self.workspace_id,
            checkout_id: &self.checkout_id,
            build_class: self.build_class.dir_name(),
            build_fingerprint: self.build_fingerprint.as_deref(),
        })
        .map_err(|_| TestdError::GrantDigestSerialization)?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }
}

/// Pure derivation of the layout path:
/// `<build-root>/<workspace>/<checkout>/<class>[/<fingerprint>]`.
///
/// No filesystem access happens here: the build root is shape-checked
/// lexically (absolute, no parent traversal, no lowercasing of the proposed
/// path), and the joined result is proven a strict descendant of the build
/// root. Directory creation stays with the physical owner (testd daemon or
/// Kernel), and [`verify_layout_binding`] establishes filesystem truth
/// afterwards, including after path replacement.
///
/// The final `<fingerprint>` level is present exactly when the owner issued a
/// `BuildFingerprint` digest for this binding, which is what the governed work
/// envelope does (issue #1897: its governed root is
/// `<build-root>/<workspace>/<checkout>/<build-mode>/<fingerprint>`). Issue
/// #1806's binding already carried that digest as the constraint its bound
/// output "must satisfy"; resolving it as a path level is what makes it a real
/// constraint instead of a compared-but-unused field. Without it two work
/// items in one workspace, checkout, and class that differ only in build inputs
/// would share one mutable root. A binding without a fingerprint keeps the
/// class-level root it has always resolved.
pub fn derive_layout_path(layout: &TargetLayoutBinding) -> Result<PathBuf, TestdError> {
    layout.validate()?;
    let build_root = Path::new(&layout.build_root);
    if !build_root.is_absolute() {
        return Err(TestdError::Invalid {
            field: "target_layout.build_root",
            reason: "must be an absolute path",
        });
    }
    if build_root
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(TestdError::Invalid {
            field: "target_layout.build_root",
            reason: "parent traversal is forbidden",
        });
    }
    let mut derived = build_root
        .join(&layout.workspace_id)
        .join(&layout.checkout_id)
        .join(layout.build_class.dir_name());
    if let Some(fingerprint) = layout.build_fingerprint.as_deref() {
        derived = derived.join(fingerprint);
    }
    if !is_strict_descendant(&derived, build_root) {
        return Err(TestdError::Invalid {
            field: "target_layout.build_root",
            reason: "derived layout root must descend from the admitted build root",
        });
    }
    Ok(derived)
}

/// Immutable envelope coupling canonical roots to their layout binding.
///
/// Construction and every revalidation go through [`verify_layout_binding`]:
/// the envelope never carries roots that disagree with the binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundTargetRoots {
    /// Canonical roots retained for execution and receipt checks.
    pub roots: TargetRoots,
    /// Owner-issued layout binding the roots were verified against.
    pub layout: TargetLayoutBinding,
}

/// Verifies canonical roots against an owner-issued layout binding.
///
/// The checks compose, in order: binding shapes, the full existing
/// [`TargetRoots::validate`](super::TargetRoots::validate) gate (D0
/// cache/target equality, contour/source disjointness, target inside the
/// contour, source/target disjointness), admitted build-root identity with
/// reparse refusal, strict descent of the derived root, and canonical
/// equality between the derived layout root and the canonical target root.
/// Textual prefix checks alone are never containment proof: every equality
/// here compares canonical identities. A missing or mismatched safe root is
/// a typed refusal, never a repository `target/` fallback.
pub fn verify_layout_binding(
    roots: &TargetRoots,
    layout: &TargetLayoutBinding,
) -> Result<BoundTargetRoots, TestdError> {
    layout.validate()?;
    roots.validate()?;
    let build_root = validate_root_identity(&layout.build_root, "target_layout.build_root")?;
    let derived = derive_layout_path(layout)?;
    let canonical_derived =
        validate_root_identity(&derived.to_string_lossy(), "target_layout.derived_root")?;
    if !is_strict_descendant(&canonical_derived, &build_root) {
        return Err(TestdError::InvalidBinding);
    }
    let canonical_target = validate_root_identity(&roots.target_root, "target_roots.target_root")?;
    if canonical_derived != canonical_target {
        return Err(TestdError::InvalidBinding);
    }
    Ok(BoundTargetRoots {
        roots: roots.clone(),
        layout: layout.clone(),
    })
}

/// Verifies canonical roots of an enveloped job against its layout binding.
///
/// This is the lane-root check, not a second derivation. The envelope's
/// `derive_target_root` is the single authority for where a governed lane
/// builds; [`derive_layout_path`] is deliberately NOT called here, so the
/// layout's build-class level never competes with the envelope's build-mode
/// level. The layout contributes exactly two admitted facts and both are
/// compared by content:
///
/// * its identity: `layout.workspace_id == envelope.workspace_id` and
///   `layout.checkout_id == envelope.worktree_id`, so the lane runs under the
///   admitted workspace and the real admitted checkout, not beside them; and
/// * its containment: the governed root is a strict descendant of
///   `<admitted build root>/<workspace-id>/<checkout-id>` and its remaining
///   levels are exactly the envelope's build mode and normalized fingerprint,
///   so no other root can be substituted for the lane's.
///
/// The existing [`TargetRoots::validate`](super::TargetRoots::validate) gate
/// still runs first and unchanged, so `cache_root == target_root`, contour and
/// source disjointness, and target-inside-contour hold exactly as before. Every
/// equality here compares canonical identities, never textual prefixes. A
/// missing or mismatched safe root is a typed refusal, never a repository
/// `target/` fallback.
///
/// # Errors
///
/// Returns [`TestdError`] when the binding shapes, the root gate, or the
/// admitted build-root identity fail, and [`TestdError::InvalidBinding`] when
/// the lane identity, the containment, or the canonical target root disagrees.
pub fn verify_envelope_layout_binding(
    roots: &TargetRoots,
    layout: &TargetLayoutBinding,
    envelope: &GovernedWorkEnvelope,
) -> Result<BoundTargetRoots, TestdError> {
    layout.validate()?;
    roots.validate()?;
    if envelope.workspace_id != layout.workspace_id
        || envelope.worktree_id != layout.checkout_id
    {
        return Err(TestdError::InvalidBinding);
    }
    let build_root = validate_root_identity(&layout.build_root, "target_layout.build_root")?;
    let lane_root = build_root.join(&layout.workspace_id).join(&layout.checkout_id);
    let canonical_lane_root =
        validate_root_identity(&lane_root.to_string_lossy(), "target_layout.lane_root")?;
    let governed = envelope
        .derive_target_root()
        .map_err(|error| TestdError::Contract(error.to_string()))?;
    let canonical_governed =
        validate_root_identity(&governed.to_string_lossy(), "work_envelope.governed_root")?;
    let Ok(levels) = canonical_governed.strip_prefix(&canonical_lane_root) else {
        return Err(TestdError::InvalidBinding);
    };
    let fingerprint = envelope
        .normalized_fingerprint()
        .map_err(|error| TestdError::Contract(error.to_string()))?;
    let mut remaining = levels.components();
    let mode = remaining.next().map(|component| component.as_os_str().to_owned());
    let digest = remaining.next().map(|component| component.as_os_str().to_owned());
    if remaining.next().is_some()
        || mode.as_deref() != Some(std::ffi::OsStr::new(envelope.build_mode.as_str()))
        || digest.as_deref() != Some(std::ffi::OsStr::new(&fingerprint))
    {
        return Err(TestdError::InvalidBinding);
    }
    let canonical_target = validate_root_identity(&roots.target_root, "target_roots.target_root")?;
    if canonical_governed != canonical_target {
        return Err(TestdError::InvalidBinding);
    }
    Ok(BoundTargetRoots {
        roots: roots.clone(),
        layout: layout.clone(),
    })
}

/// Whether two bound roots alias one mutable root under distinct identities.
///
/// Same canonical target root with a different `(workspace, checkout,
/// class)` identity is a conflict: two admitted identities must never share
/// one mutable root. Same identity sharing one root is intended reuse,
/// serialized by the existing lease/claim owner. Cross-process exclusion is
/// never inferred from this predicate alone; it only detects the alias so
/// the owning scheduler can refuse it.
pub fn bound_roots_conflict(
    a: &BoundTargetRoots,
    b: &BoundTargetRoots,
) -> Result<bool, TestdError> {
    let canonical_a = validate_root_identity(&a.roots.target_root, "target_roots.target_root")?;
    let canonical_b = validate_root_identity(&b.roots.target_root, "target_roots.target_root")?;
    if canonical_a != canonical_b {
        return Ok(false);
    }
    Ok(a.layout.workspace_id != b.layout.workspace_id
        || a.layout.checkout_id != b.layout.checkout_id
        || a.layout.build_class != b.layout.build_class)
}
