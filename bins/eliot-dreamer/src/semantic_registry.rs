#![forbid(unsafe_code)]

//! Slice-1 static curation-handler registry validation (issue #702).
//!
//! Constructs the closed ten-family / eleven-kind handler registry from the
//! contracts owner's descriptors, validates exact closure, proves every wire
//! kind resolves to exactly one family, and returns the deterministic digest
//! — WITHOUT running any handler. There is no invocation surface here: no
//! handler trait object is taken, stored, or called on any path, so
//! validation performs zero leaf calls by construction.
//!
//! Handler identities mirror the A-31 owner's canonical owner packages
//! (`expected_owner_package` in `eliot-dreamer-curation`, read-only here):
//! the daemon registers descriptors only, while A-31 owns invocation and
//! must not be bypassed.

use eliot_dreamer_contracts::{
    CURATION_WIRE_KINDS, ContractViolation, CurationFamily, CurationHandlerDescriptor,
    CurationHandlerRegistry, CurationKind, parse_kind,
};
use eliot_dreamer_contracts::registry::family_kinds;

use crate::DreamerError;

/// Static handler identities, one per closed family in `CURATION_FAMILIES`
/// order (I9.6: ten families cover the eleven wire kinds; `Merge`/`Split`
/// share `StructureRepair`, `Repair` maps to `MemoryRepair`).
const STATIC_HANDLERS: [(CurationFamily, &str); 10] = [
    (CurationFamily::Classification, "eliot-dreamer-classification"),
    (CurationFamily::Relation, "eliot-dreamer-relation"),
    (CurationFamily::Episode, "eliot-dreamer-episode"),
    (CurationFamily::Concept, "eliot-dreamer-concept"),
    (CurationFamily::Procedure, "eliot-dreamer-procedure"),
    (CurationFamily::Failure, "eliot-dreamer-failure"),
    (
        CurationFamily::StructureRepair,
        "eliot-dreamer-structure-repair",
    ),
    (
        CurationFamily::Reconsolidation,
        "eliot-dreamer-reconsolidation",
    ),
    (
        CurationFamily::Accessibility,
        "eliot-dreamer-accessibility",
    ),
    (CurationFamily::MemoryRepair, "eliot-dreamer-memory-repair"),
];

/// Bound for contract-violation detail carried into typed refusal lines.
const REFUSAL_DETAIL_LIMIT: usize = 256;

/// Bounds third-party contract detail carried into deny lines.
fn truncate_detail(detail: &str) -> String {
    detail.chars().take(REFUSAL_DETAIL_LIMIT).collect()
}

fn registry_refused(violation: &ContractViolation) -> DreamerError {
    DreamerError::RegistryNotClosed(truncate_detail(&violation.to_string()))
}

/// Builds the closed ten-family registry: one descriptor per family carrying
/// exactly that family's canonical kind set, then exact-closure validation.
///
/// Descriptor construction only; no handler logic is referenced or run.
pub(crate) fn closed_registry() -> Result<CurationHandlerRegistry, DreamerError> {
    let mut registry = CurationHandlerRegistry::new();
    for (family, handler_id) in STATIC_HANDLERS {
        let descriptor = CurationHandlerDescriptor {
            family,
            handler_id: handler_id.to_owned(),
            accepted_kinds: family_kinds(family).to_vec(),
        };
        registry
            .register(descriptor)
            .map_err(|violation| registry_refused(&violation))?;
    }
    registry
        .validate_closure()
        .map_err(|violation| registry_refused(&violation))?;
    Ok(registry)
}

/// Resolves one wire kind to its owning family against the registry.
///
/// A kind with no covering descriptor fails closed with the typed
/// [`DreamerError::UnsupportedCurationKind`] refusal before any leaf runs.
pub(crate) fn resolve_kind(
    kind: CurationKind,
    registry: &CurationHandlerRegistry,
) -> Result<CurationFamily, DreamerError> {
    registry
        .handlers
        .iter()
        .find(|descriptor| descriptor.accepted_kinds.contains(&kind))
        .map(|descriptor| descriptor.family)
        .ok_or(DreamerError::UnsupportedCurationKind(kind))
}

/// Proves every closed wire kind (I9.6) resolves to its owning family.
///
/// Any unknown or uncovered kind fails the admission with a typed refusal
/// before any leaf runs.
pub(crate) fn check_kind_coverage(registry: &CurationHandlerRegistry) -> Result<(), DreamerError> {
    for wire in CURATION_WIRE_KINDS {
        let kind = parse_kind(wire).map_err(|violation| registry_refused(&violation))?;
        resolve_kind(kind, registry)?;
    }
    Ok(())
}

/// Validates the static registry once and returns its deterministic digest:
/// construct, prove exact closure, prove full kind coverage, then digest.
///
/// Exactly one validation per call; callers invoke this once per admitted
/// admission. The digest is the admission evidence carried forward (future
/// slices bind handler calls against it); no handler is invoked on any path.
pub(crate) fn validated_registry_digest() -> Result<String, DreamerError> {
    let registry = closed_registry()?;
    check_kind_coverage(&registry)?;
    registry
        .digest()
        .map_err(|violation| registry_refused(&violation))
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    /// The static registry closes over exactly ten descriptors and digests to
    /// a deterministic 64-char lowercase hex identity.
    #[test]
    fn closed_registry_validates_and_digests_deterministically() {
        let registry = closed_registry().expect("static registry must close");
        assert_eq!(registry.handlers.len(), 10);
        let first = validated_registry_digest().expect("static registry must validate");
        let second = validated_registry_digest().expect("validation must be repeatable");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(
            first
                .chars()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "registry digest must be lowercase hex sha256"
        );
    }

    /// An open registry (missing coverage) cannot validate or digest: the
    /// typed refusal carries the request-rejected code, never success.
    #[test]
    fn open_registry_refuses_typed() {
        let open = CurationHandlerRegistry::new();
        assert!(open.validate_closure().is_err());
        assert!(open.digest().is_err());
        let mut partial = CurationHandlerRegistry::new();
        partial
            .register(CurationHandlerDescriptor {
                family: CurationFamily::Classification,
                handler_id: "eliot-dreamer-classification".to_owned(),
                accepted_kinds: family_kinds(CurationFamily::Classification).to_vec(),
            })
            .expect("single descriptor must register");
        assert!(partial.validate_closure().is_err());
        assert!(partial.digest().is_err());
    }

    /// A kind stripped of coverage resolves to the typed kind refusal with
    /// the request-rejected code.
    #[test]
    fn uncovered_kind_refuses_typed() {
        let mut registry = closed_registry().expect("static registry must close");
        registry.handlers.retain(|descriptor| {
            descriptor.family != CurationFamily::MemoryRepair
        });
        let refused = resolve_kind(CurationKind::Repair, &registry);
        assert!(
            matches!(
                refused,
                Err(DreamerError::UnsupportedCurationKind(CurationKind::Repair))
            ),
            "uncovered kind must refuse typed"
        );
        let error = refused.expect_err("uncovered kind must refuse");
        assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
        assert!(check_kind_coverage(&registry).is_err());
    }
}
