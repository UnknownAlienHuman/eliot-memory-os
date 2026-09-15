//! Static ten-owner registry composition owned by this component root.
//!
//! The registry carries owner *descriptors* only (pure data from the accepted
//! A-03 contracts): one [`CurationHandlerDescriptor`] per canonical family
//! with the exact canonical kind coverage. Descriptor fields reuse accepted
//! sources with no copied table: families iterate [`CURATION_FAMILIES`],
//! coverage calls [`family_kinds`], handler identity calls
//! [`expected_owner_package`]. The handler-identity convention (owner
//! package) matches both production `HANDLER_ID` constants that exist on
//! this base (`eliot-dreamer-concept`, `eliot-dreamer-failure`); it is a
//! guest-local convention pending owner-accepted identities, never a claim
//! of accepted production handler identities.
//!
//! Live ports bind descriptors to live handlers. No production
//! [`NativeCurationHandler`] implementor exists for any family on this base,
//! and the WIT Curation arm carries registry identity/data only ("no
//! callable objects"), so static live-port construction terminates at the
//! frozen [`StaticPortChallenge`]. [`assemble_ports`] binds caller-supplied
//! live handlers (the typed Rust boundary used by proof) with the same
//! closed checks A-31 enforces; it never invents a handler.

use eliot_dreamer_contracts::{
    CURATION_FAMILIES, CurationFamily, CurationHandlerDescriptor, CurationHandlerPort,
    CurationHandlerRegistry, NativeCurationHandler, parse_family,
};
use eliot_dreamer_contracts::registry::family_kinds;
use eliot_dreamer_curation::{
    NativeCurationPort, NativeCurationPortSet, OwnerRevisionPin, expected_owner_package,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::conversion::GuestError;

/// Frozen ContractChallenge for the missing live-handler edge.
///
/// The manager alone owns `crates/smart/cognitive-contract-challenges.toml`;
/// this record is the frozen evidence the manager appends. It is data, not a
/// workaround: no echo/stub handler, no invented context or policy, no
/// handler invocation outside A-31 dispatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StaticPortChallenge {
    /// Issue-qualified challenge identity.
    pub challenge_id: String,
    /// Challenge status on this base.
    pub status: String,
    /// Owner issues that must publish the missing contract.
    pub required_owner: Vec<String>,
    /// Work unit blocked at the live-port edge.
    pub needed_by: String,
    /// Exact missing contract.
    pub missing_contract: String,
    /// Explicitly refused fabrication.
    pub forbidden_workaround: String,
    /// Evidence that resolves the challenge.
    pub resolution_evidence: String,
    /// Base commit the evidence was verified against.
    pub base_sha: String,
}

/// Owner issues for the ten handler implementations, in the issue-body order
/// (#653/#655/#657/#659/#661/#663/#665/#667/#669/#671, kinds in
/// `CURATION_WIRE_KINDS` order with Merge/Split sharing their owner).
pub const MISSING_OWNER_ISSUES: &[&str] = &[
    "653", "655", "657", "659", "661", "663", "665", "667", "669", "671",
];

/// Base commit this composition was verified against.
pub const CHALLENGE_BASE_SHA: &str = "253ac3b8beee5d8c735daa509ea402eba9810c4f";

/// Returns the owning implementation issue for one handler family.
///
/// Provenance: issue #636 body requires the ten implementations in
/// `#653/#655/.../#671` order; titles verified live (`gh issue view`) bind
/// each number to its family (A-21 classification through A-30 memory
/// repair, merge/split sharing the A-27 structure-repair owner).
#[must_use]
pub const fn owner_issue(family: CurationFamily) -> &'static str {
    match family {
        CurationFamily::Classification => "653",
        CurationFamily::Relation => "655",
        CurationFamily::Episode => "657",
        CurationFamily::Concept => "659",
        CurationFamily::Procedure => "661",
        CurationFamily::Failure => "663",
        CurationFamily::StructureRepair => "665",
        CurationFamily::Reconsolidation => "667",
        CurationFamily::Accessibility => "669",
        CurationFamily::MemoryRepair => "671",
    }
}

/// Builds the frozen missing-owner challenge record.
#[must_use]
pub fn static_port_challenge() -> StaticPortChallenge {
    StaticPortChallenge {
        challenge_id: "CC-636-STATIC-PORTS".to_owned(),
        status: "OPEN_MISSING_OWNER".to_owned(),
        required_owner: MISSING_OWNER_ISSUES
            .iter()
            .map(|issue| (*issue).to_owned())
            .collect(),
        needed_by: "eliot-dreamer-curation-wasm live-port binding (issue #636)".to_owned(),
        missing_contract: "production NativeCurationHandler implementors for all ten families"
            .to_owned(),
        forbidden_workaround: "echo/stub handlers, invented acceptance context or policy, handler invocation outside A-31 dispatch, or a private ABI"
            .to_owned(),
        resolution_evidence: "ten owner-published NativeCurationHandler bindings passing ports.validate against the static registry; bytes transport dispatches with native_calls 1"
            .to_owned(),
        base_sha: CHALLENGE_BASE_SHA.to_owned(),
    }
}

/// Canonical family spellings with no published live handler on this base.
#[must_use]
pub fn missing_owner_families() -> Vec<String> {
    CURATION_FAMILIES
        .iter()
        .map(|spelling| (*spelling).to_owned())
        .collect()
}

/// Builds the frozen missing-owner error for dispatchable envelopes.
#[must_use]
pub fn missing_static_ports_error() -> GuestError {
    let challenge = static_port_challenge();
    GuestError::MissingStaticPorts {
        detail: std::format!(
            "{}: {} (owners {}), base {}",
            challenge.challenge_id,
            challenge.missing_contract,
            challenge.required_owner.join(","),
            challenge.base_sha,
        ),
        missing_handlers: missing_owner_families(),
    }
}

/// Composes the static ten-owner registry from accepted contract sources.
///
/// Ten descriptors, one per canonical family, each with the exact canonical
/// kind coverage and the owner-package handler identity. Registration runs
/// the real A-03 [`register`](CurationHandlerRegistry::register) checks, so
/// gaps, overlaps, renames and duplicates fail closed here, not in A-31.
///
/// # Errors
///
/// Returns [`GuestError::Registry`] when a canonical family spelling fails
/// to parse or a descriptor fails the real registration checks.
pub fn static_registry() -> Result<CurationHandlerRegistry, GuestError> {
    let mut registry = CurationHandlerRegistry::new();
    for spelling in CURATION_FAMILIES {
        let family = parse_family(spelling).map_err(|_| GuestError::Registry {
            detail: std::format!("canonical family spelling is not closed: {spelling}"),
        })?;
        let descriptor = CurationHandlerDescriptor {
            family,
            handler_id: expected_owner_package(family).to_owned(),
            accepted_kinds: family_kinds(family).to_vec(),
        };
        registry.register(descriptor).map_err(|error| GuestError::Registry {
            detail: std::format!("static descriptor rejected: {error}"),
        })?;
    }
    Ok(registry)
}

/// Returns the digest of the static registry (closed-registry proof).
///
/// # Errors
///
/// Returns [`GuestError::Registry`] when composition or digesting fails.
pub fn static_registry_digest() -> Result<String, GuestError> {
    static_registry()
        .and_then(|registry| registry.digest().map_err(|_| GuestError::Registry {
            detail: "static registry digest requires closed registry".to_owned(),
        }))
}

/// Assembles a live port set from caller-supplied handlers against the
/// static registry shape.
///
/// Each `(family, handler)` pair binds the registered descriptor, the
/// accepted owner package, and the batch-pinned revision for exactly one
/// canonical family. Exactly ten pairs covering each canonical family once
/// are required; the assembled set is sealed through the real
/// [`validate`](eliot_dreamer_curation::NativeCurationPortSet::validate).
/// No handler is executed to register it: assembly is inert until A-31
/// dispatches.
///
/// # Errors
///
/// Returns [`GuestError::Port`] on any missing, duplicate, unregistered, or
/// unpinned family, and [`GuestError::Registry`] when the canonical family
/// table itself cannot be read.
pub fn assemble_ports<'handlers>(
    registry: &CurationHandlerRegistry,
    pins: &[OwnerRevisionPin],
    handlers: &[(CurationFamily, &'handlers dyn NativeCurationHandler)],
) -> Result<NativeCurationPortSet<'handlers>, GuestError> {
    if handlers.len() != CURATION_FAMILIES.len() {
        return Err(GuestError::Port {
            detail: std::format!(
                "port assembly requires exactly {} live handlers",
                CURATION_FAMILIES.len()
            ),
        });
    }
    let mut ports = Vec::with_capacity(CURATION_FAMILIES.len());
    for spelling in CURATION_FAMILIES {
        let family = parse_family(spelling).map_err(|_| GuestError::Registry {
            detail: std::format!("canonical family spelling is not closed: {spelling}"),
        })?;
        let matching: Vec<&(CurationFamily, &'handlers dyn NativeCurationHandler)> = handlers
            .iter()
            .filter(|(bound, _)| *bound == family)
            .collect();
        let Some((_, handler)) = matching.first() else {
            return Err(GuestError::Port {
                detail: std::format!("no live handler supplied for family {}", family.as_str()),
            });
        };
        if matching.len() != 1 {
            return Err(GuestError::Port {
                detail: std::format!(
                    "duplicate live handlers supplied for family {}",
                    family.as_str()
                ),
            });
        }
        let Some(declared) = registry.handlers.iter().find(|item| item.family == family) else {
            return Err(GuestError::Port {
                detail: std::format!(
                    "static registry declares no descriptor for family {}",
                    family.as_str()
                ),
            });
        };
        let Some(pin) = pins.iter().find(|item| item.family == family) else {
            return Err(GuestError::Port {
                detail: std::format!(
                    "batch pins no owner revision for family {}",
                    family.as_str()
                ),
            });
        };
        ports.push(NativeCurationPort {
            port: CurationHandlerPort {
                port_id: std::format!("port-{}", family.as_str()),
                descriptor: declared.clone(),
            },
            owner_package: expected_owner_package(family).to_owned(),
            owner_revision: pin.revision.clone(),
            handler: *handler,
        });
    }
    let set = NativeCurationPortSet { ports };
    set.validate(registry, pins)
        .map_err(|error| GuestError::from(&error))?;
    Ok(set)
}
