//! Prototype contour decisions and the prototype-admission gate (issue #1955).
//!
//! Establishes the required WASM component contour and host boundary owned by
//! `eliot-wasm-host` under `I0.12`, `I10.8.16`, and `I14.19`:
//!
//! - [`PrototypeContourDecision`] records which execution contour a prototype
//!   takes. A normal new prototype defaults to the capability-limited WASM
//!   component contour; an isolated native process requires an explicit
//!   capability/isolation reason, and a static native bundle is never the
//!   first contour for new experimental behavior.
//! - [`GenerationManifest`] is the immutable generation record: guest target,
//!   artifact/interface digests, declared imports/exports, capability grants,
//!   state class and migration contract, the full limit envelope
//!   (memory/table/instance/stack, wall deadline, epoch/fuel policy and
//!   cancellation, host-call/input/output/artifact ceilings), privacy/source
//!   policy, and the shadow/canary comparator plus rollback generation.
//! - Host calls are [`HostCallProposal`]s. A proposal for a capability the
//!   manifest did not grant is uncallable; a granted capability additionally
//!   requires a [`GovernorGrant`] held from actual Governor authority. This
//!   host never fabricates a grant from ambient caller input.
//! - [`admit_prototype`] is the prototype-admission gate: a prototype without
//!   a contour decision is rejected before anything else. [`check_activation_imports`]
//!   rejects undeclared imports pre-activation, before any instantiation.
//! - [`admit_generation`] composes the full pre-activation sequence into one
//!   actual admission, binding the admitted contour, world, target, and
//!   digests into an [`AdmittedGeneration`] that dispatch sites match
//!   against. The WASM host serves only [`Contour::WasmComponent`]; any
//!   other admitted contour is refused with
//!   [`ContourGateError::ContourNotServedHere`], never executed here.
//!
//! Baseline identities: pinned Wasmtime generation
//! ([`PINNED_WASMTIME_VERSION`]), production guest target
//! [`STANDARD_GUEST_TARGET`] (`wasm32-wasip2`), and the ELIOT-owned versioned
//! WIT worlds (`wit/typed`, package [`crate::typed_bindings::TYPED_PACKAGE_ID`]).

use std::fmt;

use eliot_wasm_runtime::{InvocationLimits, InvocationRequest, Sha256Digest};

/// Pinned Wasmtime generation behind `eliot-wasm-host` (I14.19 baseline).
/// Must match the exact workspace pin; the linked engine identity is asserted
/// in tests via `wasmtime::VERSION`.
pub const PINNED_WASMTIME_VERSION: &str = "47.0.4";

/// Production guest target: the standard capability-oriented component target.
pub const STANDARD_GUEST_TARGET: &str = "wasm32-wasip2";

/// Non-standard target admitted only for a completely self-contained library
/// experiment. It is not the standard capability-oriented component target.
pub const SELF_CONTAINED_GUEST_TARGET: &str = "wasm32-unknown-unknown";

/// Filesystem capability grant name. Absence of this grant means the guest
/// cannot request filesystem effects through the supported host surface.
pub const FS_CAPABILITY: &str = "fs.read";

/// Network capability grant name. Absence of this grant means the guest
/// cannot request network effects through the supported host surface.
pub const NET_CAPABILITY: &str = "net.connect";

/// Maximum import/export/grant string length echoed in an error code.
const MAX_NAME_BYTES: usize = 96;

/// Execution contour selected for one prototype generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Contour {
    /// Default first contour for pure, bounded, portable experimental logic:
    /// the capability-limited WASM component.
    WasmComponent,
    /// Isolated native process generation. Requires an explicit
    /// capability/isolation reason recorded on the decision.
    IsolatedNativeProcess,
    /// Static native release generation. Never the first contour for new
    /// experimental behavior; the gate rejects it pre-activation.
    StaticNative,
}

impl fmt::Display for Contour {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WasmComponent => formatter.write_str("WASM_COMPONENT"),
            Self::IsolatedNativeProcess => formatter.write_str("ISOLATED_NATIVE_PROCESS"),
            Self::StaticNative => formatter.write_str("STATIC_NATIVE"),
        }
    }
}

/// Recorded contour selection for one prototype (I0.12 contract).
///
/// For the default no-authority component contour the decision is generated
/// automatically from the Module contract and manifest. Manual rationale is
/// mandatory only for a non-default contour.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrototypeContourDecision {
    /// Selected execution contour.
    pub contour: Contour,
    /// Explicit capability/isolation reason. Required for a non-default
    /// contour; `None` for the automatic default-WASM decision.
    pub rationale: Option<String>,
}

impl PrototypeContourDecision {
    /// Automatic decision for a normal new prototype: the WASM component
    /// contour with no manual rationale.
    #[must_use]
    pub fn default_for_new_prototype() -> Self {
        Self {
            contour: Contour::WasmComponent,
            rationale: None,
        }
    }

    /// Explicit decision for an isolated native process. The
    /// capability/isolation reason must be non-empty; OS/Cargo/Git/LSP/
    /// browser/native-library/credential-heavy logic belongs here, never
    /// silently.
    pub fn select_native_process(reason: &str) -> Result<Self, ContourGateError> {
        if reason.trim().is_empty() {
            return Err(ContourGateError::NativeReasonRequired);
        }
        Ok(Self {
            contour: Contour::IsolatedNativeProcess,
            rationale: Some(reason.to_owned()),
        })
    }
}

impl Default for PrototypeContourDecision {
    fn default() -> Self {
        Self::default_for_new_prototype()
    }
}

/// Immutable generation record for one component generation (I14.19 manifest).
///
/// A component is immutable after publication; the manifest binds the exact
/// component identity, target, digests, declared imports/exports, capability
/// grants, limits (including fuel policy and cancellation), and the rollback
/// generation used for forward route-switch rollback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationManifest {
    /// Admitted component identity, bound into [`AdmittedGeneration`] and
    /// matched against the caller request at dispatch: a request naming any
    /// other component is a confused-deputy attempt and fails closed before
    /// any Wasmtime invoke.
    pub component_id: String,
    /// Guest compile target, e.g. `wasm32-wasip2`.
    pub target: String,
    /// Digest of the exact immutable component artifact bytes.
    pub artifact_digest: Sha256Digest,
    /// Digest of the versioned ELIOT WIT world the artifact was built against.
    pub wit_digest: Sha256Digest,
    /// World name the generation implements.
    pub world: String,
    /// Declared imports. Anything the component actually imports that is not
    /// declared here is rejected pre-activation. Empty means closed.
    pub allowed_imports: Vec<String>,
    /// Declared exports.
    pub allowed_exports: Vec<String>,
    /// Granted capabilities (e.g. `fs.read`, `net.connect`). Absence of a
    /// filesystem, network, process, secrets, or clock grant means the guest
    /// cannot request those effects through the supported host surface.
    pub capability_grants: Vec<String>,
    /// Full per-invocation limit envelope: memory/table/instance/stack
    /// limits, wall deadline, epoch/fuel policy and cancellation, host-call,
    /// input/output, and artifact-access ceilings.
    pub limits: InvocationLimits,
    /// Owned state class (e.g. `module-derived`, `stateless`).
    pub state_class: String,
    /// Versioned state migration contract (or `none` for stateless).
    pub migration_contract: String,
    /// Privacy/source policy binding the generation.
    pub privacy_policy: String,
    /// Shadow/canary comparator identity recording divergence.
    pub comparator: String,
    /// Prior compatible generation receiving new requests on rollback.
    /// Old epochs are never reactivated; rollback is a forward route switch.
    pub rollback_generation: Option<String>,
}

impl GenerationManifest {
    /// Structural validation before admission. Fails closed on a non-standard
    /// target or an incomplete manifest; limit-envelope semantics remain owned
    /// by the Governor-resolved [`InvocationLimits`] contract.
    pub fn validate(&self) -> Result<(), ContourGateError> {
        if self.component_id.trim().is_empty() {
            return Err(ContourGateError::IncompleteManifest(
                "component-id".to_owned(),
            ));
        }
        if self.target != STANDARD_GUEST_TARGET && self.target != SELF_CONTAINED_GUEST_TARGET {
            return Err(ContourGateError::UnsupportedTarget(bounded(&self.target)));
        }
        if self.world.trim().is_empty() {
            return Err(ContourGateError::IncompleteManifest("world".to_owned()));
        }
        if self.state_class.trim().is_empty() {
            return Err(ContourGateError::IncompleteManifest(
                "state-class".to_owned(),
            ));
        }
        if self.migration_contract.trim().is_empty() {
            return Err(ContourGateError::IncompleteManifest(
                "migration-contract".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns true when the named capability was granted to this generation.
    #[must_use]
    pub fn grants(&self, capability: &str) -> bool {
        self.capability_grants
            .iter()
            .any(|grant| grant == capability)
    }

    /// Returns true when the named import was declared by this generation.
    #[must_use]
    pub fn declares_import(&self, import: &str) -> bool {
        self.allowed_imports.iter().any(|name| name == import)
    }
}

/// Governor authority held for host-call authorization.
///
/// This is an opaque input bound from actual Governor authority, mirroring the
/// port-grant injection pattern: the host resolves it from an authenticated
/// channel and never fabricates it from ambient caller input. Tests construct
/// it directly as the neutral-stand-in grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernorGrant {
    /// Capabilities the Governor authorized for this generation.
    pub granted_capabilities: Vec<String>,
    /// Authority epoch/generation binding the grant.
    pub generation: String,
}

impl GovernorGrant {
    /// Binds an explicit Governor grant. Empty scope authorizes nothing.
    #[must_use]
    pub fn new(granted_capabilities: Vec<String>, generation: String) -> Self {
        Self {
            granted_capabilities,
            generation,
        }
    }

    /// Returns true when the Governor authorized the named capability.
    #[must_use]
    pub fn authorizes(&self, capability: &str) -> bool {
        self.granted_capabilities
            .iter()
            .any(|grant| grant == capability)
    }
}

/// Proposed host call: a bounded data operation, never a bypass of Governor
/// authority. Filesystem/network proposals without a manifest grant are
/// uncallable; granted proposals still require [`GovernorGrant`] authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostCallProposal {
    /// Named capability requested (e.g. `fs.read`, `net.connect`).
    pub capability: String,
    /// Proposed input byte length, bounded by the generation limits.
    pub input_bytes: u64,
    /// Digest of the exact proposed input bytes.
    pub input_digest: Sha256Digest,
}

impl HostCallProposal {
    /// Proposes one bounded host call for later authorization.
    #[must_use]
    pub fn new(capability: String, input_bytes: u64, input_digest: Sha256Digest) -> Self {
        Self {
            capability,
            input_bytes,
            input_digest,
        }
    }
}

/// Governor-authorized host call: callable exactly once under the generation
/// limits. Carries digests only, never raw payloads or paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedHostCall {
    /// Authorized capability.
    pub capability: String,
    /// Digest of the exact authorized input bytes.
    pub input_digest: Sha256Digest,
}

/// Fail-closed prototype-admission errors with stable codes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContourGateError {
    /// Prototype arrived without a contour decision.
    MissingDecision,
    /// Static native selected as the first contour for new behavior.
    StaticNativeNotFirstContour,
    /// Isolated native process selected without an explicit reason.
    NativeReasonRequired,
    /// Guest target outside the admitted baseline.
    UnsupportedTarget(String),
    /// Manifest is structurally incomplete (names the missing field).
    IncompleteManifest(String),
    /// Actual component import not declared in the manifest.
    UndeclaredImport(String),
    /// Capability-gated import or host call without a manifest grant.
    CapabilityNotGranted(String),
    /// Granted capability without Governor authorization.
    GovernorAuthorizationRequired(String),
    /// Proposal exceeds the generation limit envelope.
    HostCallLimitExceeded(String),
    /// Admitted non-WASM contour presented to this host. `eliot-wasm-host`
    /// serves only the WASM component contour; any other admitted contour
    /// must be refused at dispatch, never executed here.
    ContourNotServedHere(String),
    /// Admitted digest does not match the recomputed digest of the supplied
    /// bytes (names `artifact` or `interface`). Manifest digest claims are
    /// never trusted without the bytes.
    AdmittedDigestMismatch(String),
    /// Caller request names a component the admission was not bound to.
    /// Confused-deputy attempts fail closed before any Wasmtime invoke.
    ComponentNotAdmitted(String),
    /// Caller input exceeds the admitted per-invocation input envelope.
    /// Denied before any Wasmtime invoke.
    InputLimitExceeded(String),
}

impl fmt::Display for ContourGateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDecision => formatter.write_str("CONTOUR_DECISION_REQUIRED"),
            Self::StaticNativeNotFirstContour => {
                formatter.write_str("STATIC_NATIVE_NOT_FIRST_CONTOUR")
            }
            Self::NativeReasonRequired => formatter.write_str("NATIVE_REASON_REQUIRED"),
            Self::UnsupportedTarget(target) => write!(formatter, "UNSUPPORTED_TARGET:{target}"),
            Self::IncompleteManifest(field) => {
                write!(formatter, "INCOMPLETE_MANIFEST:{field}")
            }
            Self::UndeclaredImport(name) => write!(formatter, "UNDECLARED_IMPORT:{name}"),
            Self::CapabilityNotGranted(capability) => {
                write!(formatter, "CAPABILITY_NOT_GRANTED:{capability}")
            }
            Self::GovernorAuthorizationRequired(capability) => {
                write!(formatter, "GOVERNOR_AUTHORIZATION_REQUIRED:{capability}")
            }
            Self::HostCallLimitExceeded(reason) => {
                write!(formatter, "HOST_CALL_LIMIT_EXCEEDED:{reason}")
            }
            Self::ContourNotServedHere(contour) => {
                write!(formatter, "CONTOUR_NOT_SERVED_HERE:{contour}")
            }
            Self::AdmittedDigestMismatch(which) => {
                write!(formatter, "ADMITTED_DIGEST_MISMATCH:{which}")
            }
            Self::ComponentNotAdmitted(component) => {
                write!(formatter, "COMPONENT_NOT_ADMITTED:{component}")
            }
            Self::InputLimitExceeded(detail) => {
                write!(formatter, "INPUT_LIMIT_EXCEEDED:{detail}")
            }
        }
    }
}

impl std::error::Error for ContourGateError {}

/// Minimal admitted-prototype fact: contour, world, and target. Admission
/// mints no authority, state, or routes; activation still requires the
/// Kernel/Governor generation cutover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedPrototype {
    /// Admitted execution contour.
    pub contour: Contour,
    /// Admitted world name.
    pub world: String,
    /// Admitted guest target.
    pub target: String,
}

/// Prototype-admission gate.
///
/// A prototype without a [`PrototypeContourDecision`] is rejected before
/// anything else is inspected. A non-default contour requires its explicit
/// rationale; the manifest must validate against the admitted baseline.
pub fn admit_prototype(
    decision: Option<&PrototypeContourDecision>,
    manifest: &GenerationManifest,
) -> Result<AdmittedPrototype, ContourGateError> {
    let Some(decision) = decision else {
        return Err(ContourGateError::MissingDecision);
    };
    match &decision.contour {
        Contour::WasmComponent => {}
        Contour::IsolatedNativeProcess => {
            let reasoned = decision
                .rationale
                .as_deref()
                .is_some_and(|reason| !reason.trim().is_empty());
            if !reasoned {
                return Err(ContourGateError::NativeReasonRequired);
            }
        }
        Contour::StaticNative => {
            return Err(ContourGateError::StaticNativeNotFirstContour);
        }
    }
    manifest.validate()?;
    Ok(AdmittedPrototype {
        contour: decision.contour.clone(),
        world: manifest.world.clone(),
        target: manifest.target.clone(),
    })
}

/// Maps an actual component import to the capability grant that gates it.
/// Returns `None` for imports that carry no host-effect capability.
fn capability_for_import(import: &str) -> Option<&'static str> {
    if import.starts_with("wasi:filesystem/") || import.starts_with("fs.") {
        Some(FS_CAPABILITY)
    } else if import.starts_with("wasi:sockets/") || import.starts_with("net.") {
        Some(NET_CAPABILITY)
    } else {
        None
    }
}

fn bounded(value: &str) -> String {
    value.chars().take(MAX_NAME_BYTES).collect()
}

/// Pre-activation import check: every actual component import observed before
/// instantiation must be declared in the manifest, and every
/// capability-gated import (filesystem/network) must additionally hold a
/// manifest grant. Runs before any instantiation or invocation.
pub fn check_activation_imports(
    manifest: &GenerationManifest,
    actual_imports: &[String],
) -> Result<(), ContourGateError> {
    for import in actual_imports {
        if !manifest.declares_import(import) {
            return Err(ContourGateError::UndeclaredImport(bounded(import)));
        }
        if let Some(capability) = capability_for_import(import)
            && !manifest.grants(capability)
        {
            return Err(ContourGateError::CapabilityNotGranted(
                capability.to_owned(),
            ));
        }
    }
    Ok(())
}

/// Bound admission evidence for one prototype generation.
///
/// Constructible only through [`admit_generation`] (or
/// [`admit_generation_with_bytes`]), which runs the full pre-activation
/// sequence (decision presence, contour rationale and first-contour rule,
/// manifest baseline validation, actual-import declaration and grant checks,
/// and — in the bytes entry — digest recomputation from real bytes) before
/// binding. Field privacy means a value of this type proves the sequence
/// ran; callers read the bound identities through the accessors below.
/// Dispatch sites additionally match the caller request against the bound
/// component and input envelope via [`check_admitted_request`] before any
/// Wasmtime invoke.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedGeneration {
    contour: Contour,
    world: String,
    target: String,
    artifact_digest: Sha256Digest,
    wit_digest: Sha256Digest,
    component_id: String,
    limits: InvocationLimits,
}

impl AdmittedGeneration {
    /// Admitted execution contour. Only [`Contour::WasmComponent`] is
    /// served by this host; any other value must be refused at dispatch.
    #[must_use]
    pub const fn contour(&self) -> &Contour {
        &self.contour
    }

    /// Admitted world name bound from the validated manifest.
    #[must_use]
    pub fn world(&self) -> &str {
        &self.world
    }

    /// Admitted guest target bound from the validated manifest.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Artifact digest bound from the validated manifest.
    #[must_use]
    pub const fn artifact_digest(&self) -> &Sha256Digest {
        &self.artifact_digest
    }

    /// WIT digest bound from the validated manifest.
    #[must_use]
    pub const fn wit_digest(&self) -> &Sha256Digest {
        &self.wit_digest
    }

    /// Admitted component identity bound from the validated manifest.
    /// Dispatch matches the caller request component against exactly this.
    #[must_use]
    pub fn component_id(&self) -> &str {
        &self.component_id
    }

    /// Admitted per-invocation limit envelope bound from the validated
    /// manifest. Dispatch matches the caller input envelope against exactly
    /// this before any Wasmtime invoke.
    #[must_use]
    pub const fn limits(&self) -> &InvocationLimits {
        &self.limits
    }
}

/// Actual contour admission: the full pre-activation sequence in one entry
/// point. A prototype without a contour decision is rejected before
/// anything else is inspected; the contour rationale and first-contour rule
/// apply next; then the manifest baseline; then every actual component
/// import observed before instantiation. Success binds the admitted
/// contour, world, target, and digests into an [`AdmittedGeneration`] that
/// dispatch sites match against before serving.
pub fn admit_generation(
    decision: Option<&PrototypeContourDecision>,
    manifest: &GenerationManifest,
    actual_imports: &[String],
) -> Result<AdmittedGeneration, ContourGateError> {
    let admitted = admit_prototype(decision, manifest)?;
    check_activation_imports(manifest, actual_imports)?;
    Ok(AdmittedGeneration {
        contour: admitted.contour,
        world: admitted.world,
        target: admitted.target,
        artifact_digest: manifest.artifact_digest.clone(),
        wit_digest: manifest.wit_digest.clone(),
        component_id: manifest.component_id.clone(),
        limits: manifest.limits.clone(),
    })
}

/// Byte-verified contour admission: `admit_generation` plus recomputation
/// of the manifest's artifact/interface digests from the supplied real
/// bytes. A manifest claim that does not match its bytes fails closed
/// here — digest claims are never trusted without the bytes they name.
/// Fence/epoch freshness is NOT minted here: it stays with Governor/Kernel
/// authority and is enforced pre-invoke inside the A-12 execution path
/// (`StaleFence` and coherence gates), which this host never duplicates.
pub fn admit_generation_with_bytes(
    decision: Option<&PrototypeContourDecision>,
    manifest: &GenerationManifest,
    actual_imports: &[String],
    artifact_bytes: &[u8],
    wit_bytes: &[u8],
) -> Result<AdmittedGeneration, ContourGateError> {
    if artifact_bytes.is_empty() || wit_bytes.is_empty() {
        return Err(ContourGateError::AdmittedDigestMismatch(
            "empty-bytes".to_owned(),
        ));
    }
    if Sha256Digest::of_bytes(artifact_bytes) != manifest.artifact_digest {
        return Err(ContourGateError::AdmittedDigestMismatch(
            "artifact".to_owned(),
        ));
    }
    if Sha256Digest::of_bytes(wit_bytes) != manifest.wit_digest {
        return Err(ContourGateError::AdmittedDigestMismatch(
            "interface".to_owned(),
        ));
    }
    admit_generation(decision, manifest, actual_imports)
}

/// Dispatch gate: matches one caller request against the bound admission
/// before any Wasmtime invoke. Contour, component, and input envelope are
/// all caller-observable here; artifact/interface/world/target digests were
/// byte-verified at admission and are enforced at invoke by the engine and
/// Governor coherence inside the execution path. Any mismatch fails closed
/// with a host-taxonomy error — no A-12 port is contacted on denial.
pub fn check_admitted_request(
    admitted: &AdmittedGeneration,
    request: &InvocationRequest,
) -> Result<(), ContourGateError> {
    if *admitted.contour() != Contour::WasmComponent {
        return Err(ContourGateError::ContourNotServedHere(
            admitted.contour().to_string(),
        ));
    }
    if request.component_id.as_str() != admitted.component_id() {
        return Err(ContourGateError::ComponentNotAdmitted(bounded(
            request.component_id.as_str(),
        )));
    }
    if request.input.len() as u64 > admitted.limits().max_input_bytes {
        return Err(ContourGateError::InputLimitExceeded(
            "input-bytes".to_owned(),
        ));
    }
    Ok(())
}

/// Authorizes one host-call proposal under the manifest grant and Governor
/// authorization. An ungranted filesystem/network capability is uncallable;
/// a granted capability without Governor authorization stays denied; the
/// proposal must fit the generation input-byte envelope.
pub fn authorize_host_call(
    manifest: &GenerationManifest,
    grant: &GovernorGrant,
    proposal: &HostCallProposal,
) -> Result<AuthorizedHostCall, ContourGateError> {
    if !manifest.grants(&proposal.capability) {
        return Err(ContourGateError::CapabilityNotGranted(
            proposal.capability.clone(),
        ));
    }
    if !grant.authorizes(&proposal.capability) {
        return Err(ContourGateError::GovernorAuthorizationRequired(
            proposal.capability.clone(),
        ));
    }
    if proposal.input_bytes > manifest.limits.max_input_bytes {
        return Err(ContourGateError::HostCallLimitExceeded(
            "input-bytes".to_owned(),
        ));
    }
    Ok(AuthorizedHostCall {
        capability: proposal.capability.clone(),
        input_digest: proposal.input_digest.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use eliot_wasm_runtime::{ArtifactAccessLimits, CancellationPolicy, EpochPolicy};

    use super::*;
    use crate::typed_bindings::{TYPED_PACKAGE_ID, typed_wit_digest};

    fn test_limits() -> InvocationLimits {
        InvocationLimits {
            max_input_bytes: 64,
            max_output_bytes: 1024,
            max_host_calls: 2,
            max_fuel: 10_000,
            max_memory_bytes: 65_536,
            max_table_elements: 8,
            max_instances: 1,
            max_stack_bytes: 8 * 1024,
            wall_deadline_ms: 500,
            epoch: EpochPolicy {
                deadline_ticks: 100,
                cancellation: CancellationPolicy::EpochAndFuel,
            },
            artifact_access: ArtifactAccessLimits {
                allowed_digests: BTreeSet::new(),
                max_reads: 1,
                max_bytes: 8 * 1024 * 1024,
            },
        }
    }

    fn closed_manifest() -> GenerationManifest {
        GenerationManifest {
            component_id: "context-admission-component".to_owned(),
            target: STANDARD_GUEST_TARGET.to_owned(),
            artifact_digest: Sha256Digest::of_bytes(b"fixture-component"),
            wit_digest: typed_wit_digest(),
            world: "context-admission".to_owned(),
            allowed_imports: Vec::new(),
            allowed_exports: vec!["admission".to_owned()],
            capability_grants: Vec::new(),
            limits: test_limits(),
            state_class: "stateless".to_owned(),
            migration_contract: "none".to_owned(),
            privacy_policy: "project_code".to_owned(),
            comparator: "shadow-exact".to_owned(),
            rollback_generation: Some("gen-41".to_owned()),
        }
    }

    fn empty_grant() -> GovernorGrant {
        GovernorGrant::new(Vec::new(), "gen-42".to_owned())
    }

    #[test]
    fn pinned_engine_and_standard_target_identities() {
        // The workspace pin is exact (`wasmtime = "=47.0.4"`); the lockfile
        // entry proves the linked generation matches the contour constant.
        let lockfile = include_str!("../../../Cargo.lock").replace("\r\n", "\n");
        let pinned = format!("name = \"wasmtime\"\nversion = \"{PINNED_WASMTIME_VERSION}\"");
        assert!(
            lockfile.contains(&pinned),
            "wasmtime lockfile entry must match PINNED_WASMTIME_VERSION"
        );
        assert_eq!(STANDARD_GUEST_TARGET, "wasm32-wasip2");
        assert_eq!(TYPED_PACKAGE_ID, "eliot:current@0.1.0");
        let manifest = closed_manifest();
        assert_eq!(manifest.wit_digest, typed_wit_digest());
        assert_eq!(manifest.target, STANDARD_GUEST_TARGET);
    }

    #[test]
    fn prototype_without_decision_is_rejected() {
        let manifest = closed_manifest();
        assert_eq!(
            admit_prototype(None, &manifest),
            Err(ContourGateError::MissingDecision)
        );
        assert_eq!(
            ContourGateError::MissingDecision.to_string(),
            "CONTOUR_DECISION_REQUIRED"
        );
    }

    #[test]
    fn normal_prototype_defaults_to_wasm() {
        assert_eq!(
            PrototypeContourDecision::default().contour,
            Contour::WasmComponent
        );
        assert_eq!(
            PrototypeContourDecision::default_for_new_prototype().contour,
            Contour::WasmComponent
        );
        let decision = PrototypeContourDecision::default();
        let manifest = closed_manifest();
        let admitted = admit_prototype(Some(&decision), &manifest);
        assert!(matches!(
            admitted,
            Ok(AdmittedPrototype {
                contour: Contour::WasmComponent,
                ..
            })
        ));
    }

    #[test]
    fn non_default_contours_require_explicit_reason() {
        assert_eq!(
            PrototypeContourDecision::select_native_process(""),
            Err(ContourGateError::NativeReasonRequired)
        );
        assert_eq!(
            PrototypeContourDecision::select_native_process("  "),
            Err(ContourGateError::NativeReasonRequired)
        );
        let native =
            PrototypeContourDecision::select_native_process("requires raw filesystem scan");
        assert!(matches!(
            native,
            Ok(PrototypeContourDecision {
                contour: Contour::IsolatedNativeProcess,
                ..
            })
        ));
        let manifest = closed_manifest();
        let admitted = admit_prototype(native.as_ref().ok(), &manifest);
        assert!(matches!(
            admitted,
            Ok(AdmittedPrototype {
                contour: Contour::IsolatedNativeProcess,
                ..
            })
        ));
        let bare_native = PrototypeContourDecision {
            contour: Contour::IsolatedNativeProcess,
            rationale: None,
        };
        assert_eq!(
            admit_prototype(Some(&bare_native), &manifest),
            Err(ContourGateError::NativeReasonRequired)
        );
        let static_native = PrototypeContourDecision {
            contour: Contour::StaticNative,
            rationale: Some("hot path".to_owned()),
        };
        assert_eq!(
            admit_prototype(Some(&static_native), &manifest),
            Err(ContourGateError::StaticNativeNotFirstContour)
        );
    }

    #[test]
    fn nonstandard_target_and_incomplete_manifest_fail_closed() {
        let decision = PrototypeContourDecision::default();
        let mut manifest = closed_manifest();
        manifest.target = "wasm32-wasip1".to_owned();
        assert!(matches!(
            admit_prototype(Some(&decision), &manifest),
            Err(ContourGateError::UnsupportedTarget(_))
        ));
        let mut manifest = closed_manifest();
        manifest.world = String::new();
        assert_eq!(
            admit_prototype(Some(&decision), &manifest),
            Err(ContourGateError::IncompleteManifest("world".to_owned()))
        );
    }

    #[test]
    fn undeclared_import_is_rejected_before_activation() {
        let manifest = closed_manifest();
        assert_eq!(
            check_activation_imports(&manifest, &["wasi:filesystem/types".to_owned()]),
            Err(ContourGateError::UndeclaredImport(
                "wasi:filesystem/types".to_owned()
            ))
        );
        assert_eq!(check_activation_imports(&manifest, &[]), Ok(()));
    }

    #[test]
    fn declared_but_ungranted_fs_import_is_uncallable() {
        let mut manifest = closed_manifest();
        manifest
            .allowed_imports
            .push("wasi:filesystem/types".to_owned());
        // Declared yet ungranted: capability gate still denies pre-activation.
        assert_eq!(
            check_activation_imports(&manifest, &["wasi:filesystem/types".to_owned()]),
            Err(ContourGateError::CapabilityNotGranted(
                FS_CAPABILITY.to_owned()
            ))
        );
        manifest.capability_grants.push(FS_CAPABILITY.to_owned());
        assert_eq!(
            check_activation_imports(&manifest, &["wasi:filesystem/types".to_owned()]),
            Ok(())
        );
    }

    #[test]
    fn ungranted_fs_and_net_host_calls_are_uncallable() {
        let manifest = closed_manifest();
        let grant = empty_grant();
        let fs = HostCallProposal::new(
            FS_CAPABILITY.to_owned(),
            16,
            Sha256Digest::of_bytes(b"fs-input"),
        );
        let net = HostCallProposal::new(
            NET_CAPABILITY.to_owned(),
            16,
            Sha256Digest::of_bytes(b"net-input"),
        );
        assert_eq!(
            authorize_host_call(&manifest, &grant, &fs),
            Err(ContourGateError::CapabilityNotGranted(
                FS_CAPABILITY.to_owned()
            ))
        );
        assert_eq!(
            authorize_host_call(&manifest, &grant, &net),
            Err(ContourGateError::CapabilityNotGranted(
                NET_CAPABILITY.to_owned()
            ))
        );
    }

    #[test]
    fn granted_capability_still_requires_governor_authorization() {
        let mut manifest = closed_manifest();
        manifest.capability_grants.push(FS_CAPABILITY.to_owned());
        let proposal = HostCallProposal::new(
            FS_CAPABILITY.to_owned(),
            16,
            Sha256Digest::of_bytes(b"fs-input"),
        );
        assert_eq!(
            authorize_host_call(&manifest, &empty_grant(), &proposal),
            Err(ContourGateError::GovernorAuthorizationRequired(
                FS_CAPABILITY.to_owned()
            ))
        );
        let grant = GovernorGrant::new(vec![FS_CAPABILITY.to_owned()], "gen-42".to_owned());
        let authorized = authorize_host_call(&manifest, &grant, &proposal);
        assert!(matches!(
            authorized,
            Ok(AuthorizedHostCall {
                capability,
                ..
            }) if capability == FS_CAPABILITY
        ));
        let oversized = HostCallProposal::new(
            FS_CAPABILITY.to_owned(),
            manifest.limits.max_input_bytes + 1,
            Sha256Digest::of_bytes(b"too-large"),
        );
        assert_eq!(
            authorize_host_call(&manifest, &grant, &oversized),
            Err(ContourGateError::HostCallLimitExceeded(
                "input-bytes".to_owned()
            ))
        );
    }

    #[test]
    fn admission_binds_contour_world_target_and_digests() {
        let decision = PrototypeContourDecision::default();
        let manifest = closed_manifest();
        let admitted = match admit_generation(Some(&decision), &manifest, &[]) {
            Ok(admitted) => admitted,
            Err(error) => panic!("admission failed: {error:?}"),
        };
        assert_eq!(admitted.contour(), &Contour::WasmComponent);
        assert_eq!(admitted.world(), "context-admission");
        assert_eq!(admitted.target(), STANDARD_GUEST_TARGET);
        assert_eq!(
            admitted.artifact_digest(),
            &Sha256Digest::of_bytes(b"fixture-component")
        );
        assert_eq!(admitted.wit_digest(), &typed_wit_digest());
    }

    #[test]
    fn admission_rejects_in_gate_order() {
        let manifest = closed_manifest();
        // Missing decision wins over every other defect.
        let mut broken = manifest.clone();
        broken.target = "wasm32-wasip1".to_owned();
        assert_eq!(
            admit_generation(None, &broken, &[]),
            Err(ContourGateError::MissingDecision)
        );
        // Static native is rejected even with a valid manifest.
        let decision = PrototypeContourDecision::default();
        let static_native = PrototypeContourDecision {
            contour: Contour::StaticNative,
            rationale: Some("hot path".to_owned()),
        };
        assert_eq!(
            admit_generation(Some(&static_native), &manifest, &[]),
            Err(ContourGateError::StaticNativeNotFirstContour)
        );
        // Undeclared actual imports fail the composed admission.
        assert_eq!(
            admit_generation(
                Some(&decision),
                &manifest,
                &["wasi:filesystem/types".to_owned()]
            ),
            Err(ContourGateError::UndeclaredImport(
                "wasi:filesystem/types".to_owned()
            ))
        );
        // A bare native decision without rationale fails the composer.
        let bare_native = PrototypeContourDecision {
            contour: Contour::IsolatedNativeProcess,
            rationale: None,
        };
        assert_eq!(
            admit_generation(Some(&bare_native), &manifest, &[]),
            Err(ContourGateError::NativeReasonRequired)
        );
    }

    #[test]
    fn native_admission_records_reason_for_dispatch() {
        let manifest = closed_manifest();
        let native = match PrototypeContourDecision::select_native_process("needs raw USB scan") {
            Ok(decision) => decision,
            Err(error) => panic!("native decision failed: {error:?}"),
        };
        let admitted = match admit_generation(Some(&native), &manifest, &[]) {
            Ok(admitted) => admitted,
            Err(error) => panic!("native admission failed: {error:?}"),
        };
        assert_eq!(admitted.contour(), &Contour::IsolatedNativeProcess);
        assert_eq!(admitted.world(), "context-admission");
    }

    fn bytes_manifest() -> (GenerationManifest, Vec<u8>, Vec<u8>) {
        let artifact = b"unit-artifact-bytes".to_vec();
        let wit = b"unit-wit-bytes".to_vec();
        let mut manifest = closed_manifest();
        manifest.artifact_digest = Sha256Digest::of_bytes(&artifact);
        manifest.wit_digest = Sha256Digest::of_bytes(&wit);
        (manifest, artifact, wit)
    }

    #[test]
    fn admission_verifies_digests_from_real_bytes() {
        let (manifest, artifact, wit) = bytes_manifest();
        let decision = PrototypeContourDecision::default();
        let admitted =
            match admit_generation_with_bytes(Some(&decision), &manifest, &[], &artifact, &wit) {
                Ok(admitted) => admitted,
                Err(error) => panic!("byte-verified admission failed: {error:?}"),
            };
        assert_eq!(admitted.artifact_digest(), &manifest.artifact_digest);
        assert_eq!(admitted.wit_digest(), &manifest.wit_digest);
        assert_eq!(admitted.component_id(), manifest.component_id.as_str());
        assert_eq!(
            admitted.limits().max_input_bytes,
            manifest.limits.max_input_bytes
        );
    }

    #[test]
    fn admission_rejects_digest_mismatch_and_empty_bytes() {
        let (manifest, artifact, wit) = bytes_manifest();
        let decision = PrototypeContourDecision::default();
        let mut tampered = artifact.clone();
        tampered[0] ^= 0xFF;
        assert_eq!(
            admit_generation_with_bytes(Some(&decision), &manifest, &[], &tampered, &wit),
            Err(ContourGateError::AdmittedDigestMismatch(
                "artifact".to_owned()
            ))
        );
        let mut tampered_wit = wit.clone();
        tampered_wit[0] ^= 0xFF;
        assert_eq!(
            admit_generation_with_bytes(Some(&decision), &manifest, &[], &artifact, &tampered_wit),
            Err(ContourGateError::AdmittedDigestMismatch(
                "interface".to_owned()
            ))
        );
        assert_eq!(
            admit_generation_with_bytes(Some(&decision), &manifest, &[], &[], &wit),
            Err(ContourGateError::AdmittedDigestMismatch(
                "empty-bytes".to_owned()
            ))
        );
        assert_eq!(
            ContourGateError::AdmittedDigestMismatch("artifact".to_owned()).to_string(),
            "ADMITTED_DIGEST_MISMATCH:artifact"
        );
    }
}
