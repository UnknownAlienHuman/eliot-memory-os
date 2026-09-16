//! Bounded contract kits and context/test capsules for typed components.
//!
//! A [`ModuleContractKit`] binds one package, world, ABI and native
//! contract with the exact declared import/export identity, artifact,
//! policy and resource compatibility, state model, and proof ceiling. A
//! guest descriptor alone is insufficient evidence; actual type and import
//! evidence arrives through the injected provider and is checked by
//! [`ModuleContractKit::check_invocation`] before any call reaches the
//! engine. [`invoke_typed`] performs that check and then calls the injected
//! [`ComponentEnginePort`] through the real neutral API, so a standalone
//! capsule exercises the exact provider path without any workspace,
//! network, Kernel, Store, or Host-binary dependence.
//!
//! [`CrateContextCapsule`] carries only exact cell, source, and public
//! interface facts with bounded measured excerpts; a scan universe is never
//! loaded context. [`ModuleTestCapsule`] binds one kit, component, world,
//! and stage so build, ABI, instantiation, invocation, result, parity, and
//! receipt proofs stay separate.
//!
//! [`ComponentEnginePort`]: crate::ports::ComponentEnginePort

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::component_contract::{
    ProofCeiling, TYPED_ABI_REVISION, TYPED_ENGINE_IMPLEMENTATION, TYPED_ENGINE_VERSION,
    TYPED_PACKAGE_ID, TypedContractError, TypedWorld, validate_observed,
};
use crate::ports::{ComponentEnginePort, PortError};
use crate::types::{
    CapabilityId, EngineInvocation, EngineReport, Sha256Digest, canonical_digest, validate_text,
};

/// Artifact carriage ceiling matching the Host preflight bound. The kit
/// pins one exact artifact; this bound only rejects absurd lengths before
/// Governor limits apply.
pub const MAX_KIT_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CAPSULE_TEXT_BYTES: usize = 512;
/// Carriage bound for a single measured excerpt.
pub const MAX_CAPSULE_EXCERPT_BYTES: usize = 4_096;
/// Carriage bound for all excerpts carried by one context capsule.
pub const MAX_CAPSULE_TOTAL_BYTES: usize = 64 * 1_024;

/// Deterministic contract kit binding one package, world, ABI, and native
/// contract with exact declared import/export identity, artifact, state
/// model, and proof ceiling. Guest descriptors alone never satisfy a kit;
/// provider-observed evidence must match exactly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleContractKit {
    pub package_id: String,
    pub world: TypedWorld,
    pub abi: crate::component_contract::AbiDescriptor,
    pub artifact_digest: Sha256Digest,
    pub artifact_len: u64,
    pub interface_digest: Sha256Digest,
    pub declared_imports: Vec<String>,
    pub declared_exports: Vec<String>,
    pub state_contract_digest: Sha256Digest,
    pub proof_ceiling: ProofCeiling,
    /// True for governed admission; false marks an explicitly selected
    /// local experiment whose results stay non-governed.
    pub governed: bool,
}

impl ModuleContractKit {
    /// Validates the kit binding. Typed worlds declare zero ambient
    /// imports and exactly one interface export; any other combination is
    /// rejected, as are unknown packages, revisions, and empty digests.
    pub fn validate(&self) -> Result<(), TypedContractError> {
        if self.package_id != TYPED_PACKAGE_ID {
            return Err(TypedContractError::InvalidKit("package".to_owned()));
        }
        if self.abi.package_id != TYPED_PACKAGE_ID
            || self.abi.world_name != self.world.world_name()
            || self.abi.abi_revision != TYPED_ABI_REVISION
        {
            return Err(TypedContractError::InvalidKit("abi".to_owned()));
        }
        self.abi
            .validate_for(self.world)
            .map_err(|_| TypedContractError::InvalidKit("abi".to_owned()))?;
        if self.artifact_len == 0 || self.artifact_len > MAX_KIT_ARTIFACT_BYTES {
            return Err(TypedContractError::InvalidKit("artifact".to_owned()));
        }
        if !self.declared_imports.is_empty() {
            return Err(TypedContractError::ImportMismatch);
        }
        let single_export = self.declared_exports.first().map(String::as_str);
        if self.declared_exports.len() != 1
            || single_export != Some(self.world.interface_name())
        {
            return Err(TypedContractError::ExportMismatch);
        }
        Ok(())
    }

    /// Returns the deterministic kit digest over every bound field. The
    /// digest is computed on demand and never part of the hashed payload,
    /// so no self-referential digest exists. No capability is invented:
    /// every byte hashed was supplied by the Governor-admitted kit.
    pub fn digest(&self) -> Result<Sha256Digest, TypedContractError> {
        canonical_digest(self)
            .map_err(|error| TypedContractError::Serialization(error.to_string()))
    }

    /// Checks one sealed engine invocation against this kit: exact world,
    /// artifact, interface, engine binding, declared import/export
    /// identity, and input admission bound. Failure never reaches the
    /// engine.
    pub fn check_invocation(
        &self,
        invocation: &EngineInvocation,
    ) -> Result<(), TypedContractError> {
        self.validate()?;
        if invocation.manifest.world.as_str() != self.world.world_name() {
            return Err(TypedContractError::WorldMismatch {
                want: self.world.world_name().to_owned(),
                got: invocation.manifest.world.as_str().to_owned(),
            });
        }
        if invocation.manifest.artifact_digest != self.artifact_digest {
            return Err(TypedContractError::ArtifactMismatch);
        }
        if invocation.manifest.interface_digest != self.interface_digest {
            return Err(TypedContractError::InterfaceMismatch);
        }
        let actual_imports: Vec<String> = invocation
            .imports
            .iter()
            .map(CapabilityId::as_str)
            .map(str::to_owned)
            .collect();
        let actual_exports: Vec<String> = invocation
            .exports
            .iter()
            .map(CapabilityId::as_str)
            .map(str::to_owned)
            .collect();
        let observed = crate::component_contract::AbiDescriptor::new(
            self.world,
            self.abi.native_contract.clone(),
            self.abi.native_revision.clone(),
            self.abi.abi_digest.clone(),
        )
        .map_err(|_| TypedContractError::InvalidKit("abi".to_owned()))?;
        validate_observed(
            &observed,
            &observed,
            &invocation.manifest.engine,
            &actual_imports,
            &self.declared_imports,
            &actual_exports,
            &self.declared_exports,
        )?;
        if invocation.manifest.engine.implementation_id != TYPED_ENGINE_IMPLEMENTATION
            || invocation.manifest.engine.exact_version != TYPED_ENGINE_VERSION
        {
            return Err(TypedContractError::EngineMismatch);
        }
        let input_len = u64::try_from(invocation.input.len())
            .map_err(|_| TypedContractError::LimitDenied)?;
        if input_len > invocation.limits.max_input_bytes {
            return Err(TypedContractError::LimitDenied);
        }
        Ok(())
    }
}

/// Invokes one kit-checked invocation through the injected provider using
/// the real neutral [`ComponentEnginePort`] API, then validates the report
/// envelope: the request digest must match and the observed output must fit
/// the admitted ceiling. Port failures keep their typed classification.
pub fn invoke_typed(
    engine: &mut dyn ComponentEnginePort,
    kit: &ModuleContractKit,
    invocation: &EngineInvocation,
) -> Result<EngineReport, TypedContractError> {
    kit.check_invocation(invocation)?;
    let report = engine.invoke(invocation).map_err(|error| match error {
        PortError::Denied => TypedContractError::EngineDenied,
        PortError::Unavailable => TypedContractError::EngineUnavailable,
        PortError::UnknownOutcome => TypedContractError::EngineUnknown,
    })?;
    if report.request_digest != invocation.request_digest {
        return Err(TypedContractError::ReportMismatch);
    }
    let output_len =
        u64::try_from(report.output.len()).map_err(|_| TypedContractError::ReportMismatch)?;
    if output_len > invocation.limits.max_output_bytes {
        return Err(TypedContractError::LimitDenied);
    }
    Ok(report)
}

/// One bounded measured excerpt carried by a context capsule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleExcerpt {
    /// Owned source path the excerpt was measured from.
    pub path: String,
    /// Exact measured bytes, bounded by [`MAX_CAPSULE_EXCERPT_BYTES`].
    pub content: Vec<u8>,
}

impl CapsuleExcerpt {
    /// Creates a bounded excerpt without loading anything else.
    pub fn new(path: String, content: Vec<u8>) -> Result<Self, TypedContractError> {
        validate_text(&path, "excerpt.path")
            .map_err(|_| TypedContractError::InvalidCapsule("excerpt-path".to_owned()))?;
        if content.is_empty() || content.len() > MAX_CAPSULE_EXCERPT_BYTES {
            return Err(TypedContractError::InvalidCapsule("excerpt-bytes".to_owned()));
        }
        Ok(Self { path, content })
    }
}

/// Bounded crate context: exact cell, source, and public interface facts
/// with the required documentation handles, path allow- and deny-lists,
/// capabilities, toolchain, inert build/test descriptions, challenges,
/// owners, and bounded measured excerpts. Unknown measurement cannot
/// certify fit: [`TypedCompleteness`](crate::component_contract::TypedCompleteness)
/// is `Complete` only when nothing is omitted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrateContextCapsule {
    pub cell: String,
    pub source_revision: String,
    pub public_interfaces: Vec<String>,
    pub doc_handles: Vec<String>,
    pub owned_paths: Vec<String>,
    pub forbidden_paths: Vec<String>,
    pub capabilities: Vec<String>,
    pub toolchain: String,
    pub target: String,
    pub build_description: String,
    pub test_description: String,
    pub challenges: Vec<String>,
    pub integration_owners: Vec<String>,
    pub excerpts: Vec<CapsuleExcerpt>,
    pub omissions: Vec<String>,
    pub completeness: crate::component_contract::TypedCompleteness,
}

impl CrateContextCapsule {
    /// Validates bounds, required handles, path containment, and the
    /// completeness contract. Every excerpt must sit under an owned path
    /// and outside every forbidden path, so secret or unbounded repository
    /// content is structurally excluded: only explicitly carried bytes are
    /// context.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), TypedContractError> {
        for (value, field) in [
            (&self.cell, "cell"),
            (&self.source_revision, "source-revision"),
            (&self.toolchain, "toolchain"),
            (&self.target, "target"),
            (&self.build_description, "build-description"),
            (&self.test_description, "test-description"),
        ] {
            if value.trim().is_empty()
                || value.len() > MAX_CAPSULE_TEXT_BYTES
                || value.chars().any(char::is_control)
            {
                return Err(TypedContractError::InvalidCapsule(field.to_owned()));
            }
        }
        if self.doc_handles.is_empty() {
            return Err(TypedContractError::InvalidCapsule("doc-handles".to_owned()));
        }
        for list in [
            &self.public_interfaces,
            &self.doc_handles,
            &self.owned_paths,
            &self.capabilities,
            &self.challenges,
            &self.integration_owners,
            &self.omissions,
        ] {
            for entry in list {
                validate_text(entry, "capsule.entry")
                    .map_err(|_| TypedContractError::InvalidCapsule("capsule-entry".to_owned()))?;
            }
        }
        if self.owned_paths.is_empty() {
            return Err(TypedContractError::InvalidCapsule("owned-paths".to_owned()));
        }
        let mut total: usize = 0;
        for excerpt in &self.excerpts {
            validate_text(&excerpt.path, "excerpt.path")
                .map_err(|_| TypedContractError::InvalidCapsule("excerpt-path".to_owned()))?;
            if excerpt.content.is_empty() || excerpt.content.len() > MAX_CAPSULE_EXCERPT_BYTES {
                return Err(TypedContractError::InvalidCapsule("excerpt-bytes".to_owned()));
            }
            total = total
                .checked_add(excerpt.content.len())
                .ok_or_else(|| TypedContractError::InvalidCapsule("excerpt-total".to_owned()))?;
            if total > MAX_CAPSULE_TOTAL_BYTES {
                return Err(TypedContractError::InvalidCapsule("excerpt-total".to_owned()));
            }
            if !self
                .owned_paths
                .iter()
                .any(|owned| path_within(&excerpt.path, owned))
            {
                return Err(TypedContractError::InvalidCapsule("excerpt-owner".to_owned()));
            }
            if self
                .forbidden_paths
                .iter()
                .any(|denied| path_within(&excerpt.path, denied))
            {
                return Err(TypedContractError::InvalidCapsule("excerpt-forbidden".to_owned()));
            }
        }
        let complete = matches!(
            self.completeness,
            crate::component_contract::TypedCompleteness::Complete
        );
        if complete && !self.omissions.is_empty() {
            return Err(TypedContractError::InvalidCapsule("completeness".to_owned()));
        }
        if !complete
            && self.omissions.is_empty()
            && matches!(
                self.completeness,
                crate::component_contract::TypedCompleteness::Partial
            )
        {
            return Err(TypedContractError::InvalidCapsule("completeness".to_owned()));
        }
        Ok(())
    }
}

fn path_within(path: &str, root: &str) -> bool {
    path == root || path.starts_with(&format!("{root}/"))
}

/// Test capsule binding one exact kit, component, world, operation, stage,
/// fixture, expected result, input/policy/resource bounds, native oracle
/// identity, and limited output evidence. Each capsule binds a single
/// [`ProofStage`](crate::types::ProofStage) so build, ABI, instantiation,
/// invocation, result, parity, and receipt proofs stay separate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleTestCapsule {
    pub kit_digest: Sha256Digest,
    pub component: CapabilityId,
    pub world: TypedWorld,
    pub operation: String,
    pub stage: crate::types::ProofStage,
    pub fixture: Vec<u8>,
    pub expected: Vec<u8>,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_work: u64,
    pub oracle: String,
}

impl ModuleTestCapsule {
    /// Validates the binding: the operation must be the world's domain
    /// operation, the fixture and expected output must fit the declared
    /// bounds, ceilings must be non-zero, and the native oracle identity
    /// must be present. A wrong artifact, world, policy, or output fails
    /// here, before any provider call.
    pub fn validate(&self, kit: &ModuleContractKit) -> Result<(), TypedContractError> {
        if self.world != kit.world {
            return Err(TypedContractError::WorldMismatch {
                want: kit.world.world_name().to_owned(),
                got: self.world.world_name().to_owned(),
            });
        }
        if self.operation != self.world.domain_func() {
            return Err(TypedContractError::InvalidCapsule("operation".to_owned()));
        }
        if kit.digest()? != self.kit_digest {
            return Err(TypedContractError::ArtifactMismatch);
        }
        if self.max_input_bytes == 0 || self.max_output_bytes == 0 || self.max_work == 0 {
            return Err(TypedContractError::LimitDenied);
        }
        let fixture_len =
            u64::try_from(self.fixture.len()).map_err(|_| TypedContractError::LimitDenied)?;
        let expected_len =
            u64::try_from(self.expected.len()).map_err(|_| TypedContractError::LimitDenied)?;
        if fixture_len > self.max_input_bytes || expected_len > self.max_output_bytes {
            return Err(TypedContractError::LimitDenied);
        }
        validate_text(&self.oracle, "oracle")
            .map_err(|_| TypedContractError::InvalidCapsule("oracle".to_owned()))?;
        Ok(())
    }
}

#[cfg(test)]
mod capsule_tests {
    use super::*;

    fn kit(world: TypedWorld) -> Result<ModuleContractKit, TypedContractError> {
        Ok(ModuleContractKit {
            package_id: TYPED_PACKAGE_ID.to_owned(),
            world,
            abi: crate::component_contract::AbiDescriptor::new(
                world,
                "native-contract".to_owned(),
                "native-revision".to_owned(),
                Sha256Digest::of_bytes(b"abi"),
            )?,
            artifact_digest: Sha256Digest::of_bytes(b"artifact"),
            artifact_len: 64,
            interface_digest: Sha256Digest::of_bytes(b"interface"),
            declared_imports: Vec::new(),
            declared_exports: vec![world.interface_name().to_owned()],
            state_contract_digest: Sha256Digest::of_bytes(b"state"),
            proof_ceiling: ProofCeiling::CandidateOnly,
            governed: false,
        })
    }

    #[test]
    fn kit_digest_is_deterministic_and_invalid_combinations_fail() {
        let built = kit(TypedWorld::ContextAssembly);
        assert!(built.is_ok());
        if let Ok(first) = built {
            assert!(first.validate().is_ok());
            let second = kit(TypedWorld::ContextAssembly);
            assert_eq!(second, Ok(first.clone()));
            assert_eq!(first.digest(), first.digest());

        let mut wrong_package = first.clone();
        wrong_package.package_id = "other:package@9.9.9".to_owned();
        assert!(wrong_package.validate().is_err());

        let mut ambient_import = first.clone();
        ambient_import
            .declared_imports
            .push("wasi:filesystem/types".to_owned());
        assert_eq!(
            ambient_import.validate(),
            Err(TypedContractError::ImportMismatch)
        );

        let mut wrong_export = first.clone();
        wrong_export.declared_exports = vec!["run".to_owned()];
        assert_eq!(
            wrong_export.validate(),
            Err(TypedContractError::ExportMismatch)
        );

        let excerpt = CapsuleExcerpt::new("crates/a/src.rs".to_owned(), vec![1, 2, 3]);
        assert!(excerpt.is_ok());
        let oversized = CapsuleExcerpt::new(
            "crates/a/src.rs".to_owned(),
            vec![0; MAX_CAPSULE_EXCERPT_BYTES + 1],
        );
        assert_eq!(
            oversized,
            Err(TypedContractError::InvalidCapsule("excerpt-bytes".to_owned()))
        );
        }
    }
}
