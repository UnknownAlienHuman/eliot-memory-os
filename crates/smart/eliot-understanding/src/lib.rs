//! Deterministic owner for project-understanding context synthesis.
//!
//! This crate turns an already admitted, revision-fenced context read into a
//! decision-local understanding view.  It does not retrieve records, infer
//! facts, call a model, or persist projections.  Every emitted section is
//! reconstructed from the exact `ContextAtom` handles selected by the context
//! compiler, and omitted material remains visible in the synthesis manifest.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use blake3::Hasher;
use eliot_context::{
    AdmissionDisposition, CompiledContext, ContextAtom, ContextCompiler, ContextError,
    ContextInput, ContextRecipe, ContextRole,
};
use eliot_contracts::{ArtifactId, ContractVersion, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of this capability contract.
pub const CONTRACT_NAME: &str = "eliot.smart.understanding";
/// Wire revision of this capability contract.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Maximum number of independently rendered role sections.
pub const MAX_SECTIONS: usize = 9;

/// Errors raised before an understanding view may influence a decision.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum UnderstandingError {
    /// The underlying context contract rejected the read set or recipe.
    #[error("context compilation failed: {0}")]
    Context(#[from] ContextError),
    /// Duplicate identities would make provenance ambiguous.
    #[error("understanding input contains duplicate atom {0}")]
    DuplicateAtom(ArtifactId),
    /// A role required by the recipe was not represented after admission.
    #[error("required understanding role {0:?} was not represented")]
    MissingRole(ContextRole),
    /// The synthesis revision must remain tied to the input fence.
    #[error("understanding fence is incompatible with the compiled context")]
    FenceMismatch,
    /// A caller supplied a blank synthesis label.
    #[error("{0} must be non-blank and free of control characters")]
    InvalidText(&'static str),
}

fn text(value: &str, field: &'static str) -> Result<(), UnderstandingError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(UnderstandingError::InvalidText(field))
    } else {
        Ok(())
    }
}

/// Optional label used to make a packet section identifiable in traces.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnderstandingRequest {
    /// The already admitted context read set.
    pub input: ContextInput,
    /// Bounded role and total budgets for this synthesis.
    pub recipe: ContextRecipe,
    /// Stable caller-visible packet label.
    pub packet_label: String,
}

/// One role-preserving section of the synthesized understanding view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnderstandingSection {
    /// Semantic role of all units in this section.
    pub role: ContextRole,
    /// Complete units rendered in deterministic admission order.
    pub atom_ids: Vec<ArtifactId>,
    /// Handles supporting both complete units and their source lineage.
    pub source_handles: Vec<ArtifactId>,
    /// Header plus lossless bounded atom payloads.
    pub payload: String,
}

/// Exact provenance and omission manifest for one synthesis.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnderstandingManifest {
    /// Input task revision represented by the synthesis.
    pub revision: eliot_contracts::TaskRevision,
    /// Fence shared by every admitted unit.
    pub state_fence: StateFence,
    /// IDs that were rendered completely.
    pub included_atoms: Vec<ArtifactId>,
    /// IDs rendered as handles only.
    pub handle_only_atoms: Vec<ArtifactId>,
    /// IDs prevented from influencing the view.
    pub suppressed_atoms: Vec<ArtifactId>,
    /// Gaps supplied by the canonical owner or created by bounded admission.
    pub unknowns: Vec<String>,
}

/// Complete immutable result of understanding/context synthesis.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnderstandingView {
    /// Caller label, retained for packet and receipt correlation.
    pub packet_label: String,
    /// The exact context compiler result used as the source of truth.
    pub compiled: CompiledContext,
    /// Role sections preserving the context pyramid's semantic boundaries.
    pub sections: Vec<UnderstandingSection>,
    /// Rebuildable admission and provenance manifest.
    pub manifest: UnderstandingManifest,
    /// Stable digest over revision, admissions and rendered sections.
    pub synthesis_digest: String,
}

impl UnderstandingView {
    /// Whether the view has all roles needed for a safe decision-local packet.
    #[must_use]
    pub fn decision_ready(&self) -> bool {
        let quality = &self.compiled.quality;
        quality.goal_coverage
            && quality.epistemic_coverage
            && quality.provenance_coverage
            && quality.fence_coherent
            && quality.uncertainty_visible
            && quality.safety_coverage
            && quality.decision_readiness
    }

    /// Return exact source handles without changing section order.
    #[must_use]
    pub fn expansion_handles(&self) -> Vec<ArtifactId> {
        let mut handles = self.compiled.handle_only.clone();
        handles.extend(
            self.manifest
                .suppressed_atoms
                .iter()
                .filter(|id| !handles.contains(id))
                .cloned(),
        );
        handles.sort();
        handles.dedup();
        handles
    }
}

/// Stateless owner of deterministic understanding synthesis.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnderstandingSynthesizer;

impl UnderstandingSynthesizer {
    /// Compile context and synthesize role-preserving understanding.
    pub fn synthesize(
        request: &UnderstandingRequest,
    ) -> Result<UnderstandingView, UnderstandingError> {
        text(request.packet_label.as_str(), "packet_label")?;
        reject_duplicate_atoms(&request.input.atoms)?;
        let compiled = ContextCompiler::compile(&request.input, &request.recipe)?;
        validate_required_roles(&compiled, &request.input, &request.recipe)?;
        if !compiled
            .state_fence
            .is_compatible_with(&request.input.state_fence)
        {
            return Err(UnderstandingError::FenceMismatch);
        }

        let sections = render_sections(&compiled);
        let manifest = manifest(&compiled);
        let synthesis_digest = digest(request.packet_label.as_str(), &compiled, &sections);
        Ok(UnderstandingView {
            packet_label: request.packet_label.clone(),
            compiled,
            sections,
            manifest,
            synthesis_digest,
        })
    }
}

fn reject_duplicate_atoms(atoms: &[ContextAtom]) -> Result<(), UnderstandingError> {
    let mut seen = BTreeSet::new();
    for atom in atoms {
        if !seen.insert(atom.atom_id.clone()) {
            return Err(UnderstandingError::DuplicateAtom(atom.atom_id.clone()));
        }
    }
    Ok(())
}

fn validate_required_roles(
    compiled: &CompiledContext,
    input: &ContextInput,
    recipe: &ContextRecipe,
) -> Result<(), UnderstandingError> {
    for role in &recipe.required_roles {
        let represented = compiled.units.iter().any(|unit| unit.role == *role)
            || compiled.admissions.iter().any(|admission| {
                admission.disposition == AdmissionDisposition::HandleOnly
                    && compiled
                        .handle_only
                        .iter()
                        .any(|id| id == &admission.atom_id)
                    && input
                        .atoms
                        .iter()
                        .any(|atom| atom.atom_id == admission.atom_id && atom.role == *role)
            });
        if !represented {
            return Err(UnderstandingError::MissingRole(*role));
        }
    }
    Ok(())
}

fn render_sections(compiled: &CompiledContext) -> Vec<UnderstandingSection> {
    let mut sections = Vec::new();
    for role in [
        ContextRole::Goal,
        ContextRole::Attention,
        ContextRole::Evidence,
        ContextRole::Model,
        ContextRole::Continuity,
        ContextRole::Safety,
        ContextRole::Unknown,
        ContextRole::Affordance,
        ContextRole::DecisionTail,
    ] {
        let units = compiled
            .units
            .iter()
            .filter(|unit| unit.role == role)
            .collect::<Vec<_>>();
        if units.is_empty() {
            continue;
        }
        let mut atom_ids = Vec::with_capacity(units.len());
        let mut handles = BTreeSet::new();
        let mut payload = format!("[{role:?}]\n");
        for unit in units {
            atom_ids.push(unit.atom_id.clone());
            handles.extend(unit.source_handles.iter().cloned());
            payload.push_str(unit.payload.as_str());
            payload.push('\n');
        }
        sections.push(UnderstandingSection {
            role,
            atom_ids,
            source_handles: handles.into_iter().collect(),
            payload,
        });
    }
    sections
}

fn manifest(compiled: &CompiledContext) -> UnderstandingManifest {
    let mut included_atoms = Vec::new();
    let mut handle_only_atoms = Vec::new();
    let mut suppressed_atoms = Vec::new();
    for admission in &compiled.admissions {
        match admission.disposition {
            AdmissionDisposition::Included => included_atoms.push(admission.atom_id.clone()),
            AdmissionDisposition::HandleOnly | AdmissionDisposition::Revalidate => {
                handle_only_atoms.push(admission.atom_id.clone())
            }
            AdmissionDisposition::Suppressed | AdmissionDisposition::Quarantined => {
                suppressed_atoms.push(admission.atom_id.clone())
            }
        }
    }
    UnderstandingManifest {
        revision: compiled.revision,
        state_fence: compiled.state_fence.clone(),
        included_atoms,
        handle_only_atoms,
        suppressed_atoms,
        unknowns: compiled.unknowns.clone(),
    }
}

fn digest(label: &str, compiled: &CompiledContext, sections: &[UnderstandingSection]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(label.as_bytes());
    hasher.update(format!("{:?}", compiled.revision).as_bytes());
    hasher.update(format!("{:?}", compiled.state_fence).as_bytes());
    for admission in &compiled.admissions {
        hasher.update(admission.atom_id.to_string().as_bytes());
        hasher.update(format!("{:?}", admission.disposition).as_bytes());
    }
    for section in sections {
        hasher.update(format!("{:?}", section.role).as_bytes());
        hasher.update(section.payload.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}
