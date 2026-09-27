//! I1.9 Generation Registry: the Kernel/ORS-owned operational generation
//! record set.
//!
//! I1.9 splits "Module Registry" into three owners. The Module Catalog and its
//! desired-state intent belong to the Governor; this module owns only the
//! Generation Registry, which is installed/running/candidate operational
//! state, process handles, the Authority Epoch, route state, drain/checkpoint/
//! restart state and the immutable admitted execution manifest. It is a
//! technical execution projection, never desired-state policy.
//!
//! Storage restrictions enforced here by construction:
//!
//! * The record carries no project claim, no task meaning and no semantic
//!   policy decision. The admitted effect ceiling, restart class and allowed
//!   scopes are read out of the immutable [`KernelExecutionManifest`] copied
//!   from the Governor admission; the ORS never widens, reinterprets or
//!   re-authorizes them.
//! * The record carries no Canonical Store authority. The manifest's accepted
//!   Catalog/Policy revision and admission receipt are opaque references to a
//!   Governor admission, not authority the ORS grants or a canonical ordering
//!   head it advances.
//!
//! This module is pure domain logic: it owns no process, store handle, or
//! canonical memory, and it issues no admission of its own. Removing or
//! invalidating a Generation Registry record mutates only this registry; it
//! cannot reach the Governor-owned Module Catalog, and a Catalog policy change
//! cannot reach the live PID/Job Object handles recorded here.

use std::collections::BTreeMap;

use eliot_contracts::{AuthorityEpoch, ResourceGeneration};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::execution_manifest::KernelExecutionManifest;
use crate::model::{OrsError, validate_digest, validate_text};

/// Operational state of one installed module generation (I1.9).
///
/// The three values are the I1.9 operational vocabulary and are not
/// interchangeable: `Installed` is staged but not running, `Running` holds
/// live process handles, and `Candidate` is staged for a fenced cutover. A
/// `Running` generation is operational liveness only; it is never, by itself,
/// admitted capability.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationOperationalState {
    /// Staged/available, not running, no live process handles.
    Installed,
    /// Live: the generation's process handles are recorded.
    Running,
    /// Staged candidate awaiting a fenced route cutover.
    Candidate,
}

impl GenerationOperationalState {
    /// The I1.9 wire spelling of the state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Running => "running",
            Self::Candidate => "candidate",
        }
    }

    /// Whether this state holds live process handles.
    #[must_use]
    pub const fn is_running(self) -> bool {
        matches!(self, Self::Running)
    }
}

/// Live process handles of one running generation (I1.9).
///
/// Operational handles only. They are recorded so the Kernel can fence, drain
/// and restart the exact admitted generation; they carry no semantic meaning,
/// no project claim and no authority, and they are never inferred from a name,
/// path or port.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationProcessHandles {
    /// Operating-system process identifier of the running generation.
    pub process_id: u32,
    /// Job Object handle/name the generation's processes are assigned to.
    pub job_object: String,
}

impl GenerationProcessHandles {
    /// Validates a non-zero PID and a bounded Job Object handle.
    fn validate(&self) -> Result<(), OrsError> {
        if self.process_id == 0 {
            return Err(OrsError::InvalidField {
                field: "generation_process_handles_process_id",
                reason: "must be greater than zero",
            });
        }
        validate_text(&self.job_object, "generation_process_handles_job_object")
    }
}

/// Route state of one generation (I1.9).
///
/// The active route scope hash is the route this generation currently serves;
/// the candidate route scope hash is a staged route awaiting a fenced cutover.
/// Both are stable scope hashes, never a live route object.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationRouteState {
    /// Stable hash of the route scope this generation currently serves.
    pub active_route_scope_hash: Option<String>,
    /// Stable hash of a staged candidate route scope.
    pub candidate_route_scope_hash: Option<String>,
}

impl GenerationRouteState {
    /// Validates the recorded route scope hashes.
    fn validate(&self) -> Result<(), OrsError> {
        if let Some(hash) = &self.active_route_scope_hash {
            validate_digest(hash, "generation_route_active_scope_hash")?;
        }
        if let Some(hash) = &self.candidate_route_scope_hash {
            validate_digest(hash, "generation_route_candidate_scope_hash")?;
        }
        Ok(())
    }
}

/// Drain/checkpoint/restart state of one generation (I1.9).
///
/// `drained` may only be set while `draining`; `checkpoint_ref` names the
/// checkpoint/state-class behavior the cutover must preserve; `restarts_spent`
/// counts restarts already consumed against the manifest's bounded restart
/// budget.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationDrainState {
    /// Whether the generation is draining in-flight work.
    pub draining: bool,
    /// Whether the generation has finished draining.
    pub drained: bool,
    /// Checkpoint/state-class reference preserved across a cutover.
    pub checkpoint_ref: Option<String>,
    /// Restarts already spent against the manifest's bounded restart budget.
    pub restarts_spent: u32,
}

impl GenerationDrainState {
    /// Validates the drain/checkpoint invariants.
    fn validate(&self) -> Result<(), OrsError> {
        if self.drained && !self.draining {
            return Err(OrsError::InvalidField {
                field: "generation_drain_drained",
                reason: "only a draining generation may be drained",
            });
        }
        if let Some(checkpoint) = &self.checkpoint_ref {
            validate_text(checkpoint, "generation_drain_checkpoint_ref")?;
        }
        Ok(())
    }
}

/// One durable Generation Registry record for one module generation (I1.9).
///
/// The record binds the operational state, the live process handles, the
/// Authority Epoch, the route state and the drain/checkpoint/restart state to
/// the exact immutable [`KernelExecutionManifest`] copied from the Governor
/// admission. It is a technical execution projection: it records what the
/// Kernel is running, never what the Governor desires and never a semantic
/// policy decision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationRegistryRecord {
    /// Stable module identity.
    pub module_id: String,
    /// Operational generation identity.
    pub generation: ResourceGeneration,
    /// Installed/running/candidate operational state.
    pub state: GenerationOperationalState,
    /// Live process handles, present only while `Running`.
    pub process_handles: Option<GenerationProcessHandles>,
    /// Authority Epoch this generation operates under. Must equal the
    /// manifest's admission epoch: a generation is bound to the epoch it was
    /// admitted under, and a new epoch requires a new Governor admission.
    pub authority_epoch: AuthorityEpoch,
    /// Route state of this generation.
    pub route_state: GenerationRouteState,
    /// Drain/checkpoint/restart state of this generation.
    pub drain_state: GenerationDrainState,
    /// The immutable admitted execution manifest copied from the Governor.
    pub execution_manifest: KernelExecutionManifest,
}

impl GenerationRegistryRecord {
    /// Validates the record shape and every storage restriction.
    ///
    /// The record must bind a non-blank module identity, a state/handle pair
    /// that is coherent (handles only while `Running`), an Authority Epoch
    /// equal to the manifest's admission epoch, valid route and drain state,
    /// and a structurally valid immutable manifest.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.module_id, "generation_registry_module_id")?;
        if self.process_handles.is_some() && !self.state.is_running() {
            return Err(OrsError::InvalidField {
                field: "generation_registry_process_handles",
                reason: "process handles are recorded only for a running generation",
            });
        }
        if self.state.is_running() && self.process_handles.is_none() {
            return Err(OrsError::InvalidField {
                field: "generation_registry_process_handles",
                reason: "a running generation must record its process handles",
            });
        }
        if let Some(handles) = &self.process_handles {
            handles.validate()?;
        }
        if self.authority_epoch != self.execution_manifest.admission.authority_epoch {
            return Err(OrsError::EpochMismatch);
        }
        self.route_state.validate()?;
        self.drain_state.validate()?;
        self.execution_manifest.validate()?;
        Ok(())
    }

    /// The stable module identity of this record.
    #[must_use]
    pub fn module_id(&self) -> &str {
        &self.module_id
    }

    /// The operational generation identity of this record.
    #[must_use]
    pub const fn generation(&self) -> ResourceGeneration {
        self.generation
    }

    /// The installed/running/candidate operational state.
    #[must_use]
    pub const fn state(&self) -> GenerationOperationalState {
        self.state
    }

    /// The live process handles, when this generation is `Running`.
    #[must_use]
    pub fn process_handles(&self) -> Option<&GenerationProcessHandles> {
        self.process_handles.as_ref()
    }

    /// The Authority Epoch this generation operates under.
    #[must_use]
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// The route state of this generation.
    #[must_use]
    pub const fn route_state(&self) -> &GenerationRouteState {
        &self.route_state
    }

    /// The drain/checkpoint/restart state of this generation.
    #[must_use]
    pub const fn drain_state(&self) -> &GenerationDrainState {
        &self.drain_state
    }

    /// The immutable admitted execution manifest this record is bound to.
    #[must_use]
    pub const fn execution_manifest(&self) -> &KernelExecutionManifest {
        &self.execution_manifest
    }

    /// The exact durable key this record is stored under.
    ///
    /// The key is injective over `(module_id, generation)`, so two distinct
    /// records can never share one.
    #[must_use]
    pub fn record_key(&self) -> String {
        format!("generation:{}:{}", self.module_id, self.generation.value())
    }

    /// Transitions a staged generation to `Running` with its exact handles.
    ///
    /// The generation must currently be `Installed` or `Candidate`; a
    /// transition from `Running` is refused so a second start cannot overwrite
    /// the live handles of the already-running process.
    pub fn mark_running(&mut self, handles: GenerationProcessHandles) -> Result<(), OrsError> {
        if self.state.is_running() {
            return Err(OrsError::InvalidTransition);
        }
        handles.validate()?;
        self.state = GenerationOperationalState::Running;
        self.process_handles = Some(handles);
        self.validate()
    }

    /// Transitions a generation to `Installed`, dropping any live handles.
    pub fn mark_installed(&mut self) -> Result<(), OrsError> {
        self.state = GenerationOperationalState::Installed;
        self.process_handles = None;
        self.validate()
    }

    /// Transitions a generation to `Candidate` for a fenced cutover.
    pub fn mark_candidate(&mut self) -> Result<(), OrsError> {
        self.state = GenerationOperationalState::Candidate;
        self.process_handles = None;
        self.validate()
    }

    /// Records that this generation finished draining its in-flight work.
    pub fn mark_drained(&mut self) -> Result<(), OrsError> {
        if !self.drain_state.draining {
            return Err(OrsError::InvalidTransition);
        }
        self.drain_state.drained = true;
        self.validate()
    }

    /// Records one restart spent against the manifest's bounded restart budget.
    ///
    /// The spend is refused once it reaches the manifest's recorded budget, so
    /// a restart can never exceed the admitted bound.
    pub fn record_restart(&mut self) -> Result<(), OrsError> {
        let budget = self
            .execution_manifest
            .projection
            .restart_budget
            .max_restarts;
        if self.drain_state.restarts_spent >= budget {
            return Err(OrsError::InvalidTransition);
        }
        self.drain_state.restarts_spent += 1;
        Ok(())
    }
}

/// The Kernel/ORS-owned Generation Registry (I1.9).
///
/// One [`GenerationRegistryRecord`] per `(module_id, generation)`. The
/// registry is the sole owner of installed/running/candidate operational
/// state, process handles, the Authority Epoch, route state and drain/
/// checkpoint/restart state. It owns no desired-state intent (that is the
/// Governor Module Catalog's), no project claim, no task meaning, no semantic
/// policy decision and no Canonical Store authority.
///
/// Removing or invalidating a record mutates only this registry. It cannot
/// reach the Governor-owned Module Catalog, so catalog intent is never
/// mutated by a Generation Registry change; conversely a Catalog policy change
/// cannot reach the live PID/Job Object handles recorded here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GenerationRegistry {
    records: BTreeMap<(String, ResourceGeneration), GenerationRegistryRecord>,
}

impl GenerationRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs one validated record, replacing any record for the same
    /// `(module_id, generation)`.
    ///
    /// The record is validated before insertion, so a malformed record can
    /// never enter the registry.
    pub fn install(&mut self, record: GenerationRegistryRecord) -> Result<(), OrsError> {
        record.validate()?;
        self.records
            .insert((record.module_id.clone(), record.generation), record);
        Ok(())
    }

    /// Returns the record for one `(module_id, generation)`, independently
    /// inspectable without reading the Module Catalog or the Capability
    /// Registry.
    #[must_use]
    pub fn get(
        &self,
        module_id: &str,
        generation: ResourceGeneration,
    ) -> Option<&GenerationRegistryRecord> {
        self.records.get(&(module_id.to_owned(), generation))
    }

    /// Returns every record for one module, in generation order.
    #[must_use]
    pub fn records_for_module(&self, module_id: &str) -> Vec<&GenerationRegistryRecord> {
        self.records
            .iter()
            .filter(|((module, _), _)| module == module_id)
            .map(|(_, record)| record)
            .collect()
    }

    /// Returns the running record for one module, if any.
    ///
    /// Operational liveness only: a running generation is not, by itself,
    /// admitted capability.
    #[must_use]
    pub fn running_for_module(&self, module_id: &str) -> Option<&GenerationRegistryRecord> {
        self.records_for_module(module_id)
            .into_iter()
            .find(|record| record.state.is_running())
    }

    /// Removes and returns the record for one `(module_id, generation)`.
    ///
    /// Removing the record mutates only this registry. It does not touch the
    /// Governor-owned Module Catalog, so catalog intent is unchanged.
    pub fn remove(
        &mut self,
        module_id: &str,
        generation: ResourceGeneration,
    ) -> Result<GenerationRegistryRecord, OrsError> {
        self.records
            .remove(&(module_id.to_owned(), generation))
            .ok_or(OrsError::GenerationRegistryRecordNotFound)
    }

    /// Returns true when one `(module_id, generation)` is `Running`.
    #[must_use]
    pub fn is_running(&self, module_id: &str, generation: ResourceGeneration) -> bool {
        self.get(module_id, generation)
            .is_some_and(|record| record.state.is_running())
    }

    /// Returns the number of retained records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns true when no records are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns every retained record, in `(module_id, generation)` order.
    #[must_use]
    pub fn records(&self) -> Vec<&GenerationRegistryRecord> {
        self.records.values().collect()
    }
}
