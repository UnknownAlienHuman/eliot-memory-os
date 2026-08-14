//! Provider-neutral generated command catalogue and thin ELIOT client surface.
//!
//! This crate owns command descriptions, typed request/response correlation and
//! deterministic help/schema projections. It does not open transports, start
//! processes, write a store, mint authority or decide task completion.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_protocol::RequestIdentity;
use eliot_receipts::{EffectClass, ProofCeiling};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

/// Stable generated catalogue identity for A-11 plan-v2.
pub const CATALOGUE_NAME: &str = "eliot.cli.commands";
/// Catalogue revision emitted by help and schema projections.
pub const CATALOGUE_REVISION: &str = "a11-plan-v2";
/// Schema projection identity.
pub const SCHEMA_VERSION: &str = "eliot-cli-schema-v1";

/// Canonical command identifiers from the first-line command projection.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, JsonSchema, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum CommandId {
    SystemSnapshot,
    BootstrapBrief,
    RecoveryStatus,
    Ui,
    Dashboard,
    DevImpactChanged,
    DevCheckChanged,
    DevTestChanged,
    DevPulse,
    InstrumentRun,
    ModuleValidate,
    ModuleTest,
    ModuleContractTest,
    ModuleEdgeTest,
    ModuleBuild,
    ModuleStage,
    ModuleCanary,
    ModulePromote,
    ModuleRollback,
    ReleaseVerify,
    DoctorIntegration,
    BackupCreate,
    BackupVerify,
    BackupRestoreTest,
    MaintenanceRun,
}

impl CommandId {
    /// Returns the canonical generated identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemSnapshot => "system-snapshot",
            Self::BootstrapBrief => "bootstrap-brief",
            Self::RecoveryStatus => "recovery-status",
            Self::Ui => "ui",
            Self::Dashboard => "dashboard",
            Self::DevImpactChanged => "dev-impact-changed",
            Self::DevCheckChanged => "dev-check-changed",
            Self::DevTestChanged => "dev-test-changed",
            Self::DevPulse => "dev-pulse",
            Self::InstrumentRun => "instrument-run",
            Self::ModuleValidate => "module-validate",
            Self::ModuleTest => "module-test",
            Self::ModuleContractTest => "module-contract-test",
            Self::ModuleEdgeTest => "module-edge-test",
            Self::ModuleBuild => "module-build",
            Self::ModuleStage => "module-stage",
            Self::ModuleCanary => "module-canary",
            Self::ModulePromote => "module-promote",
            Self::ModuleRollback => "module-rollback",
            Self::ReleaseVerify => "release-verify",
            Self::DoctorIntegration => "doctor-integration",
            Self::BackupCreate => "backup-create",
            Self::BackupVerify => "backup-verify",
            Self::BackupRestoreTest => "backup-restore-test",
            Self::MaintenanceRun => "maintenance-run",
        }
    }
}

/// Closed typed argument union for every catalogue command.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandArguments {
    SystemSnapshot,
    BootstrapBrief {
        work_unit: String,
    },
    RecoveryStatus,
    Ui,
    Dashboard,
    DevImpactChanged,
    DevCheckChanged,
    DevTestChanged,
    DevPulse {
        objective_id: String,
    },
    InstrumentRun {
        profile: String,
        scope: Option<String>,
    },
    ModuleValidate {
        module_id: String,
    },
    ModuleTest {
        module_id: String,
    },
    ModuleContractTest {
        module_id: String,
        against: String,
    },
    ModuleEdgeTest {
        edge_id: String,
    },
    ModuleBuild {
        module_id: String,
    },
    ModuleStage {
        artifact: String,
    },
    ModuleCanary {
        module_id: String,
        scope: String,
    },
    ModulePromote {
        module_id: String,
        generation: String,
    },
    ModuleRollback {
        module_id: String,
    },
    ReleaseVerify,
    DoctorIntegration {
        profile: String,
    },
    BackupCreate,
    BackupVerify,
    BackupRestoreTest,
    MaintenanceRun,
}

impl CommandArguments {
    fn command_id(&self) -> CommandId {
        match self {
            Self::SystemSnapshot => CommandId::SystemSnapshot,
            Self::BootstrapBrief { .. } => CommandId::BootstrapBrief,
            Self::RecoveryStatus => CommandId::RecoveryStatus,
            Self::Ui => CommandId::Ui,
            Self::Dashboard => CommandId::Dashboard,
            Self::DevImpactChanged => CommandId::DevImpactChanged,
            Self::DevCheckChanged => CommandId::DevCheckChanged,
            Self::DevTestChanged => CommandId::DevTestChanged,
            Self::DevPulse { .. } => CommandId::DevPulse,
            Self::InstrumentRun { .. } => CommandId::InstrumentRun,
            Self::ModuleValidate { .. } => CommandId::ModuleValidate,
            Self::ModuleTest { .. } => CommandId::ModuleTest,
            Self::ModuleContractTest { .. } => CommandId::ModuleContractTest,
            Self::ModuleEdgeTest { .. } => CommandId::ModuleEdgeTest,
            Self::ModuleBuild { .. } => CommandId::ModuleBuild,
            Self::ModuleStage { .. } => CommandId::ModuleStage,
            Self::ModuleCanary { .. } => CommandId::ModuleCanary,
            Self::ModulePromote { .. } => CommandId::ModulePromote,
            Self::ModuleRollback { .. } => CommandId::ModuleRollback,
            Self::ReleaseVerify => CommandId::ReleaseVerify,
            Self::DoctorIntegration { .. } => CommandId::DoctorIntegration,
            Self::BackupCreate => CommandId::BackupCreate,
            Self::BackupVerify => CommandId::BackupVerify,
            Self::BackupRestoreTest => CommandId::BackupRestoreTest,
            Self::MaintenanceRun => CommandId::MaintenanceRun,
        }
    }

    fn validate_text(value: &str, field: &'static str) -> Result<(), CliError> {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(CliError::InvalidArgument { field });
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), CliError> {
        match self {
            Self::BootstrapBrief { work_unit } => Self::validate_text(work_unit, "work_unit"),
            Self::DevPulse { objective_id } => Self::validate_text(objective_id, "objective_id"),
            Self::InstrumentRun { profile, scope } => {
                Self::validate_text(profile, "profile")?;
                if let Some(scope) = scope {
                    Self::validate_text(scope, "scope")?;
                }
                Ok(())
            }
            Self::ModuleValidate { module_id }
            | Self::ModuleTest { module_id }
            | Self::ModuleBuild { module_id }
            | Self::ModuleRollback { module_id } => Self::validate_text(module_id, "module_id"),
            Self::ModuleContractTest { module_id, against } => {
                Self::validate_text(module_id, "module_id")?;
                Self::validate_text(against, "against")
            }
            Self::ModuleEdgeTest { edge_id } => Self::validate_text(edge_id, "edge_id"),
            Self::ModuleStage { artifact } => Self::validate_text(artifact, "artifact"),
            Self::ModuleCanary { module_id, scope } => {
                Self::validate_text(module_id, "module_id")?;
                Self::validate_text(scope, "scope")
            }
            Self::ModulePromote {
                module_id,
                generation,
            } => {
                Self::validate_text(module_id, "module_id")?;
                Self::validate_text(generation, "generation")
            }
            Self::DoctorIntegration { profile } => Self::validate_text(profile, "profile"),
            Self::SystemSnapshot
            | Self::RecoveryStatus
            | Self::Ui
            | Self::Dashboard
            | Self::DevImpactChanged
            | Self::DevCheckChanged
            | Self::DevTestChanged
            | Self::ReleaseVerify
            | Self::BackupCreate
            | Self::BackupVerify
            | Self::BackupRestoreTest
            | Self::MaintenanceRun => Ok(()),
        }
    }
}

/// Exact unavailable state for an advertised but not-yet-reachable command.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum UnavailableReason {
    /// The capability is named by the plan but its owner has not been accepted.
    PlanGap {
        missing_work_id: String,
        dependency: String,
    },
    /// The stable surface is intentionally not admitted in this profile.
    Unsupported { dependency: String, detail: String },
}

/// Result of one thin-client operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum CommandResult {
    Help { text: String },
    Schema { json: String },
    Unavailable { reason: UnavailableReason },
}

/// Request crossing the public client boundary.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRequest {
    pub request: RequestIdentity,
    pub command: CommandId,
    pub arguments: CommandArguments,
}

impl CommandRequest {
    /// Validates full provider identity plus command/argument bijection.
    pub fn validate(&self) -> Result<(), CliError> {
        self.request
            .validate()
            .map_err(|error| CliError::Protocol(error.to_string()))?;
        self.arguments.validate()?;
        if self.arguments.command_id() != self.command {
            return Err(CliError::ArgumentCommandMismatch);
        }
        Ok(())
    }
}

/// Correlated response returned by a pure client operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandResponse {
    pub request: RequestIdentity,
    pub command: CommandId,
    pub effect: EffectClass,
    pub proof_ceiling: ProofCeiling,
    pub result: CommandResult,
}

/// One generated command row.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CommandSpec {
    pub id: CommandId,
    pub usage: &'static str,
    pub summary: &'static str,
    pub owner: &'static str,
    pub required_work_id: &'static str,
    pub argument_kind: ArgumentKind,
    pub effect: EffectClass,
    pub proof_ceiling: ProofCeiling,
    pub availability: CommandAvailability,
}

/// Argument shape name emitted with each generated command row.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentKind {
    Empty,
    WorkUnit,
    Objective,
    Profile,
    ProfileScope,
    Module,
    ModuleAgainst,
    Edge,
    Artifact,
    ModuleScope,
    ModuleGeneration,
}

/// Generated availability metadata; it is never inferred from a runtime probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum CommandAvailability {
    Admitted,
    PlanGap {
        missing_work_id: &'static str,
        dependency: &'static str,
    },
    Unsupported {
        dependency: &'static str,
        detail: &'static str,
    },
}

/// Direct C0 provider identity with the actual provider contract shape digest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderContract {
    pub work_id: String,
    pub package: String,
    pub contract_name: String,
    pub contract_version: String,
    pub shape_sha256: String,
}

static COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        id: CommandId::SystemSnapshot,
        usage: "eliot system snapshot",
        summary: "compile a partial/full CurrentSystemEvidenceSnapshot",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::Read,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::BootstrapBrief,
        usage: "eliot bootstrap brief --work-unit <file-or-id>",
        summary: "compile a route-bounded brief and coverage manifest",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::WorkUnit,
        effect: EffectClass::Read,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::RecoveryStatus,
        usage: "eliot recovery status",
        summary: "inspect authenticated RecoveryView/fallback state",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::Read,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::Ui,
        usage: "eliot ui",
        summary: "start or attach the authenticated User Broker UI",
        owner: "eliot-cli",
        required_work_id: "A-08",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::ExternalEffect,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-08",
            dependency: "eliot-controlboard",
        },
    },
    CommandSpec {
        id: CommandId::Dashboard,
        usage: "eliot dashboard",
        summary: "open the role-filtered terminal dashboard",
        owner: "eliot-cli",
        required_work_id: "A-08",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::Read,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-08",
            dependency: "eliot-controlboard",
        },
    },
    CommandSpec {
        id: CommandId::DevImpactChanged,
        usage: "eliot dev impact --changed",
        summary: "build affected dependency/test/canary plan",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::DevCheckChanged,
        usage: "eliot dev check --changed",
        summary: "run T0 checks for changed crates/modules",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::DevTestChanged,
        usage: "eliot dev test --changed",
        summary: "execute selected module/edge/scenario profiles",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::DevPulse,
        usage: "eliot dev pulse --objective <objective-id>",
        summary: "run the smallest admitted Product pulse",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Objective,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::InstrumentRun,
        usage: "eliot instrument run --profile <profile> [--scope <scope>]",
        summary: "submit a durable instrument profile job",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::ProfileScope,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::ModuleValidate,
        usage: "eliot module validate <module-id>",
        summary: "validate ownership, direction and selectors",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Module,
        effect: EffectClass::Read,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::ModuleTest,
        usage: "eliot module test <module-id>",
        summary: "execute the generated ModuleTestCapsule",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Module,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::ModuleContractTest,
        usage: "eliot module contract-test <module-id> --against <revision>",
        summary: "run provider/consumer compatibility fixtures",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::ModuleAgainst,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::ModuleEdgeTest,
        usage: "eliot module edge-test <edge-id>",
        summary: "exercise the declared process/store/protocol edge",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Edge,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::ModuleBuild,
        usage: "eliot module build <module-id>",
        summary: "build an immutable module artifact and manifest",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Module,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::ModuleStage,
        usage: "eliot module stage <artifact>",
        summary: "verify and register a candidate generation",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Artifact,
        effect: EffectClass::ReversibleMutation,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::ModuleCanary,
        usage: "eliot module canary <module-id> --scope <scope>",
        summary: "start bounded candidate traffic",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::ModuleScope,
        effect: EffectClass::ReversibleMutation,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::ModulePromote,
        usage: "eliot module promote <module-id> <generation>",
        summary: "quiesce, switch, fence and drain a generation",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::ModuleGeneration,
        effect: EffectClass::ExternalEffect,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::ModuleRollback,
        usage: "eliot module rollback <module-id>",
        summary: "return to a compatible retained generation",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Module,
        effect: EffectClass::ReversibleMutation,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::ReleaseVerify,
        usage: "eliot release verify",
        summary: "run the T4 release gate",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::Read,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::DoctorIntegration,
        usage: "eliot doctor integration <profile>",
        summary: "verify plugin, hook, protocol and runtime coverage",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Profile,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::BackupCreate,
        usage: "eliot backup create",
        summary: "manage a recovery artifact creation request",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::ReversibleMutation,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::BackupVerify,
        usage: "eliot backup verify",
        summary: "verify a recovery artifact",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::BackupRestoreTest,
        usage: "eliot backup restore-test",
        summary: "run an isolated restore test",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
    CommandSpec {
        id: CommandId::MaintenanceRun,
        usage: "eliot maintenance run",
        summary: "execute an admitted maintenance job and stop",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::ReversibleMutation,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "eliot-mcp",
        },
    },
];

/// Errors from catalogue generation or pure client validation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CliError {
    #[error("catalogue: {0}")]
    Catalogue(#[from] CatalogueError),
    #[error("protocol request identity is invalid: {0}")]
    Protocol(String),
    #[error("unknown command: {0}")]
    UnknownCommand(String),
    #[error("argument field {field} is blank or contains control characters")]
    InvalidArgument { field: &'static str },
    #[error("command and typed arguments do not match")]
    ArgumentCommandMismatch,
    #[error("request and response correlation does not match")]
    CorrelationMismatch,
    #[error("result does not match the generated command availability")]
    ResultMismatch,
}

/// Errors proving that generated catalogue data is not canonical.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CatalogueError {
    #[error("catalogue must not be empty")]
    Empty,
    #[error("duplicate command: {0}")]
    DuplicateCommand(String),
    #[error("commands are not in canonical order: {previous} before {current}")]
    NonCanonicalOrder { previous: String, current: String },
    #[error("command {command} has a blank generated field: {field}")]
    BlankField {
        command: String,
        field: &'static str,
    },
    #[error("command {0} exceeds the candidate-only proof ceiling")]
    ProofCeiling(String),
    #[error("provider work id is duplicated: {0}")]
    DuplicateProvider(String),
    #[error("provider identity is incomplete: {0}")]
    InvalidProvider(String),
    #[error("provider identity failed: {0}")]
    ProviderIdentity(String),
    #[error("generated schema serialization failed: {0}")]
    Serialization(String),
}

/// The one immutable generated catalogue used by help, schema and execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandCatalogue;

impl CommandCatalogue {
    /// Returns the A-11 plan-v2 catalogue.
    pub const fn current() -> Self {
        Self
    }

    /// Returns all generated command rows in authority order.
    pub const fn commands(self) -> &'static [CommandSpec] {
        COMMANDS
    }

    /// Resolves actual provider contract identities from their owning crates.
    pub fn providers(self) -> Result<Vec<ProviderContract>, CatalogueError> {
        provider_contracts()
    }

    /// Validates catalogue uniqueness, order, provider identities and ceilings.
    pub fn validate(self) -> Result<(), CatalogueError> {
        let providers = self.providers()?;
        validate_catalogue(self.commands(), &providers)
    }

    fn find(self, command: CommandId) -> Result<&'static CommandSpec, CliError> {
        self.commands()
            .iter()
            .find(|spec| spec.id == command)
            .ok_or_else(|| CliError::UnknownCommand(command.as_str().to_owned()))
    }

    /// Renders exact hierarchical help from the same rows used by execution.
    pub fn help_text(self) -> Result<String, CatalogueError> {
        self.validate()?;
        let mut output = format!("eliot command catalogue {CATALOGUE_REVISION}\n\nCOMMANDS\n");
        for spec in self.commands() {
            output.push_str(&format!(
                "  {}  [{}] {}\n",
                spec.usage,
                availability_code(spec.availability),
                spec.summary
            ));
        }
        Ok(output)
    }

    /// Renders actual executable input/output schemas plus catalogue rows.
    pub fn schema_json(self) -> Result<String, CatalogueError> {
        self.validate()?;
        let input_schema = command_request_input_schema()?;
        let output_schema = serde_json::to_value(schemars::schema_for!(CommandResponse))
            .map_err(|error| CatalogueError::Serialization(error.to_string()))?;
        let schema = GeneratedSchema {
            schema: SCHEMA_VERSION,
            catalogue: CATALOGUE_NAME,
            revision: CATALOGUE_REVISION,
            input_schema,
            output_schema,
            commands: self.commands().iter().map(schema_command).collect(),
            providers: self.providers()?,
        };
        serde_json::to_string(&schema)
            .map_err(|error| CatalogueError::Serialization(error.to_string()))
    }

    /// Validates and executes one operation without transport or external effects.
    pub fn execute(self, request: &CommandRequest) -> Result<CommandResponse, CliError> {
        self.validate()?;
        request.validate()?;
        let spec = self.find(request.command)?;
        let result = match spec.availability {
            CommandAvailability::Admitted => return Err(CliError::ResultMismatch),
            CommandAvailability::PlanGap {
                missing_work_id,
                dependency,
            } => CommandResult::Unavailable {
                reason: UnavailableReason::PlanGap {
                    missing_work_id: missing_work_id.to_owned(),
                    dependency: dependency.to_owned(),
                },
            },
            CommandAvailability::Unsupported { dependency, detail } => CommandResult::Unavailable {
                reason: UnavailableReason::Unsupported {
                    dependency: dependency.to_owned(),
                    detail: detail.to_owned(),
                },
            },
        };
        let response = CommandResponse {
            request: request.request.clone(),
            command: request.command,
            effect: spec.effect,
            proof_ceiling: spec.proof_ceiling,
            result,
        };
        response.validate_for(self, request)?;
        Ok(response)
    }
}

impl CommandResponse {
    /// Verifies complete RequestIdentity, command, effect, ceiling and result parity.
    pub fn validate_for(
        &self,
        catalogue: CommandCatalogue,
        request: &CommandRequest,
    ) -> Result<(), CliError> {
        request.validate()?;
        self.request
            .validate()
            .map_err(|error| CliError::Protocol(error.to_string()))?;
        if self.request != request.request || self.command != request.command {
            return Err(CliError::CorrelationMismatch);
        }
        let spec = catalogue.find(request.command)?;
        if self.effect != spec.effect || self.proof_ceiling != spec.proof_ceiling {
            return Err(CliError::ResultMismatch);
        }
        match (&spec.availability, &self.result) {
            (
                CommandAvailability::PlanGap {
                    missing_work_id,
                    dependency,
                },
                CommandResult::Unavailable {
                    reason:
                        UnavailableReason::PlanGap {
                            missing_work_id: actual,
                            dependency: actual_dependency,
                        },
                },
            ) if actual == missing_work_id && actual_dependency == dependency => {}
            (
                CommandAvailability::Unsupported { dependency, detail },
                CommandResult::Unavailable {
                    reason:
                        UnavailableReason::Unsupported {
                            dependency: actual_dependency,
                            detail: actual_detail,
                        },
                },
            ) if actual_dependency == dependency && actual_detail == detail => {}
            (CommandAvailability::Admitted, _) => return Err(CliError::ResultMismatch),
            _ => return Err(CliError::ResultMismatch),
        }
        Ok(())
    }
}

/// Validates an arbitrary generated catalogue fixture for duplicate/order negatives.
pub fn validate_catalogue(
    commands: &[CommandSpec],
    providers: &[ProviderContract],
) -> Result<(), CatalogueError> {
    if commands.is_empty() {
        return Err(CatalogueError::Empty);
    }
    let mut seen = BTreeSet::new();
    let mut previous: Option<CommandId> = None;
    for spec in commands {
        let id = spec.id.as_str();
        if !seen.insert(id) {
            return Err(CatalogueError::DuplicateCommand(id.to_owned()));
        }
        if let Some(previous) = previous
            && previous >= spec.id
        {
            return Err(CatalogueError::NonCanonicalOrder {
                previous: previous.as_str().to_owned(),
                current: id.to_owned(),
            });
        }
        previous = Some(spec.id);
        for (field, value) in [
            ("usage", spec.usage),
            ("summary", spec.summary),
            ("owner", spec.owner),
            ("required_work_id", spec.required_work_id),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(CatalogueError::BlankField {
                    command: id.to_owned(),
                    field,
                });
            }
        }
        if spec.proof_ceiling > ProofCeiling::CandidateArtifact {
            return Err(CatalogueError::ProofCeiling(id.to_owned()));
        }
        if spec.availability == CommandAvailability::Admitted && spec.required_work_id != "A-11" {
            return Err(CatalogueError::InvalidProvider(id.to_owned()));
        }
    }
    let mut provider_ids = BTreeSet::new();
    for provider in providers {
        if !provider_ids.insert(provider.work_id.as_str()) {
            return Err(CatalogueError::DuplicateProvider(provider.work_id.clone()));
        }
        if [
            provider.work_id.as_str(),
            provider.package.as_str(),
            provider.contract_name.as_str(),
            provider.contract_version.as_str(),
            provider.shape_sha256.as_str(),
        ]
        .iter()
        .any(|value| value.trim().is_empty())
        {
            return Err(CatalogueError::InvalidProvider(provider.work_id.clone()));
        }
    }
    Ok(())
}

fn provider_contracts() -> Result<Vec<ProviderContract>, CatalogueError> {
    let observations = eliot_observation_contracts::contract_identity()
        .map_err(|error| CatalogueError::ProviderIdentity(error.to_string()))?;
    let protocol = eliot_protocol::protocol_contract_identity()
        .map_err(|error| CatalogueError::ProviderIdentity(error.to_string()))?;
    let receipts = eliot_receipts::contract_identity()
        .map_err(|error| CatalogueError::ProviderIdentity(error.to_string()))?;
    let runtime = eliot_runtime_contracts::contract_identity()
        .map_err(|error| CatalogueError::ProviderIdentity(error.to_string()))?;
    Ok(vec![
        provider(
            "C0-02",
            "eliot-receipts",
            receipts.name.to_string(),
            receipts.version.to_string(),
            receipts.shape_sha256,
        ),
        provider(
            "C0-04",
            "eliot-runtime-contracts",
            runtime.name.to_string(),
            runtime.version.to_string(),
            runtime.shape_sha256,
        ),
        provider(
            "C0-07",
            "eliot-protocol",
            protocol.name.to_string(),
            protocol.version.to_string(),
            protocol.shape_sha256,
        ),
        provider(
            "C0-11",
            "eliot-observation-contracts",
            observations.name.to_string(),
            observations.version.to_string(),
            observations.shape_sha256,
        ),
    ])
}

fn provider(
    work_id: &str,
    package: &str,
    contract_name: String,
    contract_version: String,
    shape_sha256: String,
) -> ProviderContract {
    ProviderContract {
        work_id: work_id.to_owned(),
        package: package.to_owned(),
        contract_name,
        contract_version,
        shape_sha256,
    }
}

fn command_request_input_schema() -> Result<Value, CatalogueError> {
    let command_request_schema = serde_json::to_value(schemars::schema_for!(CommandRequest))
        .map_err(|error| CatalogueError::Serialization(error.to_string()))?;
    let request_schema = command_request_schema
        .pointer("/properties/request")
        .cloned()
        .ok_or_else(|| {
            CatalogueError::Serialization(
                "CommandRequest schema has no request property".to_owned(),
            )
        })?;
    let argument_schema = serde_json::to_value(schemars::schema_for!(CommandArguments))
        .map_err(|error| CatalogueError::Serialization(error.to_string()))?;
    let argument_variants = argument_schema
        .get("oneOf")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CatalogueError::Serialization(
                "CommandArguments schema has no oneOf variants".to_owned(),
            )
        })?;
    let one_of = COMMANDS
        .iter()
        .map(|spec| -> Result<Value, CatalogueError> {
            let command_tag = spec.id.as_str().replace('-', "_");
            let arguments = argument_variants
                .iter()
                .find(|variant| {
                    variant
                        .pointer("/properties/kind/const")
                        .and_then(Value::as_str)
                        == Some(command_tag.as_str())
                })
                .cloned()
                .ok_or_else(|| {
                    CatalogueError::Serialization(format!(
                        "CommandArguments schema has no variant for {command_tag}"
                    ))
                })?;
            Ok(json!({
                "type": "object",
                "properties": {
                    "request": request_schema.clone(),
                    "command": {
                        "type": "string",
                        "const": spec.id.as_str()
                    },
                    "arguments": arguments
                },
                "required": ["request", "command", "arguments"],
                "additionalProperties": false
            }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut schema = serde_json::Map::new();
    if let Some(schema_version) = command_request_schema.get("$schema") {
        schema.insert("$schema".to_owned(), schema_version.clone());
    }
    if let Some(definitions) = command_request_schema.get("$defs") {
        schema.insert("$defs".to_owned(), definitions.clone());
    }
    schema.insert(
        "title".to_owned(),
        Value::String("CommandRequest".to_owned()),
    );
    schema.insert("type".to_owned(), Value::String("object".to_owned()));
    schema.insert("oneOf".to_owned(), Value::Array(one_of));
    Ok(Value::Object(schema))
}

#[derive(Serialize)]
struct GeneratedSchema {
    schema: &'static str,
    catalogue: &'static str,
    revision: &'static str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    commands: Vec<SchemaCommand>,
    providers: Vec<ProviderContract>,
}

#[derive(Serialize)]
struct SchemaCommand {
    id: &'static str,
    usage: &'static str,
    summary: &'static str,
    owner: &'static str,
    required_work_id: &'static str,
    argument_kind: ArgumentKind,
    effect: EffectClass,
    proof_ceiling: ProofCeiling,
    availability: SchemaAvailability,
}

#[derive(Serialize)]
struct SchemaAvailability {
    code: &'static str,
    dependency: &'static str,
    missing_work_id: Option<&'static str>,
    detail: Option<&'static str>,
}

fn schema_command(spec: &CommandSpec) -> SchemaCommand {
    let availability = match spec.availability {
        CommandAvailability::Admitted => SchemaAvailability {
            code: "ADMITTED",
            dependency: "eliot-cli",
            missing_work_id: None,
            detail: None,
        },
        CommandAvailability::PlanGap {
            missing_work_id,
            dependency,
        } => SchemaAvailability {
            code: "PLAN_GAP",
            dependency,
            missing_work_id: Some(missing_work_id),
            detail: None,
        },
        CommandAvailability::Unsupported { dependency, detail } => SchemaAvailability {
            code: "UNSUPPORTED",
            dependency,
            missing_work_id: None,
            detail: Some(detail),
        },
    };
    SchemaCommand {
        id: spec.id.as_str(),
        usage: spec.usage,
        summary: spec.summary,
        owner: spec.owner,
        required_work_id: spec.required_work_id,
        argument_kind: spec.argument_kind,
        effect: spec.effect,
        proof_ceiling: spec.proof_ceiling,
        availability,
    }
}

const fn availability_code(availability: CommandAvailability) -> &'static str {
    match availability {
        CommandAvailability::Admitted => "ADMITTED",
        CommandAvailability::PlanGap { .. } => "PLAN_GAP",
        CommandAvailability::Unsupported { .. } => "UNSUPPORTED",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_identity_comes_from_actual_contract_shapes() {
        let providers = CommandCatalogue::current()
            .providers()
            .expect("provider identities");
        assert_eq!(providers.len(), 4);
        assert!(
            providers
                .iter()
                .all(|provider| !provider.contract_version.trim().is_empty())
        );
        assert!(
            providers
                .iter()
                .all(|provider| provider.shape_sha256.len() == 64)
        );
    }
}
