//! Passive execution/cancellation view and evidence DTOs with local validation/accessors.
//!
//! Source anchors: Architecture A5.1 in `docs/architecture/ELIOT_ARCHITECTURE.md`
//! (bounded observations have separate capture-route and evaluation-status characteristics;
//! verifier-backed is not independent); Architecture A10.8 (verification/finish is
//! proof-bearing); Implementation I10.8.2 in `docs/architecture/ELIOT_IMPLEMENTATION.md`
//! (one `ProcessExecutor` facade provides `start`, `inspect`, `cancel`, and `reconcile`,
//! while ownership remains with Kernel, `eliot-testd`, User Broker, or a supervisor); and
//! Appendix P.12 in `docs/generated/rust-boundary-interfaces.md` (`inspect` ->
//! `ProcessExecutionView`, `cancel` -> `CancellationReceipt`, `reconcile` ->
//! `ProcessEvidence`).
//!
//! This child owns passive execution/cancellation view/evidence DTOs plus local
//! validation/accessors only; it owns no process lifecycle, dispatch, cancellation effect,
//! or canonical authority; physical execution/reconcile authority remains `ProcessExecutor`
//! and the owning control plane.

use super::{
    Assertability, CancellationStatus, ContractError, DescendantEvidence, EvidenceAxes,
    EvidenceStatus, ExitStatus, FencingToken, OperationId, ProcessExecutionBinding, ProcessHealth,
    ProcessIdentity, ProcessLifecycle,
};
use crate::stream_evidence::{
    ProcessStreamEvidence, ProcessStreamEvidenceError, ProcessStreamKind,
};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};

/// Current wire revision for reconciliation evidence.
pub const PROCESS_EVIDENCE_SCHEMA_VERSION: &str = "eliot-process-evidence-v2";

/// Typed process execution view.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessExecutionView {
    pub(super) binding: ProcessExecutionBinding,
    pub(super) lifecycle: ProcessLifecycle,
    pub(super) health: ProcessHealth,
    pub(super) cancellation: CancellationStatus,
    pub(super) identity: Option<ProcessIdentity>,
    pub(super) exit: Option<ExitStatus>,
    pub(super) descendants: Option<DescendantEvidence>,
}

impl ProcessExecutionView {
    /// Returns the exact permit/authority/process contour binding.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        &self.binding
    }

    /// Returns lifecycle.
    pub const fn lifecycle(&self) -> ProcessLifecycle {
        self.lifecycle
    }

    /// Returns health.
    pub const fn health(&self) -> &ProcessHealth {
        &self.health
    }

    /// Returns cancellation status.
    pub const fn cancellation(&self) -> CancellationStatus {
        self.cancellation
    }

    /// Returns resumed process identity when available.
    pub const fn identity(&self) -> Option<&ProcessIdentity> {
        self.identity.as_ref()
    }

    /// Returns exit observation.
    pub const fn exit(&self) -> Option<&ExitStatus> {
        self.exit.as_ref()
    }

    /// Returns descendant evidence.
    pub const fn descendants(&self) -> Option<&DescendantEvidence> {
        self.descendants.as_ref()
    }

    /// Returns operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        self.binding.operation_id()
    }

    /// Returns request digest.
    pub fn request_digest(&self) -> &str {
        self.binding.request_digest()
    }

    /// Returns the authenticated fence.
    pub const fn fence(&self) -> &FencingToken {
        self.binding.state_fence()
    }

    fn validate_internal(&self) -> Result<(), ContractError> {
        self.binding.validate()?;
        if let Some(identity) = &self.identity
            && !self.binding.matches_identity(identity)
        {
            return Err(ContractError::EvidenceBindingMismatch);
        }
        if let (Some(identity), Some(descendants)) = (&self.identity, &self.descendants)
            && !descendants.matches(&self.binding, identity)
        {
            return Err(ContractError::EvidenceBindingMismatch);
        }
        Ok(())
    }
}

/// Reconciliation evidence emitted by a physical implementation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEvidence {
    schema_version: String,
    view: ProcessExecutionView,
    stdout: Option<ProcessStreamEvidence>,
    stderr: Option<ProcessStreamEvidence>,
    axes: EvidenceAxes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessEvidenceWire {
    #[serde(default)]
    schema_version: NullableStringWire,
    view: ProcessExecutionView,
    #[serde(default)]
    stdout: Option<ProcessStreamEvidence>,
    #[serde(default)]
    stderr: Option<ProcessStreamEvidence>,
    #[serde(default)]
    stdout_ref: LegacyReferenceWire,
    #[serde(default)]
    stderr_ref: LegacyReferenceWire,
    axes: EvidenceAxes,
}

#[derive(Default, Deserialize)]
#[serde(untagged)]
enum LegacyReferenceWire {
    Value(String),
    Null,
    #[default]
    Missing,
}

type NullableStringWire = LegacyReferenceWire;

impl ProcessEvidence {
    /// Creates raw process evidence with C0-05 observation-only axes.
    pub fn new(
        view: ProcessExecutionView,
        stdout_ref: Option<String>,
        stderr_ref: Option<String>,
        axes: EvidenceAxes,
    ) -> Result<Self, ContractError> {
        let stdout = stdout_ref
            .map(|reference| legacy_stream(&view, ProcessStreamKind::Stdout, reference))
            .transpose()?;
        let stderr = stderr_ref
            .map(|reference| legacy_stream(&view, ProcessStreamKind::Stderr, reference))
            .transpose()?;
        Self::new_typed(view, stdout, stderr, axes)
    }

    /// Creates observation-only evidence from independently typed streams.
    pub fn new_typed(
        view: ProcessExecutionView,
        stdout: Option<ProcessStreamEvidence>,
        stderr: Option<ProcessStreamEvidence>,
        axes: EvidenceAxes,
    ) -> Result<Self, ContractError> {
        view.validate_internal()?;
        axes.validate().map_err(|_| ContractError::InvalidValue {
            field: "evidence_axes",
            reason: "C0-05 evidence axes are invalid",
        })?;
        if axes.status != EvidenceStatus::Observed
            || axes.assertability != Assertability::NonAssertableUnverified
        {
            return Err(ContractError::EvidenceAuthorityEscalation);
        }
        validate_stream(&view, stdout.as_ref(), ProcessStreamKind::Stdout)?;
        validate_stream(&view, stderr.as_ref(), ProcessStreamKind::Stderr)?;
        Ok(Self {
            schema_version: PROCESS_EVIDENCE_SCHEMA_VERSION.to_owned(),
            view,
            stdout,
            stderr,
            axes,
        })
    }

    /// Returns the exact binding through the view.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        self.view.binding()
    }

    /// Returns operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        self.view.operation_id()
    }

    /// Returns request digest.
    pub fn request_digest(&self) -> &str {
        self.view.request_digest()
    }

    /// Returns the process view.
    pub const fn view(&self) -> &ProcessExecutionView {
        &self.view
    }

    /// Returns typed stdout evidence.
    pub const fn stdout(&self) -> Option<&ProcessStreamEvidence> {
        self.stdout.as_ref()
    }

    /// Returns typed stderr evidence.
    pub const fn stderr(&self) -> Option<&ProcessStreamEvidence> {
        self.stderr.as_ref()
    }

    /// Returns a quarantined legacy stdout reference, when one was supplied.
    pub fn stdout_ref(&self) -> Option<&str> {
        self.stdout
            .as_ref()
            .and_then(ProcessStreamEvidence::legacy_reference)
    }

    /// Returns a quarantined legacy stderr reference, when one was supplied.
    pub fn stderr_ref(&self) -> Option<&str> {
        self.stderr
            .as_ref()
            .and_then(ProcessStreamEvidence::legacy_reference)
    }

    /// Returns the reconciliation evidence wire revision.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Returns C0-05 evidence axes.
    pub const fn axes(&self) -> EvidenceAxes {
        self.axes
    }

    /// Revalidates the complete typed envelope.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != PROCESS_EVIDENCE_SCHEMA_VERSION {
            return Err(ContractError::SchemaVersion {
                expected: PROCESS_EVIDENCE_SCHEMA_VERSION,
                observed: self.schema_version.clone(),
            });
        }
        self.view.validate_internal()?;
        self.axes
            .validate()
            .map_err(|_| ContractError::InvalidValue {
                field: "evidence_axes",
                reason: "C0-05 evidence axes are invalid",
            })?;
        if self.axes.status != EvidenceStatus::Observed
            || self.axes.assertability != Assertability::NonAssertableUnverified
        {
            return Err(ContractError::EvidenceAuthorityEscalation);
        }
        validate_stream(&self.view, self.stdout.as_ref(), ProcessStreamKind::Stdout)?;
        validate_stream(&self.view, self.stderr.as_ref(), ProcessStreamKind::Stderr)
    }
}

impl<'de> Deserialize<'de> for ProcessEvidence {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ProcessEvidenceWire::deserialize(deserializer)?;
        let has_legacy = !matches!(wire.stdout_ref, LegacyReferenceWire::Missing)
            || !matches!(wire.stderr_ref, LegacyReferenceWire::Missing);
        let has_typed = wire.stdout.is_some() || wire.stderr.is_some();
        let (stdout, stderr) = match wire.schema_version {
            LegacyReferenceWire::Value(version) if version == PROCESS_EVIDENCE_SCHEMA_VERSION => {
                if has_legacy {
                    return Err(de::Error::custom(
                        "typed process evidence cannot contain legacy stream references",
                    ));
                }
                (wire.stdout, wire.stderr)
            }
            LegacyReferenceWire::Value(version) => {
                return Err(de::Error::custom(ContractError::SchemaVersion {
                    expected: PROCESS_EVIDENCE_SCHEMA_VERSION,
                    observed: version,
                }));
            }
            LegacyReferenceWire::Null => {
                return Err(de::Error::custom(ContractError::InvalidValue {
                    field: "schema_version",
                    reason: "schema version cannot be null",
                }));
            }
            LegacyReferenceWire::Missing if has_typed => {
                return Err(de::Error::custom(
                    "typed process evidence requires an explicit schema version",
                ));
            }
            LegacyReferenceWire::Missing => (
                legacy_reference_value(wire.stdout_ref)
                    .map(|reference| {
                        legacy_stream(&wire.view, ProcessStreamKind::Stdout, reference)
                    })
                    .transpose()
                    .map_err(de::Error::custom)?,
                legacy_reference_value(wire.stderr_ref)
                    .map(|reference| {
                        legacy_stream(&wire.view, ProcessStreamKind::Stderr, reference)
                    })
                    .transpose()
                    .map_err(de::Error::custom)?,
            ),
        };
        Self::new_typed(wire.view, stdout, stderr, wire.axes).map_err(de::Error::custom)
    }
}

fn legacy_reference_value(reference: LegacyReferenceWire) -> Option<String> {
    match reference {
        LegacyReferenceWire::Value(value) => Some(value),
        LegacyReferenceWire::Null | LegacyReferenceWire::Missing => None,
    }
}

fn validate_stream(
    view: &ProcessExecutionView,
    stream: Option<&ProcessStreamEvidence>,
    expected_kind: ProcessStreamKind,
) -> Result<(), ContractError> {
    let Some(stream) = stream else {
        return Ok(());
    };
    stream
        .validate()
        .map_err(|error| map_stream_error(&error))?;
    if stream.stream() != expected_kind || stream.binding() != view.binding() {
        return Err(ContractError::EvidenceBindingMismatch);
    }
    Ok(())
}

fn map_stream_error(error: &ProcessStreamEvidenceError) -> ContractError {
    ContractError::InvalidValue {
        field: "process_stream_evidence",
        reason: if matches!(error, ProcessStreamEvidenceError::AuthorityEscalation) {
            "stream evidence attempted authority promotion"
        } else {
            "stream evidence invariants are invalid"
        },
    }
}

fn legacy_stream(
    view: &ProcessExecutionView,
    stream: ProcessStreamKind,
    reference: String,
) -> Result<ProcessStreamEvidence, ContractError> {
    ProcessStreamEvidence::new_legacy_raw_reference(view.binding().clone(), stream, reference)
        .map_err(|error| map_stream_error(&error))
}

/// Exact cancellation command binding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationRequest {
    pub(super) binding: ProcessExecutionBinding,
}

impl CancellationRequest {
    /// Binds cancellation to the exact validated dispatch.
    pub fn new(binding: ProcessExecutionBinding) -> Self {
        Self { binding }
    }

    /// Returns the exact binding.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        &self.binding
    }
}

/// Cancellation receipt bound to exact permit, authority, process, Job, image, and session.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationReceipt {
    pub(super) binding: ProcessExecutionBinding,
    pub(super) identity: Option<ProcessIdentity>,
    pub(super) status: CancellationStatus,
    pub(super) lifecycle: ProcessLifecycle,
    pub(super) no_effect_proven: bool,
    pub(super) descendants: Option<DescendantEvidence>,
}

impl CancellationReceipt {
    /// Returns the exact authority/process binding.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        &self.binding
    }

    /// Returns cancellation status.
    pub const fn status(&self) -> CancellationStatus {
        self.status
    }

    /// Returns lifecycle.
    pub const fn lifecycle(&self) -> ProcessLifecycle {
        self.lifecycle
    }

    /// Returns whether no physical effect was proven.
    pub const fn no_effect_proven(&self) -> bool {
        self.no_effect_proven
    }

    /// Returns descendant cleanup evidence.
    pub const fn descendants(&self) -> Option<&DescendantEvidence> {
        self.descendants.as_ref()
    }
}
