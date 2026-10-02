//! Pre-launch admission submission to the canonical instrument registry (issue #1814 W1).
//!
//! [`prepare_admission_submission`] runs at the shared admission boundary: it
//! carries the admitted [`InstrumentSpec`](crate::profile::InstrumentSpec)
//! plus the executable supply-chain receipt bound to one launch as the
//! `snapshot_json` that the original registration owner persisted through
//! the closed `ApplyInstrumentRegistryState` store mutation, and runs the
//! shared snapshot acceptance boundary through [`InstrumentRegistry::recover`],
//! validating the recorded values. The original registration receipt and
//! exact named readback are supplied separately by the read-only owner port
//! before launch. The receipt binds the exact bytes that launch:
//! the canonicalized path arrives from the owner-observed identity
//! (canonicalize-at-use), the digest is hashed from that same observed
//! object (hash-same-object), and provenance is the admitted spec digest at
//! the admitted registry generation. The bytes travel to durable storage
//! through the Governor write path; this module never writes canonical
//! state itself.

use eliot_store_api::{
    EffectClass, NamedMutationOperation, NamedReadOperation, NamedReadResponse, RevisionKey,
    TransitionClass, WriteReceipt, WriteReceiptStatus,
};
use serde_json::Value;

use crate::profile::{AdmittedStage, InstrumentRegistry, ProfileError, StageExecution};
use crate::registry::{ResolvedExecutableIdentity, SupplyChainReceipt};

/// Closed `ApplyInstrumentRegistryState` mutation for one admitted stage launch.
///
/// The snapshot carries every admitted spec and supply-chain receipt at the
/// admitted registry generation, including this operation's spec and
/// receipt; the bound digests pin exactly which record this launch was
/// admitted under.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionSubmission {
    snapshot_json: String,
    spec_digest: String,
    supply_digest: String,
    executable_path: String,
    content_digest: String,
}

/// Canonical registry snapshot pin for an admitted pure instrument transform.
/// Unlike an external executable submission, it carries no executable or
/// supply-chain receipt; the closed parser generation and registered handler
/// identify the in-process transform.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PureTransformSubmission {
    snapshot_json: String,
    spec_id: String,
    spec_digest: String,
    parser_generation: u64,
}

/// Original owner-issued canonical receipt and exact named registry readback
/// observed before an external stage may create a child process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionSubmissionReadback {
    receipt: WriteReceipt,
    readback: NamedReadResponse,
    registry_revision: u64,
}

impl AdmissionSubmissionReadback {
    /// Validates the original committed receipt and same-fence named read
    /// against the exact registration snapshot accepted for this launch.
    pub fn verify(
        submission: &AdmissionSubmission,
        receipt: WriteReceipt,
        original_readback: NamedReadResponse,
        current_readback: NamedReadResponse,
    ) -> Result<Self, ProfileError> {
        Self::verify_snapshot(
            submission.snapshot_json(),
            receipt,
            original_readback,
            current_readback,
        )
    }

    /// Validates a pure transform against its exact registered parser
    /// generation and the original canonical registration receipt/readbacks.
    pub fn verify_pure_transform(
        submission: &PureTransformSubmission,
        stage: &AdmittedStage,
        receipt: WriteReceipt,
        original_readback: NamedReadResponse,
        current_readback: NamedReadResponse,
    ) -> Result<Self, ProfileError> {
        let parser_generation = match &stage.execution {
            StageExecution::Pure { parser_generation } if !stage.external => *parser_generation,
            _ => {
                return Err(ProfileError::Snapshot {
                    detail: "pure registry receipt supplied for a non-pure admitted stage"
                        .to_owned(),
                });
            }
        };
        if stage.spec.as_str() != submission.spec_id
            || stage.spec_digest != submission.spec_digest
            || parser_generation != submission.parser_generation
        {
            return Err(ProfileError::Snapshot {
                detail:
                    "pure transform stage differs from its registered spec or parser generation"
                        .to_owned(),
            });
        }
        verify_pure_snapshot(
            &submission.snapshot_json,
            &submission.spec_id,
            &submission.spec_digest,
            submission.parser_generation,
        )?;
        Self::verify_snapshot(
            &submission.snapshot_json,
            receipt,
            original_readback,
            current_readback,
        )
    }

    /// Validates one verbatim snapshot against the original registration
    /// receipt and two independently observed owner reads.
    fn verify_snapshot(
        snapshot_json: &str,
        receipt: WriteReceipt,
        original_readback: NamedReadResponse,
        current_readback: NamedReadResponse,
    ) -> Result<Self, ProfileError> {
        let refuse = |detail: &str| ProfileError::Snapshot {
            detail: detail.to_owned(),
        };
        receipt
            .validate()
            .map_err(|error| refuse(&error.to_string()))?;
        if receipt.status != WriteReceiptStatus::Committed
            || receipt.commit_id.is_none()
            || receipt.transition_class != TransitionClass::InstrumentRegistry
        {
            return Err(refuse(
                "registry write did not return its committed owner receipt",
            ));
        }
        let envelope = receipt
            .require_reconciliation_envelope()
            .map_err(|error| refuse(&error.to_string()))?;
        // `plan.rs::revision_keys` produces the scope head key from the
        // admitted transition scope. Bind the exact key from that producer to
        // the receipt's only revision delta and the read's same-key head.
        let expected_scope_key =
            RevisionKey::new(format!("scope:{}", envelope.core.work_scope.scope_id))
                .map_err(|error| refuse(&error.to_string()))?;
        if envelope.core.operation.operation_kind != "store.apply.instrument_registry"
            || envelope.core.operation.effect != EffectClass::ReversibleMutation
            || envelope.core.operation.state_fence != receipt.state_fence
            || envelope.core.work_scope.state_fence != receipt.state_fence
            || envelope.core.request.state_fence != receipt.state_fence
            || envelope.core.task.is_none()
        {
            return Err(refuse(
                "registry receipt envelope does not bind an instrument registration task, scope and fence",
            ));
        }
        let [scope_revision] = receipt.revision_before_after.as_slice() else {
            return Err(refuse(
                "registry receipt must carry its one original scope revision delta",
            ));
        };
        if scope_revision.key != expected_scope_key || scope_revision.after <= scope_revision.before
        {
            return Err(refuse(
                "registry receipt does not advance the original owner scope head",
            ));
        }
        if envelope.core.operation.operation_id.as_str() != receipt.operation_id.as_str()
            || envelope.core.operation.request_id != envelope.core.request.metadata.request_id
            || envelope.core.operation.idempotency_key != receipt.idempotency_key
            || envelope.core.work_scope.product_id != envelope.core.request.metadata.product_id
            || envelope
                .core
                .task
                .as_ref()
                .map(|task| task.task_id.to_string())
                != envelope
                    .core
                    .request
                    .metadata
                    .task_id
                    .as_ref()
                    .map(ToString::to_string)
        {
            return Err(refuse(
                "original registry receipt does not bind its request, operation, product and task",
            ));
        }
        original_readback
            .validate()
            .map_err(|error| refuse(&error.to_string()))?;
        if original_readback.operation != NamedReadOperation::GetInstrumentRegistryState
            || original_readback.state_fence != receipt.state_fence
        {
            return Err(refuse(
                "original registry readback does not match its committed receipt fence",
            ));
        }
        let original_payload = &original_readback.payload;
        let snapshot = original_payload
            .get("snapshot_json")
            .and_then(Value::as_str)
            .ok_or_else(|| refuse("original registry readback omitted its stored snapshot"))?;
        if snapshot != snapshot_json {
            return Err(refuse(
                "original registry readback differs from the submitted mutation bytes",
            ));
        }
        let original_authority_ledger = original_payload
            .get("registration_authority_json")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                refuse("original registry readback omitted its registration authority ledger")
            })?;
        let authority_value: Value = serde_json::from_str(original_authority_ledger)
            .map_err(|_| refuse("original registration authority ledger is invalid JSON"))?;
        if !authority_value.is_object() {
            return Err(refuse(
                "original registration authority ledger must be a JSON object",
            ));
        }
        let original_revision = original_payload
            .get("revision")
            .and_then(Value::as_u64)
            .filter(|revision| *revision > 0)
            .ok_or_else(|| refuse("original registry readback omitted its nonzero revision"))?;
        let registry_revision = original_revision;
        let original_payload_fence: eliot_contracts::StateFence = serde_json::from_value(
            original_payload
                .get("state_fence")
                .cloned()
                .ok_or_else(|| refuse("original registry readback omitted its state fence"))?,
        )
        .map_err(|_| refuse("original registry readback carried an invalid state fence"))?;
        let stored_operation_id = original_payload.get("operation_id").and_then(Value::as_str);
        let stored_request_hash = original_payload
            .get("canonical_request_hash")
            .and_then(Value::as_str);
        let stored_scope_id = original_payload.get("scope_id").and_then(Value::as_str);
        let stored_task_id = original_payload.get("task_id").and_then(Value::as_str);
        let original_scope_head = original_readback
            .revision_heads
            .iter()
            .find(|head| head.key == scope_revision.key)
            .ok_or_else(|| refuse("original registry readback omitted its owner scope head"))?;
        if original_payload_fence != original_readback.state_fence
            || stored_operation_id != Some(receipt.operation_id.as_str())
            || stored_request_hash != Some(receipt.canonical_request_hash.as_str())
            || stored_scope_id != Some(envelope.core.work_scope.scope_id.as_str())
            || stored_task_id
                != envelope
                    .core
                    .task
                    .as_ref()
                    .map(|task| task.task_id.as_str())
            || original_scope_head.revision < scope_revision.after
            || original_scope_head.state_fence != receipt.state_fence
        {
            return Err(refuse(
                "original registry readback does not bind the receipt, scope, task and local revision",
            ));
        }
        current_readback
            .validate()
            .map_err(|error| refuse(&error.to_string()))?;
        if current_readback.operation != NamedReadOperation::GetInstrumentRegistryState
            || current_readback.state_fence != receipt.state_fence
        {
            return Err(refuse(
                "current registry readback does not match the original fence",
            ));
        }
        let current_payload = &current_readback.payload;
        let current_snapshot = current_payload.get("snapshot_json").and_then(Value::as_str);
        let current_revision = current_payload.get("revision").and_then(Value::as_u64);
        let current_payload_fence: Option<eliot_contracts::StateFence> = current_payload
            .get("state_fence")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok());
        if current_snapshot != Some(snapshot_json)
            || current_revision != Some(registry_revision)
            || current_payload_fence.as_ref() != Some(&current_readback.state_fence)
            || current_payload.get("operation_id").and_then(Value::as_str) != stored_operation_id
            || current_payload
                .get("canonical_request_hash")
                .and_then(Value::as_str)
                != stored_request_hash
            || current_payload.get("scope_id").and_then(Value::as_str) != stored_scope_id
            || current_payload.get("task_id").and_then(Value::as_str) != stored_task_id
            || current_payload
                .get("registration_authority_json")
                .and_then(Value::as_str)
                != Some(original_authority_ledger)
            || !current_readback.revision_heads.iter().any(|head| {
                head.key == scope_revision.key
                    && head.revision >= scope_revision.after
                    && head.state_fence == receipt.state_fence
            })
        {
            return Err(refuse(
                "current registry row differs from original owner identity, snapshot or local revision",
            ));
        }
        Ok(Self {
            receipt,
            readback: current_readback,
            registry_revision,
        })
    }

    /// Exact committed owner receipt returned for the original registration.
    pub fn receipt(&self) -> &WriteReceipt {
        &self.receipt
    }

    /// Exact named read response used to prove the committed registry value.
    pub fn readback(&self) -> &NamedReadResponse {
        &self.readback
    }

    /// Registry revision witnessed by the named read.
    pub const fn registry_revision(&self) -> u64 {
        self.registry_revision
    }
}

impl AdmissionSubmission {
    /// Store mutation this submission executes.
    pub fn operation(&self) -> NamedMutationOperation {
        NamedMutationOperation::ApplyInstrumentRegistryState
    }

    /// Store read that returns the same record back.
    pub fn read_operation(&self) -> NamedReadOperation {
        NamedReadOperation::GetInstrumentRegistryState
    }

    /// Verbatim snapshot bytes the store path persists.
    pub fn snapshot_json(&self) -> &str {
        &self.snapshot_json
    }

    /// Admitted spec digest this launch was bound under.
    pub fn spec_digest(&self) -> &str {
        &self.spec_digest
    }

    /// Admitted supply-chain receipt digest this launch was bound under.
    pub fn supply_digest(&self) -> &str {
        &self.supply_digest
    }

    /// Canonicalized executable path of the object that launches.
    pub fn executable_path(&self) -> &str {
        &self.executable_path
    }

    /// Content digest of the exact executable bytes that launch.
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }
}

impl PureTransformSubmission {
    /// Verbatim full registry snapshot whose original owner receipt authorizes
    /// this pure transform stage.
    pub fn snapshot_json(&self) -> &str {
        &self.snapshot_json
    }

    /// Registered instrument identifier for this pure transform.
    pub fn spec_id(&self) -> &str {
        &self.spec_id
    }

    /// Canonical digest of the admitted pure-transform definition.
    pub fn spec_digest(&self) -> &str {
        &self.spec_digest
    }

    /// Parser generation required by the registered pure-transform handler.
    pub const fn parser_generation(&self) -> u64 {
        self.parser_generation
    }
}

/// Prepares the admitted stage against the registry snapshot already committed
/// by the original registration action. The returned value grants no write
/// authority; its receipt and readback must be supplied by the read-only owner
/// and verified separately before launch.
///
/// The live registry must still admit the stage's spec digest, and the
/// admitted receipt must still pin that spec digest and the observed
/// executable object; an explicit receipt absence must still be absent.
/// The locally decoded snapshot crosses the shared acceptance boundary and is
/// recovered for consistency checks. That local round trip proves no durable
/// state; only [`AdmissionSubmissionReadback::verify`] accepts the original
/// canonical receipt and independent exact-fence owner readback.
///
/// # Errors
///
/// Returns [`ProfileError::UnknownSpec`] when the live registry no longer
/// admits the stage's spec, or [`ProfileError::Snapshot`] when the spec,
/// receipt, or generation drifted, the observation no longer matches the
/// receipt, or the snapshot fails local acceptance.
pub fn prepare_admission_submission(
    registry: &InstrumentRegistry,
    stage: &AdmittedStage,
    observed: &ResolvedExecutableIdentity,
) -> Result<AdmissionSubmission, ProfileError> {
    if !stage.external || !matches!(&stage.execution, StageExecution::External) {
        return Err(ProfileError::Snapshot {
            detail: "external executable submission requires an external admitted stage".to_owned(),
        });
    }
    let kind = stage.spec.as_str();
    let spec = registry
        .spec(kind)
        .ok_or_else(|| ProfileError::UnknownSpec {
            profile: stage.profile.clone(),
            stage: stage.stage_id.clone(),
            spec: kind.to_owned(),
        })?;
    let spec_digest = spec.digest();
    if spec_digest != stage.spec_digest {
        return Err(ProfileError::Snapshot {
            detail: "admitted spec was replaced since compilation".to_owned(),
        });
    }
    let admitted_supply = stage
        .supply_receipt
        .as_ref()
        .map(SupplyChainReceipt::digest)
        .unwrap_or_default();
    let file_identity = observed
        .file_identity
        .ok_or_else(|| ProfileError::Snapshot {
            detail: "new external admission requires the owner-observed executable file identity"
                .to_owned(),
        })?;
    match (&stage.supply_receipt, registry.supply_chain(kind)) {
        (Some(receipt), Some(live)) => {
            receipt
                .check_observation(
                    &eliot_instrument_api::registry::ExternalExecutableObservation {
                        canonical_path: observed.canonical_path.clone(),
                        executable_file_name: observed.executable_file_name(),
                        content_digest: observed.content_digest.clone(),
                        file_identity,
                        tool_version: observed.tool_version.clone(),
                    },
                )
                .map_err(|error| ProfileError::Snapshot {
                    detail: error.to_string(),
                })?;
            if receipt.spec_digest != spec_digest || live.digest() != admitted_supply {
                return Err(ProfileError::Snapshot {
                    detail: "admitted supply-chain receipt was replaced since compilation"
                        .to_owned(),
                });
            }
        }
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => {
            return Err(ProfileError::Snapshot {
                detail: "admitted supply-chain receipt was replaced since compilation".to_owned(),
            });
        }
    }
    let snapshot_json = registry.persist()?;
    let submission = AdmissionSubmission {
        snapshot_json,
        spec_digest: stage.spec_digest.clone(),
        supply_digest: admitted_supply.clone(),
        executable_path: observed.canonical_path.clone(),
        content_digest: observed.content_digest.clone(),
    };
    let recovered = InstrumentRegistry::recover(&submission.snapshot_json)?;
    let recovered_spec = recovered
        .spec(kind)
        .ok_or_else(|| ProfileError::UnknownSpec {
            profile: stage.profile.clone(),
            stage: stage.stage_id.clone(),
            spec: kind.to_owned(),
        })?;
    if recovered_spec.digest() != stage.spec_digest
        || recovered
            .supply_chain(kind)
            .map(SupplyChainReceipt::digest)
            .unwrap_or_default()
            != admitted_supply
        || recovered.generation() != registry.generation()
    {
        return Err(ProfileError::Snapshot {
            detail: "instrument registry readback differs from the admitted record".to_owned(),
        });
    }
    Ok(submission)
}

/// Prepares a pure-transform stage against the same full registry snapshot
/// persisted by the original canonical registration action.
///
/// The pure handler comes only from the closed registry entry; this function
/// does not dispatch from caller-authored handler text and does not require an
/// executable or supply-chain receipt.
pub fn prepare_pure_transform_submission(
    registry: &InstrumentRegistry,
    stage: &AdmittedStage,
) -> Result<PureTransformSubmission, ProfileError> {
    let parser_generation = match &stage.execution {
        StageExecution::Pure { parser_generation } if !stage.external => *parser_generation,
        _ => {
            return Err(ProfileError::Snapshot {
                detail: "pure transform submission requires a pure admitted stage".to_owned(),
            });
        }
    };
    let pure = registry
        .pure_transform(stage.spec.as_str())
        .ok_or_else(|| ProfileError::UnknownSpec {
            profile: stage.profile.clone(),
            stage: stage.stage_id.clone(),
            spec: stage.spec.to_string(),
        })?;
    let spec_digest = pure.spec_digest();
    if stage.spec_digest != spec_digest || parser_generation != pure.parser_generation {
        return Err(ProfileError::Snapshot {
            detail: "admitted pure transform spec or parser generation changed".to_owned(),
        });
    }
    let snapshot_json = registry.persist()?;
    verify_pure_snapshot(
        &snapshot_json,
        stage.spec.as_str(),
        &spec_digest,
        parser_generation,
    )?;
    Ok(PureTransformSubmission {
        snapshot_json,
        spec_id: stage.spec.to_string(),
        spec_digest,
        parser_generation,
    })
}

fn verify_pure_snapshot(
    snapshot_json: &str,
    spec_id: &str,
    expected_digest: &str,
    expected_parser_generation: u64,
) -> Result<(), ProfileError> {
    let recovered = InstrumentRegistry::recover(snapshot_json)?;
    let pure = recovered
        .pure_transform(spec_id)
        .ok_or_else(|| ProfileError::Snapshot {
            detail: "registered pure transform is absent from the recovered snapshot".to_owned(),
        })?;
    if pure.spec_digest() != expected_digest || pure.parser_generation != expected_parser_generation
    {
        return Err(ProfileError::Snapshot {
            detail:
                "recovered pure transform differs from its admitted digest or parser generation"
                    .to_owned(),
        });
    }
    Ok(())
}
