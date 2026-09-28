//! Executable, receipt-bearing provider conversion transformations.
//!
//! The provider-neutral contract owner stays in the parent module. This module
//! only executes the conversions that produce a
//! [`ProviderNeutralRuntimeIr`](super::ProviderNeutralRuntimeIr), the derived
//! target artifact, typed diagnostics, and one
//! [`TranslationReceipt`](super::TranslationReceipt) bound to that exact
//! conversion (issue #1833 W4/W6/A1, I10.11). Buffered/stream conversion,
//! tool-argument repair, unknown-block dropping, output-index collapse and
//! event reordering are explicit receipt-bearing transformations here, not
//! conveniences a caller may apply silently.
//!
//! It owns no provider SDK, wire codec, transport, route admission, durable
//! state, or finish authority, and it introduces no second IR, receipt, or
//! translation owner: the single conversion entry point is
//! [`ProviderTranslationBridge::translate`], whose result cannot exist without
//! its diagnostics and translation receipt, and whose only post-translation
//! mutation path remains the parent's
//! [`edit_normalized`](super::TranslatedProviderPayload::edit_normalized).

use std::sync::Arc;

use eliot_contracts::{ArtifactId, LowercaseSha256, ResourceGeneration, canonical_json_bytes};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    CodecRevision, EventOrderChange, IdentifierPolicy, ProviderNeutralRuntimeIr,
    ProviderTranslationBridge, ReasoningOrderingPolicy, ReceiptedTranslationTransform,
    SharedProviderPayload, TranslatedProviderPayload, TranslationDiagnostic, TranslationError,
    TranslationLossClass, TranslationOverlay, TranslationPolicyProfile, TranslationReceipt,
    TranslationTransform, byte_digest, canonical_digest, text,
};
use crate::{EventId, NormalizedHostEventEnvelope, NormalizedHostEventPayload, ProofCeiling};

/// Diagnostic code recorded for one executed tool-argument repair.
const TOOL_ARGUMENT_REPAIR_CODE: &str = "TOOL_ARGUMENT_REPAIR";
/// Diagnostic code recorded for one dropped known unknown block.
const UNKNOWN_BLOCK_DROP_CODE: &str = "UNKNOWN_BLOCK_DROPPED";

/// Framing in which the source provider delivered, or the target format
/// requires, one provider event set.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderStreamFraming {
    /// One complete response carrying the whole event set.
    Buffered,
    /// Incremental events delivered in provider order.
    Stream,
}

/// One tool invocation whose provider-supplied arguments the target format
/// requires repaired before the invocation is representable.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolArgumentRepairRequest {
    /// Invocation correlation reference of the repaired invocation.
    pub invocation_ref: String,
    /// Digest of the repaired target-format argument object.
    pub repaired_arguments_digest: LowercaseSha256,
    /// Diagnostic identity recorded for this repair.
    pub diagnostic_ref: ArtifactId,
}

/// One known unknown provider block omitted from the target representation.
///
/// The dropped block is always a normalized
/// [`UnsupportedQuarantined`](crate::NormalizedHostEventPayload::UnsupportedQuarantined)
/// observation, so an omission is never an unreferenced discard: the receipt
/// names the diagnostic, the omission handle, and the recovery handle when a
/// preserved or re-derivable copy exists.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownBlockDropRequest {
    /// Identity of the quarantined unknown block to omit.
    pub event_id: EventId,
    /// Handle addressing the omitted block's content.
    pub omission_handle: ArtifactId,
    /// Handle addressing a recovery path or preserved copy of the block.
    pub recovery_handle: Option<ArtifactId>,
    /// Diagnostic identity recorded for this omission.
    pub diagnostic_ref: ArtifactId,
}

/// One source output index the target format represents under a different
/// single index.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputIndexCollapseRequest {
    /// Output index as observed in the source stream.
    pub source_index: u64,
    /// Output index used by the target format.
    pub target_index: u64,
}

/// One normalized event moved to an explicit position in the translated set.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventReorderRequest {
    /// Identity of the moved event.
    pub event_id: EventId,
    /// Required position in the translated event set, counted after every
    /// transformation previously executed by this same translation.
    pub target_position: u64,
}

/// One explicitly described provider event stream plus the transformations its
/// target format requires.
///
/// Every member is a caller-declared source fact. The bridge executes them and
/// records what it actually performed; the declared [`TranslationOverlay`] must
/// then name exactly the executed transformations, so an unrequested or
/// unperformed transformation can never reach a receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSourceStream {
    /// Codec identity and revision performing this translation.
    pub codec_revision: CodecRevision,
    /// Explicit provider-event boundary identity for the translated IR.
    pub boundary_ref: ArtifactId,
    /// Generation of the preserved source representation at translation time.
    pub preservation_generation: ResourceGeneration,
    /// Framing in which the source provider delivered the event set.
    pub source_framing: ProviderStreamFraming,
    /// Framing the target wire format requires.
    pub target_framing: ProviderStreamFraming,
    /// Normalized source events decoded from the shared provider payload.
    pub events: Vec<NormalizedHostEventEnvelope>,
    /// Tool invocations whose arguments require repair.
    pub tool_argument_repairs: Vec<ToolArgumentRepairRequest>,
    /// Known unknown blocks omitted from the target representation.
    pub unknown_block_drops: Vec<UnknownBlockDropRequest>,
    /// Source output indices collapsed onto a target output index.
    pub output_index_collapses: Vec<OutputIndexCollapseRequest>,
    /// Events moved to explicit target positions, applied in order.
    pub event_reorders: Vec<EventReorderRequest>,
}

/// Target-format projection of one source output index.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct OutputIndexMapping {
    source_index: u64,
    target_index: u64,
}

/// Derived target representation of one translation.
///
/// This is the target artifact whose bytes the receipt binds by digest: the
/// target wire-format identity, the framing this conversion selected, the
/// output-index map produced by explicit collapses, and the translated event
/// set. It is the target projection only; the provider-neutral IR remains the
/// single normalized owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct TranslatedTargetArtifact {
    target_wire_format: String,
    framing: ProviderStreamFraming,
    output_index_map: Vec<OutputIndexMapping>,
    events: Vec<NormalizedHostEventEnvelope>,
}

/// Transformations executed so far by one conversion, in execution order.
#[derive(Default)]
struct ConversionTrace {
    transformations: Vec<TranslationTransform>,
    diagnostics: Vec<TranslationDiagnostic>,
    event_order_changes: Vec<EventOrderChange>,
    omission_handles: Vec<ArtifactId>,
    recovery_handles: Vec<ArtifactId>,
    information_loss: bool,
    exact_replay_used: bool,
}

impl ConversionTrace {
    fn record_diagnostic(&mut self, diagnostic_ref: ArtifactId, code: &str) {
        self.diagnostics.push(TranslationDiagnostic {
            diagnostic_ref,
            code: code.to_owned(),
        });
    }

    fn diagnostic_refs(&self) -> Vec<ArtifactId> {
        self.diagnostics
            .iter()
            .map(|diagnostic| diagnostic.diagnostic_ref.clone())
            .collect()
    }
}

/// Replaceable provider-neutral conversion bridge for one described source
/// stream.
///
/// This is the single load-bearing conversion entry point on this boundary: it
/// returns a [`TranslatedProviderPayload`], which cannot exist without its
/// diagnostics and translation receipt.
pub struct ProviderStreamTranslationBridge {
    stream: ProviderSourceStream,
}

impl ProviderStreamTranslationBridge {
    /// Creates the bridge for one explicitly described provider event stream.
    #[must_use]
    pub const fn new(stream: ProviderSourceStream) -> Self {
        Self { stream }
    }
}

impl ProviderTranslationBridge for ProviderStreamTranslationBridge {
    /// Converts the described source stream under the explicit policy and
    /// overlay.
    ///
    /// Executed in a fixed order so the receipt is reproducible: tool-argument
    /// repair, unknown-block dropping, output-index collapse, buffered/stream
    /// conversion, then event reordering. The computed transformation list must
    /// equal the overlay's declared list exactly, otherwise the conversion is
    /// refused instead of publishing an unreceipted artifact.
    fn translate(
        &self,
        source: &SharedProviderPayload,
        policy: &TranslationPolicyProfile,
        overlay: &TranslationOverlay,
    ) -> Result<TranslatedProviderPayload, TranslationError> {
        policy.validate()?;
        overlay.validate(&policy.byte_bounds)?;
        policy
            .byte_bounds
            .check_serialized("decoded_source_message", &self.stream.events)?;

        let mut events = self.stream.events.clone();
        let mut trace = ConversionTrace::default();

        for repair in &self.stream.tool_argument_repairs {
            apply_tool_argument_repair(&mut events, repair, &mut trace)?;
        }
        for unknown_block in &self.stream.unknown_block_drops {
            apply_unknown_block_drop(&mut events, unknown_block, &mut trace)?;
        }
        let output_index_map =
            apply_output_index_collapses(&self.stream.output_index_collapses, policy, &mut trace)?;
        apply_framing(
            self.stream.source_framing,
            self.stream.target_framing,
            &mut trace,
        );
        for reorder in &self.stream.event_reorders {
            apply_event_reorder(&mut events, reorder, &mut trace)?;
        }

        if trace.transformations != overlay.transformations {
            return Err(TranslationError::ReceiptBindingMismatch);
        }

        // An unchanged, same-format conversion is the only case whose target
        // representation is the exact preserved source bytes; every other case
        // re-presents the translated event set and cannot claim exact replay.
        trace.exact_replay_used = trace.transformations.is_empty()
            && source.exact_replay_source_is_verified()
            && source.handle().wire_format == overlay.target_wire_format;
        let (target_bytes, events) = if trace.exact_replay_used {
            (Arc::from(source.bytes()), events)
        } else {
            let artifact = TranslatedTargetArtifact {
                target_wire_format: overlay.target_wire_format.clone(),
                framing: self.stream.target_framing,
                output_index_map,
                events,
            };
            let bytes =
                canonical_json_bytes(&artifact).map_err(|_| TranslationError::DigestEncoding)?;
            (Arc::from(bytes), artifact.events)
        };
        let ir = ProviderNeutralRuntimeIr::new(
            self.stream.boundary_ref.clone(),
            events,
            &policy.reasoning_ordering,
        )?;
        self.publish(source, policy, overlay, target_bytes, ir, trace)
    }
}

impl ProviderStreamTranslationBridge {
    /// Binds this executed conversion to one receipt and one target artifact.
    fn publish(
        &self,
        source: &SharedProviderPayload,
        policy: &TranslationPolicyProfile,
        overlay: &TranslationOverlay,
        target_bytes: Arc<[u8]>,
        ir: ProviderNeutralRuntimeIr,
        trace: ConversionTrace,
    ) -> Result<TranslatedProviderPayload, TranslationError> {
        let receipt = TranslationReceipt {
            source_handle: source.handle().source_handle().clone(),
            source_wire_format: source.handle().wire_format.clone(),
            target_wire_format: overlay.target_wire_format.clone(),
            codec_revision: self.stream.codec_revision.clone(),
            policy_profile_id: policy.profile_id.clone(),
            policy_revision: policy.revision,
            source_digest: source.handle().source_digest().digest.clone(),
            normalized_digest: canonical_digest(&ir)?,
            target_digest: byte_digest(&target_bytes)?,
            diagnostics: trace.diagnostic_refs(),
            loss_class: if trace.information_loss {
                TranslationLossClass::Lossy
            } else {
                TranslationLossClass::None
            },
            transformations: trace
                .transformations
                .into_iter()
                .map(|transformation| ReceiptedTranslationTransform {
                    transformation,
                    proof_ceiling: ProofCeiling::Observation,
                })
                .collect(),
            event_order_changes: trace.event_order_changes,
            synthetic_reconstruction: Vec::new(),
            exact_replay_used: trace.exact_replay_used,
            preservation_generation: self.stream.preservation_generation,
            invalidated_by_mutation: None,
            omission_handles: trace.omission_handles,
            recovery_handles: trace.recovery_handles,
            source_ordering_semantics_ref: match &policy.reasoning_ordering {
                ReasoningOrderingPolicy::SourceDefined(reference) => Some(reference.clone()),
                ReasoningOrderingPolicy::ReasoningBeforeVisibleAnswer => None,
            },
        };
        TranslatedProviderPayload::new(
            source.clone(),
            target_bytes,
            ir,
            trace.diagnostics,
            receipt,
            policy,
            overlay,
        )
    }
}

/// Rewrites one tool invocation's recorded argument digest to the repaired
/// target-format digest and records the repair with its diagnostic.
fn apply_tool_argument_repair(
    events: &mut [NormalizedHostEventEnvelope],
    repair: &ToolArgumentRepairRequest,
    trace: &mut ConversionTrace,
) -> Result<(), TranslationError> {
    text(
        &repair.invocation_ref,
        "tool_argument_repair_invocation_ref",
    )?;
    let mut repaired = false;
    for event in events.iter_mut() {
        if let NormalizedHostEventPayload::ToolInvocation(invocation) = &mut event.payload
            && invocation.invocation_ref == repair.invocation_ref
        {
            if invocation.arguments_digest == repair.repaired_arguments_digest {
                return Err(TranslationError::DegenerateTransformation);
            }
            invocation.arguments_digest = repair.repaired_arguments_digest.clone();
            repaired = true;
        }
    }
    if !repaired {
        return Err(TranslationError::UnknownTransformationTarget);
    }
    trace
        .transformations
        .push(TranslationTransform::ToolArgumentRepair {
            diagnostic_ref: repair.diagnostic_ref.clone(),
        });
    trace.record_diagnostic(repair.diagnostic_ref.clone(), TOOL_ARGUMENT_REPAIR_CODE);
    trace.information_loss = true;
    Ok(())
}

/// Omits one known unknown provider block, recording its diagnostic, omission
/// handle, and recovery handle when one exists.
fn apply_unknown_block_drop(
    events: &mut Vec<NormalizedHostEventEnvelope>,
    unknown_block: &UnknownBlockDropRequest,
    trace: &mut ConversionTrace,
) -> Result<(), TranslationError> {
    let position = events
        .iter()
        .position(|event| event.event_id == unknown_block.event_id)
        .ok_or(TranslationError::UnknownTransformationTarget)?;
    if !matches!(
        events[position].payload,
        NormalizedHostEventPayload::UnsupportedQuarantined(_)
    ) {
        return Err(TranslationError::NotAQuarantinedUnknownBlock);
    }
    events.remove(position);
    trace
        .transformations
        .push(TranslationTransform::UnknownBlockDrop {
            diagnostic_ref: unknown_block.diagnostic_ref.clone(),
            omission_handle: unknown_block.omission_handle.clone(),
            recovery_handle: unknown_block.recovery_handle.clone(),
        });
    trace.record_diagnostic(
        unknown_block.diagnostic_ref.clone(),
        UNKNOWN_BLOCK_DROP_CODE,
    );
    trace
        .omission_handles
        .push(unknown_block.omission_handle.clone());
    if let Some(recovery_handle) = &unknown_block.recovery_handle {
        trace.recovery_handles.push(recovery_handle.clone());
    }
    trace.information_loss = true;
    Ok(())
}

/// Maps every declared source output index onto its target output index.
fn apply_output_index_collapses(
    collapses: &[OutputIndexCollapseRequest],
    policy: &TranslationPolicyProfile,
    trace: &mut ConversionTrace,
) -> Result<Vec<OutputIndexMapping>, TranslationError> {
    if !collapses.is_empty() && policy.identifier_policy != IdentifierPolicy::RemapWithReceipt {
        return Err(TranslationError::InconsistentTranslationFacts);
    }
    let mut output_index_map = Vec::with_capacity(collapses.len());
    for collapse in collapses {
        if collapse.source_index == collapse.target_index {
            return Err(TranslationError::DegenerateTransformation);
        }
        if output_index_map
            .iter()
            .any(|mapping: &OutputIndexMapping| mapping.source_index == collapse.source_index)
        {
            return Err(TranslationError::InconsistentTranslationFacts);
        }
        output_index_map.push(OutputIndexMapping {
            source_index: collapse.source_index,
            target_index: collapse.target_index,
        });
        trace
            .transformations
            .push(TranslationTransform::OutputIndexCollapse {
                source_index: collapse.source_index,
                target_index: collapse.target_index,
            });
        trace.information_loss = true;
    }
    Ok(output_index_map)
}

/// Records the buffered/stream conversion the target format requires. The
/// normalized evidence is unchanged; the target representation is reframed.
fn apply_framing(
    source_framing: ProviderStreamFraming,
    target_framing: ProviderStreamFraming,
    trace: &mut ConversionTrace,
) {
    let conversion = match (source_framing, target_framing) {
        (ProviderStreamFraming::Stream, ProviderStreamFraming::Buffered) => {
            Some(TranslationTransform::StreamToBuffered)
        }
        (ProviderStreamFraming::Buffered, ProviderStreamFraming::Stream) => {
            Some(TranslationTransform::BufferedToStream)
        }
        (ProviderStreamFraming::Stream, ProviderStreamFraming::Stream)
        | (ProviderStreamFraming::Buffered, ProviderStreamFraming::Buffered) => None,
    };
    if let Some(conversion) = conversion {
        trace.transformations.push(conversion);
    }
}

/// Moves one event to its declared target position and records the exact source
/// and target positions of that move.
fn apply_event_reorder(
    events: &mut Vec<NormalizedHostEventEnvelope>,
    reorder: &EventReorderRequest,
    trace: &mut ConversionTrace,
) -> Result<(), TranslationError> {
    let source_position = events
        .iter()
        .position(|event| event.event_id == reorder.event_id)
        .ok_or(TranslationError::UnknownTransformationTarget)?;
    let source_position_index =
        u64::try_from(source_position).map_err(|_| TranslationError::DegenerateTransformation)?;
    let target_position = usize::try_from(reorder.target_position)
        .map_err(|_| TranslationError::DegenerateTransformation)?;
    let event = events.remove(source_position);
    if target_position > events.len() || target_position == source_position {
        return Err(TranslationError::DegenerateTransformation);
    }
    events.insert(target_position, event);
    trace
        .transformations
        .push(TranslationTransform::EventReorder {
            event_id: reorder.event_id.clone(),
            source_position: source_position_index,
            target_position: reorder.target_position,
        });
    trace.event_order_changes.push(EventOrderChange {
        event_id: reorder.event_id.clone(),
        source_position: source_position_index,
        target_position: reorder.target_position,
    });
    Ok(())
}
