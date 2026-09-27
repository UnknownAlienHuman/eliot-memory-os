//! Provider-neutral inputs, policy and receipts for replaceable translation.
//!
//! This module owns no provider SDK, transport, route admission or durable
//! storage. Translated events reuse the closed host-event contract; raw input
//! stays behind its restricted handle and immutable shared buffer.

use std::{fmt, sync::Arc};

use eliot_contracts::{
    ArtifactId, LowercaseSha256, PolicyRevision, ResourceGeneration, canonical_json_bytes,
    sha256_hex,
};
use eliot_observation_contracts::{ObservationError, PrivacyRetentionDisclosure};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ContractError, HOST_EVENT_RAW_BYTES_DIGEST_ALGORITHM, NormalizedHostEventEnvelope,
    NormalizedHostEventPayload, QualifiedSourceDigest, RawSourceRecord, RestrictedRawSourceHandle,
    RouteFingerprint,
};

/// Provider payload metadata plus its opaque immutable source identity.
///
/// The raw bytes are carried separately by [`SharedProviderPayload`] so cloning
/// this metadata never clones a provider context tree.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPayloadHandle {
    /// Immutable raw or deterministically redacted source binding.
    pub raw_source: RawSourceRecord,
    /// States whether the stored representation is exact provider input or a
    /// referenced deterministic redacted projection.
    pub representation: ProviderRepresentation,
    /// Source wire-format identity, including its version where applicable.
    pub wire_format: String,
    /// Existing privacy-domain, retention-policy and disclosure references.
    pub privacy_retention_disclosure: PrivacyRetentionDisclosure,
    /// Producer route identity, not route admission or authority.
    pub producer_route: RouteFingerprint,
    /// Producer runtime generation.
    pub producer_generation: ResourceGeneration,
}

impl ProviderPayloadHandle {
    /// Validates metadata without resolving or exposing its source bytes.
    pub fn validate(&self) -> Result<(), TranslationError> {
        text(&self.wire_format, "wire_format")?;
        self.raw_source
            .validate()
            .map_err(TranslationError::SourceContract)?;
        if matches!(
            &self.representation,
            ProviderRepresentation::DeterministicallyRedacted { .. }
        ) && self.raw_source.digest.algorithm != HOST_EVENT_RAW_BYTES_DIGEST_ALGORITHM
        {
            return Err(TranslationError::RepresentationDigestMismatch);
        }
        self.privacy_retention_disclosure
            .validate()
            .map_err(TranslationError::PrivacyContract)?;
        self.producer_route
            .validate()
            .map_err(TranslationError::SourceContract)
    }

    /// Returns the opaque restricted source handle.
    #[must_use]
    pub const fn source_handle(&self) -> &RestrictedRawSourceHandle {
        &self.raw_source.handle
    }

    /// Returns the algorithm-qualified source digest.
    #[must_use]
    pub const fn source_digest(&self) -> &QualifiedSourceDigest {
        &self.raw_source.digest
    }
}

/// Caller-supplied bound applied separately to each serialized translation
/// component. It introduces no default or policy-owned numeric limit.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranslationByteBounds {
    /// Maximum bytes for each bounded component; must be positive.
    pub max_component_bytes: usize,
}

impl TranslationByteBounds {
    fn validate(&self) -> Result<(), TranslationError> {
        if self.max_component_bytes == 0 {
            return Err(TranslationError::InvalidByteBound);
        }
        Ok(())
    }

    fn check(&self, field: &'static str, bytes: &[u8]) -> Result<(), TranslationError> {
        self.validate()?;
        if bytes.len() > self.max_component_bytes {
            return Err(TranslationError::ByteBoundExceeded(field));
        }
        Ok(())
    }

    fn check_serialized<T: Serialize>(
        &self,
        field: &'static str,
        value: &T,
    ) -> Result<(), TranslationError> {
        let bytes = canonical_json_bytes(value).map_err(|_| TranslationError::DigestEncoding)?;
        self.check(field, &bytes)
    }
}

/// Explicit identity of the source representation held by the shared bundle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProviderRepresentation {
    /// The buffer contains exact provider wire bytes.
    ExactRaw,
    /// The buffer contains the referenced deterministic redacted projection.
    DeterministicallyRedacted { projection_ref: ArtifactId },
}

/// Immutable provider bytes shared across retries and classifiers.
///
/// The custom debug output intentionally omits raw provider bytes.
#[derive(Clone)]
pub struct SharedProviderPayload {
    handle: ProviderPayloadHandle,
    bytes: Arc<[u8]>,
    digest_verified: bool,
    byte_bounds: TranslationByteBounds,
}

impl SharedProviderPayload {
    /// Creates a shared payload from already admitted metadata and bytes.
    ///
    /// When the digest names exact raw bytes, those bytes are recomputed here.
    /// Canonical-message digests are recomputed by the decoder after parsing.
    pub fn new(
        handle: ProviderPayloadHandle,
        bytes: impl Into<Arc<[u8]>>,
        byte_bounds: TranslationByteBounds,
    ) -> Result<Self, TranslationError> {
        handle.validate()?;
        byte_bounds.validate()?;
        byte_bounds.check_serialized("source_handle_metadata", &handle)?;
        let bytes = bytes.into();
        byte_bounds.check("source_bytes", &bytes)?;
        let digest_verified =
            if handle.raw_source.digest.algorithm == HOST_EVENT_RAW_BYTES_DIGEST_ALGORITHM {
                handle
                    .raw_source
                    .digest
                    .verify_raw_bytes(&bytes)
                    .map_err(|_| TranslationError::SourceDigestMismatch)?;
                true
            } else {
                false
            };
        Ok(Self {
            handle,
            bytes,
            digest_verified,
            byte_bounds,
        })
    }

    /// Verifies a decoded canonical source message against its qualified digest.
    pub fn verify_canonical_source<T: Serialize>(
        mut self,
        decoded_message: &T,
    ) -> Result<Self, TranslationError> {
        self.byte_bounds
            .check_serialized("decoded_source_message", decoded_message)?;
        self.handle
            .raw_source
            .digest
            .verify_canonical_message(decoded_message)
            .map_err(|_| TranslationError::SourceDigestMismatch)?;
        self.digest_verified = true;
        Ok(self)
    }

    /// Returns immutable payload metadata.
    #[must_use]
    pub const fn handle(&self) -> &ProviderPayloadHandle {
        &self.handle
    }

    /// Returns read-only source bytes to the admitted translation bridge.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns whether the qualified source digest was recomputed successfully.
    #[must_use]
    pub const fn digest_is_verified(&self) -> bool {
        self.digest_verified
    }

    /// Exact byte replay needs verification of the stored bytes themselves.
    #[must_use]
    pub fn exact_replay_source_is_verified(&self) -> bool {
        self.digest_verified
            && self.handle.raw_source.digest.algorithm == HOST_EVENT_RAW_BYTES_DIGEST_ALGORITHM
    }
}

impl fmt::Debug for SharedProviderPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedProviderPayload")
            .field("handle", &self.handle)
            .field("bytes", &"<restricted>")
            .finish_non_exhaustive()
    }
}

/// Named translation-policy family.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TranslationProfileKind {
    Exploratory,
    AgentTooling,
    ProofBearing,
    SameFormatExact,
}

/// Behavior for fields the target format does not recognize.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnknownFieldPolicy {
    Preserve,
    DropWithReceipt,
    Reject,
}

/// Permission for a conversion that loses source information.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LossyConversionPolicy {
    Reject,
    PermitWithReceipt,
}

/// Behavior for identifiers that cannot be represented directly by a target.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentifierPolicy {
    Preserve,
    RemapWithReceipt,
    Reject,
}

/// Policy for retaining an exact source representation across conversion.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PreservationPolicy {
    PreferExact,
    Normalize,
    RequireExact,
}

/// Ordering contract applied to reasoning and visible-answer events.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "source_semantics_ref",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum ReasoningOrderingPolicy {
    /// Reasoning deltas precede the first visible-answer delta in an event set.
    ReasoningBeforeVisibleAnswer,
    /// Source semantics explicitly define another ordering.
    SourceDefined(ArtifactId),
}

/// Versioned, provider-neutral translation policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranslationPolicyProfile {
    /// Stable profile identity.
    pub profile_id: String,
    /// Immutable policy revision.
    pub revision: PolicyRevision,
    /// Policy family required by the caller.
    pub profile: TranslationProfileKind,
    /// Unknown-field behavior.
    pub unknown_field_policy: UnknownFieldPolicy,
    /// Lossy-conversion behavior.
    pub lossy_conversion_policy: LossyConversionPolicy,
    /// Identifier conversion behavior.
    pub identifier_policy: IdentifierPolicy,
    /// Exact-source preservation behavior.
    pub preservation_policy: PreservationPolicy,
    /// Target capabilities required by this translation.
    pub target_capability_requirements: Vec<String>,
    /// Reasoning and visible-answer ordering rule.
    pub reasoning_ordering: ReasoningOrderingPolicy,
    /// Caller-supplied serialized component bound shared with the source bundle.
    pub byte_bounds: TranslationByteBounds,
}

impl TranslationPolicyProfile {
    /// Validates policy identity and capability references.
    pub fn validate(&self) -> Result<(), TranslationError> {
        text(&self.profile_id, "translation_policy_profile_id")?;
        for capability in &self.target_capability_requirements {
            text(capability, "target_capability_requirement")?;
        }
        self.byte_bounds.validate()?;
        self.byte_bounds
            .check_serialized("translation_policy_profile", self)?;
        Ok(())
    }
}

/// Codec identity and revision used for a translation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodecRevision {
    /// Stable codec identity.
    pub codec_id: String,
    /// Immutable codec revision.
    pub revision: String,
}

impl CodecRevision {
    fn validate(&self) -> Result<(), TranslationError> {
        text(&self.codec_id, "codec_id")?;
        text(&self.revision, "codec_revision")
    }
}

/// Provider-neutral runtime IR for one explicitly identified provider-event
/// boundary, using the existing normalized event contract.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderNeutralRuntimeIr {
    boundary_ref: ArtifactId,
    events: Vec<NormalizedHostEventEnvelope>,
}

impl ProviderNeutralRuntimeIr {
    /// Creates one boundary's event set after enforcing its reasoning/answer order.
    pub fn new(
        boundary_ref: ArtifactId,
        events: Vec<NormalizedHostEventEnvelope>,
        ordering: &ReasoningOrderingPolicy,
    ) -> Result<Self, TranslationError> {
        let ir = Self {
            boundary_ref,
            events,
        };
        ir.validate_order(ordering)?;
        Ok(ir)
    }

    /// Returns the explicit provider-event boundary identity for this IR.
    #[must_use]
    pub const fn boundary_ref(&self) -> &ArtifactId {
        &self.boundary_ref
    }

    /// Returns the normalized ELIOT-owned host events by shared reference.
    #[must_use]
    pub fn events(&self) -> &[NormalizedHostEventEnvelope] {
        &self.events
    }

    fn validate_order(&self, ordering: &ReasoningOrderingPolicy) -> Result<(), TranslationError> {
        if matches!(ordering, ReasoningOrderingPolicy::SourceDefined(_)) {
            return Ok(());
        }

        let mut visible_answer_started = false;
        for event in &self.events {
            match &event.payload {
                NormalizedHostEventPayload::AssistantDelta(_) => visible_answer_started = true,
                NormalizedHostEventPayload::ReasoningSummary(_) if visible_answer_started => {
                    return Err(TranslationError::ReasoningAfterVisibleAnswer);
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Explicit provider-protocol transformation recorded in a translation receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum TranslationTransform {
    BufferedToStream,
    StreamToBuffered,
    ToolArgumentRepair {
        diagnostic_ref: ArtifactId,
    },
    UnknownBlockDrop {
        diagnostic_ref: ArtifactId,
        omission_handle: ArtifactId,
        recovery_handle: Option<ArtifactId>,
    },
    OutputIndexCollapse {
        source_index: u64,
        target_index: u64,
    },
    EventReorder {
        event_id: crate::EventId,
        source_position: u64,
        target_position: u64,
    },
    SyntheticReconstruction {
        output_ref: ArtifactId,
        source_ref: Option<ArtifactId>,
    },
}

/// Transformation plus the existing receipt proof ceiling for its claim.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptedTranslationTransform {
    /// Concrete protocol change performed by the translator.
    pub transformation: TranslationTransform,
    /// Proof ceiling claimed by this transformation receipt.
    pub proof_ceiling: crate::ProofCeiling,
}

/// Event identity and positions for one explicit ordering change.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventOrderChange {
    /// Stable event identity.
    pub event_id: crate::EventId,
    /// Original event position.
    pub source_position: u64,
    /// Translated event position.
    pub target_position: u64,
}

/// Typed diagnostic returned by a load-bearing translation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranslationDiagnostic {
    /// Stable diagnostic artifact identity.
    pub diagnostic_ref: ArtifactId,
    /// Diagnostic category, without provider-controlled free-form text.
    pub code: String,
}

/// Information-loss class recorded by the translation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TranslationLossClass {
    None,
    Lossy,
    Unknown,
}

/// Exact-replay invalidation fact caused by normalized-content mutation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NormalizedMutation {
    ContentChanged,
}

/// Machine-readable account of one provider-to-ELIOT translation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranslationReceipt {
    /// Raw source handle linked to the translation.
    pub source_handle: RestrictedRawSourceHandle,
    /// Source wire-format identity.
    pub source_wire_format: String,
    /// Target wire-format identity.
    pub target_wire_format: String,
    /// Codec identity and version.
    pub codec_revision: CodecRevision,
    /// Policy profile identity and version.
    pub policy_profile_id: String,
    /// Policy revision used by the translator.
    pub policy_revision: PolicyRevision,
    /// Digest of source provider bytes/message.
    pub source_digest: LowercaseSha256,
    /// Digest of the provider-neutral normalized IR.
    pub normalized_digest: LowercaseSha256,
    /// Digest of target-format bytes at translation time; after normalized
    /// mutation this identifies historical output whose bytes are unavailable.
    pub target_digest: LowercaseSha256,
    /// Diagnostics associated with this translation.
    pub diagnostics: Vec<ArtifactId>,
    /// Declared information-loss class.
    pub loss_class: TranslationLossClass,
    /// Explicit protocol transformations performed.
    pub transformations: Vec<ReceiptedTranslationTransform>,
    /// Event ordering changes, separately inspectable from other transforms.
    pub event_order_changes: Vec<EventOrderChange>,
    /// Synthetic output or evidence handles created by reconstruction.
    pub synthetic_reconstruction: Vec<ArtifactId>,
    /// Whether exact source-format replay was used for this translation.
    pub exact_replay_used: bool,
    /// Generation of the preserved source representation.
    pub preservation_generation: ResourceGeneration,
    /// Mutation that invalidated normalized exact replay, if any.
    pub invalidated_by_mutation: Option<NormalizedMutation>,
    /// Handles for content omitted from the target representation.
    pub omission_handles: Vec<ArtifactId>,
    /// Handles for recovery paths or preserved omitted content.
    pub recovery_handles: Vec<ArtifactId>,
    /// Reference to source-defined ordering semantics when applied.
    pub source_ordering_semantics_ref: Option<ArtifactId>,
}

impl TranslationReceipt {
    /// Returns whether exact source replay remains valid for the current IR.
    #[must_use]
    pub const fn replay_is_exact_preserved(&self) -> bool {
        self.exact_replay_used && self.invalidated_by_mutation.is_none()
    }

    fn invalidate_replay(&mut self) -> Result<(), TranslationError> {
        self.preservation_generation = self
            .preservation_generation
            .next()
            .map_err(|_| TranslationError::PreservationGenerationOverflow)?;
        self.invalidated_by_mutation = Some(NormalizedMutation::ContentChanged);
        Ok(())
    }

    fn validate(&self, policy: &TranslationPolicyProfile) -> Result<(), TranslationError> {
        text(&self.source_wire_format, "source_wire_format")?;
        text(&self.target_wire_format, "target_wire_format")?;
        text(&self.policy_profile_id, "policy_profile_id")?;
        self.codec_revision.validate()?;
        let omission_handles = self
            .transformations
            .iter()
            .filter_map(|entry| match &entry.transformation {
                TranslationTransform::UnknownBlockDrop {
                    omission_handle, ..
                } => Some(omission_handle.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let recovery_handles = self
            .transformations
            .iter()
            .filter_map(|entry| match &entry.transformation {
                TranslationTransform::UnknownBlockDrop {
                    recovery_handle, ..
                } => recovery_handle.clone(),
                _ => None,
            })
            .collect::<Vec<_>>();
        let event_order_changes = self
            .transformations
            .iter()
            .filter_map(|entry| match &entry.transformation {
                TranslationTransform::EventReorder {
                    event_id,
                    source_position,
                    target_position,
                } => Some(EventOrderChange {
                    event_id: event_id.clone(),
                    source_position: *source_position,
                    target_position: *target_position,
                }),
                _ => None,
            })
            .collect::<Vec<_>>();
        let synthetic_reconstruction = self
            .transformations
            .iter()
            .filter_map(|entry| match &entry.transformation {
                TranslationTransform::SyntheticReconstruction { output_ref, .. } => {
                    Some(output_ref.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let dropped_block_diagnostic_missing = self.transformations.iter().any(|entry| {
            matches!(
                &entry.transformation,
                TranslationTransform::UnknownBlockDrop { diagnostic_ref, .. }
                    | TranslationTransform::ToolArgumentRepair { diagnostic_ref }
                    if !self.diagnostics.contains(diagnostic_ref)
            )
        });
        let has_dropped_blocks = self.transformations.iter().any(|entry| {
            matches!(
                &entry.transformation,
                TranslationTransform::UnknownBlockDrop { .. }
            )
        });
        if self
            .transformations
            .iter()
            .any(|entry| entry.proof_ceiling != crate::ProofCeiling::Observation)
            || self.omission_handles != omission_handles
            || self.recovery_handles != recovery_handles
            || self.event_order_changes != event_order_changes
            || self.synthetic_reconstruction != synthetic_reconstruction
            || dropped_block_diagnostic_missing
            || (has_dropped_blocks && self.loss_class == TranslationLossClass::None)
            || (self.loss_class == TranslationLossClass::None && !self.omission_handles.is_empty())
            || (policy.unknown_field_policy == UnknownFieldPolicy::Reject && has_dropped_blocks)
            || (policy.unknown_field_policy == UnknownFieldPolicy::Preserve && has_dropped_blocks)
            || (policy.lossy_conversion_policy == LossyConversionPolicy::Reject
                && self.loss_class != TranslationLossClass::None)
            || (policy.preservation_policy == PreservationPolicy::RequireExact
                && !self.exact_replay_used)
            || (policy.profile == TranslationProfileKind::SameFormatExact
                && !self.exact_replay_used)
        {
            return Err(TranslationError::InconsistentTranslationFacts);
        }
        if self.exact_replay_used
            && (self.source_wire_format != self.target_wire_format
                || !self.transformations.is_empty()
                || self.loss_class != TranslationLossClass::None)
        {
            return Err(TranslationError::InvalidExactReplayClaim);
        }
        Ok(())
    }
}

/// Successful load-bearing conversion: typed IR, diagnostics and receipt.
pub struct TranslatedProviderPayload {
    source: SharedProviderPayload,
    target_wire_format: Option<String>,
    target_bytes: Option<Arc<[u8]>>,
    ir: ProviderNeutralRuntimeIr,
    diagnostics: Vec<TranslationDiagnostic>,
    receipt: TranslationReceipt,
    ordering: ReasoningOrderingPolicy,
    byte_bounds: TranslationByteBounds,
}

impl TranslatedProviderPayload {
    /// Checks that the output artifact, source handle, policy and receipt agree.
    pub fn new(
        source: SharedProviderPayload,
        target_bytes: impl Into<Arc<[u8]>>,
        ir: ProviderNeutralRuntimeIr,
        diagnostics: Vec<TranslationDiagnostic>,
        receipt: TranslationReceipt,
        policy: &TranslationPolicyProfile,
        overlay: &TranslationOverlay,
    ) -> Result<Self, TranslationError> {
        policy.validate()?;
        overlay.validate(&policy.byte_bounds)?;
        receipt.validate(policy)?;
        for diagnostic in &diagnostics {
            text(&diagnostic.code, "translation_diagnostic_code")?;
        }
        let target_bytes = target_bytes.into();
        if &receipt.source_handle != source.handle.source_handle()
            || receipt.source_wire_format != source.handle.wire_format
            || receipt.target_wire_format.trim().is_empty()
            || receipt.target_wire_format != overlay.target_wire_format
            || receipt
                .transformations
                .iter()
                .map(|entry| &entry.transformation)
                .ne(overlay.transformations.iter())
            || receipt.source_digest != source.handle.raw_source.digest.digest
            || receipt.policy_profile_id != policy.profile_id
            || receipt.policy_revision != policy.revision
            || source.byte_bounds != policy.byte_bounds
            || receipt.invalidated_by_mutation.is_some()
        {
            return Err(TranslationError::ReceiptBindingMismatch);
        }
        ir.validate_order(&policy.reasoning_ordering)?;
        policy.byte_bounds.check_serialized("normalized_ir", &ir)?;
        policy.byte_bounds.check("target_bytes", &target_bytes)?;
        policy
            .byte_bounds
            .check_serialized("receipt_and_diagnostics", &(&receipt, &diagnostics))?;
        if receipt.normalized_digest != canonical_digest(&ir)?
            || receipt.target_digest != byte_digest(&target_bytes)?
        {
            return Err(TranslationError::OutputDigestMismatch);
        }
        if receipt.exact_replay_used
            && (!source.exact_replay_source_is_verified()
                || source.bytes() != target_bytes.as_ref())
        {
            return Err(TranslationError::InvalidExactReplayClaim);
        }
        if receipt.diagnostics != diagnostic_refs(&diagnostics) {
            return Err(TranslationError::DiagnosticBindingMismatch);
        }
        match &policy.reasoning_ordering {
            ReasoningOrderingPolicy::SourceDefined(reference)
                if receipt.source_ordering_semantics_ref.as_ref() != Some(reference) =>
            {
                return Err(TranslationError::MissingOrderingSemantics);
            }
            ReasoningOrderingPolicy::ReasoningBeforeVisibleAnswer
                if receipt.source_ordering_semantics_ref.is_some() =>
            {
                return Err(TranslationError::UnexpectedOrderingSemantics);
            }
            _ => {}
        }
        Ok(Self {
            source,
            target_wire_format: Some(receipt.target_wire_format.clone()),
            target_bytes: Some(target_bytes),
            ir,
            diagnostics,
            receipt,
            ordering: policy.reasoning_ordering.clone(),
            byte_bounds: policy.byte_bounds.clone(),
        })
    }

    /// Returns normalized events by shared reference.
    #[must_use]
    pub fn ir(&self) -> &ProviderNeutralRuntimeIr {
        &self.ir
    }

    /// Returns diagnostics for this translation.
    #[must_use]
    pub fn diagnostics(&self) -> &[TranslationDiagnostic] {
        &self.diagnostics
    }

    /// Returns the translation receipt.
    #[must_use]
    pub const fn receipt(&self) -> &TranslationReceipt {
        &self.receipt
    }

    /// Returns immutable target-format bytes.
    #[must_use]
    pub fn target_bytes(&self) -> Option<&[u8]> {
        self.target_bytes.as_deref()
    }

    /// Returns the target wire-format identity.
    #[must_use]
    pub fn target_wire_format(&self) -> Option<&str> {
        self.target_wire_format.as_deref()
    }

    /// Returns the shared source bundle and its restricted payload handle.
    #[must_use]
    pub const fn source(&self) -> &SharedProviderPayload {
        &self.source
    }

    /// Edits normalized content only after invalidating exact replay.
    ///
    /// The value is consumed, and replay invalidation is recorded before the
    /// closure receives mutable content. An error or panic cannot return the
    /// prior exact-preserved value.
    pub fn edit_normalized(
        mut self,
        edit: impl FnOnce(&mut Vec<NormalizedHostEventEnvelope>) -> Result<(), TranslationError>,
    ) -> Result<Self, TranslationError> {
        self.receipt.invalidate_replay()?;
        self.target_bytes = None;
        self.target_wire_format = None;
        edit(&mut self.ir.events)?;
        self.ir.validate_order(&self.ordering)?;
        self.byte_bounds
            .check_serialized("normalized_ir", &self.ir)?;
        self.receipt.normalized_digest = canonical_digest(&self.ir)?;
        self.byte_bounds.check_serialized(
            "receipt_and_diagnostics",
            &(&self.receipt, &self.diagnostics),
        )?;
        Ok(self)
    }
}

impl fmt::Debug for TranslatedProviderPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TranslatedProviderPayload")
            .field("source", &self.source.handle)
            .field("target_wire_format", &self.target_wire_format)
            .field("target_bytes", &"<restricted>")
            .field("ir_event_count", &self.ir.events.len())
            .field("diagnostics", &self.diagnostics)
            .field("receipt", &self.receipt)
            .finish_non_exhaustive()
    }
}

/// Replaceable protocol-translation bridge interface.
pub trait ProviderTranslationBridge: Send + Sync {
    /// Translates one shared source using the explicit policy and overlay.
    /// Implementations validate the overlay against `policy.byte_bounds` before
    /// processing its transformations.
    fn translate(
        &self,
        source: &SharedProviderPayload,
        policy: &TranslationPolicyProfile,
        overlay: &TranslationOverlay,
    ) -> Result<TranslatedProviderPayload, TranslationError>;
}

/// Small target-specific transformation overlay; source content stays shared.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranslationOverlay {
    /// Target wire-format identity.
    pub target_wire_format: String,
    /// Explicit transformations requested or performed for this target.
    pub transformations: Vec<TranslationTransform>,
}

impl TranslationOverlay {
    /// Validates target format identity.
    pub fn validate(&self, byte_bounds: &TranslationByteBounds) -> Result<(), TranslationError> {
        text(&self.target_wire_format, "target_wire_format")?;
        byte_bounds.check_serialized("translation_overlay", self)
    }
}

fn diagnostic_refs(diagnostics: &[TranslationDiagnostic]) -> Vec<ArtifactId> {
    diagnostics
        .iter()
        .map(|diagnostic| diagnostic.diagnostic_ref.clone())
        .collect()
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<LowercaseSha256, TranslationError> {
    let bytes = canonical_json_bytes(value).map_err(|_| TranslationError::DigestEncoding)?;
    let digest = sha256_hex(&bytes);
    serde_json::from_value(serde_json::Value::String(digest))
        .map_err(|_| TranslationError::DigestEncoding)
}

fn byte_digest(bytes: &[u8]) -> Result<LowercaseSha256, TranslationError> {
    serde_json::from_value(serde_json::Value::String(sha256_hex(bytes)))
        .map_err(|_| TranslationError::DigestEncoding)
}

fn text(value: &str, field: &'static str) -> Result<(), TranslationError> {
    if value.trim().is_empty() {
        return Err(TranslationError::EmptyField(field));
    }
    if value.chars().any(char::is_control) {
        return Err(TranslationError::InvalidText(field));
    }
    Ok(())
}

/// Translation contract validation and coherence failures.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TranslationError {
    #[error("empty translation field: {0}")]
    EmptyField(&'static str),
    #[error("invalid text in translation field: {0}")]
    InvalidText(&'static str),
    #[error("raw source digest does not match the shared bytes")]
    SourceDigestMismatch,
    #[error("translation byte bound must be positive")]
    InvalidByteBound,
    #[error("translation component exceeds its caller-supplied byte bound: {0}")]
    ByteBoundExceeded(&'static str),
    #[error("redacted source representation requires a raw-bytes digest")]
    RepresentationDigestMismatch,
    #[error("provider source and translation receipt do not match")]
    ReceiptBindingMismatch,
    #[error("translated bytes or normalized IR do not match their receipt digests")]
    OutputDigestMismatch,
    #[error("diagnostic references do not match the receipt")]
    DiagnosticBindingMismatch,
    #[error("exact replay was claimed for changed or transformed content")]
    InvalidExactReplayClaim,
    #[error("translation policy, loss and omission facts contradict one another")]
    InconsistentTranslationFacts,
    #[error("reasoning content followed visible-answer content")]
    ReasoningAfterVisibleAnswer,
    #[error("source ordering semantics are missing from the receipt")]
    MissingOrderingSemantics,
    #[error("receipt names source ordering semantics that the policy does not allow")]
    UnexpectedOrderingSemantics,
    #[error("preservation generation cannot advance")]
    PreservationGenerationOverflow,
    #[error("translation digest could not be encoded")]
    DigestEncoding,
    #[error("source contract validation failed: {0}")]
    SourceContract(ContractError),
    #[error("privacy metadata validation failed: {0}")]
    PrivacyContract(ObservationError),
}
