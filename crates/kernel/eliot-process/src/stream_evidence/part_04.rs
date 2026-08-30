/// Immutable raw stream evidence bound to one exact process operation and policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamEvidence {
    schema_version: String,
    binding: ProcessExecutionBinding,
    stream: ProcessStreamKind,
    policy: ProcessStreamPolicyBinding,
    transport: StreamTransportStatus,
    persistence: StreamPersistenceStatus,
    observed_sha256: String,
    observed_bytes: u64,
    preview: ProcessStreamPrefixPreview,
    source: Option<DurableProcessStreamSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport_prefix_identity: Option<ProcessStreamTransportPrefixIdentity>,
    gaps: Vec<StreamEvidenceGap>,
    parsing: StreamParsingStatus,
    evaluation: StreamEvaluationStatus,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessStreamEvidenceWire {
    schema_version: String,
    binding: ProcessExecutionBinding,
    stream: ProcessStreamKind,
    policy: ProcessStreamPolicyBinding,
    transport: StreamTransportStatus,
    persistence: StreamPersistenceStatus,
    observed_sha256: String,
    observed_bytes: u64,
    preview: ProcessStreamPrefixPreview,
    source: Option<DurableProcessStreamSource>,
    #[serde(default)]
    transport_prefix_identity: Option<ProcessStreamTransportPrefixIdentity>,
    gaps: Vec<StreamEvidenceGap>,
    parsing: StreamParsingStatus,
    evaluation: StreamEvaluationStatus,
}

impl ProcessStreamEvidence {
    /// Creates raw capture evidence without a separate shorter-prefix identity.
    /// Parsing/evaluation cannot be promoted here.
    #[allow(clippy::too_many_arguments)]
    pub fn new_raw(
        binding: ProcessExecutionBinding,
        stream: ProcessStreamKind,
        policy: ProcessStreamPolicyBinding,
        transport: StreamTransportStatus,
        persistence: StreamPersistenceStatus,
        observed_sha256: impl Into<String>,
        observed_bytes: u64,
        preview: ProcessStreamPrefixPreview,
        source: Option<DurableProcessStreamSource>,
        gaps: Vec<StreamEvidenceGap>,
    ) -> Result<Self, ProcessStreamEvidenceError> {
        Self::new_raw_inner(
            binding,
            stream,
            policy,
            transport,
            persistence,
            observed_sha256.into(),
            observed_bytes,
            preview,
            source,
            None,
            gaps,
        )
    }

    /// Creates raw capture evidence with an explicit physical transport-prefix identity.
    ///
    /// The prefix identity is valid only for a shorter partial exact-transport source.
    #[allow(clippy::too_many_arguments)]
    pub fn new_raw_with_transport_prefix_identity(
        binding: ProcessExecutionBinding,
        stream: ProcessStreamKind,
        policy: ProcessStreamPolicyBinding,
        transport: StreamTransportStatus,
        persistence: StreamPersistenceStatus,
        observed_sha256: impl Into<String>,
        observed_bytes: u64,
        preview: ProcessStreamPrefixPreview,
        source: Option<DurableProcessStreamSource>,
        transport_prefix_identity: Option<ProcessStreamTransportPrefixIdentity>,
        gaps: Vec<StreamEvidenceGap>,
    ) -> Result<Self, ProcessStreamEvidenceError> {
        Self::new_raw_inner(
            binding,
            stream,
            policy,
            transport,
            persistence,
            observed_sha256.into(),
            observed_bytes,
            preview,
            source,
            transport_prefix_identity,
            gaps,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_raw_inner(
        binding: ProcessExecutionBinding,
        stream: ProcessStreamKind,
        policy: ProcessStreamPolicyBinding,
        transport: StreamTransportStatus,
        persistence: StreamPersistenceStatus,
        observed_sha256: String,
        observed_bytes: u64,
        preview: ProcessStreamPrefixPreview,
        source: Option<DurableProcessStreamSource>,
        transport_prefix_identity: Option<ProcessStreamTransportPrefixIdentity>,
        mut gaps: Vec<StreamEvidenceGap>,
    ) -> Result<Self, ProcessStreamEvidenceError> {
        gaps.sort_unstable();
        let value = Self {
            schema_version: PROCESS_STREAM_EVIDENCE_SCHEMA_VERSION.to_owned(),
            binding,
            stream,
            policy,
            transport,
            persistence,
            observed_sha256,
            observed_bytes,
            preview,
            source,
            transport_prefix_identity,
            gaps,
            parsing: StreamParsingStatus::Raw,
            evaluation: StreamEvaluationStatus::Unassessed,
        };
        value.validate()?;
        Ok(value)
    }

    /// Revalidates binding, preview, persistence and status invariants.
    pub fn validate(&self) -> Result<(), ProcessStreamEvidenceError> {
        if self.schema_version != PROCESS_STREAM_EVIDENCE_SCHEMA_VERSION {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "schema_version",
                reason: "unsupported process-stream evidence revision",
            });
        }
        validate_process_execution_binding(&self.binding)?;
        self.policy.validate()?;
        self.preview.validate()?;
        if let Some(prefix) = &self.transport_prefix_identity {
            prefix.validate()?;
        }
        validate_digest("observed_sha256", &self.observed_sha256)?;
        self.validate_gap_shape()?;
        if self.parsing != StreamParsingStatus::Raw
            || self.evaluation != StreamEvaluationStatus::Unassessed
        {
            return Err(ProcessStreamEvidenceError::AuthorityEscalation);
        }

        let gaps = self.gaps.iter().copied().collect::<BTreeSet<_>>();
        self.validate_transport(&gaps)?;
        self.validate_preview_and_representation(&gaps)?;
        self.validate_persistence(&gaps)
    }

    fn validate_gap_shape(&self) -> Result<(), ProcessStreamEvidenceError> {
        if self.gaps.len() > MAX_GAPS {
            return Err(ProcessStreamEvidenceError::LimitExceeded {
                field: "gaps",
                limit: MAX_GAPS,
            });
        }
        let unique = self.gaps.iter().copied().collect::<BTreeSet<_>>();
        if unique.len() != self.gaps.len() {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "gaps",
                reason: "gap reasons must be unique",
            });
        }
        if !self.gaps.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "gaps",
                reason: "gap reasons must use canonical sorted order",
            });
        }
        Ok(())
    }

    fn validate_transport(
        &self,
        gaps: &BTreeSet<StreamEvidenceGap>,
    ) -> Result<(), ProcessStreamEvidenceError> {
        let expected = expected_transport_gap(self.transport);
        for candidate in TRANSPORT_GAPS {
            let present = gaps.contains(&candidate);
            let required = expected == Some(candidate);
            if present != required {
                return Err(ProcessStreamEvidenceError::Invariant {
                    field: "transport",
                    reason: "transport status and transport coverage gaps contradict",
                });
            }
        }

        if self.transport == StreamTransportStatus::CaptureUnavailable {
            if self.observed_bytes != 0 || self.observed_sha256 != sha256_hex(&[]) {
                return Err(ProcessStreamEvidenceError::Invariant {
                    field: "observed_stream",
                    reason: "capture-unavailable transport cannot claim observed bytes",
                });
            }
            if self.persistence != StreamPersistenceStatus::SourceUnavailable {
                return Err(ProcessStreamEvidenceError::Invariant {
                    field: "persistence",
                    reason: "capture-unavailable transport cannot publish a durable source",
                });
            }
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the representation invariants are kept together to make fail-closed cross-field review explicit"
    )]
    fn validate_preview_and_representation(
        &self,
        gaps: &BTreeSet<StreamEvidenceGap>,
    ) -> Result<(), ProcessStreamEvidenceError> {
        let source_bytes_withheld = gaps.contains(&StreamEvidenceGap::PolicyProhibited)
            || gaps.contains(&StreamEvidenceGap::RedactionFailed);
        if source_bytes_withheld {
            if self.persistence != StreamPersistenceStatus::SourceUnavailable
                || self.source.is_some()
                || self.preview.representation != StreamPreviewRepresentation::WithheldByPolicy
            {
                return Err(ProcessStreamEvidenceError::Invariant {
                    field: "withheld_source",
                    reason: "prohibited or failed-redaction evidence cannot retain inline or durable source bytes",
                });
            }
        } else if self.preview.representation == StreamPreviewRepresentation::WithheldByPolicy {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "preview.representation",
                reason: "withheld preview requires POLICY_PROHIBITED or REDACTION_FAILED",
            });
        }

        match self.preview.representation {
            StreamPreviewRepresentation::TransportBytes => {
                if self.preview.represented_bytes != self.observed_bytes {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "preview.represented_bytes",
                        reason: "transport preview must use physical observed-byte coordinates",
                    });
                }
                if !self.preview.is_truncated() && self.preview.sha256 != self.observed_sha256 {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "observed_sha256",
                        reason: "complete transport preview must match observed stream identity",
                    });
                }
            }
            StreamPreviewRepresentation::DurableSourceBytes => {
                let source = self
                    .source
                    .as_ref()
                    .ok_or(ProcessStreamEvidenceError::Invariant {
                        field: "preview.representation",
                        reason: "durable-source preview requires a durable source",
                    })?;
                if source.representation != DurableStreamRepresentation::PolicyTransformed {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "preview.representation",
                        reason: "durable-source preview is reserved for policy-transformed bytes",
                    });
                }
                if self.preview.represented_bytes != source.byte_length {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "preview.represented_bytes",
                        reason: "source preview length must match durable source identity",
                    });
                }
                if self.preview.retained_bytes != 0 && self.preview.is_truncated() {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "preview",
                        reason: "non-empty transformed preview must contain the complete durable source",
                    });
                }
                if !self.preview.is_truncated() && self.preview.sha256 != source.sha256 {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "preview.sha256",
                        reason: "complete source preview must match durable source identity",
                    });
                }
            }
            StreamPreviewRepresentation::WithheldByPolicy => {}
        }

        if let Some(source) = &self.source {
            match source.representation {
                DurableStreamRepresentation::ExactTransportBytes => {
                    if self.preview.representation != StreamPreviewRepresentation::TransportBytes {
                        return Err(ProcessStreamEvidenceError::Invariant {
                            field: "preview.representation",
                            reason: "exact transport source requires transport-byte preview coordinates",
                        });
                    }
                }
                DurableStreamRepresentation::PolicyTransformed => {
                    let transformation = source.transformation.as_ref().ok_or(
                        ProcessStreamEvidenceError::Invariant {
                            field: "source.transformation",
                            reason: "policy-transformed source requires a transformation binding",
                        },
                    )?;
                    if transformation.input_sha256 != self.observed_sha256
                        || transformation.input_byte_length != self.observed_bytes
                        || transformation.output_sha256 != source.sha256
                        || transformation.output_byte_length != source.byte_length
                        || transformation.policy_ref != self.policy.policy_ref
                        || transformation.redaction_ref != self.policy.redaction_ref
                    {
                        return Err(ProcessStreamEvidenceError::Invariant {
                            field: "source.transformation",
                            reason: "transformation must bind exact input, output and policy identities",
                        });
                    }
                    if self.preview.representation
                        != StreamPreviewRepresentation::DurableSourceBytes
                    {
                        return Err(ProcessStreamEvidenceError::Invariant {
                            field: "preview.representation",
                            reason: "policy-transformed source cannot expose a raw transport preview",
                        });
                    }
                }
            }
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the persistence-state matrix is reviewed as one fail-closed invariant group"
    )]
    fn validate_persistence(
        &self,
        gaps: &BTreeSet<StreamEvidenceGap>,
    ) -> Result<(), ProcessStreamEvidenceError> {
        match self.persistence {
            StreamPersistenceStatus::CompleteSource => {
                if self.transport_prefix_identity.is_some() {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "transport_prefix_identity",
                        reason: "complete source cannot carry a shorter-prefix identity",
                    });
                }
                let source = self
                    .source
                    .as_ref()
                    .ok_or(ProcessStreamEvidenceError::Invariant {
                        field: "source",
                        reason: "complete source requires an immutable locator and ready receipt",
                    })?;
                if self.transport != StreamTransportStatus::Complete || !gaps.is_empty() {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "persistence",
                        reason: "complete source requires EOF and no coverage gaps",
                    });
                }
                if source.representation == DurableStreamRepresentation::ExactTransportBytes
                    && (source.byte_length != self.observed_bytes
                        || source.sha256 != self.observed_sha256)
                {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "source",
                        reason: "complete exact source must identify all observed transport bytes",
                    });
                }
            }
            StreamPersistenceStatus::PartialSource => {
                let source = self
                    .source
                    .as_ref()
                    .ok_or(ProcessStreamEvidenceError::Invariant {
                        field: "source",
                        reason: "partial source requires an immutable locator and ready receipt",
                    })?;
                if gaps.is_empty() {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "gaps",
                        reason: "partial source requires an explicit coverage gap",
                    });
                }
                match source.representation {
                    DurableStreamRepresentation::ExactTransportBytes => {
                        if source.byte_length > self.observed_bytes {
                            return Err(ProcessStreamEvidenceError::Invariant {
                                field: "source.byte_length",
                                reason: "exact durable bytes cannot exceed observed transport bytes",
                            });
                        }
                        if source.byte_length == self.observed_bytes {
                            if self.transport_prefix_identity.is_some() {
                                return Err(ProcessStreamEvidenceError::Invariant {
                                    field: "transport_prefix_identity",
                                    reason: "full observed source cannot carry a shorter-prefix identity",
                                });
                            }
                            if source.sha256 != self.observed_sha256 {
                                return Err(ProcessStreamEvidenceError::Invariant {
                                    field: "source.sha256",
                                    reason: "full-length exact source must match observed transport identity",
                                });
                            }
                            if self.transport == StreamTransportStatus::Complete {
                                return Err(ProcessStreamEvidenceError::Invariant {
                                    field: "persistence",
                                    reason: "full durable EOF coverage must be COMPLETE_SOURCE",
                                });
                            }
                        } else {
                            if !PARTIAL_PERSISTENCE_GAPS
                                .iter()
                                .any(|gap| gaps.contains(gap))
                            {
                                return Err(ProcessStreamEvidenceError::Invariant {
                                    field: "gaps",
                                    reason: "shorter exact source requires a persistence coverage gap",
                                });
                            }
                            let prefix = self.transport_prefix_identity.as_ref().ok_or(
                                ProcessStreamEvidenceError::Invariant {
                                    field: "transport_prefix_identity",
                                    reason: "shorter exact source requires a physical-prefix identity",
                                },
                            )?;
                            if prefix.byte_length != source.byte_length
                                || prefix.sha256 != source.sha256
                            {
                                return Err(ProcessStreamEvidenceError::Invariant {
                                    field: "transport_prefix_identity",
                                    reason: "prefix identity must exactly match the shorter durable source",
                                });
                            }
                        }
                    }
                    DurableStreamRepresentation::PolicyTransformed => {
                        if self.transport_prefix_identity.is_some() {
                            return Err(ProcessStreamEvidenceError::Invariant {
                                field: "transport_prefix_identity",
                                reason: "transformed source cannot carry a transport-prefix identity",
                            });
                        }
                        if self.transport == StreamTransportStatus::Complete {
                            return Err(ProcessStreamEvidenceError::Invariant {
                                field: "persistence",
                                reason: "complete transformed EOF source must be COMPLETE_SOURCE",
                            });
                        }
                    }
                }
            }
            StreamPersistenceStatus::SourceUnavailable => {
                if self.source.is_some() {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "source",
                        reason: "source-unavailable evidence cannot carry a durable locator",
                    });
                }
                if self.transport_prefix_identity.is_some() {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "transport_prefix_identity",
                        reason: "source-unavailable evidence cannot carry a durable-prefix identity",
                    });
                }
                if !SOURCE_UNAVAILABLE_GAPS.iter().any(|gap| gaps.contains(gap)) {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "gaps",
                        reason: "source-unavailable evidence requires a source-availability reason",
                    });
                }
                if self.preview.representation == StreamPreviewRepresentation::DurableSourceBytes {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "preview.representation",
                        reason: "source-unavailable evidence cannot preview a durable source",
                    });
                }
            }
        }
        Ok(())
    }

    /// Content identity over the complete typed evidence description.
    pub fn identity_sha256(&self) -> Result<String, ProcessStreamEvidenceError> {
        let bytes = canonical_json_bytes(self)
            .map_err(|error| ProcessStreamEvidenceError::Serialization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    /// Wire revision.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Exact process/authority binding.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        &self.binding
    }

    /// Stdout or stderr.
    pub const fn stream(&self) -> ProcessStreamKind {
        self.stream
    }

    /// Policy fixed before persistence.
    pub const fn policy(&self) -> &ProcessStreamPolicyBinding {
        &self.policy
    }

    /// Physical capture completion.
    pub const fn transport(&self) -> StreamTransportStatus {
        self.transport
    }

    /// Exact source durability.
    pub const fn persistence(&self) -> StreamPersistenceStatus {
        self.persistence
    }

    /// SHA-256 over every physical transport byte observed.
    pub fn observed_sha256(&self) -> &str {
        &self.observed_sha256
    }

    /// Number of physical transport bytes observed.
    pub const fn observed_bytes(&self) -> u64 {
        self.observed_bytes
    }

    /// Bounded prefix preview.
    pub const fn preview(&self) -> &ProcessStreamPrefixPreview {
        &self.preview
    }

    /// Immutable expansion source, when available.
    pub const fn source(&self) -> Option<&DurableProcessStreamSource> {
        self.source.as_ref()
    }

    /// Exact physical transport-prefix identity, when a shorter exact source is durable.
    pub const fn transport_prefix_identity(&self) -> Option<&ProcessStreamTransportPrefixIdentity> {
        self.transport_prefix_identity.as_ref()
    }

    /// Coverage gaps.
    pub fn gaps(&self) -> &[StreamEvidenceGap] {
        &self.gaps
    }

    /// Parsing status. Raw `ProcessExecutor` evidence is always `RAW`.
    pub const fn parsing(&self) -> StreamParsingStatus {
        self.parsing
    }

    /// Evaluation status. Raw `ProcessExecutor` evidence is always `UNASSESSED`.
    pub const fn evaluation(&self) -> StreamEvaluationStatus {
        self.evaluation
    }
}

impl<'de> Deserialize<'de> for ProcessStreamEvidence {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ProcessStreamEvidenceWire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            binding: wire.binding,
            stream: wire.stream,
            policy: wire.policy,
            transport: wire.transport,
            persistence: wire.persistence,
            observed_sha256: wire.observed_sha256,
            observed_bytes: wire.observed_bytes,
            preview: wire.preview,
            source: wire.source,
            transport_prefix_identity: wire.transport_prefix_identity,
            gaps: wire.gaps,
            parsing: wire.parsing,
            evaluation: wire.evaluation,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}
