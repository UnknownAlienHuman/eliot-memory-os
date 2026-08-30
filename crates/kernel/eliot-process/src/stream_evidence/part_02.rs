/// Policy identities fixed before stream bytes are offered to persistence.
#[allow(
    clippy::struct_field_names,
    reason = "the *_ref suffix is part of the stable public policy-binding schema"
)]
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamPolicyBinding {
    policy_ref: String,
    privacy_ref: String,
    visibility_ref: String,
    retention_ref: String,
    redaction_ref: String,
}

#[allow(
    clippy::struct_field_names,
    reason = "the *_ref suffix must match the stable public policy-binding wire schema"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessStreamPolicyBindingWire {
    policy_ref: String,
    privacy_ref: String,
    visibility_ref: String,
    retention_ref: String,
    redaction_ref: String,
}

impl ProcessStreamPolicyBinding {
    /// Creates the exact policy/retention/disclosure binding applied before persistence.
    pub fn new(
        policy_ref: impl Into<String>,
        privacy_ref: impl Into<String>,
        visibility_ref: impl Into<String>,
        retention_ref: impl Into<String>,
        redaction_ref: impl Into<String>,
    ) -> Result<Self, ProcessStreamEvidenceError> {
        let value = Self {
            policy_ref: policy_ref.into(),
            privacy_ref: privacy_ref.into(),
            visibility_ref: visibility_ref.into(),
            retention_ref: retention_ref.into(),
            redaction_ref: redaction_ref.into(),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ProcessStreamEvidenceError> {
        for (field, value) in [
            ("policy_ref", self.policy_ref.as_str()),
            ("privacy_ref", self.privacy_ref.as_str()),
            ("visibility_ref", self.visibility_ref.as_str()),
            ("retention_ref", self.retention_ref.as_str()),
            ("redaction_ref", self.redaction_ref.as_str()),
        ] {
            validate_reference(field, value)?;
        }
        Ok(())
    }

    /// Governing policy snapshot/decision reference.
    pub fn policy_ref(&self) -> &str {
        &self.policy_ref
    }

    /// Privacy classification/reference.
    pub fn privacy_ref(&self) -> &str {
        &self.privacy_ref
    }

    /// Visibility/disclosure reference.
    pub fn visibility_ref(&self) -> &str {
        &self.visibility_ref
    }

    /// Retention/erasure reference.
    pub fn retention_ref(&self) -> &str {
        &self.retention_ref
    }

    /// Exact redaction/transformation profile reference.
    pub fn redaction_ref(&self) -> &str {
        &self.redaction_ref
    }
}

impl<'de> Deserialize<'de> for ProcessStreamPolicyBinding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ProcessStreamPolicyBindingWire::deserialize(deserializer)?;
        Self::new(
            wire.policy_ref,
            wire.privacy_ref,
            wire.visibility_ref,
            wire.retention_ref,
            wire.redaction_ref,
        )
        .map_err(de::Error::custom)
    }
}

/// Bounded inline preview with an explicit byte coordinate system.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamPrefixPreview {
    representation: StreamPreviewRepresentation,
    bytes: Vec<u8>,
    sha256: String,
    retained_bytes: u64,
    represented_bytes: u64,
    omitted_ranges: Vec<StreamByteRange>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessStreamPrefixPreviewWire {
    representation: StreamPreviewRepresentation,
    bytes: Vec<u8>,
    sha256: String,
    retained_bytes: u64,
    represented_bytes: u64,
    omitted_ranges: Vec<StreamByteRange>,
}

impl ProcessStreamPrefixPreview {
    /// Builds a prefix preview over exact physical transport bytes.
    pub fn from_transport_prefix(
        bytes: Vec<u8>,
        observed_bytes: u64,
    ) -> Result<Self, ProcessStreamEvidenceError> {
        Self::from_prefix(
            StreamPreviewRepresentation::TransportBytes,
            bytes,
            observed_bytes,
        )
    }

    /// Builds a prefix preview over the durable policy-transformed source bytes.
    pub fn from_source_prefix(
        bytes: Vec<u8>,
        source_bytes: u64,
    ) -> Result<Self, ProcessStreamEvidenceError> {
        Self::from_prefix(
            StreamPreviewRepresentation::DurableSourceBytes,
            bytes,
            source_bytes,
        )
    }

    /// Creates an explicit no-inline-bytes projection for policy-prohibited evidence.
    #[must_use]
    pub fn withheld_by_policy() -> Self {
        Self {
            representation: StreamPreviewRepresentation::WithheldByPolicy,
            bytes: Vec::new(),
            sha256: sha256_hex(&[]),
            retained_bytes: 0,
            represented_bytes: 0,
            omitted_ranges: Vec::new(),
        }
    }

    fn from_prefix(
        representation: StreamPreviewRepresentation,
        bytes: Vec<u8>,
        represented_bytes: u64,
    ) -> Result<Self, ProcessStreamEvidenceError> {
        if representation == StreamPreviewRepresentation::WithheldByPolicy {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "preview.representation",
                reason: "use withheld_by_policy for a policy-withheld preview",
            });
        }
        if bytes.len() > MAX_PREVIEW_BYTES {
            return Err(ProcessStreamEvidenceError::LimitExceeded {
                field: "preview.bytes",
                limit: MAX_PREVIEW_BYTES,
            });
        }
        let retained_bytes = usize_to_u64("preview.retained_bytes", bytes.len())?;
        if retained_bytes > represented_bytes {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "preview.represented_bytes",
                reason: "represented bytes cannot be smaller than retained bytes",
            });
        }
        let omitted_ranges = omitted_suffix(retained_bytes, represented_bytes)?;
        Ok(Self {
            representation,
            sha256: sha256_hex(&bytes),
            bytes,
            retained_bytes,
            represented_bytes,
            omitted_ranges,
        })
    }

    fn validate(&self) -> Result<(), ProcessStreamEvidenceError> {
        if self.bytes.len() > MAX_PREVIEW_BYTES {
            return Err(ProcessStreamEvidenceError::LimitExceeded {
                field: "preview.bytes",
                limit: MAX_PREVIEW_BYTES,
            });
        }
        let retained_bytes = usize_to_u64("preview.retained_bytes", self.bytes.len())?;
        if self.retained_bytes != retained_bytes {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "preview.retained_bytes",
                reason: "retained byte count does not match inline bytes",
            });
        }
        validate_digest("preview.sha256", &self.sha256)?;
        if self.sha256 != sha256_hex(&self.bytes) {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "preview.sha256",
                reason: "digest does not match retained preview bytes",
            });
        }

        if self.representation == StreamPreviewRepresentation::WithheldByPolicy {
            if !self.bytes.is_empty()
                || self.retained_bytes != 0
                || self.represented_bytes != 0
                || !self.omitted_ranges.is_empty()
            {
                return Err(ProcessStreamEvidenceError::Invariant {
                    field: "preview",
                    reason: "policy-withheld preview cannot retain byte material",
                });
            }
            return Ok(());
        }

        if self.retained_bytes > self.represented_bytes {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "preview.byte_counts",
                reason: "retained bytes cannot exceed represented bytes",
            });
        }
        if self.omitted_ranges != omitted_suffix(self.retained_bytes, self.represented_bytes)? {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "preview.omitted_ranges",
                reason: "prefix preview must expose the exact omitted suffix",
            });
        }
        Ok(())
    }

    /// Coordinate system represented by the preview.
    pub const fn representation(&self) -> StreamPreviewRepresentation {
        self.representation
    }

    /// Retained preview bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// SHA-256 over retained preview bytes only.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Number of retained bytes.
    pub const fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }

    /// Total bytes in the selected preview representation.
    pub const fn represented_bytes(&self) -> u64 {
        self.represented_bytes
    }

    /// Exact ranges omitted from the prefix preview.
    pub fn omitted_ranges(&self) -> &[StreamByteRange] {
        &self.omitted_ranges
    }

    /// Whether the preview omits bytes from its selected representation.
    pub const fn is_truncated(&self) -> bool {
        self.retained_bytes < self.represented_bytes
    }
}

impl<'de> Deserialize<'de> for ProcessStreamPrefixPreview {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ProcessStreamPrefixPreviewWire::deserialize(deserializer)?;
        let value = Self {
            representation: wire.representation,
            bytes: wire.bytes,
            sha256: wire.sha256,
            retained_bytes: wire.retained_bytes,
            represented_bytes: wire.represented_bytes,
            omitted_ranges: wire.omitted_ranges,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}
