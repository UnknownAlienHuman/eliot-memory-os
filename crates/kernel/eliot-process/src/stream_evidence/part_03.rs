/// Closed locator class for immutable expansion sources; synthetic `raw:` handles
/// are intentionally not representable.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DurableStreamLocatorKind {
    /// Provider-neutral BlobStore object/receipt.
    Blob,
    /// Another admitted immutable artifact/evidence store.
    ImmutableArtifact,
}

/// Relationship between durable bytes and physical transport bytes.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DurableStreamRepresentation {
    /// Stored bytes are exactly the transport bytes in the declared coverage interval.
    ExactTransportBytes,
    /// Stored bytes are the exact output of a declared policy transformation.
    PolicyTransformed,
}

/// Binding proving which physical input and policy produced transformed bytes.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProcessStreamTransformationBinding {
    receipt_ref: String,
    input_sha256: String,
    input_byte_length: u64,
    output_sha256: String,
    output_byte_length: u64,
    policy_ref: String,
    redaction_ref: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessStreamTransformationBindingWire {
    receipt_ref: String,
    input_sha256: String,
    input_byte_length: u64,
    output_sha256: String,
    output_byte_length: u64,
    policy_ref: String,
    redaction_ref: String,
}

impl ProcessStreamTransformationBinding {
    /// Creates one immutable transformation binding from transport to durable source.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receipt_ref: impl Into<String>,
        input_sha256: impl Into<String>,
        input_byte_length: u64,
        output_sha256: impl Into<String>,
        output_byte_length: u64,
        policy_ref: impl Into<String>,
        redaction_ref: impl Into<String>,
    ) -> Result<Self, ProcessStreamEvidenceError> {
        let value = Self {
            receipt_ref: receipt_ref.into(),
            input_sha256: input_sha256.into(),
            input_byte_length,
            output_sha256: output_sha256.into(),
            output_byte_length,
            policy_ref: policy_ref.into(),
            redaction_ref: redaction_ref.into(),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ProcessStreamEvidenceError> {
        validate_reference("transformation.receipt_ref", &self.receipt_ref)?;
        validate_digest("transformation.input_sha256", &self.input_sha256)?;
        validate_digest("transformation.output_sha256", &self.output_sha256)?;
        validate_reference("transformation.policy_ref", &self.policy_ref)?;
        validate_reference("transformation.redaction_ref", &self.redaction_ref)
    }

    /// Receipt for the exact input-to-output transformation.
    pub fn receipt_ref(&self) -> &str {
        &self.receipt_ref
    }

    /// SHA-256 over the physical transport input.
    pub fn input_sha256(&self) -> &str {
        &self.input_sha256
    }

    /// Physical transport input length.
    pub const fn input_byte_length(&self) -> u64 {
        self.input_byte_length
    }

    /// SHA-256 over the transformed durable output.
    pub fn output_sha256(&self) -> &str {
        &self.output_sha256
    }

    /// Transformed durable output length.
    pub const fn output_byte_length(&self) -> u64 {
        self.output_byte_length
    }

    /// Governing policy identity used by the transformation.
    pub fn policy_ref(&self) -> &str {
        &self.policy_ref
    }

    /// Exact redaction/transformation profile identity.
    pub fn redaction_ref(&self) -> &str {
        &self.redaction_ref
    }
}

impl<'de> Deserialize<'de> for ProcessStreamTransformationBinding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ProcessStreamTransformationBindingWire::deserialize(deserializer)?;
        Self::new(
            wire.receipt_ref,
            wire.input_sha256,
            wire.input_byte_length,
            wire.output_sha256,
            wire.output_byte_length,
            wire.policy_ref,
            wire.redaction_ref,
        )
        .map_err(de::Error::custom)
    }
}

/// Durable exact bytes plus the receipt needed to resolve and verify them.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct DurableProcessStreamSource {
    kind: DurableStreamLocatorKind,
    representation: DurableStreamRepresentation,
    locator: String,
    ready_receipt_ref: String,
    sha256: String,
    byte_length: u64,
    transformation: Option<ProcessStreamTransformationBinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableProcessStreamSourceWire {
    kind: DurableStreamLocatorKind,
    representation: DurableStreamRepresentation,
    locator: String,
    ready_receipt_ref: String,
    sha256: String,
    byte_length: u64,
    transformation: Option<ProcessStreamTransformationBinding>,
}

impl DurableProcessStreamSource {
    /// Creates an immutable source containing exact transport bytes.
    pub fn exact_transport(
        kind: DurableStreamLocatorKind,
        locator: impl Into<String>,
        ready_receipt_ref: impl Into<String>,
        sha256: impl Into<String>,
        byte_length: u64,
    ) -> Result<Self, ProcessStreamEvidenceError> {
        Self::new(
            kind,
            DurableStreamRepresentation::ExactTransportBytes,
            locator,
            ready_receipt_ref,
            sha256,
            byte_length,
            None,
        )
    }

    /// Creates an immutable source containing policy-transformed bytes.
    pub fn policy_transformed(
        kind: DurableStreamLocatorKind,
        locator: impl Into<String>,
        ready_receipt_ref: impl Into<String>,
        sha256: impl Into<String>,
        byte_length: u64,
        transformation: ProcessStreamTransformationBinding,
    ) -> Result<Self, ProcessStreamEvidenceError> {
        Self::new(
            kind,
            DurableStreamRepresentation::PolicyTransformed,
            locator,
            ready_receipt_ref,
            sha256,
            byte_length,
            Some(transformation),
        )
    }

    fn new(
        kind: DurableStreamLocatorKind,
        representation: DurableStreamRepresentation,
        locator: impl Into<String>,
        ready_receipt_ref: impl Into<String>,
        sha256: impl Into<String>,
        byte_length: u64,
        transformation: Option<ProcessStreamTransformationBinding>,
    ) -> Result<Self, ProcessStreamEvidenceError> {
        let value = Self {
            kind,
            representation,
            locator: locator.into(),
            ready_receipt_ref: ready_receipt_ref.into(),
            sha256: sha256.into(),
            byte_length,
            transformation,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ProcessStreamEvidenceError> {
        validate_locator(&self.locator)?;
        validate_reference("source.ready_receipt_ref", &self.ready_receipt_ref)?;
        validate_digest("source.sha256", &self.sha256)?;
        match (self.representation, self.transformation.as_ref()) {
            (DurableStreamRepresentation::ExactTransportBytes, None) => Ok(()),
            (DurableStreamRepresentation::PolicyTransformed, Some(binding)) => {
                binding.validate()?;
                if binding.output_sha256 != self.sha256
                    || binding.output_byte_length != self.byte_length
                {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "source.transformation",
                        reason: "transformation output identity must match durable source",
                    });
                }
                Ok(())
            }
            (DurableStreamRepresentation::ExactTransportBytes, Some(_)) => {
                Err(ProcessStreamEvidenceError::Invariant {
                    field: "source.transformation",
                    reason: "exact transport source cannot carry a transformation binding",
                })
            }
            (DurableStreamRepresentation::PolicyTransformed, None) => {
                Err(ProcessStreamEvidenceError::Invariant {
                    field: "source.transformation",
                    reason: "policy-transformed source requires an input/output receipt binding",
                })
            }
        }
    }

    /// Locator class.
    pub const fn kind(&self) -> DurableStreamLocatorKind {
        self.kind
    }

    /// Relationship between stored bytes and transport bytes.
    pub const fn representation(&self) -> DurableStreamRepresentation {
        self.representation
    }

    /// Immutable locator.
    pub fn locator(&self) -> &str {
        &self.locator
    }

    /// Receipt proving the locator is durably ready.
    pub fn ready_receipt_ref(&self) -> &str {
        &self.ready_receipt_ref
    }

    /// SHA-256 over the exact durable source bytes.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Exact durable source length.
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// Transformation binding for a policy-transformed source.
    pub const fn transformation(&self) -> Option<&ProcessStreamTransformationBinding> {
        self.transformation.as_ref()
    }
}

impl<'de> Deserialize<'de> for DurableProcessStreamSource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = DurableProcessStreamSourceWire::deserialize(deserializer)?;
        Self::new(
            wire.kind,
            wire.representation,
            wire.locator,
            wire.ready_receipt_ref,
            wire.sha256,
            wire.byte_length,
            wire.transformation,
        )
        .map_err(de::Error::custom)
    }
}
