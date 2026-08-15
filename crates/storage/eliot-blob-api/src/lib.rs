//! C0 contract for the single-owner S-04 blob lifecycle.
//!
//! This crate is the provider-neutral contract surface. It contains validated
//! wire identities, request records, observations, the durable publish/GC state
//! machines, and the one canonical object-safe [`BlobStoreClient`] port. It
//! contains no filesystem, compression, cryptographic, or key implementation.
//!
//! # Authority boundary
//!
//! The contract deliberately offers no path that turns caller-supplied data
//! into a governed result. Receipt-bearing responses ([`BlobReadyReceipt`],
//! [`BlobReadChunk`], [`BlobGcReceipt`]) have private fields, are not
//! deserializable from untrusted bytes, and are issued only by the S-04 service
//! owner after an exact physical state transition. Request records and
//! observations deserialize only into unverified values that the service
//! re-validates under its own authority.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use eliot_platform::{PlatformHandle, WorkScopePath};
use eliot_receipts::{
    ArtifactBinding, AuthorityBinding, CausalBinding, EffectClass, OperationBinding, ProofCeiling,
    Receipt, ReceiptCore, ReceiptDisposition, ReceiptKind, RequestBinding, SessionBinding,
    TaskBinding, WorkScopeBinding, contract_identity,
};
use eliot_security_contracts::{EffectCeiling, InstructionTaint, PrivacyClass};
use serde::{Deserialize, Deserializer, Serialize, de};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Stable contract identity.
pub const CONTRACT_NAME: &str = "eliot.storage.blob";
/// Current wire revision.
pub const CONTRACT_VERSION: &str = "s-04-v1";

fn valid_text(value: &str, field: &'static str) -> Result<(), BlobError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(BlobError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        })
    } else {
        Ok(())
    }
}

/// Validated provider-neutral identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct BlobId(String);

impl BlobId {
    /// Constructs a non-path identity.
    pub fn new(value: impl Into<String>) -> Result<Self, BlobError> {
        let value = value.into();
        valid_text(&value, "blob_id")?;
        if value.contains(['/', '\\']) || value == "." || value == ".." {
            return Err(BlobError::InvalidField {
                field: "blob_id",
                reason: "path syntax is forbidden",
            });
        }
        Ok(Self(value))
    }

    /// Returns the identity text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for BlobId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Lowercase BLAKE3 identity of the exact plaintext bytes.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct BlobHash(String);

impl BlobHash {
    /// Parses a canonical digest.
    pub fn new(value: impl Into<String>) -> Result<Self, BlobError> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(BlobError::InvalidField {
                field: "blob_hash",
                reason: "must be lowercase BLAKE3 hex",
            });
        }
        Ok(Self(value))
    }

    /// Returns the digest text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BlobHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for BlobHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// CAS locator. It is an identity, never an ambient filesystem path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BlobLocator {
    /// Exact content identity.
    pub hash: BlobHash,
    /// Root generation that produced the path.
    pub root_generation: u64,
    /// Immutable path-shape generation.
    pub path_generation: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobLocatorWire {
    hash: BlobHash,
    root_generation: u64,
    path_generation: u32,
}

impl BlobLocator {
    /// Validates non-zero generation identities.
    pub fn validate(&self) -> Result<(), BlobError> {
        if self.root_generation == 0 || self.path_generation == 0 {
            return Err(BlobError::InvalidField {
                field: "locator_generation",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for BlobLocator {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BlobLocatorWire::deserialize(deserializer)?;
        let value = Self {
            hash: wire.hash,
            root_generation: wire.root_generation,
            path_generation: wire.path_generation,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Retention classification interpreted by the policy owner, not `BlobStore`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetentionClass {
    Session,
    Task,
    Durable,
    LegalHold,
}

/// C0-12 policy labels preserved in metadata and receipts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobPolicyBinding {
    pub privacy_class: PrivacyClass,
    pub retention_class: RetentionClass,
    pub policy_ref: PlatformHandle,
    pub instruction_taint: InstructionTaint,
    pub effect_ceiling: EffectCeiling,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobPolicyBindingWire {
    privacy_class: PrivacyClass,
    retention_class: RetentionClass,
    policy_ref: PlatformHandle,
    instruction_taint: InstructionTaint,
    effect_ceiling: EffectCeiling,
}

impl BlobPolicyBinding {
    /// Revalidates the P-01 opaque reference because provider DTOs may cross
    /// independently versioned serde boundaries.
    pub fn validate(&self) -> Result<(), BlobError> {
        valid_text(self.policy_ref.as_str(), "policy_ref")
    }
}

impl<'de> Deserialize<'de> for BlobPolicyBinding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BlobPolicyBindingWire::deserialize(deserializer)?;
        let value = Self {
            privacy_class: wire.privacy_class,
            retention_class: wire.retention_class,
            policy_ref: wire.policy_ref,
            instruction_taint: wire.instruction_taint,
            effect_ceiling: wire.effect_ceiling,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Canonical C0-02 context from which the S-04 service issues receipts.
///
/// The fields are request data supplied by the caller. They are unverified until
/// the service validates them and issues a receipt through its own authority;
/// there is intentionally no public method that turns this context into a
/// receipt. Receipt issuance is private to the S-04 service owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobReceiptContext {
    pub work_scope: WorkScopeBinding,
    pub task: Option<TaskBinding>,
    pub session: Option<SessionBinding>,
    pub causal: CausalBinding,
    pub request: RequestBinding,
    pub operation: OperationBinding,
    pub authority: AuthorityBinding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobReceiptContextWire {
    work_scope: WorkScopeBinding,
    task: Option<TaskBinding>,
    session: Option<SessionBinding>,
    causal: CausalBinding,
    request: RequestBinding,
    operation: OperationBinding,
    authority: AuthorityBinding,
}

impl BlobReceiptContext {
    /// Builds the receipt core for validation or service issuance. This helper is
    /// private to the contract so a caller cannot mint a receipt through the
    /// blob surface; the service issues receipts through its own authority.
    fn receipt_core(
        &self,
        artifacts: Vec<ArtifactBinding>,
        kind: ReceiptKind,
        disposition: ReceiptDisposition,
    ) -> Result<ReceiptCore, BlobError> {
        Ok(ReceiptCore {
            contract: contract_identity().map_err(|error| BlobError::Receipt(error.to_string()))?,
            kind,
            work_scope: self.work_scope.clone(),
            task: self.task.clone(),
            session: self.session.clone(),
            causal: self.causal.clone(),
            request: self.request.clone(),
            operation: self.operation.clone(),
            authority: self.authority.clone(),
            artifacts,
            verifier: None,
            problem: None,
            coordination: None,
            disposition,
        })
    }

    /// Validates that all receipt/fence/request identities are internally
    /// consistent, without minting any governed result.
    fn validate_bindings(&self) -> Result<(), BlobError> {
        Receipt::issue(self.receipt_core(
            Vec::new(),
            ReceiptKind::Request,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
        )?)
        .map(|_| ())
        .map_err(|error| BlobError::Receipt(error.to_string()))
    }

    /// Validates all receipt/fence/request identities and the required effect.
    pub fn validate_for(&self, expected: EffectClass) -> Result<(), BlobError> {
        if self.operation.effect != expected || self.authority.allowed_effect != expected {
            return Err(BlobError::AuthorityRequired(
                "operation and authority effect must match the blob operation",
            ));
        }
        self.validate_bindings()
    }
}

impl<'de> Deserialize<'de> for BlobReceiptContext {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BlobReceiptContextWire::deserialize(deserializer)?;
        let value = Self {
            work_scope: wire.work_scope,
            task: wire.task,
            session: wire.session,
            causal: wire.causal,
            request: wire.request,
            operation: wire.operation,
            authority: wire.authority,
        };
        // Effect matching is operation-specific and checked by the request type;
        // this still rejects malformed cross-projection fence/request identities.
        value.validate_bindings().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Exact request/object binding that an independent issuer verifier must
/// authenticate before S-04 can expose a capability-bearing result.
///
/// This is deliberately separate from [`Receipt`]. `ReceiptEnvelope::issue`
/// only derives deterministic identity bytes; it is not an authentication
/// mechanism. [`verify_receipt`] receives the immutable signed envelope bytes
/// together with this binding and an independently pinned issuer trust anchor;
/// only its exact signature, identity and binding checks can produce a
/// `VerifiedBlobReceipt`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobReceiptBinding {
    operation_id: String,
    request_id: String,
    idempotency_key: String,
    root_generation: u64,
    path_generation: Option<u32>,
    blob_hash: Option<BlobHash>,
    proof_id: Option<BlobId>,
}

impl BlobReceiptBinding {
    /// Creates the exact binding for a blob operation.
    pub fn for_blob(
        context: &BlobReceiptContext,
        locator: &BlobLocator,
    ) -> Result<Self, BlobError> {
        context.validate_bindings()?;
        locator.validate()?;
        Ok(Self {
            operation_id: context.operation.operation_id.to_string(),
            request_id: context.request.metadata.request_id.to_string(),
            idempotency_key: context.operation.idempotency_key.clone(),
            root_generation: locator.root_generation,
            path_generation: Some(locator.path_generation),
            blob_hash: Some(locator.hash.clone()),
            proof_id: None,
        })
    }

    /// Creates an operation binding without a single blob locator, such as a
    /// reachability or GC operation. The proof identity remains explicit.
    pub fn for_operation(
        context: &BlobReceiptContext,
        root_generation: u64,
        path_generation: Option<u32>,
        proof_id: Option<&BlobId>,
    ) -> Result<Self, BlobError> {
        context.validate_bindings()?;
        if root_generation == 0 || path_generation == Some(0) {
            return Err(BlobError::StaleFence);
        }
        Ok(Self {
            operation_id: context.operation.operation_id.to_string(),
            request_id: context.request.metadata.request_id.to_string(),
            idempotency_key: context.operation.idempotency_key.clone(),
            root_generation,
            path_generation,
            blob_hash: None,
            proof_id: proof_id.cloned(),
        })
    }

    /// Returns the expected blob identity, when this binding is blob-specific.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the expected request identity.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Returns the expected idempotency identity.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Returns the expected blob identity, when this binding is blob-specific.
    #[must_use]
    pub fn blob_hash(&self) -> Option<&BlobHash> {
        self.blob_hash.as_ref()
    }

    /// Returns the expected root generation.
    #[must_use]
    pub const fn root_generation(&self) -> u64 {
        self.root_generation
    }

    /// Returns the expected path generation, when one exists.
    #[must_use]
    pub const fn path_generation(&self) -> Option<u32> {
        self.path_generation
    }

    /// Returns the expected proof identity, when one exists.
    #[must_use]
    pub fn proof_id(&self) -> Option<&BlobId> {
        self.proof_id.as_ref()
    }

    fn validate_receipt(&self, receipt: &Receipt) -> Result<(), BlobError> {
        receipt
            .validate()
            .map_err(|error| BlobError::Receipt(error.to_string()))?;
        let operation = &receipt.core.operation;
        if operation.operation_id.as_str() != self.operation_id
            || operation.request_id.as_str() != self.request_id
            || operation.idempotency_key != self.idempotency_key
            || receipt.core.request.metadata.request_id.as_str() != self.request_id
            || receipt.core.work_scope.resource_generation.value() != self.root_generation
            || operation.state_fence.resource_generation.value() != self.root_generation
            || receipt
                .core
                .authority
                .state_fence
                .resource_generation
                .value()
                != self.root_generation
        {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        if let Some(hash) = &self.blob_hash {
            let expected_prefixes = [
                format!("blob-content-{hash}"),
                format!("blob-envelope-{hash}"),
                format!("blob-read-{hash}"),
            ];
            if !receipt.core.artifacts.iter().any(|artifact| {
                expected_prefixes
                    .iter()
                    .any(|expected| artifact.artifact_id.to_string() == *expected)
            }) {
                return Err(BlobError::MetadataPayloadMismatch);
            }
            if let Some(path_generation) = self.path_generation {
                let marker = format!("path-generation:{path_generation}");
                if !receipt.core.artifacts.iter().any(|artifact| {
                    artifact
                        .source_revision
                        .as_deref()
                        .is_some_and(|source| source.contains(&marker))
                }) {
                    return Err(BlobError::MetadataPayloadMismatch);
                }
            }
        }
        Ok(())
    }
}

/// Immutable issuer trust anchor pinned by the composition owner.
///
/// The key is retained privately and is never serialized or exposed. The
/// derived fingerprint binds the issuer, key, algorithm and receipt schema;
/// downstream authority operations must compare this fingerprint with their
/// independently pinned expected anchor before consuming a capability.
#[derive(Clone, Eq, PartialEq)]
pub struct BlobIssuerTrustAnchor {
    issuer_id: String,
    key_id: String,
    algorithm: &'static str,
    schema: &'static str,
    key: Vec<u8>,
    fingerprint: String,
}

impl fmt::Debug for BlobIssuerTrustAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlobIssuerTrustAnchor")
            .field("issuer_id", &self.issuer_id)
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .field("schema", &self.schema)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl BlobIssuerTrustAnchor {
    const ALGORITHM: &'static str = "HMAC-SHA256";
    const SCHEMA: &'static str = "eliot.storage.blob.receipt/v1";

    /// Creates an anchor from composition-owned issuer metadata and key
    /// material. The resulting anchor is not globally authoritative by itself;
    /// consumers must pin and compare its fingerprint.
    pub fn new(
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
        key: impl Into<Vec<u8>>,
    ) -> Result<Self, BlobError> {
        let issuer_id = issuer_id.into();
        let key_id = key_id.into();
        let key = key.into();
        valid_text(&issuer_id, "issuer_id")?;
        valid_text(&key_id, "key_id")?;
        if key.len() < 32 {
            return Err(BlobError::InvalidField {
                field: "issuer_key",
                reason: "must contain at least 32 bytes",
            });
        }
        let fingerprint =
            anchor_fingerprint(&issuer_id, &key_id, Self::ALGORITHM, Self::SCHEMA, &key);
        Ok(Self {
            issuer_id,
            key_id,
            algorithm: Self::ALGORITHM,
            schema: Self::SCHEMA,
            key,
            fingerprint,
        })
    }

    /// Stable fingerprint that downstream owners must pin exactly.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Exact issuer identity included in the signed envelope.
    #[must_use]
    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    /// Exact key identity included in the signed envelope.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Signs an already-issued candidate envelope. The resulting bytes remain
    /// untrusted until verified against the expected pinned anchor.
    pub fn sign_receipt(&self, receipt: &Receipt) -> Result<Vec<u8>, BlobError> {
        receipt
            .validate()
            .map_err(|error| BlobError::Receipt(error.to_string()))?;
        let payload = signed_receipt_payload(
            self.schema,
            &self.issuer_id,
            &self.key_id,
            self.algorithm,
            receipt,
        )?;
        let signature = hex_encode(&hmac_sha256(&self.key, &payload));
        let wire = SignedBlobReceiptWire {
            schema: self.schema.to_owned(),
            issuer_id: self.issuer_id.clone(),
            key_id: self.key_id.clone(),
            algorithm: self.algorithm.to_owned(),
            receipt: receipt.clone(),
            signature,
        };
        serde_json::to_vec(&wire).map_err(|error| BlobError::InvalidContract(error.to_string()))
    }
}

/// Explicitly untrusted signed receipt wire record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedBlobReceiptWire {
    pub schema: String,
    pub issuer_id: String,
    pub key_id: String,
    pub algorithm: String,
    pub receipt: Receipt,
    pub signature: String,
}

/// Non-deserializable receipt capability produced only after verifier approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBlobReceipt {
    receipt: Receipt,
    receipt_bytes: Vec<u8>,
    binding: BlobReceiptBinding,
    anchor_fingerprint: String,
}

impl VerifiedBlobReceipt {
    /// Returns the verified immutable envelope.
    #[must_use]
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }

    /// Returns the exact bytes approved by the independent verifier.
    #[must_use]
    pub fn receipt_bytes(&self) -> &[u8] {
        &self.receipt_bytes
    }

    /// Returns the exact request/blob/generation binding that was approved.
    #[must_use]
    pub fn binding(&self) -> &BlobReceiptBinding {
        &self.binding
    }

    /// Returns the exact trust-anchor fingerprint used for acceptance.
    #[must_use]
    pub fn anchor_fingerprint(&self) -> &str {
        &self.anchor_fingerprint
    }
}

/// Parses and accepts one immutable receipt envelope only after independent
/// verification and exact request/blob/generation binding.
pub fn verify_receipt(
    anchor: &BlobIssuerTrustAnchor,
    receipt_bytes: &[u8],
    binding: BlobReceiptBinding,
) -> Result<VerifiedBlobReceipt, BlobError> {
    let wire: SignedBlobReceiptWire = serde_json::from_slice(receipt_bytes)
        .map_err(|error| BlobError::Receipt(format!("receipt wire decode failed: {error}")))?;
    let canonical_wire = serde_json::to_vec(&wire)
        .map_err(|error| BlobError::Receipt(format!("receipt wire encode failed: {error}")))?;
    if canonical_wire != receipt_bytes {
        return Err(BlobError::Receipt(
            "receipt bytes are not the exact immutable envelope".to_owned(),
        ));
    }
    if wire.schema != anchor.schema
        || wire.issuer_id != anchor.issuer_id
        || wire.key_id != anchor.key_id
        || wire.algorithm != anchor.algorithm
    {
        return Err(BlobError::Receipt(
            "receipt issuer, key, algorithm, or schema identity mismatch".to_owned(),
        ));
    }
    let payload = signed_receipt_payload(
        &wire.schema,
        &wire.issuer_id,
        &wire.key_id,
        &wire.algorithm,
        &wire.receipt,
    )?;
    let expected_signature = hmac_sha256(&anchor.key, &payload);
    let supplied_signature = hex_decode(&wire.signature)?;
    if !constant_time_eq(&expected_signature, &supplied_signature) {
        return Err(BlobError::Receipt("issuer signature mismatch".to_owned()));
    }
    binding.validate_receipt(&wire.receipt)?;
    Ok(VerifiedBlobReceipt {
        receipt: wire.receipt,
        receipt_bytes: receipt_bytes.to_vec(),
        binding,
        anchor_fingerprint: anchor.fingerprint.clone(),
    })
}

fn signed_receipt_payload(
    schema: &str,
    issuer_id: &str,
    key_id: &str,
    algorithm: &str,
    receipt: &Receipt,
) -> Result<Vec<u8>, BlobError> {
    serde_json::to_vec(&(schema, issuer_id, key_id, algorithm, receipt))
        .map_err(|error| BlobError::InvalidContract(error.to_string()))
}

fn anchor_fingerprint(
    issuer_id: &str,
    key_id: &str,
    algorithm: &str,
    schema: &str,
    key: &[u8],
) -> String {
    let mut identity = Vec::new();
    for field in [
        schema.as_bytes(),
        issuer_id.as_bytes(),
        key_id.as_bytes(),
        algorithm.as_bytes(),
        key,
    ] {
        identity.extend_from_slice(&(field.len() as u64).to_be_bytes());
        identity.extend_from_slice(field);
    }
    hex_encode(&Sha256::digest(identity))
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = [0_u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0x36_u8; BLOCK];
    let mut outer = [0x5c_u8; BLOCK];
    for index in 0..BLOCK {
        inner[index] ^= normalized[index];
        outer[index] ^= normalized[index];
    }
    let mut inner_input = Vec::with_capacity(BLOCK + message.len());
    inner_input.extend_from_slice(&inner);
    inner_input.extend_from_slice(message);
    let inner_digest = Sha256::digest(inner_input);
    let mut outer_input = Vec::with_capacity(BLOCK + inner_digest.len());
    outer_input.extend_from_slice(&outer);
    outer_input.extend_from_slice(&inner_digest);
    Sha256::digest(outer_input).into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn hex_decode(value: &str) -> Result<Vec<u8>, BlobError> {
    if value.len() % 2 != 0 {
        return Err(BlobError::Receipt(
            "invalid issuer signature encoding".to_owned(),
        ));
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| BlobError::Receipt("invalid issuer signature encoding".to_owned()))
        })
        .collect()
}

/// Exclusive root lease supplied by the lifecycle owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobRootLease {
    pub root_id: PlatformHandle,
    pub owner_id: BlobId,
    pub lease_id: BlobId,
    pub root_generation: u64,
    pub fence_binding: RequestBinding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobRootLeaseWire {
    root_id: PlatformHandle,
    owner_id: BlobId,
    lease_id: BlobId,
    root_generation: u64,
    fence_binding: RequestBinding,
}

impl BlobRootLease {
    /// Validates root identity, generation, and fence alignment.
    pub fn validate(&self) -> Result<(), BlobError> {
        valid_text(self.root_id.as_str(), "root_id")?;
        self.fence_binding
            .metadata
            .validate()
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        self.fence_binding
            .state_fence
            .validate()
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        if self.fence_binding.metadata.state_fence != self.fence_binding.state_fence {
            return Err(BlobError::StaleFence);
        }
        if self.root_generation == 0
            || self.fence_binding.state_fence.resource_generation.value() != self.root_generation
        {
            return Err(BlobError::StaleFence);
        }
        Ok(())
    }

    /// Requires an operation context to be bound to this exact lease fence.
    pub fn validate_context(&self, context: &BlobReceiptContext) -> Result<(), BlobError> {
        self.validate()?;
        if context.request.state_fence != self.fence_binding.state_fence
            || context.operation.state_fence != self.fence_binding.state_fence
            || context.authority.state_fence != self.fence_binding.state_fence
        {
            return Err(BlobError::StaleFence);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for BlobRootLease {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BlobRootLeaseWire::deserialize(deserializer)?;
        let value = Self {
            root_id: wire.root_id,
            owner_id: wire.owner_id,
            lease_id: wire.lease_id,
            root_generation: wire.root_generation,
            fence_binding: wire.fence_binding,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Immutable compression format selected by the injected codec.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CompressionDescriptor {
    pub algorithm: BlobId,
    pub version: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompressionDescriptorWire {
    algorithm: BlobId,
    version: u32,
}

impl CompressionDescriptor {
    pub fn validate(&self) -> Result<(), BlobError> {
        if self.version == 0 {
            return Err(BlobError::InvalidField {
                field: "compression.version",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for CompressionDescriptor {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = CompressionDescriptorWire::deserialize(deserializer)?;
        let value = Self {
            algorithm: wire.algorithm,
            version: wire.version,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Versioned AEAD/key-lineage metadata. No key bytes are representable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CryptoDescriptor {
    pub algorithm: BlobId,
    pub version: u32,
    pub key_lineage: BlobId,
    pub key_generation: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CryptoDescriptorWire {
    algorithm: BlobId,
    version: u32,
    key_lineage: BlobId,
    key_generation: u64,
}

impl CryptoDescriptor {
    pub fn validate(&self) -> Result<(), BlobError> {
        if self.version == 0 || self.key_generation == 0 {
            return Err(BlobError::InvalidField {
                field: "crypto_generation",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for CryptoDescriptor {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = CryptoDescriptorWire::deserialize(deserializer)?;
        let value = Self {
            algorithm: wire.algorithm,
            version: wire.version,
            key_lineage: wire.key_lineage,
            key_generation: wire.key_generation,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Durable stage request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobStageRequest {
    pub context: BlobReceiptContext,
    pub root_lease: BlobRootLease,
    pub bytes: Vec<u8>,
    pub policy: BlobPolicyBinding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobStageRequestWire {
    context: BlobReceiptContext,
    root_lease: BlobRootLease,
    bytes: Vec<u8>,
    policy: BlobPolicyBinding,
}

impl BlobStageRequest {
    pub fn validate(&self) -> Result<(), BlobError> {
        self.context.validate_for(EffectClass::ReversibleMutation)?;
        self.root_lease.validate_context(&self.context)?;
        self.policy.validate()?;
        Ok(())
    }
}

impl<'de> Deserialize<'de> for BlobStageRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BlobStageRequestWire::deserialize(deserializer)?;
        let value = Self {
            context: wire.context,
            root_lease: wire.root_lease,
            bytes: wire.bytes,
            policy: wire.policy,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Bounded read request with exact durable metadata binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobReadRequest {
    pub context: BlobReceiptContext,
    pub root_lease: BlobRootLease,
    pub locator: BlobLocator,
    pub expected_metadata_sha256: String,
    pub expected_ready_receipt_id: String,
    pub max_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobReadRequestWire {
    context: BlobReceiptContext,
    root_lease: BlobRootLease,
    locator: BlobLocator,
    expected_metadata_sha256: String,
    expected_ready_receipt_id: String,
    max_bytes: u64,
}

impl BlobReadRequest {
    pub fn validate(&self) -> Result<(), BlobError> {
        self.context.validate_for(EffectClass::Read)?;
        self.root_lease.validate_context(&self.context)?;
        self.locator.validate()?;
        if self.locator.root_generation != self.root_lease.root_generation {
            return Err(BlobError::StaleFence);
        }
        canonical_sha256(&self.expected_metadata_sha256, "expected_metadata_sha256")?;
        valid_text(&self.expected_ready_receipt_id, "expected_ready_receipt_id")?;
        if self.max_bytes == 0 {
            return Err(BlobError::InvalidField {
                field: "max_bytes",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for BlobReadRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BlobReadRequestWire::deserialize(deserializer)?;
        let value = Self {
            context: wire.context,
            root_lease: wire.root_lease,
            locator: wire.locator,
            expected_metadata_sha256: wire.expected_metadata_sha256,
            expected_ready_receipt_id: wire.expected_ready_receipt_id,
            max_bytes: wire.max_bytes,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Non-semantic storage reference observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobReferenceRequest {
    pub context: BlobReceiptContext,
    pub root_lease: BlobRootLease,
    pub locator: BlobLocator,
    pub expected_metadata_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobReferenceRequestWire {
    context: BlobReceiptContext,
    root_lease: BlobRootLease,
    locator: BlobLocator,
    expected_metadata_sha256: String,
}

impl BlobReferenceRequest {
    pub fn validate(&self) -> Result<(), BlobError> {
        self.context.validate_for(EffectClass::Read)?;
        self.root_lease.validate_context(&self.context)?;
        self.locator.validate()?;
        canonical_sha256(&self.expected_metadata_sha256, "expected_metadata_sha256")
    }
}

impl<'de> Deserialize<'de> for BlobReferenceRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BlobReferenceRequestWire::deserialize(deserializer)?;
        let value = Self {
            context: wire.context,
            root_lease: wire.root_lease,
            locator: wire.locator,
            expected_metadata_sha256: wire.expected_metadata_sha256,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Completeness proof for a canonical-owner supplied live set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LiveSetCompleteness {
    Complete,
    Partial,
    Unknown,
}

/// Immutable live-set snapshot. `BlobStore` never discovers semantic roots.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobLiveSetProof {
    pub proof_id: BlobId,
    pub canonical_owner_ref: BlobId,
    pub completeness: LiveSetCompleteness,
    pub snapshot_sha256: String,
    pub revision: u64,
    pub fence_binding: RequestBinding,
    pub live: Vec<BlobLocator>,
    pub receipt_refs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobLiveSetProofWire {
    proof_id: BlobId,
    canonical_owner_ref: BlobId,
    completeness: LiveSetCompleteness,
    snapshot_sha256: String,
    revision: u64,
    fence_binding: RequestBinding,
    live: Vec<BlobLocator>,
    receipt_refs: Vec<String>,
}

impl BlobLiveSetProof {
    pub fn validate_complete(&self) -> Result<(), BlobError> {
        if self.completeness != LiveSetCompleteness::Complete {
            return Err(BlobError::IncompleteLiveSet);
        }
        canonical_sha256(&self.snapshot_sha256, "live_set.snapshot_sha256")?;
        self.fence_binding
            .metadata
            .validate()
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        self.fence_binding
            .state_fence
            .validate()
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        if self.fence_binding.metadata.state_fence != self.fence_binding.state_fence {
            return Err(BlobError::StaleFence);
        }
        if self.revision == 0 || self.receipt_refs.is_empty() {
            return Err(BlobError::IncompleteLiveSet);
        }
        let mut seen = BTreeSet::new();
        for locator in &self.live {
            locator.validate()?;
            if !seen.insert(locator) {
                return Err(BlobError::DuplicateIdentity("live_set.live"));
            }
        }
        for receipt in &self.receipt_refs {
            valid_text(receipt, "live_set.receipt_ref")?;
        }
        Ok(())
    }

    #[must_use]
    pub fn contains(&self, locator: &BlobLocator) -> bool {
        self.live.contains(locator)
    }
}

impl<'de> Deserialize<'de> for BlobLiveSetProof {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BlobLiveSetProofWire::deserialize(deserializer)?;
        let value = Self {
            proof_id: wire.proof_id,
            canonical_owner_ref: wire.canonical_owner_ref,
            completeness: wire.completeness,
            snapshot_sha256: wire.snapshot_sha256,
            revision: wire.revision,
            fence_binding: wire.fence_binding,
            live: wire.live,
            receipt_refs: wire.receipt_refs,
        };
        value.validate_complete().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Fenced reachability request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobReachabilityRequest {
    pub context: BlobReceiptContext,
    pub root_lease: BlobRootLease,
    pub live_set: BlobLiveSetProof,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobReachabilityRequestWire {
    context: BlobReceiptContext,
    root_lease: BlobRootLease,
    live_set: BlobLiveSetProof,
}

impl BlobReachabilityRequest {
    pub fn validate(&self) -> Result<(), BlobError> {
        self.context.validate_for(EffectClass::Read)?;
        self.root_lease.validate_context(&self.context)?;
        self.live_set.validate_complete()?;
        if self.live_set.fence_binding.state_fence != self.root_lease.fence_binding.state_fence {
            return Err(BlobError::StaleFence);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for BlobReachabilityRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BlobReachabilityRequestWire::deserialize(deserializer)?;
        let value = Self {
            context: wire.context,
            root_lease: wire.root_lease,
            live_set: wire.live_set,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Fenced GC request. Only candidates absent from the complete live set are eligible.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobGcRequest {
    pub context: BlobReceiptContext,
    pub root_lease: BlobRootLease,
    pub live_set: BlobLiveSetProof,
    pub candidates: Vec<BlobLocator>,
    pub grace_period_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobGcRequestWire {
    context: BlobReceiptContext,
    root_lease: BlobRootLease,
    live_set: BlobLiveSetProof,
    candidates: Vec<BlobLocator>,
    grace_period_seconds: u64,
}

impl BlobGcRequest {
    pub fn validate(&self) -> Result<(), BlobError> {
        self.context.validate_for(EffectClass::ReversibleMutation)?;
        self.root_lease.validate_context(&self.context)?;
        self.live_set.validate_complete()?;
        if self.live_set.fence_binding.state_fence != self.root_lease.fence_binding.state_fence {
            return Err(BlobError::StaleFence);
        }
        let mut seen = BTreeSet::new();
        for candidate in &self.candidates {
            candidate.validate()?;
            if candidate.root_generation != self.root_lease.root_generation {
                return Err(BlobError::StaleFence);
            }
            if !seen.insert(candidate) {
                return Err(BlobError::DuplicateIdentity("gc.candidates"));
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for BlobGcRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BlobGcRequestWire::deserialize(deserializer)?;
        let value = Self {
            context: wire.context,
            root_lease: wire.root_lease,
            live_set: wire.live_set,
            candidates: wire.candidates,
            grace_period_seconds: wire.grace_period_seconds,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Durable publication state. `READY` is issued only after payload, metadata and
/// the commit marker are durably present; recovery resumes the exact state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublishState {
    JournalPrepared,
    PayloadDurable,
    MetadataDurable,
    CommitDurable,
    Ready,
    Cleaned,
}

/// Durable garbage-collection state. Unknown deletions retain the tombstone and
/// never blind-retry; recovery revalidates the live set before any effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GcState {
    TombstoneDurable,
    LiveSetRevalidated,
    PayloadDeleteAttempt,
    MetadataDeleteAttempt,
    TombstoneCleaned,
}

/// Ready result after payload and metadata were durably reconciled.
///
/// Fields are private and there is no public constructor and no untrusted
/// deserialization: a caller can only obtain this value from the S-04 service
/// after an exact physical state transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobReadyReceipt {
    receipt: Receipt,
    locator: BlobLocator,
    plaintext_length: u64,
    /// Authenticated length of the on-disk envelope (ciphertext plus tag).
    stored_length: u64,
    /// Alias-level wire contract for consumers that call the stored bytes an envelope.
    envelope_length: u64,
    plaintext_sha256: String,
    sealed_sha256: String,
    /// Canonical digest bound into the receipt identity for all blob invariants.
    receipt_binding_sha256: String,
    metadata_sha256: String,
    format: BlobId,
    format_version: u32,
    compression: CompressionDescriptor,
    crypto: CryptoDescriptor,
    policy: BlobPolicyBinding,
    root_generation: u64,
    path_generation: u32,
    anchor_fingerprint: String,
}

impl BlobReadyReceipt {
    /// Constructs a capability from an independently verified receipt. The
    /// verified binding must identify this exact locator and generations.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified(
        verified: VerifiedBlobReceipt,
        expected_anchor: &BlobIssuerTrustAnchor,
        locator: BlobLocator,
        plaintext_length: u64,
        stored_length: u64,
        plaintext_sha256: String,
        sealed_sha256: String,
        receipt_binding_sha256: String,
        metadata_sha256: String,
        format: BlobId,
        format_version: u32,
        compression: CompressionDescriptor,
        crypto: CryptoDescriptor,
        policy: BlobPolicyBinding,
    ) -> Result<Self, BlobError> {
        if verified.anchor_fingerprint() != expected_anchor.fingerprint()
            || verified.binding().blob_hash() != Some(&locator.hash)
            || verified.binding().root_generation() != locator.root_generation
            || verified.binding().path_generation() != Some(locator.path_generation)
        {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        let value = Self {
            receipt: verified.receipt().clone(),
            locator: locator.clone(),
            plaintext_length,
            stored_length,
            envelope_length: stored_length,
            plaintext_sha256,
            sealed_sha256,
            receipt_binding_sha256,
            metadata_sha256,
            format,
            format_version,
            compression,
            crypto,
            policy,
            root_generation: locator.root_generation,
            path_generation: locator.path_generation,
            anchor_fingerprint: verified.anchor_fingerprint().to_owned(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), BlobError> {
        self.receipt
            .validate()
            .map_err(|error| BlobError::Receipt(error.to_string()))?;
        self.locator.validate()?;
        canonical_sha256(&self.plaintext_sha256, "plaintext_sha256")?;
        canonical_sha256(&self.sealed_sha256, "sealed_sha256")?;
        canonical_sha256(&self.receipt_binding_sha256, "receipt_binding_sha256")?;
        canonical_sha256(&self.metadata_sha256, "metadata_sha256")?;
        if self.stored_length == 0 || self.stored_length != self.envelope_length {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        if self.format_version == 0 {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        self.compression.validate()?;
        self.crypto.validate()?;
        self.policy.validate()?;
        canonical_sha256(&self.anchor_fingerprint, "anchor_fingerprint")?;
        if self.root_generation != self.locator.root_generation
            || self.path_generation != self.locator.path_generation
        {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        if self.receipt_binding_sha256 != self.expected_receipt_binding_sha256()? {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        let content_id = format!("blob-content-{}", self.locator.hash);
        let envelope_id = format!("blob-envelope-{}", self.locator.hash);
        if self.receipt.core.artifacts.len() != 2
            || self.receipt.core.artifacts[0].artifact_id.to_string() != content_id
            || self.receipt.core.artifacts[0].sha256 != self.plaintext_sha256
            || self.receipt.core.artifacts[1].artifact_id.to_string() != envelope_id
            || self.receipt.core.artifacts[1].sha256 != self.receipt_binding_sha256
        {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        Ok(())
    }

    /// Computes the versioned identity digest that the canonical receipt must bind.
    pub fn expected_receipt_binding_sha256(&self) -> Result<String, BlobError> {
        receipt_binding_sha256(
            &self.format,
            self.format_version,
            &self.locator,
            self.plaintext_length,
            self.stored_length,
            &self.plaintext_sha256,
            &self.sealed_sha256,
            &self.compression,
            &self.crypto,
            &self.policy,
        )
    }

    #[must_use]
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }

    #[must_use]
    pub fn locator(&self) -> &BlobLocator {
        &self.locator
    }

    #[must_use]
    pub const fn plaintext_length(&self) -> u64 {
        self.plaintext_length
    }

    #[must_use]
    pub const fn stored_length(&self) -> u64 {
        self.stored_length
    }

    #[must_use]
    pub const fn envelope_length(&self) -> u64 {
        self.envelope_length
    }

    #[must_use]
    pub fn plaintext_sha256(&self) -> &str {
        &self.plaintext_sha256
    }

    #[must_use]
    pub fn sealed_sha256(&self) -> &str {
        &self.sealed_sha256
    }

    #[must_use]
    pub fn receipt_binding_sha256(&self) -> &str {
        &self.receipt_binding_sha256
    }

    #[must_use]
    pub fn metadata_sha256(&self) -> &str {
        &self.metadata_sha256
    }

    #[must_use]
    pub fn format(&self) -> &BlobId {
        &self.format
    }

    #[must_use]
    pub const fn format_version(&self) -> u32 {
        self.format_version
    }

    #[must_use]
    pub const fn compression(&self) -> &CompressionDescriptor {
        &self.compression
    }

    #[must_use]
    pub const fn crypto(&self) -> &CryptoDescriptor {
        &self.crypto
    }

    #[must_use]
    pub const fn policy(&self) -> &BlobPolicyBinding {
        &self.policy
    }

    #[must_use]
    pub const fn root_generation(&self) -> u64 {
        self.root_generation
    }

    #[must_use]
    pub const fn path_generation(&self) -> u32 {
        self.path_generation
    }

    #[must_use]
    pub fn anchor_fingerprint(&self) -> &str {
        &self.anchor_fingerprint
    }
}

/// One bounded, asynchronously delivered read chunk. Fields are private; the
/// chunk is issued only by the service after authenticated payload recovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobReadChunk {
    receipt: Receipt,
    ready_receipt: BlobReadyReceipt,
    offset: u64,
    complete: bool,
    bytes: Vec<u8>,
    anchor_fingerprint: String,
}

impl BlobReadChunk {
    /// Constructs a read capability from an independently verified receipt and
    /// an already verified ready capability.
    pub fn from_verified(
        verified: VerifiedBlobReceipt,
        expected_anchor: &BlobIssuerTrustAnchor,
        ready_receipt: BlobReadyReceipt,
        bytes: Vec<u8>,
    ) -> Result<Self, BlobError> {
        if verified.anchor_fingerprint() != expected_anchor.fingerprint()
            || verified.binding().blob_hash() != Some(&ready_receipt.locator.hash)
            || verified.binding().root_generation() != ready_receipt.root_generation
            || verified.binding().path_generation() != Some(ready_receipt.path_generation)
        {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        let value = Self {
            receipt: verified.receipt().clone(),
            ready_receipt,
            offset: 0,
            complete: true,
            bytes,
            anchor_fingerprint: verified.anchor_fingerprint().to_owned(),
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }

    #[must_use]
    pub fn ready_receipt(&self) -> &BlobReadyReceipt {
        &self.ready_receipt
    }

    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn anchor_fingerprint(&self) -> &str {
        &self.anchor_fingerprint
    }

    pub fn validate(&self) -> Result<(), BlobError> {
        self.receipt
            .validate()
            .map_err(|error| BlobError::Receipt(error.to_string()))?;
        self.ready_receipt.validate()?;
        canonical_sha256(&self.anchor_fingerprint, "anchor_fingerprint")?;
        if self.offset != 0
            || !self.complete
            || self.bytes.len() as u64 != self.ready_receipt.plaintext_length
            || hex_sha256(&self.bytes) != self.ready_receipt.plaintext_sha256
            || blake3::hash(&self.bytes).to_hex().as_str()
                != self.ready_receipt.locator.hash.as_str()
        {
            return Err(BlobError::IntegrityMismatch);
        }
        let expected_artifact_id = format!("blob-read-{}", self.ready_receipt.locator.hash);
        if self.receipt.core.artifacts.len() != 1
            || self.receipt.core.artifacts[0].artifact_id.to_string() != expected_artifact_id
            || self.receipt.core.artifacts[0].sha256 != self.ready_receipt.plaintext_sha256
            || !self.receipt.core.artifacts[0]
                .source_revision
                .as_deref()
                .is_some_and(|source| {
                    source.starts_with(self.ready_receipt.metadata_sha256.as_str())
                })
        {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        Ok(())
    }
}

/// Storage-level presence observation; never a canonical semantic reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlobReferenceObservation {
    pub receipt: Receipt,
    pub locator: BlobLocator,
    pub metadata_sha256: String,
    pub present_and_integral: bool,
}

/// Untrusted wire representation of a reference observation. Deserializing it
/// never creates a capability or authorizes a read/GC operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobReferenceObservationWire {
    pub receipt: Receipt,
    pub locator: BlobLocator,
    pub metadata_sha256: String,
    pub present_and_integral: bool,
}

/// Reachability view derived only from a complete supplied proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlobReachabilityView {
    pub receipt: Receipt,
    pub proof_id: BlobId,
    pub present: Vec<BlobLocator>,
    pub missing: Vec<BlobLocator>,
}

/// Untrusted wire representation of a reachability view. It is evidence only;
/// the canonical owner must revalidate before destructive use.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobReachabilityViewWire {
    pub receipt: Receipt,
    pub proof_id: BlobId,
    pub present: Vec<BlobLocator>,
    pub missing: Vec<BlobLocator>,
}

/// GC result. Unknown deletions are returned as errors, not listed here. Fields
/// are private; the record is issued only after the exact GC state machine runs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobGcReceipt {
    receipt: Receipt,
    proof_id: BlobId,
    deleted: Vec<BlobLocator>,
    retained: Vec<BlobLocator>,
    anchor_fingerprint: String,
}

impl BlobGcReceipt {
    pub fn from_verified(
        verified: VerifiedBlobReceipt,
        expected_anchor: &BlobIssuerTrustAnchor,
        proof_id: BlobId,
        deleted: Vec<BlobLocator>,
        retained: Vec<BlobLocator>,
    ) -> Result<Self, BlobError> {
        if verified.anchor_fingerprint() != expected_anchor.fingerprint()
            || verified.binding().proof_id() != Some(&proof_id)
        {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        let value = Self {
            receipt: verified.receipt().clone(),
            proof_id,
            deleted,
            retained,
            anchor_fingerprint: verified.anchor_fingerprint().to_owned(),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), BlobError> {
        self.receipt
            .validate()
            .map_err(|error| BlobError::Receipt(error.to_string()))?;
        canonical_sha256(&self.anchor_fingerprint, "anchor_fingerprint")?;
        let mut seen = BTreeSet::new();
        for locator in self.deleted.iter().chain(&self.retained) {
            locator.validate()?;
            if !seen.insert(locator) {
                return Err(BlobError::DuplicateIdentity("gc_receipt.locator"));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }

    #[must_use]
    pub fn proof_id(&self) -> &BlobId {
        &self.proof_id
    }

    #[must_use]
    pub fn deleted(&self) -> &[BlobLocator] {
        &self.deleted
    }

    #[must_use]
    pub fn retained(&self) -> &[BlobLocator] {
        &self.retained
    }

    #[must_use]
    pub fn anchor_fingerprint(&self) -> &str {
        &self.anchor_fingerprint
    }
}

/// Honest health dimensions required before readiness may be true.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct BlobHealth {
    pub ready: bool,
    pub owner_matches: bool,
    pub containment_proven: bool,
    pub permissions_proven: bool,
    pub recovery_clean: bool,
    pub active_key_available: bool,
    pub root_generation: u64,
    pub degraded: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct BlobHealthWire {
    ready: bool,
    owner_matches: bool,
    containment_proven: bool,
    permissions_proven: bool,
    recovery_clean: bool,
    active_key_available: bool,
    root_generation: u64,
    degraded: Vec<String>,
}

impl BlobHealth {
    pub fn validate(&self) -> Result<(), BlobError> {
        let derived = self.owner_matches
            && self.containment_proven
            && self.permissions_proven
            && self.recovery_clean
            && self.active_key_available
            && self.root_generation > 0
            && self.degraded.is_empty();
        if self.ready != derived {
            return Err(BlobError::InvalidContract(
                "health.ready does not match health dimensions".to_owned(),
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for BlobHealth {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BlobHealthWire::deserialize(deserializer)?;
        let value = Self {
            ready: wire.ready,
            owner_matches: wire.owner_matches,
            containment_proven: wire.containment_proven,
            permissions_proven: wire.permissions_proven,
            recovery_clean: wire.recovery_clean,
            active_key_available: wire.active_key_available,
            root_generation: wire.root_generation,
            degraded: wire.degraded,
        };
        for reason in &value.degraded {
            valid_text(reason, "health.degraded").map_err(de::Error::custom)?;
        }
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Computes the versioned identity digest that binds one blob's immutable
/// description into its receipt. It is a pure derivation shared by the contract
/// validation and the S-04 service; it grants no authority.
#[allow(clippy::too_many_arguments)]
pub fn receipt_binding_sha256(
    format: &BlobId,
    format_version: u32,
    locator: &BlobLocator,
    plaintext_length: u64,
    stored_length: u64,
    plaintext_sha256: &str,
    sealed_sha256: &str,
    compression: &CompressionDescriptor,
    crypto: &CryptoDescriptor,
    policy: &BlobPolicyBinding,
) -> Result<String, BlobError> {
    let bytes = serde_json::to_vec(&(
        CONTRACT_VERSION,
        format,
        format_version,
        locator,
        plaintext_length,
        stored_length,
        stored_length, // envelope_length == stored_length
        plaintext_sha256,
        sealed_sha256,
        compression,
        crypto,
        policy,
        locator.root_generation,
        locator.path_generation,
    ))
    .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
    Ok(hex_sha256(&bytes))
}

fn canonical_sha256(value: &str, field: &'static str) -> Result<(), BlobError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(BlobError::InvalidField {
            field,
            reason: "must be lowercase SHA-256 hex",
        })
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// Recovery ceiling for a missing blob encryption key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobKeyRecoveryCeiling {
    /// The configured provider may recover or rotate the referenced key lineage.
    Unavailable,
    /// The required key provider is absent from the current composition.
    PlanGap,
}

/// Operation whose key dependency could not be satisfied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobKeyOperation {
    Stage,
    Read,
    Recovery,
}

/// Typed boundary failures. No protected payload bytes are included.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BlobError {
    #[error("invalid {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid contract: {0}")]
    InvalidContract(String),
    #[error("receipt contract rejected the operation: {0}")]
    Receipt(String),
    #[error("authority binding required: {0}")]
    AuthorityRequired(&'static str),
    #[error("stale or mismatched root/authority fence")]
    StaleFence,
    #[error("root is already owned by a different lease")]
    OwnerConflict,
    #[error("duplicate identity in {0}")]
    DuplicateIdentity(&'static str),
    #[error("complete live-set proof required")]
    IncompleteLiveSet,
    #[error("blob not found")]
    NotFound,
    #[error("metadata and payload do not describe one immutable object")]
    MetadataPayloadMismatch,
    #[error("idempotency identity was reused with different content or metadata")]
    IdempotencyConflict,
    #[error("integrity/authentication verification failed")]
    IntegrityMismatch,
    #[error(
        "unknown outcome after durable publish effect for operation {operation_id} at {state:?}"
    )]
    UnknownPublishOutcome {
        operation_id: String,
        state: PublishState,
    },
    #[error("unknown outcome after durable GC effect for operation {operation_id} at {state:?}")]
    UnknownGcOutcome {
        operation_id: String,
        state: GcState,
    },
    #[error("PLAN_GAP: {0}")]
    PlanGap(String),
    #[error("provider unavailable: {0}")]
    ProviderUnavailable(&'static str),
    #[error(
        "key unavailable during {operation:?}; lineage={key_lineage:?}; generation={key_generation:?}; ceiling={recovery:?}"
    )]
    KeyUnavailable {
        operation: BlobKeyOperation,
        key_lineage: Option<BlobId>,
        key_generation: Option<u64>,
        recovery: BlobKeyRecoveryCeiling,
    },
    #[error("provider failure: {0}")]
    Provider(String),
}

impl From<eliot_receipts::ReceiptError> for BlobError {
    fn from(value: eliot_receipts::ReceiptError) -> Self {
        Self::Receipt(value.to_string())
    }
}

/// Boxed future returned by the single object-safe client port.
pub type BlobFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, BlobError>> + Send + 'a>>;

/// The one canonical provider-neutral `BlobStore` client.
///
/// It is object-safe (`&dyn BlobStoreClient` works) and returns a single boxed
/// future type; there is no parallel `async fn` trait and no second dynamic
/// trait. Receipt-bearing responses are issued by the service, never by the
/// caller.
pub trait BlobStoreClient: Send + Sync {
    fn stage(&self, request: BlobStageRequest) -> BlobFuture<'_, BlobReadyReceipt>;
    fn read(&self, request: BlobReadRequest) -> BlobFuture<'_, BlobReadChunk>;
    fn reachability(
        &self,
        request: BlobReachabilityRequest,
    ) -> BlobFuture<'_, BlobReachabilityView>;
    fn gc(&self, request: BlobGcRequest) -> BlobFuture<'_, BlobGcReceipt>;
    fn health(&self) -> BlobFuture<'_, BlobHealth>;
}

/// Computes the canonical relative payload path for a locator. The adapter
/// must still prove component/reparse containment before using it.
pub fn payload_path(locator: &BlobLocator) -> Result<WorkScopePath, BlobError> {
    locator.validate()?;
    let hash = locator.hash.as_str();
    WorkScopePath::new(format!(
        "objects/g{}/{}/{}.p{}",
        locator.root_generation,
        &hash[..2],
        hash,
        locator.path_generation
    ))
    .map_err(|error| BlobError::InvalidContract(error.to_string()))
}

/// Computes the canonical relative metadata path.
pub fn metadata_path(locator: &BlobLocator) -> Result<WorkScopePath, BlobError> {
    locator.validate()?;
    let hash = locator.hash.as_str();
    WorkScopePath::new(format!(
        "objects/g{}/{}/{}.m{}",
        locator.root_generation,
        &hash[..2],
        hash,
        locator.path_generation
    ))
    .map_err(|error| BlobError::InvalidContract(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_hash_and_locator_fail_during_deserialization() {
        assert!(serde_json::from_str::<BlobHash>("\"AA\"").is_err());
        let malformed = r#"{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","root_generation":0,"path_generation":1}"#;
        assert!(serde_json::from_str::<BlobLocator>(malformed).is_err());
    }

    #[test]
    fn blob_id_rejects_path_syntax_during_deserialization() {
        assert!(serde_json::from_str::<BlobId>("\"../owner\"").is_err());
        assert!(serde_json::from_str::<BlobId>("\"owner-1\"").is_ok());
    }

    #[test]
    fn generated_paths_are_component_relative() {
        let locator = BlobLocator {
            hash: BlobHash::new("a".repeat(64)).expect("hash"),
            root_generation: 7,
            path_generation: 1,
        };
        let path = payload_path(&locator).expect("path");
        assert_eq!(
            path.normalized_identity(),
            format!("objects/g7/aa/{}.p1", "a".repeat(64))
        );
        assert_eq!(
            path.adapter_input().containment,
            eliot_platform::AdapterContainment::ReparseAndProveWithinWorkScope
        );
    }

    #[test]
    fn validated_wire_descriptors_and_health_fail_closed() {
        assert!(
            serde_json::from_str::<CompressionDescriptor>(r#"{"algorithm":"zstd","version":0}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<CryptoDescriptor>(
                r#"{"algorithm":"aes-gcm","version":1,"key_lineage":"lineage","key_generation":0}"#
            )
            .is_err()
        );
        let lying_health = r#"{"ready":true,"owner_matches":false,"containment_proven":true,"permissions_proven":true,"recovery_clean":true,"active_key_available":true,"root_generation":1,"degraded":[]}"#;
        assert!(serde_json::from_str::<BlobHealth>(lying_health).is_err());
    }

    #[test]
    fn policy_reference_cannot_bypass_constructor_through_serde() {
        let malformed = r#"{"privacy_class":"PRIVATE","retention_class":"TASK","policy_ref":"","instruction_taint":"DATA_ONLY","effect_ceiling":"CANDIDATE_ONLY"}"#;
        assert!(serde_json::from_str::<BlobPolicyBinding>(malformed).is_err());
    }
}
