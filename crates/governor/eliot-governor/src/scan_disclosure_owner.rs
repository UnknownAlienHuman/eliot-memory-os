//! Installation-bound scan disclosure store (issue #2900).
//!
//! The concrete [`eliot_workscope::ScanDisclosureStore`] port implementation
//! in the existing durable owner. Every write, replay, read and retirement
//! flows through the ORS [`ScanDisclosureRecordOwner`] admitted by the
//! installation contour: atomicity, conflict detection and reconciliation
//! live in the ORS owner, never here. This adapter owns no filesystem, takes
//! no paths, launches no processes and makes no model calls — it only admits
//! owner bindings, maps write identities, and verifies commitments.
//!
//! The cold-start/attach ingress ([`GovernorComposition::run_cold_start_trigger_scan`])
//! takes exactly this store: no in-memory-only or loose-file fallback can
//! reach [`BootstrapScanner::scan`] through the production route.

use std::sync::Arc;

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_ors::{
    OrsError, SCAN_DISCLOSURE_RECORD_TYPE, ScanDisclosureOrsRecord, ScanDisclosureRecordOwner,
    ScanDisclosureRecordState, ScanDisclosureStageOutcome,
};
use eliot_workscope::{
    LOOSE_SCAN_DISCLOSURE_PREFIX, LOOSE_SCAN_DISCLOSURE_SUFFIX, LooseScanQuarantine,
    SCAN_DISCLOSURE_SCHEMA_VERSION, ScanDisclosureOwnerBinding, ScanDisclosureReceipt,
    ScanDisclosureStore, ScanReceiptDiagnosticView, ScanReceiptHandle, ScanReceiptRetention,
    ScanRetentionPolicy, WorkScopeError, quarantine_loose_scan_disclosure,
};

/// Installation storage contour admitted for scan disclosure writes.
///
/// Issued by the installation/session owner: the installation identity plus
/// the admitted ORS object and its generation. The object reference is
/// lexically admitted at bind time (absolute drive-anchored spelling only:
/// no UNC/network object, no device/NT/verbatim prefix, no relative,
/// drive-relative or ambient spelling, no dot or parent traversal, no
/// Windows alias component, no bare volume root), following the
/// installation `WindowsPathIdentity::parse_root` platform contract with
/// the UNC rejection the disclosure acceptance criterion requires. The
/// adapter verifies every binding against this contour before touching the
/// durable owner, and the contour's object and generation ride the writer
/// receipt into every durable row and are re-verified on every read, so a
/// row written under one object or generation is never readable as another:
/// the API has no path input at all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallationScanContour {
    installation_id: String,
    ors_object_ref: String,
    ors_generation: u64,
}

impl InstallationScanContour {
    /// Binds the contour the installation owner admitted.
    ///
    /// # Errors
    ///
    /// Returns [`WorkScopeError::InvalidText`] when an identity reference is
    /// blank or carries control characters, when the ORS object reference is
    /// not an admitted absolute drive-anchored object (UNC/network object,
    /// device/NT/verbatim prefix, relative, drive-relative or ambient
    /// spelling, dot or parent traversal, Windows alias component, or bare
    /// volume root), and [`WorkScopeError::InvalidCounter`] when the ORS
    /// generation is zero.
    pub fn bind(
        installation_id: impl Into<String>,
        ors_object_ref: impl Into<String>,
        ors_generation: u64,
    ) -> Result<Self, WorkScopeError> {
        let contour = Self {
            installation_id: installation_id.into(),
            ors_object_ref: ors_object_ref.into(),
            ors_generation,
        };
        contour.validate()?;
        Ok(contour)
    }

    /// Installation identity this contour admits writes for.
    #[must_use]
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    /// ORS object reference this contour admits writes through.
    #[must_use]
    pub fn ors_object_ref(&self) -> &str {
        &self.ors_object_ref
    }

    /// ORS generation this contour was issued at.
    #[must_use]
    pub fn ors_generation(&self) -> u64 {
        self.ors_generation
    }

    fn validate(&self) -> Result<(), WorkScopeError> {
        nonblank(&self.installation_id, "scan_contour.installation_id")?;
        nonblank(&self.ors_object_ref, "scan_contour.ors_object_ref")?;
        admit_storage_object(&self.ors_object_ref)?;
        if self.ors_generation == 0 {
            return Err(WorkScopeError::InvalidCounter {
                field: "scan_contour.ors_generation",
            });
        }
        Ok(())
    }

    fn admits(&self, binding: &ScanDisclosureOwnerBinding) -> Result<(), WorkScopeError> {
        binding.admit()?;
        if binding.installation_id != self.installation_id {
            return Err(WorkScopeError::ScanContourNotAdmitted);
        }
        Ok(())
    }
}

/// Installation-bound durable [`ScanDisclosureStore`].
///
/// Constructed once from the installation contour and the ORS owner handle;
/// the attach/cold-start ingress holds it across the trigger scan so the
/// receipt write, its replay and its readback all resolve against the same
/// admitted owner.
pub struct InstallationScanDisclosureStore {
    contour: InstallationScanContour,
    owner: Arc<dyn ScanDisclosureRecordOwner>,
}

impl InstallationScanDisclosureStore {
    /// Binds the adapter to the admitted contour and durable owner.
    ///
    /// # Errors
    ///
    /// Returns an error when the contour is malformed.
    pub fn bind(
        contour: InstallationScanContour,
        owner: Arc<dyn ScanDisclosureRecordOwner>,
    ) -> Result<Self, WorkScopeError> {
        contour.validate()?;
        Ok(Self { contour, owner })
    }

    /// Admitted installation contour this store writes through.
    #[must_use]
    pub fn contour(&self) -> &InstallationScanContour {
        &self.contour
    }

    /// Projects the bounded redacted diagnostic view of one stored receipt.
    ///
    /// Carries opaque references and the immutable commitment only: no
    /// receipt content, no allowed-class lists, no paths.
    ///
    /// # Errors
    ///
    /// Returns the handle validation error when the handle is malformed.
    pub fn diagnostic_view(
        &self,
        handle: &ScanReceiptHandle,
    ) -> Result<ScanReceiptDiagnosticView, WorkScopeError> {
        ScanReceiptDiagnosticView::project(handle)
    }

    /// Quarantines one loose `scan-disclosure-*.json` capture without
    /// adopting it.
    ///
    /// The filename shape is classified and the content is bound to it: the
    /// retired loose implementation named captures
    /// `scan-disclosure-<sha256-of-canonical-bytes>.json`, so bytes that do
    /// not reproduce the filename digest are refused as corrupt or
    /// substituted content rather than quarantined as a matching capture. A
    /// digest match still proves nothing about owner provenance: even
    /// self-consistent bytes stay quarantined for the migration owner
    /// instead of becoming readable evidence, and the bytes are never
    /// decoded as a receipt.
    ///
    /// # Errors
    ///
    /// Returns an error when the filename is blank or does not carry the
    /// retired loose-capture shape, when the content is empty, or when the
    /// content digest does not reproduce the filename segment.
    pub fn quarantine_loose_capture(
        &self,
        file_name: &str,
        bytes: &[u8],
    ) -> Result<LooseScanQuarantine, WorkScopeError> {
        let proof = quarantine_loose_scan_disclosure(file_name)?;
        if bytes.is_empty() {
            return Err(WorkScopeError::ScanReceiptCorrupt);
        }
        let stem = file_name
            .strip_prefix(LOOSE_SCAN_DISCLOSURE_PREFIX)
            .and_then(|rest| rest.strip_suffix(LOOSE_SCAN_DISCLOSURE_SUFFIX))
            .filter(|stem| stem.len() == 64 && stem.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or(WorkScopeError::ScanReceiptCorrupt)?;
        if sha256_hex(bytes) != stem.to_ascii_lowercase() {
            return Err(WorkScopeError::ScanReceiptCorrupt);
        }
        Ok(proof)
    }

    /// Writer receipt binding one commit to this contour and write identity.
    ///
    /// The admitted object reference and generation travel in the receipt, so
    /// the durable row names the exact storage object and generation it was
    /// committed through; every read re-verifies the stored receipt against
    /// the live contour.
    fn writer_receipt_for(
        &self,
        binding: &ScanDisclosureOwnerBinding,
        request_hash: &str,
    ) -> String {
        format!(
            "ors:{}:{}:{}:{}",
            self.contour.ors_object_ref,
            self.contour.ors_generation,
            binding.operation_id,
            request_hash
        )
    }

    fn check_receipt_binding(
        binding: &ScanDisclosureOwnerBinding,
        receipt: &ScanDisclosureReceipt,
    ) -> Result<(), WorkScopeError> {
        if binding.lease_ref != receipt.lease_ref
            || binding.candidate_root_ref != receipt.candidate_root_ref
            || binding.privacy_boundary_ref != receipt.privacy_boundary_ref.as_deref().unwrap_or("")
        {
            return Err(WorkScopeError::ScanContourNotAdmitted);
        }
        Ok(())
    }

    /// Builds the owner handle for one retained record after verifying the
    /// full binding: owner identity, operation key, canonical request hash,
    /// contour writer receipt, receipt digest and retention state.
    ///
    /// The stored writer receipt must reproduce this contour's object and
    /// generation for the binding's operation and request hash: a row
    /// committed under a different storage object is not admitted, a row
    /// from another generation (or the legacy receipt shape, which names no
    /// generation) is stale, and a row with the same scope but a different
    /// operation/request tail conflicts.
    fn handle_for(
        &self,
        binding: &ScanDisclosureOwnerBinding,
        record: &ScanDisclosureOrsRecord,
    ) -> Result<ScanReceiptHandle, WorkScopeError> {
        if record.installation_id != self.contour.installation_id {
            return Err(WorkScopeError::ScanContourNotAdmitted);
        }
        if record.schema_version != SCAN_DISCLOSURE_SCHEMA_VERSION {
            return Err(WorkScopeError::ScanReceiptStale);
        }
        if record.operation_key != binding.operation_key()
            || record.request_hash
                != binding.request_hash(&record.receipt_digest, record.schema_version)
        {
            return Err(WorkScopeError::ScanReceiptStale);
        }
        let writer_receipt = self.writer_receipt_for(binding, &record.request_hash);
        if record.writer_receipt != writer_receipt {
            return Err(Self::classify_writer_mismatch(
                &record.writer_receipt,
                &self.contour,
            ));
        }
        let receipt = decode_receipt(record)?;
        let retention = match record.state {
            ScanDisclosureRecordState::Prepared => {
                return Err(WorkScopeError::ScanReceiptUnknownCommit);
            }
            ScanDisclosureRecordState::Committed => ScanReceiptRetention::Active,
            ScanDisclosureRecordState::Retired => {
                let Some(policy_revision) = record.retired_by_policy else {
                    return Err(WorkScopeError::ScanReceiptCorrupt);
                };
                ScanReceiptRetention::Retired { policy_revision }
            }
            ScanDisclosureRecordState::Superseded => {
                let Some(successor) = &record.supersedes_ref else {
                    return Err(WorkScopeError::ScanReceiptCorrupt);
                };
                ScanReceiptRetention::Superseded {
                    successor_ref: successor.clone(),
                }
            }
        };
        let handle = ScanReceiptHandle {
            receipt_ref: receipt.scan_ref,
            store_ref: record.operation_key.clone(),
            owner_ref: binding.owner_ref(),
            record_commitment: binding.record_commitment(&record.receipt_digest),
            receipt_digest: record.receipt_digest.clone(),
            schema_version: record.schema_version,
            writer_receipt_ref: record.writer_receipt.clone(),
            retention,
        };
        handle.validate()?;
        Ok(handle)
    }

    fn commit_prepared(
        &mut self,
        binding: &ScanDisclosureOwnerBinding,
        operation_key: &str,
        request_hash: &str,
    ) -> Result<ScanDisclosureOrsRecord, WorkScopeError> {
        let writer_receipt = self.writer_receipt_for(binding, request_hash);
        self.owner
            .commit_scan_disclosure(operation_key, request_hash, &writer_receipt)
            .map_err(|error| conflict_error(&error))?
            .ok_or(WorkScopeError::ScanReceiptUnknownCommit)
    }

    /// Classifies a stored writer receipt that does not reproduce this
    /// contour's object, generation, operation and request hash.
    fn classify_writer_mismatch(stored: &str, contour: &InstallationScanContour) -> WorkScopeError {
        let object_prefix = format!("ors:{}:", contour.ors_object_ref);
        let Some(rest) = stored.strip_prefix(&object_prefix) else {
            return WorkScopeError::ScanContourNotAdmitted;
        };
        let generation_prefix = format!("{}:", contour.ors_generation);
        if rest.strip_prefix(&generation_prefix).is_none() {
            return WorkScopeError::ScanReceiptStale;
        }
        WorkScopeError::ScanIdentityConflict
    }
}

impl ScanDisclosureStore for InstallationScanDisclosureStore {
    fn store_receipt(
        &mut self,
        binding: &ScanDisclosureOwnerBinding,
        receipt: &ScanDisclosureReceipt,
    ) -> Result<ScanReceiptHandle, WorkScopeError> {
        self.contour.admits(binding)?;
        receipt.validate()?;
        Self::check_receipt_binding(binding, receipt)?;
        let bytes =
            canonical_json_bytes(receipt).map_err(|_| WorkScopeError::ScanReceiptInaccessible)?;
        let receipt_bytes =
            String::from_utf8(bytes).map_err(|_| WorkScopeError::ScanReceiptInaccessible)?;
        let receipt_digest = sha256_hex(receipt_bytes.as_bytes());
        let operation_key = binding.operation_key();
        let request_hash = binding.request_hash(&receipt_digest, SCAN_DISCLOSURE_SCHEMA_VERSION);
        let candidate = ScanDisclosureOrsRecord {
            contract_version: eliot_ors::CONTRACT_VERSION,
            operation_key: operation_key.clone(),
            idempotency_key: binding.idempotency_key.clone(),
            request_hash: request_hash.clone(),
            installation_id: binding.installation_id.clone(),
            principal_ref: binding.principal_ref.clone(),
            session_ref: binding.session_ref.clone(),
            host_generation_ref: binding.host_generation_ref.clone(),
            lease_ref: binding.lease_ref.clone(),
            lease_consumed: binding.lease_consumed,
            candidate_root_ref: binding.candidate_root_ref.clone(),
            privacy_boundary_ref: binding.privacy_boundary_ref.clone(),
            state_fence_ref: binding.state_fence_ref.clone(),
            authority_epoch_ref: binding.authority_epoch_ref.clone(),
            policy_revision: binding.policy_revision,
            deadline: binding.deadline,
            receipt_digest: receipt_digest.clone(),
            schema_version: SCAN_DISCLOSURE_SCHEMA_VERSION,
            receipt_bytes,
            writer_receipt: String::new(),
            state: ScanDisclosureRecordState::Prepared,
            supersedes_ref: None,
            retired_by_policy: None,
        };
        let stored = match self
            .owner
            .stage_scan_disclosure(&candidate)
            .map_err(|error| conflict_error(&error))?
        {
            ScanDisclosureStageOutcome::Stored => {
                self.commit_prepared(binding, &operation_key, &request_hash)?
            }
            ScanDisclosureStageOutcome::AlreadyBound(winner) => match winner.state {
                ScanDisclosureRecordState::Prepared => {
                    // The original stage survived but its commit response was
                    // lost: reconcile the original operation instead of
                    // creating another record.
                    self.commit_prepared(binding, &operation_key, &request_hash)?
                }
                ScanDisclosureRecordState::Committed => *winner,
                ScanDisclosureRecordState::Retired => {
                    return Err(WorkScopeError::ScanReceiptInvalidated);
                }
                ScanDisclosureRecordState::Superseded => {
                    return Err(WorkScopeError::ScanReceiptStale);
                }
            },
        };
        self.handle_for(binding, &stored)
    }

    fn readback(
        &self,
        handle: &ScanReceiptHandle,
        binding: &ScanDisclosureOwnerBinding,
    ) -> Result<ScanDisclosureReceipt, WorkScopeError> {
        handle.validate()?;
        self.contour.admits(binding)?;
        if handle.owner_ref != binding.owner_ref() {
            return Err(WorkScopeError::ScanContourNotAdmitted);
        }
        let record = self
            .owner
            .load_scan_disclosure(&handle.store_ref)
            .map_err(|error| read_error(&error))?
            .ok_or(WorkScopeError::ScanReceiptMissing)?;
        match record.state {
            ScanDisclosureRecordState::Prepared => {
                return Err(WorkScopeError::ScanReceiptUnknownCommit);
            }
            ScanDisclosureRecordState::Retired => {
                return Err(WorkScopeError::ScanReceiptInvalidated);
            }
            ScanDisclosureRecordState::Superseded => {
                return Err(WorkScopeError::ScanReceiptStale);
            }
            ScanDisclosureRecordState::Committed => (),
        }
        let verified = self.handle_for(binding, &record)?;
        if verified.record_commitment != handle.record_commitment
            || verified.receipt_digest != handle.receipt_digest
            || verified.receipt_ref != handle.receipt_ref
        {
            return Err(WorkScopeError::ScanReceiptReplaced);
        }
        decode_receipt(&record)
    }

    fn reconcile(
        &mut self,
        binding: &ScanDisclosureOwnerBinding,
    ) -> Result<ScanReceiptHandle, WorkScopeError> {
        self.contour.admits(binding)?;
        let operation_key = binding.operation_key();
        let record = self
            .owner
            .load_scan_disclosure(&operation_key)
            .map_err(|error| read_error(&error))?
            .ok_or(WorkScopeError::ScanReceiptUnknownCommit)?;
        if record.installation_id != self.contour.installation_id {
            return Err(WorkScopeError::ScanContourNotAdmitted);
        }
        let stored = match record.state {
            ScanDisclosureRecordState::Prepared => {
                let request_hash =
                    binding.request_hash(&record.receipt_digest, record.schema_version);
                if record.request_hash != request_hash {
                    return Err(WorkScopeError::ScanIdentityConflict);
                }
                self.commit_prepared(binding, &operation_key, &request_hash)?
            }
            ScanDisclosureRecordState::Committed => record,
            ScanDisclosureRecordState::Retired => {
                return Err(WorkScopeError::ScanReceiptInvalidated);
            }
            ScanDisclosureRecordState::Superseded => {
                return Err(WorkScopeError::ScanReceiptStale);
            }
        };
        self.handle_for(binding, &stored)
    }

    fn retire(
        &mut self,
        handle: &ScanReceiptHandle,
        binding: &ScanDisclosureOwnerBinding,
        policy: &ScanRetentionPolicy,
    ) -> Result<ScanReceiptHandle, WorkScopeError> {
        handle.validate()?;
        self.contour.admits(binding)?;
        policy.validate()?;
        if handle.owner_ref != binding.owner_ref() {
            return Err(WorkScopeError::ScanContourNotAdmitted);
        }
        let successor = match &handle.retention {
            ScanReceiptRetention::Active => None,
            ScanReceiptRetention::Superseded { successor_ref } => Some(successor_ref.as_str()),
            ScanReceiptRetention::Retired { .. } => {
                return Err(WorkScopeError::ScanReceiptInvalidated);
            }
        };
        let request_hash = binding.request_hash(&handle.receipt_digest, handle.schema_version);
        let stored = self
            .owner
            .retire_scan_disclosure(
                &binding.operation_key(),
                &request_hash,
                policy.policy_revision,
                successor,
            )
            .map_err(|error| conflict_error(&error))?
            .ok_or(WorkScopeError::ScanReceiptMissing)?;
        self.handle_for(binding, &stored)
    }
}

fn nonblank(value: &str, field: &'static str) -> Result<(), WorkScopeError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(WorkScopeError::InvalidText { field })
    } else {
        Ok(())
    }
}

/// Admits one installation-owned ORS object reference (issue #2900 W7).
///
/// Lexical admission only, following the installation
/// `WindowsPathIdentity::parse_root` platform contract with the stricter
/// object rule the disclosure acceptance criterion demands: UNC/network
/// objects are never admitted (a caller cannot choose an arbitrary
/// directory/UNC target), and neither are device/NT/verbatim prefixes,
/// relative, drive-relative or ambient spellings, dot or parent traversal,
/// Windows alias components, or bare volume roots. The reference names the
/// storage object the installation owner vouches; reparse-point and ACL
/// checks on the live object stay with the owner that opens it
/// ([`RedbRecoveryStore::open`] below the installation data root), while
/// this contour refuses every spelling that could name anything else.
fn admit_storage_object(value: &str) -> Result<(), WorkScopeError> {
    const FIELD: &str = "scan_contour.ors_object_ref";
    let folded = value.replace('/', "\\");
    let lower = folded.to_ascii_lowercase();
    for prefix in [
        "\\\\?\\",
        "\\\\.\\",
        "\\??\\",
        "\\\\??\\",
        "\\device\\",
        "\\\\device\\",
        "\\globalroot\\",
        "\\\\globalroot\\",
    ] {
        if lower.starts_with(prefix) {
            return Err(WorkScopeError::InvalidText { field: FIELD });
        }
    }
    if folded.starts_with("\\\\") {
        return Err(WorkScopeError::InvalidText { field: FIELD });
    }
    let bytes = folded.as_bytes();
    if bytes.len() < 4 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return Err(WorkScopeError::InvalidText { field: FIELD });
    }
    // Byte offsets 0..3 are the ASCII `X:\` anchor checked above, so
    // slicing the remainder at offset 3 always lands on a char boundary.
    let mut components = 0_usize;
    let mut first = true;
    for component in folded[3..].split('\\') {
        if component.is_empty() {
            continue;
        }
        if component == "." || component == ".." {
            return Err(WorkScopeError::InvalidText { field: FIELD });
        }
        if component.ends_with(' ') || component.ends_with('.') || component.contains(':') {
            return Err(WorkScopeError::InvalidText { field: FIELD });
        }
        if first && component.starts_with('~') {
            return Err(WorkScopeError::InvalidText { field: FIELD });
        }
        first = false;
        components += 1;
    }
    if components == 0 {
        return Err(WorkScopeError::InvalidText { field: FIELD });
    }
    if folded.contains('%') || folded.contains('$') {
        return Err(WorkScopeError::InvalidText { field: FIELD });
    }
    Ok(())
}

/// Decodes and authenticates the exact canonical receipt bytes of one
/// retained record: valid JSON, a valid receipt shape, and a digest that
/// reproduces the stored commitment.
fn decode_receipt(
    record: &ScanDisclosureOrsRecord,
) -> Result<ScanDisclosureReceipt, WorkScopeError> {
    let receipt: ScanDisclosureReceipt = serde_json::from_str(&record.receipt_bytes)
        .map_err(|_| WorkScopeError::ScanReceiptCorrupt)?;
    receipt
        .validate()
        .map_err(|_| WorkScopeError::ScanReceiptCorrupt)?;
    let bytes = canonical_json_bytes(&receipt).map_err(|_| WorkScopeError::ScanReceiptCorrupt)?;
    if sha256_hex(&bytes) != record.receipt_digest {
        return Err(WorkScopeError::ScanReceiptCorrupt);
    }
    Ok(receipt)
}

/// Maps an ORS write-path failure to its typed scan cause: binding conflicts
/// stay conflicts, everything else is an inaccessible write.
fn conflict_error(error: &OrsError) -> WorkScopeError {
    match error {
        OrsError::IntegrityProblem { record_type, .. }
            if *record_type == SCAN_DISCLOSURE_RECORD_TYPE =>
        {
            WorkScopeError::ScanIdentityConflict
        }
        _ => WorkScopeError::ScanReceiptInaccessible,
    }
}

/// Maps an ORS read-path failure to its typed scan cause: integrity breaks
/// are corruption, everything else is an inaccessible record.
fn read_error(error: &OrsError) -> WorkScopeError {
    match error {
        OrsError::IntegrityProblem { record_type, .. }
            if *record_type == SCAN_DISCLOSURE_RECORD_TYPE =>
        {
            WorkScopeError::ScanReceiptCorrupt
        }
        _ => WorkScopeError::ScanReceiptInaccessible,
    }
}
