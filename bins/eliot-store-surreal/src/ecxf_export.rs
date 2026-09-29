#![forbid(unsafe_code)]

//! Reachable product command for one `ECXF/1` export (issue #1871).
//!
//! This module is the composition root for the canonical exchange format: it
//! decodes the one-shot arguments, constructs the typed
//! [`EcxfExportRequest`], binds the real [`EcxfSourceStore`] port to the store
//! owner this process already holds, calls
//! [`eliot_backup::export_ecxf_package`] — the single `ECXF/1` export entry —
//! and projects the exporter's terminal outcome.
//!
//! The `StoreOwnerEcxfSource` port implementation is the only place that reads
//! source evidence, and it is the only thing standing between the operator's
//! arguments and the exporter: every value the fence could carry would have to
//! come from
//! [`capture_ecxf_source`](eliot_store_surreal_adapter::capture_ecxf_source),
//! the one real coherent read in the admitted vendor edge, which reads the
//! canonical member classes and the observed `state_fence`,
//! `schema_generation` and sequence counters inside one fixed
//! `BEGIN TRANSACTION`/`COMMIT` batch. This module fabricates no fence member,
//! parses no provider row into domain semantics, and re-derives no digest: the
//! only thing it forwards is the owner's own verdict.
//!
//! The `ECXF/1` package layout, the `ExportFence` and every residency,
//! checksum and integrity proof belong to `eliot-ecxf` and to the
//! `eliot-backup` exporter; neither is reimplemented, defaulted, pre-checked
//! or weakened here (I05-10 "Consistent export boundary", I05-13).
//!
//! Fail-closed is the reachable outcome today, and it is the required one, not
//! a stub. The store owner states in its own capture that it cannot be
//! projected into a complete `ECXF/1` source view while it declares evidence
//! gaps, so the port returns the typed
//! [`BackupError::UnobservedSourceMember`] refusal naming the first member the
//! owner did not observe. Nothing is defaulted, no fence member is filled in,
//! and the rows already read are not turned into records; no package is
//! written. This command reports that refusal and exits nonzero; it never
//! reports success over an incomplete view.

use std::path::{Path, PathBuf};

use eliot_backup::{
    BackupError, CoherentSourceExport, EcxfExportRequest, EcxfSourceStore, export_ecxf_package,
};
use eliot_contracts::{ClockReading, ProductId, RequestId, RequestMetadata, SourceId};
use eliot_store_api::{OperationId, OperationIdentity, RequestMeta, ScopeId};
use eliot_store_surreal_adapter::{
    EcxfCaptureGap, EcxfSourceCapture, SurrealStoreAdapter, capture_ecxf_source,
};

use crate::{SERVICE_NAME, StoreComposition, StoreLaunchConfig};

/// Maximum admitted characters of one operator-declared identifier.
///
/// A bounded identifier keeps a typed refusal bounded and keeps a hostile argv
/// from becoming an unbounded identity. This is an admission bound, not a
/// domain rule: the closed identity types re-validate the value as well.
const MAX_IDENTIFIER_CHARS: usize = 200;

/// Exact length of the lowercase hex SHA-256 digest the export request identity
/// carries. `OperationIdentity::validate` enforces the same shape; checking it
/// here reports the bad argument as a launch refusal instead of a store error.
const CANONICAL_REQUEST_HASH_CHARS: usize = 64;

/// One-shot arguments of the `ECXF/1` export launch.
///
/// Every field is either a real configuration value this process already holds
/// or an explicit bounded operator selection. None of them is source evidence:
/// the scope selects what is requested, and the export id names the operation.
/// The fence itself is observed inside the capture transaction, never supplied
/// here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcxfExportArgs {
    /// Operator-declared export identity. It becomes the `OperationId` and
    /// therefore the `ExportFence.export_id` and the report's `export_id`.
    pub export_id: String,
    /// Declared store scope to export. The adapter retains it but cannot yet
    /// prove the scope-to-record closure, so it never filters the provider
    /// read with it.
    pub scope_id: String,
    /// Canonical request hash of the admitted request envelope.
    ///
    /// FINDING (#1871): no honest derivation of this digest exists in this
    /// process. `eliot_store_api::canonical_request_hash` is defined over
    /// `CanonicalRequestView` — the admitted *apply* envelope — and an ECXF
    /// export has no such envelope: no Governor or Kernel admission path emits
    /// one for an export today. Rather than invent a digest, this value is
    /// required from the operator as an explicit bounded input, exactly as the
    /// export id and the scope are. It is request identity only: no coherence
    /// proof reads it, and `prove_coherent_boundary` never consults it, so it
    /// cannot weaken the fence. It is re-validated by the closed
    /// `EcxfExportRequest::validate` before the capture runs.
    pub canonical_request_hash: String,
    /// Absolute destination directory of the published `ECXF/1` package.
    ///
    /// The path crosses the exporter unchanged. The exporter owns the
    /// "destination already exists" refusal, the exclusively claimed staging
    /// tree and the single atomic rename, so this module never creates,
    /// probes, merges or pre-checks it.
    pub out_dir: PathBuf,
}

/// The `EcxfSourceStore` over the canonical store owner this process composes
/// (`StoreComposition::store_adapter`).
struct StoreOwnerEcxfSource<'a> {
    adapter: &'a SurrealStoreAdapter,
}

impl EcxfSourceStore for StoreOwnerEcxfSource<'_> {
    async fn coherent_export(
        &self,
        request: &EcxfExportRequest,
    ) -> Result<CoherentSourceExport, BackupError> {
        // The one real coherent read in the admitted vendor edge: the rows and
        // the observed state fence come from one fixed transaction.
        let capture = capture_ecxf_source(self.adapter, request)
            .await
            .map_err(BackupError::Store)?;
        // The store owner states in its own capture that it must not be
        // projected into a complete ECXF source view while it declares
        // evidence gaps (see `EcxfSourceCapture`'s own doc contract in
        // `crates/storage/eliot-store-surreal-adapter/src/backup_snapshot.rs`).
        // So the export refuses here, naming the member the owner did not
        // observe. Nothing is defaulted, no fence member is filled in, and the
        // rows already read are not turned into records.
        Err(BackupError::UnobservedSourceMember {
            member: unobserved_member(&capture),
        })
    }
}

/// Names the first source-view member the store owner declared it could not
/// observe.
///
/// The vocabulary is the adapter's own `EcxfCaptureGap`
/// (`crates/storage/eliot-store-surreal-adapter/src/backup_snapshot.rs`); this
/// maps each gap onto the static name of the already-existing
/// `CoherentSourceExport` / `ExportFence` member it leaves unobserved, and
/// adds no second gap type. An owner that declares no gap at all has still not
/// established the observed completeness itself.
fn unobserved_member(capture: &EcxfSourceCapture) -> &'static str {
    match capture.missing_evidence.first() {
        Some(EcxfCaptureGap::RequestedScopeClosureUnproven) => "scope_id",
        Some(EcxfCaptureGap::SourcePurgeLedgerUnavailable) => "purge_ledger",
        Some(EcxfCaptureGap::BlobStoreEvidenceUnavailable) => "reachable_blob_residency_keys",
        Some(EcxfCaptureGap::ExternalSourceIdentityEvidenceUnavailable) => {
            "architecture_source_digest"
        }
        Some(EcxfCaptureGap::SourceExportReceiptUnavailable) => "export_receipt",
        None => "completeness",
    }
}

/// Runs one `ECXF/1` export against the store owner this process holds and
/// projects the exporter's terminal outcome.
///
/// Returns `Ok(())` only when the exporter published a package and its report
/// validates. Every refusal is projected as JSON on standard output and
/// returned as `Err`, which the launch path turns into this binary's own
/// nonzero launch failure; a refusal is never reported as success and a
/// published-but-unreconciled package is never reported as nothing written.
#[allow(clippy::print_stdout)]
pub async fn export_ecxf_once(
    composition: &StoreComposition,
    config: &StoreLaunchConfig,
    clock: &ClockReading,
    args: &EcxfExportArgs,
) -> Result<(), String> {
    let request = export_request(config, clock, args)?;
    let out_dir = destination(args)?;
    // The port implementation owns the single coherent read of the admitted
    // vendor edge, so the exporter — not this command — decides what the store
    // owner can and cannot prove.
    let source = StoreOwnerEcxfSource {
        adapter: composition.store_adapter(),
    };
    match export_ecxf_package(&request, &source, out_dir).await {
        Ok(report) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .map_err(|error| format!("serialize ECXF export report: {error}"))?
            );
            Ok(())
        }
        Err(error) => {
            project_refusal(&request, &error);
            Err(refusal_message(&error))
        }
    }
}

/// Constructs the typed `ECXF/1` export request from values this process holds.
///
/// The state fence is the bridge's own configured launch fence, which is the
/// same fence the adapter compares against the one observed inside the capture
/// transaction: a stale or foreign fence therefore refuses in the store rather
/// than producing a package. The request identity follows the construction
/// already used by the portable-dev schema-initialization one-shot: the
/// per-launch `request_id` binds the declared export id to the configured
/// instance id and launch nonce, and the stable `idempotency_key` binds the
/// declared export id to the configured instance id so a retry of the same
/// export keeps one logical retry identity. No counter, clock tick or constant
/// is used as identity.
fn export_request(
    config: &StoreLaunchConfig,
    clock: &ClockReading,
    args: &EcxfExportArgs,
) -> Result<EcxfExportRequest, String> {
    let export_id = bounded_identifier(&args.export_id, "export id")?;
    let scope_id = bounded_identifier(&args.scope_id, "scope id")?;
    let canonical_request_hash = bounded_canonical_request_hash(&args.canonical_request_hash)?;
    let operation_id = OperationId::new(export_id.clone())
        .map_err(|error| format!("invalid export id: {error}"))?;
    let idempotency_key = format!("ecxf-export-{export_id}-{}", config.instance_id);
    let request_id = RequestId::new(format!(
        "ecxf-export-{export_id}-{}-{}",
        config.instance_id, config.launch_nonce
    ))
    .map_err(|error| format!("invalid ECXF export request id: {error}"))?;
    let context: RequestMeta = RequestMetadata {
        request_id,
        // A one-shot launch has no attached semantic session and binds no
        // task; both stay explicitly absent rather than defaulted to a value.
        session_id: None,
        task_id: None,
        product_id: ProductId::new(SERVICE_NAME)
            .map_err(|error| format!("invalid ECXF export product id: {error}"))?,
        source_id: SourceId::new(config.instance_id.clone())
            .map_err(|error| format!("invalid ECXF export source id: {error}"))?,
        state_fence: config.runtime_launch.authority_state_fence.clone(),
        clock: *clock,
    };
    Ok(EcxfExportRequest {
        context,
        identity: OperationIdentity {
            operation_id,
            idempotency_key,
            canonical_request_hash,
        },
        scope_id: ScopeId::new(scope_id)
            .map_err(|error| format!("invalid ECXF export scope id: {error}"))?,
    })
}

/// Resolves the operator's destination without touching it.
///
/// Only absoluteness is checked, because a relative destination would resolve
/// against whatever current directory the launch happened to have. Existence,
/// writability and emptiness are deliberately left to the exporter: it refuses
/// an existing package and claims its staging tree exclusively, and a weaker
/// pre-check here would duplicate that ownership in the wrong place.
fn destination(args: &EcxfExportArgs) -> Result<&Path, String> {
    if !args.out_dir.is_absolute() {
        return Err("the ECXF export destination must be an absolute path".to_owned());
    }
    Ok(args.out_dir.as_path())
}

/// Rejects one blank, over-long or control-character operator identifier.
fn bounded_identifier(value: &str, what: &str) -> Result<String, String> {
    if value.is_empty()
        || value.trim().is_empty()
        || value.trim().len() != value.len()
        || value.chars().count() > MAX_IDENTIFIER_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "the ECXF export {what} must be a non-blank identifier of at most {MAX_IDENTIFIER_CHARS} characters"
        ));
    }
    Ok(value.to_owned())
}

/// Rejects one canonical request hash that is not 64 lowercase hex characters.
fn bounded_canonical_request_hash(value: &str) -> Result<String, String> {
    if value.len() != CANONICAL_REQUEST_HASH_CHARS
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!(
            "the ECXF export canonical request hash must be exactly {CANONICAL_REQUEST_HASH_CHARS} lowercase hex characters"
        ));
    }
    Ok(value.to_owned())
}

/// Projects one typed exporter refusal onto standard output.
///
/// The projection names the export id, the declared scope and the format, so a
/// refusal is attributable to one operation instead of appearing as an
/// anonymous failure. It states whether a package was published: the
/// post-publication reconciliation refusal is the only outcome that says yes.
#[allow(clippy::print_stdout, clippy::print_stderr)]
fn project_refusal(request: &EcxfExportRequest, error: &BackupError) {
    let published = matches!(error, BackupError::PublishReconciliationRequired { .. });
    let status = serde_json::json!({
        "service": SERVICE_NAME,
        "operation": "export_ecxf",
        "status": "REFUSED",
        "export_id": request.identity.operation_id.to_string(),
        "scope_id": request.scope_id.as_str(),
        "format": eliot_backup::FORMAT_VERSION,
        "package_published": published,
        "detail": refusal_message(error),
    });
    match serde_json::to_string_pretty(&status) {
        Ok(rendered) => println!("{rendered}"),
        // The refusal detail is already on the launch failure path, so a
        // serialization defect here must not replace the typed refusal with a
        // different one.
        Err(_) => eprintln!("{SERVICE_NAME}: ECXF export refusal detail could not be serialized"),
    }
}

/// Renders one typed exporter refusal as bounded launch-failure text.
///
/// The post-publication reconciliation refusal keeps its own wording because it
/// is the only outcome that reports an `ECXF/1` package which already exists
/// on disk; every other refusal is a refusal to publish.
fn refusal_message(error: &BackupError) -> String {
    match error {
        BackupError::PublishReconciliationRequired {
            export_id,
            package_path,
            reason,
        } => format!(
            "the ECXF/1 package for export {export_id} is published at {package_path} and requires reconciliation: {reason}"
        ),
        BackupError::UnobservedSourceMember { member } => format!(
            "the store owner did not observe the ECXF/1 source member {member}, so no package was published (I05-10)"
        ),
        BackupError::InconsistentBoundary => {
            "the observed source view cannot prove one coherent export boundary, so no ECXF/1 package was published (I05-10)".to_owned()
        }
        other => other.to_string(),
    }
}
