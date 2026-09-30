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
//! arguments and the exporter: every value the fence could carry comes from
//! [`capture_ecxf_source`](eliot_store_surreal_adapter::capture_ecxf_source),
//! the one real coherent read in the admitted vendor edge, which reads the
//! canonical member classes and the observed `state_fence`,
//! `schema_generation` and sequence counters inside one fixed
//! `BEGIN TRANSACTION`/`COMMIT` batch and projects those same rows onto the
//! store owners' typed `RevisionHead`, `OrderingHead`, `CanonicalEvent`,
//! `ProjectionPublicationRecord` and `WriteReceipt` values. This module
//! fabricates no fence member, parses no provider row into domain semantics, and
//! re-derives no digest: the only thing it forwards is the owner's own verdict.
//!
//! That capture is the whole of this store's evidence, which is why the export
//! cannot complete here. The vendor census captures no blob-residency member
//! class and no purge-ledger class, and the store bridge observes neither the
//! externally sealed Architecture and `NormativePair` identities nor a durable
//! source-side export receipt, so both the coherent view and the independent
//! blob-reachability read refuse rather than fill a fence member in with a
//! default. Both refusals are the store owner's own verdict read out of its
//! census, not this module's judgement.
//!
//! The `ECXF/1` package layout, the `ExportFence` and every residency,
//! checksum and integrity proof belong to `eliot-ecxf` and to the
//! `eliot-backup` exporter; neither is reimplemented, defaulted, pre-checked
//! or weakened here (I05-10 "Consistent export boundary", I05-13).
//!
//! Fail-closed is still the reachable outcome, and it is the required one, not
//! a stub — but the reason is now narrower and evidence-derived rather than
//! structural. The capture carries the typed revision heads, ordering heads,
//! events, projections and receipts the fence needs, read in the one transaction
//! that also observed the fence, plus the store's own recorded generations and
//! this adapter's own declared contract identity. What it still cannot carry is
//! the evidence no admitted column or class supplies: the source purge ledger,
//! blob residency reachability, the externally sealed Architecture and
//! `NormativePair` identities, and a source-side export receipt. The owner states
//! that in its own capture as a derived `missing_evidence` list, so the port
//! returns the typed [`BackupError::UnobservedSourceMember`] refusal naming the
//! first member the owner did not observe, and the separate blob-reachability
//! read refuses on its own census. Nothing is defaulted, no fence member is
//! filled in, and no package is written. This command reports that refusal and
//! exits nonzero; it never reports success over an incomplete view.

use std::path::{Path, PathBuf};

use eliot_backup::{
    BackupError, CanonicalRecord, CoherentSourceExport, EcxfExportRequest, EcxfSourceStore,
    export_ecxf_package,
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
    /// Operator-declared canonical request hash for this export's request
    /// identity. **There is no admitted request envelope for an ECXF export
    /// today**, so this is not a value read from an admission path; see the
    /// finding below.
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
        // observe. Nothing is defaulted and no fence member is filled in.
        //
        // A capture that declares no gap is a complete, coherent view observed
        // inside one store transaction, and it is projected onto the exporter's
        // source view below. The refusal above therefore remains the reachable
        // outcome for exactly the evidence the owner still lacks, and it is the
        // exporter's own `prove_coherent_boundary` that independently re-proves
        // everything projected here against the store's own rows.
        if let Some(member) = unobserved_member(&capture) {
            return Err(BackupError::UnobservedSourceMember { member });
        }
        Ok(CoherentSourceExport {
            completeness: capture.completeness,
            // The adapter's own declared contract identity: it is the component
            // that read the source, so it owns this pair.
            source_adapter: eliot_store_surreal_adapter::ADAPTER_NAME.to_owned(),
            source_adapter_version: eliot_store_surreal_adapter::ADAPTER_CONTRACT_VERSION
                .as_string(),
            // Both generations are the store's own recorded values, read from its
            // `schema_meta` row in the same transaction as the member batch.
            schema_generation: capture.schema_generation,
            store_generation: capture.store_generation,
            // Not observed by the store bridge, which is not the owner of the
            // Architecture source or of a `NormativePair` seal. Left absent
            // rather than filled with a build constant of this binary.
            architecture_source_digest: String::new(),
            normative_pair_identity_receipt_digest: String::new(),
            // The source store issues no durable ECXF export receipt of its own.
            export_receipt: String::new(),
            scope_id: Some(capture.scope_id),
            state_fence: capture.state_fence,
            revision_heads: capture.revision_heads,
            ordering_heads: capture.ordering_heads,
            // Derived from the observed `CanonicalEvent::event_ordinal` values —
            // the store's own monotonic commit ordinals, in the order the capture
            // sorted them. `prove_event_range_against_store` re-proves this
            // interval against those same events' validated ordinals.
            event_range: eliot_backup::EventRange {
                first_sequence: capture.events.first().map(|event| event.event_ordinal),
                last_sequence: capture.events.last().map(|event| event.event_ordinal),
                count: capture.events.len() as u64,
            },
            events: capture
                .events
                .iter()
                .map(canonical_event_record)
                .collect::<Result<Vec<_>, _>>()?,
            projections: capture
                .projections
                .iter()
                .map(|record| projection_record(record, ECXF_PROJECTION_RECORD_TYPE))
                .collect::<Result<Vec<_>, _>>()?,
            receipts: capture.receipts,
            blobs: Vec::new(),
            purge_ledger: Vec::new(),
            missing_features: capture
                .missing_evidence
                .iter()
                .map(|gap| format!("{gap:?}"))
                .collect(),
        })
    }

    /// Reads the source Store's own reachable residency-key set for this export.
    ///
    /// Issue #1871, A2 requires the fence's blob-reachability value to be
    /// checkable against the source Store. The only comparison available to the
    /// exporter is the one between what the Store says is reachable and what
    /// the delivered package carries, so this is a second store read rather
    /// than a field of the view that also carries the blobs: reading the
    /// residency keys out of the blobs being exported would make the export
    /// vouch for itself.
    ///
    /// The admitted vendor edge answers from the store's own census, and that
    /// census is what decides this. When it declares
    /// [`EcxfCaptureGap::BlobStoreEvidenceUnavailable`] no blob-residency member
    /// class is captured, so the store has no residency record to declare
    /// reachable and this refuses. When it declares none, a blob member class
    /// *is* captured but this module has no admitted decoder that projects such
    /// a row onto a residency-key digest — it parses no provider row into domain
    /// semantics — so it still refuses rather than deriving a digest here.
    ///
    /// Both outcomes are refusals derived from a real read of this store's own
    /// census, and neither returns a set. An empty set is not an honest answer:
    /// "no blob is reachable" and "this store cannot say" are different facts,
    /// and only the store owner can tell them apart. Returning an empty vector
    /// here would let a package ship a fence that declares an empty reachability
    /// set purely because nobody asked.
    async fn reachable_residency_keys(
        &self,
        request: &EcxfExportRequest,
    ) -> Result<Vec<String>, BackupError> {
        // One real read of this store's own capture census. Only the gap list is
        // consulted; no fence value is ever taken from this capture, so a second
        // consistent-read point cannot contribute to a published fence.
        let capture = capture_ecxf_source(self.adapter, request)
            .await
            .map_err(BackupError::Store)?;
        if capture
            .missing_evidence
            .contains(&EcxfCaptureGap::BlobStoreEvidenceUnavailable)
        {
            return Err(BackupError::UnobservedSourceMember {
                member: "reachable_blob_residency_keys",
            });
        }
        Err(BackupError::Interchange(
            "the admitted store census captures no blob-residency member class that this module \
             can project onto a residency-key digest, so the source Store cannot declare blob \
             reachability (I05-12, I05-13)"
                .to_owned(),
        ))
    }
}

/// Record-type label of one canonical event inside the `ECXF/1` event stream.
const ECXF_EVENT_RECORD_TYPE: &str = "canonical-event";

/// Record-type label of one projection publication inside the `ECXF/1`
/// projection stream.
const ECXF_PROJECTION_RECORD_TYPE: &str = "projection-record";

/// Projects one store-observed [`CanonicalEvent`] onto a canonical record.
///
/// The event's own canonical bytes are the payload, so the record digest
/// `eliot-ecxf` computes describes exactly the event the store holds. The event
/// was already validated by its own owner inside the capture transaction, and
/// `prove_event_range_against_store` decodes the projected payload back into
/// `CanonicalEvent` and runs that owner's `validate` again before any byte is
/// written.
fn canonical_event_record(
    event: &eliot_store_api::CanonicalEvent,
) -> Result<CanonicalRecord, BackupError> {
    let record_id = event.event_id.to_string();
    let payload = serde_json::to_value(event)
        .map_err(|error| BackupError::Serialization(error.to_string()))?;
    CanonicalRecord::new(ECXF_EVENT_RECORD_TYPE, record_id, payload)
}

/// Projects one store-observed [`ProjectionPublicationRecord`] onto a canonical
/// record, from the publication's own canonical bytes.
fn projection_record(
    record: &eliot_store_api::ProjectionPublicationRecord,
    record_type: &str,
) -> Result<CanonicalRecord, BackupError> {
    let record_id = record.publication_id.to_string();
    let payload = serde_json::to_value(record)
        .map_err(|error| BackupError::Serialization(error.to_string()))?;
    CanonicalRecord::new(record_type, record_id, payload)
}

/// Names the first source-view member the store owner declared it could not
/// observe, or `None` when the owner declared no gap at all.
///
/// The vocabulary is the adapter's own `EcxfCaptureGap`
/// (`crates/storage/eliot-store-surreal-adapter/src/backup_snapshot.rs`); this
<<<<<<< HEAD
/// maps each gap onto the static name of the already-existing
/// [`CoherentSourceExport`] field it leaves unobserved, and adds no second gap
/// type. Only `scope_id`, `store_generation`, `source_adapter` and `compression`
/// are also source-view or manifest members under those names; the rest are
/// named after the field the source view would have had to supply.
/// `BlobStoreEvidenceUnavailable` names `reachable_blob_residency_keys`, which
/// since issue #1871 A2 is no longer a source-view field at all: reachability is
/// read through its own port call, so the name identifies the member that read
/// cannot supply. That read refuses on the same gap under its own arm, and this
/// arm stays because the coherent view is refused before that read is reached.
/// `StoreResourceGenerationUnavailable` names `store_generation` rather than
/// `state_fence.resource_generation` because the fence's resource generation is
/// the generation relevant to one decision, not the store's own.
fn unobserved_member(capture: &EcxfSourceCapture) -> Option<&'static str> {
    match capture.missing_evidence.first() {
        Some(EcxfCaptureGap::RequestedScopeClosureUnproven) => Some("scope_id"),
        Some(EcxfCaptureGap::SourcePurgeLedgerUnavailable) => Some("purge_ledger"),
        Some(EcxfCaptureGap::BlobStoreEvidenceUnavailable) => Some("reachable_blob_residency_keys"),
        Some(EcxfCaptureGap::ExternalSourceIdentityEvidenceUnavailable) => {
            Some("architecture_source_digest")
        }
        Some(EcxfCaptureGap::SourceExportReceiptUnavailable) => Some("export_receipt"),
        None => None,
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
