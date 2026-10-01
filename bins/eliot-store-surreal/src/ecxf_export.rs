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
//! `schema_generation`, the store's own recorded adapter identity and sequence
//! counters inside one fixed `BEGIN TRANSACTION`/`COMMIT` batch, decides
//! requested-scope membership per class from those rows, and projects the same
//! rows onto the store owners' typed `RevisionHead`, `OrderingHead`,
//! `CanonicalEvent`, `ProjectionPublicationRecord` and `WriteReceipt` values.
//! This module
//! fabricates no fence member, parses no provider row into domain semantics, and
//! re-derives no digest: the only thing it forwards is the owner's own verdict.
//!
//! The `ECXF/1` package layout, the `ExportFence` and every residency,
//! checksum and integrity proof belong to `eliot-ecxf` and to the
//! `eliot-backup` exporter; neither is reimplemented, defaulted, pre-checked
//! or weakened here (I05-10 "Consistent export boundary", I05-13).
//!
//! Fail-closed is still the reachable outcome, and it is the required one, not
//! a stub — but the reason is now measured per member rather than structural.
//! The capture *does* carry the typed revision heads, ordering heads, events,
//! projections and receipts the fence needs, read in the one transaction that
//! also observed the fence, and it now also carries the store's OWN recorded
//! adapter identity (`schema_meta.compatible_bridge_range`) and a per-class
//! requested-scope membership verdict read from the same rows. What it still
//! cannot carry is the evidence no admitted column or class supplies: the
//! scope-to-record closure (only `write_receipt` rows record the admitted
//! `ScopeId`, so the other eight captured classes cannot be attributed), the
//! source purge ledger, blob residency reachability, the externally sealed
//! Architecture and `NormativePair` identities, a source-side export receipt, the
//! store's aggregate generation, this adapter's VERSION, and the export's
//! compression and encryption profiles. The owner states that in its own capture
//! as a derived `missing_evidence` list, so the port returns the typed
//! [`BackupError::UnobservedSourceMember`] refusal naming the first member the
//! owner did not observe. Nothing is defaulted, no fence member is filled in,
//! and no package is written. This command reports that refusal and exits
//! nonzero; it never reports success over an incomplete view.
//!
//! # WHY NO SUCCESS PROJECTION IS WRITTEN HERE (#2569)
//!
//! The refusal above is a measured property of the store's own evidence, not a
//! missing line of code in this module, and the distinction decides whether a
//! later change may close it. Every half is re-measured against `main`:
//!
//! * `observed_capture_gaps`
//!   (`crates/storage/eliot-store-surreal-adapter/src/backup_snapshot.rs`) is now
//!   entirely predicate-driven. Its first three entries are read from THIS
//!   transaction — `scope_closure_proven` over the observed rows,
//!   `captures_purge_ledger` and `observed_blob_reachability` over the census —
//!   and the remaining entries ask the schema owner through its own
//!   `declares_column_name` over the admitted baseline. No entry is appended
//!   unconditionally any more, and no entry is a hand-maintained column list.
//! * `capture_completeness` maps that derived list to
//!   `SnapshotCompleteness::Partial`, and `prove_coherent_boundary`
//!   (`crates/storage/eliot-backup/src/ecxf_export.rs`, which is where that
//!   proof now lives) refuses any view that is not complete *before* it reads a
//!   single member.
//!
//! So no assignment in `coherent_export` can return `Ok` on any input today.
//! That is the ceiling this slice reaches, and the remaining members are
//! enumerated exactly below rather than filled in.
//!
//! Writing the success projection anyway is the one move forbidden here, and it
//! would now also be an uncalled conversion — this repository forbids a helper
//! with no caller. Four members have no source anywhere in the store:
//! `store_generation` (the identifier does not appear in the adapter crate at
//! all), `architecture_source_digest`, `normative_pair_identity_receipt_digest`
//! and `export_receipt`. Three more have no captured class: `purge_ledger` (the
//! adapter's only `PurgeLedgerEntry` reader is on the restore path, a different
//! owner), `blobs` and `reachable_blob_residency_keys` — the last of which now
//! distinguishes a POSITIVELY OBSERVED empty live set from an absent
//! observation, so it can no longer be satisfied by an empty vector. Filling
//! any of them would mean an empty string, an empty vector or a synthesised
//! digest in a field `eliot-ecxf` then validates, which publishes a manifest
//! whose fence nobody observed. An earlier attempt at exactly that is preserved
//! on the unmerged branch `fix/1871-export-package-members-W3k5` (`c362f4cb0`),
//! where those members were `String::new()` and `Vec::new()`;
//! `fix/1871-export-reachable-command-W3k6` (`fb860c9a3`) withdrew the
//! projection again once the independent reachability read was found to refuse on
//! its own census. Neither branch is on `main` and neither is ported here.
//!
//! Closing this needs the missing evidence to be *observed and carried*, not
//! this module to project harder. One earlier version of this refusal
//! over-stated the case by claiming the store had no adapter identity of its own:
//! `ADAPTER_NAME` is a real declared value
//! (`crates/storage/eliot-store-surreal-adapter/src/config.rs`) and is
//! available. It is not enough on its own, because a build constant of the
//! running binary is not an observation of the source store. The identity IS now
//! observed, from the store's own `schema_meta.compatible_bridge_range`; the
//! VERSION has no source at all and stays a declared gap. The four members named
//! above are unchanged.
//!
//! # THE OBSERVED MEMBERS STILL DO NOT TYPE-CHECK AGAINST THE SOURCE VIEW
//!
//! Independent of the gap list, the capture and the exporter disagree on two
//! member types, so a projection is owed here before any refusal can lift.
//! `EcxfSourceCapture` carries `events: Vec<CanonicalEvent>` and
//! `projections: Vec<ProjectionPublicationRecord>`
//! (`crates/storage/eliot-store-surreal-adapter/src/backup_snapshot.rs`), while
//! `CoherentSourceExport` declares both as `Vec<CanonicalRecord>`
//! (`crates/storage/eliot-backup/src/ecxf_export.rs`). No owner performs that
//! conversion on `main`: `git grep` for a projection from `CanonicalEvent` to
//! `CanonicalRecord` returns only the *reverse* read in
//! `prove_event_range_against_store`
//! (`crates/storage/eliot-backup/src/ecxf_export.rs`), which decodes a
//! `CanonicalRecord` payload back into the store owner's `CanonicalEvent`.
//!
//! That reverse read does fix the forward projection's contract, so it is
//! recorded rather than guessed: a projected event record's payload must be the
//! canonical JSON of the owner's own `CanonicalEvent`, because that is the only
//! payload the exporter will accept back. Its `record_id` is the event identity
//! and its `record_type` is the adapter's own class token for that member
//! (`"canonical-event"`; the projection analogue is `"projection-record"`, both
//! in `backup_snapshot.rs`'s `CANONICAL_SOURCE_CLASSES`). Building that
//! projection is deliberately not done here while this arm still refuses: it
//! would have no caller, and an uncalled conversion is the shim this repository
//! forbids.

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
        // The capture already carries the typed fence members the source store
        // does hold — the revision and ordering heads, the events, the
        // projections and the receipts, all read inside the same transaction
        // that observed the fence. They are not projected onto
        // `CoherentSourceExport` here precisely because the members that remain
        // cannot be: every one of them would have to be a default, a zero, an
        // empty collection or a synthesized digest, and a fence member filled
        // that way is worse than the refusal, because it would publish a
        // manifest whose fence nobody observed.
        //
        // This is the measured blocker recorded in the module docs under
        // "WHY NO SUCCESS PROJECTION IS WRITTEN HERE": the owner's gap list is
        // non-empty on every admitted generation, so `capture_completeness`
        // yields `Partial` and `prove_coherent_boundary` refuses any such view
        // before reading a member. Every gap is now a PREDICATE — over the rows
        // this transaction read, over the census, or over the admitted baseline
        // through the schema owner's own whole-name matcher — so the refusal
        // names a genuinely unobserved member rather than a fixed list, and a
        // generation that supplies the evidence closes its gap with no edit
        // here. This arm therefore still cannot return `Ok` on any input, and
        // the members a projection would owe have no source in the store.
        // Closing it means observing and carrying that evidence, not filling
        // these fields in.
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
/// [`CoherentSourceExport`] field it leaves unobserved, and adds no second gap
/// type. Only `scope_id` and `store_generation` are also `ExportFence` members
/// under those names; the rest are source-view and manifest members
/// (`purge_ledger`, `reachable_blob_residency_keys`,
/// `architecture_source_digest`, `export_receipt`, `source_adapter_version`,
/// `compression`), which is why they are named after the field the source view
/// would have had to supply. `StoreResourceGenerationUnavailable` names
/// `store_generation` rather than `state_fence.resource_generation` because the
/// fence's resource generation is the generation relevant to one decision, not
/// the store's own. `SourceAdapterVersionUnavailable` names
/// `source_adapter_version` because the IDENTITY half is now observed — the
/// capture reads the store's own `schema_meta.compatible_bridge_range` — so the
/// gap covers exactly the version, which has no column anywhere.
///
/// The empty-list arm is the one case this mapping cannot describe. An owner
/// that declares no gap has, by its own `capture_completeness` derivation, also
/// declared `SnapshotCompleteness::Complete` — the two fields are derived from
/// the same list and are deliberately not independent. Naming a member there
/// would report a refusal over an owner verdict that says the opposite, so the
/// arm names `completeness`, the one source-view field whose counterpart in the
/// fence is `consistent`. Reaching it requires an owner that closes all eight
/// gaps; today four of them have no column in any baseline this store ships and
/// the scope closure is unprovable for eight of the nine captured classes.
fn unobserved_member(capture: &EcxfSourceCapture) -> &'static str {
    match capture.missing_evidence.first() {
        Some(EcxfCaptureGap::RequestedScopeClosureUnproven) => "scope_id",
        Some(EcxfCaptureGap::SourcePurgeLedgerUnavailable) => "purge_ledger",
        Some(EcxfCaptureGap::BlobStoreEvidenceUnavailable) => "reachable_blob_residency_keys",
        Some(EcxfCaptureGap::ExternalSourceIdentityEvidenceUnavailable) => {
            "architecture_source_digest"
        }
        Some(EcxfCaptureGap::SourceExportReceiptUnavailable) => "export_receipt",
        Some(EcxfCaptureGap::StoreResourceGenerationUnavailable) => "store_generation",
        Some(EcxfCaptureGap::SourceAdapterVersionUnavailable) => "source_adapter_version",
        Some(EcxfCaptureGap::ExportProfileUnavailable) => "compression",
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
