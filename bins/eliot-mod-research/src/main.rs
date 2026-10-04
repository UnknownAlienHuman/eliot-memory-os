#![forbid(unsafe_code)]

//! One-shot bounded research-provider operation.
//!
//! This binary performs exactly one admitted provider operation and then
//! exits. It is a composition root and nothing more: admitted-material
//! decoding, authenticated contract construction, dependency wiring, one
//! bounded lifecycle, and a terminal receipt projection. It owns no task,
//! policy, evidence admission, canonical write, or finish, and it never reads
//! an executable path, a pipe, or a peer identity from an environment variable.
//!
//! Fail-closed shape: when the authenticated Kernel front door is unreachable,
//! when no Kernel-issued admitted material was delivered, or when a reply does
//! not verify against this process's own dispatch, there is no admission. In
//! that one honest case the process emits `KERNEL_ADMISSION_REQUIRED` and exits
//! 78. Every other outcome — including provider failure — is reported as a
//! typed coverage gap with its exact I7.20 reason code and a terminal receipt,
//! because a provider failure degrades only acquisition coverage, never the
//! Kernel, the Governor, or independent work.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::Arc;

use eliot_contracts::CapabilityCellProof;
use eliot_kernel_service::{RESEARCH_PROVIDER_DISPATCH_OPERATION, ResearchProviderDispatch};
use eliot_mod_research::AdmittedResearchBridge;
use eliot_mod_research::admission::ProviderAdmission;
use eliot_mod_research::dispatch_authority::{AdmittedRequestPort, ProviderEvidenceRecorder};
use eliot_mod_research::dispatched_material::{AdmittedOperation, read_admitted_material};
use eliot_mod_research::evidence::{
    CancellationEvidence, OwnerReconciliationAttempt, ProviderExecutionReceipt,
    ReconciliationEvidence,
};
use eliot_mod_research::execution::ProviderBridge;
use eliot_mod_research::kernel_client::{ResearchKernelClient, ResearchKernelClientError};
use eliot_mod_research::{
    AcquisitionCoverageDegradation, BridgeIdentity, CancellationOutcome, EvidenceObservation,
    Obligation, RESEARCH_SOURCE_UNAVAILABLE, RawProviderEvidence, ResearchDispatchAuthority,
    SubmissionRecord, acquisition_coverage_degradation, compose_admitted, project_admitted_inquiry,
    resolve_admitted_cell,
};

/// Stable code prefixed to the bounded report of follow-up obligations the
/// primary failure could not discharge.
///
/// This is one extra line on the same evidence stream, not a second terminal
/// event: the receipt's own outcome and reason code are unchanged, and this
/// names only the obligations that failed alongside the primary cause.
const UNDISCHARGED_OBLIGATIONS: &str = "UNDISCHARGED_OBLIGATIONS";

/// Returns the stable wire name of one bounded follow-up obligation.
const fn obligation_name(obligation: Obligation) -> &'static str {
    match obligation {
        Obligation::Cancellation => "cancellation",
        Obligation::StreamReadback => "stream_readback",
    }
}
use eliot_process::{Generation, OperationId};
use eliot_process_executor::WindowsProcessExecutor;
use eliot_research_exchange_api::DisclosureClass;
use eliot_researcher::Researcher;

const SERVICE_NAME: &str = "eliot-mod-research";
const PROTOCOL_VERSION: &str = "eliot.research.provider.v1";
const OPERATION: &str = "eliot.research.provider.execute";
const KERNEL_ADMISSION_REQUIRED: &str = "KERNEL_ADMISSION_REQUIRED";
const EXIT_KERNEL_ADMISSION_REQUIRED: i32 = 78;
/// Exit code for a bounded operation that ran and produced a terminal receipt.
/// Provider degradation is an acquisition-coverage outcome, not a process
/// failure, so it never reuses the admission-required code.
const EXIT_OPERATION_RECEIPTED: i32 = 0;
/// Exit code for a bounded operation that ran but degraded acquisition
/// coverage. The typed gap and the retained evidence are on stderr.
const EXIT_OPERATION_DEGRADED: i32 = 1;

fn main() {
    match run() {
        Ok(receipt) => {
            // The receipt is the product of this one-shot operation: route,
            // privacy, budget, deadline, raw evidence, cancellation and the
            // provider outcome all travel on stdout so the caller receives
            // evidence rather than a bare exit code.
            let _ = writeln!(io::stdout(), "{receipt}");
            std::process::exit(EXIT_OPERATION_RECEIPTED);
        }
        Err(Failure::NoAdmission(detail)) => {
            let _ = writeln!(io::stderr(), "{}: {detail}", admission_required_message());
            std::process::exit(EXIT_KERNEL_ADMISSION_REQUIRED);
        }
        Err(Failure::Degraded(degradation, receipt)) => {
            // A provider failure is not a Researcher semantic failure and not a
            // fabricated empty result: it is a typed coverage gap carrying the
            // exact stable code, the typed coverage-gap kind the crate's own
            // conversion produced, and the evidence that was retained. The exit
            // code is a distinct degraded disposition, so nothing that reads
            // this line can mistake the run for a process failure.
            let _ = writeln!(
                io::stderr(),
                "{RESEARCH_SOURCE_UNAVAILABLE}: reason={} coverage_gap={:?} receipt={receipt}",
                // A degraded exit always has a reason. `None` here would mean a
                // completed run reached the degraded disposition, and rendering
                // it as a bare `reason=` would hide that contradiction instead of
                // showing it.
                receipt.reason_code.unwrap_or("none"),
                degradation.coverage_gap,
            );
            std::process::exit(EXIT_OPERATION_DEGRADED);
        }
    }
}

/// Typed one-shot failure.
///
/// The degraded variant is boxed so the common no-admission path stays small
/// and the typed failure can be returned by value from every step without a
/// large-error allocation.
enum Failure {
    /// No admission exists: the front door is unreachable, no admitted
    /// material was delivered, or a reply did not verify against this
    /// process's own dispatch.
    NoAdmission(String),
    /// The operation ran and degraded acquisition coverage only.
    ///
    /// The typed coverage degradation is carried beside the receipt rather than
    /// being implied by this variant's name, so a degraded exit cannot be
    /// produced without the classification that says which acquisition gap
    /// occurred — and, per `A13.11`, no Kernel, Governor or independent work
    /// state is represented here to be touched.
    Degraded(
        AcquisitionCoverageDegradation,
        Box<ProviderExecutionReceipt>,
    ),
}

/// Runs the one bounded operation.
///
/// # Errors
///
/// Returns [`Failure::NoAdmission`] when the Kernel front door is
/// unreachable, no admitted material was delivered, or a reply does not
/// verify; and [`Failure::Degraded`] when the operation ran but the provider
/// degraded acquisition coverage.
fn run() -> Result<String, Failure> {
    // 1. Authenticated contract construction. A closed or unverifiable front
    //    door means no admission exists at all.
    let mut client = ResearchKernelClient::load()
        .map_err(|error| Failure::NoAdmission(format!("front door unavailable: {error}")))?;
    let live_epoch = client
        .live_authority_epoch()
        .map_err(|error| Failure::NoAdmission(format!("live authority unknown: {error}")))?;

    // 2. Admitted material, re-proved against the live authority. Absent or
    //    invalid material is a typed denial, never a fabricated empty
    //    operation and never a default identity.
    let admitted = read_admitted_material(&live_epoch)
        .map_err(|error| Failure::NoAdmission(format!("admitted material refused: {error}")))?
        .ok_or_else(|| {
            Failure::NoAdmission("no Kernel-issued admitted material was delivered".to_owned())
        })?;

    // 3. The Kernel-issued dispatch receipt is the admission. The client
    //    re-verifies every reply against this process's own dispatch before
    //    the receipt can be used, and the local admission is built only from
    //    fields that receipt echoes.
    let client_receipt = client
        .dispatch(&admitted.dispatch, RESEARCH_PROVIDER_DISPATCH_OPERATION)
        .map_err(|error| Failure::NoAdmission(format!("kernel dispatch: {error}")))?;
    let (admission, capability_cell_proof) = admit(&admitted, &client_receipt)?;

    // 4. Dependency wiring. The dispatch authority is ephemeral and in-process;
    //    its key never crosses the front-door boundary.
    let authority = Arc::new(
        ResearchDispatchAuthority::new()
            .map_err(|error| Failure::NoAdmission(format!("dispatch authority: {error}")))?,
    );
    let sink = Arc::new(ProviderEvidenceRecorder::new());
    let executor = Arc::new(WindowsProcessExecutor::new(authority.clone()));
    let port = Arc::new(AdmittedRequestPort::new(
        authority,
        admitted.dispatch.clone(),
        admitted.request.clone(),
        eliot_mod_research::dispatch_authority::unix_ms(),
    ));
    let runner = ProviderBridge::new(executor, port, sink.clone());

    // 5. One bounded operation through the shared governed process contour.
    let mut researcher: Researcher<_> = compose_admitted(runner, admission.clone());
    let submitted = researcher.submit_query(admitted.request.clone());
    let records = sink
        .records()
        .map_err(|error| Failure::NoAdmission(format!("evidence custody: {error}")))?;
    let (mut bridge, _exchange) = researcher.into_exchange().into_parts();

    // A `submit` that returned `Ok` proves only that the Rust call finished:
    // `ProviderBridge::execute` returns `Ok` for every terminal state it could
    // classify, including a crash, a cancellation, a timeout and an unknown
    // outcome. The outcome that was computed inside the bridge is therefore
    // read back inside the reporting half and carried verbatim; nothing on this
    // path is allowed to relabel a run as a completed acquisition.
    if let Ok(job) = submitted {
        return report_classified_operation(
            &client,
            &admitted,
            &client_receipt,
            &admission,
            &capability_cell_proof,
            &mut bridge,
            records,
            job.job_id,
        );
    }
    report_failed_operation(
        &mut client,
        &admitted,
        &client_receipt,
        &admission,
        &capability_cell_proof,
        &mut bridge,
        records,
    )
}

/// Reports the terminal receipt and governance view of a classified attempt.
///
/// `submit` returning `Ok` proves only that the Rust call finished, so the
/// retained classification is read back from the bridge rather than inferred
/// from the exit. A completed acquisition and a degraded one are decided from
/// the same two values — the typed outcome and the typed degradation this crate
/// builds from it — and the two halves disagreeing is reported as a defect of
/// this process rather than resolved in favour of whichever one is convenient.
///
/// A completed run carries no reason code and no acquisition gap: I7.20 reason
/// codes describe non-success dispositions, so `outcome=Completed
/// reason=RUNTIME_FAILED` was a contradiction on the receipt of a run that
/// exited zero. A non-success run always carries both, because a receipt with no
/// reason would be an unexplained failure.
#[allow(clippy::too_many_arguments)]
fn report_classified_operation(
    client: &ResearchKernelClient,
    admitted: &AdmittedOperation,
    client_receipt: &eliot_kernel_service::ResearchProviderDispatchReceipt,
    admission: &ProviderAdmission,
    capability_cell_proof: &CapabilityCellProof,
    bridge: &mut AdmittedResearchBridge,
    records: Vec<eliot_mod_research::ProviderEvidenceRecord>,
    job_id: String,
) -> Result<String, Failure> {
    let outcome = bridge.last_outcome().map_or(
        eliot_mod_research::ProviderOutcome::Unknown,
        eliot_mod_research::SubmittedOutcome::provider_outcome,
    );
    let cancellation = bridge.last_cancellation();
    // A positive terminal outcome needs no owner reconciliation; anything else
    // is reconciled by the stable operation identity before it is reported, so
    // the receipt distinguishes an owner-attested classification from a local
    // one.
    let reconciliation = if outcome == eliot_mod_research::ProviderOutcome::Completed {
        ReconciliationEvidence::not_required()
    } else {
        reconcile_with_owner(client, admitted, cancellation, outcome)
    };
    let reason_code = terminal_reason_code(outcome, &reconciliation, cancellation);
    let cancellation_outcome = cancellation.map_or(CancellationOutcome::NotAttempted, |receipt| {
        CancellationOutcome::Confirmed(Box::new(receipt.clone()))
    });
    // The retained terminal classification is absent on this path because
    // `execute` left no `BridgeError` behind; the crate's own typed conversion
    // still produces both the reason code the receipt carries and the degraded
    // disposition this run exits with, so neither is a second, privately chosen
    // classification of the same run. A completed run has no degradation at all:
    // `outcome_degradation` is `None` for it, so a success can never be given an
    // acquisition gap to report.
    let degradation =
        eliot_mod_research::TerminalFailure::outcome_degradation(outcome, cancellation)
            .map(|terminal| acquisition_coverage_degradation(Some(&terminal)));
    // A classified terminal run reached `finish_terminal`, which reads the
    // executor's captured streams back before it classifies, so the retained
    // evidence here was genuinely observed rather than inferred.
    let raw = bridge.last_evidence().cloned();
    let observation = raw
        .as_ref()
        .map_or(EvidenceObservation::NotAttempted, |evidence| {
            EvidenceObservation::Observed(Box::new(evidence.clone()))
        });
    let receipt = terminal_receipt(
        admitted,
        client_receipt,
        admission,
        capability_cell_proof,
        raw.as_ref(),
        &observation,
        cancellation.cloned(),
        cancellation_outcome,
        Vec::new(),
        bridge.last_submission(),
        bridge.last_provider_job_ref().cloned(),
        Some(job_id),
        outcome,
        bridge.last_observed_disposition(),
        reason_code,
        records,
        reconciliation,
    );
    report_admitted_inquiry(
        &admitted.request,
        admission,
        &receipt,
        bridge.last_failure(),
        bridge.last_retained_stdout(),
    );
    match (outcome, degradation) {
        (eliot_mod_research::ProviderOutcome::Completed, None) => Ok(receipt.to_string()),
        (eliot_mod_research::ProviderOutcome::Completed, Some(_)) => Err(Failure::NoAdmission(
            "a completed acquisition reported an acquisition degradation".to_owned(),
        )),
        (_, Some(degradation)) => Err(Failure::Degraded(degradation, Box::new(receipt))),
        (_, None) => Err(Failure::NoAdmission(
            "a non-success terminal outcome reported no acquisition degradation".to_owned(),
        )),
    }
}

/// Reports the terminal receipt and governance view of an attempt that failed.
///
/// The bridge retains the typed terminal classification, the raw evidence
/// materialized before the failure, and the cancellation receipt. A failure
/// that never reached the executor is still an acquisition gap, never a
/// Researcher semantic failure.
///
/// The conversion from that retained classification into the typed
/// acquisition-coverage degradation is the crate's one named conversion, not
/// an arm of this function. The outcome and the reason code the receipt
/// carries therefore cannot be a second, privately chosen classification of
/// the same failure, and the degraded disposition this run exits with is
/// built from that same record.
///
/// The stream-readback state travels with the failure rather than being
/// re-derived from the presence of an evidence record, so a readback that never
/// answered is never reported as a stream that was read and was empty.
#[allow(clippy::too_many_arguments)]
fn report_failed_operation(
    client: &mut ResearchKernelClient,
    admitted: &AdmittedOperation,
    client_receipt: &eliot_kernel_service::ResearchProviderDispatchReceipt,
    admission: &ProviderAdmission,
    capability_cell_proof: &CapabilityCellProof,
    bridge: &mut AdmittedResearchBridge,
    records: Vec<eliot_mod_research::ProviderEvidenceRecord>,
) -> Result<String, Failure> {
    let failure = bridge.last_failure();
    let degradation = acquisition_coverage_degradation(failure);
    //
    // A non-success terminal state is reconciled against the owner that holds
    // the operation before it is reported, so the receipt distinguishes an
    // owner-attested classification from a local guess.
    let outcome = degradation.outcome;
    let cancellation = bridge.last_cancellation();
    let reconciliation = reconcile_with_owner(client, admitted, cancellation, outcome);
    let reason_code = terminal_reason_code(outcome, &reconciliation, cancellation);
    let observation = failure.map_or(EvidenceObservation::NotAttempted, |terminal| {
        terminal.evidence_observation.clone()
    });
    let cancellation_outcome = failure.map_or(CancellationOutcome::NotAttempted, |terminal| {
        terminal.cancellation_outcome.clone()
    });
    let undischarged = failure.map_or_else(Vec::new, |terminal| terminal.undischarged.clone());
    let receipt = terminal_receipt(
        admitted,
        client_receipt,
        admission,
        capability_cell_proof,
        bridge.last_evidence(),
        &observation,
        bridge.last_cancellation().cloned(),
        cancellation_outcome,
        undischarged,
        bridge.last_submission(),
        bridge.last_provider_job_ref().cloned(),
        None,
        outcome,
        bridge.last_observed_disposition(),
        reason_code,
        records,
        reconciliation,
    );
    report_admitted_inquiry(
        &admitted.request,
        admission,
        &receipt,
        failure,
        bridge.last_retained_stdout(),
    );
    // The bounded secondary obligations and the stream-readback state are
    // reported so the primary cause on the receipt is never the whole story: a
    // timeout whose cancellation or readback never answered says so.
    report_bounded_gaps(failure, bridge.last_operation_id());
    Err(Failure::Degraded(degradation, Box::new(receipt)))
}

/// Reports the bounded follow-up gaps a primary failure left behind.
///
/// This adds no terminal event: the receipt already carries the primary cause
/// and its classification, and this line only names what the primary cause
/// could not discharge plus the exact operation identity that a possibly-started
/// attempt must be resolved against. Nothing is emitted when there is nothing
/// to report, so a clean run's stream is unchanged.
fn report_bounded_gaps(
    failure: Option<&eliot_mod_research::TerminalFailure>,
    operation_id: Option<&str>,
) {
    let Some(failure) = failure else {
        return;
    };
    let readback = match &failure.evidence_observation {
        EvidenceObservation::NotAttempted => "not_attempted",
        EvidenceObservation::Unobserved => "unobserved",
        EvidenceObservation::Observed(_) => "observed",
    };
    let obligations = failure
        .undischarged
        .iter()
        .copied()
        .map(obligation_name)
        .collect::<Vec<_>>()
        .join(",");
    let cancellation_attempted = !matches!(
        &failure.cancellation_outcome,
        CancellationOutcome::NotAttempted
    );
    let cancellation_confirmed = matches!(
        &failure.cancellation_outcome,
        CancellationOutcome::Confirmed(_)
    );
    if failure.undischarged.is_empty() && !cancellation_attempted {
        return;
    }
    let _ = writeln!(
        io::stderr(),
        "{}: operation={} reason={} readback={readback} cancel_attempted={} \
         cancel_confirmed={} undischarged={}",
        UNDISCHARGED_OBLIGATIONS,
        operation_id.unwrap_or("none"),
        failure.reason_code,
        cancellation_attempted,
        cancellation_confirmed,
        if obligations.is_empty() {
            "none"
        } else {
            &obligations
        },
    );
}

/// Reports the `R6` inquiry-governance view of the operation this run performed.
///
/// The provider receipt on stdout stays this process's product and is not
/// rewritten. The `R6` view is the second half of the same evidence stream: it
/// states the versioned inquiry profile with its selected grade and lane, the
/// source-admissibility disposition of the retained material, the coverage
/// receipt with its declared denominator kind, and the terminal typed inquiry
/// disposition bound to the profile, portfolio, manifest and State Fence. A
/// submission acknowledgement and a provider exit code are not inquiry outcomes,
/// so this view is what distinguishes an answered inquiry from a completed
/// process, and every non-answering outcome keeps its explicit unknown, narrower
/// claim and next probe.
///
/// A projection that cannot be built is reported as a typed gap on the same
/// stream. It never becomes a closed inquiry, never rewrites the receipt, and
/// never changes this process's exit code: the operation's own truth is the
/// provider receipt, and the governance view is a projection of it.
///
/// `failure` is the bridge's retained typed terminal classification. It carries
/// the acquisition coverage gap this run suffered, so the dependent inquiry
/// records the named `I21.11` outcome (`RESEARCH_SOURCE_UNAVAILABLE` or
/// `INCOMPLETE_COVERAGE`) and keeps its preserved explicit unknown and next
/// probe instead of reporting a generic acquisition code.
fn report_admitted_inquiry(
    request: &eliot_research_exchange_api::ResearchQueryRequest,
    admission: &ProviderAdmission,
    receipt: &ProviderExecutionReceipt,
    failure: Option<&eliot_mod_research::TerminalFailure>,
    retained_stdout: Option<&[u8]>,
) {
    match project_admitted_inquiry(request, admission, receipt, failure, retained_stdout) {
        Ok(inquiry) => {
            // The release gate is asked here, on the real run, and its answer is
            // published beside the governance view. Before this the run rendered
            // the record and stopped: `public_class()`, `dimensions_complete()`
            // and `is_complete()` existed with no caller, so the audit existed and
            // nothing on any production path ever read it. `report_admitted_inquiry`
            // is a renderer, not an authority — it does not refuse the run and does
            // not change this process's exit code — but the gate answer it prints is
            // the one a release consumer has to see before it promotes anything.
            //
            // A2: the delivered text is the wording this run actually publishes,
            // read off each audited claim's own `released_statement` — the exact
            // wording that was judged. A renderer that reworded a claim between the
            // audit and this print would hand the gate text that disagrees with
            // what the audit saw, and the gate refuses it. Building the map here
            // (rather than passing an empty one) is what makes the post-audit
            // material-edit check fire on the real run instead of existing only as
            // an uncalled method.
            let delivered: BTreeMap<String, String> = inquiry
                .claim_audits
                .iter()
                .map(|audit| (audit.claim_id.clone(), audit.released_statement.clone()))
                .collect();
            let gate = match inquiry.release_gate(&delivered) {
                Ok(()) => eliot_mod_research::RELEASE_GATE_ADMITTED.to_owned(),
                Err(error) => format!("{}:{error}", eliot_mod_research::RELEASE_GATE_BLOCKED),
            };
            let _ = writeln!(
                io::stderr(),
                "{}: {inquiry} release_gate={gate}",
                eliot_mod_research::INQUIRY_GOVERNANCE_VIEW
            );
        }
        Err(error) => {
            let _ = writeln!(
                io::stderr(),
                "{}: reason={error}",
                eliot_mod_research::INQUIRY_GOVERNANCE_REFUSED
            );
        }
    }
}

/// Seals one verified Kernel dispatch receipt into a local admission and binds
/// it to the generated #13 capability-cell record.
///
/// The receipt was already re-proved against the presented dispatch by the
/// client's identity and admission checks on the dispatch path. The local
/// admission is built only from fields that
/// receipt echoes, so a receipt can never widen the executable, generation,
/// epoch, fence, privacy class, budget, or deadline beyond what the Kernel
/// admitted under the live authority; and because it is assembled from those
/// two independently delivered records, it is then re-bound to the admitted
/// operation by [`ProviderAdmission::bind_admitted_dispatch`], which compares
/// every fact the exchange request does not carry against the Kernel's own
/// attested content by value.
///
/// The returned [`CapabilityCellProof`] is #13's proof surface for the generated
/// capability cell the sealed `module_id` names. It is produced here, before any
/// port, authority, or executor exists, and travels onto the terminal receipt so
/// the run states which compiled capability cell admitted it and which proof
/// entrypoint is independently invokable for that cell.
///
/// # Errors
///
/// Returns [`Failure::NoAdmission`] when the admitted material cannot be turned
/// into a local admission, when the sealed record is not the record of the
/// dispatch that receipt was issued for, or when the sealed Module/Capability
/// Registry reference names no declared cell with a current proof surface.
fn admit(
    admitted: &AdmittedOperation,
    client_receipt: &eliot_kernel_service::ResearchProviderDispatchReceipt,
) -> Result<(ProviderAdmission, CapabilityCellProof), Failure> {
    let dispatch: &ResearchProviderDispatch = &admitted.dispatch;
    let bridge = BridgeIdentity::new(
        dispatch.executable_path.clone(),
        dispatch.executable_sha256.clone(),
    )
    .map_err(|error| Failure::NoAdmission(format!("bridge identity: {error}")))?;
    let generation = Generation::new(dispatch.process_generation)
        .map_err(|error| Failure::NoAdmission(format!("process generation: {error}")))?;
    // The privacy class is re-derived from the sealed dispatch's own closed
    // wire vocabulary; an unknown spelling is a typed denial, never a default
    // that could widen disclosure.
    let disclosure = match dispatch.disclosure.as_str() {
        "Private" => DisclosureClass::Private,
        "ProjectBound" => DisclosureClass::ProjectBound,
        "ExportableRedacted" => DisclosureClass::ExportableRedacted,
        "Public" => DisclosureClass::Public,
        other => {
            return Err(Failure::NoAdmission(format!(
                "admitted privacy class is not the closed wire vocabulary: {other}"
            )));
        }
    };
    let admission = ProviderAdmission::new(
        bridge,
        dispatch.config_digest.clone(),
        dispatch.protocol_digest.clone(),
        dispatch.module_id.clone(),
        dispatch.module_generation_id.clone(),
        generation,
        client_receipt.admitted_authority_epoch.clone(),
        client_receipt.admitted_fence.clone(),
        disclosure,
        dispatch.budget_units,
        dispatch.deadline_ms,
        dispatch.protocol_revision,
        dispatch.required_schema.clone(),
        dispatch.bridge_generation.clone(),
        OperationId::new(dispatch.operation_id.clone())
            .map_err(|error| Failure::NoAdmission(format!("operation identity: {error}")))?,
        dispatch.cancellation_id.clone(),
        dispatch.inquiry_digest.clone(),
        dispatch.denominator_digest.clone(),
        admitted.request.coverage_goal.clone(),
    )
    .map_err(|error| Failure::NoAdmission(format!("admission refused: {}", error.reason())))?;
    // The record above is assembled from two independently delivered values —
    // the presented dispatch and the sealed Kernel receipt — so it is bound to
    // the admitted operation here rather than assumed to be. Every fact the
    // record carries that the exchange request does not (artifact, config and
    // protocol digests, Module/Capability Registry references, process
    // generation, Authority Epoch, State Fence, privacy/data class, budget and
    // deadline, the operation identity and the cancellation identity) is
    // compared by value against the Kernel's own attested content through the
    // wire owner's `verify_echo` and the field-wise comparison beside it. A
    // record built from one dispatch and a receipt for another is refused here,
    // before any port, authority, or executor is constructed.
    //
    // This is the admission-only re-proof, and it stays admission-only: an
    // admission can never be sealed from a non-success receipt. That is why the
    // client's control-operation path returns those receipts intact instead —
    // neither this call nor any other turns a refusal into an admission.
    admission
        .bind_admitted_dispatch(dispatch, client_receipt)
        .map_err(|error| Failure::NoAdmission(format!("admission refused: {}", error.reason())))?;
    // The Module/Capability Registry reference the record seals is bound to the
    // generated #13 cell record before any port, authority, or executor exists,
    // and the resolved record's own proof surface is returned so the run can
    // receipt which compiled capability cell answered it. A Kernel that
    // admitted a module id this package does not declare, or a declared cell
    // whose proof surface is stale, is refused here rather than after a provider
    // process was started: there is no executor contact for a cell this process
    // cannot name.
    let capability_cell_proof = resolve_admitted_cell(&admission)
        .map_err(|error| Failure::NoAdmission(format!("admission refused: {}", error.reason())))?;
    Ok((admission, capability_cell_proof))
}

/// Asks the Kernel owner what it still holds for this operation, and records
/// exactly what it answered.
///
/// This process reached a terminal state it cannot classify on its own evidence
/// alone. Issue #24 requires that outcome to be reconciled "by stable
/// operation identity" against the owner rather than asserted locally, and that
/// a cancellation whose effect is unproven stays `CANCELLATION_UNCONFIRMED`
/// instead of decaying into a generic unknown. The owner is asked through the
/// existing authenticated Kernel client; no new wire, port or side door is
/// introduced, and the owner's closed disposition vocabulary is preserved
/// verbatim.
///
/// Three questions are asked, each only where it is meaningful:
/// - `status` always, because it is the owner's answer to "do you still hold
///   this operation, and what class is it in";
/// - `cancel` only when a cancellation was actually issued and its receipt
///   could not prove no effect, so a fresh control request never manufactures a
///   cancellation that the run did not perform;
/// - `reconcile` only while the local outcome is still unknown, because that is
///   the only state the owner is being asked to reconcile.
///
/// A control operation the owner does not serve is answered honestly as
/// `Unavailable`/`CAPABILITY_UNAVAILABLE` and recorded as such: an absent
/// confirmation lowers a claim, it never raises one. Transport failures are
/// recorded as transport failures and never rendered as a disposition.
fn reconcile_with_owner(
    client: &ResearchKernelClient,
    admitted: &AdmittedOperation,
    cancellation: Option<&CancellationEvidence>,
    outcome: eliot_mod_research::ProviderOutcome,
) -> ReconciliationEvidence {
    let mut attempts = Vec::new();
    let dispatch = &admitted.dispatch;

    ask_control_operation(
        &mut attempts,
        client,
        eliot_kernel_service::RESEARCH_PROVIDER_STATUS_OPERATION,
        |client| client.status(dispatch),
    );
    if cancellation.is_some_and(|receipt| !receipt.no_effect_proven) {
        ask_control_operation(
            &mut attempts,
            client,
            eliot_kernel_service::RESEARCH_PROVIDER_CANCEL_OPERATION,
            |client| client.cancel(dispatch),
        );
    }
    if outcome == eliot_mod_research::ProviderOutcome::Unknown {
        ask_control_operation(
            &mut attempts,
            client,
            eliot_kernel_service::RESEARCH_PROVIDER_RECONCILE_OPERATION,
            |client| client.reconcile(dispatch),
        );
    }
    ReconciliationEvidence { attempts }
}

/// Returns the exact I7.20 reason code one terminal outcome is reported with.
///
/// `CANCELLATION_UNCONFIRMED` is reachable only when a cancellation WAS issued
/// whose no-effect is unproven and whose owner confirmation is absent: that is
/// the single condition the research-provider vocabulary's own code names, and
/// `leaves_cancellation_unconfirmed` is what proves it. A run that never
/// cancelled anything — a plain unknown outcome, a crash, a protocol
/// violation, a policy refusal — therefore keeps the reason code its own
/// classification already produced, instead of having its real cause
/// overwritten with a cancellation that never happened.
///
/// A completed run has no failure reason at all and reports `None`. It used to
/// report `RUNTIME_FAILED`, which put an observable
/// `outcome=Completed reason=RUNTIME_FAILED` contradiction on the receipt of a
/// run that exited zero with proven tree closure. I7.20 reason codes describe
/// non-success dispositions, so a success cannot carry one: either the code is
/// absent or it is claiming something false about a run that succeeded.
fn terminal_reason_code(
    outcome: eliot_mod_research::ProviderOutcome,
    reconciliation: &ReconciliationEvidence,
    cancellation: Option<&CancellationEvidence>,
) -> Option<&'static str> {
    if outcome == eliot_mod_research::ProviderOutcome::Completed {
        return None;
    }
    if reconciliation.leaves_cancellation_unconfirmed(cancellation) {
        return Some(eliot_kernel_service::REASON_CANCELLATION_UNCONFIRMED);
    }
    // `outcome_degradation` is `None` only for a completed acquisition, which
    // returned above, so this is always the retained non-success record rather
    // than a failure invented for a success. The `None` arm is still typed and
    // reported rather than defaulted: substituting a code here would put a
    // reason on a run that has none.
    match eliot_mod_research::TerminalFailure::outcome_degradation(outcome, cancellation) {
        Some(terminal) => Some(acquisition_coverage_degradation(Some(&terminal)).reason_code),
        // Unreachable for the non-success outcomes that reach here, because
        // `outcome_degradation` declines only `Completed` and that returned
        // above. Naming the code rather than panicking keeps the function total
        // if that pairing ever changes: an unresolved effect is the honest
        // reading, and it is still a real code rather than a reason invented for
        // a run that has none.
        None => Some(eliot_kernel_service::REASON_UNKNOWN_OUTCOME),
    }
}

/// Sends one control operation and records the owner's answer verbatim.
///
/// The owner's disposition is never rewritten and a transport refusal never
/// becomes a disposition, so the receipt can always be read as "this is what
/// the owner said, or that it was never reached".
fn ask_control_operation(
    attempts: &mut Vec<OwnerReconciliationAttempt>,
    client: &ResearchKernelClient,
    operation: &'static str,
    send: impl FnOnce(
        &ResearchKernelClient,
    ) -> Result<
        eliot_kernel_service::ResearchProviderDispatchReceipt,
        ResearchKernelClientError,
    >,
) {
    attempts.push(match send(client) {
        Ok(receipt) => OwnerReconciliationAttempt::answered(operation, &receipt),
        Err(error) => OwnerReconciliationAttempt::untransportable(operation, error.to_string()),
    });
}

/// Builds the terminal receipt for one bounded operation.
///
/// `observation` is the stream-readback state and `undischarged` the bounded
/// follow-up obligations, so the receipt can state a stream gap as a gap. When
/// the readback was never attempted or never answered, `raw` is absent and the
/// receipt records that absence through `observation`; it must not fall back to
/// the digest and byte count of an actually empty capture, which would report
/// "the provider produced nothing" for a stream nobody ever read.
#[allow(clippy::too_many_arguments)]
fn terminal_receipt(
    admitted: &AdmittedOperation,
    client_receipt: &eliot_kernel_service::ResearchProviderDispatchReceipt,
    admission: &ProviderAdmission,
    capability_cell_proof: &CapabilityCellProof,
    raw: Option<&RawProviderEvidence>,
    observation: &EvidenceObservation,
    cancellation: Option<CancellationEvidence>,
    cancellation_outcome: CancellationOutcome,
    undischarged: Vec<Obligation>,
    submission: Option<&SubmissionRecord>,
    provider_job_ref: Option<String>,
    job_id: Option<String>,
    outcome: eliot_mod_research::ProviderOutcome,
    observed_disposition: Option<eliot_mod_research::ProviderOutcome>,
    reason_code: Option<&'static str>,
    records: Vec<eliot_mod_research::ProviderEvidenceRecord>,
    reconciliation: ReconciliationEvidence,
) -> ProviderExecutionReceipt {
    let dispatch = &admitted.dispatch;
    // The retained evidence is used only when the readback actually answered.
    // A not-attempted or never-answered readback falls back to the explicit
    // absence record, whose streams carry the `NoHandle` omission, so an
    // unread stream is never rendered with the digest and byte count of a
    // stream that was really read and really was empty. Those are two
    // different observations and this receipt keeps them different.
    let raw = match (raw, observation) {
        (Some(evidence), EvidenceObservation::Observed(_)) => evidence.clone(),
        _ => RawProviderEvidence::absent(
            dispatch.operation_id.as_str(),
            &client_receipt.request_sha256,
        ),
    };
    ProviderExecutionReceipt {
        operation_id: dispatch.operation_id.clone(),
        cancellation_id: admission.cancellation_id().to_owned(),
        exchange_id: dispatch.exchange_id.clone(),
        idempotency_key: dispatch.idempotency_key.clone(),
        dispatch_sha256: dispatch.canonical_sha256().unwrap_or_default(),
        admission_receipt_sha256: client_receipt.receipt_digest.clone(),
        executable_sha256: admission.bridge().executable_sha256().to_owned(),
        module_generation_id: dispatch.module_generation_id.clone(),
        capability_cell_proof: capability_cell_proof.clone(),
        process_generation: dispatch.process_generation,
        disclosure: dispatch.disclosure.clone(),
        budget_units: dispatch.budget_units,
        deadline_ms: dispatch.deadline_ms,
        inquiry_digest: dispatch.inquiry_digest.clone(),
        denominator_digest: dispatch.denominator_digest.clone(),
        submit_envelope_sha256: submission
            .as_ref()
            .map_or_else(String::new, |record| record.envelope_sha256.clone()),
        submit_binding_sha256: submission
            .as_ref()
            .map_or_else(String::new, |record| record.submit_binding_sha256.clone()),
        outcome,
        observed_disposition,
        stream_readback: observation.clone(),
        cancellation_outcome,
        undischarged,
        reason_code,
        raw,
        cancellation,
        reconciliation,
        evidence_records: records,
        provider_job_ref: provider_job_ref.or(job_id),
        candidate_sha256: None,
        candidate_only: true,
    }
}

fn admission_required_message() -> String {
    format!(
        "{KERNEL_ADMISSION_REQUIRED}: service={SERVICE_NAME} protocol={PROTOCOL_VERSION} operation={OPERATION}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_diagnostic_is_stable_and_never_claims_readiness() {
        let message = admission_required_message();
        assert_eq!(
            message,
            "KERNEL_ADMISSION_REQUIRED: service=eliot-mod-research protocol=eliot.research.provider.v1 operation=eliot.research.provider.execute"
        );
        assert!(!message.to_ascii_lowercase().contains("ready"));
        assert_ne!(EXIT_KERNEL_ADMISSION_REQUIRED, 0);
    }
}
