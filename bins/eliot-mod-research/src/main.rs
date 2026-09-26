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

use std::io::{self, Write};
use std::sync::Arc;

use eliot_kernel_service::{RESEARCH_PROVIDER_DISPATCH_OPERATION, ResearchProviderDispatch};
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
    BridgeIdentity, RESEARCH_SOURCE_UNAVAILABLE, RawProviderEvidence, ResearchDispatchAuthority,
    SubmissionRecord, compose_admitted, project_admitted_inquiry,
};
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
        Err(Failure::Degraded(receipt)) => {
            // A provider failure is not a Researcher semantic failure and not a
            // fabricated empty result: it is a typed coverage gap carrying the
            // exact stable code plus the evidence that was retained.
            let _ = writeln!(
                io::stderr(),
                "{RESEARCH_SOURCE_UNAVAILABLE}: reason={} receipt={receipt}",
                receipt.reason_code
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
    Degraded(Box<ProviderExecutionReceipt>),
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
    let client = ResearchKernelClient::load()
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
    let admission = admit(&admitted, &client_receipt)?;

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
    let (bridge, _exchange) = researcher.into_exchange().into_parts();

    if let Ok(job) = submitted {
        let receipt = terminal_receipt(
            &admitted,
            &client_receipt,
            &admission,
            bridge.last_evidence().cloned(),
            bridge.last_cancellation().cloned(),
            bridge.last_submission(),
            bridge.last_provider_job_ref().cloned(),
            Some(job.job_id),
            eliot_mod_research::ProviderOutcome::Completed,
            eliot_kernel_service::REASON_RUNTIME_FAILED,
            records,
            // A positive terminal outcome needs no owner reconciliation, and the
            // empty attempt list records that fact rather than hiding it.
            ReconciliationEvidence::not_required(),
        );
        report_admitted_inquiry(&admitted.request, &receipt, bridge.last_failure());
        return Ok(receipt.to_string());
    }
    // The bridge retains the typed terminal classification, the raw evidence
    // materialized before the failure, and the cancellation receipt. A failure
    // that never reached the executor is still an acquisition gap, never a
    // Researcher semantic failure.
    //
    // A non-success terminal state is reconciled against the owner that holds
    // the operation before it is reported, so the receipt distinguishes an
    // owner-attested classification from a local guess.
    let failure = bridge.last_failure();
    let outcome =
        failure.map_or(eliot_mod_research::ProviderOutcome::Unknown, |terminal| {
            terminal.outcome
        });
    let reconciliation = reconcile_with_owner(
        &client,
        &admitted,
        bridge.last_cancellation(),
        outcome,
    );
    let no_effect_proven = bridge
        .last_cancellation()
        .is_some_and(|receipt| receipt.no_effect_proven);
    let reason_code = if reconciliation.leaves_cancellation_unconfirmed(no_effect_proven) {
        // The provider's own vocabulary names this state and nothing else
        // produced it: a cancellation whose no-effect is unproven and which the
        // owner did not confirm is not the same fact as a plain unknown.
        eliot_kernel_service::REASON_CANCELLATION_UNCONFIRMED
    } else {
        failure.map_or(eliot_kernel_service::REASON_UNKNOWN_OUTCOME, |terminal| {
            terminal.reason_code
        })
    };
    let receipt = terminal_receipt(
        &admitted,
        &client_receipt,
        &admission,
        bridge.last_evidence().cloned(),
        bridge.last_cancellation().cloned(),
        bridge.last_submission(),
        bridge.last_provider_job_ref().cloned(),
        None,
        outcome,
        reason_code,
        records,
        reconciliation,
    );
    report_admitted_inquiry(&admitted.request, &receipt, bridge.last_failure());
    Err(Failure::Degraded(Box::new(receipt)))
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
    receipt: &ProviderExecutionReceipt,
    failure: Option<&eliot_mod_research::TerminalFailure>,
) {
    match project_admitted_inquiry(request, receipt, failure) {
        Ok(inquiry) => {
            let _ = writeln!(
                io::stderr(),
                "{}: {inquiry}",
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

/// Seals one verified Kernel dispatch receipt into a local admission.
///
/// The receipt was already re-proved against the presented dispatch by the wire
/// owner's `verify_echo`. The local admission is built only from fields that
/// receipt echoes, so a receipt can never widen the executable, generation,
/// epoch, fence, privacy class, budget, or deadline beyond what the Kernel
/// admitted under the live authority.
///
/// # Errors
///
/// Returns [`Failure::NoAdmission`] when the admitted material cannot be turned
/// into a local admission.
fn admit(
    admitted: &AdmittedOperation,
    client_receipt: &eliot_kernel_service::ResearchProviderDispatchReceipt,
) -> Result<ProviderAdmission, Failure> {
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
    ProviderAdmission::new(
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
        dispatch.inquiry_digest.clone(),
        dispatch.denominator_digest.clone(),
        admitted.request.coverage_goal.clone(),
    )
    .map_err(|error| Failure::NoAdmission(format!("admission refused: {}", error.reason())))
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

/// Sends one control operation and records the owner's answer verbatim.
///
/// The owner's disposition is never rewritten and a transport refusal never
/// becomes a disposition, so the receipt can always be read as "this is what
/// the owner said, or that it was never reached".
fn ask_control_operation(
    attempts: &mut Vec<OwnerReconciliationAttempt>,
    client: &ResearchKernelClient,
    operation: &'static str,
    send: impl FnOnce(&ResearchKernelClient) -> Result<
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
#[allow(clippy::too_many_arguments)]
fn terminal_receipt(
    admitted: &AdmittedOperation,
    client_receipt: &eliot_kernel_service::ResearchProviderDispatchReceipt,
    admission: &ProviderAdmission,
    raw: Option<RawProviderEvidence>,
    cancellation: Option<CancellationEvidence>,
    submission: Option<&SubmissionRecord>,
    provider_job_ref: Option<String>,
    job_id: Option<String>,
    outcome: eliot_mod_research::ProviderOutcome,
    reason_code: &'static str,
    records: Vec<eliot_mod_research::ProviderEvidenceRecord>,
    reconciliation: ReconciliationEvidence,
) -> ProviderExecutionReceipt {
    let dispatch = &admitted.dispatch;
    ProviderExecutionReceipt {
        operation_id: dispatch.operation_id.clone(),
        cancellation_id: dispatch.cancellation_id.clone(),
        exchange_id: dispatch.exchange_id.clone(),
        idempotency_key: dispatch.idempotency_key.clone(),
        dispatch_sha256: dispatch.canonical_sha256().unwrap_or_default(),
        admission_receipt_sha256: client_receipt.receipt_digest.clone(),
        executable_sha256: admission.bridge().executable_sha256().to_owned(),
        module_generation_id: dispatch.module_generation_id.clone(),
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
        reason_code,
        raw: raw.unwrap_or_else(|| {
            RawProviderEvidence::absent(
                dispatch.operation_id.as_str(),
                &client_receipt.request_sha256,
            )
        }),
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
