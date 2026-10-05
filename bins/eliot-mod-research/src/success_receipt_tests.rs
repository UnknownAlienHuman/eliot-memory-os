use std::{error::Error, num::NonZeroU64};

use eliot_contracts::{
    CapabilityCellProof, ContractVersion, EpochId, EpochLineageId, ResourceGeneration, StateFence,
};
use eliot_mod_research::{
    CancellationOutcome, EvidenceObservation, ProviderAdmission, ProviderExecutionReceipt,
    ProviderOutcome, RawProviderEvidence, ReconciliationEvidence, TerminalFailure,
    resolve_admitted_cell, sha256_hex,
};
use eliot_process::{ExitDisposition, ExitStatus, Generation, OperationId};
use eliot_process_executor::CapturedStream;
use eliot_research_exchange_api::DisclosureClass;

use super::terminal_reason_code;

const EXECUTABLE_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONFIG_SHA256: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PROTOCOL_SHA256: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const INQUIRY_SHA256: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const DENOMINATOR_SHA256: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const DISPATCH_SHA256: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const ADMISSION_RECEIPT_SHA256: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const INVOCATION_SHA256: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const SUBMIT_ENVELOPE_SHA256: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
const SUBMIT_BINDING_SHA256: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";
const PROVIDER_STDOUT: &[u8] = b"opaque provider success response";
const CANDIDATE_BYTES: &[u8] = b"candidate held for Governor admission";

fn success_fixture() -> Result<(ProviderAdmission, ProviderExecutionReceipt), Box<dyn Error>> {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")?,
        NonZeroU64::MIN,
    )?;
    let fence = StateFence::new(epoch.clone(), ResourceGeneration::genesis());
    let admission = ProviderAdmission::new(
        eliot_mod_research::BridgeIdentity::new(
            r"C:\providers\research-bridge-v1.exe",
            EXECUTABLE_SHA256,
        )?,
        CONFIG_SHA256,
        PROTOCOL_SHA256,
        "mod-research-provider",
        "gen-mod-24-a",
        Generation::new(3)?,
        epoch,
        fence,
        DisclosureClass::ProjectBound,
        10,
        1_800_000_000_000,
        ContractVersion::new(1, 0, 0),
        "research-evidence-bundle/v1",
        "gen-24-slice-a",
        OperationId::new("op-24-slice-a")?,
        "cancel-24-slice-a",
        INQUIRY_SHA256,
        DENOMINATOR_SHA256,
        "bounded exact sources with explicit unknowns",
    )
    .map_err(|refusal| std::io::Error::other(refusal.reason()))?;
    let capability_cell_proof = resolve_admitted_cell(&admission)
        .map_err(|refusal| std::io::Error::other(refusal.reason()))?;

    let stdout = CapturedStream {
        bytes: PROVIDER_STDOUT.to_vec(),
        total_bytes: PROVIDER_STDOUT.len() as u64,
        truncated: false,
        complete: true,
        captured: true,
    };
    let stderr = CapturedStream {
        bytes: Vec::new(),
        total_bytes: 0,
        truncated: false,
        complete: true,
        captured: true,
    };
    let exit = ExitStatus::new(ExitDisposition::Completed, Some(0), None, 1_799_999_999_999)?;
    let raw = RawProviderEvidence::materialize(
        admission.operation_id().as_str(),
        INVOCATION_SHA256,
        &exit,
        &stdout,
        &stderr,
        true,
    );

    let reconciliation = ReconciliationEvidence::not_required();
    let reason_code = terminal_reason_code(ProviderOutcome::Completed, &reconciliation, None);
    let receipt = ProviderExecutionReceipt {
        operation_id: admission.operation_id().as_str().to_owned(),
        cancellation_id: admission.cancellation_id().to_owned(),
        exchange_id: "ex-24-slice-a".to_owned(),
        idempotency_key: "idem-24-slice-a".to_owned(),
        dispatch_sha256: DISPATCH_SHA256.to_owned(),
        admission_receipt_sha256: ADMISSION_RECEIPT_SHA256.to_owned(),
        executable_sha256: admission.bridge().executable_sha256().to_owned(),
        module_generation_id: admission.module_generation_id().as_str().to_owned(),
        capability_cell_proof,
        process_generation: admission.process_generation().get(),
        disclosure: "ProjectBound".to_owned(),
        budget_units: admission.budget_units(),
        deadline_ms: admission.deadline_ms(),
        inquiry_digest: admission.inquiry_digest().to_owned(),
        denominator_digest: admission.denominator_digest().to_owned(),
        submit_envelope_sha256: SUBMIT_ENVELOPE_SHA256.to_owned(),
        submit_binding_sha256: SUBMIT_BINDING_SHA256.to_owned(),
        outcome: ProviderOutcome::Completed,
        observed_disposition: Some(ProviderOutcome::Completed),
        stream_readback: EvidenceObservation::Observed(Box::new(raw.clone())),
        cancellation_outcome: CancellationOutcome::NotAttempted,
        undischarged: Vec::new(),
        reason_code,
        raw,
        cancellation: None,
        reconciliation,
        evidence_records: Vec::new(),
        provider_job_ref: Some("provider-job-local-17".to_owned()),
        candidate_sha256: Some(sha256_hex(CANDIDATE_BYTES)),
        candidate_only: true,
    };

    Ok((admission, receipt))
}

#[test]
fn completed_receipt_renders_without_failure_or_acquisition_degradation()
-> Result<(), Box<dyn Error>> {
    let (admission, receipt) = success_fixture()?;

    assert_success_state(&receipt);
    assert_admitted_context(&admission, &receipt);
    assert_cell_proof_surface(&receipt.capability_cell_proof);

    let expected = expected_success_rendering(&receipt.capability_cell_proof);
    let rendered = receipt.to_string();
    assert_eq!(rendered, expected);
    assert!(rendered.contains("outcome=Completed"));
    assert!(rendered.contains("reason=none"));
    assert!(rendered.contains("candidate_only=true"));
    assert!(!rendered.contains("RUNTIME_FAILED"));
    assert!(!rendered.contains("opaque provider success response"));

    Ok(())
}

fn assert_success_state(receipt: &ProviderExecutionReceipt) {
    assert_eq!(receipt.outcome, ProviderOutcome::Completed);
    assert_eq!(receipt.reason_code, None);
    assert!(
        TerminalFailure::outcome_degradation(receipt.outcome, receipt.cancellation.as_ref())
            .is_none()
    );
    assert!(receipt.candidate_only);
    assert_eq!(
        receipt.candidate_sha256.as_deref(),
        Some(sha256_hex(CANDIDATE_BYTES).as_str())
    );
    assert_eq!(receipt.raw.exit_disposition, ExitDisposition::Completed);
    assert_eq!(receipt.raw.exit_code, Some(0));
    assert!(receipt.raw.descendants_complete);
}

fn assert_admitted_context(admission: &ProviderAdmission, receipt: &ProviderExecutionReceipt) {
    assert_eq!(receipt.operation_id, admission.operation_id().as_str());
    assert_eq!(receipt.cancellation_id, admission.cancellation_id());
    assert_eq!(
        receipt.executable_sha256,
        admission.bridge().executable_sha256()
    );
    assert_eq!(
        receipt.module_generation_id,
        admission.module_generation_id().as_str()
    );
    assert_eq!(
        receipt.process_generation,
        admission.process_generation().get()
    );
    assert_eq!(receipt.disclosure, "ProjectBound");
    assert_eq!(receipt.budget_units, admission.budget_units());
    assert_eq!(receipt.deadline_ms, admission.deadline_ms());
    assert_eq!(receipt.inquiry_digest, admission.inquiry_digest());
    assert_eq!(receipt.denominator_digest, admission.denominator_digest());
    assert_eq!(receipt.exchange_id, "ex-24-slice-a");
    assert_eq!(receipt.idempotency_key, "idem-24-slice-a");
    assert_eq!(receipt.dispatch_sha256, DISPATCH_SHA256);
    assert_eq!(receipt.admission_receipt_sha256, ADMISSION_RECEIPT_SHA256);
    assert_eq!(receipt.submit_envelope_sha256, SUBMIT_ENVELOPE_SHA256);
    assert_eq!(receipt.submit_binding_sha256, SUBMIT_BINDING_SHA256);
    assert_eq!(
        receipt.provider_job_ref.as_deref(),
        Some("provider-job-local-17")
    );
}

fn assert_cell_proof_surface(proof: &CapabilityCellProof) {
    assert_eq!(proof.cell().as_str(), "mod-research-provider");
    assert_eq!(
        proof.contract_digest().as_str(),
        "fd0a6fbf1af1d4463ea2ced41576c8b1abf5ef2cd74a79a3716067486558d731"
    );
    assert_eq!(proof.source_crate().as_str(), "eliot-mod-research");
    assert_eq!(
        proof.proof_entrypoint().as_str(),
        "cargo test -p eliot-mod-research --all-targets --all-features"
    );
}

fn expected_success_rendering(proof: &CapabilityCellProof) -> String {
    format!(
        concat!(
            "operation={} exchange={} cancellation={} dispatch={} admission_receipt={} ",
            "executable={} module_generation={} capability_cell={} capability_cell_contract={} ",
            "capability_cell_registry={} capability_cell_support={:?} capability_cell_source_crate={} ",
            "capability_cell_proof_entrypoint={} process_generation={} disclosure={} budget_units={} ",
            "deadline_ms={} inquiry={} denominator={} submit_envelope={} submit_binding={} outcome={:?} ",
            "process_disposition={:?} stream_readback={} cancel_state={} undischarged={} reason={} ",
            "stdout_sha256={} stdout_bytes={} stdout_omission={} stderr_sha256={} stderr_bytes={} ",
            "stderr_omission={} exit={:?} exit_code={} descendants_complete={} cancel_receipt_present={} ",
            "cancel_status={} no_effect_proven={} reconciliation_attempts={} owner_confirmed={} ",
            "cancellation_unconfirmed={} reconciliation={} evidence_records={} provider_job_ref={} ",
            "candidate_sha256={} candidate_only={}"
        ),
        "op-24-slice-a",
        "ex-24-slice-a",
        "cancel-24-slice-a",
        DISPATCH_SHA256,
        ADMISSION_RECEIPT_SHA256,
        EXECUTABLE_SHA256,
        "gen-mod-24-a",
        proof.cell().as_str(),
        proof.contract_digest().as_str(),
        proof.registry_digest(),
        proof.current_support(),
        proof.source_crate().as_str(),
        proof.proof_entrypoint().as_str(),
        3,
        "ProjectBound",
        10,
        1_800_000_000_000_i64,
        INQUIRY_SHA256,
        DENOMINATOR_SHA256,
        SUBMIT_ENVELOPE_SHA256,
        SUBMIT_BINDING_SHA256,
        ProviderOutcome::Completed,
        Some(ProviderOutcome::Completed),
        "observed",
        "not_attempted",
        "",
        "none",
        sha256_hex(PROVIDER_STDOUT),
        PROVIDER_STDOUT.len(),
        "none",
        sha256_hex(&[]),
        0,
        "none",
        ExitDisposition::Completed,
        "0",
        true,
        false,
        "none",
        false,
        0,
        false,
        false,
        "none",
        0,
        "provider-job-local-17",
        sha256_hex(CANDIDATE_BYTES),
        true,
    )
}
