//! The production composition root for the local ELIOT test daemon.
//!
//! Test execution is admitted only as the pair of contracts that describe it:
//! an instrument invocation and its exact supervised-process request.  This
//! surface deliberately does not manufacture process evidence or promote a
//! result to a verification claim; those effects belong to the injected
//! instrument and process owners.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_instrument_api::{InstrumentContractError, InstrumentInvocation, InstrumentKind};
use eliot_process::{ContractError as ProcessContractError, ProcessRequest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable daemon service identity.
pub const SERVICE_NAME: &str = "eliot-testd";
/// Stable line-protocol revision.
pub const PROTOCOL_VERSION: &str = "eliot.testd.v1";
/// Maximum number of admitted, unfinished invocations retained by one daemon.
pub const MAX_ADMITTED_RUNS: usize = 64;

/// One test admission submitted to the daemon.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestRequest {
    /// The provider-neutral instrument contract.
    pub invocation: InstrumentInvocation,
    /// The exact process contract the platform supervisor must execute.
    pub process: ProcessRequest,
}

impl TestRequest {
    /// Validates the two contracts and their binding identity.
    pub fn validate(&self) -> Result<(), TestdError> {
        self.invocation.validate()?;
        self.process.validate()?;
        if !matches!(self.invocation.kind, InstrumentKind::Test) {
            return Err(TestdError::WrongInstrumentKind);
        }
        if self.invocation.request.request_id.as_str() != self.process.operation_id().as_str() {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }
}

/// Lifecycle visible at the daemon boundary.  Running and terminal states
/// are emitted only by a provider owner; admission itself never implies them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TestState {
    Accepted,
    CancelRequested,
}

/// A stable admission receipt returned by the composition root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestReceipt {
    pub request_id: String,
    pub process_tree_id: String,
    pub process_generation: u64,
    pub invocation_digest: String,
    pub state: TestState,
}

#[derive(Clone, Debug)]
struct AdmittedRun {
    request: TestRequest,
    state: TestState,
}

/// Errors returned by the daemon composition root.
#[derive(Debug, Error)]
pub enum TestdError {
    #[error("instrument contract: {0}")]
    Instrument(#[from] InstrumentContractError),
    #[error("process contract: {0}")]
    Process(#[from] ProcessContractError),
    #[error("only TEST instrument invocations are accepted")]
    WrongInstrumentKind,
    #[error("instrument and process contracts are not bound")]
    InvalidBinding,
    #[error("duplicate test request: {0}")]
    DuplicateRequest(String),
    #[error("admission capacity exhausted")]
    CapacityExhausted,
    #[error("unknown test request: {0}")]
    UnknownRequest(String),
    #[error("test request is already being cancelled: {0}")]
    AlreadyCancelling(String),
}

/// In-memory composition root for one supervised test-daemon process.
pub struct TestdComposition {
    admitted: BTreeMap<String, AdmittedRun>,
    capacity: usize,
}

impl Default for TestdComposition {
    fn default() -> Self {
        Self::new(MAX_ADMITTED_RUNS)
    }
}

impl TestdComposition {
    /// Creates a composition with a bounded admission table.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            admitted: BTreeMap::new(),
            capacity: capacity.max(1),
        }
    }

    /// Admits one exact instrument/process pair.
    pub fn submit(&mut self, request: TestRequest) -> Result<TestReceipt, TestdError> {
        request.validate()?;
        let request_id = request.invocation.request.request_id.as_str().to_owned();
        if self.admitted.contains_key(&request_id) {
            return Err(TestdError::DuplicateRequest(request_id));
        }
        if self.admitted.len() >= self.capacity {
            return Err(TestdError::CapacityExhausted);
        }
        let receipt = receipt(&request, TestState::Accepted);
        self.admitted.insert(
            request_id,
            AdmittedRun {
                request,
                state: TestState::Accepted,
            },
        );
        Ok(receipt)
    }

    /// Returns the current admission receipt without changing provider state.
    pub fn status(&self, request_id: &str) -> Result<TestReceipt, TestdError> {
        self.admitted
            .get(request_id)
            .map(|run| receipt(&run.request, run.state))
            .ok_or_else(|| TestdError::UnknownRequest(request_id.to_owned()))
    }

    /// Records a cancellation request for an admitted but not yet started run.
    pub fn cancel(&mut self, request_id: &str) -> Result<TestReceipt, TestdError> {
        let run = self
            .admitted
            .get_mut(request_id)
            .ok_or_else(|| TestdError::UnknownRequest(request_id.to_owned()))?;
        if run.state == TestState::CancelRequested {
            return Err(TestdError::AlreadyCancelling(request_id.to_owned()));
        }
        run.state = TestState::CancelRequested;
        Ok(receipt(&run.request, run.state))
    }
}

fn receipt(request: &TestRequest, state: TestState) -> TestReceipt {
    TestReceipt {
        request_id: request.invocation.request.request_id.as_str().to_owned(),
        process_tree_id: request.process.process_tree_id().as_str().to_owned(),
        process_generation: request.process.generation().get(),
        invocation_digest: request.process.invocation_digest().to_owned(),
        state,
    }
}
