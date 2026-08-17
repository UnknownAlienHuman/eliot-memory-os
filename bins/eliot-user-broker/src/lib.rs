//! Production composition root for the A-09 user broker.
//!
//! The binary owns only process lifetime and durable registration wiring. G-01
//! and P-04 remain explicit provider boundaries; this root never manufactures
//! authority or process evidence when those providers are not composed.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_platform::ClockObservation;
use eliot_platform::WorkScopePath;
use eliot_platform_windows::{ProtectedPathLease, WindowsPlatform};
use eliot_process::{
    ActionLeaseRef, CancellationReceipt, DispatchAuthorityId, DispatchPermitAuthority,
    DispatchValidationContext, FencingToken, KernelDispatchKey, OperationId, PermitIssuance,
    ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError, ProcessExecutionView,
    ProcessExecutor, ProcessIntent, ProcessRequest, SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::{DispatchValidationPort, WindowsProcessExecutor};
use eliot_protocol::RequestIdentity;
use eliot_user_broker_core::{
    AuthorityPort, BrokerError, BrokerSnapshot, DurableRegistrationPort, HeartbeatReceipt,
    HeartbeatRequest, LaunchGrant, LaunchRequest, OperatorArtifact, PortError, ProcessPort,
    ProcessStartOutcome, RegistrationFenceReceipt, RegistrationFenceRequest, RegistrationGrant,
    RegistrationReceipt, RegistrationRequest, RequiredProvider, UserBroker,
};
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SERVICE_NAME: &str = "eliot-user-broker";
pub const PROTOCOL_VERSION: &str = "eliot.user-broker.v1";
const LAUNCH_CONFIG_RELATIVE_PATH: &str = "Eliot/user-broker/launch.json";
const SNAPSHOT_RELATIVE_DIRECTORY: &str = "Eliot/user-broker";
const SNAPSHOT_LIMIT: u64 = 16 * 1024 * 1024;

/// Installation-owned launch declaration.  It is loaded through a retained
/// protected handle; stdin never supplies any of these identities or keys.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerLaunchConfig {
    pub registration: RegistrationRequest,
    pub request_identity: RequestIdentity,
    pub operator_artifact: OperatorArtifactConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorArtifactConfig {
    pub image_id: String,
    pub executable: String,
    pub artifact_digest: String,
}

fn artifact_digest() -> Result<String, CompositionError> {
    let executable = std::env::current_exe().map_err(CompositionError::Durable)?;
    let bytes = fs::read(executable).map_err(CompositionError::Durable)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_launch_config(config: &BrokerLaunchConfig) -> Result<(), CompositionError> {
    config
        .registration
        .validate()
        .map_err(|error| CompositionError::Launch(error.to_string()))?;
    config
        .request_identity
        .validate()
        .map_err(|error| CompositionError::Launch(error.to_string()))?;
    let expected_pid = std::process::id().to_string();
    if config.registration.broker_process_id != expected_pid {
        return Err(CompositionError::Launch(
            "protected broker process identity does not match current process".to_owned(),
        ));
    }
    if !config
        .registration
        .broker_artifact_digest
        .eq_ignore_ascii_case(&artifact_digest()?)
    {
        return Err(CompositionError::Launch(
            "protected broker artifact digest does not match current executable".to_owned(),
        ));
    }
    OperatorArtifact {
        image_id: config.operator_artifact.image_id.clone(),
        executable: config.operator_artifact.executable.clone(),
        artifact_digest: config.operator_artifact.artifact_digest.clone(),
    }
    .validate()
    .map_err(|error| CompositionError::Launch(error.to_string()))?;
    #[cfg(windows)]
    {
        let identity = eliot_platform_windows::current_process_named_pipe_expectation()
            .map_err(|error| CompositionError::Launch(error.to_string()))?;
        if config.registration.windows_sid != identity.expected_sid()
            || config.registration.interactive_session_id
                != identity.expected_session_id().to_string()
        {
            return Err(CompositionError::Launch(
                "protected broker SID/session does not match current token".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Loads the protected installation launch declaration and returns its retained
/// no-follow/reparse-safe file lease to the composition owner.
fn load_protected_launch_config()
-> Result<(BrokerLaunchConfig, ProtectedPathLease), CompositionError> {
    #[cfg(not(windows))]
    {
        Err(CompositionError::Kernel(
            "Windows protected broker launch configuration".to_owned(),
        ))
    }
    #[cfg(windows)]
    {
        let path = eliot_platform_windows::protected_program_data_path(LAUNCH_CONFIG_RELATIVE_PATH)
            .map_err(|error| CompositionError::Protected(error.to_string()))?;
        let lease = ProtectedPathLease::open_existing_absolute(&path)
            .map_err(|error| CompositionError::Protected(error.to_string()))?;
        let bytes = lease
            .read_bounded(64 * 1024)
            .map_err(|error| CompositionError::Protected(error.to_string()))?;
        let config = serde_json::from_slice(&bytes).map_err(CompositionError::Encoding)?;
        validate_launch_config(&config)?;
        Ok((config, lease))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerConfig {
    pub data_root: PathBuf,
    pub snapshot_name: String,
}

impl BrokerConfig {
    pub fn from_root(data_root: impl Into<PathBuf>) -> Self {
        Self {
            data_root: data_root.into(),
            snapshot_name: "user-broker.snapshot.json".to_owned(),
        }
    }

    fn validate(&self) -> Result<(), CompositionError> {
        if !self.data_root.is_absolute() {
            return Err(CompositionError::InvalidConfiguration(
                "data_root must be an absolute path".to_owned(),
            ));
        }
        if self.snapshot_name.trim().is_empty()
            || Path::new(&self.snapshot_name).components().count() != 1
        {
            return Err(CompositionError::InvalidConfiguration(
                "snapshot_name must be one file name".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum CompositionError {
    #[error("invalid broker configuration: {0}")]
    InvalidConfiguration(String),
    #[error("durable registration: {0}")]
    Durable(#[source] io::Error),
    #[error("snapshot encoding: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("protected broker path: {0}")]
    Protected(String),
    #[error("protected launch configuration: {0}")]
    Launch(String),
    #[error("broker recovery: {0}")]
    Recovery(#[source] BrokerError),
    #[error("Kernel front-door composition: {0}")]
    Kernel(String),
    #[error("Kernel front-door lock poisoned")]
    KernelLock,
}

type SharedKernelClient = Arc<Mutex<eliot_cli::kernel_client::KernelClient>>;

fn kernel_port_error(error: eliot_cli::kernel_client::KernelClientError) -> PortError {
    match error {
        eliot_cli::kernel_client::KernelClientError::FrontDoorClosed(_) => PortError::Unavailable,
        eliot_cli::kernel_client::KernelClientError::UnknownOutcome(_) => PortError::Unknown,
        eliot_cli::kernel_client::KernelClientError::MissingRequestIdentity => {
            PortError::Invalid("missing authenticated RequestIdentity".to_owned())
        }
        eliot_cli::kernel_client::KernelClientError::Configuration(detail)
        | eliot_cli::kernel_client::KernelClientError::Rejected(detail) => {
            PortError::Invalid(detail)
        }
    }
}

fn kernel_call(
    client: &SharedKernelClient,
    operation: &str,
    payload: Value,
) -> Result<Value, PortError> {
    let mut client = client.lock().map_err(|_| PortError::Unknown)?;
    client
        .transact_json(operation, payload)
        .map_err(kernel_port_error)
}

struct KernelAuthorityPort {
    client: SharedKernelClient,
}

impl AuthorityPort for KernelAuthorityPort {
    fn register(&mut self, request: &RegistrationRequest) -> Result<RegistrationGrant, PortError> {
        serde_json::from_value(kernel_call(
            &self.client,
            "eliot.user-broker.register",
            serde_json::to_value(request).map_err(|error| PortError::Invalid(error.to_string()))?,
        )?)
        .map_err(|error| PortError::Invalid(format!("decode registration grant: {error}")))
    }

    fn heartbeat(
        &mut self,
        receipt: &RegistrationReceipt,
        observed_at: u64,
    ) -> Result<RegistrationGrant, PortError> {
        kernel_call(
            &self.client,
            "eliot.user-broker.heartbeat",
            serde_json::json!({
                "registration": receipt,
                "observed_at": observed_at,
            }),
        )
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|error| PortError::Invalid(format!("decode heartbeat grant: {error}")))
        })
    }

    fn authorize_launch(
        &mut self,
        receipt: &RegistrationReceipt,
        request: &LaunchRequest,
    ) -> Result<LaunchGrant, PortError> {
        kernel_call(
            &self.client,
            "eliot.user-broker.authorize-launch",
            serde_json::json!({
                "registration": receipt,
                "request": request,
            }),
        )
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|error| PortError::Invalid(format!("decode launch grant: {error}")))
        })
    }

    fn fence(
        &mut self,
        request: &RegistrationFenceRequest,
    ) -> Result<RegistrationFenceReceipt, PortError> {
        kernel_call(
            &self.client,
            "eliot.user-broker.fence",
            serde_json::to_value(request).map_err(|error| PortError::Invalid(error.to_string()))?,
        )
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|error| PortError::Invalid(format!("decode fence receipt: {error}")))
        })
    }
}

/// Retains observation-only process evidence without granting any additional
/// authority to the broker or its callers.
struct BrokerEvidenceSink {
    records: Arc<Mutex<Vec<ProcessEvidence>>>,
}

impl ProcessEvidenceSink for BrokerEvidenceSink {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), eliot_process::EvidenceSinkError> {
        self.records
            .lock()
            .map_err(|_| eliot_process::EvidenceSinkError {
                message: "broker evidence lock poisoned".to_owned(),
            })?
            .push(evidence);
        Ok(())
    }
}

/// Ephemeral broker-owned P-03 authority.  The key is generated in memory at
/// composition time and never crosses the launch-grant or stdin boundary;
/// `DispatchPermitAuthority` supplies the one-shot replay fence.
struct BrokerDispatchAuthority {
    authority: Mutex<DispatchPermitAuthority>,
    context: Mutex<Option<DispatchValidationContext>>,
}

impl BrokerDispatchAuthority {
    fn new() -> Result<Self, PortError> {
        let authority_id =
            DispatchAuthorityId::new(format!("user-broker-{}", uuid::Uuid::new_v4().simple()))
                .map_err(|error| PortError::Invalid(error.to_string()))?;
        let mut key = [0_u8; 32];
        let nonce = uuid::Uuid::new_v4().as_bytes().to_owned();
        key[..16].copy_from_slice(&nonce);
        key[16..].copy_from_slice(&Sha256::digest(nonce));
        let key = KernelDispatchKey::from_secret_bytes(key)
            .map_err(|error| PortError::Invalid(error.to_string()))?;
        Ok(Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(authority_id, key)),
            context: Mutex::new(None),
        })
    }

    fn issue(
        &self,
        intent: &ProcessIntent,
        grant: &LaunchGrant,
        now: u64,
    ) -> Result<ProcessRequest, PortError> {
        let fence = FencingToken::new(
            grant.authority_epoch,
            grant.approved.generation,
            grant.approved.process_fence_nonce.clone(),
        )
        .map_err(|error| PortError::Invalid(error.to_string()))?;
        let issuance = PermitIssuance::new(
            ActionLeaseRef::new(grant.approved.idempotency_key.clone())
                .map_err(|error| PortError::Invalid(error.to_string()))?,
            fence.clone(),
            BTreeMap::from([("launch-grant".to_owned(), grant.grant_digest.clone())]),
            now.saturating_sub(1).max(1),
            grant.expires_at,
            grant.grant_digest.clone(),
        )
        .map_err(|error| PortError::Invalid(error.to_string()))?;
        let permit = self
            .authority
            .lock()
            .map_err(|_| PortError::Unknown)?
            .issue(intent, issuance)
            .map_err(|error| PortError::Invalid(error.to_string()))?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(i64::try_from(now).unwrap_or(i64::MAX)),
                known_time_ms: Some(i64::try_from(now).unwrap_or(i64::MAX)),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            grant.authority_epoch,
            BTreeMap::from([("launch-grant".to_owned(), grant.grant_digest.clone())]),
            1,
        )
        .map_err(|error| PortError::Invalid(error.to_string()))?;
        *self.context.lock().map_err(|_| PortError::Unknown)? = Some(context);
        ProcessRequest::new(intent.clone(), permit)
            .map_err(|error| PortError::Invalid(error.to_string()))
    }
}

impl DispatchValidationPort for BrokerDispatchAuthority {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        let current = self
            .context
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("broker context lock poisoned".to_owned())
            })?
            .clone()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable("missing broker validation context".to_owned())
            })?;
        self.authority
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("broker authority lock poisoned".to_owned())
            })?
            .validate_and_consume(request, observed, &current)
            .map_err(ProcessExecutionError::from)
    }
}

/// Local P-04 composition for the interactive user's Job/process contour.
/// Kernel only supplies a typed `LaunchGrant`; this adapter never sends the
/// sealed P-03 request over EBP.
struct LocalProcessPort {
    authority: Arc<BrokerDispatchAuthority>,
    executor: WindowsProcessExecutor,
    runtime: tokio::runtime::Runtime,
    evidence: Arc<Mutex<Vec<ProcessEvidence>>>,
    pending_requests: BTreeMap<OperationId, ProcessRequest>,
}

impl LocalProcessPort {
    fn new() -> Result<Self, CompositionError> {
        let authority = Arc::new(
            BrokerDispatchAuthority::new()
                .map_err(|error| CompositionError::Kernel(error.to_string()))?,
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| CompositionError::Kernel(error.to_string()))?;
        let executor = WindowsProcessExecutor::new(authority.clone());
        Ok(Self {
            authority,
            executor,
            runtime,
            evidence: Arc::new(Mutex::new(Vec::new())),
            pending_requests: BTreeMap::new(),
        })
    }

    fn now_ms() -> Result<u64, PortError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| PortError::Invalid(error.to_string()))
            .and_then(|duration| {
                u64::try_from(duration.as_millis())
                    .map_err(|error| PortError::Invalid(error.to_string()))
            })
    }

    fn request_from_grant(&self, grant: &LaunchGrant) -> Result<ProcessRequest, PortError> {
        let now = Self::now_ms()?;
        if grant.expires_at <= now {
            return Err(PortError::Denied);
        }
        let intent = ProcessIntent::new(
            grant.approved.operation_id.clone(),
            grant.approved.process_tree_id.clone(),
            grant.approved.job_id.clone(),
            grant.approved.image_id.clone(),
            grant.approved.session_id.clone(),
            grant.approved.generation,
            grant.approved.executable.clone(),
            grant.approved.artifact_digest.clone(),
            grant.approved.argv.clone(),
            grant.approved.working_directory.clone(),
            grant.approved.environment.clone(),
            grant.approved.resource_limits,
        )
        .map_err(|error| PortError::Invalid(error.to_string()))?;
        self.authority.issue(&intent, grant, now)
    }

    fn map_error(error: ProcessExecutionError) -> PortError {
        match error {
            ProcessExecutionError::UnknownOutcome | ProcessExecutionError::NotFound => {
                PortError::Unknown
            }
            ProcessExecutionError::Unavailable(_detail) => PortError::Unavailable,
            ProcessExecutionError::Contract(error) => PortError::Invalid(error.to_string()),
            ProcessExecutionError::EvidenceSink(error) => PortError::Invalid(error.to_string()),
        }
    }
}

impl ProcessPort for LocalProcessPort {
    fn prepare_start(
        &mut self,
        grant: &LaunchGrant,
        _registration: &RegistrationReceipt,
    ) -> Result<String, PortError> {
        let request = self.request_from_grant(grant)?;
        let operation_id = request.operation_id().clone();
        let request_digest = request.invocation_digest().to_owned();
        if self
            .pending_requests
            .insert(operation_id, request)
            .is_some()
        {
            return Err(PortError::Invalid(
                "duplicate pending process start operation".to_owned(),
            ));
        }
        Ok(request_digest)
    }

    fn start(
        &mut self,
        grant: &LaunchGrant,
        _registration: &RegistrationReceipt,
        expected_request_digest: &str,
    ) -> Result<ProcessStartOutcome, PortError> {
        let request = self
            .pending_requests
            .remove(&grant.approved.operation_id)
            .ok_or_else(|| PortError::Invalid("process start was not prepared".to_owned()))?;
        let request_digest = request.invocation_digest().to_owned();
        if request_digest != expected_request_digest {
            return Err(PortError::Invalid(
                "prepared process request digest changed".to_owned(),
            ));
        }
        let sink = Arc::new(BrokerEvidenceSink {
            records: self.evidence.clone(),
        });
        match self.runtime.block_on(self.executor.start(request, sink)) {
            Ok(receipt) => Ok(ProcessStartOutcome::Started {
                request_digest,
                receipt,
            }),
            Err(ProcessExecutionError::UnknownOutcome) => {
                Ok(ProcessStartOutcome::Unknown { request_digest })
            }
            Err(error) => Err(Self::map_error(error)),
        }
    }

    fn inspect(&mut self, operation_id: &OperationId) -> Result<ProcessExecutionView, PortError> {
        self.runtime
            .block_on(self.executor.inspect(operation_id.clone()))
            .map_err(Self::map_error)
    }

    fn cancel(&mut self, operation_id: &OperationId) -> Result<CancellationReceipt, PortError> {
        self.runtime
            .block_on(self.executor.cancel(operation_id.clone()))
            .map_err(Self::map_error)
    }

    fn reconcile(&mut self, operation_id: &OperationId) -> Result<ProcessExecutionView, PortError> {
        self.runtime
            .block_on(self.executor.reconcile(operation_id.clone()))
            .map_err(Self::map_error)?;
        self.inspect(operation_id)
    }
}

struct FileRegistrationStore {
    path: PathBuf,
    #[cfg(windows)]
    platform: Option<WindowsPlatform>,
    #[cfg(windows)]
    lease: Option<ProtectedPathLease>,
    #[cfg(windows)]
    protected_relative: Option<PathBuf>,
}

impl FileRegistrationStore {
    fn open(_path: &Path) -> Result<Self, CompositionError> {
        Err(CompositionError::Protected(
            "durable broker state requires the retained protected ProgramData lease".to_owned(),
        ))
    }

    #[cfg(windows)]
    fn open_protected(path: &Path, relative: PathBuf) -> Result<Self, CompositionError> {
        let lease = ProtectedPathLease::open_or_create(&relative)
            .map_err(|error| CompositionError::Protected(error.to_string()))?;
        let canonical_path = fs::canonicalize(path).map_err(CompositionError::Durable)?;
        if lease.path() != canonical_path {
            return Err(CompositionError::Protected(
                "snapshot path is not the retained protected object".to_owned(),
            ));
        }
        let parent = canonical_path
            .parent()
            .ok_or_else(|| CompositionError::Protected("snapshot has no parent".to_owned()))?;
        let platform = WindowsPlatform::new(parent)
            .map_err(|error| CompositionError::Protected(error.to_string()))?;
        Ok(Self {
            path: canonical_path,
            platform: Some(platform),
            lease: Some(lease),
            protected_relative: Some(relative),
        })
    }

    #[cfg(windows)]
    fn read_verified_lease(
        lease: &ProtectedPathLease,
        path: &Path,
        post_publication: bool,
    ) -> Result<Vec<u8>, PortError> {
        let verify = lease
            .verify_stable_identity()
            .and_then(|()| lease.verify_path_identity());
        if let Err(error) = verify {
            return Err(if post_publication {
                PortError::Unknown
            } else {
                PortError::Invalid(error.to_string())
            });
        }
        lease.read_bounded(SNAPSHOT_LIMIT).map_err(|error| {
            if post_publication {
                PortError::Unknown
            } else {
                PortError::Invalid(format!("read {}: {error}", path.display()))
            }
        })
    }

    #[cfg(windows)]
    fn decode_snapshot(bytes: &[u8], path: &Path) -> Result<Option<BrokerSnapshot>, PortError> {
        if bytes.is_empty() {
            return Ok(None);
        }
        serde_json::from_slice(bytes)
            .map(Some)
            .map_err(|error| PortError::Invalid(format!("decode {}: {error}", path.display())))
    }

    /// Reacquires the exact protected object after an atomic publication.
    ///
    /// The replacement lease is installed before any result is returned.  A
    /// successful open whose identity/read proof fails is still retained so
    /// the next operation cannot accidentally fall back to an unprotected
    /// path; all later operations re-verify that retained handle.
    #[cfg(windows)]
    fn reacquire_after_publication(&mut self, relative: &Path) -> Result<Vec<u8>, PortError> {
        let Ok(replacement) = ProtectedPathLease::open_or_create(relative) else {
            // The old lease had to be released before replacement.  An
            // unavailable replacement is therefore an explicit unknown
            // state, never a successful save or a retryable failure.
            self.lease = None;
            return Err(PortError::Unknown);
        };
        let result = Self::read_verified_lease(&replacement, &self.path, true);
        self.lease = Some(replacement);
        result
    }
}

impl DurableRegistrationPort for FileRegistrationStore {
    fn load(&mut self) -> Result<Option<BrokerSnapshot>, PortError> {
        #[cfg(windows)]
        let bytes = {
            let lease = self.lease.as_ref().ok_or(PortError::Unavailable)?;
            lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|error| PortError::Invalid(error.to_string()))?;
            match lease.read_bounded(SNAPSHOT_LIMIT) {
                Ok(bytes) => bytes,
                Err(error) => return Err(PortError::Invalid(error.to_string())),
            }
        };
        #[cfg(not(windows))]
        return Err(PortError::Unavailable);
        if bytes.is_empty() {
            return Ok(None);
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| PortError::Invalid(format!("decode {}: {error}", self.path.display())))
    }

    fn save(&mut self, snapshot: &BrokerSnapshot) -> Result<(), PortError> {
        let bytes = serde_json::to_vec(snapshot)
            .map_err(|error| PortError::Invalid(format!("encode snapshot: {error}")))?;
        #[cfg(windows)]
        {
            let relative = self
                .protected_relative
                .as_ref()
                .ok_or(PortError::Unavailable)?
                .clone();
            let previous_bytes = {
                let lease = self.lease.as_ref().ok_or(PortError::Unavailable)?;
                Self::read_verified_lease(lease, &self.path, false)?
            };
            let previous = Self::decode_snapshot(&previous_bytes, &self.path)?;
            let scope_name = self
                .path
                .file_name()
                .ok_or(PortError::Invalid("snapshot filename missing".to_owned()))?
                .to_string_lossy()
                .into_owned();
            let scope = WorkScopePath::new(scope_name)
                .map_err(|error| PortError::Invalid(error.to_string()))?;

            // The old no-delete-sharing lease must be released for the
            // atomic replacement.  From this point onward there are no `?`
            // exits until the replacement has been retained again.
            let lease = self.lease.take().ok_or(PortError::Unavailable)?;
            drop(lease);
            if let Some(platform) = self.platform.as_ref() {
                let _ = platform.publish_atomic(&scope, &bytes);
            }

            let current_bytes = self.reacquire_after_publication(&relative)?;
            let current = Self::decode_snapshot(&current_bytes, &self.path)?;
            if current.as_ref() == Some(snapshot) {
                // The publish response may have been lost, but the exact
                // desired bytes are now durable and can be acknowledged.
                return Ok(());
            }
            if current == previous {
                return Err(PortError::Unknown);
            }
            // Any other bytes are an unresolvable publication race. Do not
            // classify this as a deterministic provider failure: the caller
            // must reconcile the exact registration snapshot before retrying.
            Err(PortError::Unknown)
        }
        #[cfg(not(windows))]
        {
            let _ = bytes;
            Err(PortError::Unavailable)
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BrokerReadiness<'a> {
    pub service: &'a str,
    pub protocol: &'a str,
    pub registration_state: &'static str,
    pub missing_providers: Vec<RequiredProvider>,
    pub snapshot: String,
}

pub struct BrokerComposition {
    broker: UserBroker,
    snapshot: PathBuf,
    kernel_client: Option<SharedKernelClient>,
    providers_admitted: bool,
    launch_config: Option<BrokerLaunchConfig>,
    launch_lease: Option<ProtectedPathLease>,
    registration_digest: Option<String>,
}

impl BrokerComposition {
    pub fn start(config: BrokerConfig) -> Result<Self, CompositionError> {
        Self::start_with_kernel(config)
    }

    /// Starts the production binary composition with an authenticated Kernel
    /// front door. The binary never substitutes a local authority/process
    /// provider when this composition is unavailable.
    pub fn start_with_kernel(config: BrokerConfig) -> Result<Self, CompositionError> {
        let (launch_config, launch_lease) = load_protected_launch_config()?;
        let client = eliot_cli::kernel_client::KernelClient::load()
            .map_err(|error| CompositionError::Kernel(error.to_string()))?;
        let client = Arc::new(Mutex::new(client));
        let process = LocalProcessPort::new()?;
        Self::start_with_ports(
            config,
            Some(Box::new(KernelAuthorityPort {
                client: client.clone(),
            })),
            Some(Box::new(process)),
            Some(client),
            Some((launch_config, launch_lease)),
        )
    }

    fn start_with_ports(
        config: BrokerConfig,
        authority: Option<Box<dyn AuthorityPort>>,
        process: Option<Box<dyn ProcessPort>>,
        kernel_client: Option<SharedKernelClient>,
        launch: Option<(BrokerLaunchConfig, ProtectedPathLease)>,
    ) -> Result<Self, CompositionError> {
        config.validate()?;
        let snapshot = config.data_root.join(config.snapshot_name);
        #[cfg(windows)]
        let mut durable = if launch.is_some() {
            let relative = PathBuf::from(SNAPSHOT_RELATIVE_DIRECTORY).join(
                snapshot.file_name().ok_or_else(|| {
                    CompositionError::InvalidConfiguration("snapshot filename missing".to_owned())
                })?,
            );
            FileRegistrationStore::open_protected(&snapshot, relative)?
        } else {
            FileRegistrationStore::open(&snapshot)?
        };
        #[cfg(not(windows))]
        let mut durable = FileRegistrationStore::open(&snapshot)?;
        if durable
            .load()
            .map_err(|error| CompositionError::InvalidConfiguration(error.to_string()))?
            .is_none()
        {
            durable
                .save(&BrokerSnapshot {
                    registration: None,
                    user_broker_epoch: 0,
                    operation_cursors: Vec::new(),
                })
                .map_err(|error| CompositionError::InvalidConfiguration(error.to_string()))?;
        }
        let providers_admitted = authority.is_some() && process.is_some();
        let mut broker = UserBroker::new(authority, process, Some(Box::new(durable)));
        broker.recover().map_err(CompositionError::Recovery)?;
        let registration_digest = broker.registration_digest().map(ToOwned::to_owned);
        let (launch_config, launch_lease) =
            launch.map_or((None, None), |(config, lease)| (Some(config), Some(lease)));
        Ok(Self {
            broker,
            snapshot,
            kernel_client,
            providers_admitted,
            launch_config,
            launch_lease,
            registration_digest,
        })
    }

    pub fn readiness(&self) -> BrokerReadiness<'_> {
        BrokerReadiness {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            registration_state: "RECOVERED",
            missing_providers: if self.providers_admitted {
                Vec::new()
            } else {
                vec![RequiredProvider::G01Authority, RequiredProvider::P03Process]
            },
            snapshot: self.snapshot.display().to_string(),
        }
    }

    /// Performs broker self-authentication from the retained installation
    /// declaration, then registers or refreshes the recovered lease.  No
    /// caller-provided registration tuple is accepted by this boundary.
    pub fn self_register(&mut self) -> Result<(), CompositionError> {
        self.verify_launch_lease()?;
        let launch = self.launch_config.clone().ok_or_else(|| {
            CompositionError::Launch("protected launch configuration is not composed".to_owned())
        })?;
        self.set_request_identity(launch.request_identity.clone())?;
        if self.broker.registration_digest().is_some() {
            let receipt = self.heartbeat()?;
            self.registration_digest = Some(receipt.registration_digest);
        } else {
            let receipt = self
                .broker
                .register(launch.registration.clone())
                .map_err(CompositionError::Recovery)?;
            self.registration_digest = Some(receipt.registration_digest);
        }
        Ok(())
    }

    /// Refreshes the exact protected registration lease; the stdin protocol
    /// cannot manufacture or submit a heartbeat identity.
    pub fn heartbeat(&mut self) -> Result<HeartbeatReceipt, CompositionError> {
        self.verify_launch_lease()?;
        let registration_digest = self
            .registration_digest
            .clone()
            .or_else(|| self.broker.registration_digest().map(ToOwned::to_owned))
            .ok_or_else(|| CompositionError::Launch("broker is not registered".to_owned()))?;
        let observed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| CompositionError::Launch(error.to_string()))?
            .as_millis()
            .try_into()
            .map_err(|error| CompositionError::Launch(format!("clock overflow: {error}")))?;
        let receipt = self
            .broker
            .heartbeat(HeartbeatRequest {
                registration_digest,
                observed_at,
            })
            .map_err(CompositionError::Recovery)?;
        self.registration_digest = Some(receipt.registration_digest.clone());
        Ok(receipt)
    }

    /// Closes the authenticated registration before the broker process exits.
    ///
    /// A clean stdin EOF and an admitted `stop` operation use the same durable
    /// close path; dropping the composition alone must never leave an active
    /// registration lease for the next process instance.
    pub fn close(&mut self) -> Result<(), CompositionError> {
        self.verify_launch_lease()?;
        self.broker.logoff().map_err(CompositionError::Recovery)?;
        self.registration_digest = None;
        Ok(())
    }

    /// Heartbeats the protected registration before an admitted launch.
    pub fn launch(
        &mut self,
        request: LaunchRequest,
    ) -> Result<eliot_user_broker_core::LaunchReceipt, CompositionError> {
        let _ = self.heartbeat()?;
        self.broker
            .launch(request)
            .map_err(CompositionError::Recovery)
    }

    /// Cancels a broker-owned operation selected by its admitted operation
    /// identity.  The sealed operation permit remains inside `UserBroker`.
    pub fn cancel(
        &mut self,
        operation_id: &OperationId,
    ) -> Result<CancellationReceipt, CompositionError> {
        self.verify_launch_lease()?;
        self.broker
            .cancel_operation(operation_id)
            .map_err(CompositionError::Recovery)
    }

    /// Reconciles a broker-owned operation selected by its admitted operation
    /// identity.  No caller-supplied P-03 request or permit crosses stdin.
    pub fn reconcile(
        &mut self,
        operation_id: &OperationId,
    ) -> Result<ProcessExecutionView, CompositionError> {
        self.verify_launch_lease()?;
        self.broker
            .reconcile_operation(operation_id)
            .map_err(CompositionError::Recovery)
    }

    fn verify_launch_lease(&self) -> Result<(), CompositionError> {
        if let Some(lease) = &self.launch_lease {
            lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|error| CompositionError::Protected(error.to_string()))?;
        }
        Ok(())
    }

    /// Binds the current EBP request identity before one provider operation.
    fn set_request_identity(&mut self, identity: RequestIdentity) -> Result<(), CompositionError> {
        let client = self.kernel_client.as_ref().ok_or_else(|| {
            CompositionError::Kernel("Kernel front door is not composed".to_owned())
        })?;
        client
            .lock()
            .map_err(|_| CompositionError::KernelLock)?
            .set_request_identity(identity);
        Ok(())
    }
}

pub fn canonical_root(path: &Path) -> Result<PathBuf, CompositionError> {
    fs::canonicalize(path).map_err(CompositionError::Durable)
}

pub fn snapshot_digest(path: &Path) -> Result<String, CompositionError> {
    let mut file = File::open(path).map_err(CompositionError::Durable)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(CompositionError::Durable)?;
    let mut digest = Sha256::new();
    digest.update(bytes);
    Ok(format!("{:x}", digest.finalize()))
}
