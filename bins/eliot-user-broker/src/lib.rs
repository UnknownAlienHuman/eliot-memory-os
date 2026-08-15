//! Production composition root for the A-09 user broker.
//!
//! The binary owns only process lifetime and durable registration wiring. G-01
//! and P-04 remain explicit provider boundaries; this root never manufactures
//! authority or process evidence when those providers are not composed.

#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use eliot_process::{
    CancellationReceipt, OperationId, ProcessExecutionView, ProcessRequest, ProcessStartReceipt,
};
use eliot_protocol::RequestIdentity;
use eliot_user_broker_core::{
    AuthorityPort, BrokerError, BrokerSnapshot, DurableRegistrationPort, LaunchGrant,
    LaunchRequest, PortError, ProcessPort, RegistrationGrant, RegistrationReceipt,
    RegistrationRequest, RequiredProvider, UserBroker,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SERVICE_NAME: &str = "eliot-user-broker";
pub const PROTOCOL_VERSION: &str = "eliot.user-broker.v1";

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
}

struct KernelProcessPort {
    client: SharedKernelClient,
}

impl ProcessPort for KernelProcessPort {
    fn start(&mut self, request: ProcessRequest) -> Result<ProcessStartReceipt, PortError> {
        kernel_call(
            &self.client,
            "eliot.user-broker.process-start",
            serde_json::to_value(request)
                .map_err(|error| PortError::Invalid(format!("encode process request: {error}")))?,
        )
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|error| PortError::Invalid(format!("decode process receipt: {error}")))
        })
    }

    fn inspect(&mut self, operation_id: &OperationId) -> Result<ProcessExecutionView, PortError> {
        kernel_call(
            &self.client,
            "eliot.user-broker.process-inspect",
            serde_json::json!({ "operation_id": operation_id }),
        )
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|error| PortError::Invalid(format!("decode process view: {error}")))
        })
    }

    fn cancel(&mut self, operation_id: &OperationId) -> Result<CancellationReceipt, PortError> {
        kernel_call(
            &self.client,
            "eliot.user-broker.process-cancel",
            serde_json::json!({ "operation_id": operation_id }),
        )
        .and_then(|value| {
            serde_json::from_value(value).map_err(|error| {
                PortError::Invalid(format!("decode cancellation receipt: {error}"))
            })
        })
    }
}

struct FileRegistrationStore {
    path: PathBuf,
}

impl FileRegistrationStore {
    fn open(path: PathBuf) -> Result<Self, CompositionError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(CompositionError::Durable)?;
        }
        Ok(Self { path })
    }
}

impl DurableRegistrationPort for FileRegistrationStore {
    fn load(&mut self) -> Result<Option<BrokerSnapshot>, PortError> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|error| {
                PortError::Invalid(format!("decode {}: {error}", self.path.display()))
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_error) => Err(PortError::Unavailable),
        }
    }

    fn save(&mut self, snapshot: &BrokerSnapshot) -> Result<(), PortError> {
        let bytes = serde_json::to_vec(snapshot)
            .map_err(|error| PortError::Invalid(format!("encode snapshot: {error}")))?;
        let temporary = self.path.with_extension("json.tmp");
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(|error| PortError::Invalid(format!("create snapshot temp: {error}")))?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|error| PortError::Invalid(format!("write snapshot: {error}")))?;
            drop(file);
            fs::rename(&temporary, &self.path)
                .map_err(|error| PortError::Invalid(format!("commit snapshot: {error}")))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
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
}

impl BrokerComposition {
    pub fn start(config: BrokerConfig) -> Result<Self, CompositionError> {
        Self::start_with_ports(config, None, None, None)
    }

    /// Starts the production binary composition with an authenticated Kernel
    /// front door. The binary never substitutes a local authority/process
    /// provider when this composition is unavailable.
    pub fn start_with_kernel(config: BrokerConfig) -> Result<Self, CompositionError> {
        let client = eliot_cli::kernel_client::KernelClient::load()
            .map_err(|error| CompositionError::Kernel(error.to_string()))?;
        let client = Arc::new(Mutex::new(client));
        Self::start_with_ports(
            config,
            Some(Box::new(KernelAuthorityPort {
                client: client.clone(),
            })),
            Some(Box::new(KernelProcessPort {
                client: client.clone(),
            })),
            Some(client),
        )
    }

    fn start_with_ports(
        config: BrokerConfig,
        authority: Option<Box<dyn AuthorityPort>>,
        process: Option<Box<dyn ProcessPort>>,
        kernel_client: Option<SharedKernelClient>,
    ) -> Result<Self, CompositionError> {
        config.validate()?;
        fs::create_dir_all(&config.data_root).map_err(CompositionError::Durable)?;
        let snapshot = config.data_root.join(config.snapshot_name);
        let mut durable = FileRegistrationStore::open(snapshot.clone())?;
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
        Ok(Self {
            broker,
            snapshot,
            kernel_client,
            providers_admitted,
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

    pub fn broker(&mut self) -> &mut UserBroker {
        &mut self.broker
    }

    /// Binds the current EBP request identity before one provider operation.
    pub fn set_request_identity(
        &mut self,
        identity: RequestIdentity,
    ) -> Result<(), CompositionError> {
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
