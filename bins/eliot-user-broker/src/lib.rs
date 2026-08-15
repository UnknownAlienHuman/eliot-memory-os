//! Production composition root for the A-09 user broker.
//!
//! The binary owns only process lifetime and durable registration wiring. G-01
//! and P-04 remain explicit provider boundaries; this root never manufactures
//! authority or process evidence when those providers are not composed.

#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use eliot_user_broker_core::{
    BrokerError, BrokerSnapshot, DurableRegistrationPort, PortError, RequiredProvider, UserBroker,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SERVICE_NAME: &str = "eliot-user-broker";
pub const PROTOCOL_VERSION: &str = "eliot.user-broker.v1";
pub const PLAN_GAP_EXIT: i32 = 78;

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
}

impl BrokerComposition {
    pub fn start(config: BrokerConfig) -> Result<Self, CompositionError> {
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
        let mut broker = UserBroker::new(None, None, Some(Box::new(durable)));
        broker.recover().map_err(CompositionError::Recovery)?;
        Ok(Self { broker, snapshot })
    }

    pub fn readiness(&self) -> BrokerReadiness<'_> {
        BrokerReadiness {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            registration_state: "RECOVERED",
            missing_providers: vec![RequiredProvider::G01Authority, RequiredProvider::P03Process],
            snapshot: self.snapshot.display().to_string(),
        }
    }

    pub fn broker(&mut self) -> &mut UserBroker {
        &mut self.broker
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
