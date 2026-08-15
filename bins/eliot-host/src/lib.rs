#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use eliot_host_state::{
    BackendError, BackendReconcileState, DurableImage, HostInstallationEpoch, HostState,
    HostStateJournal, IdempotencyIdentity, JournalBackend, PreparedAppend, StoredEpoch,
};
use eliot_platform::PlatformHandle;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SERVICE_NAME: &str = "eliot-host";
pub const PROTOCOL_VERSION: &str = "eliot.host.v1";

#[derive(Debug, Error)]
pub enum HostError {
    #[error("host state journal: {0}")]
    Journal(#[from] eliot_host_state::JournalError),
    #[error("backend: {0}")]
    Backend(#[from] BackendError),
    #[error("state file: {0}")]
    Io(#[from] io::Error),
    #[error("state file encoding: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("host is already stopped")]
    Stopped,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DiskImage {
    image: DurableImageWire,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DurableImageWire {
    epochs: Vec<StoredEpochWire>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredEpochWire {
    host: HostInstallationEpoch,
    bytes: Vec<u8>,
}

impl From<DurableImage> for DurableImageWire {
    fn from(image: DurableImage) -> Self {
        Self {
            epochs: image
                .epochs
                .into_iter()
                .map(|epoch| StoredEpochWire {
                    host: epoch.host,
                    bytes: epoch.bytes,
                })
                .collect(),
        }
    }
}

impl From<DurableImageWire> for DurableImage {
    fn from(image: DurableImageWire) -> Self {
        Self {
            epochs: image
                .epochs
                .into_iter()
                .map(|epoch| StoredEpoch {
                    host: epoch.host,
                    bytes: epoch.bytes,
                })
                .collect(),
        }
    }
}

/// A file-backed transaction backend. The journal remains the sole owner of
/// state transitions; this adapter only supplies atomic durable bytes.
pub struct FileBackend {
    path: PathBuf,
    image: DurableImage,
    staged: Option<(PreparedAppend, Vec<u8>)>,
}

impl FileBackend {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, HostError> {
        let path = path.into();
        let image = if path.exists() {
            let bytes = fs::read(&path)?;
            serde_json::from_slice::<DiskImage>(&bytes)?.image.into()
        } else {
            DurableImage::default()
        };
        Ok(Self {
            path,
            image,
            staged: None,
        })
    }

    fn persist(&self) -> Result<(), BackendError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|error| BackendError::Failed(error.to_string()))?;
        let temporary = self.path.with_extension("tmp");
        let bytes = serde_json::to_vec(&DiskImage {
            image: self.image.clone().into(),
        })
        .map_err(|error| BackendError::Failed(error.to_string()))?;
        let mut file =
            File::create(&temporary).map_err(|error| BackendError::Failed(error.to_string()))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| BackendError::Failed(error.to_string()))?;
        fs::rename(temporary, &self.path).map_err(|error| BackendError::Failed(error.to_string()))
    }
}

impl JournalBackend for FileBackend {
    fn load(&mut self) -> Result<DurableImage, BackendError> {
        Ok(self.image.clone())
    }
    fn prepare(&mut self, append: &PreparedAppend) -> Result<(), BackendError> {
        if self.staged.is_some() {
            return Err(BackendError::Failed("append already staged".into()));
        }
        self.staged = Some((append.clone(), Vec::new()));
        Ok(())
    }
    fn append_prepared(
        &mut self,
        transaction_id: &PlatformHandle,
        bytes: &[u8],
    ) -> Result<(), BackendError> {
        let Some((append, payload)) = self.staged.as_mut() else {
            return Err(BackendError::Failed("append not prepared".into()));
        };
        if &append.transaction_id != transaction_id {
            return Err(BackendError::Failed("transaction identity mismatch".into()));
        }
        payload.extend_from_slice(bytes);
        Ok(())
    }
    fn flush(&mut self, _: &PlatformHandle) -> Result<(), BackendError> {
        Ok(())
    }
    fn sync(&mut self, _: &PlatformHandle) -> Result<(), BackendError> {
        Ok(())
    }
    fn commit(&mut self, transaction_id: &PlatformHandle) -> Result<(), BackendError> {
        let Some((append, bytes)) = self.staged.take() else {
            return Err(BackendError::Failed("append not prepared".into()));
        };
        if &append.transaction_id != transaction_id {
            return Err(BackendError::Failed("transaction identity mismatch".into()));
        }
        self.image.epochs.push(StoredEpoch {
            host: append.host,
            bytes,
        });
        self.persist()
    }
    fn reconcile(
        &mut self,
        transaction_id: &PlatformHandle,
    ) -> Result<BackendReconcileState, BackendError> {
        if self
            .staged
            .as_ref()
            .is_some_and(|(append, _)| &append.transaction_id == transaction_id)
        {
            Ok(BackendReconcileState::Prepared)
        } else {
            Ok(BackendReconcileState::Absent)
        }
    }
}

/// The Host composition root. It owns one journal and exposes only lifecycle
/// observations; Kernel remains the authority for service admission.
pub struct HostComposition {
    journal: HostStateJournal<FileBackend>,
    running: bool,
}

impl HostComposition {
    pub fn open(path: impl Into<PathBuf>, host: HostInstallationEpoch) -> Result<Self, HostError> {
        Ok(Self {
            journal: HostStateJournal::open(FileBackend::open(path)?, host)?,
            running: true,
        })
    }

    pub fn snapshot(&self) -> Result<HostState, HostError> {
        Ok(self.journal.snapshot()?)
    }
    pub fn stop(&mut self) -> Result<(), HostError> {
        if !self.running {
            return Err(HostError::Stopped);
        }
        self.running = false;
        Ok(())
    }
    #[must_use]
    pub const fn running(&self) -> bool {
        self.running
    }
}
