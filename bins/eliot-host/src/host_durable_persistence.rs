//! Host journal durability helpers shared by runtime-restart and store-recovery.
//!
//! The helper keeps the Windows power-loss contract in one place: durable
//! file bytes via a writable handle and checked `sync_all`, and durable
//! directory entries via the shared `eliot_platform_windows::sync_directory_for_publication`
//! contract from Issue 334. Every I/O error from directory publication is
//! propagated as `HostError::Platform` — the former private
//! `InvalidInput`/`PermissionDenied`/`Unsupported => Ok(())` swallow is
//! deliberately removed so a failed directory sync can never be misreported
//! as durable publication nor allow evidence removal.

#![forbid(unsafe_code)]

use std::path::Path;

use super::HostError;

#[cfg(windows)]
pub(super) fn sync_dir(dir: &Path) -> Result<(), HostError> {
    #[cfg(test)]
    {
        if let Some(kind) = test_fault::take_sync_fault_if_set() {
            ordering::record("dir_sync_fault_injected");
            return Err(HostError::Platform(format!(
                "injected durability fault {:?} for {}",
                kind,
                dir.display()
            )));
        }
        if let Ok(val) = std::env::var("ELIOT_HOST_SYNC_FAULT") {
            let kind = match val.as_str() {
                "PermissionDenied" => std::io::ErrorKind::PermissionDenied,
                "InvalidInput" => std::io::ErrorKind::InvalidInput,
                "Unsupported" => std::io::ErrorKind::Unsupported,
                _ => std::io::ErrorKind::Other,
            };
            ordering::record("dir_sync_env_fault");
            return Err(HostError::Platform(format!(
                "injected durability fault via env {kind:?} for {}",
                dir.display()
            )));
        }
        ordering::record("dir_sync_attempt");
    }
    let result = eliot_platform_windows::sync_directory_for_publication(dir)
        .map_err(|error| HostError::Platform(error.to_string()));
    #[cfg(test)]
    {
        if result.is_ok() {
            ordering::record("dir_sync_success");
        } else {
            ordering::record("dir_sync_error");
        }
    }
    result
}

#[cfg(windows)]
pub(super) fn write_durable_file(path: &Path, bytes: &[u8]) -> Result<(), HostError> {
    use std::io::Write;
    #[cfg(test)]
    ordering::record("file_write_start");
    let mut file =
        std::fs::File::create(path).map_err(|error| HostError::Platform(error.to_string()))?;
    file.write_all(bytes)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    file.sync_all()
        .map_err(|error| HostError::Platform(error.to_string()))?;
    #[cfg(test)]
    ordering::record("file_sync_success");
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_fault {
    use std::cell::Cell;
    use std::io::ErrorKind;

    thread_local! {
        static SYNC_FAULT: Cell<Option<ErrorKind>> = const { Cell::new(None) };
        static SYNC_FAULT_TAKEN: Cell<bool> = const { Cell::new(false) };
    }

    /// Inject the next `sync_dir` call to fail as `kind`. The fault is
    /// consumed once, so parallel tests using distinct threads remain isolated.
    pub fn inject_sync_fault(kind: ErrorKind) {
        SYNC_FAULT.with(|slot| slot.set(Some(kind)));
        SYNC_FAULT_TAKEN.with(|slot| slot.set(false));
    }

    /// Inject a fault that succeeds once then can be re-injected. Helper for
    /// multi-step flows where the first dir sync should succeed and the
    /// second (e.g. after cleanup) should fail.
    pub fn inject_next_sync_fault(kind: ErrorKind) {
        inject_sync_fault(kind);
    }

    pub fn clear_sync_fault() {
        SYNC_FAULT.with(|slot| slot.set(None));
        SYNC_FAULT_TAKEN.with(|slot| slot.set(false));
    }

    pub(crate) fn take_sync_fault_if_set() -> Option<ErrorKind> {
        SYNC_FAULT.with(|slot| {
            let taken = SYNC_FAULT_TAKEN.with(std::cell::Cell::get);
            if taken {
                return None;
            }
            let value = slot.get();
            if value.is_some() {
                slot.set(None);
                SYNC_FAULT_TAKEN.with(|t| t.set(true));
            }
            value
        })
    }
}

#[cfg(test)]
pub(crate) mod ordering {
    use std::cell::RefCell;

    thread_local! {
        static LOG: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    pub fn record(event: &str) {
        LOG.with(|log| log.borrow_mut().push(event.to_owned()));
    }

    pub fn take_log() -> Vec<String> {
        LOG.with(|log| std::mem::take(&mut *log.borrow_mut()))
    }

    pub fn clear() {
        LOG.with(|log| log.borrow_mut().clear());
    }
}
