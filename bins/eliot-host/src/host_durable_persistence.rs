//! Private Host journal durability helpers shared by runtime-restart and store-recovery.
//!
//! The helper keeps the Windows power-loss contract in one place: durable
//! file bytes via a writable handle and checked `sync_all`, and durable
//! directory entries via `FILE_FLAG_BACKUP_SEMANTICS` and checked `sync_all`.
//! Filesystems that explicitly report `InvalidInput`, `PermissionDenied` or
//! `Unsupported` for directory open/sync remain the tolerated branch; every
//! other I/O error fails closed as `HostError::Platform`.

use std::path::Path;

use super::HostError;

#[cfg(windows)]
pub(super) fn sync_dir(dir: &Path) -> Result<(), HostError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)
    {
        Ok(file) => file,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::InvalidInput
                    | std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::Unsupported
            ) =>
        {
            return Ok(());
        }
        Err(error) => return Err(HostError::Platform(error.to_string())),
    };
    match file.sync_all() {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::InvalidInput
                    | std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::Unsupported
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(HostError::Platform(error.to_string())),
    }
}

#[cfg(windows)]
pub(super) fn write_durable_file(path: &Path, bytes: &[u8]) -> Result<(), HostError> {
    use std::io::Write;
    let mut file =
        std::fs::File::create(path).map_err(|error| HostError::Platform(error.to_string()))?;
    file.write_all(bytes)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    file.sync_all()
        .map_err(|error| HostError::Platform(error.to_string()))?;
    Ok(())
}
