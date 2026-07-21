use crate::StoreError;
use eliot_types::{BlobRef, BlobStoreConfig, inspect_secret_bytes};
use std::path::{Path, PathBuf};

pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    pub fn open(config: &BlobStoreConfig) -> Result<Self, StoreError> {
        let root = PathBuf::from(&config.root);
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn put_bytes(&self, bytes: &[u8]) -> Result<BlobRef, StoreError> {
        inspect_secret_bytes(bytes).map_err(|violation| {
            StoreError::PolicyViolation(format!(
                "secret boundary rejected blob ingress: {}",
                violation.rule
            ))
        })?;
        let digest_hex = blake3::hash(bytes).to_hex().to_string();
        let size_bytes = u64::try_from(bytes.len()).map_err(|_| StoreError::BlobTooLarge)?;
        let (prefix, suffix) = digest_hex.split_at(2);
        let relative_path = format!("{prefix}/{suffix}.blob");
        let path = self.root.join(Path::new(&relative_path));

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        if path.exists() {
            let existing_bytes = std::fs::read(&path)?;
            let existing_digest_hex = blake3::hash(&existing_bytes).to_hex().to_string();
            if existing_digest_hex != digest_hex {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("existing blob at {} has an invalid digest", path.display()),
                )
                .into());
            }
        } else {
            std::fs::write(&path, bytes)?;
        }

        Ok(BlobRef {
            algorithm: "blake3".to_owned(),
            digest_hex,
            size_bytes,
            relative_path,
        })
    }

    pub fn blob_path(&self, blob: &BlobRef) -> PathBuf {
        self.root.join(Path::new(&blob.relative_path))
    }
}

#[cfg(test)]
mod tests {
    use super::BlobStore;
    use crate::StoreError;
    use eliot_types::BlobStoreConfig;

    #[test]
    fn stores_blob_by_content_hash() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir =
            std::env::temp_dir().join(format!("eliot-governor-blob-test-{}", std::process::id()));

        let store = BlobStore::open(&BlobStoreConfig {
            root: temp_dir.display().to_string(),
        })?;
        let blob = store.put_bytes(b"hello")?;
        let bytes = std::fs::read(store.blob_path(&blob))?;

        assert_eq!(bytes, b"hello");

        let _ = std::fs::remove_dir_all(temp_dir);
        Ok(())
    }

    #[test]
    fn rejects_corrupt_existing_content_addressed_blob() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = std::env::temp_dir().join(format!(
            "eliot-governor-corrupt-existing-blob-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = BlobStore::open(&BlobStoreConfig {
            root: temp_dir.display().to_string(),
        })?;
        let blob = store.put_bytes(b"expected")?;
        let path = store.blob_path(&blob);
        std::fs::write(&path, b"corrupt")?;

        let Err(error) = store.put_bytes(b"expected") else {
            return Err("corrupt blob was accepted".into());
        };
        assert!(matches!(
            error,
            StoreError::Io(error) if error.kind() == std::io::ErrorKind::InvalidData
        ));
        assert_eq!(std::fs::read(path)?, b"corrupt");

        let _ = std::fs::remove_dir_all(temp_dir);
        Ok(())
    }

    #[test]
    fn rejects_secret_before_hash_or_persistence() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = std::env::temp_dir().join(format!(
            "eliot-governor-secret-blob-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_dir);
        let store = BlobStore::open(&BlobStoreConfig {
            root: temp_dir.display().to_string(),
        })?;
        let Some(error) = store
            .put_bytes(b"Authorization: Bearer synthetic-token-value-12345")
            .err()
        else {
            return Err(std::io::Error::other("secret-bearing blob was accepted").into());
        };
        assert!(matches!(error, StoreError::PolicyViolation(_)));
        assert!(std::fs::read_dir(&temp_dir)?.next().is_none());
        std::fs::remove_dir(temp_dir)?;
        Ok(())
    }
}
