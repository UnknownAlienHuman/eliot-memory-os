//! Pure `BlobRef` validation/path cell extracted from `crates/eliot-store/src/blob_store.rs`.
//!
//! Owns only [`validate_blob_ref`] and [`expected_blob_relative_path`] — the
//! content-addressed `BlobRef` integrity gate (`algorithm == "blake3"`,
//! 64-char lower-hex `digest_hex`, canonical relative path `{xx}/{rest}.blob`).
//! No canonical-store capacity validators, segment IDs (`canonical_segment_id`),
//! `BlobStore` lifecycle/write ownership, staged/write ingress plans, filesystem
//! I/O, credentials/security, provider/lifecycle, or frozen/Luna/Dreamer
//! semantics. Parent `blob_store` retains all I/O and write authority.
//!
//! Architecture: A13.8 Integrity — periodic integrity review checks canonical
//! references and receipts; this cell enforces the blob-reference leg before
//! `BlobStore::read_verified` touches the filesystem.
//! Implementation: I16.1 Four surfaces (durable audit vs operational logs —
//! this is a pure validation helper, not a surface) and I2.23 Capability-family
//! topology / I5.2 `BlobStore` bridge handles — the store-neutral `BlobStore`
//! (`BlobRef` in `crates/eliot-types`) has no canonical semantic or DB
//! authority and exposes only scoped stage/read operations. This child has
//! **no canonical or write authority**; it only validates references/paths.
//! Mechanical split — exact behavior and signatures preserved from
//! `crates/eliot-store/src/blob_store.rs`.

use crate::StoreError;
use eliot_types::BlobRef;
use std::path::{Path, PathBuf};

pub(super) fn validate_blob_ref(blob: &BlobRef) -> Result<(), StoreError> {
    if blob.algorithm != "blake3"
        || blob.digest_hex.len() != 64
        || !blob
            .digest_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StoreError::PolicyViolation(
            "blob reference algorithm or digest is invalid".to_owned(),
        ));
    }
    let expected = expected_blob_relative_path(&blob.digest_hex);
    if Path::new(&blob.relative_path) != expected {
        return Err(StoreError::PolicyViolation(
            "blob reference path is not the canonical digest path".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn expected_blob_relative_path(digest_hex: &str) -> PathBuf {
    let (prefix, suffix) = digest_hex.split_at(2);
    PathBuf::from(prefix).join(format!("{suffix}.blob"))
}
