//! Versioned, bounded byte-run compression provider for BlobStore.

use eliot_blob_api::{BlobError, BlobId, CompressionDescriptor};

use crate::BlobCompressionPort;

/// Stable descriptor for the BlobStore byte-run codec.
pub const RLE_COMPRESSION_ALGORITHM: &str = "eliot-rle";
pub const RLE_COMPRESSION_VERSION: u32 = 1;

/// Deterministic run-length codec. Repeated bytes are encoded as `(count,
/// value)` pairs; decompression validates the complete pair stream and its
/// output bound before returning plaintext.
#[derive(Clone, Copy, Debug, Default)]
pub struct RleCompressionPort;

impl BlobCompressionPort for RleCompressionPort {
    fn descriptor(&mut self) -> Result<CompressionDescriptor, BlobError> {
        Ok(CompressionDescriptor {
            algorithm: BlobId::new(RLE_COMPRESSION_ALGORITHM)?,
            version: RLE_COMPRESSION_VERSION,
        })
    }

    fn compress(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, BlobError> {
        let mut compressed = Vec::new();
        let mut cursor = 0;
        while cursor < plaintext.len() {
            let value = plaintext[cursor];
            let mut count = 1_u8;
            while cursor.saturating_add(usize::from(count)) < plaintext.len()
                && plaintext[cursor.saturating_add(usize::from(count))] == value
                && count < u8::MAX
            {
                count += 1;
            }
            compressed.try_reserve(2).map_err(|_| {
                BlobError::Provider("Blob compression allocation failed".to_owned())
            })?;
            compressed.push(count);
            compressed.push(value);
            cursor += usize::from(count);
        }
        Ok(compressed)
    }

    fn decompress_bounded(
        &self,
        descriptor: &CompressionDescriptor,
        compressed: &[u8],
        max_output_bytes: u64,
    ) -> Result<Vec<u8>, BlobError> {
        descriptor.validate()?;
        if descriptor.algorithm.as_str() != RLE_COMPRESSION_ALGORITHM
            || descriptor.version != RLE_COMPRESSION_VERSION
        {
            return Err(BlobError::InvalidContract(
                "unsupported Blob compression descriptor".to_owned(),
            ));
        }
        if compressed.len() % 2 != 0 {
            return Err(BlobError::InvalidContract(
                "truncated Blob run-length payload".to_owned(),
            ));
        }
        let mut plaintext = Vec::new();
        let mut output_length = 0_u64;
        for pair in compressed.chunks_exact(2) {
            let count = pair[0];
            if count == 0 {
                return Err(BlobError::InvalidContract(
                    "zero-length Blob run is invalid".to_owned(),
                ));
            }
            output_length = output_length.checked_add(u64::from(count)).ok_or_else(|| {
                BlobError::InvalidContract("Blob decompression length overflow".to_owned())
            })?;
            if output_length > max_output_bytes {
                return Err(BlobError::InvalidContract(
                    "Blob decompression output ceiling exceeded".to_owned(),
                ));
            }
            plaintext.try_reserve(usize::from(count)).map_err(|_| {
                BlobError::Provider("Blob decompression allocation failed".to_owned())
            })?;
            plaintext.extend(std::iter::repeat_n(pair[1], usize::from(count)));
        }
        Ok(plaintext)
    }
}
