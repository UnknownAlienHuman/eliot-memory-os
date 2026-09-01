//! Canonical package manifest and file-spec serialization for Windows staging.
//!
//! Architecture: A2.3, A13.8, A13.12, ARCH-MOD-01, ARCH-MOD-02.
//! Implementation: I2.23, I3.12, I15.8.
//!
//! This cell owns only `PackageFileSpec`/`PackageManifest` and their direct
//! canonical serialization (`canonical_bytes`/`canonical_digest`) with private
//! helpers `append_u64`/`append_text`. Paths are validated through the parent
//! `validate_relative_text`/`ordinal_*` helpers, sorted with Windows ordinal
//! semantics, and digested via the shared parent helper `super::hex_digest`
//! (source-backed SHA-256 hex over raw canonical bytes). It does not own
//! `PackageRelativePath` grammar, PE/COFF, Authenticode, trusted-source/SCM,
//! no-follow/provider, installation ownership, or path-containment authority.

use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    MAX_PACKAGE_FILE_BYTES, MAX_PACKAGE_FILES, PackageStagingError, ordinal_path_cmp,
    ordinal_path_eq, validate_package_relative_path, validate_relative_text,
};

/// One manifest file admitted to a package stage.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFileSpec {
    /// Canonical slash-separated relative path.
    pub relative_path: String,
    /// Whether the file must parse as an AMD64 PE/COFF executable and pass
    /// the Authenticode gate.
    pub executable: bool,
    /// Exact expected byte size measured from the retained source handle.
    ///
    /// This is an identity binding, not an upper bound: a file with one byte
    /// more or less is a different package object and is rejected.
    pub expected_size: u64,
}

impl PackageFileSpec {
    /// Build one file specification after validating its path and exact size.
    ///
    /// # Errors
    ///
    /// Returns an error when the path or byte bound is invalid.
    pub fn new(
        relative_path: impl AsRef<Path>,
        executable: bool,
        expected_size: u64,
    ) -> Result<Self, PackageStagingError> {
        let relative_path = validate_package_relative_path(relative_path.as_ref())?;
        if expected_size == 0 || expected_size > MAX_PACKAGE_FILE_BYTES {
            return Err(PackageStagingError::BoundExceeded);
        }
        Ok(Self {
            relative_path: relative_path.as_str().to_owned(),
            executable,
            expected_size,
        })
    }
}

/// Canonical package manifest supplied by the installation coordinator.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageManifest {
    /// Relative generation root below the retained installation root.
    pub generation: String,
    /// Exact files expected under the generation root.
    pub files: Vec<PackageFileSpec>,
}

impl PackageManifest {
    /// Build and validate a manifest.  File order is not authority: canonical
    /// bytes sort paths with Windows ordinal component semantics.
    ///
    /// # Errors
    ///
    /// Returns an error when generation or file paths are invalid, duplicate,
    /// or exceed the bounded manifest limits.
    pub fn new(
        generation: impl AsRef<Path>,
        files: Vec<PackageFileSpec>,
    ) -> Result<Self, PackageStagingError> {
        let generation = validate_package_relative_path(generation.as_ref())?;
        let manifest = Self {
            generation: generation.as_str().to_owned(),
            files,
        };
        manifest.validate()
    }

    pub(super) fn validate(&self) -> Result<Self, PackageStagingError> {
        if self.files.len() > MAX_PACKAGE_FILES {
            return Err(PackageStagingError::BoundExceeded);
        }
        let generation = validate_relative_text(&self.generation)?;
        let mut files = Vec::with_capacity(self.files.len());
        for file in &self.files {
            let path = validate_relative_text(&file.relative_path)?;
            if file.expected_size == 0 || file.expected_size > MAX_PACKAGE_FILE_BYTES {
                return Err(PackageStagingError::BoundExceeded);
            }
            files.push((path, file));
        }
        files.sort_by(|left, right| ordinal_path_cmp(&left.0, &right.0));
        for pair in files.windows(2) {
            if ordinal_path_eq(&pair[0].0, &pair[1].0) {
                return Err(PackageStagingError::ManifestCollision);
            }
        }
        let files = files
            .into_iter()
            .map(|(path, file)| PackageFileSpec {
                relative_path: path.as_str().to_owned(),
                executable: file.executable,
                expected_size: file.expected_size,
            })
            .collect();
        Ok(Self {
            generation: generation.as_str().to_owned(),
            files,
        })
    }

    /// Return stable canonical bytes for receipt binding.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let validated = self.validate().unwrap_or_else(|_| self.clone());
        let mut bytes = b"ELIOT-PACKAGE-MANIFEST\0v1\0".to_vec();
        append_text(&mut bytes, &validated.generation);
        append_u64(&mut bytes, validated.files.len() as u64);
        for file in validated.files {
            append_text(&mut bytes, &file.relative_path);
            bytes.push(u8::from(file.executable));
            append_u64(&mut bytes, file.expected_size);
        }
        bytes
    }

    /// Return the lowercase SHA-256 digest of [`Self::canonical_bytes`].
    #[must_use]
    pub fn canonical_digest(&self) -> String {
        super::hex_digest(&self.canonical_bytes())
    }
}

fn append_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_text(bytes: &mut Vec<u8>, value: &str) {
    append_u64(bytes, value.len() as u64);
    bytes.extend_from_slice(value.as_bytes());
}
