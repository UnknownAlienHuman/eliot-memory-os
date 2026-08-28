use std::cmp::Ordering;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{MAX_PACKAGE_PATH_DEPTH, PackageStagingError};

/// A validated relative package path using `/` as its canonical separator.
///
/// The constructor rejects absolute, UNC, device, NT and verbatim forms;
/// colon/ADS syntax; empty, dot and parent components; and Windows-invalid
/// trailing dots or spaces.  Comparison of components uses Windows ordinal
/// case-insensitive semantics on Windows.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageRelativePath {
    pub(super) canonical: String,
    pub(super) components: Vec<String>,
}

impl PackageRelativePath {
    /// Returns the canonical slash-separated path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// Returns the validated path components.
    #[must_use]
    pub fn components(&self) -> &[String] {
        &self.components
    }

    pub(super) fn join_to(&self, root: &Path) -> PathBuf {
        self.components
            .iter()
            .fold(root.to_path_buf(), |mut path, component| {
                path.push(component);
                path
            })
    }
}

/// Validate one package-relative path and return its canonical representation.
///
/// # Errors
///
/// Returns [`PackageStagingError::InvalidRelativePath`] for any absolute,
/// device, ADS, dot, parent, empty or trailing-dot/space form.
pub fn validate_package_relative_path(
    path: &Path,
) -> Result<PackageRelativePath, PackageStagingError> {
    let raw = path
        .to_str()
        .ok_or(PackageStagingError::InvalidRelativePath)?;
    validate_relative_text(raw)
}

pub(super) fn validate_relative_text(
    raw: &str,
) -> Result<PackageRelativePath, PackageStagingError> {
    if raw.is_empty()
        || raw.contains('\0')
        || raw.starts_with('/')
        || raw.starts_with('\\')
        || raw.starts_with("//")
        || raw.starts_with("\\\\")
    {
        return Err(PackageStagingError::InvalidRelativePath);
    }
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("\\?\\")
        || lower.starts_with("//?/")
        || lower.starts_with("\\.\\")
        || lower.starts_with("//./")
        || lower.starts_with("\\??\\")
        || lower.starts_with("/??/")
        || lower.starts_with("nt\\")
        || lower.starts_with("nt/")
    {
        return Err(PackageStagingError::InvalidRelativePath);
    }

    let mut components = Vec::new();
    for component in raw.split(['/', '\\']) {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.contains(':')
            || component.chars().any(char::is_control)
            || component.ends_with('.')
            || component.ends_with(' ')
            || is_windows_device_name(component)
        {
            return Err(PackageStagingError::InvalidRelativePath);
        }
        components.push(component.to_owned());
        if components.len() > MAX_PACKAGE_PATH_DEPTH {
            return Err(PackageStagingError::BoundExceeded);
        }
    }
    if components.is_empty() {
        return Err(PackageStagingError::InvalidRelativePath);
    }

    Ok(PackageRelativePath {
        canonical: components.join("/"),
        components,
    })
}

/// Return whether a path component names a DOS device rather than a regular
/// filesystem entry.  Windows applies these names even when an extension is
/// present (for example, `NUL.txt`), so the comparison uses the text before
/// the first dot.
pub(super) fn is_windows_device_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "CLOCK$"
            | "COM¹"
            | "COM²"
            | "COM³"
            | "LPT¹"
            | "LPT²"
            | "LPT³"
    ) || (upper.len() == 4
        && (upper.starts_with("COM") || upper.starts_with("LPT"))
        && upper.as_bytes()[3].is_ascii_digit()
        && upper.as_bytes()[3] != b'0')
}

pub fn ordinal_component_cmp(left: &str, right: &str) -> Ordering {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;
        use windows_sys::Win32::Globalization::{CSTR_EQUAL, CSTR_LESS_THAN, CompareStringOrdinal};

        let left: Vec<u16> = std::ffi::OsStr::new(left).encode_wide().collect();
        let right: Vec<u16> = std::ffi::OsStr::new(right).encode_wide().collect();
        let Ok(left_len) = i32::try_from(left.len()) else {
            return Ordering::Greater;
        };
        let Ok(right_len) = i32::try_from(right.len()) else {
            return Ordering::Less;
        };
        let result =
            unsafe { CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) };
        match result {
            CSTR_LESS_THAN => Ordering::Less,
            CSTR_EQUAL => Ordering::Equal,
            _ => Ordering::Greater,
        }
    }
    #[cfg(not(windows))]
    {
        left.to_lowercase().cmp(&right.to_lowercase())
    }
}

pub fn ordinal_path_cmp(left: &PackageRelativePath, right: &PackageRelativePath) -> Ordering {
    left.components
        .iter()
        .zip(&right.components)
        .map(|(left, right)| ordinal_component_cmp(left, right))
        .find(|ordering| *ordering != Ordering::Equal)
        .unwrap_or_else(|| left.components.len().cmp(&right.components.len()))
}

pub fn ordinal_path_eq(left: &PackageRelativePath, right: &PackageRelativePath) -> bool {
    left.components.len() == right.components.len()
        && left
            .components
            .iter()
            .zip(&right.components)
            .all(|(left, right)| ordinal_component_cmp(left, right) == Ordering::Equal)
}

pub fn ordinal_cmp_str(a: &str, b: &str) -> Ordering {
    let left = validate_relative_text(a);
    let right = validate_relative_text(b);
    match (left, right) {
        (Ok(l), Ok(r)) => ordinal_path_cmp(&l, &r),
        _ => a.to_lowercase().cmp(&b.to_lowercase()),
    }
}

pub fn ordinal_eq_str(a: &str, b: &str) -> bool {
    ordinal_cmp_str(a, b) == Ordering::Equal
}
