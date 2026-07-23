use crate::{ProjectId, inspect_text_encoding};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

use super::normalize::{normalize_path, normalize_symbol};

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CueKind {
    FilePath,
    DirPath,
    Symbol,
    ErrorSignature,
    CommandPattern,
    Dependency,
    ApiSurface,
    TaskClass,
    Subsystem,
    Concept,
}

impl CueKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FilePath => "file_path",
            Self::DirPath => "dir_path",
            Self::Symbol => "symbol",
            Self::ErrorSignature => "error_signature",
            Self::CommandPattern => "command_pattern",
            Self::Dependency => "dependency",
            Self::ApiSurface => "api_surface",
            Self::TaskClass => "task_class",
            Self::Subsystem => "subsystem",
            Self::Concept => "concept",
        }
    }
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CueMatchMode {
    Exact,
    Prefix,
    Signature,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CueStrength {
    Primary,
    Secondary,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct CueBinding {
    pub cue_kind: CueKind,
    pub cue_value: String,
    pub match_mode: CueMatchMode,
    pub strength: CueStrength,
    pub expected_reuse_note: String,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CueBindingError {
    #[error("cue binding collection must contain 1..=12 entries")]
    InvalidCount,
    #[error("cue binding collection must contain at least one primary binding")]
    MissingPrimary,
    #[error("expected_reuse_note must contain 1..=200 UTF-8 bytes")]
    InvalidReuseNote,
    #[error("cue_value is empty")]
    EmptyValue,
    #[error("cue_value failed the shared encoding guard")]
    InvalidEncoding,
    #[error("cue match mode is invalid for {0}")]
    InvalidMatchMode(&'static str),
    #[error("error signature must be sig: followed by 64 lowercase hex characters")]
    InvalidSignature,
}

fn unicode_lower(raw: &str) -> String {
    raw.chars().flat_map(char::to_lowercase).collect()
}

pub fn normalize_binding(
    mut binding: CueBinding,
    project_root: Option<&str>,
) -> Result<CueBinding, CueBindingError> {
    let note_len = binding.expected_reuse_note.len();
    if binding.expected_reuse_note.trim().is_empty() || note_len > 200 {
        return Err(CueBindingError::InvalidReuseNote);
    }
    if !inspect_text_encoding(&json!(binding.cue_value)).is_empty() {
        return Err(CueBindingError::InvalidEncoding);
    }
    binding.cue_value = match binding.cue_kind {
        CueKind::FilePath => {
            if binding.match_mode != CueMatchMode::Exact {
                return Err(CueBindingError::InvalidMatchMode("file_path"));
            }
            normalize_path(&binding.cue_value, project_root)
        }
        CueKind::DirPath => {
            if binding.match_mode != CueMatchMode::Prefix {
                return Err(CueBindingError::InvalidMatchMode("dir_path"));
            }
            normalize_path(&binding.cue_value, project_root)
        }
        CueKind::Symbol => {
            if binding.match_mode != CueMatchMode::Exact {
                return Err(CueBindingError::InvalidMatchMode("symbol"));
            }
            normalize_symbol(&binding.cue_value)
        }
        CueKind::ErrorSignature => {
            if binding.match_mode != CueMatchMode::Signature
                || binding.cue_value.len() != 68
                || !binding.cue_value.starts_with("sig:")
                || !binding.cue_value[4..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(CueBindingError::InvalidSignature);
            }
            binding.cue_value
        }
        CueKind::CommandPattern => {
            if binding.match_mode != CueMatchMode::Exact {
                return Err(CueBindingError::InvalidMatchMode("command_pattern"));
            }
            unicode_lower(binding.cue_value.trim())
        }
        CueKind::Dependency
        | CueKind::ApiSurface
        | CueKind::TaskClass
        | CueKind::Subsystem
        | CueKind::Concept => unicode_lower(binding.cue_value.trim()),
    };
    if binding.cue_value.is_empty() {
        return Err(CueBindingError::EmptyValue);
    }
    Ok(binding)
}

pub fn normalize_bindings(
    bindings: Vec<CueBinding>,
    project_root: Option<&str>,
) -> Result<Vec<CueBinding>, CueBindingError> {
    if bindings.is_empty() || bindings.len() > 12 {
        return Err(CueBindingError::InvalidCount);
    }
    let mut normalized = BTreeMap::new();
    for binding in bindings {
        let binding = normalize_binding(binding, project_root)?;
        let key = (
            binding.cue_kind,
            binding.cue_value.clone(),
            binding.match_mode,
        );
        normalized
            .entry(key)
            .and_modify(|current: &mut CueBinding| {
                if binding.strength == CueStrength::Primary {
                    *current = binding.clone();
                }
            })
            .or_insert(binding);
    }
    let bindings = normalized.into_values().collect::<Vec<_>>();
    if !bindings
        .iter()
        .any(|binding| binding.strength == CueStrength::Primary)
    {
        return Err(CueBindingError::MissingPrimary);
    }
    Ok(bindings)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CueIndexRow {
    pub row_id: String,
    pub project_id: ProjectId,
    pub cue_kind: CueKind,
    pub cue_value_norm: String,
    pub match_mode: CueMatchMode,
    pub record_ref: String,
    pub record_kind: String,
    pub strength: CueStrength,
    pub negative_memory: bool,
    pub lifecycle: String,
    pub token_estimate: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CueRecordSource {
    pub record_ref: String,
    pub record_kind: String,
    pub preview_text: String,
    pub cue_bindings: Vec<CueBinding>,
    pub negative_memory: bool,
    pub lifecycle: String,
}

#[must_use]
pub fn cue_row_id(
    project_id: ProjectId,
    cue_kind: CueKind,
    cue_value: &str,
    record_ref: &str,
) -> String {
    let input = format!(
        "{project_id}|{}|{cue_value}|{record_ref}",
        cue_kind.as_str()
    );
    let digest = blake3::hash(input.as_bytes()).to_hex().to_string();
    format!("cue:{}", &digest[..32])
}

#[must_use]
#[allow(clippy::manual_div_ceil)] // Task 03 fixes this exact conservative estimate formula.
pub fn ul_token_estimate(text: &str) -> u32 {
    (u32::try_from(text.len()).unwrap_or(u32::MAX) + 3) / 4
}
