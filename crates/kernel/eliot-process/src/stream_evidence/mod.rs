//! Provider-neutral durable process-stream evidence contract.
//!
//! This module owns immutable stdout/stderr evidence descriptions and their
//! fail-closed validation. It owns no process, store, ORS, parser, evaluator,
//! canonical, authority, or task-completion state.

use std::collections::BTreeSet;

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{de, Deserialize, Deserializer, Serialize};
use thiserror::Error;

use super::{
    ActionLeaseRef, DispatchAuthorityId, FencingToken, Generation, ImageId, JobId, OperationId,
    ProcessExecutionBinding, ProcessTreeId, SessionId,
};

/// Current wire revision for one stdout/stderr evidence description.
pub const PROCESS_STREAM_EVIDENCE_SCHEMA_VERSION: &str = "eliot-process-stream-evidence-v1";

const MAX_REFERENCE_BYTES: usize = 2_048;
const MAX_PREVIEW_BYTES: usize = 16 * 1024 * 1024;
const MAX_GAPS: usize = 16;

include!("part_01.rs");
include!("part_02.rs");
include!("part_03.rs");
include!("part_04.rs");
include!("part_05.rs");
include!("tests.rs");
