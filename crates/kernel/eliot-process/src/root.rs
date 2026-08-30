//! Provider-neutral governed process contracts plus durable stdout/stderr evidence.
//!
//! The original `src/lib.rs` remains the byte-preserved process-contract v3
//! implementation. The additive stream-evidence module defines only immutable,
//! privacy-bound evidence identities; it owns no process, `BlobStore`, ORS,
//! parser, evaluator, canonical, or finish state.

#![forbid(unsafe_code)]

#[path = "lib.rs"]
mod process_contract_v3;
pub use process_contract_v3::*;

mod stream_evidence;
pub use stream_evidence::{
    DurableProcessStreamSource, DurableStreamLocatorKind, DurableStreamRepresentation,
    PROCESS_STREAM_EVIDENCE_SCHEMA_VERSION, ProcessStreamEvidence, ProcessStreamEvidenceError,
    ProcessStreamKind, ProcessStreamPolicyBinding, ProcessStreamPrefixPreview,
    ProcessStreamTransformationBinding, StreamByteRange, StreamEvaluationStatus,
    StreamEvidenceGap, StreamParsingStatus, StreamPersistenceStatus,
    StreamPreviewRepresentation, StreamTransportStatus,
};
