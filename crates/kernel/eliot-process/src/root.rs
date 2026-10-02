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

mod kernel_dispatch_grant;
pub use kernel_dispatch_grant::{DispatchValidationPort, KernelDispatchGrant};

mod stream_evidence;
pub use stream_evidence::{
    DurableProcessStreamSource, DurableStreamLocatorKind, DurableStreamRepresentation,
    PROCESS_STREAM_EVIDENCE_SCHEMA_VERSION, ProcessStreamEvidence, ProcessStreamEvidenceError,
    ProcessStreamKind, ProcessStreamPolicyBinding, ProcessStreamPrefixPreview,
    ProcessStreamTransformationBinding, ProcessStreamTransportPrefixIdentity, StreamByteRange,
    StreamEvaluationStatus, StreamEvidenceGap, StreamParsingStatus, StreamPersistenceStatus,
    StreamPreviewRepresentation, StreamTransportStatus,
};

mod origin_challenge;
pub use origin_challenge::{
    ORIGIN_CHALLENGE_SCHEMA_VERSION, OriginChallenge, OriginChallengeAuthority,
    OriginChallengeReplayEntry, OriginChallengeReplaySnapshot, OriginChallengeRequest,
    OriginControlGrant, OriginControlOperation, OriginControlPresentation,
    OriginGrantEffectOutcome,
};

mod operation_owner_map;
pub use operation_owner_map::{
    ADOPT_BLOCKED_ROW, ATTACH_CREDENTIAL_BLOCKED_ROW, CHALLENGE_KILL_ROW,
    DAEMON_RECOVERY_CANCEL_ROW, FRESH_STORE_LAUNCH_ROW, FROZEN_OPERATION_OWNER_MAP,
    HOST_TERMINATE_ROW, MUTATE_BLOCKED_ROW, NATIVE_WORKER_CANCEL_ROW, OWNED_RECONNECT_ROW,
    OperationOwnerRecord, OwnerAdmission, WIRE_CANCEL_ROW, admitted_challenge_operations,
    bootstrap_rows, frozen_operation_owner_map, is_documented_production_caller, owner_record_for,
};

mod stream_sink;
pub use stream_sink::{
    PROCESS_STREAM_SINK_SCHEMA_VERSION, ProcessStreamDigestAlgorithm, ProcessStreamSinkAbortReason,
    ProcessStreamSinkAbortRequest, ProcessStreamSinkAppend, ProcessStreamSinkAppendDisposition,
    ProcessStreamSinkClient, ProcessStreamSinkError, ProcessStreamSinkFinalizeRequest,
    ProcessStreamSinkFuture, ProcessStreamSinkLimits, ProcessStreamSinkModel,
    ProcessStreamSinkOpenRequest, ProcessStreamSinkReadback, ProcessStreamSinkSession,
    ProcessStreamSinkSessionId, ProcessStreamSinkSessionView, ProcessStreamSinkSourceId,
    ProcessStreamSinkState, ProcessStreamSinkTerminal, ProcessStreamSinkTerminalCommandIdentity,
    ProcessStreamSinkTerminalCommandKind, ProcessStreamSinkTerminalId,
    ProcessStreamSinkUnknownOutcome, binding_canonical_authorizes, validate_binding_canonical,
};
