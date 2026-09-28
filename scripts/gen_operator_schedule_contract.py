#!/usr/bin/env python3
"""Generate the C# mirror of the Kernel UserAutomation schedule contract (#2865).

The Kernel owner contract is `crates/kernel/eliot-kernel-core/src/user_automation.rs`
together with `user_automation_zones.rs`. The Operator is NOT a second
calendar/zone owner: it validates the bounded wire shape and the exact supported
contract version of what the owner issued, and it never resolves a zone, reads a
timezone database, or consults ambient Windows locale/timezone data. To keep that
boundary honest, the grammar constants, the closed disposition vocabulary, the
owner refusal Display strings and the byte shape of every grammar function the
mirror reimplements are GENERATED from the Rust source of truth instead of
hand-copied.

Usage:

    python scripts/gen_operator_schedule_contract.py            # write the artefact
    python scripts/gen_operator_schedule_contract.py --check    # gate: non-zero if stale

`--check` compares the committed artefact byte for byte against what the current
Rust source would emit, and re-derives the source digests it records. A Rust
contract/schema change therefore fails the gate — and, through the MSBuild target
in `apps/Eliot.Operator/Eliot.Operator.csproj`, fails `dotnet build` — until the
mirror is regenerated and reviewed. A hand-edited generated constant cannot be
kept, because the check compares bytes.

The generator fails closed. A constant whose declaration or value it cannot read
exactly, a disposition vocabulary it cannot enumerate, a refusal Display string it
cannot attribute to a variant, and a pinned grammar function whose body it cannot
locate are each a non-zero exit with a named reason, so the mirror can never
silently diverge from the contract it claims to mirror.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Pinned inputs.
# ---------------------------------------------------------------------------

USER_AUTOMATION_RS = "crates/kernel/eliot-kernel-core/src/user_automation.rs"
USER_AUTOMATION_ZONES_RS = "crates/kernel/eliot-kernel-core/src/user_automation_zones.rs"
USER_AUTOMATION_TRANSITION_RS = "crates/kernel/eliot-kernel-service/src/user_automation_runtime_handoff.rs"
USER_AUTOMATION_SERVICE_RS = "crates/kernel/eliot-kernel-service/src/user_automation.rs"
USER_AUTOMATION_EXECUTION_RS = "crates/kernel/eliot-kernel-service/src/user_automation_execution.rs"
USER_AUTOMATION_ORCHESTRATION_RS = "crates/kernel/eliot-kernel-service/src/user_automation_orchestration.rs"
STORE_API_RS = "crates/storage/eliot-store-api/src/lib.rs"
RUNTIME_CONTRACTS_RS = "crates/foundation/eliot-runtime-contracts/src/lib.rs"
EPOCH_IDENTITY_RS = "crates/foundation/eliot-contracts/src/epoch_identity.rs"
JOB_STATE_RS = "crates/foundation/eliot-protocol/src/dreamer_job.rs"
NOTIFICATION_STATE_RS = "crates/kernel/eliot-kernel-core/src/module/notification_state.rs"
OPERATOR_RESULT_DECODER_CS = "apps/Eliot.Operator/Protocol/UserAutomationScheduleContract.cs"

ARTEFACT = "apps/Eliot.Operator/Protocol/Generated/OperatorScheduleContract.g.cs"

#: Rust files the artefact is derived from, recorded in the artefact header so a
#: reader can see exactly which owner source the mirror is bound to. The
#: recorded spelling is always POSIX-separated so the committed artefact, and
#: therefore `--check`, is byte-identical on every host.
SOURCE_FILES = (
    "crates/kernel/eliot-kernel-core/src/user_automation.rs",
    "crates/kernel/eliot-kernel-core/src/user_automation_zones.rs",
    "crates/kernel/eliot-kernel-service/src/user_automation_runtime_handoff.rs",
    "crates/kernel/eliot-kernel-service/src/user_automation.rs",
    "crates/kernel/eliot-kernel-service/src/user_automation_execution.rs",
    "crates/kernel/eliot-kernel-service/src/user_automation_orchestration.rs",
    "crates/foundation/eliot-contracts/src/lib.rs",
    "crates/foundation/eliot-contracts/src/epoch_identity.rs",
    "crates/foundation/eliot-runtime-contracts/src/lib.rs",
    "crates/foundation/eliot-protocol/src/dreamer_job.rs",
    "crates/storage/eliot-store-api/src/lib.rs",
    "crates/kernel/eliot-kernel-core/src/module/notification_state.rs",
)

#: Constants the mirror needs as C# constants, in the order they are emitted.
#: Each entry is (name, rust file). A name that no longer exists, changes type,
#: or stops evaluating to a literal is a hard refusal, never a default.
PINNED_CONSTANTS = (
    # The exact versioned occurrence encoding. It is field 0 of every owner
    # occurrence key, so the Operator reads the supported contract version off
    # the owner's own bytes instead of carrying a second copy of it on the wire.
    ("NORMALIZED_OCCURRENCE_ENCODING", USER_AUTOMATION_RS, "string"),
    # Retired versioned predecessors remain explicit refusal inputs. Read their
    # spellings from Rust so the Operator cannot carry a drifting legacy list.
    ("LEGACY_NORMALIZED_OCCURRENCE_ENCODING_V3", USER_AUTOMATION_RS, "string"),
    ("LEGACY_NORMALIZED_OCCURRENCE_ENCODING_V2", USER_AUTOMATION_RS, "string"),
    # The domain the owner binds the compiled expression/calendar digest to. The
    # Operator displays it; it cannot recompute the digest (it does not own the
    # expression language), so it never claims to have verified the value.
    ("SCHEDULE_SOURCE_DIGEST_DOMAIN", USER_AUTOMATION_RS, "string"),
    ("NORMALIZED_OCCURRENCE_FIELD_SEPARATOR", USER_AUTOMATION_RS, "char"),
    ("NORMALIZED_OCCURRENCE_FIELD_COUNT", USER_AUTOMATION_RS, "int"),
    ("MAX_OCCURRENCE_KEY_BYTES", USER_AUTOMATION_RS, "int"),
    ("CIVIL_WALL_CLOCK_BYTES", USER_AUTOMATION_RS, "int"),
    ("UTC_INSTANT_BYTES", USER_AUTOMATION_RS, "int"),
    ("UTC_OFFSET_BYTES", USER_AUTOMATION_RS, "int"),
    ("MAX_CIVIL_UTC_OFFSET_MINUTES", USER_AUTOMATION_RS, "int"),
    ("MAX_TRANSITION_STEP_MINUTES", USER_AUTOMATION_RS, "int"),
    ("MAX_ZONE_IDENTITY_BYTES", USER_AUTOMATION_RS, "int"),
    ("MAX_ZONE_DATABASE_REVISION_BYTES", USER_AUTOMATION_RS, "int"),
    ("MIN_CIVIL_YEAR", USER_AUTOMATION_RS, "int"),
    ("MAX_CIVIL_YEAR", USER_AUTOMATION_RS, "int"),
    ("USER_AUTOMATION_PREFLIGHT_CONTRACT_REVISION", USER_AUTOMATION_RS, "string"),
    # The only zone database release this build admits, and the token every
    # owner occurrence record must carry verbatim.
    ("PINNED_ZONE_DATABASE_RELEASE", USER_AUTOMATION_ZONES_RS, "string"),
    ("USER_AUTOMATION_RESULT_WIRE_ID", USER_AUTOMATION_TRANSITION_RS, "string"),
    ("USER_AUTOMATION_RESULT_WIRE_VERSION", USER_AUTOMATION_TRANSITION_RS, "int"),
    ("USER_AUTOMATION_TRANSITION_WIRE_ID", USER_AUTOMATION_TRANSITION_RS, "string"),
    ("USER_AUTOMATION_TRANSITION_WIRE_VERSION", USER_AUTOMATION_TRANSITION_RS, "int"),
    ("MAX_TEXT_BYTES", USER_AUTOMATION_RS, "int"),
    ("MAX_REFERENCES", USER_AUTOMATION_RS, "int"),
)

# Public Rust result structs mirrored by the strict Operator decoder. Required
# and optional field sets are generated from each struct's serde attributes and
# field types; a schema change is also checked against the explicit C# decoder
# pin below, so regenerating the artefact alone cannot silently admit it.
RESULT_SCHEMA_STRUCTS = (
    ("UserAutomationOperatorResultEnvelope", "USER_AUTOMATION_RESULT_ENVELOPE_MEMBERS"),
    ("UserAutomationResultCorrelation", "USER_AUTOMATION_RESULT_CORRELATION_MEMBERS"),
    ("UserAutomationOperatorTransitionValue", "USER_AUTOMATION_TRANSITION_VALUE_MEMBERS"),
    ("UserAutomationScheduleInspectionProjection", "USER_AUTOMATION_SCHEDULE_PROJECTION_MEMBERS"),
    ("UserAutomationOccurrenceInspectionProjection", "USER_AUTOMATION_OCCURRENCE_PROJECTION_MEMBERS"),
    ("UserAutomationOperatorTransition", "USER_AUTOMATION_TRANSITION_MEMBERS"),
    ("AutomationOccurrenceIdentity", "USER_AUTOMATION_OCCURRENCE_IDENTITY_MEMBERS"),
    ("UserAutomationHorizonPhase", "USER_AUTOMATION_HORIZON_PHASE_MEMBERS"),
    ("UserAutomationOrchestrationRecord", "USER_AUTOMATION_ORCHESTRATION_RECORD_MEMBERS"),
    ("UserAutomationRuntimeObligation", "USER_AUTOMATION_RUNTIME_OBLIGATION_MEMBERS"),
    ("OperationIdentity", "USER_AUTOMATION_OPERATION_IDENTITY_MEMBERS"),
    ("StateFence", "USER_AUTOMATION_STATE_FENCE_MEMBERS"),
    ("EpochId", "USER_AUTOMATION_EPOCH_ID_MEMBERS"),
    ("WriteReceipt", "USER_AUTOMATION_WRITE_RECEIPT_MEMBERS"),
    ("UserAutomationRevision", "USER_AUTOMATION_REVISION_MEMBERS"),
    ("UserAutomationWakeReadback", "USER_AUTOMATION_WAKE_READBACK_MEMBERS"),
    ("WakeIntent", "USER_AUTOMATION_WAKE_INTENT_MEMBERS"),
    ("AutomationExecutionReference", "USER_AUTOMATION_EXECUTION_REFERENCE_MEMBERS"),
    ("UserAutomationInvocation", "USER_AUTOMATION_INVOCATION_MEMBERS"),
    ("UserAutomationExecutionProjection", "USER_AUTOMATION_EXECUTION_PROJECTION_MEMBERS"),
    ("UserAutomationFailureProjection", "USER_AUTOMATION_FAILURE_PROJECTION_MEMBERS"),
    ("UserAutomationInvocationProvenance", "USER_AUTOMATION_INVOCATION_PROVENANCE_MEMBERS"),
    ("AutomationReconciliationReference", "USER_AUTOMATION_RECONCILIATION_REFERENCE_MEMBERS"),
    ("NormalizedSchedule", "USER_AUTOMATION_NORMALIZED_SCHEDULE_MEMBERS"),
    ("AutomationWorkScope", "USER_AUTOMATION_WORK_SCOPE_MEMBERS"),
    ("AutomationTaskBinding", "USER_AUTOMATION_TASK_BINDING_MEMBERS"),
    ("AutomationCapabilityProfile", "USER_AUTOMATION_CAPABILITY_PROFILE_MEMBERS"),
    ("ProviderFingerprint", "USER_AUTOMATION_PROVIDER_FINGERPRINT_MEMBERS"),
    ("RouteCostPolicy", "USER_AUTOMATION_ROUTE_COST_POLICY_MEMBERS"),
    ("AutomationDeliveryTarget", "USER_AUTOMATION_DELIVERY_TARGET_MEMBERS"),
    ("AutomationResourceCeiling", "USER_AUTOMATION_RESOURCE_CEILING_MEMBERS"),
    ("RecursionPolicy", "USER_AUTOMATION_RECURSION_POLICY_MEMBERS"),
    ("RevisionDelta", "USER_AUTOMATION_REVISION_DELTA_MEMBERS"),
    ("OrderingHead", "USER_AUTOMATION_ORDERING_HEAD_MEMBERS"),
    ("PolicyConfigSchemaVersions", "USER_AUTOMATION_POLICY_SCHEMA_MEMBERS"),
)

# Owner enum wire tags whose closed values are checked before the Operator
# describes a transition. These arrays are generated from serde rename rules.
RESULT_SCHEMA_ENUMS = (
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationOperatorResultStatus", "USER_AUTOMATION_RESULT_STATUS_VALUES"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationOperatorResultRecovery", "USER_AUTOMATION_RESULT_RECOVERY_KINDS"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationConfigurationPhase", "USER_AUTOMATION_CONFIGURATION_PHASE_KINDS"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationHorizonOutcome", "USER_AUTOMATION_HORIZON_OUTCOME_KINDS"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationWakePhase", "USER_AUTOMATION_WAKE_PHASE_KINDS"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationExecutionPhase", "USER_AUTOMATION_EXECUTION_PHASE_KINDS"),
    (STORE_API_RS, "WriteReceiptStatus", "USER_AUTOMATION_WRITE_RECEIPT_STATUS_VALUES"),
    (RUNTIME_CONTRACTS_RS, "WakeIntentState", "USER_AUTOMATION_WAKE_INTENT_STATE_VALUES"),
    (JOB_STATE_RS, "JobState", "USER_AUTOMATION_EXECUTION_STATE_VALUES"),
    (USER_AUTOMATION_EXECUTION_RS, "UserAutomationHorizonTrigger", "USER_AUTOMATION_HORIZON_TRIGGER_VALUES"),
    (USER_AUTOMATION_ORCHESTRATION_RS, "UserAutomationRuntimeObligationKind", "USER_AUTOMATION_RUNTIME_OBLIGATION_KINDS"),
    (USER_AUTOMATION_ORCHESTRATION_RS, "UserAutomationRuntimeObligationAnswer", "USER_AUTOMATION_RUNTIME_OBLIGATION_ANSWER_KINDS"),
    (USER_AUTOMATION_ORCHESTRATION_RS, "UserAutomationRuntimeObligationDisposition", "USER_AUTOMATION_RUNTIME_OBLIGATION_DISPOSITION_KINDS"),
    (USER_AUTOMATION_SERVICE_RS, "UserAutomationReadResult", "USER_AUTOMATION_READ_RESULT_KINDS"),
    (USER_AUTOMATION_SERVICE_RS, "UserAutomationMutationResult", "USER_AUTOMATION_MUTATION_RESULT_KINDS"),
    (USER_AUTOMATION_RS, "UserAutomationConfigurationState", "USER_AUTOMATION_CONFIGURATION_STATES"),
    (USER_AUTOMATION_RS, "ScheduleKind", "USER_AUTOMATION_SCHEDULE_KINDS"),
    (USER_AUTOMATION_RS, "DstFoldPolicy", "USER_AUTOMATION_DST_FOLD_POLICIES"),
    (USER_AUTOMATION_RS, "DstGapPolicy", "USER_AUTOMATION_DST_GAP_POLICIES"),
    (USER_AUTOMATION_RS, "UserAutomationTrigger", "USER_AUTOMATION_TRIGGER_KINDS"),
    (USER_AUTOMATION_RS, "UserAutomationExecutionMode", "USER_AUTOMATION_EXECUTION_MODES"),
    (USER_AUTOMATION_RS, "UserAutomationTriggerOrigin", "USER_AUTOMATION_TRIGGER_ORIGINS"),
    (USER_AUTOMATION_RS, "AutomationTaskKind", "USER_AUTOMATION_TASK_KINDS"),
    (USER_AUTOMATION_RS, "AutomationWorkClass", "USER_AUTOMATION_WORK_CLASSES"),
    (USER_AUTOMATION_RS, "ProviderFingerprintPolicy", "USER_AUTOMATION_PROVIDER_POLICY_KINDS"),
    (USER_AUTOMATION_RS, "OverlapPolicy", "USER_AUTOMATION_OVERLAP_POLICIES"),
    (USER_AUTOMATION_RS, "AutomationReconciliationCause", "USER_AUTOMATION_RECONCILIATION_CAUSES"),
    (USER_AUTOMATION_RS, "UserAutomationFailureReason", "USER_AUTOMATION_FAILURE_REASON_KINDS"),
    (NOTIFICATION_STATE_RS, "DeliveryChannel", "USER_AUTOMATION_DELIVERY_CHANNELS"),
    (STORE_API_RS, "TransitionClass", "USER_AUTOMATION_TRANSITION_CLASSES"),
    (STORE_API_RS, "Resubmission", "USER_AUTOMATION_RESUBMISSION_VALUES"),
    ("crates/foundation/eliot-contracts/src/lib.rs", "ErrorCode", "USER_AUTOMATION_ERROR_CODE_VALUES"),
    (USER_AUTOMATION_RS, "UserAutomationDeferReason", "USER_AUTOMATION_DEFER_REASONS"),
)

# Fingerprint the full serde declarations in the closed result union and the
# phase DTO graph it contains. This includes enum variant tags, nested payload
# fields, serde renames/defaults and optional wire behavior, not only the flat
# fields of the four member arrays emitted below.
RESULT_SCHEMA_DECLARATIONS = (
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationResultCorrelation"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationOperatorResultStatus"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationOperatorResultRecovery"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationOperatorResultValue"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationOperatorTransitionValue"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationScheduleInspectionProjection"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationOccurrenceInspectionProjection"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationAttemptRefusalValue"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationAttemptOperationIdentity"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationRefusalDetails"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationNotRetainedValue"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationUnavailableValue"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationUnknownOutcomeValue"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationOutcomeSettledValue"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationRejectedValue"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationIdentityConflictValue"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationOperatorResultEnvelope"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationConfigurationPhase"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationHorizonOutcome"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationHorizonPhase"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationWakePhase"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationExecutionPhase"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationRecoveryPhase"),
    (USER_AUTOMATION_TRANSITION_RS, "UserAutomationOperatorTransition"),
    (USER_AUTOMATION_RS, "UserAutomationConfigurationState"),
    (USER_AUTOMATION_RS, "ScheduleKind"),
    (USER_AUTOMATION_RS, "DstFoldPolicy"),
    (USER_AUTOMATION_RS, "DstGapPolicy"),
    (USER_AUTOMATION_RS, "UserAutomationTrigger"),
    (USER_AUTOMATION_RS, "AutomationOccurrenceIdentity"),
    (USER_AUTOMATION_RS, "UserAutomationDeferReason"),
    (USER_AUTOMATION_EXECUTION_RS, "UserAutomationHorizonTrigger"),
    (USER_AUTOMATION_EXECUTION_RS, "UserAutomationWakeReadback"),
    (USER_AUTOMATION_SERVICE_RS, "UserAutomationReadResult"),
    (USER_AUTOMATION_SERVICE_RS, "UserAutomationMutationResult"),
    (USER_AUTOMATION_ORCHESTRATION_RS, "UserAutomationRuntimeObligationKind"),
    (USER_AUTOMATION_ORCHESTRATION_RS, "UserAutomationRuntimeObligationAnswer"),
    (USER_AUTOMATION_ORCHESTRATION_RS, "UserAutomationRuntimeObligationDisposition"),
    (USER_AUTOMATION_ORCHESTRATION_RS, "UserAutomationRuntimeObligation"),
    (USER_AUTOMATION_ORCHESTRATION_RS, "UserAutomationOrchestrationRecord"),
    ("crates/foundation/eliot-contracts/src/lib.rs", "StateFence"),
    (STORE_API_RS, "OperationIdentity"),
    (STORE_API_RS, "WriteReceipt"),
    (STORE_API_RS, "WriteReceiptStatus"),
    (USER_AUTOMATION_RS, "UserAutomationRevision"),
    (USER_AUTOMATION_RS, "UserAutomationInvocation"),
    (USER_AUTOMATION_RS, "UserAutomationInvocationProvenance"),
    (USER_AUTOMATION_RS, "AutomationExecutionReference"),
    (USER_AUTOMATION_RS, "UserAutomationExecutionProjection"),
    (USER_AUTOMATION_RS, "UserAutomationFailureProjection"),
    (USER_AUTOMATION_RS, "AutomationReconciliationReference"),
    (USER_AUTOMATION_RS, "NormalizedSchedule"),
    (USER_AUTOMATION_RS, "AutomationWorkScope"),
    (USER_AUTOMATION_RS, "AutomationTaskBinding"),
    (USER_AUTOMATION_RS, "AutomationCapabilityProfile"),
    (USER_AUTOMATION_RS, "ProviderFingerprint"),
    (USER_AUTOMATION_RS, "RouteCostPolicy"),
    (USER_AUTOMATION_RS, "AutomationDeliveryTarget"),
    (USER_AUTOMATION_RS, "AutomationResourceCeiling"),
    (USER_AUTOMATION_RS, "RecursionPolicy"),
    (STORE_API_RS, "RevisionDelta"),
    (STORE_API_RS, "OrderingHead"),
    (STORE_API_RS, "PolicyConfigSchemaVersions"),
    (USER_AUTOMATION_RS, "AutomationReconciliationCause"),
    (USER_AUTOMATION_RS, "UserAutomationExecutionMode"),
    (USER_AUTOMATION_RS, "UserAutomationTriggerOrigin"),
    (USER_AUTOMATION_RS, "AutomationTaskKind"),
    (USER_AUTOMATION_RS, "AutomationWorkClass"),
    (USER_AUTOMATION_RS, "ProviderFingerprintPolicy"),
    (USER_AUTOMATION_RS, "OverlapPolicy"),
    (USER_AUTOMATION_RS, "UserAutomationFailureReason"),
    (NOTIFICATION_STATE_RS, "DeliveryChannel"),
    (RUNTIME_CONTRACTS_RS, "WakeIntent"),
    (RUNTIME_CONTRACTS_RS, "WakeIntentState"),
    (JOB_STATE_RS, "JobState"),
    (EPOCH_IDENTITY_RS, "EpochId"),
    (STORE_API_RS, "TransitionClass"),
    (STORE_API_RS, "Resubmission"),
    ("crates/foundation/eliot-contracts/src/lib.rs", "ErrorCode"),
    (NOTIFICATION_STATE_RS, "DeliveryChannel"),
)
RESULT_SCHEMA_DECODER_PIN = "SupportedUserAutomationResultSchemaSha256"

#: Values the Rust owner spells as an inline expression over a pinned constant.
#: They are resolved here from the same Rust declarations rather than re-typed,
#: so the mirror cannot drift from the expression the owner evaluates.
DERIVED_CONSTANTS = (
    # `is_legacy_occurrence_key` admits exactly these two retired record lengths:
    # a civil wall clock plus `Z`, and a civil wall clock plus a UTC offset.
    ("LEGACY_OCCURRENCE_INSTANT_BYTES", "UTC_INSTANT_BYTES"),
    ("LEGACY_OCCURRENCE_OFFSET_BYTES", "CIVIL_WALL_CLOCK_BYTES + UTC_OFFSET_BYTES"),
)

#: Closed fold/gap disposition vocabulary, enumerated from the owner's parser
#: rather than listed here, so a new disposition in the owner is a gate failure
#: instead of a silently un-admitted spelling.
DISPOSITION_FUNCTION = "parse_occurrence_disposition"
DISPOSITION_VARIANT_TYPE = "OccurrenceDisposition"

#: The owner enum whose `#[error(...)]` attributes are the canonical Display
#: strings the Operator must decode instead of collapsing into a generic error.
REFUSAL_ENUM = "UserAutomationError"

#: Every grammar function the C# mirror reimplements. Each one's exact body is
#: digested into the artefact, so a Rust change to a rule the mirror depends on
#: fails the gate even when no constant moved.
#:
#: `require_pinned_zone_evidence` and `is_pinned_zone` are deliberately absent:
#: they are the pinned zone-table membership checks, they need the owner table,
#: and the Operator must not become a second zone owner. Their absence is the
#: stated boundary of this mirror, not an oversight.
PINNED_GRAMMAR_FUNCTIONS = (
    "source_digest",
    "normalized_occurrences",
    "parse_occurrence",
    "parse_civil_wall_clock",
    "parse_utc_offset",
    "parse_utc_instant",
    "parse_civil_instant",
    "parse_occurrence_disposition",
    "parse_transition_window",
    "require_declared_disposition",
    "require_resolved_instant",
    "validate_occurrence_local_relation",
    "is_legacy_occurrence_key",
    "is_canonical_zone_database_revision",
)


class Refused(Exception):
    """The Rust source of truth does not say what the mirror must say."""


# ---------------------------------------------------------------------------
# Rust declaration reading.
# ---------------------------------------------------------------------------

#: The first line of a `const NAME: TYPE = EXPR` declaration, with any visibility
#: prefix. The declaration's remaining lines, and its terminating `;`, are found
#: by scanning, so a multi-line right-hand side is read whole.
CONST_DECLARATION = re.compile(
    r"^(?P<vis>pub(?:\(crate\))?\s+)?const\s+"
    r"(?P<name>[A-Z][A-Z0-9_]*)\s*:\s*"
    r"(?P<type>[^=]+?)\s*=\s*"
    r"(?P<rhs>.*)$"
)

FN_DECLARATION = re.compile(r"^(?:pub(?:\(crate\))?\s+)?(?:const\s+)?fn\s+")

ERROR_ATTRIBUTE = re.compile(r'#\[error\("((?:[^"\\]|\\.)*)"\)\]')

RUST_INT_SUFFIX = re.compile(r"^(\d[\d_]*)((?:i|u)(?:8|16|32|64|128|size))?$")

RUST_ESCAPES = {
    "\\": "\\", '"': '"', "n": "\n", "r": "\r", "t": "\t",
    "0": "\0", "'": "'",
}


def normalise_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def read_source(path: str) -> list[str]:
    if not os.path.isfile(path):
        raise Refused(f"{path} is missing; the owner contract source is absent")
    with open(path, encoding="utf-8") as handle:
        return normalise_newlines(handle.read()).split("\n")


# ---------------------------------------------------------------------------
# A deliberately tiny Rust literal evaluator.
#
# The mirror needs the VALUE of a handful of pinned constants, not a Rust
# parser. The grammar below is the whole grammar the owner uses for those
# declarations: a string literal, a char literal, an integer literal with an
# optional numeric suffix, `+` and `*` between them, and references to other
# constants that were already resolved. Anything else is a refusal, so a
# declaration that grows an expression this evaluator does not understand stops
# the mirror instead of being silently approximated.
# ---------------------------------------------------------------------------


def tokenise_rust_expression(expression: str) -> list[str]:
    tokens: list[str] = []
    index = 0
    length = len(expression)
    while index < length:
        char = expression[index]
        if char.isspace():
            index += 1
            continue
        if char in "+*":
            tokens.append(char)
            index += 1
            continue
        if char == '"':
            end = index + 1
            while end < length and expression[end] != '"':
                if expression[end] == "\\":
                    end += 1
                end += 1
            if end >= length:
                raise Refused(f"unterminated string literal in {expression!r}")
            tokens.append(expression[index : end + 1])
            index = end + 1
            continue
        if char == "'":
            end = index + 1
            while end < length and expression[end] != "'":
                if expression[end] == "\\":
                    end += 1
                end += 1
            if end >= length:
                raise Refused(f"unterminated char literal in {expression!r}")
            tokens.append(expression[index : end + 1])
            index = end + 1
            continue
        start = index
        while index < length and (expression[index].isalnum() or expression[index] == "_"):
            index += 1
        if start == index:
            raise Refused(f"unsupported token {char!r} in constant expression {expression!r}")
        tokens.append(expression[start:index])
    return tokens


def decode_rust_string(literal: str) -> str:
    body = literal[1:-1]
    out: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        index += 1
        if index >= len(body):
            raise Refused(f"trailing escape in string literal {literal!r}")
        escape = body[index]
        if escape in RUST_ESCAPES:
            out.append(RUST_ESCAPES[escape])
            index += 1
            continue
        if escape == "x":
            out.append(chr(int(body[index + 1 : index + 3], 16)))
            index += 3
            continue
        if escape == "u":
            close = body.index("}", index)
            out.append(chr(int(body[index + 2 : close], 16)))
            index = close + 1
            continue
        if escape == "n":
            out.append("\n")
            index += 1
            continue
        raise Refused(f"unsupported string escape \\{escape} in {literal!r}")
    return "".join(out)


def decode_rust_char(literal: str) -> str:
    body = literal[1:-1]
    if not body.startswith("\\"):
        if len(body) != 1:
            raise Refused(f"unsupported char literal {literal!r}")
        return body
    if body == "\\'":
        return "'"
    if body == "\\\\":
        return "\\"
    if body == "\\n":
        return "\n"
    if body == "\\t":
        return "\t"
    if body.startswith("\\x"):
        return chr(int(body[2:], 16))
    if body.startswith("\\u{"):
        return chr(int(body[3 : body.index("}")], 16))
    raise Refused(f"unsupported char escape in {literal!r}")


def decode_rust_int(token: str) -> int:
    match = RUST_INT_SUFFIX.fullmatch(token)
    if match is None:
        raise Refused(f"unsupported integer literal {token!r}")
    return int(match.group(1).replace("_", ""))


def evaluate_rust_expression(expression: str, resolved: dict[str, object]) -> object:
    tokens = tokenise_rust_expression(expression)
    if not tokens:
        raise Refused(f"empty constant expression {expression!r}")

    position = 0

    def parse_product() -> object:
        nonlocal position
        value = parse_atom()
        while position < len(tokens) and tokens[position] == "*":
            position += 1
            right = parse_atom()
            if not isinstance(value, int) or not isinstance(right, int):
                raise Refused(f"non-integer multiplication in {expression!r}")
            value = int(value) * int(right)
        return value

    def parse_sum() -> object:
        nonlocal position
        value = parse_product()
        while position < len(tokens) and tokens[position] == "+":
            position += 1
            right = parse_product()
            if not isinstance(value, int) or not isinstance(right, int):
                raise Refused(
                    f"`+` over non-integer operands in {expression!r}; the owner "
                    "concatenation form is not a pinned constant"
                )
            value = int(value) + int(right)
        return value

    def parse_atom() -> object:
        nonlocal position
        if position >= len(tokens):
            raise Refused(f"truncated constant expression {expression!r}")
        token = tokens[position]
        position += 1
        if token.startswith('"'):
            return decode_rust_string(token)
        if token.startswith("'"):
            return decode_rust_char(token)
        if token[0].isdigit():
            return decode_rust_int(token)
        if token in resolved:
            return resolved[token]
        raise Refused(
            f"constant expression {expression!r} references {token!r}, which this "
            "generator does not resolve; add it to the pinned set explicitly"
        )

    value = parse_sum()
    if position != len(tokens):
        raise Refused(f"trailing tokens in constant expression {expression!r}")
    return value


# ---------------------------------------------------------------------------
# Extracted facts.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RustConstant:
    name: str
    rust_type: str
    value: object
    source: str


@dataclass(frozen=True)
class RustFunction:
    name: str
    body: str


@dataclass(frozen=True)
class RustRefusal:
    variant: str
    display: str


@dataclass(frozen=True)
class RustResultField:
    name: str
    rust_type: str
    required: bool


@dataclass(frozen=True)
class RustResultStruct:
    name: str
    fields: tuple[RustResultField, ...]


@dataclass(frozen=True)
class RustResultEnum:
    name: str
    variants: tuple[str, ...]


def collapse(text: str) -> str:
    return " ".join(text.split())


def statement_ends(text: str) -> bool:
    """Whether `text` has reached the `;` that terminates one Rust statement.

    The scan skips over double-quoted literals, so a `;` inside a pinned string
    constant cannot be mistaken for the end of the declaration.
    """
    in_string = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_string:
            if char == "\\":
                index += 2
                continue
            if char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == ";":
            return True
        index += 1
    return False


def collect_constants(lines: list[str]) -> dict[str, RustConstant]:
    """Every `const` declaration in one Rust file, keyed by name.

    A declaration's recorded source is its own lines with whitespace collapsed,
    so a doc-comment edit, a line move or a reformat does not pin the digest,
    while the declared name, type and value expression do.
    """
    found: dict[str, RustConstant] = {}
    index = 0
    while index < len(lines):
        match = CONST_DECLARATION.match(lines[index])
        if match is None:
            index += 1
            continue
        statement = lines[index]
        end = index
        while not statement_ends(statement) and end + 1 < len(lines):
            end += 1
            statement = f"{statement} {lines[end].strip()}"
        if not statement_ends(statement):
            raise Refused(
                f"constant {match.group('name')!r} has no terminating `;`"
            )
        declaration = collapse(statement).rsplit(";", 1)[0]
        name = match.group("name")
        if name in found:
            raise Refused(f"constant {name!r} is declared more than once")
        found[name] = RustConstant(
            name=name,
            rust_type=collapse(match.group("type")),
            value=None,
            source=declaration,
        )
        index = end + 1
    return found


def collect_result_struct(lines: list[str], name: str) -> RustResultStruct:
    """Extract one flat public result struct and its serde-required fields."""
    start = None
    header = re.compile(rf"^\s*pub\s+struct\s+{re.escape(name)}\s*\{{\s*$")
    for index, line in enumerate(lines):
        if header.match(line):
            start = index + 1
            break
    if start is None:
        raise Refused(f"result schema struct {name!r} is absent")

    fields: list[RustResultField] = []
    pending_serde = ""
    field_re = re.compile(r"^\s*pub\s+([a-zA-Z0-9_]+)\s*:\s*(.+),\s*$")
    for line in lines[start:]:
        stripped = line.strip()
        if stripped == "}":
            break
        if stripped.startswith("#[serde("):
            pending_serde += stripped
            continue
        match = field_re.match(line)
        if match is None:
            if stripped.startswith("pub "):
                raise Refused(f"result schema field in {name!r} is not a one-line field")
            continue
        field_name = match.group(1)
        rust_type = collapse(match.group(2))
        required = "skip_serializing_if" not in pending_serde
        fields.append(RustResultField(field_name, rust_type, required))
        pending_serde = ""
    else:
        raise Refused(f"result schema struct {name!r} has no closing brace")
    if not fields:
        raise Refused(f"result schema struct {name!r} has no public fields")
    return RustResultStruct(name, tuple(fields))


def collect_result_declaration(lines: list[str], name: str) -> str:
    """Collect one serde type declaration, including its attributes and variants."""
    header = re.compile(rf"^\s*pub\s+(?:struct|enum)\s+{re.escape(name)}\b")
    for index, line in enumerate(lines):
        if header.match(line) is None:
            continue
        first = index
        while first > 0 and lines[first - 1].strip().startswith("#["):
            first -= 1
        depth = 0
        opened = False
        declaration: list[str] = []
        for candidate in lines[index:]:
            declaration.append(candidate)
            code = candidate.split("//", 1)[0]
            depth += code.count("{") - code.count("}")
            opened |= "{" in code
            if opened and depth == 0:
                return "\n".join(lines[first:index] + declaration)
        raise Refused(f"result schema declaration {name!r} has no closing brace")
    raise Refused(f"result schema declaration {name!r} is absent")


def collect_result_deserializer(lines: list[str], name: str) -> str:
    """Collect the custom discriminator-aware Deserialize implementation for one result type."""
    header = re.compile(
        rf"^\s*impl\s*<\s*'de\s*>\s+Deserialize\s*<\s*'de\s*>\s+for\s+{re.escape(name)}\s*\{{\s*$"
    )
    for index, line in enumerate(lines):
        if header.match(line) is None:
            continue
        depth = 0
        opened = False
        declaration: list[str] = []
        for candidate in lines[index:]:
            declaration.append(candidate)
            code = candidate.split("//", 1)[0]
            depth += code.count("{") - code.count("}")
            opened |= "{" in code
            if opened and depth == 0:
                return "\n".join(declaration)
        raise Refused(f"result deserializer {name!r} has no closing brace")
    raise Refused(f"result deserializer {name!r} is absent")


def collect_result_enum(lines: list[str], name: str) -> RustResultEnum:
    """Collect enum variants using the serde rename rule on the owner type."""
    header = re.compile(rf"^\s*pub\s+enum\s+{re.escape(name)}\b")
    for index, line in enumerate(lines):
        if header.match(line) is None:
            continue
        attribute_start = index
        while attribute_start > 0 and lines[attribute_start - 1].strip().startswith("#["):
            attribute_start -= 1
        attributes = "\n".join(lines[attribute_start:index])
        rename_match = re.search(r'rename_all\s*=\s*"([^"]+)"', attributes)
        rename_rule = rename_match.group(1) if rename_match else ""

        def wire_name(variant: str) -> str:
            explicit_rename = re.search(
                rf"#\[serde\([^\]]*rename\s*=\s*\"([^\"]+)\"[^\]]*\)\]\s*{re.escape(variant)}\b",
                "\n".join(lines[index + 1 :]),
            )
            if explicit_rename is not None:
                return explicit_rename.group(1)
            if rename_rule == "lowercase":
                return variant.lower()
            snake = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", variant)
            snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", snake).lower()
            if rename_rule == "SCREAMING_SNAKE_CASE":
                return snake.upper()
            if rename_rule == "kebab-case":
                return snake.replace("_", "-")
            if rename_rule in {"snake_case", ""}:
                return snake
            raise Refused(f"enum {name!r} uses unsupported serde rename rule {rename_rule!r}")

        variant_names: list[str] = []
        depth = 0
        opened = False
        variant_re = re.compile(r"^\s*([A-Z][a-zA-Z0-9_]*)\s*(?:[,({]|$)")
        for candidate in lines[index:]:
            code = candidate.split("//", 1)[0]
            if not opened:
                if "{" in code:
                    opened = True
                    depth = code.count("{") - code.count("}")
                continue
            if depth == 1:
                match = variant_re.match(candidate)
                if match is not None:
                    variant_names.append(wire_name(match.group(1)))
            depth += code.count("{") - code.count("}")
            if depth == 0:
                if not variant_names:
                    raise Refused(f"result schema enum {name!r} has no variants")
                return RustResultEnum(name, tuple(variant_names))
        raise Refused(f"result schema enum {name!r} has no closing brace")
    raise Refused(f"result schema enum {name!r} is absent")


def collect_functions(lines: list[str], name: str) -> RustFunction:
    """The exact body of one free `fn`, located by brace matching."""
    header = re.compile(
        rf"^\s*(?:pub(?:\(crate\))?\s+)?(?:const\s+)?fn\s+{re.escape(name)}\b"
    )
    for index, line in enumerate(lines):
        if header.match(line) is None:
            continue
        depth = 0
        opened = False
        body: list[str] = []
        for candidate in lines[index:]:
            body.append(candidate)
            depth += candidate.count("{") - candidate.count("}")
            if "{" in candidate:
                opened = True
            if opened and depth <= 0:
                return RustFunction(name=name, body="\n".join(body))
        raise Refused(f"function {name!r} has no closed body in the owner source")
    raise Refused(f"function {name!r} is absent from the owner source")


def collect_dispositions(lines: list[str]) -> list[str]:
    """The closed disposition vocabulary, in owner declaration order."""
    function = collect_functions(lines, DISPOSITION_FUNCTION)
    arms = re.findall(
        r'"([A-Z0-9_]+)"\s*=>\s*Ok\(' + re.escape(DISPOSITION_VARIANT_TYPE) + r"::",
        function.body,
    )
    if not arms:
        raise Refused(
            f"{DISPOSITION_FUNCTION} carries no {DISPOSITION_VARIANT_TYPE} match arms"
        )
    if len(set(arms)) != len(arms):
        raise Refused(f"{DISPOSITION_FUNCTION} repeats a disposition spelling")
    return arms


def collect_refusals(lines: list[str]) -> list[RustRefusal]:
    """Every `#[error(...)]` Display string, attributed to its variant."""
    refusals: list[RustRefusal] = []
    for index, line in enumerate(lines):
        attribute = ERROR_ATTRIBUTE.search(line)
        if attribute is None:
            continue
        variant = None
        for candidate in lines[index + 1 : index + 4]:
            stripped = candidate.strip()
            if not stripped or stripped.startswith("///") or stripped.startswith("#[error"):
                continue
            name = re.match(r"([A-Z][A-Za-z0-9]*)", stripped)
            if name is None:
                break
            variant = name.group(1)
            break
        if variant is None:
            raise Refused(
                f"refusal Display string {attribute.group(1)!r} has no variant; the "
                "operator refusal table would be unattributable"
            )
        refusals.append(
            RustRefusal(variant=variant, display=attribute.group(1).replace('\\"', '"'))
        )
    if not refusals:
        raise Refused(f"no refusal Display strings were read from {REFUSAL_ENUM}")
    return refusals


# ---------------------------------------------------------------------------
# Emission.
# ---------------------------------------------------------------------------


def csharp_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{escaped}"'


def csharp_char(value: str) -> str:
    if len(value) != 1:
        raise Refused(f"expected a single-character separator, found {value!r}")
    if value == "'":
        return "'\\''"
    if value == "\\":
        return "'\\\\'"
    return f"'{value}'"


def render_artefact(
    constants: list[RustConstant],
    dispositions: list[str],
    refusals: list[RustRefusal],
    functions: list[RustFunction],
    result_structs: list[tuple[str, str, RustResultStruct]],
    result_enums: list[tuple[str, str, RustResultEnum]],
    digests: dict[str, str],
) -> str:
    lines: list[str] = []
    add = lines.append

    add("// <auto-generated>")
    add("//     Generated by scripts/gen_operator_schedule_contract.py. Do not edit.")
    add("// </auto-generated>")
    add("//")
    add("// Bounded C# mirror of the Kernel UserAutomation schedule/occurrence contract")
    add(f"// ({REFUSAL_ENUM} owner, crates/kernel/eliot-kernel-core/src/user_automation.rs).")
    add("//")
    add("// Every value below is GENERATED from the owner Rust source, and")
    add("// `python scripts/gen_operator_schedule_contract.py --check` compares this")
    add("// file byte for byte against what that source would emit today. A Rust")
    add("// contract or schema change therefore fails the gate — and the Operator")
    add("// build — until the mirror is regenerated and reviewed.")
    add("//")
    add("// Source of truth:")
    for path in SOURCE_FILES:
        add(f"//   {path}")
    add(f"// contract_source_sha256: {digests['contract']}")
    add(f"// constants_source_sha256: {digests['constants']}")
    add(f"// dispositions_source_sha256: {digests['dispositions']}")
    add(f"// refusals_source_sha256: {digests['refusals']}")
    add(f"// grammar_source_sha256: {digests['grammar']}")
    add(f"// user_automation_result_schema_sha256: {digests['result_schema']}")
    add("//")
    add("// Stated boundary of this mirror. The Operator validates the bounded wire")
    add("// shape, the exact supported contract version and the self-consistency of the")
    add("// owner-issued evidence. It never resolves a zone, reads a timezone database,")
    add("// or reads ambient Windows locale/timezone data, so the following owner")
    add("// rules are deliberately NOT mirrored and remain the owner's decision:")
    add("//   require_pinned_zone_evidence — needs the pinned zone table;")
    add("//   is_pinned_zone              — zone membership is table membership;")
    add("//   ZONE_TABLE_WINDOW_*         — the pinned window is owner evidence.")
    add("// The Operator also cannot recompute the source digest: it is a SHA-256 over")
    add("// a Rust canonical JSON tuple of the expression language, which the Operator")
    add("// does not own. It therefore pins only what the owner-issued bytes decide.")
    add("")
    add("namespace Eliot.Operator.Protocol.Generated;")
    add("")
    add("/// One owner refusal variant and the exact Display string the Kernel emits")
    add("/// for it. The Operator matches an owner answer against `LiteralPrefix` so a")
    add("/// typed refusal is shown as its own actionable reason instead of a generic")
    add("/// JSON error. `CarriesPayload` distinguishes a fixed sentence from one whose")
    add("/// tail names the offending field, zone or window.")
    add("public sealed record OperatorOwnerRefusalTemplate(")
    add("    string Variant,")
    add("    string DisplayTemplate,")
    add("    string LiteralPrefix,")
    add("    bool CarriesPayload);")
    add("")
    add("/// <summary>")
    add("/// Generated mirror of the pinned constants, the closed disposition vocabulary")
    add("/// and the owner refusal Display strings of the canonical UserAutomation")
    add("/// schedule contract. Never mutated at runtime.")
    add("/// </summary>")
    add("public static class OperatorScheduleContract")
    add("{")
    add("    /// <summary>")
    add("    /// Rust declarations these constants were derived from, in the order they")
    add("    /// are emitted, as `name<TAB>type<TAB>value`.")
    add("    /// </summary>")
    add("    public static readonly IReadOnlyList<string> ConstantSourceLines =")
    add("    [")
    for constant in constants:
        add(f"        {csharp_string(constant.source)},")
    add("    ];")
    add("")
    add("    /// <summary>")
    add("    /// Owner functions the C# mirror reimplements, as `name<TAB>sha256`.")
    add("    /// </summary>")
    add("    public static readonly IReadOnlyList<string> GrammarFunctionDigests =")
    add("    [")
    for function in functions:
        add(
            f"        {csharp_string(function.name + '\t' + digests['function:' + function.name])},"  # noqa: E501
        )
    add("    ];")
    add("")
    for constant in constants:
        if isinstance(constant.value, str):
            rendered = f"public const string {constant.name} = {csharp_string(constant.value)};"
        elif isinstance(constant.value, bool):
            raise Refused(f"constant {constant.name!r} resolved to a boolean")
        elif isinstance(constant.value, int):
            rendered = f"public const int {constant.name} = {int(constant.value)};"
        else:
            raise Refused(f"constant {constant.name!r} resolved to an unsupported type")
        add(f"    /// <summary>`{constant.source}`</summary>")
        add(f"    {rendered}")
        add("")
    add("    /// <summary>")
    add("    /// Digest of the closed result envelope and transition field/type census.")
    add("    /// The C# decoder source pins this value separately; changing only the")
    add("    /// generated artefact cannot widen the decoder.")
    add("    /// </summary>")
    add(
        "    public const string USER_AUTOMATION_RESULT_SCHEMA_SHA256 = "
        + csharp_string(digests["result_schema"])
        + ";"
    )
    add("")
    for _struct_name, member_constant, schema in result_structs:
        add(f"    /// <summary>Generated public members of `{schema.name}`.</summary>")
        add(f"    public static readonly string[] {member_constant} =")
        add("    [")
        for field in schema.fields:
            add(f"        {csharp_string(field.name)},")
        add("    ];")
        add("")
        if any(field.required for field in schema.fields) and any(
            not field.required for field in schema.fields
        ):
            required_constant = member_constant.replace("_MEMBERS", "_REQUIRED_MEMBERS")
            add(f"    /// <summary>Required serialized members of `{schema.name}`.</summary>")
            add(f"    public static readonly string[] {required_constant} =")
            add("    [")
            for field in schema.fields:
                if field.required:
                    add(f"        {csharp_string(field.name)},")
            add("    ];")
            add("")
    for _enum_name, value_constant, schema in result_enums:
        add(f"    /// <summary>Generated serialized variants of `{schema.name}`.</summary>")
        add(f"    public static readonly string[] {value_constant} =")
        add("    [")
        for variant in schema.variants:
            add(f"        {csharp_string(variant)},")
        add("    ];")
        add("")
    add("    /// <summary>")
    add("    /// The closed fold/gap disposition vocabulary, enumerated from the owner's")
    add("    /// own parser rather than listed by hand.")
    add("    /// </summary>")
    add("    public static readonly IReadOnlyList<string> Dispositions =")
    add("    [")
    for disposition in dispositions:
        add(f"        {csharp_string(disposition)},")
    add("    ];")
    add("")
    add("    /// <summary>")
    add("    /// Every owner refusal Display string, in owner declaration order.")
    add("    /// </summary>")
    add("    public static readonly IReadOnlyList<OperatorOwnerRefusalTemplate> OwnerRefusals =")
    add("    [")
    for refusal in refusals:
        prefix = refusal.display.split("{", 1)[0]
        add(
            "        new("
            + csharp_string(refusal.variant)
            + ", "
            + csharp_string(refusal.display)
            + ", "
            + csharp_string(prefix)
            + ", "
            + ("true" if "{" in refusal.display else "false")
            + "),"
        )
    add("    ];")
    add("}")
    add("")
    return "\n".join(lines)


def build(root: str) -> tuple[str, dict[str, int]]:
    sources = {path: read_source(os.path.join(root, path)) for path in SOURCE_FILES}

    # ---- pinned constants -------------------------------------------------
    declared = {path: collect_constants(lines) for path, lines in sources.items()}
    resolved: dict[str, object] = {}
    rendered: list[RustConstant] = []
    for name, path, expected in PINNED_CONSTANTS:
        declaration = declared[path].get(name)
        if declaration is None:
            raise Refused(f"pinned constant {name!r} is absent from {path}")
        if len(declaration.source) > 512:
            raise Refused(f"pinned constant {name!r} has an unexpectedly long declaration")
        value = evaluate_rust_expression(
            declaration.source.split("=", 1)[1].rsplit(";", 1)[0].strip()
            if "=" in declaration.source
            else "",
            resolved,
        )
        if expected == "string" and not isinstance(value, str):
            raise Refused(f"pinned constant {name!r} is not a string literal")
        if expected == "char" and not (isinstance(value, str) and len(value) == 1):
            raise Refused(f"pinned constant {name!r} is not a single-character literal")
        if expected == "int" and not isinstance(value, int):
            raise Refused(f"pinned constant {name!r} is not an integer literal")
        resolved[name] = value
        rendered.append(
            RustConstant(
                name=name,
                rust_type=declaration.rust_type,
                value=value,
                source=f"{name}\t{declaration.rust_type}\t{render_value(value)}",
            )
        )

    for name, expression in DERIVED_CONSTANTS:
        value = evaluate_rust_expression(expression, resolved)
        if not isinstance(value, int):
            raise Refused(f"derived constant {name!r} did not evaluate to an integer")
        resolved[name] = value
        rendered.append(
            RustConstant(
                name=name,
                rust_type="derived",
                value=value,
                source=f"{name}\tderived\t{expression} = {value}",
            )
        )

    result_struct_sources = {
        "AutomationOccurrenceIdentity": USER_AUTOMATION_RS,
        "AutomationExecutionReference": USER_AUTOMATION_RS,
        "UserAutomationRevision": USER_AUTOMATION_RS,
        "UserAutomationInvocation": USER_AUTOMATION_RS,
        "UserAutomationInvocationProvenance": USER_AUTOMATION_RS,
        "UserAutomationExecutionProjection": USER_AUTOMATION_RS,
        "UserAutomationFailureProjection": USER_AUTOMATION_RS,
        "AutomationReconciliationReference": USER_AUTOMATION_RS,
        "NormalizedSchedule": USER_AUTOMATION_RS,
        "AutomationWorkScope": USER_AUTOMATION_RS,
        "AutomationTaskBinding": USER_AUTOMATION_RS,
        "AutomationCapabilityProfile": USER_AUTOMATION_RS,
        "ProviderFingerprint": USER_AUTOMATION_RS,
        "RouteCostPolicy": USER_AUTOMATION_RS,
        "AutomationDeliveryTarget": USER_AUTOMATION_RS,
        "AutomationResourceCeiling": USER_AUTOMATION_RS,
        "RecursionPolicy": USER_AUTOMATION_RS,
        "RevisionDelta": STORE_API_RS,
        "OrderingHead": STORE_API_RS,
        "PolicyConfigSchemaVersions": STORE_API_RS,
        "UserAutomationRuntimeObligation": USER_AUTOMATION_ORCHESTRATION_RS,
        "UserAutomationOrchestrationRecord": USER_AUTOMATION_ORCHESTRATION_RS,
        "UserAutomationWakeReadback": USER_AUTOMATION_EXECUTION_RS,
        "OperationIdentity": STORE_API_RS,
        "WriteReceipt": STORE_API_RS,
        "StateFence": "crates/foundation/eliot-contracts/src/lib.rs",
        "EpochId": EPOCH_IDENTITY_RS,
        "WakeIntent": RUNTIME_CONTRACTS_RS,
    }
    result_structs = [
        (
            name,
            member_constant,
            collect_result_struct(
                sources[result_struct_sources.get(name, USER_AUTOMATION_TRANSITION_RS)],
                name,
            ),
        )
        for name, member_constant in RESULT_SCHEMA_STRUCTS
    ]
    result_declarations = [
        (
            path,
            name,
            collect_result_declaration(sources[path], name),
        )
        for path, name in RESULT_SCHEMA_DECLARATIONS
    ]
    result_schema_lines = [
        f"{path}\t{name}\n{declaration}"
        for path, name, declaration in result_declarations
    ]
    result_schema_lines.append(
        f"{USER_AUTOMATION_TRANSITION_RS}\tUserAutomationOperatorResultValue::Deserialize\n"
        + collect_result_deserializer(
            sources[USER_AUTOMATION_TRANSITION_RS],
            "UserAutomationOperatorResultValue",
        )
    )
    result_schema_digest = hashlib.sha256(
        "\n".join(result_schema_lines).encode("utf-8")
    ).hexdigest()
    result_enums = [
        (name, value_constant, collect_result_enum(sources[path], name))
        for path, name, value_constant in RESULT_SCHEMA_ENUMS
    ]
    decoder_lines = read_source(os.path.join(root, OPERATOR_RESULT_DECODER_CS))
    decoder_source = "\n".join(decoder_lines)
    pin_pattern = re.compile(
        rf"\bconst\s+string\s+{re.escape(RESULT_SCHEMA_DECODER_PIN)}\s*=\s*\"([0-9a-f]{{64}})\""
    )
    pin_match = pin_pattern.search(decoder_source)
    if pin_match is None:
        raise Refused(
            f"Operator decoder pin {RESULT_SCHEMA_DECODER_PIN!r} is absent from {OPERATOR_RESULT_DECODER_CS}"
        )
    if pin_match.group(1) != result_schema_digest:
        raise Refused(
            "Rust UserAutomation result schema changed; update the C# decoder and its explicit schema pin "
            f"({pin_match.group(1)} != {result_schema_digest})"
        )

    constants_digest = hashlib.sha256(
        "".join(f"{c.source}\n" for c in rendered).encode("utf-8")
    ).hexdigest()

    # ---- dispositions, refusals, grammar bodies --------------------------
    disposition_source = sources[USER_AUTOMATION_RS]
    dispositions = collect_dispositions(disposition_source)
    dispositions_digest = hashlib.sha256(
        "\n".join(dispositions).encode("utf-8")
    ).hexdigest()

    refusals = collect_refusals(disposition_source)
    refusals_digest = hashlib.sha256(
        "".join(f"{r.variant}\t{r.display}\n" for r in refusals).encode("utf-8")
    ).hexdigest()

    functions = [collect_functions(disposition_source, name) for name in PINNED_GRAMMAR_FUNCTIONS]
    function_digests = {
        f"function:{function.name}": hashlib.sha256(
            function.body.encode("utf-8")
        ).hexdigest()
        for function in functions
    }
    grammar_digest = hashlib.sha256(
        "".join(
            f"{function.name}\t{function_digests['function:' + function.name]}\n"
            for function in functions
        ).encode("utf-8")
    ).hexdigest()

    digests = {
        "constants": constants_digest,
        "dispositions": dispositions_digest,
        "refusals": refusals_digest,
        "grammar": grammar_digest,
        "result_schema": result_schema_digest,
    }
    digests.update(function_digests)
    digests["contract"] = hashlib.sha256(
        "".join(
            f"{key}\t{digests[key]}\n"
            for key in ("constants", "dispositions", "refusals", "grammar", "result_schema")
        ).encode("utf-8")
    ).hexdigest()

    return render_artefact(
        rendered,
        dispositions,
        refusals,
        functions,
        result_structs,
        result_enums,
        digests,
    ), {
        "constants": len(rendered),
        "dispositions": len(dispositions),
        "refusals": len(refusals),
        "grammar_functions": len(functions),
        "result_schema_fields": sum(len(schema.fields) for _, _, schema in result_structs),
        "result_schema_enums": len(result_enums),
    }


def render_value(value: object) -> str:
    if isinstance(value, str):
        if len(value) == 1:
            return f"'{value}'"
        return json_dumps(value)
    return str(value)


def json_dumps(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def first_difference(expected: str, actual: str) -> int:
    limit = min(len(expected), len(actual))
    for index in range(limit):
        if expected[index] != actual[index]:
            return index
    return limit


def normalise_line_endings(raw: bytes) -> bytes:
    """Line-ending-insensitive form of a text artefact.

    The repository pins LF for Rust/TOML/Markdown/JSON/PowerShell, not for C#,
    so a fresh Windows checkout may deliver this artefact with CRLF. Comparing
    raw bytes would then fail on line endings alone, which is a fact about the
    host and not about contract drift. Line endings are therefore NOT part of
    the compared identity; every other byte still is, and the on-disk byte count
    is reported alongside the normalised one so a line-ending-only difference
    stays visible.
    """
    return raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when the committed artefact is stale (the parity gate)",
    )
    parser.add_argument(
        "--root",
        default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        help="repository root the owner Rust source is read from",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="artefact path override; defaults to the repository path, resolved "
        "against the current directory so a scratch --root still checks the "
        "committed artefact",
    )
    args = parser.parse_args(argv)

    root = os.path.abspath(args.root)
    out = os.path.abspath(args.out or ARTEFACT)

    def display(path: str) -> str:
        """Readable path: repository-relative when it is inside the root."""
        absolute = os.path.abspath(path)
        if os.path.commonpath([absolute, root]) == root:
            return os.path.relpath(absolute, root)
        return absolute

    try:
        payload, summary = build(root)
    except Refused as error:
        print(f"refused: {error}", file=sys.stderr)
        return 2

    raw = payload.encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()

    if args.check:
        if not os.path.isfile(out):
            print(
                f"stale: {display(out)} is missing; regenerate the "
                "Operator schedule contract mirror",
                file=sys.stderr,
            )
            return 1
        with open(out, "rb") as handle:
            committed = handle.read()
        committed_normalised = normalise_line_endings(committed)
        if committed_normalised != raw:
            offset = first_difference(payload, committed_normalised.decode("utf-8", "replace"))
            print(
                "stale: the committed Operator schedule contract mirror does not "
                "match the current Kernel owner contract.",
                file=sys.stderr,
            )
            print(
                f"  artefact: {display(out)}",
                file=sys.stderr,
            )
            print(f"  first difference at byte {offset}", file=sys.stderr)
            print(
                f"  expected sha256={digest} bytes={len(raw)}",
                file=sys.stderr,
            )
            print(
                f"  committed sha256={hashlib.sha256(committed_normalised).hexdigest()} "
                f"bytes={len(committed_normalised)} "
                f"(line-ending normalised from {len(committed)} on-disk bytes)",
                file=sys.stderr,
            )
            print(
                "  the Kernel schedule/occurrence contract changed, or this artefact "
                "was hand-edited; run "
                "python scripts/gen_operator_schedule_contract.py and review the diff",
                file=sys.stderr,
            )
            return 1
        print(
            f"ok: operator-schedule-contract mirror is current bytes={len(raw)} "
            f"sha256={digest}"
        )
        return 0

    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "wb") as handle:
        handle.write(raw)
    print(
        f"wrote {display(out)} bytes={len(raw)} sha256={digest} "
        + " ".join(f"{key}={value}" for key, value in summary.items())
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
