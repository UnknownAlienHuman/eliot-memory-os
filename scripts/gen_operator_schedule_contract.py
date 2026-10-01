#!/usr/bin/env python3
"""Generate the C# mirror of the Kernel UserAutomation schedule contract (#2865).

The Kernel owner contract is `crates/kernel/eliot-kernel-core/src/user_automation.rs`
together with `user_automation_zones.rs`. The Operator is NOT a second
calendar/zone owner: it validates the bounded wire shape and the exact supported
contract version of what the owner issued, and it never resolves a zone, reads a
timezone database, or consults ambient Windows locale/timezone data. To keep that
boundary honest, the grammar constants, the closed operation/member census, the
result value discriminators and member census, the closed disposition vocabulary,
the owner refusal Display strings and the byte shape of every grammar function
the mirror reimplements are GENERATED from the Rust source of truth instead of
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
RECEIPTS_RS = "crates/foundation/eliot-receipts/src/lib.rs"
PLATFORM_HANDLE_RS = "crates/kernel/eliot-platform/src/handle_nonce.rs"
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
    RECEIPTS_RS,
    PLATFORM_HANDLE_RS,
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
    ("USER_AUTOMATION_NORMALIZATION_OPERATION_KIND", USER_AUTOMATION_RS, "string"),
    ("USER_AUTOMATION_LEGACY_MIGRATION_OPERATION_KIND", USER_AUTOMATION_RS, "string"),
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
    ("UserAutomationOperatorContextValue", "USER_AUTOMATION_CONTEXT_VALUE_MEMBERS"),
    ("UserAutomationNormalizedScheduleValue", "USER_AUTOMATION_NORMALIZED_SCHEDULE_VALUE_MEMBERS"),
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

# Closed request operation tags and the fields of the operations the Operator
# constructs directly. These arrays come from the same Rust tagged enum as the
# result schema above; adding or changing one makes the generated artifact stale
# at the existing MSBuild parity gate.
REQUEST_OPERATION_ENUM = (USER_AUTOMATION_RS, "UserAutomationOperation")
REQUEST_OPERATION_VARIANTS = (
    ("Create", "USER_AUTOMATION_CREATE_OPERATION_MEMBERS"),
    ("Edit", "USER_AUTOMATION_EDIT_OPERATION_MEMBERS"),
    ("NormalizeSchedule", "USER_AUTOMATION_NORMALIZE_SCHEDULE_OPERATION_MEMBERS"),
    ("MigrateLegacySchedule", "USER_AUTOMATION_MIGRATE_LEGACY_SCHEDULE_OPERATION_MEMBERS"),
    ("GetContext", "USER_AUTOMATION_GET_CONTEXT_OPERATION_MEMBERS"),
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
    in_serde_attribute = False
    field_re = re.compile(r"^\s*pub\s+([a-zA-Z0-9_]+)\s*:\s*(.+),\s*$")
    for line in lines[start:]:
        stripped = line.strip()
        if stripped == "}":
            break
        if stripped.startswith("#[serde("):
            pending_serde += stripped
            in_serde_attribute = not stripped.endswith(")]")
            continue
        if in_serde_attribute:
            pending_serde += stripped
            in_serde_attribute = not stripped.endswith(")]")
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
    header = re.compile(
        rf"^\s*(?:(?:pub(?:\([^)]*\))?)\s+)?(?:struct|enum)\s+{re.escape(name)}\b"
    )
    for index, line in enumerate(lines):
        if header.match(line) is None:
            continue
        first = _preceding_attributes_start(lines, index)
        type_kind = re.search(r"\b(struct|enum)\b", line)
        if type_kind is not None and type_kind.group(1) == "struct":
            # Tuple/unit structs end with `;` and have no declaration body.
            # Stop there instead of accidentally absorbing the following impl
            # block as if it were part of the serialized type.
            line_code = line.split("//", 1)[0]
            if ";" in line_code and "{" not in line_code:
                return "\n".join(lines[first : index + 1])
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


def _matching_delimiter(text: str, start: int, opening: str, closing: str) -> int:
    """Return the matching delimiter while ignoring Rust comments and literals."""
    depth = 0
    in_string = False
    in_char = False
    escaped = False
    line_comment = False
    block_comment = 0
    for index in range(start, len(text)):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            continue
        if block_comment:
            if char == "/" and next_char == "*":
                block_comment += 1
            elif char == "*" and next_char == "/":
                block_comment -= 1
            continue
        if in_string or in_char:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif in_string and char == '"':
                in_string = False
            elif in_char and char == "'":
                in_char = False
            continue
        if char == "/" and next_char == "/":
            line_comment = True
            continue
        if char == "/" and next_char == "*":
            block_comment = 1
            continue
        if char == '"':
            in_string = True
            continue
        # A Rust lifetime starts with `'` followed by an identifier, while a
        # character literal closes with the next unescaped quote. Only enter
        # character mode when a closing quote appears before a newline.
        if char == "'" and re.match(r"'(?:\\.|[^'\\])'", text[index:]) is not None:
            in_char = True
            continue
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index
    raise Refused(f"unclosed Rust delimiter {opening!r} in result schema input")


def _strip_rust_comments_and_attributes(
    text: str, *, strip_attributes: bool = True
) -> str:
    """Remove comments and, by default, Rust attributes from declaration text."""
    output: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        next_pair = text[index : index + 2]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if next_pair == "//":
            newline = text.find("\n", index)
            if newline == -1:
                break
            output.append("\n")
            index = newline + 1
            continue
        if next_pair == "/*":
            end = index + 2
            depth = 1
            while end < len(text) and depth:
                pair = text[end : end + 2]
                if pair == "/*":
                    depth += 1
                    end += 2
                elif pair == "*/":
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise Refused("unclosed Rust block comment in result schema input")
            output.append(" ")
            index = end
            continue
        if next_pair == "#[" and strip_attributes:
            end = _matching_delimiter(text, index + 1, "[", "]")
            output.append(" ")
            index = end + 1
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _split_top_level(text: str, delimiter: str) -> list[str]:
    """Split Rust declaration text at delimiters outside nested type syntax."""
    result: list[str] = []
    start = 0
    angles = parens = brackets = braces = 0
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            continue
        if char == delimiter and angles == parens == brackets == braces == 0:
            result.append(text[start:index])
            start = index + 1
            continue
        if char == "<":
            angles += 1
        elif char == ">" and angles:
            angles -= 1
        elif char == "(":
            parens += 1
        elif char == ")":
            parens -= 1
        elif char == "[":
            brackets += 1
        elif char == "]":
            brackets -= 1
        elif char == "{":
            braces += 1
        elif char == "}":
            braces -= 1
    result.append(text[start:])
    return result


def _strip_leading_rust_attributes(text: str) -> tuple[str, bool]:
    """Remove adjacent leading attributes and report whether any were present."""
    index = 0
    found = False
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if not text.startswith("#[", index):
            break
        closing = _matching_delimiter(text, index + 1, "[", "]")
        index = closing + 1
        found = True
    return text[index:].strip(), found


def _declaration_kind(declaration: str, name: str) -> str:
    code = _strip_rust_comments_and_attributes(declaration)
    match = re.search(
        rf"\b(struct|enum|type)\s+{re.escape(name)}\b", code
    )
    if match is None:
        for macro_name in _RESULT_TYPE_MACROS:
            if f"{macro_name}!" in declaration:
                return f"macro:{macro_name}"
        raise Refused(f"result schema declaration kind for {name!r} is unsupported")
    return match.group(1)


def _type_expressions(declaration: str, name: str) -> list[str]:
    """Read field/payload type expressions from one struct, enum or alias."""
    code = _strip_rust_comments_and_attributes(declaration)
    kind = _declaration_kind(declaration, name)
    if kind.startswith("macro:"):
        return []
    if kind == "type":
        alias = re.search(rf"\btype\s+{re.escape(name)}\b[^=]*=\s*(.*?);", code, re.S)
        if alias is None:
            raise Refused(f"type alias {name!r} could not be read exactly")
        return [alias.group(1)]

    header = re.search(rf"\b(?:struct|enum)\s+{re.escape(name)}\b", code)
    assert header is not None
    open_brace = code.find("{", header.end())
    semicolon = code.find(";", header.end())
    if kind == "struct" and semicolon >= 0 and (open_brace < 0 or semicolon < open_brace):
        open_paren = code.find("(", header.end(), semicolon)
        if open_paren < 0:
            return []
        close_paren = _matching_delimiter(code, open_paren, "(", ")")
        return [
            value.strip()
            for value in _split_top_level(code[open_paren + 1 : close_paren], ",")
            if value.strip()
        ]
    if open_brace < 0:
        raise Refused(f"result schema declaration {name!r} has no body")
    close_brace = _matching_delimiter(code, open_brace, "{", "}")
    body = code[open_brace + 1 : close_brace]

    def field_types(field_body: str) -> list[str]:
        types: list[str] = []
        for member in _split_top_level(field_body, ","):
            parts = _split_top_level(member, ":")
            if len(parts) < 2:
                continue
            types.append(":".join(parts[1:]).strip())
        return types

    if kind == "struct":
        return field_types(body)

    types = []
    for variant in _split_top_level(body, ","):
        open_paren = variant.find("(")
        open_variant_brace = variant.find("{")
        if open_variant_brace >= 0 and (open_paren < 0 or open_variant_brace < open_paren):
            close_variant_brace = _matching_delimiter(
                variant, open_variant_brace, "{", "}"
            )
            types.extend(field_types(variant[open_variant_brace + 1 : close_variant_brace]))
        elif open_paren >= 0:
            close_paren = _matching_delimiter(variant, open_paren, "(", ")")
            types.extend(
                value.strip()
                for value in _split_top_level(variant[open_paren + 1 : close_paren], ",")
                if value.strip()
            )
    return types


_RUST_PRIMITIVE_TYPES = {
    "bool", "char", "str", "String", "u8", "u16", "u32", "u64", "u128",
    "usize", "i8", "i16", "i32", "i64", "i128", "isize", "f32", "f64",
    "Self", "Box", "Vec", "Option", "Result", "BTreeMap", "BTreeSet",
    "HashMap", "HashSet", "VecDeque", "Cow", "Arc", "Rc", "RefCell",
    "Cell", "NonZeroU8", "NonZeroU16", "NonZeroU32", "NonZeroU64",
}


def _type_references(expression: str, generic_parameters: set[str]) -> set[str]:
    """Return custom Rust type identifiers referenced by a field type."""
    code = _strip_rust_comments_and_attributes(expression)
    code = re.sub(r"'(?:[A-Za-z_][A-Za-z0-9_]*|_)", " ", code)
    identifiers = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", code))
    return {
        identifier
        for identifier in identifiers
        if identifier[0].isupper()
        and identifier not in _RUST_PRIMITIVE_TYPES
        and identifier not in generic_parameters
    }


def _generic_parameters(declaration: str, name: str) -> set[str]:
    code = _strip_rust_comments_and_attributes(declaration)
    match = re.search(rf"\b(?:struct|enum|type)\s+{re.escape(name)}\b", code)
    if match is None:
        return set()
    after_name = code[match.end() :]
    generic_open = re.match(r"\s*<", after_name)
    if generic_open is None:
        return set()
    open_angle = match.end() + generic_open.end() - 1
    close_angle = _matching_delimiter(code, open_angle, "<", ">")
    params = set()
    for parameter in _split_top_level(code[open_angle + 1 : close_angle], ","):
        found = re.match(r"\s*(?:const\s+)?(?:'([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*))", parameter)
        if found is not None:
            params.add(found.group(1) or found.group(2))
    return params


def _collect_result_type_alias(lines: list[str], name: str) -> str:
    header = re.compile(
        rf"^\s*(?:(?:pub(?:\([^)]*\))?)\s+)?type\s+{re.escape(name)}\b"
    )
    for index, line in enumerate(lines):
        if header.match(line) is None:
            continue
        first = _preceding_attributes_start(lines, index)
        statement = lines[index]
        end = index
        while not statement_ends(statement) and end + 1 < len(lines):
            end += 1
            statement += " " + lines[end].strip()
        if not statement_ends(statement):
            raise Refused(f"result schema type alias {name!r} has no terminator")
        return "\n".join(lines[first : index + 1] + lines[index + 1 : end + 1])
    raise Refused(f"result schema type alias {name!r} is absent")


def _preceding_attributes_start(lines: list[str], declaration_index: int) -> int:
    """Return the start of adjacent attributes, including multiline groups."""
    first = declaration_index
    cursor = declaration_index - 1
    while cursor >= 0:
        if not lines[cursor].strip():
            break
        if lines[cursor].lstrip().startswith("//"):
            break

        depth = 0
        group_start = None
        for candidate_index in range(cursor, -1, -1):
            candidate = lines[candidate_index]
            if not candidate.strip() or candidate.lstrip().startswith("//"):
                break
            code = re.sub(r'"(?:\\.|[^"\\])*"', '""', candidate)
            for char in reversed(code):
                if char == "]":
                    depth += 1
                elif char == "[":
                    depth -= 1
            if depth == 0 and candidate.lstrip().startswith("#["):
                group_start = candidate_index
                break
            if depth < 0:
                break
        if group_start is None:
            break
        first = group_start
        cursor = group_start - 1
    return first


_RESULT_TYPE_MACROS = ("opaque_id", "string_id", "counter")


def _collect_type_macro_type(lines: list[str], name: str, macro_name: str) -> str:
    text = "\n".join(lines)
    for match in re.finditer(rf"\b{re.escape(macro_name)}\s*!\s*\(", text):
        opening = text.find("(", match.start())
        closing = _matching_delimiter(text, opening, "(", ")")
        invocation = text[match.start() : closing + 1]
        without_line_comments = re.sub(r"(?m)//[^\n]*", "", invocation)
        if re.search(rf"\b{re.escape(name)}\s*,", without_line_comments) is not None:
            return invocation
    raise Refused(f"{macro_name}! schema invocation {name!r} is absent")


def _collect_type_macro_definition(lines: list[str], macro_name: str) -> str:
    text = "\n".join(lines)
    match = re.search(
        rf"\bmacro_rules\s*!\s*{re.escape(macro_name)}\s*\{{", text
    )
    if match is None:
        raise Refused(f"{macro_name}! macro definition is absent from its owner source")
    opening = text.find("{", match.start())
    closing = _matching_delimiter(text, opening, "{", "}")
    return text[match.start() : closing + 1]


def _collect_serde_impls(lines: list[str], name: str) -> list[str]:
    text = "\n".join(lines)
    implementations = []
    for match in re.finditer(r"(?m)^\s*impl\b", text):
        opening = _find_impl_body_opening(text, match.start())
        if opening < 0:
            raise Refused(f"serde impl for {name!r} has no body")
        header = _strip_rust_comments_and_attributes(text[match.start() : opening])
        if re.search(r"\b(?:Serialize|Deserialize)\b", header) is None:
            continue
        if re.search(
            rf"\bfor\s+(?:[A-Za-z_][A-Za-z0-9_]*::)*{re.escape(name)}\b",
            header,
        ) is None:
            continue
        closing = _matching_delimiter(text, opening, "{", "}")
        implementations.append(text[match.start() : closing + 1])
    return implementations


def _serde_impl_type_references(
    implementation: str, generic_parameters: set[str]
) -> set[str]:
    """Find qualified owner types used by custom serde code, such as *Wire DTOs."""
    code = _strip_rust_comments_and_attributes(implementation)
    code = re.sub(r'"(?:\\.|[^"\\])*"', '""', code)
    code = re.sub(r"\bserde_json\s*::\s*Value\b", " ", code)
    names = set(re.findall(r"\b([A-Z][A-Za-z0-9_]*)\s*::", code))
    serde_and_std_paths = {
        "Deserialize", "Serialize", "Deserializer", "Serializer", "Error"
    }
    return {
        name
        for name in names
        if name not in _RUST_PRIMITIVE_TYPES
        and name not in generic_parameters
        and name not in serde_and_std_paths
    }


def _implementation_generic_parameters(implementation: str) -> set[str]:
    """Read generic names from a custom impl header so they are not owner types."""
    opening = _find_impl_body_opening(implementation, 0)
    if opening < 0:
        raise Refused("custom serde implementation has no body")
    header = _strip_rust_comments_and_attributes(implementation[:opening])
    parameters: set[str] = set()

    def add_parameter_names(generic_list: str) -> None:
        for parameter in _split_top_level(generic_list, ","):
            found = re.match(
                r"\s*(?:const\s+)?(?:'([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*))",
                parameter,
            )
            if found is not None:
                parameters.add(found.group(1) or found.group(2))

    impl_generic = re.match(r"\s*impl\s*<", header)
    if impl_generic is not None:
        open_angle = impl_generic.end() - 1
        close_angle = _matching_delimiter(header, open_angle, "<", ">")
        add_parameter_names(header[open_angle + 1 : close_angle])

    body = _strip_rust_comments_and_attributes(implementation)
    for function in re.finditer(r"\bfn\s+[A-Za-z_][A-Za-z0-9_]*\s*<", body):
        open_angle = body.find("<", function.start())
        close_angle = _matching_delimiter(body, open_angle, "<", ">")
        add_parameter_names(body[open_angle + 1 : close_angle])
    return parameters


def _find_impl_body_opening(text: str, start: int) -> int:
    """Find one impl body brace without confusing comments/generics for its body."""
    angles = parens = brackets = 0
    in_string = False
    escaped = False
    line_comment = False
    block_comment = 0
    index = start
    while index < len(text):
        char = text[index]
        next_pair = text[index : index + 2]
        if line_comment:
            if char == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if next_pair == "/*":
                block_comment += 1
                index += 2
            elif next_pair == "*/":
                block_comment -= 1
                index += 2
            else:
                index += 1
            continue
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if next_pair == "//":
            line_comment = True
            index += 2
            continue
        if next_pair == "/*":
            block_comment = 1
            index += 2
            continue
        if char == '"':
            in_string = True
        elif char == "<":
            angles += 1
        elif char == ">" and angles:
            angles -= 1
        elif char == "(":
            parens += 1
        elif char == ")":
            parens -= 1
        elif char == "[":
            brackets += 1
        elif char == "]":
            brackets -= 1
        elif char == "{" and angles == parens == brackets == 0:
            return index
        elif char == ";" and angles == parens == brackets == 0:
            return -1
        index += 1
    return -1


def collect_result_schema_closure(
    sources: dict[str, list[str]], roots: tuple[tuple[str, str], ...]
) -> list[tuple[str, str, str]]:
    """Resolve and fingerprint every custom type nested below accepted result roots."""
    if len(set(roots)) != len(roots):
        raise Refused("RESULT_SCHEMA_DECLARATIONS repeats a pinned owner declaration")
    declarations: dict[tuple[str, str], tuple[str, str]] = {}
    type_index: dict[str, list[tuple[str, str, str]]] = {}
    for path, lines in sources.items():
        for line in lines:
            type_header = re.match(
                r"^\s*(?:(?:pub(?:\([^)]*\))?)\s+)?(struct|enum)\s+([A-Z][A-Za-z0-9_]*)\b",
                line,
            )
            if type_header is not None:
                kind, name = type_header.groups()
                type_index.setdefault(name, []).append((path, name, kind))
                continue
            alias_header = re.match(
                r"^\s*(?:(?:pub(?:\([^)]*\))?)\s+)?type\s+([A-Z][A-Za-z0-9_]*)\b",
                line,
            )
            if alias_header is not None:
                name = alias_header.group(1)
                type_index.setdefault(name, []).append((path, name, "type"))

        text = "\n".join(lines)
        for macro_name in _RESULT_TYPE_MACROS:
            for match in re.finditer(rf"\b{re.escape(macro_name)}\s*!\s*\(", text):
                opening = text.find("(", match.start())
                closing = _matching_delimiter(text, opening, "(", ")")
                invocation = text[match.start() : closing + 1]
                invocation = re.sub(r"(?m)//[^\n]*", "", invocation)
                declared = re.search(r"\b([A-Z][A-Za-z0-9_]*)\s*,", invocation)
                if declared is not None:
                    name = declared.group(1)
                    candidate = (path, name, f"macro:{macro_name}")
                    if candidate not in type_index.setdefault(name, []):
                        type_index[name].append(candidate)

    for name, candidates in type_index.items():
        type_index[name] = list(dict.fromkeys(candidates))

    pending = list(dict.fromkeys(roots))
    visited: set[tuple[str, str]] = set()
    while pending:
        path, name = pending.pop(0)
        key = (path, name)
        if key in visited:
            continue
        if path not in sources:
            raise Refused(f"result schema source {path!r} is not pinned in SOURCE_FILES")
        macro_kind = next(
            (
                kind
                for candidate_path, candidate_name, kind in type_index.get(name, [])
                if candidate_path == path
                and candidate_name == name
                and kind.startswith("macro:")
            ),
            None,
        )
        if macro_kind is not None:
            macro_name = macro_kind.removeprefix("macro:")
            declaration = _collect_type_macro_type(sources[path], name, macro_name)
            declaration = (
                f"{macro_name}! macro definition\n"
                + _collect_type_macro_definition(sources[path], macro_name)
                + "\ninvocation\n"
                + declaration
            )
        elif (path, name, "type") in type_index.get(name, []):
            declaration = _collect_result_type_alias(sources[path], name)
        else:
            declaration = collect_result_declaration(sources[path], name)
        kind = _declaration_kind(declaration, name)
        serde_impls = _collect_serde_impls(sources[path], name)
        if serde_impls:
            declaration += "\ncustom serde implementations\n" + "\n".join(serde_impls)
        declarations[key] = (kind, declaration)
        visited.add(key)

        generic_parameters = _generic_parameters(declaration, name)
        dependencies: set[str] = set()
        for expression in _type_expressions(declaration, name):
            dependencies.update(_type_references(expression, generic_parameters))
        for implementation in serde_impls:
            dependencies.update(
                _serde_impl_type_references(
                    implementation,
                    _implementation_generic_parameters(implementation),
                )
            )
        for dependency in sorted(dependencies):
            candidates = type_index.get(dependency, [])
            if not candidates:
                raise Refused(
                    f"result schema type {path}:{name} references unresolved non-primitive "
                    f"type {dependency!r}"
                )
            if len(candidates) == 1:
                selected = candidates[0]
            else:
                distinct = sorted({candidate[0] for candidate in candidates})
                raise Refused(
                    f"result schema type {path}:{name} references ambiguous type "
                    f"{dependency!r} in {distinct!r}"
                )
            pending.append((selected[0], selected[1]))

    return [
        (path, name, declarations[(path, name)][1])
        for path, name in sorted(visited)
    ]


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


def collect_result_outcomes(lines: list[str], name: str) -> list[str]:
    """Collect the explicit literal outcomes accepted by a closed result decoder."""
    decoder = _strip_rust_comments_and_attributes(
        collect_result_deserializer(lines, name)
    )
    match = re.search(
        r'match\s+object\.get\("outcome"\)\s*\.and_then\s*'
        r'\(\s*serde_json::Value::as_str\s*\)\s*\{',
        decoder,
    )
    if match is None:
        raise Refused(f"result deserializer {name!r} has no pinned outcome match")
    opening = decoder.find("{", match.start())
    closing = _matching_delimiter(decoder, opening, "{", "}")
    arms = decoder[opening + 1 : closing]
    literals = list(
        re.finditer(
            r'\bSome\s*\(\s*("(?:\\.|[^"\\])*")\s*\)\s*=>\s*'
            r'("(?:\\.|[^"\\])*")',
            arms,
        )
    )
    if len(literals) != len(re.findall(r"\bSome\s*\(", arms)):
        raise Refused(
            f"result deserializer {name!r} changed its literal outcome mapping"
        )
    outcomes: list[str] = []
    for literal in literals:
        accepted = decode_rust_string(literal.group(1))
        selected = decode_rust_string(literal.group(2))
        if accepted != selected:
            raise Refused(
                f"result deserializer {name!r} maps outcome {accepted!r} "
                f"to unsupported discriminator {selected!r}"
            )
        outcomes.append(accepted)
    if not outcomes or len(set(outcomes)) != len(outcomes):
        raise Refused(f"result deserializer {name!r} has no unique outcome values")
    return outcomes


def collect_enum_variant_members(
    lines: list[str], enum_name: str, variant_name: str
) -> RustResultStruct:
    """Collect the JSON members carried by one tagged enum operation variant."""
    declaration = collect_result_declaration(lines, enum_name)
    code = _strip_rust_comments_and_attributes(declaration, strip_attributes=False)
    header = re.search(rf"\benum\s+{re.escape(enum_name)}\b", code)
    if header is None:
        raise Refused(f"request operation enum {enum_name!r} is absent")
    opening = code.find("{", header.end())
    if opening < 0:
        raise Refused(f"request operation enum {enum_name!r} has no body")
    closing = _matching_delimiter(code, opening, "{", "}")
    body = code[opening + 1 : closing]
    for variant in _split_top_level(body, ","):
        text, has_variant_attributes = _strip_leading_rust_attributes(variant)
        variant_match = re.match(r"([A-Z][A-Za-z0-9_]*)\b(.*)", text, re.S)
        if variant_match is None or variant_match.group(1) != variant_name:
            continue
        if has_variant_attributes:
            raise Refused(
                f"request operation variant {enum_name}::{variant_name} uses unsupported attributes"
            )
        payload = variant_match.group(2).strip()
        if not payload:
            return RustResultStruct(
                f"{enum_name}::{variant_name}", ()
            )
        if not payload.startswith("{"):
            raise Refused(
                f"request operation {enum_name}::{variant_name} is not a unit or struct variant"
            )
        payload_close = _matching_delimiter(payload, 0, "{", "}")
        if payload[payload_close + 1 :].strip():
            raise Refused(
                f"request operation {enum_name}::{variant_name} has trailing syntax"
            )
        fields: list[RustResultField] = []
        for member in _split_top_level(payload[1:payload_close], ","):
            member, has_attributes = _strip_leading_rust_attributes(member)
            if not member:
                continue
            if has_attributes or "#[" in member:
                raise Refused(
                    f"request operation fields in {enum_name}::{variant_name} use unsupported attributes"
                )
            parts = _split_top_level(member, ":")
            if len(parts) < 2:
                raise Refused(
                    f"request operation field in {enum_name}::{variant_name} is not a named field"
                )
            field_name = parts[0].strip()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field_name) is None:
                raise Refused(
                    f"request operation field in {enum_name}::{variant_name} has an unsupported name"
                )
            fields.append(
                RustResultField(field_name, ":".join(parts[1:]).strip(), True)
            )
        return RustResultStruct(f"{enum_name}::{variant_name}", tuple(fields))
    raise Refused(
        f"request operation variant {enum_name}::{variant_name} is absent"
    )


def collect_enum_discriminator(lines: list[str], enum_name: str) -> str:
    """Collect the literal serde tag field for one internally tagged enum."""
    declaration = collect_result_declaration(lines, enum_name)
    code = _strip_rust_comments_and_attributes(declaration, strip_attributes=False)
    header = re.search(rf"\benum\s+{re.escape(enum_name)}\b", code)
    if header is None:
        raise Refused(f"request operation enum {enum_name!r} is absent")
    attributes = code[: header.start()]
    serde_attributes = re.findall(
        r"#\s*\[\s*serde\s*\((.*?)\)\s*\]", attributes, re.S
    )
    tags = [
        decode_rust_string(match.group(1))
        for attribute in serde_attributes
        for match in re.finditer(
            r"\btag\s*=\s*((?:\"(?:\\.|[^\"\\])*\"))", attribute
        )
    ]
    if len(tags) != 1 or not tags[0]:
        raise Refused(
            f"request operation enum {enum_name!r} must have one literal serde tag"
        )
    rename_rules = [
        decode_rust_string(match.group(1))
        for attribute in serde_attributes
        for match in re.finditer(
            r"\brename_all\s*=\s*((?:\"(?:\\.|[^\"\\])*\"))", attribute
        )
    ]
    if len(rename_rules) != 1 or rename_rules[0] not in {
        "lowercase",
        "snake_case",
        "SCREAMING_SNAKE_CASE",
        "kebab-case",
    }:
        raise Refused(
            f"request operation enum {enum_name!r} must have one supported literal rename_all rule"
        )
    opening = code.find("{", header.end())
    if opening < 0:
        raise Refused(f"request operation enum {enum_name!r} has no body")
    closing = _matching_delimiter(code, opening, "{", "}")
    for variant in _split_top_level(code[opening + 1 : closing], ","):
        _text, has_attributes = _strip_leading_rust_attributes(variant)
        if has_attributes:
            raise Refused(
                f"request operation enum {enum_name!r} uses unsupported variant attributes"
            )
    return tags[0]


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
    """Read the owner's closed literal-to-disposition parser without guessing."""
    function = collect_functions(lines, DISPOSITION_FUNCTION)
    code = collapse(_strip_rust_comments_and_attributes(function.body))
    function_shape = re.fullmatch(
        r"fn\s+parse_occurrence_disposition\s*\(\s*"
        r"value\s*:\s*&str\s*,\s*field\s*:\s*&'static\s+str\s*,?\s*"
        r"\)\s*->\s*Result\s*<\s*OccurrenceDisposition\s*,\s*"
        r"UserAutomationError\s*>\s*\{\s*match\s+value\s*\{(?P<arms>.*)\}\s*\}",
        code,
    )
    if function_shape is None:
        raise Refused(
            f"{DISPOSITION_FUNCTION} changed its pinned closed parser shape"
        )

    dispositions: list[str] = []
    fallback_count = 0
    for arm in _split_top_level(function_shape.group("arms"), ","):
        arm = collapse(arm)
        if not arm:
            continue
        if re.fullmatch(
            r"_\s*=>\s*Err\(UserAutomationError::Invalid\(field\)\)", arm
        ):
            fallback_count += 1
            continue
        literal_arm = re.fullmatch(
            r'("(?:\\.|[^"\\])*")\s*=>\s*Ok\(\s*'
            + re.escape(DISPOSITION_VARIANT_TYPE)
            + r"::([A-Za-z_][A-Za-z0-9_]*)\s*\)",
            arm,
        )
        if literal_arm is None:
            raise Refused(
                f"{DISPOSITION_FUNCTION} contains an unpinned arm {arm!r}; "
                "only direct literal mappings and the exact refusing fallback are supported"
            )
        wire_value = decode_rust_string(literal_arm.group(1))
        if re.fullmatch(r"[A-Z0-9_]+", wire_value) is None:
            raise Refused(
                f"{DISPOSITION_FUNCTION} contains a non-canonical disposition "
                f"spelling {wire_value!r}"
            )
        dispositions.append(wire_value)

    if fallback_count != 1:
        raise Refused(
            f"{DISPOSITION_FUNCTION} must retain exactly one refusing fallback arm"
        )
    if not dispositions:
        raise Refused(
            f"{DISPOSITION_FUNCTION} carries no {DISPOSITION_VARIANT_TYPE} literal mappings"
        )
    if len(set(dispositions)) != len(dispositions):
        raise Refused(f"{DISPOSITION_FUNCTION} repeats a disposition spelling")
    return dispositions


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
    request_operation_discriminator: str,
    request_operation_kinds: list[str],
    request_operation_structs: list[tuple[str, RustResultStruct]],
    result_value_outcomes: list[str],
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
    add("    /// <summary>Serde discriminator field of `UserAutomationOperation`.</summary>")
    add(
        "    public const string USER_AUTOMATION_OPERATION_DISCRIMINATOR = "
        + csharp_string(request_operation_discriminator)
        + ";"
    )
    add("")
    add("    /// <summary>Generated serialized kinds of `UserAutomationOperation`.</summary>")
    add("    public static readonly string[] USER_AUTOMATION_OPERATION_KINDS =")
    add("    [")
    for operation_kind in request_operation_kinds:
        add(f"        {csharp_string(operation_kind)},")
    add("    ];")
    add("")
    for member_constant, schema in request_operation_structs:
        add(f"    /// <summary>Generated JSON members of `{schema.name}`.</summary>")
        add(f"    public static readonly string[] {member_constant} =")
        add("    [")
        for field in schema.fields:
            add(f"        {csharp_string(field.name)},")
        add("    ];")
        add("")
    add("    /// <summary>")
    add("    /// Explicit literal outcomes accepted by the Rust result value deserializer.")
    add("    /// </summary>")
    add("    public static readonly string[] USER_AUTOMATION_RESULT_VALUE_OUTCOMES =")
    add("    [")
    for outcome in result_value_outcomes:
        add(f"        {csharp_string(outcome)},")
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
    if len(set(RESULT_SCHEMA_STRUCTS)) != len(RESULT_SCHEMA_STRUCTS):
        raise Refused("RESULT_SCHEMA_STRUCTS repeats a pinned owner struct")
    result_declarations = collect_result_schema_closure(
        sources, RESULT_SCHEMA_DECLARATIONS
    )
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
    if len(set(RESULT_SCHEMA_ENUMS)) != len(RESULT_SCHEMA_ENUMS) or len(
        {(path, name) for path, name, _constant in RESULT_SCHEMA_ENUMS}
    ) != len(RESULT_SCHEMA_ENUMS):
        raise Refused("RESULT_SCHEMA_ENUMS repeats a pinned owner enum")
    result_enums = [
        (name, value_constant, collect_result_enum(sources[path], name))
        for path, name, value_constant in RESULT_SCHEMA_ENUMS
    ]
    request_operation_enum = collect_result_enum(
        sources[REQUEST_OPERATION_ENUM[0]], REQUEST_OPERATION_ENUM[1]
    )
    request_operation_discriminator = collect_enum_discriminator(
        sources[REQUEST_OPERATION_ENUM[0]], REQUEST_OPERATION_ENUM[1]
    )
    request_operation_kinds = list(request_operation_enum.variants)
    if len(set(request_operation_kinds)) != len(request_operation_kinds):
        raise Refused("UserAutomationOperation repeats a serialized operation kind")
    if len(set(REQUEST_OPERATION_VARIANTS)) != len(REQUEST_OPERATION_VARIANTS) or len(
        {member_constant for _variant, member_constant in REQUEST_OPERATION_VARIANTS}
    ) != len(REQUEST_OPERATION_VARIANTS):
        raise Refused("REQUEST_OPERATION_VARIANTS repeats a pinned owner variant")
    request_operation_structs = [
        (
            member_constant,
            collect_enum_variant_members(
                sources[REQUEST_OPERATION_ENUM[0]],
                REQUEST_OPERATION_ENUM[1],
                variant,
            ),
        )
        for variant, member_constant in REQUEST_OPERATION_VARIANTS
    ]
    result_value_outcomes = collect_result_outcomes(
        sources[USER_AUTOMATION_TRANSITION_RS],
        "UserAutomationOperatorResultValue",
    )
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
        request_operation_discriminator,
        request_operation_kinds,
        request_operation_structs,
        result_value_outcomes,
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
