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
USER_AUTOMATION_EXECUTION_RS = "crates/kernel/eliot-kernel-service/src/user_automation_execution.rs"
USER_AUTOMATION_ORCHESTRATION_RS = "crates/kernel/eliot-kernel-service/src/user_automation_orchestration.rs"
USER_AUTOMATION_SERVICE_RS = "crates/kernel/eliot-kernel-service/src/user_automation.rs"
USER_AUTOMATION_HANDOFF_RS = "crates/kernel/eliot-kernel-service/src/user_automation_runtime_handoff.rs"
STORE_API_RS = "crates/storage/eliot-store-api/src/lib.rs"

ARTEFACT = "apps/Eliot.Operator/Protocol/Generated/OperatorScheduleContract.g.cs"

#: Rust files the artefact is derived from, recorded in the artefact header so a
#: reader can see exactly which owner source the mirror is bound to. The
#: recorded spelling is always POSIX-separated so the committed artefact, and
#: therefore `--check`, is byte-identical on every host.
SOURCE_FILES = (
    "crates/kernel/eliot-kernel-core/src/user_automation.rs",
    "crates/kernel/eliot-kernel-core/src/user_automation_zones.rs",
    "crates/kernel/eliot-kernel-service/src/user_automation_execution.rs",
    "crates/kernel/eliot-kernel-service/src/user_automation_orchestration.rs",
    "crates/kernel/eliot-kernel-service/src/user_automation.rs",
    "crates/kernel/eliot-kernel-service/src/user_automation_runtime_handoff.rs",
    "crates/storage/eliot-store-api/src/lib.rs",
)

#: Constants the mirror needs as C# constants, in the order they are emitted.
#: Each entry is (name, rust file). A name that no longer exists, changes type,
#: or stops evaluating to a literal is a hard refusal, never a default.
PINNED_CONSTANTS = (
    # The exact versioned occurrence encoding. It is field 0 of every owner
    # occurrence key, so the Operator reads the supported contract version off
    # the owner's own bytes instead of carrying a second copy of it on the wire.
    ("NORMALIZED_OCCURRENCE_ENCODING", USER_AUTOMATION_RS, "string"),
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
    ("USER_AUTOMATION_OPERATOR_RESULT_SCHEMA_ID", USER_AUTOMATION_HANDOFF_RS, "string"),
    ("USER_AUTOMATION_OPERATOR_RESULT_SCHEMA_VERSION", USER_AUTOMATION_HANDOFF_RS, "int"),
    ("USER_AUTOMATION_TRANSITION_WIRE_ID", USER_AUTOMATION_HANDOFF_RS, "string"),
    ("USER_AUTOMATION_TRANSITION_WIRE_VERSION", USER_AUTOMATION_HANDOFF_RS, "int"),
    # The only zone database release this build admits, and the token every
    # owner occurrence record must carry verbatim.
    ("PINNED_ZONE_DATABASE_RELEASE", USER_AUTOMATION_ZONES_RS, "string"),
)

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
    "is_legacy_occurrence_key",
    "is_canonical_zone_database_revision",
)

#: Closed public JSON shapes used by the Operator result decoder. The field
#: names, Rust types and omitted-Option semantics are read from their public
#: Rust declarations and emitted into the generated mirror. OperationIdentity
#: is the Store API type shared by the known transition and typed refusal.
RESULT_SCHEMA_STRUCTS = (
    ("UserAutomationOperatorResultEnvelopeFields", USER_AUTOMATION_HANDOFF_RS, "UserAutomationOperatorResultEnvelope"),
    ("UserAutomationOperatorResultValueFields", USER_AUTOMATION_HANDOFF_RS, "UserAutomationOperatorResultValue"),
    ("UserAutomationOperatorTransitionRequiredFields", USER_AUTOMATION_HANDOFF_RS, "UserAutomationOperatorTransition"),
    ("OperationIdentityFields", STORE_API_RS, "OperationIdentity"),
    ("UserAutomationHorizonPhaseFields", USER_AUTOMATION_HANDOFF_RS, "UserAutomationHorizonPhase"),
    ("UserAutomationOrchestrationRecordFields", USER_AUTOMATION_ORCHESTRATION_RS, "UserAutomationOrchestrationRecord"),
    ("UserAutomationRuntimeObligationFields", USER_AUTOMATION_ORCHESTRATION_RS, "UserAutomationRuntimeObligation"),
    ("UserAutomationWakeReadbackFields", USER_AUTOMATION_EXECUTION_RS, "UserAutomationWakeReadback"),
)
RESULT_SCHEMA_OPTIONAL_STRUCT = (
    "UserAutomationOperatorTransitionOptionalFields",
    USER_AUTOMATION_HANDOFF_RS,
    "UserAutomationOperatorTransition",
)
RESULT_SCHEMA_ENUMS = (
    ("UserAutomationOperatorResultStatuses", USER_AUTOMATION_HANDOFF_RS, "UserAutomationOperatorResultStatus"),
    ("UserAutomationRecoveryPhaseKinds", USER_AUTOMATION_HANDOFF_RS, "UserAutomationRecoveryPhase"),
    ("UserAutomationConfigurationPhaseKinds", USER_AUTOMATION_HANDOFF_RS, "UserAutomationConfigurationPhase"),
    ("UserAutomationWakePhaseKinds", USER_AUTOMATION_HANDOFF_RS, "UserAutomationWakePhase"),
    ("UserAutomationExecutionPhaseKinds", USER_AUTOMATION_HANDOFF_RS, "UserAutomationExecutionPhase"),
    ("UserAutomationHorizonOutcomeKinds", USER_AUTOMATION_HANDOFF_RS, "UserAutomationHorizonOutcome"),
    ("UserAutomationHorizonTriggers", USER_AUTOMATION_EXECUTION_RS, "UserAutomationHorizonTrigger"),
    ("UserAutomationReadResultKinds", USER_AUTOMATION_SERVICE_RS, "UserAutomationReadResult"),
    ("UserAutomationMutationResultKinds", USER_AUTOMATION_SERVICE_RS, "UserAutomationMutationResult"),
    ("UserAutomationRuntimeObligationKinds", USER_AUTOMATION_ORCHESTRATION_RS, "UserAutomationRuntimeObligationKind"),
    ("UserAutomationRuntimeObligationAnswerKinds", USER_AUTOMATION_ORCHESTRATION_RS, "UserAutomationRuntimeObligationAnswer"),
    ("UserAutomationRuntimeObligationDispositionKinds", USER_AUTOMATION_ORCHESTRATION_RS, "UserAutomationRuntimeObligationDisposition"),
)
RESULT_SCHEMA_RECOVERY_FIELDS = (USER_AUTOMATION_HANDOFF_RS, "UserAutomationRecoveryPhase")

# Updating these pins requires a deliberate C# decoder review. A public Rust
# field, optionality, enum value or version change therefore refuses both
# generation and the Operator build gate until the decoder and its pin move
# together.
EXPECTED_RESULT_SCHEMA_ID = "eliot.kernel.user-automation.operator-result"
EXPECTED_RESULT_SCHEMA_VERSION = 1
EXPECTED_TRANSITION_WIRE_ID = "eliot.kernel.user-automation.transition"
EXPECTED_TRANSITION_WIRE_VERSION = 1
SUPPORTED_RESULT_SCHEMA_LAYOUT = {
    "UserAutomationOperatorResultEnvelopeFields": (
        "schema_id", "schema_version", "status", "value", "recovery",
    ),
    "UserAutomationOperatorResultValueFields": ("transition", "occurrences"),
    "UserAutomationOperatorTransitionRequiredFields": (
        "wire_id", "wire_version", "identity", "state_fence", "configuration", "wake", "execution",
    ),
    "UserAutomationOperatorTransitionOptionalFields": ("horizon", "orchestration"),
    "OperationIdentityFields": ("operation_id", "idempotency_key", "canonical_request_hash"),
    "UserAutomationRecoveryPhaseFields": ("kind", "reason"),
    "UserAutomationOperatorResultStatuses": ("known", "unknown"),
    "UserAutomationRecoveryPhaseKinds": ("unavailable", "unknown_outcome"),
    "UserAutomationHorizonPhaseFields": (
        "trigger", "automation_id", "automation_revision", "revision_digest",
        "requested_occurrence_ids", "remaining_occurrence_ids", "retry_handle", "outcome",
    ),
    "UserAutomationOrchestrationRecordFields": (
        "parent", "state_fence", "automation_id", "automation_revision",
        "revision_digest", "committed_receipt_digest", "obligations",
    ),
    "UserAutomationRuntimeObligationFields": (
        "kind", "owner_operation_id", "request_digest", "subject_ids", "disposition",
    ),
    "UserAutomationWakeReadbackFields": (
        "intent", "operation_id", "idempotency_key", "record_checksum",
    ),
    "UserAutomationConfigurationPhaseKinds": ("read", "committed", "replayed"),
    "UserAutomationWakePhaseKinds": ("not_applicable", "published", "cancelled", "unknown_outcome", "unavailable"),
    "UserAutomationExecutionPhaseKinds": ("not_applicable", "admitted", "deferred", "blocked_config", "unknown_outcome", "unavailable"),
    "UserAutomationHorizonOutcomeKinds": ("published", "partial", "unavailable", "unknown_outcome"),
    "UserAutomationHorizonTriggers": ("ACCEPTED_REVISION", "SUPERSEDING_EDIT", "RESUMED_REVISION", "DISPOSITION_ADVANCE"),
    "UserAutomationReadResultKinds": ("list", "status", "history", "inspect_last_failure"),
    "UserAutomationMutationResultKinds": ("revision", "run_now"),
    "UserAutomationRuntimeObligationKinds": ("wake_horizon_publication", "wake_cancellation"),
    "UserAutomationRuntimeObligationAnswerKinds": ("wake_horizon_publication", "wake_cancellation"),
    "UserAutomationRuntimeObligationDispositionKinds": ("retained", "reconciling", "answered", "unavailable"),
}

# Exact nested JSON wire shapes are pinned separately from the short sets used
# by the decoder. Descriptors include serde tags/casing, named variant payload
# fields, Rust payload types, field renames, and omitted-Option behavior.
SUPPORTED_RESULT_SCHEMA_WIRE_SHAPES = {
    "UserAutomationOperatorResultEnvelopeWireShape": (
        "serde=deny_unknown_fields",
        "field=schema_id:String:omitted=0",
        "field=schema_version:u16:omitted=0",
        "field=status:UserAutomationOperatorResultStatus:omitted=0",
        "field=value:UserAutomationOperatorResultValue:omitted=0",
        "field=recovery:Option<UserAutomationRecoveryPhase>:omitted=0",
    ),
    "UserAutomationOperatorResultValueWireShape": (
        "serde=deny_unknown_fields",
        "field=transition:UserAutomationOperatorTransition:omitted=0",
        "field=occurrences:Vec<serde_json::Value>:omitted=0",
    ),
    "UserAutomationOperatorTransitionWireShape": (
        "serde=deny_unknown_fields",
        "field=wire_id:String:omitted=0",
        "field=wire_version:u16:omitted=0",
        "field=identity:OperationIdentity:omitted=0",
        "field=state_fence:StateFence:omitted=0",
        "field=configuration:UserAutomationConfigurationPhase:omitted=0",
        "field=wake:UserAutomationWakePhase:omitted=0",
        "field=execution:UserAutomationExecutionPhase:omitted=0",
        "field=horizon:Option<Box<UserAutomationHorizonPhase>>:omitted=1:defaulted=1",
        "field=orchestration:Option<Box<UserAutomationOrchestrationRecord>>:omitted=1:defaulted=1",
    ),
    "OperationIdentityWireShape": (
        "serde=deny_unknown_fields",
        "field=operation_id:OperationId:omitted=0",
        "field=idempotency_key:String:omitted=0",
        "field=canonical_request_hash:String:omitted=0",
    ),
    "UserAutomationHorizonPhaseWireShape": (
        "serde=deny_unknown_fields;rename_all=snake_case;tag=kind",
        "field=trigger:UserAutomationHorizonTrigger:omitted=0",
        "field=automation_id:String:omitted=0",
        "field=automation_revision:String:omitted=0",
        "field=revision_digest:String:omitted=0",
        "field=requested_occurrence_ids:Vec<String>:omitted=0",
        "field=remaining_occurrence_ids:Vec<String>:omitted=0",
        "field=retry_handle:String:omitted=0",
        "field=outcome:UserAutomationHorizonOutcome:omitted=0",
    ),
    "UserAutomationOrchestrationRecordWireShape": (
        "serde=deny_unknown_fields",
        "field=parent:OperationIdentity:omitted=0",
        "field=state_fence:StateFence:omitted=0",
        "field=automation_id:String:omitted=0",
        "field=automation_revision:String:omitted=0",
        "field=revision_digest:String:omitted=0",
        "field=committed_receipt_digest:String:omitted=0",
        "field=obligations:Vec<UserAutomationRuntimeObligation>:omitted=0",
    ),
    "UserAutomationRuntimeObligationWireShape": (
        "serde=deny_unknown_fields",
        "field=kind:UserAutomationRuntimeObligationKind:omitted=0",
        "field=owner_operation_id:String:omitted=0",
        "field=request_digest:String:omitted=0",
        "field=subject_ids:Vec<String>:omitted=0",
        "field=disposition:UserAutomationRuntimeObligationDisposition:omitted=0",
    ),
    "UserAutomationWakeReadbackWireShape": (
        "serde=deny_unknown_fields",
        "field=intent:WakeIntent:omitted=0",
        "field=operation_id:String:omitted=0",
        "field=idempotency_key:String:omitted=0",
        "field=record_checksum:String:omitted=0",
    ),
    "UserAutomationOperatorResultStatusWireShape": (
        "serde=allow_unknown_fields;rename_all=snake_case",
        "variant=known",
        "variant=unknown",
    ),
    "UserAutomationRecoveryPhaseWireShape": (
        "serde=deny_unknown_fields;rename_all=snake_case;tag=kind",
        "variant=unavailable|reason:String:omitted=0",
        "variant=unknown_outcome|reason:String:omitted=0",
    ),
    "UserAutomationConfigurationPhaseWireShape": (
        "serde=deny_unknown_fields;rename_all=snake_case;tag=kind",
        "variant=read|result:Box<UserAutomationReadResult>:omitted=0",
        "variant=committed|receipt:Box<WriteReceipt>:omitted=0,result:Box<UserAutomationMutationResult>:omitted=0",
        "variant=replayed|receipt:Box<WriteReceipt>:omitted=0,result:Box<UserAutomationMutationResult>:omitted=0",
    ),
    "UserAutomationWakePhaseWireShape": (
        "serde=deny_unknown_fields;rename_all=snake_case;tag=kind",
        "variant=not_applicable|reason:String:omitted=0",
        "variant=published|readback:UserAutomationWakeReadback:omitted=0",
        "variant=cancelled|cancelled_wake_ids:Vec<String>:omitted=0",
        "variant=unknown_outcome|reason:String:omitted=0",
        "variant=unavailable|reason:String:omitted=0",
    ),
    "UserAutomationExecutionPhaseWireShape": (
        "serde=deny_unknown_fields;rename_all=snake_case;tag=kind",
        "variant=not_applicable|reason:String:omitted=0",
        "variant=admitted|execution:Box<AutomationExecutionReference>:omitted=0",
        "variant=deferred|reason:UserAutomationDeferReason:omitted=0",
        "variant=blocked_config|failure_fingerprint:String:omitted=0",
        "variant=unknown_outcome|reason:String:omitted=0",
        "variant=unavailable|reason:String:omitted=0",
    ),
    "UserAutomationHorizonOutcomeWireShape": (
        "serde=deny_unknown_fields;rename_all=snake_case;tag=kind",
        "variant=published|publication_operation_id:Box<eliot_store_api::OperationId>:omitted=0",
        "variant=partial|publication_operation_id:Box<eliot_store_api::OperationId>:omitted=0,reason:String:omitted=0",
        "variant=unavailable|reason:String:omitted=0",
        "variant=unknown_outcome|reason:String:omitted=0",
    ),
    "UserAutomationHorizonTriggerWireShape": (
        "serde=allow_unknown_fields;rename_all=SCREAMING_SNAKE_CASE",
        "variant=ACCEPTED_REVISION",
        "variant=SUPERSEDING_EDIT",
        "variant=RESUMED_REVISION",
        "variant=DISPOSITION_ADVANCE",
    ),
    "UserAutomationReadResultWireShape": (
        "serde=deny_unknown_fields;rename_all=snake_case;tag=kind",
        "variant=list|revisions:Vec<UserAutomationRevision>:omitted=0",
        "variant=status|revision:UserAutomationRevision:omitted=0,execution:UserAutomationExecutionProjection:omitted=0",
        "variant=history|automation_id:String:omitted=0,execution:UserAutomationExecutionProjection:omitted=0",
        "variant=inspect_last_failure|automation_id:String:omitted=0,revision:UserAutomationRevision:omitted=0,failure:Option<UserAutomationFailureProjection>:omitted=0",
    ),
    "UserAutomationMutationResultWireShape": (
        "serde=deny_unknown_fields;rename_all=snake_case;tag=kind",
        "variant=revision|revision:UserAutomationRevision:omitted=0,cancelled_wake_ids:Vec<String>:omitted=0",
        "variant=run_now|invocation:UserAutomationInvocation:omitted=0,wake_intent:WakeIntent:omitted=0",
    ),
    "UserAutomationRuntimeObligationKindWireShape": (
        "serde=allow_unknown_fields;rename_all=snake_case",
        "variant=wake_horizon_publication",
        "variant=wake_cancellation",
    ),
    "UserAutomationRuntimeObligationAnswerWireShape": (
        "serde=deny_unknown_fields;rename_all=snake_case;tag=kind",
        "variant=wake_horizon_publication|acknowledgement:Box<UserAutomationWakePublication>:omitted=0",
        "variant=wake_cancellation|cancelled_wake_ids:Vec<String>:omitted=0",
    ),
    "UserAutomationRuntimeObligationDispositionWireShape": (
        "serde=deny_unknown_fields;rename_all=snake_case;tag=kind",
        "variant=retained",
        "variant=reconciling|reason:String:omitted=0",
        "variant=answered|answer:Box<UserAutomationRuntimeObligationAnswer>:omitted=0",
        "variant=unavailable|reason:String:omitted=0",
    ),
}


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
class RustWireField:
    name: str
    rust_type: str
    omitted_when_none: bool
    defaulted: bool = False


@dataclass(frozen=True)
class RustWireStruct:
    name: str
    fields: tuple[RustWireField, ...]
    wire_shape: tuple[str, ...]


@dataclass(frozen=True)
class RustWireEnum:
    name: str
    variants: tuple[str, ...]
    tag: str | None
    shared_fields: tuple[str, ...]
    wire_shape: tuple[str, ...]


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


def collect_declaration_block(
    lines: list[str],
    declaration_kind: str,
    name: str,
) -> tuple[int, list[str]]:
    """Read one public struct/enum body with simple brace matching."""
    header = re.compile(rf"^\s*pub\s+{declaration_kind}\s+{re.escape(name)}\b")
    for index, line in enumerate(lines):
        if header.match(line) is None:
            continue
        depth = 0
        opened = False
        body: list[str] = []
        for offset, candidate in enumerate(lines[index:]):
            depth += candidate.count("{") - candidate.count("}")
            if "{" in candidate:
                opened = True
            if opened and offset > 0:
                body.append(candidate)
            if opened and depth == 0:
                return index, body[:-1]
        raise Refused(f"{declaration_kind} {name!r} has no closed body")
    raise Refused(f"public {declaration_kind} {name!r} is absent from the owner source")


def preceding_attributes(lines: list[str], index: int) -> str:
    attributes: list[str] = []
    cursor = index - 1
    while cursor >= 0:
        stripped = lines[cursor].strip()
        if stripped.startswith("#["):
            attributes.append(stripped)
        elif stripped.startswith("///") or not stripped:
            pass
        else:
            break
        cursor -= 1
    return "\n".join(reversed(attributes))


def serde_options(attributes: str, allowed: set[str], declaration: str) -> dict[str, str | None]:
    """Read the small explicit serde attribute vocabulary used by pinned shapes."""
    options: dict[str, str | None] = {}
    for line in attributes.splitlines():
        match = re.fullmatch(r"\s*#\[serde\((.*)\)\]\s*", line)
        if match is None:
            continue
        for item in match.group(1).split(","):
            item = item.strip()
            if not item:
                continue
            key, separator, raw_value = item.partition("=")
            key = key.strip()
            if key not in allowed:
                raise Refused(f"{declaration} uses unsupported serde option {key!r}")
            value = raw_value.strip().strip('"') if separator else None
            if key in options:
                raise Refused(f"{declaration} repeats serde option {key!r}")
            options[key] = value
    return options


def serde_container_shape(attributes: str, options: dict[str, str | None]) -> str:
    """Canonical container-level wire metadata retained in the generated pin."""
    ordered = ["deny_unknown_fields" if "deny_unknown_fields" in attributes else "allow_unknown_fields"]
    for key in ("rename_all", "rename_all_fields", "tag", "content"):
        if key in options:
            ordered.append(f"{key}={options[key] or ''}")
    if "untagged" in options:
        ordered.append("untagged")
    return "serde=" + ";".join(ordered)


def collect_wire_struct(lines: list[str], name: str) -> RustWireStruct:
    """Read JSON field names/types and omitted-Option semantics for one type."""
    index, body = collect_declaration_block(lines, "struct", name)
    attributes = preceding_attributes(lines, index)
    options = serde_options(
        attributes,
        {"deny_unknown_fields", "rename_all", "tag", "content"},
        f"wire struct {name!r}",
    )
    if "deny_unknown_fields" not in attributes:
        raise Refused(f"public wire struct {name!r} must deny unknown fields")
    rename_all = options.get("rename_all")
    if rename_all not in (None, "snake_case"):
        raise Refused(f"wire struct {name!r} has unsupported rename_all {rename_all!r}")

    fields: list[RustWireField] = []
    pending_attributes: list[str] = []
    field_declaration = re.compile(r"^\s*pub\s+([a-z][a-z0-9_]*)\s*:\s*(.+?),\s*$")
    for line in body:
        stripped = line.strip()
        if not stripped or stripped.startswith("///"):
            continue
        if stripped.startswith("#["):
            pending_attributes.append(stripped)
            continue
        match = field_declaration.match(line)
        if match is None:
            if stripped.startswith("pub "):
                raise Refused(f"wire field in {name!r} is not one bounded declaration line: {stripped!r}")
            continue

        rust_name, rust_type = match.groups()
        field_attributes = " ".join(pending_attributes)
        field_options = serde_options(
            field_attributes,
            {"rename", "skip_serializing_if", "default"},
            f"wire field {name}.{rust_name}",
        )
        wire_name = field_options.get("rename") or rust_name
        skip_if = field_options.get("skip_serializing_if")
        if skip_if not in (None, "Option::is_none"):
            raise Refused(f"wire field {name}.{rust_name} has unsupported skip_serializing_if {skip_if!r}")
        omitted_when_none = skip_if == "Option::is_none"
        if omitted_when_none and not rust_type.startswith("Option<"):
            raise Refused(f"wire field {name}.{rust_name} skips serialization but is not an Option")
        if any(field.name == wire_name for field in fields):
            raise Refused(f"wire struct {name!r} repeats JSON field {wire_name!r}")
        fields.append(
            RustWireField(
                name=wire_name,
                rust_type=collapse(rust_type),
                omitted_when_none=omitted_when_none,
                defaulted="default" in field_options,
            )
        )
        pending_attributes.clear()

    if not fields:
        raise Refused(f"wire struct {name!r} has no public JSON fields")
    wire_shape = [serde_container_shape(attributes, options)]
    wire_shape.extend(
        f"field={field.name}:{field.rust_type}:omitted={int(field.omitted_when_none)}"
        + (":defaulted=1" if field.defaulted else "")
        for field in fields
    )
    return RustWireStruct(name=name, fields=tuple(fields), wire_shape=tuple(wire_shape))


def to_snake_case(value: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", value).lower()


def collect_wire_enum(lines: list[str], name: str) -> RustWireEnum:
    """Read one bounded serde enum, including every named variant payload."""
    index, body = collect_declaration_block(lines, "enum", name)
    attributes = preceding_attributes(lines, index)
    options = serde_options(
        attributes,
        {"rename_all", "rename_all_fields", "tag", "content", "deny_unknown_fields", "untagged"},
        f"wire enum {name!r}",
    )
    rename_all = options.get("rename_all")
    if rename_all not in ("snake_case", "SCREAMING_SNAKE_CASE"):
        raise Refused(f"public wire enum {name!r} has unsupported rename_all {rename_all!r}")
    tag = options.get("tag")
    if tag is not None and "deny_unknown_fields" not in attributes:
        raise Refused(f"tagged wire enum {name!r} must deny unknown fields")

    variants: list[str] = []
    variant_fields: list[tuple[RustWireField, ...]] = []
    wire_shape = [serde_container_shape(attributes, options)]
    index = 0
    variant_declaration = re.compile(r"^\s{4}([A-Z][A-Za-z0-9_]*)\s*(.*)$")
    field_declaration = re.compile(r"^\s{8}([a-z][a-z0-9_]*)\s*:\s*(.+?)(?:,\s*)?$")
    while index < len(body):
        stripped = body[index].strip()
        if not stripped or stripped.startswith("///"):
            index += 1
            continue
        if stripped.startswith("#["):
            index += 1
            continue
        match = variant_declaration.match(body[index])
        if match is None:
            raise Refused(
                f"wire enum {name!r} has an unsupported declaration line: {stripped!r}"
            )
        variant, tail = match.groups()
        variant_options = serde_options(
            preceding_attributes(body, index),
            {"rename"},
            f"wire enum variant {name}.{variant}",
        )
        if variant_options.get("rename") is not None:
            wire_variant = variant_options["rename"]
        else:
            wire_variant = to_snake_case(variant)
            if rename_all == "SCREAMING_SNAKE_CASE":
                wire_variant = wire_variant.upper()
        if wire_variant in variants:
            raise Refused(f"wire enum {name!r} repeats variant {wire_variant!r}")
        variants.append(wire_variant)
        fields: list[RustWireField] = []
        tail = tail.strip().rstrip(",").strip()
        if "(" in tail:
            raise Refused(f"wire enum variant {name}.{variant} uses an unsupported tuple payload")
        if "{" in tail:
            if "}" in tail:
                raise Refused(f"wire enum variant {name}.{variant} uses an unsupported inline payload")
            index += 1
            pending_field_attributes: list[str] = []
            while index < len(body) and "}" not in body[index]:
                field_line = body[index]
                field_stripped = field_line.strip()
                if not field_stripped or field_stripped.startswith("///"):
                    index += 1
                    continue
                if field_stripped.startswith("#["):
                    pending_field_attributes.append(field_stripped)
                    index += 1
                    continue
                field = field_declaration.match(body[index])
                if field is None:
                    raise Refused(
                        f"wire enum field in {name}.{variant} is not one bounded declaration line: "
                        f"{field_stripped!r}"
                    )
                rust_name, rust_type = field.groups()
                field_options = serde_options(
                    " ".join(pending_field_attributes),
                    {"rename", "skip_serializing_if", "default"},
                    f"wire enum field {name}.{variant}.{rust_name}",
                )
                skip_if = field_options.get("skip_serializing_if")
                if skip_if not in (None, "Option::is_none"):
                    raise Refused(
                        f"wire enum field {name}.{variant}.{rust_name} has unsupported "
                        f"skip_serializing_if {skip_if!r}"
                    )
                wire_name = field_options.get("rename") or rust_name
                omitted_when_none = skip_if == "Option::is_none"
                if omitted_when_none and not rust_type.strip().startswith("Option<"):
                    raise Refused(
                        f"wire enum field {name}.{variant}.{rust_name} skips serialization but is not an Option"
                    )
                fields.append(
                    RustWireField(
                        wire_name,
                        collapse(rust_type.rstrip(",").strip()),
                        omitted_when_none,
                        "default" in field_options,
                    )
                )
                pending_field_attributes.clear()
                index += 1
            if index >= len(body):
                raise Refused(f"wire enum variant {name}.{variant} has no closing brace")
        elif tail not in ("",):
            raise Refused(f"wire enum variant {name}.{variant} has unsupported payload {tail!r}")
        if len({field.name for field in fields}) != len(fields):
            raise Refused(f"wire enum variant {name}.{variant} repeats a JSON field")
        variant_fields.append(tuple(fields))
        field_shape = ",".join(
            f"{field.name}:{field.rust_type}:omitted={int(field.omitted_when_none)}"
            + (":defaulted=1" if field.defaulted else "")
            for field in fields
        )
        wire_shape.append(f"variant={wire_variant}" + (f"|{field_shape}" if field_shape else ""))
        index += 1

    if not variants:
        raise Refused(f"wire enum {name!r} has no public variants")
    field_names = [tuple(field.name for field in fields) for fields in variant_fields]
    common_fields = field_names[0] if tag is not None and all(item == field_names[0] for item in field_names) else ()
    return RustWireEnum(
        name=name,
        variants=tuple(variants),
        tag=tag,
        shared_fields=tuple(common_fields),
        wire_shape=tuple(wire_shape),
    )


def collect_result_schema(
    sources: dict[str, list[str]],
) -> tuple[dict[str, tuple[str, ...]], str]:
    """Return generated member sets and a digest of the pinned public schema."""
    members: dict[str, tuple[str, ...]] = {}
    schema_lines: list[str] = []
    for output_name, path, type_name in RESULT_SCHEMA_STRUCTS:
        schema = collect_wire_struct(sources[path], type_name)
        if output_name.endswith("RequiredFields"):
            fields = tuple(field.name for field in schema.fields if not field.omitted_when_none)
        else:
            fields = tuple(field.name for field in schema.fields)
        members[output_name] = fields
        shape_name = f"{schema.name}WireShape"
        members[shape_name] = schema.wire_shape
        schema_lines.extend(
            f"struct\t{schema.name}\t{field.name}\t{field.rust_type}\tomitted={int(field.omitted_when_none)}"
            for field in schema.fields
        )
        schema_lines.extend(f"shape\t{shape_name}\t{item}" for item in schema.wire_shape)

    optional_name, optional_path, optional_type = RESULT_SCHEMA_OPTIONAL_STRUCT
    optional_schema = collect_wire_struct(sources[optional_path], optional_type)
    members[optional_name] = tuple(field.name for field in optional_schema.fields if field.omitted_when_none)
    optional_shape_name = f"{optional_schema.name}WireShape"
    members[optional_shape_name] = optional_schema.wire_shape
    schema_lines.extend(f"shape\t{optional_shape_name}\t{item}" for item in optional_schema.wire_shape)
    if not members[optional_name]:
        raise Refused(f"wire struct {optional_type!r} has no omitted optional fields")

    for output_name, path, type_name in RESULT_SCHEMA_ENUMS:
        schema = collect_wire_enum(sources[path], type_name)
        members[output_name] = schema.variants
        shape_name = f"{schema.name}WireShape"
        members[shape_name] = schema.wire_shape
        schema_lines.append(
            f"enum\t{schema.name}\ttag={schema.tag or ''}\tshared={','.join(schema.shared_fields)}"
        )
        schema_lines.extend(f"shape\t{shape_name}\t{item}" for item in schema.wire_shape)

    recovery_path, recovery_type = RESULT_SCHEMA_RECOVERY_FIELDS
    recovery = collect_wire_enum(sources[recovery_path], recovery_type)
    if recovery.tag is None:
        raise Refused(f"wire enum {recovery_type!r} has no serde tag")
    members["UserAutomationRecoveryPhaseFields"] = (recovery.tag, *recovery.shared_fields)
    members[f"{recovery.name}WireShape"] = recovery.wire_shape
    schema_lines.append(
        f"enum\t{recovery.name}\ttag={recovery.tag}\tshared={','.join(recovery.shared_fields)}"
    )
    schema_lines.extend(
        f"shape\t{recovery.name}WireShape\t{item}" for item in recovery.wire_shape
    )

    for name, expected in SUPPORTED_RESULT_SCHEMA_LAYOUT.items():
        if members.get(name) != expected:
            found = members.get(name)
            raise Refused(
                f"public result schema {name} changed from {expected!r} to {found!r}; "
                "update and review the C# decoder before changing its schema pin"
            )
    for name, expected in SUPPORTED_RESULT_SCHEMA_WIRE_SHAPES.items():
        if members.get(name) != expected:
            found = members.get(name)
            raise Refused(
                f"public nested wire shape {name} changed from {expected!r} to {found!r}; "
                "review the affected C# decoder before changing its schema pin"
            )
    digest = hashlib.sha256("\n".join(schema_lines).encode("utf-8")).hexdigest()
    return members, digest


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
    result_schema_members: dict[str, tuple[str, ...]],
    digests: dict[str, str],
) -> str:
    lines: list[str] = []
    add = lines.append

    add("// <auto-generated>")
    add("//     Generated by scripts/gen_operator_schedule_contract.py. Do not edit.")
    add("// </auto-generated>")
    add("//")
    add("// Bounded C# mirror of the Kernel UserAutomation schedule/occurrence/result contracts")
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
    add(f"// result_schema_source_sha256: {digests['result_schema']}")
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
    add("    /// Closed field/variant sets and nested wire descriptors read from")
    add("    /// public Rust phase, projection, and Store identity types.")
    add("    /// </summary>")
    for name, members in result_schema_members.items():
        add(f"    public static readonly IReadOnlyList<string> {name} =")
        add("    [")
        for member in members:
            add(f"        {csharp_string(member)},")
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

    expected_constants = {
        "USER_AUTOMATION_OPERATOR_RESULT_SCHEMA_ID": EXPECTED_RESULT_SCHEMA_ID,
        "USER_AUTOMATION_OPERATOR_RESULT_SCHEMA_VERSION": EXPECTED_RESULT_SCHEMA_VERSION,
        "USER_AUTOMATION_TRANSITION_WIRE_ID": EXPECTED_TRANSITION_WIRE_ID,
        "USER_AUTOMATION_TRANSITION_WIRE_VERSION": EXPECTED_TRANSITION_WIRE_VERSION,
    }
    for name, expected in expected_constants.items():
        if resolved.get(name) != expected:
            raise Refused(
                f"public result schema constant {name} changed from {expected!r} "
                f"to {resolved.get(name)!r}; update and review the C# decoder before changing its schema pin"
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

    result_schema_members, result_schema_digest = collect_result_schema(sources)

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
        result_schema_members,
        digests,
    ), {
        "constants": len(rendered),
        "dispositions": len(dispositions),
        "refusals": len(refusals),
        "grammar_functions": len(functions),
        "result_schema_members": sum(len(value) for value in result_schema_members.values()),
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
