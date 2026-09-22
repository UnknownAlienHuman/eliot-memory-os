using System.Text.Json;
using System.Text.Json.Serialization;

namespace Eliot.Operator.Protocol;

/// Typed operator-mutation envelope mirroring the serving owner's closed
/// input (`OperatorCommandToolInput` in `crates/eliot-app/src/mcp_stdio.rs`):
/// `project_id`, `task_id`, `expected_revision`, `idempotency_key`, `command`.
/// The UI creates the operation identity once per user action and retains the
/// exact bytes until a terminal receipt; reconciliation resends the same
/// identity, never a second one.
public sealed record OperatorIntentEnvelope(
    [property: JsonPropertyName("project_id")] string ProjectId,
    [property: JsonPropertyName("task_id")] string TaskId,
    [property: JsonPropertyName("expected_revision")] ulong ExpectedRevision,
    [property: JsonPropertyName("idempotency_key")] string OperationId,
    [property: JsonPropertyName("command")] JsonElement Command)
{
    /// Mints one operation identity for one user action. Retries of the same
    /// action reuse the returned envelope; a new user action mints a new one.
    public static OperatorIntentEnvelope Create(
        string projectId,
        string taskId,
        ulong expectedRevision,
        JsonElement command)
    {
        var envelope = new OperatorIntentEnvelope(
            projectId,
            taskId,
            expectedRevision,
            Guid.NewGuid().ToString("N"),
            command);
        envelope.Validate();
        return envelope;
    }

    public void Validate()
    {
        OperatorIntentContract.RequireText(ProjectId, "project_id");
        OperatorIntentContract.RequireText(TaskId, "task_id");
        OperatorIntentContract.RequireOperationId(OperationId);
        if (Command.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("Operator intent command must be one JSON object.");
        }
    }
}

/// Field-level validation for the typed intent envelope. The owner still
/// revalidates capability, target identity, expected revision/fence, and the
/// command digest before forwarding; this guard only keeps malformed
/// envelopes from ever leaving the UI.
public static class OperatorIntentContract
{
    public static void RequireText(string? value, string field)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 1024 || value.Any(char.IsControl))
        {
            throw new InvalidOperationException($"Operator intent field '{field}' is not a bounded text value.");
        }
    }

    public static void RequireOperationId(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length != 32
            || !value.All(character => Uri.IsHexDigit(character)))
        {
            throw new InvalidOperationException("Operator intent requires one 32-character hex operation identity.");
        }
    }
}

/// Durable phases of one UI-issued operation. `UnknownReconciling` means the
/// request may have executed: the same identity must be reconciled, never
/// resubmitted as a new mutation.
public enum OperatorOperationPhase
{
    Created,
    Submitted,
    PossiblyExecuted,
    Receipted,
    Rejected,
    Cancelled,
    StaleFence,
    UnknownReconciling
}

/// One retained operation: identity, canonical envelope bytes, expected
/// revision/fence input, and phase until a terminal receipt.
public sealed record OperatorPendingOperation(
    string OperationId,
    string EnvelopeJson,
    ulong ExpectedRevision,
    string CommandName,
    OperatorOperationPhase Phase,
    DateTimeOffset CreatedAtUtc)
{
    public OperatorPendingOperation WithPhase(OperatorOperationPhase phase) =>
        this with { Phase = phase };
}

/// Versioned compatibility record for the `eliot_operator_*` wire path.
///
/// The WinUI client reaches the Governor pipe through the four legacy tools
/// served by `crates/eliot-app` (`mcp_stdio` dispatch/catalog). That path
/// conflicts with current ControlBoard/runtime-status ownership unless it is
/// retained behind exactly one explicit adapter: this record. It pins the
/// schema/hash, names the single consumer, states the proof ceiling, and
/// carries expiry/removal criteria. No new `eliot-app` feature may be added
/// through it.
public static class LegacyOperatorAdapter
{
    public const string ToolContract = "eliot_operator_contract";
    public const string ToolSnapshot = "eliot_operator_snapshot";
    public const string ToolQuery = "eliot_operator_query";
    public const string ToolCommand = "eliot_operator_command";

    public static string SchemaVersion => OperatorProtocol.SchemaVersion;
    public static string ContractHash => OperatorProtocol.PinnedContractHash;

    /// The single admitted consumer of the legacy wire path.
    public const string Consumer = "Eliot.Operator.Services.GovernorPipeClient";

    /// Package/edge proof ceiling for this adapter; installed Product proof
    /// remains issue #11.
    public const string ProofCeiling = "OPERATOR_USER_SESSION_EDGE_CANDIDATE";

    /// Expiry/removal criteria: remove this adapter (and migrate reads to the
    /// current ControlBoard/runtime-status owner and mutations to the current
    /// typed Operator-intent owner) as soon as the Governor serves a
    /// current-owner route on the UI pipe, or when the #1189 retirement owner
    /// lands. The adapter must never gain a fifth tool, a new command shape,
    /// or a wider capability.
    public const string ExpiryRemoval =
        "Remove when the Governor serves a current-owner ControlBoard/OperatorIntent route " +
        "on the UI pipe or the #1189 retirement owner lands; no new tool or command shape may be added.";
}
