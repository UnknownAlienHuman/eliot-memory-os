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

/// Which owner route a retained operation belongs to. A pending entry is
/// reconciled on its own route under its own identity; a retained entry can
/// never be replayed through the other route.
public enum OperatorMutationRoute
{
    OperatorCommand = 0,
    UserAutomation
}

/// Durable phases of one UI-issued operation. `UnknownReconciling` means the
/// request may have executed: the same identity must be reconciled, never
/// resubmitted as a new mutation. `PossiblyExecuted` is a transport loss after
/// the request was written; `StaleFence` is an owner-bound rejection proving
/// the mutation was not admitted. `NotAttempted` is reserved for a request
/// proven never to have left this process; it is not terminal and is never
/// assigned to an older retained operation, because a failure before a new
/// send says nothing about a previous execution. All eight states stay
/// distinct.
public enum OperatorOperationPhase
{
    Created,
    Submitted,
    PossiblyExecuted,
    Receipted,
    Rejected,
    Cancelled,
    StaleFence,
    UnknownReconciling,
    NotAttempted
}

/// One retained operation: identity, canonical envelope bytes, expected
/// revision/fence input, and phase until a terminal receipt.
public sealed record OperatorPendingOperation(
    string OperationId,
    OperatorMutationRoute Route,
    string EnvelopeJson,
    ulong? ExpectedRevision,
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

    /// Expiry/removal criteria: migrate reads to the current
    /// ControlBoard/runtime-status owner and mutations to the current typed
    /// Operator-intent owner, then delete these four tools. Every precondition
    /// below is a fact a maintainer can check in the tree, and ALL of them must
    /// hold first.
    ///
    /// 1. A current-owner ControlBoard read route is served on the Operator
    ///    pipe and this client consumes it. It is not served today:
    ///    `git grep "controlboard.status" -- apps/` matches nothing.
    /// 2. The consumed page carries an owner-issued State Fence that this
    ///    client validates, replacing the `owner_unissued` constant
    ///    (`OperatorResponseBounds.cs:151`). The current owner already computes
    ///    one that this client does not read: `ControlBoardContour.view_fence`
    ///    (`controlboard_projection.rs:199`) and
    ///    `RenderedControlBoard.view_fence` (`controlboard_consumer.rs:534`).
    /// 3. Mutations no longer ride `eliot_operator_command`. The legacy page is
    ///    `OperatorProjectionPage` (`crates/eliot-types/src/cognition.rs:1302`
    ///    -`:1323`; `task_revision` only, no fence or epoch), produced only by
    ///    `crates/eliot-app/src/mcp_stdio/operator.rs:821` -`:840`, in a crate
    ///    that calls itself "not a current production composition root"
    ///    (`crates/eliot-app/Cargo.toml:7`) and depends on no `eliot-contracts`.
    /// 4. The UI pipe carries one protocol for this client. It carries two
    ///    today: the broker redeem leg (`BrokerPipeClient.cs:75` -`:134`) and
    ///    the Governor handshake leg, which writes `eliot_ipc_handshake`
    ///    (`GovernorPipeClient.cs:579` -`:594`) on the pipe the broker's only
    ///    server for that name binds (`bins/eliot-user-broker/src/main.rs:872`)
    ///    and where anything other than `operator_challenge` then
    ///    `redeem_operator_handoff` is answered
    ///    `BROKER_PROTOCOL_SEQUENCE_REJECTED` (`:941` -`:954`, `:979` -`:990`).
    /// 5. `Consumer` has no remaining call site of the four tools.
    ///
    /// An unmet precondition leaves the adapter exactly as it is. It must never
    /// gain a fifth tool, a new command shape, or a wider capability.
    public const string ExpiryRemoval =
        "Remove only when all five preconditions in the comment above hold: a served, " +
        "consumed current-owner ControlBoard read route; an owner-issued State Fence on " +
        "the consumed page; mutations served by the current typed Operator-intent owner; " +
        "one protocol on the UI pipe; and no remaining call site of the four tools. " +
        "No new tool or command shape may be added.";

    /// The exact closed set of routes this adapter may issue. A tool outside
    /// the set is refused before it is written to the pipe, so the adapter
    /// cannot gain a fifth tool, a second command shape or a wider capability
    /// by accident.
    private static readonly string[] AdmittedTools =
    [
        ToolContract,
        ToolSnapshot,
        ToolQuery,
        ToolCommand,
        UserAutomationContract.Route
    ];

    public static bool IsAdmittedTool(string? tool) =>
        tool is not null && AdmittedTools.Contains(tool, StringComparer.Ordinal);

    /// Bounded redacted description of this adapter's boundary. It carries the
    /// pinned identity, the single consumer, the proof ceiling and the removal
    /// condition; it carries no endpoint, nonce, credential or payload.
    public static string Describe() =>
        $"legacy adapter schema={SchemaVersion} hash={ContractHash} consumer={Consumer} " +
        $"tools={AdmittedTools.Length} proof_ceiling={ProofCeiling} removal={ExpiryRemoval}";
}
