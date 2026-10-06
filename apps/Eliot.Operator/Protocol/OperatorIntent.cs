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

    /// The one character test for an operation identity. Case is part of the
    /// identity, not a spelling of it: both minters emit lowercase only
    /// (`Guid.NewGuid().ToString("N")` above, and the lowercase hex digest in
    /// `UserAutomationOperatorRequest.DeriveIdempotencyKey`), and every
    /// comparison of an operation id in this application is case-SENSITIVE
    /// (`StringComparison.Ordinal`, an ordinal `HashSet<string>`, or `==` on
    /// `string`). The owner keys its operation record on the exact string
    /// bytes too, so an uppercase twin admitted here would be a SECOND
    /// identity for one logical transition, not a tolerated spelling: the
    /// guarded comparison and the guarded admission would disagree about what
    /// "the same key" means, and the rejection that makes a reused key with a
    /// different canonical request hash an identity conflict
    /// (`docs/architecture/I05-05-write-envelope.md:34`) would rest on a
    /// character rule the guard did not state. This tightens the existing test
    /// rather than adding a mechanism: `Uri.IsHexDigit` already accepts
    /// `A`-`F`, so the extra clause only drops values no producer emits, and
    /// the one refusal sentence this method throws is unchanged.
    public static void RequireOperationId(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length != 32
            || !value.All(character => Uri.IsHexDigit(character) && !char.IsAsciiLetterUpper(character)))
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
/// send says nothing about a previous execution. All nine states stay
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
///
/// Five tool names are admitted, not four: the four legacy `eliot_operator_*`
/// tools above plus the typed user-automation owner route
/// (`UserAutomationContract.Route`), which the current Kernel serves and which
/// is not an `eliot-app` tool. The admission set is the contract, so this
/// adapter admits five names and its removal condition retires the four
/// legacy ones.
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
    /// Operator-intent owner, then delete these four legacy `eliot_operator_*`
    /// tools. Every precondition below is a fact a maintainer can check in the
    /// tree, and ALL of them must hold first.
    ///
    /// 1. A current-owner ControlBoard read route is served on the Operator
    ///    pipe and this client consumes it. It is not served today:
    ///    `git grep "controlboard.status" -- apps/` matches nothing.
    /// 2. The consumed page carries an owner-issued State Fence that this
    ///    client validates, replacing the `owner_unissued` constant
    ///    (`OperatorResponseBounds.cs:151`). The current owner already computes
    ///    one that this client does not read: `ControlBoardContour.view_fence`
    ///    (`controlboard_projection.rs:200`) and
    ///    `RenderedControlBoard.view_fence` (`controlboard_consumer.rs:538`).
    /// 3. Mutations no longer ride `eliot_operator_command`. The legacy page is
    ///    `OperatorProjectionPage` (`crates/eliot-types/src/cognition.rs:1348`
    ///    -`:1369`; `task_revision` only, no fence or epoch), produced only by
    ///    `crates/eliot-app/src/mcp_stdio/operator.rs:821` -`:841`, in a crate
    ///    that calls itself "not a current production composition root"
    ///    (`crates/eliot-app/Cargo.toml:7`) and depends on no `eliot-contracts`.
    /// 4. The UI pipe carries one protocol for this client. It carries two
    ///    today: the broker redeem leg (`BrokerPipeClient.cs:75` -`:134`) and
    ///    the Governor handshake leg, which writes `eliot_ipc_handshake`
    ///    (`GovernorPipeClient.cs:685` -`:700`) on the pipe the broker's only
    ///    server for that name binds (`bins/eliot-user-broker/src/main.rs:872`)
    ///    and where anything other than `operator_challenge` then
    ///    `redeem_operator_handoff` is answered
    ///    `BROKER_PROTOCOL_SEQUENCE_REJECTED` (`:941` -`:954`, `:979` -`:993`).
    /// 5. `Consumer` has no remaining call site of the four legacy
    ///    `eliot_operator_*` tools. The typed user-automation owner route
    ///    (`UserAutomationContract.Route`, served by the current Kernel) is not
    ///    one of them: it is not an `eliot-app` tool, it is not removed with
    ///    this adapter, and `IsAdmittedTool` admits it only while it is served
    ///    on the same pipe.
    ///
    /// An unmet precondition leaves the adapter exactly as it is. It must never
    /// gain a sixth admitted tool, a new command shape, or a wider capability.
    ///
    /// The five preconditions are the path that retires this adapter on its own
    /// merits. The second, independent path is unchanged: this adapter is legacy
    /// core, so when the #1189 retirement owner (with #18) retires that core, it
    /// is removed then regardless of how many preconditions above still hold.
    public const string ExpiryRemoval =
        "Remove when all five preconditions in the comment above hold: a served, " +
        "consumed current-owner ControlBoard read route; an owner-issued State Fence on " +
        "the consumed page; mutations served by the current typed Operator-intent owner; " +
        "one protocol on the UI pipe; and no remaining call site of the four legacy " +
        "eliot_operator_* tools. " +
        "Also remove when the #1189 retirement owner retires this legacy core. " +
        "No new tool or command shape may be added.";

    /// The exact closed set of routes this adapter may issue: the four legacy
    /// `eliot_operator_*` tools plus the typed user-automation owner route.
    /// `IsAdmittedTool` gates on this array, so its five entries are the
    /// contract and the prose above counts the four legacy tools separately.
    /// A tool outside the set is refused before it is written to the pipe, so
    /// the adapter cannot gain a sixth route, a second command shape or a wider
    /// capability by accident.
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

    /// The `removal=` value the startup log carries. It is a POINTER to
    /// `ExpiryRemoval` above, not a paraphrase of it: the full normative
    /// condition, including the #1189 retirement path, stays in the source,
    /// and reproducing 400+ characters of a source comment in a log record
    /// exceeds the one-line record bound, where the formatter clips it
    /// SILENTLY and severing the text mid-word looks like a whole condition.
    /// I15.4 governs the shape directly: "Startup diagnostics may record which
    /// reference/version was used, never the value"
    /// (`docs/architecture/I15-04-secrets.md:17`). Nothing parses this field:
    /// "Operational logs never become verifier evidence by themselves"
    /// (`docs/architecture/I16-17-instrument-plane-observability.md:34`), so a
    /// named reference is the truthful and sufficient record. The pointer is
    /// deliberately not a weaker claim: both retirement paths are named here,
    /// and no precondition, threshold or clause is restated or dropped.
    public const string RemovalReference =
        "see OperatorIntent LegacyOperatorAdapter removal conditions " +
        "(5 preconditions; #1189 legacy-core retirement)";

    /// Bounded redacted description of this adapter's boundary. It carries the
    /// pinned identity, the single consumer, the admitted-route count, the
    /// proof ceiling and a pointer to the removal condition; it carries no
    /// endpoint, nonce, credential or payload.
    ///
    /// `tools=` counts the entries of the closed admission set `IsAdmittedTool`
    /// gates on, so it is five: the four legacy `eliot_operator_*` tool names
    /// plus the typed user-automation owner route. That is the same count the
    /// code has always enforced; it is not the "four tools" of the removal
    /// condition, which names the four legacy tools specifically. Both counts
    /// are now stated in the prose above, so the field beside them no longer
    /// contradicts them.
    ///
    /// Length: the composed record is 392 characters against
    /// `OperatorDiagnostics.MaxRecordChars` (512), margin 120, so the
    /// formatter's clip cannot silently sever this record.
    public static string Describe() =>
        $"legacy adapter schema={SchemaVersion} hash={ContractHash} consumer={Consumer} " +
        $"tools={AdmittedTools.Length} proof_ceiling={ProofCeiling} removal={RemovalReference}";
}
