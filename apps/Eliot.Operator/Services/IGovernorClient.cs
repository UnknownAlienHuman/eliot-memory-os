using System.Text.Json;
using Eliot.Operator.Protocol;

namespace Eliot.Operator.Services;

public interface IGovernorClient
{
    Task<OperatorSnapshot> SnapshotAsync(
        string? projectId = null,
        string? taskId = null,
        CancellationToken cancellationToken = default);

    Task<OperatorProjectionPage> QueryAsync(
        OperatorQueryRequest request,
        CancellationToken cancellationToken = default);

    Task<JsonElement> CommandAsync(
        object commandEnvelope,
        CancellationToken cancellationToken = default);

    /// Reconciles the SAME operation after a lost response: resends the exact
    /// retained envelope bytes (same operation identity) and returns the owner
    /// receipt. Minting a second identity for the same logical mutation is
    /// forbidden; pipe loss without a fresh owner handoff surfaces the typed
    /// restart-required disposition instead of a silent retry.
    Task<JsonElement> ReconcileAsync(
        JsonElement commandEnvelope,
        CancellationToken cancellationToken = default);

    Task<JsonElement> UserAutomationAsync(
        UserAutomationOperation operation,
        CancellationToken cancellationToken = default);
}
