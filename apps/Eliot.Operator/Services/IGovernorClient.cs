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
}
