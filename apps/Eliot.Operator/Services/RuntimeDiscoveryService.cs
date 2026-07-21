using System.Text.Json;
using Eliot.Operator.Protocol;

namespace Eliot.Operator.Services;

public sealed class RuntimeDiscoveryException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public sealed record DiscoveredRuntime(RuntimePublication Publication, RuntimeAuthentication Authentication);

public sealed class RuntimeDiscoveryService
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task<DiscoveredRuntime> DiscoverAsync(CancellationToken cancellationToken = default)
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var publicationPath = Path.Combine(localAppData, "Eliot", "instances", "default", "runtime", "publication.json");
        if (!File.Exists(publicationPath))
        {
            throw new RuntimeDiscoveryException("publication_missing", $"ELIOT runtime publication not found: {publicationPath}");
        }

        var publication = JsonSerializer.Deserialize<RuntimePublication>(
            await File.ReadAllTextAsync(publicationPath, cancellationToken), Json)
            ?? throw new RuntimeDiscoveryException("publication_unreadable", "ELIOT runtime publication is empty");
        if (publication.ProtocolVersion != OperatorProtocol.IpcProtocolVersion || publication.State != "ready")
        {
            throw new RuntimeDiscoveryException("publication_not_ready", "ELIOT runtime protocol or readiness state does not match");
        }
        if (!File.Exists(publication.AuthRef))
        {
            throw new RuntimeDiscoveryException("authentication_missing", "ELIOT runtime authentication reference is missing");
        }

        var authentication = JsonSerializer.Deserialize<RuntimeAuthentication>(
            await File.ReadAllTextAsync(publication.AuthRef, cancellationToken), Json)
            ?? throw new RuntimeDiscoveryException("authentication_unreadable", "ELIOT runtime authentication file is empty");
        ValidateGeneration(publication, authentication);
        return new DiscoveredRuntime(publication, authentication);
    }

    public static void ValidateGeneration(
        RuntimePublication publication,
        RuntimeAuthentication authentication)
    {
        if (authentication.ProtocolVersion != publication.ProtocolVersion
            || authentication.InstanceName != publication.InstanceName
            || authentication.RuntimeId != publication.RuntimeId
            || authentication.AuthGeneration != publication.AuthGeneration
            || authentication.PipeName != publication.PipeName
            || authentication.TokenGenerationId != publication.AuthGeneration
            || string.IsNullOrWhiteSpace(authentication.Token))
        {
            throw new RuntimeDiscoveryException("stale_auth", "ELIOT runtime authentication does not match the active generation");
        }
    }
}
