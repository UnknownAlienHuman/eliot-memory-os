using Eliot.Operator.Protocol;

namespace Eliot.Operator.Services;

public sealed class RuntimeDiscoveryException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public sealed class RuntimeDiscoveryService
{
    internal const string EndpointEnvironmentVariable = "ELIOT_OPERATOR_ENDPOINT";

    public Task<OperatorEndpoint> DiscoverAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var encoded = Environment.GetEnvironmentVariable(EndpointEnvironmentVariable);
        // The inherited value is a consuming authenticator, never a reconnect token.
        Environment.SetEnvironmentVariable(EndpointEnvironmentVariable, null);
        if (string.IsNullOrWhiteSpace(encoded))
        {
            throw new RuntimeDiscoveryException("endpoint_missing", "authenticated User Broker endpoint was not inherited");
        }

        try
        {
            var endpoint = System.Text.Json.JsonSerializer.Deserialize<OperatorEndpoint>(encoded)
                ?? throw new RuntimeDiscoveryException("endpoint_unreadable", "User Broker endpoint is empty");
            ValidateEndpoint(endpoint);
            return Task.FromResult(endpoint);
        }
        catch (System.Text.Json.JsonException error)
        {
            throw new RuntimeDiscoveryException("endpoint_unreadable", error.Message);
        }
    }

    public static void ValidateEndpoint(OperatorEndpoint endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint.PipeName)
            || !endpoint.PipeName.StartsWith(@"\\.\pipe\", StringComparison.OrdinalIgnoreCase)
            || endpoint.BrokerEpoch == 0
            || string.IsNullOrWhiteSpace(endpoint.InteractiveSessionId)
            || string.IsNullOrWhiteSpace(endpoint.HandoffNonce)
            || endpoint.Role != "human_operator"
            || !endpoint.Capabilities.SequenceEqual(
                ["controlboard.read", "operator.command"],
                StringComparer.Ordinal))
        {
            throw new RuntimeDiscoveryException("endpoint_invalid", "User Broker endpoint is not a role-filtered authenticated binding");
        }
    }
}
