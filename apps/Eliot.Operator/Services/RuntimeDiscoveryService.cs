using System.Text.Json;
using Eliot.Operator.Protocol;

namespace Eliot.Operator.Services;

public sealed class RuntimeDiscoveryException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

/// Single-use source of the one owner-issued Operator handoff.
///
/// The inherited `ELIOT_OPERATOR_ENDPOINT` value is a consuming
/// authenticator, not a reconnect token. This service reads it exactly once,
/// clears it immediately, binds it to the exact current installation, user
/// SID/logon Session and Operator process generation, and never reads,
/// re-parses or re-presents it again. Once the bound handoff is consumed,
/// expired, invalidated or refused, every further call returns the typed
/// restart-required disposition: a replacement handoff is the owner's to
/// issue, never this process to reconstruct from a PID, a user, a pipe name
/// or a cached endpoint.
public sealed class RuntimeDiscoveryService
{
    internal const string EndpointEnvironmentVariable = "ELIOT_OPERATOR_ENDPOINT";

    private readonly object _gate = new();
    private OperatorHandoff? _inheritedHandoff;

    public Task<OperatorHandoff> DiscoverAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (_inheritedHandoff is { } bound)
            {
                if (bound.IsUsable)
                {
                    return Task.FromResult(bound);
                }
                // The consumed value is not re-read and not re-presented. The
                // owner must issue a new single-use handoff.
                throw new RuntimeDiscoveryException(
                    "endpoint_missing",
                    OperatorHandoff.ReacquisitionRequirement);
            }

            var encoded = Environment.GetEnvironmentVariable(EndpointEnvironmentVariable);
            // The inherited value is a consuming authenticator, never a reconnect token.
            Environment.SetEnvironmentVariable(EndpointEnvironmentVariable, null);
            if (string.IsNullOrWhiteSpace(encoded))
            {
                throw new RuntimeDiscoveryException(
                    "endpoint_missing",
                    OperatorHandoff.ReacquisitionRequirement);
            }
            if (encoded.Length > OperatorProtocol.MaxEndpointChars)
            {
                throw new RuntimeDiscoveryException(
                    "endpoint_unreadable",
                    $"{OperatorFaultReason.EndpointUnreadable}: encoded endpoint exceeds the closed endpoint bound");
            }

            try
            {
                // Closed decode first: the broker-issued endpoint has exactly six
                // known properties; unknown or duplicate fields fail before use.
                OperatorJsonGuard.ValidateClosedObject(
                    encoded,
                    ["pipe_name", "broker_epoch", "interactive_session_id", "handoff_nonce", "role", "capabilities"],
                    OperatorProtocol.MaxControlMembers,
                    OperatorProtocol.MaxControlStringChars,
                    OperatorProtocol.MaxControlDepth,
                    OperatorProtocol.MaxControlTokens,
                    "endpoint");
                var endpoint = JsonSerializer.Deserialize<OperatorEndpoint>(encoded, OperatorJson.Reader)
                    ?? throw new RuntimeDiscoveryException("endpoint_unreadable", OperatorFaultReason.EndpointUnreadable);
                ValidateEndpoint(endpoint);
                _inheritedHandoff = OperatorHandoff.Bind(
                    endpoint,
                    OperatorProcessIdentityProvider.Current,
                    DateTimeOffset.UtcNow);
                return Task.FromResult(_inheritedHandoff);
            }
            catch (JsonException)
            {
                throw new RuntimeDiscoveryException("endpoint_unreadable", OperatorFaultReason.EndpointUnreadable);
            }
            catch (OperatorProtocolException error)
            {
                throw new RuntimeDiscoveryException(
                    "endpoint_unreadable",
                    $"{OperatorFaultReason.EndpointUnreadable}: {error.Reason}");
            }
            catch (OperatorProcessIdentityException error)
            {
                throw new RuntimeDiscoveryException("endpoint_invalid", error.Message);
            }
            catch (ArgumentException error)
            {
                throw new RuntimeDiscoveryException("endpoint_invalid", $"{OperatorFaultReason.EndpointInvalid}: {error.Message}");
            }
            catch (InvalidOperationException error)
            {
                throw new RuntimeDiscoveryException("endpoint_invalid", $"{OperatorFaultReason.EndpointInvalid}: {error.Message}");
            }
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
            throw new RuntimeDiscoveryException("endpoint_invalid", OperatorFaultReason.EndpointInvalid);
        }
    }
}
