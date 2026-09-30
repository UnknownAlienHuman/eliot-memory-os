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
///
/// Single use is structural, not a side effect of the clear. The environment
/// is consulted at most once per process whatever that attempt returns, and
/// the first refusal becomes the process-wide terminal disposition reported
/// verbatim afterwards, so one root cause can never be reported under a
/// second code. There is no retry here and none is implied: recovery is a new
/// owner-issued single-use handoff, which this process cannot obtain itself.
public sealed class RuntimeDiscoveryService
{
    internal const string EndpointEnvironmentVariable = "ELIOT_OPERATOR_ENDPOINT";

    private readonly object _gate = new();
    private OperatorHandoff? _inheritedHandoff;
    /// Set before the single environment read, so no later call can reach it
    /// again whatever the attempt returned.
    private bool _endpointReadAttempted;
    /// The first terminal refusal, kept verbatim. A latched refusal is never
    /// recomputed, so one root cause is never reported under two codes.
    private (string Code, string Message)? _terminalRefusal;

    public Task<OperatorHandoff> DiscoverAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (_terminalRefusal is { } latched)
            {
                throw new RuntimeDiscoveryException(latched.Code, latched.Message);
            }
            if (_inheritedHandoff is { } bound)
            {
                if (bound.IsUsable)
                {
                    return Task.FromResult(bound);
                }
                // The consumed value is not re-read and not re-presented. The
                // owner must issue a new single-use handoff.
                throw Latch("endpoint_missing", OperatorHandoff.ReacquisitionRequirement);
            }
            if (_endpointReadAttempted)
            {
                // Unreachable while a refusal is latched; kept so the one read
                // stays structural instead of relying on the clear below to make
                // a second read harmless.
                throw Latch("endpoint_missing", OperatorHandoff.ReacquisitionRequirement);
            }
            _endpointReadAttempted = true;

            var encoded = Environment.GetEnvironmentVariable(EndpointEnvironmentVariable);
            // The inherited value is a consuming authenticator, never a reconnect token.
            Environment.SetEnvironmentVariable(EndpointEnvironmentVariable, null);
            if (string.IsNullOrWhiteSpace(encoded))
            {
                throw Latch("endpoint_missing", OperatorHandoff.ReacquisitionRequirement);
            }
            if (encoded.Length > OperatorProtocol.MaxEndpointChars)
            {
                throw Latch(
                    "endpoint_unreadable",
                    $"{OperatorFaultReason.EndpointUnreadable}: encoded endpoint exceeds the closed endpoint bound");
            }

            // Decode and bind are two separately-redacted phases, not one. They
            // differ in what can raise: the decode phase raises framework
            // `JsonException` plus the guard's own `OperatorProtocolException`,
            // while the bind phase raises only locally authored refusals that
            // name a binding axis and never the value refused. Sharing one
            // handler across both forced the safe, useful local reasons to be
            // redacted as if they were framework text, and left the one genuinely
            // caller-supplied string (the guard reason) published unchanged.
            OperatorEndpoint endpoint;
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
                endpoint = JsonSerializer.Deserialize<OperatorEndpoint>(encoded, OperatorJson.Reader)
                    ?? throw new RuntimeDiscoveryException("endpoint_unreadable", OperatorFaultReason.EndpointUnreadable);
                ValidateEndpoint(endpoint);
            }
            catch (JsonException)
            {
                throw Latch("endpoint_unreadable", OperatorFaultReason.EndpointUnreadable);
            }
            catch (OperatorProtocolException error)
            {
                // Kept verbatim, and this is the deliberate A11 call. The guard
                // states its own intent: "Only the shape name and reason travel;
                // values never do", and "Only the property names of a rejection
                // are reported; values are never echoed". A reason is therefore a
                // closed guard code plus, for `duplicate:` / `unknown:` only, a
                // member name — a length-capped protocol token, not a value: no
                // pipe name, nonce, credential or body can reach it, because the
                // guard refuses the name on `MaxControlStringChars` against the
                // raw `ValueSpan` before `GetString` allocates and never reads a
                // member value at all. A11 forbids a nonce, endpoint,
                // credential, body or protected record content; a JSON key is
                // none of those. The leak direction is also not the one A11
                // guards: an attacker who can set the inherited endpoint already
                // chooses that text, so publishing it exposes the attacker's own
                // input, never a secret this process holds. `OperatorFaultReason
                // .ForException` already publishes this same reason as a closed
                // code, so this path is the established convention, not a new one.
                throw Latch(
                    "endpoint_unreadable",
                    $"{OperatorFaultReason.EndpointUnreadable}: {error.Reason}");
            }
            catch (ArgumentException)
            {
                // Framework text never becomes a latched message.
                throw Latch("endpoint_invalid", OperatorFaultReason.EndpointInvalid);
            }
            catch (InvalidOperationException)
            {
                // Unreachable on this path: `OperatorProtocolException` derives
                // from `InvalidOperationException` and is caught above, and the
                // guard raises nothing else. Kept as a fail-closed net so that no
                // future framework text reaches a latch that is replayed for the
                // life of the process.
                throw Latch("endpoint_invalid", OperatorFaultReason.EndpointInvalid);
            }
            catch (RuntimeDiscoveryException error)
            {
                // A refusal raised inside the decode (for example the null
                // endpoint) keeps its own typed code instead of being swallowed
                // by the shape handlers above.
                throw Latch(error.Code, error.Message);
            }

            try
            {
                _inheritedHandoff = OperatorHandoff.Bind(
                    endpoint,
                    OperatorProcessIdentityProvider.Current,
                    DateTimeOffset.UtcNow);
            }
            catch (OperatorProcessIdentityException error)
            {
                // `Observe` substitutes a locally authored sentence for every
                // framework message it catches, so `error.Message` here is never
                // framework text.
                throw Latch("endpoint_invalid", error.Message);
            }
            catch (ArgumentException)
            {
                // `Bind` guards both references with `ThrowIfNull`. That is
                // framework text and stays a bare closed code.
                throw Latch("endpoint_invalid", OperatorFaultReason.EndpointInvalid);
            }
            catch (InvalidOperationException error)
            {
                // The locally authored refusal, latched again. Everything between
                // this handler and `OperatorHandoff.Bind` that raises
                // `InvalidOperationException` is one of three fixed sentences in
                // `OperatorIdentityFields.RequireText`, `OperatorProcessIdentity
                // .Validate` and `OperatorHandoff.Bind` itself. Each names a
                // binding axis ("installation_id", "pipe_name",
                // "handoff_nonce", "broker_epoch", ...) interpolated from a local
                // constant, and none echoes the value it refused — so this is not
                // framework text and is not caller-supplied. Redacting it left
                // `endpoint_invalid` as the only bare code in this method, and the
                // operator could no longer tell a zero registration epoch from a
                // blank nonce, a blank session id or an unproven identity.
                throw Latch("endpoint_invalid", $"{OperatorFaultReason.EndpointInvalid}: {error.Message}");
            }
            return Task.FromResult(_inheritedHandoff);
        }
    }

    /// Records the refusal as this process's terminal disposition and returns
    /// it to throw. The exception is rebuilt per call so a stable typed code
    /// never becomes a shared stack trace.
    ///
    /// The latched message is replayed verbatim for the life of the process, so
    /// only a closed [`OperatorFaultReason`] code, a locally authored bounded
    /// refusal, or a guard reason may be passed here. Framework exception text
    /// must never be latched; the phases above separate the two so that the
    /// safe local reasons stay distinguishable without opening a path for
    /// framework text.
    private RuntimeDiscoveryException Latch(string code, string message)
    {
        _terminalRefusal = (code, message);
        return new RuntimeDiscoveryException(code, message);
    }

    public static void ValidateEndpoint(OperatorEndpoint endpoint)
    {
        // The role is exact; the accepted capabilities are a non-empty list of
        // distinct members of the closed two-capability vocabulary. An absent,
        // null, empty, duplicated, unknown or wider set is refused. The check is
        // null-safe: the closed decode admits any subset of the six names, so a
        // missing member arrives here as a null list and must be refused as a
        // typed `endpoint_invalid` rather than dereferenced.
        //
        // This is a fail-early shape check, not the authority. The owner
        // (eliot-user-broker-core OperatorEndpoint::validate and
        // OperatorHandoffAuthority::issue) mints the full ordered capability
        // set and re-checks it against the request and again on redemption;
        // only that owner check is authoritative.
        //
        // Two names are NOT this method and must never be cited as its
        // implementation. `OperatorFaultReason.EndpointInvalid`
        // (OperatorClientFaults.cs) is the production fault-reason CONSTANT this
        // method throws at the bottom of this block; it is a reason string with
        // no validation logic and no conformance surface, so a grep that finds
        // it proves only that the reason exists. The conformance harness
        // asserts these refusals through its own local helper
        // `RefusesCapabilities` in `tests/Eliot.Operator.Tests/Program.cs`,
        // which calls this method and reports the typed `endpoint_invalid`
        // code; that helper is the only harness symbol for these cases, and the
        // harness file contains no `EndpointInvalid` at all. In this file the
        // name occurs only as the qualified `OperatorFaultReason.EndpointInvalid`
        // reference. The production callers of this method are
        // `DiscoverAsync` below and
        // `BrokerPipeClient.RedeemOperatorHandoffAsync`.
        if (string.IsNullOrWhiteSpace(endpoint.PipeName)
            || !endpoint.PipeName.StartsWith(@"\\.\pipe\", StringComparison.OrdinalIgnoreCase)
            || endpoint.BrokerEpoch == 0
            || string.IsNullOrWhiteSpace(endpoint.InteractiveSessionId)
            || string.IsNullOrWhiteSpace(endpoint.HandoffNonce)
            || !string.Equals(endpoint.Role, OperatorCapabilityNames.HumanOperatorRole, StringComparison.Ordinal)
            || endpoint.Capabilities is not { Count: > 0 }
            || endpoint.Capabilities.Any(capability =>
                !string.Equals(capability, OperatorCapabilityNames.ControlboardRead, StringComparison.Ordinal)
                && !string.Equals(capability, OperatorCapabilityNames.OperatorCommand, StringComparison.Ordinal))
            || endpoint.Capabilities.Distinct(StringComparer.Ordinal).Count() != endpoint.Capabilities.Count)
        {
            throw new RuntimeDiscoveryException("endpoint_invalid", OperatorFaultReason.EndpointInvalid);
        }
    }
}
