using System.Text.Json;
using Eliot.Operator.Protocol;

namespace Eliot.Operator.Services;

/// The owner-issued handoff is consumed, expired, mismatched or absent, and no
/// replacement handoff is available in-process: the UI must restart through a
/// fresh broker-issued binding. Retrying on the consumed endpoint, PID, pipe
/// name, or cached environment value is forbidden.
public class OperatorRestartRequiredException : InvalidOperationException
{
    public OperatorRestartRequiredException(string reason, string? operationId = null)
        : base(operationId is null
            ? $"Operator restart required: {reason}"
            : $"Operator restart required for {operationId}: {reason}")
    {
        Reason = reason;
        OperationId = operationId;
    }

    public string Reason { get; }
    public string? OperationId { get; }
}

/// A handoff was refused before use. Every refusal is terminal for that
/// handoff, so the only recovery is a new owner-issued single-use handoff.
/// The message carries the bounded invalidation code and the broker
/// registration generation; the nonce, pipe name, endpoint and session value
/// never appear here.
public sealed class OperatorHandoffRefusedException : OperatorRestartRequiredException
{
    public OperatorHandoffRefusedException(OperatorHandoffInvalidation invalidation, ulong brokerEpoch)
        : base(
            $"handoff refused ({invalidation}) at broker registration generation {brokerEpoch}; " +
            OperatorHandoff.ReacquisitionRequirement)
    {
        Invalidation = invalidation;
        BrokerRegistrationEpoch = brokerEpoch;
    }

    public OperatorHandoffInvalidation Invalidation { get; }
    public ulong BrokerRegistrationEpoch { get; }
}

/// A mutation request may have reached the owner but its outcome was not
/// proven by a typed receipt. The same operation identity must be reconciled;
/// minting a second identity for the same logical mutation is forbidden.
public sealed class OperatorUnknownOutcomeException(
    string operationId,
    string tool,
    string detail)
    : IOException($"Operator outcome unknown for {operationId} via {tool}: {detail}")
{
    public string OperationId { get; } = operationId;
    public string Tool { get; } = tool;
}

/// Closed, versioned, transport-independent fault codes. The UI and the
/// startup log show these instead of framework message text, because a
/// framework message can carry a pipe name, an endpoint, a path, a protocol
/// fragment or a decoded value. One code always means the same condition, so
/// diagnostics never leak and never drift.
public static class OperatorFaultReason
{
    public const string ConnectionRefused = "connection_refused";
    public const string ConnectionTimeout = "connection_timeout";
    public const string HandshakeRefused = "handshake_refused";
    public const string HandshakeShapeRefused = "handshake_shape_refused";
    public const string PipeLost = "pipe_lost";
    public const string AccessDenied = "access_denied";
    public const string ResponseOversize = "response_oversize";
    public const string ResponseShapeRefused = "response_shape_refused";
    public const string ResponseCorrelationRefused = "response_correlation_refused";
    public const string OwnerErrorUnbound = "owner_error_unbound";
    public const string OwnerResultAbsent = "owner_result_absent";
    public const string OwnerResultUnreadable = "owner_result_unreadable";
    public const string EndpointUnreadable = "endpoint_unreadable";
    public const string EndpointInvalid = "endpoint_invalid";
    public const string ProcessIdentityUnproven = "process_identity_unproven";
    public const string RequestTimeout = "request_timeout";

    /// Maps one transport/protocol exception to its closed code. The type
    /// name and HRESULT stay available for the bounded startup log; the
    /// message never travels.
    public static string ForException(Exception error) => error switch
    {
        OperatorProtocolException protocol => $"{protocol.Shape}_{protocol.Reason.Replace(':', '_')}",
        UnauthorizedAccessException => AccessDenied,
        TimeoutException => ConnectionTimeout,
        OperationCanceledException => RequestTimeout,
        JsonException => ResponseShapeRefused,
        NotSupportedException => ResponseShapeRefused,
        OperatorProcessIdentityException => ProcessIdentityUnproven,
        IOException => PipeLost,
        InvalidOperationException => ResponseShapeRefused,
        _ => "unexpected_fault"
    };
}
