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
    string detail,
    string? stage = null)
    : IOException($"Operator outcome unknown for {operationId} via {tool} at {stage ?? OperatorExchangeStages.Exchange}: {detail}")
{
    public string OperationId { get; } = operationId;
    public string Tool { get; } = tool;

    /// The bounded stage of the whole caller operation at which the outcome
    /// stopped being provable. It is a closed code, never free prose, so a
    /// diagnostic built from it can carry no pipe name, endpoint or payload.
    public string Stage { get; } = stage ?? OperatorExchangeStages.Exchange;
}

/// The request was proven NOT to have reached the owner.
///
/// This is only reported while no application byte could have left this
/// process: admission, queue waiting, discovery, connection, handshake,
/// initialization and contract checks, or a deadline that expired before the
/// first write. The moment a write starts, the outcome is
/// [`OperatorUnknownOutcomeException`] instead, because a failed write may be
/// partial. The stage and reason code distinguish a whole-operation deadline
/// from the caller's own cancellation and from a closing client, so no caller
/// has to infer which bound fired.
public sealed class OperatorNotAttemptedException(
    string operationId,
    string tool,
    string detail,
    string stage)
    : IOException($"Operator request not attempted for {operationId} via {tool} at {stage}: {detail}")
{
    public string OperationId { get; } = operationId;
    public string Tool { get; } = tool;
    public string Stage { get; } = stage;
}

/// The owner side of the exchange is settled and only the LOCAL teardown of
/// the transport that carried it was incomplete.
///
/// This is deliberately distinct from
/// [`OperatorUnknownOutcomeException`]: `OwnerAnswerObserved` says the owner
/// did answer, so the operation's owner outcome is not unknown, and only the
/// local connection cleanup is limited. The primary outcome is never replaced
/// by this fault, and the retained operation identity is unchanged.
public sealed class OperatorCleanupIncompleteException(
    string operationId,
    string tool,
    string detail,
    string stage,
    bool ownerAnswerObserved)
    : IOException($"Operator cleanup incomplete for {operationId} via {tool} at {stage}: {detail} (owner answer observed: {ownerAnswerObserved})")
{
    public string OperationId { get; } = operationId;
    public string Tool { get; } = tool;
    public string Stage { get; } = stage;
    public bool OwnerAnswerObserved { get; } = ownerAnswerObserved;
}

/// The closed set of stages one caller operation can fail in. A stage is a
/// bounded code, never free prose: it names where the bounded work stopped,
/// and never carries a pipe name, endpoint, nonce or payload.
public static class OperatorExchangeStages
{
    public const string Admission = "admission";
    public const string Queue = "queue";
    public const string Establishment = "establishment";
    public const string Connect = "connect";
    public const string HandshakeRead = "handshake_read";
    public const string Initialize = "initialize";
    public const string Contract = "contract";
    public const string Exchange = "exchange";
    public const string Decode = "decode";
    public const string Cleanup = "cleanup";
    public const string Dispose = "dispose";
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
    /// The caller's own token cancelled the request, distinct from the
    /// whole-operation deadline and from a closing client.
    public const string RequestCancelled = "request_cancelled";
    /// The client entered its closing lifecycle transition, so the request was
    /// refused or interrupted by UI teardown rather than by a transport fault.
    public const string ClientClosing = "client_closing";
    /// The one-shot owner handoff's establishment window closed. It bounds
    /// connection and the required initial authentication steps only, and a
    /// handoff whose window closed can never establish a session afterwards.
    public const string EstablishmentWindowExpired = "handoff_establishment_window_expired";
    /// The transport was aborted but its reader/writer completions did not
    /// finish inside the finite local teardown allowance. The primary outcome
    /// is preserved and only the cleanup is limited.
    public const string CleanupIncomplete = "cleanup_incomplete";

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
