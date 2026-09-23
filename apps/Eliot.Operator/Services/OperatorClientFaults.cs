using Eliot.Operator.Protocol;

namespace Eliot.Operator.Services;

/// The owner-issued handoff is consumed or absent and no replacement handoff
/// is available: the UI must restart through a fresh broker-issued binding.
/// Retrying on the consumed endpoint, PID, pipe name, or cached environment
/// value is forbidden.
public sealed class OperatorRestartRequiredException(string reason, string? operationId = null)
    : InvalidOperationException(
        operationId is null
            ? $"Operator restart required: {reason}"
            : $"Operator restart required for {operationId}: {reason}")
{
    public string? OperationId { get; } = operationId;
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
