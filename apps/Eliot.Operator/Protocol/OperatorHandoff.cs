using Eliot.Operator.Services;

namespace Eliot.Operator.Protocol;

/// Why a one-shot owner handoff stopped being usable. Every value is terminal
/// for that handoff: continuity is never re-established from a process, a
/// user, a pipe name, a cached endpoint or a consumed environment value.
public enum OperatorHandoffInvalidation
{
    None = 0,
    Consumed,
    Expired,
    PipeLost,
    InstallationMismatch,
    SessionMismatch,
    ProcessMismatch,
    EpochRotated,
    ReconnectRequired
}

/// The exact current user-session, installation and Operator process facts a
/// handoff is bound to. Everything here is locally observed; nothing is
/// owner-asserted, and no credential, endpoint or nonce is part of it.
public sealed record OperatorProcessIdentity(
    string InstallationId,
    string UserSid,
    int LogonSessionId,
    string ArtifactFingerprint,
    string ProcessGeneration)
{
    public void Validate()
    {
        OperatorIdentityFields.RequireText(InstallationId, "installation_id");
        OperatorIdentityFields.RequireText(UserSid, "user_sid");
        OperatorIdentityFields.RequireText(ArtifactFingerprint, "artifact_fingerprint");
        OperatorIdentityFields.RequireText(ProcessGeneration, "process_generation");
        if (LogonSessionId <= 0)
        {
            throw new InvalidOperationException("logon_session_id must be a positive Windows session id.");
        }
    }

    /// Bounded, redacted projection for diagnostics. It names the binding
    /// axes and nothing else: no SID value, no path, no digest.
    public string Describe() =>
        $"session={LogonSessionId} sid_bound=true installation_bound=true " +
        $"artifact_bound=true process_generation_bound=true";
}

/// Field-level validation shared by the handoff binding. Values are bounded
/// and control-free; a handoff never carries free-form owner prose.
public static class OperatorIdentityFields
{
    public const int MaxFieldChars = 512;

    public static void RequireText(string? value, string field)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > MaxFieldChars || value.Any(char.IsControl))
        {
            throw new InvalidOperationException($"Operator identity field '{field}' is not a bounded text value.");
        }
    }
}

/// One owner-issued, single-use, expiring, generation-bound Operator handoff.
///
/// The owner issues exactly six wire fields
/// (`crates/surfaces/eliot-user-broker-core::OperatorEndpoint`); this type
/// binds them to the exact installation, user SID/logon Session, broker
/// registration epoch, Operator artifact fingerprint, Operator process
/// generation, endpoint generation, role/capability set and expiry that this
/// process can prove locally. It holds no credential: the handoff nonce is
/// never exposed outside the handshake the owner already authenticates.
///
/// Consumption is single-use and irreversible. After `Consume`, the handoff
/// cannot authenticate another connection: pipe loss yields the typed
/// restart-required disposition, and a replacement handoff is the owner's to
/// issue, never this process to infer.
public sealed class OperatorHandoff
{
    /// The exact owner obligation for continuity. The UI states it verbatim
    /// and never substitutes a cached value, a PID, a user or a pipe name.
    public const string ReacquisitionRequirement =
        "a new User Broker-issued single-use handoff is required; the consumed value is never re-read " +
        "and continuity is never inferred from process, user, pipe name or a cached endpoint";

    private readonly object _gate = new();

    public OperatorEndpoint Endpoint { get; }
    public OperatorProcessIdentity Identity { get; }
    /// Broker registration epoch as issued by the owner. A handoff issued
    /// under an older registration generation can never be replayed here.
    public ulong BrokerRegistrationEpoch => Endpoint.BrokerEpoch;
    /// Governor endpoint generation. The owner publishes one generation per
    /// registration epoch; rotating it invalidates every older handoff.
    public ulong EndpointGeneration => Endpoint.BrokerEpoch;
    public DateTimeOffset ReceivedAtUtc { get; }
    public DateTimeOffset ExpiresAtUtc { get; }
    public OperatorHandoffInvalidation Invalidation { get; private set; } = OperatorHandoffInvalidation.None;

    private OperatorHandoff(
        OperatorEndpoint endpoint,
        OperatorProcessIdentity identity,
        DateTimeOffset receivedAtUtc)
    {
        Endpoint = endpoint;
        Identity = identity;
        ReceivedAtUtc = receivedAtUtc;
        ExpiresAtUtc = receivedAtUtc.AddSeconds(OperatorProtocol.HandoffLifetimeSeconds);
    }

    /// Binds one validated owner endpoint to the current process identity. The
    /// endpoint shape itself is already closed and role-filtered; this adds the
    /// local binding axes and the owner's expiry. It performs no use, so a
    /// bound-but-unused handoff never authenticates anything.
    public static OperatorHandoff Bind(
        OperatorEndpoint endpoint,
        OperatorProcessIdentity identity,
        DateTimeOffset receivedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(identity);
        identity.Validate();
        OperatorIdentityFields.RequireText(endpoint.PipeName, "pipe_name");
        OperatorIdentityFields.RequireText(endpoint.HandoffNonce, "handoff_nonce");
        OperatorIdentityFields.RequireText(endpoint.InteractiveSessionId, "interactive_session_id");
        if (endpoint.BrokerEpoch == 0)
        {
            throw new InvalidOperationException("broker_epoch must be a non-zero registration generation.");
        }
        return new OperatorHandoff(endpoint, identity, receivedAtUtc);
    }

    public bool IsUsable => Invalidation == OperatorHandoffInvalidation.None;

    /// Remaining owner-allowed lifetime, never negative.
    public TimeSpan RemainingLifetime(DateTimeOffset nowUtc)
    {
        var remaining = ExpiresAtUtc - nowUtc;
        return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
    }

    /// The single-use transition. It is taken before the connection is
    /// opened, so a failed connect can never present the same nonce twice.
    public void Consume(DateTimeOffset nowUtc)
    {
        lock (_gate)
        {
            if (Invalidation != OperatorHandoffInvalidation.None)
            {
                throw new OperatorHandoffRefusedException(Invalidation, Endpoint.BrokerEpoch);
            }
            if (nowUtc >= ExpiresAtUtc)
            {
                Invalidation = OperatorHandoffInvalidation.Expired;
                throw new OperatorHandoffRefusedException(Invalidation, Endpoint.BrokerEpoch);
            }
            Invalidation = OperatorHandoffInvalidation.Consumed;
        }
    }

    /// Marks the handoff unusable for any further connection attempt.
    public void Invalidate(OperatorHandoffInvalidation reason)
    {
        lock (_gate)
        {
            if (reason == OperatorHandoffInvalidation.None) return;
            if (Invalidation == OperatorHandoffInvalidation.None) Invalidation = reason;
        }
    }

    /// Proves that the owner-issued endpoint still describes this exact
    /// installation, user session and Operator process generation. Any drift
    /// is refused before a single byte is written to the pipe.
    public void RequireBindingTo(OperatorProcessIdentity current, DateTimeOffset nowUtc)
    {
        lock (_gate)
        {
            if (Invalidation != OperatorHandoffInvalidation.None)
            {
                throw new OperatorHandoffRefusedException(Invalidation, Endpoint.BrokerEpoch);
            }
            if (nowUtc >= ExpiresAtUtc)
            {
                Invalidation = OperatorHandoffInvalidation.Expired;
                throw new OperatorHandoffRefusedException(Invalidation, Endpoint.BrokerEpoch);
            }
            if (!string.Equals(Identity.InstallationId, current.InstallationId, StringComparison.Ordinal))
            {
                Invalidation = OperatorHandoffInvalidation.InstallationMismatch;
                throw new OperatorHandoffRefusedException(Invalidation, Endpoint.BrokerEpoch);
            }
            if (!string.Equals(Identity.UserSid, current.UserSid, StringComparison.Ordinal)
                || !IsBoundLogonSession(Endpoint.InteractiveSessionId, current.LogonSessionId))
            {
                Invalidation = OperatorHandoffInvalidation.SessionMismatch;
                throw new OperatorHandoffRefusedException(Invalidation, Endpoint.BrokerEpoch);
            }
            if (!string.Equals(Identity.ProcessGeneration, current.ProcessGeneration, StringComparison.Ordinal))
            {
                Invalidation = OperatorHandoffInvalidation.ProcessMismatch;
                throw new OperatorHandoffRefusedException(Invalidation, Endpoint.BrokerEpoch);
            }
            if (!string.Equals(Identity.ArtifactFingerprint, current.ArtifactFingerprint, StringComparison.Ordinal))
            {
                Invalidation = OperatorHandoffInvalidation.ProcessMismatch;
                throw new OperatorHandoffRefusedException(Invalidation, Endpoint.BrokerEpoch);
            }
        }
    }

    /// The owner publishes the logon Session as its decimal id
    /// (`identity.expected_session_id().to_string()`); anything else cannot
    /// be verified and is refused rather than trusted.
    private static bool IsBoundLogonSession(string ownerIssuedSessionId, int currentSessionId) =>
        int.TryParse(ownerIssuedSessionId, System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture, out var issued)
        && issued == currentSessionId;

    /// Bounded redacted projection. The nonce, pipe name and session value
    /// never appear here.
    public override string ToString() =>
        $"handoff state={Invalidation} broker_epoch={BrokerRegistrationEpoch} " +
        $"role={Endpoint.Role} capabilities={Endpoint.Capabilities.Count} identity={Identity.Describe()}";
}
