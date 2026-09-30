using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Eliot.Operator.Protocol;

namespace Eliot.Operator.Services;

/// Redeems the inherited one-shot handoff with the User Broker before the
/// Governor connection is opened. The client has one owner-issued pipe, one
/// challenge/redeem exchange and no cached authority or retry path.
///
/// The authenticated binding's LIFETIME is the session, not this method. The
/// bound pipe is the one that proved the OS-observed peer identity and that
/// carried the Kernel-backed binding, so it is RETAINED after redemption
/// rather than disposed with the call: a later request leg issues on that same
/// bound handle and that same authenticated binding, reusing the existing
/// handle and the existing binding object. No second pipe is opened, the
/// challenge/redeem exchange is not repeated, no token is re-minted and no
/// authority is copied into a cache - the only state retained is a live
/// OS handle plus the object the broker already bound.
///
/// Retention is process memory and is never persisted or carried across
/// processes, so a restarted UI comes up with no retained session at all and
/// the next request has to earn a fresh Kernel challenge/session token through
/// the whole exchange again. A restart therefore cannot revive the previous
/// binding's authority, which is exactly the acceptance this lifetime change
/// has to keep true.
internal static class BrokerPipeClient
{
    private const string Preface = "ELIOT-BROKER-1\n";

    private static readonly object BindingGate = new();

    /// The one bound pipe this process holds, or null when none is retained.
    /// Cleared and disposed by <see cref="ReleaseOperatorBinding"/> when the
    /// session ends or the binding is explicitly invalidated.
    private static BrokerPipeSession? _session;

    private static readonly string[] ChallengeProperties =
    [
        "status",
        "kernel_session_token",
        "broker_epoch",
        "handoff_nonce",
        "role",
        "capabilities"
    ];

    private static readonly string[] RedeemedProperties =
    [
        "status",
        "principal",
        "interactive_session_id",
        "client_process_id",
        "kernel_session_token",
        "role",
        "capabilities"
    ];

    private static readonly string[] ErrorProperties = ["status", "code", "detail"];

    /// Performs the one challenge/redeem exchange and RETAINS the bound pipe
    /// for the session, returning the authenticated binding the broker minted
    /// for this exact process, endpoint and peer. A refusal or fault throws and
    /// retains nothing, exactly as before.
    ///
    /// The accessibility is `internal`, matching the enclosing type's own
    /// effective accessibility: the returned session type is no wider than this
    /// class, so declaring the method wider than the type it returns would only
    /// assert an accessibility the type does not have.
    internal static async Task<BrokerPipeSession> RedeemOperatorHandoffAsync(
        OperatorEndpoint endpoint,
        OperatorProcessIdentity clientIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(clientIdentity);
        try
        {
            RuntimeDiscoveryService.ValidateEndpoint(endpoint);
        }
        catch (RuntimeDiscoveryException)
        {
            throw new OperatorRestartRequiredException(OperatorFaultReason.EndpointInvalid);
        }
        clientIdentity.Validate();

        var processId = Environment.ProcessId;
        var sessionId = clientIdentity.LogonSessionId.ToString(CultureInfo.InvariantCulture);
        if (!OperatingSystem.IsWindows())
        {
            throw new OperatorRestartRequiredException(OperatorFaultReason.ProcessIdentityUnproven);
        }
        if (processId <= 0 || !ProcessGenerationMatches(clientIdentity.ProcessGeneration, processId))
        {
            throw new OperatorHandoffRefusedException(
                OperatorHandoffInvalidation.ProcessMismatch,
                endpoint.BrokerEpoch);
        }
        if (!string.Equals(endpoint.InteractiveSessionId, sessionId, StringComparison.Ordinal))
        {
            throw new OperatorHandoffRefusedException(
                OperatorHandoffInvalidation.SessionMismatch,
                endpoint.BrokerEpoch);
        }

        var pipe = new NamedPipeClientStream(
            ".",
            OwnerIssuedPipeName(endpoint),
            PipeDirection.InOut,
            PipeOptions.Asynchronous);
        // The framing is constructed over the handle before the connection is
        // opened and is read from only after it is, so binding it here changes
        // nothing the broker sees; it lets the hold own all three resources and
        // keeps the failure path a single deterministic disposal.
        var reader = new StreamReader(
            pipe,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
            detectEncodingFromByteOrderMarks: false,
            bufferSize: 4096,
            leaveOpen: true);
        var writer = new StreamWriter(
            pipe,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
            bufferSize: 4096,
            leaveOpen: true)
        {
            AutoFlush = true,
            NewLine = "\n"
        };
        try
        {
            await pipe.ConnectAsync(cancellationToken).ConfigureAwait(false);

            await pipe.WriteAsync(Encoding.ASCII.GetBytes(Preface), cancellationToken).ConfigureAwait(false);

            await WriteRequestAsync(writer, new
            {
                operation = "operator_challenge",
                endpoint
            }, cancellationToken).ConfigureAwait(false);

            using var challenge = await ReadExpectedResponseAsync(
                reader,
                "challenge",
                ChallengeProperties,
                "broker_challenge",
                cancellationToken).ConfigureAwait(false);
            var token = RequiredString(challenge.RootElement, "kernel_session_token", "broker_challenge");
            RequireBoundedText(token, "broker_challenge", "kernel_session_token");
            if (RequiredUInt64(challenge.RootElement, "broker_epoch", "broker_challenge") != endpoint.BrokerEpoch)
            {
                throw new OperatorHandoffRefusedException(
                    OperatorHandoffInvalidation.EpochRotated,
                    endpoint.BrokerEpoch);
            }
            if (!string.Equals(
                    RequiredString(challenge.RootElement, "handoff_nonce", "broker_challenge"),
                    endpoint.HandoffNonce,
                    StringComparison.Ordinal)
                || !string.Equals(
                    RequiredString(challenge.RootElement, "role", "broker_challenge"),
                    endpoint.Role,
                    StringComparison.Ordinal)
                || !CapabilitiesMatch(challenge.RootElement, endpoint.Capabilities, "broker_challenge"))
            {
                throw new OperatorRestartRequiredException(OperatorFaultReason.HandshakeRefused);
            }

            await WriteRequestAsync(writer, new
            {
                operation = "redeem_operator_handoff",
                endpoint,
                client = new
                {
                    client_process_id = processId,
                    windows_sid = clientIdentity.UserSid,
                    interactive_session_id = sessionId,
                    kernel_session_token = token
                }
            }, cancellationToken).ConfigureAwait(false);

            using var redeemed = await ReadExpectedResponseAsync(
                reader,
                "redeemed",
                RedeemedProperties,
                "broker_redeem",
                cancellationToken).ConfigureAwait(false);
            if (!string.Equals(
                    RequiredString(redeemed.RootElement, "principal", "broker_redeem"),
                    clientIdentity.UserSid,
                    StringComparison.Ordinal)
                || !string.Equals(
                    RequiredString(redeemed.RootElement, "interactive_session_id", "broker_redeem"),
                    sessionId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    RequiredString(redeemed.RootElement, "interactive_session_id", "broker_redeem"),
                    endpoint.InteractiveSessionId,
                    StringComparison.Ordinal)
                )
            {
                throw new OperatorHandoffRefusedException(
                    OperatorHandoffInvalidation.SessionMismatch,
                    endpoint.BrokerEpoch);
            }
            if (RequiredInt32(redeemed.RootElement, "client_process_id", "broker_redeem") != processId)
            {
                throw new OperatorHandoffRefusedException(
                    OperatorHandoffInvalidation.ProcessMismatch,
                    endpoint.BrokerEpoch);
            }
            if (!string.Equals(
                    RequiredString(redeemed.RootElement, "kernel_session_token", "broker_redeem"),
                    token,
                    StringComparison.Ordinal)
                || !string.Equals(
                    RequiredString(redeemed.RootElement, "role", "broker_redeem"),
                    endpoint.Role,
                    StringComparison.Ordinal)
                || !CapabilitiesMatch(redeemed.RootElement, endpoint.Capabilities, "broker_redeem"))
            {
                throw new OperatorRestartRequiredException(OperatorFaultReason.HandshakeRefused);
            }

            // Redemption proved the peer and admitted the Kernel-backed
            // binding, so the handle becomes session state instead of going
            // out of scope with this call. Publishing is the last step: nothing
            // is retained unless every check above already passed.
            return PublishSession(new BrokerPipeSession(pipe, reader, writer));
        }
        catch
        {
            // No partial binding survives a failed exchange, exactly as when
            // this handle was scoped to the method, and releasing it cannot
            // replace the refusal with a close failure.
            new BrokerPipeSession(pipe, reader, writer).Dispose();
            throw;
        }
    }

    /// Releases the retained binding and closes its pipe. This is the
    /// deterministic end of the session's hold: after it returns, no bound pipe
    /// remains and the next request has to run a fresh challenge/redeem
    /// exchange for a new Kernel challenge/token. Calling it when nothing is
    /// retained does nothing.
    internal static void ReleaseOperatorBinding()
    {
        BrokerPipeSession? released;
        lock (BindingGate)
        {
            released = _session;
            _session = null;
        }
        released?.Dispose();
    }

    /// Makes the freshly bound session THE session this process holds and
    /// releases whatever the previous binding held, so at most one bound pipe
    /// is ever live and a superseded handle is neither leaked nor reused. The
    /// swap happens under one lock and the disposal outside it, so disposing a
    /// pipe can never be observed as the retained session.
    private static BrokerPipeSession PublishSession(BrokerPipeSession session)
    {
        BrokerPipeSession? superseded;
        lock (BindingGate)
        {
            superseded = _session;
            _session = session;
        }
        superseded?.Dispose();
        return session;
    }

    /// The endpoint is the only owner-issued statement of WHICH broker
    /// instance this handoff may authenticate against, so that name is used
    /// verbatim with the same normalisation the Governor client applies to its
    /// own endpoint. A name literal in this client would contradict the owner
    /// (the broker serves exactly the name it minted into this handoff) and
    /// would let a stale or forged endpoint be redeemed against an arbitrary
    /// pipe. An unusable owner-issued name is therefore the same typed refusal
    /// as any other invalid endpoint: no default, no cached name, no second
    /// attempt, and the name itself never reaches a message or diagnostic.
    private static string OwnerIssuedPipeName(OperatorEndpoint endpoint)
    {
        var pipeName = endpoint.PipeName is { } issued
            ? issued.Replace(@"\\.\pipe\", string.Empty, StringComparison.OrdinalIgnoreCase)
            : string.Empty;
        if (string.IsNullOrWhiteSpace(pipeName))
        {
            throw new OperatorRestartRequiredException(OperatorFaultReason.EndpointInvalid);
        }

        return pipeName;
    }

    /// The generation's tick field is an OS creation instant, not an opaque
    /// marker: OperatorProcessIdentityProvider.Observe minted it from
    /// process.StartTime.ToUniversalTime().Ticks of the very process this
    /// generation names. Range-checking that field only proves the token is
    /// well shaped, so a forged "{pid}:1" would satisfy a shape check and be
    /// accepted as the same process generation, while a replacement process
    /// inheriting a recycled PID has a different creation instant. The instant
    /// is therefore read live here, at comparison time, from the process that
    /// holds this PID now - a fresh observation, never a remembered or cached
    /// start time, so nothing can go stale between production and comparison.
    ///
    /// A start time that cannot be observed is a refusal, never a match: an
    /// exited or replaced process, an invalid id and an unavailable API are all
    /// conditions in which no continuity may be claimed. The PID equality above
    /// is kept, and the shape parse keeps its NumberStyles.None /
    /// CultureInfo.InvariantCulture discipline.
    private static bool ProcessGenerationMatches(string processGeneration, int processId)
    {
        var separator = processGeneration.IndexOf(':');
        return separator > 0
            && int.TryParse(
                processGeneration.AsSpan(0, separator),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var generationProcessId)
            && generationProcessId == processId
            && long.TryParse(
                processGeneration.AsSpan(separator + 1),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var processStartTicks)
            && processStartTicks > 0
            && LiveStartTicksEqual(processId, processStartTicks);
    }

    /// Compares the generation's tick field against the live creation instant
    /// of the process that currently owns the PID. Every way this observation
    /// can fail is a fail-closed refusal, so a generation can never be honoured
    /// on the strength of its shape alone.
    private static bool LiveStartTicksEqual(int processId, long expectedStartTicks)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return process.StartTime.ToUniversalTime().Ticks == expectedStartTicks;
        }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException
            or NotSupportedException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    private static async Task WriteRequestAsync(
        StreamWriter writer,
        object request,
        CancellationToken cancellationToken)
    {
        var line = JsonSerializer.Serialize(request, OperatorJson.Writer);
        if (line.Length > OperatorProtocol.MaxLineChars)
        {
            throw new OperatorProtocolException("broker_request", "line_cap");
        }
        await writer.WriteLineAsync(line.AsMemory(), cancellationToken).ConfigureAwait(false);
    }

    private static async Task<JsonDocument> ReadExpectedResponseAsync(
        StreamReader reader,
        string expectedStatus,
        IReadOnlyCollection<string> allowedProperties,
        string shapeName,
        CancellationToken cancellationToken)
    {
        var line = await ReadBoundedLineAsync(reader, cancellationToken).ConfigureAwait(false)
            ?? throw new IOException("User Broker closed the pipe before its response.");
        OperatorJsonGuard.ValidateFramedLine(
            line,
            OperatorProtocol.MaxControlMembers,
            OperatorProtocol.MaxControlStringChars,
            OperatorProtocol.MaxControlDepth,
            OperatorProtocol.MaxControlTokens,
            shapeName);
        using var statusDocument = JsonDocument.Parse(line, new JsonDocumentOptions
        {
            MaxDepth = OperatorProtocol.MaxControlDepth
        });
        var root = statusDocument.RootElement;
        var status = RequiredString(root, "status", shapeName);
        if (string.Equals(status, "error", StringComparison.Ordinal))
        {
            OperatorJsonGuard.ValidateClosedObject(
                line,
                ErrorProperties,
                OperatorProtocol.MaxControlMembers,
                OperatorProtocol.MaxControlStringChars,
                OperatorProtocol.MaxControlDepth,
                OperatorProtocol.MaxControlTokens,
                "broker_error");
            _ = RequiredString(root, "code", "broker_error");
            _ = RequiredString(root, "detail", "broker_error");
            throw new OperatorRestartRequiredException(OperatorFaultReason.HandshakeRefused);
        }
        if (!string.Equals(status, expectedStatus, StringComparison.Ordinal))
        {
            throw new OperatorProtocolException(shapeName, "status");
        }
        OperatorJsonGuard.ValidateClosedObject(
            line,
            allowedProperties,
            OperatorProtocol.MaxControlMembers,
            OperatorProtocol.MaxControlStringChars,
            OperatorProtocol.MaxControlDepth,
            OperatorProtocol.MaxControlTokens,
            shapeName);
        return JsonDocument.Parse(line, new JsonDocumentOptions
        {
            MaxDepth = OperatorProtocol.MaxControlDepth
        });
    }

    private static async Task<string?> ReadBoundedLineAsync(
        StreamReader reader,
        CancellationToken cancellationToken)
    {
        var line = new StringBuilder();
        var buffer = new char[1024];
        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                if (line.Length == 0) return null;
                throw new OperatorProtocolException("broker_response", "unterminated_line");
            }
            for (var index = 0; index < read; index++)
            {
                var character = buffer[index];
                if (character == '\n')
                {
                    if (index != read - 1)
                    {
                        throw new OperatorProtocolException("broker_response", "trailing_frame");
                    }
                    if (line.Length > 0 && line[^1] == '\r') line.Length--;
                    return line.ToString();
                }
                if (line.Length >= OperatorProtocol.MaxLineChars)
                {
                    throw new OperatorProtocolException("broker_response", "line_cap");
                }
                line.Append(character);
            }
        }
    }

    private static string RequiredString(JsonElement parent, string propertyName, string shapeName)
    {
        if (parent.ValueKind == JsonValueKind.Object
            && parent.TryGetProperty(propertyName, out var value)
            && value.ValueKind == JsonValueKind.String
            && value.GetString() is { } text)
        {
            return text;
        }
        throw new OperatorProtocolException(shapeName, $"field:{propertyName}");
    }

    private static ulong RequiredUInt64(JsonElement parent, string propertyName, string shapeName)
    {
        if (parent.ValueKind == JsonValueKind.Object
            && parent.TryGetProperty(propertyName, out var value)
            && value.ValueKind == JsonValueKind.Number
            && value.TryGetUInt64(out var number))
        {
            return number;
        }
        throw new OperatorProtocolException(shapeName, $"field:{propertyName}");
    }

    private static int RequiredInt32(JsonElement parent, string propertyName, string shapeName)
    {
        if (parent.ValueKind == JsonValueKind.Object
            && parent.TryGetProperty(propertyName, out var value)
            && value.ValueKind == JsonValueKind.Number
            && value.TryGetInt32(out var number))
        {
            return number;
        }
        throw new OperatorProtocolException(shapeName, $"field:{propertyName}");
    }

    private static bool CapabilitiesMatch(
        JsonElement parent,
        IReadOnlyList<string> expected,
        string shapeName)
    {
        if (!parent.TryGetProperty("capabilities", out var value)
            || value.ValueKind != JsonValueKind.Array)
        {
            throw new OperatorProtocolException(shapeName, "field:capabilities");
        }
        var capabilities = new List<string>();
        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || item.GetString() is not { } capability)
            {
                throw new OperatorProtocolException(shapeName, "field:capabilities");
            }
            capabilities.Add(capability);
        }
        return capabilities.SequenceEqual(expected, StringComparer.Ordinal);
    }

    private static void RequireBoundedText(string value, string shapeName, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > OperatorProtocol.MaxControlStringChars
            || value.Any(char.IsControl))
        {
            throw new OperatorProtocolException(shapeName, $"field:{fieldName}");
        }
    }
}

/// The authenticated binding this process holds on one bound broker pipe: the
/// handle the broker proved the OS-observed peer identity on, plus the framing
/// that handle carries. Holding the session rather than the authority is the
/// point - the grant itself stays in the broker, so retaining this object
/// grants nothing that a fresh challenge/redeem exchange would not also grant.
///
/// Disposal is deterministic and idempotent: it closes the pipe and is the
/// only way the hold ends, so the session's end and explicit invalidation both
/// release the handle exactly once. It never propagates a close failure. Every
/// request line was already flushed by the writer's AutoFlush and nothing is
/// read from here on, so a failure while releasing is not a lost request and
/// must not escape into whoever ends the session - and above all must not
/// escape into the redemption that published this handle, where it would tear
/// down the freshly proven binding instead of the spent one.
internal sealed class BrokerPipeSession : IDisposable
{
    private readonly NamedPipeClientStream _pipe;
    private readonly StreamReader _reader;
    private readonly StreamWriter _writer;
    private int _disposed;

    internal BrokerPipeSession(NamedPipeClientStream pipe, StreamReader reader, StreamWriter writer)
    {
        _pipe = pipe;
        _reader = reader;
        _writer = writer;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        try
        {
            _reader.Dispose();
        }
        catch (Exception)
        {
            // Release continues: the pipe close below is what ends the hold.
        }

        try
        {
            _writer.Dispose();
        }
        catch (Exception)
        {
            // As above.
        }

        try
        {
            _pipe.Dispose();
        }
        catch (Exception)
        {
            // As above.
        }
    }
}
