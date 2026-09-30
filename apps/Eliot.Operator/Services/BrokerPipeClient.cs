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
/// The redeemed CONNECTION is RETURNED, never discarded: the broker keeps
/// serving that same authenticated pipe after redemption, so the one
/// state-changing request it will still accept rides on this exact transport
/// rather than on a second connection that would have to prove the same
/// binding again. The connection and the authority it carries are owned by
/// the caller's session lifecycle and are released with it — never kept for
/// the process lifetime.
///
/// The redeemed binding is never stored here: the broker-issued Kernel
/// session token lives only in the caller's process memory, bound to the
/// connection the redemption vouched for, and is discarded with it. It is
/// never written to a file, an envelope, a log or a banner, so a UI restart
/// creates a new operational binding and never revives authority from cached
/// application state (I11.8).
internal static class BrokerPipeClient
{
    private const string Preface = "ELIOT-BROKER-1\n";

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

    /// The closed member set of the broker's cancellation receipt. The broker
    /// answers the third request with the same receipt stdin renders, so the
    /// receipt payload is an owner `Value` and is bounded as an already
    /// validated frame rather than decoded into a second projection here.
    private static readonly string[] CancelledProperties = ["status", "receipt"];

    /// The broker-ADMITTED Human binding one redemption vouched for: the
    /// principal, session, process, Kernel session token, role and exact
    /// capability set the broker echoed on its authenticated pipe, each proved
    /// equal to the owner-issued handoff and the live process identity before
    /// this record is built.
    ///
    /// The principal is the broker's own echo of the OS-observed pipe peer
    /// (`peer.sid()` on the broker side), never a self-declared string
    /// (A12.2): the redemption checks below prove it equal to this process's
    /// observed SID before it is retained. The token is opaque process memory:
    /// it is compared by exact ordinal equality only, never recomputed,
    /// never logged, and never placed in an envelope, a file or a banner.
    public sealed record RedeemedOperatorBinding(
        string Principal,
        string InteractiveSessionId,
        int ClientProcessId,
        string KernelSessionToken,
        OperatorRoleBinding Grant,
        ulong BrokerEpoch)
    {
        public void Validate()
        {
            OperatorIdentityFields.RequireText(Principal, "principal");
            OperatorIdentityFields.RequireText(InteractiveSessionId, "interactive_session_id");
            if (ClientProcessId <= 0)
            {
                throw new InvalidOperationException("Redeemed binding client_process_id must be a positive process id.");
            }
            OperatorIdentityFields.RequireText(KernelSessionToken, "kernel_session_token");
            ArgumentNullException.ThrowIfNull(Grant);
            OperatorIdentityFields.RequireText(Grant.Role, "role");
            foreach (var capability in Grant.Capabilities)
            {
                OperatorIdentityFields.RequireText(capability, "capabilities");
            }
        }

        /// Proves this binding still describes the given live process
        /// identity. A process cannot change its SID, logon session or PID,
        /// so a mismatch means the retained authority belongs to another
        /// binding and must be discarded, never honoured.
        public bool DescribesProcess(OperatorProcessIdentity current, int processId) =>
            string.Equals(Principal, current.UserSid, StringComparison.Ordinal)
            && string.Equals(
                InteractiveSessionId,
                current.LogonSessionId.ToString(CultureInfo.InvariantCulture),
                StringComparison.Ordinal)
            && ClientProcessId == processId;
    }

    /// One redeemed User Broker connection and the Human binding admitted on
    /// it, held together so the two can never be separated.
    ///
    /// The connection is a RESOURCE and this type is its whole owner: it holds
    /// the pipe, the framed reader and the framed writer, and `Dispose` closes
    /// the pipe before the streams so a pending write cannot outlive the
    /// handle. Disposal is idempotent, so the many sites that end a session
    /// (a proven binding loss, an aborted transport, a replacement
    /// establishment, client disposal) may all release it without racing on
    /// which one got there first.
    ///
    /// LIFETIME. It is deliberately bounded on both ends rather than held for
    /// the process lifetime. It is created by exactly one redemption and
    /// released with the session it was redeemed for, so repeated redemptions
    /// cannot accumulate pipe handles. It is also single-use after a
    /// state-change request: the broker serves one `cancel` on this connection
    /// and then closes, so the request path releases it as soon as the broker
    /// has answered and a later request is refused rather than written to a
    /// dead pipe. The broker's own handoff window bounds it from the other
    /// side — the owner stops serving this pipe at the end of that window
    /// whether or not the client asked for anything.
    ///
    /// It is never logged, never placed in an envelope, a file or a banner,
    /// and never survives the session it was admitted under, so a UI restart
    /// creates a new operational binding and revives nothing (I11.8).
    public sealed class RedeemedOperatorConnection : IDisposable
    {
        private readonly NamedPipeClientStream _pipe;
        private readonly StreamReader _reader;
        private readonly StreamWriter _writer;
        private int _disposed;

        internal RedeemedOperatorConnection(
            NamedPipeClientStream pipe,
            StreamReader reader,
            StreamWriter writer,
            RedeemedOperatorBinding binding)
        {
            _pipe = pipe;
            _reader = reader;
            _writer = writer;
            Binding = binding;
        }

        /// The broker-admitted Human authority this exact connection was
        /// redeemed for. It is readable while the connection lives and is
        /// released with it, never copied out and kept.
        public RedeemedOperatorBinding Binding { get; }

        /// Sends the ONE state-changing request a redeemed connection may
        /// still make — the delegated-Operator cancel — on this connection,
        /// carrying the admitted Human authority built from the binding the
        /// broker vouched for on this pipe.
        ///
        /// The authority is not caller-chosen. Principal, session, role,
        /// capability set and Kernel session token are read from `Binding`,
        /// which was proved equal to this process's observed identity at
        /// redemption; only the approval hash is passed in, because it is the
        /// one field no local observation can produce. The broker admits the
        /// whole record through its existing `admit_human_state_change` against
        /// the OS-observed pipe peer, so the request still succeeds only
        /// through the typed Kernel path.
        ///
        /// The connection is released once the broker has answered, on every
        /// outcome: the owner serves this leg once and closes, so a retained
        /// handle past this point is a leak rather than a reusable session.
        ///
        /// A broker `error` answer arrives as this client's existing
        /// restart-required disposition, which is this file's own stated rule
        /// rather than a new one: the owner closes the pipe after its one
        /// state-changing leg, so the authority this connection carried is
        /// gone with it and only a fresh owner-issued handoff can restore one.
        /// The refusal is not softened into "not attempted" — the request did
        /// reach the broker and was decided there.
        public async Task<JsonElement> CancelBrokerOperationAsync(
            string operationId,
            string approvalHash,
            CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(
                Volatile.Read(ref _disposed) != 0,
                this);
            OperatorIdentityFields.RequireText(operationId, "operation_id");
            OperatorIdentityFields.RequireText(approvalHash, "approval_hash");
            // Every authority field below comes from the binding this exact
            // connection was redeemed for, never from the caller: a caller that
            // could name its own principal, role or capability set would make
            // the broker's own binding check advisory instead of authoritative.
            var authority = new
            {
                principal = Binding.Principal,
                interactive_session_id = Binding.InteractiveSessionId,
                role = Binding.Grant.Role,
                capabilities = Binding.Grant.Capabilities,
                approval_hash = approvalHash,
                kernel_session_token = Binding.KernelSessionToken
            };
            try
            {
                await WriteRequestAsync(_writer, new
                {
                    operation = "cancel",
                    operation_id = operationId,
                    authority
                }, cancellationToken).ConfigureAwait(false);
                using var cancelled = await ReadExpectedResponseAsync(
                    _reader,
                    "cancelled",
                    CancelledProperties,
                    "broker_cancel",
                    cancellationToken).ConfigureAwait(false);
                return cancelled.RootElement.Clone();
            }
            finally
            {
                // The owner's third leg is served once on this connection.
                // Whether it answered, refused or the pipe failed, the handle
                // is released here so no redemption leaves a live pipe behind.
                Dispose();
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            // The pipe closes first so a pending write unwinds; only then are
            // the framed streams released, so disposal cannot block on a flush
            // to a peer that already answered and closed.
            try
            {
                _pipe.Dispose();
            }
            catch (Exception)
            {
                // Teardown never replaces the request's own outcome.
            }
            try
            {
                _reader.Dispose();
            }
            catch (Exception)
            {
                // The peer is already gone.
            }
            try
            {
                _writer.Dispose();
            }
            catch (Exception)
            {
                // A broken pipe surfaces here only as a teardown limitation.
            }
        }
    }

    public static async Task<RedeemedOperatorConnection> RedeemOperatorHandoffAsync(
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

        // The connection outlives this method: the broker keeps serving this
        // same authenticated pipe after redemption, so its lifetime is the
        // caller's session, not this exchange. Ownership is therefore
        // TRANSFERRED into `RedeemedOperatorConnection` on the success path
        // and the locals are nulled there; the `finally` releases them on
        // every failure instead, so a refused redemption can never leave a
        // pipe handle behind.
        var pipe = new NamedPipeClientStream(
            ".",
            OwnerIssuedPipeName(endpoint),
            PipeDirection.InOut,
            PipeOptions.Asynchronous);
        StreamReader? reader = null;
        StreamWriter? writer = null;
        var retained = false;
        try
        {
            await pipe.ConnectAsync(cancellationToken).ConfigureAwait(false);

            await pipe.WriteAsync(Encoding.ASCII.GetBytes(Preface), cancellationToken).ConfigureAwait(false);
            reader = new StreamReader(
                pipe,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
                detectEncodingFromByteOrderMarks: false,
                bufferSize: 4096,
                leaveOpen: true);
            writer = new StreamWriter(
                pipe,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
                bufferSize: 4096,
                leaveOpen: true)
            {
                AutoFlush = true,
                NewLine = "\n"
            };

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

            // Every value below was proved equal to the broker's authenticated
            // echo above: the principal and session against the redeemed record,
            // the process id against it, the token against it, and the role and
            // exact capability set against it. The binding is therefore the
            // ADMITTED one, and the caller retains it in process memory only.
            // The capability list is copied, never aliased: `OperatorEndpoint.
            // Capabilities` is the client's authority material, so handing out
            // the aliased instance would let a holder rewrite what the binding
            // was admitted for.
            var binding = new RedeemedOperatorBinding(
                clientIdentity.UserSid,
                sessionId,
                processId,
                token,
                new OperatorRoleBinding(endpoint.Role, [.. endpoint.Capabilities]),
                endpoint.BrokerEpoch);
            binding.Validate();
            var connection = new RedeemedOperatorConnection(pipe, reader, writer, binding);
            // Ownership has moved into the connection. `retained` is what tells
            // the `finally` below that this transport is now the caller's to
            // release; without it the hand-off would immediately dispose the
            // pipe it just returned.
            retained = true;
            return connection;
        }
        finally
        {
            // Reached only when no connection took ownership. The pipe is
            // closed before the streams so a pending write cannot outlive the
            // handle, and a redemption that never produced a connection leaves
            // nothing open.
            if (!retained)
            {
                pipe.Dispose();
                reader?.Dispose();
                writer?.Dispose();
            }
        }
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
            // The owner's own stable refusal code is carried on the fault
            // rather than folded into a handshake code: a broker that refuses
            // THIS request for THIS reason (an approval it will not accept, a
            // capability it never granted, a session token it no longer
            // honours) is a materially different fact for the Operator than a
            // refused handshake, and flattening the two would tell the
            // operator to restart for a condition a restart does not fix.
            // The owner's free-text `detail` stays unread: it is owner prose,
            // not a closed code, and must never reach a banner or a log.
            var code = RequiredString(root, "code", "broker_error");
            _ = RequiredString(root, "detail", "broker_error");
            throw new OperatorBrokerRefusedException(code);
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
