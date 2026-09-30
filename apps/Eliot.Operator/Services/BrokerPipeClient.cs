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

    public static async Task RedeemOperatorHandoffAsync(
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

        using var pipe = new NamedPipeClientStream(
            ".",
            OwnerIssuedPipeName(endpoint),
            PipeDirection.InOut,
            PipeOptions.Asynchronous);
        await pipe.ConnectAsync(cancellationToken).ConfigureAwait(false);

        await pipe.WriteAsync(Encoding.ASCII.GetBytes(Preface), cancellationToken).ConfigureAwait(false);
        using var reader = new StreamReader(
            pipe,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
            detectEncodingFromByteOrderMarks: false,
            bufferSize: 4096,
            leaveOpen: true);
        using var writer = new StreamWriter(
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
