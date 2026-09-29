using System.Globalization;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Eliot.Operator.Protocol;

namespace Eliot.Operator.Services;

/// Validated, Kernel-issued redemption retained for the exact Governor
/// connection and forwarded without rewriting in its handshake.
internal sealed record OperatorBrokerRedemption(
    JsonElement WireValue,
    string KernelSessionToken,
    string Principal,
    string InteractiveSessionId,
    string HandoffNonce,
    string Role,
    IReadOnlyList<string> Capabilities,
    ulong ExpiresAt);

/// Redeems the inherited one-shot handoff with the User Broker before the
/// Governor connection is opened. The client has one fixed pipe, one
/// challenge/redeem exchange and no cached authority or retry path.
internal static class BrokerPipeClient
{
    private const string PipeName = @"eliot\user-broker\operator";
    private const string Preface = "ELIOT-BROKER-1\n";

    private static readonly string[] ChallengeProperties =
    [
        "status",
        "challenge",
        "broker_epoch",
        "handoff_nonce",
        "role",
        "capabilities"
    ];

    private static readonly string[] RedeemedProperties =
    [
        "status",
        "redemption"
    ];

    private static readonly string[] ChallengeGrantProperties =
    [
        "schema_version",
        "challenge_id",
        "challenge_token",
        "context_digest",
        "broker_registration_digest",
        "expires_at"
    ];

    private static readonly string[] BrokerRedemptionProperties =
    [
        "schema_version",
        "installation_id",
        "broker_registration_digest",
        "authority_epoch",
        "broker_epoch",
        "handoff_nonce",
        "principal",
        "interactive_session_id",
        "process_id",
        "process_start_time_100ns",
        "process_image_path",
        "executable_file_volume_serial_number",
        "executable_file_index",
        "approved_artifact_digest",
        "role",
        "capabilities",
        "challenge_id",
        "kernel_session_token",
        "expires_at"
    ];

    private static readonly string[] AuthorityEpochProperties = ["lineage_id", "sequence"];

    private static readonly string[] ErrorProperties = ["status", "code", "detail"];

    public static async Task<OperatorBrokerRedemption> RedeemOperatorHandoffAsync(
        OperatorEndpoint endpoint,
        OperatorProcessIdentity clientIdentity,
        DateTimeOffset endpointExpiresAtUtc,
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
            PipeName,
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
        var challengeGrant = RequiredObject(challenge.RootElement, "challenge", "broker_challenge");
        OperatorJsonGuard.ValidateClosedObject(
            challengeGrant.GetRawText(),
            ChallengeGrantProperties,
            OperatorProtocol.MaxControlMembers,
            OperatorProtocol.MaxControlStringChars,
            OperatorProtocol.MaxControlDepth,
            OperatorProtocol.MaxControlTokens,
            "broker_challenge_grant");
        if (RequiredUInt64(challengeGrant, "schema_version", "broker_challenge_grant") != 1)
        {
            throw new OperatorProtocolException("broker_challenge_grant", "schema_version");
        }
        var challengeId = RequiredString(challengeGrant, "challenge_id", "broker_challenge_grant");
        var token = RequiredString(challengeGrant, "challenge_token", "broker_challenge_grant");
        var contextDigest = RequiredString(challengeGrant, "context_digest", "broker_challenge_grant");
        var registrationDigest = RequiredString(
            challengeGrant,
            "broker_registration_digest",
            "broker_challenge_grant");
        var challengeExpiresAt = RequiredUInt64(challengeGrant, "expires_at", "broker_challenge_grant");
        RequireBoundedText(challengeId, "broker_challenge_grant", "challenge_id");
        RequireBoundedText(token, "broker_challenge_grant", "challenge_token");
        RequireSha256(contextDigest, "broker_challenge_grant", "context_digest");
        RequireSha256(registrationDigest, "broker_challenge_grant", "broker_registration_digest");
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var endpointExpiry = endpointExpiresAtUtc.ToUnixTimeMilliseconds();
        if (challengeExpiresAt <= (ulong)Math.Max(0, now)
            || endpointExpiry <= now
            || challengeExpiresAt > (ulong)endpointExpiry)
        {
            throw new OperatorHandoffRefusedException(
                OperatorHandoffInvalidation.Expired,
                endpoint.BrokerEpoch);
        }
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
                kernel_challenge_token = token
            }
        }, cancellationToken).ConfigureAwait(false);

        using var redeemed = await ReadExpectedResponseAsync(
            reader,
            "redeemed",
            RedeemedProperties,
            "broker_redeem",
            cancellationToken).ConfigureAwait(false);
        var redemption = RequiredObject(redeemed.RootElement, "redemption", "broker_redeem");
        OperatorJsonGuard.ValidateClosedObject(
            redemption.GetRawText(),
            BrokerRedemptionProperties,
            OperatorProtocol.MaxControlMembers,
            OperatorProtocol.MaxControlStringChars,
            OperatorProtocol.MaxControlDepth,
            OperatorProtocol.MaxControlTokens,
            "broker_redemption");
        var value = ValidateRedemption(
            redemption,
            endpoint,
            clientIdentity,
            processId,
            sessionId,
            challengeId);
        return new OperatorBrokerRedemption(
            value,
            RequiredString(value, "kernel_session_token", "broker_redemption"),
            RequiredString(value, "principal", "broker_redemption"),
            RequiredString(value, "interactive_session_id", "broker_redemption"),
            RequiredString(value, "handoff_nonce", "broker_redemption"),
            RequiredString(value, "role", "broker_redemption"),
            ReadCapabilities(value, "broker_redemption"),
            RequiredUInt64(value, "expires_at", "broker_redemption"));
    }

    private static bool ProcessGenerationMatches(string processGeneration, int processId)
    {
        return TryReadProcessGeneration(processGeneration, out var generationProcessId, out _)
            && generationProcessId == processId;
    }

    private static bool TryReadProcessGeneration(
        string processGeneration,
        out int processId,
        out ulong processStartTime100ns)
    {
        processId = 0;
        processStartTime100ns = 0;
        var separator = processGeneration.IndexOf(':');
        if (separator <= 0
            || !int.TryParse(
                processGeneration.AsSpan(0, separator),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out processId)
            || !long.TryParse(
                processGeneration.AsSpan(separator + 1),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var processStartTicks)
            || processStartTicks <= DateTimeToFileTimeEpochTicks)
        {
            processId = 0;
            return false;
        }
        processStartTime100ns = checked((ulong)(processStartTicks - DateTimeToFileTimeEpochTicks));
        return processStartTime100ns != 0;
    }

    private const long DateTimeToFileTimeEpochTicks = 504_911_232_000_000_000L;

    private static JsonElement ValidateRedemption(
        JsonElement redemption,
        OperatorEndpoint endpoint,
        OperatorProcessIdentity clientIdentity,
        int processId,
        string sessionId,
        string challengeId)
    {
        if (RequiredUInt64(redemption, "schema_version", "broker_redemption") != 1
            || RequiredUInt64(redemption, "broker_epoch", "broker_redemption") != endpoint.BrokerEpoch
            || !string.Equals(
                RequiredString(redemption, "handoff_nonce", "broker_redemption"),
                endpoint.HandoffNonce,
                StringComparison.Ordinal)
            || !string.Equals(
                RequiredString(redemption, "principal", "broker_redemption"),
                clientIdentity.UserSid,
                StringComparison.Ordinal)
            || !string.Equals(
                RequiredString(redemption, "interactive_session_id", "broker_redemption"),
                sessionId,
                StringComparison.Ordinal)
            || RequiredInt32(redemption, "process_id", "broker_redemption") != processId
            || !string.Equals(
                RequiredString(redemption, "role", "broker_redemption"),
                endpoint.Role,
                StringComparison.Ordinal)
            || !CapabilitiesMatch(redemption, endpoint.Capabilities, "broker_redemption")
            || !string.Equals(
                RequiredString(redemption, "challenge_id", "broker_redemption"),
                challengeId,
                StringComparison.Ordinal))
        {
            throw new OperatorHandoffRefusedException(
                OperatorHandoffInvalidation.SessionMismatch,
                endpoint.BrokerEpoch);
        }

        var currentGeneration = OperatorProcessIdentityProvider.Current.ProcessGeneration;
        if (!TryReadProcessGeneration(currentGeneration, out var currentPid, out var currentStartTime)
            || currentPid != processId
            || RequiredUInt64(redemption, "process_start_time_100ns", "broker_redemption") != currentStartTime)
        {
            throw new OperatorHandoffRefusedException(
                OperatorHandoffInvalidation.ProcessMismatch,
                endpoint.BrokerEpoch);
        }

        RequireBoundedText(
            RequiredString(redemption, "installation_id", "broker_redemption"),
            "broker_redemption",
            "installation_id");
        RequireSha256(
            RequiredString(redemption, "broker_registration_digest", "broker_redemption"),
            "broker_redemption",
            "broker_registration_digest");
        RequireSha256(
            RequiredString(redemption, "approved_artifact_digest", "broker_redemption"),
            "broker_redemption",
            "approved_artifact_digest");
        RequireBoundedText(
            RequiredString(redemption, "kernel_session_token", "broker_redemption"),
            "broker_redemption",
            "kernel_session_token");
        RequireBoundedText(
            RequiredString(redemption, "process_image_path", "broker_redemption"),
            "broker_redemption",
            "process_image_path");
        var actualImage = Environment.ProcessPath;
        var claimedImage = RequiredString(redemption, "process_image_path", "broker_redemption");
        if (string.IsNullOrWhiteSpace(actualImage)
            || !string.Equals(
                Path.GetFullPath(actualImage),
                Path.GetFullPath(claimedImage),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new OperatorHandoffRefusedException(
                OperatorHandoffInvalidation.ProcessMismatch,
                endpoint.BrokerEpoch);
        }

        if (!redemption.TryGetProperty("authority_epoch", out var authorityEpoch)
            || authorityEpoch.ValueKind != JsonValueKind.Object
            || RequiredUInt64(redemption, "expires_at", "broker_redemption")
                <= (ulong)Math.Max(0, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()))
        {
            throw new OperatorProtocolException("broker_redemption", "authority_epoch_or_expiry");
        }
        OperatorJsonGuard.ValidateClosedObject(
            authorityEpoch.GetRawText(),
            AuthorityEpochProperties,
            OperatorProtocol.MaxControlMembers,
            OperatorProtocol.MaxControlStringChars,
            OperatorProtocol.MaxControlDepth,
            OperatorProtocol.MaxControlTokens,
            "broker_redemption_epoch");
        var lineageId = RequiredString(authorityEpoch, "lineage_id", "broker_redemption_epoch");
        if (!Guid.TryParseExact(lineageId, "D", out _)
            || !string.Equals(lineageId, lineageId.ToLowerInvariant(), StringComparison.Ordinal)
            || RequiredUInt64(authorityEpoch, "sequence", "broker_redemption_epoch") == 0)
        {
            throw new OperatorProtocolException("broker_redemption_epoch", "identity");
        }
        var volumeSerial = OptionalUInt64(
            redemption,
            "executable_file_volume_serial_number",
            "broker_redemption");
        var fileIndex = OptionalUInt64(redemption, "executable_file_index", "broker_redemption");
        if (volumeSerial.HasValue != fileIndex.HasValue
            || volumeSerial.GetValueOrDefault() > uint.MaxValue)
        {
            throw new OperatorProtocolException("broker_redemption", "executable_file_identity");
        }
        return redemption.Clone();
    }

    private static void RequireSha256(string value, string shapeName, string fieldName)
    {
        if (value.Length != 64
            || value.Any(character => !char.IsAsciiHexDigit(character) || char.IsUpper(character)))
        {
            throw new OperatorProtocolException(shapeName, $"field:{fieldName}");
        }
    }

    private static ulong? OptionalUInt64(JsonElement parent, string propertyName, string shapeName)
    {
        if (!parent.TryGetProperty(propertyName, out var value))
        {
            throw new OperatorProtocolException(shapeName, $"field:{propertyName}");
        }
        if (value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind == JsonValueKind.Number && value.TryGetUInt64(out var number)) return number;
        throw new OperatorProtocolException(shapeName, $"field:{propertyName}");
    }

    private static JsonElement RequiredObject(JsonElement parent, string propertyName, string shapeName)
    {
        if (parent.ValueKind == JsonValueKind.Object
            && parent.TryGetProperty(propertyName, out var value)
            && value.ValueKind == JsonValueKind.Object)
        {
            return value;
        }
        throw new OperatorProtocolException(shapeName, $"field:{propertyName}");
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
        var capabilities = ReadCapabilities(parent, shapeName);
        return capabilities.SequenceEqual(expected, StringComparer.Ordinal);
    }

    private static IReadOnlyList<string> ReadCapabilities(JsonElement parent, string shapeName)
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
            RequireBoundedText(capability, shapeName, "capabilities");
            capabilities.Add(capability);
        }
        return capabilities;
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
