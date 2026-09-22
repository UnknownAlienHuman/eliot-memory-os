using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Eliot.Operator.Protocol;

namespace Eliot.Operator.Services;

/// Role-filtered Governor pipe client. This is the single admitted consumer
/// of the versioned [`LegacyOperatorAdapter`] wire path (`eliot_operator_*`
/// tools); reads migrate to the current ControlBoard/runtime-status owner and
/// mutations to the current typed Operator-intent owner as soon as the
/// Governor serves a current-owner route on this pipe (see
/// [`LegacyOperatorAdapter.ExpiryRemoval`]).
///
/// Handoff/reconnect rule: the one-shot broker endpoint is consumed once. A
/// lost pipe never loops on the consumed value and never infers continuity
/// from PID, pipe name, or cached state. Pipe loss during a mutation becomes
/// the typed unknown-outcome fault carrying the same operation identity for
/// reconciliation; pipe loss with no replacement handoff becomes the typed
/// restart-required disposition.
public sealed class GovernorPipeClient(RuntimeDiscoveryService discovery) : IGovernorClient, IAsyncDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        // Explicit, never wider than the framework default.
        MaxDepth = 64
    };
    private NamedPipeClientStream? _pipe;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private OperatorEndpoint? _endpoint;
    private long _requestId;
    private readonly SemaphoreSlim _requestGate = new(1, 1);

    public async Task<OperatorSnapshot> SnapshotAsync(string? projectId = null, string? taskId = null, CancellationToken cancellationToken = default)
    {
        var contract = await CallToolAsync<OperatorContractResponse>(
            LegacyOperatorAdapter.ToolContract, new { }, "read:contract", cancellationToken);
        if (contract.SchemaVersion != OperatorProtocol.SchemaVersion
            || contract.IpcProtocolVersion != OperatorProtocol.IpcProtocolVersion
            || contract.ProtocolHash != OperatorProtocol.PinnedContractHash)
        {
            throw new InvalidOperationException("Governor operator contract differs from the client-pinned version/hash");
        }
        return await CallToolAsync<OperatorSnapshot>(
            LegacyOperatorAdapter.ToolSnapshot,
            new { project_id = projectId, task_id = taskId },
            "read:snapshot",
            cancellationToken);
    }

    public async Task<JsonElement> CommandAsync(object commandEnvelope, CancellationToken cancellationToken = default)
    {
        var envelope = JsonSerializer.SerializeToElement(commandEnvelope, Json);
        var operationId = RequireOperationId(envelope);
        await ValidateContractAsync(cancellationToken);
        // One send; a lost response reconciles the same identity through
        // ReconcileAsync, never a second logical mutation.
        return await CallToolAsync<JsonElement>(LegacyOperatorAdapter.ToolCommand, envelope, operationId, cancellationToken);
    }

    public async Task<JsonElement> ReconcileAsync(JsonElement commandEnvelope, CancellationToken cancellationToken = default)
    {
        var operationId = RequireOperationId(commandEnvelope);
        await ValidateContractAsync(cancellationToken);
        // The exact retained envelope bytes travel again under the same
        // operation identity; only the transport correlation id is new.
        return await CallToolAsync<JsonElement>(LegacyOperatorAdapter.ToolCommand, commandEnvelope, operationId, cancellationToken);
    }

    public Task<JsonElement> UserAutomationAsync(
        UserAutomationOperation operation,
        CancellationToken cancellationToken = default)
    {
        var request = UserAutomationOperatorRequest.Create(operation);
        request.Validate();
        // Kernel/Host authenticates this route and supplies RequestMetadata,
        // principal, State Fence and OperationIdentity. Reusing the generic
        // task-scoped operator-command envelope would discard that contract.
        return CallToolAsync<JsonElement>(
            UserAutomationContract.Route, request, $"automation:{request.IdempotencyKey}", cancellationToken);
    }

    public async Task<OperatorProjectionPage> QueryAsync(
        OperatorQueryRequest request,
        CancellationToken cancellationToken = default)
    {
        await ValidateContractAsync(cancellationToken);
        return await CallToolAsync<OperatorProjectionPage>(LegacyOperatorAdapter.ToolQuery, request, "read:query", cancellationToken);
    }

    private async Task ValidateContractAsync(CancellationToken cancellationToken)
    {
        var contract = await CallToolAsync<OperatorContractResponse>(
            LegacyOperatorAdapter.ToolContract,
            new { },
            "read:contract",
            cancellationToken);
        if (contract.SchemaVersion != OperatorProtocol.SchemaVersion
            || contract.IpcProtocolVersion != OperatorProtocol.IpcProtocolVersion
            || contract.ProtocolHash != OperatorProtocol.PinnedContractHash)
        {
            throw new InvalidOperationException("Governor operator contract differs from the client-pinned version/hash");
        }
    }

    private static string RequireOperationId(JsonElement envelope)
    {
        if (envelope.ValueKind == JsonValueKind.Object
            && envelope.TryGetProperty("idempotency_key", out var key)
            && key.ValueKind == JsonValueKind.String
            && !string.IsNullOrWhiteSpace(key.GetString()))
        {
            return key.GetString()!;
        }
        throw new ArgumentException(
            "Operator mutation commands require one retained idempotency_key; retries reuse the same identity.",
            nameof(envelope));
    }

    private async Task<T> CallToolAsync<T>(string tool, object arguments, string operationScope, CancellationToken cancellationToken)
    {
        await _requestGate.WaitAsync(cancellationToken);
        try
        {
            try
            {
                await EnsureConnectedAsync(cancellationToken);
                var response = await RequestAsync<JsonRpcResponse<McpToolResult>>(new
                {
                    jsonrpc = "2.0",
                    id = Interlocked.Increment(ref _requestId),
                    method = "tools/call",
                    @params = new { name = tool, arguments }
                }, cancellationToken);
                if (response.Error is not null || response.Result is null)
                {
                    // The owner explicitly refused: terminal answer, never an
                    // unknown outcome and never a silent retry.
                    throw new InvalidOperationException($"Governor rejected operator tool {tool}");
                }
                try
                {
                    return response.Result.StructuredContent.Deserialize<T>(Json)
                        ?? throw new OperatorUnknownOutcomeException(
                            operationScope, tool, "owner answer was empty and unproven");
                }
                catch (JsonException error)
                {
                    // The owner answered but the bytes prove nothing: the same
                    // operation must be reconciled, on the live connection.
                    throw new OperatorUnknownOutcomeException(operationScope, tool, error.Message);
                }
            }
            catch (IOException error)
            {
                await DisconnectAsync();
                throw new OperatorUnknownOutcomeException(operationScope, tool, error.Message);
            }
        }
        finally
        {
            _requestGate.Release();
        }
    }

    private async Task EnsureConnectedAsync(CancellationToken cancellationToken)
    {
        if (_pipe?.IsConnected == true && _endpoint is not null)
        {
            return;
        }
        OperatorEndpoint activeRuntime;
        try
        {
            activeRuntime = await discovery.DiscoverAsync(cancellationToken);
        }
        catch (RuntimeDiscoveryException error) when (error.Code == "endpoint_missing")
        {
            throw new OperatorRestartRequiredException(
                "one-shot broker handoff is consumed and no replacement handoff is available in-process");
        }
        if (_pipe is not null)
        {
            await DisconnectAsync();
        }
        _endpoint = activeRuntime;
        var pipeName = _endpoint.PipeName.Replace(@"\\.\pipe\", string.Empty, StringComparison.OrdinalIgnoreCase);
        _pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await _pipe.ConnectAsync(TimeSpan.FromSeconds(OperatorProtocol.ConnectTimeoutSeconds), cancellationToken);
        }
        catch (Exception error) when (error is IOException or TimeoutException or OperationCanceledException)
        {
            await DisconnectAsync();
            throw new OperatorRestartRequiredException($"Governor pipe is unreachable: {error.GetType().Name}");
        }
        _reader = new StreamReader(_pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
        _writer = new StreamWriter(_pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
        try
        {
            await _writer.WriteLineAsync(JsonSerializer.Serialize(new
            {
                kind = "eliot_ipc_handshake",
                protocol_version = OperatorProtocol.IpcProtocolVersion,
                broker_epoch = _endpoint.BrokerEpoch,
                interactive_session_id = _endpoint.InteractiveSessionId,
                handoff_nonce = _endpoint.HandoffNonce,
                client_nonce = Guid.NewGuid().ToString("N"),
                profile = "human_operator",
                requested_session_id = (string?)null
            }, Json));
            var handshakeLine = await ReadBoundedLineAsync(cancellationToken)
                ?? throw new IOException("Governor closed the pipe during handshake");
            OperatorJsonGuard.ValidateFramedLine(
                handshakeLine,
                OperatorProtocol.MaxControlMembers,
                OperatorProtocol.MaxControlStringChars,
                OperatorProtocol.MaxControlDepth,
                OperatorProtocol.MaxControlTokens,
                "handshake");
            using var handshake = JsonDocument.Parse(handshakeLine);
            if (!handshake.RootElement.TryGetProperty("accepted", out var accepted)
                || accepted.ValueKind != JsonValueKind.True && accepted.ValueKind != JsonValueKind.False
                || !accepted.GetBoolean())
            {
                throw new UnauthorizedAccessException("Governor rejected the operator handshake");
            }
            var initialize = await RequestAsync<JsonRpcResponse<JsonElement>>(new
            {
                jsonrpc = "2.0",
                id = Interlocked.Increment(ref _requestId),
                method = "initialize",
                @params = new
                {
                    protocolVersion = "2025-06-18",
                    eliotProfile = "human_operator",
                    clientInfo = new { name = "Eliot.Operator", version = "0.1.0" },
                    capabilities = new { }
                }
            }, cancellationToken);
            if (initialize.Error is not null || initialize.Result.ValueKind == JsonValueKind.Undefined)
            {
                throw new UnauthorizedAccessException("Governor rejected operator initialization");
            }
        }
        catch (OperatorRestartRequiredException)
        {
            await DisconnectAsync();
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            await DisconnectAsync();
            throw;
        }
        catch (Exception error) when (error is IOException or OperatorProtocolException or InvalidOperationException or JsonException)
        {
            await DisconnectAsync();
            throw new OperatorRestartRequiredException($"operator handshake failed closed: {error.GetType().Name}");
        }
    }

    private async Task<T> RequestAsync<T>(object request, CancellationToken cancellationToken)
    {
        try
        {
            await _writer!.WriteLineAsync(JsonSerializer.Serialize(request, Json));
            var response = await ReadBoundedLineAsync(cancellationToken)
                ?? throw new IOException("Governor closed the named pipe");
            if (Encoding.UTF8.GetByteCount(response) > OperatorProtocol.MaxDecodedBytes)
            {
                throw new OperatorProtocolException("response", "body_cap");
            }
            return JsonSerializer.Deserialize<T>(response, Json)
                ?? throw new InvalidOperationException("Governor returned an unreadable response");
        }
        catch (InvalidOperationException error) when (
            _pipe?.IsConnected != true
            || error.Message.Contains("pipe is broken", StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("Governor named pipe is no longer connected", error);
        }
    }

    /// Reads one framed line enforcing the inline ceiling before allocation
    /// completes: over-ceiling input fails closed and is never truncated into
    /// a valid object. Returns null only on a clean end-of-stream.
    private async Task<string?> ReadBoundedLineAsync(CancellationToken cancellationToken)
    {
        var reader = _reader ?? throw new IOException("Governor pipe reader is not connected");
        var buffer = new char[4096];
        var line = new StringBuilder();
        while (true)
        {
            var read = await reader.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                return line.Length == 0 ? null : throw new IOException("Governor closed the pipe mid-line");
            }
            for (var index = 0; index < read; index++)
            {
                var character = buffer[index];
                if (character == '\n')
                {
                    return line.ToString();
                }
                if (character != '\r')
                {
                    if (line.Length >= OperatorProtocol.MaxLineChars)
                    {
                        throw new OperatorProtocolException("response", "line_cap");
                    }
                    line.Append(character);
                }
            }
        }
    }

    private async Task DisconnectAsync()
    {
        var writer = _writer;
        var reader = _reader;
        var pipe = _pipe;
        _writer = null;
        _reader = null;
        _pipe = null;
        _endpoint = null;
        try
        {
            if (writer is not null) await writer.DisposeAsync();
        }
        catch (IOException)
        {
            // The peer is already gone; cleanup must not mask the reconnect attempt.
        }
        catch (InvalidOperationException)
        {
            // StreamWriter may surface a broken pipe as InvalidOperationException on dispose.
        }
        reader?.Dispose();
        pipe?.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        await _requestGate.WaitAsync();
        try
        {
            await DisconnectAsync();
        }
        finally
        {
            _requestGate.Release();
            _requestGate.Dispose();
        }
    }
}
