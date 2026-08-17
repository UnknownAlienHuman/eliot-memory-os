using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Eliot.Operator.Protocol;

namespace Eliot.Operator.Services;

public sealed class GovernorPipeClient(RuntimeDiscoveryService discovery) : IGovernorClient, IAsyncDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private NamedPipeClientStream? _pipe;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private OperatorEndpoint? _endpoint;
    private long _requestId;
    private readonly SemaphoreSlim _requestGate = new(1, 1);

    public async Task<OperatorSnapshot> SnapshotAsync(string? projectId = null, string? taskId = null, CancellationToken cancellationToken = default)
    {
        var contract = await CallToolAsync<OperatorContractResponse>("eliot_operator_contract", new { }, cancellationToken);
        if (contract.SchemaVersion != OperatorProtocol.SchemaVersion
            || contract.IpcProtocolVersion != OperatorProtocol.IpcProtocolVersion
            || contract.ProtocolHash != OperatorProtocol.PinnedContractHash)
        {
            throw new InvalidOperationException("Governor operator contract differs from the client-pinned version/hash");
        }
        return await CallToolAsync<OperatorSnapshot>(
            "eliot_operator_snapshot",
            new { project_id = projectId, task_id = taskId },
            cancellationToken);
    }

    public async Task<JsonElement> CommandAsync(object commandEnvelope, CancellationToken cancellationToken = default)
    {
        var envelope = JsonSerializer.SerializeToElement(commandEnvelope, Json);
        if (!envelope.TryGetProperty("idempotency_key", out var key)
            || key.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(key.GetString()))
        {
            throw new ArgumentException(
                "Operator mutation commands require one client-generated idempotency_key.",
                nameof(commandEnvelope));
        }
        await ValidateContractAsync(cancellationToken);
        // CallToolAsync reuses this exact serialized envelope across its reconnect retry, so
        // a lost response cannot create a second logical mutation.
        return await CallToolAsync<JsonElement>("eliot_operator_command", envelope, cancellationToken);
    }

    public async Task<OperatorProjectionPage> QueryAsync(
        OperatorQueryRequest request,
        CancellationToken cancellationToken = default)
    {
        await ValidateContractAsync(cancellationToken);
        return await CallToolAsync<OperatorProjectionPage>("eliot_operator_query", request, cancellationToken);
    }

    private async Task ValidateContractAsync(CancellationToken cancellationToken)
    {
        var contract = await CallToolAsync<OperatorContractResponse>(
            "eliot_operator_contract",
            new { },
            cancellationToken);
        if (contract.SchemaVersion != OperatorProtocol.SchemaVersion
            || contract.IpcProtocolVersion != OperatorProtocol.IpcProtocolVersion
            || contract.ProtocolHash != OperatorProtocol.PinnedContractHash)
        {
            throw new InvalidOperationException("Governor operator contract differs from the client-pinned version/hash");
        }
    }

    private async Task<T> CallToolAsync<T>(string tool, object arguments, CancellationToken cancellationToken)
    {
        await _requestGate.WaitAsync(cancellationToken);
        try
        {
            for (var attempt = 0; attempt < 2; attempt++)
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
                        throw new InvalidOperationException($"Governor rejected operator tool {tool}");
                    }
                    return response.Result.StructuredContent.Deserialize<T>(Json)
                        ?? throw new InvalidOperationException($"Governor returned an empty {tool} result");
                }
                catch (Exception error) when (
                    attempt == 0
                    && error is IOException or UnauthorizedAccessException or RuntimeDiscoveryException)
                {
                    await DisconnectAsync();
                }
            }
            throw new IOException("Governor named-pipe reconnect failed");
        }
        finally
        {
            _requestGate.Release();
        }
    }

    private async Task EnsureConnectedAsync(CancellationToken cancellationToken)
    {
        var activeRuntime = await discovery.DiscoverAsync(cancellationToken);
        if (_pipe?.IsConnected == true
            && _endpoint?.BrokerEpoch == activeRuntime.BrokerEpoch
            && _endpoint.InteractiveSessionId == activeRuntime.InteractiveSessionId
            && _endpoint.HandoffNonce == activeRuntime.HandoffNonce)
        {
            return;
        }
        if (_pipe is not null)
        {
            await DisconnectAsync();
        }
        _endpoint = activeRuntime;
        var pipeName = _endpoint.PipeName.Replace(@"\\.\pipe\", string.Empty, StringComparison.OrdinalIgnoreCase);
        _pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await _pipe.ConnectAsync(TimeSpan.FromSeconds(10), cancellationToken);
        _reader = new StreamReader(_pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
        _writer = new StreamWriter(_pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
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
        var handshakeLine = await _reader.ReadLineAsync(cancellationToken)
            ?? throw new IOException("Governor closed the pipe during handshake");
        using var handshake = JsonDocument.Parse(handshakeLine);
        if (!handshake.RootElement.GetProperty("accepted").GetBoolean())
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

    private async Task<T> RequestAsync<T>(object request, CancellationToken cancellationToken)
    {
        try
        {
            await _writer!.WriteLineAsync(JsonSerializer.Serialize(request, Json));
            var response = await _reader!.ReadLineAsync(cancellationToken)
                ?? throw new IOException("Governor closed the named pipe");
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
