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
/// Handoff/reconnect rule: the broker handoff is single-use. It is bound to the
/// exact installation, user SID/logon Session, broker registration epoch,
/// Operator artifact fingerprint, Operator process generation, endpoint
/// generation, role/capability set and the owner's expiry, and it is consumed
/// before the connection is opened. A lost pipe invalidates it permanently:
/// the next attempt returns the typed restart-required disposition and never
/// re-presents the consumed nonce, the cached endpoint, the PID, the user or
/// the pipe name. Pipe loss during a mutation becomes the typed
/// unknown-outcome fault carrying the same operation identity for
/// reconciliation.
public sealed class GovernorPipeClient(RuntimeDiscoveryService discovery) : IGovernorClient, IAsyncDisposable
{
    // One closed profile for every surface: unknown members are refused rather
    // than ignored, depth is bounded, and the raw line is bounded before the
    // typed object is allocated.
    private static readonly JsonSerializerOptions Json = OperatorJson.Reader;
    private NamedPipeClientStream? _pipe;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private OperatorHandoff? _handoff;
    private long _requestId;
    private readonly SemaphoreSlim _requestGate = new(1, 1);
    private readonly StringBuilder _readAhead = new();

    public async Task<OperatorSnapshot> SnapshotAsync(string? projectId = null, string? taskId = null, CancellationToken cancellationToken = default)
    {
        var contract = await CallToolAsync<OperatorContractResponse>(
            LegacyOperatorAdapter.ToolContract, new { }, "read:contract", cancellationToken);
        RequireCurrentContract(contract);
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
        RequireBoundedPageRequest(request);
        await ValidateContractAsync(cancellationToken);
        var page = await CallToolAsync<OperatorProjectionPage>(
            LegacyOperatorAdapter.ToolQuery, request, "read:query", cancellationToken);
        // Retained containers are bounded before the page is handed to the UI.
        OperatorProjectionGuard.ValidatePage(page);
        return page;
    }

    private async Task ValidateContractAsync(CancellationToken cancellationToken)
    {
        var contract = await CallToolAsync<OperatorContractResponse>(
            LegacyOperatorAdapter.ToolContract,
            new { },
            "read:contract",
            cancellationToken);
        RequireCurrentContract(contract);
    }

    private static void RequireCurrentContract(OperatorContractResponse contract)
    {
        // The client pins the compatibility adapter's own schema and contract
        // hash, not a bare protocol constant, so an owner change cannot be
        // absorbed silently by this one admitted consumer.
        if (contract.SchemaVersion != LegacyOperatorAdapter.SchemaVersion
            || contract.IpcProtocolVersion != OperatorProtocol.IpcProtocolVersion
            || contract.ProtocolHash != LegacyOperatorAdapter.ContractHash)
        {
            throw new OperatorProtocolException("contract", "version_or_hash_mismatch");
        }
    }

    /// The page request is bounded locally: an unbounded page size or cursor
    /// never leaves the UI.
    private static void RequireBoundedPageRequest(OperatorQueryRequest request)
    {
        if (request.PageSize is < OperatorProtocol.MinPageSize or > OperatorProtocol.MaxPageSize)
        {
            throw new OperatorProtocolException("query_request", "page_size_cap");
        }
        RequireBoundedCursor(request.Cursor, "query_request");
        RequireBoundedCursor(request.SelectedRef, "query_request");
    }

    private static void RequireBoundedCursor(string? cursor, string shapeName)
    {
        if (cursor is null) return;
        if (cursor.Length > OperatorProtocol.MaxCursorChars || cursor.Any(char.IsControl))
        {
            throw new OperatorProtocolException(shapeName, "cursor_cap");
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
        if (!LegacyOperatorAdapter.IsAdmittedTool(tool))
        {
            // The compatibility adapter admits exactly its four pinned tools
            // plus the typed owner route. Anything else is refused before use.
            throw new OperatorProtocolException("tool", "unadmitted_tool");
        }
        await _requestGate.WaitAsync(cancellationToken);
        try
        {
            // Connection establishment and handshake failures happen before
            // this mutation/read request is written. They still cannot
            // compact a retained reconciliation entry: a fresh connection
            // refusal says nothing about the original effect. Convert every
            // known local/pre-send failure to the same typed recovery outcome
            // used after a possible send.
            try
            {
                await EnsureConnectedAsync(cancellationToken);
            }
            catch (OperatorRestartRequiredException)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception error)
            {
                throw new OperatorUnknownOutcomeException(
                    operationScope, tool, OperatorFaultReason.ForException(error));
            }
            var requestId = Interlocked.Increment(ref _requestId);
            try
            {
                var response = await RequestAsync<JsonRpcResponse<McpToolResult>>(new
                {
                    jsonrpc = "2.0",
                    id = requestId,
                    method = "tools/call",
                    @params = new { name = tool, arguments }
                }, cancellationToken);
                ValidateJsonRpcResponse(response, requestId);
                if (response.Error is not null)
                {
                    // A JSON-RPC error carries no owner-bound terminal receipt;
                    // the request may already have reached the mutation owner.
                    throw new OperatorUnknownOutcomeException(
                        operationScope, tool, OperatorFaultReason.OwnerErrorUnbound);
                }
                if (response.Result is null)
                {
                    throw new OperatorUnknownOutcomeException(
                        operationScope, tool, OperatorFaultReason.OwnerResultAbsent);
                }
                try
                {
                    return response.Result.StructuredContent.Deserialize<T>(Json)
                        ?? throw new OperatorUnknownOutcomeException(
                            operationScope, tool, OperatorFaultReason.OwnerResultUnreadable);
                }
                catch (JsonException)
                {
                    // The owner answered but the bytes prove nothing: the same
                    // operation must be reconciled, on the live connection.
                    throw new OperatorUnknownOutcomeException(
                        operationScope, tool, OperatorFaultReason.OwnerResultUnreadable);
                }
            }
            catch (OperatorUnknownOutcomeException)
            {
                await DisconnectAsync(OperatorHandoffInvalidation.PipeLost);
                throw;
            }
            catch (OperationCanceledException)
            {
                await DisconnectAsync(OperatorHandoffInvalidation.PipeLost);
                throw new OperatorUnknownOutcomeException(operationScope, tool, OperatorFaultReason.RequestTimeout);
            }
            catch (Exception error)
            {
                await DisconnectAsync(OperatorHandoffInvalidation.PipeLost);
                throw new OperatorUnknownOutcomeException(operationScope, tool, OperatorFaultReason.ForException(error));
            }
        }
        finally
        {
            _requestGate.Release();
        }
    }

    /// Opens the single authenticated connection bound to one consumed handoff.
    ///
    /// The handoff is validated against the exact current process identity and
    /// consumed before the pipe is opened, so a failed connect can never
    /// present the same nonce twice. The effective connect deadline is the
    /// handoff's own remaining lifetime: a handoff that cannot be consumed in
    /// time is refused rather than burned.
    private async Task EnsureConnectedAsync(CancellationToken cancellationToken)
    {
        // A live connection is reusable; the handoff that authenticated it is
        // not. Single use binds connection establishment, not request handling.
        if (_pipe?.IsConnected == true)
        {
            return;
        }
        OperatorHandoff handoff;
        try
        {
            handoff = await discovery.DiscoverAsync(cancellationToken);
            handoff.RequireBindingTo(OperatorProcessIdentityProvider.Current, DateTimeOffset.UtcNow);
        }
        catch (OperatorHandoffRefusedException)
        {
            await DisconnectAsync(OperatorHandoffInvalidation.ReconnectRequired);
            throw;
        }
        catch (RuntimeDiscoveryException)
        {
            await DisconnectAsync(OperatorHandoffInvalidation.ReconnectRequired);
            throw new OperatorRestartRequiredException(OperatorHandoff.ReacquisitionRequirement);
        }
        catch (OperatorProcessIdentityException)
        {
            await DisconnectAsync(OperatorHandoffInvalidation.ReconnectRequired);
            throw new OperatorRestartRequiredException(OperatorFaultReason.ProcessIdentityUnproven);
        }
        if (_pipe is not null)
        {
            await DisconnectAsync(OperatorHandoffInvalidation.ReconnectRequired);
        }
        _handoff = handoff;

        var remaining = handoff.RemainingLifetime(DateTimeOffset.UtcNow);
        if (remaining <= TimeSpan.Zero)
        {
            handoff.Invalidate(OperatorHandoffInvalidation.Expired);
            throw new OperatorRestartRequiredException(OperatorHandoff.ReacquisitionRequirement);
        }
        var connectBudget = remaining < TimeSpan.FromSeconds(OperatorProtocol.ConnectTimeoutSeconds)
            ? remaining
            : TimeSpan.FromSeconds(OperatorProtocol.ConnectTimeoutSeconds);
        var pipeName = handoff.Endpoint.PipeName.Replace(@"\\.\pipe\", string.Empty, StringComparison.OrdinalIgnoreCase);
        // Single use: the nonce is spent now, not after a successful connect.
        handoff.Consume(DateTimeOffset.UtcNow);
        _pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            using var connectWindow = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectWindow.CancelAfter(connectBudget);
            await _pipe.ConnectAsync(connectWindow.Token);
        }
        catch (Exception error) when (error is IOException or TimeoutException or OperationCanceledException)
        {
            await DisconnectAsync(OperatorHandoffInvalidation.PipeLost);
            throw new OperatorRestartRequiredException(
                $"{OperatorFaultReason.ConnectionRefused} at broker registration generation {handoff.BrokerRegistrationEpoch}");
        }
        _reader = new StreamReader(_pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
        _writer = new StreamWriter(_pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
        try
        {
            await _writer.WriteLineAsync(JsonSerializer.Serialize(new
            {
                kind = "eliot_ipc_handshake",
                protocol_version = OperatorProtocol.IpcProtocolVersion,
                broker_epoch = handoff.Endpoint.BrokerEpoch,
                interactive_session_id = handoff.Endpoint.InteractiveSessionId,
                handoff_nonce = handoff.Endpoint.HandoffNonce,
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
                throw new UnauthorizedAccessException(OperatorFaultReason.HandshakeRefused);
            }
            var initializeId = Interlocked.Increment(ref _requestId);
            var initialize = await RequestAsync<JsonRpcResponse<JsonElement>>(new
            {
                jsonrpc = "2.0",
                id = initializeId,
                method = "initialize",
                @params = new
                {
                    protocolVersion = "2025-06-18",
                    eliotProfile = "human_operator",
                    clientInfo = new { name = "Eliot.Operator", version = "0.1.0" },
                    capabilities = new { }
                }
            }, cancellationToken);
            ValidateJsonRpcResponse(initialize, initializeId);
            if (initialize.Error is not null || initialize.Result.ValueKind == JsonValueKind.Undefined)
            {
                throw new UnauthorizedAccessException(OperatorFaultReason.HandshakeRefused);
            }
        }
        catch (OperatorRestartRequiredException)
        {
            await DisconnectAsync(OperatorHandoffInvalidation.PipeLost);
            throw;
        }
        catch (OperationCanceledException)
        {
            await DisconnectAsync(OperatorHandoffInvalidation.PipeLost);
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            await DisconnectAsync(OperatorHandoffInvalidation.PipeLost);
            throw;
        }
        catch (Exception error) when (error is IOException or OperatorProtocolException or InvalidOperationException or JsonException)
        {
            await DisconnectAsync(OperatorHandoffInvalidation.PipeLost);
            throw new OperatorRestartRequiredException(
                $"{OperatorFaultReason.HandshakeShapeRefused} at broker registration generation {handoff.BrokerRegistrationEpoch}");
        }
    }

    /// Writes one framed request and reads one framed answer. The absolute
    /// per-request ceiling applies even when the caller supplies no
    /// cancellation token, so a silent owner cannot hold a request open.
    private async Task<T> RequestAsync<T>(object request, CancellationToken cancellationToken)
    {
        using var requestWindow = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        requestWindow.CancelAfter(TimeSpan.FromSeconds(OperatorProtocol.RequestTimeoutSeconds));
        try
        {
            await _writer!.WriteLineAsync(JsonSerializer.Serialize(request, Json));
            var response = await ReadBoundedLineAsync(requestWindow.Token)
                ?? throw new IOException("Governor closed the named pipe");
            if (Encoding.UTF8.GetByteCount(response) > OperatorProtocol.MaxDecodedBytes)
            {
                throw new OperatorProtocolException("response", "body_cap");
            }
            // Independent member/depth/token/string/item caps and duplicate-key
            // rejection run on the raw line before the typed object exists.
            OperatorResponseGuard.ValidateFramedResponse(response, "response");
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
        while (true)
        {
            var newlineIndex = FindNewline(_readAhead);
            if (newlineIndex >= 0)
            {
                if (newlineIndex > OperatorProtocol.MaxLineChars)
                {
                    throw new OperatorProtocolException("response", "line_cap");
                }
                var line = new StringBuilder(newlineIndex);
                for (var index = 0; index < newlineIndex; index++)
                {
                    var character = _readAhead[index];
                    if (character != '\r')
                    {
                        if (line.Length >= OperatorProtocol.MaxLineChars)
                        {
                            throw new OperatorProtocolException("response", "line_cap");
                        }
                        line.Append(character);
                    }
                }
                _readAhead.Remove(0, newlineIndex + 1);
                return line.ToString();
            }
            if (_readAhead.Length > OperatorProtocol.MaxLineChars)
            {
                throw new OperatorProtocolException("response", "line_cap");
            }
            var read = await reader.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                return _readAhead.Length == 0
                    ? null
                    : throw new IOException("Governor closed the pipe mid-line");
            }
            _readAhead.Append(buffer, 0, read);
        }
    }

    private static int FindNewline(StringBuilder buffer)
    {
        for (var index = 0; index < buffer.Length; index++)
        {
            if (buffer[index] == '\n') return index;
        }
        return -1;
    }

    private static void ValidateJsonRpcResponse<T>(JsonRpcResponse<T> response, long expectedRequestId)
    {
        if (!string.Equals(response.JsonRpc, "2.0", StringComparison.Ordinal)
            || response.Id is not JsonElement id
            || id.ValueKind != JsonValueKind.Number
            || !id.TryGetInt64(out var actualRequestId)
            || actualRequestId != expectedRequestId)
        {
            throw new OperatorProtocolException("json_rpc_response", "correlation");
        }
    }

    /// Drops the connection and permanently invalidates the handoff it used.
    /// The nonce, the endpoint and the pipe name are released together: nothing
    /// here can authenticate a later connection.
    private async Task DisconnectAsync(OperatorHandoffInvalidation invalidation)
    {
        var writer = _writer;
        var reader = _reader;
        var pipe = _pipe;
        var handoff = _handoff;
        _writer = null;
        _reader = null;
        _pipe = null;
        _handoff = null;
        _readAhead.Clear();
        handoff?.Invalidate(invalidation);
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
            await DisconnectAsync(OperatorHandoffInvalidation.ReconnectRequired);
        }
        finally
        {
            _requestGate.Release();
            _requestGate.Dispose();
        }
    }
}
