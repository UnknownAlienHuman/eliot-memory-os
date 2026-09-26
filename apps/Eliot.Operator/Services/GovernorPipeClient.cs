using System.Diagnostics;
using System.Globalization;
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
///
/// Deadline rule: ONE caller-operation budget is created before queue waiting
/// and is carried, not restarted, through queue acquisition, discovery,
/// connection, handshake, initialization/contract checks and the application
/// exchange. A nested exchange consumes the same budget, so contract
/// negotiation plus the application call can never nest a fresh full timeout.
/// Local elapsed time is monotonic; the owner's wall-clock handoff expiry is
/// evaluated once at establishment and converted into the remaining allowance
/// without extending it. Teardown is bounded by a separate, finite and
/// explicitly accounted [`TeardownAllowanceSeconds`], so no indefinite
/// cleanup is hidden outside the advertised bound: the whole caller operation
/// is bounded by `OperatorProtocol.RequestTimeoutSeconds` plus that allowance.
/// The owner-issued handoff TTL bounds ESTABLISHMENT only. Once establishment
/// succeeded, the request budget and the serving owner's actual session and
/// revocation rules govern later authorized requests; the spent nonce's
/// historical five second lifetime never expires an established session.
public sealed class GovernorPipeClient(RuntimeDiscoveryService discovery) : IGovernorClient, IAsyncDisposable
{
    // One closed profile for every surface: unknown members are refused rather
    // than ignored, depth is bounded, and the raw line is bounded before the
    // typed object is allocated.
    private static readonly JsonSerializerOptions Json = OperatorJson.Reader;

    /// Finite, explicitly accounted local teardown allowance. It covers
    /// transport abort, reader/writer completion observation and the disposal
    /// gate wait, so a blocked write or flush can never prevent its own
    /// cleanup or a later request. It is a local UI-lifetime allowance, not a
    /// protocol constant: no wire value, framing rule or declared limit in
    /// [`OperatorProtocol`] changes because of it. A caller operation is
    /// therefore bounded by `OperatorProtocol.RequestTimeoutSeconds` plus this
    /// allowance, and nothing else.
    public const int TeardownAllowanceSeconds = 5;

    private const int LifecycleOpen = 0;
    private const int LifecycleClosing = 1;
    private const int LifecycleDisposed = 2;

    private GovernorConnection? _connection;
    private long _requestId;
    private readonly SemaphoreSlim _requestGate = new(1, 1);
    // Cancelled once, at the closing lifecycle transition, and deliberately
    // never disposed: every in-flight budget holds a linked source registered
    // on it, so disposing it here would break the very wakes this transition
    // depends on. It owns no unmanaged handle on this path because
    // `AvailableWaitHandle` is never used.
    private readonly CancellationTokenSource _closing = new();
    // Roots the cleanup completions that are still unwinding, so an unfinished
    // writer disposal stays observed instead of being forgotten.
    private readonly object _retainedGate = new();
    private readonly List<Task> _retainedCompletions = [];
    private int _lifecycle = LifecycleOpen;
    private int _gateHolders;

    public async Task<OperatorSnapshot> SnapshotAsync(string? projectId = null, string? taskId = null, CancellationToken cancellationToken = default)
    {
        using var budget = new OperationBudget("read:snapshot", cancellationToken, _closing.Token);
        var contract = await CallToolAsync<OperatorContractResponse>(
            LegacyOperatorAdapter.ToolContract, new { }, "read:contract", budget).ConfigureAwait(false);
        RequireCurrentContract(contract);
        return await CallToolAsync<OperatorSnapshot>(
            LegacyOperatorAdapter.ToolSnapshot,
            new { project_id = projectId, task_id = taskId },
            "read:snapshot",
            budget).ConfigureAwait(false);
    }

    public async Task<JsonElement> CommandAsync(object commandEnvelope, CancellationToken cancellationToken = default)
    {
        using var budget = new OperationBudget("command", cancellationToken, _closing.Token);
        var envelope = JsonSerializer.SerializeToElement(commandEnvelope, Json);
        var operationId = RequireOperationId(envelope);
        await ValidateContractAsync(budget).ConfigureAwait(false);
        // One send; a lost response reconciles the same identity through
        // ReconcileAsync, never a second logical mutation.
        return await CallToolAsync<JsonElement>(LegacyOperatorAdapter.ToolCommand, envelope, operationId, budget).ConfigureAwait(false);
    }

    public async Task<JsonElement> ReconcileAsync(JsonElement commandEnvelope, CancellationToken cancellationToken = default)
    {
        using var budget = new OperationBudget("reconcile", cancellationToken, _closing.Token);
        var operationId = RequireOperationId(commandEnvelope);
        await ValidateContractAsync(budget).ConfigureAwait(false);
        // The exact retained envelope bytes travel again under the same
        // operation identity; only the transport correlation id is new.
        return await CallToolAsync<JsonElement>(LegacyOperatorAdapter.ToolCommand, commandEnvelope, operationId, budget).ConfigureAwait(false);
    }

    public async Task<JsonElement> UserAutomationAsync(
        UserAutomationOperatorRequest request,
        CancellationToken cancellationToken = default)
    {
        // The caller supplies the one prepared request, so the transmitted
        // identity is the retained identity. Only its shape is checked here:
        // re-deriving the key would rewrite a pending request's identity to
        // match today's serializer instead of honouring the retained one.
        request.Validate();
        using var budget = new OperationBudget($"automation:{request.IdempotencyKey}", cancellationToken, _closing.Token);
        // Kernel/Host authenticates this route and supplies RequestMetadata,
        // principal, State Fence and OperationIdentity. Reusing the generic
        // task-scoped operator-command envelope would discard that contract.
        return await CallToolAsync<JsonElement>(
            UserAutomationContract.Route, request, $"automation:{request.IdempotencyKey}", budget).ConfigureAwait(false);
    }

    public async Task<OperatorProjectionPage> QueryAsync(
        OperatorQueryRequest request,
        CancellationToken cancellationToken = default)
    {
        using var budget = new OperationBudget("read:query", cancellationToken, _closing.Token);
        RequireBoundedPageRequest(request);
        await ValidateContractAsync(budget).ConfigureAwait(false);
        var page = await CallToolAsync<OperatorProjectionPage>(
            LegacyOperatorAdapter.ToolQuery, request, "read:query", budget).ConfigureAwait(false);
        // Retained containers are bounded before the page is handed to the UI.
        OperatorProjectionGuard.ValidatePage(page);
        return page;
    }

    private async Task ValidateContractAsync(OperationBudget budget)
    {
        var contract = await CallToolAsync<OperatorContractResponse>(
            LegacyOperatorAdapter.ToolContract,
            new { },
            "read:contract",
            budget,
            OperatorExchangeStages.Contract).ConfigureAwait(false);
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

    /// One bounded exchange of one admitted tool, on one already-established
    /// connection, carrying the caller's whole-operation budget.
    ///
    /// The budget covers the queue wait as well as the exchange, so a request
    /// that waits behind a silent peer cannot add a second full window to it.
    /// A request that is proven never to have reached the transport is
    /// reported as not attempted; once any application byte could have reached
    /// the owner, the outcome is reported as unknown under the SAME operation
    /// identity, because a failed write may be partial and pipe closure is
    /// neither rollback nor server-side cancellation.
    private async Task<T> CallToolAsync<T>(
        string tool,
        object arguments,
        string operationScope,
        OperationBudget budget,
        string stage = OperatorExchangeStages.Exchange)
    {
        if (!LegacyOperatorAdapter.IsAdmittedTool(tool))
        {
            // The compatibility adapter admits exactly its four pinned tools
            // plus the typed owner route. Anything else is refused before use.
            throw new OperatorProtocolException("tool", "unadmitted_tool");
        }
        if (Volatile.Read(ref _lifecycle) != LifecycleOpen)
        {
            // Disposal is a lifecycle transition: a closing client refuses new
            // work immediately instead of queueing behind a gate that its own
            // teardown will cancel.
            throw new OperatorNotAttemptedException(
                operationScope, tool, OperatorFaultReason.ClientClosing, OperatorExchangeStages.Admission);
        }

        var acquired = false;
        try
        {
            // Queue waiting observes the effective cancellation: the caller's
            // token, the client's closing transition, or the whole-operation
            // deadline. There is no wait that outlives the advertised bound.
            await _requestGate.WaitAsync(budget.Token).ConfigureAwait(false);
            acquired = true;
            Interlocked.Increment(ref _gateHolders);
        }
        catch (OperationCanceledException)
        {
            throw BudgetRefusal(operationScope, tool, budget, OperatorExchangeStages.Queue);
        }
        catch (ObjectDisposedException)
        {
            // Teardown disposes the gate only when no holder or pending
            // releaser can race it; a late arrival is still reported as the
            // bounded typed refusal instead of surfacing as disposal noise.
            throw new OperatorNotAttemptedException(
                operationScope, tool, OperatorFaultReason.ClientClosing, OperatorExchangeStages.Queue);
        }

        try
        {
            GovernorConnection connection;
            try
            {
                connection = await EnsureConnectedAsync(budget, operationScope, tool).ConfigureAwait(false);
            }
            catch (OperatorRestartRequiredException)
            {
                throw;
            }
            catch (OperatorNotAttemptedException)
            {
                // Establishment failures happen before this request is written.
                // They still cannot compact a retained reconciliation entry: a
                // fresh connection refusal says nothing about the original
                // effect, so the caller keeps the same recovery outcome.
                throw;
            }
            catch (OperationCanceledException)
            {
                throw BudgetRefusal(operationScope, tool, budget, OperatorExchangeStages.Establishment);
            }
            catch (Exception error)
            {
                throw new OperatorUnknownOutcomeException(
                    operationScope, tool, OperatorFaultReason.ForException(error), OperatorExchangeStages.Establishment);
            }

            var state = new ExchangeState();
            var requestId = Interlocked.Increment(ref _requestId);
            try
            {
                var response = await RequestAsync<JsonRpcResponse<McpToolResult>>(connection, new
                {
                    jsonrpc = "2.0",
                    id = requestId,
                    method = "tools/call",
                    @params = new { name = tool, arguments }
                }, budget, stage, state, applicationRequest: true).ConfigureAwait(false);
                ValidateJsonRpcResponse(response, requestId);
                if (response.Error is not null)
                {
                    // A JSON-RPC error carries no owner-bound terminal receipt;
                    // the request may already have reached the mutation owner.
                    throw new OperatorUnknownOutcomeException(
                        operationScope, tool, OperatorFaultReason.OwnerErrorUnbound, OperatorExchangeStages.Decode);
                }
                if (response.Result is null)
                {
                    throw new OperatorUnknownOutcomeException(
                        operationScope, tool, OperatorFaultReason.OwnerResultAbsent, OperatorExchangeStages.Decode);
                }
                T value;
                try
                {
                    value = response.Result.StructuredContent.Deserialize<T>(Json)
                        ?? throw new OperatorUnknownOutcomeException(
                            operationScope, tool, OperatorFaultReason.OwnerResultUnreadable, OperatorExchangeStages.Decode);
                }
                catch (JsonException)
                {
                    // The owner answered but the bytes prove nothing: the same
                    // operation must be reconciled, on the live connection.
                    throw new OperatorUnknownOutcomeException(
                        operationScope, tool, OperatorFaultReason.OwnerResultUnreadable, OperatorExchangeStages.Decode);
                }
                // The owner answered. A budget that expires while that answer
                // is in hand never invalidates the answer, but the transport
                // that carried it is not reused: it is aborted, and an
                // incomplete abort is reported as a cleanup limitation under
                // the same identity, never as an unknown owner outcome.
                if (budget.IsExpired
                    && !await AbortConnectionAsync(connection, OperatorHandoffInvalidation.PipeLost, OperatorExchangeStages.Cleanup).ConfigureAwait(false))
                {
                    throw new OperatorCleanupIncompleteException(
                        operationScope, tool, OperatorFaultReason.RequestTimeout, OperatorExchangeStages.Cleanup, ownerAnswerObserved: true);
                }
                return value;
            }
            catch (OperatorUnknownOutcomeException)
            {
                await AbortQuietlyAsync(connection).ConfigureAwait(false);
                throw;
            }
            catch (OperatorNotAttemptedException)
            {
                await AbortQuietlyAsync(connection).ConfigureAwait(false);
                throw;
            }
            catch (OperatorCleanupIncompleteException)
            {
                // The transport was already aborted by the cleanup path.
                throw;
            }
            catch (OperationCanceledException)
            {
                await AbortQuietlyAsync(connection).ConfigureAwait(false);
                throw BudgetRefusal(
                    operationScope,
                    tool,
                    budget,
                    stage,
                    possiblyExecuted: state.ApplicationWriteStarted);
            }
            catch (Exception error)
            {
                await AbortQuietlyAsync(connection).ConfigureAwait(false);
                throw new OperatorUnknownOutcomeException(
                    operationScope, tool, OperatorFaultReason.ForException(error), stage);
            }
        }
        finally
        {
            Interlocked.Decrement(ref _gateHolders);
            // Only a gate this call actually acquired is released, and a
            // repeated disposal can therefore never double-release it.
            if (acquired) _requestGate.Release();
        }
    }

    /// Opens the single authenticated connection bound to one consumed handoff,
    /// or returns the established one.
    ///
    /// The handoff is validated against the exact current process identity and
    /// consumed before the pipe is opened, so a failed connect can never
    /// present the same nonce twice, even when no application payload was
    /// sent. Connection and the required initial authentication steps are
    /// bounded by ONE establishment window: the smallest of the handoff's own
    /// remaining owner-allowed lifetime, the declared connect ceiling, and the
    /// caller's whole-operation budget. That window ends with establishment:
    /// afterwards the request budget and the serving owner's session and
    /// revocation rules apply, never the spent nonce's old TTL.
    private async Task<GovernorConnection> EnsureConnectedAsync(OperationBudget budget, string operationScope, string tool)
    {
        var live = Volatile.Read(ref _connection);
        if (live is not null && !live.IsAborted && live.Pipe.IsConnected)
        {
            // A live connection is reusable; the handoff that authenticated it
            // is not. Single use binds connection establishment, not request
            // handling.
            return live;
        }
        if (live is not null)
        {
            // Dropped, aborted or half-open. Exactly that connection is
            // released; a replacement established later is a different object.
            await AbortConnectionAsync(live, OperatorHandoffInvalidation.ReconnectRequired, OperatorExchangeStages.Establishment).ConfigureAwait(false);
        }

        OperatorHandoff handoff;
        try
        {
            handoff = await discovery.DiscoverAsync(budget.Token).ConfigureAwait(false);
            handoff.RequireBindingTo(OperatorProcessIdentityProvider.Current, DateTimeOffset.UtcNow);
        }
        catch (OperatorHandoffRefusedException)
        {
            throw;
        }
        catch (RuntimeDiscoveryException)
        {
            throw new OperatorRestartRequiredException(OperatorHandoff.ReacquisitionRequirement);
        }
        catch (OperatorProcessIdentityException)
        {
            throw new OperatorRestartRequiredException(OperatorFaultReason.ProcessIdentityUnproven);
        }

        var ownerRemaining = handoff.RemainingLifetime(DateTimeOffset.UtcNow);
        if (ownerRemaining <= TimeSpan.Zero)
        {
            // A handoff that cannot be consumed in time is refused, not burned.
            handoff.Invalidate(OperatorHandoffInvalidation.Expired);
            throw new OperatorRestartRequiredException(OperatorHandoff.ReacquisitionRequirement);
        }
        var connectCeiling = TimeSpan.FromSeconds(OperatorProtocol.ConnectTimeoutSeconds);
        var establishmentAllowance = ownerRemaining < connectCeiling
            ? ownerRemaining
            : connectCeiling;
        // Converting the owner's wall-clock expiry into the local monotonic
        // budget NEVER extends it: a caller that already spent its own budget
        // gets the smaller of the two.
        if (budget.Remaining < establishmentAllowance) establishmentAllowance = budget.Remaining;
        if (establishmentAllowance <= TimeSpan.Zero)
        {
            handoff.Invalidate(OperatorHandoffInvalidation.Expired);
            throw new OperatorNotAttemptedException(
                operationScope, tool, OperatorFaultReason.EstablishmentWindowExpired, OperatorExchangeStages.Establishment);
        }

        var pipeName = handoff.Endpoint.PipeName.Replace(@"\\.\pipe\", string.Empty, StringComparison.OrdinalIgnoreCase);
        // Single use: the nonce is spent now, not after a successful connect.
        handoff.Consume(DateTimeOffset.UtcNow);
        var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        var connection = new GovernorConnection(pipe, handoff);
        Interlocked.Exchange(ref _connection, connection);

        using var establishment = budget.OpenWindow(establishmentAllowance, OperatorExchangeStages.Establishment);
        try
        {
            // The cancellation registration references THIS connection only, so
            // a late establishment cancellation can never close a replacement
            // connection, and it never waits for the request gate the cancelled
            // operation itself may hold.
            using var abortOnEstablishment = connection.BindAbort(establishment.Token);
            try
            {
                await pipe.ConnectAsync(establishment.Token).ConfigureAwait(false);
            }
            catch (Exception error) when (error is IOException or TimeoutException or OperationCanceledException)
            {
                await AbortConnectionAsync(connection, OperatorHandoffInvalidation.PipeLost, OperatorExchangeStages.Connect).ConfigureAwait(false);
                if (error is OperationCanceledException)
                {
                    throw EstablishmentRefusal(budget, establishment, operationScope, tool, OperatorExchangeStages.Connect);
                }
                throw new OperatorRestartRequiredException(
                    error is TimeoutException
                        ? $"{OperatorFaultReason.ConnectionTimeout} at broker registration generation {handoff.BrokerRegistrationEpoch}"
                        : $"{OperatorFaultReason.ConnectionRefused} at broker registration generation {handoff.BrokerRegistrationEpoch}");
            }

            var streams = new GovernorStreams(
                new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true),
                new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true });
            connection.PublishStreams(streams);

            // Handshake write, handshake read and the required initialize
            // exchange are the initial authentication steps. They observe the
            // establishment window, not the request budget's remaining time and
            // not a fresh per-call window.
            establishment.ThrowIfExpired();
            await streams.Writer.WriteLineAsync(JsonSerializer.Serialize(new
            {
                kind = "eliot_ipc_handshake",
                protocol_version = OperatorProtocol.IpcProtocolVersion,
                broker_epoch = handoff.Endpoint.BrokerEpoch,
                interactive_session_id = handoff.Endpoint.InteractiveSessionId,
                handoff_nonce = handoff.Endpoint.HandoffNonce,
                client_nonce = Guid.NewGuid().ToString("N"),
                profile = "human_operator",
                requested_session_id = (string?)null
            }, Json).AsMemory(), establishment.Token).ConfigureAwait(false);

            var handshakeLine = await ReadBoundedLineAsync(
                connection, streams, establishment, OperatorExchangeStages.HandshakeRead).ConfigureAwait(false)
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
            var initialize = await RequestAsync<JsonRpcResponse<JsonElement>>(connection, new
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
            }, establishment, OperatorExchangeStages.Initialize, state: null, applicationRequest: false).ConfigureAwait(false);
            ValidateJsonRpcResponse(initialize, initializeId);
            if (initialize.Error is not null || initialize.Result.ValueKind == JsonValueKind.Undefined)
            {
                throw new UnauthorizedAccessException(OperatorFaultReason.HandshakeRefused);
            }
        }
        catch (OperatorRestartRequiredException)
        {
            throw;
        }
        catch (OperatorNotAttemptedException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            await AbortConnectionAsync(connection, OperatorHandoffInvalidation.PipeLost, OperatorExchangeStages.Establishment).ConfigureAwait(false);
            throw EstablishmentRefusal(budget, establishment, operationScope, tool, OperatorExchangeStages.Establishment);
        }
        catch (UnauthorizedAccessException)
        {
            await AbortConnectionAsync(connection, OperatorHandoffInvalidation.PipeLost, OperatorExchangeStages.Establishment).ConfigureAwait(false);
            throw;
        }
        catch (Exception error) when (error is IOException or OperatorProtocolException or InvalidOperationException or JsonException)
        {
            await AbortConnectionAsync(connection, OperatorHandoffInvalidation.PipeLost, OperatorExchangeStages.Establishment).ConfigureAwait(false);
            throw new OperatorRestartRequiredException(
                $"{OperatorFaultReason.HandshakeShapeRefused} at broker registration generation {handoff.BrokerRegistrationEpoch}");
        }
        return connection;
    }

    /// Writes one framed request and reads one framed answer on the captured
    /// connection. The whole-operation budget, not a fresh per-call window,
    /// bounds it, and every wait observes the effective token: the
    /// `ReadOnlyMemory<char>, CancellationToken` write overload carries the
    /// token into the buffered write and its AutoFlush, and the read carries
    /// it into the pipe.
    private async Task<T> RequestAsync<T>(
        GovernorConnection connection,
        object request,
        IExchangeWindow window,
        string stage,
        ExchangeState? state,
        bool applicationRequest)
    {
        var streams = connection.Streams
            ?? throw new IOException("Governor pipe transport is not connected");
        // Expiry is checked before a new bounded serialization stage starts, so
        // a request that can no longer be answered is never written.
        window.ThrowIfExpired();
        var line = JsonSerializer.Serialize(request, Json);

        // From here any failure may be partial: the application request can
        // have reached the owner, so its outcome is unknown, never "not sent".
        if (applicationRequest) state!.ApplicationWriteStarted = true;
        // A late cancellation closes THIS connection's pipe so the pending
        // write unwinds. It never touches the request gate and never reaches a
        // replacement connection.
        using var abortOnWrite = connection.BindAbort(window.Token);
        await streams.Writer.WriteLineAsync(line.AsMemory(), window.Token).ConfigureAwait(false);

        var response = await ReadBoundedLineAsync(connection, streams, window, stage).ConfigureAwait(false)
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

    /// Reads one framed line enforcing the inline ceiling before allocation
    /// completes: over-ceiling input fails closed and is never truncated into
    /// a valid object. Returns null only on a clean end-of-stream. Every read
    /// observes the effective cancellation, and expiry is checked before an
    /// already-buffered answer is consumed, because an answer this client
    /// refuses to consume leaves the owner's disposition unproven.
    private static async Task<string?> ReadBoundedLineAsync(
        GovernorConnection connection,
        GovernorStreams streams,
        IExchangeWindow window,
        string stage)
    {
        var buffer = new char[4096];
        while (true)
        {
            var newlineIndex = FindNewline(streams.ReadAhead);
            if (newlineIndex >= 0)
            {
                window.ThrowIfExpired();
                if (newlineIndex > OperatorProtocol.MaxLineChars)
                {
                    throw new OperatorProtocolException("response", "line_cap");
                }
                var line = new StringBuilder(newlineIndex);
                for (var index = 0; index < newlineIndex; index++)
                {
                    var character = streams.ReadAhead[index];
                    if (character != '\r')
                    {
                        if (line.Length >= OperatorProtocol.MaxLineChars)
                        {
                            throw new OperatorProtocolException("response", "line_cap");
                        }
                        line.Append(character);
                    }
                }
                streams.ReadAhead.Remove(0, newlineIndex + 1);
                return line.ToString();
            }
            if (streams.ReadAhead.Length > OperatorProtocol.MaxLineChars)
            {
                throw new OperatorProtocolException("response", "line_cap");
            }
            // The read is bound to the captured connection's reader, so a
            // replacement connection can never deliver into this exchange.
            using var abortOnRead = connection.BindAbort(window.Token);
            var read = await streams.Reader.ReadAsync(buffer, window.Token).ConfigureAwait(false);
            if (read == 0)
            {
                return streams.ReadAhead.Length == 0
                    ? null
                    : throw new IOException("Governor closed the pipe mid-line");
            }
            streams.ReadAhead.Append(buffer, 0, read);
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

    /// Aborts the EXACT transport of one connection, then observes its
    /// reader/writer completions, and never throws: the caller's primary
    /// failure is preserved and the cleanup limitation is reported separately.
    ///
    /// The order matters. The pipe is closed first so the pending operation
    /// unwinds; only then is the buffered writer disposed, so disposal cannot
    /// block on a flush to a silent peer. The nonce, the endpoint and the pipe
    /// name are released together: nothing here can authenticate a later
    /// connection.
    private async Task<bool> AbortConnectionAsync(
        GovernorConnection connection,
        OperatorHandoffInvalidation invalidation,
        string stage)
    {
        connection.Handoff?.Invalidate(invalidation);
        // Detach only this connection: a replacement established later is a
        // different object and is never touched by this cleanup.
        Interlocked.CompareExchange(ref _connection, null, connection);
        var aborted = connection.Abort();
        var allowance = TimeSpan.FromSeconds(TeardownAllowanceSeconds);
        var (completed, pending) = await connection.DisposeStreamsAsync(allowance).ConfigureAwait(false);
        if (pending is not null) RetainCompletion(pending);
        if (!aborted || !completed)
        {
            RecordLimitation(
                stage,
                aborted ? OperatorFaultReason.CleanupIncomplete : "transport_abort_failed",
                connection);
            return false;
        }
        return true;
    }

    private async Task AbortQuietlyAsync(GovernorConnection connection) =>
        await AbortConnectionAsync(connection, OperatorHandoffInvalidation.PipeLost, OperatorExchangeStages.Cleanup).ConfigureAwait(false);

    private void RetainCompletion(Task completion)
    {
        // Root the completion until it is observed, then forget it: a
        // timed-out writer disposal is neither abandoned nor accumulated.
        lock (_retainedGate)
        {
            _retainedCompletions.Add(completion);
        }
        completion.ContinueWith(
            static pending => { _ = pending.Exception; },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
        lock (_retainedGate)
        {
            _retainedCompletions.Remove(completion);
        }
    }

    /// Disposal is a bounded lifecycle transition.
    ///
    /// The client is first marked closing so new work is refused instead of
    /// queued, and every current wait is cancelled and woken so an active
    /// request can unwind on its own connection. Only then is the gate needed
    /// by pending work acquired, and it is released only when this call
    /// acquired it. Repeated disposal cannot double-release, cannot reconnect
    /// and cannot replace a primary failure with an
    /// `ObjectDisposedException` or a flush exception: nothing here throws, and
    /// every incomplete cleanup is recorded explicitly. The close path is
    /// bounded by two teardown allowances in the worst case: the gate wait and
    /// then the aborted connection's stream disposal.
    public async ValueTask DisposeAsync()
    {
        // Only the transition from OPEN owns the teardown. A repeated or
        // concurrent disposal returns immediately, so it can never
        // double-release the gate, reconnect, or race the one disposer.
        if (Interlocked.CompareExchange(ref _lifecycle, LifecycleClosing, LifecycleOpen) != LifecycleOpen)
        {
            return;
        }
        // New work is refused first, then every current wait is cancelled and
        // woken, and only then is the gate pending work needs acquired.
        _closing.Cancel();

        var acquired = false;
        try
        {
            acquired = await _requestGate
                .WaitAsync(TimeSpan.FromSeconds(TeardownAllowanceSeconds), CancellationToken.None)
                .ConfigureAwait(false);
            if (!acquired)
            {
                // An active request that could not unwind inside the teardown
                // allowance is an explicit, recorded incompleteness, not a
                // hang.
                RecordLimitation(OperatorExchangeStages.Dispose, "gate_wait_incomplete");
            }
        }
        catch (ObjectDisposedException)
        {
            RecordLimitation(OperatorExchangeStages.Dispose, "gate_disposed");
        }

        if (acquired)
        {
            Interlocked.Increment(ref _gateHolders);
            var soleHolder = false;
            try
            {
                var connection = Interlocked.Exchange(ref _connection, null);
                if (connection is not null)
                {
                    await AbortConnectionAsync(connection, OperatorHandoffInvalidation.ReconnectRequired, OperatorExchangeStages.Dispose).ConfigureAwait(false);
                }
                // While this call holds the only gate count, no other holder and
                // no pending releaser exists: every earlier waiter was
                // cancelled, and new requests are refused. Only then may the
                // gate be left held and disposed, so a racing release can never
                // become a double-release or an `ObjectDisposedException`.
                soleHolder = Volatile.Read(ref _gateHolders) == 1;
                if (!soleHolder)
                {
                    RecordLimitation(OperatorExchangeStages.Dispose, "gate_still_held", connection);
                }
            }
            finally
            {
                Interlocked.Decrement(ref _gateHolders);
                if (!soleHolder) _requestGate.Release();
            }
            if (soleHolder) _requestGate.Dispose();
        }
        Interlocked.Exchange(ref _lifecycle, LifecycleDisposed);
    }

    /// The typed outcome of an effective cancellation, which is always a
    /// deadline, a client-closing transition, or the caller's own token: the
    /// three are never conflated. A caller-initiated cancellation keeps its
    /// own exception type so a read that the operator cancelled stays a
    /// cancellation, while a request that already reached the transport is
    /// reported as unknown under its own identity.
    private static Exception BudgetRefusal(
        string operationScope,
        string tool,
        OperationBudget budget,
        string stage,
        bool possiblyExecuted = false)
    {
        if (!possiblyExecuted && budget.CallerCancelled)
        {
            return new OperationCanceledException($"Operator request cancelled during {stage}.", budget.Token);
        }
        return possiblyExecuted
            ? new OperatorUnknownOutcomeException(operationScope, tool, budget.CancellationReason, stage)
            : new OperatorNotAttemptedException(operationScope, tool, budget.CancellationReason, stage);
    }

    private static Exception EstablishmentRefusal(
        OperationBudget budget,
        BudgetWindow establishment,
        string operationScope,
        string tool,
        string stage)
    {
        if (budget.CallerCancelled
            && !budget.Closing
            && !budget.DeadlineExpired
            && !establishment.OwnCancellationRequested)
        {
            return new OperationCanceledException($"Operator request cancelled during {stage}.", budget.Token);
        }
        var reason = budget.Closing
            ? OperatorFaultReason.ClientClosing
            : budget.DeadlineExpired
                ? OperatorFaultReason.RequestTimeout
                : OperatorFaultReason.EstablishmentWindowExpired;
        return new OperatorNotAttemptedException(operationScope, tool, reason, stage);
    }

    /// One caller-operation budget. It is created before queue waiting and is
    /// carried, never restarted, through every stage of one caller operation,
    /// so a nested exchange consumes it instead of nesting a fresh full
    /// timeout. Local elapsed time is monotonic; the deadline additionally
    /// interrupts a blocked wait. This type is a private lifetime helper, not a
    /// second transport or a second admission gate: the single request gate
    /// still serializes all exchanges.
    private sealed class OperationBudget : IExchangeWindow
    {
        private readonly CancellationToken _caller;
        private readonly CancellationToken _closing;
        private readonly CancellationTokenSource _deadline;
        private readonly CancellationTokenSource _effective;
        private readonly long _startedAt = Stopwatch.GetTimestamp();
        private int _disposed;

        public OperationBudget(string scope, CancellationToken caller, CancellationToken closing)
        {
            Scope = scope;
            _caller = caller;
            _closing = closing;
            _deadline = new CancellationTokenSource();
            _effective = CancellationTokenSource.CreateLinkedTokenSource(caller, closing, _deadline.Token);
            _deadline.CancelAfter(TimeSpan.FromSeconds(OperatorProtocol.RequestTimeoutSeconds));
        }

        public string Scope { get; }

        public CancellationToken Token => _effective.Token;

        public bool CallerCancelled => _caller.IsCancellationRequested;

        public bool Closing => _closing.IsCancellationRequested;

        public bool DeadlineExpired => _deadline.IsCancellationRequested;

        public bool IsExpired => DeadlineExpired || Remaining <= TimeSpan.Zero;

        /// Monotonic remaining local allowance. A nested window is capped by
        /// it and can never extend it.
        public TimeSpan Remaining
        {
            get
            {
                var spent = Stopwatch.GetElapsedTime(_startedAt);
                var left = TimeSpan.FromSeconds(OperatorProtocol.RequestTimeoutSeconds) - spent;
                return left > TimeSpan.Zero ? left : TimeSpan.Zero;
            }
        }

        public string CancellationReason =>
            DeadlineExpired
                ? OperatorFaultReason.RequestTimeout
                : Closing
                    ? OperatorFaultReason.ClientClosing
                    : OperatorFaultReason.RequestCancelled;

        public BudgetWindow OpenWindow(TimeSpan allowance, string stage)
        {
            // A nested stage window is capped by the caller's own remaining
            // allowance and can never extend it.
            var capped = Remaining < allowance ? Remaining : allowance;
            return new BudgetWindow(capped, Token, stage);
        }

        public void ThrowIfExpired() => Expire();

        private void Expire()
        {
            if (IsExpired)
            {
                throw new OperationCanceledException(
                    $"Operator operation {Scope} exceeded its whole-operation deadline at {CancellationReason}.",
                    Token);
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            _effective.Dispose();
            _deadline.Dispose();
        }
    }

    /// One bounded stage window. The owner-issued handoff expiry is converted
    /// into one of these at establishment, without extending the caller's
    /// budget; it ends with establishment. Its own bound is distinguished from
    /// an outer cancellation, so a caller can tell "the handoff establishment
    /// window closed" from "the operator cancelled" and from "the client is
    /// closing".
    private sealed class BudgetWindow : IExchangeWindow
    {
        private readonly long _startedAt = Stopwatch.GetTimestamp();
        private readonly TimeSpan _allowance;
        private readonly string _stage;
        private readonly CancellationTokenSource? _window;
        private readonly CancellationTokenRegistration _ownBound;
        private readonly CancellationToken _token;
        private int _ownBoundFired;

        public BudgetWindow(TimeSpan allowance, CancellationToken outer, string stage)
        {
            _stage = stage;
            _allowance = allowance > TimeSpan.Zero ? allowance : TimeSpan.Zero;
            if (_allowance <= TimeSpan.Zero)
            {
                _token = outer;
                _ownBound = default;
                return;
            }
            _window = CancellationTokenSource.CreateLinkedTokenSource(outer);
            _window.CancelAfter(_allowance);
            _token = _window.Token;
            // The linked source also fires for an outer cancellation, so the
            // window's own bound is recognised only when no outer source fired.
            _ownBound = _token.Register(() =>
            {
                if (!outer.IsCancellationRequested) Interlocked.Exchange(ref _ownBoundFired, 1);
            });
        }

        public CancellationToken Token => _token;

        public bool OwnCancellationRequested => Volatile.Read(ref _ownBoundFired) != 0;

        public TimeSpan Remaining
        {
            get
            {
                var left = _allowance - Stopwatch.GetElapsedTime(_startedAt);
                return left > TimeSpan.Zero ? left : TimeSpan.Zero;
            }
        }

        public bool IsExpired => Remaining <= TimeSpan.Zero;

        public void ThrowIfExpired()
        {
            if (IsExpired)
            {
                throw new OperationCanceledException($"Governor exchange stage {_stage} exceeded its bound.", _token);
            }
        }

        public void Dispose()
        {
            _ownBound.Dispose();
            _window?.Dispose();
        }
    }

    private interface IExchangeWindow : IDisposable
    {
        CancellationToken Token { get; }
        bool IsExpired { get; }
        void ThrowIfExpired();
    }

    /// What one exchange has proven so far, so the reported phase truth
    /// matches the bytes rather than the hope.
    private sealed class ExchangeState
    {
        /// The application request was handed to the transport, so it may be
        /// partially written and may have executed.
        public bool ApplicationWriteStarted { get; set; }
    }

    /// One owned transport. Every exchange captures the reader, the writer and
    /// the read-ahead buffer of the connection it started on, so a mutable
    /// field can never switch an in-flight exchange's destination.
    private sealed class GovernorStreams
    {
        public GovernorStreams(StreamReader reader, StreamWriter writer)
        {
            Reader = reader;
            Writer = writer;
        }

        public StreamReader Reader { get; }
        public StreamWriter Writer { get; }
        public StringBuilder ReadAhead { get; } = new();
    }

    /// One authenticated connection: its pipe, the handoff that authenticated
    /// it, and the streams opened on it. Identity and lifetime belong to this
    /// object, never to a mutable client field, so an abort, a cleanup or a
    /// late cancellation always names the exact transport it owns.
    private sealed class GovernorConnection
    {
        private static long _sequence;
        private readonly object _gate = new();
        private GovernorStreams? _streams;
        private int _aborted;
        private int _released;

        public GovernorConnection(NamedPipeClientStream pipe, OperatorHandoff? handoff)
        {
            Pipe = pipe;
            Handoff = handoff;
            Identity = Interlocked.Increment(ref _sequence);
        }

        public NamedPipeClientStream Pipe { get; }

        public OperatorHandoff? Handoff { get; }

        public long Identity { get; }

        public bool IsAborted => Volatile.Read(ref _aborted) != 0;

        public GovernorStreams? Streams
        {
            get { lock (_gate) { return _aborted == 0 ? _streams : null; } }
        }

        public void PublishStreams(GovernorStreams streams)
        {
            lock (_gate)
            {
                if (_aborted != 0)
                {
                    throw new IOException("Governor pipe transport was aborted before its streams were published.");
                }
                _streams = streams;
            }
        }

        /// Binds one effective token to THIS connection only. The registered
        /// callback is this instance, not a client field, so a late
        /// cancellation can never close a replacement connection.
        public CancellationTokenRegistration BindAbort(CancellationToken token) =>
            token.CanBeCanceled ? token.Register(AbortTransport) : default;

        private void AbortTransport() => Abort();

        /// Closes this connection's own pipe so its pending read and write
        /// unwind. It takes no gate, touches no client field and cannot reach a
        /// replacement connection, so a cancellation can never wait for the
        /// gate held by the operation it is cancelling.
        public bool Abort()
        {
            Interlocked.Exchange(ref _aborted, 1);
            try
            {
                Pipe.Dispose();
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// Disposes the streams after the pipe is already closed, so the
        /// buffered writer cannot block on a flush to a silent peer. Returns
        /// whether the cleanup completed inside the allowance and, when it did
        /// not, the one completion the caller must still observe.
        public async Task<(bool Completed, Task? Pending)> DisposeStreamsAsync(TimeSpan allowance)
        {
            GovernorStreams? streams;
            lock (_gate)
            {
                if (Interlocked.Exchange(ref _released, 1) != 0) return (true, null);
                streams = _streams;
                _streams = null;
            }
            if (streams is null) return (true, null);
            // Reader disposal never flushes and cannot block on the peer.
            try
            {
                streams.Reader.Dispose();
            }
            catch (Exception)
            {
                // The peer is already gone; cleanup must not mask the outcome.
            }
            var completion = streams.Writer.DisposeAsync().AsTask();
            if (!completion.IsCompleted)
            {
                var finished = await Task.WhenAny(completion, Task.Delay(allowance)).ConfigureAwait(false);
                if (finished != completion) return (false, completion);
            }
            try
            {
                completion.GetAwaiter().GetResult();
            }
            catch (Exception)
            {
                // StreamWriter may surface a broken pipe on dispose. The
                // connection is already aborted, so this is a limitation of the
                // teardown, not of the operation.
            }
            return (true, null);
        }
    }

    /// Bounded, redacted record of a cleanup that is incomplete. It reuses the
    /// existing bounded startup log and names the stage, the closed code and
    /// the connection identity it applies to. A pipe name, nonce, endpoint,
    /// payload, stack trace or exception message never enters it.
    private static void RecordLimitation(string stage, string code, GovernorConnection? connection = null)
    {
        try
        {
            var directory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Eliot",
                "logs");
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, "operator-startup.log");
            var info = new FileInfo(path);
            if (info.Exists && OperatorDiagnostics.ShouldRotate(info.Length))
            {
                File.Delete(path);
            }
            var subject = connection is null
                ? "none"
                : connection.Identity.ToString(CultureInfo.InvariantCulture);
            File.AppendAllText(path, OperatorDiagnostics.FormatStartupRecord(
                $"operator-pipe:{stage}:{code}:connection={subject}", null, hresult: null) + Environment.NewLine);
        }
        catch (Exception)
        {
            // Diagnostics must never mask the transport outcome.
        }
    }
}
