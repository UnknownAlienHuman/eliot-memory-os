using System.Text.Json;
using System.Text.Json.Serialization;
using Eliot.Operator.Protocol;
using Eliot.Operator.Services;
using Eliot.Operator.ViewModels;

// Executed-assertion counter. Only the `True` and `Equal` helpers below touch
// it, so it counts executed assertions and nothing else: no individual
// assertion is rewritten to maintain it. The terminal receipt prints it, which
// is what makes the executed count demonstrable — a run that executed one
// assertion and a run that executed all of them can no longer produce
// byte-identical output. It is a counter, not a gate: the helpers still throw
// on the first failure, so a run that did not pass never reaches the receipt.
var executedAssertions = 0;

var manifestPath = Path.Combine(AppContext.BaseDirectory, "operator-contract-v1.json");
var manifestBytes = await File.ReadAllBytesAsync(manifestPath);
using var manifest = JsonDocument.Parse(manifestBytes);
Equal(OperatorProtocol.SchemaVersion, manifest.RootElement.GetProperty("schema_version").GetString(), "schema version");
Equal(OperatorProtocol.IpcProtocolVersion, manifest.RootElement.GetProperty("ipc_protocol_version").GetString(), "IPC version");
Equal(64, OperatorProtocol.PinnedContractHash.Length, "pinned BLAKE3 contract hash length");
True(!OperatorProtocol.PinnedContractHash.Contains("PENDING", StringComparison.Ordinal), "contract hash finalized");

var endpoint = new OperatorEndpoint(
    @"\\.\pipe\eliot\operator\one-shot", 7, "session-1", "nonce-1",
    "human_operator", ["controlboard.read", "operator.command"]);
RuntimeDiscoveryService.ValidateEndpoint(endpoint);
// These pin the four refusals `ValidateEndpoint` actually makes, and they are
// the four that are load-bearing: an empty, duplicated, unknown or wider-than-
// vocabulary capability set is a real defect vector. A wider set asserts an
// authority the owner never mints; a duplicate is a decode defect; an unknown
// name is an unadmitted vocabulary entry.
//
// This deliberately does NOT pin that a NARROWER subset is refused.
// `ValidateEndpoint` accepts a subset by design: the accepted capabilities are
// "a non-empty list of distinct members of the closed two-capability
// vocabulary" (RuntimeDiscoveryService.cs:214-241). The owner mints an exact
// ordered zip against the same constant (`exact_operator_capabilities` in
// eliot-user-broker-core), so it can never mint a subset, and a client that
// receives one has narrowed its own authority — which I03-09 permits
// ("Lower layers may narrow authority ... They cannot expand a higher boundary
// unless the higher layer explicitly delegates expansion"). Only the owner's
// check is authoritative; this client check is a fail-early shape gate.
True(RefusesCapabilities(["controlboard.read", "controlboard.read"]), "duplicated capability refused");
True(RefusesCapabilities(["controlboard.read", "operator.command", "third.capability"]), "wider capability set refused");
True(RefusesCapabilities(["controlboard.read", "unknown.capability"]), "unknown capability refused");
True(RefusesCapabilities([]), "empty capability set refused");
Environment.SetEnvironmentVariable(
    RuntimeDiscoveryService.EndpointEnvironmentVariable,
    JsonSerializer.Serialize(endpoint));
await new RuntimeDiscoveryService().DiscoverAsync();
True(
    Environment.GetEnvironmentVariable(RuntimeDiscoveryService.EndpointEnvironmentVariable) is null,
    "one-shot endpoint environment cleared after parse");
Equal(
    "b00a82807e003ad1e1b9b717a9759024335ffe461a0cc3f5d67867ec8750394f",
    OperatorProtocol.PinnedContractHash,
    "canonical pinned BLAKE3 contract hash");

Equal(14, OperatorPageCatalog.All.Count, "required page count");
Equal(14, OperatorPageCatalog.All.Select(page => page.Tag).Distinct(StringComparer.Ordinal).Count(), "unique page tags");
True(OperatorPageCatalog.All.Any(page => page.Tag == "causal_provenance"), "native graph page");
True(OperatorPageCatalog.All.Any(page => page.Tag == "query_lab"), "semantic query lab page");
True(OperatorPageCatalog.All.Any(page => page.Tag == "user_automation"), "typed UserAutomation page");
Equal(6, manifest.RootElement.GetProperty("schema_families").GetArrayLength(), "live schema families");
Equal(6, manifest.RootElement.GetProperty("query_operations").GetArrayLength(), "closed query operations");

var client = new FakeGovernorClient();
var viewModel = new MainViewModel(client)
{
    ProjectId = "00000000-0000-0000-0000-000000000001",
    TaskId = "00000000-0000-0000-0000-000000000002"
};
var sampleUserAutomationFence = JsonSerializer.SerializeToElement(new
{
    authority_epoch = new
    {
        lineage_id = "00000000-0000-0000-0000-000000000003",
        sequence = 1
    },
    resource_generation = 1,
    task_revision = (ulong?)null,
    policy_revision = (ulong?)null,
    integration_revision = (ulong?)null
});
var userAutomationWire = JsonSerializer.Serialize(
    UserAutomationOperatorRequest.Create(new UserAutomationListOperation(false), sampleUserAutomationFence));
True(!userAutomationWire.Contains("\"command\"", StringComparison.Ordinal), "UserAutomation has no generic command envelope");
True(userAutomationWire.Contains("\"kind\":\"list\"", StringComparison.Ordinal), "closed UserAutomation operation kind");
True(userAutomationWire.Contains("\"idempotency_key\"", StringComparison.Ordinal), "retry-stable UserAutomation identity");
await viewModel.RunUserAutomationAsync();
Equal(1, client.UserAutomationCount, "typed UserAutomation caller submitted once");
True(client.LastUserAutomation is UserAutomationListOperation, "UserAutomation caller preserved typed operation");
await viewModel.SelectSectionAsync("autonomy");
Equal("autonomy", client.LastQuery?.Projection, "typed projection selection");
Equal(1, viewModel.ItemCount, "first bounded page");
True(viewModel.CanLoadMore, "continuation advertised");
await viewModel.LoadMoreAsync();
Equal(2, viewModel.ItemCount, "continuation appended");
True(!viewModel.CanLoadMore, "continuation exhausted");

viewModel.FilterText = "run";
viewModel.SaveCurrentFilter("runs");
viewModel.FilterText = "changed";
await viewModel.ApplySavedFilterAsync();
Equal("run", viewModel.FilterText, "saved filter restored");

viewModel.SelectedRecord = viewModel.Records[0];
viewModel.SelectedAction = viewModel.SelectedRecord.Actions[0];
await viewModel.ExecuteSelectedActionAsync();
True(client.CommandCount == 1, "typed action submitted once");
True(!string.IsNullOrWhiteSpace(client.LastIdempotencyKey), "logical action generated idempotency key");
True(viewModel.StatusMessage.Contains("canonical receipt", StringComparison.Ordinal), "canonical receipt surfaced");
client.OmitCanonicalReceipt = true;
await viewModel.ExecuteSelectedActionAsync();
Equal(
    "Unknown outcome — reconcile, do not resubmit",
    viewModel.StatusTitle,
    "durable command without receipt stays reconciling, not failed");
True(
    viewModel.StatusMessage.Contains("without a canonical receipt", StringComparison.Ordinal),
    "missing canonical receipt failure explained");
True(viewModel.HasUnknownOperations, "unproven mutation retained for reconciliation");
client.OmitCanonicalReceipt = false;
await viewModel.ReconcilePendingAsync();
True(!viewModel.HasUnknownOperations, "reconciled operation leaves the unknown set");
Equal("Command accepted", viewModel.StatusTitle, "reconciliation resolves the retained operation");
Equal(1, client.ReconcileCount, "exact reconciliation of the retained operation");

await viewModel.SelectSectionAsync("query_lab");
viewModel.QueryOperation = "relationship_slice";
viewModel.QueryParametersText = "{\"selected_ref\":\"claim:1\"}";
viewModel.ResultMode = "graph";
viewModel.GraphDepth = 2;
await viewModel.RefreshAsync();
Equal("relationship_slice", client.LastQuery?.QueryOperation, "typed query operation submitted");
Equal("graph", client.LastQuery?.ResultMode, "graph result mode submitted");
Equal(2, client.LastQuery?.ExpandDepth, "bounded graph depth submitted");
await viewModel.ExpandGraphNodeAsync("claim:1");
Equal("claim:1", client.LastQuery?.SelectedRef, "selected graph neighborhood submitted");

viewModel.QueryOperation = "recall_preview";
viewModel.QueryParametersText = "{\"query\":\"current candidate\"}";
viewModel.ResultMode = "human";
await viewModel.RefreshAsync();
var rankTrace = viewModel.Records.Single(record => record.RecordKind == "l0_rank_trace");
True(
    rankTrace.Fields.Any(field => field.Label == "query" && field.Value == "current candidate"),
    "L0 query field rendered by view model");
True(
    viewModel.Records.Any(record =>
        record.RecordKind == "l0_rank_candidate"
        && record.Status == "suppressed"
        && record.Fields.Any(field => field.Label == "reasons")),
    "L0 suppression reason rendered by view model");
var disposition = viewModel.Records.Single(record => record.RecordKind == "canonical_m6_disposition_chain");
foreach (var requiredField in new[] {
    "candidate_result_id", "actor_role_lease_id", "write_receipt_id",
    "task_revision_before", "task_revision_after", "source_commit", "policy_snapshot_id"
})
{
    True(disposition.Fields.Any(field => field.Label == requiredField), $"M6 {requiredField} rendered by view model");
}

client.DelayQueries = true;
var cancelled = viewModel.RefreshAsync();
viewModel.CancelActiveRequest();
await cancelled;
Equal("Request cancelled", viewModel.StatusTitle, "nonblocking cancellation surfaced");

// Lost transport response keeps one identity through send, reconnect and
// reconciliation; a retry never mints a second logical mutation.
await viewModel.SelectSectionAsync("autonomy");
viewModel.SelectedRecord = viewModel.Records[0];
viewModel.SelectedAction = viewModel.SelectedRecord.Actions[0];
client.ThrowUnknownOnce = true;
var commandsBefore = client.CommandCount;
await viewModel.ExecuteSelectedActionAsync();
Equal(commandsBefore + 1, client.CommandCount, "unknown-outcome action sent once");
Equal(
    "Unknown outcome — reconcile, do not resubmit",
    viewModel.StatusTitle,
    "pipe loss surfaces unknown outcome");
var retainedKey = client.LastIdempotencyKey;
True(!string.IsNullOrWhiteSpace(retainedKey), "lost response kept its operation identity");
True(viewModel.HasUnknownOperations, "lost response retained for reconciliation");
await viewModel.ReconcilePendingAsync();
Equal(retainedKey, client.LastReconciledKey, "reconciliation reuses the retained identity");
Equal(commandsBefore + 1, client.CommandCount, "reconciliation never resubmits a new command");
True(!viewModel.HasUnknownOperations, "reconciled set drains");
await viewModel.ExecuteSelectedActionAsync();
True(client.LastIdempotencyKey != retainedKey, "a new user action mints a new identity");

// Runtime/generation rotation invalidates dependent UI state before use.
client.RotateGeneration = true;
await viewModel.RefreshAsync();
True(
    viewModel.StatusMessage.Contains("invalidated", StringComparison.Ordinal),
    "generation rotation invalidates dependent state");
client.RotateGeneration = false;

// The legacy wire path is one versioned adapter with one consumer, a proof
// ceiling, and removal criteria; it gains no new shape here.
Equal(OperatorProtocol.SchemaVersion, LegacyOperatorAdapter.SchemaVersion, "legacy adapter pins current schema");
Equal(OperatorProtocol.PinnedContractHash, LegacyOperatorAdapter.ContractHash, "legacy adapter pins current hash");
Equal("Eliot.Operator.Services.GovernorPipeClient", LegacyOperatorAdapter.Consumer, "legacy adapter has one consumer");
True(!string.IsNullOrWhiteSpace(LegacyOperatorAdapter.ExpiryRemoval), "legacy adapter carries removal criteria");

// Typed intent envelope: one identity per action in the exact owner shape.
var intent = OperatorIntentEnvelope.Create(
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002",
    7,
    JsonSerializer.SerializeToElement(new { command = "resume_run" }));
Equal(32, intent.OperationId.Length, "per-action operation identity");
var intentWire = JsonSerializer.Serialize(intent);
foreach (var field in new[] { "project_id", "task_id", "expected_revision", "idempotency_key", "command" })
{
    True(intentWire.Contains($"\"{field}\"", StringComparison.Ordinal), $"intent carries {field}");
}

// Closed decoding: unknown and duplicate protected fields fail before use.
var endpointJson = JsonSerializer.Serialize(endpoint);
OperatorJsonGuard.ValidateClosedObject(
    endpointJson,
    ["pipe_name", "broker_epoch", "interactive_session_id", "handoff_nonce", "role", "capabilities"],
    32, 1024, 4, 512, "endpoint");
var unknownRejected = false;
try
{
    OperatorJsonGuard.ValidateClosedObject(
        "{\"pipe_name\":\"x\",\"roleX\":\"y\"}", ["pipe_name"], 32, 1024, 4, 512, "endpoint");
}
catch (OperatorProtocolException error) when (error.Reason.StartsWith("unknown:", StringComparison.Ordinal))
{
    unknownRejected = true;
}
True(unknownRejected, "closed decode rejects unknown protected fields");
var duplicateRejected = false;
try
{
    OperatorJsonGuard.ValidateClosedObject(
        "{\"pipe_name\":\"x\",\"pipe_name\":\"y\"}", ["pipe_name"], 32, 1024, 4, 512, "endpoint");
}
catch (OperatorProtocolException error) when (error.Reason.StartsWith("duplicate:", StringComparison.Ordinal))
{
    duplicateRejected = true;
}
True(duplicateRejected, "closed decode rejects duplicate protected fields");
var capped = false;
try
{
    OperatorJsonGuard.ValidateFramedLine(
        "{\"pipe_name\":\"" + new string('x', OperatorProtocol.MaxControlStringChars + 1) + "\"}",
        32, OperatorProtocol.MaxControlStringChars, 4, 512, "response");
}
catch (OperatorProtocolException error) when (error.Reason == "string_cap")
{
    capped = true;
}
True(capped, "oversized strings fail closed before allocation completes");
Equal(262_144, OperatorProtocol.MaxLineChars, "framed line ceiling pinned");

// Bounded redacted diagnostics: type and HRESULT only, never message/stack,
// endpoint, nonce, credential, or command body (absent by construction: the
// formatter accepts no such input).
var record = OperatorDiagnostics.FormatStartupRecord(
    "launch:begin", "System.IO.IOException", unchecked((int)0x80070005));
True(record.Contains("launch:begin", StringComparison.Ordinal), "diagnostic keeps the stage");
True(record.Contains("System.IO.IOException", StringComparison.Ordinal), "diagnostic keeps the type");
True(!record.Contains(" at ", StringComparison.Ordinal), "diagnostic carries no stack trace");
True(record.Length <= OperatorDiagnostics.MaxRecordChars, "diagnostic record bounded");
True(OperatorDiagnostics.ShouldRotate(OperatorDiagnostics.MaxLogBytes + 1), "log rotates at the cap");
True(!OperatorDiagnostics.ShouldRotate(0), "empty log does not rotate");

// The live probe runs AFTER every conformance assertion, and its failure is
// bounded to one typed line. A run that reaches here has already executed and
// passed every assertion above; a live probe that throws must not turn that
// into a lost terminal receipt, and it must not be able to hide a conformance
// failure either — a failing assertion above throws and never reaches this
// block. The live line is NOT an assertion and adds none: it reports a probe
// outcome, and the executed count above is unchanged by it.
//
// Redaction: one bounded line carrying the stage and the exception TYPE only.
// No message, no stack trace, no endpoint, pipe name, nonce, credential or
// command/query body (A11). The exception message may embed any of those.
if (args.Contains("--live", StringComparer.Ordinal))
{
    try
    {
        await using var liveClient = new GovernorPipeClient(new RuntimeDiscoveryService());
        var liveSnapshot = await liveClient.SnapshotAsync();
        var livePage = await liveClient.QueryAsync(new OperatorQueryRequest(
            "overview", null, null, new OperatorProjectionFilter(), null, 20));
        Console.WriteLine(
            $"LIVE_OPERATOR_OK runtime={liveSnapshot.RuntimeId} auth_generation={liveSnapshot.AuthGeneration} overview_records={livePage.Returned}");
    }
    catch (Exception liveError)
    {
        var liveType = (liveError.GetType().FullName ?? "System.Exception");
        if (liveType.Length > OperatorDiagnostics.MaxTypeChars)
        {
            liveType = liveType[..OperatorDiagnostics.MaxTypeChars];
        }
        Console.WriteLine($"LIVE_OPERATOR_UNAVAILABLE stage=live_operator_probe type={liveType}");
    }
}

Console.WriteLine(
    $"ELIOT Operator protocol, auth, paging, view-model, command, reconcile, bounds, redaction and invalidation tests passed; assertions={executedAssertions}");

// The only two places the executed count moves. Both still throw on the first
// failure: counting an assertion never weakens it, and a failing run aborts
// before the terminal receipt instead of printing one.
void True(bool condition, string label)
{
    executedAssertions++;
    if (!condition) throw new Exception($"assertion failed: {label}");
}

void Equal<T>(T expected, T actual, string label)
{
    executedAssertions++;
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
        throw new Exception($"assertion failed: {label}; expected={expected}; actual={actual}");
}

// Not an assertion and it moves no counter: it only reports whether
// `ValidateEndpoint` refused the supplied capability set with the typed
// `endpoint_invalid` code. Acceptance is a false result, and any other
// exception propagates rather than being read as a refusal, so the helper can
// never widen what counts as a refusal. It reuses the already-validated
// endpoint, so every other field stays valid and the capability set is the
// only thing under test.
bool RefusesCapabilities(IReadOnlyList<string> capabilities)
{
    try { RuntimeDiscoveryService.ValidateEndpoint(endpoint with { Capabilities = capabilities }); }
    catch (RuntimeDiscoveryException error) when (error.Code == "endpoint_invalid") { return true; }
    return false;
}

sealed class FakeGovernorClient : IGovernorClient
{
    private static readonly TaskContractView CanonicalTask = new(
        "00000000-0000-0000-0000-000000000002",
        "00000000-0000-0000-0000-000000000001",
        "Operator test task",
        "active",
        7,
        []);

    // The owner omits an absent receipt rather than sending a null member, so
    // the harness omits it the same way instead of writing a null the client
    // would have to reinterpret.
    private static readonly JsonSerializerOptions OwnerReceiptJson = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public OperatorQueryRequest? LastQuery { get; private set; }
    public int CommandCount { get; private set; }
    public int ReconcileCount { get; private set; }
    public int UserAutomationCount { get; private set; }
    public UserAutomationOperation? LastUserAutomation { get; private set; }
    public string? LastIdempotencyKey { get; private set; }
    public string? LastReconciledKey { get; private set; }
    public bool DelayQueries { get; set; }
    public bool OmitCanonicalReceipt { get; set; }
    public bool ThrowUnknownOnce { get; set; }
    public bool RotateGeneration { get; set; }

    // This fake has no broker-authenticated transport, so there is no
    // redeemed grant to report. The production client reports null for any
    // connection that is not live and authenticated, and null never
    // authorizes: callers treat it as "let the transport authenticate",
    // never as a capability. Fabricating a binding here would grant the
    // harness capabilities no owner ever issued to it.
    public OperatorRoleBinding? GrantedBinding => null;

    public Task<OperatorSnapshot> SnapshotAsync(
        string? projectId = null,
        string? taskId = null,
        CancellationToken cancellationToken = default) => Task.FromResult(new OperatorSnapshot(
            OperatorProtocol.SchemaVersion,
            OperatorProtocol.IpcProtocolVersion,
            OperatorProtocol.PinnedContractHash,
            "runtime-a",
            "generation-a",
            ["runtime:healthy"],
            [new TaskCognitionView(CanonicalTask, null, new EpistemicPacketView([], [], [], []))],
            null,
            new AgentRoutingView([], [], [], [], [], [], []),
            [new AutonomyRunView(
                new AutonomyRunContractView("run-1", CanonicalTask.ProjectId, CanonicalTask.TaskId, "bounded run", "running", 2),
                [], [], [], "running")],
            [],
            new TraceTimelineView(null, null, [], [])));

    public async Task<OperatorProjectionPage> QueryAsync(
        OperatorQueryRequest request,
        CancellationToken cancellationToken = default)
    {
        LastQuery = request;
        if (DelayQueries) await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken);
        if (request.QueryOperation == "recall_preview")
        {
            var rank = new OperatorRecordView(
                "l0-rank-trace:test", "l0_rank_trace", "current candidate",
                "Deterministic query-aware memory ranking.", "candidates_found", null,
                "canonical_store_query_ranker", null,
                [
                    new OperatorFieldView("query", "current candidate", true),
                    new OperatorFieldView("query_mode", "query_aware_semantic_lexical_relational_v2", false),
                    new OperatorFieldView("at_revision", "19", true)
                ], [], []);
            var suppressed = new OperatorRecordView(
                "l0-candidate:claim:suppressed", "l0_rank_candidate", "claim:suppressed",
                "lifecycle_suppressed", "suppressed", "suppressed",
                "canonical_store_query_ranker", null,
                [
                    new OperatorFieldView("reasons", "inactive_lifecycle", false),
                    new OperatorFieldView("at_revision", "19", true)
                ], [], []);
            var disposition = new OperatorRecordView(
                "canonical-m6:run:test-case", "canonical_m6_disposition_chain", "test-case",
                "Store-resolved candidate, disposition, authority, verifier and receipt chain.",
                "accepted", null, "writer_actor_canonical_store", null,
                [
                    new OperatorFieldView("candidate_result_id", "candidate:1", true),
                    new OperatorFieldView("actor_role_lease_id", "role:1", true),
                    new OperatorFieldView("write_receipt_id", "receipt:1", true),
                    new OperatorFieldView("task_revision_before", "18", true),
                    new OperatorFieldView("task_revision_after", "19", true),
                    new OperatorFieldView("source_commit", "commit:1", true),
                    new OperatorFieldView("policy_snapshot_id", "policy:1", true)
                ], [], []);
            var generation = RotateGeneration ? "generation-b" : "generation-a";
            return new OperatorProjectionPage(
                OperatorProtocol.SchemaVersion, "runtime-a", generation, "memory_explorer",
                request.ProjectId, request.TaskId, 19, request.Cursor, null, request.PageSize,
                3, 3, true, false, [rank, suppressed, disposition], request.ResultMode,
                JsonSerializer.SerializeToElement(new { operation = request.QueryOperation }),
                DateTimeOffset.UtcNow);
        }
        var second = request.Cursor is not null;
        var record = new OperatorRecordView(
            second ? "autonomy-run:run-2" : "autonomy-run:run-1",
            "autonomy_run",
            second ? "Second bounded run" : "Bounded run",
            "running @ revision 2",
            "running",
            null,
            "governor_control_plane",
            null,
            [new OperatorFieldView("run_id", second ? "run-2" : "run-1", true)],
            [],
            [new OperatorActionView("resume_run", "Resume", "R1", false, false)]);
        return new OperatorProjectionPage(
            OperatorProtocol.SchemaVersion,
            "runtime-a",
            RotateGeneration ? "generation-b" : "generation-a",
            request.Projection,
            request.ProjectId,
            request.TaskId,
            7,
            request.Cursor,
            second ? null : "offset:1",
            request.PageSize,
            1,
            2,
            true,
            !second,
            [record],
            request.ResultMode,
            JsonSerializer.SerializeToElement(new { operation = request.QueryOperation, records = new[] { record.RecordRef } }),
            DateTimeOffset.UtcNow);
    }

    /// One owner-bound command receipt in the exact shape the serving owner
    /// emits (`OperatorCommandReceipt` in `crates/eliot-types`, written at
    /// `crates/eliot-app/src/mcp_stdio/operator.rs`). The owner echoes the
    /// submitted `idempotency_key` as `operation_id` and the submitted
    /// `expected_revision` verbatim, and reports the bound task `revision`;
    /// `MainViewModel.ReadCommandReceipt` refuses a receipt that is not bound
    /// to that exact operation identity, that exact expected revision and that
    /// same produced revision, and it requires a `canonical_receipt.receipt_id`
    /// whenever the owner claims `executed`. A receipt that omitted those
    /// bindings modelled a transport the owner does not serve, so every value
    /// is taken from the envelope this call actually received rather than
    /// written as a constant.
    ///
    /// The owner derives `command_id` from a BLAKE3 digest of the identity. The
    /// harness has no such dependency and inventing a digest would model a
    /// value the owner never sends, so the field is absent; the client binds
    /// nothing to it. The fake commits nothing, so the revision it reports is
    /// the revision it was asked to act at.
    private static JsonElement OwnerCommandReceipt(
        JsonElement envelope,
        string receiptId,
        string writeId,
        bool omitCanonicalReceipt)
    {
        var operationId = envelope.GetProperty("idempotency_key").GetString() ?? "unknown";
        var expectedRevision = envelope.GetProperty("expected_revision").GetUInt64();
        var taskId = envelope.GetProperty("task_id").GetString();
        var command = envelope.GetProperty("command");
        var action = command.ValueKind == JsonValueKind.Object
            && command.TryGetProperty("command", out var actionName)
            && actionName.ValueKind == JsonValueKind.String
                ? actionName.GetString() ?? "unknown"
                : "unknown";
        return JsonSerializer.SerializeToElement(new
        {
            operation_id = operationId,
            expected_revision = expectedRevision,
            task_id = taskId,
            action = action,
            accepted = true,
            executed = true,
            outcome = "canonical_mutation_committed",
            revision = expectedRevision,
            reasons = Array.Empty<string>(),
            canonical_receipt = omitCanonicalReceipt
                ? null
                : new { receipt_id = receiptId, write_id = writeId },
            generated_at = DateTimeOffset.UtcNow
        }, OwnerReceiptJson);
    }

    public Task<JsonElement> CommandAsync(
        OperatorIntentEnvelope commandEnvelope,
        CancellationToken cancellationToken = default)
    {
        CommandCount++;
        var envelope = JsonSerializer.SerializeToElement(commandEnvelope);
        LastIdempotencyKey = envelope.GetProperty("idempotency_key").GetString();
        if (ThrowUnknownOnce)
        {
            ThrowUnknownOnce = false;
            throw new OperatorUnknownOutcomeException(
                LastIdempotencyKey ?? "unknown", "eliot_operator_command", "simulated pipe loss");
        }
        return Task.FromResult(OwnerCommandReceipt(
            envelope, "receipt-1", "write-1", OmitCanonicalReceipt));
    }

    public Task<JsonElement> ReconcileAsync(
        JsonElement commandEnvelope,
        CancellationToken cancellationToken = default)
    {
        // Same-identity reconciliation: the retained envelope resends under
        // its original key; no second logical mutation is minted. The receipt
        // is bound to the retained bytes, not to a fresh identity.
        ReconcileCount++;
        LastReconciledKey = commandEnvelope.GetProperty("idempotency_key").GetString();
        return Task.FromResult(OwnerCommandReceipt(
            commandEnvelope, "receipt-r", "write-r", OmitCanonicalReceipt));
    }

    public Task<JsonElement> UserAutomationAsync(
        UserAutomationOperatorRequest request,
        CancellationToken cancellationToken = default)
    {
        request.Validate();
        if (request.Operation is UserAutomationGetContextOperation)
        {
            var contextFence = JsonSerializer.SerializeToElement(new
            {
                authority_epoch = new
                {
                    lineage_id = "00000000-0000-0000-0000-000000000003",
                    sequence = 1
                },
                resource_generation = 1,
                task_revision = (ulong?)null,
                policy_revision = (ulong?)null,
                integration_revision = (ulong?)null
            });
            return Task.FromResult(JsonSerializer.SerializeToElement(new
            {
                wire_id = OperatorScheduleContract.USER_AUTOMATION_RESULT_WIRE_ID,
                wire_version = OperatorScheduleContract.USER_AUTOMATION_RESULT_WIRE_VERSION,
                status = "known",
                correlation = new
                {
                    operation_id = $"user-automation-operation:{request.IdempotencyKey}",
                    idempotency_key = request.IdempotencyKey
                },
                state_fence = contextFence,
                value = new { outcome = "context", state_fence = contextFence },
                recovery = (object?)null
            }));
        }

        UserAutomationCount++;
        LastUserAutomation = request.Operation;
        return Task.FromResult(JsonSerializer.SerializeToElement(new
        {
            accepted = true,
            executed = false,
            outcome = "typed_user_automation_operation_admitted"
        }));
    }
}
