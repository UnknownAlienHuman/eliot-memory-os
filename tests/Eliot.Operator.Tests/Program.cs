using System.Text.Json;
using Eliot.Operator.Protocol;
using Eliot.Operator.Services;
using Eliot.Operator.ViewModels;

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
var wrongCapabilities = endpoint with { Capabilities = ["operator.command"] };
var wrongCapabilitiesRejected = false;
try { RuntimeDiscoveryService.ValidateEndpoint(wrongCapabilities); }
catch (RuntimeDiscoveryException error) when (error.Code == "endpoint_invalid") { wrongCapabilitiesRejected = true; }
True(wrongCapabilitiesRejected, "exact Operator capability allowlist");
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

if (args.Contains("--live", StringComparer.Ordinal))
{
    await using var liveClient = new GovernorPipeClient(new RuntimeDiscoveryService());
    var liveSnapshot = await liveClient.SnapshotAsync();
    var livePage = await liveClient.QueryAsync(new OperatorQueryRequest(
        "overview", null, null, new OperatorProjectionFilter(), null, 20));
    Console.WriteLine(
        $"LIVE_OPERATOR_OK runtime={liveSnapshot.RuntimeId} auth_generation={liveSnapshot.AuthGeneration} overview_records={livePage.Returned}");
}

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
var userAutomationWire = JsonSerializer.Serialize(
    UserAutomationOperatorRequest.Create(new UserAutomationListOperation(false)));
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

Console.WriteLine("ELIOT Operator protocol, auth, paging, view-model, command, reconcile, bounds, redaction and invalidation tests passed");

static void True(bool condition, string label)
{
    if (!condition) throw new Exception($"assertion failed: {label}");
}

static void Equal<T>(T expected, T actual, string label)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
        throw new Exception($"assertion failed: {label}; expected={expected}; actual={actual}");
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

    public Task<JsonElement> CommandAsync(
        object commandEnvelope,
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
        using var document = JsonDocument.Parse(OmitCanonicalReceipt
            ? """{"accepted":true,"executed":true,"outcome":"canonical_mutation_committed"}"""
            : """{"accepted":true,"executed":true,"outcome":"canonical_mutation_committed","canonical_receipt":{"receipt_id":"receipt-1","write_id":"write-1"}}""");
        return Task.FromResult(document.RootElement.Clone());
    }

    public Task<JsonElement> ReconcileAsync(
        JsonElement commandEnvelope,
        CancellationToken cancellationToken = default)
    {
        // Same-identity reconciliation: the retained envelope resends under
        // its original key; no second logical mutation is minted.
        ReconcileCount++;
        LastReconciledKey = commandEnvelope.GetProperty("idempotency_key").GetString();
        using var document = JsonDocument.Parse(
            """{"accepted":true,"executed":true,"outcome":"canonical_mutation_committed","canonical_receipt":{"receipt_id":"receipt-r","write_id":"write-r"}}""");
        return Task.FromResult(document.RootElement.Clone());
    }

    public Task<JsonElement> UserAutomationAsync(
        UserAutomationOperatorRequest request,
        CancellationToken cancellationToken = default)
    {
        request.Validate();
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
