using System.Text.Json;
using System.Text.Json.Serialization;
using Eliot.Operator.Protocol;
using Eliot.Operator.Protocol.Generated;
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
// One closed owner State Fence witness, written with exactly the members
// `UserAutomationOutcomeClassifier.IsClosedStateFence` reads: a closed
// authority epoch carrying a lowercase UUID lineage and a positive sequence,
// a positive resource generation, and the three optional positive revisions.
// The harness mints no other fence. Every BUSINESS case below carries this one
// witness, both when admitted and when refused, so the operation or the key is
// the only thing under test; the single handshake case that pins key syntax
// carries `ExpectedStateFence: null`, which is the only value that operation
// admits (`Validate` refuses any fence on a get_context request), so in no case
// here is the fence the discriminating variable. The lineage is written out as
// a literal rather than derived because the contract reads it as bounded text
// and then parses it as a lowercase UUID (`TryReadBoundedText(..., 36, ...)`
// followed by `IsLowercaseUuid`), which a computed value would have to
// reproduce by hand anyway.
var userAutomationFence = JsonSerializer.SerializeToElement(new
{
    authority_epoch = new
    {
        lineage_id = "00000000-0000-0000-0000-000000000007",
        sequence = 7
    },
    resource_generation = 7,
    task_revision = 7,
    policy_revision = 1,
    integration_revision = 1
});
// The fake owner is a nested class and cannot see this top-level local, so it
// is handed the SAME witness here instead of carrying a second literal: the
// fence is defined exactly once in this file. That matters because the fence
// the fake answers the handshake with and the fence every business request
// carries must be the same BYTES, not two fixtures that merely look alike --
// `ReadContextStateFence` returns the envelope fence it admitted
// (UserAutomationScheduleContract.cs:1268) and `Create(operation, fence)`
// clones it onto the next request (UserAutomationContracts.cs:659), so what is
// compared below is one value that travelled, not two that agreed.
client.UserAutomationFence = userAutomationFence;
// The read path mints its request through the same `Create(operation, fence)`
// overload the UI effect path uses: `Create(operation)` is the handshake-only
// mint and its FACTORY refuses a business operation outright, so that is the
// overload every minted business request here goes through. The refusals below
// construct `UserAutomationOperatorRequest` directly instead, because a
// direct construction is the only way to reach a refusal the validator makes:
// the record is a public positional one and such a request is built fine, then
// refused by `Validate`.
var userAutomationWire = JsonSerializer.Serialize(
    UserAutomationOperatorRequest.Create(new UserAutomationListOperation(false), userAutomationFence));
True(!userAutomationWire.Contains("\"command\"", StringComparison.Ordinal), "UserAutomation has no generic command envelope");
True(userAutomationWire.Contains("\"kind\":\"list\"", StringComparison.Ordinal), "closed UserAutomation operation kind");
True(userAutomationWire.Contains("\"idempotency_key\"", StringComparison.Ordinal), "retry-stable UserAutomation identity");
await viewModel.RunUserAutomationAsync();
// The read branch of `SubmitUserAutomationAsync` (MainViewModel.cs:738-749)
// ALWAYS reads a fresh context first and only then sends the business read, so
// a successful typed read is TWO requests, not one: the `get_context`
// handshake, then the `list` that carries the fence the handshake returned.
// Before the fake could answer the closed handshake envelope this branch
// aborted at `ReadFreshUserAutomationStateFenceAsync` and only one request was
// ever sent; the count below is the observation of that order. The count of 2 is
// the stronger claim over the old count of 1: it proves the handshake really
// travelled BEFORE the business request, which a business-only count could not.
Equal(2, client.UserAutomationCount, "typed UserAutomation caller submitted the handshake and its one business read");
True(client.LastUserAutomation is UserAutomationListOperation, "UserAutomation caller preserved typed operation");
// UI READ PATH, end to end through the real view model: the request the client
// received for the BUSINESS operation carries exactly the fence the client
// itself returned in the `get_context` answer one call earlier. That round trip
// is the whole reason the handshake exists, and it is only observable where the
// request actually lands, so it is pinned here rather than only at the
// mint-level `Create(operation, fence)` assertion below.
True(
    client.LastBusinessStateFence is { } readFence
        && JsonElement.DeepEquals(readFence, userAutomationFence),
    "UI read path business request carries the exact fence the get_context answer returned");

// The narrow identity split, pinned on both halves at once. The read-only
// `get_context` handshake is a per-session route read whose result supplies
// the fence every later request carries, so its identity is a fresh per-call
// nonce and NOT the digest of its own bytes; requiring that digest of it would
// refuse every context read before it reached the transport and no business
// request could ever obtain its fence. Business operations are the opposite
// case and must keep the exact binding: `idempotency_key` is the digest of
// their own canonical operation bytes, because that key is what makes a retry,
// a reconnect and a resend the SAME logical mutation rather than a second one.
// Both halves are asserted together so neither can be widened without failing.
var contextRequest = UserAutomationOperatorRequest.CreateContext();
// A fresh context request is admitted by the same validator the transport
// boundary calls, so the UI read path reaches the real client transport
// instead of being refused for a business-digest relation it never had. This
// is the assertion that would fail on a validator still demanding the digest
// of the handshake's own bytes: `Validate()` succeeds, `ValidateCurrentIdentity`
// does not, and the context read dies before it can return the fence every
// later request carries.
True(AcceptsCurrentIdentity(contextRequest), "fresh get_context handshake passes the current identity validator");
var repeatedContextRequest = UserAutomationOperatorRequest.CreateContext();
// This one is true on origin/main as well: two independent
// `Guid.NewGuid().ToString("N")` draws at `UserAutomationContracts.cs:640` are
// always different, so it is not evidence that the split happened. Its force is
// the substitution issue #2643, audit comment 5964149245 forbids. If
// `CreateContext` were "fixed" by minting `DeriveIdempotencyKey(Operation)`
// instead of a fresh nonce, both keys
// would be the SAME constant and this assertion would fail — the handshake must
// keep a distinct per-call identity.
True(
    !string.Equals(
        contextRequest.IdempotencyKey,
        repeatedContextRequest.IdempotencyKey,
        StringComparison.Ordinal),
    "repeated fresh context handshake retains its fresh per-call identity");
// Likewise a guard against the same forbidden constant-hash substitution, and
// the direct statement of what `CreateContext()` must never return: its key is
// the per-call nonce, not the digest of the handshake's operation bytes, which
// are constant because the get_context operation carries no fields. It passes
// on origin/main too and is not evidence that the split happened.
True(
    !string.Equals(
        contextRequest.IdempotencyKey,
        UserAutomationOperatorRequest.DeriveIdempotencyKey(contextRequest.Operation),
        StringComparison.Ordinal),
    "get_context handshake identity is a per-call nonce, not the constant digest of its operation bytes");
// The UI read path at the MINT level: `list` is a business request (it is not
// the handshake), so it carries a closed fence AND the digest-derived key and is
// admitted. This case pins the mint and the validator gate with the harness
// witness `userAutomationFence`, which STANDS IN for the fence a handshake
// returns; the fence that a `get_context` answer actually returns is proven
// end to end by "UI read path business request carries the exact fence the
// get_context answer returned".
True(
    AcceptsCurrentIdentity(
        UserAutomationOperatorRequest.Create(new UserAutomationListOperation(false), userAutomationFence)),
    "UI read path business request minted with the harness State Fence witness passes identity validation");
// The UI effect path at the same level: `pause` is an owner mutation, so it must
// clear the same invariant as the read, and both UI paths mint through
// `Create(operation, fence)` and are gated by the same validator at the
// transport boundary, so proving only the read would leave the mutation path
// unproven. This case likewise pins the mint and the validator gate with the
// harness witness, and the fence a handshake actually returns on the effect
// path is proven end to end by "UI effect path business request carries the
// exact fence the get_context answer returned".
True(
    AcceptsCurrentIdentity(
        UserAutomationOperatorRequest.Create(
            new UserAutomationPauseOperation("00000000-0000-0000-0000-000000000003", "rev-1"),
            userAutomationFence)),
    "UI effect path business request minted with the harness State Fence witness passes identity validation");
// The split must not weaken the business side. A syntactically valid key that
// is not this operation's digest -- the exact shape an edited or corrupted
// journal entry carries -- names a DIFFERENT logical mutation, so it is
// refused here and can never reach the transport under that identity. The
// refusal must be the digest check itself (`UserAutomationContracts.cs:760`),
// which is reachable only because the key passes `RequireOperationId` first.
True(
    RefusesCurrentIdentity(
        new UserAutomationOperatorRequest(
            new UserAutomationListOperation(false),
            Guid.NewGuid().ToString("N"),
            userAutomationFence),
        "idempotency_key does not name the retained typed operation."),
    "business request whose key is not its operation digest is refused");
// The handshake half of the split is narrow, not absent. The handshake exists
// precisely to obtain the fence, so a get_context request that already carries
// one is not the read this route defines. The expected sentence is the one at
// `UserAutomationContracts.cs:694`, so this case cannot pass on the key-syntax
// or digest rule instead: the key handed here is syntactically valid and the
// digest rule is skipped for the handshake.
True(
    RefusesCurrentIdentity(
        new UserAutomationOperatorRequest(
            new UserAutomationGetContextOperation(),
            Guid.NewGuid().ToString("N"),
            userAutomationFence),
        "get_context must omit expected_state_fence"),
    "get_context request carrying an expected_state_fence is still refused");
// ...and the handshake key is still checked for syntax. The split relaxed the
// DIGEST relation for the handshake, never the operation-identity rule that
// every key in this application is 32 lowercase hex characters; this literal is
// neither 32 characters nor hex, so `RequireOperationId`
// (`OperatorIntent.cs:86`, reached from `UserAutomationContracts.cs:689`)
// refuses it, and the expected sentence below names exactly that check.
True(
    RefusesCurrentIdentity(
        new UserAutomationOperatorRequest(
            new UserAutomationGetContextOperation(),
            "not-a-32-hex-operation-id",
            ExpectedStateFence: null),
        "Operator intent requires one 32-character hex operation identity."),
    "get_context request with a syntactically invalid key is still refused");
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

// UI EFFECT PATH, end to end through the real view model. `pause` is the
// production entry point for a UserAutomation mutation:
// `BuildUserAutomationOperation` maps it to `UserAutomationPauseOperation`
// (MainViewModel.cs:1201) and that operation's `IsEffect()` is true
// (UserAutomationContracts.cs:162), so `SubmitUserAutomationAsync` takes the
// effect branch at MainViewModel.cs:802-845 -- fresh context fence, one
// retry-stable identity, journal that exact request, transmit it. That branch
// needs no live pipe: the only two gates before the send are the command grant,
// which `CanIssueCommands` reports true for an unauthenticated client because
// `_roleBinding is null` (MainViewModel.cs:302), and the pending journal, which
// this fixture does not construct, so `TryPersistPendingState` returns true
// (MainViewModel.cs:2023). Nothing private is called and no production member
// was added to reach it. It sits after every other conformance assertion
// because the effect deliberately leaves one retained operation behind.
// Production entry point: `MainViewModel.RunUserAutomationAsync` selects this
// closed kind through its `UserAutomationOperation` property and builds the
// operation in `BuildUserAutomationOperation`, so nothing below is a
// hand-built request.
viewModel.UserAutomationOperation = "pause";
viewModel.UserAutomationId = "00000000-0000-0000-0000-000000000003";
viewModel.UserAutomationRevision = "rev-1";
await viewModel.RunUserAutomationAsync();
True(
    client.LastUserAutomation is UserAutomationPauseOperation pauseOperation
        && pauseOperation.IsEffect(),
    "UI effect path submitted an operation whose IsEffect() is true");
True(
    client.LastBusinessStateFence is { } effectFence
        && JsonElement.DeepEquals(effectFence, userAutomationFence),
    "UI effect path business request carries the exact fence the get_context answer returned");

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

// Not an assertion and neither helper moves a counter; only the `True` and
// `Equal` helpers above touch it. They report only whether
// `UserAutomationOperatorRequest.ValidateCurrentIdentity` — the exact validator
// `GovernorPipeClient.UserAutomationAsync` calls at the transport boundary —
// admitted or refused the supplied request.
//
// `RefusesCurrentIdentity` mirrors `RefusesCapabilities` above in two ways and
// they are both load-bearing. It catches only the typed
// `InvalidOperationException` that validator throws, so every other exception
// type propagates and can never be read as a refusal. And it compares the WHOLE
// message against the exact production sentence supplied by the call site:
// without that filter a refusal for the WRONG reason would pass silently, so
// each case pins WHICH check refused rather than merely that something refused.
//
// The comparison is an ordinal whole-message equality. That is deliberately
// stricter than the prefix tests the framing cases above use
// (`error.Reason.StartsWith("unknown:")` and `StartsWith("duplicate:")`,
// which admit any reason under those prefixes); the closer precedent in this
// file is `RefusesCapabilities`' `error.Code == "endpoint_invalid"` below.
//
// A case passes only when production throws exactly the sentence named at that
// call site, and the three literals are byte-exact copies of the production
// sentences at `UserAutomationContracts.cs:760` (digest mismatch),
// `UserAutomationContracts.cs:694` (fence on the handshake) and
// `OperatorIntent.cs:86` (key syntax). As a secondary note the three are also
// neither substrings nor prefixes of one another, but that is not what makes the
// filter sound: under whole-string equality the literals must simply equal the
// production prose.
//
// The filter lives in the `when` clause, so a refusal carrying a DIFFERENT
// sentence is not returned as false — it propagates and the run dies on the raw
// `InvalidOperationException` instead of a labelled assertion failure. That is
// deliberate: a mismatched sentence means production prose changed and has to be
// looked at, not absorbed into a passing run.
bool AcceptsCurrentIdentity(UserAutomationOperatorRequest request)
{
    request.ValidateCurrentIdentity();
    return true;
}

bool RefusesCurrentIdentity(UserAutomationOperatorRequest request, string expectedRefusal)
{
    try { request.ValidateCurrentIdentity(); }
    catch (InvalidOperationException error) when (string.Equals(error.Message, expectedRefusal, StringComparison.Ordinal))
    {
        return true;
    }

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

    // The one closed owner State Fence witness, assigned by the top-level code
    // from its own local so the fence is defined exactly once in this file.
    public JsonElement? UserAutomationFence { get; set; }

    // The `expected_state_fence` the client OBSERVED on the most recent
    // BUSINESS request; a `get_context` handshake leaves it untouched. It is a
    // capture point and deliberately not an assertion of its own: on its own it
    // would only restate that a business request arrived. Each of the two
    // end-to-end assertions compares this OBSERVED fence against the witness
    // the fake ADMITTED in its own handshake answer, byte for byte. Those two
    // values are the same object today by construction -- the fake hands back
    // its `UserAutomationFence` property -- so the comparison is not two
    // independent owner values happening to agree; what it proves is the round
    // trip, that the fence the handshake answer admitted is the fence the view
    // model then carried into the business request.
    public JsonElement? LastBusinessStateFence { get; private set; }
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
        UserAutomationCount++;
        LastUserAutomation = request.Operation;

        // Both answers below are the CLOSED seven-member result envelope
        // `OperatorScheduleContract.USER_AUTOMATION_RESULT_ENVELOPE_MEMBERS`
        // generates, because both production readers demand it:
        // `UserAutomationOutcomeClassifier.ReadContextStateFence` for the
        // handshake (UserAutomationScheduleContract.cs:1238) and
        // `HasCurrentResultEnvelope` for every business answer (:1801). A
        // three-member answer is not "admitted but degraded": the handshake
        // reader throws, `ReadFreshUserAutomationStateFenceAsync` (MainViewModel.cs:855)
        // propagates it and the read is abandoned at MainViewModel.cs:766.

        if (request.Operation is UserAutomationGetContextOperation)
        {
            var contextFence = UserAutomationFence
                ?? throw new InvalidOperationException("the fake owner has no State Fence witness to admit");
            // ReadContextStateFence requires, in order: the exact envelope
            // members; `wire_id`/`wire_version` equal to the current result
            // contract (:1239-1244); `status` == "known" (:1245-1246); a
            // `correlation` object with exactly the two generated members whose
            // `operation_id` is the Kernel-prefixed pending operation id and
            // whose `idempotency_key` is this request's key (:1247-1249,
            // MatchesResultCorrelation :1823-1829); a JSON-null `recovery`
            // (:1250-1251); a closed envelope `state_fence` (:1252-1253); and a
            // `value` with exactly the generated context members whose `outcome`
            // is "context" and whose nested `state_fence` is the SAME fence
            // (:1254-1262, SameStateFence :2703). `UserAutomationResultValidationContext.FromRequest`
            // (:1087-1095) is what mints the expected `user-automation-operation:{key}`
            // correlation id, so it is reproduced rather than spelled differently.
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
                value = new
                {
                    outcome = "context",
                    state_fence = contextFence
                },
                recovery = (object?)null
            }));
        }

        LastBusinessStateFence = request.ExpectedStateFence?.Clone();

        // The business answer is the owner's `not_retained` disposition, the
        // one closed `status: "known"` value `ReadKnownEnvelope` accepts for a
        // non-normalizing operation without any owner-minted digest:
        // `value` with exactly `accepted`/`outcome`/`reason`, `accepted` false,
        // `outcome` "not_retained" (a member of the generated
        // USER_AUTOMATION_RESULT_VALUE_OUTCOMES), a bounded reason, and a
        // JSON-null `recovery` (UserAutomationScheduleContract.cs:1398-1404).
        // The branches that WOULD answer a `list` or a `pause` as success are
        // not reachable here: the normalization value is gated on
        // `ExpectedOperationKind` being `normalize_schedule` or
        // `migrate_legacy_schedule` (:1521-1527), and the transition value
        // demands a Store canonical request hash, a write receipt and a full
        // bounded schedule revision that this harness cannot mint. The envelope
        // fence still echoes the submitted fence, which `HasCurrentResultEnvelope`
        // requires (:1811-1815).
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
            state_fence = request.ExpectedStateFence!.Value,
            value = new
            {
                accepted = false,
                outcome = "not_retained",
                reason = "the fake owner retains no Store record for this typed operation"
            },
            recovery = (object?)null
        }));
    }
}
