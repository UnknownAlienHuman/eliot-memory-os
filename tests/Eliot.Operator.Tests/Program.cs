using System.Globalization;
using System.IO.Pipes;
using System.Text;
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

// ---------------------------------------------------------------------------
// #1777 acceptance: the authenticated WinUI session binding (I11.8, I11.3).
//
// One fixture serves all four cases. `BrokerWireDouble` is the OWNER side of
// the broker pipe the production client connects to: it binds the owner-issued
// pipe name, reads the owner's preface and the two requests the client writes,
// and answers with the broker's own `challenge` and `redeemed` objects. Every
// value it sends is either the endpoint the client presented, the Kernel
// session token it minted for that one exchange, or the identity this process
// actually observes. It introduces no DTO, no field name, no protocol step and
// no fault code, and it does not stand in for the Kernel: what is proved here
// is the client side of the binding, which is the only side this file owns.
// ---------------------------------------------------------------------------

var operatorIdentity = OperatorProcessIdentityProvider.Current;
var operatorSessionId = operatorIdentity.LogonSessionId.ToString(CultureInfo.InvariantCulture);
var openBrokerPipes = new List<BrokerWireDouble>();
using var bindingWindow = new CancellationTokenSource(TimeSpan.FromSeconds(60));

// A fresh owner-issued handoff for each case: its own pipe name, its own nonce
// and its own requested capability set, all bound to THIS process's observed
// logon session so the client's session check is a real comparison and not a
// tautology.
OperatorEndpoint BrokerIssuedEndpoint(IReadOnlyList<string> capabilities) => new(
    @"\\.\pipe\eliot\operator\binding-" + Guid.NewGuid().ToString("N"),
    7,
    operatorSessionId,
    "nonce-" + Guid.NewGuid().ToString("N"),
    OperatorCapabilityNames.HumanOperatorRole,
    capabilities);

// CASE 1 - POSITIVE. A binding redeemed from a fresh Kernel-backed handoff
// yields exactly the granted role/capability set: no member of the requested
// set is dropped and no member beyond it is added.
var fullCapabilities = new[] { OperatorCapabilityNames.ControlboardRead, OperatorCapabilityNames.OperatorCommand };
var freshEndpoint = BrokerIssuedEndpoint(fullCapabilities);
var freshBroker = new BrokerWireDouble(freshEndpoint, "kernel-token-first", staleKernelSessionToken: null);
openBrokerPipes.Add(freshBroker);
var freshServing = freshBroker.ServeAsync(bindingWindow.Token);
var freshSession = await BrokerPipeClient.RedeemOperatorHandoffAsync(
    freshEndpoint, operatorIdentity, bindingWindow.Token);
await freshServing;
Equal(1, freshBroker.Challenges, "case 1: a fresh Kernel-backed binding runs one challenge exchange");
Equal(1, freshBroker.Redemptions, "case 1: a fresh Kernel-backed binding is redeemed exactly once");
var presentedEndpoint = freshBroker.PresentedEndpoint;
True(presentedEndpoint is not null, "case 1: redemption presented the owner-issued endpoint");
Equal(freshEndpoint.PipeName, presentedEndpoint!.PipeName, "case 1: redemption presented the owner-issued pipe name verbatim");
Equal(freshEndpoint.HandoffNonce, presentedEndpoint!.HandoffNonce, "case 1: redemption presented the owner-issued handoff nonce verbatim");
Equal(freshEndpoint.BrokerEpoch, presentedEndpoint!.BrokerEpoch, "case 1: redemption presented the owner-issued registration epoch verbatim");
Equal("kernel-token-first", freshBroker.RedeemedKernelToken, "case 1: redemption presented this exchange's Kernel session token");
var grantedPrincipal = BrokerPipeClient.RetainedPrincipal;
True(grantedPrincipal is not null, "case 1: a redeemed binding retains the broker-issued Human principal");
True(
    ReferenceEquals(grantedPrincipal, freshSession.Principal),
    "case 1: the retained principal is the one this exchange produced");
Equal(operatorIdentity.UserSid, grantedPrincipal!.Principal, "case 1: the retained principal is this process's authenticated user SID");
Equal(operatorSessionId, grantedPrincipal.InteractiveSessionId, "case 1: the retained principal is bound to this interactive session");
Equal("kernel-token-first", grantedPrincipal.KernelSessionToken, "case 1: the retained principal carries this exchange's Kernel session token");
Equal(OperatorCapabilityNames.HumanOperatorRole, grantedPrincipal.Grant.Role, "case 1: the granted role is the broker-granted role");
Equal(fullCapabilities.Length, grantedPrincipal.Grant.Capabilities.Count, "case 1: the granted set carries no member beyond the requested set");
for (var capability = 0; capability < fullCapabilities.Length; capability++)
{
    Equal(fullCapabilities[capability], grantedPrincipal.Grant.Capabilities[capability], $"case 1: granted capability {capability} is the requested capability");
}
True(grantedPrincipal.Grant.GrantsCommands, "case 1: the granted set grants operator.command");

// The UI gates on that GRANT, so the same grant that redemption produced is
// the one handed to the view model: nothing here is invented for the UI.
var grantedClient = new FakeGovernorClient { GrantedBinding = grantedPrincipal.Grant };
var grantedViewModel = new MainViewModel(grantedClient)
{
    ProjectId = "00000000-0000-0000-0000-000000000001",
    TaskId = "00000000-0000-0000-0000-000000000002"
};
await grantedViewModel.SelectSectionAsync("autonomy");
True(grantedViewModel.CanIssueCommands, "case 1: the broker-granted set lets the UI offer the command");
grantedViewModel.SelectedRecord = grantedViewModel.Records[0];
grantedViewModel.SelectedAction = grantedViewModel.SelectedRecord.Actions[0];
await grantedViewModel.ExecuteSelectedActionAsync();
Equal(1, grantedClient.CommandCount, "case 1: the authorized request is submitted once as a typed operator intent");

// CASE 2 - RESTART. Releasing the binding is what `GovernorPipeClient.DisposeAsync`
// does, so this is the restart shape: a new instance holds no retained principal
// and has to earn a fresh challenge and a fresh Kernel session token, and nothing
// from the previous instance survives into the new one.
BrokerPipeClient.ReleaseOperatorBinding();
True(BrokerPipeClient.RetainedPrincipal is null, "case 2: a released binding retains no Human principal");
True(!freshSession.IsLive, "case 2: the previous instance's session is no longer live");
await using (var restartedClient = new GovernorPipeClient(new RuntimeDiscoveryService()))
{
    True(restartedClient.GrantedBinding is null, "case 2: a new client instance holds no granted binding");
}
var restartedEndpoint = BrokerIssuedEndpoint(fullCapabilities);
var restartedBroker = new BrokerWireDouble(restartedEndpoint, "kernel-token-second", staleKernelSessionToken: null);
openBrokerPipes.Add(restartedBroker);
var restartedServing = restartedBroker.ServeAsync(bindingWindow.Token);
var restartedSession = await BrokerPipeClient.RedeemOperatorHandoffAsync(
    restartedEndpoint, operatorIdentity, bindingWindow.Token);
await restartedServing;
var restartedPrincipal = BrokerPipeClient.RetainedPrincipal;
True(restartedPrincipal is not null, "case 2: the restarted UI earns a fresh Kernel-backed binding");
True(
    ReferenceEquals(restartedPrincipal, restartedSession.Principal),
    "case 2: the fresh binding is the one the new exchange produced");
True(!ReferenceEquals(restartedPrincipal, grantedPrincipal), "case 2: nothing from the previous instance survives");
Equal(1, restartedBroker.Challenges, "case 2: the restarted UI runs a fresh challenge, not the spent one");
Equal("kernel-token-second", restartedBroker.RedeemedKernelToken, "case 2: the fresh exchange presented its own newly issued token");
Equal("kernel-token-second", restartedPrincipal!.KernelSessionToken, "case 2: the restarted UI holds the newly issued Kernel session token");
True(
    restartedPrincipal.KernelSessionToken != grantedPrincipal.KernelSessionToken,
    "case 2: the restarted UI holds a new Kernel session token, not the previous one");
Equal(restartedEndpoint.HandoffNonce, restartedBroker.PresentedEndpoint?.HandoffNonce, "case 2: the fresh exchange ran against a fresh owner-issued handoff");

// CASE 3 - REFUSAL, STALE/ABSENT. Two arms, both refused before any state
// change and both reported as the dispositions the branch already publishes.
//
// (a) No retained principal and no inherited handoff: the state-changing route
// is refused at establishment with the existing typed disposition. No new fault
// code is introduced and no binding is established.
BrokerPipeClient.ReleaseOperatorBinding();
True(BrokerPipeClient.RetainedPrincipal is null, "case 3: no Human principal is retained before the refused command");
Environment.SetEnvironmentVariable(RuntimeDiscoveryService.EndpointEnvironmentVariable, null);
await using (var refusingClient = new GovernorPipeClient(new RuntimeDiscoveryService()))
{
    OperatorRestartRequiredException? refusal = null;
    try
    {
        await refusingClient.CommandAsync(OperatorIntentEnvelope.Create(
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            7,
            JsonSerializer.SerializeToElement(new { command = "resume_run" })));
    }
    catch (OperatorRestartRequiredException error)
    {
        refusal = error;
    }
    True(refusal is not null, "case 3: a state-changing route with no retained principal is refused");
    Equal(
        OperatorHandoff.ReacquisitionRequirement,
        refusal!.Reason,
        "case 3: the refusal reports the existing reacquisition disposition, not a new fault code");
    True(refusingClient.GrantedBinding is null, "case 3: the refused command established no binding and sent nothing");
}

// (b) A stale token: the exchange answers `redeemed` with the PREVIOUS
// instance's Kernel session token instead of the one this challenge minted.
// The redemption is refused and nothing is retained.
var staleEndpoint = BrokerIssuedEndpoint(fullCapabilities);
var staleBroker = new BrokerWireDouble(staleEndpoint, "kernel-token-third", staleKernelSessionToken: "kernel-token-second");
openBrokerPipes.Add(staleBroker);
var staleServing = staleBroker.ServeAsync(bindingWindow.Token);
OperatorRestartRequiredException? staleRefusal = null;
try
{
    await BrokerPipeClient.RedeemOperatorHandoffAsync(staleEndpoint, operatorIdentity, bindingWindow.Token);
}
catch (OperatorRestartRequiredException error)
{
    staleRefusal = error;
}
await staleServing;
True(staleRefusal is not null, "case 3: a redemption answered with a stale Kernel session token is refused");
Equal(
    OperatorFaultReason.HandshakeRefused,
    staleRefusal!.Reason,
    "case 3: the stale-token refusal is the existing handshake-refused disposition");
Equal(1, staleBroker.Redemptions, "case 3: the stale-token answer was refused at redemption");
True(BrokerPipeClient.RetainedPrincipal is null, "case 3: a refused redemption retains no principal");

// CASE 4 - REFUSAL, CAPABILITY. The read-only subset is a real admitted
// endpoint shape (`RuntimeDiscoveryService.ValidateEndpoint` admits any
// non-empty subset of the closed vocabulary), so a read-only broker-issued
// binding is reachable and its `operator.command` is simply not granted. The
// capability is compared against the GRANTED set, not against a shape, and the
// UI withholds the command before anything is journaled or sent.
var readOnlyCapabilities = new[] { OperatorCapabilityNames.ControlboardRead };
var readOnlyEndpoint = BrokerIssuedEndpoint(readOnlyCapabilities);
var readOnlyBroker = new BrokerWireDouble(readOnlyEndpoint, "kernel-token-readonly", staleKernelSessionToken: null);
openBrokerPipes.Add(readOnlyBroker);
var readOnlyServing = readOnlyBroker.ServeAsync(bindingWindow.Token);
var readOnlySession = await BrokerPipeClient.RedeemOperatorHandoffAsync(
    readOnlyEndpoint, operatorIdentity, bindingWindow.Token);
await readOnlyServing;
var readOnlyPrincipal = BrokerPipeClient.RetainedPrincipal;
True(readOnlyPrincipal is not null, "case 4: the read-only broker-issued binding retains its own principal");
True(
    ReferenceEquals(readOnlyPrincipal, readOnlySession.Principal),
    "case 4: the retained principal is the one the read-only exchange produced");
Equal(readOnlyCapabilities.Length, readOnlyPrincipal!.Grant.Capabilities.Count, "case 4: the granted set carries exactly the read-only member");
Equal(OperatorCapabilityNames.ControlboardRead, readOnlyPrincipal.Grant.Capabilities[0], "case 4: the granted member is controlboard.read");
True(!readOnlyPrincipal.Grant.Grants(OperatorCapabilityNames.OperatorCommand), "case 4: operator.command is not granted to this role");
True(!readOnlyPrincipal.Grant.GrantsCommands, "case 4: the granted set grants no command");

var withheldClient = new FakeGovernorClient { GrantedBinding = readOnlyPrincipal.Grant };
var withheldViewModel = new MainViewModel(withheldClient)
{
    ProjectId = "00000000-0000-0000-0000-000000000001",
    TaskId = "00000000-0000-0000-0000-000000000002"
};
await withheldViewModel.SelectSectionAsync("autonomy");
True(!withheldViewModel.CanIssueCommands, "case 4: the UI withholds the command from a role not granted operator.command");
withheldViewModel.SelectedRecord = withheldViewModel.Records[0];
withheldViewModel.SelectedAction = withheldViewModel.SelectedRecord.Actions[0];
await withheldViewModel.ExecuteSelectedActionAsync();
Equal(0, withheldClient.CommandCount, "case 4: the capability-expanded request is refused before any state change");
Equal("Command withheld for this role", withheldViewModel.StatusTitle, "case 4: the refusal is stated rather than silently dropped");
True(
    withheldViewModel.StatusMessage.Contains("nothing was journaled and nothing was sent", StringComparison.Ordinal),
    "case 4: nothing was journaled and nothing was sent");

BrokerPipeClient.ReleaseOperatorBinding();
foreach (var openBrokerPipe in openBrokerPipes)
{
    openBrokerPipe.Dispose();
}

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

    // This fake has no broker-authenticated transport of its own, so it
    // defaults to no binding: the production client reports null for any
    // connection that is not live and authenticated, and null never
    // authorizes: callers treat it as "let the transport authenticate",
    // never as a capability. Fabricating a binding here would grant the
    // harness capabilities no owner ever issued to it.
    //
    // It is settable because the #1777 binding cases hand the view model the
    // EXACT grant a real redemption against the owner-side pipe produced in
    // this same run, and nothing else. A read-only broker-issued grant makes
    // the UI withhold more authority than it did before, so no case can widen
    // what this fake has.
    public OperatorRoleBinding? GrantedBinding { get; set; }

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
        return Task.FromResult(JsonSerializer.SerializeToElement(new
        {
            accepted = true,
            executed = false,
            outcome = "typed_user_automation_operation_admitted"
        }));
    }
}

/// The owner side of ONE broker-pipe exchange, for the #1777 session-binding
/// cases. It binds the owner-issued pipe name, reads the owner's preface and
/// the two requests the client writes, and answers with the broker's own
/// `challenge` and `redeemed` objects, in the broker's field names and no
/// others.
///
/// It is a fixture, not a stub of the Kernel: it never decides authority. The
/// capability set it grants is exactly the set the endpoint asked for, because
/// that is the only grant the owner's minting path produces for this client
/// (`exact_operator_capabilities` in `eliot-user-broker-core`), and the Kernel
/// session token is the one value it mints for that single exchange. A
/// redemption that would have to be granted MORE than was asked for cannot be
/// expressed here, because the owner cannot mint it; the capability arm of the
/// acceptance is therefore proved on the admitted read-only subset, which the
/// owner does mint.
sealed class BrokerWireDouble : IDisposable
{
    private const string Preface = "ELIOT-BROKER-1";
    private const int MaxBufferedBytes = 65_536;

    private readonly NamedPipeServerStream _pipe;
    private readonly OperatorEndpoint _endpoint;
    private readonly string _kernelSessionToken;
    private readonly string _answerKernelSessionToken;
    private readonly string _userSid;
    private readonly string _sessionId;
    private readonly int _processId;
    private readonly List<byte> _buffered = [];
    private int _disposed;

    public BrokerWireDouble(
        OperatorEndpoint endpoint,
        string kernelSessionToken,
        string? staleKernelSessionToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        _endpoint = endpoint;
        _kernelSessionToken = kernelSessionToken;
        // A stale token is what a restart must NOT reuse: the answer then
        // carries the previous instance's token and the client must refuse it.
        _answerKernelSessionToken = staleKernelSessionToken ?? kernelSessionToken;
        var identity = OperatorProcessIdentityProvider.Current;
        _userSid = identity.UserSid;
        _sessionId = identity.LogonSessionId.ToString(CultureInfo.InvariantCulture);
        _processId = Environment.ProcessId;
        _pipe = new NamedPipeServerStream(
            endpoint.PipeName.Replace(@"\\.\pipe\", string.Empty, StringComparison.OrdinalIgnoreCase),
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
    }

    public int Challenges { get; private set; }
    public int Redemptions { get; private set; }
    /// The endpoint the CLIENT presented, captured from its own request bytes.
    public OperatorEndpoint? PresentedEndpoint { get; private set; }
    /// The Kernel session token the client carried back into redemption.
    public string? RedeemedKernelToken { get; private set; }

    public async Task ServeAsync(CancellationToken cancellationToken)
    {
        await _pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
        var preface = await ReadLineAsync(cancellationToken).ConfigureAwait(false);
        if (!string.Equals(preface, Preface, StringComparison.Ordinal))
        {
            throw new IOException("the client did not send the broker preface");
        }
        Challenges++;

        using (var challengeRequest = JsonDocument.Parse(await ReadLineAsync(cancellationToken).ConfigureAwait(false)))
        {
            PresentedEndpoint = challengeRequest.RootElement
                .GetProperty("endpoint")
                .Deserialize<OperatorEndpoint>(OperatorJson.Reader);
        }

        await WriteLineAsync(JsonSerializer.Serialize(new
        {
            status = "challenge",
            kernel_session_token = _kernelSessionToken,
            broker_epoch = _endpoint.BrokerEpoch,
            handoff_nonce = _endpoint.HandoffNonce,
            role = _endpoint.Role,
            capabilities = _endpoint.Capabilities
        }, OperatorJson.Writer), cancellationToken).ConfigureAwait(false);

        using var redeemRequest = JsonDocument.Parse(await ReadLineAsync(cancellationToken).ConfigureAwait(false));
        RedeemedKernelToken = redeemRequest.RootElement
            .GetProperty("client")
            .GetProperty("kernel_session_token")
            .GetString();
        Redemptions++;

        await WriteLineAsync(JsonSerializer.Serialize(new
        {
            status = "redeemed",
            principal = _userSid,
            interactive_session_id = _sessionId,
            client_process_id = _processId,
            kernel_session_token = _answerKernelSessionToken,
            role = _endpoint.Role,
            capabilities = _endpoint.Capabilities
        }, OperatorJson.Writer), cancellationToken).ConfigureAwait(false);
    }

    /// Reads exactly one framed line, keeping any bytes that arrived past its
    /// terminator: the client writes the preface and the first request without
    /// waiting in between, so one read can carry both.
    private async Task<string> ReadLineAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            for (var index = 0; index < _buffered.Count; index++)
            {
                if (_buffered[index] != (byte)'\n') continue;
                var line = Encoding.UTF8.GetString(_buffered.GetRange(0, index).ToArray());
                _buffered.RemoveRange(0, index + 1);
                return line;
            }
            var chunk = new byte[512];
            var read = await _pipe.ReadAsync(chunk.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new IOException("the client closed the broker pipe before its request");
            }
            _buffered.AddRange(chunk.AsSpan(0, read).ToArray());
            if (_buffered.Count > MaxBufferedBytes)
            {
                throw new IOException("a broker request exceeded the fixture's own buffer bound");
            }
        }
    }

    private async Task WriteLineAsync(string line, CancellationToken cancellationToken)
    {
        await _pipe
            .WriteAsync(Encoding.UTF8.GetBytes(line + "\n").AsMemory(), cancellationToken)
            .ConfigureAwait(false);
        await _pipe.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }
        try
        {
            _pipe.Dispose();
        }
        catch (Exception)
        {
            // The exchange is finished with this pipe; a close failure here is
            // not a conformance result and must not replace one.
        }
    }
}
