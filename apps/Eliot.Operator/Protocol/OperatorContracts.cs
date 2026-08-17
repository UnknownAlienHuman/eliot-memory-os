using System.Text.Json;
using System.Text.Json.Serialization;

namespace Eliot.Operator.Protocol;

public static class OperatorProtocol
{
    public const string SchemaVersion = "eliot-operator-contract-v1";
    public const string IpcProtocolVersion = "eliot-ipc-l3-v1";
    public const string PinnedContractHash = "3c1a50d6581e90838a2375fadd70f6868a499d48f4e83223613a0a5fdedf2278";
    public const int MaxPageSize = 100;
}

/// One broker-owned, one-shot UI binding. It contains no bearer credential.
public sealed record OperatorEndpoint(
    [property: JsonPropertyName("pipe_name")] string PipeName,
    [property: JsonPropertyName("broker_epoch")] ulong BrokerEpoch,
    [property: JsonPropertyName("interactive_session_id")] string InteractiveSessionId,
    [property: JsonPropertyName("handoff_nonce")] string HandoffNonce,
    [property: JsonPropertyName("role")] string Role,
    [property: JsonPropertyName("capabilities")] IReadOnlyList<string> Capabilities);

public sealed record OperatorContractResponse(
    [property: JsonPropertyName("schema_version")] string SchemaVersion,
    [property: JsonPropertyName("ipc_protocol_version")] string IpcProtocolVersion,
    [property: JsonPropertyName("protocol_hash")] string ProtocolHash,
    [property: JsonPropertyName("manifest")] JsonElement Manifest);

public sealed record TaskContractView(
    [property: JsonPropertyName("task_id")] string TaskId,
    [property: JsonPropertyName("project_id")] string ProjectId,
    [property: JsonPropertyName("title")] string Title,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("memory_revision")] ulong MemoryRevision,
    [property: JsonPropertyName("acceptance_items")] IReadOnlyList<JsonElement> AcceptanceItems);

public sealed record ActiveDecisionStateView(
    [property: JsonPropertyName("packet_id")] string PacketId,
    [property: JsonPropertyName("next_allowed_action")] string NextAllowedAction,
    [property: JsonPropertyName("expected_observable")] string ExpectedObservable,
    [property: JsonPropertyName("verifier")] string Verifier,
    [property: JsonPropertyName("stop_condition")] string StopCondition,
    [property: JsonPropertyName("open_unknowns")] IReadOnlyList<string> OpenUnknowns);

public sealed record EpistemicPacketView(
    [property: JsonPropertyName("supported")] IReadOnlyList<string> Supported,
    [property: JsonPropertyName("assumed")] IReadOnlyList<string> Assumed,
    [property: JsonPropertyName("conflicted")] IReadOnlyList<string> Conflicted,
    [property: JsonPropertyName("unknown")] IReadOnlyList<string> Unknown);

public sealed record TaskCognitionView(
    [property: JsonPropertyName("task_contract")] TaskContractView TaskContract,
    [property: JsonPropertyName("active_decision_state")] ActiveDecisionStateView? ActiveDecisionState,
    [property: JsonPropertyName("epistemic_state")] EpistemicPacketView EpistemicState);

public sealed record MemoryInspectorView(
    [property: JsonPropertyName("active_current_claim_refs")] IReadOnlyList<string> ActiveCurrentClaimRefs,
    [property: JsonPropertyName("recalled_candidate_refs")] IReadOnlyList<string> RecalledCandidateRefs,
    [property: JsonPropertyName("stale_or_superseded_refs")] IReadOnlyList<string> StaleOrSupersededRefs);

public sealed record AgentRoutingView(
    [property: JsonPropertyName("host_session_refs")] IReadOnlyList<string> HostSessionRefs,
    [property: JsonPropertyName("task_role_lease_refs")] IReadOnlyList<string> TaskRoleLeaseRefs,
    [property: JsonPropertyName("work_or_action_lease_refs")] IReadOnlyList<string> WorkOrActionLeaseRefs,
    [property: JsonPropertyName("route_policies")] IReadOnlyList<JsonElement> RoutePolicies,
    [property: JsonPropertyName("route_decisions")] IReadOnlyList<JsonElement> RouteDecisions,
    [property: JsonPropertyName("agent_results")] IReadOnlyList<JsonElement> AgentResults,
    [property: JsonPropertyName("agent_result_dispositions")] IReadOnlyList<JsonElement> AgentResultDispositions);

public sealed record AutonomyRunContractView(
    [property: JsonPropertyName("autonomy_run_id")] string AutonomyRunId,
    [property: JsonPropertyName("project_id")] string ProjectId,
    [property: JsonPropertyName("root_task_id")] string RootTaskId,
    [property: JsonPropertyName("user_goal")] string UserGoal,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("state_revision")] ulong StateRevision);

public sealed record AutonomyRunView(
    [property: JsonPropertyName("contract")] AutonomyRunContractView Contract,
    [property: JsonPropertyName("work_item_refs")] IReadOnlyList<string> WorkItemRefs,
    [property: JsonPropertyName("assignment_refs")] IReadOnlyList<string> AssignmentRefs,
    [property: JsonPropertyName("verifier_result_refs")] IReadOnlyList<string> VerifierResultRefs,
    [property: JsonPropertyName("finish_status")] string FinishStatus);

public sealed record ApprovalView(
    [property: JsonPropertyName("approval_id")] string ApprovalId,
    [property: JsonPropertyName("exact_action_hash")] string ExactActionHash,
    [property: JsonPropertyName("risk_tier")] string RiskTier,
    [property: JsonPropertyName("reason_summary")] string ReasonSummary);

public sealed record TraceTimelineView(
    [property: JsonPropertyName("cursor")] string? Cursor,
    [property: JsonPropertyName("next_cursor")] string? NextCursor,
    [property: JsonPropertyName("event_refs")] IReadOnlyList<string> EventRefs,
    [property: JsonPropertyName("incident_refs")] IReadOnlyList<string> IncidentRefs);

public sealed record OperatorSnapshot(
    [property: JsonPropertyName("schema_version")] string SchemaVersion,
    [property: JsonPropertyName("protocol_version")] string ProtocolVersion,
    [property: JsonPropertyName("protocol_hash")] string ProtocolHash,
    [property: JsonPropertyName("runtime_id")] string RuntimeId,
    [property: JsonPropertyName("auth_generation")] string AuthGeneration,
    [property: JsonPropertyName("health_refs")] IReadOnlyList<string> HealthRefs,
    [property: JsonPropertyName("task_cognition")] IReadOnlyList<TaskCognitionView> TaskCognition,
    [property: JsonPropertyName("memory_inspector")] MemoryInspectorView? MemoryInspector,
    [property: JsonPropertyName("routing")] AgentRoutingView Routing,
    [property: JsonPropertyName("runs")] IReadOnlyList<AutonomyRunView> Runs,
    [property: JsonPropertyName("approvals")] IReadOnlyList<ApprovalView> Approvals,
    [property: JsonPropertyName("timeline")] TraceTimelineView Timeline);

public sealed record OperatorProjectionFilter(
    [property: JsonPropertyName("search")] string? Search = null,
    [property: JsonPropertyName("record_kind")] string? RecordKind = null,
    [property: JsonPropertyName("status")] string? Status = null,
    [property: JsonPropertyName("lifecycle")] string? Lifecycle = null,
    [property: JsonPropertyName("authority")] string? Authority = null,
    [property: JsonPropertyName("observed_after")] string? ObservedAfter = null,
    [property: JsonPropertyName("observed_before")] string? ObservedBefore = null);

public sealed record OperatorQueryRequest(
    [property: JsonPropertyName("projection")] string Projection,
    [property: JsonPropertyName("project_id")] string? ProjectId,
    [property: JsonPropertyName("task_id")] string? TaskId,
    [property: JsonPropertyName("filter")] OperatorProjectionFilter Filter,
    [property: JsonPropertyName("cursor")] string? Cursor,
    [property: JsonPropertyName("page_size")] int PageSize,
    [property: JsonPropertyName("query_operation")] string? QueryOperation = null,
    [property: JsonPropertyName("query_parameters")] JsonElement? QueryParameters = null,
    [property: JsonPropertyName("result_mode")] string ResultMode = "human",
    [property: JsonPropertyName("selected_ref")] string? SelectedRef = null,
    [property: JsonPropertyName("expand_depth")] int ExpandDepth = 1);

public sealed record OperatorFieldView(
    [property: JsonPropertyName("label")] string Label,
    [property: JsonPropertyName("value")] string Value,
    [property: JsonPropertyName("copyable")] bool Copyable);

public sealed record OperatorRelationshipView(
    [property: JsonPropertyName("relation")] string Relation,
    [property: JsonPropertyName("target_ref")] string TargetRef,
    [property: JsonPropertyName("evidence_ref")] string? EvidenceRef,
    [property: JsonPropertyName("observed_at")] string? ObservedAt)
{
    public string EvidenceSummary => string.IsNullOrWhiteSpace(EvidenceRef) ? "Evidence: not recorded" : $"Evidence: {EvidenceRef}";
    public string ObservedSummary => string.IsNullOrWhiteSpace(ObservedAt) ? "Observed: not recorded" : $"Observed: {ObservedAt}";
}

public sealed record OperatorActionView(
    [property: JsonPropertyName("command")] string Command,
    [property: JsonPropertyName("label")] string Label,
    [property: JsonPropertyName("risk_tier")] string RiskTier,
    [property: JsonPropertyName("requires_reason")] bool RequiresReason,
    [property: JsonPropertyName("requires_exact_action_hash")] bool RequiresExactActionHash);

public sealed record OperatorRecordView(
    [property: JsonPropertyName("record_ref")] string RecordRef,
    [property: JsonPropertyName("record_kind")] string RecordKind,
    [property: JsonPropertyName("title")] string Title,
    [property: JsonPropertyName("summary")] string Summary,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("lifecycle")] string? Lifecycle,
    [property: JsonPropertyName("authority")] string Authority,
    [property: JsonPropertyName("observed_at")] string? ObservedAt,
    [property: JsonPropertyName("fields")] IReadOnlyList<OperatorFieldView> Fields,
    [property: JsonPropertyName("relationships")] IReadOnlyList<OperatorRelationshipView> Relationships,
    [property: JsonPropertyName("actions")] IReadOnlyList<OperatorActionView> Actions)
{
    public string AccessibleSummary => $"{RecordKind}: {Title}. Status {Status}. {Summary}";
}

public sealed record OperatorProjectionPage(
    [property: JsonPropertyName("schema_version")] string SchemaVersion,
    [property: JsonPropertyName("runtime_id")] string RuntimeId,
    [property: JsonPropertyName("auth_generation")] string AuthGeneration,
    [property: JsonPropertyName("projection")] string Projection,
    [property: JsonPropertyName("project_id")] string? ProjectId,
    [property: JsonPropertyName("task_id")] string? TaskId,
    [property: JsonPropertyName("task_revision")] ulong? TaskRevision,
    [property: JsonPropertyName("cursor")] string? Cursor,
    [property: JsonPropertyName("next_cursor")] string? NextCursor,
    [property: JsonPropertyName("page_size")] int PageSize,
    [property: JsonPropertyName("returned")] int Returned,
    [property: JsonPropertyName("total_matching")] int TotalMatching,
    [property: JsonPropertyName("total_is_exact")] bool TotalIsExact,
    [property: JsonPropertyName("truncated")] bool Truncated,
    [property: JsonPropertyName("records")] IReadOnlyList<OperatorRecordView> Records,
    [property: JsonPropertyName("result_mode")] string ResultMode,
    [property: JsonPropertyName("result_payload")] JsonElement? ResultPayload,
    [property: JsonPropertyName("generated_at")] DateTimeOffset GeneratedAt);

public sealed record McpToolResult([property: JsonPropertyName("structuredContent")] JsonElement StructuredContent);
public sealed record JsonRpcResponse<T>([property: JsonPropertyName("result")] T? Result, [property: JsonPropertyName("error")] JsonElement? Error);
