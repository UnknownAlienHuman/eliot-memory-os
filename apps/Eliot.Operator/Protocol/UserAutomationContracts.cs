using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Eliot.Operator.Protocol;

/// Closed UserAutomation operation surface carried by the authenticated
/// Governor command. It contains no principal, StateFence, Store receipt,
/// scheduler, provider credential, or ambient settings.
[JsonPolymorphic(TypeDiscriminatorPropertyName = "kind")]
[JsonDerivedType(typeof(UserAutomationCreateOperation), "create")]
[JsonDerivedType(typeof(UserAutomationListOperation), "list")]
[JsonDerivedType(typeof(UserAutomationStatusOperation), "status")]
[JsonDerivedType(typeof(UserAutomationHistoryOperation), "history")]
[JsonDerivedType(typeof(UserAutomationPauseOperation), "pause")]
[JsonDerivedType(typeof(UserAutomationResumeOperation), "resume")]
[JsonDerivedType(typeof(UserAutomationEditOperation), "edit")]
[JsonDerivedType(typeof(UserAutomationRunNowOperation), "run_now")]
[JsonDerivedType(typeof(UserAutomationRemoveOperation), "remove")]
[JsonDerivedType(typeof(UserAutomationInspectLastFailureOperation), "inspect_last_failure")]
public abstract record UserAutomationOperation
{
    public abstract void Validate();

    /// True when the operation is an effect rather than a read. Effects
    /// follow the owner's admission and approval policy and retain one
    /// operation identity until a terminal receipt; reads execute immediately
    /// inside existing authority and retain nothing.
    public abstract bool IsEffect { get; }
}

public sealed record UserAutomationCreateOperation(
    [property: JsonPropertyName("revision")] UserAutomationRevision Revision)
    : UserAutomationOperation
{
    public override void Validate() => Revision.Validate();

    public override bool IsEffect => true;
}

public sealed record UserAutomationListOperation(
    [property: JsonPropertyName("include_retired")] bool IncludeRetired)
    : UserAutomationOperation
{
    public override void Validate() { }

    public override bool IsEffect => false;
}

public sealed record UserAutomationStatusOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireText(AutomationId, "automation_id");

    public override bool IsEffect => false;
}

public sealed record UserAutomationHistoryOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireText(AutomationId, "automation_id");

    public override bool IsEffect => false;
}

public sealed record UserAutomationPauseOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId,
    [property: JsonPropertyName("automation_revision")] string AutomationRevision)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireIdentity(AutomationId, AutomationRevision);

    public override bool IsEffect => true;
}

public sealed record UserAutomationResumeOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId,
    [property: JsonPropertyName("automation_revision")] string AutomationRevision)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireIdentity(AutomationId, AutomationRevision);

    public override bool IsEffect => true;
}

public sealed record UserAutomationEditOperation(
    [property: JsonPropertyName("previous_revision")] UserAutomationRevision PreviousRevision,
    [property: JsonPropertyName("revision")] UserAutomationRevision Revision)
    : UserAutomationOperation
{
    public override void Validate()
    {
        PreviousRevision.Validate();
        Revision.Validate();
        if (!string.Equals(PreviousRevision.AutomationId, Revision.AutomationId, StringComparison.Ordinal)
            || !string.Equals(Revision.Supersedes, PreviousRevision.Revision, StringComparison.Ordinal)
            || string.Equals(PreviousRevision.Revision, Revision.Revision, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("UserAutomation edit must supersede one distinct revision of the same automation.");
        }
    }

    public override bool IsEffect => true;
}

public sealed record UserAutomationRunNowOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId,
    [property: JsonPropertyName("automation_revision")] string AutomationRevision,
    [property: JsonPropertyName("nonce")] string Nonce)
    : UserAutomationOperation
{
    public override void Validate()
    {
        UserAutomationContract.RequireIdentity(AutomationId, AutomationRevision);
        UserAutomationContract.RequireText(Nonce, "nonce");
    }

    public override bool IsEffect => true;
}

public sealed record UserAutomationRemoveOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId,
    [property: JsonPropertyName("automation_revision")] string AutomationRevision)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireIdentity(AutomationId, AutomationRevision);

    public override bool IsEffect => true;
}

public sealed record UserAutomationInspectLastFailureOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireText(AutomationId, "automation_id");

    public override bool IsEffect => false;
}

/// Exact authenticated UserAutomation front-door payload. The named route
/// adds the authenticated session, principal, request metadata, State Fence
/// and issued operation identity; the surface supplies only the closed
/// operation and one retry-stable idempotency key.
public sealed record UserAutomationOperatorRequest(
    [property: JsonPropertyName("operation")] UserAutomationOperation Operation,
    [property: JsonPropertyName("idempotency_key")] string IdempotencyKey)
{
    /// The retry-stable identity of one typed operation. It is derived from
    /// the exact canonical operation bytes, so a lost response, a transport
    /// reconnect or an operator resubmission of the same typed operation
    /// carries the SAME identity and cannot create a second logical mutation.
    /// Two genuinely different operations always differ, because the
    /// distinguishing field is part of the canonical bytes.
    public static string DeriveIdempotencyKey(UserAutomationOperation operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        operation.Validate();
        var canonical = JsonSerializer.Serialize(operation, OperatorJson.Writer);
        var bytes = Encoding.UTF8.GetBytes(canonical);
        if (bytes.Length > OperatorProtocol.MaxRetainedInputChars)
        {
            throw new InvalidOperationException("typed UserAutomation operation exceeds the canonical input bound");
        }
        var digest = SHA256.HashData(bytes);
        return Convert.ToHexString(digest.AsSpan(0, 16)).ToLowerInvariant();
    }

    public static UserAutomationOperatorRequest Create(UserAutomationOperation operation) =>
        new(operation, DeriveIdempotencyKey(operation));

    public void Validate()
    {
        Operation.Validate();
        OperatorIntentContract.RequireOperationId(IdempotencyKey);
    }
}

/// Typed immutable revision payload used only for create/edit operations. The
/// canonical owner still decides normalization, admission and identity.
public sealed record UserAutomationRevision(
    [property: JsonPropertyName("automation_id")] string AutomationId,
    [property: JsonPropertyName("revision")] string Revision,
    [property: JsonPropertyName("supersedes")] string? Supersedes,
    [property: JsonPropertyName("owner_principal")] string OwnerPrincipal,
    [property: JsonPropertyName("work_scope")] UserAutomationWorkScope WorkScope,
    [property: JsonPropertyName("natural_language_intent")] string NaturalLanguageIntent,
    [property: JsonPropertyName("schedule")] UserAutomationNormalizedSchedule Schedule,
    [property: JsonPropertyName("mode")] string Mode,
    [property: JsonPropertyName("task")] UserAutomationTaskBinding Task,
    [property: JsonPropertyName("portable_skill_package_revision_refs")] IReadOnlyList<string> PortableSkillPackageRevisionRefs,
    [property: JsonPropertyName("workdir_ref")] string WorkdirRef,
    [property: JsonPropertyName("route_cost_policy")] UserAutomationRouteCostPolicy RouteCostPolicy,
    [property: JsonPropertyName("provider_policy")] UserAutomationProviderPolicy ProviderPolicy,
    [property: JsonPropertyName("delivery_target")] UserAutomationDeliveryTarget DeliveryTarget,
    [property: JsonPropertyName("preflight_contract_revision")] string PreflightContractRevision,
    [property: JsonPropertyName("resource_ceiling")] UserAutomationResourceCeiling ResourceCeiling,
    [property: JsonPropertyName("overlap_policy")] string OverlapPolicy,
    [property: JsonPropertyName("recursion_policy")] UserAutomationRecursionPolicy RecursionPolicy,
    [property: JsonPropertyName("configuration_state")] string ConfigurationState,
    [property: JsonPropertyName("work_class")] string WorkClass,
    [property: JsonPropertyName("current_execution_refs")] IReadOnlyList<string> CurrentExecutionRefs,
    [property: JsonPropertyName("execution_history_query_ref")] string ExecutionHistoryQueryRef)
{
    public void Validate()
    {
        UserAutomationContract.RequireText(AutomationId, "automation_id");
        UserAutomationContract.RequireText(Revision, "revision");
        UserAutomationContract.RequireText(OwnerPrincipal, "owner_principal");
        UserAutomationContract.RequireText(NaturalLanguageIntent, "natural_language_intent");
        UserAutomationContract.RequireText(WorkdirRef, "workdir_ref");
        UserAutomationContract.RequireText(PreflightContractRevision, "preflight_contract_revision");
        UserAutomationContract.RequireText(ExecutionHistoryQueryRef, "execution_history_query_ref");
        UserAutomationContract.RequireOneOf(Mode, "mode", "AGENT", "DETERMINISTIC_PROCESS");
        UserAutomationContract.RequireOneOf(ConfigurationState, "configuration_state", "ACTIVE", "PAUSED", "BLOCKED_CONFIG", "RETIRED");
        UserAutomationContract.RequireOneOf(
            WorkClass,
            "work_class",
            "CONTROL",
            "INTERACTIVE",
            "VERIFICATION",
            "CANONICAL_WRITE",
            "NORMAL_BACKGROUND",
            "MODEL_JOBS",
            "SWARM",
            "REPORTING",
            "MAINTENANCE");
        UserAutomationContract.RequireOneOf(OverlapPolicy, "overlap_policy", "FORBID_OVERLAP", "QUEUE_ONE", "COALESCE_LATEST");
        if (Supersedes is not null) UserAutomationContract.RequireText(Supersedes, "supersedes");
        WorkScope.Validate();
        Schedule.Validate();
        Task.Validate();
        UserAutomationContract.RequireTextList(PortableSkillPackageRevisionRefs, "portable_skill_package_revision_refs");
        if (!string.Equals(WorkdirRef, WorkScope.WorkdirRef, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("workdir_ref must equal work_scope.workdir_ref.");
        }
        RouteCostPolicy.Validate();
        ProviderPolicy.Validate();
        DeliveryTarget.Validate();
        if (!string.Equals(PreflightContractRevision, UserAutomationContract.PreflightContractRevision, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("preflight_contract_revision is not the admitted UserAutomation contract.");
        }
        ResourceCeiling.Validate();
        RecursionPolicy.Validate();
        UserAutomationContract.RequireTextList(CurrentExecutionRefs, "current_execution_refs");
        if (CurrentExecutionRefs.Zip(CurrentExecutionRefs.Skip(1)).Any(pair => string.Equals(pair.First, pair.Second, StringComparison.Ordinal)))
        {
            throw new InvalidOperationException("current_execution_refs must not contain adjacent duplicates.");
        }
        if (Mode == "AGENT" && (Task.Kind != "AGENT_TASK" || ProviderPolicy is not UserAutomationAllowedProviderPolicy))
        {
            throw new InvalidOperationException("AGENT revisions require an agent task and allowed provider policy.");
        }
        if (Mode == "DETERMINISTIC_PROCESS"
            && (Task.Kind != "QUALIFIED_SCRIPT"
                || Task.CapabilityProfile.ModelAccess
                || Task.CapabilityProfile.ProviderAccess
                || Task.CapabilityProfile.AutomationScheduling
                || ProviderPolicy is not UserAutomationDeterministicOnlyProviderPolicy
                || WorkClass == "MODEL_JOBS"))
        {
            throw new InvalidOperationException("DETERMINISTIC_PROCESS revisions must exclude model, provider and scheduling access.");
        }
    }
}

public sealed record UserAutomationNormalizedSchedule(
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("expression")] string Expression,
    [property: JsonPropertyName("calendar")] string Calendar,
    [property: JsonPropertyName("timezone")] string Timezone,
    [property: JsonPropertyName("dst_fold")] string DstFold,
    [property: JsonPropertyName("dst_gap")] string DstGap,
    [property: JsonPropertyName("start_at")] string StartAt,
    [property: JsonPropertyName("end_at")] string? EndAt,
    [property: JsonPropertyName("next_occurrences")] IReadOnlyList<string> NextOccurrences)
{
    public void Validate()
    {
        UserAutomationContract.RequireOneOf(Kind, "schedule.kind", "ONE_SHOT", "RECURRING");
        UserAutomationContract.RequireText(Expression, "schedule.expression");
        UserAutomationContract.RequireText(Calendar, "schedule.calendar");
        UserAutomationContract.RequireText(Timezone, "schedule.timezone");
        UserAutomationContract.RequireOneOf(DstFold, "schedule.dst_fold", "FIRST", "SECOND", "REJECT");
        UserAutomationContract.RequireOneOf(DstGap, "schedule.dst_gap", "SHIFT_FORWARD", "REJECT");
        UserAutomationContract.RequireText(StartAt, "schedule.start_at");
        if (EndAt is not null) UserAutomationContract.RequireText(EndAt, "schedule.end_at");
        UserAutomationContract.RequireTextList(NextOccurrences, "schedule.next_occurrences");
        if (NextOccurrences.Count == 0 || NextOccurrences.Zip(NextOccurrences.Skip(1)).Any(pair => string.CompareOrdinal(pair.First, pair.Second) >= 0))
        {
            throw new InvalidOperationException("schedule.next_occurrences must be non-empty and strictly ordered.");
        }
        if (Kind == "ONE_SHOT" && NextOccurrences.Count != 1)
        {
            throw new InvalidOperationException("ONE_SHOT schedules require one next occurrence.");
        }
    }
}

public sealed record UserAutomationWorkScope(
    [property: JsonPropertyName("scope_id")] string ScopeId,
    [property: JsonPropertyName("product_id")] string ProductId,
    [property: JsonPropertyName("workdir_ref")] string WorkdirRef)
{
    public void Validate()
    {
        UserAutomationContract.RequireText(ScopeId, "work_scope.scope_id");
        UserAutomationContract.RequireText(ProductId, "work_scope.product_id");
        UserAutomationContract.RequireText(WorkdirRef, "work_scope.workdir_ref");
    }
}

public sealed record UserAutomationTaskBinding(
    [property: JsonPropertyName("qualified_ref")] string QualifiedRef,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("capability_profile")] UserAutomationCapabilityProfile CapabilityProfile)
{
    public void Validate()
    {
        UserAutomationContract.RequireText(QualifiedRef, "task.qualified_ref");
        UserAutomationContract.RequireOneOf(Kind, "task.kind", "AGENT_TASK", "QUALIFIED_SCRIPT");
        CapabilityProfile.Validate();
    }
}

public sealed record UserAutomationCapabilityProfile(
    [property: JsonPropertyName("model_access")] bool ModelAccess,
    [property: JsonPropertyName("provider_access")] bool ProviderAccess,
    [property: JsonPropertyName("automation_scheduling")] bool AutomationScheduling)
{
    public void Validate() { }
}

[JsonPolymorphic(TypeDiscriminatorPropertyName = "kind")]
[JsonDerivedType(typeof(UserAutomationAllowedProviderPolicy), "allowed")]
[JsonDerivedType(typeof(UserAutomationDeterministicOnlyProviderPolicy), "deterministic_only")]
public abstract record UserAutomationProviderPolicy
{
    public abstract void Validate();
}

public sealed record UserAutomationAllowedProviderPolicy(
    [property: JsonPropertyName("fingerprints")] IReadOnlyList<UserAutomationProviderFingerprint> Fingerprints)
    : UserAutomationProviderPolicy
{
    public override void Validate()
    {
        if (Fingerprints.Count == 0) throw new InvalidOperationException("provider_policy.fingerprints must not be empty.");
        foreach (var fingerprint in Fingerprints) fingerprint.Validate();
        if (Fingerprints.Zip(Fingerprints.Skip(1)).Any(pair => pair.First == pair.Second))
        {
            throw new InvalidOperationException("provider_policy.fingerprints must not contain adjacent duplicates.");
        }
    }
}

public sealed record UserAutomationDeterministicOnlyProviderPolicy : UserAutomationProviderPolicy
{
    public override void Validate() { }
}

public sealed record UserAutomationProviderFingerprint(
    [property: JsonPropertyName("provider")] string Provider,
    [property: JsonPropertyName("model")] string Model,
    [property: JsonPropertyName("adapter")] string Adapter,
    [property: JsonPropertyName("fingerprint")] string Fingerprint)
{
    public void Validate()
    {
        UserAutomationContract.RequireText(Provider, "provider.provider");
        UserAutomationContract.RequireText(Model, "provider.model");
        UserAutomationContract.RequireText(Adapter, "provider.adapter");
        UserAutomationContract.RequireText(Fingerprint, "provider.fingerprint");
    }
}

public sealed record UserAutomationRouteCostPolicy(
    [property: JsonPropertyName("route_ref")] string RouteRef,
    [property: JsonPropertyName("max_cost_units")] ulong MaxCostUnits,
    [property: JsonPropertyName("max_duration_ms")] ulong MaxDurationMs,
    [property: JsonPropertyName("policy_revision")] ulong? PolicyRevision)
{
    public void Validate()
    {
        UserAutomationContract.RequireText(RouteRef, "route_cost.route_ref");
        if (MaxCostUnits == 0 || MaxDurationMs == 0) throw new InvalidOperationException("route cost ceilings must be nonzero.");
    }
}

public sealed record UserAutomationDeliveryTarget(
    [property: JsonPropertyName("target_ref")] string TargetRef,
    [property: JsonPropertyName("channels")] IReadOnlyList<string> Channels,
    [property: JsonPropertyName("recipient_refs")] IReadOnlyList<string> RecipientRefs)
{
    public void Validate()
    {
        UserAutomationContract.RequireText(TargetRef, "delivery.target_ref");
        if (Channels.Count == 0) throw new InvalidOperationException("delivery.channels must not be empty.");
        UserAutomationContract.RequireOneOf(Channels, "delivery.channels", "CONTROL_BOARD", "NATIVE_TOAST", "WINDOWS_EVENT_LOG", "RECOVERY_FALLBACK");
        UserAutomationContract.RequireTextList(RecipientRefs, "delivery.recipient_refs");
    }
}

public sealed record UserAutomationResourceCeiling(
    [property: JsonPropertyName("max_runtime_ms")] ulong MaxRuntimeMs,
    [property: JsonPropertyName("max_output_bytes")] ulong MaxOutputBytes,
    [property: JsonPropertyName("max_child_count")] uint MaxChildCount)
{
    public void Validate()
    {
        if (MaxRuntimeMs == 0 || MaxOutputBytes == 0) throw new InvalidOperationException("resource ceilings must be nonzero.");
    }
}

public sealed record UserAutomationRecursionPolicy(
    [property: JsonPropertyName("allow_child_automation")] bool AllowChildAutomation,
    [property: JsonPropertyName("max_child_depth")] ushort MaxChildDepth)
{
    public void Validate()
    {
        if (!AllowChildAutomation && MaxChildDepth != 0) throw new InvalidOperationException("disabled child automation requires max_child_depth=0.");
    }
}

public static class UserAutomationContract
{
    public const string Route = "eliot_user_automation";
    public const string PreflightContractRevision = "eliot.user-automation.preflight.v1";

    public static readonly IReadOnlyList<string> OperationKinds =
    [
        "create", "list", "status", "history", "pause", "resume", "edit", "run_now", "remove", "inspect_last_failure"
    ];

    public static void RequireText(string? value, string field)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Any(char.IsControl))
        {
            throw new InvalidOperationException($"{field} must be nonblank and contain no control characters.");
        }
    }

    public static void RequireIdentity(string automationId, string automationRevision)
    {
        RequireText(automationId, "automation_id");
        RequireText(automationRevision, "automation_revision");
    }

    public static void RequireTextList(IEnumerable<string> values, string field)
    {
        if (values is null) throw new InvalidOperationException($"{field} must be present.");
        foreach (var value in values) RequireText(value, field);
    }

    public static void RequireOneOf(string value, string field, params string[] allowed)
    {
        RequireText(value, field);
        if (!allowed.Contains(value, StringComparer.Ordinal))
        {
            throw new InvalidOperationException($"{field} is not an admitted value.");
        }
    }

    public static void RequireOneOf(IEnumerable<string> values, string field, params string[] allowed)
    {
        foreach (var value in values) RequireOneOf(value, field, allowed);
    }
}
