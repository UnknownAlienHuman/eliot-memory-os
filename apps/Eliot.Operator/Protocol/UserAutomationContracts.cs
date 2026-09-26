using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Eliot.Operator.Protocol.Generated;

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
    ///
    /// This is a local routing classifier, not part of the operation. It is a
    /// method rather than a property because System.Text.Json serializes a
    /// public getter by default: the owner-side
    /// `UserAutomationOperation` is `deny_unknown_fields`, so a serialized
    /// `isEffect` member would make every request undecodable. A method has no
    /// serialized surface at all, which keeps the exclusion exact for the
    /// abstract declaration, all ten derived records, the polymorphic
    /// `UserAutomationOperation` contract and the outer request at once.
    public abstract bool IsEffect();
}

public sealed record UserAutomationCreateOperation(
    [property: JsonPropertyName("revision")] UserAutomationRevision Revision)
    : UserAutomationOperation
{
    public override void Validate() => Revision.Validate();

    public override bool IsEffect() => true;
}

public sealed record UserAutomationListOperation(
    [property: JsonPropertyName("include_retired")] bool IncludeRetired)
    : UserAutomationOperation
{
    public override void Validate() { }

    public override bool IsEffect() => false;
}

public sealed record UserAutomationStatusOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireText(AutomationId, "automation_id");

    public override bool IsEffect() => false;
}

public sealed record UserAutomationHistoryOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireText(AutomationId, "automation_id");

    public override bool IsEffect() => false;
}

public sealed record UserAutomationPauseOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId,
    [property: JsonPropertyName("automation_revision")] string AutomationRevision)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireIdentity(AutomationId, AutomationRevision);

    public override bool IsEffect() => true;
}

public sealed record UserAutomationResumeOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId,
    [property: JsonPropertyName("automation_revision")] string AutomationRevision)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireIdentity(AutomationId, AutomationRevision);

    public override bool IsEffect() => true;
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
        // An edit is a NEW immutable revision, so an effect-relevant schedule
        // change has to be backed by a NEW owner normalization result. This
        // refuses the two provable stale-owner-evidence cases: reusing the
        // previous revision's occurrence source digest after changing the source,
        // and carrying a digest foreign to an unchanged source. Neither revision
        // is ever rewritten here; the Operator derives no normalization of its
        // own, so a genuine re-normalization must come from the owner.
        UserAutomationScheduleMirror.RequireFreshOwnerEvidenceForEdit(
            PreviousRevision.Schedule,
            Revision.Schedule);
    }

    public override bool IsEffect() => true;
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

    public override bool IsEffect() => true;
}

public sealed record UserAutomationRemoveOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId,
    [property: JsonPropertyName("automation_revision")] string AutomationRevision)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireIdentity(AutomationId, AutomationRevision);

    public override bool IsEffect() => true;
}

public sealed record UserAutomationInspectLastFailureOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireText(AutomationId, "automation_id");

    public override bool IsEffect() => false;
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

/// One typed UserAutomation request read from a retained user-local envelope,
/// together with whether the retained bytes still encode the superseded local
/// read/effect classifier.
///
/// Retained bytes are read, never rewritten. The current closed profile is the
/// authority on the exact field set: a request that decodes through it carries
/// nothing beyond the contract, because it refuses every unmapped member. Only
/// one deviation is tolerated, and only here: the single known member the
/// superseded generation emitted for the local classifier. That member is
/// non-authoritative recovery metadata — the read/effect classification is
/// re-derived from the decoded typed operation, never trusted from the old
/// bytes — and its presence never makes the envelope sendable. This profile is
/// never used to read or write a live request, so the live wire keeps refusing
/// unknown fields.
public sealed record UserAutomationRetainedRequest(
    UserAutomationOperatorRequest Request,
    bool CarriesSupersededLocalClassifier)
{
    /// The exact member name the superseded generation produced for the local
    /// `IsEffect` property under the closed Web naming policy.
    public const string SupersededLocalClassifierMember = "isEffect";

    /// The outer request is exactly these two members. It is stated here rather
    /// than read back off the request type so the retained envelope is checked
    /// against the wire contract, not against its own reader.
    private static readonly string[] RequestMemberNames = ["operation", "idempotency_key"];

    /// The one tolerated deviation, scoped to retained local recovery bytes.
    /// `OperatorJson.Reader` itself is untouched, so no unrelated surface
    /// inherits the tolerance. `Skip` is applied only to the retained bytes
    /// after the single known member has been removed, and
    /// `RequireSameMembersAndValues` then proves the result is exactly today's
    /// canonical encoding — so anything this profile skipped is refused there.
    private static readonly JsonSerializerOptions SupersededShapeJson = new(OperatorJson.Reader)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip
    };

    /// Reads one retained envelope without altering it. The decoded identity is
    /// the one the bytes already carry; it is never re-derived from today's
    /// serializer, because a re-encoded payload is a different request
    /// commitment than the one the retained key names.
    ///
    /// Every refusal is reported as one exception type, so a caller can tell
    /// "these retained bytes are not a closed UserAutomation envelope" from
    /// "this record is fine" without also handling serializer internals.
    public static UserAutomationRetainedRequest Read(string envelopeJson)
    {
        ArgumentNullException.ThrowIfNull(envelopeJson);
        UserAutomationRetainedRequest? current;
        try
        {
            current = ReadCurrentShape(envelopeJson);
        }
        catch (Exception error) when (error is JsonException or NotSupportedException)
        {
            // The current shape refused. `NotSupportedException` is how the
            // polymorphic converter reports a member it cannot bind before it
            // reaches the discriminator, so it is a shape refusal too.
            current = null;
        }
        if (current is not null)
        {
            return current;
        }

        try
        {
            return ReadSupersededShape(envelopeJson);
        }
        catch (Exception error) when (error is JsonException or NotSupportedException)
        {
            throw new InvalidOperationException(
                "retained UserAutomation request is not a closed UserAutomation envelope",
                error);
        }
    }

    /// The retained bytes decode through the current closed profile, so they
    /// carry nothing beyond the contract: that profile refuses every unmapped
    /// member.
    private static UserAutomationRetainedRequest ReadCurrentShape(string envelopeJson)
    {
        using var document = JsonDocument.Parse(envelopeJson);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("retained UserAutomation request is not one JSON object");
        }
        return new UserAutomationRetainedRequest(
            document.RootElement.Deserialize<UserAutomationOperatorRequest>(OperatorJson.Reader)
                ?? throw new InvalidOperationException("retained UserAutomation request is empty"),
            CarriesSupersededLocalClassifier: false);
    }

    /// The one tolerated deviation: the retained bytes are today's canonical
    /// encoding of the same typed operation plus the single known local
    /// classifier the superseded generation wrote. Nothing else is accepted.
    private static UserAutomationRetainedRequest ReadSupersededShape(string envelopeJson)
    {
        using var document = JsonDocument.Parse(envelopeJson);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("retained UserAutomation request is not one JSON object");
        }
        RequireExactMembers(root, RequestMemberNames);
        var operation = root.GetProperty("operation");
        if (operation.ValueKind != JsonValueKind.Object
            || !operation.TryGetProperty(SupersededLocalClassifierMember, out var classifier)
            || classifier.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new InvalidOperationException(
                "retained UserAutomation request does not carry the known superseded local classifier");
        }

        // The exact shape today's closed profile accepts: the retained bytes
        // with the one known local classifier removed and nothing else changed,
        // so the strict profile then validates the result at every depth.
        var superseded = JsonSerializer.Deserialize<UserAutomationOperatorRequest>(
                WithoutSupersededClassifier(root, operation), SupersededShapeJson)
            ?? throw new InvalidOperationException("retained UserAutomation request is empty");

        // The retained bytes must equal today's canonical encoding of that same
        // typed operation plus the one classifier, compared member by member so
        // member order is irrelevant. Anything the closed serializer would not
        // write itself — an extra field at any depth, a changed value, a
        // different casing — is refused here.
        using var canonical = JsonDocument.Parse(
            JsonSerializer.Serialize(superseded.Operation, OperatorJson.Writer));
        RequireSameMembersAndValues(operation, canonical.RootElement, classifier);
        return new UserAutomationRetainedRequest(
            superseded,
            CarriesSupersededLocalClassifier: true);
    }

    /// Rewrites the retained envelope with the one known local classifier
    /// removed and every other byte, at every depth, copied verbatim.
    private static string WithoutSupersededClassifier(JsonElement root, JsonElement operation)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            foreach (var property in root.EnumerateObject())
            {
                if (property.NameEquals("operation"))
                {
                    writer.WritePropertyName(property.Name);
                    writer.WriteStartObject();
                    foreach (var member in operation.EnumerateObject())
                    {
                        if (!string.Equals(member.Name, SupersededLocalClassifierMember, StringComparison.Ordinal))
                        {
                            member.WriteTo(writer);
                        }
                    }
                    writer.WriteEndObject();
                    continue;
                }
                property.WriteTo(writer);
            }
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static void RequireExactMembers(JsonElement element, IEnumerable<string> expected)
    {
        var actual = element.EnumerateObject().Select(property => property.Name).ToArray();
        if (!new HashSet<string>(actual, StringComparer.Ordinal).SetEquals(expected))
        {
            throw new InvalidOperationException(
                "retained UserAutomation request carries members outside the closed contract");
        }
    }

    /// Compares the retained operation with the canonical encoding of the same
    /// typed operation plus the tolerated member, by name and by value. This is
    /// the whole tolerance boundary: anything today's serializer would not write
    /// itself is refused here.
    private static void RequireSameMembersAndValues(
        JsonElement retained,
        JsonElement canonical,
        JsonElement classifier)
    {
        if (retained.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException(
                "retained UserAutomation operation is not one JSON object");
        }
        var actual = retained.EnumerateObject()
            .ToDictionary(property => property.Name, property => property.Value, StringComparer.Ordinal);
        var expected = canonical.EnumerateObject()
            .ToDictionary(property => property.Name, property => property.Value, StringComparer.Ordinal);
        expected[SupersededLocalClassifierMember] = classifier;
        if (actual.Count != expected.Count)
        {
            throw new InvalidOperationException(
                "retained UserAutomation operation carries members outside the closed contract");
        }
        foreach (var (name, value) in expected)
        {
            if (!actual.TryGetValue(name, out var retainedValue)
                || !JsonElement.DeepEquals(retainedValue, value))
            {
                throw new InvalidOperationException(
                    "retained UserAutomation operation differs from the closed contract outside the known local classifier");
            }
        }
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
    /// <summary>
    /// Validates the bounded wire shape and the exact supported contract version
    /// of the owner-issued occurrence set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every field of the versioned occurrence record is checked against the
    /// grammar in <c>UserAutomationScheduleMirror</c>, which is a generated port
    /// of the Kernel owner contract, so this method can no longer accept a
    /// revision the Kernel refuses. Three things changed decisively here:
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// The exact contract version and the pinned zone database release are
    /// READ OFF the owner's own occurrence bytes. They are not a second copy
    /// carried on this record: the owner side is <c>deny_unknown_fields</c>, so
    /// a member the owner does not know would make every request undecodable.
    /// </item>
    /// <item>
    /// A legacy shape-only occurrence is refused by name, with the
    /// re-normalization action attached. The revision is never rewritten here;
    /// an immutable revision is only ever superseded by a new one.
    /// </item>
    /// <item>
    /// Ordering is decided by the resolved canonical instant, NEVER by a lexical
    /// comparison of the raw records. Mixed offsets are exactly the case where
    /// the two disagree, and the Kernel orders by the instant.
    /// </item>
    /// </list>
    /// <para>
    /// This is a shape and evidence check only. It is not admission, and it does
    /// not make the schedule normalized: normalization is the owner's act, and
    /// a successful pass here is reported as "admitted for submission", never as
    /// "normalized".
    /// </para>
    /// </remarks>
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
        if (NextOccurrences.Count == 0)
        {
            throw new InvalidOperationException("schedule.next_occurrences must be non-empty.");
        }
        if (Kind == "ONE_SHOT" && NextOccurrences.Count != 1)
        {
            throw new InvalidOperationException("ONE_SHOT schedules require one next occurrence.");
        }
        UserAutomationScheduleMirror.ReadOwnerSchedule(
            Timezone, DstFold, DstGap, StartAt, EndAt, NextOccurrences);
    }

    /// <summary>
    /// The typed normalization receipt this Operator preserves for a schedule it
    /// has admitted for submission.
    /// </summary>
    /// <remarks>
    /// This is a METHOD, not a property, for the same reason
    /// <c>UserAutomationOperation.IsEffect</c> is: the owner-side request records
    /// are <c>deny_unknown_fields</c>, so a serialized member the owner does not
    /// know would make every request undecodable. A method has no serialized
    /// surface at all, which keeps the exclusion exact.
    /// <para>
    /// The receipt carries only what the owner-issued bytes decide. It is NOT an
    /// owner receipt, and it does not certify that the owner admitted or
    /// normalized the revision.
    /// </para>
    /// </remarks>
    public UserAutomationScheduleReceipt NormalizationReceipt()
    {
        Validate();
        return UserAutomationScheduleMirror.ReadOwnerSchedule(
            Timezone, DstFold, DstGap, StartAt, EndAt, NextOccurrences);
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

    /// <summary>
    /// The admitted preflight contract revision, read from the GENERATED mirror
    /// of the owner contract rather than hand-copied, so a Kernel change to the
    /// revision cannot be absorbed silently by this one consumer.
    /// </summary>
    public const string PreflightContractRevision =
        Generated.OperatorScheduleContract.USER_AUTOMATION_PREFLIGHT_CONTRACT_REVISION;

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
