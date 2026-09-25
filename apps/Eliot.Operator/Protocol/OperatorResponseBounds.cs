using System.Text.Json;

namespace Eliot.Operator.Protocol;

/// One response's independent caps. The axes are separate on purpose: a
/// response may legitimately be wide, deep, string-heavy or item-heavy, and
/// each axis is refused on its own before the decoded data can be trusted or
/// retained.
public sealed record OperatorResponseBounds(
    int MaxMembers,
    int MaxDepth,
    int MaxTokens,
    int MaxStringChars,
    int MaxArrayItems)
{
    /// Caps for one framed owner response line.
    public static OperatorResponseBounds Response { get; } = new(
        OperatorProtocol.MaxResponseMembers,
        OperatorProtocol.MaxResponseDepth,
        OperatorProtocol.MaxResponseTokens,
        OperatorProtocol.MaxResponseStringChars,
        OperatorProtocol.MaxResponseArrayItems);

    /// Caps for one operator-typed local JSON parameter object.
    public static OperatorResponseBounds LocalParameter { get; } = new(
        OperatorProtocol.MaxLocalParameterMembers,
        OperatorProtocol.MaxLocalParameterDepth,
        OperatorProtocol.MaxLocalParameterTokens,
        OperatorProtocol.MaxLocalParameterStringChars,
        OperatorProtocol.MaxLocalParameterItems);

    public void Validate()
    {
        if (MaxMembers <= 0 || MaxDepth <= 0 || MaxTokens <= 0 || MaxStringChars <= 0 || MaxArrayItems <= 0)
        {
            throw new InvalidOperationException("Operator response bounds must be positive.");
        }
    }
}

/// Refuses an oversized or untrusted payload before the decoded object is
/// constructed. Over-limit input fails closed; it is never truncated into a
/// valid-looking object.
public static class OperatorResponseGuard
{
    /// Validates one framed owner response line against independent member,
    /// depth, token, string and array-item caps, and refuses duplicate
    /// property names at every nesting level. This runs on the raw line
    /// before the strongly typed projection is allocated.
    public static void ValidateFramedResponse(string rawJson, string shapeName)
    {
        var bounds = OperatorResponseBounds.Response;
        bounds.Validate();
        OperatorJsonGuard.ValidateFramedResponse(
            rawJson,
            bounds.MaxMembers,
            bounds.MaxStringChars,
            bounds.MaxDepth,
            bounds.MaxTokens,
            bounds.MaxArrayItems,
            shapeName);
    }

    /// Validates one operator-typed local JSON parameter object against its own
    /// independent caps before the UI stores or forwards it.
    public static void ValidateLocalParameter(string rawJson, string shapeName)
    {
        var bounds = OperatorResponseBounds.LocalParameter;
        bounds.Validate();
        OperatorJsonGuard.ValidateFramedResponse(
            rawJson,
            bounds.MaxMembers,
            bounds.MaxStringChars,
            bounds.MaxDepth,
            bounds.MaxTokens,
            bounds.MaxArrayItems,
            shapeName);
    }
}

/// The exact identity one retained projection is bound to.
///
/// Rows, selection, cursor, task context and the retained result payload are
/// rebuildable views of this binding, never authority. Any change to runtime,
/// auth generation, owner task revision, projection or project/task scope
/// invalidates every dependent piece of UI state before the new page is used.
///
/// `GeneratedAtUtc` is the owner's timestamp. The page contract in
/// `crates/eliot-types` carries no State Fence or consistency discriminator,
/// so this binding records them as owner-unissued rather than inventing one:
/// the client refuses to *act* on a binding it cannot place against the exact
/// owner revision, and the owner remains the single source of both values.
public sealed record OperatorProjectionBinding(
    string SchemaVersion,
    string RuntimeId,
    string AuthGeneration,
    string Projection,
    string? ProjectId,
    string? TaskId,
    ulong? TaskRevision,
    DateTimeOffset GeneratedAtUtc)
{
    /// The owner-supplied State Fence discriminator does not exist in the
    /// current page contract. It is reported as absent, never defaulted to a
    /// value the client made up.
    public const string StateFence = "owner_unissued";
    public const string Consistency = "owner_unissued";

    /// Bounded clock-skew tolerance for the owner timestamp, taken from the
    /// owner's own handoff lifetime. A page dated further into the future is
    /// refused instead of becoming permanently "fresh".
    public static TimeSpan ClockSkewTolerance { get; } =
        TimeSpan.FromSeconds(OperatorProtocol.HandoffLifetimeSeconds);

    public static OperatorProjectionBinding From(OperatorProjectionPage page, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(page);
        if (page.GeneratedAt - nowUtc > ClockSkewTolerance)
        {
            throw new OperatorProtocolException("projection", "generated_at_ahead_of_client");
        }
        return new OperatorProjectionBinding(
            page.SchemaVersion,
            page.RuntimeId,
            page.AuthGeneration,
            page.Projection,
            page.ProjectId,
            page.TaskId,
            page.TaskRevision,
            page.GeneratedAt);
    }

    /// True when the two bindings describe different owner state. A change on
    /// any identity axis requires invalidation before use.
    public bool DiffersFrom(OperatorProjectionBinding? other) =>
        other is null
        || !string.Equals(SchemaVersion, other.SchemaVersion, StringComparison.Ordinal)
        || !string.Equals(RuntimeId, other.RuntimeId, StringComparison.Ordinal)
        || !string.Equals(AuthGeneration, other.AuthGeneration, StringComparison.Ordinal)
        || !string.Equals(Projection, other.Projection, StringComparison.Ordinal)
        || !string.Equals(ProjectId, other.ProjectId, StringComparison.Ordinal)
        || !string.Equals(TaskId, other.TaskId, StringComparison.Ordinal)
        || TaskRevision != other.TaskRevision;

    /// Bounded redacted projection for the status banner. It names the binding
    /// axes and revision, never a record body.
    public string Describe() =>
        $"runtime={RuntimeId} auth_generation={AuthGeneration} projection={Projection} " +
        $"task_revision={(TaskRevision?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "none")} " +
        $"state_fence={StateFence} consistency={Consistency}";
}

/// Refuses a decoded projection page whose retained containers exceed their
/// independent caps. The page is bounded, not clipped: an over-limit page is
/// rejected whole, because a partially retained page is a projection that
/// looks complete and is not.
public static class OperatorProjectionGuard
{
    public static void ValidatePage(OperatorProjectionPage page)
    {
        ArgumentNullException.ThrowIfNull(page);
        RequireText(page.SchemaVersion, "schema_version");
        RequireText(page.RuntimeId, "runtime_id");
        RequireText(page.AuthGeneration, "auth_generation");
        RequireText(page.Projection, "projection");
        RequireText(page.ResultMode, "result_mode");
        RequireCursor(page.Cursor, "cursor");
        RequireCursor(page.NextCursor, "next_cursor");
        RequireOptionalText(page.ProjectId, "project_id");
        RequireOptionalText(page.TaskId, "task_id");

        if (page.PageSize is < OperatorProtocol.MinPageSize or > OperatorProtocol.MaxPageSize)
        {
            throw new OperatorProtocolException("projection", "page_size_cap");
        }
        if (page.Returned < 0
            || page.TotalMatching < 0
            || page.TotalMatching > OperatorProtocol.MaxTotalMatching)
        {
            throw new OperatorProtocolException("projection", "count_cap");
        }
        if (page.Records.Count > OperatorProtocol.MaxPageSize
            || page.Records.Count > OperatorProtocol.MaxProjectionRecords)
        {
            throw new OperatorProtocolException("projection", "record_cap");
        }
        foreach (var record in page.Records)
        {
            ValidateRecord(record);
        }
    }

    /// Bounds the retained result payload. An oversized payload is refused
    /// whole and surfaced as a typed reason; it is never clipped into an
    /// object that still parses.
    public static string? BoundRetainedResult(JsonElement? payload)
    {
        if (payload is not { } element
            || element.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
        {
            return null;
        }
        var raw = element.GetRawText();
        if (raw.Length > OperatorProtocol.MaxRetainedResultChars)
        {
            throw new OperatorProtocolException("result_payload", "retained_buffer_cap");
        }
        return raw;
    }

    private static void ValidateRecord(OperatorRecordView record)
    {
        if (record is null) throw new OperatorProtocolException("projection", "null_record");
        RequireText(record.RecordRef, "record_ref");
        RequireText(record.RecordKind, "record_kind");
        RequireText(record.Title, "title");
        RequireText(record.Summary, "summary");
        RequireText(record.Status, "status");
        RequireText(record.Authority, "authority");
        RequireOptionalText(record.ObservedAt, "observed_at");
        RequireOptionalText(record.Lifecycle, "lifecycle");
        RequireCount(record.Fields.Count, "fields");
        RequireCount(record.Relationships.Count, "relationships");
        RequireCount(record.Actions.Count, "actions");
        foreach (var field in record.Fields)
        {
            if (field is null) throw new OperatorProtocolException("projection", "null_field");
            RequireText(field.Label, "field_label");
            RequireText(field.Value, "field_value");
        }
        foreach (var relationship in record.Relationships)
        {
            if (relationship is null) throw new OperatorProtocolException("projection", "null_relationship");
            RequireText(relationship.Relation, "relation");
            RequireText(relationship.TargetRef, "target_ref");
        }
        foreach (var action in record.Actions)
        {
            if (action is null) throw new OperatorProtocolException("projection", "null_action");
            RequireText(action.Command, "action_command");
            RequireText(action.Label, "action_label");
            RequireText(action.RiskTier, "risk_tier");
        }
    }

    private static void RequireCount(int count, string field)
    {
        if (count < 0 || count > OperatorProtocol.MaxPageCollections)
        {
            throw new OperatorProtocolException("projection", $"{field}_cap");
        }
    }

    private static void RequireCursor(string? cursor, string field)
    {
        if (cursor is null) return;
        if (cursor.Length > OperatorProtocol.MaxCursorChars || cursor.Any(char.IsControl))
        {
            throw new OperatorProtocolException("projection", $"{field}_cap");
        }
    }

    private static void RequireOptionalText(string? value, string field)
    {
        if (value is null) return;
        RequireText(value, field);
    }

    private static void RequireText(string? value, string field)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > OperatorProtocol.MaxRecordTextChars
            || value.Any(char.IsControl))
        {
            throw new OperatorProtocolException("projection", $"{field}_cap");
        }
    }
}
