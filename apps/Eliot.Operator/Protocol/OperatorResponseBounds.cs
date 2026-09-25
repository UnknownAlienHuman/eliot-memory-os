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

/// The closed `ReadConsistency` vocabulary of I5.20. It is a classification
/// of values the owner already issued on the page, not a support level the
/// client picks: the vocabulary is fixed, and every input is an owner-issued
/// field of `OperatorProjectionPage`. A read consistency word is never a
/// Material State Fence — see `OperatorProjectionBinding.MaterialStateFence`.
public enum OperatorReadConsistency
{
    /// I5.20:17 — cheap preview. No task revision is bound to the page, so
    /// there is no owner revision to be read-your-write against.
    Eventual = 0,

    /// I5.20:18 — read-your-write after receipt. The owner issued the
    /// matching count as a lower bound it declined to sharpen.
    AtLeastRevision = 1,

    /// I5.20:20 — all listed dependency revisions must match. The owner issued
    /// an exact count and a task revision, so every revision key in
    /// `ProjectionDependencySet` is owner-issued and comparable.
    ExactFence = 2
}

/// The exact I5.20 vocabulary word for one classified read consistency.
/// Nothing else is ever written in its place.
public static class OperatorReadConsistencyTokens
{
    public static string Token(this OperatorReadConsistency consistency) => consistency switch
    {
        OperatorReadConsistency.Eventual => "eventual",
        OperatorReadConsistency.AtLeastRevision => "at_least_revision",
        OperatorReadConsistency.ExactFence => "exact_fence",
        // A value outside the closed vocabulary is refused, never reported
        // under a word the owner did not issue.
        _ => throw new OperatorProtocolException("projection", "read_consistency_unclassified")
    };
}

/// The exact owner-issued dependency tuple one retained page was built from.
/// I5.20:46 requires every reused response to carry its dependency set and
/// invalidation conditions, and I5.20:26-32 compares that set as one unit
/// (read it, read it again, publish only if every dependency revision still
/// matches). These are the owner-issued revision keys the page itself carries;
/// no key is added and none is invented.
public readonly record struct OperatorProjectionDependencySet(
    string RuntimeId,
    string AuthGeneration,
    string SchemaVersion,
    string Projection,
    string? ProjectId,
    string? TaskId,
    ulong? TaskRevision)
{
    public static OperatorProjectionDependencySet From(OperatorProjectionPage page)
    {
        ArgumentNullException.ThrowIfNull(page);
        return new OperatorProjectionDependencySet(
            page.RuntimeId,
            page.AuthGeneration,
            page.SchemaVersion,
            page.Projection,
            page.ProjectId,
            page.TaskId,
            page.TaskRevision);
    }
}

/// The exact identity one retained projection is bound to.
///
/// Rows, selection, cursor, task context and the retained result payload are
/// rebuildable views of this binding, never authority. Any change to runtime,
/// auth generation, owner task revision, projection, project/task scope,
/// owner read consistency or the owner-issued dependency set invalidates
/// every dependent piece of UI state before the new page is used.
///
/// `GeneratedAtUtc` is the owner's timestamp and the page contract in
/// `crates/eliot-types` carries no expiry field, so the expiry axis is the
/// owner's own handoff lifetime applied to that timestamp: a page outside that
/// bound is refused whole, in both directions, and a retained binding never
/// outlives its own expiry. The same page contract carries no Material State
/// Fence, and I5.20:34 forbids treating a rebuildable aggregate as one, so
/// that axis stays owner-unissued rather than being invented here.
public sealed record OperatorProjectionBinding(
    string SchemaVersion,
    string RuntimeId,
    string AuthGeneration,
    string Projection,
    string? ProjectId,
    string? TaskId,
    ulong? TaskRevision,
    OperatorReadConsistency ReadConsistency,
    OperatorProjectionDependencySet ProjectionDependencySet,
    DateTimeOffset GeneratedAtUtc)
{
    /// No Material State Fence exists on this page contract, and a rebuildable
    /// aggregate is never sufficient for one by itself. It is reported as
    /// absent and is never defaulted to a value the client made up.
    public const string MaterialStateFence = "owner_unissued";

    /// Bounded clock-skew tolerance for the owner timestamp, taken from the
    /// owner's own handoff lifetime. A page dated further into the future is
    /// refused instead of becoming permanently "fresh", and a page already
    /// older than this bound is no longer reusable.
    public static TimeSpan ClockSkewTolerance { get; } =
        TimeSpan.FromSeconds(OperatorProtocol.HandoffLifetimeSeconds);

    /// Expiry of one page on the owner's own bound. The single place that bound
    /// is turned into a time, so the refusal in `From` and the axis carried by
    /// every binding can never drift apart.
    public static DateTimeOffset ExpiryOf(DateTimeOffset generatedAtUtc) =>
        generatedAtUtc + ClockSkewTolerance;

    /// When this retained page stops being reusable. It never becomes stale
    /// silently: `From` refuses the page outright once this moment has passed.
    public DateTimeOffset ExpiresAtUtc => ExpiryOf(GeneratedAtUtc);

    public static OperatorProjectionBinding From(OperatorProjectionPage page, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(page);
        if (page.GeneratedAt - nowUtc > ClockSkewTolerance)
        {
            throw new OperatorProtocolException("projection", "generated_at_ahead_of_client");
        }
        if (nowUtc > ExpiryOf(page.GeneratedAt))
        {
            throw new OperatorProtocolException("projection", "page_past_expiry");
        }
        return new OperatorProjectionBinding(
            page.SchemaVersion,
            page.RuntimeId,
            page.AuthGeneration,
            page.Projection,
            page.ProjectId,
            page.TaskId,
            page.TaskRevision,
            ClassifyReadConsistency(page),
            OperatorProjectionDependencySet.From(page),
            page.GeneratedAt);
    }

    /// Classifies the owner-issued page fields into the closed I5.20
    /// `ReadConsistency` vocabulary, strongest match first: an exact owner
    /// count bound to an owner task revision is `exact_fence`; a count the
    /// owner issued as a lower bound is `at_least_revision`; a page with no
    /// bound task revision is an `eventual` preview. Every branch reads only
    /// owner-issued fields, so the class cannot be used to claim a support
    /// level the owner did not send.
    public static OperatorReadConsistency ClassifyReadConsistency(OperatorProjectionPage page)
    {
        ArgumentNullException.ThrowIfNull(page);
        if (page.TotalIsExact && page.TaskRevision is not null) return OperatorReadConsistency.ExactFence;
        if (!page.TotalIsExact) return OperatorReadConsistency.AtLeastRevision;
        return OperatorReadConsistency.Eventual;
    }

    /// True when the two bindings describe different owner state. A change on
    /// any identity, read-consistency or dependency-set axis requires
    /// invalidation before use. The expiry axis is deliberately not compared
    /// here: a fresh page always carries a fresh owner timestamp, so comparing
    /// it would rotate every read rather than describe a change in owner
    /// state. Expiry is enforced by refusing the page in `From`.
    public bool DiffersFrom(OperatorProjectionBinding? other) =>
        other is null
        || !string.Equals(SchemaVersion, other.SchemaVersion, StringComparison.Ordinal)
        || !string.Equals(RuntimeId, other.RuntimeId, StringComparison.Ordinal)
        || !string.Equals(AuthGeneration, other.AuthGeneration, StringComparison.Ordinal)
        || !string.Equals(Projection, other.Projection, StringComparison.Ordinal)
        || !string.Equals(ProjectId, other.ProjectId, StringComparison.Ordinal)
        || !string.Equals(TaskId, other.TaskId, StringComparison.Ordinal)
        || TaskRevision != other.TaskRevision
        || ReadConsistency != other.ReadConsistency
        || ProjectionDependencySet != other.ProjectionDependencySet;

    /// Bounded redacted projection for the status banner. It names the binding
    /// axes and revision, never a record body.
    public string Describe() =>
        $"runtime={RuntimeId} auth_generation={AuthGeneration} projection={Projection} " +
        $"task_revision={(TaskRevision?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "none")} " +
        $"read_consistency={ReadConsistency.Token()} " +
        $"material_state_fence={MaterialStateFence} " +
        $"expires_at={ExpiresAtUtc.UtcDateTime:o}";
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
