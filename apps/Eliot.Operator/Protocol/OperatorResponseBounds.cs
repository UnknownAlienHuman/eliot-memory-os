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

/// The closed `ReadConsistency` vocabulary of I5.20, used here only to classify
/// values the owner already issued on `OperatorProjectionPage`.
///
/// Every branch reads an owner-issued field, so the class can never claim a
/// support level the owner did not send, and it exists for exactly one purpose:
/// deciding whether a newly read page still describes the same owner view as
/// the page the retained UI state was built from. `stable_scope` is deliberately
/// absent: nothing the page contract issues distinguishes a stable-scope
/// assembly from an exact one, and an undeterminable vocabulary word would be a
/// word the owner never issued.
public enum OperatorReadConsistency
{
    /// I5.20:17 — cheap preview. The owner issued an exact count but bound no
    /// task revision, so there is no owner revision to be read-your-write
    /// against and nothing to compare.
    Eventual = 0,

    /// I5.20:18 — read-your-write after receipt. The owner issued the matching
    /// count as a lower bound it declined to sharpen, so the retained view is
    /// pinned to the bound revision but is not an exact count.
    AtLeastRevision = 1,

    /// I5.20:20 — all listed dependency revisions must match. This client
    /// never reports it: `OperatorProjectionPage` carries `task_revision` and
    /// no `state_fence`, `authority_epoch`, `resource_generation` or `epoch`,
    /// so there are no owner-issued dependency revisions to match and the
    /// guarantee cannot be made. The member stays in the closed vocabulary
    /// with its exact I5.20 token; only the classifier refuses to reach it.
    ExactFence = 2
}

/// The exact I5.20 vocabulary word for one classified read consistency. A value
/// outside the closed vocabulary is refused, never reported under a word the
/// owner did not issue.
public static class OperatorReadConsistencyTokens
{
    public static string Token(this OperatorReadConsistency consistency) => consistency switch
    {
        OperatorReadConsistency.Eventual => "eventual",
        OperatorReadConsistency.AtLeastRevision => "at_least_revision",
        OperatorReadConsistency.ExactFence => "exact_fence",
        _ => throw new OperatorProtocolException("projection", "read_consistency_unclassified")
    };
}

/// The exact identity one retained projection is bound to.
///
/// Rows, selection, cursor, task context and the retained result payload are
/// rebuildable views of this binding, never authority. Any change to runtime,
/// auth generation, owner task revision, projection, project/task scope or the
/// owner-issued read consistency invalidates every dependent piece of UI state
/// before the new page is used.
///
/// `GeneratedAtUtc` is the owner's timestamp. The page contract in
/// `crates/eliot-types` carries no State Fence, so this binding reports the
/// fence as owner-unissued rather than inventing one: the client refuses to
/// *act* on a binding it cannot place against the exact owner revision, and the
/// owner remains the single source of that value.
public sealed record OperatorProjectionBinding(
    string SchemaVersion,
    string RuntimeId,
    string AuthGeneration,
    string Projection,
    string? ProjectId,
    string? TaskId,
    ulong? TaskRevision,
    OperatorReadConsistency ReadConsistency,
    DateTimeOffset GeneratedAtUtc)
{
    /// The owner-supplied State Fence discriminator does not exist in the
    /// current page contract. It is reported as absent, never defaulted to a
    /// value the client made up, and it is deliberately not a comparable axis:
    /// a constant can never differ, so comparing it would be a hard-wired pass.
    public const string StateFence = "owner_unissued";

    /// Bounded clock-skew tolerance for the owner timestamp, taken from the
    /// owner's own handoff lifetime. A page dated further into the future is
    /// refused instead of becoming permanently "fresh".
    public static TimeSpan ClockSkewTolerance { get; } =
        TimeSpan.FromSeconds(OperatorProtocol.HandoffLifetimeSeconds);

    /// Classifies the owner-issued page fields into the closed I5.20
    /// `ReadConsistency` vocabulary, reporting only the consistency this
    /// client can actually evidence. This is a classification of what the
    /// owner sent, never a level the client picks.
    ///
    /// `ExactFence` is unreachable here. I5.20:20 requires that all listed
    /// dependency revisions match, but `OperatorProjectionPage` carries
    /// `task_revision` and no `state_fence`, `authority_epoch`,
    /// `resource_generation` or `epoch`, so no owner-issued State Fence exists
    /// on this contract and an exact count plus a bound task revision is not
    /// that match. The word is refused rather than asserted.
    ///
    /// `AtLeastRevision` (I5.20:18, read-your-write after receipt) is reported
    /// only when the owner actually issued a `task_revision` to read after.
    /// With no owner-issued revision there is nothing to be read-your-write
    /// against, so the honest floor I5.20:17 `Eventual` applies.
    public static OperatorReadConsistency ClassifyReadConsistency(OperatorProjectionPage page)
    {
        ArgumentNullException.ThrowIfNull(page);
        // `total_is_exact` is deliberately not read here: it is a count
        // qualifier, not a generation/revision/fence axis, and the owner
        // revision is compared directly in `DiffersFrom`.
        return page.TaskRevision is not null
            ? OperatorReadConsistency.AtLeastRevision
            : OperatorReadConsistency.Eventual;
    }

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
            ClassifyReadConsistency(page),
            page.GeneratedAt);
    }

    /// True when the two bindings describe different owner state. A change on
    /// any identity or read-consistency axis requires invalidation before use.
    ///
    /// The owner timestamp is deliberately not compared: every fresh page
    /// carries a fresh timestamp, so comparing it would rotate on every read
    /// rather than describe a change in owner state, and would destroy the
    /// append (load-more) path. Freshness is a refusal in `From`, not an axis.
    public bool DiffersFrom(OperatorProjectionBinding? other) =>
        other is null
        || !string.Equals(SchemaVersion, other.SchemaVersion, StringComparison.Ordinal)
        || !string.Equals(RuntimeId, other.RuntimeId, StringComparison.Ordinal)
        || !string.Equals(AuthGeneration, other.AuthGeneration, StringComparison.Ordinal)
        || !string.Equals(Projection, other.Projection, StringComparison.Ordinal)
        || !string.Equals(ProjectId, other.ProjectId, StringComparison.Ordinal)
        || !string.Equals(TaskId, other.TaskId, StringComparison.Ordinal)
        || TaskRevision != other.TaskRevision
        || ReadConsistency != other.ReadConsistency;

    /// Bounded redacted projection for the status banner. It names the binding
    /// axes and revision, never a record body.
    public string Describe() =>
        $"runtime={RuntimeId} auth_generation={AuthGeneration} projection={Projection} " +
        $"task_revision={(TaskRevision?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "none")} " +
        $"state_fence={StateFence} read_consistency={ReadConsistency.Token()}";
}

/// One owner-issued degraded capability the current page carries. The
/// classification reads ONLY the closed record vocabulary the Governor
/// emits (`crates/eliot-app/src/mcp_stdio/operator.rs`):
/// `operator_incident_record` issues kind `incident` under authority
/// `governor_incident_service` with the lowercase `IncidentStatus`
/// (`crates/eliot-types/src/safety.rs`: open/acknowledged/mitigated/closed)
/// and a `"{Severity:?} / {Kind:?}"` summary;
/// `operator_backup_record` issues kind `backup_inventory` under authority
/// `governor_backup_service` with the lowercase `BackupStatus`. Anything else
/// is not a degraded signal, and a closed incident is history, not degraded.
/// `Severe` separates a degraded backend (degraded/blocking/critical
/// incident severity, failed/partial backup) from an operational notice
/// (info/warning incident, backup with warnings): both stay visible and
/// neither keeps the green banner.
public sealed record OperatorDegradedSignal(
    string Kind,
    string Summary,
    bool Severe);

/// Classifies the degraded backend capabilities one decoded page already
/// carries, so the UI shows them as degraded (I11.9) instead of keeping the
/// green connected banner. This is a classification of what the owner sent,
/// never a health verdict the client invents.
public static class OperatorDegradedSignals
{
    public const string IncidentKind = "incident";
    public const string IncidentAuthority = "governor_incident_service";
    public const string ClosedIncidentStatus = "closed";
    public const string BackupKind = "backup_inventory";
    public const string BackupAuthority = "governor_backup_service";

    private static readonly string[] DegradedBackupStatuses =
    [
        "failed",
        "partial",
        "succeeded_with_warnings"
    ];

    /// Owner-issued `IncidentSeverity` Debug names that describe a degraded
    /// backend rather than an informational note. They lead the incident
    /// summary as `"{Severity:?} / ..."`, so the match anchors on the
    /// severity position, never on kind text.
    private static readonly string[] DegradedSeverityPrefixes =
    [
        "Degraded / ",
        "Blocking / ",
        "Critical / "
    ];

    public static IReadOnlyList<OperatorDegradedSignal> FromRecords(
        IEnumerable<OperatorRecordView> records)
    {
        ArgumentNullException.ThrowIfNull(records);
        var signals = new List<OperatorDegradedSignal>();
        foreach (var record in records)
        {
            if (record is null) continue;
            if (string.Equals(record.RecordKind, IncidentKind, StringComparison.Ordinal)
                && string.Equals(record.Authority, IncidentAuthority, StringComparison.Ordinal)
                && !string.Equals(record.Status, ClosedIncidentStatus, StringComparison.Ordinal))
            {
                // Severity is owner-issued in the record summary
                // (`"{Severity:?} / {Kind:?}"`); the record title is the human
                // summary shown in the banner.
                signals.Add(new OperatorDegradedSignal(IncidentKind, record.Title, IsDegradedSeverity(record.Summary)));
            }
            else if (string.Equals(record.RecordKind, BackupKind, StringComparison.Ordinal)
                && string.Equals(record.Authority, BackupAuthority, StringComparison.Ordinal)
                && DegradedBackupStatuses.Contains(record.Status, StringComparer.Ordinal))
            {
                var failed = string.Equals(record.Status, "failed", StringComparison.Ordinal)
                    || string.Equals(record.Status, "partial", StringComparison.Ordinal);
                signals.Add(new OperatorDegradedSignal(BackupKind, record.Title, failed));
            }
        }
        return signals;
    }

    public static bool IsDegradedSeverity(string summary) =>
        DegradedSeverityPrefixes.Any(prefix =>
            summary.StartsWith(prefix, StringComparison.Ordinal));
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
