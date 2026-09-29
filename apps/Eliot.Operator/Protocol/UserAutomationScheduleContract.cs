using System.Globalization;
using System.Text;
using System.Text.Json;
using Eliot.Operator.Protocol.Generated;

namespace Eliot.Operator.Protocol;

/// <summary>
/// One refusal of the canonical UserAutomation schedule/occurrence contract,
/// carried with the identity of the exact owner rule that refused it.
/// </summary>
/// <remarks>
/// <para>
/// The contract version, the pinned zone database release and the occurrence
/// grammar are read from the GENERATED mirror
/// (<see cref="OperatorScheduleContract"/>), which is derived from the Kernel
/// owner source and re-checked byte for byte on every build. Nothing in this
/// file re-states an owner constant by hand.
/// </para>
/// <para>
/// The refusal kinds below are the owner's <c>UserAutomationError</c> variants
/// this surface can raise, and every <see cref="Display"/> is the owner's exact
/// <c>Display</c> string, taken from the generated refusal table. That is what
/// makes the refusal actionable: the Human reads the same sentence the Kernel
/// would have produced for the same bytes, not a generic JSON error.
/// </para>
/// <para>
/// This type extends <see cref="InvalidOperationException"/> so the existing
/// Operator submit paths keep treating a locally refused revision as "nothing
/// was sent", while a caller that wants the typed identity can still catch
/// this type and read <see cref="Kind"/>, <see cref="Field"/> and
/// <see cref="OwnerText"/>.
/// </para>
/// </remarks>
public sealed class UserAutomationScheduleContractException : InvalidOperationException
{
    public UserAutomationScheduleContractException(
        string kind,
        string ownerText,
        string action)
        : base($"{ownerText} -> {action}")
    {
        Kind = kind;
        OwnerText = ownerText;
        Action = action;
    }

    /// <summary>The owner variant name whose rule refused these bytes.</summary>
    public string Kind { get; }

    /// <summary>
    /// The exact owner <c>Display</c> string, byte-identical to what the Kernel
    /// emits for the same refusal. It is never reworded, abbreviated or
    /// collapsed into a generic error.
    /// </summary>
    public string OwnerText { get; }

    /// <summary>
    /// The single next action the Human can take, in the Operator's own words.
    /// For a legacy encoding this names the re-normalization action rather than
    /// silently rewriting the revision: an immutable revision is never rewritten
    /// in place.
    /// </summary>
    public string Action { get; }
}

/// <summary>
/// One decoded occurrence record under the normalized schedule grammar, plus
/// its arithmetic instant. Parsing does not establish who produced the record.
/// </summary>
/// <remarks>
/// The raw record is retained verbatim on <see cref="Record"/> so the exact input
/// bytes stay available for submission and inspection. The decoded fields
/// are what the Operator displays: zone identity, the pinned zone database
/// revision, the requested and resolved local wall clocks, the resolved UTC instant and applied offset,
/// and the applied fold/gap disposition.
/// </remarks>
public sealed record UserAutomationNormalizedOccurrence(
    string Record,
    string Encoding,
    string Timezone,
    string ZoneDatabaseRevision,
    string RequestedLocal,
    string ResolvedLocal,
    int OffsetMinutes,
    string Offset,
    string Instant,
    long InstantSeconds,
    string? TransitionBeforeOffset,
    string? TransitionAfterOffset,
    string Disposition,
    string SourceDigest)
{
    /// <summary>
    /// One bounded display line for the Human inspection surface. It states the
    /// pinned database revision, the requested and resolved local clocks, the resolved instant and
    /// offset, the applied disposition and the raw record bytes, so the
    /// projection is inspectable before activation without the Operator
    /// resolving anything.
    /// </summary>
    public string Describe()
    {
        var transition = TransitionBeforeOffset is null
            ? "-"
            : $"{TransitionBeforeOffset}~{TransitionAfterOffset}";
        return string.Create(
            CultureInfo.InvariantCulture,
            $"{Timezone}@{ZoneDatabaseRevision} requested local {RequestedLocal} resolved local {ResolvedLocal} offset {Offset} instant {Instant} disposition {Disposition} transition {transition} source_digest {SourceDigest} record [{Record}]");
    }
}

/// <summary>
/// The typed, local shape-and-field view of one parsed schedule.
/// </summary>
/// <remarks>
/// <para>
/// This is a local projection the Operator builds for a revision it has parsed.
/// It is a METHOD-returned value rather than a
/// property for the same reason <c>IsEffect</c> is a method: the owner-side
/// request records are <c>deny_unknown_fields</c>, so a serialized member the
/// owner does not know would make every request undecodable. Nothing here is
/// transmitted, and nothing here is an owner receipt.
/// </para>
/// <para>
/// What this local projection records is exactly what the supplied revision
/// bytes carry: the contract version, pinned zone database release, zone
/// identity, source digest, occurrence count and resolved instant span. It does
/// NOT assert that the owner issued or normalized those bytes, or admitted the
/// revision. A local projection alone is never normalization evidence.
/// </para>
/// </remarks>
public sealed record UserAutomationScheduleProjection(
    string Encoding,
    string PinnedZoneDatabaseRelease,
    string Timezone,
    string SourceDigest,
    int OccurrenceCount,
    long FirstInstantSeconds,
    long LastInstantSeconds,
    IReadOnlyList<UserAutomationNormalizedOccurrence> Occurrences,
    UserAutomationScheduleNormalizationReceipt? NormalizationReceipt = null)
{
    /// <summary>
    /// The exact contract identity observed in these parsed schedule bytes, as
    /// one line. It names their contract version and pinned database release;
    /// it is inspection data and is not an owner-issued receipt.
    /// </summary>
    public string ContractIdentity() => string.Create(
        CultureInfo.InvariantCulture,
        $"{Encoding} zone-database {PinnedZoneDatabaseRelease} zone {Timezone} source_digest {SourceDigest} occurrences {OccurrenceCount}");
}

/// <summary>
/// The bounded C# mirror of the owner's normalized schedule/occurrence grammar.
/// </summary>
/// <remarks>
/// <para>
/// <b>Responsibility split.</b> The Operator validates bounded JSON/wire shape
/// and the exact supported contract version of supplied revision bytes. The
/// admitted calendar/time owner is responsible for issuing normalized
/// occurrences with bound provenance. Kernel validates owner evidence and
/// admission. The Operator displays parsed projections and fail-closed
/// incompatibilities, but parsing does not prove who produced the bytes. This mirror
/// therefore never resolves a zone, never reads a timezone database, and never
/// consults ambient Windows locale or timezone data; it does not call
/// <see cref="TimeZoneInfo"/>, <see cref="DateTime"/> or any other ambient
/// clock.
/// </para>
/// <para>
/// <b>What is deliberately NOT mirrored.</b> Three owner rules are absent on
/// purpose and stay the owner's decision: zone-table membership
/// (<c>is_pinned_zone</c>), the pinned zone evidence check
/// (<c>require_pinned_zone_evidence</c>, which needs that table), and the pinned
/// zone-table window. The Operator also cannot recompute the occurrence source
/// digest: it is a SHA-256 over a Rust canonical JSON tuple of the expression
/// and calendar, and the Operator does not own the expression language. It pins
/// only what the supplied bytes decide — see
/// <see cref="RequireOneSourceDigest"/> and
/// <see cref="RequireFreshOwnerEvidenceForEdit"/> for exactly what is pinned
/// and what is not.
/// </para>
/// <para>
/// Every rule below is a port of one named owner function, and the byte shape of
/// those functions is digested into the generated artefact, so a Rust change to
/// a rule this mirror depends on fails the build until the mirror is revisited.
/// </para>
/// </remarks>
public static class UserAutomationScheduleMirror
{
    /// <summary>
    /// Port of <c>is_legacy_occurrence_key</c>. A key is the retired, shape-only
    /// encoding when its length is exactly a civil wall clock plus <c>Z</c>, or
    /// exactly a civil wall clock plus a UTC offset, AND its first
    /// <c>CIVIL_WALL_CLOCK_BYTES</c> bytes match the civil wall-clock shape.
    /// </summary>
    public static bool IsLegacyOccurrenceKey(string occurrenceKey)
    {
        ArgumentNullException.ThrowIfNull(occurrenceKey);
        var bytes = Encoding.UTF8.GetBytes(occurrenceKey);
        var retired = bytes.Length == OperatorScheduleContract.LEGACY_OCCURRENCE_INSTANT_BYTES
            || bytes.Length == OperatorScheduleContract.LEGACY_OCCURRENCE_OFFSET_BYTES;
        if (!retired) return false;
        for (var index = 0; index < OperatorScheduleContract.CIVIL_WALL_CLOCK_BYTES; index++)
        {
            if (!IsCivilWallClockByte(bytes, index)) return false;
        }
        return true;
    }

    /// <summary>
    /// V2 and V3 are retired versioned occurrence contracts. They cannot be
    /// reinterpreted as V4 because neither carries both local clocks.
    /// </summary>
    private static bool IsPredecessorOccurrenceEncoding(string encoding) =>
        encoding is OperatorScheduleContract.LEGACY_NORMALIZED_OCCURRENCE_ENCODING_V2
            or OperatorScheduleContract.LEGACY_NORMALIZED_OCCURRENCE_ENCODING_V3;

    /// <summary>
    /// Port of <c>parse_civil_wall_clock</c>. The value must be exactly
    /// <c>YYYY-MM-DDTHH:MM:SS</c> — no fractional second, no lower-case
    /// <c>t</c>, no leap second — and must be range-checked against the
    /// proleptic Gregorian calendar, honouring leap days and the closed year
    /// range. Nothing here reads a clock or a locale: the same bytes always
    /// produce the same value.
    /// </summary>
    private static long ParseCivilWallClockSeconds(string value, string field)
    {
        if (!IsCanonicalCivilWallClock(value))
        {
            throw Invalid(field);
        }

        var year = DecimalQuad(value);
        var month = DecimalPair(value, 5);
        var day = DecimalPair(value, 8);
        var hour = DecimalPair(value, 11);
        var minute = DecimalPair(value, 14);
        var second = DecimalPair(value, 17);
        if (year < OperatorScheduleContract.MIN_CIVIL_YEAR
            || year > OperatorScheduleContract.MAX_CIVIL_YEAR
            || month is < 1 or > 12
            || day == 0
            || day > DaysInCivilMonth(year, month)
            || hour > 23
            || minute > 59
            || second > 59)
        {
            throw Invalid(field);
        }
        return DaysFromCivil(year, month, day) * 86_400L
            + hour * 3_600L
            + minute * 60L
            + second;
    }

    /// <summary>
    /// Port of <c>parse_utc_offset</c>. The canonical spelling is
    /// <c>+HH:MM</c> or <c>-HH:MM</c>. A negative zero and any offset past the
    /// largest civil offset the database contains are refused, so a spelled
    /// offset that names no instant never reaches the projection.
    /// </summary>
    private static int ParseUtcOffsetMinutes(string value, string field)
    {
        if (!IsCanonicalUtcOffset(value))
        {
            throw Invalid(field);
        }
        var hours = DecimalPair(value, 1);
        var minutes = DecimalPair(value, 4);
        if (hours > 23 || minutes > 59)
        {
            throw Invalid(field);
        }
        var total = hours * 60 + minutes;
        if ((total == 0 && value[0] == '-')
            || total > OperatorScheduleContract.MAX_CIVIL_UTC_OFFSET_MINUTES)
        {
            throw Invalid(field);
        }
        return value[0] == '+' ? total : -total;
    }

    /// <summary>
    /// Port of <c>parse_utc_instant</c>: the canonical spelling of a resolved
    /// instant is the civil UTC value with a <c>Z</c> suffix, so one instant has
    /// exactly one byte representation.
    /// </summary>
    private static long ParseUtcInstantSeconds(string value, string field)
    {
        if (value.Length != OperatorScheduleContract.UTC_INSTANT_BYTES
            || value[^1] != 'Z')
        {
            throw Invalid(field);
        }
        return ParseCivilWallClockSeconds(
            value[..OperatorScheduleContract.CIVIL_WALL_CLOCK_BYTES], field);
    }

    /// <summary>
    /// Port of <c>parse_civil_instant</c>: <c>start_at</c> and <c>end_at</c> are
    /// INSTANTS, not wall clocks, so the offset is applied here. This is the
    /// exact reason lexical comparison of the interval bounds is wrong, and why
    /// the mirror never compares those two strings as text.
    /// </summary>
    private static long ParseCivilInstantSeconds(string value, string field)
    {
        if (value.Length < OperatorScheduleContract.CIVIL_WALL_CLOCK_BYTES + 1)
        {
            throw Invalid(field);
        }
        var civil = ParseCivilWallClockSeconds(
            value[..OperatorScheduleContract.CIVIL_WALL_CLOCK_BYTES], field);
        var offset = value[OperatorScheduleContract.CIVIL_WALL_CLOCK_BYTES..];
        var offsetMinutes = offset == "Z" ? 0 : ParseUtcOffsetMinutes(offset, field);
        return civil - (long)offsetMinutes * 60L;
    }

    /// <summary>
    /// Port of <c>parse_transition_window</c>. A unique occurrence carries
    /// <c>-</c>: its local wall clock exists once, so there is no transition to
    /// reproduce. A fold or a gap carries the offsets the pinned revision applies
    /// immediately before and after the transition, joined by <c>~</c>; the
    /// step between them must be non-zero and no larger than one civil day.
    /// </summary>
    private static (string? Before, string? After) ParseTransitionWindow(
        string value,
        string disposition,
        string field)
    {
        if (disposition == "UNIQUE")
        {
            return value == "-" ? (null, null) : throw Invalid(field);
        }
        var separator = value.IndexOf('~', StringComparison.Ordinal);
        if (separator < 0 || value.IndexOf('~', separator + 1) >= 0)
        {
            throw Invalid(field);
        }
        var before = value[..separator];
        var after = value[(separator + 1)..];
        var pre = ParseUtcOffsetMinutes(before, field);
        var post = ParseUtcOffsetMinutes(after, field);
        var step = Math.Abs(pre - post);
        if (step == 0 || step > OperatorScheduleContract.MAX_TRANSITION_STEP_MINUTES)
        {
            throw Invalid(field);
        }
        return (before, after);
    }

    /// <summary>
    /// Port of <c>require_declared_disposition</c>. A <c>REJECT</c> policy
    /// produces no normalized occurrence at all, so a <c>REJECT</c> schedule
    /// never carries a fold or gap member and a <c>FIRST</c> or <c>SECOND</c>
    /// schedule never silently carries the other side of a fold.
    /// </summary>
    private static void RequireDeclaredDisposition(
        string disposition,
        string dstFold,
        string dstGap)
    {
        var admitted = disposition switch
        {
            "UNIQUE" => true,
            "FOLD_FIRST" => dstFold == "FIRST",
            "FOLD_SECOND" => dstFold == "SECOND",
            "GAP_SHIFT_FORWARD" => dstGap == "SHIFT_FORWARD",
            _ => false
        };
        if (!admitted)
        {
            throw Invalid("schedule.occurrence_key.disposition");
        }
    }

    /// <summary>
    /// Port of <c>validate_occurrence_local_relation</c>. The requested and
    /// resolved wall clocks, transition, applied offset and UTC instant must be
    /// one arithmetic relation. This consumes supplied bytes only; it consults
    /// no zone table or ambient timezone data.
    /// </summary>
    private static void ValidateOccurrenceLocalRelation(
        long requestedLocalSeconds,
        long resolvedLocalSeconds,
        int offsetMinutes,
        string disposition,
        (string? Before, string? After) transition,
        long instantSeconds)
    {
        if (disposition == "UNIQUE")
        {
            if (transition.Before is not null || transition.After is not null)
            {
                throw Invalid("schedule.occurrence_key.transition");
            }
            if (requestedLocalSeconds != resolvedLocalSeconds)
            {
                throw Invalid("schedule.occurrence_key.resolved_local");
            }
            RequireInstantForOffset(resolvedLocalSeconds, offsetMinutes, instantSeconds);
            return;
        }

        if (disposition == "FOLD_FIRST"
            && transition.Before is not null
            && transition.After is not null
            && ParseUtcOffsetMinutes(transition.Before, "schedule.occurrence_key.transition")
                > ParseUtcOffsetMinutes(transition.After, "schedule.occurrence_key.transition")
            && offsetMinutes == ParseUtcOffsetMinutes(
                transition.Before, "schedule.occurrence_key.transition"))
        {
            RequireEqualFoldClocksAndInstant(requestedLocalSeconds, resolvedLocalSeconds, offsetMinutes, instantSeconds);
            return;
        }

        if (disposition == "FOLD_SECOND"
            && transition.Before is not null
            && transition.After is not null
            && ParseUtcOffsetMinutes(transition.Before, "schedule.occurrence_key.transition")
                > ParseUtcOffsetMinutes(transition.After, "schedule.occurrence_key.transition")
            && offsetMinutes == ParseUtcOffsetMinutes(
                transition.After, "schedule.occurrence_key.transition"))
        {
            RequireEqualFoldClocksAndInstant(requestedLocalSeconds, resolvedLocalSeconds, offsetMinutes, instantSeconds);
            return;
        }

        if (disposition == "GAP_SHIFT_FORWARD"
            && transition.Before is not null
            && transition.After is not null
            && ParseUtcOffsetMinutes(transition.Before, "schedule.occurrence_key.transition")
                < ParseUtcOffsetMinutes(transition.After, "schedule.occurrence_key.transition")
            && offsetMinutes == ParseUtcOffsetMinutes(
                transition.After, "schedule.occurrence_key.transition"))
        {
            var pre = ParseUtcOffsetMinutes(transition.Before, "schedule.occurrence_key.transition");
            var post = ParseUtcOffsetMinutes(transition.After, "schedule.occurrence_key.transition");
            var gapSeconds = (long)(post - pre) * 60L;
            if (requestedLocalSeconds + gapSeconds != resolvedLocalSeconds)
            {
                throw Invalid("schedule.occurrence_key.resolved_local");
            }
            var requestedInstant = requestedLocalSeconds - (long)pre * 60L;
            var resolvedInstant = resolvedLocalSeconds - (long)post * 60L;
            if (requestedInstant != resolvedInstant)
            {
                throw Invalid("schedule.occurrence_key.resolved_local");
            }
            if (instantSeconds != requestedInstant)
            {
                throw Invalid("schedule.occurrence_key.instant");
            }
            return;
        }

        throw Invalid("schedule.occurrence_key.transition");
    }

    private static void RequireEqualFoldClocksAndInstant(
        long requestedLocalSeconds,
        long resolvedLocalSeconds,
        int offsetMinutes,
        long instantSeconds)
    {
        if (requestedLocalSeconds != resolvedLocalSeconds)
        {
            throw Invalid("schedule.occurrence_key.resolved_local");
        }
        RequireInstantForOffset(resolvedLocalSeconds, offsetMinutes, instantSeconds);
    }

    private static void RequireInstantForOffset(long localSeconds, int offsetMinutes, long instantSeconds)
    {
        if (localSeconds - (long)offsetMinutes * 60L != instantSeconds)
        {
            throw Invalid("schedule.occurrence_key.instant");
        }
    }

    /// <summary>
    /// Port of the owner's <c>parse_occurrence</c>, restricted to the rules the
    /// Operator may decide from supplied occurrence bytes alone.
    /// </summary>
    /// <remarks>
    /// Two owner rules are deliberately not here. Zone-table membership and the
    /// pinned zone evidence check need the pinned table, which is the owner's
    /// data and would make the Operator a second zone owner. The source digest
    /// EQUALITY against the owner's compiled digest is not here either: that
    /// digest is a SHA-256 over a Rust canonical JSON tuple of the expression
    /// language, which the Operator does not own and cannot recompute. What is
    /// pinned instead is that the digest field is non-empty and that EVERY
    /// member of one schedule carries the SAME one, which
    /// <see cref="RequireOneSourceDigest"/> checks across the whole set. The
    /// Kernel remains the only component that can decide whether that digest is
    /// the right one for this expression and calendar.
    /// </remarks>
    private static UserAutomationNormalizedOccurrence ParseOccurrence(
        string occurrenceKey,
        string timezone,
        string dstFold,
        string dstGap)
    {
        if (Encoding.UTF8.GetByteCount(occurrenceKey) > OperatorScheduleContract.MAX_OCCURRENCE_KEY_BYTES)
        {
            throw Invalid("schedule.occurrence_key.shape");
        }
        var fields = occurrenceKey.Split(
            OperatorScheduleContract.NORMALIZED_OCCURRENCE_FIELD_SEPARATOR);
        if (fields.Length != OperatorScheduleContract.NORMALIZED_OCCURRENCE_FIELD_COUNT)
        {
            throw (IsLegacyOccurrenceKey(occurrenceKey)
                || (fields.Length > 0 && IsPredecessorOccurrenceEncoding(fields[0])))
                ? LegacyScheduleEncoding()
                : Invalid("schedule.occurrence_key.shape");
        }
        var encoding = fields[0];
        if (!string.Equals(encoding, OperatorScheduleContract.NORMALIZED_OCCURRENCE_ENCODING, StringComparison.Ordinal))
        {
            if (IsPredecessorOccurrenceEncoding(encoding))
            {
                throw LegacyScheduleEncoding();
            }
            // The exact supported contract version is a shape/version refusal,
            // not a semantic one: the Operator does not recognize this record
            // as a current revision, and it never rewrites it into one.
            throw new UserAutomationScheduleContractException(
                "Invalid",
                OwnerText("Invalid", "schedule.occurrence_key.encoding"),
                $"re-normalize the schedule under {OperatorScheduleContract.NORMALIZED_OCCURRENCE_ENCODING}; this Operator admits that contract version only");
        }
        if (!string.Equals(fields[1], timezone, StringComparison.Ordinal))
        {
            throw Invalid("schedule.occurrence_key.timezone");
        }
        if (fields[2].Length > OperatorScheduleContract.MAX_ZONE_DATABASE_REVISION_BYTES
            || !string.Equals(
                fields[2], OperatorScheduleContract.PINNED_ZONE_DATABASE_RELEASE, StringComparison.Ordinal))
        {
            throw new UserAutomationScheduleContractException(
                "ZoneDatabaseRevision",
                OwnerText("ZoneDatabaseRevision", "schedule.occurrence_key.zone_database_revision"),
                $"obtain a new owner normalization against pinned zone database {OperatorScheduleContract.PINNED_ZONE_DATABASE_RELEASE}; a database update can never rewrite an existing revision");
        }
        if (fields[9].Length == 0
            || Encoding.UTF8.GetByteCount(fields[9]) > OperatorScheduleContract.MAX_OCCURRENCE_KEY_BYTES)
        {
            throw Invalid("schedule.occurrence_key.source_digest");
        }
        var disposition = fields[8];
        if (!OperatorScheduleContract.Dispositions.Contains(disposition, StringComparer.Ordinal))
        {
            throw Invalid("schedule.occurrence_key.disposition");
        }
        RequireDeclaredDisposition(disposition, dstFold, dstGap);
        var requestedLocalSeconds = ParseCivilWallClockSeconds(
            fields[3], "schedule.occurrence_key.requested_local");
        var resolvedLocalSeconds = ParseCivilWallClockSeconds(
            fields[4], "schedule.occurrence_key.resolved_local");
        var offsetMinutes = ParseUtcOffsetMinutes(fields[5], "schedule.occurrence_key.offset");
        var instantSeconds = ParseUtcInstantSeconds(fields[6], "schedule.occurrence_key.instant");
        var transition = ParseTransitionWindow(
            fields[7], disposition, "schedule.occurrence_key.transition");
        ValidateOccurrenceLocalRelation(
            requestedLocalSeconds, resolvedLocalSeconds, offsetMinutes, disposition, transition, instantSeconds);
        return new UserAutomationNormalizedOccurrence(
            Record: occurrenceKey,
            Encoding: encoding,
            Timezone: fields[1],
            ZoneDatabaseRevision: fields[2],
            RequestedLocal: fields[3],
            ResolvedLocal: fields[4],
            OffsetMinutes: offsetMinutes,
            Offset: fields[5],
            Instant: fields[6],
            InstantSeconds: instantSeconds,
            TransitionBeforeOffset: transition.Before,
            TransitionAfterOffset: transition.After,
            Disposition: disposition,
            SourceDigest: fields[9]);
    }

    /// <summary>
    /// Bounded local inspection of the cross-member and interval rules over the
    /// supplied occurrence set. This does not issue normalization evidence.
    /// </summary>
    /// <remarks>
    /// The interval bounds are parsed as INSTANTS and every member is compared
    /// by its resolved canonical instant. Lexical ordering of the raw records is
    /// NOT used anywhere: two chronologically ordered members of one set can
    /// spell their instants so that a byte comparison puts them in the opposite
    /// order, and a mixed-offset set is exactly that case.
    /// </remarks>
    public static UserAutomationScheduleProjection ReadScheduleProjection(
        string timezone,
        string dstFold,
        string dstGap,
        string startAt,
        string? endAt,
        IReadOnlyList<string> nextOccurrences)
    {
        ArgumentNullException.ThrowIfNull(nextOccurrences);
        RequireCanonicalTimezone(timezone);
        var start = ParseCivilInstantSeconds(startAt, "schedule.start_at");
        var end = endAt is null ? (long?)null : ParseCivilInstantSeconds(endAt, "schedule.end_at");
        if (end is { } last && last < start)
        {
            throw Invalid("schedule.end_at");
        }

        string? pinnedRevision = null;
        string? sourceDigest = null;
        long? previousInstant = null;
        var occurrences = new List<UserAutomationNormalizedOccurrence>(nextOccurrences.Count);
        foreach (var key in nextOccurrences)
        {
            var occurrence = ParseOccurrence(key, timezone, dstFold, dstGap);
            if (pinnedRevision is not null
                && !string.Equals(pinnedRevision, occurrence.ZoneDatabaseRevision, StringComparison.Ordinal))
            {
                throw Invalid("schedule.next_occurrences.zone_database_revision");
            }
            pinnedRevision ??= occurrence.ZoneDatabaseRevision;
            if (occurrence.InstantSeconds < start
                || (end is { } bound && occurrence.InstantSeconds > bound))
            {
                throw Invalid("schedule.next_occurrences.interval");
            }
            if (previousInstant is { } previous)
            {
                if (occurrence.InstantSeconds == previous)
                {
                    throw Invalid("schedule.next_occurrences.duplicate_instant");
                }
                if (occurrence.InstantSeconds < previous)
                {
                    throw Invalid("schedule.next_occurrences.order");
                }
            }
            previousInstant = occurrence.InstantSeconds;
            sourceDigest ??= occurrence.SourceDigest;
            occurrences.Add(occurrence);
        }
        RequireOneSourceDigest(occurrences);

        return new UserAutomationScheduleProjection(
            Encoding: OperatorScheduleContract.NORMALIZED_OCCURRENCE_ENCODING,
            PinnedZoneDatabaseRelease: pinnedRevision
                ?? OperatorScheduleContract.PINNED_ZONE_DATABASE_RELEASE,
            Timezone: timezone,
            SourceDigest: sourceDigest ?? string.Empty,
            OccurrenceCount: occurrences.Count,
            FirstInstantSeconds: occurrences.Count == 0 ? 0L : occurrences[0].InstantSeconds,
            LastInstantSeconds: occurrences.Count == 0 ? 0L : occurrences[^1].InstantSeconds,
            Occurrences: occurrences);
    }

    /// <summary>
    /// Every member of one schedule carries the SAME compiled source digest.
    /// </summary>
    /// <remarks>
    /// This is the whole of what the Operator can decide about the source digest.
    /// The owner additionally requires that value to equal the digest it
    /// compiled from this schedule's <c>expression</c> and <c>calendar</c>; that
    /// equality is not reproducible here, because the digest is a SHA-256 over a
    /// Rust canonical JSON tuple of an expression language the Operator does not
    /// own. The Operator therefore proves the members agree with each other and
    /// leaves the value to the owner. It never claims to have verified it.
    /// <para>
    /// The owner states the same fact per member, as
    /// <c>schedule.occurrence_key.source_digest</c>; the cross-member form
    /// <c>schedule.next_occurrences.source_digest</c> below is the Operator's
    /// spelling of that single owner rule over the whole set.
    /// </para>
    /// </remarks>
    public static void RequireOneSourceDigest(
        IReadOnlyList<UserAutomationNormalizedOccurrence> occurrences)
    {
        ArgumentNullException.ThrowIfNull(occurrences);
        string? first = null;
        foreach (var occurrence in occurrences)
        {
            if (occurrence.SourceDigest.Length == 0)
            {
                throw Invalid("schedule.occurrence_key.source_digest");
            }
            if (first is not null
                && !string.Equals(first, occurrence.SourceDigest, StringComparison.Ordinal))
            {
                throw Invalid("schedule.next_occurrences.source_digest");
            }
            first ??= occurrence.SourceDigest;
        }
    }

    /// <summary>
    /// The non-table part of the owner's <c>validate_timezone</c>: the declared
    /// zone identity must be non-empty, bounded, and carry no leading or trailing
    /// whitespace.
    /// </summary>
    /// <remarks>
    /// Zone MEMBERSHIP is not checked and is not checkable here: the owner admits
    /// a zone by membership of the pinned zone table, and answering from a
    /// spelling or from an ambient Windows timezone list is exactly the second
    /// zone owner this surface must not become. An unknown or invented zone is
    /// therefore the owner's <c>UnknownZone</c> refusal, which the classifier
    /// surfaces verbatim.
    /// </remarks>
    public static void RequireCanonicalTimezone(string timezone)
    {
        if (string.IsNullOrEmpty(timezone)
            || Encoding.UTF8.GetByteCount(timezone) > OperatorScheduleContract.MAX_ZONE_IDENTITY_BYTES
            || timezone.Trim() != timezone)
        {
            throw Invalid("schedule.timezone.canonical");
        }
    }

    /// <summary>
    /// Refuses a fresh create/edit submission until an owner-issued normalization
    /// result or explicit migration action is bound to the immutable revision.
    /// </summary>
    /// <remarks>
    /// The accepted owner operation schema validates caller-supplied V4
    /// occurrence records, but exposes no callable normalization result,
    /// migration action, or bound owner identity. Equality with a previous
    /// revision and a caller-supplied source digest prove neither owner issuance
    /// nor freshness. This gate belongs to fresh submission, not typed request
    /// validation: retained requests must remain decodable for exact-identity
    /// reconciliation. Reads and inspection remain available, and no immutable
    /// revision is rewritten.
    /// </remarks>
    public static void RequireOwnerIssuedNormalizationForFreshSubmission(string action)
    {
        if (!string.Equals(action, "create", StringComparison.Ordinal)
            && !string.Equals(action, "edit", StringComparison.Ordinal))
        {
            throw new ArgumentOutOfRangeException(
                nameof(action),
                "Only fresh create/edit schedule submissions require this owner-issued normalization gate.");
        }

        throw new InvalidOperationException(
            $"UserAutomation {action} not sent: the current owner contract has no callable normalization result or explicit migration action bound to this immutable schedule revision. Preserve the existing revision; obtain an owner-issued result bound to a new immutable revision before submission.");
    }

    /// <summary>
    /// Checks only the locally provable relation between source fields and
    /// source digests for an edit. It cannot establish fresh owner evidence.
    /// </summary>
    /// <remarks>
    /// The owner source digest is a hash of expression and calendar only. This
    /// method rejects reusing the prior digest after either source field changes
    /// and rejects changing the digest when both source fields stay the same.
    /// A zone, DST policy, interval or occurrence change may validly retain the
    /// same digest; whether that effect-relevant edit has fresh normalization
    /// evidence cannot be decided here. Fresh submissions are guarded separately
    /// because the Operator cannot recompute the source hash or prove provenance.
    /// </remarks>
    public static void RequireFreshOwnerEvidenceForEdit(
        UserAutomationNormalizedSchedule previous,
        UserAutomationNormalizedSchedule next)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(next);
        var previousProjection = previous.ReadLocalProjection();
        var nextProjection = next.ReadLocalProjection();
        var sameSource = string.Equals(previous.Expression, next.Expression, StringComparison.Ordinal)
            && string.Equals(previous.Calendar, next.Calendar, StringComparison.Ordinal);
        var sameDigest = string.Equals(
            previousProjection.SourceDigest, nextProjection.SourceDigest, StringComparison.Ordinal);
        if (!sameSource && sameDigest)
        {
            throw new UserAutomationScheduleContractException(
                "Invalid",
                OwnerText("Invalid", "schedule.next_occurrences.source_digest"),
                "this edit changes its expression or calendar but reuses the previous source digest; obtain fresh owner normalization and submit a new immutable revision");
        }
        if (sameSource && !sameDigest)
        {
            throw new UserAutomationScheduleContractException(
                "Invalid",
                OwnerText("Invalid", "schedule.occurrence_key.source_digest"),
                "this edit keeps the same expression and calendar but changes their source digest; obtain the correct owner normalization for this source");
        }
    }

    /// <summary>
    /// Renders one owner refusal's exact <c>Display</c> string, using the
    /// generated refusal table so the sentence is never re-typed here.
    /// </summary>
    /// <remarks>
    /// A variant that carries a payload gets the offending field appended to the
    /// literal prefix; a variant whose sentence is fixed gets that sentence
    /// alone. A field is therefore never concatenated onto a complete owner
    /// sentence.
    /// </remarks>
    public static string OwnerText(string variant, string field) =>
        FindTemplate(variant, field)
        ?? throw new UserAutomationScheduleContractException(
            "Unclassified",
            $"the owner refusal {variant} is not in the generated refusal table",
            "regenerate the schedule contract mirror; the Operator cannot name this refusal");

    private static string? FindTemplate(string variant, string field)
    {
        var template = OperatorScheduleContract.OwnerRefusals
            .FirstOrDefault(candidate => candidate.Variant == variant);
        if (template is null) return null;
        return template.CarriesPayload ? template.LiteralPrefix + field : template.DisplayTemplate;
    }

    private static UserAutomationScheduleContractException Invalid(string field) =>
        new("Invalid", OwnerText("Invalid", field), "correct the revision payload and resubmit");

    private static UserAutomationScheduleContractException LegacyScheduleEncoding() =>
        new(
            "LegacyScheduleEncoding",
            OwnerText("LegacyScheduleEncoding", "schedule.next_occurrences"),
            "this occurrence uses a retired encoding; this Operator has no owner re-normalization or migration route, so preserve the legacy revision and obtain a current owner-normalized result before creating a NEW revision; an immutable revision is never rewritten in place");

    private static bool IsCanonicalCivilWallClock(string value)
    {
        if (value.Length != OperatorScheduleContract.CIVIL_WALL_CLOCK_BYTES) return false;
        for (var index = 0; index < OperatorScheduleContract.CIVIL_WALL_CLOCK_BYTES; index++)
        {
            if (!IsCivilWallClockByte(value, index)) return false;
        }
        return true;
    }

    private static bool IsCivilWallClockByte(string value, int index)
    {
        var expected = index switch
        {
            4 or 7 => '-',
            10 => 'T',
            13 or 16 => ':',
            _ => '\0'
        };
        var current = value[index];
        return expected == '\0' ? current is >= '0' and <= '9' : current == expected;
    }

    private static bool IsCivilWallClockByte(byte[] value, int index)
    {
        int expected = index switch
        {
            4 or 7 => '-',
            10 => 'T',
            13 or 16 => ':',
            _ => 0
        };
        int current = value[index];
        return expected == 0
            ? current is >= '0' and <= '9'
            : current == expected;
    }

    private static bool IsCanonicalUtcOffset(string value)
    {
        if (value.Length != OperatorScheduleContract.UTC_OFFSET_BYTES) return false;
        if (value[0] is not ('+' or '-')) return false;
        if (value[3] != ':') return false;
        return IsDigit(value[1]) && IsDigit(value[2]) && IsDigit(value[4]) && IsDigit(value[5]);
    }

    private static bool IsDigit(char value) => value is >= '0' and <= '9';

    private static int DecimalPair(string value, int start) =>
        (value[start] - '0') * 10 + (value[start + 1] - '0');

    private static int DecimalQuad(string value) => DecimalPair(value, 0) * 100 + DecimalPair(value, 2);

    private static bool IsCivilLeapYear(int year) =>
        year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);

    private static int DaysInCivilMonth(int year, int month) => month switch
    {
        1 or 3 or 5 or 7 or 8 or 10 or 12 => 31,
        4 or 6 or 9 or 11 => 30,
        2 when IsCivilLeapYear(year) => 29,
        2 => 28,
        _ => 0
    };

    /// <summary>
    /// Days from 1970-01-01 to one proleptic Gregorian civil date, computed the
    /// owner's way. It reads no clock, locale or calendar database, so two
    /// processes always agree on the chronological order of a normalized
    /// occurrence.
    /// </summary>
    private static long DaysFromCivil(int year, int month, int day)
    {
        var shiftedYear = month <= 2 ? year - 1 : year;
        var shiftedMonth = month <= 2 ? month + 12 : month;
        // The caller range-checks the year to MIN_CIVIL_YEAR..=MAX_CIVIL_YEAR, the
        // domain in which `shiftedYear` is non-negative and truncating division
        // is therefore the owner's floor division.
        var era = shiftedYear / 400;
        var yearOfEra = shiftedYear - era * 400;
        var monthPosition = shiftedMonth - 3;
        var dayOfYear = (153 * monthPosition + 2) / 5 + day - 1;
        var dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear;
        return era * 146_097L + dayOfEra - 719_468L;
    }
}

/// <summary>
/// What the Operator is allowed to say about one typed UserAutomation result.
/// A decodable occurrence projection is inspection data; without independently
/// bound owner provenance it is never a normalization claim.
/// </summary>
public enum UserAutomationOutcomeClass
{
    /// <summary>The owner answered and this answer carries no typed refusal.</summary>
    OwnerAnswered,

    /// <summary>The owner answered with a structured refusal this build can name.</summary>
    OwnerRefused,

    /// <summary>The owner route is unavailable and this operation remains unresolved.</summary>
    OwnerUnavailable,

    /// <summary>
    /// An unresolved owner transition includes a schedule projection that can
    /// be inspected, but does not settle the operation outcome or prove fresh
    /// normalization provenance.
    /// </summary>
    OwnerScheduleOutcomeUnknown,

    /// <summary>
    /// The owner reports a current versioned transition bound to the submitted
    /// operation. The Operator has no independent current-fence comparand, and
    /// the schedule fields remain inspection data without normalization proof.
    /// </summary>
    OwnerBoundTransitionScheduleUnverified,

    /// <summary>The owner reports non-retention, but no independent current-fence comparison is available.</summary>
    OwnerReportedNotRetainedFenceUnverified,

    /// <summary>The owner reports a commit with a ledger read owed, but the current fence is not independently compared.</summary>
    OwnerReportedCommitFenceUnverifiedLedgerReadOwed,

    /// <summary>
    /// The answer does not prove schedule normalization provenance. A decodable
    /// projection may be displayed for inspection, but is always unverified.
    /// </summary>
    UnverifiedOwnerAnswer,

    /// <summary>
    /// The owner did not answer at all, or the answer could not be bound to a
    /// request. The Operator reports the named failure and never claims the
    /// schedule is normalized.
    /// </summary>
    OwnerAbsent,

    /// <summary>
    /// The revision was refused locally, before anything was sent, on the exact
    /// wire shape and contract version this Operator supports.
    /// </summary>
    RefusedBeforeSubmission
}

/// <summary>
/// The decoded result of one typed UserAutomation operation: what the owner
/// said, which typed refusal it was, and any parsed schedule projection summary.
/// A projection is inspection data, not proof of owner-issued normalization.
/// </summary>
public sealed record UserAutomationOutcome(
    UserAutomationOutcomeClass Class,
    string Title,
    string Detail,
    string? RefusalKind,
    string? RefusalText,
    UserAutomationScheduleProjection? ScheduleProjection);

/// <summary>
/// Identity retained by the Operator for the exact request whose response is
/// being decoded. The transport correlation is deliberately a separate,
/// optional field: this client does not expose its JSON-RPC identifier, so it
/// remains null rather than being inferred from the operation key.
/// </summary>
public sealed record UserAutomationResultValidationContext
{
    // A reviewed decoder change must explicitly acknowledge the Rust result schema.
    private const string SupportedUserAutomationResultSchemaSha256 = "a33f0f2df3f54d99ac0af98f256bd4766f943552a46be06c98e5f74f4462dc5c";

    private UserAutomationResultValidationContext(
        string expectedOperationId,
        string expectedIdempotencyKey,
        string expectedResultWireId,
        int supportedResultWireVersion,
        string? transportCorrelationId)
    {
        ExpectedOperationId = expectedOperationId;
        ExpectedIdempotencyKey = expectedIdempotencyKey;
        ExpectedResultWireId = expectedResultWireId;
        SupportedResultWireVersion = supportedResultWireVersion;
        TransportCorrelationId = transportCorrelationId;
    }

    public string ExpectedOperationId { get; }

    public string ExpectedIdempotencyKey { get; }

    /// <summary>The versioned result contract this decoder admits.</summary>
    public string ExpectedResultWireId { get; }

    public int SupportedResultWireVersion { get; }

    /// <summary>
    /// The transport may expose a separate JSON-RPC correlation identifier in
    /// a future client. It is null while the client hides that identifier and
    /// is never substituted for the semantic operation identity.
    /// </summary>
    public string? TransportCorrelationId { get; }

    /// <summary>
    /// Creates validation context from the same request value that is sent or
    /// retained for recovery. It preserves the exact retry key; the retained
    /// request reader deliberately does not rederive it through today's
    /// serializer. A newly minted request has already derived its key in
    /// <see cref="UserAutomationOperatorRequest.Create"/>.
    /// </summary>
    public static UserAutomationResultValidationContext FromRequest(
        UserAutomationOperatorRequest request,
        string? transportCorrelationId = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.Validate();
        if (transportCorrelationId is not null
            && (string.IsNullOrWhiteSpace(transportCorrelationId)
                || transportCorrelationId.Length > 256
                || transportCorrelationId.Any(char.IsControl)))
        {
            throw new ArgumentException("transport correlation identifier is malformed", nameof(transportCorrelationId));
        }

        return new UserAutomationResultValidationContext(
            $"user-automation-operation:{request.IdempotencyKey}",
            request.IdempotencyKey,
            OperatorScheduleContract.USER_AUTOMATION_RESULT_WIRE_ID,
            OperatorScheduleContract.USER_AUTOMATION_RESULT_WIRE_VERSION,
            transportCorrelationId);
    }

    /// <summary>Rejects a context that does not name the current closed wire contract.</summary>
    public bool IsValid() =>
        string.Equals(
            ExpectedOperationId,
            $"user-automation-operation:{ExpectedIdempotencyKey}",
            StringComparison.Ordinal)
        && string.Equals(
            ExpectedResultWireId,
            OperatorScheduleContract.USER_AUTOMATION_RESULT_WIRE_ID,
            StringComparison.Ordinal)
        && SupportedResultWireVersion == OperatorScheduleContract.USER_AUTOMATION_RESULT_WIRE_VERSION
        && string.Equals(
            OperatorScheduleContract.USER_AUTOMATION_RESULT_SCHEMA_SHA256,
            SupportedUserAutomationResultSchemaSha256,
            StringComparison.Ordinal);
}

/// <summary>
/// Decodes one owner answer into a typed, actionable outcome.
/// </summary>
/// <remarks>
/// <para>
/// A Kernel refusal is decoded only from the bounded, closed typed envelope.
/// Its operation identity is checked against the request that produced this
/// answer. Refusal codes are a closed vocabulary; display prose is never scanned
/// to infer a code. An unknown, malformed or mismatched envelope is
/// <see cref="UserAutomationOutcomeClass.UnverifiedOwnerAnswer"/>, never a
/// success.
/// </para>
/// <para>
/// The classifier decodes versioned occurrence projections for inspection,
/// but a Store transition may echo caller-authored revision bytes. A projection
/// alone is never treated as owner-issued normalization evidence.
/// </para>
/// </remarks>
public static class UserAutomationOutcomeClassifier
{
    private const int MaxTypedEnvelopeChars = OperatorProtocol.MaxLineChars;
    private const int MaxIdentityChars = 256;
    // The Kernel's bounded idempotency key is prefixed in operation_id.
    private const int MaxOperationIdChars = 320;
    // The owner-minted members the Operator reads for shape only. A typed
    // refusal projects the route's correlation handle; a transition carries the
    // Store's canonical request hash.
    private const string RequestIdMember = "request_id";
    private const string CanonicalRequestHashMember = "canonical_request_hash";
    // The one optional member of the closed transition value.
    private const string OptionalOrchestrationMember = "orchestration";
    private const int MaxRefusalFieldChars = 256;
    private const int MaxRecoveryReasonChars = 1_024;
    // Bound summary text; the retained response remains available separately.
    private const int MaxDescribedOccurrences = 8;
    /// <summary>Decodes one owner answer for one typed operation identity.</summary>
    public static UserAutomationOutcome Read(
        string action,
        JsonElement answer,
        UserAutomationResultValidationContext context)
    {
        ArgumentNullException.ThrowIfNull(action);
        ArgumentNullException.ThrowIfNull(context);
        if (!context.IsValid())
        {
            return UnverifiedOwnerAnswer(action, "the submitted result-validation context is unsupported");
        }
        if (answer.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
        {
            return OwnerAbsent(action, "the owner route returned no result payload.");
        }

        if (answer.ValueKind != JsonValueKind.Object)
        {
            return UnverifiedOwnerAnswer(action, "the owner answer is not one JSON object");
        }

        if (!HasCurrentResultEnvelope(answer, context))
        {
            return UnverifiedOwnerAnswer(
                action,
                "the owner answer is missing the supported versioned result envelope or its operation/fence binding");
        }

        if (answer.TryGetProperty("status", out _))
        {
            if (!TryReadBoundedText(answer, "status", 32, out var statusText))
            {
                return UnverifiedOwnerAnswer(action, "the typed owner status is malformed");
            }

            if (string.Equals(statusText, "unknown", StringComparison.Ordinal))
            {
                return ReadUnknownEnvelope(action, answer, context);
            }

            if (string.Equals(statusText, "known", StringComparison.Ordinal))
            {
                // Known owner transitions can carry a full bounded schedule
                // projection. Do not apply the much smaller refusal-envelope
                // size limit to this successful result. The expected identity
                // travels with it: a JSON-RPC-correlated body is transport
                // evidence, not the Store operation identity it must answer
                // (#2972).
                return ReadKnownEnvelope(action, answer, context);
            }

            return UnverifiedOwnerAnswer(
                action,
                $"the owner returned the unsupported or mismatched typed status '{statusText}'");
        }

        // The typed error contract is a top-level envelope. An object carrying
        // its `value` without the required status cannot fall through to the
        // schedule projection scanner.
        if (answer.TryGetProperty("value", out _)
            || answer.TryGetProperty("refusal", out _)
            || answer.TryGetProperty("attempt_state", out _))
        {
            return UnverifiedOwnerAnswer(action, "the typed owner envelope is missing its status");
        }

        var projection = FindScheduleProjection(answer);
        if (projection is not null)
        {
            return new UserAutomationOutcome(
                UserAutomationOutcomeClass.UnverifiedOwnerAnswer,
                $"UserAutomation {action} answered — schedule projection unverified",
                DescribeUnverifiedScheduleProjection(projection),
                RefusalKind: null,
                RefusalText: null,
                ScheduleProjection: null);
        }

        return new UserAutomationOutcome(
            UserAutomationOutcomeClass.UnverifiedOwnerAnswer,
            $"UserAutomation {action} answered — schedule not verified",
            "the owner answered this typed operation but this answer carries no decodable "
            + $"{OperatorScheduleContract.NORMALIZED_OCCURRENCE_ENCODING} occurrence projection, "
            + "so the Operator does not report the schedule as normalized",
            RefusalKind: null,
            RefusalText: null,
            ScheduleProjection: null);
    }

    private static UserAutomationOutcome ReadKnownEnvelope(
        string action,
        JsonElement answer,
        UserAutomationResultValidationContext context)
    {
        if (!TryReadBoundedText(answer, "status", 32, out var status)
            || !string.Equals(status, "known", StringComparison.Ordinal)
            || !TryGetObject(answer, "value", out var value)
            || !answer.TryGetProperty("recovery", out var recovery)
            || recovery.ValueKind is not (JsonValueKind.Null or JsonValueKind.Object))
        {
            return UnverifiedOwnerAnswer(action, "the known owner transition is not a closed, settled typed shape");
        }

        if (HasExactProperties(value, "accepted", "outcome", "reason")
            && value.TryGetProperty("accepted", out var notRetainedAccepted)
            && notRetainedAccepted.ValueKind == JsonValueKind.False
            && TryReadBoundedText(value, "outcome", 64, out var notRetainedOutcome)
            && string.Equals(notRetainedOutcome, "not_retained", StringComparison.Ordinal)
            && TryReadBoundedText(value, "reason", MaxRecoveryReasonChars, out var notRetainedReason)
            && recovery.ValueKind == JsonValueKind.Null)
        {
            return new UserAutomationOutcome(
                UserAutomationOutcomeClass.OwnerReportedNotRetainedFenceUnverified,
                $"UserAutomation {action}: owner reports not retained; current fence unverified",
                $"The owner reports that this operation was not retained: {notRetainedReason}. The Operator has no independent submitted/current State Fence comparand for this result, so this remains an owner-reported value and does not authorize a new submission.",
                RefusalKind: null,
                RefusalText: null,
                ScheduleProjection: null);
        }

        if (HasExactProperties(value, "accepted", "outcome", "reason")
            && value.TryGetProperty("accepted", out var settledAccepted)
            && settledAccepted.ValueKind == JsonValueKind.True
            && TryReadBoundedText(value, "outcome", 64, out var settledOutcome)
            && string.Equals(settledOutcome, "outcome_settled", StringComparison.Ordinal)
            && TryReadBoundedText(value, "reason", MaxRecoveryReasonChars, out var settledReason)
            && HasExactProperties(recovery, "kind", "reason")
            && TryReadBoundedText(recovery, "kind", 64, out var settledRecoveryKind)
            && string.Equals(settledRecoveryKind, "ledger_read_owed", StringComparison.Ordinal)
            && TryReadBoundedText(recovery, "reason", MaxRecoveryReasonChars, out var ledgerReadReason))
        {
            return new UserAutomationOutcome(
                UserAutomationOutcomeClass.OwnerReportedCommitFenceUnverifiedLedgerReadOwed,
                $"UserAutomation {action}: owner reports commit; current fence unverified and ledger read owed",
                $"The owner reports a canonical commit ({settledReason}) and a separate ledger read remains owed ({ledgerReadReason}). The Operator has no independent submitted/current State Fence comparand for this result, so keep it under the same identity and reconcile before another submission.",
                RefusalKind: null,
                RefusalText: null,
                ScheduleProjection: null);
        }

        // A pre-Store runtime-channel rejection uses this separate closed
        // shape. It explains this attempt but cannot settle a retained retry.
        if (HasExactProperties(value, "accepted", "outcome", "reason")
            && value.TryGetProperty("accepted", out var accepted)
            && accepted.ValueKind == JsonValueKind.False
            && TryReadBoundedText(value, "outcome", 64, out var outcome)
            && string.Equals(outcome, "rejected", StringComparison.Ordinal)
            && TryReadBoundedText(value, "reason", MaxRecoveryReasonChars, out var reason)
            && recovery.ValueKind == JsonValueKind.Null)
        {
            return new UserAutomationOutcome(
                UserAutomationOutcomeClass.OwnerRefused,
                $"UserAutomation {action} Host runtime protocol rejected this attempt — reconcile the operation",
                $"The Host runtime protocol rejected this attempt before Store because its open frame or response was malformed: {reason}. "
                + "An earlier attempt under this same identity may still have committed. "
                + "Action: restore valid Host runtime protocol framing or response handling, "
                + "then reconcile this same operation before any new submission.",
                "runtime_owner_rejection",
                reason,
                ScheduleProjection: null);
        }

        if (HasExactProperties(value, "accepted", "outcome")
            && value.TryGetProperty("accepted", out var identityAccepted)
            && identityAccepted.ValueKind == JsonValueKind.False
            && TryReadBoundedText(value, "outcome", 64, out var identityOutcome)
            && string.Equals(identityOutcome, "identity_conflict", StringComparison.Ordinal)
            && recovery.ValueKind == JsonValueKind.Null)
        {
            return new UserAutomationOutcome(
                UserAutomationOutcomeClass.OwnerRefused,
                $"UserAutomation {action} identity conflict on this attempt — reconcile the operation",
                "The owner rejected this attempt before Store because the request identity or State Fence did not match the authenticated owner session. "
                + "An earlier attempt under this same identity may still have committed. Action: establish a fresh authenticated owner session with the matching identity and State Fence, "
                + "then reconcile this same operation before any new submission.",
                "identity_conflict",
                RefusalText: null,
                ScheduleProjection: null);
        }

        // Identity first (#2972). A stale cache, a substituted fixture, a
        // transport-correlation bug or a server defect can present a
        // structurally familiar transition belonging to ANOTHER operation. The
        // exact Store operation identity is therefore compared against the
        // submitted request before any schedule projection is scanned or any
        // answer is described, and a nested projection never compensates for a
        // foreign parent result.
        if (recovery.ValueKind != JsonValueKind.Null
            || !HasExactProperties(value, OperatorScheduleContract.USER_AUTOMATION_TRANSITION_VALUE_MEMBERS)
            || !TryGetObject(value, "transition", out var transition)
            || !HasCurrentTransitionShape(transition)
            || !HasCurrentInspectionProjection(value)
            || !TryGetObject(transition, "identity", out var identity)
            || !MatchesOperationIdentity(
                identity,
                context,
                CanonicalRequestHashMember))
        {
            return UnverifiedOwnerAnswer(
                action,
                "the known owner transition does not carry the exact operation identity of this request");
        }

        // The State Fence context is read through the same closed helper the
        // typed refusal path uses, so both result paths accept one fence shape
        // and neither infers a lineage, generation or revision from names.
        if (!TryGetObject(transition, "state_fence", out var stateFence)
            || !IsClosedStateFence(stateFence)
            || !TryGetObject(answer, "state_fence", out var envelopeFence)
            || !SameSerializedFence(stateFence, envelopeFence))
        {
            return UnverifiedOwnerAnswer(
                action,
                "the known owner transition does not carry a closed State Fence for this request");
        }

        var projection = FindScheduleProjection(answer);
        if (projection is not null)
        {
            return new UserAutomationOutcome(
                UserAutomationOutcomeClass.OwnerBoundTransitionScheduleUnverified,
                $"UserAutomation {action} answered — schedule normalization unverified",
                "The owner reports a known transition under its reported State Fence. "
                + "The Operator has no independent submitted/current-fence comparand. "
                + DescribeUnverifiedScheduleProjection(projection),
                RefusalKind: null,
                RefusalText: null,
                ScheduleProjection: null);
        }

        return new UserAutomationOutcome(
            UserAutomationOutcomeClass.OwnerBoundTransitionScheduleUnverified,
            $"UserAutomation {action} answered — schedule not verified",
            "The owner reports a known transition under its reported State Fence, but the Operator has no independent submitted/current-fence comparand. "
            + "This answer carries no decodable "
            + $"{OperatorScheduleContract.NORMALIZED_OCCURRENCE_ENCODING} occurrence projection, "
            + "so the Operator does not report the schedule as normalized",
            RefusalKind: null,
            RefusalText: null,
            ScheduleProjection: null);
    }

    private static UserAutomationOutcome ReadUnknownEnvelope(
        string action,
        JsonElement answer,
        UserAutomationResultValidationContext context)
    {
        if (!TryReadBoundedText(answer, "status", 32, out var status)
            || !string.Equals(status, "unknown", StringComparison.Ordinal)
            || !TryGetObject(answer, "value", out var value)
            || !TryGetObject(answer, "recovery", out var recovery))
        {
            return UnverifiedOwnerAnswer(action, "the unknown-outcome envelope is not a closed typed shape");
        }

        if (TryReadBoundedText(value, "kind", 64, out var kind)
            && string.Equals(kind, "user_automation_refusal", StringComparison.Ordinal))
        {
            if (answer.GetRawText().Length > MaxTypedEnvelopeChars)
            {
                return UnverifiedOwnerAnswer(action, "the typed refusal envelope exceeds its size bound");
            }
            return ReadAttemptRefusal(action, value, recovery, context, answer);
        }

        if (HasExactProperties(value, "outcome")
            && TryReadBoundedText(value, "outcome", 64, out var outcome)
            && string.Equals(outcome, "unavailable", StringComparison.Ordinal)
            && HasExactProperties(recovery, "kind", "reason")
            && TryReadBoundedText(recovery, "kind", 64, out var recoveryKind)
            && string.Equals(recoveryKind, "unavailable", StringComparison.Ordinal)
            && TryReadBoundedText(recovery, "reason", MaxRecoveryReasonChars, out var reason))
        {
            return new UserAutomationOutcome(
                UserAutomationOutcomeClass.OwnerUnavailable,
                $"UserAutomation {action} owner unavailable — outcome remains unknown",
                $"The UserAutomation owner is unavailable: {reason}. The operation outcome remains unknown. "
                + "Action: restore owner availability, then reconcile this same operation before any new submission.",
                RefusalKind: null,
                RefusalText: null,
                ScheduleProjection: null);
        }

        if (HasExactProperties(value, "outcome")
            && TryReadBoundedText(value, "outcome", 64, out var unknownOutcome)
            && string.Equals(unknownOutcome, "unknown_outcome", StringComparison.Ordinal)
            && HasExactProperties(recovery, "kind", "reason")
            && TryReadBoundedText(recovery, "kind", 64, out var unknownRecoveryKind)
            && string.Equals(unknownRecoveryKind, "unknown_outcome", StringComparison.Ordinal)
            && TryReadBoundedText(recovery, "reason", MaxRecoveryReasonChars, out var unknownReason))
        {
            return new UserAutomationOutcome(
                UserAutomationOutcomeClass.UnverifiedOwnerAnswer,
                $"UserAutomation {action} outcome unknown — reconcile the operation",
                $"The owner reports an unknown outcome: {unknownReason}. Action: reconcile this same operation identity before any new submission. "
                + "The Operator does not claim commit or noncommit.",
                RefusalKind: null,
                RefusalText: null,
                ScheduleProjection: null);
        }

        if (HasUserAutomationTransitionProperties(value, context, answer)
            && HasExactProperties(recovery, "kind", "reason")
            && TryReadBoundedText(recovery, "kind", 64, out var transitionRecoveryKind)
            && (string.Equals(transitionRecoveryKind, "unknown_outcome", StringComparison.Ordinal)
                || string.Equals(transitionRecoveryKind, "unavailable", StringComparison.Ordinal))
            && TryReadBoundedText(recovery, "reason", MaxRecoveryReasonChars, out var transitionRecoveryReason))
        {
            var projection = FindScheduleProjection(answer);
            if (projection is not null)
            {
                return new UserAutomationOutcome(
                    UserAutomationOutcomeClass.OwnerScheduleOutcomeUnknown,
                    $"UserAutomation {action} outcome unknown — schedule projection unverified",
                    $"The owner returned a decodable occurrence projection, but it carries no owner-issued normalization receipt or provenance. "
                    + $"Its {transitionRecoveryKind} handoff leaves the operation unresolved. "
                    + $"Reason: {transitionRecoveryReason}. Action: follow the recovery reason and reconcile this same operation identity before any new submission.\n"
                    + DescribeScheduleProjection(projection),
                    RefusalKind: null,
                    RefusalText: null,
                    ScheduleProjection: null);
            }

            return UnverifiedOwnerAnswer(
                action,
                $"the owner transition remains unknown ({transitionRecoveryKind}): {transitionRecoveryReason}");
        }

        return UnverifiedOwnerAnswer(action, "the unknown-outcome envelope has an unsupported value or recovery shape");
    }

    /// <summary>
    /// Admits only the current transition nested in the versioned result
    /// wrapper. No wire version is inferred from a familiar member census.
    /// </summary>
    private static bool HasUserAutomationTransitionProperties(
        JsonElement value,
        UserAutomationResultValidationContext context,
        JsonElement answer) =>
        HasExactProperties(value, OperatorScheduleContract.USER_AUTOMATION_TRANSITION_VALUE_MEMBERS)
        && TryGetObject(value, "transition", out var transition)
        && HasCurrentTransitionShape(transition)
        && HasCurrentInspectionProjection(value)
        && TryGetObject(transition, "identity", out var identity)
        && MatchesOperationIdentity(identity, context, CanonicalRequestHashMember)
        && TryGetObject(transition, "state_fence", out var stateFence)
        && IsClosedStateFence(stateFence)
        && TryGetObject(answer, "state_fence", out var envelopeFence)
        && SameSerializedFence(stateFence, envelopeFence);

    private static bool HasCurrentResultEnvelope(
        JsonElement answer,
        UserAutomationResultValidationContext context)
    {
        if (!HasExactProperties(answer, OperatorScheduleContract.USER_AUTOMATION_RESULT_ENVELOPE_MEMBERS)
            || !TryReadBoundedText(answer, "wire_id", 128, out var wireId)
            || !string.Equals(wireId, context.ExpectedResultWireId, StringComparison.Ordinal)
            || !answer.TryGetProperty("wire_version", out var wireVersion)
            || wireVersion.ValueKind != JsonValueKind.Number
            || !wireVersion.TryGetInt32(out var version)
            || version != context.SupportedResultWireVersion
            || !TryGetObject(answer, "correlation", out var correlation)
            || !HasExactProperties(correlation, OperatorScheduleContract.USER_AUTOMATION_RESULT_CORRELATION_MEMBERS)
            || !MatchesResultCorrelation(correlation, context)
            || !TryGetObject(answer, "state_fence", out var stateFence)
            || !IsClosedStateFence(stateFence))
        {
            return false;
        }

        return true;
    }

    private static bool MatchesResultCorrelation(
        JsonElement correlation,
        UserAutomationResultValidationContext context) =>
        TryReadBoundedText(correlation, "operation_id", MaxOperationIdChars, out var operationId)
        && string.Equals(operationId, context.ExpectedOperationId, StringComparison.Ordinal)
        && TryReadBoundedText(correlation, "idempotency_key", MaxIdentityChars, out var idempotencyKey)
        && string.Equals(idempotencyKey, context.ExpectedIdempotencyKey, StringComparison.Ordinal);

    private static bool HasCurrentTransitionShape(JsonElement transition) =>
        HasAllowedAndRequiredProperties(
            transition,
            OperatorScheduleContract.USER_AUTOMATION_TRANSITION_MEMBERS,
            OperatorScheduleContract.USER_AUTOMATION_TRANSITION_REQUIRED_MEMBERS)
        && TryReadBoundedText(transition, "wire_id", 128, out var wireId)
        && string.Equals(wireId, OperatorScheduleContract.USER_AUTOMATION_TRANSITION_WIRE_ID, StringComparison.Ordinal)
        && transition.TryGetProperty("wire_version", out var versionValue)
        && versionValue.ValueKind == JsonValueKind.Number
        && versionValue.TryGetInt32(out var version)
        && version == OperatorScheduleContract.USER_AUTOMATION_TRANSITION_WIRE_VERSION
        && TryGetObject(transition, "identity", out var identity)
        && HasExactProperties(identity, "operation_id", "canonical_request_hash", "idempotency_key")
        && TryReadBoundedText(identity, "operation_id", MaxOperationIdChars, out _)
        && TryReadBoundedText(identity, "canonical_request_hash", 64, out var canonicalHash)
        && IsLowerHexSha256(canonicalHash)
        && TryReadBoundedText(identity, "idempotency_key", MaxIdentityChars, out _)
        && TryGetObject(transition, "state_fence", out var stateFence)
        && IsClosedStateFence(stateFence)
        && TryGetObject(transition, "configuration", out var configuration)
        && HasCurrentConfigurationPhase(configuration)
        && TryGetObject(transition, "wake", out var wake)
        && HasCurrentWakePhase(wake)
        && TryGetObject(transition, "execution", out var execution)
        && HasCurrentExecutionPhase(execution)
        && OptionalRecordIsAbsentOrObject(transition, "horizon")
        && (!transition.TryGetProperty("horizon", out var horizon) || HasCurrentHorizonPhase(horizon))
        && OptionalRecordIsAbsentOrObject(transition, OptionalOrchestrationMember)
        && (!transition.TryGetProperty(OptionalOrchestrationMember, out var orchestration)
            || HasCurrentOrchestrationRecord(orchestration));

    // Rust serializes both Option records with skip_serializing_if=None. An
    // absent member means None; explicit null is outside the current wire.
    private static bool OptionalRecordIsAbsentOrObject(JsonElement value, string propertyName) =>
        !value.TryGetProperty(propertyName, out var optional)
        || optional.ValueKind == JsonValueKind.Object;

    private static bool HasCurrentConfigurationPhase(JsonElement phase)
    {
        if (!TryReadClosedValue(
                phase,
                "kind",
                OperatorScheduleContract.USER_AUTOMATION_CONFIGURATION_PHASE_KINDS,
                out var kind))
        {
            return false;
        }

        return kind switch
        {
            "read" => HasExactProperties(phase, "kind", "result")
                && TryGetObject(phase, "result", out var readResult)
                && HasCurrentReadResult(readResult),
            "committed" or "replayed" => HasExactProperties(phase, "kind", "receipt", "result")
                && TryGetObject(phase, "receipt", out var receipt)
                && HasCurrentWriteReceipt(receipt)
                && TryGetObject(phase, "result", out var mutationResult)
                && HasCurrentMutationResult(mutationResult),
            _ => false
        };
    }

    private static bool HasCurrentReadResult(JsonElement result)
    {
        if (!TryReadClosedValue(
                result,
                "kind",
                OperatorScheduleContract.USER_AUTOMATION_READ_RESULT_KINDS,
                out var kind))
        {
            return false;
        }

        return kind switch
        {
            "list" => HasExactProperties(result, "kind", "revisions")
                && HasObjectArray(result, "revisions")
                && HasCurrentRevisionArray(result.GetProperty("revisions")),
            "status" => HasExactProperties(result, "kind", "revision", "execution")
                && TryGetObject(result, "revision", out var statusRevision)
                && HasCurrentRevision(statusRevision)
                && TryGetObject(result, "execution", out var statusExecution)
                && HasCurrentExecutionProjection(statusExecution),
            "history" => HasExactProperties(result, "kind", "automation_id", "execution")
                && TryReadBoundedText(result, "automation_id", MaxIdentityChars, out _)
                && TryGetObject(result, "execution", out var historyExecution)
                && HasCurrentExecutionProjection(historyExecution),
            "inspect_last_failure" => HasExactProperties(result, "kind", "automation_id", "revision", "failure")
                && TryReadBoundedText(result, "automation_id", MaxIdentityChars, out _)
                && TryGetObject(result, "revision", out var failureRevision)
                && HasCurrentRevision(failureRevision)
                && result.TryGetProperty("failure", out var failure)
                && (failure.ValueKind == JsonValueKind.Null || HasCurrentFailureProjection(failure)),
            _ => false
        };
    }

    private static bool HasCurrentRevisionArray(JsonElement revisions)
    {
        foreach (var revision in revisions.EnumerateArray())
        {
            if (!HasCurrentRevision(revision)) return false;
        }
        return true;
    }

    private static bool HasCurrentRevision(JsonElement revision) =>
        HasExactProperties(revision, OperatorScheduleContract.USER_AUTOMATION_REVISION_MEMBERS)
        && TryReadBoundedText(revision, "automation_id", MaxIdentityChars, out _)
        && TryReadBoundedText(revision, "revision", MaxIdentityChars, out _)
        && HasOptionalBoundedText(revision, "supersedes", MaxIdentityChars)
        && TryReadBoundedText(revision, "owner_principal", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && TryGetObject(revision, "work_scope", out var workScope)
        && HasExactProperties(workScope, OperatorScheduleContract.USER_AUTOMATION_WORK_SCOPE_MEMBERS)
        && TryReadBoundedText(workScope, "scope_id", MaxIdentityChars, out _)
        && TryReadBoundedText(workScope, "product_id", MaxIdentityChars, out _)
        && TryReadBoundedText(workScope, "workdir_ref", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && TryReadBoundedText(revision, "natural_language_intent", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && TryGetObject(revision, "schedule", out var schedule)
        && HasCurrentNormalizedSchedule(schedule)
        && TryReadClosedValue(revision, "mode", OperatorScheduleContract.USER_AUTOMATION_EXECUTION_MODES, out _)
        && TryGetObject(revision, "task", out var task)
        && HasExactProperties(task, OperatorScheduleContract.USER_AUTOMATION_TASK_BINDING_MEMBERS)
        && TryReadBoundedText(task, "qualified_ref", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && TryReadClosedValue(task, "kind", OperatorScheduleContract.USER_AUTOMATION_TASK_KINDS, out _)
        && TryGetObject(task, "capability_profile", out var capabilityProfile)
        && HasExactProperties(capabilityProfile, OperatorScheduleContract.USER_AUTOMATION_CAPABILITY_PROFILE_MEMBERS)
        && IsBooleanProperty(capabilityProfile, "model_access")
        && IsBooleanProperty(capabilityProfile, "provider_access")
        && IsBooleanProperty(capabilityProfile, "automation_scheduling")
        && HasBoundedStringArray(revision, "portable_skill_package_revision_refs", OperatorScheduleContract.MAX_TEXT_BYTES)
        && HasBoundedArrayLength(revision, "portable_skill_package_revision_refs", OperatorScheduleContract.MAX_REFERENCES)
        && TryReadBoundedText(revision, "workdir_ref", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && TryGetObject(revision, "route_cost_policy", out var routeCost)
        && HasExactProperties(routeCost, OperatorScheduleContract.USER_AUTOMATION_ROUTE_COST_POLICY_MEMBERS)
        && TryReadBoundedText(routeCost, "route_ref", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && IsPositiveUInt64Property(routeCost, "max_cost_units")
        && IsPositiveUInt64Property(routeCost, "max_duration_ms")
        && IsNullOrPositiveUInt64Property(routeCost, "policy_revision")
        && TryGetObject(revision, "provider_policy", out var providerPolicy)
        && HasCurrentProviderPolicy(providerPolicy)
        && TryGetObject(revision, "delivery_target", out var deliveryTarget)
        && HasExactProperties(deliveryTarget, OperatorScheduleContract.USER_AUTOMATION_DELIVERY_TARGET_MEMBERS)
        && TryReadBoundedText(deliveryTarget, "target_ref", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && HasClosedStringArray(deliveryTarget, "channels", OperatorScheduleContract.USER_AUTOMATION_DELIVERY_CHANNELS)
        && HasBoundedStringArray(deliveryTarget, "recipient_refs", OperatorScheduleContract.MAX_TEXT_BYTES)
        && TryReadBoundedText(revision, "preflight_contract_revision", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && TryGetObject(revision, "resource_ceiling", out var resourceCeiling)
        && HasExactProperties(resourceCeiling, OperatorScheduleContract.USER_AUTOMATION_RESOURCE_CEILING_MEMBERS)
        && IsPositiveUInt64Property(resourceCeiling, "max_runtime_ms")
        && IsPositiveUInt64Property(resourceCeiling, "max_output_bytes")
        && IsUnsignedIntegerProperty(resourceCeiling, "max_child_count")
        && TryReadClosedValue(revision, "overlap_policy", OperatorScheduleContract.USER_AUTOMATION_OVERLAP_POLICIES, out _)
        && TryGetObject(revision, "recursion_policy", out var recursionPolicy)
        && HasExactProperties(recursionPolicy, OperatorScheduleContract.USER_AUTOMATION_RECURSION_POLICY_MEMBERS)
        && IsBooleanProperty(recursionPolicy, "allow_child_automation")
        && IsUnsignedIntegerProperty(recursionPolicy, "max_child_depth")
        && TryReadClosedValue(revision, "configuration_state", OperatorScheduleContract.USER_AUTOMATION_CONFIGURATION_STATES, out _)
        && TryReadClosedValue(revision, "work_class", OperatorScheduleContract.USER_AUTOMATION_WORK_CLASSES, out _)
        && HasBoundedStringArray(revision, "current_execution_refs", OperatorScheduleContract.MAX_TEXT_BYTES)
        && HasBoundedArrayLength(revision, "current_execution_refs", OperatorScheduleContract.MAX_REFERENCES)
        && TryReadBoundedText(revision, "execution_history_query_ref", OperatorScheduleContract.MAX_TEXT_BYTES, out _);

    private static bool HasCurrentNormalizedSchedule(JsonElement schedule) =>
        HasExactProperties(schedule, OperatorScheduleContract.USER_AUTOMATION_NORMALIZED_SCHEDULE_MEMBERS)
        && TryReadClosedValue(schedule, "kind", OperatorScheduleContract.USER_AUTOMATION_SCHEDULE_KINDS, out _)
        && TryReadBoundedText(schedule, "expression", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && TryReadBoundedText(schedule, "calendar", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && TryReadBoundedText(schedule, "timezone", OperatorScheduleContract.MAX_ZONE_IDENTITY_BYTES, out _)
        && TryReadClosedValue(schedule, "dst_fold", OperatorScheduleContract.USER_AUTOMATION_DST_FOLD_POLICIES, out _)
        && TryReadClosedValue(schedule, "dst_gap", OperatorScheduleContract.USER_AUTOMATION_DST_GAP_POLICIES, out _)
        && TryReadBoundedText(schedule, "start_at", OperatorScheduleContract.UTC_INSTANT_BYTES, out _)
        && HasOptionalBoundedText(schedule, "end_at", OperatorScheduleContract.UTC_INSTANT_BYTES)
        && HasBoundedStringArray(schedule, "next_occurrences", OperatorScheduleContract.MAX_OCCURRENCE_KEY_BYTES)
        && HasBoundedArrayLength(schedule, "next_occurrences", OperatorScheduleContract.MAX_REFERENCES, requireNonEmpty: true);

    private static bool HasCurrentProviderPolicy(JsonElement policy)
    {
        if (!TryReadClosedValue(policy, "kind", OperatorScheduleContract.USER_AUTOMATION_PROVIDER_POLICY_KINDS, out var kind))
        {
            return false;
        }
        return kind switch
        {
            "deterministic_only" => HasExactProperties(policy, "kind"),
            "allowed" => HasExactProperties(policy, "kind", "fingerprints")
                && HasObjectArray(policy, "fingerprints")
                && HasCurrentProviderFingerprints(policy.GetProperty("fingerprints")),
            _ => false
        };
    }

    private static bool HasCurrentProviderFingerprints(JsonElement fingerprints)
    {
        foreach (var fingerprint in fingerprints.EnumerateArray())
        {
            if (!HasExactProperties(fingerprint, OperatorScheduleContract.USER_AUTOMATION_PROVIDER_FINGERPRINT_MEMBERS)
                || !TryReadBoundedText(fingerprint, "provider", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
                || !TryReadBoundedText(fingerprint, "model", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
                || !TryReadBoundedText(fingerprint, "adapter", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
                || !TryReadBoundedText(fingerprint, "fingerprint", OperatorScheduleContract.MAX_TEXT_BYTES, out _))
            {
                return false;
            }
        }
        return true;
    }

    private static bool HasCurrentWriteReceipt(JsonElement receipt) =>
        HasExactProperties(receipt, OperatorScheduleContract.USER_AUTOMATION_WRITE_RECEIPT_MEMBERS)
        && TryReadBoundedText(receipt, "operation_id", MaxOperationIdChars, out _)
        && TryReadBoundedText(receipt, "idempotency_key", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && TryReadBoundedText(receipt, "canonical_request_hash", 64, out var requestHash)
        && IsLowerHexSha256(requestHash)
        && TryReadClosedValue(receipt, "transition_class", OperatorScheduleContract.USER_AUTOMATION_TRANSITION_CLASSES, out _)
        && TryReadClosedValue(receipt, "status", OperatorScheduleContract.USER_AUTOMATION_WRITE_RECEIPT_STATUS_VALUES, out _)
        && HasOptionalBoundedText(receipt, "commit_id", OperatorScheduleContract.MAX_TEXT_BYTES)
        && TryGetObject(receipt, "state_fence", out var receiptFence)
        && IsClosedStateFence(receiptFence)
        && HasObjectArray(receipt, "ordering_sequences")
        && HasObjectArray(receipt, "revision_before_after")
        && HasBoundedStringArray(receipt, "applied_command_ids", OperatorScheduleContract.MAX_TEXT_BYTES)
        && HasBoundedStringArray(receipt, "emitted_event_ids", OperatorScheduleContract.MAX_TEXT_BYTES)
        && HasBoundedStringArray(receipt, "projection_refs", OperatorScheduleContract.MAX_TEXT_BYTES)
        && HasBoundedStringArray(receipt, "outbox_refs", OperatorScheduleContract.MAX_TEXT_BYTES)
        && TryReadBoundedText(receipt, "operation_manifest_digest", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && TryReadBoundedText(receipt, "admission_digest", 64, out var admissionDigest)
        && IsLowerHexSha256(admissionDigest)
        && TryReadBoundedText(receipt, "mutation_plan_digest", 64, out var mutationDigest)
        && IsLowerHexSha256(mutationDigest)
        && HasBoundedStringArray(receipt, "semantic_source_revisions", OperatorScheduleContract.MAX_TEXT_BYTES)
        && TryGetObject(receipt, "policy_config_schema_versions", out var policySchema)
        && HasExactProperties(policySchema, OperatorScheduleContract.USER_AUTOMATION_POLICY_SCHEMA_MEMBERS)
        && HasOptionalClosedValue(receipt, "error_code", OperatorScheduleContract.USER_AUTOMATION_ERROR_CODE_VALUES)
        && TryReadClosedValue(receipt, "resubmission", OperatorScheduleContract.USER_AUTOMATION_RESUBMISSION_VALUES, out _)
        && HasOptionalBoundedText(receipt, "committed_at", OperatorScheduleContract.MAX_TEXT_BYTES)
        && OptionalRecordIsAbsentOrObject(receipt, "envelope");

    private static bool HasCurrentWakeIntent(JsonElement intent) =>
        HasExactProperties(intent, OperatorScheduleContract.USER_AUTOMATION_WAKE_INTENT_MEMBERS)
        && TryReadBoundedText(intent, "wake_id", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && TryReadBoundedText(intent, "reason", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && TryGetObject(intent, "state_fence", out var fence)
        && IsClosedStateFence(fence)
        && TryReadClosedValue(intent, "state", OperatorScheduleContract.USER_AUTOMATION_WAKE_INTENT_STATE_VALUES, out _);

    private static bool HasCurrentWakeReadback(JsonElement readback) =>
        HasExactProperties(readback, OperatorScheduleContract.USER_AUTOMATION_WAKE_READBACK_MEMBERS)
        && TryGetObject(readback, "intent", out var intent)
        && HasCurrentWakeIntent(intent)
        && TryReadBoundedText(readback, "operation_id", MaxOperationIdChars, out _)
        && TryReadBoundedText(readback, "idempotency_key", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && TryReadBoundedText(readback, "record_checksum", 64, out var checksum)
        && IsLowerHexSha256(checksum);

    private static bool HasCurrentInvocation(JsonElement invocation) =>
        HasAllowedAndRequiredProperties(
            invocation,
            OperatorScheduleContract.USER_AUTOMATION_INVOCATION_MEMBERS,
            OperatorScheduleContract.USER_AUTOMATION_INVOCATION_REQUIRED_MEMBERS)
        && TryReadBoundedText(invocation, "automation_id", MaxIdentityChars, out _)
        && TryReadBoundedText(invocation, "automation_revision", MaxIdentityChars, out _)
        && TryGetObject(invocation, "trigger", out var trigger)
        && HasCurrentTrigger(trigger)
        && TryReadClosedValue(invocation, "mode", OperatorScheduleContract.USER_AUTOMATION_EXECUTION_MODES, out _)
        && TryReadBoundedText(invocation, "principal_ref", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && TryReadBoundedText(invocation, "work_scope_ref", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && TryReadBoundedText(invocation, "workdir_ref", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && TryReadClosedValue(invocation, "trigger_origin", OperatorScheduleContract.USER_AUTOMATION_TRIGGER_ORIGINS, out _)
        && IsUnsignedIntegerProperty(invocation, "child_depth")
        && OptionalRecordIsAbsentOrObject(invocation, "provenance");

    private static bool HasCurrentTrigger(JsonElement trigger)
    {
        if (!TryReadClosedValue(trigger, "kind", OperatorScheduleContract.USER_AUTOMATION_TRIGGER_KINDS, out var kind))
        {
            return false;
        }
        return kind switch
        {
            "scheduled" => HasExactProperties(trigger, "kind", "occurrence_key")
                && TryReadBoundedText(trigger, "occurrence_key", OperatorScheduleContract.MAX_OCCURRENCE_KEY_BYTES, out _),
            "manual" => HasExactProperties(trigger, "kind", "nonce")
                && TryReadBoundedText(trigger, "nonce", OperatorScheduleContract.MAX_TEXT_BYTES, out _),
            _ => false
        };
    }

    private static bool HasCurrentExecutionReference(JsonElement execution) =>
        HasExactProperties(execution, OperatorScheduleContract.USER_AUTOMATION_EXECUTION_REFERENCE_MEMBERS)
        && TryReadBoundedText(execution, "occurrence_id", MaxIdentityChars, out _)
        && TryReadBoundedText(execution, "durable_job_ref", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
        && TryReadClosedValue(execution, "state", OperatorScheduleContract.USER_AUTOMATION_EXECUTION_STATE_VALUES, out _);

    private static bool HasCurrentExecutionProjection(JsonElement projection) =>
        HasExactProperties(projection, OperatorScheduleContract.USER_AUTOMATION_EXECUTION_PROJECTION_MEMBERS)
        && HasObjectArray(projection, "current_execution_refs")
        && HasCurrentExecutionReferences(projection.GetProperty("current_execution_refs"))
        && HasObjectArray(projection, "unresolved_reconciliation_refs")
        && HasCurrentReconciliationReferences(projection.GetProperty("unresolved_reconciliation_refs"))
        && TryReadBoundedText(projection, "history_query_ref", OperatorScheduleContract.MAX_TEXT_BYTES, out _);

    private static bool HasCurrentExecutionReferences(JsonElement references)
    {
        foreach (var reference in references.EnumerateArray())
        {
            if (!HasCurrentExecutionReference(reference)) return false;
        }
        return true;
    }

    private static bool HasCurrentReconciliationReferences(JsonElement references)
    {
        foreach (var reference in references.EnumerateArray())
        {
            if (!HasExactProperties(reference, OperatorScheduleContract.USER_AUTOMATION_RECONCILIATION_REFERENCE_MEMBERS)
                || !TryReadBoundedText(reference, "occurrence_id", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
                || !TryReadBoundedText(reference, "operation_ref", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
                || !TryReadClosedValue(reference, "cause", OperatorScheduleContract.USER_AUTOMATION_RECONCILIATION_CAUSES, out _)
                || !TryReadBoundedText(reference, "read_revision", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
                || !HasOptionalBoundedText(reference, "denominator_query_ref", OperatorScheduleContract.MAX_TEXT_BYTES))
            {
                return false;
            }
        }
        return true;
    }

    private static bool HasCurrentFailureProjection(JsonElement failure) =>
        HasExactProperties(failure, OperatorScheduleContract.USER_AUTOMATION_FAILURE_PROJECTION_MEMBERS)
        && TryReadBoundedText(failure, "failure_fingerprint", 64, out var fingerprint)
        && IsLowerHexSha256(fingerprint)
        && TryGetObject(failure, "reason", out var reason)
        && HasCurrentFailureReason(reason)
        && TryGetObject(failure, "notification", out _);

    private static bool HasCurrentFailureReason(JsonElement reason)
    {
        if (!TryReadClosedValue(reason, "kind", OperatorScheduleContract.USER_AUTOMATION_FAILURE_REASON_KINDS, out var kind))
        {
            return false;
        }
        return kind == "canonical_blocked_config"
            ? HasExactProperties(reason, "kind", "class")
                && TryReadBoundedText(reason, "class", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
            : HasExactProperties(reason, "kind");
    }

    private static bool HasCurrentMutationResult(JsonElement result)
    {
        if (!TryReadClosedValue(
                result,
                "kind",
                OperatorScheduleContract.USER_AUTOMATION_MUTATION_RESULT_KINDS,
                out var kind))
        {
            return false;
        }

        return kind switch
        {
            "revision" => HasExactProperties(result, "kind", "revision", "cancelled_wake_ids")
                && TryGetObject(result, "revision", out var changedRevision)
                && HasCurrentRevision(changedRevision)
                && HasBoundedStringArray(result, "cancelled_wake_ids", OperatorScheduleContract.MAX_TEXT_BYTES),
            "run_now" => HasExactProperties(result, "kind", "invocation", "wake_intent")
                && TryGetObject(result, "invocation", out var invocation)
                && HasCurrentInvocation(invocation)
                && TryGetObject(result, "wake_intent", out var wakeIntent)
                && HasCurrentWakeIntent(wakeIntent),
            _ => false
        };
    }

    private static bool HasCurrentWakePhase(JsonElement phase)
    {
        if (!TryReadClosedValue(phase, "kind", OperatorScheduleContract.USER_AUTOMATION_WAKE_PHASE_KINDS, out var kind))
        {
            return false;
        }

        return kind switch
        {
            "not_applicable" => HasExactProperties(phase, "kind", "reason")
                && TryReadBoundedText(phase, "reason", MaxRecoveryReasonChars, out _),
            "published" => HasExactProperties(phase, "kind", "readback")
                && TryGetObject(phase, "readback", out var readback)
                && HasCurrentWakeReadback(readback),
            "cancelled" => HasExactProperties(phase, "kind", "cancelled_wake_ids")
                && HasBoundedStringArray(phase, "cancelled_wake_ids", OperatorScheduleContract.MAX_TEXT_BYTES),
            "unknown_outcome" or "unavailable" => HasExactProperties(phase, "kind", "reason")
                && TryReadBoundedText(phase, "reason", MaxRecoveryReasonChars, out _),
            _ => false
        };
    }

    private static bool HasCurrentExecutionPhase(JsonElement phase)
    {
        if (!TryReadClosedValue(
                phase,
                "kind",
                OperatorScheduleContract.USER_AUTOMATION_EXECUTION_PHASE_KINDS,
                out var kind))
        {
            return false;
        }

        return kind switch
        {
            "not_applicable" => HasExactProperties(phase, "kind", "reason")
                && TryReadBoundedText(phase, "reason", MaxRecoveryReasonChars, out _),
            "admitted" => HasExactProperties(phase, "kind", "execution")
                && TryGetObject(phase, "execution", out var execution)
                && HasCurrentExecutionReference(execution),
            "deferred" => HasExactProperties(phase, "kind", "reason")
                && TryReadClosedValue(phase, "reason", OperatorScheduleContract.USER_AUTOMATION_DEFER_REASONS, out _),
            "blocked_config" => HasExactProperties(phase, "kind", "failure_fingerprint")
                && TryReadBoundedText(phase, "failure_fingerprint", 64, out _),
            "unknown_outcome" or "unavailable" => HasExactProperties(phase, "kind", "reason")
                && TryReadBoundedText(phase, "reason", MaxRecoveryReasonChars, out _),
            _ => false
        };
    }

    private static bool HasCurrentHorizonPhase(JsonElement phase)
    {
        if (!HasAllowedAndRequiredProperties(
                phase,
                OperatorScheduleContract.USER_AUTOMATION_HORIZON_PHASE_MEMBERS,
                OperatorScheduleContract.USER_AUTOMATION_HORIZON_PHASE_MEMBERS)
            || !TryReadClosedValue(phase, "trigger", OperatorScheduleContract.USER_AUTOMATION_HORIZON_TRIGGER_VALUES, out _)
            || !TryReadBoundedText(phase, "automation_id", MaxIdentityChars, out _)
            || !TryReadBoundedText(phase, "automation_revision", MaxIdentityChars, out _)
            || !TryReadBoundedText(phase, "revision_digest", 64, out var revisionDigest)
            || !IsLowerHexSha256(revisionDigest)
            || !HasBoundedStringArray(phase, "requested_occurrence_ids", OperatorScheduleContract.MAX_TEXT_BYTES)
            || !HasBoundedStringArray(phase, "remaining_occurrence_ids", OperatorScheduleContract.MAX_TEXT_BYTES)
            || !TryReadBoundedText(phase, "retry_handle", MaxIdentityChars, out _)
            || !TryGetObject(phase, "outcome", out var outcome)
            || !TryReadClosedValue(outcome, "kind", OperatorScheduleContract.USER_AUTOMATION_HORIZON_OUTCOME_KINDS, out var kind))
        {
            return false;
        }

        return kind switch
        {
            "published" => HasExactProperties(outcome, "kind", "publication_operation_id")
                && TryReadBoundedText(outcome, "publication_operation_id", MaxOperationIdChars, out _),
            "partial" => HasExactProperties(outcome, "kind", "publication_operation_id", "reason")
                && TryReadBoundedText(outcome, "publication_operation_id", MaxOperationIdChars, out _)
                && TryReadBoundedText(outcome, "reason", MaxRecoveryReasonChars, out _),
            "unavailable" or "unknown_outcome" => HasExactProperties(outcome, "kind", "reason")
                && TryReadBoundedText(outcome, "reason", MaxRecoveryReasonChars, out _),
            _ => false
        };
    }

    private static bool HasCurrentOrchestrationRecord(JsonElement record)
    {
        if (!HasAllowedAndRequiredProperties(
                record,
                OperatorScheduleContract.USER_AUTOMATION_ORCHESTRATION_RECORD_MEMBERS,
                OperatorScheduleContract.USER_AUTOMATION_ORCHESTRATION_RECORD_MEMBERS)
            || !TryGetObject(record, "parent", out var parent)
            || !HasExactProperties(parent, "operation_id", "canonical_request_hash", "idempotency_key")
            || !TryReadBoundedText(parent, "operation_id", MaxOperationIdChars, out _)
            || !TryReadBoundedText(parent, "canonical_request_hash", 64, out var parentHash)
            || !IsLowerHexSha256(parentHash)
            || !TryReadBoundedText(parent, "idempotency_key", MaxIdentityChars, out _)
            || !TryGetObject(record, "state_fence", out var stateFence)
            || !IsClosedStateFence(stateFence)
            || !TryReadBoundedText(record, "automation_id", MaxIdentityChars, out _)
            || !TryReadBoundedText(record, "automation_revision", MaxIdentityChars, out _)
            || !TryReadBoundedText(record, "revision_digest", 64, out var revisionDigest)
            || !IsLowerHexSha256(revisionDigest)
            || !TryReadBoundedText(record, "committed_receipt_digest", 64, out var receiptDigest)
            || !IsLowerHexSha256(receiptDigest)
            || !HasObjectArray(record, "obligations"))
        {
            return false;
        }

        foreach (var obligation in record.GetProperty("obligations").EnumerateArray())
        {
            if (!HasAllowedAndRequiredProperties(
                    obligation,
                    OperatorScheduleContract.USER_AUTOMATION_RUNTIME_OBLIGATION_MEMBERS,
                    OperatorScheduleContract.USER_AUTOMATION_RUNTIME_OBLIGATION_MEMBERS)
                || !TryReadClosedValue(obligation, "kind", OperatorScheduleContract.USER_AUTOMATION_RUNTIME_OBLIGATION_KINDS, out _)
                || !TryReadBoundedText(obligation, "owner_operation_id", MaxOperationIdChars, out _)
                || !TryReadBoundedText(obligation, "request_digest", 64, out var requestDigest)
                || !IsLowerHexSha256(requestDigest)
                || !HasBoundedStringArray(obligation, "subject_ids", OperatorScheduleContract.MAX_TEXT_BYTES)
                || !obligation.TryGetProperty("wake_enumeration_receipt", out var enumerationReceipt)
                || enumerationReceipt.ValueKind is not (JsonValueKind.Null or JsonValueKind.Object)
                || !TryGetObject(obligation, "disposition", out var disposition)
                || !HasCurrentObligationDisposition(disposition))
            {
                return false;
            }
        }
        return true;
    }

    private static bool HasCurrentObligationDisposition(JsonElement disposition)
    {
        if (!TryReadClosedValue(
                disposition,
                "kind",
                OperatorScheduleContract.USER_AUTOMATION_RUNTIME_OBLIGATION_DISPOSITION_KINDS,
                out var kind))
        {
            return false;
        }

        return kind switch
        {
            "retained" => HasExactProperties(disposition, "kind"),
            "reconciling" or "unavailable" => HasExactProperties(disposition, "kind", "reason")
                && TryReadBoundedText(disposition, "reason", MaxRecoveryReasonChars, out _),
            "answered" => HasExactProperties(disposition, "kind", "answer")
                && TryGetObject(disposition, "answer", out var answer)
                && HasCurrentObligationAnswer(answer),
            _ => false
        };
    }

    private static bool HasCurrentObligationAnswer(JsonElement answer)
    {
        if (!TryReadClosedValue(
                answer,
                "kind",
                OperatorScheduleContract.USER_AUTOMATION_RUNTIME_OBLIGATION_ANSWER_KINDS,
                out var kind))
        {
            return false;
        }

        return kind switch
        {
            "wake_horizon_publication" => HasExactProperties(answer, "kind", "publication_request", "acknowledgement")
                && answer.TryGetProperty("publication_request", out var publicationRequest)
                && (publicationRequest.ValueKind == JsonValueKind.Null || publicationRequest.ValueKind == JsonValueKind.Object)
                && TryGetObject(answer, "acknowledgement", out _),
            "wake_cancellation" => HasExactProperties(answer, "kind", "cancelled_wake_ids", "enumeration_receipt")
                && HasBoundedStringArray(answer, "cancelled_wake_ids", OperatorScheduleContract.MAX_TEXT_BYTES)
                && answer.TryGetProperty("enumeration_receipt", out var enumerationReceipt)
                && (enumerationReceipt.ValueKind == JsonValueKind.Null || enumerationReceipt.ValueKind == JsonValueKind.Object),
            "wake_target_enumeration_receipt" => HasExactProperties(answer, "kind", "receipt")
                && TryGetObject(answer, "receipt", out _),
            _ => false
        };
    }

    private static bool TryReadClosedValue(
        JsonElement parent,
        string memberName,
        string[] allowedValues,
        out string value) =>
        TryReadBoundedText(parent, memberName, 64, out value)
        && Array.IndexOf(allowedValues, value) >= 0;

    private static bool HasObjectArray(JsonElement parent, string memberName)
    {
        if (!parent.TryGetProperty(memberName, out var array) || array.ValueKind != JsonValueKind.Array)
        {
            return false;
        }
        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) return false;
        }
        return true;
    }

    private static bool HasBoundedStringArray(JsonElement parent, string memberName, int maximumLength)
    {
        if (!parent.TryGetProperty(memberName, out var array) || array.ValueKind != JsonValueKind.Array)
        {
            return false;
        }
        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String
                || string.IsNullOrWhiteSpace(item.GetString())
                || item.GetString()!.Length > maximumLength
                || item.GetString()!.Any(char.IsControl))
            {
                return false;
            }
        }
        return true;
    }

    private static bool HasClosedStringArray(JsonElement parent, string memberName, string[] allowedValues)
    {
        if (!parent.TryGetProperty(memberName, out var array) || array.ValueKind != JsonValueKind.Array)
        {
            return false;
        }
        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String
                || string.IsNullOrWhiteSpace(item.GetString())
                || item.GetString()!.Any(char.IsControl)
                || Array.IndexOf(allowedValues, item.GetString()) < 0)
            {
                return false;
            }
        }
        return true;
    }

    private static bool HasBoundedArrayLength(
        JsonElement parent,
        string memberName,
        int maximumLength,
        bool requireNonEmpty = false) =>
        parent.TryGetProperty(memberName, out var array)
        && array.ValueKind == JsonValueKind.Array
        && array.GetArrayLength() <= maximumLength
        && (!requireNonEmpty || array.GetArrayLength() > 0);

    private static bool HasOptionalBoundedText(JsonElement value, string propertyName, int maximumLength) =>
        value.TryGetProperty(propertyName, out var member)
        && (member.ValueKind == JsonValueKind.Null
            || (member.ValueKind == JsonValueKind.String
                && !string.IsNullOrWhiteSpace(member.GetString())
                && member.GetString()!.Length <= maximumLength
                && !member.GetString()!.Any(char.IsControl)));

    private static bool HasOptionalClosedValue(JsonElement value, string propertyName, string[] allowedValues) =>
        value.TryGetProperty(propertyName, out var member)
        && (member.ValueKind == JsonValueKind.Null
            || (member.ValueKind == JsonValueKind.String
                && Array.IndexOf(allowedValues, member.GetString()) >= 0));

    private static bool IsBooleanProperty(JsonElement value, string propertyName) =>
        value.TryGetProperty(propertyName, out var member)
        && member.ValueKind is JsonValueKind.True or JsonValueKind.False;

    private static bool IsUnsignedIntegerProperty(JsonElement value, string propertyName) =>
        value.TryGetProperty(propertyName, out var member)
        && member.ValueKind == JsonValueKind.Number
        && member.TryGetUInt32(out _);

    private static bool IsPositiveUInt64Property(JsonElement value, string propertyName) =>
        value.TryGetProperty(propertyName, out var member)
        && IsPositiveUInt64(member);

    private static bool IsNullOrPositiveUInt64Property(JsonElement value, string propertyName) =>
        value.TryGetProperty(propertyName, out var member)
        && (member.ValueKind == JsonValueKind.Null || IsPositiveUInt64(member));


    private static bool IsLowerHexSha256(string value) =>
        value.Length == 64
        && value.All(character => (character >= '0' && character <= '9')
            || (character >= 'a' && character <= 'f'));

    private static bool HasCurrentInspectionProjection(JsonElement transitionValue)
    {
        if (!transitionValue.TryGetProperty("occurrences", out var projectionArray)
            || projectionArray.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (var projection in projectionArray.EnumerateArray())
        {
            if (!HasAllowedAndRequiredProperties(
                    projection,
                    OperatorScheduleContract.USER_AUTOMATION_SCHEDULE_PROJECTION_MEMBERS,
                    OperatorScheduleContract.USER_AUTOMATION_SCHEDULE_PROJECTION_REQUIRED_MEMBERS)
                || !TryReadBoundedText(projection, "automation_id", MaxIdentityChars, out var automationId)
                || !TryReadBoundedText(projection, "revision", MaxIdentityChars, out var revision)
                || !TryReadClosedValue(projection, "kind", OperatorScheduleContract.USER_AUTOMATION_SCHEDULE_KINDS, out _)
                || !TryReadBoundedText(projection, "expression", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
                || !TryReadBoundedText(projection, "calendar", OperatorScheduleContract.MAX_TEXT_BYTES, out _)
                || !TryReadBoundedText(projection, "timezone", OperatorScheduleContract.MAX_ZONE_IDENTITY_BYTES, out _)
                || !TryReadClosedValue(projection, "dst_fold", OperatorScheduleContract.USER_AUTOMATION_DST_FOLD_POLICIES, out _)
                || !TryReadClosedValue(projection, "dst_gap", OperatorScheduleContract.USER_AUTOMATION_DST_GAP_POLICIES, out _)
                || !TryReadBoundedText(projection, "start_at", OperatorScheduleContract.UTC_INSTANT_BYTES, out _)
                || !TryReadClosedValue(projection, "configuration_state", OperatorScheduleContract.USER_AUTOMATION_CONFIGURATION_STATES, out _)
                || !projection.TryGetProperty("next_occurrences", out var normalizedOccurrences)
                || normalizedOccurrences.ValueKind != JsonValueKind.Array
                || normalizedOccurrences.GetArrayLength() == 0
                || normalizedOccurrences.GetArrayLength() > OperatorScheduleContract.MAX_REFERENCES
                || !projection.TryGetProperty("occurrences", out var occurrenceProjections)
                || occurrenceProjections.ValueKind != JsonValueKind.Array
                || occurrenceProjections.GetArrayLength() != normalizedOccurrences.GetArrayLength())
            {
                return false;
            }

            if (projection.TryGetProperty("end_at", out var endAt)
                && (endAt.ValueKind != JsonValueKind.String
                    || string.IsNullOrWhiteSpace(endAt.GetString())
                    || endAt.GetString()!.Length > OperatorScheduleContract.UTC_INSTANT_BYTES
                    || endAt.GetString()!.Any(char.IsControl)))
            {
                return false;
            }

            var occurrenceKeys = new HashSet<string>(StringComparer.Ordinal);
            foreach (var normalizedOccurrence in normalizedOccurrences.EnumerateArray())
            {
                if (normalizedOccurrence.ValueKind != JsonValueKind.String)
                {
                    return false;
                }
                var occurrenceKey = normalizedOccurrence.GetString();
                if (string.IsNullOrWhiteSpace(occurrenceKey)
                    || occurrenceKey.Length > OperatorScheduleContract.MAX_OCCURRENCE_KEY_BYTES
                    || occurrenceKey.Any(char.IsControl)
                    || !occurrenceKeys.Add(occurrenceKey))
                {
                    return false;
                }
            }

            var seenOccurrenceIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (var occurrence in occurrenceProjections.EnumerateArray())
            {
                if (!HasAllowedAndRequiredProperties(
                        occurrence,
                        OperatorScheduleContract.USER_AUTOMATION_OCCURRENCE_PROJECTION_MEMBERS,
                        OperatorScheduleContract.USER_AUTOMATION_OCCURRENCE_PROJECTION_REQUIRED_MEMBERS)
                    || !TryGetObject(occurrence, "identity", out var identity)
                    || !HasExactProperties(identity, OperatorScheduleContract.USER_AUTOMATION_OCCURRENCE_IDENTITY_MEMBERS)
                    || !TryReadBoundedText(identity, "automation_id", MaxIdentityChars, out var identityAutomationId)
                    || !string.Equals(identityAutomationId, automationId, StringComparison.Ordinal)
                    || !TryReadBoundedText(identity, "revision", MaxIdentityChars, out var identityRevision)
                    || !string.Equals(identityRevision, revision, StringComparison.Ordinal)
                    || !TryReadBoundedText(identity, "occurrence_id", MaxIdentityChars, out var occurrenceId)
                    || !seenOccurrenceIds.Add(occurrenceId)
                    || !TryGetObject(identity, "trigger", out var trigger)
                    || !HasExactProperties(trigger, "kind", "occurrence_key")
                    || !TryReadClosedValue(trigger, "kind", OperatorScheduleContract.USER_AUTOMATION_TRIGGER_KINDS, out var triggerKind)
                    || !string.Equals(triggerKind, "scheduled", StringComparison.Ordinal)
                    || !TryReadBoundedText(trigger, "occurrence_key", OperatorScheduleContract.MAX_OCCURRENCE_KEY_BYTES, out var triggerOccurrenceKey)
                    || !occurrenceKeys.Contains(triggerOccurrenceKey))
                {
                    return false;
                }

                if (occurrence.TryGetProperty("next_occurrence", out var nextOccurrence)
                    && (nextOccurrence.ValueKind != JsonValueKind.String
                        || !occurrenceKeys.Contains(nextOccurrence.GetString() ?? string.Empty)))
                {
                    return false;
                }
            }
        }

        return true;
    }

    private static bool HasAllowedAndRequiredProperties(
        JsonElement value,
        string[] allowedNames,
        string[] requiredNames)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            return false;
        }
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!allowedNames.Contains(property.Name, StringComparer.Ordinal)
                || !names.Add(property.Name))
            {
                return false;
            }
        }
        return requiredNames.All(names.Contains);
    }

    private static bool SameSerializedFence(JsonElement left, JsonElement right) =>
        string.Equals(left.GetRawText(), right.GetRawText(), StringComparison.Ordinal);

    private static UserAutomationOutcome ReadAttemptRefusal(
        string action,
        JsonElement value,
        JsonElement recovery,
        UserAutomationResultValidationContext context,
        JsonElement answer)
    {
        if (!HasExactProperties(
                value,
                "kind",
                "schema_version",
                "operation",
                "state_fence",
                "attempt_state",
                "refusal")
            || !TryReadBoundedText(value, "kind", 64, out var kind)
            || !string.Equals(kind, "user_automation_refusal", StringComparison.Ordinal)
            || !value.TryGetProperty("schema_version", out var schemaVersion)
            || schemaVersion.ValueKind != JsonValueKind.Number
            || !schemaVersion.TryGetInt32(out var version)
            || version != 1
            || !TryGetObject(value, "operation", out var operation)
            || !MatchesOperationIdentity(operation, context, RequestIdMember)
            || !TryGetObject(value, "state_fence", out var stateFence)
            || !IsClosedStateFence(stateFence)
            || !TryGetObject(answer, "state_fence", out var envelopeFence)
            || !SameSerializedFence(stateFence, envelopeFence)
            || !TryReadBoundedText(value, "attempt_state", 64, out var attemptState)
            || !string.Equals(attemptState, "store_not_called", StringComparison.Ordinal)
            || !HasExactProperties(recovery, "kind", "reason")
            || !TryReadBoundedText(recovery, "kind", 64, out var recoveryKind)
            || !string.Equals(recoveryKind, "unknown_outcome", StringComparison.Ordinal)
            || !TryReadBoundedText(recovery, "reason", MaxRecoveryReasonChars, out var recoveryReason)
            || !TryGetObject(value, "refusal", out var refusal))
        {
            return UnverifiedOwnerAnswer(
                action,
                "the typed refusal is malformed or does not bind to this request; the operation outcome remains unknown");
        }

        var hasField = HasExactProperties(refusal, "code", "field");
        if (!hasField && !HasExactProperties(refusal, "code"))
        {
            return UnverifiedOwnerAnswer(action, "the typed refusal has an open or malformed code shape");
        }

        if (!TryReadBoundedText(refusal, "code", 64, out var code)
            || !TryExplainRefusal(code, out var explanation))
        {
            return UnverifiedOwnerAnswer(action, "the typed refusal code is unsupported; the operation outcome remains unknown");
        }

        string? field = null;
        if (hasField)
        {
            if (!TryReadBoundedText(refusal, "field", MaxRefusalFieldChars, out var fieldValue))
            {
                return UnverifiedOwnerAnswer(action, "the typed refusal field is malformed; the operation outcome remains unknown");
            }
            field = fieldValue;
        }

        if (string.Equals(code, "semantic_rejection", StringComparison.Ordinal)
            && string.Equals(field, "revision.supersedes", StringComparison.Ordinal))
        {
            explanation = "Action: submit one new immutable revision superseding one distinct revision of the same automation.";
        }

        var fieldText = field is null ? string.Empty : $" Field: {field}.";
        return new UserAutomationOutcome(
            UserAutomationOutcomeClass.OwnerRefused,
            $"UserAutomation {action} refused on this attempt — reconcile the operation",
            $"This attempt was refused before Store ({attemptState}); an earlier attempt under the same identity may still have committed. "
            + $"Owner reason: {code}.{fieldText} {explanation} "
            + $"Recovery: {recoveryReason}",
            code,
            RefusalText: null,
            ScheduleProjection: null);
    }

    /// <summary>
    /// The one operation-correlation parser of this classifier. The typed
    /// refusal projects the authenticated route's correlation handle beside
    /// the operation identity, and a known transition carries the Store
    /// identity itself, whose third member is the canonical request hash. The
    /// two owner projections therefore name a different owner-minted member,
    /// so that name is passed in once per envelope, but every identity the
    /// Operator can derive is compared by the single rule below. The known and
    /// the unknown/refusal paths cannot drift apart (#2972).
    /// </summary>
    private static bool MatchesOperationIdentity(
        JsonElement operation,
        UserAutomationResultValidationContext context,
        string ownerMintedMemberName)
    {
        if (!HasExactProperties(operation, "operation_id", ownerMintedMemberName, "idempotency_key")
            || !TryReadBoundedText(operation, "operation_id", MaxOperationIdChars, out var operationId)
            || !TryReadBoundedText(operation, ownerMintedMemberName, MaxIdentityChars, out _)
            || !TryReadBoundedText(operation, "idempotency_key", MaxIdentityChars, out var idempotencyKey))
        {
            return false;
        }

        // The owner-minted member is the route's RequestId for a typed refusal
        // and the Store's canonical request hash for a transition. Each is
        // sealed inside the authenticated owner and neither can be recomputed
        // here, so each is read for its closed bounded shape only. The two
        // identities the Operator does hold are exact: the pending operation ID
        // is the request idempotency key, and Kernel prefixes that key when it
        // returns its operation ID.
        return string.Equals(idempotencyKey, context.ExpectedIdempotencyKey, StringComparison.Ordinal)
            && string.Equals(
                operationId,
                context.ExpectedOperationId,
                StringComparison.Ordinal);
    }

    private static bool IsClosedStateFence(JsonElement stateFence)
    {
        if (!HasExactProperties(
                stateFence,
                "authority_epoch",
                "resource_generation",
                "task_revision",
                "policy_revision",
                "integration_revision")
            || !TryGetObject(stateFence, "authority_epoch", out var authorityEpoch)
            || !HasExactProperties(authorityEpoch, "lineage_id", "sequence")
            || !TryReadBoundedText(authorityEpoch, "lineage_id", 36, out var lineageId)
            || !IsLowercaseUuid(lineageId)
            || !stateFence.TryGetProperty("resource_generation", out var resourceGeneration)
            || !IsPositiveUInt64(resourceGeneration))
        {
            return false;
        }

        if (!authorityEpoch.TryGetProperty("sequence", out var sequence)
            || !IsPositiveUInt64(sequence))
        {
            return false;
        }

        return IsOptionalPositiveUInt64(stateFence, "task_revision")
            && IsOptionalPositiveUInt64(stateFence, "policy_revision")
            && IsOptionalPositiveUInt64(stateFence, "integration_revision");
    }

    private static bool IsOptionalPositiveUInt64(JsonElement value, string propertyName) =>
        value.TryGetProperty(propertyName, out var member)
        && (member.ValueKind == JsonValueKind.Null || IsPositiveUInt64(member));

    private static bool IsPositiveUInt64(JsonElement value) =>
        value.ValueKind == JsonValueKind.Number
        && value.TryGetUInt64(out var number)
        && number > 0;

    private static bool IsLowercaseUuid(string value)
    {
        if (value.Length != 36) return false;
        for (var index = 0; index < value.Length; index++)
        {
            if (index is 8 or 13 or 18 or 23)
            {
                if (value[index] != '-') return false;
            }
            else if (!((value[index] >= '0' && value[index] <= '9')
                || (value[index] >= 'a' && value[index] <= 'f')))
            {
                return false;
            }
        }
        return true;
    }

    private static bool HasExactProperties(JsonElement value, params string[] expectedNames)
    {
        if (value.ValueKind != JsonValueKind.Object) return false;
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!expectedNames.Contains(property.Name, StringComparer.Ordinal)
                || !names.Add(property.Name))
            {
                return false;
            }
        }
        return names.Count == expectedNames.Length;
    }

    private static bool TryGetObject(JsonElement parent, string propertyName, out JsonElement value)
    {
        value = default;
        return parent.ValueKind == JsonValueKind.Object
            && parent.TryGetProperty(propertyName, out value)
            && value.ValueKind == JsonValueKind.Object;
    }

    private static bool TryReadBoundedText(
        JsonElement parent,
        string propertyName,
        int maximumLength,
        out string value)
    {
        value = string.Empty;
        if (parent.ValueKind != JsonValueKind.Object
            || !parent.TryGetProperty(propertyName, out var member)
            || member.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        var text = member.GetString();
        if (string.IsNullOrWhiteSpace(text)
            || text.Length > maximumLength
            || text.Any(char.IsControl))
        {
            return false;
        }
        value = text;
        return true;
    }

    private static bool TryExplainRefusal(string code, out string explanation)
    {
        explanation = code switch
        {
            "unsupported_contract_version" =>
                $"Action: obtain an owner-normalized result under {OperatorScheduleContract.NORMALIZED_OCCURRENCE_ENCODING} and submit a new immutable revision; this Operator build exposes no re-normalization route, and the existing revision must not be rewritten.",
            "legacy_encoding" =>
                "Action: preserve the legacy immutable revision and obtain a current owner-normalized result before submitting a NEW revision; this Operator build exposes no migration route and never rewrites a revision in place.",
            "stale_normalization_revision" =>
                "Action: obtain a fresh owner normalization for the current effect-relevant schedule fields, then submit a new immutable revision.",
            "invalid_or_moved_receipt" =>
                "Action: obtain a valid owner-issued receipt bound to this exact schedule and operation; do not move or reuse the prior receipt.",
            "semantic_rejection" =>
                "Action: correct the owner-rejected field or schedule meaning, obtain fresh owner evidence when schedule semantics changed, and submit a new operation.",
            _ => string.Empty
        };
        return explanation.Length != 0;
    }

    private static UserAutomationOutcome UnverifiedOwnerAnswer(string action, string reason) =>
        new(
            UserAutomationOutcomeClass.UnverifiedOwnerAnswer,
            $"UserAutomation {action} answered — outcome unverified",
            $"{reason}. The operation remains unknown and must be reconciled under its same identity; the Operator does not claim commit or noncommit.",
            RefusalKind: null,
            RefusalText: null,
            ScheduleProjection: null);

    /// <summary>
    /// Explains why the decoded occurrence fields are inspection data rather
    /// than owner-issued normalization evidence, then shows a bounded summary.
    /// </summary>
    private static string DescribeUnverifiedScheduleProjection(UserAutomationScheduleProjection projection) =>
        $"A decodable {OperatorScheduleContract.NORMALIZED_OCCURRENCE_ENCODING} occurrence projection is shown for inspection, "
        + "but this response does not prove the owner-issued normalization receipt or provenance. Any embedded receipt identity is unverified. Its freshness and relationship to "
        + "effect-relevant schedule fields are unverified; the Operator does not report it as normalized.\n"
        + DescribeScheduleProjection(projection);

    /// <summary>
    /// Summarizes the parsed projection's contract identity and occurrence
    /// details without asserting who normalized the underlying bytes.
    /// </summary>
    private static string DescribeScheduleProjection(UserAutomationScheduleProjection projection)
    {
        var builder = new StringBuilder(projection.ContractIdentity());
        if (projection.NormalizationReceipt is { } normalizationReceipt)
        {
            builder.Append("\ncaller-supplied normalization_receipt (identity and provenance unverified): ")
                .Append("receipt_id ").Append(normalizationReceipt.ReceiptId)
                .Append("; authority ").Append(normalizationReceipt.NormalizerAuthority)
                .Append("; source_digest ").Append(normalizationReceipt.SourceDigest)
                .Append("; occurrences_digest ").Append(normalizationReceipt.OccurrencesDigest)
                .Append("; zone_database_revision ").Append(normalizationReceipt.ZoneDatabaseRevision).Append('.');
        }
        else
        {
            builder.Append("\nNo normalization_receipt is available in this projection.");
        }
        var shown = Math.Min(MaxDescribedOccurrences, projection.Occurrences.Count);
        for (var index = 0; index < shown; index++)
        {
            builder.Append('\n').Append(projection.Occurrences[index].Describe());
        }
        if (projection.Occurrences.Count > shown)
        {
            builder.Append(CultureInfo.InvariantCulture, $"\n...{projection.Occurrences.Count - shown} further occurrence(s); inspect the retained response for the complete list.");
        }
        return builder.ToString();
    }

    /// <summary>
    /// Reports an owner that did not answer. No schedule state is asserted: the
    /// Operator has no owner evidence, so it cannot claim a normalization.
    /// </summary>
    public static UserAutomationOutcome OwnerAbsent(string action, string reason) =>
        new(
            UserAutomationOutcomeClass.OwnerAbsent,
            $"UserAutomation {action} — owner did not answer",
            $"{reason} No owner normalization result is in hand, so the Operator does not "
            + "report this schedule as normalized.",
            RefusalKind: null,
            RefusalText: null,
            ScheduleProjection: null);

    /// <summary>
    /// Reports a revision refused locally, before transmission. The exact owner
    /// sentence and the single next action are both preserved.
    /// </summary>
    public static UserAutomationOutcome RefusedBeforeSubmission(
        UserAutomationScheduleContractException refusal) =>
        new(
            UserAutomationOutcomeClass.RefusedBeforeSubmission,
            "UserAutomation command not sent",
            refusal.Message,
            refusal.Kind,
            refusal.OwnerText,
            ScheduleProjection: null);

    /// <summary>
    /// Decodes a versioned occurrence projection when the answer carries one.
    /// The answer is treated as untrusted data at a bounded depth; decoding it
    /// provides inspection details, not proof of normalization provenance.
    /// </summary>
    private static UserAutomationScheduleProjection? FindScheduleProjection(JsonElement answer)
    {
        if (!TryGetObject(answer, "value", out var value)
            || !value.TryGetProperty("occurrences", out var projections)
            || projections.ValueKind != JsonValueKind.Array)
        {
            return null;
        }
        foreach (var projection in projections.EnumerateArray())
        {
            if (TryReadScheduleProjection(projection, out var receipt)) return receipt;
        }
        return null;
    }

    private static bool TryReadScheduleProjection(
        JsonElement element,
        out UserAutomationScheduleProjection receipt)
    {
        receipt = null!;
        if (!element.TryGetProperty("timezone", out var timezone)
            || timezone.ValueKind != JsonValueKind.String
            || !element.TryGetProperty("dst_fold", out var fold)
            || fold.ValueKind != JsonValueKind.String
            || !element.TryGetProperty("dst_gap", out var gap)
            || gap.ValueKind != JsonValueKind.String
            || !element.TryGetProperty("start_at", out var startAt)
            || startAt.ValueKind != JsonValueKind.String
            || !element.TryGetProperty("next_occurrences", out var occurrences)
            || occurrences.ValueKind != JsonValueKind.Array)
        {
            return false;
        }
        var keys = new List<string>(occurrences.GetArrayLength());
        foreach (var occurrence in occurrences.EnumerateArray())
        {
            if (occurrence.ValueKind != JsonValueKind.String) return false;
            keys.Add(occurrence.GetString()!);
        }
        var endAt = element.TryGetProperty("end_at", out var endElement)
            && endElement.ValueKind == JsonValueKind.String
                ? endElement.GetString()
                : null;
        UserAutomationScheduleNormalizationReceipt? normalizationReceipt = null;
        if (element.TryGetProperty("normalization_receipt", out var normalizationElement))
        {
            if (normalizationElement.ValueKind != JsonValueKind.Object
                || !TryGetString(normalizationElement, "receipt_id", out var receiptId)
                || !TryGetString(normalizationElement, "normalizer_authority", out var normalizerAuthority)
                || !TryGetString(normalizationElement, "source_digest", out var sourceDigest)
                || !TryGetString(normalizationElement, "zone_database_revision", out var zoneDatabaseRevision)
                || !TryGetString(normalizationElement, "occurrences_digest", out var occurrencesDigest))
            {
                return false;
            }
            normalizationReceipt = new UserAutomationScheduleNormalizationReceipt(
                receiptId,
                normalizerAuthority,
                sourceDigest,
                zoneDatabaseRevision,
                occurrencesDigest);
            try
            {
                normalizationReceipt.Validate();
            }
            catch (InvalidOperationException)
            {
                return false;
            }
        }
        try
        {
            receipt = UserAutomationScheduleMirror.ReadScheduleProjection(
                timezone.GetString()!,
                fold.GetString()!,
                gap.GetString()!,
                startAt.GetString()!,
                endAt,
                keys) with { NormalizationReceipt = normalizationReceipt };
            return true;
        }
        catch (UserAutomationScheduleContractException)
        {
            // The owner answer carries a schedule this build cannot decode under
            // the pinned contract. That is unverified evidence, not a success,
            // and it is never reported as a normalized schedule.
            return false;
        }
    }

    private static bool TryGetString(JsonElement element, string name, out string value)
    {
        value = string.Empty;
        if (!element.TryGetProperty(name, out var property)
            || property.ValueKind != JsonValueKind.String)
        {
            return false;
        }
        value = property.GetString()!;
        return true;
    }
}
