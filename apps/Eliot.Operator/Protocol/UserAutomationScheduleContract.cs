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
/// One decoded owner-issued normalized occurrence, exactly as the owner recorded
/// it, plus the arithmetic instant the owner bound it to.
/// </summary>
/// <remarks>
/// The raw record is retained verbatim on <see cref="Record"/> so the exact owner
/// bytes stay available for exact submission and inspection. The decoded fields
/// are what the Operator displays: zone identity, the pinned zone database
/// revision, the local wall clock, the resolved UTC instant and applied offset,
/// and the applied fold/gap disposition.
/// </remarks>
public sealed record UserAutomationNormalizedOccurrence(
    string Record,
    string Encoding,
    string Timezone,
    string ZoneDatabaseRevision,
    string Local,
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
    /// pinned database revision, the local wall clock, the resolved instant and
    /// offset, the applied disposition and the owner's own record bytes, so the
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
            $"{Timezone}@{ZoneDatabaseRevision} local {Local} offset {Offset} instant {Instant} disposition {Disposition} transition {transition} source_digest {SourceDigest} record [{Record}]");
    }
}

/// <summary>
/// The typed, local, shape-and-evidence view of one validated schedule.
/// </summary>
/// <remarks>
/// <para>
/// This is the normalization receipt the Operator preserves for a revision it
/// has admitted for submission. It is a METHOD-returned value rather than a
/// property for the same reason <c>IsEffect</c> is a method: the owner-side
/// request records are <c>deny_unknown_fields</c>, so a serialized member the
/// owner does not know would make every request undecodable. Nothing here is
/// transmitted, and nothing here is an owner receipt.
/// </para>
/// <para>
/// What this receipt asserts is exactly what the owner-issued bytes decide: the
/// exact contract version, the pinned zone database release, the zone identity,
/// the one source digest every member carries, the occurrence count, and the
/// resolved instant span. What it does NOT assert is that the owner admitted
/// the revision: only an owner answer can do that, and a schedule is never
/// described as normalized on the strength of a local receipt alone.
/// </para>
/// </remarks>
public sealed record UserAutomationScheduleReceipt(
    string Encoding,
    string PinnedZoneDatabaseRelease,
    string Timezone,
    string SourceDigest,
    int OccurrenceCount,
    long FirstInstantSeconds,
    long LastInstantSeconds,
    IReadOnlyList<UserAutomationNormalizedOccurrence> Occurrences)
{
    /// <summary>
    /// The exact contract identity this receipt is bound to, as one line. It
    /// names the contract version and the pinned database release the owner
    /// bytes already carry, so the UI never needs a second copy of either.
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
/// and the exact supported contract version of what an owner-issued result
/// carries. The admitted calendar/time owner issues the normalized occurrences
/// and its receipt. Kernel validates owner evidence and admission. The Operator
/// displays the owner result and any fail-closed incompatibility. This mirror
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
/// only what the owner-issued bytes decide — see
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
    /// Port of <c>require_resolved_instant</c>: the recorded instant must be
    /// exactly the one the recorded disposition and applied offset select for the
    /// recorded local wall clock. This is arithmetic over the owner's own bytes —
    /// it consults no zone, no table and no ambient clock — so an occurrence
    /// whose recorded offset is neither side of its recorded transition, or
    /// whose instant does not round-trip through its own offset, is refused
    /// here rather than presented as a fold or gap.
    /// </summary>
    private static void RequireResolvedInstant(
        long localSeconds,
        int offsetMinutes,
        string disposition,
        (string? Before, string? After) transition,
        long instantSeconds)
    {
        int applied;
        if (disposition == "UNIQUE" && transition.Before is null)
        {
            applied = offsetMinutes;
        }
        else if (disposition == "FOLD_FIRST"
            && transition.Before is not null
            && transition.After is not null
            && ParseUtcOffsetMinutes(transition.Before, "schedule.occurrence_key.transition")
                > ParseUtcOffsetMinutes(transition.After, "schedule.occurrence_key.transition")
            && offsetMinutes == ParseUtcOffsetMinutes(
                transition.Before, "schedule.occurrence_key.transition"))
        {
            applied = offsetMinutes;
        }
        else if (disposition == "FOLD_SECOND"
            && transition.Before is not null
            && transition.After is not null
            && ParseUtcOffsetMinutes(transition.Before, "schedule.occurrence_key.transition")
                > ParseUtcOffsetMinutes(transition.After, "schedule.occurrence_key.transition")
            && offsetMinutes == ParseUtcOffsetMinutes(
                transition.After, "schedule.occurrence_key.transition"))
        {
            applied = offsetMinutes;
        }
        else if (disposition == "GAP_SHIFT_FORWARD"
            && transition.Before is not null
            && transition.After is not null
            && ParseUtcOffsetMinutes(transition.Before, "schedule.occurrence_key.transition")
                < ParseUtcOffsetMinutes(transition.After, "schedule.occurrence_key.transition")
            && offsetMinutes == ParseUtcOffsetMinutes(
                transition.After, "schedule.occurrence_key.transition"))
        {
            applied = ParseUtcOffsetMinutes(
                transition.Before, "schedule.occurrence_key.transition");
        }
        else
        {
            throw Invalid("schedule.occurrence_key.transition");
        }
        if (localSeconds - (long)applied * 60L != instantSeconds)
        {
            throw Invalid("schedule.occurrence_key.instant");
        }
    }

    /// <summary>
    /// Port of the owner's <c>parse_occurrence</c>, restricted to the rules the
    /// Operator may decide from the owner-issued bytes alone.
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
            throw IsLegacyOccurrenceKey(occurrenceKey)
                ? LegacyScheduleEncoding()
                : Invalid("schedule.occurrence_key.shape");
        }
        var encoding = fields[0];
        if (!string.Equals(encoding, OperatorScheduleContract.NORMALIZED_OCCURRENCE_ENCODING, StringComparison.Ordinal))
        {
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
        if (fields[8].Length == 0
            || Encoding.UTF8.GetByteCount(fields[8]) > OperatorScheduleContract.MAX_OCCURRENCE_KEY_BYTES)
        {
            throw Invalid("schedule.occurrence_key.source_digest");
        }
        var disposition = fields[7];
        if (!OperatorScheduleContract.Dispositions.Contains(disposition, StringComparer.Ordinal))
        {
            throw Invalid("schedule.occurrence_key.disposition");
        }
        RequireDeclaredDisposition(disposition, dstFold, dstGap);
        var localSeconds = ParseCivilWallClockSeconds(
            fields[3], "schedule.occurrence_key.local");
        var offsetMinutes = ParseUtcOffsetMinutes(fields[4], "schedule.occurrence_key.offset");
        var instantSeconds = ParseUtcInstantSeconds(fields[5], "schedule.occurrence_key.instant");
        var transition = ParseTransitionWindow(
            fields[6], disposition, "schedule.occurrence_key.transition");
        RequireResolvedInstant(localSeconds, offsetMinutes, disposition, transition, instantSeconds);
        return new UserAutomationNormalizedOccurrence(
            Record: occurrenceKey,
            Encoding: encoding,
            Timezone: fields[1],
            ZoneDatabaseRevision: fields[2],
            Local: fields[3],
            OffsetMinutes: offsetMinutes,
            Offset: fields[4],
            Instant: fields[5],
            InstantSeconds: instantSeconds,
            TransitionBeforeOffset: transition.Before,
            TransitionAfterOffset: transition.After,
            Disposition: disposition,
            SourceDigest: fields[8]);
    }

    /// <summary>
    /// Port of <c>normalized_occurrences</c>: the cross-member and interval rules
    /// over the whole set.
    /// </summary>
    /// <remarks>
    /// The interval bounds are parsed as INSTANTS and every member is compared
    /// by its resolved canonical instant. Lexical ordering of the raw records is
    /// NOT used anywhere: two chronologically ordered members of one set can
    /// spell their instants so that a byte comparison puts them in the opposite
    /// order, and a mixed-offset set is exactly that case.
    /// </remarks>
    public static UserAutomationScheduleReceipt ReadOwnerSchedule(
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

        return new UserAutomationScheduleReceipt(
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
    /// The stale-owner-evidence checks for an edit that changes an
    /// effect-relevant schedule field.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An edit is a NEW immutable revision. If it changes a source
    /// (expression/calendar), a zone, a DST policy, the interval, or the
    /// occurrence set itself, it must be backed by a NEW owner normalization
    /// result; the Operator never derives one, never re-normalizes, and never
    /// rewrites a revision in place.
    /// </para>
    /// <para>
    /// Two refusals follow, both decidable from the owner-issued bytes without
    /// recomputing the owner's digest:
    /// </para>
    /// <list type="number">
    /// <item>
    /// The new revision carries the PREVIOUS revision's occurrence source digest
    /// while an effect-relevant schedule field changed. The new revision is
    /// reusing the previous revision's owner normalization result, so it is
    /// refused as stale owner evidence.
    /// </item>
    /// <item>
    /// The new revision's expression and calendar are unchanged but its
    /// occurrence source digest differs. That digest is foreign to that source,
    /// so it is refused.
    /// </item>
    /// </list>
    /// <para>
    /// The two checks are independent on purpose. The occurrence comparison in
    /// the first check deliberately EXCLUDES the source digest field, so that a
    /// digest-only difference counts as "unchanged occurrences" and reaches the
    /// second check instead of masking it as an occurrence change.
    /// </para>
    /// <para>
    /// Limit, stated plainly: the Operator cannot recompute the owner's compiled
    /// digest, so it cannot PROVE that a genuinely changed source was properly
    /// re-normalized. It proves only that the two provable reuse and foreign
    /// cases are refused, and it never asserts that an accepted edit's digest is
    /// the correct one. The owner remains the sole authority on that.
    /// </para>
    /// </remarks>
    public static void RequireFreshOwnerEvidenceForEdit(
        UserAutomationNormalizedSchedule previous,
        UserAutomationNormalizedSchedule next)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(next);
        var previousReceipt = previous.NormalizationReceipt();
        var nextReceipt = next.NormalizationReceipt();
        var sameSource = string.Equals(previous.Expression, next.Expression, StringComparison.Ordinal)
            && string.Equals(previous.Calendar, next.Calendar, StringComparison.Ordinal);
        var effectRelevantChanged = !sameSource
            || !string.Equals(previous.Timezone, next.Timezone, StringComparison.Ordinal)
            || !string.Equals(previous.DstFold, next.DstFold, StringComparison.Ordinal)
            || !string.Equals(previous.DstGap, next.DstGap, StringComparison.Ordinal)
            || !string.Equals(previous.StartAt, next.StartAt, StringComparison.Ordinal)
            || !string.Equals(previous.EndAt, next.EndAt, StringComparison.Ordinal)
            || !OccurrencesMatchWithoutSourceDigest(previous.NextOccurrences, next.NextOccurrences);
        var sameDigest = string.Equals(
            previousReceipt.SourceDigest, nextReceipt.SourceDigest, StringComparison.Ordinal);
        if (effectRelevantChanged && sameDigest)
        {
            throw new UserAutomationScheduleContractException(
                "Invalid",
                OwnerText("Invalid", "schedule.next_occurrences.source_digest"),
                "this edit reuses the previous revision's owner normalization result; obtain a new owner normalization and submit it as a new immutable revision");
        }
        if (sameSource && !sameDigest)
        {
            throw new UserAutomationScheduleContractException(
                "Invalid",
                OwnerText("Invalid", "schedule.occurrence_key.source_digest"),
                "this edit keeps the same source but carries a foreign occurrence source digest; the owner's normalization result for this source is required");
        }
    }

    /// <summary>
    /// Whether two owner-issued occurrence sets are the same apart from the
    /// occurrence source digest.
    /// </summary>
    /// <remarks>
    /// The digest is the LAST field of the fixed-arity record, and both sets have
    /// already passed the occurrence grammar, so dropping it is a positional read
    /// of the owner's own record rather than a re-interpretation of it.
    /// </remarks>
    private static bool OccurrencesMatchWithoutSourceDigest(
        IReadOnlyList<string> previous,
        IReadOnlyList<string> next)
    {
        if (previous.Count != next.Count) return false;
        for (var index = 0; index < previous.Count; index++)
        {
            if (!string.Equals(
                    WithoutSourceDigest(previous[index]),
                    WithoutSourceDigest(next[index]),
                    StringComparison.Ordinal))
            {
                return false;
            }
        }
        return true;
    }

    private static string WithoutSourceDigest(string occurrenceKey)
    {
        var fields = occurrenceKey.Split(
            OperatorScheduleContract.NORMALIZED_OCCURRENCE_FIELD_SEPARATOR);
        return string.Join(
            OperatorScheduleContract.NORMALIZED_OCCURRENCE_FIELD_SEPARATOR,
            fields.Take(fields.Length - 1));
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
            "this occurrence is the retired shape-only encoding; run the owner re-normalization/migration action and create a NEW revision; an immutable revision is never rewritten in place");

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
/// What the Operator is allowed to say about the outcome of one typed
/// UserAutomation operation. It never claims a schedule is normalized unless the
/// owner actually issued the evidence in THIS answer.
/// </summary>
public enum UserAutomationOutcomeClass
{
    /// <summary>The owner answered and this answer carries no typed refusal.</summary>
    OwnerAnswered,

    /// <summary>
    /// The owner answered, and this answer carries the owner-issued normalized
    /// occurrence projection. The occurrence evidence is the owner's; the
    /// Operator only decodes and displays it.
    /// </summary>
    OwnerIssuedNormalization,

    /// <summary>The owner answered with a typed refusal this build can name.</summary>
    OwnerRefused,

    /// <summary>
    /// The owner answered, and this answer proves nothing about the schedule.
    /// The Operator reports it as unverified and never as normalized.
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
/// said, which typed refusal it was, and the owner-issued occurrence evidence if
/// this answer carried any.
/// </summary>
public sealed record UserAutomationOutcome(
    UserAutomationOutcomeClass Class,
    string Title,
    string Detail,
    string? RefusalKind,
    string? RefusalText,
    UserAutomationScheduleReceipt? Receipt);

/// <summary>
/// Decodes one owner answer into a typed, actionable outcome.
/// </summary>
/// <remarks>
/// <para>
/// A Kernel refusal is decoded from the owner answer by matching the exact
/// <c>Display</c> strings the owner emits, using the GENERATED refusal table
/// rather than a hand-typed list. The scan is bounded in depth, member count and
/// string length, and it reports nothing as decoded unless it actually matched
/// an owner sentence: an unrecognised answer is
/// <see cref="UserAutomationOutcomeClass.UnverifiedOwnerAnswer"/>, never a
/// success.
/// </para>
/// <para>
/// The classifier is deliberately unable to say "normalized" on its own. It says
/// <see cref="UserAutomationOutcomeClass.OwnerIssuedNormalization"/> only when the
/// owner's answer itself carries a schedule whose occurrence set this build
/// decodes under the pinned contract version; and it never produces that class
/// for a locally refused revision, which cannot have been sent at all.
/// </para>
/// </remarks>
public static class UserAutomationOutcomeClassifier
{
    /// <summary>Owner answer member names that may carry a refusal sentence.</summary>
    private static readonly string[] RefusalMembers =
    [
        "error", "reason", "message", "detail", "cause", "display", "refusal", "diagnosis"
    ];

    private const int MaxScanDepth = 6;
    private const int MaxScannedStrings = 64;
    private const int MaxScannedStringChars = 1_024;

    /// <summary>
    /// How many owner occurrence lines the summary names. The retained owner
    /// bytes stay whole in the result payload, so bounding the summary never
    /// drops evidence — it only states how many further occurrences the owner
    /// issued instead of silently shortening the list.
    /// </summary>
    private const int MaxDescribedOccurrences = 8;

    /// <summary>Decodes one owner answer for one typed operation.</summary>
    public static UserAutomationOutcome Read(string action, JsonElement answer)
    {
        ArgumentNullException.ThrowIfNull(action);
        if (answer.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
        {
            return OwnerAbsent(action, "the owner route returned no result payload.");
        }

        var refusal = FindRefusal(answer);
        if (refusal is not null)
        {
            // The owner's exact sentence is shown verbatim and the Operator adds
            // only the one next action. Neither is reworded, abbreviated, nor
            // collapsed into a generic JSON error.
            var text = refusal.Value.Text;
            return new UserAutomationOutcome(
                UserAutomationOutcomeClass.OwnerRefused,
                $"UserAutomation {action} refused by the owner",
                $"{text} {ExplainVariant(refusal.Value.Template.Variant)}",
                refusal.Value.Template.Variant,
                text,
                Receipt: null);
        }

        var receipt = FindOwnerSchedule(answer);
        if (receipt is not null)
        {
            return new UserAutomationOutcome(
                UserAutomationOutcomeClass.OwnerIssuedNormalization,
                $"UserAutomation {action} owner-issued schedule",
                DescribeOwnerSchedule(receipt),
                RefusalKind: null,
                RefusalText: null,
                Receipt: receipt);
        }

        return new UserAutomationOutcome(
            UserAutomationOutcomeClass.UnverifiedOwnerAnswer,
            $"UserAutomation {action} answered — schedule not verified",
            "the owner answered this typed operation but this answer carries no owner-issued "
            + $"{OperatorScheduleContract.NORMALIZED_OCCURRENCE_ENCODING} occurrence projection, "
            + "so the Operator does not report the schedule as normalized",
            RefusalKind: null,
            RefusalText: null,
            Receipt: null);
    }

    /// <summary>
    /// The inspection summary of one owner-issued occurrence set: the contract
    /// identity first, then each occurrence's zone database revision, local wall
    /// clock, resolved instant and offset, applied disposition and transition
    /// evidence, exactly as the owner recorded them.
    /// </summary>
    private static string DescribeOwnerSchedule(UserAutomationScheduleReceipt receipt)
    {
        var builder = new StringBuilder(receipt.ContractIdentity());
        var shown = Math.Min(MaxDescribedOccurrences, receipt.Occurrences.Count);
        for (var index = 0; index < shown; index++)
        {
            builder.Append('\n').Append(receipt.Occurrences[index].Describe());
        }
        if (receipt.Occurrences.Count > shown)
        {
            builder.Append(CultureInfo.InvariantCulture, $"\n...{receipt.Occurrences.Count - shown} further owner-issued occurrence(s); the retained owner bytes below are complete.");
        }
        return builder.ToString();
    }

    /// <summary>
    /// The one next action for a decoded owner refusal variant, in the
    /// Operator's own words. The owner's exact sentence is always shown
    /// alongside it and is never reworded.
    /// </summary>
    private static string ExplainVariant(string variant) => variant switch
    {
        "LegacyScheduleEncoding" =>
            "Action: run the owner re-normalization/migration action and create a NEW immutable revision; the Operator never rewrites a revision in place.",
        "ZoneDatabaseRevision" =>
            $"Action: obtain a new owner normalization against pinned zone database {OperatorScheduleContract.PINNED_ZONE_DATABASE_RELEASE}; a database update can never rewrite an existing revision.",
        "UnknownZone" =>
            "Action: declare a zone the pinned owner zone table actually carries; the Operator does not resolve a zone from its spelling or from ambient Windows timezone data.",
        "ZoneEvidence" or "ZoneTableIntegrity" =>
            "Action: obtain a fresh owner normalization result; the recorded offset, transition or disposition is not what the owner's pinned zone table applies.",
        "ZoneTableWindow" =>
            "Action: obtain a new owner normalization result inside the owner's pinned zone table window; the Operator never extrapolates it.",
        "Receipt" or "ReceiptBinding" =>
            "Action: obtain a valid, request-bound owner-issued source receipt; a moved or unbound receipt is refused rather than repaired.",
        "RevisionMismatch" or "OccurrenceMismatch" =>
            "Action: resend the exact immutable revision and occurrence identity the owner issued.",
        "InvalidSupersession" =>
            "Action: submit one edit that supersedes one distinct revision of the same automation.",
        "Invalid" or "LimitExceeded" =>
            "Action: correct the named field against the owner contract and submit a new revision.",
        _ =>
            "Action: read the owner's sentence above; the Operator reports it verbatim and infers nothing further."
    };

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
            Receipt: null);

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
            Receipt: null);

    /// <summary>
    /// Describes the exact bytes one create/edit request is bound to, so the UI
    /// can show the contract identity and digest it is about to submit rather
    /// than asserting normalization on the strength of a local check.
    /// </summary>
    public static string DescribeSubmission(
        string action,
        UserAutomationScheduleReceipt receipt,
        string operationIdentity) =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"UserAutomation {action} is bound to {receipt.ContractIdentity()} under one retry-stable operation identity {operationIdentity}. Shape and contract version are checked locally; admission and normalization remain the owner's decision, and the owner's own source-digest value is not verified here.");

    private static (OperatorOwnerRefusalTemplate Template, string Text)? FindRefusal(JsonElement answer)
    {
        var seen = 0;
        return ScanForRefusal(answer, 0, ref seen);
    }

    private static (OperatorOwnerRefusalTemplate Template, string Text)? ScanForRefusal(
        JsonElement element,
        int depth,
        ref int seen)
    {
        if (element.ValueKind == JsonValueKind.String)
        {
            if (seen >= MaxScannedStrings) return null;
            var text = element.GetString();
            if (string.IsNullOrEmpty(text) || text.Length > MaxScannedStringChars) return null;
            seen++;
            var template = Match(text);
            return template is null ? null : (template, text);
        }
        if (depth >= MaxScanDepth) return null;
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (!RefusalMembers.Contains(property.Name, StringComparer.Ordinal)) continue;
                var matched = ScanForRefusal(property.Value, depth + 1, ref seen);
                if (matched is not null) return matched;
            }
            return null;
        }
        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                var matched = ScanForRefusal(item, depth + 1, ref seen);
                if (matched is not null) return matched;
            }
        }
        return null;
    }

    /// <summary>
    /// Matches one owner sentence against the generated refusal table. The
    /// longest literal prefix wins, so a variant whose sentence is a prefix of
    /// another's cannot shadow it.
    /// </summary>
    private static OperatorOwnerRefusalTemplate? Match(string text)
    {
        OperatorOwnerRefusalTemplate? best = null;
        foreach (var template in OperatorScheduleContract.OwnerRefusals)
        {
            if (!text.StartsWith(template.LiteralPrefix, StringComparison.Ordinal)) continue;
            if (best is null || template.LiteralPrefix.Length > best.LiteralPrefix.Length)
            {
                best = template;
            }
        }
        return best;
    }

    /// <summary>
    /// Decodes the owner-issued occurrence projection when the answer carries
    /// one. The answer is treated as untrusted data at a bounded depth, and a
    /// projection this build cannot decode leaves the outcome unverified rather
    /// than guessing at it.
    /// </summary>
    private static UserAutomationScheduleReceipt? FindOwnerSchedule(JsonElement answer)
    {
        var seen = 0;
        return ScanForSchedule(answer, 0, ref seen);
    }

    private static UserAutomationScheduleReceipt? ScanForSchedule(
        JsonElement element,
        int depth,
        ref int seen)
    {
        if (depth > MaxScanDepth || seen > MaxScannedStrings) return null;
        if (element.ValueKind == JsonValueKind.Object)
        {
            seen++;
            if (TryReadOwnerSchedule(element, out var receipt)) return receipt;
            foreach (var property in element.EnumerateObject())
            {
                var found = ScanForSchedule(property.Value, depth + 1, ref seen);
                if (found is not null) return found;
            }
            return null;
        }
        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                var found = ScanForSchedule(item, depth + 1, ref seen);
                if (found is not null) return found;
            }
        }
        return null;
    }

    private static bool TryReadOwnerSchedule(
        JsonElement element,
        out UserAutomationScheduleReceipt receipt)
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
        try
        {
            receipt = UserAutomationScheduleMirror.ReadOwnerSchedule(
                timezone.GetString()!,
                fold.GetString()!,
                gap.GetString()!,
                startAt.GetString()!,
                endAt,
                keys);
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
}
