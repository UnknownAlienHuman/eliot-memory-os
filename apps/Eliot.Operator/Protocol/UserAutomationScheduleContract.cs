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
            $"{Timezone}@{ZoneDatabaseRevision} local {Local} offset {Offset} instant {Instant} disposition {Disposition} transition {transition} source_digest {SourceDigest} record [{Record}]");
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
    /// names the contract version and pinned database release carried by the
    /// parsed revision bytes, so the UI never needs a second copy of either.
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
    /// recorded local wall clock. This is arithmetic over the supplied record bytes —
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
    /// Checks only the locally provable relation between source fields and
    /// source digests for an edit. It cannot establish fresh owner evidence.
    /// </summary>
    /// <remarks>
    /// The owner source digest is a hash of expression and calendar only. This
    /// method rejects reusing the prior digest after either source field changes
    /// and rejects changing the digest when both source fields stay the same.
    /// A zone, DST policy, interval or occurrence change may validly retain the
    /// same digest; whether that effect-relevant edit has fresh normalization
    /// evidence cannot be decided here. The Operator cannot recompute the source
    /// hash or prove provenance, so those freshness checks remain for the owner
    /// and Kernel until a bound owner receipt exists.
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
        var sameDigest = string.Equals(
            previousReceipt.SourceDigest, nextReceipt.SourceDigest, StringComparison.Ordinal);
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
    UserAutomationScheduleReceipt? Receipt);

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
    private const int MaxTypedEnvelopeChars = 8_192;
    private const int MaxIdentityChars = 256;
    // The Kernel's bounded idempotency key is prefixed in operation_id.
    private const int MaxOperationIdChars = 320;
    private const int MaxRefusalFieldChars = 256;
    private const int MaxRecoveryReasonChars = 1_024;
    private const int MaxScheduleScanDepth = 6;
    private const int MaxScheduleScannedObjects = 64;
    // Bound summary text; the retained response remains available separately.
    private const int MaxDescribedOccurrences = 8;
    /// <summary>Decodes one owner answer for one typed operation identity.</summary>
    public static UserAutomationOutcome Read(
        string action,
        JsonElement answer,
        string expectedIdempotencyKey)
    {
        ArgumentNullException.ThrowIfNull(action);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedIdempotencyKey);
        if (answer.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
        {
            return OwnerAbsent(action, "the owner route returned no result payload.");
        }

        if (answer.ValueKind != JsonValueKind.Object)
        {
            return UnverifiedOwnerAnswer(action, "the owner answer is not one JSON object");
        }

        if (answer.TryGetProperty("status", out _))
        {
            if (!TryReadBoundedText(answer, "status", 32, out var statusText))
            {
                return UnverifiedOwnerAnswer(action, "the typed owner status is malformed");
            }

            if (string.Equals(statusText, "unknown", StringComparison.Ordinal))
            {
                return ReadUnknownEnvelope(action, answer, expectedIdempotencyKey);
            }

            if (string.Equals(statusText, "known", StringComparison.Ordinal))
            {
                // Known owner transitions can carry a full bounded schedule
                // projection. Do not apply the much smaller refusal-envelope
                // size limit to this successful result.
                return ReadKnownEnvelope(action, answer);
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
                Receipt: null);
        }

        return new UserAutomationOutcome(
            UserAutomationOutcomeClass.UnverifiedOwnerAnswer,
            $"UserAutomation {action} answered — schedule not verified",
            "the owner answered this typed operation but this answer carries no decodable "
            + $"{OperatorScheduleContract.NORMALIZED_OCCURRENCE_ENCODING} occurrence projection, "
            + "so the Operator does not report the schedule as normalized",
            RefusalKind: null,
            RefusalText: null,
            Receipt: null);
    }

    private static UserAutomationOutcome ReadKnownEnvelope(string action, JsonElement answer)
    {
        if (!HasExactProperties(answer, "status", "value", "recovery")
            || !TryReadBoundedText(answer, "status", 32, out var status)
            || !string.Equals(status, "known", StringComparison.Ordinal)
            || !TryGetObject(answer, "value", out var value)
            || !answer.TryGetProperty("recovery", out var recovery)
            || recovery.ValueKind != JsonValueKind.Null)
        {
            return UnverifiedOwnerAnswer(action, "the known owner transition is not a closed, settled typed shape");
        }

        // A pre-Store runtime-channel rejection uses this separate closed
        // shape. It explains this attempt but cannot settle a retained retry.
        if (HasExactProperties(value, "accepted", "outcome", "reason")
            && value.TryGetProperty("accepted", out var accepted)
            && accepted.ValueKind == JsonValueKind.False
            && TryReadBoundedText(value, "outcome", 64, out var outcome)
            && string.Equals(outcome, "rejected", StringComparison.Ordinal)
            && TryReadBoundedText(value, "reason", MaxRecoveryReasonChars, out var reason))
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
                Receipt: null);
        }

        if (HasExactProperties(value, "accepted", "outcome")
            && value.TryGetProperty("accepted", out var identityAccepted)
            && identityAccepted.ValueKind == JsonValueKind.False
            && TryReadBoundedText(value, "outcome", 64, out var identityOutcome)
            && string.Equals(identityOutcome, "identity_conflict", StringComparison.Ordinal))
        {
            return new UserAutomationOutcome(
                UserAutomationOutcomeClass.OwnerRefused,
                $"UserAutomation {action} identity conflict on this attempt — reconcile the operation",
                "The owner rejected this attempt before Store because the request identity or State Fence did not match the authenticated owner session. "
                + "An earlier attempt under this same identity may still have committed. Action: establish a fresh authenticated owner session with the matching identity and State Fence, "
                + "then reconcile this same operation before any new submission.",
                "identity_conflict",
                RefusalText: null,
                Receipt: null);
        }

        if (!HasUserAutomationTransitionProperties(value))
        {
            return UnverifiedOwnerAnswer(action, "the known owner result has an unsupported value shape");
        }

        var projection = FindScheduleProjection(answer);
        if (projection is not null)
        {
            return new UserAutomationOutcome(
                UserAutomationOutcomeClass.UnverifiedOwnerAnswer,
                $"UserAutomation {action} answered — schedule normalization unverified",
                "The owner returned a settled transition. "
                + DescribeUnverifiedScheduleProjection(projection),
                RefusalKind: null,
                RefusalText: null,
                Receipt: null);
        }

        return new UserAutomationOutcome(
            UserAutomationOutcomeClass.UnverifiedOwnerAnswer,
            $"UserAutomation {action} answered — schedule not verified",
            "the owner answered this typed operation but this answer carries no decodable "
            + $"{OperatorScheduleContract.NORMALIZED_OCCURRENCE_ENCODING} occurrence projection, "
            + "so the Operator does not report the schedule as normalized",
            RefusalKind: null,
            RefusalText: null,
            Receipt: null);
    }

    private static UserAutomationOutcome ReadUnknownEnvelope(
        string action,
        JsonElement answer,
        string expectedIdempotencyKey)
    {
        if (!HasExactProperties(answer, "status", "value", "recovery")
            || !TryReadBoundedText(answer, "status", 32, out var status)
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
            return ReadAttemptRefusal(action, value, recovery, expectedIdempotencyKey);
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
                Receipt: null);
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
                Receipt: null);
        }

        if (HasUserAutomationTransitionProperties(value)
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
                    Receipt: null);
            }

            return UnverifiedOwnerAnswer(
                action,
                $"the owner transition remains unknown ({transitionRecoveryKind}): {transitionRecoveryReason}");
        }

        return UnverifiedOwnerAnswer(action, "the unknown-outcome envelope has an unsupported value or recovery shape");
    }

    private static bool HasUserAutomationTransitionProperties(JsonElement value) =>
        HasExactProperties(
            value,
            "identity",
            "state_fence",
            "configuration",
            "wake",
            "horizon",
            "execution",
            "occurrences");

    private static UserAutomationOutcome ReadAttemptRefusal(
        string action,
        JsonElement value,
        JsonElement recovery,
        string expectedIdempotencyKey)
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
            || !MatchesOperationIdentity(operation, expectedIdempotencyKey)
            || !TryGetObject(value, "state_fence", out var stateFence)
            || !IsClosedStateFence(stateFence)
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
            Receipt: null);
    }

    private static bool MatchesOperationIdentity(JsonElement operation, string expectedIdempotencyKey)
    {
        if (!HasExactProperties(operation, "operation_id", "request_id", "idempotency_key")
            || !TryReadBoundedText(operation, "operation_id", MaxOperationIdChars, out var operationId)
            || !TryReadBoundedText(operation, "request_id", MaxIdentityChars, out _)
            || !TryReadBoundedText(operation, "idempotency_key", MaxIdentityChars, out var idempotencyKey))
        {
            return false;
        }

        // RequestId is minted inside the authenticated Kernel route and is
        // correlated by the pipe response; the Operator cannot independently
        // derive it. The two identities it does hold are exact: the pending
        // operation ID is the request idempotency key, and Kernel prefixes that
        // key when it returns its operation ID.
        return string.Equals(idempotencyKey, expectedIdempotencyKey, StringComparison.Ordinal)
            && string.Equals(
                operationId,
                $"user-automation-operation:{expectedIdempotencyKey}",
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
                $"Action: re-normalize under {OperatorScheduleContract.NORMALIZED_OCCURRENCE_ENCODING} and submit a new immutable revision; do not rewrite the existing revision.",
            "legacy_encoding" =>
                "Action: run the owner re-normalization or migration path and submit a NEW immutable revision; the Operator never rewrites a revision in place.",
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
            Receipt: null);

    /// <summary>
    /// Explains why the decoded occurrence fields are inspection data rather
    /// than owner-issued normalization evidence, then shows a bounded summary.
    /// </summary>
    private static string DescribeUnverifiedScheduleProjection(UserAutomationScheduleReceipt projection) =>
        $"A decodable {OperatorScheduleContract.NORMALIZED_OCCURRENCE_ENCODING} occurrence projection is shown for inspection, "
        + "but this response carries no owner-issued normalization receipt or provenance. Its freshness and relationship to "
        + "effect-relevant schedule fields are unverified; the Operator does not report it as normalized.\n"
        + DescribeScheduleProjection(projection);

    /// <summary>
    /// Summarizes the parsed projection's contract identity and occurrence
    /// details without asserting who normalized the underlying bytes.
    /// </summary>
    private static string DescribeScheduleProjection(UserAutomationScheduleReceipt projection)
    {
        var builder = new StringBuilder(projection.ContractIdentity());
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

    /// <summary>
    /// Decodes a versioned occurrence projection when the answer carries one.
    /// The answer is treated as untrusted data at a bounded depth; decoding it
    /// provides inspection details, not proof of normalization provenance.
    /// </summary>
    private static UserAutomationScheduleReceipt? FindScheduleProjection(JsonElement answer)
    {
        var seen = 0;
        return ScanForScheduleProjection(answer, 0, ref seen);
    }

    private static UserAutomationScheduleReceipt? ScanForScheduleProjection(
        JsonElement element,
        int depth,
        ref int seen)
    {
        if (depth > MaxScheduleScanDepth || seen > MaxScheduleScannedObjects) return null;
        if (element.ValueKind == JsonValueKind.Object)
        {
            seen++;
            if (TryReadScheduleProjection(element, out var projection)) return projection;
            foreach (var property in element.EnumerateObject())
            {
                var found = ScanForScheduleProjection(property.Value, depth + 1, ref seen);
                if (found is not null) return found;
            }
            return null;
        }
        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                var found = ScanForScheduleProjection(item, depth + 1, ref seen);
                if (found is not null) return found;
            }
        }
        return null;
    }

    private static bool TryReadScheduleProjection(
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
