#!/usr/bin/env python3
"""Generate the pinned IANA zone table consumed by the Kernel UserAutomation
occurrence validator (#2805).

The Kernel must relate an owner-claimed UTC offset and fold/gap disposition to
the *named* zone, at the *claimed* local wall clock, against an exact pinned
time zone database release. A shape check over area directories cannot do that,
and reading the ambient machine locale would let two processes disagree, so the
database is expanded here into a committed, digest-pinned table.

The expansion is a self-contained implementation of the `zic` semantics of the
time zone database: `Zone` lines are walked in order, the named `Rule` sets of
each line are expanded per year, and the result is one closed list of
`(UTC instant, offset-after)` events per zone over an explicit coverage window.

The generator fails closed. Every tzdata construct it does not expand, every
unresolvable `Link`, every coverage violation and every disagreement against the
independent Node.js ICU oracle is a non-zero exit with a named reason, so the
committed table can never silently diverge from the release it claims to carry.

The unit of the offset column is **seconds**, because that is what a `Zone` record
carries and what the Node.js ICU oracle returns. The rendered header declares that
unit explicitly, as `# offset_unit seconds`, and the Kernel refuses a table whose
header does not carry exactly that token: a consumer therefore never has to guess
the unit of the second column, and never has to infer it from the magnitude of a
sample value. An undeclared unit is precisely how this table's seconds were once
read as minutes by the Kernel that consumes it (#2882).

Usage:

    python scripts/gen_user_automation_zone_table.py \
        --tzdb <extracted-tzdata-dir> --release 2026c

The extracted directory must contain the release's own `version` file, and the
claimed release is compared against it before anything else is read.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Pinned inputs and the closed coverage window.
# ---------------------------------------------------------------------------

#: Format tag written into the table header; the Kernel refuses any other one.
TABLE_FORMAT = "eliot.user-automation.zone-table.v1"

#: Unit of the offset column of every body line, written into the table header as
#: `# offset_unit seconds`; the Kernel refuses a table that does not declare
#: exactly this token. The table is written in seconds because that is the unit a
#: `Zone` record carries and the unit the Node.js ICU oracle answers in. The
#: Kernel converts to its own canonical internal unit once, at the parse boundary,
#: and refuses any offset that is not a whole number of that unit, so this token
#: is the only place the wire unit is decided.
TABLE_OFFSET_UNIT = "seconds"

#: The tzdata source files of the default `zcode` `TDATA` build, minus
#: `factory`. `factory` is excluded deliberately: it declares the single
#: `Factory` zone, whose only purpose is to be a noncommittal `TZ` placeholder,
#: so no occurrence may be normalized against it. `backzone` is excluded because
#: it is not part of `TDATA`; its pre-1970 fallback definitions are outside this
#: contract's coverage window in any case.
TZDATA_FILES = (
    "africa",
    "antarctica",
    "asia",
    "australasia",
    "europe",
    "northamerica",
    "southamerica",
    "etcetera",
    "backward",
)

#: Files of the release that are deliberately NOT read: `factory` declares the
#: single `Factory` zone, whose only purpose is to be a noncommittal `TZ`
#: placeholder, so no occurrence may be normalized against it; `backzone` is not
#: part of `TDATA` and carries pre-1970 fallback definitions. They are listed
#: here, and named in the table header, so the omission is a named, reviewable
#: decision rather than a silent one. Every other `.awk`, `.tab`, `.list`,
#: `.html`, `Makefile`, `NEWS`, `README`, `LICENSE`, `SECURITY`, `CONTRIBUTING`
#: and `version` entry of the release is likewise not read.
REFUSED_TZDATA_FILES = ("factory", "backzone")

#: Inclusive first instant of the admitted window: 1970-01-01T00:00:00Z.
WINDOW_START_SECONDS = 0

#: Exclusive last instant of the admitted window: 2100-01-01T00:00:00Z.
WINDOW_END_EXCLUSIVE_SECONDS = 4_102_444_800

#: The stored offset timeline extends this far beyond the admitted window on
#: each side, so resolving an in-window local wall clock to its candidate
#: instants never needs an offset outside the table. Every civil UTC offset the
#: release contains is far smaller than this margin; the generator asserts it.
COVERAGE_MARGIN_SECONDS = 2 * 86_400

TABLE_START_SECONDS = WINDOW_START_SECONDS - COVERAGE_MARGIN_SECONDS
TABLE_END_EXCLUSIVE_SECONDS = WINDOW_END_EXCLUSIVE_SECONDS + COVERAGE_MARGIN_SECONDS

MONTHS = (
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec",
)
MONTH_INDEX = {name: number for number, name in enumerate(MONTHS, start=1)}

#: Weekday tokens and their `zic` index, where Sunday is 0. `zic` numbers
#: weekdays from Sunday, so `Sun>=8` and `lastSun` resolve against this table
#: rather than against a Monday-based index.
WEEKDAY_INDEX = {
    "su": 0, "mo": 1, "tu": 2, "we": 3, "th": 4, "fr": 5, "sa": 6,
}

ZONE_NAME = re.compile(r"[A-Za-z0-9_+/-]{1,64}")

#: The zone the issue's own refuted counterexample names. If this cannot be
#: proven against the oracle then no table closes the issue, so the generator
#: refuses to write one.
ISSUE_EVIDENCE_ZONE = "America/New_York"

#: Zones that MUST be proven against the oracle and admitted, or the generator
#: reports them loudly as withheld. These carry the issue's own evidence and the
#: canonical spellings an owner automation is most likely to declare.
MUST_PROVE_ZONES = (
    "America/New_York",
    "Europe/London",
    "Asia/Kolkata",
    "Australia/Lord_Howe",
    "America/Argentina/Buenos_Aires",
    "Etc/UTC",
    "Etc/GMT-1",
    "EST5EDT",
    "US/Eastern",
)
RULE_SET_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
CIVIL_DURATION = re.compile(r"[+-]?\d{1,2}(:\d{2}){0,2}")
# The repeated minute/second part is non-capturing so that the suffix stays in
# the second group; a capturing group there would silently return the last
# `:mm` fragment instead of the suffix and lose every `s`/`u` clock marker.
AT_CLOCK = re.compile(r"([+-]?\d{1,2}(?::\d{2}){0,2})([suw]?)")
UNTIL_TIME = re.compile(r"[+-]?\d{1,2}(?::\d{2}){0,2}[suw]?")

ON_GE = re.compile(r"([A-Za-z]{3})>=(\d{1,2})")
ON_LE = re.compile(r"([A-Za-z]{3})<=(\d{1,2})")
ON_LAST = re.compile(r"last([A-Za-z]{3})")
ON_DOM = re.compile(r"(\d{1,2})")


class Unexpanded(Exception):
    """A tzdata construct this generator refuses to expand."""


# ---------------------------------------------------------------------------
# Proleptic Gregorian calendar arithmetic, independent of host locale.
# ---------------------------------------------------------------------------


def is_leap(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def days_in_month(year: int, month: int) -> int:
    if month == 2:
        return 29 if is_leap(year) else 28
    return 31 if month in (1, 3, 5, 7, 8, 10, 12) else 30


def days_from_civil(year: int, month: int, day: int) -> int:
    """Days from 1970-01-01 to a proleptic Gregorian civil date."""
    shifted_year = year - 1 if month <= 2 else year
    shifted_month = month + 12 if month <= 2 else month
    era = shifted_year // 400
    year_of_era = shifted_year - era * 400
    month_position = shifted_month - 3
    day_of_year = (153 * month_position + 2) // 5 + day - 1
    day_of_era = year_of_era * 365 + year_of_era // 4 - year_of_era // 100 + day_of_year
    return era * 146_097 + day_of_era - 719_468


def civil_from_days(days: int) -> tuple[int, int, int]:
    """Inverse of [`days_from_civil`], used only to report readable instants."""
    shifted = days + 719_468
    era = shifted // 146_097
    day_of_era = shifted - era * 146_097
    year_of_era = (
        day_of_era - day_of_era // 1460 + day_of_era // 36_524 - day_of_era // 146_096
    ) // 365
    shifted_year = year_of_era + era * 400
    day_of_year = day_of_era - (
        365 * year_of_era + year_of_era // 4 - year_of_era // 100
    )
    month_position = (5 * day_of_year + 2) // 153
    day = day_of_year - (153 * month_position + 2) // 5 + 1
    month = month_position + 3 if month_position < 10 else month_position - 9
    year = shifted_year + 1 if month <= 2 else shifted_year
    return year, month, day


def weekday(days: int) -> int:
    """`zic` weekday index, Sunday = 0, for a count of days from 1970-01-01.

    1970-01-01 was a Thursday, whose `zic` index is 4, so the epoch is offset by
    four rather than by three.
    """
    return (days + 4) % 7


def g_year_of(instant: int) -> int:
    """Proleptic Gregorian year of an absolute instant."""
    return civil_from_days(instant // 86_400)[0]


def parse_hms(text: str) -> int:
    """Parse a signed `hh[:mm[:ss]]` civil duration into seconds."""
    body = text.strip()
    sign = 1
    if body.startswith("-"):
        sign = -1
        body = body[1:]
    elif body.startswith("+"):
        body = body[1:]
    parts = body.split(":")
    if not 1 <= len(parts) <= 3:
        raise Unexpanded(f"unparseable civil duration {text!r}")
    hours = int(parts[0])
    minutes = int(parts[1]) if len(parts) > 1 else 0
    seconds = int(parts[2]) if len(parts) > 2 else 0
    if minutes > 59 or seconds > 59:
        raise Unexpanded(f"unparseable civil duration {text!r}")
    return sign * (hours * 3600 + minutes * 60 + seconds)


def parse_at_clock(text: str) -> tuple[int, str]:
    """Parse a `Rule` AT or `Zone` UNTIL clock into (seconds, suffix)."""
    match = AT_CLOCK.fullmatch(text.strip())
    if match is None:
        raise Unexpanded(f"unparseable civil clock {text!r}")
    return parse_hms(match.group(1)), match.group(2)


# ---------------------------------------------------------------------------
# Parsed tzdata records.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OnSpec:
    """A `Rule` ON or `Zone` UNTIL day specification.

    `kind` is one of `dom` (a day of month), `last` (the last `weekday` of the
    month), `ge` (the first `weekday` on or after `day`), `le` (the last
    `weekday` on or before `day`) or `month_last` (the last day of the month).
    `day` is the day of month, and `weekday` is the `zic` weekday index.
    """

    kind: str
    day: int
    weekday: int


@dataclass(frozen=True)
class Rule:
    name: str
    from_year: int
    to_year: int
    month: int
    on: OnSpec
    at_seconds: int
    at_standard: bool
    at_utc: bool
    save_seconds: int
    order: int


@dataclass(frozen=True)
class UntilSpec:
    year: int
    month: int
    on: OnSpec
    time_seconds: int
    utc: bool


@dataclass(frozen=True)
class Segment:
    """One `Zone` line: a GMT offset, a rule source, and the instant it ends.

    `rule_names` is the named `Rule` set, and `fixed_save_seconds` is the
    alternative `RULES` spelling that supplies a constant daylight saving amount
    for the whole segment. Exactly one of the two is in force.
    """

    gmtoff_seconds: int
    rule_names: tuple[str, ...]
    fixed_save_seconds: int | None
    until: UntilSpec | None


@dataclass
class Zone:
    name: str
    segments: list[Segment] = field(default_factory=list)


def read_records(path: str) -> list[tuple[str, ...]]:
    with open(path, encoding="utf-8") as handle:
        records = []
        for line in handle:
            body = line.split("#", 1)[0].strip()
            if body:
                records.append(tuple(body.split()))
        return records


def on_day_offset(year: int, month: int, on: OnSpec) -> int:
    """Day selected by a `Rule` ON or `Zone` UNTIL day, relative to the 1st.

    The result is a signed day count where `0` is the first of `month`. A
    `<Weekday><=day` specification can select a day of the *preceding* month
    when the named day is at the very start of the month, exactly as `zic`
    reads it, so the offset is allowed to be negative rather than clamped.
    """
    first = days_from_civil(year, month, 1)
    length = days_in_month(year, month)
    if on.kind == "month_last":
        return length - 1
    if on.kind == "last":
        candidate = length
        while weekday(first + candidate - 1) != on.weekday:
            candidate -= 1
        return candidate - 1
    if not 1 <= on.day <= length:
        raise Unexpanded(f"rule day {on.day} is outside {year}-{month:02d}")
    if on.kind == "dom":
        return on.day - 1
    if on.kind == "ge":
        candidate = on.day
        while candidate <= length and weekday(first + candidate - 1) != on.weekday:
            candidate += 1
        # `zic` lets a `>=` specification roll forward into the next month when
        # the month holds no matching weekday at or after the named day.
        if candidate > length + 7:
            raise Unexpanded(
                f"rule day {on.day} selects no weekday in {year}-{month:02d}"
            )
        return candidate - 1
    candidate = on.day
    while weekday(first + candidate - 1) != on.weekday:
        candidate -= 1
        if candidate < -7:
            raise Unexpanded(
                f"rule day {on.day} selects no weekday on or before it in "
                f"{year}-{month:02d}"
            )
    return candidate - 1


def parse_on(text: str) -> OnSpec:
    """Classify a `Rule` ON or `Zone` UNTIL day field.

    The `zic` weekday tokens are `Sun`, `Mon`, ..., each with the two-letter
    abbreviation this table indexes. A form this generator does not expand is
    refused rather than approximated.
    """
    for pattern, kind in ((ON_GE, "ge"), (ON_LE, "le"), (ON_LAST, "last")):
        match = pattern.fullmatch(text)
        if match:
            token = match.group(1)[:2].lower()
            if token not in WEEKDAY_INDEX:
                raise Unexpanded(f"unexpanded Rule ON weekday {text!r}")
            if kind == "last":
                return OnSpec("last", 0, WEEKDAY_INDEX[token])
            return OnSpec(kind, int(match.group(2)), WEEKDAY_INDEX[token])
    match = ON_DOM.fullmatch(text)
    if match:
        return OnSpec("dom", int(match.group(1)), 0)
    raise Unexpanded(f"unexpanded Rule ON form {text!r}")


def parse_rule_set(field: str) -> tuple[tuple[str, ...], int | None]:
    """Read one `RULES` field as either a named rule set or a fixed save.

    The `RULES` column of a `Zone` line is either `-` (no rule), the name of a
    declared `Rule` set, or a signed fixed daylight saving amount that applies
    for the whole segment. The third spelling is what `zic` calls a "constant
    save" segment, and it is expanded as such rather than refused.
    """
    if field == "-":
        return (), None
    if CIVIL_DURATION.fullmatch(field) is not None:
        return (), parse_hms(field)
    if RULE_SET_NAME.fullmatch(field) is not None:
        return (field,), None
    raise Unexpanded(f"unexpanded Zone RULES field {field!r}")


def parse_until(fields: list[str], index: int) -> tuple[UntilSpec, int]:
    """Read one `UNTIL` specification.

    `UNTIL` is `[year][month[day[time]]]`. A missing month or day defaults to
    the first of the month or of the year. A day may be a day of month, a
    `last<Weekday>` or `<Weekday>>=<day>` form, and a time of `24:00` denotes
    midnight of the following day, exactly as `zic` reads it.
    """
    if index >= len(fields):
        raise Unexpanded("a Zone continuation is missing its UNTIL year")
    if re.fullmatch(r"\d{1,4}", fields[index]) is None:
        raise Unexpanded(f"unparseable Zone UNTIL year {fields[index]!r}")
    year = int(fields[index])
    index += 1
    month = 1
    on = OnSpec("dom", 1, 0)
    if index < len(fields) and fields[index][:3].lower() in MONTH_INDEX:
        month = MONTH_INDEX[fields[index][:3].lower()]
        index += 1
        if index >= len(fields):
            # `zic` reads an omitted day as the last day of the month.
            on = OnSpec("month_last", 0, 0)
        else:
            day_text = fields[index]
            if re.fullmatch(r"\d{1,2}", day_text) is not None:
                on = OnSpec("dom", int(day_text), 0)
            else:
                on = parse_on(day_text)
            index += 1
    time_seconds, utc = 0, False
    if index < len(fields):
        match = UNTIL_TIME.fullmatch(fields[index])
        if match is not None:
            time_seconds, suffix = parse_at_clock(fields[index])
            if suffix == "w":
                raise Unexpanded(
                    "a wall-clock (`w`) Zone UNTIL time, whose offset depends on "
                    "the save carried by the preceding rule instance"
                )
            utc = suffix == "u"
            index += 1
    return (UntilSpec(year, month, on, time_seconds, utc), index)


def parse_tzdata(root: str) -> tuple[dict[str, list[Rule]], dict[str, Zone], dict[str, str]]:
    rules: dict[str, list[Rule]] = {}
    zones: dict[str, Zone] = {}
    links: dict[str, str] = {}
    order = 0

    for filename in TZDATA_FILES:
        records = read_records(os.path.join(root, filename))
        index = 0
        while index < len(records):
            fields = records[index]
            kind = fields[0]
            if kind == "Rule":
                if len(fields) not in (9, 10):
                    raise Unexpanded(f"Rule with {len(fields)} fields: {fields}")
                month = MONTH_INDEX.get(fields[5][:3].lower())
                if month is None:
                    raise Unexpanded(f"Rule with unknown month {fields[5]!r}")
                on = parse_on(fields[6])
                at_seconds, at_suffix = parse_at_clock(fields[7])
                if at_suffix == "w":
                    raise Unexpanded(
                        "a wall-clock (`w`) Rule AT time, whose offset depends on "
                        "the save carried by the preceding rule instance"
                    )
                if CIVIL_DURATION.fullmatch(fields[8].strip()) is None:
                    raise Unexpanded(f"non-numeric Rule SAVE amount {fields[8]!r}")
                from_year = int(fields[2])
                to_text = fields[3]
                to_year = (
                    from_year if to_text == "only"
                    else 10 ** 6 if to_text == "max"
                    else int(to_text)
                )
                rules.setdefault(fields[1], []).append(
                    Rule(
                        name=fields[1],
                        from_year=from_year,
                        to_year=to_year,
                        month=month,
                        on=on,
                        at_seconds=at_seconds,
                        # `zic` reads `s` as standard time and `u`/`g`/`z` as
                        # both standard and UT, so a UT clock never carries the
                        # running `save` into its instant.
                        at_standard=at_suffix in ("s", "u"),
                        at_utc=at_suffix == "u",
                        save_seconds=parse_hms(fields[8]),
                        order=order,
                    )
                )
                order += 1
                index += 1
            elif kind == "Zone":
                group, index = parse_zone_group(records, index)
                zone_name, zone_segments = group
                if zone_name in zones:
                    raise Unexpanded(f"zone {zone_name} is declared more than once")
                zones[zone_name] = Zone(zone_name, zone_segments)
            elif kind == "Link":
                # `Link TARGET ALIAS`: the alias names the same zone as the
                # target, and is admitted under the target's whole timeline.
                if len(fields) != 3:
                    raise Unexpanded(f"Link with {len(fields)} fields: {fields}")
                if fields[2] in zones or fields[2] in links:
                    raise Unexpanded(f"link alias {fields[2]} is also a zone")
                links[fields[2]] = fields[1]
                index += 1
            else:
                raise Unexpanded(f"unsupported tzdata record type {kind!r}")
    return rules, zones, links


# ---------------------------------------------------------------------------
# Expansion of one zone into its closed offset timeline.
# ---------------------------------------------------------------------------


def until_spec_utc(segment: Segment) -> bool:
    """Whether a `Zone` UNTIL clock is already UT."""
    return segment.until is not None and segment.until.utc


def until_spec_standard(segment: Segment) -> bool:
    """Whether a `Zone` UNTIL clock is standard rather than wall time.

    `zic` reads a bare UNTIL clock as wall time, and a `u` clock as UT, which
    `outzone` treats as both standard and UT. There is no `s` spelling in the
    data, so a bare clock is wall time.
    """
    return False


def until_instant(segment: Segment, gmtoff: int, save: int) -> int:
    """The UTC instant at which one `Zone` line stops being in effect."""
    spec = segment.until
    assert spec is not None
    offset = on_day_offset(spec.year, spec.month, spec.on)
    naive = (
        (days_from_civil(spec.year, spec.month, 1) + offset) * 86_400
        + spec.time_seconds
    )
    if until_spec_utc(segment):
        return naive
    if not until_spec_standard(segment):
        naive -= save
    return naive - gmtoff


def parse_zone_group(
    records: list[tuple[str, ...]],
    index: int,
) -> tuple[tuple[str, list[Segment]], int]:
    """Read one `Zone` record and its continuation lines into segments.

    A `Zone` record is `Zone NAME GMTOFF RULES FORMAT [UNTIL...]`. Its
    continuation lines are `GMTOFF RULES FORMAT [UNTIL...]`. The last line of a
    group omits both `FORMAT` and `UNTIL`, so the number of trailing tokens is
    what distinguishes a closed line from a final open one.
    """
    head = list(records[index])
    if len(head) < 5:
        raise Unexpanded(f"a Zone record has {len(head)} columns: {' '.join(head)}")
    name = head[1]
    if CIVIL_DURATION.fullmatch(head[2]) is None:
        raise Unexpanded(f"non-numeric Zone GMT offset {head[2]!r} in {' '.join(head)}")
    segments: list[Segment] = []
    rule_names, fixed_save = parse_rule_set(head[3])
    if len(head) == 5:
        # `Zone NAME GMTOFF RULES FORMAT` with no UNTIL is a closed final line.
        segments.append(Segment(parse_hms(head[2]), rule_names, fixed_save, None))
        return (name, segments), index + 1
    # head[4] is the FORMAT column; the UNTIL begins after it.
    until, consumed = parse_until(head, 5)
    if consumed != len(head):
        raise Unexpanded(
            f"unexpanded Zone continuation of {name}: {' '.join(head[consumed:])}"
        )
    segments.append(Segment(parse_hms(head[2]), rule_names, fixed_save, until))
    index += 1
    while index < len(records) and records[index][0] not in ("Zone", "Rule", "Link"):
        line = list(records[index])
        index += 1
        if CIVIL_DURATION.fullmatch(line[0]) is None:
            raise Unexpanded(
                f"non-numeric Zone GMT offset {line[0]!r} in {name}: {' '.join(line)}"
            )
        rule_names, fixed_save = parse_rule_set(line[1])
        if len(line) == 3:
            segments.append(Segment(parse_hms(line[0]), rule_names, fixed_save, None))
            return (name, segments), index
        if len(line) < 4:
            raise Unexpanded(
                f"a Zone continuation of {name} has {len(line)} columns: "
                f"{' '.join(line)}"
            )
        until, consumed = parse_until(line, 3)
        if consumed != len(line):
            raise Unexpanded(
                f"unexpanded Zone continuation of {name}: {' '.join(line[consumed:])}"
            )
        segments.append(Segment(parse_hms(line[0]), rule_names, fixed_save, until))
    return None, index


def expand_zone(
    name: str,
    zone: Zone,
    rules: dict[str, list[Rule]],
) -> list[tuple[int, int]]:
    """Expand one zone into the closed `(instant, offset-after)` list.

    This is the `zic` `outzone` walk, restricted to the offsets:

    - `save` is a running value carried across the whole zone, so a segment
      starts from the daylight saving amount the previous segment left in force.
    - a rule's `AT` clock is wall time unless it carries a suffix, exactly as
      `zic` reads it: a bare value and `w` are wall time, `s` is standard time,
      and `u`/`g`/`z` is UT. The offset subtracted from the wall value is
      therefore `stdoff + save`, `stdoff`, or zero respectively.
    - a segment's `UNTIL` is reduced to UT the same way, with the `save` in
      force when the `UNTIL` is reached.
    - within a year the rule whose transition instant is earliest is applied
      first, and every rule applies for each year of its own `FROM`..`TO` range.
      A rule at or after the segment's `UNTIL` ends the segment.
    - a segment with no rule set carries its `RULES` column, which is either a
      fixed daylight saving amount or nothing at all, for its whole extent.
    """
    events: dict[int, int] = {}
    current: int | None = None
    # The first segment begins at the beginning of time, so the walk starts
    # before the coverage window; the base offset is then resolved at the end.
    boundary = -(1 << 62)
    year_low, year_high = 1969, 2101

    for position, segment in enumerate(zone.segments):
        gmtoff = segment.gmtoff_seconds
        if abs(gmtoff) > COVERAGE_MARGIN_SECONDS:
            raise Unexpanded(
                f"zone {name} standard offset {gmtoff}s is outside the coverage margin"
            )
        last = position == len(zone.segments) - 1
        if last and segment.until is not None:
            raise Unexpanded(f"zone {name} ends with a bounded segment")

        # `zic` restarts `save` at zero for every zone line and only lets that
        # line's own rule set move it, so a segment never inherits a save.
        save = 0
        if segment.fixed_save_seconds is not None:
            save = segment.fixed_save_seconds
            declarations: list[Rule] = []
        else:
            declarations = []
            for rule_name in segment.rule_names:
                found = rules.get(rule_name)
                if found is None:
                    raise Unexpanded(
                        f"Zone RULES names undeclared rule set {rule_name!r}"
                    )
                declarations.extend(found)

        # `zic` reduces a segment's UNTIL to UT with the `save` that is in
        # force at the moment the UNTIL is reached, and recomputes it on every
        # pass of the year walk. A segment that spends part of its extent in
        # daylight saving therefore ends at a different instant than the same
        # spelling under a permanent standard offset would.
        spec_until = None if last else segment.until
        assert spec_until is not None or last

        def segment_end_time(current_save: int) -> int | None:
            if spec_until is None:
                return None
            days = on_day_offset(spec_until.year, spec_until.month, spec_until.on)
            value = (
                (days_from_civil(spec_until.year, spec_until.month, 1) + days)
                * 86_400
                + spec_until.time_seconds
            )
            if not until_spec_utc(segment):
                value -= gmtoff
            if not until_spec_standard(segment):
                value -= current_save
            return value

        until_time = segment_end_time(save)

        def record(instant: int, offset: int) -> None:
            """Apply one offset from `instant` onwards, recording a breakpoint."""
            nonlocal current
            if current != offset:
                events[instant] = offset
            current = offset

        def open_segment(instant: int, offset: int) -> None:
            """Record the offset a segment opens with, even when it is unchanged.

            A segment boundary always states the offset in force from that
            instant. Recording it unconditionally is what makes the offset at
            the start of the coverage window recoverable: a zone whose history
            before the window is one long unchanged run still states the offset
            the window actually begins with.
            """
            nonlocal current
            events[instant] = offset
            current = offset

        if not declarations:
            # No rules: the whole segment is one fixed offset, which is what the
            # offset in force from its start becomes.
            open_segment(boundary, gmtoff + save)
            if not last:
                boundary = until_time if until_time is not None else boundary
            continue

        # A segment with rules opens with the offset its own rules leave in
        # force at its start, which `zic` computes as `z_stdoff + save` where
        # `save` is the save of the last rule instance of THIS line that fires
        # before the boundary. A line that resumes daylight saving partway
        # through therefore opens in daylight time, not in standard time, so the
        # opening entry is deferred until the walk has crossed the boundary.
        opening = True

        # The walk starts a year before the boundary so that an instance in the
        # preceding calendar year can still leave a save in force at the start.
        segment_year = year_low
        if boundary > -(1 << 40):
            segment_year = max(
                segment_year,
                min(year_high, g_year_of(boundary) - 1),
            )
        for year in range(segment_year, year_high + 1):
            pending = [rule for rule in declarations if rule.from_year <= year <= rule.to_year]
            if not pending:
                continue
            # `zic` repeatedly picks the pending rule whose transition instant
            # is earliest, recomputing each candidate's instant with the `save`
            # that is in force at that moment. A candidate therefore has to be
            # re-evaluated after every application, not sorted up front.
            exhausted = False
            while pending:
                walls: list[tuple[int, int, Rule]] = []
                for rule in pending:
                    days = on_day_offset(year, rule.month, rule.on)
                    wall = (
                        (days_from_civil(year, rule.month, 1) + days) * 86_400
                        + rule.at_seconds
                    )
                    base = 0 if rule.at_utc else gmtoff
                    if not rule.at_standard:
                        base += save
                    walls.append((wall - base, rule.order, rule))
                walls.sort(key=lambda item: (item[0], item[1]))
                at, _order, chosen = walls[0]
                # The UNTIL is reduced to UT with the save in force right now.
                until_time = segment_end_time(save)
                if at >= TABLE_END_EXCLUSIVE_SECONDS or (
                    until_time is not None and at >= until_time
                ):
                    exhausted = True
                    break
                if at >= boundary:
                    if opening:
                        open_segment(boundary, gmtoff + save)
                        opening = False
                    # A rule firing exactly at the segment boundary is the one
                    # that opens the segment, so its value is what the segment
                    # opens with and must replace the boundary entry.
                    record(at, gmtoff + chosen.save_seconds)
                save = chosen.save_seconds
                pending = [rule for rule in pending if rule is not chosen]
            if exhausted:
                break
            until_time = segment_end_time(save)
            if until_time is not None:
                # Every remaining year of this segment is past its own end, so
                # the walk stops here rather than running to the horizon.
                next_year_start = (
                    days_from_civil(year + 1, 1, 1) * 86_400
                )
                if next_year_start >= until_time:
                    break

        if opening:
            open_segment(boundary, gmtoff + save)
        if not last:
            boundary = (
                segment_end_time(save)
                if segment_end_time(save) is not None
                else boundary
            )

    if current is None:
        raise Unexpanded(f"zone {name} has no offset inside the coverage window")
    # The first `record` call is always at or before the coverage window, so
    # the base offset is the last breakpoint at or before its start.
    base = None
    for at in sorted(events):
        if at <= TABLE_START_SECONDS:
            base = events[at]
    if base is None:
        raise Unexpanded(f"zone {name} has no offset at the coverage window start")
    merged: dict[int, int] = {TABLE_START_SECONDS: base}
    for at, offset in events.items():
        if TABLE_START_SECONDS < at < TABLE_END_EXCLUSIVE_SECONDS:
            merged[at] = offset
    for at, offset in merged.items():
        if abs(offset) > COVERAGE_MARGIN_SECONDS:
            raise Unexpanded(
                f"zone {name} offset {offset}s at {at}s is outside the coverage margin"
            )
    return sorted(merged.items())


# ---------------------------------------------------------------------------
# Table emission.
# ---------------------------------------------------------------------------


def render_table(
    release: str,
    timelines: dict[str, list[tuple[int, int]]],
    withheld: dict[str, str],
    oracle_identity: str,
    comparisons: int,
) -> bytes:
    """Render the committed table, including the withheld-zone record.

    A zone whose expansion cannot be proven byte-exact against the independent
    oracle is NOT emitted. The header names every withheld zone and why, so the
    omission is a reviewable, machine-readable decision rather than a silent
    one, and so a schedule naming a withheld zone is refused as unknown rather
    than resolved from a guess.

    The header also declares the unit of the offset column, exactly once. The
    emitted table is re-read here to prove the declaration is present and
    unambiguous, because the Kernel requires that token before it will read a
    single offset, and a missing or repeated declaration would either refuse
    every lookup or leave the required token ambiguous.
    """
    zones = sorted(timelines)
    transition_count = sum(len(timelines[zone]) - 1 for zone in zones)
    reasons = sorted(set(withheld.values()))
    unit_declaration = f"# offset_unit {TABLE_OFFSET_UNIT}"
    lines = [
        f"# format {TABLE_FORMAT}",
        unit_declaration,
        f"# release {release}",
        "# source_files " + " ".join(TZDATA_FILES),
        "# refused_source_files " + " ".join(REFUSED_TZDATA_FILES),
        f"# oracle {oracle_identity}",
        f"# oracle_comparisons {comparisons}",
        "# window_start_utc 1970-01-01T00:00:00Z",
        "# window_end_exclusive_utc 2100-01-01T00:00:00Z",
        f"# window_start_seconds {WINDOW_START_SECONDS}",
        f"# window_end_exclusive_seconds {WINDOW_END_EXCLUSIVE_SECONDS}",
        f"# table_start_seconds {TABLE_START_SECONDS}",
        f"# table_end_exclusive_seconds {TABLE_END_EXCLUSIVE_SECONDS}",
        f"# zone_count {len(zones)}",
        f"# transition_count {transition_count}",
        f"# withheld_zone_count {len(withheld)}",
    ]
    for reason in reasons:
        names = sorted(n for n, r in withheld.items() if r == reason)
        lines.append(f"# withheld {reason} {len(names)} " + " ".join(names))
    lines.append(f"# withheld_total {len(withheld)}")
    declared = [line for line in lines if line.startswith("# offset_unit")]
    assert declared == [unit_declaration], (
        f"the rendered table must declare its offset unit exactly once as "
        f"{unit_declaration!r}, found {declared!r}"
    )
    for zone in zones:
        lines.append(f"Z {zone}")
        for at, offset in timelines[zone]:
            lines.append(f"{at} {offset}")
    return ("\n".join(lines) + "\n").encode("utf-8")


# ---------------------------------------------------------------------------
# Independent oracle: Node.js ICU, over a line protocol on one process.
# ---------------------------------------------------------------------------

ORACLE_SCRIPT = r"""
'use strict';
const readline = require('readline');
const formatters = new Map();
function formatter(zone) {
  let f = formatters.get(zone);
  if (f === undefined) {
    try {
      f = new Intl.DateTimeFormat('en-US', {
        timeZone: zone,
        hourCycle: 'h23',
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
      });
      f.formatToParts(new Date(0));
    } catch (e) {
      f = null;
    }
    formatters.set(zone, f);
  }
  return f;
}
function offsetSeconds(f, epochMs) {
  const parts = {};
  for (const p of f.formatToParts(new Date(epochMs))) parts[p.type] = p.value;
  const asUtc = Date.UTC(
    Number(parts.year), Number(parts.month) - 1, Number(parts.day),
    Number(parts.hour) % 24, Number(parts.minute), Number(parts.second),
  );
  return Math.round((asUtc - epochMs) / 1000);
}
const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  if (line.length === 0) return;
  const request = JSON.parse(line);
  const f = formatter(request.zone);
  if (f === null) {
    process.stdout.write(JSON.stringify({ resolved: false, offsets: [] }) + '\n');
    return;
  }
  const offsets = request.points.map((p) => offsetSeconds(f, p * 1000));
  process.stdout.write(JSON.stringify({ resolved: true, offsets }) + '\n');
});
process.stdout.write(JSON.stringify({
  identity: 'node-intl-icu', node: process.version, icu: process.versions.icu,
}) + '\n');
"""


class Oracle:
    """A single Node.js ICU process answering one zone-offset request at a time."""

    def __init__(self, node: str) -> None:
        import tempfile

        self.script = os.path.join(
            tempfile.gettempdir(), "eliot-tzdb-oracle-icu.js"
        )
        with open(self.script, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(ORACLE_SCRIPT)
        self.process = subprocess.Popen(
            [node, self.script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        if self.process.stdout is None or self.process.stdin is None:
            raise SystemExit("oracle: could not open the Node.js pipes")
        identity = json.loads(self.process.stdout.readline())
        self.node = identity["node"]
        self.icu = identity["icu"]

    def offsets(self, zone: str, points: list[int]) -> list[int] | None:
        if self.process.stdin is None or self.process.stdout is None:
            raise SystemExit("oracle: pipe closed")
        self.process.stdin.write(json.dumps({"zone": zone, "points": points}) + "\n")
        self.process.stdin.flush()
        answer = json.loads(self.process.stdout.readline())
        if not answer["resolved"]:
            return None
        return answer["offsets"]

    def close(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()
        self.process.wait()


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tzdb", required=True, help="extracted tzdata directory")
    parser.add_argument("--release", required=True, help="claimed release id")
    parser.add_argument(
        "--out",
        default=os.path.join(
            "crates", "kernel", "eliot-kernel-core", "src",
            "user_automation_zone_table.tzd",
        ),
        help="output table path",
    )
    parser.add_argument("--node", default="node", help="Node.js executable")
    args = parser.parse_args(argv)

    version_path = os.path.join(args.tzdb, "version")
    if not os.path.isfile(version_path):
        print(f"refused: {version_path} is missing", file=sys.stderr)
        return 2
    with open(version_path, encoding="utf-8") as handle:
        found_release = handle.read().strip()
    if found_release != args.release:
        print(
            f"refused: extracted tzdata version is {found_release!r}, not the "
            f"claimed release {args.release!r}",
            file=sys.stderr,
        )
        return 2
    for missing in TZDATA_FILES:
        if not os.path.isfile(os.path.join(args.tzdb, missing)):
            print(
                f"refused: {missing} is missing from {args.tzdb}; this table is "
                f"built only from a complete {args.release} extraction",
                file=sys.stderr,
            )
            return 2

    try:
        rules, zones, links = parse_tzdata(args.tzdb)
    except Unexpanded as error:
        print(f"refused: unexpanded construct: {error}", file=sys.stderr)
        return 3

    timelines: dict[str, list[tuple[int, int]]] = {}
    try:
        for name in sorted(zones):
            timeline = expand_zone(name, zones[name], rules)
            if timeline:
                timelines[name] = timeline
        for alias in sorted(links):
            target = links[alias]
            if target not in timelines:
                raise Unexpanded(f"Link {alias} targets undefined zone {target}")
            timelines[alias] = timelines[target]
    except Unexpanded as error:
        print(f"refused: unexpanded construct: {error}", file=sys.stderr)
        return 3

    for name in sorted(timelines):
        if ZONE_NAME.fullmatch(name) is None:
            print(f"refused: non-canonical zone identity {name!r}", file=sys.stderr)
            return 3

    # ---- independent oracle cross-check, and prove-or-withhold -----------
    # A zone is admitted only when an independent implementation of the same
    # IANA data agrees with it byte-exactly across the whole coverage window. A
    # zone the oracle cannot resolve, or with which it disagrees anywhere, is
    # withheld and named in the table header. Nothing is ever admitted on the
    # strength of its spelling.
    names = sorted(timelines)
    year_points = []
    for year in range(1970, 2100):
        year_points.append(days_from_civil(year, 1, 1) * 86_400)
        year_points.append(days_from_civil(year, 7, 1) * 86_400)

    oracle = Oracle(args.node)
    admitted: dict[str, list[tuple[int, int]]] = {}
    withheld: dict[str, str] = {}
    comparisons = 0
    transition_total = 0
    disagreement_total = 0
    unresolvable: list[str] = []
    disagreement_sample: list[str] = []

    for name in names:
        timeline = timelines[name]
        points = {TABLE_START_SECONDS, TABLE_END_EXCLUSIVE_SECONDS - 1}
        points.update(year_points)
        for at, _offset in timeline[1:]:
            points.update((at - 1, at, at + 1))
        ordered = sorted(
            p for p in points if TABLE_START_SECONDS <= p < TABLE_END_EXCLUSIVE_SECONDS
        )
        reported = oracle.offsets(name, ordered)
        if reported is None:
            unresolvable.append(name)
            withheld[name] = "oracle-unresolvable"
            continue
        if len(reported) != len(ordered):
            print(
                f"refused: oracle returned {len(reported)} offsets for {name}, "
                f"expected {len(ordered)}",
                file=sys.stderr,
            )
            oracle.close()
            return 5
        comparisons += len(ordered)
        base = timeline[0][1]
        mismatches = 0
        for point, expected in zip(ordered, reported):
            actual = base
            for at, offset in timeline:
                if at > point:
                    break
                actual = offset
            if actual != expected:
                mismatches += 1
                if len(disagreement_sample) < 20:
                    disagreement_sample.append(
                        f"{name} at instant {point} "
                        f"(utc-offset-seconds table={actual} oracle={expected})"
                    )
        if mismatches:
            disagreement_total += mismatches
            withheld[name] = "oracle-disagreement"
            continue
        admitted[name] = timeline
        transition_total += len(timeline) - 1
    oracle.close()

    print(
        f"oracle identity=node-intl-icu node={oracle.node} icu={oracle.icu} "
        f"candidate_zones={len(names)} admitted_zones={len(admitted)} "
        f"withheld_zones={len(withheld)} admitted_transitions={transition_total} "
        f"comparisons={comparisons} disagreements={disagreement_total} "
        f"unresolvable={len(unresolvable)}"
    )
    for line in disagreement_sample:
        print(f"oracle-disagreement {line} (offset-seconds)", file=sys.stderr)

    # `America/New_York` is the zone the issue's own counterexample names, so a
    # table that cannot prove it does not close the issue and is a hard stop.
    if ISSUE_EVIDENCE_ZONE not in admitted:
        print(
            f"refused: {ISSUE_EVIDENCE_ZONE} could not be proven against the "
            f"oracle ({withheld.get(ISSUE_EVIDENCE_ZONE, 'unknown')}), so no "
            f"table is written",
            file=sys.stderr,
        )
        return 6

    # Every other required zone that could not be proven is named loudly. It is
    # withheld, so a schedule declaring it is refused as an unknown zone rather
    # than resolved from a guess.
    unproven = [name for name in MUST_PROVE_ZONES if name not in admitted]
    if unproven:
        print(
            "REQUIRED-ZONE-WITHHELD: these required zones are NOT admitted "
            "because the independent oracle does not confirm them: "
            + " ".join(unproven),
            file=sys.stderr,
        )
        for name in unproven:
            print(
                f"REQUIRED-ZONE-WITHHELD {name} reason={withheld.get(name, 'unknown')}",
                file=sys.stderr,
            )

    # The table is written in seconds, and the Kernel's own canonical internal
    # unit is minutes, so a zone whose pinned timeline carries an offset that is
    # not a whole number of minutes cannot be answered by the Kernel without
    # truncating it. The Kernel refuses such a zone rather than truncating, so the
    # generator names them here: an operator reading this output learns from the
    # generator which zones the pinned release can express in the canonical unit.
    sub_minute = sorted(
        name
        for name, timeline in admitted.items()
        if any(offset % 60 != 0 for _at, offset in timeline)
    )
    if ISSUE_EVIDENCE_ZONE in sub_minute:
        print(
            f"refused: {ISSUE_EVIDENCE_ZONE} carries a sub-minute offset, so the "
            f"Kernel cannot answer it in its canonical unit without truncating",
            file=sys.stderr,
        )
        return 7
    if sub_minute:
        print(
            "SUB-MINUTE-ZONE: these admitted zones carry a UTC offset that is not "
            "a whole number of minutes, so the Kernel refuses them by name and "
            "never truncates the offset: " + " ".join(sub_minute),
            file=sys.stderr,
        )

    payload = render_table(
        args.release,
        admitted,
        withheld,
        f"node-intl-icu node={oracle.node} icu={oracle.icu}",
        comparisons,
    )
    with open(args.out, "wb") as handle:
        handle.write(payload)
    print(
        f"wrote {args.out} bytes={len(payload)} "
        f"sha256={hashlib.sha256(payload).hexdigest()} "
        f"offset_unit={TABLE_OFFSET_UNIT} "
        f"zones={len(admitted)} transitions={transition_total} "
        f"withheld={len(withheld)} "
        f"sub_minute_zones={len(sub_minute)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
