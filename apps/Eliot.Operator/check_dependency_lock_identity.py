#!/usr/bin/env python3
"""Value-compare a requested NuGet version with the committed dependency lock (#1137).

`apps/Eliot.Operator/Eliot.Operator.csproj` pins `Microsoft.WindowsAppSDK` in two
committed files: the `PackageReference` in the project file, and the resolved
graph in `apps/Eliot.Operator/packages.lock.json`. Nothing in the release path
compares those two values. `scripts/write-operator-build-receipt.ps1` records the
version the project requested, and `Get-VerifiedOperatorBuildReceipt` in
`scripts/build-eliot-windows-x64-release.ps1` re-reads that same requested version
from the project and compares the receipt against it; the lock itself is bound by
SHA-256 alone. A lock that was never regenerated for a version bump, or that was
edited by hand, therefore agrees with every receipt check while the published
binary carries a different Windows App SDK runtime than the project, the README
and the receipt all name. This checker owns that one missing value comparison, and
the MSBuild target `CheckOperatorWindowsAppSdkLockIdentity` runs it on every build
before `CoreCompile`, so the drift fails the build instead of the release.

Usage:

    python apps/Eliot.Operator/check_dependency_lock_identity.py \
        --lock apps/Eliot.Operator/packages.lock.json \
        --package Microsoft.WindowsAppSDK --requested 2.3.1

    # exit 0, the build gate passes; exit 1, the versions disagree; exit 2, an
    # input could not be read, parsed or interpreted

The comparison is offline and read-only. Only the two committed files are opened;
no network request, NuGet cache, restore output or `project.assets.json` is read,
and the lock is never regenerated, rewritten or reformatted - NuGet owns that, and
a hand-edited lock is what this gate exists to reject.

Both committed NuGet lock shapes are read without assuming a key. The
`dependencies` section is walked because its keys are the target-framework
monikers the restore actually produced, and the later `packages` section, whose
keys are `id/version`, is walked too. Package identity is matched exactly, or
case-insensitively on the `id` part of a `packages` key, so a same-prefixed
sibling such as `Microsoft.WindowsAppSDK.WinUI` can never satisfy or fail this
gate. A direct entry is the project's own request and is authoritative; when the
graph records identity only in `packages`, the requested version must still be
one of the recorded versions for that exact id.

The check fails closed with a named reason and a distinct exit code: an absent
lock entry, a disagreement between the requested and resolved versions, and an
unreadable or uninterpretable input are three different defects, and none of them
is reported as a pass. Every run writes exactly one `condition=` summary line to
stdout, because the MSBuild target names that line in its build error; the
human-readable detail goes to stderr.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass

#: Exit codes, one per defect. They are the checker's typed surface: the MSBuild
#: target refuses any non-zero code, and a human reading a log can tell the three
#: failures apart from the code alone.
EXIT_AGREED = 0
EXIT_DISAGREED = 1
EXIT_REFUSED = 2

#: The `type` value NuGet writes for a project-requested package in the
#: `dependencies` section, and in the later `packages` section respectively.
DIRECT_DEPENDENCY_TYPE = "Direct"
DIRECT_PACKAGE_TYPE = "direct"

#: A single exact package version. A range, a floating wildcard or a bare
#: comparison cannot be value-compared with a resolved version, and a project that
#: requests one has no identity for the lock to agree with, so the regex refuses
#: it instead of guessing which version inside the range was meant.
EXACT_VERSION = re.compile(
    r"^\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?$"
)


class Refused(Exception):
    """A committed input does not say which version the lock binds."""


@dataclass(frozen=True)
class Occurrence:
    """One place in the lock where the package's resolved version is recorded."""

    location: str
    version: str
    direct: bool


def read_lock(path: str) -> dict:
    """Read the committed lock as JSON, byte-faithfully to what NuGet wrote."""
    try:
        with open(path, encoding="utf-8-sig") as handle:
            document = json.load(handle)
    except OSError as error:
        raise Refused(f"{path} could not be read: {error}")
    except ValueError as error:
        raise Refused(f"{path} is not valid JSON: {error}")
    if not isinstance(document, dict):
        raise Refused(f"{path} does not hold a JSON object at its root")
    return document


def collapse(text: str) -> str:
    """Fold a message onto one line, so a refusal reason stays a single record."""
    return " ".join(text.split())


def version_text(value: object) -> str | None:
    """A version recorded in the lock, or None when the field is not a version."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def read_occurrences(document: dict, package: str) -> list[Occurrence]:
    """Every place the committed lock records a resolved version of `package`.

    `dependencies` is walked as the section NuGet writes for the graph of each
    target it restored, and `packages` is walked for the later lock format whose
    keys carry `id/version`. Only exact package identities are collected, so the
    Windows App SDK sub-packages cannot be mistaken for the package itself.
    """
    found: list[Occurrence] = []

    dependencies = document.get("dependencies", {})
    if not isinstance(dependencies, dict):
        raise Refused("the lock 'dependencies' section is not a JSON object")
    for target, packages in dependencies.items():
        if not isinstance(packages, dict):
            continue
        for identity, entry in packages.items():
            if identity != package or not isinstance(entry, dict):
                continue
            version = version_text(entry.get("resolved"))
            if version is None:
                raise Refused(
                    f"the lock entry dependencies.{target}.{identity} records no "
                    "string 'resolved' version"
                )
            found.append(
                Occurrence(
                    location=f"dependencies.{target}.{identity}",
                    version=version,
                    direct=entry.get("type") == DIRECT_DEPENDENCY_TYPE,
                )
            )

    sections = document.get("packages")
    if sections is None:
        return found
    if not isinstance(sections, dict):
        raise Refused("the lock 'packages' section is not a JSON object")
    wanted = package.lower()
    for key, entry in sections.items():
        if not isinstance(key, str) or key.count("/") != 1:
            continue
        identity, _, version = key.partition("/")
        if identity.lower() != wanted:
            continue
        recorded = version_text(version)
        if recorded is None:
            raise Refused(f"the lock 'packages' key {key} records no version")
        found.append(
            Occurrence(
                location=f"packages.{key}",
                version=recorded,
                direct=isinstance(entry, dict) and entry.get("type") == DIRECT_PACKAGE_TYPE,
            )
        )
    return found


def bound_version(occurrences: list[Occurrence]) -> tuple[str, list[str]]:
    """The one version the lock binds for the package, and where it is recorded.

    A direct entry is the project's own request, so it decides. Only a graph with
    no direct entry falls back to the recorded package keys. Occurrences that
    disagree with each other are a contradiction in the committed lock, not
    something to average or pick from.
    """
    direct = [occurrence for occurrence in occurrences if occurrence.direct]
    binding = direct or occurrences
    versions = sorted({occurrence.version for occurrence in binding})
    if len(versions) != 1:
        raise Refused(
            "the committed lock records contradictory versions for this package: "
            + "; ".join(
                f"{occurrence.version} at {occurrence.location}"
                for occurrence in binding
            )
        )
    return versions[0], [occurrence.location for occurrence in binding]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--lock",
        required=True,
        help="path of the committed packages.lock.json",
    )
    parser.add_argument(
        "--package",
        default="Microsoft.WindowsAppSDK",
        help="package identity whose requested and locked versions are compared",
    )
    parser.add_argument(
        "--requested",
        required=True,
        help="exact version the project requests for that package",
    )
    args = parser.parse_args(argv)

    # One machine-facing summary line carries the condition and the exact
    # observed values, and always goes to stdout, because the MSBuild target
    # names it in the build error. The human-readable detail goes to stderr.
    def summary(condition: str, **fields: str) -> None:
        print(
            "dependency-lock-identity condition="
            + condition
            + " package="
            + args.package
            + " "
            + " ".join(f"{key}={value}" for key, value in fields.items())
        )

    package = args.package
    requested = version_text(args.requested)
    if requested is None:
        summary("NO_REQUESTED_VERSION", requested="<none>")
        print(
            "refused: the build passed no requested version, so the project "
            "declares no exact PackageReference version to compare with the lock",
            file=sys.stderr,
        )
        return EXIT_REFUSED
    if not EXACT_VERSION.match(requested):
        summary("NOT_AN_EXACT_VERSION", requested=requested, locked="<none>")
        print(
            "stale: the project requests a range or floating version, which "
            "carries no identity for the committed lock to agree with; request "
            "one exact version",
            file=sys.stderr,
        )
        return EXIT_DISAGREED

    try:
        document = read_lock(args.lock)
        occurrences = read_occurrences(document, package)
        if not occurrences:
            raise Refused(
                f"the lock holds no entry for {package} (lock: {args.lock}); the "
                "lock does not describe the packages this project requests"
            )
        locked, locations = bound_version(occurrences)
    except Refused as error:
        summary("INPUT_UNUSABLE", requested=requested, reason=collapse(str(error)))
        print(f"refused: {error}", file=sys.stderr)
        return EXIT_REFUSED

    location = collapse(";".join(locations))
    if locked != requested:
        summary("VERSION_MISMATCH", requested=requested, locked=locked, lock=location)
        print(
            f"stale: the project requests {package} {requested}, but the "
            f"committed lock resolves it to {locked}",
            file=sys.stderr,
        )
        print(f"  lock: {args.lock} at {location}", file=sys.stderr)
        print(
            "  the lock was not regenerated for the requested version, or it was "
            "hand-edited; run 'dotnet restore "
            "apps/Eliot.Operator/Eliot.Operator.csproj' so NuGet rewrites the "
            "lock from the requested version, review the lock diff, and commit it "
            "with the project change. Do not hand-edit packages.lock.json.",
            file=sys.stderr,
        )
        return EXIT_DISAGREED

    print(
        f"ok: dependency-lock-identity condition=AGREED package={package} "
        f"requested={requested} locked={locked} lock={location}"
    )
    return EXIT_AGREED


if __name__ == "__main__":
    raise SystemExit(main())
