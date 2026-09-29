#!/usr/bin/env python3
"""Fail-closed gate for the cognitive donor map (issues #251 W1/W4/A5, #816).

`crates/smart/cognitive-donor-map.toml` is a declared inventory of the active
`cognitive-micromodules` workstream (`workstreams/ACTIVE.toml`). Its
`[[donor]].disposition` and `[[topology_donor]].observed_disposition` rows are
claims about owner decisions, so this gate compares each claim with the current
content of the decision it names instead of checking that the row is well
formed. A recorded disposition is not evidence that it is still true.

Three properties are enforced, each against current source rather than against
the map's own shape:

1. Disposition against current reality (W1). A donor row names either a path in
   this repository or a non-tree reference such as `branch:<name>`. A row whose
   path exists may not carry the retirement class, and a row whose path is
   absent MUST carry it: a source that has been deleted cannot be described as
   retained, split or deferred, because that is a deferral of reuse from a
   source that no longer exists. This is the check that refuses the stale
   `crates/smart/eliot-system-experience` row corrected on 2026-09-28.
2. One current base (W4). `current_main_commit` is the base the dispositions
   were re-read on, and `[topology_donor_authority].dispositions_base` and
   `[topology_donor_authority].authority_base` name the same base with it: the
   donor dispositions and the topology donor authority are one decision and
   they are read on one base, so a map whose three base fields disagree is
   refused. All three are then checked against the repository itself, never
   against a copy of one of the three: the declared base must be a real commit
   on the current history, and no path that a disposition claims about may have
   changed between that base and the current base. That second condition is
   what makes the check load-bearing rather than a self-consistency assertion,
   and it is why a triple that is internally consistent but stale fails. The
   currency test is deliberately tied to the content the map claims about
   rather than to the moving `main` tip, so it discriminates staleness without
   becoming a gate that no commit could ever satisfy.
3. Authority scope, never a runtime owner (A5). `[topology_donor_authority]`
   must keep its donor-and-owner reconciliation ceiling with runtime completion
   false, the workstream rule that keeps prototype and donor presence from
   conferring admission must still be declared by the workstream that owns this
   inventory, and a `[[topology_donor]]` row may not disagree with the
   `[[donor]]` row for the same path, because the two are one disposition
   restated, not two decisions.

The gate reads only tracked text files. It builds nothing, resolves no
dependency, grants no admission, and its PASS is metadata evidence at the
map's declared proof ceiling - never runtime or product evidence (I0.8 audit
classes; `source_status = "STATIC_REVIEW_ONLY"`).
"""

from __future__ import annotations

import argparse
import re
import subprocess
import tomllib
from pathlib import Path

MAP_REL = Path("crates/smart/cognitive-donor-map.toml")
ACTIVE_REL = Path("workstreams/ACTIVE.toml")
OWNING_WORKSTREAM = "cognitive-micromodules"
# The sentence that keeps donor and prototype presence from conferring anything.
# It is quoted from the `implementation_rule` of the workstream that declares
# this map as one of its inventories. Dropping it lifts the authority ceiling
# silently, so it is checked rather than assumed.
AUTHORITY_SCOPE_RULE = (
    "Prototype Cargo/module manifests on main create no workspace, runtime, "
    "state, authority, or support admission."
)
AUTHORITY_CEILING = "DONOR_AND_OWNER_RECONCILIATION_ONLY"
# This map's own retirement class, taken from the rows whose sources are absent
# from the tree. It is deliberately narrower than I0.8's ledger verbs: the
# `RETIRE_AS_...` form retires a state owner while deferring the rest and
# therefore still describes a live source, so only this prefix counts as
# retired.
RETIRED_PREFIX = "RETIRED_"
NON_TREE_PREFIXES = ("branch:", "tag:", "commit:")
SHA1 = re.compile(r"^[0-9a-f]{40}$")


def load_toml(root: Path, relative: Path) -> dict:
    path = root / relative
    if not path.is_file():
        raise SystemExit(f"DONOR_DISPOSITIONS: FAIL missing {relative.as_posix()}")
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise SystemExit(
            f"DONOR_DISPOSITIONS: FAIL unparsable {relative.as_posix()} ({error})"
        ) from error


def text_of(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def is_tree_path(path: str) -> bool:
    """Whether a donor path names this repository rather than a revision."""
    return "/" in path and not path.startswith(NON_TREE_PREFIXES)


def git_output(root: Path, *args: str) -> str | None:
    """One line of `git` output, or None when git cannot answer."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def current_repository_base(root: Path) -> str | None:
    """The one current base of this repository, derived from git itself.

    `WORKFLOW.md` makes `main` the current product source and documentation
    authority and names `refs/heads/main` / `origin/main` as the authority
    ref, so the authority ref is resolved first and the local branch second.
    Returning None means the base could not be established; the caller then
    fails closed, because an unprovable base is not a passing base.
    """
    for ref in ("origin/main", "main"):
        resolved = git_output(root, "rev-parse", "--verify", f"{ref}^{{commit}}")
        if resolved and SHA1.match(resolved):
            return resolved
    return None


def claim_paths(data: dict) -> list[str]:
    """Every in-tree path a disposition or observed disposition is claimed about."""
    paths: list[str] = []
    for key in ("donor", "topology_donor"):
        for row in data.get(key, []):
            if not isinstance(row, dict):
                continue
            path = text_of(row.get("path"))
            if is_tree_path(path):
                paths.append(path)
    return sorted(set(paths))


def drifted_claim_paths(root: Path, base: str, current: str, paths: list[str]) -> list[str]:
    """Claim-bearing paths whose content changed between `base` and `current`.

    This is the independent staleness discriminator. It is computed from git
    history, never from the map, so a map that restates one stale commit in all
    three base fields is still caught: a disposition re-read before a path it
    describes changed is not a current disposition.
    """
    drifted: list[str] = []
    for path in paths:
        touching = git_output(
            root, "rev-list", "--count", f"{base}..{current}", "--", path
        )
        if touching and touching != "0":
            drifted.append(path)
    return drifted


def single_base_failures(root: Path, data: dict) -> list[str]:
    """W4: the donor dispositions and the topology donor authority are on one
    CURRENT base.

    Every expectation here is derived from the repository, not from this map.
    Comparing the three base fields only against one another would prove that
    three copies of the same caller-supplied value agree, which passes a triple
    that is internally consistent and arbitrarily stale. Instead this function
    requires the declared base to be a real commit on the current history, and
    requires that no path any disposition claims about has changed since that
    base was read. The second condition is what makes an internally consistent
    but stale map fail, and tying the check to claimed content rather than to
    the moving `main` tip is what keeps it a real check without making it a
    gate that can never be green.
    """
    failures: list[str] = []
    authority = data.get("topology_donor_authority")
    if not isinstance(authority, dict):
        return ["[topology_donor_authority] table is missing"]

    bases = (
        ("current_main_commit", text_of(data.get("current_main_commit"))),
        (
            "[topology_donor_authority].dispositions_base",
            text_of(authority.get("dispositions_base")),
        ),
        (
            "[topology_donor_authority].authority_base",
            text_of(authority.get("authority_base")),
        ),
    )
    for label, value in bases:
        if not SHA1.match(value):
            failures.append(f"{label} must be one exact 40-hex base commit, got {value!r}")
    if failures:
        return failures

    # Three independently authored fields must name one base, not two.
    declared = {value for _, value in bases}
    if len(declared) != 1:
        failures.append(
            "the donor dispositions and the topology donor authority are on more "
            "than one base: "
            + ", ".join(f"{label}={value}" for label, value in bases)
        )
        return failures
    base = declared.pop()

    current = current_repository_base(root)
    if current is None:
        failures.append(
            "the current base could not be derived from this repository: neither "
            "origin/main nor main resolves to a 40-hex commit, so no base in this "
            "map can be shown to be current"
        )
        return failures

    if git_output(root, "merge-base", "--is-ancestor", base, current) is None:
        failures.append(
            f"the declared base {base} is not a commit on the current history "
            f"(it is not an ancestor of {current}); a base that is not a real "
            "ancestor of the current base cannot be the base these dispositions "
            "were re-read on"
        )
        return failures

    drifted = drifted_claim_paths(root, base, current, claim_paths(data))
    if drifted:
        behind = git_output(root, "rev-list", "--count", f"{base}..{current}") or "?"
        failures.append(
            f"the map is stale on its own declared base {base}: these claimed paths "
            f"changed in the {behind} commit(s) between that base and the current "
            f"base {current}, so the dispositions were not re-read against current "
            "source: " + ", ".join(drifted)
        )
    return failures


def authority_scope_failures(data: dict) -> list[str]:
    """A5: the topology donor stays a reconciliation record, not a runtime owner."""
    failures: list[str] = []
    authority = data.get("topology_donor_authority")
    if not isinstance(authority, dict):
        return ["[topology_donor_authority] table is missing"]
    if authority.get("runtime_completion") is not False:
        failures.append(
            "the topology donor authority claims runtime completion; donor and "
            "owner reconciliation is not runtime ownership"
        )
    if text_of(authority.get("proof_ceiling")) != AUTHORITY_CEILING:
        failures.append(
            "the topology donor authority proof ceiling must stay "
            f"{AUTHORITY_CEILING!r}, got {authority.get('proof_ceiling')!r}"
        )
    return failures


def owner_decision_failures(root: Path, rows: list[dict]) -> list[str]:
    failures: list[str] = []
    seen: set[str] = set()
    for row in rows:
        path = text_of(row.get("path"))
        disposition = text_of(row.get("disposition"))
        if not path:
            failures.append("donor row without a path")
            continue
        if path in seen:
            failures.append(f"duplicate donor row for {path}")
        seen.add(path)
        if not disposition:
            failures.append(f"{path}: disposition must be a named non-empty value")
            continue
        if not text_of(row.get("rationale")):
            failures.append(f"{path}: a disposition claim needs its reason")
        if not text_of(row.get("rejected_overgeneralization")):
            failures.append(f"{path}: rejected_overgeneralization must be stated")
        if not is_tree_path(path):
            # A branch, tag or commit reference is not this repository, so the
            # tree cannot contradict it; its own disposition says it is stale.
            continue
        exists = (root / path).exists()
        retired = disposition.startswith(RETIRED_PREFIX)
        if exists and retired:
            failures.append(
                f"{path}: disposition {disposition!r} retires a source that is "
                "still present in the tree"
            )
        elif not exists and not retired:
            failures.append(
                f"{path}: disposition {disposition!r} describes a source that is "
                f"absent from the tree; only a {RETIRED_PREFIX}* disposition may "
                "describe a removed donor"
            )
    return failures


def topology_donor_failures(
    root: Path, rows: list[dict], donor_dispositions: dict[str, str]
) -> list[str]:
    """A5/W4: the topology rows restate one disposition; they never add one."""
    failures: list[str] = []
    seen: set[str] = set()
    for row in rows:
        path = text_of(row.get("path"))
        if not path:
            failures.append("topology_donor row without a path")
            continue
        if path in seen:
            failures.append(f"duplicate topology_donor row for {path}")
        seen.add(path)
        for key in ("observed_disposition", "current_owner", "evidence", "uncertainty"):
            if not text_of(row.get(key)):
                failures.append(f"{path}: topology_donor {key} must be stated")
        if not row.get("owner_issue_refs"):
            failures.append(f"{path}: topology_donor owner_issue_refs must be stated")
        observed = text_of(row.get("observed_disposition"))
        if path in donor_dispositions and observed != donor_dispositions[path]:
            failures.append(
                f"{path}: topology_donor observed_disposition {observed!r} disagrees "
                f"with the donor disposition {donor_dispositions[path]!r}; they are "
                "one disposition on one base"
            )
        # The same direction check the `[[donor]]` rows get: an observed
        # disposition restated for a path that is gone is only evidence if it
        # says the donor was retired, never if it claims a live split.
        if is_tree_path(path):
            exists = (root / path).exists()
            if exists and observed.startswith(RETIRED_PREFIX):
                failures.append(
                    f"{path}: topology_donor observed_disposition {observed!r} retires "
                    "a source that is still present in the tree"
                )
            elif not exists and not observed.startswith(RETIRED_PREFIX):
                failures.append(
                    f"{path}: topology_donor observed_disposition {observed!r} describes "
                    f"a source absent from the tree; only a {RETIRED_PREFIX}* "
                    "disposition may describe a removed donor"
                )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    root = args.root.resolve()

    data = load_toml(root, MAP_REL)
    failures: list[str] = []
    failures.extend(single_base_failures(root, data))
    failures.extend(authority_scope_failures(data))

    donor_rows = [row for row in data.get("donor", []) if isinstance(row, dict)]
    topology_rows = [
        row for row in data.get("topology_donor", []) if isinstance(row, dict)
    ]
    if not donor_rows:
        failures.append("the donor map declares no [[donor]] row")
    if not topology_rows:
        failures.append("the donor map declares no [[topology_donor]] row")
    failures.extend(owner_decision_failures(root, donor_rows))
    failures.extend(
        topology_donor_failures(
            root,
            topology_rows,
            {text_of(row.get("path")): text_of(row.get("disposition")) for row in donor_rows},
        )
    )

    active = load_toml(root, ACTIVE_REL)
    rule = next(
        (
            text_of(workstream.get("implementation_rule"))
            for workstream in active.get("workstream", [])
            if text_of(workstream.get("id")) == OWNING_WORKSTREAM
        ),
        "",
    )
    if AUTHORITY_SCOPE_RULE not in rule:
        failures.append(
            f"{ACTIVE_REL.as_posix()} workstream {OWNING_WORKSTREAM!r} no longer "
            "declares that donor and prototype presence confers no workspace, "
            f"runtime, state, authority or support admission: {AUTHORITY_SCOPE_RULE!r}"
        )

    donors = len(donor_rows)
    topology = len(topology_rows)
    if failures:
        print(
            f"DONOR_DISPOSITIONS: FAIL donors={donors} topology_donors={topology} "
            f"issues={len(failures)}"
        )
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(
        f"DONOR_DISPOSITIONS: PASS donors={donors} topology_donors={topology} "
        f"base={text_of(data.get('current_main_commit'))} "
        f"current_base={current_repository_base(root)} "
        f"authority_base={text_of((data.get('topology_donor_authority') or {}).get('authority_base'))} "
        f"ceiling={AUTHORITY_CEILING} runtime_completion=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
