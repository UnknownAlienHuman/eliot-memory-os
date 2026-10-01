#!/usr/bin/env python3
"""Read back live branch protection/rulesets and compare against the retained rule.

Issue #3004 (Implementation sequence section 11, step 5; Acceptance "Enforcement"):
after enforcement is configured, read back and record the active rule, required
check context/app and bypass actors. This tool performs exactly that readback and
compares it against the retained expected rule. It never configures anything:
applying protection is a separate governed act (one ``gh api`` call recorded in
the issue report) because requiring the check while it is red would block every
lane's merges.

Exit codes: 0 = observed state matches the retained rule; 1 = mismatch (typed
``BP-*`` findings); 2 = the live state could not be read.

Bypass closure (issue #3004 W10 "keep only a governed break-glass path"). Every
actor the readback can see is compared against the retained allow-list, and each
one fails closed:

- branch protection push restrictions ``users`` / ``teams`` / ``apps``
  (an app may push without an account, so an account-only list cannot express it);
- repository rulesets ``bypass_actors``, for every ``actor_type`` and
  ``bypass_mode``;
- ``enforce_admins`` false, which is an implicit administrator bypass.

A bypass actor that is undeclared fails (``BP-BYPASS-ALLOWED``); a declared
actor that is absent from the live rule also fails (``BP-BYPASS-DRIFTED``), so
the check is set equality in both directions rather than one.

The retained rule is itself audited. A rule that requires no context, declines
to pin the app identity, or does not demand strict/admin enforcement cannot
discriminate a correct rule from a wrong one, so it is refused
(``BP-RETENED-RULE-EMPTY`` / ``BP-RETENED-RULE-UNBOUND`` /
``BP-RETENED-RULE-WEAK``) rather than comparing equal to every observation.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EXPECTED = REPO_ROOT / "config" / "merge-compile-enforcement.json"
DEFAULT_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def emitted_check_names(workflow: Path) -> set[str]:
    """Return the job ids a workflow emits as check names.

    GitHub names a check run after the job id. The retained rule must name a
    check the checked-in workflow still emits, otherwise the rule has drifted
    from its emitter and can only ever compare as a mismatch. Job ids are the
    two-space-indented keys directly under ``jobs:``; an unparseable workflow
    raises rather than silently yielding an empty emitter set.
    """
    try:
        content = workflow.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReadError(f"workflow unreadable: {workflow}: {exc}") from exc
    names: set[str] = set()
    inside = False
    for line in content.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not inside:
            if line.rstrip() == "jobs:":
                inside = True
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            # A new top-level key ends the jobs mapping.
            break
        if indent != 2:
            # Job body: runs-on/steps/if and so on.
            continue
        key, separator, _ = line.strip().partition(":")
        if separator and key.strip():
            names.add(key.strip())
    if not names:
        raise ReadError(f"no job ids parsed from {workflow}; the retained rule cannot be bound to an emitter")
    return names


class ReadError(Exception):
    """The live enforcement state could not be read."""


def gh_api(path: str) -> tuple[int, str]:
    """Run ``gh api`` and return (returncode, stdout).

    A missing/timed-out ``gh`` connection is a typed ``ReadError``, never an
    unhandled traceback: W10 requires a blocking owner action when the
    connection cannot read protection.
    """
    try:
        proc = subprocess.run(
            ["gh", "api", "--paginate", path],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError as exc:
        raise ReadError(f"gh CLI not available on PATH: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ReadError(f"gh api timed out after 120s: {path}") from exc
    except OSError as exc:
        raise ReadError(f"gh api could not run: {exc}") from exc
    return proc.returncode, proc.stdout


def read_protection(repo: str, branch: str) -> dict:
    """Read branch protection; 404 means verifiably unprotected, not an error."""
    code, out = gh_api(f"repos/{repo}/branches/{branch}/protection")
    if code != 0:
        try:
            payload = json.loads(out or "{}")
        except json.JSONDecodeError:
            payload = {}
        message = str(payload.get("message", ""))
        if "Branch not protected" in message or code == 1 and not out.strip():
            return {"protected": False, "raw": None}
        raise ReadError(f"protection read failed: {message or out.strip() or code}")
    try:
        raw = json.loads(out)
    except json.JSONDecodeError as exc:
        raise ReadError(f"protection read returned invalid JSON: {exc}") from exc
    checks = raw.get("required_status_checks") or {}
    admins = raw.get("enforce_admins") or {}
    restrictions = raw.get("restrictions") or {}
    # GitHub reports an app-bound requirement through ``checks`` and a legacy
    # context-only requirement through ``contexts``. Both are read so the
    # comparison below can tell an exactly-bound check from a bare context that
    # any app could satisfy with the same name.
    bound = {}
    for check in checks.get("checks") or []:
        if isinstance(check, dict) and check.get("context"):
            bound[check["context"]] = check.get("app_id")
    return {
        "protected": True,
        "contexts": list(checks.get("contexts") or []),
        "bound_checks": bound,
        "strict": bool(checks.get("strict", False)),
        "enforce_admins": bool(admins.get("enabled", False)),
        "bypass_users": sorted(u.get("login", "") for u in restrictions.get("users") or []),
        "bypass_teams": sorted(t.get("slug", "") for t in restrictions.get("teams") or []),
        # Every remaining push-allowance actor GitHub exposes on a protection
        # rule. ``restrictions.apps`` is an APP-LEVEL exemption: an app listed
        # here may push without an account, so it is a bypass surface the
        # account-only users/teams lists cannot express. It is read here
        # (previously it was dropped on the floor) so the comparison below can
        # fail closed on an app that is not the retained break-glass actor.
        "bypass_apps": sorted(
            f"{app.get('slug') or app.get('name') or app.get('id')}"
            for app in (restrictions.get("apps") or [])
            if isinstance(app, dict) and (app.get("slug") or app.get("name") or app.get("id"))
        ),
        "raw": raw,
    }


def read_rulesets(repo: str) -> list:
    """Read repository rulesets (empty list is a valid observation)."""
    code, out = gh_api(f"repos/{repo}/rulesets")
    if code != 0:
        raise ReadError(f"ruleset read failed: {out.strip() or code}")
    try:
        payload = json.loads(out or "[]")
    except json.JSONDecodeError as exc:
        raise ReadError(f"ruleset read returned invalid JSON: {exc}") from exc
    return payload if isinstance(payload, list) else []


def bypass_actor_names(ruleset: dict) -> list[str]:
    """Return every actor that can skip this ruleset's rules.

    A ruleset's ``bypass_actors`` is a SEPARATE bypass surface from branch
    protection's push-restriction lists, and it is the one GitHub added later.
    Each entry names an ``actor_type`` (``Integration``, ``OrganizationAdmin``,
    ``RepositoryRole``, ``Team``, ``DeployKey``) and a ``bypass_mode``
    (``always`` means unconditionally; ``pull_request`` means it may skip for
    its own PR). Both are a bypass path, and ``exempt``/absent modes are read as
    permissive rather than assumed safe: an unrecognised shape must not read as
    "no bypass actor". A missing ``actor_type`` is a defect in the ruleset
    itself, not an absent actor, so it is reported too.
    """
    names: list[str] = []
    for actor in ruleset.get("bypass_actors") or []:
        if not isinstance(actor, dict):
            # A non-object actor is unreadable, therefore not provably absent.
            names.append(f"<unreadable-bypass-actor:{actor!r}>")
            continue
        kind = str(actor.get("actor_type") or "<unspecified-actor-type>")
        mode = str(actor.get("bypass_mode") or "always")
        identity = actor.get("actor_id")
        if identity is None:
            identity = actor.get("team_id") or actor.get("integration_id") or actor.get("app_id")
        names.append(f"{kind}:{identity} ({mode})")
    return names


def read_default_branch(repo: str) -> str:
    """Read the repository's CURRENT default branch.

    The retained rule names a branch; the repository's default branch is the
    branch that actually receives merges. A rule enforced only on some other
    branch must never compare as MATCH for ``main``. A repository read failure
    is a typed ``ReadError`` (exit 2), not a silently skipped check.
    """
    code, out = gh_api(f"repos/{repo}")
    if code != 0:
        raise ReadError(f"repository read failed: {out.strip() or code}")
    try:
        payload = json.loads(out or "{}")
    except json.JSONDecodeError as exc:
        raise ReadError(f"repository read returned invalid JSON: {exc}") from exc
    branch = payload.get("default_branch")
    if not isinstance(branch, str) or not branch.strip():
        raise ReadError("repository read returned no default_branch")
    return branch.strip()


def compare(expected: dict, protection: dict, rulesets: list, emitted: set[str],
            default_branch: str | None = None) -> list[dict]:
    """Compare observed state against the retained rule; return typed findings."""
    findings: list[dict] = []
    want_contexts = list(expected.get("required_contexts") or [])
    want_app_id = expected.get("required_check_app_id")

    # --- The rule must target the branch that actually receives merges. ------
    # Comparing a rule on a side branch as MATCH for ``main`` is precisely the
    # wrong-rule-passes failure this readback exists to prevent. This is the same
    # class as BP-APP-UNBOUND: a value read but not compared.
    want_branch = expected.get("branch")
    if default_branch is not None and want_branch and want_branch != default_branch:
        findings.append({
            "code": "BP-DEFAULT-BRANCH",
            "detail": (
                f"the retained rule targets {want_branch!r} but the repository default branch "
                f"is {default_branch!r}; a rule on a non-merge branch would satisfy MATCH"
            ),
        })

    # --- The retained rule itself must still MEASURE something. -------------
    # Issue #3004 W10: read back and retain the EXACT rule. A retained rule that
    # requires no context, or that declines to pin the app identity, cannot
    # discriminate a correct rule from a wrong one, so it compares equal to every
    # observation including a completely unenforced branch. That is the #943
    # class ("an empty profile still reaches a positive verdict") and it is a
    # finding, not a remark.
    if not want_contexts:
        findings.append({
            "code": "BP-RETENED-RULE-EMPTY",
            "detail": (
                "the retained rule requires no status-check context, so it cannot "
                "distinguish an enforced rule from an unenforced branch"
            ),
        })
    if want_app_id is None:
        findings.append({
            "code": "BP-RETAINED-RULE-UNBOUND",
            "detail": (
                "the retained rule declares no required_check_app_id; a context-only "
                "requirement can be satisfied by any app posting that name"
            ),
        })
    if expected.get("strict") is not True:
        findings.append({
            "code": "BP-RETENED-RULE-WEAK",
            "detail": (
                "the retained rule does not require strict semantics; with strict "
                "absent the readback would accept a rule that merges on a stale base"
            ),
        })
    if expected.get("enforce_admins") is not True:
        findings.append({
            "code": "BP-RETENED-RULE-WEAK",
            "detail": (
                "the retained rule does not require enforce_admins; administrators and "
                "agents with admin rights could bypass the required check"
            ),
        })

    # The retained rule must still name a check the checked-in workflow emits,
    # or it has drifted from its emitter and no comparison can be meaningful.
    for context in want_contexts:
        if emitted and context not in emitted:
            findings.append({
                "code": "BP-RULE-UNBOUND",
                "detail": (
                    f"retained context {context!r} is not emitted by the checked-in workflow "
                    f"({sorted(emitted)}); the rule has drifted from its emitter"
                ),
            })

    if not protection.get("protected"):
        findings.append({
            "code": "BP-UNPROTECTED",
            "detail": f"branch {expected.get('branch')} has no protection rule",
        })
    else:
        observed = list(protection.get("contexts", [])) + list(protection.get("bound_checks", {}))
        missing = [c for c in want_contexts if c not in observed]
        for context in missing:
            findings.append({
                "code": "BP-CONTEXT-MISSING",
                "detail": f"required context {context!r} not in {sorted(set(observed))}",
            })
        # An exactly-bound requirement names both the check and the app that
        # emits it. A context-only requirement can be satisfied by any app
        # posting that name, so an unbound or mis-bound app is a real gap.
        bound_checks = protection.get("bound_checks", {})
        if want_app_id is not None:
            for context in want_contexts:
                if context not in observed:
                    continue
                observed_app = bound_checks.get(context)
                if observed_app is None:
                    findings.append({
                        "code": "BP-APP-UNBOUND",
                        "detail": (
                            f"required context {context!r} is not bound to a check app; any app "
                            f"posting that name would satisfy it (retained app_id {want_app_id})"
                        ),
                    })
                elif int(observed_app) != int(want_app_id):
                    findings.append({
                        "code": "BP-APP-MISMATCH",
                        "detail": (
                            f"required context {context!r} is bound to app_id {observed_app}, "
                            f"retained app_id {want_app_id}"
                        ),
                    })
        if expected.get("strict", False) and not protection.get("strict", False):
            findings.append({
                "code": "BP-NOT-STRICT",
                "detail": "required status checks are not strict (stale success would satisfy)",
            })
        if expected.get("enforce_admins", False) and not protection.get("enforce_admins", False):
            findings.append({
                "code": "BP-BYPASS-ALLOWED",
                "detail": "administrators/agents can bypass the required check",
            })
        # --- Break-glass closure: EVERY bypass actor the readback can see. ----
        # `allowed_bypass_actors` is a single flat allow-list applied to users,
        # teams AND apps. Comparing only users/teams left an app-level exemption
        # invisible: an app that may push without an account is a bypass actor
        # that no account list can name. All three are compared here, and the
        # check is set equality in BOTH directions: an undeclared actor fails,
        # and an actor the contract declares but the rule does not carry also
        # fails, because a declared break-glass owner that silently stopped
        # existing is drift the readback must not report as a clean match.
        allowed = set(expected.get("allowed_bypass_actors") or [])
        present: list[str] = []
        for actor in (
            list(protection.get("bypass_users") or [])
            + list(protection.get("bypass_teams") or [])
            + list(protection.get("bypass_apps") or [])
        ):
            present.append(actor)
            if actor not in allowed:
                findings.append({
                    "code": "BP-BYPASS-ALLOWED",
                    "detail": (
                        f"bypass actor {actor!r} is not in the retained allow-list; "
                        "an undeclared break-glass path is not a governed one"
                    ),
                })
        for actor in sorted(allowed - set(present)):
            findings.append({
                "code": "BP-BYPASS-DRIFTED",
                "detail": (
                    f"retained break-glass actor {actor!r} is absent from the live rule; "
                    "the declared exception and the enforced rule have diverged"
                ),
            })
    # --- Ruleset bypass closure. --------------------------------------------
    # Rulesets are an INDEPENDENT enforcement surface. An active ruleset that
    # carries any bypass actor can skip the very context the branch rule
    # requires, so its existence previously produced no finding at all. Every
    # actor is compared against the same allow-list, and an active ruleset that
    # does not itself require the retained context is reported too: a second,
    # weaker enforcement surface over the same branch is drift, not agreement.
    for ruleset in rulesets:
        if not isinstance(ruleset, dict):
            continue
        name = ruleset.get("name") or ruleset.get("id") or "<unnamed ruleset>"
        if ruleset.get("enforcement") != "active":
            # A disabled/evaluate ruleset enforces nothing; it is not a bypass
            # path, so it is recorded but cannot excuse an actor.
            continue
        for actor in bypass_actor_names(ruleset):
            findings.append({
                "code": "BP-BYPASS-ALLOWED",
                "detail": (
                    f"active ruleset {name!r} carries bypass actor {actor!r}, which can skip "
                    "the required check independently of branch protection"
                ),
            })
        ruleset_contexts = set()
        for rule in ruleset.get("rules") or []:
            if not isinstance(rule, dict):
                continue
            params = rule.get("parameters") or {}
            for check in params.get("required_status_checks") or []:
                if isinstance(check, dict) and check.get("context"):
                    ruleset_contexts.add(check["context"])
        for context in want_contexts:
            if context not in ruleset_contexts:
                findings.append({
                    "code": "BP-RULESET-DIVERGED",
                    "detail": (
                        f"active ruleset {name!r} does not require {context!r}; it is a "
                        "second enforcement surface that does not carry the merge gate"
                    ),
                })
    if rulesets:
        ruleset_contexts = set()
        for ruleset in rulesets:
            if not isinstance(ruleset, dict) or ruleset.get("enforcement") != "active":
                continue
            for rule in ruleset.get("rules") or []:
                if not isinstance(rule, dict):
                    continue
                params = rule.get("parameters") or {}
                for check in params.get("required_status_checks") or []:
                    if isinstance(check, dict) and check.get("context"):
                        ruleset_contexts.add(check["context"])
        for context in want_contexts:
            if context not in ruleset_contexts and not protection.get("protected"):
                findings.append({
                    "code": "BP-RULESET-DIVERGED",
                    "detail": f"no active ruleset requires {context!r}",
                })
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="UnknownAlienHuman/eliot-memory-os")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--expect", default=str(DEFAULT_EXPECTED),
                        help="retained expected-rule JSON (default: config/merge-compile-enforcement.json)")
    parser.add_argument("--readback-out", default=None,
                        help="write the observed+verdict readback JSON to this path")
    parser.add_argument("--emitter", default=str(DEFAULT_WORKFLOW),
                        help="workflow whose job ids must still emit the retained context")
    parser.add_argument("--json-out", action="store_true",
                        help="print the full readback JSON instead of the one-line verdict")
    args = parser.parse_args(argv)

    try:
        expected = json.loads(Path(args.expect).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"BP-READ-ERROR retained rule unreadable: {args.expect}: {exc}", file=sys.stderr)
        return 2
    try:
        protection = read_protection(args.repo, args.branch)
        rulesets = read_rulesets(args.repo)
        default_branch = read_default_branch(args.repo)
        emitted = emitted_check_names(Path(args.emitter))
    except ReadError as exc:
        print(f"BP-READ-ERROR {exc}", file=sys.stderr)
        if args.readback_out:
            readback = {
                "repo": args.repo,
                "branch": args.branch,
                "expected_rule": args.expect,
                "verdict": "READ-ERROR",
                "findings": [{"code": "BP-READ-ERROR", "detail": str(exc)}],
                "observed": None,
                "emitter": {"workflow": args.emitter, "emitted_check_names": []},
            }
            Path(args.readback_out).write_text(json.dumps(readback, indent=2) + "\n", encoding="utf-8")
        return 2

    findings = compare(expected, protection, rulesets, emitted, default_branch)
    verdict = "MATCH" if not findings else "MISMATCH"
    readback = {
        "repo": args.repo,
        "branch": args.branch,
        "default_branch": default_branch,
        "expected_rule": args.expect,
        "verdict": verdict,
        "findings": findings,
        "observed": {
            "protected": protection.get("protected"),
            "contexts": protection.get("contexts", []),
            "bound_checks": protection.get("bound_checks", {}),
            "strict": protection.get("strict", False),
            "enforce_admins": protection.get("enforce_admins", False),
            "bypass_users": protection.get("bypass_users", []),
            "bypass_teams": protection.get("bypass_teams", []),
            "bypass_apps": protection.get("bypass_apps", []),
            "rulesets": [
                {
                    "id": r.get("id"),
                    "name": r.get("name"),
                    "enforcement": r.get("enforcement"),
                    "bypass_actors": bypass_actor_names(r) if isinstance(r, dict) else [],
                }
                for r in rulesets if isinstance(r, dict)
            ],
        },
        "emitter": {
            "workflow": args.emitter,
            "emitted_check_names": sorted(emitted),
        },
    }
    if args.readback_out:
        Path(args.readback_out).write_text(json.dumps(readback, indent=2) + "\n", encoding="utf-8")
    if args.json_out:
        print(json.dumps(readback, indent=2))
    else:
        codes = ",".join(f["code"] for f in findings) if findings else "none"
        print(f"BRANCH_PROTECTION: {verdict} findings={codes}")
    return 0 if verdict == "MATCH" else 1


if __name__ == "__main__":
    raise SystemExit(main())
