#!/usr/bin/env python3
"""Verify GitHub workflows, pinned action inputs, dependency locks, and test execution.

Enforces that:
1. Triggers follow a closed per-workflow policy (accepted issue #3004): every
   workflow is workflow_dispatch-only except ci.yml, the sole automatic
   compile-only merge check (workflow_dispatch, main-scoped pull_request and
   push). pull_request_target, schedules, releases, merge queue and every
   other automatic trigger are rejected on every workflow.
2. Every third-party Action is verified by immutable identity (issue #1225 step
   2): the reference must be a reviewed full 40-character commit SHA owned by an
   approved action owner, the human-readable release stays comment-only metadata,
   mutable tags/branches/short SHAs/expressions are rejected, the same action may
   not carry two different pins across workflows, and every reference's
   owner/repository/SHA identity is derived from the files and published in the
   --json-out payload as the first step toward the run manifest. The reference is
   read from every YAML spelling GitHub accepts (same-line value, block-mapping
   value on the following lines, flow-mapping value), so a mutable tag cannot
   escape the rule by changing only the YAML shape, and the manifest records
   exactly the references the rules judge.
3. Top-level permissions remain minimal (contents: read); broad write-all is rejected.
4. Python verification dependencies are fully version- and hash-locked with --hash=sha256.
5. NuGet dependencies for Eliot.Operator and the Eliot.Operator.Tests harness
   are locked with RestorePackagesWithLockFile and checked-in
   packages.lock.json files, so locked-mode restore fails on drift, and each
   checked-in lock must already agree with the project graph it covers
   (docs/DEPENDENCY_POLICY.md binds direct PackageReference entries to the
   configured lock target and inventory versions), so stale-lock graph drift
   fails on source evidence alone.
6. The .NET SDK identity is explicit (issue #1225 step 4): the repository
   `global.json` pins one SDK band, and that band must equal the band derived
   from the target frameworks the locked Operator projects declare, so a TFM
   bump and an SDK bump cannot disagree silently.
7. Operator coverage is classified by workflow/profile class (issue #3004):
   MergeCompile workflows restore/build both Operator projects through the
   shared profile with zero execution and no execution claim; every other
   workflow that builds Eliot.Operator executes the Eliot.Operator.Tests
   harness through an explicit dotnet run/exec invocation (issue #1225
   N_step5: a restore line, a step name, quoted prose, or a run-summary
   claim alone is not execution; an invocation GitHub may skip or
   discard is not executed evidence; and an invocation whose shell-level
   result cannot reach the step's exit status is not terminal evidence
   either).
8. Workflow names indicate manual invocation and state bounded proof ceilings.
9. Referenced local scripts exist on disk.
10. Workflow pip installs consume only the hash-locked
    scripts/requirements-verification.txt with --require-hashes.
11. Workflow dotnet restores run with --locked-mode against the checked-in
    packages.lock.json files, so graph drift or a lock-mutating restore fails
    instead of silently resolving a new graph.
12. Permissions, credentials and secrets stay fail-closed on every workflow:
    no elevated write/admin grant, no secrets interpolation, no OIDC
    id-token authority, and every checkout step disables persisted
    credentials in its own step block.
13. Every `actions/cache` key binds runner platform/architecture, dependency
    lock, toolchain, source manifests, and event/fork trust class on every
    cache step of every workflow, so a cache hit never crosses a trust,
    source or toolchain boundary (AC10).
14. The --json-out run manifest records the oracle identity (issue #1225
    N_step10; I18.27): the sha256 of every oracle-owned file, so the
    independent/manual source-candidate or Review owner attests the exact
    oracle bytes that produced the verdict instead of a self-certified pass.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import fnmatch
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
# A YAML `uses` KEY, wherever it appears in a workflow: a step-level `- uses:`,
# a job-level reusable `uses:` (no dash), the same key in a flow mapping
# (`- { uses: ... }`), and a block mapping whose value sits on later lines
# (`- uses:` followed by an indented value). The key accepts every YAML spelling
# GitHub accepts (optionally single- or double-quoted, any spacing before the
# `:`), mirroring the `on:`-key handling in _on_block_child_key, so the pin,
# owner and one-pin rules see all of them. A double-quoted key may also carry
# backslash escapes (`"us\u0065s"` parses as `uses`); the quoted text is
# captured so the caller decodes it before comparing (single-quoted and plain
# keys have no escapes, so they stay literal).
USES_KEY_RE = re.compile(r"""(?:^|[{,\s\[])(?:-)?\s*(?:"(?P<dqkey>(?:[^"\\]|\\.)*)"|'uses'|uses)\s*:(?!:)""")
# A `uses` VALUE: a single-quoted or double-quoted scalar, or a plain scalar,
# terminated at a comment (`# ...` release annotation) or at a flow mapping
# separator. The value is never taken across a comment, so a release
# annotation stays comment metadata and never becomes part of the ref.
USES_VALUE_RE = re.compile(
    r'''\s*(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)'|(?P<plain>[^\s,\]#}]+))'''
)
# Action identity shape: owner/repo[/path...]@ref. A `${{ ... }}` ref fails the
# full 40-hex ref test, and a reference without an owner segment fails the
# owner-shape test, so neither can silently reach the pin decision.
ACTION_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9._-]+)+$")
PERMISSION_WRITE_ALL_RE = re.compile(r"^\s*permissions:\s*(?:write-all|read-all)", re.MULTILINE)
# Fail-closed privilege and secret handling (issue #1225 step 8). Fork and
# untrusted candidate code must never receive protected material: no elevated
# `write`/`admin` permission grant on any code line, no `secrets.*`
# interpolation a run could observe, no OIDC `id-token` authority, and every
# `actions/checkout` step carries `persist-credentials: false` in its own step
# block. Quoted prose and `#` comments are stripped before matching
# (workflow_code_line), so a checker asserting on a marker string is never
# itself a violation.
ELEVATED_PERMISSION_RE = re.compile(r":\s*(write|admin)\b")
SECRET_REF_RE = re.compile(r"secrets\b")
OIDC_TOKEN_RE = re.compile(r"id-token\s*:")

# Closed approved action owner set (issue #1225 step 2, Wave D "unapproved
# owners"). Evidence-derived, not aspirational: `actions` is the only owner any
# workflow in this repository references. A third-party `uses:` whose owner
# segment is not listed here is rejected (GWF-002) even when it carries a
# syntactically valid full 40-hex SHA, so a well-formed pin cannot smuggle in an
# unreviewed publisher. Adding an owner is a reviewed change to this constant
# together with the workflow reference that introduces it; never a discovery
# result. There is deliberately no wildcard and no org-prefix matching.
APPROVED_ACTION_OWNERS = ("actions",)

# Closed per-workflow trigger policy (accepted issue #3004). Default: every
# repository workflow is manual-only. ci.yml is the sole exception: the
# automatic compile-only merge check.
DEFAULT_ALLOWED_EVENTS = {"workflow_dispatch"}
WORKFLOW_EVENT_EXCEPTIONS = {
    "ci.yml": {"workflow_dispatch", "pull_request", "push"},
}
# ci.yml exception scoping: automatic events are main-only, and PR activity
# must cover every open/update/reopen/ready transition (an absent types key
# keeps the GitHub default, which covers them).
CI_MAIN_BRANCHES = ["main"]
CI_REQUIRED_PR_TYPES = {"opened", "synchronize", "reopened", "ready_for_review"}
# Compile-only workflow/profile class marker (issue #3004 item 8).
COMPILE_ONLY_PROFILE_MARKER = "-Profile MergeCompile"

# Operator harness execution identity (issue #1225 N_step5). A non-compile-only
# workflow that builds Eliot.Operator must EXECUTE the Eliot.Operator.Tests
# harness: an explicit `dotnet run` (or `dotnet exec`) invocation whose target
# is the harness project, with `dotnet` standing at command position on its
# code line. A `dotnet restore`/`dotnet build` line, a step name, quoted
# prose, a run-summary execution claim, or a harness-shaped mention passed as
# an argument to a print builtin (`echo`, `Write-Host`, `Write-Output`,
# `printf`) is not execution. Quoted string literals and `#` comments are
# stripped before matching, so only real invocations count (same technique as
# check_dotnet_restore_lock).
OPERATOR_HARNESS_EXECUTION_RE = re.compile(r"dotnet\s+(run|exec)\b[^\n]*Eliot\.Operator\.Tests")
# Print/forward builtins whose arguments are prose, not invoked commands.
# Matched case-insensitively as whole tokens in the code before the `dotnet`
# token, so `echo dotnet run ...` and `Write-Host dotnet run ...` never count
# as harness execution even when unquoted.
NON_EXECUTION_COMMAND_RE = re.compile(r"(?<![\w.-])(echo|write-host|write-output|printf)(?![\w-])", re.IGNORECASE)
# What may legally precede the invoked `dotnet` token on one code line: YAML
# step framing (`- run:`), block-scalar/chaining separators, the PowerShell
# call operator, and explicit shell wrappers (`pwsh -Command`, `sh -c`, ...).
HARNESS_COMMAND_PREFIX_RE = re.compile(
    r"""(?ix)^
    [\s|>&;]*
    (?:-\s+)?
    (?:run:\s*)?
    (?:[|>&;]+\s*|&&\s*|\|\|\s*)*
    (?:&\s*)?
    (?:(?:pwsh(?:\.exe)?|powershell(?:\.exe)?|sh|bash|cmd(?:\.exe)?|/bin/(?:sh|bash))
       (?:\s+[^\s|>&;]+)*\s+(?:-c(?:ommand)?\s+)?)?
    $"""
)
# Run-summary wording that asserts the harness ran. The claim is never compared
# with anything on its own: it satisfies the coverage rule only together with
# an execution invocation above, and it fails the rule without one.
OPERATOR_EXECUTION_CLAIM = "Operator tests: executed"
# Shell-level failure suppression (issue #1225 N_step5). A harness whose exit
# status cannot reach the step's exit status never produces terminal evidence,
# so an invocation carrying one of these operators is not executed evidence even
# though `dotnet` still stands at command position: `|| <cmd>` replaces a
# failure with the right-hand side's status, `| <cmd>` replaces it with the
# pipeline's last status, and a trailing `&` detaches the harness from the step,
# so its result arrives after the step has already reported. The `&` of a `2>&1`
# redirection is excluded and `||` is matched by the same `|`, so only a real
# suppression operator refuses.
HARNESS_FAILURE_SUPPRESSION_RE = re.compile(r"\|(?!\|)|(?<!>)&(?!&)")
# A bare `exit 0` as the statement immediately after the invocation replaces a
# harness failure with success before anything can observe the exit code. A
# guarded block is a different shape: the statement that reaches the exit has
# already converted the failure, so only the adjacent one is this defect.
HARNESS_EXIT_OVERRIDE_RE = re.compile(r"^exit\s+0$", re.IGNORECASE)

# Execution conditions (issue #1225 N_step5). An invocation line is executed
# evidence only when the step that carries it can actually execute and its
# result reaches the run, so each of these governing keys is read:
#   `if:`            a step condition makes the step conditional, so a false
#                    condition means the step is skipped and nothing executed,
#                    and any condition that cannot be proven false is still an
#                    unverifiable execution condition;
#   `continue-on-error:`
#                    a failing step is discarded, so its outcome proves nothing
#                    about the harness having run and passed;
#   `timeout-minutes:`
#                    a step that is always killed before the harness finishes
#                    never reaches terminal harness evidence.
# GitHub accepts the hyphenated and underscored spellings of the two hyphenated
# keys, so both are recognized. The keys are compared on the normalized key, and
# every enclosing job scope is read as well: a skipped job never reaches its
# steps, and a `continue-on-error` job discards its steps' results.


def _strip_expression_braces(body: str) -> str:
    return body.replace("$", "").replace("{", "").replace("}", "").strip()


def _strip_comment(text: str) -> str:
    return text.split("#", 1)[0]


def _strip_quotes(text: str) -> str:
    return text.strip().strip("'\"")


# YAML double-quoted scalar escapes (YAML 1.2 section 5.7): the single-character
# escapes plus the hexadecimal `\xXX`, `\uXXXX` and `\UXXXXXXXX` forms. A
# backslash followed by a line break is a continuation and contributes nothing.
_YAML_DQ_SIMPLE_ESCAPES = {
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    " ": " ",
    '"': '"',
    "\\": "\\",
    "N": chr(0x85),
    "_": chr(0xA0),
    "L": chr(0x2028),
    "P": chr(0x2029),
}


def _unescape_yaml_double_quoted(text: str) -> str:
    """Decode backslash escapes in a double-quoted YAML scalar.

    GitHub parses `"i\u0066"` as the key `if`, so a raw-text comparison never
    sees it. Unknown escapes are left as written rather than dropped, so an
    unrecognized spelling can never silently become a governed key.
    """
    def replace(match: re.Match[str]) -> str:
        seq = match.group(1)
        if len(seq) == 1:
            if seq in ("\n", "\r"):
                return ""
            return _YAML_DQ_SIMPLE_ESCAPES.get(seq, match.group(0))
        if seq[0] in ("x", "u", "U"):
            try:
                return chr(int(seq[1:], 16))
            except ValueError:
                return match.group(0)
        return match.group(0)
    return re.sub(
        r"\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)",
        replace,
        text,
        flags=re.DOTALL,
    )


def _action_identity_line(line: str) -> str:
    """A workflow line with YAML quote delimiters removed but content kept.

    `workflow_code_line` deletes quoted spans because quoted prose is not code;
    that also deletes a quoted `uses: "actions/cache@..."` value before the
    `"<action>@" in code` step-recognition tests, so the step escapes every
    rule that depends on it. Step recognition only asks whether the line names
    the action, so it keeps the span content and drops just the delimiters
    (plus a trailing `#` comment), judging quoted spellings exactly like
    unquoted ones.
    """
    return _strip_comment(line).replace('"', "").replace("'", "")


def workflow_code_line(line: str) -> str:
    """A workflow line without quoted prose or a trailing comment.

    Quoted literals (for example a checker asserting on a marker string) and
    `#` comments are not gate invocations, so only the remaining code is
    judged (same technique as check_dotnet_restore_lock).
    """
    code = re.sub(r'"[^"]*"', "", line)
    code = re.sub(r"'[^']*'", "", code)
    return code.split("#", 1)[0]


def _condition_is_falsy(expression: str) -> bool:
    """True when a GitHub `if:` condition provably evaluates to false.

    Two closed cases: an empty condition (`if:`, `if: ${{ }}`, `if: null`) and a
    condition whose value is `false` or numeric zero. Any other condition is not
    proof of a skip, so it stays an unverifiable condition rather than a licence
    to claim execution.
    """
    value = _strip_quotes(_strip_comment(_strip_expression_braces(expression)))
    text = value.strip()
    if text in ("", "null"):
        return True
    if text.lower() == "false":
        return True
    try:
        return float(text) == 0.0
    except ValueError:
        return False


def _condition_is_unconditional(expression: str) -> bool:
    """True when a GitHub `if:` condition runs the step on every dispatch.

    An absent condition, the literals `true`/`always()`, and a comparison whose
    two sides are identical all run the step whatever the run looks like. Any
    other condition depends on something the workflow does not fix at authoring
    time, so it is a condition the claim may not assume holds.
    """
    value = _strip_quotes(_strip_comment(_strip_expression_braces(expression)))
    text = value.strip()
    if text in ("", "true", "always", "always()"):
        return True
    left, separator, right = text.partition("==")
    if separator and left.strip() and left.strip() == right.strip():
        return True
    return False


def _yaml_key(line: str) -> str | None:
    """The YAML mapping key of a line, or None when the line carries none.

    Accepts the ordinary spellings GitHub accepts for a mapping key: an
    optionally quoted key, any spacing before the `:`, and either a value or a
    block indicator after it. Block-scalar shell source, list items and
    comments carry no key and yield None.
    """
    match = re.match(r"^\s*(?:-\s+)?(?:\"([^\"]*)\"|'([^']*)'|([^\s#:][^:]*?))\s*:(?:\s|$)", line)
    if match is None:
        return None
    if match.group(1) is not None:
        return _unescape_yaml_double_quoted(match.group(1)).strip()
    for group in (match.group(2), match.group(3)):
        if group is not None:
            return group.strip()
    return None


def _yaml_value(line: str) -> str:
    """The scalar value written on a mapping line, or "" for a block indicator."""
    _, separator, tail = line.partition(":")
    if not separator:
        return ""
    tail = tail.strip()
    if tail in ("|", ">", "|-", ">-", "|+", ">+"):
        return ""
    return _strip_quotes(_strip_comment(tail))


def _is_yaml_comment(line: str) -> bool:
    stripped = line.lstrip()
    return stripped == "" or stripped.startswith("#")


def _is_step_entry(line: str) -> bool:
    """True for a YAML block-sequence entry (`      - name: ...`)."""
    stripped = line.lstrip(" ")
    return stripped.startswith("- ") or stripped.rstrip() == "-"


def _enclosing_job_block(lines: list[str], index: int, indent: int) -> list[int]:
    """Line indexes of the job body that owns a step at `indent`.

    A YAML mapping is unordered, so the owning job's body is every mapping
    line at the job-body indentation: from the `steps:` container up to (but
    not including) the shallower job header, and below the steps block down
    to (but not including) the next shallower mapping line. Every governing
    `if:`/`continue-on-error:`/`timeout-minutes:` a job body can carry is one
    of those lines, so a skipped or soft-failure job is seen no matter which
    key carries it or where in the job body the key is written. The `steps:`
    container may sit at the step entries' own column (legal YAML for a block
    sequence), and that spelling still opens the job body.
    """
    governing: list[int] = []
    body_indent: int | None = None
    for previous in range(index, -1, -1):
        line = lines[previous]
        if _is_yaml_comment(line):
            continue
        key = _yaml_key(line)
        if key is None:
            continue
        leading = len(line) - len(line.lstrip(" "))
        if leading > indent:
            continue
        if leading == indent and key != "steps" and body_indent != leading:
            # Same column as the step entry but not the `steps:` container
            # itself (a sibling entry such as `- name:` still reads as a key
            # here): only the container at this column opens the job body, so
            # sibling keys above it are skipped while job-body keys at the
            # same column below it are kept.
            continue
        if body_indent is not None and leading < body_indent:
            # Shallower than a job-body key: this is the job header, so the job
            # body ends here and nothing above it governs the step.
            break
        governing.append(previous)
        if key == "steps":
            body_indent = leading
    if body_indent is not None:
        # A job-level key may also be written after the `steps:` block (the
        # mapping is unordered and GitHub still reads it as a job condition),
        # so collect the job-body keys below the step too. Deeper lines are
        # step content; the first shallower mapping line ends the job body.
        for following in range(index + 1, len(lines)):
            line = lines[following]
            if _is_yaml_comment(line):
                continue
            key = _yaml_key(line)
            if key is None:
                continue
            leading = len(line) - len(line.lstrip(" "))
            if leading > body_indent:
                continue
            if leading < body_indent:
                break
            governing.append(following)
    return governing


def _nearest_list_item(lines: list[str], index: int) -> int | None:
    """The index of the nearest block-sequence entry at or above `index`."""
    for previous in range(index, -1, -1):
        if not _is_yaml_comment(lines[previous]) and _is_step_entry(lines[previous]):
            return previous
    return None


def _own_block_end(lines: list[str], item: int) -> int:
    """The last line index of the block owned by the sequence entry at `item`.

    The entry owns every following line that is blank, a comment, or indented
    deeper than the entry's dash. Its first same-indent sibling ends the block.
    """
    indent = len(lines[item]) - len(lines[item].lstrip(" "))
    last = item
    for index in range(item + 1, len(lines)):
        line = lines[index]
        if _is_yaml_comment(line):
            continue
        if len(line) - len(line.lstrip(" ")) > indent:
            last = index
            continue
        break
    return last


def _own_block(lines: list[str], item: int) -> list[int]:
    """Line indexes from the sequence entry at `item` to the end of its block."""
    return list(range(item, _own_block_end(lines, item) + 1))


def _enclosing_step_scope(lines: list[str], index: int) -> int | None:
    """The index of the sequence entry that owns the invocation at `index`.

    A step's `run`/`uses` body belongs to its own sequence entry, so the owning
    entry is the nearest one whose block still covers `index`. A mapping line at
    the entry's own indentation or shallower is that entry's preceding sibling,
    which ends the walk. The index is resolved to the entry's line rather than
    kept as a scan point, so an identical repeated mapping line never resolves
    to a later, unrelated block.
    """
    item = _nearest_list_item(lines, index)
    if item is None:
        return None
    if index > _own_block_end(lines, item):
        return None
    return item


def _overrides_harness_status(lines: list[str], index: int) -> bool:
    """True when the next statement in the block discards the harness status.

    Only the statement immediately after the invocation can be reached before
    anything has observed the harness's exit code, so a bare `exit 0` there
    replaces a failure with success. A block that guards the exit first
    (`if ... { throw }`) has already converted the failure and is left alone.
    """
    for follow in range(index + 1, len(lines)):
        code = workflow_code_line(lines[follow]).strip()
        if not code:
            continue
        return HARNESS_EXIT_OVERRIDE_RE.match(code) is not None
    return False


def _harness_invocations(lines: list[str]) -> list[tuple[int, int]]:
    """(owning sequence entry, invocation line) for every real invocation."""
    invocations: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        code = workflow_code_line(line)
        match = OPERATOR_HARNESS_EXECUTION_RE.search(code)
        if match is None:
            continue
        before = code[: match.start()]
        if NON_EXECUTION_COMMAND_RE.search(before):
            continue
        if not HARNESS_COMMAND_PREFIX_RE.match(before):
            continue
        if HARNESS_FAILURE_SUPPRESSION_RE.search(code[match.end() :]):
            continue
        if _overrides_harness_status(lines, index):
            continue
        scope = _enclosing_step_scope(lines, index)
        if scope is None:
            continue
        invocations.append((scope, index))
    return invocations


def _mapping_value_is_falsy(line: str) -> bool:
    """True when a governing `if:` is provably false (or carries no value)."""
    value = _yaml_value(line)
    if value == "":
        return True
    return _condition_is_falsy(value)


def _step_executes(scope: int, lines: list[str]) -> bool:
    """True when the step carrying the invocation can execute and report.

    The step's own `if:`/`continue-on-error:`/`timeout-minutes:` govern it, and
    so does the job that owns it: a job whose `if:` is false never reaches its
    steps, and a `continue-on-error` job discards their results. A step timeout
    is a bound rather than a skip, so only a degenerate bound of zero refuses.
    An `if:` runs the step on every dispatch only when it is unconditional;
    any other condition may skip the step, so it cannot carry an execution
    claim.
    """
    indent = len(lines[scope]) - len(lines[scope].lstrip(" "))
    governing: list[int] = _enclosing_job_block(lines, scope - 1, indent)
    governing.extend(_own_block(lines, scope))
    for index in governing:
        key = _yaml_key(lines[index])
        if key is None:
            continue
        normalized = key.replace("_", "-").lower()
        if normalized == "continue-on-error":
            return False
        if normalized == "timeout-minutes":
            # A step timeout is a bound, not a skip: only a degenerate bound of
            # zero (or a missing value) can stop the harness from finishing.
            # A real bound such as `timeout-minutes: 30` still executes.
            if _mapping_value_is_falsy(lines[index]):
                return False
            continue
        if key.lower() == "if":
            value = _yaml_value(lines[index])
            if _condition_is_falsy(value):
                return False
            # A condition that is not provably false is still a condition. It
            # runs the step on every dispatch only when it is unconditional
            # (`true`, `always()`, a tautology, or no value at all); anything
            # else depends on run state the workflow does not fix, so the step
            # may be skipped and an execution claim may not assume it ran.
            if not _condition_is_unconditional(value):
                return False
            continue
    return True


def operator_harness_executed(content: str) -> bool:
    """True when the workflow text EXECUTES the Operator test harness.

    The harness mention counts only when `dotnet` is the invoked command: a
    print builtin (`echo`, `Write-Host`, ...) before it on the same code line
    makes the mention its argument (prose, not execution), and anything else
    before it outside YAML framing, chaining separators, or an explicit shell
    wrapper means `dotnet` is not at command position.

    An invocation is execution evidence only when its step can actually execute
    and its result can reach the run (issue #1225 N_step5). A step that is
    conditionally skipped, marked `continue-on-error`, or bounded by a step
    timeout discards the harness result, so the run-summary claim
    `Operator tests: executed ...` is compared against a nonzero executed
    denominator: an invocable line whose step never executes satisfies that
    claim for nothing. The shell must also pass the harness result on: a
    `||`/`|` suppression or a detached `&` after the invocation, and a bare
    `exit 0` as the statement right after it, all replace a harness failure
    with success before anything can observe it, so they are not terminal
    evidence either.
    """
    lines = content.splitlines()
    invocations = _harness_invocations(lines)
    if not invocations:
        return False
    claim_index = content.find(OPERATOR_EXECUTION_CLAIM)
    if claim_index < 0:
        # No execution claim: coverage needs a step that actually executes.
        return any(_step_executes(scope, lines) for scope, _index in invocations)
    # A claim is only satisfied by an executing invocation that precedes it: the
    # evidence must be produced before the summary line asserts the result.
    claim_line = content.count("\n", 0, claim_index) + 1
    return any(
        scope < claim_line and _step_executes(scope, lines)
        for scope, _index in invocations
    )


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    line: int
    detail: str


def _on_block_child_key(line: str) -> str | None:
    """The event name of a block-mapping child of the `on:` section, or None.

    Every YAML spelling of the same key is one key: the name may be single- or
    double-quoted and the `:` may be written with any spacing before it
    (`push:`, `"push":`, `'pull_request_target' :`). GitHub parses each of these
    as the same automatic event, so all of them must be reported; a spelling
    that is not a mapping key at all (a block sequence item, a comment, a
    nested value) is not an event and yields None.
    """
    if _is_yaml_comment(line):
        return None
    match = re.match(r"^ {2}(?:\"([^\"]+)\"|'([^']+)'|([^#\s][^:]*?))\s*:(?:\s|$)", line)
    if match is None:
        return None
    for group in (match.group(1), match.group(2), match.group(3)):
        if group is not None:
            name = group.strip()
            return name or None
    return None


def parse_workflow_events(content: str) -> set[str]:
    """Extract event triggers defined in the top-level 'on:' section.

    Only a top-level mapping key opens the section, so a nested mapping that
    happens to carry an `on:` key (an `env:` variable, a job input) can neither
    shadow the real section nor fabricate a permitted event set from it: a
    shadowed section reports what the shadow says, not what the workflow
    triggers. The block style accepts every YAML spelling of an event key
    (optionally quoted, any spacing before the `:`), because GitHub's own YAML
    semantics carry the event in all of them.
    """
    lines = content.splitlines()
    for index, line in enumerate(lines):
        if line != line.lstrip(" "):
            continue
        if _yaml_key(line) != "on":
            continue
        tail = _yaml_value(line)
        if tail.startswith("[") and tail.endswith("]"):
            return {
                item.strip(" '\"")
                for item in tail[1:-1].split(",")
                if item.strip()
            }
        if tail:
            return {tail}
        events: set[str] = set()
        for candidate in lines[index + 1 :]:
            stripped = candidate.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if candidate == candidate.lstrip():
                break
            name = _on_block_child_key(candidate)
            if name:
                events.add(name)
        return events
    return set()


def event_scalar_list(content: str, event: str, key: str) -> list[str] | None:
    """Values under `key:` inside one top-level event block.

    Returns None when the event is absent, [] when the event is present
    without the key, otherwise the listed values (flow or block style).
    """
    lines = content.splitlines()
    values: list[str] | None = None
    in_list = False
    for line in lines:
        if values is None:
            if re.match(rf"^  {re.escape(event)}:\s*(#.*)?$", line):
                values = []
            continue
        if re.match(r"^  [A-Za-z_][A-Za-z0-9_-]*:\s*(#.*)?$", line):
            break
        if line.strip() and line == line.lstrip():
            break
        key_match = re.match(rf"^    {re.escape(key)}:\s*(.*)$", line)
        if key_match:
            tail = key_match.group(1).split("#", 1)[0].strip()
            if tail.startswith("["):
                return [
                    item.strip(" '\"")
                    for item in tail.strip("[]").split(",")
                    if item.strip()
                ]
            in_list = True
            continue
        if in_list:
            item_match = re.match(r"^      -\s*(\S+)", line)
            if item_match:
                values.append(item_match.group(1).strip("'\""))
            elif line.strip() and not line.startswith("      ") and not line.strip().startswith("#"):
                in_list = False
    return values


def iter_action_references_in_text(content: str) -> list[tuple[int, str]]:
    """(line number, reference) for every third-party `uses:` in one workflow.

    The reference is read from every YAML spelling GitHub accepts, not only from
    a value written on the same physical line as its `uses:` key (issue #1225
    W2): a same-line value, a block-mapping value on the following lines, and a
    flow-mapping value. The block form is exactly the supported input in which
    the human-readable release stays a comment:

        - uses:
            # v4.2.2
            actions/checkout@<sha>

    A value that would cross a `#` comment is not a reference at all: the
    annotation is comment metadata, so a key line that carries only an
    annotation is read exactly like a key line that carries no value, and the
    real reference underneath it is reached. A mutable tag therefore cannot hide
    behind an annotation, and a `uses:` key that carries no reachable value is
    reported with an empty reference so it cannot be dropped from the identity
    record.
    """
    lines = content.splitlines()
    references: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        for key_match in USES_KEY_RE.finditer(line):
            dqkey = key_match.group("dqkey")
            if dqkey is not None and _unescape_yaml_double_quoted(dqkey) != "uses":
                continue
            value_match = USES_VALUE_RE.match(line, key_match.end())
            if value_match is not None:
                references.append(
                    (index + 1, value_match.group("dq") or value_match.group("sq") or value_match.group("plain"))
                )
                break
            resolved = False
            for follow in range(index + 1, len(lines)):
                candidate = lines[follow]
                if _is_yaml_comment(candidate):
                    continue
                if not candidate.strip():
                    continue
                if len(candidate) - len(candidate.lstrip(" ")) <= len(line) - len(line.lstrip(" ")):
                    break
                value_match = USES_VALUE_RE.match(candidate)
                if value_match is None:
                    break
                references.append(
                    (
                        follow + 1,
                        value_match.group("dq") or value_match.group("sq") or value_match.group("plain"),
                    )
                )
                resolved = True
                break
            if not resolved:
                references.append((index + 1, ""))
            break
    return references


def check_workflows(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    workflows_dir = root / ".github" / "workflows"
    if not workflows_dir.is_dir():
        findings.append(Finding("GWF-000", ".github/workflows", 0, "workflows directory missing"))
        return findings

    workflow_files = iter_workflow_files(root)
    if not workflow_files:
        findings.append(Finding("GWF-000", ".github/workflows", 0, "no workflow files found"))
        return findings

    for wf_path in workflow_files:
        rel_path = str(wf_path.relative_to(root)).replace("\\", "/")
        try:
            content = wf_path.read_text(encoding="utf-8")
        except Exception as exc:
            findings.append(Finding("GWF-000", rel_path, 0, f"cannot read file: {exc}"))
            continue

        lines = content.splitlines()

        # 1. Event trigger check: closed per-workflow policy (issue #3004).
        # Default is workflow_dispatch-only; ci.yml is the sole automatic
        # exception with main-scoped pull_request/push.
        events = parse_workflow_events(content)
        allowed_events = WORKFLOW_EVENT_EXCEPTIONS.get(wf_path.name, DEFAULT_ALLOWED_EVENTS)
        if not events:
            findings.append(Finding("GWF-001", rel_path, 1, "missing 'on:' event trigger section"))
        elif events != allowed_events:
            invalid = sorted(events - allowed_events)
            findings.append(
                Finding(
                    "GWF-001",
                    rel_path,
                    1,
                    f"unauthorized workflow triggers {invalid} for {wf_path.name}; only {sorted(allowed_events)} allowed",
                )
            )
        if wf_path.name in WORKFLOW_EVENT_EXCEPTIONS:
            for scoped_event in ("pull_request", "push"):
                if scoped_event in events:
                    branches = event_scalar_list(content, scoped_event, "branches")
                    if branches != CI_MAIN_BRANCHES:
                        findings.append(
                            Finding(
                                "GWF-001",
                                rel_path,
                                1,
                                f"{wf_path.name} {scoped_event} must target branches {CI_MAIN_BRANCHES}",
                            )
                        )
            pr_types = event_scalar_list(content, "pull_request", "types")
            if pr_types is not None and pr_types:
                missing_types = sorted(CI_REQUIRED_PR_TYPES - set(pr_types))
                if missing_types:
                    findings.append(
                        Finding(
                            "GWF-001",
                            rel_path,
                            1,
                            f"{wf_path.name} pull_request types miss required activity {missing_types}",
                        )
                    )

        # 2. Action identity check (issue #1225 step 2): every third-party `uses:`
        # is a reviewed full 40-character commit SHA owned by an approved action
        # owner. The capture below is used for the owner decision, not only for
        # the error message, so a well-formed SHA from an unreviewed publisher
        # still fails. `iter_action_references_in_text` covers the step-level
        # `- uses:`, the job-level reusable `uses:` (no dash), and every value
        # spelling (same line, block mapping, flow mapping), so neither a
        # reusable workflow nor a re-spelled `uses:` value can escape the rule.
        for line_no, action_ref in iter_action_references_in_text(content):
            # Local actions (./.github/actions/...) are exempt from remote SHA pinning
            if action_ref.startswith("./"):
                continue
            if "@" not in action_ref:
                findings.append(
                    Finding(
                        "GWF-002",
                        rel_path,
                        line_no,
                        f"action '{action_ref}' has no version or SHA pin",
                    )
                )
                continue
            action_name, ref = action_ref.split("@", 1)
            # Identity shape: a reference with no owner segment is not an
            # identity this verifier can attest, so it fails on its own code
            # rather than being attributed to the mutable-ref rule.
            if not ACTION_NAME_RE.fullmatch(action_name):
                findings.append(
                    Finding(
                        "GWF-010",
                        rel_path,
                        line_no,
                        f"action reference '{action_ref}' is not an owner/repository identity; "
                        f"expected owner/repo[/path]@<40-hex SHA> with owner in {list(APPROVED_ACTION_OWNERS)}",
                    )
                )
                continue
            if action_name.split("/")[0] not in APPROVED_ACTION_OWNERS:
                findings.append(
                    Finding(
                        "GWF-002",
                        rel_path,
                        line_no,
                        f"unapproved action owner '{action_name.split('/')[0]}' for '{action_name}'; "
                        f"approved owners are {list(APPROVED_ACTION_OWNERS)}",
                    )
                )
                continue
            if not FULL_SHA_RE.fullmatch(ref):
                findings.append(
                    Finding(
                        "GWF-002",
                        rel_path,
                        line_no,
                        f"mutable action ref '{ref}' for '{action_name}'; full 40-character SHA required",
                    )
                )

        # 3. Permissions check: minimal permissions required
        if PERMISSION_WRITE_ALL_RE.search(content):
            findings.append(
                Finding(
                    "GWF-003",
                    rel_path,
                    1,
                    "overbroad permissions (write-all / read-all) forbidden",
                )
            )

        # 4. Operator coverage check, classified by workflow/profile class
        # (issue #3004 item 8). Compile-only MergeCompile workflows restore
        # and build both Operator projects through the shared profile with
        # zero execution and no execution claim. Every other workflow that
        # builds Eliot.Operator must execute the harness (issue #1225 N_step5:
        # execution is an explicit dotnet run/exec of Eliot.Operator.Tests,
        # compared with the operation that would justify the run-summary
        # claim; mere substring presence proves nothing).
        has_operator_build = any(
            "apps/Eliot.Operator/Eliot.Operator.csproj" in workflow_code_line(line)
            for line in lines
        )
        has_operator_test = operator_harness_executed(content)
        # Closed compile-only class: ci.yml is the single workflow that may
        # invoke the MergeCompile profile. repository-policy.yml names the
        # profile only inside its own checker prose (not an invocation) and
        # is exempt; any other file carrying the marker is rejected.
        invokes_mergecompile = COMPILE_ONLY_PROFILE_MARKER in content
        is_compile_only = wf_path.name == "ci.yml" and invokes_mergecompile
        if invokes_mergecompile and wf_path.name not in ("ci.yml", "repository-policy.yml"):
            findings.append(
                Finding(
                    "GWF-006",
                    rel_path,
                    1,
                    f"only ci.yml may invoke {COMPILE_ONLY_PROFILE_MARKER}",
                )
            )
        if is_compile_only:
            if re.search(r"dotnet\s+(run|test|vstest)\b", content):
                findings.append(
                    Finding(
                        "GWF-006",
                        rel_path,
                        1,
                        "compile-only MergeCompile workflow must not execute dotnet run/test",
                    )
                )
            if "Operator tests: executed" in content:
                findings.append(
                    Finding(
                        "GWF-006",
                        rel_path,
                        1,
                        "compile-only MergeCompile workflow must not claim Operator test execution",
                    )
                )
            verify_ps1 = root / "scripts" / "verify.ps1"
            if verify_ps1.is_file():
                try:
                    verify_text = verify_ps1.read_text(encoding="utf-8")
                except Exception as exc:
                    findings.append(
                        Finding("GWF-006", rel_path, 1, f"cannot read scripts/verify.ps1: {exc}")
                    )
                    verify_text = ""
                for need in (
                    "dotnet restore",
                    "dotnet build",
                    "apps/Eliot.Operator/Eliot.Operator.csproj",
                    "tests/Eliot.Operator.Tests/Eliot.Operator.Tests.csproj",
                ):
                    if need not in verify_text:
                        findings.append(
                            Finding(
                                "GWF-006",
                                rel_path,
                                1,
                                f"MergeCompile profile lacks required Operator coverage: {need}",
                            )
                        )
                if re.search(r"dotnet\s+(run|test|vstest)\b", verify_text):
                    findings.append(
                        Finding(
                            "GWF-006",
                            rel_path,
                            1,
                            "verify.ps1 must not execute dotnet run/test in the compile-only class",
                        )
                    )
        elif has_operator_build and not has_operator_test:
            findings.append(
                Finding(
                    "GWF-006",
                    rel_path,
                    1,
                    "workflow builds Eliot.Operator but does not execute test harness tests/Eliot.Operator.Tests",
                )
            )
        elif OPERATOR_EXECUTION_CLAIM in content and not has_operator_test:
            findings.append(
                Finding(
                    "GWF-006",
                    rel_path,
                    1,
                    "workflow claims Operator test execution but never executes "
                    "the Eliot.Operator.Tests harness (dotnet run/exec required)",
                )
            )

        # 5. Workflow naming: manual workflows must indicate manual
        # invocation; ci.yml (the automatic exception) must instead state
        # its compile-only ceiling.
        for line_no, line in enumerate(lines, start=1):
            if line.startswith("name:"):
                wf_name = line.split(":", 1)[1].strip()
                if wf_path.name == "ci.yml":
                    if "compile" not in wf_name.lower():
                        findings.append(
                            Finding(
                                "GWF-007",
                                rel_path,
                                line_no,
                                f"workflow name '{wf_name}' is the automatic ci.yml exception but does not state its compile-only ceiling",
                            )
                        )
                elif "pull request integration" in wf_name.lower() and "manual" not in wf_name.lower():
                    findings.append(
                        Finding(
                            "GWF-007",
                            rel_path,
                            line_no,
                            f"workflow name '{wf_name}' implies automatic PR integration; must indicate manual invocation",
                        )
                    )
                break

        # 6. Local scripts executed in steps must exist
        # We look for execution patterns like 'scripts/foo.py', 'scripts/bar.ps1', but ignore 'forbidden=(' lists
        in_forbidden_block = False
        for line_no, line in enumerate(lines, start=1):
            if "forbidden=(" in line:
                in_forbidden_block = True
                continue
            if in_forbidden_block:
                if line.strip() == ")":
                    in_forbidden_block = False
                continue
            # Match executed scripts
            for match in re.finditer(r"(?:python|pwsh|bash|sh|-File|\.)\s+(?:[^\n]*\s+)?scripts/([a-zA-Z0-9_\-\./]+\.(?:py|ps1|sh))", line):
                s_ref = match.group(1)
                full_script_path = root / "scripts" / s_ref
                if not full_script_path.is_file():
                    findings.append(
                        Finding(
                            "GWF-008",
                            rel_path,
                            line_no,
                            f"executed script does not exist at target: scripts/{s_ref}",
                        )
                    )

    return findings


# Issue #1923 (I18.44): the dimensions a restored cargo cache is trusted across.
# A `~/.cargo/registry` / `~/.cargo/git` restore is reused acquisition state, so
# the key has to separate a cache entry by every dimension that changes whether
# reusing it is safe: the toolchain that will consume it, the source manifests
# that produced it, and the trust class the run runs under. Each entry is a
# (dimension label, regex that must match the key value) pair, and every one is
# required: a key that drops one lets a cache entry cross that boundary.
CACHE_KEY_REQUIRED_BINDINGS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("runner platform", re.compile(r"runner\.os")),
    ("runner architecture", re.compile(r"runner\.arch")),
    ("dependency lock", re.compile(r"hashFiles\(\s*'Cargo\.lock'\s*\)")),
    ("toolchain", re.compile(r"hashFiles\([^)]*'rust-toolchain\.toml'")),
    ("source manifests", re.compile(r"hashFiles\([^)]*Cargo\.toml")),
    ("event/trust class", re.compile(r"event_name")),
    ("fork trust class", re.compile(r"head\.repo\.fork")),
)


def check_cache_key_fingerprints(root: Path) -> list[Finding]:
    """Every `actions/cache` key must bind trust, source and toolchain.

    A key that names only OS+lockfile+profile looks isolated but reuses the same
    entry across a fork pull request, a changed source manifest and a changed
    toolchain. Each missing dimension is its own finding so the report says
    which boundary is open, and the rule is repository-level rather than
    per-file so it also covers a workflow that caches without a `key:` at all.

    EVERY `actions/cache` step in a file is judged, not just the first: a
    workflow that restores the same cargo cache in three jobs would otherwise
    have two of its three keys escape the rule entirely.
    """
    findings: list[Finding] = []
    seen_cache_step = False
    for wf_path in iter_workflow_files(root):
        rel_path = str(wf_path.relative_to(root)).replace("\\", "/")
        try:
            content = wf_path.read_text(encoding="utf-8")
        except Exception:
            continue
        lines = content.splitlines()
        # Each cache step's `key:` lives inside that step's `with:` block, so the
        # search for the next key stops at the next step entry, which is what
        # keeps a sibling job's key from being read as this step's key.
        for cache_line, line in enumerate(lines):
            if "actions/cache@" not in _action_identity_line(line):
                continue
            seen_cache_step = True
            step_indent = len(line) - len(line.lstrip(" "))
            key_line = next(
                (
                    i
                    for i in range(cache_line + 1, len(lines))
                    if _yaml_key(lines[i]) == "key"
                    or (
                        _is_step_entry(lines[i])
                        and len(lines[i]) - len(lines[i].lstrip(" ")) <= step_indent
                    )
                ),
                None,
            )
            if key_line is None or _yaml_key(lines[key_line]) != "key":
                findings.append(
                    Finding(
                        "GWF-020",
                        rel_path,
                        cache_line + 1,
                        "actions/cache step declares no restore key, so every dimension boundary is open",
                    )
                )
                continue
            key_value = _yaml_value(lines[key_line])
            for label, pattern in CACHE_KEY_REQUIRED_BINDINGS:
                if not pattern.search(key_value):
                    findings.append(
                        Finding(
                            "GWF-020",
                            rel_path,
                            key_line + 1,
                            f"cache key does not bind the {label} dimension: {key_value}",
                        )
                    )
    if not seen_cache_step:
        findings.append(
            Finding(
                "GWF-020",
                ".github/workflows",
                0,
                "no workflow restores a cargo cache, so cache isolation is never exercised",
            )
        )
    return findings


# Issue #1923 (I18.44): the source-manifest coverage a cache key must reach.
# `CACHE_KEY_REQUIRED_BINDINGS` only asks whether the key mentions a
# `Cargo.toml` at all, which any glob satisfies. That is a copy of the caller's
# own shape: it cannot tell a glob that reaches every workspace member from one
# that reaches most of them, so a member root the glob misses stays invisible
# and its manifest edits are served from a cache entry acquired under the old
# manifest. The expected set here is read from the root manifest's own
# `[workspace] members` table, never from the glob under test, so a new member
# root added to the workspace is a finding until the key reaches it.


def _hashfiles_manifest_globs(key_value: str) -> list[str]:
    """Manifest glob patterns a cache key hashes, in the order written.

    Every quoted argument of every `hashFiles(...)` in the key is collected; a
    pattern is returned only when it names a `Cargo.toml`, because the other
    hashed inputs (`Cargo.lock`, `rust-toolchain.toml`) are not workspace member
    manifests and are already bound by their own GWF-020 dimension.
    """
    globs: list[str] = []
    for call in re.finditer(r"hashFiles\(([^)]*)\)", key_value):
        for argument in re.findall(r"'([^']*)'", call.group(1)):
            if not argument.endswith("Cargo.toml"):
                continue
            if argument not in globs:
                globs.append(argument)
    return globs


def _glob_matches_path(pattern: str, path: str) -> bool:
    """Whether an `@actions/glob` pattern selects a repository-relative path.

    Mirrors the subset GitHub's `hashFiles` uses: `**` spans any number of
    directories, `*` and `?` stop at one, and `[...]` is a character class. The
    member root is a directory, so coverage is asked of `<root>/Cargo.toml`,
    which is the manifest that actually carries the member's dependencies.
    """
    return fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(path, pattern.replace("**/", ""))


def workspace_member_manifests(root: Path) -> list[str]:
    """Repository-relative manifests of every root `[workspace] members` names.

    The root manifest is the authority: a member it lists is a workspace input
    whether or not any cache key hashes it. `exclude` is not consulted, so a
    member later moved to `exclude` is still required until the table says
    otherwise — an excluded path simply stops being a member and stops being
    required on the next pass.
    """
    manifest = root / "Cargo.toml"
    if not manifest.is_file():
        return []
    try:
        content = manifest.read_text(encoding="utf-8")
    except Exception:
        return []
    members: list[str] = []

    def add_member(entry: str) -> None:
        """Records one member root as the manifest that carries its inputs."""
        candidate = f"{entry.rstrip('/')}/Cargo.toml"
        if candidate not in members:
            members.append(candidate)

    in_workspace = False
    in_members = False
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            # Either spelling is accepted: the dotted `[workspace.members]`
            # table and the `members = [...]` key inside `[workspace]` that
            # this repository actually writes.
            normalized = line.replace(" ", "")
            in_workspace = normalized == "[workspace]"
            in_members = normalized == "[workspace.members]"
            continue
        if in_members:
            if line.startswith("]"):
                in_members = False
                continue
            entry = line.rstrip(",").strip().strip("\"'")
            if entry:
                add_member(entry)
            continue
        if not in_workspace:
            continue
        key, separator, tail = line.partition("=")
        if separator and key.strip() == "members":
            opening = tail.strip()
            if opening in ("[", ""):
                in_members = True
                continue
            # The whole array on one line: every quoted entry is a member.
            for entry in re.findall(r"[\"']([^\"']+)[\"']", opening):
                add_member(entry)
            if "]" not in opening:
                in_members = True
    return members


def check_cache_key_manifest_coverage(root: Path) -> list[Finding]:
    """Every cache key must hash every workspace member manifest.

    A key that names a `Cargo.toml` but whose globs stop short of a member
    root reuses one cache entry across two different resolutions of the
    workspace. The expected set is the root manifest's own member list, so
    this rule is independent of the globs it judges: it cannot be satisfied by
    restating the same pattern the workflows already use.
    """
    expected = workspace_member_manifests(root)
    if not expected:
        return [
            Finding(
                "GWF-021",
                "Cargo.toml",
                0,
                "no workspace members could be read from the root manifest, so cache key manifest coverage cannot be judged",
            )
        ]
    findings: list[Finding] = []
    for wf_path in iter_workflow_files(root):
        rel_path = str(wf_path.relative_to(root)).replace("\\", "/")
        try:
            content = wf_path.read_text(encoding="utf-8")
        except Exception:
            continue
        lines = content.splitlines()
        for cache_line, line in enumerate(lines):
            if "actions/cache@" not in _action_identity_line(line):
                continue
            step_indent = len(line) - len(line.lstrip(" "))
            key_line = next(
                (
                    i
                    for i in range(cache_line + 1, len(lines))
                    if _yaml_key(lines[i]) == "key"
                    or (
                        _is_step_entry(lines[i])
                        and len(lines[i]) - len(lines[i].lstrip(" ")) <= step_indent
                    )
                ),
                None,
            )
            if key_line is None or _yaml_key(lines[key_line]) != "key":
                # GWF-020 already reports a key-less cache step; do not
                # restate it as a coverage gap.
                continue
            globs = _hashfiles_manifest_globs(_yaml_value(lines[key_line]))
            uncovered = [
                manifest
                for manifest in expected
                if not any(_glob_matches_path(pattern, manifest) for pattern in globs)
            ]
            if uncovered:
                findings.append(
                    Finding(
                        "GWF-021",
                        rel_path,
                        key_line + 1,
                        f"cache key hashes {len(globs)} manifest pattern(s) but misses "
                        f"{len(uncovered)} workspace member manifest(s): "
                        f"{', '.join(sorted(uncovered))}",
                    )
                )
    return findings


def iter_workflow_files(root: Path) -> list[Path]:
    """Every workflow file in the one closed directory, deterministically ordered."""
    workflows_dir = root / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return []
    return sorted([*workflows_dir.glob("*.yml"), *workflows_dir.glob("*.yaml")])


def iter_action_references(root: Path):
    """Yield (rel_path, line_no, action_ref) for every third-party `uses:` ref.

    Derived from the files, never hand-written. Mirrors the
    `iter_action_references_in_text` handling in check_workflows, including the
    `./` local-action exemption, so the identity record and the enforcement
    decision can never disagree about which references are in scope: every
    YAML spelling of a `uses:` value the rules judge is also a reference the
    run manifest records.
    """
    for wf_path in iter_workflow_files(root):
        rel_path = str(wf_path.relative_to(root)).replace("\\", "/")
        try:
            content = wf_path.read_text(encoding="utf-8")
        except Exception:
            continue
        for line_no, action_ref in iter_action_references_in_text(content):
            if action_ref.startswith("./"):
                continue
            yield rel_path, line_no, action_ref


def collect_action_identities(root: Path) -> list[dict[str, str]]:
    """Derived owner/repository/SHA identity for every third-party `uses:` ref.

    This is the source of truth for the run manifest's action record: no workflow
    hand-types its action list. The returned list is sorted by
    (workflow, line, action, ref) so repeated runs over an unchanged tree produce
    a byte-identical payload, and it is bounded by the number of `uses:` lines in
    the repository. `ref` is empty when the reference carries no `@` pin, so an
    unpinned reference is still recorded rather than silently dropped.
    """
    records: list[dict[str, str]] = []
    for rel_path, line_no, action_ref in iter_action_references(root):
        if "@" in action_ref:
            action_name, ref = action_ref.split("@", 1)
        else:
            action_name, ref = action_ref, ""
        records.append(
            {
                "workflow": rel_path,
                "line": str(line_no),
                "action": action_name,
                "ref": ref,
            }
        )
    records.sort(key=lambda r: (r["workflow"], int(r["line"]), r["action"], r["ref"]))
    return records


# Oracle-owned files (issue #1225 N_step10). A change to workflow YAML, this
# verifier, profile definitions, lock validation or the repository-policy
# denominator cannot use only its newly modified oracle as acceptance (I18.27:
# "Changes to implementation and oracle in one candidate are split unless the
# oracle is mechanically derived from the same unchanged source"). The run
# manifest therefore records the exact oracle bytes behind the verdict, so the
# existing independent/manual source-candidate or Review owner attests a named
# oracle instead of a self-certified pass: a candidate that weakens any file
# below ships a manifest whose digest differs from the reviewed baseline.
ORACLE_VERSION = "github-workflow-oracle-v1"
ORACLE_OWNED_PATHS = (
    "scripts/verify-github-workflows.py",
    ".github/workflows/ci.yml",
    ".github/workflows/integration.yml",
    ".github/workflows/repository-policy.yml",
    ".github/workflows/source-candidate.yml",
    "scripts/verify.ps1",
)


def collect_oracle_identity(root: Path) -> dict[str, Any]:
    """Digest identity for the oracle files that produced this verdict.

    Sorted and bounded like collect_action_identities: an unchanged tree yields
    a byte-identical record, and any oracle byte change alters `digest`. Files
    absent from `root` are omitted from `files` (a fixture tree carries no
    oracle), so the record never fails a tree it only describes; judging
    workflows is left to the check_* rules.
    """
    files: list[dict[str, str]] = []
    for rel_path in ORACLE_OWNED_PATHS:
        candidate = root.joinpath(*rel_path.split("/"))
        if not candidate.is_file():
            continue
        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        files.append({"path": rel_path, "sha256": digest})
    combined = hashlib.sha256(
        "".join(f"{entry['path']}\0{entry['sha256']}\n" for entry in files).encode("utf-8")
    ).hexdigest()
    return {"version": ORACLE_VERSION, "digest": combined, "files": files}


def check_action_pin_divergence(root: Path) -> list[Finding]:
    """One action, one pin: reject the same action carried at two different SHAs.

    Without this, a future workflow can silently introduce a different (possibly
    compromised) commit for an action the repository already pins, and every
    per-file check still passes because each reference is individually
    well-formed. The first workflow in deterministic order is the reference
    observation and is never itself a finding; each divergent reference is.
    """
    findings: list[Finding] = []
    first_ref: dict[str, tuple[str, int, str]] = {}
    for rel_path, line_no, action_ref in iter_action_references(root):
        if "@" not in action_ref:
            continue
        action_name, ref = action_ref.split("@", 1)
        if not ACTION_NAME_RE.fullmatch(action_name):
            continue
        observed = first_ref.get(action_name)
        if observed is None:
            first_ref[action_name] = (rel_path, line_no, ref)
            continue
        if ref == observed[2]:
            continue
        findings.append(
            Finding(
                "GWF-011",
                rel_path,
                line_no,
                f"action '{action_name}' diverges from its repository pin: "
                f"{ref} here but {observed[2]} at {observed[0]}:{observed[1]}; "
                "one action carries one reviewed commit SHA across all workflows",
            )
        )
    return findings


def check_python_requirements(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    req_file = root / "scripts" / "requirements-verification.txt"
    rel_path = "scripts/requirements-verification.txt"
    if not req_file.is_file():
        findings.append(Finding("GWF-004", rel_path, 0, "requirements-verification.txt missing"))
        return findings

    content = req_file.read_text(encoding="utf-8")
    lines = content.splitlines()
    current_package: str | None = None
    has_hash = False

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("--hash="):
            if not current_package:
                findings.append(
                    Finding("GWF-004", rel_path, line_no, "orphan --hash line without preceding package")
                )
            elif not re.fullmatch(r"--hash=sha256:[0-9a-fA-F]{64}\s*\\?", stripped):
                findings.append(
                    Finding("GWF-004", rel_path, line_no, f"invalid hash format on line: {stripped}")
                )
            else:
                has_hash = True
            continue

        # Encountered a new package line
        if current_package and not has_hash:
            findings.append(
                Finding(
                    "GWF-004",
                    rel_path,
                    line_no - 1,
                    f"package '{current_package}' is missing required --hash=sha256",
                )
            )

        pkg_part = stripped.rstrip("\\").strip()
        if "==" not in pkg_part:
            findings.append(
                Finding(
                    "GWF-004",
                    rel_path,
                    line_no,
                    f"package requirement '{pkg_part}' is not exact version-pinned with ==",
                )
            )
        current_package = pkg_part
        has_hash = False

    if current_package and not has_hash:
        findings.append(
            Finding(
                "GWF-004",
                rel_path,
                len(lines),
                f"package '{current_package}' is missing required --hash=sha256",
            )
        )

    return findings


NUGET_LOCKED_PROJECTS = (
    ("apps/Eliot.Operator/Eliot.Operator.csproj", "apps/Eliot.Operator/packages.lock.json"),
    ("tests/Eliot.Operator.Tests/Eliot.Operator.Tests.csproj", "tests/Eliot.Operator.Tests/packages.lock.json"),
)
# Project graph facts the lock must already agree with. A `PackageReference`
# whose version is an MSBuild expression cannot be checked against a checked-in
# lock without evaluating the project, so it is reported instead of assumed
# clean. `TargetFramework` selects the lock's dependency frame; NuGet shortens
# the platform version, so `net10.0-windows10.0.19041.0` is locked under
# `net10.0-windows10.0.19041` and the frame is matched on a segment boundary.
TARGET_FRAMEWORK_RE = re.compile(r"<TargetFramework>([^<]+)</TargetFramework>")
TFM_BAND_RE = re.compile(r"^net(\d+)\.(\d+)")
PACKAGE_REFERENCE_RE = re.compile(r"<PackageReference\b[^>]*>")
INCLUDE_ATTR_RE = re.compile(r'Include="([^"]+)"')
VERSION_ATTR_RE = re.compile(r'Version="([^"]+)"')
# `global.json` rollForward is a closed vocabulary defined by the .NET SDK; an
# open value would let a future SDK band outside the accepted identity resolve
# silently.
SDK_ROLL_FORWARD_VALUES = (
    "patch",
    "feature",
    "latestPatch",
    "minor",
    "latestFeature",
    "major",
    "latestMajor",
    "disable",
)
SDK_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def lock_frame_for_target_framework(frames: dict, target_framework: str) -> str | None:
    """The lock frame that covers one project's TargetFramework, or None."""
    for key in sorted(frames):
        if key == target_framework or target_framework.startswith(f"{key}."):
            return key
    return None


def check_nuget_lock_graph(rel_csproj: str, rel_lock: str, content: str, lock: Any) -> list[Finding]:
    """The checked-in lock must already describe the project's current graph.

    `--locked-mode` already fails a restore that would change lock state, but
    only where a restore actually runs (Windows, with an installed SDK). A
    `PackageReference` edit that leaves the checked-in lock stale is graph drift
    that is visible in source today, so it is rejected here instead of waiting
    for a restore. docs/DEPENDENCY_POLICY.md states the same binding: direct
    project PackageReference entries are bound to the configured lock target and
    inventory versions.
    """
    findings: list[Finding] = []
    if not isinstance(lock, dict) or lock.get("version") != 1:
        findings.append(
            Finding(
                "GWF-013",
                rel_lock,
                1,
                f"{rel_lock} is not a version 1 NuGet lock file",
            )
        )
        return findings
    frames = lock.get("dependencies")
    if not isinstance(frames, dict):
        findings.append(Finding("GWF-013", rel_lock, 1, f"{rel_lock} has no dependencies map"))
        return findings

    target_framework_match = TARGET_FRAMEWORK_RE.search(content)
    references = PACKAGE_REFERENCE_RE.findall(content)
    if target_framework_match is None:
        if references:
            findings.append(
                Finding(
                    "GWF-013",
                    rel_csproj,
                    1,
                    f"{rel_csproj} declares PackageReference entries but no TargetFramework, "
                    "so its checked-in lock cannot be bound to a project graph",
                )
            )
        return findings

    target_framework = target_framework_match.group(1)
    frame = lock_frame_for_target_framework(frames, target_framework)
    if frame is None:
        findings.append(
            Finding(
                "GWF-013",
                rel_lock,
                1,
                f"{rel_lock} has no dependency frame for {rel_csproj} TargetFramework {target_framework}; "
                "the checked-in lock is stale for this project",
            )
        )
        return findings

    frame_dependencies = frames.get(frame)
    if not isinstance(frame_dependencies, dict):
        frame_dependencies = {}
    for element in references:
        include = INCLUDE_ATTR_RE.search(element)
        version = VERSION_ATTR_RE.search(element)
        if include is None or version is None:
            findings.append(
                Finding(
                    "GWF-013",
                    rel_csproj,
                    1,
                    f"{rel_csproj} has a PackageReference without a literal Include/Version "
                    f"({element.strip()}), so it cannot be verified against {rel_lock}",
                )
            )
            continue
        name = include.group(1)
        declared = version.group(1)
        entry = frame_dependencies.get(name)
        if not isinstance(entry, dict):
            findings.append(
                Finding(
                    "GWF-013",
                    rel_lock,
                    1,
                    f"{name} is a direct dependency of {rel_csproj} but absent from the "
                    f"{frame} frame of {rel_lock}; regenerate the checked-in lock",
                )
            )
            continue
        if entry.get("resolved") != declared:
            findings.append(
                Finding(
                    "GWF-013",
                    rel_lock,
                    1,
                    f"{name} resolves to {entry.get('resolved')!r} in the {frame} frame of "
                    f"{rel_lock} but {rel_csproj} declares {declared!r}",
                )
            )
    return findings


def check_dotnet_sdk_identity(root: Path) -> list[Finding]:
    """The .NET SDK must be pinned by a repository global.json, not the runner.

    Without global.json, `dotnet` resolves to whatever SDK the machine or runner
    image happens to carry, so the .NET toolchain input of both locked Operator
    projects is unbound. The accepted identity is derived, not asserted: the
    pinned SDK band must equal the `net<major>.<minor>` band of the target
    frameworks the locked projects declare, and the exact patch stays per-run
    evidence (`dotnet --version`, `$(NETCoreSdkVersion)` in the Operator build
    receipt). No version is hardcoded here.
    """
    findings: list[Finding] = []
    bands: dict[str, str] = {}
    for rel_csproj, _rel_lock in NUGET_LOCKED_PROJECTS:
        csproj_path = root.joinpath(*rel_csproj.split("/"))
        if not csproj_path.is_file():
            continue
        target_framework = TARGET_FRAMEWORK_RE.search(csproj_path.read_text(encoding="utf-8"))
        if target_framework is None:
            continue
        band = TFM_BAND_RE.match(target_framework.group(1))
        if band is None:
            findings.append(
                Finding(
                    "GWF-014",
                    rel_csproj,
                    1,
                    f"unrecognised TargetFramework {target_framework.group(1)!r}; "
                    "the required .NET SDK band cannot be derived from it",
                )
            )
            continue
        bands[f"{band.group(1)}.{band.group(2)}"] = rel_csproj
    if not bands:
        return findings

    global_json = root / "global.json"
    if not global_json.is_file():
        findings.append(
            Finding(
                "GWF-014",
                "global.json",
                0,
                "no explicit .NET SDK identity: global.json is missing, so `dotnet` "
                "resolves to whatever SDK the machine carries",
            )
        )
        return findings
    try:
        document = json.loads(global_json.read_text(encoding="utf-8"))
    except Exception as exc:
        findings.append(Finding("GWF-014", "global.json", 1, f"corrupted global.json: {exc}"))
        return findings
    sdk = document.get("sdk") if isinstance(document, dict) else None
    if not isinstance(sdk, dict):
        findings.append(Finding("GWF-014", "global.json", 1, "global.json has no sdk object"))
        return findings
    version = sdk.get("version")
    version_match = SDK_VERSION_RE.fullmatch(version) if isinstance(version, str) else None
    if version_match is None:
        findings.append(
            Finding(
                "GWF-014",
                "global.json",
                1,
                f"global.json sdk.version is not an exact SDK version: {version!r}",
            )
        )
        return findings
    if sdk.get("rollForward") not in SDK_ROLL_FORWARD_VALUES:
        findings.append(
            Finding(
                "GWF-014",
                "global.json",
                1,
                f"global.json sdk.rollForward {sdk.get('rollForward')!r} is outside the closed "
                f"SDK vocabulary {list(SDK_ROLL_FORWARD_VALUES)}",
            )
        )
    if sdk.get("allowPrerelease") is not False:
        findings.append(
            Finding(
                "GWF-014",
                "global.json",
                1,
                "global.json sdk.allowPrerelease must be false; a preview SDK is not the accepted identity",
            )
        )
    pinned_band = f"{version_match.group(1)}.{version_match.group(2)}"
    for band, rel_csproj in sorted(bands.items()):
        if pinned_band != band:
            findings.append(
                Finding(
                    "GWF-014",
                    "global.json",
                    1,
                    f"global.json pins .NET SDK band {pinned_band} but {rel_csproj} targets net{band}",
                )
            )
    return findings


def check_nuget_lock(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for rel_csproj, rel_lock in NUGET_LOCKED_PROJECTS:
        csproj_path = root.joinpath(*rel_csproj.split("/"))
        if not csproj_path.is_file():
            continue
        content = csproj_path.read_text(encoding="utf-8")
        if "<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>" not in content:
            findings.append(
                Finding(
                    "GWF-005",
                    rel_csproj,
                    1,
                    f"missing <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile> in {rel_csproj}",
                )
            )
        lock_file = root.joinpath(*rel_lock.split("/"))
        if not lock_file.is_file():
            findings.append(
                Finding(
                    "GWF-005",
                    rel_lock,
                    0,
                    f"checked-in NuGet {rel_lock} is missing for locked restore",
                )
            )
            continue
        try:
            lock = json.loads(lock_file.read_text(encoding="utf-8"))
        except Exception as exc:
            findings.append(
                Finding(
                    "GWF-005",
                    rel_lock,
                    1,
                    f"corrupted {rel_lock}: {exc}",
                )
            )
            continue
        findings.extend(check_nuget_lock_graph(rel_csproj, rel_lock, content, lock))

    return findings


def check_pip_install_lock(root: Path) -> list[Finding]:
    """Every workflow pip install must consume the hash-locked closure."""
    findings: list[Finding] = []
    workflows_dir = root / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return findings
    for wf_path in sorted([*workflows_dir.glob("*.yml"), *workflows_dir.glob("*.yaml")]):
        rel_path = str(wf_path.relative_to(root)).replace("\\", "/")
        try:
            lines = wf_path.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue
        for line_no, line in enumerate(lines, start=1):
            if "pip install" not in line:
                continue
            if "--require-hashes" not in line or "scripts/requirements-verification.txt" not in line:
                findings.append(
                    Finding(
                        "GWF-009",
                        rel_path,
                        line_no,
                        "pip install must use --require-hashes -r scripts/requirements-verification.txt",
                    )
                )
    return findings


def check_dotnet_restore_lock(root: Path) -> list[Finding]:
    """Every workflow dotnet restore must run in locked mode.

    A restore without --locked-mode may silently resolve a new dependency
    graph or mutate the checked-in packages.lock.json instead of failing on
    drift, so it cannot satisfy the NuGet lock contract (issue #1225 step
    4). Quoted prose and trailing comments are not gate invocations: string
    literals (for example a checker asserting on the 'dotnet restore'
    marker) and '#' comments are stripped before matching, so only real
    restore commands are judged.
    """
    findings: list[Finding] = []
    for wf_path in iter_workflow_files(root):
        rel_path = str(wf_path.relative_to(root)).replace("\\", "/")
        try:
            lines = wf_path.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue
        for line_no, line in enumerate(lines, start=1):
            if "dotnet restore" not in line:
                continue
            code = re.sub(r'"[^"]*"', "", line)
            code = re.sub(r"'[^']*'", "", code)
            code = code.split("#", 1)[0]
            if "dotnet restore" not in code:
                continue
            if "--locked-mode" not in code:
                findings.append(
                    Finding(
                        "GWF-012",
                        rel_path,
                        line_no,
                        "dotnet restore must use --locked-mode against the checked-in packages.lock.json",
                    )
                )
    return findings


def check_fail_closed_privilege(root: Path) -> list[Finding]:
    """Permissions, credentials and secrets stay fail-closed on every workflow.

    Least privilege (issue #1225 step 8, AC9): an elevated `write`/`admin`
    grant, a `secrets.*` interpolation, or an OIDC `id-token` authority fails
    wherever it is written, and a checkout step without
    `persist-credentials: false` in its own step block fails so credentials
    cannot reach candidate processes, logs, summaries, caches or artifacts.
    The checkout verdict is block-scoped, so one conforming step never covers
    a sibling that persists credentials.
    """
    findings: list[Finding] = []
    for wf_path in iter_workflow_files(root):
        rel_path = str(wf_path.relative_to(root)).replace("\\", "/")
        try:
            lines = wf_path.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue
        for line_no, line in enumerate(lines, start=1):
            code = workflow_code_line(line)
            if ELEVATED_PERMISSION_RE.search(code):
                findings.append(
                    Finding(
                        "GWF-021",
                        rel_path,
                        line_no,
                        "elevated permission grant forbidden; workflows run least-privilege read-only",
                    )
                )
            if SECRET_REF_RE.search(code):
                findings.append(
                    Finding(
                        "GWF-021",
                        rel_path,
                        line_no,
                        "secret material forbidden in workflow text; fork/untrusted code must never receive it",
                    )
                )
            if OIDC_TOKEN_RE.search(code):
                findings.append(
                    Finding(
                        "GWF-021",
                        rel_path,
                        line_no,
                        "OIDC id-token authority forbidden without a separately accepted workflow owner",
                    )
                )
        for index, line in enumerate(lines):
            if "actions/checkout@" not in _action_identity_line(line):
                continue
            item = _nearest_list_item(lines, index)
            block = _own_block(lines, item) if item is not None else [index]
            if not any(
                _yaml_key(lines[owned]) == "persist-credentials"
                and _yaml_value(lines[owned]) == "false"
                for owned in block
            ):
                findings.append(
                    Finding(
                        "GWF-021",
                        rel_path,
                        index + 1,
                        "actions/checkout step must carry persist-credentials: false in its own step block",
                    )
                )
    return findings


def verify_all(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(check_workflows(root))
    findings.extend(check_fail_closed_privilege(root))
    findings.extend(check_action_pin_divergence(root))
    findings.extend(check_cache_key_fingerprints(root))
    findings.extend(check_cache_key_manifest_coverage(root))
    findings.extend(check_python_requirements(root))
    findings.extend(check_nuget_lock(root))
    findings.extend(check_dotnet_sdk_identity(root))
    findings.extend(check_dotnet_restore_lock(root))
    findings.extend(check_pip_install_lock(root))
    return findings


def run_self_tests() -> int:
    import contextlib
    import io
    import tempfile

    # Production-dispatch probes (issue #1225 N_step9). Every refusal below is
    # judged twice: once against its own rule and once through verify_all, the
    # production dispatch owner. Deleting a rule from verify_all, or gutting
    # its body while leaving the dispatch line, still fails the suite because
    # the re-judgment no longer carries the expected code. `probed_rules`
    # records which production rule each probe verified, so the completeness
    # check at the end proves EVERY check_* rule was exercised, not just the
    # ones this file historically called directly.
    dispatch_probes = 0
    probed_rules: set[str] = set()

    def require_dispatched(tmp_root: Path, direct: list[Finding], case_name: str, rule_name: str) -> bool:
        """Re-judge a refusal through verify_all and record the rule probed.

        Asserts every finding the direct rule call just produced reappears in
        the production dispatch output with identical code, path, line and
        detail. Code membership alone is not enough: two rules can share one
        code (GWF-021 is emitted by both the privilege rule and the
        cache-manifest-coverage rule), so a dispatched code does not prove
        the rule under test ran. Prints the failure and returns False
        otherwise; the caller turns False into a nonzero exit.
        """
        nonlocal dispatch_probes
        dispatched = set(verify_all(tmp_root))
        missing = [f for f in direct if f not in dispatched]
        if missing:
            print(
                f"SELF_TEST_FAILURE in {case_name}: {len(missing)} refusal finding(s) from "
                f"{rule_name} missing from the production dispatch: {missing}",
                file=sys.stderr,
            )
            return False
        probed_rules.add(rule_name)
        dispatch_probes += 1
        return True

    # (name, filename, workflow yaml, expected finding or None for clean[, extra files]).
    # Negative fixtures stay on test.yml (default dispatch-only policy); the
    # ci.yml exception and the compile-only Operator class get their own cases.
    ci_triggers = (
        "on:\n  workflow_dispatch:\n  pull_request:\n    branches: [main]\n"
        "    types: [opened, synchronize, reopened, ready_for_review]\n  push:\n    branches: [main]\n"
    )
    ci_prefix = "name: Automatic PR Merge Compile Gate\n" + ci_triggers + "permissions:\n  contents: read\n"
    # Action-identity fixtures (issue #1225 step 2). `gate_yaml` wraps a
    # `uses:` body in an otherwise conforming manual-dispatch workflow so a
    # rejection can only come from the action rule under test.
    gate_yaml = (
        "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n"
        "    runs-on: ubuntu-latest\n    steps:\n      {body}\n"
    )
    # A second 40-hex SHA, so divergence cases are distinguishable from the
    # reviewed actions/checkout pin by value and not only by position.
    other_sha = "a" * 40

    def step_uses(ref: str) -> str:
        return gate_yaml.format(body=f"- uses: {ref}")

    def job_uses(ref: str) -> str:
        # Job-level reusable workflow: `uses:` at job scope carries no dash.
        return (
            "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\n"
            "jobs:\n  t:\n    uses: " + ref + "\n"
        )

    def operator_case(tail: str) -> str:
        """A manual workflow that builds the Operator, invokes the harness with
        `tail` appended, and then keeps the terminal execution claim. `tail` is
        the only variable, so a verdict can only come from the harness-result
        rule under test."""
        return (
            "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\n"
            "jobs:\n  t:\n    runs-on: windows-latest\n    steps:\n"
            "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
            "      - run: dotnet build apps/Eliot.Operator/Eliot.Operator.csproj -c Release --no-restore\n"
            "      - name: Execute Eliot.Operator test harness\n"
            "        run: dotnet run --project tests/Eliot.Operator.Tests/Eliot.Operator.Tests.csproj -c Release" + tail + "\n"
            "      - run: echo \"Operator tests: executed Eliot.Operator.Tests (exit 0)\"\n"
        )

    test_cases = [
        ("trigger_push", "test.yml", "on:\n  push:\n    branches: [main]\n", "GWF-001"),
        ("trigger_pr", "test.yml", "on:\n  pull_request:\n", "GWF-001"),
        ("mutable_action", "test.yml", "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n", "GWF-002"),
        ("write_all_perms", "test.yml", "name: Manual Gate\non:\n  workflow_dispatch:\npermissions: write-all\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n", "GWF-003"),
        ("build_only_operator", "test.yml", "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: windows-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - run: dotnet build apps/Eliot.Operator/Eliot.Operator.csproj\n", "GWF-006"),
        # --- Operator harness execution evidence (issue #1225 N_step5) ---
        # A locked-mode restore line carries the `tests/Eliot.Operator.Tests`
        # substring but never runs the harness: restore-only must fail.
        ("operator_restore_only_rejected", "test.yml", "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: windows-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - run: dotnet restore apps/Eliot.Operator/Eliot.Operator.csproj --locked-mode\n      - run: dotnet restore tests/Eliot.Operator.Tests/Eliot.Operator.Tests.csproj --locked-mode\n      - run: dotnet build apps/Eliot.Operator/Eliot.Operator.csproj -c Release --no-restore\n", "GWF-006"),
        # A step named for harness execution whose body never invokes it, with
        # the run-summary claim kept, must fail: the claim is compared with the
        # operation that would justify it, not with the step name.
        ("operator_fake_harness_body_rejected", "test.yml", "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: windows-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - run: dotnet build apps/Eliot.Operator/Eliot.Operator.csproj -c Release --no-restore\n      - name: Execute Eliot.Operator test harness\n        run: Write-Host \"harness intentionally not executed\"\n      - run: echo \"Operator tests: executed Eliot.Operator.Tests (exit 0)\"\n", "GWF-006"),
        # An executed-test claim with no harness invocation at all must fail,
        # even when nothing is built: zero/nonexecuted checks cannot satisfy an
        # execution claim.
        ("operator_claim_without_execution_rejected", "test.yml", "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: windows-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - run: echo \"Operator tests: executed Eliot.Operator.Tests (exit 0)\"\n", "GWF-006"),
        # An `echo` of the harness command is prose, not execution: the
        # invocation-shaped substring is an argument to echo, so the build
        # plus the terminal claim still fail without a real invocation.
        ("operator_echo_bypass_rejected", "test.yml", "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: windows-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - run: dotnet build apps/Eliot.Operator/Eliot.Operator.csproj -c Release --no-restore\n      - run: echo dotnet run --project tests/Eliot.Operator.Tests/Eliot.Operator.Tests.csproj -c Release --no-restore\n      - run: echo \"Operator tests: executed Eliot.Operator.Tests (exit 0)\"\n", "GWF-006"),
        # Same bypass through the PowerShell print builtin, unquoted: still
        # prose, so the build still fails without a real invocation.
        ("operator_write_host_bypass_rejected", "test.yml", "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: windows-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - run: dotnet build apps/Eliot.Operator/Eliot.Operator.csproj -c Release --no-restore\n      - run: Write-Host dotnet run tests/Eliot.Operator.Tests please\n      - run: echo \"Operator tests: executed Eliot.Operator.Tests (exit 0)\"\n", "GWF-006"),
        # The true shape passes: build plus an explicit dotnet run of the
        # harness project plus the terminal execution claim.
        ("operator_execution_accepted", "test.yml", "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: windows-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - run: dotnet build apps/Eliot.Operator/Eliot.Operator.csproj -c Release --no-restore\n      - run: dotnet run --project tests/Eliot.Operator.Tests/Eliot.Operator.Tests.csproj -c Release --no-restore\n      - run: echo \"Operator tests: executed Eliot.Operator.Tests (exit 0)\"\n", None),
        # --- Shell-level failure suppression (issue #1225 N_step5) ---
        # Each shape below keeps `dotnet` at command position and keeps the
        # terminal execution claim, yet replaces a harness failure with
        # success, so the run can report a passing run over a harness that
        # never reached its own result. A `2>&1` redirection is not one of
        # them and stays accepted.
        ("operator_failure_suppression_or_rejected", "test.yml", operator_case(" --no-restore || exit 0"), "GWF-006"),
        ("operator_failure_suppression_pipe_rejected", "test.yml", operator_case(" --no-restore | Out-Null"), "GWF-006"),
        ("operator_failure_suppression_background_rejected", "test.yml", operator_case(" --no-restore &"), "GWF-006"),
        ("operator_adjacent_exit_zero_rejected", "test.yml", operator_case(" --no-restore\n        exit 0"), "GWF-006"),
        ("operator_redirect_accepted", "test.yml", operator_case(" --no-restore 2>&1"), None),
        ("operator_guarded_exit_zero_accepted", "test.yml", operator_case(" --no-restore\n        if [ $? -ne 0 ]; then exit 1; fi"), None),
        ("ci_exception_accepted", "ci.yml", ci_prefix + "jobs:\n  check:\n    runs-on: windows-latest\n    steps:\n      # invokes -Profile MergeCompile through the shared profile owner\n      - run: echo merge-compile-check\n", None),
        ("ci_pr_target_rejected", "ci.yml", "name: Automatic PR Merge Compile Gate\non:\n  workflow_dispatch:\n  pull_request_target:\n    branches: [main]\n  push:\n    branches: [main]\npermissions:\n  contents: read\njobs:\n  check:\n    runs-on: windows-latest\n    steps:\n      - run: echo never\n", "GWF-001"),
        ("ci_unscoped_push_rejected", "ci.yml", "name: Automatic PR Merge Compile Gate\non:\n  workflow_dispatch:\n  pull_request:\n    branches: [main]\n  push:\npermissions:\n  contents: read\njobs:\n  check:\n    runs-on: windows-latest\n    steps:\n      - run: echo never\n", "GWF-001"),
        ("other_workflow_push_rejected", "policy.yml", "name: Manual Policy Gate\non:\n  workflow_dispatch:\n  push:\n    branches: [main]\npermissions:\n  contents: read\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo never\n", "GWF-001"),
        ("mergecompile_dotnet_run_rejected", "ci.yml", ci_prefix + "jobs:\n  check:\n    runs-on: windows-latest\n    steps:\n      - run: pwsh -NoProfile -File scripts/verify.ps1 -Profile MergeCompile\n      - run: dotnet test tests/Eliot.Operator.Tests/Eliot.Operator.Tests.csproj\n", "GWF-006"),
        ("mergecompile_claim_rejected", "ci.yml", ci_prefix + "jobs:\n  check:\n    runs-on: windows-latest\n    steps:\n      # invokes -Profile MergeCompile through the shared profile owner\n      - run: echo \"Operator tests: executed Eliot.Operator.Tests\"\n", "GWF-006"),
        ("mergecompile_clean_accepted", "ci.yml", ci_prefix + "jobs:\n  check:\n    runs-on: windows-latest\n    steps:\n      # invokes -Profile MergeCompile through the shared profile owner\n      - run: echo merge-compile-check\n", None, {"scripts/verify.ps1": "# stub profile owner\ndotnet restore apps/Eliot.Operator/Eliot.Operator.csproj --locked-mode\ndotnet restore tests/Eliot.Operator.Tests/Eliot.Operator.Tests.csproj --locked-mode\ndotnet build apps/Eliot.Operator/Eliot.Operator.csproj\ndotnet build tests/Eliot.Operator.Tests/Eliot.Operator.Tests.csproj\n"}),
        ("mergecompile_elsewhere_rejected", "extra.yml", "name: Manual Extra Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  check:\n    runs-on: windows-latest\n    steps:\n      - run: pwsh -NoProfile -File scripts/verify.ps1 -Profile MergeCompile\n", "GWF-006"),
        ("policy_checker_exempt", "repository-policy.yml", "name: Manual Repository Policy Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"asserts -Profile MergeCompile wiring\"\n", None),
        # --- Action identity (issue #1225 step 2) ---
        # An unapproved owner fails even with a syntactically perfect 40-hex
        # SHA: a valid pin is not on its own an approved identity.
        ("unapproved_owner_rejected", "test.yml", step_uses(f"evilcorp/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"), "GWF-002"),
        # Job-level reusable workflow `uses:` has no leading dash. This is the
        # blind spot the dash-optional ACTION_REF_RE closes: a mutable ref here
        # was previously not parsed at all.
        ("reusable_workflow_mutable_ref_rejected", "test.yml", job_uses("actions/reusable/.github/workflows/x.yml@v1"), "GWF-002"),
        ("reusable_workflow_expression_rejected", "test.yml", job_uses("actions/reusable/.github/workflows/x.yml@${{ inputs.ref }}"), "GWF-002"),
        ("reusable_workflow_pinned_accepted", "test.yml", job_uses("actions/reusable/.github/workflows/x.yml@11bd71901bbe5b1630ceea73d27597364c9af683"), None),
        ("expression_ref_rejected", "test.yml", step_uses("actions/checkout@${{ env.ACTION_SHA }}"), "GWF-002"),
        ("short_sha_rejected", "test.yml", step_uses("actions/checkout@11bd7190"), "GWF-002"),
        ("branch_ref_rejected", "test.yml", step_uses("actions/checkout@main"), "GWF-002"),
        ("wildcard_ref_rejected", "test.yml", step_uses("actions/checkout@*"), "GWF-002"),
        # No owner segment: the reference is not an owner/repository identity.
        ("malformed_action_name_rejected", "test.yml", step_uses(f"checkout@11bd71901bbe5b1630ceea73d27597364c9af683"), "GWF-010"),
        # The pre-existing no-`@` branch is reached first and is unchanged: a
        # reference with neither an owner segment nor a pin is reported as an
        # unpinned action, not reclassified as a malformed identity.
        ("unpinned_action_rejected", "test.yml", step_uses("checkout"), "GWF-002"),
        ("approved_owner_full_sha_accepted", "test.yml", step_uses("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2"), None),
        # Divergence is a repository-level rule: it needs two workflow files, so
        # it runs as a dedicated block below rather than in this single-file table.
    ]

    for case in test_cases:
        name, filename, wf_yaml, expected_code = case[:4]
        extra_files = case[4] if len(case) > 4 else {}
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            wf_dir = tmp_root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / filename).write_text(wf_yaml, encoding="utf-8")
            for rel_extra, body_extra in extra_files.items():
                extra_path = tmp_root / rel_extra
                extra_path.parent.mkdir(parents=True, exist_ok=True)
                extra_path.write_text(body_extra, encoding="utf-8")

            findings = check_workflows(tmp_root)
            codes = {f.code for f in findings}
            if expected_code is None:
                if findings:
                    print(f"SELF_TEST_FAILURE in {name}: expected clean, got {findings}", file=sys.stderr)
                    return 1
            elif expected_code not in codes:
                print(f"SELF_TEST_FAILURE in {name}: expected finding {expected_code}, got {codes}", file=sys.stderr)
                return 1
            else:
                if not require_dispatched(tmp_root, findings, name, "check_workflows"):
                    return 1

    # Cross-workflow pin divergence (issue #1225 step 2): the same action at two
    # different SHAs is a finding, and one SHA everywhere is clean. Each pair of
    # workflows is individually well-formed, so only the repository-level check
    # can reject the divergent pair.
    divergence_cases = [
        ("divergent_pin_rejected", step_uses(f"actions/checkout@{other_sha}"), True),
        ("consistent_pin_accepted", step_uses("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"), False),
    ]
    for name, second_workflow, expect_finding in divergence_cases:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            wf_dir = tmp_root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "a.yml").write_text(
                step_uses("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"),
                encoding="utf-8",
            )
            (wf_dir / "b.yml").write_text(second_workflow, encoding="utf-8")
            findings = check_action_pin_divergence(tmp_root)
            if expect_finding and not any(f.code == "GWF-011" for f in findings):
                print(
                    f"SELF_TEST_FAILURE in {name}: expected GWF-011 for divergent action pin, got {findings}",
                    file=sys.stderr,
                )
                return 1
            if expect_finding and not require_dispatched(tmp_root, findings, name, "check_action_pin_divergence"):
                return 1
            if not expect_finding and findings:
                print(
                    f"SELF_TEST_FAILURE in {name}: consistent pin produced unexpected findings: {findings}",
                    file=sys.stderr,
                )
                return 1

    # Cache-key fingerprint binding (issue #1923). Each fixture carries a fully
    # bound key and then drops exactly one dimension, so a regression can only
    # come from the rule under test and never from an unrelated finding.
    def cache_workflow(key_line: str) -> str:
        return (
            gate_yaml.format(
                body="- uses: actions/cache@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0\n"
                "    with:\n"
                "      path: |\n"
                "        ~/.cargo/registry\n"
                + key_line
            )
        )

    bound_key = (
        "      key: ${{ runner.os }}-${{ runner.arch }}-cargo-${{ hashFiles('Cargo.lock') }}"
        "-${{ hashFiles('rust-toolchain.toml') }}-${{ hashFiles('Cargo.toml') }}"
        "-${{ github.event_name == 'push' && 'main' || 'pr' }}"
        "-${{ github.event.pull_request.head.repo.fork && 'untrusted-fork' || 'trusted' }}\n"
    )
    cache_cases = [
        ("cache_key_full_binding_accepted", bound_key, False),
        (
            "cache_key_without_fork_trust_rejected",
            bound_key.replace("${{ github.event.pull_request.head.repo.fork && 'untrusted-fork' || 'trusted' }}", "trusted"),
            True,
        ),
        (
            "cache_key_without_source_manifest_rejected",
            bound_key.replace("${{ hashFiles('Cargo.toml') }}-", ""),
            True,
        ),
        (
            "cache_key_without_toolchain_rejected",
            bound_key.replace("${{ hashFiles('rust-toolchain.toml') }}-", ""),
            True,
        ),
        (
            "cache_key_without_architecture_rejected",
            bound_key.replace("${{ runner.arch }}-", ""),
            True,
        ),
        ("cache_step_without_key_rejected", "", True),
    ]
    for name, key_line, expect_finding in cache_cases:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            wf_dir = tmp_root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "test.yml").write_text(cache_workflow(key_line), encoding="utf-8")
            findings = check_cache_key_fingerprints(tmp_root)
            has_finding = any(f.code == "GWF-020" for f in findings)
            if expect_finding and not has_finding:
                print(
                    f"SELF_TEST_FAILURE in {name}: expected GWF-020, got {findings}",
                    file=sys.stderr,
                )
                return 1
            if not expect_finding and findings:
                print(
                    f"SELF_TEST_FAILURE in {name}: full binding produced unexpected findings: {findings}",
                    file=sys.stderr,
                )
                return 1
            if expect_finding and not require_dispatched(tmp_root, findings, name, "check_cache_key_fingerprints"):
                return 1

    # A second cache step in the same file must be judged on its own key, not
    # inherit the first step's verdict: the bound-then-unbound pair is the exact
    # shape of a workflow that restores one cargo cache in several jobs, and
    # judging only the first step left the rest unverified.
    def two_step_cache_workflow(second_key_line: str) -> str:
        return gate_yaml.format(
            body="- uses: actions/cache@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0\n"
            "    with:\n"
            "      path: |\n"
            "        ~/.cargo/registry\n"
            + bound_key
            + "  - name: Build\n"
            "    run: echo built\n"
            + "  - uses: actions/cache@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0\n"
            "    with:\n"
            "      path: |\n"
            "        ~/.cargo/registry\n"
            + second_key_line
        )

    second_step_cases = [
        ("cache_second_step_bound_accepted", bound_key, False),
        (
            "cache_second_step_unbound_rejected",
            "      key: ${{ runner.os }}-cargo-${{ hashFiles('Cargo.lock') }}\n",
            True,
        ),
        (
            "cache_second_step_key_absent_rejected",
            "  - name: Build\n    run: echo built\n",
            True,
        ),
    ]
    for name, second_key_line, expect_finding in second_step_cases:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            wf_dir = tmp_root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "test.yml").write_text(
                two_step_cache_workflow(second_key_line), encoding="utf-8"
            )
            findings = check_cache_key_fingerprints(tmp_root)
            has_finding = any(f.code == "GWF-020" for f in findings)
            if expect_finding and not has_finding:
                print(
                    f"SELF_TEST_FAILURE in {name}: expected GWF-020, got {findings}",
                    file=sys.stderr,
                )
                return 1
            if not expect_finding and findings:
                print(
                    f"SELF_TEST_FAILURE in {name}: full binding produced unexpected findings: {findings}",
                    file=sys.stderr,
                )
                return 1
            if expect_finding and not require_dispatched(tmp_root, findings, name, "check_cache_key_fingerprints"):
                return 1

    # Cache-key manifest COVERAGE (issue #1923). The expected set is the root
    # manifest's own member list, so a key that reaches `crates/**` and
    # `bins/**` but not `workspace/**` is a finding even though it names a
    # Cargo.toml and passes every GWF-020 dimension. The fixture workspace is
    # written with exactly that three-root shape, which is the real one.
    three_root_workspace = (
        "[workspace]\nmembers = [\n"
        '  "bins/eliot",\n'
        '  "crates/eliot-app",\n'
        '  "workspace/tools/eliot-runtime-compiler",\n'
        "]\nexclude = []\n"
    )
    covering_key = bound_key.replace(
        "${{ hashFiles('Cargo.toml') }}",
        "${{ hashFiles('Cargo.toml', 'crates/**/Cargo.toml', 'bins/**/Cargo.toml',"
        " 'workspace/**/Cargo.toml') }}",
    )
    # The pre-fix shape: it names a Cargo.toml and satisfies every GWF-020
    # dimension, yet misses the workspace/tools member root entirely.
    partial_key = bound_key.replace(
        "${{ hashFiles('Cargo.toml') }}",
        "${{ hashFiles('Cargo.toml', 'crates/**/Cargo.toml', 'bins/**/Cargo.toml') }}",
    )
    coverage_cases = [
        ("cache_manifest_coverage_complete_accepted", covering_key, False),
        ("cache_manifest_coverage_missing_member_rejected", partial_key, True),
    ]
    for name, key_line, expect_finding in coverage_cases:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            (tmp_root / "Cargo.toml").write_text(three_root_workspace, encoding="utf-8")
            wf_dir = tmp_root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "test.yml").write_text(cache_workflow(key_line), encoding="utf-8")
            findings = check_cache_key_manifest_coverage(tmp_root)
            has_finding = any(f.code == "GWF-021" for f in findings)
            if expect_finding and not has_finding:
                print(
                    f"SELF_TEST_FAILURE in {name}: expected GWF-021, got {findings}",
                    file=sys.stderr,
                )
                return 1
            if not expect_finding and findings:
                print(
                    f"SELF_TEST_FAILURE in {name}: complete coverage produced unexpected findings: {findings}",
                    file=sys.stderr,
                )
                return 1
            if expect_finding and not require_dispatched(
                tmp_root, findings, name, "check_cache_key_manifest_coverage"
            ):
                return 1

    # A workspace whose members cannot be read is a coverage gap, never a
    # silent pass: an unreadable expected set must not make the rule vacuous.
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        wf_dir = tmp_root / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "test.yml").write_text(cache_workflow(covering_key), encoding="utf-8")
        findings = check_cache_key_manifest_coverage(tmp_root)
        if not any(f.code == "GWF-021" for f in findings):
            print(
                f"SELF_TEST_FAILURE in cache_manifest_coverage_without_workspace_manifest_rejected: {findings}",
                file=sys.stderr,
            )
            return 1
        if not require_dispatched(
            tmp_root,
            findings,
            "cache_manifest_coverage_without_workspace_manifest_rejected",
            "check_cache_key_manifest_coverage",
        ):
            return 1

    # The identity record is derived from the files and deterministic: the same
    # tree yields the same sorted records, and every third-party ref is present
    # including the job-level (no dash) form.
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        wf_dir = tmp_root / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "b.yml").write_text(
            step_uses("actions/cache@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0"), encoding="utf-8"
        )
        (wf_dir / "a.yml").write_text(
            step_uses("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2")
            + job_uses(f"actions/reusable/.github/workflows/x.yml@{other_sha}"),
            encoding="utf-8",
        )
        identities = collect_action_identities(tmp_root)
        expected_identities = [
            {
                "workflow": ".github/workflows/a.yml",
                "line": "10",
                "action": "actions/checkout",
                "ref": "11bd71901bbe5b1630ceea73d27597364c9af683",
            },
            {
                "workflow": ".github/workflows/a.yml",
                "line": "18",
                "action": "actions/reusable/.github/workflows/x.yml",
                "ref": other_sha,
            },
            {
                "workflow": ".github/workflows/b.yml",
                "line": "10",
                "action": "actions/cache",
                "ref": "1bd1e32a3bdc45362d1e726936510720a7c30a57",
            },
        ]
        if identities != expected_identities:
            print(
                f"SELF_TEST_FAILURE in derived_action_identity: expected {expected_identities}, got {identities}",
                file=sys.stderr,
            )
            return 1
        if collect_action_identities(tmp_root) != identities:
            print(
                "SELF_TEST_FAILURE in derived_action_identity: record is not deterministic",
                file=sys.stderr,
            )
            return 1

    # Test python requirements without hash
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        scripts_dir = tmp_root / "scripts"
        scripts_dir.mkdir(parents=True)
        (scripts_dir / "requirements-verification.txt").write_text("jsonschema==4.25.1\n", encoding="utf-8")
        findings = check_python_requirements(tmp_root)
        if not any(f.code == "GWF-004" for f in findings):
            print("SELF_TEST_FAILURE: expected GWF-004 for unhashed requirement", file=sys.stderr)
            return 1
        if not require_dispatched(tmp_root, findings, "unhashed_requirement_rejected", "check_python_requirements"):
            return 1

    # Test valid requirements
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        scripts_dir = tmp_root / "scripts"
        scripts_dir.mkdir(parents=True)
        (scripts_dir / "requirements-verification.txt").write_text(
            "jsonschema==4.25.1 \\\n    --hash=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
            encoding="utf-8",
        )
        findings = check_python_requirements(tmp_root)
        if findings:
            print(f"SELF_TEST_FAILURE: valid requirement produced unexpected findings: {findings}", file=sys.stderr)
            return 1

    # Test missing nuget lock
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        op_dir = tmp_root / "apps" / "Eliot.Operator"
        op_dir.mkdir(parents=True)
        (op_dir / "Eliot.Operator.csproj").write_text("<Project><PropertyGroup></PropertyGroup></Project>", encoding="utf-8")
        findings = check_nuget_lock(tmp_root)
        if not any(f.code == "GWF-005" for f in findings):
            print("SELF_TEST_FAILURE: expected GWF-005 for missing RestorePackagesWithLockFile", file=sys.stderr)
            return 1
        if not require_dispatched(tmp_root, findings, "missing_nuget_lock_rejected", "check_nuget_lock"):
            return 1

    # Test harness project without lock flag or lock file
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        harness_dir = tmp_root / "tests" / "Eliot.Operator.Tests"
        harness_dir.mkdir(parents=True)
        (harness_dir / "Eliot.Operator.Tests.csproj").write_text(
            "<Project><PropertyGroup></PropertyGroup></Project>", encoding="utf-8"
        )
        findings = check_nuget_lock(tmp_root)
        if not any(
            f.code == "GWF-005" and "Eliot.Operator.Tests" in f.path for f in findings
        ):
            print("SELF_TEST_FAILURE: expected GWF-005 for unlocked Operator harness", file=sys.stderr)
            return 1
        if not require_dispatched(tmp_root, findings, "unlocked_harness_rejected", "check_nuget_lock"):
            return 1

    # Test locked harness project accepted
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        harness_dir = tmp_root / "tests" / "Eliot.Operator.Tests"
        harness_dir.mkdir(parents=True)
        (harness_dir / "Eliot.Operator.Tests.csproj").write_text(
            "<Project><PropertyGroup><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>"
            "</PropertyGroup></Project>",
            encoding="utf-8",
        )
        (harness_dir / "packages.lock.json").write_text(
            '{"version": 1, "dependencies": {"net10.0": {}}}', encoding="utf-8"
        )
        findings = check_nuget_lock(tmp_root)
        if findings:
            print(f"SELF_TEST_FAILURE: locked harness produced unexpected findings: {findings}", file=sys.stderr)
            return 1

    # Test pip install without hash lock rejected
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        wf_dir = tmp_root / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "test.yml").write_text(
            "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n"
            "    runs-on: windows-latest\n    steps:\n"
            "      - run: python -m pip install -r scripts/requirements.txt\n",
            encoding="utf-8",
        )
        findings = check_pip_install_lock(tmp_root)
        if not any(f.code == "GWF-009" for f in findings):
            print("SELF_TEST_FAILURE: expected GWF-009 for unhashed pip install", file=sys.stderr)
            return 1
        if not require_dispatched(tmp_root, findings, "unhashed_pip_install_rejected", "check_pip_install_lock"):
            return 1

    # Test hash-locked pip install accepted
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        wf_dir = tmp_root / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "test.yml").write_text(
            "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n"
            "    runs-on: windows-latest\n    steps:\n"
            "      - run: python -m pip install --require-hashes -r scripts/requirements-verification.txt\n",
            encoding="utf-8",
        )
        findings = check_pip_install_lock(tmp_root)
        if findings:
            print(f"SELF_TEST_FAILURE: hash-locked pip install produced unexpected findings: {findings}", file=sys.stderr)
            return 1

    # Fail-closed privilege, locked restore, SDK identity and lock-graph drift
    # (issue #1225 N_step9). These four production rules decide
    # `persist-credentials: false`, least-privilege contents, `--locked-mode`
    # restore and the .NET SDK band, yet the self-test never judged them, so
    # deleting them left the suite printing a full PASS. Every body below is
    # read from a committed file under scripts/testdata/github-workflows/, and
    # every refusal is judged twice: once against its own rule and once
    # through verify_all, so removing the rule from the production dispatch
    # fails the suite even when the rule itself still works.
    fixture_dir = Path(__file__).resolve().parent / "testdata" / "github-workflows"

    def fixture_body(name: str) -> str:
        return (fixture_dir / name).read_text(encoding="utf-8")

    def materialize(tmp_root: Path, rel_path: str, body: str) -> None:
        target = tmp_root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")

    def setup_workflow(tmp_root: Path, fixture_name: str) -> None:
        materialize(tmp_root, ".github/workflows/test.yml", fixture_body(fixture_name))

    def setup_sdk(tmp_root: Path, fixture_name: str) -> None:
        materialize(
            tmp_root,
            "apps/Eliot.Operator/Eliot.Operator.csproj",
            fixture_body("operator-net10.csproj"),
        )
        materialize(tmp_root, "global.json", fixture_body(fixture_name))

    def setup_lock_graph(tmp_root: Path, fixture_name: str) -> None:
        materialize(
            tmp_root,
            "apps/Eliot.Operator/Eliot.Operator.csproj",
            fixture_body(fixture_name),
        )
        materialize(
            tmp_root,
            "apps/Eliot.Operator/packages.lock.json",
            fixture_body("lock-stale.packages.lock.json"),
        )

    def call_lock_graph(tmp_root: Path) -> list[Finding]:
        """Judge the materialized Operator project against its checked-in lock.

        check_nuget_lock_graph takes the project bytes and the parsed lock
        rather than a repository root, so the adapter reads exactly the two
        files the setup wrote and calls the production rule by name. The
        verify_all dispatch probe then proves the same rule is reached from the
        production dispatch (verify_all -> check_nuget_lock ->
        check_nuget_lock_graph), so deleting the rule from either place fails
        the suite.
        """
        rel_csproj = "apps/Eliot.Operator/Eliot.Operator.csproj"
        rel_lock = "apps/Eliot.Operator/packages.lock.json"
        content = (tmp_root / rel_csproj).read_text(encoding="utf-8")
        lock = json.loads((tmp_root / rel_lock).read_text(encoding="utf-8"))
        return check_nuget_lock_graph(rel_csproj, rel_lock, content, lock)

    # The adapter judges check_nuget_lock_graph by its production name, so the
    # completeness check below counts this table for that rule.
    call_lock_graph.__exercises__ = "check_nuget_lock_graph"  # type: ignore[attr-defined]

    fail_closed_tables = [
        (
            "GWF-021",
            check_fail_closed_privilege,
            setup_workflow,
            [
                ("privilege_persist_credentials_rejected", "reject-persist-credentials.yml", True),
                ("privilege_overbroad_permission_rejected", "reject-overbroad-permissions.yml", True),
                ("privilege_secret_interpolation_rejected", "reject-secret-interpolation.yml", True),
                ("privilege_oidc_token_rejected", "reject-oidc-token.yml", True),
                ("privilege_clean_accepted", "accept-privilege.yml", False),
            ],
        ),
        (
            "GWF-012",
            check_dotnet_restore_lock,
            setup_workflow,
            [
                ("restore_unlocked_rejected", "reject-unlocked-restore.yml", True),
                ("restore_locked_accepted", "accept-locked-restore.yml", False),
            ],
        ),
        (
            "GWF-014",
            check_dotnet_sdk_identity,
            setup_sdk,
            [
                ("sdk_identity_drift_rejected", "global-drift.json", True),
                ("sdk_identity_accepted", "global-accept.json", False),
            ],
        ),
        (
            "GWF-013",
            call_lock_graph,
            setup_lock_graph,
            [
                ("nuget_lock_graph_stale_rejected", "lock-stale.csproj", True),
                ("nuget_lock_graph_fresh_accepted", "operator-net10.csproj", False),
            ],
        ),
    ]
    for expected_code, rule, setup, cases in fail_closed_tables:
        for name, fixture_name, expect_finding in cases:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_root = Path(tmpdir)
                setup(tmp_root, fixture_name)
                direct = rule(tmp_root)
                if expect_finding:
                    if not any(f.code == expected_code for f in direct):
                        print(
                            f"SELF_TEST_FAILURE in {name}: expected {expected_code}, got {direct}",
                            file=sys.stderr,
                        )
                        return 1
                    if not require_dispatched(
                        tmp_root, direct, name, getattr(rule, "__exercises__", rule.__name__)
                    ):
                        return 1
                elif direct:
                    print(
                        f"SELF_TEST_FAILURE in {name}: expected clean, got {direct}",
                        file=sys.stderr,
                    )
                    return 1

    # Completeness (issue #1225 N_step9): the probes above must have verified
    # EVERY production check_* rule. The expected set is derived from this
    # module's globals, not from a hand list that could silently shrink beside
    # a rule deletion: a new check_* rule without a probe group fails here,
    # while a deleted rule fails earlier at its own group's by-name call
    # (NameError) or at its probe (code missing from the dispatch).
    defined_rules = {
        name for name, obj in globals().items() if name.startswith("check_") and callable(obj)
    }
    if probed_rules != defined_rules:
        print(
            f"SELF_TEST_FAILURE in rule_coverage_completeness: probed {sorted(probed_rules)} "
            f"!= defined {sorted(defined_rules)}",
            file=sys.stderr,
        )
        return 1
    completeness_cases = 1

    # Oracle identity (issue #1225 N_step10; I18.27). Every property is judged
    # against real file bytes: the record derives from the files, is
    # deterministic, changes when any oracle byte changes, covers the closed
    # oracle set on the production tree, and reaches the machine-readable
    # payload through the real main() caller.
    oracle_case_count = 0
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        if collect_oracle_identity(tmp_root) != collect_oracle_identity(tmp_root):
            print("SELF_TEST_FAILURE in oracle_identity_empty_deterministic", file=sys.stderr)
            return 1
        if collect_oracle_identity(tmp_root)["files"] != []:
            print("SELF_TEST_FAILURE in oracle_identity_empty_covers_absent_files", file=sys.stderr)
            return 1
        oracle_case_count += 2
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        oracle_target = tmp_root / ".github" / "workflows" / "ci.yml"
        oracle_target.parent.mkdir(parents=True, exist_ok=True)
        oracle_target.write_text(fixture_body("accept-privilege.yml"), encoding="utf-8")
        derived = collect_oracle_identity(tmp_root)
        expected_sha = hashlib.sha256(oracle_target.read_bytes()).hexdigest()
        if derived["files"] != [{"path": ".github/workflows/ci.yml", "sha256": expected_sha}]:
            print(f"SELF_TEST_FAILURE in oracle_identity_derived_from_bytes: got {derived}", file=sys.stderr)
            return 1
        oracle_case_count += 1
        oracle_target.write_text(fixture_body("accept-privilege.yml") + "\n# drift\n", encoding="utf-8")
        mutated = collect_oracle_identity(tmp_root)
        if mutated["digest"] == derived["digest"]:
            print("SELF_TEST_FAILURE in oracle_identity_mutation_sensitive: digest unchanged after oracle byte change", file=sys.stderr)
            return 1
        oracle_case_count += 1
    repo_root = Path(__file__).resolve().parent.parent
    production_oracle = collect_oracle_identity(repo_root)
    if [entry["path"] for entry in production_oracle["files"]] != list(ORACLE_OWNED_PATHS):
        print(f"SELF_TEST_FAILURE in oracle_identity_production_coverage: got {production_oracle}", file=sys.stderr)
        return 1
    oracle_case_count += 1
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        wf_dir = tmp_root / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "test.yml").write_text(fixture_body("accept-privilege.yml"), encoding="utf-8")
        payload_path = tmp_root / "gwf.json"
        saved_argv = sys.argv
        sys.argv = ["verify-github-workflows.py", "--root", str(tmp_root), "--json-out", str(payload_path)]
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                main()
        finally:
            sys.argv = saved_argv
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
        if payload.get("oracle") != collect_oracle_identity(tmp_root):
            print(f"SELF_TEST_FAILURE in oracle_identity_payload_carriage: got {payload.get('oracle')}", file=sys.stderr)
            return 1
        if "actions" not in payload or "status" not in payload or "findings" not in payload:
            print(f"SELF_TEST_FAILURE in oracle_identity_payload_additive: got {sorted(payload)}", file=sys.stderr)
            return 1
        oracle_case_count += 2

    # 31 single-file workflow cases + 2 cross-workflow divergence cases
    # + 1 derived-identity case + 7 rule-level cases below, plus the two
    # cache-key groups (issue #1923) and the four fail-closed rule tables
    # (issue #1225 N_step9), each judged directly with every refusal re-judged
    # through verify_all (dispatch_probes), the rule-coverage completeness
    # case (completeness_cases), plus the seven oracle-identity
    # cases (issue #1225 N_step10; oracle_case_count). The reported count is derived from
    # the case lists themselves: a hardcoded total would keep reporting PASS
    # with the same number after a case group was added, which is the count
    # reading as evidence when it is not counting the cases that actually ran.
    case_count = (
        len(test_cases)
        + len(divergence_cases)
        + 1
        + 7
        + len(cache_cases)
        + len(second_step_cases)
        + len(coverage_cases)
        + 1
        + sum(len(cases) for _, _, _, cases in fail_closed_tables)
        + dispatch_probes
        + completeness_cases
        + oracle_case_count
    )
    print(f"GITHUB_WORKFLOW_VERIFIER_SELF_TEST: PASS ({case_count}/{case_count} cases verified)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify GitHub workflows and external input locks.")
    parser.add_argument("--root", default=".", help="Repository root directory")
    parser.add_argument("--json-out", help="Write findings to JSON output file")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-tests")
    args = parser.parse_args()

    if args.self_test:
        return run_self_tests()

    root = Path(args.root).resolve()
    findings = verify_all(root)

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "status": "fail" if findings else "pass",
            "findings_count": len(findings),
            "findings": [
                {
                    "code": f.code,
                    "path": f.path,
                    "line": f.line,
                    "detail": f.detail,
                }
                for f in findings
            ],
            # Derived action identity (issue #1225 step 2). Additive key: every
            # existing consumer reads `status`/`findings_count`/`findings`, which
            # keep their meaning and ordering unchanged. Sorted and bounded, so
            # an unchanged tree yields a byte-identical file.
            "actions": collect_action_identities(root),
            # Oracle identity (issue #1225 N_step10). Additive key like
            # `actions`: existing consumers read status/findings/actions
            # unchanged, and the independent/manual source-candidate or Review
            # owner reads `oracle` to attest the exact oracle bytes behind the
            # verdict for this source.
            "oracle": collect_oracle_identity(root),
        }
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if findings:
        print(f"VERIFY_GITHUB_WORKFLOWS: FAIL ({len(findings)} findings)")
        for f in findings:
            print(f"  [{f.code}] {f.path}:{f.line}: {f.detail}")
        return 1

    print("VERIFY_GITHUB_WORKFLOWS: PASS (all workflows, action SHAs, and dependency locks conform)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
