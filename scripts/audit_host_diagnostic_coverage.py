#!/usr/bin/env python3
"""Bounded read-only Host diagnostic coverage/identity validator (issue #985).

Verifies the reviewed table at ``scripts/testdata/host-diagnostic-coverage/coverage.toml``
against the current tree: exact tracked file/cfg/target graph with one disposition
per file, per-boundary source spans/digests/callers/emitters/tests, and honest
incompletes for unmerged children. Any source/rule/profile change stales the
table via input/span digests (never raw HEAD equality); the table is excluded
from its own digest.

Closed interface: ``--root`` (+ ``--format text|json``). Fixed table path and
fixed Host/package roots. Offline and read-only: never executes table content,
never mutates source, no globs/paths/commands from the table, no external fetch.

Exit codes: 0 COMPLETE, 2 INCOMPLETE (honest, itemized), 1 STALE/MALFORMED/ERROR.
Text and JSON render from one validated result object.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - stdlib on 3.11+
    tomllib = None  # type: ignore[assignment]

SCHEMA = "eliot.host-diagnostic-coverage.v1"
# Canonical repo-relative paths always use forward slashes (table format);
# os.path.join(root, rel) accepts them on every platform.
TABLE_REL = "scripts/testdata/host-diagnostic-coverage/coverage.toml"
SRC_DIR = "bins/eliot-host/src"
TESTS_DIR = "bins/eliot-host/tests"
HOST_MANIFEST = "bins/eliot-host/Cargo.toml"
FACADE_REL = SRC_DIR + "/host_diagnostics.rs"
LIB_REL = SRC_DIR + "/lib.rs"
MAIN_REL = SRC_DIR + "/main.rs"

# Fixed diagnostic-emission patterns. Absence spans must be free of all of them.
# Table fields can never narrow this set.
DIAG_PATTERNS = (
    "observe_entrypoint",
    "observe_terminal",
    "TerminalGuard::armed",
    "install_host_diagnostics",
    "event_log_sink_status",
)
TERMINAL_PATTERNS = ("observe_terminal", "TerminalGuard::armed")

VALID_KINDS = frozenset({
    "terminal", "entrypoint", "propagated", "sink", "singleton",
    "receipt_owned", "external", "uncalled", "dead",
})
VALID_REASONS = frozenset({
    "in_flight_child", "missing_callsite", "missing_test_binding",
    "host_seam_unavailable",
})
VALID_SCOPES = frozenset({"wired", "structural", "none"})
VALID_DECIDABLE = frozenset({"validator", "validator_partial", "test_phase"})


class Failure(Exception):
    """Hard validator failure (stale/malformed/error)."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_bytes(root: str, rel: str) -> bytes:
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        raise Failure(f"missing file: {rel}")
    with open(path, "rb") as handle:
        return handle.read()


def split_lines(text: str) -> list[str]:
    return text.split("\n")


def span_digest_from_lines(lines: list[str], start: int, end: int) -> str:
    if start < 1 or end < start or end > len(lines):
        raise Failure(f"span out of range: {start}-{end} (have {len(lines)} lines)")
    seg = "\n".join(lines[start - 1:end]) + "\n"
    return sha256_bytes(seg.encode("utf-8"))


def is_full_comment(line: str) -> bool:
    return line.strip().startswith("//")


def norm_rel(path: str) -> str:
    return path.replace(os.sep, "/")


class Result:
    def __init__(self) -> None:
        self.stale: list[str] = []
        self.incomplete: list[dict[str, str]] = []
        self.proven: list[str] = []
        self.counts: dict[str, int] = {}

    def ok(self) -> bool:
        return not self.stale


def check_table_shape(table: dict, res: Result) -> None:
    if table.get("schema") != SCHEMA:
        res.stale.append(f"schema must be {SCHEMA!r}")
    if table.get("issue") != 985:
        res.stale.append("issue must be 985")
    for key in ("reconciliation", "file", "input", "boundary", "matrix"):
        if key not in table:
            res.stale.append(f"missing section: {key}")
    if not isinstance(table.get("file", []), list):
        res.stale.append("section [[file]] must be a list")
    if not isinstance(table.get("boundary", []), list):
        res.stale.append("section [[boundary]] must be a list")


def iter_src_rs(root: str) -> list[str]:
    found: list[str] = []
    base = os.path.join(root, SRC_DIR)
    if not os.path.isdir(base):
        raise Failure(f"missing source dir: {SRC_DIR}")
    for dirpath, _dirnames, filenames in os.walk(base, followlinks=False):
        for name in filenames:
            if name.endswith(".rs"):
                full = os.path.join(dirpath, name)
                found.append(norm_rel(os.path.relpath(full, root)))
    return sorted(found)


def check_inputs(root: str, table: dict, res: Result) -> dict[str, bytes]:
    blobs: dict[str, bytes] = {}
    seen: set[str] = set()
    for entry in table.get("input", []):
        rel = entry.get("path", "")
        want = entry.get("sha256", "")
        if not rel or not want:
            res.stale.append("input entry needs path + sha256")
            continue
        if rel in seen:
            res.stale.append(f"duplicate input: {rel}")
            continue
        seen.add(rel)
        try:
            data = read_bytes(root, rel)
        except Failure as exc:
            res.stale.append(str(exc))
            continue
        blobs[rel] = data
        if sha256_bytes(data) != want:
            res.stale.append(f"input digest mismatch (stale table): {rel}")
    return blobs


def parse_own_cfg(text: str) -> frozenset[str]:
    text = text.strip()
    if not text:
        return frozenset()
    if text == "#[cfg(windows)]":
        return frozenset({"windows"})
    if text == "#[cfg(test)]":
        return frozenset({"test"})
    if text == "#[cfg(all(test, windows))]" or text == "#[cfg(all(windows, test))]":
        return frozenset({"windows", "test"})
    raise Failure(f"unsupported cfg text: {text!r}")


def cfg_name(conds: frozenset[str], target: str) -> str:
    if target == "bin":
        return "bin"
    if not conds:
        return "always"
    if conds == frozenset({"windows"}):
        return "windows"
    if conds == frozenset({"test"}):
        return "test"
    if conds == frozenset({"windows", "test"}):
        return "windows+test"
    raise Failure(f"unsupported cfg combination: {sorted(conds)}")


def check_files(root: str, table: dict, res: Result) -> tuple[dict[str, dict], dict[str, str]]:
    records = {f.get("path", ""): f for f in table.get("file", [])}
    if "" in records:
        res.stale.append("file entry with empty path")
    actual = iter_src_rs(root)
    missing = [p for p in records if p not in actual]
    extra = [p for p in actual if p not in records]
    for path in missing:
        res.stale.append(f"table references absent source file: {path}")
    for path in extra:
        res.stale.append(f"untracked-by-table source file (new/moved source): {path}")
    recon = table.get("reconciliation", {})
    if recon.get("current_count") != len(records):
        res.stale.append("reconciliation.current_count != len([[file]])")
    added = table.get("added_file", [])
    deleted = table.get("deleted_file", [])
    if (recon.get("current_count", 0) - recon.get("baseline_count", 0)) != len(added) - len(deleted):
        res.stale.append("reconciliation arithmetic broken: current-baseline != added-deleted")
    texts: dict[str, str] = {}
    for path in sorted(records):
        if path in actual:
            try:
                data = read_bytes(root, path)
            except Failure as exc:
                res.stale.append(str(exc))
                continue
            texts[path] = data.decode("utf-8")
            if sha256_bytes(data) != records[path].get("sha256", ""):
                res.stale.append(f"file digest mismatch (stale table): {path}")
    # Module-graph edge + effective cfg per file.
    by_path = records
    memo: dict[str, frozenset[str]] = {}

    def effective(path: str, stack: tuple[str, ...]) -> frozenset[str]:
        if path in memo:
            return memo[path]
        if path in stack:
            raise Failure(f"module parent cycle at {path}")
        rec = by_path.get(path)
        if rec is None:
            raise Failure(f"parent file not in table: {path}")
        own = parse_own_cfg(rec.get("parent_cfg", "") or "")
        parent = rec.get("parent")
        if not parent:
            memo[path] = own
            return own
        conds = own | effective(parent, stack + (path,))
        memo[path] = conds
        return conds

    mod_decl = re.compile(r"mod\s+([A-Za-z0-9_]+)\s*;")
    for path in sorted(records):
        rec = records[path]
        disp_owner = rec.get("owner")
        exclusion = rec.get("exclusion")
        if (disp_owner is None) == (exclusion is None):
            res.stale.append(f"{path}: want exactly one of owner/exclusion")
            continue
        if exclusion == "facade":
            target = rec.get("exclusion_target", "")
            if target not in by_path:
                res.stale.append(f"{path}: facade target not in table: {target}")
            if path in texts and re.search(
                r"^\s*(pub(\([^)]*\))?\s+)?fn\s+[A-Za-z0-9_]", texts[path], re.M
            ):
                res.stale.append(f"{path}: facade contains a fn definition (exclusion lost)")
        elif exclusion == "test_only":
            pass
        elif exclusion is not None:
            res.stale.append(f"{path}: unknown exclusion {exclusion!r}")
        parent = rec.get("parent")
        if not parent:
            if path not in (LIB_REL, MAIN_REL):
                res.stale.append(f"{path}: only lib.rs/main.rs may omit parent")
            continue
        if parent not in texts:
            continue
        plines = split_lines(texts[parent])
        line_no = rec.get("parent_line", 0)
        if not isinstance(line_no, int) or line_no < 1 or line_no > len(plines):
            res.stale.append(f"{path}: parent_line out of range")
            continue
        decl = plines[line_no - 1].strip()
        match = mod_decl.search(decl)
        if not match:
            res.stale.append(f"{path}: no mod decl at {parent}:{line_no}")
            continue
        modname = match.group(1)
        want_cfg = rec.get("parent_cfg", "") or ""
        if want_cfg:
            seen_attr = any(
                plines[line_no - 1 - back].strip() == want_cfg
                for back in (1, 2, 3)
                if line_no - 1 - back >= 0
            )
            if not seen_attr:
                res.stale.append(f"{path}: cfg attr {want_cfg!r} missing above {parent}:{line_no}")
        # Edge resolution: standard path or #[path] naming this file.
        base = os.path.basename(path)
        stem = base[:-3]
        parent_stem = os.path.basename(parent)[:-3]
        standard = (
            (parent in (LIB_REL, MAIN_REL) and modname == stem)
            or (parent not in (LIB_REL, MAIN_REL)
                and path == norm_rel(os.path.join(os.path.dirname(parent), parent_stem, modname + ".rs")))
        )
        if not standard:
            attr_ok = any(
                re.search(r'#\[path\s*=\s*"' + re.escape(base) + r'"\]', plines[line_no - 1 - back])
                for back in (1, 2, 3)
                if line_no - 1 - back >= 0
            )
            if not attr_ok:
                res.stale.append(f"{path}: decl {modname} resolves to neither standard path nor #[path]")
        try:
            conds = effective(path, ())
        except Failure as exc:
            res.stale.append(str(exc))
            continue
        try:
            want = cfg_name(conds, rec.get("target", ""))
        except Failure as exc:
            res.stale.append(f"{path}: {exc}")
            continue
        if rec.get("cfg") != want:
            res.stale.append(f"{path}: cfg {rec.get('cfg')!r} != recomputed {want!r}")
    return records, texts


def check_test_only(root: str, table: dict, res: Result, texts: dict[str, str]) -> None:
    records = {f.get("path", ""): f for f in table.get("file", [])}
    prod = [p for p, r in records.items() if r.get("cfg") not in ("test", "windows+test")]
    mod_decl = re.compile(r"mod\s+([A-Za-z0-9_]+)\s*;")
    for path, rec in sorted(records.items()):
        if rec.get("exclusion") != "test_only":
            continue
        if rec.get("cfg") not in ("test", "windows+test"):
            res.stale.append(f"{path}: test_only exclusion without a test cfg")
        parent, line_no = rec.get("parent", ""), rec.get("parent_line", 0)
        if parent not in texts:
            continue
        decl = split_lines(texts[parent])[line_no - 1]
        match = mod_decl.search(decl)
        if not match:
            continue
        modname = match.group(1)
        for other in prod:
            for num, line in enumerate(split_lines(texts[other]), 1):
                if is_full_comment(line):
                    continue
                if re.search(rf"\b{re.escape(modname)}::", line):
                    res.stale.append(
                        f"{path}: test module referenced from production file {other}:{num}"
                    )


def check_deleted(root: str, table: dict, res: Result, texts: dict[str, str]) -> None:
    actual = set(iter_src_rs(root))
    for entry in table.get("deleted_file", []):
        path = entry.get("path", "")
        if path in actual:
            res.stale.append(f"deleted file present again: {path}")
        ev_file = entry.get("evidence_file", "")
        marker = entry.get("marker", "")
        if ev_file not in texts:
            res.stale.append(f"deleted_file evidence file unknown: {ev_file}")
        elif marker not in texts[ev_file]:
            res.stale.append(f"deleted_file successor marker missing in {ev_file}")


def check_added(table: dict, res: Result, records: dict[str, dict]) -> None:
    for entry in table.get("added_file", []):
        if entry.get("path", "") not in records:
            res.stale.append(f"added file not in [[file]]: {entry.get('path', '')}")


def facade_consts(texts: dict[str, str], res: Result) -> tuple[int | None, int | None]:
    text = texts.get(FACADE_REL, "")
    field = detail = None
    match = re.search(r"MAX_DIAGNOSTIC_FIELD_BYTES[^=]*=\s*(\d+)", text)
    if match:
        field = int(match.group(1))
    else:
        res.stale.append("facade MAX_DIAGNOSTIC_FIELD_BYTES not found")
    match = re.search(r"MAX_DIAGNOSTIC_DETAIL_BYTES[^=]*=\s*(\d+)", text)
    if match:
        detail = int(match.group(1))
    else:
        res.stale.append("facade MAX_DIAGNOSTIC_DETAIL_BYTES not found")
    return field, detail


def const_value(text: str, name: str) -> str | None:
    match = re.search(rf"{re.escape(name)}\s*:\s*&\s*str\s*=\s*\"([^\"]+)\"", text)
    return match.group(1) if match else None


def check_boundaries(
    root: str,
    table: dict,
    res: Result,
    records: dict[str, dict],
    texts: dict[str, str],
    field_ceiling: int | None,
    detail_ceiling: int | None,
) -> dict[str, dict]:
    boundaries = {b.get("id", ""): b for b in table.get("boundary", [])}
    if "" in boundaries:
        res.stale.append("boundary with empty id")
    for bid, bnd in sorted(boundaries.items()):
        if not bid:
            continue
        kind = bnd.get("kind", "")
        if kind not in VALID_KINDS:
            res.stale.append(f"{bid}: unknown kind {kind!r}")
            continue
        if bnd.get("scope") not in VALID_SCOPES:
            res.stale.append(f"{bid}: bad scope {bnd.get('scope')!r}")
        if bnd.get("status") not in ("proven", "incomplete"):
            res.stale.append(f"{bid}: bad status {bnd.get('status')!r}")
        if bnd.get("ceiling_field_bytes") != field_ceiling:
            res.stale.append(f"{bid}: field ceiling != facade const")
        if bnd.get("ceiling_detail_bytes") != detail_ceiling:
            res.stale.append(f"{bid}: detail ceiling != facade const")
        rel = bnd.get("file", "")
        if rel not in texts:
            res.stale.append(f"{bid}: file not in table/denominator: {rel}")
            continue
        lines = split_lines(texts[rel])
        if not isinstance(bnd.get("owner"), int):
            res.stale.append(f"{bid}: owner must be an issue number")
        # Sites.
        codes: list[str] = []
        union = ""
        for site in bnd.get("site", []):
            start, end = site.get("start", 0), site.get("end", 0)
            try:
                digest = span_digest_from_lines(lines, start, end)
            except Failure as exc:
                res.stale.append(f"{bid}: site {start}-{end}: {exc}")
                continue
            if digest != site.get("digest", ""):
                res.stale.append(f"{bid}: site digest mismatch at {rel}:{start}-{end}")
                continue
            seg = "\n".join(lines[start - 1:end])
            union += seg + "\n"
            for marker in site.get("markers", []):
                if marker not in seg:
                    res.stale.append(f"{bid}: site marker {marker!r} missing at {rel}:{start}-{end}")
            code = site.get("code")
            if code:
                codes.append(code)
                if code not in seg:
                    consts = [m for m in site.get("markers", []) if m.startswith("HOST_TERMINAL_CODE_")]
                    if not consts:
                        res.stale.append(f"{bid}: code {code!r} missing at {rel}:{start}-{end}")
                    else:
                        value = const_value(texts.get(FACADE_REL, ""), consts[0])
                        if value != code:
                            res.stale.append(f"{bid}: const {consts[0]} value != code {code!r}")
            if kind == "entrypoint":
                for pat in TERMINAL_PATTERNS:
                    if pat in seg:
                        res.stale.append(f"{bid}: entrypoint site contains terminal pattern {pat!r}")
        if kind == "terminal" and not codes:
            res.stale.append(f"{bid}: terminal boundary without a frozen code")
        if kind == "entrypoint" and not bnd.get("site"):
            res.stale.append(f"{bid}: entrypoint boundary without sites")
        bnd["_codes"] = codes
        # Absence spans.
        for span in bnd.get("absence", []):
            start, end = span.get("start", 0), span.get("end", 0)
            try:
                digest = span_digest_from_lines(lines, start, end)
            except Failure as exc:
                res.stale.append(f"{bid}: absence {start}-{end}: {exc}")
                continue
            if digest != span.get("digest", ""):
                res.stale.append(f"{bid}: absence digest mismatch at {rel}:{start}-{end}")
                continue
            seg = "\n".join(lines[start - 1:end])
            union += seg + "\n"
            for pat in DIAG_PATTERNS:
                if pat in seg:
                    res.stale.append(f"{bid}: absence span now contains {pat!r} (gap closed or bytes changed)")
        for marker in bnd.get("markers", []):
            if marker not in union:
                res.stale.append(f"{bid}: boundary marker {marker!r} missing from recorded spans")
        # Caller + entry pins (exact line text).
        for pin in list(bnd.get("caller", [])) + list(bnd.get("entry", [])):
            cfile, cline = pin.get("file", ""), pin.get("line", 0)
            try:
                ctxt = read_bytes(root, cfile).decode("utf-8")
            except Failure:
                res.stale.append(f"{bid}: pin file missing: {cfile}")
                continue
            clines = split_lines(ctxt)
            if not isinstance(cline, int) or cline < 1 or cline > len(clines):
                res.stale.append(f"{bid}: pin line out of range: {cfile}:{cline}")
                continue
            if clines[cline - 1].strip() != (pin.get("text", "") or ""):
                res.stale.append(f"{bid}: pin text changed at {cfile}:{cline}")
        # Test bindings (existence only; execution belongs to TEST-PHASE provenance).
        for test in bnd.get("test", []):
            tfile, case = test.get("file", ""), test.get("case", "")
            allowed_roots = (TESTS_DIR + "/", SRC_DIR + "/")
            if not tfile.startswith(allowed_roots):
                res.stale.append(f"{bid}: test file outside fixed roots: {tfile}")
                continue
            try:
                body = read_bytes(root, tfile).decode("utf-8")
            except Failure:
                res.stale.append(f"{bid}: test file missing: {tfile}")
                continue
            if f"fn {case}" not in body:
                res.stale.append(f"{bid}: test case fn {case} missing in {tfile}")
            fixture = test.get("fixture")
            if fixture and not os.path.isfile(os.path.join(root, fixture)):
                res.stale.append(f"{bid}: fixture missing: {fixture}")
        # Zero-caller scans (comment-aware, original line numbers).
        for scan in bnd.get("zeroscan", []):
            ident = scan.get("ident", "")
            allowed = set(scan.get("allowed", []))
            if not ident or not allowed:
                res.stale.append(f"{bid}: zeroscan needs ident + allowed lines")
                continue
            for path in sorted(texts):
                for num, line in enumerate(split_lines(texts[path]), 1):
                    if is_full_comment(line):
                        continue
                    if re.search(rf"\b{re.escape(ident)}\b", line):
                        if f"{path}:{num}" not in allowed:
                            res.stale.append(f"{bid}: zeroscan {ident}: unexpected {path}:{num}")
        # External caller span.
        ext = bnd.get("ext_caller")
        if ext:
            efile = ext.get("file", "")
            if ".." in efile or os.path.isabs(efile):
                res.stale.append(f"{bid}: ext_caller path escapes root: {efile}")
                continue
            try:
                ctxt = read_bytes(root, efile).decode("utf-8")
            except Failure:
                res.stale.append(f"{bid}: ext_caller file missing: {efile}")
                continue
            elines = split_lines(ctxt)
            try:
                digest = span_digest_from_lines(elines, ext.get("start", 0), ext.get("end", 0))
            except Failure as exc:
                res.stale.append(f"{bid}: ext_caller span: {exc}")
                continue
            if digest != ext.get("digest", ""):
                res.stale.append(f"{bid}: ext_caller digest mismatch")
                continue
            seg = "\n".join(elines[ext["start"] - 1:ext["end"]])
            for marker in ext.get("markers", []):
                if marker not in seg:
                    res.stale.append(f"{bid}: ext_caller marker {marker!r} missing")
        reexp = bnd.get("reexport")
        if reexp:
            rfile = reexp.get("file", "")
            if rfile not in texts:
                res.stale.append(f"{bid}: reexport file unknown: {rfile}")
            else:
                rlines = split_lines(texts[rfile])
                try:
                    digest = span_digest_from_lines(rlines, reexp.get("start", 0), reexp.get("end", 0))
                except Failure as exc:
                    res.stale.append(f"{bid}: reexport span: {exc}")
                else:
                    if digest != reexp.get("digest", ""):
                        res.stale.append(f"{bid}: reexport digest mismatch")
                    seg = "\n".join(rlines[reexp["start"] - 1:reexp["end"]])
                    for marker in reexp.get("markers", []):
                        if marker not in seg:
                            res.stale.append(f"{bid}: reexport marker {marker!r} missing")
        # Kind-specific global checks.
        if kind == "singleton":
            main_text = texts.get(MAIN_REL, "")
            if main_text.count("install_host_diagnostics") != 1:
                res.stale.append(f"{bid}: install_host_diagnostics singularity lost in main.rs")
            if main_text.count("observe_terminal_error") != 1:
                res.stale.append(f"{bid}: observe_terminal_error singularity lost in main.rs")
            for path, text in sorted(texts.items()):
                if path == FACADE_REL:
                    continue
                if re.search(r"tracing(::|!|_subscriber)", text):
                    res.stale.append(f"{bid}: tracing use outside facade: {path}")
        if kind == "sink":
            for path, text in sorted(texts.items()):
                for num, line in enumerate(split_lines(text), 1):
                    if is_full_comment(line):
                        continue
                    if "platform_windows::event_log" in line:
                        res.stale.append(f"{bid}: Host now consumes the platform port at {path}:{num}")
            try:
                manifest = read_bytes(root, HOST_MANIFEST).decode("utf-8")
            except Failure as exc:
                res.stale.append(f"{bid}: {exc}")
            else:
                if "Win32_System_EventLog" in manifest:
                    res.stale.append(f"{bid}: Host manifest now enables Win32_System_EventLog")
        # Status consistency.
        status, reason = bnd.get("status"), bnd.get("reason")
        tests = bnd.get("test", [])
        if status == "proven":
            if reason is not None:
                res.stale.append(f"{bid}: proven boundary must not carry a reason")
            if not tests and kind not in ("uncalled", "dead", "external"):
                res.stale.append(f"{bid}: proven boundary without a test binding")
        else:
            if reason not in VALID_REASONS:
                res.stale.append(f"{bid}: bad incomplete reason {reason!r}")
            if reason in ("missing_test_binding", "in_flight_child") and tests:
                res.stale.append(f"{bid}: {reason} must not claim tests")
            if reason == "missing_callsite" and not bnd.get("absence"):
                res.stale.append(f"{bid}: missing_callsite needs an absence span")
            if reason == "host_seam_unavailable" and kind != "sink":
                res.stale.append(f"{bid}: host_seam_unavailable is sink-only")
    # Terminal code uniqueness across boundaries (no double designation).
    seen: dict[str, str] = {}
    for bid, bnd in sorted(boundaries.items()):
        for code in bnd.get("_codes", []):
            if code in seen and seen[code] != bid:
                res.stale.append(f"code {code!r} designated by both {seen[code]} and {bid}")
            else:
                seen[code] = bid
    # Terminal refs exist + acyclic.
    for bid, bnd in sorted(boundaries.items()):
        for target in bnd.get("terminals", []):
            if target not in boundaries:
                res.stale.append(f"{bid}: unknown terminal ref {target}")
    visiting: set[str] = set()
    done: set[str] = set()

    def visit(node: str, chain: tuple[str, ...]) -> None:
        if node in done:
            return
        if node in visiting:
            res.stale.append(f"terminal ref cycle: {' -> '.join(chain + (node,))}")
            return
        visiting.add(node)
        for target in boundaries.get(node, {}).get("terminals", []):
            if target in boundaries:
                visit(target, chain + (node,))
        visiting.discard(node)
        done.add(node)

    for bid in sorted(boundaries):
        visit(bid, ())
    # Coverage: every owner file >=1 boundary; exclusion files none.
    have: dict[str, int] = {}
    for bnd in boundaries.values():
        have[bnd.get("file", "")] = have.get(bnd.get("file", ""), 0) + 1
    for path, rec in sorted(records.items()):
        if rec.get("owner") is not None:
            if not have.get(path):
                res.stale.append(f"behavior file without a boundary: {path}")
        else:
            if have.get(path):
                res.stale.append(f"excluded file carries a boundary: {path}")
    return boundaries


def check_matrix(table: dict, res: Result, boundaries: dict[str, dict]) -> None:
    rows = table.get("matrix", [])
    seen: set[int] = set()
    for row in rows:
        num = row.get("n", 0)
        if num in seen:
            res.stale.append(f"duplicate matrix row: {num}")
        seen.add(num)
        if row.get("decidable") not in VALID_DECIDABLE:
            res.stale.append(f"A{num}: bad decidable flag {row.get('decidable')!r}")
        for ref in row.get("boundaries", []):
            if ref not in boundaries:
                res.stale.append(f"A{num}: unknown boundary ref {ref}")
    if seen != set(range(1, 19)):
        res.stale.append(f"matrix must cover exactly cases 1..18 (have {sorted(seen)})")


def collect_verdict(res: Result, boundaries: dict[str, dict]) -> None:
    for bid, bnd in sorted(boundaries.items()):
        if bnd.get("status") == "incomplete":
            res.incomplete.append({
                "id": bid,
                "reason": bnd.get("reason", ""),
                "owner": str(bnd.get("owner", "")),
                "operation": bnd.get("operation", ""),
            })
        else:
            res.proven.append(bid)


def render_text(res: Result, verdict: str) -> str:
    out = [f"host-diagnostic-coverage: {verdict}"]
    out.append(
        f"files={res.counts.get('files', 0)} "
        f"boundaries={res.counts.get('boundaries', 0)} "
        f"proven={len(res.proven)} incomplete={len(res.incomplete)} stale={len(res.stale)}"
    )
    for item in res.incomplete:
        out.append(f"INCOMPLETE {item['id']} [{item['reason']}] owner={item['owner']} :: {item['operation']}")
    for line in res.stale:
        out.append(f"STALE {line}")
    return "\n".join(out) + "\n"


def render_json(res: Result, verdict: str) -> str:
    import json

    return json.dumps({
        "schema": SCHEMA,
        "verdict": verdict,
        "counts": res.counts,
        "proven": res.proven,
        "incomplete": res.incomplete,
        "stale": res.stale,
    }, indent=2, sort_keys=True) + "\n"


def run(root: str) -> tuple[Result, dict]:
    res = Result()
    if tomllib is None:
        raise Failure("tomllib unavailable (need Python 3.11+)")
    try:
        with open(os.path.join(root, TABLE_REL), "rb") as handle:
            table = tomllib.load(handle)
    except FileNotFoundError:
        raise Failure(f"missing table: {TABLE_REL}")
    except tomllib.TOMLDecodeError as exc:
        raise Failure(f"malformed table: {exc}")
    check_table_shape(table, res)
    check_inputs(root, table, res)
    records, texts = check_files(root, table, res)
    res.counts["files"] = len(records)
    check_deleted(root, table, res, texts)
    check_added(table, res, records)
    check_test_only(root, table, res, texts)
    field_ceiling, detail_ceiling = facade_consts(texts, res)
    boundaries = check_boundaries(root, table, res, records, texts, field_ceiling, detail_ceiling)
    res.counts["boundaries"] = len(boundaries)
    check_matrix(table, res, boundaries)
    collect_verdict(res, boundaries)
    return res, table


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the reviewed Host diagnostic coverage table against the current tree."
    )
    parser.add_argument("--root", default=".", help="repository root (default: .)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    root = os.path.abspath(args.root)
    try:
        res, _table = run(root)
    except Failure as exc:
        res = Result()
        res.stale.append(str(exc))
        verdict = "STALE"
    else:
        verdict = "COMPLETE" if res.ok() and not res.incomplete else ("INCOMPLETE" if res.ok() else "STALE")
    text = render_json(res, verdict) if args.format == "json" else render_text(res, verdict)
    sys.stdout.write(text)
    return {"COMPLETE": 0, "INCOMPLETE": 2, "STALE": 1}[verdict]


if __name__ == "__main__":
    raise SystemExit(main())
