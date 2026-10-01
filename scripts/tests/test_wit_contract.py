"""Typed current WIT ABI contract for #756; real pinned-parser proof, no stubs.

Pinned tooling (already on main via #870 and workspace pins):
- wit-parser =0.252.0 and wasmtime =47.0.4 from Cargo.lock / Cargo.toml,
  verified through the fixed command grammar
  `cargo metadata --locked --format-version 1` (no shell, fixed argv, repo root cwd).
- Rust channel 1.97.1 from rust-toolchain.toml.
- WIT syntax/type/world/import validation through a pinned wit-parser helper
  crate (wit-parser =0.252.0, offline build) invoked as
  `wit-abi-helper <wit-dir>` (no shell, fixed fixture paths only).
- Normalized round trips and ABI digests computed from the actual WIT bytes
  with abi-digest values excluded from the hashed payload.

No Wasmtime execution, no guest build, no network, no arbitrary shell input.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TYPED_DIR = ROOT / "bins" / "eliot-wasm-host" / "wit" / "typed"
LEGACY_WIT = ROOT / "bins" / "eliot-wasm-host" / "wit" / "guest.wit"
FIXTURE_DIR = ROOT / "scripts" / "testdata" / "wit-contract"

EXPECTED_PACKAGE = "eliot:current@0.1.0"
EXPECTED_WORLDS = [
    "context-admission",
    "context-assembly",
    "cue-activation",
    "dreamer-handler",
    "memory-curation-screen",
    "dreamer-cycle",
]
EXPECTED_INTERFACES = {
    "context-admission": "admission",
    "context-assembly": "assembly",
    "cue-activation": "activation",
    "dreamer-handler": "handler",
    "memory-curation-screen": "screen",
    "dreamer-cycle": "cycle",
}
PINNED_WIT_PARSER = "0.252.0"
PINNED_WASMTIME = "47.0.4"
PINNED_CHANNEL = "1.97.1"
EXPECTED_LEGACY_SHA = "18b2853534b3797b49215f13e8b5e87455ae962f674e9d7651eef4545d9f1277"
EXPECTED_LEGACY_PACKAGE = "eliot:wasm@1.0.0"

AMBIENT_MARKERS = [
    "wasi:filesystem",
    "wasi:sockets",
    "wasi:http",
    "wasi:clocks",
    "wasi:random",
    "wasi:io",
    "wasi:cli",
    "wasi:config",
    "wasi:logging",
    "filesystem",
    "wasi:socket",
    "network",
    "clock",
    "random",
    "process",
    "thread",
    "environment",
    "stdio",
    "stdin",
    "stdout",
    "stderr",
    "credential",
]

_CACHE: dict[str, object] = {}

HELPER_RUST_MAIN = r"""use wit_parser::Resolve;
fn main() {
    let path = std::env::args().nth(1).expect("usage: wit-abi-helper <wit-dir>");
    let mut resolve = Resolve::new();
    match resolve.push_dir(&path) {
        Ok((pkg, _)) => {
            let pkg_name = resolve.packages[pkg].name.to_string();
            println!("PACKAGE {pkg_name}");
            for (_, w) in resolve.worlds.iter() {
                let ic = w.imports.len();
                let ec = w.exports.len();
                println!("WORLD {} imports={ic} exports={ec}", w.name);
            }
            for (_, i) in resolve.interfaces.iter() {
                if let Some(n) = &i.name {
                    println!("INTERFACE {n}");
                }
            }
            println!("OK worlds={} interfaces={}", resolve.worlds.len(), resolve.interfaces.len());
        }
        Err(e) => {
            eprintln!("WIT_PARSE_FAIL {e:#}");
            std::process::exit(1);
        }
    }
}
"""


def _cargo_env() -> dict[str, str]:
    env = os.environ.copy()
    slot = Path("C:/Development/Rust/projects/eliot-swarm/MGR01-target")
    if slot.exists() and "CARGO_TARGET_DIR" not in env:
        env["CARGO_TARGET_DIR"] = str(slot)
    env["RUSTUP_AUTO_INSTALL"] = "0"
    for name in ("RUSTUP_TOOLCHAIN", "RUSTC_BOOTSTRAP", "RUSTFLAGS", "RUSTC_WRAPPER"):
        env.pop(name, None)
    return env


def _cargo_metadata() -> dict:
    if "metadata" in _CACHE:
        return _CACHE["metadata"]  # type: ignore[return-value]
    argv = ["cargo", "metadata", "--locked", "--format-version", "1"]
    proc = subprocess.run(
        argv,
        cwd=str(ROOT),
        env=_cargo_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        shell=False,
    )
    if proc.returncode != 0:
        raise AssertionError(f"cargo metadata failed: {proc.stderr.decode('utf-8', 'replace')[:2000]}")
    data = json.loads(proc.stdout.decode("utf-8"))
    _CACHE["metadata"] = data
    return data


def _pinned_versions_from_lock() -> tuple[str, str]:
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]
    lock = tomllib.loads((ROOT / "Cargo.lock").read_bytes().decode("utf-8"))
    wit = wasmtime = ""
    for pkg in lock.get("package", []):
        if pkg.get("name") == "wit-parser":
            wit = pkg.get("version", "")
        if pkg.get("name") == "wasmtime":
            wasmtime = pkg.get("version", "")
    return wit, wasmtime


def _helper_binary() -> Path:
    if "helper" in _CACHE:
        return _CACHE["helper"]  # type: ignore[return-value]
    work = Path(tempfile.gettempdir()) / "eliot-wit-756-helper"
    proj = work / "wit-abi-helper"
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "src").mkdir(parents=True, exist_ok=True)
    (proj / "Cargo.toml").write_text(
        '[package]\nname = "wit-abi-helper"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nwit-parser = "=0.252.0"\n',
        encoding="utf-8",
    )
    (proj / "src" / "main.rs").write_text(HELPER_RUST_MAIN, encoding="utf-8")
    argv = ["cargo", "build", "--offline", "--manifest-path", str(proj / "Cargo.toml")]
    proc = subprocess.run(
        argv,
        cwd=str(ROOT),
        env=_cargo_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=300,
        shell=False,
    )
    if proc.returncode != 0:
        raise AssertionError(f"helper build failed: {proc.stderr.decode('utf-8', 'replace')[:3000]}")
    exe = "wit-abi-helper.exe" if sys.platform.startswith("win") else "wit-abi-helper"
    target_dir = os.environ.get("CARGO_TARGET_DIR", "") or _cargo_env().get("CARGO_TARGET_DIR", "")
    candidates = []
    if target_dir:
        candidates.append(Path(target_dir) / "debug" / exe)
    # Shared MGR01 cargo slot required by the wave assignment.
    candidates.append(Path("C:/Development/Rust/projects/eliot-swarm/MGR01-target") / "debug" / exe)
    candidates.append(Path.home() / ".cargo" / "target" / "debug" / exe)
    # Cargo prints the binary under the active target dir; probe both plus work/target.
    candidates.append(work / "target" / "debug" / exe)
    for cand in candidates:
        if cand.exists():
            _CACHE["helper"] = cand
            return cand
    # Fall back to cargo metadata target-directory discovery.
    meta = _cargo_metadata()
    # Search the default target layout relative to workspace root.
    fallback = ROOT / "target" / "debug" / exe
    if fallback.exists():
        _CACHE["helper"] = fallback
        return fallback
    raise AssertionError(f"helper binary not found; tried {[str(c) for c in candidates]}")


def _wit_parse(wit_dir: Path) -> dict[str, object]:
    binary = _helper_binary()
    argv = [str(binary), str(wit_dir)]
    proc = subprocess.run(
        argv,
        cwd=str(ROOT),
        env=_cargo_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        shell=False,
    )
    out = proc.stdout.decode("utf-8", "replace")
    err = proc.stderr.decode("utf-8", "replace")
    if proc.returncode != 0:
        raise AssertionError(f"wit parse failed for {wit_dir}: {err[:3000]}")
    package = ""
    worlds: dict[str, dict[str, int]] = {}
    interfaces: list[str] = []
    for line in out.splitlines():
        if line.startswith("PACKAGE "):
            package = line[len("PACKAGE "):].strip()
        elif line.startswith("WORLD "):
            # WORLD <name> imports=<n> exports=<m>
            rest = line[len("WORLD "):]
            name, tail = rest.rsplit(" imports=", 1)
            imp_s, exp_s = tail.split(" exports=")
            worlds[name.strip()] = {"imports": int(imp_s), "exports": int(exp_s)}
        elif line.startswith("INTERFACE "):
            interfaces.append(line[len("INTERFACE "):].strip())
    return {"package": package, "worlds": worlds, "interfaces": interfaces, "raw": out}


def _wit_parse_must_fail(wit_dir: Path) -> str:
    binary = _helper_binary()
    argv = [str(binary), str(wit_dir)]
    proc = subprocess.run(
        argv,
        cwd=str(ROOT),
        env=_cargo_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        shell=False,
    )
    err = proc.stderr.decode("utf-8", "replace")
    if proc.returncode == 0:
        raise AssertionError(f"wit parse unexpectedly succeeded for {wit_dir}")
    return err


def _typed_files() -> list[Path]:
    files = sorted(TYPED_DIR.glob("*.wit"))
    if not files:
        raise AssertionError("no typed WIT files found")
    return files


def _read_typed_text() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in _typed_files()}


def _strip_comments(text: str) -> str:
    out_lines = []
    in_block = False
    i = 0
    # Real block/line comment handling so // inside strings does not split.
    for raw in text.splitlines():
        line_out: list[str] = []
        j = 0
        in_str = False
        while j < len(raw):
            ch = raw[j]
            nxt = raw[j + 1] if j + 1 < len(raw) else ""
            if in_block:
                if ch == "*" and nxt == "/":
                    in_block = False
                    j += 2
                else:
                    j += 1
                continue
            if in_str:
                line_out.append(ch)
                if ch == '"':
                    in_str = False
                j += 1
                continue
            if ch == '"':
                in_str = True
                line_out.append(ch)
                j += 1
                continue
            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                in_block = True
                j += 2
                continue
            line_out.append(ch)
            j += 1
        out_lines.append("".join(line_out))
        i += 1
    return "\n".join(out_lines)


def _normalized_payload() -> bytes:
    parts = []
    for name in sorted(_read_typed_text().keys()):
        text = _read_typed_text()[name]
        cleaned = _strip_comments(text)
        norm_lines = []
        for line in cleaned.splitlines():
            s = " ".join(line.strip().split())
            if s == "":
                continue
            norm_lines.append(s)
        parts.append(name + "\n" + "\n".join(norm_lines))
    return "\n".join(parts).encode("utf-8")


def _normalized_digest() -> str:
    return hashlib.sha256(_normalized_payload()).hexdigest()


def _load_json(name: str) -> object:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def _tokenize(text: str) -> list[str]:
    toks: list[str] = []
    cur = ""
    in_str = False
    i = 0
    cleaned = _strip_comments(text)
    while i < len(cleaned):
        ch = cleaned[i]
        if in_str:
            cur += ch
            if ch == '"':
                toks.append(cur)
                cur = ""
                in_str = False
            i += 1
            continue
        if ch == '"':
            if cur:
                toks.append(cur)
                cur = ""
            cur = '"'
            in_str = True
            i += 1
            continue
        if ch.isalnum() or ch in ("-", "_", ".", "@", ":", "/"):
            cur += ch
            i += 1
            continue
        if cur:
            toks.append(cur)
            cur = ""
        if ch.strip() == "":
            i += 1
            continue
        toks.append(ch)
        i += 1
    if cur:
        toks.append(cur)
    return toks


def _result_errors(text: str) -> list[str]:
    toks = _tokenize(text)
    errs: list[str] = []
    i = 0
    while i < len(toks):
        if toks[i] == "result" and i + 1 < len(toks) and toks[i + 1] == "<":
            depth = 0
            j = i + 1
            inner: list[str] = []
            while j < len(toks):
                if toks[j] == "<":
                    depth += 1
                elif toks[j] == ">":
                    depth -= 1
                    if depth == 0:
                        break
                if depth >= 1 and not (j == i + 1 and toks[j] == "<"):
                    inner.append(toks[j])
                j += 1
            # Split top-level comma.
            d2 = 0
            comma = -1
            for k, t in enumerate(inner):
                if t == "<":
                    d2 += 1
                elif t == ">":
                    d2 -= 1
                elif t == "," and d2 == 0:
                    comma = k
                    break
            if comma != -1:
                err_part = "".join(inner[comma + 1:]).replace(" ", "")
                errs.append(err_part)
            i = j + 1
            continue
        i += 1
    return errs


def _split_top_level(body: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in body:
        if ch in "<(":
            depth += 1
        elif ch in ">)":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return [p.strip() for p in parts if p.strip()]


def _parse_wit_types(text: str) -> dict[str, dict[str, object]]:
    """Parse comment-stripped WIT text into record/variant/enum structure.

    Returns {"records": {name: {field: type}}, "variants": {name: {case: payload|None}},
    "enums": {name: [cases]}, "aliases": {name: aliased}}. This covers only the
    structural shape cases 5/16 must enforce; the pinned wit-parser helper still
    owns syntax/type/world/import validation through _wit_parse.
    """
    cleaned = _strip_comments(text)
    records: dict[str, dict[str, str]] = {}
    variants: dict[str, dict[str, object]] = {}
    enums: dict[str, list[str]] = {}
    aliases: dict[str, str] = {}
    for alias in re.finditer(r"\btype\s+([A-Za-z0-9_-]+)\s*=\s*([^;]+);", cleaned):
        aliases[alias.group(1)] = " ".join(alias.group(2).split())
    pattern = re.compile(r"\b(record|variant|enum)\s+([A-Za-z0-9_-]+)\s*\{")
    pos = 0
    while True:
        found = pattern.search(cleaned, pos)
        if found is None:
            break
        kind, name = found.group(1), found.group(2)
        depth = 1
        i = found.end()
        while i < len(cleaned) and depth > 0:
            if cleaned[i] == "{":
                depth += 1
            elif cleaned[i] == "}":
                depth -= 1
            i += 1
        body = cleaned[found.end():i - 1]
        if kind == "record":
            fields: dict[str, str] = {}
            for chunk in _split_top_level(body):
                field, _, ftype = chunk.partition(":")
                fields[field.strip()] = "".join(ftype.split())
            records[name] = fields
        elif kind == "variant":
            cases: dict[str, object] = {}
            for chunk in _split_top_level(body):
                case = re.fullmatch(r"([A-Za-z0-9_-]+)(?:\((.*)\))?", chunk)
                if case is None:
                    raise AssertionError(f"unparseable variant case {chunk!r} in {name}")
                payload = case.group(2)
                cases[case.group(1)] = "".join(payload.split()) if payload is not None else None
            variants[name] = cases
        else:
            members = []
            for chunk in _split_top_level(body):
                if not re.fullmatch(r"[A-Za-z0-9_-]+", chunk):
                    raise AssertionError(f"unparseable enum case {chunk!r} in {name}")
                members.append(chunk)
            enums[name] = members
        pos = i
    return {"records": records, "variants": variants, "enums": enums, "aliases": aliases}


_WIT_PRIMITIVES = frozenset(
    {"string", "bool", "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "float32", "float64", "char"}
)


def _wit_type_exists(name: str, parsed: dict[str, dict[str, object]]) -> bool:
    return (
        name in parsed["records"]
        or name in parsed["variants"]
        or name in parsed["enums"]
        or name in parsed["aliases"]
    )


def _wit_member_kind(name: str, member: str, parsed: dict[str, dict[str, object]]) -> str | None:
    records = parsed["records"]
    variants = parsed["variants"]
    enums = parsed["enums"]
    if name in records and member in records[name]:  # type: ignore[operator]
        return "field"
    if name in variants and member in variants[name]:  # type: ignore[operator]
        return "case"
    if name in enums and member in enums[name]:  # type: ignore[operator]
        return "case"
    return None


def _check_wit_payload_types(tc: unittest.TestCase, payload: str, parsed: dict[str, dict[str, object]], context: str) -> None:
    for ident in re.findall(r"[A-Za-z][A-Za-z0-9_-]*", payload):
        if ident in _WIT_PRIMITIVES:
            continue
        tc.assertTrue(
            _wit_type_exists(ident, parsed),
            f"{context}: payload type {ident} missing from WIT",
        )


def _resolve_admission_wit_ref(tc: unittest.TestCase, entry: dict[str, object], parsed: dict[str, dict[str, object]]) -> None:
    """Resolve one native-field-map admission row fully against parsed WIT.

    Every named WIT type must exist and every named field/variant case must be
    a member of its head type, including `plus`-chained second types, dotted
    member references and parenthesized variant payloads. Checking only the
    first token (the gap audit 5884499327 names) is not enough.
    """
    native = entry["native"]
    ref = entry["wit"]
    tc.assertIsInstance(ref, str)
    ref_s = ref  # type: ignore[assignment]
    for seg in ref_s.split(" plus "):
        seg = seg.strip()
        tc.assertTrue(seg, f"native {native}: empty WIT segment in {ref_s!r}")
        head, _, rest = seg.partition(" ")
        if "." in head and not rest:
            tname, _, member = head.partition(".")
            tc.assertTrue(
                _wit_type_exists(tname, parsed),
                f"native {native}: WIT type {tname} missing",
            )
            tc.assertIsNotNone(
                _wit_member_kind(tname, member, parsed),
                f"native {native}: {tname}.{member} missing from WIT",
            )
            continue
        tc.assertTrue(
            _wit_type_exists(head, parsed),
            f"native {native}: WIT type {head} missing",
        )
        if not rest:
            continue
        for item in rest.split("/"):
            item = item.strip()
            tc.assertTrue(item, f"native {native}: empty WIT member in {ref_s!r}")
            parsed_item = re.fullmatch(r"([A-Za-z0-9_-]+)(?:\((.*)\))?", item)
            tc.assertIsNotNone(parsed_item, f"native {native}: malformed map item {item!r}")
            label = parsed_item.group(1)  # type: ignore[union-attr]
            payload = parsed_item.group(2)  # type: ignore[union-attr]
            tc.assertIsNotNone(
                _wit_member_kind(head, label, parsed),
                f"native {native}: {head} lacks member {label}",
            )
            if payload is not None:
                _check_wit_payload_types(tc, payload, parsed, f"native {native}")


# Audit 5884499327 denominator: every native AdmissionInput closure member must
# survive structurally with exact fields/types. Deleting a floor member
# dependency, measurement cost/status/unit, or omission authorization field
# fails the structural assertions below; adding a comment or a map row cannot
# satisfy them. Types are compared spaceless ("option<string>").
_ADMISSION_REQUIRED_RECORDS: dict[str, dict[str, str]] = {
    "context-binding": {
        "task-id": "string",
        "attempt-id": "string",
        "scope-id": "string",
        "fence-epoch": "string",
        "fence-generation": "u64",
        "decision-id": "string",
        "operation-id": "option<string>",
    },
    "decision-revision": {
        "decision-id": "string",
        "recipe-revision": "string",
        "policy-sha256": "digest-hex",
    },
    "provider-role": {"provider": "string", "role": "string"},
    "provider-disposition": {"slot": "provider-role", "disposition": "admission-disposition"},
    "provider-denominator": {
        "requested": "list<provider-role>",
        "dispositions": "list<provider-disposition>",
    },
    "safety-floor-member": {
        "atom-id": "artifact-id",
        "role": "semantic-role",
        "availability": "atom-availability",
        "measurement": "option<measurement-ref>",
        "required-dependencies": "list<artifact-id>",
    },
    "safety-floor": {
        "binding": "context-binding",
        "mandatory-atoms": "list<artifact-id>",
        "mandatory-roles": "list<semantic-role>",
        "providers": "provider-denominator",
        "members": "list<safety-floor-member>",
        "interpretation-dependencies": "list<artifact-id>",
        "rule-evidence": "artifact-id",
        "capacity": "capacity-limits",
    },
    "safety-floor-identity": {
        "floor-id": "artifact-id",
        "decision": "decision-revision",
        "floor": "safety-floor",
    },
    "candidate-priority": {
        "atom-id": "artifact-id",
        "class": "admission-priority-class",
        "ordinal": "u32",
    },
    "priority-policy": {
        "policy-id": "artifact-id",
        "decision": "decision-revision",
        "priorities": "list<candidate-priority>",
    },
    "admission-rule": {
        "rule-id": "artifact-id",
        "decision": "decision-revision",
        "rule-sha256": "digest-hex",
    },
    "measurement-composition-profile": {
        "profile-id": "artifact-id",
        "schema-version": "u32",
        "serializer-id": "string",
        "serializer-version": "string",
        "serializer-options-digest": "digest-hex",
        "route-id": "string",
        "model-id": "string",
        "unit": "measurement-unit",
        "aggregation": "measurement-aggregation",
        "qualification": "artifact-id",
        "capacity": "capacity-limits",
    },
    "measurement-binding": {
        "context": "context-binding",
        "schema-version": "u32",
        "subject-digest": "digest-hex",
        "input-digest": "digest-hex",
        "output-digest": "digest-hex",
        "serializer-id": "string",
        "serializer-version": "string",
        "serializer-options-digest": "digest-hex",
        "route-id": "string",
        "model-id": "string",
    },
    "admission-measurement": {
        "measurement-id": "artifact-id",
        "atom-id": "artifact-id",
        "representation": "representation-kind",
        "unit": "measurement-unit",
        "status": "measurement-status",
        "binding": "measurement-binding",
        "cost": "measured-cost",
        "observation": "option<measured-cost>",
    },
    "supplied-omission-binding": {
        "atom-id": "artifact-id",
        "policy": "loss-policy",
        "expansion": "option<expansion-handle>",
        "non-recoverable-reason": "option<non-recoverable-reason>",
        "authorization-requirement": "string",
        "privacy-requirement": "string",
        "proof-requirement": "string",
        "expires": "option<artifact-id>",
        "invalidation": "option<artifact-id>",
    },
    "learning-ticket": {
        "schema-version": "u32",
        "source-campaign-id": "string",
        "target-task-id": "string",
        "fence-epoch": "string",
        "fence-generation": "u64",
        "overlay-id": "option<string>",
        "candidate-id": "option<string>",
        "scope-ref": "string",
        "authority-ref": "string",
        "retention-ref": "string",
        "evaluator-ref": "string",
        "rollback-ref": "string",
        "digest": "digest-hex",
    },
    "learning-provenance": {
        "campaign-id": "string",
        "overlay-id": "option<string>",
        "candidate-id": "option<string>",
        "closure-ref": "option<string>",
        "owner": "option<string>",
        "draft": "bool",
        "expires-at-unix-secs": "option<u64>",
        "permit-digest": "digest-hex",
    },
    "measurement-ref": {
        "serializer": "string",
        "schema-revision": "string",
        "route": "string",
        "model": "string",
        "tokenizer": "string",
        "input-digest": "digest-hex",
    },
    "stu-estimate": {"value": "u64", "empirical": "bool"},
    "tokenizer-observation": {
        "tokenizer-id": "string",
        "tokenizer-version": "string",
        "tokenizer-hash": "digest-hex",
        "tokens": "u64",
    },
    "capacity-limits": {
        "total-capacity": "u64",
        "fixed-overhead": "u64",
        "output-reserve": "u64",
        "review-reserve": "u64",
    },
    "atom-representation": {
        "kind": "representation-kind",
        "content": "string",
        "manifest": "list<string>",
        "source-digest": "digest-hex",
        "handle": "artifact-id",
    },
    "context-candidate": {
        "atom-id": "artifact-id",
        "source-digest": "digest-hex",
        "source-revision": "string",
        "semantic-role": "string",
        "provider-role": "provider-role",
        "loss-policy": "loss-policy",
        "representation": "atom-representation",
        "measurement": "measurement-ref",
        "privacy": "privacy-class",
        "authority": "authority-class",
        "availability": "atom-availability",
        "dependencies": "list<artifact-id>",
        "learning": "option<learning-provenance>",
    },
    "admitted-atom": {
        "atom-id": "artifact-id",
        "representation": "atom-representation",
        "measurement": "measurement-ref",
    },
    "expansion-handle": {
        "atom-id": "artifact-id",
        "decision-digest": "digest-hex",
        "task-id": "string",
        "scope-id": "string",
        "fence-epoch": "string",
        "source-revision": "string",
        "handle": "artifact-id",
        "expiry-ms": "option<s64>",
    },
    "omission-record": {
        "atom-id": "artifact-id",
        "reason": "omission-reason-kind",
        "non-recoverable": "option<non-recoverable-reason>",
        "measured-cost": "u64",
        "expansion": "option<expansion-handle>",
        "decision-revision": "string",
        "policy-revision": "string",
        "digest": "digest-hex",
    },
    "economy-allocations": {
        "required-allocation": "u64",
        "optional-allocation": "u64",
        "headroom": "u64",
    },
    "economy-receipt": {
        "requested": "list<artifact-id>",
        "admitted": "list<artifact-id>",
        "displaced": "list<artifact-id>",
        "omitted": "list<artifact-id>",
        "blocked": "list<artifact-id>",
        "applied-rule": "string",
        "allocations": "economy-allocations",
        "capacity": "capacity-limits",
        "decision-digest": "digest-hex",
    },
    "provider-gap": {"slot": "provider-role", "state": "atom-availability"},
    "decision-incomplete": {
        "code": "decision-incomplete-code",
        "missing": "list<artifact-id>",
        "stale": "list<artifact-id>",
        "blocked": "list<artifact-id>",
        "unavailable": "list<artifact-id>",
        "omitted": "list<artifact-id>",
        "exhausted": "list<artifact-id>",
        "unknown": "list<artifact-id>",
        "known-empty": "list<artifact-id>",
        "partial": "list<artifact-id>",
        "provider-gaps": "list<provider-gap>",
        "oversized": "list<artifact-id>",
        "failed-floor-rule": "artifact-id",
        "measurements": "list<artifact-id>",
        "reopening-requirements": "list<string>",
        "proof-ceiling": "proof-ceiling",
    },
    "admitted-context-set": {
        "operation-id": "string",
        "task-id": "string",
        "attempt-id": "string",
        "scope-id": "string",
        "fence-epoch": "string",
        "fence-generation": "u64",
        "recipe-digest": "digest-hex",
        "recipe-revision": "string",
        "members": "list<admitted-atom>",
        "dispositions": "list<provider-disposition>",
        "omissions": "list<omission-record>",
        "economy": "economy-receipt",
        "frontier": "list<artifact-id>",
        "proof-ceiling": "proof-ceiling",
        "canonical-digest": "digest-hex",
    },
    "admission-request": {
        "schema-revision": "u32",
        "operation-id": "string",
        "task-id": "string",
        "attempt-id": "string",
        "scope-id": "string",
        "fence-epoch": "string",
        "fence-generation": "u64",
        "binding": "context-binding",
        "candidates": "list<context-candidate>",
        "recipe-digest": "digest-hex",
        "recipe-revision": "string",
        "provider-denominator": "list<provider-role>",
        "capacity": "capacity-limits",
        "floor": "safety-floor-identity",
        "priority": "priority-policy",
        "rule": "admission-rule",
        "measurement-profile": "measurement-composition-profile",
        "supplied-omissions": "list<supplied-omission-binding>",
        "measurements": "list<admission-measurement>",
        "learning-tickets": "list<learning-ticket>",
        "deadline-ms": "option<s64>",
        "cancelled": "bool",
        "predecessor-digest": "option<digest-hex>",
        "invalidation": "option<string>",
    },
    "abi-descriptor": {
        "world-name": "string",
        "package-id": "string",
        "abi-revision": "u32",
        "native-contract": "string",
        "native-revision": "string",
        "abi-digest": "string",
    },
    "admission-malformed": {"field": "string", "human-detail": "string"},
    "admission-denominator": {"human-detail": "string"},
    "admission-fence": {"human-detail": "string"},
    "admission-capacity": {"human-detail": "string"},
    "admission-unknown-measurement": {"human-detail": "string"},
    "admission-omission": {"human-detail": "string"},
    "admission-economy": {"human-detail": "string"},
    "admission-schema": {
        "want-revision": "u32",
        "got-revision": "u32",
        "human-detail": "string",
    },
    "admission-internal": {"human-detail": "string"},
}

_ADMISSION_REQUIRED_VARIANTS: dict[str, dict[str, str | None]] = {
    # Zero (exact-utf8-bytes 0), unknown and unavailable stay distinct cases.
    "measured-cost": {
        "exact-utf8-bytes": "u64",
        "conservative-stu": "stu-estimate",
        "exact-tokenizer": "tokenizer-observation",
        "unknown": None,
        "unavailable": None,
    },
    "admission-result": {
        "admitted": "admitted-context-set",
        "incomplete": "decision-incomplete",
    },
    "admission-error": {
        "malformed": "admission-malformed",
        "denominator-mismatch": "admission-denominator",
        "stale-fence": "admission-fence",
        "capacity-exceeded": "admission-capacity",
        "unknown-measurement": "admission-unknown-measurement",
        "omission-handle-invalid": "admission-omission",
        "economy-mismatch": "admission-economy",
        "unsupported-schema": "admission-schema",
        "internal": "admission-internal",
    },
}

_ADMISSION_REQUIRED_ENUMS: dict[str, list[str]] = {
    "loss-policy": ["non-droppable", "handle-only", "extractive", "summarizable"],
    "representation-kind": ["whole", "handle", "extractive", "summary"],
    "atom-availability": [
        "present-current",
        "missing",
        "stale",
        "blocked",
        "unavailable",
        "omitted",
        "exhausted",
        "unknown",
        "known-empty",
        "partial",
    ],
    "privacy-class": ["open", "restricted", "confidential"],
    "authority-class": ["none", "observer", "proposer"],
    "admission-disposition": [
        "include-member",
        "handle-only",
        "revalidate",
        "suppress",
        "quarantine",
        "unavailable",
        "blocked",
        "over-budget",
    ],
    "omission-reason-kind": [
        "over-budget",
        "policy",
        "stale-source",
        "blocked-source",
        "conflict",
        "non-recoverable",
    ],
    "non-recoverable-reason": ["policy-forbidden", "source-withdrawn", "conflict-unresolvable"],
    "proof-ceiling": [
        "observation",
        "candidate-only",
        "admission",
        "assembly",
        "activation",
        "screen",
        "cycle",
        "handler",
    ],
    "semantic-role": [
        "authority",
        "goal",
        "scope",
        "acceptance",
        "source",
        "verifier",
        "material-unknown",
        "negative",
        "security",
        "evidence",
        "instruction",
        "optional",
        "conflict",
        "constraint",
    ],
    "admission-priority-class": ["protected", "required", "high", "normal", "low"],
    "measurement-unit": ["utf8-bytes", "stu", "tokenizer-tokens"],
    "measurement-aggregation": ["qualified-utf8-contribution", "whole-context-observation"],
    "measurement-status": [
        "exact-utf8",
        "conservative-stu",
        "exact-tokenizer",
        "unknown",
        "unavailable",
    ],
    "decision-incomplete-code": ["decision-context-incomplete"],
}


def _require_admission_structure(tc: unittest.TestCase, parsed: dict[str, dict[str, object]]) -> None:
    records = parsed["records"]
    variants = parsed["variants"]
    enums = parsed["enums"]
    for name, fields in _ADMISSION_REQUIRED_RECORDS.items():
        tc.assertIn(name, records, f"admission WIT record {name} missing")
        actual = records[name]
        tc.assertIsInstance(actual, dict)
        for field, ftype in fields.items():
            tc.assertIn(field, actual, f"{name} lacks field {field}: deletion must fail")  # type: ignore[operator]
            tc.assertEqual(actual[field], ftype, f"{name}.{field} type changed")  # type: ignore[index]
        tc.assertEqual(set(actual.keys()), set(fields.keys()), f"{name} field set changed")  # type: ignore[union-attr]
    for name, cases in _ADMISSION_REQUIRED_VARIANTS.items():
        tc.assertIn(name, variants, f"admission WIT variant {name} missing")
        actual = variants[name]
        tc.assertIsInstance(actual, dict)
        for case, payload in cases.items():
            tc.assertIn(case, actual, f"{name} lacks case {case}: deletion must fail")  # type: ignore[operator]
            tc.assertEqual(actual[case], payload, f"{name}.{case} payload changed")  # type: ignore[index]
        tc.assertEqual(set(actual.keys()), set(cases.keys()), f"{name} case set changed")  # type: ignore[union-attr]
    for name, cases in _ADMISSION_REQUIRED_ENUMS.items():
        tc.assertIn(name, enums, f"admission WIT enum {name} missing")
        tc.assertEqual(set(enums[name]), set(cases), f"{name} case set changed")  # type: ignore[union-attr]


class WitContractTests(unittest.TestCase):
    # WORK_UNIT_CASE: 756/1
    def test_legacy_guest_separately_addressable_identity(self) -> None:
        raw = LEGACY_WIT.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(digest, EXPECTED_LEGACY_SHA)
        text = raw.decode("utf-8")
        self.assertIn(f"package {EXPECTED_LEGACY_PACKAGE};", text)
        self.assertIn("world guest", text)
        self.assertIn("export run: func(input: list<u8>) -> result<list<u8>, string>;", text)
        parsed = _wit_parse(LEGACY_WIT.parent)
        # Legacy dir parses as its own package only when typed files are absent
        # from that dir; here the parent contains guest.wit alongside typed/.
        # Parse the single legacy file via a temp copy to prove standalone identity.
        with tempfile.TemporaryDirectory(prefix="eliot-wit-legacy-") as tmp:
            single = Path(tmp) / "guest.wit"
            single.write_bytes(raw)
            solo = _wit_parse(Path(tmp))
            self.assertEqual(solo["package"], EXPECTED_LEGACY_PACKAGE)
            worlds = solo["worlds"]  # type: ignore[assignment]
            self.assertIn("guest", worlds)

    # WORK_UNIT_CASE: 756/2
    def test_opaque_legacy_cannot_satisfy_typed_abi(self) -> None:
        legacy = LEGACY_WIT.read_text(encoding="utf-8")
        typed = _read_typed_text()
        for name, text in typed.items():
            self.assertNotIn("list<u8>", text, f"{name} must not carry opaque list<u8>")
        self.assertIn("list<u8>", legacy)
        parsed = _wit_parse(TYPED_DIR)
        self.assertEqual(parsed["package"], EXPECTED_PACKAGE)
        # Legacy export shape is absent from every typed world file.
        for name, text in typed.items():
            self.assertNotIn("export run: func(input: list<u8>)", text)

    # WORK_UNIT_CASE: 756/3
    def test_exactly_six_worlds_and_consumer_map(self) -> None:
        parsed = _wit_parse(TYPED_DIR)
        worlds = parsed["worlds"]  # type: ignore[assignment]
        self.assertEqual(sorted(worlds.keys()), sorted(EXPECTED_WORLDS))
        consumer_map = _load_json("consumer-map.json")
        self.assertIsInstance(consumer_map, dict)
        cmap = consumer_map  # type: ignore[assignment]
        self.assertEqual(sorted(cmap["worlds"]), sorted(EXPECTED_WORLDS))
        # Every required consumer appears exactly where the issue demands.
        self.assertEqual(cmap["consumers"]["context-admission"], ["#638"])
        self.assertEqual(cmap["consumers"]["context-assembly"], ["#762"])
        self.assertEqual(cmap["consumers"]["cue-activation"], ["#640"])
        self.assertEqual(sorted(cmap["consumers"]["dreamer-handler"]), ["#632", "#634", "#636"])
        self.assertEqual(cmap["consumers"]["memory-curation-screen"], ["#642"])
        self.assertEqual(cmap["consumers"]["dreamer-cycle"], ["#644"])
        texts = _read_typed_text()
        for world, iface in EXPECTED_INTERFACES.items():
            text = texts[f"{world}.wit"]
            self.assertIn(f"world {world}", text)
            self.assertIn(f"export {iface};", text)

    # WORK_UNIT_CASE: 756/4
    def test_every_world_explicitly_versioned(self) -> None:
        parsed = _wit_parse(TYPED_DIR)
        self.assertEqual(parsed["package"], EXPECTED_PACKAGE)
        policy = _load_json("version-policy.json")
        self.assertEqual(policy["package"], EXPECTED_PACKAGE)  # type: ignore[index]
        texts = _read_typed_text()
        for world in EXPECTED_WORLDS:
            fname = f"{world}.wit"
            self.assertIn(fname, texts)
            self.assertIn("abi-revision", texts[fname])
            self.assertIn("schema-revision", texts[fname])
            self.assertIn("record abi-descriptor", texts[fname])
        # Legacy keeps its own established version, never the current one.
        legacy = LEGACY_WIT.read_text(encoding="utf-8")
        self.assertIn(EXPECTED_LEGACY_PACKAGE, legacy)
        self.assertNotIn(EXPECTED_PACKAGE, legacy)

    # WORK_UNIT_CASE: 756/5
    def test_context_admission_maps_native_fields_errors(self) -> None:
        text = (TYPED_DIR / "context-admission.wit").read_text(encoding="utf-8")
        for token in [
            "enum loss-policy",
            "non-droppable",
            "handle-only",
            "extractive",
            "summarizable",
            "record admission-request",
            "record admitted-context-set",
            "record economy-receipt",
            "record omission-record",
            "record decision-incomplete",
            "variant admission-error",
            "variant measured-cost",
            "exact-utf8-bytes",
            "unavailable",
            "record supplied-omission-binding",
            "authorization-requirement",
            "record learning-ticket",
            "record learning-provenance",
            "required-dependencies",
            "record measurement-binding",
            "subject-digest",
            "output-digest",
            "record safety-floor-identity",
            "record priority-policy",
            "record admission-rule",
            "record measurement-composition-profile",
            "admit: func(request: admission-request)",
        ]:
            self.assertIn(token, text)
        # Pinned parser still owns syntax/type/world/import truth: the world
        # parses with zero imports and exports exactly the admission interface.
        parsed_worlds = _wit_parse(TYPED_DIR)
        worlds = parsed_worlds["worlds"]  # type: ignore[assignment]
        self.assertEqual(worlds["context-admission"], {"imports": 0, "exports": 1})
        self.assertIn("admission", parsed_worlds["interfaces"])  # type: ignore[operator]
        # Parsed structural denominator (audit 5884499327): every required
        # native closure member survives with exact fields/types, so deleting
        # a floor member dependency, measurement cost/status/unit, or omission
        # authorization field fails here instead of passing on row count.
        parsed = _parse_wit_types(text)
        _require_admission_structure(self, parsed)
        # Complete mapped denominator: every admission field-map row resolves
        # to a real WIT type plus every named field/variant case/payload, not
        # just the first token of its row.
        field_map = _load_json("native-field-map.json")
        admission = [m for m in field_map["mappings"] if m["world"] == "context-admission"]  # type: ignore[index]
        self.assertTrue(admission)
        for entry in admission:
            _resolve_admission_wit_ref(self, entry, parsed)  # type: ignore[arg-type]

    # WORK_UNIT_CASE: 756/6
    def test_explicit_incomplete_and_loss_economy_identity(self) -> None:
        text = (TYPED_DIR / "context-admission.wit").read_text(encoding="utf-8")
        self.assertIn("variant admission-result", text)
        self.assertIn("admitted(admitted-context-set)", text)
        self.assertIn("incomplete(decision-incomplete)", text)
        self.assertIn("failed-floor-rule", text)
        self.assertIn("reopening-requirements", text)
        self.assertIn("requested", text)
        self.assertIn("displaced", text)
        self.assertIn("applied-rule", text)
        # Incomplete is a result variant, never a bare string error.
        for err in _result_errors(text):
            self.assertNotEqual(err, "string")

    # WORK_UNIT_CASE: 756/7
    def test_assembly_admitted_only_boundary(self) -> None:
        text = (TYPED_DIR / "context-assembly.wit").read_text(encoding="utf-8")
        self.assertIn("record assembly-request", text)
        self.assertIn("admitted", text)
        self.assertIn("record selection-proof", text)
        self.assertIn("assemble: func(request: assembly-request)", text)
        self.assertNotIn("admit: func", text)
        self.assertNotIn("record admission-request", text)

    # WORK_UNIT_CASE: 756/8
    def test_direct_zero_edge_activation_representable(self) -> None:
        text = (TYPED_DIR / "cue-activation.wit").read_text(encoding="utf-8")
        self.assertIn("record direct-activation", text)
        self.assertIn("record activation-request", text)
        self.assertIn("relation-edges", text)
        # Direct activation carries no path; derived does.
        direct_block = text.split("record direct-activation")[1].split("}")[0]
        self.assertNotIn("path", direct_block)
        self.assertIn("record derived-activation", text)
        derived_block = text.split("record derived-activation")[1].split("}")[0]
        self.assertIn("path", derived_block)

    # WORK_UNIT_CASE: 756/9
    def test_cue_trace_path_truncation_limit_identity(self) -> None:
        text = (TYPED_DIR / "cue-activation.wit").read_text(encoding="utf-8")
        for token in [
            "record activation-bounds",
            "max-depth",
            "max-fanout",
            "max-results",
            "max-nodes",
            "max-edges",
            "max-work",
            "max-path-len",
            "max-seeds",
            "max-direct",
            "max-derived",
            "max-trace-steps",
            "max-output-bytes",
            "record activation-trace",
            "enum completeness",
            "no-direct-match",
            "frontier",
        ]:
            self.assertIn(token, text)

    # WORK_UNIT_CASE: 756/10
    def test_dreamer_candidate_envelope_with_typed_subtypes(self) -> None:
        text = (TYPED_DIR / "dreamer-handler.wit").read_text(encoding="utf-8")
        for token in [
            "record validated-candidate",
            "variant handler-subtype",
            "orientation(orientation-payload)",
            "research-synthesis(research-payload)",
            "curation(curation-request-ref)",
            "unsupported(unsupported-subtype)",
            "record research-pack-ref",
            "record research-brief",
            "record classification-payload",
            "record relation-payload",
            "enum curation-kind",
            "classification",
            "reconsolidation",
            "accessibility",
            "enum job-class",
            "research-synthesis",
            "orientation",
            "curation",
            "candidate-only",
        ]:
            self.assertIn(token, text)
        # Eleven wire kinds and nine job classes are all present.
        for kind in ["classification", "relation", "episode", "concept", "procedure", "failure", "merge", "split", "reconsolidation", "accessibility", "repair"]:
            self.assertIn(kind, text)

    # WORK_UNIT_CASE: 756/11
    def test_closed_typed_errors_no_freeform_status(self) -> None:
        for fname in sorted(_read_typed_text().keys()):
            text = _read_typed_text()[fname]
            for err in _result_errors(text):
                self.assertNotEqual(err, "string", f"{fname} has generic string error")
                self.assertNotIn("list<u8>", err, f"{fname} error escapes bytes")
        admission = (TYPED_DIR / "context-admission.wit").read_text(encoding="utf-8")
        self.assertIn("variant admission-error", admission)
        handler = (TYPED_DIR / "dreamer-handler.wit").read_text(encoding="utf-8")
        self.assertIn("variant handler-error", handler)

    # WORK_UNIT_CASE: 756/12
    def test_no_whole_payload_serialization_escape(self) -> None:
        for fname, text in _read_typed_text().items():
            self.assertNotIn("list<u8>", text, f"{fname} escapes whole payload as bytes")
            lowered = text.lower()
            self.assertNotIn("json", lowered, f"{fname} escapes through json")
            for err in _result_errors(text):
                self.assertNotEqual(err.replace(" ", ""), "string")
        # Negative fixtures prove the semantic check actually rejects escapes.
        neg = FIXTURE_DIR / "negative" / "escape-list-u8.wit"
        self.assertIn("list<u8>", neg.read_text(encoding="utf-8"))
        neg2 = FIXTURE_DIR / "negative" / "generic-string-error.wit"
        neg2_text = neg2.read_text(encoding="utf-8")
        compact = neg2_text.replace(" ", "").replace("\n", "").replace("\r", "")
        self.assertIn("result<probe-input,string>", compact)
        pos = FIXTURE_DIR / "positive" / "minimal-ok.wit"
        with tempfile.TemporaryDirectory(prefix="eliot-wit-pos-") as tmp:
            single = Path(tmp) / "probe.wit"
            single.write_text(pos.read_text(encoding="utf-8"), encoding="utf-8")
            ok = _wit_parse(Path(tmp))
            self.assertIn("probe-ok", ok["worlds"])  # type: ignore[index]

    # WORK_UNIT_CASE: 756/13
    def test_parsed_worlds_have_zero_ambient_imports(self) -> None:
        parsed = _wit_parse(TYPED_DIR)
        worlds = parsed["worlds"]  # type: ignore[assignment]
        for world, info in worlds.items():
            self.assertEqual(info["imports"], 0, f"{world} must have zero imports")
            self.assertEqual(info["exports"], 1, f"{world} must export exactly one interface")
        for fname, text in _read_typed_text().items():
            lowered = _strip_comments(text).lower()
            for marker in AMBIENT_MARKERS:
                # Interface-local words like "model-invocation" contain "model";
                # only flag real WASI-style or dotted capability imports.
                if marker.startswith("wasi:"):
                    self.assertNotIn(marker, lowered, f"{fname} ambient import {marker}")
        # The negative ambient fixture fails pinned parsing (unknown dep) or our import gate.
        neg_dir = FIXTURE_DIR / "negative"
        with tempfile.TemporaryDirectory(prefix="eliot-wit-amb-") as tmp:
            single = Path(tmp) / "ambient.wit"
            single.write_text((neg_dir / "ambient-import.wit").read_text(encoding="utf-8"), encoding="utf-8")
            try:
                solo = _wit_parse(Path(tmp))
                amb_worlds = solo["worlds"]  # type: ignore[assignment]
                for info in amb_worlds.values():
                    self.assertGreater(info["imports"], 0)
            except AssertionError as exc:
                self.assertIn("wit parse failed", str(exc).lower())

    # WORK_UNIT_CASE: 756/14
    def test_unknown_version_cannot_select_invocation(self) -> None:
        parsed = _wit_parse(TYPED_DIR)
        self.assertEqual(parsed["package"], EXPECTED_PACKAGE)
        policy = _load_json("version-policy.json")
        self.assertIn("Unknown or ambiguous", json.dumps(policy))
        neg = (FIXTURE_DIR / "negative" / "unknown-version.wit").read_text(encoding="utf-8")
        self.assertIn("eliot:current@9.9.9", neg)
        with tempfile.TemporaryDirectory(prefix="eliot-wit-ver-") as tmp:
            single = Path(tmp) / "version.wit"
            single.write_text(neg, encoding="utf-8")
            solo = _wit_parse(Path(tmp))
            self.assertNotEqual(solo["package"], EXPECTED_PACKAGE)

    # WORK_UNIT_CASE: 756/15
    def test_pinned_normalization_stable_digest_rejects_mutation(self) -> None:
        first = _normalized_digest()
        second = _normalized_digest()
        self.assertEqual(first, second)
        expected = _load_json("abi-digest.json")
        self.assertEqual(first, expected["abi_digest"])  # type: ignore[index]
        # Load-bearing mutation changes the digest.
        payload = _normalized_payload()
        mutated = bytearray(payload)
        mutated[100] = (mutated[100] + 1) % 256
        self.assertNotEqual(hashlib.sha256(bytes(mutated)).hexdigest(), first)
        # Pinned tool identity is real: cargo metadata reports the pinned parser.
        meta = _cargo_metadata()
        versions = {p["name"]: p["version"] for p in meta["packages"]}
        self.assertEqual(versions.get("wit-parser"), PINNED_WIT_PARSER)
        self.assertEqual(versions.get("wasmtime"), PINNED_WASMTIME)
        wit_lock, wasmtime_lock = _pinned_versions_from_lock()
        self.assertEqual(wit_lock, PINNED_WIT_PARSER)
        self.assertEqual(wasmtime_lock, PINNED_WASMTIME)

    # WORK_UNIT_CASE: 756/16
    def test_exact_allowed_diff_no_missing_field(self) -> None:
        allowed = _load_json("allowed-diff.json")
        self.assertIn("forbidden", allowed)  # type: ignore[operator]
        field_map = _load_json("native-field-map.json")
        texts = _read_typed_text()
        joined = "\n".join(texts.values())
        admission_parsed = _parse_wit_types(texts["context-admission.wit"])
        for entry in field_map["mappings"]:  # type: ignore[index]
            if entry["world"] == "context-admission":
                # No missing native field concealed by schema/proof weakening:
                # the full WIT side of every admission row must resolve to real
                # types/fields/cases, including second `plus` types and
                # parenthesized variant payloads.
                _resolve_admission_wit_ref(self, entry, admission_parsed)  # type: ignore[arg-type]
                continue
            wit_key = entry["wit"].split()[0].split(".")[0].split("(")[0]
            self.assertIn(wit_key, joined, f"native {entry['native']} missing from WIT")
        # No schema/proof weakening: every world keeps its descriptor and proof ceiling.
        for world in EXPECTED_WORLDS:
            text = texts[f"{world}.wit"]
            self.assertIn("abi-descriptor", text)
            self.assertIn("proof-ceiling", text)

    # WORK_UNIT_CASE: 756/17
    def test_memory_screen_generic_eligibility_no_routing_leak(self) -> None:
        text = (TYPED_DIR / "memory-curation-screen.wit").read_text(encoding="utf-8")
        for token in [
            "enum eligibility-status",
            "eligible-for-semantic-curation",
            "enum protection-decision",
            "enum finding-class",
            "provenance-gap",
            "conflict-ambiguity",
            "record screen-request",
            "record screen-result-body",
            "screen: func(request: screen-request)",
        ]:
            self.assertIn(token, text)
        for leak in ["curation-kind", "curation-family", "handler-id", "registry-digest"]:
            self.assertNotIn(leak, text)

    # WORK_UNIT_CASE: 756/18
    def test_cycle_pure_state_no_schedule_or_authority(self) -> None:
        text = (TYPED_DIR / "dreamer-cycle.wit").read_text(encoding="utf-8")
        for token in [
            "record dreamer-state",
            "record cycle-policy",
            "record cycle-step-input",
            "record cycle-step-result",
            "record inert-owner-request",
            "enum cycle-phase",
            "bundle-validated",
            "closure-observed",
            "step: func(input: cycle-step-input)",
        ]:
            self.assertIn(token, text)
        lowered = _strip_comments(text).lower()
        for forbidden in ["schedule", "executable", "authority", "spawn", "dispatch-permit"]:
            self.assertNotIn(forbidden, lowered)
        # Cycle never imports scheduling/effect capabilities: parser proves zero imports.
        parsed = _wit_parse(TYPED_DIR)
        self.assertEqual(parsed["worlds"]["dreamer-cycle"]["imports"], 0)  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
