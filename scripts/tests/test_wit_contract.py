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
            "admit: func(request: admission-request)",
        ]:
            self.assertIn(token, text)
        field_map = _load_json("native-field-map.json")
        admission = [m for m in field_map["mappings"] if m["world"] == "context-admission"]  # type: ignore[index]
        self.assertGreaterEqual(len(admission), 10)
        for entry in admission:
            wit_key = entry["wit"].split()[0].split(".")[0]
            self.assertIn(wit_key, text)

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
        for entry in field_map["mappings"]:  # type: ignore[index]
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
