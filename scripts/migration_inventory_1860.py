#!/usr/bin/env python3
"""Migration inventory and impact graph for issue #1860 (bins/eliotd coordination).

Deterministic, stdlib-only evidence tool. It never builds or runs repository
code, never mutates source/issues/workflows, and never promotes a package to
production support. It reads tracked manifests plus fixed Git/Cargo identity
commands and emits one canonical JSON document below `.eliot/`.

Outputs (via --emit):
  .eliot/migration-inventory-1860.json  -- full inventory, dispositions,
     active-reference scan, repair impact graph, Product Proof plan pointer.

Subcommands:
  --self-test   fixture-only unit checks, no subprocess, no output file.
  --emit        build from the live tree and write --output (must be under
                .eliot/). Use --overwrite to replace an existing file.
  --check       rebuild in memory and fail-closed unless every invariant in
                `check_inventory` holds (owner + disposition + active-reference
                status + impact edges for every row; 43+13 premise coverage;
                plan names the installed-route receipt).

Issue: https://github.com/UnknownAlienHuman/eliot-memory-os/issues/1860
Normative: I19.1, I19.2, I19.3, I19.13, I19.16, I0.8 (see docs bundle receipt
recorded in docs/migration/1860-migration-inventory.md).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

SCHEMA = "eliot.migration-inventory-1860.v1"
TOOL_VERSION = "0.1.0"
ISSUE = 1860
OUTPUT_ROOT = ".eliot"
DEFAULT_OUTPUT = ".eliot/migration-inventory-1860.json"

# Audit premise from the issue body: the conformance audit counted 43 of 158
# workspace packages reachable from no binary and 13 excluded packages. The
# tree has since grown (174 members at the base commit below); the ledger
# below dispositions every currently-unreachable package, which is a superset
# covering the audit-time 43, plus the full 13-wide excluded scope.
AUDIT_UNREACHABLE_PREMISE = 43
EXCLUDED_SCOPE_PREMISE = 13

# The first Product Proof plan must name a concrete installed-route receipt.
INSTALLED_ROUTE_RECEIPT = "ProductPulseReceipt"
PRODUCT_PROOF_PLAN = "docs/migration/1860-product-proof-plan.md"

ALLOWED_DISPOSITIONS = ("KEEP", "WRAP", "EXTRACT", "REWORK", "REPLACE", "RETIRE", "UNKNOWN")

IGNORED_SCAN_PARTS = {".eliot", "target"}
SKIP_SUFFIXES = (".exe", ".dll", ".pdb", ".lib", ".png", ".jpg", ".ico", ".pdf", ".zip")
MAX_SCAN_FILE_BYTES = 2 * 1024 * 1024
MAX_SCAN_TOTAL_BYTES = 256 * 1024 * 1024

STANDALONE_INVENTORY_REL = "workstreams/security/standalone-crate-dispositions.toml"

# ---------------------------------------------------------------------------
# Disposition rules (I19.3 verbs). Explicit per-path overrides win; area rules
# cover drift (any newly-unreachable package defaults to UNKNOWN, fail-closed).
# ---------------------------------------------------------------------------

# Four deleting aggregate crates (legacy-migration-facades, #1189) plus the two
# storage export crates whose manifests name #1716 as their disposition owner.
RETIRE_PATHS = {
    "crates/eliot-app": (
        "bins/eliotd migration coordination (#1860); extraction owner #18; retirement owner #1189",
        "Legacy migration/regression facade. RETIRE only after every unique production "
        "consumer migrates to the documented current owner; removal gated on #1189.",
    ),
    "crates/eliot-engine": (
        "bins/eliotd migration coordination (#1860); extraction owner #18; retirement owner #1189",
        "Legacy aggregate engine facade. RETIRE only after consumer migration; gated on #1189.",
    ),
    "crates/eliot-store": (
        "bins/eliotd migration coordination (#1860); extraction owner #19; retirement owner #1189",
        "Legacy aggregate store facade. RETIRE only after named Store operations own every reader; gated on #1189.",
    ),
    "crates/eliot-types": (
        "bins/eliotd migration coordination (#1860); extraction owner #18; retirement owner #1189",
        "Legacy aggregate contract facade. RETIRE only after additive host/route/capability contracts land; gated on #1189.",
    ),
    "crates/storage/eliot-backup": (
        "storage plane disposition owner #1716 (governed export path #1871; recoverability evidence #1873)",
        "Unreachable export/backup path, not a selectable production fallback. RETIRE only via the #1716 disposition with #1871/#1873 evidence.",
    ),
    "crates/storage/eliot-ecxf": (
        "storage plane disposition owner #1716 (governed export path #1871)",
        "Unreachable governed export path, not a selectable production fallback. RETIRE only via the #1716 disposition.",
    ),
}

# Instrument-plane support crates: KEEP as instrument/test-plane support, never
# as production runtime dependencies (owner #20 testd / registry #13).
INSTRUMENT_KEEP = (
    "instrument plane support owner #20 (testd) via capability registry #13",
    "Instrument-plane support crate, not a production runtime dependency. KEEP as typed "
    "Instrument execution/evidence support; no promotion to runtime authority implied.",
)

# Admitted capability cells that are not yet wired into a production binary:
# KEEP as admitted members; wiring is future work owned by the functional cell.
ADMITTED_KEEP = (
    "functional-cell owner per [package.metadata.eliot] lifecycle_owner; coordinated by bins/eliotd (#1860)",
    "Admitted capability cell awaiting production wiring. KEEP; no deletion. Reachability "
    "alone never implies retirement (I19.2 refresh rule).",
)

# Prototype cells pending implementation and proof: REWORK per #1811 semantics.
PROTOTYPE_REWORK = (
    "functional-cell owner per [package.metadata.eliot] lifecycle_owner; integration via cognitive-wave-integrator",
    "Prototype cell pending agent implementation and proof. REWORK before any admission-to-runtime claim.",
)

WRAP_PATHS = {
    "crates/agent/eliot-agent-acp": (
        "agent plane via bins/eliot-native-worker (#22); provider-neutral execution allocation #361",
        "Provider-neutral ACP v1 stdio compatibility adapter referenced by the native-worker "
        "adapter registry. WRAP behind the admitted native owner; never a parallel agent runtime.",
    ),
}

UNKNOWN_PATHS = {
    "crates/security/eliot-erasure": (
        "security.erasure (component owner TBD); coordinated by bins/eliotd (#1860)",
        "Governed privacy-erasure orchestration with no admitted production consumer. UNKNOWN: "
        "requires owner experiment before any KEEP/REPLACE/RETIRE decision; no retirement inferred.",
    ),
    "crates/security/eliot-influence": (
        "security.influence (component owner TBD); coordinated by bins/eliotd (#1860)",
        "Origin-bound influence/provenance policy owner with no admitted production consumer. "
        "UNKNOWN: requires owner experiment; no retirement inferred.",
    ),
    "crates/smart/eliot-context": (
        "smart.context (component owner TBD, ref #248); coordinated by bins/eliotd (#1860)",
        "Pre-wave context donor crate with no module owner record. UNKNOWN: requires owner "
        "experiment/disposition; no retirement inferred from reachability alone.",
    ),
    "crates/smart/eliot-cues": (
        "smart.cues (component owner TBD); coordinated by bins/eliotd (#1860)",
        "Cue projection/activation donor crate with no module owner record. UNKNOWN: requires "
        "owner experiment/disposition; no retirement inferred.",
    ),
    "crates/smart/eliot-dreamer-core": (
        "smart.dreamer.core (component owner TBD); coordinated by bins/eliotd (#1860)",
        "Dreamer core donor crate with no module owner record. UNKNOWN: requires owner "
        "experiment/disposition; no retirement inferred.",
    ),
    "crates/smart/eliot-memory-curation": (
        "smart.memory.curation (component owner TBD); coordinated by bins/eliotd (#1860)",
        "Memory-curation donor crate with no module owner record. UNKNOWN: requires owner "
        "experiment/disposition; no retirement inferred.",
    ),
}

KEEP_PATHS = {
    "crates/agent/eliot-swarm": (
        "A-07 swarm planning cell (lifecycle_owner A-07)",
        "Bounded swarm planning/coordination/review cell. KEEP; production wiring via the future agent path.",
    ),
    "crates/foundation/eliot-test-support": (
        "C0-10 test-support cell (lifecycle_owner C0-10)",
        "Test-support fixture plane. KEEP as proof fixtures; never production authority.",
    ),
    "crates/meta/eliot-improvement": (
        "meta plane owner #17 (doctor/repair family)",
        "Meta improvement crate. KEEP as diagnostic support; no runtime authority implied.",
    ),
    "crates/meta/eliot-learning-activation-assessment": (
        "meta.learning.activation_assessment (admitted via #967 T8-AL1)",
        "Admitted assessment cell. KEEP; no deletion.",
    ),
    "crates/meta/eliot-self-quality": (
        "meta.self_quality.diagnosis (admitted via #967 T8-AL1)",
        "Admitted self-quality cell. KEEP; no deletion.",
    ),
    "crates/storage/eliot-store-memory": (
        "storage plane owner #19 (non-runtime reference per #1715)",
        "Non-runtime implementation-support reference validating admitted named operations. "
        "KEEP as reference only; never a selectable production fallback.",
    ),
    "workspace/tools/eliot-campaign-executor": (
        "workspace tooling owner (developer tool, not production runtime)",
        "Developer campaign tool. KEEP outside the production runtime boundary.",
    ),
    "workspace/tools/eliot-runtime-compiler": (
        "workspace tooling owner (developer tool, not production runtime)",
        "Developer runtime-compiler tool. KEEP outside the production runtime boundary.",
    ),
}

# Repair impact graph (I19.5 order + issue work items). Nodes are migration
# facts, not support claims; edges are blocking/ordering relations.
IMPACT_NODES = (
    ("HB1-canonical-finish", "Hard-boundary repair: strict canonical finish only (I19.5 B)"),
    ("HB2-lossless-payload", "Hard-boundary repair: lossless generic payload authority (I19.5 B)"),
    ("HB3-one-writer", "Hard-boundary repair: canonical control records and one online writer composition (I19.5 B)"),
    ("LEGACY-RETIREMENT", "Legacy-crate retirement: eliot-app/engine/store/types aggregate facades (#1189)"),
    ("KERNEL-STORE-V1-DECODE-REMOVAL", "Kernel-Store v1 decode removal (sole compat decoder crates/kernel/eliot-kernel-service/src/store_exchange.rs; eliotd v1-compat projection)"),
    ("RELEASE-SURFACE", "Release surface: docs/release/WINDOWS_X64_RELEASE.md + scripts/build-eliot-windows-x64-release.ps1 gate"),
    ("WINDOWS-PRODUCT-PROOF", "Windows Product Proof: installed D0/D1 pulse with ProductPulseReceipt (#11)"),
    ("STORE-PATH", "Store dependency path: admitted named Store operations (owner #19)"),
    ("GOVERNOR-PATH", "Governor dependency path: eliotd semantic ownership (owner #18)"),
)
IMPACT_EDGES = (
    ("HB1-canonical-finish", "GOVERNOR-PATH", "finish semantics must land in eliotd before facade extraction"),
    ("HB2-lossless-payload", "GOVERNOR-PATH", "payload authority must precede agent-path cutover"),
    ("HB3-one-writer", "STORE-PATH", "one-writer composition must precede Store bridge migration"),
    ("GOVERNOR-PATH", "LEGACY-RETIREMENT", "facade consumers migrate to eliotd before RETIRE"),
    ("STORE-PATH", "LEGACY-RETIREMENT", "Store readers migrate to named operations before RETIRE"),
    ("STORE-PATH", "KERNEL-STORE-V1-DECODE-REMOVAL", "v1 compat decoders removable only after v2-only production"),
    ("GOVERNOR-PATH", "KERNEL-STORE-V1-DECODE-REMOVAL", "eliotd v1-compat projection removable only after v2-only resolution"),
    ("LEGACY-RETIREMENT", "RELEASE-SURFACE", "release gate must reject retired crates as inputs"),
    ("KERNEL-STORE-V1-DECODE-REMOVAL", "RELEASE-SURFACE", "release bundle must carry no legacy decode path"),
    ("RELEASE-SURFACE", "WINDOWS-PRODUCT-PROOF", "installed proof runs from the gated release bundle"),
    ("HB1-canonical-finish", "WINDOWS-PRODUCT-PROOF", "pulse asserts strict finish"),
    ("HB2-lossless-payload", "WINDOWS-PRODUCT-PROOF", "pulse asserts lossless payload round-trip"),
    ("HB3-one-writer", "WINDOWS-PRODUCT-PROOF", "pulse asserts single-writer composition"),
)


class InventoryError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _root(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise InventoryError("REPOSITORY_UNAVAILABLE", f"root unavailable: {path}") from exc
    if not (resolved / "Cargo.toml").is_file() or not (resolved / ".git").exists():
        raise InventoryError("NOT_A_REPOSITORY", f"expected Git/Cargo root: {resolved}")
    return resolved


def _run(root: Path, argv: tuple[str, ...]) -> bytes:
    allowed = {
        ("git", "ls-files"),
        ("git", "rev-parse"),
        ("git", "status"),
        ("cargo", "metadata"),
        ("cargo", "-Vv"),
        ("rustc", "-Vv"),
    }
    if tuple(argv[:2]) not in allowed:
        raise InventoryError("COMMAND_NOT_ALLOWED", f"not a fixed command: {list(argv)!r}")
    env = {k: v for k, v in os.environ.items() if k in {"PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "RUSTUP_HOME", "CARGO_HOME"} and v}
    env.update({"CARGO_TERM_COLOR": "never", "RUST_BACKTRACE": "0"})
    if "CARGO_TARGET_DIR" not in env and os.environ.get("CARGO_TARGET_DIR"):
        env["CARGO_TARGET_DIR"] = os.environ["CARGO_TARGET_DIR"]
    try:
        done = subprocess.run(list(argv), cwd=root, env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=900, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InventoryError("COMMAND_FAILED", f"could not run {argv[0]}: {exc}") from exc
    if len(done.stdout) + len(done.stderr) > 128 * 1024 * 1024:
        raise InventoryError("COMMAND_OUTPUT_TOO_LARGE", f"output too large: {list(argv)!r}")
    if done.returncode != 0:
        raise InventoryError("COMMAND_FAILED", f"exit {done.returncode}: {list(argv)!r}: {done.stderr.decode('utf-8', 'replace')[-2000:]}")
    return done.stdout


def _workspace_sets(root: Path) -> tuple[list[str], list[str]]:
    data = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
    return [str(x) for x in data.get("members", [])], [str(x) for x in data.get("exclude", [])]


def _discover_standalone(root: Path) -> dict[str, str]:
    members, exclude = _workspace_sets(root)
    member_set, exclude_set = set(members), set(exclude)
    found: dict[str, str] = {}
    for manifest in sorted(root.rglob("Cargo.toml")):
        rel = manifest.parent.relative_to(root).as_posix()
        if manifest == root / "Cargo.toml":
            continue
        if any(part in {"target", "testdata", "fixtures"} for part in manifest.parts):
            continue
        try:
            text = manifest.read_text(encoding="utf-8")
        except OSError:
            continue
        if "[workspace]" not in text:
            continue
        if rel in member_set or rel in exclude_set:
            continue
        try:
            parsed = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            continue
        if "package" not in parsed:
            continue
        found[rel] = str(parsed["package"]["name"])
    return found


def _load_standalone_dispositions(root: Path) -> dict[str, dict[str, str]]:
    path = root / STANDALONE_INVENTORY_REL
    if not path.is_file():
        raise InventoryError("STANDALONE_INVENTORY_MISSING", f"missing {STANDALONE_INVENTORY_REL}")
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    out: dict[str, dict[str, str]] = {}
    for row in data.get("crate", []):
        out[str(row.get("path"))] = {"disposition": str(row.get("disposition", "")), "owner": str(row.get("owner", ""))}
    return out


def _cargo_graph(root: Path) -> tuple[dict[str, dict], dict[str, set[str]]]:
    raw = _run(root, ("cargo", "metadata", "--locked", "--format-version", "1"))
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InventoryError("MALFORMED_METADATA", "cargo metadata is not JSON") from exc
    pkgs: dict[str, dict] = {}
    for pkg in data.get("packages", []):
        try:
            rel = Path(str(pkg["manifest_path"])).resolve().relative_to(root).as_posix()
        except (ValueError, OSError):
            continue
        pkgs[str(pkg["id"])] = {"name": str(pkg["name"]), "manifest_dir": str(Path(rel).parent.as_posix()), "targets": pkg.get("targets", [])}
    fwd: dict[str, set[str]] = {}
    for node in (data.get("resolve") or {}).get("nodes", []):
        if node.get("id") not in pkgs:
            continue
        outs: set[str] = set()
        for dep in node.get("deps", []):
            if dep.get("pkg") not in pkgs:
                continue
            kinds = {(k.get("kind") or "normal") for k in dep.get("dep_kinds", []) if isinstance(k, dict)} or {"normal"}
            if kinds & {"normal", "build"}:
                outs.add(dep["pkg"])
        fwd[node["id"]] = outs
    return pkgs, fwd


def _bins_unreachable(pkgs: dict[str, dict], fwd: dict[str, set[str]]) -> tuple[set[str], set[str]]:
    roots = {pid for pid, p in pkgs.items() if p["manifest_dir"].startswith("bins/")}
    seen = set(roots)
    stack = list(roots)
    while stack:
        cur = stack.pop()
        for nxt in fwd.get(cur, set()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return roots, {pid for pid in pkgs if pid not in seen}


def _crate_meta(root: Path, manifest_dir: str) -> dict[str, str]:
    out = {"lifecycle_owner": "", "functional_cell": "", "prototype": "", "source_status": "", "workspace_admission": ""}
    mod = root / manifest_dir / "module.toml"
    if mod.is_file():
        try:
            data = tomllib.loads(mod.read_text(encoding="utf-8"))
            out["lifecycle_owner"] = str(data.get("lifecycle_owner", "") or "")
            out["functional_cell"] = str(data.get("functional_cell", "") or "")
        except (OSError, tomllib.TOMLDecodeError):
            pass
    man = root / manifest_dir / "Cargo.toml"
    try:
        meta = tomllib.loads(man.read_text(encoding="utf-8")).get("package", {}).get("metadata", {}).get("eliot", {})
        if isinstance(meta, dict):
            out["lifecycle_owner"] = out["lifecycle_owner"] or str(meta.get("lifecycle_owner", "") or "")
            out["functional_cell"] = out["functional_cell"] or str(meta.get("functional_cell", "") or "")
            out["prototype"] = str(meta.get("prototype", "") or "")
            out["source_status"] = str(meta.get("source_status", "") or "")
            out["workspace_admission"] = str(meta.get("workspace_admission", "") or "")
    except (OSError, tomllib.TOMLDecodeError):
        pass
    return out


def _nearest_agents_issues(root: Path, manifest_dir: str) -> tuple[str | None, list[str]]:
    cur = root / manifest_dir
    while True:
        cand = cur / "AGENTS.md"
        if cand.is_file():
            try:
                text = cand.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return cand.relative_to(root).as_posix(), []
            return cand.relative_to(root).as_posix(), sorted({m for m in re.findall(r"#(\d{1,5})", text)}, key=int)[:8]
        if cur == root:
            return None, []
        cur = cur.parent


def resolve_owner(root: Path, manifest_dir: str) -> str:
    meta = _crate_meta(root, manifest_dir)
    if meta["lifecycle_owner"]:
        return f"{meta['lifecycle_owner']} (module/package owner record)"
    agents, issues = _nearest_agents_issues(root, manifest_dir)
    if issues:
        return f"issue #{issues[0]} via {agents} (nearest instruction owner)"
    area = manifest_dir.split("/")[0] + "/" + (manifest_dir.split("/")[1] if "/" in manifest_dir else "")
    return f"{area} area owner TBD; coordinated by bins/eliotd (#1860)"


def assign_disposition(manifest_dir: str, meta: dict[str, str]) -> tuple[str, str, str]:
    """Return (disposition, owner, rationale). Never invents retirement."""
    if manifest_dir in RETIRE_PATHS:
        owner, rationale = RETIRE_PATHS[manifest_dir]
        return "RETIRE", owner, rationale
    if manifest_dir in WRAP_PATHS:
        owner, rationale = WRAP_PATHS[manifest_dir]
        return "WRAP", owner, rationale
    if manifest_dir in UNKNOWN_PATHS:
        owner, rationale = UNKNOWN_PATHS[manifest_dir]
        return "UNKNOWN", owner, rationale
    if manifest_dir in KEEP_PATHS:
        owner, rationale = KEEP_PATHS[manifest_dir]
        return "KEEP", owner, rationale
    if manifest_dir.startswith("crates/instrument/"):
        return "KEEP", INSTRUMENT_KEEP[0], INSTRUMENT_KEEP[1]
    if meta.get("prototype") == "True":
        owner = meta.get("lifecycle_owner") or resolve_owner_fallback(manifest_dir)
        return "REWORK", owner, PROTOTYPE_REWORK[1]
    if meta.get("workspace_admission", "").startswith("admitted via") or meta.get("workspace_admission", "") == "ready_for_wave_integration":
        owner = meta.get("lifecycle_owner") or resolve_owner_fallback(manifest_dir)
        return "KEEP", f"{owner} ({meta['workspace_admission']})", ADMITTED_KEEP[1]
    return "UNKNOWN", resolve_owner_fallback(manifest_dir), (
        "No rule matched this unreachable package. UNKNOWN (fail-closed): requires owner "
        "experiment before any other disposition; no retirement inferred (I19.2)."
    )


def resolve_owner_fallback(manifest_dir: str) -> str:
    return f"{manifest_dir} owner TBD; coordinated by bins/eliotd (#1860)"


def _surface_class(path: str) -> str:
    if path.startswith("bins/"):
        return "binary"
    if path.startswith("integrations/agent-skills/") or "/skills/" in path:
        return "skill"
    if path.startswith("integrations/"):
        return "integration"
    if path.startswith("config/"):
        return "config"
    if path.startswith(".github/"):
        return "ci"
    if path.endswith((".surql", ".surql.retired", ".retired")) or path.startswith("migrations/"):
        return "schema"
    if path.startswith("docs/"):
        return "docs"
    if path.startswith("scripts/"):
        return "script"
    if path.startswith("tests/") or "/tests/" in path:
        return "test"
    if path.startswith("apps/"):
        return "app"
    if path.startswith("plugin/"):
        return "plugin"
    if path.startswith("workspace/"):
        return "tool"
    if path.startswith("workstreams/"):
        return "workstream"
    if path.endswith("prompt.md") or "/prompts/" in path or "/evals/" in path:
        return "prompt"
    if path.endswith(".rs"):
        return "source"
    if path.endswith("Cargo.toml") or path.endswith("Cargo.lock"):
        return "manifest"
    if "release" in path.lower() or "install" in path.lower() or path.endswith((".ps1", ".manifest")):
        return "install"
    if path.startswith("bins/eliot-wasm-host/wit/") or path.endswith(".wit"):
        return "generated-schema"
    return "other"


def read_scan_corpus(root: Path, tracked: list[str]) -> dict[str, str]:
    """Read every eligible tracked file once; shared by all package scans."""
    texts: dict[str, str] = {}
    total = 0
    for rel in tracked:
        if rel.startswith(".eliot/") or rel.startswith("target/") or "/target/" in rel:
            continue
        if rel.lower().endswith(SKIP_SUFFIXES):
            continue
        full = root / rel
        try:
            if full.stat().st_size > MAX_SCAN_FILE_BYTES:
                continue
        except OSError:
            continue
        if total > MAX_SCAN_TOTAL_BYTES:
            break
        try:
            body = full.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError, ValueError):
            continue
        total += len(body)
        texts[rel] = body
    return texts


def active_reference_scan(corpus: dict[str, str], manifest_dir: str, package_name: str) -> dict:
    hits: dict[str, list[str]] = {}
    own_prefix = manifest_dir + "/"
    # Word-boundary match on the package name (so `eliot-store` does not match
    # `eliot-store-api`), plus any literal mention of the package directory.
    # Over-reporting is fail-safe for migration; under-reporting would sever
    # hidden dependencies, so directory mentions always count.
    name_pat = re.compile(r"(?<![A-Za-z0-9_-])" + re.escape(package_name) + r"(?![A-Za-z0-9_-])")
    dir_needle = manifest_dir + "/"
    for rel, body in corpus.items():
        if rel.startswith(own_prefix):
            continue
        if dir_needle in body or name_pat.search(body) is not None:
            cls = _surface_class(rel)
            hits.setdefault(cls, []).append(rel)
    for cls in hits:
        hits[cls] = sorted(hits[cls])[:25]
    status = "ACTIVE_REFERENCE" if hits else "NO_REPO_REFERENCE_LIVE_UNKNOWN"
    return {
        "status": status,
        "hit_classes": sorted(hits),
        "hits_by_class": hits,
        "unscanned_surfaces": ["live store/data", "installed artifacts/manifests", "active integrations runtime state"],
        "note": "Any unscanned surface is UNKNOWN per #1860 work order; NO_REPO_REFERENCE never implies retirement.",
    }


def build_inventory(root: Path) -> dict:
    root = _root(root)
    head = _run(root, ("git", "rev-parse", "HEAD")).decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", head):
        raise InventoryError("INVALID_SOURCE_IDENTITY", "git HEAD is not a full identity")
    status = _run(root, ("git", "status", "--porcelain=v1", "--untracked-files=no"))
    tracked = [l for l in _run(root, ("git", "ls-files", "-z")).decode("utf-8", errors="replace").split("\0") if l]
    members, exclude = _workspace_sets(root)
    standalone = _discover_standalone(root)
    standalone_disp = _load_standalone_dispositions(root)
    pkgs, fwd = _cargo_graph(root)
    bins_roots, unreach = _bins_unreachable(pkgs, fwd)
    cargo_version = _run(root, ("cargo", "-Vv")).decode("utf-8", errors="replace").strip()
    rustc_version = _run(root, ("rustc", "-Vv")).decode("utf-8", errors="replace").strip()
    lock = root / "Cargo.lock"
    lock_sha = _sha256(lock.read_bytes()) if lock.is_file() else None

    dir_of = {pid: p["manifest_dir"] for pid, p in pkgs.items()}
    name_of = {pid: p["name"] for pid, p in pkgs.items()}
    corpus = read_scan_corpus(root, tracked)

    packages: list[dict] = []
    for pid in sorted(pkgs, key=lambda i: dir_of[i]):
        manifest_dir = dir_of[pid]
        meta = _crate_meta(root, manifest_dir)
        reachable = pid not in unreach
        if reachable:
            disp, owner = "REACHABLE_NO_DISPOSITION", resolve_owner(root, manifest_dir)
            rationale = "Reachable from a bins/ binary; no migration disposition required."
        else:
            disp, owner, rationale = assign_disposition(manifest_dir, meta)
        scan = active_reference_scan(corpus, manifest_dir, name_of[pid])
        packages.append({
            "path": manifest_dir,
            "package": name_of[pid],
            "bins_reachable": reachable,
            "owner": owner,
            "disposition": disp,
            "rationale": rationale,
            "active_reference": scan,
            "crate_meta": meta,
        })

    excluded_rows: list[dict] = []
    for rel in sorted(standalone):
        row = standalone_disp.get(rel)
        if row is None:
            raise InventoryError("UNDISPOSITIONED_STANDALONE", f"standalone package without #1811 row: {rel}")
        if row["disposition"] not in ALLOWED_DISPOSITIONS:
            raise InventoryError("BAD_DISPOSITION", f"{rel}: {row['disposition']!r}")
        if not row["owner"]:
            raise InventoryError("OWNERLESS_STANDALONE", f"standalone package without owner: {rel}")
        excluded_rows.append({
            "path": rel,
            "package": standalone[rel],
            "owner": row["owner"],
            "disposition": row["disposition"],
            "rationale": f"Verbatim #1811 standalone disposition ({STANDALONE_INVENTORY_REL}); confers no workspace/runtime admission.",
            "active_reference": active_reference_scan(corpus, rel, standalone[rel]),
        })

    node_names = [n for n, _ in IMPACT_NODES]
    for a, b, _ in IMPACT_EDGES:
        if a not in node_names or b not in node_names:
            raise InventoryError("IMPACT_EDGE_DANGLING", f"edge {a}->{b} names an unknown node")

    unreach_rows = [p for p in packages if not p["bins_reachable"]]
    undispositioned = [p["path"] for p in unreach_rows if p["disposition"] not in ALLOWED_DISPOSITIONS]
    if undispositioned:
        raise InventoryError("UNDISPOSITIONED_UNREACHABLE", f"unreachable rows without disposition: {undispositioned[:10]}")
    ownerless = [p["path"] for p in unreach_rows + excluded_rows if not p["owner"]]
    if ownerless:
        raise InventoryError("OWNERLESS_ROW", f"rows without owner: {ownerless[:10]}")

    inv = {
        "schema": SCHEMA,
        "tool_version": TOOL_VERSION,
        "issue": ISSUE,
        "coordinator": "bins/eliotd migration coordination",
        "source_identity": {"git_head": head.lower(), "tracked_tree_clean": not bool(status),
                            "cargo_lock_sha256": lock_sha, "cargo_version": cargo_version, "rustc_version": rustc_version},
        "denominator": {
            "workspace_members": len(members),
            "workspace_exclude": exclude,
            "bins_roots": len(bins_roots),
            "bins_reachable": sum(1 for p in packages if p["bins_reachable"]),
            "bins_unreachable": len(unreach_rows),
            "standalone_packages": len(standalone),
            "audit_unreachable_premise": AUDIT_UNREACHABLE_PREMISE,
            "excluded_scope_premise": EXCLUDED_SCOPE_PREMISE,
            "premise_coverage": f"ledger dispositions {len(unreach_rows)} unreachable (superset of audit 43) and {len(excluded_rows)} standalone rows covering the 13-wide excluded scope with the #1811 reconciliation (11 packages + 3 non-production roots)",
        },
        "packages": packages,
        "excluded_scope": excluded_rows,
        "surfaces": _surface_inventory(tracked),
        "impact_graph": {
            "nodes": [{"id": n, "label": label} for n, label in IMPACT_NODES],
            "edges": [{"from": a, "to": b, "relation": r} for a, b, r in IMPACT_EDGES],
        },
        "product_proof_plan": {"path": PRODUCT_PROOF_PLAN, "installed_route_receipt": INSTALLED_ROUTE_RECEIPT},
        "proof_ceiling": "MIGRATION_INVENTORY_EVIDENCE_ONLY",
    }
    inv["aggregate_sha256"] = _sha256(_canonical(inv))
    return inv


def _surface_inventory(tracked: list[str]) -> list[dict]:
    by_class: dict[str, list[str]] = {}
    for rel in tracked:
        if rel.startswith(".eliot/") or "/target/" in rel or rel.startswith("target/"):
            continue
        by_class.setdefault(_surface_class(rel), []).append(rel)
    rows = []
    for cls in sorted(by_class):
        paths = sorted(by_class[cls])
        rows.append({"class": cls, "count": len(paths), "paths": paths[:40], "truncated": len(paths) > 40,
                     "lookup": "owner/disposition/impact via packages[] and excluded_scope[] rows matching the surface path or owning binary"})
    return rows


def check_inventory(inv: dict, root: Path) -> list[str]:
    failures: list[str] = []
    if inv.get("schema") != SCHEMA:
        failures.append(f"schema mismatch: {inv.get('schema')!r}")
    for row in inv.get("packages", []):
        if not row.get("bins_reachable", True):
            if row.get("disposition") not in ALLOWED_DISPOSITIONS:
                failures.append(f"{row.get('path')}: missing disposition")
            if not row.get("owner"):
                failures.append(f"{row.get('path')}: missing owner")
            if not row.get("active_reference", {}).get("status"):
                failures.append(f"{row.get('path')}: missing active-reference status")
    for row in inv.get("excluded_scope", []):
        if row.get("disposition") not in ALLOWED_DISPOSITIONS:
            failures.append(f"excluded {row.get('path')}: missing disposition")
        if not row.get("owner"):
            failures.append(f"excluded {row.get('path')}: missing owner")
        if not row.get("active_reference", {}).get("status"):
            failures.append(f"excluded {row.get('path')}: missing active-reference status")
    unreach = sum(1 for r in inv.get("packages", []) if not r.get("bins_reachable", True))
    if unreach < AUDIT_UNREACHABLE_PREMISE:
        failures.append(f"unreachable rows {unreach} below audit premise {AUDIT_UNREACHABLE_PREMISE}")
    if len(inv.get("excluded_scope", [])) + 2 < EXCLUDED_SCOPE_PREMISE:
        failures.append("excluded scope below 13-wide premise (11 packages + #1811 reconciliation)")
    nodes = {n["id"] for n in inv.get("impact_graph", {}).get("nodes", [])}
    for e in inv.get("impact_graph", {}).get("edges", []):
        if e.get("from") not in nodes or e.get("to") not in nodes:
            failures.append(f"dangling impact edge {e}")
    plan = root / str(inv.get("product_proof_plan", {}).get("path", ""))
    receipt = str(inv.get("product_proof_plan", {}).get("installed_route_receipt", ""))
    if not plan.is_file():
        failures.append(f"product proof plan missing: {plan}")
    elif receipt not in plan.read_text(encoding="utf-8", errors="replace"):
        failures.append(f"product proof plan does not name installed-route receipt {receipt!r}")
    return failures


def _safe_output(root: Path, output: Path, overwrite: bool) -> Path:
    cand = output if output.is_absolute() else root / output
    parent = cand.parent.resolve()
    try:
        parent.relative_to(root)
    except ValueError as exc:
        raise InventoryError("UNSAFE_OUTPUT", "output must be below the repository root") from exc
    if parent.relative_to(root).parts[:1] != (OUTPUT_ROOT,):
        raise InventoryError("UNSAFE_OUTPUT", f"output must be below ./{OUTPUT_ROOT}/")
    if cand.exists() and not overwrite:
        raise InventoryError("OUTPUT_EXISTS", f"refusing to overwrite {cand}")
    return cand


def run_self_tests() -> int:
    # disposition rule coverage over the fixed current denominator shape
    meta_proto = {"lifecycle_owner": "smart.x.y", "functional_cell": "", "prototype": "True", "source_status": "", "workspace_admission": "pending_agent_implementation_and_proof"}
    d, o, r = assign_disposition("crates/smart/eliot-x-new", meta_proto)
    assert d == "REWORK" and o and r, "prototype rule"
    meta_adm = {"lifecycle_owner": "smart.x.y", "functional_cell": "", "prototype": "False", "source_status": "IMPLEMENTED", "workspace_admission": "admitted via #999 root workspace membership"}
    d, o, r = assign_disposition("crates/smart/eliot-x-new2", meta_adm)
    assert d == "KEEP" and o and r, "admitted rule"
    d, o, r = assign_disposition("crates/eliot-app", {})
    assert d == "RETIRE" and o and r, "facade rule"
    d, o, r = assign_disposition("crates/instrument/eliot-x-new", {})
    assert d == "KEEP" and o and r, "instrument rule"
    d, o, r = assign_disposition("crates/totally-new/eliot-x", {})
    assert d == "UNKNOWN" and o and "fail-closed" in r, "drift fallback rule"
    for path in list(RETIRE_PATHS) + list(WRAP_PATHS) + list(UNKNOWN_PATHS) + list(KEEP_PATHS):
        d, o, r = assign_disposition(path, {})
        assert d in ALLOWED_DISPOSITIONS and o and r, f"explicit rule {path}"
    # impact graph closure
    nodes = {n for n, _ in IMPACT_NODES}
    assert len(nodes) == len(IMPACT_NODES), "impact node ids unique"
    for a, b, rel in IMPACT_EDGES:
        assert a in nodes and b in nodes and rel, f"edge {a}->{b}"
    assert any("WINDOWS-PRODUCT-PROOF" in e for e in IMPACT_EDGES), "proof node linked"
    # canonical hashing determinism
    assert _sha256(_canonical({"b": 1, "a": [2, 1]})) == _sha256(_canonical({"a": [2, 1], "b": 1}))
    # surface classifier covers the issue's required families
    for probe, want in [("bins/eliotd/src/main.rs", "binary"), ("migrations/0001_bootstrap.surql.retired", "schema"),
                        ("config/architecture-boundaries.toml", "config"), (".github/workflows/x.yml", "ci"),
                        ("integrations/agent-skills/a/SKILL.md", "skill"), ("integrations/opencode/x.js", "integration"),
                        ("docs/release/WINDOWS_X64_RELEASE.md", "docs"), ("scripts/build-eliot-windows-x64-release.ps1", "script")]:
        assert _surface_class(probe) == want, f"class {probe}"
    print("MIGRATION_INVENTORY_1860_SELF_TEST: PASS")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--emit", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--output", type=Path, default=Path(DEFAULT_OUTPUT))
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument("--root", type=Path, default=Path("."))
    args = ap.parse_args(argv)
    if args.self_test:
        return run_self_tests()
    try:
        root = _root(args.root)
        inv = build_inventory(root)
    except InventoryError as exc:
        print(json.dumps({"status": "error", "code": exc.code, "detail": exc.detail}, sort_keys=True), file=sys.stderr)
        return 2
    if args.emit:
        try:
            out = _safe_output(root, args.output, args.overwrite)
        except InventoryError as exc:
            print(json.dumps({"status": "error", "code": exc.code, "detail": exc.detail}, sort_keys=True), file=sys.stderr)
            return 2
        out.parent.mkdir(parents=True, exist_ok=True)
        if args.overwrite and out.exists():
            out.unlink()
        with out.open("xb") as fh:
            fh.write(_canonical(inv))
            fh.write(b"\n")
        print(json.dumps({"status": "ok", "output": str(out), "aggregate_sha256": inv["aggregate_sha256"],
                          "unreachable": inv["denominator"]["bins_unreachable"],
                          "standalone": inv["denominator"]["standalone_packages"]}, sort_keys=True))
        return 0
    if args.check:
        failures = check_inventory(inv, root)
        if failures:
            print(f"MIGRATION_INVENTORY_1860: FAIL issues={len(failures)}")
            for failure in failures:
                print(f"  - {failure}")
            return 1
        print(f"MIGRATION_INVENTORY_1860: PASS unreachable={inv['denominator']['bins_unreachable']} "
              f"standalone={inv['denominator']['standalone_packages']} aggregate={inv['aggregate_sha256'][:16]}")
        return 0
    ap.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
