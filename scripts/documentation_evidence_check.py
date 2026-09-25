#!/usr/bin/env python3
"""Frozen outer `DocumentationEvidenceCheck` for docs evidence packages (I18.31 W4).

The candidate documentation generator cannot certify itself solely by emitting
a green report. This check runs from a frozen outer script/generation over the
exact packaged bytes: package re-extraction plus digest comparison is
mandatory, a green report without re-extraction evidence does not count, and
any post-package edit creates a new revision (the report binds the exact
package SHA-256, so edited bytes yield a different report identity).

Frozen-generation rule: the script bytes are pinned by
``scripts/documentation_evidence_check.freeze.json``. ``--self-test`` fails
unless the running script matches the pin, so any edit to this file must
mint a new frozen generation explicitly. Never weaken a rule and its corpus
case in the same change.

Package layout (ZIP; ``manifest.json`` at the archive root)::

    manifest.json   {"revision": str, "files": {relpath: sha256},
                     "counts": {"files": int}, "versioned_copy": {...}?,
                     "evidence_refs": [relpath]?}
    ledger.json     {"markdown": relpath, "markdown_sha256": str}? (optional)
    dispositions.json {"codes": {code: disposition}}? (optional)
    payload/...     payload files
    receipts/...    receipt payloads (optional)

Usage::

    python scripts/documentation_evidence_check.py verify --package P.zip [--workspace W]
    python scripts/documentation_evidence_check.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

GENERATION = "i18-31-docs-outer-v1"
FREEZE_FILE = Path(__file__).with_name("documentation_evidence_check.freeze.json")

# Fields owned by ReceiptEnvelope; a receipt payload must never redefine them.
ENVELOPE_OWNED_FIELDS = ("identity", "authority", "fence", "provenance")

# Stable AgentResponseDisposition values an additive reason code round-trips under.
STABLE_DISPOSITIONS = ("accept", "reject", "defer", "escalate")

_TEMPLATE_RE = re.compile(r"\{\{[A-Z][A-Z0-9_]*\}\}")
_CONTRACT_SECTION_RE = re.compile(r"^## Contract:\s*(\S+)\s*$")


@dataclass(frozen=True)
class Finding:
    """One typed check failure."""

    code: str
    location: str
    detail: str


@dataclass
class EvidenceReport:
    """Outcome of one `DocumentationEvidenceCheck` run."""

    package: str
    package_sha256: str
    generation: str = GENERATION
    reextracted: bool = False
    findings: list[Finding] = field(default_factory=list)

    @property
    def accepted(self) -> bool:
        """Accept only a finding-free run with re-extraction evidence.

        A green report without re-extraction evidence does not count.
        """
        return self.reextracted and not self.findings


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class DocumentationEvidenceCheck:
    """Frozen outer check over exact packaged docs bytes."""

    def __init__(self, package: Path, workspace: Path | None = None) -> None:
        self.package = package
        self.workspace = workspace

    def verify(self) -> EvidenceReport:
        """Run every rule and return the evidence report (never raises)."""
        report = EvidenceReport(
            package=str(self.package),
            package_sha256=_sha256_file(self.package) if self.package.is_file() else "unhashed",
        )
        if not self.package.exists():
            report.findings.append(Finding("DEC-00", str(self.package), "package is missing"))
            return report
        if not zipfile.is_zipfile(self.package):
            # Staging directories are working drafts, not frozen packages:
            # report findings honestly but never accept without re-extraction.
            report.findings.append(
                Finding("DEC-01", str(self.package), "package is not a re-extractable ZIP")
            )
            return report
        workdir = Path(tempfile.mkdtemp(prefix="eliot-docs-evidence-"))
        try:
            with zipfile.ZipFile(self.package) as archive:
                archive.extractall(workdir)
            report.reextracted = True
            self._verify_manifest(workdir, report)
            if self.workspace is not None:
                self._verify_workspace_divergence(workdir, report)
            self._verify_ledger(workdir, report)
            self._verify_templates(workdir, report)
            self._verify_counts(workdir, report)
            self._verify_current_verified(workdir, report)
            self._verify_contract_sections(workdir, report)
            self._verify_receipts(workdir, report)
            self._verify_dispositions(workdir, report)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        return report

    def _load_json(self, workdir: Path, name: str, report: EvidenceReport) -> dict | None:
        path = workdir / name
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            report.findings.append(Finding("DEC-02", name, f"unreadable JSON: {error}"))
            return None
        if not isinstance(data, dict):
            report.findings.append(Finding("DEC-02", name, "top-level JSON value is not an object"))
            return None
        return data

    def _verify_manifest(self, workdir: Path, report: EvidenceReport) -> None:
        manifest = self._load_json(workdir, "manifest.json", report)
        if manifest is None:
            report.findings.append(Finding("DEC-02", "manifest.json", "manifest is missing"))
            return
        files = manifest.get("files", {})
        if not isinstance(files, dict):
            report.findings.append(Finding("DEC-02", "manifest.json", "'files' is not an object"))
            return
        for relpath, expected in files.items():
            target = workdir / relpath
            if not target.is_file():
                report.findings.append(Finding("DEC-05", relpath, "manifested artifact is missing"))
                continue
            if _sha256_file(target) != expected:
                report.findings.append(
                    Finding("DEC-03", relpath, "bytes differ from the manifest digest")
                )
        versioned = manifest.get("versioned_copy")
        if isinstance(versioned, dict):
            relpath = str(versioned.get("path", ""))
            expected = str(versioned.get("sha256", ""))
            target = workdir / relpath if relpath else None
            if target is None or not target.is_file() or _sha256_file(target) != expected:
                report.findings.append(
                    Finding("DEC-07", "manifest.json", "manifest points to different bytes")
                )

    def _verify_workspace_divergence(self, workdir: Path, report: EvidenceReport) -> None:
        assert self.workspace is not None
        manifest = self._load_json(workdir, "manifest.json", report)
        if manifest is None:
            return
        files = manifest.get("files", {})
        if not isinstance(files, dict):
            return
        for relpath in files:
            packaged = workdir / relpath
            live = self.workspace / relpath
            if not packaged.is_file() or not live.is_file():
                continue
            if _sha256_file(packaged) != _sha256_file(live):
                report.findings.append(
                    Finding("DEC-06", relpath, "ZIP payload differs from workspace file")
                )

    def _verify_ledger(self, workdir: Path, report: EvidenceReport) -> None:
        ledger = self._load_json(workdir, "ledger.json", report)
        if ledger is None:
            return
        relpath = str(ledger.get("markdown", ""))
        expected = str(ledger.get("markdown_sha256", ""))
        target = workdir / relpath if relpath else None
        if target is None or not target.is_file():
            report.findings.append(Finding("DEC-04", "ledger.json", "ledger markdown is missing"))
        elif _sha256_file(target) != expected:
            report.findings.append(
                Finding("DEC-04", "ledger.json", "Markdown digest changed but ledger is stale")
            )

    def _payload_texts(self, workdir: Path) -> list[tuple[str, str]]:
        texts: list[tuple[str, str]] = []
        for path in sorted(workdir.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in {".md", ".txt", ".toml"}:
                continue
            try:
                texts.append((path.relative_to(workdir).as_posix(), path.read_text("utf-8")))
            except (OSError, UnicodeDecodeError):
                continue
        return texts

    def _verify_templates(self, workdir: Path, report: EvidenceReport) -> None:
        for relpath, text in self._payload_texts(workdir):
            for token in sorted(set(_TEMPLATE_RE.findall(text))):
                report.findings.append(
                    Finding("DEC-08", f"{relpath}:{token}", "unresolved template variable")
                )

    def _verify_counts(self, workdir: Path, report: EvidenceReport) -> None:
        manifest = self._load_json(workdir, "manifest.json", report)
        if manifest is None:
            return
        counts = manifest.get("counts", {})
        if not isinstance(counts, dict) or "files" not in counts:
            return
        try:
            expected = int(counts["files"])
        except (TypeError, ValueError):
            report.findings.append(Finding("DEC-09", "manifest.json", "count is not an integer"))
            return
        observed = sum(1 for _ in self._payload_files(workdir, manifest))
        if observed != expected:
            report.findings.append(
                Finding(
                    "DEC-09",
                    "manifest.json",
                    f"count {expected} generated from a different revision ({observed} now)",
                )
            )

    def _payload_files(self, workdir: Path, manifest: dict) -> list[Path]:
        files = manifest.get("files", {})
        if not isinstance(files, dict):
            return []
        return [workdir / relpath for relpath in files if (workdir / relpath).is_file()]

    def _verify_current_verified(self, workdir: Path, report: EvidenceReport) -> None:
        manifest = self._load_json(workdir, "manifest.json", report)
        refs: object = manifest.get("evidence_refs", []) if manifest else []
        resolved = {
            ref
            for ref in (refs if isinstance(refs, list) else [])
            if isinstance(ref, str) and (workdir / ref).is_file()
        }
        for relpath, text in self._payload_texts(workdir):
            if "CURRENT_VERIFIED" in text and not resolved:
                report.findings.append(
                    Finding(
                        "DEC-10",
                        relpath,
                        "CURRENT_VERIFIED claim with no executable evidence",
                    )
                )

    def _verify_contract_sections(self, workdir: Path, report: EvidenceReport) -> None:
        seen: dict[str, tuple[str, str]] = {}
        for relpath, text in self._payload_texts(workdir):
            sections: dict[str, list[str]] = {}
            current: str | None = None
            for line in text.splitlines():
                match = _CONTRACT_SECTION_RE.match(line)
                if match:
                    current = match.group(1)
                    sections.setdefault(current, [])
                elif current is not None:
                    sections[current].append(line)
            for name, body in sections.items():
                digest = _sha256_bytes("\n".join(body).encode("utf-8"))
                if name in seen and seen[name][1] != digest:
                    report.findings.append(
                        Finding(
                            "DEC-11",
                            f"{relpath}#{name}",
                            f"duplicate contract section diverges from {seen[name][0]}",
                        )
                    )
                else:
                    seen.setdefault(name, (f"{relpath}#{name}", digest))

    def _verify_receipts(self, workdir: Path, report: EvidenceReport) -> None:
        receipts_dir = workdir / "receipts"
        receipt_paths = sorted(receipts_dir.rglob("*.json")) if receipts_dir.is_dir() else []
        for path in receipt_paths:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            for owned in ENVELOPE_OWNED_FIELDS:
                if owned in data:
                    report.findings.append(
                        Finding(
                            "DEC-12",
                            path.relative_to(workdir).as_posix(),
                            f"receipt redefines envelope-owned field '{owned}'",
                        )
                    )

    def _verify_dispositions(self, workdir: Path, report: EvidenceReport) -> None:
        registry = self._load_json(workdir, "dispositions.json", report)
        if registry is None:
            return
        codes = registry.get("codes", {})
        if not isinstance(codes, dict):
            report.findings.append(
                Finding("DEC-13", "dispositions.json", "'codes' is not an object")
            )
            return
        for code, disposition in codes.items():
            if disposition not in STABLE_DISPOSITIONS:
                report.findings.append(
                    Finding(
                        "DEC-13",
                        f"dispositions.json:{code}",
                        f"reason code does not round-trip under a stable disposition ({disposition!r})",
                    )
                )


def _cmd_verify(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace) if args.workspace else None
    check = DocumentationEvidenceCheck(Path(args.package), workspace)
    report = check.verify()
    print(f"DOC_EVIDENCE: package={report.package} sha256={report.package_sha256}")
    print(f"DOC_EVIDENCE: generation={report.generation} reextracted={report.reextracted}")
    for finding in report.findings:
        print(f"DOC_EVIDENCE_FINDING: {finding.code} {finding.location} :: {finding.detail}")
    print(f"DOC_EVIDENCE: {'ACCEPT' if report.accepted else 'REJECT'}")
    if args.report_out:
        Path(args.report_out).write_text(
            json.dumps(
                {
                    "package": report.package,
                    "package_sha256": report.package_sha256,
                    "generation": report.generation,
                    "reextracted": report.reextracted,
                    "accepted": report.accepted,
                    "findings": [vars(finding) for finding in report.findings],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    return 0 if report.accepted else 1


def _write_package(root: Path, files: dict[str, str | bytes], manifest_extra: dict | None = None) -> Path:
    manifest_extra = manifest_extra or {}
    payloads: dict[str, str] = {}
    for relpath, content in files.items():
        if relpath in {"manifest.json", "ledger.json", "dispositions.json"}:
            continue
        data = content.encode("utf-8") if isinstance(content, str) else content
        (root / relpath).parent.mkdir(parents=True, exist_ok=True)
        (root / relpath).write_bytes(data)
        payloads[relpath] = _sha256_bytes(data)
    manifest = {"revision": "r1", "files": payloads, "counts": {"files": len(payloads)}}
    manifest.update(manifest_extra)
    (root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    for name in ("ledger.json", "dispositions.json"):
        if name in files:
            content = files[name]
            (root / name).write_text(content if isinstance(content, str) else content.decode(), encoding="utf-8")
    package = root.parent / f"{root.name}.zip"
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(root).as_posix())
    return package


def _repack(staged: Path, out: Path) -> Path:
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(staged.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(staged).as_posix())
    return out


def _script_bytes_for_pin() -> bytes:
    # Newline-insensitive so git autocrlf checkouts keep the frozen pin
    # valid; any content change still breaks it.
    return Path(__file__).read_bytes().replace(b"\r\n", b"\n")


def _self_test_freeze_pin() -> None:
    if not FREEZE_FILE.is_file():
        raise AssertionError(f"freeze pin is missing: {FREEZE_FILE}")
    pin = json.loads(FREEZE_FILE.read_text(encoding="utf-8"))
    if pin.get("generation") != GENERATION:
        raise AssertionError("freeze pin names a different generation")
    if pin.get("script_sha256") != _sha256_bytes(_script_bytes_for_pin()):
        raise AssertionError("running script bytes differ from the frozen pin")


def _expect(root: Path, name: str, package: Path, codes: set[str], accepted: bool) -> None:
    report = DocumentationEvidenceCheck(package).verify()
    observed = {finding.code for finding in report.findings}
    if observed != codes or report.accepted != accepted:
        raise AssertionError(
            f"{name}: findings={sorted(observed)} accepted={report.accepted} "
            f"(want {sorted(codes)}/{accepted}): "
            + "; ".join(f"{f.code}@{f.location}" for f in report.findings)
        )


def _cmd_self_test() -> int:
    _self_test_freeze_pin()
    base = Path(tempfile.mkdtemp(prefix="eliot-docs-evidence-selftest-"))
    try:
        clean = base / "clean"
        clean.mkdir()
        clean_markdown = b"# Audit\nStatus: DRAFT\n"
        package = _write_package(
            clean,
            {
                "payload/audit.md": clean_markdown.decode("utf-8"),
                "ledger.json": json.dumps(
                    {
                        "markdown": "payload/audit.md",
                        "markdown_sha256": _sha256_bytes(clean_markdown),
                    }
                ),
                "dispositions.json": json.dumps({"codes": {"timeout": "defer"}}),
            },
            {"evidence_refs": []},
        )
        _expect(base, "clean", package, set(), True)

        # DEC-03 post-manifest mutation: rewrite bytes after packaging.
        mutated = base / "mutated"
        mutated.mkdir()
        package = _write_package(mutated, {"payload/audit.md": "# Audit\n"})
        mutated_stage = base / "mutated-stage"
        mutated_stage.mkdir()
        with zipfile.ZipFile(package) as archive:
            archive.extractall(mutated_stage)
        (mutated_stage / "payload" / "audit.md").write_text("# Audit\nmutated\n", encoding="utf-8")
        package = _repack(mutated_stage, base / "mutated-repacked.zip")
        _expect(base, "post-manifest-mutation", package, {"DEC-03"}, False)

        # DEC-04 stale ledger.
        stale = base / "stale"
        stale.mkdir()
        package = _write_package(
            stale,
            {
                "payload/audit.md": "# Audit v2\n",
                "ledger.json": json.dumps({"markdown": "payload/audit.md", "markdown_sha256": "0" * 64}),
            },
        )
        _expect(base, "stale-ledger", package, {"DEC-04"}, False)

        # DEC-08 unresolved template variable.
        templated = base / "templated"
        templated.mkdir()
        package = _write_package(templated, {"payload/audit.md": "Verdict: {{PENDING}}\n"})
        _expect(base, "template", package, {"DEC-08"}, False)

        # DEC-05 missing artifact: manifest names a file the ZIP lacks.
        missing = base / "missing"
        missing.mkdir()
        (missing / "payload").mkdir()
        package = _write_package(missing, {"payload/audit.md": "# Audit\n"})
        staged = base / "missing-stage"
        staged.mkdir()
        with zipfile.ZipFile(package) as archive:
            archive.extractall(staged)
        manifest = json.loads((staged / "manifest.json").read_text(encoding="utf-8"))
        manifest["files"]["payload/gone.md"] = "1" * 64
        (staged / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        repacked = _repack(staged, base / "missing-repacked.zip")
        _expect(base, "missing-artifact", repacked, {"DEC-05"}, False)

        # DEC-07 version-mispointed manifest.
        mispointed = base / "mispointed"
        mispointed.mkdir()
        package = _write_package(
            mispointed,
            {"payload/audit.md": "# Audit\n"},
            {"versioned_copy": {"path": "payload/audit.md", "sha256": "2" * 64}},
        )
        _expect(base, "mispointed", package, {"DEC-07"}, False)

        # DEC-06 ZIP/workspace divergence.
        diverged = base / "diverged"
        diverged.mkdir()
        package = _write_package(diverged, {"payload/audit.md": "# Audit zip\n"})
        workspace = base / "diverged-ws"
        (workspace / "payload").mkdir(parents=True)
        (workspace / "payload" / "audit.md").write_text("# Audit live\n", encoding="utf-8")
        report = DocumentationEvidenceCheck(package, workspace).verify()
        if {f.code for f in report.findings} != {"DEC-06"} or report.accepted:
            raise AssertionError("zip-workspace-divergence case failed")

        # DEC-09 wrong-revision counts.
        counted = base / "counted"
        counted.mkdir()
        package = _write_package(
            counted, {"payload/audit.md": "# Audit\n"}, {"counts": {"files": 7}}
        )
        _expect(base, "counts", package, {"DEC-09"}, False)

        # DEC-10 unevidenced CURRENT_VERIFIED.
        unverified = base / "unverified"
        unverified.mkdir()
        package = _write_package(
            unverified, {"payload/audit.md": "Status: CURRENT_VERIFIED\n"}, {"evidence_refs": []}
        )
        _expect(base, "current-verified", package, {"DEC-10"}, False)

        # DEC-11 duplicate contract sections with divergent digests.
        duped = base / "duped"
        duped.mkdir()
        package = _write_package(
            duped,
            {
                "payload/one.md": "## Contract: Widget\nshape: circle\n",
                "payload/two.md": "## Contract: Widget\nshape: square\n",
            },
        )
        _expect(base, "duplicate-sections", package, {"DEC-11"}, False)

        # DEC-12 receipt-identity redefinition.
        receipts = base / "receipts"
        receipts.mkdir()
        package = _write_package(
            receipts,
            {
                "payload/audit.md": "# Audit\n",
                "receipts/r1.json": json.dumps({"identity": "forged", "note": "x"}),
            },
        )
        _expect(base, "receipt-identity", package, {"DEC-12"}, False)

        # DEC-13 non-round-tripping reason code.
        reasons = base / "reasons"
        reasons.mkdir()
        package = _write_package(
            reasons,
            {
                "payload/audit.md": "# Audit\n",
                "dispositions.json": json.dumps({"codes": {"mystery": "limbo"}}),
            },
        )
        _expect(base, "reason-code", package, {"DEC-13"}, False)

        # A2: a finding-free staging directory still does not count.
        staging = base / "staging"
        (staging / "payload").mkdir(parents=True)
        (staging / "payload" / "audit.md").write_text("# Audit\n", encoding="utf-8")
        (staging / "manifest.json").write_text(
            json.dumps(
                {
                    "revision": "r1",
                    "files": {"payload/audit.md": _sha256_file(staging / "payload" / "audit.md")},
                    "counts": {"files": 1},
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        report = DocumentationEvidenceCheck(staging).verify()
        if report.accepted or {f.code for f in report.findings} != {"DEC-01"}:
            raise AssertionError("staging-without-reextraction case failed")
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print("DOC_EVIDENCE_SELF_TEST: PASS 13/13")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Frozen outer DocumentationEvidenceCheck (I18.31 W4).")
    parser.add_argument("--self-test", action="store_true", help="run the frozen corpus self-test")
    sub = parser.add_subparsers(dest="command")
    verify = sub.add_parser("verify", help="verify one evidence package")
    verify.add_argument("--package", required=True, help="frozen evidence ZIP package")
    verify.add_argument("--workspace", help="live workspace root for divergence comparison")
    verify.add_argument("--report-out", help="write the JSON report to this path")
    args = parser.parse_args(argv)
    if args.self_test:
        return _cmd_self_test()
    if args.command == "verify":
        return _cmd_verify(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
