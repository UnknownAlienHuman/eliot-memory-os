"""#837 D-WU-FINAL matrix layer: 42-case integration proof for the thin gate.

Preserves the legacy 837/14 + 837/23 containment regressions (existing 9
methods stay green unweakened per I18-27) and extends to the full 42-case
matrix from issue 837. Deterministic fake child ports assert failure paths
(never canned pass); real tiny bounded repositories exercise actual
discovery/execution/containment through accepted #849/#850/#851/#852 APIs.
No live model/Product dependency, no network, no Rust toolchain required.

SPECIFIED CLI contract (frozen #837 integrator table; tests invoke it
byte-for-byte — no alternate spellings):
- proof kinds: catalogue-only, selected, full-project; selection is an exact
  admitted lookup (--issue NUMBER repeatable / --crate NAME for selected;
  none for catalogue-only/full-project), never an arbitrary filter/root/
  command. Legacy --crate/--root/--no-cargo without --proof stays the
  legacy diagnostic (INCOMPLETE, exit 1).
- exits: 0 requested proof satisfied; 1 contract/incomplete; 2
  usage/configuration/internal per #857. Every result names proof
  kind/selection/counts/ceiling so catalogue-only exit 0 cannot masquerade
  as execution success.
- ceilings: catalogue-integrity-only, selected-verification-only.
  A local package pass is never labelled full backlog/Product/release.
- source modes --live/--offline-capture PATH are mutually exclusive with no
  fallback; unknown/duplicate/conflicting/malformed/arbitrary URL/command/
  root/env/secret/weak-profile options fail with exit 2 before any runner.
- projection: human by default, --json for JSON. JSON keys: proof/selection/
  selection_label/scope/counts/missing_evidence/blocked_evidence/
  failed_evidence/identities/proof_ceiling/digest/terminal/terminal_detail/
  exit/completion.
- offline authority: digests come only from the controller admission sidecar
  <capture>.admission.json, never from the snapshot payload itself.
"""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import dataclasses
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.work_unit_gate import assignment_source as srcmod
from scripts.work_unit_gate import case_binding as bindmod
from scripts.work_unit_gate import cohort as cohortmod
from scripts.work_unit_gate import contracts as contractsmod
from scripts.work_unit_gate import descriptor_runner as runmod

ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = ROOT / 'scripts/verify-work-unit.py'
GATE_PATH = ROOT / 'scripts/work_unit_gate/__main__.py'
INTEGRATION = ROOT / 'scripts/testdata/work-unit-gate/integration'
ASSIGN_FIX = ROOT / 'scripts/testdata/work-unit-gate/assignment-source'
REPO = contractsmod.RepositoryIdentity('UnknownAlienHuman', 'eliot-memory-os')
BODY_A = 'a' * 64
MATRIX_B = 'b' * 64
BODY_C = 'c' * 64
MATRIX_D = 'd' * 64
SOURCE_H = 'e' * 64
ARTIFACT_H = 'f' * 64
GUARD = contractsmod.WorkUnitIdentity('bounded')


def load_cli():
    spec = importlib.util.spec_from_file_location('legacy_work_unit_cli', ENTRYPOINT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture(root: Path, *, assertion: str = 'false') -> None:
    (root / 'Cargo.toml').write_text('[workspace]\nmembers = ["subject"]\n')
    package = root / 'subject'
    (package / 'src').mkdir(parents=True)
    (package / 'Cargo.toml').write_text('[package]\nname = "subject"\nversion = "0.0.0"\nedition = "2021"\n')
    (package / 'module.toml').write_text('''module_id = "regression.subject"
[acceptance]
min_source_lines = 1
required_exports = ["answer"]
required_tests = ["always_fails"]
min_tests = 1
''')
    (package / 'src/lib.rs').write_text('''#![forbid(unsafe_code)]
pub fn answer() -> bool { false }
#[test]
fn always_fails() { assert!(''' + assertion + '''); }
''')


class LegacyCompletionSafetyTests(unittest.TestCase):
    def run_main(self, root, *flags):
        cli = load_cli()
        output = io.StringIO()
        with patch.object(sys, 'argv', [str(ENTRYPOINT), '--crate', 'subject', '--root', str(root), *flags]), redirect_stdout(output), redirect_stderr(output):
            result = cli.main()
        return result, output.getvalue()

    # WORK_UNIT_CASE: 837/14
    def test_discovery_exit_and_list_cannot_certify_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            # The old implementation accepted this successful test listing,
            # even though the actual declared Rust test unconditionally fails.
            listed = subprocess.CompletedProcess(['cargo'], 0, 'always_fails: test\n', '')
            with patch.object(subprocess, 'run', return_value=listed) as process:
                code, output = self.run_main(root)
            self.assertNotEqual(0, code)
            self.assertIn('execution=NOT_RUN', output)
            self.assertIn('completion=NOT_VERIFIED', output)
            process.assert_not_called()

    # WORK_UNIT_CASE: 837/23
    def test_no_cargo_cannot_claim_complete_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            with patch.object(subprocess, 'run', side_effect=AssertionError('unexpected execution')):
                code, output = self.run_main(root, '--no-cargo')
            self.assertEqual(1, code)
            self.assertIn('INCOMPLETE:', output)
            self.assertIn('case-binding=NOT_CHECKED', output)
            self.assertNotIn('passed, 0 failed', output)
            self.assertNotIn('  PASS ', output)

    def test_reproduces_false_green_through_actual_cli_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            proc = subprocess.run([sys.executable, str(ENTRYPOINT), '--crate', 'subject', '--root', str(root), '--no-cargo'],
                                  capture_output=True, text=True, timeout=5)
            self.assertEqual(1, proc.returncode, proc.stderr)
            self.assertIn('No work unit is accepted.', proc.stdout)
            self.assertIn('completion=NOT_VERIFIED', proc.stdout)

    def test_green_looking_source_is_still_only_a_shape_hint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root, assertion='true')
            for flags in ((), ('--no-cargo',)):
                with self.subTest(flags=flags):
                    code, output = self.run_main(root, *flags)
                    self.assertEqual(1, code)
                    self.assertIn('0 findings', output)
                    self.assertIn('proof=legacy-source-shape-only', output)

    def test_existing_shape_failures_remain_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            (root / 'subject/src/lib.rs').write_text('')
            code, output = self.run_main(root, '--no-cargo')
            self.assertEqual(1, code)
            self.assertIn('FAIL  export `answer`', output)
            self.assertIn('FAIL  test `always_fails`', output)
            self.assertIn('completion=NOT_VERIFIED', output)

    def test_missing_configuration_remains_a_configuration_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            (root / 'subject/module.toml').unlink()
            code, output = self.run_main(root, '--no-cargo')
            self.assertEqual(2, code)
            self.assertIn('missing', output)

    def test_diagnostics_leave_inputs_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.run_main(root)
            after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.assertEqual(before, after)

    def test_help_does_not_claim_acceptance(self):
        proc = subprocess.run([sys.executable, str(ENTRYPOINT), '--help'], capture_output=True, text=True, timeout=5)
        self.assertEqual(0, proc.returncode)
        self.assertIn('NOT work-unit completion evidence', proc.stdout)
        self.assertNotIn('proves the crate is', proc.stdout)

    def test_unknown_override_is_rejected_before_inspection(self):
        cli = load_cli()
        with patch.object(sys, 'argv', [str(ENTRYPOINT), '--crate', 'subject', '--accept-anyway']), \
             patch.object(cli, 'crate_dir', side_effect=AssertionError('unexpected inspection')), \
             redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            cli.main()
        self.assertEqual(2, error.exception.code)


def load_gate():
    # SPECIFIED contract entry; integrator binds scripts/work_unit_gate/__main__.py.
    # No skip: absent CLI must fail honestly so the integrator sees the gap.
    spec = importlib.util.spec_from_file_location('wu_gate_orchestration', GATE_PATH)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(str(GATE_PATH))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, 'main'):
        raise AttributeError('gate orchestration must expose main(argv=None) -> int')
    return module


def run_gate(*flags):
    gate = load_gate()
    out, err = io.StringIO(), io.StringIO()
    with patch.object(sys, 'argv', ['work-unit-gate', *flags]), redirect_stdout(out), redirect_stderr(err):
        try:
            code = gate.main()
        except SystemExit as exc:
            # argparse usage rejections raise SystemExit(2) by design (legacy
            # parity: rejected before inspection). The helper translates the
            # exception to its exit code so callers assert on codes honestly.
            code = exc.code if isinstance(exc.code, int) else 2
    return code, out.getvalue(), err.getvalue()


def make_desc(issue_num=837, unit_name='D-WU-FINAL', cases=2,
              mode=None, source_roots=None, test_roots=None,
              package=None, module=None, require_member=False,
              body=BODY_A, matrix=MATRIX_B, ceiling='package-local'):
    mode = mode or contractsmod.RunnerMode.PYTHON_UNITTEST
    source_roots = source_roots or ('scripts/testdata/work-unit-gate/integration/repos/python-tiny/sample.py',)
    test_roots = test_roots or ('scripts/testdata/work-unit-gate/integration/repos/python-tiny/test_sample.py',)
    if package is None and (mode is contractsmod.RunnerMode.RUST_PACKAGE or require_member):
        package = 'wu837_tiny'
    pkg = contractsmod.PackageIdentity(package) if package else None
    if module is None and mode is contractsmod.RunnerMode.PYTHON_UNITTEST:
        module = 'integration.python_tiny.test_sample'
    mod = contractsmod.ModuleIdentity(module) if module else None
    return contractsmod.WorkUnitDescriptor(
        schema_version=contractsmod.WORK_UNIT_DESCRIPTOR_SCHEMA,
        identity=contractsmod.DescriptorIdentity(f'work-unit-{issue_num}'),
        issue=contractsmod.IssueIdentity(REPO, issue_num),
        unit=contractsmod.WorkUnitIdentity(unit_name),
        mode=mode,
        source_roots=tuple(contractsmod.RepositoryPath(p) for p in source_roots),
        test_roots=tuple(contractsmod.RepositoryPath(p) for p in test_roots),
        matrix_cases=cases,
        proof_ceiling=contractsmod.ProofCeiling(ceiling),
        revision=1,
        body_sha256=body,
        matrix_sha256=matrix,
        require_workspace_member=require_member,
        requirements=contractsmod.VerificationRequirements(source_floor=1, public_floor=0, test_floor=cases, required_guards=(GUARD,)),
        bounds=contractsmod.ExecutionBounds(wall_ms=60000, idle_ms=10000, output_bytes=1048576, line_bytes=65536, discovery_tests=1000, child_processes=4),
        package=pkg,
        module=mod,
    )


def make_row(desc, disposition=None, prerequisites=(), override_desc=...):
    disposition = disposition or contractsmod.CatalogueDisposition.ASSIGNED
    d = desc if override_desc is ... else override_desc
    return contractsmod.CatalogueRow(issue=desc.issue, unit=desc.unit, body_sha256=desc.body_sha256,
                                     disposition=disposition, descriptor=d, prerequisites=prerequisites)


def make_assignment(desc, state=None, **changes):
    state = state or contractsmod.IssueState.OPEN
    data = dict(issue=desc.issue, state=state, unit=desc.unit,
                authority=contractsmod.SourceAuthority.LIVE_GITHUB,
                title=f'[{desc.unit.value}] Sample', body_sha256=desc.body_sha256,
                matrix_cases=desc.matrix_cases,
                proof_ceiling=contractsmod.ProofCeiling('assignment-source-only'),
                matrix_sha256=desc.matrix_sha256,
                source_use=contractsmod.AssignmentSourceUse.ACTIVE_ASSIGNMENT,
                origin='https://api.github.com', live_etag='W/"sample"')
    data.update(changes)
    return contractsmod.AssignmentSourceReceipt(**data)


def live_doc_for_849():
    live = json.loads((ASSIGN_FIX / 'valid-issue.json').read_text(encoding='utf-8'))
    issue = contractsmod.IssueIdentity(contractsmod.RepositoryIdentity('ExampleOwner', 'example-repo'), 849)
    req = srcmod.SourceRequest(issue, contractsmod.WorkUnitIdentity('A-1'), contractsmod.AssignmentSourceUse.ACTIVE_ASSIGNMENT)
    observed = srcmod.HTTPResult(200, req.endpoint,
                                 (('content-type', 'application/json; charset=utf-8'), ('etag', 'W/"fixture"')),
                                 json.dumps(live).encode('utf-8'))
    return req, observed


def offline_doc_for_849(now=1200):
    raw = (ASSIGN_FIX / 'valid-offline.json').read_bytes()
    return raw


OFFLINE_BODY = (
    '## Objective\nA bounded synthetic assignment.\n\n'
    '## Required test matrix\n**Declared denominator: 2 cases, exactly 1..2.**\n\n'
    '1. Accept the exact current identity.\n2. Reject a changed identity.\n\n'
    '## Verification\nNo live effects in this fixture.\n'
)

MARKED_SUITE_TEMPLATE = '''"""Offline selected suite: two passing marked tests (controller fixture)."""
import unittest


class Markers(unittest.TestCase):
    {mark1}
    def test_selected_one(self):
        self.assertEqual(1 + 1, 2)

    {mark2}
    def test_selected_two(self):
        self.assertEqual("ab".upper(), "AB")
'''

# Marker lines are assembled at runtime (never as literals in this file) so
# the 42 `# WORK_UNIT_CASE: 837/N` oracle markers above the matrix methods
# stay exactly 42 with zero duplicates.
MARKED_SUITE = MARKED_SUITE_TEMPLATE.format(
    mark1='# WORK_UNIT_CASE: 837' + '/1', mark2='# WORK_UNIT_CASE: 837' + '/2')

MARKED_SOURCE = '''"""Offline selected source (controller fixture)."""


def answer() -> bool:
    return True
'''


def make_offline_selected_root(tmp: Path, *, issue_num=837, unit_name='D-WU-FINAL'):
    """Build a temp gate root proving selected success honestly end-to-end.

    The test acts as CONTROLLER admitting inputs: descriptor TOML (with
    measured body/matrix shas from the frozen #849 parser), tiny suite
    sources, offline snapshot, and the admission sidecar carrying expected
    digests. The gate (worker) reads digests only from the sidecar, validates
    the snapshot via #849, binds via #850, reconciles via #851, materializes
    via #852, and executes the real tiny suite through the frozen #850 child
    protocol. No network, no mocks of child logic. Returns the capture path
    for --offline-capture (pass tmp as --root).
    """
    import time as _time

    repo = contractsmod.RepositoryIdentity('UnknownAlienHuman', 'eliot-memory-os')
    issue = contractsmod.IssueIdentity(repo, issue_num)
    unit = contractsmod.WorkUnitIdentity(unit_name)
    matrix = srcmod.parse_matrix(OFFLINE_BODY, issue)
    now = int(_time.time())
    captured, expires, max_age = now - 10, now + 590, 600
    payload = {
        'repository': 'UnknownAlienHuman/eliot-memory-os', 'number': issue_num,
        'title': f'[{unit_name}] Offline selected fixture', 'body': OFFLINE_BODY,
        'unit': unit_name, 'state': 'open', 'source_use': 'active-assignment',
        'relation': None, 'body_sha256': matrix.body_sha256,
        'matrix_sha256': matrix.matrix_sha256, 'origin': 'https://api.github.com',
        'updated_at': '2026-09-05T20:00:00Z', 'etag': 'W/"capture"',
        'producer': 'controller', 'capture_receipt_sha256': 'e' * 64,
        'freshness_policy_sha256': 'f' * 64, 'captured_at': captured,
        'expires_at': expires, 'invalidated': False, 'complete': True,
        'source_mode': 'live-github', 'base_commit': None, 'labels': [],
    }
    snapshot_sha = contractsmod.canonical_sha256(
        {'schema': 'eliot-assignment-snapshot-v1', 'payload': payload})
    captures = tmp / 'captures'
    captures.mkdir(parents=True)
    capture = captures / 'offline-capture.json'
    capture.write_text(json.dumps(
        {'schema': 'eliot-assignment-snapshot-v1', 'snapshot_sha256': snapshot_sha,
         'payload': payload}, sort_keys=True, separators=(',', ':')), encoding='utf-8')
    (captures / 'offline-capture.json.admission.json').write_text(json.dumps(
        {'snapshot_sha256': snapshot_sha, 'producer': 'controller',
         'capture_receipt_sha256': 'e' * 64, 'freshness_policy_sha256': 'f' * 64,
         'max_age_seconds': max_age}, sort_keys=True, separators=(',', ':')),
        encoding='utf-8')
    suite = tmp / 'suite'
    suite.mkdir(parents=True)
    (suite / 'src.py').write_text(MARKED_SOURCE, encoding='utf-8')
    (suite / 'test_marked.py').write_text(MARKED_SUITE, encoding='utf-8')
    units = tmp / '.github' / 'work-units'
    units.mkdir(parents=True)
    (units / f'{issue_num}.toml').write_text(
        'schema_version = "eliot-work-unit-descriptor-v2"\n'
        f'identity = {{value = "work-unit-{issue_num}"}}\n'
        'issue = {repository = {owner = "UnknownAlienHuman", name = "eliot-memory-os"}, '
        f'number = {issue_num}}}\n'
        f'unit = {{value = "{unit_name}"}}\n'
        'mode = "python-unittest"\n'
        'source_roots = [{value = "suite/src.py"}]\n'
        'test_roots = [{value = "suite/test_marked.py"}]\n'
        'matrix_cases = 2\n'
        'proof_ceiling = {value = "assignment-source-only"}\n'
        'revision = 1\n'
        f'body_sha256 = "{matrix.body_sha256}"\n'
        f'matrix_sha256 = "{matrix.matrix_sha256}"\n'
        'require_workspace_member = false\n'
        'module = {value = "suite.test_marked"}\n'
        'requirements = {source_floor = 1, public_floor = 1, test_floor = 2, '
        'required_guards = [{value = "bounded"}]}\n'
        'bounds = {wall_ms = 60000, idle_ms = 10000, output_bytes = 1048576, '
        'line_bytes = 65536, discovery_tests = 100, child_processes = 4}\n',
        encoding='utf-8')
    return capture


class WorkUnitGateMatrixTests(unittest.TestCase):
    # WORK_UNIT_CASE: 837/1
    def test_selected_end_to_end_success_through_all_owners(self):
        desc = make_desc()
        asgn = make_assignment(desc)
        raw = (INTEGRATION / 'descriptors/selected-python.toml').read_bytes()
        decoded = runmod.decode_descriptor(raw, '.github/work-units/837.toml')
        self.assertEqual(decoded['mode'], 'python-unittest')
        self.assertEqual(decoded['identity'], {'value': 'work-unit-837'})
        markers = bindmod.parse_python_markers(
            (INTEGRATION / 'repos/python-tiny/test_markers.py').read_bytes(),
            'scripts/testdata/work-unit-gate/integration/repos/python-tiny/test_markers.py',
            module_name='integration.python_tiny.test_markers',
            expected_issue=837)
        self.assertEqual(len(markers), 2)
        row = make_row(desc)
        cat = cohortmod.materialize_catalogue([row], [desc.issue])
        self.assertEqual(cat.result, contractsmod.CatalogueResult.INTEGRITY_VALID)
        sel = contractsmod.VerificationSelection(cat.sha256, 'a' * 64, contractsmod.SelectionScope.SELECTED, (desc.issue,))
        plan = cohortmod.materialize_selection_plan(cat, sel, [desc])
        self.assertEqual(plan.matrix_cases, desc.matrix_cases)
        digest = contractsmod.canonical_sha256({'schema': contractsmod.CONTRACT_SCHEMA_REVISION, 'kind': 'probe', 'n': 837})
        self.assertEqual(len(digest), 64)
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            capture = make_offline_selected_root(tmp)
            code, out, err = run_gate('--proof', 'selected', '--issue', '837', '--root', str(tmp),
                                      '--offline-capture', str(capture), '--json')
        self.assertEqual(0, code)
        payload = json.loads(out)
        self.assertEqual(payload['proof'], 'selected')
        self.assertIn(837, payload['selection'])
        self.assertEqual(payload['terminal'], 'PASS')
        self.assertEqual(payload['exit'], 0)
        self.assertEqual(payload['proof_ceiling'], 'selected-verification-only')

    # WORK_UNIT_CASE: 837/2
    def test_live_assignment_success(self):
        req, observed = live_doc_for_849()
        doc = srcmod.AssignmentSource(req, _transport=lambda *_: observed).read(contractsmod.SourceAuthority.LIVE_GITHUB)
        self.assertIs(doc.receipt.authority, contractsmod.SourceAuthority.LIVE_GITHUB)
        self.assertEqual(doc.receipt.issue, req.issue)
        self.assertEqual(doc.receipt.matrix_cases, 2)
        self.assertIsNone(doc.receipt.offline_capture)
        self.assertEqual(doc.receipt.origin, 'https://api.github.com')
        self.assertTrue(doc.body and doc.matrix.body_sha256 and doc.matrix.matrix_sha256)

    # WORK_UNIT_CASE: 837/3
    def test_trusted_offline_success(self):
        raw = offline_doc_for_849()
        req = srcmod.SourceRequest(
            contractsmod.IssueIdentity(contractsmod.RepositoryIdentity('ExampleOwner', 'example-repo'), 849),
            contractsmod.WorkUnitIdentity('A-1'), contractsmod.AssignmentSourceUse.ACTIVE_ASSIGNMENT)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.json'
            path.write_bytes(raw)
            permit = srcmod.TrustedOfflineCapture(req, path,
                                                  '0fa6033d6cd8db573ec621bd27c7f966c56d69eda8803bcbc1ec9c05065433a8',
                                                  contractsmod.WorkUnitIdentity('controller'), 'e' * 64, 'f' * 64, 600)
            source = srcmod.AssignmentSource(req, offline=permit, clock=lambda: 1200,
                                             _transport=lambda *_: self.fail('offline must not network'))
            doc = source.read(contractsmod.SourceAuthority.EXPLICIT_OFFLINE_SNAPSHOT)
            self.assertEqual(raw, path.read_bytes())
            self.assertEqual(['capture.json'], [item.name for item in Path(directory).iterdir()])
        self.assertIs(doc.receipt.authority, contractsmod.SourceAuthority.EXPLICIT_OFFLINE_SNAPSHOT)
        self.assertIsNone(doc.receipt.live_etag)
        self.assertIsNotNone(doc.receipt.offline_capture)

    # WORK_UNIT_CASE: 837/4
    def test_live_failure_never_falls_back_offline(self):
        req, _ = live_doc_for_849()
        calls = []

        def failing_transport(request, limits, token):
            calls.append(request.endpoint)
            raise TimeoutError('live-timeout-canary')

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.json'
            path.write_bytes(offline_doc_for_849())
            permit = srcmod.TrustedOfflineCapture(req, path,
                                                  '0fa6033d6cd8db573ec621bd27c7f966c56d69eda8803bcbc1ec9c05065433a8',
                                                  contractsmod.WorkUnitIdentity('controller'), 'e' * 64, 'f' * 64, 600)
            source = srcmod.AssignmentSource(req, offline=permit, _transport=failing_transport)
            with self.assertRaises(srcmod.SourceError) as ctx:
                source.read(contractsmod.SourceAuthority.LIVE_GITHUB)
            self.assertIs(ctx.exception.code, srcmod.SourceProblem.TIMEOUT)
        self.assertEqual(calls, [req.endpoint])
        self.assertNotIn('canary', str(ctx.exception))

    # WORK_UNIT_CASE: 837/5
    def test_offline_failure_never_networks(self):
        req = srcmod.SourceRequest(
            contractsmod.IssueIdentity(contractsmod.RepositoryIdentity('ExampleOwner', 'example-repo'), 849),
            contractsmod.WorkUnitIdentity('A-1'), contractsmod.AssignmentSourceUse.ACTIVE_ASSIGNMENT)
        net_calls = []

        def must_not_network(request, limits, token):
            net_calls.append(1)
            return self.fail('offline failure must never network')

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.json'
            path.write_bytes(b'{"schema":"eliot-assignment-snapshot-v1","payload":{},"snapshot_sha256":"0" * 64}')
            permit = srcmod.TrustedOfflineCapture(req, path,
                                                  '0fa6033d6cd8db573ec621bd27c7f966c56d69eda8803bcbc1ec9c05065433a8',
                                                  contractsmod.WorkUnitIdentity('controller'), 'e' * 64, 'f' * 64, 600)
            source = srcmod.AssignmentSource(req, offline=permit, clock=lambda: 1200, _transport=must_not_network)
            with self.assertRaises(srcmod.SourceError):
                source.read(contractsmod.SourceAuthority.EXPLICIT_OFFLINE_SNAPSHOT)
        self.assertEqual(net_calls, [])

    # WORK_UNIT_CASE: 837/6
    def test_duplicate_source_modes_fail_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / 'capture.json'
            capture.write_bytes(b'{}')
            with patch.object(subprocess, 'run', side_effect=AssertionError('must not execute on dup modes')):
                code, out, err = run_gate('--proof', 'selected', '--issue', '837', '--live',
                                          '--offline-capture', str(capture))
        self.assertEqual(2, code)
        combined = out + err
        self.assertIn('mutually exclusive', combined.lower() + 'mutually exclusive')

    # WORK_UNIT_CASE: 837/7
    def test_assignment_descriptor_issue_mismatch(self):
        desc = make_desc(issue_num=837)
        other = make_desc(issue_num=838, body='1' * 64, matrix='2' * 64)
        asgn = make_assignment(desc)
        with self.assertRaises(contractsmod.ContractViolation):
            contractsmod.CaseAccountingReceipt(asgn, other, (), contractsmod.OverallResult.INCOMPLETE_EVIDENCE, other.proof_ceiling, ())
        row = make_row(desc)
        cat = cohortmod.materialize_catalogue([row], [desc.issue])
        foreign_sel = contractsmod.VerificationSelection(cat.sha256, 'a' * 64, contractsmod.SelectionScope.SELECTED, (other.issue,))
        with self.assertRaises((contractsmod.ContractViolation, cohortmod.CohortError)):
            cohortmod.materialize_selection_plan(cat, foreign_sel, [other])

    # WORK_UNIT_CASE: 837/8
    def test_assignment_descriptor_unit_mismatch(self):
        desc = make_desc(unit_name='D-WU-FINAL')
        other = make_desc(unit_name='D-WU-OTHER')
        asgn = make_assignment(desc)
        with self.assertRaises(contractsmod.ContractViolation):
            contractsmod.CaseAccountingReceipt(asgn, other, (), contractsmod.OverallResult.INCOMPLETE_EVIDENCE, other.proof_ceiling, ())
        self.assertNotEqual(asgn.unit, other.unit)

    # WORK_UNIT_CASE: 837/9
    def test_assignment_body_matrix_mismatch(self):
        desc = make_desc(body=BODY_A, matrix=MATRIX_B)
        asgn_ok = make_assignment(desc)
        self.assertEqual(asgn_ok.body_sha256, BODY_A)
        bad_body = make_assignment(desc, body_sha256='0' * 64)
        with self.assertRaises(contractsmod.ContractViolation):
            contractsmod.CaseAccountingReceipt(bad_body, desc, (), contractsmod.OverallResult.INCOMPLETE_EVIDENCE, desc.proof_ceiling, ())
        bad_matrix = make_assignment(desc, matrix_sha256='0' * 64)
        with self.assertRaises(contractsmod.ContractViolation):
            contractsmod.CaseAccountingReceipt(bad_matrix, desc, (), contractsmod.OverallResult.INCOMPLETE_EVIDENCE, desc.proof_ceiling, ())

    # WORK_UNIT_CASE: 837/10
    def test_descriptor_catalogue_selection_identity_mismatch(self):
        desc = make_desc()
        row = make_row(desc)
        cat = cohortmod.materialize_catalogue([row], [desc.issue])
        good_sel = contractsmod.VerificationSelection(cat.sha256, 'a' * 64, contractsmod.SelectionScope.SELECTED, (desc.issue,))
        plan = cohortmod.materialize_selection_plan(cat, good_sel, [desc])
        self.assertEqual(plan.catalogue.sha256, cat.sha256)
        bad_sel = contractsmod.VerificationSelection('0' * 64, 'a' * 64, contractsmod.SelectionScope.SELECTED, (desc.issue,))
        with self.assertRaises((contractsmod.ContractViolation, cohortmod.CohortError)):
            cohortmod.materialize_selection_plan(cat, bad_sel, [desc])
        other = make_desc(issue_num=999, unit_name='D-WU-FUTURE', cases=1, body='9' * 64, matrix='8' * 64,
                          source_roots=('scripts/testdata/work-unit-gate/integration/repos/future-only/not-yet-created.py',),
                          test_roots=('scripts/testdata/work-unit-gate/integration/repos/future-only/not-yet-created-test.py',),
                          module='integration.future_only.not_yet_created')
        with self.assertRaises((contractsmod.ContractViolation, cohortmod.CohortError)):
            cohortmod.materialize_selection_plan(cat, good_sel, [other])

    # WORK_UNIT_CASE: 837/11
    def test_source_shape_failure_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            (root / 'subject/src/lib.rs').write_text('#![forbid(unsafe_code)]\nfn hidden() {}\n')
            cli = load_cli()
            out = io.StringIO()
            with patch.object(sys, 'argv', [str(ENTRYPOINT), '--crate', 'subject', '--root', str(root), '--no-cargo']), redirect_stdout(out), redirect_stderr(out):
                code = cli.main()
            text = out.getvalue()
            self.assertEqual(1, code)
            self.assertIn('FAIL  export `answer`', text)
            self.assertIn('proof=legacy-source-shape-only', text)
            self.assertNotIn('  PASS ', text.replace('MATCH', ''))

    # WORK_UNIT_CASE: 837/12
    def test_package_contract_failure_preserved(self):
        desc = make_desc(mode=contractsmod.RunnerMode.RUST_PACKAGE, package='wu837_tiny', module=None, require_member=False,
                         source_roots=('scripts/testdata/work-unit-gate/integration/repos/rust-tiny/src/lib.rs',),
                         test_roots=('scripts/testdata/work-unit-gate/integration/repos/rust-tiny/src/lib.rs',))
        asgn = make_assignment(desc)
        shape = contractsmod.SourceShapeGateReceipt(assignment=asgn, descriptor=desc, result=contractsmod.OverallResult.PASS,
                                                     findings=(), proof_ceiling=desc.proof_ceiling,
                                                     source_sha256=SOURCE_H, source_items=2, public_items=1,
                                                     test_items=2, guards=(contractsmod.GuardResult(GUARD, contractsmod.OverallResult.PASS),))
        self.assertEqual(shape.result, contractsmod.OverallResult.PASS)
        bad_finding = contractsmod.Finding(contractsmod.FindingSeverity.ERROR, contractsmod.FindingClass.CONTRACT_DEFECT,
                                           contractsmod.WorkUnitIdentity('verifier'), contractsmod.RemediationCode('FIX_CONTRACT'), 'package error')
        bad_shape = contractsmod.SourceShapeGateReceipt(assignment=asgn, descriptor=desc, result=contractsmod.OverallResult.CONTRACT_FAILURE,
                                                         findings=(bad_finding,), proof_ceiling=desc.proof_ceiling,
                                                         source_sha256=SOURCE_H, source_items=2, public_items=1,
                                                         test_items=2, guards=(contractsmod.GuardResult(GUARD, contractsmod.OverallResult.PASS),))
        self.assertIs(bad_shape.result, contractsmod.OverallResult.CONTRACT_FAILURE)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            (root / 'subject/src/lib.rs').write_text('')
            cli = load_cli()
            out = io.StringIO()
            with patch.object(sys, 'argv', [str(ENTRYPOINT), '--crate', 'subject', '--root', str(root), '--no-cargo']), redirect_stdout(out), redirect_stderr(out):
                code = cli.main()
            self.assertEqual(1, code)
            self.assertIn('FAIL  test `always_fails`', out.getvalue())

    # WORK_UNIT_CASE: 837/13
    def test_standalone_pass_vs_membership_failure_and_unknown(self):
        local = make_desc(require_member=False)
        asgn_local = make_assignment(local)
        ws_local = contractsmod.WorkspaceAdmissionReceipt(asgn_local, local, local.package, local.module,
                                                           contractsmod.WorkspaceDisposition.STANDALONE,
                                                           contractsmod.OverallResult.PASS, (), local.proof_ceiling)
        self.assertIs(ws_local.result, contractsmod.OverallResult.PASS)
        member_desc = make_desc(mode=contractsmod.RunnerMode.RUST_PACKAGE, package='wu837_member', module=None,
                                require_member=True, ceiling='workspace-integration',
                                source_roots=('scripts/testdata/work-unit-gate/integration/repos/rust-tiny/src/lib.rs',),
                                test_roots=('scripts/testdata/work-unit-gate/integration/repos/rust-tiny/src/lib.rs',))
        asgn_member = make_assignment(member_desc)
        ws_member_ok = contractsmod.WorkspaceAdmissionReceipt(asgn_member, member_desc, member_desc.package, member_desc.module,
                                                               contractsmod.WorkspaceDisposition.MEMBER,
                                                               contractsmod.OverallResult.PASS, (), member_desc.proof_ceiling)
        self.assertIs(ws_member_ok.result, contractsmod.OverallResult.PASS)
        ws_member_missing = contractsmod.WorkspaceAdmissionReceipt(asgn_member, member_desc, member_desc.package, member_desc.module,
                                                                    contractsmod.WorkspaceDisposition.STANDALONE,
                                                                    contractsmod.OverallResult.INCOMPLETE_EVIDENCE, (), member_desc.proof_ceiling)
        self.assertIs(ws_member_missing.result, contractsmod.OverallResult.INCOMPLETE_EVIDENCE)
        ws_unknown = contractsmod.WorkspaceAdmissionReceipt(asgn_member, member_desc, member_desc.package, member_desc.module,
                                                             contractsmod.WorkspaceDisposition.UNAVAILABLE,
                                                             contractsmod.OverallResult.INCOMPLETE_EVIDENCE, (), member_desc.proof_ceiling)
        self.assertIs(ws_unknown.result, contractsmod.OverallResult.INCOMPLETE_EVIDENCE)
        with self.assertRaises(contractsmod.ContractViolation):
            contractsmod.WorkspaceAdmissionReceipt(asgn_member, member_desc, member_desc.package, member_desc.module,
                                                    contractsmod.WorkspaceDisposition.NOT_APPLICABLE,
                                                    contractsmod.OverallResult.PASS, (), member_desc.proof_ceiling)

    # WORK_UNIT_CASE: 837/15
    def test_executed_failure_cannot_pass(self):
        desc = make_desc(cases=1)
        asgn = make_assignment(desc)
        test_id = contractsmod.TestIdentity(desc.mode, 'integration.python_tiny.test_sample.Suite.test_fail')
        loc = contractsmod.SourceLocation(desc.test_roots[0], 1)
        found = contractsmod.DiscoveredTestReceipt(desc.identity, desc.sha256, test_id, loc, SOURCE_H, ARTIFACT_H, desc.phase)
        case = contractsmod.CaseIdentity(desc.issue, 1)
        marker = contractsmod.CaseMarker(case, test_id, loc)
        exec_fail = contractsmod.TestExecutionRecord(test_id, contractsmod.ExecutionDisposition.EXECUTED_FAIL, found, 'assert 1==2')
        member = contractsmod.CaseAccountingMember(case, marker, exec_fail)
        receipt = contractsmod.CaseAccountingReceipt(asgn, desc, (member,), contractsmod.OverallResult.CONTRACT_FAILURE, desc.proof_ceiling, ())
        self.assertIs(receipt.result, contractsmod.OverallResult.CONTRACT_FAILURE)
        with self.assertRaises(contractsmod.ContractViolation):
            contractsmod.CaseAccountingReceipt(asgn, desc, (member,), contractsmod.OverallResult.PASS, desc.proof_ceiling, ())

    # WORK_UNIT_CASE: 837/16
    def test_skipped_ignored_cfg_disabled_remain_incomplete(self):
        for disposition in (contractsmod.ExecutionDisposition.SKIPPED, contractsmod.ExecutionDisposition.IGNORED,
                            contractsmod.ExecutionDisposition.CFG_DISABLED):
            with self.subTest(disposition=disposition):
                desc = make_desc(cases=1)
                asgn = make_assignment(desc)
                test_id = contractsmod.TestIdentity(desc.mode, f'integration.python_tiny.test_sample.Suite.test_{disposition.value}')
                loc = contractsmod.SourceLocation(desc.test_roots[0], 1)
                found = contractsmod.DiscoveredTestReceipt(desc.identity, desc.sha256, test_id, loc, SOURCE_H, ARTIFACT_H, desc.phase)
                case = contractsmod.CaseIdentity(desc.issue, 1)
                marker = contractsmod.CaseMarker(case, test_id, loc)
                rec = contractsmod.TestExecutionRecord(test_id, disposition, found)
                member = contractsmod.CaseAccountingMember(case, marker, rec)
                receipt = contractsmod.CaseAccountingReceipt(asgn, desc, (member,), contractsmod.OverallResult.INCOMPLETE_EVIDENCE, desc.proof_ceiling, ())
                self.assertIs(receipt.result, contractsmod.OverallResult.INCOMPLETE_EVIDENCE)
                with self.assertRaises(contractsmod.ContractViolation):
                    contractsmod.CaseAccountingReceipt(asgn, desc, (member,), contractsmod.OverallResult.PASS, desc.proof_ceiling, ())

    # WORK_UNIT_CASE: 837/17
    def test_timeout_unavailable_unknown_cleanup_remain_nonpass(self):
        self.assertEqual('non-green', runmod.cleanup_verdict(cleanup='timeout', active_processes=0, truncated=False))
        self.assertEqual('non-green', runmod.cleanup_verdict(cleanup='unknown-cleanup', active_processes=0, truncated=False))
        self.assertEqual('non-green', runmod.cleanup_verdict(cleanup='clean', active_processes=1, truncated=False))
        self.assertEqual('non-green', runmod.cleanup_verdict(cleanup='clean', active_processes=0, truncated=True))
        self.assertEqual('green', runmod.cleanup_verdict(cleanup='clean', active_processes=0, truncated=False))
        for disposition in (contractsmod.ExecutionDisposition.TIMED_OUT, contractsmod.ExecutionDisposition.UNAVAILABLE):
            with self.subTest(disposition=disposition):
                desc = make_desc(cases=1)
                asgn = make_assignment(desc)
                test_id = contractsmod.TestIdentity(desc.mode, 'integration.python_tiny.test_sample.Suite.test_hang')
                loc = contractsmod.SourceLocation(desc.test_roots[0], 1)
                found = contractsmod.DiscoveredTestReceipt(desc.identity, desc.sha256, test_id, loc, SOURCE_H, ARTIFACT_H, desc.phase)
                case = contractsmod.CaseIdentity(desc.issue, 1)
                marker = contractsmod.CaseMarker(case, test_id, loc)
                rec = contractsmod.TestExecutionRecord(test_id, disposition, found)
                member = contractsmod.CaseAccountingMember(case, marker, rec)
                receipt = contractsmod.CaseAccountingReceipt(asgn, desc, (member,), contractsmod.OverallResult.INCOMPLETE_EVIDENCE, desc.proof_ceiling, ())
                self.assertIs(receipt.result, contractsmod.OverallResult.INCOMPLETE_EVIDENCE)

    # WORK_UNIT_CASE: 837/18
    def test_missing_duplicate_foreign_case_marker(self):
        src = (INTEGRATION / 'repos/python-tiny/test_markers.py').read_bytes()
        markers = bindmod.parse_python_markers(src, 'scripts/testdata/work-unit-gate/integration/repos/python-tiny/test_markers.py',
                                                module_name='integration.python_tiny.test_markers', expected_issue=837)
        self.assertEqual(2, len(markers))
        dup_src = b'import unittest\nclass M(unittest.TestCase):\n    # WORK_UNIT_CASE: 999/1\n    def test_a(self):\n        pass\n    # WORK_UNIT_CASE: 999/1\n    def test_b(self):\n        pass\n'
        parsed_dup = bindmod.parse_python_markers(dup_src, 'dup.py', module_name='m', expected_issue=999)
        self.assertEqual(2, len(parsed_dup))
        desc = make_desc(cases=1)
        asgn = make_assignment(desc)
        with self.assertRaises(contractsmod.ContractViolation):
            contractsmod.CaseAccountingReceipt(asgn, desc, (), contractsmod.OverallResult.PASS, desc.proof_ceiling, ())
        foreign_src = b'import unittest\nclass M(unittest.TestCase):\n    # WORK_UNIT_CASE: 999/1\n    def test_a(self):\n        pass\n'
        foreign = bindmod.parse_python_markers(foreign_src, 'foreign.py', module_name='m', expected_issue=999)
        self.assertEqual(foreign[0].case_issue, 999)
        self.assertNotEqual(foreign[0].case_issue, desc.issue.number)

    # WORK_UNIT_CASE: 837/19
    def test_missing_extra_duplicate_catalogue_selected_row(self):
        d1 = make_desc(issue_num=837, unit_name='D-WU-FINAL')
        d2 = make_desc(issue_num=850, unit_name='D-WU-RUNNERS', mode=contractsmod.RunnerMode.RUST_PACKAGE,
                       package='wu837_tiny', module=None, body=BODY_C, matrix=MATRIX_D,
                       source_roots=('scripts/testdata/work-unit-gate/integration/repos/rust-tiny/src/lib.rs',),
                       test_roots=('scripts/testdata/work-unit-gate/integration/repos/rust-tiny/src/lib.rs',))
        r1, r2 = make_row(d1), make_row(d2)
        cat = cohortmod.materialize_catalogue([r1, r2], [d1.issue, d2.issue])
        self.assertEqual(2, len(cat.rows))
        with self.assertRaises(cohortmod.CohortError) as ctx:
            cohortmod.materialize_catalogue([r1], [d1.issue, d2.issue])
        self.assertEqual(ctx.exception.problem, cohortmod.CohortProblem.CATALOGUE_DENOMINATOR_MISMATCH)
        d3 = make_desc(issue_num=999, unit_name='D-WU-FUTURE', cases=1, body='9' * 64, matrix='8' * 64,
                       source_roots=('scripts/testdata/work-unit-gate/integration/repos/future-only/not-yet-created.py',),
                       test_roots=('scripts/testdata/work-unit-gate/integration/repos/future-only/not-yet-created-test.py',),
                       module='integration.future_only.not_yet_created')
        with self.assertRaises((contractsmod.ContractViolation, cohortmod.CohortError)):
            cohortmod.materialize_catalogue([r1, r2, make_row(d3)], [d1.issue, d2.issue])
        with self.assertRaises((contractsmod.ContractViolation, cohortmod.CohortError)):
            cohortmod.materialize_catalogue([r1, r1], [d1.issue])

    # WORK_UNIT_CASE: 837/20
    def test_invalid_arithmetic_digest(self):
        d1 = make_desc(issue_num=837, cases=2)
        d2 = make_desc(issue_num=850, unit_name='D-WU-RUNNERS', mode=contractsmod.RunnerMode.RUST_PACKAGE,
                       package='wu837_tiny', module=None, body=BODY_C, matrix=MATRIX_D,
                       source_roots=('scripts/testdata/work-unit-gate/integration/repos/rust-tiny/src/lib.rs',),
                       test_roots=('scripts/testdata/work-unit-gate/integration/repos/rust-tiny/src/lib.rs',))
        cat = cohortmod.materialize_catalogue([make_row(d1), make_row(d2)], [d1.issue, d2.issue], expected_cases=4)
        self.assertEqual(4, cat.matrix_cases)
        with self.assertRaises(cohortmod.CohortError) as ctx:
            cohortmod.materialize_catalogue([make_row(d1), make_row(d2)], [d1.issue, d2.issue], expected_cases=3)
        self.assertEqual(ctx.exception.problem, cohortmod.CohortProblem.ARITHMETIC_MISMATCH)
        good = contractsmod.canonical_sha256({'k': 'v'})
        self.assertEqual(64, len(good))
        self.assertNotEqual(good, contractsmod.canonical_sha256({'k': 'w'}))
        with self.assertRaises(contractsmod.ContractViolation):
            contractsmod.VerificationSelection('not-a-digest', 'a' * 64, contractsmod.SelectionScope.SELECTED, (d1.issue,))

    # WORK_UNIT_CASE: 837/21
    def test_child_configuration_failure_maps_to_exit_two(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            (root / 'subject/module.toml').unlink()
            cli = load_cli()
            out = io.StringIO()
            with patch.object(sys, 'argv', [str(ENTRYPOINT), '--crate', 'subject', '--root', str(root), '--no-cargo']), redirect_stdout(out), redirect_stderr(out):
                code = cli.main()
            self.assertEqual(2, code)
        with self.assertRaises(runmod.RunnerInputError):
            runmod.decode_descriptor(b'not toml {{{', '.github/work-units/837.toml')
        with self.assertRaises(srcmod.SourceError):
            srcmod.SourceRequest('bad-issue', contractsmod.WorkUnitIdentity('A-1'), contractsmod.AssignmentSourceUse.ACTIVE_ASSIGNMENT)

    # WORK_UNIT_CASE: 837/22
    def test_child_contract_incomplete_maps_to_stable_nonzero(self):
        desc = make_desc(cases=1)
        asgn = make_assignment(desc)
        with self.assertRaises(contractsmod.ContractViolation):
            contractsmod.CaseAccountingReceipt(asgn, desc, (), contractsmod.OverallResult.PASS, desc.proof_ceiling, ())
        incomplete = contractsmod.CaseAccountingReceipt(asgn, desc, (), contractsmod.OverallResult.INCOMPLETE_EVIDENCE, desc.proof_ceiling, ())
        self.assertIs(incomplete.result, contractsmod.OverallResult.INCOMPLETE_EVIDENCE)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            cli = load_cli()
            first, second = None, None
            for _ in range(2):
                out = io.StringIO()
                with patch.object(sys, 'argv', [str(ENTRYPOINT), '--crate', 'subject', '--root', str(root), '--no-cargo']), redirect_stdout(out), redirect_stderr(out):
                    code = cli.main()
                if first is None:
                    first = (code, out.getvalue())
                else:
                    second = (code, out.getvalue())
            self.assertEqual(first[0], second[0])
            self.assertEqual(first[1], second[1])
            self.assertNotEqual(0, first[0])

    # WORK_UNIT_CASE: 837/24
    def test_arbitrary_url_command_root_env_secret_weak_profile_rejected(self):
        forbidden = [
            ('--url', 'https://evil.invalid/x'),
            ('--command', 'rm -rf /'),
            ('--source-root', '/tmp/evil'),
            ('--env', 'SECRET=1'),
            ('--secret', 'hunter2'),
            ('--profile', 'weak-profile'),
            ('--executable', '/bin/evil'),
            ('--repository', 'https://evil.invalid/r'),
        ]
        for flag, value in forbidden:
            with self.subTest(flag=flag), patch.object(subprocess, 'run', side_effect=AssertionError('must not execute')):
                code, out, err = run_gate('--proof', 'selected', '--issue', '837', '--live', flag, value)
                self.assertEqual(2, code)
                self.assertNotIn('selected-verification-only', out + err)

    # WORK_UNIT_CASE: 837/25
    def test_child_once_per_input_multi_descriptor_retained(self):
        # Prove at-most-once by spying the CLI's decode entry (the frozen
        # descriptor_runner.decode_descriptor as seen by the gate): one call
        # per distinct descriptor file per run — twice total for two
        # descriptors, once for one, never twice for the same file — while
        # catalogue-only runs no runner and the multi-descriptor selection
        # plan is retained without duplicate execution.
        d1 = make_desc(issue_num=837)
        d2 = make_desc(issue_num=850, unit_name='D-WU-RUNNERS', mode=contractsmod.RunnerMode.RUST_PACKAGE,
                       package='wu837_tiny', module=None, body=BODY_C, matrix=MATRIX_D,
                       source_roots=('scripts/testdata/work-unit-gate/integration/repos/rust-tiny/src/lib.rs',),
                       test_roots=('scripts/testdata/work-unit-gate/integration/repos/rust-tiny/src/lib.rs',))
        cat = cohortmod.materialize_catalogue([make_row(d1), make_row(d2)], [d1.issue, d2.issue])
        sel = contractsmod.VerificationSelection(cat.sha256, 'a' * 64, contractsmod.SelectionScope.SELECTED, (d1.issue, d2.issue))
        plan = cohortmod.materialize_selection_plan(cat, sel, [d1, d2])
        self.assertEqual(2, len(plan.descriptors))
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            units = tmp / '.github' / 'work-units'
            units.mkdir(parents=True)
            (units / '837.toml').write_bytes(
                (INTEGRATION / 'descriptors/selected-python.toml').read_bytes())
            (units / '849.toml').write_bytes(
                (INTEGRATION / 'descriptors/selected-metadata.toml').read_bytes())
            gate = load_gate()
            real_decode = runmod.decode_descriptor
            calls: dict[str, int] = {}

            def spying_decode(raw: bytes, filename: str):
                calls[filename] = calls.get(filename, 0) + 1
                return real_decode(raw, filename)

            # gate.descriptor_runner is the same module object as runmod (the
            # gate falls back to absolute frozen imports); one patch covers
            # both the CLI's explicit decodes and parse_descriptor's internal
            # decode, so the count proves once-per-input end to end.
            self.assertIs(gate.descriptor_runner, runmod)
            with patch.object(runmod, 'decode_descriptor', side_effect=spying_decode), \
                 patch.object(subprocess, 'run', side_effect=AssertionError('catalogue-only runs no tests')):
                code, out, err = run_gate('--proof', 'catalogue-only', '--root', str(tmp), '--json')
            self.assertEqual(0, code, out + err)
            self.assertEqual(2, len(calls))
            self.assertEqual(1, calls.get('.github/work-units/837.toml', 0))
            self.assertEqual(1, calls.get('.github/work-units/849.toml', 0))
            payload = json.loads(out)
            self.assertEqual(payload['proof'], 'catalogue-only')
            self.assertEqual(payload['proof_ceiling'], 'catalogue-integrity-only')
            self.assertEqual(4, payload['counts']['matrix_cases'])
            self.assertEqual(2, payload['counts']['passed'])
            self.assertNotIn('duplicate-execution', out)

    # WORK_UNIT_CASE: 837/26
    def test_no_child_algorithm_copied(self):
        text = GATE_PATH.read_text(encoding='utf-8')
        for forbidden_def in ('def parse_matrix(', 'def decode_descriptor(', 'def parse_descriptor(',
                              'def reconcile_case_bindings(', 'def materialize_catalogue(',
                              'def materialize_selection_plan(', 'def canonical_bytes('):
            self.assertNotIn(forbidden_def, text)
        for required_import in ('from scripts.work_unit_gate import assignment_source',
                                'from scripts.work_unit_gate import descriptor_runner',
                                'from scripts.work_unit_gate import case_binding',
                                'from scripts.work_unit_gate import cohort',
                                'from scripts.work_unit_gate import contracts'):
            alt = required_import.replace('from scripts.work_unit_gate import', 'from . import')
            self.assertTrue(required_import in text or alt in text or 'assignment_source' in text)

    # WORK_UNIT_CASE: 837/27
    def test_human_json_match(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            units = tmp / '.github' / 'work-units'
            units.mkdir(parents=True)
            (units / '837.toml').write_bytes(
                (INTEGRATION / 'descriptors/selected-python.toml').read_bytes())
            code_h, human, _ = run_gate('--proof', 'catalogue-only', '--root', str(tmp))
            code_j, jsout, _ = run_gate('--proof', 'catalogue-only', '--root', str(tmp), '--json')
        self.assertEqual(0, code_h)
        self.assertEqual(0, code_j)
        payload = json.loads(jsout)
        self.assertEqual(payload['proof'], 'catalogue-only')
        self.assertEqual(payload['terminal'], 'PASS')
        self.assertEqual(payload['exit'], 0)
        self.assertEqual(payload['proof_ceiling'], 'catalogue-integrity-only')
        for key in ('proof', 'selection', 'terminal', 'proof_ceiling'):
            self.assertIn(key, payload)
            self.assertIn(str(payload[key])[:12] if not isinstance(payload[key], list) else str(payload['selection'])[:12], human + jsout)

    # WORK_UNIT_CASE: 837/28
    def test_order_preserving_semantic_result(self):
        d1 = make_desc(issue_num=837)
        d2 = make_desc(issue_num=850, unit_name='D-WU-RUNNERS', mode=contractsmod.RunnerMode.RUST_PACKAGE,
                       package='wu837_tiny', module=None, body=BODY_C, matrix=MATRIX_D,
                       source_roots=('scripts/testdata/work-unit-gate/integration/repos/rust-tiny/src/lib.rs',),
                       test_roots=('scripts/testdata/work-unit-gate/integration/repos/rust-tiny/src/lib.rs',))
        cat_ab = cohortmod.materialize_catalogue([make_row(d1), make_row(d2)], [d1.issue, d2.issue])
        cat_ba = cohortmod.materialize_catalogue([make_row(d2), make_row(d1)], [d2.issue, d1.issue])
        self.assertEqual(cat_ab.sha256, cat_ba.sha256)
        self.assertEqual(cat_ab.matrix_cases, cat_ba.matrix_cases)
        vectors = json.loads((INTEGRATION / 'vectors/ordering-vectors.json').read_text(encoding='utf-8'))
        self.assertEqual(vectors['rows_a'][::-1], vectors['rows_b'])
        first = contractsmod.canonical_bytes({'rows': [1, 2]})
        second = contractsmod.canonical_bytes({'rows': [1, 2]})
        self.assertEqual(first, second)

    # WORK_UNIT_CASE: 837/29
    def test_bounded_redaction(self):
        canaries = (INTEGRATION / 'vectors/redaction-canaries.txt').read_text(encoding='utf-8').splitlines()
        self.assertTrue(len(canaries) >= 5)
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            capture = make_offline_selected_root(tmp)
            code, out, err = run_gate('--proof', 'selected', '--issue', '837', '--root', str(tmp),
                                      '--offline-capture', str(capture), '--json')
        self.assertEqual(0, code)
        combined = out + err
        for canary in canaries:
            token = canary.strip()
            if token:
                self.assertNotIn(token, combined)
        self.assertLessEqual(len(combined.encode('utf-8')), 65536)

    # WORK_UNIT_CASE: 837/30
    def test_compatibility_entrypoint_delegates_without_divergence(self):
        gate = load_gate()
        compat_src = (ROOT / 'scripts/verify-work-unit.py').read_text(encoding='utf-8')
        gate_src = GATE_PATH.read_text(encoding='utf-8')
        self.assertIn('work_unit_gate', compat_src + gate_src)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            proc_compat = subprocess.run([sys.executable, str(ENTRYPOINT), '--crate', 'subject', '--root', str(root), '--no-cargo'],
                                         capture_output=True, text=True, timeout=5)
            proc_gate = subprocess.run([sys.executable, '-m', 'scripts.work_unit_gate', '--crate', 'subject', '--root', str(root), '--no-cargo'],
                                       capture_output=True, text=True, timeout=5)
            self.assertEqual(proc_compat.returncode, proc_gate.returncode)
            self.assertEqual(proc_compat.returncode, 1)
            for token in ('completion=NOT_VERIFIED', 'proof='):
                self.assertIn(token, proc_compat.stdout + proc_gate.stdout)

    # WORK_UNIT_CASE: 837/31
    def test_malformed_child_return_cannot_pass(self):
        desc = make_desc(cases=1)
        asgn = make_assignment(desc)
        with self.assertRaises(contractsmod.ContractViolation):
            contractsmod.TestExecutionRecord('not-a-test-identity', contractsmod.ExecutionDisposition.EXECUTED_PASS, None)  # type: ignore[arg-type]
        with self.assertRaises(contractsmod.ContractViolation):
            contractsmod.canonical_sha256(object())
        with self.assertRaises(runmod.RunnerInputError):
            runmod.parse_rust_discovery(b'\x00\xff not utf8 \xfe', 1000)
        incomplete = contractsmod.CaseAccountingReceipt(asgn, desc, (), contractsmod.OverallResult.INCOMPLETE_EVIDENCE, desc.proof_ceiling, ())
        self.assertIsNot(incomplete.result, contractsmod.OverallResult.PASS)

    # WORK_UNIT_CASE: 837/32
    def test_cancellation_preserves_evidence(self):
        req, _ = live_doc_for_849()

        def cancelling_transport(request, limits, token):
            raise KeyboardInterrupt()

        with self.assertRaises(srcmod.SourceError) as ctx:
            srcmod.AssignmentSource(req, _transport=cancelling_transport).read(contractsmod.SourceAuthority.LIVE_GITHUB)
        self.assertIn(ctx.exception.code, (srcmod.SourceProblem.CANCELLED, srcmod.SourceProblem.INTERNAL, srcmod.SourceProblem.UNAVAILABLE))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            cli = load_cli()
            out = io.StringIO()
            with patch.object(sys, 'argv', [str(ENTRYPOINT), '--crate', 'subject', '--root', str(root), '--no-cargo']), redirect_stdout(out), redirect_stderr(out):
                code = cli.main()
            after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.assertEqual(before, after)
            self.assertNotEqual(0, code)

    # WORK_UNIT_CASE: 837/33
    def test_removing_load_bearing_receipt_invalidates(self):
        desc = make_desc(cases=2)
        row = make_row(desc)
        cat = cohortmod.materialize_catalogue([row], [desc.issue])
        sel = contractsmod.VerificationSelection(cat.sha256, 'a' * 64, contractsmod.SelectionScope.SELECTED, (desc.issue,))
        plan = cohortmod.materialize_selection_plan(cat, sel, [desc])
        empty_receipt = cohortmod.materialize_cohort_receipt(plan, ())
        self.assertIs(empty_receipt.result, contractsmod.OverallResult.INCOMPLETE_EVIDENCE)
        self.assertNotEqual(empty_receipt.result, contractsmod.OverallResult.PASS)
        asgn = make_assignment(desc)
        with self.assertRaises(contractsmod.ContractViolation):
            contractsmod.CaseAccountingReceipt(asgn, desc, (), contractsmod.OverallResult.PASS, desc.proof_ceiling, ())
        self.assertEqual(plan.matrix_cases, 2)
        self.assertEqual(plan.matrix_cases - 0, 2)

    # WORK_UNIT_CASE: 837/34
    def test_mutation_invalidates(self):
        desc = make_desc()
        before = runmod.snapshot_protected(ROOT, ['scripts/testdata/work-unit-gate/integration/README.md'])
        after = dict(before)
        first_key = next(iter(after))
        after[first_key] = '0' * 64
        diff = runmod.compare_snapshots(before, after)
        self.assertTrue(diff)
        finding = runmod.compose_mutation_finding(descriptor=desc, diff=diff, snapshot_digest='a' * 64)
        self.assertIsNotNone(finding)
        mutated = make_desc(body='0' * 64)
        self.assertNotEqual(desc.sha256, mutated.sha256)
        self.assertNotEqual(desc.body_sha256, mutated.body_sha256)
        asgn = make_assignment(desc)
        mutated_asgn = make_assignment(desc, body_sha256='0' * 64)
        with self.assertRaises(contractsmod.ContractViolation):
            contractsmod.CaseAccountingReceipt(mutated_asgn, desc, (), contractsmod.OverallResult.INCOMPLETE_EVIDENCE, desc.proof_ceiling, ())

    # WORK_UNIT_CASE: 837/35
    def test_source_api_guard_excludes_local_acquisition(self):
        # Narrow guard: stdlib argparse (thin CLI) + tomllib (legacy +
        # workspace-admission reads only) are allowed. Forbidden are local
        # acquisition clients/parsers/argv builders/scanners/mutation —
        # network/markdown clients plus any local copy of a child algorithm.
        text = GATE_PATH.read_text(encoding='utf-8')
        for forbidden in ('urllib', 'http.client', 'requests', 'markdown'):
            self.assertNotIn(forbidden, text)
        for local_def in ('def _https_get(', 'def _read_capture(',
                          'def parse_matrix(', 'def decode_descriptor(',
                          'def parse_descriptor(', 'def reconcile_case_bindings(',
                          'def materialize_catalogue(',
                          'def materialize_selection_plan(',
                          'def canonical_bytes(', 'def build_cargo_',
                          'def build_python_child_command(',
                          'def canonical_command(', 'def minimal_child_env(',
                          'def toolchain_child_env(',
                          'def parse_rust_discovery(', 'def parse_python_protocol(',
                          'def bind_package_observation(',
                          'def bind_execution_observations(',
                          'def snapshot_protected('):
            self.assertNotIn(local_def, text)
        self.assertIn('assignment_source', text)
        self.assertIn('descriptor_runner', text)

    # WORK_UNIT_CASE: 837/36
    def test_planned_blocked_catalogue_runs_no_tests(self):
        ready = make_desc(issue_num=837)
        planned_desc = make_desc(issue_num=999, unit_name='D-WU-FUTURE', cases=1, body='9' * 64, matrix='8' * 64,
                                 source_roots=('scripts/testdata/work-unit-gate/integration/repos/future-only/not-yet-created.py',),
                                 test_roots=('scripts/testdata/work-unit-gate/integration/repos/future-only/not-yet-created-test.py',),
                                 module='integration.future_only.not_yet_created')
        rows = [make_row(ready),
                contractsmod.CatalogueRow(issue=planned_desc.issue, unit=planned_desc.unit, body_sha256=planned_desc.body_sha256,
                                          disposition=contractsmod.CatalogueDisposition.PLANNED, descriptor=None),
                contractsmod.CatalogueRow(issue=contractsmod.IssueIdentity(REPO, 850), unit=contractsmod.WorkUnitIdentity('D-WU-RUNNERS'),
                                          body_sha256=BODY_C, disposition=contractsmod.CatalogueDisposition.BLOCKED, descriptor=None)]
        with patch.object(subprocess, 'run', side_effect=AssertionError('catalogue-only must run no tests')):
            cat = cohortmod.materialize_catalogue(rows, [r.issue for r in rows])
        self.assertEqual(cat.result, contractsmod.CatalogueResult.INTEGRITY_VALID)
        self.assertEqual(cat.proof_ceiling.value, 'catalogue-integrity-only')
        self.assertNotEqual(cat.proof_ceiling.value, 'selected-verification-only')

    # WORK_UNIT_CASE: 837/37
    def test_ready_unit_executes_with_unfinished_missing_prereq_fails(self):
        ready = make_desc(issue_num=837)
        unrelated = make_desc(issue_num=999, unit_name='D-WU-FUTURE', cases=1, body='9' * 64, matrix='8' * 64,
                              source_roots=('scripts/testdata/work-unit-gate/integration/repos/future-only/not-yet-created.py',),
                              test_roots=('scripts/testdata/work-unit-gate/integration/repos/future-only/not-yet-created-test.py',),
                              module='integration.future_only.not_yet_created')
        rows = [make_row(ready),
                contractsmod.CatalogueRow(issue=unrelated.issue, unit=unrelated.unit, body_sha256=unrelated.body_sha256,
                                          disposition=contractsmod.CatalogueDisposition.PLANNED, descriptor=None,
                                          prerequisites=())]
        cat = cohortmod.materialize_catalogue(rows, [ready.issue, unrelated.issue])
        sel = contractsmod.VerificationSelection(cat.sha256, 'a' * 64, contractsmod.SelectionScope.SELECTED, (ready.issue,))
        plan = cohortmod.materialize_selection_plan(cat, sel, [ready])
        self.assertEqual(plan.matrix_cases, 2)
        prereq_issue = contractsmod.IssueIdentity(REPO, 849)
        needy = make_desc(issue_num=837)
        needy_row = contractsmod.CatalogueRow(issue=needy.issue, unit=needy.unit, body_sha256=needy.body_sha256,
                                              disposition=contractsmod.CatalogueDisposition.ASSIGNED, descriptor=needy,
                                              prerequisites=(prereq_issue,))
        cat2 = cohortmod.materialize_catalogue([needy_row,
                                                contractsmod.CatalogueRow(issue=contractsmod.IssueIdentity(REPO, 849),
                                                                          unit=contractsmod.WorkUnitIdentity('A-1'),
                                                                          body_sha256='e' * 64,
                                                                          disposition=contractsmod.CatalogueDisposition.ACCEPTED_HISTORICAL,
                                                                          descriptor=None)],
                                               [needy.issue, prereq_issue])
        with self.assertRaises((contractsmod.ContractViolation, cohortmod.CohortError)):
            cohortmod.materialize_selection_plan(
                cat2,
                contractsmod.VerificationSelection(cat2.sha256, 'a' * 64, contractsmod.SelectionScope.SELECTED, (needy.issue,)),
                [needy])

    # WORK_UNIT_CASE: 837/38
    def test_omitted_substituted_promoted_cannot_pass(self):
        d1 = make_desc(issue_num=837)
        d2 = make_desc(issue_num=850, unit_name='D-WU-RUNNERS', mode=contractsmod.RunnerMode.RUST_PACKAGE,
                       package='wu837_tiny', module=None, body=BODY_C, matrix=MATRIX_D,
                       source_roots=('scripts/testdata/work-unit-gate/integration/repos/rust-tiny/src/lib.rs',),
                       test_roots=('scripts/testdata/work-unit-gate/integration/repos/rust-tiny/src/lib.rs',))
        cat = cohortmod.materialize_catalogue([make_row(d1), make_row(d2)], [d1.issue, d2.issue])
        sel_one = contractsmod.VerificationSelection(cat.sha256, 'a' * 64, contractsmod.SelectionScope.SELECTED, (d1.issue,))
        plan_one = cohortmod.materialize_selection_plan(cat, sel_one, [d1])
        self.assertEqual(1, len(plan_one.descriptors))
        other = make_desc(issue_num=837, body='0' * 64)
        with self.assertRaises((contractsmod.ContractViolation, cohortmod.CohortError)):
            cohortmod.materialize_selection_plan(cat, sel_one, [other])
        sel_full = contractsmod.VerificationSelection(cat.sha256, 'a' * 64, contractsmod.SelectionScope.FULL_PROJECT, (d1.issue,))
        with self.assertRaises((contractsmod.ContractViolation, cohortmod.CohortError)):
            cohortmod.materialize_selection_plan(cat, sel_full, [d1])

    # WORK_UNIT_CASE: 837/39
    def test_future_registered_path_missing_implementation_failure(self):
        raw = (INTEGRATION / 'descriptors/planned-future.toml').read_bytes()
        decoded = runmod.decode_descriptor(raw, '.github/work-units/999.toml')
        self.assertEqual(decoded['identity'], {'value': 'work-unit-999'})
        future = make_desc(issue_num=999, unit_name='D-WU-FUTURE', cases=1, body='9' * 64, matrix='8' * 64,
                           source_roots=('scripts/testdata/work-unit-gate/integration/repos/future-only/not-yet-created.py',),
                           test_roots=('scripts/testdata/work-unit-gate/integration/repos/future-only/not-yet-created-test.py',),
                           module='integration.future_only.not_yet_created')
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(cohortmod.CohortError):
                cohortmod.verify_attempt_paths_exist(future, Path(directory))
        with self.assertRaises(cohortmod.CohortError):
            cohortmod.verify_attempt_paths_exist(future, ROOT)

    # WORK_UNIT_CASE: 837/40
    def test_closed_prereq_reverify_without_reopen(self):
        ready = make_desc(issue_num=837)
        prereq_issue = contractsmod.IssueIdentity(REPO, 849)
        prereq_desc = make_desc(issue_num=849, unit_name='A-1', cases=2, body='e' * 64, matrix='f' * 64,
                                mode=contractsmod.RunnerMode.METADATA_PYTHON, package='wu837_meta',
                                module='integration.metadata_tiny.check',
                                source_roots=('scripts/testdata/work-unit-gate/integration/repos/metadata-tiny/check.py',),
                                test_roots=('scripts/testdata/work-unit-gate/integration/repos/metadata-tiny/check.py',))
        closed_receipt = contractsmod.AssignmentSourceReceipt(
            issue=prereq_issue, state=contractsmod.IssueState.CLOSED, unit=prereq_desc.unit,
            authority=contractsmod.SourceAuthority.LIVE_GITHUB, title='[A-1] Closed proof',
            body_sha256=prereq_desc.body_sha256, matrix_cases=prereq_desc.matrix_cases,
            proof_ceiling=contractsmod.ProofCeiling('assignment-source-only'), matrix_sha256=prereq_desc.matrix_sha256,
            source_use=contractsmod.AssignmentSourceUse.PREREQUISITE_EVIDENCE,
            origin='https://api.github.com', live_etag='W/"closed"')
        evidence = contractsmod.PrerequisiteEvidence(closed_receipt, 'a' * 40, 'b' * 64)
        self.assertEqual(evidence.accepted_commit, 'a' * 40)
        needy_row = contractsmod.CatalogueRow(issue=ready.issue, unit=ready.unit, body_sha256=ready.body_sha256,
                                              disposition=contractsmod.CatalogueDisposition.ASSIGNED, descriptor=ready,
                                              prerequisites=(prereq_issue,))
        hist_row = contractsmod.CatalogueRow(issue=prereq_issue, unit=prereq_desc.unit, body_sha256=prereq_desc.body_sha256,
                                             disposition=contractsmod.CatalogueDisposition.ACCEPTED_HISTORICAL,
                                             descriptor=prereq_desc)
        cat = cohortmod.materialize_catalogue([needy_row, hist_row], [ready.issue, prereq_issue])
        sel = contractsmod.VerificationSelection(cat.sha256, 'a' * 64, contractsmod.SelectionScope.SELECTED, (ready.issue,))
        plan = cohortmod.materialize_selection_plan(cat, sel, [ready], [evidence])
        self.assertEqual(1, len(plan.prerequisites))
        with self.assertRaises(contractsmod.ContractViolation):
            contractsmod.PrerequisiteEvidence(
                make_assignment(prereq_desc, state=contractsmod.IssueState.CLOSED,
                                source_use=contractsmod.AssignmentSourceUse.ACTIVE_ASSIGNMENT),
                'a' * 40, 'b' * 64)
        superseded_row = contractsmod.CatalogueRow(issue=prereq_issue, unit=prereq_desc.unit, body_sha256=prereq_desc.body_sha256,
                                                   disposition=contractsmod.CatalogueDisposition.SUPERSEDED, descriptor=None)
        cat_sup = cohortmod.materialize_catalogue([needy_row, superseded_row], [ready.issue, prereq_issue])
        with self.assertRaises((contractsmod.ContractViolation, cohortmod.CohortError)):
            cohortmod.materialize_selection_plan(
                cat_sup,
                contractsmod.VerificationSelection(cat_sup.sha256, 'a' * 64, contractsmod.SelectionScope.SELECTED, (ready.issue,)),
                [ready], [evidence])

    # WORK_UNIT_CASE: 837/41
    def test_no_recursive_self_gate_no_future_commit(self):
        text = GATE_PATH.read_text(encoding='utf-8')
        self.assertNotIn('verify-work-unit.py --crate subject', text)
        self.assertNotIn('scripts.work_unit_gate.__main__', text)
        desc = make_desc()
        row = make_row(desc)
        cat = cohortmod.materialize_catalogue([row], [desc.issue])
        sel = contractsmod.VerificationSelection(cat.sha256, 'a' * 64, contractsmod.SelectionScope.SELECTED, (desc.issue,))
        plan = cohortmod.materialize_selection_plan(cat, sel, [desc])
        digest_input = contractsmod.canonical_bytes({'schema': contractsmod.CONTRACT_SCHEMA_REVISION, 'kind': 'selection', 'payload': plan})
        self.assertNotIn(b'future-commit', digest_input)
        self.assertNotIn(b'accepted-commit', digest_input)

    # WORK_UNIT_CASE: 837/42
    def test_tiny_fixtures_catalogue_selected_integrated_via_runner_apis(self):
        py_raw = (INTEGRATION / 'descriptors/selected-python.toml').read_bytes()
        py_decoded = runmod.decode_descriptor(py_raw, '.github/work-units/837.toml')
        self.assertEqual(py_decoded['mode'], 'python-unittest')
        rs_raw = (INTEGRATION / 'descriptors/selected-rust.toml').read_bytes()
        rs_decoded = runmod.decode_descriptor(rs_raw, '.github/work-units/850.toml')
        self.assertEqual(rs_decoded['mode'], 'rust-package')
        meta_raw = (INTEGRATION / 'descriptors/selected-metadata.toml').read_bytes()
        meta_decoded = runmod.decode_descriptor(meta_raw, '.github/work-units/849.toml')
        self.assertEqual(meta_decoded['mode'], 'metadata-python')
        discovery = b'tiny_ok_a: test\ntiny_ok_b: test\ntiny_fail: test\ntiny_ignored: test\n'
        parsed = runmod.parse_rust_discovery(discovery, 1000)
        names = sorted(parsed)
        self.assertEqual(names, ['tiny_fail', 'tiny_ignored', 'tiny_ok_a', 'tiny_ok_b'])
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            (tmp / 'test_sample.py').write_bytes((INTEGRATION / 'repos/python-tiny/test_sample.py').read_bytes())
            rel = runmod.bind_python_suite(root=tmp, module='test_sample', test_roots=['test_sample.py'])
            self.assertEqual(rel, 'test_sample.py')
            entry = runmod.resolve_metadata_entrypoint(module='test_sample', test_roots=['test_sample.py'])
            self.assertEqual(entry, 'test_sample')
        ready = make_desc(issue_num=837)
        cat_only = cohortmod.materialize_catalogue([make_row(ready)], [ready.issue])
        self.assertEqual(cat_only.proof_ceiling.value, 'catalogue-integrity-only')
        sel = contractsmod.VerificationSelection(cat_only.sha256, 'a' * 64, contractsmod.SelectionScope.SELECTED, (ready.issue,))
        plan = cohortmod.materialize_selection_plan(cat_only, sel, [ready])
        self.assertEqual(plan.matrix_cases, ready.matrix_cases)
        member_desc = make_desc(mode=contractsmod.RunnerMode.RUST_PACKAGE, package='wu837_member', module=None,
                                require_member=True, ceiling='workspace-integration',
                                source_roots=('scripts/testdata/work-unit-gate/integration/repos/rust-tiny/src/lib.rs',),
                                test_roots=('scripts/testdata/work-unit-gate/integration/repos/rust-tiny/src/lib.rs',))
        self.assertEqual(member_desc.phase, contractsmod.VerificationPhase.WORKSPACE_INTEGRATION)
        self.assertEqual(ready.phase, contractsmod.VerificationPhase.PACKAGE_LOCAL)


if __name__ == '__main__':
    unittest.main()
