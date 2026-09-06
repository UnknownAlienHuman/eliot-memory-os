"""Incremental #850 tests; no claim of OS containment or complete runner.

The child smoke tests launch only generated, trusted synthetic Python code on
POSIX. Their use of subprocess is test provisioning, NOT a production backend.
Current v4 constructors are tested directly. Cargo/Windows acceptance remains separate.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/work_unit_gate/descriptor_runner.py'
from scripts.work_unit_gate import descriptor_runner as r
from scripts.work_unit_gate import contracts as c

VALID = '''schema_version = "eliot-work-unit-descriptor-v2"
identity = {value = "work-unit-850"}
issue = {repository = {owner = "UnknownAlienHuman", name = "eliot-memory-os"}, number = 850}
unit = {value = "D-WU-RUNNERS"}
mode = "python-unittest"
source_roots = [{value = "scripts/work_unit_gate/descriptor_runner.py"}]
test_roots = [{value = "scripts/tests/test_work_unit_descriptor_runner.py"}]
matrix_cases = 44
proof_ceiling = {value = "package-local"}
revision = 1
body_sha256 = "BODY"
matrix_sha256 = "MATRIX"
require_workspace_member = false
package = {name = "runner"}
module = {value = "scripts.tests.test_work_unit_descriptor_runner"}
requirements = {source_floor = 1, public_floor = 1, test_floor = 44, required_guards = [{value = "bounded"}]}
bounds = {wall_ms = 10000, idle_ms = 5000, output_bytes = 65536, line_bytes = 4096, discovery_tests = 1000, child_processes = 4}
'''.replace('BODY', 'a'*64).replace('MATRIX', 'b'*64).encode()
FILENAME = '.github/work-units/850.toml'


class CodecTests(unittest.TestCase):
    def rejected(self, raw, filename=FILENAME):
        with self.assertRaises(r.RunnerInputError):
            r.decode_descriptor(raw, filename)

    def test_minimal_descriptor_modes(self):
        for mode in sorted(r.MODES):
            data = r.decode_descriptor(VALID.replace(b'python-unittest', mode.encode()), FILENAME)
            self.assertEqual(mode, data['mode'])
            self.assertEqual(44, data['matrix_cases'])

    def test_unknown_schema_and_mode(self):
        self.rejected(VALID.replace(b'descriptor-v2', b'descriptor-v1'))
        self.rejected(VALID.replace(b'python-unittest', b'powershell'))
        self.rejected(VALID.replace(b'mode = "python-unittest"', b'mode = ["python-unittest"]'))

    def test_closed_fields_all_command_escape_hatches(self):
        for key in ('command', 'argv', 'executable', 'shell', 'url', 'network_origin', 'environment', 'secret', 'credential', 'working_directory', 'output_path'):
            with self.subTest(key=key):
                self.rejected(VALID + f'{key} = "CANARY"\n'.encode())

    def test_exact_filename_and_issue(self):
        for path in ('850.toml', '.github/work-units/851.toml', '.github/work-units/0850.toml', '/.github/work-units/850.toml'):
            self.rejected(VALID, path)
        self.rejected(VALID.replace(b'number = 850', b'number = 851'))
        self.rejected(VALID.replace(b'work-unit-850', b'work-unit-851'))

    def test_missing_duplicate_roots(self):
        self.rejected(VALID.replace(b'source_roots = [{value = "scripts/work_unit_gate/descriptor_runner.py"}]', b'source_roots = []'))
        self.rejected(VALID + b'source_roots = []\n')
        self.rejected(VALID.replace(b'[{value = "scripts/work_unit_gate/descriptor_runner.py"}]', b'[{value = "scripts/a.py"}, {value = "scripts/a.py"}]'))

    def test_root_shapes(self):
        for value in (b'["scripts/a.py"]', b'[{path = "scripts/a.py"}]', b'false', b'[{value = 1}]'):
            self.rejected(VALID.replace(b'[{value = "scripts/work_unit_gate/descriptor_runner.py"}]', value))

    def test_absolute_traversal_wildcard_alias_roots(self):
        for path in ('/tmp/a', 'C:/a', '//host/a', 'scripts/../a', 'scripts/./a', 'scripts//a', 'scripts/a/', 'scripts/**', 'scripts/[x].py', 'scripts', '.', 'scripts/a:stream'):
            with self.subTest(path=path):
                self.rejected(VALID.replace(b'scripts/work_unit_gate/descriptor_runner.py', path.encode()))

    def test_percent_is_literal(self):
        data = r.decode_descriptor(VALID.replace(b'scripts/work_unit_gate/descriptor_runner.py', b'scripts/%2e%2e%2fa.py'), FILENAME)
        self.assertEqual('scripts/%2e%2e%2fa.py', data['source_roots'][0]['value'])

    def test_physical_links_and_missing_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'real').mkdir()
            (root/'real/a').write_text('x')
            self.assertEqual(root/'real/a', r._safe_path(root, 'real/a'))
            (root/'alias').symlink_to(root/'real', target_is_directory=True)
            for path in ('alias/a', 'missing/a'):
                with self.assertRaises(r.RunnerInputError): r._safe_path(root, path)

    def test_time_output_and_discovery_bounds(self):
        for key in ('wall_ms', 'idle_ms', 'output_bytes', 'line_bytes', 'discovery_tests', 'child_processes'):
            import re
            for bad in ('0', '-1', 'true', '9999999999999999'):
                self.rejected(re.sub(fr'{key} = [0-9]+'.encode(), f'{key} = {bad}'.encode(), VALID))
        self.rejected(VALID.replace(b'idle_ms = 5000', b'idle_ms = 10001'))
        self.rejected(VALID.replace(b'line_bytes = 4096', b'line_bytes = 65537'))
        self.rejected(VALID.replace(b'discovery_tests = 1000', b'discovery_tests = 43'))

    def test_floors_and_guards(self):
        self.rejected(VALID.replace(b'test_floor = 44', b'test_floor = 43'))
        self.rejected(VALID.replace(b'source_floor = 1', b'source_floor = -1'))
        self.rejected(VALID.replace(b'[{value = "bounded"}]', b'[{value = "bounded"},{value = "bounded"}]'))

    def test_identity_fields_and_bindings_are_required(self):
        for line in (b'body_sha256', b'matrix_sha256', b'unit', b'identity', b'issue'):
            self.rejected(b'\n'.join(l for l in VALID.splitlines() if not l.startswith(line + b' =')))
        self.rejected(VALID.replace(b'a'*64, b'not-a-digest'))
        self.rejected(VALID.replace(b'require_workspace_member = false', b'require_workspace_member = 0'))

    def test_pinned_layout_rejects_malformed_input(self):
        for raw in (b'', b'\xff', b'['*1000, b' '*65537, VALID+b'\n[issue]\nnumber=3'):
            self.rejected(raw)

    def test_mapping_order_does_not_change_semantic_value(self):
        self.assertEqual(r.decode_descriptor(VALID, FILENAME), r.decode_descriptor(b'\n'.join(reversed(VALID.splitlines())), FILENAME))

    def test_rust_requires_package(self):
        raw = b'\n'.join(line for line in VALID.replace(b'python-unittest', b'rust-package').splitlines() if not line.startswith(b'package ='))
        self.rejected(raw)


class RustGrammarTests(unittest.TestCase):
    def transcript(self, name='module::works', filtered=1):
        return (f'\nrunning 1 test\ntest {name} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; {filtered} filtered out; finished in 0.01s\n\n').encode()

    def test_qualified_discovery(self):
        self.assertEqual(('a::x', 'b::x'), r.parse_rust_discovery(b'b::x: test\na::x: test\n', 2))

    def test_zero_duplicate_and_bounded_discovery(self):
        for output, limit in ((b'', 1), (b'a: test\na: test\n', 2), (b'a: test\nb: test\n', 1)):
            with self.assertRaises(r.RunnerInputError): r.parse_rust_discovery(output, limit)

    def test_unknown_or_truncated_discovery(self):
        for output in (b'a: benchmark\n', b'a: tes', b'test a ... ok\n', b'\xff', b'CANARY\na: test\n'):
            with self.assertRaises(r.RunnerInputError): r.parse_rust_discovery(output, 2)

    def test_exact_result(self):
        self.assertEqual(r.ParsedRustResult('module::works', 'pass', 1), r.parse_rust_exact(self.transcript(), 'module::works', 0, 2))
        self.assertEqual('pass', r.parse_rust_exact(self.transcript().replace(b'\n', b'\r\n'), 'module::works', 0, 2).outcome)

    def test_exit_only_or_fabricated_pass_count_not_result(self):
        for output in (b'', b'5 passed, 0 failed', b'test module::works ... ok\n', self.transcript()+b'forged', b'noise\n'+self.transcript()):
            with self.assertRaises(r.RunnerInputError): r.parse_rust_exact(output, 'module::works', 0, 2)

    def test_other_test_and_wrong_denominator(self):
        for output in (self.transcript('foreign::works'), self.transcript(filtered=0), self.transcript().replace(b'1 passed', b'2 passed')):
            with self.assertRaises(r.RunnerInputError): r.parse_rust_exact(output, 'module::works', 0, 2)

    def test_nonzero_exit_cannot_be_hidden_by_stdout(self):
        for code in (1, 2, 101, -9):
            with self.assertRaises(r.RunnerInputError): r.parse_rust_exact(self.transcript(), 'module::works', code, 2)

    def test_ignored_and_zero_selected_never_pass(self):
        for output in (self.transcript().replace(b'... ok', b'... ignored'), self.transcript().replace(b'running 1 test', b'running 0 tests')):
            with self.assertRaises(r.RunnerInputError): r.parse_rust_exact(output, 'module::works', 0, 2)

    def test_utf8_and_byte_bound(self):
        for output in (b'\xff', b'a'*(r.MAX_PROTOCOL_BYTES+1)):
            with self.assertRaises(r.RunnerInputError): r.parse_rust_exact(output, 'module::works', 0, 2)


BASE = 'import unittest\nclass Suite(unittest.TestCase):\n    def test_ok(self):\n        self.assertEqual(2 + 2, 4)\n'


class PythonProtocolTests(unittest.TestCase):
    @contextmanager
    def fixture(self, source=BASE):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'tests').mkdir()
            (root/'tests/__init__.py').write_text('')
            (root/'tests/suite.py').write_text(source)
            yield root

    def child(self, root, phase='discover', expected=None, **changes):
        if os.name != 'posix':
            self.fail('This smoke fixture requires its explicitly selected POSIX test environment; no Windows claim.')
        source = root/'tests/suite.py'
        req = dict(schema=r.PYTHON_PROTOCOL, phase=phase, root=str(root), module='tests.suite', source='tests/suite.py', source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), max_tests=100, expected=expected or [])
        req.update(changes)
        raw = json.dumps(req, sort_keys=True).encode()
        with tempfile.TemporaryFile() as protocol:
            observed = subprocess.run([sys.executable, '-I', '-B', str(SCRIPT), '--_python-child', str(protocol.fileno())], input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(protocol.fileno(),), timeout=5,
                                      env={'PATH': os.defpath, 'PYTHONDONTWRITEBYTECODE': '1'}, cwd=root)
            protocol.seek(0)
            body = protocol.read(r.MAX_PROTOCOL_BYTES+1)
        data = r.parse_python_protocol(body, request_sha256=hashlib.sha256(raw).hexdigest(), expected_module=req["module"], expected_source_sha256=req["source_sha256"], expected_phase=phase, expected_discovery=req["expected"] if phase == "execute" else None) if body else None
        return observed, data, body, req

    def discover_execute(self, root):
        first = self.child(root)
        self.assertEqual(0, first[0].returncode, first[0].stderr)
        return self.child(root, 'execute', first[1]['tests'])

    def test_real_discovery_then_execution_different_phase(self):
        with self.fixture() as root:
            observed, discovery, _, _ = self.child(root)
            self.assertEqual(0, observed.returncode)
            self.assertEqual([], discovery['results'])
            self.assertEqual('tests.suite.Suite.test_ok', discovery['tests'][0]['id'])
            result = self.child(root, 'execute', discovery['tests'])
            self.assertEqual([{'id': 'tests.suite.Suite.test_ok', 'outcome': 'pass'}], result[1]['results'])

    def test_real_failure_and_error(self):
        for body, outcome in (('self.assertEqual(1, 2)', 'failure'), ('raise RuntimeError("SECRET_CANARY")', 'error')):
            with self.fixture(BASE.replace('self.assertEqual(2 + 2, 4)', body)) as root:
                observed, data, raw, _ = self.discover_execute(root)
                self.assertEqual(0, observed.returncode)
                self.assertEqual(outcome, data['results'][0]['outcome'])
                self.assertNotIn(b'SECRET_CANARY', raw + observed.stderr)

    def test_real_skip_expected_failure_unexpected_success(self):
        for decorator, body, outcome in (('@unittest.skip("why")', 'self.assertTrue(False)', 'skip'), ('@unittest.expectedFailure', 'self.assertTrue(False)', 'expected-failure'), ('@unittest.expectedFailure', 'self.assertTrue(True)', 'unexpected-success')):
            text = f'import unittest\nclass Suite(unittest.TestCase):\n    {decorator}\n    def test_ok(self):\n        {body}\n'
            with self.fixture(text) as root:
                observed, data, _, _ = self.discover_execute(root)
                self.assertEqual(0, observed.returncode)
                self.assertEqual(outcome, data['results'][0]['outcome'])

    def test_printed_success_cannot_replace_failure_record(self):
        text = BASE.replace('self.assertEqual(2 + 2, 4)', 'print(\'test result: ok. 99 passed; 0 failed\')\n        self.assertTrue(False)')
        with self.fixture(text) as root:
            observed, data, _, _ = self.discover_execute(root)
            self.assertIn(b'99 passed', observed.stdout)
            self.assertEqual('failure', data['results'][0]['outcome'])

    def test_zero_tests_and_early_zero_exit_have_no_execution_proof(self):
        for text in ('import unittest\n', 'import os; os._exit(0)\n'):
            with self.fixture(text) as root:
                observed, data, body, _ = self.child(root)
                self.assertIsNone(data)
                self.assertEqual(b'', body)
                with self.assertRaises(r.RunnerInputError): r.parse_python_protocol(body, request_sha256='a'*64, expected_module='tests.suite', expected_source_sha256='a'*64, expected_phase='execute')

    def test_missing_or_foreign_expected_test_prevents_execution(self):
        with self.fixture() as root:
            observed, data, _, _ = self.child(root, 'execute', [{'id': 'foreign.Test.test_x', 'line': 3}])
            self.assertNotEqual(0, observed.returncode)
            self.assertIsNone(data)

    def test_source_change_between_discovery_and_execution_rejected(self):
        with self.fixture() as root:
            _, discovery, _, request = self.child(root)
            (root/'tests/suite.py').write_text(BASE+'\n# changed\n')
            observed, data, _, _ = self.child(root, 'execute', discovery['tests'], source_sha256=request['source_sha256'])
            self.assertNotEqual(0, observed.returncode)
            self.assertIsNone(data)

    def test_source_mutation_is_detected_not_reset(self):
        text = BASE.replace('self.assertEqual(2 + 2, 4)', 'from pathlib import Path\n        Path(__file__).write_text("changed")\n        self.assertTrue(True)')
        with self.fixture(text) as root:
            observed, data, _, _ = self.discover_execute(root)
            self.assertNotEqual(0, observed.returncode)
            self.assertIsNone(data)
            self.assertEqual('changed', (root/'tests/suite.py').read_text())

    def test_custom_run_refused_instead_of_simulated_success(self):
        text = BASE+'    def run(self, result):\n        return None\n'
        with self.fixture(text) as root:
            observed, data, _, _ = self.child(root)
            self.assertNotEqual(0, observed.returncode)
            self.assertIsNone(data)

    def test_test_bound(self):
        with self.fixture(BASE+'    def test_two(self):\n        self.assertTrue(True)\n') as root:
            observed, data, _, _ = self.child(root, max_tests=1)
            self.assertNotEqual(0, observed.returncode)
            self.assertIsNone(data)

    def test_protocol_unknown_duplicate_fields_and_wrong_nonce(self):
        with self.fixture() as root:
            _, data, raw, request = self.child(root)
            digest = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
            for altered in (raw[:-1]+b',"schema":"duplicate"}', raw[:-1]+b',"secret":"CANARY"}', raw[:-1], b'\xff'):
                with self.assertRaises(r.RunnerInputError) as error: r.parse_python_protocol(altered, request_sha256=digest, expected_module=request["module"], expected_source_sha256=request["source_sha256"], expected_phase=request["phase"], expected_discovery=request["expected"])
                self.assertNotIn('CANARY', str(error.exception))
            with self.assertRaises(r.RunnerInputError): r.parse_python_protocol(raw, request_sha256='f'*64, expected_module=request['module'], expected_source_sha256=request['source_sha256'], expected_phase=request['phase'])

    def test_protocol_foreign_missing_duplicate_terminal(self):
        with self.fixture() as root:
            _, data, _, request = self.discover_execute(root)
            digest = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
            for rows in ([], [data['results'][0]]*2, [{'id': 'foreign.Test.x', 'outcome': 'pass'}], [{'id': data['results'][0]['id'], 'outcome': 'success'}]):
                with self.assertRaises(r.RunnerInputError): r.parse_python_protocol(json.dumps(data|{'results': rows}).encode(), request_sha256=digest, expected_module=request["module"], expected_source_sha256=request["source_sha256"], expected_phase=request["phase"], expected_discovery=request["expected"])

    def test_discovery_cannot_contain_execution_results(self):
        with self.fixture() as root:
            _, data, _, request = self.child(root)
            digest = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
            data['results'] = [{'id': data['tests'][0]['id'], 'outcome': 'pass'}]
            with self.assertRaises(r.RunnerInputError): r.parse_python_protocol(json.dumps(data).encode(), request_sha256=digest, expected_module=request["module"], expected_source_sha256=request["source_sha256"], expected_phase=request["phase"], expected_discovery=request["expected"])

    def test_test_code_runs_only_in_child_not_parent(self):
        text = BASE.replace('import unittest', 'import unittest, os\nprint("child_pid=" + str(os.getpid()))')
        with self.fixture(text) as root:
            observed, data, _, _ = self.child(root)
            self.assertNotIn('tests.suite', sys.modules)
            self.assertNotIn(f'child_pid={os.getpid()}\n'.encode(), observed.stdout)
            self.assertIsNotNone(data)

    def test_secrets_not_in_minimal_test_environment(self):
        text = BASE.replace('self.assertEqual(2 + 2, 4)', 'import os\n        self.assertNotIn("GH_TOKEN", os.environ)')
        old = os.environ.get('GH_TOKEN')
        os.environ['GH_TOKEN'] = 'CANARY'
        try:
            with self.fixture(text) as root:
                self.assertEqual('pass', self.discover_execute(root)[1]['results'][0]['outcome'])
        finally:
            if old is None: os.environ.pop('GH_TOKEN')
            else: os.environ['GH_TOKEN'] = old

    def test_json_depth_and_nonfinite_values_are_bounded(self):
        for raw in (b'['*33+b'0'+b']'*33, b'{"x":NaN}', b'{"x":1,"\\u0078":2}'):
            with self.assertRaises(r.RunnerInputError): r._bounded_json(raw)

    def test_protocol_requires_expected_source_module_and_discovery(self):
        with self.fixture() as root:
            _, data, raw, request = self.discover_execute(root)
            kwargs = dict(request_sha256=hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest(),
                          expected_module=request['module'], expected_source_sha256=request['source_sha256'], expected_phase=request['phase'],
                          expected_discovery=request['expected'])
            for change in ({'expected_source_sha256': 'f'*64}, {'expected_module': 'foreign'},
                           {'expected_discovery': None}, {'expected_discovery': []}):
                with self.assertRaises(r.RunnerInputError): r.parse_python_protocol(raw, **(kwargs|change))
            bad = dict(data, results=[{'id': data['tests'][0]['id'], 'outcome': ['pass']}])
            with self.assertRaises(r.RunnerInputError): r.parse_python_protocol(json.dumps(bad).encode(), **kwargs)

    def test_source_has_no_production_spawn_or_shell(self):
        tree = ast.parse(SCRIPT.read_text())
        imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        self.assertTrue(imports.isdisjoint({'subprocess', 'requests', 'socket', 'ctypes'}))
        self.assertNotIn('eval(', SCRIPT.read_text())
        self.assertNotIn('exec(', SCRIPT.read_text())


class DescriptorBindingTests(unittest.TestCase):
    def assignment(self, **changes):
        import dataclasses
        issue = c.IssueIdentity(c.RepositoryIdentity("UnknownAlienHuman", "eliot-memory-os"), 850)
        value = c.AssignmentSourceReceipt(
            issue=issue, state=c.IssueState.OPEN, unit=c.WorkUnitIdentity("D-WU-RUNNERS"),
            authority=c.SourceAuthority.LIVE_GITHUB, title="fixture, not a live authorization",
            body_sha256="a" * 64, matrix_cases=44, proof_ceiling=c.ProofCeiling("assignment-source-only"),
            matrix_sha256="b" * 64, source_use=c.AssignmentSourceUse.ACTIVE_ASSIGNMENT,
            origin="https://api.github.com")
        return dataclasses.replace(value, **changes)

    def test_all_modes_construct_actual_v4_not_a_parallel_descriptor(self):
        for mode in c.RunnerMode:
            raw = VALID.replace(b"python-unittest", mode.value.encode())
            result = r.parse_descriptor(raw, FILENAME, self.assignment())
            self.assertIs(type(result), c.WorkUnitDescriptor)
            self.assertIs(result.mode, mode)
            self.assertEqual(result.sha256, c.canonical_sha256(result))

    def test_required_v4_assignment_body_matrix_and_owner_are_exact(self):
        variants = ({"body_sha256": "c" * 64}, {"matrix_sha256": "d" * 64},
                    {"matrix_cases": 43}, {"unit": c.WorkUnitIdentity("another-owner")},
                    {"issue": c.IssueIdentity(c.RepositoryIdentity("UnknownAlienHuman", "eliot-memory-os"), 851)})
        for change in variants:
            with self.subTest(field=next(iter(change))), self.assertRaises(r.RunnerInputError):
                r.parse_descriptor(VALID, FILENAME, self.assignment(**change))

    def test_missing_or_historical_assignment_cannot_authorize_execution(self):
        closed = self.assignment(state=c.IssueState.CLOSED, source_use=c.AssignmentSourceUse.PREREQUISITE_EVIDENCE)
        for value in (None, {}, closed):
            with self.assertRaises(r.RunnerInputError):
                r.parse_descriptor(VALID, FILENAME, value)

    def test_mapping_order_keeps_the_shared_canonical_digest(self):
        raw = b"\n".join(reversed(VALID.splitlines()))
        self.assertEqual(r.parse_descriptor(VALID, FILENAME, self.assignment()).sha256,
                         r.parse_descriptor(raw, FILENAME, self.assignment()).sha256)

    def test_package_local_and_workspace_requirements_change_identity(self):
        local = r.parse_descriptor(VALID, FILENAME, self.assignment())
        integrated = r.parse_descriptor(VALID.replace(b"require_workspace_member = false",
                                                    b"require_workspace_member = true"), FILENAME, self.assignment())
        self.assertIs(local.phase, c.VerificationPhase.PACKAGE_LOCAL)
        self.assertIs(integrated.phase, c.VerificationPhase.WORKSPACE_INTEGRATION)
        self.assertNotEqual(local.sha256, integrated.sha256)


class CurrentSourceExecutionTests(unittest.TestCase):
    # Reuse only provisioning helpers; do not inherit/recount the old tests.
    fixture = PythonProtocolTests.fixture
    child = PythonProtocolTests.child
    discover_execute = PythonProtocolTests.discover_execute

    def stale_cache(self, path, replacement):
        import py_compile
        original = path.stat()
        py_compile.compile(str(path), doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
        self.assertEqual(original.st_size, len(replacement.encode()))
        path.write_text(replacement)
        os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))

    def test_same_size_same_timestamp_cached_pass_does_not_replace_current_failing_test(self):
        with self.fixture() as root:
            self.stale_cache(root / "tests/suite.py", BASE.replace("2 + 2, 4", "2 + 2, 5"))
            observed, data, _, _ = self.discover_execute(root)
            self.assertEqual(0, observed.returncode)
            self.assertEqual("failure", data["results"][0]["outcome"])

    def test_repository_helper_also_executes_current_source_not_timestamp_cache(self):
        source = BASE.replace("self.assertEqual(2 + 2, 4)",
                              "from tests.helper import answer\n        self.assertEqual(answer(), 4)")
        with self.fixture(source) as root:
            helper = root / "tests/helper.py"
            helper.write_text("def answer():\n    return 4\n")
            self.stale_cache(helper, "def answer():\n    return 5\n")
            observed, data, _, _ = self.discover_execute(root)
            self.assertEqual(0, observed.returncode)
            self.assertEqual("failure", data["results"][0]["outcome"])

    def test_imported_helper_mutation_invalidates_result_without_reset(self):
        source = BASE.replace("self.assertEqual(2 + 2, 4)",
                              "from tests import helper\n        from pathlib import Path\n        Path(helper.__file__).write_text('changed')\n        self.assertTrue(True)")
        with self.fixture(source) as root:
            helper = root / "tests/helper.py"
            helper.write_text("VALUE = 1\n")
            observed, data, _, _ = self.discover_execute(root)
            self.assertNotEqual(0, observed.returncode)
            self.assertIsNone(data)
            self.assertEqual("changed", helper.read_text())

    def test_discovery_packet_cannot_be_accepted_as_execution_packet(self):
        with self.fixture() as root:
            _, data, raw, request = self.child(root)
            with self.assertRaisesRegex(r.RunnerInputError, "PROTOCOL_PHASE"):
                r.parse_python_protocol(raw,
                    request_sha256=hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest(),
                    expected_module=request["module"], expected_source_sha256=request["source_sha256"],
                    expected_phase="execute", expected_discovery=data["tests"])

    def test_sourceless_repository_bytecode_is_not_test_source(self):
        import py_compile
        source = BASE.replace("self.assertEqual(2 + 2, 4)",
                              "from tests.helper import answer\n        self.assertEqual(answer(), 4)")
        with self.fixture(source) as root:
            helper = root / "tests/helper.py"
            helper.write_text("def answer():\n    return 4\n")
            py_compile.compile(str(helper), cfile=str(helper.with_suffix(".pyc")), doraise=True)
            helper.unlink()
            observed, data, _, _ = self.discover_execute(root)
            # An import error is a nonpassing test result; bytecode cannot be used.
            self.assertTrue(observed.returncode != 0 or data["results"][0]["outcome"] != "pass")


if __name__ == '__main__':
    unittest.main()
