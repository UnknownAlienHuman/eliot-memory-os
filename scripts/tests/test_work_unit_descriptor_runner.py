"""Incremental #850 tests; no claim of complete runner.

The child tests launch only generated, trusted synthetic Python code plus the
checked-in tiny fixtures. Their use of subprocess is test provisioning, NOT a
production backend. The WindowsOwnedTree launcher above is a real owned-tree
test harness (Job Object with KILL_ON_JOB_CLOSE plus TerminateJobObject reap on
Windows, plain bounded subprocess on POSIX). Current v4 constructors are tested
directly.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/work_unit_gate/descriptor_runner.py'
from scripts.work_unit_gate import descriptor_runner as r
from scripts.work_unit_gate import contracts as c

FIXTURE_ROOT = ROOT / 'scripts/testdata/work-unit-gate/descriptor-runner'
DESCRIPTOR_DIR = FIXTURE_ROOT / 'descriptors'
RUST_TINY_DIR = FIXTURE_ROOT / 'rust-tiny'
RUST_TINY_MANIFEST = RUST_TINY_DIR / 'Cargo.toml'
PYTHON_TINY_DIR = FIXTURE_ROOT / 'python-tiny'


class WindowsOwnedTree:
    """Test-owned bounded owned-tree launcher (TEST FILE ONLY, never production).

    B2 reuse interface:
      launcher = WindowsOwnedTree(output_bytes=65536, line_bytes=4096)
      disp = launcher.run(argv, *, input_bytes=None, timeout=..., cwd=..., env=...)
    disp keys: argv, returncode, stdout (bytes), stderr (bytes), timed_out (bool),
      truncated (bool), truncate_reason (str), active_processes (int),
      total_processes (int), cleanup (str), cleanup_ok (bool).

    Windows: Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, Popen spawn,
    immediate AssignProcessToJobObject, timeout wait via communicate(),
    TerminateJobObject cleanup on timeout, zero-active-process verification via
    JobObjectBasicAccountingInformation (class 1). No kill-by-name, no PID reuse:
    only the owned Job handle is terminated/queried.
    POSIX: process-group leader + killpg + empty-group verification; same dict shape.

    Bounded capture is fail-closed: when stdout/stderr exceeds output_bytes or
    any line exceeds line_bytes, truncated=True and the caller must reject the
    output as proof (returncode is preserved for diagnostics only).

    Windows: the child is created SUSPENDED (CREATE_SUSPENDED), assigned to the
    Job before its first instruction runs, then its threads are resumed via a
    Toolhelp snapshot; breakaway is denied (the BREAKAWAY_OK limit is absent)
    so descendants cannot leave, and nested descendants inherit membership.
    Timeout/cancellation uses TerminateJobObject on the owned handle, then
    accounting must show zero active processes or cleanup is reported failed.
    POSIX: the child starts as a process-group leader (start_new_session) and
    timeout uses killpg + ESRCH verification of an empty group. Not a sandbox:
    only controller-admitted test source runs here, and a descendant that
    calls setsid(2) on POSIX would leave the owned group undetected -- the
    verdict covers the owned group/tree only.

    Residual honesty: unknown cleanup (failed queries, surviving members) is
    reported as cleanup-failed/cleanup_ok=False and never passes.
    """

    KILL_ON_JOB_CLOSE = 0x2000
    _CREATE_SUSPENDED = 0x00000004
    _TH32CS_SNAPTHREAD = 0x00000004
    _THREAD_SUSPEND_RESUME = 0x0002
    _JOB_EXTENDED = 9
    _JOB_BASIC_ACCOUNTING = 1
    _JOB_BASIC_ACCOUNTING_INFORMATION = 1

    class _THREADENTRY32(ctypes.Structure):
        _fields_ = [('dwSize', ctypes.c_uint32), ('cntUsage', ctypes.c_uint32),
                    ('th32ThreadID', ctypes.c_uint32), ('th32OwnerProcessID', ctypes.c_uint32),
                    ('tpBasePri', ctypes.c_long), ('tpDeltaPri', ctypes.c_long),
                    ('dwFlags', ctypes.c_uint32)]

    @staticmethod
    def _resume_threads(kernel32, pid):
        """Resume every thread of a suspended-created child. Raises on failure."""
        kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        kernel32.Thread32First.restype = ctypes.c_bool
        kernel32.Thread32Next.restype = ctypes.c_bool
        kernel32.OpenThread.restype = ctypes.c_void_p
        kernel32.OpenThread.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
        kernel32.ResumeThread.restype = ctypes.c_uint32
        kernel32.ResumeThread.argtypes = [ctypes.c_void_p]
        invalid = ctypes.c_void_p(-1).value
        snap = kernel32.CreateToolhelp32Snapshot(WindowsOwnedTree._TH32CS_SNAPTHREAD, 0)
        if not snap or snap == invalid:
            raise RuntimeError('CreateToolhelp32Snapshot failed')
        try:
            entry = WindowsOwnedTree._THREADENTRY32()
            entry.dwSize = ctypes.sizeof(WindowsOwnedTree._THREADENTRY32)
            resumed = 0
            ok = kernel32.Thread32First(snap, ctypes.byref(entry))
            while ok:
                if entry.th32OwnerProcessID == pid:
                    handle = kernel32.OpenThread(WindowsOwnedTree._THREAD_SUSPEND_RESUME, False,
                                                 entry.th32ThreadID)
                    if not handle:
                        raise RuntimeError('OpenThread failed')
                    try:
                        if kernel32.ResumeThread(handle) == 0xFFFFFFFF:
                            raise RuntimeError('ResumeThread failed')
                    finally:
                        kernel32.CloseHandle(handle)
                    resumed += 1
                ok = kernel32.Thread32Next(snap, ctypes.byref(entry))
            if resumed == 0:
                raise RuntimeError('no suspended threads resumed')
        finally:
            kernel32.CloseHandle(snap)

    def __init__(self, *, output_bytes=65536, line_bytes=4096):
        self.output_bytes = int(output_bytes)
        self.line_bytes = int(line_bytes)

    def _check_bounds(self, stdout: bytes, stderr: bytes):
        if len(stdout) > self.output_bytes or len(stderr) > self.output_bytes:
            return True, 'OUTPUT_BYTE_BOUND'
        for chunk in (stdout, stderr):
            for line in chunk.splitlines():
                if len(line) > self.line_bytes:
                    return True, 'LINE_BYTE_BOUND'
        return False, ''

    def _run_posix(self, argv, *, input_bytes, timeout, cwd, env):
        proc = subprocess.Popen(list(argv), stdin=subprocess.PIPE if input_bytes is not None else None,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, env=env,
                                start_new_session=True)
        timed_out = False
        try:
            out, err = proc.communicate(input=input_bytes, timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            try:
                out, err = proc.communicate(timeout=5)
            except Exception:
                out, err = b'', b''
            timed_out = True
        # Verify the owned process GROUP is empty (direct kill is not proof).
        active = -1
        cleanup = 'cleanup-failed'
        for _ in range(20):
            try:
                os.killpg(proc.pid, 0)
            except ProcessLookupError:
                active = 0
                cleanup = 'timeout-reaped' if timed_out else 'clean'
                break
            except (PermissionError, OSError):
                break
            time.sleep(0.1)
        truncated, reason = self._check_bounds(out or b'', err or b'')
        return {'argv': tuple(argv), 'returncode': proc.returncode, 'stdout': out or b'',
                'stderr': err or b'', 'timed_out': timed_out, 'truncated': truncated,
                'truncate_reason': reason, 'active_processes': active, 'total_processes': 1,
                'cleanup': cleanup, 'cleanup_ok': active == 0}

    def _run_windows(self, argv, *, input_bytes, timeout, cwd, env):
        kernel32 = ctypes.windll.kernel32
        try:
            kernel32.CreateJobObjectW.restype = ctypes.c_void_p
            kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            kernel32.SetInformationJobObject.restype = ctypes.c_bool
            kernel32.AssignProcessToJobObject.restype = ctypes.c_bool
            kernel32.TerminateJobObject.restype = ctypes.c_bool
            kernel32.QueryInformationJobObject.restype = ctypes.c_bool
            kernel32.CloseHandle.restype = ctypes.c_bool
        except Exception:
            pass

        class _IO(ctypes.Structure):
            _fields_ = [('ReadOperationCount', ctypes.c_uint64), ('WriteOperationCount', ctypes.c_uint64),
                        ('OtherOperationCount', ctypes.c_uint64), ('ReadTransferCount', ctypes.c_uint64),
                        ('WriteTransferCount', ctypes.c_uint64), ('OtherTransferCount', ctypes.c_uint64)]

        class _BASIC(ctypes.Structure):
            _fields_ = [('PerProcessUserTimeLimit', ctypes.c_int64), ('PerJobUserTimeLimit', ctypes.c_int64),
                        ('LimitFlags', ctypes.c_uint32), ('MinimumWorkingSetSize', ctypes.c_size_t),
                        ('MaximumWorkingSetSize', ctypes.c_size_t), ('ActiveProcessCount', ctypes.c_uint32),
                        ('Affinity', ctypes.c_size_t), ('PriorityClass', ctypes.c_uint32),
                        ('SchedulingClass', ctypes.c_uint32)]

        class _EXT(ctypes.Structure):
            _fields_ = [('BasicLimitInformation', _BASIC), ('IoInfo', _IO),
                        ('ProcessMemoryLimit', ctypes.c_size_t), ('JobMemoryLimit', ctypes.c_size_t),
                        ('PeakProcessMemoryUsed', ctypes.c_size_t), ('PeakJobMemoryUsed', ctypes.c_size_t)]

        class _ACC(ctypes.Structure):
            _fields_ = [('TotalUserTime', ctypes.c_int64), ('TotalKernelTime', ctypes.c_int64),
                        ('ThisPeriodTotalUserTime', ctypes.c_int64), ('ThisPeriodTotalKernelTime', ctypes.c_int64),
                        ('TotalPageFaultCount', ctypes.c_uint32), ('TotalProcesses', ctypes.c_uint32),
                        ('ActiveProcesses', ctypes.c_uint32), ('TotalTerminatedProcesses', ctypes.c_uint32)]

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            raise RuntimeError('CreateJobObjectW failed')
        try:
            ext = _EXT()
            ext.BasicLimitInformation.LimitFlags = self.KILL_ON_JOB_CLOSE
            if not kernel32.SetInformationJobObject(job, self._JOB_EXTENDED, ctypes.byref(ext), ctypes.sizeof(ext)):
                raise RuntimeError('SetInformationJobObject KILL_ON_JOB_CLOSE failed')
            proc = subprocess.Popen(list(argv), stdin=subprocess.PIPE if input_bytes is not None else None,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, env=env,
                                    creationflags=self._CREATE_SUSPENDED)
            try:
                assigned = kernel32.AssignProcessToJobObject(job, proc._handle)
                if not assigned:
                    proc.kill()
                    raise RuntimeError('AssignProcessToJobObject failed')
                try:
                    self._resume_threads(kernel32, proc.pid)
                except Exception:
                    kernel32.TerminateJobObject(job, 1)
                    try:
                        proc.wait(timeout=10)
                    except Exception:
                        pass
                    raise
                try:
                    out, err = proc.communicate(input=input_bytes, timeout=timeout)
                    timed_out = False
                    cleanup = 'clean'
                except subprocess.TimeoutExpired:
                    kernel32.TerminateJobObject(job, 1)
                    try:
                        out, err = proc.communicate(timeout=10)
                    except Exception:
                        out, err = b'', b''
                    timed_out = True
                    cleanup = 'timeout-reaped'
                out = out or b''
                err = err or b''
                truncated, reason = self._check_bounds(out, err)
                acc = _ACC()
                length = ctypes.c_uint32(0)
                active = total = -1
                if kernel32.QueryInformationJobObject(job, self._JOB_BASIC_ACCOUNTING_INFORMATION,
                                                      ctypes.byref(acc), ctypes.sizeof(acc), ctypes.byref(length)):
                    active, total = int(acc.ActiveProcesses), int(acc.TotalProcesses)
                else:
                    cleanup = 'cleanup-failed'
                if active != 0:
                    time.sleep(0.5)
                    if kernel32.QueryInformationJobObject(job, self._JOB_BASIC_ACCOUNTING_INFORMATION,
                                                          ctypes.byref(acc), ctypes.sizeof(acc), ctypes.byref(length)):
                        active, total = int(acc.ActiveProcesses), int(acc.TotalProcesses)
                    if active != 0:
                        cleanup = 'cleanup-failed'
                if timed_out and cleanup == 'clean':
                    cleanup = 'timeout-reaped'
                cleanup_ok = (active == 0)
                if not cleanup_ok:
                    cleanup = 'cleanup-failed'
                return {'argv': tuple(argv), 'returncode': proc.returncode, 'stdout': out, 'stderr': err,
                        'timed_out': timed_out, 'truncated': truncated, 'truncate_reason': reason,
                        'active_processes': active, 'total_processes': total,
                        'cleanup': cleanup, 'cleanup_ok': cleanup_ok}
            finally:
                try:
                    if proc.poll() is None:
                        kernel32.TerminateJobObject(job, 1)
                        proc.wait(timeout=10)
                except Exception:
                    pass
        finally:
            try:
                kernel32.CloseHandle(job)
            except Exception:
                pass

    def run(self, argv, *, input_bytes=None, timeout, cwd, env):
        if os.name == 'nt':
            return self._run_windows(argv, input_bytes=input_bytes, timeout=timeout, cwd=cwd, env=env)
        return self._run_posix(argv, input_bytes=input_bytes, timeout=timeout, cwd=cwd, env=env)


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
            (root/'tests/__init__.py').write_text('', newline='\n')
            (root/'tests/suite.py').write_text(source, newline='\n')
            yield root

    def child(self, root, phase='discover', expected=None, **changes):
        source = root/'tests/suite.py'
        req = dict(schema=r.PYTHON_PROTOCOL, phase=phase, root=str(root), module='tests.suite', source='tests/suite.py', source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), max_tests=100, expected=expected or [])
        req.update(changes)
        raw = json.dumps(req, sort_keys=True).encode()
        if os.name == 'posix':
            with tempfile.TemporaryFile() as protocol:
                observed = subprocess.run([sys.executable, '-I', '-B', str(SCRIPT), '--_python-child', str(protocol.fileno())], input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(protocol.fileno(),), timeout=15,
                                          env={'PATH': os.defpath, 'PYTHONDONTWRITEBYTECODE': '1'}, cwd=root)
                protocol.seek(0)
                body = protocol.read(r.MAX_PROTOCOL_BYTES+1)
            data = r.parse_python_protocol(body, request_sha256=hashlib.sha256(raw).hexdigest(), expected_module=req["module"], expected_source_sha256=req["source_sha256"], expected_phase=phase, expected_discovery=req["expected"] if phase == "execute" else None) if body else None
            return observed, data, body, req
        # Windows: pass_fds is NOT supported (verified AssertionError on 3.12), so use
        # a file-transport driver run under WindowsOwnedTree. The driver dup2s the
        # protocol file onto fd 10 then runpys descriptor_runner --_python-child 10,
        # exercising the real _child_main/_python_child in a contained child. The
        # driver itself runs isolated (-I -B, stdlib only); candidate code executes
        # only inside _python_child under the fresh-source loader.
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            proto = tmp / 'proto.bin'
            driver = tmp / 'wu850_driver.py'
            driver.write_text('import os, sys, runpy\nproto = sys.argv[1]\ntarget = int(sys.argv[2])\nscript = sys.argv[3]\nf = open(proto, "wb")\nos.dup2(f.fileno(), target)\nsys.argv = [script, "--_python-child", str(target)]\nrunpy.run_path(script, run_name="__main__")\n', newline='\n')
            argv = [sys.executable, '-I', '-B', str(driver), str(proto), '10', str(SCRIPT)]
            launcher = WindowsOwnedTree()
            env = {'PATH': os.environ.get('PATH', os.defpath), 'SYSTEMROOT': os.environ.get('SYSTEMROOT', r'C:\Windows'),
                   'TEMP': tempfile.gettempdir(), 'TMP': tempfile.gettempdir(),
                   'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONIOENCODING': 'utf-8'}
            disp = launcher.run(argv, input_bytes=raw, timeout=15, cwd=str(root), env=env)
            self.assertFalse(disp['truncated'], disp['truncate_reason'])
            self.assertTrue(disp['cleanup_ok'], disp)
            observed = subprocess.CompletedProcess(argv, disp['returncode'], disp['stdout'], disp['stderr'])
            body = proto.read_bytes() if proto.exists() else b''
            if len(body) > r.MAX_PROTOCOL_BYTES + 1:
                body = body[:r.MAX_PROTOCOL_BYTES + 1]
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
            (root/'tests/suite.py').write_text(BASE+'\n# changed\n', newline='\n')
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
        path.write_text(replacement, newline='\n')
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
            helper.write_text("def answer():\n    return 4\n", newline='\n')
            self.stale_cache(helper, "def answer():\n    return 5\n")
            observed, data, _, _ = self.discover_execute(root)
            self.assertEqual(0, observed.returncode)
            self.assertEqual("failure", data["results"][0]["outcome"])

    def test_imported_helper_mutation_invalidates_result_without_reset(self):
        source = BASE.replace("self.assertEqual(2 + 2, 4)",
                              "from tests import helper\n        from pathlib import Path\n        Path(helper.__file__).write_text('changed')\n        self.assertTrue(True)")
        with self.fixture(source) as root:
            helper = root / "tests/helper.py"
            helper.write_text("VALUE = 1\n", newline='\n')
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
            helper.write_text("def answer():\n    return 4\n", newline='\n')
            py_compile.compile(str(helper), cfile=str(helper.with_suffix(".pyc")), doraise=True)
            helper.unlink()
            observed, data, _, _ = self.discover_execute(root)
            # An import error is a nonpassing test result; bytecode cannot be used.
            self.assertTrue(observed.returncode != 0 or data["results"][0]["outcome"] != "pass")

    def test_native_repository_module_is_not_test_source(self):
        # Regression (no matrix marker): an in-root native module must never
        # execute as test source. The method-level import below runs only at
        # execution time, so discovery succeeds and the NATIVE reject surfaces
        # as a test error: rc 0 is fine, but the outcome can never be "pass".
        source = BASE.replace("self.assertEqual(2 + 2, 4)",
                              "from tests.helper import answer\n        self.assertEqual(answer(), 4)")
        with self.fixture(source) as root:
            (root / "tests/helper.pyd").write_bytes(b'\x00not-a-library')
            observed, data, _, _ = self.discover_execute(root)
            self.assertTrue(observed.returncode != 0 or data["results"][0]["outcome"] != "pass")
            self.assertEqual("error", data["results"][0]["outcome"])

    def test_helper_reload_after_mutation_invalidates_without_reset(self):
        # Regression (no matrix marker): a helper reloaded after mid-run
        # mutation must invalidate even though the loader saw it before; the
        # first-seen digest is authoritative and the file is never reset.
        source = BASE.replace(
            "self.assertEqual(2 + 2, 4)",
            "from tests import helper\n        import importlib\n        from pathlib import Path\n"
            "        Path(helper.__file__).write_text('def answer():\\n    return 99\\n')\n"
            "        importlib.reload(helper)\n        self.assertTrue(True)")
        with self.fixture(source) as root:
            helper = root / "tests/helper.py"
            helper.write_text("def answer():\n    return 4\n", newline='\n')
            observed, data, _, _ = self.discover_execute(root)
            self.assertNotEqual(0, observed.returncode)
            self.assertIsNone(data)
            self.assertIn("return 99", helper.read_text())


def _b1_assignment(**changes):
    import dataclasses
    issue = c.IssueIdentity(c.RepositoryIdentity("UnknownAlienHuman", "eliot-memory-os"), 850)
    value = c.AssignmentSourceReceipt(
        issue=issue, state=c.IssueState.OPEN, unit=c.WorkUnitIdentity("D-WU-RUNNERS"),
        authority=c.SourceAuthority.LIVE_GITHUB, title="fixture, not a live authorization",
        body_sha256="a" * 64, matrix_cases=44, proof_ceiling=c.ProofCeiling("assignment-source-only"),
        matrix_sha256="b" * 64, source_use=c.AssignmentSourceUse.ACTIVE_ASSIGNMENT,
        origin="https://api.github.com")
    return dataclasses.replace(value, **changes)


class DescriptorFixtureCases(unittest.TestCase):
    # WORK_UNIT_CASE: 850/1
    def test_file_fixture_minimal_descriptors_decode_per_mode(self):
        expected_modes = {'minimal-python-unittest.toml': 'python-unittest', 'minimal-rust-package.toml': 'rust-package', 'minimal-metadata-python.toml': 'metadata-python'}
        for name, mode in expected_modes.items():
            raw = (DESCRIPTOR_DIR / name).read_bytes()
            self.assertNotIn(b'\r', raw)
            data = r.decode_descriptor(raw, FILENAME)
            self.assertEqual(mode, data['mode'])
            self.assertEqual(44, data['matrix_cases'])
            self.assertEqual('D-WU-RUNNERS', data['unit']['value'])
            self.assertEqual('a' * 64, data['body_sha256'])
            self.assertEqual(10000, data['bounds']['wall_ms'])
        rust_raw = (DESCRIPTOR_DIR / 'minimal-rust-package.toml').read_bytes()
        self.assertIn(b'package = ', rust_raw)
        meta_raw = (DESCRIPTOR_DIR / 'minimal-metadata-python.toml').read_bytes()
        self.assertIn(b'module = ', meta_raw)

    # WORK_UNIT_CASE: 850/2
    def test_unknown_schema_field_mode_rejected(self):
        self.assertRaises(r.RunnerInputError, r.decode_descriptor, VALID.replace(b'descriptor-v2', b'descriptor-v1'), FILENAME)
        self.assertRaises(r.RunnerInputError, r.decode_descriptor, VALID.replace(b'python-unittest', b'powershell'), FILENAME)
        self.assertRaises(r.RunnerInputError, r.decode_descriptor, VALID.replace(b'mode = "python-unittest"', b'mode = 7'), FILENAME)
        unknown_raw = (DESCRIPTOR_DIR / 'unknown-field.toml').read_bytes()
        self.assertIn(b'extra_unknown_key', unknown_raw)
        self.assertRaises(r.RunnerInputError, r.decode_descriptor, unknown_raw, FILENAME)

    # WORK_UNIT_CASE: 850/3
    def test_filename_issue_unit_mismatch(self):
        for bad_name in ('850.toml', '.github/work-units/851.toml', '.github/work-units/0850.toml'):
            with self.assertRaises(r.RunnerInputError):
                r.decode_descriptor(VALID, bad_name)
        self.assertRaises(r.RunnerInputError, r.decode_descriptor, VALID.replace(b'number = 850', b'number = 851'), FILENAME)
        self.assertRaises(r.RunnerInputError, r.decode_descriptor, VALID.replace(b'work-unit-850', b'work-unit-851'), FILENAME)
        with self.assertRaises(r.RunnerInputError):
            r.parse_descriptor(VALID, FILENAME, _b1_assignment(unit=c.WorkUnitIdentity('other-owner')))

    # WORK_UNIT_CASE: 850/4
    def test_missing_duplicate_roots(self):
        self.assertRaises(r.RunnerInputError, r.decode_descriptor,
                          VALID.replace(b'source_roots = [{value = "scripts/work_unit_gate/descriptor_runner.py"}]', b'source_roots = []'), FILENAME)
        dup = VALID.replace(b'[{value = "scripts/work_unit_gate/descriptor_runner.py"}]', b'[{value = "scripts/a.py"}, {value = "scripts/a.py"}]')
        self.assertRaises(r.RunnerInputError, r.decode_descriptor, dup, FILENAME)
        missing = b'\n'.join(l for l in VALID.splitlines() if not l.startswith(b'test_roots ='))
        self.assertRaises(r.RunnerInputError, r.decode_descriptor, missing, FILENAME)
        dup_key = VALID + b'source_roots = []\n'
        self.assertRaises(r.RunnerInputError, r.decode_descriptor, dup_key, FILENAME)

    # WORK_UNIT_CASE: 850/5
    def test_absolute_drive_unc_traversal_rejected(self):
        for path in ('/tmp/a', 'C:/a', 'C:\\a', '//host/a', '\\\\host\\share', 'scripts/../escape', 'scripts/./dot', 'a/../../b'):
            with self.subTest(path=path):
                with self.assertRaises(r.RunnerInputError):
                    r.decode_descriptor(VALID.replace(b'scripts/work_unit_gate/descriptor_runner.py', path.encode()), FILENAME)

    # WORK_UNIT_CASE: 850/6
    def test_control_nul_alias_and_literal_percent(self):
        for bad in ('a\x01b', 'a\x1fb', 'a\\b', 'a:b', 'a*b', 'a?b', 'a[b', 'trailing ', 'trailing.'):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(r.RunnerInputError):
                    r._relative_path('scripts/' + bad)
        with self.assertRaises(r.RunnerInputError):
            r._relative_path('scripts/a\x00b')
        data = r.decode_descriptor(VALID.replace(b'scripts/work_unit_gate/descriptor_runner.py', b'scripts/%2e%2e%2fa.py'), FILENAME)
        self.assertEqual('scripts/%2e%2e%2fa.py', data['source_roots'][0]['value'])
        self.assertNotIn('..', data['source_roots'][0]['value'].split('/'))

    # WORK_UNIT_CASE: 850/7
    def test_physical_symlink_escape(self):
        method_used = 'symlink'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'real').mkdir()
            (root / 'real' / 'a').write_text('x', newline='\n')
            link = root / 'alias'
            try:
                link.symlink_to(root / 'real', target_is_directory=True)
            except OSError:
                method_used = 'junction-mklink-J'
                proc = subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(root / 'real')],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
                self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertRaises(r.RunnerInputError, r._safe_path, root, 'alias/a')
            self.assertEqual(root / 'real' / 'a', r._safe_path(root, 'real/a'))
        self.assertIn(method_used, ('symlink', 'junction-mklink-J'))

    # WORK_UNIT_CASE: 850/8
    def test_broad_root_wildcard_rejected(self):
        for path in ('scripts', '.', 'scripts/**', 'scripts/*.py', 'scripts/[a].py', 'scripts/a/', 'a'):
            with self.subTest(path=path):
                with self.assertRaises(r.RunnerInputError):
                    r.decode_descriptor(VALID.replace(b'scripts/work_unit_gate/descriptor_runner.py', path.encode()), FILENAME)

    # WORK_UNIT_CASE: 850/9
    def test_negative_zero_oneover_and_inconsistent_bounds(self):
        import re
        maxima = {'wall_ms': 86400000, 'idle_ms': 86400000, 'output_bytes': 67108864,
                  'line_bytes': 1048576, 'discovery_tests': 100000, 'child_processes': 64}
        for key, limit in maxima.items():
            for bad in ('0', '-1', str(limit + 1), 'true'):
                with self.subTest(key=key, bad=bad):
                    with self.assertRaises(r.RunnerInputError):
                        r.decode_descriptor(re.sub(fr'{key} = [0-9]+'.encode(), f'{key} = {bad}'.encode(), VALID), FILENAME)
        self.assertRaises(r.RunnerInputError, r.decode_descriptor, VALID.replace(b'idle_ms = 5000', b'idle_ms = 10001'), FILENAME)
        self.assertRaises(r.RunnerInputError, r.decode_descriptor, VALID.replace(b'line_bytes = 4096', b'line_bytes = 65537'), FILENAME)
        self.assertRaises(r.RunnerInputError, r.decode_descriptor, VALID.replace(b'discovery_tests = 1000', b'discovery_tests = 43'), FILENAME)


class DescriptorEscapeCases(unittest.TestCase):
    # WORK_UNIT_CASE: 850/10
    def test_command_argv_shell_exec_rejected(self):
        for key in ('command', 'argv', 'executable', 'shell'):
            with self.subTest(key=key):
                with self.assertRaises(r.RunnerInputError):
                    r.decode_descriptor(VALID + f'{key} = "CANARY"\n'.encode(), FILENAME)
        with self.assertRaises(r.RunnerInputError):
            r.decode_descriptor(VALID + b'command = ["cargo", "test"]\n', FILENAME)

    # WORK_UNIT_CASE: 850/11
    def test_url_network_origin_rejected(self):
        for key in ('url', 'network_origin', 'working_directory', 'output_path'):
            with self.subTest(key=key):
                with self.assertRaises(r.RunnerInputError):
                    r.decode_descriptor(VALID + f'{key} = "CANARY"\n'.encode(), FILENAME)
        with self.assertRaises(r.RunnerInputError):
            r.decode_descriptor(VALID + b'url = "https://example.invalid/x"\n', FILENAME)

    # WORK_UNIT_CASE: 850/12
    def test_env_secret_credential_rejected(self):
        for key in ('environment', 'secret', 'credential'):
            with self.subTest(key=key):
                with self.assertRaises(r.RunnerInputError):
                    r.decode_descriptor(VALID + f'{key} = "CANARY"\n'.encode(), FILENAME)
        unknown_raw = (DESCRIPTOR_DIR / 'unknown-field.toml').read_bytes()
        with self.assertRaises(r.RunnerInputError):
            r.decode_descriptor(unknown_raw, FILENAME)
        filtered = r.minimal_child_env({'PATH': 'x', 'GH_TOKEN': 'CANARY', 'MY_SECRET': 's', 'PYTHONIOENCODING': 'utf-8'})
        self.assertNotIn('GH_TOKEN', filtered)
        self.assertNotIn('MY_SECRET', filtered)

    # WORK_UNIT_CASE: 850/13
    def test_key_permutation_digest_equality(self):
        raw = (DESCRIPTOR_DIR / 'minimal-python-unittest.toml').read_bytes()
        permuted = b'\n'.join(reversed(raw.splitlines()))
        self.assertEqual(r.decode_descriptor(raw, FILENAME), r.decode_descriptor(permuted, FILENAME))
        first = r.parse_descriptor(raw, FILENAME, _b1_assignment())
        second = r.parse_descriptor(permuted, FILENAME, _b1_assignment())
        self.assertEqual(first.sha256, second.sha256)
        self.assertEqual(c.canonical_sha256(first), c.canonical_sha256(second))


class PackageManifestCases(unittest.TestCase):
    # WORK_UNIT_CASE: 850/14
    def test_exact_one_package_manifest_resolution(self):
        binding = r.resolve_package_manifest(package_name='wu850_tiny',
                                             metadata_packages=[{'name': 'wu850_tiny', 'manifest_rel': 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml', 'member_kind': 'member'}],
                                             require_workspace_member=False)
        self.assertEqual('wu850_tiny', binding['name'])
        self.assertEqual('member', binding['member_kind'])

    # WORK_UNIT_CASE: 850/15
    def test_missing_duplicate_package_identity(self):
        with self.assertRaises(r.RunnerInputError):
            r.resolve_package_manifest(package_name='missing', metadata_packages=[{'name': 'wu850_tiny', 'manifest_rel': 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml', 'member_kind': 'member'}])
        with self.assertRaises(r.RunnerInputError):
            r.resolve_package_manifest(package_name='wu850_tiny', metadata_packages=[])
        dup = [{'name': 'wu850_tiny', 'manifest_rel': 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml', 'member_kind': 'member'},
               {'name': 'wu850_tiny', 'manifest_rel': 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml', 'member_kind': 'member'}]
        with self.assertRaises(r.RunnerInputError):
            r.resolve_package_manifest(package_name='wu850_tiny', metadata_packages=dup)

    # WORK_UNIT_CASE: 850/16
    def test_four_member_kinds_distinct(self):
        rel = 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml'
        for kind, package_only_ok in (('member', True), ('excluded', True), ('standalone', True), ('unavailable', False)):
            with self.subTest(kind=kind):
                if package_only_ok:
                    binding = r.resolve_package_manifest(package_name='wu850_tiny',
                                                         metadata_packages=[{'name': 'wu850_tiny', 'manifest_rel': rel, 'member_kind': kind}])
                    self.assertEqual(kind, binding['member_kind'])
                else:
                    with self.assertRaises(r.RunnerInputError):
                        r.resolve_package_manifest(package_name='wu850_tiny',
                                                   metadata_packages=[{'name': 'wu850_tiny', 'manifest_rel': rel, 'member_kind': kind}])
        member = r.resolve_package_manifest(package_name='p', metadata_packages=[{'name': 'p', 'manifest_rel': rel, 'member_kind': 'member'}], require_workspace_member=True)
        self.assertEqual('member', member['member_kind'])
        with self.assertRaises(r.RunnerInputError):
            r.resolve_package_manifest(package_name='p', metadata_packages=[{'name': 'p', 'manifest_rel': rel, 'member_kind': 'excluded'}], require_workspace_member=True)

    # WORK_UNIT_CASE: 850/17
    def test_package_only_vs_membership_required(self):
        rel = 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml'
        excluded_only = r.resolve_package_manifest(package_name='wu850_tiny',
                                                   metadata_packages=[{'name': 'wu850_tiny', 'manifest_rel': rel, 'member_kind': 'excluded'}],
                                                   require_workspace_member=False)
        self.assertEqual('excluded', excluded_only['member_kind'])
        with self.assertRaises(r.RunnerInputError):
            r.resolve_package_manifest(package_name='wu850_tiny',
                                       metadata_packages=[{'name': 'wu850_tiny', 'manifest_rel': rel, 'member_kind': 'excluded'}],
                                       require_workspace_member=True)
        local = r.parse_descriptor(VALID, FILENAME, _b1_assignment())
        integrated = r.parse_descriptor(VALID.replace(b'require_workspace_member = false', b'require_workspace_member = true'), FILENAME, _b1_assignment())
        self.assertNotEqual(local.sha256, integrated.sha256)
        self.assertIs(local.phase, c.VerificationPhase.PACKAGE_LOCAL)


class RustRealRunnerCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._scratch = Path(tempfile.mkdtemp(prefix='wu850-'))
        cls._target = cls._scratch / 'target'
        cls._target.mkdir()
        cls._manifest_abs = str(RUST_TINY_MANIFEST.resolve())
        cls._target_abs = str(cls._target.resolve())
        cls.launcher = WindowsOwnedTree()
        # Deviation disclosed: cargo runs use the full host env minus
        # secret-marked names (MSVC link.exe requires inherited INCLUDE/LIB/
        # SystemRoot and the Cargo/Rust toolchain vars), NOT the 6-name
        # minimal_child_env used for the python child. Secret names carrying
        # TOKEN/SECRET/CREDENTIAL/PASSWORD/KEY are still filtered by name, and
        # values never enter diagnostics.
        blocked = ('TOKEN', 'SECRET', 'CREDENTIAL', 'PASSWORD', 'KEY')
        cls.cargo_env = {k: v for k, v in os.environ.items() if not any(m in k.upper() for m in blocked)}
        argv = ['cargo', 'test', '--manifest-path', cls._manifest_abs, '--target-dir', cls._target_abs,
                '-p', 'wu850_tiny', '--', '--list', '--format', 'terse']
        disp = cls.launcher.run(argv, timeout=180, cwd=str(ROOT), env=cls.cargo_env)
        assert disp['returncode'] == 0, disp['stderr'][:2000]
        assert disp['cleanup_ok'], disp
        assert not disp['truncated'], disp
        cls.discovery_stdout = disp['stdout']
        cls.discovery_names = r.parse_rust_discovery(cls.discovery_stdout, 1000)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(str(cls._scratch), ignore_errors=True)

    def _exact_stdout(self, test_id, timeout=120):
        argv = ['cargo', 'test', '--manifest-path', self._manifest_abs, '--target-dir', self._target_abs,
                '-p', 'wu850_tiny', '--', '--exact', test_id]
        disp = self.launcher.run(argv, timeout=timeout, cwd=str(ROOT), env=self.cargo_env)
        return disp

    def _libtest_section(self, stdout):
        # Proof is scoped to the selected libtest binary section: a passing
        # cargo test -p emits one section per target (unit tests, then
        # doc-tests), and the frozen parse_rust_exact grammar binds exactly one
        # terminal record. When several sections exist, the discarded suffix is
        # asserted to contain no FAILED result line, so a failing doc-test or
        # other target cannot hide behind the split (a failing unit run has a
        # single section because cargo stops before doc-tests). Per-binary
        # aggregation across targets is controller-owned (#837).
        head, sep, tail = stdout.partition(b'\nrunning 0 tests')
        if sep:
            self.assertNotIn(b'test result: FAILED', tail)
            return head
        return stdout

    # WORK_UNIT_CASE: 850/18
    def test_real_cargo_discovery(self):
        expected = (RUST_TINY_DIR / 'expected-discovery.txt').read_bytes()
        self.assertNotIn(b'\r', expected)
        self.assertEqual(expected, self.discovery_stdout)
        self.assertEqual(('tiny_fail', 'tiny_ignored', 'tiny_ok_a', 'tiny_ok_b'), self.discovery_names)
        shape = r.build_cargo_discovery_command(manifest_rel='scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml',
                                                target_dir_rel='target/wu850-tiny', package='wu850_tiny')
        self.assertEqual(('cargo', 'test', '--manifest-path', 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml',
                          '--target-dir', 'target/wu850-tiny', '-p', 'wu850_tiny', '--', '--list', '--format', 'terse'), shape)
        self.assertIn(b'[dependencies]', RUST_TINY_MANIFEST.read_bytes())

    # WORK_UNIT_CASE: 850/19
    def test_zero_rust_discovery_fails(self):
        with self.assertRaises(r.RunnerInputError):
            r.parse_rust_discovery(b'', 10)
        with self.assertRaises(r.RunnerInputError):
            r.parse_rust_discovery(b'tiny_ok_a: test\ntiny_ok_a: test\n', 10)

    # WORK_UNIT_CASE: 850/20
    def test_real_exact_single_test_execution_green(self):
        disp = self._exact_stdout('tiny_ok_a')
        self.assertEqual(0, disp['returncode'], disp['stderr'][:2000])
        self.assertTrue(disp['cleanup_ok'], disp)
        section = self._libtest_section(disp['stdout'])
        parsed = r.parse_rust_exact(section, 'tiny_ok_a', 0, 4)
        self.assertEqual('pass', parsed.outcome)
        self.assertEqual(3, parsed.filtered)

    # WORK_UNIT_CASE: 850/21
    def test_ignored_filtered_cfg_disabled_never_pass(self):
        disp = self._exact_stdout('tiny_ignored')
        self.assertIn(b'ignored', disp['stdout'])
        with self.assertRaises(r.RunnerInputError):
            r.parse_rust_exact(self._libtest_section(disp['stdout']), 'tiny_ignored', disp['returncode'], 4)
        grammar = b'\nrunning 1 test\ntest tiny_ok_a ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.01s\n\n'
        with self.assertRaises(r.RunnerInputError):
            r.parse_rust_exact(grammar.replace(b'running 1 test', b'running 0 tests'), 'tiny_ok_a', 0, 4)
        with self.assertRaises(r.RunnerInputError):
            r.parse_rust_exact(grammar.replace(b'... ok', b'... ignored'), 'tiny_ok_a', 0, 4)

    # WORK_UNIT_CASE: 850/22
    def test_assertion_vs_process_failure_distinct(self):
        disp = self._exact_stdout('tiny_fail')
        self.assertNotEqual(0, disp['returncode'])
        with self.assertRaises(r.RunnerInputError) as ctx_fail:
            r.parse_rust_exact(self._libtest_section(disp['stdout']), 'tiny_fail', disp['returncode'], 4)
        self.assertIn('TEST_OR_HARNESS_FAILED', str(ctx_fail.exception))
        grammar = b'\nrunning 1 test\ntest tiny_ok_a ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.01s\n\n'
        with self.assertRaises(r.RunnerInputError) as ctx_malformed:
            r.parse_rust_exact(b'noise\n' + grammar, 'tiny_ok_a', 0, 4)
        self.assertIn('UNTRUSTED_OR_INCOMPLETE_RESULT', str(ctx_malformed.exception))
        self.assertNotEqual(str(ctx_fail.exception), str(ctx_malformed.exception))

    # WORK_UNIT_CASE: 850/23
    def test_malformed_truncated_unsupported_output_incomplete(self):
        for output in (b'a: benchmark\n', b'a: tes', b'test a ... ok\n', b'\xff', b'CANARY\na: test\n'):
            with self.assertRaises(r.RunnerInputError):
                r.parse_rust_discovery(output, 4)
        grammar = b'\nrunning 1 test\ntest tiny_ok_a ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.01s\n\n'
        for output in (b'', grammar + b'forged', grammar.replace(b'1 passed', b'2 passed')):
            with self.assertRaises(r.RunnerInputError):
                r.parse_rust_exact(output, 'tiny_ok_a', 0, 4)

    # WORK_UNIT_CASE: 850/24
    def test_package_mode_never_workspace_wide(self):
        rel_m = 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml'
        rel_t = 'target/wu850-tiny'
        discovery = r.build_cargo_discovery_command(manifest_rel=rel_m, target_dir_rel=rel_t, package='wu850_tiny')
        exact = r.build_cargo_test_command(manifest_rel=rel_m, target_dir_rel=rel_t, package='wu850_tiny', test_id='tiny_ok_a')
        build = r.build_cargo_build_command(manifest_rel=rel_m, target_dir_rel=rel_t, package='wu850_tiny')
        for argv in (discovery, exact, build):
            self.assertNotIn('--workspace', argv)
            self.assertNotIn('--all', argv)
            self.assertEqual(tuple(argv), r.assert_no_workspace_wide(argv))
        for bad in (['cargo', 'test', '--workspace'], ['cargo', 'test', '--all'], ('cargo', 'build', '--workspace')):
            with self.assertRaises(r.RunnerInputError):
                r.assert_no_workspace_wide(bad)


class BoundedCompletionCases(unittest.TestCase):
    # Reuse only provisioning helpers; each case below is a new bound test.
    fixture = PythonProtocolTests.fixture
    child = PythonProtocolTests.child
    discover_execute = PythonProtocolTests.discover_execute

    def _short_child(self, root, phase, expected, timeout, max_tests=100):
        # Test-only bounded driver run (mirrors PythonProtocolTests.child but
        # with a caller-chosen wall timeout). Returns (disp, body, req).
        source = root / 'tests/suite.py'
        req = dict(schema=r.PYTHON_PROTOCOL, phase=phase, root=str(root), module='tests.suite',
                   source='tests/suite.py',
                   source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                   max_tests=max_tests, expected=expected)
        raw = json.dumps(req, sort_keys=True).encode()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            proto = tmp / 'proto.bin'
            driver = tmp / 'wu850_driver.py'
            driver.write_text('import os, sys, runpy\nproto = sys.argv[1]\ntarget = int(sys.argv[2])\nscript = sys.argv[3]\nf = open(proto, "wb")\nos.dup2(f.fileno(), target)\nsys.argv = [script, "--_python-child", str(target)]\nrunpy.run_path(script, run_name="__main__")\n', newline='\n')
            argv = [sys.executable, '-I', '-B', str(driver), str(proto), '10', str(SCRIPT)]
            launcher = WindowsOwnedTree()
            env = {'PATH': os.environ.get('PATH', os.defpath), 'SYSTEMROOT': os.environ.get('SYSTEMROOT', r'C:\Windows'),
                   'TEMP': tempfile.gettempdir(), 'TMP': tempfile.gettempdir(),
                   'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONIOENCODING': 'utf-8'}
            disp = launcher.run(argv, input_bytes=raw, timeout=timeout, cwd=str(root), env=env)
            body = proto.read_bytes() if proto.exists() else b''
            return disp, body, req

    def _minimal_env(self):
        return {'PATH': os.environ.get('PATH', os.defpath), 'SYSTEMROOT': os.environ.get('SYSTEMROOT', r'C:\Windows'),
                'TEMP': tempfile.gettempdir(), 'TMP': tempfile.gettempdir(),
                'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONIOENCODING': 'utf-8'}

    # WORK_UNIT_CASE: 850/25
    def test_real_bounded_child_tree_timeout_cleanup(self):
        import inspect
        launcher = WindowsOwnedTree()
        code = ('import subprocess, sys, time; '
                'subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"]); '
                'time.sleep(60)')
        disp = launcher.run([sys.executable, '-c', code], timeout=3, cwd=str(ROOT), env=self._minimal_env())
        self.assertTrue(disp['timed_out'], disp)
        self.assertEqual('timeout-reaped', disp['cleanup'], disp)
        self.assertTrue(disp['cleanup_ok'], disp)
        self.assertEqual(0, disp['active_processes'], disp)
        self.assertGreaterEqual(disp['total_processes'], 1, disp)
        # The reap path is TerminateJobObject on the owned Job, which a plain
        # Popen.kill-only cleanup cannot produce (a kill-only parent leaves the
        # grandchild alive and accounting nonzero).
        self.assertIn('TerminateJobObject', inspect.getsource(WindowsOwnedTree._run_windows))

    # WORK_UNIT_CASE: 850/26
    def test_stdout_stderr_line_bounds_fail_closed(self):
        launcher = WindowsOwnedTree(output_bytes=2048, line_bytes=256)
        over_out = launcher.run([sys.executable, '-c', 'import sys\nfor i in range(200): sys.stdout.write("y" * 20 + "\\n")'],
                                timeout=30, cwd=str(ROOT), env=self._minimal_env())
        self.assertTrue(over_out['truncated'], over_out['truncate_reason'])
        self.assertEqual('OUTPUT_BYTE_BOUND', over_out['truncate_reason'])
        over_line = launcher.run([sys.executable, '-c', 'import sys; sys.stdout.write("z" * 1000 + "\\n")'],
                                 timeout=30, cwd=str(ROOT), env=self._minimal_env())
        self.assertTrue(over_line['truncated'], over_line['truncate_reason'])
        self.assertEqual('LINE_BYTE_BOUND', over_line['truncate_reason'])
        over_err = launcher.run([sys.executable, '-c', 'import sys; sys.stderr.write("e" * 5000)'],
                                timeout=30, cwd=str(ROOT), env=self._minimal_env())
        self.assertTrue(over_err['truncated'], over_err['truncate_reason'])
        # Fail-closed: over-bound bytes are never accepted as proof.
        with self.assertRaises(r.RunnerInputError):
            r.parse_rust_exact(b'a' * (r.MAX_PROTOCOL_BYTES + 1), 'tiny_ok_a', 0, 2)
        with self.assertRaises(r.RunnerInputError):
            r._bounded_json(b'a' * (r.MAX_PROTOCOL_BYTES + 1))

    # WORK_UNIT_CASE: 850/27
    def test_exact_python_discovery_execution_in_contained_children(self):
        sample = (PYTHON_TINY_DIR / 'test_sample.py').read_text()
        self.assertIn('import json', sample)
        self.assertIn('import os', sample)
        self.assertEqual(6, sample.count('def test_'))
        with self.fixture() as root:
            observed, discovery, body, req = self.child(root)
            self.assertEqual(0, observed.returncode, observed.stderr)
            self.assertEqual('discover', discovery['phase'])
            self.assertEqual(req['module'], 'tests.suite')
            self.assertEqual(discovery['source_sha256'], req['source_sha256'])
            self.assertEqual(discovery['request_sha256'], hashlib.sha256(json.dumps(req, sort_keys=True).encode()).hexdigest())
            self.assertTrue(discovery['tests'][0]['id'].startswith('tests.suite.'))
            observed2, data2, _, req2 = self.child(root, 'execute', discovery['tests'])
            self.assertEqual(0, observed2.returncode, observed2.stderr)
            self.assertEqual('execute', data2['phase'])
            self.assertEqual(discovery['tests'], data2['tests'])
            self.assertEqual('pass', data2['results'][0]['outcome'])
            self.assertEqual(req2['expected'], discovery['tests'])

    # WORK_UNIT_CASE: 850/28
    def test_zero_python_tests_fail(self):
        with self.fixture('import unittest\n') as root:
            observed, data, body, _ = self.child(root)
            self.assertIsNone(data)
            self.assertEqual(b'', body)
            self.assertNotEqual(0, observed.returncode)
            with self.assertRaises(r.RunnerInputError):
                r.parse_python_protocol(body, request_sha256='a' * 64, expected_module='tests.suite',
                                        expected_source_sha256='a' * 64, expected_phase='execute')

    # WORK_UNIT_CASE: 850/29
    def test_all_six_python_outcomes_in_one_real_execution(self):
        sample = (PYTHON_TINY_DIR / 'test_sample.py').read_text()
        with self.fixture(sample) as root:
            observed, data, _, _ = self.discover_execute(root)
            self.assertEqual(0, observed.returncode, observed.stderr)
            by_id = {row['id']: row['outcome'] for row in data['results']}
            self.assertEqual(6, len(by_id))
            self.assertEqual('pass', by_id['tests.suite.Suite.test_ok'])
            self.assertEqual('failure', by_id['tests.suite.Suite.test_fail'])
            self.assertEqual('error', by_id['tests.suite.Suite.test_err'])
            self.assertEqual('skip', by_id['tests.suite.Suite.test_skip'])
            self.assertEqual('expected-failure', by_id['tests.suite.Suite.test_xfail'])
            self.assertEqual('unexpected-success', by_id['tests.suite.Suite.test_unexp'])
            self.assertEqual(6, len(set(by_id.values())))

    # WORK_UNIT_CASE: 850/30
    def test_foreign_identity_rejected_stdlib_imports_allowed(self):
        sample = (PYTHON_TINY_DIR / 'test_sample.py').read_text()
        with self.fixture(sample) as root:
            observed, data, _, _ = self.discover_execute(root)
            self.assertEqual(0, observed.returncode, observed.stderr)
            self.assertEqual(6, len(data['results']))
        with self.fixture() as root:
            _, _, body, req = self.child(root)
            digest = hashlib.sha256(json.dumps(req, sort_keys=True).encode()).hexdigest()
            with self.assertRaises(r.RunnerInputError) as ctx:
                r.parse_python_protocol(body, request_sha256=digest, expected_module='foreign.mod',
                                        expected_source_sha256=req['source_sha256'], expected_phase='discover')
            self.assertIn('FOREIGN_TEST_IDENTITY', str(ctx.exception))

    # WORK_UNIT_CASE: 850/31
    def test_metadata_mode_uses_only_registered_entrypoint(self):
        raw = (DESCRIPTOR_DIR / 'minimal-metadata-python.toml').read_bytes()
        data = r.decode_descriptor(raw, FILENAME)
        self.assertEqual('metadata-python', data['mode'])
        roots = [entry['value'] for entry in data['test_roots']]
        module = data['module']['value']
        self.assertEqual(module, r.resolve_metadata_entrypoint(module=module, test_roots=roots))
        with self.assertRaises(r.RunnerInputError):
            r.resolve_metadata_entrypoint(module='other.unregistered', test_roots=roots)

    # WORK_UNIT_CASE: 850/32
    def test_metadata_generator_mutation_network_spellings_rejected(self):
        for spelling in ('mod:gen', 'mod/run', 'mod\\x', 'evil!', 'a b', 'x.py', 'x.ps1', 'x.sh',
                         'x.pyw', 'x.pyc', 'x.pyd', 'x.psm1', 'x.psd1', 'x.dll', 'x.so', 'x.dylib', 'x.bat', 'x.exe'):
            with self.subTest(spelling=spelling):
                with self.assertRaises(r.RunnerInputError) as ctx:
                    r.resolve_metadata_entrypoint(module=spelling, test_roots=['scripts/tests'])
                self.assertIn('NOT_A_REGISTERED_SUITE', str(ctx.exception))

    # WORK_UNIT_CASE: 850/33
    def test_duplicate_test_ids_rejected(self):
        with self.fixture() as root:
            _, data, body, req = self.child(root)
            digest = hashlib.sha256(json.dumps(req, sort_keys=True).encode()).hexdigest()
            doubled = dict(data, tests=data['tests'] + data['tests'][:1])
            with self.assertRaises(r.RunnerInputError) as ctx:
                r.parse_python_protocol(json.dumps(doubled).encode(), request_sha256=digest,
                                        expected_module=req['module'], expected_source_sha256=req['source_sha256'],
                                        expected_phase='discover')
            self.assertIn('DUPLICATE_OR_UNSORTED_TESTS', str(ctx.exception))
            self.assertEqual(1, len(data['tests']))

    # WORK_UNIT_CASE: 850/34
    def test_source_discovery_execution_mismatch_rejected(self):
        with self.fixture() as root:
            _, discovery, _, _ = self.child(root)
            altered = [dict(discovery['tests'][0], line=discovery['tests'][0]['line'] + 1)]
            observed, data, _, _ = self.child(root, 'execute', altered)
            self.assertNotEqual(0, observed.returncode)
            self.assertIsNone(data)
            _, _, exec_body, exec_req = self.child(root, 'execute', discovery['tests'])
            kwargs = dict(request_sha256=hashlib.sha256(json.dumps(exec_req, sort_keys=True).encode()).hexdigest(),
                          expected_module=exec_req['module'], expected_source_sha256=exec_req['source_sha256'],
                          expected_phase='execute', expected_discovery=altered)
            with self.assertRaises(r.RunnerInputError) as ctx:
                r.parse_python_protocol(exec_body, **kwargs)
            self.assertIn('DISCOVERY_EXECUTION_MISMATCH', str(ctx.exception))

    # WORK_UNIT_CASE: 850/35
    def test_zero_exit_without_records_incomplete(self):
        with self.assertRaises(r.RunnerInputError):
            r.parse_python_protocol(b'', request_sha256='a' * 64, expected_module='tests.suite',
                                    expected_source_sha256='a' * 64, expected_phase='execute')
        forged = {'schema': r.PYTHON_PROTOCOL, 'request_sha256': 'a' * 64, 'phase': 'execute',
                  'tests': [{'id': 'm.T.test_x', 'line': 1}], 'results': [], 'source_sha256': 'a' * 64}
        with self.assertRaises(r.RunnerInputError) as ctx:
            r.parse_python_protocol(json.dumps(forged).encode(), request_sha256='a' * 64, expected_module='m',
                                    expected_source_sha256='a' * 64, expected_phase='execute',
                                    expected_discovery=forged['tests'])
        self.assertIn('MISSING_EXECUTION', str(ctx.exception))

    # WORK_UNIT_CASE: 850/36
    def test_both_python_modes_enforce_timeout_output_descendant_bounds(self):
        for name, mode in (('minimal-python-unittest.toml', 'python-unittest'),
                           ('minimal-metadata-python.toml', 'metadata-python')):
            data = r.decode_descriptor((DESCRIPTOR_DIR / name).read_bytes(), FILENAME)
            self.assertEqual(mode, data['mode'])
            self.assertGreater(data['bounds']['wall_ms'], 0)
        argv = r.build_python_child_command(script_rel='scripts/work_unit_gate/descriptor_runner.py', fd=10)
        self.assertEqual(argv, r.build_python_child_command(script_rel='scripts/work_unit_gate/descriptor_runner.py', fd=10))
        slow = BASE.replace('self.assertEqual(2 + 2, 4)', 'import time\n        time.sleep(30)')
        with self.fixture(slow) as root:
            observed, discovery, _, _ = self.child(root)
            self.assertEqual(0, observed.returncode, observed.stderr)
            disp, body, _ = self._short_child(root, 'execute', discovery['tests'], timeout=3)
            self.assertTrue(disp['timed_out'], disp)
            self.assertEqual('timeout-reaped', disp['cleanup'], disp)
            self.assertTrue(disp['cleanup_ok'], disp)
            self.assertEqual(0, disp['active_processes'], disp)
            self.assertEqual(b'', body)
        tiny = WindowsOwnedTree(output_bytes=64, line_bytes=16)
        disp = tiny.run([sys.executable, '-c', 'print("q" * 1024)'], timeout=30, cwd=str(ROOT), env=self._minimal_env())
        self.assertTrue(disp['truncated'], disp)

    # WORK_UNIT_CASE: 850/37
    def test_deterministic_commands_and_semantic_normalization(self):
        exact = dict(manifest_rel='scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml',
                     target_dir_rel='target/wu850-tiny', package='wu850_tiny', test_id='tiny_ok_a')
        first = r.canonical_command(r.build_cargo_test_command(**exact))
        second = r.canonical_command(r.build_cargo_test_command(**exact))
        self.assertEqual(first, second)
        self.assertIn('--exact', first)
        local = r.parse_descriptor(VALID, FILENAME, _b1_assignment())
        again = r.parse_descriptor(b'\n'.join(reversed(VALID.splitlines())), FILENAME, _b1_assignment())
        self.assertEqual(local.sha256, again.sha256)
        self.assertEqual('green', r.phase_verdict('discover', 'complete'))
        self.assertEqual('green', r.phase_verdict('execute', 'pass'))
        for outcome in ('failure', 'error', 'skip', 'expected-failure', 'unexpected-success', 'missing', 'timeout'):
            self.assertEqual('non-green', r.phase_verdict('execute', outcome), outcome)
        for outcome in ('empty', 'malformed'):
            self.assertEqual('non-green', r.phase_verdict('discover', outcome), outcome)
        with self.assertRaises(r.RunnerInputError):
            r.phase_verdict('execute', 'bogus-outcome')

    # WORK_UNIT_CASE: 850/38
    def test_credential_values_absent_from_child_environment_and_diagnostics(self):
        old_token, old_secret = os.environ.get('GH_TOKEN'), os.environ.get('MY_SECRET')
        os.environ['GH_TOKEN'] = 'CANARY-GH-TOKEN-6382'
        os.environ['MY_SECRET'] = 'CANARY-MY-SECRET-9174'
        try:
            with self.fixture() as root:
                observed, data, body, _ = self.discover_execute(root)
                self.assertEqual(0, observed.returncode, observed.stderr)
                self.assertEqual('pass', data['results'][0]['outcome'])
                for stream in (observed.stdout, observed.stderr, body):
                    self.assertNotIn(b'CANARY-GH-TOKEN-6382', stream)
                    self.assertNotIn(b'CANARY-MY-SECRET-9174', stream)
        finally:
            if old_token is None:
                os.environ.pop('GH_TOKEN', None)
            else:
                os.environ['GH_TOKEN'] = old_token
            if old_secret is None:
                os.environ.pop('MY_SECRET', None)
            else:
                os.environ['MY_SECRET'] = old_secret
        filtered = r.minimal_child_env({'PATH': 'x', 'GH_TOKEN': 'CANARY', 'MY_SECRET': 's', 'PYTHONIOENCODING': 'utf-8'})
        self.assertNotIn('GH_TOKEN', filtered)
        self.assertNotIn('MY_SECRET', filtered)
        self.assertEqual('x', filtered['PATH'])

    # WORK_UNIT_CASE: 850/39
    def test_source_api_guard_excludes_shell_spawn_and_snapshot_writes(self):
        tree = ast.parse(SCRIPT.read_text())
        imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        imports |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
        self.assertTrue(imports.isdisjoint({'subprocess', 'requests', 'socket', 'ctypes'}), imports)
        banned_attrs = {'spawnl', 'spawnle', 'spawnlp', 'spawnlpe', 'spawnv', 'spawnve', 'spawnvp', 'spawnvpe',
                        'execl', 'execle', 'execlp', 'execlpe', 'execv', 'execve', 'execvp', 'execvpe',
                        'system', 'popen'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ('eval', 'exec'):
                self.fail('eval/exec call in runner')
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in banned_attrs:
                self.fail('spawn/exec/system/popen call in runner: ' + node.func.attr)
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg == 'shell':
                        self.fail('shell= keyword in runner')
        funcs = {node.name: node for node in ast.walk(tree)
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        for name in ('snapshot_protected', 'compare_snapshots'):
            target = funcs[name]
            for node in ast.walk(target):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'open':
                    self.fail(name + ' opens files for writing/reading directly')
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ('write', 'writelines'):
                    self.fail(name + ' writes files')

    # WORK_UNIT_CASE: 850/40
    def test_malformed_corpus_never_escapes_or_crashes_parent(self):
        toml_corpus = (b'', b'\xff', b'[' * 1000, b' ' * 70000, VALID + b'\n[issue]\nnumber=3')
        for raw in toml_corpus:
            with self.assertRaises(r.RunnerInputError):
                r.decode_descriptor(raw, FILENAME)
        json_corpus = (b'', b'\xff', b'[' * 33 + b'0' + b']' * 33, b'{"x":NaN}',
                       b'{"x":1,"\\u0078":2}', b'a' * (r.MAX_PROTOCOL_BYTES + 1), b'{"schema":"x"}')
        for raw in json_corpus:
            with self.assertRaises(r.RunnerInputError):
                if raw == b'{"schema":"x"}':
                    r.parse_python_protocol(raw, request_sha256='a' * 64, expected_module='tests.suite',
                                            expected_source_sha256='a' * 64, expected_phase='discover')
                else:
                    r._bounded_json(raw)
        for raw in (b'a: benchmark\n', b'', b'\xff', b'a' * (r.MAX_PROTOCOL_BYTES + 1),
                    b'a' * 2000 + b': test\n'):
            with self.assertRaises(r.RunnerInputError):
                r.parse_rust_discovery(raw, 4)
        for raw in (b'\xff', b'a' * (r.MAX_PROTOCOL_BYTES + 1), b''):
            with self.assertRaises(r.RunnerInputError):
                r.parse_rust_exact(raw, 'tiny_ok_a', 0, 2)
        with self.assertRaises(r.RunnerInputError):
            r.parse_rust_exact(b'', 'a' * 300, 0, 2)
        with self.assertRaises(r.RunnerInputError):
            r.canonical_command(['x'] * 5000)
        # Parent is alive and functional after the full corpus.
        self.assertEqual('cargo test', r.canonical_command(('cargo', 'test')))

    # WORK_UNIT_CASE: 850/41
    def test_real_nested_powershell_reap_unknown_cleanup_never_green(self):
        bridge = (FIXTURE_ROOT / 'windows-cleanup' / 'ps-bridge-sample.py').read_text()
        self.assertIn('Start-Sleep', bridge)
        self.assertIn('powershell', bridge.lower())
        with self.fixture(bridge) as root:
            observed, discovery, _, _ = self.child(root)
            self.assertEqual(0, observed.returncode, observed.stderr)
            self.assertEqual('tests.suite.Suite.test_bridge', discovery['tests'][0]['id'])
            disp, body, _ = self._short_child(root, 'execute', discovery['tests'], timeout=5)
            self.assertTrue(disp['timed_out'], disp)
            self.assertEqual(0, disp['active_processes'], disp)
            self.assertTrue(disp['cleanup_ok'], disp)
            self.assertEqual('timeout-reaped', disp['cleanup'], disp)
            self.assertEqual(b'', body)

            def is_green(d):
                return d['cleanup'] in ('clean', 'timeout-reaped') and d['cleanup_ok'] and d['active_processes'] == 0 and not d['truncated']
            self.assertTrue(is_green(disp))
            fake_unknown = dict(disp, cleanup='unknown-mystery', cleanup_ok=False, active_processes=3)
            self.assertFalse(is_green(fake_unknown))

    # WORK_UNIT_CASE: 850/42
    def test_real_mutation_invalidation_preserves_evidence_without_reset(self):
        text = ('import unittest\nfrom pathlib import Path\nclass Suite(unittest.TestCase):\n'
                '    def test_ok(self):\n'
                "        Path(__file__).with_name('seed.txt').write_text('mutated-by-test')\n"
                '        self.assertTrue(True)\n')
        with self.fixture(text) as root:
            seed = root / 'tests/seed.txt'
            seed.write_text('original', newline='\n')
            before = r.snapshot_protected(root, ['tests/suite.py', 'tests/seed.txt'])
            observed, data, _, _ = self.discover_execute(root)
            after = r.snapshot_protected(root, ['tests/suite.py', 'tests/seed.txt'])
            diff = r.compare_snapshots(before, after)
            self.assertEqual(['tests/seed.txt'], diff['mutated'])
            self.assertEqual([], diff['added'])
            self.assertEqual([], diff['removed'])
            # Evidence preserved and the candidate is never auto-reset.
            self.assertEqual('mutated-by-test', seed.read_text())
            self.assertNotEqual(before['tests/seed.txt'], after['tests/seed.txt'])
            self.assertEqual(0, observed.returncode, observed.stderr)

    # WORK_UNIT_CASE: 850/43
    def test_stale_assignment_rejected(self):
        stale_raw = (DESCRIPTOR_DIR / 'stale-assignment.toml').read_bytes()
        stale_data = r.decode_descriptor(stale_raw, FILENAME)
        self.assertNotEqual('a' * 64, stale_data['body_sha256'])
        with self.assertRaises(r.RunnerInputError) as ctx:
            r.parse_descriptor(stale_raw, FILENAME, _b1_assignment())
        self.assertIn('STALE_ASSIGNMENT_BINDING', str(ctx.exception))
        with self.assertRaises(r.RunnerInputError) as ctx_absent:
            r.parse_descriptor(VALID, FILENAME, None)
        self.assertIn('ASSIGNMENT_RECEIPT_REQUIRED', str(ctx_absent.exception))
        closed = _b1_assignment(state=c.IssueState.CLOSED, source_use=c.AssignmentSourceUse.PREREQUISITE_EVIDENCE)
        with self.assertRaises(r.RunnerInputError) as ctx_closed:
            r.parse_descriptor(VALID, FILENAME, closed)
        self.assertIn('INACTIVE_ASSIGNMENT', str(ctx_closed.exception))

    # WORK_UNIT_CASE: 850/44
    def test_forgery_rejected(self):
        grammar = (b'\nrunning 1 test\ntest tiny_ok_a ... ok\n\ntest result: ok. 1 passed; 0 failed; '
                   b'0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n\n')
        forged_count = grammar.replace(b'1 passed', b'99 passed')
        with self.assertRaises(r.RunnerInputError):
            r.parse_rust_exact(forged_count, 'tiny_ok_a', 0, 1)
        with self.assertRaises(r.RunnerInputError):
            r.parse_rust_exact(b'', 'tiny_ok_a', 0, 1)
        with self.assertRaises(r.RunnerInputError):
            r.parse_rust_exact(grammar, 'other::test', 0, 1)
        with self.assertRaises(r.RunnerInputError):
            r.parse_rust_exact(grammar, 'tiny_ok_a', 1, 1)
        text = BASE.replace('self.assertEqual(2 + 2, 4)',
                            'print("test result: ok. 99 passed; 0 failed")\n        self.assertTrue(False)')
        with self.fixture(text) as root:
            observed, data, _, _ = self.discover_execute(root)
            self.assertIn(b'99 passed', observed.stdout)
            self.assertEqual('failure', data['results'][0]['outcome'])
            _, _, exec_body, exec_req = self.child(root, 'execute', data['tests'])
            kwargs = dict(request_sha256=hashlib.sha256(json.dumps(exec_req, sort_keys=True).encode()).hexdigest(),
                          expected_module=exec_req['module'], expected_source_sha256=exec_req['source_sha256'],
                          expected_phase='execute', expected_discovery=exec_req['expected'])
            foreign = dict(json.loads(exec_body.decode()),
                           results=[{'id': 'foreign.Test.test_x', 'outcome': 'pass'}])
            with self.assertRaises(r.RunnerInputError):
                r.parse_python_protocol(json.dumps(foreign).encode(), **kwargs)
            bad_outcome = dict(json.loads(exec_body.decode()),
                               results=[{'id': exec_req['expected'][0]['id'], 'outcome': 'success'}])
            with self.assertRaises(r.RunnerInputError):
                r.parse_python_protocol(json.dumps(bad_outcome).encode(), **kwargs)


if __name__ == '__main__':
    unittest.main()
